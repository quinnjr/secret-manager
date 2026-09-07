//! ssh add / list / remove / askpass.
//!
//! Keys are ordinary items: `xdg:schema=org.secret-manager.ssh`, `path=<canonical>`,
//! `has_passphrase=true|false`. Keys without a passphrase hold an empty secret so
//! `ssh list` can inventory them.

use super::client::Client;
use super::secrets::{delete_each, escape_control, find, find_all};
use super::{CliError, load_config, read_password};
use crate::prompt::{PinOutcome, PinRequest, Pinentry};
use clap::Subcommand;
use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use zbus::zvariant::OwnedObjectPath;
use zeroize::Zeroizing;

pub const SSH_SCHEMA: &str = "org.secret-manager.ssh";

#[derive(Subcommand, Debug)]
pub enum SshCommand {
    /// Register a key; prompts for its passphrase unless --no-passphrase
    Add {
        path: PathBuf,
        #[arg(long)]
        no_passphrase: bool,
    },
    /// List registered keys
    List,
    /// Forget a key
    Remove { path: PathBuf },
    /// SSH_ASKPASS entry point: answers ssh's passphrase prompt from the vault.
    ///
    /// Releasing a stored passphrase always raises a pinentry confirmation
    /// naming the key, because `ssh` only consults SSH_ASKPASS when there is
    /// no terminal on which it could have asked. Set SM_ASKPASS_NO_CONFIRM=1
    /// to skip that confirmation for unattended use; any use of the key is
    /// then answered without asking.
    Askpass {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        prompt: Vec<String>,
    },
}

fn canonical(path: &Path) -> Result<PathBuf, CliError> {
    std::fs::canonicalize(path).map_err(|e| CliError::Usage(format!("{}: {e}", path.display())))
}

/// Fallback for a path whose file no longer exists: canonicalize the parent
/// directory (resolving any symlinks in it) and re-attach the file name, so
/// the result matches what `add` recorded via `canonical` while the file was
/// still there. Falls back further to `std::path::absolute` if even the
/// parent directory cannot be resolved.
fn canonicalize_missing(path: &Path) -> Result<PathBuf, CliError> {
    let file_name = path
        .file_name()
        .ok_or_else(|| CliError::Usage(format!("{}: no file name", path.display())))?;
    let parent = path.parent().filter(|p| !p.as_os_str().is_empty());
    match parent {
        Some(parent) => match std::fs::canonicalize(parent) {
            Ok(parent) => Ok(parent.join(file_name)),
            Err(_) => std::path::absolute(path).map_err(CliError::from),
        },
        None => std::path::absolute(path).map_err(CliError::from),
    }
}

fn key_query(path: &Path) -> BTreeMap<String, String> {
    BTreeMap::from([
        ("xdg:schema".to_string(), SSH_SCHEMA.to_string()),
        ("path".to_string(), path.to_string_lossy().into_owned()),
    ])
}

fn key_attrs(path: &Path, has_passphrase: bool) -> BTreeMap<String, String> {
    let mut attrs = key_query(path);
    attrs.insert("has_passphrase".to_string(), has_passphrase.to_string());
    attrs
}

pub async fn add(path: PathBuf, no_passphrase: bool) -> Result<(), CliError> {
    let path = canonical(&path)?;
    let secret: Zeroizing<Vec<u8>> = if no_passphrase {
        Zeroizing::new(Vec::new())
    } else {
        Zeroizing::new(
            read_password(&format!("Passphrase for {}", path.display()))?
                .as_bytes()
                .to_vec(),
        )
    };
    let client = Client::connect().await?;
    // Strict: a lenient delete here would leave a stale registration behind in
    // a collection that could not be unlocked, which `askpass` may later
    // prefer over the one we are about to write.
    delete_each(&client, &find_all(&client, &key_query(&path)).await?).await?;
    client
        .store(
            &key_attrs(&path, !no_passphrase),
            &format!("SSH key {}", path.display()),
            &secret,
        )
        .await?;
    println!(
        "Registered {}{}",
        path.display(),
        if no_passphrase {
            " (no passphrase)"
        } else {
            ""
        }
    );
    Ok(())
}

pub async fn list() -> Result<(), CliError> {
    let client = Client::connect().await?;
    let query = BTreeMap::from([("xdg:schema".to_string(), SSH_SCHEMA.to_string())]);
    let mut out = std::io::stdout().lock();
    for item in find(&client, &query).await? {
        let info = client.item_info(&item).await?;
        // The `path` attribute is settable by any client on the session bus,
        // so it gets the same treatment as every other value `sm list` prints:
        // a `\r` or an ANSI escape must not be able to forge or erase a row.
        let path = escape_control(info.attributes.get("path").map_or("", String::as_str));
        let stored = info
            .attributes
            .get("has_passphrase")
            .is_some_and(|v| v == "true");
        writeln!(
            out,
            "{path}\tpassphrase: {}",
            if stored { "stored" } else { "none" }
        )?;
    }
    Ok(())
}

pub async fn remove(path: PathBuf) -> Result<(), CliError> {
    // The key file may already be gone (that's often why it's being removed),
    // so canonicalize falls back to resolving the parent directory (which
    // still exists, symlinks and all) and re-attaching the file name, instead
    // of `std::path::absolute`, which would leave a symlinked parent
    // unresolved and so fail to match the canonical path recorded by `add`.
    let path = canonical(&path).or_else(|_| canonicalize_missing(&path))?;
    let client = Client::connect().await?;
    // Strict: reporting "Removed <path>" while a copy of the passphrase
    // survives in a collection whose prompt was dismissed would be a lie.
    let items = find_all(&client, &key_query(&path)).await?;
    if items.is_empty() {
        return Err(CliError::NotFound(format!(
            "{} is not registered",
            path.display()
        )));
    }
    delete_each(&client, &items).await?;
    println!("Removed {}", path.display());
    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
pub enum AskpassKind {
    Passphrase(PathBuf),
    Confirm,
    Other,
}

/// Markers that make a prompt a yes/no question, whatever else it contains.
/// OpenSSH embeds the (attacker-chosen) destination string in the host-key
/// question, so a destination carrying `passphrase for key '...'` would
/// otherwise turn a confirmation into a passphrase request.
const CONFIRM_MARKERS: [&str; 4] = [
    "(yes/no",
    "authenticity of host",
    "Allow use of key",
    "Confirm user presence",
];

/// `ssh` asks `Enter passphrase for key '/p': `; `ssh-keygen` asks `Enter passphrase for "/p": `.
/// `SSH_ASKPASS_PROMPT=confirm` marks yes/no questions on OpenSSH >= 8.4.
///
/// Confirmation shape is decided *first*, and only a prompt that starts with
/// the passphrase question, holds no newline, quotes the path symmetrically
/// and names an absolute path is treated as a request for a stored secret.
pub fn classify_prompt(prompt: &str, askpass_prompt_env: Option<&str>) -> AskpassKind {
    // The explicit tag is authoritative and comes from `ssh` itself, not from
    // the prompt text, so it is honoured before anything is parsed.
    if askpass_prompt_env == Some("confirm") {
        return AskpassKind::Confirm;
    }
    // A passphrase question is a single line; anything multi-line is some
    // other dialog that merely quotes one.
    if !prompt.contains('\n')
        && let Some(path) = passphrase_path(prompt)
    {
        return AskpassKind::Passphrase(path);
    }
    // Only now: the markers are substring matches, so testing them first would
    // let a key path containing `Allow use of key` turn a real passphrase
    // request into a yes/no question.
    if CONFIRM_MARKERS.iter().any(|m| prompt.contains(m)) {
        return AskpassKind::Confirm;
    }
    // OpenSSH treats an empty answer to a question as "yes", so anything still
    // shaped like a question is confirmed rather than typed into.
    if prompt.trim_end().ends_with('?') {
        return AskpassKind::Confirm;
    }
    AskpassKind::Other
}

/// The key path in a passphrase prompt, if this is one.
///
/// Three shapes are accepted, matching the installed OpenSSH binaries:
/// `ssh` quotes with `'…'`, `ssh-keygen` with `"…"`, and `ssh-add` does not
/// quote at all and may append ` (will confirm each use)`. Each quote style is
/// closed by its own kind so an apostrophe in a path cannot truncate it to a
/// different key, and the whole prompt must be consumed, so a longer line that
/// merely opens with the question is not a passphrase request.
///
/// The unquoted form has no delimiters, so it is restricted to an absolute
/// path; a quoted relative path (`ssh -i ./key`) is returned as-is and
/// resolved — and checked against the registered keys — by [`askpass`].
pub(crate) fn passphrase_path(prompt: &str) -> Option<PathBuf> {
    // Compiled once. `askpass` calls this a handful of times per invocation
    // and the fuzz target calls it millions, where recompiling the regex was
    // the whole cost of the run.
    static RE: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
        regex::Regex::new(
            r#"(?i)^\s*Enter passphrase for (?:key )?(?:'([^']+)'|"([^"]+)"|(/[^:]*?))(?: \(will confirm each use\))?: *$"#,
        )
        .expect("static regex")
    });
    let c = RE.captures(prompt)?;
    let m = c
        .get(1)
        .or_else(|| c.get(2))
        .or_else(|| c.get(3))
        .expect("one alternative matched");
    // The quoted alternatives are `[^']`/`[^"]`, which admit both line
    // terminators, and `classify_prompt`'s single-line guard tests only `\n`.
    // A carriage return survived both and reached the path: harmless where
    // the path is *displayed* (every such site escapes it), but a key path is
    // a filename and no real OpenSSH prompt carries one, so it is refused
    // here — at the one place both callers go through — rather than left to
    // each consumer to remember. Found by `fuzz_targets/askpass_prompt.rs`
    // with `Enter passphrase for key 'a\rb': `.
    let path = m.as_str();
    if path.contains(['\n', '\r']) {
        return None;
    }
    Some(PathBuf::from(path))
}

/// `ssh` prints the identity file with `%.100s`, so a longer registered path
/// arrives truncated to exactly this many bytes and can only be matched by
/// prefix.
const SSH_PROMPT_PATH_LIMIT: usize = 100;

/// One registered key that a prompt could be asking about.
struct KeyMatch {
    item: OwnedObjectPath,
    /// The path to name in the consent dialog: the value the item was
    /// registered under, never the (symlinked, relative, truncated) spelling
    /// the prompt used.
    display: PathBuf,
    locked: bool,
}

/// Registered keys matching `path`, **without unlocking anything**: this runs
/// before the user has consented, so it must not be able to raise the master
/// password prompt, unlock the collection for every other bus client, or pull
/// a plaintext secret into this process. `Client::search` is the plain
/// `SearchItems` call, which reports locked matches instead of opening them.
async fn registered_keys(
    client: &Client,
    path: &Path,
    as_prompted: &str,
) -> Result<Vec<KeyMatch>, CliError> {
    let (unlocked, locked) = client.search(&key_query(path)).await?;
    // An exact attribute match means the stored `path` *is* `path`, so it can
    // be named in the dialog without reading the (locked) item back.
    let mut out: Vec<KeyMatch> = unlocked
        .into_iter()
        .map(|item| KeyMatch {
            item,
            display: path.to_path_buf(),
            locked: false,
        })
        .chain(locked.into_iter().map(|item| KeyMatch {
            item,
            display: path.to_path_buf(),
            locked: true,
        }))
        .collect();
    if !out.is_empty() || as_prompted.len() != SSH_PROMPT_PATH_LIMIT {
        return Ok(out);
    }
    // Truncated by `%.100s`. Only unlocked items can be matched this way,
    // because reading the stored `path` back is what makes the prefix
    // comparison possible in the first place.
    let schema = BTreeMap::from([("xdg:schema".to_string(), SSH_SCHEMA.to_string())]);
    let (unlocked, _locked) = client.search(&schema).await?;
    for item in unlocked {
        let info = client.item_info(&item).await?;
        if let Some(stored) = info.attributes.get("path")
            && stored.as_bytes().starts_with(as_prompted.as_bytes())
        {
            out.push(KeyMatch {
                item,
                display: PathBuf::from(stored),
                locked: false,
            });
        }
    }
    Ok(out)
}

/// Resolve the path a prompt named to the path `add` would have recorded:
/// symlinks followed, relative paths taken against this process's cwd. Doing
/// this once, before anything else, is what keeps the key named in the consent
/// dialog and the key whose passphrase is released the same key.
fn resolve_prompt_path(raw: &Path) -> PathBuf {
    canonical(raw).unwrap_or_else(|_| raw.to_path_buf())
}

pub async fn askpass(words: Vec<String>) -> Result<(), CliError> {
    let prompt = words.join(" ");
    let env = std::env::var("SSH_ASKPASS_PROMPT").ok();
    let kind = classify_prompt(&prompt, env.as_deref());
    if let AskpassKind::Passphrase(raw) = &kind
        && let Some(pass) = release_passphrase(raw).await?
    {
        println!("{}", pass.as_str());
        return Ok(());
    }
    fallback(&prompt, kind == AskpassKind::Confirm).await
}

/// Confirm, then look up. `ssh` consults SSH_ASKPASS precisely when there is
/// no controlling terminal, so the dialog is the only place a human can
/// consent to the key being used.
///
/// Order matters as much as the question: the lookup is what raises the master
/// password prompt, unlocks the collection for every client on the bus and
/// pulls the plaintext into this process, so a declined use must not have done
/// any of it. Everything before the dialog is a plain `SearchItems`, which
/// cannot unlock anything.
///
/// `Ok(None)` means "not ours to answer" and falls back to an interactive
/// prompt; `Err` means the user said no.
async fn release_passphrase(raw: &Path) -> Result<Option<Zeroizing<String>>, CliError> {
    let path = resolve_prompt_path(raw);
    let as_prompted = raw.to_string_lossy().into_owned();
    // No daemon, no bus, an unreadable collection: not an error, just nothing
    // we can answer from, so the user gets the ordinary passphrase box.
    let Ok(client) = Client::connect().await else {
        return Ok(None);
    };
    let Ok(matches) = registered_keys(&client, &path, &as_prompted).await else {
        return Ok(None);
    };
    let one = match matches.len() {
        0 => return Ok(None),
        1 => &matches[0],
        // Attributes are settable by any client on the session bus, so a
        // planted item can claim a registered key's path. Picking one would
        // mean answering ssh from an item an attacker chose; refuse and let
        // the user type the passphrase instead.
        n => {
            eprintln!(
                "secret-manager: {n} stored keys claim {}; refusing to choose between them",
                escape_control(&path.to_string_lossy())
            );
            return Ok(None);
        }
    };
    if !consented(&one.display).await? {
        return Err(CliError::NotFound("key use declined".into()));
    }
    // Consent given: only now may anything unlock or decrypt.
    if one.locked
        && client
            .unlock(std::slice::from_ref(&one.item))
            .await
            .is_err()
    {
        return Ok(None);
    }
    let Ok(secret) = client.get_secret(&one.item).await else {
        return Ok(None);
    };
    if secret.is_empty() {
        return Ok(None);
    }
    Ok(std::str::from_utf8(&secret)
        .ok()
        .map(|s| Zeroizing::new(s.to_string())))
}

/// Ask the user to approve one use of `path`. `SM_ASKPASS_NO_CONFIRM=1` opts
/// out for unattended use (documented in `sm ssh askpass --help`).
async fn consented(path: &Path) -> Result<bool, CliError> {
    if std::env::var("SM_ASKPASS_NO_CONFIRM").as_deref() == Ok("1") {
        return Ok(true);
    }
    let config = load_config()?;
    Pinentry::new(&config.prompt.pinentry)
        .confirm(&PinRequest {
            title: "ssh".into(),
            description: format!(
                "Allow ssh to use the stored passphrase for the key\n{}?",
                escape_control(&path.to_string_lossy())
            ),
            prompt: String::new(),
            error: None,
            repeat: false,
        })
        .await
        .map_err(|e| CliError::Failed(e.to_string()))
}

async fn fallback(prompt: &str, confirm: bool) -> Result<(), CliError> {
    let config = load_config()?;
    let pinentry = Pinentry::new(&config.prompt.pinentry);
    let req = PinRequest {
        title: "ssh".into(),
        description: prompt.to_string(),
        prompt: if confirm {
            String::new()
        } else {
            "Passphrase:".into()
        },
        error: None,
        repeat: false,
    };
    if confirm {
        let yes = pinentry
            .confirm(&req)
            .await
            .map_err(|e| CliError::Failed(e.to_string()))?;
        println!("{}", if yes { "yes" } else { "no" });
        return Ok(());
    }
    match pinentry
        .ask(&req)
        .await
        .map_err(|e| CliError::Failed(e.to_string()))?
    {
        // An empty line is read as "yes" by OpenSSH's confirmation path and as
        // an empty passphrase elsewhere; neither is an answer the user gave.
        PinOutcome::Pin(pin) if pin.is_empty() => {
            Err(CliError::NotFound("empty answer; nothing sent".into()))
        }
        PinOutcome::Pin(pin) => {
            println!("{}", pin.as_str());
            Ok(())
        }
        PinOutcome::Cancelled => Err(CliError::NotFound("cancelled".into())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_prompts() {
        assert_eq!(
            classify_prompt("Enter passphrase for key '/home/j/.ssh/id_ed25519': ", None),
            AskpassKind::Passphrase(PathBuf::from("/home/j/.ssh/id_ed25519"))
        );
        assert_eq!(
            classify_prompt("Enter passphrase for \"/k\": ", None),
            AskpassKind::Passphrase(PathBuf::from("/k"))
        );
        assert_eq!(
            classify_prompt(
                "Are you sure you want to continue connecting (yes/no/[fingerprint])?",
                None
            ),
            AskpassKind::Confirm
        );
        assert_eq!(
            classify_prompt("anything", Some("confirm")),
            AskpassKind::Confirm
        );
        assert_eq!(
            classify_prompt("Enter PIN for authenticator:", None),
            AskpassKind::Other
        );
    }

    /// OpenSSH puts the destination string, which the attacker controls (a
    /// `.gitmodules` URL, an `ssh://` link, a shared config), inside the
    /// host-key question. It must stay a confirmation.
    #[test]
    fn a_host_key_question_embedding_a_passphrase_prompt_is_a_confirmation() {
        let hostile = "The authenticity of host \
             'Enter passphrase for key '/home/u/.ssh/id_ed25519': ' can't be established.\n\
             ED25519 key fingerprint is SHA256:abc.\n\
             Are you sure you want to continue connecting (yes/no/[fingerprint])? ";
        assert_eq!(classify_prompt(hostile, None), AskpassKind::Confirm);
        // Even with the markers stripped, the leading text and the newlines
        // keep it out of the passphrase branch.
        let unmarked = "Host Enter passphrase for key '/home/u/.ssh/id_ed25519': \n\
             wants something.";
        assert_ne!(
            classify_prompt(unmarked, None),
            AskpassKind::Passphrase(PathBuf::from("/home/u/.ssh/id_ed25519"))
        );
    }

    #[test]
    fn a_key_path_containing_an_apostrophe_is_not_truncated() {
        // Double-quoted (ssh-keygen): the apostrophe is part of the path and
        // must not close the quote.
        assert_eq!(
            classify_prompt(
                "Enter passphrase for \"/home/j/o'brien/id_ed25519\": ",
                None
            ),
            AskpassKind::Passphrase(PathBuf::from("/home/j/o'brien/id_ed25519"))
        );
        // Single-quoted (ssh): the quoted run stops at the first apostrophe
        // and the remainder does not close the prompt, so the whole thing is
        // not a passphrase request at all. Falling back to a typed answer is
        // right: naming a *different* key would be worse.
        assert_eq!(
            classify_prompt("Enter passphrase for key '/home/j/o'brien/id': ", None),
            AskpassKind::Other
        );
    }

    #[test]
    fn a_prompt_with_a_newline_is_never_a_passphrase_request() {
        assert_ne!(
            classify_prompt("Enter passphrase for key '/k':\nand allow forwarding", None),
            AskpassKind::Passphrase(PathBuf::from("/k"))
        );
    }

    /// MEDIUM 1: `ssh-add` does not quote the path, and appends an optional
    /// suffix with `-c`. These are the four prompt strings the installed
    /// OpenSSH binaries actually print.
    #[test]
    fn the_real_openssh_prompts_are_all_recognized() {
        let key = "/home/j/.ssh/id_ed25519";
        for prompt in [
            // ssh(1)
            "Enter passphrase for key '/home/j/.ssh/id_ed25519': ",
            // ssh-add(1)
            "Enter passphrase for /home/j/.ssh/id_ed25519: ",
            // ssh-add -c
            "Enter passphrase for /home/j/.ssh/id_ed25519 (will confirm each use): ",
            // ssh-keygen(1)
            "Enter passphrase for \"/home/j/.ssh/id_ed25519\": ",
        ] {
            assert_eq!(
                classify_prompt(prompt, None),
                AskpassKind::Passphrase(PathBuf::from(key)),
                "{prompt:?}"
            );
        }
    }

    /// LOW: the confirmation markers are matched anywhere in the prompt, so a
    /// key whose path contains one must still be a passphrase request. The
    /// markers only apply once the passphrase pattern has failed.
    #[test]
    fn a_key_path_containing_a_confirm_marker_is_still_a_passphrase_request() {
        assert_eq!(
            classify_prompt(
                "Enter passphrase for key '/home/j/Allow use of key/id': ",
                None
            ),
            AskpassKind::Passphrase(PathBuf::from("/home/j/Allow use of key/id"))
        );
    }

    #[test]
    fn a_relative_key_path_is_a_passphrase_request_resolved_later() {
        // LOW: `ssh -i ./key` prints the identity file as given. The path is
        // kept relative here and resolved against the process cwd by
        // `askpass`, which releases a passphrase only if it canonicalizes to
        // an already registered key.
        assert_eq!(
            classify_prompt("Enter passphrase for key 'id_ed25519': ", None),
            AskpassKind::Passphrase(PathBuf::from("id_ed25519"))
        );
        // The unquoted (ssh-add) form still requires an absolute path: it has
        // no delimiters, so a relative capture could swallow arbitrary text.
        assert_eq!(
            classify_prompt("Enter passphrase for id_ed25519: ", None),
            AskpassKind::Other
        );
    }

    /// A key path is a filename; a line terminator inside one means the
    /// prompt was assembled by something other than OpenSSH. `\n` was already
    /// refused by `classify_prompt`'s single-line guard, but `\r` reached the
    /// returned path through the quoted alternatives, and `passphrase_path`
    /// leaked both when called directly. Red before the fix.
    #[test]
    fn a_path_carrying_a_line_terminator_is_not_a_passphrase_request() {
        for raw in ["a\rb", "a\nb", "/tmp/k\r", "/tmp/\nk"] {
            for prompt in [
                format!("Enter passphrase for key '{raw}': "),
                format!("Enter passphrase for \"{raw}\": "),
                format!("Enter passphrase for {raw}: "),
            ] {
                assert_eq!(passphrase_path(&prompt), None, "{prompt:?}");
                assert!(
                    !matches!(classify_prompt(&prompt, None), AskpassKind::Passphrase(_)),
                    "{prompt:?}"
                );
            }
        }
    }

    #[test]
    fn an_unclassified_question_is_confirmed() {
        assert_eq!(
            classify_prompt("Allow use of key /k?", None),
            AskpassKind::Confirm
        );
        assert_eq!(
            classify_prompt("Confirm user presence for key ED25519", None),
            AskpassKind::Confirm
        );
        assert_eq!(
            classify_prompt("Some unlabelled question? ", None),
            AskpassKind::Confirm
        );
    }
}

#[cfg(test)]
mod canonicalize_missing_tests {
    use super::*;

    /// `sm ssh remove /nonexistent/..` reaches the fallback (the `canonical`
    /// call fails) with a path whose `file_name()` is `None`. This resolver
    /// decides which registered item `remove` deletes, so a path that names no
    /// file must be refused rather than resolved to its parent directory --
    /// which is not a key and would make `remove` report on the wrong item.
    #[test]
    fn canonicalize_missing_refuses_a_path_with_no_file_name() {
        for bad in ["/nonexistent-9f2c/..", "/"] {
            let err = canonicalize_missing(Path::new(bad)).unwrap_err();
            assert!(matches!(err, CliError::Usage(_)), "{bad}: got {err:?}");
            assert!(err.to_string().contains("no file name"), "{bad}: {err}");
        }
    }

    /// The success case the refusal must not swallow: a key file that is gone
    /// resolves through its canonicalized parent, so a registration made
    /// through a symlinked directory is still matched after the file is
    /// deleted.
    #[test]
    fn canonicalize_missing_resolves_a_gone_file_through_its_parent() {
        let base = tempfile::tempdir().unwrap();
        let real = std::fs::canonicalize(base.path()).unwrap().join("real");
        std::fs::create_dir(&real).unwrap();
        let link = base.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert_eq!(
            canonicalize_missing(&link.join("id_gone")).unwrap(),
            real.join("id_gone")
        );
    }
}
