//! Shared GPG helpers: colons parsing, homedir resolution, discovery and
//! the agent preset.
//!
//! Pure data or explicit-path subprocesses only: no locks, no D-Bus, no
//! config reads, so both the CLI (`src/cli/gpg.rs`) and the daemon's
//! unlock hook (`src/dbus/gpg_preset.rs`) build on this. Callers pass
//! every external binary and home explicitly; bare `"gpg"` defaults
//! resolve on the *caller's* PATH, which is the login environment for
//! the CLI and the user manager environment for the daemon.
//!
//! On the trust model (`README.md`, "Same-uid trust"): feeding a
//! passphrase to an ambient-resolved helper hands nothing to anyone who
//! could not already read the same unlocked item over the session bus.
//! The pipe (never argv) and the `Zeroizing` buffers are about narrower
//! exposure — `ps` output, core dumps, swap — not about the uid boundary.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

pub const GPG_SCHEMA: &str = "org.secret-manager.gpg";

/// Bound on one gpg/gpg-agent invocation. These are local, single-shot
/// helpers: a hung agent must surface as an error, never park a caller —
/// and in the daemon's unlock hook there is one such task per unlock.
const CHILD_TIMEOUT: Duration = Duration::from_secs(30);

/// Colons field indexes (`gpg -K --with-keygrip --with-colons` layout).
const F_VALIDITY: usize = 1;
const F_CAPABILITY: usize = 11;
const F_VALUE: usize = 9;

/// The binaries and home a preset run talks to: everything resolved,
/// nothing ambient. Built from config ([`Bins::from_config`], the daemon
/// path) or from the login environment ([`Bins::from_env`], the CLI path).
#[derive(Debug, Clone)]
pub struct Bins {
    pub gpg: PathBuf,
    pub agent: PathBuf,
    pub homedir: PathBuf,
}

impl Bins {
    pub fn from_config(cfg: &crate::config::GpgConfig) -> Self {
        Self {
            gpg: cfg.gpg_bin.clone(),
            agent: cfg.agent_bin.clone(),
            homedir: effective_homedir(cfg.homedir.as_deref()),
        }
    }

    /// Inherited: a login shell or terminal carries the right `GNUPGHOME`.
    /// (The daemon cannot assume that, so it builds from config instead.)
    pub fn from_env() -> Self {
        Self {
            gpg: PathBuf::from("gpg"),
            agent: PathBuf::from("gpg-connect-agent"),
            homedir: effective_homedir(None),
        }
    }
}

/// One secret key with sign capability. The fingerprint is the full 40-hex
/// record from the colons listing; `longid` is derived from it, so explicit
/// key selection never consults anything but gpg's own output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretKey {
    pub fpr: String,
    pub grip: String,
}

impl SecretKey {
    /// Long key id, uppercased. Degrades to the whole fingerprint rather
    /// than panicking on a short one: the type does not enforce the
    /// length the parser does, so a future constructor must not turn data
    /// into a panic.
    pub fn longid(&self) -> String {
        self.fpr
            .get(self.fpr.len().saturating_sub(16)..)
            .unwrap_or(&self.fpr)
            .to_uppercase()
    }
}

/// The gpg home to pass explicitly: configured, else `$GNUPGHOME`, else
/// `~/.gnupg`. An empty `GNUPGHOME` counts as unset — it is what an
/// unguarded `export GNUPGHOME=$(...)` leaves behind, never a home.
///
/// The environment lookup is injectable so tests never touch the
/// process-global environment they share with every parallel test.
pub fn effective_homedir(configured: Option<&Path>) -> PathBuf {
    effective_homedir_with(configured, |name| std::env::var_os(name))
}

fn effective_homedir_with(
    configured: Option<&Path>,
    getenv: impl Fn(&str) -> Option<std::ffi::OsString>,
) -> PathBuf {
    // An explicitly configured empty path is the same misconfiguration
    // as an empty variable: fall through rather than spawn gpg with
    // `--homedir ""`.
    if let Some(dir) = configured.filter(|d| !d.as_os_str().is_empty()) {
        return dir.to_path_buf();
    }
    if let Some(home) = getenv("GNUPGHOME").filter(|v| !v.is_empty()) {
        return PathBuf::from(home);
    }
    crate::config::home_dir().join(".gnupg")
}

pub fn key_query(longid: &str) -> std::collections::BTreeMap<String, String> {
    std::collections::BTreeMap::from([
        ("xdg:schema".to_string(), GPG_SCHEMA.to_string()),
        ("keyid".to_string(), longid.to_string()),
    ])
}

/// Secret keys with sign capability from `gpg -K --with-keygrip --with-colons`.
///
/// Only `sec`/`ssb` records are read; the `fpr` and `grp` lines following
/// one belong to it. Expired and revoked keys are skipped, and a record
/// without a keygrip is dropped — there is nothing to preset. Anything
/// else on the line (uids, fields newer gpgs may add) is ignored rather
/// than rejected, so a newer gpg degrades to fewer keys, never to a
/// parse error.
pub fn parse_colons(text: &str) -> Vec<SecretKey> {
    let mut out = Vec::new();
    let mut sign = false;
    let mut fpr: Option<String> = None;
    for line in text.lines() {
        let f: Vec<&str> = line.split(':').collect();
        match f.first() {
            Some(&"sec") | Some(&"ssb") => {
                let valid = !matches!(f.get(F_VALIDITY), Some(v) if ["e", "r"].contains(v));
                sign = valid && f.get(F_CAPABILITY).is_some_and(|c| c.contains('s'));
                fpr = None;
            }
            Some(&"fpr") => {
                if fpr.is_none()
                    && let Some(fp) = f.get(F_VALUE)
                    && fp.len() == 40
                    && fp.chars().all(|c| c.is_ascii_hexdigit())
                {
                    fpr = Some(fp.to_uppercase());
                }
            }
            Some(&"grp") => {
                // Real keygrips are 40 hex digits. Anything else is not a
                // keyring line worth presetting into: it would be spliced
                // verbatim into an Assuan command below.
                let grip = f.get(F_VALUE).unwrap_or(&"");
                let grip_ok = grip.len() == 40 && grip.chars().all(|c| c.is_ascii_hexdigit());
                if sign
                    && grip_ok
                    && let Some(fp) = fpr.take()
                {
                    out.push(SecretKey {
                        fpr: fp,
                        grip: grip.to_uppercase(),
                    });
                }
                sign = false;
                fpr = None;
            }
            _ => {}
        }
    }
    out
}

/// Match a user-supplied id against a fingerprint: full fingerprint or
/// long (16-hex) key id, each with an optional `0x` prefix, case
/// insensitive. Short (8-hex) ids are refused outright: 32-bit collisions
/// are manufacturable, and a colliding key in the ring must never select
/// which secret gets stored. Anything else matches nothing rather than a
/// substring.
pub fn keyid_matches(input: &str, fpr: &str) -> bool {
    normalize_id(input).is_some_and(|norm| fpr.to_uppercase().ends_with(&norm))
}

/// Canonical form of a key id for comparisons: `0x` prefix stripped,
/// uppercased; a 40-hex fingerprint folds to its long id. Anything else
/// (short ids, non-hex, wrong length) is `None` and matches nothing.
fn normalize_id(input: &str) -> Option<String> {
    let norm: String = input
        .strip_prefix("0x")
        .or_else(|| input.strip_prefix("0X"))
        .unwrap_or(input)
        .to_uppercase();
    if !norm.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    match norm.len() {
        40 => Some(norm[norm.len() - 16..].to_string()),
        16 => Some(norm),
        _ => None,
    }
}

/// Whether `longid` passes an allowlist in the same id forms enrollment
/// accepts. An empty filter allows everything; an entry that normalizes
/// to nothing matches nothing.
pub fn key_allowed(filter: &[String], longid: &str) -> bool {
    if filter.is_empty() {
        return true;
    }
    let Some(want) = normalize_id(longid) else {
        return false;
    };
    filter
        .iter()
        .filter_map(|s| normalize_id(s))
        .any(|f| f == want)
}

#[derive(Debug, PartialEq, Eq)]
pub enum GpgError {
    /// The binary is not on PATH (holds its name for the message).
    Missing(String),
    Failed(String),
}

impl std::fmt::Display for GpgError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GpgError::Missing(bin) => write!(f, "{bin} not found on PATH"),
            GpgError::Failed(m) => write!(f, "{m}"),
        }
    }
}

pub fn discover(bins: &Bins) -> Result<Vec<SecretKey>, GpgError> {
    let child = std::process::Command::new(&bins.gpg)
        .arg("--homedir")
        .arg(&bins.homedir)
        .args(["-K", "--with-keygrip", "--with-colons"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                GpgError::Missing(bins.gpg.to_string_lossy().into_owned())
            } else {
                GpgError::Failed(format!("cannot run {}: {e}", bins.gpg.display()))
            }
        })?;
    let out = wait_bounded(child, "gpg -K")?;
    if !out.status.success() {
        let detail = String::from_utf8_lossy(&out.stderr);
        let detail = detail.trim();
        return Err(GpgError::Failed(if detail.is_empty() {
            format!("gpg -K failed with status {}", out.status)
        } else {
            crate::sanitize::escape_control(detail)
        }));
    }
    Ok(parse_colons(&String::from_utf8_lossy(&out.stdout)))
}

/// Wait for a child, killing it past [`CHILD_TIMEOUT`]. A hung gpg must
/// surface as an error, never park the caller — in the daemon's unlock
/// hook there is one such task per unlock, so an unkilled hang would
/// accumulate a process per unlock.
///
/// `pub(crate)`: the CLI's enroll testsign shares it rather than growing
/// its own wait.
pub(crate) fn wait_bounded(
    child: std::process::Child,
    what: &str,
) -> Result<std::process::Output, GpgError> {
    wait_bounded_with(child, what, CHILD_TIMEOUT)
}

/// [`wait_bounded`] with an injectable budget, so the kill path is
/// provable in milliseconds rather than once per thirty seconds.
fn wait_bounded_with(
    mut child: std::process::Child,
    what: &str,
    timeout: Duration,
) -> Result<std::process::Output, GpgError> {
    let start = Instant::now();
    loop {
        match child
            .try_wait()
            .map_err(|e| GpgError::Failed(format!("cannot wait for {what}: {e}")))?
        {
            Some(_) => {
                return child
                    .wait_with_output()
                    .map_err(|e| GpgError::Failed(format!("cannot read {what} output: {e}")));
            }
            None if start.elapsed() >= timeout => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(GpgError::Failed(format!(
                    "{what} timed out after {}s",
                    timeout.as_secs()
                )));
            }
            None => std::thread::sleep(Duration::from_millis(10)),
        }
    }
}

fn hex(bytes: &[u8]) -> Zeroizing<String> {
    let mut s = Zeroizing::new(String::with_capacity(bytes.len() * 2));
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Feed one passphrase to the agent. The command travels over a pipe, never
/// argv, so it never appears in `ps`; the hex and the command buffer are
/// wiped on drop. `GNUPGHOME` is set explicitly: the caller (in particular
/// the daemon) may have no usable environment of its own.
pub fn preset_one(bins: &Bins, keygrip: &str, passphrase: &[u8]) -> Result<(), GpgError> {
    // Validated at the sink as well as the parser: `preset_one` is `pub`
    // and a future caller must not be able to splice a newline into an
    // Assuan command by handing over an unchecked grip.
    if keygrip.len() != 40 || !keygrip.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(GpgError::Failed(
            "refusing to preset into a non-hex keygrip".into(),
        ));
    }
    let mut child = std::process::Command::new(&bins.agent)
        .env("GNUPGHOME", &bins.homedir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                GpgError::Missing(bins.agent.to_string_lossy().into_owned())
            } else {
                GpgError::Failed(format!("cannot start {}: {e}", bins.agent.display()))
            }
        })?;
    let cmd = Zeroizing::new(format!(
        "PRESET_PASSPHRASE {keygrip} -1 {}\nBYE\n",
        hex(passphrase).as_str()
    ));
    // A failed write leaves the child holding a pipe it will never read:
    // kill and reap it rather than leaking one process per failing key.
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| GpgError::Failed("gpg-connect-agent has no stdin".into()))?;
    if let Err(e) = stdin.write_all(cmd.as_bytes()) {
        drop(stdin);
        let _ = child.kill();
        let _ = child.wait();
        return Err(GpgError::Failed(format!("cannot talk to gpg-agent: {e}")));
    }
    drop(stdin);
    let out = wait_bounded(child, "gpg-connect-agent")?;
    let reply = String::from_utf8_lossy(&out.stdout);
    if !out.status.success() || reply.lines().any(|l| l.starts_with("ERR")) {
        // Peer text (agent reply) is escaped before it reaches a log or a
        // terminal, like every other value a subprocess hands back.
        let first = reply
            .lines()
            .find(|l| l.starts_with("ERR"))
            .map(crate::sanitize::escape_control)
            .unwrap_or_default();
        return Err(GpgError::Failed(format!(
            "gpg-agent refused PRESET_PASSPHRASE ({first}); \
             add `allow-preset-passphrase` to gpg-agent.conf and run \
             `gpg-connect-agent reloadagent /bye`"
        )));
    }
    Ok(())
}

/// Feed every enrolled passphrase to the agent. Returns `(preset, failures)`:
/// the caller decides whether a failure is fatal (interactive enroll) or
/// log-only (daemon unlock hook, login helper).
pub fn preset_enrolled(
    bins: &Bins,
    pairs: &[(String, Zeroizing<Vec<u8>>)],
) -> (usize, Vec<String>) {
    let mut done = 0usize;
    let mut failed = Vec::new();
    // Discovery is what names the grips. A missing binary is a failure
    // entry here (the CLI's quiet path returns before reaching this);
    // an undiscoverable ring presets nothing rather than erroring, so a
    // rotated-away key is a skip.
    let keys = match discover(bins) {
        Ok(keys) => keys,
        Err(e) => return (0, vec![e.to_string()]),
    };
    for (longid, secret) in pairs {
        if secret.is_empty() {
            continue;
        }
        let Some(want) = normalize_id(longid) else {
            continue;
        };
        let Some(key) = keys.iter().find(|k| k.longid() == want) else {
            continue;
        };
        match preset_one(bins, &key.grip, secret) {
            Ok(()) => done += 1,
            Err(e) => failed.push(format!("{longid}: {e}")),
        }
    }
    (done, failed)
}

/// Whether two enrolled `keyid` values name the same key: normalized
/// comparison first, raw equality for values no normalization accepts
/// (both unparseable can still be the same typo twice).
fn same_enrollment(a: &str, b: &str) -> bool {
    match (normalize_id(a), normalize_id(b)) {
        (Some(x), Some(y)) => x == y,
        _ => a == b,
    }
}

/// Enrolled `(keyid, secret)` pairs from one unlocked vault's items,
/// appended to `pairs` with first-wins across calls: the daemon walks
/// every collection through this one function, so the dedup rule cannot
/// drift between vaults. Returns warnings (duplicate enrollments) for
/// the caller to log; skips are silent by design.
pub fn collect_enrolled(
    items: &[crate::vault::format::Item],
    filter: &[String],
    pairs: &mut Vec<(String, Zeroizing<Vec<u8>>)>,
) -> Vec<String> {
    let mut warnings = Vec::new();
    for item in items {
        if item.attributes.get("xdg:schema").map(String::as_str) != Some(GPG_SCHEMA) {
            continue;
        }
        let Some(keyid) = item.attributes.get("keyid") else {
            continue;
        };
        if !key_allowed(filter, keyid) {
            continue;
        }
        if item.secret.is_empty() {
            continue;
        }
        if pairs.iter().any(|(k, _)| same_enrollment(k, keyid)) {
            warnings.push(format!("{keyid} enrolled twice; using the first"));
            continue;
        }
        pairs.push((keyid.clone(), item.secret.clone()));
    }
    warnings
}

#[cfg(test)]
mod tests {
    use super::*;

    const FPR: &str = "214A13BF20AED6B3C7EB6BDCD98C3F305E74B9E3";
    const GRIP: &str = "EFEB25D85B8B0F2835DE2591EA242763FE1FCCF9";

    fn colons(sec_line: &str) -> String {
        format!("{sec_line}\nfpr:::::::::{FPR}:\ngrp:::::::::{GRIP}:\n")
    }

    #[test]
    fn parses_a_signing_key() {
        let keys = parse_colons(&colons(
            "sec:u:255:22:D98C3F305E74B9E3:1774453727:1837525727::u:::scESC:::+:::23::0:",
        ));
        assert_eq!(
            keys,
            vec![SecretKey {
                fpr: FPR.into(),
                grip: GRIP.into()
            }]
        );
        assert_eq!(keys[0].longid(), "D98C3F305E74B9E3");
    }

    #[test]
    fn an_encrypt_only_key_is_not_a_signing_key() {
        let keys = parse_colons(&colons(
            "ssb:u:255:18:F168BEF944D781E9:1774453727:1837525727:::::e:::+:::23::0:",
        ));
        assert!(keys.is_empty());
    }

    #[test]
    fn a_sign_capable_subkey_is_preset_by_its_own_grip() {
        // Offline primary without `s`, signing subkey with it: only the
        // subkey may preset, bound to its own fingerprint and grip.
        let text = "sec:u:255:22:D98C3F305E74B9E3:1774453727:1837525727::u:::cert:::+:::23::0:\n\
                    fpr:::::::::214A13BF20AED6B3C7EB6BDCD98C3F305E74B9E3:\n\
                    grp:::::::::EFEB25D85B8B0F2835DE2591EA242763FE1FCCF9:\n\
                    ssb:u:255:18:AAAAAAAAAAAAAAAA:1774453727:1837525727:::::s:::+:::23::0:\n\
                    fpr:::::::::BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB:\n\
                    grp:::::::::CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC:\n";
        let keys = parse_colons(text);
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].fpr, "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB");
        assert_eq!(keys[0].grip, "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC");
    }

    #[test]
    fn garbage_colons_degrade_to_no_keys() {
        // Documented leniency, pinned: a corrupt or newer-than-us layout
        // presets nothing rather than erroring. (A truly broken keyring
        // makes gpg itself exit non-zero, which `discover` reports.)
        assert!(parse_colons("not colons at all\nsec:broken\n").is_empty());
    }

    #[test]
    fn expired_and_revoked_keys_are_skipped() {
        for validity in ["e", "r"] {
            let line = format!(
                "sec:{validity}:255:22:D98C3F305E74B9E3:1774453727:1837525727::u:::scESC:::+:::23::0:"
            );
            assert!(parse_colons(&colons(&line)).is_empty(), "{validity}");
        }
    }

    #[test]
    fn a_record_without_a_keygrip_is_dropped() {
        let text = "sec:u:255:22:D98C3F305E74B9E3:1774453727:1837525727::u:::scESC:::+:::23::0:\n\
                    fpr:::::::::214A13BF20AED6B3C7EB6BDCD98C3F305E74B9E3:\n";
        assert!(parse_colons(text).is_empty());
    }

    #[test]
    fn keyid_matching_accepts_long_and_fingerprint() {
        for good in [
            "D98C3F305E74B9E3",
            "d98c3f305e74b9e3",
            "0xD98C3F305E74B9E3",
            FPR,
            &format!("0x{FPR}"),
        ] {
            assert!(keyid_matches(good, FPR), "{good}");
        }
        // Short (8-hex) ids are refused: 32-bit collisions are
        // manufacturable, so a colliding ring entry must never select a key.
        for bad in [
            "",
            "D98C3F30",
            "5E74B9E3",
            "ZZZ",
            "0x",
            "D98C3F305E74B9E4",
            "214A13BF20AED6B3C7EB6BDCD98C3F305E74B9E",
        ] {
            assert!(!keyid_matches(bad, FPR), "{bad}");
        }
    }

    #[test]
    fn a_non_hex_keygrip_drops_the_record() {
        let text = "sec:u:255:22:D98C3F305E74B9E3:1774453727:1837525727::u:::scESC:::+:::23::0:\n\
                    fpr:::::::::214A13BF20AED6B3C7EB6BDCD98C3F305E74B9E3:\n\
                    grp:::::::::not a grip at all:\n";
        assert!(parse_colons(text).is_empty());
    }

    #[test]
    fn key_allowed_accepts_enroll_spellings() {
        let filter = vec![
            "d98c3f305e74b9e3".to_string(),
            "0xAAAAAAAAAAAAAAAA".to_string(),
        ];
        assert!(key_allowed(&[], "D98C3F305E74B9E3"));
        assert!(key_allowed(&filter, "D98C3F305E74B9E3"));
        assert!(!key_allowed(&filter, "BBBBBBBBBBBBBBBB"));
        assert!(!key_allowed(&["5E74B9E3".to_string()], "D98C3F305E74B9E3"));
        assert!(!key_allowed(&filter, "not a keyid"));
    }

    #[test]
    fn homedir_resolution_prefers_config_then_env_then_default() {
        let dir = PathBuf::from("/home/u/.config/gnupg");
        let none = |_: &str| None;
        assert_eq!(effective_homedir_with(Some(&dir), none), dir);
        assert_eq!(
            effective_homedir_with(None, |_| Some("not a tty".into())),
            PathBuf::from("not a tty"),
            "a non-empty value is honored verbatim here; emptiness is what is guarded"
        );
        assert_eq!(
            effective_homedir_with(None, |_| Some("".into())),
            crate::config::home_dir().join(".gnupg")
        );
        assert_eq!(
            effective_homedir_with(None, none),
            crate::config::home_dir().join(".gnupg")
        );
    }

    #[test]
    fn a_missing_gpg_binary_is_a_failure_entry_not_a_silent_skip() {
        let bins = Bins {
            gpg: PathBuf::from("/nonexistent/gpg-for-tests"),
            agent: PathBuf::from("/nonexistent/gpg-connect-agent-for-tests"),
            homedir: PathBuf::from("/nonexistent"),
        };
        let (done, failed) = preset_enrolled(
            &bins,
            &[("D98C3F305E74B9E3".into(), Zeroizing::new(b"x".to_vec()))],
        );
        assert_eq!(done, 0);
        assert_eq!(failed.len(), 1);
        assert!(failed[0].contains("not found"), "{}", failed[0]);
    }

    #[test]
    fn collect_enrolled_applies_one_shared_rule() {
        use crate::vault::format::Item;
        use std::collections::BTreeMap;
        fn item(keyid: &str, secret: &[u8], schema: &str) -> Item {
            Item {
                id: keyid.into(),
                label: keyid.into(),
                attributes: BTreeMap::from([
                    ("xdg:schema".into(), schema.into()),
                    ("keyid".into(), keyid.into()),
                ]),
                secret: Zeroizing::new(secret.to_vec()),
                content_type: "".into(),
                created: 0,
                modified: 0,
            }
        }
        let items = vec![
            item("D98C3F305E74B9E3", b"one", GPG_SCHEMA),
            item("other", b"x", "org.secret-manager.ssh"),
            item("d98c3f305e74b9e3", b"two", GPG_SCHEMA),
            item("BBBBBBBBBBBBBBBB", b"", GPG_SCHEMA),
            Item {
                id: "nokey".into(),
                label: "nokey".into(),
                // Schema matches, no keyid: malformed enrollment, skipped
                // without a pair and without a warning.
                attributes: BTreeMap::from([("xdg:schema".into(), GPG_SCHEMA.into())]),
                secret: Zeroizing::new(b"x".to_vec()),
                content_type: "".into(),
                created: 0,
                modified: 0,
            },
        ];
        // Unfiltered: schema mismatch skipped, empty secret skipped, the
        // case-variant duplicate warns and loses to the first.
        let mut pairs = Vec::new();
        let warnings = collect_enrolled(&items, &[], &mut pairs);
        assert_eq!(pairs.len(), 1);
        assert_eq!(pairs[0].0, "D98C3F305E74B9E3");
        assert_eq!(warnings.len(), 1);
        // Filtered, in enroll spellings (lowercase, 0x, fingerprint).
        let mut pairs = Vec::new();
        let warnings = collect_enrolled(
            &items[..1],
            &[
                "d98c3f305e74b9e3".to_string(),
                "0x214A13BF20AED6B3C7EB6BDCD98C3F305E74B9E3".to_string(),
            ],
            &mut pairs,
        );
        assert!(warnings.is_empty());
        assert_eq!(pairs.len(), 1);
        // A filter matching nothing presets nothing.
        let mut pairs = Vec::new();
        collect_enrolled(&items[..1], &["AAAAAAAAAAAAAAAA".to_string()], &mut pairs);
        assert!(pairs.is_empty());
    }

    #[test]
    fn an_explicit_homedir_wins_over_everything() {
        let dir = PathBuf::from("/home/u/.config/gnupg");
        assert_eq!(effective_homedir(Some(&dir)), dir);
    }

    #[test]
    fn an_explicitly_empty_homedir_falls_through() {
        let none = |_: &str| None;
        assert_eq!(
            effective_homedir_with(Some(Path::new("")), none),
            crate::config::home_dir().join(".gnupg")
        );
    }

    #[test]
    fn a_hung_child_is_killed_on_a_budget() {
        let child = std::process::Command::new("sh")
            .args(["-c", "sleep 30"])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let err = wait_bounded_with(child, "sleep", Duration::from_millis(100)).unwrap_err();
        assert!(matches!(err, GpgError::Failed(_)), "{err:?}");
        assert!(err.to_string().contains("timed out"), "{err}");
    }

    #[test]
    fn preset_one_refuses_a_non_hex_grip_before_spawning() {
        let bins = Bins {
            gpg: PathBuf::from("/nonexistent"),
            agent: PathBuf::from("/nonexistent"),
            homedir: PathBuf::from("/nonexistent"),
        };
        // No subprocess runs: the refusal precedes every spawn, so even
        // impossible binary paths cannot change the outcome.
        let err = preset_one(&bins, "AAAA\nBYE\nCLEAR_PASSPHRASE x", b"pw").unwrap_err();
        assert!(err.to_string().contains("non-hex keygrip"), "{err}");
    }
}
