//! Live extraction from gnome-keyring, over a private session bus.
//!
//! This module starts `dbus-daemon --session` and a
//! `gnome-keyring-daemon --components=secrets` child against it, unlocks with
//! the login password on the child's **stdin** (never argv), and walks the
//! standard Secret Service API on that private bus, so the real daemon on the
//! real session bus is never displaced. It also owns the refusal that
//! `--from gnome-keyring` cannot be served from the session bus when
//! `org.freedesktop.secrets` is owned by something other than
//! `gnome-keyring-daemon`, and the named, timed-out error for an unlock
//! prompt that nothing can answer.
//!
//! Nothing here parses the encrypted half of a `.keyring` file; the cleartext
//! header parser lives in [`super::formats`] and is what
//! `sm import --inventory` uses.
//!
//! ## Why a private bus at all
//!
//! Our daemon wants `org.freedesktop.secrets` and gnome-keyring provides the
//! same name; they cannot both hold it. Rather than negotiate, the assistant
//! stands up a bus nobody else can see, exported to the child alone, and puts
//! gnome-keyring on *that*. The real session bus is untouched, so a migration
//! runs happily after secret-manager is installed — which is exactly when a
//! user discovers they need one.
//!
//! ## Two things measured against a real gnome-keyring 50.0, not assumed
//!
//! The spec left both as open questions; both are now settled, and the
//! answers are load-bearing enough to record here.
//!
//! **`--start` is incompatible with `--unlock`.** The daemon refuses the
//! combination outright (`The --start option is incompatible with --unlock`)
//! and then fails to find a control socket, so the spec's four-word command
//! line does not run. [`PrivateKeyring::start`] omits `--start`, which is the
//! right flag to drop anyway: `--start` means "talk to the daemon that is
//! already running", and the entire point here is that we want a fresh one on
//! a bus of our own.
//!
//! **The stdin terminator is a newline, and it is stripped.** A keyring
//! created by feeding `abc\n` to `--unlock` is unlocked by a later `--unlock`
//! fed a bare `abc`, so the reader stops at the first newline and does not
//! keep it. [`PrivateKeyring::start`] writes the password followed by `\n` and
//! closes the pipe, which satisfies a newline-terminated reader and an
//! EOF-terminated one identically.

use super::formats::{
    ITEM_TYPE_CHAINED_KEYRING_PASSWORD, ITEM_TYPE_ENCRYPTION_KEY_PASSWORD,
    ITEM_TYPE_GENERIC_SECRET, ITEM_TYPE_NETWORK_PASSWORD, ITEM_TYPE_NOTE, MAX_SOURCE_BYTES,
};
use super::{ItemReport, Provenance, Refusal, SourceItem};
use crate::dbus::prompt::display_label;
use crate::dbus::proxies::{CollectionProxy, ItemProxy, PromptProxy, ServiceProxy, SessionProxy};
use crate::session::dh::KeyPair;
use crate::session::{ALGORITHM_DH, ALGORITHM_PLAIN, SessionCipher};
use crate::vault::format::escape_control;
use futures_util::StreamExt;
use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, Command};
use zbus::Connection;
use zbus::connection::Builder;
use zbus::proxy::CacheProperties;
use zbus::zvariant::{OwnedObjectPath, Value};
use zeroize::{Zeroize, Zeroizing};

// --------------------------------------------------------------------------
// Item types
// --------------------------------------------------------------------------

/// gnome-keyring's non-standard `org.freedesktop.Secret.Item.Type` property.
///
/// It is a **string**, not the `u32` the on-disk index uses, and it is the
/// signal the chained-item refusal is made on: the on-disk index's numeric
/// type is correct but only reachable with the file parser, and the live
/// property is what the walk already has in hand. Verified against
/// gnome-keyring 50.0, where every one of these round-trips through
/// `CreateItem` and back out of the property unchanged.
pub const TYPE_GENERIC: &str = "org.freedesktop.Secret.Generic";
/// `NETWORK_PASSWORD`. Flattens: our daemon exposes no `Type`.
pub const TYPE_NETWORK_PASSWORD: &str = "org.gnome.keyring.NetworkPassword";
/// `NOTE`. Flattens.
pub const TYPE_NOTE: &str = "org.gnome.keyring.Note";
/// A secret whose purpose is to unlock **another keyring**. Refused.
pub const TYPE_CHAINED_KEYRING: &str = "org.gnome.keyring.ChainedKeyring";
/// A secret whose purpose is to unlock an encryption key. Refused.
pub const TYPE_ENCRYPTION_KEY: &str = "org.gnome.keyring.EncryptionKey";
/// gnome-keyring's internal PKCS#11 bookkeeping. Flattens; `user.keystore`
/// itself is out of scope and never parsed.
pub const TYPE_PK_STORAGE: &str = "org.gnome.keyring.PkStorage";

/// The numeric type of a [`TYPE_PK_STORAGE`] item. [`super::formats`] names
/// the five types the refusal and the report need and stops there, and it is
/// not this module's file to extend, so the sixth lives here.
const ITEM_TYPE_PK_STORAGE: u32 = 5;

/// The on-disk index's numeric type for a live `Item.Type` string.
///
/// [`Refusal::ChainedKeyringItem`] and [`ItemReport::lost_item_type`] both
/// speak in the file format's numbering, so the two halves of a report say
/// the same thing about the same item whether it was reached through the
/// parser or through the bus. `None` for a type string this build does not
/// know — never a guess at the nearest number. `None` is not a report, and
/// the caller may not treat it as one: [`ExtractedItem::report`] turns it into
/// [`ItemReport::unknown_item_type`], carrying the string, because
/// [`ItemReport::lost_item_type`] has no room for a type that has no number
/// and its own `None` already means "nothing was lost".
pub fn item_type_code(item_type: &str) -> Option<u32> {
    match item_type {
        TYPE_GENERIC => Some(ITEM_TYPE_GENERIC_SECRET),
        TYPE_NETWORK_PASSWORD => Some(ITEM_TYPE_NETWORK_PASSWORD),
        TYPE_NOTE => Some(ITEM_TYPE_NOTE),
        TYPE_CHAINED_KEYRING => Some(ITEM_TYPE_CHAINED_KEYRING_PASSWORD),
        TYPE_ENCRYPTION_KEY => Some(ITEM_TYPE_ENCRYPTION_KEY_PASSWORD),
        TYPE_PK_STORAGE => Some(ITEM_TYPE_PK_STORAGE),
        _ => None,
    }
}

/// True for the two item types that are refused, listed, and never written.
///
/// Deliberately an allow-list of the two the format defines rather than a
/// prefix match on `org.gnome.keyring.`: `NetworkPassword` and `Note` share
/// that prefix and are ordinary user secrets, and refusing them would strand
/// data. An unrecognised type is *not* treated as an unlock credential; it is
/// carried, and the report says its type was lost.
pub fn is_unlock_credential_type(item_type: &str) -> bool {
    matches!(item_type, TYPE_CHAINED_KEYRING | TYPE_ENCRYPTION_KEY)
}

// --------------------------------------------------------------------------
// Who actually owns org.freedesktop.secrets
// --------------------------------------------------------------------------

/// The program name a `--from gnome-keyring` session-bus route requires.
pub const GNOME_KEYRING_PROGRAM: &str = "gnome-keyring-daemon";

/// Our own daemon's program name. An owner that is *us* is the ordinary
/// post-install state, not a foreign provider to warn about.
pub const OUR_PROGRAM: &str = "secret-manager";

/// The name both providers, and we, compete for.
pub const SECRETS_BUS_NAME: &str = "org.freedesktop.secrets";

/// Who holds [`SECRETS_BUS_NAME`] on the real session bus.
///
/// This exists because the obvious design — connect to the well-known name,
/// enumerate, copy — has a failure that is not theoretical. On the author's
/// machine that name is owned by `/usr/bin/ksecretd`, KWallet's Secret
/// Service bridge, while gnome-keyring sits masked with its keyrings unread on
/// disk. `--from gnome-keyring` down the session-bus route would have silently
/// migrated KWallet data, and verification would have agreed with itself
/// because both halves read the same wrong source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BusOwner {
    /// Nothing owns the name.
    Unowned,
    /// Something owns it, but `ps` could not say what. Treated as a refusal:
    /// an unidentified owner is not evidence of the right one.
    Unidentified { pid: u32 },
    /// `pid` owns it and `ps -p <pid> -o cmd=` said `command`.
    Process { pid: u32, command: String },
}

impl BusOwner {
    /// True only for a `Process` whose argv[0] basename is
    /// [`GNOME_KEYRING_PROGRAM`].
    pub fn is_gnome_keyring(&self) -> bool {
        match self {
            BusOwner::Process { command, .. } => {
                program_name(command) == Some(GNOME_KEYRING_PROGRAM)
            }
            _ => false,
        }
    }

    /// True for a `Process` whose argv[0] basename is [`OUR_PROGRAM`].
    pub fn is_secret_manager(&self) -> bool {
        match self {
            BusOwner::Process { command, .. } => program_name(command) == Some(OUR_PROGRAM),
            _ => false,
        }
    }

    /// What to *tell the user* about this owner before a private-bus
    /// gnome-keyring extraction, or `None` when there is nothing to say.
    ///
    /// The private-bus route reads `$XDG_DATA_HOME/keyrings` directly and
    /// never touches the session bus, so who owns [`SECRETS_BUS_NAME`] cannot
    /// block it and is not a precondition for it. What the owner *does* say is
    /// which provider the user's secrets have actually been going to: a name
    /// held by `ksecretd` means the keyrings on disk may be stale, and
    /// "migrate gnome-keyring" would faithfully migrate a set of keyrings
    /// nobody has written to since. That is a statement about the source, not
    /// about reachability, so it is a warning and never a refusal — the user
    /// may well be migrating exactly the stale keyrings on purpose.
    ///
    /// The two states this is deliberately silent about are the two the
    /// install guides produce: nothing owns the name (gnome-keyring masked,
    /// our daemon not yet started) and *we* own it. Refusing either is how
    /// this command came to be unusable in the state it exists for.
    pub fn foreign_provider_warning(&self) -> Option<String> {
        match self {
            BusOwner::Unowned => None,
            _ if self.is_gnome_keyring() || self.is_secret_manager() => None,
            BusOwner::Unidentified { .. } => Some(format!(
                "{}, so this run cannot tell which provider your secrets have actually been \
                 going to. If it is not gnome-keyring, the keyrings read below are stale and \
                 this import will faithfully copy them.",
                self.describe()
            )),
            BusOwner::Process { .. } => Some(format!(
                "{}, which is neither {GNOME_KEYRING_PROGRAM} nor {OUR_PROGRAM}. Your secrets \
                 have been going to that provider, so the gnome-keyring files read below may \
                 be stale or empty and this import will faithfully copy whatever they hold. \
                 If you meant to migrate that provider, run `sm import` against it instead.",
                self.describe()
            )),
        }
    }

    /// A sentence naming the owner, safe to print. The command line belongs to
    /// another same-uid process and is therefore attacker-controlled text, so
    /// it goes through [`display_label`] before it reaches a terminal.
    pub fn describe(&self) -> String {
        match self {
            BusOwner::Unowned => format!("nothing owns {SECRETS_BUS_NAME}"),
            BusOwner::Unidentified { pid } => {
                format!("pid {pid} owns {SECRETS_BUS_NAME} but could not be identified")
            }
            BusOwner::Process { pid, command } => {
                format!(
                    "{} (pid {pid}) owns {SECRETS_BUS_NAME}",
                    display_label(command)
                )
            }
        }
    }
}

/// argv[0]'s basename: the first whitespace-separated token of a `ps -o cmd=`
/// line, with a kernel-thread's square brackets removed and the directory
/// stripped.
///
/// `None` for output with no token at all, which is what an unreadable or
/// empty `ps` gives and which must never be confused with a match.
pub fn program_name(command: &str) -> Option<&str> {
    let token = command.split_whitespace().next()?;
    let token = token.trim_start_matches('[').trim_end_matches(']');
    let base = token.rsplit('/').next()?;
    (!base.is_empty()).then_some(base)
}

/// The `PID=` line of `busctl --user status <name>`.
///
/// `busctl` prints a block of `KEY=VALUE` lines; only the first `PID=` is
/// read, and a line that is not a decimal `u32` is treated as no answer
/// rather than as a zero.
pub fn parse_busctl_pid(status: &str) -> Option<u32> {
    status
        .lines()
        .find_map(|line| line.trim().strip_prefix("PID="))
        .and_then(|v| v.trim().parse().ok())
}

/// Turns the two command outputs into a [`BusOwner`], with no I/O.
///
/// Split out from [`secrets_bus_owner`] precisely so the four cases the
/// refusal turns on — right owner, wrong owner, no owner, unreadable `ps` —
/// are testable without a bus and without a process table.
///
/// `busctl_status` is `None` when `busctl` failed or the name is not owned;
/// `ps_command` is `None` when `ps` failed. Whitespace-only `ps` output is the
/// same as none: it identifies nothing.
pub fn classify_bus_owner(busctl_status: Option<&str>, ps_command: Option<&str>) -> BusOwner {
    let Some(pid) = busctl_status.and_then(parse_busctl_pid) else {
        return BusOwner::Unowned;
    };
    match ps_command.map(str::trim) {
        Some(cmd) if !cmd.is_empty() => BusOwner::Process {
            pid,
            command: cmd.to_string(),
        },
        _ => BusOwner::Unidentified { pid },
    }
}

/// Runs `busctl --user status org.freedesktop.secrets` and then
/// `ps -p <pid> -o cmd=`, each under [`COMMAND_TIMEOUT`].
///
/// `extract_gnome` in `src/cli/import.rs` calls this for
/// [`BusOwner::foreign_provider_warning`] alone: the private-bus route it uses
/// stands up its own gnome-keyring against the files on disk, so the session
/// bus's owner cannot make the extraction read the wrong provider — it can
/// only tell the user that the files on disk are not where their secrets have
/// been going. A session-bus route, if one is ever added, is the caller that
/// would need this as a *precondition*.
pub async fn secrets_bus_owner() -> Result<BusOwner, GnomeError> {
    let status = run_capture("busctl", &["--user", "status", SECRETS_BUS_NAME]).await?;
    let Some(pid) = status.as_deref().and_then(parse_busctl_pid) else {
        return Ok(BusOwner::Unowned);
    };
    let ps = run_capture("ps", &["-p", &pid.to_string(), "-o", "cmd="]).await?;
    Ok(classify_bus_owner(status.as_deref(), ps.as_deref()))
}

/// The absolute path of a helper program, resolved only against
/// `/usr/bin` and `/bin`.
///
/// A bare name resolves through whatever `PATH` this process inherited, which
/// a caller controls; the daemons and tools spawned here are named absolutely
/// so the lookup is pinned. When neither directory holds the program the bare
/// name is returned and the spawn fails with the usual `Spawn` error rather
/// than a resolution error of our own.
fn program_path(name: &str) -> PathBuf {
    for dir in ["/usr/bin", "/bin"] {
        let candidate = PathBuf::from(dir).join(name);
        if candidate.is_file() {
            return candidate;
        }
    }
    PathBuf::from(name)
}

/// The environment the two daemon children get: nothing inherited except a
/// pinned `PATH` and the location variables a daemon needs to find its user's
/// runtime, then the caller adds its own.
///
/// The daemons outlive the spawn call and read the world through their
/// environment; an inherited `DBUS_SESSION_BUS_ADDRESS` would point the fresh
/// bus at the real one, and an inherited `GNOME_KEYRING_*` would point the
/// fresh keyring at the real daemon's control socket. `env_clear` removes all
/// of that at once, and the allow-list below is what comes back.
fn minimal_env(cmd: &mut Command) {
    cmd.env_clear();
    cmd.env("PATH", "/usr/bin:/bin");
    for key in ["HOME", "TMPDIR", "XDG_RUNTIME_DIR", "USER", "LOGNAME"] {
        if let Some(value) = std::env::var_os(key) {
            cmd.env(key, value);
        }
    }
}

/// Runs a command to completion under [`COMMAND_TIMEOUT`], returning its
/// stdout when it exits 0 and `None` when it does not.
///
/// A non-zero exit is not an error here: `busctl status` exits non-zero for a
/// name nobody owns, and `ps` for a pid that has gone. Both are answers.
async fn run_capture(program: &str, args: &[&str]) -> Result<Option<String>, GnomeError> {
    let child = Command::new(program_path(program))
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| GnomeError::Spawn {
            program: program.to_string(),
            message: e.to_string(),
        })?;
    let out = tokio::time::timeout(COMMAND_TIMEOUT, child.wait_with_output())
        .await
        .map_err(|_| GnomeError::CommandTimeout {
            program: program.to_string(),
            waited: COMMAND_TIMEOUT,
        })?
        .map_err(|e| GnomeError::Spawn {
            program: program.to_string(),
            message: e.to_string(),
        })?;
    if !out.status.success() {
        return Ok(None);
    }
    // Lossy, not `from_utf8().ok()`: a stray non-UTF-8 byte in a `ps` line
    // must not turn into the same `None` that means "the command failed",
    // which is the answer that decides an owner is unidentified.
    Ok(Some(String::from_utf8_lossy(&out.stdout).into_owned()))
}

// --------------------------------------------------------------------------
// Errors and time bounds
// --------------------------------------------------------------------------

/// How long a helper command (`busctl`, `ps`) may take.
pub const COMMAND_TIMEOUT: Duration = Duration::from_secs(5);
/// How long one D-Bus method call or property read may take.
pub const CALL_TIMEOUT: Duration = Duration::from_secs(20);
/// How long the private bus and gnome-keyring have to come up.
pub const STARTUP_TIMEOUT: Duration = Duration::from_secs(20);
/// How long to wait for a `Prompt.Completed` before naming it unanswerable.
///
/// On a private bus there is no prompter, so the honest expectation is that
/// this always expires; it is short because a wait nobody can end is pure
/// latency, and long enough that a prompter which *is* present (a session-bus
/// route, a test) has room to answer.
pub const PROMPT_TIMEOUT: Duration = Duration::from_secs(10);
/// One aggregate bound on the per-item `GetSecret` fallback.
///
/// Without it the fallback is N × [`CALL_TIMEOUT`] with no deadline at all, so
/// a source that answers every call slowly turns a batch that failed once into
/// an unbounded walk. The batch is the fast path; this is the slow one, and it
/// gets a budget rather than a per-call allowance.
pub const SECRETS_FALLBACK_TIMEOUT: Duration = Duration::from_secs(120);

/// The most collections a source may offer before the walk refuses it.
///
/// Nothing on the wire bounds these lists, and the failure this module exists
/// to avoid is a truncated migration that reports success — so the cap refuses
/// rather than truncating. Both numbers are far above any real keyring: the
/// author's machine has 3 collections and 28 items in the largest.
pub const MAX_COLLECTIONS: usize = 512;
/// The most items one collection may offer before the walk refuses it.
pub const MAX_ITEMS_PER_COLLECTION: usize = 100_000;
/// How much of `gnome-keyring-daemon`'s stderr is kept for an error message.
///
/// Bounded on purpose in both directions: an unread pipe fills at 64 KiB and
/// blocks the child, and an unbounded buffer lets the child choose how much of
/// our memory to spend. What matters is the first line or two — "The password
/// or PIN is incorrect" — which is why the *head* is kept and the tail
/// dropped.
pub const STDERR_CAPTURE_LIMIT: usize = 4096;
/// How much escaped peer text an error message carries. Bytes, not characters,
/// and applied *after* escaping, so the bound is on what is printed.
const ERROR_TEXT_LIMIT: usize = 512;
/// The largest total of secret bytes one walk will hold, across all items.
///
/// `MAX_ITEMS_PER_COLLECTION` alone bounds nothing that matters here: one
/// secret may be many megabytes, so a bounded count of them is still an
/// unbounded number of resident bytes. 256 MiB is orders of magnitude above
/// any real keyring and still a bound. Exceeding it aborts the walk — the
/// session close in `extract` still runs — mirroring `kwallet::MAX_SECRET_BYTES`.
pub const MAX_SECRET_BYTES: usize = 256 << 20;
/// The most files `KeyringSnapshot::create` will copy, and the most bytes in
/// total.
///
/// The snapshot feeds a child that rewrites what it opens, so every regular
/// file in the source directory is copied — and nothing on disk bounds how
/// many of them there are or how large they grow. The per-file bound is
/// `formats::MAX_SOURCE_BYTES`, the same ceiling `read_source` enforces; this
/// is the budget across all of them, so a directory of many almost-huge files
/// cannot become unbounded memory and disk either. Both refuse rather than
/// truncate: a thinner source would be measured against the wrong header.
const MAX_SNAPSHOT_FILES: usize = 128;
const MAX_SNAPSHOT_BYTES: u64 = 256 << 20;

/// Peer text on its way into an **error message**, sanitised without being
/// truncated into uselessness.
///
/// [`display_label`] is the *dialog-label* sanitiser: it collapses whitespace
/// and cuts at 64 characters, which is the right rule for a label and the
/// wrong one for prose. gnome-keyring's first stderr line is an ~85-character
/// capabilities warning, so a 64-character cut is *guaranteed* to drop "The
/// password or PIN is incorrect" — the one thing [`STDERR_CAPTURE_LIMIT`]'s
/// 4 KiB exists to preserve — and the same cut took the cause back out of
/// [`GnomeError::KeyringNeverReady`] and out of the batch cause threaded into
/// a per-item failure.
///
/// [`escape_control`] satisfies the `CLAUDE.md` rule that peer text is
/// sanitised before a log or a dialog — every control character and invisible
/// formatter becomes `\xNN` — and leaves the sentence intact. The cap that
/// remains is [`ERROR_TEXT_LIMIT`], on a character boundary, which is a bound
/// on how much of our output a hostile peer can choose and not a rule about
/// labels.
fn error_text(text: &str) -> String {
    let escaped = escape_control(text);
    if escaped.len() <= ERROR_TEXT_LIMIT {
        return escaped;
    }
    let mut cut = ERROR_TEXT_LIMIT;
    while !escaped.is_char_boundary(cut) {
        cut -= 1;
    }
    let mut out = escaped[..cut].to_string();
    out.push('\u{2026}');
    out
}

/// Every way this module can fail, each one named so a report can say which.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum GnomeError {
    #[error("could not run {program}: {message}")]
    Spawn { program: String, message: String },

    #[error("{program} did not finish within {waited:?}")]
    CommandTimeout { program: String, waited: Duration },

    #[error("the private session bus did not print an address within {waited:?}")]
    BusNeverReady { waited: Duration },

    /// `detail` carries what the daemon said on stderr and the last error the
    /// readiness poll saw, so the message can name the cause — a wrong
    /// password above all — instead of guessing at it.
    #[error(
        "gnome-keyring-daemon did not take {SECRETS_BUS_NAME} on the private bus within \
         {waited:?}: {detail}"
    )]
    KeyringNeverReady { waited: Duration, detail: String },

    #[error("gnome-keyring-daemon exited before it took {SECRETS_BUS_NAME}: {detail}")]
    KeyringExited { detail: String },

    /// The sharpest edge in the design. A keyring that is neither the login
    /// keyring nor chained to it needs an unlock prompt, and on a private bus
    /// with no prompter the prompt object is returned and then never
    /// completes. Blocking on it hangs the tool forever, so the wait is bound
    /// and its expiry is this error.
    #[error(
        "the unlock prompt for {object} cannot be answered: no prompter is running on the \
         private bus, and nothing completed it within {waited:?}"
    )]
    UnanswerablePrompt { object: String, waited: Duration },

    #[error("the unlock prompt for {object} was dismissed")]
    PromptDismissed { object: String },

    /// `Service.Unlock` returned neither the object nor a prompt. Distinct
    /// from [`GnomeError::UnanswerablePrompt`], which used to be reported
    /// here and made three false claims about it: there was no prompt, no
    /// prompter was involved, and nothing was waited for.
    #[error(
        "gnome-keyring did not unlock {object} and offered no prompt to unlock it with, \
         so nothing further can be tried"
    )]
    UnlockOfferedNothing { object: String },

    /// The prompt completed without being dismissed, and the objects it says
    /// it unlocked do not include the one we asked for. A prompt that
    /// completes is not a prompt that succeeded, and this is the difference.
    #[error("the unlock prompt for {object} completed without unlocking it")]
    PromptUnlockedNothing { object: String },

    #[error(
        "the source offered {count} {what}, over the {limit} this import accepts; \
         refusing rather than reading part of it"
    )]
    TooMany {
        what: &'static str,
        count: usize,
        limit: usize,
    },

    #[error("{call} failed: {message}")]
    Bus { call: String, message: String },

    #[error("{call} did not answer within {waited:?}")]
    CallTimeout { call: String, waited: Duration },

    #[error(
        "this gnome-keyring holds no keyring named '{container}'; it holds {available}. \
         Import names one keyring, so a name that matches none of them would import \
         nothing and report success"
    )]
    NoSuchCollection {
        container: String,
        /// The labels the walk did see, already sanitized for display.
        available: String,
    },

    /// Two collections share the display name the walk was told to import.
    ///
    /// Matching `only_container` against the display label is what lets one
    /// invocation name one keyring, and two keyrings can carry the same label.
    /// Importing both into a destination named after one of them would produce
    /// the mislabelled union `only_container` exists to prevent, so the walk
    /// refuses instead. Both object paths are named — sanitised at the call
    /// site — so the user can tell the two apart.
    #[error(
        "more than one collection is named '{container}' ({first} and {second}); \
         refusing to import their union into one destination"
    )]
    AmbiguousCollection {
        container: String,
        first: String,
        second: String,
    },

    #[error("could not open a session with gnome-keyring: {message}")]
    NoSession { message: String },

    #[error("could not decrypt a secret off the transport: {message}")]
    Decrypt { message: String },
}

/// Bounds one D-Bus call and names it in both failure modes.
async fn call<T>(
    name: &str,
    fut: impl std::future::Future<Output = zbus::Result<T>>,
) -> Result<T, GnomeError> {
    tokio::time::timeout(CALL_TIMEOUT, fut)
        .await
        .map_err(|_| GnomeError::CallTimeout {
            call: name.to_string(),
            waited: CALL_TIMEOUT,
        })?
        .map_err(|e| GnomeError::Bus {
            call: name.to_string(),
            message: e.to_string(),
        })
}

/// Builds any of the generated proxies at `path`, with property caching off
/// and both failure modes named by `call`.
///
/// The same six-line builder-plus-`map_err` block appeared once per proxy
/// type; the generated proxies all implement [`zbus::proxy::Defaults`] and
/// `From<zbus::Proxy>`, which is exactly the bound that lets one function
/// stand in for all of them.
async fn proxy_at<T>(conn: &Connection, call: &str, path: &OwnedObjectPath) -> Result<T, GnomeError>
where
    T: zbus::proxy::Defaults + From<zbus::Proxy<'static>>,
{
    zbus::proxy::Builder::<'static, T>::new(conn)
        .path(path.clone())
        .map_err(|e| GnomeError::Bus {
            call: call.to_string(),
            message: e.to_string(),
        })?
        .cache_properties(CacheProperties::No)
        .build()
        .await
        .map_err(|e| GnomeError::Bus {
            call: call.to_string(),
            message: e.to_string(),
        })
}

/// [`proxy_at`] for a proxy that carries its own default path.
async fn proxy_default<T>(conn: &Connection, call: &str) -> Result<T, GnomeError>
where
    T: zbus::proxy::Defaults + From<zbus::Proxy<'static>>,
{
    zbus::proxy::Builder::<'static, T>::new(conn)
        .cache_properties(CacheProperties::No)
        .build()
        .await
        .map_err(|e| GnomeError::Bus {
            call: call.to_string(),
            message: e.to_string(),
        })
}

// --------------------------------------------------------------------------
// The private bus and the private daemon
// --------------------------------------------------------------------------

/// A child process that is killed on every exit path.
///
/// `kill_on_drop` covers the early return, the `?`, and the panic; [`reap`]
/// covers the ordinary path and additionally *waits*, so the process is gone
/// rather than merely signalled by the time the caller continues. A private
/// `dbus-daemon` and a `gnome-keyring-daemon` left running after the tool
/// exits is a leak with a user's keyrings open in it.
struct Reaped(Option<Child>);

impl Reaped {
    async fn reap(&mut self) {
        if let Some(mut child) = self.0.take() {
            let pid = child.id();
            if let Err(e) = child.start_kill() {
                tracing::warn!("could not signal private helper process {pid:?}: {e}");
            }
            match tokio::time::timeout(COMMAND_TIMEOUT, child.wait()).await {
                Ok(Ok(_)) => {}
                Ok(Err(e)) => {
                    tracing::warn!("waiting on private helper process {pid:?} failed: {e}");
                }
                Err(_) => {
                    tracing::warn!(
                        "private helper process {pid:?} did not exit within {COMMAND_TIMEOUT:?} \
                         after being signalled"
                    );
                }
            }
        }
    }
}

/// A mode-0700 directory that is removed when it drops.
///
/// `tempfile` is a dev-dependency and this is a shipped path, so rather than
/// promote it for one directory this creates the directory itself. That is
/// also the stronger version: `DirBuilder::mode` passes the permissions to
/// `mkdir(2)`, so the directory is never briefly world-readable the way a
/// create-then-`chmod` leaves it, and `create` on an existing path fails
/// rather than adopting a directory somebody else made.
struct PrivateDir(PathBuf);

impl PrivateDir {
    /// Under `TMPDIR`, with a random name from the `uuid` the crate already
    /// depends on.
    fn create() -> std::io::Result<PrivateDir> {
        let path =
            std::env::temp_dir().join(format!("sm-import-gkr-{}", uuid::Uuid::new_v4().simple()));
        std::os::unix::fs::DirBuilderExt::mode(&mut std::fs::DirBuilder::new(), 0o700)
            .create(&path)?;
        Ok(PrivateDir(path))
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for PrivateDir {
    fn drop(&mut self) {
        // gnome-keyring puts a control socket in here; the directory is ours
        // alone, so removing it whole is right. A failure cannot be returned
        // from `drop`, and swallowing it would leave a mode-0700 directory of
        // keyring copies behind with no word said — so it is logged, with the
        // path, and the leftover directory is named rather than silent.
        if let Err(e) = std::fs::remove_dir_all(&self.0) {
            tracing::warn!(
                "could not remove private directory {}: {e}; it is left behind",
                self.0.display()
            );
        }
    }
}

/// A private copy of a `keyrings/` directory, and the `XDG_DATA_HOME` that
/// points [`PrivateKeyring::start`] at it. Removed when it drops.
///
/// The child this feeds is **not a reader**: `gnome-keyring-daemon --unlock`
/// rewrites the keyrings it opens and creates a `login.keyring` where there is
/// none. Pointed at the user's own `$XDG_DATA_HOME` it does both to the files
/// the import exists to leave alone — including on a `--dry-run`, whose whole
/// promise is that nothing was written. No flag of ours suppresses those
/// writes, so the only way to keep the promise is to give the child a copy and
/// let it write to that.
pub struct KeyringSnapshot {
    dir: PrivateDir,
}

impl KeyringSnapshot {
    /// Copies every regular file in `source_dir` into `<private>/keyrings/`.
    ///
    /// Each copy is created 0600 before anything is written into it, and the
    /// directory above it is 0700 from `mkdir(2)` onwards, so the copies are
    /// never briefly readable by another user. A file that cannot be copied is
    /// an error and not a thinner source: an extraction that quietly read half
    /// the keyrings would be measured against the header of all of them.
    ///
    /// Bounded as the copy is made: these are foreign files, so each one is
    /// opened once, its size on the open handle is an early refusal at
    /// [`MAX_SOURCE_BYTES`], and the copy itself goes through
    /// `take(MAX_SOURCE_BYTES + 1)` — the `stat` alone bounds nothing, because
    /// the file can grow between the two syscalls. A running total across all
    /// files refuses past [`MAX_SNAPSHOT_BYTES`], and the file count refuses
    /// past [`MAX_SNAPSHOT_FILES`], so a directory of many almost-huge files
    /// is refused rather than copied.
    pub fn create(source_dir: &Path) -> Result<KeyringSnapshot, GnomeError> {
        use std::io::Read as _;
        use std::os::unix::fs::OpenOptionsExt as _;
        let io = |path: &Path, e: std::io::Error| GnomeError::Spawn {
            program: format!(
                "private copy of {}",
                display_label(&path.display().to_string())
            ),
            message: e.to_string(),
        };
        // A source file over the per-file ceiling, refused rather than
        // truncated into a copy the daemon would then fail to open.
        let too_large = |len: u64| GnomeError::TooMany {
            what: "bytes in one keyring file",
            count: len as usize,
            limit: MAX_SOURCE_BYTES as usize,
        };
        let dir = PrivateDir::create().map_err(|e| io(Path::new("the temp directory"), e))?;
        // gnome-keyring appends `keyrings/` to `XDG_DATA_HOME`, so the copy
        // has to sit under that name whatever the original was called.
        let dest = dir.path().join(KEYRINGS_SUBDIR);
        std::os::unix::fs::DirBuilderExt::mode(&mut std::fs::DirBuilder::new(), 0o700)
            .create(&dest)
            .map_err(|e| io(&dest, e))?;
        let mut files_seen = 0usize;
        let mut total_bytes = 0u64;
        for entry in std::fs::read_dir(source_dir).map_err(|e| io(source_dir, e))? {
            let entry = entry.map_err(|e| io(source_dir, e))?;
            if !entry.file_type().map_err(|e| io(source_dir, e))?.is_file() {
                continue;
            }
            files_seen += 1;
            if files_seen > MAX_SNAPSHOT_FILES {
                return Err(GnomeError::TooMany {
                    what: "files in the keyring directory",
                    count: files_seen,
                    limit: MAX_SNAPSHOT_FILES,
                });
            }
            let from = std::fs::File::open(entry.path()).map_err(|e| io(&entry.path(), e))?;
            let len = from.metadata().map_err(|e| io(&entry.path(), e))?.len();
            if len > MAX_SOURCE_BYTES {
                return Err(too_large(len));
            }
            let to = dest.join(entry.file_name());
            let mut target = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&to)
                .map_err(|e| io(&to, e))?;
            // One byte past the limit, so a file that grew after the `stat`
            // is refused rather than silently truncated into a copy that
            // blames the format.
            let copied = std::io::copy(&mut from.take(MAX_SOURCE_BYTES + 1), &mut target)
                .map_err(|e| io(&to, e))?;
            if copied > MAX_SOURCE_BYTES {
                return Err(too_large(copied));
            }
            total_bytes = total_bytes.saturating_add(copied);
            if total_bytes > MAX_SNAPSHOT_BYTES {
                return Err(GnomeError::TooMany {
                    what: "bytes in the keyring snapshot",
                    count: total_bytes as usize,
                    limit: MAX_SNAPSHOT_BYTES as usize,
                });
            }
        }
        Ok(KeyringSnapshot { dir })
    }

    /// The directory to hand [`extract_over_private_bus`] or
    /// [`PrivateKeyring::start`] as the child's `XDG_DATA_HOME`.
    pub fn data_home(&self) -> &Path {
        self.dir.path()
    }
}

/// The directory gnome-keyring reads under `XDG_DATA_HOME`.
pub const KEYRINGS_SUBDIR: &str = "keyrings";

/// The head of a child's stderr, collected by a task so the pipe never fills.
///
/// A `gnome-keyring-daemon` that refuses the password says so on stderr and
/// nowhere else; piping that and never reading it threw away the cause of
/// every startup failure and, at 64 KiB, would have blocked the child.
#[derive(Clone, Default)]
struct StderrTail {
    text: Arc<Mutex<String>>,
    /// The first read error the drain task hit, if any. Kept rather than
    /// discarded: an empty capture and a failed capture are different facts,
    /// and `detail` reports them differently.
    read_error: Arc<Mutex<Option<String>>>,
}

impl StderrTail {
    /// Reads `stderr` to EOF on a task, keeping at most
    /// [`STDERR_CAPTURE_LIMIT`] bytes.
    fn drain(stderr: tokio::process::ChildStderr) -> StderrTail {
        let tail = StderrTail::default();
        let sink = tail.text.clone();
        let failed = tail.read_error.clone();
        tokio::spawn(async move {
            let mut stderr = stderr;
            let mut buf = [0u8; 1024];
            loop {
                match stderr.read(&mut buf).await {
                    Ok(0) => return,
                    Err(e) => {
                        if let Ok(mut held) = failed.lock()
                            && held.is_none()
                        {
                            *held = Some(e.to_string());
                        }
                        return;
                    }
                    Ok(n) => {
                        let Ok(mut held) = sink.lock() else { return };
                        if held.len() >= STDERR_CAPTURE_LIMIT {
                            continue;
                        }
                        let room = STDERR_CAPTURE_LIMIT - held.len();
                        let chunk = &buf[..n.min(room)];
                        held.push_str(&String::from_utf8_lossy(chunk));
                    }
                }
            }
        });
        tail
    }

    /// What the daemon said, sanitised: it is peer text on its way to a
    /// terminal, so it goes through [`error_text`] — escaped, not truncated at
    /// a label's 64 characters, because the cause is usually on the *second*
    /// line and a label cut would take exactly it. `None` when it said
    /// nothing.
    fn text(&self) -> Option<String> {
        let held = self.text.lock().ok()?;
        let trimmed = held.trim();
        (!trimmed.is_empty()).then(|| error_text(trimmed))
    }

    /// `detail` for an error, combining what the daemon said with whatever
    /// else the caller knows. Never empty, so no message ends in a colon.
    ///
    /// Three absences, three messages: nothing said, the capture itself
    /// failed, and the capture's lock poisoned — the last is ours, not the
    /// daemon's, and it must not read as the daemon's silence.
    fn detail(&self, fallback: &str) -> String {
        if let Some(said) = self.text() {
            let mut out = format!("{fallback}; gnome-keyring-daemon said: {said}");
            if let Ok(held) = self.read_error.lock()
                && let Some(e) = held.as_deref()
            {
                out.push_str("; the stderr capture also failed: ");
                out.push_str(&error_text(e));
            }
            return out;
        }
        if self.text.lock().is_err() {
            return format!("{fallback}; the captured stderr could not be read");
        }
        match self.read_error.lock().ok().and_then(|held| held.clone()) {
            Some(e) => format!(
                "{fallback}; it printed nothing on stderr, and the stderr capture failed: {}",
                error_text(&e)
            ),
            None => format!("{fallback}; it printed nothing on stderr"),
        }
    }
}

/// A running gnome-keyring on a session bus nobody else can see.
///
/// Both children are killed on every exit path, and there is no `Drop` impl on
/// this struct doing it: each child is a [`Reaped`], spawned with
/// `kill_on_drop(true)`, so dropping this — on a panic or an early return —
/// drops the two `Child`s and signals them. [`PrivateKeyring::shutdown`] is
/// the ordinary path and additionally *waits*, so by the time it returns the
/// processes are gone rather than merely signalled. That is the difference
/// between the two, and it is why both exist.
pub struct PrivateKeyring {
    bus: Reaped,
    keyring: Reaped,
    address: String,
    /// What the private gnome-keyring printed on stderr, so a failure can
    /// name its cause instead of saying the password "may" be wrong.
    stderr: StderrTail,
    /// Mode-0700, removed on drop, and never `/run/user/<uid>/keyring`: a
    /// private control directory is what keeps this daemon from colliding
    /// with a real one.
    _control_dir: PrivateDir,
}

impl PrivateKeyring {
    /// The address of the private bus, for [`Connection`].
    pub fn address(&self) -> &str {
        &self.address
    }

    /// Starts `dbus-daemon --session` and, against it, a
    /// `gnome-keyring-daemon --components=secrets` unlocked with `password`.
    ///
    /// The password is written to the child's **stdin** and closed. It never
    /// reaches argv (world-readable through `/proc`), a file, or a log; the
    /// only copy this function makes is the newline-terminated one it writes,
    /// and that is `Zeroizing`.
    ///
    /// `data_home` overrides `XDG_DATA_HOME` for the child, which is how
    /// gnome-keyring finds `keyrings/`. It is **required**, and it must not be
    /// the user's own: this child is not a reader. `gnome-keyring-daemon
    /// --unlock` rewrites the keyrings it opens and creates a `login.keyring`
    /// where there is none, so pointed at the real directory it writes to the
    /// very files a migration — and a `--dry-run` above all — exists to leave
    /// alone. A migration passes [`KeyringSnapshot::data_home`]; a test passes
    /// a directory of its own. There is no value here that means "the user's
    /// own", which is why the parameter is not an `Option`. It is set on the
    /// child alone, so the process running the import is unaffected.
    pub async fn start(
        password: &Zeroizing<Vec<u8>>,
        data_home: &Path,
    ) -> Result<PrivateKeyring, GnomeError> {
        let control_dir = PrivateDir::create().map_err(|e| GnomeError::Spawn {
            program: "control directory".into(),
            message: e.to_string(),
        })?;

        let mut bus_cmd = Command::new(program_path("dbus-daemon"));
        bus_cmd
            // No `--address`: the packaged session.conf listens under
            // `/tmp`, and a socket path we chose ourselves inside a long
            // temp directory overflows `sun_path` — a 108-byte limit that
            // fails as "Socket name too long" and looks like a bug in
            // dbus.
            .args(["--session", "--nofork", "--nopidfile", "--print-address"])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true);
        minimal_env(&mut bus_cmd);
        let mut bus = Reaped(Some(bus_cmd.spawn().map_err(|e| GnomeError::Spawn {
            program: "dbus-daemon".into(),
            message: e.to_string(),
        })?));

        let address = match read_address(&mut bus).await {
            Ok(a) => a,
            Err(e) => {
                bus.reap().await;
                return Err(e);
            }
        };

        let mut started = Command::new(program_path(GNOME_KEYRING_PROGRAM));
        // Cleared first: the child must not inherit the real session's
        // `DBUS_SESSION_BUS_ADDRESS` or `GNOME_KEYRING_*`, which would point
        // it at the live daemon. The `env_remove` lines below are then
        // belt-and-braces rather than load-bearing, and they stay so the
        // requirement reads at the place it is enforced.
        minimal_env(&mut started);
        started
            // `--start` is rejected alongside `--unlock` by gnome-keyring 50,
            // and would be the wrong flag regardless: it means "reuse the
            // daemon already running", and this needs a fresh one.
            .args(["--foreground", "--components=secrets", "--unlock"])
            .arg(format!(
                "--control-directory={}",
                control_dir.path().display()
            ))
            .env("DBUS_SESSION_BUS_ADDRESS", &address)
            // The child must not find the *real* daemon's control socket and
            // defer to it; `--control-directory` is only half of that.
            .env_remove("GNOME_KEYRING_CONTROL")
            .env_remove("GNOME_KEYRING_PID")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .env("XDG_DATA_HOME", data_home);

        let mut child = started.spawn().map_err(|e| GnomeError::Spawn {
            program: GNOME_KEYRING_PROGRAM.into(),
            message: e.to_string(),
        })?;
        // Drained immediately: an unread 64 KiB pipe blocks the child, and
        // the only account of a wrong password is on it.
        let stderr = match child.stderr.take() {
            Some(pipe) => StderrTail::drain(pipe),
            None => StderrTail::default(),
        };
        let keyring = Reaped(Some(child));

        let mut this = PrivateKeyring {
            bus,
            keyring,
            address,
            stderr,
            _control_dir: control_dir,
        };
        // From here every failure goes through `shutdown`, so neither child
        // can outlive an error.
        if let Err(e) = this.feed_password(password).await {
            this.shutdown().await;
            return Err(e);
        }
        if let Err(e) = this.await_name().await {
            this.shutdown().await;
            return Err(e);
        }
        Ok(this)
    }

    async fn feed_password(&mut self, password: &Zeroizing<Vec<u8>>) -> Result<(), GnomeError> {
        let stderr = self.stderr.clone();
        let Some(child) = self.keyring.0.as_mut() else {
            return Err(GnomeError::KeyringExited {
                detail: "the daemon was never spawned".into(),
            });
        };
        let Some(mut stdin) = child.stdin.take() else {
            return Err(GnomeError::KeyringExited {
                detail: "stdin was not a pipe".into(),
            });
        };
        // Password plus the terminator its reader stops at. Assembled in one
        // `Zeroizing` buffer so the concatenation is wiped too, not just the
        // caller's copy.
        let mut line = Zeroizing::new(Vec::with_capacity(password.len() + 1));
        line.extend_from_slice(password);
        line.push(b'\n');
        let write = async {
            stdin.write_all(&line).await?;
            stdin.flush().await?;
            Ok::<(), std::io::Error>(())
        };
        tokio::time::timeout(COMMAND_TIMEOUT, write)
            .await
            .map_err(|_| GnomeError::CommandTimeout {
                program: GNOME_KEYRING_PROGRAM.into(),
                waited: COMMAND_TIMEOUT,
            })?
            .map_err(|e| GnomeError::KeyringExited {
                detail: stderr.detail(&format!("writing the password failed: {e}")),
            })?;
        // Dropping the pipe is the EOF the reader may be waiting for.
        drop(stdin);
        Ok(())
    }

    /// Polls until gnome-keyring owns [`SECRETS_BUS_NAME`] on the private bus,
    /// or the child dies, or [`STARTUP_TIMEOUT`] expires.
    /// The bus connection is built **once** and the property call is what
    /// repeats. Rebuilding a whole `Connection` every 100 ms for up to 200
    /// iterations is 200 handshakes to answer one question, and discarding
    /// every error left [`GnomeError::KeyringNeverReady`] unable to say what
    /// had failed. The last error is kept and reported.
    async fn await_name(&mut self) -> Result<(), GnomeError> {
        let deadline = tokio::time::Instant::now() + STARTUP_TIMEOUT;
        let mut proxy: Option<ServiceProxy<'static>> = None;
        let mut last_error = String::from("it never answered a property call");
        loop {
            if let Some(child) = self.keyring.0.as_mut()
                && let Ok(Some(status)) = child.try_wait()
            {
                return Err(GnomeError::KeyringExited {
                    detail: self.stderr.detail(&format!("exited with {status}")),
                });
            }
            if proxy.is_none() {
                // The bus is up before the keyring is, so a connection that
                // fails here is retried; one that succeeds is kept.
                match Builder::address(self.address.as_str()) {
                    Ok(builder) => match builder.build().await {
                        Ok(conn) => {
                            match proxy_default::<ServiceProxy<'static>>(&conn, "Service").await {
                                Ok(p) => proxy = Some(p),
                                Err(e) => last_error = e.to_string(),
                            }
                        }
                        Err(e) => last_error = e.to_string(),
                    },
                    Err(e) => last_error = e.to_string(),
                }
            }
            if let Some(proxy) = proxy.as_ref() {
                match proxy.collections().await {
                    Ok(_) => return Ok(()),
                    Err(e) => last_error = e.to_string(),
                }
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(GnomeError::KeyringNeverReady {
                    waited: STARTUP_TIMEOUT,
                    detail: self.stderr.detail(&error_text(&last_error)),
                });
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    /// The pids of the private bus and the private keyring, while they live.
    ///
    /// Reaping is an invariant a test has to be able to *check*, and "the
    /// process is gone" is only checkable against the pid it had.
    pub fn child_pids(&self) -> (Option<u32>, Option<u32>) {
        (
            self.bus.0.as_ref().and_then(Child::id),
            self.keyring.0.as_ref().and_then(Child::id),
        )
    }

    /// Kills and waits for both children. Idempotent.
    pub async fn shutdown(&mut self) {
        self.keyring.reap().await;
        self.bus.reap().await;
    }
}

/// `dbus-daemon --print-address` writes one line and then serves. Reading it
/// is bounded: a `dbus-daemon` that starts and says nothing would otherwise
/// hang the tool here rather than at any of the places the design worried
/// about.
async fn read_address(bus: &mut Reaped) -> Result<String, GnomeError> {
    let Some(stdout) = bus.0.as_mut().and_then(|c| c.stdout.take()) else {
        return Err(GnomeError::Spawn {
            program: "dbus-daemon".into(),
            message: "stdout was not a pipe".into(),
        });
    };
    let mut line = String::new();
    let mut reader = BufReader::new(stdout);
    let n = tokio::time::timeout(STARTUP_TIMEOUT, reader.read_line(&mut line))
        .await
        .map_err(|_| GnomeError::BusNeverReady {
            waited: STARTUP_TIMEOUT,
        })?
        .map_err(|e| GnomeError::Spawn {
            program: "dbus-daemon".into(),
            message: e.to_string(),
        })?;
    let address = line.trim().to_string();
    if n == 0 || address.is_empty() {
        return Err(GnomeError::BusNeverReady {
            waited: STARTUP_TIMEOUT,
        });
    }
    Ok(address)
}

// --------------------------------------------------------------------------
// Prompts
// --------------------------------------------------------------------------

/// `/`, the Secret Service's "no prompt is needed" object path.
pub const NO_PROMPT: &str = "/";

/// Drives one prompt to completion, or names it unanswerable.
///
/// **Every prompt wait is bounded.** On the private bus no prompter is
/// running, so `Prompt.Prompt` returns and `Completed` never arrives; without
/// a timeout this is where the tool hangs forever, and a hang is the one
/// failure a migration assistant cannot report on. The wait expires into
/// [`GnomeError::UnanswerablePrompt`], and the prompt is dismissed on the way
/// out so the source daemon does not keep a dialog object alive for a caller
/// that has stopped listening.
///
/// The signal stream is subscribed **before** `Prompt` is called: a prompter
/// that answers instantly would otherwise complete into a stream that does not
/// exist yet, and the wait would expire on a prompt that had already
/// succeeded.
pub async fn await_prompt(
    conn: &Connection,
    prompt: &OwnedObjectPath,
    timeout: Duration,
) -> Result<zbus::zvariant::OwnedValue, GnomeError> {
    let proxy: PromptProxy<'static> = proxy_at(conn, "Prompt", prompt).await?;
    let mut completed = call("Prompt.Completed subscribe", proxy.receive_completed()).await?;
    call("Prompt.Prompt", proxy.prompt("")).await?;

    let signal = match tokio::time::timeout(timeout, completed.next()).await {
        Ok(Some(signal)) => Some(signal),
        // A stream that ends without a signal and a wait that expires are the
        // same outcome — no answer — so they take the same exit, dismiss
        // included. Dismissing on only one of the two left a dialog alive for
        // a caller that had stopped listening, which is the thing the doc
        // above promises does not happen.
        Ok(None) | Err(_) => None,
    };
    let Some(signal) = signal else {
        // Best effort: the dialog nobody can answer should not outlive us
        // either. Its failure is not interesting — the prompt is already
        // being reported as unanswerable.
        let _ = tokio::time::timeout(COMMAND_TIMEOUT, proxy.dismiss()).await;
        return Err(GnomeError::UnanswerablePrompt {
            object: prompt.as_str().to_string(),
            waited: timeout,
        });
    };
    let args = signal.args().map_err(|e| GnomeError::Bus {
        call: "Prompt.Completed".into(),
        message: e.to_string(),
    })?;
    if args.dismissed {
        return Err(GnomeError::PromptDismissed {
            object: prompt.as_str().to_string(),
        });
    }
    args.result.try_to_owned().map_err(|e| GnomeError::Bus {
        call: "Prompt.Completed".into(),
        message: e.to_string(),
    })
}

// --------------------------------------------------------------------------
// The walk
// --------------------------------------------------------------------------

/// The in-memory `session` collection: never on disk, dies with the daemon,
/// and must not be migrated. Identified by its object path's last segment,
/// which gnome-keyring fixes, rather than by its label, which is empty.
pub const SESSION_COLLECTION: &str = "session";

/// True for the collection that must be skipped.
pub fn is_session_collection(path: &str) -> bool {
    path.rsplit('/').next() == Some(SESSION_COLLECTION)
}

/// gnome-keyring numbers its items within a keyring, and the number is the
/// object path's last segment. It is the only stable handle a report can
/// carry for an item whose label is not worth trusting, so a path that does
/// not end in one yields `0` rather than a guess.
pub fn path_item_id(path: &str) -> u32 {
    path.rsplit('/')
        .next()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
}

/// One collection, as the report sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CollectionSummary {
    pub path: String,
    pub label: String,
    pub locked: bool,
    pub created: u64,
    pub modified: u64,
    /// How many items the collection holds, or `None` when the walk never got
    /// to look.
    ///
    /// `Option` rather than a count with a zero in it, because "nobody looked"
    /// and "there are none" are different facts and only one of them is worth
    /// printing. A collection skipped for an unanswerable prompt is skipped
    /// *before* `Collection.Items` is read, and as a `usize` this field then
    /// said `0` — so the note built from it read "holds 0 items … so none of
    /// them were read" for a keyring holding forty, which is the silent
    /// shortfall [`CollectionSummary::unanswerable_prompt`] exists to rule
    /// out. A caller printing `None` must say the number is unknown; the
    /// independent count from the cleartext header is where the real total
    /// comes from in that case.
    pub item_count: Option<usize>,
    /// The collection could not be unlocked because its prompt cannot be
    /// answered. Its items are absent from the extraction, and that is a
    /// reported error rather than a silent shortfall — which is also why
    /// [`CollectionSummary::item_count`] is `None` here rather than `0`.
    pub unanswerable_prompt: bool,
}

/// One item, with the source type the vault has no room for.
#[derive(Debug, Clone)]
pub struct ExtractedItem {
    pub item: SourceItem,
    /// gnome-keyring's `Item.Type` string, or `None` when the daemon does not
    /// expose the property at all. Never `None` because the read *failed*:
    /// an item whose type could not be read is refused rather than carried,
    /// so this is an absent property and never an unanswered one.
    pub item_type: Option<String>,
}

impl ExtractedItem {
    /// The per-item report, with the lost type filled in.
    ///
    /// `acl_downgrade` is set for **every** gnome-keyring item, not for the
    /// ones we can prove had an ACL. Format 0 records the per-item access list
    /// in the *encrypted* half, which this module never parses, so the choice
    /// is between flagging all of them and flagging none. Every item that
    /// moves does lose whatever ACL it had, and the direction that
    /// under-reports a security downgrade is the wrong one.
    /// A type this build does not recognise is reported as *itself*, not as
    /// `lost_item_type: None`. `item_type_code` answers `None` for both "there
    /// was nothing to lose" and "a type string arrived that this build cannot
    /// place", and collapsing the two is how a gnome-keyring type added after
    /// this was written would flatten with the report saying nothing at all.
    pub fn report(&self) -> ItemReport {
        let mut report = ItemReport::imported(&self.item);
        report.acl_downgrade = true;
        if let Some(item_type) = self.item_type.as_deref().filter(|t| *t != TYPE_GENERIC) {
            match item_type_code(item_type) {
                Some(code) => report.lost_item_type = Some(code),
                // Peer text on its way to a terminal and to the report file,
                // so it is sanitised here, at the one place that sets it.
                None => report.unknown_item_type = Some(display_label(item_type)),
            }
        }
        report
    }
}

/// One item the walk could not carry, and why. Label and reason only: both are
/// peer text on their way to a terminal and to the report file, so both are
/// sanitised on the way in — the label through [`display_label`], which is a
/// label; the reason through [`error_text`], because a reason cut at 64
/// characters is a reason nobody can act on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkippedEntry {
    pub label: String,
    pub reason: String,
}

/// Everything one walk produced.
#[derive(Debug, Clone)]
pub struct Extraction {
    pub items: Vec<ExtractedItem>,
    /// Items that were read *about* and never read: an unlock credential's
    /// secret is not fetched at all, and a cap violation's is dropped.
    pub refused: Vec<ItemReport>,
    /// Items the walk found and could not carry, for a reason
    /// [`Refusal`](crate::import::Refusal) does not name: the source daemon
    /// would not hand the secret over, or the session cipher would not decrypt
    /// what it did hand over.
    ///
    /// These are per-*item* failures and are treated as such — one item an ACL
    /// denies must not discard the four hundred already walked, which is
    /// exactly the policy `check_caps` states for a cap violation fourteen
    /// lines below the read. They are named rather than counted, because
    /// "something did not come across" is the one thing a migration report may
    /// not round off, and the CLI carries them into its own `not_migrated`
    /// section.
    ///
    /// They would be `Refusal`s if `src/import/mod.rs` had a variant for an
    /// unreadable secret; it has one for unreadable attributes and one for an
    /// unreadable item type, and inventing neither is why this list exists.
    pub skipped: Vec<SkippedEntry>,
    pub collections: Vec<CollectionSummary>,
    /// Why DH was not used, when it was not. `Some` for exactly the runs whose
    /// transport was `plain`, because [`open_session`] fills it in on every
    /// path that returns [`ALGORITHM_PLAIN`] — the caller asking for it as
    /// much as the source refusing DH. So this is the whole of what a reader
    /// needs to know about the transport, and it is the one the CLI prints.
    ///
    /// An `algorithm: &'static str` sat beside this and said the same thing
    /// less usefully: `plain` here is `Some(reason)`, `dh` is `None`, and
    /// nothing outside a test ever read the second copy. A field a report is
    /// never built from is not a record of anything.
    pub plain_fallback_reason: Option<String>,
    /// No item exposed `Item.Type`, so the chained-item refusal could not be
    /// evaluated on this source. A refusal that cannot fire is worse than
    /// none, because it looks like protection; the caller must say so.
    ///
    /// Set only when the property was *consulted* for at least one item and
    /// no item answered it with a type. An item whose type read failed does
    /// not clear this flag and does not need to: it is refused outright, so
    /// the refusal did fire for it. An item that never reached the type read
    /// at all — one refused earlier, for unreadable attributes — does not set
    /// it either, because nothing was asked about that item and a walk that
    /// asked nothing has established nothing. This is the backstop for a
    /// provider that has no `Type` property, and it was never a backstop for a
    /// single flaky read — which is why that case is refused per item rather
    /// than left to this flag.
    pub item_type_unavailable: bool,
}

impl Extraction {
    /// Collections whose unlock prompt could not be answered. Their items are
    /// missing, and the independent count from the cleartext header will say
    /// so — this names why.
    pub fn unanswerable_collections(&self) -> impl Iterator<Item = &CollectionSummary> {
        self.collections.iter().filter(|c| c.unanswerable_prompt)
    }

    /// The distinct containers the items came from, in walk order.
    ///
    /// A walk with no [`ExtractOptions::only_container`] covers *every*
    /// keyring the source daemon holds, so a caller that labels its
    /// destination collection after one of them is telling the truth only when
    /// this has one element. Either name the keyring in the options, or read
    /// this and label honestly; the caller must not assume it walked one.
    pub fn containers(&self) -> Vec<&str> {
        let mut out: Vec<&str> = Vec::new();
        for container in self
            .items
            .iter()
            .map(|e| e.item.provenance.container.as_str())
        {
            if !out.contains(&container) {
                out.push(container);
            }
        }
        out
    }
}

/// Options a caller can vary; every field has a defensible default.
///
/// The child's `XDG_DATA_HOME` is deliberately *not* one of them. It was, and
/// its default was the user's own directory — so the ergonomic call,
/// `extract_over_private_bus(&pw, &ExtractOptions::default())`, pointed a
/// daemon that writes at the files the import exists to leave alone. It is now
/// a [`KeyringSnapshot`] argument of [`extract_over_private_bus`], which no
/// `..Default::default()` can reach past.
#[derive(Debug, Clone)]
pub struct ExtractOptions {
    /// How long to wait on an unlock prompt before naming it unanswerable.
    pub prompt_timeout: Duration,
    /// Try `dh-ietf1024-sha256-aes128-cbc-pkcs7` first. Off only for a source
    /// known not to implement it; the fallback is automatic either way.
    pub prefer_dh: bool,
    /// Walk **only** the collection with this container name, or every
    /// collection when `None`.
    ///
    /// A gnome-keyring session exposes every keyring it holds, so an
    /// unfiltered walk is a walk of all of them. The caller, meanwhile,
    /// located *one* `.keyring` file and labels the destination collection
    /// after it — so on a user with `login.keyring` and `work.keyring` the
    /// items of both were written into one collection named after whichever
    /// the `default` file happened to name. A label that misdescribes its
    /// contents is the one thing a migration report must not produce, and the
    /// walk is the side that can fix it: the caller cannot un-mix items after
    /// the fact.
    ///
    /// The name is matched against the same string the walk records in each
    /// item's [`Provenance`]: `Collection.Label`, or the last segment of the
    /// object path when the label is empty. That is the keyring's display
    /// name, which is exactly what the `.keyring` header carries. A name that
    /// matches no collection is [`GnomeError::NoSuchCollection`] rather than
    /// an empty, successful import.
    pub only_container: Option<String>,
}

impl Default for ExtractOptions {
    fn default() -> Self {
        ExtractOptions {
            prompt_timeout: PROMPT_TIMEOUT,
            prefer_dh: true,
            only_container: None,
        }
    }
}

/// Starts a private bus and a private gnome-keyring, walks it, and shuts both
/// down — on the error path too.
///
/// The `snapshot` is what the private daemon is given as `XDG_DATA_HOME`, and
/// it is an argument rather than an option because there is no safe default
/// for it: the child writes to whatever directory it is pointed at. See
/// [`KeyringSnapshot`].
pub async fn extract_over_private_bus(
    password: &Zeroizing<Vec<u8>>,
    snapshot: &KeyringSnapshot,
    options: &ExtractOptions,
) -> Result<Extraction, GnomeError> {
    let mut keyring = PrivateKeyring::start(password, snapshot.data_home()).await?;
    let result = async {
        let conn = Builder::address(keyring.address())
            .map_err(|e| GnomeError::Bus {
                call: "connect".into(),
                message: e.to_string(),
            })?
            .build()
            .await
            .map_err(|e| GnomeError::Bus {
                call: "connect".into(),
                message: e.to_string(),
            })?;
        extract(&conn, options).await
    }
    .await;
    keyring.shutdown().await;
    result
}

/// Walks a Secret Service provider on `conn`.
///
/// Split from [`extract_over_private_bus`] so a caller that already has a
/// connection — a two-bus test fixture, say — reuses the same walk rather than
/// a second copy of it. There is no session-bus route: the private bus is what
/// lets a migration run after secret-manager owns the name, which is when a
/// user discovers they need one.
pub async fn extract(
    conn: &Connection,
    options: &ExtractOptions,
) -> Result<Extraction, GnomeError> {
    let service: ServiceProxy<'static> = proxy_default(conn, "Service").await?;

    let (session, cipher, plain_fallback_reason) =
        open_session(&service, options.prefer_dh).await?;

    let mut out = Extraction {
        items: Vec::new(),
        refused: Vec::new(),
        skipped: Vec::new(),
        collections: Vec::new(),
        plain_fallback_reason,
        item_type_unavailable: false,
    };

    // Every `?` from here to the close belongs to this block, not to the
    // function: the session holds the transport key, and closing it only on
    // the success path left one open on the source daemon for every failure.
    let walked = async {
        let mut saw_type = false;
        let mut saw_item = false;
        // Plaintext bytes successfully decrypted so far, across every
        // collection in this walk. The count bounds how many items are read;
        // only a byte budget bounds how much memory reading them takes. See
        // `MAX_SECRET_BYTES`.
        let secret_bytes = Cell::new(0usize);
        // Every container name the walk saw, filtered or not, so a filter that
        // matches nothing can say what was actually there.
        let mut seen_containers: Vec<String> = Vec::new();
        // Object paths that matched `only_container`, in walk order. Two
        // collections can share a display label, and importing both into a
        // destination named after one of them is the mislabelled union the
        // filter exists to prevent — so the second match refuses instead.
        let mut matched_paths: Vec<String> = Vec::new();

        let collections = call("Service.Collections", service.collections()).await?;
        if collections.len() > MAX_COLLECTIONS {
            return Err(GnomeError::TooMany {
                what: "collections",
                count: collections.len(),
                limit: MAX_COLLECTIONS,
            });
        }

        for path in collections {
            if is_session_collection(path.as_str()) {
                continue;
            }
            let collection: CollectionProxy<'static> = proxy_at(conn, "Collection", &path).await?;

            // A collection whose label, lock state or timestamps cannot be read
            // is not walked with guesses in their place: the label decides the
            // filter below, the lock state decides whether an unlock is tried,
            // and a defaulted `locked = true` would send every such collection
            // down the unanswerable-prompt path with a report that claims it
            // was locked. `call` already names the property, so `?` refuses
            // the run with the failing property in the message.
            let label = call("Collection.Label", collection.label()).await?;
            let container = if label.is_empty() {
                path.as_str().rsplit('/').next().unwrap_or("keyring").into()
            } else {
                label.clone()
            };
            seen_containers.push(container.clone());
            // Filtered here, before the unlock and before any summary: a
            // keyring the caller did not name must not be unlocked, must not
            // prompt, and must not contribute items to a collection labelled
            // after a different keyring. See `ExtractOptions::only_container`.
            if options
                .only_container
                .as_ref()
                .is_some_and(|only| *only != container)
            {
                continue;
            }
            // Pin by identity, not by display label: the match above is on
            // the label, and a second collection with the same label would
            // otherwise be walked into the same destination — the union
            // `only_container` exists to refuse. The error names both object
            // paths so the two collections can be told apart.
            if options.only_container.is_some() {
                if let Some(first) = matched_paths.first() {
                    return Err(GnomeError::AmbiguousCollection {
                        container: display_label(&container),
                        first: error_text(first),
                        second: error_text(path.as_str()),
                    });
                }
                matched_paths.push(path.as_str().to_string());
            }

            let locked = call("Collection.Locked", collection.locked()).await?;

            let mut summary = CollectionSummary {
                path: path.as_str().to_string(),
                label,
                locked,
                created: call("Collection.Created", collection.created()).await?,
                modified: call("Collection.Modified", collection.modified()).await?,
                item_count: None,
                unanswerable_prompt: false,
            };

            if locked {
                match unlock(conn, &service, &path, options.prompt_timeout).await {
                    Ok(()) => summary.locked = false,
                    Err(
                        GnomeError::UnanswerablePrompt { .. }
                        | GnomeError::PromptDismissed { .. }
                        | GnomeError::UnlockOfferedNothing { .. }
                        | GnomeError::PromptUnlockedNothing { .. },
                    ) => {
                        // Named, reported, and survivable: the other keyrings are
                        // still worth reading, and the report says this one was
                        // not.
                        summary.unanswerable_prompt = true;
                        out.collections.push(summary);
                        continue;
                    }
                    Err(e) => return Err(e),
                }
            }

            // A collection whose item list cannot be read is *not* made a
            // per-collection skip: unlike an item, it has no report to carry the
            // shortfall, so continuing here would drop an unknown number of items
            // out of a run that then claims success. Aborting is the loud
            // failure, and it is the right one.
            let items = call("Collection.Items", collection.items()).await?;
            if items.len() > MAX_ITEMS_PER_COLLECTION {
                return Err(GnomeError::TooMany {
                    what: "items in one collection",
                    count: items.len(),
                    limit: MAX_ITEMS_PER_COLLECTION,
                });
            }
            summary.item_count = Some(items.len());
            out.collections.push(summary);

            // Two passes. The first reads *about* every item; the second fetches
            // secrets for the ones that are not refused, so an unlock credential's
            // bytes never cross the bus at all.
            let mut candidates = Vec::new();
            for item_path in items {
                let meta = match read_metadata(conn, &item_path, &container).await? {
                    Metadata::Read(meta) => *meta,
                    Metadata::Refused(report) => {
                        // Refused before the `Type` read was reached — an
                        // unreadable attribute map returns above it — so this
                        // item establishes nothing either way about whether
                        // the provider has the property. Counting it as one
                        // that was asked is what made a collection whose every
                        // item failed its attribute read report "this provider
                        // exposes no item type" when nothing was ever asked.
                        out.refused.push(*report);
                        continue;
                    }
                };
                // Set only once the property has actually been consulted, so
                // `item_type_unavailable` below means "asked, and nothing
                // answered" rather than "never asked".
                saw_item = true;
                match &meta.item_type {
                    ItemType::Known(t) => {
                        saw_type = true;
                        if is_unlock_credential_type(t) {
                            let code =
                                item_type_code(t).unwrap_or(ITEM_TYPE_CHAINED_KEYRING_PASSWORD);
                            out.refused.push(ItemReport::refused(
                                meta.provenance,
                                meta.label,
                                Refusal::ChainedKeyringItem { item_type: code },
                            ));
                            continue;
                        }
                    }
                    // The property is absent, which is a provider whose types we
                    // cannot see — benign, and the item is carried.
                    ItemType::Unsupported => {}
                    // The property exists and the read failed. That is refused,
                    // not carried: `is_unlock_credential_type` on a type we could
                    // not read is false, so carrying it would import an unlock
                    // credential on the strength of a failed read, and the read
                    // that failed is one the foreign daemon controls.
                    ItemType::Unreadable => {
                        out.refused.push(ItemReport::refused(
                            meta.provenance,
                            meta.label,
                            // What is true is that the read failed — not that
                            // the item is a chained-keyring password. Recording
                            // the refusal it protects against would put "item
                            // type 3 unlocks another keyring" in a security
                            // report about an item whose type nobody knows.
                            Refusal::UnreadableItemType,
                        ));
                        continue;
                    }
                }
                candidates.push((item_path, meta));
            }

            fetch_secrets(
                &Walk {
                    conn,
                    service: &service,
                    session: &session,
                    cipher: &cipher,
                    secret_bytes: &secret_bytes,
                },
                candidates,
                &mut out.items,
                &mut out.refused,
                &mut out.skipped,
            )
            .await?;
        }

        if let Some(only) = &options.only_container
            && !seen_containers.iter().any(|c| c == only)
        {
            return Err(GnomeError::NoSuchCollection {
                container: display_label(only),
                available: if seen_containers.is_empty() {
                    "none".to_string()
                } else {
                    seen_containers
                        .iter()
                        .map(|c| format!("'{}'", display_label(c)))
                        .collect::<Vec<_>>()
                        .join(", ")
                },
            });
        }

        out.item_type_unavailable = saw_item && !saw_type;
        Ok(out)
    }
    .await;

    // The session holds the transport key; close it rather than leaving it
    // for the daemon to garbage-collect when we disconnect. Unconditional:
    // it runs before the walk's error is propagated, not instead of it.
    if let Ok(proxy) = proxy_at::<SessionProxy<'static>>(conn, "Session", &session).await {
        let _ = tokio::time::timeout(COMMAND_TIMEOUT, proxy.close()).await;
    }

    walked
}

/// `OpenSession`, DH first.
///
/// DH keeps the plaintext off the bus, and `src/session/dh.rs` already
/// implements this side, so reusing it is nearly free. `plain` is a fallback
/// and never a silent one: the reason is carried into the report.
async fn open_session(
    service: &ServiceProxy<'_>,
    prefer_dh: bool,
) -> Result<(OwnedObjectPath, SessionCipher, Option<String>), GnomeError> {
    if prefer_dh {
        let pair = KeyPair::generate();
        let opened = tokio::time::timeout(
            CALL_TIMEOUT,
            service.open_session(ALGORITHM_DH, &Value::from(pair.public_bytes().to_vec())),
        )
        .await
        .map_err(|_| GnomeError::CallTimeout {
            call: "Service.OpenSession(dh)".into(),
            waited: CALL_TIMEOUT,
        })?;
        match opened {
            Ok((output, path)) => {
                let peer = Vec::<u8>::try_from(output).map_err(|e| GnomeError::NoSession {
                    message: format!("bad DH reply: {e}"),
                })?;
                let cipher =
                    SessionCipher::from_dh(&pair, &peer).map_err(|e| GnomeError::NoSession {
                        message: e.to_string(),
                    })?;
                return Ok((path, cipher, None));
            }
            Err(e) => {
                // The peer chose this text and it is printed verbatim by
                // `sm import`, which interpolates `plain_fallback_reason`
                // without escaping it. Sanitised here, at construction, so
                // there is no unsanitised copy for a caller to reach.
                let reason = format!(
                    "the source refused {ALGORITHM_DH}: {}",
                    error_text(&e.to_string())
                );
                let (_, path) = call(
                    "Service.OpenSession(plain)",
                    service.open_session(ALGORITHM_PLAIN, &Value::from("")),
                )
                .await?;
                return Ok((path, SessionCipher::plain(), Some(reason)));
            }
        }
    }
    let (_, path) = call(
        "Service.OpenSession(plain)",
        service.open_session(ALGORITHM_PLAIN, &Value::from("")),
    )
    .await?;
    Ok((
        path,
        SessionCipher::plain(),
        Some("the caller asked for plain".into()),
    ))
}

/// `Service.Unlock`, driving any prompt under a bound.
async fn unlock(
    conn: &Connection,
    service: &ServiceProxy<'_>,
    path: &OwnedObjectPath,
    prompt_timeout: Duration,
) -> Result<(), GnomeError> {
    let objects = [path.clone()];
    let (unlocked, prompt) = call("Service.Unlock", service.unlock(&objects)).await?;
    if unlocked.contains(path) {
        return Ok(());
    }
    if prompt.as_str() == NO_PROMPT {
        // No prompt and not unlocked: nothing further can be done. The same
        // shortfall as an unanswerable prompt, but not the same event — it is
        // reported as itself rather than as a wait that never happened.
        return Err(GnomeError::UnlockOfferedNothing {
            object: path.as_str().to_string(),
        });
    }
    // The `Completed` signal's result is `ao`: the objects the prompt
    // actually unlocked. Discarding it made a prompt that completed with
    // `dismissed = false` and an empty result look like a success, so the
    // collection was marked unlocked, `GetSecrets` then failed on it, and the
    // per-item fallback aborted the whole migration instead of skipping one
    // collection. A prompt that completes is not a prompt that succeeded.
    let result = await_prompt(conn, &prompt, prompt_timeout).await?;
    // A result that is not an object-path array is a daemon that answered
    // outside the interface, not an unlock of nothing: defaulting it to empty
    // would report `PromptUnlockedNothing` for a reply that said something
    // else entirely. It propagates with the call named.
    let unlocked = Vec::<OwnedObjectPath>::try_from(result).map_err(|e| GnomeError::Bus {
        call: "Prompt.Completed".into(),
        message: e.to_string(),
    })?;
    if !unlocked.contains(path) {
        return Err(GnomeError::PromptUnlockedNothing {
            object: path.as_str().to_string(),
        });
    }
    Ok(())
}

/// Everything about one item except its secret.
/// What one metadata read produced: everything the walk needs, or a per-item
/// refusal to record before moving to the next item.
///
/// The refusal is a value rather than an error because the distinction it
/// draws is the one that matters here — a `GnomeError` aborts the walk and
/// discards every item already read, and one item whose attributes the source
/// daemon would not return is not a reason to lose the other twenty-seven.
enum Metadata {
    Read(Box<ItemMetadata>),
    Refused(Box<ItemReport>),
}

struct ItemMetadata {
    label: String,
    attributes: BTreeMap<String, String>,
    created: u64,
    modified: u64,
    item_type: ItemType,
    provenance: Provenance,
}

/// What one `Item.Type` read established — three outcomes, not two.
///
/// Collapsing them into `Option<String>` is what made the chained-keyring
/// refusal fail open: `None` meant both "this provider has no `Type`
/// property", which is benign, and "the read errored or timed out", which is
/// the case the foreign daemon controls and the one an unlock credential
/// would arrive through.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ItemType {
    /// The daemon answered with a type string.
    Known(String),
    /// The daemon answered `UnknownProperty` or `InvalidArgs`: it does not
    /// implement the property at all. Our own daemon answers this way.
    Unsupported,
    /// The read failed or timed out. Nothing was established.
    ///
    /// It carries no reason: the one caller turns it straight into
    /// [`Refusal::UnreadableItemType`], which has no room for one. A payload
    /// nothing reads is a payload nobody sanitises — one of the two
    /// construction sites was passing a raw `zbus` error string, the only
    /// unsanitised peer text in this module, waiting for whoever first decided
    /// to print it.
    Unreadable,
}

impl ItemType {
    /// The type string, for a report — `None` for both non-answers, which is
    /// the shape [`ExtractedItem`] and the report have always spoken in.
    fn known(&self) -> Option<&str> {
        match self {
            ItemType::Known(t) => Some(t.as_str()),
            _ => None,
        }
    }

    /// Classifies one property-read outcome. A D-Bus method error naming
    /// `UnknownProperty` or `InvalidArgs` is the daemon saying the property
    /// does not exist; **everything else** — any other error, and the timeout
    /// — is a read that failed.
    fn classify(outcome: Result<zbus::Result<String>, tokio::time::error::Elapsed>) -> ItemType {
        match outcome {
            Ok(Ok(t)) => ItemType::Known(t),
            Ok(Err(zbus::Error::MethodError(name, _, _)))
                if name.as_str().ends_with(".UnknownProperty")
                    || name.as_str().ends_with(".InvalidArgs") =>
            {
                ItemType::Unsupported
            }
            Ok(Err(_)) | Err(_) => ItemType::Unreadable,
        }
    }
}

/// gnome-keyring's non-standard `Type` property, and nothing else.
///
/// The shared [`crate::dbus::proxies`] describe the *spec* interface, which
/// our own daemon implements and which has no `Type`; extending them for a
/// property only one foreign provider has would put a call in the CLI's path
/// that our daemon answers with `UnknownProperty`. So the spec proxies are
/// reused for every standard call the walk makes — eighteen of them, across
/// the `Service`, `Collection`, `Item`, `Prompt` and `Session` proxies — and
/// this one non-standard property gets its own two-line proxy, whose absence
/// is tolerated.
#[zbus::proxy(
    interface = "org.freedesktop.Secret.Item",
    default_service = "org.freedesktop.secrets"
)]
trait GnomeItem {
    #[zbus(property)]
    fn type_(&self) -> zbus::Result<String>;
}

/// The report label for an item whose own label could not be read.
///
/// Self-made rather than peer-made, so there is nothing to sanitise: the
/// object path's last segment is the only handle the walk has for an item it
/// cannot name. See [`path_item_id`].
fn unreadable_item_label(path: &str) -> String {
    format!("item {}", path_item_id(path))
}

async fn read_metadata(
    conn: &Connection,
    path: &OwnedObjectPath,
    container: &str,
) -> Result<Metadata, GnomeError> {
    let item: ItemProxy<'static> = proxy_at(conn, "Item", path).await?;

    let provenance = Provenance::gnome(container, path_item_id(path.as_str()));
    // `Label`, `Created` and `Modified` degrade to per-item refusals, never
    // to defaults: a defaulted label misnames the report, defaulted
    // timestamps reorder `sm get`'s newest-wins resolution, and all three
    // silent would let the source daemon choose what the vault claims.
    // `UnreadableAttributes` is the refusal they share with the attribute
    // map — the item cannot be faithfully copied, so it is not copied.
    let label = match call("Item.Label", item.label()).await {
        Ok(label) => label,
        Err(_) => {
            return Ok(Metadata::Refused(Box::new(ItemReport::refused(
                provenance,
                unreadable_item_label(path.as_str()),
                Refusal::UnreadableAttributes,
            ))));
        }
    };

    // D-Bus `s` and the `a{ss}` attribute map are validated UTF-8 by the
    // marshaller, so an attribute that is not UTF-8 cannot arise on this
    // route: it could not have reached the bus in the first place. There is
    // therefore no encoding refusal here, and `SourceItem`'s doc records why
    // one would have to be added alongside any future route that reads raw
    // attribute bytes.
    //
    // The read *failing* is a different thing, and it is a per-item refusal
    // rather than a `?`: attributes are the item's identity, so an item whose
    // map we could not read must not be written, but one such item is no
    // reason to discard every item the walk has already collected. Same shape
    // as a cap violation — refuse the item, continue the walk. `Label`,
    // `Created`, `Modified` and `Type` all degrade rather than abort too.
    let attributes: BTreeMap<String, String> =
        match call("Item.Attributes", item.attributes()).await {
            Ok(pairs) => pairs.into_iter().collect(),
            Err(_) => {
                return Ok(Metadata::Refused(Box::new(ItemReport::refused(
                    provenance,
                    label,
                    Refusal::UnreadableAttributes,
                ))));
            }
        };

    // Three outcomes, never two. A proxy that cannot even be built is an
    // unreadable type, not an absent one: nothing was established either way,
    // and the direction that guesses "absent" is the direction that imports
    // an unlock credential.
    let item_type = match proxy_at::<GnomeItemProxy<'static>>(conn, "Item.Type", path).await {
        Ok(proxy) => ItemType::classify(tokio::time::timeout(CALL_TIMEOUT, proxy.type_()).await),
        Err(_) => ItemType::Unreadable,
    };

    Ok(Metadata::Read(Box::new({
        // Read before constructing, so each failure can refuse with the label
        // and provenance the success path would have carried.
        let created = match call("Item.Created", item.created()).await {
            Ok(created) => created,
            Err(_) => {
                return Ok(Metadata::Refused(Box::new(ItemReport::refused(
                    provenance,
                    label,
                    Refusal::UnreadableAttributes,
                ))));
            }
        };
        let modified = match call("Item.Modified", item.modified()).await {
            Ok(modified) => modified,
            Err(_) => {
                return Ok(Metadata::Refused(Box::new(ItemReport::refused(
                    provenance,
                    label,
                    Refusal::UnreadableAttributes,
                ))));
            }
        };
        ItemMetadata {
            label,
            attributes,
            created,
            modified,
            item_type,
            provenance,
        }
    })))
}

/// `Service.GetSecrets` for the whole batch, per-item `GetSecret` for whatever
/// it left out.
///
/// The five things every secret fetch needs and none of them varies within a
/// walk: the connection, the service proxy, the session, its cipher, and the
/// walk-wide count of decrypted secret bytes.
///
/// Grouping them is what retires the `#[allow(clippy::too_many_arguments)]`
/// this function used to carry — the lint was right that seven positional
/// parameters, four of them fixed context, is a call nobody can read.
struct Walk<'a> {
    conn: &'a Connection,
    service: &'a ServiceProxy<'a>,
    session: &'a OwnedObjectPath,
    cipher: &'a SessionCipher,
    /// Plaintext bytes decrypted so far, across every collection in the walk.
    /// A `Cell` because the walk is shared, not exclusive: `fetch_secrets`
    /// and `drain_batch` take `&Walk`, and the budget they enforce is still
    /// walk-wide. See `MAX_SECRET_BYTES`.
    secret_bytes: &'a Cell<usize>,
}

/// One round trip rather than N, which also halves the window in which
/// plaintext is in flight.
async fn fetch_secrets(
    walk: &Walk<'_>,
    candidates: Vec<(OwnedObjectPath, ItemMetadata)>,
    items: &mut Vec<ExtractedItem>,
    refused: &mut Vec<ItemReport>,
    skipped: &mut Vec<SkippedEntry>,
) -> Result<(), GnomeError> {
    if candidates.is_empty() {
        return Ok(());
    }
    let paths: Vec<OwnedObjectPath> = candidates.iter().map(|(p, _)| p.clone()).collect();
    // The cause of a failed batch is kept rather than erased. Erasing it made
    // the run degrade silently to N individual calls, and the error the user
    // finally saw came from a different call site with the batch's cause
    // destroyed.
    let (mut batch, batch_failure) =
        match tokio::time::timeout(CALL_TIMEOUT, walk.service.get_secrets(&paths, walk.session))
            .await
        {
            Ok(Ok(batch)) => (batch, None),
            Ok(Err(e)) => (
                HashMap::new(),
                Some(format!(
                    "Service.GetSecrets failed: {}",
                    error_text(&e.to_string())
                )),
            ),
            Err(_) => (
                HashMap::new(),
                Some(format!(
                    "Service.GetSecrets did not answer within {CALL_TIMEOUT:?}"
                )),
            ),
        };

    // One deadline for the whole fallback, not one per call: N items at
    // `CALL_TIMEOUT` each is an unbounded walk in every way that matters.
    let drained = tokio::time::timeout(
        SECRETS_FALLBACK_TIMEOUT,
        drain_batch(
            walk,
            candidates,
            &mut batch,
            batch_failure.as_deref(),
            items,
            refused,
            skipped,
        ),
    )
    .await;

    // `SecretStruct::value` is the plaintext on a `plain` session — a whole
    // collection's worth of it held at once. The type does wipe itself:
    // `value` is `Zeroizing` and its `Debug` redacts. What it cannot do is
    // wipe *early*, and that is what this is for: the map outlives the last
    // item that needed it, so whatever is left in it on any path out of here
    // — the `?` paths included — is wiped here rather than whenever the
    // `HashMap` happens to drop. `parameters` is a plain `Vec<u8>` and is
    // wiped for the same reason.
    for secret in batch.values_mut() {
        secret.value.zeroize();
        secret.parameters.zeroize();
    }
    batch.clear();

    match drained {
        Ok(result) => result,
        Err(_) => Err(GnomeError::CallTimeout {
            call: match batch_failure {
                Some(cause) => format!("Item.GetSecret for the whole batch (after {cause})"),
                None => "Item.GetSecret for the items the batch left out".into(),
            },
            waited: SECRETS_FALLBACK_TIMEOUT,
        }),
    }
}

/// The per-item half of [`fetch_secrets`], split out so one timeout can bound
/// the whole of it and so its `?` paths still reach the wipe above.
///
/// **A failure to read or decrypt one item is that item's failure, not the
/// run's.** It is recorded in `skipped` and the walk continues, which is the
/// policy every other per-item problem here already follows: a cap violation
/// refuses one item fourteen lines below, and an unreadable attribute map or
/// item type refuses one item in the caller. One ACL-denied item out of five
/// hundred used to discard the four hundred and ninety-nine already walked.
///
/// The one thing that is still the run's failure is a transport that produced
/// *nothing*: if every candidate here failed and none succeeded, the first
/// error is returned rather than a report saying five hundred items were
/// "not migrated" over a green verification.
async fn drain_batch(
    walk: &Walk<'_>,
    candidates: Vec<(OwnedObjectPath, ItemMetadata)>,
    batch: &mut HashMap<OwnedObjectPath, crate::dbus::session::SecretStruct>,
    batch_failure: Option<&str>,
    items: &mut Vec<ExtractedItem>,
    refused: &mut Vec<ItemReport>,
    skipped: &mut Vec<SkippedEntry>,
) -> Result<(), GnomeError> {
    // Items accounted for: carried, or deliberately refused. Not the ones that
    // failed.
    let mut carried = 0usize;
    let mut first_failure: Option<GnomeError> = None;
    let skip = |skipped: &mut Vec<SkippedEntry>,
                first_failure: &mut Option<GnomeError>,
                label: &str,
                e: GnomeError| {
        skipped.push(SkippedEntry {
            label: display_label(label),
            reason: error_text(&e.to_string()),
        });
        if first_failure.is_none() {
            *first_failure = Some(e);
        }
    };
    for (path, meta) in candidates {
        let mut secret = match batch.remove(&path) {
            Some(s) => s,
            None => {
                let proxied: Result<ItemProxy<'static>, GnomeError> =
                    proxy_at(walk.conn, "Item", &path).await;
                let fetched = match proxied {
                    Ok(item) => call("Item.GetSecret", item.get_secret(walk.session))
                        .await
                        // The batch's cause travels with the per-item failure
                        // it caused, instead of being replaced by it.
                        .map_err(|e| match batch_failure {
                            Some(cause) => GnomeError::Bus {
                                call: "Item.GetSecret".into(),
                                message: format!("{e} (the batch had already failed: {cause})"),
                            },
                            None => e,
                        }),
                    Err(e) => Err(e),
                };
                match fetched {
                    Ok(s) => s,
                    Err(e) => {
                        skip(skipped, &mut first_failure, &meta.label, e);
                        continue;
                    }
                }
            }
        };
        let plaintext = cipher_decrypt(walk.cipher, &secret);
        // Wiped the moment it has been copied out, so the transport buffer
        // does not sit in memory for the rest of the collection's walk.
        secret.value.zeroize();
        secret.parameters.zeroize();
        let plaintext = match plaintext {
            Ok(p) => p,
            Err(e) => {
                skip(skipped, &mut first_failure, &meta.label, e);
                continue;
            }
        };
        // Checked as soon as the bytes exist, before anything is pushed, so
        // the walk cannot be made to hold more than the budget even by one
        // enormous secret. Refusing aborts the walk rather than truncating
        // it — a partial migration that reports success is the failure this
        // module exists to avoid.
        let total = walk.secret_bytes.get().saturating_add(plaintext.len());
        walk.secret_bytes.set(total);
        if total > MAX_SECRET_BYTES {
            return Err(GnomeError::TooMany {
                what: "secret bytes in this import",
                count: total,
                limit: MAX_SECRET_BYTES,
            });
        }

        let source = SourceItem {
            label: meta.label,
            attributes: meta.attributes,
            secret: plaintext,
            content_type: secret.content_type,
            created: meta.created,
            modified: meta.modified,
            provenance: meta.provenance,
            // The gnome path synthesises nothing: every key in the map is
            // one the source daemon reported.
            inserted_keys: BTreeSet::new(),
        };
        // Checked here, before anything is written: an item the D-Bus API
        // could never have created must not reach a vault file, and a
        // migration that fails halfway is worse than one that refuses now.
        if let Some(violation) = source.cap_violation() {
            refused.push(ItemReport::refused(
                source.provenance.clone(),
                source.label.clone(),
                violation,
            ));
            carried += 1;
            continue;
        }
        items.push(ExtractedItem {
            item: source,
            item_type: meta.item_type.known().map(str::to_string),
        });
        carried += 1;
    }
    // Nothing was accounted for at all — neither carried nor deliberately
    // refused: that is the transport, not five hundred individually unlucky
    // items, and reporting it as the latter would hand the user a green
    // verification over an empty collection.
    match first_failure {
        Some(e) if carried == 0 => Err(e),
        _ => Ok(()),
    }
}

/// One decrypt, named so the wipe that must follow it cannot be skipped by an
/// early `?`.
fn cipher_decrypt(
    cipher: &SessionCipher,
    secret: &crate::dbus::session::SecretStruct,
) -> Result<Zeroizing<Vec<u8>>, GnomeError> {
    cipher
        .decrypt(&secret.parameters, &secret.value)
        .map_err(|e| GnomeError::Decrypt {
            message: e.to_string(),
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader as StdBufReader};
    use std::process::{Child as StdChild, Command as StdCommand};
    use std::sync::{Arc, Mutex};

    // ----------------------------------------------------------------
    // The bus-owner check, against synthetic inputs
    // ----------------------------------------------------------------

    /// Real `busctl --user status` output, trimmed to the lines that matter.
    fn busctl(pid: &str) -> String {
        format!(
            "PID={pid}\nPIDFD=yes\nPPID=1\nTTY=n/a\nUID=1000\nEUID=1000\n\
             Comm=whatever\nUnit=session-2.scope\n"
        )
    }

    #[test]
    fn the_right_owner_is_accepted() {
        let owner = classify_bus_owner(
            Some(&busctl("4242")),
            Some("/usr/bin/gnome-keyring-daemon --daemonize --login\n"),
        );
        assert_eq!(
            owner,
            BusOwner::Process {
                pid: 4242,
                command: "/usr/bin/gnome-keyring-daemon --daemonize --login".into(),
            }
        );
        assert!(owner.is_gnome_keyring());
        assert!(owner.describe().contains("4242"));
        assert_eq!(owner.foreign_provider_warning(), None);
    }

    /// The case that motivates the check: on the author's machine `ksecretd`
    /// owns the name while gnome-keyring is masked, so a `--from
    /// gnome-keyring` that believed the bus would have migrated KWallet data
    /// and called it a success.
    ///
    /// The private-bus route cannot make that mistake — it reads the keyring
    /// files itself — so what is left is worth *saying*: the files it is about
    /// to read are not where this user's secrets have been going. It is a
    /// warning, and the extraction goes ahead.
    #[test]
    fn a_foreign_owner_is_named_in_a_warning() {
        let owner = classify_bus_owner(
            Some(&busctl("7585")),
            Some("/usr/bin/ksecretd --pam-login 4 5\n"),
        );
        assert!(!owner.is_gnome_keyring());
        let described = owner.describe();
        assert!(described.contains("ksecretd"), "{described}");
        assert!(described.contains("7585"), "{described}");
        let warning = owner
            .foreign_provider_warning()
            .expect("a foreign provider is worth telling the user about");
        assert!(warning.contains("ksecretd"), "{warning}");
        assert!(warning.contains("stale"), "{warning}");
    }

    /// The two states the install guides produce. Masking gnome-keyring leaves
    /// the name unowned until our own daemon takes it, and both are the
    /// ordinary state to run `sm import` from: neither is refused, and neither
    /// is worth a warning.
    #[test]
    fn an_unowned_name_and_our_own_daemon_are_both_silent() {
        assert_eq!(classify_bus_owner(None, None), BusOwner::Unowned);
        assert_eq!(
            classify_bus_owner(Some("Failed to get PID: no such name\n"), None),
            BusOwner::Unowned
        );
        assert!(!BusOwner::Unowned.is_gnome_keyring());
        assert!(BusOwner::Unowned.describe().contains(SECRETS_BUS_NAME));
        assert_eq!(BusOwner::Unowned.foreign_provider_warning(), None);

        let ours = classify_bus_owner(
            Some(&busctl("31")),
            Some("/usr/local/bin/secret-manager --foreground\n"),
        );
        assert!(ours.is_secret_manager());
        assert_eq!(ours.foreign_provider_warning(), None);
    }

    /// An owner `ps` cannot describe is not assumed to be anything. Empty
    /// output, whitespace-only output and a failed `ps` are the same answer:
    /// we do not know, so we say we do not know.
    #[test]
    fn an_unreadable_ps_says_so_rather_than_assuming() {
        for ps in [None, Some(""), Some("   \n\t")] {
            let owner = classify_bus_owner(Some(&busctl("99")), ps);
            assert_eq!(owner, BusOwner::Unidentified { pid: 99 }, "{ps:?}");
            assert!(!owner.is_gnome_keyring(), "{ps:?}");
            assert!(!owner.is_secret_manager(), "{ps:?}");
            assert!(owner.describe().contains("99"));
            let warning = owner.foreign_provider_warning().expect("{ps:?}");
            assert!(warning.contains("99"), "{warning}");
        }
    }

    /// A non-numeric or absent `PID=` is no answer, never pid 0.
    #[test]
    fn a_malformed_pid_line_is_no_owner() {
        for status in ["PID=\n", "PID=notanumber\n", "PID=-1\n", "", "NAME=x\n"] {
            assert_eq!(parse_busctl_pid(status), None, "{status:?}");
        }
        assert_eq!(parse_busctl_pid("PID=1\nPID=2\n"), Some(1));
        assert_eq!(parse_busctl_pid("  PID=17  \n"), Some(17));
    }

    /// The match is on argv[0]'s basename, so neither a path nor arguments
    /// can smuggle the name in, and neither can a lookalike.
    #[test]
    fn only_argv0s_basename_decides() {
        assert_eq!(
            program_name("/usr/bin/gnome-keyring-daemon --login"),
            Some(GNOME_KEYRING_PROGRAM)
        );
        assert_eq!(
            program_name("gnome-keyring-daemon"),
            Some("gnome-keyring-daemon")
        );
        assert_eq!(program_name("[kthreadd]"), Some("kthreadd"));
        assert_eq!(program_name("   \n"), None);
        assert_eq!(program_name(""), None);
        for imposter in [
            "/usr/bin/ksecretd --gnome-keyring-daemon",
            "/tmp/not-gnome-keyring-daemon",
            "/usr/bin/gnome-keyring-daemon-x",
            "sh -c gnome-keyring-daemon",
        ] {
            let owner = classify_bus_owner(Some(&busctl("5")), Some(imposter));
            assert!(!owner.is_gnome_keyring(), "{imposter}");
        }
    }

    // ----------------------------------------------------------------
    // Item types, mapping and refusal classification
    // ----------------------------------------------------------------

    #[test]
    fn only_the_two_unlock_credential_types_are_refused() {
        assert!(is_unlock_credential_type(TYPE_CHAINED_KEYRING));
        assert!(is_unlock_credential_type(TYPE_ENCRYPTION_KEY));
        for kept in [
            TYPE_GENERIC,
            TYPE_NETWORK_PASSWORD,
            TYPE_NOTE,
            TYPE_PK_STORAGE,
            "org.gnome.keyring.SomethingNew",
            "",
        ] {
            assert!(!is_unlock_credential_type(kept), "{kept}");
        }
    }

    /// The live type string and the on-disk numeric type must name the same
    /// item type, or a report assembled from both halves contradicts itself.
    #[test]
    fn live_type_strings_map_onto_the_file_formats_numbering() {
        assert_eq!(item_type_code(TYPE_GENERIC), Some(ITEM_TYPE_GENERIC_SECRET));
        assert_eq!(
            item_type_code(TYPE_NETWORK_PASSWORD),
            Some(ITEM_TYPE_NETWORK_PASSWORD)
        );
        assert_eq!(item_type_code(TYPE_NOTE), Some(ITEM_TYPE_NOTE));
        assert_eq!(
            item_type_code(TYPE_CHAINED_KEYRING),
            Some(ITEM_TYPE_CHAINED_KEYRING_PASSWORD)
        );
        assert_eq!(
            item_type_code(TYPE_ENCRYPTION_KEY),
            Some(ITEM_TYPE_ENCRYPTION_KEY_PASSWORD)
        );
        assert_eq!(item_type_code(TYPE_PK_STORAGE), Some(ITEM_TYPE_PK_STORAGE));
        assert_eq!(item_type_code("org.example.Whatever"), None);
    }

    fn extracted(item_type: Option<&str>, pairs: &[(&str, &str)]) -> ExtractedItem {
        ExtractedItem {
            item: SourceItem {
                label: "Test Item".into(),
                attributes: pairs
                    .iter()
                    .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
                    .collect(),
                secret: Zeroizing::new(b"s3cr3t".to_vec()),
                content_type: "text/plain".into(),
                created: 1_788_893_013,
                modified: 1_788_893_014,
                provenance: Provenance::gnome("Login", 1),
                inserted_keys: BTreeSet::new(),
            },
            item_type: item_type.map(str::to_string),
        }
    }

    /// The mapping is near-total and invents nothing. An item with no
    /// `xdg:schema` gets no synthesised one — two of 28 items on the author's
    /// machine have none, and inventing one produces an item that looks
    /// migrated and is unreachable.
    ///
    /// Every assertion here is on [`ExtractedItem::report`]'s output, not on
    /// the fields `extracted` set two lines above: `assert_eq!(e.item.created,
    /// …)` on a value the test's own helper wrote is a test of the helper, and
    /// it stayed green through any change to the code it was supposed to be
    /// pinning.
    #[test]
    fn the_mapping_copies_and_invents_nothing() {
        let e = extracted(Some(TYPE_GENERIC), &[("server", "example.com")]);
        let report = e.report();
        // Exactly the source's keys: none dropped, and no `xdg:schema`
        // conjured for an item that had none.
        assert_eq!(report.attribute_keys.iter().collect::<Vec<_>>(), ["server"]);
        assert_eq!(report.label, "Test Item");
        assert_eq!(report.content_type, "text/plain");
        assert_eq!(report.secret_len, b"s3cr3t".len());
        assert_eq!(report.provenance, e.item.provenance);
        assert_eq!(
            report.outcome,
            Some(super::super::Outcome::AttributesPreserved)
        );
        assert!(report.refusals.is_empty());
        // Generic is the type our daemon *does* represent, so nothing is lost.
        assert_eq!(report.lost_item_type, None);
        assert_eq!(report.unknown_item_type, None);
    }

    /// Item types other than generic have no target, so they flatten — and the
    /// report records which items lost one.
    #[test]
    fn a_flattened_item_type_is_recorded() {
        for (name, code) in [
            (TYPE_NETWORK_PASSWORD, ITEM_TYPE_NETWORK_PASSWORD),
            (TYPE_NOTE, ITEM_TYPE_NOTE),
            (TYPE_PK_STORAGE, ITEM_TYPE_PK_STORAGE),
        ] {
            let report = extracted(Some(name), &[]).report();
            assert_eq!(report.lost_item_type, Some(code), "{name}");
            assert_eq!(report.unknown_item_type, None, "{name}");
        }
        // No type at all: nothing was lost, and neither field is set.
        let absent = extracted(None, &[]).report();
        assert_eq!(absent.lost_item_type, None);
        assert_eq!(absent.unknown_item_type, None);
    }

    /// A type string this build does not know is a type that flattened, and
    /// the report has to say so by name.
    ///
    /// This is the case `lost_item_type` cannot express: it speaks the on-disk
    /// format's numbering and there is no number for a string we have never
    /// seen, so `item_type_code` answers `None` — which is the same value that
    /// means "this item had no type to lose". Folding the two together is how
    /// a gnome-keyring type added after this was written flattens in silence,
    /// with the report claiming nothing happened.
    #[test]
    fn a_type_this_build_does_not_know_is_reported_as_unknown_and_not_as_nothing() {
        let report = extracted(Some("org.gnome.keyring.Unheard"), &[]).report();
        assert_eq!(
            report.lost_item_type, None,
            "an unknown type has no number and must not be given the nearest one"
        );
        assert_eq!(
            report.unknown_item_type.as_deref(),
            Some("org.gnome.keyring.Unheard"),
            "the type flattened and the report says nothing about it"
        );
    }

    /// The type string is peer text on its way to a terminal and to the report
    /// file, so it goes through `display_label` like every other.
    #[test]
    fn an_unknown_type_is_sanitised_before_it_reaches_the_report() {
        let report = extracted(Some("org.gnome.\r\nkeyring.Evil\u{7}"), &[]).report();
        let shown = report.unknown_item_type.expect("an unknown type");
        assert!(!shown.contains('\r'), "{shown:?}");
        assert!(!shown.contains('\n'), "{shown:?}");
        assert!(!shown.contains('\u{7}'), "{shown:?}");
        assert!(shown.contains("keyring.Evil"), "{shown:?}");
    }

    /// Error prose is sanitised without being truncated into uselessness.
    ///
    /// The finding this pins: `display_label`'s 64-character cut, applied to
    /// [`StderrTail`] and to D-Bus error strings, threw away the cause the
    /// message exists to carry. gnome-keyring's first stderr line is an
    /// ~85-character capabilities warning, so "The password or PIN is
    /// incorrect" — the one thing [`STDERR_CAPTURE_LIMIT`]'s 4 KiB is for —
    /// was *guaranteed* to be past the cut.
    #[test]
    fn error_prose_keeps_its_cause_and_is_still_escaped_and_bounded() {
        let stderr = "gnome-keyring-daemon: insufficient process capabilities, insecure \
                      memory might get used\n\
                      gnome-keyring-daemon: The password or PIN is incorrect";
        assert!(stderr.find('\n').unwrap() > 64, "the premise of this test");
        let shown = error_text(stderr);
        assert!(
            shown.contains("The password or PIN is incorrect"),
            "the cause was cut off: {shown:?}"
        );
        // Sanitised all the same: nothing that can move a cursor survives.
        assert!(!shown.contains('\n'), "{shown:?}");
        assert!(shown.contains("\\x0a"), "{shown:?}");

        // And still bounded: a peer does not choose how much of our output it
        // fills. The cap is on the escaped bytes, so an escape cannot smuggle
        // four bytes out of one.
        let capped = error_text(&"\u{7}".repeat(4096));
        assert!(capped.ends_with('\u{2026}'), "{capped:?}");
        assert_eq!(capped.len(), ERROR_TEXT_LIMIT + '\u{2026}'.len_utf8());
    }

    /// gnome-keyring's per-item ACLs live in the encrypted half, which is
    /// never parsed, so every item is flagged rather than none: each one does
    /// lose whatever ACL it had, and under-reporting a security downgrade is
    /// the wrong direction to be wrong in.
    #[test]
    fn every_imported_item_reports_the_acl_downgrade() {
        assert!(extracted(Some(TYPE_GENERIC), &[]).report().acl_downgrade);
    }

    /// A refusal carries the type as the *file format's* number, so the two
    /// halves of a report agree, and it carries no secret and no attribute
    /// value.
    #[test]
    fn a_refused_unlock_credential_names_its_type_and_leaks_nothing() {
        for (name, code) in [
            (TYPE_CHAINED_KEYRING, ITEM_TYPE_CHAINED_KEYRING_PASSWORD),
            (TYPE_ENCRYPTION_KEY, ITEM_TYPE_ENCRYPTION_KEY_PASSWORD),
        ] {
            assert!(is_unlock_credential_type(name));
            let report = ItemReport::refused(
                Provenance::gnome("Login", 2),
                "Unlock password for Extra keyring",
                Refusal::ChainedKeyringItem {
                    item_type: item_type_code(name).unwrap(),
                },
            );
            assert!(report.is_refused());
            assert_eq!(report.outcome, None);
            assert_eq!(report.secret_len, 0);
            assert!(report.attribute_keys.is_empty());
            assert_eq!(
                report.refusals,
                vec![Refusal::ChainedKeyringItem { item_type: code }]
            );
        }
    }

    #[test]
    fn the_in_memory_session_collection_is_skipped() {
        assert!(is_session_collection(
            "/org/freedesktop/secrets/collection/session"
        ));
        assert!(!is_session_collection(
            "/org/freedesktop/secrets/collection/login"
        ));
        assert!(!is_session_collection(
            "/org/freedesktop/secrets/collection/session/1"
        ));
    }

    #[test]
    fn an_items_id_comes_from_its_object_path() {
        assert_eq!(
            path_item_id("/org/freedesktop/secrets/collection/login/17"),
            17
        );
        assert_eq!(path_item_id("/org/freedesktop/secrets/collection/login"), 0);
        assert_eq!(path_item_id(""), 0);
    }

    // ----------------------------------------------------------------
    // The unanswerable prompt
    // ----------------------------------------------------------------

    /// A private `dbus-daemon`, killed on drop. The tests below are the only
    /// place this module needs one that is not gnome-keyring's.
    struct Bus {
        address: String,
        child: StdChild,
    }

    impl Drop for Bus {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    /// A private bus, or the reason there is none.
    ///
    /// The reason is the point. Collapsing "not installed", "spawned but said
    /// nothing" and "printed an empty address" into one `None` meant every
    /// caller printed "dbus-daemon is not installed" — so a *broken*
    /// `dbus-daemon` reported as an absent one and every test using it passed
    /// vacuously, which is exactly what the skip is supposed to prevent.
    fn private_bus() -> Result<Bus, String> {
        let mut child = StdCommand::new("dbus-daemon")
            .args(["--session", "--nofork", "--nopidfile", "--print-address"])
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| format!("dbus-daemon could not be started: {e}"))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| "dbus-daemon's stdout was not a pipe".to_string())?;
        let mut line = String::new();
        StdBufReader::new(stdout)
            .read_line(&mut line)
            .map_err(|e| format!("dbus-daemon printed no address: {e}"))?;
        let address = line.trim().to_string();
        if address.is_empty() {
            return Err("dbus-daemon started and printed an empty address".into());
        }
        Ok(Bus { address, child })
    }

    /// A prompt that behaves exactly as one does on a bus with no prompter:
    /// `Prompt` is accepted, and `Completed` is never emitted.
    struct SilentPrompt {
        prompted: Arc<Mutex<u32>>,
        dismissed: Arc<Mutex<u32>>,
    }

    #[zbus::interface(name = "org.freedesktop.Secret.Prompt")]
    impl SilentPrompt {
        fn prompt(&self, _window_id: &str) {
            *self.prompted.lock().unwrap() += 1;
        }
        fn dismiss(&self) {
            *self.dismissed.lock().unwrap() += 1;
        }
    }

    /// A prompt that answers immediately, so the timeout test above cannot
    /// pass because `await_prompt` is broken.
    struct AnsweringPrompt;

    #[zbus::interface(name = "org.freedesktop.Secret.Prompt")]
    impl AnsweringPrompt {
        async fn prompt(
            &self,
            _window_id: &str,
            #[zbus(signal_emitter)] emitter: zbus::object_server::SignalEmitter<'_>,
        ) {
            let empty: Vec<OwnedObjectPath> = Vec::new();
            let _ = AnsweringPrompt::completed(&emitter, true, &Value::from(empty)).await;
        }
        fn dismiss(&self) {}

        #[zbus(signal)]
        async fn completed(
            emitter: &zbus::object_server::SignalEmitter<'_>,
            dismissed: bool,
            result: &Value<'_>,
        ) -> zbus::Result<()>;
    }

    /// The failure the spec calls the sharpest edge of the design: a keyring
    /// that is neither the login keyring nor chained to it needs a prompt, and
    /// on a private bus with no prompter the prompt object is returned and
    /// **never completes**. Waiting on it hangs the tool forever.
    ///
    /// The assertion is not just "an error came back" but that it came back
    /// *fast* — the whole point is that the wait is bound. The test's own
    /// timeout is generous relative to the one under test, so a slow machine
    /// cannot flake it, while a reintroduced unbounded wait fails it by
    /// running past both.
    #[tokio::test]
    async fn an_unanswerable_prompt_times_out_with_a_named_error() {
        let bus = match private_bus() {
            Ok(bus) => bus,
            Err(reason) => {
                println!("SKIPPED: {reason}");
                return;
            }
        };
        let prompted = Arc::new(Mutex::new(0));
        let dismissed = Arc::new(Mutex::new(0));
        let _server = Builder::address(bus.address.as_str())
            .unwrap()
            .name(SECRETS_BUS_NAME)
            .unwrap()
            .serve_at(
                "/prompt",
                SilentPrompt {
                    prompted: prompted.clone(),
                    dismissed: dismissed.clone(),
                },
            )
            .unwrap()
            .build()
            .await
            .unwrap();

        let client = Builder::address(bus.address.as_str())
            .unwrap()
            .build()
            .await
            .unwrap();
        let path = OwnedObjectPath::try_from("/prompt").unwrap();

        let started = std::time::Instant::now();
        let waited = Duration::from_millis(300);
        let result = tokio::time::timeout(
            Duration::from_secs(20),
            await_prompt(&client, &path, waited),
        )
        .await
        .expect("await_prompt blocked forever instead of timing out");

        match result {
            Err(GnomeError::UnanswerablePrompt { object, waited: w }) => {
                assert_eq!(object, "/prompt");
                assert_eq!(w, waited);
            }
            other => panic!("expected UnanswerablePrompt, got {other:?}"),
        }
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "the wait was not bound by the timeout: {:?}",
            started.elapsed()
        );
        assert_eq!(*prompted.lock().unwrap(), 1, "Prompt was never called");
        assert_eq!(
            *dismissed.lock().unwrap(),
            1,
            "the unanswerable prompt was left alive"
        );
    }

    /// The other half, without which the test above proves nothing: when a
    /// prompt *does* complete, `await_prompt` sees it and reports the outcome
    /// rather than timing out. A broken signal subscription would make both
    /// tests say `UnanswerablePrompt`, and only this one catches that.
    #[tokio::test]
    async fn a_prompt_that_completes_is_not_reported_as_unanswerable() {
        let bus = match private_bus() {
            Ok(bus) => bus,
            Err(reason) => {
                println!("SKIPPED: {reason}");
                return;
            }
        };
        let _server = Builder::address(bus.address.as_str())
            .unwrap()
            .name(SECRETS_BUS_NAME)
            .unwrap()
            .serve_at("/prompt", AnsweringPrompt)
            .unwrap()
            .build()
            .await
            .unwrap();
        let client = Builder::address(bus.address.as_str())
            .unwrap()
            .build()
            .await
            .unwrap();
        let path = OwnedObjectPath::try_from("/prompt").unwrap();
        let result = tokio::time::timeout(
            Duration::from_secs(20),
            await_prompt(&client, &path, Duration::from_secs(10)),
        )
        .await
        .expect("await_prompt blocked forever");
        match result {
            Err(GnomeError::PromptDismissed { object }) => assert_eq!(object, "/prompt"),
            other => panic!("expected PromptDismissed, got {other:?}"),
        }
    }

    // ----------------------------------------------------------------
    // A prompt that completes and unlocks nothing
    // ----------------------------------------------------------------

    /// A prompt that completes **successfully** and unlocks nothing:
    /// `dismissed` is false and the result is an empty `ao`.
    struct EmptyResultPrompt;

    #[zbus::interface(name = "org.freedesktop.Secret.Prompt")]
    impl EmptyResultPrompt {
        async fn prompt(
            &self,
            _window_id: &str,
            #[zbus(signal_emitter)] emitter: zbus::object_server::SignalEmitter<'_>,
        ) {
            let empty: Vec<OwnedObjectPath> = Vec::new();
            let _ = EmptyResultPrompt::completed(&emitter, false, &Value::from(empty)).await;
        }
        fn dismiss(&self) {}

        #[zbus(signal)]
        async fn completed(
            emitter: &zbus::object_server::SignalEmitter<'_>,
            dismissed: bool,
            result: &Value<'_>,
        ) -> zbus::Result<()>;
    }

    /// The same, but its result actually names the object it unlocked.
    struct UnlockingPrompt {
        unlocked: OwnedObjectPath,
    }

    #[zbus::interface(name = "org.freedesktop.Secret.Prompt")]
    impl UnlockingPrompt {
        async fn prompt(
            &self,
            _window_id: &str,
            #[zbus(signal_emitter)] emitter: zbus::object_server::SignalEmitter<'_>,
        ) {
            let unlocked = vec![self.unlocked.clone()];
            let _ = UnlockingPrompt::completed(&emitter, false, &Value::from(unlocked)).await;
        }
        fn dismiss(&self) {}

        #[zbus(signal)]
        async fn completed(
            emitter: &zbus::object_server::SignalEmitter<'_>,
            dismissed: bool,
            result: &Value<'_>,
        ) -> zbus::Result<()>;
    }

    /// A `Service` whose `Unlock` unlocks nothing and hands back one prompt.
    struct UnlockService {
        prompt: OwnedObjectPath,
    }

    #[zbus::interface(name = "org.freedesktop.Secret.Service")]
    impl UnlockService {
        fn unlock(
            &self,
            _objects: Vec<OwnedObjectPath>,
        ) -> (Vec<OwnedObjectPath>, OwnedObjectPath) {
            (Vec::new(), self.prompt.clone())
        }
    }

    /// `Prompt.Completed` carries the objects the prompt actually unlocked,
    /// and a prompt that completes is not a prompt that succeeded. Throwing
    /// the result away made an empty `ao` with `dismissed = false` look like
    /// a successful unlock, so the collection was marked unlocked, its
    /// `GetSecrets` then failed, and the per-item fallback aborted the whole
    /// migration instead of skipping one keyring.
    ///
    /// Both directions are asserted in one test on purpose: the negative half
    /// alone would still pass if `unlock` had simply started refusing every
    /// prompt.
    #[tokio::test]
    async fn a_prompt_that_unlocks_nothing_is_not_a_successful_unlock() {
        let bus = match private_bus() {
            Ok(bus) => bus,
            Err(reason) => {
                println!("SKIPPED: {reason}");
                return;
            }
        };
        let target =
            OwnedObjectPath::try_from("/org/freedesktop/secrets/collection/locked").unwrap();
        let _server = Builder::address(bus.address.as_str())
            .unwrap()
            .name(SECRETS_BUS_NAME)
            .unwrap()
            .serve_at(
                "/svc/empty",
                UnlockService {
                    prompt: OwnedObjectPath::try_from("/prompt/empty").unwrap(),
                },
            )
            .unwrap()
            .serve_at(
                "/svc/full",
                UnlockService {
                    prompt: OwnedObjectPath::try_from("/prompt/full").unwrap(),
                },
            )
            .unwrap()
            .serve_at("/prompt/empty", EmptyResultPrompt)
            .unwrap()
            .serve_at(
                "/prompt/full",
                UnlockingPrompt {
                    unlocked: target.clone(),
                },
            )
            .unwrap()
            .build()
            .await
            .unwrap();

        let client = Builder::address(bus.address.as_str())
            .unwrap()
            .build()
            .await
            .unwrap();
        let service_at = async |path: &str| -> ServiceProxy<'static> {
            ServiceProxy::builder(&client)
                .path(path.to_string())
                .unwrap()
                .cache_properties(CacheProperties::No)
                .build()
                .await
                .unwrap()
        };

        let empty = service_at("/svc/empty").await;
        let result = tokio::time::timeout(
            Duration::from_secs(20),
            unlock(&client, &empty, &target, Duration::from_secs(10)),
        )
        .await
        .expect("unlock blocked forever");
        match result {
            Err(GnomeError::PromptUnlockedNothing { object }) => {
                assert_eq!(object, target.as_str());
            }
            other => panic!("expected PromptUnlockedNothing, got {other:?}"),
        }

        let full = service_at("/svc/full").await;
        tokio::time::timeout(
            Duration::from_secs(20),
            unlock(&client, &full, &target, Duration::from_secs(10)),
        )
        .await
        .expect("unlock blocked forever")
        .expect("a prompt that named the object should be a successful unlock");
    }

    // ----------------------------------------------------------------
    // An Item whose Type cannot be read
    // ----------------------------------------------------------------

    const FAKE_COLLECTION: &str = "/org/freedesktop/secrets/collection/test";
    const FAKE_UNREADABLE_ITEM: &str = "/org/freedesktop/secrets/collection/test/1";
    const FAKE_READABLE_ITEM: &str = "/org/freedesktop/secrets/collection/test/2";
    const FAKE_ATTRLESS_ITEM: &str = "/org/freedesktop/secrets/collection/test/3";

    /// Every path whose secret was asked for, by any route. The assertion the
    /// refusal is worth making is not "it was not imported" but "its bytes
    /// never crossed the bus".
    type Fetched = Arc<Mutex<Vec<String>>>;

    struct TypeService {
        fetched: Fetched,
        /// The collection paths this service exposes. Per-test, because
        /// "every keyring the daemon holds" is itself under test.
        collections: Vec<&'static str>,
    }

    #[zbus::interface(name = "org.freedesktop.Secret.Service")]
    impl TypeService {
        fn open_session(
            &self,
            algorithm: &str,
            _input: Value<'_>,
        ) -> zbus::fdo::Result<(zbus::zvariant::OwnedValue, OwnedObjectPath)> {
            if algorithm != ALGORITHM_PLAIN {
                return Err(zbus::fdo::Error::NotSupported(algorithm.to_string()));
            }
            Ok((
                Value::from("").try_to_owned().unwrap(),
                OwnedObjectPath::try_from("/session/1").unwrap(),
            ))
        }

        fn read_alias(&self, _name: &str) -> OwnedObjectPath {
            OwnedObjectPath::try_from(NO_PROMPT).unwrap()
        }

        fn get_secrets(
            &self,
            items: Vec<OwnedObjectPath>,
            session: OwnedObjectPath,
        ) -> HashMap<OwnedObjectPath, crate::dbus::session::SecretStruct> {
            let mut out = HashMap::new();
            for path in items {
                self.fetched.lock().unwrap().push(path.as_str().to_string());
                out.insert(
                    path,
                    crate::dbus::session::SecretStruct {
                        session: session.clone(),
                        parameters: Vec::new(),
                        value: b"batched-secret".to_vec().into(),
                        content_type: "text/plain".into(),
                    },
                );
            }
            out
        }

        #[zbus(property)]
        fn collections(&self) -> Vec<OwnedObjectPath> {
            self.collections
                .iter()
                .map(|p| OwnedObjectPath::try_from(*p).unwrap())
                .collect()
        }
    }

    /// The item list is per-test rather than fixed: each test serves exactly
    /// the items it names, so one test's extra item cannot change another's
    /// counts.
    struct FakeCollection {
        items: Vec<&'static str>,
        label: &'static str,
    }

    #[zbus::interface(name = "org.freedesktop.Secret.Collection")]
    impl FakeCollection {
        #[zbus(property)]
        fn items(&self) -> Vec<OwnedObjectPath> {
            self.items
                .iter()
                .map(|p| OwnedObjectPath::try_from(*p).unwrap())
                .collect()
        }
        #[zbus(property)]
        fn label(&self) -> String {
            self.label.into()
        }
        #[zbus(property)]
        fn locked(&self) -> bool {
            false
        }
        #[zbus(property)]
        fn created(&self) -> u64 {
            1_788_893_013
        }
        #[zbus(property)]
        fn modified(&self) -> u64 {
            1_788_893_014
        }
    }

    struct FakeItem {
        path: &'static str,
        label: &'static str,
        /// `None` makes the `Type` property **fail**, which is the case under
        /// test: not absent, not answered — errored.
        item_type: Option<&'static str>,
        /// `true` makes the `Attributes` property **fail**: the daemon has the
        /// item and will not say what its attribute set is.
        attributes_fail: bool,
        fetched: Fetched,
    }

    #[zbus::interface(name = "org.freedesktop.Secret.Item")]
    impl FakeItem {
        fn get_secret(&self, session: OwnedObjectPath) -> crate::dbus::session::SecretStruct {
            self.fetched.lock().unwrap().push(self.path.to_string());
            crate::dbus::session::SecretStruct {
                session,
                parameters: Vec::new(),
                value: b"per-item-secret".to_vec().into(),
                content_type: "text/plain".into(),
            }
        }
        #[zbus(property)]
        fn attributes(&self) -> zbus::fdo::Result<HashMap<String, String>> {
            if self.attributes_fail {
                return Err(zbus::fdo::Error::Failed(
                    "attributes are unavailable".into(),
                ));
            }
            Ok(HashMap::from([(
                "server".to_string(),
                "example.com".to_string(),
            )]))
        }
        #[zbus(property)]
        fn label(&self) -> String {
            self.label.into()
        }
        #[zbus(property)]
        fn created(&self) -> u64 {
            1_788_893_013
        }
        #[zbus(property)]
        fn modified(&self) -> u64 {
            1_788_893_014
        }
        #[zbus(property, name = "Type")]
        fn item_type(&self) -> zbus::fdo::Result<String> {
            match self.item_type {
                Some(t) => Ok(t.to_string()),
                None => Err(zbus::fdo::Error::Failed("no idea".into())),
            }
        }
    }

    // ----------------------------------------------------------------
    // One keyring, or all of them
    // ----------------------------------------------------------------

    const LOGIN_COLLECTION: &str = "/org/freedesktop/secrets/collection/login";
    const LOGIN_ITEM: &str = "/org/freedesktop/secrets/collection/login/1";
    const WORK_COLLECTION: &str = "/org/freedesktop/secrets/collection/work";
    const WORK_ITEM: &str = "/org/freedesktop/secrets/collection/work/1";

    /// **A walk covers every keyring the daemon holds, and the caller labels
    /// its destination after one of them.**
    ///
    /// So without a filter the items of `Work` are written into a collection
    /// named `Login` — a label that misdescribes its contents, which is the
    /// one thing a migration must not produce. `only_container` is the fix,
    /// and [`Extraction::containers`] is what a caller that does not filter
    /// must consult before it labels anything.
    #[tokio::test]
    async fn a_filtered_walk_reads_one_keyring_and_an_unfiltered_one_reads_them_all() {
        let bus = match private_bus() {
            Ok(bus) => bus,
            Err(reason) => {
                println!("SKIPPED: {reason}");
                return;
            }
        };
        let fetched: Fetched = Arc::new(Mutex::new(Vec::new()));
        let _server = Builder::address(bus.address.as_str())
            .unwrap()
            .name(SECRETS_BUS_NAME)
            .unwrap()
            .serve_at(
                "/org/freedesktop/secrets",
                TypeService {
                    fetched: fetched.clone(),
                    collections: vec![LOGIN_COLLECTION, WORK_COLLECTION],
                },
            )
            .unwrap()
            .serve_at(
                LOGIN_COLLECTION,
                FakeCollection {
                    items: vec![LOGIN_ITEM],
                    label: "Login",
                },
            )
            .unwrap()
            .serve_at(
                WORK_COLLECTION,
                FakeCollection {
                    items: vec![WORK_ITEM],
                    label: "Work",
                },
            )
            .unwrap()
            .serve_at(
                LOGIN_ITEM,
                FakeItem {
                    path: LOGIN_ITEM,
                    label: "Login item",
                    item_type: Some(TYPE_GENERIC),
                    attributes_fail: false,
                    fetched: fetched.clone(),
                },
            )
            .unwrap()
            .serve_at(
                WORK_ITEM,
                FakeItem {
                    path: WORK_ITEM,
                    label: "Work item",
                    item_type: Some(TYPE_GENERIC),
                    attributes_fail: false,
                    fetched: fetched.clone(),
                },
            )
            .unwrap()
            .build()
            .await
            .unwrap();

        let client = Builder::address(bus.address.as_str())
            .unwrap()
            .build()
            .await
            .unwrap();
        let plain = ExtractOptions {
            prefer_dh: false,
            ..ExtractOptions::default()
        };

        // Unfiltered: both keyrings, and the walk says so rather than leaving
        // the caller to assume it read the one it named.
        let all = extract(&client, &plain)
            .await
            .expect("the unfiltered walk failed");
        assert_eq!(all.containers(), vec!["Login", "Work"], "{:?}", all.items);
        assert_eq!(all.collections.len(), 2);

        // Filtered: only the named keyring, and every item's provenance
        // agrees with the label the caller will use.
        let only_work = ExtractOptions {
            only_container: Some("Work".to_string()),
            ..plain.clone()
        };
        let work = extract(&client, &only_work)
            .await
            .expect("the filtered walk failed");
        assert_eq!(work.containers(), vec!["Work"], "{:?}", work.items);
        let labels: Vec<&str> = work.items.iter().map(|e| e.item.label.as_str()).collect();
        assert_eq!(labels, vec!["Work item"]);
        assert_eq!(
            work.collections.len(),
            1,
            "a keyring that was not walked must not be summarised: {:?}",
            work.collections
        );

        // The unnamed keyring's secret never crossed the bus.
        let fetched_paths = fetched.lock().unwrap().clone();
        assert_eq!(
            fetched_paths.iter().filter(|p| *p == LOGIN_ITEM).count(),
            1,
            "the filtered walk fetched a secret from the keyring it was told to skip: \
             {fetched_paths:?}"
        );

        // A name that matches nothing is an error, not a successful import of
        // nothing at all.
        let missing = ExtractOptions {
            only_container: Some("Nonexistent".to_string()),
            ..plain
        };
        match extract(&client, &missing).await {
            Err(GnomeError::NoSuchCollection {
                container,
                available,
            }) => {
                assert_eq!(container, "Nonexistent");
                assert!(
                    available.contains("Login") && available.contains("Work"),
                    "{available}"
                );
            }
            other => panic!("expected NoSuchCollection, got {other:?}"),
        }
    }

    /// **One unreadable attribute map refuses one item, not the run.**
    ///
    /// `Item.Attributes` used to be read with `?`, so a single item the source
    /// daemon would not describe aborted the whole walk and discarded every
    /// item already collected — while `Label`, `Created`, `Modified` and
    /// `Type` on the same object all degraded gracefully. The item still may
    /// not be written: attributes are how every libsecret client finds its
    /// secret again, and a copy with a guessed map is a secret nothing can
    /// look up. So it is refused, named in the report, and the walk goes on.
    #[tokio::test]
    async fn an_unreadable_attribute_map_refuses_one_item_and_not_the_walk() {
        let bus = match private_bus() {
            Ok(bus) => bus,
            Err(reason) => {
                println!("SKIPPED: {reason}");
                return;
            }
        };
        let fetched: Fetched = Arc::new(Mutex::new(Vec::new()));
        let _server = Builder::address(bus.address.as_str())
            .unwrap()
            .name(SECRETS_BUS_NAME)
            .unwrap()
            .serve_at(
                "/org/freedesktop/secrets",
                TypeService {
                    fetched: fetched.clone(),
                    collections: vec![FAKE_COLLECTION],
                },
            )
            .unwrap()
            .serve_at(
                FAKE_COLLECTION,
                FakeCollection {
                    items: vec![FAKE_ATTRLESS_ITEM, FAKE_READABLE_ITEM],
                    label: "Test",
                },
            )
            .unwrap()
            .serve_at(
                FAKE_ATTRLESS_ITEM,
                FakeItem {
                    path: FAKE_ATTRLESS_ITEM,
                    label: "Attributes Cannot Be Read",
                    item_type: Some(TYPE_GENERIC),
                    attributes_fail: true,
                    fetched: fetched.clone(),
                },
            )
            .unwrap()
            .serve_at(
                FAKE_READABLE_ITEM,
                FakeItem {
                    path: FAKE_READABLE_ITEM,
                    label: "Ordinary",
                    item_type: Some(TYPE_GENERIC),
                    attributes_fail: false,
                    fetched: fetched.clone(),
                },
            )
            .unwrap()
            .build()
            .await
            .unwrap();

        let client = Builder::address(bus.address.as_str())
            .unwrap()
            .build()
            .await
            .unwrap();
        let options = ExtractOptions {
            prefer_dh: false,
            ..ExtractOptions::default()
        };
        let extraction = tokio::time::timeout(Duration::from_secs(30), extract(&client, &options))
            .await
            .expect("the walk blocked forever")
            .expect("one unreadable attribute map must not abort the walk");

        // The item after it in walk order is still imported: that is the half
        // the `?` used to throw away.
        let labels: Vec<&str> = extraction
            .items
            .iter()
            .map(|e| e.item.label.as_str())
            .collect();
        assert_eq!(labels, vec!["Ordinary"], "{:?}", extraction.items);

        assert_eq!(extraction.refused.len(), 1, "{:?}", extraction.refused);
        let refused = &extraction.refused[0];
        assert_eq!(refused.label, "Attributes Cannot Be Read");
        assert_eq!(refused.refusals, vec![Refusal::UnreadableAttributes]);
        assert!(refused.attribute_keys.is_empty());
        assert_eq!(refused.secret_len, 0);
        assert_eq!(refused.outcome, None);

        // Refused before the second pass, so its bytes never crossed the bus.
        let fetched = fetched.lock().unwrap().clone();
        assert!(
            !fetched.iter().any(|p| p == FAKE_ATTRLESS_ITEM),
            "the secret of an item with no readable attributes was fetched: {fetched:?}"
        );
    }

    /// **A question nobody asked has no answer.**
    ///
    /// `item_type_unavailable` says "this provider exposes no `Item.Type`",
    /// and the CLI turns it into "check by hand that no imported item is an
    /// unlock credential". An item refused for unreadable attributes returns
    /// from `read_metadata` *above* the `Type` read, so it never consulted the
    /// property at all — and a walk whose every item was refused that way
    /// consulted it zero times. Marking the item seen before the read is what
    /// made such a walk print a claim about a property nothing had asked
    /// about.
    #[tokio::test]
    async fn a_walk_that_never_reached_a_type_read_claims_nothing_about_the_property() {
        let bus = match private_bus() {
            Ok(bus) => bus,
            Err(reason) => {
                println!("SKIPPED: {reason}");
                return;
            }
        };
        let fetched: Fetched = Arc::new(Mutex::new(Vec::new()));
        let _server = Builder::address(bus.address.as_str())
            .unwrap()
            .name(SECRETS_BUS_NAME)
            .unwrap()
            .serve_at(
                "/org/freedesktop/secrets",
                TypeService {
                    fetched: fetched.clone(),
                    collections: vec![FAKE_COLLECTION],
                },
            )
            .unwrap()
            .serve_at(
                FAKE_COLLECTION,
                FakeCollection {
                    items: vec![FAKE_ATTRLESS_ITEM],
                    label: "Test",
                },
            )
            .unwrap()
            .serve_at(
                FAKE_ATTRLESS_ITEM,
                FakeItem {
                    path: FAKE_ATTRLESS_ITEM,
                    // The property is there and would answer; the walk never
                    // gets that far, which is the point.
                    label: "Attributes Cannot Be Read",
                    item_type: Some(TYPE_GENERIC),
                    attributes_fail: true,
                    fetched: fetched.clone(),
                },
            )
            .unwrap()
            .build()
            .await
            .unwrap();

        let client = Builder::address(bus.address.as_str())
            .unwrap()
            .build()
            .await
            .unwrap();
        let options = ExtractOptions {
            prefer_dh: false,
            ..ExtractOptions::default()
        };
        let extraction = tokio::time::timeout(Duration::from_secs(30), extract(&client, &options))
            .await
            .expect("the walk blocked forever")
            .expect("the walk itself failed");

        assert!(extraction.items.is_empty(), "{:?}", extraction.items);
        assert_eq!(extraction.refused.len(), 1, "{:?}", extraction.refused);
        assert!(
            !extraction.item_type_unavailable,
            "the walk consulted Item.Type for no item, so it may not report that the \
             provider has none"
        );
    }

    /// **The refusal must not fail open on the one input the foreign daemon
    /// controls.** A `Type` read that *errors* is not a provider without the
    /// property: nothing was established, so the item may be an unlock
    /// credential for another keyring, and importing it on the strength of a
    /// failed read is the failure this module exists to prevent.
    ///
    /// Collapsing the three outcomes into `Option<String>` made
    /// `is_unlock_credential_type(None)` false, so the item was carried, its
    /// secret fetched, and it was imported with nothing said — the
    /// `item_type_unavailable` backstop cannot fire, because the *other* item
    /// here exposes its type perfectly well.
    #[tokio::test]
    async fn an_item_whose_type_cannot_be_read_is_refused_not_imported() {
        let bus = match private_bus() {
            Ok(bus) => bus,
            Err(reason) => {
                println!("SKIPPED: {reason}");
                return;
            }
        };
        let fetched: Fetched = Arc::new(Mutex::new(Vec::new()));
        let _server = Builder::address(bus.address.as_str())
            .unwrap()
            .name(SECRETS_BUS_NAME)
            .unwrap()
            .serve_at(
                "/org/freedesktop/secrets",
                TypeService {
                    fetched: fetched.clone(),
                    collections: vec![FAKE_COLLECTION],
                },
            )
            .unwrap()
            .serve_at(
                FAKE_COLLECTION,
                FakeCollection {
                    items: vec![FAKE_UNREADABLE_ITEM, FAKE_READABLE_ITEM],
                    label: "Test",
                },
            )
            .unwrap()
            .serve_at(
                FAKE_UNREADABLE_ITEM,
                FakeItem {
                    path: FAKE_UNREADABLE_ITEM,
                    label: "Type Cannot Be Read",
                    item_type: None,
                    attributes_fail: false,
                    fetched: fetched.clone(),
                },
            )
            .unwrap()
            .serve_at(
                FAKE_READABLE_ITEM,
                FakeItem {
                    path: FAKE_READABLE_ITEM,
                    label: "Ordinary",
                    item_type: Some(TYPE_GENERIC),
                    attributes_fail: false,
                    fetched: fetched.clone(),
                },
            )
            .unwrap()
            .build()
            .await
            .unwrap();

        let client = Builder::address(bus.address.as_str())
            .unwrap()
            .build()
            .await
            .unwrap();
        let options = ExtractOptions {
            prefer_dh: false,
            ..ExtractOptions::default()
        };
        let extraction = tokio::time::timeout(Duration::from_secs(30), extract(&client, &options))
            .await
            .expect("the walk blocked forever")
            .expect("the walk itself failed");

        // The ordinary item still comes through, so the refusal is selective
        // rather than a blanket failure that would pass this test vacuously.
        let labels: Vec<&str> = extraction
            .items
            .iter()
            .map(|e| e.item.label.as_str())
            .collect();
        assert_eq!(labels, vec!["Ordinary"], "{:?}", extraction.items);

        assert_eq!(extraction.refused.len(), 1, "{:?}", extraction.refused);
        let refused = &extraction.refused[0];
        assert_eq!(refused.label, "Type Cannot Be Read");
        assert!(refused.is_refused());
        assert_eq!(refused.secret_len, 0);
        // The refusal says what is true — the type could not be read — and
        // not "type 3 unlocks another keyring", which is a claim about an item
        // whose type nobody established.
        assert_eq!(refused.refusals, vec![Refusal::UnreadableItemType]);

        // The point of refusing before the second pass: the bytes never
        // crossed the bus at all.
        let fetched = fetched.lock().unwrap().clone();
        assert!(
            !fetched.iter().any(|p| p == FAKE_UNREADABLE_ITEM),
            "the secret of an item with an unreadable type was fetched: {fetched:?}"
        );
        assert!(
            fetched.iter().any(|p| p == FAKE_READABLE_ITEM),
            "the ordinary item's secret was never fetched: {fetched:?}"
        );

        // One item did expose its type, so the backstop is silent — which is
        // exactly why it cannot stand in for this refusal.
        assert!(!extraction.item_type_unavailable);
    }

    // ----------------------------------------------------------------
    // The private copy the child is pointed at
    // ----------------------------------------------------------------

    /// Every regular file comes across, the copies are 0600 under a 0700
    /// directory, and the layout is the one `XDG_DATA_HOME` implies — because
    /// the whole point is that a child told to write to `keyrings/` writes
    /// here and not in the user's home.
    #[test]
    fn a_snapshot_copies_the_directory_and_nothing_of_it_leaks() {
        use std::os::unix::fs::PermissionsExt;
        let source = tempfile::tempdir().unwrap();
        std::fs::write(source.path().join("login.keyring"), b"keyring bytes").unwrap();
        std::fs::write(source.path().join("default"), b"login\n").unwrap();
        std::fs::create_dir(source.path().join("a-subdirectory")).unwrap();

        let snapshot = KeyringSnapshot::create(source.path()).unwrap();
        let copied = snapshot.data_home().join(KEYRINGS_SUBDIR);
        assert_eq!(
            std::fs::read(copied.join("login.keyring")).unwrap(),
            b"keyring bytes"
        );
        assert_eq!(std::fs::read(copied.join("default")).unwrap(), b"login\n");
        assert!(!copied.join("a-subdirectory").exists());
        assert_eq!(
            std::fs::metadata(&copied).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            std::fs::metadata(copied.join("login.keyring"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );

        // What the child does to the copy stays in the copy.
        std::fs::write(copied.join("login.keyring"), b"rewritten by the daemon").unwrap();
        std::fs::write(copied.join("user.keystore"), b"created by the daemon").unwrap();
        assert_eq!(
            std::fs::read(source.path().join("login.keyring")).unwrap(),
            b"keyring bytes"
        );
        assert!(!source.path().join("user.keystore").exists());

        let path = snapshot.data_home().to_path_buf();
        drop(snapshot);
        assert!(!path.exists(), "the private copy outlived the extraction");
    }

    // ----------------------------------------------------------------
    // The live path
    // ----------------------------------------------------------------

    /// The finding this exists for: `gnome-keyring-daemon --unlock` is not a
    /// reader. Pointed at a directory it *writes* to it — it creates a
    /// `login.keyring` where there is none, and rewrites what it opens — so a
    /// run pointed at the user's own `$XDG_DATA_HOME` modifies the very files
    /// `--dry-run` promises it has not touched.
    ///
    /// So the assertion is about the source directory, made against a real
    /// daemon: start one on the snapshot of a directory, and afterwards that
    /// directory holds exactly the bytes and exactly the names it started
    /// with. Point the same daemon at the directory itself and it does not,
    /// which is the bug.
    #[tokio::test]
    #[ignore = "needs a live gnome-keyring-daemon and dbus-daemon; run with `cargo test -- --ignored`"]
    async fn a_live_daemon_writes_to_the_snapshot_and_not_to_the_source() {
        if !live_prerequisites() {
            return;
        }
        let source = tempfile::tempdir().expect("a writable temp directory");
        let keyrings = source.path().join(KEYRINGS_SUBDIR);
        std::fs::create_dir(&keyrings).unwrap();
        // A directory with no `login.keyring` at all: the case where the child
        // creates one.
        std::fs::write(keyrings.join("default"), b"login\n").unwrap();
        let before = std::fs::read(keyrings.join("default")).unwrap();

        let snapshot = KeyringSnapshot::create(&keyrings).expect("the snapshot is made");
        let password = Zeroizing::new(b"sm-import-snapshot-test".to_vec());
        match PrivateKeyring::start(&password, snapshot.data_home()).await {
            Ok(mut keyring) => keyring.shutdown().await,
            Err(e) => {
                println!("SKIPPED: could not start a private gnome-keyring: {e}");
                return;
            }
        }

        let mut names: Vec<String> = std::fs::read_dir(&keyrings)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        assert_eq!(
            names,
            ["default"],
            "the daemon wrote into the user's own keyrings directory"
        );
        assert_eq!(std::fs::read(keyrings.join("default")).unwrap(), before);
    }

    /// `false`, with a printed reason, when one of `programs` is not on this
    /// machine. A skip that says why is the only honest alternative to
    /// coverage; a silent pass is the failure mode the whole suite exists to
    /// avoid.
    ///
    /// Presence is "ran `--version` and exited zero". `status().is_err()`
    /// alone accepts a binary that ran and failed, which is a broken tool
    /// reported as a present one — so every live test asks the question here
    /// rather than writing its own weaker version of it.
    fn programs_present(programs: &[&str]) -> bool {
        let mut missing = Vec::new();
        for program in programs {
            let ran = StdCommand::new(program)
                .arg("--version")
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
            if !matches!(ran, Ok(status) if status.success()) {
                missing.push(*program);
            }
        }
        if missing.is_empty() {
            return true;
        }
        println!(
            "SKIPPED: {} is not installed, or did not answer --version successfully",
            missing.join(", ")
        );
        false
    }

    /// `false`, with a printed reason, when this machine cannot run the live
    /// extraction.
    fn live_prerequisites() -> bool {
        programs_present(&["dbus-daemon", GNOME_KEYRING_PROGRAM])
    }

    /// The synthetic tests above pin the *decision*; this pins the two command
    /// invocations that feed it. A `busctl` whose output format moved, or a
    /// `ps` invoked with the wrong flag, would leave every synthetic test green
    /// while the real check answered `Unowned` for every machine — which is
    /// silence, so no import would break, but nobody would ever be told their
    /// source is stale.
    #[tokio::test]
    #[ignore = "needs the real busctl/ps and a live session bus; run with `cargo test -- --ignored`"]
    async fn the_real_bus_owner_check_runs_against_the_real_tools() {
        if !programs_present(&["busctl", "ps"]) {
            return;
        }
        let owner = secrets_bus_owner().await.expect("the check itself failed");
        match &owner {
            // No session bus, or nobody serving secrets: a legitimate answer.
            // `Unowned` is the state the install guides leave behind and is
            // silent; an owner nobody could identify is worth a sentence.
            BusOwner::Unowned => {
                assert!(!owner.is_gnome_keyring());
                assert_eq!(owner.foreign_provider_warning(), None);
            }
            BusOwner::Unidentified { .. } => {
                assert!(!owner.is_gnome_keyring());
                assert!(owner.foreign_provider_warning().is_some());
            }
            BusOwner::Process { pid, command } => {
                assert!(*pid > 0);
                assert!(
                    program_name(command).is_some(),
                    "ps said {command:?}, which names no program"
                );
                assert_eq!(
                    owner.is_gnome_keyring(),
                    program_name(command) == Some(GNOME_KEYRING_PROGRAM)
                );
            }
        }
        // Not `warning.is_none() == is_gnome_keyring() || is_secret_manager()`,
        // which is `foreign_provider_warning`'s own guard clause restated: it
        // passes however wrong the guard is, and it sat inside the `Process`
        // arm, which does not run at all on a machine where nothing owns the
        // name. What a live run can pin instead is that the sentence is built
        // from what the real `ps` said, rather than from a constant.
        if let Some(warning) = owner.foreign_provider_warning() {
            assert!(
                warning.contains(&owner.describe()),
                "the warning does not name the owner it is about: {warning:?}"
            );
        }
        // Whatever the answer, it renders without panicking and names the bus.
        assert!(owner.describe().contains(SECRETS_BUS_NAME));
    }

    /// The end-to-end path, against a real `gnome-keyring-daemon` on a bus
    /// nobody else can see and a keyrings directory of its own.
    ///
    /// `XDG_DATA_HOME` is redirected at the child, so this never reads, writes
    /// or locks the user's real keyrings: the daemon creates a fresh
    /// `login.keyring` with the password this test chose. That is what makes
    /// the assertions worth making — the items are ones this test put there,
    /// so "attributes byte-for-byte" and "the chained item is refused" are
    /// checkable rather than hopeful.
    #[tokio::test]
    #[ignore = "needs a live gnome-keyring-daemon on a private bus; run with `cargo test -- --ignored`"]
    async fn a_real_gnome_keyring_round_trips_through_the_walk() {
        if !live_prerequisites() {
            return;
        }
        let data_home = tempfile::tempdir().expect("a writable temp directory");
        let password = Zeroizing::new(b"sm-import-live-test".to_vec());
        let mut keyring = match PrivateKeyring::start(&password, data_home.path()).await {
            Ok(k) => k,
            Err(e) => {
                println!("SKIPPED: could not start a private gnome-keyring: {e}");
                return;
            }
        };
        assert!(keyring.address().starts_with("unix:"));
        let (bus_pid, keyring_pid) = keyring.child_pids();

        let outcome = populate_and_walk(keyring.address()).await;
        keyring.shutdown().await;

        // Reaping is the invariant, not a nicety: a private bus and a
        // gnome-keyring left running after the tool exits is a leak with the
        // user's keyrings open inside it.
        for pid in [bus_pid, keyring_pid] {
            let pid = pid.expect("both children had pids");
            assert!(
                !Path::new(&format!("/proc/{pid}")).exists(),
                "pid {pid} survived shutdown"
            );
        }

        let extraction = match outcome {
            Ok(e) => e,
            Err(reason) => {
                println!("SKIPPED: {reason}");
                return;
            }
        };

        assert!(
            extraction
                .collections
                .iter()
                .all(|c| !is_session_collection(&c.path)),
            "the in-memory session collection was not skipped: {:?}",
            extraction.collections
        );
        // A plain transport is never silent: whichever way `open_session`
        // reached it, the reason is there for the CLI to print. This walk asks
        // for DH, so the expected shape is `None` — but a source that refuses
        // DH is a legitimate outcome here and must carry its reason.
        if let Some(reason) = &extraction.plain_fallback_reason {
            assert!(!reason.is_empty(), "a plain run with no reason given");
        }
        // The property is there, so the refusal is a check that can actually
        // fire. If it were absent the extraction must say so rather than
        // quietly importing an unlock credential.
        assert!(!extraction.item_type_unavailable);

        let generic = extraction
            .items
            .iter()
            .find(|e| e.item.label == "Live Generic")
            .expect("the generic item did not survive the walk");
        // Byte-for-byte: exactly what the source reports, with nothing added
        // and nothing normalised. The `xdg:schema` is **gnome-keyring's**, not
        // ours — it derives one from `Item.Type` when an item is created, and
        // it is part of the stored attribute set the client will search on.
        // Copying it is fidelity; the rule the importer must not break is
        // inventing one where the source has none, which the two items on the
        // author's machine with no schema would expose.
        assert_eq!(
            generic.item.attributes,
            BTreeMap::from([
                ("server".to_string(), "example.com".to_string()),
                ("user".to_string(), "joseph".to_string()),
                ("xdg:schema".to_string(), TYPE_GENERIC.to_string()),
            ])
        );
        assert_eq!(
            generic.report().outcome,
            Some(super::super::Outcome::FullyPortable)
        );
        assert_eq!(generic.item.secret.as_slice(), b"live-secret\n\x00bytes");
        assert_eq!(generic.item.content_type, "text/plain");
        assert!(generic.item.created > 0 && generic.item.modified > 0);
        assert_eq!(generic.item_type.as_deref(), Some(TYPE_GENERIC));
        assert_eq!(generic.report().lost_item_type, None);
        assert!(generic.report().acl_downgrade);

        let note = extraction
            .items
            .iter()
            .find(|e| e.item.label == "Live Note")
            .expect("the note did not survive the walk");
        assert_eq!(note.item_type.as_deref(), Some(TYPE_NOTE));
        assert_eq!(note.report().lost_item_type, Some(ITEM_TYPE_NOTE));

        // The refusal the spec insists on, fired against a real item of a real
        // type, and with its secret never fetched.
        let refused: Vec<_> = extraction
            .refused
            .iter()
            .filter(|r| {
                r.refusals
                    .iter()
                    .any(|f| matches!(f, Refusal::ChainedKeyringItem { .. }))
            })
            .collect();
        assert_eq!(refused.len(), 2, "{:?}", extraction.refused);
        let mut codes: Vec<u32> = refused
            .iter()
            .flat_map(|r| {
                r.refusals.iter().filter_map(|f| match f {
                    Refusal::ChainedKeyringItem { item_type } => Some(*item_type),
                    _ => None,
                })
            })
            .collect();
        codes.sort_unstable();
        assert_eq!(
            codes,
            vec![
                ITEM_TYPE_CHAINED_KEYRING_PASSWORD,
                ITEM_TYPE_ENCRYPTION_KEY_PASSWORD
            ]
        );
        for r in refused {
            assert_eq!(r.secret_len, 0, "a refused item's secret was read");
            assert_eq!(r.outcome, None);
        }
        assert!(
            !extraction.items.iter().any(|e| e
                .item_type
                .as_deref()
                .is_some_and(is_unlock_credential_type)),
            "an unlock credential was imported"
        );
    }

    /// Writes four items into the private keyring's default collection and
    /// then walks it. `Err(reason)` is a skip, not a failure: a machine where
    /// gnome-keyring cannot create its login keyring cannot run this test, and
    /// saying so is better than a red suite that means "not here".
    async fn populate_and_walk(address: &str) -> Result<Extraction, String> {
        use std::collections::HashMap;

        let conn = Builder::address(address)
            .map_err(|e| e.to_string())?
            .build()
            .await
            .map_err(|e| e.to_string())?;
        let service = ServiceProxy::builder(&conn)
            .cache_properties(CacheProperties::No)
            .build()
            .await
            .map_err(|e| e.to_string())?;
        let (_, session) = service
            .open_session(ALGORITHM_PLAIN, &Value::from(""))
            .await
            .map_err(|e| e.to_string())?;
        let default = service
            .read_alias("default")
            .await
            .map_err(|e| e.to_string())?;
        if default.as_str() == NO_PROMPT {
            return Err("gnome-keyring created no default collection to write into".into());
        }
        let collection = CollectionProxy::builder(&conn)
            .path(default)
            .map_err(|e| e.to_string())?
            .cache_properties(CacheProperties::No)
            .build()
            .await
            .map_err(|e| e.to_string())?;

        /// Label, `Item.Type`, attributes, secret bytes.
        struct Case {
            label: &'static str,
            item_type: &'static str,
            attributes: &'static [(&'static str, &'static str)],
            secret: &'static [u8],
        }
        const fn case(
            label: &'static str,
            item_type: &'static str,
            attributes: &'static [(&'static str, &'static str)],
            secret: &'static [u8],
        ) -> Case {
            Case {
                label,
                item_type,
                attributes,
                secret,
            }
        }

        // A secret with an embedded NUL and an interior newline, because those
        // are the bytes an importer is most likely to mangle.
        let cases = [
            case(
                "Live Generic",
                TYPE_GENERIC,
                &[("server", "example.com"), ("user", "joseph")],
                b"live-secret\n\x00bytes",
            ),
            case("Live Note", TYPE_NOTE, &[("note", "n")], b"note body"),
            case(
                "Unlock password for Extra keyring",
                TYPE_CHAINED_KEYRING,
                &[("keyring", "extra")],
                b"must-never-be-read",
            ),
            case(
                "Encryption key password",
                TYPE_ENCRYPTION_KEY,
                &[("key", "k")],
                b"must-never-be-read",
            ),
        ];
        for Case {
            label,
            item_type,
            attributes,
            secret,
        } in cases
        {
            let attrs: HashMap<&str, &str> = attributes.iter().copied().collect();
            let mut props: HashMap<&str, Value<'_>> = HashMap::new();
            props.insert("org.freedesktop.Secret.Item.Label", Value::from(label));
            props.insert("org.freedesktop.Secret.Item.Type", Value::from(item_type));
            props.insert(
                "org.freedesktop.Secret.Item.Attributes",
                Value::from(attrs.clone()),
            );
            let struct_ = crate::dbus::session::SecretStruct {
                session: session.clone(),
                parameters: Vec::new(),
                value: secret.to_vec().into(),
                content_type: "text/plain".into(),
            };
            collection
                .create_item(props, &struct_, true)
                .await
                .map_err(|e| format!("CreateItem({label}) failed: {e}"))?;
        }

        extract(&conn, &ExtractOptions::default())
            .await
            .map_err(|e| e.to_string())
    }
}
