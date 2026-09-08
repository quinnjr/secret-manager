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
    ITEM_TYPE_GENERIC_SECRET, ITEM_TYPE_NETWORK_PASSWORD, ITEM_TYPE_NOTE,
};
use super::{ItemReport, Provenance, Refusal, SourceItem};
use crate::dbus::prompt::display_label;
use crate::dbus::proxies::{CollectionProxy, ItemProxy, PromptProxy, ServiceProxy, SessionProxy};
use crate::session::dh::KeyPair;
use crate::session::{ALGORITHM_DH, ALGORITHM_PLAIN, SessionCipher};
use futures_util::StreamExt;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, Command};
use zbus::Connection;
use zbus::connection::Builder;
use zbus::proxy::CacheProperties;
use zbus::zvariant::{OwnedObjectPath, Value};
use zeroize::Zeroizing;

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
/// know, which is reported as an unknown type rather than guessed at.
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
/// Reusable on purpose: the CLI asks this question before it offers any
/// session-bus route, and the answer is the same question this module asks.
pub async fn secrets_bus_owner() -> Result<BusOwner, GnomeError> {
    let status = run_capture("busctl", &["--user", "status", SECRETS_BUS_NAME]).await?;
    let Some(pid) = status.as_deref().and_then(parse_busctl_pid) else {
        return Ok(BusOwner::Unowned);
    };
    let ps = run_capture("ps", &["-p", &pid.to_string(), "-o", "cmd="]).await?;
    Ok(classify_bus_owner(status.as_deref(), ps.as_deref()))
}

/// The precondition, with no override flag.
///
/// A `--from` that disagrees with the bus is a user error worth stopping for,
/// not a warning worth printing: the failure it prevents is a silent,
/// successful-looking migration of the wrong data.
pub async fn require_gnome_keyring_owner() -> Result<BusOwner, GnomeError> {
    let owner = secrets_bus_owner().await?;
    if owner.is_gnome_keyring() {
        Ok(owner)
    } else {
        Err(GnomeError::WrongBusOwner {
            owner: owner.describe(),
        })
    }
}

/// Runs a command to completion under [`COMMAND_TIMEOUT`], returning its
/// stdout when it exits 0 and `None` when it does not.
///
/// A non-zero exit is not an error here: `busctl status` exits non-zero for a
/// name nobody owns, and `ps` for a pid that has gone. Both are answers.
async fn run_capture(program: &str, args: &[&str]) -> Result<Option<String>, GnomeError> {
    let child = Command::new(program)
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
    Ok(String::from_utf8(out.stdout).ok())
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

/// Every way this module can fail, each one named so a report can say which.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum GnomeError {
    /// The precondition. No override flag exists, deliberately.
    #[error(
        "refusing to read gnome-keyring from the session bus: {owner}, not {GNOME_KEYRING_PROGRAM}. \
         Migrate that provider instead, or stop it and log back in so gnome-keyring takes the name."
    )]
    WrongBusOwner { owner: String },

    #[error("could not run {program}: {message}")]
    Spawn { program: String, message: String },

    #[error("{program} did not finish within {waited:?}")]
    CommandTimeout { program: String, waited: Duration },

    #[error("the private session bus did not print an address within {waited:?}")]
    BusNeverReady { waited: Duration },

    #[error(
        "gnome-keyring-daemon did not take {SECRETS_BUS_NAME} on the private bus within \
         {waited:?}; the password may be wrong"
    )]
    KeyringNeverReady { waited: Duration },

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

    #[error("{call} failed: {message}")]
    Bus { call: String, message: String },

    #[error("{call} did not answer within {waited:?}")]
    CallTimeout { call: String, waited: Duration },

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
            let _ = child.start_kill();
            let _ = tokio::time::timeout(COMMAND_TIMEOUT, child.wait()).await;
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
        // alone, so removing it whole is right and a failure is not worth
        // reporting over the error that is already on its way out.
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A running gnome-keyring on a session bus nobody else can see.
///
/// Dropping it kills both children. [`PrivateKeyring::shutdown`] is the
/// ordinary path and waits for them; `Drop` is the backstop for a panic or an
/// early return, which is why both exist.
pub struct PrivateKeyring {
    bus: Reaped,
    keyring: Reaped,
    address: String,
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
    /// gnome-keyring finds `keyrings/`. `None` means the user's own, which is
    /// what a migration wants; a path means that directory and nothing else,
    /// which is what reading a backup — or a test — wants. It is set on the
    /// child alone, so the process running the import is unaffected.
    pub async fn start(
        password: &Zeroizing<Vec<u8>>,
        data_home: Option<&Path>,
    ) -> Result<PrivateKeyring, GnomeError> {
        let control_dir = PrivateDir::create().map_err(|e| GnomeError::Spawn {
            program: "control directory".into(),
            message: e.to_string(),
        })?;

        let mut bus = Reaped(Some(
            Command::new("dbus-daemon")
                // No `--address`: the packaged session.conf listens under
                // `/tmp`, and a socket path we chose ourselves inside a long
                // temp directory overflows `sun_path` — a 108-byte limit that
                // fails as "Socket name too long" and looks like a bug in
                // dbus.
                .args(["--session", "--nofork", "--nopidfile", "--print-address"])
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .kill_on_drop(true)
                .spawn()
                .map_err(|e| GnomeError::Spawn {
                    program: "dbus-daemon".into(),
                    message: e.to_string(),
                })?,
        ));

        let address = match read_address(&mut bus).await {
            Ok(a) => a,
            Err(e) => {
                bus.reap().await;
                return Err(e);
            }
        };

        let mut started = Command::new(GNOME_KEYRING_PROGRAM);
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
            .kill_on_drop(true);
        if let Some(home) = data_home {
            started.env("XDG_DATA_HOME", home);
        }

        let keyring = Reaped(Some(started.spawn().map_err(|e| GnomeError::Spawn {
            program: GNOME_KEYRING_PROGRAM.into(),
            message: e.to_string(),
        })?));

        let mut this = PrivateKeyring {
            bus,
            keyring,
            address,
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
                detail: e.to_string(),
            })?;
        // Dropping the pipe is the EOF the reader may be waiting for.
        drop(stdin);
        Ok(())
    }

    /// Polls until gnome-keyring owns [`SECRETS_BUS_NAME`] on the private bus,
    /// or the child dies, or [`STARTUP_TIMEOUT`] expires.
    async fn await_name(&mut self) -> Result<(), GnomeError> {
        let deadline = tokio::time::Instant::now() + STARTUP_TIMEOUT;
        loop {
            if let Some(child) = self.keyring.0.as_mut()
                && let Ok(Some(status)) = child.try_wait()
            {
                return Err(GnomeError::KeyringExited {
                    detail: format!("exited with {status}"),
                });
            }
            if let Ok(builder) = Builder::address(self.address.as_str())
                && let Ok(conn) = builder.build().await
                && let Ok(proxy) = ServiceProxy::builder(&conn)
                    .cache_properties(CacheProperties::No)
                    .build()
                    .await
                && proxy.collections().await.is_ok()
            {
                return Ok(());
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(GnomeError::KeyringNeverReady {
                    waited: STARTUP_TIMEOUT,
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
    let proxy = PromptProxy::builder(conn)
        .path(prompt.clone())
        .map(|b| b.cache_properties(CacheProperties::No))
        .map_err(|e| GnomeError::Bus {
            call: "Prompt".into(),
            message: e.to_string(),
        })?
        .build()
        .await
        .map_err(|e| GnomeError::Bus {
            call: "Prompt".into(),
            message: e.to_string(),
        })?;
    let mut completed = call("Prompt.Completed subscribe", proxy.receive_completed()).await?;
    call("Prompt.Prompt", proxy.prompt("")).await?;

    let signal = match tokio::time::timeout(timeout, completed.next()).await {
        Ok(Some(signal)) => signal,
        Ok(None) => {
            return Err(GnomeError::UnanswerablePrompt {
                object: prompt.as_str().to_string(),
                waited: timeout,
            });
        }
        Err(_) => {
            // Best effort: the dialog nobody can answer should not outlive us
            // either. Its failure is not interesting — the prompt is already
            // being reported as unanswerable.
            let _ = tokio::time::timeout(COMMAND_TIMEOUT, proxy.dismiss()).await;
            return Err(GnomeError::UnanswerablePrompt {
                object: prompt.as_str().to_string(),
                waited: timeout,
            });
        }
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
    pub item_count: usize,
    /// The collection could not be unlocked because its prompt cannot be
    /// answered. Its items are absent from the extraction, and that is a
    /// reported error rather than a silent shortfall.
    pub unanswerable_prompt: bool,
}

/// One item, with the source type the vault has no room for.
#[derive(Debug, Clone)]
pub struct ExtractedItem {
    pub item: SourceItem,
    /// gnome-keyring's `Item.Type` string, or `None` when the daemon does not
    /// expose the property.
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
    pub fn report(&self) -> ItemReport {
        let mut report = ItemReport::imported(&self.item);
        report.acl_downgrade = true;
        report.lost_item_type = self
            .item_type
            .as_deref()
            .filter(|t| *t != TYPE_GENERIC)
            .and_then(item_type_code);
        report
    }
}

/// Everything one walk produced.
#[derive(Debug, Clone)]
pub struct Extraction {
    pub items: Vec<ExtractedItem>,
    /// Items that were read *about* and never read: an unlock credential's
    /// secret is not fetched at all, and a cap violation's is dropped.
    pub refused: Vec<ItemReport>,
    pub collections: Vec<CollectionSummary>,
    /// The label of the collection `ReadAlias("default")` names.
    pub default_collection: Option<String>,
    /// `dh-ietf1024-sha256-aes128-cbc-pkcs7`, or `plain` with a reason.
    pub algorithm: &'static str,
    /// Why DH was not used, when it was not. Present in the report so a
    /// plaintext-on-the-bus run is never silent.
    pub plain_fallback_reason: Option<String>,
    /// No item exposed `Item.Type`, so the chained-item refusal could not be
    /// evaluated on this source. A refusal that cannot fire is worse than
    /// none, because it looks like protection; the caller must say so.
    pub item_type_unavailable: bool,
}

impl Extraction {
    /// Collections whose unlock prompt could not be answered. Their items are
    /// missing, and the independent count from the cleartext header will say
    /// so — this names why.
    pub fn unanswerable_collections(&self) -> impl Iterator<Item = &CollectionSummary> {
        self.collections.iter().filter(|c| c.unanswerable_prompt)
    }
}

/// Options a caller can vary; every field has a defensible default.
#[derive(Debug, Clone)]
pub struct ExtractOptions {
    /// How long to wait on an unlock prompt before naming it unanswerable.
    pub prompt_timeout: Duration,
    /// Try `dh-ietf1024-sha256-aes128-cbc-pkcs7` first. Off only for a source
    /// known not to implement it; the fallback is automatic either way.
    pub prefer_dh: bool,
    /// `XDG_DATA_HOME` for the private gnome-keyring, or `None` for the
    /// user's own. See [`PrivateKeyring::start`].
    pub data_home: Option<PathBuf>,
}

impl Default for ExtractOptions {
    fn default() -> Self {
        ExtractOptions {
            prompt_timeout: PROMPT_TIMEOUT,
            prefer_dh: true,
            data_home: None,
        }
    }
}

/// Starts a private bus and a private gnome-keyring, walks it, and shuts both
/// down — on the error path too.
pub async fn extract_over_private_bus(
    password: &Zeroizing<Vec<u8>>,
    options: &ExtractOptions,
) -> Result<Extraction, GnomeError> {
    let mut keyring = PrivateKeyring::start(password, options.data_home.as_deref()).await?;
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
/// connection — a two-bus test fixture, or a session-bus route that has passed
/// [`require_gnome_keyring_owner`] — reuses the same walk rather than a second
/// copy of it.
pub async fn extract(
    conn: &Connection,
    options: &ExtractOptions,
) -> Result<Extraction, GnomeError> {
    let service = ServiceProxy::builder(conn)
        .cache_properties(CacheProperties::No)
        .build()
        .await
        .map_err(|e| GnomeError::Bus {
            call: "Service".into(),
            message: e.to_string(),
        })?;

    let (session, cipher, algorithm, plain_fallback_reason) =
        open_session(&service, options.prefer_dh).await?;

    let mut out = Extraction {
        items: Vec::new(),
        refused: Vec::new(),
        collections: Vec::new(),
        default_collection: None,
        algorithm,
        plain_fallback_reason,
        item_type_unavailable: false,
    };

    let default_path = call("Service.ReadAlias", service.read_alias("default"))
        .await
        .ok()
        .filter(|p| p.as_str() != NO_PROMPT);

    let mut saw_type = false;
    let mut saw_item = false;

    for path in call("Service.Collections", service.collections()).await? {
        if is_session_collection(path.as_str()) {
            continue;
        }
        let collection = CollectionProxy::builder(conn)
            .path(path.clone())
            .map(|b| b.cache_properties(CacheProperties::No))
            .map_err(|e| GnomeError::Bus {
                call: "Collection".into(),
                message: e.to_string(),
            })?
            .build()
            .await
            .map_err(|e| GnomeError::Bus {
                call: "Collection".into(),
                message: e.to_string(),
            })?;

        let label = call("Collection.Label", collection.label())
            .await
            .unwrap_or_default();
        let container = if label.is_empty() {
            path.as_str().rsplit('/').next().unwrap_or("keyring").into()
        } else {
            label.clone()
        };
        let locked = call("Collection.Locked", collection.locked())
            .await
            .unwrap_or(true);

        let mut summary = CollectionSummary {
            path: path.as_str().to_string(),
            label,
            locked,
            created: call("Collection.Created", collection.created())
                .await
                .unwrap_or(0),
            modified: call("Collection.Modified", collection.modified())
                .await
                .unwrap_or(0),
            item_count: 0,
            unanswerable_prompt: false,
        };

        if locked {
            match unlock(conn, &service, &path, options.prompt_timeout).await {
                Ok(()) => summary.locked = false,
                Err(GnomeError::UnanswerablePrompt { .. } | GnomeError::PromptDismissed { .. }) => {
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

        if default_path.as_ref().is_some_and(|d| *d == path) {
            out.default_collection = Some(container.clone());
        }

        let items = call("Collection.Items", collection.items()).await?;
        summary.item_count = items.len();
        out.collections.push(summary);

        // Two passes. The first reads *about* every item; the second fetches
        // secrets for the ones that are not refused, so an unlock credential's
        // bytes never cross the bus at all.
        let mut candidates = Vec::new();
        for item_path in items {
            saw_item = true;
            let meta = read_metadata(conn, &item_path, &container).await?;
            if meta.item_type.is_some() {
                saw_type = true;
            }
            if meta
                .item_type
                .as_deref()
                .is_some_and(is_unlock_credential_type)
            {
                let code = meta
                    .item_type
                    .as_deref()
                    .and_then(item_type_code)
                    .unwrap_or(ITEM_TYPE_CHAINED_KEYRING_PASSWORD);
                out.refused.push(ItemReport::refused(
                    meta.provenance,
                    meta.label,
                    Refusal::ChainedKeyringItem { item_type: code },
                ));
                continue;
            }
            candidates.push((item_path, meta));
        }

        fetch_secrets(
            conn,
            &service,
            &session,
            &cipher,
            candidates,
            &mut out.items,
            &mut out.refused,
        )
        .await?;
    }

    out.item_type_unavailable = saw_item && !saw_type;

    // The session holds the transport key; close it rather than leaving it
    // for the daemon to garbage-collect when we disconnect.
    if let Ok(proxy) = SessionProxy::builder(conn)
        .path(session.clone())
        .map(|b| b.cache_properties(CacheProperties::No))
        .map_err(|e| GnomeError::Bus {
            call: "Session".into(),
            message: e.to_string(),
        })?
        .build()
        .await
    {
        let _ = tokio::time::timeout(COMMAND_TIMEOUT, proxy.close()).await;
    }

    Ok(out)
}

/// `OpenSession`, DH first.
///
/// DH keeps the plaintext off the bus, and `src/session/dh.rs` already
/// implements this side, so reusing it is nearly free. `plain` is a fallback
/// and never a silent one: the reason is carried into the report.
async fn open_session(
    service: &ServiceProxy<'_>,
    prefer_dh: bool,
) -> Result<(OwnedObjectPath, SessionCipher, &'static str, Option<String>), GnomeError> {
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
                return Ok((path, cipher, ALGORITHM_DH, None));
            }
            Err(e) => {
                let reason = format!("the source refused {ALGORITHM_DH}: {e}");
                let (_, path) = call(
                    "Service.OpenSession(plain)",
                    service.open_session(ALGORITHM_PLAIN, &Value::from("")),
                )
                .await?;
                return Ok((path, SessionCipher::plain(), ALGORITHM_PLAIN, Some(reason)));
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
        ALGORITHM_PLAIN,
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
        // No prompt and not unlocked: nothing further can be done, and this
        // is the same shortfall an unanswerable prompt produces.
        return Err(GnomeError::UnanswerablePrompt {
            object: path.as_str().to_string(),
            waited: Duration::ZERO,
        });
    }
    await_prompt(conn, &prompt, prompt_timeout).await?;
    Ok(())
}

/// Everything about one item except its secret.
struct ItemMetadata {
    label: String,
    attributes: BTreeMap<String, String>,
    created: u64,
    modified: u64,
    item_type: Option<String>,
    provenance: Provenance,
}

/// gnome-keyring's non-standard `Type` property, and nothing else.
///
/// The shared [`crate::dbus::proxies`] describe the *spec* interface, which
/// our own daemon implements and which has no `Type`; extending them for a
/// property only one foreign provider has would put a call in the CLI's path
/// that our daemon answers with `UnknownProperty`. So the spec proxies are
/// reused for all seven standard calls and this one non-standard property gets
/// its own two-line proxy, whose absence is tolerated.
#[zbus::proxy(
    interface = "org.freedesktop.Secret.Item",
    default_service = "org.freedesktop.secrets"
)]
trait GnomeItem {
    #[zbus(property)]
    fn type_(&self) -> zbus::Result<String>;
}

async fn read_metadata(
    conn: &Connection,
    path: &OwnedObjectPath,
    container: &str,
) -> Result<ItemMetadata, GnomeError> {
    let item = ItemProxy::builder(conn)
        .path(path.clone())
        .map(|b| b.cache_properties(CacheProperties::No))
        .map_err(|e| GnomeError::Bus {
            call: "Item".into(),
            message: e.to_string(),
        })?
        .build()
        .await
        .map_err(|e| GnomeError::Bus {
            call: "Item".into(),
            message: e.to_string(),
        })?;

    // D-Bus `s` and the `a{ss}` attribute map are validated UTF-8 by the
    // marshaller, so `Refusal::NonUtf8Attribute` cannot arise on this route:
    // a non-UTF-8 attribute could not have reached the bus in the first
    // place. The KWallet sidecar is where that refusal earns its keep.
    let attributes: BTreeMap<String, String> = call("Item.Attributes", item.attributes())
        .await?
        .into_iter()
        .collect();

    let item_type = GnomeItemProxy::builder(conn)
        .path(path.clone())
        .map(|b| b.cache_properties(CacheProperties::No))
        .map_err(|e| GnomeError::Bus {
            call: "Item".into(),
            message: e.to_string(),
        })?
        .build()
        .await
        .ok();
    let item_type = match item_type {
        // Tolerated, not required: a provider without the property is not an
        // error, it is a provider whose types we cannot see.
        Some(proxy) => tokio::time::timeout(CALL_TIMEOUT, proxy.type_())
            .await
            .ok()
            .and_then(Result::ok),
        None => None,
    };

    Ok(ItemMetadata {
        label: call("Item.Label", item.label()).await.unwrap_or_default(),
        attributes,
        created: call("Item.Created", item.created()).await.unwrap_or(0),
        modified: call("Item.Modified", item.modified()).await.unwrap_or(0),
        item_type,
        provenance: Provenance::gnome(container, path_item_id(path.as_str())),
    })
}

/// `Service.GetSecrets` for the whole batch, per-item `GetSecret` for whatever
/// it left out.
///
/// One round trip rather than N, which also halves the window in which
/// plaintext is in flight.
#[allow(clippy::too_many_arguments)]
async fn fetch_secrets(
    conn: &Connection,
    service: &ServiceProxy<'_>,
    session: &OwnedObjectPath,
    cipher: &SessionCipher,
    candidates: Vec<(OwnedObjectPath, ItemMetadata)>,
    items: &mut Vec<ExtractedItem>,
    refused: &mut Vec<ItemReport>,
) -> Result<(), GnomeError> {
    if candidates.is_empty() {
        return Ok(());
    }
    let paths: Vec<OwnedObjectPath> = candidates.iter().map(|(p, _)| p.clone()).collect();
    let mut batch = tokio::time::timeout(CALL_TIMEOUT, service.get_secrets(&paths, session))
        .await
        .ok()
        .and_then(Result::ok)
        .unwrap_or_default();

    for (path, meta) in candidates {
        let secret = match batch.remove(&path) {
            Some(s) => s,
            None => {
                let item = ItemProxy::builder(conn)
                    .path(path.clone())
                    .map(|b| b.cache_properties(CacheProperties::No))
                    .map_err(|e| GnomeError::Bus {
                        call: "Item".into(),
                        message: e.to_string(),
                    })?
                    .build()
                    .await
                    .map_err(|e| GnomeError::Bus {
                        call: "Item".into(),
                        message: e.to_string(),
                    })?;
                call("Item.GetSecret", item.get_secret(session)).await?
            }
        };
        let plaintext = cipher
            .decrypt(&secret.parameters, &secret.value)
            .map_err(|e| GnomeError::Decrypt {
                message: e.to_string(),
            })?;

        let source = SourceItem {
            label: meta.label,
            attributes: meta.attributes,
            secret: plaintext,
            content_type: secret.content_type,
            created: meta.created,
            modified: meta.modified,
            provenance: meta.provenance,
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
            continue;
        }
        items.push(ExtractedItem {
            item: source,
            item_type: meta.item_type,
        });
    }
    Ok(())
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
    }

    /// The case that motivates the whole check: on the author's machine
    /// `ksecretd` owns the name while gnome-keyring is masked, so a
    /// `--from gnome-keyring` that trusted the bus would have migrated
    /// KWallet data and called it a success.
    #[test]
    fn the_wrong_owner_is_refused_and_named() {
        let owner = classify_bus_owner(
            Some(&busctl("7585")),
            Some("/usr/bin/ksecretd --pam-login 4 5\n"),
        );
        assert!(!owner.is_gnome_keyring());
        let described = owner.describe();
        assert!(described.contains("ksecretd"), "{described}");
        assert!(described.contains("7585"), "{described}");
        let err = GnomeError::WrongBusOwner { owner: described }.to_string();
        assert!(err.contains("ksecretd"), "{err}");
        assert!(err.contains(GNOME_KEYRING_PROGRAM), "{err}");
    }

    #[test]
    fn no_owner_is_not_a_match() {
        assert_eq!(classify_bus_owner(None, None), BusOwner::Unowned);
        assert_eq!(
            classify_bus_owner(Some("Failed to get PID: no such name\n"), None),
            BusOwner::Unowned
        );
        assert!(!BusOwner::Unowned.is_gnome_keyring());
        assert!(BusOwner::Unowned.describe().contains(SECRETS_BUS_NAME));
    }

    /// An owner `ps` cannot describe is refused, not assumed. Empty output,
    /// whitespace-only output and a failed `ps` are the same answer: we do not
    /// know, so we do not proceed.
    #[test]
    fn an_unreadable_ps_refuses_rather_than_assumes() {
        for ps in [None, Some(""), Some("   \n\t")] {
            let owner = classify_bus_owner(Some(&busctl("99")), ps);
            assert_eq!(owner, BusOwner::Unidentified { pid: 99 }, "{ps:?}");
            assert!(!owner.is_gnome_keyring(), "{ps:?}");
            assert!(owner.describe().contains("99"));
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
            },
            item_type: item_type.map(str::to_string),
        }
    }

    /// The mapping is near-total: attributes byte-for-byte, timestamps
    /// carried, nothing invented. An item with no `xdg:schema` gets no
    /// synthesised one — two of 28 items on the author's machine have none,
    /// and inventing one produces an item that looks migrated and is
    /// unreachable.
    #[test]
    fn the_mapping_copies_and_invents_nothing() {
        let e = extracted(Some(TYPE_GENERIC), &[("server", "example.com")]);
        let report = e.report();
        assert_eq!(
            e.item.attributes,
            BTreeMap::from([("server".to_string(), "example.com".to_string())])
        );
        assert_eq!(e.item.created, 1_788_893_013);
        assert_eq!(e.item.modified, 1_788_893_014);
        assert_eq!(
            report.outcome,
            Some(super::super::Outcome::AttributesPreserved)
        );
        assert!(report.refusals.is_empty());
        // Generic is the type our daemon *does* represent, so nothing is lost.
        assert_eq!(report.lost_item_type, None);
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
        }
        assert_eq!(extracted(None, &[]).report().lost_item_type, None);
        assert_eq!(
            extracted(Some("org.gnome.keyring.Unheard"), &[])
                .report()
                .lost_item_type,
            None
        );
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

    /// `None`, with a printed reason, when this machine has no `dbus-daemon`.
    /// Never a vacuous pass.
    fn private_bus() -> Option<Bus> {
        let mut child = StdCommand::new("dbus-daemon")
            .args(["--session", "--nofork", "--nopidfile", "--print-address"])
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .ok()?;
        let mut line = String::new();
        let stdout = child.stdout.take()?;
        StdBufReader::new(stdout).read_line(&mut line).ok()?;
        let address = line.trim().to_string();
        if address.is_empty() {
            return None;
        }
        Some(Bus { address, child })
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
        let Some(bus) = private_bus() else {
            println!("SKIPPED: dbus-daemon is not installed, so no private bus can be started");
            return;
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
        let Some(bus) = private_bus() else {
            println!("SKIPPED: dbus-daemon is not installed, so no private bus can be started");
            return;
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
    // The live path
    // ----------------------------------------------------------------

    /// `false`, with a printed reason, when this machine cannot run the live
    /// extraction. A skip that says why is the only honest alternative to
    /// coverage; a silent pass is the failure mode the whole suite exists to
    /// avoid.
    fn live_prerequisites() -> bool {
        let mut missing = Vec::new();
        for program in ["dbus-daemon", GNOME_KEYRING_PROGRAM] {
            if StdCommand::new(program)
                .arg("--version")
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .is_err()
            {
                missing.push(program);
            }
        }
        if missing.is_empty() {
            return true;
        }
        println!("SKIPPED: {} is not installed", missing.join(", "));
        false
    }

    /// The synthetic tests above pin the *decision*; this pins the two command
    /// invocations that feed it. A `busctl` whose output format moved, or a
    /// `ps` invoked with the wrong flag, would leave every synthetic test green
    /// while the real check answered `Unowned` for every machine — which is a
    /// refusal, so it fails safe, but it would refuse everyone.
    #[tokio::test]
    async fn the_real_bus_owner_check_runs_against_the_real_tools() {
        for program in ["busctl", "ps"] {
            if StdCommand::new(program)
                .arg("--version")
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .is_err()
            {
                println!("SKIPPED: {program} is not installed");
                return;
            }
        }
        let owner = secrets_bus_owner().await.expect("the check itself failed");
        match &owner {
            // No session bus, or nobody serving secrets: a legitimate answer,
            // and a refusal.
            BusOwner::Unowned | BusOwner::Unidentified { .. } => {
                assert!(!owner.is_gnome_keyring());
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
    async fn a_real_gnome_keyring_round_trips_through_the_walk() {
        if !live_prerequisites() {
            return;
        }
        let data_home = tempfile::tempdir().expect("a writable temp directory");
        let password = Zeroizing::new(b"sm-import-live-test".to_vec());
        let mut keyring = match PrivateKeyring::start(&password, Some(data_home.path())).await {
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
        assert!(
            extraction.algorithm == ALGORITHM_DH || extraction.algorithm == ALGORITHM_PLAIN,
            "{}",
            extraction.algorithm
        );
        if extraction.algorithm == ALGORITHM_PLAIN {
            assert!(extraction.plain_fallback_reason.is_some());
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
                value: secret.to_vec(),
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
