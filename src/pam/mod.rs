//! PAM module that unlocks the secret-manager vault at login.
//!
//! * `auth`: copy the password PAM already collected into module data. Never prompts.
//! * `session`: start the user's daemon if needed, derive the vault key from
//!   the password, and send `UnlockWithKey`.
//! * `password`: derive old and new keys so the vault follows `passwd`
//!   (`ChangeKey`).
//!
//! The login password itself never crosses the control socket, and nothing
//! that answers the socket gets to influence the derivation: the salt and
//! Argon2 parameters are read from the collection's own vault file on disk
//! (see [`vault_header`]), which is opened `O_NOFOLLOW | O_NONBLOCK` and
//! required to be a *regular* file owned by the target user and not group- or
//! world-writable, and whose header is read under the hook's own deadline so a
//! file backed by something that never answers cannot wedge root. The most an
//! impostor daemon can learn is an Argon2id hash of the password under
//! parameters this module bounds on both sides (see
//! [`kdf_acceptable_for_login`]) — the same thing a thief of the vault file
//! would hold, not a reusable password.
//!
//! The control socket's directory lives under the user's own
//! `/run/user/<uid>`, so it is never addressed by name twice: it is opened
//! once (`O_DIRECTORY | O_NOFOLLOW`), validated on the descriptor, and every
//! later unlink, connect and re-check goes through that descriptor (see
//! [`SocketDir`]). A whole hook is additionally bounded by one wall-clock
//! deadline ([`HOOK_BUDGET`]), since every stage of it is influenced by the
//! user being logged in.
//!
//! Every failure is logged to syslog and returns `PAM_SUCCESS`; a broken vault
//! must never block login. Hook bodies additionally run inside
//! [`catch_unwind`](std::panic::catch_unwind), so a panic can never unwind
//! into libpam.
//!
//! Options:
//! * `collection=<id>` (default `default`)
//! * `vault_dir=<absolute path>` — where `<collection>.vault` lives. Default
//!   `<home>/.local/share/secret-manager`, from the target user's `pw_dir`.
//!   A relative value is logged and ignored.
//! * `auto_start=no`
//! * `socket=<path>` — tests only, ignored when running as root.

// Without the `pam` feature the `pam_sm_*` entry points are not compiled, so
// the helpers they call have no production caller in this build.
#![cfg_attr(not(feature = "pam"), allow(dead_code))]

use crate::protocol::{
    KdfParams, ProtocolError, Request, Response, SALT_LEN, Zeroizing,
    call_expecting_uid_with_timeout, socket_path_for_runtime_dir,
};
use std::ffi::{CString, OsStr};
use std::fs::File;
use std::mem::ManuallyDrop;
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::{Path, PathBuf};
use std::process::{Child, ExitStatus, Stdio};
use std::time::{Duration, Instant};

#[cfg(feature = "pam")]
mod hooks;
use crate::vault::crypto::{self, Key};
use crate::vault::format;

pub(crate) const START_TIMEOUT: Duration = Duration::from_secs(5);
/// How often `run_bounded` and `wait_for` re-check their condition.
const POLL_INTERVAL: Duration = Duration::from_millis(100);
/// Absolute `systemctl` locations, tried in order. Never resolved through the
/// inherited `PATH`: this code runs as root inside someone else's login.
const SYSTEMCTL_PATHS: [&str; 2] = ["/usr/bin/systemctl", "/bin/systemctl"];
/// Minimal `PATH` handed to the child, since `systemctl` re-execs helpers.
const SAFE_PATH: &str = "/usr/bin:/bin";
/// Longest error text copied into a syslog line.
const MAX_LOGGED_ERROR: usize = 200;
/// Vault directory relative to the target user's home, when `vault_dir=` is
/// not given.
const DEFAULT_VAULT_SUBDIR: &str = ".local/share/secret-manager";
/// Wall-clock ceiling on everything a session or password hook does. The
/// stages are serial and every one of them is influenced by the user being
/// logged in (the vault header they wrote, the daemon that answers the
/// socket, the systemd job that starts it), so their sum is login latency an
/// attacker chooses. One deadline covers the lot — the vault-file read
/// included, via [`read_exact_bounded`] — and when it is spent the unlock is
/// abandoned and the login proceeds without the vault.
///
/// The real bound on a hook is *not* exactly this constant. Argon2 is not
/// interruptible, so the budget is checked before each derivation but cannot
/// cut one short once it has begun. `open_session` runs at most two
/// derivations (the first unlock and the retry after starting the daemon) and
/// `chauthtok` runs two (old key and new key), each bounded by the login KDF
/// ceiling of [`MAX_M_COST_KIB_LOGIN`] / [`MAX_T_COST_LOGIN`] /
/// [`MAX_P_COST_LOGIN`] rather than by the vault's. So the guarantee is:
///
/// > this budget, plus at most the KDF ceiling cost of the derivations that
/// > were actually started before it ran out.
///
/// A derivation is never *started* after the budget is spent, so the excess is
/// bounded by one ceiling-cost derivation in practice.
pub(crate) const HOOK_BUDGET: Duration = Duration::from_secs(8);
/// Secondary budget for reaping a child that has already been killed.
const REAP_TIMEOUT: Duration = Duration::from_secs(2);
/// Longest `collection=` accepted, so the value cannot bloat a syslog line or
/// a path.
const MAX_COLLECTION_LEN: usize = 64;

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Options {
    pub collection: String,
    pub auto_start: bool,
    pub socket: Option<PathBuf>,
    pub vault_dir: Option<PathBuf>,
}

pub(crate) fn parse_options(args: &[String]) -> Options {
    let mut opts = Options {
        collection: "default".into(),
        auto_start: true,
        socket: None,
        vault_dir: None,
    };
    for arg in args {
        match arg.split_once('=') {
            Some(("collection", v)) => {
                if collection_is_valid(v) {
                    opts.collection = v.to_string();
                } else {
                    log(&format!(
                        "ignoring unusable collection '{}'; using '{}'",
                        v, opts.collection
                    ));
                }
            }
            Some(("auto_start", v)) => match parse_bool(v) {
                Some(b) => opts.auto_start = b,
                None => log(&format!(
                    "ignoring unrecognised auto_start '{}'; leaving it {}",
                    v,
                    if opts.auto_start { "on" } else { "off" }
                )),
            },
            Some(("socket", v)) => opts.socket = Some(PathBuf::from(v)),
            Some(("vault_dir", v)) => {
                let path = PathBuf::from(v);
                if path.is_absolute() {
                    opts.vault_dir = Some(path);
                } else {
                    log(&format!(
                        "ignoring non-absolute vault_dir '{}'; using the default",
                        sanitize(v)
                    ));
                }
            }
            _ => log(&format!("ignoring unknown option '{arg}'")),
        }
    }
    opts
}

/// `auto_start=` is a switch, not a "not one of these three words" test:
/// `off`, `disabled` and `No` must never fall through to the branch that
/// unlinks as root and runs `systemctl`. `None` means "unrecognised", which
/// the caller logs and treats as "leave the default alone".
fn parse_bool(v: &str) -> Option<bool> {
    match v.to_ascii_lowercase().as_str() {
        "no" | "false" | "0" | "off" => Some(false),
        "yes" | "true" | "1" | "on" => Some(true),
        _ => None,
    }
}

/// `collection=` is interpolated straight into `<vault_dir>/<id>.vault`, so a
/// value containing `/` or `..` would escape the vault directory and an empty
/// one would open `.vault`. Restrict it to the daemon's own id charset.
fn collection_is_valid(v: &str) -> bool {
    !v.is_empty()
        && v.len() <= MAX_COLLECTION_LEN
        && v.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

/// Strips control characters (so a hostile string cannot forge syslog lines or
/// terminal escapes) and bounds the length of text that came from the daemon.
///
/// `char::is_control()` covers C0/C1 but not the Unicode *format* characters,
/// which can reorder a log line as it is read; the bidi controls are dropped
/// explicitly.
pub(crate) fn sanitize(text: &str) -> String {
    strip_unsafe(text).take(MAX_LOGGED_ERROR).collect()
}

/// The escaping half of [`sanitize`], without the length bound: [`log`]
/// applies it to whole lines, which are already short but must not be
/// truncated in the middle of a path.
fn strip_unsafe(text: &str) -> impl Iterator<Item = char> + '_ {
    text.chars()
        .filter(|c| !c.is_control() && !is_bidi_format(*c))
}

/// The Unicode bidirectional formatting characters: embeddings and overrides
/// (`U+202A..=U+202E`) and isolates (`U+2066..=U+2069`).
fn is_bidi_format(c: char) -> bool {
    matches!(c, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
}

/// Sanitizing here rather than at each call site means no caller can forget:
/// the PAM username, the vault path and the daemon's own error text all reach
/// syslog through this one function. Already-sanitized arguments are
/// unaffected, since [`sanitize`] is idempotent.
pub(crate) fn log(msg: &str) {
    let clean: String = strip_unsafe(msg).collect();
    let line = format!("pam_secret_manager: {clean}");
    // An interior NUL cannot be passed to syslog; escape it rather than
    // dropping the line entirely.
    let Ok(text) = CString::new(line.as_str())
        .or_else(|_| CString::new(line.replace('\0', "\\0")))
        .or_else(|_| CString::new("pam_secret_manager: <unloggable message>"))
    else {
        return;
    };
    // SAFETY: "%s" is a valid format with exactly one C-string argument that outlives the call.
    unsafe {
        libc::syslog(
            libc::LOG_WARNING | libc::LOG_AUTHPRIV,
            c"%s".as_ptr(),
            text.as_ptr(),
        )
    };
}

/// Runs a PAM hook body with unwinding contained. libpam calls us through C,
/// where an unwind is undefined behaviour, so a panic becomes a logged
/// `PAM_SUCCESS` instead: a bug in this module must never block a login.
pub(crate) fn guard<T>(what: &str, on_panic: T, body: impl FnOnce() -> T) -> T {
    match catch_unwind(AssertUnwindSafe(body)) {
        Ok(rc) => rc,
        Err(_) => {
            log(&format!("panic in {what}; continuing without the vault"));
            on_panic
        }
    }
}

pub(crate) fn effective_uid() -> u32 {
    // SAFETY: geteuid takes no arguments, has no preconditions and cannot fail.
    unsafe { libc::geteuid() }
}

/// uid and home directory of `user`, from `getpwnam_r`.
pub(crate) fn user_info(user: &str) -> Option<(u32, PathBuf)> {
    let name = CString::new(user).ok()?;
    // SAFETY: passwd is plain data; zeroed is a valid initial value.
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    let mut size = 16384usize;
    // A short buffer is reported as ERANGE rather than "no such user"; retry
    // once with a much larger one before giving up.
    for attempt in 0..2 {
        let mut buf = vec![0u8; size];
        // SAFETY: every pointer is valid for the duration of the call, and the
        // strings `pwd` points into live in `buf`, which outlives the copies
        // made below.
        let rc = unsafe {
            libc::getpwnam_r(
                name.as_ptr(),
                &mut pwd,
                buf.as_mut_ptr() as *mut libc::c_char,
                buf.len(),
                &mut result,
            )
        };
        if rc == libc::ERANGE {
            if attempt == 0 {
                size *= 4;
                continue;
            }
            log(&format!("cannot look up user '{user}': buffer too small"));
            return None;
        }
        if rc != 0 {
            log(&format!("cannot look up user '{user}': errno {rc}"));
            return None;
        }
        if result.is_null() {
            return None;
        }
        if pwd.pw_dir.is_null() {
            log(&format!("user '{user}' has no home directory"));
            return None;
        }
        // SAFETY: pw_dir is a NUL-terminated string inside `buf`, which is
        // still alive; the bytes are copied before `buf` is dropped.
        let home = unsafe { std::ffi::CStr::from_ptr(pwd.pw_dir) };
        let home = PathBuf::from(std::ffi::OsStr::from_bytes(home.to_bytes()));
        if !home.is_absolute() {
            log(&format!("user '{user}' has a non-absolute home directory"));
            return None;
        }
        return Some((pwd.pw_uid, home));
    }
    None
}

fn default_vault_dir(home: &Path) -> PathBuf {
    home.join(DEFAULT_VAULT_SUBDIR)
}

/// Root only touches `<runtime>/secret-manager` when it is a plain directory
/// owned by the target user and writable by nobody else. A symlink the user
/// planted there would redirect an unlink or a connect elsewhere, and a
/// group- or world-writable directory would let another local user plant the
/// socket inode.
fn runtime_subdir_is_safe(meta: &std::fs::Metadata, uid: u32) -> bool {
    meta.file_type().is_dir() && meta.uid() == uid && meta.mode() & 0o022 == 0
}

/// An owned directory descriptor, closed exactly once on drop.
struct DirFd(RawFd);

impl DirFd {
    fn as_raw(&self) -> RawFd {
        self.0
    }

    /// `fstat` on the descriptor itself, so the answer is about the inode
    /// that was validated when it was opened rather than about whatever the
    /// name resolves to now.
    fn metadata(&self) -> std::io::Result<std::fs::Metadata> {
        // SAFETY: `self.0` is an open descriptor owned by `self`. The `File`
        // is wrapped in `ManuallyDrop` so its destructor never runs and the
        // descriptor is not closed here; it is only borrowed for the `fstat`
        // and does not escape this function.
        let file = ManuallyDrop::new(unsafe { File::from_raw_fd(self.0) });
        file.metadata()
    }
}

impl Drop for DirFd {
    fn drop(&mut self) {
        // SAFETY: `self.0` was returned by `open` and is owned by `self`, so
        // it is closed exactly once and never used again afterwards.
        unsafe { libc::close(self.0) };
    }
}

/// Opens `dir` without following a final symlink and without accepting a
/// non-directory. `Ok(None)` means it simply does not exist yet.
fn open_dir_fd(dir: &Path) -> std::io::Result<Option<DirFd>> {
    let c = CString::new(dir.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    // SAFETY: `c` is a NUL-terminated path that outlives the call, the flags
    // are constants, and `open` takes no other arguments in this form. The
    // returned descriptor is immediately given to `DirFd`, which owns it.
    let fd = unsafe {
        libc::open(
            c.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd >= 0 {
        return Ok(Some(DirFd(fd)));
    }
    let e = std::io::Error::last_os_error();
    if e.kind() == std::io::ErrorKind::NotFound {
        Ok(None)
    } else {
        Err(e)
    }
}

/// The control socket, addressed through a descriptor for its directory
/// rather than through its name.
///
/// `unlink(2)` does not follow the *final* component, but it does follow
/// every parent — and the parent here (`/run/user/<uid>/secret-manager`) is
/// user-owned. Validating the name and then removing through the name leaves
/// a window (a whole vault read plus a connect attempt) in which the user can
/// swap the directory for a symlink and have root delete somebody else's
/// socket. So the directory is opened and validated once, and every later
/// operation goes through that descriptor: `unlinkat` for the removal, a
/// re-`fstat` of the same fd for the re-check, and a `/proc/self/fd/<n>/`
/// path for the connect.
///
/// What that does and does not guarantee, precisely:
///
/// * **The unlink is inode-safe.** `unlinkat(dirfd, name, 0)` is genuinely
///   descriptor-relative: no part of the parent path is resolved again, so a
///   swap of the directory *name* after validation cannot redirect it.
/// * **The connect is not.** `connect(2)` takes a path, and
///   `/proc/self/fd/<n>/control.sock` is resolved in full — including a
///   symlink at the final component. Pinning the directory means root's
///   connect always starts from the validated inode, but the user can still
///   make `control.sock` inside it a symlink to a socket elsewhere. That
///   window is narrowed to the gap between check and connect by
///   [`SocketDir::connect_path`], which `fstatat`s the name with
///   `AT_SYMLINK_NOFOLLOW` and requires a socket; it is not closed, because
///   this API has no `connectat`.
/// * **What contains the residue** is the `SO_PEERCRED` check in
///   [`crate::protocol`]: whatever root ends up connected to must be owned by
///   the target uid, so the worst a swap achieves is redirecting the unlock to
///   another of the user's own listeners. It is not a privilege escalation,
///   and the key that would reach it is an Argon2 hash under the vault
///   header's own parameters, not the password.
pub(crate) struct SocketDir {
    /// The name the socket was originally given, used when the directory does
    /// not exist yet and there is therefore nothing to hold open.
    sock: PathBuf,
    /// Final component, for `unlinkat`.
    name: CString,
    uid: u32,
    dir: Option<DirFd>,
}

impl SocketDir {
    /// Validates the socket's directory and holds it open. `None` (already
    /// logged) means root must not touch this path at all. An absent
    /// directory is not a refusal: the daemon has yet to create it, and there
    /// is nothing there to follow or to unlink.
    pub(crate) fn open(sock: &Path, uid: u32) -> Option<Self> {
        let Some(name) = sock
            .file_name()
            .and_then(|n| CString::new(n.as_bytes()).ok())
        else {
            log(&format!(
                "{} has no usable file name; refusing to use it",
                sock.display()
            ));
            return None;
        };
        let parent = sock.parent().unwrap_or(Path::new(""));
        let dir = if parent.as_os_str().is_empty() {
            None
        } else {
            match open_dir_fd(parent) {
                Ok(fd) => fd,
                Err(e) => {
                    log(&format!(
                        "cannot open {} as a directory: {}; refusing to use it",
                        parent.display(),
                        sanitize(&e.to_string())
                    ));
                    return None;
                }
            }
        };
        if let Some(fd) = &dir {
            match fd.metadata() {
                Ok(meta) if runtime_subdir_is_safe(&meta, uid) => {}
                Ok(meta) => {
                    log(&format!(
                        "{} is not a directory owned by uid {uid} and private to it \
                         (owner {}, mode {:o}); refusing to use it",
                        parent.display(),
                        meta.uid(),
                        meta.mode() & 0o7777
                    ));
                    return None;
                }
                Err(e) => {
                    log(&format!(
                        "cannot stat {}: {}; refusing to use it",
                        parent.display(),
                        sanitize(&e.to_string())
                    ));
                    return None;
                }
            }
        }
        Some(Self {
            sock: sock.to_path_buf(),
            name,
            uid,
            dir,
        })
    }

    /// Whether the directory exists and is being held open.
    #[cfg(test)]
    fn is_open(&self) -> bool {
        self.dir.is_some()
    }

    /// The path the socket is addressed by. When the directory is held open
    /// this is rooted at the validated inode via `/proc/self/fd/<n>`, so no
    /// part of the *parent* path is resolved again.
    ///
    /// The final component still is. Use [`SocketDir::connect_path`] for
    /// anything that connects; this one is for the existence poll in
    /// [`wait_for`], which does its own `lstat` and is not harmed by a symlink
    /// it can see.
    pub(crate) fn socket_path(&self) -> PathBuf {
        match &self.dir {
            Some(fd) => PathBuf::from(format!("/proc/self/fd/{}", fd.as_raw()))
                .join(OsStr::from_bytes(self.name.as_bytes())),
            None => self.sock.clone(),
        }
    }

    /// The path to connect to, but only once the entry at the socket name has
    /// been confirmed to be a socket *and not a symlink*, right now.
    ///
    /// `connect(2)` resolves its whole path, symlinks at the final component
    /// included, so without this the user could point root's connect at any
    /// socket on the system simply by replacing `control.sock` with a link.
    /// `fstatat(dirfd, name, AT_SYMLINK_NOFOLLOW)` answers about the entry in
    /// the validated directory rather than about whatever it points to.
    ///
    /// This is a check-then-use, and the gap is real: the user may swap the
    /// name between the `fstatat` and the `connect`. There is no `connectat`,
    /// so that gap is as tight as this interface allows; the `SO_PEERCRED`
    /// check on the other side is what keeps the consequence to "one of the
    /// user's own listeners".
    ///
    /// `ErrorKind::NotFound` means there is nothing there yet, which the
    /// caller reads as "start the daemon". Anything else is a refusal.
    pub(crate) fn connect_path(&self) -> std::io::Result<PathBuf> {
        let Some(fd) = &self.dir else {
            // No directory to hold, so nothing has been created inside it
            // either; let the connect fail with the real errno.
            return Ok(self.sock.clone());
        };
        // SAFETY: `st` is plain data; zeroed is a valid initial value.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: `fd` is an open directory descriptor owned by `self`,
        // `self.name` is a NUL-terminated relative name outliving the call,
        // and `st` is a live out-parameter of the right type.
        let rc = unsafe {
            libc::fstatat(
                fd.as_raw(),
                self.name.as_ptr(),
                &mut st,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if rc != 0 {
            return Err(std::io::Error::last_os_error());
        }
        if st.st_mode & libc::S_IFMT != libc::S_IFSOCK {
            log(&format!(
                "{} is not a socket (mode {:o}); refusing to connect to it",
                self.sock.display(),
                st.st_mode & 0o7777
            ));
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "the control socket name is not a socket",
            ));
        }
        Ok(self.socket_path())
    }

    /// Re-checks after the daemon-start window. A held descriptor is
    /// re-`fstat`ed — the same inode, so this catches a `chown`/`chmod` but
    /// cannot be fooled by a rename. A directory that did not exist before is
    /// opened and validated now; nothing was done through its name in the
    /// meantime, so there is nothing for a swap to have redirected.
    ///
    /// By construction this says nothing about the directory's *contents*:
    /// re-`fstat`ing an inode cannot see that `control.sock` inside it was
    /// replaced — with a symlink, a regular file, or another socket — while
    /// the daemon was starting. Nor is it meant to. The socket entry is
    /// covered by the `fstatat` in [`SocketDir::connect_path`], which is done
    /// immediately before each connect.
    pub(crate) fn revalidate(&mut self) -> bool {
        match &self.dir {
            Some(fd) => match fd.metadata() {
                Ok(meta) if runtime_subdir_is_safe(&meta, self.uid) => true,
                Ok(_) => {
                    log("the runtime directory changed owner or mode; refusing to use it");
                    false
                }
                Err(e) => {
                    log(&format!(
                        "cannot re-check the runtime directory: {}",
                        sanitize(&e.to_string())
                    ));
                    false
                }
            },
            None => match Self::open(&self.sock.clone(), self.uid) {
                Some(fresh) => {
                    *self = fresh;
                    true
                }
                None => false,
            },
        }
    }

    /// `unlinkat` relative to the validated directory. Absent directory means
    /// there is nothing to remove.
    fn remove_socket(&self) -> std::io::Result<()> {
        let Some(fd) = &self.dir else {
            return Ok(());
        };
        // SAFETY: `fd` is an open directory descriptor owned by `self`, and
        // `self.name` is a NUL-terminated relative name that outlives the
        // call. Flags of 0 means "unlink, not rmdir".
        let rc = unsafe { libc::unlinkat(fd.as_raw(), self.name.as_ptr(), 0) };
        if rc == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        }
    }
}

/// The vault header supplies the KDF parameters, and it is not authenticated
/// until a successful decrypt. Refuse anything below the OWASP floor (19 MiB,
/// two passes), so a tampered header cannot ask for a cheap-to-crack hash of
/// the login password, and anything above the login ceiling, so it cannot
/// stall the login instead.
fn kdf_acceptable_for_login(kdf: &KdfParams) -> bool {
    const MIN_M_COST_KIB: u32 = 19 * 1024;
    const MIN_T_COST: u32 = 2;
    kdf.validate().is_ok()
        && kdf.m_cost_kib >= MIN_M_COST_KIB
        && kdf.t_cost >= MIN_T_COST
        && kdf.m_cost_kib <= MAX_M_COST_KIB_LOGIN
        && kdf.t_cost <= MAX_T_COST_LOGIN
        && kdf.p_cost <= MAX_P_COST_LOGIN
        && kdf.m_cost_kib as u64 * kdf.t_cost as u64 <= MAX_TOTAL_WORK_LOGIN
}

/// The login path needs its own ceiling, far below the vault's.
/// `KdfParams::MAX_M_COST_KIB` (256 MiB) is sized for one interactive
/// `secret-manager unlock`; here root runs the derivation inside every login,
/// single-threaded, with no admission control. Forty parallel `ssh` logins
/// against a 256 MiB header would ask this process for ~10 GB, and a failed
/// Rust allocation *aborts* — which `catch_unwind` cannot contain, so the
/// panic guard would not save the host process. 64 MiB still covers the
/// shipped default of 64 MiB / t=3 / p=1.
const MAX_M_COST_KIB_LOGIN: u32 = 64 * 1024;
const MAX_T_COST_LOGIN: u32 = 4;
const MAX_P_COST_LOGIN: u32 = 2;
/// The per-axis ceilings also bound the product, so a header cannot combine
/// the memory corner with the passes corner.
const MAX_TOTAL_WORK_LOGIN: u64 = MAX_M_COST_KIB_LOGIN as u64 * MAX_T_COST_LOGIN as u64;

/// Waits for `fd` to become readable, or gives up when `budget` is spent.
///
/// `ErrorKind::TimedOut` means the budget ran out; the caller abandons the
/// unlock rather than waiting on something the user controls.
fn poll_readable(fd: RawFd, budget: &Budget) -> std::io::Result<()> {
    loop {
        let Some(left) = budget.remaining() else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "the login budget is spent",
            ));
        };
        // At least 1ms, so a sub-millisecond remainder is a real wait rather
        // than a spin; `poll` clamps to `c_int` milliseconds.
        let ms = left.as_millis().clamp(1, i32::MAX as u128) as libc::c_int;
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: `pfd` is a live, correctly initialised single-element array
        // of `pollfd`, and `fd` is borrowed for the duration of the call.
        let rc = unsafe { libc::poll(&mut pfd, 1, ms) };
        if rc > 0 {
            return Ok(());
        }
        if rc == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "timed out waiting for the vault file to become readable",
            ));
        }
        let e = std::io::Error::last_os_error();
        if e.kind() != std::io::ErrorKind::Interrupted {
            return Err(e);
        }
    }
}

/// `read_exact`, but with a deadline: every read is preceded by a
/// [`poll_readable`] against what is left of `budget`, and an `EAGAIN` from
/// the non-blocking descriptor sends us back to the poll rather than failing.
///
/// This is what bounds the vault-file read. `O_NONBLOCK` affects the *open*,
/// and on a pipe, socket or FUSE-backed file it also makes `read` return
/// `EAGAIN` instead of blocking — so the wait happens in `poll`, where it has
/// a deadline. On a local regular file `poll` reports readable immediately and
/// the kernel's own read is not interruptible by this deadline; that case does
/// not stall in the first place. What an attacker can reach — a FIFO, a
/// socket, a file served by a filesystem they control or a server that is not
/// answering — goes through the bounded path.
fn read_exact_bounded(fd: RawFd, buf: &mut [u8], budget: &Budget) -> std::io::Result<()> {
    let mut done = 0usize;
    while done < buf.len() {
        poll_readable(fd, budget)?;
        let rest = &mut buf[done..];
        // SAFETY: `rest` is a live, uniquely borrowed slice of exactly
        // `rest.len()` bytes, and `fd` is an open descriptor for the call.
        let n = unsafe { libc::read(fd, rest.as_mut_ptr().cast(), rest.len()) };
        if n > 0 {
            done += n as usize;
            continue;
        }
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "the file ended before the header did",
            ));
        }
        let e = std::io::Error::last_os_error();
        match e.kind() {
            // Nothing ready after all, or a signal: poll again, which is what
            // enforces the deadline.
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted => continue,
            _ => return Err(e),
        }
    }
    Ok(())
}

/// Opens `<vault_dir>/<collection>.vault` and returns the salt and KDF
/// parameters from its header, or `None` (already logged) if anything about
/// the file or the header is unsuitable, or if `budget` runs out first.
///
/// The file belongs to `uid` but is read by root, so it is opened with
/// `O_NOFOLLOW` and the *open file* is then checked: owned by `uid`, a regular
/// file, and writable by nobody else. Only the header prefix is read; the
/// ciphertext never enters this process.
///
/// Both the open and the read are bounded. `O_NOFOLLOW | O_NONBLOCK` keeps the
/// *open* from blocking on a FIFO, and the type check then refuses one — but
/// `O_NONBLOCK` does nothing for a `read` of something that passes for a
/// regular file. A FUSE mount the user owns, or a vault on a network
/// filesystem that has stopped answering, blocks root in the kernel exactly as
/// the FIFO did. So every read goes through [`read_exact_bounded`], which
/// polls against what is left of the hook's `budget` and abandons the unlock
/// on a timeout.
pub(crate) fn vault_header(
    vault_dir: &Path,
    collection: &str,
    uid: u32,
    budget: &Budget,
) -> Option<([u8; SALT_LEN], KdfParams)> {
    let path = vault_dir.join(format!("{collection}.vault"));
    let shown = path.display().to_string();
    // Held for the life of the function: `fd` below borrows it, and dropping
    // it would close the descriptor the reads use.
    let file = match std::fs::OpenOptions::new()
        .read(true)
        // O_NONBLOCK: `O_NOFOLLOW` refuses a symlink but not a FIFO, and
        // `open(O_RDONLY)` on a FIFO blocks until a writer appears — so a
        // `mkfifo <collection>.vault` would wedge root in the kernel and lock
        // that user out of their own machine. It is kept set afterwards so a
        // read of a FUSE- or NFS-backed file returns `EAGAIN` and the wait
        // happens in `read_exact_bounded`'s poll, where it has a deadline.
        // O_CLOEXEC: never leak the descriptor into the `systemctl` child.
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(&path)
    {
        Ok(f) => f,
        Err(e) => {
            log(&format!(
                "cannot open {shown}: {}",
                sanitize(&e.to_string())
            ));
            return None;
        }
    };
    // fstat on the descriptor we will read, not a second lookup of the name.
    let meta = match file.metadata() {
        Ok(m) => m,
        Err(e) => {
            log(&format!(
                "cannot stat {shown}: {}",
                sanitize(&e.to_string())
            ));
            return None;
        }
    };
    // Type first: a FIFO, device or socket owned by the user with mode 0600
    // passes both checks below, and reading one has nothing to do with
    // reading a vault.
    if !meta.file_type().is_file() {
        log(&format!(
            "{shown} is not a regular file; refusing to read it"
        ));
        return None;
    }
    if meta.uid() != uid {
        log(&format!(
            "{shown} is owned by uid {}, expected {uid}; refusing to read it",
            meta.uid()
        ));
        return None;
    }
    if meta.mode() & 0o022 != 0 {
        log(&format!(
            "{shown} is group- or world-writable (mode {:o}); refusing to read it",
            meta.mode() & 0o7777
        ));
        return None;
    }

    let fd = file.as_raw_fd();
    let mut bytes = vec![0u8; format::PREFIX_LEN];
    if let Err(e) = read_exact_bounded(fd, &mut bytes, budget) {
        log(&format!(
            "cannot read the header of {shown}: {}",
            sanitize(&e.to_string())
        ));
        return None;
    }
    let need = match format::header_prefix_len(&bytes) {
        Ok(n) => n,
        Err(e) => {
            log(&format!("{shown}: {}", sanitize(&e.to_string())));
            return None;
        }
    };
    bytes.resize(need, 0);
    if let Err(e) = read_exact_bounded(fd, &mut bytes[format::PREFIX_LEN..], budget) {
        log(&format!(
            "cannot read the header of {shown}: {}",
            sanitize(&e.to_string())
        ));
        return None;
    }
    let header = match format::decode_header(&bytes) {
        Ok(h) => h,
        Err(e) => {
            log(&format!("{shown}: {}", sanitize(&e.to_string())));
            return None;
        }
    };
    if !kdf_acceptable_for_login(&header.kdf) {
        log(&format!(
            "{shown}: refusing to hash the login password with KDF parameters \
             m_cost_kib={} t_cost={} p_cost={}",
            header.kdf.m_cost_kib, header.kdf.t_cost, header.kdf.p_cost
        ));
        return None;
    }
    Some((header.salt, header.kdf))
}

/// `socket=` is a test-harness affordance. A real login runs as root, where a
/// typo in the PAM config could otherwise aim the unlock at any socket on the
/// system; there the option is ignored.
fn socket_override_allowed(euid: u32) -> bool {
    euid != 0
}

/// Everything the session and password hooks need about the target user: the
/// control socket, the uid the daemon there must run as, and where the vault
/// files live.
pub(crate) struct Target {
    pub sock: PathBuf,
    pub uid: u32,
    pub vault_dir: PathBuf,
}

pub(crate) fn target_for(user: &str, opts: &Options) -> Option<Target> {
    let (uid, home) = user_info(user)?;
    let vault_dir = opts
        .vault_dir
        .clone()
        .unwrap_or_else(|| default_vault_dir(&home));
    if let Some(sock) = &opts.socket {
        if socket_override_allowed(effective_uid()) {
            // The fake daemon in the test harness runs as the current user.
            return Some(Target {
                sock: sock.clone(),
                uid: effective_uid(),
                vault_dir,
            });
        }
        log(
            "ignoring the 'socket=' option: it exists for tests and this module is running as root",
        );
    }
    Some(Target {
        sock: socket_path_for_runtime_dir(Path::new(&format!("/run/user/{uid}"))),
        uid,
        vault_dir,
    })
}

/// Spawns `cmd`, polling for exit rather than blocking on it, so the caller's
/// worst case is bounded by `timeout` regardless of how long the child runs.
/// Kills (and reaps) the child if it has not exited by then.
fn run_bounded(cmd: &mut std::process::Command, timeout: Duration) -> Result<ExitStatus, String> {
    let mut child = cmd.spawn().map_err(|e| format!("cannot spawn: {e}"))?;
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status),
            Ok(None) => {
                if start.elapsed() >= timeout {
                    if let Err(e) = child.kill() {
                        log(&format!("cannot kill timed-out child: {e}"));
                    }
                    if !reap_bounded(&mut child, REAP_TIMEOUT) {
                        log("timed-out child did not die; leaving it to init to reap");
                    }
                    return Err(format!("timed out after {timeout:?}"));
                }
                std::thread::sleep(POLL_INTERVAL);
            }
            Err(e) => return Err(format!("cannot wait: {e}")),
        }
    }
}

/// Collects a child that has already been killed, within `timeout`.
///
/// `SIGKILL` is not instantaneous: a process in uninterruptible sleep stays
/// there until its syscall finishes, and a plain `wait()` on it blocks
/// forever — inside a login, as root. Giving up leaves a zombie until this
/// process exits, which is far cheaper than a hung login.
fn reap_bounded(child: &mut Child, timeout: Duration) -> bool {
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return true,
            Err(_) => return false,
            Ok(None) => {
                if start.elapsed() >= timeout {
                    return false;
                }
                std::thread::sleep(POLL_INTERVAL);
            }
        }
    }
}

/// One wall-clock deadline shared by every stage of a hook, in the shape
/// `call_inner` in [`crate::protocol`] uses: each stage asks what is left and
/// is skipped once nothing is.
pub(crate) struct Budget {
    start: Instant,
    total: Duration,
}

impl Budget {
    pub(crate) fn new(total: Duration) -> Self {
        Self {
            start: Instant::now(),
            total,
        }
    }

    /// Time left, or `None` once the budget is spent.
    pub(crate) fn remaining(&self) -> Option<Duration> {
        self.total
            .checked_sub(self.start.elapsed())
            .filter(|d| !d.is_zero())
    }

    /// [`Budget::remaining`], but never more than a stage's own constant.
    pub(crate) fn capped(&self, max: Duration) -> Option<Duration> {
        self.remaining().map(|left| left.min(max))
    }
}

fn systemctl_path() -> &'static Path {
    SYSTEMCTL_PATHS
        .iter()
        .map(Path::new)
        .find(|p| p.exists())
        .unwrap_or_else(|| Path::new(SYSTEMCTL_PATHS[0]))
}

pub(crate) fn start_daemon(user: &str, budget: &Budget) {
    let Some(timeout) = budget.capped(START_TIMEOUT) else {
        log("no time left to start the daemon; vault stays locked");
        return;
    };
    let mut cmd = std::process::Command::new(systemctl_path());
    cmd.args([
        "--user",
        &format!("--machine={user}@.host"),
        "--no-block",
        "start",
        "secret-manager.service",
    ])
    .env_clear()
    .env("PATH", SAFE_PATH)
    .stdin(Stdio::null())
    .stdout(Stdio::null())
    .stderr(Stdio::null());
    match run_bounded(&mut cmd, timeout) {
        Ok(s) if s.success() => {}
        Ok(s) => log(&format!("systemctl exited with {s}")),
        Err(e) => log(&format!("cannot run systemctl: {}", sanitize(&e))),
    }
}

/// True once `path` is a socket. Existence is not enough: a regular file or a
/// dangling symlink the user planted at the socket path would otherwise end
/// the wait and send the retry into a connect that cannot succeed.
fn is_socket(path: &Path) -> bool {
    use std::os::unix::fs::FileTypeExt;
    std::fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_socket())
}

pub(crate) fn wait_for(path: &Path, timeout: Duration) -> bool {
    let start = Instant::now();
    while start.elapsed() < timeout {
        if is_socket(path) {
            return true;
        }
        std::thread::sleep(POLL_INTERVAL);
    }
    is_socket(path)
}

/// What may be done with the socket file after a failed connect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StaleSocket {
    /// Nothing is listening on a socket that exists: it is a leftover from a
    /// crashed daemon, and must be removed before a new one can bind it.
    Unlink,
    /// There is no socket to remove; just start the daemon.
    LeaveAlone,
}

/// Whether a failed connect proves the socket is stale. `None` means it does
/// not: a permission or timeout failure can happen against a perfectly live
/// daemon, and unlinking there would take its socket away.
pub(crate) fn stale_socket_action(kind: std::io::ErrorKind) -> Option<StaleSocket> {
    match kind {
        std::io::ErrorKind::ConnectionRefused => Some(StaleSocket::Unlink),
        std::io::ErrorKind::NotFound => Some(StaleSocket::LeaveAlone),
        _ => None,
    }
}

/// Performs one control-socket call, logging anything the daemon reports.
/// Transport failures are returned so the caller can decide whether to retry.
pub(crate) fn try_send(
    sock: &Path,
    req: &Request,
    uid: u32,
    what: &str,
    budget: Duration,
) -> Result<(), ProtocolError> {
    match call_expecting_uid_with_timeout(sock, req, uid, budget) {
        Ok(Response::Ok) => Ok(()),
        Ok(Response::Error(e)) => {
            log(&format!("{what} failed: {}", sanitize(&e)));
            Ok(())
        }
        // Variant name only: a `Response::Status` carries peer-chosen labels.
        Ok(other) => {
            log(&format!(
                "{what}: unexpected response {}",
                other.variant_name()
            ));
            Ok(())
        }
        Err(e) => Err(e),
    }
}

/// Argon2id under the header's own parameters. This is the expensive part of
/// a login — up to the login KDF ceiling, and `open_session` and `chauthtok`
/// each run it twice — so the hook's budget is consulted before starting one:
/// once it is spent the unlock is abandoned rather than added to.
///
/// The check is *before* the derivation, not during it: `derive_key` is not
/// interruptible, so a started derivation always runs to completion. The
/// bound this gives is "budget plus at most one KDF ceiling cost", which is
/// what [`HOOK_BUDGET`] documents.
fn derive(password: &str, salt: &[u8; SALT_LEN], kdf: KdfParams, budget: &Budget) -> Option<Key> {
    if budget.remaining().is_none() {
        log("no time left in the login budget; skipping the key derivation");
        return None;
    }
    match crypto::derive_key(password.as_bytes(), salt, kdf) {
        Ok(key) => Some(key),
        Err(e) => {
            log(&format!(
                "key derivation failed: {}",
                sanitize(&e.to_string())
            ));
            None
        }
    }
}

/// Derives the key locally from the header's own salt and parameters and
/// unlocks with it. Only transport errors are returned; everything else is
/// logged and treated as done.
#[allow(clippy::too_many_arguments)]
pub(crate) fn unlock_by_key(
    sock: &Path,
    collection: &str,
    uid: u32,
    password: &str,
    salt: &[u8; SALT_LEN],
    kdf: KdfParams,
    budget: &Budget,
    call_budget: Duration,
) -> Result<(), ProtocolError> {
    let Some(key) = derive(password, salt, kdf, budget) else {
        return Ok(());
    };
    let req = Request::UnlockWithKey {
        collection: collection.to_string(),
        key: Zeroizing::new(*key.as_bytes()),
    };
    try_send(sock, &req, uid, "unlock", call_budget)
}

/// Builds the `ChangeKey` request: `old_key` under the header's salt, and
/// `new_key` under a freshly generated one, both with the header's
/// parameters. `None` (already logged) if the RNG or Argon2 fails.
pub(crate) fn change_key_request(
    collection: &str,
    old: &str,
    new: &str,
    salt: &[u8; SALT_LEN],
    kdf: KdfParams,
    budget: &Budget,
) -> Option<Request> {
    // Non-panicking: an unavailable RNG must not abort a login.
    let new_salt = match crypto::try_random_bytes::<SALT_LEN>() {
        Ok(s) => s,
        Err(e) => {
            log(&format!(
                "cannot generate a new salt: {}",
                sanitize(&e.to_string())
            ));
            return None;
        }
    };
    let old_key = derive(old, salt, kdf, budget)?;
    let new_key = derive(new, &new_salt, kdf, budget)?;
    Some(Request::ChangeKey {
        collection: collection.to_string(),
        old_key: Zeroizing::new(*old_key.as_bytes()),
        new_salt,
        new_kdf: kdf,
        new_key: Zeroizing::new(*new_key.as_bytes()),
    })
}

pub(crate) fn log_transport(what: &str, e: &ProtocolError) {
    log(&format!("{what}: {}", sanitize(&e.to_string())));
}

/// Removes a socket that is provably stale, reporting whether the daemon may
/// now be started. A failed unlink (other than "already gone") means the
/// daemon could not bind the socket anyway, and may mean the path is not
/// ours to remove — so give up rather than start a daemon that will fail.
pub(crate) fn start_after_clearing(dir: &SocketDir, action: StaleSocket) -> bool {
    if action == StaleSocket::LeaveAlone {
        return true;
    }
    match dir.remove_socket() {
        Ok(()) => true,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => true,
        Err(e) => {
            log(&format!(
                "cannot remove the stale socket {}: {}; not starting the daemon",
                dir.sock.display(),
                sanitize(&e.to_string())
            ));
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{decode_frame, encode_frame, read_frame_sync};
    use crate::vault::crypto::NONCE_LEN;
    use crate::vault::format::{self, Header, VaultFile};
    use std::io::Write as _;
    use std::os::unix::fs::PermissionsExt as _;
    use std::os::unix::net::UnixListener;

    /// Cheapest parameters `kdf_acceptable_for_login` accepts, so tests that
    /// really run Argon2 stay fast.
    const LOGIN_KDF: KdfParams = KdfParams {
        m_cost_kib: 19 * 1024,
        t_cost: 2,
        p_cost: 1,
    };
    const SALT: [u8; SALT_LEN] = [0x5a; SALT_LEN];

    fn header_with(kdf: KdfParams, salt: [u8; SALT_LEN]) -> Header {
        Header {
            version: format::VERSION,
            label: "default".into(),
            created: 1,
            modified: 2,
            kdf,
            salt,
            index_salt: [7u8; SALT_LEN],
            nonce: [9u8; NONCE_LEN],
            index: Vec::new(),
        }
    }

    /// Writes a real vault file (header plus a little ciphertext) at
    /// `<dir>/<collection>.vault`, mode 0600.
    fn write_vault(dir: &Path, collection: &str, header: Header) -> PathBuf {
        let path = dir.join(format!("{collection}.vault"));
        let bytes = VaultFile::new(header, vec![0xab; 4096]).unwrap().encode();
        std::fs::write(&path, bytes).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        path
    }

    /// A budget with plenty left, for the tests that are not about the bound.
    fn full_budget() -> Budget {
        Budget::new(Duration::from_secs(60))
    }

    fn me() -> u32 {
        // SAFETY: getuid has no preconditions.
        unsafe { libc::getuid() }
    }

    /// Fake daemon: accepts exactly one connection, decodes the request,
    /// answers `Ok`, and hands the request back through the join handle.
    fn fake_daemon(sock: &Path) -> std::thread::JoinHandle<Request> {
        let listener = UnixListener::bind(sock).unwrap();
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let body = read_frame_sync(&mut stream).unwrap();
            let req: Request = decode_frame(&body).unwrap();
            stream
                .write_all(&encode_frame(&Response::Ok).unwrap())
                .unwrap();
            req
        })
    }

    #[test]
    fn parses_options_with_defaults() {
        let o = parse_options(&[]);
        assert_eq!(
            o,
            Options {
                collection: "default".into(),
                auto_start: true,
                socket: None,
                vault_dir: None,
            }
        );
        let o = parse_options(&[
            "collection=work".into(),
            "auto_start=no".into(),
            "socket=/tmp/s".into(),
            "vault_dir=/srv/vaults".into(),
            "bogus".into(),
        ]);
        assert_eq!(
            o,
            Options {
                collection: "work".into(),
                auto_start: false,
                socket: Some(PathBuf::from("/tmp/s")),
                vault_dir: Some(PathBuf::from("/srv/vaults")),
            }
        );
    }

    /// A relative `vault_dir=` would be resolved against whatever cwd the
    /// calling service happens to have; refuse it and use the default.
    #[test]
    fn rejects_a_relative_vault_dir() {
        assert_eq!(
            parse_options(&["vault_dir=relative/path".into()]).vault_dir,
            None
        );
        assert_eq!(parse_options(&["vault_dir=".into()]).vault_dir, None);
    }

    #[test]
    fn resolves_uid_and_home_of_current_user() {
        let user = std::env::var("USER").expect("USER set");
        let (uid, home) = user_info(&user).expect("current user resolves");
        assert_eq!(uid, me());
        assert!(home.is_absolute(), "{}", home.display());
        assert_eq!(user_info("definitely-not-a-user-9f2c"), None);
    }

    #[test]
    fn default_vault_dir_is_under_the_users_data_dir() {
        assert_eq!(
            default_vault_dir(Path::new("/home/alice")),
            PathBuf::from("/home/alice/.local/share/secret-manager")
        );
    }

    /// The KDF parameters come from an unauthenticated vault header, so they
    /// are attacker-controlled: too weak means a cheap-to-crack hash of the
    /// login password, too strong means a login that stalls for minutes.
    #[test]
    fn login_derivation_refuses_a_kdf_outside_the_login_bounds() {
        assert!(kdf_acceptable_for_login(&KdfParams::default()));
        assert!(kdf_acceptable_for_login(&LOGIN_KDF));
        // Floor.
        assert!(!kdf_acceptable_for_login(&KdfParams {
            m_cost_kib: 8,
            t_cost: 1,
            p_cost: 1
        }));
        assert!(!kdf_acceptable_for_login(&KdfParams {
            m_cost_kib: 19 * 1024 - 1,
            t_cost: 2,
            p_cost: 1
        }));
        assert!(!kdf_acceptable_for_login(&KdfParams {
            m_cost_kib: 65536,
            t_cost: 1,
            p_cost: 1
        }));
        // Ceiling.
        assert!(!kdf_acceptable_for_login(&KdfParams {
            m_cost_kib: KdfParams::MAX_M_COST_KIB + 1,
            t_cost: 2,
            p_cost: 1
        }));
        assert!(!kdf_acceptable_for_login(&KdfParams {
            m_cost_kib: 19 * 1024,
            t_cost: 9,
            p_cost: 1
        }));
        assert!(!kdf_acceptable_for_login(&KdfParams {
            m_cost_kib: 19 * 1024,
            t_cost: 2,
            p_cost: 5
        }));
        // The login ceiling is exactly reachable.
        assert!(kdf_acceptable_for_login(&KdfParams {
            m_cost_kib: MAX_M_COST_KIB_LOGIN,
            t_cost: MAX_T_COST_LOGIN,
            p_cost: MAX_P_COST_LOGIN
        }));
    }

    #[test]
    fn sanitize_strips_control_characters_and_bounds_length() {
        assert_eq!(sanitize("ok\nline\u{1b}[31m"), "okline[31m");
        assert_eq!(sanitize(&"x".repeat(1000)).len(), MAX_LOGGED_ERROR);
    }

    #[test]
    fn systemctl_is_an_absolute_path() {
        assert!(systemctl_path().is_absolute());
        assert!(SYSTEMCTL_PATHS.contains(&systemctl_path().to_str().unwrap()));
    }

    #[test]
    fn run_bounded_succeeds_within_timeout() {
        let status = run_bounded(
            &mut std::process::Command::new("true"),
            Duration::from_secs(5),
        )
        .expect("true should succeed");
        assert!(status.success());
    }

    #[test]
    fn run_bounded_kills_and_errors_on_timeout() {
        let start = Instant::now();
        let mut cmd = std::process::Command::new("sleep");
        cmd.arg("30");
        let err = run_bounded(&mut cmd, Duration::from_millis(300))
            .expect_err("sleep 30 should time out");
        assert!(err.contains("timed out"));
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "run_bounded should not wait for the full sleep"
        );
    }

    #[test]
    fn wait_for_sees_a_socket_that_appears_late() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("control.sock");
        let target = path.clone();
        let writer = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(150));
            UnixListener::bind(&target).unwrap()
        });
        assert!(wait_for(&path, Duration::from_secs(5)));
        drop(writer.join().unwrap());
    }

    /// Only a socket ends the wait: a regular file or a dangling symlink the
    /// user planted at the socket path must not pass for a running daemon.
    #[test]
    fn wait_for_accepts_only_a_socket() {
        let dir = tempfile::tempdir().unwrap();
        let plain = dir.path().join("plain");
        std::fs::write(&plain, b"").unwrap();
        assert!(!wait_for(&plain, Duration::from_millis(200)));

        let dangling = dir.path().join("dangling");
        std::os::unix::fs::symlink(dir.path().join("nowhere"), &dangling).unwrap();
        assert!(!wait_for(&dangling, Duration::from_millis(200)));

        let sock = dir.path().join("live.sock");
        let listener = UnixListener::bind(&sock).unwrap();
        assert!(wait_for(&sock, Duration::from_millis(200)));
        drop(listener);
    }

    #[test]
    fn wait_for_gives_up_on_a_path_that_never_appears() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("never");
        let start = Instant::now();
        assert!(!wait_for(&path, Duration::from_millis(300)));
        assert!(start.elapsed() >= Duration::from_millis(300));
        assert!(start.elapsed() < Duration::from_secs(5));
    }

    /// Unwinding across the C boundary libpam calls us through is undefined
    /// behaviour, so every hook body runs inside `guard`.
    #[test]
    fn guard_turns_a_panic_into_the_fallback() {
        assert_eq!(
            guard("test", 0u8, || panic!("boom")),
            0u8,
            "a panic must not unwind into libpam"
        );
        assert_eq!(guard("test", 0u8, || 7u8), 7);
        assert_eq!(guard("test", 0u8, || 9u8), 9);
    }

    /// The whole point of the design: the daemon receives Argon2id(password)
    /// under the header's own salt and parameters, never the password.
    #[test]
    fn unlock_by_key_sends_exactly_the_locally_derived_key() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("control.sock");
        let server = fake_daemon(&sock);
        unlock_by_key(
            &sock,
            "work",
            me(),
            "hunter2",
            &SALT,
            LOGIN_KDF,
            &full_budget(),
            Duration::from_secs(5),
        )
        .expect("unlock");
        let req = server.join().unwrap();
        let expected = crypto::derive_key(b"hunter2", &SALT, LOGIN_KDF).unwrap();
        match req {
            Request::UnlockWithKey { collection, key } => {
                assert_eq!(collection, "work");
                assert_eq!(&*key, expected.as_bytes());
            }
            ref other => panic!("expected UnlockWithKey, got {}", other.variant_name()),
        }
    }

    /// A transport failure must be reported, not swallowed: `open_session`
    /// decides from it whether to start the daemon.
    #[test]
    fn unlock_by_key_reports_a_transport_error() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("nothing-listening.sock");
        let err = unlock_by_key(
            &sock,
            "work",
            me(),
            "hunter2",
            &SALT,
            LOGIN_KDF,
            &full_budget(),
            Duration::from_secs(5),
        )
        .expect_err("nothing is listening");
        assert!(matches!(err, ProtocolError::Connect(_)), "{err:?}");
    }

    #[test]
    fn reads_salt_and_kdf_from_the_vault_header() {
        let dir = tempfile::tempdir().unwrap();
        write_vault(dir.path(), "default", header_with(LOGIN_KDF, SALT));
        let (salt, kdf) =
            vault_header(dir.path(), "default", me(), &full_budget()).expect("header readable");
        assert_eq!(salt, SALT);
        assert_eq!(kdf, LOGIN_KDF);
        // A collection with no vault file yields nothing, not a fallback.
        assert_eq!(
            vault_header(dir.path(), "absent", me(), &full_budget()),
            None
        );
    }

    /// Root reads this file out of a user-owned tree: anything the group or
    /// world can rewrite could aim the derivation at a chosen salt.
    #[test]
    fn refuses_a_group_writable_vault_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_vault(dir.path(), "default", header_with(LOGIN_KDF, SALT));
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o660)).unwrap();
        assert_eq!(
            vault_header(dir.path(), "default", me(), &full_budget()),
            None
        );
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o606)).unwrap();
        assert_eq!(
            vault_header(dir.path(), "default", me(), &full_budget()),
            None
        );
    }

    /// What this proves: the owner comparison in `vault_header` rejects a file
    /// whose owner is not the uid it was asked about.
    ///
    /// What it does **not** prove: that a genuinely cross-owner inode is
    /// refused. Creating a file owned by another uid needs root, which the test
    /// suite does not have, so the foreign owner is simulated from the other
    /// side — by passing `me() ^ 1` as the *expected* uid against a file this
    /// user owns. The comparison is exercised; the real cross-owner case is
    /// not. Do not read this as coverage of the privileged path.
    #[test]
    fn refuses_a_vault_file_owned_by_someone_else() {
        let dir = tempfile::tempdir().unwrap();
        write_vault(dir.path(), "default", header_with(LOGIN_KDF, SALT));
        assert_eq!(
            vault_header(dir.path(), "default", me() ^ 1, &full_budget()),
            None
        );
    }

    /// O_NOFOLLOW: a symlink at `<collection>.vault` could point at a file
    /// the user does not own but root can read.
    #[test]
    fn refuses_a_symlinked_vault_file() {
        let dir = tempfile::tempdir().unwrap();
        let real = write_vault(dir.path(), "real", header_with(LOGIN_KDF, SALT));
        std::os::unix::fs::symlink(&real, dir.path().join("default.vault")).unwrap();
        assert_eq!(
            vault_header(dir.path(), "default", me(), &full_budget()),
            None
        );
    }

    #[test]
    fn refuses_a_header_whose_kdf_is_out_of_bounds() {
        let dir = tempfile::tempdir().unwrap();
        // Below the login floor: cheap to crack.
        write_vault(
            dir.path(),
            "weak",
            header_with(
                KdfParams {
                    m_cost_kib: 8,
                    t_cost: 1,
                    p_cost: 1,
                },
                SALT,
            ),
        );
        assert_eq!(vault_header(dir.path(), "weak", me(), &full_budget()), None);
        // Above the vault's own ceiling: rejected by `decode_header` itself.
        write_vault(
            dir.path(),
            "huge",
            header_with(
                KdfParams {
                    m_cost_kib: u32::MAX,
                    t_cost: 1,
                    p_cost: 1,
                },
                SALT,
            ),
        );
        assert_eq!(vault_header(dir.path(), "huge", me(), &full_budget()), None);
    }

    #[test]
    fn refuses_a_file_that_is_not_a_vault() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("default.vault");
        std::fs::write(&path, b"NOTAVAULT and then some").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            vault_header(dir.path(), "default", me(), &full_budget()),
            None
        );
    }

    /// `ChangeKey` re-seals under a fresh salt, but keeps the header's
    /// parameters; the old key must still be the one that opens the vault.
    #[test]
    fn change_key_request_derives_both_keys_from_the_header_kdf() {
        let req = change_key_request("work", "old-pw", "new-pw", &SALT, LOGIN_KDF, &full_budget())
            .expect("request built");
        let Request::ChangeKey {
            collection,
            old_key,
            new_salt,
            new_kdf,
            new_key,
        } = req
        else {
            panic!("expected ChangeKey");
        };
        assert_eq!(collection, "work");
        assert_eq!(new_kdf, LOGIN_KDF);
        assert_ne!(new_salt, SALT, "rotation picks a fresh salt");
        let expected_old = crypto::derive_key(b"old-pw", &SALT, LOGIN_KDF).unwrap();
        let expected_new = crypto::derive_key(b"new-pw", &new_salt, LOGIN_KDF).unwrap();
        assert_eq!(&*old_key, expected_old.as_bytes());
        assert_eq!(&*new_key, expected_new.as_bytes());
    }

    /// Only a socket that provably has nobody behind it may be unlinked:
    /// unlinking on a transient error would destroy a live daemon's socket.
    #[test]
    fn only_a_refused_connect_may_unlink_the_socket() {
        use std::io::ErrorKind::*;
        assert_eq!(
            stale_socket_action(ConnectionRefused),
            Some(StaleSocket::Unlink)
        );
        assert_eq!(stale_socket_action(NotFound), Some(StaleSocket::LeaveAlone));
        for kind in [PermissionDenied, TimedOut, WouldBlock, Interrupted, Other] {
            assert_eq!(stale_socket_action(kind), None, "{kind:?}");
        }
    }

    /// `socket=` exists for the test harness. A real login runs as root, and
    /// there a stray option must never redirect the unlock to another socket.
    #[test]
    fn socket_override_is_ignored_for_root() {
        assert!(!socket_override_allowed(0));
        assert!(socket_override_allowed(1000));
        assert!(socket_override_allowed(me().max(1)));
    }

    fn mkfifo_at(path: &Path) {
        let c = CString::new(path.as_os_str().as_bytes()).unwrap();
        // SAFETY: `c` is a NUL-terminated path that outlives the call.
        let rc = unsafe { libc::mkfifo(c.as_ptr(), 0o600) };
        assert_eq!(rc, 0, "mkfifo: {}", std::io::Error::last_os_error());
    }

    /// Scope: the **open**, not the read. `O_NOFOLLOW` does not refuse a FIFO,
    /// and `open(O_RDONLY)` on one blocks until a writer appears — so a
    /// `mkfifo ~/.local/share/secret-manager/default.vault` would wedge root
    /// inside the login forever. This test proves only that the open is
    /// non-blocking and that the file type is checked, so the FIFO never
    /// reaches a read at all.
    ///
    /// The separate hazard of a read that blocks on something that *is* a
    /// regular file (a FUSE mount, a stalled NFS server) is covered by
    /// `a_read_that_never_completes_is_abandoned_within_the_budget` and
    /// `vault_header_refuses_to_read_on_a_spent_budget`; nothing here bears on
    /// it.
    #[test]
    fn refuses_a_fifo_in_place_of_the_vault_file_at_open_time() {
        let dir = tempfile::tempdir().unwrap();
        mkfifo_at(&dir.path().join("default.vault"));
        let start = Instant::now();
        assert_eq!(
            vault_header(dir.path(), "default", me(), &full_budget()),
            None
        );
        assert!(
            start.elapsed() < Duration::from_secs(3),
            "opening a FIFO must not block root: took {:?}",
            start.elapsed()
        );
    }

    /// A directory root will unlink inside must be a real directory, owned by
    /// the target user, and writable by nobody else.
    #[test]
    fn runtime_subdir_is_safe_only_for_an_owned_private_directory() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("secret-manager");
        std::fs::create_dir(&real).unwrap();
        std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o700)).unwrap();
        let meta = |p: &Path| std::fs::symlink_metadata(p).unwrap();
        assert!(runtime_subdir_is_safe(&meta(&real), me()));
        assert!(!runtime_subdir_is_safe(&meta(&real), me() ^ 1));
        // Group- or world-writable: another local user could plant the socket.
        std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o770)).unwrap();
        assert!(!runtime_subdir_is_safe(&meta(&real), me()));
        std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o707)).unwrap();
        assert!(!runtime_subdir_is_safe(&meta(&real), me()));
        std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o700)).unwrap();
        let link = dir.path().join("linked");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert!(!runtime_subdir_is_safe(&meta(&link), me()));
        let file = dir.path().join("file");
        std::fs::write(&file, b"").unwrap();
        assert!(!runtime_subdir_is_safe(&meta(&file), me()));
    }

    fn private_dir(parent: &Path, name: &str) -> PathBuf {
        let p = parent.join(name);
        std::fs::create_dir(&p).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o700)).unwrap();
        p
    }

    #[test]
    fn socket_dir_opens_an_owned_private_directory() {
        let dir = tempfile::tempdir().unwrap();
        let rt = private_dir(dir.path(), "secret-manager");
        let sd = SocketDir::open(&rt.join("control.sock"), me()).expect("owned 0700 dir");
        assert!(
            sd.is_open(),
            "the directory exists, so it must be held open"
        );
        // The path handed to `connect` resolves through the validated inode.
        let via = sd.socket_path();
        assert!(via.starts_with("/proc/self/fd/"), "{}", via.display());
    }

    #[test]
    fn socket_dir_rejects_a_symlinked_runtime_directory() {
        let dir = tempfile::tempdir().unwrap();
        let real = private_dir(dir.path(), "real");
        let link = dir.path().join("secret-manager");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert!(SocketDir::open(&link.join("control.sock"), me()).is_none());
    }

    /// What this proves: `SocketDir::open` refuses a directory whose owner is
    /// not the uid it was asked about, and one that is group-writable.
    ///
    /// What it does **not** prove: that a directory genuinely owned by another
    /// uid is refused. As in `refuses_a_vault_file_owned_by_someone_else`, the
    /// foreign owner is simulated by passing `me() ^ 1` as the *expected* uid
    /// rather than by creating an inode owned by someone else, which needs
    /// root. Only the group-writable half of this test uses a real inode
    /// property.
    #[test]
    fn socket_dir_rejects_a_wrong_owner_or_group_writable_directory() {
        let dir = tempfile::tempdir().unwrap();
        let rt = private_dir(dir.path(), "secret-manager");
        let sock = rt.join("control.sock");
        assert!(SocketDir::open(&sock, me() ^ 1).is_none());
        std::fs::set_permissions(&rt, std::fs::Permissions::from_mode(0o770)).unwrap();
        assert!(SocketDir::open(&sock, me()).is_none());
    }

    /// Absent is not a refusal: the daemon has simply not created its runtime
    /// directory yet, and there is nothing there to follow or to unlink.
    #[test]
    fn socket_dir_tolerates_an_absent_runtime_directory() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("secret-manager").join("control.sock");
        let sd = SocketDir::open(&sock, me()).expect("absent is fine");
        assert!(!sd.is_open());
        assert_eq!(sd.socket_path(), sock);
        // Nothing to remove, and no error.
        assert!(start_after_clearing(&sd, StaleSocket::Unlink));
    }

    /// The whole point of holding the descriptor: after validation the user
    /// may swap the *name* for a symlink elsewhere, and root's unlink must
    /// still land in the directory that was checked.
    #[test]
    fn a_directory_swap_after_validation_does_not_redirect_the_unlink() {
        let dir = tempfile::tempdir().unwrap();
        let rt = private_dir(dir.path(), "secret-manager");
        let victim = private_dir(dir.path(), "someone-else");
        std::fs::write(rt.join("control.sock"), b"stale").unwrap();
        std::fs::write(victim.join("control.sock"), b"live").unwrap();

        let sd = SocketDir::open(&rt.join("control.sock"), me()).expect("valid at open");
        // Swap the validated name for a symlink to another user's directory.
        let moved = dir.path().join("moved");
        std::fs::rename(&rt, &moved).unwrap();
        std::os::unix::fs::symlink(&victim, &rt).unwrap();

        assert!(start_after_clearing(&sd, StaleSocket::Unlink));
        assert!(
            !moved.join("control.sock").exists(),
            "the unlink must land in the validated directory"
        );
        assert!(
            victim.join("control.sock").exists(),
            "the swapped-in directory must be untouched"
        );
    }

    /// 40 parallel logins each derive a key in this process's address space,
    /// single-threaded; the login ceiling has to be far below the vault's own.
    #[test]
    fn login_kdf_ceiling_is_tighter_than_the_vaults() {
        // The shipped default still fits.
        assert!(kdf_acceptable_for_login(&KdfParams::default()));
        assert!(kdf_acceptable_for_login(&LOGIN_KDF));
        assert!(kdf_acceptable_for_login(&KdfParams {
            m_cost_kib: MAX_M_COST_KIB_LOGIN,
            t_cost: 2,
            p_cost: 1
        }));
        // The vault's own ceiling is now far too expensive for a login.
        assert!(!kdf_acceptable_for_login(&KdfParams {
            m_cost_kib: KdfParams::MAX_M_COST_KIB,
            t_cost: 8,
            p_cost: 4
        }));
        assert!(!kdf_acceptable_for_login(&KdfParams {
            m_cost_kib: MAX_M_COST_KIB_LOGIN + 1,
            t_cost: 2,
            p_cost: 1
        }));
        assert!(!kdf_acceptable_for_login(&KdfParams {
            m_cost_kib: 19 * 1024,
            t_cost: MAX_T_COST_LOGIN + 1,
            p_cost: 1
        }));
        assert!(!kdf_acceptable_for_login(&KdfParams {
            m_cost_kib: 19 * 1024,
            t_cost: 2,
            p_cost: MAX_P_COST_LOGIN + 1
        }));
        // Total work is bounded too: 64 MiB x 4 passes is the most a login may
        // be asked for, and that corner is exactly reachable.
        let corner = KdfParams {
            m_cost_kib: MAX_M_COST_KIB_LOGIN,
            t_cost: MAX_T_COST_LOGIN,
            p_cost: MAX_P_COST_LOGIN,
        };
        assert!(kdf_acceptable_for_login(&corner));
        assert_eq!(
            corner.m_cost_kib as u64 * corner.t_cost as u64,
            MAX_TOTAL_WORK_LOGIN,
            "the work bound must be exactly the m/t corner, not slack above it"
        );
        // Nothing beyond it, on either axis.
        assert!(!kdf_acceptable_for_login(&KdfParams {
            m_cost_kib: corner.m_cost_kib + 1,
            ..corner
        }));
        assert!(!kdf_acceptable_for_login(&KdfParams {
            t_cost: corner.t_cost + 1,
            ..corner
        }));
    }

    /// `log` escapes only NUL, so an unsanitized PAM username could forge
    /// syslog lines. Sanitizing inside `log` means no call site can forget.
    #[test]
    fn sanitize_strips_newlines_and_bidi_overrides() {
        assert_eq!(
            sanitize("alice\npam_secret_manager: unlocked root"),
            "alicepam_secret_manager: unlocked root"
        );
        // `char::is_control()` misses the Unicode bidi format characters.
        assert_eq!(sanitize("a\u{202e}b\u{2066}c\u{2069}d\u{202a}e"), "abcde");
        // Already-sanitized text is unchanged.
        assert_eq!(sanitize("plain text"), "plain text");
        assert_eq!(sanitize(&sanitize("x\ny")), sanitize("x\ny"));
    }

    /// Every serial stage of the unlock is attacker-influenced; one deadline
    /// covers them all.
    #[test]
    fn budget_shrinks_and_then_refuses() {
        let b = Budget::new(Duration::from_secs(8));
        let left = b.remaining().expect("fresh budget has time");
        assert!(left <= Duration::from_secs(8) && left > Duration::from_secs(7));
        assert_eq!(
            b.capped(Duration::from_millis(50)),
            Some(Duration::from_millis(50)),
            "a stage never gets more than its own constant"
        );
        let spent = Budget::new(Duration::ZERO);
        assert_eq!(spent.remaining(), None);
        assert_eq!(spent.capped(START_TIMEOUT), None);
    }

    /// `off`/`disabled`/`No` must not turn into the branch that unlinks as
    /// root and runs `systemctl`.
    #[test]
    fn auto_start_is_parsed_explicitly() {
        for v in ["no", "false", "0", "off", "NO", "Off", "FALSE"] {
            assert!(
                !parse_options(&[format!("auto_start={v}")]).auto_start,
                "auto_start={v} must disable"
            );
        }
        for v in ["yes", "true", "1", "on", "YES", "On"] {
            assert!(
                parse_options(&[format!("auto_start={v}")]).auto_start,
                "auto_start={v} must enable"
            );
        }
        // Anything unrecognised keeps the default rather than guessing.
        assert!(parse_options(&["auto_start=maybe".into()]).auto_start);
        assert!(parse_options(&["auto_start=".into()]).auto_start);
    }

    /// `collection=` is interpolated straight into a file name, so it must be
    /// restricted to the daemon's own id charset.
    #[test]
    fn rejects_a_collection_that_could_escape_the_vault_directory() {
        for v in ["../x", "", "a/b", "a.b", "a b", "..", "a-b"] {
            assert_eq!(
                parse_options(&[format!("collection={v}")]).collection,
                "default",
                "collection={v} must fall back"
            );
        }
        assert_eq!(
            parse_options(&["collection=work_2".into()]).collection,
            "work_2"
        );
    }

    /// A pipe with its write end held open and nothing ever written is the
    /// cheapest fd that is open, readable in principle, and never ready. It
    /// stands in for the hostile case that motivates the bound: a FUSE mount
    /// (or a stalled NFS server) serving a file that reports `S_IFREG | 0600`
    /// owned by the user, whose read handler simply never returns.
    fn blocked_pipe() -> (File, File) {
        let mut fds = [0 as libc::c_int; 2];
        // SAFETY: `fds` is a live array of two ints, which is what pipe2 writes.
        let rc = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) };
        assert_eq!(rc, 0, "pipe2: {}", std::io::Error::last_os_error());
        // SAFETY: both descriptors were just returned by pipe2 and are given to
        // `File`s that own them from here on.
        unsafe { (File::from_raw_fd(fds[0]), File::from_raw_fd(fds[1])) }
    }

    /// The HIGH finding: `O_NONBLOCK` bounds the *open*, not the *read*. A
    /// read that never completes must be abandoned when the hook's budget is
    /// spent, not waited on forever inside a login, as root.
    #[test]
    fn a_read_that_never_completes_is_abandoned_within_the_budget() {
        let (reader, _writer) = blocked_pipe();
        let mut buf = [0u8; 16];
        let budget = Budget::new(Duration::from_millis(300));
        let start = Instant::now();
        let e = read_exact_bounded(reader.as_raw_fd(), &mut buf, &budget)
            .expect_err("a read that never completes must not hang");
        assert_eq!(e.kind(), std::io::ErrorKind::TimedOut, "{e}");
        assert!(
            start.elapsed() >= Duration::from_millis(250),
            "it must actually wait for the budget: {:?}",
            start.elapsed()
        );
        assert!(
            start.elapsed() < Duration::from_secs(3),
            "it must not wait past the budget: {:?}",
            start.elapsed()
        );
    }

    /// An already-spent budget must not start a read at all.
    #[test]
    fn a_spent_budget_refuses_the_read_outright() {
        let (reader, _writer) = blocked_pipe();
        let mut buf = [0u8; 16];
        let start = Instant::now();
        let e = read_exact_bounded(reader.as_raw_fd(), &mut buf, &Budget::new(Duration::ZERO))
            .expect_err("no budget, no read");
        assert_eq!(e.kind(), std::io::ErrorKind::TimedOut, "{e}");
        assert!(start.elapsed() < Duration::from_millis(200));
    }

    /// The bound must not break the ordinary case: data that is there, and
    /// data that arrives late, are both read in full.
    #[test]
    fn the_bounded_read_still_reads_data_that_is_there() {
        let (reader, mut writer) = blocked_pipe();
        writer.write_all(b"0123456789").unwrap();
        let mut buf = [0u8; 10];
        read_exact_bounded(
            reader.as_raw_fd(),
            &mut buf,
            &Budget::new(Duration::from_secs(5)),
        )
        .expect("data already in the pipe");
        assert_eq!(&buf, b"0123456789");

        let (late_reader, mut late_writer) = blocked_pipe();
        let feeder = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(120));
            late_writer.write_all(b"late").unwrap();
            late_writer
        });
        let mut buf = [0u8; 4];
        read_exact_bounded(
            late_reader.as_raw_fd(),
            &mut buf,
            &Budget::new(Duration::from_secs(5)),
        )
        .expect("data that arrives inside the budget");
        assert_eq!(&buf, b"late");
        drop(feeder.join().unwrap());
    }

    /// A truncated file is an error, not a silent short header.
    #[test]
    fn the_bounded_read_reports_end_of_file() {
        let (reader, writer) = blocked_pipe();
        drop(writer);
        let mut buf = [0u8; 4];
        let e = read_exact_bounded(
            reader.as_raw_fd(),
            &mut buf,
            &Budget::new(Duration::from_secs(5)),
        )
        .expect_err("no writer, no data, ever");
        assert_eq!(e.kind(), std::io::ErrorKind::UnexpectedEof, "{e}");
    }

    /// The budget reaches `vault_header` itself: a spent hook must not start
    /// reading a file the user controls.
    #[test]
    fn vault_header_refuses_to_read_on_a_spent_budget() {
        let dir = tempfile::tempdir().unwrap();
        write_vault(dir.path(), "default", header_with(LOGIN_KDF, SALT));
        assert!(vault_header(dir.path(), "default", me(), &full_budget()).is_some());
        assert_eq!(
            vault_header(dir.path(), "default", me(), &Budget::new(Duration::ZERO)),
            None,
            "a spent budget must abandon the read"
        );
    }

    /// The HIGH finding on `connect`: `unlinkat` is descriptor-relative and so
    /// is inode-safe, but `connect(2)` on `/proc/self/fd/<n>/control.sock`
    /// resolves the whole path and follows a symlink at the final component.
    /// The name must be checked with `AT_SYMLINK_NOFOLLOW` first.
    #[test]
    fn connect_path_refuses_a_symlink_planted_at_the_socket_name() {
        let dir = tempfile::tempdir().unwrap();
        let rt = private_dir(dir.path(), "secret-manager");
        let sock = rt.join("control.sock");

        // Somewhere else entirely, with a real listener on it, so the only
        // reason to refuse is the symlink itself.
        let elsewhere = dir.path().join("elsewhere.sock");
        let listener = UnixListener::bind(&elsewhere).unwrap();

        let sd = SocketDir::open(&sock, me()).expect("owned 0700 dir");
        std::os::unix::fs::symlink(&elsewhere, &sock).unwrap();
        let e = sd
            .connect_path()
            .expect_err("a symlink at the socket name must be refused");
        assert_ne!(
            e.kind(),
            std::io::ErrorKind::NotFound,
            "a planted symlink is a refusal, not an absent socket"
        );
        drop(listener);
    }

    /// The same check must not refuse the real thing, and must report an
    /// absent entry as `NotFound` so the caller can still start the daemon.
    #[test]
    fn connect_path_accepts_a_real_socket_and_reports_an_absent_one() {
        let dir = tempfile::tempdir().unwrap();
        let rt = private_dir(dir.path(), "secret-manager");
        let sock = rt.join("control.sock");
        let sd = SocketDir::open(&sock, me()).expect("owned 0700 dir");

        let e = sd.connect_path().expect_err("nothing there yet");
        assert_eq!(e.kind(), std::io::ErrorKind::NotFound, "{e}");

        let listener = UnixListener::bind(&sock).unwrap();
        let p = sd.connect_path().expect("a real socket is accepted");
        assert!(p.starts_with("/proc/self/fd/"), "{}", p.display());
        drop(listener);

        // A regular file planted at the name is refused too, and not as
        // "absent" — root must not be pointed at a non-socket.
        std::fs::remove_file(&sock).unwrap();
        std::fs::write(&sock, b"not a socket").unwrap();
        let e = sd
            .connect_path()
            .expect_err("a regular file is not a socket");
        assert_ne!(e.kind(), std::io::ErrorKind::NotFound, "{e}");
    }

    /// The MEDIUM finding: `HOOK_BUDGET` has to cover the Argon2 derivations,
    /// which are the expensive part of a login, not just the socket calls.
    #[test]
    fn a_spent_budget_skips_the_derivations() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("control.sock");
        let spent = Budget::new(Duration::ZERO);

        // No listener: if the derivation were skipped but the call still made,
        // this would come back as a transport error rather than `Ok`.
        let start = Instant::now();
        unlock_by_key(
            &sock,
            "work",
            me(),
            "hunter2",
            &SALT,
            LOGIN_KDF,
            &spent,
            Duration::from_secs(5),
        )
        .expect("a spent budget abandons the unlock rather than failing it");
        assert!(
            start.elapsed() < Duration::from_millis(200),
            "no Argon2 may run on a spent budget: took {:?}",
            start.elapsed()
        );

        let start = Instant::now();
        assert!(
            change_key_request("work", "old-pw", "new-pw", &SALT, LOGIN_KDF, &spent).is_none(),
            "a spent budget abandons the key change"
        );
        assert!(
            start.elapsed() < Duration::from_millis(200),
            "no Argon2 may run on a spent budget: took {:?}",
            start.elapsed()
        );
    }

    /// After `kill`, a plain `wait` blocks forever on a child stuck in
    /// uninterruptible sleep; the reap gets its own short budget.
    #[test]
    fn reap_bounded_returns_promptly() {
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        child.kill().unwrap();
        let start = Instant::now();
        assert!(reap_bounded(&mut child, Duration::from_secs(2)));
        assert!(start.elapsed() < Duration::from_secs(2));
        // A live child is given up on rather than waited for.
        let mut live = std::process::Command::new("sleep")
            .arg("30")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let start = Instant::now();
        assert!(!reap_bounded(&mut live, Duration::from_millis(200)));
        assert!(start.elapsed() < Duration::from_secs(2));
        let _ = live.kill();
        let _ = live.wait();
    }
}
