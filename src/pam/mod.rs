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
/// derivations (the first unlock and the retry after starting the daemon),
/// three when the reset retry fires (first unlock, reset retry, and the retry
/// after starting the daemon), and `chauthtok` runs two (old key and new key),
/// each bounded by the login KDF ceiling of [`MAX_M_COST_KIB_LOGIN`] /
/// [`MAX_T_COST_LOGIN`] / [`MAX_P_COST_LOGIN`] rather than by the vault's. So
/// the guarantee is:
///
/// > this budget, plus at most the KDF ceiling cost of the derivations that
/// > were actually started before it ran out — budget plus at most two KDF
/// > ceilings when the reset retry fires.
///
/// A derivation is never *started* after the budget is spent, so the excess is
/// bounded by one ceiling-cost derivation in practice, two when the reset
/// retry fires. The reset retry deliberately re-derives rather than reusing
/// the first key.
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

/// Transport deaths worth exactly one retry: the peer vanished mid-call —
/// a daemon restart landing in the window — not a decision. Anything else
/// (refused, timed out, malformed, a daemon error reply) is deterministic,
/// and retrying it only spends login budget re-proving the failure.
fn retryable_reset(e: &ProtocolError) -> bool {
    let ProtocolError::Io(io) = e else {
        return false;
    };
    matches!(
        io.kind(),
        std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::BrokenPipe
            | std::io::ErrorKind::UnexpectedEof
    )
}

/// Whether this process must shed root before touching the socket: only
/// root facing a foreign target. Anything else is already where it needs
/// to be (the target itself, or root's own vault), or cannot get there.
fn privileges_to_drop(euid: u32, target: u32) -> bool {
    euid == 0 && target != 0 && euid != target
}

/// Shed root before the first connect: a daemon behind mount sandboxing
/// runs inside a single-uid user namespace, where every host uid except
/// the target maps to the overflow uid — so root would arrive
/// unrecognisable and be refused, while the target uid maps to itself.
/// Supplementary groups go first (peer checks are uid-only, and nothing
/// past this point needs root's memberships); setuid is irreversible by
/// design. Everything root is needed for (fd-pinned directory validation,
/// header read) already happened above. A failure keeps old behaviour
/// (proceed as-is) rather than inventing a new one.
fn drop_privileges_for_socket(target: u32) -> bool {
    // SAFETY: geteuid has no preconditions and cannot fail.
    let euid = unsafe { libc::geteuid() };
    if !privileges_to_drop(euid, target) {
        return true;
    }
    // SAFETY: dropping to an empty group list; root only reaches here.
    if unsafe { libc::setgroups(0, std::ptr::null()) } != 0 {
        log("cannot drop supplementary groups; continuing with them");
    }
    // SAFETY: setuid from euid 0; target is a validated non-zero uid.
    if unsafe { libc::setuid(target) } != 0 {
        log(&format!("cannot setuid to {target}; continuing as root"));
        return false;
    }
    true
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
/// bound this gives is "budget plus at most one KDF ceiling cost" — budget
/// plus at most two KDF ceilings when the reset retry fires — which is what
/// [`HOOK_BUDGET`] documents.
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

/// One unlock attempt: the `fstatat` check on the socket name plus the
/// derivation and the call. `connect_path` refusals surface as
/// `ProtocolError::Connect`, so callers map every error the same way.
#[allow(clippy::too_many_arguments)]
fn unlock_once(
    dir: &SocketDir,
    opts: &Options,
    target: &Target,
    password: &str,
    salt: &[u8; SALT_LEN],
    kdf: KdfParams,
    call: Duration,
    budget: &Budget,
) -> Result<(), ProtocolError> {
    match dir.connect_path() {
        Ok(path) => unlock_by_key(
            &path,
            &opts.collection,
            target.uid,
            password,
            salt,
            kdf,
            budget,
            call,
        ),
        Err(e) => Err(ProtocolError::Connect(e)),
    }
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

// ---------------------------------------------------------------------------
// Hook decisions
//
// The `pam_sm_*` entry points in `hooks.rs` only exist in the `--features pam`
// cdylib, so nothing in that file is reachable from a normal `cargo test`. The
// ordering each hook decides — what is checked before what, what is skipped
// once the budget is spent, when the stashed password is cleared — is the part
// that matters and the part that is easy to get wrong, so it lives here, where
// it compiles and is tested without libpam.
//
// The split is: everything that needs a `PamHandle` stays in `hooks.rs`;
// everything that decides stays here and returns an outcome value the hook
// only has to translate into `PamError::SUCCESS`. The two things that cannot
// be resolved up front are passed as closures rather than values, because
// *when* they run is itself part of the ordering: resolving the target user
// runs `getpwnam` and can log a refusal, and starting the daemon execs
// `systemctl`. Nothing else is injected — `SocketDir`, `Budget`, `Target` and
// the vault file are all real here.
// ---------------------------------------------------------------------------

/// Ceiling for one control-socket call. A whole hook is bounded by
/// [`HOOK_BUDGET`]; this keeps a single stalled call from consuming all of it
/// while still shrinking as the budget does.
const CALL_BUDGET: Duration = Duration::from_secs(3);

/// Logged when a hook's overall deadline runs out. The login itself always
/// proceeds; only the vault work is abandoned.
const SPENT: &str = "took too long; abandoning the unlock so the login can proceed";

/// `PAM_PRELIM_CHECK` from <security/pam_modules.h>; pamsm does not expose it.
pub(crate) const PAM_PRELIM_CHECK: i32 = 0x4000;

/// What `authenticate` found in libpam's authentication-token cache.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum AuthOutcome {
    /// A token is available and the hook must stash it for `open_session`.
    Stash,
    /// libpam has no token; there will be nothing to unlock with later.
    NoToken,
    /// libpam refused to hand the token over.
    Unavailable,
}

/// `authenticate`'s whole decision: whether the token PAM already collected is
/// worth stashing. `Err` carries the libpam error text; `Ok(None)` means there
/// simply is no token, which is normal and logged differently.
pub(crate) fn authenticate_decision(token: Result<Option<&str>, &str>) -> AuthOutcome {
    match token {
        Ok(Some(_)) => AuthOutcome::Stash,
        Ok(None) => {
            log("no authentication token available; nothing to unlock later");
            AuthOutcome::NoToken
        }
        Err(e) => {
            log(&format!("cannot read authentication token: {e}"));
            AuthOutcome::Unavailable
        }
    }
}

/// What [`open_session_decision`] decided, separated from libpam so the
/// ordering can be tested. The hook itself only turns this into
/// `PamError::SUCCESS` and clears the stashed password.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum SessionOutcome {
    /// `authenticate` stashed nothing, so there is nothing to unlock with —
    /// and nothing to clear either.
    NoPassword,
    /// The target user did not resolve, so there is no socket path.
    NoTarget,
    /// [`SocketDir::open`] refused the runtime directory; root must not touch
    /// anything under it.
    RefusedSocketDir,
    /// The collection's vault header could not be read, so there is no salt
    /// and no KDF to derive under.
    NoVaultHeader,
    /// The deadline ran out before the derivation could be started.
    BudgetSpent,
    /// Time is left, but not enough to give a control-socket call.
    NoCallBudget,
    /// The unlock call was made. "Made", not "succeeded": a daemon that
    /// answers `Error`, and a derivation the budget cut off inside
    /// [`unlock_by_key`], both land here — neither is a transport failure and
    /// neither is retried.
    Attempted,
    /// The attempt failed in a way that is not "the daemon is not running":
    /// any non-transport error, or a connect failure with `auto_start=no`.
    Failed,
    /// The connect failed, but not with an errno that proves nobody is behind
    /// the socket, so the daemon is not started on the strength of it.
    ConnectNotStale,
    /// The daemon-start path was taken; see [`StartOutcome`].
    Started(StartOutcome),
}

impl SessionOutcome {
    /// Whether the hook must clear the password `authenticate` stashed.
    ///
    /// Every path does, which is the point: the stash outlives the hook
    /// otherwise, in a process the target user is logging in to. The one
    /// exception is the path where the retrieve itself found nothing, where
    /// there is no stash to clear. Matched exhaustively on purpose — a new
    /// exit path has to answer this question.
    pub(crate) fn clears_stash(&self) -> bool {
        match self {
            Self::NoPassword => false,
            Self::NoTarget
            | Self::RefusedSocketDir
            | Self::NoVaultHeader
            | Self::BudgetSpent
            | Self::NoCallBudget
            | Self::Attempted
            | Self::Failed
            | Self::ConnectNotStale
            | Self::Started(_) => true,
        }
    }
}

/// How far the `auto_start` path got. Everything here happens after a connect
/// that proved the daemon is not answering.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum StartOutcome {
    /// The deadline was already spent, so the daemon was not started.
    NoStartBudget,
    /// A stale socket was in the way and could not be removed. The daemon
    /// could not bind it either, so it is not started.
    StaleSocketStuck,
    /// The target user's name was not available, so nothing was started and
    /// nothing was retried.
    NoUser,
    /// The daemon was started but the retry was not attempted.
    /// `revalidated` is `None` when the wait timed out, because the runtime
    /// directory is then never re-checked at all.
    NotRetried {
        waited: bool,
        revalidated: Option<bool>,
    },
    /// The socket appeared and the directory revalidated, but the deadline was
    /// spent before the second derivation could start.
    RetryBudgetSpent,
    /// Time remains overall but not enough for a call. Unreachable in
    /// practice — `remaining()` being `Some` makes `capped()` `Some` — and
    /// kept only because the hook has the branch.
    NoRetryCallBudget,
    /// The second unlock was attempted.
    Retried,
}

/// The `auto_start` tail shared by the first attempt and the reset retry:
/// clear a provably stale socket, start the daemon, wait for its socket,
/// revalidate the directory, and try the unlock once more. Callers route a
/// `Connect` failure here; everything after the connect error is identical,
/// so it lives in one place rather than twice.
#[allow(clippy::too_many_arguments)]
fn start_and_retry(
    dir: &mut SocketDir,
    opts: &Options,
    target: &Target,
    password: &str,
    salt: &[u8; SALT_LEN],
    kdf: KdfParams,
    budget: &Budget,
    sock: &Path,
    e: std::io::Error,
    start_daemon: &dyn Fn(&Budget) -> bool,
) -> SessionOutcome {
    let Some(action) = stale_socket_action(e.kind()) else {
        log_transport("unlock", &ProtocolError::Connect(e));
        return SessionOutcome::ConnectNotStale;
    };
    log(&format!("cannot reach the daemon ({e}); starting it"));
    if budget.capped(START_TIMEOUT).is_none() {
        log(SPENT);
        return SessionOutcome::Started(StartOutcome::NoStartBudget);
    }
    if !start_after_clearing(dir, action) {
        return SessionOutcome::Started(StartOutcome::StaleSocketStuck);
    }
    if !start_daemon(budget) {
        return SessionOutcome::Started(StartOutcome::NoUser);
    }
    // The runtime directory is re-checked: the wait spans a window in which
    // the user could have replaced it. `revalidate` is only consulted when the
    // socket actually turned up, so a timed-out wait leaves it unevaluated.
    let waited = budget
        .capped(START_TIMEOUT)
        .is_some_and(|left| wait_for(sock, left));
    let revalidated = if waited { Some(dir.revalidate()) } else { None };
    if revalidated != Some(true) {
        log("daemon did not start in time; vault stays locked");
        return SessionOutcome::Started(StartOutcome::NotRetried {
            waited,
            revalidated,
        });
    }
    if budget.remaining().is_none() {
        log(SPENT);
        return SessionOutcome::Started(StartOutcome::RetryBudgetSpent);
    }
    let Some(left) = budget.capped(CALL_BUDGET) else {
        log("no time left in the login budget");
        return SessionOutcome::Started(StartOutcome::NoRetryCallBudget);
    };
    if let Err(e) = unlock_once(dir, opts, target, password, salt, kdf, left, budget) {
        log_transport("unlock", &e);
    }
    SessionOutcome::Started(StartOutcome::Retried)
}

/// Everything `open_session` decides, in the order it decides it.
///
/// `resolve_target` and `start_daemon` are closures because the hook resolves
/// both through the `PamHandle`, and because both must run *when* the hook
/// runs them: `resolve_target` reaches NSS and logs, and `start_daemon` execs
/// `systemctl`. The parsed options are handed to `resolve_target` rather than
/// parsed by the hook, so `parse_options` — which logs — still runs exactly
/// once. `start_daemon` returns whether it ran at all — the hook has no
/// user name to start a daemon for if `pam_get_user` fails, and then nothing
/// downstream happens either.
pub(crate) fn open_session_decision(
    password: Option<&str>,
    args: &[String],
    budget: &Budget,
    resolve_target: &dyn Fn(&Options) -> Option<Target>,
    start_daemon: &dyn Fn(&Budget) -> bool,
) -> SessionOutcome {
    let opts = parse_options(args);
    let Some(password) = password else {
        log("no stashed password for session; vault stays locked");
        return SessionOutcome::NoPassword;
    };
    let Some(t) = resolve_target(&opts) else {
        log("cannot determine the control socket path");
        return SessionOutcome::NoTarget;
    };
    // The directory is held open from here on: every later unlink, connect and
    // re-check goes through this descriptor rather than through a name the
    // user can swap underneath root.
    let Some(mut dir) = SocketDir::open(&t.sock, t.uid) else {
        return SessionOutcome::RefusedSocketDir;
    };
    // Salt and parameters come from the vault file itself, never from whatever
    // happens to answer the socket.
    let Some((salt, kdf)) = vault_header(&t.vault_dir, &opts.collection, t.uid, budget) else {
        return SessionOutcome::NoVaultHeader;
    };
    if budget.remaining().is_none() {
        log(SPENT);
        return SessionOutcome::BudgetSpent;
    }
    // Shed root before touching the socket: root-validated directory and
    // header are behind us, and every later step (connects, systemctl as
    // the user, the key send) is better — or only works — as the target.
    drop_privileges_for_socket(t.uid);
    // A leftover socket from a crashed daemon looks exactly like a running
    // one, so only a failed connect is a usable test.
    let sock = dir.socket_path();
    let Some(call) = budget.capped(CALL_BUDGET) else {
        log("no time left in the login budget; vault stays locked");
        return SessionOutcome::NoCallBudget;
    };
    // `connect_path` re-checks the socket *name* with `AT_SYMLINK_NOFOLLOW`:
    // holding the directory open pins the parent, but `connect(2)` still
    // resolves the final component, so a symlink planted there would redirect
    // root. A refusal is reported as a connect failure, which is what it is.
    let attempt = unlock_once(&dir, &opts, &t, password, &salt, kdf, call, budget);
    match attempt {
        Ok(()) => SessionOutcome::Attempted,
        Err(ProtocolError::Connect(e)) if opts.auto_start => start_and_retry(
            &mut dir,
            &opts,
            &t,
            password,
            &salt,
            kdf,
            budget,
            &sock,
            e,
            start_daemon,
        ),
        Err(e) if retryable_reset(&e) => {
            // One retry, not a loop: whatever the second attempt reports is
            // returned. The re-derivation below is itself budget-gated inside
            // `unlock_by_key` via `derive`; the reset retry deliberately
            // re-derives rather than reusing the first key.
            log_transport("unlock", &e);
            let Some(call) = budget.capped(CALL_BUDGET) else {
                log("no time left in the login budget; vault stays locked");
                return SessionOutcome::NoCallBudget;
            };
            log("unlock hit a reset transport; retrying once within budget");
            // The retry is a second connect into a directory the logging-in
            // user controls. Re-check the held descriptor first; if the
            // directory changed, abort. Whatever socket the retry does reach
            // is still contained by the SO_PEERCRED check, which requires the
            // peer to run as the target uid.
            if !dir.revalidate() {
                log_transport("unlock", &e);
                return SessionOutcome::Failed;
            }
            match unlock_once(&dir, &opts, &t, password, &salt, kdf, call, budget) {
                Ok(()) => SessionOutcome::Attempted,
                Err(second) if retryable_reset(&second) => {
                    log_transport("unlock", &second);
                    SessionOutcome::Failed
                }
                Err(ProtocolError::Connect(e2)) if opts.auto_start => start_and_retry(
                    &mut dir,
                    &opts,
                    &t,
                    password,
                    &salt,
                    kdf,
                    budget,
                    &sock,
                    e2,
                    start_daemon,
                ),
                Err(second) => {
                    log_transport("unlock", &second);
                    SessionOutcome::Failed
                }
            }
        }
        Err(e) => {
            log_transport("unlock", &e);
            SessionOutcome::Failed
        }
    }
}

/// What [`chauthtok_decision`] decided.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ChauthtokOutcome {
    /// `PAM_PRELIM_CHECK`: the stack is only asking whether the change could
    /// work. Nothing is read, derived or sent on this pass.
    Prelim,
    /// One or both passwords were unavailable. Carries the text logged, since
    /// which one is missing is the whole content of the decision.
    Missing(&'static str),
    /// The target user did not resolve.
    NoTarget,
    /// [`SocketDir::open`] refused the runtime directory.
    RefusedSocketDir,
    /// The collection's vault header could not be read.
    NoVaultHeader,
    /// A derivation or the RNG failed, so there is no request to send.
    NoRequest,
    /// The deadline ran out after the derivations.
    BudgetSpent,
    /// Time is left, but not enough to give a control-socket call.
    NoCallBudget,
    /// The `ChangeKey` request was delivered.
    Sent,
    /// The request could not be delivered.
    SendFailed,
}

/// Everything `chauthtok` decides, in the order it decides it.
///
/// `flags` is the raw bit set libpam passed, so the `PAM_PRELIM_CHECK` early
/// return is part of what is tested. `budget` is created by the hook before
/// this is called and is therefore live across the prelim return; that costs
/// an `Instant::now()` and nothing else. Options are parsed *here* rather than
/// by the hook, because parsing logs and a prelim pass must stay silent.
pub(crate) fn chauthtok_decision(
    flags: i32,
    old: Option<&str>,
    new: Option<&str>,
    args: &[String],
    budget: &Budget,
    resolve_target: &dyn Fn(&Options) -> Option<Target>,
) -> ChauthtokOutcome {
    if flags & PAM_PRELIM_CHECK != 0 {
        return ChauthtokOutcome::Prelim;
    }
    let opts = parse_options(args);
    let (Some(old), Some(new)) = (old, new) else {
        let missing = match (old.is_some(), new.is_some()) {
            (false, false) => "old and new passwords",
            (false, true) => "the old password",
            _ => "the new password",
        };
        log(&format!(
            "cannot forward the password change: {missing} unavailable"
        ));
        return ChauthtokOutcome::Missing(missing);
    };
    let Some(t) = resolve_target(&opts) else {
        log("cannot determine the control socket path");
        return ChauthtokOutcome::NoTarget;
    };
    let Some(dir) = SocketDir::open(&t.sock, t.uid) else {
        return ChauthtokOutcome::RefusedSocketDir;
    };
    let Some((salt, kdf)) = vault_header(&t.vault_dir, &opts.collection, t.uid, budget) else {
        return ChauthtokOutcome::NoVaultHeader;
    };
    let Some(req) = change_key_request(&opts.collection, old, new, &salt, kdf, budget) else {
        return ChauthtokOutcome::NoRequest;
    };
    if budget.remaining().is_none() {
        log(SPENT);
        return ChauthtokOutcome::BudgetSpent;
    }
    let Some(left) = budget.capped(CALL_BUDGET) else {
        log("no time left in the password-change budget");
        return ChauthtokOutcome::NoCallBudget;
    };
    // Same blindness as the login path: shed root before touching the
    // socket so the daemon sees the target uid, not the overflow uid.
    drop_privileges_for_socket(t.uid);
    match dir.connect_path() {
        Ok(path) => match try_send(&path, &req, t.uid, "password change", left) {
            Ok(()) => ChauthtokOutcome::Sent,
            Err(e) => {
                log_transport("password change", &e);
                ChauthtokOutcome::SendFailed
            }
        },
        Err(e) => {
            log_transport("password change", &ProtocolError::Connect(e));
            ChauthtokOutcome::SendFailed
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

    /// How long a fake daemon waits for the next connection, and how often it
    /// polls. The timeouts are the hang guard: a missing connection fails the
    /// test instead of blocking `join` forever.
    const ACCEPT_TIMEOUT: Duration = Duration::from_secs(5);
    const ACCEPT_POLL: Duration = Duration::from_millis(20);

    fn accept_one(
        listener: &UnixListener,
        what: &str,
    ) -> (
        std::os::unix::net::UnixStream,
        std::os::unix::net::SocketAddr,
    ) {
        let start = Instant::now();
        loop {
            match listener.accept() {
                Ok((stream, addr)) => {
                    // The timeouts are the hang guard: a client that connects
                    // and then never sends must not block the test forever.
                    stream.set_read_timeout(Some(ACCEPT_TIMEOUT)).unwrap();
                    return (stream, addr);
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    let elapsed = start.elapsed();
                    assert!(
                        elapsed < ACCEPT_TIMEOUT,
                        "no {what} arrived after {elapsed:?}"
                    );
                    std::thread::sleep(ACCEPT_POLL);
                }
                Err(e) => {
                    let elapsed = start.elapsed();
                    panic!("{what} accept failed after {elapsed:?}: {e}");
                }
            }
        }
    }

    /// Fake daemon that drops `drops` connections unanswered (a restart
    /// landing mid-call), then serves one `Ok` and hands its request back.
    fn fake_daemon_flapping(sock: &Path, drops: usize) -> std::thread::JoinHandle<Request> {
        let listener = UnixListener::bind(sock).unwrap();
        listener.set_nonblocking(true).unwrap();
        std::thread::spawn(move || {
            for i in 0..drops {
                let (mut first, _) = accept_one(&listener, &format!("connection {}", i + 1));
                let _ = read_frame_sync(&mut first);
                drop(first);
            }
            let (mut stream, _) = accept_one(&listener, "retry");
            // The timeouts are the hang guard: see `accept_one`.
            stream.set_read_timeout(Some(ACCEPT_TIMEOUT)).unwrap();
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

    /// Answers one connection with a chosen [`Response`], for the arms
    /// [`fake_daemon`] cannot reach: it always answers `Ok`.
    fn fake_daemon_answering(sock: &Path, resp: Response) -> std::thread::JoinHandle<()> {
        let listener = UnixListener::bind(sock).unwrap();
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            read_frame_sync(&mut stream).unwrap();
            stream.write_all(&encode_frame(&resp).unwrap()).unwrap();
        })
    }

    /// `revalidate` is what stands between the daemon-start window and the
    /// retry unlock. A directory that was owned and private when it was
    /// opened may have been opened up while `systemctl` ran, and the held
    /// descriptor sees that: it is the same inode, so a `chmod` on it is
    /// visible even though a rename would not be.
    #[test]
    fn revalidate_refuses_a_directory_opened_up_during_the_start_window() {
        let dir = tempfile::tempdir().unwrap();
        let rt = private_dir(dir.path(), "secret-manager");
        let mut sd = SocketDir::open(&rt.join("control.sock"), me()).expect("valid at open");
        assert!(sd.revalidate(), "nothing has changed yet");

        std::fs::set_permissions(&rt, std::fs::Permissions::from_mode(0o770)).unwrap();
        assert!(
            !sd.revalidate(),
            "a group-writable runtime directory must not be used after the window"
        );
        // Restore, so the temp directory can still be torn down.
        std::fs::set_permissions(&rt, std::fs::Permissions::from_mode(0o700)).unwrap();
    }

    /// The other arm of `revalidate`: nothing was held open because the
    /// directory did not exist, and the daemon created it during the window.
    /// It has never been used through its name, so there is nothing a swap
    /// could have redirected — but it has also never been validated, so it
    /// must be validated now rather than adopted on trust.
    #[test]
    fn revalidate_validates_a_directory_that_only_appeared_during_the_window() {
        let dir = tempfile::tempdir().unwrap();
        let rt = dir.path().join("secret-manager");
        let mut sd = SocketDir::open(&rt.join("control.sock"), me()).expect("absent is fine");
        assert!(!sd.is_open(), "there was nothing to hold open");

        // Appears world-writable: another local user could plant the socket.
        std::fs::create_dir(&rt).unwrap();
        std::fs::set_permissions(&rt, std::fs::Permissions::from_mode(0o707)).unwrap();
        assert!(
            !sd.revalidate(),
            "a directory that appears world-writable must be refused, not adopted"
        );
        assert!(!sd.is_open(), "a refused directory is not held open");

        // Owned and private: adopted, and held open from here on.
        std::fs::set_permissions(&rt, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(sd.revalidate(), "an owned 0700 directory is adopted");
        assert!(sd.is_open(), "the adopted directory must be held open");
        assert!(
            sd.socket_path().starts_with("/proc/self/fd/"),
            "{}",
            sd.socket_path().display()
        );
    }

    /// A failed unlink means the daemon could not have bound that socket
    /// either, and may mean the path is not ours to remove. `open_session`
    /// reads `false` as "do not start the daemon", rather than launching one
    /// that is certain to fail to bind.
    ///
    /// `0500` is the case that reaches the refusal: `runtime_subdir_is_safe`
    /// only tests `mode & 0o022`, so a directory that is readable and
    /// searchable but not writable passes validation and then denies the
    /// `unlinkat` with `EACCES`.
    #[test]
    fn a_stale_socket_that_cannot_be_removed_stops_the_daemon_start() {
        let dir = tempfile::tempdir().unwrap();
        let rt = private_dir(dir.path(), "secret-manager");
        let sock = rt.join("control.sock");
        std::fs::write(&sock, b"stale").unwrap();

        std::fs::set_permissions(&rt, std::fs::Permissions::from_mode(0o500)).unwrap();
        let sd = SocketDir::open(&sock, me()).expect("0500 is not group- or world-writable");
        let started = start_after_clearing(&sd, StaleSocket::Unlink);
        // Restore before asserting, so a failure cannot leave an
        // undeletable temp directory behind.
        std::fs::set_permissions(&rt, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(
            !started,
            "an unlink refused with EACCES must not be followed by a daemon start"
        );
        assert!(sock.exists(), "nothing was removed");
    }

    /// "Already gone" is not a failure: the daemon may have cleaned up, or
    /// another login may have won the race. There is nothing left to bind
    /// over, so the start proceeds.
    #[test]
    fn a_socket_that_vanished_under_us_is_not_a_refusal() {
        let dir = tempfile::tempdir().unwrap();
        let rt = private_dir(dir.path(), "secret-manager");
        let sd = SocketDir::open(&rt.join("control.sock"), me()).expect("owned 0700 dir");
        assert!(
            start_after_clearing(&sd, StaleSocket::Unlink),
            "an absent socket is nothing to remove, not an error"
        );
    }

    /// `LeaveAlone` is chosen when the connect said `NotFound`, and it must
    /// stay a no-op: anything at the name is not ours to delete on that
    /// evidence.
    #[test]
    fn leave_alone_never_touches_the_filesystem() {
        let dir = tempfile::tempdir().unwrap();
        let rt = private_dir(dir.path(), "secret-manager");
        let sock = rt.join("control.sock");
        std::fs::write(&sock, b"someone else's").unwrap();
        let sd = SocketDir::open(&sock, me()).expect("owned 0700 dir");
        assert!(start_after_clearing(&sd, StaleSocket::LeaveAlone));
        assert!(sock.exists(), "LeaveAlone must not unlink");
    }

    /// A daemon that answers is a daemon that is running, whatever it says.
    /// An `Err` here would be read by `open_session` as "unreachable", and it
    /// would then unlink a live daemon's socket and relaunch it.
    #[test]
    fn a_daemon_that_answers_error_is_still_reachable() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("control.sock");
        let server = fake_daemon_answering(
            &sock,
            Response::Error("no such collection\nforged: unlocked root".into()),
        );
        try_send(
            &sock,
            &Request::Status,
            me(),
            "unlock",
            Duration::from_secs(5),
        )
        .expect("a daemon that reports an error is still a running daemon");
        server.join().unwrap();
    }

    /// The same for a reply this call never asked for. `Status` carries
    /// peer-chosen collection ids, labels and warnings, so it is logged by
    /// variant name only and none of it reaches the line.
    #[test]
    fn an_unexpected_response_variant_is_still_reachable() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("control.sock");
        let server = fake_daemon_answering(
            &sock,
            Response::Status {
                aliases_error: None,
                collections: vec![crate::protocol::CollectionStatus {
                    id: "default".into(),
                    label: "\u{202e}forged label".into(),
                    locked: false,
                    items: 1,
                    warning: Some("attacker text".into()),
                }],
                uptime_secs: 7,
            },
        );
        try_send(
            &sock,
            &Request::Status,
            me(),
            "unlock",
            Duration::from_secs(5),
        )
        .expect("an unexpected variant is still an answer");
        server.join().unwrap();
        assert_eq!(
            Response::Status {
                aliases_error: None,
                collections: Vec::new(),
                uptime_secs: 0,
            }
            .variant_name(),
            "Status",
            "the log line is the variant name, never the peer's labels"
        );
    }

    /// `parse_options` takes any `socket=` value verbatim, so these are all
    /// reachable from a PAM config. A path with no final component gives
    /// nothing to `unlinkat` or to `fstatat`, so it must be refused before
    /// any directory is opened.
    #[test]
    fn socket_dir_refuses_a_path_with_no_usable_file_name() {
        for p in ["/", "/run/user/0/..", "", "/run/user/0/."] {
            assert!(
                SocketDir::open(Path::new(p), me()).is_none(),
                "socket={p} has no file name to address"
            );
        }
    }

    /// The length bound keeps `collection=` from bloating a syslog line or a
    /// path; the boundary itself must be exactly `MAX_COLLECTION_LEN`.
    #[test]
    fn a_collection_longer_than_the_maximum_falls_back_to_the_default() {
        let at_max = "a".repeat(MAX_COLLECTION_LEN);
        assert!(collection_is_valid(&at_max));
        assert_eq!(
            parse_options(&[format!("collection={at_max}")]).collection,
            at_max
        );
        let over = "a".repeat(MAX_COLLECTION_LEN + 1);
        assert!(!collection_is_valid(&over));
        assert_eq!(
            parse_options(&[format!("collection={over}")]).collection,
            "default"
        );
    }

    /// `target_for` composes the user lookup with the vault-directory choice.
    /// A name that does not resolve must yield nothing at all: a target
    /// rooted at a bogus `/run/user/<uid>` would send root off to unlink and
    /// connect inside a path chosen by whatever put that name in the config.
    #[test]
    fn target_for_refuses_a_user_that_does_not_resolve() {
        let opts = parse_options(&[]);
        assert!(target_for("definitely-not-a-user-9f2c", &opts).is_none());
    }

    #[test]
    fn target_for_uses_the_vault_dir_override_and_the_users_runtime_dir() {
        let user = std::env::var("USER").expect("USER set");
        let t = target_for(&user, &parse_options(&[])).expect("current user resolves");
        assert_eq!(t.uid, me());
        assert!(
            t.vault_dir.ends_with(DEFAULT_VAULT_SUBDIR),
            "{}",
            t.vault_dir.display()
        );
        assert_eq!(
            t.sock,
            socket_path_for_runtime_dir(Path::new(&format!("/run/user/{}", me())))
        );

        let t = target_for(&user, &parse_options(&["vault_dir=/srv/vaults".into()]))
            .expect("current user resolves");
        assert_eq!(t.vault_dir, PathBuf::from("/srv/vaults"));

        // `socket=` is a test affordance, honoured only below root. This
        // suite does not run as root, but say so rather than assume it.
        if effective_uid() != 0 {
            let t = target_for(&user, &parse_options(&["socket=/tmp/harness.sock".into()]))
                .expect("current user resolves");
            assert_eq!(t.sock, PathBuf::from("/tmp/harness.sock"));
            assert_eq!(t.uid, effective_uid());
        }
    }

    // -----------------------------------------------------------------
    // Hook decisions
    //
    // `hooks.rs` only exists in the `--features pam` cdylib, so nothing below
    // can go through libpam. What is tested here is what the hooks decide:
    // the order of the checks, which paths clear the stashed password, and
    // which paths are allowed to spend a derivation or a connect. Everything
    // is real — a real `SocketDir` over a real directory, a real vault file, a
    // real `Budget`, a real listener. The only injected parts are the two
    // things the hook resolves through the `PamHandle`: the target user, and
    // starting the daemon.
    // -----------------------------------------------------------------

    fn args(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| (*s).to_string()).collect()
    }

    /// A target pointing at a runtime directory and a vault directory the
    /// test controls, owned by whoever is running the test.
    fn target_at(sock: PathBuf, vault_dir: &Path) -> Target {
        Target {
            sock,
            uid: me(),
            vault_dir: vault_dir.to_path_buf(),
        }
    }

    /// A `resolve_target` that must never be called.
    fn no_target_lookup(_: &Options) -> Option<Target> {
        panic!("the target must not be resolved on this path");
    }

    /// A `start_daemon` that must never be called.
    fn no_start(_: &Budget) -> bool {
        panic!("the daemon must not be started on this path");
    }

    /// A listener that is bound but never accepts, so a test can assert
    /// afterwards that nothing connected to it.
    fn idle_listener(sock: &Path) -> UnixListener {
        let l = UnixListener::bind(sock).unwrap();
        l.set_nonblocking(true).unwrap();
        l
    }

    fn nobody_connected(l: &UnixListener) {
        match l.accept() {
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            other => panic!("something connected to the control socket: {other:?}"),
        }
    }

    /// A vault directory with a usable `default.vault`, plus a private runtime
    /// directory to put the socket in.
    fn session_fixture() -> (tempfile::TempDir, PathBuf, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let vault = private_dir(dir.path(), "vault");
        write_vault(&vault, "default", header_with(LOGIN_KDF, SALT));
        let rt = private_dir(dir.path(), "secret-manager");
        let sock = rt.join("control.sock");
        (dir, vault, sock)
    }

    /// The stash `authenticate` leaves behind is a login password sitting in
    /// PAM data. Every path out of `open_session` has to clear it; the only
    /// exception is the path that found nothing stashed in the first place.
    #[test]
    fn every_session_exit_path_clears_the_stashed_password() {
        use SessionOutcome::*;
        for outcome in [
            NoTarget,
            RefusedSocketDir,
            NoVaultHeader,
            BudgetSpent,
            NoCallBudget,
            Attempted,
            Failed,
            ConnectNotStale,
            Started(StartOutcome::NoStartBudget),
            Started(StartOutcome::StaleSocketStuck),
            Started(StartOutcome::NoUser),
            Started(StartOutcome::NotRetried {
                waited: false,
                revalidated: None,
            }),
            Started(StartOutcome::NotRetried {
                waited: true,
                revalidated: Some(false),
            }),
            Started(StartOutcome::RetryBudgetSpent),
            Started(StartOutcome::NoRetryCallBudget),
            Started(StartOutcome::Retried),
        ] {
            assert!(
                outcome.clears_stash(),
                "{outcome:?} would leave the login password in PAM data"
            );
        }
        assert!(
            !SessionOutcome::NoPassword.clears_stash(),
            "there is nothing stashed to clear on this path"
        );
    }

    /// No stash means `authenticate` never ran, or ran without a token. The
    /// hook must stop immediately: no NSS lookup, no directory opened as root.
    #[test]
    fn a_session_with_no_stashed_password_does_nothing_at_all() {
        let outcome =
            open_session_decision(None, &[], &full_budget(), &no_target_lookup, &no_start);
        assert_eq!(outcome, SessionOutcome::NoPassword);
        assert!(!outcome.clears_stash());
    }

    #[test]
    fn a_session_whose_target_does_not_resolve_clears_the_stash() {
        let outcome =
            open_session_decision(Some("hunter2"), &[], &full_budget(), &|_| None, &no_start);
        assert_eq!(outcome, SessionOutcome::NoTarget);
        assert!(outcome.clears_stash());
    }

    /// `SocketDir::open` is the gate on the user's own runtime directory. A
    /// refusal there means root must not touch anything under that path — and
    /// the stash still has to go.
    #[test]
    fn a_session_refusing_the_runtime_directory_clears_the_stash() {
        let (dir, vault, _) = session_fixture();
        let hostile = dir.path().join("world-writable");
        std::fs::create_dir(&hostile).unwrap();
        std::fs::set_permissions(&hostile, std::fs::Permissions::from_mode(0o777)).unwrap();
        let sock = hostile.join("control.sock");
        let outcome = open_session_decision(
            Some("hunter2"),
            &[],
            &full_budget(),
            &|_| Some(target_at(sock.clone(), &vault)),
            &no_start,
        );
        assert_eq!(outcome, SessionOutcome::RefusedSocketDir);
        assert!(outcome.clears_stash());
    }

    /// No vault file means there is no salt and no KDF to derive under, so
    /// there is nothing to send and nothing to start a daemon for.
    #[test]
    fn a_session_with_an_unreadable_vault_header_clears_the_stash() {
        let dir = tempfile::tempdir().unwrap();
        let empty = private_dir(dir.path(), "vault");
        let rt = private_dir(dir.path(), "secret-manager");
        let sock = rt.join("control.sock");
        let outcome = open_session_decision(
            Some("hunter2"),
            &[],
            &full_budget(),
            &|_| Some(target_at(sock.clone(), &empty)),
            &no_start,
        );
        assert_eq!(outcome, SessionOutcome::NoVaultHeader);
        assert!(outcome.clears_stash());
    }

    /// The ordinary case: the daemon is already listening, so one connect and
    /// one derivation are all it takes, and the daemon receives the key rather
    /// than the password.
    #[test]
    fn a_session_that_reaches_the_daemon_unlocks_on_the_first_connect() {
        let (_dir, vault, sock) = session_fixture();
        let server = fake_daemon(&sock);
        let outcome = open_session_decision(
            Some("hunter2"),
            &[],
            &full_budget(),
            &|_| Some(target_at(sock.clone(), &vault)),
            &no_start,
        );
        assert_eq!(outcome, SessionOutcome::Attempted);
        assert!(outcome.clears_stash());
        let expected = crypto::derive_key(b"hunter2", &SALT, LOGIN_KDF).unwrap();
        match server.join().unwrap() {
            Request::UnlockWithKey { collection, key } => {
                assert_eq!(collection, "default");
                assert_eq!(&*key, expected.as_bytes());
            }
            ref other => panic!("expected UnlockWithKey, got {}", other.variant_name()),
        }
    }

    /// A transport reset mid-unlock is retried once: the first connection is
    /// dropped unanswered (a daemon restart landing mid-call), the second is
    /// served, and the key is still delivered.
    #[test]
    fn a_reset_mid_unlock_retries_once() {
        let (_dir, vault, sock) = session_fixture();
        let server = fake_daemon_flapping(&sock, 1);
        let outcome = open_session_decision(
            Some("hunter2"),
            &[],
            &full_budget(),
            &|_| Some(target_at(sock.clone(), &vault)),
            &no_start,
        );
        let req = server.join().unwrap();
        assert_eq!(outcome, SessionOutcome::Attempted);
        let expected = crypto::derive_key(b"hunter2", &SALT, LOGIN_KDF).unwrap();
        match req {
            Request::UnlockWithKey { collection, key } => {
                assert_eq!(collection, "default");
                assert_eq!(&*key, expected.as_bytes());
            }
            ref other => panic!("expected UnlockWithKey, got {}", other.variant_name()),
        }
    }

    /// Dropping root is a decision, and only root facing a foreign target
    /// takes it: anything else is already where it needs to be, or cannot
    /// get there.
    #[test]
    fn privilege_drop_only_root_facing_a_foreign_target() {
        assert!(privileges_to_drop(0, 1000));
        assert!(!privileges_to_drop(0, 0));
        assert!(!privileges_to_drop(1000, 1000));
        assert!(!privileges_to_drop(1000, 0));
    }

    /// The drop itself, isolated from the test runner by a fork: whatever
    /// uid runs the suite, the child lands on the target and the parent
    /// keeps its own.
    #[test]
    fn dropping_privileges_lands_on_the_target_uid() {
        let me = unsafe { libc::getuid() };
        // A target the child can always name: root drops to the overflow
        // uid, anyone else drops nowhere.
        let target = if me == 0 { 65534 } else { me };
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed");
        if pid == 0 {
            let ok = drop_privileges_for_socket(target);
            let landed = unsafe { libc::geteuid() } == target;
            unsafe { libc::_exit(i32::from(!(ok && landed))) };
        }
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        assert!(
            libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
            "child did not land on uid {target}"
        );
    }

    /// One retry, not a loop: two resets in a row mean the failure is not a
    /// restart landing in the window, so the second one is returned as-is and
    /// no third connection is ever made.
    #[test]
    fn a_second_reset_is_a_failure_not_another_retry() {
        let (_dir, vault, sock) = session_fixture();
        let listener = UnixListener::bind(&sock).unwrap();
        listener.set_nonblocking(true).unwrap();
        let accepts = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counting = std::sync::Arc::clone(&accepts);
        let server = std::thread::spawn(move || {
            for _ in 0..2 {
                let (mut stream, _) = accept_one(&listener, "unlock attempt");
                counting.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let _ = read_frame_sync(&mut stream);
                drop(stream);
            }
        });
        let outcome = open_session_decision(
            Some("hunter2"),
            &[],
            &full_budget(),
            &|_| Some(target_at(sock.clone(), &vault)),
            &no_start,
        );
        server.join().unwrap();
        assert_eq!(outcome, SessionOutcome::Failed);
        assert!(outcome.clears_stash());
        assert_eq!(
            accepts.load(std::sync::atomic::Ordering::SeqCst),
            2,
            "exactly the first attempt plus one retry"
        );
    }

    /// The retry's budget gate comes before its log and its connect: a budget
    /// that dies during the first derivation still pays for that derivation
    /// (Argon2 is not interruptible) but never starts a second connection.
    #[test]
    fn a_reset_with_no_retry_budget_makes_no_second_connection() {
        let (_dir, vault, sock) = session_fixture();
        // Fastest of a few runs, so a cold first allocation does not inflate
        // the estimate: overestimating `d` is what would leave budget over.
        let one_derivation = || {
            (0..3)
                .map(|_| {
                    let start = Instant::now();
                    crypto::derive_key(b"calibrate", &SALT, LOGIN_KDF).unwrap();
                    start.elapsed()
                })
                .min()
                .unwrap()
        };
        one_derivation();
        let d = one_derivation();
        let budget = Budget::new(d / 2);

        let listener = UnixListener::bind(&sock).unwrap();
        listener.set_nonblocking(true).unwrap();
        let accepts = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counting = std::sync::Arc::clone(&accepts);
        let server = std::thread::spawn(move || {
            let (mut first, _) = accept_one(&listener, "first connection");
            counting.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let _ = read_frame_sync(&mut first);
            drop(first);
            // A buggy retry would arrive promptly (one derivation, no sleep);
            // a short poll catches it without paying the full hang guard.
            let start = Instant::now();
            while start.elapsed() < Duration::from_millis(800) {
                match listener.accept() {
                    Ok((mut second, _)) => {
                        counting.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        let _ = read_frame_sync(&mut second);
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(ACCEPT_POLL);
                    }
                    Err(e) => panic!("second accept failed: {e}"),
                }
            }
        });
        let outcome = open_session_decision(
            Some("hunter2"),
            &[],
            &budget,
            &|_| Some(target_at(sock.clone(), &vault)),
            &no_start,
        );
        server.join().unwrap();
        assert_eq!(
            outcome,
            SessionOutcome::NoCallBudget,
            "the spent retry budget must stop before the second connect \
             (one derivation took {d:?})"
        );
        assert!(outcome.clears_stash());
        assert_eq!(
            accepts.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "the retry must not connect a second time"
        );
    }

    /// A timeout is deterministic, not a vanished peer: the server took the
    /// request and never answered, so retrying would only spend login budget
    /// re-proving the stall.
    #[test]
    fn a_timeout_mid_unlock_is_not_retried() {
        let (_dir, vault, sock) = session_fixture();
        let listener = UnixListener::bind(&sock).unwrap();
        listener.set_nonblocking(true).unwrap();
        let accepts = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counting = std::sync::Arc::clone(&accepts);
        let server = std::thread::spawn(move || {
            let (mut stream, _) = accept_one(&listener, "only connection");
            counting.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let _ = read_frame_sync(&mut stream);
            std::thread::sleep(CALL_BUDGET + Duration::from_secs(1));
            drop(stream);
        });
        let start = Instant::now();
        let outcome = open_session_decision(
            Some("hunter2"),
            &[],
            &full_budget(),
            &|_| Some(target_at(sock.clone(), &vault)),
            &no_start,
        );
        server.join().unwrap();
        assert_eq!(outcome, SessionOutcome::Failed);
        assert!(outcome.clears_stash());
        assert_eq!(
            accepts.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "a timeout must not be retried"
        );
        assert!(
            start.elapsed() < CALL_BUDGET + ACCEPT_TIMEOUT + Duration::from_secs(2),
            "took {elapsed:?}",
            elapsed = start.elapsed()
        );
    }

    /// Only a vanished peer is worth one retry. Refused, timed out, would-block
    /// and malformed are deterministic; a connect wrapper never is.
    #[test]
    fn retryable_reset_only_retries_a_vanished_peer() {
        use std::io::ErrorKind::*;
        for kind in [ConnectionReset, BrokenPipe, UnexpectedEof] {
            assert!(
                retryable_reset(&ProtocolError::Io(std::io::Error::new(kind, "gone"))),
                "{kind:?} must retry"
            );
        }
        for kind in [TimedOut, ConnectionRefused, WouldBlock, InvalidData] {
            assert!(
                !retryable_reset(&ProtocolError::Io(std::io::Error::new(kind, "no"))),
                "{kind:?} must not retry"
            );
        }
        assert!(
            !retryable_reset(&ProtocolError::Connect(std::io::Error::new(
                ConnectionReset,
                "connect"
            ))),
            "a Connect wrapper is a start decision, never a reset retry"
        );
    }

    /// Arm order: a reset first does not swallow a connect decision. Drop the
    /// first connection (reset, worth one retry), then refuse the retry, and
    /// the refused retry must route to the daemon-start path — a `Started`
    /// variant, never `Failed`. This pins the Finding-2 routing.
    #[test]
    fn a_connect_after_a_reset_still_starts_the_daemon() {
        let (_dir, vault, sock) = session_fixture();
        let listener = UnixListener::bind(&sock).unwrap();
        listener.set_nonblocking(true).unwrap();
        let server = std::thread::spawn(move || {
            let (mut first, _) = accept_one(&listener, "first connection");
            let _ = read_frame_sync(&mut first);
            drop(first);
            // The retry must see a refused connect, not another listener:
            // dropping with the file left behind makes the next connect
            // refused, which proves nobody is behind the socket. The client's
            // re-derivation lands after this drop, so the race is not close.
            drop(listener);
        });
        let outcome = open_session_decision(
            Some("hunter2"),
            &[],
            &full_budget(),
            &|_| Some(target_at(sock.clone(), &vault)),
            &|_| true,
        );
        server.join().unwrap();
        assert!(
            matches!(outcome, SessionOutcome::Started(_)),
            "a Connect after a reset must route to start, got {outcome:?}"
        );
        assert!(outcome.clears_stash());
    }

    /// `auto_start=no` is a switch on unlinking and `systemctl` running as
    /// root. A connect failure must not talk itself past it.
    #[test]
    fn auto_start_off_never_starts_the_daemon() {
        let (_dir, vault, sock) = session_fixture();
        let outcome = open_session_decision(
            Some("hunter2"),
            &args(&["auto_start=no"]),
            &full_budget(),
            &|_| Some(target_at(sock.clone(), &vault)),
            &no_start,
        );
        assert_eq!(outcome, SessionOutcome::Failed);
        assert!(outcome.clears_stash());
    }

    /// Only an errno that proves nobody is behind the socket may lead to a
    /// start. A name that is not a socket at all is refused by `connect_path`
    /// with `InvalidInput`, which proves nothing of the sort.
    #[test]
    fn a_connect_error_that_does_not_prove_the_daemon_is_gone_starts_nothing() {
        let (_dir, vault, sock) = session_fixture();
        std::fs::write(&sock, b"not a socket").unwrap();
        let outcome = open_session_decision(
            Some("hunter2"),
            &[],
            &full_budget(),
            &|_| Some(target_at(sock.clone(), &vault)),
            &no_start,
        );
        assert_eq!(outcome, SessionOutcome::ConnectNotStale);
        assert!(outcome.clears_stash());
        assert!(
            sock.exists(),
            "a name that is not a socket must not be unlinked"
        );
    }

    /// A stale socket that cannot be removed means the daemon could not bind
    /// it either, so it is not started.
    #[test]
    fn a_stale_socket_that_cannot_be_removed_stops_the_session_start() {
        let (dir, vault, sock) = session_fixture();
        let rt = sock.parent().unwrap().to_path_buf();
        // Bind and drop: the inode stays, so a connect is refused.
        drop(UnixListener::bind(&sock).unwrap());
        // Owned and private, so `SocketDir::open` accepts it, but not writable
        // by us, so `unlinkat` fails.
        std::fs::set_permissions(&rt, std::fs::Permissions::from_mode(0o500)).unwrap();
        let outcome = open_session_decision(
            Some("hunter2"),
            &[],
            &full_budget(),
            &|_| Some(target_at(sock.clone(), &vault)),
            &no_start,
        );
        std::fs::set_permissions(&rt, std::fs::Permissions::from_mode(0o700)).unwrap();
        drop(dir);
        assert_eq!(
            outcome,
            SessionOutcome::Started(StartOutcome::StaleSocketStuck)
        );
        assert!(outcome.clears_stash());
    }

    /// Without a user name there is nothing to hand `systemctl --machine=`,
    /// and the hook does not go on to wait or retry either.
    #[test]
    fn a_session_with_no_user_name_starts_nothing_and_retries_nothing() {
        let (_dir, vault, sock) = session_fixture();
        let outcome = open_session_decision(
            Some("hunter2"),
            &[],
            &full_budget(),
            &|_| Some(target_at(sock.clone(), &vault)),
            &|_| false,
        );
        assert_eq!(outcome, SessionOutcome::Started(StartOutcome::NoUser));
        assert!(outcome.clears_stash());
    }

    // The retry unlock is the second time root connects into a directory the
    // logging-in user controls, and the daemon-start window is exactly when
    // they could have changed it. It runs only if `waited && revalidate()`,
    // and the four tests below are the four combinations.

    /// waited = true, revalidate = true: the only combination that retries.
    #[test]
    fn the_retry_runs_when_the_socket_appeared_and_the_directory_still_checks_out() {
        let (_dir, vault, sock) = session_fixture();
        let started: std::sync::Mutex<Option<std::thread::JoinHandle<Request>>> =
            std::sync::Mutex::new(None);
        let outcome = open_session_decision(
            Some("hunter2"),
            &[],
            &full_budget(),
            &|_| Some(target_at(sock.clone(), &vault)),
            &|_| {
                *started.lock().unwrap() = Some(fake_daemon(&sock));
                true
            },
        );
        assert_eq!(outcome, SessionOutcome::Started(StartOutcome::Retried));
        assert!(outcome.clears_stash());
        let server = started.lock().unwrap().take().expect("the daemon started");
        let expected = crypto::derive_key(b"hunter2", &SALT, LOGIN_KDF).unwrap();
        match server.join().unwrap() {
            Request::UnlockWithKey { collection, key } => {
                assert_eq!(collection, "default");
                assert_eq!(&*key, expected.as_bytes());
            }
            ref other => panic!("expected UnlockWithKey, got {}", other.variant_name()),
        }
    }

    /// waited = false, directory fine: no retry, and `revalidate` is not even
    /// consulted — `revalidated: None` is what records that.
    #[test]
    fn no_retry_when_the_socket_never_appeared() {
        let (_dir, vault, sock) = session_fixture();
        let outcome = open_session_decision(
            Some("hunter2"),
            &[],
            &Budget::new(Duration::from_millis(400)),
            &|_| Some(target_at(sock.clone(), &vault)),
            &|_| true,
        );
        assert_eq!(
            outcome,
            SessionOutcome::Started(StartOutcome::NotRetried {
                waited: false,
                revalidated: None,
            })
        );
        assert!(outcome.clears_stash());
    }

    /// waited = false, directory *not* fine: still no retry, and still no
    /// `revalidate` call. If the wait were not short-circuiting, this would
    /// come back as `Some(false)` rather than `None`.
    #[test]
    fn no_retry_and_no_revalidation_when_the_socket_never_appeared() {
        let (dir, vault, sock) = session_fixture();
        let rt = sock.parent().unwrap().to_path_buf();
        let outcome = open_session_decision(
            Some("hunter2"),
            &[],
            &Budget::new(Duration::from_millis(400)),
            &|_| Some(target_at(sock.clone(), &vault)),
            &|_| {
                std::fs::set_permissions(&rt, std::fs::Permissions::from_mode(0o777)).unwrap();
                true
            },
        );
        std::fs::set_permissions(
            sock.parent().unwrap(),
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        drop(dir);
        assert_eq!(
            outcome,
            SessionOutcome::Started(StartOutcome::NotRetried {
                waited: false,
                revalidated: None,
            }),
            "revalidate must not be consulted when the wait timed out"
        );
    }

    /// waited = true, revalidate = false: the socket turned up, but the
    /// directory it is in was opened to other local users while the daemon was
    /// starting. Root must not connect into it, and nothing may be sent.
    #[test]
    fn no_retry_when_the_directory_was_opened_up_during_the_start_window() {
        let (dir, vault, sock) = session_fixture();
        let rt = sock.parent().unwrap().to_path_buf();
        let listener = std::sync::Mutex::new(None);
        let outcome = open_session_decision(
            Some("hunter2"),
            &[],
            &full_budget(),
            &|_| Some(target_at(sock.clone(), &vault)),
            &|_| {
                *listener.lock().unwrap() = Some(idle_listener(&sock));
                std::fs::set_permissions(&rt, std::fs::Permissions::from_mode(0o777)).unwrap();
                true
            },
        );
        nobody_connected(listener.lock().unwrap().as_ref().expect("bound"));
        std::fs::set_permissions(
            sock.parent().unwrap(),
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        drop(dir);
        assert_eq!(
            outcome,
            SessionOutcome::Started(StartOutcome::NotRetried {
                waited: true,
                revalidated: Some(false),
            })
        );
        assert!(outcome.clears_stash());
    }

    /// A spent budget must stop the session before Argon2, before any connect,
    /// and it must still clear the stash.
    ///
    /// The variant it stops at is `NoVaultHeader`, not `BudgetSpent`: the
    /// header read consults the same budget and refuses first. The later
    /// budget guards in the hook are therefore defence in depth — see
    /// `SessionOutcome::BudgetSpent`.
    #[test]
    fn a_spent_session_budget_starts_no_derivation_and_no_call() {
        let (_dir, vault, sock) = session_fixture();
        let listener = idle_listener(&sock);
        let start = Instant::now();
        let outcome = open_session_decision(
            Some("hunter2"),
            &[],
            &Budget::new(Duration::ZERO),
            &|_| Some(target_at(sock.clone(), &vault)),
            &no_start,
        );
        let elapsed = start.elapsed();
        nobody_connected(&listener);
        assert_eq!(outcome, SessionOutcome::NoVaultHeader);
        assert!(outcome.clears_stash());
        assert!(
            elapsed < Duration::from_millis(200),
            "no Argon2 may run on a spent budget: took {elapsed:?}"
        );
    }

    // ----- chauthtok -----

    /// `PAM_PRELIM_CHECK` is the stack asking whether the change *could* work.
    /// Nothing may be read, derived or sent on that pass — the resolver below
    /// panics if it is reached, so returning at all is the assertion.
    #[test]
    fn a_prelim_check_returns_before_doing_any_work() {
        let (_dir, vault, sock) = session_fixture();
        let listener = idle_listener(&sock);
        let start = Instant::now();
        let outcome = chauthtok_decision(
            PAM_PRELIM_CHECK,
            Some("old-pw"),
            Some("new-pw"),
            &args(&["definitely-not-an-option"]),
            &full_budget(),
            &no_target_lookup,
        );
        let elapsed = start.elapsed();
        let _ = &vault;
        nobody_connected(&listener);
        assert_eq!(outcome, ChauthtokOutcome::Prelim);
        assert!(
            elapsed < Duration::from_millis(50),
            "the prelim pass must do nothing: took {elapsed:?}"
        );
    }

    /// Only that one bit short-circuits: the update pass, and any other flag
    /// libpam sets alongside it, must go on to do the work.
    #[test]
    fn other_chauthtok_flags_do_not_short_circuit() {
        // PAM_UPDATE_AUTHTOK and PAM_CHANGE_EXPIRED_AUTHTOK.
        for flags in [0, 0x2000, 0x1] {
            assert_eq!(
                chauthtok_decision(flags, None, None, &[], &full_budget(), &no_target_lookup),
                ChauthtokOutcome::Missing("old and new passwords"),
                "flags {flags:#x} must not be read as a prelim check"
            );
        }
        assert_eq!(
            chauthtok_decision(
                PAM_PRELIM_CHECK | 0x2000,
                None,
                None,
                &[],
                &full_budget(),
                &no_target_lookup
            ),
            ChauthtokOutcome::Prelim
        );
    }

    /// A password change with a password missing is refused before the vault
    /// file is opened: the resolver panics if it is reached.
    #[test]
    fn a_missing_old_or_new_password_is_refused_without_touching_the_vault() {
        for (old, new, missing) in [
            (None, None, "old and new passwords"),
            (None, Some("new-pw"), "the old password"),
            (Some("old-pw"), None, "the new password"),
        ] {
            assert_eq!(
                chauthtok_decision(0, old, new, &[], &full_budget(), &no_target_lookup),
                ChauthtokOutcome::Missing(missing),
                "old={old:?} new={new:?}"
            );
        }
    }

    #[test]
    fn a_password_change_whose_target_does_not_resolve_stops() {
        assert_eq!(
            chauthtok_decision(
                0,
                Some("old-pw"),
                Some("new-pw"),
                &[],
                &full_budget(),
                &|_| None
            ),
            ChauthtokOutcome::NoTarget
        );
    }

    #[test]
    fn a_password_change_refuses_an_untrusted_runtime_directory() {
        let (dir, vault, _) = session_fixture();
        let hostile = dir.path().join("world-writable");
        std::fs::create_dir(&hostile).unwrap();
        std::fs::set_permissions(&hostile, std::fs::Permissions::from_mode(0o777)).unwrap();
        let sock = hostile.join("control.sock");
        assert_eq!(
            chauthtok_decision(
                0,
                Some("old-pw"),
                Some("new-pw"),
                &[],
                &full_budget(),
                &|_| { Some(target_at(sock.clone(), &vault)) }
            ),
            ChauthtokOutcome::RefusedSocketDir
        );
    }

    #[test]
    fn a_password_change_without_a_vault_header_stops() {
        let dir = tempfile::tempdir().unwrap();
        let empty = private_dir(dir.path(), "vault");
        let rt = private_dir(dir.path(), "secret-manager");
        let sock = rt.join("control.sock");
        assert_eq!(
            chauthtok_decision(
                0,
                Some("old-pw"),
                Some("new-pw"),
                &[],
                &full_budget(),
                &|_| { Some(target_at(sock.clone(), &empty)) }
            ),
            ChauthtokOutcome::NoVaultHeader
        );
    }

    /// The whole password hook: both keys derived locally, the old one under
    /// the header's own salt and the new one under a fresh salt, and only keys
    /// on the wire.
    #[test]
    fn a_password_change_sends_both_locally_derived_keys() {
        let (_dir, vault, sock) = session_fixture();
        let server = fake_daemon(&sock);
        let outcome = chauthtok_decision(
            0,
            Some("old-pw"),
            Some("new-pw"),
            &[],
            &full_budget(),
            &|_| Some(target_at(sock.clone(), &vault)),
        );
        assert_eq!(outcome, ChauthtokOutcome::Sent);
        let expected_old = crypto::derive_key(b"old-pw", &SALT, LOGIN_KDF).unwrap();
        match server.join().unwrap() {
            Request::ChangeKey {
                collection,
                old_key,
                new_salt,
                new_kdf,
                new_key,
            } => {
                assert_eq!(collection, "default");
                assert_eq!(&*old_key, expected_old.as_bytes());
                assert_ne!(new_salt, SALT, "the new key needs a fresh salt");
                assert_eq!(new_kdf, LOGIN_KDF);
                let expected_new = crypto::derive_key(b"new-pw", &new_salt, LOGIN_KDF).unwrap();
                assert_eq!(&*new_key, expected_new.as_bytes());
            }
            ref other => panic!("expected ChangeKey, got {}", other.variant_name()),
        }
    }

    #[test]
    fn a_password_change_that_cannot_reach_the_daemon_reports_it() {
        let (_dir, vault, sock) = session_fixture();
        assert_eq!(
            chauthtok_decision(
                0,
                Some("old-pw"),
                Some("new-pw"),
                &[],
                &full_budget(),
                &|_| { Some(target_at(sock.clone(), &vault)) }
            ),
            ChauthtokOutcome::SendFailed
        );
    }

    /// Argon2 is not interruptible, so the budget can only be checked
    /// *between* derivations — and `chauthtok` runs two. A budget that dies
    /// during the second one must abandon the change rather than send it: the
    /// socket below has nothing listening, so a send would come back as
    /// `SendFailed` and a request that never left would not.
    ///
    /// Hitting that window means picking a total in `(d, 2d)` where `d` is one
    /// derivation. `d` is measured rather than guessed, and re-measured for
    /// each attempt, because a loaded machine moves it: an attempt whose first
    /// derivation overran the whole budget stops one step earlier, at
    /// `NoRequest`. Either way nothing is sent, which every attempt asserts.
    #[test]
    fn a_budget_that_dies_between_the_derivations_sends_nothing() {
        let (_dir, vault, sock) = session_fixture();
        // The fastest of a few runs, so a cold first allocation of the Argon2
        // block does not inflate the estimate: overestimating `d` is the one
        // error that would put the whole pair *inside* the budget.
        let one_derivation = || {
            (0..3)
                .map(|_| {
                    let start = Instant::now();
                    crypto::derive_key(b"calibrate", &SALT, LOGIN_KDF).unwrap();
                    start.elapsed()
                })
                .min()
                .unwrap()
        };
        one_derivation();
        let mut hit = false;
        for _ in 0..8 {
            let d = one_derivation();
            let outcome = chauthtok_decision(
                0,
                Some("old-pw"),
                Some("new-pw"),
                &[],
                &Budget::new(d + d / 3),
                &|_| Some(target_at(sock.clone(), &vault)),
            );
            match outcome {
                // The window was hit: both derivations ran, the request was
                // built, and the spent budget stopped it before the socket.
                ChauthtokOutcome::BudgetSpent => hit = true,
                // The first derivation alone outran the budget, so the second
                // was never started. Still nothing sent.
                ChauthtokOutcome::NoRequest => {}
                other => panic!(
                    "a spent budget must not reach the socket, got {other:?} \
                     (one derivation took {d:?})"
                ),
            }
            if hit {
                break;
            }
        }
        assert!(
            hit,
            "the budget never expired between the two derivations in 8 attempts"
        );
    }

    // ----- authenticate -----

    /// `authenticate` stashes what PAM already collected and never prompts.
    /// The three cases are distinguished because they are logged differently
    /// and only one of them leaves a password behind to clear.
    #[test]
    fn authenticate_stashes_only_a_token_it_was_actually_given() {
        assert_eq!(
            authenticate_decision(Ok(Some("hunter2"))),
            AuthOutcome::Stash
        );
        assert_eq!(authenticate_decision(Ok(None)), AuthOutcome::NoToken);
        assert_eq!(
            authenticate_decision(Err("PAM_AUTHTOK_ERR")),
            AuthOutcome::Unavailable
        );
        // An empty token is still a token: PAM collected it, so it is stashed
        // and `open_session` derives from it like any other.
        assert_eq!(authenticate_decision(Ok(Some(""))), AuthOutcome::Stash);
    }

    /// `socket=` is taken verbatim from the PAM config, so it may be a bare
    /// name with no directory component. There is then nothing to open,
    /// validate or hold — and nothing a symlink swap could redirect — so
    /// `SocketDir` keeps the name exactly as given and lets the connect fail
    /// with the real errno, rather than refusing or inventing a directory.
    #[test]
    fn socket_dir_accepts_a_bare_name_with_no_directory_to_hold() {
        let sd = SocketDir::open(Path::new("control.sock"), me()).expect("that is a file name");
        assert!(!sd.is_open(), "there is no parent directory to hold open");
        assert_eq!(sd.socket_path(), Path::new("control.sock"));
        assert_eq!(
            sd.connect_path().expect("nothing to check without a dirfd"),
            Path::new("control.sock"),
            "no dirfd means no /proc/self/fd rewrite"
        );
    }

    /// A vault file whose header is cut short must be refused, not read
    /// short: the prefix says how many bytes the header occupies, and a file
    /// that ends before that is either truncated or a decoy. Reading what is
    /// there and deriving from it would aim the login at an attacker-chosen
    /// salt.
    #[test]
    fn refuses_a_vault_file_whose_header_is_truncated() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_vault(dir.path(), "default", header_with(LOGIN_KDF, SALT));
        let full = std::fs::read(&path).unwrap();
        assert!(
            full.len() > format::PREFIX_LEN + 1,
            "the fixture must have a header to truncate"
        );
        // Long enough for the prefix (so the length is read and believed),
        // far too short for the header it announces.
        std::fs::write(&path, &full[..format::PREFIX_LEN + 1]).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            vault_header(dir.path(), "default", me(), &full_budget()),
            None
        );
    }

    /// `derive` exists to be non-panicking: it is called as root inside a
    /// login, with parameters that came off disk. Argon2 rejecting them must
    /// produce `None` and a log line, never an unwind through the C boundary.
    #[test]
    fn derive_reports_parameters_argon2_rejects_instead_of_panicking() {
        let unusable = KdfParams {
            m_cost_kib: 0,
            t_cost: 0,
            p_cost: 0,
        };
        assert!(
            crypto::derive_key(b"pw", &SALT, unusable).is_err(),
            "the fixture must be parameters Argon2 refuses"
        );
        assert!(derive("pw", &SALT, unusable, &full_budget()).is_none());
    }
}
