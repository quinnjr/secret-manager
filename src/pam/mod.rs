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
//! (see [`vault_header`]), which is opened `O_NOFOLLOW` and required to be
//! owned by the target user and not group- or world-writable. The most an
//! impostor daemon can learn is an Argon2id hash of the password under
//! parameters this module bounds on both sides (see
//! [`kdf_acceptable_for_login`]) — the same thing a thief of the vault file
//! would hold, not a reusable password.
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
    KdfParams, ProtocolError, Request, Response, SALT_LEN, Zeroizing, call_expecting_uid,
    socket_path_for_runtime_dir,
};
use std::ffi::CString;
use std::io::Read;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::{Path, PathBuf};
use std::process::{ExitStatus, Stdio};
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
            Some(("collection", v)) => opts.collection = v.to_string(),
            Some(("auto_start", v)) => opts.auto_start = !matches!(v, "no" | "false" | "0"),
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

/// Strips control characters (so a hostile string cannot forge syslog lines or
/// terminal escapes) and bounds the length of text that came from the daemon.
pub(crate) fn sanitize(text: &str) -> String {
    text.chars()
        .filter(|c| !c.is_control())
        .take(MAX_LOGGED_ERROR)
        .collect()
}

pub(crate) fn log(msg: &str) {
    let line = format!("pam_secret_manager: {msg}");
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

/// Root only touches `dir` (`<runtime>/secret-manager`) when it is a plain
/// directory owned by the target user. A symlink the user planted there
/// would otherwise redirect `remove_file` and `connect` elsewhere. Absent is
/// fine: there is nothing to follow yet.
fn runtime_subdir_is_safe(dir: &Path, uid: u32) -> bool {
    match std::fs::symlink_metadata(dir) {
        Ok(meta) => meta.file_type().is_dir() && meta.uid() == uid,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => true,
        Err(_) => false,
    }
}

/// [`runtime_subdir_is_safe`] for a socket path, with the refusal logged.
/// Checked again after `wait_for`, because the daemon-start window gives the
/// user time to replace the directory underneath us.
pub(crate) fn runtime_dir_ok(sock: &Path, uid: u32) -> bool {
    let Some(dir) = sock.parent() else {
        return true;
    };
    if runtime_subdir_is_safe(dir, uid) {
        return true;
    }
    log(&format!(
        "{} is not a directory owned by uid {uid}; refusing to use it",
        dir.display()
    ));
    false
}

/// The vault header supplies the KDF parameters, and it is not authenticated
/// until a successful decrypt. Refuse anything below the OWASP floor (19 MiB,
/// two passes), so a tampered header cannot ask for a cheap-to-crack hash of
/// the login password, and anything above the login ceiling, so it cannot
/// stall the login instead.
fn kdf_acceptable_for_login(kdf: &KdfParams) -> bool {
    const MIN_M_COST_KIB: u32 = 19 * 1024;
    const MIN_T_COST: u32 = 2;
    /// Below `KdfParams::MAX_T_COST`: 64 passes over 256 MiB is minutes of
    /// login latency, which is a denial of service, not a security margin.
    const MAX_T_COST: u32 = 8;
    const MAX_P_COST: u32 = 4;
    kdf.validate().is_ok()
        && kdf.m_cost_kib >= MIN_M_COST_KIB
        && kdf.t_cost >= MIN_T_COST
        && kdf.m_cost_kib <= KdfParams::MAX_M_COST_KIB
        && kdf.t_cost <= MAX_T_COST
        && kdf.p_cost <= MAX_P_COST
}

/// Opens `<vault_dir>/<collection>.vault` and returns the salt and KDF
/// parameters from its header, or `None` (already logged) if anything about
/// the file or the header is unsuitable.
///
/// The file belongs to `uid` but is read by root, so it is opened with
/// `O_NOFOLLOW` and the *open file* is then checked: owned by `uid`, and
/// writable by nobody else. Only the header prefix is read; the ciphertext
/// never enters this process.
pub(crate) fn vault_header(
    vault_dir: &Path,
    collection: &str,
    uid: u32,
) -> Option<([u8; SALT_LEN], KdfParams)> {
    let path = vault_dir.join(format!("{collection}.vault"));
    let shown = path.display().to_string();
    let mut file = match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
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

    let mut bytes = vec![0u8; format::PREFIX_LEN];
    if let Err(e) = file.read_exact(&mut bytes) {
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
    if let Err(e) = file.read_exact(&mut bytes[format::PREFIX_LEN..]) {
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
                    let _ = child.wait();
                    return Err(format!("timed out after {timeout:?}"));
                }
                std::thread::sleep(POLL_INTERVAL);
            }
            Err(e) => return Err(format!("cannot wait: {e}")),
        }
    }
}

fn systemctl_path() -> &'static Path {
    SYSTEMCTL_PATHS
        .iter()
        .map(Path::new)
        .find(|p| p.exists())
        .unwrap_or_else(|| Path::new(SYSTEMCTL_PATHS[0]))
}

pub(crate) fn start_daemon(user: &str) {
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
    match run_bounded(&mut cmd, START_TIMEOUT) {
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
) -> Result<(), ProtocolError> {
    match call_expecting_uid(sock, req, uid) {
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

fn derive(password: &str, salt: &[u8; SALT_LEN], kdf: KdfParams) -> Option<Key> {
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
pub(crate) fn unlock_by_key(
    sock: &Path,
    collection: &str,
    uid: u32,
    password: &str,
    salt: &[u8; SALT_LEN],
    kdf: KdfParams,
) -> Result<(), ProtocolError> {
    let Some(key) = derive(password, salt, kdf) else {
        return Ok(());
    };
    let req = Request::UnlockWithKey {
        collection: collection.to_string(),
        key: Zeroizing::new(*key.as_bytes()),
    };
    try_send(sock, &req, uid, "unlock")
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
    let old_key = derive(old, salt, kdf)?;
    let new_key = derive(new, &new_salt, kdf)?;
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
pub(crate) fn start_after_clearing(sock: &Path, action: StaleSocket) -> bool {
    if action == StaleSocket::LeaveAlone {
        return true;
    }
    match std::fs::remove_file(sock) {
        Ok(()) => true,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => true,
        Err(e) => {
            log(&format!(
                "cannot remove the stale socket {}: {}; not starting the daemon",
                sock.display(),
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

    /// Root must only touch `<runtime>/secret-manager` when it is a real
    /// directory owned by the target user: never a symlink the user planted.
    #[test]
    fn runtime_subdir_is_safe_only_for_an_owned_real_directory() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("secret-manager");
        std::fs::create_dir(&real).unwrap();
        assert!(runtime_subdir_is_safe(&real, me()));
        assert!(!runtime_subdir_is_safe(&real, me() ^ 1));
        let link = dir.path().join("linked");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert!(!runtime_subdir_is_safe(&link, me()));
        let file = dir.path().join("file");
        std::fs::write(&file, b"").unwrap();
        assert!(!runtime_subdir_is_safe(&file, me()));
        // Not existing yet is fine: nothing to follow.
        assert!(runtime_subdir_is_safe(&dir.path().join("absent"), me()));
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
        // The ceiling is exactly reachable.
        assert!(kdf_acceptable_for_login(&KdfParams {
            m_cost_kib: KdfParams::MAX_M_COST_KIB,
            t_cost: 8,
            p_cost: 4
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
        unlock_by_key(&sock, "work", me(), "hunter2", &SALT, LOGIN_KDF).expect("unlock");
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
        let err = unlock_by_key(&sock, "work", me(), "hunter2", &SALT, LOGIN_KDF)
            .expect_err("nothing is listening");
        assert!(matches!(err, ProtocolError::Connect(_)), "{err:?}");
    }

    #[test]
    fn reads_salt_and_kdf_from_the_vault_header() {
        let dir = tempfile::tempdir().unwrap();
        write_vault(dir.path(), "default", header_with(LOGIN_KDF, SALT));
        let (salt, kdf) = vault_header(dir.path(), "default", me()).expect("header readable");
        assert_eq!(salt, SALT);
        assert_eq!(kdf, LOGIN_KDF);
        // A collection with no vault file yields nothing, not a fallback.
        assert_eq!(vault_header(dir.path(), "absent", me()), None);
    }

    /// Root reads this file out of a user-owned tree: anything the group or
    /// world can rewrite could aim the derivation at a chosen salt.
    #[test]
    fn refuses_a_group_writable_vault_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_vault(dir.path(), "default", header_with(LOGIN_KDF, SALT));
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o660)).unwrap();
        assert_eq!(vault_header(dir.path(), "default", me()), None);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o606)).unwrap();
        assert_eq!(vault_header(dir.path(), "default", me()), None);
    }

    #[test]
    fn refuses_a_vault_file_owned_by_someone_else() {
        let dir = tempfile::tempdir().unwrap();
        write_vault(dir.path(), "default", header_with(LOGIN_KDF, SALT));
        assert_eq!(vault_header(dir.path(), "default", me() ^ 1), None);
    }

    /// O_NOFOLLOW: a symlink at `<collection>.vault` could point at a file
    /// the user does not own but root can read.
    #[test]
    fn refuses_a_symlinked_vault_file() {
        let dir = tempfile::tempdir().unwrap();
        let real = write_vault(dir.path(), "real", header_with(LOGIN_KDF, SALT));
        std::os::unix::fs::symlink(&real, dir.path().join("default.vault")).unwrap();
        assert_eq!(vault_header(dir.path(), "default", me()), None);
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
        assert_eq!(vault_header(dir.path(), "weak", me()), None);
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
        assert_eq!(vault_header(dir.path(), "huge", me()), None);
    }

    #[test]
    fn refuses_a_file_that_is_not_a_vault() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("default.vault");
        std::fs::write(&path, b"NOTAVAULT and then some").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(vault_header(dir.path(), "default", me()), None);
    }

    /// `ChangeKey` re-seals under a fresh salt, but keeps the header's
    /// parameters; the old key must still be the one that opens the vault.
    #[test]
    fn change_key_request_derives_both_keys_from_the_header_kdf() {
        let req = change_key_request("work", "old-pw", "new-pw", &SALT, LOGIN_KDF)
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
}
