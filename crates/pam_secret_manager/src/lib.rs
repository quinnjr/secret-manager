//! PAM module that unlocks the secret-manager vault at login.
//!
//! * `auth`: copy the password PAM already collected into module data. Never prompts.
//! * `session`: start the user's daemon if needed and send `Unlock`.
//! * `password`: forward old/new passwords so the vault follows `passwd`.
//!
//! Every failure is logged to syslog and returns `PAM_SUCCESS`; a broken vault
//! must never block login. Options: `collection=<id>` (default `default`),
//! `auto_start=no`, `socket=<path>` (tests only).

use control_protocol::{Request, Response, Zeroizing, call, socket_path_for_runtime_dir};
use pamsm::{Pam, PamData, PamError, PamFlags, PamLibExt, PamServiceModule, pam_module};
use std::ffi::CString;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

const DATA_KEY: &str = "secret_manager_password";
/// `PAM_PRELIM_CHECK` from <security/pam_modules.h>; pamsm does not expose it.
const PAM_PRELIM_CHECK: i32 = 0x4000;
const START_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone)]
struct Password(Zeroizing<String>);

impl PamData for Password {}

#[derive(Debug, PartialEq, Eq)]
pub struct Options {
    pub collection: String,
    pub auto_start: bool,
    pub socket: Option<PathBuf>,
}

pub fn parse_options(args: &[String]) -> Options {
    let mut opts = Options {
        collection: "default".into(),
        auto_start: true,
        socket: None,
    };
    for arg in args {
        match arg.split_once('=') {
            Some(("collection", v)) => opts.collection = v.to_string(),
            Some(("auto_start", v)) => opts.auto_start = !matches!(v, "no" | "false" | "0"),
            Some(("socket", v)) => opts.socket = Some(PathBuf::from(v)),
            _ => log(&format!("ignoring unknown option '{arg}'")),
        }
    }
    opts
}

fn log(msg: &str) {
    if let Ok(text) = CString::new(format!("pam_secret_manager: {msg}")) {
        // SAFETY: "%s" is a valid format with exactly one C-string argument that outlives the call.
        unsafe {
            libc::syslog(
                libc::LOG_WARNING | libc::LOG_AUTHPRIV,
                c"%s".as_ptr(),
                text.as_ptr(),
            )
        };
    }
}

fn uid_of(user: &str) -> Option<u32> {
    let name = CString::new(user).ok()?;
    // SAFETY: passwd is plain data; zeroed is a valid initial value.
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut buf = vec![0u8; 16384];
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: every pointer is valid for the duration of the call and `buf` outlives `pwd`'s use.
    let rc = unsafe {
        libc::getpwnam_r(
            name.as_ptr(),
            &mut pwd,
            buf.as_mut_ptr() as *mut libc::c_char,
            buf.len(),
            &mut result,
        )
    };
    if rc != 0 || result.is_null() {
        return None;
    }
    Some(pwd.pw_uid)
}

fn user_name(pamh: &Pam) -> Option<String> {
    pamh.get_user(None)
        .ok()
        .flatten()
        .map(|u| u.to_string_lossy().into_owned())
}

fn socket_for(pamh: &Pam, opts: &Options) -> Option<PathBuf> {
    if let Some(s) = &opts.socket {
        return Some(s.clone());
    }
    let uid = uid_of(&user_name(pamh)?)?;
    Some(socket_path_for_runtime_dir(Path::new(&format!(
        "/run/user/{uid}"
    ))))
}

fn start_daemon(user: &str) {
    let result = std::process::Command::new("systemctl")
        .args([
            "--user",
            &format!("--machine={user}@.host"),
            "start",
            "secret-manager.service",
        ])
        .status();
    match result {
        Ok(s) if s.success() => {}
        Ok(s) => log(&format!("systemctl exited with {s}")),
        Err(e) => log(&format!("cannot run systemctl: {e}")),
    }
}

fn wait_for(path: &Path, timeout: Duration) -> bool {
    let start = Instant::now();
    while start.elapsed() < timeout {
        if path.exists() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    path.exists()
}

fn send(sock: &Path, req: Request, what: &str) {
    match call(sock, &req) {
        Ok(Response::Ok) => {}
        Ok(Response::Error(e)) => log(&format!("{what} failed: {e}")),
        Ok(_) => {}
        Err(e) => log(&format!("{what}: {e}")),
    }
}

struct PamSecretManager;

impl PamServiceModule for PamSecretManager {
    fn authenticate(pamh: Pam, _flags: PamFlags, _args: Vec<String>) -> PamError {
        match pamh.get_cached_authtok() {
            Ok(Some(tok)) => {
                let password = Password(Zeroizing::new(tok.to_string_lossy().into_owned()));
                // SAFETY: DATA_KEY is only ever paired with `Password` in send_data/retrieve_data.
                if let Err(e) = unsafe { pamh.send_data(DATA_KEY, password) } {
                    log(&format!("cannot stash password: {e}"));
                }
            }
            Ok(None) => log("no authentication token available; nothing to unlock later"),
            Err(e) => log(&format!("cannot read authentication token: {e}")),
        }
        PamError::SUCCESS
    }

    fn open_session(pamh: Pam, _flags: PamFlags, args: Vec<String>) -> PamError {
        let opts = parse_options(&args);
        // SAFETY: same type as stored under DATA_KEY in `authenticate`.
        let Ok(Password(password)) = (unsafe { pamh.retrieve_data::<Password>(DATA_KEY) }) else {
            return PamError::SUCCESS;
        };
        let Some(sock) = socket_for(&pamh, &opts) else {
            log("cannot determine the control socket path");
            return PamError::SUCCESS;
        };
        if !sock.exists() && opts.auto_start {
            if let Some(user) = user_name(&pamh) {
                start_daemon(&user);
            }
            if !wait_for(&sock, START_TIMEOUT) {
                log("daemon did not start in time; vault stays locked");
                return PamError::SUCCESS;
            }
        }
        send(
            &sock,
            Request::Unlock {
                collection: opts.collection,
                password,
            },
            "unlock",
        );
        PamError::SUCCESS
    }

    fn chauthtok(pamh: Pam, flags: PamFlags, args: Vec<String>) -> PamError {
        if flags.bits() & PAM_PRELIM_CHECK != 0 {
            return PamError::SUCCESS;
        }
        let opts = parse_options(&args);
        let (Ok(Some(old)), Ok(Some(new))) =
            (pamh.get_cached_oldauthtok(), pamh.get_cached_authtok())
        else {
            return PamError::SUCCESS;
        };
        let Some(sock) = socket_for(&pamh, &opts) else {
            return PamError::SUCCESS;
        };
        let req = Request::ChangePassword {
            collection: opts.collection,
            old: Zeroizing::new(old.to_string_lossy().into_owned()),
            new: Zeroizing::new(new.to_string_lossy().into_owned()),
        };
        send(&sock, req, "password change");
        PamError::SUCCESS
    }

    fn setcred(_: Pam, _: PamFlags, _: Vec<String>) -> PamError {
        PamError::SUCCESS
    }

    fn close_session(_: Pam, _: PamFlags, _: Vec<String>) -> PamError {
        PamError::SUCCESS
    }

    fn acct_mgmt(_: Pam, _: PamFlags, _: Vec<String>) -> PamError {
        PamError::SUCCESS
    }
}

pam_module!(PamSecretManager);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_options_with_defaults() {
        let o = parse_options(&[]);
        assert_eq!(
            o,
            Options {
                collection: "default".into(),
                auto_start: true,
                socket: None
            }
        );
        let o = parse_options(&[
            "collection=work".into(),
            "auto_start=no".into(),
            "socket=/tmp/s".into(),
            "bogus".into(),
        ]);
        assert_eq!(
            o,
            Options {
                collection: "work".into(),
                auto_start: false,
                socket: Some(PathBuf::from("/tmp/s"))
            }
        );
    }

    #[test]
    fn resolves_uid_of_current_user() {
        let user = std::env::var("USER").expect("USER set");
        // SAFETY: getuid has no preconditions.
        assert_eq!(uid_of(&user), Some(unsafe { libc::getuid() }));
        assert_eq!(uid_of("definitely-not-a-user-9f2c"), None);
    }
}
