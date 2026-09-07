//! The `pam_sm_*` entry points, and the only code in the crate that links
//! `libpam`.
//!
//! Everything they call lives in the parent module, which compiles and is
//! tested without `pamsm`. A plain `cargo test` therefore exercises the login
//! logic, while this file exists only in the `cdylib` PAM actually loads.

use super::{
    Budget, HOOK_BUDGET, Options, START_TIMEOUT, SocketDir, change_key_request, guard, log,
    log_transport, parse_options, stale_socket_action, start_after_clearing, start_daemon,
    target_for, try_send, unlock_by_key, vault_header, wait_for,
};
use crate::protocol::{ProtocolError, Zeroizing};
use pamsm::{Pam, PamData, PamError, PamFlags, PamLibExt, PamServiceModule, pam_module};

/// Ceiling for one control-socket call. The whole hook is bounded by
/// `HOOK_BUDGET`; this keeps a single stalled call from consuming all of it
/// while still shrinking as the budget does.
const CALL_BUDGET: std::time::Duration = std::time::Duration::from_secs(3);

const DATA_KEY: &str = "secret_manager_password";
/// Logged when the hook's overall deadline runs out. The login itself always
/// proceeds; only the vault work is abandoned.
const SPENT: &str = "took too long; abandoning the unlock so the login can proceed";
/// `PAM_PRELIM_CHECK` from <security/pam_modules.h>; pamsm does not expose it.
const PAM_PRELIM_CHECK: i32 = 0x4000;

#[derive(Clone)]
struct Password(Zeroizing<String>);

impl PamData for Password {}

fn user_name(pamh: &Pam) -> Option<String> {
    pamh.get_user(None)
        .ok()
        .flatten()
        .map(|u| u.to_string_lossy().into_owned())
}

fn target(pamh: &Pam, opts: &Options) -> Option<super::Target> {
    target_for(&user_name(pamh)?, opts)
}

/// Overwrites the stashed password with an empty string as soon as the module
/// is done with it, rather than leaving it in PAM data until `pam_end`.
fn clear_stashed_password(pamh: &Pam) {
    // SAFETY: DATA_KEY is only ever paired with `Password` in send_data/retrieve_data.
    if let Err(e) = unsafe { pamh.send_data(DATA_KEY, Password(Zeroizing::new(String::new()))) } {
        log(&format!("cannot clear the stashed password: {e}"));
    }
}

struct PamSecretManager;

impl PamServiceModule for PamSecretManager {
    fn authenticate(pamh: Pam, _flags: PamFlags, _args: Vec<String>) -> PamError {
        guard("authenticate", PamError::SUCCESS, || {
            match pamh.get_cached_authtok() {
                Ok(Some(tok)) => {
                    let password = Password(Zeroizing::new(tok.to_string_lossy().into_owned()));
                    // SAFETY: DATA_KEY is only ever paired with `Password`.
                    if let Err(e) = unsafe { pamh.send_data(DATA_KEY, password) } {
                        log(&format!("cannot stash password: {e}"));
                    }
                }
                Ok(None) => log("no authentication token available; nothing to unlock later"),
                Err(e) => log(&format!("cannot read authentication token: {e}")),
            }
            PamError::SUCCESS
        })
    }

    fn open_session(pamh: Pam, _flags: PamFlags, args: Vec<String>) -> PamError {
        guard("open_session", PamError::SUCCESS, || {
            // Every stage below is serial and attacker-influenced; without one
            // deadline over the lot they sum to half a minute of login latency
            // the user being logged in gets to choose.
            let budget = Budget::new(HOOK_BUDGET);
            let opts = parse_options(&args);
            // SAFETY: same type as stored under DATA_KEY in `authenticate`.
            let Ok(Password(password)) = (unsafe { pamh.retrieve_data::<Password>(DATA_KEY) })
            else {
                log("no stashed password for session; vault stays locked");
                return PamError::SUCCESS;
            };
            let Some(t) = target(&pamh, &opts) else {
                log("cannot determine the control socket path");
                clear_stashed_password(&pamh);
                return PamError::SUCCESS;
            };
            // The directory is held open from here on: every later unlink,
            // connect and re-check goes through this descriptor rather than
            // through a name the user can swap underneath root.
            let Some(mut dir) = SocketDir::open(&t.sock, t.uid) else {
                clear_stashed_password(&pamh);
                return PamError::SUCCESS;
            };
            // Salt and parameters come from the vault file itself, never from
            // whatever happens to answer the socket.
            let Some((salt, kdf)) = vault_header(&t.vault_dir, &opts.collection, t.uid) else {
                clear_stashed_password(&pamh);
                return PamError::SUCCESS;
            };
            if budget.remaining().is_none() {
                log(SPENT);
                clear_stashed_password(&pamh);
                return PamError::SUCCESS;
            }
            // A leftover socket from a crashed daemon looks exactly like a
            // running one, so only a failed connect is a usable test.
            let sock = dir.socket_path();
            match unlock_by_key(
                &sock,
                &opts.collection,
                t.uid,
                &password,
                &salt,
                kdf,
                match budget.capped(CALL_BUDGET) {
                    Some(left) => left,
                    None => {
                        log("no time left in the login budget; vault stays locked");
                        clear_stashed_password(&pamh);
                        return PamError::SUCCESS;
                    }
                },
            ) {
                Ok(()) => {}
                Err(ProtocolError::Connect(e)) if opts.auto_start => {
                    match stale_socket_action(e.kind()) {
                        Some(action) => {
                            log(&format!("cannot reach the daemon ({e}); starting it"));
                            match budget.capped(START_TIMEOUT) {
                                None => log(SPENT),
                                Some(_) if !start_after_clearing(&dir, action) => {}
                                Some(_) => {
                                    if let Some(user) = user_name(&pamh) {
                                        start_daemon(&user, &budget);
                                        // The runtime directory is re-checked:
                                        // the wait spans a window in which the
                                        // user could have replaced it.
                                        let waited = budget
                                            .capped(START_TIMEOUT)
                                            .is_some_and(|left| wait_for(&sock, left));
                                        if waited && dir.revalidate() {
                                            if budget.remaining().is_none() {
                                                log(SPENT);
                                            } else if let Some(left) = budget.capped(CALL_BUDGET) {
                                                if let Err(e) = unlock_by_key(
                                                    &dir.socket_path(),
                                                    &opts.collection,
                                                    t.uid,
                                                    &password,
                                                    &salt,
                                                    kdf,
                                                    left,
                                                ) {
                                                    log_transport("unlock", &e);
                                                }
                                            } else {
                                                log("no time left in the login budget");
                                            }
                                        } else {
                                            log("daemon did not start in time; vault stays locked");
                                        }
                                    }
                                }
                            }
                        }
                        None => log_transport("unlock", &ProtocolError::Connect(e)),
                    }
                }
                Err(e) => log_transport("unlock", &e),
            }
            drop(password);
            clear_stashed_password(&pamh);
            PamError::SUCCESS
        })
    }

    fn chauthtok(pamh: Pam, flags: PamFlags, args: Vec<String>) -> PamError {
        guard("chauthtok", PamError::SUCCESS, || {
            if flags.bits() & PAM_PRELIM_CHECK != 0 {
                return PamError::SUCCESS;
            }
            // Two Argon2 derivations plus a socket call, all serial: same
            // deadline as the session hook.
            let budget = Budget::new(HOOK_BUDGET);
            let opts = parse_options(&args);
            let old = pamh.get_cached_oldauthtok();
            let new = pamh.get_cached_authtok();
            let (Ok(Some(old)), Ok(Some(new))) = (&old, &new) else {
                let missing = match (matches!(old, Ok(Some(_))), matches!(new, Ok(Some(_)))) {
                    (false, false) => "old and new passwords",
                    (false, true) => "the old password",
                    _ => "the new password",
                };
                log(&format!(
                    "cannot forward the password change: {missing} unavailable"
                ));
                return PamError::SUCCESS;
            };
            let Some(t) = target(&pamh, &opts) else {
                log("cannot determine the control socket path");
                return PamError::SUCCESS;
            };
            let Some(dir) = SocketDir::open(&t.sock, t.uid) else {
                return PamError::SUCCESS;
            };
            let Some((salt, kdf)) = vault_header(&t.vault_dir, &opts.collection, t.uid) else {
                return PamError::SUCCESS;
            };
            let old = Zeroizing::new(old.to_string_lossy().into_owned());
            let new = Zeroizing::new(new.to_string_lossy().into_owned());
            let Some(req) = change_key_request(&opts.collection, &old, &new, &salt, kdf) else {
                return PamError::SUCCESS;
            };
            if budget.remaining().is_none() {
                log(SPENT);
                return PamError::SUCCESS;
            }
            match budget.capped(CALL_BUDGET) {
                Some(left) => {
                    if let Err(e) =
                        try_send(&dir.socket_path(), &req, t.uid, "password change", left)
                    {
                        log_transport("password change", &e);
                    }
                }
                None => log("no time left in the password-change budget"),
            }
            PamError::SUCCESS
        })
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
