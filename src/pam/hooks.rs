//! The `pam_sm_*` entry points, and the only code in the crate that links
//! `libpam`.
//!
//! There is deliberately no logic here. Each hook pulls its inputs out of the
//! `PamHandle`, hands them to the matching `*_decision` function in the parent
//! module, and turns the outcome back into a `PamError`. Everything that
//! decides anything — the order of the checks, the budget guards, whether the
//! session hook still has a stash to clear — lives in the parent module, which
//! compiles and is tested without `pamsm`, so a plain `cargo test` exercises
//! it. This file exists only in the `cdylib` PAM actually loads.

use super::{
    AuthOutcome, Budget, HOOK_BUDGET, Options, PAM_PRELIM_CHECK, Target, authenticate_decision,
    chauthtok_decision, guard, log, open_session_decision, start_daemon, target_for,
};
use crate::protocol::Zeroizing;
use pamsm::{Pam, PamData, PamError, PamFlags, PamLibExt, PamServiceModule, pam_module};
use std::panic::{AssertUnwindSafe, catch_unwind};

const DATA_KEY: &str = "secret_manager_password";

#[derive(Clone)]
struct Password(Zeroizing<String>);

impl PamData for Password {}

fn user_name(pamh: &Pam) -> Option<String> {
    pamh.get_user(None)
        .ok()
        .flatten()
        .map(|u| u.to_string_lossy().into_owned())
}

fn target(pamh: &Pam, opts: &Options) -> Option<Target> {
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

/// Clears the stash when it leaves scope, so a hook that returns *and* a hook
/// that panics both reach the clear.
///
/// `guard` catches the unwind and turns it into `PAM_SUCCESS`, which used to
/// mean the panic path returned to libpam with the login password still in PAM
/// data for the rest of the transaction. A destructor runs during that unwind;
/// the explicit call sites do not.
///
/// `armed` is what `SessionOutcome::clears_stash` answers: `open_session`
/// disarms it on the one path where there was nothing stashed to clear.
struct ClearStash<'a> {
    pamh: &'a Pam,
    armed: bool,
}

impl Drop for ClearStash<'_> {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        // A panic escaping a destructor that is itself running during an
        // unwind aborts the process — and the process here is `sshd`, `login`
        // or `passwd`. Swallow it: this is already the "something went wrong"
        // path, and there is nothing left to clean up after.
        let _ = catch_unwind(AssertUnwindSafe(|| clear_stashed_password(self.pamh)));
    }
}

struct PamSecretManager;

impl PamServiceModule for PamSecretManager {
    fn authenticate(pamh: Pam, _flags: PamFlags, _args: Vec<String>) -> PamError {
        guard("authenticate", PamError::SUCCESS, || {
            let cached = pamh.get_cached_authtok();
            let failure = cached.as_ref().err().map(|e| format!("{e}"));
            let token = cached
                .ok()
                .flatten()
                .map(|t| Zeroizing::new(t.to_string_lossy().into_owned()));
            let decision = authenticate_decision(match &failure {
                Some(e) => Err(e.as_str()),
                None => Ok(token.as_ref().map(|t| t.as_str())),
            });
            if let (AuthOutcome::Stash, Some(token)) = (decision, token) {
                // SAFETY: DATA_KEY is only ever paired with `Password`.
                if let Err(e) = unsafe { pamh.send_data(DATA_KEY, Password(token)) } {
                    log(&format!("cannot stash password: {e}"));
                }
            }
            PamError::SUCCESS
        })
    }

    fn open_session(pamh: Pam, _flags: PamFlags, args: Vec<String>) -> PamError {
        guard("open_session", PamError::SUCCESS, || {
            // Armed before anything that can panic, so the stash goes even if
            // one of the stages below unwinds into `guard`.
            let mut clear = ClearStash {
                pamh: &pamh,
                armed: true,
            };
            // Every stage below is serial and attacker-influenced; without one
            // deadline over the lot they sum to half a minute of login latency
            // the user being logged in gets to choose.
            let budget = Budget::new(HOOK_BUDGET);
            // SAFETY: same type as stored under DATA_KEY in `authenticate`.
            let stashed = unsafe { pamh.retrieve_data::<Password>(DATA_KEY) }.ok();
            let outcome = open_session_decision(
                stashed.as_ref().map(|Password(p)| p.as_str()),
                &args,
                &budget,
                &|opts| target(&pamh, opts),
                &|budget| match user_name(&pamh) {
                    Some(user) => {
                        start_daemon(&user, budget);
                        true
                    }
                    None => false,
                },
            );
            drop(stashed);
            clear.armed = outcome.clears_stash();
            PamError::SUCCESS
        })
    }

    fn chauthtok(pamh: Pam, flags: PamFlags, args: Vec<String>) -> PamError {
        guard("chauthtok", PamError::SUCCESS, || {
            // The password hook never reads the stash, so there is no
            // `clears_stash` question to answer: it clears on every exit. A
            // `passwd` transaction runs `auth` and `password` and never
            // `session`, so without this the login password the auth hook
            // stashed sits in PAM data until `pam_end`.
            let _clear = ClearStash {
                pamh: &pamh,
                armed: true,
            };
            // Two Argon2 derivations plus a socket call, all serial: same
            // deadline as the session hook. It is started before the prelim
            // check returns, which costs one `Instant::now()` and nothing else.
            let budget = Budget::new(HOOK_BUDGET);
            // libpam's item getters are pure reads, but a prelim pass is
            // defined to do nothing at all, so it does not touch the handle
            // either. `chauthtok_decision` checks the same bit and returns
            // before it looks at these.
            let owned = |r: Result<Option<&std::ffi::CStr>, PamError>| {
                r.ok()
                    .flatten()
                    .map(|s| Zeroizing::new(s.to_string_lossy().into_owned()))
            };
            let (old, new) = if flags.bits() & PAM_PRELIM_CHECK == 0 {
                (
                    owned(pamh.get_cached_oldauthtok()),
                    owned(pamh.get_cached_authtok()),
                )
            } else {
                (None, None)
            };
            chauthtok_decision(
                flags.bits(),
                old.as_ref().map(|s| s.as_str()),
                new.as_ref().map(|s| s.as_str()),
                &args,
                &budget,
                &|opts| target(&pamh, opts),
            );
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
