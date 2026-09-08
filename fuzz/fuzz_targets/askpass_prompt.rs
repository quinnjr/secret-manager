//! The prompt string OpenSSH hands to `SSH_ASKPASS`.
//!
//! `sm-askpass` is executed by `ssh`, `ssh-add` and `ssh-keygen` with the
//! dialog text as argv. Part of that text is attacker-chosen: the host-key
//! question embeds the destination string the user was talked into
//! connecting to, so a `ssh 'passphrase for key ...'` puts arbitrary content
//! inside a prompt whose *shape* decides whether this process releases a
//! stored passphrase or asks a yes/no question.
//!
//! Two classification errors matter, in opposite directions. A confirmation
//! misread as a passphrase request means a stored secret is looked up (and,
//! before the third audit's fix, decrypted) for a question the user was only
//! being asked to approve. A passphrase request misread as a confirmation
//! means an empty answer, which OpenSSH reads as "yes".
//!
//! The property asserted here is the one the whole askpass path rests on:
//! whatever `PathBuf` comes back is a *single-line, non-empty* path, and the
//! unquoted form — which has no delimiters and so could otherwise swallow
//! arbitrary text — is absolute. A quoted relative path is deliberately
//! allowed through (`ssh -i ./key` prints exactly that) and is resolved and
//! matched against the registered keys by `askpass`, so absoluteness is
//! asserted where the code actually promises it and not where it does not.
#![no_main]

use arbitrary::Unstructured;
use libfuzzer_sys::fuzz_target;
use secret_manager::fuzz_api::{classify_prompt, escape_control, passphrase_path, AskpassKind};

/// Everything a returned path must satisfy before anything is looked up.
fn check_path(p: &std::path::Path, prompt: &str) {
    let s = p.to_string_lossy();
    assert!(!s.is_empty(), "empty key path from {prompt:?}");
    // A key path is a filename. A line terminator in one means the prompt was
    // not written by OpenSSH, and would let a single dialog line describe two
    // keys — one shown, one used.
    assert!(
        !s.contains('\n') && !s.contains('\r'),
        "a line terminator reached the key path from {prompt:?}: {s:?}"
    );
    // Defence in depth: every site that shows this path escapes it first, and
    // that escaping has to survive whatever the prompt contained.
    let shown = escape_control(&s);
    assert!(
        !shown.chars().any(char::is_control),
        "the dialog would show a control character from {prompt:?}: {shown:?}"
    );
    // The unquoted `ssh-add` form is anchored on a leading `/`; a relative
    // path can only have come from a quoted form, which `askpass` resolves
    // against the cwd and checks against the registered keys before it
    // releases anything.
    if !prompt.contains('\'') && !prompt.contains('"') {
        assert!(
            p.is_absolute(),
            "an unquoted prompt yielded a relative path from {prompt:?}: {s:?}"
        );
    }
}

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);
    let Ok(tail) = smfuzz::hostile_string(&mut u) else {
        return;
    };

    // Prompts shaped like the real ones with a hostile payload spliced in,
    // alongside the raw hostile string: the mutator reaches the interesting
    // parsing states far faster from a well-formed prompt than from noise.
    let prompts = [
        tail.clone(),
        format!("Enter passphrase for key '{tail}': "),
        format!("Enter passphrase for \"{tail}\": "),
        format!("Enter passphrase for {tail}: "),
        format!("Enter passphrase for {tail} (will confirm each use): "),
        format!("Enter passphrase for key '/home/u/.ssh/{tail}': "),
        format!("The authenticity of host '{tail}' can't be established.\nED25519 key fingerprint is SHA256:x.\nAre you sure you want to continue connecting (yes/no/[fingerprint])? "),
        format!("Allow use of key {tail}?"),
        format!("Confirm user presence for key ED25519 {tail}"),
    ];

    // The env var is set by `ssh` itself, so only its real values and a
    // hostile one matter.
    let envs = [None, Some("confirm"), Some("none"), Some(tail.as_str())];

    for prompt in &prompts {
        // Called directly: `askpass` is not the only caller, so the contract
        // has to hold at the function, not at one call site.
        if let Some(p) = passphrase_path(prompt) {
            check_path(&p, prompt);
        }
        for env in envs {
            match classify_prompt(prompt, env) {
                AskpassKind::Passphrase(p) => {
                    // The explicit tag from `ssh` is authoritative and can
                    // never be overridden by the prompt text.
                    assert_ne!(
                        env,
                        Some("confirm"),
                        "SSH_ASKPASS_PROMPT=confirm was overridden by {prompt:?}"
                    );
                    check_path(&p, prompt);
                }
                AskpassKind::Confirm | AskpassKind::Other => {}
            }
        }
        // The tag `ssh` sets is authoritative on its own, whatever the text
        // it accompanies claims to be.
        assert_eq!(
            classify_prompt(prompt, Some("confirm")),
            AskpassKind::Confirm,
            "{prompt:?}"
        );
        // A passphrase question is one line. Anything multi-line is some
        // other dialog that merely quotes one — the host-key question with a
        // forged destination is exactly that — and must never be answered
        // with a stored secret.
        if prompt.contains('\n') {
            assert!(
                !matches!(classify_prompt(prompt, None), AskpassKind::Passphrase(_)),
                "a multi-line dialog was read as a passphrase request: {prompt:?}"
            );
        }
    }
});
