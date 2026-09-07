mod common;

use common::Fixture;
use predicates::prelude::*;
use std::path::{Path, PathBuf};

fn make_key(dir: &Path, name: &str, passphrase: &str) -> PathBuf {
    let path = dir.join(name);
    let status = std::process::Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", passphrase, "-C", "test", "-f"])
        .arg(&path)
        .status()
        .unwrap();
    assert!(status.success());
    path
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn add_list_askpass_remove() {
    let fx = Fixture::start().await;
    fx.unlock_default().await;
    let keys = tempfile::tempdir().unwrap();
    let key = make_key(keys.path(), "id_test", "pass123");
    let plain = make_key(keys.path(), "id_plain", "");

    fx.sm()
        .args(["ssh", "add"])
        .arg(&key)
        .write_stdin("pass123\n")
        .assert()
        .success();
    fx.sm()
        .args(["ssh", "add", "--no-passphrase"])
        .arg(&plain)
        .assert()
        .success();
    fx.sm()
        .args(["ssh", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains(format!(
            "{}\tpassphrase: stored",
            key.display()
        )))
        .stdout(predicate::str::contains(format!(
            "{}\tpassphrase: none",
            plain.display()
        )));

    let ssh_prompt = format!("Enter passphrase for key '{}': ", key.display());
    fx.sm()
        .args(["ssh", "askpass", &ssh_prompt])
        .env("FAKE_CONFIRM", "yes")
        .assert()
        .success()
        .stdout("pass123\n");
    let keygen_prompt = format!("Enter passphrase for \"{}\": ", key.display());
    fx.sm()
        .args(["ssh", "askpass", &keygen_prompt])
        .env("FAKE_CONFIRM", "yes")
        .assert()
        .success()
        .stdout("pass123\n");
    // `ssh -i ./key` prints the identity file exactly as given, so a relative
    // path is resolved against this process's cwd -- and only answered when it
    // canonicalizes to an already registered key.
    fx.sm()
        .current_dir(keys.path())
        .args(["ssh", "askpass", "Enter passphrase for \"id_test\": "])
        .env("FAKE_CONFIRM", "yes")
        .env("FAKE_PIN", "typed")
        .assert()
        .success()
        .stdout("pass123\n");
    // A relative path that resolves to nothing registered is not answered from
    // the vault; the user types it.
    fx.sm()
        .current_dir(keys.path())
        .args(["ssh", "askpass", "Enter passphrase for \"id_unknown\": "])
        .env("FAKE_CONFIRM", "yes")
        .env("FAKE_PIN", "typed")
        .assert()
        .success()
        .stdout("typed\n");

    fx.sm()
        .args(["ssh", "add", "--no-passphrase"])
        .arg(&key)
        .assert()
        .success();
    let out = fx
        .sm()
        .args(["ssh", "list"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    assert_eq!(
        String::from_utf8_lossy(&out).matches("id_test").count(),
        1,
        "re-adding replaces, never duplicates"
    );

    fx.sm().args(["ssh", "remove"]).arg(&key).assert().success();
    fx.sm().args(["ssh", "remove"]).arg(&key).assert().code(1);
    fx.sm()
        .args(["ssh", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("id_test").not());
    fx.sm()
        .args(["ssh", "add", "/nonexistent/key"])
        .assert()
        .code(2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn remove_forgets_a_key_whose_file_is_gone() {
    let fx = Fixture::start().await;
    fx.unlock_default().await;
    let keys = tempfile::tempdir().unwrap();
    let key = make_key(keys.path(), "id_deleted", "pass123");

    fx.sm()
        .args(["ssh", "add"])
        .arg(&key)
        .write_stdin("pass123\n")
        .assert()
        .success();

    std::fs::remove_file(&key).unwrap();
    std::fs::remove_file(format!("{}.pub", key.display())).unwrap();

    fx.sm()
        .current_dir(keys.path())
        .args(["ssh", "remove", "id_deleted"])
        .assert()
        .success();
    fx.sm()
        .args(["ssh", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("id_deleted").not());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn remove_forgets_a_key_added_through_a_symlinked_dir_after_the_file_is_gone() {
    let fx = Fixture::start().await;
    fx.unlock_default().await;
    let base = tempfile::tempdir().unwrap();
    let real = base.path().join("real");
    std::fs::create_dir(&real).unwrap();
    let link = base.path().join("link");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    let key = make_key(&link, "id_test", "pass123");

    fx.sm()
        .args(["ssh", "add"])
        .arg(&key)
        .write_stdin("pass123\n")
        .assert()
        .success();

    std::fs::remove_file(&key).unwrap();
    std::fs::remove_file(format!("{}.pub", key.display())).unwrap();

    fx.sm().args(["ssh", "remove"]).arg(&key).assert().success();
    fx.sm()
        .args(["ssh", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("id_test").not());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ssh_keygen_uses_sm_askpass_symlink() {
    let fx = Fixture::start().await;
    fx.unlock_default().await;
    let keys = tempfile::tempdir().unwrap();
    let key = make_key(keys.path(), "id_e2e", "pass123");
    fx.sm()
        .args(["ssh", "add"])
        .arg(&key)
        .write_stdin("pass123\n")
        .assert()
        .success();

    let link = keys.path().join("sm-askpass");
    std::os::unix::fs::symlink(env!("CARGO_BIN_EXE_secret-manager"), &link).unwrap();
    let mut cmd = std::process::Command::new("ssh-keygen");
    cmd.args(["-y", "-f"])
        .arg(&key)
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("HOME", fx.data_dir.path())
        .env("SSH_ASKPASS", &link)
        .env("SSH_ASKPASS_REQUIRE", "force")
        .env("FAKE_CONFIRM", "yes")
        .env("DISPLAY", ":0")
        .stdin(std::process::Stdio::null());
    for (k, v) in fx.envs() {
        cmd.env(k, v);
    }
    let out = cmd.output().unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let pubkey = std::fs::read_to_string(format!("{}.pub", key.display())).unwrap();
    assert_eq!(
        String::from_utf8_lossy(&out.stdout)
            .split_whitespace()
            .nth(1),
        pubkey.split_whitespace().nth(1)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn askpass_falls_back_to_pinentry() {
    let fx = Fixture::start().await;
    fx.sm()
        .args([
            "ssh",
            "askpass",
            "Enter passphrase for key '/no/such/key': ",
        ])
        .env("FAKE_PIN", "typed")
        .assert()
        .success()
        .stdout("typed\n");
    fx.sm()
        .args(["ssh", "askpass", "Enter PIN for authenticator:"])
        .env("FAKE_PIN", "typed")
        .assert()
        .success()
        .stdout("typed\n");
    fx.sm()
        .args([
            "ssh",
            "askpass",
            "Are you sure you want to continue connecting (yes/no/[fingerprint])?",
        ])
        .env("SSH_ASKPASS_PROMPT", "confirm")
        .env("FAKE_CONFIRM", "yes")
        .assert()
        .success()
        .stdout("yes\n");
    fx.sm()
        .args(["ssh", "askpass", "continue? (yes/no)"])
        .env("FAKE_CONFIRM", "no")
        .assert()
        .success()
        .stdout("no\n");
    fx.sm()
        .args([
            "ssh",
            "askpass",
            "Enter passphrase for key '/no/such/key': ",
        ])
        .env_remove("FAKE_PIN")
        .assert()
        .code(1);
    fx.sm()
        .args([
            "ssh",
            "askpass",
            "Enter passphrase for key '/no/such/key': ",
        ])
        .env("DBUS_SESSION_BUS_ADDRESS", "unix:path=/nonexistent")
        .env("FAKE_PIN", "offline")
        .assert()
        .success()
        .stdout("offline\n");
}

/// HIGH 1: `sm ssh remove` must not report success while a copy of the
/// passphrase survives in a collection whose unlock prompt was not answered.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn remove_refuses_a_partial_unlock() {
    let fx = Fixture::start().await;
    fx.unlock_default().await;
    let keys = tempfile::tempdir().unwrap();
    let key = make_key(keys.path(), "id_two_places", "pass123");
    let canonical = std::fs::canonicalize(&key).unwrap();

    fx.sm()
        .args(["ssh", "add"])
        .arg(&key)
        .write_stdin("pass123\n")
        .assert()
        .success();

    // A second collection with a different password holding the same key.
    let dir = fx.data_dir.path().join("secret-manager");
    let mut extra = secret_manager::vault::Vault::create(
        &dir.join("extra.vault"),
        "Extra",
        b"other-password",
        secret_manager::vault::crypto::KdfParams::FAST_FOR_TESTS,
    )
    .unwrap();
    extra
        .insert_item(
            "SSH key",
            std::collections::BTreeMap::from([
                (
                    "xdg:schema".to_string(),
                    "org.secret-manager.ssh".to_string(),
                ),
                ("path".to_string(), canonical.to_string_lossy().into_owned()),
                ("has_passphrase".to_string(), "true".to_string()),
            ]),
            b"pass123".to_vec(),
            "text/plain",
            false,
        )
        .unwrap();
    drop(extra);
    secret_manager::protocol::call(
        &fx.control_socket(),
        &secret_manager::protocol::Request::Reload,
    )
    .unwrap();
    fx.lock_default().await;

    fx.sm()
        .args(["ssh", "remove"])
        .arg(&key)
        .assert()
        .code(1)
        .stderr(predicate::str::contains("nothing was deleted"));
    fx.sm()
        .args(["ssh", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("id_two_places"));
}

/// MEDIUM 3: releasing a stored passphrase needs an explicit confirmation,
/// because `ssh` only calls the helper when there is no terminal to ask on.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn askpass_requires_confirmation_before_releasing_a_passphrase() {
    let fx = Fixture::start().await;
    fx.unlock_default().await;
    let keys = tempfile::tempdir().unwrap();
    let key = make_key(keys.path(), "id_consent", "pass123");
    fx.sm()
        .args(["ssh", "add"])
        .arg(&key)
        .write_stdin("pass123\n")
        .assert()
        .success();
    let prompt = format!("Enter passphrase for key '{}': ", key.display());

    // Declined: exits as cancelled and prints nothing.
    let out = fx
        .sm()
        .args(["ssh", "askpass", &prompt])
        .env("FAKE_CONFIRM", "no")
        .env_remove("FAKE_PIN")
        .assert()
        .code(1)
        .get_output()
        .stdout
        .clone();
    assert!(out.is_empty(), "declined confirmation leaked output");

    // Accepted: the passphrase is released.
    fx.sm()
        .args(["ssh", "askpass", &prompt])
        .env("FAKE_CONFIRM", "yes")
        .assert()
        .success()
        .stdout("pass123\n");

    // Escape hatch for unattended use.
    fx.sm()
        .args(["ssh", "askpass", &prompt])
        .env("SM_ASKPASS_NO_CONFIRM", "1")
        .env("FAKE_CONFIRM", "no")
        .assert()
        .success()
        .stdout("pass123\n");
}

/// HIGH 2 end to end: an OpenSSH host-key question whose destination string
/// embeds a passphrase prompt must never be answered with a passphrase.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn host_key_question_embedding_a_passphrase_prompt_is_a_confirmation() {
    let fx = Fixture::start().await;
    fx.unlock_default().await;
    let keys = tempfile::tempdir().unwrap();
    let key = make_key(keys.path(), "id_target", "pass123");
    fx.sm()
        .args(["ssh", "add"])
        .arg(&key)
        .write_stdin("pass123\n")
        .assert()
        .success();

    let hostile = format!(
        "The authenticity of host 'Enter passphrase for key '{}': ' can't be established.\n\
         ED25519 key fingerprint is SHA256:xxx.\n\
         Are you sure you want to continue connecting (yes/no/[fingerprint])? ",
        key.display()
    );
    let out = fx
        .sm()
        .args(["ssh", "askpass", &hostile])
        .env("FAKE_CONFIRM", "no")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    assert_eq!(String::from_utf8_lossy(&out), "no\n");
}

/// LOW 2: an untagged confirmation question must not be answered with a typed
/// value, and an empty answer (which OpenSSH reads as "yes") is never printed.
///
/// Note what `no` on stdout with exit 0 means here, because the shape invites
/// the opposite reading: OpenSSH inspects the *content* of what the askpass
/// helper prints, not its exit status. `ssh_askpass()` collects the answer and
/// `ask_permission()` accepts it only when it is empty or `yes`; anything else
/// -- `no` included -- is a refusal. So printing `no` and exiting 0 is the
/// correct way to decline, and an EMPTY answer means YES. That is precisely
/// why the helper must never print an empty line: a cancelled or empty pinentry
/// box would otherwise read as the user approving the use of the key.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn untagged_question_is_confirmed_and_empty_answers_are_refused() {
    let fx = Fixture::start().await;
    fx.sm()
        .args(["ssh", "askpass", "Allow remote host to use this key?"])
        .env("FAKE_PIN", "typed")
        .env("FAKE_CONFIRM", "no")
        .assert()
        .success()
        .stdout("no\n");
    // A passphrase box that comes back empty is an error, not an empty line.
    let out = fx
        .sm()
        .args(["ssh", "askpass", "Enter PIN for authenticator:"])
        .env("FAKE_PIN", "")
        .assert()
        .code(1)
        .get_output()
        .stdout
        .clone();
    assert!(out.is_empty(), "an empty answer was printed: {out:?}");
}

/// HIGH 1: the consent dialog must name the key whose passphrase is about to
/// be released, not the (attacker-chosen) spelling the prompt used. A hostile
/// repo can steer `ssh -i` at a symlink through `core.sshCommand` or a
/// `.gitmodules` URL; the dialog naming the symlink while the production key's
/// passphrase is what gets released is consent to the wrong thing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_consent_dialog_names_the_real_key_behind_a_symlink() {
    let fx = Fixture::start().await;
    fx.unlock_default().await;
    let keys = tempfile::tempdir().unwrap();
    let key = make_key(keys.path(), "id_prod", "pass123");
    let real = std::fs::canonicalize(&key).unwrap();
    let link = keys.path().join("deploy_key");
    std::os::unix::fs::symlink(&real, &link).unwrap();

    fx.sm()
        .args(["ssh", "add"])
        .arg(&key)
        .write_stdin("pass123\n")
        .assert()
        .success();

    let before = fx.pinentry_log().len();
    fx.sm()
        .args([
            "ssh",
            "askpass",
            &format!("Enter passphrase for key '{}': ", link.display()),
        ])
        .env("FAKE_CONFIRM", "yes")
        .assert()
        .success()
        .stdout("pass123\n");

    let log = fx.pinentry_log();
    let dialog: String = log[before..]
        .lines()
        .filter(|l| l.starts_with("SETDESC"))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        dialog.contains(&real.display().to_string()),
        "the dialog must name the key being released: {dialog:?}"
    );
    assert!(
        !dialog.contains("deploy_key"),
        "the dialog named the symlink, not the key: {dialog:?}"
    );
}

/// HIGH 2: the lookup is what raises the master password prompt and unlocks
/// the collection for every client on the bus. Declining must not have done
/// any of that, so the question comes first.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn declining_does_not_unlock_the_collection() {
    let fx = Fixture::start().await;
    fx.unlock_default().await;
    let keys = tempfile::tempdir().unwrap();
    let key = make_key(keys.path(), "id_locked", "pass123");
    fx.sm()
        .args(["ssh", "add"])
        .arg(&key)
        .write_stdin("pass123\n")
        .assert()
        .success();
    fx.lock_default().await;

    // FAKE_PIN is set, so any unlock prompt raised here *would* succeed --
    // which is the point: the collection must stay locked because nothing
    // asked for it, not because the prompt failed.
    let out = fx
        .sm()
        .args([
            "ssh",
            "askpass",
            &format!("Enter passphrase for key '{}': ", key.display()),
        ])
        .env("FAKE_CONFIRM", "no")
        .assert()
        .code(1)
        .get_output()
        .stdout
        .clone();
    assert!(out.is_empty(), "declined confirmation leaked output");
    assert!(
        fx.daemon.state.lock().await.collections["default"].is_locked(),
        "a declined key use left the collection unlocked for every bus client"
    );

    // Approving still works, and only then may it unlock.
    fx.sm()
        .args([
            "ssh",
            "askpass",
            &format!("Enter passphrase for key '{}': ", key.display()),
        ])
        .env("FAKE_CONFIRM", "yes")
        .assert()
        .success()
        .stdout("pass123\n");
}

/// MEDIUM 1: `/usr/bin/ssh-add` prompts unquoted, with an optional suffix.
/// Against the old anchored regex every one of these classified as `Other`,
/// so the user was asked to type a passphrase sitting in the vault.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ssh_add_style_prompts_are_answered_from_the_vault() {
    let fx = Fixture::start().await;
    fx.unlock_default().await;
    let keys = tempfile::tempdir().unwrap();
    let key = make_key(keys.path(), "id_add", "pass123");
    fx.sm()
        .args(["ssh", "add"])
        .arg(&key)
        .write_stdin("pass123\n")
        .assert()
        .success();

    for prompt in [
        format!("Enter passphrase for {}: ", key.display()),
        format!(
            "Enter passphrase for {} (will confirm each use): ",
            key.display()
        ),
    ] {
        fx.sm()
            .args(["ssh", "askpass", &prompt])
            .env("FAKE_CONFIRM", "yes")
            .env("FAKE_PIN", "typed")
            .assert()
            .success()
            .stdout("pass123\n");
    }
}

/// LOW: `ssh` formats the identity file with `%.100s`, so a registered key
/// with a longer path is only ever named truncated. Match those by prefix.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_prompt_truncated_at_a_hundred_bytes_still_finds_the_key() {
    let fx = Fixture::start().await;
    fx.unlock_default().await;
    let base = tempfile::tempdir().unwrap();
    // Build a directory deep enough that the key's canonical path is well
    // past 100 bytes.
    let mut dir = std::fs::canonicalize(base.path()).unwrap();
    while dir.to_string_lossy().len() < 110 {
        dir = dir.join("dddddddddd");
    }
    std::fs::create_dir_all(&dir).unwrap();
    let key = make_key(&dir, "id_long", "pass123");
    let real = std::fs::canonicalize(&key).unwrap();
    let full = real.to_string_lossy().into_owned();
    assert!(full.len() > 100, "{full}");

    fx.sm()
        .args(["ssh", "add"])
        .arg(&key)
        .write_stdin("pass123\n")
        .assert()
        .success();

    let truncated = &full[..100];
    fx.sm()
        .args([
            "ssh",
            "askpass",
            &format!("Enter passphrase for key '{truncated}': "),
        ])
        .env("FAKE_CONFIRM", "yes")
        .env("FAKE_PIN", "typed")
        .assert()
        .success()
        .stdout("pass123\n");
}

/// MEDIUM 2: `sm ssh list` prints the `path` attribute, and attributes are
/// settable by any client on the session bus, so a row could be erased or
/// forged with `\r` and ANSI escapes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ssh_list_escapes_control_characters_in_the_path() {
    let fx = Fixture::start().await;
    fx.unlock_default().await;
    fx.sm()
        .args([
            "set",
            "xdg:schema=org.secret-manager.ssh",
            "path=/k\u{1b}[2K\rforged\tpassphrase: stored",
            "has_passphrase=true",
            "--label",
            "planted",
        ])
        .write_stdin("x")
        .assert()
        .success();
    let out = fx
        .sm()
        .args(["ssh", "list"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let text = String::from_utf8_lossy(&out).into_owned();
    assert!(
        !text.contains('\r') && !text.contains('\u{1b}'),
        "raw control characters reached stdout: {text:?}"
    );
    assert!(text.contains("\\x1b") && text.contains("\\x0d"), "{text:?}");
}

/// MEDIUM 2: any client on the bus can plant an item claiming a registered
/// key's `path`, and `SearchItems` is subset matching, so it matches too.
/// Picking one would mean answering ssh from an item an attacker chose.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn askpass_refuses_to_choose_between_two_items_claiming_one_key() {
    let fx = Fixture::start().await;
    fx.unlock_default().await;
    let keys = tempfile::tempdir().unwrap();
    let key = make_key(keys.path(), "id_ambiguous", "pass123");
    let real = std::fs::canonicalize(&key).unwrap();
    fx.sm()
        .args(["ssh", "add"])
        .arg(&key)
        .write_stdin("pass123\n")
        .assert()
        .success();
    // The extra attribute keeps this a separate item while still matching a
    // subset search on {xdg:schema, path}.
    fx.sm()
        .args([
            "set",
            "xdg:schema=org.secret-manager.ssh",
            &format!("path={}", real.display()),
            "has_passphrase=true",
            "planted=1",
            "--label",
            "planted",
        ])
        .write_stdin("attacker-chosen")
        .assert()
        .success();

    fx.sm()
        .args([
            "ssh",
            "askpass",
            &format!("Enter passphrase for key '{}': ", key.display()),
        ])
        .env("FAKE_CONFIRM", "yes")
        .env("FAKE_PIN", "typed")
        .assert()
        .success()
        // Neither stored secret is released; the user types the answer.
        .stdout("typed\n")
        .stderr(predicate::str::contains("refusing to choose"));
}

/// CRITICAL: a key registered with `--no-passphrase` stores an EMPTY secret so
/// `ssh list` can inventory it. `release_passphrase` guards on
/// `secret.is_empty()`; without it, `askpass` would print an empty line -- and
/// OpenSSH reads an empty answer as approval (see
/// `untagged_question_is_confirmed_and_empty_answers_are_refused`). So the
/// guard is what stops an empty stored secret being turned into a "yes". The
/// only correct behaviour is to fall through to the ordinary typed prompt.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn askpass_never_answers_from_a_key_registered_without_a_passphrase() {
    let fx = Fixture::start().await;
    fx.unlock_default().await;
    let keys = tempfile::tempdir().unwrap();
    let plain = make_key(keys.path(), "id_no_pass", "");

    fx.sm()
        .args(["ssh", "add", "--no-passphrase"])
        .arg(&plain)
        .assert()
        .success();

    let out = fx
        .sm()
        .args([
            "ssh",
            "askpass",
            &format!("Enter passphrase for key '{}': ", plain.display()),
        ])
        .env("FAKE_CONFIRM", "yes")
        .env("FAKE_PIN", "typed")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    assert_eq!(
        String::from_utf8_lossy(&out),
        "typed\n",
        "the empty stored secret was released as an answer"
    );
}

/// CRITICAL: any bus client -- or `sm set` with binary stdin -- can create an
/// item carrying the ssh schema, a registered key's `path` and
/// `has_passphrase=true` with a secret that is not valid UTF-8. That gate sits
/// *after* consent has been granted and after the collection has been
/// unlocked, so it is the last thing between a garbage secret and ssh's stdin.
/// It must fall through to the typed prompt, never emit lossy or truncated
/// bytes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn askpass_never_answers_from_a_secret_that_is_not_utf8() {
    let fx = Fixture::start().await;
    fx.unlock_default().await;
    let keys = tempfile::tempdir().unwrap();
    let key = make_key(keys.path(), "id_binary", "pass123");
    let real = std::fs::canonicalize(&key).unwrap();

    // Registered directly rather than through `ssh add`, so this is the single
    // item claiming the path and `release_passphrase` reaches the UTF-8 gate
    // instead of the ambiguity refusal.
    fx.sm()
        .args([
            "set",
            "xdg:schema=org.secret-manager.ssh",
            &format!("path={}", real.display()),
            "has_passphrase=true",
            "--label",
            "binary",
        ])
        .write_stdin(vec![0xffu8, 0xfe, 0x80, 0x41])
        .assert()
        .success();

    let out = fx
        .sm()
        .args([
            "ssh",
            "askpass",
            &format!("Enter passphrase for key '{}': ", key.display()),
        ])
        .env("FAKE_CONFIRM", "yes")
        .env("FAKE_PIN", "typed")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    assert_eq!(
        String::from_utf8_lossy(&out),
        "typed\n",
        "a non-UTF-8 stored secret reached ssh"
    );
}

/// WARNING: the approve-then-dismiss ordering, which
/// `declining_does_not_unlock_the_collection` does not cover. Consent is
/// granted, so the unlock is attempted -- and then the master password prompt
/// is dismissed. That must degrade to the ordinary typed prompt rather than
/// propagate an error out of `askpass` before the fallback is reached, and it
/// must leave the collection locked.
///
/// The daemon's pinentry cancels (`start_with_pin(None)`) while the CLI's own
/// answers `typed`, which is what separates "fell through to the fallback"
/// from "failed on the way there": both would otherwise exit 1.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_dismissed_unlock_after_consent_falls_back_to_a_typed_answer() {
    let fx = Fixture::start_with_pin(None).await;
    fx.unlock_default().await;
    let keys = tempfile::tempdir().unwrap();
    let key = make_key(keys.path(), "id_dismissed", "pass123");
    fx.sm()
        .args(["ssh", "add"])
        .arg(&key)
        .write_stdin("pass123\n")
        .assert()
        .success();
    fx.lock_default().await;

    let out = fx
        .sm()
        .args([
            "ssh",
            "askpass",
            &format!("Enter passphrase for key '{}': ", key.display()),
        ])
        .env("FAKE_CONFIRM", "yes")
        .env("FAKE_PIN", "typed")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    assert_eq!(
        String::from_utf8_lossy(&out),
        "typed\n",
        "a dismissed unlock did not fall through to the typed prompt"
    );
    assert!(
        fx.daemon.state.lock().await.collections["default"].is_locked(),
        "a dismissed master password prompt left the collection unlocked"
    );
}
