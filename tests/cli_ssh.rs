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
    // A relative key path is not a passphrase request: the prompt must name an
    // absolute path, or a lookup could be steered at another key entirely.
    fx.sm()
        .current_dir(keys.path())
        .args(["ssh", "askpass", "Enter passphrase for \"id_test\": "])
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
