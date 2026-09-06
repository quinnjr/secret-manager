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
        .assert()
        .success()
        .stdout("pass123\n");
    let keygen_prompt = format!("Enter passphrase for \"{}\": ", key.display());
    fx.sm()
        .args(["ssh", "askpass", &keygen_prompt])
        .assert()
        .success()
        .stdout("pass123\n");
    fx.sm()
        .current_dir(keys.path())
        .args(["ssh", "askpass", "Enter passphrase for \"id_test\": "])
        .assert()
        .success()
        .stdout("pass123\n");

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
