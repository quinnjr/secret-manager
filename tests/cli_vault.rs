mod common;

use common::Fixture;
use predicates::prelude::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn status_unlock_lock_change_password() {
    let fx = Fixture::start().await;
    fx.sm()
        .arg("status")
        .assert()
        .success()
        .stdout(predicate::str::contains("default").and(predicate::str::contains("locked")));
    fx.sm()
        .arg("unlock")
        .write_stdin("wrong\n")
        .assert()
        .code(1)
        // The daemon deliberately does not say *why* it refused: a wrong key,
        // a damaged file and an absent collection are one message, so the
        // socket is not an existence oracle for collection names.
        .stderr(predicate::str::contains("cannot unlock that collection"));
    fx.sm().arg("unlock").write_stdin("pw\n").assert().success();
    fx.sm()
        .arg("status")
        .assert()
        .success()
        .stdout(predicate::str::contains("unlocked"));
    assert!(!fx.daemon.state.lock().await.collections["default"].is_locked());
    fx.sm().arg("lock").assert().success();
    assert!(fx.daemon.state.lock().await.collections["default"].is_locked());
    fx.sm()
        .args(["unlock", "--collection", "nope"])
        .write_stdin("pw\n")
        .assert()
        .code(1)
        .stderr(predicate::str::contains("no collection"));

    fx.sm()
        .arg("change-password")
        .write_stdin("pw\nnewpw\n")
        .assert()
        .success();
    fx.sm().arg("lock").assert().success();
    fx.sm().arg("unlock").write_stdin("pw\n").assert().code(1);
    fx.sm()
        .arg("unlock")
        .write_stdin("newpw\n")
        .assert()
        .success();
    fx.sm()
        .arg("change-password")
        .write_stdin("newpw\n\n")
        .assert()
        .code(2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unreachable_daemon_exits_3() {
    let fx = Fixture::start().await;
    let empty = tempfile::tempdir().unwrap();
    fx.sm()
        .arg("status")
        .env("XDG_RUNTIME_DIR", empty.path())
        .assert()
        .code(3)
        .stderr(predicate::str::contains(
            "systemctl --user start secret-manager",
        ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn missing_xdg_runtime_dir_exits_3_but_init_still_succeeds() {
    let fx = Fixture::start().await;
    fx.sm()
        .arg("status")
        .env_remove("XDG_RUNTIME_DIR")
        .assert()
        .code(3)
        .stderr(predicate::str::contains("XDG_RUNTIME_DIR is not set"));
    fx.sm()
        .args(["init", "--collection", "tmpx"])
        .env_remove("XDG_RUNTIME_DIR")
        .write_stdin("hunter2\n")
        .assert()
        .success();
}

#[test]
fn completions_render() {
    let mut cmd = assert_cmd::Command::cargo_bin("secret-manager").unwrap();
    cmd.args(["completions", "bash"])
        .assert()
        .success()
        .stdout(predicate::str::contains("sm"));
    let mut cmd = assert_cmd::Command::cargo_bin("secret-manager").unwrap();
    cmd.args(["completions", "zsh"])
        .assert()
        .success()
        .stdout(predicate::str::contains("compdef"));
}

/// HIGH 3: `--collection` is pasted into a filesystem path, so only a value
/// that is already a normalized collection id may be accepted.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn collection_argument_is_validated() {
    let fx = Fixture::start().await;

    // A planted vault file outside the vault directory must be unreachable.
    let outside = tempfile::tempdir().unwrap();
    let planted = outside.path().join("planted.vault");
    secret_manager::vault::Vault::create(
        &planted,
        "Planted",
        b"attacker",
        secret_manager::vault::crypto::KdfParams::FAST_FOR_TESTS,
    )
    .unwrap();
    let traversal = format!("{}/planted", outside.path().display());
    for arg in [
        "../x".to_string(),
        "..".to_string(),
        traversal,
        "My Work".to_string(),
        "UPPER".to_string(),
    ] {
        fx.sm()
            .args(["unlock", "--collection", &arg])
            .write_stdin("pw\n")
            .assert()
            .code(2)
            .stderr(predicate::str::contains("[a-z0-9_]"));
        fx.sm()
            .args(["change-password", "--collection", &arg])
            .write_stdin("pw\nnew\n")
            .assert()
            .code(2)
            .stderr(predicate::str::contains("[a-z0-9_]"));
    }
    // A valid id that simply does not exist is still a "not found", not usage.
    fx.sm()
        .args(["unlock", "--collection", "nope"])
        .write_stdin("pw\n")
        .assert()
        .code(1)
        .stderr(predicate::str::contains("no collection"));
}

/// HIGH 3: `sm init` still accepts a human label, but names the derived id so
/// the same string is not later passed to `sm unlock`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn init_reports_the_derived_collection_id() {
    let fx = Fixture::start().await;
    fx.sm()
        .args(["init", "--collection", "My Work"])
        .write_stdin("hunter2\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("my_work"));
    fx.sm()
        .args(["unlock", "--collection", "my_work"])
        .write_stdin("hunter2\n")
        .assert()
        .success();
}
