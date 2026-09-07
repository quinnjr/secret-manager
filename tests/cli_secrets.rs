mod common;

use common::Fixture;
use predicates::prelude::*;
use std::collections::BTreeMap;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn set_get_list_delete_round_trip() {
    let fx = Fixture::start().await;
    fx.unlock_default().await;
    fx.sm()
        .args(["set", "app=git", "user=joe", "--label", "git token"])
        .write_stdin("s3cret\n")
        .assert()
        .success();
    fx.sm()
        .args(["get", "app=git", "user=joe"])
        .assert()
        .success()
        .stdout("s3cret");
    fx.sm()
        .args(["get", "app=git"])
        .assert()
        .success()
        .stdout("s3cret");
    fx.sm()
        .args(["get", "app=git", "--label", "git token"])
        .assert()
        .success()
        .stdout("s3cret");
    fx.sm()
        .args(["get", "app=git", "--label", "other"])
        .assert()
        .code(1);
    fx.sm()
        .args(["get", "user=nobody"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("no matching secret"));

    // replace keeps a single item
    fx.sm()
        .args(["set", "app=git", "user=joe", "--label", "git token 2"])
        .write_stdin("newer")
        .assert()
        .success();
    fx.sm()
        .args(["get", "app=git"])
        .assert()
        .success()
        .stdout("newer");
    fx.sm()
        .args(["list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("git token 2").and(predicate::str::contains("app=git")));
    fx.sm()
        .args(["list", "app=git"])
        .assert()
        .success()
        .stdout(predicate::str::contains("user=joe"));
    fx.sm()
        .args(["list", "app=nope"])
        .assert()
        .success()
        .stdout("");
    let json = fx
        .sm()
        .args(["list", "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let parsed: serde_json::Value = serde_json::from_slice(&json).unwrap();
    assert_eq!(parsed[0]["label"], "git token 2");
    assert_eq!(parsed[0]["attributes"]["user"], "joe");
    assert_eq!(parsed[0]["locked"], false);
    assert!(
        !fx.sm()
            .args(["list"])
            .assert()
            .get_output()
            .stdout
            .windows(5)
            .any(|w| w == b"newer"),
        "list never prints secrets"
    );

    fx.sm().args(["delete", "app=git"]).assert().success();
    fx.sm().args(["get", "app=git"]).assert().code(1);
    fx.sm().args(["delete", "app=git"]).assert().code(1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn most_recent_item_wins() {
    let fx = Fixture::start().await;
    fx.unlock_default().await;
    fx.sm()
        .args(["set", "k=v", "n=1", "--label", "one"])
        .write_stdin("first")
        .assert()
        .success();
    // Force the first item's `modified` timestamp back deterministically
    // instead of sleeping past the second-granularity clock, so this test
    // doesn't depend on a >1s wall-clock sleep.
    let first_id = fx
        .daemon
        .state
        .lock()
        .await
        .collections
        .get("default")
        .unwrap()
        .search_ids(&BTreeMap::from([("k".to_string(), "v".to_string())]))
        .into_iter()
        .next()
        .unwrap();
    fx.daemon
        .state
        .lock()
        .await
        .collections
        .get_mut("default")
        .unwrap()
        .set_modified_for_tests(&first_id, 1)
        .unwrap();
    fx.sm()
        .args(["set", "k=v", "n=2", "--label", "two"])
        .write_stdin("second")
        .assert()
        .success();
    fx.sm()
        .args(["get", "k=v"])
        .assert()
        .success()
        .stdout("second");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn binary_secrets_survive() {
    let fx = Fixture::start().await;
    fx.unlock_default().await;
    let bytes: Vec<u8> = vec![0, 1, 2, 255, 10, 13, 10];
    fx.sm()
        .args(["set", "bin=1", "--label", "bin"])
        .write_stdin(bytes.clone())
        .assert()
        .success();
    let out = fx
        .sm()
        .args(["get", "bin=1"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    assert_eq!(
        out,
        &bytes[..bytes.len() - 1],
        "exactly one trailing newline is stripped on set"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn usage_errors_and_unreachable() {
    let fx = Fixture::start().await;
    fx.sm()
        .args(["get", "noequals"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("ATTR=VALUE"));
    fx.sm().args(["set", "a=b"]).assert().code(2); // clap: --label required
    fx.sm().args(["get"]).assert().code(2);
    fx.sm()
        .args(["get", "a=b"])
        .env("DBUS_SESSION_BUS_ADDRESS", "unix:path=/nonexistent/bus")
        .assert()
        .code(3);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn get_prompts_to_unlock() {
    let fx = Fixture::start().await; // locked, pinentry answers pw
    fx.sm()
        .args(["set", "a=b", "--label", "x"])
        .write_stdin("v")
        .assert()
        .success();
    assert!(
        fx.pinentry_log().contains("GETPIN"),
        "set unlocked through the prompt"
    );
    fx.lock_default().await;
    fx.sm().args(["get", "a=b"]).assert().success().stdout("v");
    fx.sm()
        .args(["list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("x"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dismissed_prompt_exits_1() {
    let fx = Fixture::start_with_pin(None).await;
    fx.sm()
        .args(["set", "a=b", "--label", "x"])
        .write_stdin("v")
        .assert()
        .code(1)
        .stderr(predicate::str::contains("dismissed"));
    fx.unlock_default().await;
    fx.sm()
        .args(["set", "a=b", "--label", "x"])
        .write_stdin("v")
        .assert()
        .success();
    fx.lock_default().await;
    fx.sm()
        .args(["get", "a=b"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("dismissed"));
    fx.sm()
        .args(["list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("[locked]"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn interop_with_secret_tool() {
    if std::process::Command::new("secret-tool")
        .arg("--version")
        .output()
        .is_err()
    {
        return;
    }
    let fx = Fixture::start().await;
    fx.unlock_default().await;
    fx.sm()
        .args(["set", "app=interop", "--label", "from sm"])
        .write_stdin("shared")
        .assert()
        .success();
    let out = std::process::Command::new("secret-tool")
        .args(["lookup", "app", "interop"])
        .env("DBUS_SESSION_BUS_ADDRESS", &fx.bus.address)
        .output()
        .unwrap();
    assert_eq!(String::from_utf8_lossy(&out.stdout), "shared");
}
