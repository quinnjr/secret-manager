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

/// CRITICAL: `sm delete` must delete nothing unless every locked match could
/// be unlocked. Two collections hold a matching item; only one of them can be
/// opened with the password the prompt answers, so the daemon reports
/// `dismissed = false` while listing only the paths it actually unlocked.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn delete_refuses_a_partial_unlock() {
    let fx = Fixture::start().await;
    fx.unlock_default().await;
    fx.sm()
        .args(["set", "app=dup", "--label", "copy in default"])
        .write_stdin("a")
        .assert()
        .success();

    // A second collection whose password is *not* the one the fake pinentry
    // answers, holding an item with the same attributes.
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
            "copy in extra",
            BTreeMap::from([("app".to_string(), "dup".to_string())]),
            b"a".to_vec(),
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
        .args(["delete", "app=dup"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("nothing was deleted"));

    // Both copies survive: the default one is now unlocked (its prompt was
    // answered), the other is still locked.
    fx.sm().args(["list", "app=dup"]).assert().success().stdout(
        predicate::str::contains("copy in default").and(predicate::str::contains("[locked]")),
    );
}

/// MEDIUM 1: a second matching item (which any bus client can create by
/// adding attributes to the user's own) must be announced on stderr.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn get_warns_when_more_than_one_item_matches() {
    let fx = Fixture::start().await;
    fx.unlock_default().await;
    fx.sm()
        .args(["set", "app=git", "--label", "github token"])
        .write_stdin("mine")
        .assert()
        .success();
    fx.sm()
        .args(["get", "app=git"])
        .assert()
        .success()
        .stdout("mine")
        .stderr("");

    // A shadowing item: same attributes plus one more, so it still matches.
    fx.sm()
        .args(["set", "app=git", "evil=1", "--label", "shadow"])
        .write_stdin("theirs")
        .assert()
        .success();
    fx.sm().args(["get", "app=git"]).assert().success().stderr(
        predicate::str::contains("warning: 2 items match").and(predicate::str::contains("--label")),
    );
    // A --label filter that narrows to one item is silent again.
    fx.sm()
        .args(["get", "app=git", "--label", "github token"])
        .assert()
        .success()
        .stdout("mine")
        .stderr("");
}

/// MEDIUM 2: stdin is capped, so `sm set < /dev/zero` cannot exhaust memory.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn set_rejects_an_oversized_secret() {
    let fx = Fixture::start().await;
    fx.unlock_default().await;
    fx.sm()
        .args(["set", "big=1", "--label", "big"])
        .write_stdin(vec![b'x'; (1 << 20) + 1])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("exceeds 1 MiB"));
    // Exactly at the limit still works.
    fx.sm()
        .args(["set", "big=1", "--label", "big"])
        .write_stdin(vec![b'x'; 1 << 20])
        .assert()
        .success();
    // LOW: the trailing newline is a delimiter, not part of the secret, so it
    // must be dropped *before* the size check. `printf '%s\n'` of a 1 MiB
    // secret is a 1 MiB secret.
    let mut with_newline = vec![b'x'; 1 << 20];
    with_newline.push(b'\n');
    fx.sm()
        .args(["set", "big=2", "--label", "big2"])
        .write_stdin(with_newline)
        .assert()
        .success();
    fx.sm()
        .args(["get", "big=2"])
        .assert()
        .success()
        .stdout(predicate::function(|o: &[u8]| {
            o.len() == (1 << 20) && o.iter().all(|b| *b == b'x')
        }));
    // One byte past the limit *plus* a newline is still too big.
    let mut oversized = vec![b'x'; (1 << 20) + 1];
    oversized.push(b'\n');
    fx.sm()
        .args(["set", "big=3", "--label", "big3"])
        .write_stdin(oversized)
        .assert()
        .code(2)
        .stderr(predicate::str::contains("exceeds 1 MiB"));
}

/// LOW 1: control characters in a label or an attribute value must not reach
/// the terminal, or a hostile item could erase or forge `sm list` rows.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn list_escapes_control_characters() {
    let fx = Fixture::start().await;
    fx.unlock_default().await;
    fx.sm()
        .args([
            "set",
            "app=x\u{1b}[31mred",
            "--label",
            "sneaky\rHIDDEN\u{1b}[2K",
        ])
        .write_stdin("v")
        .assert()
        .success();
    let out = fx
        .sm()
        .args(["list"])
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
    assert!(
        text.contains("\\x0d"),
        "carriage return is rendered: {text:?}"
    );
    assert!(text.contains("\\x1b"), "escape is rendered: {text:?}");
    // The --json path is unchanged and still carries the real bytes.
    let json = fx
        .sm()
        .args(["list", "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let parsed: serde_json::Value = serde_json::from_slice(&json).unwrap();
    assert_eq!(parsed[0]["label"], "sneaky\rHIDDEN\u{1b}[2K");
}
