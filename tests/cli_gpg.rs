mod common;

use common::Fixture;
use common::gpg as g;
use predicates::prelude::*;

fn hex(s: &str) -> String {
    s.bytes().map(|b| format!("{b:02x}")).collect()
}

fn gpg_env(cmd: &mut assert_cmd::Command, work: &std::path::Path) {
    cmd.env("PATH", g::fixture_path())
        .env("FAKE_GPG_COLONS", work.join("colons"))
        .env("FAKE_GPG_STATE", work.join("state"));
}

fn setup(work: &std::path::Path) {
    std::fs::create_dir_all(work.join("state")).unwrap();
    std::fs::write(work.join("colons"), g::colons_single()).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn enroll_stores_and_verifies_the_roundtrip() {
    let fx = Fixture::start().await;
    fx.unlock_default().await;
    let work = tempfile::tempdir().unwrap();
    setup(work.path());
    let state = work.path().join("state");

    let mut cmd = fx.sm();
    gpg_env(&mut cmd, work.path());
    cmd.args(["gpg", "enroll", "--keyid", g::KEYID])
        .write_stdin("test-pass\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("verified"))
        .stdout(predicate::str::contains("To preset at login"));

    // The enroll preset the agent: the marker only exists if a real
    // PRESET_PASSPHRASE roundtrip ran, and the batch testsign only
    // succeeds when one does.
    assert!(
        state.join(format!("preset-{}", g::GRIP)).exists(),
        "enroll must preset the agent as part of verification"
    );
    fx.sm()
        .args(["list", "xdg:schema=org.secret-manager.gpg"])
        .assert()
        .success()
        .stdout(predicate::str::contains(format!(
            "GPG signing key {}",
            g::KEYID
        )));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn enroll_hides_the_hint_once_the_daemon_is_enabled() {
    let fx = Fixture::start_with_config(|c| c.gpg.enabled = true).await;
    fx.unlock_default().await;
    let work = tempfile::tempdir().unwrap();
    setup(work.path());

    let mut cmd = fx.sm();
    gpg_env(&mut cmd, work.path());
    let out = cmd
        .args(["gpg", "enroll", "--keyid", g::KEYID])
        .write_stdin("test-pass\n")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let out = String::from_utf8_lossy(&out);
    assert!(out.contains("verified"), "{out}");
    assert!(
        !out.contains("To preset at login"),
        "no hint once the daemon is enabled: {out}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reenroll_replaces_the_old_passphrase() {
    let fx = Fixture::start().await;
    fx.unlock_default().await;
    let work = tempfile::tempdir().unwrap();
    setup(work.path());
    let log = work.path().join("gpg.log");

    let mut cmd = fx.sm();
    gpg_env(&mut cmd, work.path());
    cmd.env("FAKE_GPG_LOG", &log);
    cmd.args(["gpg", "enroll", "--keyid", g::KEYID])
        .write_stdin("first-pass\n")
        .assert()
        .success();
    // Only the second enrollment's secret may reach the agent afterwards.
    std::fs::write(&log, "").unwrap();
    let mut cmd = fx.sm();
    gpg_env(&mut cmd, work.path());
    cmd.env("FAKE_GPG_LOG", &log);
    cmd.args(["gpg", "enroll", "--keyid", g::KEYID])
        .write_stdin("second-pass\n")
        .assert()
        .success();

    let listed = fx
        .sm()
        .args(["list", "xdg:schema=org.secret-manager.gpg"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    assert_eq!(
        String::from_utf8_lossy(&listed)
            .lines()
            .filter(|l| l.contains("GPG signing key"))
            .count(),
        1,
        "re-enroll must replace, not duplicate"
    );
    let log = std::fs::read_to_string(&log).unwrap();
    assert!(log.contains(&hex("second-pass")), "new secret preset");
    assert!(!log.contains(&hex("first-pass")), "old secret gone");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn preset_reapplies_enrolled_keys_after_a_fresh_login() {
    let fx = Fixture::start().await;
    fx.unlock_default().await;
    let work = tempfile::tempdir().unwrap();
    setup(work.path());
    let state = work.path().join("state");

    let mut cmd = fx.sm();
    gpg_env(&mut cmd, work.path());
    cmd.args(["gpg", "enroll", "--keyid", g::KEYID])
        .write_stdin("test-pass\n")
        .assert()
        .success();
    let marker = state.join(format!("preset-{}", g::GRIP));
    assert!(marker.exists());

    // A fresh login: the agent forgot everything.
    std::fs::remove_file(&marker).unwrap();
    let mut cmd = fx.sm();
    gpg_env(&mut cmd, work.path());
    cmd.args(["gpg", "preset"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Preset 1 GPG key"));
    assert!(
        marker.exists(),
        "preset must feed the enrolled passphrase back to a fresh agent"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn preset_counts_only_enrolled_keys() {
    let fx = Fixture::start().await;
    fx.unlock_default().await;
    let work = tempfile::tempdir().unwrap();
    setup(work.path());
    // Two keys discovered, one enrolled.
    std::fs::write(work.path().join("colons"), g::colons_two_keys()).unwrap();
    let state = work.path().join("state");

    let mut cmd = fx.sm();
    gpg_env(&mut cmd, work.path());
    cmd.args(["gpg", "enroll", "--keyid", g::KEYID])
        .write_stdin("test-pass\n")
        .assert()
        .success();
    for entry in std::fs::read_dir(&state).unwrap() {
        std::fs::remove_file(entry.unwrap().path()).unwrap();
    }

    let mut cmd = fx.sm();
    gpg_env(&mut cmd, work.path());
    cmd.args(["gpg", "preset"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Preset 1 GPG key"));
    assert!(state.join(format!("preset-{}", g::GRIP)).exists());
    assert!(
        !state.join(format!("preset-{}", g::GRIP_B)).exists(),
        "an unenrolled discovered key must stay untouched"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn preset_is_quiet_when_a_key_rotated_away() {
    let fx = Fixture::start().await;
    fx.unlock_default().await;
    let work = tempfile::tempdir().unwrap();
    setup(work.path());
    let state = work.path().join("state");

    let mut cmd = fx.sm();
    gpg_env(&mut cmd, work.path());
    cmd.args(["gpg", "enroll", "--keyid", g::KEYID])
        .write_stdin("test-pass\n")
        .assert()
        .success();
    // The key is gone from the ring; the enrollment is orphaned.
    std::fs::write(
        work.path().join("colons"),
        format!(
            "sec:u:255:22:{}:1774453727:1837525727::u:::scESC:::+:::23::0:\nfpr:::::::::{}:\ngrp:::::::::{}:\n",
            g::KEYID_B,
            g::FPR_B,
            g::GRIP_B
        ),
    )
    .unwrap();
    for entry in std::fs::read_dir(&state).unwrap() {
        std::fs::remove_file(entry.unwrap().path()).unwrap();
    }

    let mut cmd = fx.sm();
    gpg_env(&mut cmd, work.path());
    cmd.args(["gpg", "preset"]).assert().success().stdout("");
    assert!(
        std::fs::read_dir(&state).unwrap().next().is_none(),
        "a rotated-away enrollment is a skip, not an error and not a wrong-key preset"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn preset_never_fails_the_boot_without_gpg() {
    let fx = Fixture::start().await;
    fx.unlock_default().await;
    let empty = tempfile::tempdir().unwrap();

    fx.sm()
        .args(["gpg", "preset"])
        .env("PATH", empty.path())
        .assert()
        .success()
        .stdout("");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn preset_reports_a_broken_keyring() {
    let fx = Fixture::start().await;
    fx.unlock_default().await;
    let work = tempfile::tempdir().unwrap();
    setup(work.path());

    let mut cmd = fx.sm();
    gpg_env(&mut cmd, work.path());
    cmd.env("FAKE_GPG_K_FAIL", "1");
    cmd.args(["gpg", "preset"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("keyring failed"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn preset_is_quiet_when_nothing_is_enrolled() {
    let fx = Fixture::start().await;
    fx.unlock_default().await;
    let work = tempfile::tempdir().unwrap();
    setup(work.path());
    let state = work.path().join("state");

    // The key exists in gpg but was never enrolled: nothing to feed.
    let mut cmd = fx.sm();
    gpg_env(&mut cmd, work.path());
    cmd.args(["gpg", "preset"]).assert().success().stdout("");
    assert!(
        !state.join(format!("preset-{}", g::GRIP)).exists(),
        "preset must not invent a passphrase for an unenrolled key"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn preset_says_so_when_the_config_cannot_be_read() {
    let fx = Fixture::start().await;
    fx.unlock_default().await;
    let work = tempfile::tempdir().unwrap();
    setup(work.path());

    let mut cmd = fx.sm();
    gpg_env(&mut cmd, work.path());
    cmd.args(["gpg", "enroll", "--keyid", g::KEYID])
        .write_stdin("test-pass\n")
        .assert()
        .success();
    // Corrupt the fixture config: the filter is unreadable, so the
    // preset must say it is proceeding unfiltered rather than either
    // failing or silently widening.
    std::fs::write(
        fx.data_dir
            .path()
            .join("config")
            .join("secret-manager")
            .join("config.toml"),
        "[[[broken",
    )
    .unwrap();
    for entry in std::fs::read_dir(work.path().join("state")).unwrap() {
        std::fs::remove_file(entry.unwrap().path()).unwrap();
    }

    let mut cmd = fx.sm();
    gpg_env(&mut cmd, work.path());
    cmd.args(["gpg", "preset"])
        .assert()
        .success()
        .stderr(predicate::str::contains("unreadable config"));
    assert!(
        work.path()
            .join("state")
            .join(format!("preset-{}", g::GRIP))
            .exists()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn enroll_proves_the_enrolled_key_not_the_default() {
    let fx = Fixture::start().await;
    fx.unlock_default().await;
    let work = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(work.path().join("state")).unwrap();
    // Two keys in the ring; enroll the second. The verifier must check
    // the second key's preset, not any cached default.
    std::fs::write(work.path().join("colons"), g::colons_two_keys()).unwrap();

    let mut cmd = fx.sm();
    gpg_env(&mut cmd, work.path());
    cmd.env("FAKE_GPG_TESTSIGN_GRIP", g::GRIP_B);
    cmd.args(["gpg", "enroll", "--keyid", g::KEYID_B])
        .write_stdin("test-pass\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("verified"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn enroll_refuses_an_unknown_keyid() {
    let fx = Fixture::start().await;
    fx.unlock_default().await;
    let work = tempfile::tempdir().unwrap();
    setup(work.path());

    let mut cmd = fx.sm();
    gpg_env(&mut cmd, work.path());
    cmd.args(["gpg", "enroll", "--keyid", "DEADBEEF"])
        .write_stdin("test-pass\n")
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::contains("no secret signing key matches"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn enroll_rejects_an_empty_passphrase() {
    let fx = Fixture::start().await;
    fx.unlock_default().await;
    let work = tempfile::tempdir().unwrap();
    setup(work.path());

    let mut cmd = fx.sm();
    gpg_env(&mut cmd, work.path());
    cmd.args(["gpg", "enroll", "--keyid", g::KEYID])
        .write_stdin("\n")
        .assert()
        .failure()
        .stderr(predicate::str::contains("empty"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn enroll_proves_the_testsign_step_too() {
    let fx = Fixture::start().await;
    fx.unlock_default().await;
    let work = tempfile::tempdir().unwrap();
    setup(work.path());
    let state = work.path().join("state");

    // The preset lands but signing still fails: stored, yet honest.
    let mut cmd = fx.sm();
    gpg_env(&mut cmd, work.path());
    cmd.env("FAKE_GPG_TESTSIGN_FAIL", "1");
    cmd.args(["gpg", "enroll", "--keyid", g::KEYID])
        .write_stdin("test-pass\n")
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::contains("verification testsign failed"));
    assert!(state.join(format!("preset-{}", g::GRIP)).exists());
    fx.sm()
        .args(["list", "xdg:schema=org.secret-manager.gpg"])
        .assert()
        .success()
        .stdout(predicate::str::contains(format!(
            "GPG signing key {}",
            g::KEYID
        )));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn enroll_names_the_fix_when_the_agent_refuses_the_preset() {
    let fx = Fixture::start().await;
    fx.unlock_default().await;
    let work = tempfile::tempdir().unwrap();
    setup(work.path());

    let mut cmd = fx.sm();
    gpg_env(&mut cmd, work.path());
    cmd.env("FAKE_GPG_PRESET_FAIL", "1");
    cmd.args(["gpg", "enroll", "--keyid", g::KEYID])
        .write_stdin("test-pass\n")
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::contains("allow-preset-passphrase"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn enroll_fails_when_gpg_is_missing() {
    let fx = Fixture::start().await;
    fx.unlock_default().await;
    let empty = tempfile::tempdir().unwrap();

    fx.sm()
        .args(["gpg", "enroll", "--keyid", g::KEYID])
        .env("PATH", empty.path())
        .write_stdin("test-pass\n")
        .assert()
        .failure()
        .stderr(predicate::str::contains("gpg not found"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn enroll_reports_a_broken_keyring() {
    let fx = Fixture::start().await;
    fx.unlock_default().await;
    let work = tempfile::tempdir().unwrap();
    setup(work.path());

    let mut cmd = fx.sm();
    gpg_env(&mut cmd, work.path());
    cmd.env("FAKE_GPG_K_FAIL", "1");
    cmd.args(["gpg", "enroll", "--keyid", g::KEYID])
        .write_stdin("test-pass\n")
        .assert()
        .failure()
        .stderr(predicate::str::contains("keyring failed"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn enroll_fails_closed_when_the_config_is_unreadable() {
    let fx = Fixture::start().await;
    fx.unlock_default().await;
    let work = tempfile::tempdir().unwrap();
    setup(work.path());
    std::fs::write(
        fx.data_dir
            .path()
            .join("config")
            .join("secret-manager")
            .join("config.toml"),
        "[[[broken",
    )
    .unwrap();

    let mut cmd = fx.sm();
    gpg_env(&mut cmd, work.path());
    cmd.args(["gpg", "enroll", "--keyid", g::KEYID])
        .write_stdin("test-pass\n")
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::contains("unreadable config"));
    // Nothing stranded: the secret was never stored.
    fx.sm()
        .args(["list", "xdg:schema=org.secret-manager.gpg"])
        .assert()
        .success()
        .stdout(predicate::str::contains("GPG signing key").not());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn preset_errors_when_the_configured_gpg_is_missing() {
    // Bare names stay quiet (boot helper); an explicit configured path
    // that resolves nowhere is an operator error and fails loud.
    let fx = Fixture::start_with_config(|c| {
        c.gpg.gpg_bin = std::path::PathBuf::from("/nonexistent/gpg-for-tests");
    })
    .await;
    fx.unlock_default().await;

    fx.sm()
        .args(["gpg", "preset"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("not found"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn preset_skips_quietly_when_the_daemon_is_unreachable() {
    let fx = Fixture::start().await;
    fx.unlock_default().await;
    let work = tempfile::tempdir().unwrap();
    setup(work.path());

    // A dead bus address: the login helper warns and exits 0 rather
    // than failing the boot. (Discovery stays hermetic via the fake
    // so a missing real gpg cannot short-circuit the assertion.)
    let mut cmd = fx.sm();
    gpg_env(&mut cmd, work.path());
    cmd.args(["gpg", "preset"])
        .env(
            "DBUS_SESSION_BUS_ADDRESS",
            "unix:path=/nonexistent/bus-for-tests",
        )
        .assert()
        .success()
        .stderr(predicate::str::contains("unreachable"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn preset_warns_on_an_empty_enrollment() {
    let fx = Fixture::start().await;
    fx.unlock_default().await;
    let work = tempfile::tempdir().unwrap();
    setup(work.path());

    // Only reachable by hand: `enroll` itself refuses empty passphrases.
    fx.sm()
        .args([
            "set",
            "xdg:schema=org.secret-manager.gpg",
            &format!("keyid={}", g::KEYID),
            "--label",
            &format!("GPG signing key {}", g::KEYID),
        ])
        .write_stdin("")
        .assert()
        .success();

    let mut cmd = fx.sm();
    gpg_env(&mut cmd, work.path());
    cmd.args(["gpg", "preset"])
        .assert()
        .success()
        .stderr(predicate::str::contains("empty passphrase"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn preset_reports_when_the_agent_refuses() {
    let fx = Fixture::start().await;
    fx.unlock_default().await;
    let work = tempfile::tempdir().unwrap();
    setup(work.path());

    let mut cmd = fx.sm();
    gpg_env(&mut cmd, work.path());
    cmd.args(["gpg", "enroll", "--keyid", g::KEYID])
        .write_stdin("test-pass\n")
        .assert()
        .success();
    for entry in std::fs::read_dir(work.path().join("state")).unwrap() {
        std::fs::remove_file(entry.unwrap().path()).unwrap();
    }

    // The quiet login helper must fail loud here: the agent refuses.
    let mut cmd = fx.sm();
    gpg_env(&mut cmd, work.path());
    cmd.env("FAKE_GPG_PRESET_FAIL", "1");
    cmd.args(["gpg", "preset"])
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::contains("allow-preset-passphrase"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn preset_reports_unreadable_keys_when_locked() {
    // Prompts cancel here, so a locked vault stays locked: seeding
    // bypasses the prompt via unlock_default, locking back is direct.
    let fx = Fixture::start_with_pin(None).await;
    secret_manager::dbus::state::with_vault(&fx.daemon.state, "default", |v| {
        v.unlock(common::PASSWORD.as_bytes())
    })
    .await
    .unwrap();
    let work = tempfile::tempdir().unwrap();
    setup(work.path());

    fx.sm()
        .args([
            "set",
            "xdg:schema=org.secret-manager.gpg",
            &format!("keyid={}", g::KEYID),
            "--label",
            &format!("GPG signing key {}", g::KEYID),
        ])
        .write_stdin("test-pass\n")
        .assert()
        .success();
    fx.lock_default().await;

    let mut cmd = fx.sm();
    gpg_env(&mut cmd, work.path());
    cmd.args(["gpg", "preset"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("could not be read"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn preset_reports_an_empty_discovery_stderr() {
    let fx = Fixture::start().await;
    fx.unlock_default().await;
    let work = tempfile::tempdir().unwrap();
    setup(work.path());

    let mut cmd = fx.sm();
    gpg_env(&mut cmd, work.path());
    cmd.env("FAKE_GPG_K_FAIL", "quiet");
    cmd.args(["gpg", "preset"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("failed with status"));
}
