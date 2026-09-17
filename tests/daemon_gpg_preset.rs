//! Daemon-side GPG preset: unlocking a collection feeds enrolled
//! passphrases to gpg-agent with no client involved.
mod common;

use common::gpg as g;
use common::{Fixture, wait_for};
use futures_util::StreamExt;
use secret_manager::dbus::proxies::{PromptProxy, ServiceProxy};
use std::path::PathBuf;
use std::time::Duration;
use zbus::zvariant::{OwnedObjectPath, OwnedValue};

async fn start_with_gpg(
    work: PathBuf,
    colons: String,
    mutate: impl FnOnce(&mut secret_manager::config::Config),
) -> Fixture {
    // The daemon always passes --homedir explicitly and sets GNUPGHOME on
    // the agent child, so the fakes resolve everything under it and no
    // process-global environment is involved.
    std::fs::write(work.join("colons"), colons).unwrap();
    Fixture::start_with_config(mutate).await
}

async fn start_enabled(work: &std::path::Path, keys: Vec<String>) -> Fixture {
    let dir = work.to_path_buf();
    let homedir = dir.clone();
    start_with_gpg(dir, g::colons_two_keys(), move |c| {
        c.gpg.enabled = true;
        c.gpg.gpg_bin = g::fixture("gpg");
        c.gpg.agent_bin = g::fixture("gpg-connect-agent");
        c.gpg.homedir = Some(homedir.clone());
        c.gpg.keys = keys;
    })
    .await
}

async fn enroll(fx: &Fixture, work: &std::path::Path, keyid: &str) {
    // CLI discovery honors FAKE_GPG_COLONS here; the daemon under test
    // uses the homedir file written above.
    let mut cmd = fx.sm();
    cmd.env("PATH", g::fixture_path())
        .env("FAKE_GPG_COLONS", work.join("colons"))
        .env("FAKE_GPG_STATE", work);
    cmd.args(["gpg", "enroll", "--keyid", keyid])
        .write_stdin("test-pass\n")
        .assert()
        .success();
}

fn clear_markers(work: &std::path::Path) {
    for entry in std::fs::read_dir(work).unwrap() {
        let p = entry.unwrap().path();
        if p.file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with("preset-")
        {
            std::fs::remove_file(p).unwrap();
        }
    }
}

/// Subscribe, trigger, and wait for `Completed`. Mirrors the helper in
/// `dbus_prompts.rs`: the D-Bus unlock path under test.
async fn perform(conn: &zbus::Connection, prompt: &OwnedObjectPath) -> (bool, OwnedValue) {
    let proxy = PromptProxy::builder(conn)
        .path(prompt.clone())
        .unwrap()
        .build()
        .await
        .unwrap();
    let mut completed = proxy.receive_completed().await.unwrap();
    proxy.prompt("").await.unwrap();
    let sig = tokio::time::timeout(Duration::from_secs(10), completed.next())
        .await
        .unwrap()
        .unwrap();
    let args = sig.args().unwrap();
    (args.dismissed, args.result.try_to_owned().unwrap())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn daemon_unlock_presets_enrolled_gpg_keys() {
    let work = tempfile::tempdir().unwrap();
    let fx = start_enabled(work.path(), vec![]).await;
    enroll(&fx, work.path(), g::KEYID).await;

    // Whatever unlocks happened during setup, measure from locked with a
    // fresh agent.
    clear_markers(work.path());
    fx.lock_default().await;
    let marker = work.path().join(format!("preset-{}", g::GRIP));
    assert!(!marker.exists());

    // Through the control socket: the PAM/`sm unlock` path.
    fx.sm()
        .args(["unlock"])
        .write_stdin("pw\n")
        .assert()
        .success();
    assert!(
        wait_for(Duration::from_secs(5), || async { marker.exists() }).await,
        "unlocking through the daemon must preset the enrolled key without any client help"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn daemon_unlock_through_a_dialog_presets_too() {
    let work = tempfile::tempdir().unwrap();
    let fx = start_enabled(work.path(), vec![]).await;
    enroll(&fx, work.path(), g::KEYID).await;
    clear_markers(work.path());
    fx.lock_default().await;

    // Through the D-Bus prompt: the interactive-unlock path.
    let conn = fx.client().await;
    let service = ServiceProxy::new(&conn).await.unwrap();
    let (unlocked, prompt) = service.unlock(&[fx.default_collection()]).await.unwrap();
    assert!(unlocked.is_empty());
    let (dismissed, _) = perform(&conn, &prompt).await;
    assert!(!dismissed);

    let marker = work.path().join(format!("preset-{}", g::GRIP));
    assert!(
        wait_for(Duration::from_secs(5), || async { marker.exists() }).await,
        "a dialog unlock must preset exactly like a control-socket unlock"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn daemon_preset_honors_the_keys_allowlist() {
    let work = tempfile::tempdir().unwrap();
    let fx = start_enabled(work.path(), vec![g::KEYID.to_string()]).await;
    enroll(&fx, work.path(), g::KEYID).await;
    enroll(&fx, work.path(), g::KEYID_B).await;
    clear_markers(work.path());
    fx.lock_default().await;

    fx.sm()
        .args(["unlock"])
        .write_stdin("pw\n")
        .assert()
        .success();
    let marker = work.path().join(format!("preset-{}", g::GRIP));
    assert!(
        wait_for(Duration::from_secs(5), || async { marker.exists() }).await,
        "the listed key must be preset"
    );
    assert!(
        !work.path().join(format!("preset-{}", g::GRIP_B)).exists(),
        "an enrolled but unlisted key must stay untouched"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn daemon_preset_with_an_allowlist_matching_nothing_presets_nothing() {
    let work = tempfile::tempdir().unwrap();
    let fx = start_enabled(work.path(), vec!["AAAAAAAAAAAAAAAA".to_string()]).await;
    enroll(&fx, work.path(), g::KEYID).await;
    clear_markers(work.path());
    fx.lock_default().await;

    fx.sm()
        .args(["unlock"])
        .write_stdin("pw\n")
        .assert()
        .success();
    // The unlock itself succeeded; give the background task a moment to
    // prove it presets nothing, then assert the negative.
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert!(
        std::fs::read_dir(work.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .all(|e| !e.file_name().to_string_lossy().starts_with("preset-")),
        "a non-matching allowlist must preset nothing"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn daemon_unlock_succeeds_when_the_agent_refuses() {
    let work = tempfile::tempdir().unwrap();
    let fx = start_enabled(work.path(), vec![]).await;
    enroll(&fx, work.path(), g::KEYID).await;
    clear_markers(work.path());
    fx.lock_default().await;
    // The agent refuses every preset; the unlock must not notice.
    std::fs::write(work.path().join("fail-preset"), "").unwrap();

    fx.sm()
        .args(["unlock"])
        .write_stdin("pw\n")
        .assert()
        .success();
    // Let the background task run to completion, then assert the vault
    // is open and the agent got nothing: failures are log-only.
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert!(!work.path().join(format!("preset-{}", g::GRIP)).exists());
    let status = fx
        .sm()
        .args(["status"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    assert!(
        String::from_utf8_lossy(&status).contains("unlocked"),
        "unlock succeeds despite the agent refusing every preset"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn daemon_preset_walks_past_a_locked_second_collection() {
    use secret_manager::vault::Vault;
    use secret_manager::vault::crypto::KdfParams;

    let work = tempfile::tempdir().unwrap();
    let fx = start_enabled(work.path(), vec![]).await;
    enroll(&fx, work.path(), g::KEYID).await;
    // A second collection the test never unlocks: the hook must walk
    // past its locked guard without prompting, failing, or leaking.
    // (A decoy item inside it is unplantable — `sm set` targets the
    // default collection only — so the read rule itself is pinned by
    // the `collect_enrolled` unit tests instead.)
    Vault::create(
        &fx.data_dir
            .path()
            .join("secret-manager")
            .join("second.vault"),
        "Second",
        b"pw",
        KdfParams::FAST_FOR_TESTS,
    )
    .unwrap();
    fx.sm().args(["reload"]).assert().success();
    clear_markers(work.path());
    fx.lock_default().await;

    fx.sm()
        .args(["unlock"])
        .write_stdin("pw\n")
        .assert()
        .success();
    let marker = work.path().join(format!("preset-{}", g::GRIP));
    assert!(
        wait_for(Duration::from_secs(5), || async { marker.exists() }).await,
        "the unlocked collection presets while a locked one is skipped"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn daemon_unlock_succeeds_when_discovery_fails() {
    let work = tempfile::tempdir().unwrap();
    let dir = work.path().to_path_buf();
    std::fs::write(dir.join("colons"), g::colons_single()).unwrap();
    let fx = start_with_gpg(dir, g::colons_single(), |c| {
        c.gpg.enabled = true;
        c.gpg.gpg_bin = PathBuf::from("/nonexistent/gpg-for-tests");
        c.gpg.agent_bin = g::fixture("gpg-connect-agent");
        c.gpg.homedir = Some(work.path().to_path_buf());
    })
    .await;
    // No `enroll` here: it needs a working gpg for discovery, and the
    // point is a broken one. Store the item directly instead.
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
    clear_markers(work.path());
    fx.lock_default().await;

    // Discovery cannot even spawn: the unlock still succeeds, log-only.
    fx.sm()
        .args(["unlock"])
        .write_stdin("pw\n")
        .assert()
        .success();
    let status = fx
        .sm()
        .args(["status"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    assert!(
        String::from_utf8_lossy(&status).contains("unlocked"),
        "unlock succeeds despite undiscoverable gpg"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn preset_is_opt_in_nothing_happens_when_disabled() {
    let work = tempfile::tempdir().unwrap();
    std::fs::write(work.path().join("colons"), g::colons_single()).unwrap();
    let fx = Fixture::start_with_config(|_| {}).await;
    // Same PATH-shimmed enroll as above, against a daemon whose [gpg]
    // section stays default-off.
    let mut cmd = fx.sm();
    cmd.env("PATH", g::fixture_path())
        .env("FAKE_GPG_COLONS", work.path().join("colons"))
        .env("FAKE_GPG_STATE", work.path());
    cmd.args(["gpg", "enroll", "--keyid", g::KEYID])
        .write_stdin("test-pass\n")
        .assert()
        .success();
    // Enroll verifies via its own preset; clear that marker so the
    // measured sequence starts clean.
    clear_markers(work.path());
    fx.lock_default().await;

    fx.sm()
        .args(["unlock"])
        .write_stdin("pw\n")
        .assert()
        .success();
    // Disabled returns before any task exists, so the negative is
    // immediate rather than a timing window: nothing was ever spawned.
    assert!(
        !work.path().join(format!("preset-{}", g::GRIP)).exists(),
        "a disabled [gpg] section must leave the agent alone"
    );
}
