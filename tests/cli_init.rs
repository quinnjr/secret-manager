mod common;

use common::{Fixture, wait_for};
use predicates::prelude::*;
use secret_manager::dbus::paths;
use secret_manager::dbus::proxies::ServiceProxy;
use secret_manager::vault::Vault;
use std::time::Duration;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn init_creates_vault_and_running_daemon_reloads() {
    let fx = Fixture::start().await;
    fx.sm()
        .args(["init", "--collection", "Work"])
        .write_stdin("hunter2\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("work.vault"));
    let dir = fx.data_dir.path().join("secret-manager");
    let mut v = Vault::open(&dir.join("work.vault")).unwrap();
    v.unlock(b"hunter2").unwrap();
    assert_eq!(v.label(), "Work");

    let service = ServiceProxy::new(&fx.client().await).await.unwrap();
    assert!(
        wait_for(Duration::from_secs(3), || async {
            service
                .collections()
                .await
                .unwrap()
                .contains(&paths::collection("work"))
        })
        .await
    );
    assert_eq!(
        service.read_alias("default").await.unwrap(),
        fx.default_collection(),
        "existing default alias untouched"
    );

    fx.sm()
        .args(["init", "--collection", "Work"])
        .write_stdin("x\n")
        .assert()
        .code(1)
        .stderr(predicate::str::contains("already exists"));
    fx.sm()
        .args(["init", "--collection", "Other"])
        .write_stdin("\n")
        .assert()
        .code(2)
        .stderr(predicate::str::contains("empty"));
}

#[test]
fn init_without_daemon_sets_default_alias() {
    let data = tempfile::tempdir().unwrap();
    let runtime = tempfile::tempdir().unwrap();
    let mut cmd = assert_cmd::Command::cargo_bin("secret-manager").unwrap();
    cmd.env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("HOME", data.path())
        .env("XDG_DATA_HOME", data.path())
        .env("XDG_RUNTIME_DIR", runtime.path())
        .env("XDG_CONFIG_HOME", data.path().join("config"))
        .env("DBUS_SESSION_BUS_ADDRESS", "unix:path=/nonexistent")
        .arg("init")
        .write_stdin("pw\n")
        .assert()
        .success();
    let dir = data.path().join("secret-manager");
    assert!(dir.join("default.vault").exists());
    let aliases = std::fs::read_to_string(dir.join("aliases.toml")).unwrap();
    assert!(aliases.contains("default = \"default\""));
}
