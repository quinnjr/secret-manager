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
        .envs(common::profiling_env())
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

/// A CLI child that is not attached to a fixture: its own HOME, config and
/// runtime directory, and a bus address that goes nowhere.
///
/// `env_clear` is deliberate — the CLI must not inherit the test runner's
/// environment — but it also drops the variable the coverage profiler needs,
/// so that one is put back explicitly (see `Fixture::sm`).
fn bare_sm(home: &std::path::Path) -> assert_cmd::Command {
    let mut cmd = assert_cmd::Command::cargo_bin("secret-manager").unwrap();
    cmd.env_clear()
        .envs(common::profiling_env())
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("HOME", home)
        .env("XDG_DATA_HOME", home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("XDG_RUNTIME_DIR", home.join("run"))
        .env("DBUS_SESSION_BUS_ADDRESS", "unix:path=/nonexistent");
    for key in ["LLVM_PROFILE_FILE", "LLVM_PROFILE_DIR"] {
        if let Ok(v) = std::env::var(key) {
            cmd.env(key, v);
        }
    }
    cmd
}

/// Writes a config whose vault directory is `dir`, with a KDF cheap enough for
/// a test.
fn write_config(home: &std::path::Path, dir: &std::path::Path) {
    let config_dir = home.join("config").join("secret-manager");
    std::fs::create_dir_all(&config_dir).unwrap();
    std::fs::write(
        config_dir.join("config.toml"),
        format!(
            "[vault]\ndir = \"{}\"\n[kdf]\nm_cost_kib = 8\nt_cost = 1\np_cost = 1\n",
            dir.display()
        ),
    )
    .unwrap();
}

/// A vault directory that cannot be created is a plain failure naming the
/// path, not a panic and not a success: `sm init` reports the vault layer's
/// own error (`VaultError` becomes `CliError::Failed`, exit 1) so the user can
/// see which path was refused.
#[test]
fn init_fails_when_the_vault_directory_cannot_be_created() {
    let home = tempfile::tempdir().unwrap();
    // A regular file where the vault directory's parent should be, so
    // `mkdir -p` cannot succeed.
    let blocker = home.path().join("blocker");
    std::fs::write(&blocker, b"not a directory").unwrap();
    let vault_dir = blocker.join("vaults");
    write_config(home.path(), &vault_dir);

    bare_sm(home.path())
        .arg("init")
        .write_stdin("hunter2\n")
        .assert()
        .code(1)
        .stderr(predicate::str::contains(vault_dir.display().to_string()));
    assert!(
        !vault_dir.exists(),
        "a refused vault directory must not have been created"
    );
}

/// A password that cannot be *read* must fail, not be taken as an empty one.
///
/// `read_password` reads a line from stdin when there is no terminal; if that
/// read fails there is no password, and treating the failure as an empty
/// string would create a vault whose master password is "" — the one outcome
/// worse than an error. A directory opened as stdin makes the read fail
/// (`EISDIR`) without any pty machinery, and the run must end as a failure
/// (exit 1) rather than the "empty password not allowed" usage error (exit 2)
/// that a silently-empty read would produce.
#[test]
fn a_stdin_that_cannot_be_read_is_not_an_empty_password() {
    let home = tempfile::tempdir().unwrap();
    let vault_dir = home.path().join("vaults");
    write_config(home.path(), &vault_dir);

    let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_secret-manager"));
    cmd.env_clear()
        .envs(common::profiling_env())
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("HOME", home.path())
        .env("XDG_DATA_HOME", home.path())
        .env("XDG_CONFIG_HOME", home.path().join("config"))
        .env("XDG_RUNTIME_DIR", home.path().join("run"))
        .env("DBUS_SESSION_BUS_ADDRESS", "unix:path=/nonexistent");
    for key in ["LLVM_PROFILE_FILE", "LLVM_PROFILE_DIR"] {
        if let Ok(v) = std::env::var(key) {
            cmd.env(key, v);
        }
    }
    // Reading from a directory is `EISDIR`, so this is a stdin that exists,
    // is readable-looking, and errors on the first read.
    let dir_as_stdin = std::fs::File::open(home.path()).unwrap();
    let out = cmd
        .arg("init")
        .stdin(std::process::Stdio::from(dir_as_stdin))
        .output()
        .unwrap();

    assert_eq!(
        out.status.code(),
        Some(1),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("empty password"),
        "an unreadable stdin was mistaken for an empty password: {stderr}"
    );
    assert!(
        !vault_dir.join("default.vault").exists(),
        "a vault was created from a password that was never read"
    );
}

/// A corrupt `aliases.toml` must not fail `sm init`.
///
/// The alias write happens *after* `Vault::create`, so a fatal error there
/// left a half-finished init: the vault on disk, the id the user needs never
/// printed, no `Reload` sent, and a re-run reporting "collection already
/// exists". That is the same asymmetry the daemon had, one layer up — the
/// file holding nothing but convenience mappings deciding whether the real
/// work counts.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn init_survives_an_unreadable_alias_file() {
    let fx = Fixture::start().await;
    let dir = fx.data_dir.path().join("secret-manager");
    let corrupt = b"aliases = 5\n";
    std::fs::write(dir.join("aliases.toml"), corrupt).unwrap();

    fx.sm()
        .args(["init", "--collection", "Work"])
        .write_stdin("hunter2\n")
        .assert()
        .success()
        // The id is what every later command takes, so it has to be printed.
        .stdout(predicate::str::contains("Its id is 'work'"))
        .stderr(predicate::str::contains("aliases.toml"));

    let mut v = Vault::open(&dir.join("work.vault")).unwrap();
    v.unlock(b"hunter2").unwrap();
    assert_eq!(
        std::fs::read(dir.join("aliases.toml")).unwrap(),
        corrupt,
        "the file the operator still has to repair was overwritten"
    );
}
