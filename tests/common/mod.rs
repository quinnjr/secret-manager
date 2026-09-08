// Shared by every tests/*.rs binary; not every binary uses every helper.
#![allow(dead_code)]
//! Private bus + in-process daemon for integration tests.

use secret_manager::config::{Config, KdfConfig, PromptConfig, VaultConfig};
use secret_manager::daemon::{BusAddress, Daemon, DaemonOptions};
use secret_manager::vault::Vault;
use secret_manager::vault::crypto::KdfParams;
use std::collections::BTreeMap;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::Duration;
use tempfile::TempDir;
use zbus::Connection;
use zbus::zvariant::OwnedObjectPath;

pub const PASSWORD: &str = "pw";

pub struct TestBus {
    pub address: String,
    child: Child,
    _dir: TempDir,
}

impl TestBus {
    pub fn start() -> TestBus {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("bus");
        let mut child = Command::new("dbus-daemon")
            .args(["--session", "--nofork", "--nopidfile", "--print-address"])
            .arg(format!("--address=unix:path={}", sock.display()))
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("dbus-daemon must be installed");
        let mut line = String::new();
        BufReader::new(child.stdout.take().unwrap())
            .read_line(&mut line)
            .unwrap();
        TestBus {
            address: line.trim().to_string(),
            child,
            _dir: dir,
        }
    }
}

impl Drop for TestBus {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

pub fn fake_pinentry() -> PathBuf {
    PathBuf::from(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/fake-pinentry.sh"
    ))
}

pub struct Fixture {
    pub bus: TestBus,
    pub data_dir: TempDir,
    pub runtime_dir: TempDir,
    pub daemon: Daemon,
    pub pinentry_log: PathBuf,
    pub pin: Option<String>,
}

impl Fixture {
    /// Daemon with a `default` collection (password `pw`), pinentry answering `pw`.
    pub async fn start() -> Fixture {
        Self::start_with_pin(Some(PASSWORD)).await
    }

    /// `pin = None` makes every prompt cancel.
    pub async fn start_with_pin(pin: Option<&str>) -> Fixture {
        Self::start_custom(pin, Duration::ZERO).await
    }

    /// Daemon with a fast idle-lock timer instead of the default disabled one.
    pub async fn start_with_idle(idle: Duration) -> Fixture {
        Self::start_custom(Some(PASSWORD), idle).await
    }

    /// General constructor: `pin = None` makes every prompt cancel; `idle` sets
    /// `auto_lock_after`.
    pub async fn start_custom(pin: Option<&str>, idle: Duration) -> Fixture {
        Self::start_with_pin_and_env(pin, Vec::new(), idle).await
    }

    /// Like [`start_with_pin`](Self::start_with_pin), with extra environment
    /// variables passed to the fake pinentry (e.g. `FAKE_DELAY` to make it
    /// hang before answering, for tests that race a `Dismiss` against it).
    pub async fn start_with_pin_and_env(
        pin: Option<&str>,
        extra_pinentry_env: Vec<(String, String)>,
        idle: Duration,
    ) -> Fixture {
        Self::start_full(pin, extra_pinentry_env, idle, |_| {}).await
    }

    /// Daemon with the default fixture plus `mutate` applied to its config.
    pub async fn start_with_config(mutate: impl FnOnce(&mut Config)) -> Fixture {
        Self::start_full(Some(PASSWORD), Vec::new(), Duration::ZERO, mutate).await
    }

    pub async fn start_full(
        pin: Option<&str>,
        extra_pinentry_env: Vec<(String, String)>,
        idle: Duration,
        mutate: impl FnOnce(&mut Config),
    ) -> Fixture {
        Self::start_inner(pin, extra_pinentry_env, idle, mutate, true).await
    }

    /// The default fixture, except that the alias file is never written, so
    /// `ReadAlias("default")` answers `/`.
    ///
    /// Every other constructor installs `default = "default"` before the
    /// daemon starts, which makes the CLI's "no default collection" path
    /// unreachable — and that path is what every `sm set` and `sm ssh add`
    /// hits on a machine where `sm init` has never run.
    pub async fn start_without_default_alias() -> Fixture {
        Self::start_inner(Some(PASSWORD), Vec::new(), Duration::ZERO, |_| {}, false).await
    }

    async fn start_inner(
        pin: Option<&str>,
        extra_pinentry_env: Vec<(String, String)>,
        idle: Duration,
        mutate: impl FnOnce(&mut Config),
        write_default_alias: bool,
    ) -> Fixture {
        let bus = TestBus::start();
        let data_dir = tempfile::tempdir().unwrap();
        let runtime_dir = tempfile::tempdir().unwrap();
        let vault_dir = data_dir.path().join("secret-manager");
        std::fs::create_dir_all(&vault_dir).unwrap();
        Vault::create(
            &vault_dir.join("default.vault"),
            "Default",
            PASSWORD.as_bytes(),
            KdfParams::FAST_FOR_TESTS,
        )
        .unwrap();
        if write_default_alias {
            secret_manager::dbus::state::save_aliases_to(
                &vault_dir,
                &BTreeMap::from([("default".to_string(), "default".to_string())]),
            )
            .unwrap();
        }
        let pinentry_log = runtime_dir.path().join("pinentry.log");
        let mut config = Config {
            vault: VaultConfig {
                dir: vault_dir.clone(),
                auto_lock_after: idle,
                lock_memory: false,
                locked_search: true,
            },
            prompt: PromptConfig {
                pinentry: fake_pinentry().to_string_lossy().into_owned(),
            },
            kdf: KdfConfig {
                m_cost_kib: 8,
                t_cost: 1,
                p_cost: 1,
            },
        };
        mutate(&mut config);
        let config_dir = data_dir.path().join("config").join("secret-manager");
        std::fs::create_dir_all(&config_dir).unwrap();
        std::fs::write(
            config_dir.join("config.toml"),
            format!(
                "[vault]\ndir = \"{}\"\n[prompt]\npinentry = \"{}\"\n[kdf]\nm_cost_kib = 8\nt_cost = 1\np_cost = 1\n",
                vault_dir.display(),
                fake_pinentry().display()
            ),
        )
        .unwrap();
        let mut pinentry_env = vec![(
            "FAKE_LOG".to_string(),
            pinentry_log.to_string_lossy().into_owned(),
        )];
        if let Some(p) = pin {
            pinentry_env.push(("FAKE_PIN".to_string(), p.to_string()));
        }
        pinentry_env.extend(extra_pinentry_env);
        let opts = DaemonOptions {
            config,
            bus: BusAddress::Address(bus.address.clone()),
            control_socket: Some(
                runtime_dir
                    .path()
                    .join("secret-manager")
                    .join("control.sock"),
            ),
            pinentry_env,
            idle_check_interval: Duration::from_millis(200),
        };
        let daemon = Daemon::start(opts).await.expect("daemon starts");
        Fixture {
            bus,
            data_dir,
            runtime_dir,
            daemon,
            pinentry_log,
            pin: pin.map(str::to_string),
        }
    }

    pub async fn client(&self) -> Connection {
        zbus::connection::Builder::address(self.bus.address.as_str())
            .unwrap()
            .build()
            .await
            .unwrap()
    }

    pub fn control_socket(&self) -> PathBuf {
        self.runtime_dir
            .path()
            .join("secret-manager")
            .join("control.sock")
    }

    pub fn default_collection(&self) -> OwnedObjectPath {
        secret_manager::dbus::paths::collection("default")
    }

    /// Environment for spawning the CLI against this fixture.
    pub fn envs(&self) -> Vec<(String, String)> {
        let mut v = vec![
            (
                "DBUS_SESSION_BUS_ADDRESS".to_string(),
                self.bus.address.clone(),
            ),
            (
                "XDG_DATA_HOME".to_string(),
                self.data_dir.path().to_string_lossy().into_owned(),
            ),
            (
                "XDG_RUNTIME_DIR".to_string(),
                self.runtime_dir.path().to_string_lossy().into_owned(),
            ),
            (
                "XDG_CONFIG_HOME".to_string(),
                self.data_dir
                    .path()
                    .join("config")
                    .to_string_lossy()
                    .into_owned(),
            ),
            (
                "PINENTRY".to_string(),
                fake_pinentry().to_string_lossy().into_owned(),
            ),
            (
                "FAKE_LOG".to_string(),
                self.pinentry_log.to_string_lossy().into_owned(),
            ),
        ];
        if let Some(p) = &self.pin {
            v.push(("FAKE_PIN".to_string(), p.clone()));
        }
        v
    }

    pub fn sm(&self) -> assert_cmd::Command {
        let mut cmd = assert_cmd::Command::new(env!("CARGO_BIN_EXE_secret-manager"));
        cmd.env_clear();
        cmd.env("PATH", std::env::var("PATH").unwrap_or_default());
        // The CLI runs as a child process, so its coverage is only recorded if
        // it can write its own profile. `env_clear` above is deliberate — the
        // CLI must not inherit the test runner's environment — but it also
        // removes the variable the profiler needs, which silently reports the
        // whole CLI as unexercised however many times these tests drive it.
        cmd.envs(profiling_env());
        cmd.env("HOME", self.data_dir.path());
        for (k, v) in self.envs() {
            cmd.env(k, v);
        }
        cmd
    }

    pub fn pinentry_log(&self) -> String {
        std::fs::read_to_string(&self.pinentry_log).unwrap_or_default()
    }

    pub async fn unlock_default(&self) {
        secret_manager::dbus::state::with_vault(&self.daemon.state, "default", |v| {
            v.unlock(PASSWORD.as_bytes())
        })
        .await
        .unwrap();
    }

    pub async fn lock_default(&self) {
        secret_manager::dbus::state::with_vault(&self.daemon.state, "default", |v| v.lock()).await;
    }
}

/// Poll until `f` returns true or `timeout` elapses.
pub async fn wait_for<F, Fut>(timeout: Duration, mut f: F) -> bool
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let start = std::time::Instant::now();
    while start.elapsed() < timeout {
        if f().await {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    false
}

/// The coverage profiler's output path, to survive an `env_clear()`.
///
/// A profiled child process records nothing unless it is told where to write
/// its counters, so a test that clears the environment before running the CLI
/// silently reports that whole run as unexercised — however much of the CLI it
/// actually drove. This is not hypothetical: it hid roughly eight points of
/// measured coverage across the CLI until it was found.
///
/// Chain it after every `env_clear()`: `.env_clear().envs(common::profiling_env())`.
pub fn profiling_env() -> Vec<(String, String)> {
    ["LLVM_PROFILE_FILE", "LLVM_PROFILE_DIR"]
        .iter()
        .filter_map(|k| std::env::var(k).ok().map(|v| ((*k).to_string(), v)))
        .collect()
}
