//! Configuration file and XDG path helpers.

use serde::{Deserialize, Serialize};
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::Duration;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub vault: VaultConfig,
    pub prompt: PromptConfig,
    pub kdf: KdfConfig,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct VaultConfig {
    pub dir: PathBuf,
    /// Lock every collection after this much time without a secret access.
    /// `0s` disables auto-lock.
    #[serde(with = "humantime_serde")]
    pub auto_lock_after: Duration,
    /// `mlockall` the daemon so secrets are never paged to swap. Needs
    /// `RLIMIT_MEMLOCK` large enough for the process (Argon2 alone maps
    /// `m_cost_kib`).
    ///
    /// **A failure is fatal, not ignored.** `Daemon::start` propagates it as
    /// `DaemonError::Hardening` and the daemon refuses to start: the setting
    /// was asked for, and starting anyway would leave the operator believing
    /// in a property that is not being provided. Do not "restore" an
    /// ignore-on-failure path here - the refusal is the invariant.
    pub lock_memory: bool,
    /// Hash item attributes into the vault header so `SearchItems` works
    /// while locked. Off means a file holder learns only the item count, and
    /// searches match nothing until the collection is unlocked.
    pub locked_search: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PromptConfig {
    pub pinentry: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct KdfConfig {
    pub m_cost_kib: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

impl KdfConfig {
    /// OWASP's minimum for Argon2id: 19 MiB and two passes.
    pub const MIN_RECOMMENDED_M_COST_KIB: u32 = 19 * 1024;
    pub const MIN_RECOMMENDED_T_COST: u32 = 2;

    pub fn below_recommended_floor(&self) -> bool {
        self.m_cost_kib < Self::MIN_RECOMMENDED_M_COST_KIB
            || self.t_cost < Self::MIN_RECOMMENDED_T_COST
    }
}

impl From<KdfConfig> for crate::vault::crypto::KdfParams {
    fn from(c: KdfConfig) -> Self {
        Self {
            m_cost_kib: c.m_cost_kib,
            t_cost: c.t_cost,
            p_cost: c.p_cost,
        }
    }
}

impl Default for VaultConfig {
    fn default() -> Self {
        Self {
            dir: data_dir(),
            auto_lock_after: Duration::from_secs(15 * 60),
            lock_memory: false,
            locked_search: true,
        }
    }
}

impl Default for PromptConfig {
    fn default() -> Self {
        Self {
            pinentry: std::env::var("PINENTRY").unwrap_or_else(|_| "pinentry".to_string()),
        }
    }
}

impl Default for KdfConfig {
    /// One number per cost, not two that can drift: the shipped Argon2
    /// parameters are stated once, in `KdfParams::default`, and this is the
    /// same three numbers read back out. `defaults_match_spec` asserts the
    /// two agree as well as asserting the literals the spec names.
    fn default() -> Self {
        let p = crate::vault::crypto::KdfParams::default();
        Self {
            m_cost_kib: p.m_cost_kib,
            t_cost: p.t_cost,
            p_cost: p.p_cost,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("cannot read {path}: {source}")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("invalid config: {0}")]
    Parse(#[from] toml::de::Error),
    #[error("[kdf] is unusable: {0}")]
    UnusableKdf(String),
}

impl Config {
    /// Load `$SECRET_MANAGER_CONFIG` or `$XDG_CONFIG_HOME/secret-manager/config.toml`.
    /// A missing file yields defaults.
    pub fn load() -> Result<Config, ConfigError> {
        let path = std::env::var_os("SECRET_MANAGER_CONFIG")
            .map(PathBuf::from)
            .unwrap_or_else(config_file);
        Config::load_from(&path)
    }

    /// [`Config::load`] with the file chosen by the caller instead of by the
    /// environment. `load` reads process-global state, which a test cannot
    /// set without `unsafe` and cannot set at all while other tests run in
    /// parallel; everything after the path is decided lives here so it can be
    /// exercised directly.
    fn load_from(path: &Path) -> Result<Config, ConfigError> {
        match std::fs::read_to_string(path) {
            Ok(text) => Config::from_str(&text),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Config::default()),
            Err(source) => Err(ConfigError::Read {
                path: path.to_path_buf(),
                source,
            }),
        }
    }

    // Not FromStr: parsing does tilde expansion and returns ConfigError, and callers pass file contents, not tokens.
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(text: &str) -> Result<Config, ConfigError> {
        let mut c: Config = toml::from_str(text)?;
        c.vault.dir = expand_tilde(&c.vault.dir);
        // Catch an out-of-range setting at startup rather than at the first
        // `sm init` or password change.
        let params: crate::vault::crypto::KdfParams = c.kdf.into();
        params
            .validate()
            .map_err(|e| ConfigError::UnusableKdf(e.to_string()))?;
        if c.kdf.below_recommended_floor() {
            tracing::warn!(
                "[kdf] is below the recommended floor ({} KiB, {} passes); vaults created with it are easier to brute-force",
                KdfConfig::MIN_RECOMMENDED_M_COST_KIB,
                KdfConfig::MIN_RECOMMENDED_T_COST
            );
        }
        Ok(c)
    }
}

fn expand_tilde(p: &Path) -> PathBuf {
    if let Ok(rest) = p.strip_prefix("~") {
        home_dir().join(rest)
    } else {
        p.to_path_buf()
    }
}

pub fn home_dir() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/"))
}

fn xdg(var: &str, fallback: &str) -> PathBuf {
    xdg_value(std::env::var_os(var), fallback)
}

/// [`xdg`] with the environment value supplied by the caller, so the
/// unset-or-empty fallback is reachable without mutating the process
/// environment out from under tests running in parallel.
fn xdg_value(value: Option<OsString>, fallback: &str) -> PathBuf {
    match value {
        Some(v) if !v.is_empty() => PathBuf::from(v),
        _ => home_dir().join(fallback),
    }
}

/// `$XDG_DATA_HOME/secret-manager`
pub fn data_dir() -> PathBuf {
    xdg("XDG_DATA_HOME", ".local/share").join("secret-manager")
}

/// `$XDG_CONFIG_HOME/secret-manager/config.toml`
pub fn config_file() -> PathBuf {
    xdg("XDG_CONFIG_HOME", ".config")
        .join("secret-manager")
        .join("config.toml")
}

/// `$XDG_RUNTIME_DIR/secret-manager`, or `None` if `XDG_RUNTIME_DIR` is unset
/// or empty. There is no world-writable fallback: a runtime dir without a
/// private `$XDG_RUNTIME_DIR` is not safe to use.
pub fn runtime_dir() -> Option<PathBuf> {
    runtime_dir_from(std::env::var_os("XDG_RUNTIME_DIR"))
}

/// [`runtime_dir`] with the environment value supplied by the caller. See
/// [`xdg_value`] for why the environment read is separated out.
fn runtime_dir_from(value: Option<OsString>) -> Option<PathBuf> {
    match value {
        Some(v) if !v.is_empty() => Some(PathBuf::from(v).join("secret-manager")),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn defaults_match_spec() {
        let c = Config::default();
        assert_eq!(c.kdf.m_cost_kib, 65536);
        assert_eq!(c.kdf.t_cost, 3);
        assert_eq!(c.kdf.p_cost, 1);
        // The literals above are the spec's; these are the vault layer's own
        // defaults, and the two must be the same three numbers. `KdfConfig`
        // is defined from `KdfParams` so they cannot drift, and this fails if
        // that definition is ever unwound back into a second set of literals.
        assert_eq!(
            crate::vault::crypto::KdfParams::from(c.kdf),
            crate::vault::crypto::KdfParams::default()
        );
        assert_eq!(c.prompt.pinentry, "pinentry");
        assert_eq!(c.vault.auto_lock_after, Duration::from_secs(15 * 60));
        assert!(!c.vault.lock_memory);
        assert!(c.vault.locked_search);
        assert!(c.vault.dir.ends_with("secret-manager"));
    }

    #[test]
    fn weak_kdf_is_flagged_but_still_parses() {
        let c = Config::from_str("[kdf]\nm_cost_kib = 8\nt_cost = 1\n").unwrap();
        assert!(c.kdf.below_recommended_floor());
        assert!(!KdfConfig::default().below_recommended_floor());
        assert!(
            !KdfConfig {
                m_cost_kib: 19456,
                t_cost: 2,
                p_cost: 1
            }
            .below_recommended_floor()
        );
    }

    #[test]
    fn parses_memory_and_search_flags() {
        let c = Config::from_str("[vault]\nlock_memory = true\nlocked_search = false\n").unwrap();
        assert!(c.vault.lock_memory);
        assert!(!c.vault.locked_search);
    }

    #[test]
    fn parses_partial_file() {
        let text = r#"
[vault]
auto_lock_after = "15m"
[prompt]
pinentry = "/usr/bin/pinentry-tty"
"#;
        let c = Config::from_str(text).unwrap();
        assert_eq!(c.vault.auto_lock_after, Duration::from_secs(900));
        assert_eq!(c.prompt.pinentry, "/usr/bin/pinentry-tty");
        assert_eq!(c.kdf.t_cost, 3);
    }

    #[test]
    fn rejects_kdf_parameters_the_daemon_could_not_run() {
        let err = Config::from_str("[kdf]\nm_cost_kib = 4000000\n").unwrap_err();
        assert!(matches!(err, ConfigError::UnusableKdf(_)), "{err:?}");
        // The shipped defaults and a deliberately weak-but-legal set both load.
        assert!(Config::from_str("").is_ok());
        assert!(Config::from_str("[kdf]\nm_cost_kib = 8\nt_cost = 1\np_cost = 1\n").is_ok());
    }

    #[test]
    fn rejects_unknown_keys() {
        assert!(Config::from_str("[vault]\nbogus = 1\n").is_err());
    }

    #[test]
    fn expands_tilde_in_vault_dir() {
        let c = Config::from_str("[vault]\ndir = \"~/vaults\"\n").unwrap();
        assert!(!c.vault.dir.to_string_lossy().starts_with('~'));
        assert!(c.vault.dir.ends_with("vaults"));
    }

    #[test]
    fn xdg_env_overrides() {
        // Tests run in parallel; use unique env keys is not possible, so only assert the shape.
        if let Some(dir) = runtime_dir() {
            assert!(dir.ends_with("secret-manager"));
        }
        assert!(config_file().ends_with("secret-manager/config.toml"));
    }

    /// No config file is the normal case on a fresh install, so it must be
    /// indistinguishable from an empty one rather than an error.
    #[test]
    fn a_config_file_that_is_not_there_yields_the_defaults() {
        let d = tempfile::tempdir().unwrap();
        let c = Config::load_from(&d.path().join("config.toml")).unwrap();
        assert_eq!(c, Config::default());
    }

    /// A file that exists but cannot be read is the opposite case: silently
    /// falling back to the defaults would run the daemon with settings the
    /// operator did not choose, so it has to be an error that names the path.
    #[test]
    fn a_config_file_that_cannot_be_read_is_reported_with_its_path() {
        let d = tempfile::tempdir().unwrap();
        // A directory where the file should be: present, so not `NotFound`,
        // and `read_to_string` refuses it.
        let path = d.path().join("config.toml");
        std::fs::create_dir(&path).unwrap();

        let err = Config::load_from(&path).unwrap_err();
        let ConfigError::Read { path: p, .. } = &err else {
            panic!("{err:?}");
        };
        assert_eq!(p, &path);
    }

    /// A file that is there and readable is parsed by the same path `load`
    /// takes, so the seam cannot drift from `from_str`.
    #[test]
    fn a_readable_config_file_is_parsed() {
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("config.toml");
        std::fs::write(&path, "[prompt]\npinentry = \"/usr/bin/pinentry-tty\"\n").unwrap();
        let c = Config::load_from(&path).unwrap();
        assert_eq!(c.prompt.pinentry, "/usr/bin/pinentry-tty");
    }

    /// An XDG variable that is unset *or* empty falls back under `$HOME`; an
    /// empty one must not produce a path rooted at the filesystem root.
    #[test]
    fn an_unset_or_empty_xdg_variable_falls_back_under_home() {
        let fallback = home_dir().join(".config");
        assert_eq!(xdg_value(None, ".config"), fallback);
        assert_eq!(xdg_value(Some(OsString::new()), ".config"), fallback);
        assert_eq!(
            xdg_value(Some(OsString::from("/xdg")), ".config"),
            PathBuf::from("/xdg")
        );
    }

    /// There is deliberately no fallback for the runtime directory: without a
    /// private `$XDG_RUNTIME_DIR` there is nowhere safe to put the control
    /// socket, so both unset and empty must yield `None` rather than a guess.
    #[test]
    fn no_runtime_directory_without_a_private_xdg_runtime_dir() {
        assert_eq!(runtime_dir_from(None), None);
        assert_eq!(runtime_dir_from(Some(OsString::new())), None);
        assert_eq!(
            runtime_dir_from(Some(OsString::from("/run/user/1000"))),
            Some(PathBuf::from("/run/user/1000/secret-manager"))
        );
    }
}
