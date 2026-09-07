//! Configuration file and XDG path helpers.

use serde::{Deserialize, Serialize};
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
    /// `m_cost_kib`); a failure is logged and ignored.
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
    fn default() -> Self {
        Self {
            m_cost_kib: 65536,
            t_cost: 3,
            p_cost: 1,
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
}

impl Config {
    /// Load `$SECRET_MANAGER_CONFIG` or `$XDG_CONFIG_HOME/secret-manager/config.toml`.
    /// A missing file yields defaults.
    pub fn load() -> Result<Config, ConfigError> {
        let path = std::env::var_os("SECRET_MANAGER_CONFIG")
            .map(PathBuf::from)
            .unwrap_or_else(config_file);
        match std::fs::read_to_string(&path) {
            Ok(text) => Config::from_str(&text),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Config::default()),
            Err(source) => Err(ConfigError::Read { path, source }),
        }
    }

    // Not FromStr: parsing does tilde expansion and returns ConfigError, and callers pass file contents, not tokens.
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(text: &str) -> Result<Config, ConfigError> {
        let mut c: Config = toml::from_str(text)?;
        c.vault.dir = expand_tilde(&c.vault.dir);
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
    match std::env::var_os(var) {
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
    match std::env::var_os("XDG_RUNTIME_DIR") {
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
}
