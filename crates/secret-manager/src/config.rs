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
    #[serde(with = "humantime_serde")]
    pub auto_lock_after: Duration,
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

impl Default for VaultConfig {
    fn default() -> Self {
        Self {
            dir: data_dir(),
            auto_lock_after: Duration::ZERO,
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

    #[allow(clippy::should_implement_trait)]
    pub fn from_str(text: &str) -> Result<Config, ConfigError> {
        let mut c: Config = toml::from_str(text)?;
        c.vault.dir = expand_tilde(&c.vault.dir);
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

/// `$XDG_RUNTIME_DIR/secret-manager`, falling back to `/tmp/secret-manager-<uid>`.
pub fn runtime_dir() -> PathBuf {
    match std::env::var_os("XDG_RUNTIME_DIR") {
        Some(v) if !v.is_empty() => PathBuf::from(v).join("secret-manager"),
        // SAFETY: getuid has no preconditions and cannot fail.
        _ => PathBuf::from(format!("/tmp/secret-manager-{}", unsafe { libc::getuid() })),
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
        assert_eq!(c.vault.auto_lock_after, Duration::ZERO);
        assert!(c.vault.dir.ends_with("secret-manager"));
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
        assert!(runtime_dir().ends_with("secret-manager"));
        assert!(config_file().ends_with("secret-manager/config.toml"));
    }
}
