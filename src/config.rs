//! The config file (`~/.config/passmng/config.toml`) that records where the
//! vault lives.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::fsutil;

/// File name of the vault inside the vault directory.
pub const VAULT_FILE_NAME: &str = "vault.bin";

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct Config {
    /// Absolute path of the directory that holds the vault file.
    pub vault_dir: PathBuf,
}

impl Config {
    /// Path of the vault file.
    pub fn vault_path(&self) -> PathBuf {
        self.vault_dir.join(VAULT_FILE_NAME)
    }

    pub fn load(path: &Path) -> Result<Self> {
        let text = fs::read_to_string(path)
            .with_context(|| format!("failed to read config {}", path.display()))?;
        toml::from_str(&text).with_context(|| format!("invalid config {}", path.display()))
    }

    /// Writes the config, creating its parent directory when needed.
    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(dir) = path.parent() {
            fsutil::create_private_dir_all(dir)?;
        }
        let text = toml::to_string(self).context("failed to serialize config")?;
        fsutil::write_atomic(path, text.as_bytes())
    }
}

/// Default location of the config file: `~/.config/passmng/config.toml`.
pub fn default_path() -> Result<PathBuf> {
    let dir = dirs::config_dir().context("cannot determine the config directory")?;
    Ok(dir.join("passmng").join("config.toml"))
}

/// Default vault directory offered by `init`: `~/.local/share/passmng`.
pub fn default_vault_dir() -> Result<PathBuf> {
    let dir = dirs::data_dir().context("cannot determine the data directory")?;
    Ok(dir.join("passmng"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn save_and_load_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested").join("config.toml");
        let config = Config {
            vault_dir: PathBuf::from("/home/user/vault"),
        };
        config.save(&path).unwrap();
        assert_eq!(Config::load(&path).unwrap(), config);
    }

    #[test]
    fn load_rejects_invalid_config() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        fs::write(&path, "unknown = 1\n").unwrap();
        assert!(Config::load(&path).is_err());
    }

    #[test]
    fn vault_path_is_inside_vault_dir() {
        let config = Config {
            vault_dir: PathBuf::from("/v"),
        };
        assert_eq!(config.vault_path(), PathBuf::from("/v/vault.bin"));
    }
}
