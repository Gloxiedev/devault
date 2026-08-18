use crate::error::{DevaultError, Result};
use std::path::PathBuf;

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct Config {
    pub vault_path: PathBuf,
    pub socket_path: PathBuf,
    pub daemon: DaemonConfig,
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct DaemonConfig {
    pub enabled: bool,
    pub auto_start: bool,
}

impl Default for Config {
    fn default() -> Self {
        let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
        Self {
            vault_path: home.join(".devault").join("vault.db"),
            socket_path: PathBuf::from("/tmp/devault.sock"),
            daemon: DaemonConfig {
                enabled: true,
                auto_start: false,
            },
        }
    }
}

impl Config {
    pub fn load() -> Result<Self> {
        let config_path = Self::config_path()?;
        if config_path.exists() {
            let content = std::fs::read_to_string(&config_path)?;
            let config: Config = toml::from_str(&content)?;
            Ok(config)
        } else {
            Ok(Self::default())
        }
    }

    pub fn save(&self) -> Result<()> {
        let config_path = Self::config_path()?;
        if let Some(parent) = config_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let content = toml::to_string_pretty(self)?;
        std::fs::write(&config_path, content)?;
        Ok(())
    }

    fn config_path() -> Result<PathBuf> {
        let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
        Ok(home.join(".devault").join("config.toml"))
    }
}