use crate::error::{DevaultError, Result};
use crate::vault::{Vault, BackupData};
use std::path::PathBuf;

pub async fn create_backup(vault: &Vault, output: Option<PathBuf>, password: &str) -> Result<PathBuf> {
    let backup = vault.export_backup(password).await?;
    let path = output.unwrap_or_else(|| PathBuf::from(format!("devault-backup-{}.json", chrono::Utc::now().format("%Y%m%d-%H%M%S"))));
    tokio::fs::write(&path, serde_json::to_vec(&backup)?).await?;
    Ok(path)
}

pub async fn restore_backup(vault: &Vault, file: PathBuf, password: &str) -> Result<()> {
    let data = tokio::fs::read(&file).await?;
    let backup: BackupData = serde_json::from_slice(&data)?;
    vault.import_backup(backup, password).await?;
    Ok(())
}