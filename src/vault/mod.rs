use crate::error::{DevaultError, Result};
use crate::vault::crypto::{MasterKey, VaultHeader};
use crate::vault::database::VaultDatabase;
use crate::vault::models::*;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

pub mod crypto;
pub mod database;
pub mod models;
pub mod tests;

pub struct Vault {
    db: VaultDatabase,
    master_key: Arc<RwLock<Option<MasterKey>>>,
    vault_path: PathBuf,
    locked: Arc<RwLock<bool>>,
}

impl Vault {
    pub async fn init(vault_path: PathBuf, password: &str) -> Result<Self> {
        if vault_path.exists() {
            return Err(DevaultError::InvalidInput("Vault already exists".into()));
        }

        if let Some(parent) = vault_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let master_key = MasterKey::new();
        let header = VaultHeader::new(&master_key, password)?;

        let db = VaultDatabase::new(&vault_path).await?;
        db.set_header(&header).await?;

        Ok(Self {
            db,
            master_key: Arc::new(RwLock::new(Some(master_key))),
            vault_path,
            locked: Arc::new(RwLock::new(false)),
        })
    }

    pub async fn unlock(vault_path: PathBuf, password: &str) -> Result<Self> {
        let db = VaultDatabase::new(&vault_path).await?;
        let header = db.get_header().await?
            .ok_or(DevaultError::NotInitialized)?;
        let master_key = header.verify_password(password)?;

        Ok(Self {
            db,
            master_key: Arc::new(RwLock::new(Some(master_key))),
            vault_path,
            locked: Arc::new(RwLock::new(false)),
        })
    }

    pub async fn lock(&self) -> Result<()> {
        *self.master_key.write().await = None;
        *self.locked.write().await = true;
        Ok(())
    }

    pub async fn is_locked(&self) -> bool {
        *self.locked.read().await
    }

    pub async fn status(&self) -> Result<VaultStatus> {
        let locked = self.is_locked().await;
        let cred_count = self.db.list_credentials(None, None).await?.len();
        let server_count = self.db.list_servers(None).await?.len();
        let git_count = self.db.list_git_credentials().await?.len();
        let env_count = self.db.list_env_profiles().await?.len();
        let agent_count = self.db.list_agents().await?.len();

        Ok(VaultStatus {
            locked,
            path: self.vault_path.clone(),
            credentials: cred_count,
            servers: server_count,
            git_credentials: git_count,
            environment_profiles: env_count,
            agents: agent_count,
        })
    }

    async fn get_master_key(&self) -> Result<MasterKey> {
        let key = self.master_key.read().await;
        key.as_ref().map(|k| k.clone_key()).ok_or(DevaultError::Locked)
    }

    pub async fn add_credential(&self, mut cred: Credential) -> Result<()> {
        let master_key = self.get_master_key().await?;
        let data_key = master_key.derive_data_key(cred.name.as_bytes())?;
        let encrypted = data_key.encrypt(&cred.credential)?;
        // Store the full EncryptedData as JSON
        cred.credential = serde_json::to_vec(&encrypted)?;
        self.db.insert_credential(&cred).await
    }

    pub async fn get_credential(&self, name: &str) -> Result<Credential> {
        let master_key = self.get_master_key().await?;
        let mut cred = self.db.get_credential(name).await?
            .ok_or_else(|| DevaultError::NotFound(name.into()))?;
        let encrypted: crate::vault::crypto::EncryptedData = serde_json::from_slice(&cred.credential)?;
        let data_key = master_key.derive_data_key(cred.name.as_bytes())?;
        let plaintext = data_key.decrypt(&encrypted)?;
        cred.last_used_at = Some(chrono::Utc::now());
        // Re-encrypt for storage update
        let encrypted = data_key.encrypt(&plaintext)?;
        cred.credential = serde_json::to_vec(&encrypted)?;
        self.db.update_credential(&cred).await?;
        // Return credential with plaintext
        cred.credential = plaintext;
        Ok(cred)
    }

    pub async fn get_credential_raw(&self, name: &str) -> Result<Vec<u8>> {
        let cred = self.get_credential(name).await?;
        Ok(cred.credential)
    }

    pub async fn get_credential_by_id(&self, id: Uuid) -> Result<Credential> {
        let master_key = self.get_master_key().await?;
        let mut cred = self.db.get_credential_by_id(id).await?
            .ok_or_else(|| DevaultError::NotFound(id.to_string()))?;
        let encrypted: crate::vault::crypto::EncryptedData = serde_json::from_slice(&cred.credential)?;
        let data_key = master_key.derive_data_key(cred.name.as_bytes())?;
        let plaintext = data_key.decrypt(&encrypted)?;
        cred.last_used_at = Some(chrono::Utc::now());
        // Re-encrypt for storage update
        let encrypted = data_key.encrypt(&plaintext)?;
        cred.credential = serde_json::to_vec(&encrypted)?;
        self.db.update_credential(&cred).await?;
        // Return credential with plaintext
        cred.credential = plaintext;
        Ok(cred)
    }

    pub async fn list_credentials(&self, cred_type: Option<CredentialType>, tag: Option<&str>) -> Result<Vec<CredentialMetadata>> {
        let creds = self.db.list_credentials(cred_type, tag).await?;
        Ok(creds.iter().map(|c| c.into()).collect())
    }

    pub async fn search_credentials(&self, query: &SearchQuery) -> Result<Vec<CredentialMetadata>> {
        let creds = self.db.search_credentials(query).await?;
        Ok(creds.iter().map(|c| c.into()).collect())
    }

    pub async fn remove_credential(&self, name: &str) -> Result<()> {
        self.db.delete_credential(name).await?;
        Ok(())
    }

    pub async fn update_credential(&self, mut cred: Credential) -> Result<()> {
        let master_key = self.get_master_key().await?;
        let data_key = master_key.derive_data_key(cred.name.as_bytes())?;
        let encrypted = data_key.encrypt(&cred.credential)?;
        cred.credential = serde_json::to_vec(&encrypted)?;
        cred.updated_at = chrono::Utc::now();
        self.db.update_credential(&cred).await
    }

    pub async fn add_server(&self, server: Server) -> Result<()> {
        self.db.insert_server(&server).await
    }

    pub async fn get_server(&self, name: &str) -> Result<Server> {
        self.db.get_server(name).await?
            .ok_or_else(|| DevaultError::NotFound(name.into()))
    }

    pub async fn list_servers(&self, tag: Option<&str>) -> Result<Vec<Server>> {
        self.db.list_servers(tag).await
    }

    pub async fn remove_server(&self, name: &str) -> Result<()> {
        self.db.delete_server(name).await?;
        Ok(())
    }

    pub async fn add_git_credential(&self, git: GitCredential) -> Result<()> {
        self.db.insert_git_credential(&git).await
    }

    pub async fn get_git_credential(&self, name: &str) -> Result<GitCredential> {
        self.db.get_git_credential(name).await?
            .ok_or_else(|| DevaultError::NotFound(name.into()))
    }

    pub async fn list_git_credentials(&self) -> Result<Vec<GitCredential>> {
        self.db.list_git_credentials().await
    }

    pub async fn remove_git_credential(&self, name: &str) -> Result<()> {
        self.db.delete_git_credential(name).await?;
        Ok(())
    }

    pub async fn add_env_profile(&self, profile: EnvironmentProfile) -> Result<()> {
        self.db.insert_env_profile(&profile).await
    }

    pub async fn get_env_profile(&self, name: &str) -> Result<EnvironmentProfile> {
        self.db.get_env_profile(name).await?
            .ok_or_else(|| DevaultError::NotFound(name.into()))
    }

    pub async fn list_env_profiles(&self) -> Result<Vec<EnvironmentProfile>> {
        self.db.list_env_profiles().await
    }

    pub async fn remove_env_profile(&self, name: &str) -> Result<()> {
        self.db.delete_env_profile(name).await?;
        Ok(())
    }

    pub async fn add_agent(&self, agent: Agent) -> Result<()> {
        self.db.insert_agent(&agent).await
    }

    pub async fn get_agent(&self, token: &str) -> Result<Agent> {
        self.db.get_agent_by_token(token).await?
            .ok_or_else(|| DevaultError::Unauthorized("Invalid agent token".into()))
    }

    pub async fn list_agents(&self) -> Result<Vec<Agent>> {
        self.db.list_agents().await
    }

    pub async fn revoke_agent(&self, name: &str) -> Result<()> {
        self.db.revoke_agent(name).await?;
        Ok(())
    }

    pub async fn export_backup(&self, password: &str) -> Result<BackupData> {
        let master_key = self.get_master_key().await?;
        
        let credentials = self.db.list_credentials(None, None).await?;
        let servers = self.db.list_servers(None).await?;
        let git_credentials = self.db.list_git_credentials().await?;
        let env_profiles = self.db.list_env_profiles().await?;
        let agents = self.db.list_agents().await?;

        // Create a new header that encrypts the master key with the backup password
        let backup_header = VaultHeader::new(&master_key, password)?;

        Ok(BackupData {
            version: 1,
            header: backup_header,
            credentials,
            servers,
            git_credentials,
            env_profiles,
            agents,
            exported_at: chrono::Utc::now(),
        })
    }

    pub async fn import_backup(&self, backup: BackupData, password: &str) -> Result<()> {
        // Verify backup password and get the original vault's master key
        let original_master_key = backup.header.verify_password(password)?;

        // Get the new vault's master key for re-encryption
        let new_master_key = self.get_master_key().await?;

        for mut cred in backup.credentials {
            // Decrypt credential using original master key
            let encrypted: crate::vault::crypto::EncryptedData = serde_json::from_slice(&cred.credential)?;
            let data_key = original_master_key.derive_data_key(cred.name.as_bytes())?;
            let plaintext = data_key.decrypt(&encrypted)?;
            
            // Re-encrypt with new vault's master key
            let new_data_key = new_master_key.derive_data_key(cred.name.as_bytes())?;
            let new_encrypted = new_data_key.encrypt(&plaintext)?;
            cred.credential = serde_json::to_vec(&new_encrypted)?;
            
            // Check if credential already exists, update if so
            match self.db.get_credential(&cred.name).await? {
                Some(existing) => {
                    cred.id = existing.id;
                    self.db.update_credential(&cred).await?;
                }
                None => {
                    self.db.insert_credential(&cred).await?;
                }
            }
        }
        for server in backup.servers {
            match self.db.get_server(&server.name).await? {
                Some(existing) => {
                    // Update existing server with new data but keep the id
                    let mut updated = server;
                    updated.id = existing.id;
                    self.db.delete_server(&updated.name).await?;
                    self.db.insert_server(&updated).await?;
                }
                None => {
                    self.db.insert_server(&server).await?;
                }
            }
        }
        for git in backup.git_credentials {
            match self.db.get_git_credential(&git.name).await? {
                Some(_) => {
                    self.db.delete_git_credential(&git.name).await?;
                    self.db.insert_git_credential(&git).await?;
                }
                None => {
                    self.db.insert_git_credential(&git).await?;
                }
            }
        }
        for env in backup.env_profiles {
            match self.db.get_env_profile(&env.name).await? {
                Some(_) => {
                    self.db.delete_env_profile(&env.name).await?;
                    self.db.insert_env_profile(&env).await?;
                }
                None => {
                    self.db.insert_env_profile(&env).await?;
                }
            }
        }
        for agent in backup.agents {
            match self.db.get_agent_by_token(&agent.token).await? {
                Some(_) => {
                    self.db.revoke_agent(&agent.name).await?;
                    self.db.insert_agent(&agent).await?;
                }
                None => {
                    self.db.insert_agent(&agent).await?;
                }
            }
        }

        Ok(())
    }
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct VaultStatus {
    pub locked: bool,
    pub path: PathBuf,
    pub credentials: usize,
    pub servers: usize,
    pub git_credentials: usize,
    pub environment_profiles: usize,
    pub agents: usize,
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct BackupData {
    pub version: u32,
    pub header: VaultHeader,
    pub credentials: Vec<Credential>,
    pub servers: Vec<Server>,
    pub git_credentials: Vec<GitCredential>,
    pub env_profiles: Vec<EnvironmentProfile>,
    pub agents: Vec<Agent>,
    pub exported_at: chrono::DateTime<chrono::Utc>,
}