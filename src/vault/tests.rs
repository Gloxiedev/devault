#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::crypto::{MasterKey, VaultHeader};
    use crate::vault::models::*;
    use crate::vault::Vault;
    use tempfile::tempdir;
    use uuid::Uuid;

    #[tokio::test]
    async fn test_vault_init_and_unlock() {
        let dir = tempdir().unwrap();
        let vault_path = dir.path().join("vault.db");
        let password = "test-password-123";

        let vault = Vault::init(vault_path.clone(), password).await.unwrap();
        assert!(!vault.is_locked().await);

        vault.lock().await.unwrap();
        assert!(vault.is_locked().await);

        let vault = Vault::unlock(vault_path, password).await.unwrap();
        assert!(!vault.is_locked().await);
    }

    #[tokio::test]
    async fn test_wrong_password() {
        let dir = tempdir().unwrap();
        let vault_path = dir.path().join("vault.db");
        let password = "test-password-123";

        Vault::init(vault_path.clone(), password).await.unwrap();
        let result = Vault::unlock(vault_path, "wrong-password").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_add_and_get_credential() {
        let dir = tempdir().unwrap();
        let vault_path = dir.path().join("vault.db");
        let password = "test-password-123";

        let vault = Vault::init(vault_path.clone(), password).await.unwrap();

        let cred = Credential::new(
            "github".into(),
            CredentialType::ApiToken,
            b"ghp_test123".to_vec(),
            "GitHub personal access token".into(),
            Some("My GitHub token".into()),
            vec!["development".into(), "github".into()],
        );
        vault.add_credential(cred).await.unwrap();

        let retrieved = vault.get_credential("github").await.unwrap();
        assert_eq!(retrieved.name, "github");
        assert_eq!(retrieved.credential_type, CredentialType::ApiToken);
        assert_eq!(retrieved.credential, b"ghp_test123");
        assert_eq!(retrieved.context, "GitHub personal access token");
        assert_eq!(retrieved.tags, vec!["development", "github"]);
    }

    #[tokio::test]
    async fn test_list_credentials() {
        let dir = tempdir().unwrap();
        let vault_path = dir.path().join("vault.db");
        let password = "test-password-123";

        let vault = Vault::init(vault_path.clone(), password).await.unwrap();

        vault.add_credential(Credential::new(
            "github".into(),
            CredentialType::ApiToken,
            b"token1".to_vec(),
            "GitHub".into(),
            None,
            vec!["dev".into()],
        )).await.unwrap();

        vault.add_credential(Credential::new(
            "aws".into(),
            CredentialType::ApiKey,
            b"key1".to_vec(),
            "AWS".into(),
            None,
            vec!["prod".into()],
        )).await.unwrap();

        let creds = vault.list_credentials(None, None).await.unwrap();
        assert_eq!(creds.len(), 2);

        let api_tokens = vault.list_credentials(Some(CredentialType::ApiToken), None).await.unwrap();
        assert_eq!(api_tokens.len(), 1);
        assert_eq!(api_tokens[0].name, "github");

        let tagged = vault.list_credentials(None, Some("prod")).await.unwrap();
        assert_eq!(tagged.len(), 1);
        assert_eq!(tagged[0].name, "aws");
    }

    #[tokio::test]
    async fn test_search_credentials() {
        let dir = tempdir().unwrap();
        let vault_path = dir.path().join("vault.db");
        let password = "test-password-123";

        let vault = Vault::init(vault_path.clone(), password).await.unwrap();

        vault.add_credential(Credential::new(
            "github-token".into(),
            CredentialType::ApiToken,
            b"ghp_123".to_vec(),
            "GitHub personal access token".into(),
            None,
            vec!["github".into()],
        )).await.unwrap();

        vault.add_credential(Credential::new(
            "gitlab-token".into(),
            CredentialType::ApiToken,
            b"glpat_123".to_vec(),
            "GitLab personal access token".into(),
            None,
            vec!["gitlab".into()],
        )).await.unwrap();

        let results = vault.search_credentials(&SearchQuery {
            query: Some("github".into()),
            credential_type: None,
            tags: vec![],
            limit: None,
        }).await.unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "github-token");

        let results = vault.search_credentials(&SearchQuery {
            query: Some("token".into()),
            credential_type: None,
            tags: vec![],
            limit: None,
        }).await.unwrap();
        assert_eq!(results.len(), 2);
    }

    #[tokio::test]
    async fn test_update_credential() {
        let dir = tempdir().unwrap();
        let vault_path = dir.path().join("vault.db");
        let password = "test-password-123";

        let vault = Vault::init(vault_path.clone(), password).await.unwrap();

        vault.add_credential(Credential::new(
            "test".into(),
            CredentialType::Password,
            b"old-password".to_vec(),
            "Test".into(),
            None,
            vec![],
        )).await.unwrap();

        let mut cred = vault.get_credential("test").await.unwrap();
        cred.credential = b"new-password".to_vec();
        cred.context = "Updated".into();
        cred.tags = vec!["updated".into()];
        vault.update_credential(cred).await.unwrap();

        let updated = vault.get_credential("test").await.unwrap();
        assert_eq!(updated.credential, b"new-password");
        assert_eq!(updated.context, "Updated");
        assert_eq!(updated.tags, vec!["updated"]);
    }

    #[tokio::test]
    async fn test_remove_credential() {
        let dir = tempdir().unwrap();
        let vault_path = dir.path().join("vault.db");
        let password = "test-password-123";

        let vault = Vault::init(vault_path.clone(), password).await.unwrap();

        vault.add_credential(Credential::new(
            "test".into(),
            CredentialType::Password,
            b"password".to_vec(),
            "Test".into(),
            None,
            vec![],
        )).await.unwrap();

        vault.remove_credential("test").await.unwrap();
        let result = vault.get_credential("test").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_servers() {
        let dir = tempdir().unwrap();
        let vault_path = dir.path().join("vault.db");
        let password = "test-password-123";

        let vault = Vault::init(vault_path.clone(), password).await.unwrap();

        let server = Server {
            id: Uuid::new_v4(),
            name: "production".into(),
            host: "example.com".into(),
            port: 22,
            username: "ubuntu".into(),
            auth_method: ServerAuthMethod::Password("secret".into()),
            credential_id: None,
            tags: vec!["production".into()],
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        vault.add_server(server).await.unwrap();

        let servers = vault.list_servers(None).await.unwrap();
        assert_eq!(servers.len(), 1);
        assert_eq!(servers[0].name, "production");

        let prod = vault.get_server("production").await.unwrap();
        assert_eq!(prod.host, "example.com");
        assert_eq!(prod.port, 22);
    }

    #[tokio::test]
    async fn test_git_credentials() {
        let dir = tempdir().unwrap();
        let vault_path = dir.path().join("vault.db");
        let password = "test-password-123";

        let vault = Vault::init(vault_path.clone(), password).await.unwrap();

        let cred = Credential::new(
            "github-token".into(),
            CredentialType::ApiToken,
            b"ghp_123".to_vec(),
            "GitHub".into(),
            None,
            vec![],
        );
        vault.add_credential(cred.clone()).await.unwrap();

        let git_cred = GitCredential {
            id: Uuid::new_v4(),
            name: "github".into(),
            host: "github.com".into(),
            username: "user".into(),
            credential_type: GitCredentialType::Token,
            credential_id: cred.id,
            tags: vec![],
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        vault.add_git_credential(git_cred).await.unwrap();

        let git_creds = vault.list_git_credentials().await.unwrap();
        assert_eq!(git_creds.len(), 1);
        assert_eq!(git_creds[0].name, "github");
    }

    #[tokio::test]
    async fn test_environment_profiles() {
        let dir = tempdir().unwrap();
        let vault_path = dir.path().join("vault.db");
        let password = "test-password-123";

        let vault = Vault::init(vault_path.clone(), password).await.unwrap();

        let profile = EnvironmentProfile {
            id: Uuid::new_v4(),
            name: "production".into(),
            variables: vec![
                EnvironmentVariable {
                    key: "DATABASE_URL".into(),
                    value: b"postgres://...".to_vec(),
                    credential_id: None,
                },
                EnvironmentVariable {
                    key: "API_KEY".into(),
                    value: b"secret".to_vec(),
                    credential_id: None,
                },
            ],
            tags: vec!["prod".into()],
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        vault.add_env_profile(profile).await.unwrap();

        let profiles = vault.list_env_profiles().await.unwrap();
        assert_eq!(profiles.len(), 1);
        assert_eq!(profiles[0].name, "production");
        assert_eq!(profiles[0].variables.len(), 2);
    }

    #[tokio::test]
    async fn test_agents() {
        let dir = tempdir().unwrap();
        let vault_path = dir.path().join("vault.db");
        let password = "test-password-123";

        let vault = Vault::init(vault_path.clone(), password).await.unwrap();

        let agent = Agent {
            id: Uuid::new_v4(),
            name: "opencode".into(),
            token: "test-token-123".into(),
            permissions: vec![
                AgentPermission::ListCredentials,
                AgentPermission::GetCredential,
            ],
            created_at: chrono::Utc::now(),
            last_used_at: None,
        };
        vault.add_agent(agent).await.unwrap();

        let agents = vault.list_agents().await.unwrap();
        assert_eq!(agents.len(), 1);
        assert_eq!(agents[0].name, "opencode");

        let found = vault.get_agent("test-token-123").await.unwrap();
        assert_eq!(found.name, "opencode");

        vault.revoke_agent("opencode").await.unwrap();
        let agents = vault.list_agents().await.unwrap();
        assert_eq!(agents.len(), 0);
    }

    #[tokio::test]
    async fn test_backup_restore() {
        let dir = tempdir().unwrap();
        let vault_path = dir.path().join("vault.db");
        let password = "test-password-123";

        let vault = Vault::init(vault_path.clone(), password).await.unwrap();

        vault.add_credential(Credential::new(
            "test".into(),
            CredentialType::Password,
            b"secret".to_vec(),
            "Test".into(),
            None,
            vec![],
        )).await.unwrap();

        let backup = vault.export_backup("backup-password").await.unwrap();
        assert_eq!(backup.credentials.len(), 1);

        let dir2 = tempdir().unwrap();
        let vault_path2 = dir2.path().join("vault.db");
        let vault2 = Vault::init(vault_path2.clone(), "new-password").await.unwrap();
        vault2.import_backup(backup, "backup-password").await.unwrap();

        let cred = vault2.get_credential("test").await.unwrap();
        assert_eq!(cred.credential, b"secret");
    }

    #[test]
    fn test_master_key_derivation() {
        let key = MasterKey::new();
        let data_key = key.derive_data_key(b"test-context").unwrap();
        
        let plaintext = b"secret data";
        let encrypted = data_key.encrypt(plaintext).unwrap();
        let decrypted = data_key.decrypt(&encrypted).unwrap();
        
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_vault_header() {
        let master_key = MasterKey::new();
        let header = VaultHeader::new(&master_key, "password123").unwrap();
        
        let recovered = header.verify_password("password123").unwrap();
        assert_eq!(recovered.as_bytes(), master_key.as_bytes());

        let wrong = header.verify_password("wrong");
        assert!(wrong.is_err());
    }

    #[test]
    fn test_credential_type_parsing() {
        assert_eq!(CredentialType::from_str("password"), CredentialType::Password);
        assert_eq!(CredentialType::from_str("api_key"), CredentialType::ApiKey);
        assert_eq!(CredentialType::from_str("ssh"), CredentialType::SshKey);
        assert_eq!(CredentialType::from_str("unknown"), CredentialType::Generic);
    }
}