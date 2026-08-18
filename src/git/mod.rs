use crate::error::{DevaultError, Result};
use crate::vault::models::*;
use git2::{Cred, CredentialType, RemoteCallbacks, Repository};
use std::path::Path;

pub async fn configure(git_cred: &GitCredential, repo_path: Option<&str>) -> Result<()> {
    let repo_path = repo_path.unwrap_or(".");
    let repo = Repository::open(repo_path)
        .map_err(|e| DevaultError::Git(e))?;

    match git_cred.credential_type {
        GitCredentialType::Token => configure_token(&repo, git_cred).await,
        GitCredentialType::UsernamePassword => configure_password(&repo, git_cred).await,
        GitCredentialType::SshKey => configure_ssh(&repo, git_cred).await,
    }
}

async fn configure_token(repo: &Repository, git_cred: &GitCredential) -> Result<()> {
    let mut config = repo.config()
        .map_err(|e| DevaultError::Git(e))?;
    
    config.set_str(&format!("credential.https://{}.helper", git_cred.host), "!devault git-credential-helper")
        .map_err(|e| DevaultError::Git(e))?;
    
    println!("Git credential helper configured for token auth");
    println!("Run: git config --global credential.helper '!devault git-credential-helper'");
    Ok(())
}

async fn configure_password(repo: &Repository, git_cred: &GitCredential) -> Result<()> {
    let mut config = repo.config()
        .map_err(|e| DevaultError::Git(e))?;
    
    config.set_str(&format!("credential.https://{}.helper", git_cred.host), "!devault git-credential-helper")
        .map_err(|e| DevaultError::Git(e))?;
    
    println!("Git credential helper configured for username/password auth");
    Ok(())
}

async fn configure_ssh(repo: &Repository, git_cred: &GitCredential) -> Result<()> {
    let mut config = repo.config()
        .map_err(|e| DevaultError::Git(e))?;
    
    config.set_str(&format!("credential.ssh://{}.helper", git_cred.host), "!devault git-credential-helper")
        .map_err(|e| DevaultError::Git(e))?;
    
    println!("Git credential helper configured for SSH auth");
    Ok(())
}

pub fn credential_helper() -> Result<()> {
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)
        .map_err(|e| DevaultError::InvalidInput(e.to_string()))?;
    
    let lines: Vec<&str> = input.lines().collect();
    let mut protocol = String::new();
    let mut host = String::new();
    let mut username = String::new();
    
    for line in lines {
        if line.starts_with("protocol=") {
            protocol = line["protocol=".len()..].to_string();
        } else if line.starts_with("host=") {
            host = line["host=".len()..].to_string();
        } else if line.starts_with("username=") {
            username = line["username=".len()..].to_string();
        }
    }
    
    println!("protocol={}", protocol);
    println!("host={}", host);
    println!("username={}", username);
    
    Ok(())
}

pub struct GitCredentialHelper {
    vault_path: std::path::PathBuf,
    password: Option<String>,
}

impl GitCredentialHelper {
    pub fn new(vault_path: std::path::PathBuf, password: Option<String>) -> Self {
        Self { vault_path, password }
    }

    pub async fn get_credential(&self, url: &str, username: &str) -> Result<(String, String)> {
        let password = self.password.as_deref()
            .ok_or_else(|| DevaultError::InvalidInput("Password required for git credential helper".into()))?;
        let vault = crate::vault::Vault::unlock(self.vault_path.clone(), password).await?;
        let git_creds = vault.list_git_credentials().await?;
        
        for gc in git_creds {
            if url.contains(&gc.host) && gc.username == username {
                let cred = vault.get_credential_by_id(gc.credential_id).await?;
                
                let password = String::from_utf8(cred.credential)
                    .map_err(|_| DevaultError::Crypto("Invalid credential encoding".into()))?;
                
                return Ok((gc.username.clone(), password));
            }
        }
        
        Err(DevaultError::NotFound("No matching git credential".into()))
    }
}

pub async fn clone_with_credentials(url: &str, path: &Path, git_cred: &GitCredential, vault: &crate::vault::Vault) -> Result<()> {
    let cred = vault.get_credential_by_id(git_cred.credential_id).await?;
    
    let password = String::from_utf8(cred.credential)
        .map_err(|_| DevaultError::Crypto("Invalid credential encoding".into()))?;

    let mut callbacks = RemoteCallbacks::new();
    callbacks.credentials(move |_url, username_from_url, _allowed_types| {
        let username = username_from_url.unwrap_or(&git_cred.username);
        Cred::userpass_plaintext(username, &password)
    });

    let mut fetch_options = git2::FetchOptions::new();
    fetch_options.remote_callbacks(callbacks);

    let mut builder = git2::build::RepoBuilder::new();
    builder.fetch_options(fetch_options);
    builder.clone(url, path)
        .map_err(|e| DevaultError::Git(e))?;

    Ok(())
}