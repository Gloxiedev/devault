use crate::error::{DevaultError, Result};
use crate::vault::models::*;
use russh::client;
use russh::keys::load_secret_key;
use std::path::Path;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, BufReader};

pub async fn execute(server: &Server, command: &str) -> Result<String> {
    match &server.auth_method {
        ServerAuthMethod::Password(password) => execute_password(server, command, password).await,
        ServerAuthMethod::PrivateKey { key_path, passphrase } => execute_key(server, command, key_path, passphrase.as_deref()).await,
        ServerAuthMethod::Agent => Err(DevaultError::Ssh("SSH agent authentication not yet supported".into())),
    }
}

async fn run_command_on_channel(channel: russh::Channel<russh::client::Msg>, command: &str) -> Result<String> {
    channel.exec(true, command).await
        .map_err(|e| DevaultError::Ssh(e.to_string()))?;

    let mut output = String::new();
    let mut reader = BufReader::new(channel.into_stream());
    let mut line = String::new();
    while reader.read_line(&mut line).await.map_err(|e| DevaultError::Ssh(e.to_string()))? > 0 {
        output.push_str(&line);
        line.clear();
    }

    Ok(output)
}

async fn execute_password(server: &Server, command: &str, password: &str) -> Result<String> {
    let config = client::Config::default();
    let sh = ClientHandler { host: server.host.clone(), port: server.port };
    let mut session = client::connect(Arc::new(config), (server.host.as_str(), server.port), sh).await
        .map_err(|e| DevaultError::Ssh(e.to_string()))?;

    session.authenticate_password(server.username.clone(), password).await
        .map_err(|e| DevaultError::Ssh(e.to_string()))?;

    let channel = session.channel_open_session().await
        .map_err(|e| DevaultError::Ssh(e.to_string()))?;
    
    let output = run_command_on_channel(channel, command).await?;
    Ok(output)
}

async fn execute_key(server: &Server, command: &str, key_path: &str, passphrase: Option<&str>) -> Result<String> {
    let key_path = Path::new(key_path);
    let key_pair = load_secret_key(key_path, passphrase)
        .map_err(|e| DevaultError::Ssh(format!("Failed to load key: {}", e)))?;

    let config = client::Config::default();
    let sh = ClientHandler { host: server.host.clone(), port: server.port };
    let mut session = client::connect(Arc::new(config), (server.host.as_str(), server.port), sh).await
        .map_err(|e| DevaultError::Ssh(e.to_string()))?;

    let key_with_hash = russh::keys::PrivateKeyWithHashAlg::new(std::sync::Arc::new(key_pair), None);
    session.authenticate_publickey(server.username.clone(), key_with_hash).await
        .map_err(|e| DevaultError::Ssh(e.to_string()))?;

    let channel = session.channel_open_session().await
        .map_err(|e| DevaultError::Ssh(e.to_string()))?;
    
    let output = run_command_on_channel(channel, command).await?;
    Ok(output)
}

struct ClientHandler {
    host: String,
    port: u16,
}

impl client::Handler for ClientHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        key: &russh::keys::PublicKey,
    ) -> std::result::Result<bool, Self::Error> {
        let known_hosts_path = dirs::home_dir()
            .unwrap_or_default()
            .join(".devault")
            .join("known_hosts");
        
        let key_fingerprint = format!("{:?}", key);
        
        if known_hosts_path.exists() {
            if let Ok(contents) = std::fs::read_to_string(&known_hosts_path) {
                let entry = format!(":{} {}", self.port, key_fingerprint);
                if contents.lines().any(|line| line == entry) {
                    return Ok(true);
                }
            }
        }

        eprintln!("Warning: Unknown host key for {}:{}", self.host, self.port);
        eprintln!("Accept? (yes/no): ");
        
        let mut input = String::new();
        std::io::stdin().read_line(&mut input).map_err(|e| russh::Error::IO(e))?;
        
        if input.trim().eq_ignore_ascii_case("yes") || input.trim().eq_ignore_ascii_case("y") {
            let entry = format!(":{} {}\n", self.port, key_fingerprint);
            let mut contents = if known_hosts_path.exists() {
                std::fs::read_to_string(&known_hosts_path).unwrap_or_default()
            } else {
                String::new()
            };
            contents.push_str(&format!("{}{}", self.host, entry));
            let _ = known_hosts_path.parent().map(|p| std::fs::create_dir_all(p));
            let _ = std::fs::write(&known_hosts_path, contents);
            return Ok(true);
        }

        Ok(false)
    }
}

pub async fn test_connection(server: &Server) -> Result<()> {
    let _ = execute(server, "echo 'Connection test successful'").await?;
    Ok(())
}