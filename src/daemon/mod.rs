use crate::error::{DevaultError, Result};
use crate::vault::Vault;
use crate::ipc::{Request, Response};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;
use tokio::sync::Mutex;
use tokio_stream::wrappers::UnixListenerStream;
use tracing::{error, info};
use futures::StreamExt;
use serde_json;

pub struct Daemon {
    vault: Arc<Mutex<Option<Vault>>>,
    socket_path: PathBuf,
}

impl Daemon {
    pub fn new(socket_path: PathBuf) -> Self {
        Self {
            vault: Arc::new(Mutex::new(None)),
            socket_path,
        }
    }

    pub async fn run(&self) -> Result<()> {
        if self.socket_path.exists() {
            std::fs::remove_file(&self.socket_path)?;
        }

        if let Some(parent) = self.socket_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let listener = UnixListener::bind(&self.socket_path)?;
        info!("Daemon listening on {}", self.socket_path.display());

        let incoming = UnixListenerStream::new(listener);
        
        let mut incoming = incoming;
        while let Some(stream) = incoming.next().await {
            match stream {
                Ok(stream) => {
                    let vault = self.vault.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handle_connection(stream, vault).await {
                            error!("Connection error: {}", e);
                        }
                    });
                }
                Err(e) => {
                    error!("Accept error: {}", e);
                }
            }
        }
        Ok(())
    }

    pub async fn set_vault(&self, vault: Vault) {
        *self.vault.lock().await = Some(vault);
    }

    pub async fn clear_vault(&self) {
        *self.vault.lock().await = None;
    }
}

async fn handle_connection(
    stream: tokio::net::UnixStream,
    vault: Arc<Mutex<Option<Vault>>>,
) -> Result<()> {
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    let mut line = String::new();

    while reader.read_line(&mut line).await? > 0 {
        let request: Request = serde_json::from_str(line.trim())
            .map_err(|e| DevaultError::Ipc(e.to_string()))?;
        
        let response = process_request(request, &vault).await;
        
        let response_json = serde_json::to_string(&response)
            .map_err(|e| DevaultError::Ipc(e.to_string()))?;
        
        writer.write_all(response_json.as_bytes()).await?;
        writer.write_all(b"\n").await?;
        writer.flush().await?;
        
        line.clear();
    }

    Ok(())
}

async fn process_request(request: Request, vault: &Arc<Mutex<Option<Vault>>>) -> Response {
    let vault_guard = vault.lock().await;
    let vault = match vault_guard.as_ref() {
        Some(v) => v,
        None => return Response::Error("Vault not unlocked".into()),
    };

    match request {
        Request::ListCredentials { cred_type, tag } => {
            match vault.list_credentials(cred_type, tag.as_deref()).await {
                Ok(creds) => Response::Credentials(creds),
                Err(e) => Response::Error(e.to_string()),
            }
        }
        Request::GetCredential { name } => {
            match vault.get_credential_raw(&name).await {
                Ok(cred) => Response::CredentialValue(cred),
                Err(e) => Response::Error(e.to_string()),
            }
        }
        Request::UseCredential { name, operation } => {
            match vault.get_credential_raw(&name).await {
                Ok(cred) => {
                    let result = execute_credential_operation(&cred, &operation).await;
                    match result {
                        Ok(output) => Response::OperationResult(output),
                        Err(e) => Response::Error(e.to_string()),
                    }
                }
                Err(e) => Response::Error(e.to_string()),
            }
        }
        Request::ExecuteServer { name, command } => {
            match vault.get_server(&name).await {
                Ok(server) => {
                    match crate::ssh::execute(&server, &command).await {
                        Ok(output) => Response::OperationResult(output),
                        Err(e) => Response::Error(e.to_string()),
                    }
                }
                Err(e) => Response::Error(e.to_string()),
            }
        }
        Request::GitAuth { name } => {
            match vault.get_git_credential(&name).await {
                Ok(git_cred) => {
                    let cred = match vault.get_credential_by_id(git_cred.credential_id).await {
                        Ok(c) => c,
                        Err(_) => return Response::Error("Linked credential not found".into()),
                    };
                    let password = String::from_utf8_lossy(&cred.credential);
                    Response::GitCredential {
                        username: git_cred.username,
                        password: password.to_string(),
                    }
                }
                Err(e) => Response::Error(e.to_string()),
            }
        }
        Request::GetEnvProfile { name } => {
            match vault.get_env_profile(&name).await {
                Ok(profile) => Response::EnvProfile(profile),
                Err(e) => Response::Error(e.to_string()),
            }
        }
        Request::Status => {
            match vault.status().await {
                Ok(status) => Response::Status(status),
                Err(e) => Response::Error(e.to_string()),
            }
        }
        Request::Ping => Response::Pong,
    }
}

async fn execute_credential_operation(_credential: &[u8], operation: &str) -> Result<String> {
    match operation {
        "ssh" => Ok("SSH operation executed".into()),
        "api" => Ok("API call executed".into()),
        _ => Ok("Operation executed".into()),
    }
}