use crate::error::{DevaultError, Result};
use crate::ipc::{AgentRequest, Request, Response, get_socket_path};
use crate::vault::models::*;
use std::path::PathBuf;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use serde_json;

pub struct DevaultAgent {
    socket_path: PathBuf,
    token: String,
}

impl DevaultAgent {
    pub fn new(token: String) -> Self {
        Self {
            socket_path: get_socket_path(),
            token,
        }
    }

    pub fn with_socket(socket_path: PathBuf, token: String) -> Self {
        Self {
            socket_path,
            token,
        }
    }

    async fn send_request(&self, request: Request) -> Result<Response> {
        let stream = UnixStream::connect(&self.socket_path).await
            .map_err(|e| DevaultError::Ipc(format!("Connection failed: {}", e)))?;

        let (reader, mut writer) = stream.into_split();
        let mut reader = BufReader::new(reader);

        let agent_request = AgentRequest {
            token: self.token.clone(),
            request,
        };

        let request_json = serde_json::to_string(&agent_request)
            .map_err(|e| DevaultError::Ipc(e.to_string()))?;
        
        writer.write_all(request_json.as_bytes()).await?;
        writer.write_all(b"\n").await?;
        writer.flush().await?;

        let mut line = String::new();
        reader.read_line(&mut line).await
            .map_err(|e| DevaultError::Ipc(e.to_string()))?;

        let response: Response = serde_json::from_str(line.trim())
            .map_err(|e| DevaultError::Ipc(e.to_string()))?;

        Ok(response)
    }

    pub async fn list_credentials(&self, cred_type: Option<CredentialType>, tag: Option<String>) -> Result<Vec<CredentialMetadata>> {
        let response = self.send_request(Request::ListCredentials { cred_type, tag }).await?;
        match response {
            Response::Credentials(creds) => Ok(creds),
            Response::Error(e) => Err(DevaultError::Ipc(e)),
            _ => Err(DevaultError::Ipc("Unexpected response".into())),
        }
    }

    pub async fn get_credential(&self, name: &str) -> Result<Vec<u8>> {
        let response = self.send_request(Request::GetCredential { name: name.into() }).await?;
        match response {
            Response::CredentialValue(value) => Ok(value),
            Response::Error(e) => Err(DevaultError::Ipc(e)),
            _ => Err(DevaultError::Ipc("Unexpected response".into())),
        }
    }

    pub async fn use_credential(&self, name: &str, operation: &str) -> Result<String> {
        let response = self.send_request(Request::UseCredential { 
            name: name.into(), 
            operation: operation.into() 
        }).await?;
        match response {
            Response::OperationResult(result) => Ok(result),
            Response::Error(e) => Err(DevaultError::Ipc(e)),
            _ => Err(DevaultError::Ipc("Unexpected response".into())),
        }
    }

    pub async fn execute_server(&self, name: &str, command: &str) -> Result<String> {
        let response = self.send_request(Request::ExecuteServer { 
            name: name.into(), 
            command: command.into() 
        }).await?;
        match response {
            Response::OperationResult(result) => Ok(result),
            Response::Error(e) => Err(DevaultError::Ipc(e)),
            _ => Err(DevaultError::Ipc("Unexpected response".into())),
        }
    }

    pub async fn git_auth(&self, name: &str) -> Result<(String, String)> {
        let response = self.send_request(Request::GitAuth { name: name.into() }).await?;
        match response {
            Response::GitCredential { username, password } => Ok((username, password)),
            Response::Error(e) => Err(DevaultError::Ipc(e)),
            _ => Err(DevaultError::Ipc("Unexpected response".into())),
        }
    }

    pub async fn get_env_profile(&self, name: &str) -> Result<EnvironmentProfile> {
        let response = self.send_request(Request::GetEnvProfile { name: name.into() }).await?;
        match response {
            Response::EnvProfile(profile) => Ok(profile),
            Response::Error(e) => Err(DevaultError::Ipc(e)),
            _ => Err(DevaultError::Ipc("Unexpected response".into())),
        }
    }

    pub async fn status(&self) -> Result<crate::vault::VaultStatus> {
        let response = self.send_request(Request::Status).await?;
        match response {
            Response::Status(status) => Ok(status),
            Response::Error(e) => Err(DevaultError::Ipc(e)),
            _ => Err(DevaultError::Ipc("Unexpected response".into())),
        }
    }

    pub async fn ping(&self) -> Result<bool> {
        let response = self.send_request(Request::Ping).await?;
        match response {
            Response::Pong => Ok(true),
            _ => Ok(false),
        }
    }
}

pub async fn create_agent_skill(token: String) -> Result<DevaultAgent> {
    let agent = DevaultAgent::new(token);
    agent.ping().await?;
    Ok(agent)
}