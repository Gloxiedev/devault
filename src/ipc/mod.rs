use crate::vault::models::*;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(tag = "type", content = "data")]
pub enum Request {
    ListCredentials {
        cred_type: Option<CredentialType>,
        tag: Option<String>,
    },
    GetCredential {
        name: String,
    },
    UseCredential {
        name: String,
        operation: String,
    },
    ExecuteServer {
        name: String,
        command: String,
    },
    GitAuth {
        name: String,
    },
    GetEnvProfile {
        name: String,
    },
    Status,
    Ping,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(tag = "type", content = "data")]
pub enum Response {
    Credentials(Vec<CredentialMetadata>),
    CredentialValue(Vec<u8>),
    OperationResult(String),
    GitCredential {
        username: String,
        password: String,
    },
    EnvProfile(EnvironmentProfile),
    Status(crate::vault::VaultStatus),
    Pong,
    Error(String),
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AgentRequest {
    pub token: String,
    pub request: Request,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AgentResponse {
    pub response: Response,
}

pub const DEFAULT_SOCKET_PATH: &str = "/tmp/devault.sock";

pub fn get_socket_path() -> PathBuf {
    std::env::var("DEVAULT_SOCKET")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(DEFAULT_SOCKET_PATH))
}