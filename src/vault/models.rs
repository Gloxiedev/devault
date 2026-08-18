use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum CredentialType {
    Password,
    ApiKey,
    ApiToken,
    SshKey,
    SshPassword,
    Vps,
    Git,
    Database,
    Cloud,
    Docker,
    Environment,
    Generic,
}

impl CredentialType {
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "password" => Self::Password,
            "api_key" | "apikey" => Self::ApiKey,
            "api_token" | "apitoken" => Self::ApiToken,
            "ssh_key" | "ssh" => Self::SshKey,
            "ssh_password" => Self::SshPassword,
            "vps" => Self::Vps,
            "git" => Self::Git,
            "database" | "db" => Self::Database,
            "cloud" => Self::Cloud,
            "docker" => Self::Docker,
            "environment" | "env" => Self::Environment,
            _ => Self::Generic,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Password => "password",
            Self::ApiKey => "api_key",
            Self::ApiToken => "api_token",
            Self::SshKey => "ssh_key",
            Self::SshPassword => "ssh_password",
            Self::Vps => "vps",
            Self::Git => "git",
            Self::Database => "database",
            Self::Cloud => "cloud",
            Self::Docker => "docker",
            Self::Environment => "environment",
            Self::Generic => "generic",
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Credential {
    pub id: Uuid,
    pub name: String,
    pub credential_type: CredentialType,
    pub credential: Vec<u8>,
    pub context: String,
    pub description: Option<String>,
    pub tags: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
}

impl Credential {
    pub fn new(
        name: String,
        credential_type: CredentialType,
        credential: Vec<u8>,
        context: String,
        description: Option<String>,
        tags: Vec<String>,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            name,
            credential_type,
            credential,
            context,
            description,
            tags,
            created_at: now,
            updated_at: now,
            last_used_at: None,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct CredentialMetadata {
    pub id: Uuid,
    pub name: String,
    pub credential_type: CredentialType,
    pub context: String,
    pub description: Option<String>,
    pub tags: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
}

impl From<&Credential> for CredentialMetadata {
    fn from(c: &Credential) -> Self {
        Self {
            id: c.id,
            name: c.name.clone(),
            credential_type: c.credential_type.clone(),
            context: c.context.clone(),
            description: c.description.clone(),
            tags: c.tags.clone(),
            created_at: c.created_at,
            updated_at: c.updated_at,
            last_used_at: c.last_used_at,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Server {
    pub id: Uuid,
    pub name: String,
    pub host: String,
    pub port: u16,
    pub username: String,
    pub auth_method: ServerAuthMethod,
    pub credential_id: Option<Uuid>,
    pub tags: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(tag = "type", content = "value")]
pub enum ServerAuthMethod {
    Password(String),
    PrivateKey { key_path: String, passphrase: Option<String> },
    Agent,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct GitCredential {
    pub id: Uuid,
    pub name: String,
    pub host: String,
    pub username: String,
    pub credential_type: GitCredentialType,
    pub credential_id: Uuid,
    pub tags: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "lowercase")]
pub enum GitCredentialType {
    Token,
    UsernamePassword,
    SshKey,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct EnvironmentProfile {
    pub id: Uuid,
    pub name: String,
    pub variables: Vec<EnvironmentVariable>,
    pub tags: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct EnvironmentVariable {
    pub key: String,
    pub value: Vec<u8>,
    pub credential_id: Option<Uuid>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Agent {
    pub id: Uuid,
    pub name: String,
    pub token: String,
    pub permissions: Vec<AgentPermission>,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "snake_case")]
pub enum AgentPermission {
    ListCredentials,
    GetCredential,
    UseCredential,
    ExecuteServer,
    GitAuth,
    Environment,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct SearchQuery {
    pub query: Option<String>,
    pub credential_type: Option<CredentialType>,
    pub tags: Vec<String>,
    pub limit: Option<usize>,
}