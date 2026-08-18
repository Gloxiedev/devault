use thiserror::Error;

#[derive(Error, Debug)]
pub enum DevaultError {
    #[error("Vault not initialized. Run 'devault init' first.")]
    NotInitialized,

    #[error("Vault is locked. Run 'devault unlock' first.")]
    Locked,

    #[error("Invalid master password")]
    InvalidPassword,

    #[error("Credential not found: {0}")]
    NotFound(String),

    #[error("Credential already exists: {0}")]
    AlreadyExists(String),

    #[error("Cryptographic error: {0}")]
    Crypto(String),

    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("SSH error: {0}")]
    Ssh(String),

    #[error("Git error: {0}")]
    Git(#[from] git2::Error),

    #[error("IPC error: {0}")]
    Ipc(String),

    #[error("Agent not authorized: {0}")]
    Unauthorized(String),

    #[error("Invalid input: {0}")]
    InvalidInput(String),

    #[error("Backup error: {0}")]
    Backup(String),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Dialoguer error: {0}")]
    Dialoguer(#[from] dialoguer::Error),

    #[error("UUID error: {0}")]
    Uuid(#[from] uuid::Error),

    #[error("Parse error: {0}")]
    Parse(#[from] chrono::ParseError),
}

pub type Result<T> = std::result::Result<T, DevaultError>;
pub type DevaultResult<T> = std::result::Result<T, DevaultError>;