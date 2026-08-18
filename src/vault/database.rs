use crate::error::{DevaultError, Result};
use crate::vault::models::*;
use crate::vault::crypto::VaultHeader;
use sqlx::{sqlite::SqlitePoolOptions, Row, SqlitePool};
use std::path::Path;
use uuid::Uuid;
use chrono::{DateTime, Utc};

const DB_VERSION: i32 = 1;

pub struct VaultDatabase {
    pool: SqlitePool,
}

impl VaultDatabase {
    pub async fn new(path: &Path) -> Result<Self> {
        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect(&format!("sqlite:{}?mode=rwc", path.display()))
            .await?;
        let db = Self { pool };
        db.migrate().await?;
        Ok(db)
    }

    pub async fn new_in_memory() -> Result<Self> {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await?;
        let db = Self { pool };
        db.migrate().await?;
        Ok(db)
    }

    async fn migrate(&self) -> Result<()> {
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS vault_meta (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            "#,
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS credentials (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL UNIQUE,
                credential_type TEXT NOT NULL,
                credential TEXT NOT NULL,
                context TEXT NOT NULL,
                description TEXT,
                tags TEXT NOT NULL DEFAULT '[]',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                last_used_at TEXT
            );
            "#,
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS servers (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL UNIQUE,
                host TEXT NOT NULL,
                port INTEGER NOT NULL DEFAULT 22,
                username TEXT NOT NULL,
                auth_method TEXT NOT NULL,
                credential_id TEXT,
                tags TEXT NOT NULL DEFAULT '[]',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY (credential_id) REFERENCES credentials(id) ON DELETE SET NULL
            );
            "#,
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS git_credentials (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL UNIQUE,
                host TEXT NOT NULL,
                username TEXT NOT NULL,
                credential_type TEXT NOT NULL,
                credential_id TEXT NOT NULL,
                tags TEXT NOT NULL DEFAULT '[]',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY (credential_id) REFERENCES credentials(id) ON DELETE CASCADE
            );
            "#,
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS environment_profiles (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL UNIQUE,
                variables TEXT NOT NULL DEFAULT '[]',
                tags TEXT NOT NULL DEFAULT '[]',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            "#,
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS agents (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL UNIQUE,
                token TEXT NOT NULL UNIQUE,
                permissions TEXT NOT NULL DEFAULT '[]',
                created_at TEXT NOT NULL,
                last_used_at TEXT
            );
            "#,
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_credentials_name ON credentials(name);"
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_credentials_type ON credentials(credential_type);"
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_servers_name ON servers(name);"
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_git_credentials_name ON git_credentials(name);"
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_env_profiles_name ON environment_profiles(name);"
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_agents_name ON agents(name);"
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn set_header(&self, header: &VaultHeader) -> Result<()> {
        let json = serde_json::to_string(header)?;
        sqlx::query(
            "INSERT OR REPLACE INTO vault_meta (key, value) VALUES ('header', ?1)"
        )
        .bind(json)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn get_header(&self) -> Result<Option<VaultHeader>> {
        let row = sqlx::query("SELECT value FROM vault_meta WHERE key = 'header'")
            .fetch_optional(&self.pool)
            .await?;
        if let Some(row) = row {
            let json: String = row.get("value");
            let header: VaultHeader = serde_json::from_str(&json)?;
            Ok(Some(header))
        } else {
            Ok(None)
        }
    }

    pub async fn insert_credential(&self, cred: &Credential) -> Result<()> {
        let tags = serde_json::to_string(&cred.tags)?;
        let credential_json = serde_json::to_string(&cred.credential)?;
        sqlx::query(
            r#"
            INSERT INTO credentials (id, name, credential_type, credential, context, description, tags, created_at, updated_at, last_used_at)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
            "#,
        )
        .bind(cred.id.to_string())
        .bind(&cred.name)
        .bind(cred.credential_type.as_str())
        .bind(&credential_json)
        .bind(&cred.context)
        .bind(&cred.description)
        .bind(tags)
        .bind(cred.created_at.to_rfc3339())
        .bind(cred.updated_at.to_rfc3339())
        .bind(cred.last_used_at.map(|dt| dt.to_rfc3339()))
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn get_credential(&self, name: &str) -> Result<Option<Credential>> {
        let row = sqlx::query(
            "SELECT * FROM credentials WHERE name = ?1"
        )
        .bind(name)
        .fetch_optional(&self.pool)
        .await?;
        row.map(Self::row_to_credential).transpose()
    }

    pub async fn get_credential_by_id(&self, id: Uuid) -> Result<Option<Credential>> {
        let row = sqlx::query(
            "SELECT * FROM credentials WHERE id = ?1"
        )
        .bind(id.to_string())
        .fetch_optional(&self.pool)
        .await?;
        row.map(Self::row_to_credential).transpose()
    }

    pub async fn list_credentials(&self, cred_type: Option<CredentialType>, tag: Option<&str>) -> Result<Vec<Credential>> {
        let mut query = "SELECT * FROM credentials".to_string();
        let mut conditions = Vec::new();
        
        if cred_type.is_some() {
            conditions.push("credential_type = ?".to_string());
        }
        if tag.is_some() {
            conditions.push("tags LIKE ?".to_string());
        }
        
        if !conditions.is_empty() {
            query.push_str(" WHERE ");
            query.push_str(&conditions.join(" AND "));
        }
        query.push_str(" ORDER BY name");

        let mut q = sqlx::query(&query);
        if let Some(ct) = cred_type {
            q = q.bind(ct.as_str());
        }
        if let Some(t) = tag {
            q = q.bind(format!("%{}%", t));
        }

        let rows = q.fetch_all(&self.pool).await?;
        rows.into_iter().map(Self::row_to_credential).collect()
    }

    pub async fn update_credential(&self, cred: &Credential) -> Result<()> {
        let tags = serde_json::to_string(&cred.tags)?;
        let credential_json = serde_json::to_string(&cred.credential)?;
        sqlx::query(
            r#"
            UPDATE credentials SET credential_type = ?1, credential = ?2, context = ?3, description = ?4, tags = ?5, updated_at = ?6, last_used_at = ?7
            WHERE id = ?8
            "#,
        )
        .bind(cred.credential_type.as_str())
        .bind(&credential_json)
        .bind(&cred.context)
        .bind(&cred.description)
        .bind(tags)
        .bind(cred.updated_at.to_rfc3339())
        .bind(cred.last_used_at.map(|dt| dt.to_rfc3339()))
        .bind(cred.id.to_string())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn delete_credential(&self, name: &str) -> Result<bool> {
        let result = sqlx::query("DELETE FROM credentials WHERE name = ?1")
            .bind(name)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn search_credentials(&self, query: &SearchQuery) -> Result<Vec<Credential>> {
        let mut sql = "SELECT * FROM credentials WHERE 1=1".to_string();
        let mut binds: Vec<String> = Vec::new();

        if let Some(q) = &query.query {
            sql.push_str(" AND (name LIKE ? OR context LIKE ? OR description LIKE ?)");
            let like = format!("%{}%", q);
            binds.push(like.clone());
            binds.push(like.clone());
            binds.push(like);
        }
        if let Some(ct) = &query.credential_type {
            sql.push_str(" AND credential_type = ?");
            binds.push(ct.as_str().to_string());
        }
        for tag in &query.tags {
            sql.push_str(" AND tags LIKE ?");
            binds.push(format!("%{}%", tag));
        }
        sql.push_str(" ORDER BY name");
        if let Some(limit) = query.limit {
            sql.push_str(&format!(" LIMIT {}", limit));
        }

        let mut q = sqlx::query(&sql);
        for b in binds {
            q = q.bind(b);
        }

        let rows = q.fetch_all(&self.pool).await?;
        rows.into_iter().map(Self::row_to_credential).collect()
    }

    fn row_to_credential(row: sqlx::sqlite::SqliteRow) -> Result<Credential> {
        let id: String = row.get("id");
        let tags: String = row.get("tags");
        let credential_json: String = row.get("credential");
        let credential: Vec<u8> = serde_json::from_str(&credential_json)?;
        let created_at: String = row.get("created_at");
        let updated_at: String = row.get("updated_at");
        let last_used_at: Option<String> = row.get("last_used_at");

        Ok(Credential {
            id: Uuid::parse_str(&id)?,
            name: row.get("name"),
            credential_type: CredentialType::from_str(&row.get::<String, _>("credential_type")),
            credential,
            context: row.get("context"),
            description: row.get("description"),
            tags: serde_json::from_str(&tags)?,
            created_at: DateTime::parse_from_rfc3339(&created_at)?.with_timezone(&Utc),
            updated_at: DateTime::parse_from_rfc3339(&updated_at)?.with_timezone(&Utc),
            last_used_at: last_used_at.map(|s| DateTime::parse_from_rfc3339(&s).unwrap().with_timezone(&Utc)),
        })
    }

    pub async fn insert_server(&self, server: &Server) -> Result<()> {
        let tags = serde_json::to_string(&server.tags)?;
        let auth = serde_json::to_string(&server.auth_method)?;
        let cred_id = server.credential_id.map(|id| id.to_string());
        sqlx::query(
            r#"
            INSERT INTO servers (id, name, host, port, username, auth_method, credential_id, tags, created_at, updated_at)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
            "#,
        )
        .bind(server.id.to_string())
        .bind(&server.name)
        .bind(&server.host)
        .bind(server.port as i64)
        .bind(&server.username)
        .bind(auth)
        .bind(cred_id)
        .bind(tags)
        .bind(server.created_at.to_rfc3339())
        .bind(server.updated_at.to_rfc3339())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn get_server(&self, name: &str) -> Result<Option<Server>> {
        let row = sqlx::query("SELECT * FROM servers WHERE name = ?1")
            .bind(name)
            .fetch_optional(&self.pool)
            .await?;
        row.map(Self::row_to_server).transpose()
    }

    pub async fn list_servers(&self, tag: Option<&str>) -> Result<Vec<Server>> {
        let mut query = "SELECT * FROM servers".to_string();
        if tag.is_some() {
            query.push_str(" WHERE tags LIKE ?");
        }
        query.push_str(" ORDER BY name");

        let mut q = sqlx::query(&query);
        if let Some(t) = tag {
            q = q.bind(format!("%\"{}\"", t));
        }

        let rows = q.fetch_all(&self.pool).await?;
        rows.into_iter().map(Self::row_to_server).collect()
    }

    pub async fn delete_server(&self, name: &str) -> Result<bool> {
        let result = sqlx::query("DELETE FROM servers WHERE name = ?1")
            .bind(name)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    fn row_to_server(row: sqlx::sqlite::SqliteRow) -> Result<Server> {
        let id: String = row.get("id");
        let tags: String = row.get("tags");
        let auth: String = row.get("auth_method");
        let cred_id: Option<String> = row.get("credential_id");
        let created_at: String = row.get("created_at");
        let updated_at: String = row.get("updated_at");

        Ok(Server {
            id: Uuid::parse_str(&id)?,
            name: row.get("name"),
            host: row.get("host"),
            port: row.get::<i64, _>("port") as u16,
            username: row.get("username"),
            auth_method: serde_json::from_str(&auth)?,
            credential_id: cred_id.map(|s| Uuid::parse_str(&s)).transpose()?,
            tags: serde_json::from_str(&tags)?,
            created_at: DateTime::parse_from_rfc3339(&created_at)?.with_timezone(&Utc),
            updated_at: DateTime::parse_from_rfc3339(&updated_at)?.with_timezone(&Utc),
        })
    }

    pub async fn insert_git_credential(&self, git: &GitCredential) -> Result<()> {
        let tags = serde_json::to_string(&git.tags)?;
        sqlx::query(
            r#"
            INSERT INTO git_credentials (id, name, host, username, credential_type, credential_id, tags, created_at, updated_at)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
            "#,
        )
        .bind(git.id.to_string())
        .bind(&git.name)
        .bind(&git.host)
        .bind(&git.username)
        .bind(match git.credential_type {
            GitCredentialType::Token => "token",
            GitCredentialType::UsernamePassword => "username_password",
            GitCredentialType::SshKey => "ssh_key",
        })
        .bind(git.credential_id.to_string())
        .bind(tags)
        .bind(git.created_at.to_rfc3339())
        .bind(git.updated_at.to_rfc3339())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn get_git_credential(&self, name: &str) -> Result<Option<GitCredential>> {
        let row = sqlx::query("SELECT * FROM git_credentials WHERE name = ?1")
            .bind(name)
            .fetch_optional(&self.pool)
            .await?;
        row.map(Self::row_to_git_credential).transpose()
    }

    pub async fn list_git_credentials(&self) -> Result<Vec<GitCredential>> {
        let rows = sqlx::query("SELECT * FROM git_credentials ORDER BY name")
            .fetch_all(&self.pool)
            .await?;
        rows.into_iter().map(Self::row_to_git_credential).collect()
    }

    pub async fn delete_git_credential(&self, name: &str) -> Result<bool> {
        let result = sqlx::query("DELETE FROM git_credentials WHERE name = ?1")
            .bind(name)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    fn row_to_git_credential(row: sqlx::sqlite::SqliteRow) -> Result<GitCredential> {
        let id: String = row.get("id");
        let tags: String = row.get("tags");
        let created_at: String = row.get("created_at");
        let updated_at: String = row.get("updated_at");
        let cred_type: String = row.get("credential_type");

        Ok(GitCredential {
            id: Uuid::parse_str(&id)?,
            name: row.get("name"),
            host: row.get("host"),
            username: row.get("username"),
            credential_type: match cred_type.as_str() {
                "token" => GitCredentialType::Token,
                "username_password" => GitCredentialType::UsernamePassword,
                "ssh_key" => GitCredentialType::SshKey,
                _ => GitCredentialType::Token,
            },
            credential_id: Uuid::parse_str(&row.get::<String, _>("credential_id"))?,
            tags: serde_json::from_str(&tags)?,
            created_at: DateTime::parse_from_rfc3339(&created_at)?.with_timezone(&Utc),
            updated_at: DateTime::parse_from_rfc3339(&updated_at)?.with_timezone(&Utc),
        })
    }

    pub async fn insert_env_profile(&self, profile: &EnvironmentProfile) -> Result<()> {
        let variables = serde_json::to_string(&profile.variables)?;
        let tags = serde_json::to_string(&profile.tags)?;
        sqlx::query(
            r#"
            INSERT INTO environment_profiles (id, name, variables, tags, created_at, updated_at)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6)
            "#,
        )
        .bind(profile.id.to_string())
        .bind(&profile.name)
        .bind(variables)
        .bind(tags)
        .bind(profile.created_at.to_rfc3339())
        .bind(profile.updated_at.to_rfc3339())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn get_env_profile(&self, name: &str) -> Result<Option<EnvironmentProfile>> {
        let row = sqlx::query("SELECT * FROM environment_profiles WHERE name = ?1")
            .bind(name)
            .fetch_optional(&self.pool)
            .await?;
        row.map(Self::row_to_env_profile).transpose()
    }

    pub async fn list_env_profiles(&self) -> Result<Vec<EnvironmentProfile>> {
        let rows = sqlx::query("SELECT * FROM environment_profiles ORDER BY name")
            .fetch_all(&self.pool)
            .await?;
        rows.into_iter().map(Self::row_to_env_profile).collect()
    }

    pub async fn delete_env_profile(&self, name: &str) -> Result<bool> {
        let result = sqlx::query("DELETE FROM environment_profiles WHERE name = ?1")
            .bind(name)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    fn row_to_env_profile(row: sqlx::sqlite::SqliteRow) -> Result<EnvironmentProfile> {
        let id: String = row.get("id");
        let variables: String = row.get("variables");
        let tags: String = row.get("tags");
        let created_at: String = row.get("created_at");
        let updated_at: String = row.get("updated_at");

        Ok(EnvironmentProfile {
            id: Uuid::parse_str(&id)?,
            name: row.get("name"),
            variables: serde_json::from_str(&variables)?,
            tags: serde_json::from_str(&tags)?,
            created_at: DateTime::parse_from_rfc3339(&created_at)?.with_timezone(&Utc),
            updated_at: DateTime::parse_from_rfc3339(&updated_at)?.with_timezone(&Utc),
        })
    }

    pub async fn insert_agent(&self, agent: &Agent) -> Result<()> {
        let permissions = serde_json::to_string(&agent.permissions)?;
        sqlx::query(
            r#"
            INSERT INTO agents (id, name, token, permissions, created_at, last_used_at)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6)
            "#,
        )
        .bind(agent.id.to_string())
        .bind(&agent.name)
        .bind(&agent.token)
        .bind(permissions)
        .bind(agent.created_at.to_rfc3339())
        .bind(agent.last_used_at.map(|dt| dt.to_rfc3339()))
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn get_agent_by_token(&self, token: &str) -> Result<Option<Agent>> {
        let row = sqlx::query("SELECT * FROM agents WHERE token = ?1")
            .bind(token)
            .fetch_optional(&self.pool)
            .await?;
        row.map(Self::row_to_agent).transpose()
    }

    pub async fn list_agents(&self) -> Result<Vec<Agent>> {
        let rows = sqlx::query("SELECT * FROM agents ORDER BY name")
            .fetch_all(&self.pool)
            .await?;
        rows.into_iter().map(Self::row_to_agent).collect()
    }

    pub async fn revoke_agent(&self, name: &str) -> Result<bool> {
        let result = sqlx::query("DELETE FROM agents WHERE name = ?1")
            .bind(name)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn update_agent_last_used(&self, token: &str) -> Result<()> {
        let now = Utc::now().to_rfc3339();
        sqlx::query("UPDATE agents SET last_used_at = ?1 WHERE token = ?2")
            .bind(now)
            .bind(token)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    fn row_to_agent(row: sqlx::sqlite::SqliteRow) -> Result<Agent> {
        let id: String = row.get("id");
        let permissions: String = row.get("permissions");
        let created_at: String = row.get("created_at");
        let last_used_at: Option<String> = row.get("last_used_at");

        Ok(Agent {
            id: Uuid::parse_str(&id)?,
            name: row.get("name"),
            token: row.get("token"),
            permissions: serde_json::from_str(&permissions)?,
            created_at: DateTime::parse_from_rfc3339(&created_at)?.with_timezone(&Utc),
            last_used_at: last_used_at.map(|s| DateTime::parse_from_rfc3339(&s).unwrap().with_timezone(&Utc)),
        })
    }
}