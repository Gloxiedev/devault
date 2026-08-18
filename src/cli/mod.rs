use crate::error::{DevaultError, Result};
use crate::vault::models::*;
use crate::vault::{Vault, BackupData};
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use uuid::Uuid;

#[derive(Parser)]
#[command(name = "devault", version, about = "Local credential vault and agent access layer")]
#[command(alias = "dvault")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,

    #[arg(short, long, global = true, help = "Vault directory path")]
    pub vault_dir: Option<PathBuf>,

    #[arg(short, long, global = true, help = "Output as JSON")]
    pub json: bool,

    #[arg(long = "master-password", global = true, help = "Master password (for non-interactive use)")]
    pub master_password: Option<String>,
}

#[derive(Subcommand, Clone)]
pub enum Commands {
    #[command(about = "Initialize a new vault")]
    Init {
        #[arg(short, long, help = "Master password (interactive if omitted)")]
        password: Option<String>,
    },

    #[command(about = "Unlock the vault")]
    Unlock {
        #[arg(short, long, help = "Master password (interactive if omitted)")]
        password: Option<String>,
    },

    #[command(about = "Lock the vault")]
    Lock,

    #[command(about = "Show vault status")]
    Status,

    #[command(about = "List credentials")]
    List {
        #[arg(short, long, help = "Filter by type")]
        r#type: Option<String>,
        #[arg(short = 'g', long, help = "Filter by tag")]
        tag: Option<String>,
    },

    #[command(about = "Add a credential")]
    Add {
        #[arg(help = "Credential name")]
        name: String,
        #[arg(help = "Credential value (interactive if omitted)")]
        credential: Option<String>,
        #[arg(help = "Context/description")]
        context: Option<String>,
        #[arg(short, long, help = "Credential type")]
        r#type: Option<String>,
        #[arg(short, long, help = "Description")]
        description: Option<String>,
        #[arg(short = 'g', long, help = "Tags (comma-separated)")]
        tags: Option<String>,
    },

    #[command(about = "Get a credential value")]
    Get {
        #[arg(help = "Credential name")]
        name: String,
        #[arg(short, long, help = "Show raw value")]
        show: bool,
    },

    #[command(about = "Remove a credential")]
    Remove {
        #[arg(help = "Credential name")]
        name: String,
        #[arg(short, long, help = "Force removal without confirmation")]
        force: bool,
    },

    #[command(about = "Edit a credential")]
    Edit {
        #[arg(help = "Credential name")]
        name: String,
        #[arg(short, long, help = "New credential value (interactive if omitted)")]
        credential: Option<String>,
        #[arg(short = 'x', long, help = "New context")]
        context: Option<String>,
        #[arg(short, long, help = "New description")]
        description: Option<String>,
        #[arg(short, long, help = "New tags (comma-separated)")]
        tags: Option<String>,
    },

    #[command(about = "Search credentials")]
    Search {
        #[arg(help = "Search query")]
        query: String,
        #[arg(short, long, help = "Filter by type")]
        r#type: Option<String>,
        #[arg(short = 'g', long, help = "Filter by tags (comma-separated)")]
        tags: Option<String>,
        #[arg(short, long, help = "Limit results")]
        limit: Option<usize>,
    },

    #[command(about = "Manage tags")]
    Tag {
        #[arg(help = "Credential name")]
        name: String,
        #[command(subcommand)]
        action: TagAction,
    },

    #[command(about = "Server/SSH management")]
    Server {
        #[command(subcommand)]
        action: ServerAction,
    },

    #[command(about = "Git credential management")]
    Git {
        #[command(subcommand)]
        action: GitAction,
    },

    #[command(about = "Environment profile management")]
    Env {
        #[command(subcommand)]
        action: EnvAction,
    },

    #[command(about = "Agent management")]
    Agent {
        #[command(subcommand)]
        action: AgentAction,
    },

    #[command(about = "Backup management")]
    Backup {
        #[command(subcommand)]
        action: BackupAction,
    },

    #[command(about = "Generate shell completions")]
    Completion {
        #[arg(value_enum, help = "Shell type")]
        shell: clap_complete::Shell,
    },

    #[command(about = "Scan for supported IDEs/agents")]
    Scan {
        #[arg(short, long, help = "Output as JSON")]
        json: bool,
    },

    #[command(about = "Manage IDE/agent skills")]
    Skill {
        #[command(subcommand)]
        action: SkillAction,
    },
}

#[derive(Subcommand, Clone)]
pub enum SkillAction {
    #[command(about = "Add skill for an IDE/agent")]
    Add {
        #[arg(help = "IDE/agent name (opencode, cursor, vscode, windsurf, zed, helix, manual)")]
        ide: String,
        #[arg(short, long, help = "Force overwrite existing skill")]
        force: bool,
    },
    #[command(about = "Remove skill for an IDE/agent")]
    Remove {
        #[arg(help = "IDE/agent name")]
        ide: String,
    },
    #[command(about = "List installed skills")]
    List,
    #[command(about = "Show skill file content")]
    Show {
        #[arg(help = "IDE/agent name")]
        ide: String,
    },
}

#[derive(Subcommand, Clone)]
pub enum TagAction {
    #[command(about = "Add tags")]
    Add {
        #[arg(help = "Tags to add (comma-separated)")]
        tags: String,
    },
    #[command(about = "Remove tags")]
    Remove {
        #[arg(help = "Tags to remove (comma-separated)")]
        tags: String,
    },
}

#[derive(Subcommand, Clone)]
pub enum ServerAction {
    #[command(about = "Add a server")]
    Add {
        #[arg(help = "Server name")]
        name: String,
        #[arg(short = 'H', long, help = "Host")]
        host: String,
        #[arg(short = 'P', long, default_value = "22", help = "Port")]
        port: u16,
        #[arg(short, long, help = "Username")]
        user: String,
        #[arg(short, long, help = "Auth method: password, key, agent")]
        auth: String,
        #[arg(short, long, help = "Password or key path")]
        secret: Option<String>,
        #[arg(short = 'p', long, help = "Key passphrase")]
        passphrase: Option<String>,
        #[arg(short, long, help = "Credential name to link")]
        credential: Option<String>,
        #[arg(short, long, help = "Tags (comma-separated)")]
        tags: Option<String>,
    },
    #[command(about = "List servers")]
    List {
        #[arg(short, long, help = "Filter by tag")]
        tag: Option<String>,
    },
    #[command(about = "Get server details")]
    Get {
        #[arg(help = "Server name")]
        name: String,
    },
    #[command(about = "Execute command on server")]
    Exec {
        #[arg(help = "Server name")]
        name: String,
        #[arg(help = "Command to execute")]
        command: String,
    },
    #[command(about = "Remove a server")]
    Remove {
        #[arg(help = "Server name")]
        name: String,
    },
}

#[derive(Subcommand, Clone)]
pub enum GitAction {
    #[command(about = "Add a Git credential")]
    Add {
        #[arg(help = "Credential name")]
        name: String,
        #[arg(short = 'H', long, help = "Git host (e.g., github.com)")]
        host: String,
        #[arg(short, long, help = "Username")]
        user: String,
        #[arg(short, long, help = "Type: token, password, ssh")]
        r#type: String,
        #[arg(short, long, help = "Credential name in vault")]
        credential: String,
        #[arg(short = 'g', long, help = "Tags (comma-separated)")]
        tags: Option<String>,
    },
    #[command(about = "List Git credentials")]
    List,
    #[command(about = "Use Git credential (configure git)")]
    Use {
        #[arg(help = "Credential name")]
        name: String,
        #[arg(short, long, help = "Repository path")]
        repo: Option<String>,
    },
    #[command(about = "Remove a Git credential")]
    Remove {
        #[arg(help = "Credential name")]
        name: String,
    },
}

#[derive(Subcommand, Clone)]
pub enum EnvAction {
    #[command(about = "List environment profiles")]
    List,
    #[command(about = "Run command with environment profile")]
    Run {
        #[arg(help = "Profile name")]
        name: String,
        #[arg(help = "Command to run")]
        command: Vec<String>,
    },
    #[command(about = "Add environment profile")]
    Add {
        #[arg(help = "Profile name")]
        name: String,
        #[arg(short = 'V', long, help = "Variables as KEY=VALUE (comma-separated)")]
        vars: String,
        #[arg(short, long, help = "Tags (comma-separated)")]
        tags: Option<String>,
    },
    #[command(about = "Remove environment profile")]
    Remove {
        #[arg(help = "Profile name")]
        name: String,
    },
}

#[derive(Subcommand, Clone)]
pub enum AgentAction {
    #[command(about = "Add an agent")]
    Add {
        #[arg(help = "Agent name")]
        name: String,
        #[arg(short, long, help = "Permissions (comma-separated): list,get,use,exec,git,env")]
        permissions: String,
    },
    #[command(about = "List agents")]
    List,
    #[command(about = "Revoke an agent")]
    Revoke {
        #[arg(help = "Agent name")]
        name: String,
    },
}

#[derive(Subcommand, Clone)]
pub enum BackupAction {
    #[command(about = "Create encrypted backup")]
    Create {
        #[arg(short, long, help = "Output file path")]
        output: Option<PathBuf>,
        #[arg(short, long, help = "Backup password (interactive if omitted)")]
        password: Option<String>,
    },
    #[command(about = "Restore from backup")]
    Restore {
        #[arg(help = "Backup file path")]
        file: PathBuf,
        #[arg(short, long, help = "Backup password (interactive if omitted)")]
        password: Option<String>,
    },
}

pub async fn run(mut cli: Cli) -> Result<()> {
    let vault_dir = cli.vault_dir.clone().unwrap_or_else(default_vault_dir);
    let json_output = cli.json;
    let command = cli.command.clone();
    
    match command {
        Commands::Init { password } => cmd_init(&vault_dir, password).await,
        Commands::Unlock { password } => cmd_unlock(&cli, &vault_dir, password, json_output).await,
        Commands::Lock => cmd_lock(&cli, &vault_dir).await,
        Commands::Status => cmd_status(&cli, &vault_dir, json_output).await,
        Commands::List { r#type, tag } => cmd_list(&cli, &vault_dir, r#type, tag, json_output).await,
        Commands::Add { name, credential, context, r#type, description, tags } => 
            cmd_add(&cli, &vault_dir, name, credential, context, r#type, description, tags).await,
        Commands::Get { name, show } => cmd_get(&cli, &vault_dir, name, show).await,
        Commands::Remove { name, force } => cmd_remove(&cli, &vault_dir, name, force).await,
        Commands::Edit { name, credential, context, description, tags } => 
            cmd_edit(&cli, &vault_dir, name, credential, context, description, tags).await,
        Commands::Search { query, r#type, tags, limit } => 
            cmd_search(&cli, &vault_dir, query, r#type, tags, limit, json_output).await,
        Commands::Tag { name, action } => cmd_tag(&cli, &vault_dir, name, action).await,
        Commands::Server { action } => cmd_server(&cli, &vault_dir, action, json_output).await,
        Commands::Git { action } => cmd_git(&cli, &vault_dir, action).await,
        Commands::Env { action } => cmd_env(&cli, &vault_dir, action).await,
        Commands::Agent { action } => cmd_agent(&cli, &vault_dir, action).await,
        Commands::Backup { action } => cmd_backup(&cli, &vault_dir, action).await,
        Commands::Completion { shell } => cmd_completion(shell),
        Commands::Scan { json } => cmd_scan(json),
        Commands::Skill { action } => cmd_skill(action),
    }
}

fn default_vault_dir() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".devault")
        .join("vault.db")
}

fn get_password(prompt: &str, confirm: bool) -> Result<String> {
    use dialoguer::Password;
    let password = Password::new()
        .with_prompt(prompt)
        .interact()?;
    if confirm {
        let confirm_pass = Password::new()
            .with_prompt("Confirm password")
            .interact()?;
        if password != confirm_pass {
            return Err(DevaultError::InvalidInput("Passwords do not match".into()));
        }
    }
    Ok(password)
}

fn get_input(prompt: &str) -> Result<String> {
    use dialoguer::Input;
    Input::new()
        .with_prompt(prompt)
        .interact_text()
        .map_err(|e| DevaultError::InvalidInput(e.to_string()))
}

async fn get_vault(cli: &Cli, vault_dir: &PathBuf) -> Result<Vault> {
    let password = cli.master_password.clone()
        .or_else(|| get_password("Master password", false).ok());
    let password = password.ok_or_else(|| DevaultError::InvalidInput("Password required".into()))?;
    Vault::unlock(vault_dir.clone(), &password).await
}

async fn cmd_init(vault_dir: &PathBuf, password: Option<String>) -> Result<()> {
    let password = password.unwrap_or_else(|| get_password("Master password", true).unwrap());

    let vault = Vault::init(vault_dir.clone(), &password).await?;
    println!("Vault initialized at {}", vault_dir.display());
    Ok(())
}

async fn cmd_unlock(cli: &Cli, vault_dir: &PathBuf, password: Option<String>, json: bool) -> Result<()> {
    let password = password
        .or_else(|| cli.master_password.clone())
        .or_else(|| get_password("Master password", false).ok())
        .ok_or_else(|| DevaultError::InvalidInput("Password required".into()))?;

    let vault = Vault::unlock(vault_dir.clone(), &password).await?;
    let status = vault.status().await?;
    
    if json {
        println!("{}", serde_json::to_string_pretty(&status)?);
    } else {
        println!("Vault unlocked");
        println!("Vault: {}", status.path.display());
        println!("Credentials: {}", status.credentials);
        println!("Servers: {}", status.servers);
        println!("Git credentials: {}", status.git_credentials);
        println!("Environment profiles: {}", status.environment_profiles);
        println!("Agents: {}", status.agents);
    }
    Ok(())
}

async fn cmd_lock(cli: &Cli, vault_dir: &PathBuf) -> Result<()> {
    let vault = get_vault(cli, vault_dir).await?;
    vault.lock().await?;
    println!("Vault locked");
    Ok(())
}

async fn cmd_status(cli: &Cli, vault_dir: &PathBuf, json: bool) -> Result<()> {
    let vault = get_vault(cli, vault_dir).await?;
    let status = vault.status().await?;
    
    if json {
        println!("{}", serde_json::to_string_pretty(&status)?);
    } else {
        println!("Vault: {}", status.path.display());
        println!("Status: {}", if status.locked { "Locked" } else { "Unlocked" });
        println!("Credentials: {}", status.credentials);
        println!("Servers: {}", status.servers);
        println!("Git credentials: {}", status.git_credentials);
        println!("Environment profiles: {}", status.environment_profiles);
        println!("Agents: {}", status.agents);
    }
    Ok(())
}

async fn cmd_list(cli: &Cli, vault_dir: &PathBuf, r#type: Option<String>, tag: Option<String>, json: bool) -> Result<()> {
    let vault = get_vault(cli, vault_dir).await?;
    let cred_type = r#type.map(|s| CredentialType::from_str(&s));
    let creds = vault.list_credentials(cred_type, tag.as_deref()).await?;
    
    if json {
        println!("{}", serde_json::to_string_pretty(&creds)?);
    } else {
        println!("{:<20} {:<15} {}", "NAME", "TYPE", "CONTEXT");
        println!("{}", "-".repeat(60));
        for c in creds {
            println!("{:<20} {:<15} {}", c.name, c.credential_type.as_str(), c.context);
        }
    }
    Ok(())
}

async fn cmd_add(
    cli: &Cli,
    vault_dir: &PathBuf,
    name: String,
    credential: Option<String>,
    context: Option<String>,
    r#type: Option<String>,
    description: Option<String>,
    tags: Option<String>,
) -> Result<()> {
    let vault = get_vault(cli, vault_dir).await?;
    
    let cred_value = credential.unwrap_or_else(|| get_password("Credential value", false).unwrap());

    let ctx = context.unwrap_or_else(|| get_input("Context").unwrap_or_default());

    let cred_type = r#type.map(|s| CredentialType::from_str(&s)).unwrap_or(CredentialType::Generic);
    let desc = description;
    let tag_list = tags.map(|s| s.split(',').map(|s| s.trim().to_string()).collect()).unwrap_or_default();

    let cred = Credential::new(name, cred_type, cred_value.into_bytes(), ctx, desc, tag_list);
    vault.add_credential(cred).await?;
    println!("Credential added");
    Ok(())
}

async fn cmd_get(cli: &Cli, vault_dir: &PathBuf, name: String, show: bool) -> Result<()> {
    let vault = get_vault(cli, vault_dir).await?;
    let cred = vault.get_credential(&name).await?;
    
    if show {
        println!("{}", String::from_utf8_lossy(&cred.credential));
    } else {
        println!("Credential retrieved (use --show to display)");
    }
    Ok(())
}

async fn cmd_remove(cli: &Cli, vault_dir: &PathBuf, name: String, force: bool) -> Result<()> {
    if !force {
        use dialoguer::Confirm;
        let confirmed = Confirm::new()
            .with_prompt(format!("Remove credential '{}'?", name))
            .interact()?;
        if !confirmed {
            println!("Cancelled");
            return Ok(());
        }
    }
    
    let vault = get_vault(cli, vault_dir).await?;
    vault.remove_credential(&name).await?;
    println!("Credential removed");
    Ok(())
}

async fn cmd_edit(
    cli: &Cli,
    vault_dir: &PathBuf,
    name: String,
    credential: Option<String>,
    context: Option<String>,
    description: Option<String>,
    tags: Option<String>,
) -> Result<()> {
    let vault = get_vault(cli, vault_dir).await?;
    let mut cred = vault.get_credential(&name).await?;
    
    if let Some(c) = credential {
        cred.credential = c.into_bytes();
    }
    if let Some(c) = context {
        cred.context = c;
    }
    if let Some(d) = description {
        cred.description = Some(d);
    }
    if let Some(t) = tags {
        cred.tags = t.split(',').map(|s| s.trim().to_string()).collect();
    }
    cred.updated_at = chrono::Utc::now();
    
    vault.update_credential(cred).await?;
    println!("Credential updated");
    Ok(())
}

async fn cmd_search(
    cli: &Cli,
    vault_dir: &PathBuf,
    query: String,
    r#type: Option<String>,
    tags: Option<String>,
    limit: Option<usize>,
    json: bool,
) -> Result<()> {
    let vault = get_vault(cli, vault_dir).await?;
    let search_query = SearchQuery {
        query: Some(query),
        credential_type: r#type.map(|s| CredentialType::from_str(&s)),
        tags: tags.map(|s| s.split(',').map(|s| s.trim().to_string()).collect()).unwrap_or_default(),
        limit,
    };
    let results = vault.search_credentials(&search_query).await?;
    
    if json {
        println!("{}", serde_json::to_string_pretty(&results)?);
    } else {
        println!("{:<20} {:<15} {}", "NAME", "TYPE", "CONTEXT");
        println!("{}", "-".repeat(60));
        for c in results {
            println!("{:<20} {:<15} {}", c.name, c.credential_type.as_str(), c.context);
        }
    }
    Ok(())
}

async fn cmd_tag(cli: &Cli, vault_dir: &PathBuf, name: String, action: TagAction) -> Result<()> {
    let vault = get_vault(cli, vault_dir).await?;
    let mut cred = vault.get_credential(&name).await?;
    
    match action {
        TagAction::Add { tags } => {
            for tag in tags.split(',') {
                let tag = tag.trim().to_string();
                if !cred.tags.contains(&tag) {
                    cred.tags.push(tag);
                }
            }
        }
        TagAction::Remove { tags } => {
            for tag in tags.split(',') {
                let tag = tag.trim().to_string();
                cred.tags.retain(|t| t != &tag);
            }
        }
    }
    cred.updated_at = chrono::Utc::now();
    vault.update_credential(cred).await?;
    println!("Tags updated");
    Ok(())
}

async fn cmd_server(cli: &Cli, vault_dir: &PathBuf, action: ServerAction, json: bool) -> Result<()> {
    let vault = get_vault(cli, vault_dir).await?;
    
    match action {
        ServerAction::Add { name, host, port, user, auth, secret, passphrase, credential, tags } => {
            let auth_method = match auth.as_str() {
                "password" => {
                    let pass = secret.unwrap_or_else(|| get_password("SSH password", false).unwrap());
                    ServerAuthMethod::Password(pass)
                }
                "key" => {
                    let key_path = secret.unwrap_or_else(|| get_input("Private key path").unwrap());
                    ServerAuthMethod::PrivateKey { key_path, passphrase }
                }
                "agent" => ServerAuthMethod::Agent,
                _ => return Err(DevaultError::InvalidInput("Invalid auth method".into())),
            };
            
            let cred_id = if let Some(c) = credential {
                let cred = vault.get_credential(&c).await?;
                Some(cred.id)
            } else {
                None
            };
            
            let server = Server {
                id: Uuid::new_v4(),
                name,
                host,
                port,
                username: user,
                auth_method,
                credential_id: cred_id,
                tags: tags.map(|s| s.split(',').map(|s| s.trim().to_string()).collect()).unwrap_or_default(),
                created_at: chrono::Utc::now(),
                updated_at: chrono::Utc::now(),
            };
            vault.add_server(server).await?;
            println!("Server added");
        }
        ServerAction::List { tag } => {
            let servers = vault.list_servers(tag.as_deref()).await?;
            if json {
                println!("{}", serde_json::to_string_pretty(&servers)?);
            } else {
                println!("{:<20} {:<30} {}", "NAME", "HOST", "USER");
                println!("{}", "-".repeat(60));
                for s in servers {
                    println!("{:<20} {:<30} {}", s.name, format!("{}:{}", s.host, s.port), s.username);
                }
            }
        }
        ServerAction::Get { name } => {
            let server = vault.get_server(&name).await?;
            if json {
                println!("{}", serde_json::to_string_pretty(&server)?);
            } else {
                println!("Name: {}", server.name);
                println!("Host: {}:{}", server.host, server.port);
                println!("User: {}", server.username);
                println!("Auth: {:?}", server.auth_method);
            }
        }
        ServerAction::Exec { name, command } => {
            let server = vault.get_server(&name).await?;
            let output = crate::ssh::execute(&server, &command).await?;
            println!("{}", output);
        }
        ServerAction::Remove { name } => {
            vault.remove_server(&name).await?;
            println!("Server removed");
        }
    }
    Ok(())
}

async fn cmd_git(cli: &Cli, vault_dir: &PathBuf, action: GitAction) -> Result<()> {
    let vault = get_vault(cli, vault_dir).await?;
    
    match action {
        GitAction::Add { name, host, user, r#type, credential, tags } => {
            let cred = vault.get_credential(&credential).await?;
            let git_type = match r#type.as_str() {
                "token" => GitCredentialType::Token,
                "password" => GitCredentialType::UsernamePassword,
                "ssh" => GitCredentialType::SshKey,
                _ => return Err(DevaultError::InvalidInput("Invalid git credential type".into())),
            };
            let git = GitCredential {
                id: Uuid::new_v4(),
                name,
                host,
                username: user,
                credential_type: git_type,
                credential_id: cred.id,
                tags: tags.map(|s| s.split(',').map(|s| s.trim().to_string()).collect()).unwrap_or_default(),
                created_at: chrono::Utc::now(),
                updated_at: chrono::Utc::now(),
            };
            vault.add_git_credential(git).await?;
            println!("Git credential added");
        }
        GitAction::List => {
            let creds = vault.list_git_credentials().await?;
            println!("{:<20} {:<30} {:<15} {}", "NAME", "HOST", "TYPE", "USER");
            println!("{}", "-".repeat(80));
            for c in creds {
                println!("{:<20} {:<30} {:<15} {}", c.name, c.host, 
                    match c.credential_type {
                        GitCredentialType::Token => "token",
                        GitCredentialType::UsernamePassword => "password",
                        GitCredentialType::SshKey => "ssh",
                    }, c.username);
            }
        }
        GitAction::Use { name, repo } => {
            let git = vault.get_git_credential(&name).await?;
            crate::git::configure(&git, repo.as_deref()).await?;
            println!("Git configured for {}", name);
        }
        GitAction::Remove { name } => {
            vault.remove_git_credential(&name).await?;
            println!("Git credential removed");
        }
    }
    Ok(())
}

async fn cmd_env(cli: &Cli, vault_dir: &PathBuf, action: EnvAction) -> Result<()> {
    let vault = get_vault(cli, vault_dir).await?;
    
    match action {
        EnvAction::List => {
            let profiles = vault.list_env_profiles().await?;
            println!("{:<20} {}", "NAME", "VARIABLES");
            println!("{}", "-".repeat(60));
            for p in profiles {
                println!("{:<20} {}", p.name, p.variables.len());
            }
        }
        EnvAction::Run { name, command } => {
            let profile = vault.get_env_profile(&name).await?;
            crate::env::run_with_env(&profile, &command).await?;
        }
        EnvAction::Add { name, vars, tags } => {
            let mut variables = Vec::new();
            for pair in vars.split(',') {
                let parts: Vec<&str> = pair.splitn(2, '=').collect();
                if parts.len() == 2 {
                    variables.push(EnvironmentVariable {
                        key: parts[0].trim().to_string(),
                        value: parts[1].trim().as_bytes().to_vec(),
                        credential_id: None,
                    });
                }
            }
            let profile = EnvironmentProfile {
                id: Uuid::new_v4(),
                name,
                variables,
                tags: tags.map(|s| s.split(',').map(|s| s.trim().to_string()).collect()).unwrap_or_default(),
                created_at: chrono::Utc::now(),
                updated_at: chrono::Utc::now(),
            };
            vault.add_env_profile(profile).await?;
            println!("Environment profile added");
        }
        EnvAction::Remove { name } => {
            vault.remove_env_profile(&name).await?;
            println!("Environment profile removed");
        }
    }
    Ok(())
}

async fn cmd_agent(cli: &Cli, vault_dir: &PathBuf, action: AgentAction) -> Result<()> {
    let vault = get_vault(cli, vault_dir).await?;
    
    match action {
        AgentAction::Add { name, permissions } => {
            let perms: Vec<AgentPermission> = permissions.split(',')
                .filter_map(|p| match p.trim() {
                    "list" => Some(AgentPermission::ListCredentials),
                    "get" => Some(AgentPermission::GetCredential),
                    "use" => Some(AgentPermission::UseCredential),
                    "exec" => Some(AgentPermission::ExecuteServer),
                    "git" => Some(AgentPermission::GitAuth),
                    "env" => Some(AgentPermission::Environment),
                    _ => None,
                })
                .collect();
            let token = uuid::Uuid::new_v4().to_string();
            let agent = Agent {
                id: Uuid::new_v4(),
                name,
                token: token.clone(),
                permissions: perms,
                created_at: chrono::Utc::now(),
                last_used_at: None,
            };
            vault.add_agent(agent).await?;
            println!("Agent added. Token: {}", token);
        }
        AgentAction::List => {
            let agents = vault.list_agents().await?;
            println!("{:<20} {:<40} {}", "NAME", "TOKEN", "PERMISSIONS");
            println!("{}", "-".repeat(100));
            for a in agents {
                let perms: Vec<String> = a.permissions.iter().map(|p| format!("{:?}", p)).collect();
                println!("{:<20} {:<40} {}", a.name, &a.token[..8], perms.join(","));
            }
        }
        AgentAction::Revoke { name } => {
            vault.revoke_agent(&name).await?;
            println!("Agent revoked");
        }
    }
    Ok(())
}

async fn cmd_backup(cli: &Cli, vault_dir: &PathBuf, action: BackupAction) -> Result<()> {
    let vault = get_vault(cli, vault_dir).await?;
    
    match action {
        BackupAction::Create { output, password } => {
            let password = password.unwrap_or_else(|| get_password("Backup password", true).unwrap());
            let backup = vault.export_backup(&password).await?;
            let path = output.unwrap_or_else(|| PathBuf::from(format!("devault-backup-{}.json", chrono::Utc::now().format("%Y%m%d-%H%M%S"))));
            tokio::fs::write(&path, serde_json::to_vec(&backup)?).await?;
            println!("Backup created at {}", path.display());
        }
        BackupAction::Restore { file, password } => {
            let password = password.unwrap_or_else(|| get_password("Backup password", false).unwrap());
            let data = tokio::fs::read(&file).await?;
            let backup: BackupData = serde_json::from_slice(&data)?;
            vault.import_backup(backup, &password).await?;
            println!("Backup restored");
        }
    }
    Ok(())
}

fn cmd_completion(shell: clap_complete::Shell) -> Result<()> {
    use clap::CommandFactory;
    let mut cmd = Cli::command();
    clap_complete::generate(shell, &mut cmd, "devault", &mut std::io::stdout());
    Ok(())
}

struct DetectedIde {
    name: String,
    config_dir: PathBuf,
    skill_dir: PathBuf,
}

fn detect_ides() -> Vec<DetectedIde> {
    let home = dirs::home_dir().unwrap_or_default();
    let xdg_config = std::env::var("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| home.join(".config"));
    let mut found = Vec::new();

    let candidates: Vec<(&str, Vec<PathBuf>)> = vec![
        ("opencode", vec![
            xdg_config.join("opencode").join("skills"),
            home.join(".opencode").join("skills"),
        ]),
        ("cursor", vec![
            xdg_config.join("Cursor").join("skills"),
            home.join(".cursor").join("skills"),
        ]),
        ("vscode", vec![
            xdg_config.join("Code").join("skills"),
            home.join(".vscode").join("skills"),
        ]),
        ("windsurf", vec![
            xdg_config.join("windsurf").join("skills"),
            home.join(".windsurf").join("skills"),
        ]),
        ("zed", vec![
            xdg_config.join("zed").join("skills"),
            home.join(".zed").join("skills"),
        ]),
        ("helix", vec![
            xdg_config.join("helix").join("skills"),
            home.join(".helix").join("skills"),
        ]),
        ("neovim", vec![
            home.join(".config/nvim/skills"),
            home.join(".local/share/nvim/skills"),
        ]),
        ("claude", vec![
            xdg_config.join("claude").join("skills"),
            home.join(".claude").join("skills"),
        ]),
        ("aider", vec![
            xdg_config.join("aider").join("skills"),
            home.join(".aider").join("skills"),
        ]),
        ("continue", vec![
            xdg_config.join("continue").join("skills"),
        ]),
        ("cody", vec![
            xdg_config.join("cody").join("skills"),
        ]),
        ("manual", vec![]),
    ];

    for (name, paths) in candidates {
        let skill_dir = paths.first().cloned().unwrap_or_default();
        let skill_file = skill_dir.join("devault").join("SKILL.md");
        if skill_dir.parent().map_or(false, |p| p.exists()) || name == "manual" {
            found.push(DetectedIde {
                name: name.to_string(),
                config_dir: skill_dir.parent().map(|p| p.to_path_buf()).unwrap_or_default(),
                skill_dir,
            });
        }
    }

    found
}

fn cmd_scan(json: bool) -> Result<()> {
    let detected = detect_ides();

    if json {
        let items: Vec<serde_json::Value> = detected.iter().map(|d| {
            let skill_file = d.skill_dir.join("devault").join("SKILL.md");
            serde_json::json!({
                "name": d.name,
                "config_dir": d.config_dir.to_string_lossy(),
                "skill_dir": d.skill_dir.to_string_lossy(),
                "has_skill": skill_file.exists(),
            })
        }).collect();
        println!("{}", serde_json::to_string_pretty(&items)?);
    } else {
        if detected.is_empty() {
            println!("No supported IDEs/agents found.");
        } else {
            println!("Supported IDEs/agents found:");
            println!();
            for d in &detected {
                let skill_file = d.skill_dir.join("devault").join("SKILL.md");
                let status = if skill_file.exists() { " [installed]" } else { "" };
                println!("  {}{}", d.name, status);
                println!("    config: {}", d.config_dir.display());
            }
            println!();
            println!("Install skills with: devault skill add <ide>");
        }
    }

    Ok(())
}

fn get_skill_content() -> &'static str {
    r#"---
name: devault
description: Access local encrypted credential vault for secrets, SSH, Git, and environment profiles
license: MIT
metadata:
  type: security
  audience: developers
---

# Devault Agent Skill

You have access to a local encrypted credential vault via Devault.

## Quick Start

Start the daemon: `devaultd &`

## Available Operations

### List credentials
```bash
devault list
devault list --json
```

### Get a secret value
```bash
devault get <name> --show
```

### Execute SSH command on a server
```bash
devault server exec <server-name> "<command>"
```

### Use Git credentials
```bash
devault git auth <host> --format json
```

### Run with environment profile
```bash
devault env run <profile-name> -- <command>
```

### Search credentials
```bash
devault search <query>
```

## Security Rules

- NEVER echo/print raw secret values in conversation
- NEVER log or write secrets to files
- Use `devault get <name> --show` only when explicitly needed
- Prefer `devault server exec` over direct SSH for server operations
- Prefer `devault env run` over manually setting environment variables

## Agent Token

If you have an agent token, you can authenticate via the Unix socket:
```python
# Connect to /tmp/devault.sock
# Send: {"type": "Use", "name": "credential-name"}
# Receive: {"type": "CredentialValue", "value": "..."}
```
"#
}

fn cmd_skill(action: SkillAction) -> Result<()> {
    let detected = detect_ides();

    match action {
        SkillAction::Add { ide, force } => {
            let ide_lower = ide.to_lowercase();
            let target = detected.iter().find(|d| d.name == ide_lower);

            let skill_dir = match target {
                Some(d) => {
                    let dir = d.skill_dir.join("devault");
                    std::fs::create_dir_all(&dir)?;
                    dir
                }
                None => {
                    let home = dirs::home_dir().ok_or_else(|| {
                        DevaultError::InvalidInput("Cannot determine home directory".into())
                    })?;
                    let dir = home.join(".devault").join("skills").join(&ide_lower);
                    std::fs::create_dir_all(&dir)?;
                    dir
                }
            };

            let skill_file = skill_dir.join("SKILL.md");

            if skill_file.exists() && !force {
                println!("Skill already exists at: {}", skill_file.display());
                println!("Use --force to overwrite.");
                return Ok(());
            }

            std::fs::write(&skill_file, get_skill_content())?;
            println!("Skill installed: {}", skill_file.display());

            if let Some(d) = target {
                if d.name == "opencode" {
                    println!();
                    println!("Skill will be auto-discovered by OpenCode.");
                    println!("No config changes needed.");
                }
            }
        }
        SkillAction::Remove { ide } => {
            let ide_lower = ide.to_lowercase();
            let target = detected.iter().find(|d| d.name == ide_lower);

            let skill_file = match target {
                Some(d) => d.skill_dir.join("devault").join("SKILL.md"),
                None => {
                    let home = dirs::home_dir().ok_or_else(|| {
                        DevaultError::InvalidInput("Cannot determine home directory".into())
                    })?;
                    home.join(".devault").join("skills").join(&ide_lower).join("SKILL.md")
                }
            };

            if skill_file.exists() {
                std::fs::remove_file(&skill_file)?;
                println!("Skill removed: {}", skill_file.display());
                if let Some(dir) = skill_file.parent() {
                    if dir.read_dir()?.next().is_none() {
                        std::fs::remove_dir(dir)?;
                    }
                }
            } else {
                println!("No skill found for '{}'.", ide_lower);
            }
        }
        SkillAction::List => {
            println!("IDE/agent skills:");
            println!();
            for d in &detected {
                let skill_file = d.skill_dir.join("devault").join("SKILL.md");
                let status = if skill_file.exists() { "installed" } else { "not installed" };
                println!("  {} - {}", d.name, status);
                if skill_file.exists() {
                    println!("    {}", skill_file.display());
                }
            }
        }
        SkillAction::Show { ide } => {
            let ide_lower = ide.to_lowercase();
            let target = detected.iter().find(|d| d.name == ide_lower);

            let skill_file = match target {
                Some(d) => d.skill_dir.join("devault").join("SKILL.md"),
                None => {
                    let home = dirs::home_dir().ok_or_else(|| {
                        DevaultError::InvalidInput("Cannot determine home directory".into())
                    })?;
                    home.join(".devault").join("skills").join(&ide_lower).join("SKILL.md")
                }
            };

            if skill_file.exists() {
                println!("{}", std::fs::read_to_string(&skill_file)?);
            } else {
                println!("No skill found for '{}'. Install with: devault skill add {}", ide_lower, ide_lower);
            }
        }
    }

    Ok(())
}