use crate::error::{DevaultError, Result};
use crate::vault::models::*;
use std::process::Command;

pub async fn run_with_env(profile: &EnvironmentProfile, command: &[String]) -> Result<()> {
    if command.is_empty() {
        return Err(DevaultError::InvalidInput("No command provided".into()));
    }

    let mut cmd = Command::new(&command[0]);
    cmd.args(&command[1..]);

    for var in &profile.variables {
        let value = String::from_utf8_lossy(&var.value);
        cmd.env(&var.key, value.as_ref());
    }

    let status = cmd.status()
        .map_err(|e| DevaultError::InvalidInput(format!("Failed to execute command: {}", e)))?;

    if !status.success() {
        return Err(DevaultError::InvalidInput(format!("Command exited with status: {}", status)));
    }

    Ok(())
}

pub fn generate_env_file(profile: &EnvironmentProfile, path: &std::path::Path) -> Result<()> {
    let mut content = String::new();
    for var in &profile.variables {
        let value = String::from_utf8_lossy(&var.value);
        content.push_str(&format!("{}={}\n", var.key, value));
    }
    std::fs::write(path, content)
        .map_err(|e| DevaultError::Io(e))?;
    Ok(())
}

pub async fn get_env_vars(profile: &EnvironmentProfile) -> Result<Vec<(String, String)>> {
    let mut vars = Vec::new();
    for var in &profile.variables {
        let value = String::from_utf8_lossy(&var.value);
        vars.push((var.key.clone(), value.to_string()));
    }
    Ok(vars)
}