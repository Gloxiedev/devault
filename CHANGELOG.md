# Changelog

All notable changes to Devault will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial implementation of Devault local credential vault
- AES-256-GCM encryption with Argon2id key derivation
- CLI with commands: init, unlock, lock, status, list, add, get, remove, edit, search
- Credential types: password, api_key, api_token, ssh_key, vps, git, database, cloud, docker, environment, generic
- SSH/VPS server management and command execution
- Git credential integration for GitHub/GitLab/self-hosted
- Environment profile management with secure injection
- Agent API via Unix domain socket
- Token-based agent authentication with permissions
- Encrypted backup/restore functionality
- Tag support for credentials
- Search across credential metadata
- JSON output for all list/status/search commands
- Shell completion for Bash, Zsh, Fish
- Comprehensive test suite

### Security
- Zeroize trait on all sensitive types
- No secrets in logs, errors, or debug output
- Per-credential unique encryption keys
- Secure memory handling

## [0.1.0] - 2024-01-XX

### Added
- Initial release