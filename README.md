# Devault

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/rust-1.75%2B-orange.svg)](https://www.rust-lang.org)

**Devault is a local credential vault and agent access layer for developers and AI coding agents.**

Devault securely stores developer credentials locally and allows AI agents/developer tools to use those credentials without unnecessarily exposing the raw secrets.

---

## Key Features

| Feature | Description |
|---------|-------------|
| **Local-First** | Runs entirely on your machine - no cloud, no accounts, no internet required |
| **Encrypted Vault** | AES-256-GCM encryption with Argon2id key derivation |
| **CLI** | Simple, memorable commands for credential management |
| **Agent Integration** | Local Unix socket API for AI coding agents |
| **SSH/VPS** | Execute commands on remote servers using stored credentials |
| **Git Integration** | Configure Git credentials for GitHub/GitLab/self-hosted |
| **Environment Profiles** | Inject secrets into child processes securely |
| **Encrypted Backups** | Portable, password-protected vault backups |
| **Tags & Search** | Organize and find credentials quickly |
| **JSON Output** | Machine-readable output for automation |
| **Shell Completion** | Bash, Zsh, Fish completion support |

---

## Architecture

```
                    LOCAL MACHINE

┌─────────────────────────────────────────────┐
│                                             │
│  Human ──→ Devault CLI                      │
│                │                            │
│                ↓                            │
│         ┌───────────────┐                   │
│         │    Devault    │                   │
│         │     Vault     │  (AES-256-GCM)    │
│         └───────┬───────┘                   │
│                 │                            │
│          Local IPC (Unix socket)            │
│                 │                            │
│        ┌────────┴─────────┐                  │
│        ↓                  ↓                  │
│    OpenCode           Other Agents           │
│                                             │
└─────────────────────────────────────────────┘
```

---

## Installation

### From Source (Rust)

```bash
git clone https://github.com/Gloxiedev/devault
cd devault
cargo install --path .
```

### Pre-built Binaries

Download from [GitHub Releases](https://github.com/Gloxiedev/devault/releases).

---

## Quick Start

```bash
# Initialize vault
devault init

# Add credentials (interactive, hidden input)
devault add github
devault add gemini
devault add production-vps

# List credentials
devault list

# Use VPS
devault server exec production-vps "systemctl status aegis"

# Run with environment profile
devault env run production -- npm run build
```

---

## CLI Reference

### Vault Management

```bash
devault init                    # Initialize new vault
devault unlock                  # Unlock vault (interactive password)
devault lock                    # Lock vault
devault status                  # Show vault status
devault status --json           # JSON output
```

### Credentials

```bash
devault list                                    # List all credentials
devault list --type api_token                   # Filter by type
devault list --tag production                   # Filter by tag
devault list --json                             # JSON output

devault add <name>                              # Interactive add
devault add <name> <credential> <context>       # Direct add
devault add github "TOKEN" "GitHub API token"   # Example

devault get <name>                              # Get metadata
devault get <name> --show                       # Show raw value

devault edit <name>                             # Edit credential
devault remove <name>                           # Remove credential
devault remove <name> --force                   # Force remove

devault search <query>                          # Search credentials
devault search github --type api_token          # Filtered search

devault tag <name> add <tag1,tag2>              # Add tags
devault tag <name> remove <tag1>                # Remove tags
```

### SSH / VPS Servers

```bash
devault server add production \
  --host example.com \
  --user ubuntu \
  --auth key \
  --secret ~/.ssh/id_rsa \
  --credential github-token

devault server list
devault server list --tag production
devault server get production
devault server exec production "systemctl status aegis"
devault server remove production
```

### Git Credentials

```bash
devault git add github \
  --host github.com \
  --user myuser \
  --type token \
  --credential github-token

devault git list
devault git use github              # Configure git for current repo
devault git use github --repo /path # Configure for specific repo
devault git remove github
```

### Environment Profiles

```bash
devault env list
devault env add production \
  --vars "DATABASE_URL=postgres://...,API_KEY=secret"
devault env run production -- npm run build
devault env remove production
```

### Agents

```bash
devault agent add opencode --permissions list,get,use,exec,git,env
devault agent list
devault agent revoke opencode
```

### Backups

```bash
devault backup create                          # Interactive password
devault backup create --output backup.json     # Specify output
devault backup restore backup.json             # Restore from backup
```

### Shell Completion

```bash
devault completion bash > /usr/local/share/bash-completion/completions/devault
devault completion zsh > ~/.zsh/completions/_devault
devault completion fish > ~/.config/fish/completions/devault.fish
```

---

## Agent Integration

Devault provides a local Unix socket API that AI coding agents can use.

### OpenCode Skill

```typescript
// .opencode/skill/devault.ts
import { DevaultAgent } from 'devault-agent';

const agent = new DevaultAgent('your-agent-token');

// List credentials
const creds = await agent.listCredentials();

// Use a server (Devault handles SSH internally)
const output = await agent.executeServer('production', 'systemctl status aegis');

// Get Git credentials
const { username, password } = await agent.gitAuth('github');

// Run with environment profile
await agent.runWithEnv('production', ['npm', 'run', 'build']);
```

### Available Agent Operations

| Operation | Description |
|-----------|-------------|
| `listCredentials()` | List all credentials (metadata only) |
| `getCredential(name)` | Retrieve raw credential value |
| `useCredential(name, operation)` | Use credential for operation |
| `executeServer(name, command)` | Execute command on SSH server |
| `gitAuth(name)` | Get Git credentials for host |
| `getEnvProfile(name)` | Get environment variables |

---

## Security Model

- **Encryption**: AES-256-GCM authenticated encryption
- **Key Derivation**: Argon2id with 32-byte salt
- **Master Key**: Randomly generated, encrypted with password-derived key
- **Per-Credential Keys**: Unique data keys derived per credential name
- **Memory Safety**: Zeroize trait on all sensitive types
- **Local Only**: Unix socket bound to filesystem, no network exposure
- **Agent Auth**: Token-based authentication for agent connections

### What Devault Does NOT Do

- ❌ No cloud sync or remote storage
- ❌ No approval queues or human-in-the-loop
- ❌ No enterprise IAM/policy engine
- ❌ No secret rotation automation
- ❌ No audit logging to external systems

---

## Configuration

Devault stores its configuration at `~/.devault/config.toml`:

```toml
vault_path = "/home/user/.devault/vault.db"
socket_path = "/tmp/devault.sock"

[daemon]
enabled = true
auto_start = false
```

Environment variables:
- `DEVAULT_VAULT` - Override vault path
- `DEVAULT_SOCKET` - Override socket path

---

## Development

### Requirements

- Rust 1.75+
- OpenSSL development headers (for `ssh2`)

### Building

```bash
cargo build --release
```

### Testing

```bash
cargo test
```

### Running Locally

```bash
cargo run -- init
cargo run -- add test
cargo run -- list
```

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for details.

---

## Security

See [SECURITY.md](SECURITY.md) for vulnerability reporting.

---

## License

MIT License - see [LICENSE](LICENSE) for details.