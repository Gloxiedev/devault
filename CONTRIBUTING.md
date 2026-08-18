# Contributing to Devault

Thank you for contributing to Devault!

## Development Setup

### Prerequisites

- Rust 1.75+
- OpenSSL development headers
- pkg-config

```bash
# Ubuntu/Debian
sudo apt-get install libssl-dev pkg-config

# macOS
brew install openssl pkg-config

# Fedora
sudo dnf install openssl-devel pkg-config
```

### Building

```bash
git clone https://github.com/devault/devault
cd devault
cargo build
```

### Running Tests

```bash
cargo test
```

### Running Locally

```bash
# Initialize a test vault
cargo run -- init

# Add a credential
cargo run -- add test

# List credentials
cargo run -- list
```

## Repository Structure

```
devault/
├── src/
│   ├── main.rs              # CLI entry point
│   ├── lib.rs               # Library root
│   ├── error.rs             # Error types
│   ├── config/              # Configuration
│   ├── vault/               # Core vault implementation
│   │   ├── crypto.rs        # Encryption/decryption
│   │   ├── models.rs        # Data models
│   │   ├── database.rs      # SQLite storage
│   │   └── mod.rs           # Vault operations
│   ├── cli/                 # CLI commands
│   ├── daemon/              # Unix socket daemon
│   ├── agent/               # Agent client library
│   ├── ssh/                 # SSH execution
│   ├── git/                 # Git integration
│   ├── env/                 # Environment profiles
│   ├── backup/              # Backup/restore
│   └── ipc/                 # IPC protocol
├── Cargo.toml
├── README.md
├── LICENSE
├── CONTRIBUTING.md
├── SECURITY.md
├── CHANGELOG.md
└── .gitignore
```

## Coding Standards

- **Zero comments in source code** - Use descriptive names and clean architecture
- **Rust 2024 edition** - Use modern Rust patterns
- **Error handling** - Use `thiserror` for error types, `anyhow` for application errors
- **Async** - Use `tokio` for async operations
- **Crypto** - Never implement custom cryptography; use established libraries
- **Security** - Never log, print, or expose secrets

## Submitting Changes

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Make your changes
4. Run tests: `cargo test`
5. Run clippy: `cargo clippy -- -D warnings`
6. Run fmt: `cargo fmt --check`
7. Commit with conventional commits: `git commit -m "feat: add new feature"`
8. Push and create a Pull Request

## Security Expectations

- No hardcoded secrets or credentials
- No plaintext secret handling in logs/errors
- All cryptographic operations use established libraries
- Memory-zeroizing for sensitive data
- Input validation on all external data

## Testing Requirements

- Unit tests for all vault operations
- Integration tests for CLI commands
- Security tests for credential leakage
- Test both success and failure paths

## Release Process

1. Update version in `Cargo.toml`
2. Update `CHANGELOG.md`
3. Create release tag
4. GitHub Actions builds and publishes binaries