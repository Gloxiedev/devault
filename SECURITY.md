# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | ✅        |

## Reporting a Vulnerability

**Do not open public issues for security vulnerabilities.**

Please report security vulnerabilities by emailing: security@devault.dev

Include the following information:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Any proof-of-concept code (if applicable)

We will acknowledge receipt within 48 hours and provide a timeline for fix.

## What NOT to Publicly Disclose

- Details of unpatched vulnerabilities
- Exploit code or proof-of-concepts
- Information that could help attackers

## Security Features

### Encryption
- AES-256-GCM for authenticated encryption
- Argon2id for password-based key derivation (OWASP recommended)
- Per-credential unique data keys via HKDF
- Random 256-bit master key generated at vault creation

### Memory Safety
- `zeroize` crate on all sensitive types (`MasterKey`, `DataKey`)
- Automatic zeroization on drop
- No secrets in debug output or logs

### Local-Only Architecture
- Unix domain socket for IPC (filesystem permissions)
- No network listeners by default
- No cloud connectivity
- No telemetry

### Agent Authentication
- Token-based authentication
- Per-agent permissions
- Tokens never logged

## Threat Model

### Protected Against
- Local filesystem access to vault database
- Memory dumps (zeroization)
- Process listing (interactive password entry)
- Shell history (interactive input)
- Unauthorized agent access

### Not Protected Against
- Compromised host (root access)
- Malicious local user with same UID
- Hardware keyloggers
- Rubber-hose cryptanalysis

## Dependencies

We regularly audit dependencies:
- `cargo audit` in CI
- Minimal dependency policy
- Pinned versions in `Cargo.lock`

## Disclosure Timeline

1. **Day 0**: Vulnerability reported
2. **Day 1-2**: Acknowledgment and triage
3. **Day 7**: Initial assessment and timeline
4. **Day 30**: Target fix for critical issues
5. **Day 90**: Target fix for non-critical issues
6. **Release**: Security advisory published with fix