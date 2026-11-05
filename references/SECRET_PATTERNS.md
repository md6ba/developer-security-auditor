# Secret Patterns

Patterns used by `secret_scan.py` and `git_history_scan.py`. Each entry lists what it
matches, where it is usually found, and how to report it without exposing the value.

**Never print a matched value.** Report length, charset class, and a SHA-256 prefix.

## Credential categories

| Category | Typical shape | Example locations |
|----------|---------------|-------------------|
| Cloud access key | `AKIA` + 16 uppercase alphanumeric | `.env`, `settings.py`, CI variables |
| Private key | `-----BEGIN ... PRIVATE KEY-----` | `keys/`, `*.pem`, `*.key` |
| Database URL with credentials | `scheme://user:pass@host` | `.env`, config, compose files |
| API key | long alphanumeric, often prefixed | source, docs, CI |
| JWT signing secret | high-entropy string | settings, `.env` |
| Telegram bot token | `<digits>:<30+ chars>` | `.env`, bot source |
| SMTP / mail password | 16-char app password format | settings, `.env` |
| OAuth client secret | high-entropy string | `.env`, config |
| RPC provider credential | URL with project ID | source, config |
| Web3 private key | `0x` + 64 hex | source, tests, `.env` |
| Mnemonic / seed phrase | 12–24 dictionary words | source, notes |
| Session secret | high-entropy string | settings, `.env` |
| Encryption key | base64/hex block | config, source |
| Access token | `ghp_`, `xox`, payment-provider secret keys | source, CI |

## High-value file locations

Search these first — they carry the most exposure:

1. `.env`, `.env.*` (excluding `*.example`, `*.sample`, `*.template`)
2. `*.pem`, `*.key`, `*.p12`, `*.pfx`, `*.keystore`
3. `docker-compose*.yml`, `Dockerfile`, `Containerfile`
4. `.github/workflows/*.yml`, `.gitlab-ci.yml`, `Jenkinsfile`
5. `settings.py`, `config.py`, `config.json`, `config.yml`, `appsettings.json`
6. `credentials*`, `secrets*`, `service-account*.json`
7. `requirements.txt`, `package.json`, `pyproject.toml` (for scripts, not secrets)
8. Documentation: README, wiki exports, markdown with code blocks
9. Logs and backups: `*.log`, `*.bak`, `*.sql`, `*.dump`
10. Build artifacts: `dist/`, `build/`, `out/`

## Repeated credentials

The same secret often appears in several files. Detect this by fingerprint:

```
sha256[:12] of the matched value
```

Group findings by fingerprint. A repeated credential is a stronger signal than a
single occurrence: it means the secret was copied, and rotation must cover every copy.

## Reporting format

```
MORALIS_API_KEY=[REDACTED]  (44 chars, base64ish, sha256:8f3a1c9e2b7d)
```

Never include:
- the full value
- more than the first and last 4 characters
- enough context to reconstruct the value

## Status wording

Always use:

```
UNVERIFIED - POTENTIALLY EXPOSED
```

Do not write "valid", "active", "compromised", or "exploited" unless the account
owner has provided authorized evidence.
