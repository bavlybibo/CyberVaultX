# Security Policy

CyberVault X is a local-first security project. Please report issues with clear reproduction steps and avoid including real passwords, master passwords, tokens, private keys, or personal vault data.

## Sensitive Data Rules

- Do not upload real vault databases publicly.
- Do not attach plaintext credential exports.
- Do not include master passwords or backup passphrases in bug reports.
- Use privacy-safe reports for demos or issue reproduction.

## Supported Security Expectations

- Master password is not stored.
- Credential fields are encrypted at rest.
- Reports and AI summaries redact secrets.
- Backups use a separate passphrase and integrity checks.

## Out of Scope for This Local Demo

- Cloud sync security, because the project does not include a sync backend.
- Full global breach intelligence, because the app includes only a local offline subset.
- Password recovery, because recovery would weaken the master-password model.
