# CyberVault X Security Model

CyberVault X is a local password-security assessment prototype. It is designed to demonstrate sound security engineering choices in an academic setting without claiming to be a fully audited commercial password manager.

## Protected Assets

- Stored credential titles, usernames, passwords, notes, categories, tags, and websites.
- Master-password-derived vault key material.
- Encrypted backup contents.
- Report package integrity metadata.
- Local audit history.

## Trust Assumptions

- The user runs CyberVault X on a trusted local machine.
- The operating system account is not fully compromised while the vault is unlocked.
- The user remembers the master password and backup passphrase.
- Local files may be copied by an attacker, so at-rest encryption and backup encryption matter.

## Cryptographic Choices

| Control | Current implementation | Notes |
|---|---|---|
| Master password KDF | PBKDF2-SHA256 | Course-compatible and portable; Argon2id is stronger future work |
| Credential field encryption | AES-GCM | Uses authenticated encryption and contextual associated data |
| Backup encryption | Encrypted backup envelope with KDF metadata | Separate backup passphrase from vault password |
| Audit integrity | Local hash-chain integrity check | Detects accidental or simple local edits, not a fully trusted external ledger |
| Report package integrity | Local HMAC manifest signature labeled as local integrity proof | Useful locally; not independently verifiable without the local secret |

## Privacy Controls

- Reports never export plaintext credential passwords.
- Privacy-safe reports redact owner/vault identity and credential identifiers.
- Audit export sanitizes local paths under privacy-safe levels.
- AI-style Local Security Coach uses redacted local telemetry and deterministic rules.
- Custom breach-list import accepts local SHA1 hashes only and does not upload data.

## What Is Not Protected

- Python runtime strings cannot be securely zeroized.
- A fully compromised machine can observe data while the vault is unlocked.
- A local attacker who can edit both the database and integrity metadata may be able to recalculate local checks.
- The bundled breach list is a small offline subset, not a full internet breach service.
- Local HMAC report signatures are vault-local integrity proofs; report packages also include a public Ed25519 manifest signature for external verification. This proves package integrity, not legal identity attestation.

## Security Upgrade Hooks

- Add Argon2id as an optional KDF profile.
- Add optional certificate-style identity binding for report signing keys.
- Add stronger OS-specific secret storage for non-vault settings.
- Add stricter service separation after UI mixins are split.

- Local encryption at rest using AES-GCM protects credential fields before they are stored in SQLite.
