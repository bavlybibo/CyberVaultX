# Security Model

CyberVault X is a local-first encrypted password vault.

## Key Derivation

The master password is processed through PBKDF2-SHA256 with a random salt. The derived key is held in memory only while the vault is unlocked. The master password itself is not stored.

## Encryption

Credential fields are encrypted with AES-GCM. Row/field-associated data binds encrypted values to their intended database context, reducing the risk of ciphertext field swaps.

## Authentication Handling

Wrong master-password attempts do not reveal sensitive details. Repeated failures trigger a temporary lockout. Re-authentication checks do not clear an already-unlocked vault key.

## Reports and AI Coach

Reports and AI outputs are risk summaries. They must not include plaintext passwords, master passwords, derived keys, tokens, full notes, or raw secret material. Privacy-safe reports redact owner, title, username, website, and local paths depending on level.

## Backups

Backups are encrypted with a separate passphrase and AES-GCM context. Restore preview and duplicate handling are available before importing into the current vault.

## Limitations

The bundled breach database is an offline subset. It is useful for demo/local detection but does not prove a password is absent from all breaches.
