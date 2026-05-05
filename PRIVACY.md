# Privacy

CyberVault X is designed to run locally. It does not require network access for vault storage, password analysis, reports, backups, or the deterministic AI Security Coach.

## Data Stored Locally

- Encrypted credential fields.
- Non-secret settings such as theme and timeout values.
- Privacy-redacted audit events.
- Encrypted backup/report signing metadata when needed.

## Data Not Stored in Plaintext

- Master password.
- Credential passwords.
- Backup passphrases.
- Derived encryption keys.

## Reports

Privacy-safe reports redact owner name, vault name, credential titles, usernames, websites, notes, and local paths according to the selected privacy level. Reports never include plaintext passwords.
