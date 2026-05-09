# CyberVault X Architecture Overview

## Layered design

CyberVault X now uses a clearer layered layout while keeping backward-compatible module names:

- `app/core/` — deterministic security/domain primitives such as master-password policy and system-health checks.
- `app/crypto_utils.py` — AES-GCM encryption, PBKDF2 key derivation, backup encryption, and integrity helpers.
- `app/db.py` — SQLite schema, migrations, metadata, activity log, and low-level storage.
- `app/manager.py` — vault orchestration layer used by UI and tests.
- `app/services/` — reporting, backup/restore, AI-style Local Security Coach, proof/signing, and snapshot workflows.
- `app/ai/` — redacted deterministic recommendation logic.
- `app/ui*.py` — Tkinter desktop UI pages, visual styling, controllers, dialogs, and refresh logic.
- `tests/` — unit and workflow tests.

## Data flow

1. UI collects a credential and sends it to `VaultManager`.
2. `VaultManager` validates state and encrypts sensitive fields.
3. `crypto_utils` derives/uses the active vault key and AES-GCM AAD.
4. `VaultDatabase` writes only ciphertext, nonce, timestamps, and non-secret metadata.
5. Analysis/reporting services decrypt only while the vault is unlocked and produce redacted summaries when exporting.

## AI/security coach model

The assistant is local and deterministic. It ranks real signals such as weak score, reuse, stale age, local breach hash hit, missing metadata, and site-policy fit. It must not claim remote breach intelligence or external AI processing unless explicitly added in the future.
