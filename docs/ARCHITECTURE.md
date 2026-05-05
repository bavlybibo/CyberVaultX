# CyberVault X Architecture

CyberVault X keeps the existing `VaultManager` orchestration layer for compatibility, while exposing clearer modules for future development.

## Layers

1. **Core** — constants, config resolution, errors, shared safe models, system health.
2. **Crypto** — wrappers for key derivation and AES-GCM secret encryption. The implementation remains in `app.crypto_utils` to preserve existing tests and migrations.
3. **Security** — password strength analysis, secure password generation, local breach-subset checks, and vault-level risk summaries.
4. **Storage** — SQLite database and repository/backup facades.
5. **Services** — dashboard state, settings, reporting, backup, proof, health, and product intelligence.
6. **AI** — deterministic local coach that turns evidence into concise findings.
7. **UI** — Tkinter pages/controllers/refresh mixins. UI files should call services/manager methods and avoid owning business rules.

## Dependency Rule

UI may call services or `VaultManager`. Services may call security/crypto/storage/core. Crypto must not import UI. Reports must not include secrets.

## Compatibility

The existing `app.manager.VaultManager` remains the main integration point, so current UI and tests keep working while new modules make future refactors safer.
