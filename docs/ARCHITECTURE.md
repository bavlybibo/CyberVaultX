# CyberVault X Architecture

CyberVault X is a local-first desktop application with a Tkinter UI and a service-oriented Python backend. The current version keeps backward compatibility with legacy manager methods while gradually extracting product workflows into focused services.

## Layers

```text
UI layer
  app/ui.py
  app/ui_pages.py
  app/ui_controllers.py
  app/ui_refresh.py

Service layer
  app/services/analysis.py
  app/services/ai_guardian.py
  app/services/backup.py
  app/services/proof.py
  app/services/reporting.py
  app/services/product_upgrade.py

Core/security layer
  app/crypto_utils.py
  app/analyzer.py
  app/breach_db.py
  app/security_policy.py
  app/site_policy.py

Storage layer
  app/db.py
  SQLite vault database
```

## Vault Lifecycle

1. User creates a vault and master password.
2. PBKDF2-SHA256 derives key material from the master password.
3. Credential fields are encrypted using AES-GCM with contextual associated data.
4. Metadata/settings are stored locally.
5. Audit events are appended with a hash-chain integrity value.
6. UI refresh builds an in-memory snapshot for dashboard, findings, reports, and coach recommendations.

## Dashboard Flow

The Dashboard Command Center uses `manager.dashboard()`, `manager.security_findings()`, `manager.report_readiness_score()`, and Proof Center status to answer:

- Is the vault healthy?
- Which findings are highest priority?
- Is backup/report evidence ready?
- What should be fixed first?

## Security Center Flow

Security Center findings are generated from decrypted in-memory credential objects. Findings are grouped by local risk signals:

- password strength
- offline breach-subset hit
- reuse count
- password age
- missing metadata
- inferred site-policy fit

## Report Export Flow

1. User chooses report type and privacy level.
2. Privacy-safe payload is generated.
3. `check_privacy_safe_export()` blocks obvious raw secret, owner identity, note, username, and local-path leaks.
4. HTML/JSON/TXT report is written.
5. Package export writes report artifacts, manifest hashes, local manifest signature, and verification output.

## Backup Flow

1. Backup export uses a separate backup passphrase.
2. Restore preview decrypts the backup and reports impact without modifying the current vault.
3. Replace operations create local safety snapshots before destructive changes.
4. Backup status is surfaced in Trust Center and report readiness.

## Trust / Proof Flow

Proof Center combines:

- encrypted schema checks
- strict AAD migration state
- audit hash-chain verification
- report package verification
- backup format status
- privacy-safe logs
- local KDF policy checks

## Maintainability Notes

The codebase still contains large UI mixins. Product logic added in this upgrade lives in `app/services/product_upgrade.py` to avoid making the UI files larger than necessary. Future refactoring should split UI pages, controllers, widgets, and dialogs without changing service contracts.
