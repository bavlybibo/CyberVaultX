# CyberVault X v5.7.2

CyberVault X is a **commercial-style academic prototype** for local password-security assessment. It stores credentials in an encrypted SQLite vault, analyzes password posture locally, explains risk with a deterministic **Local Security Coach**, exports privacy-safe evidence packages, and verifies local integrity controls without cloud processing.



## Bonus Feature Pack

CyberVaultX now includes a bonus-grade security evidence layer:

- Security Proof Center for local proof checks and audit-chain validation.
- Attack Simulation Lab for safe defensive simulations.
- Privacy Export Preview before report export.
- Password Relationship Graph for reuse and near-duplicate pattern clusters.
- Remediation Planner with Today / This Week / Later actions.
- Generator Plus with profile-aware password/passphrase generation.
- Emergency Kit with recovery instructions, proof evidence, manifest hashes, and optional encrypted backup.
- Security Evidence Package exporting proof, attack lab, privacy preview, graph, remediation plan, timeline, backup status, clipboard status, and manifest.
- Isolated Demo Vault mode that opens synthetic data in a separate local database instead of mutating the real vault.
- Conservative passphrase model that penalizes famous phrases while avoiding unfair Very Weak results for generated-style multi-word passphrases.

All bonus features are local, deterministic, privacy-aware, and covered by `tests/test_bonus_features.py`. See `docs/BONUS_FEATURES.md` for the detailed feature map and security honesty notes.

## Feature Matrix

| Capability | Implementation | Verification |
|---|---|---|
| Local encrypted vault | SQLite + AES-GCM encrypted credential fields | `app/manager.py`, `app/crypto_utils.py`, `tests/test_crypto.py` |
| Password posture analysis | Weak, reused, stale, context-based, and offline breach-subset checks | `app/analyzer.py`, `app/services/analysis.py` |
| Local Security Coach | Rule-based recommendations with evidence, confidence, and next action | `app/ai/`, `app/services/ai_guardian.py` |
| Security Center | Severity-based findings for Critical/High/Medium/Low triage | `app/ui_pages.py`, `app/ui_refresh.py` |
| Proof / Trust Center | Local audit hash-chain, backup, report-package, privacy checks, and public Ed25519 manifest signature verification | `app/services/proof.py`, `app/services/product_upgrade.py` |
| Report Export Wizard | Report type, privacy level, package generation, verification output | `app/services/reporting.py`, `verify_report_package.py` |
| Backup / Restore | Encrypted backup, restore preview, duplicate handling, rollback snapshot | `app/services/backup.py` |
| Custom breach subset | Local SHA1 hash-list import with format validation | `app/breach_db.py`, `app/services/product_upgrade.py` |
| Isolated demo vault | Separate synthetic demo database with visible DEMO VAULT banner | `app/manager.py`, `app/ui_controllers.py`, `tests/test_strong_pass_upgrades.py` |
| Release quality | Tests, coverage, and release preflight gate | `tests/`, `tools/release_preflight.py` |

## Quick Start

```bash
python -m venv .venv
.venv\Scripts\activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m pip install -r requirements-dev.txt
python main.py
```

Windows helper scripts are also included:

```bat
setup_windows.bat
run_windows.bat
```

## Product Workflow

1. Create or unlock a local vault.
2. Add credentials manually or import a CSV using the safe import wizard.
3. Review the Dashboard Command Center for health score, findings, backup status, audit integrity, and next actions.
4. Open Security Center to triage findings by severity, confidence, status, and recommended fix.
5. Review the Local Security Coach for rule-based recommendations and evidence.
6. Check report readiness before export.
7. Export a privacy-safe package and verify the manifest output.
8. Export an encrypted backup and preview restore impact before any restore operation.
9. Use **Open Isolated Demo Vault** for presentations when sample data is needed; it never inserts demo credentials into the real vault.

## Report Outputs

A report package can include:

- `executive_report.html`
- `audit_log.html`
- `ai_guardian_summary.txt` internal legacy filename containing the Local Security Coach summary
- `manifest.json`
- `verification_output.txt`

Sample exported outputs are available in `sample_outputs/`.

## Security Model Summary

- Master password derives the local vault key through PBKDF2-SHA256.
- Credential fields are protected using AES-GCM encryption at rest.
- Reports do not export plaintext passwords or master-password material.
- Privacy-safe reports redact owner identity, credential titles, usernames, notes, local paths, and raw secrets according to level.
- Audit logs use a local hash-chain integrity check.
- Report packages use both a local manifest integrity signature and a public Ed25519 manifest signature. The local HMAC is vault-only; the Ed25519 signature can be checked by the external verifier without the vault secret.
- All password analysis and breach-subset checks run locally.

See `docs/SECURITY_MODEL.md`, `docs/THREAT_MODEL.md`, and `docs/LIMITATIONS.md`.

## Testing

```bash
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 python -m pytest -q
python -m pytest --cov=app --cov-report=term-missing
python tools/release_preflight.py
python -m ruff check .
```

Saved evidence files are in `evidence/` when generated by the release process.

## Project Structure

```text
app/              application code and service layer
docs/             architecture, security model, grading evidence, walkthrough
tests/            regression and product-quality tests
tools/            release preflight and generation helpers
sample_outputs/   exported report examples
evidence/         test/preflight/build logs from release checks
```

## Team Roles

| Team Member | Role | Main Areas |
|---|---|---|
| Bavly | Product/security lead | Security architecture, vault workflow, reporting, QA |
| Member 2 | UI/product flow | Dashboard, Security Center, settings polish |
| Member 3 | Testing/documentation | Test evidence, walkthrough, grading evidence |

Update names and ownership before final submission if your team structure differs.

## Limitations

- Python strings cannot be securely zeroized once loaded into runtime memory.
- PBKDF2-SHA256 is acceptable for course/demo compatibility; Argon2id is stronger future work.
- The local HMAC manifest signature is not independently verifiable without the local secret, but report packages now also include a public Ed25519 manifest signature for external verification.
- The bundled offline breach database is a demo-sized subset, not a full internet breach lookup.
- Tkinter is portable, but it requires careful layout discipline to feel premium.

## Future Work

- Argon2id migration option.
- Optional certificate-style identity binding for the Ed25519 public key.
- More service extraction from the legacy UI mixins.
- Optional PyQt/PySide interface after core services remain stable.

## Security Model Summary
- Local encryption at rest using AES-GCM protects credential fields before they are stored in SQLite.

## v5.7.2 Security Trust Upgrade Notes

This release hardens the project after the zero-mercy audit:

- Password scoring now separates raw charset entropy from pattern-adjusted effective entropy.
- Predictable passwords such as keyboard walks, season/year combinations, dictionary words plus suffixes, context-derived passwords, and weak leetspeak bases are capped below Excellent.
- The Security Coach is explicitly local deterministic guidance. It does not use an external LLM, does not send secrets to cloud AI, and labels confidence as heuristic policy confidence unless a measured calibration dataset is added.
- Full reports default away from private export and require explicit acknowledgement plus master-password re-authentication in the UI.
- Audit export redaction now uses a universal redaction pass for paths, emails, tokens, raw credential values, notes, and domains where required by privacy level.
- Synthetic assessment credentials were moved out of the production backup service into `app/demo/sample_workspace.py`.
- Presentation mode no longer inserts demo data into a real vault.
- Merge backup imports now create encrypted safety snapshots before mutation.
- Normal backup import no longer accepts legacy no-AAD fallback unless launched through an explicit migration environment gate.

## KDF Roadmap

Current vault metadata uses PBKDF2-SHA256 for course compatibility and broad Windows portability. Future production hardening should add versioned Argon2id metadata and a guided migration flow. PBKDF2 remains acceptable for this academic prototype only when paired with strong master-password policy, high iterations, random salt, and AES-GCM authenticated encryption.
