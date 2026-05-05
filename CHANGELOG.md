# Changelog

## 5.7.2 - Strict Final Review

- Fixed Tk UI smoke-test gating so headless Linux CI skips only when the display is unreachable instead of failing on stale DISPLAY values.
- Reworked release preflight compile validation to compile Python sources in memory without generating `__pycache__` artifacts.
- Added release preflight detection for stale validation logs and developer-local absolute paths.
- Removed developer-local absolute path usage from the presentation generator helper import.
- Added friendly GUI startup failure messaging for no-display environments while preserving normal Windows startup through `python main.py`.


## v5.6.9-core-health-hardening

- Added `app/core/` for core security/domain primitives.
- Centralized master-password policy validation and preserved generic, non-secret-leaking errors.
- Added local System Health / Dependency Check UI page.
- Added `setup_windows.bat`, `run_windows.bat`, and `requirements-dev.txt`.
- Added `docs/ARCHITECTURE_OVERVIEW.md` and `docs/DEMO_SCRIPT.md`.
- Improved release preflight with generated-cache detection.
- Added tests for core master-password policy and system-health readiness.
- Validated: 71 passed, 1 skipped; release preflight 30/30 passed.


## v5.6.8 — UI Delight & Guided Flow

- Refreshed the visual palette to feel more alive while keeping the premium dark look.
- Added page-specific color cues so each major workflow is easier to recognize instantly.
- Reworked the sidebar into clearer groups: Workspace and Control & Evidence.
- Added a guided context badge and page tip in the topbar to reduce confusion for first-time users.
- Improved metric cards with visual icons/badges for faster scanning.
- Preserved the existing local-first / AES-GCM / offline product behavior and passed regression tests.

## v5.6.7 — AI/UI Site Behavior Polish

### Added
- Site Behavior Reasoner fields for likely website behavior, symbol handling, MFA/passkey expectations, recovery-channel review, trusted-device review, and session/token cleanup.
- Live Password Coach now renders six chips: Length, Character Mix, Context Leak, Site Fit, MFA/Passkey, and Form Logic.
- Generator analysis includes likely website behavior and stronger site-fit explanations.
- AI Guardian v6 carries site behavior into redacted priority items and optional LLM context.

### Improved
- Reworked vault editor field order so Website/Category context is captured before Password typing.
- Reduced visual crowding in topbar, metrics, sidebar, and tables.
- Removed forced horizontal Treeview scrollbars that caused the white bars seen in the screenshots.
- Tuned table row height and fixed duplicated credential badge rendering.

### Validation
- Full test discovery: 68 tests OK, 1 skipped.

## v5.6.6 — Live Coach AI + UI polish

### Added
- Live Password Coach state model with readiness, mood, next best action, and likely site behavior.
- Four compact password-entry chips: Length, Character Mix, Context Leak, and Site Fit.
- AI Guardian Coach UX Snapshot with readiness, first user action, site profile mix, and UX prompts.
- AI export section for the Coach UX Snapshot.

### Improved
- AI Guardian mode upgraded to v5 while preserving Site Policy Reasoner wording for regression compatibility.
- Password editor now gives shorter, more enjoyable live feedback while the user types.
- Site Requirement Checklist includes inferred website behavior instead of only raw blocker text.

### Validation
- Full test discovery: 65 tests OK, 1 skipped.

- Added local site/account-profile inference so the app understands whether a credential is Email/Identity, Banking/Crypto, Infrastructure/Admin, Work/Developer, Social, Education, Shopping, Entertainment, or General.
- Added a **Live Password Coach** in the Vault editor that updates while the user types and shows site-fit score, target length, next fix, and MFA/passkey guidance.
- Added a **Site Requirement Checklist** inside the Credential Intelligence tab with blockers, warnings, passed checks, and the reason behind the inferred profile.
- Added a **Tune** action beside the password field to configure the Generator automatically for the current website/category.
- Upgraded AI Guardian to **Local-first Explainable AI Guardian v4 · Site Policy Reasoner** with site-fit mismatch as a ranking signal.
- Expanded Generator use cases with Social, Education, Servers, and Crypto presets.
- Added focused regression tests for the site-policy reasoner and AI Guardian site-fit fields.

## v5.6.4 — AI Precision & UI Cleanup Pass

- Upgraded AI Guardian to **Local-first Explainable AI Guardian v3**.
- Added confidence scoring, urgency scoring, primary risk signals, exposure paths, evidence tags, and decision traces for each priority item.
- Added AI Decision Matrix, Posture Heatmap, and Quality Gates to make the AI output cleaner and easier to defend in a presentation or report.
- Expanded the privacy-safe optional LLM payload with only redacted metrics, decision rows, and heatmap data.
- Improved the AI Guardian page layout: wider priority queue, clearer signal/confidence columns, and separate decision/quality panels instead of one long raw text block.
- Enhanced AI summary exports with evidence confidence, exposure paths, decision traces, heatmap rows, and quality-gate status.
- Added focused regression tests for the new explainability fields and redacted-context behavior.

## v5.6.3 — Product Polish Pass

- Updated the main UI language to feel like a product instead of a prototype-style deliverable.
- Hid assessment-workspace creation from primary screen actions and moved it under Quick Actions / Workspace Operations.
- Renamed visible full-screen walkthrough controls to **Full-Screen Focus Mode**.
- Replaced remaining prototype-style workspace records with enterprise-style records.
- Updated activity log wording to **Assessment Workspace Created** and **Assessment Workspace Already Present**.
- Added `PRODUCT_UI_POLISH_NOTES.md`.

## v5.6.2 — Assessment Dataset UI Polish

- Renamed visible dataset-loading workflow to **Create Assessment Workspace**.
- Expanded the built-in security assessment dataset to 30 curated synthetic records.
- Added richer data coverage for weak, breached, reused, stale, privileged, financial, cloud, DevOps, and retired credentials.
- Removed visible “demo vault” wording from the main UI flow, status messages, and activity logs.
- Updated dataset notes/tags/usernames to look like a professional security assessment workspace while remaining privacy-safe.


## v5.6.1-ui-polish

- Added scrollable page shells for all dense UI pages.
- Reduced default/minimum window sizing for projector/laptop friendliness.
- Cleaned topbar actions and pinned Panic Lock in the sidebar footer.
- Added tabbed Vault workspace: Details, Intelligence, History.
- Improved report export preview and CSV import wizard UX.
- Added active filter chip feedback and more explicit progress/status text.

## v5.6.0 — Professional Release & Demo Validation

- Added signed report packages using a local vault signing key and manifest HMAC verification.
- Added signature status to the package verifier and standalone verifier environment-key support.
- Added audit head hash export/compare support for stronger tamper-evident audit workflows.
- Added richer backup restore diff preview with add/skip/trash row decisions.
- Added local product-intelligence helpers: privacy redaction preview, AI-style security coach, attack-path simulation, executive score timeline, remediation workflow actions, CSV import wizard plan, and emergency kit export.
- Added Security Proof Center v3 structured sections for Encryption, Backup, Audit, Report, Privacy, and Runtime proof.
- Added `DEMO_SCRIPT.md`, `RELEASE_CHECKLIST.md`, `docs/WINDOWS_GUI_SMOKE_TEST.md`, `docs/EMERGENCY_KIT.md`, and an Inno Setup installer template.
- Bumped schema metadata to v9 for signed report packages and product release helpers.
- Added regression tests for v5.6.0 product-release features.

## v5.5.1 — Security Hardening Patch

- Hardened report package verification against path traversal, nested paths, unexpected files, duplicate manifest entries, and missing required files.
- Added audit retention compaction checkpoints so retained audit rows keep a valid tamper-evident hash chain after old events are purged.
- Renamed report digest copy to Payload SHA-256 and clarified that final artifact hashes live in the report package manifest.
- Fixed AI Guardian HTML report priority table column mismatch.
- Added explicit rollback handling to safety snapshot restore.
- Disabled PyInstaller UPX compression to reduce AV false positives.
- Added regression tests for v5.6.0 hardening behavior.


## v5.5 — Security Proof & Demo Intelligence

- Renamed the assessment pathway around **Assessment Dataset** for a stronger presentation story.
- Added **Security Proof Center** as a first-class sidebar page.
- Added report-package verification against `manifest.json` SHA-256 hashes.
- Added encrypted backup restore preview before Merge/Replace import.
- Added **AI Guardian v2** priority explanations: attack scenario, business impact, fix path, and expected score gain.
- Added tamper-evident audit hash chaining with schema migration v8.
- Split the Security Proof Center page into `app/ui_pages_proof.py` as the first focused UI-page refactor.
- Added regression tests for package tamper detection, backup preview, audit-chain tamper detection, and AI Guardian v2 redaction.
- Updated README release flow, screenshot list, and demo flow for the new proof-centered presentation.


## v5.4 — Demo Reliability & Presentation Polish

- Fixed **Load Demo Data** so it now works even after a user manually adds a credential.
- Assessment dataset loading is now idempotent: it merges curated synthetic assessment records and skips exact duplicates.
- Added a richer demo scenario covering healthy, weak, breached, reused, stale, incomplete metadata, and Trash recovery states.
- Added Security Center action buttons: Open in Vault, Generate Replacement, and Mark Reviewed.
- Improved generator empty state with clearer local-analysis capabilities.
- Increased desktop window size, tree row height, and core UI font/button sizing for better screenshots and live presentations.
- Assessment dataset loading now defaults report privacy to `analyst` to avoid unsafe public screenshots.
- Added regression coverage for demo merge behavior.


## vNext hardening pass

- Fixed AI Guardian snapshot behavior so normal refresh/report export no longer overwrites the comparison baseline.
- Added explicit AI baseline persistence when the user generates the smart plan.
- Hardened favicon lookup against stale async icon application.
- Blocked favicon lookup for private/internal hosts and sensitive local names.
- Enforced strict post-migration AAD decryption for credentials and password history.
- Made new credential insertion transaction-safe so the temporary pre-AAD row is never committed.
- Reduced plaintext metadata exposure in audit logs and safety snapshot metadata.
- Added Security Model and Limitations documentation.

## Hardened refactor patch

- Replaced password-generator randomness with `secrets.SystemRandom`.
- Fixed master-password rotation so encrypted owner/vault metadata is preserved.
- Added re-authentication verification that does not clear the active vault key on failure.
- Made normal lock clear clipboard content and hide revealed passwords.
- Scheduled auto-lock immediately after setup/unlock.
- Added stale single-instance lock recovery using stored PID checks.
- Redacted absolute paths from backup/report audit logs.
- Switched report/backup export writes to same-directory atomic file replacement.
- Strengthened backup passphrase validation and honored backup KDF iteration metadata.
- Added AES-GCM AAD support and row/field-bound AAD for credential fields with legacy fallback.
- Added a redacted `app/ai/` advisor context layer for future AI features.
- Expanded regression tests for rotation, re-auth, AAD tamper detection, backup policy, redacted logs, and AI-safe context.

# Changelog

## vNext - Security hardening refresh

### Added
- Re-authentication gate before copying passwords to the clipboard
- Persistent unlock throttling stored in SQLite metadata
- Backup passphrase flow separate from the vault password
- Backup format/integrity metadata (`CyberVaultBackup/v3`)
- Duplicate-aware backup import with import stats
- Privacy mode for local activity logs to hide credential titles
- Single-instance runtime lock and crash/runtime log file
- Unit tests for crypto, rotation/history, backup import, and unlock throttling
- Schema version metadata and lightweight migration defaults
- Prefix-indexed offline breach lookup path for better scalability

### Fixed
- Password history truncation during master-password rotation
- Password history truncation inside encrypted backups
- Secure-delete PRAGMA and storage cleanup after destructive operations
- Sensitive owner/vault metadata migration toward encrypted-at-rest storage

### Notes
- `ui.py` remains a large file and still needs a future structural split into smaller modules.
- Performance is improved only indirectly; the full decrypt-on-listing flow is still present and can be optimized further later.

## vNext - AI Guardian upgrade

### Added
- New **AI Guardian** page in the sidebar.
- **Generate Smart Security Plan** action that builds a local-first remediation plan from vault findings.
- Risk cards for Critical / High / Moderate / Low findings.
- AI-style executive summary, action plan, priority queue, and explanation panels.
- Privacy-preserving optional LLM payload blueprint that excludes raw passwords, full usernames, notes, backup blobs, and database paths.
- Dedicated AI Guardian summary export.
- Executive HTML/TXT report now includes an **AI Guardian Summary** and action plan.
- Regression tests for redacted AI planning, report AI summary inclusion, and AI export path redaction.

### Notes
- AI Guardian is deterministic and local-first in this build. No external AI API is called.
- Future LLM integration should only consume the generated redacted payload.

## AI Guardian polish and hardening patch

- Fixed the UI about-page favicon f-string compatibility issue.
- Removed runtime bytecode/cache folders from the distributable build.
- Added UI import and helper tests.
- Added composite risk scoring so AI Guardian considers reuse, breach/common hits, age, category criticality, and score.
- Stopped treating “No major issues detected.” as a real security finding.
- Hardened optional favicon lookup with HTTP/HTTPS-only handling, safe cache names, timeout, and download-size limit.
- Added privacy-safe report export from the UI and manager API.
- Made encrypted backup import validation and replacement transaction-safe.
- Split reusable risk policy, UI URL/favicon helpers, and AI insight simulation into separate modules as a gradual refactor step.
- Added `run.bat` for easier Windows demo startup.
- Added AI Guardian “What Changed” and “Fix Impact Simulation” sections in UI, text exports, and HTML reports.
- Expanded regression coverage to 24 tests.

## Release polish pass — branding, reports, audit, AI remediation

- Added bundled `app/assets/app_icon.png`, `app/assets/app_icon.ico`, and `app/assets/splash.png`.
- Updated PyInstaller spec to include app assets and Windows icon.
- Added startup splash screen and window icon branding.
- Added privacy-safe report package export with `manifest.json` SHA-256 hashes.
- Added AI Guardian remediation progress tracker with Mark Selected Fixed / Clear Progress actions.
- Added Generate Replacement Password shortcut from AI Guardian priorities.
- Improved Activity page with severity filter, date filter, failed-unlock metric, highlighted levels, report package export, and old-log purge action.
- Added password-history timeline with strength labels and re-authenticated reveal/copy for old passwords.
- Added activity-retention purge implementation.
- Added screenshot and Windows release checklists under `docs/`.

## v5.4.1 — Release Hardening Pass

- Added unified release metadata through `VERSION` and `app/version.py`.
- Updated the About page to read the canonical app version/channel.
- Hardened encrypted backup restore by disabling legacy no-AAD fallback by default.
- Added explicit transaction rollback to encrypted backup import.
- Added release/legal/security documents: `LICENSE`, `PRIVACY.md`, `SECURITY.md`, and `DISCLAIMER.md`.
- Added `docs/REFACTOR_ROADMAP.md` for the next safe component-level split.
- Updated README release-readiness table and final delivery checklist.


## 5.7.0-ui-command-center

### Added
- Dedicated Reports workspace for executive, privacy-safe, and signed package exports.
- Dedicated Backup / Recovery workspace for encrypted backup, preview, import, and safety snapshot recovery.
- Reusable UI helper components: page hero header, severity badge, mini stat card, report option card, and timeline step.
- UI navigation metadata test coverage for new premium pages.

### Changed
- Reorganized sidebar into Workspace, Delivery, and Operations sections.
- Renamed the generator navigation entry to Password Analyzer for a clearer demo flow.
- Moved advanced delivery/proof workflows out of crowded Settings/Proof-only flows into cleaner first-class pages.

### Security UX
- Reports page now explicitly reinforces privacy-safe exports.
- Backup page now emphasizes separate passphrases, non-destructive restore preview, and careful screenshot/report handling.

### Notes
- No new heavy UI dependency was added.
- Core encryption, database, backup, and report logic were not replaced.
