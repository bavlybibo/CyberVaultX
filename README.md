# CyberVault X v5.7.2 — Local Password Security Command Center

CyberVault X is a local-first cybersecurity vault and password-risk analysis desktop application. It stores credentials in an encrypted SQLite vault, analyzes password posture locally, generates privacy-safe reports, and provides a deterministic AI Security Coach without sending secrets to external services.

> Demo promise: the app is designed for a GitHub/demo walkthrough where the vault, dashboard, analyzer, coach, reports, backup/recovery, settings, and system-health screens all reflect real local data.

## Core Features

- **Encrypted local vault** using PBKDF2-SHA256 key derivation and AES-GCM authenticated encryption.
- **Master-password workflow** with policy checks, friendly wrong-password handling, and temporary lockout after repeated failures.
- **Credential vault UI** with add/edit/delete, trash/recovery, copy/reveal flows, categories, favorites, and search.
- **Password analyzer** with entropy, pattern, context, local breach-subset, and recommendation logic.
- **AI Security Coach** based on deterministic local evidence: weak passwords, reuse, old credentials, missing metadata, trash/backup posture, and site-fit reasoning.
- **Reports** in HTML, JSON, and text. Privacy-safe modes redact owner, titles, usernames, notes, paths, and secrets.
- **Encrypted backup/recovery** with separate backup passphrase, restore preview, duplicate handling, and safety snapshots.
- **System health** screen for runtime, crypto, storage, dependencies, required files, and report-engine status.
- **Release tooling** for preflight checks, project cleanup, and safe fake demo-vault generation.

## Security Model

CyberVault X is local-first. Raw passwords, the master password, derived keys, tokens, and notes are not exported in reports or AI coach payloads. Credential fields are encrypted at rest. Reports summarize risk without including plaintext secrets. Backup files are separately encrypted and integrity checked.

Important limitations are documented in [`docs/SECURITY_MODEL.md`](docs/SECURITY_MODEL.md) and [`docs/REPORTING.md`](docs/REPORTING.md). The bundled breach check is an offline subset and must not be described as a full internet breach lookup.

## Project Structure

```text
app/
  core/        config, constants, models, user-safe errors, health checks
  crypto/      wrapper layer around key derivation and vault encryption helpers
  security/    password strength, generator, breach checker, risk engine
  storage/     database/repository/backup facades
  services/    vault, settings, reporting, backup, proof, health services
  ai/          local deterministic coach, finding builder, recommendations
  ui*.py       Tkinter command-center UI and controllers
  manager.py   compatibility orchestration layer used by the UI/tests

tools/
  release_preflight.py
  project_cleaner.py
  demo_data_generator.py

tests/
  fast unit tests for crypto, vault manager, reporting, UI metadata, health, and product hardening
```

## Setup

```bash
python -m venv .venv
.venv\Scripts\activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m pip install -r requirements-dev.txt
```

On Windows, you can also run:

```bat
setup_windows.bat
run_windows.bat
```

## Run

```bash
python main.py
```

The app stores runtime data under a writable local app-data directory such as `%USERPROFILE%\.cybervault_x` on Windows or `app_data/` as fallback. The project does not hardcode absolute local paths.

## Test

```bash
python -m pytest -q
```

For release checks:

```bash
python tools/release_preflight.py
python tools/project_cleaner.py
```

## Demo Flow

1. Launch `python main.py`.
2. Create a vault with a strong master password.
3. Add a strong credential and a weak/demo credential.
4. Open Dashboard and confirm metrics reflect the actual saved rows.
5. Use Password Analyzer for live strength feedback.
6. Open AI Security Coach and review concise evidence cards.
7. Export a privacy-safe HTML or JSON report.
8. Create an encrypted backup and preview restore.
9. Open System Health and confirm runtime/crypto/report status.

## Screenshot Placeholders

Place GitHub screenshots in `assets/screenshots/`:

- `01_dashboard.png` — command center with real metrics.
- `02_vault.png` — searchable vault table and editor.
- `03_analyzer.png` — password analyzer and live coach.
- `04_ai_security_coach.png` — concise evidence cards.
- `05_reports.png` — report preview/export controls.
- `06_system_health.png` — dependency and release-readiness checks.

## Report Exports

- `.html` for executive/demo-ready reports.
- `.json` for machine-readable summaries.
- `.txt` for lightweight text reports.
- PDF is optional and should only be advertised when the reportlab-based tooling is confirmed in the current environment.

## Privacy and Safety

- No master password is stored.
- No plaintext credential password is stored in SQLite.
- No raw password is written to logs, reports, AI summaries, package manifests, or preflight output.
- Clipboard copy is time-bounded through settings.
- Backup restore requires passphrase validation and preview logic.

## Known Limitations

- The desktop UI depends on Tkinter and needs a graphical environment.
- Breach detection uses the bundled offline SHA1 subset only.
- This is a local password-security product, not a cloud sync service.
- The deterministic AI coach is evidence-based guidance, not an external LLM or breach-intelligence feed.

## Future Work

- Optional PDF report button when reportlab is installed and validated.
- Optional secure import adapters for browser exports.
- Stronger visual charts for risk trend history.
- Optional hardware-backed key storage integration.
- More extensive UI automation tests on Windows CI.
