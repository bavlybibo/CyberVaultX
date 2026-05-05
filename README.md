<div align="center">

# CyberVault X

### Local-First Password Vault & Security Posture Command Center

CyberVault X is a desktop cybersecurity application for storing encrypted credentials, analyzing password risk, generating privacy-safe reports, and guiding users with a deterministic local AI Security Coach.

![Python](https://img.shields.io/badge/Python-3.10%2B-blue)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Desktop-lightgrey)
![Security](https://img.shields.io/badge/Security-Local--First-success)
![License](https://img.shields.io/badge/License-MIT-green)

</div>

---

## Overview

**CyberVault X** is built as a local password-security workspace, not a cloud password manager. It combines an encrypted SQLite vault, password-strength analysis, local breach-subset checks, risk scoring, backup/recovery workflows, and exportable security reports in one desktop interface.

The project is designed for cybersecurity students, security analysts, demo environments, and local-first password posture assessment.

---

## Key Features

| Area | What CyberVault X Provides |
|---|---|
| **Encrypted Vault** | AES-GCM encrypted credential fields with PBKDF2-SHA256 key derivation. |
| **Master Password Flow** | Strong password policy checks, safe error messages, and temporary lockout after repeated failures. |
| **Credential Management** | Add, edit, delete, recover, favorite, search, copy, and reveal credentials through a desktop UI. |
| **Password Analyzer** | Entropy checks, weak-pattern detection, reuse signals, context leaks, and local breach-subset checks. |
| **AI Security Coach** | Deterministic local guidance based on vault evidence, not external API calls. |
| **Reports** | Export HTML, JSON, and text reports with privacy-safe redaction modes. |
| **Backup & Recovery** | Encrypted backups with separate passphrases, restore preview, duplicate handling, and safety snapshots. |
| **System Health** | Runtime, crypto, storage, dependency, report-engine, and release-readiness checks. |
| **Release Tooling** | Preflight checks, cleanup tooling, demo-data generation, and Windows launch scripts. |

---

## Screenshots

> Add screenshots inside `assets/screenshots/` and replace these placeholders.

| Dashboard | Vault Workspace |
|---|---|
| `assets/screenshots/01_dashboard.png` | `assets/screenshots/02_vault.png` |

| Password Analyzer | AI Security Coach |
|---|---|
| `assets/screenshots/03_analyzer.png` | `assets/screenshots/04_ai_security_coach.png` |

| Reports | System Health |
|---|---|
| `assets/screenshots/05_reports.png` | `assets/screenshots/06_system_health.png` |

---

## Security Model

CyberVault X follows a **local-first security model**:

- The master password is **not stored**.
- Credential passwords are **not stored in plaintext**.
- Vault fields are encrypted at rest using **AES-GCM**.
- Keys are derived using **PBKDF2-SHA256** with a random salt.
- Reports and AI summaries are designed to avoid leaking plaintext secrets.
- Backup files use a separate passphrase and integrity checks.
- The AI Security Coach is deterministic and local; it does not send secrets to an external LLM.

> This project is an academic/product prototype and should not be treated as a formally audited commercial password manager.

---

## Project Structure

```text
CyberVaultX/
├── app/
│   ├── ai/              # Local AI coach, findings, recommendations
│   ├── core/            # Config, constants, models, errors, health checks
│   ├── crypto/          # Key derivation and vault crypto wrappers
│   ├── security/        # Password strength, breach checks, risk engine
│   ├── services/        # Vault, settings, reports, backup, health services
│   ├── storage/         # SQLite database and repository layer
│   ├── ui*.py           # Tkinter UI pages, controllers, visuals, dialogs
│   └── manager.py       # Main orchestration layer
├── assets/
│   └── screenshots/     # GitHub/demo screenshots
├── docs/                # Architecture, usage, reporting, security docs
├── installer/           # Windows installer template
├── presentation/        # Project presentation assets
├── tests/               # Unit and product-hardening tests
├── tools/               # Preflight, cleanup, demo data, report tools
├── main.py              # Application entry point
├── requirements.txt     # Runtime dependencies
└── README.md
```

---

## Requirements

- Python **3.10+** recommended
- Windows desktop environment recommended
- Tkinter support enabled
- Runtime dependencies from `requirements.txt`
- Development dependencies from `requirements-dev.txt`

Current core runtime dependencies:

```text
pycryptodome>=3.20.0
cryptography>=43.0.0
```

---

## Quick Start

### 1. Clone the repository

```bash
git clone https://github.com/<your-username>/<your-repo>.git
cd <your-repo>
```

### 2. Create a virtual environment

```bash
python -m venv .venv
```

### 3. Activate the environment

**Windows:**

```bat
.venv\Scripts\activate
```

**Linux/macOS:**

```bash
source .venv/bin/activate
```

### 4. Install dependencies

```bash
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

### 5. Run the app

```bash
python main.py
```

---

## Windows Shortcuts

The project includes helper scripts for Windows users:

```bat
setup_windows.bat
run_windows.bat
```

You can also use:

```bat
run.bat
```

---

## Testing

Install development dependencies:

```bash
python -m pip install -r requirements-dev.txt
```

Run the test suite:

```bash
python -m pytest -q
```

Run release checks:

```bash
python tools/release_preflight.py
python tools/project_cleaner.py
```

---

## Reports

CyberVault X can export:

- **HTML reports** for polished demo and review use.
- **JSON reports** for structured validation and tooling.
- **Text reports** for lightweight summaries.

Reports may include vault posture, risk summary, AI coach findings, recommendations, limitations, and integrity metadata. They are designed to avoid exporting plaintext passwords or master secrets.

---

## Demo Workflow

A clean project demo can follow this path:

1. Launch CyberVault X.
2. Create a new vault with a strong master password.
3. Add one strong credential and one weak credential.
4. Review dashboard metrics.
5. Open Password Analyzer and compare password quality.
6. Open AI Security Coach and review evidence-based recommendations.
7. Export a privacy-safe HTML report.
8. Create an encrypted backup.
9. Open System Health and confirm release readiness.

---

## Privacy Notes

CyberVault X is designed to keep sensitive data local:

- No cloud sync backend is included.
- No plaintext password export is required for reports.
- No external AI service is required for the local coach.
- Demo screenshots should use synthetic credentials only.
- Real vault databases should never be uploaded publicly.

---

## Known Limitations

- The bundled breach database is an offline subset, not a complete global breach source.
- The UI requires a graphical desktop environment.
- PDF export is optional and should only be used when the report tooling is installed and verified.
- The project has not undergone third-party cryptographic or penetration-testing audit.
- It is not a cloud password manager and does not include account sync.

---

## Documentation

Useful project docs:

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)
- [`docs/SECURITY_MODEL.md`](docs/SECURITY_MODEL.md)
- [`docs/USAGE.md`](docs/USAGE.md)
- [`docs/REPORTING.md`](docs/REPORTING.md)
- [`docs/TROUBLESHOOTING.md`](docs/TROUBLESHOOTING.md)
- [`SECURITY.md`](SECURITY.md)
- [`PRIVACY.md`](PRIVACY.md)
- [`DISCLAIMER.md`](DISCLAIMER.md)

---

## Roadmap

- Improve Windows UI automation coverage.
- Add optional browser-export import adapters.
- Add stronger posture trend charts.
- Add optional hardware-backed key storage support.
- Expand report templates for executive and technical audiences.

---

## License

This project is licensed under the **MIT License**. See [`LICENSE`](LICENSE) for details.

---

<div align="center">

**CyberVault X** — Local-first credential protection, password-risk analysis, and privacy-safe security reporting.

</div>
