# CyberVault X - Final Project Report

**Course:** CET334 - Cryptographic Algorithms & Protocols  
**Project:** Project 4 - Secure Password Manager with Local Encryption at Rest  
**Version:** v5.7.2 Strict Final Review  
**Team Size:** 3 students  
**Delivery Type:** Working desktop implementation, GitHub repository, documentation, presentation, screenshots, evidence files, and live demo

---

## 1. Executive Summary

CyberVault X is a local-first password manager and security-assessment desktop app. It protects credential data with **local encryption at rest using AES-GCM**, master-password protection, password generation, offline demo breach-subset checks, and security posture analysis.

The project is a **commercial-style academic prototype**. It extends the base password-manager requirement with an AI-style Local Security Coach, Security Proof Center, encrypted backups, a local audit hash-chain integrity check, privacy-safe reports, and local manifest integrity verification. All analysis is designed to run locally without sending secrets to external services.

---

## 2. Problem Statement

Users often reuse weak passwords across many services. When a single service is breached, attackers can use credential stuffing to compromise other accounts. A secure password manager should store credentials safely, generate strong passwords, warn users about risky credentials, and help them improve their security posture.

CyberVault X addresses this problem through encrypted local storage, local risk analysis, safe reporting, and demo-ready proof workflows.

---

## 3. Project Objectives

1. Build a local encrypted password vault.
2. Protect the vault with a strong master password and PBKDF2-based key derivation.
3. Encrypt sensitive credential fields using AES-GCM authenticated encryption.
4. Provide a configurable password generator.
5. Detect weak, reused, stale, and demo breach-subset passwords using an offline SHA1 list.
6. Generate privacy-safe reports for academic review.
7. Provide proof screens and verification tools that demonstrate security controls during the live demo.
8. Package final evidence: screenshots, sample outputs, test logs, preflight logs, PDF report, and PowerPoint deck.

---

## 4. Tools and Technologies

| Area | Technology |
|---|---|
| Language | Python 3.11+ |
| Desktop GUI | Tkinter |
| Encryption | PyCryptodome AES-GCM |
| Key Derivation | PBKDF2-SHA256 |
| Local Storage | SQLite |
| Testing | pytest / unittest |
| Packaging | PyInstaller |
| Documentation | Markdown, PDF report, PowerPoint deck |

**GUI note:** The original idea suggested PyQt5. CyberVault X uses Tkinter as a lightweight built-in desktop GUI alternative to reduce setup complexity while preserving the same functional objectives.

---

## 5. System Architecture

CyberVault X is organized into layers:

1. **UI Layer:** Desktop screens, dialogs, workflow controls, and presentation mode.
2. **Manager Layer:** Vault actions, authentication, settings, and service coordination.
3. **Service Layer:** Backup, reporting, local security coach, proof checks, product intelligence, and analysis helpers.
4. **Crypto Layer:** AES-GCM encryption, backup encryption, master password verification, and passphrase policies.
5. **Database Layer:** SQLite schema, migrations, metadata, credential rows, password history, and audit logs.
6. **Testing Layer:** Regression tests for encryption, reporting, backup, redaction, integrity checks, and product hardening.

---

## 6. Cryptographic Design

### 6.1 Master Password Protection

The master password is not stored directly. CyberVault X uses PBKDF2-SHA256 with a random salt to derive cryptographic material from the master password.

### 6.2 AES-GCM Field Encryption

Sensitive credential fields are encrypted before being written to SQLite. AES-GCM provides confidentiality and integrity, so tampered ciphertext should fail during decryption.

### 6.3 Additional Authenticated Data

Credential encryption uses context-specific Additional Authenticated Data (AAD), binding ciphertext to the credential id and field name. This reduces ciphertext-swapping risk.

### 6.4 Encrypted Backups

Backups use a dedicated encrypted envelope format. Backup import supports preview and rollback so a failed restore does not corrupt the active vault.

---

## 7. Main Features

### 7.1 Encrypted Vault

Users can add, edit, delete, restore, and search credentials. Sensitive fields remain encrypted at rest.

### 7.2 Password Generator

The generator supports configurable length, character classes, presets, and entropy feedback.

### 7.3 Security Center

The Security Center identifies weak, reused, demo breach-subset, stale, and metadata-incomplete credentials. It converts raw findings into readable risk levels.

### 7.4 AI-style Local Security Coach

The coach is deterministic and local. It does not call a cloud model. It transforms local findings into an executive summary, prioritized action plan, attacker view, remediation steps, and expected score improvement.

### 7.5 Security Proof Center

The Security Proof Center demonstrates encrypted schema validation, strict AAD status, local audit hash-chain integrity, report package verification, backup preview, and privacy-safe logging.

### 7.6 Local Audit Hash-Chain Integrity Check

Activity events are linked using previous-hash and event-hash values. If an old event is modified, deleted, or reordered without recalculating the chain, verification detects the problem. This is not tamper-proof against a privileged local attacker.

### 7.7 Privacy-Safe Reports

The reporting service exports executive and technical evidence without exposing raw passwords. Report packages include a manifest with SHA-256 hashes and a local HMAC-based manifest integrity signature.

---

## 8. Testing and Validation

Recommended commands:

```bash
python -m pytest -q
python -m pytest --cov=app --cov-report=term-missing
python tools/release_preflight.py
```

Saved evidence is stored in `evidence/`. Sample report outputs are stored in `sample_outputs/`.

---

## 9. Live Demo Scenario

1. Launch CyberVault X.
2. Create a vault with a strong master password.
3. Create the Assessment Workspace.
4. Open Dashboard and explain the health score.
5. Open Security Center and identify weak/reused/demo breach-subset entries.
6. Open the AI-style Local Security Coach and generate a plan.
7. Generate a replacement password.
8. Mark a remediation action as complete.
9. Open Security Proof Center and run proof checks.
10. Export and verify a report package.
11. Export an encrypted backup and preview restore impact.
12. Demonstrate panic lock.

---

## 10. Security Limitations

CyberVault X is a strong academic prototype, but it is not a certified commercial password manager. Important limitations:

- Python strings cannot be securely zeroized once loaded into runtime memory.
- PBKDF2-SHA256 is acceptable for course/demo compatibility, but Argon2id is stronger future work.
- The local HMAC manifest signature is not independently verifiable without the local secret.
- The offline breach database is a demo-sized subset, not a full breach-intelligence feed.
- The local audit hash-chain integrity check is useful for accidental or unsophisticated tampering, but not a complete defense against a privileged database writer.
- Tkinter is portable, but premium UI quality depends on careful styling and final Windows screenshots.

---

## 11. Final Submission Evidence

The final package includes standardized screenshot names, sample report outputs, test output files, coverage output when available, preflight output, and build instructions. The release preflight script checks stale version text, screenshots, evidence files, sample outputs, and core project structure.

---

## 12. Future Improvements

1. Optional Argon2id migration path while keeping PBKDF2 compatibility.
2. Optional custom offline breach-list import wizard.
3. Ed25519 public/private signature mode for independently verifiable report packages.
4. Better secure-memory handling where possible.
5. Component-level UI refactor for long-term maintainability.
6. Full screenshot automation after packaging on Windows.
7. Optional PyQt/PySide interface variant if the course instructor requires it.

---

## 13. Conclusion

CyberVault X satisfies the core requirements of the secure password manager project and extends them with professional security workflows. The project demonstrates applied cryptography, local privacy protection, secure software design, test coverage, report generation, and live-demo readiness.
