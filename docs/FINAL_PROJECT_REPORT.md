# CyberVault X - Final Project Report

**Course:** CET334 - Cryptographic Algorithms & Protocols  
**Project:** Project 4 - Secure Password Manager with End-to-End Encryption  
**Version:** 5.7.2 Strict Final Review  
**Team Size:** 3 students  
**Delivery Type:** Working desktop implementation, GitHub repository, documentation, presentation, and live demo

---

## 1. Executive Summary

CyberVault X is a local-first password manager designed to protect user credentials using end-to-end encryption, master-password protection, password generation, breach checking, and security posture analysis. The project implements the required cryptographic core while extending the original scope with a professional product layer: AI Guardian, Security Proof Center, encrypted backups, tamper-evident audit logs, privacy-safe reports, and report-package verification.

The system is built as an academic security product prototype. It runs locally, stores data in SQLite, encrypts sensitive fields before database storage, and avoids cloud transmission for vault data and security analysis.

---

## 2. Problem Statement

Users often reuse weak passwords across many services. When a single service is breached, attackers can use credential stuffing to compromise other accounts. A secure password manager should solve this problem by storing credentials safely, generating strong passwords, warning users about risky credentials, and helping them improve their security posture.

CyberVault X addresses this problem by combining encrypted local storage with practical user-facing security workflows.

---

## 3. Project Objectives

1. Build a local encrypted password vault.
2. Protect the vault with a strong master password and PBKDF2-based key derivation.
3. Encrypt sensitive credential fields using AES-GCM.
4. Provide a configurable password generator.
5. Detect weak, reused, stale, and known-breached passwords using an offline SHA1 breach list.
6. Generate reports that are safe to share during academic review.
7. Provide proof screens and verification tools that demonstrate security controls during the live demo.

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

**GUI note:** The original project idea suggested PyQt5. CyberVault X uses Tkinter as a lightweight built-in desktop GUI alternative, which reduces setup complexity and keeps the project portable while preserving the same functional objectives.

---

## 5. System Architecture

CyberVault X is organized into clear layers:

1. **UI Layer:** Desktop screens, dialogs, workflow controls, and presentation mode.
2. **Manager Layer:** Main orchestration for vault actions, authentication, settings, and service coordination.
3. **Service Layer:** Backup, reporting, AI Guardian, proof checks, product intelligence, and analysis helpers.
4. **Crypto Layer:** AES-GCM encryption, backup encryption, master password verification, and passphrase policies.
5. **Database Layer:** SQLite schema, migrations, metadata, credential rows, password history, and audit logs.
6. **Testing Layer:** Regression tests for encryption, reporting, backup, AI redaction, and product hardening.

---

## 6. Cryptographic Design

### 6.1 Master Password Protection

The master password is not stored directly. CyberVault X uses PBKDF2-SHA256 to derive cryptographic material from the master password and a random salt. The derived key is used to verify vault unlock attempts and encrypt sensitive data.

### 6.2 AES-GCM Field Encryption

Sensitive credential fields are encrypted before being written to SQLite. Each field is stored as a nonce/cipher pair. AES-GCM provides confidentiality and integrity, meaning tampered ciphertext should fail during decryption.

### 6.3 Additional Authenticated Data

Credential encryption uses context-specific Additional Authenticated Data (AAD), binding ciphertext to the credential id and field name. This reduces ciphertext-swapping attacks where an attacker tries to move encrypted values between fields or records.

### 6.4 Encrypted Backups

Backups are encrypted using a dedicated backup envelope format. Backup import supports preview and rollback, so a failed restore does not corrupt the active vault.

---

## 7. Main Features

### 7.1 Encrypted Vault

Users can add, edit, delete, restore, and search credentials. Sensitive fields remain encrypted at rest.

### 7.2 Password Generator

The generator supports configurable length, character classes, presets, and entropy feedback.

### 7.3 Security Center

The Security Center identifies weak, reused, breached, stale, and metadata-incomplete credentials. It converts raw findings into readable risk levels.

### 7.4 AI Guardian

AI Guardian is a deterministic local security advisor. It does not call a cloud model. It transforms local security findings into an executive summary, prioritized action plan, attacker view, remediation steps, and expected score improvement.

### 7.5 Security Proof Center

The Security Proof Center demonstrates local proof checks including encrypted schema validation, strict AAD status, audit-chain integrity, report package verification, backup preview, and privacy-safe logging.

### 7.6 Tamper-Evident Audit Log

Activity events are linked using a hash chain. If an old event is modified, deleted, or reordered, the audit-chain verification detects the problem.

### 7.7 Privacy-Safe Reports

The reporting service exports executive and technical evidence without exposing raw passwords. Report packages include a manifest with SHA-256 hashes and a local HMAC-based manifest signature.

---

## 8. Database Design

The SQLite database includes:

- `app_meta` for version, settings, master verifier metadata, and encrypted metadata pointers.
- `credentials` for encrypted credential fields, timestamps, deletion state, and usage counters.
- `credential_history` for encrypted password history.
- `activity_log` for auditable events with previous-hash and event-hash columns.
- `schema_migrations` for migration tracking.

The design avoids plaintext password columns and supports future migration.

---

## 9. Testing and Validation

The project includes automated tests covering:

- AES-GCM encryption/decryption behavior.
- AAD-bound ciphertext swap prevention.
- Backup encryption, wrong-passphrase handling, and rollback.
- Report package manifest hashing and tamper detection.
- AI Guardian redaction rules.
- Security scoring and posture consistency.
- Audit log retention and hash-chain behavior.

Recommended commands:

```bash
python -m pytest -q tests
python tools/release_preflight.py
```

---

## 10. Live Demo Scenario

1. Launch CyberVault X.
2. Create a vault with a strong master password.
3. load the Assessment Dataset.
4. Open Dashboard and explain the health score.
5. Open Security Center and identify weak/reused/breached entries.
6. Open AI Guardian and generate a smart security plan.
7. Generate a replacement password.
8. Mark a remediation action as complete.
9. Open Security Proof Center and run proof checks.
10. Export and verify a report package.
11. Export an encrypted backup and preview restore impact.
12. Demonstrate panic lock.

---

## 11. Security Limitations

CyberVault X is a strong academic prototype, but it is not a certified commercial password manager. Important limitations:

- The included breach dataset is a small offline demo subset, not a full Have I Been Pwned mirror.
- Python cannot guarantee full secure memory zeroization for strings already loaded into runtime memory.
- HMAC-based report signing proves integrity using a local vault secret, but it is not the same as independent public-key notarization.
- Screenshots and final EXE validation must be captured on the Windows delivery machine.

---

## 12. Future Improvements

1. Optional Argon2id migration path while keeping PBKDF2 compatibility.
2. Optional custom offline breach-list import wizard.
3. Ed25519 public/private signature mode for independently verifiable report packages.
4. Better secure-memory handling where possible.
5. Component-level UI refactor for long-term maintainability.
6. Full screenshot automation after packaging on Windows.
7. Optional PyQt5 interface variant if the course instructor requires PyQt specifically.

---

## 13. Conclusion

CyberVault X satisfies the core requirements of the secure password manager project and extends them with professional security workflows. The project demonstrates applied cryptography, local privacy protection, secure software design, test coverage, report generation, and live-demo readiness.
