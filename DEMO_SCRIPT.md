# CyberVault X Demo Script

## 1. Launch and framing
- Open `run_windows.bat`.
- Explain that CyberVault X is a local-first encrypted password vault and security-posture assistant.
- State the boundary clearly: this is an academic/product prototype, not a certified commercial password manager.

## 2. Create or unlock vault
- Create a vault with a strong master password.
- Mention PBKDF2-SHA256 key derivation and AES-GCM field encryption.
- Do not use real personal credentials during the demo.

## 3. Dashboard
- Show health score, risk distribution, and next recommended action.
- Explain that cards summarize local telemetry without sending secrets anywhere.

## 4. Add credential and live coach
- Add a sample credential.
- Type a weak password first to show deterministic evidence-based warnings.
- Generate a strong replacement and show the site-fit guidance.

## 5. Security Center
- Load the assessment workspace or use demo records.
- Show weak, reused, old, and breached/offline-hash findings.
- Open one finding and explain evidence, impact, and remediation.

## 6. AI-style Local Security Coach
- Generate the local security plan.
- Emphasize that the assistant is explainable and redacted: no raw password, note, username, backup blob, or absolute path is included.

## 7. Reports and proof
- Export a privacy-safe report.
- Show report package manifest/hash verification.
- Explain the local audit log and tamper-evident chain.

## 8. System Health
- Open System Health.
- Show dependency, local dataset, required files, and writable app-data checks.
- Explain PASS/WARN/FAIL meanings before submission.

## 9. Close
- Lock the vault.
- Summarize limitations and future work: passkeys, larger breach datasets, platform secure storage integration, and independent security review.
