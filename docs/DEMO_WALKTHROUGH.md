# CyberVault X Walkthrough

This walkthrough is designed for a live university review where the goal is to prove working security logic, not just show static screens.

## 1. Open the app

Run:

```bash
python main.py
```

Create or unlock a vault using a strong master password.

## 2. Create an assessment workspace

Use **Create Assessment Workspace** to add clearly synthetic local records. Existing credentials are not overwritten, and repeated workspace creation skips duplicates.

Explain that the workspace contains safe local records representing common password-security findings: weak passwords, reuse, stale credentials, strong credentials, missing metadata, and local breach-subset matches.

## 3. Review Dashboard Command Center

Explain the first-screen decisions:

- overall security score
- vault health status
- highest-priority findings
- next actions
- report readiness
- backup and audit status

## 4. Review Security Center

Open Security Center and show how findings are grouped by severity. For a high-risk card, explain:

- affected credential reference
- why it matters
- confidence level
- recommended fix
- open/reviewed/fixed workflow through audit events

## 5. Review AI-style Local Security Coach

Explain clearly:

- analysis is rule-based and local
- no external LLM or cloud AI is used
- raw passwords and notes are excluded from coach payloads
- every recommendation includes evidence and next action

## 6. Use the Password Fix Simulator

Select the top issues and show the projected score change. Explain that this is a deterministic estimate for prioritization, not an exact prediction.

## 7. Check report readiness

Open Reports and run readiness check before exporting. Discuss blockers, warnings, privacy status, and verification status.

## 8. Export and verify a report package

Export a privacy-safe package, then verify it. Explain generated artifacts:

- HTML executive report
- audit log
- local coach summary
- manifest
- verification output

## 9. Backup and restore preview

Export an encrypted backup with a separate passphrase. Use restore preview to show impact without modifying the current vault.

## 10. Close with limitations

Mention the honest limitations: Python memory zeroization, PBKDF2 vs Argon2id, local HMAC signature limitations, and demo-sized offline breach subset.
