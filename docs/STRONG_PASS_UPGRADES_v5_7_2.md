# CyberVault X v5.7.2 Strong Pass Upgrade Notes

This pass completes the remaining P2/Strong Pass items without weakening the existing P1 security fixes.

## Completed

- Added isolated demo vault creation in a separate SQLite database.
- Added a visible `DEMO VAULT — synthetic data only` banner and UI entry/exit flow.
- Added tests proving the real vault is not mutated when the isolated demo vault is opened.
- Added conservative passphrase modeling: famous phrases are downgraded, generated-style multi-word passphrases are not unfairly marked Very Weak, and uncertainty is explained.
- Clarified Proof Center wording as local integrity proof, not independent public-key attestation.
- Updated release evidence after the full suite and release preflight passed.

## Still honest limitations

- The password manager remains a commercial-style academic prototype, not an audited commercial password manager.
- Passphrase scoring is heuristic because the app cannot prove random word selection from text alone.
- Report package signatures now include local HMAC integrity proof plus a public Ed25519 manifest signature for external verification.
- GUI smoke checks are skipped on headless Linux without a display server.
