# CyberVaultX Bonus Feature Pack

This pack upgrades CyberVaultX from a safe local password manager prototype into a stronger security-product submission. Every feature below is local, deterministic, privacy-aware, and covered by regression tests.

## Implemented premium features

1. **Security Proof Center**
   - Verifies encrypted credential schema, audit hash-chain integrity, backup format policy, privacy-safe logging, package manifest/signing, and KDF policy.

2. **Attack Simulation Lab**
   - Runs safe local defensive simulations:
     - plaintext DB secret scan
     - AES-GCM tampered backup rejection
     - adversarial analyzer check
     - privacy-safe report leak scan
     - audit hash-chain validation
   - Does not attack live services and does not expose secrets.

3. **Privacy Export Preview**
   - Shows what each export privacy level includes before export.
   - Uses a leak scan before marking the preview as PASS.
   - Never displays raw passwords, master password, backup passphrase, or private notes.

4. **Password Relationship Graph**
   - Detects exact password reuse, near-duplicate base patterns, and same-site duplicate records.
   - Uses `Credential #N` references only; no raw passwords, titles, usernames, or full websites are returned.

5. **Remediation Planner**
   - Produces a deterministic Today / This Week / Later plan.
   - Prioritizes critical/high-risk credentials, relationship clusters, backup status, and report-readiness evidence.

6. **Generator Plus**
   - Adds profile-aware generation for General, Social, Education, Work, Banking, Servers, Crypto, Recovery, and Developer accounts.
   - Supports random character passwords and memorable passphrases.
   - Generated values are not saved unless the user explicitly stores them.

7. **Emergency Kit**
   - Exports recovery instructions, proof evidence, attack lab output, manifest hashes, and optionally an encrypted vault backup.
   - Does not store master password or backup passphrase.

8. **Security Evidence Package**
   - Exports proof center, attack lab, privacy preview, relationship graph, remediation plan, timeline, backup status, clipboard status, and manifest hashes.
   - A final redaction pass is applied before writing evidence files.

9. **UI integration**
   - Proof tab includes buttons for:
     - Attack Lab
     - Evidence Package
     - Emergency Kit
     - Privacy Preview
     - Relationship Graph
     - Remediation Plan

## Security honesty

- Local Security Coach is deterministic and rule-based.
- No external LLM or cloud AI is used.
- Confidence is heuristic/policy confidence, not calibrated ML confidence.
- Offline breach checks use local SHA-1 hash lists only.
- The product does not protect against malware, keyloggers, screenshots, shoulder surfing, or memory scraping.

## Test evidence

Primary bonus tests:

```bash
python -m pytest -q tests/test_bonus_features.py
```

Expected result:

```text
7 passed
```

Full collected test count after this pack:

```bash
python -m pytest --collect-only -q
```

Expected result:

```text
100 tests collected
```
