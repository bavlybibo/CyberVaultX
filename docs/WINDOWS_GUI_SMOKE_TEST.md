# Windows Full GUI Smoke Test

Run this on the final delivery PC after building the EXE.

## Command checks

```bat
python -m compileall -q app tests main.py verify_report_package.py
python -m pytest -q
python -m unittest discover -s tests -v
build_release.bat
dist\CyberVaultX\CyberVaultX.exe
```

## Manual feature checks

| Area | Expected result |
|---|---|
| Vault creation | New encrypted vault is created and unlocks successfully |
| Lock / panic lock | Secret data disappears from UI state |
| Add/Edit/Delete/Restore | Credential lifecycle works without crashes |
| Reveal/Copy | Requires re-auth; clipboard clears only CyberVault-owned value |
| Assessment workspace | Curated local assessment workspace loads idempotently |
| AI-style Local Security Coach | Explains weak/reused/breached/stale/missing metadata risks |
| Remediation workflow | Progress log updates and safe tag actions work |
| Backup preview | Shows add/skip/diff summary before modifying vault |
| Backup import | Merge/Replace works transactionally |
| Report package export | Creates report, audit log, AI summary, manifest |
| Package verifier | Valid package passes; tampered package fails |
| Audit head export | JSON head hash exports and can be compared later |
| Emergency kit | Safe TXT guide exports with no secrets |

## Screenshot checklist

Capture real Windows screenshots for:

- Login / Unlock
- Dashboard
- Vault
- AI-style Local Security Coach
- Security Proof Center v3
- Backup Restore Preview
- Report Package Verifier
- Exported Report
- Emergency Kit export confirmation
