# CyberVault X Windows Release Checklist

Run these on the Windows delivery machine:

```bat
cd cybervault_ai_work
python -m unittest discover -s tests -v
build_release.bat
dist\CyberVaultX\CyberVaultX.exe
```

Manual smoke test:

- Create a new vault.
- Unlock and lock the vault.
- Create the built-in assessment workspace.
- Add a credential via Quick Add.
- Save/edit a credential.
- Reveal password after re-authentication.
- Copy password after re-authentication.
- Update a password and verify history timeline.
- Reveal/copy an old history password after re-authentication.
- Generate AI Guardian plan.
- Mark a priority item as fixed.
- Export privacy-safe report package and inspect `manifest.json`.
- Import backup with Merge, Replace, and Cancel.
- Import CSV preview and cancel safely.
- Open Activity filters by severity/date/search.
- Panic lock.
