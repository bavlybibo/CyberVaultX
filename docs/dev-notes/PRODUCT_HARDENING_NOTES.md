# CyberVault X — Product Hardening Notes

This version focuses on turning the polished prototype into a safer desktop product.

## Added

- UI smoke test scaffold for page construction.
- Schema migration history table and v5 metadata defaults.
- Privacy levels across normal and privacy-safe reports.
- CSV import preview with mapped-row validation and duplicate detection.
- Duplicate detection for Quick Add and the full vault editor.
- Emergency safety snapshot listing and restore UI.
- Printable executive report CSS and SHA-256 report fingerprint.
- Exportable privacy-aware audit log.
- Interactive Local Security Coach Fix Impact Simulator.
- Windows PyInstaller packaging files (`build_release.bat`, `cybervaultx.spec`, `requirements-build.txt`).

## Packaging

On Windows, run:

```bat
build_release.bat
```

The script creates `.venv_build`, installs build dependencies, runs tests, and outputs:

```text
dist\CyberVaultX\CyberVaultX.exe
```

## Safety model

Destructive restore operations create a new encrypted safety snapshot before replacing current credentials.
Safety snapshots are local encrypted checkpoints tied to the active vault key and are not a replacement for user-controlled encrypted backups.


## v5.5.1 Hardening Pass

- Report package verification now enforces a strict allowlist: `executive_report.html`, `audit_log.html`, and `ai_guardian_summary.txt`.
- Manifest entries with absolute paths, `../` traversal, nested paths, unknown files, or duplicate file names are rejected before hashing.
- Audit retention compaction now rebases the remaining local chain and stores an `audit_last_retention_checkpoint` hash in app metadata.
- Safety snapshot restore now uses explicit transaction rollback on any restore failure.
- Reports now label the canonical report digest as `Payload SHA-256`; final exported file hashes live in the report package manifest.
- PyInstaller UPX compression is disabled to reduce security-product false positives during demos.
