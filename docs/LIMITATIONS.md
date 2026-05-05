# CyberVault X Limitations

CyberVault X is a strong product-grade educational release, but it should be presented honestly.

## Current limitations

1. The breach database is intentionally small and offline for offline speed and portability.
2. AI Guardian is deterministic and local-rule based; it is not a cloud LLM in this version.
3. Online favicon lookup is disabled by default and should stay optional because domain lookup can leak saved site names.
4. The project has privacy-safe audit logging, but SQLite metadata and runtime memory are still local-machine trust concerns.
5. PyInstaller/EXE validation must be performed on the final Windows delivery machine.
6. Screenshots in the README should be captured from the actual built app before final submission.

## Recommended future upgrades

- Argon2id or scrypt KDF migration path.
- Optional Have I Been Pwned k-anonymity check.
- Signed report package manifest.
- More granular UI module split under `app/ui/pages`, `app/ui/widgets`, and `app/ui/dialogs`.
- Automated GUI smoke tests on Windows CI.


## v5.5.1 Clarifications

- The bundled breach data file is a small offline breach-intelligence subset, not the full Have I Been Pwned corpus.
- The audit log hash chain is tamper-evident for retained local events, not tamper-proof against a privileged database writer.
- `Payload SHA-256` in reports hashes the canonical report payload. Final HTML/text artifact hashes are recorded in report package manifests.
- Windows EXE smoke testing must still be performed on a real Windows GUI environment before external release.
