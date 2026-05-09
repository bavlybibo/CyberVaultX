# Public Report Signature Upgrade

Implemented after code review to remove the weakest part of the previous report-package proof model.

## Changed
- Added Ed25519 public manifest signatures to exported report packages.
- Kept the old vault-local HMAC signature as a second local integrity proof.
- Updated `verify_report_package.py` so an external reviewer can verify package integrity without the vault-local secret.
- Added regression tests for valid packages, manifest tampering, and CLI verification.
- Regenerated sample report-package outputs with the new signature fields.

## Important limitation
The public signature proves that the exported package was not modified after signing. It does not prove legal identity unless the public key is separately trusted or certified.
