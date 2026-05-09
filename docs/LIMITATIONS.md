# CyberVault X - Security Limitations

CyberVault X is a commercial-style academic prototype. These limitations are documented intentionally because honest boundaries make the project more credible.

## Runtime memory

Python strings cannot be securely zeroized once loaded into runtime memory. CyberVault X reduces exposure through auto-lock behavior, clipboard timeout, redacted reports, and local-only processing, but it cannot provide the same memory-hard guarantees as a native audited password manager.

## Key derivation

PBKDF2-SHA256 is used for course/demo compatibility and broad Python support. Argon2id is stronger future work because it is memory-hard and more resistant to GPU cracking.

## Report integrity

Report packages include SHA-256 file hashes, a local HMAC-based manifest integrity signature, and a public Ed25519 manifest signature. The HMAC remains vault-local, while the Ed25519 signature can be verified externally with `verify_report_package.py` from the exported package data.

## Audit hash-chain

The local audit hash-chain integrity check can detect accidental edits or unsophisticated tampering. It is not tamper-proof against a privileged local attacker who can modify the database and recompute the chain.

## Breach subset

The bundled `pwned_sha1.txt` file is an offline demo breach-subset, not a complete Have I Been Pwned mirror or live breach-intelligence feed.

## UI toolkit

Tkinter is portable and easy to run in academic environments, but it requires careful spacing, typography, and layout discipline to look premium. A PyQt/PySide UI could be a future upgrade once the service layer is stable.


## Passphrase scoring

The passphrase model is conservative. It penalizes famous public examples such as `correct horse battery staple`, and it gives generated-style multi-word passphrases a fairer score, but it cannot prove that words were selected randomly. Treat the passphrase entropy estimate as a heuristic, not a mathematical guarantee.

## Demo isolation

The isolated demo vault creates a separate local database with synthetic data and a visible DEMO VAULT banner. The older Create Assessment Workspace action remains for backward compatibility and still asks for explicit confirmation before inserting synthetic data into the current vault.
