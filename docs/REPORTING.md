# Reporting

CyberVault X supports three report formats:

- **HTML**: executive/demo-ready report with cards and printable CSS.
- **JSON**: machine-readable report payload for tooling and validation.
- **Text**: lightweight local summary.

## Report Contents

Reports include app/vault summary, generated timestamp, encryption status, dashboard metrics, AI Guardian summary, top priority items, findings, recommendations, limitations, and payload hashes.

## Redaction Rules

Reports must not include plaintext passwords, master passwords, derived keys, backup passphrases, tokens, secret keys, or sensitive raw notes. Privacy-safe modes redact identifying fields.

## PDF

PDF should only be advertised or used when optional report tooling and dependencies are installed and verified. HTML remains the default reliable export.
