# Emergency Kit

CyberVault X can export a safe emergency kit using `export_emergency_kit(path)`.

The emergency kit includes:

- where the local vault database is stored
- how to restore from encrypted backups
- what to do if the master password is forgotten
- monthly owner checklist
- security limitations

It intentionally excludes:

- master password
- backup passphrase
- raw passwords
- secret notes
- clipboard values
