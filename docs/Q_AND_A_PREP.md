# Q&A Prep

**Does CyberVault X store the master password?**  
No. It stores a salted verifier and uses a derived key only while unlocked.

**Does the AI coach send passwords online?**  
No. It is deterministic local logic and uses redacted vault metadata.

**Are reports safe to share?**  
Use privacy-safe reports. They redact sensitive identifiers and never include plaintext passwords.

**Is breach detection complete?**  
No. It uses a bundled offline SHA1 subset. It can identify local matches but cannot prove full breach absence.

**Why not PDF by default?**  
HTML/JSON/text are reliable in the base app. PDF should be enabled only when optional tooling is verified.
