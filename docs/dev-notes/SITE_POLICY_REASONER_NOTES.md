# CyberVault X v5.6.5 — Site Policy Reasoner & Live Password Coach

This pass focuses on making CyberVault understand **what kind of account the user is saving** and whether the password actually fits that account.

## Added

- `app/site_policy.py`
  - Local account-profile inference from website, title, username, and category.
  - Profiles include Email / Identity Provider, Banking / Crypto, Infrastructure / Admin Console, Work / Developer Platform, Social, Education, Shopping, Entertainment, and General.
  - Each profile has a target length, minimum length, character expectations, rotation window, MFA/passkey hint, and security rationale.

- Live Password Coach in the Vault editor
  - Updates while the user types the password, website, title, or category.
  - Shows site-fit score, fit label, target length, MFA hint, and next recommended fix.
  - Adds a `Tune` button beside the password field to configure the Generator for the current site profile.

- Site Requirement Checklist in the Intelligence tab
  - Shows what the inferred site profile wants.
  - Separates hard blockers, warnings, and passed checks.
  - Explains why a Gmail/Google/email account is treated differently from a game account, banking account, or server admin login.

- Local Security Coach v4 Site Policy Reasoner
  - Adds `site_policy_mismatch` as a signal in AI ranking.
  - Priority items now carry `site_profile`, `site_fit_score`, `site_fit_label`, and local inferred requirements.
  - AI exports now include site-fit reasoning.

- Generator enhancements
  - New use cases: Social, Education, Servers, Crypto.
  - Generator output now includes site-fit score and inferred profile logic.

## Privacy note

The reasoner is deterministic and local. It never sends passwords, domains, usernames, notes, or backups to an external service.

## Validation performed

```bash
/usr/bin/python3 -m compileall -q app tests
PYTHONPATH=. /usr/bin/python3 -m unittest tests.test_site_policy_reasoner_v565 tests.test_ai_guardian_v564
```

Selected tests passed. Full test discovery was started but timed out in this container after partial progress, so run the full Windows test pass before final submission:

```bat
python -m unittest discover -s tests -v
```
