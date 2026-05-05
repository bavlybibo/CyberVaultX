# CyberVaultX v5.6.7 — AI/UI Site Behavior Polish

## Focus
This pass fixes the UI problems visible in the screenshots and makes the AI feel more useful while the user enters a website and password.

## UI improvements
- Slimmer sidebar and topbar.
- Shorter metric cards so the workspace has more usable height.
- Removed forced horizontal Treeview scrollbars that created the visible white bars.
- Reduced table row height for cleaner density.
- Fixed duplicated credential badges.
- Reordered the Vault editor so Website and Category are captured before Password, giving the Live Coach context immediately.
- Expanded Live Password Coach into six compact chips:
  - Length
  - Character Mix
  - Context Leak
  - Site Fit
  - MFA / Passkey
  - Form Logic

## AI / password logic improvements
- Added Site Behavior Reasoner fields:
  - session revocation expectation
  - connected-app/token review
  - trusted-device review
  - recovery-channel review
  - passkey/MFA emphasis
  - symbol restrictions for legacy forms
- Added passphrase-aware scoring so long passphrases are not punished as harshly when the profile allows them.
- Expanded domain/category inference for infrastructure, banking, identity, developer, social, education, shopping, and gaming/media services.
- Generator analysis now explains likely website behavior, not only entropy and basic strength.

## Validation
- Full Python test discovery completed.
- Result: 68 tests OK, 1 skipped.
