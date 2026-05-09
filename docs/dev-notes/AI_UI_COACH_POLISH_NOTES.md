# CyberVaultX v5.6.6 — Live Coach AI + UI Polish Notes

## Focus
This patch strengthens the feeling of the product while the user is actually entering a password. The goal is to make CyberVaultX feel like a smart assistant, not a static password strength meter.

## Added
- `build_password_coach_state()` in `app/site_policy.py`.
- Live readiness states: Waiting, Do not save, Unsafe fit, Needs tune-up, Good almost ready, Ready to save.
- Four compact live UI chips: Length, Character Mix, Context Leak, and Site Fit.
- Per-site likely behavior summary: minimum length, recommended target length, character expectations, review window, and MFA/passkey recommendation.
- Local Security Coach `coach_overview` section with readiness summary, first user action, site profile mix, and UX prompts.
- AI Summary export now includes the AI Coach UX Snapshot.

## Improved
- Local Security Coach mode upgraded to: `Local-first Explainable Local Security Coach v5 · Site Policy Reasoner + Live Coach UX`.
- Live coach now uses one unified coaching state instead of only raw `evaluate_password_fit()` output.
- The password editor is less text-heavy and gives clearer short actions while typing.
- Site Requirement Checklist now includes likely website behavior.

## Privacy
- No raw passwords are added to AI exports.
- Live coach computation is local-only.
- Optional LLM payload still contains redacted telemetry only.

## Validation
- Full test discovery completed: 65 tests OK, 1 skipped.
