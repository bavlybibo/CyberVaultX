# CyberVaultX AI/UI V8 Patch Notes

## UI upgrades
- Reworked the AI page into a clearer Decision Theater with compact hero actions.
- Added four new intelligence cards: Guided Workflow, Signal Graph, Honest Limits, and Next Checkpoint.
- Reduced action-button clipping risk by changing the AI hero actions from a long horizontal row into a compact grid.
- Extended the action-plan panel with workflow lanes, signal graph summary, and honest capability/limitation notes.

## AI / Local Coach upgrades
- Upgraded the plan mode to Local Security Coach v8.
- Added a deterministic signal relationship graph built from redacted local telemetry.
- Added guided remediation workflow lanes: triage, containment, hardening, evidence.
- Added honest-limits output so the app clearly states what it can and cannot verify.
- Kept all raw secrets, full usernames, notes, paths, master keys, and backup data out of the plan and optional LLM payload.

## Verification
- `python -m pytest -q` => 109 passed, 1 skipped, 4 subtests passed.
- `python tools/release_preflight.py` => 77 passed, 0 failed.
