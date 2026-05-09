# CyberVault X v5.6.4 — AI Precision & UI Cleanup Notes

This pass focuses on making the Local Security Coach feel sharper, cleaner, and more defensible.

## Added

- Explainable Local Security Coach v3.
- Per-item confidence percentage.
- Primary risk signal and urgency score.
- Exposure path and attack scenario for every priority item.
- Evidence tags and decision trace for report-ready justification.
- Decision Matrix panel inside the Local Security Coach page.
- Posture Heatmap for breach/reuse/weakness/age/metadata pressure.
- Quality Gates panel for redaction, actionability, payload hygiene, and evidence coverage.
- AI summary export now includes the new explainability data.
- Regression test file: `tests/test_ai_guardian_v564.py`.

## Privacy posture

The AI layer remains local-first. The optional LLM payload contains only redacted metrics, credential references, masked hints, decision rows, and heatmap data. It does not include raw passwords, master keys, notes, database paths, or backup blobs.

## Validation performed

- `python -m compileall -q app tests main.py`
- `python -m unittest tests/test_ai_guardian_v564.py -v`

Full discovery may take longer on machines with GUI/security tests; run it locally before final submission.
