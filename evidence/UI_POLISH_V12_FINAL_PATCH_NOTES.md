# CyberVaultX v5.7.2 — V12 Final UI Polish Patch Notes

Scope: final code-only UI stabilization after reviewing fresh screenshots. Screenshots/Windows EXE captures remain manual submission evidence.

## AI Coach / Decision Theater fixes

- Compact hero spacing and action buttons so the page does not waste vertical space on projectors.
- Reduced AI posture, severity, snapshot, and action-plan panel heights while keeping the content readable.
- Fixed AI canvas drawing coordinates so the severity legend and posture gauge do not clip after compacting the page.
- Increased/corrected card heights for AI intelligence and risk cards where text was being cut off.
- Reduced oversized risk-count typography so each risk card can show the story line reliably.
- Added integrated dark scrollbars to dense AI text panels:
  - Smart Action Plan + Workflow
  - Evidence-bound Explanation
  - Decision Matrix
  - Quality Gates
  - Optional LLM Blueprint
- Reduced AI priority queue height and added better scrollbar behavior so the lower explanation panel appears sooner during presentation.

## Table and scrollbar fixes

- Reworked shared table scrollbar attachment.
- Horizontal table scrollbars are now auto-hidden when the columns fit the available width.
- This removes the bright/white horizontal bar visible in wide empty tables on Windows.
- Vertical table scrollbars are also auto-hidden when the table has no overflow.
- Dense tables still get horizontal scrollbars when needed, especially AI/Proof evidence views.

## General polish

- Security-side text panels now share the same integrated dark scrollbar treatment as AI panels.
- Kept the core vault, crypto, reporting, and tests untouched except for UI rendering behavior.

## Validation

- pytest: 117 passed, 1 skipped, 4 subtests passed.
- release_preflight: 77 passed, 0 failed.
