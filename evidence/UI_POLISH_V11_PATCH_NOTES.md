# CyberVaultX V11 UI Polish Patch Notes

Scope: UI/UX stability and presentation-readiness only. No vault crypto, dataset, or report-data behavior was weakened.

## Fixed / improved

- Added responsive label wrapping across the Tkinter UI so long subtitles, tips, evidence text, and report explanations shrink with their card instead of clipping on laptop/projector widths.
- Reworked the sidebar into a scroll-safe navigation rail. Footer/status and Panic Lock remain reachable while the nav list scrolls independently on shorter screens.
- Rebuilt the topbar layout with a responsive action row. On narrower windows, actions move below the title instead of pushing text off-screen.
- Improved authentication dialog responsiveness. The right trust panel hides automatically on narrow dialog widths so the form stays readable.
- Added dark horizontal table scrollbars for wide evidence/AI/audit tables. Wide columns no longer rely on clipping.
- Tuned default window sizing from an oversized desktop-first layout to a more presentation-friendly 1500x900 with a safer 1160x720 minimum.
- Reduced fixed right-rail widths in the dashboard and vault workspace to give tables and main panels more breathing room.
- Kept screenshot placeholders untouched as requested; replace them with real Windows screenshots after running the EXE.

## Verification

- pytest: 117 passed, 1 skipped, 4 subtests passed.
- release preflight: 77 passed, 0 failed.
