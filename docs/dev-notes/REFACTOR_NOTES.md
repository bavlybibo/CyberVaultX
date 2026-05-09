# CyberVault X Refactor Notes

This build keeps the original public entry points (`app.ui.run_app` and `app.manager.VaultManager`) while splitting the previous large modules into smaller, safer units.

## UI split

- `app/ui.py` now acts as a thin application shell.
- Page-building code moved to `app/ui_pages.py`.
- Dialog/auth/import/tour code moved to `app/ui_dialogs.py`.
- User actions, import/export, clipboard, lock, generator, and settings logic moved to `app/ui_controllers.py`.
- Refresh/table/selection logic moved to `app/ui_refresh.py`.
- Drawing/theme/site-badge helpers moved to `app/ui_visual.py`.
- Shared colors, page metadata, icons, and category constants moved to `app/ui_shared.py`.

## Manager split

- `app/manager.py` remains the stable facade for the rest of the app.
- Analysis/dashboard/security logic moved to `app/services/analysis.py`.
- Cached `VaultSnapshot` logic moved to `app/services/snapshot.py`.
- Local Security Coach context, plan generation, and previous snapshot persistence moved to `app/services/ai_guardian.py`.
- Report generation and privacy-safe report levels moved to `app/services/reporting.py`.
- Backup/import/CSV/assessment workspace data and encrypted safety snapshots moved to `app/services/backup.py`.

## Security and privacy updates

- Added in-memory `VaultSnapshot` cache to reduce repeated decrypt/recalculate cycles.
- Mutating vault operations invalidate the snapshot cache.
- Local Security Coach stores previous metrics in app metadata so “What Changed” can compare against the previous run.
- Added encrypted local safety snapshots before destructive operations.
- Added privacy-safe report levels: `minimal`, `standard`, and `analyst`.
- Strengthened encrypted backup import validation.
- Favicon lookup now asks for explicit confirmation and blocks online lookups for high-sensitivity categories.
- Schema version increased to 3 for AI snapshot and privacy-report metadata.

## Test notes

New regression tests were added for schema v3 defaults, privacy report levels, snapshot cache invalidation, and safety snapshot creation.
