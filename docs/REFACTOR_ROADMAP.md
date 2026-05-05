# Refactor Roadmap

This release keeps the application stable and avoids risky rewrites before delivery. v5.5 starts the split by moving the Security Proof Center page into `app/ui_pages_proof.py`. The next maintainability pass should continue splitting large files gradually using the structure below.

## Phase 1 — UI split

Move page-specific code from `app/ui_pages.py` into:

```text
app/ui/pages/dashboard_page.py
app/ui/pages/vault_page.py
app/ui/pages/security_page.py
app/ui/pages/ai_guardian_page.py
app/ui/pages/proof_center_page.py
app/ui/pages/activity_page.py
app/ui/pages/settings_page.py
```

Keep `app/ui.py` as the shell only: startup, window state, and top-level orchestration.

## Phase 2 — controller split

Move workflows from `app/ui_controllers.py` into:

```text
app/ui/controllers/vault_controller.py
app/ui/controllers/backup_controller.py
app/ui/controllers/report_controller.py
app/ui/controllers/ai_guardian_controller.py
```

## Phase 3 — service split

Move backup/import/export logic from `app/services/backup.py` into:

```text
app/services/backup/exporter.py
app/services/backup/importer.py
app/services/backup/csv_importer.py
app/services/backup/snapshot_restore.py
```

## Guardrails

- Do one file family per pull request.
- Keep regression tests green after every split.
- Do not change crypto behavior during UI refactors.
- Preserve report package format and manifest hashing.
- Add one smoke test per moved workflow.
