from __future__ import annotations

"""Small GUI smoke validator for release checks.

It exits with:
- 0: GUI initialized and core pages were found.
- 2: GUI could not start because no display server is available.
- 1: GUI/import failure.
"""

import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def main() -> int:
    if sys.platform.startswith('linux') and not os.environ.get('DISPLAY'):
        print('SKIP: no DISPLAY server is available for GUI smoke validation.')
        return 2
    try:
        from app.ui import PasswordManagerApp

        tmp = tempfile.TemporaryDirectory()
        db_path = Path(tmp.name) / 'smoke.db'
        app = PasswordManagerApp(db_path)
        if not app.manager.has_master_password():
            app.manager.setup_master_password('Smoke', 'Strong!VaultPass123')
        app.update_idletasks()
        required_attrs = ['dashboard_frame', 'vault_tree', 'security_tree', 'report_level_var']
        missing = [name for name in required_attrs if not hasattr(app, name)]
        app.destroy()
        tmp.cleanup()
        if missing:
            print('FAIL: missing UI widgets: ' + ', '.join(missing))
            return 1
        print('PASS: GUI initialized and core pages/widgets are present.')
        return 0
    except Exception as exc:  # pragma: no cover - release utility
        message = str(exc)
        if 'display' in message.lower() or 'no display' in message.lower():
            print(f'SKIP: GUI smoke validation requires a reachable display server: {message}')
            return 2
        print(f'FAIL: GUI smoke validation failed: {exc}')
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
