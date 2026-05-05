from __future__ import annotations

import logging
import os
from pathlib import Path
import tkinter as tk
from tkinter import messagebox

from app.runtime import SingleInstanceLock, configure_runtime_logging
from app.ui import run_app


def resolve_app_dir() -> Path:
    candidates: list[Path] = []
    userprofile = os.environ.get('USERPROFILE')
    if userprofile:
        candidates.append(Path(userprofile) / '.cybervault_x')
    try:
        candidates.append(Path.home() / '.cybervault_x')
    except Exception:
        pass
    candidates.append(Path.cwd() / 'app_data')

    for candidate in candidates:
        try:
            candidate.mkdir(parents=True, exist_ok=True)
            test = candidate / '.write_test'
            test.write_text('ok', encoding='utf-8')
            test.unlink(missing_ok=True)
            return candidate
        except Exception:
            continue

    fallback = Path.cwd() / 'app_data'
    fallback.mkdir(parents=True, exist_ok=True)
    return fallback


if __name__ == '__main__':
    app_dir = resolve_app_dir()
    configure_runtime_logging(app_dir)
    lock = SingleInstanceLock(app_dir / 'cybervault.lock')
    if not lock.acquire():
        try:
            root = tk.Tk()
            root.withdraw()
            messagebox.showwarning('CyberVault X', 'Another CyberVault X instance appears to be running. Close it before opening a second window.')
            root.destroy()
        except Exception:
            print('Another CyberVault X instance appears to be running.')
        raise SystemExit(1)
    logging.info('Starting CyberVault X.')
    try:
        run_app(app_dir / 'vault.db')
    except tk.TclError as exc:
        lock.release()
        logging.error('CyberVault X GUI startup failed: %s', exc)
        print('CyberVault X could not open the desktop UI. Run it on Windows or on a machine with a reachable display server.')
        raise SystemExit(2) from exc
