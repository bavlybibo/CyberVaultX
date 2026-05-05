from __future__ import annotations

import atexit
import logging
import os
import sys
import traceback
from pathlib import Path


class SingleInstanceLock:
    def __init__(self, lock_path: str | Path) -> None:
        self.lock_path = Path(lock_path)
        self.fd: int | None = None

    def acquire(self) -> bool:
        self.lock_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            self.fd = os.open(self.lock_path, os.O_CREAT | os.O_EXCL | os.O_RDWR)
            os.write(self.fd, str(os.getpid()).encode('utf-8'))
            atexit.register(self.release)
            return True
        except FileExistsError:
            if self._lock_is_stale():
                try:
                    self.lock_path.unlink(missing_ok=True)
                except Exception:
                    return False
                return self.acquire()
            return False

    def _lock_is_stale(self) -> bool:
        try:
            raw_pid = self.lock_path.read_text(encoding='utf-8').strip()
            pid = int(raw_pid)
        except Exception:
            return True
        if pid <= 0 or pid == os.getpid():
            return True
        return not _pid_exists(pid)

    def release(self) -> None:
        try:
            if self.fd is not None:
                os.close(self.fd)
                self.fd = None
            self.lock_path.unlink(missing_ok=True)
        except Exception:
            pass


def _pid_exists(pid: int) -> bool:
    if os.name == 'nt':
        try:
            import ctypes
            from ctypes import wintypes

            PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
            kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
            OpenProcess = kernel32.OpenProcess
            OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
            OpenProcess.restype = wintypes.HANDLE
            CloseHandle = kernel32.CloseHandle
            CloseHandle.argtypes = [wintypes.HANDLE]
            handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
            if handle:
                CloseHandle(handle)
                return True
            return False
        except Exception:
            return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return True
    return True


def configure_runtime_logging(app_dir: str | Path) -> Path:
    app_dir = Path(app_dir)
    app_dir.mkdir(parents=True, exist_ok=True)
    log_path = app_dir / 'cybervault_runtime.log'
    logging.basicConfig(
        filename=log_path,
        level=logging.INFO,
        format='%(asctime)s %(levelname)s %(message)s',
    )

    def _handle_exception(exc_type, exc_value, exc_traceback):
        if issubclass(exc_type, KeyboardInterrupt):
            sys.__excepthook__(exc_type, exc_value, exc_traceback)
            return
        logging.critical('Unhandled exception:\n%s', ''.join(traceback.format_exception(exc_type, exc_value, exc_traceback)))
        sys.__excepthook__(exc_type, exc_value, exc_traceback)

    sys.excepthook = _handle_exception
    return log_path
