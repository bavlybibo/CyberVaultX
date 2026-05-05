from __future__ import annotations

import shutil
from pathlib import Path

JUNK_DIRS = {"__pycache__", ".pytest_cache", "build", "dist"}
JUNK_SUFFIXES = {".pyc", ".pyo", ".log"}
JUNK_GLOBS = ("VALIDATION_LOG_*.txt",)


def clean_project(root: str | Path = ".") -> dict[str, int]:
    base = Path(root)
    removed_files = 0
    removed_dirs = 0
    for pattern in JUNK_GLOBS:
        for path in base.glob(pattern):
            if path.is_file():
                try:
                    path.unlink()
                    removed_files += 1
                except OSError:
                    pass
    for path in sorted(base.rglob("*"), key=lambda p: len(p.parts), reverse=True):
        if path.is_dir() and path.name in JUNK_DIRS:
            shutil.rmtree(path, ignore_errors=True)
            removed_dirs += 1
        elif path.is_file() and path.suffix in JUNK_SUFFIXES:
            try:
                path.unlink()
                removed_files += 1
            except OSError:
                pass
    return {"removed_files": removed_files, "removed_dirs": removed_dirs}


if __name__ == "__main__":
    print(clean_project(Path.cwd()))
