from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from .constants import (
    DEFAULT_AUTO_LOCK_MINUTES,
    DEFAULT_CLIPBOARD_CLEAR_SECONDS,
    DEFAULT_THEME_ACCENT,
    VAULT_DB_FILENAME,
)


@dataclass(frozen=True, slots=True)
class AppConfig:
    app_dir: Path
    vault_db: Path
    theme_accent: str = DEFAULT_THEME_ACCENT
    auto_lock_minutes: int = DEFAULT_AUTO_LOCK_MINUTES
    clipboard_clear_seconds: int = DEFAULT_CLIPBOARD_CLEAR_SECONDS
    demo_mode: bool = False


def resolve_default_app_dir() -> Path:
    """Return a writable local app-data directory without hardcoded user paths."""
    candidates: list[Path] = []
    userprofile = os.environ.get("USERPROFILE")
    if userprofile:
        candidates.append(Path(userprofile) / ".cybervault_x")
    try:
        candidates.append(Path.home() / ".cybervault_x")
    except Exception:
        pass
    candidates.append(Path.cwd() / "app_data")
    for candidate in candidates:
        try:
            candidate.mkdir(parents=True, exist_ok=True)
            probe = candidate / ".write_test"
            probe.write_text("ok", encoding="utf-8")
            probe.unlink(missing_ok=True)
            return candidate
        except OSError:
            continue
    fallback = Path.cwd() / "app_data"
    fallback.mkdir(parents=True, exist_ok=True)
    return fallback


def load_config(app_dir: str | Path | None = None) -> AppConfig:
    base = Path(app_dir) if app_dir is not None else resolve_default_app_dir()
    base.mkdir(parents=True, exist_ok=True)
    return AppConfig(app_dir=base, vault_db=base / VAULT_DB_FILENAME)
