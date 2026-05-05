from __future__ import annotations

from pathlib import Path

from ..core.constants import SUPPORTED_REPORT_FORMATS


def supported_report_formats() -> tuple[str, ...]:
    return SUPPORTED_REPORT_FORMATS


def normalize_report_path(path: str | Path, default_suffix: str = ".html") -> Path:
    dest = Path(path)
    suffix = dest.suffix.lower()
    if suffix not in SUPPORTED_REPORT_FORMATS:
        dest = dest.with_suffix(default_suffix)
    return dest
