from __future__ import annotations

import os
import re
from pathlib import Path

_SAFE_NAME_RE = re.compile(r'[^A-Za-z0-9_.-]+')


def safe_display_path(path: str | Path) -> str:
    """Return only a non-sensitive filename for audit logs and UI status text."""
    name = Path(path).name or 'file'
    return _SAFE_NAME_RE.sub('_', name)


def atomic_write_text(dest: str | Path, content: str, *, encoding: str = 'utf-8') -> Path:
    """Write text using a same-directory temporary file then atomic replace."""
    target = Path(dest)
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp = target.with_name(f'.{target.name}.tmp')
    tmp.write_text(content, encoding=encoding)
    try:
        os.chmod(tmp, 0o600)
    except Exception:
        pass
    tmp.replace(target)
    try:
        os.chmod(target, 0o600)
    except Exception:
        pass
    return target



def atomic_write_bytes(dest: str | Path, content: bytes) -> Path:
    """Write bytes using a same-directory temporary file then atomic replace."""
    target = Path(dest)
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp = target.with_name(f'.{target.name}.tmp')
    tmp.write_bytes(content)
    try:
        os.chmod(tmp, 0o600)
    except Exception:
        pass
    tmp.replace(target)
    try:
        os.chmod(target, 0o600)
    except Exception:
        pass
    return target
