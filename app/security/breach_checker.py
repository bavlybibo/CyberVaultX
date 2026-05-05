from __future__ import annotations

from typing import Any

from ..breach_db import is_pwned_password


def breach_status(password: str) -> dict[str, Any]:
    """Check the local offline breach subset without exposing the password."""
    hit = is_pwned_password(password)
    return {
        "checked": True,
        "source": "local-offline-sha1-subset",
        "breached": bool(hit),
        "evidence": "SHA-1 hash matched local offline dataset." if hit else "No match in bundled offline dataset.",
    }
