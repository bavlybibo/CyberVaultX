from __future__ import annotations

from dataclasses import asdict
from typing import Any

from ..analyzer import analyze_password


def analyze_password_strength(password: str, *, context: str = "") -> dict[str, Any]:
    """Return deterministic strength analysis without logging or persisting the password."""
    result = analyze_password(password, context=context)
    payload = asdict(result)
    payload["safe_to_store"] = result.score >= 70 and not result.breached
    payload["recommended_action"] = (
        "Use this password only if it is unique for this account."
        if payload["safe_to_store"]
        else "Generate a longer unique password before saving."
    )
    return payload


def is_strong_password(password: str, *, context: str = "") -> bool:
    result = analyze_password(password, context=context)
    return result.score >= 80 and not result.breached
