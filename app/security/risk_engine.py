from __future__ import annotations

from collections import Counter
from typing import Any, Iterable

from ..analyzer import analyze_password, password_is_old


def summarize_vault_risk(credentials: Iterable[Any]) -> dict[str, Any]:
    items = list(credentials)
    password_counts = Counter(getattr(item, "password", "") for item in items if getattr(item, "password", ""))
    weak = 0
    breached = 0
    old = 0
    for item in items:
        analysis = analyze_password(getattr(item, "password", ""), context=f"{getattr(item, 'title', '')} {getattr(item, 'website', '')}")
        if analysis.score < 70:
            weak += 1
        if analysis.breached:
            breached += 1
        if password_is_old(getattr(item, "updated_at", "")):
            old += 1
    reused = sum(1 for count in password_counts.values() if count > 1)
    return {
        "total": len(items),
        "weak_passwords": weak,
        "breach_alerts": breached,
        "old_passwords": old,
        "reused_password_groups": reused,
        "risk_level": "Critical" if breached or weak >= 3 else "High" if weak or reused else "Low",
    }
