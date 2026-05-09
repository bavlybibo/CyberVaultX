from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any, Iterable

from ..analyzer import analyze_password, normalize_site, password_is_old
from ..security_policy import composite_risk_level, is_high_value_category, normalize_category_name, normalize_issue_list


def _credential_ref(index: int, item: Any) -> str:
    identifier = getattr(item, "id", None)
    return f"credential #{identifier}" if identifier is not None else f"credential row {index}"


def summarize_vault_risk(credentials: Iterable[Any]) -> dict[str, Any]:
    """Return a privacy-safe vault risk model from decrypted in-memory credentials.

    The output deliberately avoids raw passwords, usernames, notes, and URLs. It
    counts reuse by impacted item as well as by password group, highlights
    compounding risk paths, and gives the UI/AI/reporting layers one consistent
    source of truth for core posture.
    """
    items = list(credentials)
    password_counts = Counter(getattr(item, "password", "") for item in items if getattr(item, "password", ""))
    password_group_ids: dict[str, list[str]] = defaultdict(list)
    site_counts = Counter(normalize_site(getattr(item, "website", "")) for item in items if normalize_site(getattr(item, "website", "")))

    weak = breached = old = high_value = 0
    reused_items = 0
    priority_items: list[dict[str, Any]] = []
    critical_paths: list[str] = []
    risk_drivers = Counter()
    score_total = 0

    for index, item in enumerate(items, start=1):
        password = getattr(item, "password", "")
        category = getattr(item, "category", "General")
        context = f"{getattr(item, 'title', '')} {getattr(item, 'website', '')}"
        analysis = analyze_password(password, context=context)
        score_total += int(analysis.score)
        reuse_count = password_counts.get(password, 0) if password else 0
        if reuse_count > 1:
            reused_items += 1
            password_group_ids[password].append(_credential_ref(index, item))
        is_old = password_is_old(getattr(item, "updated_at", ""))
        is_high_value = is_high_value_category(category)
        if is_high_value:
            high_value += 1
        if analysis.score < 70:
            weak += 1
            risk_drivers["weak_passwords"] += 1
        if analysis.breached:
            breached += 1
            risk_drivers["offline_breach_hits"] += 1
        if is_old:
            old += 1
            risk_drivers["old_passwords"] += 1
        if reuse_count > 1:
            risk_drivers["password_reuse"] += 1
        norm_site = normalize_site(getattr(item, "website", ""))
        if norm_site and site_counts.get(norm_site, 0) > 1:
            risk_drivers["duplicate_sites"] += 1

        issues = normalize_issue_list(analysis.warnings)
        if reuse_count > 1:
            issues.append(f"Reused password across {reuse_count} accounts.")
        if is_old:
            issues.append("Password is older than 90 days.")
        risk_level = composite_risk_level(
            analysis.score,
            breached=analysis.breached,
            common_password="Common password" in analysis.patterns or "Simple substitution" in analysis.patterns,
            reuse_count=max(1, reuse_count),
            old_password=is_old,
            category=category,
            issues=issues,
        )
        if risk_level in {"Critical", "High"}:
            priority_items.append({
                "credential_ref": _credential_ref(index, item),
                "risk_level": risk_level,
                "score": analysis.score,
                "category": normalize_category_name(category),
                "signals": sorted(set(analysis.patterns + [issue for issue in issues[:3]]))[:6],
                "first_action": analysis.remediation_advice,
            })
        if analysis.breached and reuse_count > 1:
            critical_paths.append(f"{_credential_ref(index, item)}: breach signal is also part of a reuse chain.")
        if is_high_value and (analysis.score < 70 or reuse_count > 1 or is_old):
            critical_paths.append(f"{_credential_ref(index, item)}: high-value category has weak, reused, or stale credential risk.")

    reused_groups = sum(1 for count in password_counts.values() if count > 1)
    avg_score = round(score_total / max(1, len(items))) if items else 0
    hygiene_penalty = breached * 16 + reused_items * 12 + weak * 10 + old * 5
    hygiene_score = max(0, min(100, avg_score - round(hygiene_penalty / max(1, len(items))))) if items else 0
    if breached or any("reuse chain" in path for path in critical_paths):
        risk_level = "Critical"
    elif weak >= 3 or reused_items >= 2 or any("high-value" in path for path in critical_paths):
        risk_level = "High"
    elif weak or reused_items or old:
        risk_level = "Moderate"
    else:
        risk_level = "Low"

    return {
        "total": len(items),
        "weak_passwords": weak,
        "breach_alerts": breached,
        "old_passwords": old,
        "high_value_accounts": high_value,
        "reused_password_groups": reused_groups,
        "reused_password_items": reused_items,
        "risk_level": risk_level,
        "hygiene_score": hygiene_score,
        "risk_drivers": dict(risk_drivers),
        "critical_paths": critical_paths[:8],
        "priority_items": sorted(priority_items, key=lambda row: ({"Critical": 0, "High": 1}.get(row["risk_level"], 9), row["score"]))[:10],
        "privacy_model": "No raw passwords, usernames, notes, or URLs are included in this summary.",
    }
