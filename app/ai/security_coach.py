from __future__ import annotations

from typing import Any

from .finding_builder import build_finding
from .recommendation_engine import recommended_action_for_issues


def coach_findings_from_security_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Convert internal security rows into concise card-ready AI Coach findings."""
    findings: list[dict[str, Any]] = []
    for row in rows:
        issues = [str(item) for item in row.get("issues", []) if str(item).strip()]
        risk = str(row.get("risk_level", "Low"))
        if not issues and risk == "Low":
            continue
        score = int(row.get("score", 100) or 100)
        confidence = max(45, min(95, 100 - abs(70 - score)))
        findings.append(build_finding(
            title=str(row.get("title") or "Credential risk finding"),
            severity="Medium" if risk == "Moderate" else risk,
            confidence=confidence,
            evidence=issues[:4] or [f"Risk engine classified this item as {risk}."],
            why_it_matters="Weak, reused, breached, or stale passwords increase account takeover risk when attackers obtain credential material from other sources.",
            recommendation=recommended_action_for_issues(issues, risk_level=risk),
            affected_item=str(row.get("title") or row.get("id") or "Credential"),
        ))
    return findings


def build_local_security_coach(manager: Any) -> dict[str, Any]:
    rows = manager.security_findings() if manager.is_unlocked else []
    findings = coach_findings_from_security_rows(rows)
    return {
        "mode": "local-deterministic",
        "privacy": "No raw password, master password, key, or token is included.",
        "finding_count": len(findings),
        "findings": findings,
    }
