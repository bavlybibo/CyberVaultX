from __future__ import annotations

from typing import Any

from .finding_builder import build_finding
from .recommendation_engine import recommended_action_for_issues


def _heuristic_confidence_for(row: dict[str, Any], issues: list[str]) -> tuple[int, list[str]]:
    """Return a policy-confidence value and a human explanation.

    This is not calibrated ML accuracy. It is a deterministic confidence score
    based on local evidence quality: breach/common hits, reuse counts, weak
    analyzer labels, stale age, and the number of independent issues.
    """
    lowered = " ".join(issues).lower()
    score = int(row.get("score", 100) or 100)
    confidence = 45 + min(20, len(issues) * 4)
    sources: list[str] = []
    if "breach" in lowered or "common" in lowered:
        confidence += 20; sources.append("offline breach/common-password evidence")
    if "reuse" in lowered or int(row.get("reuse_count", 0) or 0) > 1:
        confidence += 14; sources.append("reuse count evidence")
    if score < 55 or "weak" in lowered or "entropy" in lowered:
        confidence += 12; sources.append("password analyzer evidence")
    if "old" in lowered or "stale" in lowered:
        confidence += 6; sources.append("credential age evidence")
    if not sources:
        sources.append("single local policy signal")
    return max(45, min(95, confidence)), sources


def coach_findings_from_security_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Convert internal security rows into concise local coach findings."""
    findings: list[dict[str, Any]] = []
    for row in rows:
        issues = [str(item) for item in row.get("issues", []) if str(item).strip()]
        risk = str(row.get("risk_level", "Low"))
        if not issues and risk == "Low":
            continue
        confidence, sources = _heuristic_confidence_for(row, issues)
        evidence = issues[:4] or [f"Risk engine classified this item as {risk}."]
        evidence.append("Mode: local deterministic; confidence is heuristic policy confidence, not calibrated ML accuracy.")
        evidence.append("Evidence basis: " + ", ".join(sources[:3]) + ".")
        finding = build_finding(
            title=str(row.get("title") or "Credential risk finding"),
            severity="Medium" if risk == "Moderate" else risk,
            confidence=confidence,
            evidence=evidence,
            why_it_matters="Weak, reused, breached, or stale passwords increase account takeover risk when attackers obtain credential material from other sources.",
            recommendation=recommended_action_for_issues(issues, risk_level=risk),
            affected_item=str(row.get("title") or row.get("id") or "Credential"),
        )
        finding["confidence_label"] = "heuristic policy confidence"
        finding["confidence_sources"] = sources
        finding["uncertainty"] = "Deterministic local rules; no external LLM, no cloud AI, and no calibrated validation dataset."
        findings.append(finding)
    return findings


def build_local_security_coach(manager: Any) -> dict[str, Any]:
    rows = manager.security_findings() if manager.is_unlocked else []
    findings = coach_findings_from_security_rows(rows)
    return {
        "mode": "local-deterministic",
        "display_name": "Local Security Coach",
        "confidence_model": "heuristic policy confidence; not calibrated ML accuracy",
        "privacy": "No raw password, master password, key, token, or cloud AI request is included.",
        "limitations": [
            "No external LLM or cloud AI is used.",
            "Recommendations are evidence-bound to local analyzer, reuse, breach-subset, age, and metadata signals.",
            "Confidence values are heuristic policy confidence unless a measured validation dataset is added.",
        ],
        "finding_count": len(findings),
        "findings": findings,
    }
