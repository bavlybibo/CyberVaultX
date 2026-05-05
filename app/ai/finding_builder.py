from __future__ import annotations

from ..core.models import SecurityFindingView


def build_finding(
    *,
    title: str,
    severity: str,
    confidence: int,
    evidence: list[str],
    why_it_matters: str,
    recommendation: str,
    affected_item: str,
) -> dict:
    return SecurityFindingView(
        title=title,
        severity=severity,
        confidence=max(0, min(100, int(confidence))),
        evidence=evidence,
        why_it_matters=why_it_matters,
        recommendation=recommendation,
        affected_item=affected_item,
    ).as_dict()
