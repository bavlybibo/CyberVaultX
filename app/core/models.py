from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Any


@dataclass(frozen=True, slots=True)
class SafeCredentialView:
    id: int
    title: str
    username_masked: str
    category: str
    website_host: str
    risk_level: str = "Low"
    updated_at: str = ""

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class SecurityFindingView:
    title: str
    severity: str
    confidence: int
    evidence: list[str]
    why_it_matters: str
    recommendation: str
    affected_item: str

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)
