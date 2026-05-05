from __future__ import annotations

from typing import Any

from ..security.risk_engine import summarize_vault_risk


class VaultService:
    """Application service for dashboard-level vault operations."""

    def __init__(self, manager: Any) -> None:
        self.manager = manager

    def dashboard_state(self) -> dict[str, Any]:
        credentials = self.manager.list_credentials() if self.manager.is_unlocked else []
        dashboard = self.manager.dashboard() if self.manager.is_unlocked else {}
        return {
            "unlocked": self.manager.is_unlocked,
            "initialized": self.manager.is_initialized,
            "metrics": dashboard,
            "risk_summary": summarize_vault_risk(credentials),
        }
