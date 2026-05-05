from __future__ import annotations

from pathlib import Path
from typing import Any

from ..manager import VaultManager


class VaultRepository:
    """Small service-facing repository wrapper around the existing VaultManager.

    It keeps UI/application code away from raw SQLite details while preserving the
    proven manager implementation.
    """

    def __init__(self, db_path: str | Path) -> None:
        self.manager = VaultManager(db_path)

    def list_safe_credentials(self) -> list[dict[str, Any]]:
        rows = []
        for item in self.manager.list_credentials():
            rows.append({
                "id": item.id,
                "title": item.title,
                "username_masked": item.username[:2] + "***" if item.username else "",
                "category": item.category,
                "website": item.website,
                "updated_at": item.updated_at,
            })
        return rows
