from __future__ import annotations

from pathlib import Path
from typing import Any

from ..core.system_health import collect_system_health, summarize_health


class HealthService:
    def __init__(self, root: str | Path | None = None, app_data_dir: str | Path | None = None) -> None:
        self.root = root
        self.app_data_dir = app_data_dir

    def checks(self) -> list[dict[str, str]]:
        return collect_system_health(self.root, self.app_data_dir)

    def summary(self) -> dict[str, Any]:
        return summarize_health(self.checks())
