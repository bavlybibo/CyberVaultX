from __future__ import annotations

from pathlib import Path
from typing import Any


class BackupManager:
    """Typed facade for backup operations implemented by VaultManager."""

    def __init__(self, manager: Any) -> None:
        self.manager = manager

    def export(self, path: str | Path, passphrase: str) -> Path:
        return self.manager.export_encrypted_backup(path, passphrase)

    def preview_restore(self, path: str | Path, passphrase: str) -> dict[str, Any]:
        return self.manager.preview_encrypted_backup(path, passphrase)

    def restore(self, path: str | Path, passphrase: str, *, replace_existing: bool = False, skip_duplicates: bool = True) -> dict[str, Any]:
        return self.manager.import_encrypted_backup(path, passphrase, replace_existing=replace_existing, skip_duplicates=skip_duplicates)
