from __future__ import annotations

from pathlib import Path
import tempfile

from app.manager import VaultManager

DEMO_OWNER = "Demo User"
DEMO_MASTER = "Demo!MasterPassphrase2026"


def create_demo_vault(path: str | Path | None = None) -> Path:
    """Create a clearly labeled local demo vault with fake credentials only."""
    dest = Path(path) if path is not None else Path(tempfile.gettempdir()) / "cybervault_demo_vault.db"
    if dest.exists():
        dest.unlink()
    manager = VaultManager(dest)
    manager.setup_master_password(DEMO_OWNER, DEMO_MASTER)
    manager.add_credential(title="DEMO GitHub", username="demo@example.test", password="Demo!UniquePassphrase2026", category="Work", tags="demo", notes="Fake demo row", website="github.example.test", is_favorite=True)
    manager.add_credential(title="DEMO Weak Example", username="weak@example.test", password="password123", category="Demo", tags="demo weak", notes="Fake demo row", website="legacy.example.test", is_favorite=False)
    return dest


if __name__ == "__main__":
    print(create_demo_vault())
