from __future__ import annotations

import json
import tempfile
from pathlib import Path

from app import crypto_utils
from app.ai.security_coach import build_local_security_coach
from app.core.config import load_config
from app.crypto.vault_crypto import decrypt_secret, encrypt_secret
from app.manager import VaultManager
from app.security.password_generator import generate_password
from app.security.password_strength import analyze_password_strength, is_strong_password
from app.services.health_service import HealthService
from app.services.report_service import supported_report_formats
from tools.project_cleaner import clean_project

crypto_utils.MIN_BACKUP_KDF_ITERATIONS = 2
crypto_utils.PBKDF2_ITERATIONS = 2


def _manager(tmp: tempfile.TemporaryDirectory[str]) -> VaultManager:
    manager = VaultManager(Path(tmp.name) / "vault.db")
    manager.setup_master_password("Bavly", "Strong!VaultPass123")
    return manager


def test_new_architecture_wrappers_encrypt_and_analyze_without_plaintext_logging() -> None:
    key = b"K" * 32
    payload = encrypt_secret("secret-value", key, aad="field:demo")
    assert payload["ciphertext"] != "secret-value"
    assert decrypt_secret(payload, key, aad="field:demo") == "secret-value"

    generated = generate_password(20)
    assert len(generated) == 20
    assert is_strong_password(generated)
    analysis = analyze_password_strength("password123", context="demo")
    assert analysis["score"] < 70
    assert analysis["safe_to_store"] is False


def test_json_report_export_is_machine_readable_and_redacted() -> None:
    with tempfile.TemporaryDirectory() as raw:
        tmp = tempfile.TemporaryDirectory(dir=raw)
        try:
            manager = _manager(tmp)
            manager.add_credential(
                title="Private Bank",
                username="private.person@example.com",
                password="password123",
                category="Banking",
                tags="secret",
                notes="do not expose",
                website="bank.example",
                is_favorite=False,
            )
            report_path = Path(tmp.name) / "report.json"
            manager.export_report(report_path, privacy_safe=True, privacy_level="minimal")
            data = json.loads(report_path.read_text(encoding="utf-8"))
            rendered = json.dumps(data)
            assert data["export_format"] == "json"
            assert "limitations" in data
            assert "password123" not in rendered
            assert "private.person@example.com" not in rendered
            assert "Private Bank" not in rendered
            assert "do not expose" not in rendered
        finally:
            tmp.cleanup()


def test_local_security_coach_schema_and_health_service() -> None:
    with tempfile.TemporaryDirectory() as raw:
        tmp = tempfile.TemporaryDirectory(dir=raw)
        try:
            manager = _manager(tmp)
            manager.add_credential(
                title="Weak Demo",
                username="weak@example.test",
                password="password123",
                category="Demo",
                tags="",
                notes="",
                website="demo.example",
                is_favorite=False,
            )
            coach = build_local_security_coach(manager)
            assert coach["mode"] == "local-deterministic"
            assert coach["findings"]
            finding = coach["findings"][0]
            assert {"title", "severity", "confidence", "evidence", "why_it_matters", "recommendation", "affected_item"}.issubset(finding)
            summary = HealthService(root=Path.cwd(), app_data_dir=Path(tmp.name)).summary()
            assert summary["total"] >= 1
            assert supported_report_formats() == (".html", ".json", ".txt")
        finally:
            tmp.cleanup()


def test_config_and_project_cleaner_are_safe_for_release_tree() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        cfg = load_config(tmp)
        assert cfg.vault_db.name == "vault.db"
        junk = Path(tmp) / "pkg" / "__pycache__"
        junk.mkdir(parents=True)
        (junk / "x.pyc").write_bytes(b"cache")
        result = clean_project(tmp)
        assert result["removed_dirs"] >= 1
        assert not junk.exists()
