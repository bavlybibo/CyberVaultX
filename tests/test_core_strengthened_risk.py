from __future__ import annotations

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from app.analyzer import analyze_password, build_breach_intelligence
from app.security.risk_engine import summarize_vault_risk
from app.security_policy import composite_risk_level, is_high_value_category
from app.site_policy import infer_account_policy


def _cred(idx: int, password: str, *, category: str = "General", days_old: int = 0, website: str = "example.com"):
    updated = (datetime.now(timezone.utc) - timedelta(days=days_old)).replace(microsecond=0).isoformat()
    return SimpleNamespace(
        id=idx,
        title=f"Credential {idx}",
        username=f"user{idx}@example.com",
        password=password,
        category=category,
        website=website,
        updated_at=updated,
    )


def test_high_value_category_is_case_and_alias_safe():
    assert is_high_value_category("email")
    assert is_high_value_category("financial apps")
    assert is_high_value_category("infra-admin")
    assert composite_risk_level(80, reuse_count=2, category="email") == "Critical"
    assert infer_account_policy(category="crypto").risk_tier == "Critical"


def test_dictionary_suffix_password_is_not_overrated():
    result = analyze_password("CompanyPortal2026!!", context="Company Portal login")
    assert result.score <= 58
    assert "Dictionary suffix pattern" in result.patterns
    assert result.score_cap_reason


def test_leetspeak_common_password_intelligence_is_consistent():
    intel = build_breach_intelligence("P@ssw0rd123", context="admin portal")
    assert intel["common_password"] is True
    assert intel["score"] <= 45


def test_summarize_vault_risk_has_privacy_safe_core_model():
    rows = [
        _cred(1, "Summer2026!!", category="email", days_old=120, website="mail.example.com"),
        _cred(2, "Summer2026!!", category="Shopping", website="shop.example.com"),
        _cred(3, "N9#qL2!sV7@pX4zR", category="General", website="notes.example.com"),
    ]
    summary = summarize_vault_risk(rows)
    assert summary["reused_password_groups"] == 1
    assert summary["reused_password_items"] == 2
    assert summary["risk_level"] in {"Critical", "High"}
    assert summary["priority_items"]
    payload = repr(summary).lower()
    assert "summer2026" not in payload
    assert "user1@example" not in payload
    assert summary["privacy_model"].startswith("No raw passwords")


def test_backup_validation_rejects_unknown_history_reference(tmp_path):
    from app.manager import VaultManager

    manager = VaultManager(tmp_path / "vault.db")
    manager.setup_master_password("Analyst", "Correct-Horse-2026!Vault")
    with pytest.raises(ValueError, match="unknown credential id"):
        manager._validate_backup_payload({
            "credentials": [
                {"id": "1", "title": "A", "username": "u", "password": "p", "category": "General"}
            ],
            "history": {"999": [{"password": "old"}]},
        })
