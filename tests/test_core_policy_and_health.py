from __future__ import annotations

from pathlib import Path

from app.core.password_policy import validate_master_password_policy
from app.core.system_health import collect_system_health, summarize_health
from app.manager import VaultManager


def test_master_password_policy_rejects_personal_or_predictable_values() -> None:
    weak = validate_master_password_policy('BavlyPassword123!', 'Bavly')
    assert not weak.ok
    assert any('owner name' in reason or 'predictable' in reason for reason in weak.reasons)


def test_master_password_policy_accepts_strong_passphrase() -> None:
    strong = validate_master_password_policy('River!Vault-Photon-2026', 'Bavly')
    assert strong.ok
    assert strong.score >= 80


def test_manager_uses_core_master_password_policy(tmp_path: Path) -> None:
    manager = VaultManager(tmp_path / 'vault.db')
    try:
        manager.setup_master_password('Bavly', 'BavlyPassword123!')
    except ValueError as exc:
        assert 'owner name' in str(exc) or 'predictable' in str(exc)
    else:  # pragma: no cover - defensive
        raise AssertionError('weak owner-derived master password was accepted')


def test_system_health_summary_reports_release_readiness(tmp_path: Path) -> None:
    checks = collect_system_health(Path(__file__).resolve().parents[1], tmp_path)
    names = {item['name'] for item in checks}
    assert 'Python runtime' in names
    assert 'Offline breach dataset' in names
    summary = summarize_health(checks)
    assert summary['total'] == len(checks)
    assert 0 <= summary['score'] <= 100
