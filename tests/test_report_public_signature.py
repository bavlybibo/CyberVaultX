from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from app.manager import VaultManager
from app.services.signing import verify_manifest_public_signature


def _manager(tmp_path: Path) -> VaultManager:
    manager = VaultManager(tmp_path / 'vault.db')
    manager.setup_master_password('Bavly', 'Strong!VaultPass123')
    manager.add_credential(
        title='Package Public Signature',
        username='sig@example.com',
        password='Signature!Passphrase123',
        category='Work',
        tags='proof',
        notes='private note must not leak',
        website='signature.example',
        is_favorite=False,
    )
    return manager


def test_report_package_has_independent_public_signature(tmp_path: Path) -> None:
    manager = _manager(tmp_path)
    package_dir = tmp_path / 'package'
    manager.export_report_package(package_dir, privacy_level='minimal')

    manifest = json.loads((package_dir / 'manifest.json').read_text(encoding='utf-8'))
    assert manifest['public_signature_algorithm'] == 'Ed25519/public-manifest-signature-v1'
    assert manifest['signing_public_key_b64']
    assert manifest['signing_public_key_fingerprint']
    assert manifest['public_manifest_signature']
    assert verify_manifest_public_signature(manifest)

    verification = manager.verify_report_package(package_dir)
    assert verification['valid'] is True
    assert verification['public_signature_valid'] is True
    assert verification['public_signature_fingerprint_match'] is True


def test_public_signature_detects_manifest_tampering(tmp_path: Path) -> None:
    manager = _manager(tmp_path)
    package_dir = tmp_path / 'package'
    manager.export_report_package(package_dir, privacy_level='minimal')

    manifest_path = package_dir / 'manifest.json'
    manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
    manifest['privacy_level'] = 'analyst'
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding='utf-8')

    verification = manager.verify_report_package(package_dir)
    assert verification['valid'] is False
    assert verification['public_signature_valid'] is False


def test_external_verifier_accepts_public_signature_without_local_secret(tmp_path: Path) -> None:
    manager = _manager(tmp_path)
    package_dir = tmp_path / 'package'
    manager.export_report_package(package_dir, privacy_level='minimal')

    result = subprocess.run(
        [sys.executable, 'verify_report_package.py', str(package_dir)],
        cwd=Path(__file__).resolve().parents[1],
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert 'public_manifest_signature verified' in result.stdout
