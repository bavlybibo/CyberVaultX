from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from app import crypto_utils
from app.manager import VaultManager

crypto_utils.MIN_BACKUP_KDF_ITERATIONS = 2
crypto_utils.PBKDF2_ITERATIONS = 2


class V551HardeningTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tmp.name) / 'vault.db'
        self.manager = VaultManager(self.db_path)
        self.manager.setup_master_password('Bavly', 'Strong!VaultPass123')

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_report_package_verifier_rejects_path_traversal(self) -> None:
        self.manager.add_credential(
            title='Verifier', username='verifier@example.com', password='Verifier!Passphrase123',
            category='Work', tags='', notes='', website='verify.example', is_favorite=False,
        )
        package_dir = Path(self.tmp.name) / 'package'
        self.manager.export_report_package(package_dir, privacy_level='minimal')
        manifest_path = package_dir / 'manifest.json'
        manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
        manifest['files'][0]['name'] = '../evil.txt'
        manifest_path.write_text(json.dumps(manifest), encoding='utf-8')
        with self.assertRaises(ValueError):
            self.manager.verify_report_package(package_dir)

    def test_audit_retention_purge_keeps_retained_chain_valid(self) -> None:
        for idx in range(3):
            self.manager.add_log(f'Old Event {idx}', f'old event {idx}')
        old_timestamp = (datetime.now(timezone.utc) - timedelta(days=900)).replace(microsecond=0).isoformat()
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('UPDATE activity_log SET timestamp=?', (old_timestamp,))
            conn.commit()
        self.manager.add_log('Current Event', 'new retained event')
        deleted = self.manager.purge_old_activity_logs(days=365)
        self.assertGreater(deleted, 0)
        chain = self.manager.verify_audit_chain()
        self.assertTrue(chain['valid'])
        self.assertTrue(self.manager.get_setting('audit_last_retention_checkpoint'))

    def test_html_report_uses_payload_hash_and_seven_ai_priority_columns(self) -> None:
        self.manager.add_credential(
            title='Weak', username='weak@example.com', password='password123',
            category='Work', tags='', notes='', website='weak.example', is_favorite=False,
        )
        report = Path(self.tmp.name) / 'report.html'
        self.manager.export_report(report, privacy_safe=True, privacy_level='minimal')
        rendered = report.read_text(encoding='utf-8')
        self.assertIn('Payload SHA-256', rendered)
        self.assertIn('Final file hashes are recorded in report-package manifests', rendered)
        self.assertIn('<th>Attack Scenario</th><th>Business Impact</th>', rendered)

    def test_restore_safety_snapshot_rolls_back_on_insert_failure(self) -> None:
        self.manager.add_credential(
            title='Original', username='original@example.com', password='Original!Passphrase123',
            category='Work', tags='', notes='', website='original.example', is_favorite=False,
        )
        snapshot = self.manager.create_safety_snapshot('rollback regression', fail_silent=False)
        original_encrypt = self.manager._encrypt_fields_with_key

        def fail_encrypt(*args, **kwargs):
            raise RuntimeError('forced restore failure')

        self.manager._encrypt_fields_with_key = fail_encrypt  # type: ignore[method-assign]
        try:
            with self.assertRaises(RuntimeError):
                self.manager.restore_safety_snapshot(snapshot)
        finally:
            self.manager._encrypt_fields_with_key = original_encrypt  # type: ignore[method-assign]
        titles = {item.title for item in self.manager.list_credentials()}
        self.assertEqual(titles, {'Original'})


if __name__ == '__main__':
    unittest.main()
