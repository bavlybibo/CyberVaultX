from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from app import crypto_utils
from app.breach_db import sha1_hex
from app.manager import VaultManager

crypto_utils.MIN_BACKUP_KDF_ITERATIONS = 2
crypto_utils.PBKDF2_ITERATIONS = 2


class ProductUpgradeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tmp.name) / 'vault.db'
        self.manager = VaultManager(self.db_path)
        self.manager.setup_master_password('Bavly', 'Strong!VaultPass123')

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_privacy_safe_export_check_does_not_leak_raw_secrets(self) -> None:
        self.manager.add_credential(
            title='Private Admin', username='admin@example.com', password='NeverLeak!12345',
            category='Work', tags='admin', notes='private internal note', website='admin.example', is_favorite=True,
        )
        check = self.manager.check_privacy_safe_export(privacy_level='minimal')
        self.assertTrue(check['ok'], check)
        report_path = Path(self.tmp.name) / 'safe_report.json'
        self.manager.export_privacy_safe_report(report_path, level='minimal')
        rendered = report_path.read_text(encoding='utf-8')
        self.assertNotIn('NeverLeak!12345', rendered)
        self.assertNotIn('admin@example.com', rendered)
        self.assertNotIn('private internal note', rendered)

    def test_report_readiness_score_is_explainable(self) -> None:
        self.manager.add_credential(
            title='Weak Portal', username='weak@example.com', password='123456',
            category='Work', tags='', notes='', website='', is_favorite=False,
        )
        readiness = self.manager.report_readiness_score(privacy_level='minimal')
        self.assertIn('percentage', readiness)
        self.assertIn(readiness['status'], {'Ready', 'Needs review', 'Not ready'})
        self.assertTrue(readiness['warnings'] or readiness['blockers'])
        self.assertIn('privacy_status', readiness)

    def test_custom_breach_list_import_validates_sha1_and_affects_offline_lookup(self) -> None:
        password = 'CustomBreached!2026'
        custom = Path(self.tmp.name) / 'custom_hashes.txt'
        custom.write_text(sha1_hex(password) + '\n', encoding='utf-8')
        result = self.manager.import_custom_breach_sha1_list(custom)
        self.assertEqual(result['imported'], 1)
        self.manager.add_credential(
            title='Imported Hit', username='hit@example.com', password=password,
            category='Work', tags='test', notes='', website='hit.example', is_favorite=False,
        )
        findings = self.manager.security_findings()
        self.assertTrue(any(row['breached'] for row in findings))

    def test_custom_breach_list_rejects_invalid_hashes(self) -> None:
        bad = Path(self.tmp.name) / 'bad_hashes.txt'
        bad.write_text('not-a-sha1\n', encoding='utf-8')
        with self.assertRaises(ValueError):
            self.manager.import_custom_breach_sha1_list(bad)

    def test_password_fix_simulator_produces_explainable_output(self) -> None:
        self.manager.add_credential(
            title='Weak', username='weak@example.com', password='password123',
            category='Email', tags='', notes='', website='mail.example', is_favorite=False,
        )
        simulation = self.manager.password_fix_simulator(top_n=1)
        self.assertIsNotNone(simulation['current_score'])
        self.assertGreaterEqual(simulation['projected_score'], simulation['current_score'])
        self.assertTrue(simulation['selected_fixes'])
        self.assertIn('Rule-based', simulation['method'])
        self.assertIn('recommended_action', simulation['selected_fixes'][0])

    def test_audit_timeline_generation_from_logs(self) -> None:
        self.manager.add_credential(
            title='Timeline', username='time@example.com', password='Timeline!Pass123',
            category='General', tags='timeline', notes='', website='time.example', is_favorite=False,
        )
        report_dir = Path(self.tmp.name) / 'package'
        self.manager.export_report_package(report_dir, privacy_level='minimal')
        events = self.manager.audit_timeline(limit=20)
        categories = {event['category'] for event in events}
        self.assertIn('credential_added', categories)
        self.assertIn('report_generated', categories)

    def test_backup_and_clipboard_status_are_product_safe(self) -> None:
        backup_status = self.manager.backup_integrity_status()
        clipboard_status = self.manager.clipboard_safety_status()
        self.assertIn(backup_status['status'], {'PASS', 'WARNING'})
        self.assertEqual(clipboard_status['status'], 'PASS')
        self.assertGreaterEqual(clipboard_status['clipboard_clear_seconds'], 5)

    def test_report_package_writes_verification_output(self) -> None:
        self.manager.add_credential(
            title='Package', username='pkg@example.com', password='Pkg!Passphrase123',
            category='Work', tags='pkg', notes='', website='pkg.example', is_favorite=False,
        )
        package_dir = Path(self.tmp.name) / 'report_package'
        self.manager.export_report_package(package_dir, privacy_level='minimal')
        verification = package_dir / 'verification_output.txt'
        self.assertTrue(verification.exists())
        rendered = json.loads(verification.read_text(encoding='utf-8'))
        self.assertTrue(rendered['valid'])

    def test_manager_backwards_compatibility_methods_still_exist(self) -> None:
        self.assertTrue(hasattr(self.manager, 'load_demo_data'))
        self.assertTrue(hasattr(self.manager, 'create_assessment_workspace'))
        self.assertTrue(hasattr(self.manager, 'export_report_package'))
        self.assertTrue(hasattr(self.manager, 'verify_report_package'))


if __name__ == '__main__':
    unittest.main()
