from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from app import crypto_utils
from app.manager import VaultManager

crypto_utils.MIN_BACKUP_KDF_ITERATIONS = 2
crypto_utils.PBKDF2_ITERATIONS = 2


class V560ProductReleaseTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tmp.name) / 'vault.db'
        self.manager = VaultManager(self.db_path)
        self.manager.setup_master_password('Bavly', 'Strong!VaultPass123')

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_signed_report_package_and_signature_tamper_detection(self) -> None:
        self.manager.add_credential(
            title='Weak Demo', username='weak@example.com', password='password123',
            category='Work', tags='', notes='', website='weak.example', is_favorite=False,
        )
        package_dir = Path(self.tmp.name) / 'package'
        self.manager.export_report_package(package_dir, privacy_level='minimal')
        manifest = json.loads((package_dir / 'manifest.json').read_text(encoding='utf-8'))
        self.assertEqual(manifest['format_version'], 'CyberVaultReportPackage/v3-signed')
        self.assertTrue(manifest.get('manifest_signature'))
        result = self.manager.verify_report_package(package_dir)
        self.assertTrue(result['valid'])
        self.assertTrue(result['signature_valid'])

        manifest['privacy_level'] = 'tampered'
        (package_dir / 'manifest.json').write_text(json.dumps(manifest), encoding='utf-8')
        tampered = self.manager.verify_report_package(package_dir)
        self.assertFalse(tampered['valid'])
        self.assertFalse(tampered['signature_valid'])

    def test_audit_head_export_and_compare(self) -> None:
        self.manager.add_log('Demo Event', 'Generated a proof checkpoint.')
        head_path = Path(self.tmp.name) / 'audit_head.json'
        self.manager.export_audit_head_hash(head_path)
        result = self.manager.compare_audit_head_hash(head_path)
        self.assertTrue(result['valid'])
        self.manager.add_log('Later Event', 'Head should change.')
        result2 = self.manager.compare_audit_head_hash(head_path)
        self.assertFalse(result2['valid'])

    def test_backup_preview_has_diff_summary(self) -> None:
        self.manager.add_credential(
            title='GitHub', username='user@example.com', password='GitHub!Passphrase123',
            category='Work', tags='mfa', notes='', website='github.com', is_favorite=False,
        )
        backup_path = Path(self.tmp.name) / 'backup.cvxbackup'
        self.manager.export_encrypted_backup(backup_path, 'Backup!Passphrase123')
        preview = self.manager.preview_encrypted_backup(backup_path, 'Backup!Passphrase123')
        self.assertIn('diff_summary', preview)
        self.assertIn('diff_preview', preview)
        self.assertEqual(preview['diff_summary']['will_skip_duplicates_on_merge'], 1)

    def test_local_product_intelligence_helpers(self) -> None:
        cid = self.manager.add_credential(
            title='Cloud Dashboard', username='ops@example.com', password='password123',
            category='Servers', tags='', notes='', website='cloud.example', is_favorite=True,
        )
        coach = self.manager.local_ai_security_coach(cid)
        self.assertIn('why_risky', coach)
        attack = self.manager.attack_path_simulation(cid)
        self.assertGreaterEqual(len(attack['chain']), 2)
        timeline = self.manager.executive_score_timeline()
        self.assertGreaterEqual(len(timeline), 4)
        redaction = self.manager.privacy_redaction_preview('analyst')
        self.assertIn('raw passwords', redaction['excluded'])
        progress = self.manager.record_remediation_action(cid, action='set_mfa_enabled')
        self.assertEqual(progress['latest']['action'], 'set_mfa_enabled')
        updated = self.manager.get_credential(cid)
        self.assertIn('mfa', updated.tags.lower())


if __name__ == '__main__':
    unittest.main()
