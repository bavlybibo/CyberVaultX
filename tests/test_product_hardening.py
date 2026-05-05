from __future__ import annotations

import csv
import json
import os
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

from app import crypto_utils
from app.manager import VaultManager
from app.db import VaultDatabase, SCHEMA_VERSION

crypto_utils.MIN_BACKUP_KDF_ITERATIONS = 2
crypto_utils.PBKDF2_ITERATIONS = 2


class ProductHardeningTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tmp.name) / 'vault.db'
        self.manager = VaultManager(self.db_path)
        self.manager.setup_master_password('Bavly', 'Strong!VaultPass123')

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_schema_version_5_migrations_are_recorded(self) -> None:
        self.assertGreaterEqual(self.manager.get_schema_version(), 5)
        self.assertEqual(self.manager.get_setting('default_report_privacy_level'), 'analyst')
        versions = {int(item['version']) for item in self.manager.get_migration_history()}
        self.assertIn(4, versions)
        self.assertIn(5, versions)

    def test_duplicate_detection_finds_existing_credential(self) -> None:
        cid = self.manager.add_credential(
            title='Bugcrowd', username='bavly@example.com', password='Unique!Passphrase123',
            category='Work', tags='bb', notes='', website='https://www.bugcrowd.com/', is_favorite=False
        )
        matches = self.manager.find_duplicate_credentials(title='bugcrowd', username='bavly@example.com', website='bugcrowd.com')
        self.assertEqual([m.id for m in matches], [cid])

    def test_csv_preview_reports_valid_invalid_and_duplicates(self) -> None:
        self.manager.add_credential(
            title='Bugcrowd', username='bavly@example.com', password='Unique!Passphrase123',
            category='Work', tags='bb', notes='', website='bugcrowd.com', is_favorite=False
        )
        rows = [
            {'name': 'Bugcrowd', 'login': 'bavly@example.com', 'password': 'x', 'url': 'https://bugcrowd.com'},
            {'name': 'Missing Password', 'login': 'x@example.com', 'password': '', 'url': 'example.com'},
            {'name': 'New Site', 'login': 'new@example.com', 'password': 'Strong!Passphrase456', 'url': 'new.example'},
        ]
        mapping = {'title': 'name', 'username': 'login', 'password': 'password', 'website': 'url'}
        preview = self.manager.preview_csv_rows(rows, mapping)
        self.assertEqual(preview['total'], 3)
        self.assertEqual(preview['valid'], 1)
        self.assertEqual(preview['invalid'], 2)
        self.assertEqual(preview['duplicates'], 1)
        self.assertTrue(preview['preview'])

    def test_safety_snapshot_restore_roundtrip(self) -> None:
        first = self.manager.add_credential(
            title='Keep', username='keep@example.com', password='Keep!Passphrase123',
            category='General', tags='safe', notes='', website='keep.example', is_favorite=False
        )
        snapshot = self.manager.create_safety_snapshot('unit test restore', fail_silent=False)
        self.manager.add_credential(
            title='Later', username='later@example.com', password='Later!Passphrase123',
            category='General', tags='', notes='', website='later.example', is_favorite=False
        )
        stats = self.manager.restore_safety_snapshot(snapshot)
        titles = {item.title for item in self.manager.list_credentials()}
        self.assertEqual(stats['imported'], 1)
        self.assertEqual(titles, {'Keep'})
        self.assertIsNotNone(self.manager.get_setting('last_safety_snapshot_sha256'))

    def test_printable_report_has_hash_and_print_css(self) -> None:
        self.manager.add_credential(
            title='Weak', username='weak@example.com', password='fff', category='Social', tags='', notes='', website='weak.example', is_favorite=False
        )
        path = Path(self.tmp.name) / 'report.html'
        self.manager.export_report(path, privacy_safe=True, privacy_level='minimal')
        report = path.read_text(encoding='utf-8')
        self.assertIn('@media print', report)
        self.assertIn('Report SHA-256', report)
        self.assertIn('Privacy-safe mode is enabled', report)
        self.assertNotIn('weak@example.com', report)

    def test_audit_log_export_is_privacy_aware(self) -> None:
        self.manager.add_credential(
            title='Audit', username='audit@example.com', password='Audit!Passphrase123',
            category='General', tags='', notes='', website='audit.example', is_favorite=False
        )
        path = Path(self.tmp.name) / 'audit.html'
        self.manager.export_audit_log(path, privacy_level='minimal')
        rendered = path.read_text(encoding='utf-8')
        self.assertIn('CyberVault X Audit Activity', rendered)
        self.assertIn('SHA-256', rendered)
        self.assertNotIn(str(self.tmp.name), rendered)

    def test_interactive_fix_simulator_projects_gain(self) -> None:
        self.manager.add_credential(
            title='Weak', username='weak@example.com', password='fff', category='Social', tags='', notes='', website='weak.example', is_favorite=False
        )
        result = self.manager.simulate_fix_impact({'weak': True, 'reused': False, 'old': False, 'metadata': False, 'trash': False, 'backup': False})
        self.assertIsNotNone(result['current_score'])
        self.assertGreaterEqual(result['projected_score'], result['current_score'])
        self.assertTrue(result['selected_fixes'])

    def test_report_package_exports_manifest_hashes(self) -> None:
        self.manager.add_credential(
            title='Package Test', username='pkg@example.com', password='Pkg!Passphrase123',
            category='Work', tags='pkg', notes='', website='pkg.example', is_favorite=False
        )
        package_dir = Path(self.tmp.name) / 'report_package'
        exported = self.manager.export_report_package(package_dir, privacy_level='minimal')
        self.assertEqual(exported, package_dir)
        manifest = json.loads((package_dir / 'manifest.json').read_text(encoding='utf-8'))
        self.assertEqual(manifest['package'], 'CyberVault X Report Package')
        self.assertEqual(manifest['privacy_level'], 'minimal')
        names = {item['name'] for item in manifest['files']}
        self.assertEqual(names, {'executive_report.html', 'audit_log.html', 'ai_guardian_summary.txt'})
        for item in manifest['files']:
            data = (package_dir / item['name']).read_bytes()
            import hashlib
            self.assertEqual(hashlib.sha256(data).hexdigest(), item['sha256'])

    def test_report_package_verifier_detects_tampering(self) -> None:
        self.manager.add_credential(
            title='Package Verify', username='verify@example.com', password='Verify!Passphrase123',
            category='Work', tags='pkg', notes='', website='verify.example', is_favorite=False
        )
        package_dir = Path(self.tmp.name) / 'verify_package'
        self.manager.export_report_package(package_dir, privacy_level='minimal')
        valid = self.manager.verify_report_package(package_dir)
        self.assertTrue(valid['valid'])
        (package_dir / 'ai_guardian_summary.txt').write_text('tampered', encoding='utf-8')
        tampered = self.manager.verify_report_package(package_dir)
        self.assertFalse(tampered['valid'])
        self.assertTrue(any(not item['valid'] for item in tampered['files']))

    def test_backup_restore_preview_reports_duplicates_without_importing(self) -> None:
        cid = self.manager.add_credential(
            title='Preview', username='preview@example.com', password='Preview!Passphrase123',
            category='Work', tags='preview', notes='', website='preview.example', is_favorite=False
        )
        backup_path = Path(self.tmp.name) / 'preview.cvxbackup'
        self.manager.export_encrypted_backup(backup_path, 'Backup!Passphrase123')
        preview = self.manager.preview_encrypted_backup(backup_path, 'Backup!Passphrase123')
        self.assertEqual(preview['total_rows'], 1)
        self.assertEqual(preview['duplicates_in_current_vault'], 1)
        self.assertEqual(len(self.manager.list_credentials()), 1)
        self.assertEqual(self.manager.get_credential(cid).title, 'Preview')

    def test_security_proof_center_and_audit_chain(self) -> None:
        self.manager.add_credential(
            title='Proof', username='proof@example.com', password='Proof!Passphrase123',
            category='Work', tags='proof', notes='', website='proof.example', is_favorite=False
        )
        proof = self.manager.security_proof_center()
        self.assertIn(proof['overall_status'], {'PASS', 'REVIEW'})
        self.assertTrue(proof['audit_chain']['valid'])
        self.assertGreaterEqual(proof['audit_chain']['events_checked'], 1)
        with self.manager.db.connect() as conn:
            conn.execute("UPDATE activity_log SET details='tampered' WHERE id=(SELECT MIN(id) FROM activity_log)")
            conn.commit()
        tampered = self.manager.verify_audit_chain()
        self.assertFalse(tampered['valid'])

    def test_ai_guardian_v2_priority_explanations_are_redacted(self) -> None:
        self.manager.add_credential(
            title='Bank', username='bank.person@example.com', password='password123',
            category='Banking', tags='', notes='private note', website='bank.example', is_favorite=False
        )
        plan = self.manager.ai_security_plan()
        self.assertTrue(plan['priority_items'])
        item = plan['priority_items'][0]
        self.assertIn('attack_scenario', item)
        self.assertIn('business_impact', item)
        self.assertIn('fix_path', item)
        self.assertIn('expected_score_gain', item)
        rendered = json.dumps(plan)
        self.assertNotIn('password123', rendered)
        self.assertNotIn('bank.person@example.com', rendered)
        self.assertNotIn('private note', rendered)


    def test_report_package_does_not_contain_sensitive_source_strings(self) -> None:
        self.manager.add_credential(
            title='Sensitive Private Bank', username='private.person@example.com', password='Pkg!Passphrase123',
            category='Banking', tags='secret', notes='do not export this note', website='bank.example', is_favorite=False
        )
        package_dir = Path(self.tmp.name) / 'privacy_package'
        self.manager.export_report_package(package_dir, privacy_level='minimal')
        combined = '\n'.join(path.read_text(encoding='utf-8', errors='ignore') for path in package_dir.iterdir() if path.is_file())
        self.assertNotIn('Pkg!Passphrase123', combined)
        self.assertNotIn('Sensitive Private Bank', combined)
        self.assertNotIn('private.person@example.com', combined)
        self.assertNotIn('do not export this note', combined)
        self.assertNotIn(str(self.tmp.name), combined)

    def test_ai_remediation_progress_tracks_without_changing_credentials(self) -> None:
        cid = self.manager.add_credential(
            title='Weak', username='weak@example.com', password='fff', category='Social', tags='', notes='', website='weak.example', is_favorite=False
        )
        before = self.manager.get_credential(cid).password
        result = self.manager.mark_ai_remediation_complete('Credential #1', 'Replace weak password')
        self.assertEqual(result['completed_count'], 1)
        self.assertEqual(self.manager.get_credential(cid).password, before)
        log = self.manager.get_ai_remediation_log()
        self.assertEqual(log[0]['credential_ref'], 'Credential #1')

    def test_activity_retention_purges_old_logs_only(self) -> None:
        with self.manager.db.connect() as conn:
            conn.execute(
                "INSERT INTO activity_log(timestamp, action, details, severity) VALUES (?, ?, ?, ?)",
                ('2001-01-01T00:00:00+00:00', 'Old Event', 'old', 'info'),
            )
            conn.execute(
                "INSERT INTO activity_log(timestamp, action, details, severity) VALUES (?, ?, ?, ?)",
                ('2999-01-01T00:00:00+00:00', 'Future Event', 'keep', 'info'),
            )
            conn.commit()
        deleted = self.manager.purge_old_activity_logs(days=365)
        self.assertGreaterEqual(deleted, 1)
        actions = {row['action'] for row in self.manager.get_logs(limit=100)}
        self.assertNotIn('Old Event', actions)
        self.assertIn('Future Event', actions)



def _tk_display_available() -> bool:
    if sys.platform.startswith('win'):
        return True
    if os.environ.get('CYBERVAULTX_RUN_TK_SMOKE', '').strip().lower() not in {'1', 'true', 'yes'}:
        return False
    if not os.environ.get('DISPLAY'):
        return False
    try:
        import tkinter as _tk
        root = _tk.Tk()
        root.withdraw()
        root.destroy()
        return True
    except Exception:
        return False


@unittest.skipUnless(_tk_display_available(), 'Tk smoke tests require a reachable display server')
class UISmokeTests(unittest.TestCase):
    def test_main_ui_builds_and_core_pages_exist(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        try:
            from app.ui import PasswordManagerApp
            app = PasswordManagerApp(Path(tmp.name) / 'vault.db')
            app.withdraw()
            for page in ('dashboard', 'vault', 'security', 'ai_guardian', 'proof', 'generator', 'trash', 'activity', 'settings', 'about'):
                self.assertIn(page, app.pages)
            app.destroy()
        finally:
            tmp.cleanup()


if __name__ == '__main__':
    unittest.main()
