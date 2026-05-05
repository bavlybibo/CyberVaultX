from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from app import crypto_utils
from app.manager import VaultManager

# Keep unit tests quick while production defaults remain high.
crypto_utils.MIN_BACKUP_KDF_ITERATIONS = 2
crypto_utils.PBKDF2_ITERATIONS = 2


class VaultManagerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tmp.name) / 'vault.db'
        self.manager = VaultManager(self.db_path)
        self.manager.setup_master_password('Bavly', 'Strong!VaultPass123')

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_master_rotation_keeps_full_history(self) -> None:
        cid = self.manager.add_credential(
            title='GitHub', username='user', password='Pass!001', category='Work', tags='', notes='', website='github.com', is_favorite=False
        )
        for idx in range(2, 8):
            self.manager.update_credential(
                cid,
                title='GitHub', username='user', password=f'Pass!00{idx}', category='Work', tags='', notes='', website='github.com', is_favorite=False
            )
        before = self.manager.get_password_history(cid, include_all=True)
        self.assertEqual(len(before), 6)
        self.manager.change_master_password('Strong!VaultPass123', 'Even!StrongerPass456')
        after = self.manager.get_password_history(cid, include_all=True)
        self.assertEqual(len(after), 6)

    def test_master_rotation_preserves_owner_and_vault_name(self) -> None:
        self.assertEqual(self.manager.owner_name, 'Bavly')
        self.assertEqual(self.manager.vault_name, 'Bavly Secure Vault')
        self.manager.change_master_password('Strong!VaultPass123', 'Even!StrongerPass456')
        self.assertEqual(self.manager.owner_name, 'Bavly')
        self.assertEqual(self.manager.vault_name, 'Bavly Secure Vault')

    def test_reauth_failure_does_not_lock_active_vault(self) -> None:
        cid = self.manager.add_credential(
            title='Mail', username='bavly@example.com', password='Pass!001', category='Email', tags='', notes='', website='mail.example', is_favorite=False
        )
        self.assertFalse(self.manager.verify_master_password_only('wrong-password'))
        self.assertTrue(self.manager.is_unlocked)
        self.assertEqual(self.manager.get_credential(cid).title, 'Mail')

    def test_unlock_throttling_persists_in_db(self) -> None:
        for _ in range(3):
            self.manager.lock()
            self.manager.unlock('wrong-password')
        reloaded = VaultManager(self.db_path)
        status = reloaded.unlock_guard_status()
        self.assertTrue(status['blocked'] or status['failed_attempts'] >= 3)

    def test_backup_roundtrip_with_duplicate_skip(self) -> None:
        cid = self.manager.add_credential(
            title='GitHub', username='user', password='Pass!001', category='Work', tags='', notes='', website='github.com', is_favorite=False
        )
        self.manager.update_credential(
            cid,
            title='GitHub', username='user', password='Pass!002', category='Work', tags='', notes='', website='github.com', is_favorite=False
        )
        backup_path = Path(self.tmp.name) / 'vault.cvxbackup'
        self.manager.export_encrypted_backup(backup_path, 'Backup!Passphrase123')
        exported = json.loads(backup_path.read_text(encoding='utf-8'))
        self.assertEqual(exported['format'], 'CyberVaultBackup/v3')

        second_db = Path(self.tmp.name) / 'second.db'
        second = VaultManager(second_db)
        second.setup_master_password('Bavly', 'Strong!VaultPass123')
        stats1 = second.import_encrypted_backup(backup_path, 'Backup!Passphrase123', replace_existing=False, skip_duplicates=True)
        stats2 = second.import_encrypted_backup(backup_path, 'Backup!Passphrase123', replace_existing=False, skip_duplicates=True)
        self.assertEqual(stats1['imported'], 1)
        self.assertEqual(stats2['skipped_duplicates'], 1)
        imported_item = second.list_credentials()[0]
        self.assertEqual(len(second.get_password_history(imported_item.id, include_all=True)), 1)

    def test_aad_blocks_encrypted_field_swaps(self) -> None:
        cid = self.manager.add_credential(
            title='GitHub', username='user', password='Pass!001', category='Work', tags='', notes='', website='github.com', is_favorite=False
        )
        conn = sqlite3.connect(self.db_path)
        try:
            row = conn.execute('SELECT title_nonce, title_cipher, password_nonce, password_cipher FROM credentials WHERE id=?', (cid,)).fetchone()
            conn.execute(
                'UPDATE credentials SET title_nonce=?, title_cipher=? WHERE id=?',
                (row[2], row[3], cid),
            )
            conn.commit()
        finally:
            conn.close()
        with self.assertRaises(ValueError):
            self.manager.get_credential(cid)

    def test_export_logs_hide_absolute_paths(self) -> None:
        self.manager.add_credential(
            title='GitHub', username='user', password='Pass!001', category='Work', tags='', notes='', website='github.com', is_favorite=False
        )
        report_path = Path(self.tmp.name) / 'nested' / 'report.html'
        self.manager.export_report(report_path)
        logs = self.manager.get_logs()
        report_logs = [row for row in logs if row['action'] == 'Report Exported']
        self.assertTrue(report_logs)
        self.assertIn('report.html', report_logs[0]['details'])
        self.assertNotIn(str(self.tmp.name), report_logs[0]['details'])

    def test_ai_context_is_redacted(self) -> None:
        self.manager.add_credential(
            title='Private GitHub', username='bavly@example.com', password='Pass!001', category='Work', tags='', notes='private note', website='github.com', is_favorite=False
        )
        ctx = self.manager.ai_advisor_context()
        rendered = json.dumps(ctx)
        self.assertNotIn('Pass!001', rendered)
        self.assertNotIn('bavly@example.com', rendered)
        self.assertNotIn('private note', rendered)
        self.assertIn('credential #', rendered)

    def test_ai_security_plan_is_local_redacted_and_actionable(self) -> None:
        self.manager.add_credential(
            title='Primary Email', username='bavly@example.com', password='qwerty12345', category='Email', tags='', notes='private note', website='mail.example', is_favorite=False
        )
        self.manager.add_credential(
            title='Shop', username='shop@example.com', password='qwerty12345', category='Shopping', tags='', notes='', website='shop.example', is_favorite=False
        )
        plan = self.manager.ai_security_plan()
        rendered = json.dumps(plan)
        self.assertIn('executive_summary', plan)
        self.assertTrue(plan['priority_items'])
        self.assertTrue(any(item['timeline'] in {'Today', 'This week'} for item in plan['priority_items']))
        self.assertNotIn('qwerty12345', rendered)
        self.assertNotIn('bavly@example.com', rendered)
        self.assertNotIn('private note', rendered)
        self.assertTrue(plan['optional_llm_payload']['user_context']['policy']['no_raw_passwords'])

    def test_ai_security_plan_refresh_does_not_persist_baseline(self) -> None:
        self.manager.add_credential(
            title='Portal',
            username='admin@example.com',
            password='Weakpass123!',
            category='Work',
            tags='',
            notes='',
            website='https://example.com',
            is_favorite=False,
        )
        self.assertIsNone(self.manager.db.get_meta('ai_last_snapshot_json'))
        self.manager.ai_security_plan()
        self.assertIsNone(self.manager.db.get_meta('ai_last_snapshot_json'))
        self.manager.ai_security_plan(persist_snapshot=True)
        self.assertIsNotNone(self.manager.db.get_meta('ai_last_snapshot_json'))

    def test_report_contains_ai_guardian_summary(self) -> None:
        self.manager.add_credential(
            title='GitHub', username='user', password='Pass!001', category='Work', tags='', notes='', website='github.com', is_favorite=False
        )
        report_path = Path(self.tmp.name) / 'report.txt'
        self.manager.export_report(report_path)
        report = report_path.read_text(encoding='utf-8')
        self.assertIn('AI Guardian Summary', report)
        self.assertIn('AI Guardian Action Plan', report)

    def test_ai_summary_export_logs_hide_absolute_paths(self) -> None:
        self.manager.add_credential(
            title='GitHub', username='user', password='Pass!001', category='Work', tags='', notes='', website='github.com', is_favorite=False
        )
        export_path = Path(self.tmp.name) / 'private' / 'ai-summary.txt'
        self.manager.export_ai_summary(export_path)
        summary = export_path.read_text(encoding='utf-8')
        self.assertIn('AI Guardian Security Plan', summary)
        logs = self.manager.get_logs()
        ai_logs = [row for row in logs if row['action'] == 'AI Summary Exported']
        self.assertTrue(ai_logs)
        self.assertIn('ai-summary.txt', ai_logs[0]['details'])
        self.assertNotIn(str(self.tmp.name), ai_logs[0]['details'])


    def test_demo_data_merges_when_user_already_has_credentials(self) -> None:
        self.manager.add_credential(
            title='Personal Test',
            username='tester@example.com',
            password='LocalOnly!Test123',
            category='General',
            tags='manual',
            notes='',
            website='personal.example',
            is_favorite=False,
        )
        stats1 = self.manager.load_demo_data()
        stats2 = self.manager.load_demo_data()
        active_titles = {item.title for item in self.manager.list_credentials()}
        trashed_titles = {item.title for item in self.manager.list_credentials(deleted_only=True)}
        self.assertGreaterEqual(stats1['created'], 8)
        self.assertEqual(stats2['created'], 0)
        self.assertIn('GitHub Admin Portal', active_titles)
        self.assertIn('Finance Portal', active_titles)
        self.assertIn('Retired VPN Access', trashed_titles)
        self.assertEqual(self.manager.get_setting('default_report_privacy_level', 'disabled'), 'analyst')

    def test_ui_module_imports(self) -> None:
        import app.ui
        self.assertTrue(hasattr(app.ui, 'run_app'))

    def test_composite_risk_elevates_reused_high_value_password(self) -> None:
        self.manager.add_credential(
            title='Primary Email', username='bavly@example.com', password='StrongUnique!Passphrase2026', category='Email', tags='primary', notes='', website='mail.example', is_favorite=False
        )
        self.manager.add_credential(
            title='Work Login', username='bavly@work.example', password='StrongUnique!Passphrase2026', category='Work', tags='work', notes='', website='work.example', is_favorite=False
        )
        findings = self.manager.security_findings()
        self.assertTrue(any(row['risk_level'] == 'Critical' and row['reuse_count'] > 1 for row in findings))

    def test_no_major_issues_placeholder_is_not_reported_as_issue(self) -> None:
        self.manager.add_credential(
            title='Healthy', username='healthy@example.com', password='N7!vBq#29LmZ@pR4sT6x', category='General', tags='unique', notes='', website='healthy.example', is_favorite=False
        )
        finding = self.manager.security_findings()[0]
        self.assertNotIn('No major issues detected.', finding['issues'])

    def test_privacy_safe_report_redacts_owner_title_and_username(self) -> None:
        self.manager.add_credential(
            title='Private GitHub', username='bavly@example.com', password='Pass!001', category='Work', tags='', notes='', website='github.com', is_favorite=False
        )
        report_path = Path(self.tmp.name) / 'privacy.txt'
        self.manager.export_privacy_safe_report(report_path)
        report = report_path.read_text(encoding='utf-8')
        self.assertIn('Privacy-safe mode: Enabled', report)
        self.assertIn('Credential #', report)
        self.assertNotIn('Private GitHub', report)
        self.assertNotIn('bavly@example.com', report)
        self.assertNotIn('Bavly Secure Vault', report)

    def test_backup_import_validation_rolls_back_replace_existing(self) -> None:
        cid = self.manager.add_credential(
            title='KeepMe', username='safe@example.com', password='Keep!Passphrase123', category='Work', tags='safe', notes='', website='keep.example', is_favorite=False
        )
        backup_path = Path(self.tmp.name) / 'bad.cvxbackup'
        self.manager.export_encrypted_backup(backup_path, 'Backup!Passphrase123')
        from app.crypto_utils import decrypt_backup_json, encrypt_backup_json

        encrypted = json.loads(backup_path.read_text(encoding='utf-8'))
        payload = decrypt_backup_json(encrypted, 'Backup!Passphrase123')
        del payload['credentials'][0]['title']
        backup_path.write_text(json.dumps(encrypt_backup_json(payload, 'Backup!Passphrase123')), encoding='utf-8')

        with self.assertRaises(ValueError):
            self.manager.import_encrypted_backup(backup_path, 'Backup!Passphrase123', replace_existing=True)

        self.assertIsNotNone(self.manager.get_credential(cid))
        self.assertEqual(self.manager.get_credential(cid).title, 'KeepMe')


    def test_backup_import_mid_transaction_rolls_back_replace_existing(self) -> None:
        cid = self.manager.add_credential(
            title='KeepMe', username='safe@example.com', password='Keep!Passphrase123',
            category='Work', tags='safe', notes='', website='keep.example', is_favorite=False
        )
        backup_path = Path(self.tmp.name) / 'bad-mid-transaction.cvxbackup'
        self.manager.export_encrypted_backup(backup_path, 'Backup!Passphrase123')
        from app.crypto_utils import decrypt_backup_json, encrypt_backup_json

        encrypted = json.loads(backup_path.read_text(encoding='utf-8'))
        payload = decrypt_backup_json(encrypted, 'Backup!Passphrase123')
        payload['credentials'].append({
            'id': 999,
            'title': 'Bad Row',
            'username': 'bad@example.com',
            'password': 'Bad!Passphrase123',
            'category': 'Work',
            'tags': '',
            'notes': '',
            'website': 'bad.example',
            'copy_count': 'not-an-integer',
        })
        backup_path.write_text(json.dumps(encrypt_backup_json(payload, 'Backup!Passphrase123')), encoding='utf-8')

        with self.assertRaises(ValueError):
            self.manager.import_encrypted_backup(backup_path, 'Backup!Passphrase123', replace_existing=True)

        restored = self.manager.get_credential(cid)
        self.assertIsNotNone(restored)
        self.assertEqual(restored.title, 'KeepMe')

    def test_ai_plan_includes_change_summary_and_fix_impact(self) -> None:
        self.manager.add_credential(
            title='Primary Email', username='bavly@example.com', password='qwerty12345', category='Email', tags='', notes='', website='mail.example', is_favorite=False
        )
        plan = self.manager.ai_security_plan()
        self.assertIn('change_summary', plan)
        self.assertIn('fix_impact', plan)
        self.assertGreaterEqual(plan['fix_impact']['projected_score'], plan['fix_impact']['current_score'])

    def test_schema_migration_v3_defaults_exist(self) -> None:
        self.assertGreaterEqual(self.manager.get_schema_version(), 3)
        self.assertEqual(self.manager.get_setting('privacy_report_level', 'missing'), 'minimal')
        self.assertEqual(self.manager.get_setting('safety_snapshot_format', 'missing'), 'CyberVaultSafetySnapshot/v1')

    def test_privacy_safe_report_levels(self) -> None:
        self.manager.add_credential(
            title='Private GitHub', username='bavly@example.com', password='Pass!001', category='Work', tags='', notes='', website='github.com', is_favorite=False
        )
        minimal_path = Path(self.tmp.name) / 'privacy-minimal.txt'
        standard_path = Path(self.tmp.name) / 'privacy-standard.txt'
        analyst_path = Path(self.tmp.name) / 'privacy-analyst.txt'

        self.manager.export_privacy_safe_report(minimal_path, level='minimal')
        self.manager.export_privacy_safe_report(standard_path, level='standard')
        self.manager.export_privacy_safe_report(analyst_path, level='analyst')

        minimal = minimal_path.read_text(encoding='utf-8')
        standard = standard_path.read_text(encoding='utf-8')
        analyst = analyst_path.read_text(encoding='utf-8')
        self.assertIn('Privacy level: minimal', minimal)
        self.assertIn('Privacy level: standard', standard)
        self.assertIn('Privacy level: analyst', analyst)
        self.assertNotIn('bavly@example.com', minimal + standard + analyst)
        self.assertNotIn('Private GitHub', minimal + standard + analyst)
        self.assertNotIn('github.com', minimal)

    def test_vault_snapshot_cache_reuses_analysis_and_invalidates_after_mutation(self) -> None:
        for idx in range(40):
            self.manager.add_credential(
                title=f'Account {idx}', username=f'user{idx}@example.com', password=f'Unique!Passphrase{idx:02d}',
                category='General', tags='bulk', notes='', website=f'site{idx}.example', is_favorite=False
            )
        first_snapshot = self.manager.vault_snapshot()
        self.assertEqual(first_snapshot.active_count, 40)
        self.manager.dashboard()
        self.manager.security_findings()
        self.assertIs(first_snapshot, self.manager.vault_snapshot())
        self.manager.add_credential(
            title='New Account', username='new@example.com', password='Another!StrongPass123',
            category='General', tags='bulk', notes='', website='new.example', is_favorite=False
        )
        self.assertIsNot(first_snapshot, self.manager.vault_snapshot())

    def test_permanent_delete_creates_safety_snapshot(self) -> None:
        cid = self.manager.add_credential(
            title='Delete Me', username='delete@example.com', password='Delete!Passphrase123', category='General', tags='', notes='', website='delete.example', is_favorite=False
        )
        self.manager.permanent_delete(cid)
        snapshots = list((self.db_path.parent / 'safety_snapshots').glob('*.cvxsnapshot'))
        self.assertTrue(snapshots)
        rendered = snapshots[0].read_text(encoding='utf-8')
        self.assertIn('CyberVaultSafetySnapshot/v1', rendered)
        self.assertNotIn('Delete!Passphrase123', rendered)

class PostureConsistencyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tmp.name) / 'vault.db'
        self.manager = VaultManager(self.db_path)
        self.manager.setup_master_password('Bavly', 'Strong!VaultPass123')

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_critical_weak_item_prevents_excellent_health_score(self) -> None:
        self.manager.add_credential(
            title='Healthy', username='healthy@example.com', password='N7!vBq#29LmZ@pR4sT6x', category='General', tags='unique', notes='', website='healthy.example', is_favorite=False
        )
        self.manager.add_credential(
            title='Weak', username='weak@example.com', password='fff', category='Social', tags='weak', notes='', website='weak.example', is_favorite=False
        )
        metrics = self.manager.dashboard()
        self.assertLess(metrics['health_score'], 85)
        self.assertEqual(metrics['weak'], 1)

    def test_ai_priority_queue_excludes_healthy_low_risk_records(self) -> None:
        self.manager.add_credential(
            title='Healthy Email', username='healthy@example.com', password='N7!vBq#29LmZ@pR4sT6x', category='Email', tags='primary', notes='', website='mail.example', is_favorite=False
        )
        plan = self.manager.ai_security_plan()
        self.assertEqual(plan['priority_items'], [])

    def test_html_report_does_not_emit_no_major_issues_as_finding(self) -> None:
        self.manager.add_credential(
            title='Healthy', username='healthy@example.com', password='N7!vBq#29LmZ@pR4sT6x', category='General', tags='unique', notes='', website='healthy.example', is_favorite=False
        )
        report_path = Path(self.tmp.name) / 'report.html'
        self.manager.export_report(report_path)
        report = report_path.read_text(encoding='utf-8')
        self.assertNotIn('No major issues.', report)
        self.assertIn('No actionable security findings', report)

if __name__ == '__main__':
    unittest.main()
