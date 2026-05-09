from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from app import crypto_utils
from app.ai.security_coach import build_local_security_coach
from app.analyzer import analyze_password
from app.manager import VaultManager

crypto_utils.MIN_BACKUP_KDF_ITERATIONS = 2
crypto_utils.PBKDF2_ITERATIONS = 2


class SecurityReleaseFixesTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tmp.name) / 'vault.db'
        self.manager = VaultManager(self.db_path)
        self.manager.setup_master_password('Bavly', 'Strong!VaultPass123')

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_predictable_passwords_are_capped_below_excellent(self) -> None:
        cases = [
            ('Qwerty2026!!', '', 45),
            ('Summer2026!!', '', 50),
            ('Password2026!', '', 45),
            ('CompanyName2026!', 'CompanyName admin portal', 55),
        ]
        for password, context, expected_cap in cases:
            with self.subTest(password=password):
                analysis = analyze_password(password, context=context)
                self.assertNotEqual(analysis.label, 'Excellent')
                self.assertLessEqual(analysis.score, expected_cap)
                self.assertTrue(analysis.patterns)
                self.assertIsNotNone(analysis.score_cap)
                self.assertIn('Pattern-adjusted effective entropy', analysis.entropy_note)

    def test_random_password_remains_excellent_and_dictionary_phrase_is_downgraded(self) -> None:
        random_analysis = analyze_password('bN7!qzP4@Lw9#sT2')
        self.assertEqual(random_analysis.label, 'Excellent')
        self.assertGreaterEqual(random_analysis.score, 85)
        self.assertFalse(random_analysis.patterns)

        phrase_analysis = analyze_password('CorrectHorseBatteryStaple')
        self.assertNotEqual(phrase_analysis.label, 'Excellent')
        self.assertIn('Dictionary words', phrase_analysis.patterns)
        self.assertIn('multi-word dictionary passphrase', phrase_analysis.score_cap_reason)

    def test_local_security_coach_discloses_deterministic_heuristic_mode(self) -> None:
        self.manager.add_credential(
            title='Weak Admin', username='admin@example.com', password='Qwerty2026!!',
            category='Work', tags='admin', notes='', website='admin.example', is_favorite=True,
        )
        coach = build_local_security_coach(self.manager)
        rendered = json.dumps(coach, ensure_ascii=False)
        self.assertEqual(coach['mode'], 'local-deterministic')
        self.assertIn('heuristic policy confidence', rendered)
        self.assertIn('No external LLM or cloud AI is used.', rendered)
        self.assertIn('Recommendations are evidence-bound', rendered)

    def test_demo_credentials_are_not_in_production_backup_service(self) -> None:
        backup_source = Path('app/services/backup.py').read_text(encoding='utf-8')
        for forbidden in ('password123', 'Password1', '123456', 'Backup2020!'):
            self.assertNotIn(forbidden, backup_source)
        self.assertIn('assessment_workspace_records', backup_source)

    def test_merge_backup_import_creates_safety_snapshot(self) -> None:
        self.manager.add_credential(
            title='Source', username='source@example.com', password='Src!Passphrase123',
            category='Work', tags='src', notes='', website='source.example', is_favorite=False,
        )
        backup_path = Path(self.tmp.name) / 'source.cvxbackup'
        self.manager.export_encrypted_backup(backup_path, 'Backup!Passphrase123')

        target = VaultManager(Path(self.tmp.name) / 'target.db')
        target.setup_master_password('Target', 'Strong!VaultPass123')
        target.add_credential(
            title='Existing', username='existing@example.com', password='Existing!Passphrase123',
            category='Work', tags='existing', notes='', website='existing.example', is_favorite=False,
        )
        stats = target.import_encrypted_backup(backup_path, 'Backup!Passphrase123', replace_existing=False)
        self.assertEqual(stats['imported'], 1)
        snapshots = list((Path(self.tmp.name) / 'safety_snapshots').glob('*.cvxsnapshot'))
        self.assertTrue(snapshots)
        rendered = snapshots[0].read_text(encoding='utf-8')
        self.assertIn('CyberVaultSafetySnapshot/v1', rendered)
        self.assertNotIn('Existing!Passphrase123', rendered)

    def test_audit_export_redacts_arbitrary_paths_emails_tokens_and_domains(self) -> None:
        self.manager.add_credential(
            title='Private Admin', username='admin@example.com', password='NeverLeak!12345',
            category='Work', tags='admin', notes='private note', website='admin.example.com', is_favorite=True,
        )
        self.manager.set_setting('privacy_mode_logs', '0')
        self.manager.add_log(
            'Synthetic Leak',
            r'C:\Users\Bavly\vault\file.txt admin@example.com api_key=SECRET1234567890 clipboard=ClipSecret! admin.example.com NeverLeak!12345 private note',
            'warning',
        )
        out = Path(self.tmp.name) / 'audit.txt'
        self.manager.export_audit_log(out, privacy_level='minimal')
        rendered = out.read_text(encoding='utf-8')
        for forbidden in (
            r'C:\Users\Bavly\vault\file.txt', 'admin@example.com', 'SECRET1234567890',
            'ClipSecret!', 'admin.example.com', 'NeverLeak!12345', 'private note',
        ):
            self.assertNotIn(forbidden, rendered)
        self.assertIn('[local-path]', rendered)
        self.assertIn('[redacted-value]', rendered)


if __name__ == '__main__':
    unittest.main()
