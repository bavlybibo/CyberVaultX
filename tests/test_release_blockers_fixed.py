from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from app import crypto_utils
from app.manager import VaultManager
from app.services.backup import BackupImportError
from app.ui_controllers import ControllersMixin

crypto_utils.MIN_BACKUP_KDF_ITERATIONS = 2
crypto_utils.PBKDF2_ITERATIONS = 2


class ReleaseBlockerFixesTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tmp.name) / 'vault.db'
        self.manager = VaultManager(self.db_path)
        self.manager.setup_master_password('Bavly', 'Strong!VaultPass123')

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_audit_export_redacts_partial_notes_paths_tokens_and_emails(self) -> None:
        self.manager.add_credential(
            title='Private Admin', username='admin@example.com', password='NeverLeak!12345',
            category='Work', tags='admin', notes='private note for payroll recovery', website='admin.example.com', is_favorite=True,
        )
        self.manager.set_setting('privacy_mode_logs', '0')
        slash = chr(92)
        win_path = 'C:' + slash + 'Users' + slash + 'Bavly' + slash + 'vault' + slash + 'file.txt'
        posix_path = '/' + 'home' + '/bavly/vault.txt'
        self.manager.add_log(
            'Synthetic Leak admin@example.com',
            f'{win_path} {posix_path} username=admin api_key=SECRET1234567890 '
            'clipboard=ClipSecret! admin.example.com NeverLeak!12345 private note token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTYifQ.signaturePart',
            'warning',
        )
        out = Path(self.tmp.name) / 'audit.json'
        self.manager.export_audit_log(out, privacy_level='minimal')
        rendered = out.read_text(encoding='utf-8')
        for forbidden in (
            win_path, posix_path, 'admin@example.com', 'admin.example.com',
            'SECRET1234567890', 'ClipSecret!', 'NeverLeak!12345', 'private note', 'eyJhbGciOiJIUzI1NiJ9',
        ):
            self.assertNotIn(forbidden, rendered)
        self.assertIn('structured safe audit events', rendered)
        self.assertIn('redaction_status', rendered)
        self.assertIn('[local-path]', rendered)
        self.assertIn('[redacted-value]', rendered)

    def test_evidence_package_redacts_partial_notes_and_arbitrary_audit_details(self) -> None:
        self.manager.add_credential(
            title='Finance Root', username='finance.root@example.com', password='Finance!Secret12345',
            category='Banking', tags='finance', notes='private note for wire approvals', website='finance.example.com', is_favorite=True,
        )
        self.manager.set_setting('privacy_mode_logs', '0')
        slash = chr(92)
        win_path = 'C:' + slash + 'Users' + slash + 'Bavly' + slash + 'Desktop' + slash + 'vault.db'
        self.manager.add_log(
            'Evidence Leak',
            f'{win_path} finance.root@example.com session_id=SESSION123456 private note Finance!Secret12345 finance.example.com',
            'warning',
        )
        evidence_dir = Path(self.tmp.name) / 'evidence'
        self.manager.export_security_evidence_package(evidence_dir)
        combined = '\n'.join(path.read_text(encoding='utf-8', errors='ignore') for path in evidence_dir.iterdir() if path.is_file())
        for forbidden in (
            win_path, 'finance.root@example.com', 'SESSION123456',
            'private note', 'Finance!Secret12345', 'finance.example.com', 'Finance Root',
        ):
            self.assertNotIn(forbidden, combined)
        self.assertIn('redaction_status', combined)

    def test_full_report_service_layer_rejects_bypass_and_allows_verified_flow(self) -> None:
        self.manager.add_credential(
            title='Full Export Target', username='full@example.com', password='Full!Secret12345',
            category='Work', tags='', notes='', website='full.example.com', is_favorite=False,
        )
        report = Path(self.tmp.name) / 'full.html'
        with self.assertRaises(PermissionError):
            self.manager.export_report(report, privacy_safe=False)
        with self.assertRaises(PermissionError):
            self.manager.export_report(
                report, privacy_safe=False, full_export_ack=True,
                warning_version=self.manager.FULL_REPORT_WARNING_VERSION,
            )
        token = self.manager.issue_full_export_reauth_token('Strong!VaultPass123')
        self.manager.export_report(
            report,
            privacy_safe=False,
            full_export_ack=True,
            reauth_token=token,
            warning_version=self.manager.FULL_REPORT_WARNING_VERSION,
        )
        self.assertTrue(report.exists())
        actions = [row['action'] for row in self.manager.get_logs(limit=20)]
        self.assertIn('FULL_REPORT_EXPORT_APPROVED', actions)

    def _make_backup(self) -> Path:
        source_db = Path(self.tmp.name) / 'source.db'
        source = VaultManager(source_db)
        source.setup_master_password('Bavly', 'Strong!VaultPass123')
        source.add_credential(
            title='Imported', username='import@example.com', password='Import!Secret12345',
            category='Work', tags='', notes='', website='import.example.com', is_favorite=False,
        )
        backup = Path(self.tmp.name) / 'source.cvxbackup'
        source.export_encrypted_backup(backup, 'Backup!Passphrase123')
        return backup

    def test_merge_import_aborts_when_safety_snapshot_fails(self) -> None:
        backup = self._make_backup()
        self.manager.add_credential(
            title='Existing', username='existing@example.com', password='Existing!Secret12345',
            category='Work', tags='', notes='', website='existing.example.com', is_favorite=False,
        )
        before = [item.title for item in self.manager.list_credentials()]
        self.manager.create_safety_snapshot = lambda *args, **kwargs: None  # type: ignore[method-assign]
        with self.assertRaises(BackupImportError):
            self.manager.import_encrypted_backup(backup, 'Backup!Passphrase123', replace_existing=False)
        after = [item.title for item in self.manager.list_credentials()]
        self.assertEqual(before, after)
        self.assertTrue(any(row['action'] == 'BACKUP_IMPORT_ABORTED_SNAPSHOT_FAILED' for row in self.manager.get_logs()))

    def test_replace_import_aborts_when_safety_snapshot_fails(self) -> None:
        backup = self._make_backup()
        self.manager.add_credential(
            title='Existing', username='existing@example.com', password='Existing!Secret12345',
            category='Work', tags='', notes='', website='existing.example.com', is_favorite=False,
        )
        before = [item.title for item in self.manager.list_credentials()]
        self.manager.create_safety_snapshot = lambda *args, **kwargs: None  # type: ignore[method-assign]
        with self.assertRaises(BackupImportError):
            self.manager.import_encrypted_backup(backup, 'Backup!Passphrase123', replace_existing=True)
        after = [item.title for item in self.manager.list_credentials()]
        self.assertEqual(before, after)
        self.assertTrue(any(row['action'] == 'BACKUP_IMPORT_ABORTED_SNAPSHOT_FAILED' for row in self.manager.get_logs()))

    def test_clipboard_clear_failure_is_visible_and_audited(self) -> None:
        class DummyController(ControllersMixin):
            def __init__(self, manager: VaultManager) -> None:
                self.manager = manager
                self._clipboard_owned_value = 'ClipSecret!'
                self.status_messages: list[tuple[str, str]] = []
                self.toasts: list[tuple[str, str, str]] = []
            def clipboard_get(self):
                raise RuntimeError('clipboard unavailable')
            def _set_status(self, message: str, level: str = 'info', toast: bool = True):
                self.status_messages.append((level, message))
            def _show_toast(self, title: str, message: str, kind: str = 'info', parent=None):
                self.toasts.append((title, message, kind))

        dummy = DummyController(self.manager)
        ControllersMixin._clear_clipboard_contents(dummy)
        self.assertTrue(any('Clipboard clear failed' in msg for _level, msg in dummy.status_messages))
        self.assertTrue(any(row['action'] == 'Clipboard Clear Failed' for row in self.manager.get_logs()))


if __name__ == '__main__':
    unittest.main()
