from __future__ import annotations

import csv
import json
import secrets
import string
import threading
import urllib.request
import webbrowser
from datetime import datetime, timedelta, timezone
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, ttk

from .analyzer import analyze_password, normalize_site, password_is_old
from .breach_db import breach_db_size
from .manager import Credential, VaultManager
from .ui_helpers import normalize_http_url, safe_cache_name, safe_favicon_host
from .ui_shared import *
from .site_policy import build_password_coach_state, evaluate_password_fit, format_policy_fit_lines, infer_account_policy

class ControllersMixin:
    def save_settings(self) -> None:
        previous_favicon = self.manager.get_setting('favicon_lookup_enabled', '0').strip().lower() in {'1', 'true', 'yes', 'on'}
        enabling_favicon = self.favicon_lookup_var.get() and not previous_favicon
        if enabling_favicon:
            approved = messagebox.askyesno(
                'Privacy trade-off',
                'Online favicon lookup can reveal saved website domains to a third-party favicon service.\n\n'
                'CyberVault will still block lookup for high-sensitivity categories and fall back to local monograms. Enable it?',
                parent=self,
            )
            if not approved:
                self.favicon_lookup_var.set(False)

        self.manager.set_setting_int('auto_lock_minutes', int(self.auto_lock_var.get()))
        self.manager.set_setting_int('clipboard_clear_seconds', int(self.clipboard_clear_var.get()))
        self.manager.set_setting('theme_accent', self.theme_var.get())
        self.manager.set_setting('favicon_lookup_enabled', '1' if self.favicon_lookup_var.get() else '0')
        self.manager.set_setting('privacy_mode_logs', '1' if self.privacy_logs_var.get() else '0')
        if hasattr(self, 'report_privacy_default_var'):
            self.manager.set_setting('default_report_privacy_level', self.report_privacy_default_var.get())
        self._apply_theme(self.theme_var.get())
        self.refresh_all()
        self._set_status('Settings saved.', level='success')

    def reset_settings_defaults(self) -> None:
        self.auto_lock_var.set(3)
        self.clipboard_clear_var.set(15)
        self.theme_var.set('Cyan')
        self.favicon_lookup_var.set(False)
        self.privacy_logs_var.set(True)
        if hasattr(self, 'report_privacy_default_var'):
            self.report_privacy_default_var.set('analyst')
        self._apply_theme('Cyan')
        self.refresh_all()
        self._set_status('Settings reset to defaults. Save to keep them.', level='info')

    def _update_settings_previews(self, _value=None) -> None:
        self.auto_lock_preview_var.set(f'Auto-lock after inactivity: {int(self.auto_lock_var.get())} minute(s)')
        self.clipboard_preview_var.set(f'Clipboard auto-clear: {int(self.clipboard_clear_var.get())} second(s)')

    def _set_theme_preview(self, accent_name: str) -> None:
        self.theme_var.set(accent_name)
        self._apply_theme(accent_name)

    def _set_threat_filter(self, value: str) -> None:
        self.threat_filter_var.set(value)
        self._refresh_filter_chips()
        self.refresh_all()

    def _activity_bucket(self, action: str) -> str:
        lowered = action.lower()
        if any(token in lowered for token in ('unlock', 'lock', 'auth', 'panic')):
            return 'Authentication'
        if any(token in lowered for token in ('copied', 'revealed', 'trash', 'delete', 'restore')):
            return 'Sensitive'
        if any(token in lowered for token in ('export', 'import', 'backup', 'report')):
            return 'Exports'
        return 'System'

    def clear_editor(self) -> None:
        self.selected_id = None
        self.title_var.set('')
        self.username_var.set('')
        self.password_var.set('')
        self.category_var.set('General')
        self.tags_var.set('')
        self.website_var.set('')
        self.favorite_var.set(False)
        self.notes_text.delete('1.0', 'end')
        self.created_var.set('Created: -')
        self.updated_var.set('Updated: -')
        self.copy_stats_var.set('Copies: 0 | Reveals: 0')
        self.site_host_var.set('No site selected')
        self._draw_site_badge('--')
        self.site_image_label.configure(image='')
        self.current_favicon_image = None
        self._set_history([])
        self._render_credential_badges(None)
        self.update_analysis_panel()
        self.show_view('vault')

    def _maybe_handle_duplicate(self, payload: dict, *, parent=None) -> tuple[str, int | None]:
        """Return (action, credential_id). action is add/update/cancel."""
        matches = self.manager.find_duplicate_credentials(
            title=payload.get('title', ''),
            username=payload.get('username', ''),
            website=payload.get('website', ''),
            exclude_id=self.selected_id,
        )
        if not matches:
            return 'add', None
        first = matches[0]
        answer = messagebox.askyesnocancel(
            'Possible Duplicate',
            f"A similar credential already exists: #{first.id} ({first.title}).\n\n"
            'Yes = update the existing credential\nNo = save as a new credential\nCancel = stop',
            parent=parent or self,
        )
        if answer is None:
            return 'cancel', None
        if answer:
            return 'update', first.id
        return 'add', None

    def save_credential(self) -> None:
        try:
            payload = self._editor_payload()
            if self.selected_id is None:
                action, target_id = self._maybe_handle_duplicate(payload)
                if action == 'cancel':
                    self._set_status('Save cancelled after duplicate check.', level='info')
                    return
                if action == 'update' and target_id is not None:
                    self.manager.update_credential(target_id, **payload)
                    self.selected_id = target_id
                    self._set_status('Existing duplicate credential updated.', level='success')
                else:
                    new_id = self.manager.add_credential(**payload)
                    self.selected_id = new_id
                    self._set_status('Credential saved.', level='success')
            else:
                self.manager.update_credential(self.selected_id, **payload)
                self._set_status('Credential updated.', level='success')
            self.refresh_all(select_id=self.selected_id)
        except Exception as exc:
            self._show_toast('Save Error', str(exc), kind='danger')

    def move_selected_to_trash(self) -> None:
        if self.selected_id is None:
            return
        if not self._confirm_action('Move to Trash', 'Move this credential to Trash?', kind='warning'):
            return
        self.manager.move_to_trash(self.selected_id)
        self.selected_id = None
        self.clear_editor()
        self.refresh_all()
        self._set_status('Moved to Trash.', level='warning')

    def restore_trash_item(self) -> None:
        if self.selected_trash_id is None:
            return
        self.manager.restore_from_trash(self.selected_trash_id)
        self.refresh_all(select_id=self.selected_trash_id)
        self._set_status('Credential restored from Trash.', level='success')

    def delete_trash_item_forever(self) -> None:
        if self.selected_trash_id is None:
            return
        if not self._confirm_action('Delete Forever', 'This permanently deletes the item and its password history. Continue?', kind='danger'):
            return
        self.manager.permanent_delete(self.selected_trash_id)
        self.selected_trash_id = None
        self.refresh_all()
        self._set_status('Item permanently deleted.', level='danger')

    def purge_trash(self) -> None:
        purged = self.manager.purge_expired_trash()
        self.refresh_all()
        self._set_status(f'Purged {purged} expired trash item(s).', level='warning')

    def _selected_ai_priority_values(self) -> tuple[str, str] | None:
        if not hasattr(self, 'ai_priority_tree'):
            return None
        selection = self.ai_priority_tree.selection()
        if not selection:
            self._set_status('Select an AI Guardian priority item first.', level='warning')
            return None
        values = self.ai_priority_tree.item(selection[0], 'values')
        if not values:
            self._set_status('Selected AI priority is empty.', level='warning')
            return None
        credential_ref = str(values[0])
        action = str(values[6]) if len(values) > 6 else 'Marked AI Guardian recommendation as completed'
        return credential_ref, action

    def mark_ai_priority_fixed(self) -> None:
        selected = self._selected_ai_priority_values()
        if not selected:
            return
        credential_ref, action = selected
        result = self.manager.mark_ai_remediation_complete(credential_ref, action)
        self.refresh_all()
        self._set_status(f"AI remediation tracked. Completed actions: {result['completed_count']}.", level='success')

    def clear_ai_remediation_progress(self) -> None:
        if not self._confirm_action('Clear AI Remediation Progress', 'This only clears the remediation progress tracker; it does not change credentials. Continue?', kind='warning'):
            return
        self.manager.clear_ai_remediation_log()
        self.refresh_all()
        self._set_status('AI Guardian remediation progress cleared.', level='warning')

    def generate_replacement_for_priority(self) -> None:
        selected = self._selected_ai_priority_values()
        if not selected:
            return
        self.generator_length_var.set(max(20, int(self.generator_length_var.get() or 20)))
        self.generator_use_case_var.set('Recovery')
        self.generate_password()
        self.show_view('generator')
        self._set_status('Generated a high-security replacement password for the selected priority item.', level='success')

    def generate_ai_security_plan(self) -> None:
        self._refresh_ai_guardian(persist_snapshot=True)
        self.manager.add_log('AI Guardian Plan Generated', 'Generated local privacy-preserving security plan.', 'success')
        self._set_status('AI Guardian smart security plan generated locally.', level='success')

    def export_ai_summary(self) -> None:
        path = filedialog.asksaveasfilename(
            parent=self,
            defaultextension='.txt',
            filetypes=[('AI Guardian summary', '*.txt')],
            initialfile='cybervault_ai_guardian_summary.txt',
        )
        if not path:
            return
        self.manager.export_ai_summary(path)
        self.refresh_all()
        self._set_status('AI Guardian summary exported.', level='success')

    def _choose_report_privacy(self, *, privacy_only: bool = False) -> tuple[bool, str] | None:
        result: dict[str, tuple[bool, str] | None] = {'value': None}
        dialog = tk.Toplevel(self)
        dialog.title('Report Export Preview')
        dialog.geometry('640x560')
        dialog.minsize(560, 480)
        dialog.configure(bg=APP_BG)
        dialog.transient(self)
        dialog.grab_set()
        self._center_window(dialog, 640, 560)
        shell = tk.Frame(dialog, bg=APP_BG, padx=18, pady=18)
        shell.pack(fill='both', expand=True)
        card = self._card(shell, bg=CARD_BG, padx=18, pady=18)
        card.pack(fill='both', expand=True)
        ci = card.inner
        self._label(ci, 'Report Export Preview', bg=ci.cget('bg'), font=('Segoe UI Semibold', 14)).pack(anchor='w')
        self._label(ci, 'Choose the report type, privacy level, and confirm exactly what will be included before any file is written.', fg=SUBTEXT, bg=ci.cget('bg'), wraplength=560).pack(anchor='w', pady=(6, 14))
        choice = tk.StringVar(value='minimal' if privacy_only else self.manager.get_setting('default_report_privacy_level', 'analyst'))
        options = [] if privacy_only else [('full', 'Full report — owner, titles, usernames, and normal analyst detail')]
        options.extend([
            ('analyst', 'Analyst redacted — masked usernames, useful technical context'),
            ('standard', 'Standard redacted — masked usernames, no websites/domains'),
            ('minimal', 'Minimal safe — credential references only, no usernames or domains'),
        ])
        preview_var = tk.StringVar()

        def update_preview() -> None:
            value = choice.get()
            if value == 'full':
                preview_var.set(
                    'Type: Executive full report\n'
                    'Includes: health score, finding table, security recommendations, audit summary, readable owner/title/username/domain metadata.\n'
                    'Best for: private live walkthrough on your own sample vault.'
                )
            elif value == 'analyst':
                preview_var.set(
                    'Type: Analyst redacted report\n'
                    'Includes: useful technical context, masked usernames, domains where helpful, risk drivers, and remediation actions.\n'
                    'Best for: internal security review and team handoff.'
                )
            elif value == 'standard':
                preview_var.set(
                    'Type: Standard redacted report\n'
                    'Includes: findings, scores, recommendations, and proof summary with usernames and websites removed.\n'
                    'Best for: sharing outside the team.'
                )
            else:
                preview_var.set(
                    'Type: Minimal privacy-safe report\n'
                    'Includes: aggregate posture, anonymized credential references, recommendations, and no usernames or domains.\n'
                    'Best for: screenshots, public walkthroughs, or LMS uploads.'
                )

        for value, text in options:
            ttk.Radiobutton(ci, text=text, value=value, variable=choice, command=update_preview).pack(anchor='w', pady=4)
        preview = tk.Frame(ci, bg=CARD_BG_2, padx=12, pady=12, highlightthickness=1, highlightbackground=BORDER)
        preview.pack(fill='x', pady=(12, 0))
        self._label(preview, 'Preview', bg=preview.cget('bg'), font=('Segoe UI Semibold', 11)).pack(anchor='w')
        self._label(preview, textvariable=preview_var, fg=SUBTEXT, bg=preview.cget('bg'), wraplength=540, font=('Segoe UI', 9)).pack(anchor='w', pady=(6, 0))
        update_preview()
        btns = tk.Frame(ci, bg=ci.cget('bg'))
        btns.pack(fill='x', pady=(18, 0))
        def accept() -> None:
            value = choice.get()
            result['value'] = (value != 'full', 'minimal' if value == 'full' else value)
            dialog.destroy()
        ttk.Button(btns, text='Cancel', command=dialog.destroy, style='Ghost.TButton').pack(side='right')
        ttk.Button(btns, text='Continue Export', command=accept, style='Accent.TButton').pack(side='right', padx=(0, 8))
        self.wait_window(dialog)
        return result['value']

    def export_report(self) -> None:
        privacy = self._choose_report_privacy()
        if privacy is None:
            return
        privacy_safe, privacy_level = privacy
        suffix_name = 'privacy_safe' if privacy_safe else 'executive_security'
        path = filedialog.asksaveasfilename(parent=self, defaultextension='.html', filetypes=[('Executive HTML report', '*.html'), ('JSON report', '*.json'), ('Text report', '*.txt')], initialfile=f'cybervault_{suffix_name}_report.html')
        if not path:
            return
        self._set_status('Exporting report preview selection...', level='info')
        self.update_idletasks()
        self.manager.export_report(path, privacy_safe=privacy_safe, privacy_level=privacy_level)
        self.refresh_all()
        self._set_status(f'Executive security report exported ({"privacy-safe " + privacy_level if privacy_safe else "full"}).', level='success')

    def export_privacy_safe_report(self) -> None:
        privacy = self._choose_report_privacy(privacy_only=True)
        if privacy is None:
            return
        _privacy_safe, privacy_level = privacy
        path = filedialog.asksaveasfilename(parent=self, defaultextension='.html', filetypes=[('Privacy-safe HTML report', '*.html'), ('JSON report', '*.json'), ('Text report', '*.txt')], initialfile=f'cybervault_privacy_safe_{privacy_level}_report.html')
        if not path:
            return
        self._set_status('Exporting privacy-safe report...', level='info')
        self.update_idletasks()
        self.manager.export_privacy_safe_report(path, level=privacy_level)
        self.refresh_all()
        self._set_status(f'Privacy-safe security report exported ({privacy_level}).', level='success')

    def import_csv(self) -> None:
        path = filedialog.askopenfilename(parent=self, filetypes=[('CSV files', '*.csv'), ('All files', '*.*')])
        if not path:
            return
        self._set_status('Reading CSV and opening import wizard...', level='info')
        self.update_idletasks()
        try:
            with open(path, 'r', encoding='utf-8-sig', newline='') as fh:
                reader = csv.DictReader(fh)
                rows = list(reader)
        except Exception as exc:
            self._show_toast('CSV Import Failed', str(exc), kind='danger')
            return
        if not rows or not reader.fieldnames:
            self._show_toast('CSV Import Failed', 'No readable CSV rows were found.', kind='danger')
            return
        self._open_import_wizard(path, rows, list(reader.fieldnames))

    def export_report_package(self) -> None:
        privacy = self._choose_report_privacy(privacy_only=True)
        if privacy is None:
            return
        _privacy_safe, privacy_level = privacy
        directory = filedialog.askdirectory(parent=self, title='Choose folder for CyberVault report package')
        if not directory:
            return
        self._set_status('Building signed report package...', level='info')
        self.update_idletasks()
        try:
            self.manager.export_report_package(directory, privacy_level=privacy_level)
        except Exception as exc:
            self._show_toast('Report Package Failed', str(exc), kind='danger')
            return
        self.refresh_all()
        self._set_status('Report package exported with manifest hashes and local manifest signature.', level='success')

    def purge_old_activity_logs(self) -> None:
        days = self.manager.get_setting_int('activity_retention_days', 365)
        if not self._confirm_action('Purge Old Activity Logs', f'This removes audit events older than {days} day(s). Continue?', kind='warning'):
            return
        deleted = self.manager.purge_old_activity_logs(days)
        self.refresh_all()
        self._set_status(f'Purged {deleted} old audit event(s).', level='warning' if deleted else 'info')

    def export_audit_log(self) -> None:
        privacy = self._choose_report_privacy(privacy_only=True)
        if privacy is None:
            return
        _privacy_safe, privacy_level = privacy
        path = filedialog.asksaveasfilename(parent=self, defaultextension='.html', filetypes=[('Audit HTML report', '*.html'), ('Text log', '*.txt')], initialfile=f'cybervault_audit_log_{privacy_level}.html')
        if not path:
            return
        try:
            self.manager.export_audit_log(path, privacy_level=privacy_level)
        except Exception as exc:
            self._show_toast('Audit Export Failed', str(exc), kind='danger')
            return
        self.refresh_all()
        self._set_status('Audit activity exported.', level='success')

    def _format_backup_preview(self, preview: dict[str, object]) -> str:
        categories = preview.get('categories', {})
        if isinstance(categories, dict) and categories:
            category_line = ', '.join(f"{k}: {v}" for k, v in categories.items())
        else:
            category_line = 'None'
        warnings = preview.get('warnings', [])
        warning_lines = '\n'.join(f"- {item}" for item in warnings) if isinstance(warnings, list) and warnings else '- No preview warnings.'
        setting_changes = preview.get('setting_changes', {})
        settings_line = ', '.join(setting_changes.keys()) if isinstance(setting_changes, dict) and setting_changes else 'None'
        diff_summary = preview.get('diff_summary', {})
        if isinstance(diff_summary, dict) and diff_summary:
            diff_line = (
                f"Will add: {diff_summary.get('will_add_on_merge', 0)} | "
                f"Will skip duplicates: {diff_summary.get('will_skip_duplicates_on_merge', 0)} | "
                f"Will update: {diff_summary.get('will_update_on_merge', 0)} | "
                f"Risk: {diff_summary.get('risk', 'Safe')}"
            )
        else:
            diff_line = 'Not available'
        diff_preview = preview.get('diff_preview', [])
        if isinstance(diff_preview, list) and diff_preview:
            diff_rows = '\n'.join(
                f"- {item.get('item', 'Row')}: {item.get('action', '-')}; {item.get('reason', '')}"
                for item in diff_preview[:8] if isinstance(item, dict)
            )
        else:
            diff_rows = '- No row-level diff preview available.'
        return (
            f"Backup path: {preview.get('path', '')}\n"
            f"Format: {preview.get('format', 'unknown')} | Exported: {preview.get('exported_at', '-')}\n\n"
            f"Rows: {preview.get('total_rows', 0)} total | {preview.get('active_rows', 0)} active | {preview.get('deleted_rows', 0)} deleted\n"
            f"Duplicates in current vault: {preview.get('duplicates_in_current_vault', 0)}\n"
            f"Merge would add: {preview.get('merge_would_add', 0)}\n"
            f"Replace would remove current rows: {preview.get('replace_would_remove_current', 0)}\n"
            f"High-value rows: {preview.get('high_value_rows', 0)}\n"
            f"Missing metadata rows: {preview.get('missing_metadata_rows', 0)}\n"
            f"Recommended mode: {preview.get('recommended_mode', 'merge')}\n"
            f"Diff summary: {diff_line}\n"
            f"Setting changes: {settings_line}\n"
            f"Categories: {category_line}\n\n"
            f"Row-level preview:\n{diff_rows}\n\n"
            f"Warnings:\n{warning_lines}"
        )

    def run_security_proof_center(self) -> None:
        try:
            proof = self.manager.security_proof_center()
        except Exception as exc:
            self._show_toast('Proof Center Failed', str(exc), kind='danger')
            return
        lines = [
            f"Generated: {proof.get('generated_at', '-')}",
            f"Overall status: {proof.get('overall_status', 'REVIEW')} ({proof.get('passed', 0)}/{proof.get('total', 0)} passed)",
            '',
            'Checks',
        ]
        for item in proof.get('checks', []):
            status = 'PASS' if item.get('status') else 'REVIEW'
            lines.append(f"[{status}] {item.get('name')}")
            lines.append(f"  {item.get('details')}")
        chain = proof.get('audit_chain', {})
        lines.extend([
            '',
            'Audit Chain',
            f"Valid: {chain.get('valid')}",
            f"Events checked: {chain.get('events_checked')}",
            f"Head hash: {chain.get('head_hash')}",
        ])
        if chain.get('first_invalid'):
            lines.append(f"First invalid: {json.dumps(chain.get('first_invalid'), ensure_ascii=False)}")
        self.proof_status_var.set(f"Proof Center: {proof.get('overall_status', 'REVIEW')} — {proof.get('passed', 0)}/{proof.get('total', 0)} checks passed.")
        if hasattr(self, 'proof_text'):
            self._set_text(self.proof_text, '\n'.join(lines))
        self._set_status('Security Proof Center checks completed.', level='success' if proof.get('overall_status') == 'PASS' else 'warning')

    def verify_report_package_ui(self) -> None:
        directory = filedialog.askdirectory(parent=self, title='Select CyberVault report package folder')
        if not directory:
            return
        try:
            result = self.manager.verify_report_package(directory)
        except Exception as exc:
            self._show_toast('Package Verification Failed', str(exc), kind='danger')
            return
        lines = [
            f"Verified: {result.get('verified_at', '-')}",
            f"Directory: {result.get('directory', '')}",
            f"Status: {'VALID' if result.get('valid') else 'REVIEW REQUIRED'}",
            f"Package hash valid: {result.get('package_hash_valid')}",
            f"Signature present: {result.get('signature_present')}",
            f"Signature checked: {result.get('signature_checked')}",
            f"Signature valid: {result.get('signature_valid')}",
            f"Signing fingerprint match: {result.get('signature_fingerprint_match')}",
            f"Files checked: {result.get('files_checked', 0)}",
            '',
            'Files',
        ]
        for item in result.get('files', []):
            status = 'PASS' if item.get('valid') else 'FAIL'
            lines.append(f"[{status}] {item.get('name')} — {item.get('reason')}")
            lines.append(f"  expected {str(item.get('expected_sha256', ''))[:16]}... | actual {str(item.get('actual_sha256', ''))[:16]}...")
        self.package_verify_var.set('Report package is valid.' if result.get('valid') else 'Report package needs review.')
        if hasattr(self, 'package_verify_text'):
            self._set_text(self.package_verify_text, '\n'.join(lines))
        self.refresh_all()
        self._set_status('Report package verification completed.', level='success' if result.get('valid') else 'warning')

    def preview_backup_restore_ui(self) -> None:
        path = filedialog.askopenfilename(parent=self, filetypes=[('CyberVault Backup', '*.cvxbackup'), ('All files', '*.*')])
        if not path:
            return
        passphrase = simpledialog.askstring('Backup Passphrase', 'Enter the backup passphrase used during export:', parent=self, show='*')
        if passphrase is None:
            return
        try:
            preview = self.manager.preview_encrypted_backup(path, passphrase)
        except Exception as exc:
            self._show_toast('Backup Preview Failed', str(exc), kind='danger')
            return
        rendered = self._format_backup_preview(preview)
        self.backup_preview_var.set(
            f"Backup preview: {preview.get('total_rows', 0)} row(s), {preview.get('duplicates_in_current_vault', 0)} duplicate(s), recommended {preview.get('recommended_mode', 'merge')}."
        )
        for attr in ('backup_preview_text', 'backup_preview_text_proof'):
            if hasattr(self, attr):
                self._set_text(getattr(self, attr), rendered)
        if hasattr(self, 'backup_status_panel_var'):
            self.backup_status_panel_var.set(f"Preview ready: {preview.get('total_rows', 0)} row(s), recommended {preview.get('recommended_mode', 'merge')} restore mode.")
        self._set_status('Backup restore preview generated without changing the vault.', level='success')

    def export_backup(self) -> None:
        path = filedialog.asksaveasfilename(parent=self, defaultextension='.cvxbackup', filetypes=[('CyberVault Backup', '*.cvxbackup')], initialfile='cybervault_backup.cvxbackup')
        if not path:
            return
        passphrase = simpledialog.askstring('Backup Passphrase', 'Set a backup passphrase separate from the vault password:', parent=self, show='*')
        if passphrase is None:
            return
        confirm = simpledialog.askstring('Confirm Backup Passphrase', 'Re-enter the backup passphrase:', parent=self, show='*')
        if confirm is None:
            return
        if passphrase != confirm:
            self._show_toast('Backup Error', 'Backup passphrase confirmation does not match.', kind='danger')
            return
        try:
            self.manager.export_encrypted_backup(path, passphrase)
        except Exception as exc:
            self._show_toast('Backup Error', str(exc), kind='danger')
            return
        if hasattr(self, 'backup_status_panel_var'):
            self.backup_status_panel_var.set(f'Encrypted backup exported: {Path(path).name}')
        self.refresh_all()
        self._set_status('Encrypted backup exported.', level='success')

    def change_master_password(self) -> None:
        current_password = self.current_master_var.get()
        new_password = self.new_master_var.get()
        confirm_password = self.confirm_master_var.get()
        if not current_password or not new_password or not confirm_password:
            self._show_toast('Rotation Failed', 'Fill in the current password, new password, and confirmation fields first.', kind='warning')
            return
        if new_password != confirm_password:
            self._show_toast('Rotation Failed', 'The new master password confirmation does not match.', kind='danger')
            return
        if not self._confirm_action(
            'Rotate Master Password',
            'This re-encrypts the full vault with a new master password. Make sure you already exported a fresh backup.',
            ok_text='Rotate Now',
            cancel_text='Cancel',
        ):
            return
        try:
            self.manager.change_master_password(current_password, new_password)
        except Exception as exc:
            self._show_toast('Rotation Failed', str(exc), kind='danger')
            return
        self.current_master_var.set('')
        self.new_master_var.set('')
        self.confirm_master_var.set('')
        self.refresh_all()
        self._show_toast('Master Password Updated', 'The vault was re-encrypted successfully with the new master password.', kind='success')
        self._set_status('Master password rotated successfully.', level='success')

    def _choose_backup_import_mode(self) -> str | None:
        answer = messagebox.askyesnocancel(
            'Import Options',
            'How should CyberVault import this backup?\n\n'
            'Yes = Replace current credentials after creating a safety snapshot.\n'
            'No = Merge with the current vault and skip duplicates.\n'
            'Cancel = Stop without importing.',
            parent=self,
        )
        if answer is None:
            return None
        return 'replace' if answer else 'merge'

    def import_backup(self) -> None:
        path = filedialog.askopenfilename(parent=self, filetypes=[('CyberVault Backup', '*.cvxbackup'), ('All files', '*.*')])
        if not path:
            return
        passphrase = simpledialog.askstring('Backup Passphrase', 'Enter the backup passphrase used during export:', parent=self, show='*')
        if passphrase is None:
            return
        try:
            preview = self.manager.preview_encrypted_backup(path, passphrase)
        except Exception as exc:
            self._show_toast('Backup Preview Failed', str(exc), kind='danger')
            return
        preview_text = self._format_backup_preview(preview)
        proceed = messagebox.askokcancel(
            'Backup Restore Preview',
            preview_text + '\n\nContinue to choose Merge or Replace?',
            parent=self,
        )
        if not proceed:
            self._set_status('Encrypted backup import cancelled after preview.', level='info')
            return
        self.backup_preview_var.set(
            f"Backup preview: {preview.get('total_rows', 0)} row(s), {preview.get('duplicates_in_current_vault', 0)} duplicate(s), recommended {preview.get('recommended_mode', 'merge')}."
        )
        for attr in ('backup_preview_text', 'backup_preview_text_proof'):
            if hasattr(self, attr):
                self._set_text(getattr(self, attr), preview_text)
        if hasattr(self, 'backup_status_panel_var'):
            self.backup_status_panel_var.set(f"Import preview complete: {preview.get('total_rows', 0)} row(s), {preview.get('duplicates_in_current_vault', 0)} duplicate(s).")
        import_mode = self._choose_backup_import_mode()
        if import_mode is None:
            self._set_status('Encrypted backup import cancelled.', level='info')
            return
        replace_existing = import_mode == 'replace'
        try:
            stats = self.manager.import_encrypted_backup(path, passphrase, replace_existing=replace_existing, skip_duplicates=True)
        except Exception as exc:
            self._show_toast('Import Failed', str(exc), kind='danger')
            return
        self.refresh_all()
        snap = self.manager.get_setting('last_safety_snapshot_path', '')
        suffix = f' Safety snapshot: {Path(snap).name}' if replace_existing and snap else ''
        self._set_status(f"Encrypted backup {import_mode} completed. Added {stats['imported']} item(s), skipped {stats['skipped_duplicates']} duplicate(s).{suffix}", level='success')

    def restore_safety_snapshot(self) -> None:
        snapshots = self.manager.list_safety_snapshots()
        if not snapshots:
            self._show_toast('No Safety Snapshots', 'No local emergency snapshots were found for this vault.', kind='warning')
            return
        dialog = tk.Toplevel(self)
        dialog.title('Restore Emergency Safety Snapshot')
        dialog.geometry('900x520')
        dialog.minsize(760, 420)
        dialog.configure(bg=APP_BG)
        dialog.transient(self)
        dialog.grab_set()
        self._center_window(dialog, 900, 520)
        shell = tk.Frame(dialog, bg=APP_BG, padx=18, pady=18)
        shell.pack(fill='both', expand=True)
        card = self._card(shell, bg=CARD_BG, padx=18, pady=18)
        card.pack(fill='both', expand=True)
        ci = card.inner
        self._label(ci, 'Restore Emergency Snapshot', bg=ci.cget('bg'), font=('Segoe UI Semibold', 14)).pack(anchor='w')
        self._label(ci, 'Restoring replaces current credentials with the encrypted checkpoint. CyberVault creates a new safety snapshot before restore.', fg=SUBTEXT, bg=ci.cget('bg'), wraplength=760).pack(anchor='w', pady=(6, 12))
        cols = ('created', 'reason', 'sha', 'file')
        tree = ttk.Treeview(ci, columns=cols, show='headings', selectmode='browse', height=10)
        for c, label, width in [('created', 'Created', 170), ('reason', 'Reason', 240), ('sha', 'SHA-256', 180), ('file', 'File', 260)]:
            tree.heading(c, text=label)
            tree.column(c, width=width, anchor='w')
        tree.pack(fill='both', expand=True)
        paths: dict[str, str] = {}
        for idx, item in enumerate(snapshots, start=1):
            iid = str(idx)
            paths[iid] = item['path']
            tree.insert('', 'end', iid=iid, values=(self._fmt_dt(item.get('created_at', '')), item.get('reason', ''), item.get('sha256', '')[:16], item.get('name', '')))
        if paths:
            tree.selection_set('1')
        btns = tk.Frame(ci, bg=ci.cget('bg'))
        btns.pack(fill='x', pady=(14, 0))
        def do_restore() -> None:
            selection = tree.selection()
            if not selection:
                return
            if not self._confirm_action('Confirm Restore', 'This replaces current vault credentials with the selected checkpoint. Continue?', ok_text='Restore', cancel_text='Cancel', kind='danger'):
                return
            try:
                stats = self.manager.restore_safety_snapshot(paths[selection[0]])
            except Exception as exc:
                self._show_toast('Restore Failed', str(exc), kind='danger', parent=dialog)
                return
            dialog.destroy()
            self.refresh_all()
            self._set_status(f"Safety snapshot restored: {stats['imported']} credential(s).", level='warning')
        ttk.Button(btns, text='Cancel', command=dialog.destroy, style='Ghost.TButton').pack(side='right')
        ttk.Button(btns, text='Restore Selected Snapshot', command=do_restore, style='Danger.TButton').pack(side='right', padx=(0, 8))

    def load_demo_data(self) -> None:
        existing_count = len(self.manager.list_credentials(include_deleted=True))
        if existing_count:
            approved = messagebox.askyesno(
                'Create Assessment Workspace',
                'CyberVault will create a curated local assessment workspace inside the vault.\n\n'
                'Existing credentials will stay untouched, exact assessment duplicates are skipped, '
                'and retired credentials are moved to Trash so recovery and purge controls can be reviewed. Continue?',
                parent=self,
            )
            if not approved:
                self._set_status('Assessment workspace setup cancelled.', level='info')
                return
        stats = self.manager.load_demo_data()
        select_id = None
        created_ids = stats.get('created_ids', []) if isinstance(stats, dict) else []
        if created_ids:
            select_id = created_ids[0]
        self.refresh_all(select_id=select_id)
        if stats.get('created', 0):
            msg = f"Assessment workspace ready: {stats['created']} added, {stats.get('skipped_existing', 0)} skipped."
            self._set_status(msg, level='success')
            self._show_toast('Workspace Ready', msg, kind='success')
        else:
            msg = 'Assessment workspace is already ready. No duplicate credentials were added.'
            self._set_status(msg, level='info')
            self._show_toast('Workspace Already Ready', msg, kind='info')

    def _selected_history_reference(self) -> tuple[int, str] | None:
        if self.selected_id is None or not hasattr(self, 'history_tree'):
            return None
        selection = self.history_tree.selection()
        if not selection or selection[0] == 'empty':
            self._set_status('Select a password-history row first.', level='warning')
            return None
        try:
            index = int(selection[0]) - 1
        except ValueError:
            self._set_status('Invalid history selection.', level='warning')
            return None
        history = self.manager.get_password_history(self.selected_id)
        if index < 0 or index >= len(history):
            self._set_status('History selection is no longer available.', level='warning')
            return None
        return self.selected_id, history[index].get('changed_at', '')

    def reveal_history_password(self) -> None:
        ref = self._selected_history_reference()
        if not ref:
            return
        credential_id, changed_at = ref
        self.pending_history_payload = (credential_id, changed_at, 'reveal')
        self._show_auth_dialog(mode='reauth_history_reveal')

    def copy_history_password(self) -> None:
        ref = self._selected_history_reference()
        if not ref:
            return
        credential_id, changed_at = ref
        self.pending_history_payload = (credential_id, changed_at, 'copy')
        self._show_auth_dialog(mode='reauth_history_copy')

    def _complete_history_secret(self, mode: str) -> None:
        if not self.pending_history_payload:
            return
        credential_id, changed_at, requested_action = self.pending_history_payload
        history = self.manager.get_password_history(credential_id)
        match = next((item for item in history if item.get('changed_at') == changed_at), None)
        if not match:
            self.pending_history_payload = None
            self._set_status('Selected history entry is no longer available.', level='warning')
            return
        password = match.get('password', '')
        label = 'Historical Password'
        if requested_action == 'copy' or mode == 'reauth_history_copy':
            self.copy_custom_value(password, label)
            self.manager.add_log('Copied Historical Secret', f'Copied old password for {self.manager._log_target(credential_id=credential_id)}.', 'warning')
            self._set_status('Historical password copied after re-authentication.', level='success')
        else:
            self._show_history_secret_dialog(password, changed_at)
            self.manager.add_log('Historical Secret Revealed', f'Revealed old password for {self.manager._log_target(credential_id=credential_id)}.', 'warning')
            self._set_status('Historical password revealed in a temporary dialog.', level='warning')
        self.pending_history_payload = None
        self.refresh_all(select_id=credential_id)

    def _show_history_secret_dialog(self, password: str, changed_at: str) -> None:
        dialog = tk.Toplevel(self)
        dialog.title('Historical Password')
        dialog.geometry('560x240')
        dialog.minsize(520, 220)
        dialog.configure(bg=APP_BG)
        dialog.transient(self)
        dialog.grab_set()
        self._center_window(dialog, 560, 240)
        shell = tk.Frame(dialog, bg=APP_BG, padx=18, pady=18)
        shell.pack(fill='both', expand=True)
        card = self._card(shell, bg=CARD_BG, padx=18, pady=18)
        card.pack(fill='both', expand=True)
        ci = card.inner
        self._label(ci, 'Historical password revealed', bg=ci.cget('bg'), font=('Segoe UI Semibold', 14)).pack(anchor='w')
        self._label(ci, f'Changed at: {self._fmt_dt(changed_at)} · This window auto-closes in 20 seconds.', fg=SUBTEXT, bg=ci.cget('bg'), wraplength=500).pack(anchor='w', pady=(6, 12))
        value_var = tk.StringVar(value=password)
        entry = self._styled_entry(ci, value_var)
        entry.configure(state='readonly')
        entry.pack(fill='x', ipady=7)
        buttons = tk.Frame(ci, bg=ci.cget('bg'))
        buttons.pack(fill='x', pady=(14, 0))
        ttk.Button(buttons, text='Copy', command=lambda: self.copy_custom_value(password, 'Historical Password'), style='Accent.TButton').pack(side='left')
        ttk.Button(buttons, text='Hide Now', command=dialog.destroy, style='Ghost.TButton').pack(side='right')
        dialog.after(20_000, lambda: dialog.destroy() if dialog.winfo_exists() else None)

    def begin_reveal(self) -> None:
        if self.selected_id is None:
            return
        if not self.manager.get_credential(self.selected_id):
            return
        self.reauth_target = self.selected_id
        self._show_auth_dialog(mode='reauth')

    def _reveal_selected_password(self) -> None:
        if self.reauth_target is None:
            return
        credential_id = self.reauth_target
        item = self.manager.get_credential(credential_id)
        if not item:
            self.reauth_target = None
            return
        self.password_var.set(item.password)
        if hasattr(self, 'password_entry'):
            self.password_entry.configure(show='')
        if self.reveal_hide_job:
            self.after_cancel(self.reveal_hide_job)
        self.reveal_hide_job = self.after(15_000, self._hide_revealed_password)
        self.manager.record_view(credential_id)
        self._set_status('Password revealed after re-authentication. It will auto-hide in 15s.', level='success')
        self.refresh_all(select_id=credential_id)
        self.reauth_target = None

    def _hide_revealed_password(self) -> None:
        if hasattr(self, 'password_entry'):
            self.password_entry.configure(show='*')
        if self.selected_id is not None:
            self.password_var.set('••••••••••••')
        else:
            self.password_var.set('')
        self.reveal_hide_job = None
        self._set_status('Password hidden again.', level='info', toast=False)

    def _complete_password_copy(self) -> None:
        if not self.pending_copy_payload:
            return
        credential_id, field_name, label = self.pending_copy_payload
        item = self.manager.get_credential(credential_id)
        if not item:
            self.pending_copy_payload = None
            return
        value = getattr(item, field_name, '')
        if not value:
            self.pending_copy_payload = None
            return
        self.copy_custom_value(value, label)
        self.manager.record_copy(credential_id, label)
        self._set_status('Password copied after re-authentication.', level='success')
        self.refresh_all(select_id=credential_id)
        self.pending_copy_payload = None

    def copy_field(self, field_name: str) -> None:
        if self.selected_id is None:
            return
        item = self.manager.get_credential(self.selected_id)
        if not item:
            return
        value = getattr(item, field_name)
        if not value:
            return
        label = {'username': 'Username', 'password': 'Password', 'website': 'Website'}.get(field_name, field_name)
        if field_name == 'password':
            self.pending_copy_payload = (item.id, field_name, label)
            self._show_auth_dialog(mode='reauth_copy')
            return
        self.copy_custom_value(value, label)
        self.manager.record_copy(item.id, label)
        self.refresh_all(select_id=item.id)

    def copy_custom_value(self, value: str, label: str) -> None:
        if not value:
            return
        self.clipboard_clear()
        self.clipboard_append(value)
        self._clipboard_owned_value = value
        seconds = max(5, self.manager.get_setting_int('clipboard_clear_seconds', 15))
        if self.clipboard_job:
            self.after_cancel(self.clipboard_job)
        self.clipboard_job = self.after(seconds * 1000, self._clear_clipboard_contents)
        self._set_status(f'{label} copied. Clipboard clears in {seconds}s.', level='info')

    def _clear_clipboard_contents(self) -> None:
        try:
            expected = getattr(self, '_clipboard_owned_value', None)
            current = self.clipboard_get() if expected is not None else None
            if expected is not None and current == expected:
                self.clipboard_clear()
                self.clipboard_append('')
                self._set_status('Clipboard cleared.', level='info', toast=False)
            elif expected is not None:
                self._set_status('Clipboard changed externally; CyberVault left it unchanged.', level='info', toast=False)
        except Exception:
            pass
        self._clipboard_owned_value = None
        self.clipboard_job = None

    def open_website(self) -> None:
        site = self.website_var.get().strip()
        if not site:
            return
        try:
            url = normalize_http_url(site)
        except ValueError as exc:
            self._set_status(str(exc), level='warning')
            return
        webbrowser.open(url)

    def panic_lock(self) -> None:
        self._clear_clipboard_contents()
        self.lock_vault()

    def lock_vault(self) -> None:
        self._clear_clipboard_contents()
        if self.reveal_hide_job:
            self.after_cancel(self.reveal_hide_job)
            self.reveal_hide_job = None
        if self.clipboard_job:
            self.after_cancel(self.clipboard_job)
            self.clipboard_job = None
        self.reauth_target = None
        self.pending_copy_payload = None
        self.pending_history_payload = None
        self._clipboard_owned_value = None
        self.password_var.set('')
        if hasattr(self, 'password_entry'):
            self.password_entry.configure(show='*')
        self.clear_editor()
        self.manager.lock()
        self.state_var.set('Status: Locked')
        self._set_status('Vault locked.', level='warning')
        self._show_auth_dialog(mode='unlock')

    def open_quick_add(self) -> None:
        dialog = tk.Toplevel(self)
        dialog.title('Quick Add Credential')
        dialog.geometry('700x760')
        dialog.minsize(620, 560)
        dialog.configure(bg=APP_BG)
        dialog.transient(self)
        dialog.grab_set()
        self._center_window(dialog, 700, 760)

        shell = tk.Frame(dialog, bg=APP_BG, padx=18, pady=18)
        shell.pack(fill='both', expand=True)

        card = self._card(shell, bg=CARD_BG, padx=0, pady=0)
        card.pack(fill='both', expand=True)
        ci = card.inner

        header = tk.Frame(ci, bg=CARD_BG, padx=24, pady=20)
        header.pack(fill='x', side='top')
        title_row = tk.Frame(header, bg=header.cget('bg'))
        title_row.pack(fill='x')
        mark = tk.Canvas(title_row, width=44, height=44, bg=title_row.cget('bg'), highlightthickness=0)
        mark.pack(side='left')
        mark.create_oval(4, 4, 40, 40, fill=self.accent, outline=self.accent)
        mark.create_text(22, 22, text='+', fill=APP_BG, font=('Segoe UI Semibold', 18))
        text_head = tk.Frame(title_row, bg=title_row.cget('bg'))
        text_head.pack(side='left', fill='x', expand=True, padx=(12, 0))
        self._label(text_head, 'Quick Add', bg=text_head.cget('bg'), font=('Segoe UI Semibold', 18)).pack(anchor='w')
        self._label(
            text_head,
            'Add the essentials fast. The footer stays visible, while the form scrolls safely on smaller screens.',
            fg=SUBTEXT,
            bg=text_head.cget('bg'),
            wraplength=560,
            font=('Segoe UI', 10),
        ).pack(anchor='w', pady=(4, 0))

        separator = tk.Frame(ci, bg=BORDER_SOFT, height=1)
        separator.pack(fill='x')

        body_shell = tk.Frame(ci, bg=CARD_BG)
        body_shell.pack(fill='both', expand=True)
        _canvas, body = self._scrollable_panel(body_shell, bg=CARD_BG, padx=24, pady=18)

        title = tk.StringVar()
        username = tk.StringVar()
        password = tk.StringVar()
        category = tk.StringVar(value='General')
        website = tk.StringVar()
        tags = tk.StringVar(value='quick-add')

        entries: list[tk.Entry] = []

        def add_field(label: str, var: tk.StringVar, *, hint: str = '') -> tk.Entry:
            self._label(body, label, bg=body.cget('bg'), font=('Segoe UI Semibold', 10)).pack(anchor='w', pady=(10, 0))
            entry = self._styled_entry(body, var)
            entry.pack(fill='x', pady=(6, 0), ipady=7)
            if hint:
                self._label(body, hint, fg=MUTED, bg=body.cget('bg'), font=('Segoe UI', 8), wraplength=560).pack(anchor='w', pady=(4, 0))
            entries.append(entry)
            return entry

        add_field('Title *', title, hint='Example: Bugcrowd, Gmail, University Portal')
        add_field('Username / Email *', username)
        add_field('Website / URL', website, hint='Optional, but useful for favicon badges and duplicate-site intelligence.')
        add_field('Tags', tags, hint='Comma-separated tags like bug-bounty, work, personal.')

        self._label(body, 'Password *', bg=body.cget('bg'), font=('Segoe UI Semibold', 10)).pack(anchor='w', pady=(10, 0))
        pw_row = tk.Frame(body, bg=body.cget('bg'))
        pw_row.pack(fill='x', pady=(6, 0))
        pw_entry = self._styled_entry(pw_row, password, show='*')
        pw_entry.pack(side='left', fill='x', expand=True, ipady=7)
        entries.append(pw_entry)
        password_visible = tk.BooleanVar(value=False)

        def toggle_password() -> None:
            password_visible.set(not password_visible.get())
            pw_entry.configure(show='' if password_visible.get() else '*')
            show_btn.configure(text='Hide' if password_visible.get() else 'Show')

        show_btn = ttk.Button(pw_row, text='Show', command=toggle_password, style='Ghost.TButton')
        show_btn.pack(side='left', padx=(8, 0))

        def quick_generate() -> None:
            self.generate_password()
            password.set(self.generated_password_var.get())
            self._show_toast('Generated', 'A strong password was generated for this credential.', kind='success', parent=dialog)

        ttk.Button(pw_row, text='Generate', command=quick_generate, style='Accent.TButton').pack(side='left', padx=(8, 0))

        self._label(body, 'Category', bg=body.cget('bg'), font=('Segoe UI Semibold', 10)).pack(anchor='w', pady=(10, 0))
        category_box = ttk.Combobox(body, textvariable=category, values=CATEGORIES, state='readonly')
        category_box.pack(fill='x', pady=(6, 0))

        info = tk.Frame(body, bg=SURFACE_2, padx=14, pady=12, highlightthickness=1, highlightbackground=BORDER_SOFT)
        info.pack(fill='x', pady=(18, 10))
        self._label(info, 'Local-first save', bg=info.cget('bg'), font=('Segoe UI Semibold', 10)).pack(anchor='w')
        self._label(
            info,
            'Quick Add writes directly to the encrypted vault using the same validation, AES-GCM field encryption, and audit logging as the full editor.',
            fg=SUBTEXT,
            bg=info.cget('bg'),
            wraplength=560,
            font=('Segoe UI', 9),
        ).pack(anchor='w', pady=(4, 0))

        footer = tk.Frame(ci, bg=CARD_BG, padx=24, pady=16, highlightthickness=1, highlightbackground=BORDER_SOFT)
        footer.pack(fill='x', side='bottom')
        error_var = tk.StringVar(value='Required: title, username/email, and password.')
        self._label(footer, textvariable=error_var, fg=MUTED, bg=footer.cget('bg'), font=('Segoe UI', 9), wraplength=360).pack(side='left')
        buttons = tk.Frame(footer, bg=footer.cget('bg'))
        buttons.pack(side='right')

        def do_save() -> None:
            missing = []
            if not title.get().strip():
                missing.append('title')
            if not username.get().strip():
                missing.append('username/email')
            if not password.get():
                missing.append('password')
            if missing:
                error_var.set('Missing required field(s): ' + ', '.join(missing) + '.')
                self._show_toast('Quick Add Validation', error_var.get(), kind='warning', parent=dialog)
                return
            payload = {
                'title': title.get(),
                'username': username.get(),
                'password': password.get(),
                'category': category.get(),
                'tags': tags.get(),
                'notes': 'Added from Quick Add.',
                'website': website.get(),
                'is_favorite': False,
            }
            try:
                action, target_id = self._maybe_handle_duplicate(payload, parent=dialog)
                if action == 'cancel':
                    error_var.set('Save cancelled after duplicate check.')
                    return
                if action == 'update' and target_id is not None:
                    self.manager.update_credential(target_id, **payload)
                    new_id = target_id
                else:
                    new_id = self.manager.add_credential(**payload)
            except Exception as exc:
                error_var.set(str(exc))
                self._show_toast('Quick Add Failed', str(exc), kind='danger', parent=dialog)
                return
            dialog.destroy()
            self.show_view('vault')
            self.refresh_all(select_id=new_id)
            self._set_status('Credential added from Quick Add.', level='success')
            self._show_toast('Saved', 'Credential added to the encrypted vault.', kind='success')

        ttk.Button(buttons, text='Cancel', command=dialog.destroy, style='Ghost.TButton').pack(side='left', padx=(0, 8))
        ttk.Button(buttons, text='Save Credential', command=do_save, style='Accent.TButton').pack(side='left')

        try:
            entries[0].focus_set()
            dialog.bind('<Return>', lambda _e: do_save())
            dialog.bind('<Escape>', lambda _e: dialog.destroy())
        except Exception:
            pass

    def _selected_security_id(self) -> int | None:
        if not hasattr(self, 'security_tree'):
            return None
        selection = self.security_tree.selection()
        if not selection:
            self._set_status('Select a Security Center finding first.', level='warning')
            return None
        try:
            return int(selection[0])
        except (TypeError, ValueError):
            self._set_status('Invalid Security Center selection.', level='warning')
            return None

    def open_selected_security_in_vault(self) -> None:
        credential_id = self._selected_security_id()
        if credential_id is None:
            return
        self.show_view('vault')
        self.refresh_all(select_id=credential_id)
        self._set_status('Opened selected finding in the Vault editor.', level='info')

    def generate_replacement_for_security(self) -> None:
        credential_id = self._selected_security_id()
        if credential_id is None:
            return
        self.selected_id = credential_id
        self.generator_length_var.set(max(20, int(self.generator_length_var.get() or 20)))
        current = self.manager.get_credential(credential_id)
        if current:
            policy = infer_account_policy(title=current.title, username=current.username, website=current.website, category=current.category)
            self.generator_use_case_var.set(policy.generator_preset)
            self.generator_length_var.set(max(int(self.generator_length_var.get() or 20), policy.target_length))
        else:
            self.generator_use_case_var.set('Work')
        self.generate_password()
        self.show_view('generator')
        self._set_status('Generated a strong replacement for the selected Security Center finding.', level='success')

    def mark_security_finding_reviewed(self) -> None:
        credential_id = self._selected_security_id()
        if credential_id is None:
            return
        self.manager.add_log('Security Finding Reviewed', f'Reviewed {self.manager._log_target(credential_id=credential_id)} from Security Center.', 'success')
        self.refresh_all(select_id=credential_id)
        self._set_status('Security finding marked as reviewed in the local activity log.', level='success')

    def toggle_presentation_mode(self) -> None:
        self.presentation_mode = not self.presentation_mode
        try:
            self.attributes('-fullscreen', self.presentation_mode)
        except Exception:
            pass
        if self.presentation_mode and not self.manager.list_credentials():
            self.manager.load_demo_data()
            self.refresh_all()
        self.show_view('dashboard')
        self._set_status('Full-screen focus mode enabled.' if self.presentation_mode else 'Full-screen focus mode disabled.', level='info')

    def update_fix_simulator(self) -> None:
        options = {
            'weak': self.fix_weak_var.get(),
            'reused': self.fix_reused_var.get(),
            'old': self.fix_old_var.get(),
            'metadata': self.fix_metadata_var.get(),
            'trash': self.fix_trash_var.get(),
            'backup': self.fix_backup_var.get(),
        }
        result = self.manager.simulate_fix_impact(options)
        current = result.get('current_score')
        projected = result.get('projected_score')
        if current is None or projected is None:
            self.fix_projection_var.set('Add credentials first to simulate impact.')
            return
        fixes = '; '.join(result.get('selected_fixes', [])[:2])
        self.fix_projection_var.set(f"Current {current}/100 → projected {projected}/100 (+{result.get('estimated_gain', 0)}). {fixes}")

    def _bind_shortcuts(self) -> None:
        self.bind_all('<Control-n>', lambda _e: self.open_quick_add())
        self.bind_all('<Control-f>', lambda _e: (self.show_view('vault'), self.focus_force()))
        self.bind_all('<Control-l>', lambda _e: self.lock_vault())
        self.bind_all('<Control-e>', lambda _e: self.export_report())
        self.bind_all('<Control-g>', lambda _e: self.show_view('generator'))

    def _editor_payload(self) -> dict:
        raw_password = self.password_var.get()
        if self.selected_id and raw_password and set(raw_password) == {'•'}:
            current = self.manager.get_credential(self.selected_id)
            raw_password = current.password if current else ''
        return {
            'title': self.title_var.get(),
            'username': self.username_var.get(),
            'password': raw_password,
            'category': self.category_var.get(),
            'tags': self.tags_var.get(),
            'notes': self.notes_text.get('1.0', 'end').strip(),
            'website': self.website_var.get(),
            'is_favorite': self.favorite_var.get(),
        }

    def _apply_generator_preset(self, length: int) -> None:
        self.generator_length_var.set(length)
        if hasattr(self, 'length_label'):
            self.length_label.configure(text=f'{self.generator_length_var.get()} characters')

    def generate_password(self) -> None:
        use_case = self.generator_use_case_var.get()
        target_length = self.generator_length_var.get()
        if use_case == 'Banking':
            target_length = max(target_length, 20)
            self.generator_digits_var.set(True)
            self.generator_symbols_var.set(True)
        elif use_case == 'Recovery':
            target_length = max(target_length, 24)
            self.generator_upper_var.set(True)
            self.generator_lower_var.set(True)
            self.generator_digits_var.set(True)
        elif use_case == 'Work':
            target_length = max(target_length, 18)
        elif use_case == 'Social':
            target_length = max(target_length, 18)
            self.generator_digits_var.set(True)
        elif use_case == 'Education':
            target_length = max(target_length, 18)
        elif use_case == 'Servers':
            target_length = max(target_length, 26)
            self.generator_upper_var.set(True)
            self.generator_lower_var.set(True)
            self.generator_digits_var.set(True)
            self.generator_symbols_var.set(True)
        elif use_case == 'Crypto':
            target_length = max(target_length, 24)
            self.generator_upper_var.set(True)
            self.generator_lower_var.set(True)
            self.generator_digits_var.set(True)
            self.generator_symbols_var.set(True)
        self.generator_length_var.set(target_length)
        if hasattr(self, 'length_label'):
            self.length_label.configure(text=f'{self.generator_length_var.get()} characters')

        length = max(8, min(64, self.generator_length_var.get()))
        pools = []
        if self.generator_upper_var.get():
            pools.append(string.ascii_uppercase)
        if self.generator_lower_var.get():
            pools.append(string.ascii_lowercase)
        if self.generator_digits_var.get():
            pools.append(string.digits)
        if self.generator_symbols_var.get():
            pools.append('!@#$%^&*()-_=+[]{};:,.?/')
        if not pools:
            pools = [string.ascii_letters + string.digits]
        if self.generator_easy_read_var.get():
            ambiguous = "O0Il1|`'\""
            pools = [''.join(ch for ch in pool if ch not in ambiguous) for pool in pools]
        rng = secrets.SystemRandom()
        password_chars = [rng.choice(pool) for pool in pools if pool]
        merged = ''.join(pools)
        while len(password_chars) < length:
            password_chars.append(rng.choice(merged))
        rng.shuffle(password_chars)
        password = ''.join(password_chars[:length])
        self.generated_password_var.set(password)
        analysis = analyze_password(password)
        fit = evaluate_password_fit(
            password,
            title=self.title_var.get(),
            username=self.username_var.get(),
            website=self.website_var.get(),
            category=self.category_var.get(),
            password_score=analysis.score,
        )
        self.generator_score_var.set(f'Strength: {analysis.label} ({analysis.score}/100) — {analysis.entropy_bits} bits · Site-fit {fit.fit_score}/100')
        fit_note = {
            'General': 'Balanced for most personal accounts.',
            'Work': 'Good baseline for productivity suites and work accounts.',
            'Banking': 'Longer output with digits and symbols for higher-risk accounts.',
            'Recovery': 'Extra-long output intended for recovery or root-level secrets.',
            'Social': 'Long unique output for public identity and reputation protection.',
            'Education': 'Balanced for portals that combine grades, mail, and personal records.',
            'Servers': 'Maximum-strength output for admin consoles and infrastructure.',
            'Crypto': 'Maximum-strength output for high-value wallet and exchange accounts.',
        }.get(use_case, 'Balanced for most personal accounts.')
        if hasattr(self, 'generator_analysis_vars'):
            self.generator_analysis_vars['score'].set(f'{analysis.score}/100 · {analysis.label}')
            self.generator_analysis_vars['entropy'].set(f'{analysis.entropy_bits} bits')
            self.generator_analysis_vars['fit'].set(use_case)
            if 'profile' in self.generator_analysis_vars:
                self.generator_analysis_vars['profile'].set(fit.profile)
        warning_lines = [f'• {w}' for w in analysis.warnings] or ['• No major generator warnings.']
        suggestion_lines = [f'• {s}' for s in analysis.suggestions] or ['• Store it only in the encrypted vault and avoid reuse.']
        lines = [
            f'Use case: {use_case}',
            f'Site profile: {fit.profile} ({fit.risk_tier})',
            f'Entropy: {analysis.entropy_bits} bits',
            f'Score: {analysis.score}/100 ({analysis.label})',
            f'Site-fit score: {fit.fit_score}/100 ({fit.fit_label})',
            '',
            'Explanation',
            f'• {analysis.entropy_note}',
            f'• {fit_note}',
            f'• {fit.headline}',
            f'• {fit.mfa_hint}',
            '',
            'Warnings',
            *warning_lines,
            '',
            'Likely Website Behavior',
            *[f'• {item}' for item in getattr(fit, 'form_behavior', [])[:5]],
            '',
            'Site Requirement Logic',
            *[f'• {item}' for item in fit.requirements[:7]],
            '',
            'Must Fix for This Site',
            *([f'• {item}' for item in fit.must_fix[:5]] or ['• No site-specific blocker.']),
            '',
            'Suggestions',
            *suggestion_lines,
        ]
        self._set_text(self.generator_analysis, '\n'.join(lines))
        self.generator_meter_var.set(f'{fit_note} Copy it or send it into the editor to replace a risky credential.')
        self._draw_generator_meter(analysis.score, analysis.entropy_bits)

    def use_generated_password(self) -> None:
        if self.generated_password_var.get():
            self.password_var.set(self.generated_password_var.get())
            self.show_view('vault')
            self.update_analysis_panel()


    def _bind_live_password_coach(self) -> None:
        """Attach lightweight traces so the vault feels alive while typing."""
        def _schedule(*_args) -> None:
            try:
                if getattr(self, '_live_coach_after_id', None):
                    self.after_cancel(self._live_coach_after_id)
                self._live_coach_after_id = self.after(120, self._update_live_password_coach)
            except Exception:
                self._update_live_password_coach()
        self._live_coach_after_id = None
        for var in (self.title_var, self.username_var, self.password_var, self.website_var, self.category_var):
            try:
                var.trace_add('write', _schedule)
            except Exception:
                pass
        self._update_live_password_coach()

    def _current_editor_password_for_analysis(self) -> str:
        raw = self.password_var.get() or ''
        if self.selected_id and raw and set(raw) == {'•'}:
            current = self.manager.get_credential(self.selected_id)
            return current.password if current else ''
        return raw.replace('•', '')

    def _draw_live_coach_meter(self, score: int, label: str = '') -> None:
        if not hasattr(self, 'live_coach_canvas'):
            return
        c = self.live_coach_canvas
        c.delete('all')
        width = max(c.winfo_width() or 430, 430) - 18
        x0, y0, bar_h = 8, 18, 14
        color = DANGER if score < 45 else WARNING if score < 72 else SUCCESS
        c.create_rectangle(x0, y0, x0 + width, y0 + bar_h, fill=INPUT_BG, outline=BORDER_SOFT)
        c.create_rectangle(x0, y0, x0 + (width * max(0, min(score, 100)) / 100), y0 + bar_h, fill=color, outline=color)
        for mark in (25, 50, 75):
            mx = x0 + width * mark / 100
            c.create_line(mx, y0 - 3, mx, y0 + bar_h + 3, fill=BORDER)
        c.create_text(x0, 46, text=f'Site-fit {score}/100', anchor='w', fill=TEXT, font=('Segoe UI Semibold', 9))
        c.create_text(x0 + width, 46, text=label, anchor='e', fill=SUBTEXT, font=('Segoe UI', 9))

    def _render_live_coach_chips(self, coach: dict) -> None:
        """Paint compact live-coach chips without exposing the password."""
        if not hasattr(self, 'live_coach_chip_vars') or not hasattr(self, 'live_coach_chip_frames'):
            return
        state_colors = {
            'safe': ('#0F2B22', SUCCESS),
            'good': ('#0F2B22', SUCCESS),
            'watch': ('#332710', WARNING),
            'danger': ('#351522', DANGER),
            'idle': (CARD_BG, MUTED),
        }
        for chip in coach.get('chips', []):
            key = str(chip.get('key', ''))
            if key not in self.live_coach_chip_vars:
                continue
            title_var = self.live_coach_chip_vars[key]['title']
            value_var = self.live_coach_chip_vars[key]['value']
            title_var.set(str(chip.get('label', key.title())))
            value_var.set(str(chip.get('value', '—')))
            frame = self.live_coach_chip_frames.get(key)
            if frame:
                bg, outline = state_colors.get(str(chip.get('state', 'idle')), (CARD_BG, BORDER_SOFT))
                try:
                    frame.configure(bg=bg, highlightbackground=outline)
                    for child in frame.winfo_children():
                        child.configure(bg=bg)
                except tk.TclError:
                    pass

    def _update_live_password_coach(self) -> None:
        password = self._current_editor_password_for_analysis()
        title = self.title_var.get()
        username = self.username_var.get()
        website = self.website_var.get()
        category = self.category_var.get()
        analysis = analyze_password(password, context=f'{title} {username} {website}')
        coach = build_password_coach_state(
            password,
            title=title,
            username=username,
            website=website,
            category=category,
            password_score=analysis.score,
        )
        fit_data = coach.get('fit', {})
        fit_score = int(fit_data.get('fit_score', 0) or 0)
        fit_label = str(fit_data.get('fit_label', 'Waiting'))
        self.site_fit_var.set(f'{fit_score}/100 · {fit_label}')
        self.live_coach_var.set(coach.get('coach_line', 'Live coach waiting for password input.'))
        self.live_coach_hint_var.set(coach.get('policy_story', 'Local-only site policy reasoning.'))
        if hasattr(self, 'live_coach_status_var'):
            self.live_coach_status_var.set(f"Readiness: {coach.get('readiness', 'Waiting')}")
        if hasattr(self, 'live_coach_action_var'):
            self.live_coach_action_var.set(f"Next best action: {coach.get('next_action', 'Generate or save when ready.')}")
        self.site_policy_var.set(
            f"Site profile: {coach.get('profile', fit_data.get('profile', 'General'))} · Risk tier: {coach.get('risk_tier', fit_data.get('risk_tier', 'Low'))} · Confidence: {fit_data.get('confidence', 0)}%"
        )
        self.site_policy_detail_var.set(coach.get('microcopy', fit_data.get('site_reason', '')))
        self._draw_live_coach_meter(fit_score, fit_label)
        self._render_live_coach_chips(coach) if hasattr(self, '_render_live_coach_chips') else None
        if hasattr(self, 'site_policy_text'):
            lines = format_policy_fit_lines(fit_data)
            lines.extend(['', 'Likely website behavior:'])
            lines.extend(f"• {item}" for item in coach.get('likely_constraints', []))
            self._set_text(self.site_policy_text, '\n'.join(lines))

    def apply_generator_to_current_site(self) -> None:
        policy = infer_account_policy(
            title=self.title_var.get(),
            username=self.username_var.get(),
            website=self.website_var.get(),
            category=self.category_var.get(),
        )
        self.generator_use_case_var.set(policy.generator_preset)
        self.generator_length_var.set(max(int(self.generator_length_var.get() or 18), policy.target_length))
        self.generator_upper_var.set(True)
        self.generator_lower_var.set(True)
        self.generator_digits_var.set(True)
        self.generator_symbols_var.set(policy.requires_symbol)
        if hasattr(self, 'length_label'):
            self.length_label.configure(text=f'{self.generator_length_var.get()} characters')
        self.generate_password()
        self.show_view('generator')
        self._set_status(f'Generator tuned for {policy.profile}.', level='success')

    def _bind_activity_tracking(self) -> None:
        for seq in ('<Any-KeyPress>', '<Any-ButtonPress>', '<Motion>'):
            self.bind_all(seq, self._on_activity, add='+')

    def _on_activity(self, _event=None) -> None:
        if self.auth_window and self.auth_window.winfo_exists():
            return
        if self.auto_lock_job:
            self.after_cancel(self.auto_lock_job)
        minutes = max(1, self.manager.get_setting_int('auto_lock_minutes', 3))
        self.auto_lock_job = self.after(minutes * 60 * 1000, self.lock_vault)
