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
from .site_policy import evaluate_password_fit, format_policy_fit_lines

class DialogsMixin:
    def _show_startup_dialog(self) -> None:
        if hasattr(self, '_hide_splash_screen'):
            self._hide_splash_screen()
        if not self.manager.is_initialized:
            self._show_setup_dialog()
        else:
            self._show_auth_dialog(mode='unlock')

    def _show_setup_dialog(self) -> None:
        self.auth_window = tk.Toplevel(self)
        self._style_auth_window(self.auth_window, 'Create personal vault')
        self.auth_window.protocol('WM_DELETE_WINDOW', self.destroy)
        owner = tk.StringVar()
        pw1 = tk.StringVar()
        pw2 = tk.StringVar()
        self._auth_form(
            self.auth_window,
            title='Create your personal vault',
            subtitle='Set your owner name and master password, choose a visual accent, and launch a fully local encrypted experience.',
            fields=[('Owner / User Name', owner, False), ('Master Password', pw1, True), ('Confirm Password', pw2, True)],
            primary_text='Create Vault',
            primary=lambda: self._complete_setup(owner.get(), pw1.get(), pw2.get()),
            secondary_text='Exit',
            secondary=self.destroy,
        )

    def _complete_setup(self, owner: str, pw1: str, pw2: str) -> None:
        if pw1 != pw2:
            self._show_toast('Mismatch', 'Passwords do not match.', kind='danger', parent=self.auth_window)
            return
        try:
            self.manager.setup_master_password(owner, pw1)
        except Exception as exc:
            self._show_toast('Setup Error', str(exc), kind='danger', parent=self.auth_window)
            return
        self._close_auth_dialog()
        self.deiconify()
        self.refresh_all()
        self._on_activity()
        self._set_status(f'Vault created successfully for {self.manager.owner_name}.', level='success')

    def _show_auth_dialog(self, mode: str = 'unlock') -> None:
        if mode == 'unlock':
            self.withdraw()
        if self.auth_window and self.auth_window.winfo_exists():
            self.auth_window.focus_force()
            return
        self.auth_window = tk.Toplevel(self)
        self._style_auth_window(self.auth_window, 'Authentication')
        self.auth_window.protocol('WM_DELETE_WINDOW', self.destroy if mode == 'unlock' else self._close_auth_dialog)
        pw = tk.StringVar()
        if mode == 'unlock':
            title = 'Unlock personal vault'
            subtitle = 'Enter the master password to open the vault.'
        elif mode == 'reauth_copy':
            title = 'Re-authenticate to copy password'
            subtitle = 'Password copy now requires the master password before the secret reaches the clipboard.'
        elif mode == 'reauth_history_copy':
            title = 'Re-authenticate to copy old password'
            subtitle = 'Password-history entries remain masked until the master password is verified.'
        elif mode == 'reauth_history_reveal':
            title = 'Re-authenticate to reveal old password'
            subtitle = 'Historical passwords are masked by default and revealed only after verification.'
        else:
            title = 'Re-authenticate to reveal'
            subtitle = 'The secret stays hidden until the correct master password is entered.'
        self._auth_form(
            self.auth_window,
            title=title,
            subtitle=subtitle,
            fields=[('Master Password', pw, True)],
            primary_text='Unlock' if mode == 'unlock' else 'Verify',
            primary=lambda: self._complete_auth(pw.get(), mode),
            secondary_text='Exit' if mode == 'unlock' else 'Cancel',
            secondary=self.destroy if mode == 'unlock' else self._close_auth_dialog,
        )

    def _complete_auth(self, password: str, mode: str) -> None:
        if mode == 'unlock':
            ok = self.manager.unlock(password)
        else:
            ok = self.manager.verify_master_password_only(password)
        if not ok:
            message = self.manager.last_unlock_message or 'Incorrect master password.'
            kind = 'warning' if 'Try again in' in message or 'locked for' in message else 'danger'
            self._show_toast('Authentication Failed', message, kind=kind, parent=self.auth_window)
            return
        if mode == 'unlock':
            self.deiconify()
            self._on_activity()
        elif mode == 'reauth_copy':
            self._complete_password_copy()
        elif mode in {'reauth_history_copy', 'reauth_history_reveal'}:
            self._complete_history_secret(mode)
        else:
            self._reveal_selected_password()
        self._close_auth_dialog()
        self.refresh_all()
        self._set_status('Vault unlocked.' if mode == 'unlock' else 'Re-authentication verified.', level='success')

    def _close_auth_dialog(self) -> None:
        if self.auth_window and self.auth_window.winfo_exists():
            self.auth_window.destroy()
        self.auth_window = None
        self.reauth_target = None
        self.pending_copy_payload = None
        self.pending_history_payload = None

    def _style_auth_window(self, window: tk.Toplevel, title: str) -> None:
        window.title(title)
        window.geometry('780x640')
        window.minsize(680, 540)
        window.resizable(True, True)
        window.configure(bg=APP_BG)
        window.grab_set()
        self._center_window(window, 780, 640)

    def _auth_form(self, window: tk.Toplevel, *, title: str, subtitle: str, fields: list[tuple[str, tk.StringVar, bool]], primary_text: str, primary, secondary_text: str, secondary) -> None:
        shell = tk.Frame(window, bg=APP_BG, padx=24, pady=24)
        shell.pack(fill='both', expand=True)

        hero = tk.Frame(shell, bg=APP_BG)
        hero.pack(fill='x', pady=(0, 16))
        badge = tk.Canvas(hero, width=58, height=58, bg=APP_BG, highlightthickness=0)
        badge.pack(side='left', anchor='n')
        badge.create_oval(4, 4, 54, 54, fill=self.accent, outline=self.accent)
        badge.create_text(29, 29, text='CV', fill=APP_BG, font=('Segoe UI Semibold', 17))
        hero_text = tk.Frame(hero, bg=APP_BG)
        hero_text.pack(side='left', fill='x', expand=True, padx=(14, 0))
        self._label(hero_text, 'CyberVault X', bg=APP_BG, font=('Segoe UI Semibold', 24)).pack(anchor='w')
        self._label(hero_text, 'Secure local password manager', fg=SUBTEXT, bg=APP_BG, font=('Segoe UI', 10)).pack(anchor='w', pady=(2, 0))
        chips = tk.Frame(hero_text, bg=APP_BG)
        chips.pack(anchor='w', pady=(10, 0))
        for value in ('Local', 'AES-GCM', 'PBKDF2', 'Offline Checks'):
            tk.Label(chips, text=value, bg=SURFACE_2, fg=TEXT, padx=10, pady=6, font=('Segoe UI Semibold', 8), highlightthickness=1, highlightbackground=BORDER_SOFT).pack(side='left', padx=(0, 6))

        card = self._card(shell, bg=CARD_BG, padx=0, pady=0)
        card.pack(fill='both', expand=True)
        ci = card.inner

        footer = tk.Frame(ci, bg=CARD_BG, padx=26, pady=18, highlightthickness=1, highlightbackground=BORDER_SOFT)
        footer.pack(fill='x', side='bottom')
        self._label(footer, 'Everything stays encrypted and local on your machine.', fg=MUTED, bg=footer.cget('bg'), wraplength=420, font=('Segoe UI', 9)).pack(side='left')
        footer_buttons = tk.Frame(footer, bg=footer.cget('bg'))
        footer_buttons.pack(side='right')
        ttk.Button(footer_buttons, text=secondary_text, command=secondary, style='Ghost.TButton').pack(side='left', padx=(0, 8))
        ttk.Button(footer_buttons, text=primary_text, command=primary, style='Accent.TButton').pack(side='left')

        body = tk.Frame(ci, bg=CARD_BG, padx=26, pady=26)
        body.pack(fill='both', expand=True)
        self._label(body, title, bg=body.cget('bg'), font=('Segoe UI Semibold', 20)).pack(anchor='w')
        self._label(body, subtitle, fg=SUBTEXT, bg=body.cget('bg'), font=('Segoe UI', 11), wraplength=620).pack(anchor='w', pady=(8, 18))

        for label, var, masked in fields:
            self._label(body, label, bg=body.cget('bg'), font=('Segoe UI Semibold', 10)).pack(anchor='w', pady=(10, 0))
            field_row = tk.Frame(body, bg=body.cget('bg'))
            field_row.pack(fill='x', pady=(6, 0))
            entry = self._styled_entry(field_row, var, show='*' if masked else '')
            entry.pack(side='left', fill='x', expand=True, ipady=7)
            if masked:
                visible = tk.BooleanVar(value=False)
                def toggle(e=entry, v=visible, b=None):
                    v.set(not v.get())
                    e.configure(show='' if v.get() else '*')
                btn = ttk.Button(field_row, text='Show', style='Ghost.TButton')
                btn.configure(command=lambda e=entry, v=visible, b=btn: (v.set(not v.get()), e.configure(show='' if v.get() else '*'), b.configure(text='Hide' if v.get() else 'Show')))
                btn.pack(side='left', padx=(8, 0))
            try:
                if not hasattr(body, '_cvx_entries'):
                    body._cvx_entries = []  # type: ignore[attr-defined]
                body._cvx_entries.append(entry)  # type: ignore[attr-defined]
            except Exception:
                pass

        if 'Create your personal vault' in title:
            theme_row = tk.Frame(body, bg=body.cget('bg'))
            theme_row.pack(fill='x', pady=(14, 0))
            self._label(theme_row, 'Accent Theme', bg=theme_row.cget('bg'), font=('Segoe UI Semibold', 10)).pack(side='left')
            ttk.Combobox(theme_row, textvariable=self.theme_var, values=list(ACCENTS.keys()), state='readonly', width=16).pack(side='left', padx=(12, 0))

        last_unlock = next((row.get('timestamp', '') for row in self.manager.get_logs(limit=50) if 'Unlock Success' in row.get('action', '')), '')
        if last_unlock:
            self._label(body, f'Last unlock recorded: {self._fmt_dt(last_unlock)}', fg=SUBTEXT, bg=body.cget('bg'), font=('Segoe UI', 9)).pack(anchor='w', pady=(14, 0))

        try:
            entries = getattr(body, '_cvx_entries', [])
            if entries:
                entries[0].focus_set()
            window.bind('<Return>', lambda _e: primary())
            window.bind('<Escape>', lambda _e: secondary())
        except Exception:
            pass

    def _open_import_wizard(self, path_value: str, rows: list[dict], fieldnames: list[str]) -> None:
        dialog = tk.Toplevel(self)
        dialog.title('Import Browser / CSV Data')
        dialog.geometry('960x680')
        dialog.minsize(820, 560)
        dialog.configure(bg=APP_BG)
        self._center_window(dialog, 960, 680)
        dialog.transient(self)
        dialog.grab_set()
        shell = tk.Frame(dialog, bg=APP_BG, padx=18, pady=18)
        shell.pack(fill='both', expand=True)
        card = self._card(shell, bg=CARD_BG, padx=18, pady=18)
        card.pack(fill='both', expand=True)
        ci = card.inner
        self._label(ci, 'Import Wizard', bg=ci.cget('bg'), font=('Segoe UI Semibold', 14)).pack(anchor='w')
        self._label(ci, f'Preview and map columns before encrypting imported rows into the local vault. File: {Path(path_value).name}', fg=MUTED, bg=ci.cget('bg'), wraplength=820).pack(anchor='w', pady=(4, 12))
        stepper = tk.Frame(ci, bg=ci.cget('bg'))
        stepper.pack(fill='x', pady=(0, 12))
        for idx, step in enumerate(('1 Select file', '2 Map columns', '3 Preview rows', '4 Import encrypted')):
            chip = tk.Label(stepper, text=step, bg=(self.accent if idx == 0 else SURFACE_2), fg=(APP_BG if idx == 0 else TEXT), padx=12, pady=7, font=('Segoe UI Semibold', 9))
            chip.pack(side='left', padx=(0 if idx == 0 else 8, 0))

        guesses = {
            'title': next((f for f in fieldnames if f.lower() in {'name', 'title', 'account', 'site name'}), fieldnames[0]),
            'username': next((f for f in fieldnames if f.lower() in {'username', 'user name', 'email', 'login', 'user'}), fieldnames[0]),
            'password': next((f for f in fieldnames if f.lower() in {'password', 'pass'}), fieldnames[0]),
            'website': next((f for f in fieldnames if f.lower() in {'url', 'website', 'site', 'origin'}), ''),
            'category': next((f for f in fieldnames if f.lower() == 'category'), ''),
            'tags': next((f for f in fieldnames if f.lower() == 'tags'), ''),
            'notes': next((f for f in fieldnames if f.lower() in {'notes', 'note', 'comments'}), ''),
            'favorite': '',
        }
        mapping_vars = {key: tk.StringVar(value=value) for key, value in guesses.items()}
        map_wrap = tk.Frame(ci, bg=ci.cget('bg'))
        map_wrap.pack(fill='x', pady=(0, 12))
        for idx, key in enumerate(['title', 'username', 'password', 'website', 'category', 'tags', 'notes']):
            cell = tk.Frame(map_wrap, bg=ci.cget('bg'))
            cell.grid(row=idx // 3, column=idx % 3, sticky='ew', padx=6, pady=6)
            self._label(cell, key.replace('_', ' ').title(), bg=cell.cget('bg'), font=('Segoe UI Semibold', 10)).pack(anchor='w')
            ttk.Combobox(cell, textvariable=mapping_vars[key], values=['', *fieldnames], state='readonly', width=24).pack(anchor='w', pady=(6, 0))
        for i in range(3):
            map_wrap.grid_columnconfigure(i, weight=1)

        preview_cols = ('row', 'title', 'username', 'website', 'status')
        preview = ttk.Treeview(ci, columns=preview_cols, show='headings', height=12)
        for col, label, width in [('row', '#', 60), ('title', 'Mapped Title', 190), ('username', 'Mapped Username', 220), ('website', 'Mapped Website', 220), ('status', 'Preview Status', 260)]:
            preview.heading(col, text=label)
            preview.column(col, width=width, anchor='w')
        preview.pack(fill='both', expand=True)
        self._configure_tree_visuals(preview)
        self._attach_tree_scrollbars(preview)

        footer = tk.Frame(ci, bg=ci.cget('bg'))
        footer.pack(fill='x', pady=(14, 0))
        summary_var = tk.StringVar(value='Run preview to validate mapped rows before import.')
        self._label(footer, textvariable=summary_var, fg=SUBTEXT, bg=footer.cget('bg'), wraplength=560).pack(side='left')

        def current_mapping() -> dict[str, str]:
            return {k: v.get() for k, v in mapping_vars.items()}

        def refresh_preview() -> dict:
            summary_var.set('Refreshing preview and duplicate checks...')
            dialog.update_idletasks()
            preview.delete(*preview.get_children())
            result = self.manager.preview_csv_rows(rows, current_mapping())
            for item in result.get('preview', []):
                preview.insert('', 'end', values=(item.get('row', ''), item.get('title', '')[:48], item.get('username', '')[:48], item.get('website', '')[:48], item.get('status', '')[:80]))
            summary = f"Rows: {result['total']} · valid: {result['valid']} · invalid: {result['invalid']} · duplicates: {result['duplicates']}"
            if result.get('issues'):
                summary += ' · First issue: ' + result['issues'][0]
            summary_var.set(summary)
            return result

        for combo in map_wrap.winfo_children():
            for child in combo.winfo_children():
                if isinstance(child, ttk.Combobox):
                    child.bind('<<ComboboxSelected>>', lambda _e: refresh_preview())
        refresh_preview()

        def do_import():
            preview_result = refresh_preview()
            if preview_result.get('invalid'):
                proceed = messagebox.askyesno(
                    'CSV Import Preview',
                    f"{preview_result['invalid']} row(s) are invalid or duplicates. Import only valid non-duplicate rows?",
                    parent=dialog,
                )
                if not proceed:
                    return
            summary_var.set('Encrypting valid rows into the local vault...')
            dialog.update_idletasks()
            try:
                result = self.manager.import_csv_rows(rows, current_mapping())
            except Exception as exc:
                self._show_toast('CSV Import Failed', str(exc), kind='danger', parent=dialog)
                return
            dialog.destroy()
            self.refresh_all(select_id=result['imported_ids'][0] if result['imported_ids'] else None)
            msg = f"Imported {result['imported']} row(s), skipped {result['skipped']} (duplicates: {result['duplicates']})."
            if result['failures']:
                msg += ' First issue: ' + result['failures'][0]
            self._set_status(msg, level='success' if result['imported'] else 'warning')
        ttk.Button(footer, text='Refresh Preview', command=refresh_preview, style='Ghost.TButton').pack(side='right', padx=(0, 8))
        ttk.Button(footer, text='Import Valid Rows', command=do_import, style='Accent.TButton').pack(side='right', padx=(0, 8))
        ttk.Button(footer, text='Cancel', command=dialog.destroy, style='Ghost.TButton').pack(side='right', padx=(0, 8))

    def open_analysis_modal(self) -> None:
        actual = self.manager.get_credential(self.selected_id) if self.selected_id else None
        if not actual:
            self.update_analysis_panel()
            self._show_toast('Analyze', 'Select a credential first.', kind='warning')
            return
        self.update_analysis_panel(actual)
        intel = self.manager.breach_intelligence_for(actual)
        analysis = analyze_password(actual.password, context=f'{actual.title} {actual.username} {actual.website}')
        site_fit = evaluate_password_fit(
            actual.password,
            title=actual.title,
            username=actual.username,
            website=actual.website,
            category=actual.category,
            password_score=analysis.score,
            breached=bool(intel.get('breached')),
            common_password=bool(intel.get('common_password')),
            reuse_count=int(intel.get('reuse_count', 1) or 1),
            updated_at_iso=actual.updated_at,
        )
        dialog = tk.Toplevel(self)
        dialog.title('Credential Analysis')
        dialog.geometry('800x660')
        dialog.minsize(680, 520)
        dialog.configure(bg=APP_BG)
        self._center_window(dialog, 800, 660)
        dialog.transient(self)
        dialog.grab_set()
        shell = tk.Frame(dialog, bg=APP_BG, padx=18, pady=18)
        shell.pack(fill='both', expand=True)
        card = self._card(shell, bg=CARD_BG, padx=18, pady=18)
        card.pack(fill='both', expand=True)
        ci = card.inner
        self._label(ci, f'Analysis — {actual.title}', bg=ci.cget('bg'), font=('Segoe UI Semibold', 14)).pack(anchor='w')
        self._label(ci, f"Strength {analysis.label} ({analysis.score}/100) · Entropy {analysis.entropy_bits} bits · Risk {intel['risk_level']} · Site-fit {site_fit.fit_score}/100", fg=SUBTEXT, bg=ci.cget('bg')).pack(anchor='w', pady=(4, 10))
        text_widget = tk.Text(ci, wrap='word', bg=INPUT_BG, fg=TEXT, insertbackground=TEXT, relief='flat', bd=0, padx=12, pady=12)
        text_widget.pack(fill='both', expand=True)
        self._style_text_widget(text_widget)
        lines = [
            'Warnings:',
            *[f'• {item}' for item in analysis.warnings],
            '',
            'Detected patterns:',
            *([f'• {item}' for item in analysis.patterns] or ['• None']),
            '',
            'Site policy reasoner:',
            *format_policy_fit_lines(site_fit),
            '',
            'Breach intelligence:',
            f"• Explanation: {intel['explanation']}",
            *[f'• {item}' for item in intel['why_matters']],
            '',
            'Fix recommendations:',
            *[f'• {item}' for item in intel['fix_recommendations']],
        ]
        text_widget.insert('1.0', '\n'.join(lines))
        text_widget.configure(state='disabled')
        ttk.Button(ci, text='Close', command=dialog.destroy, style='Accent.TButton').pack(anchor='e', pady=(12, 0))

    def show_quick_tour(self) -> None:
        messagebox.showinfo(
            'CyberVault X Tour',
            '1) Add or import credentials.\n2) Use Security Center to review weak, breached, reused, and old passwords.\n3) Open the Generator to replace risky passwords.\n4) Export the Executive Security Report for stakeholder review.\n5) Toggle Full-Screen Focus Mode for a clean walkthrough.'
        )
