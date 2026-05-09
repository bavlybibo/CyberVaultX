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
        window.title(f'CyberVaultX — {title}')
        width, height = (1120, 720) if 'Create' in title else (1040, 680)
        window.geometry(f'{width}x{height}')
        window.minsize(900, 620)
        window.resizable(True, True)
        window.configure(bg=APP_BG)
        window.grab_set()
        self._center_window(window, width, height)

    def _auth_form(self, window: tk.Toplevel, *, title: str, subtitle: str, fields: list[tuple[str, tk.StringVar, bool]], primary_text: str, primary, secondary_text: str, secondary) -> None:
        shell = tk.Frame(window, bg=APP_BG, padx=28, pady=24)
        shell.pack(fill='both', expand=True)

        # Premium header: brand + trustworthy technology chips.
        header = tk.Frame(shell, bg=APP_BG)
        header.pack(fill='x', pady=(0, 22))
        mark = tk.Canvas(header, width=74, height=74, bg=APP_BG, highlightthickness=0)
        mark.pack(side='left', anchor='n')
        mark.create_oval(5, 5, 69, 69, fill='#06213A', outline=self.accent, width=2)
        mark.create_oval(13, 13, 61, 61, outline='#2377FF', width=2)
        mark.create_text(37, 38, text='CV', fill=self.accent, font=('Segoe UI Semibold', 19))
        brand = tk.Frame(header, bg=APP_BG)
        brand.pack(side='left', fill='x', expand=True, padx=(18, 0))
        self._label(brand, 'CyberVault X', bg=APP_BG, font=('Segoe UI Semibold', 30)).pack(anchor='w')
        self._label(brand, 'Secure local password manager', fg=SUBTEXT, bg=APP_BG, font=('Segoe UI', 12)).pack(anchor='w', pady=(2, 0))
        chips = tk.Frame(brand, bg=APP_BG)
        chips.pack(anchor='w', pady=(16, 0))
        for value, icon, color in [('LOCAL-FIRST', '⌂', SUCCESS), ('AES-GCM', '▣', self.accent), ('PBKDF2 / ARGON2 READY', '⚿', INFO), ('OFFLINE CHECKS', '◌', SUCCESS)]:
            tk.Label(chips, text=f'{icon}  {value}', bg=PANEL_DEEP, fg=color, padx=14, pady=8, font=('Segoe UI Semibold', 9), highlightthickness=1, highlightbackground=BORDER).pack(side='left', padx=(0, 10))
        right_art = tk.Canvas(header, width=230, height=112, bg=APP_BG, highlightthickness=0)
        right_art.pack(side='right')
        cx, cy = 155, 60
        for r, col in [(54, '#0D2B55'), (40, '#0B5FFF'), (25, self.accent)]:
            right_art.create_oval(cx-r, cy-r, cx+r, cy+r, outline=col, width=2)
        right_art.create_rectangle(cx-18, cy-6, cx+18, cy+28, outline=self.accent, width=2, fill='#071B35')
        right_art.create_arc(cx-14, cy-25, cx+14, cy+11, start=0, extent=180, outline=self.accent, width=3)
        right_art.create_text(cx, cy+11, text='•', fill=TEXT, font=('Segoe UI Semibold', 22))

        # Split panel.  Unlock gets a compact trust footer; setup gets a larger onboarding side rail.
        main = tk.Frame(shell, bg=APP_BG)
        main.pack(fill='both', expand=True)
        form_card = self._glow_card(main, bg=CARD_BG, accent=self.accent, padx=0, pady=0)
        form_card.pack(side='left', fill='both', expand=True, padx=(0, 18))
        ci = form_card.inner
        ci.configure(padx=0, pady=0)

        footer = tk.Frame(ci, bg=PANEL_DEEP, padx=28, pady=20, highlightthickness=1, highlightbackground=BORDER_SOFT)
        footer.pack(fill='x', side='bottom')
        self._label(footer, 'Your vault never leaves this device. All data stays encrypted and local.', fg=SUBTEXT, bg=footer.cget('bg'), wraplength=620, font=('Segoe UI', 10)).pack(side='left')
        footer_buttons = tk.Frame(footer, bg=footer.cget('bg'))
        footer_buttons.pack(side='right')
        ttk.Button(footer_buttons, text=secondary_text, command=secondary, style='Ghost.TButton').pack(side='left', padx=(0, 12))
        ttk.Button(footer_buttons, text=('Unlock Vault' if primary_text == 'Unlock' else primary_text), command=primary, style='Accent.TButton').pack(side='left')

        body = tk.Frame(ci, bg=CARD_BG, padx=34, pady=32)
        body.pack(fill='both', expand=True)
        eyebrow = 'WELCOME BACK' if 'Unlock' in title else 'STEP 1 · LOCAL VAULT SETUP'
        self._label(body, eyebrow, fg=self.accent, bg=body.cget('bg'), font=('Segoe UI Semibold', 10)).pack(anchor='w')
        self._label(body, title.replace('personal vault', 'personal vault'), bg=body.cget('bg'), font=('Segoe UI Semibold', 24)).pack(anchor='w', pady=(8, 0))
        self._label(body, subtitle, fg=SUBTEXT, bg=body.cget('bg'), font=('Segoe UI', 12), wraplength=680).pack(anchor='w', pady=(10, 18))
        tk.Frame(body, bg=BORDER_SOFT, height=1).pack(fill='x', pady=(0, 20))

        entries: list[tk.Entry] = []
        password_strength_row = None
        for label, var, masked in fields:
            self._label(body, label, bg=body.cget('bg'), font=('Segoe UI Semibold', 11)).pack(anchor='w', pady=(12, 0))
            field_row = tk.Frame(body, bg=body.cget('bg'))
            field_row.pack(fill='x', pady=(7, 0))
            entry = tk.Entry(
                field_row, textvariable=var, show='*' if masked else '', bg=INPUT_BG, fg=TEXT,
                insertbackground=TEXT, relief='flat', bd=0, highlightthickness=1,
                highlightbackground=INPUT_BORDER, highlightcolor=self.accent, font=('Segoe UI', 12)
            )
            entry.pack(side='left', fill='x', expand=True, ipady=11)
            if masked:
                btn = ttk.Button(field_row, text='Show', style='Ghost.TButton')
                visible = tk.BooleanVar(value=False)
                btn.configure(command=lambda e=entry, v=visible, b=btn: (v.set(not v.get()), e.configure(show='' if v.get() else '*'), b.configure(text='Hide' if v.get() else 'Show')))
                btn.pack(side='left', padx=(10, 0))
            entries.append(entry)
            if label == 'Master Password' and 'Create your personal vault' in title:
                password_strength_row = tk.Frame(body, bg=body.cget('bg'))
                password_strength_row.pack(fill='x', pady=(8, 4))
                meter = tk.Canvas(password_strength_row, height=16, bg=body.cget('bg'), highlightthickness=0)
                meter.pack(side='left', fill='x', expand=True)
                strength_lbl = self._label(password_strength_row, '0 / 4 criteria met', fg=MUTED, bg=body.cget('bg'), font=('Segoe UI', 10))
                strength_lbl.pack(side='right', padx=(14, 0))
                def draw_strength(*_):
                    pwd = var.get()
                    checks = [len(pwd) >= 12, any(c.islower() for c in pwd), any(c.isupper() for c in pwd), any(c.isdigit() or not c.isalnum() for c in pwd)]
                    count = sum(checks)
                    meter.delete('all')
                    width = max(meter.winfo_width() or 420, 420)
                    part = (width - 18) / 4
                    colors = [DANGER, WARNING, INFO, SUCCESS]
                    for i in range(4):
                        fill = colors[min(count-1, 3)] if i < count and count else SURFACE_3
                        meter.create_rectangle(i*(part+6), 3, i*(part+6)+part, 13, fill=fill, outline='')
                    strength = 'Too weak' if count < 2 else 'Fair' if count < 3 else 'Strong' if count < 4 else 'Excellent'
                    strength_lbl.configure(text=f'{count} / 4 criteria met · {strength}', fg=colors[min(max(count-1, 0), 3)] if count else DANGER)
                var.trace_add('write', draw_strength)
                meter.bind('<Configure>', draw_strength)
                draw_strength()

        if 'Create your personal vault' in title:
            protection = tk.Frame(body, bg=PANEL_DEEP, padx=16, pady=14, highlightthickness=1, highlightbackground=BORDER_SOFT)
            protection.pack(fill='x', pady=(18, 0))
            self._label(protection, 'Vault Protection Summary', fg=self.accent, bg=protection.cget('bg'), font=('Segoe UI Semibold', 11)).pack(anchor='w')
            grid = tk.Frame(protection, bg=protection.cget('bg'))
            grid.pack(fill='x', pady=(12, 0))
            for idx, (k, v, icon) in enumerate([('Encryption', 'AES-256-GCM', '▣'), ('Key Derivation', 'PBKDF2 / Argon2 ready', '⚿'), ('Iterations', '600,000+', '↻'), ('Access', 'Local only', '⌂')]):
                cell = tk.Frame(grid, bg=protection.cget('bg'))
                cell.grid(row=0, column=idx, sticky='ew', padx=(0 if idx == 0 else 14, 0))
                grid.grid_columnconfigure(idx, weight=1)
                self._label(cell, icon, fg=self.accent, bg=cell.cget('bg'), font=('Segoe UI Semibold', 18)).pack(side='left')
                txt = tk.Frame(cell, bg=cell.cget('bg'))
                txt.pack(side='left', padx=(8, 0))
                self._label(txt, k, fg=MUTED, bg=txt.cget('bg'), font=('Segoe UI', 8)).pack(anchor='w')
                self._label(txt, v, fg=SUBTEXT, bg=txt.cget('bg'), font=('Segoe UI Semibold', 9)).pack(anchor='w')

        last_unlock = next((row.get('timestamp', '') for row in self.manager.get_logs(limit=50) if 'Unlock Success' in row.get('action', '')), '')
        if last_unlock and 'Unlock' in title:
            info_row = tk.Frame(body, bg=body.cget('bg'))
            info_row.pack(fill='x', pady=(18, 0))
            self._label(info_row, f'◷  Last unlock recorded: {self._fmt_dt(last_unlock)}', fg=SUBTEXT, bg=info_row.cget('bg'), font=('Segoe UI', 10)).pack(side='left')
            self._label(info_row, 'View recent activity  ›', fg=self.accent, bg=info_row.cget('bg'), font=('Segoe UI Semibold', 10)).pack(side='right')

        side = self._glow_card(main, bg=CARD_BG, accent='#2377FF', padx=22, pady=22)
        side.pack(side='right', fill='both', padx=(0, 0))
        side.configure(width=360)
        side.pack_propagate(False)
        si = side.inner
        art = tk.Canvas(si, height=190, bg=si.cget('bg'), highlightthickness=0)
        art.pack(fill='x')
        cx, cy = 160, 92
        for r, color in [(68, '#0B2A52'), (48, '#0B5FFF'), (31, self.accent)]:
            art.create_polygon(cx, cy-r, cx+int(r*.86), cy-int(r*.5), cx+int(r*.86), cy+int(r*.5), cx, cy+r, cx-int(r*.86), cy+int(r*.5), cx-int(r*.86), cy-int(r*.5), outline=color, fill='' if r != 31 else '#082B52', width=2)
        art.create_text(cx, cy+2, text='🔒', fill=TEXT, font=('Segoe UI', 30))
        self._label(si, 'Your data. Your control.' if 'Create' in title else 'Local vault unlock', bg=si.cget('bg'), font=('Segoe UI Semibold', 15)).pack(anchor='w', pady=(12, 0))
        side_text = 'Create a vault that lives only on your device. Encryption keys are derived locally from your master password.' if 'Create' in title else 'Unlock decrypts your local vault only on this machine. No cloud sync, telemetry, or remote secrets.'
        self._label(si, side_text, fg=SUBTEXT, bg=si.cget('bg'), font=('Segoe UI', 10), wraplength=300).pack(anchor='w', pady=(8, 14))
        for heading, detail, icon in [
            ('100% Local & Private', 'Everything stays on your device.', '▣'),
            ('Zero-knowledge Architecture', 'The app never stores the master password.', '◉'),
            ('Strong Cryptography', 'AES-GCM and hardened key derivation.', '◆'),
            ('Offline-First', 'Works without internet access.', '◌'),
        ]:
            row = tk.Frame(si, bg=si.cget('bg'))
            row.pack(fill='x', pady=(0, 14))
            tk.Label(row, text=icon, bg=PANEL_DEEP, fg=self.accent, width=3, pady=5, font=('Segoe UI Semibold', 12), highlightthickness=1, highlightbackground=BORDER_SOFT).pack(side='left', anchor='n')
            text = tk.Frame(row, bg=row.cget('bg'))
            text.pack(side='left', fill='x', expand=True, padx=(10, 0))
            self._label(text, heading, bg=text.cget('bg'), font=('Segoe UI Semibold', 10)).pack(anchor='w')
            self._label(text, detail, fg=MUTED, bg=text.cget('bg'), font=('Segoe UI', 9), wraplength=235).pack(anchor='w', pady=(2, 0))

        def _adapt_auth_layout(_event=None) -> None:
            try:
                width = main.winfo_width()
                if width and width < 1040:
                    if side.winfo_manager():
                        side.pack_forget()
                    form_card.pack_configure(padx=(0, 0))
                    if right_art.winfo_manager():
                        right_art.pack_forget()
                else:
                    if not side.winfo_manager():
                        side.pack(side='right', fill='both', padx=(0, 0))
                    form_card.pack_configure(padx=(0, 18))
                    if not right_art.winfo_manager():
                        right_art.pack(side='right')
            except Exception:
                pass

        main.bind('<Configure>', _adapt_auth_layout, add='+')
        main.after_idle(_adapt_auth_layout)

        try:
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
