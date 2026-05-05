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
from .ui_pages_proof import build_proof_tab
from .core.system_health import collect_system_health, summarize_health

class PagesMixin:
    def _build_ui(self) -> None:
        shell = tk.Frame(self, bg=APP_BG)
        shell.pack(fill='both', expand=True)

        sidebar = tk.Frame(shell, bg=SIDEBAR_BG, width=198)
        sidebar.pack(side='left', fill='y')
        sidebar.pack_propagate(False)
        self.sidebar = sidebar

        main = tk.Frame(shell, bg=APP_BG)
        main.pack(side='right', fill='both', expand=True)
        self.main = main

        self._build_sidebar(sidebar)
        self._build_main_area(main)
        self._build_statusbar(main)
        self.show_view('dashboard')

    def _build_statusbar(self, parent: tk.Frame) -> None:
        bar = tk.Frame(parent, bg=PANEL_DEEP, padx=20, pady=10, highlightthickness=1, highlightbackground=BORDER)
        bar.pack(fill='x', side='bottom')
        self.status_badge = tk.Canvas(bar, width=14, height=14, bg=bar.cget('bg'), highlightthickness=0)
        self.status_badge.pack(side='left')
        self.status_badge.create_oval(2, 2, 12, 12, fill=self.accent, outline=self.accent)
        self._label(bar, textvariable=self.status_var, fg=SUBTEXT, bg=bar.cget('bg'), font=('Segoe UI', 9)).pack(side='left', padx=(8, 0))
        self._label(bar, 'Local • Encrypted • Offline-first', fg=MUTED, bg=bar.cget('bg'), font=('Segoe UI', 9)).pack(side='right')

    def _build_sidebar(self, parent: tk.Frame) -> None:
        top = tk.Frame(parent, bg=SIDEBAR_BG, padx=14, pady=16)
        top.pack(fill='x')

        mark = tk.Canvas(top, width=56, height=56, bg=SIDEBAR_BG, highlightthickness=0)
        mark.pack(anchor='w', pady=(0, 10))
        mark.create_oval(3, 3, 53, 53, fill=CARD_BG_2, outline=BORDER, width=2)
        mark.create_oval(9, 9, 47, 47, fill=self.accent, outline=self.accent)
        mark.create_text(28, 28, text='CV', fill=APP_BG, font=('Segoe UI Semibold', 15))

        self._label(top, 'CyberVault X', font=('Segoe UI Semibold', 16), bg=SIDEBAR_BG).pack(anchor='w')
        self._label(top, 'Security Control Center', fg=SUBTEXT, bg=SIDEBAR_BG, font=('Segoe UI', 9), wraplength=170).pack(anchor='w', pady=(2, 0))
        badge_row = tk.Frame(top, bg=SIDEBAR_BG)
        badge_row.pack(fill='x', pady=(10, 0))
        for label, color in [('LOCAL', self.accent), ('AES-GCM', None), ('OFFLINE', None)]:
            chip = tk.Label(badge_row, text=label, bg=(color or SURFACE_2), fg=(APP_BG if color else TEXT), padx=8, pady=4, font=('Segoe UI Semibold', 8))
            chip.pack(side='left', padx=(0, 5))

        nav_shell = tk.Frame(parent, bg=SIDEBAR_BG)
        nav_shell.pack(fill='both', expand=True)
        nav = tk.Frame(nav_shell, bg=SIDEBAR_BG, padx=10, pady=4)
        nav.pack(fill='x')

        def section(title: str) -> None:
            tk.Label(nav, text=title.upper(), bg=SIDEBAR_BG, fg=MUTED, font=('Segoe UI Semibold', 8), anchor='w').pack(fill='x', pady=(12, 5))

        section('Workspace')
        for key, label in [
            ('dashboard', 'Dashboard'),
            ('vault', 'Vault'),
            ('generator', 'Password Analyzer'),
            ('security', 'Risk Findings'),
            ('ai_guardian', 'AI Coach'),
        ]:
            self._sidebar_button(nav, key, label).pack(fill='x', pady=3)

        section('Delivery')
        for key, label in [
            ('reports', 'Reports'),
            ('backup_recovery', 'Backup / Recovery'),
            ('proof', 'Proof Center'),
            ('system_health', 'System Health'),
        ]:
            self._sidebar_button(nav, key, label).pack(fill='x', pady=3)

        section('Operations')
        for key, label in [('activity', 'Activity'), ('trash', 'Trash'), ('settings', 'Settings'), ('about', 'About')]:
            self._sidebar_button(nav, key, label).pack(fill='x', pady=3)

        helper = tk.Frame(parent, bg=CARD_BG, padx=12, pady=12, highlightthickness=1, highlightbackground=BORDER_SOFT)
        helper.pack(fill='x', padx=12, pady=(8, 0))
        self._label(helper, 'Demo flow', bg=helper.cget('bg'), font=('Segoe UI Semibold', 10)).pack(anchor='w')
        self._label(helper, 'Dashboard → Vault → Analyzer → Reports. Backup and Health are ready for Q&A.', fg=SUBTEXT, bg=helper.cget('bg'), font=('Segoe UI', 8), wraplength=166).pack(anchor='w', pady=(5, 0))

        footer = tk.Frame(parent, bg=PANEL_BG, padx=14, pady=14, highlightthickness=1, highlightbackground=BORDER)
        footer.pack(fill='x', padx=12, pady=14)
        self._label(footer, textvariable=self.vault_var, font=('Segoe UI Semibold', 10), bg=footer.cget('bg'), wraplength=168).pack(anchor='w')
        self._label(footer, textvariable=self.state_var, fg=SUBTEXT, bg=footer.cget('bg'), font=('Segoe UI', 9)).pack(anchor='w', pady=(5, 0))
        self._label(footer, textvariable=self.status_var, fg=MUTED, bg=footer.cget('bg'), font=('Segoe UI', 8), wraplength=168).pack(anchor='w', pady=(4, 8))
        ttk.Button(footer, text='!  Panic Lock', command=self.panic_lock, style='Danger.TButton').pack(fill='x')

    def _new_scroll_page(self, parent: tk.Widget) -> tuple[tk.Frame, tk.Frame]:
        """Return an outer page frame plus a scrollable body.

        This keeps dense product pages usable on 1366x768 laptops and projectors
        without clipping controls at the bottom of Settings, Vault, AI Guardian, or
        Proof Center.
        """
        outer = tk.Frame(parent, bg=APP_BG)
        canvas = tk.Canvas(outer, bg=APP_BG, highlightthickness=0, bd=0)
        scrollbar = ttk.Scrollbar(outer, orient='vertical', command=canvas.yview, style='Vertical.TScrollbar')
        body = tk.Frame(canvas, bg=APP_BG)
        window_id = canvas.create_window((0, 0), window=body, anchor='nw')
        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.pack(side='left', fill='both', expand=True)
        scrollbar.pack(side='right', fill='y')

        def sync_region(_event=None) -> None:
            try:
                canvas.configure(scrollregion=canvas.bbox('all'))
            except Exception:
                pass

        def sync_width(event) -> None:
            try:
                canvas.itemconfigure(window_id, width=event.width)
            except Exception:
                pass

        def on_mousewheel(event) -> None:
            # Avoid fighting with native Treeview scrolling when the cursor is inside tables.
            widget = getattr(event, 'widget', None)
            try:
                if widget and widget.winfo_class() == 'Treeview':
                    return
                if getattr(event, 'num', None) == 4:
                    canvas.yview_scroll(-1, 'units')
                elif getattr(event, 'num', None) == 5:
                    canvas.yview_scroll(1, 'units')
                else:
                    canvas.yview_scroll(int(-1 * (event.delta / 120)), 'units')
            except Exception:
                pass

        body.bind('<Configure>', sync_region)
        canvas.bind('<Configure>', sync_width)
        canvas.bind('<MouseWheel>', on_mousewheel)
        body.bind('<MouseWheel>', on_mousewheel)
        canvas.bind('<Button-4>', on_mousewheel)
        canvas.bind('<Button-5>', on_mousewheel)
        body.bind('<Button-4>', on_mousewheel)
        body.bind('<Button-5>', on_mousewheel)
        return outer, body

    def _build_main_area(self, parent: tk.Frame) -> None:
        header = tk.Frame(parent, bg=APP_BG, padx=16, pady=10)
        header.pack(fill='x')
        self._build_topbar(header)
        self._build_metrics(header)

        self.content_container = tk.Frame(parent, bg=APP_BG, padx=16, pady=0)
        self.content_container.pack(fill='both', expand=True)

        self.dashboard_page, self.dashboard_tab = self._new_scroll_page(self.content_container)
        self.vault_page, self.vault_tab = self._new_scroll_page(self.content_container)
        self.generator_page, self.generator_tab = self._new_scroll_page(self.content_container)
        self.security_page, self.security_tab = self._new_scroll_page(self.content_container)
        self.ai_guardian_page, self.ai_guardian_tab = self._new_scroll_page(self.content_container)
        self.reports_page, self.reports_tab = self._new_scroll_page(self.content_container)
        self.backup_recovery_page, self.backup_recovery_tab = self._new_scroll_page(self.content_container)
        self.proof_page, self.proof_tab = self._new_scroll_page(self.content_container)
        self.system_health_page, self.system_health_tab = self._new_scroll_page(self.content_container)
        self.activity_page, self.activity_tab = self._new_scroll_page(self.content_container)
        self.trash_page, self.trash_tab = self._new_scroll_page(self.content_container)
        self.settings_page, self.settings_tab = self._new_scroll_page(self.content_container)
        self.about_page, self.about_tab = self._new_scroll_page(self.content_container)
        self.pages = {
            'dashboard': self.dashboard_page,
            'vault': self.vault_page,
            'generator': self.generator_page,
            'security': self.security_page,
            'ai_guardian': self.ai_guardian_page,
            'reports': self.reports_page,
            'backup_recovery': self.backup_recovery_page,
            'proof': self.proof_page,
            'system_health': self.system_health_page,
            'activity': self.activity_page,
            'trash': self.trash_page,
            'settings': self.settings_page,
            'about': self.about_page,
        }

        self._build_dashboard_tab()
        self._build_vault_tab()
        self._build_generator_tab()
        self._build_security_tab()
        self._build_ai_guardian_tab()
        self._build_reports_tab()
        self._build_backup_recovery_tab()
        self._build_proof_tab()
        self._build_system_health_tab()
        self._build_activity_tab()
        self._build_trash_tab()
        self._build_settings_tab()
        self._build_about_tab()

    def _build_topbar(self, parent: tk.Frame) -> None:
        wrap = self._card(parent, bg=PANEL_DEEP, padx=16, pady=12)
        wrap.pack(fill='x')
        inner = wrap.inner
        left = tk.Frame(inner, bg=inner.cget('bg'))
        left.pack(side='left', fill='x', expand=True)
        self._label(left, textvariable=self.page_title_var, font=('Segoe UI Semibold', 17), bg=left.cget('bg')).pack(anchor='w')
        self._label(left, textvariable=self.page_subtitle_var, fg=SUBTEXT, bg=left.cget('bg'), font=('Segoe UI', 9), wraplength=760).pack(anchor='w', pady=(4, 0))
        top_pills = tk.Frame(left, bg=left.cget('bg'))
        top_pills.pack(anchor='w', pady=(9, 0))
        for pill_text, pill_color in [('LOCAL-FIRST', self.accent), ('AES-GCM', None), ('PRIVACY SAFE', None)]:
            self._status_pill(top_pills, pill_text, color=pill_color).pack(side='left', padx=(0, 6))

        context = tk.Frame(left, bg=left.cget('bg'))
        context.pack(fill='x', pady=(10, 0))
        self.page_context_badge = tk.Label(context, textvariable=self.page_context_var, bg=PAGE_COLORS.get('dashboard', self.accent), fg=APP_BG, padx=12, pady=6, font=('Segoe UI Semibold', 9))
        self.page_context_badge.pack(side='left', anchor='n')
        self._label(context, textvariable=self.page_tip_var, fg=MUTED, bg=context.cget('bg'), font=('Segoe UI', 9), wraplength=600).pack(side='left', padx=(10, 0), fill='x', expand=True)

        right = tk.Frame(inner, bg=inner.cget('bg'))
        right.pack(side='right')
        self._top_action_button(right, 'Add Credential', self.open_quick_add, kind='accent').pack(side='left')
        self._build_quick_actions_button(right).pack(side='left', padx=(8, 0))
        self._top_action_button(right, 'Lock', self.lock_vault).pack(side='left', padx=(8, 0))

    def _build_metrics(self, parent: tk.Frame) -> None:
        row = tk.Frame(parent, bg=APP_BG)
        row.pack(fill='x', pady=(12, 0))
        self.metrics_row = row
        defs = [
            ('total', 'Accounts', '◈'),
            ('health_score', 'Vault Health', '◎'),
            ('weak', 'Weak', '△'),
            ('breached', 'Breached', '◆'),
            ('reused_passwords', 'Reused', '↺'),
        ]
        for idx, (key, title, icon) in enumerate(defs):
            card = self._card(row, bg=CARD_BG, padx=0, pady=0, height=84)
            card.pack(side='left', fill='both', expand=True, padx=(0 if idx == 0 else 10, 0))
            accent_bar = tk.Frame(card, bg=self.accent, height=3)
            accent_bar.pack(fill='x', side='top')
            inner = tk.Frame(card, bg=CARD_BG, padx=14, pady=10)
            inner.pack(fill='both', expand=True)
            head = tk.Frame(inner, bg=inner.cget('bg'))
            head.pack(fill='x')
            bubble = tk.Label(head, text=icon, bg=CARD_BG_2, fg=self.accent, width=3, pady=2, font=('Segoe UI Semibold', 10))
            bubble.pack(side='left')
            self._label(head, title, fg=SUBTEXT, bg=head.cget('bg'), font=('Segoe UI', 10)).pack(side='left', padx=(8, 0))
            var = tk.StringVar(value='0')
            self.metric_vars[key] = var
            self._label(inner, textvariable=var, bg=inner.cget('bg'), font=('Segoe UI Semibold', 18)).pack(anchor='w', pady=(8, 0))

    def _build_dashboard_tab(self) -> None:
        root = self.dashboard_tab
        left_col = tk.Frame(root, bg=APP_BG)
        right_col = tk.Frame(root, bg=APP_BG, width=360)
        left_col.pack(side='left', fill='both', expand=True, padx=(0, 12))
        right_col.pack(side='right', fill='y')
        right_col.pack_propagate(False)

        hero = self._card(left_col, bg=CARD_BG_2, padx=22, pady=20)
        hero.pack(fill='x')
        hero_i = hero.inner
        head = tk.Frame(hero_i, bg=hero_i.cget('bg'))
        head.pack(fill='x')
        head_left = tk.Frame(head, bg=head.cget('bg'))
        head_left.pack(side='left', fill='x', expand=True)
        self._label(head_left, textvariable=self.dashboard_welcome_var, bg=head_left.cget('bg'), font=('Segoe UI Semibold', 17)).pack(anchor='w')
        self._label(head_left, 'A clean local command center for vault posture, active threats, and the next best fix.', fg=SUBTEXT, bg=head_left.cget('bg'), font=('Segoe UI', 10), wraplength=760).pack(anchor='w', pady=(4, 0))

        self.health_score_canvas = tk.Canvas(hero_i, width=760, height=150, bg=hero_i.cget('bg'), highlightthickness=0)
        self.health_score_canvas.pack(fill='x', pady=(14, 0))
        self._label(hero_i, textvariable=self.health_note_var, fg=SUBTEXT, bg=hero_i.cget('bg'), wraplength=760).pack(anchor='w', pady=(10, 0))

        hero_stats = tk.Frame(hero_i, bg=hero_i.cget('bg'))
        hero_stats.pack(fill='x', pady=(16, 0))
        self.dashboard_stat_vars = {}
        stat_defs = [
            ('critical', 'Critical'),
            ('breached', 'Breached'),
            ('reused', 'Reused'),
            ('rotation_due', 'Rotation Due'),
        ]
        for idx, (key, label) in enumerate(stat_defs):
            stat = tk.Frame(hero_stats, bg=CARD_BG, padx=14, pady=12, highlightthickness=1, highlightbackground=BORDER)
            stat.grid(row=0, column=idx, sticky='nsew', padx=(0 if idx == 0 else 10, 0))
            hero_stats.grid_columnconfigure(idx, weight=1)
            self._label(stat, label, fg=MUTED, bg=stat.cget('bg'), font=('Segoe UI', 9)).pack(anchor='w')
            var = tk.StringVar(value='0')
            self.dashboard_stat_vars[key] = var
            self._label(stat, textvariable=var, bg=stat.cget('bg'), font=('Segoe UI Semibold', 16)).pack(anchor='w', pady=(6, 0))

        rec_wrap = tk.Frame(left_col, bg=APP_BG)
        rec_wrap.pack(fill='both', expand=True, pady=(14, 0))

        rec_card = self._card(rec_wrap, bg=CARD_BG, padx=18, pady=18)
        rec_card.pack(side='left', fill='both', expand=True, padx=(0, 12))
        rec_i = rec_card.inner
        self._label(rec_i, 'Security Recommendations', fg=TEXT, bg=rec_i.cget('bg'), font=('Segoe UI Semibold', 13)).pack(anchor='w')
        self._label(rec_i, 'Action cards adapt to the current risk so the next step stays obvious.', fg=MUTED, bg=rec_i.cget('bg'), font=('Segoe UI', 9)).pack(anchor='w', pady=(4, 14))
        self.dashboard_recommendation_cards = []
        card_grid = tk.Frame(rec_i, bg=rec_i.cget('bg'))
        card_grid.pack(fill='both', expand=True)
        for idx in range(3):
            action_card = tk.Frame(card_grid, bg=CARD_BG_2, padx=16, pady=16, highlightthickness=1, highlightbackground=BORDER)
            action_card.grid(row=0, column=idx, sticky='nsew', padx=(0 if idx == 0 else 10, 0), pady=0)
            card_grid.grid_columnconfigure(idx, weight=1)
            title_var = tk.StringVar(value=f'Action {idx+1}')
            body_var = tk.StringVar(value='No recommendation available yet.')
            btn_text = tk.StringVar(value='Open')
            btn = ttk.Button(action_card, textvariable=btn_text, style='Ghost.TButton')
            self._label(action_card, textvariable=title_var, bg=action_card.cget('bg'), font=('Segoe UI Semibold', 12)).pack(anchor='w')
            self._label(action_card, textvariable=body_var, fg=SUBTEXT, bg=action_card.cget('bg'), wraplength=250, font=('Segoe UI', 9)).pack(anchor='w', pady=(8, 14))
            btn.pack(anchor='w')
            self.dashboard_recommendation_cards.append({'title': title_var, 'body': body_var, 'button': btn, 'button_text': btn_text})

        focus_card = self._card(rec_wrap, bg=CARD_BG, padx=18, pady=18, height=340)
        focus_card.pack(side='right', fill='y')
        fi = focus_card.inner
        self._label(fi, 'Next Best Action', bg=fi.cget('bg'), font=('Segoe UI Semibold', 13)).pack(anchor='w')
        self._label(fi, textvariable=self.dashboard_priority_var, fg=SUBTEXT, bg=fi.cget('bg'), wraplength=280).pack(anchor='w', pady=(10, 12))
        qa = tk.Frame(fi, bg=fi.cget('bg'))
        qa.pack(fill='x', pady=(4, 12))
        self._top_action_button(qa, 'Add Credential', self.open_quick_add, kind='accent').pack(fill='x')
        self._top_action_button(qa, 'Export Report', self.export_report).pack(fill='x', pady=(8, 0))
        # Workspace seeding is intentionally tucked under Quick Actions so the product UI stays clean.
        self.dashboard_response_var = tk.StringVar(value='Response workflow will appear here once the vault has data.')
        self._label(fi, 'Rapid Response', bg=fi.cget('bg'), font=('Segoe UI Semibold', 12)).pack(anchor='w', pady=(16, 0))
        self._label(fi, textvariable=self.dashboard_response_var, fg=MUTED, bg=fi.cget('bg'), wraplength=280).pack(anchor='w', pady=(8, 0))

        auth_card = self._card(right_col, bg=CARD_BG, padx=18, pady=18, height=332)
        auth_card.pack(fill='x')
        self.dashboard_auth_card = auth_card
        auth_i = auth_card.inner
        self._label(auth_i, 'Authentication Timeline', bg=auth_i.cget('bg'), font=('Segoe UI Semibold', 13)).pack(anchor='w')
        self.auth_timeline_note_var = tk.StringVar(value='Unlock successes, failures, and lock events appear here.')
        self._label(auth_i, textvariable=self.auth_timeline_note_var, fg=MUTED, bg=auth_i.cget('bg'), font=('Segoe UI', 9), wraplength=320).pack(anchor='w', pady=(4, 12))
        self.auth_timeline_wrap = tk.Frame(auth_i, bg=auth_i.cget('bg'))
        self.auth_timeline_wrap.pack(fill='both', expand=True)
        self.auth_timeline_rows = []
        for _ in range(4):
            row = tk.Frame(self.auth_timeline_wrap, bg=CARD_BG_2, padx=12, pady=10, highlightthickness=1, highlightbackground=BORDER)
            row.pack(fill='x', pady=(0, 8))
            dot = tk.Canvas(row, width=14, height=14, bg=row.cget('bg'), highlightthickness=0)
            dot.pack(side='left', anchor='n', pady=(4, 0))
            text_wrap = tk.Frame(row, bg=row.cget('bg'))
            text_wrap.pack(side='left', fill='x', expand=True, padx=(10, 0))
            title_var = tk.StringVar(value='Waiting for activity')
            detail_var = tk.StringVar(value='No events yet.')
            time_var = tk.StringVar(value='—')
            self._label(text_wrap, textvariable=title_var, bg=text_wrap.cget('bg'), font=('Segoe UI Semibold', 10)).pack(anchor='w')
            self._label(text_wrap, textvariable=detail_var, fg=MUTED, bg=text_wrap.cget('bg'), font=('Segoe UI', 9), wraplength=250).pack(anchor='w', pady=(3, 0))
            self._label(text_wrap, textvariable=time_var, fg=SUBTEXT, bg=text_wrap.cget('bg'), font=('Segoe UI', 8)).pack(anchor='w', pady=(5, 0))
            self.auth_timeline_rows.append({'frame': row, 'dot': dot, 'title': title_var, 'detail': detail_var, 'time': time_var})

        radar_card = self._card(right_col, bg=CARD_BG, padx=18, pady=18)
        radar_card.pack(fill='both', expand=True, pady=(14, 0))
        self.dashboard_radar_card = radar_card
        ri = radar_card.inner
        self._label(ri, 'Security Radar', bg=ri.cget('bg'), font=('Segoe UI Semibold', 13)).pack(anchor='w')
        self._label(ri, 'Risk buckets and score drivers update as the vault changes.', fg=MUTED, bg=ri.cget('bg'), font=('Segoe UI', 9), wraplength=320).pack(anchor='w', pady=(4, 12))
        radar_grid = tk.Frame(ri, bg=ri.cget('bg'))
        radar_grid.pack(fill='x')
        self.dashboard_radar_vars = {}
        for idx, (key, label) in enumerate((('Critical', 'Critical'), ('High', 'High'), ('Moderate', 'Moderate'), ('Low', 'Low'))):
            box = tk.Frame(radar_grid, bg=CARD_BG_2, padx=12, pady=10, highlightthickness=1, highlightbackground=BORDER)
            box.grid(row=idx // 2, column=idx % 2, sticky='nsew', padx=(0 if idx % 2 == 0 else 10, 0), pady=(0, 10))
            radar_grid.grid_columnconfigure(idx % 2, weight=1)
            self._label(box, label, fg=MUTED, bg=box.cget('bg'), font=('Segoe UI', 9)).pack(anchor='w')
            var = tk.StringVar(value='0')
            self.dashboard_radar_vars[key] = var
            self._label(box, textvariable=var, bg=box.cget('bg'), font=('Segoe UI Semibold', 16)).pack(anchor='w', pady=(6, 0))
        self.dashboard_ops_var = tk.StringVar(value='Local only • AES-GCM • PBKDF2 • Offline breach checks')
        self.dashboard_score_story_var = tk.StringVar(value='Score story will appear here after the first credential is added.')
        self._label(ri, textvariable=self.dashboard_ops_var, fg=TEXT, bg=ri.cget('bg'), font=('Segoe UI Semibold', 10), wraplength=300).pack(anchor='w', pady=(4, 0))
        self._label(ri, textvariable=self.dashboard_score_story_var, fg=SUBTEXT, bg=ri.cget('bg'), wraplength=300).pack(anchor='w', pady=(8, 0))

    def _render_auth_timeline(self, rows: list[dict[str, str]]) -> None:
        if not hasattr(self, 'auth_timeline_rows'):
            return
        display_rows = list(rows[:len(self.auth_timeline_rows)])
        while len(display_rows) < len(self.auth_timeline_rows):
            display_rows.append({'action': 'Waiting for activity', 'details': 'No additional auth events yet.', 'timestamp': ''})
        palette = {
            'success': SUCCESS,
            'warning': WARNING,
            'danger': DANGER,
            'info': self.accent,
        }
        for widget_row, event in zip(self.auth_timeline_rows, display_rows):
            action = event.get('action', 'Activity')
            details = event.get('details', 'No details captured.')
            when = self._fmt_dt(event.get('timestamp', ''))
            lowered = action.lower()
            level = 'info'
            if 'failed' in lowered:
                level = 'danger'
            elif 'success' in lowered or 'revealed' in lowered or 'backup' in lowered:
                level = 'success'
            elif 'locked' in lowered or 'panic' in lowered:
                level = 'warning'
            widget_row['title'].set(action)
            widget_row['detail'].set(details)
            widget_row['time'].set(when if when != '-' else 'Awaiting activity')
            dot = widget_row['dot']
            dot.delete('all')
            dot.create_oval(2, 2, 12, 12, fill=palette[level], outline=palette[level])

    def _render_dashboard_radar(self, metrics: dict, findings: list[dict]) -> None:
        if not hasattr(self, 'dashboard_radar_vars'):
            return
        risk_counts = {'Critical': 0, 'High': 0, 'Moderate': 0, 'Low': 0}
        for finding in findings:
            risk = finding.get('risk_level', 'Low')
            if risk in risk_counts:
                risk_counts[risk] += 1
        for key, var in self.dashboard_radar_vars.items():
            var.set(str(risk_counts.get(key, 0)))
        if hasattr(self, 'dashboard_stat_vars'):
            self.dashboard_stat_vars['critical'].set(str(risk_counts['Critical']))
            self.dashboard_stat_vars['breached'].set(str(metrics.get('breached', 0)))
            self.dashboard_stat_vars['reused'].set(str(metrics.get('reused_passwords', 0)))
            self.dashboard_stat_vars['rotation_due'].set(str(metrics.get('old', 0)))
        score = int(metrics.get('health_score', 0) or 0)
        weak = int(metrics.get('weak', 0) or 0)
        breached = int(metrics.get('breached', 0) or 0)
        reused = int(metrics.get('reused_passwords', 0) or 0)
        old = int(metrics.get('old', 0) or 0)
        drivers = []
        if breached:
            drivers.append(f'{breached} breached')
        if weak:
            drivers.append(f'{weak} weak')
        if reused:
            drivers.append(f'{reused} reused')
        if old:
            drivers.append(f'{old} stale')
        self.dashboard_ops_var.set(f"{self.vault_var.get()} • Auto-lock {self.auto_lock_var.get()} min • Clipboard {self.clipboard_clear_var.get()}s • Last backup {self.last_backup_var.get().replace('Last backup: ', '')}")
        if not drivers:
            self.dashboard_score_story_var.set('The current score is driven mostly by healthy unique credentials, completed metadata, and low exposure.')
            self.dashboard_response_var.set('Maintain momentum: keep exporting encrypted backups, rotate old secrets on schedule, and preserve unique passwords across every site.')
            return
        driver_text = ', '.join(drivers[:4])
        self.dashboard_score_story_var.set(f'Score {score}/100 is currently being pushed by {driver_text}. The fastest wins are in Security Center and the Generator.')
        if breached or risk_counts['Critical']:
            self.dashboard_response_var.set('Start with breached or critical credentials, replace them with generator output, then export the executive report to show measurable improvement.')
        elif reused or weak:
            self.dashboard_response_var.set('Open Security Center, sort risky credentials, generate unique replacements, and resave the edited credentials to raise the score quickly.')
        else:
            self.dashboard_response_var.set('Finish metadata, verify backups, and clean Trash so the vault reads like a polished production product during the walkthrough.')

    def _set_dashboard_side_state(self, has_data: bool) -> None:
        if not hasattr(self, 'dashboard_radar_card') or not hasattr(self, 'dashboard_auth_card'):
            return
        if has_data:
            if not self.dashboard_radar_card.winfo_manager():
                self.dashboard_radar_card.pack(fill='both', expand=True, pady=(14, 0))
            self.auth_timeline_note_var.set('Unlock successes, failures, and lock events appear here.')
        else:
            if self.dashboard_radar_card.winfo_manager():
                self.dashboard_radar_card.pack_forget()
            self.auth_timeline_note_var.set('No credential data yet. Add a record or import CSV to activate live auth and risk storytelling.')

    def _build_vault_tab(self) -> None:
        root = self.vault_tab

        command = self._card(root, bg=CARD_BG_2, padx=18, pady=18)
        command.pack(fill='x', pady=(0, 12))
        ci = command.inner
        left = tk.Frame(ci, bg=ci.cget('bg'))
        left.pack(side='left', fill='both', expand=True)
        self._label(left, 'Vault Command Center', bg=left.cget('bg'), font=('Segoe UI Semibold', 14)).pack(anchor='w')
        self._label(left, 'Risk score, encryption posture, last backup, and quick actions in one premium control panel.', fg=MUTED, bg=left.cget('bg'), font=('Segoe UI', 9), wraplength=720).pack(anchor='w', pady=(4, 12))
        self.vault_command_canvas = tk.Canvas(left, width=500, height=126, bg=left.cget('bg'), highlightthickness=0)
        self.vault_command_canvas.pack(anchor='w')
        meta = tk.Frame(left, bg=left.cget('bg'))
        meta.pack(anchor='w', pady=(10, 0))
        self._label(meta, textvariable=self.command_encryption_var, fg=TEXT, bg=meta.cget('bg'), font=('Segoe UI Semibold', 10)).pack(anchor='w')
        self._label(meta, textvariable=self.command_exposure_var, fg=SUBTEXT, bg=meta.cget('bg')).pack(anchor='w', pady=(4, 0))
        self._label(meta, textvariable=self.command_backup_var, fg=SUBTEXT, bg=meta.cget('bg')).pack(anchor='w', pady=(4, 0))
        self._label(meta, textvariable=self.command_note_var, fg=MUTED, bg=meta.cget('bg'), wraplength=760).pack(anchor='w', pady=(8, 0))

        right = tk.Frame(ci, bg=ci.cget('bg'))
        right.pack(side='right', fill='y')
        self._top_action_button(right, 'Add Credential', self.open_quick_add, kind='accent').pack(fill='x')
        self._top_action_button(right, 'Import CSV', self.import_csv).pack(fill='x', pady=(8, 0))
        self._top_action_button(right, 'Export Report', self.export_report).pack(fill='x', pady=(8, 0))
        # Curated workspace seeding is available from Quick Actions when needed.
        self._top_action_button(right, 'Quick Tour', self.show_quick_tour).pack(fill='x', pady=(8, 0))

        toolbar = self._card(root, bg=PANEL_DEEP, padx=16, pady=14)
        toolbar.pack(fill='x', pady=(0, 12))
        tb = toolbar.inner
        controls = tk.Frame(tb, bg=tb.cget('bg'))
        controls.pack(fill='x')
        left = tk.Frame(controls, bg=tb.cget('bg'))
        left.pack(side='left', fill='x', expand=True)
        search = ttk.Entry(left, textvariable=self.search_var, width=32)
        search.pack(side='left')
        search.bind('<Return>', lambda _e: self.refresh_all())
        self._top_action_button(left, 'Search', self.refresh_all).pack(side='left', padx=(8, 8))
        ttk.Combobox(left, textvariable=self.category_filter_var, values=['All', *CATEGORIES], state='readonly', width=18).pack(side='left')
        ttk.Combobox(left, textvariable=self.threat_filter_var, values=['All Status', 'Weak', 'Breached', 'Reused', 'Old', 'Favorites', 'Recent'], state='readonly', width=16).pack(side='left', padx=(8, 0))
        self._top_action_button(left, 'Clear', self._clear_filters).pack(side='left', padx=(8, 0))
        right = tk.Frame(controls, bg=tb.cget('bg'))
        right.pack(side='right')
        self._top_action_button(right, 'Focus Mode', self.toggle_presentation_mode).pack(side='left')

        quick_filters = tk.Frame(tb, bg=tb.cget('bg'))
        quick_filters.pack(fill='x', pady=(12, 0))
        self._label(quick_filters, textvariable=self.filter_summary_var, fg=SUBTEXT, bg=quick_filters.cget('bg'), font=('Segoe UI', 9)).pack(side='left')
        chip_wrap = tk.Frame(quick_filters, bg=quick_filters.cget('bg'))
        chip_wrap.pack(side='right')
        self.threat_filter_buttons = {}
        for label, value in [('Weak', 'Weak'), ('Breached', 'Breached'), ('Reused', 'Reused'), ('Favorites', 'Favorites'), ('Recent', 'Recent')]:
            btn = ttk.Button(chip_wrap, text=label, command=lambda v=value: self._set_threat_filter(v), style='Pill.TButton')
            btn.pack(side='left', padx=(8, 0))
            self.threat_filter_buttons[value] = {'button': btn, 'label': label}

        main = tk.Frame(root, bg=APP_BG)
        main.pack(fill='both', expand=True)
        left_col = tk.Frame(main, bg=APP_BG)
        right_col = tk.Frame(main, bg=APP_BG, width=470)
        left_col.pack(side='left', fill='both', expand=True, padx=(0, 12))
        right_col.pack(side='right', fill='y')
        right_col.pack_propagate(False)

        table_card = self._card(left_col, bg=CARD_BG, padx=14, pady=14)
        table_card.pack(fill='both', expand=True)
        ti = table_card.inner
        head = tk.Frame(ti, bg=ti.cget('bg'))
        head.pack(fill='x', pady=(0, 12))
        self._label(head, 'Encrypted Credential Vault', bg=head.cget('bg'), font=('Segoe UI Semibold', 13)).pack(side='left')
        self._label(head, 'Search, filter, import, analyze, and manage encrypted credentials locally.', fg=MUTED, bg=head.cget('bg'), font=('Segoe UI', 9)).pack(side='left', padx=(10, 0))
        cols = ('title', 'username', 'category', 'tags', 'updated')
        self.tree = ttk.Treeview(ti, columns=cols, show='headings', selectmode='browse', height=13)
        widths = {'title': 220, 'username': 220, 'category': 120, 'tags': 170, 'updated': 170}
        for c, label in [('title', 'Title'), ('username', 'Username'), ('category', 'Category'), ('tags', 'Tags'), ('updated', 'Updated')]:
            self.tree.heading(c, text=label)
            self.tree.column(c, width=widths[c], anchor='w', stretch=True)
        self.tree.pack(fill='both', expand=True)
        self._configure_tree_visuals(self.tree)
        self._attach_tree_scrollbars(self.tree)
        self.tree.bind('<<TreeviewSelect>>', self.on_select_credential)
        self.empty_state = tk.Frame(ti, bg=CARD_BG_2, padx=28, pady=26, highlightthickness=1, highlightbackground='#20314f')
        self.empty_state.place(relx=0.5, rely=0.5, anchor='center')
        self._label(self.empty_state, 'Start your secure vault', bg=self.empty_state.cget('bg'), font=('Segoe UI Semibold', 15)).pack()
        self._label(self.empty_state, 'Import browser data, add your first credential, or load a curated assessment scenario to showcase weak, breached, reused, and stale accounts.', fg=SUBTEXT, bg=self.empty_state.cget('bg'), wraplength=440, justify='center').pack(pady=(8, 12))
        steps = tk.Frame(self.empty_state, bg=self.empty_state.cget('bg'))
        steps.pack(pady=(0, 14))
        for text_value in ('1. Add or import credentials', '2. Analyze vault posture', '3. Export executive report'):
            tk.Label(steps, text=text_value, bg=SURFACE_2, fg=TEXT, padx=10, pady=6, font=('Segoe UI Semibold', 8)).pack(side='left', padx=4)
        actions = tk.Frame(self.empty_state, bg=self.empty_state.cget('bg'))
        actions.pack()
        ttk.Button(actions, text='Add First Credential', command=self.open_quick_add, style='Accent.TButton').pack(side='left')
        ttk.Button(actions, text='Import Browser CSV', command=self.import_csv, style='Pill.TButton').pack(side='left', padx=(8, 0))
        # Curated assessment workspace is available from Quick Actions; primary empty-state stays product-focused.

        editor = self._card(right_col, bg=CARD_BG, padx=18, pady=18)
        editor.pack(fill='both', expand=True)
        ei = editor.inner
        self._label(ei, 'Credential Workspace', bg=ei.cget('bg'), font=('Segoe UI Semibold', 13)).pack(anchor='w')
        self._label(ei, 'Tabs keep editing, intelligence, and history separated so the right panel stays readable on small screens.', fg=MUTED, bg=ei.cget('bg'), font=('Segoe UI', 9), wraplength=430).pack(anchor='w', pady=(4, 12))

        self.credential_notebook = ttk.Notebook(ei)
        self.credential_notebook.pack(fill='both', expand=True)
        profile_tab = tk.Frame(self.credential_notebook, bg=CARD_BG, padx=2, pady=12)
        intel_tab = tk.Frame(self.credential_notebook, bg=CARD_BG, padx=2, pady=12)
        history_tab = tk.Frame(self.credential_notebook, bg=CARD_BG, padx=2, pady=12)
        self.credential_notebook.add(profile_tab, text='Details')
        self.credential_notebook.add(intel_tab, text='Intelligence')
        self.credential_notebook.add(history_tab, text='History')
        ei = profile_tab

        site_row = tk.Frame(ei, bg=CARD_BG_2, padx=12, pady=12, highlightthickness=1, highlightbackground=BORDER)
        site_row.pack(fill='x')
        self.site_canvas = tk.Canvas(site_row, width=58, height=58, bg=CARD_BG_2, highlightthickness=0)
        self.site_canvas.pack(side='left')
        self.site_image_label = tk.Label(site_row, bg=CARD_BG_2)
        self.site_image_label.place(x=13, y=13)
        info = tk.Frame(site_row, bg=CARD_BG_2)
        info.pack(side='left', fill='x', expand=True, padx=(12, 0))
        self._label(info, textvariable=self.site_host_var, bg=info.cget('bg'), font=('Segoe UI Semibold', 11)).pack(anchor='w')
        self._label(info, textvariable=self.copy_stats_var, fg=MUTED, bg=info.cget('bg'), font=('Segoe UI', 9)).pack(anchor='w', pady=(4, 0))
        self.credential_badges = tk.Frame(info, bg=info.cget('bg'))
        self.credential_badges.pack(anchor='w', pady=(8, 0))

        self._labeled_entry(ei, 'Title', self.title_var)
        self._labeled_entry(ei, 'Website / URL', self.website_var)
        self._category_row(ei)
        self._labeled_entry(ei, 'Username / Email', self.username_var)
        self._password_row(ei)
        coach = tk.Frame(ei, bg=PANEL_DEEP, padx=12, pady=12, highlightthickness=1, highlightbackground=BORDER_SOFT)
        coach.pack(fill='x', pady=(10, 0))
        top = tk.Frame(coach, bg=coach.cget('bg'))
        top.pack(fill='x')
        self._label(top, 'Live Password Coach', bg=top.cget('bg'), font=('Segoe UI Semibold', 10)).pack(side='left')
        self._label(top, textvariable=self.site_fit_var, fg=self.accent, bg=top.cget('bg'), font=('Segoe UI Semibold', 10)).pack(side='right')
        self.live_coach_canvas = tk.Canvas(coach, width=430, height=54, bg=coach.cget('bg'), highlightthickness=0)
        self.live_coach_canvas.pack(fill='x', pady=(8, 0))
        self._label(coach, textvariable=self.live_coach_var, fg=TEXT, bg=coach.cget('bg'), font=('Segoe UI Semibold', 9), wraplength=430).pack(anchor='w', pady=(6, 0))
        self._label(coach, textvariable=self.live_coach_hint_var, fg=MUTED, bg=coach.cget('bg'), font=('Segoe UI', 9), wraplength=430).pack(anchor='w', pady=(3, 0))
        self._label(coach, textvariable=self.live_coach_status_var, fg=self.accent, bg=coach.cget('bg'), font=('Segoe UI Semibold', 9), wraplength=430).pack(anchor='w', pady=(6, 0))
        self._label(coach, textvariable=self.live_coach_action_var, fg=SUBTEXT, bg=coach.cget('bg'), font=('Segoe UI', 9), wraplength=430).pack(anchor='w', pady=(2, 0))
        chip_grid = tk.Frame(coach, bg=coach.cget('bg'))
        chip_grid.pack(fill='x', pady=(10, 0))
        self.live_coach_chip_vars = {}
        self.live_coach_chip_frames = {}
        for idx, key in enumerate(('length', 'mix', 'context', 'sitefit', 'mfa', 'form')):
            chip = tk.Frame(chip_grid, bg=CARD_BG, padx=8, pady=7, highlightthickness=1, highlightbackground=BORDER_SOFT)
            chip.grid(row=idx // 3, column=idx % 3, sticky='nsew', padx=(0 if idx % 3 == 0 else 6, 0), pady=(0 if idx < 3 else 6, 0))
            chip_grid.grid_columnconfigure(idx % 3, weight=1)
            title_var = tk.StringVar(value=key.title())
            value_var = tk.StringVar(value='Waiting')
            self.live_coach_chip_vars[key] = {'title': title_var, 'value': value_var}
            self.live_coach_chip_frames[key] = chip
            self._label(chip, textvariable=title_var, fg=MUTED, bg=chip.cget('bg'), font=('Segoe UI', 7)).pack(anchor='w')
            self._label(chip, textvariable=value_var, fg=TEXT, bg=chip.cget('bg'), font=('Segoe UI Semibold', 8), wraplength=120).pack(anchor='w', pady=(3, 0))
        self._labeled_entry(ei, 'Tags (comma-separated)', self.tags_var)

        self._label(ei, 'Encrypted Notes', bg=ei.cget('bg'), font=('Segoe UI Semibold', 10)).pack(anchor='w', pady=(10, 0))
        self.notes_text = tk.Text(ei, height=5, wrap='word', bg=INPUT_BG, fg=TEXT, insertbackground=TEXT, relief='flat', bd=0, padx=10, pady=8)
        self.notes_text.pack(fill='x', pady=(6, 0))
        self._style_text_widget(self.notes_text)
        self._label(ei, textvariable=self.created_var, fg=MUTED, bg=ei.cget('bg'), font=('Segoe UI', 9)).pack(anchor='w', pady=(10, 0))
        self._label(ei, textvariable=self.updated_var, fg=MUTED, bg=ei.cget('bg'), font=('Segoe UI', 9)).pack(anchor='w', pady=(2, 0))

        actions = tk.Frame(ei, bg=ei.cget('bg'))
        actions.pack(fill='x', pady=(14, 0))
        ttk.Button(actions, text='New', command=self.clear_editor, style='Ghost.TButton').pack(side='left')
        ttk.Button(actions, text='Save', command=self.save_credential, style='Accent.TButton').pack(side='left', padx=(8, 0))
        ttk.Button(actions, text='Trash', command=self.move_selected_to_trash, style='Danger.TButton').pack(side='left', padx=(8, 0))

        quick = tk.Frame(ei, bg=ei.cget('bg'))
        quick.pack(fill='x', pady=(10, 0))
        for text, cmd in [
            ('Reveal', self.begin_reveal),
            ('Copy User', lambda: self.copy_field('username')),
            ('Copy Pass', lambda: self.copy_field('password')),
            ('Copy Site', lambda: self.copy_field('website')),
            ('Open Site', self.open_website),
        ]:
            ttk.Button(quick, text=text, command=cmd, style='Ghost.TButton').pack(side='left', padx=(0, 8))

        ei = intel_tab
        analysis = self._card(ei, bg=CARD_BG_2, padx=14, pady=14)
        analysis.pack(fill='both', expand=True, pady=(14, 0))
        ai = analysis.inner
        self._label(ai, 'Password Intelligence', bg=ai.cget('bg'), font=('Segoe UI Semibold', 12)).pack(anchor='w')
        self.strength_var = tk.StringVar(value='Strength: -')
        self.entropy_var = tk.StringVar(value='Entropy: -')
        self.entropy_note_var = tk.StringVar(value='Entropy explanation: -')
        self.issue_var = tk.StringVar(value='Issues: -')
        self._label(ai, textvariable=self.strength_var, bg=ai.cget('bg'), font=('Segoe UI Semibold', 11)).pack(anchor='w', pady=(10, 0))
        self._label(ai, textvariable=self.entropy_var, fg=SUBTEXT, bg=ai.cget('bg')).pack(anchor='w', pady=(3, 0))
        self._label(ai, textvariable=self.entropy_note_var, fg=SUBTEXT, bg=ai.cget('bg'), wraplength=430).pack(anchor='w', pady=(3, 0))
        self._label(ai, textvariable=self.issue_var, bg=ai.cget('bg'), wraplength=430).pack(anchor='w', pady=(8, 0))
        policy = tk.Frame(ai, bg=PANEL_DEEP, padx=12, pady=10, highlightthickness=1, highlightbackground=BORDER_SOFT)
        policy.pack(fill='x', pady=(12, 0))
        self._label(policy, textvariable=self.site_policy_var, bg=policy.cget('bg'), font=('Segoe UI Semibold', 10), wraplength=420).pack(anchor='w')
        self._label(policy, textvariable=self.site_policy_detail_var, fg=SUBTEXT, bg=policy.cget('bg'), font=('Segoe UI', 9), wraplength=420).pack(anchor='w', pady=(4, 0))
        self._label(ai, 'Site Requirement Checklist', fg=MUTED, bg=ai.cget('bg'), font=('Segoe UI', 9)).pack(anchor='w', pady=(12, 0))
        self.site_policy_text = tk.Text(ai, height=7, wrap='word', bg=INPUT_BG, fg=TEXT, insertbackground=TEXT, relief='flat', bd=0, padx=10, pady=10)
        self.site_policy_text.pack(fill='both', expand=True, pady=(6, 0))
        self._style_text_widget(self.site_policy_text)
        self.site_policy_text.configure(state='disabled')
        self._label(ai, 'Suggestions', fg=MUTED, bg=ai.cget('bg'), font=('Segoe UI', 9)).pack(anchor='w', pady=(10, 0))
        self.suggestions_text = tk.Text(ai, height=6, wrap='word', bg=INPUT_BG, fg=TEXT, insertbackground=TEXT, relief='flat', bd=0, padx=10, pady=10)
        self.suggestions_text.pack(fill='both', expand=True, pady=(6, 0))
        self._style_text_widget(self.suggestions_text)
        self.suggestions_text.configure(state='disabled')

        ei = history_tab
        hist = self._card(ei, bg=CARD_BG_2, padx=14, pady=14)
        hist.pack(fill='x', pady=(14, 0))
        hi = hist.inner
        self._label(hi, 'Password History', bg=hi.cget('bg'), font=('Segoe UI Semibold', 12)).pack(anchor='w')
        self._label(hi, 'Old passwords stay masked by default. Reveal or copy requires master-password re-authentication.', fg=MUTED, bg=hi.cget('bg'), font=('Segoe UI', 9), wraplength=430).pack(anchor='w', pady=(4, 8))
        cols = ('changed', 'strength', 'preview')
        self.history_tree = ttk.Treeview(hi, columns=cols, show='headings', selectmode='browse', height=4)
        for c, label, width in [('changed', 'Changed At', 150), ('strength', 'Strength', 100), ('preview', 'Masked Preview', 180)]:
            self.history_tree.heading(c, text=label)
            self.history_tree.column(c, width=width, anchor='w')
        self.history_tree.pack(fill='x', pady=(0, 8))
        self._configure_tree_visuals(self.history_tree)
        self._attach_tree_scrollbars(self.history_tree)
        history_actions = tk.Frame(hi, bg=hi.cget('bg'))
        history_actions.pack(fill='x')
        ttk.Button(history_actions, text='Reveal Old', command=self.reveal_history_password, style='Ghost.TButton').pack(side='left')
        ttk.Button(history_actions, text='Copy Old', command=self.copy_history_password, style='Pill.TButton').pack(side='left', padx=(8, 0))
        self.history_hint_var = tk.StringVar(value='No password history selected.')
        self._label(hi, textvariable=self.history_hint_var, fg=SUBTEXT, bg=hi.cget('bg'), font=('Segoe UI', 9), wraplength=430).pack(anchor='w', pady=(8, 0))

    def _password_row(self, parent: tk.Widget) -> None:
        self._label(parent, 'Password', bg=parent.cget('bg'), font=('Segoe UI Semibold', 10)).pack(anchor='w', pady=(10, 0))
        row = tk.Frame(parent, bg=parent.cget('bg'))
        row.pack(fill='x', pady=(6, 0))
        self.password_entry = tk.Entry(row, textvariable=self.password_var, show='*', bg=INPUT_BG, fg=TEXT, insertbackground=TEXT, relief='flat', bd=0, highlightthickness=1, highlightbackground=INPUT_BORDER, highlightcolor=self.accent)
        self.password_entry.pack(side='left', fill='x', expand=True)
        ttk.Button(row, text='◔', command=self.begin_reveal, style='Pill.TButton').pack(side='left', padx=(8, 0))
        ttk.Button(row, text='Analyze', command=self.open_analysis_modal, style='Pill.TButton').pack(side='left', padx=(8, 0))
        ttk.Button(row, text='Tune', command=self.apply_generator_to_current_site, style='Pill.TButton').pack(side='left', padx=(8, 0))

    def _category_row(self, parent: tk.Widget) -> None:
        row = tk.Frame(parent, bg=parent.cget('bg'))
        row.pack(fill='x', pady=(10, 0))
        left = tk.Frame(row, bg=row.cget('bg'))
        left.pack(side='left', fill='x', expand=True)
        self._label(left, 'Category', bg=left.cget('bg'), font=('Segoe UI Semibold', 10)).pack(anchor='w')
        ttk.Combobox(left, textvariable=self.category_var, values=CATEGORIES, state='readonly').pack(fill='x', pady=(6, 0))
        fav = tk.Frame(row, bg=row.cget('bg'))
        fav.pack(side='left', padx=(12, 0))
        self._label(fav, 'Favorite', bg=fav.cget('bg'), font=('Segoe UI Semibold', 10)).pack(anchor='w')
        ttk.Checkbutton(fav, variable=self.favorite_var).pack(anchor='w', pady=(6, 0))

    def _build_security_tab(self) -> None:
        root = self.security_tab
        top = self._card(root, bg=PANEL_DEEP, padx=16, pady=14)
        top.pack(fill='x', pady=(0, 12))
        ti = top.inner
        self._label(ti, 'Security Findings', bg=ti.cget('bg'), font=('Segoe UI Semibold', 13)).pack(side='left')
        self._label(ti, 'Weak alerts, offline breach hits, reuse, age, metadata hygiene, and score explainability in one analyst-ready queue.', fg=MUTED, bg=ti.cget('bg'), font=('Segoe UI', 9)).pack(side='left', padx=(10, 0))
        buttons = tk.Frame(ti, bg=ti.cget('bg'))
        buttons.pack(side='right')
        ttk.Button(buttons, text='Export Report', command=self.export_report, style='Ghost.TButton').pack(side='left')
        ttk.Button(buttons, text='Refresh Findings', command=self.refresh_all, style='Accent.TButton').pack(side='left', padx=(8, 0))

        summary = self._card(root, bg=CARD_BG_2, padx=16, pady=16)
        summary.pack(fill='x', pady=(0, 12))
        si = summary.inner
        self._label(si, 'Risk Distribution & Health Signals', bg=si.cget('bg'), font=('Segoe UI Semibold', 13)).pack(anchor='w')
        self._label(si, 'A cleaner executive snapshot for critical, high, moderate, and low findings plus the operational drivers behind the score.', fg=MUTED, bg=si.cget('bg'), font=('Segoe UI', 9), wraplength=1180).pack(anchor='w', pady=(4, 14))
        grid = tk.Frame(si, bg=si.cget('bg'))
        grid.pack(fill='x')
        self.sec_metric_vars = {}
        defs = [
            ('health_score', 'Health Score'),
            ('critical', 'Critical'),
            ('high', 'High'),
            ('breached', 'Breached'),
            ('reused_passwords', 'Reused'),
            ('old', 'Old'),
            ('missing_fields', 'Missing Metadata'),
            ('duplicate_sites', 'Duplicate Sites'),
        ]
        for idx, (key, title) in enumerate(defs):
            card = tk.Frame(grid, bg=CARD_BG, padx=14, pady=12, highlightthickness=1, highlightbackground=BORDER)
            card.grid(row=idx // 4, column=idx % 4, sticky='nsew', padx=(0 if idx % 4 == 0 else 10, 0), pady=(0, 10))
            grid.grid_columnconfigure(idx % 4, weight=1)
            self._label(card, title, fg=MUTED, bg=card.cget('bg'), font=('Segoe UI', 9)).pack(anchor='w')
            var = tk.StringVar(value='0')
            self.sec_metric_vars[key] = var
            self._label(card, textvariable=var, bg=card.cget('bg'), font=('Segoe UI Semibold', 18)).pack(anchor='w', pady=(8, 0))

        main = tk.Frame(root, bg=APP_BG)
        main.pack(fill='both', expand=True)
        left = self._card(main, bg=CARD_BG, padx=14, pady=14)
        left.pack(side='left', fill='both', expand=True, padx=(0, 12))
        right = self._card(main, bg=CARD_BG_2, padx=16, pady=16, height=500)
        right.pack(side='right', fill='y')

        li = left.inner
        cols = ('title', 'score', 'issues')
        self.security_tree = ttk.Treeview(li, columns=cols, show='headings', selectmode='browse')
        for c, label, width in [('title', 'Credential', 220), ('score', 'Score', 80), ('issues', 'Issues', 640)]:
            self.security_tree.heading(c, text=label)
            self.security_tree.column(c, width=width, anchor='w')
        self.security_tree.pack(fill='both', expand=True)
        self._configure_tree_visuals(self.security_tree)
        self._attach_tree_scrollbars(self.security_tree)
        self.security_tree.bind('<<TreeviewSelect>>', self.on_select_finding)
        security_actions = tk.Frame(li, bg=li.cget('bg'))
        security_actions.pack(fill='x', pady=(10, 0))
        ttk.Button(security_actions, text='Open in Vault', command=self.open_selected_security_in_vault, style='Accent.TButton').pack(side='left')
        ttk.Button(security_actions, text='Generate Replacement', command=self.generate_replacement_for_security, style='Pill.TButton').pack(side='left', padx=(8, 0))
        ttk.Button(security_actions, text='Mark Reviewed', command=self.mark_security_finding_reviewed, style='Pill.TButton').pack(side='left', padx=(8, 0))
        self.security_empty_state = tk.Frame(li, bg=CARD_BG_2, padx=26, pady=24, highlightthickness=1, highlightbackground=BORDER)
        self._label(self.security_empty_state, 'No security findings yet', bg=self.security_empty_state.cget('bg'), font=('Segoe UI Semibold', 14)).pack()
        self._label(self.security_empty_state, 'Add credentials or import a browser CSV to populate breach intelligence, duplicate detection, stale-password checks, and the executive score story.', fg=SUBTEXT, bg=self.security_empty_state.cget('bg'), wraplength=400, justify='center').pack(pady=(8, 12))
        act = tk.Frame(self.security_empty_state, bg=self.security_empty_state.cget('bg'))
        act.pack()
        ttk.Button(act, text='Add Credential', command=self.open_quick_add, style='Accent.TButton').pack(side='left')
        # Workspace setup action is available from Quick Actions for clean product presentation.

        ri = right.inner
        self._label(ri, 'Local Breach Intelligence', bg=ri.cget('bg'), font=('Segoe UI Semibold', 13)).pack(anchor='w')
        self._label(ri, 'Known leaked/common password status, why the risk matters, the fastest remediation path, and a clean score narrative.', fg=MUTED, bg=ri.cget('bg'), font=('Segoe UI', 9), wraplength=430).pack(anchor='w', pady=(4, 12))
        self.breach_intel_text = tk.Text(ri, height=10, wrap='word', bg=INPUT_BG, fg=TEXT, insertbackground=TEXT, relief='flat', bd=0, padx=10, pady=10)
        self.breach_intel_text.pack(fill='x')
        self._style_text_widget(self.breach_intel_text)
        self.breach_intel_text.configure(state='disabled')
        self.security_focus_var = tk.StringVar(value='Focus guidance will adapt after findings appear.')
        self._label(ri, textvariable=self.security_focus_var, fg=SUBTEXT, bg=ri.cget('bg'), wraplength=430).pack(anchor='w', pady=(10, 0))
        self._label(ri, 'Recommended Actions', bg=ri.cget('bg'), font=('Segoe UI Semibold', 12)).pack(anchor='w', pady=(14, 0))
        self.security_recommendations = tk.Text(ri, height=7, wrap='word', bg=INPUT_BG, fg=TEXT, insertbackground=TEXT, relief='flat', bd=0, padx=10, pady=10)
        self.security_recommendations.pack(fill='x', pady=(8, 0))
        self._style_text_widget(self.security_recommendations)
        self.security_recommendations.configure(state='disabled')
        self._label(ri, 'Score Drivers', bg=ri.cget('bg'), font=('Segoe UI Semibold', 12)).pack(anchor='w', pady=(14, 0))
        self.security_score_story = tk.Text(ri, height=7, wrap='word', bg=INPUT_BG, fg=TEXT, insertbackground=TEXT, relief='flat', bd=0, padx=10, pady=10)
        self.security_score_story.pack(fill='x', pady=(8, 0))
        self._style_text_widget(self.security_score_story)
        self.security_score_story.configure(state='disabled')
        self._label(ri, 'Healthy Signals', bg=ri.cget('bg'), font=('Segoe UI Semibold', 12)).pack(anchor='w', pady=(14, 0))
        self.security_strengths = tk.Text(ri, height=5, wrap='word', bg=INPUT_BG, fg=TEXT, insertbackground=TEXT, relief='flat', bd=0, padx=10, pady=10)
        self.security_strengths.pack(fill='both', expand=True, pady=(8, 0))
        self._style_text_widget(self.security_strengths)
        self.security_strengths.configure(state='disabled')

    def _build_ai_guardian_tab(self) -> None:
        root = self.ai_guardian_tab
        top = self._card(root, bg=PANEL_DEEP, padx=16, pady=14)
        top.pack(fill='x', pady=(0, 12))
        ti = top.inner
        left = tk.Frame(ti, bg=ti.cget('bg'))
        left.pack(side='left', fill='x', expand=True)
        self._label(left, 'CyberVault AI Guardian', bg=left.cget('bg'), font=('Segoe UI Semibold', 14)).pack(anchor='w')
        self._label(
            left,
            'Local-first intelligence that ranks vault risk, explains what to fix first, and prepares a safe optional LLM payload without exposing secrets.',
            fg=MUTED,
            bg=left.cget('bg'),
            font=('Segoe UI', 9),
            wraplength=820,
        ).pack(anchor='w', pady=(4, 0))
        actions = tk.Frame(ti, bg=ti.cget('bg'))
        actions.pack(side='right')
        self._top_action_button(actions, 'Generate Smart Security Plan', self.generate_ai_security_plan, kind='accent').pack(side='left')
        self._top_action_button(actions, 'Export AI Summary', self.export_ai_summary).pack(side='left', padx=(8, 0))
        self._top_action_button(actions, 'Export Report', self.export_report).pack(side='left', padx=(8, 0))
        self._top_action_button(actions, 'Privacy Report', self.export_privacy_safe_report).pack(side='left', padx=(8, 0))
        self._top_action_button(actions, 'Report Package', self.export_report_package).pack(side='left', padx=(8, 0))

        summary = self._card(root, bg=CARD_BG_2, padx=18, pady=18)
        summary.pack(fill='x', pady=(0, 12))
        si = summary.inner
        self._label(si, textvariable=self.ai_mode_var, bg=si.cget('bg'), fg=self.accent, font=('Segoe UI Semibold', 10)).pack(anchor='w')
        self._label(si, textvariable=self.ai_summary_var, bg=si.cget('bg'), fg=TEXT, font=('Segoe UI Semibold', 13), wraplength=1180).pack(anchor='w', pady=(8, 0))
        self._label(si, 'Privacy model: AI Guardian is local-first and never sends raw passwords, master keys, notes, backup data, or full usernames to any model.', bg=si.cget('bg'), fg=SUCCESS, font=('Segoe UI Semibold', 9), wraplength=1180).pack(anchor='w', pady=(8, 0))
        meta = tk.Frame(si, bg=si.cget('bg'))
        meta.pack(fill='x', pady=(10, 0))
        self._label(meta, textvariable=self.ai_generated_var, bg=meta.cget('bg'), fg=SUBTEXT, font=('Segoe UI', 9)).pack(side='left')
        self._label(meta, textvariable=self.ai_privacy_var, bg=meta.cget('bg'), fg=MUTED, font=('Segoe UI', 9), wraplength=720).pack(side='right')

        coach_panel = tk.Frame(si, bg=PANEL_DEEP, padx=12, pady=10, highlightthickness=1, highlightbackground=BORDER_SOFT)
        coach_panel.pack(fill='x', pady=(12, 0))
        self._label(coach_panel, 'AI Coach UX Snapshot', bg=coach_panel.cget('bg'), fg=self.accent, font=('Segoe UI Semibold', 10)).pack(anchor='w')
        self._label(coach_panel, textvariable=self.ai_coach_overview_var, bg=coach_panel.cget('bg'), fg=TEXT, font=('Segoe UI Semibold', 9), wraplength=1160).pack(anchor='w', pady=(6, 0))
        ai_meta_row = tk.Frame(coach_panel, bg=coach_panel.cget('bg'))
        ai_meta_row.pack(fill='x', pady=(6, 0))
        self._label(ai_meta_row, textvariable=self.ai_first_action_var, bg=ai_meta_row.cget('bg'), fg=SUBTEXT, font=('Segoe UI', 9), wraplength=560).pack(side='left')
        self._label(ai_meta_row, textvariable=self.ai_site_mix_var, bg=ai_meta_row.cget('bg'), fg=MUTED, font=('Segoe UI', 9), wraplength=560).pack(side='right')

        cards = tk.Frame(root, bg=APP_BG)
        cards.pack(fill='x', pady=(0, 12))
        self.ai_risk_vars: dict[str, tk.StringVar] = {}
        self.ai_risk_story_vars: dict[str, tk.StringVar] = {}
        risk_tints = {
            'Critical': ('#2A1520', DANGER),
            'High': ('#2A1D14', WARNING),
            'Moderate': ('#202513', '#EAB308'),
            'Low': ('#13261D', SUCCESS),
        }
        for idx, level in enumerate(('Critical', 'High', 'Moderate', 'Low')):
            tint, color = risk_tints[level]
            card = tk.Frame(cards, bg=tint, padx=16, pady=14, highlightthickness=1, highlightbackground=color)
            card.pack(side='left', fill='both', expand=True, padx=(0 if idx == 0 else 10, 0))
            self._label(card, level, bg=card.cget('bg'), fg=color, font=('Segoe UI Semibold', 10)).pack(anchor='w')
            count_var = tk.StringVar(value='0')
            story_var = tk.StringVar(value='Waiting for plan generation.')
            self.ai_risk_vars[level] = count_var
            self.ai_risk_story_vars[level] = story_var
            self._label(card, textvariable=count_var, bg=card.cget('bg'), fg=TEXT, font=('Segoe UI Semibold', 26)).pack(anchor='w', pady=(6, 0))
            self._label(card, textvariable=story_var, bg=card.cget('bg'), fg=SUBTEXT, font=('Segoe UI', 9), wraplength=255).pack(anchor='w', pady=(6, 0))

        main = tk.Frame(root, bg=APP_BG)
        main.pack(fill='both', expand=True)
        left_col = self._card(main, bg=CARD_BG, padx=14, pady=14)
        left_col.pack(side='left', fill='both', expand=True, padx=(0, 12))
        right_col = self._card(main, bg=CARD_BG_2, padx=16, pady=16)
        right_col.pack(side='right', fill='both')

        li = left_col.inner
        self._label(li, 'Priority Queue', bg=li.cget('bg'), font=('Segoe UI Semibold', 13)).pack(anchor='w')
        self._label(li, 'AI Guardian ranks items by risk, reuse, breach intelligence, age, and high-value categories.', fg=MUTED, bg=li.cget('bg'), font=('Segoe UI', 9), wraplength=720).pack(anchor='w', pady=(4, 12))
        cols = ('ref', 'risk', 'signal', 'confidence', 'timeline', 'why', 'action')
        self.ai_priority_tree = ttk.Treeview(li, columns=cols, show='headings', selectmode='browse', height=10)
        for c, label, width in [
            ('ref', 'Credential Ref', 120),
            ('risk', 'Risk', 82),
            ('signal', 'Primary Signal', 135),
            ('confidence', 'Conf.', 70),
            ('timeline', 'Timeline', 105),
            ('why', 'Why First', 245),
            ('action', 'Recommended Action', 410),
        ]:
            self.ai_priority_tree.heading(c, text=label)
            self.ai_priority_tree.column(c, width=width, anchor='w')
        self.ai_priority_tree.pack(fill='both', expand=True)
        self._configure_tree_visuals(self.ai_priority_tree)
        self._attach_tree_scrollbars(self.ai_priority_tree)
        pq_actions = tk.Frame(li, bg=li.cget('bg'))
        pq_actions.pack(fill='x', pady=(10, 0))
        ttk.Button(pq_actions, text='Mark Selected Fixed', command=self.mark_ai_priority_fixed, style='Accent.TButton').pack(side='left')
        ttk.Button(pq_actions, text='Generate Replacement Password', command=self.generate_replacement_for_priority, style='Pill.TButton').pack(side='left', padx=(8, 0))
        ttk.Button(pq_actions, text='Clear Progress', command=self.clear_ai_remediation_progress, style='Pill.TButton').pack(side='left', padx=(8, 0))
        self.ai_progress_var = tk.StringVar(value='Remediation progress: 0 completed actions tracked.')
        self._label(li, textvariable=self.ai_progress_var, fg=SUBTEXT, bg=li.cget('bg'), font=('Segoe UI', 9), wraplength=760).pack(anchor='w', pady=(8, 0))
        self.ai_priority_empty_state = self._empty_state_card(
            li,
            title='No priority queue yet',
            body='Add a credential, import a browser CSV, or load assessment data. AI Guardian will replace this empty state with ranked, actionable fixes.',
            button_text='Add Credential',
            command=self.open_quick_add,
        )

        ri = right_col.inner
        self._label(ri, 'Smart Action Plan', bg=ri.cget('bg'), font=('Segoe UI Semibold', 13)).pack(anchor='w')
        self._label(ri, 'Deterministic AI-style guidance generated locally from redacted security signals.', fg=MUTED, bg=ri.cget('bg'), font=('Segoe UI', 9), wraplength=430).pack(anchor='w', pady=(4, 12))
        self.ai_action_text = tk.Text(ri, height=11, wrap='word', bg=INPUT_BG, fg=TEXT, insertbackground=TEXT, relief='flat', bd=0, padx=10, pady=10)
        self.ai_action_text.pack(fill='x')
        self._style_text_widget(self.ai_action_text)
        self.ai_action_text.configure(state='disabled')
        self._label(ri, 'AI-Style Explanation', bg=ri.cget('bg'), font=('Segoe UI Semibold', 12)).pack(anchor='w', pady=(14, 0))
        self.ai_explanation_text = tk.Text(ri, height=8, wrap='word', bg=INPUT_BG, fg=TEXT, insertbackground=TEXT, relief='flat', bd=0, padx=10, pady=10)
        self.ai_explanation_text.pack(fill='x', pady=(8, 0))
        self._style_text_widget(self.ai_explanation_text)
        self.ai_explanation_text.configure(state='disabled')
        self._label(ri, 'Decision Matrix', bg=ri.cget('bg'), font=('Segoe UI Semibold', 12)).pack(anchor='w', pady=(14, 0))
        self.ai_decision_text = tk.Text(ri, height=6, wrap='word', bg=INPUT_BG, fg=TEXT, insertbackground=TEXT, relief='flat', bd=0, padx=10, pady=10)
        self.ai_decision_text.pack(fill='x', pady=(8, 0))
        self._style_text_widget(self.ai_decision_text)
        self.ai_decision_text.configure(state='disabled')
        self._label(ri, 'Quality Gates', bg=ri.cget('bg'), font=('Segoe UI Semibold', 12)).pack(anchor='w', pady=(14, 0))
        self.ai_quality_text = tk.Text(ri, height=5, wrap='word', bg=INPUT_BG, fg=TEXT, insertbackground=TEXT, relief='flat', bd=0, padx=10, pady=10)
        self.ai_quality_text.pack(fill='x', pady=(8, 0))
        self._style_text_widget(self.ai_quality_text)
        self.ai_quality_text.configure(state='disabled')
        sim = self._card(ri, bg=CARD_BG, padx=12, pady=12)
        sim.pack(fill='x', pady=(14, 0))
        si = sim.inner
        self._label(si, 'Interactive Fix Impact Simulator', bg=si.cget('bg'), font=('Segoe UI Semibold', 12)).pack(anchor='w')
        self._label(si, 'Choose remediation buckets and preview the likely score movement without changing vault data.', fg=MUTED, bg=si.cget('bg'), wraplength=420, font=('Segoe UI', 9)).pack(anchor='w', pady=(4, 8))
        fix_grid = tk.Frame(si, bg=si.cget('bg'))
        fix_grid.pack(fill='x')
        for idx, (var, text_value) in enumerate([
            (self.fix_weak_var, 'Fix weak'),
            (self.fix_reused_var, 'Remove reuse'),
            (self.fix_old_var, 'Rotate old'),
            (self.fix_metadata_var, 'Clean metadata'),
            (self.fix_trash_var, 'Resolve trash'),
            (self.fix_backup_var, 'Export backup'),
        ]):
            ttk.Checkbutton(fix_grid, text=text_value, variable=var, command=self.update_fix_simulator).grid(row=idx // 2, column=idx % 2, sticky='w', padx=(0, 12), pady=2)
        self._label(si, textvariable=self.fix_projection_var, fg=SUBTEXT, bg=si.cget('bg'), wraplength=420, font=('Segoe UI', 9)).pack(anchor='w', pady=(8, 0))

        self._label(ri, 'Optional LLM Integration Blueprint', bg=ri.cget('bg'), font=('Segoe UI Semibold', 12)).pack(anchor='w', pady=(14, 0))
        self.ai_llm_payload_text = tk.Text(ri, height=7, wrap='word', bg=INPUT_BG, fg=TEXT, insertbackground=TEXT, relief='flat', bd=0, padx=10, pady=10)
        self.ai_llm_payload_text.pack(fill='both', expand=True, pady=(8, 0))
        self._style_text_widget(self.ai_llm_payload_text)
        self.ai_llm_payload_text.configure(state='disabled')

    def _build_proof_tab(self) -> None:
        build_proof_tab(self)

    def _build_generator_tab(self) -> None:
        root = self.generator_tab
        left = self._card(root, bg=CARD_BG, padx=18, pady=18)
        left.pack(side='left', fill='both', expand=True, padx=(0, 12))
        right = self._card(root, bg=CARD_BG_2, padx=18, pady=18)
        right.pack(side='right', fill='both', expand=True)

        li = left.inner
        self._label(li, 'Smart Password Generator', bg=li.cget('bg'), font=('Segoe UI Semibold', 13)).pack(anchor='w')
        self._label(li, 'Configurable complexity, use-case presets, easy-read mode, entropy verification, and one-click injection into the editor.', fg=MUTED, bg=li.cget('bg'), wraplength=520, font=('Segoe UI', 9)).pack(anchor='w', pady=(4, 16))

        preset_frame = tk.Frame(li, bg=li.cget('bg'))
        preset_frame.pack(fill='x', pady=(0, 12))
        for label, value in [('Balanced', 16), ('Strong', 22), ('Maximum', 30), ('Admin', 26)]:
            ttk.Button(preset_frame, text=label, command=lambda v=value: self._apply_generator_preset(v), style='Ghost.TButton').pack(side='left', padx=(0, 8))

        use_case_row = tk.Frame(li, bg=li.cget('bg'))
        use_case_row.pack(fill='x', pady=(0, 12))
        self._label(use_case_row, 'Use case', bg=use_case_row.cget('bg'), font=('Segoe UI Semibold', 10)).pack(side='left')
        ttk.Combobox(use_case_row, textvariable=self.generator_use_case_var, values=['General', 'Work', 'Banking', 'Recovery', 'Social', 'Education', 'Servers', 'Crypto'], state='readonly', width=20).pack(side='left', padx=(10, 0))

        self._label(li, 'Length', bg=li.cget('bg'), font=('Segoe UI Semibold', 10)).pack(anchor='w')
        ttk.Scale(li, from_=8, to=32, variable=self.generator_length_var, orient='horizontal', command=lambda _v: self.length_label.configure(text=f'{self.generator_length_var.get()} characters')).pack(fill='x', pady=(8, 0))
        self.length_label = self._label(li, f'{self.generator_length_var.get()} characters', fg=SUBTEXT, bg=li.cget('bg'))
        self.length_label.pack(anchor='w', pady=(5, 14))

        option_grid = tk.Frame(li, bg=li.cget('bg'))
        option_grid.pack(fill='x')
        for idx, (var, text_value) in enumerate([
            (self.generator_upper_var, 'Uppercase'),
            (self.generator_lower_var, 'Lowercase'),
            (self.generator_digits_var, 'Digits'),
            (self.generator_symbols_var, 'Symbols'),
            (self.generator_easy_read_var, 'Easy to read'),
        ]):
            ttk.Checkbutton(option_grid, text=text_value, variable=var).grid(row=idx // 2, column=idx % 2, sticky='w', pady=2, padx=(0, 14))

        row = tk.Frame(li, bg=li.cget('bg'))
        row.pack(fill='x', pady=(16, 0))
        ttk.Button(row, text='Generate', command=self.generate_password, style='Accent.TButton').pack(side='left')
        ttk.Button(row, text='Copy', command=lambda: self.copy_custom_value(self.generated_password_var.get(), 'Generated password'), style='Pill.TButton').pack(side='left', padx=(8, 0))
        ttk.Button(row, text='Use in Editor', command=self.use_generated_password, style='Pill.TButton').pack(side='left', padx=(8, 0))

        ttk.Entry(li, textvariable=self.generated_password_var).pack(fill='x', pady=(14, 0))
        self.generator_score_var = tk.StringVar(value='Strength: -')
        self._label(li, textvariable=self.generator_score_var, bg=li.cget('bg'), font=('Segoe UI Semibold', 10)).pack(anchor='w', pady=(8, 0))
        self.generator_meter_canvas = tk.Canvas(li, width=520, height=92, bg=li.cget('bg'), highlightthickness=0)
        self.generator_meter_canvas.pack(fill='x', pady=(10, 0))
        self._label(li, textvariable=self.generator_meter_var, fg=SUBTEXT, bg=li.cget('bg'), wraplength=520).pack(anchor='w', pady=(8, 0))

        ri = right.inner
        self._label(ri, 'Generator Analysis', bg=ri.cget('bg'), font=('Segoe UI Semibold', 13)).pack(anchor='w')
        self._label(ri, 'Entropy, warnings, use-case fit, and suggestions for the generated password.', fg=MUTED, bg=ri.cget('bg'), font=('Segoe UI', 9)).pack(anchor='w', pady=(4, 12))

        analysis_cards = tk.Frame(ri, bg=ri.cget('bg'))
        analysis_cards.pack(fill='x', pady=(0, 12))
        self.generator_analysis_vars = {}
        for idx, (key, title, value) in enumerate([
            ('score', 'Score', '—'),
            ('entropy', 'Entropy', '—'),
            ('fit', 'Use Case', 'Waiting'),
            ('profile', 'Site Profile', 'Auto'),
        ]):
            stat = tk.Frame(analysis_cards, bg=CARD_BG, padx=12, pady=10, highlightthickness=1, highlightbackground=BORDER_SOFT)
            stat.grid(row=0, column=idx, sticky='nsew', padx=(0 if idx == 0 else 8, 0))
            analysis_cards.grid_columnconfigure(idx, weight=1)
            self._label(stat, title, fg=MUTED, bg=stat.cget('bg'), font=('Segoe UI', 8)).pack(anchor='w')
            var = tk.StringVar(value=value)
            self.generator_analysis_vars[key] = var
            self._label(stat, textvariable=var, bg=stat.cget('bg'), font=('Segoe UI Semibold', 12), wraplength=150).pack(anchor='w', pady=(5, 0))

        self.generator_analysis = tk.Text(ri, height=18, wrap='word', bg=PANEL_DEEP, fg=TEXT, insertbackground=TEXT, relief='flat', bd=0, padx=14, pady=14)
        self.generator_analysis.pack(fill='both', expand=True)
        self._style_text_widget(self.generator_analysis)
        self.generator_analysis.insert(
            '1.0',
            'Ready to analyze.\n\nGenerate a password to unlock the live analysis panel:\n\n'
            '• Site profile reasoning from the selected website/category\n'
            '• Entropy estimate, crack resistance, and site-fit score\n'
            '• Likely website behavior: MFA, session review, form restrictions\n'
            '• Replacement advice for risky vault credentials\n'
            '• One-click copy or injection into the encrypted editor\n\n'
            'Everything runs locally; no generated password is sent outside the app.'
        )
        self.generator_analysis.configure(state='disabled')

    def _build_trash_tab(self) -> None:
        root = self.trash_tab
        card = self._card(root, bg=CARD_BG, padx=16, pady=16)
        card.pack(fill='both', expand=True)
        ci = card.inner
        top = tk.Frame(ci, bg=ci.cget('bg'))
        top.pack(fill='x', pady=(0, 12))
        self._label(top, 'Trash / Recovery Bin', bg=top.cget('bg'), font=('Segoe UI Semibold', 13)).pack(side='left')
        self._label(top, 'Deleted credentials remain recoverable for 7 days, giving the product a safer recovery workflow.', fg=MUTED, bg=top.cget('bg'), font=('Segoe UI', 9)).pack(side='left', padx=(10, 0))
        ttk.Button(top, text='Purge Expired', command=self.purge_trash, style='Ghost.TButton').pack(side='right')

        summary = tk.Frame(ci, bg=ci.cget('bg'))
        summary.pack(fill='x', pady=(0, 12))
        self.trash_summary_vars = {}
        for idx, (key, label) in enumerate([('count', 'Items in Trash'), ('expiring', 'Expiring Soon'), ('restore', 'Ready to Restore')]):
            box = tk.Frame(summary, bg=CARD_BG_2, padx=14, pady=12, highlightthickness=1, highlightbackground=BORDER)
            box.grid(row=0, column=idx, sticky='nsew', padx=(0 if idx == 0 else 10, 0))
            summary.grid_columnconfigure(idx, weight=1)
            self._label(box, label, fg=MUTED, bg=box.cget('bg'), font=('Segoe UI', 9)).pack(anchor='w')
            var = tk.StringVar(value='0')
            self.trash_summary_vars[key] = var
            self._label(box, textvariable=var, bg=box.cget('bg'), font=('Segoe UI Semibold', 20)).pack(anchor='w', pady=(8, 0))

        cols = ('title', 'username', 'deleted')
        self.trash_tree = ttk.Treeview(ci, columns=cols, show='headings', selectmode='browse')
        for c, label, width in [('title', 'Title', 280), ('username', 'Username', 240), ('deleted', 'Deleted At', 220)]:
            self.trash_tree.heading(c, text=label)
            self.trash_tree.column(c, width=width, anchor='w')
        self.trash_tree.pack(fill='both', expand=True)
        self._configure_tree_visuals(self.trash_tree)
        self._attach_tree_scrollbars(self.trash_tree)
        self.trash_tree.bind('<<TreeviewSelect>>', self.on_select_trash)

        self.trash_empty_state = tk.Frame(ci, bg=CARD_BG_2, padx=26, pady=24, highlightthickness=1, highlightbackground=BORDER)
        self._label(self.trash_empty_state, 'Trash is clean', bg=self.trash_empty_state.cget('bg'), font=('Segoe UI Semibold', 14)).pack()
        self._label(self.trash_empty_state, 'Nothing is waiting for restore or permanent purge right now.', fg=SUBTEXT, bg=self.trash_empty_state.cget('bg'), wraplength=360, justify='center').pack(pady=(8, 12))
        ttk.Button(self.trash_empty_state, text='Open Vault', command=lambda: self.show_view('vault'), style='Accent.TButton').pack()

        actions = tk.Frame(ci, bg=ci.cget('bg'))
        actions.pack(fill='x', pady=(12, 0))
        ttk.Button(actions, text='Restore', command=self.restore_trash_item, style='Accent.TButton').pack(side='left')
        ttk.Button(actions, text='Delete Forever', command=self.delete_trash_item_forever, style='Danger.TButton').pack(side='left', padx=(8, 0))

    def _build_activity_tab(self) -> None:
        card = self._card(self.activity_tab, bg=CARD_BG, padx=16, pady=16)
        card.pack(fill='both', expand=True)
        ci = card.inner
        self._label(ci, 'Audit Activity', bg=ci.cget('bg'), font=('Segoe UI Semibold', 13)).pack(anchor='w')
        self._label(ci, 'Authentication, exports, deletes, clipboard actions, and updates are timestamped locally for security visibility and presentation storytelling.', fg=MUTED, bg=ci.cget('bg'), font=('Segoe UI', 9)).pack(anchor='w', pady=(4, 12))

        summary = tk.Frame(ci, bg=ci.cget('bg'))
        summary.pack(fill='x', pady=(0, 12))
        self.activity_summary_vars = {}
        for idx, (key, label) in enumerate([('total', 'Events'), ('auth', 'Authentication'), ('sensitive', 'Sensitive'), ('exports', 'Exports'), ('failed', 'Failed Unlocks')]):
            box = tk.Frame(summary, bg=CARD_BG_2, padx=14, pady=12, highlightthickness=1, highlightbackground=BORDER)
            box.grid(row=0, column=idx, sticky='nsew', padx=(0 if idx == 0 else 10, 0))
            summary.grid_columnconfigure(idx, weight=1)
            self._label(box, label, fg=MUTED, bg=box.cget('bg'), font=('Segoe UI', 9)).pack(anchor='w')
            var = tk.StringVar(value='0')
            self.activity_summary_vars[key] = var
            self._label(box, textvariable=var, bg=box.cget('bg'), font=('Segoe UI Semibold', 20)).pack(anchor='w', pady=(8, 0))

        filters = tk.Frame(ci, bg=ci.cget('bg'))
        filters.pack(fill='x', pady=(0, 12))
        ttk.Combobox(filters, textvariable=self.activity_filter_var, values=['All activity', 'Authentication', 'Sensitive', 'Exports', 'System'], state='readonly', width=17).pack(side='left')
        ttk.Combobox(filters, textvariable=self.activity_severity_var, values=['All levels', 'Info', 'Success', 'Warning', 'Danger'], state='readonly', width=13).pack(side='left', padx=(8, 0))
        ttk.Combobox(filters, textvariable=self.activity_date_var, values=['All time', 'Today', 'Last 7 days', 'Last 30 days'], state='readonly', width=14).pack(side='left', padx=(8, 0))
        ttk.Entry(filters, textvariable=self.activity_search_var, width=28).pack(side='left', padx=(10, 0))
        ttk.Button(filters, text='Apply Filters', command=self._refresh_logs, style='Ghost.TButton').pack(side='left', padx=(10, 0))
        ttk.Button(filters, text='Clear', command=lambda: (self.activity_filter_var.set('All activity'), self.activity_severity_var.set('All levels'), self.activity_date_var.set('All time'), self.activity_search_var.set(''), self._refresh_logs()), style='Pill.TButton').pack(side='left', padx=(8, 0))
        ttk.Button(filters, text='Purge Old Logs', command=self.purge_old_activity_logs, style='Ghost.TButton').pack(side='right', padx=(8, 0))
        ttk.Button(filters, text='Report Package', command=self.export_report_package, style='Ghost.TButton').pack(side='right', padx=(8, 0))
        ttk.Button(filters, text='Export Audit Log', command=self.export_audit_log, style='Accent.TButton').pack(side='right')

        cols = ('time', 'action', 'severity', 'details')
        self.log_tree = ttk.Treeview(ci, columns=cols, show='headings')
        for c, label, width in [('time', 'Timestamp', 200), ('action', 'Action', 190), ('severity', 'Level', 90), ('details', 'Details', 860)]:
            self.log_tree.heading(c, text=label)
            self.log_tree.column(c, width=width, anchor='w')
        self.log_tree.tag_configure('warning', foreground=WARNING)
        self.log_tree.tag_configure('danger', foreground=DANGER)
        self.log_tree.tag_configure('success', foreground=SUCCESS)
        self.log_tree.pack(fill='both', expand=True)
        self._configure_tree_visuals(self.log_tree)
        self._attach_tree_scrollbars(self.log_tree)

    def _build_settings_tab(self) -> None:
        left = self._card(self.settings_tab, bg=CARD_BG, padx=18, pady=18)
        left.pack(side='left', fill='both', expand=True, padx=(0, 12))
        right = self._card(self.settings_tab, bg=CARD_BG_2, padx=18, pady=18)
        right.pack(side='right', fill='both', expand=True)

        li = left.inner
        self._label(li, 'Security Controls', bg=li.cget('bg'), font=('Segoe UI Semibold', 13)).pack(anchor='w')
        self._label(li, 'Tune runtime protection, privacy defaults, branding, and master-password hygiene without touching the encrypted vault contents until you confirm a change.', fg=MUTED, bg=li.cget('bg'), font=('Segoe UI', 9), wraplength=520).pack(anchor='w', pady=(4, 16))

        protection = self._card(li, bg=CARD_BG_2, padx=16, pady=16)
        protection.pack(fill='x')
        pi = protection.inner
        self._label(pi, 'Runtime Protection', bg=pi.cget('bg'), font=('Segoe UI Semibold', 12)).pack(anchor='w')
        self._label(pi, 'Shorter lock and clipboard timers make the product feel more security-focused during the walkthrough, while the unlock guard slows repeated failed attempts.', fg=MUTED, bg=pi.cget('bg'), wraplength=500, font=('Segoe UI', 9)).pack(anchor='w', pady=(4, 12))
        self._label(pi, textvariable=self.auto_lock_preview_var, bg=pi.cget('bg'), font=('Segoe UI Semibold', 10)).pack(anchor='w')
        ttk.Scale(pi, from_=1, to=30, variable=self.auto_lock_var, orient='horizontal', command=self._update_settings_previews).pack(fill='x', pady=(8, 12))
        self._label(pi, textvariable=self.clipboard_preview_var, bg=pi.cget('bg'), font=('Segoe UI Semibold', 10)).pack(anchor='w')
        ttk.Scale(pi, from_=5, to=60, variable=self.clipboard_clear_var, orient='horizontal', command=self._update_settings_previews).pack(fill='x', pady=(8, 12))
        self._label(pi, textvariable=self.unlock_guard_var, fg=SUBTEXT, bg=pi.cget('bg'), wraplength=500, font=('Segoe UI', 9)).pack(anchor='w')

        rotation = self._card(li, bg=CARD_BG_2, padx=16, pady=16)
        rotation.pack(fill='x', pady=(14, 0))
        ri = rotation.inner
        self._label(ri, 'Rotate Master Password', bg=ri.cget('bg'), font=('Segoe UI Semibold', 12)).pack(anchor='w')
        self._label(ri, 'Re-encrypt the entire vault with a new master password. The current password is required, and the app stays local while the vault is rewritten.', fg=MUTED, bg=ri.cget('bg'), wraplength=500, font=('Segoe UI', 9)).pack(anchor='w', pady=(4, 12))
        self._labeled_entry(ri, 'Current Master Password', self.current_master_var, show='*')
        self._labeled_entry(ri, 'New Master Password', self.new_master_var, show='*')
        self._labeled_entry(ri, 'Confirm New Master Password', self.confirm_master_var, show='*')
        ttk.Button(ri, text='Rotate Master Password', command=self.change_master_password, style='Accent.TButton').pack(anchor='w', pady=(14, 0))
        self._label(ri, textvariable=self.master_rotation_var, fg=SUBTEXT, bg=ri.cget('bg'), wraplength=500, font=('Segoe UI', 9)).pack(anchor='w', pady=(10, 0))

        branding = self._card(li, bg=CARD_BG_2, padx=16, pady=16)
        branding.pack(fill='x', pady=(14, 0))
        bi = branding.inner
        self._label(bi, 'Accent Theme', bg=bi.cget('bg'), font=('Segoe UI Semibold', 12)).pack(anchor='w')
        self._label(bi, 'Use one consistent accent across the app so the interface reads like one product, not separate pages.', fg=MUTED, bg=bi.cget('bg'), wraplength=500, font=('Segoe UI', 9)).pack(anchor='w', pady=(4, 12))
        swatches = tk.Frame(bi, bg=bi.cget('bg'))
        swatches.pack(anchor='w')
        for name, color in ACCENTS.items():
            btn = tk.Button(swatches, text=name, command=lambda v=name: self._set_theme_preview(v), bg=color, fg=APP_BG, relief='flat', bd=0, padx=12, pady=8, font=('Segoe UI Semibold', 9), cursor='hand2')
            btn.pack(side='left', padx=(0, 8))
        ttk.Combobox(bi, textvariable=self.theme_var, values=list(ACCENTS.keys()), state='readonly', width=18).pack(anchor='w', pady=(12, 0))

        actions = tk.Frame(li, bg=li.cget('bg'))
        actions.pack(fill='x', pady=(16, 0))
        ttk.Button(actions, text='Save Settings', command=self.save_settings, style='Accent.TButton').pack(side='left')
        ttk.Button(actions, text='Reset Defaults', command=self.reset_settings_defaults, style='Pill.TButton').pack(side='left', padx=(8, 0))

        rr = right.inner
        privacy = self._card(rr, bg=CARD_BG, padx=14, pady=14)
        privacy.pack(fill='x')
        pri = privacy.inner
        self._label(pri, 'Privacy Defaults', bg=pri.cget('bg'), font=('Segoe UI Semibold', 12)).pack(anchor='w')
        self._label(pri, 'Online favicon lookup is optional because it can reveal saved site domains to a third-party service. It is disabled by default, asks for confirmation before enabling, blocks high-sensitivity categories, and falls back to local monograms. Audit logs can also hide credential titles to reduce plaintext metadata leakage on disk.', fg=SUBTEXT, bg=pri.cget('bg'), wraplength=500, font=('Segoe UI', 9)).pack(anchor='w', pady=(4, 12))
        ttk.Checkbutton(pri, text='Enable online favicon lookup (explicit privacy trade-off)', variable=self.favicon_lookup_var).pack(anchor='w')
        ttk.Checkbutton(pri, text='Hide credential titles in local activity logs', variable=self.privacy_logs_var).pack(anchor='w', pady=(8, 0))
        level_row = tk.Frame(pri, bg=pri.cget('bg'))
        level_row.pack(fill='x', pady=(10, 0))
        self._label(level_row, 'Default report privacy level', bg=level_row.cget('bg'), font=('Segoe UI Semibold', 9)).pack(side='left')
        ttk.Combobox(level_row, textvariable=self.report_privacy_default_var, values=['analyst', 'standard', 'minimal'], state='readonly', width=14).pack(side='left', padx=(10, 0))
        self._label(pri, textvariable=self.breach_dataset_var, fg=MUTED, bg=pri.cget('bg'), wraplength=500, font=('Segoe UI', 9)).pack(anchor='w', pady=(10, 0))

        backup = self._card(rr, bg=CARD_BG, padx=14, pady=14)
        backup.pack(fill='x', pady=(14, 0))
        bki = backup.inner
        self._label(bki, 'Backup / Restore', bg=bki.cget('bg'), font=('Segoe UI Semibold', 12)).pack(anchor='w')
        self._label(bki, 'Encrypted backup now uses a separate backup passphrase, includes format/integrity metadata, and can be restored locally without relying on the current vault password. Take a fresh backup before rotating the master password for safety.', fg=SUBTEXT, bg=bki.cget('bg'), wraplength=500, font=('Segoe UI', 9)).pack(anchor='w', pady=(4, 12))
        row = tk.Frame(bki, bg=bki.cget('bg'))
        row.pack(fill='x')
        ttk.Button(row, text='Export Encrypted Backup', command=self.export_backup, style='Accent.TButton').pack(side='left')
        ttk.Button(row, text='Import Backup', command=self.import_backup, style='Pill.TButton').pack(side='left', padx=(8, 0))
        ttk.Button(row, text='Restore Safety Snapshot', command=self.restore_safety_snapshot, style='Danger.TButton').pack(side='left', padx=(8, 0))
        self._label(bki, textvariable=self.last_backup_var, fg=MUTED, bg=bki.cget('bg'), font=('Segoe UI', 9)).pack(anchor='w', pady=(12, 0))

        metadata = self._card(rr, bg=CARD_BG, padx=14, pady=14)
        metadata.pack(fill='x', pady=(14, 0))
        mi = metadata.inner
        self._label(mi, 'Vault Metadata', bg=mi.cget('bg'), font=('Segoe UI Semibold', 12)).pack(anchor='w')
        self._label(mi, textvariable=self.created_on_var, fg=SUBTEXT, bg=mi.cget('bg')).pack(anchor='w', pady=(10, 0))
        self._label(mi, 'Trash retention: 7 days', fg=SUBTEXT, bg=mi.cget('bg')).pack(anchor='w', pady=(6, 0))
        self._label(mi, 'Website badges always fall back to a local monogram. Online favicons only appear if you explicitly enable them here.', fg=MUTED, bg=mi.cget('bg'), wraplength=500, font=('Segoe UI', 9)).pack(anchor='w', pady=(6, 0))

        helper = self._card(rr, bg=CARD_BG, padx=14, pady=14)
        helper.pack(fill='both', expand=True, pady=(14, 0))
        hi = helper.inner
        self._label(hi, 'Workspace Operations', bg=hi.cget('bg'), font=('Segoe UI Semibold', 12)).pack(anchor='w')
        self._label(hi, 'Operational shortcuts for local workspace setup, focused review, and quick access to security findings.', fg=MUTED, bg=hi.cget('bg'), wraplength=500, font=('Segoe UI', 9)).pack(anchor='w', pady=(4, 12))
        ttk.Button(hi, text='Create Assessment Workspace', command=self.load_demo_data, style='Ghost.TButton').pack(anchor='w')
        ttk.Button(hi, text='Full-Screen Focus Mode', command=self.toggle_presentation_mode, style='Ghost.TButton').pack(anchor='w', pady=(8, 0))
        ttk.Button(hi, text='Open Security Center', command=lambda: self.show_view('security'), style='Ghost.TButton').pack(anchor='w', pady=(8, 0))


    def _build_reports_tab(self) -> None:
        root = self.reports_tab
        self._page_hero_header(
            root,
            'Reports Workspace',
            'Generate executive reports, privacy-safe summaries, and signed delivery packages from local vault telemetry.',
            action_text='Export Report',
            command=self.export_report,
            kind='accent',
        )

        stat_row = tk.Frame(root, bg=APP_BG)
        stat_row.pack(fill='x', pady=(0, 12))
        self.report_stat_vars = {
            'accounts': tk.StringVar(value='0'),
            'findings': tk.StringVar(value='0'),
            'exports': tk.StringVar(value='0'),
            'last': tk.StringVar(value='Never'),
        }
        stat_defs = [
            ('accounts', 'Accounts in scope', 'Encrypted credentials included in posture scoring.', 'info'),
            ('findings', 'Open findings', 'Weak, reused, breached, or stale accounts.', 'warning'),
            ('exports', 'Export events', 'Report, package, and backup events in audit log.', 'success'),
            ('last', 'Last backup', 'Fresh backup recommended before sharing reports.', 'medium'),
        ]
        for idx, (key, title, hint, level) in enumerate(stat_defs):
            card = self._mini_stat_card(stat_row, title, self.report_stat_vars[key], hint, level=level)
            card.pack(side='left', fill='both', expand=True, padx=(0 if idx == 0 else 10, 0))

        grid = tk.Frame(root, bg=APP_BG)
        grid.pack(fill='both', expand=True)
        left = self._card(grid, bg=CARD_BG, padx=18, pady=18)
        right = self._card(grid, bg=CARD_BG_2, padx=18, pady=18)
        left.pack(side='left', fill='both', expand=True, padx=(0, 12))
        right.pack(side='right', fill='both', expand=True)

        li = left.inner
        self._section_header(li, 'Export options', 'Choose the report format that matches the audience. Plaintext secrets are never included in reports.')
        options = tk.Frame(li, bg=li.cget('bg'))
        options.pack(fill='x')
        for idx, (title, body, button, command, level) in enumerate([
            ('Executive report', 'HTML summary for demos: score, findings, recommendations, and methodology.', 'Export Report', self.export_report, 'info'),
            ('Privacy-safe report', 'Redacted report for external review. Keeps credential titles and sensitive metadata minimized.', 'Privacy Report', self.export_privacy_safe_report, 'success'),
            ('Signed report package', 'Delivery folder with manifest hashes and local verification support.', 'Report Package', self.export_report_package, 'warning'),
        ]):
            card = self._report_option_card(options, title, body, button, command, level=level)
            card.grid(row=0, column=idx, sticky='nsew', padx=(0 if idx == 0 else 10, 0))
            options.grid_columnconfigure(idx, weight=1)

        summary = self._card(li, bg=PANEL_BG, padx=14, pady=14)
        summary.pack(fill='x', pady=(14, 0))
        si = summary.inner
        self._label(si, 'Safe report preview', bg=si.cget('bg'), font=('Segoe UI Semibold', 11)).pack(anchor='w')
        self._label(si, textvariable=self.report_summary_var, fg=SUBTEXT, bg=si.cget('bg'), font=('Segoe UI', 9), wraplength=760).pack(anchor='w', pady=(6, 0))

        ri = right.inner
        self._section_header(ri, 'Report activity', 'Recent export and verification events. Details are sanitized by privacy settings.')
        self.report_tree = ttk.Treeview(ri, columns=('time', 'type', 'status', 'details'), show='headings', height=13, style='Cyber.Treeview')
        for col, label, width in [('time', 'Time', 145), ('type', 'Type', 140), ('status', 'Status', 85), ('details', 'Details', 380)]:
            self.report_tree.heading(col, text=label)
            self.report_tree.column(col, width=width, anchor='w')
        self.report_tree.tag_configure('success', foreground=SUCCESS)
        self.report_tree.tag_configure('warning', foreground=WARNING)
        self.report_tree.tag_configure('danger', foreground=DANGER)
        self.report_tree.pack(fill='both', expand=True)
        self._attach_tree_scrollbars(self.report_tree)
        self.report_empty_state = self._empty_state_card(
            ri,
            title='No report events yet',
            body='Export a report or package to populate this delivery timeline.',
            button_text='Export Report',
            command=self.export_report,
        )
        self._label(ri, textvariable=self.report_history_var, fg=MUTED, bg=ri.cget('bg'), font=('Segoe UI', 8), wraplength=520).pack(anchor='w', pady=(10, 0))

    def _build_backup_recovery_tab(self) -> None:
        root = self.backup_recovery_tab
        self._page_hero_header(
            root,
            'Backup / Recovery',
            'A safe, step-by-step workspace for encrypted backup creation, restore preview, and emergency snapshot recovery.',
            action_text='Export Backup',
            command=self.export_backup,
            kind='accent',
        )

        grid = tk.Frame(root, bg=APP_BG)
        grid.pack(fill='both', expand=True)
        left = self._card(grid, bg=CARD_BG, padx=18, pady=18)
        right = self._card(grid, bg=CARD_BG_2, padx=18, pady=18)
        left.pack(side='left', fill='both', expand=True, padx=(0, 12))
        right.pack(side='right', fill='both', expand=True)

        li = left.inner
        self._section_header(li, 'Secure backup flow', 'Use a separate backup passphrase. Preview restore impact before any import changes the vault.')
        for idx, (title, body, level) in enumerate([
            ('Create encrypted backup', 'Export a .cvxbackup file protected by its own passphrase.', 'success'),
            ('Preview restore impact', 'Read backup metadata, duplicates, warnings, and recommended mode without changing data.', 'info'),
            ('Import or restore safely', 'Choose merge/replace only after confirmation. Safety snapshots are available for destructive operations.', 'warning'),
        ], start=1):
            self._timeline_step(li, str(idx), title, body, level=level).pack(fill='x', pady=(0 if idx == 1 else 12, 0))

        actions = self._card(li, bg=PANEL_BG, padx=14, pady=14)
        actions.pack(fill='x', pady=(16, 0))
        ai = actions.inner
        self._label(ai, 'Backup actions', bg=ai.cget('bg'), font=('Segoe UI Semibold', 11)).pack(anchor='w')
        btn_row = tk.Frame(ai, bg=ai.cget('bg'))
        btn_row.pack(fill='x', pady=(12, 0))
        self._top_action_button(btn_row, 'Export Backup', self.export_backup, kind='accent').pack(side='left')
        self._top_action_button(btn_row, 'Preview Backup', self.preview_backup_restore_ui).pack(side='left', padx=(8, 0))
        self._top_action_button(btn_row, 'Import Backup', self.import_backup).pack(side='left', padx=(8, 0))
        self._top_action_button(btn_row, 'Restore Snapshot', self.restore_safety_snapshot, kind='danger').pack(side='left', padx=(8, 0))

        ri = right.inner
        self._section_header(ri, 'Recovery status', 'Friendly status, warnings, and restore-preview output. Technical details stay contained here.')
        self._label(ri, textvariable=self.backup_status_panel_var, bg=ri.cget('bg'), fg=TEXT, font=('Segoe UI Semibold', 11), wraplength=520).pack(anchor='w')
        self._label(ri, textvariable=self.backup_recovery_hint_var, bg=ri.cget('bg'), fg=SUBTEXT, font=('Segoe UI', 9), wraplength=520).pack(anchor='w', pady=(6, 0))
        warn = self._card(ri, bg=PANEL_BG, padx=14, pady=14)
        warn.pack(fill='x', pady=(14, 0))
        wi = warn.inner
        self._label(wi, 'Security warning', bg=wi.cget('bg'), font=('Segoe UI Semibold', 11)).pack(anchor='w')
        self._label(wi, 'Backup files are encrypted, but still protect them like sensitive evidence. Reports and screenshots must never expose plaintext passwords.', fg=MUTED, bg=wi.cget('bg'), font=('Segoe UI', 9), wraplength=500).pack(anchor='w', pady=(6, 0))
        self.backup_preview_text = tk.Text(ri, height=16, wrap='word', bg=INPUT_BG, fg=TEXT, insertbackground=TEXT, relief='flat', bd=0, padx=10, pady=10)
        self.backup_preview_text.pack(fill='both', expand=True, pady=(14, 0))
        self._style_text_widget(self.backup_preview_text)
        self.backup_preview_text.configure(state='disabled')
        self._label(ri, textvariable=self.backup_flow_step_var, fg=MUTED, bg=ri.cget('bg'), font=('Segoe UI', 8), wraplength=520).pack(anchor='w', pady=(10, 0))

    def _build_system_health_tab(self) -> None:
        card = self._card(self.system_health_tab, bg=CARD_BG, padx=22, pady=22)
        card.pack(fill='both', expand=True)
        ci = card.inner
        header = tk.Frame(ci, bg=ci.cget('bg'))
        header.pack(fill='x')
        self._label(header, 'System Health & Dependency Check', bg=header.cget('bg'), font=('Segoe UI Semibold', 13)).pack(side='left', anchor='w')
        ttk.Button(header, text='Refresh Checks', command=self._refresh_system_health, style='Ghost.TButton').pack(side='right')
        self._label(ci, textvariable=self.system_health_summary_var, fg=SUBTEXT, bg=ci.cget('bg'), wraplength=1040).pack(anchor='w', pady=(8, 14))
        self.health_tree = ttk.Treeview(ci, columns=('category', 'status', 'detail'), show='headings', height=15, style='Cyber.Treeview')
        self.health_tree.heading('category', text='Category')
        self.health_tree.heading('status', text='Status')
        self.health_tree.heading('detail', text='Detail')
        self.health_tree.column('category', width=150, anchor='w')
        self.health_tree.column('status', width=110, anchor='center')
        self.health_tree.column('detail', width=760, anchor='w')
        self.health_tree.tag_configure('pass', foreground=SUCCESS)
        self.health_tree.tag_configure('warn', foreground=WARNING)
        self.health_tree.tag_configure('fail', foreground=DANGER)
        self.health_tree.pack(fill='both', expand=True)
        footer = self._card(ci, bg=PANEL_BG, padx=16, pady=14)
        footer.pack(fill='x', pady=(14, 0))
        fi = footer.inner
        self._label(fi, 'Demo readiness rule', bg=fi.cget('bg'), font=('Segoe UI Semibold', 11)).pack(anchor='w')
        self._label(fi, 'PASS means ready. WARN means explain the limitation. FAIL means fix before live demo or GitHub submission.', fg=MUTED, bg=fi.cget('bg'), wraplength=980, font=('Segoe UI', 9)).pack(anchor='w', pady=(4, 0))

    def _build_about_tab(self) -> None:
        card = self._card(self.about_tab, bg=CARD_BG, padx=22, pady=22)
        card.pack(fill='both', expand=True)
        ci = card.inner
        self._label(ci, 'About CyberVault X', bg=ci.cget('bg'), font=('Segoe UI Semibold', 13)).pack(anchor='w')
        self._label(ci, textvariable=self.about_var, fg=SUBTEXT, bg=ci.cget('bg'), wraplength=1080).pack(anchor='w', pady=(10, 0))
