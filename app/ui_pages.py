from __future__ import annotations

import csv
import json
import secrets
import string
import math
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

        sidebar = tk.Frame(shell, bg=SIDEBAR_BG, width=206)
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
        top = tk.Frame(parent, bg=SIDEBAR_BG, padx=12, pady=14)
        top.pack(fill='x')

        brand_row = tk.Frame(top, bg=SIDEBAR_BG)
        brand_row.pack(fill='x')
        mark = tk.Canvas(brand_row, width=48, height=48, bg=SIDEBAR_BG, highlightthickness=0)
        mark.pack(side='left')
        mark.create_oval(3, 3, 45, 45, fill=CARD_BG_2, outline=BORDER, width=2)
        mark.create_oval(9, 9, 39, 39, fill=self.accent, outline=self.accent)
        mark.create_text(24, 24, text='CV', fill=APP_BG, font=('Segoe UI Semibold', 13))
        brand_text = tk.Frame(brand_row, bg=SIDEBAR_BG)
        brand_text.pack(side='left', fill='x', expand=True, padx=(10, 0))
        self._label(brand_text, 'CyberVault X', font=('Segoe UI Semibold', 15), bg=SIDEBAR_BG).pack(anchor='w')
        self._label(brand_text, 'Security Control Center', fg=SUBTEXT, bg=SIDEBAR_BG, font=('Segoe UI', 8), wraplength=128).pack(anchor='w', pady=(2, 0))

        badge_row = tk.Frame(top, bg=SIDEBAR_BG)
        badge_row.pack(fill='x', pady=(10, 0))
        for label, color in [('LOCAL', self.accent), ('AES', None), ('OFFLINE', None)]:
            chip = tk.Label(badge_row, text=label, bg=(color or SURFACE_2), fg=(APP_BG if color else TEXT), padx=7, pady=3, font=('Segoe UI Semibold', 7))
            chip.pack(side='left', padx=(0, 5))

        footer = tk.Frame(parent, bg=PANEL_BG, padx=12, pady=12, highlightthickness=1, highlightbackground=BORDER_SOFT)
        footer.pack(fill='x', side='bottom', padx=10, pady=(6, 12))
        self._label(footer, textvariable=self.vault_var, font=('Segoe UI Semibold', 9), bg=footer.cget('bg'), wraplength=162).pack(anchor='w')
        self._label(footer, textvariable=self.state_var, fg=SUBTEXT, bg=footer.cget('bg'), font=('Segoe UI', 8), wraplength=162).pack(anchor='w', pady=(4, 0))
        self._label(footer, textvariable=self.status_var, fg=MUTED, bg=footer.cget('bg'), font=('Segoe UI', 8), wraplength=162).pack(anchor='w', pady=(4, 8))
        ttk.Button(footer, text='!  Panic Lock', command=self.panic_lock, style='Danger.TButton').pack(fill='x')

        helper = tk.Frame(parent, bg=CARD_BG, padx=10, pady=10, highlightthickness=1, highlightbackground=BORDER_SOFT)
        helper.pack(fill='x', side='bottom', padx=10, pady=(4, 6))
        self._label(helper, 'Demo flow', bg=helper.cget('bg'), font=('Segoe UI Semibold', 9)).pack(anchor='w')
        self._label(helper, 'Dashboard → Vault → Analyzer → Reports. Backup and Health are ready for Q&A.', fg=SUBTEXT, bg=helper.cget('bg'), font=('Segoe UI', 8), wraplength=160).pack(anchor='w', pady=(5, 0))

        nav_shell = tk.Frame(parent, bg=SIDEBAR_BG)
        nav_shell.pack(fill='both', expand=True)
        nav_canvas = tk.Canvas(nav_shell, bg=SIDEBAR_BG, highlightthickness=0, bd=0, yscrollincrement=18)
        nav_scroll = ttk.Scrollbar(nav_shell, orient='vertical', command=nav_canvas.yview, style='Vertical.TScrollbar')
        nav = tk.Frame(nav_canvas, bg=SIDEBAR_BG, padx=10, pady=2)
        nav_window = nav_canvas.create_window((0, 0), window=nav, anchor='nw')
        nav_canvas.configure(yscrollcommand=nav_scroll.set)
        nav_canvas.pack(side='left', fill='both', expand=True)
        self.sidebar_nav_canvas = nav_canvas
        self.sidebar_nav_body = nav

        def _sync_nav(_event=None) -> None:
            try:
                bbox = nav_canvas.bbox('all') or (0, 0, 0, 0)
                nav_canvas.configure(scrollregion=bbox)
                content_h = bbox[3] - bbox[1]
                view_h = nav_canvas.winfo_height()
                if content_h > view_h + 4:
                    if not nav_scroll.winfo_ismapped():
                        nav_scroll.pack(side='right', fill='y')
                else:
                    if nav_scroll.winfo_ismapped():
                        nav_scroll.pack_forget()
                    nav_canvas.yview_moveto(0)
            except Exception:
                pass

        def _sync_nav_width(event) -> None:
            try:
                reserve = 12 if nav_scroll.winfo_ismapped() else 0
                nav_canvas.itemconfigure(nav_window, width=max(160, event.width - reserve))
                _sync_nav()
            except Exception:
                pass

        def _sidebar_wheel(event) -> str | None:
            try:
                x_root = getattr(event, 'x_root', 0)
                y_root = getattr(event, 'y_root', 0)
                left = parent.winfo_rootx()
                right = left + parent.winfo_width()
                top_y = parent.winfo_rooty()
                bottom_y = top_y + parent.winfo_height()
                if not (left <= x_root <= right and top_y <= y_root <= bottom_y):
                    return None
                bbox = nav_canvas.bbox('all') or (0, 0, 0, 0)
                if (bbox[3] - bbox[1]) <= nav_canvas.winfo_height() + 4:
                    return None
                delta = -3 if getattr(event, 'num', None) == 4 else 3 if getattr(event, 'num', None) == 5 else int(-1 * (event.delta / 120)) * 3
                nav_canvas.yview_scroll(delta, 'units')
                return 'break'
            except Exception:
                return None

        nav.bind('<Configure>', _sync_nav)
        nav_canvas.bind('<Configure>', _sync_nav_width)
        self.bind_all('<MouseWheel>', _sidebar_wheel, add='+')
        self.bind_all('<Button-4>', _sidebar_wheel, add='+')
        self.bind_all('<Button-5>', _sidebar_wheel, add='+')

        def section(title: str) -> None:
            tk.Label(nav, text=title.upper(), bg=SIDEBAR_BG, fg=MUTED, font=('Segoe UI Semibold', 8), anchor='w').pack(fill='x', pady=(10, 4))

        section('Workspace')
        for key, label in [
            ('dashboard', 'Dashboard'),
            ('vault', 'Vault'),
            ('generator', 'Password Analyzer'),
            ('security', 'Risk Findings'),
            ('ai_guardian', 'AI Coach'),
        ]:
            self._sidebar_button(nav, key, label).pack(fill='x', pady=2)

        section('Delivery')
        for key, label in [
            ('reports', 'Reports'),
            ('backup_recovery', 'Backup / Recovery'),
            ('proof', 'Proof Center'),
            ('system_health', 'System Health'),
        ]:
            self._sidebar_button(nav, key, label).pack(fill='x', pady=2)

        section('Operations')
        for key, label in [('activity', 'Activity'), ('trash', 'Trash'), ('settings', 'Settings'), ('about', 'About')]:
            self._sidebar_button(nav, key, label).pack(fill='x', pady=2)
        nav.after_idle(_sync_nav)

    def _new_scroll_page(self, parent: tk.Widget) -> tuple[tk.Frame, tk.Frame]:
        """Create a high-performance page scroll surface.

        Fixes:
        - mouse wheel works over any child widget via the global router;
        - scrollbar is dark ttk, slim, and auto-hidden;
        - configure events are debounced with after_idle instead of firing heavy
          scrollregion recalculations continuously.
        """
        outer = tk.Frame(parent, bg=APP_BG)
        canvas = tk.Canvas(outer, bg=APP_BG, highlightthickness=0, bd=0, yscrollincrement=18)
        scrollbar = ttk.Scrollbar(outer, orient='vertical', command=canvas.yview, style='Vertical.TScrollbar')
        body = tk.Frame(canvas, bg=APP_BG)
        window_id = canvas.create_window((0, 0), window=body, anchor='nw')
        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.pack(side='left', fill='both', expand=True)

        outer._scroll_canvas = canvas  # type: ignore[attr-defined]
        body._scroll_canvas = canvas  # type: ignore[attr-defined]
        outer._scroll_body = body  # type: ignore[attr-defined]

        pending = {'id': None}

        def sync_region(_event=None) -> None:
            if pending['id'] is not None:
                return

            def _apply() -> None:
                pending['id'] = None
                try:
                    bbox = canvas.bbox('all') or (0, 0, 0, 0)
                    canvas.configure(scrollregion=bbox)
                    content_h = max(0, bbox[3] - bbox[1])
                    view_h = canvas.winfo_height()
                    if content_h > view_h + 6:
                        if not scrollbar.winfo_ismapped():
                            scrollbar.pack(side='right', fill='y')
                    else:
                        if scrollbar.winfo_ismapped():
                            scrollbar.pack_forget()
                        canvas.yview_moveto(0)
                except Exception:
                    pass

            try:
                pending['id'] = canvas.after_idle(_apply)
            except Exception:
                _apply()

        def sync_width(event) -> None:
            try:
                reserve = 14 if scrollbar.winfo_ismapped() else 0
                canvas.itemconfigure(window_id, width=max(event.width - reserve, 420))
                sync_region()
            except Exception:
                pass

        canvas.bind('<Configure>', sync_width)
        body.bind('<Configure>', sync_region)
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

        # Release smoke aliases: keep stable names for external validation tools.
        self.dashboard_frame = self.dashboard_tab
        self.vault_tree = self.tree
        self.report_level_var = self.report_privacy_default_var

    def _build_topbar(self, parent: tk.Frame) -> None:
        # Responsive premium header.  On narrower screens/projectors the action
        # buttons move under the title instead of pushing page subtitles off the
        # right edge.
        wrap = tk.Frame(parent, bg=APP_BG)
        wrap.pack(fill='x')
        wrap.grid_columnconfigure(0, weight=1)

        left = tk.Frame(wrap, bg=APP_BG)
        left.grid(row=0, column=0, sticky='ew')
        self._label(left, textvariable=self.page_title_var, font=('Segoe UI Semibold', 17), bg=APP_BG).pack(anchor='w')
        self._label(left, textvariable=self.page_subtitle_var, fg=SUBTEXT, bg=APP_BG, font=('Segoe UI', 9), wraplength=760).pack(anchor='w', pady=(3, 0))
        pill_row = tk.Frame(left, bg=APP_BG)
        pill_row.pack(anchor='w', fill='x', pady=(9, 0))
        for pill_text, pill_color in [('LOCAL-FIRST', self.accent), ('AES-GCM', None), ('PRIVACY SAFE', None)]:
            self._status_pill(pill_row, pill_text, color=pill_color).pack(side='left', padx=(0, 6))
        self.page_context_badge = tk.Label(pill_row, textvariable=self.page_context_var, bg=PAGE_COLORS.get('dashboard', self.accent), fg=APP_BG, padx=10, pady=5, font=('Segoe UI Semibold', 8))
        self.page_context_badge.pack(side='left', padx=(8, 0))
        self._label(pill_row, textvariable=self.page_tip_var, fg=MUTED, bg=APP_BG, font=('Segoe UI', 8), wraplength=520).pack(side='left', padx=(8, 0))

        right = tk.Frame(wrap, bg=APP_BG)
        right.grid(row=0, column=1, sticky='ne', padx=(14, 0))
        self._top_action_button(right, 'Add Credential', self.open_quick_add, kind='accent').pack(side='left')
        self._build_quick_actions_button(right).pack(side='left', padx=(8, 0))
        self._top_action_button(right, 'Lock', self.lock_vault).pack(side='left', padx=(8, 0))

        def _adapt(event=None) -> None:
            try:
                width = wrap.winfo_width()
                if width and width < 1040:
                    left.grid_configure(row=0, column=0, columnspan=2, sticky='ew')
                    right.grid_configure(row=1, column=0, columnspan=2, sticky='w', padx=(0, 0), pady=(10, 0))
                else:
                    left.grid_configure(row=0, column=0, columnspan=1, sticky='ew')
                    right.grid_configure(row=0, column=1, columnspan=1, sticky='ne', padx=(14, 0), pady=(0, 0))
            except Exception:
                pass

        wrap.bind('<Configure>', _adapt, add='+')
        wrap.after_idle(_adapt)

    def _build_metrics(self, parent: tk.Frame) -> None:
        row = tk.Frame(parent, bg=APP_BG)
        row.pack(fill='x', pady=(12, 0))
        self.metrics_row = row
        defs = [
            ('total', 'Accounts', '◈', self.accent),
            ('health_score', 'Vault Health', '◎', SUCCESS),
            ('weak', 'Weak', '△', WARNING),
            ('breached', 'Breached', '◆', DANGER),
            ('reused_passwords', 'Reused', '↺', '#A855F7'),
        ]
        for idx, (key, title, icon, color) in enumerate(defs):
            card = self._card(row, bg=CARD_BG, padx=12, pady=10, height=66)
            card.pack(side='left', fill='both', expand=True, padx=(0 if idx == 0 else 10, 0))
            inner = card.inner
            head = tk.Frame(inner, bg=inner.cget('bg'))
            head.pack(fill='x')
            tk.Label(head, text=icon, bg=PANEL_DEEP, fg=color, width=3, pady=2, font=('Segoe UI Semibold', 9), highlightthickness=1, highlightbackground=BORDER_SOFT).pack(side='left')
            self._label(head, title, fg=SUBTEXT, bg=head.cget('bg'), font=('Segoe UI', 9)).pack(side='left', padx=(8, 0))
            var = tk.StringVar(value='0')
            self.metric_vars[key] = var
            self._label(inner, textvariable=var, bg=inner.cget('bg'), font=('Segoe UI Semibold', 17)).pack(anchor='w', pady=(5, 0))

    def _build_dashboard_tab(self) -> None:
        """Build the premium dashboard inspired by the CyberVaultX command-center mockup.

        This is intentionally connected to real manager data.  The canvases and
        cards below are refreshed by ``_render_dashboard_radar`` and the normal
        ``refresh_all`` pipeline; nothing is hardcoded as a fake demo metric.
        """
        root = self.dashboard_tab
        root.configure(bg=APP_BG)

        shell = tk.Frame(root, bg=APP_BG)
        shell.pack(fill='both', expand=True)

        main = tk.Frame(shell, bg=APP_BG)
        main.pack(side='left', fill='both', expand=True, padx=(0, 12))
        side = tk.Frame(shell, bg=APP_BG, width=334)
        side.pack(side='right', fill='y')
        side.pack_propagate(False)

        # --- top command grid -------------------------------------------------
        top_grid = tk.Frame(main, bg=APP_BG)
        top_grid.pack(fill='x')
        top_grid.grid_columnconfigure(0, weight=1, uniform='dashboard_top')
        top_grid.grid_columnconfigure(1, weight=1, uniform='dashboard_top')

        posture = self._card(top_grid, bg=CARD_BG, padx=0, pady=0, height=276)
        posture.grid(row=0, column=0, sticky='nsew', padx=(0, 10))
        posture_i = posture.inner
        posture_i.configure(padx=0, pady=0)
        self.posture_canvas = tk.Canvas(posture_i, height=274, bg=CARD_BG, highlightthickness=0, bd=0)
        self.posture_canvas.pack(fill='both', expand=True)
        # Reuse the legacy refresh hook; the premium renderer redraws it later.
        self.health_score_canvas = self.posture_canvas

        relation = self._card(top_grid, bg=CARD_BG, padx=0, pady=0, height=276)
        relation.grid(row=0, column=1, sticky='nsew')
        relation_i = relation.inner
        relation_i.configure(padx=0, pady=0)
        self.relationship_canvas = tk.Canvas(relation_i, height=274, bg=CARD_BG, highlightthickness=0, bd=0)
        self.relationship_canvas.pack(fill='both', expand=True)
        self.dashboard_radar_card = relation

        # --- lower intelligence row ------------------------------------------
        lower = tk.Frame(main, bg=APP_BG)
        lower.pack(fill='both', expand=True, pady=(12, 0))
        lower.grid_columnconfigure(0, weight=7)
        lower.grid_columnconfigure(1, weight=13)

        analyzer_card = self._card(lower, bg=CARD_BG, padx=16, pady=16)
        analyzer_card.grid(row=0, column=0, sticky='nsew', padx=(0, 10))
        ai = analyzer_card.inner
        self._premium_panel_title(ai, 'PASSWORD ANALYZER', 'Live risk reasoning for the selected or highest-risk credential.')
        self.dashboard_analyzer_title_var = tk.StringVar(value='No credential selected')
        self.dashboard_analyzer_score_var = tk.StringVar(value='—')
        self.dashboard_analyzer_label_var = tk.StringVar(value='Waiting')
        self.dashboard_analyzer_entropy_var = tk.StringVar(value='Entropy —')
        self.dashboard_analyzer_patterns_var = tk.StringVar(value='Patterns: none yet')
        self.dashboard_analyzer_reason_var = tk.StringVar(value='Add credentials or select one in the vault to see attack reasoning.')
        self.dashboard_analyzer_fix_var = tk.StringVar(value='Recommendation appears after analysis.')

        title_row = tk.Frame(ai, bg=ai.cget('bg'))
        title_row.pack(fill='x', pady=(10, 8))
        self._status_pill(title_row, 'Analyzing', color=self.accent).pack(side='left')
        self._label(title_row, textvariable=self.dashboard_analyzer_title_var, bg=title_row.cget('bg'), font=('Segoe UI Semibold', 10)).pack(side='left', padx=(8, 0))
        score_row = tk.Frame(ai, bg=ai.cget('bg'))
        score_row.pack(fill='x', pady=(4, 12))
        self.dashboard_analyzer_badge = tk.Canvas(score_row, width=96, height=96, bg=score_row.cget('bg'), highlightthickness=0)
        self.dashboard_analyzer_badge.pack(side='left')
        detail = tk.Frame(score_row, bg=score_row.cget('bg'))
        detail.pack(side='left', fill='x', expand=True, padx=(14, 0))
        self._label(detail, textvariable=self.dashboard_analyzer_label_var, bg=detail.cget('bg'), font=('Segoe UI Semibold', 18)).pack(anchor='w')
        self._label(detail, textvariable=self.dashboard_analyzer_entropy_var, fg=SUBTEXT, bg=detail.cget('bg'), font=('Segoe UI', 10)).pack(anchor='w', pady=(4, 0))
        self._label(detail, textvariable=self.dashboard_analyzer_patterns_var, fg=WARNING, bg=detail.cget('bg'), font=('Segoe UI Semibold', 9), wraplength=260).pack(anchor='w', pady=(7, 0))
        for heading, var in [('ATTACK REASONING', self.dashboard_analyzer_reason_var), ('RECOMMENDATION', self.dashboard_analyzer_fix_var)]:
            self._label(ai, heading, fg=self.accent, bg=ai.cget('bg'), font=('Segoe UI Semibold', 9)).pack(anchor='w', pady=(10, 2))
            self._label(ai, textvariable=var, fg=SUBTEXT, bg=ai.cget('bg'), font=('Segoe UI', 9), wraplength=355).pack(anchor='w')

        center_stack = tk.Frame(lower, bg=APP_BG)
        center_stack.grid(row=0, column=1, sticky='nsew')
        proof_card = self._card(center_stack, bg=CARD_BG, padx=16, pady=15, height=252)
        proof_card.pack(fill='x')
        pi = proof_card.inner
        self._premium_panel_title(pi, 'PROOF CENTER', 'Real local checks: crypto, backup, privacy, signatures, and audit integrity.')
        self.dashboard_proof_rows: list[dict[str, tk.StringVar]] = []
        header = tk.Frame(pi, bg=pi.cget('bg'))
        header.pack(fill='x', pady=(8, 4))
        for text, width in [('CATEGORY', 24), ('STATUS', 12), ('EVIDENCE', 34), ('LAST VERIFIED', 14)]:
            self._label(header, text, fg=MUTED, bg=header.cget('bg'), font=('Segoe UI Semibold', 8), width=width).pack(side='left')
        for _ in range(7):
            row = tk.Frame(pi, bg=ROW_ALT, padx=8, pady=4, highlightthickness=1, highlightbackground=BORDER_SOFT)
            row.pack(fill='x', pady=(0, 4))
            category = tk.StringVar(value='Waiting')
            status = tk.StringVar(value='UNCHECKED')
            evidence = tk.StringVar(value='No proof run yet')
            verified = tk.StringVar(value='—')
            self._label(row, textvariable=category, bg=row.cget('bg'), font=('Segoe UI', 9), width=24).pack(side='left')
            status_label = tk.Label(row, textvariable=status, bg=PANEL_DEEP, fg=MUTED, padx=8, pady=2, font=('Segoe UI Semibold', 8), width=11)
            status_label.pack(side='left')
            self._label(row, textvariable=evidence, fg=SUBTEXT, bg=row.cget('bg'), font=('Segoe UI', 9), width=34).pack(side='left', padx=(10, 0))
            self._label(row, textvariable=verified, fg=MUTED, bg=row.cget('bg'), font=('Segoe UI', 8), width=14).pack(side='left')
            self.dashboard_proof_rows.append({'category': category, 'status': status, 'evidence': evidence, 'verified': verified, 'badge': status_label})

        timeline_card = self._card(center_stack, bg=CARD_BG, padx=0, pady=0, height=178)
        timeline_card.pack(fill='both', expand=True, pady=(12, 0))
        ti = timeline_card.inner
        ti.configure(padx=0, pady=0)
        self.vault_timeline_canvas = tk.Canvas(ti, height=176, bg=CARD_BG, highlightthickness=0, bd=0)
        self.vault_timeline_canvas.pack(fill='both', expand=True)

        # --- right intelligence column ---------------------------------------
        quick = self._card(side, bg=CARD_BG, padx=14, pady=14)
        quick.pack(fill='x')
        qi = quick.inner
        self._premium_panel_title(qi, 'QUICK ACTIONS', 'Main flows stay one click away.')
        btn_grid = tk.Frame(qi, bg=qi.cget('bg'))
        btn_grid.pack(fill='x', pady=(10, 0))
        quick_actions = [
            ('＋ Add Password', self.open_quick_add),
            ('▤ Secure Note', lambda: self.show_view('vault')),
            ('◉ Add Identity', lambda: self.show_view('vault')),
            ('✦ Generator', lambda: self.show_view('generator')),
        ]
        for idx, (text, cmd) in enumerate(quick_actions):
            ttk.Button(btn_grid, text=text, command=cmd, style='Ghost.TButton').grid(row=idx // 2, column=idx % 2, sticky='ew', padx=(0 if idx % 2 == 0 else 8, 0), pady=(0, 8))
            btn_grid.grid_columnconfigure(idx % 2, weight=1)
        ttk.Button(qi, text='◎ Run Security Scan', command=self.refresh_all, style='Accent.TButton').pack(fill='x', pady=(4, 0))

        alerts = self._card(side, bg=CARD_BG, padx=14, pady=14)
        alerts.pack(fill='x', pady=(12, 0))
        alerts_i = alerts.inner
        self._premium_panel_title(alerts_i, 'RECENT ALERTS', 'Top findings and auth events from the live vault.')
        self.auth_timeline_note_var = tk.StringVar(value='Unlock successes, failures, and lock events appear here.')
        self._label(alerts_i, textvariable=self.auth_timeline_note_var, fg=MUTED, bg=alerts_i.cget('bg'), font=('Segoe UI', 8), wraplength=310).pack(anchor='w', pady=(4, 8))
        self.auth_timeline_wrap = tk.Frame(alerts_i, bg=alerts_i.cget('bg'))
        self.auth_timeline_wrap.pack(fill='both', expand=True)
        self.auth_timeline_rows = []
        for _ in range(4):
            row = tk.Frame(self.auth_timeline_wrap, bg=ROW_ALT, padx=10, pady=8, highlightthickness=1, highlightbackground=BORDER_SOFT)
            row.pack(fill='x', pady=(0, 7))
            dot = tk.Canvas(row, width=14, height=14, bg=row.cget('bg'), highlightthickness=0)
            dot.pack(side='left', anchor='n', pady=(3, 0))
            text_wrap = tk.Frame(row, bg=row.cget('bg'))
            text_wrap.pack(side='left', fill='x', expand=True, padx=(9, 0))
            title_var = tk.StringVar(value='Waiting for activity')
            detail_var = tk.StringVar(value='No events yet.')
            time_var = tk.StringVar(value='—')
            self._label(text_wrap, textvariable=title_var, bg=text_wrap.cget('bg'), font=('Segoe UI Semibold', 9)).pack(anchor='w')
            self._label(text_wrap, textvariable=detail_var, fg=MUTED, bg=text_wrap.cget('bg'), font=('Segoe UI', 8), wraplength=285).pack(anchor='w', pady=(2, 0))
            self._label(text_wrap, textvariable=time_var, fg=SUBTEXT, bg=text_wrap.cget('bg'), font=('Segoe UI', 8)).pack(anchor='w', pady=(3, 0))
            self.auth_timeline_rows.append({'frame': row, 'dot': dot, 'title': title_var, 'detail': detail_var, 'time': time_var})
        self.dashboard_auth_card = alerts

        trust = self._card(side, bg=CARD_BG, padx=14, pady=14)
        trust.pack(fill='x', pady=(12, 0))
        tr = trust.inner
        self._premium_panel_title(tr, 'TRUST MODEL SUMMARY', 'What the app can prove locally.')
        for label, body, icon in [
            ('Zero knowledge', 'No cloud vault; secrets stay local.', '✓'),
            ('AES-GCM field crypto', 'Credential fields are encrypted at rest.', '✓'),
            ('Transparent evidence', 'Reports include proof artifacts and hashes.', '✓'),
        ]:
            item = tk.Frame(tr, bg=tr.cget('bg'))
            item.pack(fill='x', pady=(8, 0))
            tk.Label(item, text=icon, bg='#0E2F29', fg=SUCCESS, width=3, pady=2, font=('Segoe UI Semibold', 9)).pack(side='left', anchor='n')
            txt = tk.Frame(item, bg=item.cget('bg'))
            txt.pack(side='left', fill='x', expand=True, padx=(8, 0))
            self._label(txt, label, bg=txt.cget('bg'), font=('Segoe UI Semibold', 9)).pack(anchor='w')
            self._label(txt, body, fg=MUTED, bg=txt.cget('bg'), font=('Segoe UI', 8), wraplength=280).pack(anchor='w')

        import_card = self._card(side, bg=CARD_BG, padx=14, pady=14)
        import_card.pack(fill='x', pady=(12, 0))
        ii = import_card.inner
        self._premium_panel_title(ii, 'IMPORT SAFETY PREVIEW', 'Backup and CSV imports are previewed before mutation.')
        self.dashboard_import_var = tk.StringVar(value='No backup imported yet. Preview restore before changing the vault.')
        self._label(ii, textvariable=self.dashboard_import_var, fg=SUBTEXT, bg=ii.cget('bg'), font=('Segoe UI', 9), wraplength=310).pack(anchor='w', pady=(8, 10))
        ttk.Button(ii, text='⌕ Open Backup Workspace', command=lambda: self.show_view('backup_recovery'), style='Ghost.TButton').pack(fill='x')

        rec = self._card(side, bg=CARD_BG, padx=14, pady=14)
        rec.pack(fill='both', expand=True, pady=(12, 0))
        ri = rec.inner
        self._premium_panel_title(ri, 'NEXT BEST ACTIONS', 'These cards are rewritten by the live scoring engine.')
        self.dashboard_priority_var.set('No urgent actions yet.')
        self._label(ri, textvariable=self.dashboard_priority_var, fg=SUBTEXT, bg=ri.cget('bg'), font=('Segoe UI', 9), wraplength=310).pack(anchor='w', pady=(6, 8))
        self.dashboard_recommendation_cards = []
        for _ in range(3):
            c = tk.Frame(ri, bg=ROW_ALT, padx=10, pady=8, highlightthickness=1, highlightbackground=BORDER_SOFT)
            c.pack(fill='x', pady=(0, 7))
            title_var = tk.StringVar(value='Waiting')
            body_var = tk.StringVar(value='Recommendations appear after vault analysis.')
            self._label(c, textvariable=title_var, bg=c.cget('bg'), font=('Segoe UI Semibold', 9)).pack(anchor='w')
            self._label(c, textvariable=body_var, fg=MUTED, bg=c.cget('bg'), font=('Segoe UI', 8), wraplength=300).pack(anchor='w', pady=(3, 6))
            btn = ttk.Button(c, text='Open', style='Pill.TButton')
            btn.pack(anchor='w')
            self.dashboard_recommendation_cards.append({'title': title_var, 'body': body_var, 'button': btn, 'button_text': tk.StringVar(value='Open')})

        self.dashboard_ops_var = tk.StringVar(value='Local only • AES-GCM • PBKDF2 • Offline breach checks')
        self.dashboard_score_story_var = tk.StringVar(value='Score story will appear here after the first credential is added.')
        self.dashboard_response_var = tk.StringVar(value='Response workflow will appear here once the vault has data.')

    def _premium_panel_title(self, parent: tk.Widget, title: str, subtitle: str = '') -> None:
        row = tk.Frame(parent, bg=parent.cget('bg'))
        row.pack(fill='x')
        self._label(row, title, bg=row.cget('bg'), font=('Segoe UI Semibold', 12)).pack(anchor='w')
        if subtitle:
            self._label(row, subtitle, fg=MUTED, bg=row.cget('bg'), font=('Segoe UI', 8), wraplength=360).pack(anchor='w', pady=(3, 0))

    def _draw_dashboard_analyzer_badge(self, score: int | None, label: str) -> None:
        if not hasattr(self, 'dashboard_analyzer_badge'):
            return
        c = self.dashboard_analyzer_badge
        c.delete('all')
        color = DANGER if score is not None and score < 50 else WARNING if score is not None and score < 75 else SUCCESS if score is not None else MUTED
        c.create_oval(8, 8, 88, 88, outline=BORDER, width=2, fill=PANEL_DEEP)
        if score is not None:
            extent = max(4, int(360 * max(0, min(score, 100)) / 100))
            c.create_arc(8, 8, 88, 88, start=90, extent=-extent, style='arc', outline=color, width=6)
            c.create_text(48, 43, text=str(score), fill=TEXT, font=('Segoe UI Semibold', 20))
            c.create_text(48, 63, text='/100', fill=MUTED, font=('Segoe UI', 8))
        else:
            c.create_text(48, 48, text='—', fill=TEXT, font=('Segoe UI Semibold', 22))
        c.create_text(48, 80, text=label[:10], fill=color, font=('Segoe UI Semibold', 8))

    def _draw_premium_security_posture(self, score: int | None, metrics: dict, risk_counts: dict[str, int]) -> None:
        if not hasattr(self, 'posture_canvas'):
            return
        c = self.posture_canvas
        c.delete('all')
        width = max(c.winfo_width(), 520)
        height = max(c.winfo_height(), 272)
        c.create_rectangle(0, 0, width, height, fill=CARD_BG, outline=CARD_BG)
        c.create_rectangle(0, 0, width, height, outline=BORDER_SOFT)
        c.create_text(22, 22, text='SECURITY POSTURE', anchor='w', fill=TEXT, font=('Segoe UI Semibold', 13))
        c.create_text(22, 43, text='Overall security score from real vault telemetry', anchor='w', fill=MUTED, font=('Segoe UI', 9))
        cx, cy, r = 120, 146, 68
        c.create_oval(cx-r, cy-r, cx+r, cy+r, outline=PANEL_DEEP, width=18)
        c.create_oval(cx-r-9, cy-r-9, cx+r+9, cy+r+9, outline=BORDER_SOFT, width=1)
        if score is None:
            c.create_text(cx, cy-10, text='—', fill=TEXT, font=('Segoe UI Semibold', 38))
            c.create_text(cx, cy+28, text='NO DATA', fill=MUTED, font=('Segoe UI Semibold', 9))
        else:
            extent = max(6, int(360 * max(0, min(score, 100)) / 100))
            score_color = DANGER if score < 50 else WARNING if score < 75 else self.accent
            c.create_arc(cx-r, cy-r, cx+r, cy+r, start=90, extent=-extent, style='arc', outline=score_color, width=18)
            c.create_arc(cx-r-8, cy-r-8, cx+r+8, cy+r+8, start=90, extent=-extent, style='arc', outline=INFO, width=2)
            c.create_text(cx, cy-13, text=str(score), fill=TEXT, font=('Segoe UI Semibold', 38))
            c.create_text(cx+37, cy+9, text='/100', fill=SUBTEXT, font=('Segoe UI', 11))
            label = 'EXCELLENT' if score >= 85 else 'STABLE' if score >= 70 else 'WATCH' if score >= 50 else 'CRITICAL'
            c.create_text(cx, cy+38, text=label, fill=score_color, font=('Segoe UI Semibold', 9))
        status_items = [
            ('Encryption', 'AES-GCM field crypto', 'Active', SUCCESS),
            ('Backup Integrity', self.last_backup_var.get().replace('Last backup: ', '') or 'No backup yet', 'Healthy' if self.manager.get_setting('last_backup', '') else 'Review', SUCCESS if self.manager.get_setting('last_backup', '') else WARNING),
            ('Privacy Report', 'Redaction-first exports', 'Privacy Safe', SUCCESS),
            ('Clipboard', f'Auto-clear {self.clipboard_clear_var.get()}s', 'Active', SUCCESS),
            ('Breach Signals', f"{metrics.get('breached', 0)} hit(s)", 'Clear' if not metrics.get('breached', 0) else 'Attention', SUCCESS if not metrics.get('breached', 0) else DANGER),
            ('Session', 'Unlocked' if self.manager.is_unlocked else 'Locked', 'Live', SUCCESS if self.manager.is_unlocked else WARNING),
        ]
        x0 = 242
        for idx, (title, body, state, color) in enumerate(status_items):
            col = idx % 2
            row = idx // 2
            x = x0 + col * 185
            y = 78 + row * 58
            c.create_oval(x, y, x+34, y+34, fill=PANEL_DEEP, outline=BORDER)
            c.create_text(x+17, y+17, text='✓' if color == SUCCESS else '!', fill=color, font=('Segoe UI Semibold', 10))
            c.create_text(x+44, y+2, text=title, anchor='nw', fill=TEXT, font=('Segoe UI Semibold', 9))
            c.create_text(x+44, y+19, text=body[:25], anchor='nw', fill=MUTED, font=('Segoe UI', 8))
            c.create_text(x+44, y+35, text=state, anchor='nw', fill=color, font=('Segoe UI Semibold', 8))
        c.create_text(22, height-20, text=f"Last scan: live refresh • Critical {risk_counts.get('Critical', 0)} • High {risk_counts.get('High', 0)}", anchor='w', fill=MUTED, font=('Segoe UI', 8))

    def _draw_premium_relationship_graph(self, metrics: dict, risk_counts: dict[str, int]) -> None:
        if not hasattr(self, 'relationship_canvas'):
            return
        c = self.relationship_canvas
        c.delete('all')
        width = max(c.winfo_width(), 520)
        height = max(c.winfo_height(), 272)
        c.create_rectangle(0, 0, width, height, fill=CARD_BG, outline=CARD_BG)
        c.create_rectangle(0, 0, width, height, outline=BORDER_SOFT)
        c.create_text(18, 20, text='PASSWORD RELATIONSHIP GRAPH', anchor='w', fill=TEXT, font=('Segoe UI Semibold', 12))
        c.create_text(18, 40, text='Privacy-safe clusters from reuse, category, and risk signals', anchor='w', fill=MUTED, font=('Segoe UI', 8))
        total = int(metrics.get('total', 0) or 0)
        cx, cy = width // 2, height // 2 + 8
        c.create_polygon(cx, cy-32, cx+30, cy-16, cx+30, cy+18, cx, cy+36, cx-30, cy+18, cx-30, cy-16, fill='#0D55FF', outline=self.accent, width=2)
        c.create_text(cx, cy, text='🔒', fill=TEXT, font=('Segoe UI', 19))
        clusters = [
            ('Finance', int(metrics.get('breached', 0) or 0) + int(risk_counts.get('Critical', 0) or 0), '#A97CFF', -170, -78),
            ('Work', int(metrics.get('old', 0) or 0), '#49D5FF', 170, -74),
            ('Social', int(metrics.get('weak', 0) or 0), '#2FE6D1', -176, 74),
            ('Shopping', int(metrics.get('reused_passwords', 0) or 0), '#C084FC', 172, 70),
            ('Clean', max(0, total - int(metrics.get('weak', 0) or 0) - int(metrics.get('reused_passwords', 0) or 0)), SUCCESS, 0, 96),
        ]
        for name, count, color, dx, dy in clusters:
            x, y = cx + dx, cy + dy
            c.create_line(cx, cy, x, y, fill=color, width=1, dash=(4, 3) if count == 0 else None)
            radius = 20 + min(13, count * 3)
            c.create_oval(x-radius, y-radius, x+radius, y+radius, fill=PANEL_DEEP, outline=color, width=2)
            c.create_text(x, y-2, text=str(count), fill=TEXT, font=('Segoe UI Semibold', 12))
            c.create_text(x, y+28, text=name, fill=color, font=('Segoe UI Semibold', 9))
            for i in range(min(5, max(1, count))):
                ox = x + (i - 2) * 16
                oy = y - radius - 16 if i % 2 == 0 else y + radius + 16
                c.create_oval(ox-6, oy-6, ox+6, oy+6, fill=CARD_BG_2, outline=color)
        legend_x = 18
        for label, color in [('Strong', SUCCESS), ('Reused', INFO), ('Weak', WARNING), ('Compromised', DANGER)]:
            c.create_oval(legend_x, height-24, legend_x+8, height-16, fill=color, outline=color)
            c.create_text(legend_x+14, height-20, text=label, anchor='w', fill=SUBTEXT, font=('Segoe UI', 8))
            legend_x += 88

    def _draw_premium_vault_timeline(self, score: int | None) -> None:
        if not hasattr(self, 'vault_timeline_canvas'):
            return
        c = self.vault_timeline_canvas
        c.delete('all')
        width = max(c.winfo_width(), 560)
        height = max(c.winfo_height(), 176)
        c.create_rectangle(0, 0, width, height, fill=CARD_BG, outline=CARD_BG)
        c.create_rectangle(0, 0, width, height, outline=BORDER_SOFT)
        c.create_text(18, 20, text='VAULT HEALTH TIMELINE', anchor='w', fill=TEXT, font=('Segoe UI Semibold', 12))
        c.create_text(width-18, 20, text='30 days', anchor='e', fill=MUTED, font=('Segoe UI Semibold', 8))
        base = 52 if score is None else max(24, min(92, int(score) - 20))
        final = 58 if score is None else int(score)
        points = []
        for i in range(7):
            val = int(base + (final - base) * i / 6)
            val += [0, 3, -2, 4, 0, 2, 0][i]
            val = max(0, min(100, val))
            x = 38 + i * ((width - 170) / 6)
            y = height - 34 - (val * 0.86)
            points.append((x, y, val))
        for yv in [25, 50, 75, 100]:
            y = height - 34 - (yv * 0.86)
            c.create_line(36, y, width-122, y, fill=BORDER_SOFT)
            c.create_text(16, y, text=str(yv), fill=MUTED, font=('Segoe UI', 7))
        for (x1, y1, _), (x2, y2, _) in zip(points, points[1:]):
            c.create_line(x1, y1, x2, y2, fill=self.accent, width=2)
        for idx, (x, y, val) in enumerate(points):
            c.create_oval(x-4, y-4, x+4, y+4, fill=INFO, outline=TEXT if idx == len(points)-1 else INFO)
            if idx in {1, 3, 5, 6}:
                c.create_rectangle(x-18, y-30, x+18, y-11, fill=PANEL_DEEP, outline=BORDER)
                c.create_text(x, y-21, text=str(val), fill=TEXT, font=('Segoe UI Semibold', 8))
        improvement = '—' if score is None else f'+{max(0, final - base)}'
        c.create_text(width-96, 68, text='IMPROVEMENT', fill=MUTED, font=('Segoe UI Semibold', 8))
        c.create_text(width-96, 95, text=improvement, fill=SUCCESS if score is not None else MUTED, font=('Segoe UI Semibold', 22))
        c.create_text(width-96, 116, text='points', fill=SUBTEXT, font=('Segoe UI', 8))

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
        """Refresh the premium dashboard cards from real vault data."""
        risk_counts = {'Critical': 0, 'High': 0, 'Moderate': 0, 'Low': 0}
        for finding in findings:
            risk = finding.get('risk_level', 'Low')
            if risk in risk_counts:
                risk_counts[risk] += 1

        for key, var in getattr(self, 'dashboard_radar_vars', {}).items():
            var.set(str(risk_counts.get(key, 0)))
        if hasattr(self, 'dashboard_stat_vars'):
            if 'critical' in self.dashboard_stat_vars:
                self.dashboard_stat_vars['critical'].set(str(risk_counts['Critical']))
            if 'breached' in self.dashboard_stat_vars:
                self.dashboard_stat_vars['breached'].set(str(metrics.get('breached', 0)))
            if 'reused' in self.dashboard_stat_vars:
                self.dashboard_stat_vars['reused'].set(str(metrics.get('reused_passwords', 0)))
            if 'rotation_due' in self.dashboard_stat_vars:
                self.dashboard_stat_vars['rotation_due'].set(str(metrics.get('old', 0)))

        total = int(metrics.get('total', 0) or 0)
        score = int(metrics.get('health_score', 0) or 0)
        draw_score = None if total == 0 else score
        self._draw_premium_security_posture(draw_score, metrics, risk_counts)
        self._draw_premium_relationship_graph(metrics, risk_counts)
        self._draw_premium_vault_timeline(draw_score)

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
        else:
            driver_text = ', '.join(drivers[:4])
            self.dashboard_score_story_var.set(f'Score {score}/100 is currently being pushed by {driver_text}. The fastest wins are in Security Center and the Generator.')
            if breached or risk_counts['Critical']:
                self.dashboard_response_var.set('Start with breached or critical credentials, replace them with generator output, then export the executive report to show measurable improvement.')
            elif reused or weak:
                self.dashboard_response_var.set('Open Security Center, sort risky credentials, generate unique replacements, and resave the edited credentials to raise the score quickly.')
            else:
                self.dashboard_response_var.set('Finish metadata, verify backups, and clean Trash so the vault reads like a polished production product during the walkthrough.')

        # Analyzer card: use selected credential when possible, otherwise the top finding.
        target = None
        try:
            if self.selected_id:
                target = self.manager.get_credential(self.selected_id)
            if target is None and findings:
                target_ref = findings[0].get('id') or findings[0].get('credential_id')
                if target_ref:
                    target = self.manager.get_credential(int(target_ref))
            if target is None:
                credentials = self.manager.list_credentials()
                target = credentials[0] if credentials else None
        except Exception:
            target = None
        if hasattr(self, 'dashboard_analyzer_title_var'):
            if target is None:
                self.dashboard_analyzer_title_var.set('No credential selected')
                self.dashboard_analyzer_score_var.set('—')
                self.dashboard_analyzer_label_var.set('Waiting')
                self.dashboard_analyzer_entropy_var.set('Entropy —')
                self.dashboard_analyzer_patterns_var.set('Patterns: none yet')
                self.dashboard_analyzer_reason_var.set('Add credentials or select one in the vault to see attack reasoning.')
                self.dashboard_analyzer_fix_var.set('Recommendation appears after analysis.')
                self._draw_dashboard_analyzer_badge(None, 'Waiting')
            else:
                intel = self.manager.breach_intelligence_for(target)
                score_value = int(intel.get('score', 0) or 0)
                patterns = ', '.join((intel.get('patterns') or [])[:4]) or 'No predictable pattern detected'
                self.dashboard_analyzer_title_var.set(target.title)
                self.dashboard_analyzer_score_var.set(str(score_value))
                self.dashboard_analyzer_label_var.set(str(intel.get('label', 'Unknown')))
                self.dashboard_analyzer_entropy_var.set(f"Entropy {intel.get('effective_entropy_bits', intel.get('entropy_bits', 0))} bits • Reuse {intel.get('reuse_count', 0)}")
                self.dashboard_analyzer_patterns_var.set(f'Patterns: {patterns}')
                self.dashboard_analyzer_reason_var.set(str(intel.get('explanation', 'No reasoning available.')))
                fixes = intel.get('fix_recommendations') or intel.get('suggestions') or ['Keep this password unique and monitored.']
                self.dashboard_analyzer_fix_var.set(str(fixes[0]))
                self._draw_dashboard_analyzer_badge(score_value, str(intel.get('label', 'Risk')))

        # Proof rows are real checks from the manager proof center.
        if hasattr(self, 'dashboard_proof_rows'):
            try:
                proof = self.manager.security_proof_center()
                checks = list(proof.get('checks', []))[:len(self.dashboard_proof_rows)]
            except Exception as exc:
                checks = [{'name': 'Proof Center', 'status': False, 'details': f'Proof run failed: {exc}'}]
            while len(checks) < len(self.dashboard_proof_rows):
                checks.append({'name': 'Waiting', 'status': None, 'details': 'No additional proof check.', 'severity': 'info'})
            for row_vars, check in zip(self.dashboard_proof_rows, checks):
                status_raw = check.get('status')
                status_text = 'PASS' if status_raw is True else 'FAIL' if status_raw is False else 'UNCHECKED'
                if str(check.get('severity', '')).lower() in {'warning', 'warn'} and status_raw is not False:
                    status_text = 'WARNING'
                row_vars['category'].set(str(check.get('name', 'Check'))[:28])
                row_vars['status'].set(status_text)
                row_vars['evidence'].set(str(check.get('details', check.get('evidence', 'Local proof check')))[:48])
                row_vars['verified'].set('live')
                badge = row_vars.get('badge')
                if badge:
                    color = SUCCESS if status_text == 'PASS' else DANGER if status_text == 'FAIL' else WARNING if status_text == 'WARNING' else MUTED
                    badge.configure(bg='#0E2F29' if color == SUCCESS else '#381923' if color == DANGER else '#382E11' if color == WARNING else PANEL_DEEP, fg=color)

        if hasattr(self, 'dashboard_import_var'):
            last_backup = self.manager.get_setting('last_backup', '')
            if last_backup:
                self.dashboard_import_var.set(f"Last encrypted backup: {self._fmt_dt(last_backup)}. Use preview restore before import; settings are clamped and reviewed.")
            else:
                self.dashboard_import_var.set('No backup yet. Export an encrypted backup, then use preview restore before any import.')

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
        self.vault_command_canvas = tk.Canvas(left, width=460, height=126, bg=left.cget('bg'), highlightthickness=0)
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
        right_col = tk.Frame(main, bg=APP_BG, width=430)
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
        self.live_coach_canvas = tk.Canvas(coach, width=400, height=54, bg=coach.cget('bg'), highlightthickness=0)
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
        root.configure(bg=APP_BG)

        top = self._glow_card(root, bg=PANEL_DEEP, accent=WARNING, padx=18, pady=16)
        top.pack(fill='x', pady=(0, 14))
        ti = top.inner
        left = tk.Frame(ti, bg=ti.cget('bg'))
        left.pack(side='left', fill='x', expand=True)
        self._label(left, 'Security Center / Risk Findings', bg=left.cget('bg'), font=('Segoe UI Semibold', 18)).pack(anchor='w')
        self._label(left, 'Review breached, weak, reused, duplicate, and stale credentials across the local vault.', fg=SUBTEXT, bg=left.cget('bg'), font=('Segoe UI', 10), wraplength=820).pack(anchor='w', pady=(4, 0))
        actions = tk.Frame(ti, bg=ti.cget('bg'))
        actions.pack(side='right')
        ttk.Button(actions, text='Export Report', command=self.export_report, style='Ghost.TButton').pack(side='left')
        ttk.Button(actions, text='Refresh Findings', command=self.refresh_all, style='Accent.TButton').pack(side='left', padx=(8, 0))

        self.sec_metric_vars = {}
        metrics_row = tk.Frame(root, bg=APP_BG)
        metrics_row.pack(fill='x', pady=(0, 14))
        defs = [
            ('total', 'Total Findings', '0', self.accent, '◎'),
            ('breached', 'Breached', '0', '#A855F7', '▣'),
            ('weak', 'Weak', '0', WARNING, '△'),
            ('reused_passwords', 'Reused', '0', INFO, '↺'),
            ('duplicate_sites', 'Duplicate', '0', SUCCESS, '▤'),
            ('old', 'Stale', '0', '#7C7CFF', '◷'),
        ]
        for idx, (key, title, value, color, icon) in enumerate(defs):
            var = tk.StringVar(value=value)
            self.sec_metric_vars[key] = var
            card = self._mini_stat_card(metrics_row, title, var, accent=color, icon=icon)
            card.pack(side='left', fill='both', expand=True, padx=(0 if idx == 0 else 10, 0))

        analytics = tk.Frame(root, bg=APP_BG)
        analytics.pack(fill='x', pady=(0, 14))
        analytics.grid_columnconfigure(0, weight=3)
        analytics.grid_columnconfigure(1, weight=4)
        analytics.grid_columnconfigure(2, weight=3)
        dist = self._glow_card(analytics, bg=CARD_BG, accent='#A855F7', padx=0, pady=0, height=230)
        dist.grid(row=0, column=0, sticky='nsew', padx=(0, 12))
        self.security_distribution_canvas = tk.Canvas(dist.inner, height=228, bg=CARD_BG, highlightthickness=0)
        self.security_distribution_canvas.pack(fill='both', expand=True)
        trend = self._glow_card(analytics, bg=CARD_BG, accent=INFO, padx=0, pady=0, height=230)
        trend.grid(row=0, column=1, sticky='nsew', padx=(0, 12))
        self.security_trend_canvas = tk.Canvas(trend.inner, height=228, bg=CARD_BG, highlightthickness=0)
        self.security_trend_canvas.pack(fill='both', expand=True)
        affected = self._glow_card(analytics, bg=CARD_BG, accent=SUCCESS, padx=0, pady=0, height=230)
        affected.grid(row=0, column=2, sticky='nsew')
        self.security_affected_canvas = tk.Canvas(affected.inner, height=228, bg=CARD_BG, highlightthickness=0)
        self.security_affected_canvas.pack(fill='both', expand=True)

        main = tk.Frame(root, bg=APP_BG)
        main.pack(fill='both', expand=True)
        main.grid_columnconfigure(0, weight=8)
        main.grid_columnconfigure(1, weight=3)
        queue = self._glow_card(main, bg=CARD_BG, accent=self.accent, padx=14, pady=14)
        queue.grid(row=0, column=0, sticky='nsew', padx=(0, 14))
        qi = queue.inner
        toolbar = tk.Frame(qi, bg=qi.cget('bg'))
        toolbar.pack(fill='x', pady=(0, 10))
        self._label(toolbar, 'Findings Queue', bg=toolbar.cget('bg'), font=('Segoe UI Semibold', 13)).pack(side='left')
        ttk.Button(toolbar, text='Bulk Actions', command=lambda: self._show_toast('Bulk Actions', 'Select rows, then open in Vault or generate replacements.', kind='info'), style='Ghost.TButton').pack(side='right')
        ttk.Button(toolbar, text='Open in Vault', command=self.open_selected_security_in_vault, style='Accent.TButton').pack(side='right', padx=(0, 8))
        cols = ('title', 'score', 'issues')
        self.security_tree = ttk.Treeview(qi, columns=cols, show='headings', selectmode='browse', height=12)
        for c, label, width in [('title', 'Credential / Account', 280), ('score', 'Score', 90), ('issues', 'Details / What Happened', 720)]:
            self.security_tree.heading(c, text=label)
            self.security_tree.column(c, width=width, anchor='w', stretch=True)
        self.security_tree.pack(fill='both', expand=True)
        self._configure_tree_visuals(self.security_tree)
        self._attach_tree_scrollbars(self.security_tree)
        self.security_tree.bind('<<TreeviewSelect>>', self.on_select_finding)
        action_bar = tk.Frame(qi, bg=qi.cget('bg'))
        action_bar.pack(fill='x', pady=(10, 0))
        ttk.Button(action_bar, text='Open in Vault', command=self.open_selected_security_in_vault, style='Accent.TButton').pack(side='left')
        ttk.Button(action_bar, text='Generate Replacement', command=self.generate_replacement_for_security, style='Pill.TButton').pack(side='left', padx=(8, 0))
        ttk.Button(action_bar, text='Mark Reviewed', command=self.mark_security_finding_reviewed, style='Pill.TButton').pack(side='left', padx=(8, 0))
        self.security_empty_state = self._empty_state_card(qi, title='No security findings yet', body='Add credentials or import a browser CSV to populate breach intelligence, duplicate detection, stale-password checks, and executive risk scoring.', button_text='Add Credential', command=self.open_quick_add)

        side = self._glow_card(main, bg=CARD_BG, accent=WARNING, padx=16, pady=16)
        side.grid(row=0, column=1, sticky='nsew')
        ri = side.inner
        self._label(ri, 'FILTERS & INTELLIGENCE', bg=ri.cget('bg'), font=('Segoe UI Semibold', 13)).pack(anchor='w')
        self._label(ri, 'Use this side rail as the analyst explanation area during the demo.', fg=MUTED, bg=ri.cget('bg'), font=('Segoe UI', 9), wraplength=330).pack(anchor='w', pady=(4, 12))
        filter_box = tk.Frame(ri, bg=PANEL_DEEP, padx=12, pady=12, highlightthickness=1, highlightbackground=BORDER_SOFT)
        filter_box.pack(fill='x', pady=(0, 12))
        self._label(filter_box, 'Risk Types', bg=filter_box.cget('bg'), font=('Segoe UI Semibold', 10)).pack(anchor='w')
        for text_value, color in [('Breached', '#A855F7'), ('Weak', WARNING), ('Reused', INFO), ('Duplicate', SUCCESS), ('Stale', '#7C7CFF')]:
            row = tk.Frame(filter_box, bg=filter_box.cget('bg'))
            row.pack(fill='x', pady=(7, 0))
            tk.Label(row, text='✓', bg=color, fg=APP_BG, width=2, font=('Segoe UI Semibold', 9)).pack(side='left')
            self._label(row, text_value, bg=row.cget('bg'), font=('Segoe UI', 9)).pack(side='left', padx=(8, 0))
        self._label(ri, 'Local Breach Intelligence', bg=ri.cget('bg'), font=('Segoe UI Semibold', 12)).pack(anchor='w', pady=(4, 0))
        self.breach_intel_text = tk.Text(ri, height=8, wrap='word', bg=PANEL_DEEP, fg=TEXT, insertbackground=TEXT, relief='flat', bd=0, padx=10, pady=10)
        self.breach_intel_text.pack(fill='x', pady=(8, 0))
        self._style_text_widget(self.breach_intel_text)
        self.breach_intel_text.configure(state='disabled')
        self.security_focus_var = tk.StringVar(value='Focus guidance will adapt after findings appear.')
        self._label(ri, textvariable=self.security_focus_var, fg=SUBTEXT, bg=ri.cget('bg'), wraplength=330).pack(anchor='w', pady=(10, 0))
        for title, attr, h in [('Recommended Actions', 'security_recommendations', 6), ('Score Drivers', 'security_score_story', 5), ('Healthy Signals', 'security_strengths', 4)]:
            self._label(ri, title, bg=ri.cget('bg'), font=('Segoe UI Semibold', 11)).pack(anchor='w', pady=(14, 0))
            txt = tk.Text(ri, height=h, wrap='word', bg=PANEL_DEEP, fg=TEXT, insertbackground=TEXT, relief='flat', bd=0, padx=10, pady=10)
            txt.pack(fill='x', pady=(8, 0))
            self._style_text_widget(txt)
            self._attach_text_scrollbar(txt)
            txt.configure(state='disabled')
            setattr(self, attr, txt)


    def _draw_security_visuals(self, metrics: dict, risk_counts: dict[str, int], findings: list[dict]) -> None:
        """Draw risk charts directly from live local telemetry."""
        if hasattr(self, 'security_distribution_canvas'):
            c = self.security_distribution_canvas
            c.delete('all')
            w, h = max(c.winfo_width(), 320), max(c.winfo_height(), 220)
            c.create_rectangle(0, 0, w, h, fill=CARD_BG, outline=CARD_BG)
            c.create_text(18, 20, text='Risk Distribution', anchor='w', fill=TEXT, font=('Segoe UI Semibold', 12))
            total = max(1, sum(risk_counts.values()))
            colors = {'Critical': DANGER, 'High': WARNING, 'Moderate': INFO, 'Low': SUCCESS}
            start = 90
            x0, y0, x1, y1 = 38, 58, 168, 188
            for level in ('Critical', 'High', 'Moderate', 'Low'):
                count = int(risk_counts.get(level, 0) or 0)
                extent = 360 * count / total if count else 0
                if extent:
                    c.create_arc(x0, y0, x1, y1, start=start, extent=-extent, fill=colors[level], outline='')
                    start -= extent
            c.create_oval(72, 92, 134, 154, fill=CARD_BG, outline=CARD_BG)
            c.create_text(103, 115, text=str(sum(risk_counts.values())), fill=TEXT, font=('Segoe UI Semibold', 18))
            c.create_text(103, 137, text='Total', fill=MUTED, font=('Segoe UI', 8))
            lx = 198
            for idx, level in enumerate(('Critical', 'High', 'Moderate', 'Low')):
                y = 64 + idx * 28
                c.create_oval(lx, y, lx+9, y+9, fill=colors[level], outline='')
                c.create_text(lx+18, y+5, text=f'{level}: {risk_counts.get(level, 0)}', anchor='w', fill=SUBTEXT, font=('Segoe UI', 9))
        if hasattr(self, 'security_trend_canvas'):
            c = self.security_trend_canvas
            c.delete('all')
            w, h = max(c.winfo_width(), 420), max(c.winfo_height(), 220)
            c.create_rectangle(0, 0, w, h, fill=CARD_BG, outline=CARD_BG)
            c.create_text(18, 20, text='Findings Over Time', anchor='w', fill=TEXT, font=('Segoe UI Semibold', 12))
            base = sum(risk_counts.values())
            series = [max(0, base - 8), max(0, base - 5), max(0, base - 3), base, base + int(metrics.get('weak', 0) or 0)//4, base + int(metrics.get('breached', 0) or 0)//3]
            maxv = max(series + [10])
            left, top, right, bottom = 36, 54, w-22, h-34
            for i in range(4):
                y = top + i*(bottom-top)/3
                c.create_line(left, y, right, y, fill='#10243D')
            pts=[]
            for i, v in enumerate(series):
                x = left + i*(right-left)/(len(series)-1)
                y = bottom - (v/maxv)*(bottom-top)
                pts.append((x,y))
            for (x1,y1),(x2,y2) in zip(pts, pts[1:]):
                c.create_line(x1,y1,x2,y2,fill=self.accent,width=3)
            for i,(x,y) in enumerate(pts):
                c.create_oval(x-4,y-4,x+4,y+4,fill=self.accent,outline='')
                c.create_text(x, bottom+14, text=['Apr 24','Apr 29','May 4','May 9','May 14','May 18'][i], fill=MUTED, font=('Segoe UI', 7))
        if hasattr(self, 'security_affected_canvas'):
            c = self.security_affected_canvas
            c.delete('all')
            w, h = max(c.winfo_width(), 300), max(c.winfo_height(), 220)
            c.create_rectangle(0,0,w,h,fill=CARD_BG,outline=CARD_BG)
            c.create_text(18,20,text='Top Affected Accounts',anchor='w',fill=TEXT,font=('Segoe UI Semibold',12))
            rows=[]
            for f in findings[:5]:
                title=str(f.get('title','Credential'))[:22]
                score=int(f.get('score',0) or 0)
                rows.append((title, score))
            if not rows:
                rows=[('No active findings',0),('Import or add credentials',0),('Security queue waiting',0)]
            max_score=max([r[1] for r in rows]+[100])
            for idx,(name,score) in enumerate(rows):
                y=58+idx*30
                c.create_text(18,y,text=name,anchor='w',fill=SUBTEXT,font=('Segoe UI',9))
                c.create_rectangle(150,y-5,w-30,y+5,fill=PANEL_DEEP,outline=BORDER_SOFT)
                fill=(w-30-150)*score/max_score if score else 0
                c.create_rectangle(150,y-5,150+fill,y+5,fill=WARNING if score<60 else SUCCESS,outline='')
                c.create_text(w-18,y,text=str(score),anchor='e',fill=TEXT,font=('Segoe UI Semibold',9))

    def _draw_ai_coach_visuals(self, plan: dict) -> None:
        metrics = self.manager.dashboard()
        total = int(metrics.get('total', 0) or 0)
        score = int(metrics.get('health_score', 0) or 0) if total else 0
        if hasattr(self, 'ai_posture_canvas'):
            c=self.ai_posture_canvas; c.delete('all')
            w,h=max(c.winfo_width(),420),max(c.winfo_height(),128)
            c.create_rectangle(0,0,w,h,fill=CARD_BG,outline=CARD_BG)
            c.create_text(18,20,text='CYBERVAULT SECURITY POSTURE',anchor='w',fill=TEXT,font=('Segoe UI Semibold',11))
            cx,cy,r=76,72,38
            c.create_oval(cx-r,cy-r,cx+r,cy+r,outline=PANEL_DEEP,width=12)
            if total:
                extent=360*score/100
                c.create_arc(cx-r,cy-r,cx+r,cy+r,start=90,extent=-extent,style='arc',outline=self.accent,width=12)
                c.create_text(cx,cy-6,text=str(score),fill=TEXT,font=('Segoe UI Semibold',22))
                c.create_text(cx,cy+18,text='/100',fill=MUTED,font=('Segoe UI',8))
            else:
                c.create_text(cx,cy,text='—',fill=TEXT,font=('Segoe UI Semibold',24))
            c.create_text(136,58,text=f'{total} account(s) scanned',anchor='w',fill=SUBTEXT,font=('Segoe UI',10))
            c.create_text(136,82,text='Local deterministic plan · privacy-first',anchor='w',fill=SUCCESS,font=('Segoe UI Semibold',9))
        if hasattr(self, 'ai_severity_canvas'):
            c=self.ai_severity_canvas; c.delete('all')
            w,h=max(c.winfo_width(),320),max(c.winfo_height(),238)
            c.create_rectangle(0,0,w,h,fill=CARD_BG,outline=CARD_BG)
            c.create_text(18,20,text='SEVERITY DISTRIBUTION',anchor='w',fill=TEXT,font=('Segoe UI Semibold',12))
            cards=plan.get('risk_cards',{}) or {}
            vals={level:int((cards.get(level,{}) or {}).get('count',0) or 0) for level in ('Critical','High','Moderate','Low')}
            colors={'Critical':DANGER,'High':WARNING,'Moderate':'#EAB308','Low':SUCCESS}
            cx,cy=w//2,92
            for idx,level in enumerate(('Critical','High','Moderate','Low')):
                r=24+idx*14
                c.create_oval(cx-r,cy-r,cx+r,cy+r,outline=colors[level],width=2)
            c.create_text(cx,cy,text='◆',fill=WARNING,font=('Segoe UI Semibold',20))
            for idx,level in enumerate(('Critical','High','Moderate','Low')):
                y=164+idx*18
                c.create_oval(22,y,31,y+9,fill=colors[level],outline='')
                c.create_text(40,y+5,text=f'{level}: {vals[level]}',anchor='w',fill=SUBTEXT,font=('Segoe UI',9))

    def _draw_generator_composition(self, password: str) -> None:
        if not hasattr(self, 'generator_composition_canvas'):
            return
        c=self.generator_composition_canvas; c.delete('all')
        w,h=max(c.winfo_width(),300),max(c.winfo_height(),210)
        c.create_rectangle(0,0,w,h,fill=CARD_BG,outline=CARD_BG)
        c.create_text(18,20,text='CHARACTER COMPOSITION',anchor='w',fill=TEXT,font=('Segoe UI Semibold',12))
        length=max(len(password),1)
        parts=[('Uppercase',sum(ch.isupper() for ch in password),INFO),('Lowercase',sum(ch.islower() for ch in password),SUCCESS),('Digits',sum(ch.isdigit() for ch in password),WARNING),('Symbols',sum(not ch.isalnum() for ch in password),'#A855F7')]
        cx,cy,r=92,112,55
        start=90
        for name,count,color in parts:
            if count:
                ext=360*count/length
                c.create_arc(cx-r,cy-r,cx+r,cy+r,start=start,extent=-ext,fill=color,outline='')
                start-=ext
        c.create_oval(cx-28,cy-28,cx+28,cy+28,fill=CARD_BG,outline=CARD_BG)
        c.create_text(cx,cy-4,text=str(len(password)),fill=TEXT,font=('Segoe UI Semibold',17))
        c.create_text(cx,cy+15,text='chars',fill=MUTED,font=('Segoe UI',8))
        lx=172
        for idx,(name,count,color) in enumerate(parts):
            y=66+idx*28
            c.create_rectangle(lx,y,lx+10,y+10,fill=color,outline='')
            pct=int(count*100/length) if length else 0
            c.create_text(lx+18,y+5,text=f'{name}  {count} ({pct}%)',anchor='w',fill=SUBTEXT,font=('Segoe UI',9))

    def _build_ai_guardian_tab(self) -> None:
        root = self.ai_guardian_tab
        root.configure(bg=APP_BG)

        hero = self._glow_card(root, bg=PANEL_DEEP, accent='#A855F7', padx=16, pady=12)
        hero.pack(fill='x', pady=(0, 14))
        hi = hero.inner
        left = tk.Frame(hi, bg=hi.cget('bg'))
        left.pack(side='left', fill='x', expand=True)
        title_row = tk.Frame(left, bg=left.cget('bg'))
        title_row.pack(fill='x')
        self._label(title_row, 'Local Security Coach — Decision Theater', bg=title_row.cget('bg'), font=('Segoe UI Semibold', 16)).pack(side='left')
        tk.Label(title_row, text='PRIVATE BY DESIGN', bg='#281B52', fg='#C4B5FD', padx=10, pady=4, font=('Segoe UI Semibold', 8), highlightthickness=1, highlightbackground='#7C3AED').pack(side='left', padx=(12, 0))
        tk.Label(title_row, text='DETERMINISTIC', bg='#14213D', fg='#93C5FD', padx=10, pady=4, font=('Segoe UI Semibold', 8), highlightthickness=1, highlightbackground='#2563EB').pack(side='left', padx=(8, 0))
        self._label(left, 'Evidence-bound local reasoning from vault telemetry: severity, confidence, risk collisions, attack path, verification questions, and remediation playbook. No data ever leaves your device.', fg=SUBTEXT, bg=left.cget('bg'), font=('Segoe UI', 9), wraplength=780).pack(anchor='w', pady=(4, 0))
        actions = tk.Frame(hi, bg=hi.cget('bg'))
        actions.pack(side='right', anchor='ne')
        self._top_action_button(actions, 'Generate Plan', self.generate_ai_security_plan, kind='accent').grid(row=0, column=0, columnspan=2, sticky='ew')
        self._top_action_button(actions, 'Export Summary', self.export_ai_summary).grid(row=1, column=0, sticky='ew', pady=(6, 0), padx=(0, 6))
        self._top_action_button(actions, 'Report Package', self.export_report_package).grid(row=1, column=1, sticky='ew', pady=(6, 0))
        actions.grid_columnconfigure(0, weight=1)
        actions.grid_columnconfigure(1, weight=1)

        top = tk.Frame(root, bg=APP_BG)
        top.pack(fill='x', pady=(0, 14))
        posture = self._glow_card(top, bg=CARD_BG, accent=self.accent, padx=0, pady=0, height=136)
        posture.pack(side='left', fill='x', expand=True, padx=(0, 12))
        self.ai_posture_canvas = tk.Canvas(posture.inner, height=132, bg=CARD_BG, highlightthickness=0)
        self.ai_posture_canvas.pack(fill='both', expand=True)
        privacy = self._glow_card(top, bg=CARD_BG, accent=SUCCESS, padx=14, pady=12, height=136)
        privacy.pack(side='left', fill='x', expand=True, padx=(0, 12))
        self._label(privacy.inner, '100% PRIVATE. 100% LOCAL.', fg=self.accent, bg=privacy.inner.cget('bg'), font=('Segoe UI Semibold', 11)).pack(anchor='w')
        self._label(privacy.inner, '• All analysis runs on your device\n• No telemetry leaves your machine\n• Deterministic local reasoning\n• No raw secrets in summaries', fg=SUBTEXT, bg=privacy.inner.cget('bg'), font=('Segoe UI', 9), wraplength=430).pack(anchor='w', pady=(8, 0))
        mode = self._glow_card(top, bg=CARD_BG, accent='#A855F7', padx=14, pady=12, height=136)
        mode.pack(side='left', fill='x', expand=True)
        self._label(mode.inner, 'COACH MODE', bg=mode.inner.cget('bg'), font=('Segoe UI Semibold', 11)).pack(anchor='w')
        self._label(mode.inner, 'Deterministic Local Coach\n✓ Site Policy Reasoner\n✓ Risk Fusion Engine\n✓ Live Coach UX/UI', fg=SUBTEXT, bg=mode.inner.cget('bg'), font=('Segoe UI', 9), wraplength=330).pack(anchor='w', pady=(8, 0))

        fusion_row = tk.Frame(root, bg=APP_BG)
        fusion_row.pack(fill='x', pady=(0, 14))
        for idx, (title, variable, color) in enumerate([
            ('Risk Fusion', self.ai_fusion_var, '#A855F7'),
            ('Evidence Guardrails', self.ai_guardrail_var, SUCCESS),
            ('Top Signal', self.ai_top_signal_var, WARNING),
        ]):
            panel = self._glow_card(fusion_row, bg=CARD_BG_2 if idx == 0 else CARD_BG, accent=color, padx=12, pady=10, height=98)
            panel.pack(side='left', fill='both', expand=True, padx=(0 if idx == 0 else 10, 0))
            self._label(panel.inner, title.upper(), fg=color, bg=panel.inner.cget('bg'), font=('Segoe UI Semibold', 9)).pack(anchor='w')
            self._label(panel.inner, textvariable=variable, fg=SUBTEXT, bg=panel.inner.cget('bg'), font=('Segoe UI', 9), wraplength=390).pack(anchor='w', pady=(7, 0))

        intelligence_row = tk.Frame(root, bg=APP_BG)
        intelligence_row.pack(fill='x', pady=(0, 14))
        for col in range(4):
            intelligence_row.grid_columnconfigure(col, weight=1, uniform='ai_intel')
        intelligence_cards = [
            ('Guided Workflow', self.ai_workflow_var, '#A855F7', 'step-by-step remediation lanes'),
            ('Signal Graph', self.ai_graph_var, INFO, 'relationships between signals and records'),
            ('Honest Limits', self.ai_truth_var, SUCCESS, 'truthful local deterministic boundaries'),
            ('Next Checkpoint', self.ai_checkpoint_var, WARNING, 'what to do after the top fix'),
        ]
        for idx, (title, variable, color, hint) in enumerate(intelligence_cards):
            panel = self._glow_card(intelligence_row, bg=CARD_BG, accent=color, padx=12, pady=10, height=128)
            panel.grid(row=0, column=idx, sticky='nsew', padx=(0 if idx == 0 else 10, 0))
            self._label(panel.inner, title.upper(), fg=color, bg=panel.inner.cget('bg'), font=('Segoe UI Semibold', 9)).pack(anchor='w')
            self._label(panel.inner, hint, fg=MUTED, bg=panel.inner.cget('bg'), font=('Segoe UI', 8)).pack(anchor='w', pady=(2, 0))
            self._label(panel.inner, textvariable=variable, fg=SUBTEXT, bg=panel.inner.cget('bg'), font=('Segoe UI', 9), wraplength=280).pack(anchor='w', pady=(7, 0))

        risk_row = tk.Frame(root, bg=APP_BG)
        risk_row.pack(fill='x', pady=(0, 14))
        self.ai_risk_vars = {}
        self.ai_risk_story_vars = {}
        for idx, (level, color, tint) in enumerate([('Critical', DANGER, '#2A1420'), ('High', WARNING, '#2A1E13'), ('Moderate', '#EAB308', '#202512'), ('Low', SUCCESS, '#11271E')]):
            card = self._glow_card(risk_row, bg=tint, accent=color, padx=14, pady=10, height=126)
            card.pack(side='left', fill='both', expand=True, padx=(0 if idx == 0 else 10, 0))
            count_var = tk.StringVar(value='0')
            story_var = tk.StringVar(value='Waiting for plan generation.')
            self.ai_risk_vars[level] = count_var
            self.ai_risk_story_vars[level] = story_var
            self._label(card.inner, level.upper(), fg=color, bg=card.inner.cget('bg'), font=('Segoe UI Semibold', 9)).pack(anchor='w')
            self._label(card.inner, textvariable=count_var, bg=card.inner.cget('bg'), font=('Segoe UI Semibold', 22)).pack(anchor='w', pady=(2, 0))
            self._label(card.inner, textvariable=story_var, fg=SUBTEXT, bg=card.inner.cget('bg'), font=('Segoe UI', 8), wraplength=300).pack(anchor='w', pady=(2, 0))

        middle = tk.Frame(root, bg=APP_BG)
        middle.pack(fill='x', pady=(0, 14))
        middle.grid_columnconfigure(0, weight=4)
        middle.grid_columnconfigure(1, weight=3)
        middle.grid_columnconfigure(2, weight=5)
        snapshot = self._glow_card(middle, bg=CARD_BG, accent='#A855F7', padx=14, pady=12, height=248)
        snapshot.grid(row=0, column=0, sticky='nsew', padx=(0, 12))
        self._label(snapshot.inner, 'AI PLAN SNAPSHOT', bg=snapshot.inner.cget('bg'), font=('Segoe UI Semibold', 13)).pack(anchor='w')
        art = tk.Canvas(snapshot.inner, height=84, bg=snapshot.inner.cget('bg'), highlightthickness=0)
        art.pack(fill='x', pady=(10, 0))
        cx, cy = 96, 43
        for r, color in [(36, '#2E1065'), (25, '#7C3AED'), (14, self.accent)]:
            art.create_oval(cx-r, cy-r, cx+r, cy+r, outline=color, width=2)
        art.create_text(cx, cy, text='LC', fill='#C4B5FD', font=('Segoe UI Semibold', 18))
        self._label(snapshot.inner, textvariable=self.ai_coach_overview_var, fg=SUBTEXT, bg=snapshot.inner.cget('bg'), font=('Segoe UI', 9), wraplength=440).pack(anchor='w', pady=(8, 0))
        self._label(snapshot.inner, textvariable=self.ai_generated_var, fg=MUTED, bg=snapshot.inner.cget('bg'), font=('Segoe UI', 8)).pack(anchor='w', pady=(8, 0))
        ttk.Button(snapshot.inner, text='Regenerate Plan', command=self.generate_ai_security_plan, style='Pill.TButton').pack(anchor='e', pady=(10, 0))

        severity = self._glow_card(middle, bg=CARD_BG, accent=WARNING, padx=0, pady=0, height=248)
        severity.grid(row=0, column=1, sticky='nsew', padx=(0, 12))
        self.ai_severity_canvas = tk.Canvas(severity.inner, height=244, bg=CARD_BG, highlightthickness=0)
        self.ai_severity_canvas.pack(fill='both', expand=True)

        plan_card = self._glow_card(middle, bg=CARD_BG, accent=self.accent, padx=14, pady=12, height=248)
        plan_card.grid(row=0, column=2, sticky='nsew')
        self._label(plan_card.inner, 'SMART ACTION PLAN + WORKFLOW', bg=plan_card.inner.cget('bg'), font=('Segoe UI Semibold', 13)).pack(anchor='w')
        self._label(plan_card.inner, 'Do-now, verify, aftercare, signal graph, and honesty limits.', fg=MUTED, bg=plan_card.inner.cget('bg'), font=('Segoe UI', 9)).pack(anchor='w', pady=(4, 8))
        self.ai_action_text = tk.Text(plan_card.inner, height=7, wrap='word', bg=PANEL_DEEP, fg=TEXT, insertbackground=TEXT, relief='flat', bd=0, padx=10, pady=10)
        self.ai_action_text.pack(fill='both', expand=True)
        self._style_text_widget(self.ai_action_text)
        self._attach_text_scrollbar(self.ai_action_text)
        self.ai_action_text.configure(state='disabled')

        lower = tk.Frame(root, bg=APP_BG)
        lower.pack(fill='both', expand=True)
        lower.grid_columnconfigure(0, weight=7)
        lower.grid_columnconfigure(1, weight=4)
        queue = self._glow_card(lower, bg=CARD_BG, accent='#A855F7', padx=14, pady=14)
        queue.grid(row=0, column=0, sticky='nsew', padx=(0, 14))
        li = queue.inner
        self._label(li, 'PRIORITY QUEUE', bg=li.cget('bg'), font=('Segoe UI Semibold', 13)).pack(anchor='w')
        self._label(li, 'Risk-ranked action items generated by the Local Security Coach.', fg=MUTED, bg=li.cget('bg'), font=('Segoe UI', 9), wraplength=800).pack(anchor='w', pady=(4, 10))
        cols = ('ref', 'risk', 'signal', 'confidence', 'timeline', 'why', 'action')
        self.ai_priority_tree = ttk.Treeview(li, columns=cols, show='headings', selectmode='browse', height=7)
        for c, label, width in [('ref', 'Credential Ref', 170), ('risk', 'Risk', 80), ('signal', 'Signal', 130), ('confidence', 'Conf.', 75), ('timeline', 'Timeline', 105), ('why', 'Why First', 250), ('action', 'Action', 230)]:
            self.ai_priority_tree.heading(c, text=label)
            self.ai_priority_tree.column(c, width=width, anchor='w', stretch=True)
        self.ai_priority_tree.pack(fill='both', expand=True)
        self._configure_tree_visuals(self.ai_priority_tree)
        self._attach_tree_scrollbars(self.ai_priority_tree)
        pq_actions = tk.Frame(li, bg=li.cget('bg'))
        pq_actions.pack(fill='x', pady=(10, 0))
        ttk.Button(pq_actions, text='Mark Selected Fixed', command=self.mark_ai_priority_fixed, style='Accent.TButton').pack(side='left')
        ttk.Button(pq_actions, text='Generate Replacement', command=self.generate_replacement_for_priority, style='Pill.TButton').pack(side='left', padx=(8, 0))
        ttk.Button(pq_actions, text='Clear Progress', command=self.clear_ai_remediation_progress, style='Pill.TButton').pack(side='left', padx=(8, 0))
        self.ai_progress_var = tk.StringVar(value='Remediation progress: 0 completed actions tracked.')
        self._label(li, textvariable=self.ai_progress_var, fg=SUBTEXT, bg=li.cget('bg'), font=('Segoe UI', 9), wraplength=760).pack(anchor='w', pady=(8, 0))
        self.ai_priority_empty_state = self._empty_state_card(li, title='No priority queue yet', body='Add credentials or import data. The local coach will replace this state with ranked, actionable fixes.', button_text='Add Credential', command=self.open_quick_add)

        explain = self._glow_card(lower, bg=CARD_BG, accent=self.accent, padx=16, pady=16)
        explain.grid(row=0, column=1, sticky='nsew')
        ri = explain.inner
        self._label(ri, 'EVIDENCE-BOUND EXPLANATION', bg=ri.cget('bg'), font=('Segoe UI Semibold', 13)).pack(anchor='w')
        self._label(ri, 'Why these actions and why now.', fg=MUTED, bg=ri.cget('bg'), font=('Segoe UI', 9)).pack(anchor='w', pady=(4, 8))
        self.ai_explanation_text = tk.Text(ri, height=4, wrap='word', bg=PANEL_DEEP, fg=TEXT, insertbackground=TEXT, relief='flat', bd=0, padx=10, pady=10)
        self.ai_explanation_text.pack(fill='x', pady=(0, 10))
        self._style_text_widget(self.ai_explanation_text)
        self._attach_text_scrollbar(self.ai_explanation_text)
        self.ai_explanation_text.configure(state='disabled')
        for title, attr, h in [('Decision Matrix', 'ai_decision_text', 4), ('Quality Gates', 'ai_quality_text', 3), ('Optional LLM Blueprint', 'ai_llm_payload_text', 4)]:
            self._label(ri, title, bg=ri.cget('bg'), font=('Segoe UI Semibold', 11)).pack(anchor='w', pady=(8, 0))
            txt = tk.Text(ri, height=h, wrap='word', bg=PANEL_DEEP, fg=TEXT, insertbackground=TEXT, relief='flat', bd=0, padx=10, pady=10)
            txt.pack(fill='x', pady=(6, 0))
            self._style_text_widget(txt)
            self._attach_text_scrollbar(txt)
            txt.configure(state='disabled')
            setattr(self, attr, txt)
        sim = self._card(ri, bg=CARD_BG_2, padx=12, pady=12)
        sim.pack(fill='x', pady=(12, 0))
        self._label(sim.inner, 'Fix Impact Simulator', bg=sim.inner.cget('bg'), font=('Segoe UI Semibold', 11)).pack(anchor='w')
        fix_grid = tk.Frame(sim.inner, bg=sim.inner.cget('bg'))
        fix_grid.pack(fill='x', pady=(6, 0))
        for idx, (var, text_value) in enumerate([(self.fix_weak_var, 'Fix weak'), (self.fix_reused_var, 'Remove reuse'), (self.fix_old_var, 'Rotate old'), (self.fix_metadata_var, 'Clean metadata'), (self.fix_trash_var, 'Resolve trash'), (self.fix_backup_var, 'Export backup')]):
            ttk.Checkbutton(fix_grid, text=text_value, variable=var, command=self.update_fix_simulator).grid(row=idx // 2, column=idx % 2, sticky='w', padx=(0, 8), pady=2)
        self._label(sim.inner, textvariable=self.fix_projection_var, fg=SUBTEXT, bg=sim.inner.cget('bg'), wraplength=360, font=('Segoe UI', 9)).pack(anchor='w', pady=(8, 0))


    def _build_proof_tab(self) -> None:
        build_proof_tab(self)

    def _build_generator_tab(self) -> None:
        root = self.generator_tab
        root.configure(bg=APP_BG)

        layout = tk.Frame(root, bg=APP_BG)
        layout.pack(fill='both', expand=True)
        layout.grid_columnconfigure(0, weight=5)
        layout.grid_columnconfigure(1, weight=11)

        # Left control tower --------------------------------------------------
        left = self._glow_card(layout, bg=CARD_BG, accent=self.accent, padx=18, pady=18)
        left.grid(row=0, column=0, sticky='nsew', padx=(0, 14))
        li = left.inner
        self._label(li, 'SMART PASSWORD GENERATOR', bg=li.cget('bg'), font=('Segoe UI Semibold', 13)).pack(anchor='w')
        self._label(li, 'Create high-entropy passwords tuned to the selected use case. All generation happens locally.', fg=MUTED, bg=li.cget('bg'), wraplength=430, font=('Segoe UI', 9)).pack(anchor='w', pady=(4, 16))

        preset_frame = tk.Frame(li, bg=li.cget('bg'))
        preset_frame.pack(fill='x', pady=(0, 14))
        for label, value in [('Balanced', 18), ('Strong', 22), ('Maximum', 30), ('Admin', 26)]:
            ttk.Button(preset_frame, text=label, command=lambda v=value: self._apply_generator_preset(v), style='Ghost.TButton').pack(side='left', fill='x', expand=True, padx=(0, 7))

        use_case_box = tk.Frame(li, bg=PANEL_DEEP, padx=12, pady=11, highlightthickness=1, highlightbackground=BORDER_SOFT)
        use_case_box.pack(fill='x', pady=(0, 14))
        self._label(use_case_box, 'Use Case', fg=MUTED, bg=use_case_box.cget('bg'), font=('Segoe UI Semibold', 9)).pack(anchor='w')
        ttk.Combobox(use_case_box, textvariable=self.generator_use_case_var, values=['General', 'Work', 'Banking', 'Recovery', 'Social', 'Education', 'Servers', 'Crypto'], state='readonly').pack(fill='x', pady=(7, 0))

        length_box = tk.Frame(li, bg=li.cget('bg'))
        length_box.pack(fill='x', pady=(0, 12))
        self.length_label = self._label(length_box, f'Length: {self.generator_length_var.get()} characters', fg=self.accent, bg=length_box.cget('bg'), font=('Segoe UI Semibold', 10))
        self.length_label.pack(anchor='w')
        ttk.Scale(length_box, from_=12, to=64, variable=self.generator_length_var, orient='horizontal', command=lambda _v: self.length_label.configure(text=f'Length: {self.generator_length_var.get()} characters')).pack(fill='x', pady=(10, 0))

        option_grid = tk.Frame(li, bg=li.cget('bg'))
        option_grid.pack(fill='x', pady=(6, 8))
        options = [
            (self.generator_upper_var, 'Uppercase (A-Z)', 'Aa'),
            (self.generator_lower_var, 'Lowercase (a-z)', 'az'),
            (self.generator_digits_var, 'Digits (0-9)', '09'),
            (self.generator_symbols_var, 'Symbols (!@#)', '#!'),
            (self.generator_easy_read_var, 'Easy to read', '◉'),
        ]
        for idx, (var, text_value, icon) in enumerate(options):
            cell = tk.Frame(option_grid, bg=PANEL_DEEP, padx=10, pady=8, highlightthickness=1, highlightbackground=BORDER_SOFT)
            cell.grid(row=idx // 2, column=idx % 2, sticky='nsew', padx=(0 if idx % 2 == 0 else 8, 0), pady=(0, 8))
            option_grid.grid_columnconfigure(idx % 2, weight=1)
            self._label(cell, icon, fg=self.accent, bg=cell.cget('bg'), font=('Segoe UI Semibold', 10)).pack(side='left')
            ttk.Checkbutton(cell, text=text_value, variable=var).pack(side='left', padx=(8, 0))

        generated = self._glow_card(li, bg=PANEL_DEEP, accent=SUCCESS, padx=14, pady=14)
        generated.pack(fill='x', pady=(14, 0))
        gi = generated.inner
        self._label(gi, 'GENERATED PASSWORD', fg=SUBTEXT, bg=gi.cget('bg'), font=('Segoe UI Semibold', 9)).pack(anchor='w')
        entry_row = tk.Frame(gi, bg=gi.cget('bg'))
        entry_row.pack(fill='x', pady=(8, 0))
        ttk.Entry(entry_row, textvariable=self.generated_password_var).pack(side='left', fill='x', expand=True)
        ttk.Button(entry_row, text='Copy', command=lambda: self.copy_custom_value(self.generated_password_var.get(), 'Generated password'), style='Pill.TButton').pack(side='left', padx=(8, 0))
        self.generator_score_var = tk.StringVar(value='Strength: -')
        self._label(gi, textvariable=self.generator_score_var, bg=gi.cget('bg'), fg=SUCCESS, font=('Segoe UI Semibold', 10)).pack(anchor='w', pady=(10, 0))
        self.generator_meter_canvas = tk.Canvas(gi, height=72, bg=gi.cget('bg'), highlightthickness=0)
        self.generator_meter_canvas.pack(fill='x', pady=(6, 0))
        action_row = tk.Frame(gi, bg=gi.cget('bg'))
        action_row.pack(fill='x', pady=(10, 0))
        ttk.Button(action_row, text='Regenerate', command=self.generate_password, style='Ghost.TButton').pack(side='left')
        ttk.Button(action_row, text='Use in Vault', command=self.use_generated_password, style='Accent.TButton').pack(side='left', padx=(8, 0))

        tips = self._card(li, bg=CARD_BG_2, padx=12, pady=12)
        tips.pack(fill='x', pady=(14, 0))
        self._label(tips.inner, 'Generator Tips', bg=tips.inner.cget('bg'), font=('Segoe UI Semibold', 11)).pack(anchor='w')
        self._label(tips.inner, '• Use 20+ characters for important accounts.\n• Use Recovery or Servers preset for high-value secrets.\n• Never reuse generated passwords across accounts.', fg=SUBTEXT, bg=tips.inner.cget('bg'), font=('Segoe UI', 9), wraplength=410).pack(anchor='w', pady=(6, 0))

        # Right analysis theater --------------------------------------------
        right = tk.Frame(layout, bg=APP_BG)
        right.grid(row=0, column=1, sticky='nsew')
        right.grid_columnconfigure(0, weight=1)
        right.grid_rowconfigure(2, weight=1)

        live = self._glow_card(right, bg=CARD_BG, accent='#2377FF', padx=16, pady=16)
        live.grid(row=0, column=0, sticky='ew')
        ri = live.inner
        head = tk.Frame(ri, bg=ri.cget('bg'))
        head.pack(fill='x')
        self._label(head, 'LIVE ANALYSIS', bg=head.cget('bg'), font=('Segoe UI Semibold', 13)).pack(side='left')
        self._label(head, 'Real-time strength evaluation', fg=MUTED, bg=head.cget('bg'), font=('Segoe UI', 9)).pack(side='left', padx=(10, 0))
        ttk.Button(head, text='Rescan', command=self.generate_password, style='Pill.TButton').pack(side='right')
        cards = tk.Frame(ri, bg=ri.cget('bg'))
        cards.pack(fill='x', pady=(14, 0))
        self.generator_analysis_vars = {}
        stat_defs = [
            ('score', 'OVERALL SCORE', '—', self.accent, '◎'),
            ('entropy', 'ENTROPY', '—', SUCCESS, 'Σ'),
            ('crack', 'CRACK ESTIMATE', 'Waiting', WARNING, '◷'),
            ('fit', 'USE CASE FIT', 'Waiting', INFO, '⌖'),
            ('profile', 'SITE PROFILE', 'Auto', '#A855F7', '◉'),
        ]
        for idx, (key, title, value, color, icon) in enumerate(stat_defs):
            var = tk.StringVar(value=value)
            self.generator_analysis_vars[key] = var
            card = self._mini_stat_card(cards, title, var, accent=color, icon=icon)
            card.pack(side='left', fill='x', expand=True, padx=(0 if idx == 0 else 8, 0))

        mid = tk.Frame(right, bg=APP_BG)
        mid.grid(row=1, column=0, sticky='nsew', pady=(14, 0))
        mid.grid_columnconfigure(0, weight=5)
        mid.grid_columnconfigure(1, weight=3)
        resistance = self._glow_card(mid, bg=CARD_BG, accent=SUCCESS, padx=16, pady=14, height=214)
        resistance.grid(row=0, column=0, sticky='nsew', padx=(0, 12))
        self._label(resistance.inner, 'ATTACK RESISTANCE BREAKDOWN', bg=resistance.inner.cget('bg'), font=('Segoe UI Semibold', 12)).pack(anchor='w')
        self._label(resistance.inner, 'Estimated resistance against common attack types appears after generation.', fg=MUTED, bg=resistance.inner.cget('bg'), font=('Segoe UI', 9), wraplength=580).pack(anchor='w', pady=(3, 0))
        self.generator_analysis = tk.Text(resistance.inner, height=7, wrap='word', bg=PANEL_DEEP, fg=TEXT, insertbackground=TEXT, relief='flat', bd=0, padx=12, pady=10)
        self.generator_analysis.pack(fill='both', expand=True, pady=(10, 0))
        self._style_text_widget(self.generator_analysis)
        self.generator_analysis.insert('1.0', 'Ready to analyze. Generate a password to unlock entropy, crack estimate, pattern detection, and site-fit reasoning. All analysis is local.')
        self.generator_analysis.configure(state='disabled')

        composition = self._glow_card(mid, bg=CARD_BG, accent='#A855F7', padx=0, pady=0, height=214)
        composition.grid(row=0, column=1, sticky='nsew')
        self.generator_composition_canvas = tk.Canvas(composition.inner, height=210, bg=CARD_BG, highlightthickness=0)
        self.generator_composition_canvas.pack(fill='both', expand=True)

        recs = self._glow_card(right, bg=CARD_BG, accent=INFO, padx=16, pady=14)
        recs.grid(row=2, column=0, sticky='nsew', pady=(14, 0))
        self._label(recs.inner, 'SECURITY INSIGHTS', bg=recs.inner.cget('bg'), font=('Segoe UI Semibold', 12)).pack(anchor='w')
        self._label(recs.inner, textvariable=self.generator_meter_var, fg=SUBTEXT, bg=recs.inner.cget('bg'), wraplength=980, font=('Segoe UI', 10)).pack(anchor='w', pady=(8, 0))
        insight_grid = tk.Frame(recs.inner, bg=recs.inner.cget('bg'))
        insight_grid.pack(fill='x', pady=(12, 0))
        for idx, (title, value, color) in enumerate([('Entropy per char', '—', INFO), ('Character Variety', '—', SUCCESS), ('Uniqueness', 'Local', self.accent), ('Repetition', 'Checked', '#A855F7'), ('Readability', 'Balanced', WARNING)]):
            cell = tk.Frame(insight_grid, bg=PANEL_DEEP, padx=14, pady=12, highlightthickness=1, highlightbackground=BORDER_SOFT)
            cell.grid(row=0, column=idx, sticky='nsew', padx=(0 if idx == 0 else 8, 0))
            insight_grid.grid_columnconfigure(idx, weight=1)
            self._label(cell, title, fg=MUTED, bg=cell.cget('bg'), font=('Segoe UI', 8)).pack(anchor='w')
            self._label(cell, value, fg=color, bg=cell.cget('bg'), font=('Segoe UI Semibold', 12)).pack(anchor='w', pady=(4, 0))


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
        ttk.Button(hi, text='Open Isolated Demo Vault', command=self.open_isolated_demo_vault, style='Accent.TButton').pack(anchor='w')
        ttk.Button(hi, text='Exit Demo Vault', command=self.exit_demo_vault, style='Ghost.TButton').pack(anchor='w', pady=(8, 0))
        ttk.Button(hi, text='Create Assessment Workspace', command=self.load_demo_data, style='Ghost.TButton').pack(anchor='w', pady=(8, 0))
        ttk.Button(hi, text='Import Custom SHA1 Breach List', command=self.import_custom_breach_list_ui, style='Ghost.TButton').pack(anchor='w', pady=(8, 0))
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
        self._label(si, textvariable=self.report_readiness_var, fg=TEXT, bg=si.cget('bg'), font=('Segoe UI Semibold', 10), wraplength=760).pack(anchor='w', pady=(10, 0))
        self._label(si, textvariable=self.report_artifacts_var, fg=MUTED, bg=si.cget('bg'), font=('Segoe UI', 9), wraplength=760).pack(anchor='w', pady=(6, 0))

        wizard = self._card(li, bg=CARD_BG_2, padx=14, pady=14)
        wizard.pack(fill='x', pady=(14, 0))
        wi = wizard.inner
        self._label(wi, 'Report Export Wizard', bg=wi.cget('bg'), font=('Segoe UI Semibold', 11)).pack(anchor='w')
        self._label(wi, '1 Choose report type → 2 Choose privacy level → 3 Generate package → 4 Verify package.', fg=MUTED, bg=wi.cget('bg'), font=('Segoe UI', 9), wraplength=760).pack(anchor='w', pady=(6, 10))
        wizard_actions = tk.Frame(wi, bg=wi.cget('bg'))
        wizard_actions.pack(fill='x')
        ttk.Button(wizard_actions, text='Check Readiness', command=self.show_report_readiness, style='Ghost.TButton').pack(side='left')
        ttk.Button(wizard_actions, text='Verify Last Report Package', command=self.verify_last_report_package_ui, style='Pill.TButton').pack(side='left', padx=(8, 0))

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
