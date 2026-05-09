from __future__ import annotations

import tkinter as tk

from .ui_shared import *


def build_proof_tab(self) -> None:
    root = self.proof_tab
    top = self._card(root, bg=PANEL_DEEP, padx=16, pady=14)
    top.pack(fill='x', pady=(0, 12))
    ti = top.inner
    left = tk.Frame(ti, bg=ti.cget('bg'))
    left.pack(side='left', fill='x', expand=True)
    self._label(left, 'Security Proof Center', bg=left.cget('bg'), font=('Segoe UI Semibold', 14)).pack(anchor='w')
    self._label(
        left,
        'Run local proof checks, verify report-package hashes, preview backup restore impact, and confirm local audit hash-chain integrity before delivery.',
        fg=MUTED,
        bg=left.cget('bg'),
        font=('Segoe UI', 9),
        wraplength=860,
    ).pack(anchor='w', pady=(4, 0))
    actions = tk.Frame(ti, bg=ti.cget('bg'))
    actions.pack(side='right')
    self._top_action_button(actions, 'Run Proof Checks', self.run_security_proof_center, kind='accent').pack(side='left')
    self._top_action_button(actions, 'Verify Package', self.verify_report_package_ui).pack(side='left', padx=(8, 0))
    self._top_action_button(actions, 'Preview Backup', self.preview_backup_restore_ui).pack(side='left', padx=(8, 0))
    self._top_action_button(actions, 'Attack Lab', self.run_attack_simulation_lab_ui).pack(side='left', padx=(8, 0))
    self._top_action_button(actions, 'Evidence Package', self.export_security_evidence_package_ui).pack(side='left', padx=(8, 0))
    self._top_action_button(actions, 'Emergency Kit', self.export_emergency_kit_ui).pack(side='left', padx=(8, 0))

    grid = tk.Frame(root, bg=APP_BG)
    grid.pack(fill='both', expand=True)

    left_card = self._card(grid, bg=CARD_BG, padx=16, pady=16)
    left_card.pack(side='left', fill='both', expand=True, padx=(0, 12))
    li = left_card.inner
    self._label(li, 'Proof Checks', bg=li.cget('bg'), font=('Segoe UI Semibold', 13)).pack(anchor='w')
    self._label(li, textvariable=self.proof_status_var, bg=li.cget('bg'), fg=SUBTEXT, font=('Segoe UI', 9), wraplength=720).pack(anchor='w', pady=(4, 10))
    self.proof_text = tk.Text(li, height=22, wrap='word', bg=INPUT_BG, fg=TEXT, insertbackground=TEXT, relief='flat', bd=0, padx=10, pady=10)
    self.proof_text.pack(fill='both', expand=True)
    self._style_text_widget(self.proof_text)
    self.proof_text.configure(state='disabled')

    right_card = self._card(grid, bg=CARD_BG_2, padx=16, pady=16)
    right_card.pack(side='right', fill='both', expand=True)
    ri = right_card.inner
    self._label(ri, 'Package Verifier', bg=ri.cget('bg'), font=('Segoe UI Semibold', 13)).pack(anchor='w')
    self._label(ri, textvariable=self.package_verify_var, bg=ri.cget('bg'), fg=SUBTEXT, font=('Segoe UI', 9), wraplength=520).pack(anchor='w', pady=(4, 10))
    self.package_verify_text = tk.Text(ri, height=12, wrap='word', bg=INPUT_BG, fg=TEXT, insertbackground=TEXT, relief='flat', bd=0, padx=10, pady=10)
    self.package_verify_text.pack(fill='x')
    self._style_text_widget(self.package_verify_text)
    self.package_verify_text.configure(state='disabled')

    bonus_row = tk.Frame(ri, bg=ri.cget('bg'))
    bonus_row.pack(fill='x', pady=(14, 0))
    self._top_action_button(bonus_row, 'Privacy Preview', self.show_privacy_preview_ui).pack(side='left')
    self._top_action_button(bonus_row, 'Relationship Graph', self.show_relationship_graph_ui).pack(side='left', padx=(8, 0))
    self._top_action_button(bonus_row, 'Remediation Plan', self.show_remediation_planner_ui).pack(side='left', padx=(8, 0))

    self._label(ri, 'Backup Restore Preview / Bonus Evidence', bg=ri.cget('bg'), font=('Segoe UI Semibold', 13)).pack(anchor='w', pady=(16, 0))
    self._label(ri, textvariable=self.backup_preview_var, bg=ri.cget('bg'), fg=SUBTEXT, font=('Segoe UI', 9), wraplength=520).pack(anchor='w', pady=(4, 10))
    self.backup_preview_text_proof = tk.Text(ri, height=12, wrap='word', bg=INPUT_BG, fg=TEXT, insertbackground=TEXT, relief='flat', bd=0, padx=10, pady=10)
    self.backup_preview_text_proof.pack(fill='both', expand=True)
    self._style_text_widget(self.backup_preview_text_proof)
    self.backup_preview_text_proof.configure(state='disabled')


