from __future__ import annotations

from pathlib import Path
import tkinter as tk

from .manager import Credential, VaultManager
from .ui_shared import *
from .ui_visual import VisualMixin
from .ui_pages import PagesMixin
from .ui_dialogs import DialogsMixin
from .ui_controllers import ControllersMixin
from .ui_refresh import RefreshMixin


class PasswordManagerApp(VisualMixin, PagesMixin, DialogsMixin, ControllersMixin, RefreshMixin, tk.Tk):
    def __init__(self, db_path: str | Path) -> None:
        super().__init__()
        self.title('CyberVaultX — Security Intelligence Vault')
        self.geometry('1500x900')
        # More presentation-friendly on common laptop/projector resolutions.
        self.minsize(1160, 720)
        self.configure(bg=APP_BG)
        self.withdraw()

        self.manager = VaultManager(db_path)
        self.real_manager = self.manager
        self.demo_manager: VaultManager | None = None
        self.demo_mode_active = False
        self.db_path = Path(db_path)
        self.selected_id: int | None = None
        self.selected_trash_id: int | None = None
        self.reauth_target: int | None = None
        self.pending_copy_payload: tuple[int, str, str] | None = None
        self.pending_history_payload: tuple[int, str, str] | None = None
        self._clipboard_owned_value: str | None = None
        self.auth_window: tk.Toplevel | None = None
        self.clipboard_job: str | None = None
        self.auto_lock_job: str | None = None
        self.reveal_hide_job: str | None = None
        self.favicon_cache_dir = self.db_path.parent / 'favicons'
        self.favicon_cache_dir.mkdir(parents=True, exist_ok=True)
        self.current_favicon_image = None
        self._favicon_request_host = ''
        self._brand_images: dict[str, tk.PhotoImage] = {}
        self.splash_window: tk.Toplevel | None = None
        self.sidebar_buttons: dict[str, tk.Button] = {}
        self.pages: dict[str, tk.Frame] = {}
        self.current_page = 'dashboard'
        self.toast_window: tk.Toplevel | None = None
        self.toast_after_id: str | None = None

        self.search_var = tk.StringVar()
        self.filter_summary_var = tk.StringVar(value='Showing all credentials in the vault.')
        self.activity_search_var = tk.StringVar()
        self.activity_filter_var = tk.StringVar(value='All activity')
        self.activity_severity_var = tk.StringVar(value='All levels')
        self.activity_date_var = tk.StringVar(value='All time')
        self.dashboard_priority_var = tk.StringVar(value='No urgent actions yet.')
        self.dashboard_welcome_var = tk.StringVar(value='Welcome back.')
        self.generator_meter_var = tk.StringVar(value='Entropy profile unavailable.')
        self.live_coach_var = tk.StringVar(value='Live coach waiting for password input.')
        self.live_coach_hint_var = tk.StringVar(value='Type a password, website, and category to see site-fit logic instantly.')
        self.live_coach_status_var = tk.StringVar(value='Readiness: waiting')
        self.live_coach_action_var = tk.StringVar(value='Next best action: add website + password to activate coach.')
        self.site_policy_var = tk.StringVar(value='Site profile: waiting')
        self.site_fit_var = tk.StringVar(value='Fit: —')
        self.site_policy_detail_var = tk.StringVar(value='The site policy reasoner uses local metadata only; no password leaves the app.')
        self.search_hint_var = tk.StringVar(value='Search sites, usernames, tags...')
        self.category_filter_var = tk.StringVar(value='All')
        self.threat_filter_var = tk.StringVar(value='All Status')
        self.status_var = tk.StringVar(value='Vault locked.')
        self.command_encryption_var = tk.StringVar(value='AES-GCM Protected')
        self.command_exposure_var = tk.StringVar(value='Accounts at risk: 0')
        self.command_backup_var = tk.StringVar(value='Last backup: never')
        self.command_note_var = tk.StringVar(value='Add or import credentials to light up the command center.')
        self.presentation_mode = False
        self.page_title_var = tk.StringVar(value=PAGE_META['dashboard'][0])
        self.page_subtitle_var = tk.StringVar(value=PAGE_META['dashboard'][1])
        self.page_context_var = tk.StringVar(value=PAGE_CONTEXT['dashboard'][0])
        self.page_tip_var = tk.StringVar(value=PAGE_CONTEXT['dashboard'][1])
        self.theme_var = tk.StringVar(value=self.manager.get_setting('theme_accent', 'Cyan'))
        self.auto_lock_var = tk.IntVar(value=self.manager.get_setting_int('auto_lock_minutes', 3))
        self.clipboard_clear_var = tk.IntVar(value=self.manager.get_setting_int('clipboard_clear_seconds', 15))
        self.favicon_lookup_var = tk.BooleanVar(value=self.manager.get_setting('favicon_lookup_enabled', '0').strip().lower() in {'1', 'true', 'yes', 'on'})
        self.privacy_logs_var = tk.BooleanVar(value=self.manager.get_setting('privacy_mode_logs', '1').strip().lower() in {'1', 'true', 'yes', 'on'})
        self.auto_lock_preview_var = tk.StringVar(value=f'Auto-lock after inactivity: {self.auto_lock_var.get()} minute(s)')
        self.clipboard_preview_var = tk.StringVar(value=f'Clipboard auto-clear: {self.clipboard_clear_var.get()} second(s)')
        self.unlock_guard_var = tk.StringVar(value='Unlock guard: active, no temporary lockout in effect.')
        self.master_rotation_var = tk.StringVar(value='Master password has not been rotated yet.')
        self.breach_dataset_var = tk.StringVar(value='Offline breach dataset: local SHA1 risk subset.')
        self.current_master_var = tk.StringVar()
        self.new_master_var = tk.StringVar()
        self.confirm_master_var = tk.StringVar()
        self.generator_length_var = tk.IntVar(value=18)
        self.generator_upper_var = tk.BooleanVar(value=True)
        self.generator_lower_var = tk.BooleanVar(value=True)
        self.generator_digits_var = tk.BooleanVar(value=True)
        self.generator_symbols_var = tk.BooleanVar(value=True)
        self.generator_easy_read_var = tk.BooleanVar(value=False)
        self.generated_password_var = tk.StringVar()
        self.generator_use_case_var = tk.StringVar(value='General')
        self.ai_summary_var = tk.StringVar(value='Deterministic Local Security Coach has not generated a plan yet.')
        self.ai_generated_var = tk.StringVar(value='Generated: -')
        self.ai_mode_var = tk.StringVar(value='Mode: Deterministic local analysis · Site Policy Reasoner + Risk Fusion + Live Coach UX/UI')
        self.ai_privacy_var = tk.StringVar(value='Privacy: no raw passwords, full usernames, notes, paths, or backup data.')
        self.ai_coach_overview_var = tk.StringVar(value='Local coach overview appears after the vault is analyzed.')
        self.ai_site_mix_var = tk.StringVar(value='Site profile mix: waiting for vault data.')
        self.ai_first_action_var = tk.StringVar(value='First user action: waiting for ranked priority.')
        self.ai_fusion_var = tk.StringVar(value='Risk fusion: waiting for local telemetry.')
        self.ai_guardrail_var = tk.StringVar(value='Evidence guardrails: waiting for generated plan.')
        self.ai_top_signal_var = tk.StringVar(value='Top signal: waiting')
        self.ai_workflow_var = tk.StringVar(value='Guided workflow: waiting for ranked remediation lanes.')
        self.ai_graph_var = tk.StringVar(value='Risk graph: waiting for signal/account relationships.')
        self.ai_truth_var = tk.StringVar(value='Honest limits: deterministic, local, no external model claims.')
        self.ai_checkpoint_var = tk.StringVar(value='Next checkpoint: generate plan, fix top item, verify, export evidence.')
        self.fix_weak_var = tk.BooleanVar(value=True)
        self.fix_reused_var = tk.BooleanVar(value=True)
        self.fix_old_var = tk.BooleanVar(value=True)
        self.fix_metadata_var = tk.BooleanVar(value=True)
        self.fix_trash_var = tk.BooleanVar(value=True)
        self.fix_backup_var = tk.BooleanVar(value=True)
        self.fix_projection_var = tk.StringVar(value='Projected score appears after vault data is available.')
        self.proof_status_var = tk.StringVar(value='Security Proof Center has not run yet.')
        self.package_verify_var = tk.StringVar(value='No report package verified yet.')
        self.backup_preview_var = tk.StringVar(value='No backup preview generated yet.')
        self.report_privacy_default_var = tk.StringVar(value=self.manager.get_setting('default_report_privacy_level', 'analyst'))
        self.report_summary_var = tk.StringVar(value='No report generated yet. Choose a report type to create a safe preview or export package.')
        self.report_readiness_var = tk.StringVar(value='Report Readiness: waiting for vault data.')
        self.report_artifacts_var = tk.StringVar(value='Artifacts after package export: HTML report, audit log, coach summary, manifest, verification output.')
        self.report_history_var = tk.StringVar(value='Report history appears after exports and package verification events.')
        self.backup_status_panel_var = tk.StringVar(value='No encrypted backup has been created in this session.')
        self.backup_recovery_hint_var = tk.StringVar(value='Backups use a separate passphrase and restore preview before modifying the vault.')
        self.backup_flow_step_var = tk.StringVar(value='Recommended flow: export backup → verify file location → preview restore before import.')

        self.title_var = tk.StringVar()
        self.username_var = tk.StringVar()
        self.password_var = tk.StringVar()
        self.category_var = tk.StringVar(value='General')
        self.tags_var = tk.StringVar()
        self.website_var = tk.StringVar()
        self.favorite_var = tk.BooleanVar(value=False)
        self.updated_var = tk.StringVar(value='Updated: -')
        self.created_var = tk.StringVar(value='Created: -')
        self.copy_stats_var = tk.StringVar(value='Copies: 0 | Reveals: 0')

        self.metric_vars: dict[str, tk.StringVar] = {}
        self.owner_var = tk.StringVar()
        self.vault_var = tk.StringVar()
        self.state_var = tk.StringVar()
        self.demo_banner_var = tk.StringVar(value='')
        self.health_note_var = tk.StringVar()
        self.about_var = tk.StringVar()
        self.system_health_summary_var = tk.StringVar(value='System health has not been checked yet.')
        self.site_host_var = tk.StringVar(value='No site selected')
        self.last_backup_var = tk.StringVar(value='Last backup: never')
        self.created_on_var = tk.StringVar(value='Vault created: -')

        self._apply_theme(self.theme_var.get())
        self._apply_window_branding()
        self._show_splash_screen()
        self._build_ui()
        self._bind_live_password_coach()
        self._bind_activity_tracking()
        self._bind_shortcuts()
        self.after(900, self._show_startup_dialog)


def run_app(db_path: str | Path) -> None:
    app = PasswordManagerApp(db_path)
    app.mainloop()
