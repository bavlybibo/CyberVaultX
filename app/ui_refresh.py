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
from .version import APP_VERSION, RELEASE_CHANNEL
from .core.system_health import collect_system_health, summarize_health

class RefreshMixin:
    def refresh_all(self, *, select_id: int | None = None) -> None:
        # Keep the UI responsive: refresh shared identity/metrics every time,
        # then refresh the current workspace first.  Heavy support pages are only
        # refreshed when visible; this avoids rebuilding every table/chart after
        # each small status update.
        self._refresh_identity()
        self._refresh_metrics()
        page = getattr(self, 'current_page', 'dashboard')

        if page in {'vault', 'dashboard', 'generator'}:
            self._refresh_table(select_id=select_id)
            self._refresh_filter_chips()
        if page in {'dashboard', 'security'}:
            self._refresh_security()
        if page in {'dashboard', 'ai_guardian'}:
            self._refresh_ai_guardian()
        if page == 'trash':
            self._refresh_trash()
        if page == 'activity':
            self._refresh_logs()
        if page == 'dashboard':
            self._refresh_dashboard()
        elif page == 'security':
            # Dashboard cards are not visible, but metrics/security visuals are.
            pass
        elif page == 'ai_guardian':
            pass
        if page == 'settings':
            self._refresh_settings_metadata()
        if page in {'reports', 'backup_recovery'}:
            self._refresh_reports_and_backup()
        if page == 'system_health':
            self._refresh_system_health()
        if page == 'about':
            self._refresh_about()
        self._on_activity()

    def _refresh_identity(self) -> None:
        self.owner_var.set(f'Owner: {self.manager.owner_name}')
        self.vault_var.set(self.manager.vault_name)
        state = 'Status: Unlocked' if self.manager.is_unlocked else 'Status: Locked'
        if getattr(self.manager, 'is_demo_vault', False):
            state += ' · DEMO VAULT'
        self.state_var.set(state)
        if hasattr(self, 'demo_banner_var'):
            self.demo_banner_var.set(getattr(self.manager, 'demo_vault_banner', '') or '')

    def _refresh_metrics(self) -> None:
        metrics = self.manager.dashboard()
        total = int(metrics.get('total', 0) or 0)
        for key, var in self.metric_vars.items():
            value = metrics.get(key, 0)
            if key == 'health_score':
                var.set('N/A' if total == 0 else f'{value}/100')
            else:
                var.set(str(value))
        if hasattr(self, 'sec_metric_vars'):
            for key, var in self.sec_metric_vars.items():
                var.set(str(metrics.get(key, 0)))

    def _refresh_table(self, *, select_id: int | None = None) -> None:
        existing = self.selected_id if select_id is None else select_id
        items = self._filtered_credentials()
        self.tree.delete(*self.tree.get_children())
        for row_idx, item in enumerate(items):
            intel = self.manager.breach_intelligence_for(item)
            risk = str(intel.get('risk_level', 'Low')).lower()
            risk_tag = 'critical' if risk == 'critical' else 'high' if risk == 'high' else 'moderate' if risk == 'moderate' else 'low'
            alt_tag = 'evenrow' if row_idx % 2 else 'oddrow'
            self.tree.insert('', 'end', iid=str(item.id), values=(item.title, item.username, item.category, item.tags, self._fmt_dt(item.updated_at)), tags=(risk_tag, alt_tag))
        total_items = len(self.manager.list_credentials())
        if hasattr(self, 'filter_summary_var'):
            if total_items == 0:
                self.filter_summary_var.set('Showing an empty vault. Add or import data to activate search and filters.')
            elif len(items) == total_items:
                self.filter_summary_var.set(f'Showing all {total_items} credential(s).')
            else:
                self.filter_summary_var.set(f'Showing {len(items)} of {total_items} credential(s) after filters.')
        if items:
            self.empty_state.place_forget()
        else:
            self.empty_state.place(relx=0.5, rely=0.5, anchor='center')
        if existing and str(existing) in self.tree.get_children():
            self.tree.selection_set(str(existing))
            self.tree.focus(str(existing))
            self.on_select_credential()
        elif not items:
            self.clear_editor()

    def _filtered_credentials(self) -> list[Credential]:
        items = self.manager.list_credentials()
        term = self.search_var.get().strip().lower()
        category = self.category_filter_var.get()
        threat = self.threat_filter_var.get()
        filtered: list[Credential] = []
        for item in items:
            hay = f'{item.title} {item.username} {item.category} {item.tags} {item.website} {item.notes}'.lower()
            if term and term not in hay:
                continue
            if category != 'All' and item.category != category:
                continue
            if threat != 'All Status':
                intel = self.manager.breach_intelligence_for(item)
                if threat == 'Weak' and intel['score'] >= 60:
                    continue
                if threat == 'Breached' and not intel['breached']:
                    continue
                if threat == 'Reused' and intel['reuse_count'] <= 1:
                    continue
                if threat == 'Old' and not intel['old_password']:
                    continue
                if threat == 'Favorites' and not item.is_favorite:
                    continue
                if threat == 'Recent':
                    try:
                        updated = datetime.fromisoformat(item.updated_at)
                        if updated.tzinfo is None:
                            updated = updated.replace(tzinfo=timezone.utc)
                        if (datetime.now(timezone.utc) - updated) > timedelta(days=14):
                            continue
                    except Exception:
                        continue
            filtered.append(item)
        return filtered

    def _refresh_ai_guardian(self, *, persist_snapshot: bool = False) -> None:
        if not hasattr(self, 'ai_priority_tree'):
            return
        plan = self.manager.ai_security_plan(persist_snapshot=persist_snapshot)
        self.ai_summary_var.set(plan.get('executive_summary', 'Local Security Coach summary unavailable.'))
        self.ai_generated_var.set(f"Generated: {self._fmt_dt(plan.get('generated_at', ''))}")
        self.ai_mode_var.set(f"Mode: {plan.get('mode', 'Local-first Local Security Coach rules')}")
        self.ai_privacy_var.set(f"Privacy: {plan.get('privacy_notice', 'No secrets are included.')}")
        coach_overview = plan.get('coach_overview', {}) or {}
        risk_fusion = plan.get('risk_fusion_summary', {}) or {}
        guardrails = plan.get('guardrail_summary', {}) or {}
        workflow = plan.get('guided_remediation_workflow', {}) or {}
        graph = plan.get('signal_relationship_graph', {}) or {}
        limits = plan.get('honesty_limits', {}) or {}
        if hasattr(self, 'ai_coach_overview_var'):
            self.ai_coach_overview_var.set(f"{coach_overview.get('readiness', 'Local coach ready')}: {coach_overview.get('overview', 'No overview generated yet.')}")
        if hasattr(self, 'ai_first_action_var'):
            self.ai_first_action_var.set(f"First user action: {coach_overview.get('first_action', 'Generate plan, then remediate the top queue item.')}")
        if hasattr(self, 'ai_site_mix_var'):
            self.ai_site_mix_var.set(f"Site profile mix: {coach_overview.get('site_mix', 'waiting for vault data')}")
        if hasattr(self, 'ai_fusion_var'):
            self.ai_fusion_var.set(str(risk_fusion.get('narrative', 'Risk fusion waiting for local telemetry.')))
        if hasattr(self, 'ai_guardrail_var'):
            self.ai_guardrail_var.set(f"{guardrails.get('status', 'WAIT')}: {guardrails.get('narrative', guardrails.get('privacy', 'Guardrails waiting.'))}")
        if hasattr(self, 'ai_top_signal_var'):
            self.ai_top_signal_var.set(f"Top signal: {risk_fusion.get('top_signal', 'n/a')} · Avg confidence {risk_fusion.get('average_confidence', 0)}%")
        if hasattr(self, 'ai_workflow_var'):
            lanes = workflow.get('lanes', []) or []
            hot_lanes = [lane.get('lane', '-') for lane in lanes if lane.get('status') in {'HOT', 'ACTIVE', 'READY'}]
            self.ai_workflow_var.set(f"{workflow.get('narrative', 'Workflow waiting.')} Active lanes: {', '.join(hot_lanes[:2]) or 'none yet'}.")
        if hasattr(self, 'ai_graph_var'):
            self.ai_graph_var.set(f"{graph.get('narrative', 'Signal graph waiting.')} Nodes {graph.get('node_count', 0)} · Edges {graph.get('edge_count', 0)}.")
        if hasattr(self, 'ai_truth_var'):
            self.ai_truth_var.set(f"{limits.get('title', 'Deterministic local coach')}: {limits.get('review_status', 'Verify before export.')}")
        if hasattr(self, 'ai_checkpoint_var'):
            self.ai_checkpoint_var.set(str(workflow.get('next_checkpoint', 'Generate plan, fix top item, verify, export evidence.')))

        risk_cards = plan.get('risk_cards', {})
        for level in ('Critical', 'High', 'Moderate', 'Low'):
            card = risk_cards.get(level, {})
            if hasattr(self, 'ai_risk_vars') and level in self.ai_risk_vars:
                self.ai_risk_vars[level].set(str(card.get('count', 0)))
            if hasattr(self, 'ai_risk_story_vars') and level in self.ai_risk_story_vars:
                self.ai_risk_story_vars[level].set(str(card.get('narrative', 'No narrative available.')))

        self.ai_priority_tree.delete(*self.ai_priority_tree.get_children())
        priority_items = plan.get('priority_items', [])
        for idx, item in enumerate(priority_items, start=1):
            risk_tag = str(item.get('risk_level', 'Low')).lower()
            risk_tag = 'critical' if risk_tag == 'critical' else 'high' if risk_tag == 'high' else 'moderate' if risk_tag == 'moderate' else 'low'
            alt_tag = 'evenrow' if idx % 2 == 0 else 'oddrow'
            self.ai_priority_tree.insert(
                '',
                'end',
                iid=str(idx),
                values=(
                    item.get('credential_ref', 'Credential'),
                    item.get('risk_level', 'Low'),
                    item.get('primary_signal', 'Signal'),
                    f"{item.get('confidence_percent', 0)}%",
                    item.get('timeline', 'Review'),
                    item.get('why', ''),
                    f"{item.get('recommended_action', '')} (+{item.get('expected_score_gain', 0)} est.)",
                ),
                tags=(risk_tag, alt_tag),
            )
        if hasattr(self, 'ai_priority_empty_state'):
            if priority_items:
                self.ai_priority_empty_state.place_forget()
            else:
                self.ai_priority_empty_state.place(relx=0.5, rely=0.58, anchor='center')
        remediation_log = self.manager.get_ai_remediation_log()
        if hasattr(self, 'ai_progress_var'):
            latest = remediation_log[0] if remediation_log else None
            if latest:
                self.ai_progress_var.set(f"Remediation progress: {len(remediation_log)} completed action(s). Latest: {latest.get('credential_ref', 'priority')} at {self._fmt_dt(latest.get('completed_at', ''))}.")
            else:
                self.ai_progress_var.set('Remediation progress: 0 completed actions tracked.')

        action_plan = plan.get('action_plan', {})
        lines = []
        for title, key in [('Today', 'today'), ('This Week', 'this_week'), ('Long-Term', 'long_term')]:
            lines.append(title)
            for item in action_plan.get(key, []):
                lines.append(f'• {item}')
            lines.append('')

        if coach_overview:
            lines.append('AI Coach UX Guidance')
            lines.append(f"• Readiness: {coach_overview.get('readiness', '-')}")
            lines.append(f"• First action: {coach_overview.get('first_action', '-')}")
            lines.append(f"• Site mix: {coach_overview.get('site_mix', '-')}")
            for prompt in coach_overview.get('ux_prompts', [])[:3]:
                lines.append(f'• UX prompt: {prompt}')
            lines.append('')

        lines.append('Guided Remediation Workflow')
        lines.append(f"• {workflow.get('narrative', 'Workflow waiting.')}")
        lines.append(f"• Next checkpoint: {workflow.get('next_checkpoint', '-')}")
        for lane in workflow.get('lanes', [])[:4]:
            lines.append(f"• {lane.get('lane', '-')}: {lane.get('status', '-')}")
            for task in lane.get('tasks', [])[:2]:
                lines.append(f"  - {task}")
        lines.append('')

        lines.append('Signal Relationship Graph')
        lines.append(f"• {graph.get('narrative', 'Signal graph waiting.')}")
        for signal in graph.get('top_signals', [])[:4]:
            lines.append(f"• {signal.get('signal', '-').replace('_', ' ')}: {signal.get('count', 0)} hit(s), weight {signal.get('weight', 0)}")
        lines.append('')

        lines.append('Honest Limits')
        for claim in limits.get('claims', [])[:2]:
            lines.append(f"• Claim: {claim}")
        for limit in limits.get('limits', [])[:2]:
            lines.append(f"• Limit: {limit}")
        lines.append(f"• Review: {limits.get('review_status', '-')}")
        lines.append('')

        lines.append('What Changed')
        for item in plan.get('change_summary', []):
            lines.append(f'• {item}')
        lines.append('')

        remediation_log = self.manager.get_ai_remediation_log()
        lines.append('Remediation Progress')
        if remediation_log:
            lines.append(f"• Completed actions tracked: {len(remediation_log)}")
            for entry in remediation_log[:3]:
                lines.append(f"• {self._fmt_dt(entry.get('completed_at', ''))}: {entry.get('credential_ref', 'priority')} — {entry.get('action', 'completed')}")
        else:
            lines.append('• No completed actions have been tracked yet. Select a priority item and click Mark Selected Fixed after remediation.')
        lines.append('')

        if plan.get('priority_items'):
            lines.append('Local Security Coach v7 Evidence Details')
            for item in plan.get('priority_items', [])[:3]:
                lines.append(f"• {item.get('credential_ref', 'Credential')}: {item.get('attack_scenario', '')}")
                lines.append(f"  Signal: {item.get('primary_signal', 'n/a')} | Confidence: {item.get('confidence_percent', 0)}% ({item.get('confidence_band', 'heuristic')}) | Urgency: {item.get('urgency_score', 0)}/100")
                lines.append(f"  Exposure path: {item.get('exposure_path', 'n/a')}")
                lines.append(f"  Business impact: {item.get('business_impact', '')}")
                lines.append(f"  Risk interlocks: {'; '.join(item.get('risk_interlocks', [])[:2])}")
                lines.append(f"  Control gaps: {'; '.join(item.get('control_gaps', [])[:2])}")
                lines.append(f"  Evidence: {', '.join(item.get('evidence_tags', [])[:4])}")
                playbook = item.get('remediation_playbook', {}) or {}
                if playbook:
                    lines.append('  Do now: ' + ' → '.join(playbook.get('do_now', [])[:2]))
                    lines.append('  Verify: ' + ' → '.join(playbook.get('verify', [])[:2]))
                questions = item.get('verification_questions', [])
                if questions:
                    lines.append('  Analyst check: ' + questions[0])
                lines.append(f"  Expected gain: +{item.get('expected_score_gain', 0)}")
            lines.append('')

        impact = plan.get('fix_impact', {})
        lines.append('Fix Impact Simulation')
        lines.append(f"• Current score: {impact.get('current_score', 'n/a')}/100")
        lines.append(f"• Projected after top fixes: {impact.get('projected_score', 'n/a')}/100")
        lines.append(f"• Estimated gain: {impact.get('estimated_gain', 'n/a')}")
        for item in impact.get('top_fixes', []):
            lines.append(f'• {item}')
        lines.append('')
        self._set_text(self.ai_action_text, '\n'.join(lines).strip())
        self._set_text(self.ai_explanation_text, plan.get('ai_style_explanation', ''))
        if hasattr(self, 'ai_decision_text'):
            decision_lines = []
            for row in plan.get('decision_matrix', []):
                decision_lines.append(f"• {row.get('lens', 'Decision')}: {row.get('status', '-')}")
                decision_lines.append(f"  Why: {row.get('why', '')}")
                decision_lines.append(f"  Next: {row.get('next_step', '')}")
            decision_lines.append('')
            decision_lines.append('Risk Fusion')
            if risk_fusion:
                decision_lines.append(f"• {risk_fusion.get('narrative', '')}")
                decision_lines.append(f"• Multi-signal collisions: {risk_fusion.get('multi_signal_collisions', 0)}")
            decision_lines.append('')
            decision_lines.append('Signal Graph')
            decision_lines.append(f"• {graph.get('narrative', '')}")
            for signal in graph.get('top_signals', [])[:4]:
                decision_lines.append(f"• {signal.get('signal', '-').replace('_', ' ')}: {signal.get('count', 0)} item(s)")
            decision_lines.append('')
            decision_lines.append('Posture Heatmap')
            for row in plan.get('posture_heatmap', []):
                decision_lines.append(f"• {row.get('area', '-')}: {row.get('heat', '-')} ({row.get('count', 0)}) — {row.get('guidance', '')}")
            self._set_text(self.ai_decision_text, '\n'.join(decision_lines).strip() or 'No decision matrix available yet.')
        if hasattr(self, 'ai_quality_text'):
            quality_lines = [f"• {row.get('gate', '-')}: {row.get('status', '-')} — {row.get('detail', '')}" for row in plan.get('quality_gates', [])]
            if guardrails:
                quality_lines.append(f"• Guardrail summary: {guardrails.get('status', '-')} — {guardrails.get('privacy', '')}")
                quality_lines.append(f"• Low-confidence review queue: {guardrails.get('low_confidence_items', 0)} item(s)")
            if limits:
                quality_lines.append(f"• Honesty mode: {limits.get('title', 'deterministic local coach')}")
                for limit in limits.get('limits', [])[:2]:
                    quality_lines.append(f"  Limit: {limit}")
            self._set_text(self.ai_quality_text, '\n'.join(quality_lines) or 'Quality gates are waiting for vault data.')
        payload = plan.get('optional_llm_payload', {})
        self._set_text(self.ai_llm_payload_text, json.dumps(payload, ensure_ascii=False, indent=2)[:3000])
        if hasattr(self, '_draw_ai_coach_visuals'):
            self._draw_ai_coach_visuals(plan)
        if hasattr(self, 'fix_projection_var'):
            self.update_fix_simulator()

    def _refresh_security(self) -> None:
        findings = self.manager.security_findings()
        actionable_findings = [row for row in findings if row.get('issues') or row.get('risk_level') != 'Low']
        self.security_tree.delete(*self.security_tree.get_children())
        risk_counts = {'Critical': 0, 'High': 0, 'Moderate': 0, 'Low': 0}
        for finding in findings:
            risk = finding.get('risk_level', 'Low')
            if risk in risk_counts:
                risk_counts[risk] += 1
        for row_idx, finding in enumerate(actionable_findings):
            issue_preview = '; '.join(finding.get('issues', [])[:2])
            risk_tag = str(finding.get('risk_level', 'Low')).lower()
            risk_tag = 'critical' if risk_tag == 'critical' else 'high' if risk_tag == 'high' else 'moderate' if risk_tag == 'moderate' else 'low'
            alt_tag = 'evenrow' if row_idx % 2 else 'oddrow'
            self.security_tree.insert('', 'end', iid=str(finding['id']), values=(finding['title'], finding['score'], issue_preview), tags=(risk_tag, alt_tag))
        metrics = self.manager.dashboard()
        if hasattr(self, 'sec_metric_vars'):
            value_map = {
                'health_score': f"{metrics.get('health_score', 0)}/100" if metrics.get('total', 0) else 'N/A',
                'critical': risk_counts['Critical'],
                'high': risk_counts['High'],
                'breached': metrics.get('breached', 0),
                'reused_passwords': metrics.get('reused_passwords', 0),
                'old': metrics.get('old', 0),
                'missing_fields': metrics.get('missing_fields', 0),
                'duplicate_sites': metrics.get('duplicate_sites', 0),
            }
            for key, var in self.sec_metric_vars.items():
                var.set(str(value_map.get(key, metrics.get(key, 0))))
        if actionable_findings:
            self.security_empty_state.place_forget()
            if risk_counts['Critical']:
                self.security_focus_var.set('Critical findings exist. Start with breached or severely weak credentials, replace them with generator output, then re-export the report to show score recovery.')
            elif risk_counts['High']:
                self.security_focus_var.set('No critical findings, but high-risk items remain. Reuse, age, and weak complexity are the best visual wins for the presentation.')
            else:
                self.security_focus_var.set('Current posture is mostly moderate or low risk. Focus on cleanup, metadata completeness, and backup discipline.')
        else:
            self.security_empty_state.place(relx=0.5, rely=0.5, anchor='center')
            if findings:
                self._set_text(self.breach_intel_text, 'No actionable security findings. Healthy credentials are kept out of the findings table so the view stays focused on real issues.')
                self.security_focus_var.set('All active credentials are currently low risk. Keep backups fresh and run periodic reviews.')
            else:
                self._set_text(self.breach_intel_text, 'No security intelligence to display yet. Add credentials or load assessment data to activate offline breach checks, duplicate detection, and stale-password analysis.')
                self.security_focus_var.set('No findings yet. Import a CSV or add records so the intelligence and recommendation engine can activate.')
        self._set_text(self.security_recommendations, '\n'.join(f'• {line}' for line in self.manager.recommendations()))
        breakdown_lines = []
        for item in self.manager.score_breakdown(metrics):
            breakdown_lines.append(f"• {item['label']}: {item['count']} item(s) × {item['penalty_each']} penalty = {item['raw_penalty']}")
        if not breakdown_lines:
            breakdown_lines = ['• No negative score drivers yet.']
        self._set_text(self.security_score_story, '\n'.join(breakdown_lines))
        self._set_text(self.security_strengths, '\n'.join(f'• {line}' for line in self.manager.strength_highlights(metrics)))
        if hasattr(self, '_draw_security_visuals'):
            self._draw_security_visuals(metrics, risk_counts, actionable_findings)

    def _refresh_trash(self) -> None:
        items = self.manager.list_credentials(deleted_only=True)
        self.trash_tree.delete(*self.trash_tree.get_children())
        now = datetime.now(timezone.utc)
        expiring = 0
        for row_idx, item in enumerate(items):
            alt_tag = 'evenrow' if row_idx % 2 else 'oddrow'
            self.trash_tree.insert('', 'end', iid=str(item.id), values=(item.title, item.username, self._fmt_dt(item.deleted_at or '')), tags=(alt_tag,))
            try:
                deleted_at = datetime.fromisoformat((item.deleted_at or '').replace('Z', '+00:00'))
                if (now - deleted_at) >= timedelta(days=5):
                    expiring += 1
            except Exception:
                pass
        if hasattr(self, 'trash_summary_vars'):
            self.trash_summary_vars['count'].set(str(len(items)))
            self.trash_summary_vars['expiring'].set(str(expiring))
            self.trash_summary_vars['restore'].set(str(max(0, len(items) - expiring)))
        if hasattr(self, 'trash_empty_state'):
            if items:
                self.trash_empty_state.place_forget()
            else:
                self.trash_empty_state.place(relx=0.5, rely=0.55, anchor='center')

    def _refresh_logs(self) -> None:
        rows = self.manager.get_logs()
        self.log_tree.delete(*self.log_tree.get_children())
        bucket_counts = {'Authentication': 0, 'Sensitive': 0, 'Exports': 0, 'System': 0}
        failed_unlocks = 0
        filter_value = self.activity_filter_var.get() if hasattr(self, 'activity_filter_var') else 'All activity'
        severity_filter = self.activity_severity_var.get() if hasattr(self, 'activity_severity_var') else 'All levels'
        date_filter = self.activity_date_var.get() if hasattr(self, 'activity_date_var') else 'All time'
        search_term = self.activity_search_var.get().strip().lower() if hasattr(self, 'activity_search_var') else ''
        now = datetime.now(timezone.utc)
        cutoff: datetime | None = None
        if date_filter == 'Today':
            cutoff = now.replace(hour=0, minute=0, second=0, microsecond=0)
        elif date_filter == 'Last 7 days':
            cutoff = now - timedelta(days=7)
        elif date_filter == 'Last 30 days':
            cutoff = now - timedelta(days=30)

        for row in rows:
            action = row.get('action', '')
            details = row.get('details', '')
            severity = str(row.get('severity', 'info')).lower()
            bucket = self._activity_bucket(action)
            bucket_counts[bucket] += 1
            if 'unlock' in action.lower() and ('failed' in action.lower() or severity in {'warning', 'danger'}):
                failed_unlocks += 1
            if filter_value != 'All activity' and bucket != filter_value:
                continue
            if severity_filter != 'All levels' and severity != severity_filter.lower():
                continue
            if cutoff is not None:
                try:
                    event_dt = datetime.fromisoformat(str(row.get('timestamp', '')).replace('Z', '+00:00'))
                    if event_dt.tzinfo is None:
                        event_dt = event_dt.replace(tzinfo=timezone.utc)
                    if event_dt < cutoff:
                        continue
                except Exception:
                    continue
            hay = f"{action} {details} {severity}".lower()
            if search_term and search_term not in hay:
                continue
            alt_tag = 'evenrow' if len(self.log_tree.get_children()) % 2 else 'oddrow'
            tags = (severity, alt_tag) if severity in {'warning', 'danger', 'success'} else (alt_tag,)
            self.log_tree.insert('', 'end', values=(self._fmt_dt(row['timestamp']), action, severity.title(), details), tags=tags)
        if hasattr(self, 'activity_summary_vars'):
            self.activity_summary_vars['total'].set(str(len(rows)))
            self.activity_summary_vars['auth'].set(str(bucket_counts['Authentication']))
            self.activity_summary_vars['sensitive'].set(str(bucket_counts['Sensitive']))
            self.activity_summary_vars['exports'].set(str(bucket_counts['Exports']))
            if 'failed' in self.activity_summary_vars:
                self.activity_summary_vars['failed'].set(str(failed_unlocks))

    def _refresh_dashboard(self) -> None:
        metrics = self.manager.dashboard()
        findings = self.manager.security_findings()
        total = int(metrics.get('total', 0) or 0)
        score = metrics['health_score']
        draw_score = None if total == 0 else score
        self._draw_health_score(draw_score)
        self._draw_command_center(draw_score)
        self._render_dashboard_radar(metrics, findings)
        last_backup = self.manager.get_setting('last_backup', '')
        self.command_encryption_var.set('AES-GCM Protected • Local only')
        risk_count = int(metrics.get('weak', 0) or 0) + int(metrics.get('breached', 0) or 0) + int(metrics.get('reused_passwords', 0) or 0)
        self.command_exposure_var.set('Accounts at risk: 0' if total == 0 else f'Accounts at risk: {risk_count}')
        self.command_backup_var.set(f"Last backup: {self._fmt_dt(last_backup) if last_backup else 'never'}")
        self._set_dashboard_side_state(total > 0)
        if total == 0:
            self.dashboard_welcome_var.set('Welcome to your new vault.')
            note = 'No credentials yet. Import a browser CSV, add a first record, or load a assessment scenario to activate scoring and recommendations.'
            self.command_note_var.set('No vault data yet. Add or import credentials to activate the score and recommendations.')
        elif score >= 85:
            self.dashboard_welcome_var.set('Welcome back.')
            note = 'Vault health is excellent. Keep rotating old credentials and exporting encrypted backups.'
            self.command_note_var.set('Low-friction posture. Keep backups fresh and review older credentials on schedule.')
        elif score >= 70:
            self.dashboard_welcome_var.set('Welcome back.')
            note = 'Healthy overall, but there are still some practical fixes to make.'
            self.command_note_var.set('Stable overall. Review a few watch-list credentials and tighten remaining weak spots.')
        elif score >= 50:
            self.dashboard_welcome_var.set('Attention needed.')
            note = 'Moderate health. Prioritize breached, weak, reused, and old credentials.'
            self.command_note_var.set('Risk is building. Review Security Center and replace weak or reused passwords.')
        else:
            self.dashboard_welcome_var.set('Immediate action recommended.')
            note = 'Risk is elevated. Replace breached/reused passwords and tidy metadata quickly.'
            self.command_note_var.set('Critical issues detected. Open Security Center and rotate the highest-risk credentials first.')
        self.health_note_var.set(note)
        self._set_dashboard_actions(metrics)
        auth_rows = [row for row in self.manager.get_logs(limit=40) if 'Unlock' in row['action'] or 'Locked' in row['action'] or 'Panic' in row['action']][:4]
        self._render_auth_timeline(auth_rows)

    def _refresh_settings_metadata(self) -> None:
        last_backup = self.manager.get_setting('last_backup', '')
        self.last_backup_var.set(f"Last backup: {self._fmt_dt(last_backup) if last_backup else 'never'}")
        created_on = self.manager.get_setting('created_on', '')
        self.created_on_var.set(f"Vault created: {self._fmt_dt(created_on) if created_on else '-'}")
        rotated_on = self.manager.get_setting('master_password_rotated_at', '')
        self.master_rotation_var.set(
            f"Master password last rotated: {self._fmt_dt(rotated_on) if rotated_on else 'not recorded'}"
        )
        dataset_size = breach_db_size()
        self.breach_dataset_var.set(
            f"Offline breach dataset: {dataset_size} local SHA1 hash(es). Bundled subset plus optional custom imported hashes; no internet upload is used."
        )
        guard = self.manager.unlock_guard_status()
        if guard.get('blocked'):
            self.unlock_guard_var.set(
                f"Unlock guard: temporary lockout active for about {guard.get('remaining_seconds', 0)} second(s)."
            )
        elif int(guard.get('failed_attempts', 0)) > 0:
            remaining = max(0, int(guard.get('lockout_threshold', 3)) - int(guard.get('failed_attempts', 0)))
            self.unlock_guard_var.set(
                f"Unlock guard: {guard.get('failed_attempts', 0)} failed attempt(s) recorded in this session, {remaining} before temporary lockout."
            )
        else:
            self.unlock_guard_var.set('Unlock guard: active, no temporary lockout in effect.')


    def _refresh_reports_and_backup(self) -> None:
        """Keep the new Reports and Backup/Recovery pages live without adding storage state."""
        try:
            metrics = self.manager.dashboard()
            total = int(metrics.get('total', 0) or 0)
            findings_count = sum(int(metrics.get(key, 0) or 0) for key in ('weak', 'breached', 'reused_passwords', 'old'))
            logs = self.manager.get_logs(limit=120)
            delivery_rows = [
                row for row in logs
                if any(term in str(row.get('action', '')).lower() for term in ('report', 'package', 'backup', 'export', 'verify'))
            ]
            last_backup = self.manager.get_setting('last_backup', '')
            if hasattr(self, 'report_stat_vars'):
                self.report_stat_vars['accounts'].set(str(total))
                self.report_stat_vars['findings'].set(str(findings_count))
                self.report_stat_vars['exports'].set(str(len(delivery_rows)))
                self.report_stat_vars['last'].set(self._fmt_dt(last_backup) if last_backup else 'Never')
            if hasattr(self, 'report_summary_var'):
                if total == 0:
                    self.report_summary_var.set('No credentials yet. Reports will show methodology and empty-state guidance until vault data exists.')
                elif findings_count:
                    self.report_summary_var.set(f'Report preview: {total} account(s) in scope with {findings_count} open finding(s). Use privacy-safe mode for screenshots or external review.')
                else:
                    self.report_summary_var.set(f'Report preview: {total} account(s) in scope with no urgent findings. Export an executive report for the live demo.')
            if hasattr(self, 'report_tree'):
                self.report_tree.delete(*self.report_tree.get_children())
                for idx, row in enumerate(delivery_rows[:30], start=1):
                    severity = str(row.get('severity', 'info')).lower()
                    tag = severity if severity in {'success', 'warning', 'danger'} else ('evenrow' if idx % 2 == 0 else 'oddrow')
                    self.report_tree.insert('', 'end', iid=f'report-{idx}', values=(
                        self._fmt_dt(row.get('timestamp', '')),
                        row.get('action', 'Delivery event'),
                        severity.title(),
                        row.get('details', ''),
                    ), tags=(tag,))
                if hasattr(self, 'report_empty_state'):
                    if delivery_rows:
                        self.report_empty_state.place_forget()
                    else:
                        self.report_empty_state.place(relx=0.5, rely=0.5, anchor='center')
            if hasattr(self, 'report_readiness_var'):
                readiness = self.manager.report_readiness_score(privacy_level=self.report_privacy_default_var.get())
                bits = []
                if readiness.get('blockers'):
                    bits.append('blockers present')
                if readiness.get('warnings'):
                    bits.append(f"{len(readiness.get('warnings', []))} warning(s)")
                detail = ', '.join(bits) if bits else 'privacy and verification checks clear'
                self.report_readiness_var.set(f"Report Readiness: {readiness.get('percentage', 0)}% — {readiness.get('status', 'Unknown')} · {detail}.")
            if hasattr(self, 'report_history_var'):
                self.report_history_var.set('Recent delivery events are sanitized by the current privacy settings.')

            snapshots = self.manager.list_safety_snapshots()
            if hasattr(self, 'backup_status_panel_var'):
                if last_backup:
                    self.backup_status_panel_var.set(f'Last encrypted backup: {self._fmt_dt(last_backup)} · Safety snapshots: {len(snapshots)}')
                else:
                    self.backup_status_panel_var.set(f'No encrypted backup recorded yet · Safety snapshots: {len(snapshots)}')
            if hasattr(self, 'backup_recovery_hint_var'):
                self.backup_recovery_hint_var.set('Backups use a separate passphrase, restore preview is non-destructive, and replace operations create safety snapshots first.')
            if hasattr(self, 'backup_flow_step_var'):
                self.backup_flow_step_var.set('Current recommendation: export a fresh encrypted backup before master-password rotation, bulk import, or live demo setup.')
        except Exception:
            # UI refresh should never block vault use.
            pass

    def _refresh_system_health(self) -> None:
        if not hasattr(self, 'health_tree'):
            return
        checks = collect_system_health(Path(__file__).resolve().parents[1], self.db_path.parent)
        summary = summarize_health(checks)
        self.system_health_summary_var.set(
            f"Health score: {summary['score']}/100 · {summary['label']} · "
            f"PASS {summary['passed']} / WARN {summary['warnings']} / FAIL {summary['failed']}"
        )
        self.health_tree.delete(*self.health_tree.get_children())
        for idx, item in enumerate(checks, start=1):
            status = str(item.get('status', 'warn')).upper()
            tag = str(item.get('status', 'warn'))
            self.health_tree.insert('', 'end', iid=f'health-{idx}', values=(item.get('category', '-'), status, f"{item.get('name', '-')}: {item.get('detail', '-')}",), tags=(tag,))

    def _refresh_about(self) -> None:
        dataset_size = breach_db_size()
        favicon_status = 'Enabled by user' if self.favicon_lookup_var.get() else 'Disabled by default for privacy'
        about = (
            f'Vault Name: {self.manager.vault_name}\n'
            f'Owner: {self.manager.owner_name}\n'
            f'Version: {APP_VERSION} ({RELEASE_CHANNEL})\n'
            'Storage: local SQLite + per-field AES-GCM encryption\n'
            'Key Derivation: PBKDF2-SHA256 (600k iterations)\n'
            'Breach Detection: offline HIBP-style local SHA1 hash set\n'
            f'Offline breach dataset size: {dataset_size} hash(es) bundled locally for offline weak/breached-password checks\n'
            f'Online favicon lookup: {favicon_status}\n'
            'Recent upgrades: composite Local Security Coach risk scoring, privacy-safe reports, hardened favicon lookup, transaction-safe backup import, master-password rotation, secure clipboard clearing, encrypted backup/restore, password history, health scoring, recommendations, duplicate detection, owner branding, accent themes, and audit logs.'
        )
        self.about_var.set(about)

    def on_select_credential(self, _event=None) -> None:
        selection = self.tree.selection()
        if not selection:
            return
        cid = int(selection[0])
        item = self.manager.get_credential(cid)
        if not item:
            return
        self.selected_id = cid
        self.title_var.set(item.title)
        self.username_var.set(item.username)
        self.password_var.set('••••••••••••')
        self.category_var.set(item.category or 'General')
        self.tags_var.set(item.tags)
        self.website_var.set(item.website)
        self.favorite_var.set(item.is_favorite)
        self.notes_text.delete('1.0', 'end')
        self.notes_text.insert('1.0', item.notes)
        self.created_var.set(f'Created: {self._fmt_dt(item.created_at)}')
        self.updated_var.set(f'Updated: {self._fmt_dt(item.updated_at)}')
        self.copy_stats_var.set(f'Copies: {item.copy_count} | Reveals: {item.view_count}')
        self._render_site_visual(item.website, item.title, item.category)
        self._set_history(self.manager.get_password_history(cid))
        self._render_credential_badges(item)
        self.update_analysis_panel(item)

    def on_select_finding(self, _event=None) -> None:
        selection = self.security_tree.selection()
        if not selection:
            return
        cid = int(selection[0])
        intel = self.manager.breach_intelligence_for(cid)
        self._render_breach_intelligence(intel)
        if str(cid) in self.tree.get_children():
            self.tree.selection_set(str(cid))
            self.tree.focus(str(cid))
            self.on_select_credential()

    def on_select_trash(self, _event=None) -> None:
        selection = self.trash_tree.selection()
        if selection:
            self.selected_trash_id = int(selection[0])

    def update_analysis_panel(self, item: Credential | None = None) -> None:
        actual = item or (self.manager.get_credential(self.selected_id) if self.selected_id else None)
        password = actual.password if actual else self.password_var.get().replace('•', '')
        context = f'{self.title_var.get()} {self.username_var.get()} {self.website_var.get()}'
        analysis = analyze_password(password, context=context)
        intel = self.manager.breach_intelligence_for(actual) if actual else None
        fit = evaluate_password_fit(
            password,
            title=self.title_var.get(),
            username=self.username_var.get(),
            website=self.website_var.get(),
            category=self.category_var.get(),
            password_score=analysis.score,
            breached=bool(intel.get('breached')) if intel else False,
            common_password=bool(intel.get('common_password')) if intel else False,
            reuse_count=int(intel.get('reuse_count', 1) or 1) if intel else 1,
            updated_at_iso=actual.updated_at if actual else '',
        )
        issues = list(analysis.warnings)
        if actual:
            if password_is_old(actual.updated_at):
                issues.append('Password is older than 90 days.')
            history = self.manager.get_password_history(actual.id)
            if any(h['password'] == actual.password for h in history):
                issues.append('Current password matches a previously used password.')
        self.strength_var.set(f'Strength: {analysis.label} ({analysis.score}/100)')
        self.entropy_var.set(f'Entropy: {analysis.entropy_bits} bits')
        self.entropy_note_var.set(f'Entropy explanation: {analysis.entropy_note}')
        if fit.fit_score < 70:
            issues.append(f'Site-fit needs work: {fit.profile} ({fit.fit_score}/100).')
        self.issue_var.set('Issues: ' + ('; '.join(issues) if issues else 'None detected.'))
        self.site_fit_var.set(f'{fit.fit_score}/100 · {fit.fit_label}')
        self.site_policy_var.set(f'Site profile: {fit.profile} · Risk tier: {fit.risk_tier} · Heuristic confidence: {fit.confidence}%')
        self.site_policy_detail_var.set(f'{fit.site_reason} {fit.symbol_guidance}'.strip())
        if hasattr(self, 'site_policy_text'):
            self._set_text(self.site_policy_text, '\n'.join(format_policy_fit_lines(fit)))
        self._draw_live_coach_meter(fit.fit_score, fit.fit_label) if hasattr(self, '_draw_live_coach_meter') else None
        suggestion_lines = []
        if analysis.patterns:
            suggestion_lines.append('Detected patterns: ' + ', '.join(analysis.patterns))
        suggestion_lines.extend(f'• {s}' for s in analysis.suggestions)
        if fit.must_fix or fit.warnings:
            suggestion_lines.append('')
            suggestion_lines.append('Site-specific password logic:')
            suggestion_lines.extend(f'• {s}' for s in (fit.must_fix[:4] or fit.warnings[:4]))
        if intel and (intel.get('breached') or intel.get('common_password') or intel.get('reuse_count', 1) > 1 or intel.get('old_password')):
            suggestion_lines.append('')
            suggestion_lines.append('Local breach intelligence:')
            suggestion_lines.extend(f'• {s}' for s in intel.get('fix_recommendations', []))
        if not suggestion_lines:
            suggestion_lines = ['No immediate improvements required.']
        self._set_text(self.suggestions_text, '\n'.join(suggestion_lines))
