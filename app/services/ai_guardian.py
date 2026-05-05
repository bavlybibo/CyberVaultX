from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..io_utils import atomic_write_text, safe_display_path


class AIGuardianServiceMixin:
    def _load_ai_metrics_snapshot(self) -> dict[str, Any] | None:
        raw = self.db.get_meta('ai_last_snapshot_json')
        if not raw:
            return None
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError:
            return None
        metrics = payload.get('metrics') if isinstance(payload, dict) else None
        return dict(metrics) if isinstance(metrics, dict) else None

    def _store_ai_metrics_snapshot(self, metrics: dict[str, Any]) -> None:
        payload = {
            'created_at': self.vault_snapshot().created_at,
            'metrics': dict(metrics),
        }
        self.db.set_meta('ai_last_snapshot_json', json.dumps(payload, ensure_ascii=False, sort_keys=True))
        self.db.set_meta('ai_last_snapshot_at', str(payload['created_at']))

    def ai_advisor_context(self) -> dict[str, Any]:
        from ..ai import build_redacted_advisor_context

        snapshot = self.vault_snapshot()
        return build_redacted_advisor_context(snapshot.metrics, snapshot.findings)

    def ai_security_plan(self, *, persist_snapshot: bool = False) -> dict[str, Any]:
        from ..ai import generate_local_security_plan

        snapshot = self.vault_snapshot()
        previous = self._load_ai_metrics_snapshot()
        plan = generate_local_security_plan(snapshot.metrics, snapshot.findings, previous_metrics=previous)
        plan['baseline_persisted'] = bool(persist_snapshot)
        if persist_snapshot:
            self._store_ai_metrics_snapshot(snapshot.metrics)
        return plan

    def capture_ai_metrics_baseline(self) -> dict[str, Any]:
        snapshot = self.vault_snapshot()
        self._store_ai_metrics_snapshot(snapshot.metrics)
        self.add_log('AI Guardian Baseline Captured', 'Captured current vault metrics as the comparison baseline.', 'success')
        return {'captured_at': self.db.get_meta('ai_last_snapshot_at') or '', 'metrics': dict(snapshot.metrics)}


    def get_ai_remediation_log(self) -> list[dict[str, Any]]:
        raw = self.db.get_meta('ai_remediation_log_json') or '[]'
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError:
            return []
        return [dict(item) for item in payload] if isinstance(payload, list) else []

    def mark_ai_remediation_complete(self, credential_ref: str, action: str = '') -> dict[str, Any]:
        """Record a non-destructive remediation checkpoint for demo/progress tracking."""
        entry = {
            'completed_at': datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
            'credential_ref': str(credential_ref or 'Selected priority'),
            'action': str(action or 'Marked AI Guardian recommendation as completed'),
        }
        log = self.get_ai_remediation_log()
        log.insert(0, entry)
        log = log[:100]
        self.db.set_meta('ai_remediation_log_json', json.dumps(log, ensure_ascii=False, sort_keys=True))
        self.add_log('AI Remediation Completed', f"Marked {entry['credential_ref']} as fixed in AI Guardian progress tracker.", 'success')
        self._invalidate_snapshot()
        return {'completed_count': len(log), 'latest': entry}

    def clear_ai_remediation_log(self) -> None:
        self.db.set_meta('ai_remediation_log_json', '[]')
        self.add_log('AI Remediation Progress Cleared', 'Cleared AI Guardian remediation progress tracker.', 'warning')

    def export_ai_summary(self, path: str | Path, *, privacy_level: str | None = None) -> Path:
        plan = self.ai_security_plan(persist_snapshot=False)
        dest = Path(path)
        privacy_level = privacy_level or self.get_setting('default_report_privacy_level', 'analyst') or 'analyst'
        privacy_safe = privacy_level != 'full'
        title = 'CyberVault Privacy-Safe AI Guardian Security Plan Summary' if privacy_safe else f"{self.vault_name} — AI Guardian Security Plan"
        lines = [
            title,
            f"Generated: {plan['generated_at']}",
            f"Mode: {plan['mode']}",
            f"Export privacy level: {privacy_level}",
            f"Privacy: {plan['privacy_notice']}",
            '=' * 58,
            'Executive Summary',
            plan['executive_summary'],
            '',
            'Risk Cards',
        ]
        for level, card in plan['risk_cards'].items():
            lines.append(f"- {level}: {card['count']} — {card['narrative']}")
        lines.extend(['', 'Top Priority Items'])
        if plan['priority_items']:
            for idx, item in enumerate(plan['priority_items'], start=1):
                lines.append(f"{idx}. {item['credential_ref']} | {item['risk_level']} | {item['timeline']}")
                lines.append(f"   Why: {item['why']}")
                lines.append(f"   Primary signal: {item.get('primary_signal', 'n/a')} | Confidence: {item.get('confidence_percent', 0)}% | Urgency: {item.get('urgency_score', 0)}/100")
                lines.append(f"   Site profile: {item.get('site_profile', 'General')} | Site-fit: {item.get('site_fit_score', 'n/a')}/100 ({item.get('site_fit_label', '-')})")
                if item.get('site_policy_requirements'):
                    lines.append(f"   Inferred site requirements: {', '.join(item.get('site_policy_requirements', [])[:4])}")
                lines.append(f"   Exposure path: {item.get('exposure_path', 'n/a')}")
                lines.append(f"   Evidence: {', '.join(item.get('evidence_tags', [])[:5]) or 'n/a'}")
                lines.append(f"   Attack scenario: {item.get('attack_scenario', 'n/a')}")
                lines.append(f"   Business impact: {item.get('business_impact', 'n/a')}")
                lines.append(f"   Action: {item['recommended_action']}")
                lines.append(f"   Expected score gain: +{item.get('expected_score_gain', 0)}")
                for step in item.get('fix_path', [])[:5]:
                    lines.append(f"   - Fix step: {step}")
                for trace in item.get('decision_trace', [])[:4]:
                    lines.append(f"   - Decision trace: {trace}")
        else:
            lines.append('- No urgent items detected.')
        coach = plan.get('coach_overview', {}) or {}
        lines.extend(['', 'AI Coach UX Snapshot'])
        lines.append(f"- Readiness: {coach.get('readiness', '-')}")
        lines.append(f"- Overview: {coach.get('overview', '-')}")
        lines.append(f"- First user action: {coach.get('first_action', '-')}")
        lines.append(f"- Site profile mix: {coach.get('site_mix', '-')}")
        for prompt in coach.get('ux_prompts', [])[:3]:
            lines.append(f"- UX prompt: {prompt}")

        lines.extend(['', 'AI Decision Matrix'])
        for row in plan.get('decision_matrix', []):
            lines.append(f"- {row.get('lens', 'Decision')}: {row.get('status', '-')} — {row.get('why', '')}")
            lines.append(f"  Next: {row.get('next_step', '')}")
        lines.extend(['', 'Posture Heatmap'])
        for row in plan.get('posture_heatmap', []):
            lines.append(f"- {row.get('area', '-')}: {row.get('heat', '-')} ({row.get('count', 0)}) — {row.get('guidance', '')}")
        lines.extend(['', 'Quality Gates'])
        for row in plan.get('quality_gates', []):
            lines.append(f"- {row.get('gate', '-')}: {row.get('status', '-')} — {row.get('detail', '')}")
        lines.extend(['', 'Action Plan'])
        labels = {'today': 'Today', 'this_week': 'This Week', 'long_term': 'Long-Term'}
        for key in ('today', 'this_week', 'long_term'):
            lines.append(labels[key])
            lines.extend(f"- {item}" for item in plan['action_plan'].get(key, []))
            lines.append('')
        lines.extend(['What Changed'])
        lines.extend(f"- {item}" for item in plan.get('change_summary', []))
        impact = plan.get('fix_impact', {})
        lines.extend([
            '',
            'Fix Impact Simulation',
            f"- Current score: {impact.get('current_score', 'n/a')}/100",
            f"- Projected score after top fixes: {impact.get('projected_score', 'n/a')}/100",
            f"- Estimated gain: {impact.get('estimated_gain', 'n/a')}",
        ])
        lines.extend(f"- {item}" for item in impact.get('top_fixes', []))
        lines.extend(['', 'AI-Style Explanation', plan['ai_style_explanation']])
        atomic_write_text(dest, '\n'.join(lines), encoding='utf-8')
        self.add_log('AI Summary Exported', f'Exported AI Guardian summary to {safe_display_path(dest)}.')
        return dest
