from __future__ import annotations

from dataclasses import asdict
from typing import Any

from ..analyzer import build_recommendations, compute_dashboard
from .snapshot import VaultSnapshot, build_intelligence_for_entry, build_vault_snapshot


class AnalysisServiceMixin:
    _snapshot_cache: VaultSnapshot | None

    def _invalidate_snapshot(self) -> None:
        self._snapshot_cache = None

    def vault_snapshot(self, *, refresh: bool = False) -> VaultSnapshot:
        if refresh or getattr(self, '_snapshot_cache', None) is None:
            self._snapshot_cache = build_vault_snapshot(self)
        return self._snapshot_cache

    def credential_dicts(self, *, include_deleted: bool = False, deleted_only: bool = False) -> list[dict[str, Any]]:
        if not include_deleted and not deleted_only:
            # Reuse the active decrypted pass that feeds UI/report/AI analysis.
            return [dict(item) for item in (asdict(row) for row in self.list_credentials())]
        return [asdict(item) for item in self.list_credentials(include_deleted=include_deleted, deleted_only=deleted_only)]

    def dashboard(self) -> dict[str, int]:
        return dict(self.vault_snapshot().metrics)

    def command_center(self) -> dict[str, Any]:
        metrics = self.dashboard()
        total_risk = metrics['weak'] + metrics['breached'] + metrics['reused_passwords'] + metrics['old']
        encryption_status = 'AES-GCM Protected' if self.is_initialized else 'Not initialized'
        return {
            'metrics': metrics,
            'encryption_status': encryption_status,
            'last_backup': self.get_setting('last_backup', ''),
            'created_on': self.get_setting('created_on', ''),
            'accounts_at_risk': total_risk,
        }

    def breach_intelligence_for(self, item: Any | int | None) -> dict[str, Any]:
        target = self.get_credential(item) if isinstance(item, int) else item
        if not target:
            return {
                'score': 0,
                'label': 'No selection',
                'risk_level': 'Unknown',
                'severity': 'watch',
                'breached': False,
                'common_password': False,
                'reuse_count': 0,
                'old_password': False,
                'entropy_bits': 0,
                'explanation': 'Select a credential to inspect local breach intelligence.',
                'why_matters': ['No credential selected yet.'],
                'fix_recommendations': ['Choose a credential or import CSV data to begin analysis.'],
                'patterns': [],
                'warnings': [],
                'suggestions': [],
                'title': '',
                'username': '',
                'website': '',
            }
        return build_intelligence_for_entry(target, self.list_credentials())

    def security_findings(self) -> list[dict[str, Any]]:
        # Return defensive shallow copies so UI/report code cannot mutate cache.
        rows: list[dict[str, Any]] = []
        for row in self.vault_snapshot().findings:
            clone = dict(row)
            clone['issues'] = list(row.get('issues', []))
            clone['intelligence'] = dict(row.get('intelligence', {}))
            rows.append(clone)
        return rows

    def simulate_fix_impact(self, options: dict[str, bool] | None = None) -> dict[str, Any]:
        """Estimate score impact for selected remediation buckets without changing vault data."""
        metrics = self.dashboard()
        options = options or {
            'weak': True,
            'reused': True,
            'old': True,
            'metadata': True,
            'trash': True,
            'backup': True,
        }
        current = int(metrics.get('health_score', 0) or 0)
        total = max(1, int(metrics.get('total', 0) or 0))
        gain = 0
        fixes: list[str] = []
        if options.get('weak') and int(metrics.get('weak', 0) or 0):
            delta = min(35, int(metrics.get('weak', 0) or 0) * 12)
            gain += delta
            fixes.append(f"Replace {metrics.get('weak', 0)} weak password(s): +{delta}")
        if options.get('reused') and int(metrics.get('reused_passwords', 0) or 0):
            delta = min(30, int(metrics.get('reused_passwords', 0) or 0) * 10)
            gain += delta
            fixes.append(f"Remove password reuse across {metrics.get('reused_passwords', 0)} item(s): +{delta}")
        if options.get('old') and int(metrics.get('old', 0) or 0):
            delta = min(20, int(metrics.get('old', 0) or 0) * 5)
            gain += delta
            fixes.append(f"Rotate {metrics.get('old', 0)} old password(s): +{delta}")
        if options.get('metadata'):
            missing = int(metrics.get('missing_fields', 0) or 0)
            duplicate_sites = int(metrics.get('duplicate_sites', 0) or 0)
            delta = min(18, missing * 3 + duplicate_sites * 5)
            if delta:
                gain += delta
                fixes.append(f"Clean metadata and duplicate-site records: +{delta}")
        if options.get('trash') and int(metrics.get('trashed', 0) or 0):
            delta = min(6, int(metrics.get('trashed', 0) or 0) * 2)
            gain += delta
            fixes.append(f"Purge or restore trash safely: +{delta}")
        if options.get('backup') and not self.get_setting('last_backup', ''):
            gain += 5
            fixes.append('Export a fresh encrypted backup: +5')
        projected = min(100, current + gain)
        explanation = []
        if fixes:
            explanation = [
                'Selected fixes are scored by deterministic local rules.',
                'Largest gains come from replacing weak, reused, breached, or old credentials first.',
                'The estimate is for prioritization only; it is not an exact scientific prediction.',
            ]
        return {
            'current_score': current if total else None,
            'projected_score': projected if total else None,
            'estimated_gain': projected - current if total else 0,
            'selected_fixes': fixes or ['No measurable score change from selected options.'],
            'recommended_order': fixes[:],
            'why_it_matters': explanation,
            'method': 'Rule-based local estimate for remediation planning.',
        }

    def risk_distribution(self, findings: list[dict[str, Any]] | None = None) -> dict[str, int]:
        if findings is None:
            return dict(self.vault_snapshot().risk_distribution)
        counts = {'Critical': 0, 'High': 0, 'Moderate': 0, 'Low': 0}
        for row in findings:
            risk = row.get('risk_level', 'Low')
            if risk in counts:
                counts[risk] += 1
        return counts

    def score_breakdown(self, metrics: dict[str, int] | None = None) -> list[dict[str, Any]]:
        values = metrics or self.dashboard()
        total = max(1, int(values.get('total', 0) or 0))
        drivers = [
            ('Weak passwords', int(values.get('weak', 0) or 0), 10),
            ('Offline breach hits', int(values.get('breached', 0) or 0), 12),
            ('Password reuse', int(values.get('reused_passwords', 0) or 0), 10),
            ('Old credentials', int(values.get('old', 0) or 0), 6),
            ('Duplicate usernames', int(values.get('duplicate_usernames', 0) or 0), 3),
            ('Duplicate sites', int(values.get('duplicate_sites', 0) or 0), 3),
            ('Missing metadata', int(values.get('missing_fields', 0) or 0), 2),
            ('Trash pressure', int(values.get('trashed', 0) or 0), 1),
        ]
        rows = []
        for label, count, penalty_each in drivers:
            raw_penalty = count * penalty_each
            if not raw_penalty:
                continue
            rows.append({
                'label': label,
                'count': count,
                'penalty_each': penalty_each,
                'raw_penalty': raw_penalty,
                'impact_per_account': round(raw_penalty / total, 1),
            })
        return rows

    def strength_highlights(self, metrics: dict[str, int] | None = None) -> list[str]:
        values = metrics or self.dashboard()
        highlights: list[str] = []
        if values.get('total', 0) == 0:
            return ['Vault is ready for onboarding. Add or import credentials to activate the posture engine.']
        if values.get('breached', 0) == 0:
            highlights.append('No passwords matched the local offline breach dataset.')
        if values.get('reused_passwords', 0) == 0:
            highlights.append('No password reuse was detected across stored credentials.')
        if values.get('old', 0) == 0:
            highlights.append('No credentials are past the 90-day rotation window.')
        if values.get('missing_fields', 0) == 0:
            highlights.append('Metadata is complete across the active vault entries.')
        if not highlights:
            highlights.append('The vault has clear opportunities to improve, but the reporting and analysis pipeline is fully active.')
        return highlights

    def recommendations(self) -> list[str]:
        metrics = compute_dashboard(self.credential_dicts(), len(self.credential_dicts(deleted_only=True)))
        return build_recommendations(metrics)
