from __future__ import annotations

import html
import json
import hashlib
import secrets
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..io_utils import atomic_write_text, safe_display_path
from ..security_policy import mask_identifier, privacy_safe_title, universal_redact
from .signing import (
    PUBLIC_SIGNATURE_ALGORITHM,
    REPORT_SIGNATURE_ALGORITHM,
    generate_public_signing_private_key_b64,
    public_key_b64_from_private,
    public_key_fingerprint,
    sign_manifest,
    sign_manifest_public,
    signing_key_fingerprint,
)

PRIVACY_LEVELS = {'minimal', 'standard', 'analyst'}


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


class ReportServiceMixin:

    FULL_REPORT_WARNING_VERSION = 'full-report-warning-v2'

    def _sensitive_export_values(self) -> list[str]:
        values = [str(self.db.db_path), str(self.db.db_path.parent), self.owner_name, self.vault_name]
        try:
            for credential in self.list_credentials(include_deleted=True):
                values.extend([
                    credential.password, credential.notes, credential.username, credential.website, credential.title,
                    credential.category, credential.tags,
                ])
        except Exception:
            pass
        return [str(value) for value in values if str(value or '').strip()]

    def issue_full_export_reauth_token(self, master_password: str, *, ttl_seconds: int = 300) -> str:
        """Verify master password and issue a short-lived in-memory full-export token.

        The token is intentionally not persisted. It proves the GUI or caller
        completed the warning/re-auth flow before requesting a private full
        report from the service layer.
        """
        if not master_password or not self.verify_master_password_only(master_password):
            self.add_log('Full Report Export Blocked', 'Master password re-authentication failed before full report export.', 'warning')
            raise PermissionError('Full report export requires successful master password re-authentication.')
        token = secrets.token_urlsafe(32)
        expires = datetime.now(timezone.utc).timestamp() + max(30, int(ttl_seconds))
        if not hasattr(self, '_full_export_tokens'):
            self._full_export_tokens = {}
        self._full_export_tokens[token] = expires
        self.add_log('Full Report Re-authenticated', 'Full report export re-authentication token issued.', 'success')
        return token

    def _consume_full_export_token(self, token: str | None) -> bool:
        if not token or not hasattr(self, '_full_export_tokens'):
            return False
        expires = self._full_export_tokens.pop(str(token), None)
        if expires is None:
            return False
        return datetime.now(timezone.utc).timestamp() <= float(expires)

    def _audit_event_type(self, action: str) -> str:
        import re
        normalized = re.sub(r'[^a-z0-9]+', '_', str(action or '').strip().lower()).strip('_')
        return normalized or 'audit_event'

    def _safe_audit_event(self, row: dict[str, Any], *, privacy_level: str = 'standard') -> dict[str, str]:
        action = universal_redact(str(row.get('action', 'Audit Event')), level=privacy_level, extra_values=self._sensitive_export_values())
        details = universal_redact(str(row.get('details', '')), level=privacy_level, extra_values=self._sensitive_export_values())
        event_type = self._audit_event_type(action)
        safe_message = details or 'Audit event recorded. Sensitive values are not exported.'
        credential_ref = ''
        import re
        match = re.search(r'credential\s*#\s*(\d+)', safe_message, flags=re.IGNORECASE)
        if match:
            credential_ref = f"Credential #{match.group(1)}"
        return {
            'timestamp': str(row.get('timestamp', '')),
            'event_type': event_type,
            'action': action,
            'severity': str(row.get('severity', 'info')),
            'credential_ref': credential_ref,
            'safe_message': safe_message,
            'redaction_status': 'safe',
        }

    def _get_report_signing_secret(self, *, create: bool = True) -> str:
        """Return the vault-local HMAC report-package signing secret."""
        secret = self._get_sensitive_meta('report_signing_secret', '') if hasattr(self, '_get_sensitive_meta') else ''
        if not secret and create:
            secret = secrets.token_urlsafe(32)
            self._encrypt_sensitive_meta(self.require_key(), 'report_signing_secret', secret)
            self.set_setting('report_signing_key_fingerprint', signing_key_fingerprint(secret))
            self.add_log('Report Signing Key Created', 'Created the local report-package HMAC signing key.', 'success')
        if secret:
            self.set_setting('report_signing_key_fingerprint', signing_key_fingerprint(secret))
        return secret

    def _get_public_report_signing_private_key(self, *, create: bool = True) -> str:
        """Return the encrypted Ed25519 private key used for public package verification.

        The exported package contains only the public key and public signature,
        which lets a reviewer verify package integrity without knowing the
        vault-local HMAC secret.  The private key stays encrypted inside the
        vault metadata.
        """
        private_key = self._get_sensitive_meta('report_ed25519_private_key', '') if hasattr(self, '_get_sensitive_meta') else ''
        if not private_key and create:
            private_key = generate_public_signing_private_key_b64()
            self._encrypt_sensitive_meta(self.require_key(), 'report_ed25519_private_key', private_key)
            self.add_log('Public Report Signing Key Created', 'Created the encrypted Ed25519 report-package signing key.', 'success')
        if private_key:
            public_key = public_key_b64_from_private(private_key)
            self.set_setting('report_ed25519_public_key_fingerprint', public_key_fingerprint(public_key))
        return private_key

    def _privacy_safe_findings(self, findings: list[dict[str, Any]], *, level: str = 'minimal') -> list[dict[str, Any]]:
        level = level if level in PRIVACY_LEVELS else 'minimal'
        redacted: list[dict[str, Any]] = []
        for item in findings:
            clone = dict(item)
            credential_id = clone.get('id', '?')
            title_ref = privacy_safe_title(credential_id)
            raw_username = str(clone.get('username', ''))
            intel = dict(clone.get('intelligence', {}))

            clone['title'] = title_ref
            if level == 'minimal':
                clone['username'] = ''
                clone['website'] = ''
                intel['username'] = ''
                intel['website'] = ''
            elif level == 'standard':
                clone['username'] = mask_identifier(raw_username)
                clone['website'] = ''
                intel['username'] = clone['username']
                intel['website'] = ''
            else:  # analyst
                clone['username'] = mask_identifier(raw_username)
                intel['username'] = clone['username']
                intel['website'] = str(intel.get('website', ''))

            intel['title'] = title_ref
            clone['intelligence'] = intel
            redacted.append(clone)
        return redacted

    def _report_payload(self, *, privacy_safe: bool = False, privacy_level: str = 'minimal') -> dict[str, Any]:
        privacy_level = privacy_level if privacy_level in PRIVACY_LEVELS else 'minimal'
        metrics = self.dashboard()
        findings = self.security_findings()
        if privacy_safe:
            findings = self._privacy_safe_findings(findings, level=privacy_level)
        actionable_findings = [row for row in findings if row.get('issues') or row.get('risk_level') != 'Low']
        healthy_findings = [row for row in findings if row not in actionable_findings]
        recs = self.recommendations()
        critical = [f for f in findings if f['risk_level'] == 'Critical']
        high = [f for f in findings if f['risk_level'] == 'High']
        risk_distribution = self.risk_distribution(findings)
        score_breakdown = self.score_breakdown(metrics)
        strengths = self.strength_highlights(metrics)
        payload = {
            'vault_name': 'CyberVault Privacy-Safe Report' if privacy_safe else self.vault_name,
            'owner_name': 'Redacted Owner' if privacy_safe else self.owner_name,
            'generated_at': utc_now_iso(),
            'last_backup': self.get_setting('last_backup', ''),
            'encryption_status': 'AES-GCM Protected',
            'metrics': metrics,
            'recommendations': recs,
            'findings': actionable_findings,
            'healthy_findings': healthy_findings,
            'top_priority': (critical + high)[:5],
            'risk_distribution': risk_distribution,
            'score_breakdown': score_breakdown,
            'strengths': strengths,
            'ai_plan': self.ai_security_plan(persist_snapshot=False),
            'privacy_safe': privacy_safe,
            'privacy_level': privacy_level if privacy_safe else 'disabled',
        }
        hash_basis = json.dumps(payload, ensure_ascii=False, sort_keys=True, default=str)
        payload['payload_hash'] = hashlib.sha256(hash_basis.encode('utf-8')).hexdigest()
        # Backward-compatible alias for older integrations; UI copy labels it as a payload hash.
        payload['report_hash'] = payload['payload_hash']
        return payload

    def export_report(
        self,
        path: str | Path,
        *,
        privacy_safe: bool = False,
        privacy_level: str = 'minimal',
        full_export_ack: bool = False,
        reauth_token: str | None = None,
        warning_version: str | None = None,
    ) -> Path:
        dest = Path(path)
        if not privacy_safe:
            if not full_export_ack:
                self.add_log('Full Report Export Blocked', 'Full report export rejected: missing explicit acknowledgment.', 'warning')
                raise PermissionError('Full report export requires explicit acknowledgment of the identifier warning.')
            if warning_version != self.FULL_REPORT_WARNING_VERSION:
                self.add_log('Full Report Export Blocked', 'Full report export rejected: warning version was not recorded.', 'warning')
                raise PermissionError('Full report export requires the current warning version to be recorded.')
            if not self._consume_full_export_token(reauth_token):
                self.add_log('Full Report Export Blocked', 'Full report export rejected: missing or expired re-authentication token.', 'warning')
                raise PermissionError('Full report export requires a valid recent re-authentication token.')
            self.add_log(
                'FULL_REPORT_EXPORT_APPROVED',
                f'Private full report export approved after warning {warning_version}. Destination: {safe_display_path(dest)}.',
                'warning',
            )
        if privacy_safe and hasattr(self, 'check_privacy_safe_export'):
            privacy_check = self.check_privacy_safe_export(privacy_level=privacy_level)
            if not privacy_check.get('ok'):
                raise ValueError('Privacy-safe export check failed: ' + '; '.join(privacy_check.get('issues', [])[:3]))
        payload = self._report_payload(privacy_safe=privacy_safe, privacy_level=privacy_level)
        suffix = dest.suffix.lower()
        if suffix == '.html':
            self._export_html_report(dest, payload)
        elif suffix == '.json':
            self._export_json_report(dest, payload)
        else:
            self._export_text_report(dest, payload)
        event_name = 'Privacy-Safe Report Exported' if privacy_safe else 'Report Exported'
        self.add_log(event_name, f'Exported security report to {safe_display_path(dest)}.')
        return dest

    def export_privacy_safe_report(self, path: str | Path, *, level: str = 'minimal') -> Path:
        return self.export_report(path, privacy_safe=True, privacy_level=level)

    def export_report_package(self, directory: str | Path, *, privacy_level: str = 'minimal') -> Path:
        """Export a courtroom/demo-ready package with hashes for every artifact."""
        level = privacy_level if privacy_level in PRIVACY_LEVELS else 'minimal'
        dest = Path(directory)
        dest.mkdir(parents=True, exist_ok=True)
        report_path = dest / 'executive_report.html'
        audit_path = dest / 'audit_log.html'
        ai_path = dest / 'ai_guardian_summary.txt'
        self.export_report(report_path, privacy_safe=True, privacy_level=level)
        self.export_audit_log(audit_path, privacy_level=level)
        self.export_ai_summary(ai_path, privacy_level=level)

        files = []
        for file_path in (report_path, audit_path, ai_path):
            data = file_path.read_bytes()
            files.append({
                'name': file_path.name,
                'size_bytes': len(data),
                'sha256': hashlib.sha256(data).hexdigest(),
            })
        package_payload = {
            'package': 'CyberVault X Report Package',
            'format_version': 'CyberVaultReportPackage/v3-signed',
            'generated_at': utc_now_iso(),
            'privacy_level': level,
            'privacy_model': 'privacy-safe exports only; owner/vault identity and full credential identifiers are redacted',
            'files': files,
        }
        package_payload['package_hash'] = hashlib.sha256(json.dumps(package_payload['files'], sort_keys=True).encode('utf-8')).hexdigest()
        signing_secret = self._get_report_signing_secret(create=True)
        package_payload['signature_algorithm'] = REPORT_SIGNATURE_ALGORITHM
        package_payload['signing_key_fingerprint'] = signing_key_fingerprint(signing_secret)

        public_private_key = self._get_public_report_signing_private_key(create=True)
        public_key = public_key_b64_from_private(public_private_key)
        package_payload['public_signature_algorithm'] = PUBLIC_SIGNATURE_ALGORITHM
        package_payload['signing_public_key_b64'] = public_key
        package_payload['signing_public_key_fingerprint'] = public_key_fingerprint(public_key)
        package_payload['public_manifest_signature'] = sign_manifest_public(package_payload, public_private_key)
        package_payload['manifest_signature'] = sign_manifest(package_payload, signing_secret)
        manifest_path = dest / 'manifest.json'
        atomic_write_text(manifest_path, json.dumps(package_payload, ensure_ascii=False, indent=2, sort_keys=True), encoding='utf-8')
        verification = self.verify_report_package(dest) if hasattr(self, 'verify_report_package') else {'ok': True, 'checks': []}
        atomic_write_text(dest / 'verification_output.txt', json.dumps(verification, ensure_ascii=False, indent=2, sort_keys=True), encoding='utf-8')
        self.set_setting('last_report_package_dir', str(dest))
        self.add_log('Report Package Exported', f'Exported report package to {safe_display_path(dest)}.', 'success')
        return dest

    def export_audit_log(self, path: str | Path, *, privacy_level: str = 'standard') -> Path:
        dest = Path(path)
        rows = self.get_logs(limit=1000)
        safe_rows = [self._safe_audit_event(dict(row), privacy_level=privacy_level) for row in rows]
        if dest.suffix.lower() == '.json':
            payload = {
                'title': 'CyberVault X Audit Activity',
                'generated_at': utc_now_iso(),
                'privacy_level': privacy_level,
                'redaction_model': 'structured safe audit events; raw details are never exported directly',
                'events': safe_rows,
            }
            payload['sha256'] = hashlib.sha256(json.dumps(safe_rows, sort_keys=True).encode('utf-8')).hexdigest()
            atomic_write_text(dest, json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True), encoding='utf-8')
        elif dest.suffix.lower() == '.html':
            table_rows = ''.join(
                f"<tr><td>{html.escape(item['timestamp'])}</td><td>{html.escape(item['event_type'])}</td><td>{html.escape(item['severity'])}</td><td>{html.escape(item['credential_ref'])}</td><td>{html.escape(item['safe_message'])}</td><td>{html.escape(item['redaction_status'])}</td></tr>"
                for item in safe_rows
            ) or '<tr><td colspan="6">No audit events recorded yet.</td></tr>'
            digest = hashlib.sha256(json.dumps(safe_rows, sort_keys=True).encode('utf-8')).hexdigest()
            atomic_write_text(dest, f"""<!doctype html>
<html lang='en'><head><meta charset='utf-8'><title>CyberVault X Audit Activity</title>
<style>body{{font-family:Segoe UI,Arial,sans-serif;background:#07111f;color:#eef4ff;padding:28px}}table{{width:100%;border-collapse:collapse}}th,td{{padding:10px;border-bottom:1px solid #233a5c;text-align:left;vertical-align:top}}th{{color:#9db1d0}}.muted{{color:#9db1d0}}@media print{{body{{background:#fff;color:#111827}}th{{color:#374151}}th,td{{border-bottom:1px solid #cbd5e1}}}}</style></head>
<body><h1>CyberVault X Audit Activity</h1><p class='muted'>Generated {utc_now_iso()} · Privacy level: {html.escape(privacy_level)} · SHA-256 {digest}</p><p class='muted'>Structured export: raw audit details are not exported directly; safe_message contains redacted summaries only.</p><table><thead><tr><th>Timestamp</th><th>Event Type</th><th>Severity</th><th>Credential Ref</th><th>Safe Message</th><th>Redaction</th></tr></thead><tbody>{table_rows}</tbody></table></body></html>""", encoding='utf-8')
        else:
            lines = [
                'CyberVault X Audit Activity',
                f'Generated: {utc_now_iso()}',
                f'Privacy level: {privacy_level}',
                'Redaction model: structured safe audit events; raw details are never exported directly',
                '=' * 58,
            ]
            for item in safe_rows:
                lines.append(
                    f"[{item['timestamp']}] {item['severity'].upper()} {item['event_type']} | {item['credential_ref'] or 'n/a'} | {item['safe_message']} | redaction={item['redaction_status']}"
                )
            digest = hashlib.sha256('\n'.join(lines).encode('utf-8')).hexdigest()
            lines.insert(4, f'SHA-256: {digest}')
            atomic_write_text(dest, '\n'.join(lines), encoding='utf-8')
        self.add_log('Audit Log Exported', f'Exported audit log to {safe_display_path(dest)}.')
        return dest

    def _export_json_report(self, dest: Path, payload: dict[str, Any]) -> None:
        """Write a machine-readable report without plaintext passwords or master secrets."""
        safe_payload = dict(payload)
        safe_payload['export_format'] = 'json'
        safe_payload['limitations'] = [
            'Breach checks use the bundled offline SHA-1 subset only.',
            'Reports summarize password risk without exporting plaintext passwords.',
            'Local Security Coach output is deterministic local guidance, not an external LLM verdict.',
        ]
        atomic_write_text(
            dest,
            json.dumps(safe_payload, ensure_ascii=False, indent=2, sort_keys=True, default=str),
            encoding='utf-8',
        )

    def _export_text_report(self, dest: Path, payload: dict[str, Any]) -> None:
        metrics = payload['metrics']
        lines = [
            f"{payload['vault_name']} — Executive Security Report",
            f"Owner: {payload['owner_name']}",
            f"Generated: {payload['generated_at']}",
            f"Encryption: {payload['encryption_status']}",
            f"Last backup: {payload['last_backup'] or 'Never'}",
            f"Privacy-safe mode: {'Enabled' if payload.get('privacy_safe') else 'Disabled'}",
            f"Privacy level: {payload.get('privacy_level', 'disabled')}",
            f"Payload SHA-256: {payload.get('payload_hash', payload.get('report_hash', ''))}",
            "Hash note: the value above hashes the canonical report payload; the old Report SHA-256 label is retired because package manifests hash final exported files.",
            '=' * 58,
            'Overview',
            *(f"- {k.replace('_', ' ').title()}: {v}" for k, v in metrics.items()),
            '',
            'Local Security Coach Summary',
            payload['ai_plan']['executive_summary'],
            '',
            'Local Security Coach Action Plan',
            *(f"- Today: {item}" for item in payload['ai_plan']['action_plan'].get('today', [])),
            *(f"- This Week: {item}" for item in payload['ai_plan']['action_plan'].get('this_week', [])),
            *(f"- Long-Term: {item}" for item in payload['ai_plan']['action_plan'].get('long_term', [])),
            '',
            'Local Security Coach: What Changed',
            *(f"- {item}" for item in payload['ai_plan'].get('change_summary', [])),
            '',
            'Local Security Coach: Decision Matrix',
            *(f"- {row.get('lens', 'Decision')}: {row.get('status', '-')} — {row.get('why', '')} | Next: {row.get('next_step', '')}" for row in payload['ai_plan'].get('decision_matrix', [])),
            '',
            'Local Security Coach: Posture Heatmap',
            *(f"- {row.get('area', '-')}: {row.get('heat', '-')} ({row.get('count', 0)}) — {row.get('guidance', '')}" for row in payload['ai_plan'].get('posture_heatmap', [])),
            '',
            'Local Security Coach: Quality Gates',
            *(f"- {row.get('gate', '-')}: {row.get('status', '-')} — {row.get('detail', '')}" for row in payload['ai_plan'].get('quality_gates', [])),
            '',
            'Local Security Coach: Fix Impact Simulation',
            f"- Current score: {payload['ai_plan'].get('fix_impact', {}).get('current_score', 'n/a')}/100",
            f"- Projected score: {payload['ai_plan'].get('fix_impact', {}).get('projected_score', 'n/a')}/100",
            f"- Estimated gain: {payload['ai_plan'].get('fix_impact', {}).get('estimated_gain', 'n/a')}",
            '',
            'Recommendations',
            *(f'- {r}' for r in payload['recommendations']),
            '',
            'Top Priority Items',
        ]
        for finding in payload['top_priority']:
            lines.append(f"- {finding['title']} | {finding['risk_level']} | {finding['score']}/100")
        lines.append('')
        lines.append('Findings')
        if payload['findings']:
            for finding in payload['findings']:
                lines.append(f"\n[{finding['title']}] {finding['label']} ({finding['score']}/100) — {finding['risk_level']}")
                lines.extend(f'  - {issue}' for issue in finding.get('issues', []))
                intel = finding['intelligence']
                lines.append(f"  - Why it matters: {' '.join(intel['why_matters'])}")
        else:
            lines.append('No actionable security findings detected.')
        healthy_count = len(payload.get('healthy_findings', []))
        if healthy_count:
            lines.extend(['', 'Healthy Credentials', f'- {healthy_count} credential(s) have no active security findings.'])
        atomic_write_text(dest, '\n'.join(lines), encoding='utf-8')

    def _export_html_report(self, dest: Path, payload: dict[str, Any]) -> None:
        metrics = payload['metrics']
        risk_distribution = payload.get('risk_distribution', {})
        score_breakdown = payload.get('score_breakdown', [])
        findings_html = []
        for finding in payload['findings']:
            issues = ''.join(f'<li>{html.escape(issue)}</li>' for issue in finding.get('issues', []))
            fixes = ''.join(f'<li>{html.escape(item)}</li>' for item in finding['intelligence']['fix_recommendations'])
            why = ''.join(f'<li>{html.escape(item)}</li>' for item in finding['intelligence']['why_matters'])
            findings_html.append(f"""
            <div class='finding'>
              <div class='finding-head'>
                <h3>{html.escape(finding['title'])}</h3>
                <span class='badge risk-{finding['risk_level'].lower()}'>{html.escape(finding['risk_level'])}</span>
                <span class='score'>{finding['score']}/100</span>
              </div>
              <p class='muted'>{html.escape(finding['username'])} · {html.escape(finding.get('category', 'General'))}</p>
              <div class='columns'>
                <div>
                  <h4>Issues</h4>
                  <ul>{issues}</ul>
                </div>
                <div>
                  <h4>Why This Matters</h4>
                  <ul>{why}</ul>
                </div>
                <div>
                  <h4>Fix Recommendations</h4>
                  <ul>{fixes}</ul>
                </div>
              </div>
            </div>
            """)
        if not findings_html:
            findings_html.append("""
            <div class='finding healthy-state'>
              <div class='finding-head'>
                <h3>No actionable security findings</h3>
                <span class='badge risk-low'>Healthy</span>
              </div>
              <p class='muted'>All active credentials are currently in the low-risk bucket. Keep backups fresh and continue monthly hygiene reviews.</p>
            </div>
            """)
        recommendations_html = ''.join(f'<li>{html.escape(item)}</li>' for item in payload['recommendations'])
        top_html = ''.join(
            f"<li><strong>{html.escape(item['title'])}</strong> — {html.escape(item['risk_level'])} ({item['score']}/100)</li>"
            for item in payload['top_priority']
        ) or '<li>No urgent items detected.</li>'
        strengths_html = ''.join(f'<li>{html.escape(item)}</li>' for item in payload.get('strengths', []))
        cards = ''.join(
            f"<div class='metric'><div class='metric-label'>{html.escape(key.replace('_', ' ').title())}</div><div class='metric-value'>{value}</div></div>"
            for key, value in metrics.items()
        )
        risk_cards = ''.join(
            f"<div class='risk-card risk-{name.lower()}'><div class='metric-label'>{name}</div><div class='metric-value'>{count}</div></div>"
            for name, count in risk_distribution.items()
        )
        score_rows = ''.join(
            f"<tr><td>{html.escape(item['label'])}</td><td>{item['count']}</td><td>{item['penalty_each']}</td><td>{item['raw_penalty']}</td><td>{item['impact_per_account']}</td></tr>"
            for item in score_breakdown
        ) or '<tr><td colspan="5">No active penalties. The score is currently supported by healthy posture.</td></tr>'
        overall_class = 'critical' if metrics['health_score'] < 50 else 'high' if metrics['health_score'] < 70 else 'moderate' if metrics['health_score'] < 85 else 'low'
        ai_plan = payload.get('ai_plan', {})
        ai_summary = html.escape(str(ai_plan.get('executive_summary', 'Local Security Coach summary unavailable.')))
        ai_explanation = html.escape(str(ai_plan.get('ai_style_explanation', '')))
        ai_action_plan = ai_plan.get('action_plan', {}) if isinstance(ai_plan.get('action_plan', {}), dict) else {}
        ai_today = ''.join(f'<li>{html.escape(str(item))}</li>' for item in ai_action_plan.get('today', [])) or '<li>No urgent action detected.</li>'
        ai_week = ''.join(f'<li>{html.escape(str(item))}</li>' for item in ai_action_plan.get('this_week', [])) or '<li>Review moderate findings and cleanup tasks.</li>'
        ai_long = ''.join(f'<li>{html.escape(str(item))}</li>' for item in ai_action_plan.get('long_term', [])) or '<li>Keep monthly vault reviews and encrypted backups.</li>'
        ai_priorities = ''.join(
            f"<tr><td>{html.escape(str(item.get('credential_ref', 'Credential')))}</td>"
            f"<td>{html.escape(str(item.get('risk_level', 'Low')))}</td>"
            f"<td>{html.escape(str(item.get('primary_signal', 'Signal')))}<br><span class='muted'>{html.escape(str(item.get('confidence_percent', 0)))}% heuristic confidence</span></td>"
            f"<td>{html.escape(str(item.get('timeline', 'Review')))}</td>"
            f"<td>{html.escape(str(item.get('why', '')))}<br><span class='muted'>{html.escape(str(item.get('exposure_path', '')))}</span></td>"
            f"<td>{html.escape(str(item.get('attack_scenario', '')))}</td>"
            f"<td>{html.escape(str(item.get('business_impact', '')))}</td>"
            f"<td>{html.escape(str(item.get('recommended_action', '')))}<br><span class='muted'>Expected score gain: +{html.escape(str(item.get('expected_score_gain', 0)))}</span></td></tr>"
            for item in ai_plan.get('priority_items', [])[:5]
        ) or '<tr><td colspan="8">No Local Security Coach priority items detected.</td></tr>'
        ai_decisions = ''.join(
            f"<li><strong>{html.escape(str(row.get('lens', 'Decision')))}:</strong> {html.escape(str(row.get('status', '-')))} — {html.escape(str(row.get('why', '')))}<br><span class='muted'>Next: {html.escape(str(row.get('next_step', '')))}</span></li>"
            for row in ai_plan.get('decision_matrix', [])
        ) or '<li>No decision matrix available.</li>'
        ai_heatmap = ''.join(
            f"<li><strong>{html.escape(str(row.get('area', '-')))}:</strong> {html.escape(str(row.get('heat', '-')))} ({html.escape(str(row.get('count', 0)))}) — {html.escape(str(row.get('guidance', '')))}</li>"
            for row in ai_plan.get('posture_heatmap', [])
        ) or '<li>No posture heatmap available.</li>'
        ai_quality = ''.join(
            f"<li><strong>{html.escape(str(row.get('gate', '-')))}:</strong> {html.escape(str(row.get('status', '-')))} — {html.escape(str(row.get('detail', '')))}</li>"
            for row in ai_plan.get('quality_gates', [])
        ) or '<li>Quality gates pending.</li>'
        ai_changes = ''.join(f'<li>{html.escape(str(item))}</li>' for item in ai_plan.get('change_summary', [])) or '<li>No previous snapshot is available yet.</li>'
        impact = ai_plan.get('fix_impact', {}) if isinstance(ai_plan.get('fix_impact', {}), dict) else {}
        impact_fixes = ''.join(f'<li>{html.escape(str(item))}</li>' for item in impact.get('top_fixes', [])) or '<li>No priority fixes are currently required.</li>'
        privacy_notice = '<p class="muted">Privacy-safe mode is enabled: credential titles and owner details are redacted.</p>' if payload.get('privacy_safe') else ''
        html_doc = f"""
<!doctype html>
<html lang='en'>
<head>
<meta charset='utf-8'>
<title>{html.escape(payload['vault_name'])} — Executive Security Report</title>
<style>
:root {{ --bg:#07111f; --panel:#10213a; --card:#152843; --text:#eef4ff; --muted:#9db1d0; --accent:#11c5d9; --ok:#2fd08b; --warn:#ffb84d; --bad:#ff647a; }}
* {{ box-sizing:border-box; }}
body {{ margin:0; font-family:Segoe UI,Arial,sans-serif; background:linear-gradient(180deg,#07111f,#0d1728); color:var(--text); padding:32px; }}
.hero {{ background:linear-gradient(135deg,#132948,#0f1f36); border:1px solid #203758; border-radius:24px; padding:28px; box-shadow:0 20px 40px rgba(0,0,0,.18); }}
.header {{ display:flex; justify-content:space-between; align-items:flex-start; gap:24px; margin-bottom:18px; }}
.hero h1 {{ margin:0 0 10px 0; font-size:34px; }}
.metrics {{ display:grid; grid-template-columns:repeat(4,minmax(0,1fr)); gap:14px; margin:20px 0 0 0; }}
.metric,.panel,.finding,.risk-card {{ background:var(--card); border:1px solid #213a5a; border-radius:18px; padding:16px; }}
.metric-label,.muted,th {{ color:var(--muted); font-size:13px; }}
.metric-value {{ margin-top:10px; font-size:28px; font-weight:700; }}
.grid {{ display:grid; grid-template-columns:1.15fr .85fr; gap:16px; margin:18px 0; }}
.stack {{ display:grid; gap:16px; }}
.risk-grid {{ display:grid; grid-template-columns:repeat(4,minmax(0,1fr)); gap:14px; margin-top:14px; }}
.badge {{ padding:8px 12px; border-radius:999px; font-size:13px; font-weight:700; }}
.risk-low {{ background:rgba(47,208,139,.15); color:var(--ok); }}
.risk-moderate {{ background:rgba(17,197,217,.15); color:var(--accent); }}
.risk-high {{ background:rgba(255,184,77,.15); color:var(--warn); }}
.risk-critical {{ background:rgba(255,100,122,.15); color:var(--bad); }}
.finding {{ margin-bottom:14px; }}
.finding-head {{ display:flex; align-items:center; gap:10px; margin-bottom:8px; }}
.finding-head h3 {{ margin:0; flex:1; }}
.score {{ color:var(--accent); font-weight:700; }}
.columns {{ display:grid; grid-template-columns:1fr 1fr 1fr; gap:18px; margin-top:12px; }}
ul {{ margin:10px 0 0 18px; padding:0; }}
section h2, h3, h4, p {{ margin:0; }}
table {{ width:100%; border-collapse:collapse; margin-top:12px; }}
th,td {{ text-align:left; padding:10px 12px; border-bottom:1px solid #233a5c; font-size:14px; }}
.small {{ font-size:12px; }}
.report-footer {{ margin-top:24px; padding-top:14px; border-top:1px solid #233a5c; color:var(--muted); font-size:12px; }}
@media print {{
  :root {{ --bg:#ffffff; --panel:#ffffff; --card:#ffffff; --text:#111827; --muted:#4b5563; --accent:#1d4ed8; --ok:#047857; --warn:#b45309; --bad:#b91c1c; }}
  body {{ background:#fff; color:#111827; padding:16mm; }}
  .hero,.panel,.finding,.metric,.risk-card {{ box-shadow:none; border:1px solid #cbd5e1; break-inside:avoid; }}
  .grid,.columns,.metrics,.risk-grid {{ break-inside:avoid; }}
  table {{ page-break-inside:auto; }}
  tr {{ page-break-inside:avoid; page-break-after:auto; }}
}}
</style>
</head>
<body>
  <div class='hero'>
    <div class='header'>
      <div>
        <h1>{html.escape(payload['vault_name'])}</h1>
        <p class='muted'>Executive Security Report · Generated {html.escape(payload['generated_at'])}</p>
        <p class='muted'>Owner: {html.escape(payload['owner_name'])} · Encryption: {html.escape(payload['encryption_status'])} · Last backup: {html.escape(payload['last_backup'] or 'Never')}</p>
        {privacy_notice}
      </div>
      <div class='badge risk-{overall_class}'>Overall score {metrics['health_score']}/100</div>
    </div>
    <div class='metrics'>{cards}</div>
  </div>

  <section class='panel' style='margin-top:18px;'>
    <h2>CyberVault Local Security Coach</h2>
    <p class='muted'>{ai_summary}</p>
    <div class='columns'>
      <div>
        <h4>Today</h4>
        <ul>{ai_today}</ul>
      </div>
      <div>
        <h4>This Week</h4>
        <ul>{ai_week}</ul>
      </div>
      <div>
        <h4>Long-Term</h4>
        <ul>{ai_long}</ul>
      </div>
    </div>
    <p class='muted small' style='margin-top:14px;'>{ai_explanation}</p>
    <table>
      <thead><tr><th>Credential Ref</th><th>Risk</th><th>Signal / Confidence</th><th>Timeline</th><th>Why / Exposure</th><th>Attack Scenario</th><th>Business Impact</th><th>Recommended Action</th></tr></thead>
      <tbody>{ai_priorities}</tbody>
    </table>
    <div class='columns' style='margin-top:16px;'>
      <div>
        <h4>Decision Matrix</h4>
        <ul>{ai_decisions}</ul>
      </div>
      <div>
        <h4>Posture Heatmap</h4>
        <ul>{ai_heatmap}</ul>
      </div>
      <div>
        <h4>Quality Gates</h4>
        <ul>{ai_quality}</ul>
      </div>
    </div>
    <div class='columns' style='margin-top:16px;'>
      <div>
        <h4>What Changed</h4>
        <ul>{ai_changes}</ul>
      </div>
      <div>
        <h4>Fix Impact Simulation</h4>
        <p class='muted'>Current: {impact.get('current_score', 'n/a')}/100 · Projected: {impact.get('projected_score', 'n/a')}/100 · Gain: {impact.get('estimated_gain', 'n/a')}</p>
        <ul>{impact_fixes}</ul>
      </div>
      <div>
        <h4>Privacy Model</h4>
        <p class='muted'>Local Security Coach uses redacted local telemetry only. Raw passwords, notes, master keys, and cloud AI requests are excluded. Confidence is heuristic policy confidence, not calibrated ML accuracy.</p>
      </div>
    </div>
  </section>

  <div class='grid'>
    <section class='panel'>
      <h2>Risk Distribution</h2>
      <p class='muted'>This shows how many credentials currently land in each risk bucket.</p>
      <div class='risk-grid'>{risk_cards}</div>
    </section>
    <div class='stack'>
      <section class='panel'>
        <h2>Recommendations</h2>
        <ul>{recommendations_html}</ul>
      </section>
      <section class='panel'>
        <h2>Healthy Signals</h2>
        <ul>{strengths_html}</ul>
      </section>
    </div>
  </div>

  <div class='grid'>
    <section class='panel'>
      <h2>Score Drivers</h2>
      <p class='muted'>How the weighted health score is being reduced across the current vault state.</p>
      <table>
        <thead>
          <tr><th>Driver</th><th>Count</th><th>Penalty Each</th><th>Total Penalty</th><th>Impact / Account</th></tr>
        </thead>
        <tbody>{score_rows}</tbody>
      </table>
    </section>
    <section class='panel'>
      <h2>Top Priority Items</h2>
      <ul>{top_html}</ul>
      <p class='muted small' style='margin-top:14px;'>Use this section during the walkthrough to explain what should be fixed first and why the score improves after each remediation step.</p>
    </section>
  </div>

  <section>
    <h2>Detailed Findings</h2>
    <p class='muted small'>{len(payload.get('healthy_findings', []))} healthy credential(s) were excluded from detailed findings to keep the report focused on real issues.</p>
    {''.join(findings_html)}
  </section>
  <div class='report-footer'>Payload SHA-256: {html.escape(payload.get('payload_hash', payload.get('report_hash', '')))} · Report SHA-256 label retired because this digest is payload-only · Final file hashes are recorded in report-package manifests · Privacy level: {html.escape(str(payload.get('privacy_level', 'disabled')))} · Generated locally by CyberVault X.</div>
</body>
</html>
        """
        atomic_write_text(dest, html_doc, encoding='utf-8')
