from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..analyzer import analyze_password, normalize_site
from ..io_utils import atomic_write_text, safe_display_path


def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


class ProductIntelligenceMixin:
    """Product-grade helpers for demo workflows, local AI-style coaching, and proof exports.

    These methods are intentionally deterministic and local. They do not call any
    external LLM/API and never need raw passwords in exported artifacts.
    """

    def privacy_redaction_preview(self, level: str = 'minimal') -> dict[str, Any]:
        level = level if level in {'minimal', 'standard', 'analyst', 'full'} else 'minimal'
        included_by_level = {
            'minimal': ['risk levels', 'score bands', 'masked credential references', 'summary metrics'],
            'standard': ['masked usernames', 'risk levels', 'score bands', 'credential references', 'summary metrics'],
            'analyst': ['masked usernames', 'website/domain context', 'risk evidence', 'recommended actions', 'summary metrics'],
            'full': ['full local report contents available to the current unlocked user'],
        }
        excluded_common = ['raw passwords', 'master password material', 'backup passphrases', 'secret notes', 'full clipboard values']
        return {
            'level': level,
            'included': included_by_level[level],
            'excluded': [] if level == 'full' else excluded_common,
            'recommended_for': {
                'minimal': 'external sharing and early review' ,
                'standard': 'team review where masked account owners are acceptable',
                'analyst': 'internal security review with useful domain context',
                'full': 'local owner-only troubleshooting',
            }[level],
            'warning': 'Full reports may include sensitive identifiers. Use privacy-safe package exports for sharing.' if level == 'full' else 'Privacy-safe export excludes raw secrets by design.',
        }

    def export_audit_head_hash(self, path: str | Path) -> Path:
        """Export the current audit-chain head so it can be compared later outside the DB."""
        dest = Path(path)
        self.add_log('Audit Head Exported', f'Exported external audit head hash to {safe_display_path(dest)}.', 'success')
        proof = self.verify_audit_chain()
        checkpoint_raw = self.get_setting('audit_last_retention_checkpoint', '')
        payload = {
            'artifact': 'CyberVault X Audit Head Hash',
            'format_version': 'CyberVaultAuditHead/v1',
            'exported_at': _now_iso(),
            'valid_at_export': bool(proof.get('valid')),
            'events_checked': int(proof.get('events_checked', 0) or 0),
            'head_hash': str(proof.get('head_hash', '')),
            'last_retention_checkpoint': json.loads(checkpoint_raw) if checkpoint_raw else None,
            'note': 'Store this file outside the vault. It detects later audit-chain rewrite/rebase attempts when compared against the live DB.',
        }
        atomic_write_text(dest, json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True), encoding='utf-8')
        return dest

    def compare_audit_head_hash(self, path: str | Path) -> dict[str, Any]:
        payload = json.loads(Path(path).read_text(encoding='utf-8'))
        expected = str(payload.get('head_hash', ''))
        current = self.verify_audit_chain()
        actual = str(current.get('head_hash', ''))
        result = {
            'valid': bool(current.get('valid')) and bool(expected) and expected == actual,
            'expected_head_hash': expected,
            'actual_head_hash': actual,
            'events_checked_now': int(current.get('events_checked', 0) or 0),
            'exported_at': payload.get('exported_at', ''),
        }
        self.add_log(
            'Audit Head Compared',
            f"Compared external audit head {safe_display_path(path)}: {'match' if result['valid'] else 'mismatch'}.",
            'success' if result['valid'] else 'warning',
        )
        return result

    def password_history_summary(self, credential_id: int, *, limit: int = 5) -> dict[str, Any]:
        item = self.get_credential(credential_id)
        if not item:
            raise ValueError('Credential not found.')
        history = self.get_password_history(credential_id, include_all=True)[: max(1, int(limit))]
        rows: list[dict[str, Any]] = []
        for entry in history:
            password = str(entry.get('password', ''))
            analysis = analyze_password(password, f'{item.title} {item.username} {item.website}')
            rows.append({
                'changed_at': str(entry.get('changed_at', '')),
                'fingerprint_sha256_12': hashlib.sha256(password.encode('utf-8')).hexdigest()[:12],
                'strength_label': analysis.label,
                'score': analysis.score,
                'stored_plaintext': False,
                'note': 'History passwords remain encrypted at rest; this summary only exposes a short fingerprint and score.',
            })
        return {
            'credential_id': credential_id,
            'credential_ref': f'Credential #{credential_id}',
            'history_count': len(rows),
            'history': rows,
        }

    def remediation_progress(self) -> dict[str, Any]:
        log = self.get_ai_remediation_log() if hasattr(self, 'get_ai_remediation_log') else []
        action_counts: dict[str, int] = {}
        for item in log:
            action = str(item.get('action', 'unknown'))
            action_counts[action] = action_counts.get(action, 0) + 1
        return {
            'completed_actions': len(log),
            'action_counts': dict(sorted(action_counts.items())),
            'latest': log[0] if log else None,
        }

    def record_remediation_action(
        self,
        credential_id: int | None = None,
        *,
        action: str = 'mark_fixed',
        note: str = '',
        new_password: str | None = None,
    ) -> dict[str, Any]:
        """Record or apply a safe remediation action.

        Supported actions:
        - mark_fixed: progress tracker only
        - set_mfa_enabled: adds an `mfa` tag when missing
        - set_business_critical: adds a `business-critical` tag when missing
        - ignore_risk: adds a `risk-accepted` tag and stores a note marker
        - rotate_password: updates the credential when `new_password` is provided
        """
        allowed = {'mark_fixed', 'set_mfa_enabled', 'set_business_critical', 'ignore_risk', 'rotate_password'}
        if action not in allowed:
            raise ValueError(f'Unsupported remediation action: {action}')
        credential_ref = 'Selected priority'
        applied_change = 'progress-only'
        if credential_id is not None:
            item = self.get_credential(int(credential_id))
            if not item:
                raise ValueError('Credential not found.')
            credential_ref = f'Credential #{item.id}'
            tags = [part.strip() for part in item.tags.split(',') if part.strip()]
            notes = item.notes
            if action == 'set_mfa_enabled' and 'mfa' not in {t.lower() for t in tags}:
                tags.append('mfa')
                applied_change = 'tag:mfa'
            elif action == 'set_business_critical' and 'business-critical' not in {t.lower() for t in tags}:
                tags.append('business-critical')
                applied_change = 'tag:business-critical'
            elif action == 'ignore_risk':
                if 'risk-accepted' not in {t.lower() for t in tags}:
                    tags.append('risk-accepted')
                marker = f'Risk accepted at {_now_iso()}.'
                notes = (notes + '\n' + marker).strip() if notes else marker
                applied_change = 'risk-accepted'
            elif action == 'rotate_password':
                if not new_password:
                    raise ValueError('new_password is required for rotate_password.')
                item = item.__class__(**{**item.__dict__, 'password': new_password}) if hasattr(item, '__dict__') else item
                # Dataclass uses slots, so call update directly with original fields.
                original = self.get_credential(int(credential_id))
                if original is None:
                    raise ValueError('Credential not found.')
                self.update_credential(
                    original.id,
                    title=original.title,
                    username=original.username,
                    password=new_password,
                    category=original.category,
                    tags=original.tags,
                    notes=original.notes,
                    website=original.website,
                    is_favorite=original.is_favorite,
                )
                applied_change = 'password-rotated'
            if action in {'set_mfa_enabled', 'set_business_critical', 'ignore_risk'}:
                self.update_credential(
                    item.id,
                    title=item.title,
                    username=item.username,
                    password=item.password,
                    category=item.category,
                    tags=', '.join(tags),
                    notes=notes,
                    website=item.website,
                    is_favorite=item.is_favorite,
                )
        entry = {
            'completed_at': _now_iso(),
            'credential_ref': credential_ref,
            'action': action,
            'note': str(note or ''),
            'applied_change': applied_change,
        }
        raw = self.get_setting('ai_remediation_log_json', '[]')
        try:
            log = json.loads(raw)
        except json.JSONDecodeError:
            log = []
        if not isinstance(log, list):
            log = []
        log.insert(0, entry)
        self.set_setting('ai_remediation_log_json', json.dumps(log[:100], ensure_ascii=False, sort_keys=True))
        self.add_log('Remediation Workflow Updated', f"Recorded remediation action {action} for {credential_ref}.", 'success')
        self._invalidate_snapshot()
        return {'latest': entry, 'progress': self.remediation_progress()}

    def local_ai_security_coach(self, credential_id: int | None = None) -> dict[str, Any]:
        findings = self.security_findings()
        selected = None
        if credential_id is not None:
            selected = next((f for f in findings if int(f.get('id', -1)) == int(credential_id)), None)
        if selected is None and findings:
            selected = sorted(findings, key=lambda f: int(f.get('score', 100)))[0]
        metrics = self.dashboard()
        if not selected:
            return {
                'mode': 'local-rule-based',
                'summary': 'No urgent credential risks were detected. Keep backups fresh and review MFA metadata monthly.',
                'why_risky': 'No high-risk credential was selected.',
                'fix_first': 'Export and verify a report package, then keep the audit head hash externally.',
                'attacker_view': 'The current vault posture does not expose a clear weak-link story from local analysis.',
                'business_impact': 'Current risk appears controlled based on local metadata.',
            }
        issues = selected.get('issues', []) or []
        title = selected.get('title', f"Credential #{selected.get('id', '?')}")
        risk = selected.get('risk_level', 'Unknown')
        why = '; '.join(issues[:3]) if issues else f'{title} has elevated risk scoring.'
        return {
            'mode': 'local-rule-based',
            'credential_ref': f"Credential #{selected.get('id', '?')}",
            'risk_level': risk,
            'summary': f'{title} is currently the strongest fix candidate because it is classified as {risk}.',
            'why_risky': why,
            'fix_first': 'Rotate the password, remove reuse, add MFA metadata, and fill website/tags so future reports can prove improvement.',
            'what_changed_after_fix': 'The dashboard score should improve when weak/reused/old/missing-metadata signals disappear.',
            'attacker_view': 'An attacker would prioritize this account for password spraying, credential stuffing, or privilege escalation if it is reused or missing MFA.',
            'business_impact': f"Current health score is {metrics.get('health_score', 'n/a')}/100; fixing top risky accounts reduces the chance of account takeover chains.",
        }

    def attack_path_simulation(self, credential_id: int | None = None) -> dict[str, Any]:
        findings = self.security_findings()
        if credential_id is not None:
            findings = [f for f in findings if int(f.get('id', -1)) == int(credential_id)]
        finding = sorted(findings, key=lambda f: int(f.get('score', 100)))[0] if findings else None
        if not finding:
            return {'credential_ref': '', 'risk_level': 'Low', 'chain': ['No obvious attack path detected from local rules.'], 'recommended_breakpoints': ['Keep MFA metadata fresh', 'Verify backups monthly']}
        issues = [str(x).lower() for x in finding.get('issues', [])]
        chain = [f"Target selected: Credential #{finding.get('id', '?')} ({finding.get('risk_level', 'Unknown')})"]
        if any('weak' in x or 'short' in x or 'entropy' in x for x in issues):
            chain.append('Weak/guessable password increases offline cracking or guessing risk')
        if any('reused' in x or 'duplicate' in x for x in issues):
            chain.append('Password reuse enables credential stuffing against other services')
        if any('old' in x or 'stale' in x for x in issues):
            chain.append('Stale credential may survive role changes or old exposure windows')
        if any('metadata' in x or 'website' in x or 'tags' in x for x in issues):
            chain.append('Missing metadata makes ownership, priority, and remediation harder to prove')
        chain.append('Potential result: account takeover, lateral movement, or loss of audit confidence')
        return {
            'credential_ref': f"Credential #{finding.get('id', '?')}",
            'risk_level': finding.get('risk_level', 'Unknown'),
            'chain': chain,
            'recommended_breakpoints': ['Rotate unique password', 'Mark MFA enabled', 'Add business-critical tag only where true', 'Export a fresh report package after remediation'],
        }

    def executive_score_timeline(self) -> list[dict[str, Any]]:
        metrics = self.dashboard()
        base = int(metrics.get('health_score', 0) or 0)
        stages = [
            ('Current posture', base, 'Current weighted vault health score'),
            ('After MFA metadata review', min(100, base + 4), 'Mark accounts with verified MFA and fill missing ownership tags'),
            ('After rotating weak/reused passwords', min(100, base + 14), 'Break credential stuffing and password reuse chains'),
            ('After backup/report verification', min(100, base + 19), 'Prove restore readiness and local manifest integrity reporting'),
            ('After monthly hygiene cycle', min(100, base + 24), 'Repeat review, export audit head, and keep stale credentials low'),
        ]
        return [{'stage': name, 'score': score, 'note': note} for name, score, note in stages]

    def security_proof_center_v3(self) -> dict[str, Any]:
        proof = self.security_proof_center()
        checks = proof.get('checks', [])
        def take(names: set[str]) -> list[dict[str, Any]]:
            return [dict(item) for item in checks if str(item.get('name')) in names]
        sections = [
            {'name': 'Encryption Proof', 'checks': take({'Encrypted credential schema', 'Strict credential AAD migration', 'KDF hardening policy', 'Vault initialized'})},
            {'name': 'Backup Proof', 'checks': take({'Backup format pinned', 'Legacy backup fallback disabled'})},
            {'name': 'Audit Integrity', 'checks': take({'Tamper-evident audit columns', 'Audit hash chain valid', 'Audit retention checkpoint ready'})},
            {'name': 'Report Integrity', 'checks': take({'Report package verifier enabled', 'Report package strict file allowlist', 'Report package signing enabled'})},
            {'name': 'Privacy Proof', 'checks': take({'Privacy-safe logs enabled'})},
            {'name': 'Runtime Safety', 'checks': take({'Unlocked session'})},
        ]
        for section in sections:
            items = section['checks']
            passed = sum(1 for item in items if item.get('status'))
            section['status'] = 'Passed' if items and passed == len(items) else 'Warning' if items else 'Not checked'
            section['passed'] = passed
            section['total'] = len(items)
        return {**proof, 'format_version': 'SecurityProofCenter/v3', 'sections': sections}


    def export_emergency_kit(self, path: str | Path) -> Path:
        """Export a safe recovery guide without including secrets or master passwords."""
        dest = Path(path)
        payload = [
            'CyberVault X Emergency Kit',
            f'Generated: {_now_iso()}',
            f'Vault database path: {safe_display_path(self.db.db_path)}',
            '',
            'What this file is',
            '- A safe recovery checklist for the vault owner.',
            '- It intentionally does not include the master password, backup passphrase, raw passwords, or secret notes.',
            '',
            'Routine recovery steps',
            '1. Open CyberVault X on the trusted Windows machine.',
            '2. Unlock with the master password.',
            '3. Use Backup Restore Preview before importing any encrypted backup.',
            '4. Prefer Merge first; use Replace only after reviewing the preview and ensuring a safety snapshot exists.',
            '5. Verify report packages after export and store the audit head hash externally.',
            '',
            'If the master password is forgotten',
            '- CyberVault X cannot decrypt the vault without the correct master password.',
            '- Restore from an encrypted backup only if you know its backup passphrase.',
            '- This design protects stored credentials from local database theft.',
            '',
            'Monthly owner checklist',
            '- Export an encrypted backup.',
            '- Export and verify a report package.',
            '- Export the audit head hash and store it outside the vault folder.',
            '- Review AI-style Local Security Coach priority items and mark verified fixes.',
            '- Remove or rotate stale/reused/weak credentials.',
            '',
            'Limitations',
            '- Python desktop apps cannot guarantee complete memory zeroization.',
            '- The local breach dataset is an offline subset, not a full Have I Been Pwned mirror.',
            '- Tamper-evident audit logs are strongest when the head hash is stored externally.',
        ]
        atomic_write_text(dest, '\n'.join(payload), encoding='utf-8')
        self.add_log('Emergency Kit Exported', f'Exported safe emergency kit to {safe_display_path(dest)}.', 'success')
        return dest

    def csv_import_wizard_plan(self, rows: list[dict[str, Any]], mapping: dict[str, str]) -> dict[str, Any]:
        preview = self.preview_csv_rows(rows, mapping)
        columns = sorted({key for row in rows for key in row.keys()}) if rows else []
        return {
            'wizard_steps': ['Select CSV', 'Detect columns', 'Map fields', 'Preview rows', 'Detect duplicates', 'Import transactionally'],
            'detected_columns': columns,
            'mapping': dict(mapping),
            'preview': preview,
            'safe_to_import': preview.get('valid', 0) > 0 and preview.get('invalid', 0) == 0,
            'recommendation': 'Import safely' if preview.get('valid', 0) and not preview.get('invalid', 0) else 'Review mapping/issues before importing',
        }
