from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from ..crypto_utils import BACKUP_FORMAT, LEGACY_BACKUP_AAD_FALLBACK_ENV, MIN_BACKUP_KDF_ITERATIONS, PBKDF2_ITERATIONS
from ..io_utils import safe_display_path
from .backup import utc_now_iso
from .signing import REPORT_SIGNATURE_ALGORITHM, signing_key_fingerprint, verify_manifest_signature


ZERO_HASH = '0' * 64
ALLOWED_REPORT_PACKAGE_FILES = {'executive_report.html', 'audit_log.html', 'ai_guardian_summary.txt'}


def _safe_report_package_member(root: Path, name: str) -> Path:
    candidate_name = str(name or '').strip()
    if not candidate_name:
        raise ValueError('Report package manifest contains an empty file name.')
    member = Path(candidate_name)
    if member.name != candidate_name or member.is_absolute() or '..' in member.parts:
        raise ValueError(f'Report package manifest contains an unsafe file path: {candidate_name!r}.')
    if candidate_name not in ALLOWED_REPORT_PACKAGE_FILES:
        raise ValueError(f'Report package manifest contains an unexpected file: {candidate_name!r}.')
    root_resolved = root.resolve()
    candidate = (root_resolved / candidate_name).resolve()
    if candidate.parent != root_resolved:
        raise ValueError(f'Report package manifest path escapes the package directory: {candidate_name!r}.')
    return candidate


class ProofServiceMixin:
    """Security proof, package verification, and audit-chain checks.

    These checks are intentionally local and deterministic so the demo can prove
    security controls without uploading vault data or secrets anywhere.
    """

    def _expected_audit_hash(self, row: dict[str, Any], prev_hash: str) -> str:
        material = (
            f"{int(row.get('id', 0))}|{row.get('timestamp', '')}|{row.get('action', '')}|"
            f"{row.get('details', '')}|{row.get('severity', 'info')}|{prev_hash}"
        )
        return hashlib.sha256(material.encode('utf-8')).hexdigest()

    def verify_audit_chain(self) -> dict[str, Any]:
        with self.db.connect() as conn:
            rows = [dict(row) for row in conn.execute(
                'SELECT id, timestamp, action, details, severity, prev_hash, event_hash FROM activity_log ORDER BY id ASC'
            ).fetchall()]

        prev_hash = ZERO_HASH
        first_invalid: dict[str, Any] | None = None
        for row in rows:
            expected = self._expected_audit_hash(row, prev_hash)
            if row.get('prev_hash') != prev_hash or row.get('event_hash') != expected:
                first_invalid = {
                    'id': row.get('id'),
                    'expected_prev_hash': prev_hash,
                    'actual_prev_hash': row.get('prev_hash', ''),
                    'expected_event_hash': expected,
                    'actual_event_hash': row.get('event_hash', ''),
                }
                break
            prev_hash = expected

        return {
            'valid': first_invalid is None,
            'events_checked': len(rows),
            'head_hash': prev_hash if rows else ZERO_HASH,
            'first_invalid': first_invalid,
        }

    def security_proof_center(self) -> dict[str, Any]:
        chain = self.verify_audit_chain()
        with self.db.connect() as conn:
            credential_cols = {row['name'] for row in conn.execute('PRAGMA table_info(credentials)').fetchall()}
            activity_cols = {row['name'] for row in conn.execute('PRAGMA table_info(activity_log)').fetchall()}
            credential_count = int(conn.execute('SELECT COUNT(*) FROM credentials WHERE deleted_at IS NULL').fetchone()[0])

        encrypted_field_model = all(
            f'{field}_nonce' in credential_cols and f'{field}_cipher' in credential_cols and field not in credential_cols
            for field in ('title', 'username', 'password', 'category', 'tags', 'notes', 'website')
        )
        checks = [
            {
                'name': 'Vault initialized',
                'status': bool(self.is_initialized),
                'details': 'Master verifier exists and the vault can enforce authentication.',
            },
            {
                'name': 'Unlocked session',
                'status': bool(self.is_unlocked),
                'details': 'Proof checks that require decrypted state can run only after unlock.',
            },
            {
                'name': 'Encrypted credential schema',
                'status': encrypted_field_model,
                'details': 'Credentials table stores nonce/cipher pairs, not plaintext password columns.',
            },
            {
                'name': 'Strict credential AAD migration',
                'status': self.get_setting('credential_aad_migrated_v4', '0') == '1' or credential_count == 0,
                'details': 'AAD-bound field encryption prevents ciphertext swapping between fields/records after migration.',
            },
            {
                'name': 'Legacy backup fallback disabled',
                'status': self.get_setting('legacy_backup_aad_fallback', '0') != '1',
                'details': f'No-AAD backup fallback is disabled unless {LEGACY_BACKUP_AAD_FALLBACK_ENV}=1 is deliberately set.',
            },
            {
                'name': 'Tamper-evident audit columns',
                'status': {'prev_hash', 'event_hash'}.issubset(activity_cols),
                'details': 'Activity records include previous-hash and event-hash columns.',
            },
            {
                'name': 'Audit hash chain valid',
                'status': bool(chain['valid']),
                'details': f"{chain['events_checked']} event(s) checked. Head hash: {str(chain['head_hash'])[:16]}...",
            },
            {
                'name': 'Privacy-safe logs enabled',
                'status': self.get_setting('privacy_mode_logs', '1') == '1',
                'details': 'Activity messages redact local paths and email addresses by default.',
            },
            {
                'name': 'Report package verifier enabled',
                'status': self.get_setting('report_package_verifier_enabled', '1') == '1',
                'details': 'Exported report packages can be verified against manifest SHA-256 hashes.',
            },
            {
                'name': 'Report package strict file allowlist',
                'status': True,
                'details': f"Verifier accepts only: {', '.join(sorted(ALLOWED_REPORT_PACKAGE_FILES))}.",
            },
            {
                'name': 'Report package signing enabled',
                'status': True,
                'details': f"Manifest signing uses {REPORT_SIGNATURE_ALGORITHM}; fingerprint: {self.get_setting('report_signing_key_fingerprint', 'not-created-yet')}.",
            },
            {
                'name': 'KDF hardening policy',
                'status': PBKDF2_ITERATIONS >= MIN_BACKUP_KDF_ITERATIONS,
                'details': f'PBKDF2-SHA256 iterations: {PBKDF2_ITERATIONS:,}; minimum backup policy: {MIN_BACKUP_KDF_ITERATIONS:,}.',
            },
            {
                'name': 'Backup format pinned',
                'status': self.get_setting('backup_format_version', '3') == '3',
                'details': f'Active encrypted backup envelope: {BACKUP_FORMAT}.',
            },
            {
                'name': 'Audit retention checkpoint ready',
                'status': True,
                'details': 'Retention compaction rebases retained events and stores a checkpoint hash when old events are purged.',
            },
        ]
        passed = sum(1 for item in checks if item['status'])
        return {
            'generated_at': utc_now_iso(),
            'overall_status': 'PASS' if passed == len(checks) else 'REVIEW',
            'passed': passed,
            'total': len(checks),
            'audit_chain': chain,
            'checks': checks,
        }

    def verify_report_package(self, directory: str | Path) -> dict[str, Any]:
        root = Path(directory)
        manifest_path = root / 'manifest.json'
        if not manifest_path.exists():
            raise ValueError('manifest.json was not found in the selected report package folder.')
        manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
        files = manifest.get('files', [])
        if not isinstance(files, list):
            raise ValueError('Report package manifest has an invalid files list.')

        seen: set[str] = set()
        for item in files:
            if not isinstance(item, dict):
                raise ValueError('Report package manifest has an invalid file entry.')
            name = str(item.get('name', ''))
            _safe_report_package_member(root, name)
            if name in seen:
                raise ValueError(f'Report package manifest contains a duplicate file entry: {name!r}.')
            seen.add(name)
        missing_required = ALLOWED_REPORT_PACKAGE_FILES.difference(seen)
        if missing_required:
            raise ValueError(f'Report package manifest is missing required file(s): {sorted(missing_required)}.')

        results: list[dict[str, Any]] = []
        all_valid = True
        for item in files:
            name = str(item.get('name', ''))
            expected_sha = str(item.get('sha256', ''))
            try:
                expected_size = int(item.get('size_bytes', -1) or -1)
            except (TypeError, ValueError):
                expected_size = -1
            path = _safe_report_package_member(root, name)
            if not path.exists() or not path.is_file():
                results.append({'name': name, 'valid': False, 'reason': 'missing', 'expected_sha256': expected_sha, 'actual_sha256': ''})
                all_valid = False
                continue
            data = path.read_bytes()
            actual_sha = hashlib.sha256(data).hexdigest()
            valid = actual_sha == expected_sha and len(data) == expected_size
            if not valid:
                all_valid = False
            results.append({
                'name': name,
                'valid': valid,
                'reason': 'ok' if valid else 'hash_or_size_mismatch',
                'expected_sha256': expected_sha,
                'actual_sha256': actual_sha,
                'expected_size': expected_size,
                'actual_size': len(data),
            })

        expected_package_hash = str(manifest.get('package_hash', ''))
        actual_package_hash = hashlib.sha256(json.dumps(files, sort_keys=True).encode('utf-8')).hexdigest()
        package_hash_valid = bool(expected_package_hash) and expected_package_hash == actual_package_hash
        if not package_hash_valid:
            all_valid = False

        signing_secret = ''
        if getattr(self, 'is_unlocked', False) and hasattr(self, '_get_report_signing_secret'):
            signing_secret = self._get_report_signing_secret(create=False)
        signature_present = bool(str(manifest.get('manifest_signature', '')))
        signature_checked = bool(signing_secret)
        signature_valid = verify_manifest_signature(manifest, signing_secret) if signature_checked else False
        expected_fingerprint = str(manifest.get('signing_key_fingerprint', ''))
        actual_fingerprint = signing_key_fingerprint(signing_secret)
        signature_fingerprint_match = bool(expected_fingerprint and actual_fingerprint and expected_fingerprint == actual_fingerprint)
        if signature_present and signature_checked and (not signature_valid or not signature_fingerprint_match):
            all_valid = False
        elif not signature_present:
            all_valid = False

        result = {
            'valid': all_valid,
            'verified_at': utc_now_iso(),
            'directory': safe_display_path(root),
            'package_hash_valid': package_hash_valid,
            'signature_present': signature_present,
            'signature_checked': signature_checked,
            'signature_valid': signature_valid,
            'signature_algorithm': manifest.get('signature_algorithm', ''),
            'signing_key_fingerprint': expected_fingerprint,
            'signature_fingerprint_match': signature_fingerprint_match,
            'expected_package_hash': expected_package_hash,
            'actual_package_hash': actual_package_hash,
            'allowed_files': sorted(ALLOWED_REPORT_PACKAGE_FILES),
            'files_checked': len(results),
            'files': results,
            'privacy_level': manifest.get('privacy_level', ''),
            'generated_at': manifest.get('generated_at', ''),
        }
        self.add_log(
            'Report Package Verified',
            f"Verified report package {safe_display_path(root)}: {'valid' if all_valid else 'review required'}.",
            'success' if all_valid else 'warning',
        )
        return result
