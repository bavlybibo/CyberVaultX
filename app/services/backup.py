from __future__ import annotations

import json
import hashlib
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from ..crypto_utils import encrypt_backup_json, encrypt_text, decrypt_text, decrypt_backup_json, validate_backup_passphrase
from ..db import SCHEMA_VERSION
from ..io_utils import atomic_write_text, safe_display_path
from ..analyzer import normalize_site


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


class BackupServiceMixin:
    _MAX_BACKUP_ROWS = 10000
    _MAX_FIELD_LENGTH = 20000

    def _backup_payload(self) -> dict[str, Any]:
        return {
            'schema_version': SCHEMA_VERSION,
            'owner_name': self.owner_name,
            'vault_name': self.vault_name,
            'created_on': self.get_setting('created_on', ''),
            'settings': {
                'auto_lock_minutes': self.get_setting('auto_lock_minutes', '3'),
                'clipboard_clear_seconds': self.get_setting('clipboard_clear_seconds', '15'),
                'theme_accent': self.get_setting('theme_accent', 'Cyan'),
                'privacy_mode_logs': self.get_setting('privacy_mode_logs', '1'),
            },
            'credentials': self.credential_dicts(include_deleted=True),
            'history': {str(item.id): self.get_password_history(item.id, include_all=True) for item in self.list_credentials(include_deleted=True)},
            'exported_at': utc_now_iso(),
        }

    def create_safety_snapshot(self, reason: str, *, fail_silent: bool = True) -> Path | None:
        """Create an encrypted local rollback snapshot before destructive operations.

        The snapshot is encrypted with the active vault key and is meant as a
        local emergency checkpoint, not a replacement for user-controlled
        passphrase backups. It never stores plaintext on disk.
        """
        try:
            key = self.require_key()
            payload = self._backup_payload()
            payload['snapshot_reason'] = reason
            payload['snapshot_kind'] = 'local-safety-checkpoint'
            aad = 'CyberVaultX:safety_snapshot:v1'
            nonce, cipher = encrypt_text(json.dumps(payload, ensure_ascii=False), key, aad=aad)
            safe_reason = ''.join(ch if ch.isalnum() else '_' for ch in reason.lower()).strip('_')[:48] or 'operation'
            dest_dir = self.db.db_path.parent / 'safety_snapshots'
            dest_dir.mkdir(parents=True, exist_ok=True)
            dest = dest_dir / f"{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}_{safe_reason}.cvxsnapshot"
            envelope = {
                'format': 'CyberVaultSafetySnapshot/v1',
                'created_at': utc_now_iso(),
                'reason': reason,
                'aad': aad,
                'nonce': nonce,
                'ciphertext': cipher,
            }
            serialized = json.dumps(envelope, ensure_ascii=False, indent=2)
            atomic_write_text(dest, serialized, encoding='utf-8')
            digest = hashlib.sha256(serialized.encode('utf-8')).hexdigest()
            self.db.set_meta('last_safety_snapshot_path', safe_display_path(dest))
            self.db.set_meta('last_safety_snapshot_sha256', digest)
            self.add_log('Safety Snapshot Created', f'Created local safety snapshot before {reason}: {safe_display_path(dest)} | SHA-256 {digest[:16]}...', 'success')
            return dest
        except Exception as exc:
            if not fail_silent:
                raise
            try:
                self.add_log('Safety Snapshot Failed', f'Could not create pre-operation snapshot before {reason}: {exc}', 'warning')
            except Exception:
                pass
            return None

    def list_safety_snapshots(self) -> list[dict[str, str]]:
        dest_dir = self.db.db_path.parent / 'safety_snapshots'
        if not dest_dir.exists():
            return []
        items: list[dict[str, str]] = []
        for path in sorted(dest_dir.glob('*.cvxsnapshot'), reverse=True):
            try:
                raw = path.read_text(encoding='utf-8')
                payload = json.loads(raw)
                digest = hashlib.sha256(raw.encode('utf-8')).hexdigest()
                items.append({
                    'path': str(path),
                    'name': path.name,
                    'created_at': str(payload.get('created_at', '')),
                    'reason': str(payload.get('reason', '')),
                    'sha256': digest,
                })
            except Exception:
                items.append({'path': str(path), 'name': path.name, 'created_at': '', 'reason': 'Unreadable snapshot', 'sha256': ''})
        return items

    def restore_safety_snapshot(self, path: str | Path) -> dict[str, int]:
        key = self.require_key()
        source = Path(path)
        envelope = json.loads(source.read_text(encoding='utf-8'))
        if envelope.get('format') != 'CyberVaultSafetySnapshot/v1':
            raise ValueError('Selected file is not a CyberVault safety snapshot.')
        try:
            raw_payload = decrypt_text(envelope['nonce'], envelope['ciphertext'], key, aad=envelope.get('aad') or 'CyberVaultX:safety_snapshot:v1')
        except Exception as exc:
            raise ValueError(
                'This safety snapshot cannot be restored with the current master key. '
                'It may have been created before a master password rotation. Use an encrypted backup or select a post-rotation snapshot.'
            ) from exc
        data = json.loads(raw_payload)
        rows = self._validate_backup_payload(data)
        self.create_safety_snapshot('before safety snapshot restore', fail_silent=True)
        imported = 0
        history_imported = 0
        now = utc_now_iso()
        with self.db.connect() as conn:
            conn.execute('BEGIN')
            try:
                conn.execute('DELETE FROM credential_history')
                conn.execute('DELETE FROM credentials')
                for row in rows:
                    clean = {
                        'title': str(row.get('title', '')).strip(),
                        'username': str(row.get('username', '')).strip(),
                        'password': str(row.get('password', '')),
                        'category': str(row.get('category', 'General')).strip() or 'General',
                        'tags': str(row.get('tags', '') or '').strip(),
                        'notes': str(row.get('notes', '') or '').strip(),
                        'website': str(row.get('website', '') or '').strip(),
                    }
                    created_at = str(row.get('created_at', now) or now)
                    updated_at = str(row.get('updated_at', now) or now)
                    deleted_at = row.get('deleted_at') or None
                    is_favorite = 1 if bool(row.get('is_favorite', False)) else 0
                    copy_count = int(row.get('copy_count', 0) or 0)
                    view_count = int(row.get('view_count', 0) or 0)
                    encrypted = self._encrypt_fields_with_key(key, **clean)
                    cur = conn.execute(
                        """
                        INSERT INTO credentials(
                            title_nonce, title_cipher,
                            username_nonce, username_cipher,
                            password_nonce, password_cipher,
                            category_nonce, category_cipher,
                            tags_nonce, tags_cipher,
                            notes_nonce, notes_cipher,
                            website_nonce, website_cipher,
                            created_at, updated_at, deleted_at, is_favorite, copy_count, view_count
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (*encrypted, created_at, updated_at, deleted_at, is_favorite, copy_count, view_count),
                    )
                    new_id = int(cur.lastrowid)
                    aad_encrypted = self._encrypt_fields_with_key(key, **clean, credential_id=new_id)
                    conn.execute(
                        """
                        UPDATE credentials SET
                            title_nonce=?, title_cipher=?,
                            username_nonce=?, username_cipher=?,
                            password_nonce=?, password_cipher=?,
                            category_nonce=?, category_cipher=?,
                            tags_nonce=?, tags_cipher=?,
                            notes_nonce=?, notes_cipher=?,
                            website_nonce=?, website_cipher=?,
                            created_at=?, updated_at=?, deleted_at=?,
                            is_favorite=?, copy_count=?, view_count=?
                        WHERE id=?
                        """,
                        (*aad_encrypted, created_at, updated_at, deleted_at, is_favorite, copy_count, view_count, new_id),
                    )
                    imported += 1
                    for hist in data.get('history', {}).get(str(row.get('id')), []):
                        nonce, cipher = encrypt_text(str(hist['password']), key, aad=self._history_aad(new_id))
                        conn.execute(
                            'INSERT INTO credential_history(credential_id, password_nonce, password_cipher, changed_at) VALUES (?, ?, ?, ?)',
                            (new_id, nonce, cipher, str(hist.get('changed_at', now) or now)),
                        )
                        history_imported += 1
                conn.commit()
            except Exception:
                conn.rollback()
                raise
        self._invalidate_snapshot()
        self.add_log('Safety Snapshot Restored', f'Restored local safety snapshot {safe_display_path(source)}.', 'warning')
        return {'imported': imported, 'history_imported': history_imported}

    def preview_csv_rows(self, rows: list[dict[str, Any]], mapping: dict[str, str]) -> dict[str, Any]:
        existing_keys = {
            (item.title.strip().lower(), item.username.strip().lower(), normalize_site(item.website))
            for item in self.list_credentials(include_deleted=True)
        }
        valid = invalid = duplicates = 0
        issues: list[str] = []
        preview: list[dict[str, str]] = []

        def pick(row: dict[str, Any], key: str, default: str = '') -> str:
            src = mapping.get(key, '')
            return str(row.get(src, default) or '').strip() if src else default

        for idx, row in enumerate(rows, start=1):
            title = pick(row, 'title') or pick(row, 'website') or pick(row, 'username')
            username = pick(row, 'username')
            password = pick(row, 'password')
            website = pick(row, 'website')
            dedupe_key = (title.strip().lower(), username.strip().lower(), normalize_site(website))
            row_issues: list[str] = []
            if not title or not username or not password:
                row_issues.append('missing title/username/password')
            if dedupe_key in existing_keys:
                row_issues.append('duplicate existing credential')
                duplicates += 1
            if row_issues:
                invalid += 1
                if len(issues) < 10:
                    issues.append(f"Row {idx}: {', '.join(row_issues)}")
            else:
                valid += 1
            if len(preview) < 10:
                preview.append({
                    'row': str(idx),
                    'title': title,
                    'username': username,
                    'website': website,
                    'status': 'OK' if not row_issues else '; '.join(row_issues),
                })
        return {
            'total': len(rows),
            'valid': valid,
            'invalid': invalid,
            'duplicates': duplicates,
            'issues': issues,
            'preview': preview,
        }

    def _validate_backup_payload(self, data: dict[str, Any]) -> list[dict[str, Any]]:
        if not isinstance(data, dict):
            raise ValueError('Backup payload must be a JSON object.')
        rows = data.get('credentials', [])
        if not isinstance(rows, list):
            raise ValueError('Backup credentials field must be a list.')
        if len(rows) > self._MAX_BACKUP_ROWS:
            raise ValueError(f'Backup contains too many credentials ({len(rows)}).')

        required = ('title', 'username', 'password', 'category')
        seen_source_ids: set[str] = set()
        for idx, row in enumerate(rows, start=1):
            if not isinstance(row, dict):
                raise ValueError(f'Backup credential row #{idx} must be an object.')
            for field in required:
                if field not in row:
                    raise ValueError(f'Backup credential row #{idx} is missing required field: {field}')
                if not isinstance(row.get(field), str):
                    raise ValueError(f'Backup credential row #{idx} field {field} must be text.')
                if len(row.get(field, '')) > self._MAX_FIELD_LENGTH:
                    raise ValueError(f'Backup credential row #{idx} field {field} is too large.')
            for optional in ('tags', 'notes', 'website'):
                if optional in row and row[optional] is not None and not isinstance(row[optional], str):
                    raise ValueError(f'Backup credential row #{idx} field {optional} must be text.')
                if len(str(row.get(optional, '') or '')) > self._MAX_FIELD_LENGTH:
                    raise ValueError(f'Backup credential row #{idx} field {optional} is too large.')
            for count_field in ('copy_count', 'view_count'):
                try:
                    value = int(row.get(count_field, 0) or 0)
                except (TypeError, ValueError):
                    raise ValueError(f'Backup credential row #{idx} field {count_field} must be a non-negative integer.')
                if value < 0:
                    raise ValueError(f'Backup credential row #{idx} field {count_field} cannot be negative.')
            source_id = row.get('id')
            if source_id is not None:
                source_id_text = str(source_id)
                if source_id_text in seen_source_ids:
                    raise ValueError(f'Backup contains duplicate source credential id: {source_id_text}')
                seen_source_ids.add(source_id_text)

        history = data.get('history', {})
        if history is not None and not isinstance(history, dict):
            raise ValueError('Backup history field must be an object.')
        for credential_id, items in (history or {}).items():
            if not isinstance(items, list):
                raise ValueError(f'History for credential {credential_id} must be a list.')
            for hist_idx, hist in enumerate(items, start=1):
                if not isinstance(hist, dict) or 'password' not in hist:
                    raise ValueError(f'History item #{hist_idx} for credential {credential_id} is malformed.')
                if not isinstance(hist.get('password'), str):
                    raise ValueError(f'History item #{hist_idx} for credential {credential_id} password must be text.')

        settings = data.get('settings', {})
        if settings is not None and not isinstance(settings, dict):
            raise ValueError('Backup settings field must be an object.')
        return rows

    def export_encrypted_backup(self, path: str | Path, backup_passphrase: str) -> Path:
        self.require_key()
        validate_backup_passphrase(backup_passphrase)
        encrypted = encrypt_backup_json(self._backup_payload(), backup_passphrase)
        dest = Path(path)
        atomic_write_text(dest, json.dumps(encrypted, ensure_ascii=False, indent=2), encoding='utf-8')
        self.db.set_meta('last_backup', utc_now_iso())
        self.add_log('Backup Exported', f'Created encrypted backup {safe_display_path(dest)}.')
        return dest

    def preview_encrypted_backup(
        self,
        path: str | Path,
        backup_passphrase: str,
        *,
        allow_legacy_aad_fallback: bool = False,
    ) -> dict[str, Any]:
        """Decrypt and compare a backup without changing the current vault.

        The preview is designed for the restore/import wizard. It intentionally
        reports counts, duplicate signals, and setting changes without exposing
        raw passwords in the UI.
        """
        payload = json.loads(Path(path).read_text(encoding='utf-8'))
        data = decrypt_backup_json(payload, backup_passphrase, allow_legacy_aad_fallback=allow_legacy_aad_fallback)
        rows = self._validate_backup_payload(data)
        existing_keys = {
            (item.title.strip().lower(), item.username.strip().lower(), normalize_site(item.website))
            for item in self.list_credentials(include_deleted=True)
        }
        duplicate_rows = 0
        active_rows = 0
        deleted_rows = 0
        high_value_rows = 0
        missing_metadata_rows = 0
        categories: dict[str, int] = {}
        diff_preview: list[dict[str, str]] = []
        for idx, row in enumerate(rows, start=1):
            category = str(row.get('category', 'General') or 'General')
            categories[category] = categories.get(category, 0) + 1
            if row.get('deleted_at'):
                deleted_rows += 1
            else:
                active_rows += 1
            if category.lower() in {'banking', 'finance', 'crypto', 'servers', 'work', 'email'}:
                high_value_rows += 1
            if not str(row.get('website', '') or '').strip() or not str(row.get('tags', '') or '').strip():
                missing_metadata_rows += 1
            dedupe_key = (
                str(row.get('title', '')).strip().lower(),
                str(row.get('username', '')).strip().lower(),
                normalize_site(str(row.get('website', ''))),
            )
            is_duplicate = dedupe_key in existing_keys
            if is_duplicate:
                duplicate_rows += 1
            if len(diff_preview) < 12:
                if row.get('deleted_at'):
                    action = 'Restore to Trash'
                    reason = 'Source row is marked deleted.'
                elif is_duplicate:
                    action = 'Skip'
                    reason = 'Same title + username + normalized website exists in current vault.'
                else:
                    action = 'Add'
                    reason = 'New credential for merge mode.'
                diff_preview.append({
                    'row': str(idx),
                    'item': str(row.get('title') or row.get('website') or row.get('username') or f'Row {idx}'),
                    'action': action,
                    'reason': reason,
                })

        settings = data.get('settings', {}) if isinstance(data.get('settings', {}), dict) else {}
        setting_changes: dict[str, dict[str, str]] = {}
        for key_name in ('auto_lock_minutes', 'clipboard_clear_seconds', 'theme_accent', 'privacy_mode_logs'):
            if key_name in settings:
                current_value = self.get_setting(key_name, '')
                incoming = str(settings.get(key_name, ''))
                if current_value != incoming:
                    setting_changes[key_name] = {'current': current_value, 'incoming': incoming}

        total_rows = len(rows)
        safe_merge_adds = max(0, total_rows - duplicate_rows)
        recommendation = 'replace' if total_rows and safe_merge_adds == 0 else 'merge'
        return {
            'path': safe_display_path(Path(path)),
            'format': str(payload.get('format', 'unknown')),
            'exported_at': str(data.get('exported_at', '')),
            'owner_name_present': bool(str(data.get('owner_name', '')).strip()),
            'vault_name_present': bool(str(data.get('vault_name', '')).strip()),
            'total_rows': total_rows,
            'active_rows': active_rows,
            'deleted_rows': deleted_rows,
            'duplicates_in_current_vault': duplicate_rows,
            'merge_would_add': safe_merge_adds,
            'replace_would_remove_current': len(self.list_credentials(include_deleted=True)),
            'high_value_rows': high_value_rows,
            'missing_metadata_rows': missing_metadata_rows,
            'categories': dict(sorted(categories.items(), key=lambda pair: (-pair[1], pair[0]))[:8]),
            'setting_changes': setting_changes,
            'recommended_mode': recommendation,
            'diff_summary': {
                'will_add_on_merge': safe_merge_adds,
                'will_skip_duplicates_on_merge': duplicate_rows,
                'will_update_on_merge': 0,
                'will_move_to_trash_on_merge': deleted_rows,
                'will_replace_current_rows_on_replace': len(self.list_credentials(include_deleted=True)),
                'risk': 'Review' if setting_changes or missing_metadata_rows else 'Safe',
            },
            'diff_preview': diff_preview,
            'warnings': [
                warning
                for warning in [
                    'Replace mode deletes current credentials after creating a safety snapshot.' if total_rows else 'Backup contains no credentials.',
                    f'{duplicate_rows} row(s) already appear to exist in this vault.' if duplicate_rows else '',
                    f'{missing_metadata_rows} row(s) have missing website/tags metadata.' if missing_metadata_rows else '',
                    f'{len(setting_changes)} setting(s) will change if imported.' if setting_changes else '',
                ]
                if warning
            ],
        }

    def import_encrypted_backup(
        self,
        path: str | Path,
        backup_passphrase: str,
        *,
        replace_existing: bool = False,
        skip_duplicates: bool = True,
        allow_legacy_aad_fallback: bool = False,
    ) -> dict[str, int]:
        key = self.require_key()
        payload = json.loads(Path(path).read_text(encoding='utf-8'))
        data = decrypt_backup_json(payload, backup_passphrase, allow_legacy_aad_fallback=allow_legacy_aad_fallback)

        rows = self._validate_backup_payload(data)
        if replace_existing:
            self.create_safety_snapshot('backup import replace_existing', fail_silent=True)

        existing_keys = set()
        if not replace_existing:
            existing_keys = {
                (item.title.strip().lower(), item.username.strip().lower(), normalize_site(item.website))
                for item in self.list_credentials(include_deleted=True)
            }

        imported = 0
        skipped_duplicates = 0
        history_imported = 0
        settings = data.get('settings', {})
        now = utc_now_iso()

        with self.db.connect() as conn:
            try:
                conn.execute('BEGIN')
                if replace_existing:
                    conn.execute('DELETE FROM credential_history')
                    conn.execute('DELETE FROM credentials')

                for row in rows:
                    dedupe_key = (
                        str(row.get('title', '')).strip().lower(),
                        str(row.get('username', '')).strip().lower(),
                        normalize_site(str(row.get('website', ''))),
                    )
                    if skip_duplicates and dedupe_key in existing_keys:
                        skipped_duplicates += 1
                        continue

                    clean = {
                        'title': str(row.get('title', '')).strip(),
                        'username': str(row.get('username', '')).strip(),
                        'password': str(row.get('password', '')),
                        'category': str(row.get('category', 'General')).strip() or 'General',
                        'tags': str(row.get('tags', '') or '').strip(),
                        'notes': str(row.get('notes', '') or '').strip(),
                        'website': str(row.get('website', '') or '').strip(),
                    }
                    if not clean['title'] or not clean['username'] or not clean['password']:
                        raise ValueError('Backup contains a credential with missing title, username, or password.')

                    created_at = str(row.get('created_at', now) or now)
                    updated_at = str(row.get('updated_at', now) or now)
                    deleted_at = row.get('deleted_at') or None
                    is_favorite = 1 if bool(row.get('is_favorite', False)) else 0
                    copy_count = int(row.get('copy_count', 0) or 0)
                    view_count = int(row.get('view_count', 0) or 0)

                    encrypted = self._encrypt_fields_with_key(key, **clean)
                    cur = conn.execute(
                        """
                        INSERT INTO credentials(
                            title_nonce, title_cipher,
                            username_nonce, username_cipher,
                            password_nonce, password_cipher,
                            category_nonce, category_cipher,
                            tags_nonce, tags_cipher,
                            notes_nonce, notes_cipher,
                            website_nonce, website_cipher,
                            created_at, updated_at, deleted_at, is_favorite, copy_count, view_count
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (*encrypted, created_at, updated_at, deleted_at, is_favorite, copy_count, view_count),
                    )
                    new_id = int(cur.lastrowid)

                    aad_encrypted = self._encrypt_fields_with_key(key, **clean, credential_id=new_id)
                    conn.execute(
                        """
                        UPDATE credentials SET
                            title_nonce=?, title_cipher=?,
                            username_nonce=?, username_cipher=?,
                            password_nonce=?, password_cipher=?,
                            category_nonce=?, category_cipher=?,
                            tags_nonce=?, tags_cipher=?,
                            notes_nonce=?, notes_cipher=?,
                            website_nonce=?, website_cipher=?,
                            created_at=?, updated_at=?, deleted_at=?,
                            is_favorite=?, copy_count=?, view_count=?
                        WHERE id=?
                        """,
                        (*aad_encrypted, created_at, updated_at, deleted_at, is_favorite, copy_count, view_count, new_id),
                    )

                    imported += 1
                    existing_keys.add(dedupe_key)
                    for hist in data.get('history', {}).get(str(row.get('id')), []):
                        nonce, cipher = encrypt_text(str(hist['password']), key, aad=self._history_aad(new_id))
                        conn.execute(
                            'INSERT INTO credential_history(credential_id, password_nonce, password_cipher, changed_at) VALUES (?, ?, ?, ?)',
                            (new_id, nonce, cipher, str(hist.get('changed_at', now) or now)),
                        )
                        history_imported += 1

                for meta_key in ('auto_lock_minutes', 'clipboard_clear_seconds', 'theme_accent', 'privacy_mode_logs'):
                    if meta_key in settings:
                        conn.execute(
                            'INSERT INTO app_meta(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value',
                            (meta_key, str(settings[meta_key])),
                        )

                conn.commit()
            except Exception:
                conn.rollback()
                raise

        self._invalidate_snapshot()
        self.add_log('Backup Imported', f'Imported encrypted backup {safe_display_path(path)}.')
        return {
            'imported': imported,
            'skipped_duplicates': skipped_duplicates,
            'history_imported': history_imported,
        }

    def import_csv_rows(self, rows: list[dict[str, Any]], mapping: dict[str, str], *, skip_duplicates: bool = True) -> dict[str, Any]:
        existing_keys = {
            (
                item.title.strip().lower(),
                item.username.strip().lower(),
                normalize_site(item.website),
            )
            for item in self.list_credentials(include_deleted=True)
        }
        skipped = 0
        duplicates = 0
        failures: list[str] = []
        prepared: list[dict[str, Any]] = []

        def pick(row: dict[str, Any], key: str, default: str = '') -> str:
            src = mapping.get(key, '')
            if not src:
                return default
            return str(row.get(src, default) or '').strip()

        for idx, row in enumerate(rows, start=1):
            title = pick(row, 'title') or pick(row, 'website') or pick(row, 'username')
            username = pick(row, 'username')
            password = pick(row, 'password')
            website = pick(row, 'website')
            category = pick(row, 'category', 'Imported') or 'Imported'
            tags = pick(row, 'tags', 'csv-import') or 'csv-import'
            notes = pick(row, 'notes', 'Imported from browser/CSV.') or 'Imported from browser/CSV.'
            favorite = pick(row, 'favorite', '').lower() in {'1', 'true', 'yes', 'y', 'favorite'}

            if not title or not username or not password:
                skipped += 1
                failures.append(f'Row {idx}: missing title/username/password.')
                continue

            clean = {
                'title': title.strip(),
                'username': username.strip(),
                'password': password,
                'category': category.strip() or 'Imported',
                'tags': tags.strip(),
                'notes': notes.strip(),
                'website': website.strip(),
                'is_favorite': favorite,
            }
            oversized = [name for name, value in clean.items() if isinstance(value, str) and len(value) > self._MAX_FIELD_LENGTH]
            if oversized:
                skipped += 1
                failures.append(f"Row {idx}: field too large ({', '.join(oversized)}).")
                continue

            dedupe_key = (clean['title'].lower(), clean['username'].lower(), normalize_site(clean['website']))
            if skip_duplicates and dedupe_key in existing_keys:
                skipped += 1
                duplicates += 1
                continue
            prepared.append(clean)
            existing_keys.add(dedupe_key)

        key = self.require_key()
        now = utc_now_iso()
        imported_ids: list[int] = []
        with self.db.connect() as conn:
            try:
                conn.execute('BEGIN')
                for clean in prepared:
                    encrypted = self._encrypt_fields_with_key(
                        key,
                        title=clean['title'],
                        username=clean['username'],
                        password=clean['password'],
                        category=clean['category'],
                        tags=clean['tags'],
                        notes=clean['notes'],
                        website=clean['website'],
                    )
                    cur = conn.execute(
                        """
                        INSERT INTO credentials(
                            title_nonce, title_cipher,
                            username_nonce, username_cipher,
                            password_nonce, password_cipher,
                            category_nonce, category_cipher,
                            tags_nonce, tags_cipher,
                            notes_nonce, notes_cipher,
                            website_nonce, website_cipher,
                            created_at, updated_at, deleted_at, is_favorite, copy_count, view_count
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (*encrypted, now, now, None, 1 if clean['is_favorite'] else 0, 0, 0),
                    )
                    new_id = int(cur.lastrowid)
                    aad_encrypted = self._encrypt_fields_with_key(
                        key,
                        title=clean['title'],
                        username=clean['username'],
                        password=clean['password'],
                        category=clean['category'],
                        tags=clean['tags'],
                        notes=clean['notes'],
                        website=clean['website'],
                        credential_id=new_id,
                    )
                    conn.execute(
                        """
                        UPDATE credentials SET
                            title_nonce=?, title_cipher=?,
                            username_nonce=?, username_cipher=?,
                            password_nonce=?, password_cipher=?,
                            category_nonce=?, category_cipher=?,
                            tags_nonce=?, tags_cipher=?,
                            notes_nonce=?, notes_cipher=?,
                            website_nonce=?, website_cipher=?,
                            updated_at=?,
                            is_favorite=?
                        WHERE id=?
                        """,
                        (*aad_encrypted, now, 1 if clean['is_favorite'] else 0, new_id),
                    )
                    imported_ids.append(new_id)
                conn.commit()
            except Exception:
                conn.rollback()
                raise

        imported = len(imported_ids)
        self._invalidate_snapshot()
        self.add_log('CSV Import', f'Imported {imported} credential(s) from CSV transaction, skipped {skipped}.')
        return {
            'imported': imported,
            'skipped': skipped,
            'duplicates': duplicates,
            'failures': failures[:8],
            'imported_ids': imported_ids,
        }

    def load_demo_data(self) -> dict[str, Any]:
        """Merge a curated security assessment dataset into the unlocked vault.

        The dataset is intentionally synthetic and privacy-safe, but it is presented
        as a professional assessment workspace rather than a visible sample set. It
        contains a larger mix of privileged, weak, reused, stale, breached,
        incomplete, and retired records so the dashboard, Security Center, AI
        Guardian, Trash workflow, and report builder all have meaningful data.
        """
        existing_keys = {
            (item.title.strip().lower(), item.username.strip().lower(), normalize_site(item.website))
            for item in self.list_credentials(include_deleted=True)
        }
        samples = [
            dict(
                title='GitHub Admin Portal',
                username='admin@cybervault.local',
                password='G!tHub#2026_XVault',
                category='Work',
                tags='admin,code,privileged,healthy',
                notes='Privileged source-code account. Keep hardware MFA enabled and restrict recovery methods.',
                website='github.com',
                is_favorite=True,
                age_days=8,
            ),
            dict(
                title='Corporate Mail Gateway',
                username='mail.owner@corp.example',
                password='password123',
                category='Education',
                tags='breached,weak,email',
                notes='Mail credential using a weak known pattern. Replace immediately and enforce MFA.',
                website='mail.corp.example',
                is_favorite=False,
                age_days=2,
            ),
            dict(
                title='Cloud Operations Console',
                username='ops@cloud.example',
                password='Winter2024!',
                category='Servers',
                tags='reused,cloud,operations',
                notes='Privileged cloud console account. Reuse detection should prioritize this record.',
                website='cloud.example.com',
                is_favorite=True,
                age_days=18,
            ),
            dict(
                title='Brand Social Console',
                username='social@brand.example',
                password='Winter2024!',
                category='Social',
                tags='reused,marketing,shared-risk',
                notes='Shared social media management account using the same password as a cloud console.',
                website='instagram.com',
                is_favorite=False,
                age_days=21,
            ),
            dict(
                title='Finance Portal',
                username='finance@bank.example',
                password='Tru$tedBank#2026!Qx',
                category='Banking',
                tags='finance,mfa,healthy,critical',
                notes='High-value financial account. Maintain hardware-token MFA and strict recovery controls.',
                website='bank.example.com',
                is_favorite=True,
                age_days=5,
            ),
            dict(
                title='Legacy Mail Archive',
                username='legacy@mail.example',
                password='Qwerty2020',
                category='Email',
                tags='legacy,stale,weak',
                notes='Old archive mailbox with a predictable password. Rotate or disable after review.',
                website='archive-mail.example.com',
                is_favorite=False,
                age_days=128,
            ),
            dict(
                title='Threat Simulation Portal',
                username='bibo_fox',
                password='Ctf-Lab#2026-BlueTeam',
                category='Education',
                tags='lab,portfolio,healthy',
                notes='Security-lab account with stronger password quality used as a healthy comparison.',
                website='tryhackme.com',
                is_favorite=False,
                age_days=35,
            ),
            dict(
                title='Vendor Procurement Portal',
                username='vendor@corp.example',
                password='Vendor2026',
                category='Shopping',
                tags='vendor,metadata-needed,medium-risk',
                notes='Vendor credential missing a verified website field. Complete metadata before report export.',
                website='',
                is_favorite=False,
                age_days=12,
            ),
            dict(
                title='Retired VPN Access',
                username='vpn.retired@corp.example',
                password='RetiredVPN2020!',
                category='Servers',
                tags='retired,vpn,trash,stale',
                notes='Retired remote-access credential kept in Trash to prove safe recovery and purge workflow.',
                website='vpn.old.example.com',
                is_favorite=False,
                age_days=160,
                move_to_trash=True,
            ),
            dict(
                title='HR Payroll Portal',
                username='hr@corp.example',
                password='Welcome2024',
                category='Work',
                tags='hr,breached,weak,high-impact',
                notes='Payroll account with a common password pattern. Replace before operational use.',
                website='payroll.example.com',
                is_favorite=True,
                age_days=74,
            ),
            dict(
                title='Microsoft 365 Admin',
                username='m365.admin@corp.example',
                password='Company2024!',
                category='Email',
                tags='admin,mail,reused,tenant',
                notes='Tenant administrator account. Reused password risk must be remediated first.',
                website='admin.microsoft.example',
                is_favorite=True,
                age_days=44,
            ),
            dict(
                title='Project Operations Admin',
                username='jira.admin@corp.example',
                password='Company2024!',
                category='Work',
                tags='admin,projects,reused',
                notes='Operations admin sharing a password with the Microsoft 365 admin record.',
                website='jira.example.com',
                is_favorite=False,
                age_days=46,
            ),
            dict(
                title='Slack Workspace Owner',
                username='comms@corp.example',
                password='Summer2025!',
                category='Work',
                tags='workspace,breached,reused,comms',
                notes='Collaboration workspace owner account with password reuse exposure.',
                website='slack.com',
                is_favorite=False,
                age_days=31,
            ),
            dict(
                title='Docker Hub Registry',
                username='devops@registry.example',
                password='Summer2025!',
                category='Servers',
                tags='devops,registry,reused,supply-chain',
                notes='Container registry credential sharing a password with the collaboration workspace.',
                website='hub.docker.com',
                is_favorite=False,
                age_days=34,
            ),
            dict(
                title='DNS Registrar',
                username='domains@corp.example',
                password='Dns-Reg!strar#2026-Core',
                category='Work',
                tags='dns,critical,healthy',
                notes='Domain registrar account. Protect with hardware MFA and emergency ownership recovery.',
                website='registrar.example.com',
                is_favorite=True,
                age_days=14,
            ),
            dict(
                title='Stripe Billing Dashboard',
                username='billing@corp.example',
                password='Tr0pical$Billing-2026',
                category='Banking',
                tags='billing,payments,healthy',
                notes='Billing console account with acceptable strength. Confirm least-privilege roles.',
                website='stripe.com',
                is_favorite=True,
                age_days=9,
            ),
            dict(
                title='CRM Sales Portal',
                username='sales@corp.example',
                password='P@ssw0rd',
                category='Work',
                tags='crm,weak,breached,customer-data',
                notes='Customer-data system using a known weak pattern. Rotate and enforce MFA.',
                website='crm.example.com',
                is_favorite=False,
                age_days=11,
            ),
            dict(
                title='Database Admin Console',
                username='dba@db.example',
                password='DbAdmin#2026-Rotate',
                category='Servers',
                tags='database,privileged,rotation-due',
                notes='Database administrator credential. Add break-glass policy and rotation schedule.',
                website='db-admin.example.com',
                is_favorite=True,
                age_days=93,
            ),
            dict(
                title='Backup Management Console',
                username='backup@corp.example',
                password='Backup2020!',
                category='Servers',
                tags='backup,stale,recovery-risk',
                notes='Backup console credential is old and high-impact. Rotate after validating recovery procedures.',
                website='backup.example.com',
                is_favorite=True,
                age_days=190,
            ),
            dict(
                title='Wireless Controller',
                username='netadmin@wlc.local',
                password='NetOps#2026-WiFi',
                category='Servers',
                tags='network,wifi,healthy',
                notes='Wireless controller account with strong password. Verify admin role separation.',
                website='wlc.local',
                is_favorite=False,
                age_days=22,
            ),
            dict(
                title='Endpoint Security Console',
                username='security@edr.local',
                password='EDR-Sentinel#2026',
                category='Work',
                tags='security,edr,healthy',
                notes='Endpoint-security console. Keep emergency access and audit logging enabled.',
                website='edr.example.com',
                is_favorite=True,
                age_days=7,
            ),
            dict(
                title='API Gateway Console',
                username='api-owner@corp.example',
                password='Gateway2024!',
                category='Servers',
                tags='api,medium-risk,rotation-due',
                notes='API gateway admin account. Rotate and verify token inventory after password change.',
                website='gateway.example.com',
                is_favorite=False,
                age_days=86,
            ),
            dict(
                title='CI Deployment Service Account',
                username='svc-ci@corp.example',
                password='SvcDeploy2023!',
                category='Servers',
                tags='service-account,ci,stale',
                notes='Service account used by deployment workflows. Move to scoped token or managed identity.',
                website='ci.example.com',
                is_favorite=False,
                age_days=155,
            ),
            dict(
                title='Code Signing Portal',
                username='release@corp.example',
                password='CodeSign#2026-Critical',
                category='Work',
                tags='release,code-signing,critical,healthy',
                notes='Release-signing account. Treat as critical and require dual-control approval.',
                website='codesign.example.com',
                is_favorite=True,
                age_days=17,
            ),
            dict(
                title='Knowledge Portal Admin',
                username='knowledge.admin@corp.example',
                password='Password1',
                category='Education',
                tags='knowledge,weak,breached',
                notes='Knowledge portal account using a known compromised pattern. Replace immediately.',
                website='knowledge.example.com',
                is_favorite=False,
                age_days=28,
            ),
            dict(
                title='eCommerce Merchant Center',
                username='seller@shop.example',
                password='Merchant#2026-Live',
                category='Shopping',
                tags='merchant,payments,healthy',
                notes='Merchant account with payment exposure. Confirm alerting and account recovery settings.',
                website='merchant.example.com',
                is_favorite=False,
                age_days=19,
            ),
            dict(
                title='Helpdesk Admin Panel',
                username='support@corp.example',
                password='Helpdesk2024!',
                category='Work',
                tags='helpdesk,admin,rotation-due',
                notes='Helpdesk admin account can reset users. Enforce MFA and audit privileged actions.',
                website='helpdesk.example.com',
                is_favorite=False,
                age_days=101,
            ),
            dict(
                title='Personal Portfolio Hosting',
                username='bibo_fox@portfolio.example',
                password='BiboPortfolio#2026',
                category='Personal',
                tags='portfolio,personal,healthy',
                notes='Portfolio hosting account with healthy password strength and clear metadata.',
                website='portfolio.example.com',
                is_favorite=False,
                age_days=13,
            ),
            dict(
                title='Red Team Lab Console',
                username='analyst.redteam@lab.example',
                password='123456',
                category='Education',
                tags='lab,weak,breached,critical-finding',
                notes='High-risk lab credential used to verify weak-password detection and prioritization.',
                website='lab.example.com',
                is_favorite=False,
                age_days=3,
            ),
            dict(
                title='Old FTP Server',
                username='ftp.legacy@corp.example',
                password='FTP2020!',
                category='Servers',
                tags='retired,ftp,trash,legacy',
                notes='Legacy FTP access moved to Trash to demonstrate safer retirement workflow.',
                website='ftp.legacy.example.com',
                is_favorite=False,
                age_days=220,
                move_to_trash=True,
            ),
        ]
        created_ids: list[int] = []
        skipped_existing = 0
        moved_to_trash = 0
        now = datetime.now(timezone.utc)

        for item in samples:
            payload = dict(item)
            age_days = int(payload.pop('age_days', 0) or 0)
            move_to_trash = bool(payload.pop('move_to_trash', False))
            key = (
                payload['title'].strip().lower(),
                payload['username'].strip().lower(),
                normalize_site(payload.get('website', '')),
            )
            if key in existing_keys:
                skipped_existing += 1
                continue
            credential_id = self.add_credential(**payload)
            created_ids.append(credential_id)
            existing_keys.add(key)
            if age_days:
                adjusted_updated = (now - timedelta(days=age_days)).replace(microsecond=0).isoformat()
                self.db.set_updated_at(credential_id, adjusted_updated)
            if move_to_trash:
                self.move_to_trash(credential_id)
                moved_to_trash += 1

        if created_ids:
            self.db.set_meta('assessment_dataset_loaded_at', utc_now_iso())
            self.db.set_meta('demo_dataset_loaded_at', utc_now_iso())  # legacy compatibility
            self.db.set_meta('default_report_privacy_level', 'analyst')
            self.db.set_meta('privacy_report_level', 'analyst')
            self._invalidate_snapshot()
            self.add_log(
                'Assessment Workspace Created',
                f'Added {len(created_ids)} curated assessment credential(s); skipped {skipped_existing} existing item(s).',
                severity='success',
            )
        else:
            self.add_log('Assessment Workspace Already Present', f'Skipped {skipped_existing} existing assessment credential(s).', severity='info')

        return {
            'created': len(created_ids),
            'skipped_existing': skipped_existing,
            'moved_to_trash': moved_to_trash,
            'total_workspace_items': len(samples),
            'total_workspace_items': len(samples),
            'total_demo_items': len(samples),  # legacy compatibility  # legacy compatibility
            'total_assessment_items': len(samples),
            'created_ids': created_ids,
        }

