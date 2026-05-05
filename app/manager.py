from __future__ import annotations

import html
import json
import re
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .analyzer import (
    analyze_password,
    build_breach_intelligence,
    build_recommendations,
    compute_dashboard,
    duplicate_counts,
    duplicate_password_counts,
    normalize_site,
    password_is_old,
)
from .crypto_utils import (
    MasterRecord,
    create_master_record,
    decrypt_backup_json,
    decrypt_text,
    encrypt_backup_json,
    encrypt_text,
    validate_backup_passphrase,
    verify_master_password,
)
from .db import SCHEMA_VERSION, VaultDatabase
from .core.password_policy import validate_master_password_policy
from .io_utils import atomic_write_text, safe_display_path
from .security_policy import composite_risk_level, mask_identifier, normalize_issue_list, privacy_safe_title, severity_for_risk
from .services import AnalysisServiceMixin, AIGuardianServiceMixin, BackupServiceMixin, ProofServiceMixin, ReportServiceMixin, ProductIntelligenceMixin


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


@dataclass(slots=True)
class Credential:
    id: int
    title: str
    username: str
    password: str
    category: str
    tags: str
    notes: str
    website: str
    created_at: str
    updated_at: str
    deleted_at: str | None
    is_favorite: bool
    copy_count: int
    view_count: int


class VaultManager(AnalysisServiceMixin, AIGuardianServiceMixin, ReportServiceMixin, BackupServiceMixin, ProofServiceMixin, ProductIntelligenceMixin):
    def __init__(self, db_path: str | Path) -> None:
        self.db = VaultDatabase(db_path)
        self.master_record = self._load_master_record()
        self._key: bytes | None = None
        self.failed_unlock_attempts = 0
        self.unlock_blocked_until: datetime | None = None
        self.last_unlock_message = ''
        self._snapshot_cache = None
        self._load_unlock_guard_state()
        self.purge_expired_trash()
        self.purge_old_activity_logs()

    def _load_master_record(self) -> MasterRecord | None:
        salt = self.db.get_meta('master_salt')
        verifier = self.db.get_meta('master_verifier')
        if salt and verifier:
            return MasterRecord(salt_b64=salt, verifier_b64=verifier)
        return None

    def _load_unlock_guard_state(self) -> None:
        try:
            self.failed_unlock_attempts = int(self.db.get_meta('unlock_failed_attempts') or '0')
        except (TypeError, ValueError):
            self.failed_unlock_attempts = 0
        blocked_until_raw = (self.db.get_meta('unlock_blocked_until') or '').strip()
        if blocked_until_raw:
            try:
                self.unlock_blocked_until = datetime.fromisoformat(blocked_until_raw)
            except ValueError:
                self.unlock_blocked_until = None
        else:
            self.unlock_blocked_until = None

    def _persist_unlock_guard_state(self) -> None:
        self.db.set_meta('unlock_failed_attempts', str(max(0, self.failed_unlock_attempts)))
        self.db.set_meta('unlock_blocked_until', self.unlock_blocked_until.isoformat() if self.unlock_blocked_until else '')

    def _clear_unlock_guard_state(self) -> None:
        self.failed_unlock_attempts = 0
        self.unlock_blocked_until = None
        self._persist_unlock_guard_state()

    def _current_block_remaining(self) -> int:
        now = datetime.now(timezone.utc)
        if self.unlock_blocked_until and now < self.unlock_blocked_until:
            return max(1, int((self.unlock_blocked_until - now).total_seconds()))
        if self.unlock_blocked_until and now >= self.unlock_blocked_until:
            self.unlock_blocked_until = None
            self._persist_unlock_guard_state()
        return 0

    def _validate_master_password_policy(self, password: str, owner_name: str = '') -> None:
        result = validate_master_password_policy(password, owner_name)
        if not result.ok:
            # Raise only the first generic policy reason. Never echo the supplied secret.
            raise ValueError(result.reasons[0])

    def _meta_aad(self, meta_key: str) -> str:
        return f'CyberVaultX:app_meta:{meta_key}:v4'

    def _field_aad(self, credential_id: int, field_name: str) -> str:
        return f'CyberVaultX:credentials:{credential_id}:{field_name}:v4'

    def _history_aad(self, credential_id: int) -> str:
        return f'CyberVaultX:credential_history:{credential_id}:password:v4'

    def _credential_aad_fallback_allowed(self) -> bool:
        return self.db.get_meta('credential_aad_migrated_v4') != '1'

    def _credential_aad_options(self, credential_id: int, field_name: str) -> tuple[str | None, ...]:
        aad = self._field_aad(credential_id, field_name)
        return (aad, None) if self._credential_aad_fallback_allowed() else (aad,)

    def _history_aad_options(self, credential_id: int) -> tuple[str | None, ...]:
        aad = self._history_aad(credential_id)
        return (aad, None) if self._credential_aad_fallback_allowed() else (aad,)

    def _encrypt_sensitive_meta(self, key: bytes, meta_key: str, value: str) -> None:
        nonce, cipher = encrypt_text(value, key, aad=self._meta_aad(meta_key))
        self.db.set_meta(f'{meta_key}_nonce', nonce)
        self.db.set_meta(f'{meta_key}_cipher', cipher)

    def _get_sensitive_meta(self, meta_key: str, default: str) -> str:
        nonce = self.db.get_meta(f'{meta_key}_nonce')
        cipher = self.db.get_meta(f'{meta_key}_cipher')
        strict_encrypted_meta = self.db.get_meta('sensitive_meta_encrypted_v1') == '1'
        if nonce and cipher and self._key is not None:
            aad_options = (self._meta_aad(meta_key),) if strict_encrypted_meta else (self._meta_aad(meta_key), None)
            for aad in aad_options:
                try:
                    value = decrypt_text(nonce, cipher, self._key, aad=aad).strip()
                    if value:
                        return value
                except Exception:
                    continue
        if not strict_encrypted_meta:
            fallback = (self.db.get_meta(meta_key) or '').strip()
            return fallback or default
        return default

    def _migrate_sensitive_meta_to_encrypted(self) -> None:
        key = self._key
        if key is None:
            return
        for meta_key, default in (('owner_name', 'Vault Owner'), ('vault_name', '')):
            plain = (self.db.get_meta(meta_key) or '').strip()
            nonce = self.db.get_meta(f'{meta_key}_nonce')
            cipher = self.db.get_meta(f'{meta_key}_cipher')
            if plain and (not nonce or not cipher):
                self._encrypt_sensitive_meta(key, meta_key, plain)
                self.db.delete_meta(meta_key)
        privacy_default = self.db.get_meta('privacy_mode_logs')
        if privacy_default is None:
            self.db.set_meta('privacy_mode_logs', '1')
        if self.db.get_meta('owner_name_nonce') and self.db.get_meta('vault_name_nonce'):
            self.db.set_meta('sensitive_meta_encrypted_v1', '1')

    def _migrate_credentials_to_aad(self) -> None:
        key = self._key
        if key is None or self.db.get_meta('credential_aad_migrated_v4') == '1':
            return
        rows = self.db.fetch_credentials(include_deleted=True)
        migrated: list[dict[str, Any]] = []
        migrated_history: dict[int, list[dict[str, str]]] = {}
        for row in rows:
            credential_id = int(row['id'])
            migrated.append({
                'id': credential_id,
                'title': self._decrypt_field(row, 'title', key),
                'username': self._decrypt_field(row, 'username', key),
                'password': self._decrypt_field(row, 'password', key),
                'category': self._decrypt_field(row, 'category', key),
                'tags': self._decrypt_field(row, 'tags', key),
                'notes': self._decrypt_field(row, 'notes', key),
                'website': self._decrypt_field(row, 'website', key),
                'created_at': row['created_at'],
                'updated_at': row['updated_at'],
                'deleted_at': row['deleted_at'],
                'is_favorite': int(row['is_favorite']),
                'copy_count': int(row['copy_count']),
                'view_count': int(row['view_count']),
            })
            migrated_history[credential_id] = [
                {
                    'changed_at': hist['changed_at'],
                    'password': self._decrypt_history_password(hist, credential_id, key),
                }
                for hist in self.db.fetch_all_history(credential_id)
            ]
        with self.db.connect() as conn:
            for item in migrated:
                encrypted = self._encrypt_fields_with_key(
                    key,
                    title=item['title'],
                    username=item['username'],
                    password=item['password'],
                    category=item['category'],
                    tags=item['tags'],
                    notes=item['notes'],
                    website=item['website'],
                    credential_id=item['id'],
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
                        created_at=?, updated_at=?, deleted_at=?,
                        is_favorite=?, copy_count=?, view_count=?
                    WHERE id=?
                    """,
                    (*encrypted, item['created_at'], item['updated_at'], item['deleted_at'], item['is_favorite'], item['copy_count'], item['view_count'], item['id']),
                )
            conn.execute('DELETE FROM credential_history')
            for credential_id, history_items in migrated_history.items():
                for history_item in history_items:
                    nonce, cipher = encrypt_text(history_item['password'], key, aad=self._history_aad(credential_id))
                    conn.execute(
                        'INSERT INTO credential_history(credential_id, password_nonce, password_cipher, changed_at) VALUES (?, ?, ?, ?)',
                        (credential_id, nonce, cipher, history_item['changed_at']),
                    )
            conn.execute(
                "INSERT INTO app_meta(key, value) VALUES('credential_aad_migrated_v4', '1') ON CONFLICT(key) DO UPDATE SET value=excluded.value"
            )
            conn.commit()

    def _log_target(self, title: str | None = None, *, credential_id: int | None = None) -> str:
        privacy_enabled = self.get_setting('privacy_mode_logs', '1') == '1'
        if privacy_enabled:
            if credential_id is not None:
                return f'credential #{credential_id}'
            return 'credential'
        if title:
            return title
        if credential_id is not None:
            return f'credential #{credential_id}'
        return 'credential'

    @property
    def is_initialized(self) -> bool:
        return self.master_record is not None

    @property
    def is_unlocked(self) -> bool:
        return self._key is not None

    @property
    def owner_name(self) -> str:
        return self._get_sensitive_meta('owner_name', 'Vault Owner')

    @property
    def vault_name(self) -> str:
        custom = self._get_sensitive_meta('vault_name', '')
        return custom or f'{self.owner_name} Secure Vault'

    def setup_master_password(self, owner_name: str, password: str) -> None:
        if self.master_record is not None:
            raise ValueError('Vault already initialized.')
        owner_name = owner_name.strip()
        if len(owner_name) < 2:
            raise ValueError('Owner name must be at least 2 characters.')
        self._validate_master_password_policy(password, owner_name)
        record = create_master_record(password)
        self.db.set_meta('master_salt', record.salt_b64)
        self.db.set_meta('master_verifier', record.verifier_b64)
        self.db.set_meta('auto_lock_minutes', '3')
        self.db.set_meta('clipboard_clear_seconds', '15')
        self.db.set_meta('theme_accent', 'Cyan')
        self.db.set_meta('favicon_lookup_enabled', '0')
        self.db.set_meta('privacy_mode_logs', '1')
        self.db.set_meta('created_on', utc_now_iso())
        self.db.set_meta('master_password_rotated_at', utc_now_iso())
        self.master_record = record
        self.unlock(password)
        self._encrypt_sensitive_meta(self.require_key(), 'owner_name', owner_name)
        self._encrypt_sensitive_meta(self.require_key(), 'vault_name', f'{owner_name} Secure Vault')
        self.add_log('Vault Created', 'Initialized a new encrypted local vault.')

    def unlock(self, password: str) -> bool:
        if self.master_record is None:
            raise ValueError('Vault is not initialized.')
        remaining = self._current_block_remaining()
        if remaining > 0:
            self.last_unlock_message = f'Too many failed attempts. Try again in {remaining} second(s).'
            return False
        valid, key = verify_master_password(password, self.master_record)
        if valid and key is not None:
            self._key = key
            self._clear_unlock_guard_state()
            self.last_unlock_message = 'Vault unlocked successfully.'
            self._migrate_sensitive_meta_to_encrypted()
            self._migrate_credentials_to_aad()
            self._invalidate_snapshot()
            self.add_log('Unlock Success', 'Vault unlocked successfully.')
            return True
        self.failed_unlock_attempts += 1
        self._key = None
        if self.failed_unlock_attempts >= 3:
            delay = min(300, 15 * (2 ** (self.failed_unlock_attempts - 3)))
            self.unlock_blocked_until = datetime.now(timezone.utc) + timedelta(seconds=delay)
            self._persist_unlock_guard_state()
            self.last_unlock_message = f'Invalid master password. Vault locked for {delay} second(s) after repeated failures.'
            self.add_log('Unlock Rate Limited', self.last_unlock_message, severity='warning')
            return False
        self._persist_unlock_guard_state()
        self.last_unlock_message = f'Invalid master password. {max(0, 3 - self.failed_unlock_attempts)} attempt(s) left before temporary lockout.'
        self.add_log('Unlock Failed', 'Invalid master password attempt.', severity='warning')
        return False

    def verify_master_password_only(self, password: str) -> bool:
        """Verify re-authentication without replacing or clearing the active unlock key."""
        if self.master_record is None:
            raise ValueError('Vault is not initialized.')
        remaining = self._current_block_remaining()
        if remaining > 0:
            self.last_unlock_message = f'Too many failed attempts. Try again in {remaining} second(s).'
            return False
        valid, _key = verify_master_password(password, self.master_record)
        if valid:
            self._clear_unlock_guard_state()
            self.last_unlock_message = 'Re-authentication verified.'
            self.add_log('Re-auth Success', 'Sensitive action re-authentication verified.')
            return True
        self.failed_unlock_attempts += 1
        if self.failed_unlock_attempts >= 3:
            delay = min(300, 15 * (2 ** (self.failed_unlock_attempts - 3)))
            self.unlock_blocked_until = datetime.now(timezone.utc) + timedelta(seconds=delay)
            self._persist_unlock_guard_state()
            self.last_unlock_message = f'Invalid master password. Vault locked for {delay} second(s) after repeated failures.'
            self.add_log('Re-auth Rate Limited', self.last_unlock_message, severity='warning')
            return False
        self._persist_unlock_guard_state()
        self.last_unlock_message = f'Invalid master password. {max(0, 3 - self.failed_unlock_attempts)} attempt(s) left before temporary lockout.'
        self.add_log('Re-auth Failed', 'Invalid master password during sensitive action.', severity='warning')
        return False

    def lock(self) -> None:
        if self._key is not None:
            self._key = None
            self.add_log('Vault Locked', 'Vault locked.')

    def unlock_guard_status(self) -> dict[str, int | bool]:
        remaining = self._current_block_remaining()
        return {
            'failed_attempts': self.failed_unlock_attempts,
            'lockout_threshold': 3,
            'blocked': remaining > 0,
            'remaining_seconds': remaining,
        }

    def require_key(self) -> bytes:
        if self._key is None:
            raise RuntimeError('Vault is locked.')
        return self._key

    def get_setting_int(self, key: str, default: int) -> int:
        try:
            return int(self.db.get_meta(key) or default)
        except (TypeError, ValueError):
            return default

    def set_setting_int(self, key: str, value: int) -> None:
        self.db.set_meta(key, str(value))

    def get_setting(self, key: str, default: str = '') -> str:
        return self.db.get_meta(key) or default

    def set_setting(self, key: str, value: str) -> None:
        self.db.set_meta(key, value)

    def _encrypt_fields_with_key(self, key: bytes, *, title: str, username: str, password: str, category: str, tags: str, notes: str, website: str, credential_id: int | None = None) -> tuple[str, ...]:
        fields = [
            ('title', title),
            ('username', username),
            ('password', password),
            ('category', category),
            ('tags', tags),
            ('notes', notes),
            ('website', website),
        ]
        encrypted: list[str] = []
        for field_name, field_value in fields:
            aad = self._field_aad(credential_id, field_name) if credential_id is not None else None
            nonce, cipher = encrypt_text(field_value, key, aad=aad)
            encrypted.extend([nonce, cipher])
        return tuple(encrypted)

    def _encrypt_fields(self, *, title: str, username: str, password: str, category: str, tags: str, notes: str, website: str, credential_id: int | None = None) -> tuple[str, ...]:
        return self._encrypt_fields_with_key(
            self.require_key(),
            title=title,
            username=username,
            password=password,
            category=category,
            tags=tags,
            notes=notes,
            website=website,
            credential_id=credential_id,
        )

    def _decrypt_field(self, row: Any, field_name: str, key: bytes) -> str:
        nonce = row[f'{field_name}_nonce']
        cipher = row[f'{field_name}_cipher']
        credential_id = int(row['id'])
        for aad in self._credential_aad_options(credential_id, field_name):
            try:
                return decrypt_text(nonce, cipher, key, aad=aad)
            except Exception:
                continue
        raise ValueError(f'Unable to decrypt {field_name} for credential #{credential_id}.')

    def find_duplicate_credentials(self, *, title: str, username: str, website: str, exclude_id: int | None = None) -> list[Credential]:
        """Return likely duplicate credentials using title + username + normalized site."""
        target = (title.strip().lower(), username.strip().lower(), normalize_site(website))
        if not any(target):
            return []
        matches: list[Credential] = []
        for item in self.list_credentials(include_deleted=True):
            if exclude_id is not None and item.id == exclude_id:
                continue
            candidate = (item.title.strip().lower(), item.username.strip().lower(), normalize_site(item.website))
            exact = candidate == target
            strong_partial = bool(target[1]) and bool(target[2]) and candidate[1] == target[1] and candidate[2] == target[2]
            title_user = bool(target[0]) and bool(target[1]) and candidate[0] == target[0] and candidate[1] == target[1]
            if exact or strong_partial or title_user:
                matches.append(item)
        return matches

    def add_credential(self, *, title: str, username: str, password: str, category: str, tags: str, notes: str, website: str, is_favorite: bool) -> int:
        if not title.strip() or not username.strip() or not password:
            raise ValueError('Title, username, and password are required.')
        clean = {
            'title': title.strip(),
            'username': username.strip(),
            'password': password,
            'category': category.strip() or 'General',
            'tags': tags.strip(),
            'notes': notes.strip(),
            'website': website.strip(),
        }
        encrypted = self._encrypt_fields(**clean)
        now = utc_now_iso()

        def _rewrite_with_row_aad(credential_id: int) -> tuple[str, ...]:
            aad_encrypted = self._encrypt_fields(**clean, credential_id=credential_id)
            return (*aad_encrypted, now, 1 if is_favorite else 0, credential_id)

        credential_id = self.db.insert_credential_transactional(
            (*encrypted, now, now, None, 1 if is_favorite else 0, 0, 0),
            _rewrite_with_row_aad,
        )
        self._invalidate_snapshot()
        self.add_log('Credential Added', f'Added {self._log_target(credential_id=credential_id)}.')
        return credential_id

    def update_credential(self, credential_id: int, *, title: str, username: str, password: str, category: str, tags: str, notes: str, website: str, is_favorite: bool) -> None:
        current = self.get_credential(credential_id)
        if not current:
            raise ValueError('Credential not found.')
        if not title.strip() or not username.strip() or not password:
            raise ValueError('Title, username, and password are required.')
        if current.password != password:
            key = self.require_key()
            nonce, cipher = encrypt_text(current.password, key, aad=self._history_aad(credential_id))
            self.db.add_history(credential_id, nonce, cipher, utc_now_iso())
        encrypted = self._encrypt_fields(
            title=title.strip(),
            username=username.strip(),
            password=password,
            category=category.strip() or 'General',
            tags=tags.strip(),
            notes=notes.strip(),
            website=website.strip(),
            credential_id=credential_id,
        )
        updated = utc_now_iso()
        self.db.update_credential(credential_id, (*encrypted, updated, 1 if is_favorite else 0, credential_id))
        self._invalidate_snapshot()
        self.add_log('Credential Updated', f'Updated {self._log_target(title.strip(), credential_id=credential_id)}.')

    def _row_to_credential(self, row) -> Credential:
        key = self.require_key()
        return Credential(
            id=row['id'],
            title=self._decrypt_field(row, 'title', key),
            username=self._decrypt_field(row, 'username', key),
            password=self._decrypt_field(row, 'password', key),
            category=self._decrypt_field(row, 'category', key),
            tags=self._decrypt_field(row, 'tags', key),
            notes=self._decrypt_field(row, 'notes', key),
            website=self._decrypt_field(row, 'website', key),
            created_at=row['created_at'],
            updated_at=row['updated_at'],
            deleted_at=row['deleted_at'],
            is_favorite=bool(row['is_favorite']),
            copy_count=int(row['copy_count']),
            view_count=int(row['view_count']),
        )

    def list_credentials(self, *, include_deleted: bool = False, deleted_only: bool = False) -> list[Credential]:
        return [self._row_to_credential(row) for row in self.db.fetch_credentials(include_deleted=include_deleted, deleted_only=deleted_only)]

    def get_credential(self, credential_id: int) -> Credential | None:
        row = self.db.fetch_credential_row(credential_id)
        return self._row_to_credential(row) if row else None

    def move_to_trash(self, credential_id: int) -> None:
        item = self.get_credential(credential_id)
        if not item:
            return
        self.db.soft_delete(credential_id, utc_now_iso())
        self._invalidate_snapshot()
        self.add_log('Moved to Trash', f'Moved {self._log_target(item.title, credential_id=credential_id)} to Trash.')

    def restore_from_trash(self, credential_id: int) -> None:
        item = self.get_credential(credential_id)
        title = item.title if item else f'Credential #{credential_id}'
        self.db.restore(credential_id)
        self._invalidate_snapshot()
        self.add_log('Restored', f'Restored {self._log_target(title, credential_id=credential_id)} from Trash.')

    def permanent_delete(self, credential_id: int) -> None:
        item = self.get_credential(credential_id)
        title = item.title if item else f'Credential #{credential_id}'
        self.create_safety_snapshot('permanent delete', fail_silent=True)
        self.db.permanent_delete(credential_id)
        self._invalidate_snapshot()
        self.add_log('Permanent Delete', f'Permanently deleted {self._log_target(title, credential_id=credential_id)}.', severity='warning')

    def purge_expired_trash(self, days: int = 7) -> int:
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).replace(microsecond=0).isoformat()
        purged = 0
        # Check first so we only create a snapshot when destructive purge is real.
        expired_rows = [row for row in self.db.fetch_credentials(deleted_only=True) if row['deleted_at'] and row['deleted_at'] <= cutoff]
        if expired_rows and not self.is_unlocked:
            return 0
        if expired_rows:
            self.create_safety_snapshot('trash purge', fail_silent=True)
            purged = self.db.purge_deleted_before(cutoff)
            self._invalidate_snapshot()
        if purged:
            self.add_log('Trash Purged', f'Purged {purged} expired item(s) from Trash.')
        return purged

    def change_master_password(self, current_password: str, new_password: str) -> None:
        if self.master_record is None:
            raise ValueError('Vault is not initialized.')
        self._validate_master_password_policy(new_password, self.owner_name)
        if current_password == new_password:
            raise ValueError('New master password must be different from the current password.')

        valid, current_key = verify_master_password(current_password, self.master_record)
        if not valid or current_key is None:
            self.add_log('Master Password Rotation Failed', 'Current master password verification failed.', severity='warning')
            raise ValueError('Current master password is incorrect.')

        self.create_safety_snapshot('master password rotation', fail_silent=True)

        preserved_owner_name = self.owner_name
        preserved_vault_name = self.vault_name

        credential_rows = self.db.fetch_credentials(include_deleted=True)
        decrypted_credentials: list[dict[str, Any]] = []
        decrypted_history: dict[int, list[dict[str, str]]] = {}

        for row in credential_rows:
            decrypted_credentials.append({
                'id': int(row['id']),
                'title': self._decrypt_field(row, 'title', current_key),
                'username': self._decrypt_field(row, 'username', current_key),
                'password': self._decrypt_field(row, 'password', current_key),
                'category': self._decrypt_field(row, 'category', current_key),
                'tags': self._decrypt_field(row, 'tags', current_key),
                'notes': self._decrypt_field(row, 'notes', current_key),
                'website': self._decrypt_field(row, 'website', current_key),
                'created_at': row['created_at'],
                'updated_at': row['updated_at'],
                'deleted_at': row['deleted_at'],
                'is_favorite': int(row['is_favorite']),
                'copy_count': int(row['copy_count']),
                'view_count': int(row['view_count']),
            })
            history_rows = self.db.fetch_all_history(int(row['id']))
            decrypted_history[int(row['id'])] = [
                {
                    'changed_at': hist['changed_at'],
                    'password': self._decrypt_history_password(hist, int(row['id']), current_key),
                }
                for hist in history_rows
            ]

        new_record = create_master_record(new_password)
        _is_valid, new_key = verify_master_password(new_password, new_record)
        if new_key is None:
            raise RuntimeError('Failed to derive the new master key.')

        rotated_at = utc_now_iso()
        with self.db.connect() as conn:
            conn.execute(
                "INSERT INTO app_meta(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                ('master_salt', new_record.salt_b64),
            )
            conn.execute(
                "INSERT INTO app_meta(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                ('master_verifier', new_record.verifier_b64),
            )
            conn.execute(
                "INSERT INTO app_meta(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                ('master_password_rotated_at', rotated_at),
            )
            for item in decrypted_credentials:
                encrypted = self._encrypt_fields_with_key(
                    new_key,
                    title=item['title'],
                    username=item['username'],
                    password=item['password'],
                    category=item['category'],
                    tags=item['tags'],
                    notes=item['notes'],
                    website=item['website'],
                    credential_id=item['id'],
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
                        created_at=?, updated_at=?, deleted_at=?,
                        is_favorite=?, copy_count=?, view_count=?
                    WHERE id=?
                    """,
                    (*encrypted, item['created_at'], item['updated_at'], item['deleted_at'], item['is_favorite'], item['copy_count'], item['view_count'], item['id']),
                )
            conn.execute('DELETE FROM credential_history')
            for credential_id, history_items in decrypted_history.items():
                for history_item in history_items:
                    nonce, cipher = encrypt_text(history_item['password'], new_key, aad=self._history_aad(credential_id))
                    conn.execute(
                        'INSERT INTO credential_history(credential_id, password_nonce, password_cipher, changed_at) VALUES (?, ?, ?, ?)',
                        (credential_id, nonce, cipher, history_item['changed_at']),
                    )
            conn.commit()

        self.master_record = new_record
        self._key = new_key
        self._encrypt_sensitive_meta(new_key, 'owner_name', preserved_owner_name)
        self._encrypt_sensitive_meta(new_key, 'vault_name', preserved_vault_name)
        self._clear_unlock_guard_state()
        self.last_unlock_message = 'Master password changed successfully.'
        self._invalidate_snapshot()
        self.db.set_meta('safety_snapshots_invalidated_at', rotated_at)
        self.create_safety_snapshot('post master password rotation baseline', fail_silent=True)
        self.add_log(
            'Master Password Changed',
            'Re-encrypted the vault with a new master password and created a fresh post-rotation safety snapshot. Older local safety snapshots may require the previous master key; encrypted backups remain the portable restore option.',
            severity='success',
        )


    def _decrypt_history_password(self, row: Any, credential_id: int, key: bytes) -> str:
        for aad in self._history_aad_options(credential_id):
            try:
                return decrypt_text(row['password_nonce'], row['password_cipher'], key, aad=aad)
            except Exception:
                continue
        raise ValueError(f'Unable to decrypt password history for credential #{credential_id}.')

    def get_password_history(self, credential_id: int, *, include_all: bool = False) -> list[dict[str, str]]:
        key = self.require_key()
        history: list[dict[str, str]] = []
        history_rows = self.db.fetch_all_history(credential_id) if include_all else self.db.fetch_recent_history(credential_id)
        for row in history_rows:
            history.append({
                'changed_at': row['changed_at'],
                'password': self._decrypt_history_password(row, credential_id, key),
            })
        return history

    def record_copy(self, credential_id: int, field_name: str) -> None:
        self.db.bump_copy_count(credential_id)
        self._invalidate_snapshot()
        self.add_log('Copied Secret', f'Copied {field_name} for {self._log_target(credential_id=credential_id)}.')

    def record_view(self, credential_id: int) -> None:
        self.db.bump_view_count(credential_id)
        self._invalidate_snapshot()
        self.add_log('Secret Revealed', f'Revealed password for {self._log_target(credential_id=credential_id)}.')



    def _sanitize_audit_details(self, details: str) -> str:
        if self.get_setting('privacy_mode_logs', '1') != '1':
            return str(details)
        text = str(details)
        text = re.sub(r'[A-Za-z]:\\[^\n|]+', '[redacted-path]', text)
        text = re.sub(r'(?<!\w)/(?:[^\s|]+/)+[^\s|]+', '[redacted-path]', text)
        text = re.sub(r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}', '[redacted-email]', text)
        return text

    def add_log(self, action: str, details: str, severity: str = 'info') -> None:
        self.db.add_log(utc_now_iso(), action, self._sanitize_audit_details(details), severity)

    def get_logs(self, limit: int = 250) -> list[dict[str, str]]:
        return [dict(row) for row in self.db.fetch_logs(limit)]

    def purge_old_activity_logs(self, days: int | None = None) -> int:
        if days is None:
            try:
                days = int(self.get_setting('activity_retention_days', '365') or '365')
            except (TypeError, ValueError):
                days = 365
        days = max(1, int(days))
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).replace(microsecond=0).isoformat()
        deleted = self.db.purge_logs_before(cutoff)
        if deleted:
            self.add_log('Activity Retention Purge', f'Purged {deleted} audit event(s) older than {days} day(s).')
        return deleted

    def get_schema_version(self) -> int:
        return self.db.get_schema_version()

    def get_migration_history(self) -> list[dict[str, str]]:
        return [dict(row) for row in self.db.list_migrations()]









