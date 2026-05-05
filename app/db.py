from __future__ import annotations

import sqlite3
import json
import hashlib
from contextlib import contextmanager
import os
from pathlib import Path

SCHEMA_VERSION = 9


class VaultDatabase:
    def __init__(self, db_path: str | Path) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    @contextmanager
    def connect(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute('PRAGMA foreign_keys=ON')
        conn.execute('PRAGMA secure_delete=ON')
        conn.execute('PRAGMA busy_timeout=5000')
        try:
            yield conn
        finally:
            conn.close()

    def _initialize(self) -> None:
        with self.connect() as conn:
            conn.execute('PRAGMA journal_mode=WAL')
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS app_meta (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS credentials (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    title_nonce TEXT NOT NULL,
                    title_cipher TEXT NOT NULL,
                    username_nonce TEXT NOT NULL,
                    username_cipher TEXT NOT NULL,
                    password_nonce TEXT NOT NULL,
                    password_cipher TEXT NOT NULL,
                    category_nonce TEXT NOT NULL,
                    category_cipher TEXT NOT NULL,
                    tags_nonce TEXT NOT NULL,
                    tags_cipher TEXT NOT NULL,
                    notes_nonce TEXT NOT NULL,
                    notes_cipher TEXT NOT NULL,
                    website_nonce TEXT NOT NULL,
                    website_cipher TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    deleted_at TEXT,
                    is_favorite INTEGER NOT NULL DEFAULT 0,
                    copy_count INTEGER NOT NULL DEFAULT 0,
                    view_count INTEGER NOT NULL DEFAULT 0
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS credential_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    credential_id INTEGER NOT NULL,
                    password_nonce TEXT NOT NULL,
                    password_cipher TEXT NOT NULL,
                    changed_at TEXT NOT NULL,
                    FOREIGN KEY (credential_id) REFERENCES credentials(id) ON DELETE CASCADE
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS activity_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    action TEXT NOT NULL,
                    details TEXT NOT NULL,
                    severity TEXT NOT NULL DEFAULT 'info',
                    prev_hash TEXT NOT NULL DEFAULT '',
                    event_hash TEXT NOT NULL DEFAULT ''
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS schema_migrations (
                    version INTEGER PRIMARY KEY,
                    applied_at TEXT NOT NULL,
                    description TEXT NOT NULL
                )
                """
            )
            self._apply_migrations(conn)
            conn.commit()
        try:
            os.chmod(self.db_path, 0o600)
        except Exception:
            pass

    def _apply_migrations(self, conn: sqlite3.Connection) -> None:
        current_raw = conn.execute("SELECT value FROM app_meta WHERE key='schema_version'").fetchone()
        try:
            current = int(current_raw['value']) if current_raw else 0
        except Exception:
            current = 0

        if current < 1:
            current = 1
        if current < 2:
            # Version 2 formalizes runtime security metadata and privacy-aware settings.
            defaults = {
                'unlock_failed_attempts': '0',
                'unlock_blocked_until': '',
                'privacy_mode_logs': '1',
                'backup_format_version': '3',
            }
            for key, value in defaults.items():
                conn.execute(
                    "INSERT INTO app_meta(key, value) VALUES(?, ?) ON CONFLICT(key) DO NOTHING",
                    (key, value),
                )
            current = 2
        if current < 3:
            # Version 3 adds AI Guardian snapshot state and report privacy levels.
            defaults = {
                'ai_last_snapshot_at': '',
                'privacy_report_level': 'minimal',
                'safety_snapshot_format': 'CyberVaultSafetySnapshot/v1',
            }
            for key, value in defaults.items():
                conn.execute(
                    "INSERT INTO app_meta(key, value) VALUES(?, ?) ON CONFLICT(key) DO NOTHING",
                    (key, value),
                )
            self._record_migration(conn, 3, 'AI Guardian snapshot state and privacy-safe report defaults')
            current = 3
        if current < 4:
            # Version 4 makes report privacy/export behavior explicit and tracks safety snapshot restore support.
            defaults = {
                'default_report_privacy_level': 'analyst',
                'last_safety_snapshot_path': '',
                'last_safety_snapshot_sha256': '',
                'printable_report_css': '1',
                'audit_export_format': 'html',
            }
            for key, value in defaults.items():
                conn.execute(
                    "INSERT INTO app_meta(key, value) VALUES(?, ?) ON CONFLICT(key) DO NOTHING",
                    (key, value),
                )
            self._record_migration(conn, 4, 'Report privacy defaults, printable reports, and safety snapshot restore metadata')
            current = 4
        if current < 5:
            # Version 5 formalizes release packaging metadata and audit dashboard defaults.
            defaults = {
                'release_channel': 'desktop-local',
                'activity_retention_days': '365',
                'fix_simulator_default': 'weak,reused,old,metadata,trash,backup',
            }
            for key, value in defaults.items():
                conn.execute(
                    "INSERT INTO app_meta(key, value) VALUES(?, ?) ON CONFLICT(key) DO NOTHING",
                    (key, value),
                )
            self._record_migration(conn, 5, 'Product hardening defaults for release packaging, audit retention, and fix simulator')
            current = 5
        if current < 6:
            # Version 6 adds release branding, report package manifest support, and AI remediation progress.
            defaults = {
                'ai_remediation_log_json': '[]',
                'report_package_format': 'CyberVaultReportPackage/v1',
                'branding_assets_version': '1',
            }
            for key, value in defaults.items():
                conn.execute(
                    "INSERT INTO app_meta(key, value) VALUES(?, ?) ON CONFLICT(key) DO NOTHING",
                    (key, value),
                )
            self._record_migration(conn, 6, 'Branding assets, report package manifests, and AI remediation progress tracking')
            current = 6
        if current < 7:
            # Version 7 hardens local privacy defaults and separates AI baseline capture from UI refresh.
            defaults = {
                'ai_snapshot_persist_mode': 'explicit',
                'favicon_lookup_private_blocklist': '1',
                'sensitive_meta_encrypted_v1': '0',
                'credential_aad_strict_after_migration': '1',
            }
            for key, value in defaults.items():
                conn.execute(
                    "INSERT INTO app_meta(key, value) VALUES(?, ?) ON CONFLICT(key) DO NOTHING",
                    (key, value),
                )
            self._record_migration(conn, 7, 'Explicit AI baselines, hardened favicon privacy, and stricter AAD metadata')
            current = 7
        if current < 8:
            # Version 8 adds tamper-evident audit hash chaining and security proof center metadata.
            existing_cols = {row['name'] for row in conn.execute("PRAGMA table_info(activity_log)").fetchall()}
            if 'prev_hash' not in existing_cols:
                conn.execute("ALTER TABLE activity_log ADD COLUMN prev_hash TEXT NOT NULL DEFAULT ''")
            if 'event_hash' not in existing_cols:
                conn.execute("ALTER TABLE activity_log ADD COLUMN event_hash TEXT NOT NULL DEFAULT ''")
            self._backfill_audit_hash_chain(conn)
            defaults = {
                'security_proof_center_enabled': '1',
                'report_package_verifier_enabled': '1',
                'backup_restore_preview_enabled': '1',
            }
            for key, value in defaults.items():
                conn.execute(
                    "INSERT INTO app_meta(key, value) VALUES(?, ?) ON CONFLICT(key) DO NOTHING",
                    (key, value),
                )
            self._record_migration(conn, 8, 'Tamper-evident audit chain, Security Proof Center, and package verification support')
            current = 8
        if current < 9:
            # Version 9 adds local report-package signing and product intelligence helpers.
            defaults = {
                'report_package_format': 'CyberVaultReportPackage/v3-signed',
                'report_signing_key_fingerprint': '',
                'audit_head_export_enabled': '1',
                'privacy_redaction_preview_enabled': '1',
                'backup_restore_diff_preview_enabled': '1',
                'security_proof_center_v3_enabled': '1',
            }
            for key, value in defaults.items():
                conn.execute(
                    "INSERT INTO app_meta(key, value) VALUES(?, ?) ON CONFLICT(key) DO NOTHING",
                    (key, value),
                )
            self._record_migration(conn, 9, 'Signed report packages, audit head export, restore diff preview, and Security Proof Center v3')
            current = 9
        conn.execute(
            "INSERT INTO app_meta(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            ('schema_version', str(current)),
        )


    def _audit_event_hash(self, event_id: int, timestamp: str, action: str, details: str, severity: str, prev_hash: str) -> str:
        material = f"{int(event_id)}|{timestamp}|{action}|{details}|{severity}|{prev_hash}"
        return hashlib.sha256(material.encode('utf-8')).hexdigest()

    def _backfill_audit_hash_chain(self, conn: sqlite3.Connection) -> None:
        rows = conn.execute('SELECT id, timestamp, action, details, severity, prev_hash, event_hash FROM activity_log ORDER BY id ASC').fetchall()
        prev_hash = '0' * 64
        for row in rows:
            expected_prev = prev_hash
            event_hash = self._audit_event_hash(int(row['id']), str(row['timestamp']), str(row['action']), str(row['details']), str(row['severity']), expected_prev)
            if not row['event_hash'] or not row['prev_hash']:
                conn.execute('UPDATE activity_log SET prev_hash=?, event_hash=? WHERE id=?', (expected_prev, event_hash, int(row['id'])))
            prev_hash = event_hash

    def _rebase_audit_hash_chain(self, conn: sqlite3.Connection) -> str:
        """Rewrite retained audit rows into a valid local hash chain after retention compaction."""
        rows = conn.execute(
            'SELECT id, timestamp, action, details, severity FROM activity_log ORDER BY id ASC'
        ).fetchall()
        prev_hash = '0' * 64
        for row in rows:
            event_hash = self._audit_event_hash(
                int(row['id']),
                str(row['timestamp']),
                str(row['action']),
                str(row['details']),
                str(row['severity']),
                prev_hash,
            )
            conn.execute('UPDATE activity_log SET prev_hash=?, event_hash=? WHERE id=?', (prev_hash, event_hash, int(row['id'])))
            prev_hash = event_hash
        return prev_hash

    def _record_migration(self, conn: sqlite3.Connection, version: int, description: str) -> None:
        conn.execute(
            "INSERT OR IGNORE INTO schema_migrations(version, applied_at, description) VALUES(?, datetime('now'), ?)",
            (int(version), description),
        )

    def list_migrations(self):
        with self.connect() as conn:
            return list(conn.execute('SELECT version, applied_at, description FROM schema_migrations ORDER BY version').fetchall())

    def get_meta(self, key: str) -> str | None:
        with self.connect() as conn:
            row = conn.execute('SELECT value FROM app_meta WHERE key=?', (key,)).fetchone()
            return row['value'] if row else None

    def set_meta(self, key: str, value: str) -> None:
        with self.connect() as conn:
            conn.execute(
                'INSERT INTO app_meta(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value',
                (key, value),
            )
            conn.commit()

    def delete_meta(self, key: str) -> None:
        with self.connect() as conn:
            conn.execute('DELETE FROM app_meta WHERE key=?', (key,))
            conn.commit()

    def get_schema_version(self) -> int:
        try:
            return int(self.get_meta('schema_version') or '0')
        except (TypeError, ValueError):
            return 0

    def insert_credential(self, values: tuple) -> int:
        with self.connect() as conn:
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
                values,
            )
            conn.commit()
            return int(cur.lastrowid)

    def insert_credential_transactional(self, initial_values: tuple, rewrite_values_factory) -> int:
        """Insert a credential and rewrite it before commit.

        New rows need their SQLite id before credential-field AAD can be derived.
        This helper guarantees the temporary pre-AAD row is never committed: if the
        rewrite step fails, closing the connection rolls back the entire insert.
        """
        with self.connect() as conn:
            conn.execute('BEGIN IMMEDIATE')
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
                initial_values,
            )
            credential_id = int(cur.lastrowid)
            rewrite_values = rewrite_values_factory(credential_id)
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
                rewrite_values,
            )
            conn.commit()
            return credential_id

    def update_credential(self, credential_id: int, values: tuple) -> None:
        with self.connect() as conn:
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
                values,
            )
            conn.commit()

    def fetch_credentials(self, *, include_deleted: bool = False, deleted_only: bool = False):
        query = 'SELECT * FROM credentials'
        if deleted_only:
            query += ' WHERE deleted_at IS NOT NULL'
        elif not include_deleted:
            query += ' WHERE deleted_at IS NULL'
        query += ' ORDER BY is_favorite DESC, updated_at DESC, id DESC'
        with self.connect() as conn:
            return list(conn.execute(query).fetchall())

    def fetch_credential_row(self, credential_id: int):
        with self.connect() as conn:
            return conn.execute('SELECT * FROM credentials WHERE id=?', (credential_id,)).fetchone()

    def soft_delete(self, credential_id: int, deleted_at: str) -> None:
        with self.connect() as conn:
            conn.execute('UPDATE credentials SET deleted_at=? WHERE id=?', (deleted_at, credential_id))
            conn.commit()

    def restore(self, credential_id: int) -> None:
        with self.connect() as conn:
            conn.execute('UPDATE credentials SET deleted_at=NULL WHERE id=?', (credential_id,))
            conn.commit()

    def permanent_delete(self, credential_id: int) -> None:
        with self.connect() as conn:
            conn.execute('DELETE FROM credential_history WHERE credential_id=?', (credential_id,))
            conn.execute('DELETE FROM credentials WHERE id=?', (credential_id,))
            conn.commit()
        self.optimize_storage()

    def purge_deleted_before(self, cutoff_iso: str) -> int:
        with self.connect() as conn:
            rows = conn.execute(
                'SELECT id FROM credentials WHERE deleted_at IS NOT NULL AND deleted_at <= ?',
                (cutoff_iso,),
            ).fetchall()
            ids = [row['id'] for row in rows]
            for cid in ids:
                conn.execute('DELETE FROM credential_history WHERE credential_id=?', (cid,))
                conn.execute('DELETE FROM credentials WHERE id=?', (cid,))
            conn.commit()
        if ids:
            self.optimize_storage()
        return len(ids)

    def set_updated_at(self, credential_id: int, updated_at: str) -> None:
        with self.connect() as conn:
            conn.execute('UPDATE credentials SET updated_at=? WHERE id=?', (updated_at, credential_id))
            conn.commit()

    def add_history(self, credential_id: int, password_nonce: str, password_cipher: str, changed_at: str) -> None:
        with self.connect() as conn:
            conn.execute(
                'INSERT INTO credential_history(credential_id, password_nonce, password_cipher, changed_at) VALUES (?, ?, ?, ?)',
                (credential_id, password_nonce, password_cipher, changed_at),
            )
            conn.commit()

    def fetch_recent_history(self, credential_id: int, limit: int = 5):
        with self.connect() as conn:
            return list(
                conn.execute(
                    'SELECT * FROM credential_history WHERE credential_id=? ORDER BY changed_at DESC, id DESC LIMIT ?',
                    (credential_id, int(max(1, limit))),
                ).fetchall()
            )

    def fetch_all_history(self, credential_id: int):
        with self.connect() as conn:
            return list(
                conn.execute(
                    'SELECT * FROM credential_history WHERE credential_id=? ORDER BY changed_at DESC, id DESC',
                    (credential_id,),
                ).fetchall()
            )

    def fetch_history(self, credential_id: int):
        return self.fetch_recent_history(credential_id, limit=5)

    def bump_copy_count(self, credential_id: int) -> None:
        with self.connect() as conn:
            conn.execute('UPDATE credentials SET copy_count = copy_count + 1 WHERE id=?', (credential_id,))
            conn.commit()

    def bump_view_count(self, credential_id: int) -> None:
        with self.connect() as conn:
            conn.execute('UPDATE credentials SET view_count = view_count + 1 WHERE id=?', (credential_id,))
            conn.commit()

    def add_log(self, timestamp: str, action: str, details: str, severity: str = 'info') -> None:
        with self.connect() as conn:
            last = conn.execute(
                "SELECT event_hash FROM activity_log WHERE event_hash != '' ORDER BY id DESC LIMIT 1"
            ).fetchone()
            prev_hash = str(last['event_hash']) if last else '0' * 64
            cur = conn.execute(
                'INSERT INTO activity_log(timestamp, action, details, severity, prev_hash, event_hash) VALUES (?, ?, ?, ?, ?, ?)',
                (timestamp, action, details, severity, prev_hash, ''),
            )
            event_id = int(cur.lastrowid)
            event_hash = self._audit_event_hash(event_id, timestamp, action, details, severity, prev_hash)
            conn.execute('UPDATE activity_log SET event_hash=? WHERE id=?', (event_hash, event_id))
            conn.commit()

    def fetch_logs(self, limit: int = 250):
        with self.connect() as conn:
            return list(conn.execute('SELECT * FROM activity_log ORDER BY id DESC LIMIT ?', (limit,)).fetchall())

    def purge_logs_before(self, cutoff_iso: str) -> int:
        with self.connect() as conn:
            conn.execute('BEGIN IMMEDIATE')
            rows_to_delete = conn.execute(
                'SELECT id, timestamp, action, details, severity, prev_hash, event_hash FROM activity_log WHERE timestamp < ? ORDER BY id ASC',
                (cutoff_iso,),
            ).fetchall()
            if not rows_to_delete:
                conn.commit()
                return 0
            checkpoint_material = [dict(row) for row in rows_to_delete]
            checkpoint_hash = hashlib.sha256(
                json.dumps(checkpoint_material, sort_keys=True, default=str).encode('utf-8')
            ).hexdigest()
            cur = conn.execute('DELETE FROM activity_log WHERE timestamp < ?', (cutoff_iso,))
            deleted = int(cur.rowcount or 0)
            retained_head_hash = self._rebase_audit_hash_chain(conn)
            checkpoint = {
                'cutoff_iso': cutoff_iso,
                'deleted_events': deleted,
                'deleted_range': {
                    'first_id': int(rows_to_delete[0]['id']),
                    'last_id': int(rows_to_delete[-1]['id']),
                },
                'deleted_rows_sha256': checkpoint_hash,
                'retained_head_hash_after_rebase': retained_head_hash,
            }
            conn.execute(
                'INSERT INTO app_meta(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value',
                ('audit_last_retention_checkpoint', json.dumps(checkpoint, sort_keys=True)),
            )
            conn.commit()
            return deleted

    def optimize_storage(self) -> None:
        with self.connect() as conn:
            conn.execute('PRAGMA wal_checkpoint(TRUNCATE)')
            conn.execute('VACUUM')
            conn.commit()
