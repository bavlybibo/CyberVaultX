from __future__ import annotations

APP_NAME = "CyberVault X"
VAULT_DB_FILENAME = "vault.db"
DEFAULT_THEME_ACCENT = "Cyan"
DEFAULT_AUTO_LOCK_MINUTES = 3
DEFAULT_CLIPBOARD_CLEAR_SECONDS = 15
MIN_MASTER_PASSWORD_LENGTH = 12
MIN_BACKUP_PASSPHRASE_LENGTH = 14
SUPPORTED_REPORT_FORMATS = (".html", ".json", ".txt")
SEVERITY_ORDER = {"Low": 1, "Moderate": 2, "Medium": 2, "High": 3, "Critical": 4}
SAFE_LOG_REDACTIONS = {
    "password": "[redacted-secret]",
    "master_password": "[redacted-secret]",
    "token": "[redacted-token]",
    "secret": "[redacted-secret]",
}
