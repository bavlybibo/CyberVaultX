from __future__ import annotations

from typing import Any

from ..core.constants import DEFAULT_AUTO_LOCK_MINUTES, DEFAULT_CLIPBOARD_CLEAR_SECONDS, DEFAULT_THEME_ACCENT


class SettingsService:
    def __init__(self, manager: Any) -> None:
        self.manager = manager

    def get_security_preferences(self) -> dict[str, Any]:
        return {
            "theme_accent": self.manager.get_setting("theme_accent", DEFAULT_THEME_ACCENT),
            "auto_lock_minutes": self.manager.get_setting_int("auto_lock_minutes", DEFAULT_AUTO_LOCK_MINUTES),
            "clipboard_clear_seconds": self.manager.get_setting_int("clipboard_clear_seconds", DEFAULT_CLIPBOARD_CLEAR_SECONDS),
            "privacy_mode_logs": self.manager.get_setting("privacy_mode_logs", "1") == "1",
            "default_report_privacy_level": self.manager.get_setting("default_report_privacy_level", "analyst"),
        }

    def save_security_preferences(self, *, auto_lock_minutes: int, clipboard_clear_seconds: int, theme_accent: str) -> None:
        self.manager.set_setting_int("auto_lock_minutes", max(1, min(120, int(auto_lock_minutes))))
        self.manager.set_setting_int("clipboard_clear_seconds", max(5, min(120, int(clipboard_clear_seconds))))
        self.manager.set_setting("theme_accent", theme_accent.strip() or DEFAULT_THEME_ACCENT)
