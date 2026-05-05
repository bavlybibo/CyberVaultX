from __future__ import annotations

from app.ui_shared import PAGE_COLORS, PAGE_CONTEXT, PAGE_ICONS, PAGE_META


def test_premium_ui_navigation_pages_are_registered() -> None:
    required_pages = {'reports', 'backup_recovery', 'generator', 'system_health'}
    assert required_pages.issubset(PAGE_META)
    assert required_pages.issubset(PAGE_CONTEXT)
    assert required_pages.issubset(PAGE_COLORS)
    assert required_pages.issubset(PAGE_ICONS)
    assert PAGE_META['reports'][0] == 'Reports'
    assert PAGE_META['backup_recovery'][0] == 'Backup / Recovery'
    assert PAGE_META['generator'][0] == 'Password Analyzer'


def test_premium_ui_labels_are_short_and_demo_ready() -> None:
    for title, subtitle in PAGE_META.values():
        assert len(title) <= 32
        assert len(subtitle) <= 110
    assert 'plaintext' not in PAGE_META['reports'][1].lower()
    assert 'preview' in PAGE_META['backup_recovery'][1].lower()
