from __future__ import annotations

from .breach_db import breach_db_size
from .manager import Credential, VaultManager
from .ui_helpers import normalize_http_url, safe_cache_name, safe_favicon_host

# Centralized dark design tokens.  Keep the legacy names because the UI
# modules import them directly, but make the palette more layered and readable.
APP_BG = '#050A14'
SIDEBAR_BG = '#060C16'
PANEL_BG = '#071426'
CARD_BG = '#0B1B2E'
CARD_BG_2 = '#102A46'
SURFACE_1 = CARD_BG
SURFACE_2 = CARD_BG_2
SURFACE_3 = '#163352'
INPUT_BG = '#06111F'
INPUT_BORDER = '#1E5C8E'
TEXT = '#F5FAFF'
SUBTEXT = '#B8CAE6'
MUTED = '#7E91AD'
SUCCESS = '#29F3B2'
WARNING = '#FFB84D'
DANGER = '#FF4D72'
INFO = '#31D8FF'
SHADOW = '#010511'
BORDER = '#183C61'
BORDER_SOFT = '#102B46'
PANEL_DEEP = '#050C18'
GLASS = '#0C2138'
HOVER = '#183F66'
ROW_ALT = '#0A1A2C'

ACCENTS = {
    'Cyan': '#31D8FF',
    'Blue': '#2377FF',
    'Emerald': '#29F3B2',
    'Purple': '#A855F7',
    'Amber': '#FFB84D',
}

PAGE_COLORS = {
    'dashboard': '#49D5FF',
    'vault': '#6B8DFF',
    'security': '#FFB84D',
    'ai_guardian': '#A97CFF',
    'reports': '#38D39F',
    'backup_recovery': '#FBBF24',
    'proof': '#38D39F',
    'generator': '#34D399',
    'trash': '#FF6B84',
    'activity': '#63B3FF',
    'settings': '#C084FC',
    'system_health': '#37D39A',
    'about': '#7DD3FC',
}

PAGE_CONTEXT = {
    'dashboard': ('Command View', 'Start here: read posture, spot the next fix, and jump into the right workflow.'),
    'vault': ('Credential Workspace', 'Edit one credential at a time: site first, then password, then save or tune.'),
    'security': ('Risk Review', 'This page is for triage: highest-risk items first, then generate replacements.'),
    'ai_guardian': ('AI Plan', 'Use this page when you want an explainable action plan, not raw data tables.'),
    'reports': ('Reports Workspace', 'Preview, export, and verify delivery evidence without exposing secrets by accident.'),
    'backup_recovery': ('Backup / Recovery', 'Create encrypted backups, preview restores, and recover from safety snapshots.'),
    'proof': ('Evidence Integrity', 'Run proof checks and package verification for academic and demo delivery.'),
    'generator': ('Password Analyzer', 'Analyze passwords, generate replacements, and match them to a site profile.'),
    'trash': ('Recovery Zone', 'Restore recently deleted items or purge them securely when you are sure.'),
    'activity': ('Audit Trail', 'Review unlocks, copies, updates, and backup events in one timeline.'),
    'settings': ('Comfort & Security', 'Customize colors, auto-lock, clipboard timing, and privacy defaults.'),
    'system_health': ('System Health', 'Check dependencies, local files, offline dataset, and demo-readiness before presenting.'),
    'about': ('Product Story', 'Read local-first guarantees, privacy model, release notes, and security posture.'),
}

LEVEL_COLORS = {
    'info': INFO,
    'success': SUCCESS,
    'warning': WARNING,
    'danger': DANGER,
}

SEVERITY_COLORS = {
    'Critical': DANGER,
    'High': WARNING,
    'Moderate': INFO,
    'Low': SUCCESS,
}

RISK_TAG_BG = {
    'Critical': '#351522',
    'High': '#332710',
    'Moderate': '#112A3D',
    'Low': '#0F2B22',
}

CATEGORIES = [
    'General', 'Email', 'Work', 'Social', 'Banking', 'Shopping', 'Entertainment', 'Education', 'Servers', 'Crypto'
]

PAGE_META = {
    'dashboard': ('Dashboard', 'Health score, recommendations, and unlock activity at a glance.'),
    'vault': ('Vault', 'Store, reveal, rotate, and manage encrypted credentials locally.'),
    'security': ('Security Center', 'Review breached, weak, reused, duplicate, and stale credentials.'),
    'ai_guardian': ('AI-style Local Security Coach', 'Generate a privacy-preserving smart security plan from local vault telemetry.'),
    'reports': ('Reports', 'Generate executive, privacy-safe, and signed report packages with safe previews.'),
    'backup_recovery': ('Backup / Recovery', 'Create encrypted backups, preview restore impact, and recover safely.'),
    'proof': ('Proof Center', 'Verify encryption posture, audit integrity, and report-package hashes.'),
    'generator': ('Password Analyzer', 'Create high-entropy passwords with instant strength analysis.'),
    'trash': ('Trash', 'Soft-deleted credentials are retained for 7 days before purge.'),
    'activity': ('Activity', 'Audit trail for authentication, copy events, updates, and backups.'),
    'settings': ('Settings', 'Accent theme, auto-lock, secure clipboard, and encrypted backup controls.'),
    'system_health': ('System Health', 'Dependency check, release readiness, and local runtime diagnostics.'),
    'about': ('About', 'Product information, security model, release notes, and local-first guarantees.'),
}


PAGE_ICONS = {
    'dashboard': '◈',
    'vault': '◉',
    'security': '◆',
    'ai_guardian': '✧',
    'reports': '▤',
    'backup_recovery': '⇄',
    'proof': '▣',
    'generator': '✦',
    'trash': '⌫',
    'activity': '◌',
    'settings': '⚙',
    'system_health': '✓',
    'about': 'ⓘ',
}

ACTION_ICONS = {
    'Add Credential': '+',
    'Export Backup': '⇪',
    'Lock': '⏻',
    'Panic Lock': '!',
    'Search': '⌕',
    'Clear': '×',
    'Create Assessment Workspace': '◫',
    'Workspace Setup': '◫',
    'Focus Mode': '▣',
    'Privacy Report': '⇪',
    'Run Proof Checks': '✓',
    'Verify Package': '▤',
    'Preview Backup': '⇩',
    'Import Backup': '⇩',
    'Restore Snapshot': '↺',
    'Open Reports': '▤',
    'Open Backup': '⇄',
    'Export Report': '⇪',
    'Report Package': '▤',
    'Import CSV': '⇩',
    'Full-Screen Focus Mode': '▣',
    'Quick Tour': '❖',
    'Refresh Findings': '↻',
    'Generate Smart Security Plan': '✧',
    'Export AI Summary': '⇪',
    'Generate': '✦',
    'Copy': '⎘',
    'Use in Editor': '↳',
    'Restore': '↺',
    'Delete Forever': '✖',
    'Purge Expired': '⌫',
}



