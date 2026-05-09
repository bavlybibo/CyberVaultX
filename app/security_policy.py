from __future__ import annotations

from typing import Iterable

CRITICAL_CATEGORIES = {'Email', 'Banking', 'Work', 'Servers', 'Crypto'}
_HIGH_VALUE_CATEGORY_ALIASES = {
    'email': 'Email', 'mail': 'Email', 'identity': 'Email', 'idp': 'Email', 'sso': 'Email',
    'bank': 'Banking', 'banking': 'Banking', 'finance': 'Banking', 'financial': 'Banking', 'payments': 'Banking', 'payment': 'Banking',
    'crypto': 'Crypto', 'wallet': 'Crypto', 'web3': 'Crypto',
    'server': 'Servers', 'servers': 'Servers', 'infrastructure': 'Servers', 'infra': 'Servers', 'admin': 'Servers', 'cloud': 'Servers', 'network': 'Servers',
    'work': 'Work', 'business': 'Work', 'developer': 'Work', 'dev': 'Work', 'source code': 'Work', 'company': 'Work',
}


def normalize_category_name(category: str | None) -> str:
    """Return a stable display category without relying on exact UI casing."""
    raw = str(category or 'General').strip()
    if not raw:
        return 'General'
    key = raw.lower().replace('_', ' ').replace('-', ' ')
    key = ' '.join(key.split())
    if key in _HIGH_VALUE_CATEGORY_ALIASES:
        return _HIGH_VALUE_CATEGORY_ALIASES[key]
    for alias, canonical in _HIGH_VALUE_CATEGORY_ALIASES.items():
        if alias in key:
            return canonical
    return raw[:1].upper() + raw[1:]


def is_high_value_category(category: str | None) -> bool:
    return normalize_category_name(category) in CRITICAL_CATEGORIES
NO_MAJOR_ISSUES = {'No major issues detected.', 'No major issues detected'}


def mask_identifier(value: str) -> str:
    value = (value or '').strip()
    if not value:
        return ''
    if '@' in value:
        local, _, domain = value.partition('@')
        if not local:
            return f'***@{domain}'
        return f'{local[:1]}***@{domain}'
    return f'{value[:1]}***'


def normalize_issue_list(warnings: Iterable[str]) -> list[str]:
    issues: list[str] = []
    for warning in warnings:
        text = str(warning).strip()
        if not text or text in NO_MAJOR_ISSUES:
            continue
        if text not in issues:
            issues.append(text)
    return issues


def composite_risk_level(
    score: int,
    *,
    breached: bool = False,
    common_password: bool = False,
    reuse_count: int = 1,
    old_password: bool = False,
    category: str = 'General',
    issues: Iterable[str] | None = None,
) -> str:
    score = int(score or 0)
    reuse_count = int(reuse_count or 0)
    issue_text = ' '.join(str(item).lower() for item in (issues or []))
    high_value = is_high_value_category(category)

    if breached or common_password:
        return 'Critical'
    if score < 35:
        return 'Critical'
    if reuse_count > 1 and high_value:
        return 'Critical'
    if 'reused password' in issue_text and high_value:
        return 'Critical'

    if score < 55:
        return 'High'
    if reuse_count > 1:
        return 'High'
    if old_password and high_value:
        return 'High'
    if 'duplicate site' in issue_text and high_value:
        return 'High'
    if 'below inferred site-policy fit' in issue_text and high_value:
        return 'High'

    if score < 75:
        return 'Moderate'
    if old_password:
        return 'Moderate'
    if 'below inferred site-policy fit' in issue_text:
        return 'Moderate'
    if issue_text:
        if (
            'missing website' in issue_text
            or 'missing tags' in issue_text
            or 'username appears' in issue_text
            or 'duplicate site' in issue_text
        ):
            return 'Moderate'

    return 'Low'


def severity_for_risk(risk_level: str) -> str:
    return {
        'Critical': 'danger',
        'High': 'warning',
        'Moderate': 'watch',
        'Low': 'safe',
    }.get(str(risk_level), 'watch')


def privacy_safe_title(credential_id: int | str) -> str:
    return f'Credential #{credential_id}'


# Conservative export redaction used for audit/report text. It removes common
# local identifiers even when a log line came from a plugin, exception, or future
# feature outside the normal privacy-safe report payload. Minimal/standard export
# modes intentionally over-redact because audit/evidence packages must never
# leak raw notes, paths, tokens, usernames, or clipboard values.
import re

_EMAIL_RE = re.compile(r'(?<![\w.+-])([A-Za-z0-9._%+-]{1,64})@([A-Za-z0-9.-]+\.[A-Za-z]{2,})(?![\w.-])')
_WINDOWS_PATH_RE = re.compile(r'\b[A-Za-z]:(?:\\\\|\\|/)(?:(?![\s<>"|?*]).)+')
_POSIX_PATH_RE = re.compile(r'(?<!\w)/(?:home|Users|mnt|tmp|var|etc|opt|root|private|Volumes)/[^\s<>,;"\']+')
_SECRET_KV_RE = re.compile(
    r'(?ix)'
    r'((?:api[_-]?key|access[_-]?token|refresh[_-]?token|id[_-]?token|auth(?:orization)?|bearer|session(?:[_-]?id)?|jwt|token|secret|password|passphrase|clipboard|cookie)'
    r'\s*[=:]\s*)'
    r'(["\']?)[^\s<>,;"\']{4,}\2'
)
_LONG_SECRET_RE = re.compile(r'\b(?:[A-Za-z0-9+/]{32,}={0,2}|[A-Fa-f0-9]{32,}|sk-[A-Za-z0-9_-]{16,})\b')
_JWT_RE = re.compile(r'\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b')
_DOMAIN_RE = re.compile(r'\b(?:[A-Za-z0-9-]+\.)+(?:com|net|org|edu|gov|io|local|dev|app|cloud|example)\b', re.IGNORECASE)
_USERNAME_KV_RE = re.compile(r'(?i)\b((?:user(?:name)?|login|account)\s*[=:]\s*)([^\s<>,;"\']{3,})')
_STOPWORDS = {
    'about', 'after', 'before', 'credential', 'credentials', 'password', 'private',
    'secret', 'token', 'session', 'clipboard', 'value', 'notes', 'note', 'export',
    'report', 'backup', 'vault', 'created', 'updated', 'failed', 'warning', 'success',
}


def _redact_extra_values(value: str, extra_values: Iterable[str] | None) -> str:
    """Redact exact sensitive values plus conservative fragments.

    Exact matching alone is not enough for audit logs because a plugin/exception
    may log only part of a note or a JSON-escaped path. For privacy-safe exports,
    redacting fragments is safer than leaving a partial note behind.
    """
    output = value
    replacements: list[str] = []
    for raw in extra_values or []:
        raw_s = str(raw or '').strip()
        if len(raw_s) < 3:
            continue
        variants = {raw_s, raw_s.replace('\\', '\\\\')}
        replacements.extend(v for v in variants if len(v) >= 4)

        # Redact meaningful words from sensitive free-form values such as notes,
        # titles, usernames, and paths. This intentionally avoids tiny/common
        # tokens while still removing partial note fragments like "private note".
        words = [w for w in re.findall(r'[A-Za-z0-9_@.-]{4,}', raw_s) if len(w) >= 5]
        for word in words:
            lowered = word.lower().strip('._-')
            if lowered and lowered not in _STOPWORDS:
                replacements.append(word)
        if any(ch.isspace() for ch in raw_s):
            parts = [w for w in re.findall(r'[A-Za-z0-9_@.-]{4,}', raw_s) if len(w) >= 4]
            for size in range(2, min(5, len(parts)) + 1):
                for idx in range(0, len(parts) - size + 1):
                    phrase = ' '.join(parts[idx:idx + size])
                    if len(phrase) >= 8:
                        replacements.append(phrase)

    # Longer replacements first prevents short tokens from breaking longer ones.
    for needle in sorted(set(replacements), key=len, reverse=True):
        try:
            output = re.sub(re.escape(needle), '[redacted-value]', output, flags=re.IGNORECASE)
        except re.error:
            output = output.replace(needle, '[redacted-value]')
    return output


def universal_redact(text: str, *, level: str = 'standard', extra_values: Iterable[str] | None = None) -> str:
    """Redact sensitive values from logs and export text.

    Levels:
    - minimal/standard: redact local paths, emails, usernames, tokens, long
      secrets, sensitive key/value strings, and domains.
    - analyst: keep domains but still redact paths, emails, usernames, tokens,
      long secrets, and explicit sensitive values.
    - full: used only for private exports; explicit extra values are still
      redacted if supplied by the caller.
    """
    value = str(text or '')
    value = _redact_extra_values(value, extra_values)
    value = _SECRET_KV_RE.sub(lambda m: f"{m.group(1)}[redacted-secret]", value)
    value = _JWT_RE.sub('[redacted-token]', value)
    value = _WINDOWS_PATH_RE.sub('[local-path]', value)
    value = _POSIX_PATH_RE.sub('[local-path]', value)
    value = _EMAIL_RE.sub('[redacted-email]', value)
    value = _USERNAME_KV_RE.sub(lambda m: f"{m.group(1)}[redacted-identifier]", value)
    value = _LONG_SECRET_RE.sub('[redacted-token]', value)
    if level in {'minimal', 'standard'}:
        value = _DOMAIN_RE.sub('[domain-redacted]', value)
    return value
