from __future__ import annotations

from typing import Iterable

CRITICAL_CATEGORIES = {'Email', 'Banking', 'Work', 'Servers', 'Crypto'}
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
    high_value = str(category or 'General') in CRITICAL_CATEGORIES

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
