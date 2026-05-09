from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any

from ..analyzer import (
    analyze_password,
    build_breach_intelligence,
    compute_dashboard,
    duplicate_counts,
    duplicate_password_counts,
    normalize_site,
    password_is_old,
)
from ..security_policy import composite_risk_level, normalize_issue_list, severity_for_risk
from ..site_policy import evaluate_password_fit


@dataclass(slots=True)
class VaultSnapshot:
    """Single decrypted analysis pass for UI/report/AI refreshes.

    The snapshot lives only in memory and is invalidated after every mutating
    vault operation. It prevents repeated decrypt/recalculate cycles across the
    dashboard, Security Center, AI-style Local Security Coach, and reports.
    """

    created_at: str
    metrics: dict[str, int]
    findings: list[dict[str, Any]]
    risk_distribution: dict[str, int]
    active_count: int
    trash_count: int


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _risk_distribution(findings: list[dict[str, Any]]) -> dict[str, int]:
    counts = {'Critical': 0, 'High': 0, 'Moderate': 0, 'Low': 0}
    for row in findings:
        risk = str(row.get('risk_level', 'Low'))
        if risk in counts:
            counts[risk] += 1
    return counts


def build_intelligence_for_entry(entry: Any, entries: list[Any]) -> dict[str, Any]:
    password_dups = duplicate_password_counts([e.password for e in entries])
    reuse_count = password_dups.get(entry.password, 1)
    info = build_breach_intelligence(
        entry.password,
        context=f'{entry.title} {entry.username} {entry.website}',
        reuse_count=reuse_count,
        updated_at_iso=entry.updated_at,
    )
    site_fit = evaluate_password_fit(
        entry.password,
        title=entry.title,
        username=entry.username,
        website=entry.website,
        category=entry.category,
        password_score=int(info.get('score', 0) or 0),
        breached=bool(info.get('breached')),
        common_password=bool(info.get('common_password')),
        reuse_count=reuse_count,
        updated_at_iso=entry.updated_at,
    )
    issues = normalize_issue_list(info.get('warnings', []))
    risk_level = composite_risk_level(
        int(info.get('score', 0) or 0),
        breached=bool(info.get('breached')),
        common_password=bool(info.get('common_password')),
        reuse_count=int(info.get('reuse_count', 1) or 1),
        old_password=bool(info.get('old_password')),
        category=entry.category,
        issues=issues,
    )
    info.update({
        'title': entry.title,
        'username': entry.username,
        'website': entry.website,
        'risk_level': risk_level,
        'severity': severity_for_risk(risk_level),
        'site_policy': site_fit.to_dict(),
        'site_profile': site_fit.profile,
        'site_fit_score': site_fit.fit_score,
        'site_fit_label': site_fit.fit_label,
    })
    return info


def build_findings_for_entries(entries: list[Any]) -> list[dict[str, Any]]:
    password_dups = duplicate_password_counts([e.password for e in entries])
    username_dups = duplicate_counts([e.username for e in entries])
    site_dups = duplicate_counts([normalize_site(e.website) for e in entries])
    findings: list[dict[str, Any]] = []

    for item in entries:
        analysis = analyze_password(item.password, context=f'{item.title} {item.username} {item.website}')
        issues = normalize_issue_list(analysis.warnings)
        reuse_count = password_dups.get(item.password, 0)
        if reuse_count > 1:
            issues.append(f'Reused password across {reuse_count} accounts.')
        if username_dups.get(item.username.strip().lower(), 0) > 1 and item.username:
            issues.append('Username appears in multiple entries.')
        norm_site = normalize_site(item.website)
        if norm_site and site_dups.get(norm_site, 0) > 1:
            issues.append('Duplicate site entry detected.')
        old_password = password_is_old(item.updated_at)
        intel = build_intelligence_for_entry(item, entries)
        site_fit = intel.get('site_policy', {})
        if old_password:
            issues.append('Password is older than 90 days.')
        if isinstance(site_fit, dict) and int(site_fit.get('fit_score', 100) or 100) < 70:
            issues.append(f"Below inferred site-policy fit: {site_fit.get('profile', 'General')} ({site_fit.get('fit_score', 0)}/100).")
        if not item.website:
            issues.append('Missing website field.')
        if not item.tags:
            issues.append('Missing tags.')

        issues = normalize_issue_list(issues)
        risk_level = composite_risk_level(
            analysis.score,
            breached=bool(intel.get('breached')),
            common_password=bool(intel.get('common_password')),
            reuse_count=int(intel.get('reuse_count', reuse_count) or reuse_count or 1),
            old_password=old_password,
            category=item.category,
            issues=issues,
        )
        intel['risk_level'] = risk_level
        intel['severity'] = severity_for_risk(risk_level)
        findings.append({
            'id': item.id,
            'title': item.title,
            'username': item.username,
            'category': item.category,
            'score': analysis.score,
            'label': analysis.label,
            'risk_level': risk_level,
            'issues': issues,
            'breached': intel['breached'],
            'common_password': intel['common_password'],
            'reuse_count': intel['reuse_count'],
            'old_password': old_password,
            'site_profile': site_fit.get('profile', 'General') if isinstance(site_fit, dict) else 'General',
            'site_fit_score': site_fit.get('fit_score', 0) if isinstance(site_fit, dict) else 0,
            'site_fit_label': site_fit.get('fit_label', '-') if isinstance(site_fit, dict) else '-',
            'site_policy': site_fit if isinstance(site_fit, dict) else {},
            'intelligence': intel,
        })

    risk_rank = {'Critical': 0, 'High': 1, 'Moderate': 2, 'Low': 3}
    findings.sort(key=lambda row: (risk_rank.get(row['risk_level'], 9), row['score'], -len(row['issues'])))
    return findings


def build_vault_snapshot(manager: Any) -> VaultSnapshot:
    entries = manager.list_credentials()
    trashed = len(manager.list_credentials(deleted_only=True))
    metrics = asdict(compute_dashboard([asdict(item) for item in entries], trashed))
    findings = build_findings_for_entries(entries)
    return VaultSnapshot(
        created_at=_utc_now_iso(),
        metrics=metrics,
        findings=findings,
        risk_distribution=_risk_distribution(findings),
        active_count=len(entries),
        trash_count=trashed,
    )
