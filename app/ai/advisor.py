from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from typing import Any

from ..security_policy import CRITICAL_CATEGORIES, mask_identifier
from .insights import build_change_summary, simulate_fix_impact

RISK_LEVELS = ('Critical', 'High', 'Moderate', 'Low')
RISK_WEIGHT = {'Critical': 400, 'High': 300, 'Moderate': 200, 'Low': 100}
SIGNAL_WEIGHTS = {
    'breach_hit': 32,
    'reuse_chain': 24,
    'weak_entropy': 20,
    'site_policy_mismatch': 16,
    'stale_secret': 12,
    'high_value_category': 10,
    'metadata_gap': 5,
    'duplicate_identity': 4,
}


def _clamp(value: int, minimum: int = 0, maximum: int = 100) -> int:
    return max(minimum, min(maximum, int(value)))


def build_redacted_advisor_context(metrics: dict[str, Any], findings: list[dict[str, Any]]) -> dict[str, Any]:
    """Build a safe, future-ready AI context with no secrets or raw credentials."""
    safe_findings: list[dict[str, Any]] = []
    for item in findings:
        safe_findings.append({
            'credential_ref': f"credential #{item.get('id', '?')}",
            'title_ref': f"Credential #{item.get('id', '?')}",
            'username_hint': mask_identifier(str(item.get('username', ''))),
            'category': item.get('category', 'General'),
            'risk_level': item.get('risk_level', 'Low'),
            'score': int(item.get('score', 0) or 0),
            'issues': list(item.get('issues', [])),
            'breached': bool(item.get('breached', False)),
            'common_password': bool(item.get('common_password', False)),
            'reuse_count': int(item.get('reuse_count', 0) or 0),
            'old_password': bool(item.get('old_password', False)),
            'site_profile': item.get('site_profile', item.get('site_policy', {}).get('profile', 'General')),
            'site_fit_score': int(item.get('site_fit_score', item.get('site_policy', {}).get('fit_score', 100)) or 100),
            'site_fit_label': item.get('site_fit_label', item.get('site_policy', {}).get('fit_label', 'Strong Fit')),
            'site_policy_requirements': list(item.get('site_policy', {}).get('requirements', []))[:5],
            'site_behavior': list(item.get('site_policy', {}).get('form_behavior', []))[:4],
            'symbol_guidance': item.get('site_policy', {}).get('symbol_guidance', ''),
        })
    return {
        'metrics': dict(metrics),
        'findings': safe_findings,
        'policy': {
            'no_raw_passwords': True,
            'no_full_usernames': True,
            'no_notes': True,
            'no_backup_data': True,
            'no_database_paths': True,
            'local_first': True,
            'explainable_rules': True,
        },
    }


def _risk_distribution(findings: list[dict[str, Any]]) -> dict[str, int]:
    counts = {name: 0 for name in RISK_LEVELS}
    for item in findings:
        risk = str(item.get('risk_level', 'Low'))
        if risk in counts:
            counts[risk] += 1
    return counts


def _issue_text(item: dict[str, Any]) -> str:
    return ' '.join(str(issue).lower() for issue in item.get('issues', []))


def _signal_flags(item: dict[str, Any]) -> dict[str, bool]:
    text = _issue_text(item)
    score = int(item.get('score', 100) or 100)
    return {
        'breach_hit': bool(item.get('breached') or item.get('common_password') or 'breach' in text or 'common password' in text),
        'reuse_chain': int(item.get('reuse_count', 0) or 0) > 1 or 'reused password' in text,
        'weak_entropy': score < 60 or 'entropy' in text or 'too short' in text or 'predictable' in text,
        'site_policy_mismatch': int(item.get('site_fit_score', 100) or 100) < 70 or 'below inferred site-policy fit' in text,
        'stale_secret': bool(item.get('old_password')) or 'older than 90 days' in text,
        'high_value_category': str(item.get('category', 'General')) in CRITICAL_CATEGORIES,
        'metadata_gap': 'missing website' in text or 'missing tags' in text,
        'duplicate_identity': 'duplicate site' in text or 'username appears' in text,
    }


def _signal_score(item: dict[str, Any]) -> int:
    flags = _signal_flags(item)
    value = sum(weight for name, weight in SIGNAL_WEIGHTS.items() if flags.get(name))
    value += max(0, 100 - int(item.get('score', 100) or 100)) // 4
    return _clamp(value)


def _evidence_confidence_for(item: dict[str, Any]) -> int:
    flags = _signal_flags(item)
    issue_count = len(list(item.get('issues', [])))
    confidence = 44 + issue_count * 5
    if flags['breach_hit']:
        confidence += 22
    if flags['reuse_chain']:
        confidence += 15
    if flags['weak_entropy']:
        confidence += 12
    if flags.get('site_policy_mismatch'):
        confidence += 10
    if flags['stale_secret']:
        confidence += 7
    if flags['metadata_gap'] or flags['duplicate_identity']:
        confidence += 4
    return _clamp(confidence, 45, 98)


def _primary_signal_for(item: dict[str, Any]) -> str:
    flags = _signal_flags(item)
    ordered = [
        ('breach_hit', 'Breach/Common hit'),
        ('reuse_chain', 'Reuse chain'),
        ('weak_entropy', 'Weak entropy'),
        ('site_policy_mismatch', 'Site-fit mismatch'),
        ('stale_secret', 'Stale secret'),
        ('high_value_category', 'High-value account'),
        ('metadata_gap', 'Metadata gap'),
        ('duplicate_identity', 'Duplicate identity'),
    ]
    for key, label in ordered:
        if flags.get(key):
            return label
    return 'Routine hygiene'


def _evidence_tags_for(item: dict[str, Any]) -> list[str]:
    flags = _signal_flags(item)
    tags: list[str] = []
    if flags['breach_hit']:
        tags.append('offline breach/common-password signal')
    if flags['reuse_chain']:
        tags.append(f"reuse count {int(item.get('reuse_count', 0) or 0)}")
    if flags['weak_entropy']:
        tags.append(f"score {int(item.get('score', 0) or 0)}/100")
    if flags.get('site_policy_mismatch'):
        tags.append(f"site-fit {int(item.get('site_fit_score', 0) or 0)}/100 for {item.get('site_profile', 'General')}")
    if flags['stale_secret']:
        tags.append('older than 90 days')
    if flags['high_value_category']:
        tags.append(f"high-value category: {item.get('category', 'General')}")
    for issue in list(item.get('issues', []))[:3]:
        normalized = str(issue).rstrip('.')
        if normalized and normalized.lower() not in ' '.join(tags).lower():
            tags.append(normalized)
    return tags[:6] or ['low-noise telemetry']


def _is_actionable(item: dict[str, Any]) -> bool:
    if item.get('risk_level') in {'Critical', 'High', 'Moderate'}:
        return True
    if item.get('breached') or int(item.get('reuse_count', 0) or 0) > 1 or item.get('old_password'):
        return True
    if int(item.get('score', 100) or 100) < 75:
        return True
    return bool(list(item.get('issues', [])))


def _priority_score(item: dict[str, Any]) -> int:
    risk = str(item.get('risk_level', 'Low'))
    score = int(item.get('score', 0) or 0)
    issues = list(item.get('issues', []))
    value = RISK_WEIGHT.get(risk, 100) + max(0, 100 - score)
    if item.get('breached'):
        value += 90
    if item.get('common_password'):
        value += 60
    if int(item.get('reuse_count', 0) or 0) > 1:
        value += 62
    if item.get('old_password'):
        value += 28
    if int(item.get('site_fit_score', 100) or 100) < 70:
        value += 34
    if str(item.get('category', 'General')) in CRITICAL_CATEGORIES:
        value += 45
    value += min(48, len(issues) * 8)
    value += _signal_score(item)
    return value


def _timeline_for(item: dict[str, Any]) -> str:
    flags = _signal_flags(item)
    if flags['breach_hit'] or item.get('risk_level') == 'Critical':
        return 'Today'
    if item.get('risk_level') == 'High' or flags['reuse_chain']:
        return 'This week'
    if flags.get('site_policy_mismatch') and item.get('risk_level') in {'Moderate', 'High'}:
        return 'This week'
    if flags['high_value_category'] or flags['stale_secret']:
        return 'Next review'
    return 'Maintenance cycle'


def _action_for(item: dict[str, Any]) -> str:
    flags = _signal_flags(item)
    if flags['breach_hit']:
        return 'Rotate immediately, check reuse, revoke active sessions where possible, then enable MFA.'
    if flags['reuse_chain']:
        return 'Break the reuse chain with unique generated passwords for every linked account.'
    if flags['weak_entropy']:
        return 'Generate a stronger 20+ character password and update the real service.'
    if flags.get('site_policy_mismatch'):
        return f"Match the inferred {item.get('site_profile', 'site')} requirements with a longer unique generated password, then save it."
    if flags['stale_secret']:
        return 'Schedule rotation, verify recovery options, and save the new credential.'
    if flags['metadata_gap']:
        return 'Complete website/tags/category metadata so audits and exports are evidence-ready.'
    if flags['duplicate_identity']:
        return 'Review duplicate identity/site entries and merge or retire stale records.'
    return 'Review during the next vault hygiene pass and keep encrypted backups current.'


def _attack_scenario_for(item: dict[str, Any]) -> str:
    category = str(item.get('category', 'General'))
    flags = _signal_flags(item)
    if flags['breach_hit']:
        return 'Credential stuffing path: an attacker tests a known/common password against this account and any reused services.'
    if flags['reuse_chain']:
        return 'Pivot path: compromise of one service can spread to every entry sharing the same password pattern.'
    if flags['weak_entropy']:
        return 'Guessing/cracking path: predictable structure lowers the work factor for online guessing or offline cracking after a service breach.'
    if flags.get('site_policy_mismatch'):
        return f"Site-fit path: this password does not meet the local {item.get('site_profile', 'account')} expectation, leaving a high-value account under-protected."
    if flags['stale_secret']:
        return 'Dormant exposure path: old passwords are more likely to exist in browser exports, screenshots, old devices, or previous leaks.'
    if category in CRITICAL_CATEGORIES:
        return 'High-value account path: small hygiene issues can become larger business, mailbox, infrastructure, or finance impact.'
    return 'Low-noise hygiene path: cleanup improves future search, reporting quality, and audit confidence.'


def _exposure_path_for(item: dict[str, Any]) -> str:
    category = str(item.get('category', 'General'))
    flags = _signal_flags(item)
    if category in {'Email', 'Work'}:
        target = 'mailbox/session takeover'
    elif category in {'Servers'}:
        target = 'infrastructure access and lateral movement'
    elif category in {'Banking', 'Finance', 'Crypto'}:
        target = 'financial account exposure'
    elif category in {'Social'}:
        target = 'reputation and identity abuse'
    else:
        target = 'account takeover or data exposure'
    trigger = 'breach reuse' if flags['breach_hit'] or flags['reuse_chain'] else 'site-fit mismatch' if flags.get('site_policy_mismatch') else 'weak secret hygiene'
    return f'{trigger} → {target}'


def _business_impact_for(item: dict[str, Any]) -> str:
    category = str(item.get('category', 'General'))
    if category in {'Banking', 'Finance', 'Crypto'}:
        return 'Potential financial account exposure, fraud risk, and urgent recovery workload.'
    if category in {'Servers', 'Work', 'Email'}:
        return 'Potential workspace compromise, lateral movement, mailbox takeover, or operational disruption.'
    if category in {'Social', 'Shopping'}:
        return 'Potential reputation damage, account abuse, saved-card misuse, or identity recovery friction.'
    if item.get('breached') or int(item.get('reuse_count', 0) or 0) > 1:
        return 'Potential account takeover path if the password is reused or already known.'
    return 'Lower direct impact, but it still weakens vault hygiene and executive report quality.'


def _fix_path_for(item: dict[str, Any]) -> list[str]:
    flags = _signal_flags(item)
    path: list[str] = []
    if flags['breach_hit'] or flags['weak_entropy']:
        path.append('Generate a unique 20+ character replacement.')
        path.append('Update the real service password, then save the new value in CyberVault.')
    if flags['breach_hit']:
        path.append('Sign out other sessions or revoke trusted devices when the service supports it.')
    if flags['reuse_chain']:
        path.append('Break the reuse chain by assigning a different generated password to every related account.')
    if flags.get('site_policy_mismatch'):
        path.append(f"Use the {item.get('site_profile', 'site')} profile target instead of a generic password.")
        if item.get('site_behavior'):
            path.append('Check site behavior: ' + '; '.join(item.get('site_behavior', [])[:2]) + '.')
        path.append('Prefer a unique generated password that reaches the profile length target.')
    if flags['stale_secret']:
        path.append('Record rotation date after changing the service password.')
    if flags['high_value_category']:
        path.append('Enable MFA or hardware-key protection where available.')
    if flags['metadata_gap'] or flags['duplicate_identity']:
        path.append('Clean website, tags, category, and duplicate entries for audit-quality reporting.')
    if not path:
        path.append('Review metadata, tags, and website fields for audit quality.')
    path.append('Export a fresh privacy-safe report package after remediation.')
    return path[:6]


def _expected_score_gain_for(item: dict[str, Any]) -> int:
    flags = _signal_flags(item)
    gain = 0
    if flags['breach_hit']:
        gain += 18
    if flags['reuse_chain']:
        gain += 14
    if flags['stale_secret']:
        gain += 8
    if flags['weak_entropy']:
        gain += 12
    if flags.get('site_policy_mismatch'):
        gain += 10
    if flags['high_value_category']:
        gain += 4
    if flags['metadata_gap'] or flags['duplicate_identity']:
        gain += 4
    if list(item.get('issues', [])):
        gain += min(6, len(list(item.get('issues', []))) * 2)
    return max(3, min(34, gain))


def _decision_trace_for(item: dict[str, Any]) -> list[str]:
    trace = [
        f"Risk tier: {item.get('risk_level', 'Low')}",
        f"Primary signal: {_primary_signal_for(item)}",
        f"Evidence confidence: {_evidence_confidence_for(item)}%",
        f"Urgency score: {_signal_score(item)}/100",
    ]
    if int(item.get('site_fit_score', 100) or 100) < 70:
        trace.append(f"Site-fit score {item.get('site_fit_score')}/100 for {item.get('site_profile', 'General')} raised the priority.")
    if str(item.get('category', 'General')) in CRITICAL_CATEGORIES:
        trace.append('High-value category raised the priority.')
    if int(item.get('reuse_count', 0) or 0) > 1:
        trace.append(f"Reuse count {item.get('reuse_count')} means one compromise can fan out.")
    return trace


def _reason_for(item: dict[str, Any]) -> str:
    reasons: list[str] = []
    flags = _signal_flags(item)
    if flags['breach_hit']:
        reasons.append('matched breach/common-password intelligence')
    if flags['reuse_chain']:
        reasons.append(f"is reused across {item.get('reuse_count')} accounts")
    if flags['stale_secret']:
        reasons.append('is past the rotation window')
    if flags['weak_entropy']:
        reasons.append('has weak password strength')
    if flags.get('site_policy_mismatch'):
        reasons.append(f"does not fit the inferred {item.get('site_profile', 'site')} policy")
    if flags['high_value_category']:
        reasons.append(f"belongs to a high-value {item.get('category')} category")
    if not reasons:
        issues = list(item.get('issues', []))
        if issues:
            reasons.append(str(issues[0]).rstrip('.').lower())
    return ', '.join(reasons) or 'needs routine hygiene review'


def _risk_cards(counts: dict[str, int]) -> dict[str, dict[str, str | int]]:
    narratives = {
        'Critical': 'Immediate rotation candidates. Treat these like incident-response tasks.',
        'High': 'Strong assessment value. Fixing these usually improves health score quickly.',
        'Moderate': 'Cleanup and metadata improvements that reduce future risk.',
        'Low': 'Healthy or low-noise entries. Keep them monitored during monthly reviews.',
    }
    return {
        level: {
            'count': int(counts.get(level, 0) or 0),
            'narrative': narratives[level],
        }
        for level in RISK_LEVELS
    }


def _build_action_plan(metrics: dict[str, Any], priority_items: list[dict[str, Any]]) -> dict[str, list[str]]:
    today: list[str] = []
    this_week: list[str] = []
    long_term: list[str] = []

    if not int(metrics.get('total', 0) or 0):
        return {
            'today': ['Add or import credentials to activate CyberVault AI Guardian.'],
            'this_week': ['Load an assessment dataset to showcase risk analysis during the presentation.'],
            'long_term': ['Keep the AI layer privacy-first: never send raw passwords or notes to any model.'],
        }

    for item in priority_items[:5]:
        line = f"{item['credential_ref']}: {item['recommended_action']}"
        if item['timeline'] == 'Today':
            today.append(line)
        elif item['timeline'] == 'This week':
            this_week.append(line)
        else:
            long_term.append(line)

    if int(metrics.get('breached', 0) or 0):
        today.insert(0, 'Rotate all breached/common-password hits before any cosmetic cleanup.')
    if int(metrics.get('reused_passwords', 0) or 0):
        this_week.append('Break password reuse chains by giving every account a unique generated password.')
    if int(metrics.get('old', 0) or 0):
        this_week.append('Prioritize old credentials in Email, Banking, Work, Servers, and Crypto categories.')
    if int(metrics.get('missing_fields', 0) or 0):
        long_term.append('Complete missing websites/tags to improve search, reporting, and future AI explanations.')
    long_term.append('Run a monthly vault review and export a fresh encrypted backup after major rotations.')

    return {
        'today': today or ['No emergency rotations detected. Keep backups current and monitor future imports.'],
        'this_week': this_week or ['Review moderate findings and clean duplicate or incomplete records.'],
        'long_term': long_term,
    }


def _executive_summary(metrics: dict[str, Any], counts: dict[str, int], priority_items: list[dict[str, Any]]) -> str:
    total = int(metrics.get('total', 0) or 0)
    if not total:
        return 'AI Guardian is ready, but the vault has no active credentials yet. Add data to generate a meaningful security plan.'
    score = int(metrics.get('health_score', 0) or 0)
    critical = counts.get('Critical', 0)
    high = counts.get('High', 0)
    avg_conf = round(sum(int(item.get('confidence_percent', 0) or 0) for item in priority_items) / max(1, len(priority_items))) if priority_items else 0
    if critical and score >= 85:
        posture = 'strong overall, but one critical item needs attention'
    elif critical:
        posture = 'critical attention required'
    elif high or score < 70:
        posture = 'elevated risk'
    elif score < 85:
        posture = 'moderate risk with clear cleanup opportunities'
    else:
        posture = 'healthy posture'
    top_reason = priority_items[0]['why'] if priority_items else 'no actionable security finding detected'
    confidence_line = f' Average evidence confidence across priority items is {avg_conf}%.' if avg_conf else ''
    return (
        f'AI Guardian reviewed {total} active credential(s) and scored the vault at {score}/100. '
        f'The current posture is {posture}. The top driver is {top_reason}.{confidence_line} '
        'The plan is generated locally from redacted security signals only.'
    )


def _build_decision_matrix(metrics: dict[str, Any], priority_items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if not int(metrics.get('total', 0) or 0):
        return [
            {'lens': 'Data readiness', 'status': 'Waiting', 'why': 'No active credentials are available yet.', 'next_step': 'Add or import credentials.'},
            {'lens': 'Privacy', 'status': 'Passed', 'why': 'The AI payload is redacted by design.', 'next_step': 'Keep local-first mode enabled.'},
        ]
    top = priority_items[0] if priority_items else {}
    return [
        {
            'lens': 'First fix',
            'status': top.get('timeline', 'Monitor') if top else 'Monitor',
            'why': top.get('why', 'No urgent driver detected.'),
            'next_step': top.get('recommended_action', 'Maintain backups and monthly reviews.'),
        },
        {
            'lens': 'Evidence confidence',
            'status': f"{top.get('confidence_percent', 0)}%" if top else 'n/a',
            'why': '; '.join(top.get('evidence_tags', [])[:3]) if top else 'No priority evidence available.',
            'next_step': 'Use the evidence tags before exporting a report.',
        },
        {
            'lens': 'Score recovery',
            'status': 'Projected',
            'why': f"Current score {metrics.get('health_score', 0)}/100 with {metrics.get('weak', 0)} weak, {metrics.get('reused_passwords', 0)} reused, {metrics.get('old', 0)} old.",
            'next_step': 'Fix top queue items, then regenerate AI Guardian to compare baseline movement.',
        },
    ]


def _build_quality_gates(metrics: dict[str, Any], priority_items: list[dict[str, Any]], llm_payload: dict[str, Any] | None = None) -> list[dict[str, str]]:
    total = int(metrics.get('total', 0) or 0)
    payload = llm_payload or {}
    payload_text = str(payload)
    return [
        {
            'gate': 'Secret redaction',
            'status': 'PASS',
            'detail': 'Priority records use credential refs and masked username hints only.',
        },
        {
            'gate': 'Actionability',
            'status': 'PASS' if priority_items or not total else 'WATCH',
            'detail': f'{len(priority_items)} ranked remediation item(s) generated from current telemetry.',
        },
        {
            'gate': 'LLM payload hygiene',
            'status': 'PASS' if not any(token in payload_text.lower() for token in ('password":', 'master', 'backup_blob')) else 'REVIEW',
            'detail': 'Optional payload is designed for future models without raw passwords, master keys, notes, paths, or backup blobs.',
        },
        {
            'gate': 'Evidence coverage',
            'status': 'PASS' if not priority_items or max(int(item.get('confidence_percent', 0) or 0) for item in priority_items) >= 70 else 'WATCH',
            'detail': 'Each priority item includes confidence, primary signal, evidence tags, and a remediation path.',
        },
    ]


def _build_posture_heatmap(metrics: dict[str, Any], priority_items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    buckets = [
        ('Breach', int(metrics.get('breached', 0) or 0), 'Rotate leaked/common hits first.'),
        ('Reuse', int(metrics.get('reused_passwords', 0) or 0), 'Break shared passwords across accounts.'),
        ('Weakness', int(metrics.get('weak', 0) or 0), 'Increase length and randomness.'),
        ('Age', int(metrics.get('old', 0) or 0), 'Rotate credentials older than policy.'),
        ('Metadata', int(metrics.get('missing_fields', 0) or 0), 'Complete site, category, and tags for reporting.'),
        ('Site Fit', sum(1 for item in priority_items if int(item.get('site_fit_score', 100) or 100) < 70), 'Match password strength to the inferred website/account profile.'),
    ]
    heatmap: list[dict[str, Any]] = []
    for name, count, guidance in buckets:
        if count >= 3:
            heat = 'Hot'
        elif count > 0:
            heat = 'Warm'
        else:
            heat = 'Clear'
        related = [item['credential_ref'] for item in priority_items if name.lower() in ' '.join(item.get('evidence_tags', [])).lower()][:3]
        heatmap.append({'area': name, 'count': count, 'heat': heat, 'guidance': guidance, 'related': related})
    return heatmap



def _build_coach_overview(metrics: dict[str, Any], priority_items: list[dict[str, Any]], safe_findings: list[dict[str, Any]]) -> dict[str, Any]:
    total = int(metrics.get('total', 0) or 0)
    profile_counts = Counter(str(item.get('site_profile', 'General')) for item in safe_findings)
    mismatch_count = sum(1 for item in safe_findings if int(item.get('site_fit_score', 100) or 100) < 70)
    strong_fit_count = sum(1 for item in safe_findings if int(item.get('site_fit_score', 0) or 0) >= 78)
    high_value_count = sum(1 for item in safe_findings if str(item.get('category', 'General')) in CRITICAL_CATEGORIES)
    first = priority_items[0] if priority_items else {}
    if not total:
        readiness = 'Waiting for credential data'
        overview = 'Add or import credentials to let the AI coach build a real user journey.'
        first_action = 'Import browser CSV or add your first credential.'
    elif mismatch_count:
        readiness = 'Coach should focus on site-fit tuning'
        overview = f'{mismatch_count} credential(s) do not match their inferred site profile. Show users exactly why the account needs stronger handling.'
        first_action = first.get('recommended_action', 'Tune the weakest site-fit credential first.')
    elif priority_items:
        readiness = 'Coach has ranked cleanup path'
        overview = f'{len(priority_items)} priority item(s) are ready for guided remediation with evidence and expected score gain.'
        first_action = first.get('recommended_action', 'Open the top priority item and remediate it.')
    else:
        readiness = 'Healthy coaching mode'
        overview = 'No urgent blockers. The UX should celebrate readiness, backups, and monthly review habits.'
        first_action = 'Keep encrypted backups fresh and run a monthly vault review.'
    site_mix = ', '.join(f'{name}: {count}' for name, count in profile_counts.most_common(4)) or 'No site profiles yet'
    return {
        'readiness': readiness,
        'overview': overview,
        'first_action': first_action,
        'site_mix': site_mix,
        'site_fit_mismatches': mismatch_count,
        'strong_site_fits': strong_fit_count,
        'high_value_profiles': high_value_count,
        'profile_distribution': dict(profile_counts.most_common(8)),
        'ux_prompts': [
            'Use short next-step copy near the password field instead of long raw analysis blocks.',
            'Show Length / Mix / Context / Site-fit chips while the user types.',
            'Only escalate red states when there is a hard blocker such as breach, reuse, weak entropy, or profile mismatch.',
        ],
    }


def generate_local_security_plan(metrics: dict[str, Any], findings: list[dict[str, Any]], previous_metrics: dict[str, Any] | None = None) -> dict[str, Any]:
    """Create a privacy-preserving, deterministic AI-style security plan.

    This is intentionally local and explainable. It produces AI-grade guidance
    without sending passwords, notes, full usernames, database paths, or backup data
    to any model.
    """
    context = build_redacted_advisor_context(metrics, findings)
    safe_findings = list(context['findings'])
    counts = _risk_distribution(safe_findings)
    categories = Counter(str(item.get('category', 'General')) for item in safe_findings)

    ranked = sorted((item for item in safe_findings if _is_actionable(item)), key=_priority_score, reverse=True)
    priority_items: list[dict[str, Any]] = []
    for item in ranked[:8]:
        priority_items.append({
            'credential_ref': item['credential_ref'],
            'category': item.get('category', 'General'),
            'risk_level': item.get('risk_level', 'Low'),
            'score': int(item.get('score', 0) or 0),
            'timeline': _timeline_for(item),
            'why': _reason_for(item),
            'primary_signal': _primary_signal_for(item),
            'urgency_score': _signal_score(item),
            'confidence_percent': _evidence_confidence_for(item),
            'evidence_tags': _evidence_tags_for(item),
            'site_profile': item.get('site_profile', 'General'),
            'site_fit_score': int(item.get('site_fit_score', 100) or 100),
            'site_fit_label': item.get('site_fit_label', 'Strong Fit'),
            'site_policy_requirements': list(item.get('site_policy_requirements', []))[:5],
            'site_behavior': list(item.get('site_behavior', []))[:4],
            'site_behavior': list(item.get('site_behavior', []))[:4],
            'symbol_guidance': item.get('symbol_guidance', ''),
            'exposure_path': _exposure_path_for(item),
            'attack_scenario': _attack_scenario_for(item),
            'business_impact': _business_impact_for(item),
            'recommended_action': _action_for(item),
            'fix_path': _fix_path_for(item),
            'expected_score_gain': _expected_score_gain_for(item),
            'decision_trace': _decision_trace_for(item),
            'issues': list(item.get('issues', []))[:4],
        })

    action_plan = _build_action_plan(context['metrics'], priority_items)
    summary = _executive_summary(context['metrics'], counts, priority_items)
    change_summary = build_change_summary(context['metrics'], previous_metrics)
    fix_impact = simulate_fix_impact(context['metrics'], priority_items)
    decision_matrix = _build_decision_matrix(context['metrics'], priority_items)
    heatmap = _build_posture_heatmap(context['metrics'], priority_items)
    coach_overview = _build_coach_overview(context['metrics'], priority_items, safe_findings)
    llm_payload = build_optional_llm_payload(context, summary, priority_items, action_plan, decision_matrix=decision_matrix, heatmap=heatmap, coach_overview=coach_overview)
    quality_gates = _build_quality_gates(context['metrics'], priority_items, llm_payload)

    return {
        'generated_at': datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        'mode': 'Local-first Explainable AI Guardian v6 · Site Policy Reasoner + Site Behavior Reasoner + Live Coach UX/UI',
        'privacy_notice': 'No raw passwords, master keys, notes, full usernames, database paths, or backup blobs are included. Site reasoning uses only local metadata and inferred account profiles.',
        'executive_summary': summary,
        'risk_cards': _risk_cards(counts),
        'category_focus': dict(categories.most_common(5)),
        'posture_heatmap': heatmap,
        'coach_overview': coach_overview,
        'priority_items': priority_items,
        'decision_matrix': decision_matrix,
        'quality_gates': quality_gates,
        'action_plan': action_plan,
        'change_summary': change_summary,
        'fix_impact': fix_impact,
        'ai_style_explanation': _build_ai_style_explanation(context['metrics'], counts, action_plan, change_summary, fix_impact, decision_matrix, heatmap),
        'optional_llm_payload': llm_payload,
    }


def _build_ai_style_explanation(
    metrics: dict[str, Any],
    counts: dict[str, int],
    action_plan: dict[str, list[str]],
    change_summary: list[str],
    fix_impact: dict[str, Any],
    decision_matrix: list[dict[str, Any]] | None = None,
    heatmap: list[dict[str, Any]] | None = None,
) -> str:
    total = int(metrics.get('total', 0) or 0)
    if not total:
        return 'I do not see active credentials yet. Import or add credentials, then I can rank risks, confidence, exposure paths, and remediation order.'
    score = int(metrics.get('health_score', 0) or 0)
    risk_line = ', '.join(f'{level}: {count}' for level, count in counts.items())
    first_action = action_plan.get('today', ['No urgent action detected.'])[0]
    projected = fix_impact.get('projected_score', score)
    gain = fix_impact.get('estimated_gain', 0)
    change_line = change_summary[0] if change_summary else 'No previous snapshot is available yet.'
    hot_areas = [item['area'] for item in (heatmap or []) if item.get('heat') == 'Hot']
    heat_line = f" Hot posture areas: {', '.join(hot_areas)}." if hot_areas else ' No hot posture area dominates right now.'
    decision_line = ''
    if decision_matrix:
        first_decision = decision_matrix[0]
        decision_line = f" Decision lens: {first_decision.get('lens')} → {first_decision.get('status')} because {first_decision.get('why')}"
    return (
        f'I analyzed the vault locally and found a health score of {score}/100 across {total} credential(s). '
        f'Risk distribution is {risk_line}. The best first move is: {first_action} '
        f'Fix-impact simulation estimates a move to {projected}/100 ({gain:+} points) after the top priorities are handled. '
        f'{heat_line} What changed: {change_line}.{decision_line} '
        'After that, focus on reuse, old passwords, and incomplete metadata because these are the fastest ways to improve both security and report quality.'
    )


def build_optional_llm_payload(
    redacted_context: dict[str, Any],
    summary: str,
    priority_items: list[dict[str, Any]],
    action_plan: dict[str, list[str]],
    *,
    decision_matrix: list[dict[str, Any]] | None = None,
    heatmap: list[dict[str, Any]] | None = None,
    coach_overview: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Return a safe payload that could be sent to an LLM later.

    The app does not send this anywhere. It exists to document how an optional
    LLM integration can be added without exposing secrets.
    """
    return {
        'system_prompt': (
            'You are CyberVault AI Guardian. Explain password-vault risks clearly. '
            'Never request, infer, reveal, transform, or store raw passwords, master keys, full usernames, notes, database files, or backup files. '
            'Use only the redacted fields and explain uncertainty.'
        ),
        'user_context': {
            'metrics': redacted_context.get('metrics', {}),
            'policy': redacted_context.get('policy', {}),
            'executive_summary': summary,
            'priority_items': priority_items[:5],
            'action_plan': action_plan,
            'decision_matrix': decision_matrix or [],
            'posture_heatmap': heatmap or [],
            'coach_overview': coach_overview or {},
        },
    }
