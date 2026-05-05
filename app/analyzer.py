from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from urllib.parse import urlparse

from .breach_db import is_pwned_password

COMMON_PASSWORDS = {
    '123456', 'password', '12345678', 'qwerty', 'admin', 'welcome', 'abc123', '111111', 'iloveyou',
    'letmein', 'dragon', 'monkey', 'football', 'google', 'secret', 'passw0rd', 'password123',
    'qwerty123', '000000', 'zaq12wsx', '1q2w3e4r', 'sunshine', 'freedom', 'trustno1', 'login',
}

KEYBOARD_PATTERNS = ['qwerty', 'asdf', 'zxcv', '12345', '98765', '1q2w3e', 'poiuy', 'lkjh']
YEAR_PATTERN = re.compile(r'(19\d{2}|20\d{2})$')


@dataclass(slots=True)
class PasswordAnalysis:
    score: int
    label: str
    entropy_bits: float
    entropy_note: str
    warnings: list[str]
    suggestions: list[str]
    patterns: list[str]
    breached: bool


@dataclass(slots=True)
class DashboardMetrics:
    total: int
    weak: int
    breached: int
    reused_passwords: int
    old: int
    duplicate_usernames: int
    duplicate_sites: int
    missing_fields: int
    trashed: int
    health_score: int


def normalize_site(value: str) -> str:
    raw = (value or '').strip().lower()
    if not raw:
        return ''
    if '://' not in raw:
        raw = f'https://{raw}'
    host = urlparse(raw).netloc.lower()
    return host.removeprefix('www.')


def estimate_entropy(password: str) -> float:
    if not password:
        return 0.0
    pool = 0
    if any(c.islower() for c in password):
        pool += 26
    if any(c.isupper() for c in password):
        pool += 26
    if any(c.isdigit() for c in password):
        pool += 10
    if any(not c.isalnum() for c in password):
        pool += 32
    if pool == 0:
        return 0.0
    return len(password) * math.log2(pool)


def entropy_note(entropy: float) -> str:
    if entropy >= 85:
        return 'Excellent entropy for a local encrypted vault credential.'
    if entropy >= 65:
        return 'Healthy entropy. Resistant to basic guessing and weak brute-force strategies.'
    if entropy >= 45:
        return 'Moderate entropy. Improve length and character variety.'
    return 'Low entropy. Increase length and avoid predictable patterns.'


def score_to_risk(score: int) -> str:
    if score >= 85:
        return 'Low'
    if score >= 70:
        return 'Moderate'
    if score >= 50:
        return 'High'
    return 'Critical'


def score_to_severity(score: int) -> str:
    if score >= 85:
        return 'safe'
    if score >= 70:
        return 'watch'
    if score >= 50:
        return 'warning'
    return 'danger'


def analyze_password(password: str, context: str = '') -> PasswordAnalysis:
    warnings: list[str] = []
    suggestions: list[str] = []
    patterns: list[str] = []
    score = 100

    if not password:
        return PasswordAnalysis(0, 'Empty', 0.0, 'No password set.', ['Password is empty.'], ['Add a password.'], [], False)

    length = len(password)
    entropy = estimate_entropy(password)
    lowered = password.lower()
    context_l = context.lower()
    breached = False

    if length < 8:
        score -= 45
        warnings.append('Too short. Minimum recommended length is 12+ characters.')
    elif length < 12:
        score -= 20
        warnings.append('Could be longer for better resilience.')
    elif length >= 16:
        score += 3

    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_symbol = any(not c.isalnum() for c in password)

    if not has_lower:
        score -= 8
        suggestions.append('Add lowercase letters.')
    if not has_upper:
        score -= 8
        suggestions.append('Add uppercase letters.')
    if not has_digit:
        score -= 8
        suggestions.append('Add digits.')
    if not has_symbol:
        score -= 10
        suggestions.append('Add symbols for more search space.')

    if lowered in COMMON_PASSWORDS:
        score -= 55
        warnings.append('Common password detected.')
        patterns.append('Common password')
    for pattern in KEYBOARD_PATTERNS:
        if pattern in lowered:
            score -= 14
            warnings.append('Keyboard walk / predictable key pattern detected.')
            patterns.append('Keyboard pattern')
            break
    if re.search(r'(.)\1{2,}', password):
        score -= 14
        warnings.append('Repeated characters detected.')
        patterns.append('Repeated characters')
    if re.search(r'(0123|1234|2345|3456|4567|5678|6789)', lowered):
        score -= 12
        warnings.append('Sequential digits detected.')
        patterns.append('Sequential digits')
    if YEAR_PATTERN.search(password):
        score -= 10
        warnings.append('Ends with a year-like suffix.')
        patterns.append('Year suffix')
    if re.search(r'(?i)p@?ssw?0?rd', password):
        score -= 16
        warnings.append('Looks like a trivial substitution of a known weak password.')
        patterns.append('Simple substitution')

    unique_ratio = len(set(password)) / max(1, len(password))
    if unique_ratio < 0.55:
        score -= 10
        warnings.append('Low character diversity detected.')
        patterns.append('Low diversity')

    if context_l and any(token for token in re.split(r'[^a-z0-9]+', context_l) if token and token in lowered and len(token) >= 3):
        score -= 12
        warnings.append('Password appears related to account/site context.')
        patterns.append('Context-based password')

    if is_pwned_password(password):
        breached = True
        score -= 35
        warnings.append('Found in the offline breach database (HIBP-style local hash set).')
        patterns.append('Offline breach hit')

    if entropy < 45:
        score -= 16
        warnings.append('Entropy is lower than recommended.')
    elif entropy < 65:
        score -= 6
    elif entropy >= 85:
        score += 2

    score = max(0, min(100, score))
    if score >= 85:
        label = 'Excellent'
    elif score >= 70:
        label = 'Strong'
    elif score >= 55:
        label = 'Moderate'
    elif score >= 35:
        label = 'Weak'
    else:
        label = 'Very Weak'

    if length < 16:
        suggestions.append('Consider a 16+ character password or passphrase.')
    if breached:
        suggestions.append('Rotate this password immediately because it appears in the local breach dataset.')
    deduped_suggestions: list[str] = []
    for item in suggestions:
        if item not in deduped_suggestions:
            deduped_suggestions.append(item)

    return PasswordAnalysis(
        score=score,
        label=label,
        entropy_bits=round(entropy, 1),
        entropy_note=entropy_note(entropy),
        warnings=warnings,
        suggestions=deduped_suggestions,
        patterns=patterns,
        breached=breached,
    )


def password_is_old(updated_at_iso: str, age_days: int = 90) -> bool:
    try:
        updated = datetime.fromisoformat(updated_at_iso)
    except ValueError:
        return False
    now = datetime.now(timezone.utc)
    if updated.tzinfo is None:
        updated = updated.replace(tzinfo=timezone.utc)
    return (now - updated).days >= age_days


def duplicate_password_counts(passwords: list[str]) -> Counter:
    return Counter(p for p in passwords if p)


def duplicate_counts(values: list[str]) -> Counter:
    normalized = [v.strip().lower() for v in values if v and v.strip()]
    return Counter(normalized)


def build_breach_intelligence(password: str, *, context: str = '', reuse_count: int = 1, updated_at_iso: str = '') -> dict:
    analysis = analyze_password(password, context=context)
    lowered = (password or '').lower()
    common_hit = lowered in COMMON_PASSWORDS
    old_password = password_is_old(updated_at_iso) if updated_at_iso else False

    explanation_parts: list[str] = []
    if analysis.breached:
        explanation_parts.append('This password appears in the local offline breach dataset.')
    if common_hit:
        explanation_parts.append('It also matches a known common password pattern.')
    if reuse_count > 1:
        explanation_parts.append(f'It is reused across {reuse_count} stored account(s).')
    if old_password:
        explanation_parts.append('The credential is older than the recommended 90-day rotation window.')
    if not explanation_parts:
        explanation_parts.append('No breach or common-password hit was found in the local intelligence checks.')

    why_matters: list[str] = []
    if analysis.breached or common_hit:
        why_matters.append('Attackers prioritize leaked and common passwords during credential stuffing and password spraying.')
    if reuse_count > 1:
        why_matters.append('Reusing one password can let a single compromise spread across multiple accounts.')
    if analysis.score < 60:
        why_matters.append('Weak entropy and predictable patterns reduce the effort required to guess the password.')
    if old_password:
        why_matters.append('Stale credentials stay exposed longer if they were previously leaked or shared.')
    if not why_matters:
        why_matters.append('The credential currently shows a healthy local posture, but regular rotation and backups still matter.')

    fixes: list[str] = []
    if analysis.breached or common_hit:
        fixes.append('Rotate this password immediately.')
    if reuse_count > 1:
        fixes.append('Replace reused passwords with unique generated values for each account.')
    if analysis.score < 70:
        fixes.append('Generate a 16+ character password with uppercase, lowercase, digits, and symbols.')
    if old_password:
        fixes.append('Perform a scheduled rotation and verify recovery options for this account.')
    if not fixes:
        fixes.append('Keep this password unique and continue exporting encrypted backups.')

    return {
        'score': analysis.score,
        'label': analysis.label,
        'risk_level': score_to_risk(analysis.score),
        'severity': score_to_severity(analysis.score),
        'breached': analysis.breached,
        'common_password': common_hit,
        'reuse_count': reuse_count,
        'old_password': old_password,
        'entropy_bits': analysis.entropy_bits,
        'explanation': ' '.join(explanation_parts),
        'why_matters': why_matters,
        'fix_recommendations': fixes,
        'patterns': analysis.patterns,
        'warnings': analysis.warnings,
        'suggestions': analysis.suggestions,
    }


def compute_dashboard(active_entries: list[dict], trashed_count: int) -> DashboardMetrics:
    password_dups = duplicate_password_counts([e['password'] for e in active_entries])
    username_dups = duplicate_counts([e.get('username', '') for e in active_entries])
    site_dups = duplicate_counts([normalize_site(e.get('website', '')) for e in active_entries])

    weak = 0
    breached = 0
    reused_passwords = 0
    old = 0
    duplicate_usernames = 0
    duplicate_sites = 0
    missing_fields = 0

    password_scores: list[int] = []

    for entry in active_entries:
        analysis = analyze_password(entry['password'], context=f"{entry.get('title','')} {entry.get('username','')} {entry.get('website','')}")
        password_scores.append(int(analysis.score))
        if analysis.score < 60:
            weak += 1
        if analysis.breached:
            breached += 1
        if password_dups.get(entry['password'], 0) > 1:
            reused_passwords += 1
        if username_dups.get(entry.get('username', '').strip().lower(), 0) > 1 and entry.get('username'):
            duplicate_usernames += 1
        norm_site = normalize_site(entry.get('website', ''))
        if norm_site and site_dups.get(norm_site, 0) > 1:
            duplicate_sites += 1
        if password_is_old(entry['updated_at']):
            old += 1
        if not entry.get('website') or not entry.get('category') or not entry.get('tags'):
            missing_fields += 1

    total = len(active_entries)
    if total == 0:
        health_score = 0
    else:
        # Build the posture score from actual password quality first, then apply
        # smaller hygiene penalties.  The previous formula could show 95/100
        # while a vault contained a very weak/critical password because the
        # penalty was averaged across all accounts.
        average_password_score = round(sum(password_scores) / max(1, total))
        hygiene_penalty = (
            breached * 14
            + reused_passwords * 12
            + old * 5
            + duplicate_usernames * 2
            + duplicate_sites * 2
            + min(missing_fields, total) * 2
            + trashed_count * 1
        )
        health_score = max(0, min(100, average_password_score - round(hygiene_penalty / max(1, total))))

        # Cap optimistic scores when urgent risks exist. This keeps dashboard,
        # AI Guardian, and reports consistent: a critical password cannot still
        # present as an excellent overall posture.
        weakest_score = min(password_scores) if password_scores else 100
        if breached or reused_passwords:
            health_score = min(health_score, 69)
        elif weakest_score < 35:
            health_score = min(health_score, 74)
        elif weak:
            health_score = min(health_score, 84)

    return DashboardMetrics(
        total=total,
        weak=weak,
        breached=breached,
        reused_passwords=reused_passwords,
        old=old,
        duplicate_usernames=duplicate_usernames,
        duplicate_sites=duplicate_sites,
        missing_fields=missing_fields,
        trashed=trashed_count,
        health_score=health_score,
    )


def build_recommendations(metrics: DashboardMetrics) -> list[str]:
    recs: list[str] = []
    if metrics.total == 0:
        return ['Add or import credentials to begin monitoring password health and breach exposure.']
    if metrics.breached:
        recs.append(f'Immediately rotate {metrics.breached} password(s) found in the offline breach database.')
    if metrics.weak:
        recs.append(f'Replace {metrics.weak} weak password(s) with 16+ character generated passwords.')
    if metrics.reused_passwords:
        recs.append(f'Stop password reuse across {metrics.reused_passwords} account(s).')
    if metrics.old:
        recs.append(f'Rotate {metrics.old} password(s) older than 90 days.')
    if metrics.duplicate_usernames:
        recs.append('Review repeated usernames to confirm they are intentional and not stale duplicates.')
    if metrics.duplicate_sites:
        recs.append('Consolidate or review duplicate site entries to reduce clutter and confusion.')
    if metrics.missing_fields:
        recs.append(f'Complete metadata for {metrics.missing_fields} account(s): add site, category, and tags.')
    if metrics.trashed:
        recs.append('Review items in Trash and purge anything you no longer need.')
    if not recs:
        recs.append('Vault health looks strong. Maintain regular rotations and encrypted backups.')
    return recs
