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
    'password1', 'welcome1', 'admin123', 'backup2020', 'summer2025', 'winter2024', 'company2024',
}

WEAK_BASE_WORDS = {
    'password', 'passw0rd', 'qwerty', 'admin', 'welcome', 'letmein', 'login', 'secret', 'company',
    'backup', 'summer', 'winter', 'spring', 'autumn', 'football', 'monkey', 'dragon', 'vendor',
}

DICTIONARY_WORDS = {
    'correct', 'horse', 'battery', 'staple', 'summer', 'winter', 'spring', 'autumn', 'fall', 'company',
    'password', 'admin', 'welcome', 'backup', 'merchant', 'gateway', 'billing', 'helpdesk', 'database',
    'portal', 'security', 'finance', 'github', 'microsoft', 'slack', 'docker', 'stripe', 'portfolio',
    'cloud', 'mail', 'legacy', 'retired', 'vendor', 'payroll', 'social', 'registry', 'wireless',
}

SEASON_WORDS = {'summer', 'winter', 'spring', 'autumn', 'fall'}
MONTH_WORDS = {
    'january', 'february', 'march', 'april', 'may', 'june', 'july', 'august', 'september',
    'october', 'november', 'december', 'jan', 'feb', 'mar', 'apr', 'jun', 'jul', 'aug', 'sep',
    'sept', 'oct', 'nov', 'dec',
}
KEYBOARD_PATTERNS = [
    'qwerty', 'ytrewq', 'asdf', 'fdsa', 'zxcv', 'vcxz', '12345', '54321', '98765', '56789',
    '1q2w3e', 'e3w2q1', 'poiuy', 'yuiop', 'lkjh', 'hjkl', 'zaq12wsx', 'xsw21qaz',
]
YEAR_RE = re.compile(r'(19\d{2}|20\d{2})')
YEAR_SUFFIX_RE = re.compile(r'(19\d{2}|20\d{2})[!@#$%^&*()_+\-=\[\]{};:,.?/]*$')
DATE_RE = re.compile(r'(\d{1,2}[./_-]\d{1,2}[./_-](?:\d{2}|\d{4})|(?:19|20)\d{2}[./_-]?\d{1,2}[./_-]?\d{1,2})')
FAMOUS_PASSPHRASES = {
    'correcthorsebatterystaple',
    'correct horse battery staple',
    'correct-horse-battery-staple',
    'correct_horse_battery_staple',
}
PASSPHRASE_WORD_RE = re.compile(r'[A-Za-z]{3,}')
CAMEL_WORD_RE = re.compile(r'[A-Z]?[a-z]+|[A-Z]+(?=[A-Z]|$)')
TOKEN_RE = re.compile(r'[a-z]{3,}')
SEQUENCE_CHARS = 'abcdefghijklmnopqrstuvwxyz0123456789'


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
    raw_entropy_bits: float = 0.0
    effective_entropy_bits: float = 0.0
    score_cap: int | None = None
    score_cap_reason: str = ''
    remediation_advice: str = ''
    passphrase_model: str = ''
    passphrase_entropy_bits: float = 0.0


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


def _leet_normalize(value: str) -> str:
    table = str.maketrans({
        '@': 'a', '4': 'a', '0': 'o', '1': 'l', '!': 'i', '$': 's', '5': 's', '3': 'e', '7': 't', '+': 't',
    })
    return value.lower().translate(table)


def estimate_entropy(password: str) -> float:
    """Raw charset entropy estimate.

    This is intentionally exposed as a raw signal only. It is not the final
    strength value because predictable words, dates, keyboard walks, and context
    tokens can make a high-character-variety password easy to guess.
    """
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


def _dictionary_tokens(value: str) -> list[str]:
    normalized = _leet_normalize(value)
    tokens = TOKEN_RE.findall(normalized)
    found: list[str] = []
    for word in DICTIONARY_WORDS | WEAK_BASE_WORDS | SEASON_WORDS | MONTH_WORDS:
        if len(word) <= 3:
            if word in tokens:
                found.append(word)
        elif word in normalized:
            found.append(word)
    # CamelCase passphrases such as CorrectHorseBatteryStaple have no separators.
    # Avoid treating short month abbreviations hidden inside random strings as words.
    for token in tokens:
        for word in DICTIONARY_WORDS:
            if len(word) >= 4 and word in token and word not in found:
                found.append(word)
    return sorted(set(found), key=lambda item: (value.lower().find(item), item))


def _has_sequence(value: str, length: int = 4) -> bool:
    lower = value.lower()
    for source in (SEQUENCE_CHARS, SEQUENCE_CHARS[::-1]):
        for index in range(0, len(source) - length + 1):
            if source[index:index + length] in lower:
                return True
    return False


def _has_repeated_short_alpha_block(value: str) -> bool:
    compact = re.sub(r'[^a-z]', '', (value or '').lower())
    for size in range(3, 6):
        for idx in range(0, max(0, len(compact) - (size * 2) + 1)):
            chunk = compact[idx:idx + size]
            if len(chunk) == size and compact[idx + size:idx + (size * 2)] == chunk:
                return True
    return False


def _context_tokens(context: str) -> list[str]:
    raw_tokens = re.split(r'[^a-zA-Z0-9]+', context or '')
    tokens: list[str] = []
    for token in raw_tokens:
        token = _leet_normalize(token.strip())
        if len(token) >= 4 and not token.isdigit():
            tokens.append(token)
    return sorted(set(tokens))



def _passphrase_words(password: str) -> list[str]:
    """Return likely passphrase words without treating random mixed strings as words."""
    raw = password or ''
    if re.search(r'[\s_-]', raw):
        words = PASSPHRASE_WORD_RE.findall(raw)
    else:
        words = CAMEL_WORD_RE.findall(raw)
    return [word.lower() for word in words if len(word) >= 3]


def _passphrase_profile(password: str) -> dict[str, object]:
    """Heuristic passphrase model.

    The app cannot know whether words came from a cryptographic diceware
    generator, so the model is intentionally conservative. It prevents famous
    phrases from being overpraised while avoiding a Very Weak result for long,
    multi-word generated passphrases.
    """
    words = _passphrase_words(password)
    if len(words) < 3:
        return {'is_passphrase': False, 'words': words, 'entropy_bits': 0.0, 'known_phrase': False, 'model_note': ''}
    normalized_words = ' '.join(words)
    compact = ''.join(words)
    known_phrase = normalized_words in FAMOUS_PASSPHRASES or compact in FAMOUS_PASSPHRASES
    # Conservative diceware-style estimate: assume a small 2048-word list only
    # when four or more words are present. For three words, keep the estimate
    # deliberately low because natural phrases are often guessable.
    wordlist_size = 2048 if len(words) >= 4 else 512
    entropy_bits = len(words) * math.log2(wordlist_size)
    dictionary_hits = sum(1 for word in words if word in DICTIONARY_WORDS or word in WEAK_BASE_WORDS or word in MONTH_WORDS)
    separators = bool(re.search(r'[\s_-]', password or ''))
    model_note = (
        f'Passphrase model: {len(words)} word(s), conservative wordlist estimate {entropy_bits:.1f} bits. '
        'This is a heuristic; strength depends on whether the words were randomly generated.'
    )
    return {
        'is_passphrase': True,
        'words': words,
        'entropy_bits': entropy_bits,
        'known_phrase': known_phrase,
        'dictionary_hits': dictionary_hits,
        'has_separators': separators,
        'model_note': model_note,
    }


def _cap(current: int | None, value: int, reason: str, caps: list[tuple[int, str]]) -> int:
    caps.append((value, reason))
    return value if current is None else min(current, value)


def entropy_note(entropy: float, *, raw_entropy: float | None = None, cap_reason: str = '') -> str:
    raw = entropy if raw_entropy is None else raw_entropy
    note = f'Pattern-adjusted effective entropy: {entropy:.1f} bits (raw charset estimate: {raw:.1f} bits).'
    if cap_reason:
        note += f' Score capped because: {cap_reason}.'
    if entropy >= 85:
        return note + ' Strong when no predictable patterns are present.'
    if entropy >= 65:
        return note + ' Healthy, but continue checking reuse, breach exposure, and context clues.'
    if entropy >= 45:
        return note + ' Moderate after pattern adjustment; improve uniqueness and avoid dates/words.'
    return note + ' Low after pattern adjustment; generate a fresh unique password.'


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


def _label(score: int) -> str:
    if score >= 85:
        return 'Excellent'
    if score >= 70:
        return 'Strong'
    if score >= 55:
        return 'Moderate'
    if score >= 35:
        return 'Weak'
    return 'Very Weak'


def analyze_password(password: str, context: str = '') -> PasswordAnalysis:
    warnings: list[str] = []
    suggestions: list[str] = []
    patterns: list[str] = []
    score = 100
    score_cap: int | None = None
    caps: list[tuple[int, str]] = []

    if not password:
        return PasswordAnalysis(
            0,
            'Empty',
            0.0,
            'No password set.',
            ['Password is empty.'],
            ['Add a password.'],
            [],
            False,
            raw_entropy_bits=0.0,
            effective_entropy_bits=0.0,
            remediation_advice='Add a unique generated password.',
        )

    length = len(password)
    raw_entropy = estimate_entropy(password)
    lowered = password.lower()
    normalized = _leet_normalize(password)
    context_tokens = _context_tokens(context)
    breached = False

    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_symbol = any(not c.isalnum() for c in password)
    has_year = bool(YEAR_RE.search(password))
    has_year_suffix = bool(YEAR_SUFFIX_RE.search(password))
    has_date = bool(DATE_RE.search(password))
    dictionary_tokens = _dictionary_tokens(password)
    weak_base_hit = any(base in normalized for base in WEAK_BASE_WORDS)
    common_hit = lowered in COMMON_PASSWORDS or normalized in COMMON_PASSWORDS
    keyboard_hit = next((pattern for pattern in KEYBOARD_PATTERNS if pattern in lowered or pattern in normalized), '')
    season_hit = next((word for word in SEASON_WORDS if word in dictionary_tokens), '')
    month_hit = next((word for word in MONTH_WORDS if word in dictionary_tokens), '')
    context_hit = next((token for token in context_tokens if token and token in normalized), '')
    word_year_symbol = bool(dictionary_tokens and has_year_suffix)
    predictable_suffix = bool(re.search(r'(\d{2,4}|[!@#$%^&*]){2,}$', password))
    weak_word_plus_suffix = bool(dictionary_tokens and re.search(r'(?i)[a-z]{4,}(?:\d{2,4}|[!@#$%^&*]){1,4}$', password))
    short_sequence_hit = _has_sequence(password, length=3)
    repeated_short_block = _has_repeated_short_alpha_block(password)
    passphrase_profile = _passphrase_profile(password)
    is_passphrase = bool(passphrase_profile.get('is_passphrase'))

    if length < 8:
        score -= 45
        warnings.append('Too short. Minimum recommended length is 12+ characters.')
    elif length < 12:
        score -= 20
        warnings.append('Could be longer for better resilience.')
    elif length >= 16:
        score += 3

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

    if common_hit:
        score -= 70
        warnings.append('Common password detected.')
        patterns.append('Common password')
        score_cap = _cap(score_cap, 20, 'common password hit', caps)

    if keyboard_hit:
        score -= 28
        warnings.append('Keyboard walk / predictable key pattern detected.')
        patterns.append('Keyboard pattern')
        score_cap = _cap(score_cap, 45 if has_year else 55, 'keyboard pattern with year' if has_year else 'keyboard pattern', caps)

    if re.search(r'(.)\1{2,}', password):
        score -= 18
        warnings.append('Repeated characters detected.')
        patterns.append('Repeated characters')

    if _has_sequence(password):
        score -= 18
        warnings.append('Sequential characters detected.')
        patterns.append('Sequential characters')

    if short_sequence_hit and not _has_sequence(password):
        score -= 14
        warnings.append('Short alphabetic or numeric sequence detected.')
        patterns.append('Short sequence')
        if length <= 14 and (has_digit or has_symbol):
            score_cap = _cap(score_cap, 68, 'short sequence with predictable padding', caps)

    if repeated_short_block:
        score -= 16
        warnings.append('Repeated short word/letter block detected.')
        patterns.append('Repeated short block')
        if length <= 16:
            score_cap = _cap(score_cap, 65, 'repeated short alphabetic block', caps)

    if has_year_suffix:
        score -= 12
        warnings.append('Ends with a year-like suffix.')
        patterns.append('Year suffix')
    elif has_year:
        score -= 8
        warnings.append('Contains a year-like value.')
        patterns.append('Year')

    if has_date:
        score -= 18
        warnings.append('Date-like pattern detected.')
        patterns.append('Date pattern')

    if season_hit or month_hit:
        score -= 22
        label = 'Season pattern' if season_hit else 'Month pattern'
        warnings.append('Season/month word detected; these are common password bases.')
        patterns.append(label)
        if has_year or predictable_suffix:
            score_cap = _cap(score_cap, 50, 'season/month plus year or predictable suffix', caps)

    if re.search(r'(?i)p[@a]?ss?w?[o0]?rd', password) or 'password' in normalized:
        score -= 30
        warnings.append('Looks like a trivial substitution of a known weak password.')
        patterns.append('Simple substitution')
        score_cap = _cap(score_cap, 45 if has_year or has_symbol else 30, 'weak base word with substitution/suffix', caps)

    if dictionary_tokens:
        token_display = ', '.join(dictionary_tokens[:4])
        warnings.append(f'Dictionary token(s) detected: {token_display}.')
        patterns.append('Dictionary words')
        score -= min(24, 6 * min(len(dictionary_tokens), 4))
        if weak_word_plus_suffix:
            score -= 8
            warnings.append('Dictionary word with predictable numeric/symbol suffix detected.')
            patterns.append('Dictionary suffix pattern')
            score_cap = _cap(score_cap, 58, 'dictionary word with predictable suffix', caps)
        if word_year_symbol:
            score_cap = _cap(score_cap, 55, 'dictionary word plus year/symbol suffix', caps)
        elif len(dictionary_tokens) >= 3 and length >= 16:
            score_cap = _cap(score_cap, 78, 'multi-word dictionary passphrase without a passphrase policy check', caps)

    if is_passphrase:
        passphrase_entropy = float(passphrase_profile.get('entropy_bits', 0.0) or 0.0)
        words = list(passphrase_profile.get('words', []) or [])
        patterns.append('Passphrase model')
        warnings.append(str(passphrase_profile.get('model_note', '')).strip())
        if passphrase_profile.get('known_phrase'):
            score -= 24
            warnings.append('Famous passphrase detected; attackers know and prioritize this example phrase.')
            patterns.append('Famous passphrase')
            score_cap = _cap(score_cap, 55, 'multi-word dictionary passphrase / famous public example', caps)
        elif len(words) >= 4 and passphrase_entropy >= 44:
            # Long generated-looking passphrases should not be called Very Weak
            # solely because they lack digits/symbols. Keep a ceiling because the
            # app cannot prove random generation from text alone.
            if score < 62 and not weak_base_hit and not context_hit and not common_hit:
                score = 62
            if not dictionary_tokens and not weak_base_hit and not context_hit:
                score = max(score, 72)
            score_cap = _cap(score_cap, 84, 'passphrase randomness cannot be proven locally', caps)
            suggestions.append('Keep passphrases random-generated; avoid quotes, famous examples, names, or predictable themes.')
        else:
            score -= 8
            score_cap = _cap(score_cap, 70, 'short or natural-language passphrase uncertainty', caps)
            suggestions.append('Use at least four random words for a stronger passphrase model.')

    if weak_base_hit and not common_hit:
        score -= 16
        patterns.append('Weak base word')
        if has_year or predictable_suffix:
            score_cap = _cap(score_cap, 45 if 'password' in normalized else 55, 'weak base word plus predictable suffix', caps)

    unique_ratio = len(set(password)) / max(1, len(password))
    if unique_ratio < 0.55:
        score -= 10
        warnings.append('Low character diversity detected.')
        patterns.append('Low diversity')

    if context_hit:
        score -= 22
        warnings.append('Password appears related to account/site context.')
        patterns.append('Context-based password')
        if has_year or predictable_suffix:
            score_cap = _cap(score_cap, 55, 'context token plus year/symbol suffix', caps)

    if is_pwned_password(password):
        breached = True
        score -= 60
        warnings.append('Found in the offline breach database (HIBP-style local hash set).')
        patterns.append('Offline breach hit')
        score_cap = _cap(score_cap, 30, 'offline breach dataset hit', caps)

    effective_entropy = raw_entropy
    pattern_penalty = 0
    if common_hit:
        pattern_penalty += 75
    if keyboard_hit:
        pattern_penalty += 42
    if season_hit or month_hit:
        pattern_penalty += 32
    if dictionary_tokens:
        pattern_penalty += min(40, 8 * len(dictionary_tokens))
    if has_year or has_date:
        pattern_penalty += 18
    if weak_base_hit:
        pattern_penalty += 28
    if weak_word_plus_suffix:
        pattern_penalty += 12
    if context_hit:
        pattern_penalty += 24
    if re.search(r'(.)\1{2,}', password) or _has_sequence(password):
        pattern_penalty += 16
    if short_sequence_hit:
        pattern_penalty += 12
    if repeated_short_block:
        pattern_penalty += 16
    effective_entropy = max(0.0, raw_entropy - pattern_penalty)
    if is_passphrase:
        passphrase_entropy = float(passphrase_profile.get('entropy_bits', 0.0) or 0.0)
        if passphrase_profile.get('known_phrase'):
            effective_entropy = min(effective_entropy, 38.0)
        elif passphrase_entropy:
            effective_entropy = max(effective_entropy, min(passphrase_entropy, 84.0))

    if effective_entropy < 35:
        score -= 20
        warnings.append('Effective entropy is low after removing predictable pattern value.')
    elif effective_entropy < 55:
        score -= 10
    elif effective_entropy >= 85 and not patterns:
        score += 2

    if score_cap is not None:
        score = min(score, score_cap)

    score = max(0, min(100, score))
    label = _label(score)

    if length < 16:
        suggestions.append('Consider a 16+ character password or passphrase.')
    if breached:
        suggestions.append('Rotate this password immediately because it appears in the local breach dataset.')
    if patterns:
        suggestions.append('Replace predictable words, dates, keyboard walks, or context terms with a generated random value.')
    if score < 85 and not breached:
        suggestions.append('Use the generator to create a unique 16+ character password for this account.')

    deduped_suggestions: list[str] = []
    for item in suggestions:
        if item not in deduped_suggestions:
            deduped_suggestions.append(item)

    cap_reason = ''
    if caps:
        cap_reason = min(caps, key=lambda item: item[0])[1]
    remediation_advice = deduped_suggestions[0] if deduped_suggestions else 'Keep this password unique and monitor reuse/breach exposure.'

    return PasswordAnalysis(
        score=score,
        label=label,
        entropy_bits=round(effective_entropy, 1),
        entropy_note=entropy_note(effective_entropy, raw_entropy=raw_entropy, cap_reason=cap_reason),
        warnings=warnings,
        suggestions=deduped_suggestions,
        patterns=sorted(set(patterns)),
        breached=breached,
        raw_entropy_bits=round(raw_entropy, 1),
        effective_entropy_bits=round(effective_entropy, 1),
        score_cap=score_cap,
        score_cap_reason=cap_reason,
        remediation_advice=remediation_advice,
        passphrase_model=str(passphrase_profile.get('model_note', '')).strip() if 'passphrase_profile' in locals() else '',
        passphrase_entropy_bits=round(float(passphrase_profile.get('entropy_bits', 0.0) or 0.0), 1) if 'passphrase_profile' in locals() else 0.0,
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
    normalized_password = _leet_normalize(password)
    raw_without_suffix = re.sub(r'(?:\d{2,4}|[!@#$%^&*])+$', '', password)
    normalized_stem = _leet_normalize(raw_without_suffix)
    common_hit = (
        lowered in COMMON_PASSWORDS
        or normalized_password in COMMON_PASSWORDS
        or normalized_stem in COMMON_PASSWORDS
        or normalized_stem in WEAK_BASE_WORDS
    )
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
        'entropy_bits': analysis.effective_entropy_bits,
        'raw_entropy_bits': analysis.raw_entropy_bits,
        'effective_entropy_bits': analysis.effective_entropy_bits,
        'score_cap': analysis.score_cap,
        'score_cap_reason': analysis.score_cap_reason,
        'remediation_advice': analysis.remediation_advice,
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
        # Local Security Coach, and reports consistent: a critical password cannot still
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
