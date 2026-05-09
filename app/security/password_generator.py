from __future__ import annotations

import secrets
import string

DEFAULT_SYMBOLS = "!@#$%^&*()-_=+[]{};:,.?"
AMBIGUOUS = set("O0Il1|")


def _pool(include_upper: bool, include_lower: bool, include_digits: bool, include_symbols: bool, easy_read: bool) -> str:
    groups: list[str] = []
    if include_upper:
        groups.append(string.ascii_uppercase)
    if include_lower:
        groups.append(string.ascii_lowercase)
    if include_digits:
        groups.append(string.digits)
    if include_symbols:
        groups.append(DEFAULT_SYMBOLS)
    chars = "".join(groups) or (string.ascii_letters + string.digits + DEFAULT_SYMBOLS)
    if easy_read:
        chars = "".join(ch for ch in chars if ch not in AMBIGUOUS)
    return chars or string.ascii_letters + string.digits


def generate_password(
    length: int = 18,
    *,
    include_upper: bool = True,
    include_lower: bool = True,
    include_digits: bool = True,
    include_symbols: bool = True,
    easy_read: bool = False,
) -> str:
    """Generate a local cryptographically secure password."""
    length = max(12, min(128, int(length)))
    pool = _pool(include_upper, include_lower, include_digits, include_symbols, easy_read)
    required_groups = []
    if include_upper:
        required_groups.append(_pool(True, False, False, False, easy_read))
    if include_lower:
        required_groups.append(_pool(False, True, False, False, easy_read))
    if include_digits:
        required_groups.append(_pool(False, False, True, False, easy_read))
    if include_symbols:
        required_groups.append(_pool(False, False, False, True, easy_read))
    def _candidate() -> str:
        required = [secrets.choice(group) for group in required_groups if group]
        remaining = [secrets.choice(pool) for _ in range(max(0, length - len(required)))]
        chars = required + remaining
        secrets.SystemRandom().shuffle(chars)
        return "".join(chars)

    # Avoid rare flaky outputs that accidentally contain sequences, repeated runs,
    # or dictionary-looking substrings. This keeps the generator aligned with the
    # analyzer without weakening randomness or logging the generated secret.
    try:
        from ..analyzer import analyze_password
        fallback = _candidate()
        for _ in range(32):
            candidate = _candidate()
            analysis = analyze_password(candidate)
            if analysis.score >= 85 and not analysis.breached:
                return candidate
            fallback = candidate
        return fallback
    except Exception:
        return _candidate()
