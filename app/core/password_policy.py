from __future__ import annotations

from dataclasses import dataclass
import re

WEAK_MARKERS = (
    "password", "passw0rd", "qwerty", "123456", "admin", "letmein",
    "welcome", "iloveyou", "monkey", "football", "dragon", "trustno1",
)
SEQUENTIAL_PATTERNS = ("1234", "2345", "3456", "4567", "5678", "6789", "abcd", "qwerty", "asdf")


@dataclass(slots=True)
class MasterPasswordPolicyResult:
    ok: bool
    score: int
    reasons: list[str]
    suggestions: list[str]


def _character_groups(value: str) -> int:
    return sum([
        any(ch.islower() for ch in value),
        any(ch.isupper() for ch in value),
        any(ch.isdigit() for ch in value),
        any(not ch.isalnum() for ch in value),
    ])


def validate_master_password_policy(password: str, owner_name: str = "", *, min_length: int = 12) -> MasterPasswordPolicyResult:
    """Validate master-password quality without logging or returning the secret.

    The checks are intentionally deterministic and explainable so UI, tests, and
    documentation can all describe the same security model. The function returns
    generic reasons only; it never echoes the password.
    """
    password = password or ""
    lowered = password.lower()
    reasons: list[str] = []
    suggestions: list[str] = []
    score = 100

    if len(password) < min_length:
        score -= 45
        reasons.append(f"Master password must be at least {min_length} characters.")
        suggestions.append("Use a longer passphrase or generated master secret.")
    elif len(password) < 16:
        score -= 10
        suggestions.append("16+ characters is recommended for a master password.")
    else:
        score += 2

    groups = _character_groups(password)
    if groups < 3:
        score -= 25
        reasons.append("Master password must include at least 3 of: lowercase, uppercase, number, symbol.")
        suggestions.append("Mix character groups or use a memorable multi-word passphrase with digits/symbols.")

    if any(marker in lowered for marker in WEAK_MARKERS):
        score -= 40
        reasons.append("Master password is too predictable. Avoid common weak patterns.")
        suggestions.append("Avoid dictionary words such as password, admin, welcome, or keyboard walks.")

    if any(pattern in lowered for pattern in SEQUENTIAL_PATTERNS):
        score -= 15
        reasons.append("Master password contains a predictable sequence or keyboard pattern.")
        suggestions.append("Break sequential patterns and prefer random words or generated characters.")

    if re.search(r"(.)\1{3,}", password):
        score -= 12
        reasons.append("Master password contains excessive repeated characters.")

    owner = (owner_name or "").strip().lower()
    if owner and len(owner) >= 3 and owner in lowered:
        score -= 25
        reasons.append("Master password should not contain the owner name.")
        suggestions.append("Keep personal names, usernames, and project names out of the master password.")

    score = max(0, min(100, score))
    return MasterPasswordPolicyResult(ok=not reasons, score=score, reasons=reasons, suggestions=suggestions)
