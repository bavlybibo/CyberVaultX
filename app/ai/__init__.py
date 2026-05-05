"""Privacy-preserving AI integration package for CyberVault X.

AI features must consume only redacted vault telemetry. Never pass raw passwords,
master passwords, full usernames, notes, backup blobs, paths, or database contents
to an external model.
"""

from .advisor import (
    build_optional_llm_payload,
    build_redacted_advisor_context,
    generate_local_security_plan,
)
from .insights import build_change_summary, simulate_fix_impact
from .security_coach import build_local_security_coach, coach_findings_from_security_rows

__all__ = [
    'build_optional_llm_payload',
    'build_redacted_advisor_context',
    'generate_local_security_plan',
    'build_change_summary',
    'simulate_fix_impact',
    'build_local_security_coach',
    'coach_findings_from_security_rows',
]
