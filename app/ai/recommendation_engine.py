from __future__ import annotations


def recommended_action_for_issues(issues: list[str], *, risk_level: str = "Low") -> str:
    joined = " ".join(issues).lower()
    if "breach" in joined or risk_level == "Critical":
        return "Rotate immediately, make it unique, and enable MFA where available."
    if "reuse" in joined or "reused" in joined:
        return "Replace reused passwords with unique generated passwords."
    if "short" in joined or "entropy" in joined or "weak" in joined:
        return "Generate a longer 16+ character password and update the saved credential."
    if "old" in joined:
        return "Review the account and rotate the password if it protects sensitive access."
    return "Review this item during the next vault hygiene session."
