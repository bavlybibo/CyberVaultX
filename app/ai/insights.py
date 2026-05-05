from __future__ import annotations

from typing import Any


def build_change_summary(metrics: dict[str, Any], previous_metrics: dict[str, Any] | None = None) -> list[str]:
    current_score = int(metrics.get('health_score', 0) or 0)
    if not previous_metrics:
        return [
            f'Baseline captured: current vault health is {current_score}/100.',
            'No previous AI Guardian snapshot is stored yet; export a report after fixes to compare future progress.',
        ]

    previous_score = int(previous_metrics.get('health_score', current_score) or current_score)
    delta = current_score - previous_score
    direction = 'improved' if delta > 0 else 'dropped' if delta < 0 else 'stayed stable'
    lines = [f'Vault health {direction}: {previous_score}/100 → {current_score}/100 ({delta:+d}).']
    for key, label in [
        ('breached', 'offline breach/common hits'),
        ('reused_passwords', 'reused passwords'),
        ('weak', 'weak passwords'),
        ('old', 'old credentials'),
        ('missing_fields', 'metadata gaps'),
    ]:
        before = int(previous_metrics.get(key, 0) or 0)
        after = int(metrics.get(key, 0) or 0)
        if before != after:
            lines.append(f'{label}: {before} → {after} ({after - before:+d}).')
    if len(lines) == 1:
        lines.append('No major risk-driver movement was detected since the previous snapshot.')
    return lines


def simulate_fix_impact(metrics: dict[str, Any], priority_items: list[dict[str, Any]]) -> dict[str, Any]:
    current = int(metrics.get('health_score', 0) or 0)
    top_items = priority_items[:3]
    gain = 0
    fixes: list[str] = []
    for item in top_items:
        risk = str(item.get('risk_level', 'Low'))
        if risk == 'Critical':
            gain += 9
        elif risk == 'High':
            gain += 6
        elif risk == 'Moderate':
            gain += 3
        else:
            gain += 1
        action = str(item.get('recommended_action', 'Review this credential.'))
        fixes.append(f"{item.get('credential_ref', 'Credential')}: {action}")
    projected = min(100, current + gain)
    return {
        'current_score': current,
        'projected_score': projected,
        'estimated_gain': projected - current,
        'assumptions': [
            'Estimate assumes the top priority items are rotated or remediated successfully.',
            'Real score changes depend on whether reuse chains, weak passwords, and metadata gaps are fully fixed.',
        ],
        'top_fixes': fixes or ['No priority fixes are currently required.'],
    }
