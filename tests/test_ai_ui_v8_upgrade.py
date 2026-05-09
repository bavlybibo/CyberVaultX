from __future__ import annotations

import json

from app.ai.advisor import generate_local_security_plan


def test_ai_v8_adds_signal_graph_workflow_and_honest_limits_without_secrets() -> None:
    metrics = {
        'total': 2,
        'health_score': 48,
        'weak': 1,
        'breached': 1,
        'reused_passwords': 2,
        'old': 1,
        'missing_fields': 1,
        'trashed': 0,
    }
    findings = [
        {
            'id': 11,
            'username': 'admin.owner@example.com',
            'category': 'Servers',
            'risk_level': 'Critical',
            'score': 32,
            'issues': [
                'Found in the offline breach database (HIBP-style local hash set).',
                'Reused password across 2 accounts.',
                'Below inferred site-policy fit: Infrastructure / Admin Console (42/100).',
            ],
            'breached': True,
            'common_password': False,
            'reuse_count': 2,
            'old_password': True,
            'site_profile': 'Infrastructure / Admin Console',
            'site_fit_score': 42,
            'site_fit_label': 'Risky Fit',
            'site_policy': {'requirements': ['Recommended length 26+ characters']},
        }
    ]

    plan = generate_local_security_plan(metrics, findings)
    rendered = json.dumps(plan, ensure_ascii=False)

    assert 'Local Security Coach v8' in plan['mode']
    assert plan['signal_relationship_graph']['edge_count'] >= 2
    assert plan['guided_remediation_workflow']['lanes']
    assert plan['honesty_limits']['limits']
    assert plan['priority_items'][0]['risk_interlocks']
    assert 'admin.owner@example.com' not in rendered
    assert "'password':" not in rendered.lower()
