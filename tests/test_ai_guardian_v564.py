from __future__ import annotations

import unittest

from app.ai.advisor import build_redacted_advisor_context, generate_local_security_plan


class AIGuardianPrecisionTests(unittest.TestCase):
    def _sample_metrics(self) -> dict:
        return {
            'total': 3,
            'health_score': 52,
            'weak': 1,
            'breached': 1,
            'reused_passwords': 2,
            'old': 1,
            'missing_fields': 1,
            'trashed': 0,
        }

    def _sample_findings(self) -> list[dict]:
        return [
            {
                'id': 7,
                'username': 'alice.admin@example.com',
                'category': 'Email',
                'risk_level': 'Critical',
                'score': 34,
                'issues': [
                    'Found in the offline breach database (HIBP-style local hash set).',
                    'Reused password across 2 accounts.',
                    'Password is older than 90 days.',
                ],
                'breached': True,
                'common_password': False,
                'reuse_count': 2,
                'old_password': True,
            },
            {
                'id': 8,
                'username': 'devops@example.com',
                'category': 'Servers',
                'risk_level': 'High',
                'score': 58,
                'issues': ['Too short. Minimum recommended length is 12+ characters.'],
                'breached': False,
                'common_password': False,
                'reuse_count': 1,
                'old_password': False,
            },
        ]

    def test_precision_plan_contains_explainability_fields(self) -> None:
        plan = generate_local_security_plan(self._sample_metrics(), self._sample_findings())
        top = plan['priority_items'][0]
        self.assertIn('Site Policy Reasoner', plan['mode'])
        self.assertIn('confidence_percent', top)
        self.assertIn('primary_signal', top)
        self.assertIn('exposure_path', top)
        self.assertIn('decision_trace', top)
        self.assertGreaterEqual(top['confidence_percent'], 70)
        self.assertTrue(plan['decision_matrix'])
        self.assertTrue(plan['quality_gates'])
        self.assertTrue(plan['posture_heatmap'])

    def test_site_policy_reasoner_prioritizes_underfit_high_value_account(self) -> None:
        findings = self._sample_findings()
        findings[1].update({
            'site_profile': 'Infrastructure / Admin Console',
            'site_fit_score': 42,
            'site_fit_label': 'Risky Fit',
            'site_policy': {'requirements': ['Recommended length 26+ characters']},
            'issues': findings[1]['issues'] + ['Below inferred site-policy fit: Infrastructure / Admin Console (42/100).'],
        })
        plan = generate_local_security_plan(self._sample_metrics(), findings)
        serialized = str(plan['priority_items'])
        self.assertIn('site-fit', serialized.lower())
        self.assertIn('Infrastructure / Admin Console', serialized)


    def test_redacted_context_does_not_include_full_username(self) -> None:
        context = build_redacted_advisor_context(self._sample_metrics(), self._sample_findings())
        serialized = str(context)
        self.assertNotIn('alice.admin@example.com', serialized)
        self.assertNotIn('devops@example.com', serialized)
        self.assertNotIn("'password':", serialized.lower())
        self.assertIn('credential #7', serialized)


if __name__ == '__main__':
    unittest.main()
