from __future__ import annotations

import unittest

from app.ai import generate_local_security_plan
from app.site_policy import build_password_coach_state


class LiveCoachAIUITests(unittest.TestCase):
    def test_live_coach_blocks_underfit_financial_password(self) -> None:
        coach = build_password_coach_state(
            'paypal2024',
            title='PayPal',
            username='bavly@example.com',
            website='paypal.com',
            category='Banking',
            password_score=35,
        )
        self.assertEqual(coach['mood'], 'danger')
        self.assertIn('Financial', coach['profile'])
        self.assertTrue(any(chip['key'] == 'sitefit' and chip['state'] == 'danger' for chip in coach['chips']))
        self.assertTrue(coach['likely_constraints'])

    def test_live_coach_ready_for_strong_server_password(self) -> None:
        coach = build_password_coach_state(
            'Vx9!qL2@mN8#sT4%zR6&kP1',
            title='AWS Root',
            username='admin@example.com',
            website='aws.amazon.com',
            category='Servers',
            password_score=96,
        )
        self.assertIn(coach['mood'], {'safe', 'good'})
        self.assertIn('Infrastructure', coach['profile'])
        self.assertGreaterEqual(coach['fit']['fit_score'], 78)

    def test_ai_plan_includes_coach_overview_without_secrets(self) -> None:
        metrics = {'total': 1, 'health_score': 55, 'breached': 0, 'reused_passwords': 0, 'weak': 1, 'old': 0, 'missing_fields': 0}
        findings = [{
            'id': 7,
            'username': 'admin@example.com',
            'category': 'Servers',
            'risk_level': 'High',
            'score': 42,
            'issues': ['Below inferred site-policy fit: Infrastructure / Admin Console (45/100).'],
            'breached': False,
            'common_password': False,
            'reuse_count': 1,
            'old_password': False,
            'site_profile': 'Infrastructure / Admin Console',
            'site_fit_score': 45,
            'site_fit_label': 'Risky Fit',
            'site_policy': {'requirements': ['Minimum length 18+ characters']},
        }]
        plan = generate_local_security_plan(metrics, findings)
        self.assertIn('coach_overview', plan)
        self.assertIn('Site Policy Reasoner', plan['mode'])
        self.assertIn('Live Coach UX', plan['mode'])
        payload_text = str(plan['optional_llm_payload']).lower()
        self.assertNotIn('admin@example.com', payload_text)
        self.assertIn('coach_overview', plan['optional_llm_payload']['user_context'])


if __name__ == '__main__':
    unittest.main()
