from __future__ import annotations

import unittest

from app.site_policy import evaluate_password_fit, infer_account_policy


class SitePolicyReasonerTests(unittest.TestCase):
    def test_infers_email_identity_profile_from_gmail(self) -> None:
        policy = infer_account_policy(title="Gmail", username="bavly@example.com", website="https://accounts.google.com", category="General")
        self.assertEqual(policy.profile, "Email / Identity Provider")
        self.assertGreaterEqual(policy.target_length, 22)

    def test_underfit_bank_password_gets_blockers(self) -> None:
        fit = evaluate_password_fit("bank1234", title="PayPal", username="bavly@example.com", website="paypal.com", category="Banking", password_score=35)
        self.assertEqual(fit.risk_tier, "Critical")
        self.assertLess(fit.fit_score, 70)
        self.assertTrue(fit.must_fix)
        self.assertIn("Financial", fit.profile)

    def test_strong_server_password_fits_target(self) -> None:
        fit = evaluate_password_fit("Vx9!qL2@mN8#sT4%zR6&kP1", title="AWS Root", username="admin@example.com", website="aws.amazon.com", category="Servers", password_score=96)
        self.assertGreaterEqual(fit.fit_score, 80)
        self.assertIn("Infrastructure", fit.profile)
        self.assertFalse(fit.must_fix)


if __name__ == "__main__":
    unittest.main()
