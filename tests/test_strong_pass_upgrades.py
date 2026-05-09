from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from app import crypto_utils
from app.analyzer import analyze_password
from app.manager import VaultManager
from app.services.signing import REPORT_SIGNATURE_ALGORITHM

crypto_utils.MIN_BACKUP_KDF_ITERATIONS = 2
crypto_utils.PBKDF2_ITERATIONS = 2


class StrongPassUpgradeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.manager = VaultManager(Path(self.tmp.name) / 'real.db')
        self.manager.setup_master_password('Bavly', 'Strong!VaultPass123')

    def tearDown(self) -> None:
        self.manager.db.close()
        self.tmp.cleanup()

    def test_isolated_demo_vault_does_not_mutate_real_vault(self) -> None:
        self.manager.add_credential(
            title='Real Credential', username='real@example.com', password='Real!Secret12345',
            category='Work', tags='real', notes='real user note', website='real.example.com', is_favorite=False,
        )
        before = [(item.title, item.username, item.website) for item in self.manager.list_credentials(include_deleted=True)]
        demo_manager, stats = self.manager.create_isolated_demo_vault(Path(self.tmp.name) / 'demo')
        try:
            self.assertTrue(stats['isolated'])
            self.assertFalse(stats['real_vault_modified'])
            self.assertTrue(demo_manager.is_demo_vault)
            self.assertEqual(demo_manager.demo_vault_banner, 'DEMO VAULT — synthetic data only')
            self.assertGreaterEqual(stats['created'], 8)
            self.assertGreater(len(demo_manager.list_credentials(include_deleted=True)), 1)
            after = [(item.title, item.username, item.website) for item in self.manager.list_credentials(include_deleted=True)]
            self.assertEqual(before, after)
            self.assertFalse(self.manager.is_demo_vault)
        finally:
            demo_manager.db.close()

    def test_passphrase_model_penalizes_famous_phrase_but_accepts_generated_style(self) -> None:
        famous = analyze_password('correct horse battery staple')
        self.assertNotEqual(famous.label, 'Excellent')
        self.assertLessEqual(famous.score, 55)
        self.assertIn('Famous passphrase', famous.patterns)
        self.assertIn('Passphrase model:', famous.passphrase_model)
        self.assertIn('randomly generated', ' '.join(famous.warnings + famous.suggestions))

        generated_like = analyze_password('river orbit velvet marble lantern')
        self.assertNotEqual(generated_like.label, 'Very Weak')
        self.assertGreaterEqual(generated_like.score, 70)
        self.assertIn('Passphrase model', generated_like.patterns)
        self.assertIn('passphrase randomness cannot be proven locally', generated_like.score_cap_reason)
        self.assertIn('heuristic', generated_like.passphrase_model.lower())

    def test_proof_center_is_worded_as_local_integrity_not_independent_attestation(self) -> None:
        proof = self.manager.security_proof_center()
        rendered = json.dumps(proof, ensure_ascii=False).lower()
        self.assertIn('local-integrity', REPORT_SIGNATURE_ALGORITHM.lower())
        self.assertIn('not independently verifiable', rendered)
        self.assertNotIn('independent verification', rendered)


if __name__ == '__main__':
    unittest.main()
