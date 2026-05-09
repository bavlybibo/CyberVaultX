from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from app import crypto_utils
from app.manager import VaultManager

crypto_utils.MIN_BACKUP_KDF_ITERATIONS = 2
crypto_utils.PBKDF2_ITERATIONS = 2


class BonusFeaturesTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tmp.name) / 'vault.db'
        self.manager = VaultManager(self.db_path)
        self.manager.setup_master_password('Bavly', 'Strong!VaultPass123')
        self.manager.add_credential(
            title='Bank Main', username='bank.person@example.com', password='Password2026!',
            category='Banking', tags='finance', notes='private bank note', website='bank.example.com', is_favorite=True,
        )
        self.manager.add_credential(
            title='Bank Backup', username='backup@example.com', password='Password2027!',
            category='Banking', tags='finance', notes='', website='bank.example.com', is_favorite=False,
        )
        self.manager.add_credential(
            title='Random Dev', username='dev@example.com', password='bN7!qzP4@Lw9#sT2',
            category='Work', tags='developer', notes='', website='dev.example.com', is_favorite=False,
        )

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_privacy_export_preview_is_explainable_and_secret_free(self) -> None:
        preview = self.manager.privacy_export_preview(privacy_level='minimal')
        rendered = json.dumps(preview, ensure_ascii=False)
        self.assertEqual(preview['privacy_scan_status'], 'PASS')
        self.assertIn('field_matrix', preview)
        for forbidden in ('Password2026!', 'bank.person@example.com', 'private bank note', 'bank.example.com'):
            self.assertNotIn(forbidden, rendered)
        self.assertIn('Credential #', rendered)

    def test_password_relationship_graph_finds_near_duplicate_without_secrets(self) -> None:
        graph = self.manager.password_relationship_graph()
        rendered = json.dumps(graph, ensure_ascii=False)
        self.assertGreaterEqual(graph['cluster_count'], 1)
        self.assertTrue(any(cluster['type'] in {'near_duplicate_base_pattern', 'same_site_multiple_records'} for cluster in graph['clusters']))
        for forbidden in ('Password2026!', 'Password2027!', 'bank.person@example.com', 'Bank Main', 'bank.example.com'):
            self.assertNotIn(forbidden, rendered)

    def test_remediation_planner_groups_actions_without_identifiers(self) -> None:
        plan = self.manager.remediation_planner()
        rendered = json.dumps(plan, ensure_ascii=False)
        self.assertIn('today', plan)
        self.assertTrue(plan['today'] or plan['this_week'])
        self.assertIn('local remediation plan', plan['method'].lower())
        for forbidden in ('Password2026!', 'bank.person@example.com', 'Bank Main'):
            self.assertNotIn(forbidden, rendered)

    def test_attack_simulation_lab_passes_core_defensive_checks(self) -> None:
        result = self.manager.attack_simulation_lab()
        self.assertEqual(result['overall_status'], 'PASS', result)
        names = {item['name'] for item in result['simulations']}
        self.assertIn('Plaintext DB secret scan', names)
        self.assertIn('Tampered encrypted backup rejection', names)
        self.assertIn('Adversarial analyzer check', names)
        self.assertTrue(all(item['result'] == 'BLOCKED' for item in result['simulations']))

    def test_generator_plus_keeps_random_profile_excellent(self) -> None:
        generated = self.manager.generate_password_plus(profile='Banking', length=24)
        self.assertEqual(generated['analysis']['label'], 'Excellent')
        self.assertGreaterEqual(generated['analysis']['score'], 85)
        self.assertFalse(generated['store_history'])
        self.assertGreaterEqual(generated['length'], 24)

    def test_emergency_kit_exports_manifest_without_raw_secrets(self) -> None:
        kit_dir = Path(self.tmp.name) / 'emergency_kit'
        self.manager.create_emergency_kit(kit_dir, backup_passphrase='Backup!Passphrase123')
        self.assertTrue((kit_dir / 'manifest.json').exists())
        combined = '\n'.join(path.read_text(encoding='utf-8', errors='ignore') for path in kit_dir.iterdir() if path.is_file() and path.suffix != '.cvxbackup')
        for forbidden in ('Password2026!', 'bank.person@example.com', 'private bank note', 'Strong!VaultPass123', 'Backup!Passphrase123'):
            self.assertNotIn(forbidden, combined)
        manifest = json.loads((kit_dir / 'manifest.json').read_text(encoding='utf-8'))
        self.assertTrue(manifest['backup_included'])
        self.assertFalse(manifest['contains_raw_passwords'])

    def test_security_evidence_package_contains_bonus_artifacts_and_redacts(self) -> None:
        evidence_dir = Path(self.tmp.name) / 'evidence_package'
        self.manager.export_security_evidence_package(evidence_dir)
        expected = {
            'proof_center.json', 'attack_simulation_lab.json', 'privacy_export_preview.json',
            'password_relationship_graph.json', 'remediation_planner.json', 'security_timeline.json',
            'backup_integrity_status.json', 'clipboard_safety_status.json', 'manifest.json',
        }
        self.assertTrue(expected.issubset({path.name for path in evidence_dir.iterdir()}))
        combined = '\n'.join(path.read_text(encoding='utf-8', errors='ignore') for path in evidence_dir.iterdir() if path.is_file())
        for forbidden in ('Password2026!', 'Password2027!', 'bank.person@example.com', 'private bank note', 'Bank Main', 'bank.example.com'):
            self.assertNotIn(forbidden, combined)
        manifest = json.loads((evidence_dir / 'manifest.json').read_text(encoding='utf-8'))
        self.assertEqual(manifest['package'], 'CyberVaultX Security Evidence Package')


if __name__ == '__main__':
    unittest.main()
