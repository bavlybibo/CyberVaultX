# CyberVault X — Grading Evidence Map

| Requirement | Where implemented | Evidence file/test | How to verify |
|---|---|---|---|
| Local encrypted storage | `app/crypto_utils.py`, `app/manager.py`, `app/db.py` | `tests/test_crypto.py` | Run `python -m pytest -q tests/test_crypto.py` |
| Master password and KDF | `app/crypto_utils.py`, `app/core/password_policy.py` | `tests/test_core_policy_and_health.py` | Verify weak master passwords are rejected and PBKDF2 metadata is stored |
| Password analysis | `app/analyzer.py`, `app/services/analysis.py` | `tests/test_product_upgrade.py::ProductUpgradeTests::test_password_fix_simulator_produces_explainable_output` | Add weak/reused credentials and check Security Center findings |
| Local Security Coach | `app/ai/`, `app/services/ai_guardian.py` | `tests/test_ai_guardian_v564.py`, `tests/test_live_coach_ai_ui_v566.py` | Confirm recommendations include evidence, confidence, and rule-based mode |
| Audit hash-chain integrity | `app/db.py`, `app/services/proof.py` | `tests/test_v551_hardening.py`, `tests/test_product_upgrade.py::ProductUpgradeTests::test_audit_timeline_generation_from_logs` | Run Proof Center or verify audit chain from tests |
| Report export | `app/services/reporting.py` | `tests/test_product_hardening.py`, `tests/test_product_upgrade.py::ProductUpgradeTests::test_report_package_writes_verification_output` | Export package and verify generated artifacts |
| Privacy-safe export | `app/services/product_upgrade.py`, `app/services/reporting.py` | `tests/test_product_upgrade.py::ProductUpgradeTests::test_privacy_safe_export_check_does_not_leak_raw_secrets` | Search exported report for raw password, notes, owner identity, and local paths |
| Manifest verification | `app/services/proof.py`, `verify_report_package.py` | `tests/test_product_hardening.py::ProductHardeningTests::test_report_package_verifier_detects_tampering` | Modify an exported file and verify detection |
| Backup and restore preview | `app/services/backup.py` | `tests/test_manager.py`, `tests/test_product_upgrade.py::ProductUpgradeTests::test_backup_and_clipboard_status_are_product_safe` | Export encrypted backup and run non-destructive preview |
| Custom offline SHA1 breach list | `app/breach_db.py`, `app/services/product_upgrade.py` | `tests/test_product_upgrade.py::ProductUpgradeTests::test_custom_breach_list_import_validates_sha1_and_affects_offline_lookup` | Import a local SHA1 list and confirm matching password is flagged |
| Report readiness score | `app/services/product_upgrade.py`, `app/ui_refresh.py` | `tests/test_product_upgrade.py::ProductUpgradeTests::test_report_readiness_score_is_explainable` | Review percentage, warnings, blockers, and privacy status |
| CSV import safety | `app/ui_controllers.py` | manual UI path + regression import tests | Check file-size and row-limit blocking before import wizard opens |
| Limitations | `README.md`, `docs/SECURITY_MODEL.md`, `docs/LIMITATIONS.md` | documentation review | Confirm claims match implemented controls |
