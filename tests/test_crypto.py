from __future__ import annotations

import copy
import unittest

from app import crypto_utils
from app.crypto_utils import BACKUP_CONTEXT, decrypt_backup_json, encrypt_backup_json, encrypt_text, decrypt_text, encrypt_bytes, derive_key, _b64d, _payload_digest

# Keep unit tests quick while production defaults remain high.
crypto_utils.MIN_BACKUP_KDF_ITERATIONS = 2
crypto_utils.PBKDF2_ITERATIONS = 2


class BackupCryptoTests(unittest.TestCase):
    def test_backup_roundtrip_and_integrity(self) -> None:
        payload = {'hello': 'world', 'count': 2}
        encrypted = encrypt_backup_json(payload, 'Backup!Passphrase123')
        restored = decrypt_backup_json(encrypted, 'Backup!Passphrase123')
        self.assertEqual(restored, payload)

    def test_backup_wrong_passphrase_fails(self) -> None:
        payload = {'hello': 'world'}
        encrypted = encrypt_backup_json(payload, 'Backup!Passphrase123')
        with self.assertRaises(Exception):
            decrypt_backup_json(encrypted, 'wrong-passphrase')

    def test_backup_passphrase_policy_rejects_short_or_weak_values(self) -> None:
        with self.assertRaises(ValueError):
            encrypt_backup_json({'x': 1}, 'short')
        with self.assertRaises(ValueError):
            encrypt_backup_json({'x': 1}, 'passwordpassword')

    def test_backup_uses_kdf_metadata_and_rejects_downgrade(self) -> None:
        encrypted = encrypt_backup_json({'x': 1}, 'Backup!Passphrase123')
        tampered = copy.deepcopy(encrypted)
        tampered['kdf']['iterations'] = 1
        with self.assertRaises(ValueError):
            decrypt_backup_json(tampered, 'Backup!Passphrase123')


    def test_legacy_backup_without_aad_is_opt_in(self) -> None:
        payload = {'legacy': True}
        modern = encrypt_backup_json(payload, 'Backup!Passphrase123')
        key = derive_key('Backup!Passphrase123', _b64d(modern['kdf']['salt']), iterations=modern['kdf']['iterations'])
        legacy_cipher = encrypt_bytes(b'{"legacy": true}', key, aad=None)
        legacy = dict(modern)
        legacy.update(legacy_cipher)
        legacy['payload_sha256'] = _payload_digest(payload)

        with self.assertRaises(ValueError):
            decrypt_backup_json(legacy, 'Backup!Passphrase123')
        self.assertEqual(decrypt_backup_json(legacy, 'Backup!Passphrase123', allow_legacy_aad_fallback=True), payload)

    def test_text_encryption_aad_blocks_context_swaps(self) -> None:
        key = b'K' * 32
        nonce, cipher = encrypt_text('secret', key, aad='field:password')
        self.assertEqual(decrypt_text(nonce, cipher, key, aad='field:password'), 'secret')
        with self.assertRaises(Exception):
            decrypt_text(nonce, cipher, key, aad='field:title')


if __name__ == '__main__':
    unittest.main()
