from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
from dataclasses import dataclass
from typing import Any

try:
    from Crypto.Cipher import AES  # type: ignore
    from Crypto.Protocol.KDF import PBKDF2  # type: ignore
    from Crypto.Hash import SHA256  # type: ignore
    HAS_PYCRYPTODOME = True
except Exception:  # pragma: no cover
    HAS_PYCRYPTODOME = False
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

PBKDF2_ITERATIONS = 600_000
MIN_BACKUP_KDF_ITERATIONS = 300_000
KEY_LENGTH = 32
BACKUP_FORMAT = 'CyberVaultBackup/v3'
BACKUP_CONTEXT = b'cybervault-backup-v3'
BACKUP_MIN_PASSPHRASE_LENGTH = 14
LEGACY_BACKUP_AAD_FALLBACK_ENV = 'CYBERVAULTX_ALLOW_LEGACY_BACKUP_AAD_FALLBACK'


@dataclass(slots=True)
class MasterRecord:
    salt_b64: str
    verifier_b64: str


def _b64e(data: bytes) -> str:
    return base64.b64encode(data).decode('utf-8')


def _b64d(value: str) -> bytes:
    return base64.b64decode(value.encode('utf-8'))


def _aad_bytes(aad: str | bytes | None) -> bytes | None:
    if aad is None:
        return None
    return aad if isinstance(aad, bytes) else aad.encode('utf-8')


def derive_key(password: str, salt: bytes, *, iterations: int | None = None) -> bytes:
    iterations = PBKDF2_ITERATIONS if iterations is None else iterations
    if iterations < MIN_BACKUP_KDF_ITERATIONS:
        raise ValueError('KDF iteration count is below the safe minimum.')
    if HAS_PYCRYPTODOME:
        return PBKDF2(password.encode('utf-8'), salt, dkLen=KEY_LENGTH, count=iterations, hmac_hash_module=SHA256)
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=KEY_LENGTH, salt=salt, iterations=iterations)
    return kdf.derive(password.encode('utf-8'))


def create_master_record(password: str) -> MasterRecord:
    salt = os.urandom(16)
    key = derive_key(password, salt)
    verifier = hashlib.sha256(key + b'cybervault-verifier-v3').digest()
    return MasterRecord(salt_b64=_b64e(salt), verifier_b64=_b64e(verifier))


def verify_master_password(password: str, record: MasterRecord) -> tuple[bool, bytes | None]:
    salt = _b64d(record.salt_b64)
    key = derive_key(password, salt)
    verifier = hashlib.sha256(key + b'cybervault-verifier-v3').digest()
    is_valid = hmac.compare_digest(verifier, _b64d(record.verifier_b64))
    return is_valid, key if is_valid else None


def validate_backup_passphrase(passphrase: str) -> None:
    if len(passphrase) < BACKUP_MIN_PASSPHRASE_LENGTH:
        raise ValueError(f'Backup passphrase must be at least {BACKUP_MIN_PASSPHRASE_LENGTH} characters.')
    checks = sum([
        any(ch.islower() for ch in passphrase),
        any(ch.isupper() for ch in passphrase),
        any(ch.isdigit() for ch in passphrase),
        any(not ch.isalnum() for ch in passphrase),
    ])
    if checks < 3:
        raise ValueError('Backup passphrase must include at least 3 of these groups: lowercase, uppercase, number, symbol.')
    lowered = passphrase.lower()
    weak_markers = ('password', 'qwerty', '123456', 'admin', 'letmein', 'welcome')
    if any(marker in lowered for marker in weak_markers):
        raise ValueError('Backup passphrase is too predictable. Avoid common weak patterns.')


def encrypt_text(plaintext: str, key: bytes, *, aad: str | bytes | None = None) -> tuple[str, str]:
    aad_data = _aad_bytes(aad)
    if HAS_PYCRYPTODOME:
        nonce = os.urandom(12)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        if aad_data is not None:
            cipher.update(aad_data)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode('utf-8'))
        return _b64e(nonce), _b64e(ciphertext + tag)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode('utf-8'), aad_data)
    return _b64e(nonce), _b64e(ciphertext)


def decrypt_text(nonce_b64: str, ciphertext_b64: str, key: bytes, *, aad: str | bytes | None = None) -> str:
    nonce = _b64d(nonce_b64)
    raw = _b64d(ciphertext_b64)
    aad_data = _aad_bytes(aad)
    if HAS_PYCRYPTODOME:
        ciphertext, tag = raw[:-16], raw[-16:]
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        if aad_data is not None:
            cipher.update(aad_data)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext.decode('utf-8')
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, raw, aad_data)
    return plaintext.decode('utf-8')


def encrypt_bytes(blob: bytes, key: bytes, *, aad: str | bytes | None = None) -> dict[str, str]:
    aad_data = _aad_bytes(aad)
    if HAS_PYCRYPTODOME:
        nonce = os.urandom(12)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        if aad_data is not None:
            cipher.update(aad_data)
        ciphertext, tag = cipher.encrypt_and_digest(blob)
        return {'nonce': _b64e(nonce), 'ciphertext': _b64e(ciphertext + tag)}
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, blob, aad_data)
    return {'nonce': _b64e(nonce), 'ciphertext': _b64e(ciphertext)}


def decrypt_bytes(payload: dict[str, str], key: bytes, *, aad: str | bytes | None = None) -> bytes:
    nonce = _b64d(payload['nonce'])
    raw = _b64d(payload['ciphertext'])
    aad_data = _aad_bytes(aad)
    if HAS_PYCRYPTODOME:
        ciphertext, tag = raw[:-16], raw[-16:]
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        if aad_data is not None:
            cipher.update(aad_data)
        return cipher.decrypt_and_verify(ciphertext, tag)
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, raw, aad_data)


def encrypt_json(payload: dict[str, Any], key: bytes, *, aad: str | bytes | None = None) -> dict[str, Any]:
    encrypted = encrypt_bytes(json.dumps(payload, ensure_ascii=False).encode('utf-8'), key, aad=aad)
    return {'format': 'CyberVaultPayload/v1', **encrypted}


def decrypt_json(payload: dict[str, Any], key: bytes, *, aad: str | bytes | None = None) -> dict[str, Any]:
    blob = decrypt_bytes(payload, key, aad=aad)
    return json.loads(blob.decode('utf-8'))


def legacy_backup_aad_fallback_enabled(payload: dict[str, Any] | None = None) -> bool:
    """Return True only when legacy no-AAD backup restore is explicitly allowed.

    Modern CyberVault X backups are AES-GCM encrypted with backup-context AAD.
    Older demo backups may not be AAD-bound; restoring them is intentionally
    opt-in to avoid silently weakening the default restore path.
    """
    if isinstance(payload, dict) and payload.get('allow_legacy_aad_fallback') is True:
        return True
    return os.getenv(LEGACY_BACKUP_AAD_FALLBACK_ENV, '').strip().lower() in {'1', 'true', 'yes', 'on'}


def _payload_digest(payload: dict[str, Any]) -> str:
    canonical = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode('utf-8')
    return hashlib.sha256(canonical).hexdigest()


def encrypt_backup_json(payload: dict[str, Any], passphrase: str) -> dict[str, Any]:
    validate_backup_passphrase(passphrase)
    salt = os.urandom(16)
    iterations = PBKDF2_ITERATIONS
    key = derive_key(passphrase, salt, iterations=iterations)
    blob = json.dumps(payload, ensure_ascii=False).encode('utf-8')
    encrypted = encrypt_bytes(blob, key, aad=BACKUP_CONTEXT)
    return {
        'format': BACKUP_FORMAT,
        'kdf': {
            'name': 'PBKDF2-SHA256',
            'iterations': iterations,
            'salt': _b64e(salt),
            'context': _b64e(BACKUP_CONTEXT),
        },
        'payload_sha256': _payload_digest(payload),
        **encrypted,
    }


def decrypt_backup_json(payload: dict[str, Any], passphrase: str, *, allow_legacy_aad_fallback: bool | None = None) -> dict[str, Any]:
    if payload.get('format') != BACKUP_FORMAT:
        raise ValueError('Unsupported or outdated backup format.')
    kdf = payload.get('kdf') or {}
    salt_b64 = kdf.get('salt')
    if not salt_b64:
        raise ValueError('Backup is missing KDF metadata.')
    try:
        iterations = int(kdf.get('iterations') or PBKDF2_ITERATIONS)
    except (TypeError, ValueError):
        raise ValueError('Backup has invalid KDF iteration metadata.')
    if iterations < MIN_BACKUP_KDF_ITERATIONS:
        raise ValueError('Backup KDF iteration count is below the safe minimum.')
    salt = _b64d(salt_b64)
    key = derive_key(passphrase, salt, iterations=iterations)
    try:
        blob = decrypt_bytes({'nonce': payload['nonce'], 'ciphertext': payload['ciphertext']}, key, aad=BACKUP_CONTEXT)
    except Exception as exc:
        legacy_allowed = legacy_backup_aad_fallback_enabled(payload) if allow_legacy_aad_fallback is None else allow_legacy_aad_fallback
        if not legacy_allowed:
            raise ValueError(
                'Backup decryption failed. Legacy no-AAD fallback is disabled by default; '
                f'set {LEGACY_BACKUP_AAD_FALLBACK_ENV}=1 only for trusted old demo backups.'
            ) from exc
        blob = decrypt_bytes({'nonce': payload['nonce'], 'ciphertext': payload['ciphertext']}, key)
    data = json.loads(blob.decode('utf-8'))
    expected = payload.get('payload_sha256', '')
    actual = _payload_digest(data)
    if expected and not hmac.compare_digest(expected, actual):
        raise ValueError('Backup integrity check failed.')
    return data
