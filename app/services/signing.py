from __future__ import annotations

import base64
import hashlib
import hmac
import json
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

REPORT_SIGNATURE_ALGORITHM = 'HMAC-SHA256/local-integrity-proof'
PUBLIC_SIGNATURE_ALGORITHM = 'Ed25519/public-manifest-signature-v1'

# Signature values are never part of the signed material.  The legacy
# signature_algorithm field is also excluded so older local HMAC signatures can
# still be recomputed by tools that know the vault-local secret.
_UNSIGNED_FIELDS = {
    'manifest_signature',
    'public_manifest_signature',
    'signature_algorithm',
}


def canonical_manifest_payload(manifest: dict[str, Any]) -> bytes:
    """Return deterministic bytes for report-package integrity signatures."""
    clone = {key: value for key, value in dict(manifest).items() if key not in _UNSIGNED_FIELDS}
    return json.dumps(clone, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode('utf-8')


def signing_key_fingerprint(secret: str) -> str:
    return hashlib.sha256(secret.encode('utf-8')).hexdigest()[:16] if secret else ''


def sign_manifest(manifest: dict[str, Any], secret: str) -> str:
    return hmac.new(secret.encode('utf-8'), canonical_manifest_payload(manifest), hashlib.sha256).hexdigest()


def verify_manifest_signature(manifest: dict[str, Any], secret: str) -> bool:
    expected = str(manifest.get('manifest_signature', ''))
    if not expected or not secret:
        return False
    actual = sign_manifest(manifest, secret)
    return hmac.compare_digest(expected, actual)


def generate_public_signing_private_key_b64() -> str:
    """Create a portable raw Ed25519 private key encoded as base64."""
    key = Ed25519PrivateKey.generate()
    raw = key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return base64.b64encode(raw).decode('ascii')


def _load_private_key(private_key_b64: str) -> Ed25519PrivateKey:
    raw = base64.b64decode(private_key_b64.encode('ascii'), validate=True)
    if len(raw) != 32:
        raise ValueError('Invalid Ed25519 private key length.')
    return Ed25519PrivateKey.from_private_bytes(raw)


def _load_public_key(public_key_b64: str) -> Ed25519PublicKey:
    raw = base64.b64decode(public_key_b64.encode('ascii'), validate=True)
    if len(raw) != 32:
        raise ValueError('Invalid Ed25519 public key length.')
    return Ed25519PublicKey.from_public_bytes(raw)


def public_key_b64_from_private(private_key_b64: str) -> str:
    public_key = _load_private_key(private_key_b64).public_key()
    raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return base64.b64encode(raw).decode('ascii')


def public_key_fingerprint(public_key_b64: str) -> str:
    return hashlib.sha256(public_key_b64.encode('ascii')).hexdigest()[:16] if public_key_b64 else ''


def sign_manifest_public(manifest: dict[str, Any], private_key_b64: str) -> str:
    signature = _load_private_key(private_key_b64).sign(canonical_manifest_payload(manifest))
    return base64.b64encode(signature).decode('ascii')


def verify_manifest_public_signature(manifest: dict[str, Any]) -> bool:
    signature_b64 = str(manifest.get('public_manifest_signature', ''))
    public_key_b64 = str(manifest.get('signing_public_key_b64', ''))
    expected_fingerprint = str(manifest.get('signing_public_key_fingerprint', ''))
    if not signature_b64 or not public_key_b64:
        return False
    if expected_fingerprint and not hmac.compare_digest(expected_fingerprint, public_key_fingerprint(public_key_b64)):
        return False
    try:
        signature = base64.b64decode(signature_b64.encode('ascii'), validate=True)
        _load_public_key(public_key_b64).verify(signature, canonical_manifest_payload(manifest))
        return True
    except Exception:
        return False
