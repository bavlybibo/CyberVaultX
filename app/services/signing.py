from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any

REPORT_SIGNATURE_ALGORITHM = 'HMAC-SHA256/local-vault-key'


def canonical_manifest_payload(manifest: dict[str, Any]) -> bytes:
    """Return canonical bytes for report package signing.

    The signature fields are excluded so verification can recompute the exact
    material that was signed during export.
    """
    clone = dict(manifest)
    clone.pop('manifest_signature', None)
    clone.pop('signature_algorithm', None)
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
