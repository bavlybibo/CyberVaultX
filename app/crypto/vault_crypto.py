from __future__ import annotations

from ..crypto_utils import decrypt_text, encrypt_text


def encrypt_secret(value: str, key: bytes, *, aad: str | bytes | None = None) -> dict[str, str]:
    nonce, ciphertext = encrypt_text(value, key, aad=aad)
    return {"nonce": nonce, "ciphertext": ciphertext}


def decrypt_secret(payload: dict[str, str], key: bytes, *, aad: str | bytes | None = None) -> str:
    return decrypt_text(payload["nonce"], payload["ciphertext"], key, aad=aad)
