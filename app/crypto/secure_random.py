from __future__ import annotations

import secrets


def random_bytes(length: int = 32) -> bytes:
    return secrets.token_bytes(max(1, int(length)))


def random_token(length: int = 32) -> str:
    return secrets.token_urlsafe(max(16, int(length)))
