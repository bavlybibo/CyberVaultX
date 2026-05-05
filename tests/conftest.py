from __future__ import annotations

from app import crypto_utils

# Keep test suite fast; production constants remain high in normal runtime.
crypto_utils.MIN_BACKUP_KDF_ITERATIONS = 2
crypto_utils.PBKDF2_ITERATIONS = 2
