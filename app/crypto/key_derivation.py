from __future__ import annotations

from ..crypto_utils import MasterRecord, create_master_record as _create, derive_key, verify_master_password


def derive_master_key(password: str, salt: bytes, *, iterations: int | None = None) -> bytes:
    return derive_key(password, salt, iterations=iterations)


def create_master_record(password: str) -> MasterRecord:
    return _create(password)


def verify_master_record(password: str, record: MasterRecord) -> tuple[bool, bytes | None]:
    return verify_master_password(password, record)
