from __future__ import annotations

import hashlib
from collections import defaultdict
from functools import lru_cache
from pathlib import Path

DB_PATH = Path(__file__).with_name('pwned_sha1.txt')
PREFIX_LENGTH = 5


@lru_cache(maxsize=1)
def _load_hashes() -> tuple[str, ...]:
    if not DB_PATH.exists():
        return tuple()
    return tuple(line.strip().upper() for line in DB_PATH.read_text(encoding='utf-8').splitlines() if line.strip())


@lru_cache(maxsize=1)
def _load_prefix_index() -> dict[str, set[str]]:
    index: dict[str, set[str]] = defaultdict(set)
    for entry in _load_hashes():
        index[entry[:PREFIX_LENGTH]].add(entry)
    return dict(index)


def sha1_hex(value: str) -> str:
    return hashlib.sha1(value.encode('utf-8')).hexdigest().upper()


def lookup_prefix(prefix: str) -> set[str]:
    return _load_prefix_index().get(prefix.upper(), set())


def is_pwned_password(password: str) -> bool:
    if not password:
        return False
    digest = sha1_hex(password)
    return digest in lookup_prefix(digest[:PREFIX_LENGTH])


def breach_db_size() -> int:
    return len(_load_hashes())
