from __future__ import annotations

import hashlib
import os
import re
from collections import defaultdict
from functools import lru_cache
from pathlib import Path

DB_PATH = Path(__file__).with_name('pwned_sha1.txt')
PREFIX_LENGTH = 5
CUSTOM_BREACH_SHA1_ENV = 'CYBERVAULTX_CUSTOM_BREACH_SHA1'
SHA1_RE = re.compile(r'^[A-Fa-f0-9]{40}$')


def _read_hash_file(path: Path) -> tuple[str, ...]:
    if not path.exists():
        return tuple()
    hashes: list[str] = []
    for raw in path.read_text(encoding='utf-8', errors='ignore').splitlines():
        value = raw.strip().upper()
        if value and not value.startswith('#') and SHA1_RE.match(value):
            hashes.append(value)
    return tuple(hashes)


@lru_cache(maxsize=1)
def _load_hashes() -> tuple[str, ...]:
    bundled = list(_read_hash_file(DB_PATH))
    custom_path = os.environ.get(CUSTOM_BREACH_SHA1_ENV, '').strip()
    custom = list(_read_hash_file(Path(custom_path))) if custom_path else []
    return tuple(sorted(set(bundled + custom)))


@lru_cache(maxsize=1)
def _load_prefix_index() -> dict[str, set[str]]:
    index: dict[str, set[str]] = defaultdict(set)
    for entry in _load_hashes():
        index[entry[:PREFIX_LENGTH]].add(entry)
    return dict(index)


def clear_breach_cache() -> None:
    _load_hashes.cache_clear()
    _load_prefix_index.cache_clear()


def validate_sha1_lines(text: str) -> dict[str, object]:
    valid: list[str] = []
    invalid: list[dict[str, object]] = []
    for line_no, raw in enumerate(text.splitlines(), start=1):
        value = raw.strip().upper()
        if not value or value.startswith('#'):
            continue
        if SHA1_RE.match(value):
            valid.append(value)
        else:
            invalid.append({'line': line_no, 'value_preview': value[:16]})
    return {'valid_count': len(set(valid)), 'invalid': invalid}


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
