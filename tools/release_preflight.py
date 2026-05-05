from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

REQUIRED_FILES = [
    'README.md',
    'SECURITY.md',
    'PRIVACY.md',
    'DISCLAIMER.md',
    'LICENSE',
    'DEMO_SCRIPT.md',
    'RELEASE_CHECKLIST.md',
    'docs/ARCHITECTURE.md',
    'docs/SECURITY_MODEL.md',
    'docs/USAGE.md',
    'docs/REPORTING.md',
    'docs/DEMO_SCRIPT.md',
    'docs/Q_AND_A_PREP.md',
    'docs/TROUBLESHOOTING.md',
]

REQUIRED_DIRS = [
    'app',
    'app/core',
    'app/security',
    'app/crypto',
    'app/storage',
    'app/services',
    'app/ai',
    'tests',
    'docs',
    'assets',
    'assets/screenshots',
]

SECRET_PATTERNS = [
    re.compile(r'(?i)(api[_-]?key|secret|token|password)\s*=\s*["\'][A-Za-z0-9_\-]{20,}["\']'),
    re.compile(r'AKIA[0-9A-Z]{16}'),
]

SKIP_SECRET_SCAN = {'.git', '.venv', 'venv', '__pycache__', '.pytest_cache', 'presentation'}
SKIP_TEXT_SCANS = SKIP_SECRET_SCAN | {'docs'}
HARDCODED_PATH_PATTERNS = [
    re.compile(r'[A-Za-z]:\\\\'),
    re.compile(r'/(home|Users|mnt/data|tmp)/[^\s"\']+'),
]


def _status(ok: bool) -> str:
    return 'PASS' if ok else 'FAIL'


def check_files() -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for item in REQUIRED_FILES:
        path = ROOT / item
        rows.append({'check': f'required file: {item}', 'ok': path.is_file(), 'detail': str(path.relative_to(ROOT))})
    for item in REQUIRED_DIRS:
        path = ROOT / item
        rows.append({'check': f'required directory: {item}', 'ok': path.is_dir(), 'detail': str(path.relative_to(ROOT))})
    return rows


def check_requirements() -> list[dict[str, object]]:
    req = (ROOT / 'requirements.txt').read_text(encoding='utf-8') if (ROOT / 'requirements.txt').exists() else ''
    dev_req = (ROOT / 'requirements-dev.txt').read_text(encoding='utf-8') if (ROOT / 'requirements-dev.txt').exists() else ''
    return [
        {'check': 'runtime requirements include pycryptodome', 'ok': 'pycryptodome' in req.lower(), 'detail': 'AES-GCM preferred backend'},
        {'check': 'runtime requirements include cryptography fallback', 'ok': 'cryptography' in req.lower(), 'detail': 'fallback crypto backend'},
        {'check': 'dev requirements include pytest', 'ok': 'pytest' in dev_req.lower(), 'detail': 'test runner available'},
    ]


def check_breach_dataset() -> list[dict[str, object]]:
    path = ROOT / 'app' / 'pwned_sha1.txt'
    count = 0
    malformed = 0
    if path.exists():
        for line in path.read_text(encoding='utf-8').splitlines():
            value = line.strip()
            if not value:
                continue
            count += 1
            if len(value) != 40 or any(ch not in '0123456789abcdefABCDEF' for ch in value):
                malformed += 1
    return [
        {'check': 'offline breach dataset exists', 'ok': path.exists() and count > 0, 'detail': f'{count} SHA1 hash rows'},
        {'check': 'offline breach dataset format', 'ok': malformed == 0, 'detail': f'{malformed} malformed rows'},
    ]


def check_generated_junk() -> list[dict[str, object]]:
    junk = []
    for pattern in ('__pycache__', '.pytest_cache'):
        junk.extend(str(path.relative_to(ROOT)) for path in ROOT.rglob(pattern) if path.exists())
    junk.extend(str(path.relative_to(ROOT)) for path in ROOT.rglob('*.pyc'))
    junk.extend(str(path.relative_to(ROOT)) for path in ROOT.glob('VALIDATION_LOG_*.txt'))
    return [{
        'check': 'no generated cache or stale validation logs in release tree',
        'ok': not junk,
        'detail': 'clean' if not junk else ', '.join(junk[:8]),
    }]


def check_obvious_secrets() -> list[dict[str, object]]:
    hits: list[str] = []
    for path in ROOT.rglob('*'):
        if any(part in SKIP_SECRET_SCAN for part in path.parts):
            continue
        if not path.is_file() or path.suffix.lower() in {'.png', '.ico', '.pptx', '.pdf', '.zip', '.db'}:
            continue
        try:
            text = path.read_text(encoding='utf-8', errors='ignore')
        except OSError:
            continue
        for pattern in SECRET_PATTERNS:
            if pattern.search(text):
                hits.append(str(path.relative_to(ROOT)))
                break
    return [{
        'check': 'no obvious hardcoded secrets',
        'ok': not hits,
        'detail': 'clean' if not hits else ', '.join(hits[:8]),
    }]


def check_hardcoded_local_paths() -> list[dict[str, object]]:
    hits: list[str] = []
    for path in ROOT.rglob('*'):
        if any(part in SKIP_TEXT_SCANS for part in path.parts):
            continue
        if not path.is_file() or path.suffix.lower() in {'.png', '.ico', '.pptx', '.pdf', '.zip', '.db'}:
            continue
        try:
            text = path.read_text(encoding='utf-8', errors='ignore')
        except OSError:
            continue
        for pattern in HARDCODED_PATH_PATTERNS:
            if pattern.search(text):
                hits.append(str(path.relative_to(ROOT)))
                break
    return [{
        'check': 'no hardcoded developer-local paths',
        'ok': not hits,
        'detail': 'clean' if not hits else ', '.join(hits[:8]),
    }]


def run_compile_check() -> dict[str, object]:
    targets = [ROOT / 'app', ROOT / 'tests', ROOT / 'tools', ROOT / 'main.py', ROOT / 'verify_report_package.py']
    failures: list[str] = []
    files: list[Path] = []
    for target in targets:
        if target.is_dir():
            files.extend(sorted(target.rglob('*.py')))
        elif target.exists():
            files.append(target)
    for file_path in files:
        try:
            source = file_path.read_text(encoding='utf-8')
            compile(source, str(file_path.relative_to(ROOT)), 'exec')
        except Exception as exc:
            failures.append(f'{file_path.relative_to(ROOT)}: {type(exc).__name__}: {exc}')
    return {
        'check': 'python compile check',
        'ok': not failures,
        'detail': 'compiled in memory without bytecode output' if not failures else '; '.join(failures[:5])[:500],
    }


def main() -> int:
    rows = []
    rows.extend(check_files())
    rows.extend(check_requirements())
    rows.extend(check_breach_dataset())
    rows.extend(check_generated_junk())
    rows.extend(check_obvious_secrets())
    rows.extend(check_hardcoded_local_paths())
    rows.append(run_compile_check())

    print('\nCyberVault X release preflight')
    print('=' * 36)
    for row in rows:
        print(f"[{_status(bool(row['ok']))}] {row['check']} - {row['detail']}")
    failed = [row for row in rows if not row['ok']]
    summary = {'total': len(rows), 'passed': len(rows) - len(failed), 'failed': len(failed)}
    print('\n' + json.dumps(summary, indent=2))
    return 1 if failed else 0


if __name__ == '__main__':
    raise SystemExit(main())
