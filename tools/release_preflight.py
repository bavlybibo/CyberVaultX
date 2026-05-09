from __future__ import annotations

import json
import re
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CURRENT_VERSION = 'v5.7.2'
OLD_VERSION_PATTERNS = ['v5.6.0', '5.6.0', 'Professional Demo Vault']

SCREENSHOTS = [
    'dashboard.png', 'vault.png', 'security_center.png', 'ai_security_coach.png',
    'proof_center.png', 'report_package.png', 'backup_preview.png', 'settings.png', 'test_output.png',
]

SAMPLE_OUTPUTS = [
    'sample_outputs/privacy_safe_report.html', 'sample_outputs/report.json', 'sample_outputs/audit_log.html',
    'sample_outputs/manifest.json', 'sample_outputs/backup_preview.txt', 'sample_outputs/verification_output.txt',
]

EVIDENCE_FILES = [
    'evidence/pytest_output.txt', 'evidence/release_preflight_output.txt', 'evidence/build_output.txt',
]

REQUIRED_FILES = [
    'README.md', 'SECURITY.md', 'PRIVACY.md', 'DISCLAIMER.md', 'LICENSE', 'DEMO_SCRIPT.md',
    'RELEASE_CHECKLIST.md', 'docs/ARCHITECTURE.md', 'docs/SECURITY_MODEL.md', 'docs/GRADING_EVIDENCE.md', 'docs/USAGE.md',
    'docs/REPORTING.md', 'docs/DEMO_SCRIPT.md', 'docs/Q_AND_A_PREP.md', 'docs/TROUBLESHOOTING.md',
    'docs/FINAL_PROJECT_REPORT.md', 'docs/CyberVaultX_Final_Project_Report.pdf',
    'presentation/CyberVaultX_Presentation.pptx', 'docs/THREAT_MODEL.md', 'docs/DEMO_WALKTHROUGH.md',
]

REQUIRED_DIRS = ['app', 'app/core', 'app/security', 'app/crypto', 'app/storage', 'app/services', 'app/ai', 'tests', 'docs', 'assets', 'assets/screenshots', 'sample_outputs', 'evidence']
SECRET_PATTERNS = [re.compile(r'(?i)(api[_-]?key|secret|token|password)\s*=\s*["\'][A-Za-z0-9_\-]{20,}["\']'), re.compile(r'AKIA[0-9A-Z]{16}')]
SKIP_SECRET_SCAN = {'.git', '.venv', 'venv', '__pycache__', '.pytest_cache', 'presentation', 'evidence'}
SKIP_TEXT_SCANS = SKIP_SECRET_SCAN | {'docs'}
HARDCODED_PATH_PATTERNS = [re.compile(r'[A-Za-z]:\\\\'), re.compile(r'/(home|Users|mnt/data|tmp)/[^\s"\']+')]


def _status(ok: bool) -> str:
    return 'PASS' if ok else 'FAIL'


def _row(check: str, ok: bool, detail: str) -> dict[str, object]:
    return {'check': check, 'ok': bool(ok), 'detail': detail}


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding='utf-8', errors='ignore')
    except OSError:
        return ''


def _pptx_text(path: Path) -> str:
    if not path.exists():
        return ''
    out: list[str] = []
    try:
        with zipfile.ZipFile(path) as zf:
            for name in zf.namelist():
                if name.endswith('.xml'):
                    out.append(zf.read(name).decode('utf-8', errors='ignore'))
    except Exception as exc:
        return f'__PPTX_READ_ERROR__ {exc}'
    return '\n'.join(out)


def _pdf_text_best_effort(path: Path) -> str:
    if not path.exists():
        return ''
    raw = path.read_bytes()
    text = raw.decode('latin-1', errors='ignore')
    # ReportLab PDFs usually expose enough metadata/text for version checks; if not, source MD is also checked.
    return text


def check_files() -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for item in REQUIRED_FILES:
        path = ROOT / item
        rows.append(_row(f'required file: {item}', path.is_file(), item))
    for item in REQUIRED_DIRS:
        path = ROOT / item
        rows.append(_row(f'required directory: {item}', path.is_dir(), item))
    return rows


def check_requirements() -> list[dict[str, object]]:
    req = _read_text(ROOT / 'requirements.txt').lower()
    dev_req = _read_text(ROOT / 'requirements-dev.txt').lower()
    return [
        _row('runtime requirements include pycryptodome', 'pycryptodome' in req, 'AES-GCM preferred backend'),
        _row('runtime requirements include cryptography fallback', 'cryptography' in req, 'fallback crypto backend'),
        _row('dev requirements include pytest', 'pytest' in dev_req, 'test runner available'),
        _row('dev requirements include pytest-cov', 'pytest-cov' in dev_req, 'coverage plugin declared'),
        _row('dev requirements include ruff', 'ruff' in dev_req, 'lint runner declared'),
    ]


def check_breach_dataset() -> list[dict[str, object]]:
    path = ROOT / 'app' / 'pwned_sha1.txt'
    count = malformed = 0
    if path.exists():
        for line in path.read_text(encoding='utf-8', errors='ignore').splitlines():
            value = line.strip()
            if not value:
                continue
            count += 1
            if len(value) != 40 or any(ch not in '0123456789abcdefABCDEF' for ch in value):
                malformed += 1
    return [_row('offline demo breach-subset exists', path.exists() and count > 0, f'{count} SHA1 hash rows'), _row('offline demo breach-subset format', malformed == 0, f'{malformed} malformed rows')]


def check_generated_junk() -> list[dict[str, object]]:
    junk = []
    for pattern in ('__pycache__', '.pytest_cache'):
        junk.extend(str(path.relative_to(ROOT)) for path in ROOT.rglob(pattern) if path.exists())
    junk.extend(str(path.relative_to(ROOT)) for path in ROOT.rglob('*.pyc'))
    junk.extend(str(path.relative_to(ROOT)) for path in ROOT.glob('VALIDATION_LOG_*.txt'))
    return [_row('no generated cache or stale validation logs in release tree', not junk, 'clean' if not junk else ', '.join(junk[:8]))]


def check_obvious_secrets() -> list[dict[str, object]]:
    hits: list[str] = []
    for path in ROOT.rglob('*'):
        if any(part in SKIP_SECRET_SCAN for part in path.parts):
            continue
        if not path.is_file() or path.suffix.lower() in {'.png', '.ico', '.pptx', '.pdf', '.zip', '.db'}:
            continue
        text = _read_text(path)
        if any(pattern.search(text) for pattern in SECRET_PATTERNS):
            hits.append(str(path.relative_to(ROOT)))
    return [_row('no obvious hardcoded secrets', not hits, 'clean' if not hits else ', '.join(hits[:8]))]


def check_hardcoded_local_paths() -> list[dict[str, object]]:
    hits: list[str] = []
    for path in ROOT.rglob('*'):
        if any(part in SKIP_TEXT_SCANS for part in path.parts):
            continue
        if not path.is_file() or path.suffix.lower() in {'.png', '.ico', '.pptx', '.pdf', '.zip', '.db'}:
            continue
        text = _read_text(path)
        if any(pattern.search(text) for pattern in HARDCODED_PATH_PATTERNS):
            hits.append(str(path.relative_to(ROOT)))
    return [_row('no hardcoded developer-local paths', not hits, 'clean' if not hits else ', '.join(hits[:8]))]


def check_stale_versions() -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    text_files = ['README.md', 'docs/FINAL_PROJECT_REPORT.md', 'docs/SCREENSHOT_CAPTURE_CHECKLIST.md', 'docs/FINAL_SUBMISSION_CHECKLIST.md']
    text = '\n'.join(_read_text(ROOT / f) for f in text_files)
    pptx_text = _pptx_text(ROOT / 'presentation/CyberVaultX_Presentation.pptx')
    pdf_text = _pdf_text_best_effort(ROOT / 'docs/CyberVaultX_Final_Project_Report.pdf') + '\n' + _read_text(ROOT / 'docs/FINAL_PROJECT_REPORT.md')
    rows.append(_row('current docs mention v5.7.2', CURRENT_VERSION in text or '5.7.2' in text, CURRENT_VERSION))
    rows.append(_row('current PPT mentions v5.7.2', CURRENT_VERSION in pptx_text or '5.7.2' in pptx_text, 'presentation deck text checked'))
    rows.append(_row('current PDF/source mentions v5.7.2', CURRENT_VERSION in pdf_text or '5.7.2' in pdf_text, 'pdf/source text checked'))
    for old in OLD_VERSION_PATTERNS:
        rows.append(_row(f'no stale text in docs/PPT/PDF: {old}', old not in (text + pptx_text + pdf_text), 'stale text scan'))
    return rows


def check_screenshots() -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    folder = ROOT / 'assets' / 'screenshots'
    existing = sorted(p.name for p in folder.glob('*.png')) if folder.exists() else []
    rows.append(_row('screenshot folder contains standardized PNG set', set(existing) == set(SCREENSHOTS), ', '.join(existing)))
    readme = _read_text(ROOT / 'README.md') + _read_text(ROOT / 'assets/screenshots/README.md') + _read_text(ROOT / 'docs/SCREENSHOT_CAPTURE_CHECKLIST.md') + _read_text(ROOT / 'docs/FINAL_SUBMISSION_CHECKLIST.md')
    missing_refs = [name for name in SCREENSHOTS if name not in readme]
    rows.append(_row('all screenshot names are referenced consistently', not missing_refs, 'missing refs: ' + ', '.join(missing_refs) if missing_refs else 'all referenced'))
    too_small = []
    for name in SCREENSHOTS:
        path = folder / name
        if not path.exists() or path.stat().st_size < 10_000:
            too_small.append(name)
    rows.append(_row('screenshots are non-empty image files', not too_small, 'ok' if not too_small else ', '.join(too_small)))
    return rows


def check_evidence_and_samples() -> list[dict[str, object]]:
    rows = []
    for rel in EVIDENCE_FILES:
        path = ROOT / rel
        rows.append(_row(f'evidence file exists: {rel}', path.is_file() and path.stat().st_size > 20, rel))
    for rel in SAMPLE_OUTPUTS:
        path = ROOT / rel
        rows.append(_row(f'sample output exists: {rel}', path.is_file() and path.stat().st_size > 20, rel))
    return rows


def check_wording() -> list[dict[str, object]]:
    docs = ['README.md', 'docs/FINAL_PROJECT_REPORT.md', 'docs/LIMITATIONS.md', 'docs/THREAT_MODEL.md', 'tools/create_final_report_pdf.py', 'tools/create_presentation.js']
    combined = '\n'.join(_read_text(ROOT / d) for d in docs)
    banned = ['End-to-End Encryption', 'end-to-end encryption', 'Professional Demo Vault', 'Report signing', 'Commercial product', 'Breach Detection']
    rows = [_row(f'no exaggerated wording: {term}', term not in combined, 'wording scan') for term in banned]
    required = ['Local encryption at rest using AES-GCM', 'AI-style Local Security Coach', 'Local audit hash-chain integrity check', 'local manifest integrity signature', 'public Ed25519 manifest signature', 'commercial-style academic prototype', 'offline demo breach-subset']
    rows.extend(_row(f'honest wording present: {term}', term in combined, 'wording scan') for term in required)
    return rows


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
    return _row('python compile check', not failures, 'compiled in memory without bytecode output' if not failures else '; '.join(failures[:5])[:500])



def check_independent_verifier() -> list[dict[str, object]]:
    verifier = _read_text(ROOT / 'verify_report_package.py')
    sample_manifest = _read_text(ROOT / 'sample_outputs' / 'manifest.json')
    return [
        _row('external verifier checks public Ed25519 signature', 'verify_manifest_public_signature' in verifier and 'public_manifest_signature' in verifier, 'verify_report_package.py'),
        _row('sample manifest includes public signature', 'public_manifest_signature' in sample_manifest and 'signing_public_key_b64' in sample_manifest, 'sample_outputs/manifest.json'),
    ]

def main() -> int:
    rows = []
    for fn in (check_files, check_requirements, check_breach_dataset, check_generated_junk, check_obvious_secrets, check_hardcoded_local_paths, check_stale_versions, check_screenshots, check_evidence_and_samples, check_wording, check_independent_verifier):
        rows.extend(fn())
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
