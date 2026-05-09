from __future__ import annotations

import hashlib
import hmac
import json
import os
import sys
from pathlib import Path

from app.services.signing import (
    canonical_manifest_payload,
    public_key_fingerprint,
    sign_manifest,
    verify_manifest_public_signature,
)

ALLOWED_REPORT_PACKAGE_FILES = {'executive_report.html', 'audit_log.html', 'ai_guardian_summary.txt'}
SIGNING_KEY_ENV = 'CYBERVAULTX_REPORT_SIGNING_KEY'


def safe_member_path(root: Path, name: str) -> Path:
    candidate_name = str(name or '').strip()
    if not candidate_name:
        raise ValueError('empty file name')
    member = Path(candidate_name)
    if member.name != candidate_name or member.is_absolute() or '..' in member.parts:
        raise ValueError(f'unsafe file path: {candidate_name!r}')
    if candidate_name not in ALLOWED_REPORT_PACKAGE_FILES:
        raise ValueError(f'unexpected report package file: {candidate_name!r}')
    root_resolved = root.resolve()
    candidate = (root_resolved / candidate_name).resolve()
    if candidate.parent != root_resolved:
        raise ValueError(f'path escapes package directory: {candidate_name!r}')
    return candidate


def verify_report_package(directory: str | Path) -> int:
    root = Path(directory)
    manifest_path = root / 'manifest.json'
    if not manifest_path.exists():
        print(f'[FAIL] manifest.json not found in {root}')
        return 2
    try:
        manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
    except Exception as exc:
        print(f'[FAIL] manifest.json is not valid JSON: {exc}')
        return 2
    files = manifest.get('files', [])
    if not isinstance(files, list):
        print('[FAIL] manifest.json has invalid "files" list')
        return 2

    seen: set[str] = set()
    for item in files:
        if not isinstance(item, dict):
            print('[FAIL] manifest contains a non-object file entry')
            return 2
        name = str(item.get('name', ''))
        try:
            safe_member_path(root, name)
        except ValueError as exc:
            print(f'[FAIL] {name or "<empty>"}: {exc}')
            return 2
        if name in seen:
            print(f'[FAIL] {name}: duplicate manifest entry')
            return 2
        seen.add(name)
    missing = ALLOWED_REPORT_PACKAGE_FILES.difference(seen)
    if missing:
        print(f'[FAIL] manifest missing required file(s): {", ".join(sorted(missing))}')
        return 2

    ok = True
    for item in files:
        name = str(item.get('name', ''))
        expected = str(item.get('sha256', ''))
        try:
            expected_size = int(item.get('size_bytes', -1) or -1)
        except (TypeError, ValueError):
            expected_size = -1
        try:
            path = safe_member_path(root, name)
        except ValueError as exc:
            print(f'[FAIL] {name}: {exc}')
            ok = False
            continue
        if not path.exists() or not path.is_file():
            print(f'[FAIL] {name}: missing')
            ok = False
            continue
        data = path.read_bytes()
        actual = hashlib.sha256(data).hexdigest()
        if actual != expected or len(data) != expected_size:
            print(f'[FAIL] {name}: expected {expected[:16]}..., got {actual[:16]}..., size {len(data)}/{expected_size}')
            ok = False
        else:
            print(f'[ OK ] {name}: {actual}')

    expected_package_hash = str(manifest.get('package_hash', ''))
    actual_package_hash = hashlib.sha256(json.dumps(files, sort_keys=True).encode('utf-8')).hexdigest()
    if not expected_package_hash or expected_package_hash != actual_package_hash:
        print(f'[FAIL] package_hash mismatch: expected {expected_package_hash[:16]}..., got {actual_package_hash[:16]}...')
        ok = False
    else:
        print(f'[ OK ] package_hash: {actual_package_hash}')

    # Public Ed25519 verification is the main independent proof.  It does not
    # require the vault-local secret, so a teacher/reviewer can verify the
    # package from the exported folder alone.
    public_signature = str(manifest.get('public_manifest_signature', ''))
    public_key = str(manifest.get('signing_public_key_b64', ''))
    public_fingerprint = str(manifest.get('signing_public_key_fingerprint', ''))
    if not public_signature or not public_key:
        print('[FAIL] public Ed25519 manifest signature missing')
        ok = False
    elif verify_manifest_public_signature(manifest):
        print(f'[ OK ] public_manifest_signature verified; key fingerprint={public_key_fingerprint(public_key)}')
        if public_fingerprint and not hmac.compare_digest(public_fingerprint, public_key_fingerprint(public_key)):
            print('[FAIL] public key fingerprint mismatch')
            ok = False
    else:
        print('[FAIL] public Ed25519 manifest signature mismatch')
        ok = False

    # Local HMAC is a second optional vault-only check.  It can be verified only
    # when the caller deliberately supplies the vault-local signing key.
    signature = str(manifest.get('manifest_signature', ''))
    signing_key = os.environ.get(SIGNING_KEY_ENV, '')
    if not signature:
        print('[INFO] local manifest_signature missing; public signature result is authoritative')
    elif signing_key:
        actual_signature = sign_manifest(manifest, signing_key)
        if hmac.compare_digest(signature, actual_signature):
            print('[ OK ] local manifest_signature verified with environment signing key')
        else:
            print('[FAIL] local manifest_signature mismatch with environment signing key')
            ok = False
    else:
        print(f'[INFO] local manifest_signature present but not checked. Set {SIGNING_KEY_ENV} to verify it outside the app.')

    payload_hash = hashlib.sha256(canonical_manifest_payload(manifest)).hexdigest()
    print(f'[INFO] canonical_manifest_payload_sha256: {payload_hash}')
    return 0 if ok else 1


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print('Usage: python verify_report_package.py <CyberVault_Report_Package_folder>')
        raise SystemExit(2)
    raise SystemExit(verify_report_package(sys.argv[1]))
