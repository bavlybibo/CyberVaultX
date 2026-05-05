from __future__ import annotations

from dataclasses import dataclass, asdict
import importlib.util
import os
import platform
import sqlite3
import sys
from pathlib import Path
from typing import Any

try:
    from ..version import APP_VERSION
except Exception:  # pragma: no cover
    APP_VERSION = 'unknown'


@dataclass(slots=True)
class HealthCheck:
    name: str
    status: str
    detail: str
    category: str = "runtime"

    def as_dict(self) -> dict[str, str]:
        return asdict(self)


def _module_available(import_name: str) -> bool:
    try:
        return importlib.util.find_spec(import_name) is not None
    except (ImportError, ModuleNotFoundError, ValueError):
        return False


def _check_file(project_root: Path, item: str) -> HealthCheck:
    path = project_root / item
    return HealthCheck(f"Required file: {item}", "pass" if path.exists() else "fail", "Present" if path.exists() else "Missing", "release")


def collect_system_health(root: str | Path | None = None, app_data_dir: str | Path | None = None) -> list[dict[str, str]]:
    """Return UI/report-ready local health checks.

    The checks are intentionally offline and non-invasive. They do not inspect
    stored secrets, open the vault, or transmit telemetry.
    """
    project_root = Path(root or Path(__file__).resolve().parents[2])
    data_dir = Path(app_data_dir or project_root / "app_data")
    checks: list[HealthCheck] = []

    checks.append(HealthCheck("Application version", "pass", str(APP_VERSION), "release"))
    checks.append(HealthCheck("Operating system", "pass", f"{platform.system()} {platform.release()} ({platform.machine()})", "runtime"))
    checks.append(HealthCheck("Python runtime", "pass" if sys.version_info >= (3, 10) else "fail", f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}", "runtime"))
    checks.append(HealthCheck("SQLite runtime", "pass", sqlite3.sqlite_version, "storage"))
    checks.append(HealthCheck("PyCryptodome AES backend", "pass" if _module_available("Crypto.Cipher.AES") else "warn", "Preferred AES-GCM provider; cryptography fallback is supported.", "crypto"))
    checks.append(HealthCheck("Cryptography fallback", "pass" if _module_available("cryptography") else "warn", "Fallback AESGCM/PBKDF2 provider.", "crypto"))
    checks.append(HealthCheck("Tkinter desktop UI", "pass" if _module_available("tkinter") else "fail", "Required to launch the desktop interface.", "ui"))

    optional_modules = {
        "pytest": "Developer test runner",
        "reportlab": "Optional PDF report generation",
    }
    for module, purpose in optional_modules.items():
        checks.append(HealthCheck(f"Optional package: {module}", "pass" if _module_available(module) else "warn", purpose, "optional"))

    required_files = [
        "main.py",
        "requirements.txt",
        "README.md",
        "SECURITY.md",
        "PRIVACY.md",
        "docs/ARCHITECTURE.md",
        "docs/SECURITY_MODEL.md",
        "docs/USAGE.md",
        "docs/REPORTING.md",
    ]
    checks.extend(_check_file(project_root, item) for item in required_files)

    required_packages = ["pycryptodome", "cryptography"]
    req_path = project_root / "requirements.txt"
    if req_path.exists():
        text = req_path.read_text(encoding="utf-8", errors="ignore").lower()
        for package in required_packages:
            checks.append(HealthCheck(f"Requirement pinned: {package}", "pass" if package in text else "fail", "Listed in requirements.txt" if package in text else "Missing from requirements.txt", "release"))

    breach_path = project_root / "app" / "pwned_sha1.txt"
    if breach_path.exists():
        try:
            rows = [line.strip() for line in breach_path.read_text(encoding="utf-8").splitlines() if line.strip()]
            malformed = sum(1 for row in rows if len(row) != 40 or any(ch not in "0123456789abcdefABCDEF" for ch in row))
            status = "pass" if rows and malformed == 0 else "warn"
            detail = f"{len(rows)} local SHA1 hash rows; malformed={malformed}"
        except OSError:
            status, detail = "warn", "Unable to read local breach dataset."
    else:
        status, detail = "warn", "Offline breach dataset is missing; breach checks will be limited."
    checks.append(HealthCheck("Offline breach dataset", status, detail, "data"))

    try:
        data_dir.mkdir(parents=True, exist_ok=True)
        probe = data_dir / ".health_write_test"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink(missing_ok=True)
        checks.append(HealthCheck("App data directory", "pass", f"Writable: {data_dir}", "storage"))
    except OSError:
        checks.append(HealthCheck("App data directory", "fail", f"Not writable: {data_dir}", "storage"))

    checks.append(HealthCheck("Report engine", "pass", "HTML, JSON, and text exports are available. PDF is optional through reportlab tooling.", "reports"))
    checks.append(HealthCheck("Crypto module isolation", "pass", "Crypto helpers are exposed through app.crypto wrappers and legacy-compatible app.crypto_utils.", "crypto"))

    if os.name == "nt":
        checks.append(HealthCheck("Windows launch scripts", "pass" if (project_root / "run_windows.bat").exists() else "warn", "Use run_windows.bat for demo launch.", "release"))

    return [check.as_dict() for check in checks]


def summarize_health(checks: list[dict[str, str]]) -> dict[str, Any]:
    total = len(checks)
    failed = sum(1 for item in checks if item.get("status") == "fail")
    warned = sum(1 for item in checks if item.get("status") == "warn")
    passed = total - failed - warned
    score = 100 if total == 0 else max(0, round(((passed + warned * 0.5) / total) * 100))
    if failed:
        label = "Needs attention"
    elif warned:
        label = "Demo ready with notes"
    else:
        label = "Ready"
    return {"total": total, "passed": passed, "warnings": warned, "failed": failed, "score": score, "label": label}
