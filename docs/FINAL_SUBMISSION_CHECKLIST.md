# CyberVault X - Final Submission Checklist

Use this checklist before uploading the LMS submission and presenting the project.

## Required by the course

- [ ] Team size and member names are correct in the report.
- [ ] GitHub repository is public or accessible to the instructor.
- [ ] Repository has clean folders: `app/`, `tests/`, `docs/`, `presentation/`, `assets/`, `sample_outputs/`, `evidence/`.
- [ ] `README.md` includes setup, usage, features, demo flow, evidence, screenshots, and limitations.
- [ ] `requirements.txt`, `requirements-dev.txt`, and `requirements-build.txt` are included.
- [ ] Every team member has visible commits or a documented contribution table.
- [ ] Working implementation is available.
- [ ] Presentation is 10-15 minutes.
- [ ] Live demo path is rehearsed.
- [ ] Q&A technical answers are prepared.

## Build and testing

- [ ] Run: `python -m pip install -r requirements-build.txt`
- [ ] Run: `python -m pytest -q`
- [ ] Run: `python -m pytest --cov=app --cov-report=term-missing`
- [ ] Run: `python tools/release_preflight.py`
- [ ] Run: `build_release.bat` on Windows if an EXE is required.
- [ ] Confirm: `dist\CyberVaultX\CyberVaultX.exe` opens successfully when built.
- [ ] Create a vault and unlock it.
- [ ] Create Assessment Workspace.
- [ ] Export a report package.
- [ ] Verify report package.
- [ ] Export encrypted backup.
- [ ] Preview restore before importing.

## Screenshots to capture

Save screenshots in `assets/screenshots/`:

- [ ] `dashboard.png`
- [ ] `vault.png`
- [ ] `security_center.png`
- [ ] `ai_security_coach.png`
- [ ] `proof_center.png`
- [ ] `report_package.png`
- [ ] `backup_preview.png`
- [ ] `settings.png`
- [ ] `test_output.png`

## Evidence files

- [ ] `evidence/pytest_output.txt`
- [ ] `evidence/coverage_output.txt`
- [ ] `evidence/release_preflight_output.txt`
- [ ] `evidence/build_output.txt`

## Sample outputs

- [ ] `sample_outputs/privacy_safe_report.html`
- [ ] `sample_outputs/report.json`
- [ ] `sample_outputs/audit_log.html`
- [ ] `sample_outputs/manifest.json`
- [ ] `sample_outputs/backup_preview.txt`
- [ ] `sample_outputs/verification_output.txt`

## Files to submit

- [ ] Source ZIP.
- [ ] GitHub link.
- [ ] Final PDF report: `docs/CyberVaultX_Final_Project_Report.pdf`.
- [ ] Presentation deck: `presentation/CyberVaultX_Presentation.pptx`.
- [ ] Built EXE or installer ZIP if allowed.
- [ ] Screenshot folder.
- [ ] Exported demo report package.

## Last-minute quality check

- [ ] No real passwords or private data in screenshots.
- [ ] Assessment Workspace uses safe built-in records only.
- [ ] README does not claim commercial certification.
- [ ] Limitations are honest and professional.
- [ ] Presentation explains why Tkinter was used instead of PyQt/PySide.
- [ ] No stale old-version text remains in PDF/PPT/current docs.
