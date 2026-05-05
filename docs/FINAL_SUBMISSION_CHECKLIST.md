# CyberVault X - Final Submission Checklist

Use this checklist before uploading the LMS submission and presenting the project.

## Required by the course

- [ ] Team has exactly 3 students.
- [ ] GitHub repository is public or accessible to the instructor.
- [ ] Repository has clean folders: `app/`, `tests/`, `docs/`, `presentation/`, `assets/`.
- [ ] `README.md` includes setup, usage, features, demo flow, and limitations.
- [ ] `requirements.txt` and `requirements-build.txt` are included.
- [ ] Every team member has visible commits.
- [ ] Working implementation is available.
- [ ] Presentation is 10-15 minutes.
- [ ] Live demo path is rehearsed.
- [ ] Q&A technical answers are prepared.

## Build and testing

- [ ] Run: `python -m pip install -r requirements-build.txt`
- [ ] Run: `python -m pytest -q tests`
- [ ] Run: `python tools/release_preflight.py`
- [ ] Run: `build_release.bat` on Windows.
- [ ] Confirm: `dist\CyberVaultX\CyberVaultX.exe` opens successfully.
- [ ] Create a vault and unlock it.
- [ ] Create Assessment Workspace.
- [ ] Export a report package.
- [ ] Verify report package.
- [ ] Export encrypted backup.
- [ ] Preview restore before importing.

## Screenshots to capture

Save screenshots in `assets/screenshots/`:

- [ ] `01_dashboard.png`
- [ ] `02_vault.png`
- [ ] `03_security_center.png`
- [ ] `04_ai_guardian_v2.png`
- [ ] `05_security_proof_center.png`
- [ ] `06_activity_filters.png`
- [ ] `07_report_package_verifier.png`
- [ ] `08_backup_restore_preview.png`
- [ ] `09_exported_report_package.png`

## Files to submit

- [ ] Source ZIP.
- [ ] GitHub link.
- [ ] Final PDF report: `docs/CyberVaultX_Final_Project_Report.pdf`.
- [ ] Presentation deck: `presentation/CyberVaultX_Presentation.pptx`.
- [ ] Built EXE or installer ZIP if allowed.
- [ ] Screenshot folder.
- [ ] Optional exported demo report package.

## Last-minute quality check

- [ ] No real passwords or private data in screenshots.
- [ ] Assessment workspace uses safe built-in records only.
- [ ] README does not claim commercial certification.
- [ ] Limitations are honest and professional.
- [ ] Presentation explains why Tkinter was used instead of PyQt5.
