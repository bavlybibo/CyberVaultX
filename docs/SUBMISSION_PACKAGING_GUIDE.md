# CyberVault X - Submission Packaging Guide

Recommended final package structure:

```text
CyberVaultX_Submission/
  source/
    app/
    tests/
    docs/
    presentation/
    assets/
    main.py
    README.md
    requirements.txt
    requirements-build.txt
  build/
    CyberVaultX.exe or CyberVaultX installer
  screenshots/
    01_dashboard.png
    02_vault.png
    ...
  evidence/
    pytest_output.txt
    release_preflight_output.txt
    demo_report_package/
  CyberVaultX_Final_Project_Report.pdf
  CyberVaultX_Presentation.pptx
```

## GitHub commit split

Recommended team contribution split:

| Member | Suggested ownership | Example commit message |
|---|---|---|
| Member 1 | Crypto, database, backup | `Implement AES-GCM vault encryption and backup envelope` |
| Member 2 | UI, workflows, screenshots | `Polish dashboard, vault workspace, and proof center UI` |
| Member 3 | Testing, docs, reporting | `Add release tests, final report, and presentation deck` |

## Clean release command sequence

```bash
python -m pip install -r requirements-build.txt
python -m pytest -q tests
python tools/release_preflight.py
```

On Windows:

```bat
build_release.bat
```

## Evidence files to keep

- Terminal screenshot or text output of automated tests.
- Terminal screenshot or text output of release preflight.
- Screenshot of running EXE.
- Screenshot of report package verification success.
- Screenshot of backup restore preview.
