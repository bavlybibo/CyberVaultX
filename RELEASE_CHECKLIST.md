# Release Checklist

- [ ] `python -m pip install -r requirements.txt`
- [ ] `python -m pip install -r requirements-dev.txt`
- [ ] `python -m pytest -q`
- [ ] `python tools/release_preflight.py`
- [ ] `python tools/project_cleaner.py`
- [ ] Launch with `python main.py`
- [ ] Create/unlock vault
- [ ] Add/edit/delete credential
- [ ] Verify dashboard uses real data
- [ ] Verify AI Security Coach findings are concise and evidence-based
- [ ] Export HTML and JSON privacy-safe reports
- [ ] Create encrypted backup and preview restore
- [ ] Confirm reports/logs contain no plaintext passwords or master password
- [ ] Capture screenshots into `assets/screenshots/`
