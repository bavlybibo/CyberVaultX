# Troubleshooting

## App does not start

Run:

```bash
python -m pip install -r requirements.txt
python main.py
```

On Windows, try `run_windows.bat`.

## Tkinter error

Install a Python distribution that includes Tkinter, or run the app on a desktop environment with GUI support.

## Wrong master password

CyberVault X cannot recover the master password. Use an encrypted backup if available.

## Report export fails

Check write permission for the selected output folder. Use HTML or JSON first because PDF is optional.

## Tests are slow

Unit tests reduce KDF iterations internally. Do not change production KDF defaults just to speed up the app.

## Preflight fails on generated cache

Run:

```bash
python tools/project_cleaner.py
```
