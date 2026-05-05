@echo off
setlocal
cd /d "%~dp0"

if exist run_windows.bat (
    call run_windows.bat
) else (
    python -m pip install -r requirements.txt
    python main.py
)
