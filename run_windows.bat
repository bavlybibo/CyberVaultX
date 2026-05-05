@echo off
setlocal
cd /d "%~dp0"

if exist .venv\Scripts\activate.bat (
    call .venv\Scripts\activate.bat
)

echo [CyberVault X] Starting desktop app...
python main.py
if errorlevel 1 (
    echo [CyberVault X] App stopped with an error. Run setup_windows.bat, then try again.
    pause
    exit /b 1
)
