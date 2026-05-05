@echo off
setlocal
cd /d "%~dp0"

echo [CyberVault X] Creating local virtual environment...
if not exist .venv (
    py -m venv .venv
    if errorlevel 1 python -m venv .venv
)

call .venv\Scripts\activate.bat
if errorlevel 1 (
    echo [CyberVault X] Could not activate .venv.
    pause
    exit /b 1
)

python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m pip install -r requirements-dev.txt

echo.
echo [CyberVault X] Setup complete. Run: run_windows.bat
pause
