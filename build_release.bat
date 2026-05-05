@echo off
setlocal
cd /d "%~dp0"

echo [CyberVault X] Cleaning Python cache and stale bytecode...
for /d /r . %%d in (__pycache__) do @if exist "%%d" rd /s /q "%%d"
del /s /q *.pyc 2>nul

echo [CyberVault X] Release version:
type VERSION

echo [CyberVault X] Creating release build environment...
if not exist .venv_build (
    py -m venv .venv_build
)
call .venv_build\Scripts\activate.bat
if errorlevel 1 (
    echo [CyberVault X] Failed to activate .venv_build.
    pause
    exit /b 1
)

python -m pip install --upgrade pip
python -m pip install -r requirements-build.txt

echo [CyberVault X] Running compile check before packaging...
python -m compileall -q app tests main.py verify_report_package.py
if errorlevel 1 (
    echo [CyberVault X] Compile check failed. Build stopped.
    pause
    exit /b 1
)

echo [CyberVault X] Running automated tests before packaging...
python -m pytest -q tests
if errorlevel 1 (
    echo [CyberVault X] Automated tests failed. Build stopped.
    pause
    exit /b 1
)

echo [CyberVault X] Running release preflight checks...
python tools\release_preflight.py
if errorlevel 1 (
    echo [CyberVault X] Release preflight failed. Build stopped.
    pause
    exit /b 1
)

echo [CyberVault X] Building EXE with PyInstaller...
pyinstaller --clean --noconfirm cybervaultx.spec
if errorlevel 1 (
    echo [CyberVault X] PyInstaller failed.
    pause
    exit /b 1
)

echo [CyberVault X] Cleaning cache after packaging...
for /d /r . %%d in (__pycache__) do @if exist "%%d" rd /s /q "%%d"
del /s /q *.pyc 2>nul

echo [CyberVault X] Build complete: dist\CyberVaultX\CyberVaultX.exe
pause
