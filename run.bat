@echo off
setlocal enabledelayedexpansion
title x1vart Web Recon & ASM Platform
cd /d "%~dp0"

echo ========================================================
echo   x1vart Web Recon ^& Attack Surface Management
echo ========================================================
echo.

:: Detect Python (prefer py -3.12 or active python)
set "PY_CMD=python"
py -3.12 --version >nul 2>&1
if %errorlevel% equ 0 (
    set "PY_CMD=py -3.12"
) else (
    python --version >nul 2>&1
    if %errorlevel% neq 0 (
        echo [!] Python not found in PATH!
        echo Please install Python 3.10+ from https://www.python.org/
        pause
        exit /b 1
    )
)

:: Auto create virtual environment if not present
if not exist ".venv" (
    echo [*] Initial setup: Creating virtual environment (.venv)...
    %PY_CMD% -m venv .venv
)

:: Activate venv
if exist ".venv\Scripts\activate.bat" (
    call .venv\Scripts\activate.bat
)

:: Install/update dependencies
echo [*] Checking dependencies...
pip install -q -r requirements.txt

:: Start FastAPI Server
echo.
echo [*] Launching x1vart Platform at http://127.0.0.1:8000 ...
python app.py

pause
