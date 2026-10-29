@echo off
title FileGuard - Suspicious File Analysis Platform
color 0A
echo =====================================================================
echo           FILEGUARD - SUSPICIOUS FILE ANALYSIS PLATFORM
echo =====================================================================
echo.

where python >nul 2>nul
if %errorlevel% neq 0 (
    echo [ERROR] Python was not found in your system PATH!
    echo Please install Python 3.8 or newer from https://www.python.org/
    echo Make sure to check "Add Python to PATH" during installation.
    echo.
    pause
    exit /b 1
)

echo [*] Checking dependencies...
python -c "import flask, werkzeug" >nul 2>nul
if %errorlevel% neq 0 (
    echo [*] Installing required packages from requirements.txt...
    python -m pip install -r requirements.txt
    if %errorlevel% neq 0 (
        echo [ERROR] Failed to install dependencies.
        pause
        exit /b 1
    )
)

echo [*] Starting FileGuard Web Application...
echo [*] Open your web browser at: http://127.0.0.1:5000
echo.
python app.py
pause
