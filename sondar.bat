@echo off
setlocal

title Sondar

REM ------------------------------------------------------------
REM Sondar Launcher
REM Launches the interactive Sondar operator menu from the repo root.
REM ------------------------------------------------------------

cd /d "%~dp0"

echo.
echo Starting Sondar...
echo.

where python >nul 2>&1
if errorlevel 1 (
    echo [X] Python was not found in PATH
    echo [i] Install Python or add it to PATH, then try again
    echo.
    pause
    exit /b 1
)

where nmap >nul 2>&1
if errorlevel 1 (
    echo [X] Nmap was not found in PATH
    echo [i] Install Nmap or add it to PATH, then try again
    echo.
    pause
    exit /b 1
)

python src\sondar_main.py

endlocal