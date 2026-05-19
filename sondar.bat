@echo off
setlocal

title Sondar

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

python src\sondar_main.py

echo.
pause
endlocal