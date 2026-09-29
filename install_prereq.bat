@echo off
title Convert Prerequisites (Python + openpyxl)
rem Double-click to run. ExecutionPolicy Bypass applies to this run only (system policy unchanged).
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0install_prereq.ps1"
if %errorlevel% neq 0 (
    echo.
    echo [ERROR] Install failed. See the message above.
) else (
    echo.
    echo [OK] Ready. Run: python convert_v4.py
)
pause
