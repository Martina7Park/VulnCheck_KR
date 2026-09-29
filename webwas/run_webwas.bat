@echo off
title WebWAS Security Check

net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Run as Administrator.
    echo         Right-click this file ^> Run as administrator
    pause
    exit /b 1
)

set "SCRIPT_DIR=%~dp0"
set "OUTFILE=%SCRIPT_DIR%%COMPUTERNAME%_webwas.txt"

echo ========================================
echo  WebWAS Check - %COMPUTERNAME%
echo  1) EF  - Electronic Financial (WST)
echo  2) KISA - Critical Info Infra 2026 Guide (WEB-01~WEB-26)
echo  3) Both
echo  Output: %OUTFILE%
echo ========================================
set "SEL="
set /p SEL=Select [1/2/3]:
set "MODE=all"
if "%SEL%"=="1" set "MODE=ef"
if "%SEL%"=="2" set "MODE=mi"

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT_DIR%check_webwas.ps1" -Mode %MODE% > "%OUTFILE%" 2>&1

echo.
echo Done. Result: %OUTFILE%
pause
