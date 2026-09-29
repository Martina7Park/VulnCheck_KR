@echo off
title MSSQL Security Check

net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Run as Administrator.
    echo         Right-click this file ^> Run as administrator
    pause
    exit /b 1
)

set "SCRIPT_DIR=%~dp0"
if not defined MSSQL_SERVER set "MSSQL_SERVER=localhost"
set "OUTFILE=%SCRIPT_DIR%%COMPUTERNAME%_mssql.txt"

echo ========================================
echo  MSSQL Check - %COMPUTERNAME%
echo  Server: %MSSQL_SERVER%
echo  1) EF  - Electronic Financial (DBM)
echo  2) KISA - Critical Info Infra 2026 Guide (D-01~D-26)
echo  3) Both
echo  Output: %OUTFILE%
echo ========================================
set "SEL="
set /p SEL=Select [1/2/3]:
set "MODE=all"
if "%SEL%"=="1" set "MODE=ef"
if "%SEL%"=="2" set "MODE=mi"

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT_DIR%check_dbms_mssql.ps1" -Mode %MODE% > "%OUTFILE%" 2>&1

set "MSSQL_PASS="
echo.
echo Done. Result: %OUTFILE%
pause
