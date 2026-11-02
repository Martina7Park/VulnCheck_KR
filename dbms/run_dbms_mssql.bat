@echo off
setlocal EnableExtensions
title MSSQL Security Check

rem Administrator rights are needed for local (installed) servers: OS policy / firewall / file ACL items.
rem For remote or managed servers (RDS, Azure SQL) it is not required; OS items are reported as N-A / not-checkable.
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [WARN] Not running as Administrator - OS-level items on a local server will be reported as not-checkable.
    echo        Right-click this file ^> Run as administrator for a full local check.
    echo.
)

set "SCRIPT_DIR=%~dp0"
if not defined MSSQL_SERVER set "MSSQL_SERVER=localhost"

echo ========================================
echo  MSSQL Check - %COMPUTERNAME%
echo  Server: %MSSQL_SERVER%
echo  1) EF  - Electronic Financial (DBM)
echo  2) KISA - Critical Info Infra 2026 Guide (D-01~D-26)
echo  3) Both
echo  Output: %SCRIPT_DIR%^<host^>_mssql_^<target^>_dbms.txt  (UTF-8 with BOM, written by the script itself)
echo ========================================
echo  Env: MSSQL_SERVER MSSQL_PORT MSSQL_USER MSSQL_PASS MSSQL_WINAUTH  DBMS_ENV=rds^|azure  DBMS_REMOTE=1
echo  (If MSSQL_PASS is not set, Windows authentication is tried first, then a hidden password prompt.)
set "SEL="
set /p SEL=Select [1/2/3]:
set "MODE=all"
if "%SEL%"=="1" set "MODE=ef"
if "%SEL%"=="2" set "MODE=mi"

rem The PowerShell script saves the result (UTF-8 BOM) and evidence files itself - no cmd redirect, so Korean text is not corrupted.
rem The password is passed to sqlcmd only through the SQLCMDPASSWORD environment variable inside the PowerShell process.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT_DIR%check_dbms_mssql.ps1" -Mode %MODE%

echo.
echo Done. See the "Result file" / "Evidence file" lines printed at the end above (same folder as this script).
endlocal
pause
