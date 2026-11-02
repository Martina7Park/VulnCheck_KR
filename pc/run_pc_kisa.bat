@echo off
title PC Security Check (KISA 2026)
rem Result is saved as UTF-8 (Korean text stays intact on any Windows locale).
rem Administrator rights are requested (UAC) because security policy, audit policy, BitLocker, bcdedit and share ACL queries need them.
rem No labels/goto are used on purpose (this file has LF line endings).

set "SCRIPT_DIR=%~dp0"
set "OUTFILE=%SCRIPT_DIR%PC_KISA_%COMPUTERNAME%.txt"

net session >nul 2>&1
if not errorlevel 1 set "IS_ADMIN=1"
if not defined IS_ADMIN if /i not "%~1"=="elevated" echo Requesting administrator rights (UAC prompt)...
if not defined IS_ADMIN if /i not "%~1"=="elevated" powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "try { Start-Process -FilePath '%~f0' -ArgumentList 'elevated' -Verb RunAs -ErrorAction Stop; exit 0 } catch { exit 1 }" && exit /b 0
if not defined IS_ADMIN echo [WARN] Not running as administrator. Items that need administrator rights are reported as unable-to-check in the result.

echo ========================================
echo  PC Check - %COMPUTERNAME%
echo  Output: %OUTFILE%
echo ========================================

powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "& '%SCRIPT_DIR%check_pc_kisa.ps1' 2>&1 | Out-File -FilePath '%OUTFILE%' -Encoding UTF8 -Width 4096"

echo.
echo Done. Result: %OUTFILE%
pause
