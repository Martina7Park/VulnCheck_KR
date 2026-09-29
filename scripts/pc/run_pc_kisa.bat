@echo off
title PC Security Check (KISA 2026)

set "SCRIPT_DIR=%~dp0"
set "OUTFILE=%SCRIPT_DIR%PC_KISA_%COMPUTERNAME%.txt"

echo ========================================
echo  PC Check - %COMPUTERNAME%
echo  Output: %OUTFILE%
echo ========================================

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT_DIR%check_pc_kisa.ps1" > "%OUTFILE%" 2>&1

echo.
echo Done. Result: %OUTFILE%
pause
