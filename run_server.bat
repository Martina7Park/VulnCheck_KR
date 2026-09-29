@echo off
title Server Security Check

net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Run as Administrator.
    echo         Right-click this file ^> Run as administrator
    pause
    exit /b 1
)

set "SCRIPT_DIR=%~dp0"
echo ========================================
echo  Server Check - %COMPUTERNAME%
echo  1) EF  - Electronic Financial (SRV)
echo  2) KISA - Critical Info Infra 2026 Guide (W-01~W-64)
echo  3) Both (two result files)
echo ========================================
set "SEL="
set /p SEL=Select [1/2/3]:

if "%SEL%"=="2" (
    set "OUTFILE=%SCRIPT_DIR%%COMPUTERNAME%_w.txt"
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT_DIR%check_server_w.ps1" > "%SCRIPT_DIR%%COMPUTERNAME%_w.txt" 2>&1
) else if "%SEL%"=="3" (
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT_DIR%check_server.ps1" -Mode all > "%SCRIPT_DIR%%COMPUTERNAME%_server.txt" 2>&1
) else (
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT_DIR%check_server.ps1" -Mode srv > "%SCRIPT_DIR%%COMPUTERNAME%_server.txt" 2>&1
)

echo.
echo Done. Result file(s) in %SCRIPT_DIR%
if exist "%SCRIPT_DIR%%COMPUTERNAME%_server.txt" echo   %COMPUTERNAME%_server.txt  (EF)
if exist "%SCRIPT_DIR%%COMPUTERNAME%_w.txt" echo   %COMPUTERNAME%_w.txt  (KISA W)
echo Evidence: %COMPUTERNAME%_server_evidence.txt / %COMPUTERNAME%_w_evidence.txt
pause
