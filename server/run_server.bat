@echo off
title Server Security Check

set "SCRIPT_DIR=%~dp0"

rem Administrator check (warning only): HKU\S-1-5-19 can be read only by administrators.
rem Without admin rights the scripts still run; items needing it are reported as unable-to-check.
reg query "HKU\S-1-5-19" >nul 2>&1
if %errorlevel% neq 0 (
    echo [WARN] Not running as Administrator.
    echo        Items that need admin rights will be reported as "Unable to check".
    echo        Recommended: right-click this file ^> Run as administrator
    echo.
    pause
)

echo ========================================
echo  Server Check - %COMPUTERNAME%
echo  1) EF  - Electronic Financial (SRV)
echo  2) KISA - Critical Info Infra 2026 Guide (W-01~W-64)
echo  3) Both (two result files)
echo ========================================
set "SEL="
set /p SEL=Select [1/2/3] (Enter=1):
if not defined SEL set "SEL=1"

set "MODE="
if "%SEL%"=="1" set "MODE=srv"
if "%SEL%"=="2" set "MODE=w"
if "%SEL%"=="3" set "MODE=all"
if not defined MODE (
    echo [ERROR] Invalid selection. Enter 1, 2 or 3.
    pause
    exit /b 1
)

set "RAN_SRV="
set "RAN_W="
if "%MODE%"=="srv" set "RAN_SRV=1"
if "%MODE%"=="w" set "RAN_W=1"
if "%MODE%"=="all" set "RAN_SRV=1"
if "%MODE%"=="all" set "RAN_W=1"

rem The PowerShell scripts write their result files themselves (UTF-8 with BOM),
rem so no cmd redirect is used here (redirect would convert Korean text to the console code page).
rem Remove results of a previous run first so that only files made by this run are reported below.
if defined RAN_SRV del "%SCRIPT_DIR%%COMPUTERNAME%_server.txt" "%SCRIPT_DIR%%COMPUTERNAME%_server_evidence.txt" >nul 2>&1
if defined RAN_W del "%SCRIPT_DIR%%COMPUTERNAME%_w.txt" "%SCRIPT_DIR%%COMPUTERNAME%_w_evidence.txt" >nul 2>&1

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT_DIR%check_server.ps1" -Mode %MODE%
if %errorlevel% neq 0 echo [WARN] PowerShell exited with code %errorlevel%.

echo.
echo Done. Result file^(s^) in %SCRIPT_DIR%
if defined RAN_SRV if exist "%SCRIPT_DIR%%COMPUTERNAME%_server.txt" echo   %COMPUTERNAME%_server.txt  ^(EF^)
if defined RAN_SRV if not exist "%SCRIPT_DIR%%COMPUTERNAME%_server.txt" echo   [ERROR] %COMPUTERNAME%_server.txt was not created
if defined RAN_W if exist "%SCRIPT_DIR%%COMPUTERNAME%_w.txt" echo   %COMPUTERNAME%_w.txt  ^(KISA W^)
if defined RAN_W if not exist "%SCRIPT_DIR%%COMPUTERNAME%_w.txt" echo   [ERROR] %COMPUTERNAME%_w.txt was not created
if defined RAN_SRV if exist "%SCRIPT_DIR%%COMPUTERNAME%_server_evidence.txt" echo   Evidence: %COMPUTERNAME%_server_evidence.txt
if defined RAN_W if exist "%SCRIPT_DIR%%COMPUTERNAME%_w_evidence.txt" echo   Evidence: %COMPUTERNAME%_w_evidence.txt
pause
