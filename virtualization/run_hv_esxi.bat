@echo off
setlocal enabledelayedexpansion
title ESXi Security Check (KISA 2026 HV-01~25)

rem ================================================================
rem  Run check_hv_esxi.sh on each ESXi host over SSH (inspector PC).
rem  Requires Windows OpenSSH client (ssh.exe, Windows 10 1809+).
rem  Usage: run_hv_esxi.bat [hosts.txt] [user]
rem         hosts.txt : one ESXi IP or hostname per line (# = comment)
rem  Output: hv_output\<host>_hv.txt  (result + evidence in one file)
rem ================================================================

set "SCRIPT_DIR=%~dp0"
set "SCRIPT=%SCRIPT_DIR%check_hv_esxi.sh"
set "HOSTS=%~1"
if "%HOSTS%"=="" set "HOSTS=%SCRIPT_DIR%hosts.txt"
set "USR=%~2"
if "%USR%"=="" set "USR=root"
set "OUT=%SCRIPT_DIR%hv_output"

where ssh >nul 2>&1
if errorlevel 1 (
    echo [ERROR] ssh.exe not found.
    echo         Settings ^> Apps ^> Optional features ^> Add "OpenSSH Client"
    pause
    exit /b 1
)
if not exist "%HOSTS%" (
    echo [ERROR] Host list not found: %HOSTS%
    echo         Create hosts.txt with one ESXi IP or hostname per line.
    pause
    exit /b 1
)
if not exist "%SCRIPT%" (
    echo [ERROR] Script not found: %SCRIPT%
    pause
    exit /b 1
)
if not exist "%OUT%" mkdir "%OUT%"

echo ========================================
echo  ESXi check - hosts: %HOSTS%
echo  User: %USR%   Output: %OUT%
echo  SSH was enabled only for this check? (HV-12)
echo  1) Yes - service policy is off, stop SSH after check
echo  2) No  - judge as-is
echo ========================================
set "SEL="
set /p SEL=Select [1/2]:
set "TEMP_SSH=0"
if "%SEL%"=="1" set "TEMP_SSH=1"

for /f "usebackq eol=# tokens=1" %%H in ("%HOSTS%") do (
    echo [*] %USR%@%%H
    ssh -o ConnectTimeout=10 -o StrictHostKeyChecking=accept-new %USR%@%%H "HV_INLINE=1 HV_SSH_TEMP=!TEMP_SSH! sh -s" < "%SCRIPT%" > "%OUT%\%%H_hv.txt"
    findstr /b "HV-" "%OUT%\%%H_hv.txt" >nul 2>&1
    if errorlevel 1 (
        move /y "%OUT%\%%H_hv.txt" "%OUT%\%%H_hv_FAILED.log" >nul
        echo     [FAILED] SSH connect/run failed - see %OUT%\%%H_hv_FAILED.log
    ) else (
        echo     done: %OUT%\%%H_hv.txt
    )
)

echo.
echo Copy hv_output\*_hv.txt to converter\virtualization\output\ and run convert_v4.py
echo (2. KISA -^> 7. Virtualization). Stop the SSH service on each ESXi after the check (HV-12).
pause
