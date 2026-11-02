@echo off
title WebWAS Security Check

rem Administrator check (does not depend on the Server service, unlike "net session")
set "ISADMIN=0"
whoami /groups 2>nul | find "S-1-16-12288" >nul 2>&1 && set "ISADMIN=1"
if "%ISADMIN%"=="0" (
    echo [WARNING] Not running as Administrator. IIS config, SAM and some items will be reported as UNABLE - not checkable.
    echo           Right-click this file ^> Run as administrator for a complete check.
    echo.
)

set "SCRIPT_DIR=%~dp0"
set "OUTFILE=%SCRIPT_DIR%%COMPUTERNAME%_webwas.txt"

echo ========================================
echo  WebWAS Check - %COMPUTERNAME%
echo  1) EF  - Electronic Financial (WST)
echo  2) KISA - Critical Info Infra 2026 Guide (WEB-01~WEB-26)
echo  3) Both
echo  Output: %OUTFILE%  (UTF-8 with BOM, written by the script itself)
echo ========================================
set "SEL="
set /p SEL=Select [1/2/3]:
set "MODE=all"
if "%SEL%"=="1" set "MODE=ef"
if "%SEL%"=="2" set "MODE=mi"

rem The script writes the result file (UTF-8 BOM) and the evidence file itself; no cmd redirection (avoids OEM code page conversion and stderr mixing)
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT_DIR%check_webwas.ps1" -Mode %MODE% -OutFile "%OUTFILE%"

echo.
echo Done. Result  : %OUTFILE%
echo       Evidence: %SCRIPT_DIR%%COMPUTERNAME%_webwas_evidence.txt
pause
