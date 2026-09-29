# ================================================================
# 통합 자동 점검 (Windows Server) — check_all.bat 안의 PowerShell 부분
# ================================================================
#   OS·웹서버/WAS(IIS·Apache·Nginx·Tomcat·JEUS)·MSSQL 을 자동 탐지해 해당 점검을 모두 수행하고
#   결과를 zip 하나로 만듭니다. ※ all/build.py 가 생성 — 직접 수정하지 마세요.
#   환경변수: VC_MODE=ef|mi|all, WEBWAS=yes|no, MSSQL_SERVER / MSSQL_USER / MSSQL_PASS / MSSQL_WINAUTH
# ================================================================
$ErrorActionPreference = 'Continue'
$vcMode = "$env:VC_MODE".ToLower()
if (@('ef','mi','all') -notcontains $vcMode) { $vcMode = 'all' }
$vcHn   = $env:COMPUTERNAME
$vcTs   = Get-Date -Format 'yyyyMMdd_HHmmss'
$vcPkg  = "${vcHn}_vulncheck_$vcTs"
$vcBase = Split-Path -Parent $env:VC_SELF
$vcOut  = Join-Path $vcBase $vcPkg
$vcWork = Join-Path $env:TEMP "vulncheck_$vcTs"
New-Item -ItemType Directory -Force -Path $vcOut, $vcWork | Out-Null
$vcUtf8bom = New-Object System.Text.UTF8Encoding $true
function VC-Put([string]$vcName, [string]$vcText) { [IO.File]::WriteAllText((Join-Path $vcWork $vcName), $vcText, $vcUtf8bom) }

#@@EMBED@@

$vcSummary = Join-Path $vcOut 'summary.txt'
function VC-Say([string]$vcS) { Write-Host $vcS; Add-Content -Path $vcSummary -Value $vcS -Encoding UTF8 }
function VC-Count([string]$vcF, [string]$vcR) { @(Select-String -Path $vcF -Pattern "\|$vcR\|" -ErrorAction SilentlyContinue).Count }
function VC-Run([string]$vcLabel, [string]$vcCat, [string]$vcResName, [string]$vcScript, [hashtable]$vcScriptArgs) {
    Write-Host ""; Write-Host "▶ $vcLabel 점검 중..."
    $vcDir = Join-Path $vcOut "$vcCat\output"
    New-Item -ItemType Directory -Force -Path $vcDir | Out-Null
    $vcRes = Join-Path $vcDir "$vcResName.txt"
    Get-ChildItem $vcWork -Filter '*_evidence.txt' -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
    & (Join-Path $vcWork $vcScript) @vcScriptArgs 2>&1 | Out-File -FilePath $vcRes -Encoding UTF8
    # 증적: 스크립트가 자기 폴더(작업 폴더)에 남긴 *_evidence.txt → <결과이름>_evidence.txt (컨버터 자동 매칭)
    $vcEvd = Get-ChildItem $vcWork -Filter '*_evidence.txt' -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($vcEvd) { Move-Item -Force $vcEvd.FullName (Join-Path $vcDir "${vcResName}_evidence.txt") }
    VC-Say ("  - {0}: {1}.txt  (양호 {2} / 취약 {3} / 수동확인 {4} / N-A {5})" -f $vcLabel, $vcResName, (VC-Count $vcRes '양호'), (VC-Count $vcRes '취약'), (VC-Count $vcRes '수동확인'), (VC-Count $vcRes 'N-A'))
}

# ── OS ─────────────────────────────────────────────────────────
$vcOs = $null
try { $vcOs = Get-WmiObject Win32_OperatingSystem -ErrorAction Stop } catch {}
Set-Content -Path $vcSummary -Value "" -Encoding UTF8
VC-Say "================================================================"
VC-Say " 통합 자동 점검 — $vcHn"
VC-Say "   OS     : $(if ($vcOs) { "$($vcOs.Caption) $($vcOs.Version)" } else { 'Windows' })"
VC-Say "   기준   : $(switch ($vcMode) { 'ef' { '전자금융기반시설' } 'mi' { '주요정보통신기반시설 (2026 상세가이드)' } default { '전자금융 + 주요정보' } })"
VC-Say "   일시   : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
VC-Say "================================================================"

# ── 웹서버 / WAS 탐지 ──────────────────────────────────────────
$vcWeb = @()
if (Get-Service -Name 'W3SVC' -ErrorAction SilentlyContinue) { $vcWeb += 'IIS' }
$vcProcs = @(Get-Process -ErrorAction SilentlyContinue | ForEach-Object { $_.ProcessName.ToLower() })
if ($vcProcs -contains 'httpd' -or (Get-Service -Name 'Apache*' -ErrorAction SilentlyContinue)) { $vcWeb += 'Apache' }
if ($vcProcs -contains 'nginx') { $vcWeb += 'Nginx' }
if (($vcProcs | Where-Object { $_ -like 'tomcat*' }) -or (Get-Service -Name 'Tomcat*' -ErrorAction SilentlyContinue) -or $env:CATALINA_HOME) { $vcWeb += 'Tomcat' }
if ($env:JEUS_HOME) { $vcWeb += 'JEUS' }
switch -regex ("$env:WEBWAS".ToLower()) {
    '^(yes|y|1)$' { if (-not $vcWeb) { $vcWeb = @('(WEBWAS=yes 지정)') } }
    '^(no|n|0)$'  { $vcWeb = @() }
}

# ── DBMS 탐지 ──────────────────────────────────────────────────
$vcMssql = @(Get-Service -ErrorAction SilentlyContinue | Where-Object { ($_.Name -eq 'MSSQLSERVER' -or $_.Name -like 'MSSQL$*') -and $_.Status -eq 'Running' })
$vcOther = @()
if ($vcProcs | Where-Object { $_ -like 'oracle*' }) { $vcOther += 'Oracle' }
if ($vcProcs -contains 'mysqld' -or $vcProcs -contains 'mariadbd') { $vcOther += 'MySQL/MariaDB' }
if ($vcProcs -contains 'postgres') { $vcOther += 'PostgreSQL' }

VC-Say ""
VC-Say "[탐지 결과]"
VC-Say "  웹서버/WAS : $(if ($vcWeb) { $vcWeb -join ', ' } else { '없음 → 생략' })"
VC-Say "  DBMS       : $(if ($vcMssql) { 'MSSQL (' + (($vcMssql | ForEach-Object { $_.Name }) -join ', ') + ')' } else { 'MSSQL 없음' })$(if ($vcOther) { ' / ' + ($vcOther -join ', ') + ' → Windows 용 점검 스크립트 없음, 수동 점검' })"
VC-Say ""
VC-Say "[결과 파일]"

# ── 1. 서버 (항상) ─────────────────────────────────────────────
if ($vcMode -ne 'mi') { VC-Run '서버 (전자금융 SRV)' 'server' "${vcHn}_server" 'check_server.ps1' @{ Mode = 'srv' } }
if ($vcMode -ne 'ef') { VC-Run '서버 (주요정보 W)'   'server' "${vcHn}_w"      'check_server_w.ps1' @{} }

# ── 2. 웹서버 / WAS ────────────────────────────────────────────
if ($vcWeb) { VC-Run '웹서버/WAS' 'webwas' "${vcHn}_webwas" 'check_webwas.ps1' @{ Mode = $vcMode } }

# ── 3. MSSQL (기본 인스턴스 기준, MSSQL_PASS 가 없으면 Windows 인증 먼저 시도) ──
if ($vcMssql) { VC-Run 'DBMS (MSSQL)' 'dbms' "${vcHn}_mssql" 'check_dbms_mssql.ps1' @{ Mode = $vcMode } }
Remove-Item Env:\SQLCMDPASSWORD -ErrorAction SilentlyContinue

# ── 압축 ───────────────────────────────────────────────────────
Remove-Item -Recurse -Force $vcWork -ErrorAction SilentlyContinue
$vcZip = "$vcOut.zip"
$vcZipped = $false
if (Get-Command Compress-Archive -ErrorAction SilentlyContinue) {
    try { Compress-Archive -Path (Join-Path $vcOut '*') -DestinationPath $vcZip -Force -ErrorAction Stop; $vcZipped = $true } catch {}
}
VC-Say ""
VC-Say "================================================================"
VC-Say " 완료"
VC-Say "   결과 폴더 : $vcOut"
if ($vcZipped) { VC-Say "   압축 파일 : $vcZip   ← 이 파일 하나만 회수하세요" }
else { VC-Say "   (이 서버는 zip 생성 불가 — 결과 폴더를 통째로 회수하세요)" }
VC-Say "   점검자 PC : converter\ 폴더에서 압축을 풀면 분야별 output\ 에 바로 들어갑니다"
VC-Say "================================================================"
