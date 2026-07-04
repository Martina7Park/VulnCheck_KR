# ================================================================
# 전자금융기반시설 MSSQL Server 취약점 점검 스크립트 v4.0
# 기준: 전자금융기반시설 보안 취약점 평가기준 제2026-1호 [데이터베이스]
# 지원: SQL Server 2014 / 2016 / 2017 / 2019 / 2022
#
# [사용법] PowerShell (관리자 + SQL 권한)
#   $env:MSSQL_SERVER = "localhost"     # 기본값
#   $env:MSSQL_USER   = "sa"            # SQL 인증 (SA 또는 sysadmin)
#   $env:MSSQL_PASS   = "Password1!"
#   $env:MSSQL_WINAUTH = "1"            # Windows 인증 시 (선택)
#   .\check_dbms_mssql.ps1 > C:\Temp\MSSQL.txt
#
# [출력] DBM-항목코드|결과|근거
# ================================================================
$ErrorActionPreference = "SilentlyContinue"
$ProgressPreference    = "SilentlyContinue"

$MSSQL_SERVER = if ($env:MSSQL_SERVER) { $env:MSSQL_SERVER } else { "localhost" }
$MSSQL_USER   = if ($env:MSSQL_USER)   { $env:MSSQL_USER }   else { "sa" }
$MSSQL_PASS   = if ($env:MSSQL_PASS)   { $env:MSSQL_PASS }   else { "CHANGE_ME" }
$USE_WIN_AUTH = if ($env:MSSQL_WINAUTH) { $true } else { $false }

# sqlcmd 탐지
$sqlcmd = $null
foreach ($p in @("sqlcmd",
    "C:\Program Files\Microsoft SQL Server\Client SDK\ODBC\170\Tools\Binn\sqlcmd.exe",
    "C:\Program Files\Microsoft SQL Server\110\Tools\Binn\sqlcmd.exe",
    "C:\Program Files (x86)\Microsoft SQL Server\Client SDK\ODBC\170\Tools\Binn\sqlcmd.exe")) {
    if (Get-Command $p -EA SilentlyContinue) { $sqlcmd = $p; break }
}

$hn = $env:COMPUTERNAME
Write-Output "# ================================================================"
Write-Output "# 점검 대상: $hn"
Write-Output "# 점검 기준: 전자금융기반시설 보안 취약점 평가기준 제2026-1호 [데이터베이스]"
Write-Output "# 점검 일시: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Output "# ================================================================"

if (-not $sqlcmd) {
    Write-Output "# [ERROR] sqlcmd 미발견 - 수동 점검 필요"
    1..36 | ForEach-Object { Write-Output "DBM-$("{0:D3}" -f $_)|수동확인|sqlcmd 없음" }
    exit
}

function Run-Q([string]$q) {
    try {
        if ($USE_WIN_AUTH) {
            $r = & $sqlcmd -S $MSSQL_SERVER -E -Q $q -h -1 -W -s "|" 2>$null
        } else {
            $r = & $sqlcmd -S $MSSQL_SERVER -U $MSSQL_USER -P $MSSQL_PASS -Q $q -h -1 -W -s "|" 2>$null
        }
        return ($r | Where-Object { $_ -and $_ -notmatch "^\s*$" -and $_ -notmatch "^\(" -and $_ -notmatch "---" })
    } catch { return $null }
}
function Pass([string]$code,[string]$msg) { Write-Output "DBM-${code}|양호|$msg" }
function Fail([string]$code,[string]$msg) { Write-Output "DBM-${code}|취약|$msg" }
function NA  ([string]$code,[string]$msg) { Write-Output "DBM-${code}|N-A|$msg" }
function MC  ([string]$code,[string]$msg) { Write-Output "DBM-${code}|수동확인|$msg" }

# 버전 확인
$ver = (Run-Q "SELECT @@VERSION" | Select-Object -First 1).Trim()
$verNum = if ($ver -match "SQL Server (\d{4})") { $matches[1] } else { "unknown" }
$build = if ($ver -match "(\d+\.\d+\.\d+\.\d+)") { $matches[1] } else { "" }
Write-Output "# SQL Server 버전: $verNum ($build)"

# ── DBM-001: 취약하게 설정된 비밀번호 제거 ──────────────────────
$wkPw = Run-Q "SELECT COUNT(*) FROM sys.sql_logins WHERE is_policy_checked=0 AND is_disabled=0"
$cnt = [int]($wkPw | Select-Object -First 1).Trim()
if ($cnt -gt 0) { Fail "001" "비밀번호 정책 미적용 계정 ${cnt}개 (정책 적용 필요)" }
else { Pass "001" "모든 SQL 계정 비밀번호 정책 적용됨" }

# ── DBM-003: 불필요/관리되지 않는 계정 제거 ─────────────────────
MC "003" "업무상 불필요한 계정 수동 확인 (SELECT name,is_disabled FROM sys.server_principals WHERE type='S')"

# ── DBM-004: 불필요한 관리자 계정 제거 ──────────────────────────
$sysAdmins = Run-Q "SELECT name FROM sys.server_principals p JOIN sys.server_role_members r ON p.principal_id=r.member_principal_id JOIN sys.server_principals role ON r.role_principal_id=role.principal_id WHERE role.name='sysadmin' AND p.name NOT IN ('sa','##MS_PolicyEventProcessingLogin##','##MS_AgentSigningCertificate##')"
$admins = $sysAdmins | Where-Object { $_ }
if ($admins -and $admins.Count -gt 2) {
    MC "004" "sysadmin 계정: $($admins -join ', ') - 적정성 수동 확인"
} else {
    Pass "004" "sysadmin 추가 계정 없음 또는 최소화됨"
}

# ── DBM-005: 중요정보 암호화 ────────────────────────────────────
$tde = Run-Q "SELECT COUNT(*) FROM sys.dm_database_encryption_keys WHERE encryption_state=3"
$tdeCount = [int]($tde | Select-Object -First 1).Trim()
if ($tdeCount -gt 0) { Pass "005" "TDE 암호화 DB ${tdeCount}개 확인" }
else { MC "005" "TDE 미사용 - 컬럼 암호화 또는 다른 방법 수동 확인" }

# ── DBM-006: 로그인 실패 횟수 제한 ─────────────────────────────
# SQL Server는 Windows 정책으로 관리, 계정 잠금 정책 확인
$lockoutPol = net accounts 2>$null | Where-Object {$_ -match "Lockout threshold|잠금"}
if ($lockoutPol) {
    $cnt2 = ($lockoutPol -replace "[^0-9]","").Trim()
    if ($cnt2 -match "^\d+$") {
        $n = [int]$cnt2
        if ($n -eq 0) { Fail "006" "계정 잠금 임계값=0 (무제한)" }
        elseif ($n -le 5) { Pass "006" "계정 잠금 임계값=${n}회 (5회 이하)" }
        else { Fail "006" "계정 잠금 임계값=${n}회 (5회 이하 권고)" }
    } else { MC "006" "로그인 실패 제한: $lockoutPol" }
} else { MC "006" "로그인 실패 횟수 제한 수동 확인 (Windows 보안 정책)" }

# ── DBM-007: 비밀번호 복잡도 ────────────────────────────────────
$noPwc = Run-Q "SELECT COUNT(*) FROM sys.sql_logins WHERE is_policy_checked=0 AND is_disabled=0 AND name!='sa'"
$n7 = [int]($noPwc | Select-Object -First 1).Trim()
if ($n7 -gt 0) { Fail "007" "비밀번호 복잡도 정책 미적용 계정 ${n7}개" }
else { Pass "007" "모든 SQL 계정 비밀번호 복잡도 정책 적용됨" }

# ── DBM-008: 비밀번호 변경 주기 ─────────────────────────────────
$noExp = Run-Q "SELECT COUNT(*) FROM sys.sql_logins WHERE is_expiration_checked=0 AND is_disabled=0 AND name NOT IN ('sa','##MS_PolicyEventProcessingLogin##')"
$n8 = [int]($noExp | Select-Object -First 1).Trim()
if ($n8 -gt 0) { Fail "008" "비밀번호 만료 미설정 계정 ${n8}개" }
else { Pass "008" "모든 SQL 계정 비밀번호 만료 설정됨" }

# ── DBM-009: 미사용 세션 종료 ───────────────────────────────────
$timeout = Run-Q "SELECT value_in_use FROM sys.configurations WHERE name='remote query timeout'"
$t9 = [int](($timeout | Select-Object -First 1).Trim())
if ($t9 -gt 0 -and $t9 -le 600) { Pass "009" "remote query timeout=${t9}초" }
elseif ($t9 -eq 0) { Fail "009" "remote query timeout=0 (무제한)" }
else { MC "009" "세션 타임아웃 설정 수동 확인 (remote query timeout=${t9})" }

# ── DBM-011: 감사 로그 수집 및 백업 ─────────────────────────────
$auditCnt = Run-Q "SELECT COUNT(*) FROM sys.server_audits WHERE is_state_enabled=1"
$n11 = [int](($auditCnt | Select-Object -First 1).Trim())
if ($n11 -gt 0) { Pass "011" "서버 감사 ${n11}개 활성화됨" }
else {
    # C2 감사 (구버전)
    $c2 = Run-Q "SELECT value_in_use FROM sys.configurations WHERE name='c2 audit mode'"
    if (($c2 | Select-Object -First 1).Trim() -eq "1") { Pass "011" "C2 감사 모드 활성" }
    else { Fail "011" "서버 감사(Server Audit) 미설정" }
}

# ── DBM-013: 원격 접속 접근 제어 ───────────────────────────────
$ra = Run-Q "SELECT value_in_use FROM sys.configurations WHERE name='remote access'"
$n13 = [int](($ra | Select-Object -First 1).Trim())
if ($n13 -eq 0) { Pass "013" "remote access 비활성화됨 (=0)" }
else { Fail "013" "remote access 활성화됨 (=1) - 취약" }

# ── DBM-015: Public Role 불필요 권한 제거 ───────────────────────
$pubPriv = Run-Q "SELECT COUNT(*) FROM sys.database_permissions WHERE grantee_principal_id=0 AND permission_name NOT IN ('CONNECT')"
$n15 = [int](($pubPriv | Select-Object -First 1).Trim())
if ($n15 -gt 0) { Fail "015" "public role에 CONNECT 외 권한 ${n15}건 부여됨" }
else { Pass "015" "public role 불필요 권한 없음" }

# ── DBM-016: 보안패치 ───────────────────────────────────────────
# eos_checker.py 활용
$eosScript = Join-Path (Split-Path $MyInvocation.MyCommand.Path) "eos_checker.py"
if (Test-Path $eosScript) {
    $eosResult = python3 $eosScript "mssql" $verNum --no-api 2>$null
    $eosStatus = ($eosResult | Where-Object {$_ -match "^결과:"}) -replace "결과:\s*",""
    $eosDesc   = ($eosResult | Where-Object {$_ -match "^설명:"}) -replace "설명:\s*",""
    if ($eosStatus -eq "취약") { Fail "016" "SQL Server $verNum EoS/보안패치: $eosDesc" }
    elseif ($eosStatus -eq "양호") { Pass "016" "SQL Server $verNum 지원기간 내 - 최신 CU/SP 적용 수동 확인" }
    else { MC "016" "SQL Server $verNum 보안패치 수동 확인 (최신 CU 적용 여부)" }
} else { MC "016" "보안패치 현황 수동 확인 (SQL Server $verNum 최신 CU 확인)" }

# ── DBM-017: 시스템 테이블 접근 권한 ───────────────────────────
$sysTbl = Run-Q "SELECT COUNT(*) FROM sys.database_permissions WHERE grantee_principal_id NOT IN (1,2,3,4,5,6,7,9,10,11,12,13,14,15,16,17,18,19,20) AND major_id IN (SELECT object_id FROM sys.objects WHERE type IN ('S','IT') AND is_ms_shipped=1)"
$n17 = [int](($sysTbl | Select-Object -First 1).Trim())
if ($n17 -gt 0) { MC "017" "시스템 테이블 접근 권한 ${n17}건 - 적정성 수동 확인" }
else { Pass "017" "일반 사용자의 시스템 테이블 직접 접근 권한 없음" }

# ── DBM-019: 이전 비밀번호 재사용 ──────────────────────────────
MC "019" "SQL Server 자체 비밀번호 히스토리 미지원 - Windows 보안 정책으로 관리 (암호 히스토리 수)"

# ── DBM-020: 사용자별 계정 분리 ─────────────────────────────────
MC "020" "공용 계정(shared account) 사용 여부 수동 확인"

# ── DBM-021: 불필요한 ODBC/OLE-DB 데이터 소스 ─────────────────
$linkedSrv = Run-Q "SELECT COUNT(*) FROM sys.servers WHERE is_linked=1"
$n21 = [int](($linkedSrv | Select-Object -First 1).Trim())
if ($n21 -gt 0) { MC "021" "연결 서버(Linked Server) ${n21}개 - 불필요 항목 수동 확인" }
else { Pass "021" "연결 서버(Linked Server) 없음" }

# ── DBM-022: 설정 파일 및 중요 파일 접근 권한 ──────────────────
MC "022" "SQL Server 설치 폴더 접근 권한 수동 확인 (icacls 'C:\Program Files\Microsoft SQL Server')"

# ── DBM-024: WITH GRANT OPTION ──────────────────────────────────
$grantOpt = Run-Q "SELECT COUNT(*) FROM sys.database_permissions WHERE with_grant_option=1 AND grantee_principal_id NOT IN (1,2,3,4,5)"
$n24 = [int](($grantOpt | Select-Object -First 1).Trim())
if ($n24 -gt 0) { MC "024" "WITH GRANT OPTION 부여 ${n24}건 - 적정성 수동 확인" }
else { Pass "024" "일반 사용자의 WITH GRANT OPTION 없음" }

# ── DBM-025: EoS ────────────────────────────────────────────────
# DBM-016에서 이미 처리
MC "025" "SQL Server $verNum EoS 여부 - DBM-016 항목 참조"

# ── DBM-028: 불필요한 DB Object 제거 ────────────────────────────
# xp_cmdshell, Ole Automation 등
$xp = Run-Q "SELECT value_in_use FROM sys.configurations WHERE name='xp_cmdshell'"
$ole = Run-Q "SELECT value_in_use FROM sys.configurations WHERE name='Ole Automation Procedures'"
$xpVal  = [int](($xp  | Select-Object -First 1).Trim())
$oleVal = [int](($ole | Select-Object -First 1).Trim())
$issues28 = @()
if ($xpVal -eq 1) { $issues28 += "xp_cmdshell(활성)" }
if ($oleVal -eq 1) { $issues28 += "Ole Automation(활성)" }
if ($issues28) { Fail "028" "위험 Object 활성: $($issues28 -join ',')" }
else { Pass "028" "xp_cmdshell/Ole Automation 비활성화됨" }

# ── DBM-029: 자원 사용 제한 ─────────────────────────────────────
MC "029" "최대 서버 메모리, CPU 제한 등 자원 사용 제한 수동 확인 (sp_configure 참조)"

# ── DBM-031: SA 계정 보안설정 ───────────────────────────────────
$sa = Run-Q "SELECT is_disabled,name FROM sys.server_principals WHERE sid=0x01"
$saLine = $sa | Select-Object -First 1
if ($saLine -match "^1") { Pass "031" "SA 계정 비활성화됨 (is_disabled=1)" }
elseif ($saLine -match "^0") { Fail "031" "SA 계정 활성화됨 - 비활성화 또는 이름 변경 권고" }
else { MC "031" "SA 계정 상태 수동 확인" }

# ── DBM-034: DBMS 서비스 구동 권한 ─────────────────────────────
$svcUser = (Get-CimInstance Win32_Service -Filter "Name LIKE 'MSSQL%'" -EA SilentlyContinue | Select-Object -First 1).StartName
if (-not $svcUser) {
    # CimInstance 실패 시 레지스트리 폴백
    $mssqlRegKey = Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Services" -EA SilentlyContinue |
        Where-Object { $_.PSChildName -match "^MSSQL(SERVER|$)" } | Select-Object -First 1
    $svcUser = if ($mssqlRegKey) { (Get-ItemProperty $mssqlRegKey.PSPath -EA SilentlyContinue).ObjectName } else { $null }
}
if ($svcUser) {
    if ($svcUser -match "LocalSystem|NT AUTHORITY\\SYSTEM") {
        Fail "034" "SQL Server 서비스 계정: $svcUser (전체 권한 - 전용 서비스 계정 권고)"
    } elseif ($svcUser -match "NT Service\\|NetworkService|LocalService") {
        Pass "034" "SQL Server 서비스 계정: $svcUser (관리 서비스 계정)"
    } else {
        Pass "034" "SQL Server 서비스 계정: $svcUser (전용 계정)"
    }
} else { MC "034" "SQL Server 서비스 계정 수동 확인" }

# ── DBM-035: xp_cmdshell 비활성화 ───────────────────────────────
$xp2 = Run-Q "SELECT value_in_use FROM sys.configurations WHERE name='xp_cmdshell'"
$xpV2 = [int](($xp2 | Select-Object -First 1).Trim())
if ($xpV2 -eq 0) { Pass "035" "xp_cmdshell 비활성화됨 (=0)" }
else { Fail "035" "xp_cmdshell 활성화됨 (=1) - 보안 위험" }

# ── DBM-036: Registry Procedure 접근 권한 ──────────────────────
$regProc = Run-Q "SELECT COUNT(*) FROM sys.objects WHERE type='X' AND is_ms_shipped=1 AND name IN ('xp_regread','xp_regwrite','xp_regdeletekey','xp_regdeletevalue','xp_regenumkeys','xp_regenumvalues','xp_regaddmultistring','xp_regremovemultistring')"
$n36 = [int](($regProc | Select-Object -First 1).Trim())
if ($n36 -gt 0) {
    # PUBLIC이 실행 가능한지 확인
    $regPub = Run-Q "SELECT COUNT(*) FROM sys.database_permissions dp JOIN sys.objects o ON dp.major_id=o.object_id WHERE dp.grantee_principal_id=0 AND o.name LIKE 'xp_reg%'"
    $n36p = [int](($regPub | Select-Object -First 1).Trim())
    if ($n36p -gt 0) { Fail "036" "레지스트리 확장 프로시저 PUBLIC 접근 가능 (${n36p}개)" }
    else { Pass "036" "레지스트리 확장 프로시저 PUBLIC 접근 차단됨" }
} else { Pass "036" "레지스트리 확장 프로시저 없음" }

# N-A 항목 (타 DBMS 전용)
foreach ($code in @("012","014")) {
    NA $code "MSSQL 해당 없음 (Oracle 전용 항목)"
}
NA "026" "MSSQL 해당 없음 (Unix umask 개념 미적용)"
NA "030" "MSSQL 해당 없음 (Oracle/Tibero AUD$ 전용 항목)"
NA "032" "MSSQL 해당 없음 (PostgreSQL SSL 전용 항목)"
NA "033" "MSSQL 해당 없음 (MySQL 복제 비밀번호 전용 항목)"

Write-Output "# 점검 완료: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
