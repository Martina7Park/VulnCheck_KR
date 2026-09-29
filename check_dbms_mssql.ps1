# ================================================================
# DBMS(MSSQL) 보안 취약점 자동 점검 스크립트 v4.0
# ================================================================
#
# [용도]
#   전자금융기반시설·주요정보통신기반시설 MSSQL 데이터베이스 보안 점검. -Mode ef|mi|all (주요정보 = 2026 상세가이드 D-01~26)
#   기준: 전자금융기반시설 보안 취약점 평가기준 제2026-1호 [데이터베이스]
#   Oracle/MySQL/PostgreSQL/Tibero는 check_dbms.sh 사용.
#
# [대상 DBMS]
#   SQL Server 2014 / 2016 / 2017 / 2019 / 2022
#
# [사전 조건]
#   - 관리자 권한 PowerShell 필요
#   - MSSQL sysadmin 이상 권한 계정 (SQL 인증 또는 Windows 인증)
#   - 실행 정책 변경: Set-ExecutionPolicy RemoteSigned -Scope Process -Force
#
# [접속 정보 환경변수]
#   $env:MSSQL_SERVER  = "localhost"   (기본: localhost)
#   $env:MSSQL_USER    = "sa"          (기본: sa)
#   $env:MSSQL_PASS    = "<비밀번호>"  (기본: CHANGE_ME — 반드시 변경)
#   $env:MSSQL_WINAUTH = "1"           (Windows 인증 시 — 설정하면 USER/PASS 무시)
#
# [실행 방법]
#   .\check_dbms_mssql.ps1 > C:\Temp\$env:COMPUTERNAME_mssql.txt
#
# [산출물]
#   1) 표준출력 — 파이프 구분자 결과 (파일로 리다이렉트)
#      형식: DBM-항목코드|결과|근거설명
#      결과: 양호 / 취약 / 수동확인 / N-A
#   2) 증적 파일 — $env:TEMP\<호스트명>_mssql_evidence.txt
#      점검 중 실행한 쿼리·명령어·출력·판정 근거가 타임스탬프와 함께 기록됨
#
# ================================================================
param([string]$Mode = "")   # ef=전자금융(DBM) / mi=주요정보 2026 상세가이드(D-01~26) / all=둘 다
$script:KMODE = "$Mode".ToLower()
if (-not $script:KMODE) {
    if ([Environment]::UserInteractive -and $Host.Name -eq 'ConsoleHost') {
        Write-Host "점검 기준을 선택하세요: 1) 전자금융기반시설(DBM)  2) 주요정보통신기반시설 2026 상세가이드(D-01~D-26)  3) 둘 다"
        $sel = Read-Host "선택 [1/2/3] (Enter=3)"
        $script:KMODE = switch ("$sel".Trim()) { '1' { 'ef' } '2' { 'mi' } default { 'all' } }
    } else { $script:KMODE = 'all' }
}
$script:KMODE = switch ($script:KMODE) { '1' {'ef'} '2' {'mi'} 'kisa' {'mi'} '3' {'all'} default { $script:KMODE } }
if (@('ef','mi','all') -notcontains $script:KMODE) { Write-Host "사용법: check_dbms_mssql.ps1 -Mode ef|mi|all"; exit 1 }
$ErrorActionPreference = "SilentlyContinue"
$ProgressPreference    = "SilentlyContinue"

$MSSQL_SERVER = if ($env:MSSQL_SERVER) { $env:MSSQL_SERVER } else { "localhost" }
$MSSQL_USER   = if ($env:MSSQL_USER)   { $env:MSSQL_USER }   else { "sa" }
$MSSQL_PASS   = $env:MSSQL_PASS
$USE_WIN_AUTH = if ($env:MSSQL_WINAUTH) { $true } else { $false }

# sqlcmd 탐지
$sqlcmd = $null
foreach ($p in @("sqlcmd",
    "C:\Program Files\SqlCmd\sqlcmd.exe",
    "C:\Program Files\Microsoft SQL Server\Client SDK\ODBC\180\Tools\Binn\sqlcmd.exe",
    "C:\Program Files\Microsoft SQL Server\Client SDK\ODBC\170\Tools\Binn\sqlcmd.exe",
    "C:\Program Files\Microsoft SQL Server\110\Tools\Binn\sqlcmd.exe",
    "C:\Program Files (x86)\Microsoft SQL Server\Client SDK\ODBC\170\Tools\Binn\sqlcmd.exe")) {
    if (Get-Command $p -EA SilentlyContinue) { $sqlcmd = $p; break }
}

$hn = $env:COMPUTERNAME
Write-Output "# ================================================================"
Write-Output "# 점검 대상: $hn"
Write-Output "# DBMS 종류: mssql"
Write-Output "# 점검 기준: $(switch ($script:KMODE) { 'ef' { '전자금융기반시설 보안 취약점 평가기준 제2026-1호 [데이터베이스]' } 'mi' { '주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드(2026) [DBMS D-01~D-26]' } default { '전자금융기반시설 보안 취약점 평가기준 제2026-1호 [데이터베이스] + 주요정보통신기반시설 상세가이드(2026) [DBMS D-01~D-26]' } })"
Write-Output "# 점검 일시: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Output "# ================================================================"

if (-not $sqlcmd) {
    Write-Output "# [ERROR] sqlcmd 미발견 - 수동 점검 필요"
    if ($script:KMODE -ne 'mi') { @("001","003","004","005","006","007","008","009","011","012","013","014","015","016","017","019","020","021","022","024","025","026","028","029","030","031","032","033","034","035","036") | ForEach-Object { Write-Output "DBM-${_}|수동확인|sqlcmd 없음" } }
    if ($script:KMODE -ne 'ef') { 1..26 | ForEach-Object { Write-Output ("D-{0:D2}|수동확인|sqlcmd 없음 - 수동 점검 필요" -f $_) } }
    exit
}

# -C 지원 탐지: ODBC sqlcmd '[-C Trust …]' / go-sqlcmd '-C,--trust-server-certificate'
# ODBC 18 sqlcmd 는 암호화 기본 필수 → 자체 서명 인증서 환경은 -C(서버 인증서 신뢰) 필요 (MSSQL_ENCRYPT=0 이면 생략)
$script:TrustCert = @(); if ($env:MSSQL_ENCRYPT -ne "0" -and ((& $sqlcmd -? 2>&1 | Out-String) -match '(?i)-C(\s+|,\s*--)trust')) { $script:TrustCert = @('-C') }
$script:QErr = $false
function Run-Q([string]$q) {
    # -b: 오류 시 종료코드 1, -r 1: 오류 메시지를 stderr 로 분리 → 'Msg nnn …' 문장이 결과로 섞이지 않음. 오류는 증적에 기록하고 $null 반환
    $a = @('-S',$MSSQL_SERVER,'-Q',"SET NOCOUNT ON; $q",'-h','-1','-W','-s','|','-b','-r','1') + $script:TrustCert
    $a += if ($USE_WIN_AUTH) { @('-E') } else { @('-U',$MSSQL_USER) }
    $err = ""
    try { $r = & $sqlcmd @a 2>&1 | ForEach-Object { if ($_ -is [System.Management.Automation.ErrorRecord]) { $err += "$_`n" } else { $_ } } } catch { $err += "$_" }
    if ($LASTEXITCODE -ne 0 -or $err) {
        if ($script:EVD) { "[SQL오류] $($q.Substring(0,[Math]::Min(200,$q.Length)))`n$err" | Add-Content $script:EVD -Encoding UTF8 }
        $script:QErr = $true; return $null
    }
    $script:QErr = $false
    return ($r | Where-Object { $_ -and $_ -notmatch '^\s*$' })
}
function Q-Int([string]$q) { $v = Run-Q $q | Select-Object -First 1; if ("$v".Trim() -match '^-?\d+$') { [int]"$v".Trim() } else { $null } }
# 접속: MSSQL_PASS 미지정 → Windows 인증 우선 시도 → 실패하고 대화형이면 숨김 입력 (비밀번호는 SQLCMDPASSWORD 환경변수로만 전달, 종료 시 제거)
if (-not $USE_WIN_AUTH -and -not $MSSQL_PASS) {
    $USE_WIN_AUTH = $true
    if ("$(Run-Q 'SELECT 1' | Select-Object -First 1)".Trim() -ne "1") {
        $USE_WIN_AUTH = $false
        if ([Environment]::UserInteractive -and $Host.UI.RawUI) {
            try { $sp = Read-Host -AsSecureString "SQL Server $MSSQL_USER 비밀번호"; $MSSQL_PASS = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($sp)) } catch {}
        }
    }
}
$env:SQLCMDPASSWORD = $MSSQL_PASS
$script:cntPass=0; $script:cntFail=0; $script:cntMC=0; $script:cntNA=0

$script:ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$script:EVD = "$script:ScriptDir\${hn}_mssql_evidence.txt"
"# ================================================================" | Out-File $script:EVD -Encoding UTF8
"# MSSQL 증적 파일 (감사 추적용)" | Add-Content $script:EVD -Encoding UTF8
"# 대상: $hn / MSSQL Server: $MSSQL_SERVER" | Add-Content $script:EVD -Encoding UTF8
"# 생성: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" | Add-Content $script:EVD -Encoding UTF8
"# ================================================================" | Add-Content $script:EVD -Encoding UTF8

# 평가기준 제2026-1호 [데이터베이스] 평가항목 31개 — 그 외 DBM 코드는 참고 점검(증적만 기록, 결과·집계 제외)
$script:GUIDE_DBM = @("001","003","004","005","006","007","008","009","011","012","013","014","015","016","017","019","020","021","022","024","025","026","028","029","030","031","032","033","034","035","036")
function Test-Guide([string]$code,[string]$res,[string]$msg) {
    if ($script:KMODE -eq 'mi') { "[참고-주요정보 모드 제외] DBM-${code}|$res|$msg`n" | Add-Content $script:EVD -Encoding UTF8; return $false }
    if ($script:GUIDE_DBM -contains $code) { return $true }
    "[참고-평가기준 외] DBM-${code}|$res|$msg`n" | Add-Content $script:EVD -Encoding UTF8; return $false
}
function Pass([string]$code,[string]$msg) { if (-not (Test-Guide $code "양호" $msg)) { return }; $script:cntPass++; Write-Output "DBM-${code}|양호|$msg"; "[판정] DBM-${code}|양호|$msg`n" | Add-Content $script:EVD -Encoding UTF8 }
function Fail([string]$code,[string]$msg) { if (-not (Test-Guide $code "취약" $msg)) { return }; $script:cntFail++; Write-Output "DBM-${code}|취약|$msg"; "[판정] DBM-${code}|취약|$msg`n" | Add-Content $script:EVD -Encoding UTF8 }
function NA  ([string]$code,[string]$msg) { if (-not (Test-Guide $code "N-A" $msg)) { return }; $script:cntNA++;   Write-Output "DBM-${code}|N-A|$msg"; "[판정] DBM-${code}|N-A|$msg`n" | Add-Content $script:EVD -Encoding UTF8 }
function MC  ([string]$code,[string]$msg) { if (-not (Test-Guide $code "수동확인" $msg)) { return }; $script:cntMC++;   Write-Output "DBM-${code}|수동확인|$msg"; "[판정] DBM-${code}|수동확인|$msg`n" | Add-Content $script:EVD -Encoding UTF8 }

function KPut([string]$code,[string]$res,[string]$msg) {   # 가이드 D 항목 판정 출력 (전자금융 모드는 생략)
    if ($script:KMODE -eq 'ef') { return }
    $msg = ($msg -replace "[`r`n]+", " / ") -replace '\|', '/'
    switch ($res) { '양호' { $script:cntPass++ } '취약' { $script:cntFail++ } '수동확인' { $script:cntMC++ } default { $script:cntNA++ } }
    Write-Output "$code|$res|$msg"; "[판정] $code|$res|$msg`n" | Add-Content $script:EVD -Encoding UTF8
}
function Evd([string]$item,[string]$cmd) {
    "[$item] $(Get-Date -Format 'HH:mm:ss') PS> $cmd" | Add-Content $script:EVD -Encoding UTF8
    try { $r = Invoke-Expression $cmd 2>&1 | Out-String; $r | Add-Content $script:EVD -Encoding UTF8 } catch { $_.Exception.Message | Add-Content $script:EVD -Encoding UTF8 }
    "" | Add-Content $script:EVD -Encoding UTF8
}
function EvdQ([string]$item,[string]$desc,[string]$val) {
    "[$item] $(Get-Date -Format 'HH:mm:ss') SQL: $desc" | Add-Content $script:EVD -Encoding UTF8
    "$val`n" | Add-Content $script:EVD -Encoding UTF8
}

# Windows 보안 정책 (DBM-006/007: SQL 로그인 CHECK_POLICY 는 OS 정책을 따름)
$seceditFile = "$env:TEMP\mssql_secpol_${PID}.cfg"
$null = secedit /export /cfg $seceditFile /areas SECURITYPOLICY /quiet 2>$null
function Get-SecPol([string]$Key) {
    if (Test-Path $seceditFile) {
        $line = Get-Content $seceditFile -EA SilentlyContinue | Where-Object { $_ -match "^\s*$([regex]::Escape($Key))\s*=" }
        if ($line) { return ($line -split "=",2)[1].Trim() }
    }; return $null
}

# 접속 확인
$connTest = Run-Q "SELECT 1"
$connVal = ($connTest | Select-Object -First 1)
if (-not $connVal -or $connVal.Trim() -ne "1") {
    Write-Output "# [ERROR] SQL Server 접속 실패 ($MSSQL_SERVER) - 전 항목 수동확인 처리"
    1..36 | ForEach-Object { MC ("{0:D3}" -f $_) "SQL Server 접속 실패 - 수동 점검 필요" }
    1..26 | ForEach-Object { KPut ("D-{0:D2}" -f $_) '수동확인' "SQL Server 접속 실패($MSSQL_SERVER) - 접속 정보 확인 후 재점검" }
    $total=$script:cntPass+$script:cntFail+$script:cntMC+$script:cntNA
    Write-Output "# ================================================================"
    Write-Output "# 점검 요약"
    Write-Output "#   총 점검 항목: $total"
    Write-Output "#   양호:         $($script:cntPass)"
    Write-Output "#   취약:         $($script:cntFail)"
    Write-Output "#   수동확인:     $($script:cntMC)"
    Write-Output "#   N-A:          $($script:cntNA)"
    Write-Output "# ================================================================"
    $env:SQLCMDPASSWORD = ""
    Remove-Item $seceditFile -Force -EA SilentlyContinue
    exit
}

# 버전 확인
$ver = (Run-Q "SELECT @@VERSION" | Select-Object -First 1).Trim()
$verNum = if ($ver -match "SQL Server (\d{4})") { $matches[1] } else { "unknown" }
$build = if ($ver -match "(\d+\.\d+\.\d+\.\d+)") { $matches[1] } else { "" }
Write-Output "# SQL Server 버전: $verNum ($build)"
Write-Output "# 접속: $(if ($USE_WIN_AUTH) { 'Windows 인증' } else { "SQL 인증($MSSQL_USER)" })"

# ── DBM-001: 취약하게 설정된 비밀번호 제거 ──────────────────────
$cnt = Q-Int "SELECT COUNT(*) FROM sys.sql_logins WHERE is_policy_checked=0 AND is_disabled=0"
EvdQ "DBM-001" "SELECT COUNT(*) FROM sys.sql_logins WHERE is_policy_checked=0 AND is_disabled=0" "$cnt"
# 평가기준: 취약 비밀번호 여부는 해시 크랙으로 확인 → 정책 적용 여부만으로 양호/취약 확정 불가
if ($null -eq $cnt) { MC "001" "SQL 로그인 조회 실패(권한) - 비밀번호 복잡도·취약 여부 해시 크랙 확인 필요" }
elseif ($cnt -gt 0) { MC "001" "비밀번호 정책 미적용 계정 ${cnt}개 (크랙 우선 대상) - 비밀번호 복잡도·취약 여부 해시 크랙 확인 필요" }
else { MC "001" "모든 SQL 계정 비밀번호 정책 적용됨 - 비밀번호 복잡도·취약 여부 해시 크랙 확인 필요" }

# ── DBM-003: 불필요/관리되지 않는 계정 제거 ─────────────────────
$logins = @(Run-Q 'SELECT p.name+'' | ''+p.type_desc COLLATE DATABASE_DEFAULT+'' | disabled=''+CAST(p.is_disabled AS varchar)+'' | created=''+CONVERT(varchar(10),p.create_date,120)+'' | pwdset=''+ISNULL(CONVERT(varchar(10),CAST(LOGINPROPERTY(p.name,''PasswordLastSetTime'') AS datetime),120),''-'')+'' | expired=''+ISNULL(CAST(LOGINPROPERTY(p.name,''IsExpired'') AS varchar),''-'')+'' | locked=''+ISNULL(CAST(LOGINPROPERTY(p.name,''IsLocked'') AS varchar),''-'') FROM sys.server_principals p WHERE p.type IN (''S'',''U'',''G'') AND p.name NOT LIKE ''##%'' ORDER BY p.name')
EvdQ "DBM-003" "로그인 목록 (name | type | disabled | created | pwdset | expired | locked)" ($logins -join "`n")
MC "003" "로그인 $($logins.Count)개 - 업무상 불필요·장기 미사용 계정 인터뷰 확인 (위 현황)"

# ── DBM-004: 불필요한 관리자 계정 제거 ──────────────────────────
# 평가기준: 서버 수준 역할(sysadmin, serveradmin, securityadmin, processadmin, setupadmin, bulkadmin, diskadmin, dbcreator 등) 부여 계정 → 인터뷰로 불필요 여부 확인
$sysAdmins = Run-Q "SELECT role.name+': '+p.name FROM sys.server_principals p JOIN sys.server_role_members r ON p.principal_id=r.member_principal_id JOIN sys.server_principals role ON r.role_principal_id=role.principal_id WHERE role.name IN ('sysadmin','serveradmin','securityadmin','processadmin','setupadmin','bulkadmin','diskadmin','dbcreator') AND p.name NOT LIKE '##%' AND p.name NOT LIKE 'NT SERVICE\%' AND p.name NOT LIKE 'NT AUTHORITY\%'"
EvdQ "DBM-004" "server role members (sysadmin/serveradmin/securityadmin/processadmin/setupadmin/bulkadmin/diskadmin/dbcreator)" ($sysAdmins -join "`n")
$admins = @($sysAdmins | Where-Object { $_ -and $_.Trim() })
if ($admins.Count -gt 0) {
    MC "004" "서버 수준 관리자 역할 부여 $($admins.Count)건: $(($admins | Select-Object -First 8) -join ', ') - 업무상 필요 여부 인터뷰 확인"
} else {
    MC "004" "서버 수준 관리자 역할 조회 결과 없음 - 조회 권한 및 관리자 계정 수동 확인"
}

# ── DBM-005: 중요정보 암호화 ────────────────────────────────────
$tdeCount = Q-Int "SELECT COUNT(*) FROM sys.dm_database_encryption_keys WHERE encryption_state=3"
EvdQ "DBM-005" "TDE encryption_state=3 count" "$tdeCount"
# 평가기준: 중요정보 컬럼이 평문/취약 알고리즘으로 저장되면 취약 — TDE 는 파일 수준 암호화라 조회 시 평문 (판단 근거 아님)
MC "005" "TDE 암호화 DB $(if ($null -eq $tdeCount) { '조회 실패' } else { "${tdeCount}개" })(참고) - 중요정보 컬럼 암호화(Always Encrypted·컬럼 암호화) 적용 여부 확인"

# ── DBM-006: 로그인 실패 횟수 제한 ─────────────────────────────
# SQL Server는 Windows 정책으로 관리, 계정 잠금 정책 확인
Evd "DBM-006" "net accounts 2>`$null | Select-String 'Lockout|잠금'"
# 잠금 임계값: secedit LockoutBadCount 우선, 대체로 net accounts '임계값' 한 줄만 사용 (한글 OS는 '잠금' 포함 줄이 3개)
$n = $null; $lockSrc = ""
$lbc = Get-SecPol "LockoutBadCount"
if ($null -ne $lbc -and "$lbc" -match "^\d+$") { $n = [int]$lbc; $lockSrc = "secedit LockoutBadCount" }
else {
    $lockLine = net accounts 2>$null | Where-Object {$_ -match "Lockout threshold|잠금 임계"} | Select-Object -First 1
    if ($lockLine) {
        $v6 = ($lockLine -split ":",2)[-1].Trim()
        if ($v6 -match "^\d+$") { $n = [int]$v6 } elseif ($v6 -match "Never|아님|없음") { $n = 0 }
        $lockSrc = "net accounts: $($lockLine.Trim())"
    }
}
$noPol = Run-Q "SELECT name FROM sys.sql_logins WHERE is_policy_checked=0 AND is_disabled=0 AND name NOT LIKE '##%'"
$noPolList = @($noPol | Where-Object { $_ -and $_.Trim() })
EvdQ "DBM-006" "잠금 임계값($lockSrc) / CHECK_POLICY=OFF 활성 SQL 로그인" "$n / $($noPolList -join ', ')"
if ($null -eq $n) { MC "006" "계정 잠금 임계값 확인 실패 - Windows 계정 잠금 정책 수동 확인" }
elseif ($n -eq 0) { Fail "006" "계정 잠금 임계값 없음(무제한) - 5회 이하 설정 필요" }
elseif ($n -gt 5) { Fail "006" "계정 잠금 임계값=${n}회 (5회 이하 필요)" }
elseif ($noPolList.Count -gt 0) { Fail "006" "잠금 임계값 ${n}회이나 CHECK_POLICY=OFF SQL 로그인 $($noPolList.Count)개(잠금 미적용): $(($noPolList | Select-Object -First 5) -join ', ') - 서비스 운영 계정은 평가 제외 가능" }
else { Pass "006" "계정 잠금 임계값=${n}회 (5회 이하), 활성 SQL 로그인 모두 CHECK_POLICY 적용" }

# ── DBM-007: 비밀번호 복잡도 ────────────────────────────────────
# 평가기준: 계정별 Windows password policy(CHECK_POLICY) 적용 + OS 'password must meet complexity requirements' 사용
$noPwc = Run-Q "SELECT COUNT(*) FROM sys.sql_logins WHERE is_policy_checked=0 AND is_disabled=0 AND name NOT LIKE '##%'"
$pwc7 = Get-SecPol "PasswordComplexity"; $min7 = Get-SecPol "MinimumPasswordLength"
EvdQ "DBM-007" "is_policy_checked=0 활성 로그인 수 / OS PasswordComplexity / MinimumPasswordLength" "$($noPwc -join ' ') / $pwc7 / $min7"
$n7 = if ("$($noPwc | Select-Object -First 1)".Trim() -match '^\d+$') { [int]"$($noPwc | Select-Object -First 1)".Trim() } else { $null }
if ($null -eq $n7) { MC "007" "SQL 로그인 CHECK_POLICY 조회 실패 - 수동 확인" }
elseif ($n7 -gt 0) { Fail "007" "비밀번호 정책(CHECK_POLICY) 미적용 활성 계정 ${n7}개" }
elseif ("$pwc7" -eq "0") { Fail "007" "OS 비밀번호 복잡도 정책 사용 안 함 (PasswordComplexity=0) - SQL 로그인 복잡도 미강제" }
elseif ($null -eq $pwc7) { MC "007" "모든 활성 SQL 계정 CHECK_POLICY 적용 - OS 복잡도 정책 확인 실패(관리자 권한 필요)" }
elseif ($null -ne $min7 -and [int]$min7 -lt 8) { Fail "007" "OS 최소 비밀번호 길이=${min7}자 (3종 8자 미달)" }
else { Pass "007" "모든 활성 SQL 계정 CHECK_POLICY 적용, OS 복잡도 사용 (최소 길이 ${min7}자)" }

# ── DBM-008: 비밀번호 변경 주기 ─────────────────────────────────
$noExp = Run-Q "SELECT COUNT(*) FROM sys.sql_logins WHERE is_expiration_checked=0 AND is_disabled=0 AND name NOT IN ('sa','##MS_PolicyEventProcessingLogin##')"
EvdQ "DBM-008" "is_expiration_checked=0 count" ($noExp -join "`n")
$n8 = if ("$($noExp | Select-Object -First 1)".Trim() -match '^\d+$') { [int]"$($noExp | Select-Object -First 1)".Trim() } else { $null }
# 평가기준 평가예시: 최근 비밀번호 변경일로부터 1분기(약 90일) 이상 지난 계정 존재 시 취약
$old8 = Run-Q "SELECT name+' ('+CONVERT(varchar(10),CAST(LOGINPROPERTY(name,'PasswordLastSetTime') AS datetime),120)+')' FROM sys.sql_logins WHERE is_disabled=0 AND name NOT LIKE '##%' AND DATEDIFF(DAY,CAST(LOGINPROPERTY(name,'PasswordLastSetTime') AS datetime),GETDATE())>=90"
$old8List = @($old8 | Where-Object { $_ -and $_.Trim() })
EvdQ "DBM-008" "비밀번호 변경 후 90일 이상 활성 SQL 로그인 (PasswordLastSetTime)" ($old8List -join "`n")
if ($old8List.Count -gt 0) { Fail "008" "비밀번호 변경 후 90일 이상 경과 계정 $($old8List.Count)개: $(($old8List | Select-Object -First 5) -join ', ') - 서비스 운영 계정은 평가 제외 가능" }
elseif ($null -eq $n8) { MC "008" "비밀번호 만료 설정 조회 실패 - 수동 확인" }
elseif ($n8 -gt 0) { MC "008" "90일 이상 경과 계정 없음, 비밀번호 만료(CHECK_EXPIRATION) 미설정 계정 ${n8}개 - 주기적 변경 관리 여부 확인" }
else { Pass "008" "모든 활성 SQL 계정 비밀번호 90일 이내 변경, 만료 설정됨" }

# ── DBM-009: 미사용 세션 종료 ───────────────────────────────────
# 평가기준: 사용자 세션 last_request_end_time 이 15분(내부 규정 미명시 시) 초과 유휴 상태로 남아 있으면 취약
#   ('remote query timeout' 은 연결 서버 쿼리 타임아웃으로 유휴 세션 종료와 무관)
$idle = Run-Q "SELECT login_name+' (idle '+CAST(DATEDIFF(MINUTE,last_request_end_time,GETDATE()) AS varchar)+'분)' FROM sys.dm_exec_sessions WHERE is_user_process=1 AND status='sleeping' AND DATEDIFF(MINUTE,last_request_end_time,GETDATE())>15"
EvdQ "DBM-009" "15분 초과 유휴 사용자 세션 (sys.dm_exec_sessions)" ($idle -join "`n")
$idleList = @($idle | Where-Object { $_ -and $_.Trim() })
if ($idleList.Count -gt 0) { Fail "009" "15분 초과 유휴 세션 $($idleList.Count)개: $(($idleList | Select-Object -First 3) -join ', ') - 서비스 계정은 평가 제외 가능" }
else { MC "009" "현재 15분 초과 유휴 세션 없음 - 자동 종료 설정(접근제어 솔루션 등) 여부 수동 확인" }

# ── DBM-011: 감사 로그 수집 및 백업 ─────────────────────────────
$auditCnt = Run-Q "SELECT COUNT(*) FROM sys.server_audits WHERE is_state_enabled=1"
EvdQ "DBM-011" "server_audits enabled count" ($auditCnt -join "`n")
$n11 = if ("$($auditCnt | Select-Object -First 1)".Trim() -match '^\d+$') { [int]"$($auditCnt | Select-Object -First 1)".Trim() } else { $null }
# 평가기준: 감사 로그 수집 + 주기적 백업(인터뷰·증적) 모두 충족 시 양호 → 수집 중이면 백업 여부 수동확인
$spec11 = Run-Q "SELECT s.name+': '+d.audit_action_name FROM sys.server_audit_specifications s JOIN sys.server_audit_specification_details d ON s.server_specification_id=d.server_specification_id WHERE s.is_state_enabled=1"
EvdQ "DBM-011" "활성 서버 감사 사양 (audit_action_name)" ($spec11 -join "`n")
$loginAud = @($spec11 | Where-Object { $_ -match "FAILED_LOGIN_GROUP|SUCCESSFUL_LOGIN_GROUP" })
if ($null -eq $n11) { MC "011" "서버 감사 조회 실패(권한) - 수동 확인" }
elseif ($n11 -gt 0 -and $loginAud.Count -eq 0) { Fail "011" "서버 감사 ${n11}개 활성이나 로그인 성공/실패 감사 사양(FAILED_LOGIN_GROUP/SUCCESSFUL_LOGIN_GROUP) 미설정" }
elseif ($n11 -gt 0) { MC "011" "서버 감사 ${n11}개 활성, 로그인 감사 사양 $($loginAud.Count)건 - 감사 로그 주기적 백업 여부 확인 (미백업 시 취약)" }
else {
    # C2 감사 (구버전)
    $c2 = Run-Q "SELECT value_in_use FROM sys.configurations WHERE name='c2 audit mode'"
    if (($c2 | Select-Object -First 1).Trim() -eq "1") { MC "011" "C2 감사 모드 활성 - 감사 로그 주기적 백업 여부 확인 (미백업 시 취약)" }
    else { Fail "011" "서버 감사(Server Audit) 미설정 - 감사 로그 미수집" }
}

# ── DBM-013: 원격 접속 접근 제어 ───────────────────────────────
# 평가기준: Windows 방화벽(또는 네트워크 장비·솔루션)으로 DB 포트 원격 접근제어 ('remote access' 옵션은 무관)
$port13 = "$(Run-Q "SELECT TOP 1 local_tcp_port FROM sys.dm_exec_connections WHERE local_tcp_port IS NOT NULL" | Select-Object -First 1)".Trim()
if ($port13 -notmatch '^\d+$') {   # 공유 메모리 접속이면 NULL → 레지스트리 IPAll TcpPort/TcpDynamicPorts
    $ipall = Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server' -EA SilentlyContinue | ForEach-Object { Get-ItemProperty "$($_.PSPath)\MSSQLServer\SuperSocketNetLib\Tcp\IPAll" -EA SilentlyContinue } | Select-Object -First 1
    $port13 = @("$($ipall.TcpPort)","$($ipall.TcpDynamicPorts)") | Where-Object { $_ -match '^\d+$' } | Select-Object -First 1
    if (-not $port13) { $port13 = '1433' }
}
$prof13 = @(Get-NetFirewallProfile -EA SilentlyContinue)
$off13  = @($prof13 | Where-Object { -not $_.Enabled } | ForEach-Object { "$($_.Name)" })
$fwRules = @(Get-NetFirewallRule -Enabled True -Direction Inbound -Action Allow -EA SilentlyContinue | Where-Object {
    $pf = $_ | Get-NetFirewallPortFilter -EA SilentlyContinue; $af = $_ | Get-NetFirewallApplicationFilter -EA SilentlyContinue
    ($pf.LocalPort -contains $port13) -or ($pf.LocalPort -contains 'Any' -and "$($af.Program)" -match 'sqlservr\.exe$') })
$fwDetail = foreach ($r in $fwRules) { "$($r.DisplayName): $(($r | Get-NetFirewallAddressFilter).RemoteAddress -join ',')" }
EvdQ "DBM-013" "방화벽 프로필 Enabled / DB 포트($port13) 인바운드 허용 규칙·원격 주소" "$(($prof13 | ForEach-Object { "$($_.Name)=$($_.Enabled)" }) -join ', ')`n$($fwDetail -join "`n")"
$open = @($fwRules | Where-Object { ($_ | Get-NetFirewallAddressFilter).RemoteAddress -contains "Any" })
if ($off13.Count -gt 0) { MC "013" "Windows 방화벽 비활성 프로필: $($off13 -join ',') - 네트워크 장비·솔루션 접근제어 수동 확인(없으면 취약)" }
elseif ($fwRules.Count -eq 0) { MC "013" "DB 포트($port13) 인바운드 허용 방화벽 규칙 없음 - 네트워크 장비·솔루션 접근제어 수동 확인" }
elseif ($open.Count -gt 0) { Fail "013" "DB 포트 $port13 모든 원격 주소 허용 규칙: $(($open | ForEach-Object { $_.DisplayName }) -join ', ')" }
else { Pass "013" "DB 포트 $port13 원격 주소 제한됨: $($fwDetail -join '; ')" }

# ── DBM-015: Public Role 불필요 권한 제거 ───────────────────────
# 기본 설치 시 master 시스템 개체(is_ms_shipped)에 public 기본 GRANT 가 있으므로 제외 — 사용자 개체·DB/서버 수준 권한만 판단
$dbs = @(Run-Q 'SET NOCOUNT ON; SELECT name+'' (''+state_desc COLLATE DATABASE_DEFAULT+'')'' FROM sys.databases')
$pubDb = Run-Q 'SET NOCOUNT ON; DECLARE @s nvarchar(max)=N''''; SELECT @s=@s+N''SELECT N''''''+REPLACE(name,'''''''','''''''''''')+N'':''''+p.class_desc COLLATE DATABASE_DEFAULT+N'''':''''+ISNULL(o.name,N''''-'''') COLLATE DATABASE_DEFAULT+N'''':''''+p.permission_name COLLATE DATABASE_DEFAULT FROM ''+QUOTENAME(name)+N''.sys.database_permissions p LEFT JOIN ''+QUOTENAME(name)+N''.sys.all_objects o ON p.class=1 AND o.object_id=p.major_id WHERE p.grantee_principal_id=0 AND p.state IN (''''G'''',''''W'''') AND p.permission_name NOT IN (''''CONNECT'''',''''VIEW ANY COLUMN ENCRYPTION KEY DEFINITION'''',''''VIEW ANY COLUMN MASTER KEY DEFINITION'''') AND (p.class<>1 OR o.is_ms_shipped=0) UNION ALL '' FROM sys.databases WHERE state_desc=''ONLINE'' AND HAS_DBACCESS(name)=1; IF LEN(@s)>0 BEGIN SET @s=LEFT(@s,LEN(@s)-10); EXEC(@s); END'; $e15a = $script:QErr
$pubSrv = Run-Q 'SET NOCOUNT ON; SELECT ''SERVER:''+class_desc+'' ''+permission_name FROM sys.server_permissions WHERE grantee_principal_id=2 AND permission_name NOT IN (''VIEW ANY DATABASE'',''CONNECT SQL'') AND NOT (class_desc=''ENDPOINT'' AND permission_name=''CONNECT'') AND state IN (''G'',''W'')'; $e15b = $script:QErr
$pubList = @(@($pubDb) + @($pubSrv) | Where-Object { $_ -and "$_".Trim() })
EvdQ "DBM-015" "public 역할 비기본 권한 (전 DB: $($dbs -join ', ') + 서버 수준, 시스템 개체 기본 GRANT 제외)" ($pubList -join "`n")
if ($e15a -and $e15b) { MC "015" "public 권한 조회 실패(권한) - 수동 확인" }
elseif ($pubList.Count -gt 0) { MC "015" "public 역할 비기본 권한 $($pubList.Count)건: $(($pubList | Select-Object -First 5) -join ', ') - 업무상 필요 여부 확인 (불필요 시 취약)" }
else { Pass "015" "public 역할에 기본 외 권한 없음" }

# ── DBM-016: 보안패치 ───────────────────────────────────────────
# eos_checker.py 활용
EvdQ "DBM-016" "SQL Server version / ProductUpdateLevel / ProductUpdateReference" "$verNum ($build) / $(Run-Q "SELECT CAST(SERVERPROPERTY('ProductLevel') AS varchar)+' '+ISNULL(CAST(SERVERPROPERTY('ProductUpdateLevel') AS varchar),'-')+' '+ISNULL(CAST(SERVERPROPERTY('ProductUpdateReference') AS varchar),'-')")"
$eosScript = Join-Path (Split-Path $MyInvocation.MyCommand.Path) "eos_checker.py"
if (Test-Path $eosScript) {
    $py = @('py','python','python3') | Where-Object { Get-Command $_ -EA SilentlyContinue } | Select-Object -First 1
    $eosResult = if ($py) { & $py $eosScript "mssql" $verNum 2>$null } else { $null }
    $eosStatus = ($eosResult | Where-Object {$_ -match "^결과:"}) -replace "결과:\s*",""
    $eosDesc   = ($eosResult | Where-Object {$_ -match "^설명:"}) -replace "설명:\s*",""
    if ($eosStatus -eq "취약") { Fail "016" "SQL Server $verNum EoS/보안패치: $eosDesc" }
    elseif ($eosStatus -eq "양호") { MC "016" "SQL Server $verNum ($build) 지원기간 내 - 최신 CU/GDR 적용 여부 확인" }
    else { MC "016" "SQL Server $verNum 보안패치 수동 확인 (최신 CU 적용 여부)" }
} else { MC "016" "보안패치 현황 수동 확인 (SQL Server $verNum 최신 CU 확인)" }

# ── DBM-017: 시스템 테이블 접근 권한 ───────────────────────────
$sysTbl = @(Run-Q 'SET NOCOUNT ON; DECLARE @s nvarchar(max)=N''''; SELECT @s=@s+N''SELECT N''''''+REPLACE(name,'''''''','''''''''''')+N'':''''+o.name COLLATE DATABASE_DEFAULT+N'''':''''+d.name COLLATE DATABASE_DEFAULT+N'''':''''+p.permission_name COLLATE DATABASE_DEFAULT FROM ''+QUOTENAME(name)+N''.sys.database_permissions p JOIN ''+QUOTENAME(name)+N''.sys.all_objects o ON o.object_id=p.major_id AND p.class=1 JOIN ''+QUOTENAME(name)+N''.sys.database_principals d ON d.principal_id=p.grantee_principal_id WHERE (o.schema_id=4 OR o.type=''''S'''') AND p.state IN (''''G'''',''''W'''') AND p.grantee_principal_id<>0 AND d.is_fixed_role=0 AND d.name NOT IN (''''dbo'''',''''sys'''',''''INFORMATION_SCHEMA'''',''''guest'''') AND d.name NOT LIKE ''''##%'''' UNION ALL '' FROM sys.databases WHERE state_desc=''ONLINE'' AND HAS_DBACCESS(name)=1; IF LEN(@s)>0 BEGIN SET @s=LEFT(@s,LEN(@s)-10); EXEC(@s); END'); $e17 = $script:QErr
EvdQ "DBM-017" "sys 스키마·시스템 테이블 권한 (전 DB db:object:grantee:permission, 고정 역할·dbo·guest·## 제외)" ($sysTbl -join "`n")
if ($e17) { MC "017" "시스템 테이블 권한 조회 실패(권한) - 수동 확인" }
elseif ($sysTbl.Count -gt 0) { MC "017" "시스템 테이블/뷰 접근 권한 $($sysTbl.Count)건: $(($sysTbl | Select-Object -First 5) -join ', ') - 적정성 수동 확인" }
else { Pass "017" "일반 사용자의 시스템 테이블 직접 접근 권한 없음" }

# ── DBM-019: 이전 비밀번호 재사용 ──────────────────────────────
# 평가기준: 1) 계정별 Windows password policy(CHECK_POLICY) 적용 2) Enforce password history(PasswordHistorySize) 0 이면 취약
$hist19 = Get-SecPol "PasswordHistorySize"
EvdQ "DBM-019" "PasswordHistorySize / CHECK_POLICY=OFF 활성 SQL 로그인" "$hist19 / $($noPolList -join ', ')"
if ($null -eq $hist19) { MC "019" "Enforce password history 확인 실패(관리자 권한 필요) - 수동 확인" }
elseif ([int]$hist19 -eq 0) { Fail "019" "Enforce password history=0 (이전 비밀번호 재사용 가능)" }
elseif ($noPolList.Count -gt 0) { Fail "019" "PasswordHistorySize=$hist19 이나 CHECK_POLICY=OFF 로그인 $($noPolList.Count)개(정책 미적용): $(($noPolList | Select-Object -First 5) -join ', ') - 서비스 운영 계정은 평가 제외 가능" }
else { Pass "019" "Enforce password history=$hist19, 활성 SQL 로그인 모두 CHECK_POLICY 적용 (도메인 GPO 적용 서버는 gpresult 확인)" }

# ── DBM-020: 사용자별 계정 분리 ─────────────────────────────────
EvdQ "DBM-020" "로그인 목록 (DBM-003 동일)" ($logins -join "`n")
MC "020" "공용 계정(shared account) 사용 여부 수동 확인 (로그인 $($logins.Count)개)"

# ── DBM-021: 불필요한 ODBC/OLE-DB 데이터 소스 ─────────────────
# 평가기준: ODBC 데이터 원본 관리자 User/System DSN 중 불필요한 데이터 소스 (Linked Server 는 참고 증적)
$linkedSrv = Run-Q "SELECT name+' ('+provider+')' FROM sys.servers WHERE is_linked=1"
EvdQ "DBM-021" "참고: 연결 서버(Linked Server)" ($linkedSrv -join "`n")
$dsn = @()
foreach ($k in @('HKLM:\SOFTWARE\ODBC\ODBC.INI\ODBC Data Sources','HKLM:\SOFTWARE\WOW6432Node\ODBC\ODBC.INI\ODBC Data Sources','HKCU:\SOFTWARE\ODBC\ODBC.INI\ODBC Data Sources')) {
    $p = Get-ItemProperty $k -EA SilentlyContinue
    if ($p) { $p.PSObject.Properties | Where-Object { @('PSPath','PSParentPath','PSChildName','PSDrive','PSProvider') -notcontains $_.Name } | ForEach-Object { $dsn += "$($_.Name)[$($_.Value)]" } }
}
EvdQ "DBM-021" "ODBC DSN (System/User, 32/64bit)" ($dsn -join "`n")
if ($dsn.Count -gt 0) { MC "021" "ODBC 데이터 소스 $($dsn.Count)개: $(($dsn | Select-Object -First 6) -join ', ') - 업무상 불필요 항목 확인 (존재 시 취약)" }
else { Pass "021" "등록된 ODBC 데이터 소스(DSN) 없음" }

# ── DBM-022: 설정 파일 및 중요 파일 접근 권한 ──────────────────
# 평가기준: *.mdf·*.ndf 등 주요 파일에 관리자·SYSTEM·소유자·SQL 서비스 계정 외 읽기/쓰기 권한 부여 시 취약
$svc22 = (Get-CimInstance Win32_Service -Filter "Name='MSSQLSERVER' OR Name LIKE 'MSSQL$%'" -EA SilentlyContinue | Select-Object -First 1).StartName
$files22 = @(Run-Q "SELECT RTRIM(physical_name) FROM sys.master_files" | ForEach-Object { "$_".Trim() }) + @("$(Run-Q "SELECT CAST(SERVERPROPERTY('ErrorLogFileName') AS nvarchar(260))" | Select-Object -First 1)".Trim()) | Where-Object { $_ }
$okId = '^(BUILTIN\\Administrators|NT AUTHORITY\\SYSTEM|CREATOR OWNER|OWNER RIGHTS|NT SERVICE\\MSSQL.*|NT SERVICE\\SQLAgent.*|NT SERVICE\\SQLSERVERAGENT' + $(if ($svc22) { '|' + [regex]::Escape($svc22) }) + $(if ($env:MSSQL_ADMIN_GROUPS) { '|' + $env:MSSQL_ADMIN_GROUPS }) + ')$'
$bad22 = @(); $seen22 = 0
foreach ($f in $files22) {
    if (-not (Test-Path -LiteralPath $f)) { continue }; $seen22++
    $acl = Get-Acl -LiteralPath $f -EA SilentlyContinue; if (-not $acl) { continue }
    $bad22 += @($acl.Access | Where-Object { "$($_.AccessControlType)" -eq 'Allow' -and "$($_.IdentityReference)" -notmatch $okId -and "$($_.FileSystemRights)" -match 'Read|Write|Modify|FullControl' } | ForEach-Object { "$f : $($_.IdentityReference) ($($_.FileSystemRights))" })
}
EvdQ "DBM-022" "sys.master_files + ErrorLog ACL (관리자·SYSTEM·서비스 계정($svc22) 외 허용 ACE)" ((@($files22) + '---' + @($bad22)) -join "`n")
if ($files22.Count -eq 0) { MC "022" "DB 파일 경로 조회 실패 - 수동 확인" }
elseif ($seen22 -eq 0) { MC "022" "DB 파일 경로 접근 불가(원격 서버 점검 등) - 해당 서버에서 icacls 확인" }
elseif ($bad22.Count -gt 0) { Fail "022" "관리자 외 계정 읽기/쓰기 허용: $(($bad22 | Select-Object -First 3) -join '; ')" }
else { Pass "022" "DB·로그 파일 ${seen22}개 관리자·서비스 계정 외 권한 없음" }

# ── DBM-024: WITH GRANT OPTION ──────────────────────────────────
$grantOpt = @(Run-Q 'SET NOCOUNT ON; DECLARE @s nvarchar(max)=N''''; SELECT @s=@s+N''SELECT N''''''+REPLACE(name,'''''''','''''''''''')+N'':''''+dp.name COLLATE DATABASE_DEFAULT+N'''':''''+p.class_desc COLLATE DATABASE_DEFAULT+N'''':''''+ISNULL(OBJECT_NAME(p.major_id,''+CAST(database_id AS nvarchar(10))+N''),N''''-'''') COLLATE DATABASE_DEFAULT+N'''':''''+p.permission_name COLLATE DATABASE_DEFAULT FROM ''+QUOTENAME(name)+N''.sys.database_permissions p JOIN ''+QUOTENAME(name)+N''.sys.database_principals dp ON dp.principal_id=p.grantee_principal_id WHERE p.state=''''W'''' UNION ALL '' FROM sys.databases WHERE state_desc=''ONLINE'' AND HAS_DBACCESS(name)=1; IF LEN(@s)>0 BEGIN SET @s=LEFT(@s,LEN(@s)-10); EXEC(@s); END'); $e24 = $script:QErr
EvdQ "DBM-024" "WITH GRANT OPTION(state=W) 권한 (전 DB db:grantee:class:object:permission)" ($grantOpt -join "`n")
if ($e24) { MC "024" "WITH GRANT OPTION 조회 실패(권한) - 수동 확인" }
elseif ($grantOpt.Count -gt 0) { MC "024" "WITH GRANT OPTION $($grantOpt.Count)건: $(($grantOpt | Select-Object -First 5) -join ', ') - 업무상 필요 여부 확인(불필요 시 취약)" }
else { Pass "024" "WITH GRANT OPTION 설정 권한 없음" }

# ── DBM-025: EoS ────────────────────────────────────────────────
# DBM-016에서 이미 처리
EvdQ "DBM-025" "@@VERSION / Edition" "$ver / $(Run-Q "SELECT CAST(SERVERPROPERTY('Edition') AS varchar(100))")"
MC "025" "SQL Server $verNum EoS 여부 - DBM-016 항목 참조"

# ── DBM-028: 불필요한 DB Object 제거 ────────────────────────────
# xp_cmdshell, Ole Automation 등
$xp = Run-Q "SELECT value_in_use FROM sys.configurations WHERE name='xp_cmdshell'"
$ole = Run-Q "SELECT value_in_use FROM sys.configurations WHERE name='Ole Automation Procedures'"
EvdQ "DBM-028" "xp_cmdshell & Ole Automation" ("xp_cmdshell=$($xp -join '')`nOle Automation=$($ole -join '')")
$xpVal  = "$($xp  | Select-Object -First 1)".Trim()
$oleVal = "$($ole | Select-Object -First 1)".Trim()
$issues28 = @()
if ($xpVal -eq '1') { $issues28 += "xp_cmdshell(활성)" }
if ($oleVal -eq '1') { $issues28 += "Ole Automation(활성)" }
# 평가기준: 인가되지 않은 Object/Owner 존재 여부(인터뷰) — xp_cmdshell 은 DBM-035 항목
$objs = Run-Q "SELECT TOP 20 s.name+'.'+o.name+' ('+o.type_desc COLLATE DATABASE_DEFAULT+')' FROM sys.objects o JOIN sys.schemas s ON o.schema_id=s.schema_id WHERE o.is_ms_shipped=0 ORDER BY o.create_date DESC"
EvdQ "DBM-028" "사용자 생성 Object 목록(최근 20)" ($objs -join "`n")
MC "028" "사용자 생성 Object/Owner 인가 여부 인터뷰 확인 (참고: xp_cmdshell/Ole Automation 은 DBM-035 에서 판정)"

# ── DBM-029: 자원 사용 제한 ─────────────────────────────────────
EvdQ "DBM-029" "sys.configurations 자원 설정 / Resource Governor" "$((Run-Q "SELECT name+'='+CAST(value_in_use AS varchar) FROM sys.configurations WHERE name IN ('max server memory (MB)','max degree of parallelism','user connections','query governor cost limit')") -join ', ') / RG enabled=$(Run-Q "SELECT CAST(is_enabled AS varchar) FROM sys.resource_governor_configuration")"
MC "029" "최대 서버 메모리, CPU 제한 등 자원 사용 제한 수동 확인 (sp_configure 참조)"

# ── DBM-031: SA 계정 보안설정 ───────────────────────────────────
$sa = Run-Q "SELECT is_disabled,name FROM sys.server_principals WHERE sid=0x01"
EvdQ "DBM-031" "SA account status" ($sa -join "`n")
$saLine = $sa | Select-Object -First 1
$saPol = (Run-Q "SELECT CAST(is_policy_checked AS varchar) FROM sys.sql_logins WHERE sid=0x01" | Select-Object -First 1)
EvdQ "DBM-031" "sa is_policy_checked" "$saPol"
# 평가기준: sa 비활성 → 양호 / 활성 시 Windows password policy 적용 여부로 판정
if ($saLine -match "^1") { Pass "031" "SA 계정 비활성화됨 (is_disabled=1)" }
elseif ($saLine -match "^0" -and "$saPol".Trim() -eq "1") { Pass "031" "SA 계정 활성, 비밀번호 정책 적용됨 (is_policy_checked=1) - 복잡도 정책은 증적 확인" }
elseif ($saLine -match "^0") { Fail "031" "SA 계정 활성, 비밀번호 정책 미적용 (is_policy_checked=$saPol)" }
else { MC "031" "SA 계정 상태 수동 확인" }

# ── DBM-034: DBMS 서비스 구동 권한 ─────────────────────────────
Evd "DBM-034" "Get-CimInstance Win32_Service -Filter `"Name LIKE 'MSSQL%'`" -EA SilentlyContinue | Select-Object Name,StartName,State | Format-Table"
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
EvdQ "DBM-035" "xp_cmdshell value_in_use" ($xp2 -join "`n")
$xpV2 = "$($xp2 | Select-Object -First 1)".Trim()
if ($xpV2 -notmatch '^[01]$') { MC "035" "xp_cmdshell 설정 조회 실패 - 수동 확인" }
elseif ($xpV2 -eq '0') { Pass "035" "xp_cmdshell 비활성화됨 (=0)" }
else { Fail "035" "xp_cmdshell 활성화됨 (=1) - 보안 위험" }

# ── DBM-036: Registry Procedure 접근 권한 ──────────────────────
# 평가기준: 제한 목록 7종이 DBA 외 guest/public 에 부여되면 취약 (xp_reg* 는 sys.objects 가 아닌 sys.all_objects 에만 존재)
$n36 = Q-Int "SELECT COUNT(*) FROM master.sys.all_objects WHERE type='X' AND name LIKE 'xp_reg%'"
$regPub = @(Run-Q 'SET NOCOUNT ON; SELECT o.name+'':''+dp.name+'':''+p.state_desc COLLATE DATABASE_DEFAULT FROM master.sys.database_permissions p JOIN master.sys.all_objects o ON o.object_id=p.major_id JOIN master.sys.database_principals dp ON dp.principal_id=p.grantee_principal_id WHERE p.class=1 AND p.type=''EX'' AND p.state IN (''G'',''W'') AND dp.name IN (''public'',''guest'') AND o.name IN (''xp_regaddmultistring'',''xp_regdeletekey'',''xp_regdeletevalue'',''xp_regenumvalues'',''xp_regread'',''xp_regremovemultistring'',''xp_regwrite'')')
EvdQ "DBM-036" "레지스트리 확장 프로시저 수 / public·guest 부여" "$n36 / $($regPub -join ', ')"
if ($null -eq $n36) { MC "036" "레지스트리 확장 프로시저 조회 실패 - 수동 확인" }
elseif ($regPub.Count -gt 0) { Fail "036" "레지스트리 확장 프로시저 public/guest 부여: $($regPub -join ', ')" }
else { Pass "036" "제한 대상 레지스트리 확장 프로시저 public/guest 부여 없음" }

# N-A 항목 (타 DBMS 전용)
foreach ($code in @("012","014")) {
    NA $code "MSSQL 해당 없음 (Oracle 전용 항목)"
}
NA "026" "MSSQL 해당 없음 (Unix umask 개념 미적용)"
NA "030" "MSSQL 해당 없음 (Oracle/Tibero AUD$ 전용 항목)"
NA "032" "MSSQL 해당 없음 (PostgreSQL SSL 전용 항목)"
NA "033" "MSSQL 해당 없음 (MySQL 복제 비밀번호 전용 항목)"


# ════════════════════════════════════════════════════════════════
# 주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드(2026) — DBMS D-01 ~ D-26 (MSSQL)
#   가이드 점검 대상에 MSSQL 이 없는 항목은 N-A (D-05·07·09·12·14·15·17~22), D-10·13 은 Windows OS 대상
# ════════════════════════════════════════════════════════════════
if ($script:KMODE -ne 'ef') {
function RunQA([string]$q) { Run-Q $q | Where-Object { $_ } }   # 결과 줄만 (실패 시 0건, $script:QErr=true)
$kna = "가이드 점검 대상 제품 아님 (MSSQL)"
foreach ($c in 'D-05','D-07','D-09','D-12','D-14','D-15','D-17','D-18','D-19','D-20','D-21','D-22') { KPut $c 'N-A' $kna }
$lg = @(RunQA "SELECT name COLLATE DATABASE_DEFAULT + '|' + type COLLATE DATABASE_DEFAULT + '|' + CAST(is_disabled AS varchar(1)) FROM sys.server_principals WHERE type IN ('S','U','G') AND name NOT LIKE '##%' AND name NOT LIKE 'NT SERVICE\%' AND name NOT LIKE 'NT AUTHORITY\%'")
$sl = @(RunQA "SELECT name COLLATE DATABASE_DEFAULT + '|' + CAST(is_disabled AS varchar(1)) + '|' + CAST(is_policy_checked AS varchar(1)) + '|' + CAST(is_expiration_checked AS varchar(1)) + '|' + CONVERT(varchar(6), password_hash, 1) + '|' + CAST(principal_id AS varchar(10)) FROM sys.sql_logins WHERE name NOT LIKE '##%'")
$lgErr = $script:QErr
EvdQ "D-01" "로그인 (이름|유형 S=SQL U=Windows G=그룹|비활성)" ($lg -join "`n")
EvdQ "D-01" "SQL 로그인 (이름|비활성|암호정책|만료|해시접두|principal_id)" ($sl -join "`n")
$sa = $sl | Where-Object { ($_ -split '\|')[5] -eq '1' } | Select-Object -First 1
$saName = if ($sa) { ($sa -split '\|')[0] } else { 'sa' }; $saOff = $sa -and ($sa -split '\|')[1] -eq '1'

# D-01 기본 계정(sa) 초기 비밀번호 변경 또는 잠금
$wk = @(RunQA "SELECT name FROM sys.sql_logins WHERE principal_id = 1 AND (PWDCOMPARE('', password_hash) = 1 OR PWDCOMPARE(name, password_hash) = 1 OR PWDCOMPARE('password', password_hash) = 1 OR PWDCOMPARE('sa', password_hash) = 1)")
EvdQ "D-01" "sa 빈·기본 비밀번호 일치 여부 (PWDCOMPARE, 값 비공개)" "$(if ($wk.Count) { '일치' } else { '불일치' })"
if (-not $sa) { KPut 'D-01' '수동확인' '기본 관리자(sa) SQL 로그인 조회 실패 - 비밀번호 변경·비활성 확인' }
elseif ($saOff) { KPut 'D-01' '양호' "기본 관리자 계정($saName) 비활성(잠금)" }
elseif ($wk.Count) { KPut 'D-01' '취약' "기본 관리자 계정($saName) 비밀번호가 빈 값 또는 기본값(계정명·password)과 일치" }
else { KPut 'D-01' '양호' "기본 관리자 계정($saName) 비밀번호 변경됨 (빈 값·기본값 불일치)$(if ($saName -eq 'sa') { ' - 이름 변경 권고' })" }

# D-02 불필요 계정
$act = @($lg | Where-Object { ($_ -split '\|')[2] -eq '0' } | ForEach-Object { ($_ -split '\|')[0] })
$tst = @($act | Where-Object { $_ -match '^(test|guest|demo|temp|tmp|sample|user\d*)' })
if ($lgErr) { KPut 'D-02' '수동확인' '로그인 목록 조회 실패 - sys.server_principals 확인' } elseif ($tst.Count) { KPut 'D-02' '취약' "테스트성 로그인 활성: $($tst -join ', ')" } else { KPut 'D-02' '수동확인' "활성 로그인: $($act -join ', ') - 인가되지 않은 계정·퇴직자·미사용 계정 여부 확인 (없으면 양호)" }

# D-03 비밀번호 사용 기간 및 복잡도 (SQL 로그인 CHECK_POLICY·CHECK_EXPIRATION + OS 암호 정책)
$np = @($sl | Where-Object { $p = $_ -split '\|'; $p[1] -eq '0' -and ($p[2] -ne '1' -or $p[3] -ne '1') } | ForEach-Object { $p = $_ -split '\|'; "$($p[0])(정책=$($p[2]),만료=$($p[3]))" })
$mx = Get-SecPol 'MaximumPasswordAge'; $cx = Get-SecPol 'PasswordComplexity'
EvdQ "D-03" "OS 암호 정책 최대 사용 기간 / 복잡성 (SQL 로그인 CHECK_POLICY 가 따름)" "$mx / $cx"
$b3 = @(); if ($np.Count) { $b3 += "암호 정책·만료 강제 미적용 SQL 로그인: $($np -join ', ')" }
if ($null -ne $mx -and ([int]$mx -le 0 -or [int]$mx -gt 90)) { $b3 += "OS 최대 암호 사용 기간 $mx(90일 이하 필요)" }
if ($null -ne $cx -and "$cx" -ne '1') { $b3 += 'OS 암호 복잡성 사용 안 함' }
if ($b3.Count) { KPut 'D-03' '취약' "비밀번호 정책 미흡: $($b3 -join ' / ')" }
elseif ($null -eq $mx) { KPut 'D-03' '수동확인' "SQL 로그인 암호 정책·만료 강제 적용, OS 암호 정책(secedit) 조회 불가 - 관리자 권한으로 최대 사용 기간·복잡성 확인" }
else { KPut 'D-03' '양호' "SQL 로그인 암호 정책·만료 강제 적용, OS 최대 사용 기간 ${mx}일·복잡성 사용" }

# D-04 관리자 권한(sysadmin)은 필요한 계정에만
$sy = @(RunQA "SELECT m.name FROM sys.server_role_members rm JOIN sys.server_principals r ON r.principal_id = rm.role_principal_id JOIN sys.server_principals m ON m.principal_id = rm.member_principal_id WHERE r.name = 'sysadmin'")
$syErr = $script:QErr
EvdQ "D-04" "sysadmin 구성원" ($sy -join "`n")
$syx = @($sy | Where-Object { $_ -ne $saName -and $_ -notmatch '^NT (SERVICE|AUTHORITY)\\' })
if ($syErr) { KPut 'D-04' '수동확인' 'sysadmin 구성원 조회 실패' } elseif ($syx.Count) { KPut 'D-04' '수동확인' "sa·서비스 계정 외 sysadmin: $($syx -join ', ') - 관리자 권한 필요성 확인 (불필요 시 취약)" } else { KPut 'D-04' '양호' "sysadmin 이 sa·서비스 계정에만 부여: $($sy -join ', ')" }

# D-06 사용자별 계정 사용
KPut 'D-06' '수동확인' "활성 로그인: $(if ($lgErr) { '조회 실패' } else { $act -join ', ' }) - 사용자·응용프로그램별 개별 계정 사용 여부(공용 계정 사용 시 취약) 확인"

# D-08 안전한 암호화 알고리즘 (SQL 2012 이상 SHA-512 = 해시 0x0200, 0x0100 = SHA-1)
$old = @($sl | Where-Object { ($_ -split '\|')[4] -eq '0x0100' } | ForEach-Object { ($_ -split '\|')[0] })
if (-not $sl.Count) { KPut 'D-08' '양호' 'SQL 로그인 없음 (Windows 인증만 사용)' } elseif ($old.Count) { KPut 'D-08' '취약' "SHA-1(0x0100) 해시 비밀번호 로그인: $($old -join ', ') - 비밀번호 재설정 필요" } else { KPut 'D-08' '양호' "SQL 로그인 비밀번호 SHA-512(0x0200) 해시 ($($sl.Count)개)" }

# D-10 원격 접속 제한 (Windows 방화벽에서 DB 포트 접근 IP 지정)
$fr = @(Get-NetFirewallRule -Direction Inbound -Enabled True -Action Allow -EA SilentlyContinue | Where-Object { $pf = $_ | Get-NetFirewallPortFilter -EA SilentlyContinue; $af = $_ | Get-NetFirewallApplicationFilter -EA SilentlyContinue; "$($pf.LocalPort)" -match '(^|,)1433(,|$)' -or "$($af.Program)" -match 'sqlservr' })
$frAny = @($fr | Where-Object { @(($_ | Get-NetFirewallAddressFilter -EA SilentlyContinue).RemoteAddress) -contains 'Any' } | ForEach-Object { $_.DisplayName })
EvdQ "D-10" "SQL Server 인바운드 허용 규칙 (규칙 / 원격 주소)" (($fr | ForEach-Object { "$($_.DisplayName) / $(@(($_ | Get-NetFirewallAddressFilter).RemoteAddress) -join ',')" }) -join "`n")
if ($frAny.Count) { KPut 'D-10' '취약' "모든 IP 에서 DB 포트 접속 허용 방화벽 규칙: $($frAny -join ', ')" }
elseif ($fr.Count) { KPut 'D-10' '양호' "DB 포트 방화벽 규칙이 지정 IP 로 제한 ($($fr.Count)개)" }
else { KPut 'D-10' '수동확인' "SQL Server 인바운드 방화벽 규칙 미발견 - 네트워크 장비·보안그룹 등에서 지정 IP 접근 제한 여부 확인" }

# D-11 시스템 테이블 접근 제한 (PUBLIC·GUEST 권한 - 설치 기본 부여분 제외)
$dflt = "'trace_xe_action_map','trace_xe_event_map','spt_fallback_db','spt_fallback_dev','spt_fallback_usg','spt_monitor'"
$pg = @(RunQA "SELECT dp.name COLLATE DATABASE_DEFAULT + ':' + o.name COLLATE DATABASE_DEFAULT + ':' + p.permission_name COLLATE DATABASE_DEFAULT FROM master.sys.database_permissions p JOIN master.sys.all_objects o ON o.object_id = p.major_id JOIN master.sys.database_principals dp ON dp.principal_id = p.grantee_principal_id WHERE p.class = 1 AND dp.name IN ('public','guest') AND p.state IN ('G','W') AND o.type IN ('S','U') AND o.name NOT IN ($dflt)")
$pgErr = $script:QErr
EvdQ "D-11" "master 시스템 테이블 PUBLIC·GUEST 권한 (설치 기본 6개 제외)" ($pg -join "`n")
if ($pgErr) { KPut 'D-11' '수동확인' '시스템 테이블 권한 조회 실패 - PUBLIC·GUEST 권한 확인' } elseif ($pg.Count) { KPut 'D-11' '취약' "PUBLIC·GUEST 에 시스템 테이블 권한 부여: $($pg -join ', ')" } else { KPut 'D-11' '양호' 'PUBLIC·GUEST 에 추가 부여된 시스템 테이블 권한 없음 (설치 기본 권한 제외)' }

# D-13 불필요한 ODBC/OLE-DB 데이터 소스 (Windows OS)
$dsn = @(); foreach ($k in 'HKLM:\SOFTWARE\ODBC\ODBC.INI\ODBC Data Sources','HKLM:\SOFTWARE\WOW6432Node\ODBC\ODBC.INI\ODBC Data Sources') { if (Test-Path $k) { $dsn += @((Get-Item $k).Property) } }
EvdQ "D-13" "시스템 DSN" ($dsn -join "`n")
if ($dsn.Count) { KPut 'D-13' '수동확인' "시스템 DSN $($dsn.Count)개: $($dsn -join ', ') - 사용하지 않는 데이터 소스 제거 여부 확인" } else { KPut 'D-13' '양호' '시스템 DSN 없음' }

# D-16 Windows 인증 모드 사용 (혼합 모드면 sa 비활성 또는 강력한 암호 정책)
$iso = "$(Run-Q "SELECT CAST(SERVERPROPERTY('IsIntegratedSecurityOnly') AS varchar(1))" | Select-Object -First 1)".Trim()
$saPol = $sa -and ($sa -split '\|')[2] -eq '1'
EvdQ "D-16" "IsIntegratedSecurityOnly / sa 비활성 / sa 암호 정책" "$iso / $saOff / $saPol"
if ($iso -eq '1') { KPut 'D-16' '양호' 'Windows 인증 모드 사용' }
elseif ($saOff) { KPut 'D-16' '양호' "혼합 인증 모드, sa 비활성" }
elseif ($saPol) { KPut 'D-16' '양호' "혼합 인증 모드, sa 활성 - 암호 정책(CHECK_POLICY) 적용" }
else { KPut 'D-16' '취약' "혼합 인증 모드 사용, sa 활성이며 암호 정책(CHECK_POLICY) 미적용" }

# D-23 xp_cmdshell 사용 제한 (비활성, 또는 활성 시 public 실행 권한 없음 + 서비스 계정 sysadmin 아님)
$xp = "$(Run-Q "SELECT CAST(value_in_use AS varchar(1)) FROM sys.configurations WHERE name = 'xp_cmdshell'" | Select-Object -First 1)".Trim()
$xpPub = @(RunQA "SELECT dp.name FROM master.sys.database_permissions p JOIN master.sys.all_objects o ON o.object_id = p.major_id JOIN master.sys.database_principals dp ON dp.principal_id = p.grantee_principal_id WHERE o.name = 'xp_cmdshell' AND p.state IN ('G','W') AND dp.name IN ('public','guest')")
EvdQ "D-23" "xp_cmdshell value_in_use / public·guest 실행 권한" "$xp / $($xpPub -join ',')"
if ($xp -ne '1') { KPut 'D-23' '양호' 'xp_cmdshell 비활성' }
elseif ($xpPub.Count) { KPut 'D-23' '취약' "xp_cmdshell 활성 + public·guest 실행 권한: $($xpPub -join ', ')" }
else { KPut 'D-23' '수동확인' "xp_cmdshell 활성 (public 실행 권한 없음) - 응용프로그램 연동 서비스 계정의 sysadmin 권한 여부 확인 (sysadmin: $($sy -join ', '))" }

# D-24 Registry Procedure 권한 제한 (7종 확장 프로시저 public·guest 부여)
$rp = @(RunQA "SELECT o.name COLLATE DATABASE_DEFAULT + ':' + dp.name COLLATE DATABASE_DEFAULT FROM master.sys.database_permissions p JOIN master.sys.all_objects o ON o.object_id = p.major_id JOIN master.sys.database_principals dp ON dp.principal_id = p.grantee_principal_id WHERE p.class = 1 AND p.type = 'EX' AND p.state IN ('G','W') AND dp.name IN ('public','guest') AND o.name IN ('xp_regaddmultistring','xp_regdeletekey','xp_regdeletevalue','xp_regenumvalues','xp_regread','xp_regremovemultistring','xp_regwrite')")
EvdQ "D-24" "레지스트리 확장 프로시저 public·guest 부여" ($rp -join "`n")
if ($script:QErr) { KPut 'D-24' '수동확인' '레지스트리 확장 프로시저 권한 조회 실패' } elseif ($rp.Count) { KPut 'D-24' '취약' "DBA 외 public·guest 에 부여: $($rp -join ', ')" } else { KPut 'D-24' '양호' '제한 대상 레지스트리 확장 프로시저 public·guest 부여 없음' }

# D-25 주기적 보안 패치 (지원 종료 버전 = 취약)
$pv = "$(Run-Q "SELECT CAST(SERVERPROPERTY('ProductVersion') AS varchar(30)) COLLATE DATABASE_DEFAULT + ' ' + ISNULL(CAST(SERVERPROPERTY('ProductUpdateLevel') AS varchar(20)), CAST(SERVERPROPERTY('ProductLevel') AS varchar(20)))" | Select-Object -First 1)".Trim()
$eosDb = @{ '2012'='2022-07-12'; '2014'='2024-07-09'; '2016'='2026-07-14'; '2017'='2027-10-12'; '2019'='2030-01-08'; '2022'='2033-01-11' }
EvdQ "D-25" "@@VERSION / ProductVersion 업데이트 수준" "$ver / $pv"
if ($eosDb.ContainsKey($verNum) -and (Get-Date) -gt [datetime]$eosDb[$verNum]) { KPut 'D-25' '취약' "SQL Server $verNum 연장 지원 종료($($eosDb[$verNum])) - 보안 패치 미제공 ($pv)" }
else { KPut 'D-25' '수동확인' "SQL Server $verNum $pv$(if ($eosDb.ContainsKey($verNum)) { " (연장 지원 ~$($eosDb[$verNum]))" }) - 최신 CU·보안 업데이트 적용 여부 확인" }

# D-26 감사 기록 (로그인 감사 '실패한 로그인과 성공한 로그인 모두' = AuditLevel 3, 또는 서버 감사 사용)
$al = "$(Run-Q "DECLARE @v int; EXEC master.dbo.xp_instance_regread N'HKEY_LOCAL_MACHINE', N'Software\Microsoft\MSSQLServer\MSSQLServer', N'AuditLevel', @v OUTPUT; SELECT CAST(@v AS varchar(3))" | Select-Object -First 1)".Trim()
$sau = @(RunQA "SELECT name FROM sys.server_audits WHERE is_state_enabled = 1")
EvdQ "D-26" "로그인 감사 AuditLevel(0 없음/1 성공/2 실패/3 모두) / 활성 서버 감사" "$al / $($sau -join ', ')"
if ($al -eq '3' -or $sau.Count) { KPut 'D-26' '양호' "감사 설정: $(if ($al -eq '3') { '로그인 감사 성공·실패 모두 ' })$(if ($sau.Count) { "서버 감사 $($sau -join ', ')" }) - 감사 기록 정책(보관·백업) 수립 여부는 인터뷰" }
else { KPut 'D-26' '취약' "로그인 감사 '$(switch ($al) { '0' {'없음'} '1' {'성공한 로그인만'} '2' {'실패한 로그인만'} default {"확인 불가($al)"} })', 활성 서버 감사 없음 - 가이드: 실패·성공 모두 감사" }
}

Remove-Item Env:\SQLCMDPASSWORD -EA SilentlyContinue
Remove-Item $seceditFile -Force -EA SilentlyContinue
$total = $script:cntPass + $script:cntFail + $script:cntMC + $script:cntNA
Write-Output "# ================================================================"
Write-Output "# 점검 요약"
Write-Output "#   총 점검 항목: $total"
Write-Output "#   양호:         $($script:cntPass)  ($([math]::Round($script:cntPass/$total*100,1))%)"
Write-Output "#   취약:         $($script:cntFail)  ($([math]::Round($script:cntFail/$total*100,1))%)"
Write-Output "#   수동확인:     $($script:cntMC)"
Write-Output "#   N-A:          $($script:cntNA)"
Write-Output "# ================================================================"
Write-Output "# 점검 완료: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Output "# 증적 파일: $($script:EVD)"
