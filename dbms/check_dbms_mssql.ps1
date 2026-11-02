# ================================================================
# DBMS(MSSQL) 보안 취약점 자동 점검 스크립트 v5.0
# ================================================================
#
# [용도]
#   전자금융기반시설·주요정보통신기반시설 MSSQL 데이터베이스 보안 점검. -Mode ef|mi|all (주요정보 = 2026 상세가이드 D-01~26)
#   기준: 전자금융기반시설 보안 취약점 평가기준 제2026-1호 [데이터베이스]
#   Oracle/MySQL/PostgreSQL/Tibero는 check_dbms.sh 사용.
#
# [대상 DBMS]
#   SQL Server 2014 / 2016 / 2017 / 2019 / 2022 (설치형), AWS RDS for SQL Server, Azure SQL (관리형)
#
# [사전 조건]
#   - 설치형 로컬 점검: 관리자 권한 PowerShell 필요
#   - MSSQL sysadmin 이상 권한 계정 (SQL 인증 또는 Windows 인증)
#   - 실행 정책 변경: Set-ExecutionPolicy RemoteSigned -Scope Process -Force
#   - PowerShell 2.0(Windows Server 2008 R2) ~ 최신 지원
#
# [접속 정보 환경변수]
#   $env:MSSQL_SERVER  = "localhost"   (기본: localhost. 원격/관리형은 엔드포인트, 예: mydb.xxxx.ap-northeast-2.rds.amazonaws.com)
#   $env:MSSQL_PORT    = "1433"        (선택. MSSQL_SERVER 에 ,포트 또는 \인스턴스 가 없을 때 사용)
#   $env:MSSQL_USER    = "sa"          (기본: sa)
#   $env:MSSQL_PASS    = "<비밀번호>"  (미지정 시 Windows 인증 시도 → 대화형이면 숨김 입력. 비밀번호는 sqlcmd 인자가 아니라 SQLCMDPASSWORD 환경변수로만 전달)
#   $env:MSSQL_WINAUTH = "1"           (Windows 인증 시 — 설정하면 USER/PASS 무시)
#   $env:DBMS_ENV      = "rds|azure"   (관리형 지정. 미지정이어도 엔드포인트가 *.rds.amazonaws.com / *.cluster-* / *.database.windows.net 이면 자동 탐지. 설치형은 onprem)
#   $env:DBMS_REMOTE   = "1|0"         (접속 대상이 실행 호스트와 다른 서버(1) / 로컬(0) 강제 지정 — 터널 접속 등)
#
# [관리형(RDS·Azure) / 원격 실행]
#   관리형: 운영체제(파일·서비스 계정·방화벽·OS 암호 정책) 항목은 N-A(관리형 DB - 운영체제 접근 불가, 파라미터 그룹·콘솔 설정으로 확인),
#           rdsa·rdsadmin 등 예약 로그인은 계정 점검에서 제외하고 근거에 표시.
#   원격(설치형): 로컬 파일·서비스·방화벽·OS 정책 항목은 실행 호스트 기준으로 판정하지 않고 '점검불가' (대상 서버에서 직접 실행 필요).
#
# [실행 방법]
#   .\check_dbms_mssql.ps1 -Mode all            (결과를 같은 폴더의 <호스트>_mssql_<대상>_dbms.txt 에 UTF-8(BOM) 로 직접 저장)
#   .\check_dbms_mssql.ps1 -Mode mi -OutFile C:\Temp\result.txt
#
# [산출물]
#   1) 표준출력 + 결과 파일 — 파이프 구분자 결과 (결과 파일은 UTF-8 BOM 으로 직접 저장하므로 cmd '>' 리다이렉트에 의한 한글 깨짐 없음)
#      형식: 항목코드|결과|근거설명
#      결과: 양호 / 취약 / 수동확인 / 점검불가 / N-A
#        점검불가 = 쿼리 오류·권한 부족·접속 끊김·cmdlet/명령 없음 등으로 점검 자체를 못 한 경우 (오류 원문은 증적)
#   2) 증적 파일 — <결과 파일 이름>_evidence.txt (…_dbms_evidence.txt)
#      점검 중 실행한 SQL(전문)·열 이름·결과 행 전체·오류 원문·판정 근거가 타임스탬프와 함께 기록됨
#
# ================================================================
param([string]$Mode = "", [string]$OutFile = "")   # ef=전자금융(DBM) / mi=주요정보 2026 상세가이드(D-01~26) / all=둘 다
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
try { [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false) } catch {}   # 한글 근거가 콘솔/리다이렉트에서 깨지지 않게

$MSSQL_SERVER = if ($env:MSSQL_SERVER) { $env:MSSQL_SERVER } else { "localhost" }
$MSSQL_USER   = if ($env:MSSQL_USER)   { $env:MSSQL_USER }   else { "sa" }
$MSSQL_PASS   = $env:MSSQL_PASS
$USE_WIN_AUTH = if ($env:MSSQL_WINAUTH) { $true } else { $false }
$script:SrvArg = $MSSQL_SERVER
if ($env:MSSQL_PORT -and $MSSQL_SERVER -notmatch '[,\\]') { $script:SrvArg = "$MSSQL_SERVER,$($env:MSSQL_PORT)" }

$hn = $env:COMPUTERNAME

# ── 출력: 콘솔 + 버퍼 → 종료 시 UTF-8(BOM) 파일로 저장 ──────────────
$script:OUT = New-Object System.Collections.ArrayList
function Out-Line([string]$s) { [void]$script:OUT.Add($s); [Console]::Out.WriteLine($s) }
function Safe-Name([string]$s) { ($s -replace '[^A-Za-z0-9.\-]','_') -replace '_+','_' -replace '^_|_$','' }

# ── 접속 대상 판별: 로컬/원격, 관리형(RDS·Azure) ────────────────────
function Get-LocalIPs {
    $ips = @()
    try {
        foreach ($n in @(Get-WmiObject Win32_NetworkAdapterConfiguration -Filter "IPEnabled=True")) {
            foreach ($ip in @($n.IPAddress)) { if ("$ip" -match '^\d+\.\d+\.\d+\.\d+$' -and "$ip" -notmatch '^127\.') { $ips += "$ip" } }
        }
    } catch {}
    return @($ips | Select-Object -Unique)
}
$tHost = (("$MSSQL_SERVER" -replace '^(?i)(tcp|np|lpc):','') -split ',')[0]
$tHost = ($tHost -split '\\')[0].Trim()
$tInst = if ("$MSSQL_SERVER" -match '\\([^,\\]+)') { $matches[1] } else { '' }
$tPort = if ("$MSSQL_SERVER" -match ',(\d+)\s*$') { $matches[1] } elseif ($env:MSSQL_PORT) { "$($env:MSSQL_PORT)" } else { '1433' }
function Test-LocalHost([string]$h) {
    $l = "$h".ToLower()
    if (@('', '.', '(local)', 'localhost', '::1', '[::1]') -contains $l -or $l -match '^127\.') { return $true }
    if ($l -eq "$hn".ToLower() -or $l -like ("$hn".ToLower() + '.*')) { return $true }
    if ((Get-LocalIPs) -contains $h) { return $true }
    return $false
}
$script:Remote = $false
if ($env:DBMS_REMOTE -eq '1') { $script:Remote = $true }
elseif ($env:DBMS_REMOTE -eq '0') { $script:Remote = $false }
elseif ($tHost -and -not (Test-LocalHost $tHost)) { $script:Remote = $true }
$script:Managed = ''        # '' = 설치형 / rds / azure
$kind = "$($env:DBMS_ENV)".ToLower()
if (@('rds','aurora','azure') -contains $kind) { $script:Managed = $kind }
elseif (@('onprem','installed','none','local') -contains $kind) { $script:Managed = '' }
else {
    $lh = "$tHost".ToLower()
    if ($lh -match '\.rds\.amazonaws\.com(\.cn)?$' -or $lh -match '\.cluster-') { $script:Managed = 'rds' }
    elseif ($lh -match '\.database\.(windows\.net|chinacloudapi\.cn|usgovcloudapi\.net)$') { $script:Managed = 'azure' }
}
if ($script:Managed) { $script:Remote = $true }
$script:ManagedLabel = if ($script:Managed -eq 'azure') { 'Azure-SQL' } elseif ($script:Managed) { 'RDS-MSSQL' } else { '' }
$script:TargetId = if ($script:Remote -and $tHost) { "${tHost}$(if ($tInst) { '\' + $tInst })" + $(if (-not $tInst -or $MSSQL_SERVER -match ',') { ":$tPort" } else { '' }) } elseif ($script:Remote) { "원격(엔드포인트 미지정)" } else { $hn }
$tFile = if ($script:Remote -and $tHost) { Safe-Name ("${tHost}_$(if ($tInst) { $tInst + '_' })${tPort}") } else { 'local' }
$fbase = "$(Safe-Name $hn)_mssql_${tFile}_dbms"
$script:OUTDIR = Split-Path -Parent $MyInvocation.MyCommand.Definition
if (-not $script:OUTDIR) { $script:OUTDIR = (Get-Location).Path }
if (-not $OutFile) { $OutFile = Join-Path $script:OUTDIR "$fbase.txt" }
$script:OutFile = $OutFile
$evdBase = [System.IO.Path]::Combine([System.IO.Path]::GetDirectoryName($OutFile), ([System.IO.Path]::GetFileNameWithoutExtension($OutFile) + "_evidence.txt"))
$script:EVD = $evdBase

# 증적 파일 (UTF-8 BOM 으로 새로 생성, 이후 BOM 없이 추가) — 쓰기 불가면 TEMP 로 대체
$script:UTF8BOM = New-Object System.Text.UTF8Encoding($true)
$script:UTF8NB  = New-Object System.Text.UTF8Encoding($false)
function Evd-Write([string]$text) { try { [System.IO.File]::AppendAllText($script:EVD, $text + "`n", $script:UTF8NB) } catch {} }
try { [System.IO.File]::WriteAllText($script:EVD, "", $script:UTF8BOM) } catch {
    $script:EVD = Join-Path $env:TEMP ([System.IO.Path]::GetFileName($evdBase))
    try { [System.IO.File]::WriteAllText($script:EVD, "", $script:UTF8BOM) } catch {}
}
$script:EvdHas = @{}      # 증적 블록이 있는 항목코드
$script:Cur = 'DBM-000'   # 현재 점검 항목 (Run-Q 가 증적 블록에 표기)
$script:ItemErr = @()     # 현재 항목에서 발생한 쿼리 오류 → Emit 이 점검불가로 전환
$script:QErr = $false
function Item-Begin([string]$code) { $script:Cur = $code; $script:ItemErr = @() }
function Carry([string]$txt) { if ($txt) { $script:ItemErr += $txt } }

# sqlcmd 탐지 (PATH → Program Files 하위 신/구 버전 경로 중 가장 높은 버전)
$sqlcmd = $null
$cmdInfo = Get-Command sqlcmd -EA SilentlyContinue | Select-Object -First 1
if ($cmdInfo) { $sqlcmd = $cmdInfo.Definition }
if (-not $sqlcmd) {
    $found = @()
    foreach ($root in @($env:ProgramFiles, ${env:ProgramFiles(x86)}) | Where-Object { $_ }) {
        foreach ($pat in @("$root\Microsoft SQL Server\Client SDK\ODBC\*\Tools\Binn\sqlcmd.exe", "$root\Microsoft SQL Server\*\Tools\Binn\sqlcmd.exe", "$root\SqlCmd\sqlcmd.exe", "$root\sqlcmd\sqlcmd.exe")) {
            $found += @(Get-ChildItem -Path $pat -EA SilentlyContinue)
        }
    }
    if ($found.Count -gt 0) {
        $sqlcmd = ($found | Sort-Object { $v = 0; if ($_.FullName -match '\\(\d+)\\Tools\\Binn\\') { $v = [int]$matches[1] }; $v } -Descending | Select-Object -First 1).FullName
    }
}

# 결과/증적 마무리: 버퍼를 UTF-8(BOM) 파일로 저장하고 SQLCMDPASSWORD 제거
function Finish {
    Remove-Item Env:\SQLCMDPASSWORD -EA SilentlyContinue
    if ($script:seceditFile) { Remove-Item $script:seceditFile -Force -EA SilentlyContinue }
    try { [System.IO.File]::WriteAllLines($script:OutFile, [string[]]$script:OUT.ToArray(), $script:UTF8BOM) } catch { [Console]::Error.WriteLine("결과 파일 저장 실패: $($script:OutFile) - $_") }
    exit
}

# ── 실행 호스트 메타데이터 (IP / 실행 계정 / 클라우드) ───────────────
function Get-Http([string]$url,[string[]]$headers,[string]$method) {   # PS2.0 호환(Invoke-RestMethod 미사용), 타임아웃 2초
    try {
        $req = [System.Net.WebRequest]::Create($url); $req.Timeout = 2000; $req.ReadWriteTimeout = 2000
        if ($method) { $req.Method = $method; if ($method -eq 'PUT') { $req.ContentLength = 0 } }
        foreach ($h in @($headers)) { if ($h) { $kv = $h -split ':\s*',2; $req.Headers.Add($kv[0], $kv[1]) } }
        $resp = $req.GetResponse(); $sr = New-Object System.IO.StreamReader($resp.GetResponseStream()); $t = $sr.ReadToEnd(); $sr.Close(); $resp.Close()
        return $t
    } catch { return $null }
}
function Get-CloudInfo {
    $base = 'http://169.254.169.254'
    $tok = Get-Http "$base/latest/api/token" @('X-aws-ec2-metadata-token-ttl-seconds: 60') 'PUT'
    $hd = if ($tok) { @("X-aws-ec2-metadata-token: $tok") } else { @() }
    $id = Get-Http "$base/latest/meta-data/instance-id" $hd
    if ("$id" -match '^i-[0-9a-f]+$') {
        $reg = Get-Http "$base/latest/meta-data/placement/region" $hd
        $sg = @()
        foreach ($m in @((Get-Http "$base/latest/meta-data/network/interfaces/macs/" $hd) -split "`n" | Where-Object { $_ })) { $sg += @((Get-Http "$base/latest/meta-data/network/interfaces/macs/${m}security-group-ids" $hd) -split "`n" | Where-Object { $_ }) }
        return "AWS (instance $id, region $(if ($reg) { $reg } else { '미확인' }), SG: $(if ($sg.Count) { ($sg | Select-Object -Unique) -join ',' } else { '미확인' }))"
    }
    $j = Get-Http "$base/metadata/instance?api-version=2021-02-01" @('Metadata:true')
    if ($j -and $j -match '"vmId"') {
        $nm = if ($j -match '"name"\s*:\s*"([^"]*)"') { $matches[1] } else { '' }; $loc = if ($j -match '"location"\s*:\s*"([^"]*)"') { $matches[1] } else { '' }; $rg = if ($j -match '"resourceGroupName"\s*:\s*"([^"]*)"') { $matches[1] } else { '' }
        return "Azure (vm $nm, region $loc, resource group: $rg)"
    }
    $gid = Get-Http "$base/computeMetadata/v1/instance/id" @('Metadata-Flavor: Google')
    if ("$gid" -match '^\d+$') {
        $gn = Get-Http "$base/computeMetadata/v1/instance/name" @('Metadata-Flavor: Google'); $gz = "$(Get-Http "$base/computeMetadata/v1/instance/zone" @('Metadata-Flavor: Google'))" -replace '.*/',''
        return "GCP (instance $gn, zone $gz)"
    }
    return '없음'
}
$isAdmin = $false
try { $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) } catch {}
$whoami = "$env:USERDOMAIN\$env:USERNAME"

$script:cntPass=0; $script:cntFail=0; $script:cntMC=0; $script:cntNC=0; $script:cntNA=0
$script:CtlPerm = $null
$script:DbPort = $null

function Print-Header([string]$ver) {
    Out-Line "# ================================================================"
    Out-Line "# 점검 대상: $($script:TargetId)"
    Out-Line "# 실행 호스트: $hn"
    $ips = Get-LocalIPs
    Out-Line "# IP: $(if ($ips.Count) { $ips -join ', ' } else { '미확인' })"
    Out-Line "# 실행 계정: $whoami$(if (-not $isAdmin) { ' (관리자 아님 - 일부 항목 점검불가)' })"
    Out-Line "# 클라우드: $(Get-CloudInfo)"
    Out-Line "# DBMS 환경: $(if ($script:Managed) { '관리형 (' + $script:ManagedLabel + ')' } else { '설치형' })"
    Out-Line "# DBMS 종류: mssql"
    Out-Line "# DB 버전: $ver"
    if ($script:Remote) { Out-Line "# 점검 방식: 원격 접속 - OS 항목(파일·서비스 계정·방화벽·OS 암호 정책)은 실행 호스트 기준으로 판정하지 않음(관리형=N-A, 설치형 원격=점검불가)" }
    Out-Line "# 점검 기준: $(switch ($script:KMODE) { 'ef' { '전자금융기반시설 보안 취약점 평가기준 제2026-1호 [데이터베이스]' } 'mi' { '주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드(2026) [DBMS D-01~D-26]' } default { '전자금융기반시설 보안 취약점 평가기준 제2026-1호 [데이터베이스] + 주요정보통신기반시설 상세가이드(2026) [DBMS D-01~D-26]' } })"
    Out-Line "# 점검 일시: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    Evd-Write "# ================================================================`n# MSSQL 증적 파일 (감사 추적용)`n# 점검 대상: $($script:TargetId) / 실행 호스트: $hn / 환경: $(if ($script:Managed) { '관리형 (' + $script:ManagedLabel + ')' } elseif ($script:Remote) { '설치형(원격 접속)' } else { '설치형(로컬)' }) / DB 버전: $ver`n# 생성: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')`n# 각 블록: [항목] 시각 SQL: <실행한 SQL 전문> → 열 이름(첫 줄)과 결과 행 전체 → 오류 시 [오류 원문]`n# ================================================================"
}

if (-not $sqlcmd) {
    Print-Header '미확인'
    Out-Line "# [ERROR] sqlcmd 미발견 - 점검불가 (sqlcmd/ODBC Driver 설치 또는 PATH 확인)"
    if ($script:KMODE -ne 'mi') { @("001","003","004","005","006","007","008","009","011","012","013","014","015","016","017","019","020","021","022","024","025","026","028","029","030","031","032","033","034","035","036") | ForEach-Object { $script:cntNC++; Out-Line "DBM-${_}|점검불가|sqlcmd 명령을 찾지 못해 점검 불가" } }
    if ($script:KMODE -ne 'ef') { 1..26 | ForEach-Object { $script:cntNC++; Out-Line ("D-{0:D2}|점검불가|sqlcmd 명령을 찾지 못해 점검 불가 - 수동 점검 필요" -f $_) } }
    Finish
}

# -C 지원 탐지: ODBC sqlcmd '[-C Trust …]' / go-sqlcmd '-C,--trust-server-certificate'
# ODBC 18 sqlcmd 는 암호화 기본 필수 → 자체 서명 인증서 환경은 -C(서버 인증서 신뢰) 필요 (MSSQL_ENCRYPT=0 이면 생략)
$script:TrustCert = @(); if ($env:MSSQL_ENCRYPT -ne "0" -and ((& $sqlcmd -? 2>&1 | Out-String) -match '(?i)-C(\s+|,\s*--)trust')) { $script:TrustCert = @('-C') }

function Log-Q([string]$q,[string[]]$raw,[string]$err,$rc) {
    $flat = (($q -replace '[\r\n]+',' ') -replace '\s+',' ').Trim()
    $t = "[$($script:Cur)] $(Get-Date -Format 'HH:mm:ss') SQL: $flat`n"
    if ($raw -and $raw.Count -gt 0) { $t += (($raw) -join "`n") } else { $t += "(결과 0행 - 오류가 없다면 해당 데이터 없음)" }
    if ($err) { $t += "`n[오류 원문] " + $err.Trim() }
    if ($rc -ne 0) { $t += "`n[종료코드] $rc" }
    Evd-Write ($t + "`n")
    $script:EvdHas[$script:Cur] = $true
}
function Run-Q([string]$q,[switch]$Opt) {
    # -b: 오류 시 종료코드 1, -r 1: 오류 메시지를 stderr 로 분리 → 'Msg nnn …' 문장이 결과로 섞이지 않음. 열 이름 줄을 포함해 sqlcmd 출력을 증적에 전부 기록.
    # 오류는 증적에 원문 기록 + 현재 항목을 점검불가로 만든다(-Opt 는 버전 차이로 정상인 조회라 항목을 점검불가로 만들지 않음). 오류 시 $null 반환.
    $a = @('-S',$script:SrvArg,'-Q',"SET NOCOUNT ON; $q",'-W','-s','|','-b','-r','1') + $script:TrustCert
    $a += if ($USE_WIN_AUTH) { @('-E') } else { @('-U',$MSSQL_USER) }
    $err = ""; $lines = @(); $rc = 0
    try {
        $all = @(& $sqlcmd @a 2>&1); $rc = $LASTEXITCODE
        foreach ($x in $all) { if ($x -is [System.Management.Automation.ErrorRecord]) { $err += "$x`n" } else { $lines += "$x" } }
    } catch { $err += "$_"; $rc = 99 }
    $nz = @($lines | Where-Object { $_ -and $_.Trim() -ne '' -and $_ -notmatch '^\(\d+ rows? affected\)' })
    Log-Q $q $nz $err $rc
    if ($rc -ne 0) {
        $first = (($err -split "`n") | Where-Object { $_.Trim() } | Select-Object -First 1); if (-not $first) { $first = "sqlcmd 종료코드 $rc" }
        if (-not $Opt) { $script:ItemErr += $first.Trim() }
        $script:QErr = $true; return $null
    }
    $script:QErr = $false
    if ($nz.Count -ge 2 -and $nz[1] -match '^[-|]+$') { return @($nz | Select-Object -Skip 2) }
    return $nz
}
function Q-Int([string]$q) { $v = Run-Q $q | Select-Object -First 1; if ("$v".Trim() -match '^-?\d+$') { [int]"$v".Trim() } else { $null } }
# 접속: MSSQL_PASS 미지정 → Windows 인증 우선 시도 → 실패하고 대화형이면 숨김 입력 (비밀번호는 SQLCMDPASSWORD 환경변수로만 전달, 종료 시 제거)
Item-Begin 'DBM-000'
if (-not $USE_WIN_AUTH -and -not $MSSQL_PASS) {
    $USE_WIN_AUTH = $true
    if ("$(Run-Q 'SELECT 1' -Opt | Select-Object -First 1)".Trim() -ne "1") {
        $USE_WIN_AUTH = $false
        if ([Environment]::UserInteractive -and $Host.UI.RawUI) {
            try { $sp = Read-Host -AsSecureString "SQL Server $MSSQL_USER 비밀번호"; $MSSQL_PASS = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($sp)) } catch {}
        }
    }
}
$env:SQLCMDPASSWORD = $MSSQL_PASS

# 평가기준 제2026-1호 [데이터베이스] 평가항목 31개 — 그 외 DBM 코드는 참고 점검(증적만 기록, 결과·집계 제외)
$script:GUIDE_DBM = @("001","003","004","005","006","007","008","009","011","012","013","014","015","016","017","019","020","021","022","024","025","026","028","029","030","031","032","033","034","035","036")
function Test-Guide([string]$code,[string]$res,[string]$msg) {
    if ($script:KMODE -eq 'mi') { Evd-Write "[참고-주요정보 모드 제외] DBM-${code}|$res|$msg`n"; return $false }
    if ($script:GUIDE_DBM -contains $code) { return $true }
    Evd-Write "[참고-평가기준 외] DBM-${code}|$res|$msg`n"; return $false
}
# 판정 출력 공통: 쿼리 오류가 있었던 항목은 값을 쓰지 않고 점검불가로 바꾼다 (부분 결과가 취약이면 근거에 함께 표시)
function Emit([string]$full,[string]$res,[string]$msg) {
    $msg = ($msg -replace "[`r`n]+", " / ") -replace '\|', '/'
    $errs = @($script:ItemErr | Where-Object { $_ } | Select-Object -Unique)
    if ($errs.Count -gt 0) {
        $e1 = $errs[0]
        if ($res -eq '점검불가') { if (-not $msg.Contains($e1)) { $msg = "$msg [조회 오류: $e1]" } }
        elseif ($res -ne 'N-A') {
            $msg = "조회 오류/권한 부족으로 점검 불가 - $e1 (증적의 SQL·오류 원문 참조)$(if ($res -eq '취약') { " [참고: 오류 이전 판정 취약 - $msg]" })"
            $res = '점검불가'
        }
    }
    $script:ItemErr = @()
    switch ($res) { '양호' { $script:cntPass++ } '취약' { $script:cntFail++ } '수동확인' { $script:cntMC++ } '점검불가' { $script:cntNC++ } default { $script:cntNA++ } }
    if (-not $script:EvdHas.ContainsKey($full)) { Evd-Write "[$full] $(Get-Date -Format 'HH:mm:ss') 판정근거($res): 조회 없이 판정`n$msg`n"; $script:EvdHas[$full] = $true }
    Out-Line "$full|$res|$msg"
    Evd-Write "[판정] $full|$res|$msg`n"
}
function Pass([string]$code,[string]$msg) { if (-not (Test-Guide $code "양호" $msg)) { return }; Emit "DBM-$code" '양호' $msg }
function Fail([string]$code,[string]$msg) { if (-not (Test-Guide $code "취약" $msg)) { return }; Emit "DBM-$code" '취약' $msg }
function NA  ([string]$code,[string]$msg) { if (-not (Test-Guide $code "N-A" $msg)) { return }; Emit "DBM-$code" 'N-A' $msg }
function MC  ([string]$code,[string]$msg) { if (-not (Test-Guide $code "수동확인" $msg)) { return }; Emit "DBM-$code" '수동확인' $msg }
function NC  ([string]$code,[string]$msg) { if (-not (Test-Guide $code "점검불가" $msg)) { return }; Emit "DBM-$code" '점검불가' $msg }

function KPut([string]$code,[string]$res,[string]$msg) {   # 가이드 D 항목 판정 출력 (전자금융 모드는 생략)
    if ($script:KMODE -eq 'ef') { return }
    Emit $code $res $msg
}
function Evd([string]$item,[string]$cmd) {
    $r = ""; try { $r = Invoke-Expression $cmd 2>&1 | Out-String } catch { $r = $_.Exception.Message }
    Evd-Write "[$item] $(Get-Date -Format 'HH:mm:ss') PS> $cmd`n$r"
    $script:EvdHas[$item] = $true
}
function EvdQ([string]$item,[string]$desc,[string]$val) {   # 판정에 쓴 값 요약 (실제 SQL·열 이름·결과 행은 Run-Q 가 'SQL:' 블록으로 이미 기록)
    Evd-Write "[$item] $(Get-Date -Format 'HH:mm:ss') 판정값: $desc`n$(if ($val) { $val } else { '(없음)' })`n"
    $script:EvdHas[$item] = $true
}
# OS 의존 항목(로컬 파일·서비스·방화벽·OS 정책) 게이트: 관리형 → N-A, 원격(설치형) → 점검불가. 적용되면 $true
function Os-Gate([string]$full,[string]$desc) {
    if ($script:Managed) { Emit $full 'N-A' "N-A(관리형 DB - 운영체제 접근 불가, 파라미터 그룹·콘솔 설정으로 확인) - $desc [$($script:ManagedLabel)]"; return $true }
    if ($script:Remote) { Emit $full '점검불가' "원격 접속 대상($($script:TargetId))이라 실행 호스트($hn)의 파일·서비스·방화벽·OS 정책을 판정하지 않음 - 대상 서버에서 직접 실행 필요 - $desc"; return $true }
    return $false
}
function Os-GateD([string]$code,[string]$desc) { if ($script:KMODE -eq 'ef') { return $true }; return (Os-Gate $code $desc) }
function Os-GateE([string]$code,[string]$desc) {   # DBM 코드용 (평가기준 31개 외 / mi 모드 제외 처리 포함)
    if (-not (Test-Guide $code "OS항목" $desc)) { return $true }
    return (Os-Gate "DBM-$code" $desc)
}

# Windows 보안 정책 (DBM-006/007/019: SQL 로그인 CHECK_POLICY 는 OS 정책을 따름) — 설치형 로컬에서만 읽음
$script:seceditFile = "$env:TEMP\mssql_secpol_${PID}.cfg"
if (-not $script:Remote) { $null = secedit /export /cfg $script:seceditFile /areas SECURITYPOLICY /quiet 2>$null }
function Get-SecPol([string]$Key) {
    if (Test-Path $script:seceditFile) {
        $line = Get-Content $script:seceditFile -EA SilentlyContinue | Where-Object { $_ -match "^\s*$([regex]::Escape($Key))\s*=" }
        if ($line) { return ($line -split "=",2)[1].Trim() }
    }; return $null
}

# 접속 확인
$connTest = Run-Q "SELECT 1"
$connVal = ($connTest | Select-Object -First 1)
if (-not $connVal -or $connVal.Trim() -ne "1") {
    $connErr = if ($script:ItemErr.Count) { $script:ItemErr[0] } else { '응답 없음' }
    Print-Header '미확인'
    Out-Line "# [경고] SQL Server 접속 실패 ($($script:SrvArg)): $connErr - 전 항목 점검불가 처리"
    Out-Line "# ================================================================"
    $script:ItemErr = @()
    $why = "DB 접속 실패($($script:SrvArg)): $connErr - 접속 정보(계정/권한/호스트·방화벽·SSL) 확인 후 재점검 (증적의 접속 시도 SQL·오류 원문 참조)"
    if ($script:KMODE -ne 'mi') { 1..36 | ForEach-Object { $c = "{0:D3}" -f $_; if ($script:GUIDE_DBM -contains $c) { Emit "DBM-$c" '점검불가' $why } } }
    if ($script:KMODE -ne 'ef') { 1..26 | ForEach-Object { Emit ("D-{0:D2}" -f $_) '점검불가' $why } }
    $total=$script:cntPass+$script:cntFail+$script:cntMC+$script:cntNC+$script:cntNA
    Out-Line "# ================================================================"
    Out-Line "# 점검 요약"
    Out-Line "#   총 점검 항목: $total"
    Out-Line "#   양호:         $($script:cntPass)"
    Out-Line "#   취약:         $($script:cntFail)"
    Out-Line "#   수동확인:     $($script:cntMC)"
    Out-Line "#   점검불가:     $($script:cntNC)"
    Out-Line "#   N-A:          $($script:cntNA)"
    Out-Line "# ================================================================"
    Finish
}

# 버전 확인
$ver = "$(Run-Q "SELECT @@VERSION" | Select-Object -First 1)".Trim()
$verNum = if ($ver -match "SQL Server (\d{4})") { $matches[1] } else { "unknown" }
$build = if ($ver -match "(\d+\.\d+\.\d+\.\d+)") { $matches[1] } else { "" }
Print-Header ($ver -replace '\s+',' ')
Out-Line "# SQL Server 버전: $verNum ($build)"
Out-Line "# 접속: $(if ($USE_WIN_AUTH) { 'Windows 인증' } else { "SQL 인증($MSSQL_USER)" })"
Out-Line "# ================================================================"
# 권한 확인: password_hash·서버 수준 뷰는 CONTROL SERVER(sysadmin) 필요 — 없으면 NULL 로 조용히 비어 보이므로 미리 확인
$script:CtlPerm = Q-Int "SELECT CAST(HAS_PERMS_BY_NAME(NULL,NULL,'CONTROL SERVER') AS int) AS control_server"
EvdQ "DBM-000" "CONTROL SERVER 권한 보유(1=예) — 0 이면 password_hash 등이 NULL 로 보여 일부 항목 점검불가" "$($script:CtlPerm)"
$script:ItemErr = @()
# 관리형 예약 로그인 (계정 점검에서 제외)
$script:Rsv = if ($script:Managed) { 'rdsa','rdsadmin' } else { @() }
$rsvNote = if ($script:Managed) { " (관리형 예약 로그인 제외: $($script:Rsv -join ', '))" } else { '' }
$rsvSql = if ($script:Managed) { "'rdsa','rdsadmin','##none##'" } else { "'##none##'" }
function Strip-Rsv($list) {   # null/빈 줄 제거 + 관리형 예약 로그인 제외. 항상 배열 반환(요소 1개여도 PS2.0 에서 풀리지 않게 ,@())
    $l = @($list | Where-Object { $_ -and "$_".Trim() })
    if ($script:Managed) { $re = '^(' + ($script:Rsv -join '|') + ')(\s|\||:|\(|$)'; $l = @($l | Where-Object { "$_" -notmatch $re }) }
    return ,$l
}
# DB 포트: 연결 세션의 local_tcp_port (공유 메모리 접속이면 NULL → 레지스트리 IPAll TcpPort/TcpDynamicPorts) — 방화벽 항목(DBM-013/D-10)에서 공용
function Get-DbPort {
    if ($script:DbPort) { return $script:DbPort }
    $p = "$(Run-Q "SELECT TOP 1 local_tcp_port FROM sys.dm_exec_connections WHERE local_tcp_port IS NOT NULL" | Select-Object -First 1)".Trim()
    if ($p -notmatch '^\d+$' -and -not $script:Remote) {
        $ipall = Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server' -EA SilentlyContinue | ForEach-Object { Get-ItemProperty "$($_.PSPath)\MSSQLServer\SuperSocketNetLib\Tcp\IPAll" -EA SilentlyContinue } | Select-Object -First 1
        $p = @("$($ipall.TcpPort)","$($ipall.TcpDynamicPorts)") | Where-Object { $_ -match '^\d+$' } | Select-Object -First 1
    }
    if ($p -notmatch '^\d+$') { $p = $tPort }
    $script:DbPort = "$p"; return $script:DbPort
}
# Windows 방화벽: COM(HNetCfg.FwPolicy2, Vista/2008 이상 — PS2.0 에서도 동작) 으로 프로필 상태와 DB 포트 인바운드 허용 규칙을 읽음
function Port-InSpec([string]$spec,[string]$port) {
    foreach ($s in ("$spec" -split ',')) { $s = $s.Trim(); if ($s -eq $port) { return $true }; if ($s -match '^(\d+)-(\d+)$' -and [int]$port -ge [int]$matches[1] -and [int]$port -le [int]$matches[2]) { return $true } }
    return $false
}
function Get-FwInfo([string]$port) {
    $info = @{ Err = $null; Profiles = @(); EnabledMask = 0; Rules = @() }
    try { $fw = New-Object -ComObject HNetCfg.FwPolicy2 } catch { $info.Err = "HNetCfg.FwPolicy2 COM 생성 실패: $_"; return $info }
    if (-not $fw) { $info.Err = "HNetCfg.FwPolicy2 COM 객체를 만들지 못함"; return $info }
    foreach ($p in @(@('Domain',1),@('Private',2),@('Public',4))) {
        $en = $false; try { $en = [bool]$fw.FirewallEnabled($p[1]) } catch {}
        $info.Profiles += ,@($p[0], $en); if ($en) { $info.EnabledMask = $info.EnabledMask -bor $p[1] }
    }
    foreach ($r in $fw.Rules) {
        try {
            if (-not $r.Enabled -or $r.Direction -ne 1 -or $r.Action -ne 1) { continue }
            $lp = "$($r.LocalPorts)"; $app = "$($r.ApplicationName)"
            if ((Port-InSpec $lp $port) -or ((@('','*') -contains "$lp") -and $app -match 'sqlservr\.exe$')) {
                $info.Rules += ,@("$($r.Name)", "$($r.RemoteAddresses)", [int]$r.Profiles)
            }
        } catch {}
    }
    return $info
}

# ── DBM-001: 취약하게 설정된 비밀번호 제거 ──────────────────────
Item-Begin 'DBM-001'
$noPol1 = Strip-Rsv @(Run-Q "SELECT name FROM sys.sql_logins WHERE is_policy_checked=0 AND is_disabled=0 AND name NOT LIKE '##%' AND name NOT IN ($rsvSql) ORDER BY name")
$weak1  = Strip-Rsv @(Run-Q "SELECT name FROM sys.sql_logins WHERE is_disabled=0 AND name NOT LIKE '##%' AND name NOT IN ($rsvSql) AND (PWDCOMPARE('',password_hash)=1 OR PWDCOMPARE(name,password_hash)=1 OR PWDCOMPARE('password',password_hash)=1 OR PWDCOMPARE('sa',password_hash)=1 OR PWDCOMPARE('Password1',password_hash)=1 OR PWDCOMPARE('P@ssw0rd',password_hash)=1 OR PWDCOMPARE('123456',password_hash)=1 OR PWDCOMPARE('1234',password_hash)=1) ORDER BY name")
if ($script:CtlPerm -ne 1) { Carry "CONTROL SERVER 권한 없음(HAS_PERMS_BY_NAME=$($script:CtlPerm)) - password_hash 조회 불가로 빈/기본 비밀번호 검사를 수행하지 못함" }
EvdQ "DBM-001" "is_policy_checked=0 활성 로그인 / 빈·계정명·흔한 비밀번호와 해시 일치 로그인(PWDCOMPARE, 해시 값은 출력하지 않음)" "$($noPol1 -join ', ') / $($weak1 -join ', ')"
# 평가기준: 취약 비밀번호 여부는 해시 크랙으로 확인 → 빈 값·계정명·흔한 값 일치는 취약, 그 외는 수동확인
if ($weak1.Count -gt 0) { Fail "001" "빈 비밀번호·계정명·기본(password/sa/123456 등) 비밀번호와 일치하는 SQL 로그인: $(($weak1 | Select-Object -First 20) -join ', ')$rsvNote" }
elseif ($noPol1.Count -gt 0) { MC "001" "비밀번호 정책 미적용 활성 계정 $($noPol1.Count)개: $(($noPol1 | Select-Object -First 10) -join ', ') (크랙 우선 대상) - 비밀번호 복잡도·취약 여부 해시 크랙 확인 필요$rsvNote" }
else { MC "001" "빈·기본 비밀번호 로그인 없음, 모든 SQL 계정 비밀번호 정책 적용됨 - 비밀번호 복잡도·취약 여부 해시 크랙 확인 필요$rsvNote" }

# ── DBM-003: 불필요/관리되지 않는 계정 제거 ─────────────────────
Item-Begin 'DBM-003'
$logins = @(Run-Q 'SELECT p.name+'' | ''+p.type_desc COLLATE DATABASE_DEFAULT+'' | disabled=''+CAST(p.is_disabled AS varchar)+'' | created=''+CONVERT(varchar(10),p.create_date,120)+'' | pwdset=''+ISNULL(CONVERT(varchar(10),CAST(LOGINPROPERTY(p.name,''PasswordLastSetTime'') AS datetime),120),''-'')+'' | expired=''+ISNULL(CAST(LOGINPROPERTY(p.name,''IsExpired'') AS varchar),''-'')+'' | locked=''+ISNULL(CAST(LOGINPROPERTY(p.name,''IsLocked'') AS varchar),''-'') FROM sys.server_principals p WHERE p.type IN (''S'',''U'',''G'') AND p.name NOT LIKE ''##%'' ORDER BY p.name')
$logins = Strip-Rsv $logins
EvdQ "DBM-003" "로그인 목록 (name | type | disabled | created | pwdset | expired | locked)" ($logins -join "`n")
MC "003" "로그인 $($logins.Count)개 - 업무상 불필요·장기 미사용 계정 인터뷰 확인 (증적 참조)$rsvNote"

# ── DBM-004: 불필요한 관리자 계정 제거 ──────────────────────────
# 평가기준: 서버 수준 역할(sysadmin, serveradmin, securityadmin, processadmin, setupadmin, bulkadmin, diskadmin, dbcreator 등) 부여 계정 → 인터뷰로 불필요 여부 확인
Item-Begin 'DBM-004'
$sysAdmins = Run-Q "SELECT role.name+': '+p.name AS role_member FROM sys.server_principals p JOIN sys.server_role_members r ON p.principal_id=r.member_principal_id JOIN sys.server_principals role ON r.role_principal_id=role.principal_id WHERE role.name IN ('sysadmin','serveradmin','securityadmin','processadmin','setupadmin','bulkadmin','diskadmin','dbcreator') AND p.name NOT LIKE '##%' AND p.name NOT LIKE 'NT SERVICE\%' AND p.name NOT LIKE 'NT AUTHORITY\%'"
EvdQ "DBM-004" "server role members (sysadmin/serveradmin/securityadmin/processadmin/setupadmin/bulkadmin/diskadmin/dbcreator)" ($sysAdmins -join "`n")
$admins = @($sysAdmins | Where-Object { $_ -and $_.Trim() -and ($_ -notmatch ': (rdsa|rdsadmin)$' -or -not $script:Managed) })
if ($admins.Count -gt 0) {
    MC "004" "서버 수준 관리자 역할 부여 $($admins.Count)건: $(($admins | Select-Object -First 20) -join ', ') - 업무상 필요 여부 인터뷰 확인$rsvNote"
} else {
    MC "004" "서버 수준 관리자 역할 조회 결과 없음 - 조회 권한 및 관리자 계정 수동 확인"
}

# ── DBM-005: 중요정보 암호화 ────────────────────────────────────
Item-Begin 'DBM-005'
$tde = @(Run-Q "SELECT DB_NAME(database_id) AS db_name, encryption_state FROM sys.dm_database_encryption_keys ORDER BY 1")
EvdQ "DBM-005" "TDE 암호화 키 보유 DB (encryption_state=3 이 암호화 완료)" ($tde -join "`n")
# 평가기준: 중요정보 컬럼이 평문/취약 알고리즘으로 저장되면 취약 — TDE 는 파일 수준 암호화라 조회 시 평문 (판단 근거 아님)
MC "005" "TDE 암호화 DB $(@($tde | Where-Object { $_ -match '\|3\s*$' }).Count)개(참고) - 중요정보 컬럼 암호화(Always Encrypted·컬럼 암호화) 적용 여부 확인"

# ── DBM-006: 로그인 실패 횟수 제한 ─────────────────────────────
# SQL Server는 Windows 정책으로 관리, 계정 잠금 정책 확인
Item-Begin 'DBM-006'
$noPol = Strip-Rsv @(Run-Q "SELECT name FROM sys.sql_logins WHERE is_policy_checked=0 AND is_disabled=0 AND name NOT LIKE '##%' AND name NOT IN ($rsvSql)")
$noPolList = @($noPol | Where-Object { $_ -and $_.Trim() })
if ($script:Remote -and $noPolList.Count -gt 0) {
    EvdQ "DBM-006" "CHECK_POLICY=OFF 활성 SQL 로그인 (OS 잠금 정책은 원격/관리형이라 미확인)" ($noPolList -join ', ')
    Fail "006" "CHECK_POLICY=OFF SQL 로그인 $($noPolList.Count)개(잠금 미적용): $(($noPolList | Select-Object -First 5) -join ', ') (OS 잠금 임계값은 원격/관리형이라 미확인)$rsvNote"
} elseif (Os-GateE "006" "계정 잠금 임계값(Windows 계정 잠금 정책)은 서버 OS 정책") {
} else {
    Evd "DBM-006" "net accounts 2>`$null"
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
    EvdQ "DBM-006" "잠금 임계값($lockSrc) / CHECK_POLICY=OFF 활성 SQL 로그인" "$n / $($noPolList -join ', ')"
    if ($null -eq $n) { NC "006" "계정 잠금 임계값 확인 실패(secedit/net accounts, 관리자 권한 필요) - Windows 계정 잠금 정책 수동 확인" }
    elseif ($n -eq 0) { Fail "006" "계정 잠금 임계값 없음(무제한) - 5회 이하 설정 필요" }
    elseif ($n -gt 5) { Fail "006" "계정 잠금 임계값=${n}회 (5회 이하 필요)" }
    elseif ($noPolList.Count -gt 0) { Fail "006" "잠금 임계값 ${n}회이나 CHECK_POLICY=OFF SQL 로그인 $($noPolList.Count)개(잠금 미적용): $(($noPolList | Select-Object -First 5) -join ', ') - 서비스 운영 계정은 평가 제외 가능" }
    else { Pass "006" "계정 잠금 임계값=${n}회 (5회 이하), 활성 SQL 로그인 모두 CHECK_POLICY 적용" }
}

# ── DBM-007: 비밀번호 복잡도 ────────────────────────────────────
# 평가기준: 계정별 Windows password policy(CHECK_POLICY) 적용 + OS 'password must meet complexity requirements' 사용
Item-Begin 'DBM-007'
$noPwcL = Strip-Rsv @(Run-Q "SELECT name FROM sys.sql_logins WHERE is_policy_checked=0 AND is_disabled=0 AND name NOT LIKE '##%' AND name NOT IN ($rsvSql)")
$n7 = @($noPwcL | Where-Object { $_ -and $_.Trim() }).Count
if ($script:Remote -and $n7 -gt 0) {
    EvdQ "DBM-007" "CHECK_POLICY=OFF 활성 로그인 (OS 복잡도 정책은 원격/관리형이라 미확인)" ($noPwcL -join ', ')
    Fail "007" "비밀번호 정책(CHECK_POLICY) 미적용 활성 계정 ${n7}개: $(($noPwcL | Select-Object -First 5) -join ', ')$rsvNote"
} elseif (Os-GateE "007" "OS 암호 복잡도 정책(PasswordComplexity)은 서버 OS 정책") {
} else {
    $pwc7 = Get-SecPol "PasswordComplexity"; $min7 = Get-SecPol "MinimumPasswordLength"
    EvdQ "DBM-007" "is_policy_checked=0 활성 로그인 / OS PasswordComplexity / MinimumPasswordLength" "$($noPwcL -join ', ') / $pwc7 / $min7"
    if ($n7 -gt 0) { Fail "007" "비밀번호 정책(CHECK_POLICY) 미적용 활성 계정 ${n7}개" }
    elseif ("$pwc7" -eq "0") { Fail "007" "OS 비밀번호 복잡도 정책 사용 안 함 (PasswordComplexity=0) - SQL 로그인 복잡도 미강제" }
    elseif ($null -eq $pwc7) { NC "007" "모든 활성 SQL 계정 CHECK_POLICY 적용 - OS 복잡도 정책 확인 실패(secedit, 관리자 권한 필요)" }
    elseif ($null -ne $min7 -and [int]$min7 -lt 8) { Fail "007" "OS 최소 비밀번호 길이=${min7}자 (3종 8자 미달)" }
    else { Pass "007" "모든 활성 SQL 계정 CHECK_POLICY 적용, OS 복잡도 사용 (최소 길이 ${min7}자)" }
}

# ── DBM-008: 비밀번호 변경 주기 ─────────────────────────────────
Item-Begin 'DBM-008'
$noExp = Strip-Rsv @(Run-Q "SELECT name FROM sys.sql_logins WHERE is_expiration_checked=0 AND is_disabled=0 AND name NOT IN ('sa','##MS_PolicyEventProcessingLogin##') AND name NOT LIKE '##%' AND name NOT IN ($rsvSql) ORDER BY name")
$noExpL = @($noExp | Where-Object { $_ -and $_.Trim() })
# 평가기준 평가예시: 최근 비밀번호 변경일로부터 1분기(약 90일) 이상 지난 계정 존재 시 취약
$old8 = Strip-Rsv @(Run-Q "SELECT name+' ('+CONVERT(varchar(10),CAST(LOGINPROPERTY(name,'PasswordLastSetTime') AS datetime),120)+')' AS login_pwdset FROM sys.sql_logins WHERE is_disabled=0 AND name NOT LIKE '##%' AND name NOT IN ($rsvSql) AND DATEDIFF(DAY,CAST(LOGINPROPERTY(name,'PasswordLastSetTime') AS datetime),GETDATE())>=90 ORDER BY name")
$old8List = @($old8 | Where-Object { $_ -and $_.Trim() })
EvdQ "DBM-008" "is_expiration_checked=0 활성 로그인 / 비밀번호 변경 후 90일 이상 활성 SQL 로그인 (PasswordLastSetTime)" "$($noExpL -join ', ') / $($old8List -join ', ')"
if ($old8List.Count -gt 0) { Fail "008" "비밀번호 변경 후 90일 이상 경과 계정 $($old8List.Count)개: $(($old8List | Select-Object -First 5) -join ', ') - 서비스 운영 계정은 평가 제외 가능$rsvNote" }
elseif ($noExpL.Count -gt 0) { MC "008" "90일 이상 경과 계정 없음, 비밀번호 만료(CHECK_EXPIRATION) 미설정 계정 $($noExpL.Count)개 - 주기적 변경 관리 여부 확인" }
else { Pass "008" "모든 활성 SQL 계정 비밀번호 90일 이내 변경, 만료 설정됨$rsvNote" }

# ── DBM-009: 미사용 세션 종료 ───────────────────────────────────
# 평가기준: 사용자 세션 last_request_end_time 이 15분(내부 규정 미명시 시) 초과 유휴 상태로 남아 있으면 취약
#   ('remote query timeout' 은 연결 서버 쿼리 타임아웃으로 유휴 세션 종료와 무관)
Item-Begin 'DBM-009'
$idle = Run-Q "SELECT login_name+' (idle '+CAST(DATEDIFF(MINUTE,last_request_end_time,GETDATE()) AS varchar)+'분)' AS idle_session FROM sys.dm_exec_sessions WHERE is_user_process=1 AND status='sleeping' AND DATEDIFF(MINUTE,last_request_end_time,GETDATE())>15"
EvdQ "DBM-009" "15분 초과 유휴 사용자 세션 (sys.dm_exec_sessions)" ($idle -join "`n")
$idleList = @($idle | Where-Object { $_ -and $_.Trim() })
if ($idleList.Count -gt 0) { Fail "009" "15분 초과 유휴 세션 $($idleList.Count)개: $(($idleList | Select-Object -First 3) -join ', ') - 서비스 계정은 평가 제외 가능" }
else { MC "009" "현재 15분 초과 유휴 세션 없음 - 자동 종료 설정(접근제어 솔루션 등) 여부 수동 확인" }

# ── DBM-011: 감사 로그 수집 및 백업 ─────────────────────────────
Item-Begin 'DBM-011'
$auditRows = @(Run-Q "SELECT name, is_state_enabled FROM sys.server_audits")
$n11 = @($auditRows | Where-Object { $_ -match '\|\s*1\s*$' }).Count
# 평가기준: 감사 로그 수집 + 주기적 백업(인터뷰·증적) 모두 충족 시 양호 → 수집 중이면 백업 여부 수동확인
$spec11 = Run-Q "SELECT s.name+': '+d.audit_action_name AS audit_spec FROM sys.server_audit_specifications s JOIN sys.server_audit_specification_details d ON s.server_specification_id=d.server_specification_id WHERE s.is_state_enabled=1"
$loginAud = @($spec11 | Where-Object { $_ -match "FAILED_LOGIN_GROUP|SUCCESSFUL_LOGIN_GROUP" })
$al11 = "$(Run-Q "DECLARE @v int; EXEC master.dbo.xp_instance_regread N'HKEY_LOCAL_MACHINE', N'Software\Microsoft\MSSQLServer\MSSQLServer', N'AuditLevel', @v OUTPUT; SELECT CAST(@v AS varchar(3)) AS audit_level" -Opt | Select-Object -First 1)".Trim()
$c2 = "$(Run-Q "SELECT CAST(value_in_use AS varchar(2)) AS c2_audit_mode FROM sys.configurations WHERE name='c2 audit mode'" | Select-Object -First 1)".Trim()
EvdQ "DBM-011" "서버 감사 / 활성 감사 사양 / 로그인 감사 수준 AuditLevel(0 없음·1 성공·2 실패·3 모두) / C2" "서버 감사 활성 ${n11}개 / $($spec11 -join '; ') / $al11 / $c2"
if ($n11 -gt 0 -and $loginAud.Count -eq 0 -and $al11 -ne '3') { Fail "011" "서버 감사 ${n11}개 활성이나 로그인 성공/실패 감사 사양(FAILED_LOGIN_GROUP/SUCCESSFUL_LOGIN_GROUP) 미설정, 로그인 감사 수준=$(if ($al11) { $al11 } else { 'N/A' })" }
elseif ($n11 -gt 0) { MC "011" "서버 감사 ${n11}개 활성, 로그인 감사 사양 $($loginAud.Count)건(AuditLevel=$(if ($al11) { $al11 } else { 'N/A' })) - 감사 로그 주기적 백업 여부 확인 (미백업 시 취약)" }
elseif ($al11 -eq '3') { MC "011" "로그인 감사 수준=3(성공·실패 모두) 수집 중, 서버 감사 없음 - 감사 로그 주기적 백업 여부 확인 (미백업 시 취약)" }
elseif ($c2 -eq '1') { MC "011" "C2 감사 모드 활성 - 감사 로그 주기적 백업 여부 확인 (미백업 시 취약)" }
elseif (-not $al11) { NC "011" "활성 서버 감사가 없고 로그인 감사 수준(AuditLevel, xp_instance_regread)도 조회하지 못해 점검 불가 - 로그인 감사 설정 수동 확인" }
else { Fail "011" "서버 감사(Server Audit) 미설정, 로그인 감사 수준=$al11 - 감사 로그 미수집" }

# ── DBM-013: 원격 접속 접근 제어 ───────────────────────────────
# 평가기준: Windows 방화벽(또는 네트워크 장비·솔루션)으로 DB 포트 원격 접근제어 ('remote access' 옵션은 무관)
Item-Begin 'DBM-013'
if (Os-GateE "013" "Windows 방화벽 규칙은 서버 OS 설정 (관리형은 보안그룹·방화벽 규칙으로 통제)") { } else {
    $port13 = Get-DbPort
    $fwi = Get-FwInfo $port13
    EvdQ "DBM-013" "방화벽 프로필 Enabled / DB 포트($port13) 인바운드 허용 규칙·원격 주소·적용 프로필" "$(($fwi.Profiles | ForEach-Object { "$($_[0])=$($_[1])" }) -join ', ')`n$(($fwi.Rules | ForEach-Object { "$($_[0]) | 원격 $($_[1]) | 프로필마스크 $($_[2])" }) -join "`n")$(if ($fwi.Err) { "`n[COM 오류] $($fwi.Err)" })"
    $off13 = @($fwi.Profiles | Where-Object { -not $_[1] } | ForEach-Object { $_[0] })
    $active = @($fwi.Rules | Where-Object { ($_[2] -band $fwi.EnabledMask) -ne 0 })     # 켜져 있는 프로필에 적용되는 규칙만 유효
    $open = @($active | Where-Object { $_[1] -match '(^|,)(\*|Any)(,|$)' -or $_[1] -match '0\.0\.0\.0/0' })
    if ($fwi.Err) { NC "013" "Windows 방화벽 정보를 읽지 못함($($fwi.Err)) - 네트워크 장비·솔루션 접근제어 수동 확인" }
    elseif ($open.Count -gt 0) { Fail "013" "DB 포트 $port13 모든 원격 주소 허용 규칙(활성 프로필): $(($open | ForEach-Object { $_[0] }) -join ', ')" }
    elseif ($off13.Count -gt 0) { MC "013" "Windows 방화벽 비활성 프로필: $($off13 -join ',') - 해당 프로필에서는 규칙이 적용되지 않음. 네트워크 장비·솔루션 접근제어 수동 확인(없으면 취약)" }
    elseif ($active.Count -eq 0) { MC "013" "DB 포트($port13) 인바운드 허용 방화벽 규칙 없음 - 네트워크 장비·솔루션 접근제어 수동 확인" }
    else { Pass "013" "DB 포트 $port13 원격 주소 제한됨: $(($active | ForEach-Object { "$($_[0]): $($_[1])" }) -join '; ')" }
}

# ── DBM-015: Public Role 불필요 권한 제거 ───────────────────────
# 기본 설치 시 master 시스템 개체(is_ms_shipped)에 public 기본 GRANT 가 있으므로 제외 — 사용자 개체·DB/서버 수준 권한만 판단
Item-Begin 'DBM-015'
$dbs = @(Run-Q 'SET NOCOUNT ON; SELECT name+'' (''+state_desc COLLATE DATABASE_DEFAULT+'')'' AS db FROM sys.databases')
$pubDb = Run-Q 'SET NOCOUNT ON; DECLARE @s nvarchar(max)=N''''; SELECT @s=@s+N''SELECT N''''''+REPLACE(name,'''''''','''''''''''')+N'':''''+p.class_desc COLLATE DATABASE_DEFAULT+N'''':''''+ISNULL(o.name,N''''-'''') COLLATE DATABASE_DEFAULT+N'''':''''+p.permission_name COLLATE DATABASE_DEFAULT FROM ''+QUOTENAME(name)+N''.sys.database_permissions p LEFT JOIN ''+QUOTENAME(name)+N''.sys.all_objects o ON p.class=1 AND o.object_id=p.major_id WHERE p.grantee_principal_id=0 AND p.state IN (''''G'''',''''W'''') AND p.permission_name NOT IN (''''CONNECT'''',''''VIEW ANY COLUMN ENCRYPTION KEY DEFINITION'''',''''VIEW ANY COLUMN MASTER KEY DEFINITION'''') AND (p.class<>1 OR o.is_ms_shipped=0) UNION ALL '' FROM sys.databases WHERE state_desc=''ONLINE'' AND HAS_DBACCESS(name)=1; IF LEN(@s)>0 BEGIN SET @s=LEFT(@s,LEN(@s)-10); EXEC(@s); END'; $e15a = $script:QErr
$pubSrv = Run-Q 'SET NOCOUNT ON; SELECT ''SERVER:''+class_desc+'' ''+permission_name FROM sys.server_permissions WHERE grantee_principal_id=2 AND permission_name NOT IN (''VIEW ANY DATABASE'',''CONNECT SQL'') AND NOT (class_desc=''ENDPOINT'' AND permission_name=''CONNECT'') AND state IN (''G'',''W'')'; $e15b = $script:QErr
$pubList = @(@($pubDb) + @($pubSrv) | Where-Object { $_ -and "$_".Trim() })
EvdQ "DBM-015" "public 역할 비기본 권한 (전 DB: $($dbs -join ', ') + 서버 수준, 시스템 개체 기본 GRANT 제외)" ($pubList -join "`n")
if ($pubList.Count -gt 0) { MC "015" "public 역할 비기본 권한 $($pubList.Count)건: $(($pubList | Select-Object -First 5) -join ', ') - 업무상 필요 여부 확인 (불필요 시 취약)" }
else { Pass "015" "public 역할에 기본 외 권한 없음" }

# ── DBM-016: 보안패치 ───────────────────────────────────────────
# eos_checker.py 활용
Item-Begin 'DBM-016'
EvdQ "DBM-016" "SQL Server version / ProductLevel·ProductUpdateLevel·ProductUpdateReference" "$verNum ($build) / $(Run-Q "SELECT CAST(SERVERPROPERTY('ProductLevel') AS varchar)+' '+ISNULL(CAST(SERVERPROPERTY('ProductUpdateLevel') AS varchar),'-')+' '+ISNULL(CAST(SERVERPROPERTY('ProductUpdateReference') AS varchar),'-') AS product_level" -Opt)"
$eosScript = Join-Path (Split-Path $MyInvocation.MyCommand.Path) "eos_checker.py"
if (-not (Test-Path $eosScript)) { $eosScript = Join-Path $script:OUTDIR "..\converter\eos_checker.py" }   # 저장소 구조 그대로 실행 시
if (Test-Path $eosScript) {
    $py = @('py','python','python3') | Where-Object { Get-Command $_ -EA SilentlyContinue } | Select-Object -First 1
    $eosResult = if ($py) { & $py $eosScript "mssql" $verNum 2>$null } else { $null }
    $eosStatus = ($eosResult | Where-Object {$_ -match "^결과:"}) -replace "결과:\s*",""
    $eosDesc   = ($eosResult | Where-Object {$_ -match "^설명:"}) -replace "설명:\s*",""
    Evd-Write "[DBM-016] $(Get-Date -Format 'HH:mm:ss') PS> python eos_checker.py mssql $verNum`n$(($eosResult | Out-String).Trim())`n"
    if ($eosStatus -eq "취약") { Fail "016" "SQL Server $verNum EoS/보안패치: $eosDesc" }
    elseif ($eosStatus -eq "양호") { MC "016" "SQL Server $verNum ($build) 지원기간 내 - 최신 CU/GDR 적용 여부 확인" }
    else { MC "016" "SQL Server $verNum 보안패치 수동 확인 (최신 CU 적용 여부)" }
} else { MC "016" "보안패치 현황 수동 확인 (SQL Server $verNum 최신 CU 확인)" }

# ── DBM-017: 시스템 테이블 접근 권한 ───────────────────────────
Item-Begin 'DBM-017'
$sysTbl = @(Run-Q 'SET NOCOUNT ON; DECLARE @s nvarchar(max)=N''''; SELECT @s=@s+N''SELECT N''''''+REPLACE(name,'''''''','''''''''''')+N'':''''+o.name COLLATE DATABASE_DEFAULT+N'''':''''+d.name COLLATE DATABASE_DEFAULT+N'''':''''+p.permission_name COLLATE DATABASE_DEFAULT FROM ''+QUOTENAME(name)+N''.sys.database_permissions p JOIN ''+QUOTENAME(name)+N''.sys.all_objects o ON o.object_id=p.major_id AND p.class=1 JOIN ''+QUOTENAME(name)+N''.sys.database_principals d ON d.principal_id=p.grantee_principal_id WHERE (o.schema_id=4 OR o.type=''''S'''') AND p.state IN (''''G'''',''''W'''') AND p.grantee_principal_id<>0 AND d.is_fixed_role=0 AND d.name NOT IN (''''dbo'''',''''sys'''',''''INFORMATION_SCHEMA'''',''''guest'''') AND d.name NOT LIKE ''''##%'''' UNION ALL '' FROM sys.databases WHERE state_desc=''ONLINE'' AND HAS_DBACCESS(name)=1; IF LEN(@s)>0 BEGIN SET @s=LEFT(@s,LEN(@s)-10); EXEC(@s); END'); $e17 = $script:QErr
EvdQ "DBM-017" "sys 스키마·시스템 테이블 권한 (전 DB db:object:grantee:permission, 고정 역할·dbo·guest·## 제외)" ($sysTbl -join "`n")
if ($sysTbl.Count -gt 0) { MC "017" "시스템 테이블/뷰 접근 권한 $($sysTbl.Count)건: $(($sysTbl | Select-Object -First 5) -join ', ') - 적정성 수동 확인" }
else { Pass "017" "일반 사용자의 시스템 테이블 직접 접근 권한 없음" }

# ── DBM-019: 이전 비밀번호 재사용 ──────────────────────────────
# 평가기준: 1) 계정별 Windows password policy(CHECK_POLICY) 적용 2) Enforce password history(PasswordHistorySize) 0 이면 취약
Item-Begin 'DBM-019'
if ($script:Remote -and $noPolList.Count -gt 0) {
    EvdQ "DBM-019" "CHECK_POLICY=OFF 활성 SQL 로그인 (Enforce password history 는 원격/관리형이라 미확인)" ($noPolList -join ', ')
    Fail "019" "CHECK_POLICY=OFF 로그인 $($noPolList.Count)개(정책 미적용): $(($noPolList | Select-Object -First 5) -join ', ') (OS 비밀번호 이력 정책은 원격/관리형이라 미확인)$rsvNote"
} elseif (Os-GateE "019" "Enforce password history(PasswordHistorySize)는 서버 OS 정책") {
} else {
    $hist19 = Get-SecPol "PasswordHistorySize"
    EvdQ "DBM-019" "PasswordHistorySize / CHECK_POLICY=OFF 활성 SQL 로그인" "$hist19 / $($noPolList -join ', ')"
    if ($null -eq $hist19) { NC "019" "Enforce password history 확인 실패(secedit, 관리자 권한 필요) - 수동 확인" }
    elseif ([int]$hist19 -eq 0) { Fail "019" "Enforce password history=0 (이전 비밀번호 재사용 가능)" }
    elseif ($noPolList.Count -gt 0) { Fail "019" "PasswordHistorySize=$hist19 이나 CHECK_POLICY=OFF 로그인 $($noPolList.Count)개(정책 미적용): $(($noPolList | Select-Object -First 5) -join ', ') - 서비스 운영 계정은 평가 제외 가능" }
    else { Pass "019" "Enforce password history=$hist19, 활성 SQL 로그인 모두 CHECK_POLICY 적용 (도메인 GPO 적용 서버는 gpresult 확인)" }
}

# ── DBM-020: 사용자별 계정 분리 ─────────────────────────────────
Item-Begin 'DBM-020'
EvdQ "DBM-020" "로그인 목록 (DBM-003 동일)" ($logins -join "`n")
MC "020" "공용 계정(shared account) 사용 여부 수동 확인 (로그인 $($logins.Count)개, 증적 참조)$rsvNote"

# ── DBM-021: 불필요한 ODBC/OLE-DB 데이터 소스 ─────────────────
# 평가기준: ODBC 데이터 원본 관리자 User/System DSN 중 불필요한 데이터 소스 (Linked Server 는 참고 증적)
Item-Begin 'DBM-021'
$linkedSrv = Run-Q "SELECT name+' ('+provider+')' AS linked_server FROM sys.servers WHERE is_linked=1"
EvdQ "DBM-021" "참고: 연결 서버(Linked Server)" ($linkedSrv -join "`n")
if (Os-GateE "021" "ODBC 데이터 원본(DSN)은 서버 OS 레지스트리 (참고: 연결 서버 $(@($linkedSrv).Count)개)") { } else {
    $dsn = @()
    foreach ($k in @('HKLM:\SOFTWARE\ODBC\ODBC.INI\ODBC Data Sources','HKLM:\SOFTWARE\WOW6432Node\ODBC\ODBC.INI\ODBC Data Sources','HKCU:\SOFTWARE\ODBC\ODBC.INI\ODBC Data Sources')) {
        $p = Get-ItemProperty $k -EA SilentlyContinue
        if ($p) { $p.PSObject.Properties | Where-Object { @('PSPath','PSParentPath','PSChildName','PSDrive','PSProvider') -notcontains $_.Name } | ForEach-Object { $dsn += "$($_.Name)[$($_.Value)]" } }
    }
    EvdQ "DBM-021" "ODBC DSN (System/User, 32/64bit)" ($dsn -join "`n")
    if ($dsn.Count -gt 0) { MC "021" "ODBC 데이터 소스 $($dsn.Count)개: $(($dsn | Select-Object -First 6) -join ', ') - 업무상 불필요 항목 확인 (존재 시 취약)" }
    else { Pass "021" "등록된 ODBC 데이터 소스(DSN) 없음" }
}

# ── DBM-022: 설정 파일 및 중요 파일 접근 권한 ──────────────────
# 평가기준: *.mdf·*.ndf 등 주요 파일에 관리자·SYSTEM·소유자·SQL 서비스 계정 외 읽기/쓰기 권한 부여 시 취약
Item-Begin 'DBM-022'
$files22 = @(Run-Q "SELECT RTRIM(physical_name) AS physical_name FROM sys.master_files UNION SELECT CAST(SERVERPROPERTY('ErrorLogFileName') AS nvarchar(260))" | ForEach-Object { "$_".Trim() } | Where-Object { $_ })
$svcRows = @(Run-Q "SELECT servicename + '|' + service_account AS svc FROM sys.dm_server_services" -Opt)
$svc22 = ($svcRows | Where-Object { $_ -match '^SQL Server \(' } | Select-Object -First 1)
$svc22 = if ($svc22) { ($svc22 -split '\|',2)[1].Trim() } else { $null }
if (Os-GateE "022" "DB·로그 파일 ACL 은 서버 파일시스템 (관리형은 서비스가 관리)") { } else {
    $okId = '^(BUILTIN\\Administrators|NT AUTHORITY\\SYSTEM|CREATOR OWNER|OWNER RIGHTS|NT SERVICE\\MSSQL.*|NT SERVICE\\SQLAgent.*|NT SERVICE\\SQLSERVERAGENT' + $(if ($svc22) { '|' + [regex]::Escape($svc22) }) + $(if ($env:MSSQL_ADMIN_GROUPS) { '|' + $env:MSSQL_ADMIN_GROUPS }) + ')$'
    $bad22 = @(); $seen22 = 0; $acl22 = @()
    foreach ($f in $files22) {
        if (-not (Test-Path -LiteralPath $f)) { continue }; $seen22++
        $acl = Get-Acl -LiteralPath $f -EA SilentlyContinue; if (-not $acl) { continue }
        $acl22 += "$f : " + (($acl.Access | ForEach-Object { "$($_.IdentityReference) $($_.AccessControlType) $($_.FileSystemRights)" }) -join '; ')
        $bad22 += @($acl.Access | Where-Object { "$($_.AccessControlType)" -eq 'Allow' -and "$($_.IdentityReference)" -notmatch $okId -and "$($_.FileSystemRights)" -match 'Read|Write|Modify|FullControl' } | ForEach-Object { "$f : $($_.IdentityReference) ($($_.FileSystemRights))" })
    }
    EvdQ "DBM-022" "sys.master_files + ErrorLog 파일별 ACL 전체 / 관리자·SYSTEM·서비스 계정($svc22) 외 허용 ACE" ((@($acl22) + '--- 위반 ACE ---' + @($bad22)) -join "`n")
    if ($files22.Count -eq 0) { NC "022" "DB 파일 경로 조회 결과 없음 - 수동 확인" }
    elseif ($seen22 -eq 0) { NC "022" "DB 파일 경로($($files22.Count)개)를 파일시스템에서 찾지 못함 - 해당 서버에서 icacls 확인" }
    elseif ($bad22.Count -gt 0) { Fail "022" "관리자 외 계정 읽기/쓰기 허용: $(($bad22 | Select-Object -First 3) -join '; ') (총 $($bad22.Count)건, 증적 참조)" }
    else { Pass "022" "DB·로그 파일 ${seen22}개 관리자·서비스 계정 외 권한 없음" }
}

# ── DBM-024: WITH GRANT OPTION ──────────────────────────────────
Item-Begin 'DBM-024'
$grantOpt = @(Run-Q 'SET NOCOUNT ON; DECLARE @s nvarchar(max)=N''''; SELECT @s=@s+N''SELECT N''''''+REPLACE(name,'''''''','''''''''''')+N'':''''+dp.name COLLATE DATABASE_DEFAULT+N'''':''''+p.class_desc COLLATE DATABASE_DEFAULT+N'''':''''+ISNULL(OBJECT_NAME(p.major_id,''+CAST(database_id AS nvarchar(10))+N''),N''''-'''') COLLATE DATABASE_DEFAULT+N'''':''''+p.permission_name COLLATE DATABASE_DEFAULT FROM ''+QUOTENAME(name)+N''.sys.database_permissions p JOIN ''+QUOTENAME(name)+N''.sys.database_principals dp ON dp.principal_id=p.grantee_principal_id WHERE p.state=''''W'''' UNION ALL '' FROM sys.databases WHERE state_desc=''ONLINE'' AND HAS_DBACCESS(name)=1; IF LEN(@s)>0 BEGIN SET @s=LEFT(@s,LEN(@s)-10); EXEC(@s); END'); $e24 = $script:QErr
EvdQ "DBM-024" "WITH GRANT OPTION(state=W) 권한 (전 DB db:grantee:class:object:permission)" ($grantOpt -join "`n")
if ($grantOpt.Count -gt 0) { MC "024" "WITH GRANT OPTION $($grantOpt.Count)건: $(($grantOpt | Select-Object -First 5) -join ', ') - 업무상 필요 여부 확인(불필요 시 취약)" }
else { Pass "024" "WITH GRANT OPTION 설정 권한 없음" }

# ── EoS 표 (DBM-025 / D-25 공용): 제품 연장 지원 종료일 ──────────
$eosDb = @{ '2005'='2016-04-12'; '2008'='2019-07-09'; '2012'='2022-07-12'; '2014'='2024-07-09'; '2016'='2026-07-14'; '2017'='2027-10-12'; '2019'='2030-01-08'; '2022'='2033-01-11'; '2025'='2036-01-06' }
# ── DBM-025: EoS ────────────────────────────────────────────────
Item-Begin 'DBM-025'
EvdQ "DBM-025" "@@VERSION / Edition / 지원 종료일 표(내장)" "$ver / $(Run-Q "SELECT CAST(SERVERPROPERTY('Edition') AS varchar(100)) AS edition" -Opt) / $($eosDb[$verNum])"
if ($eosDb.ContainsKey($verNum) -and (Get-Date) -gt [datetime]$eosDb[$verNum]) {
    if ($script:Managed) { MC "025" "커뮤니티 기준 SQL Server $verNum 연장 지원 종료($($eosDb[$verNum])) 경과 - 관리형($($script:ManagedLabel))은 벤더 지원 일정을 콘솔에서 확인" }
    else { Fail "025" "SQL Server $verNum 연장 지원 종료($($eosDb[$verNum])) 경과 - 보안 패치 미제공 (점검일 $(Get-Date -Format 'yyyy-MM-dd'))" }
}
else { MC "025" "SQL Server $verNum$(if ($eosDb.ContainsKey($verNum)) { " 연장 지원 종료 예정 $($eosDb[$verNum])" }) - 최신 CU·보안 업데이트 적용 여부 수동 확인 (DBM-016 참조)" }

# ── DBM-028: 불필요한 DB Object 제거 ────────────────────────────
# xp_cmdshell, Ole Automation 등
Item-Begin 'DBM-028'
$xp = Run-Q "SELECT value_in_use AS xp_cmdshell FROM sys.configurations WHERE name='xp_cmdshell'"
$ole = Run-Q "SELECT value_in_use AS ole_automation FROM sys.configurations WHERE name='Ole Automation Procedures'"
$objs = Run-Q "SELECT TOP 20 s.name+'.'+o.name+' ('+o.type_desc COLLATE DATABASE_DEFAULT+')' AS user_object FROM sys.objects o JOIN sys.schemas s ON o.schema_id=s.schema_id WHERE o.is_ms_shipped=0 ORDER BY o.create_date DESC"
EvdQ "DBM-028" "xp_cmdshell=$($xp -join '') / Ole Automation=$($ole -join '') / 사용자 생성 Object 목록(최근 20)" ($objs -join "`n")
# 평가기준: 인가되지 않은 Object/Owner 존재 여부(인터뷰) — xp_cmdshell 은 DBM-035 항목
MC "028" "사용자 생성 Object/Owner 인가 여부 인터뷰 확인 (현재 DB 사용자 Object 최근 20건 증적 참조; xp_cmdshell/Ole Automation(=$($ole -join ''))은 DBM-035 등에서 판정)"

# ── DBM-029: 자원 사용 제한 ─────────────────────────────────────
Item-Begin 'DBM-029'
$res29 = Run-Q "SELECT name+'='+CAST(value_in_use AS varchar) AS config FROM sys.configurations WHERE name IN ('max server memory (MB)','max degree of parallelism','user connections','query governor cost limit')"
$rg29 = Run-Q "SELECT CAST(is_enabled AS varchar) AS resource_governor FROM sys.resource_governor_configuration" -Opt
EvdQ "DBM-029" "sys.configurations 자원 설정 / Resource Governor" "$($res29 -join ', ') / RG enabled=$($rg29 -join '')"
MC "029" "최대 서버 메모리, CPU 제한 등 자원 사용 제한 수동 확인 ($($res29 -join ', '))"

# ── DBM-031: SA 계정 보안설정 ───────────────────────────────────
Item-Begin 'DBM-031'
$sa = Run-Q "SELECT CAST(is_disabled AS varchar(1))+'|'+name AS sa_status FROM sys.server_principals WHERE sid=0x01"
$saLine = $sa | Select-Object -First 1
$saPol = (Run-Q "SELECT CAST(is_policy_checked AS varchar) AS sa_policy FROM sys.sql_logins WHERE sid=0x01" | Select-Object -First 1)
EvdQ "DBM-031" "SA 계정 상태(is_disabled|name) / sa is_policy_checked" "$saLine / $saPol"
# 평가기준: sa 비활성 → 양호 / 활성 시 Windows password policy 적용 여부로 판정
if ($saLine -match "^1") { Pass "031" "SA 계정 비활성화됨 (is_disabled=1)" }
elseif ($saLine -match "^0" -and "$saPol".Trim() -eq "1") { Pass "031" "SA 계정 활성, 비밀번호 정책 적용됨 (is_policy_checked=1) - 복잡도 정책은 증적 확인" }
elseif ($saLine -match "^0") { Fail "031" "SA 계정 활성, 비밀번호 정책 미적용 (is_policy_checked=$saPol)" }
else { NC "031" "SA 계정(sid=0x01) 조회 결과 없음 - 수동 확인" }

# ── DBM-032: 통신구간 암호화 (SQL Server TLS) ───────────────────
# 평가기준: 접속 시 통신 구간 암호화(Force Encryption) — 서버 레지스트리 ForceEncryption(DB 에서 xp_instance_regread 로 조회, 원격에서도 가능) + 현재 세션 encrypt_option
Item-Begin 'DBM-032'
$enc32 = "$(Run-Q "SELECT DISTINCT CAST(encrypt_option AS varchar(10)) AS encrypt_option FROM sys.dm_exec_connections WHERE session_id=@@SPID" | Select-Object -First 1)".Trim()
$force32 = "$(Run-Q "DECLARE @v int; EXEC master.dbo.xp_instance_regread N'HKEY_LOCAL_MACHINE', N'Software\Microsoft\Microsoft SQL Server\MSSQLServer\SuperSocketNetLib', N'ForceEncryption', @v OUTPUT; SELECT CAST(@v AS varchar(3)) AS force_encryption" -Opt | Select-Object -First 1)".Trim()
EvdQ "DBM-032" "현재 세션 encrypt_option / 서버 ForceEncryption(레지스트리, 관리형은 조회 불가 가능)" "$enc32 / $force32"
if ($force32 -eq '1') { Pass "032" "강제 암호화 설정됨 (ForceEncryption=1)" }
elseif ($enc32 -eq 'TRUE') { MC "032" "현재 연결 암호화됨(encrypt_option=TRUE) - 전체 연결 강제 암호화(ForceEncryption=$(if ($force32) { $force32 } else { '조회 불가' })$(if ($script:Managed) { '; 관리형은 파라미터 그룹 rds.force_ssl / 서버 TLS 최소 버전' })) 여부 수동 확인" }
elseif (-not $enc32) { NC "032" "encrypt_option 조회 결과 없음 - 수동 확인" }
else { Fail "032" "연결 암호화 미확인 (encrypt_option=$enc32, ForceEncryption=$(if ($force32) { $force32 } else { '조회 불가' })) - 평문 접속 허용" }

# ── DBM-033: 이중화 비밀번호 평문 노출 (Always On / Mirroring) ──
Item-Begin 'DBM-033'
$ag33 = Q-Int "SELECT COUNT(*) AS ag_count FROM sys.availability_groups"
$mir33 = Q-Int "SELECT COUNT(*) AS mirror_count FROM sys.database_mirroring WHERE mirroring_state IS NOT NULL"
EvdQ "DBM-033" "AG count / Mirroring count" "$ag33 / $mir33"
if (($ag33 -gt 0) -or ($mir33 -gt 0)) { MC "033" "이중화 구성됨 (AG=$ag33, Mirror=$mir33) - 암호화 수동 확인" }
elseif ($script:ItemErr.Count -gt 0) { NC "033" "이중화(Always On/Mirroring) 구성 조회 실패 - 수동 확인 (AG=$ag33, Mirror=$mir33)" }
else { NA "033" "Always On/Mirroring 미구성" }

# ── DBM-034: DBMS 서비스 구동 권한 ─────────────────────────────
# 연결한 인스턴스의 엔진 서비스 계정을 DB(sys.dm_server_services)에서 우선 조회 → 부속 서비스(Launchpad·FDLauncher·Agent 등)와 구분
Item-Begin 'DBM-034'
if ($script:Managed) { [void](Os-GateE "034" "SQL Server 서비스 계정은 서버 OS 설정") } else {
    $svcUser = $svc22
    if (-not $svcUser -and -not $script:Remote) {   # DB 조회 실패 시: 접속한 인스턴스 이름으로 엔진 서비스만 정확히 선택(MSSQLSERVER 또는 MSSQL$<인스턴스>)
        $inst = "$(Run-Q "SELECT CAST(SERVERPROPERTY('InstanceName') AS varchar(128)) AS instance_name" -Opt | Select-Object -First 1)".Trim()
        $svcName = if ($inst -and $inst -ne 'NULL') { "MSSQL`$$inst" } else { 'MSSQLSERVER' }
        $w = Get-WmiObject Win32_Service -Filter "Name='$svcName'" -EA SilentlyContinue | Select-Object -First 1
        if ($w) { $svcUser = $w.StartName }
        EvdQ "DBM-034" "WMI Win32_Service Name='$svcName' (Name,StartName,State)" "$(if ($w) { "$($w.Name) | $($w.StartName) | $($w.State)" } else { '(서비스 없음)' })"
    }
    EvdQ "DBM-034" "sys.dm_server_services (서비스명|계정) / 선택된 엔진 서비스 계정" "$($svcRows -join "`n") / $svcUser"
    if ($svcUser) {
        if ($svcUser -match "LocalSystem|NT AUTHORITY\\SYSTEM") {
            Fail "034" "SQL Server 서비스 계정: $svcUser (전체 권한 - 전용 서비스 계정 권고)"
        } elseif ($svcUser -match "NT Service\\|NetworkService|LocalService") {
            Pass "034" "SQL Server 서비스 계정: $svcUser (관리 서비스 계정)"
        } else {
            Pass "034" "SQL Server 서비스 계정: $svcUser (전용 계정)"
        }
    } else { NC "034" "SQL Server 엔진 서비스 계정을 조회하지 못함(sys.dm_server_services 권한 없음, 인스턴스 서비스 미발견) - 수동 확인" }
}

# ── DBM-035: xp_cmdshell 비활성화 ───────────────────────────────
Item-Begin 'DBM-035'
$xp2 = Run-Q "SELECT value_in_use AS xp_cmdshell FROM sys.configurations WHERE name='xp_cmdshell'"
EvdQ "DBM-035" "xp_cmdshell value_in_use" ($xp2 -join "`n")
$xpV2 = "$($xp2 | Select-Object -First 1)".Trim()
if ($xpV2 -notmatch '^[01]$') { NC "035" "xp_cmdshell 설정 조회 실패 - 수동 확인" }
elseif ($xpV2 -eq '0') { Pass "035" "xp_cmdshell 비활성화됨 (=0)" }
else { Fail "035" "xp_cmdshell 활성화됨 (=1) - 보안 위험" }

# ── DBM-036: Registry Procedure 접근 권한 ──────────────────────
# 평가기준: 제한 목록 7종이 DBA 외 guest/public 에 부여되면 취약 (xp_reg* 는 sys.objects 가 아닌 sys.all_objects 에만 존재)
Item-Begin 'DBM-036'
$n36 = Q-Int "SELECT COUNT(*) AS xp_reg_count FROM master.sys.all_objects WHERE type='X' AND name LIKE 'xp_reg%'"
$regPub = @(Run-Q 'SET NOCOUNT ON; SELECT o.name+'':''+dp.name+'':''+p.state_desc COLLATE DATABASE_DEFAULT FROM master.sys.database_permissions p JOIN master.sys.all_objects o ON o.object_id=p.major_id JOIN master.sys.database_principals dp ON dp.principal_id=p.grantee_principal_id WHERE p.class=1 AND p.type=''EX'' AND p.state IN (''G'',''W'') AND dp.name IN (''public'',''guest'') AND o.name IN (''xp_regaddmultistring'',''xp_regdeletekey'',''xp_regdeletevalue'',''xp_regenumvalues'',''xp_regread'',''xp_regremovemultistring'',''xp_regwrite'')')
EvdQ "DBM-036" "레지스트리 확장 프로시저 수 / public·guest 부여" "$n36 / $($regPub -join ', ')"
if ($null -eq $n36) { NC "036" "레지스트리 확장 프로시저 조회 실패 - 수동 확인" }
elseif ($regPub.Count -gt 0) { Fail "036" "레지스트리 확장 프로시저 public/guest 부여: $($regPub -join ', ')" }
else { Pass "036" "제한 대상 레지스트리 확장 프로시저 public/guest 부여 없음" }

# N-A 항목 (타 DBMS 전용)
foreach ($code in @("012","014")) {
    Item-Begin "DBM-$code"; NA $code "MSSQL 해당 없음 (Oracle 전용 항목)"
}
Item-Begin 'DBM-026'; NA "026" "MSSQL 해당 없음 (Unix umask 개념 미적용)"
Item-Begin 'DBM-030'; NA "030" "MSSQL 해당 없음 (Oracle/Tibero AUD$ 전용 항목)"


# ════════════════════════════════════════════════════════════════
# 주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드(2026) — DBMS D-01 ~ D-26 (MSSQL)
#   가이드 점검 대상에 MSSQL 이 없는 항목은 N-A (D-05·07·09·12·14·15·17~22), D-10·13 은 Windows OS 대상
# ════════════════════════════════════════════════════════════════
if ($script:KMODE -ne 'ef') {
function RunQA([string]$q) { Run-Q $q | Where-Object { $_ } }   # 결과 줄만 (실패 시 0건, $script:QErr=true)
$kna = "가이드 점검 대상 제품 아님 (MSSQL)"
foreach ($c in 'D-05','D-07','D-09','D-12','D-14','D-15','D-17','D-18','D-19','D-20','D-21','D-22') { Item-Begin $c; KPut $c 'N-A' $kna }
Item-Begin 'D-01'
$lg = @(RunQA "SELECT name COLLATE DATABASE_DEFAULT + '|' + type COLLATE DATABASE_DEFAULT + '|' + CAST(is_disabled AS varchar(1)) AS login_info FROM sys.server_principals WHERE type IN ('S','U','G') AND name NOT LIKE '##%' AND name NOT LIKE 'NT SERVICE\%' AND name NOT LIKE 'NT AUTHORITY\%' AND name NOT IN ($rsvSql) ORDER BY name")
$lgErr = if ($script:QErr) { ($script:ItemErr | Select-Object -First 1) } else { $null }
$sl = @(RunQA "SELECT name COLLATE DATABASE_DEFAULT + '|' + CAST(is_disabled AS varchar(1)) + '|' + CAST(is_policy_checked AS varchar(1)) + '|' + CAST(is_expiration_checked AS varchar(1)) + '|' + ISNULL(CONVERT(varchar(6), password_hash, 1),'-') + '|' + CAST(principal_id AS varchar(10)) AS sql_login FROM sys.sql_logins WHERE name NOT LIKE '##%' AND name NOT IN ($rsvSql) ORDER BY name")
$slErr = if ($script:QErr) { ($script:ItemErr | Select-Object -Last 1) } else { $null }
EvdQ "D-01" "로그인 (이름|유형 S=SQL U=Windows G=그룹|비활성)" ($lg -join "`n")
EvdQ "D-01" "SQL 로그인 (이름|비활성|암호정책|만료|해시접두(알고리즘)|principal_id)" ($sl -join "`n")
$sa = $sl | Where-Object { ($_ -split '\|')[5] -eq '1' } | Select-Object -First 1
$saName = if ($sa) { ($sa -split '\|')[0] } else { 'sa' }; $saOff = $sa -and ($sa -split '\|')[1] -eq '1'

# D-01 기본 계정(sa) 초기 비밀번호 변경 또는 잠금
$wk = @(RunQA "SELECT name FROM sys.sql_logins WHERE principal_id = 1 AND (PWDCOMPARE('', password_hash) = 1 OR PWDCOMPARE(name, password_hash) = 1 OR PWDCOMPARE('password', password_hash) = 1 OR PWDCOMPARE('sa', password_hash) = 1)")
if ($script:CtlPerm -ne 1) { Carry "CONTROL SERVER 권한 없음 - password_hash 조회 불가로 빈/기본 비밀번호 검사 불가" }
EvdQ "D-01" "sa 빈·기본 비밀번호 일치 여부 (PWDCOMPARE, 값 비공개)" "$(if ($wk.Count) { '일치' } else { '불일치' })"
if (-not $sa) { KPut 'D-01' '점검불가' '기본 관리자(sa) SQL 로그인 조회 결과 없음 - 비밀번호 변경·비활성 확인' }
elseif ($saOff) { KPut 'D-01' '양호' "기본 관리자 계정($saName) 비활성(잠금)" }
elseif ($wk.Count) { KPut 'D-01' '취약' "기본 관리자 계정($saName) 비밀번호가 빈 값 또는 기본값(계정명·password)과 일치" }
else { KPut 'D-01' '양호' "기본 관리자 계정($saName) 비밀번호 변경됨 (빈 값·기본값 불일치)$(if ($saName -eq 'sa') { ' - 이름 변경 권고' })" }

# D-02 불필요 계정
Item-Begin 'D-02'; Carry $lgErr
$act = @($lg | Where-Object { ($_ -split '\|')[2] -eq '0' } | ForEach-Object { ($_ -split '\|')[0] })
$tst = @($act | Where-Object { $_ -match '^(test|guest|demo|temp|tmp|sample|user\d*)[0-9_]*$' })   # 끝을 고정해 userdb·tempmon 같은 정상 로그인 제외
EvdQ "D-02" "활성 로그인" ($act -join ', ')
if ($tst.Count) { KPut 'D-02' '취약' "테스트성 로그인 활성: $($tst -join ', ')" } else { KPut 'D-02' '수동확인' "활성 로그인: $($act -join ', ') - 인가되지 않은 계정·퇴직자·미사용 계정 여부 확인 (없으면 양호)$rsvNote" }

# D-03 비밀번호 사용 기간 및 복잡도 (SQL 로그인 CHECK_POLICY·CHECK_EXPIRATION + OS 암호 정책)
Item-Begin 'D-03'; Carry $slErr
$np = @($sl | Where-Object { $p = $_ -split '\|'; $p[1] -eq '0' -and ($p[2] -ne '1' -or $p[3] -ne '1') } | ForEach-Object { $p = $_ -split '\|'; "$($p[0])(정책=$($p[2]),만료=$($p[3]))" })
if ($script:Remote -and $np.Count) {
    KPut 'D-03' '취약' "비밀번호 정책 미흡: 암호 정책·만료 강제 미적용 SQL 로그인: $($np -join ', ') (OS 암호 정책은 원격/관리형이라 미확인)"
} elseif (Os-GateD 'D-03' 'OS 암호 정책(최대 사용 기간·복잡성, secedit)은 서버 OS 정책') {
} else {
    $mx = Get-SecPol 'MaximumPasswordAge'; $cx = Get-SecPol 'PasswordComplexity'
    EvdQ "D-03" "OS 암호 정책 최대 사용 기간 / 복잡성 (SQL 로그인 CHECK_POLICY 가 따름)" "$mx / $cx"
    $b3 = @(); if ($np.Count) { $b3 += "암호 정책·만료 강제 미적용 SQL 로그인: $($np -join ', ')" }
    if ($null -ne $mx -and ([int]$mx -le 0 -or [int]$mx -gt 90)) { $b3 += "OS 최대 암호 사용 기간 $mx(90일 이하 필요)" }
    if ($null -ne $cx -and "$cx" -ne '1') { $b3 += 'OS 암호 복잡성 사용 안 함' }
    if ($b3.Count) { KPut 'D-03' '취약' "비밀번호 정책 미흡: $($b3 -join ' / ')" }
    elseif ($null -eq $mx) { KPut 'D-03' '점검불가' "SQL 로그인 암호 정책·만료 강제 적용, OS 암호 정책(secedit) 조회 불가 - 관리자 권한으로 최대 사용 기간·복잡성 확인" }
    else { KPut 'D-03' '양호' "SQL 로그인 암호 정책·만료 강제 적용, OS 최대 사용 기간 ${mx}일·복잡성 사용" }
}

# D-04 관리자 권한(sysadmin)은 필요한 계정에만
Item-Begin 'D-04'
$sy = @(RunQA "SELECT m.name AS sysadmin_member FROM sys.server_role_members rm JOIN sys.server_principals r ON r.principal_id = rm.role_principal_id JOIN sys.server_principals m ON m.principal_id = rm.member_principal_id WHERE r.name = 'sysadmin'")
$syErr = $script:QErr
EvdQ "D-04" "sysadmin 구성원" ($sy -join "`n")
$syx = @(Strip-Rsv ($sy | Where-Object { $_ -ne $saName -and $_ -notmatch '^NT (SERVICE|AUTHORITY)\\' }))
if ($syErr) { KPut 'D-04' '점검불가' 'sysadmin 구성원 조회 실패' } elseif ($syx.Count) { KPut 'D-04' '수동확인' "sa·서비스 계정 외 sysadmin: $($syx -join ', ') - 관리자 권한 필요성 확인 (불필요 시 취약)$rsvNote" } else { KPut 'D-04' '양호' "sysadmin 이 sa·서비스 계정에만 부여: $($sy -join ', ')" }

# D-06 사용자별 계정 사용
Item-Begin 'D-06'; Carry $lgErr
KPut 'D-06' '수동확인' "활성 로그인: $($act -join ', ') - 사용자·응용프로그램별 개별 계정 사용 여부(공용 계정 사용 시 취약) 확인$rsvNote"

# D-08 안전한 암호화 알고리즘 (SQL 2012 이상 SHA-512 = 해시 0x0200, 0x0100 = SHA-1)
Item-Begin 'D-08'; Carry $slErr
$old = @($sl | Where-Object { ($_ -split '\|')[4] -eq '0x0100' } | ForEach-Object { ($_ -split '\|')[0] })
if ($script:CtlPerm -ne 1 -and $sl.Count) { Carry "CONTROL SERVER 권한 없음 - password_hash 를 볼 수 없어 해시 알고리즘 확인 불가" }
if (-not $sl.Count -and -not $slErr) { KPut 'D-08' '양호' 'SQL 로그인 없음 (Windows 인증만 사용)' } elseif ($old.Count) { KPut 'D-08' '취약' "SHA-1(0x0100) 해시 비밀번호 로그인: $($old -join ', ') - 비밀번호 재설정 필요" } else { KPut 'D-08' '양호' "SQL 로그인 비밀번호 SHA-512(0x0200) 해시 ($($sl.Count)개)" }

# D-10 원격 접속 제한 (Windows 방화벽에서 DB 포트 접근 IP 지정)
Item-Begin 'D-10'
if (-not (Os-GateD 'D-10' 'Windows 방화벽 규칙은 서버 OS 설정 (관리형은 보안그룹·방화벽 규칙으로 통제)')) {
    $port10 = Get-DbPort
    $fw10 = Get-FwInfo $port10
    EvdQ "D-10" "방화벽 프로필 / DB 포트($port10) 인바운드 허용 규칙 (규칙 | 원격 주소 | 프로필마스크)" "$(($fw10.Profiles | ForEach-Object { "$($_[0])=$($_[1])" }) -join ', ')`n$(($fw10.Rules | ForEach-Object { "$($_[0]) | $($_[1]) | $($_[2])" }) -join "`n")$(if ($fw10.Err) { "`n[COM 오류] $($fw10.Err)" })"
    $act10 = @($fw10.Rules | Where-Object { ($_[2] -band $fw10.EnabledMask) -ne 0 })
    $any10 = @($act10 | Where-Object { $_[1] -match '(^|,)(\*|Any)(,|$)' -or $_[1] -match '0\.0\.0\.0/0' } | ForEach-Object { $_[0] })
    $off10 = @($fw10.Profiles | Where-Object { -not $_[1] } | ForEach-Object { $_[0] })
    if ($fw10.Err) { KPut 'D-10' '점검불가' "Windows 방화벽 정보를 읽지 못함($($fw10.Err)) - 네트워크 장비·보안그룹 확인" }
    elseif ($any10.Count) { KPut 'D-10' '취약' "모든 IP 에서 DB 포트($port10) 접속 허용 방화벽 규칙(활성 프로필): $($any10 -join ', ')" }
    elseif ($off10.Count) { KPut 'D-10' '수동확인' "Windows 방화벽 비활성 프로필: $($off10 -join ',') - 해당 프로필에서 규칙이 적용되지 않음. 네트워크 장비·보안그룹 등에서 지정 IP 접근 제한 여부 확인" }
    elseif ($act10.Count) { KPut 'D-10' '양호' "DB 포트($port10) 방화벽 규칙이 지정 IP 로 제한 ($($act10.Count)개)" }
    else { KPut 'D-10' '수동확인' "SQL Server 인바운드 방화벽 규칙 미발견(포트 $port10) - 네트워크 장비·보안그룹 등에서 지정 IP 접근 제한 여부 확인" }
}

# D-11 시스템 테이블 접근 제한 (PUBLIC·GUEST 권한 - 설치 기본 부여분 제외)
Item-Begin 'D-11'
$dflt = "'trace_xe_action_map','trace_xe_event_map','spt_fallback_db','spt_fallback_dev','spt_fallback_usg','spt_monitor'"
$pg = @(RunQA "SELECT dp.name COLLATE DATABASE_DEFAULT + ':' + o.name COLLATE DATABASE_DEFAULT + ':' + p.permission_name COLLATE DATABASE_DEFAULT AS sys_perm FROM master.sys.database_permissions p JOIN master.sys.all_objects o ON o.object_id = p.major_id JOIN master.sys.database_principals dp ON dp.principal_id = p.grantee_principal_id WHERE p.class = 1 AND dp.name IN ('public','guest') AND p.state IN ('G','W') AND o.type IN ('S','U') AND o.name NOT IN ($dflt)")
$pgErr = $script:QErr
EvdQ "D-11" "master 시스템 테이블 PUBLIC·GUEST 권한 (설치 기본 6개 제외)" ($pg -join "`n")
if ($pgErr) { KPut 'D-11' '점검불가' '시스템 테이블 권한 조회 실패 - PUBLIC·GUEST 권한 확인' } elseif ($pg.Count) { KPut 'D-11' '취약' "PUBLIC·GUEST 에 시스템 테이블 권한 부여: $($pg -join ', ')" } else { KPut 'D-11' '양호' 'PUBLIC·GUEST 에 추가 부여된 시스템 테이블 권한 없음 (설치 기본 권한 제외)' }

# D-13 불필요한 ODBC/OLE-DB 데이터 소스 (Windows OS)
Item-Begin 'D-13'
if (-not (Os-GateD 'D-13' 'ODBC 데이터 원본(DSN)은 서버 OS 레지스트리')) {
    $dsn = @(); foreach ($k in 'HKLM:\SOFTWARE\ODBC\ODBC.INI\ODBC Data Sources','HKLM:\SOFTWARE\WOW6432Node\ODBC\ODBC.INI\ODBC Data Sources') { if (Test-Path $k) { $dsn += @((Get-Item $k).GetValueNames()) } }
    EvdQ "D-13" "시스템 DSN (HKLM ODBC.INI ODBC Data Sources, 32/64bit)" ($dsn -join "`n")
    if ($dsn.Count) { KPut 'D-13' '수동확인' "시스템 DSN $($dsn.Count)개: $($dsn -join ', ') - 사용하지 않는 데이터 소스 제거 여부 확인" } else { KPut 'D-13' '양호' '시스템 DSN 없음' }
}

# D-16 Windows 인증 모드 사용 (혼합 모드면 sa 비활성 또는 강력한 암호 정책)
Item-Begin 'D-16'; Carry $slErr
$iso = "$(Run-Q "SELECT CAST(SERVERPROPERTY('IsIntegratedSecurityOnly') AS varchar(1)) AS integrated_only" | Select-Object -First 1)".Trim()
$saPol = $sa -and ($sa -split '\|')[2] -eq '1'
EvdQ "D-16" "IsIntegratedSecurityOnly / sa 비활성 / sa 암호 정책" "$iso / $saOff / $saPol"
if ($iso -eq '1') { KPut 'D-16' '양호' 'Windows 인증 모드 사용' }
elseif (-not $iso) { KPut 'D-16' '점검불가' '인증 모드(IsIntegratedSecurityOnly) 조회 결과 없음' }
elseif ($saOff) { KPut 'D-16' '양호' "혼합 인증 모드, sa 비활성" }
elseif ($saPol) { KPut 'D-16' '양호' "혼합 인증 모드, sa 활성 - 암호 정책(CHECK_POLICY) 적용" }
else { KPut 'D-16' '취약' "혼합 인증 모드 사용, sa 활성이며 암호 정책(CHECK_POLICY) 미적용" }

# D-23 xp_cmdshell 사용 제한 (비활성, 또는 활성 시 public 실행 권한 없음 + 서비스 계정 sysadmin 아님)
Item-Begin 'D-23'
$xp = "$(Run-Q "SELECT CAST(value_in_use AS varchar(1)) AS xp_cmdshell FROM sys.configurations WHERE name = 'xp_cmdshell'" | Select-Object -First 1)".Trim()
$xpPub = @(RunQA "SELECT dp.name AS grantee FROM master.sys.database_permissions p JOIN master.sys.all_objects o ON o.object_id = p.major_id JOIN master.sys.database_principals dp ON dp.principal_id = p.grantee_principal_id WHERE o.name = 'xp_cmdshell' AND p.state IN ('G','W') AND dp.name IN ('public','guest')")
EvdQ "D-23" "xp_cmdshell value_in_use / public·guest 실행 권한" "$xp / $($xpPub -join ',')"
if ($xp -notmatch '^[01]$') { KPut 'D-23' '점검불가' 'xp_cmdshell 설정 조회 결과 없음' }
elseif ($xp -ne '1') { KPut 'D-23' '양호' 'xp_cmdshell 비활성' }
elseif ($xpPub.Count) { KPut 'D-23' '취약' "xp_cmdshell 활성 + public·guest 실행 권한: $($xpPub -join ', ')" }
else { KPut 'D-23' '수동확인' "xp_cmdshell 활성 (public 실행 권한 없음) - 응용프로그램 연동 서비스 계정의 sysadmin 권한 여부 확인 (sysadmin: $($sy -join ', '))" }

# D-24 Registry Procedure 권한 제한 (7종 확장 프로시저 public·guest 부여)
Item-Begin 'D-24'
$rp = @(RunQA "SELECT o.name COLLATE DATABASE_DEFAULT + ':' + dp.name COLLATE DATABASE_DEFAULT AS reg_perm FROM master.sys.database_permissions p JOIN master.sys.all_objects o ON o.object_id = p.major_id JOIN master.sys.database_principals dp ON dp.principal_id = p.grantee_principal_id WHERE p.class = 1 AND p.type = 'EX' AND p.state IN ('G','W') AND dp.name IN ('public','guest') AND o.name IN ('xp_regaddmultistring','xp_regdeletekey','xp_regdeletevalue','xp_regenumvalues','xp_regread','xp_regremovemultistring','xp_regwrite')")
$rpErr = $script:QErr
EvdQ "D-24" "레지스트리 확장 프로시저 public·guest 부여" ($rp -join "`n")
if ($rpErr) { KPut 'D-24' '점검불가' '레지스트리 확장 프로시저 권한 조회 실패' } elseif ($rp.Count) { KPut 'D-24' '취약' "DBA 외 public·guest 에 부여: $($rp -join ', ')" } else { KPut 'D-24' '양호' '제한 대상 레지스트리 확장 프로시저 public·guest 부여 없음' }

# D-25 주기적 보안 패치 (지원 종료 버전 = 취약, 관리형은 벤더 일정 확인)
Item-Begin 'D-25'
$pv = "$(Run-Q "SELECT CAST(SERVERPROPERTY('ProductVersion') AS varchar(30)) COLLATE DATABASE_DEFAULT + ' ' + ISNULL(CAST(SERVERPROPERTY('ProductUpdateLevel') AS varchar(20)), CAST(SERVERPROPERTY('ProductLevel') AS varchar(20))) AS product_version" | Select-Object -First 1)".Trim()
EvdQ "D-25" "@@VERSION / ProductVersion 업데이트 수준 / 지원 종료일 표(내장)" "$ver / $pv / $($eosDb[$verNum])"
if ($eosDb.ContainsKey($verNum) -and (Get-Date) -gt [datetime]$eosDb[$verNum]) {
    if ($script:Managed) { KPut 'D-25' '수동확인' "커뮤니티 기준 SQL Server $verNum 연장 지원 종료($($eosDb[$verNum])) 경과 - 관리형($($script:ManagedLabel))은 벤더 지원 일정을 콘솔에서 확인 ($pv)" }
    else { KPut 'D-25' '취약' "SQL Server $verNum 연장 지원 종료($($eosDb[$verNum])) - 보안 패치 미제공 ($pv)" }
}
else { KPut 'D-25' '수동확인' "SQL Server $verNum $pv$(if ($eosDb.ContainsKey($verNum)) { " (연장 지원 ~$($eosDb[$verNum]))" }) - 최신 CU·보안 업데이트 적용 여부 확인" }

# D-26 감사 기록 (로그인 감사 '실패한 로그인과 성공한 로그인 모두' = AuditLevel 3, 또는 서버 감사 + 로그인 감사 사양) — DBM-011 과 같은 기준
Item-Begin 'D-26'
$al = "$(Run-Q "DECLARE @v int; EXEC master.dbo.xp_instance_regread N'HKEY_LOCAL_MACHINE', N'Software\Microsoft\MSSQLServer\MSSQLServer', N'AuditLevel', @v OUTPUT; SELECT CAST(@v AS varchar(3)) AS audit_level" -Opt | Select-Object -First 1)".Trim()
$sau = @(RunQA "SELECT name FROM sys.server_audits WHERE is_state_enabled = 1")
$lsp = @(RunQA "SELECT s.name+': '+d.audit_action_name AS audit_spec FROM sys.server_audit_specifications s JOIN sys.server_audit_specification_details d ON s.server_specification_id=d.server_specification_id WHERE s.is_state_enabled=1 AND d.audit_action_name IN ('FAILED_LOGIN_GROUP','SUCCESSFUL_LOGIN_GROUP')")
EvdQ "D-26" "로그인 감사 AuditLevel(0 없음/1 성공/2 실패/3 모두) / 활성 서버 감사 / 로그인 감사 사양" "$al / $($sau -join ', ') / $($lsp -join ', ')"
if ($al -eq '3' -or ($sau.Count -and $lsp.Count)) { KPut 'D-26' '양호' "감사 설정: $(if ($al -eq '3') { '로그인 감사 성공·실패 모두 ' })$(if ($sau.Count) { "서버 감사 $($sau -join ', ') (로그인 감사 사양 $($lsp -join ', '))" }) - 감사 기록 정책(보관·백업) 수립 여부는 인터뷰" }
elseif ($sau.Count) { KPut 'D-26' '취약' "서버 감사 $($sau -join ', ') 활성이나 로그인 성공/실패 감사 사양 없음, 로그인 감사 수준=$(if ($al) { $al } else { 'N/A' }) - 가이드: 실패·성공 모두 감사" }
elseif (-not $al) { KPut 'D-26' '점검불가' "활성 서버 감사가 없고 로그인 감사 수준(AuditLevel, xp_instance_regread)도 조회하지 못해 점검 불가 - 로그인 감사 설정 수동 확인" }
else { KPut 'D-26' '취약' "로그인 감사 '$(switch ($al) { '0' {'없음'} '1' {'성공한 로그인만'} '2' {'실패한 로그인만'} default {"확인 불가($al)"} })', 활성 서버 감사 없음 - 가이드: 실패·성공 모두 감사" }
}

$total = $script:cntPass + $script:cntFail + $script:cntMC + $script:cntNC + $script:cntNA
Out-Line "# ================================================================"
Out-Line "# 점검 요약"
Out-Line "#   총 점검 항목: $total"
if ($total -gt 0) {
Out-Line "#   양호:         $($script:cntPass)  ($([math]::Round($script:cntPass/$total*100,1))%)"
Out-Line "#   취약:         $($script:cntFail)  ($([math]::Round($script:cntFail/$total*100,1))%)"
}
Out-Line "#   수동확인:     $($script:cntMC)"
Out-Line "#   점검불가:     $($script:cntNC)"
Out-Line "#   N-A:          $($script:cntNA)"
Out-Line "# ================================================================"
Out-Line "# 점검 완료: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Out-Line "# 증적 파일: $($script:EVD)"
Out-Line "# 결과 파일: $($script:OutFile)  ← 증적 파일과 함께 회수"
Finish
