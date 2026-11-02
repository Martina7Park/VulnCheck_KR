# ================================================================
# 웹서버/WAS(Windows) 보안 취약점 자동 점검 스크립트 v4.0
# ================================================================
#
# [용도]
#   전자금융기반시설·주요정보통신기반시설 Windows 웹서버 및 WAS 보안 점검.
#   기준: 전자금융기반시설 보안 취약점 평가기준 제2026-1호 [웹서버-WAS]
#   Unix/Linux 환경은 check_webwas.sh 사용.
#
# [대상 소프트웨어]
#   웹서버: IIS 7.5/8.5/10.0 (모든 사이트·응용 프로그램·가상 디렉터리의 web.config) / Apache(Windows) / Nginx(Windows) - 동시 설치 시 모두 점검
#   WAS:    Tomcat(Windows, 모든 인스턴스) / JEUS(Windows: 일부 항목만 자동, 나머지는 수동확인)
#
# [사전 조건]
#   - 관리자 권한 PowerShell 필요
#   - 실행 정책 변경: Set-ExecutionPolicy RemoteSigned -Scope Process -Force
#   - (선택) 환경변수로 대상 지정 가능:
#     $env:WEB_SRV     = "iis"    # iis | apache | nginx  (기본: 자동탐지)
#     $env:WAS_SRV     = "tomcat" # tomcat | jeus          (기본: 자동탐지)
#     $env:TOMCAT_HOME = "C:\...\Tomcat 10.1"              (기본: 자동탐지)
#
# [실행 방법]
#   run_webwas.bat (권장) 또는  powershell -ExecutionPolicy Bypass -File check_webwas.ps1 -Mode ef|mi|all [-OutFile 결과파일]
#   결과 파일은 스크립트가 UTF-8(BOM) 로 직접 저장한다 (cmd '>' 리다이렉트 불필요 - 한글 깨짐 방지).
#
# [산출물]
#   1) 결과 파일 — <스크립트 폴더>\<호스트명>_webwas.txt (표준출력에도 동일 내용 표시)
#      형식: WST-항목코드|결과|근거설명
#      결과: 양호 / 취약 / 점검불가 / 수동확인 / N-A  (점검불가 = 권한·설정 파일 부재·조회 오류로 점검 자체를 못 한 경우, 근거에 사유)
#   2) 증적 파일 — <스크립트 폴더>\<호스트명>_webwas_evidence.txt
#      점검 중 실행한 명령어·출력·판정 근거가 타임스탬프와 함께 기록됨
#
# ================================================================
param([string]$Mode = "", [string]$OutFile = "")   # ef=전자금융(WST) / mi=주요정보 2026 상세가이드(WEB-01~26) / all=둘 다 / OutFile=결과 파일(생략 시 <스크립트 폴더>\<호스트명>_webwas.txt)
$script:KMODE = "$Mode".ToLower()
if (-not $script:KMODE) {
    if ([Environment]::UserInteractive -and $Host.Name -eq 'ConsoleHost') {
        Write-Host "점검 기준을 선택하세요: 1) 전자금융기반시설(WST)  2) 주요정보통신기반시설 2026 상세가이드(WEB-01~WEB-26)  3) 둘 다"
        $sel = Read-Host "선택 [1/2/3] (Enter=3)"
        $script:KMODE = switch ("$sel".Trim()) { '1' { 'ef' } '2' { 'mi' } default { 'all' } }
    } else { $script:KMODE = 'all' }
}
$script:KMODE = switch ($script:KMODE) { '1' {'ef'} 'srv' {'ef'} '2' {'mi'} 'kisa' {'mi'} '3' {'all'} default { $script:KMODE } }
if (@('ef','mi','all') -notcontains $script:KMODE) { Write-Host "사용법: check_webwas.ps1 -Mode ef|mi|all [-OutFile 결과파일]"; exit 1 }
$ErrorActionPreference = "SilentlyContinue"
$ProgressPreference    = "SilentlyContinue"
try { [Console]::OutputEncoding = [Text.Encoding]::UTF8 } catch {}

$script:cntPass=0; $script:cntFail=0; $script:cntMC=0; $script:cntNA=0; $script:cntUnable=0

$script:ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$hn = $env:COMPUTERNAME
$script:OUT = if ($OutFile) { $OutFile } else { "$script:ScriptDir\${hn}_webwas.txt" }
$script:EVD = "$script:ScriptDir\${hn}_webwas_evidence.txt"

# PS 2.0(2008 R2 기본) 호환: Get-CimInstance 가 없으면 Get-WmiObject 로 대체
# (CmdletBinding 으로 -ErrorAction 공통 매개변수를 쓴다 - 'ErrorAction' 매개변수를 직접 선언하면 PS 2.0 에서 중복 선언 오류)
if (-not (Get-Command Get-CimInstance -EA SilentlyContinue)) {
    function Get-CimInstance {
        [CmdletBinding()]
        param([Parameter(Position=0)][Alias('Class')][string]$ClassName, [string]$Namespace = 'root\cimv2', [string]$Filter)
        $p = @{ Class = $ClassName; Namespace = $Namespace; ErrorAction = 'SilentlyContinue' }
        if ($Filter) { $p.Filter = $Filter }
        Get-WmiObject @p
    }
}

# ── 결과·증적 파일 쓰기: UTF-8(BOM) 로 직접 저장 (cmd '>' 의 OEM 코드페이지 변환 방지, PS 2.0~5.1 동일 동작) ──
$script:Utf8Bom = New-Object Text.UTF8Encoding($true)
$script:Utf8    = New-Object Text.UTF8Encoding($false)
function Append-Utf8([string]$Path,[string]$Text) { try { [IO.File]::AppendAllText($Path, $Text + "`r`n", $script:Utf8) } catch {} }
function Start-Utf8File([string]$Path,[string]$Text) { try { [IO.File]::WriteAllText($Path, $Text + "`r`n", $script:Utf8Bom) } catch {} }
function Out-Res([string]$Line) {   # 표준출력 + 결과 파일
    Write-Output $Line
    if ($script:OutStarted) { Append-Utf8 $script:OUT $Line } else { Start-Utf8File $script:OUT $Line; $script:OutStarted = $true }
}
function Limit-Lines([string]$Text,[int]$Max = 2000) {   # 증적이 너무 길면 상한 2000줄 + 생략 표시
    if ($null -eq $Text) { return '' }
    $ls = $Text -split "`r?`n"
    if ($ls.Count -gt $Max) { return ((($ls[0..($Max - 1)]) -join "`r`n") + "`r`n(이하 $($ls.Count - $Max)줄 생략)") }
    return $Text
}
# ── 헤더 메타데이터: IP / 실행 계정(관리자 여부) / 클라우드 ──
function Get-HostIPv4 {
    $ips = @()
    try { foreach ($c in @(Get-CimInstance Win32_NetworkAdapterConfiguration -Filter "IPEnabled=True" -EA SilentlyContinue)) { foreach ($a in @($c.IPAddress)) { if ("$a" -match '^\d{1,3}(\.\d{1,3}){3}$' -and "$a" -notmatch '^127\.') { $ips += "$a" } } } } catch {}
    if (-not $ips.Count) { try { foreach ($a in [Net.Dns]::GetHostAddresses($env:COMPUTERNAME)) { if ("$($a.AddressFamily)" -eq 'InterNetwork' -and "$a" -notmatch '^127\.') { $ips += "$a" } } } catch {} }
    $ips = @($ips | Select-Object -Unique)
    if ($ips.Count) { return ($ips -join ', ') } else { return '미확인' }
}
function Test-IsAdmin {
    try { $id = [Security.Principal.WindowsIdentity]::GetCurrent(); $pr = New-Object Security.Principal.WindowsPrincipal($id); return [bool]$pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) } catch { return $false }
}
function Invoke-Imds([string]$Url,[string]$Method = 'GET',$Headers = $null) {   # 클라우드 메타데이터(IMDS) 조회, 타임아웃 2초, 실패 시 $null (PS 2.0 은 Invoke-RestMethod 없음 → WebRequest)
    try {
        $req = [Net.WebRequest]::Create($Url)
        $req.Method = $Method; $req.Timeout = 2000; $req.ReadWriteTimeout = 2000
        try { $req.Proxy = $null } catch {}
        if ($Headers) { foreach ($k in $Headers.Keys) { $req.Headers.Add([string]$k, [string]$Headers[$k]) } }
        if ($Method -eq 'PUT') { $req.ContentLength = 0 }
        $resp = $req.GetResponse()
        $sr = New-Object IO.StreamReader($resp.GetResponseStream())
        $t = $sr.ReadToEnd(); $sr.Close(); $resp.Close()
        return $t
    } catch { return $null }
}
function Get-CloudInfo {   # $script:CloudKind(AWS/Azure/GCP/'') / $script:CloudSG(보안그룹 ID 목록) / $script:CloudLine(헤더 문자열)
    $script:CloudKind = ''; $script:CloudSG = ''; $script:CloudLine = '미확인'
    $b = 'http://169.254.169.254'
    try {
        # AWS: IMDSv2 토큰 먼저, 안 되면 v1
        $tok = Invoke-Imds "$b/latest/api/token" 'PUT' @{ 'X-aws-ec2-metadata-token-ttl-seconds' = '60' }
        $hd = $null; if ($tok) { $hd = @{ 'X-aws-ec2-metadata-token' = "$tok".Trim() } }
        $doc = Invoke-Imds "$b/latest/dynamic/instance-identity/document" 'GET' $hd
        if ($doc -and $doc -match '"instanceId"\s*:\s*"([^"]+)"') {
            $iid = $matches[1]; $rg = ''; if ($doc -match '"region"\s*:\s*"([^"]+)"') { $rg = $matches[1] }
            $sgs = @()
            $macs = Invoke-Imds "$b/latest/meta-data/network/interfaces/macs/" 'GET' $hd
            foreach ($m in @("$macs" -split "`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ })) {
                $s = Invoke-Imds "$b/latest/meta-data/network/interfaces/macs/$m/security-group-ids" 'GET' $hd
                foreach ($x in @("$s" -split "`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ })) { if ($sgs -notcontains $x) { $sgs += $x } }
            }
            $script:CloudKind = 'AWS'; $script:CloudSG = ($sgs -join ',')
            $script:CloudLine = "AWS (instance $iid, region $rg, SG: $(if ($sgs.Count) { $sgs -join ',' } else { '확인 불가' }))"
            return
        }
        # Azure
        $az = Invoke-Imds "$b/metadata/instance?api-version=2021-02-01" 'GET' @{ 'Metadata' = 'true' }
        if ($az -and $az -match '"vmId"\s*:\s*"([^"]+)"') {
            $vm = $matches[1]; $loc = ''; if ($az -match '"location"\s*:\s*"([^"]+)"') { $loc = $matches[1] }
            $script:CloudKind = 'Azure'
            $script:CloudLine = "Azure (instance $vm, region $loc, NSG: IMDS 미제공 - 포털에서 확인)"
            return
        }
        # GCP
        $gh = @{ 'Metadata-Flavor' = 'Google' }
        $gid = Invoke-Imds "$b/computeMetadata/v1/instance/id" 'GET' $gh
        if ($gid -and "$gid".Trim() -match '^\d+$') {
            $zn = "$(Invoke-Imds "$b/computeMetadata/v1/instance/zone" 'GET' $gh)".Trim(); if ($zn) { $zn = $zn.Substring($zn.LastIndexOf('/') + 1) }
            $tg = "$(Invoke-Imds "$b/computeMetadata/v1/instance/tags" 'GET' $gh)" -replace '[\[\]"\s]', ''
            $script:CloudKind = 'GCP'; $script:CloudSG = $tg
            $script:CloudLine = "GCP (instance $("$gid".Trim()), zone $zn, 네트워크 태그: $(if ($tg) { $tg } else { '없음' }), 방화벽 규칙: 콘솔에서 확인)"
            return
        }
        # IMDS 응답 없음 → 제조사/모델 힌트로 클라우드 가능성만 표기
        $hint = ''
        try { $cs = Get-CimInstance Win32_ComputerSystem -EA SilentlyContinue; $bi = Get-CimInstance Win32_BIOS -EA SilentlyContinue; $hint = "$($cs.Manufacturer) $($cs.Model) $($bi.Version) $($bi.SerialNumber)" } catch {}
        if ($hint -match 'Amazon|EC2|Google') { $script:CloudLine = "미확인 (IMDS 응답 없음, 하드웨어 정보상 클라우드 가능성: $($hint.Trim()))" }
        else { $script:CloudLine = '없음' }
    } catch { $script:CloudLine = '미확인' }
}
# ── 판정 라우팅 (평가기준 [웹서버-WAS] 기준) ──
# os    : check_server.ps1 점검 본문 재사용 → SRV 코드를 동일 판단기준의 WST 코드로 변환
# web   : 기존 IIS 점검 중 평가기준 일치 항목만 반영, 그 외는 REF-(참고)
# final : 평가기준 WIN(IIS) 판단방법 기준 웹 고유 점검
$script:S2W = @{
    'SRV-001'='WST-001'
    'SRV-003'='WST-002'
    'SRV-004'='WST-003'
    'SRV-005'='WST-004'
    'SRV-006'='WST-005'
    'SRV-007'='WST-006'
    'SRV-008'='WST-007'
    'SRV-009'='WST-008'
    'SRV-010'='WST-009'
    'SRV-011'='WST-010'
    'SRV-012'='WST-011'
    'SRV-013'='WST-012'
    'SRV-014'='WST-013'
    'SRV-015'='WST-014'
    'SRV-016'='WST-015'
    'SRV-018'='WST-016'
    'SRV-020'='WST-017'
    'SRV-021'='WST-018'
    'SRV-022'='WST-019'
    'SRV-023'='WST-020'
    'SRV-024'='WST-021'
    'SRV-025'='WST-022'
    'SRV-026'='WST-023'
    'SRV-027'='WST-024'
    'SRV-028'='WST-025'
    'SRV-029'='WST-026'
    'SRV-031'='WST-027'
    'SRV-034'='WST-028'
    'SRV-035'='WST-029'
    'SRV-037'='WST-030'
    'SRV-062'='WST-045'
    'SRV-063'='WST-046'
    'SRV-064'='WST-047'
    'SRV-066'='WST-048'
    'SRV-069'='WST-049'
    'SRV-070'='WST-050'
    'SRV-072'='WST-051'
    'SRV-073'='WST-052'
    'SRV-074'='WST-053'
    'SRV-075'='WST-054'
    'SRV-078'='WST-055'
    'SRV-079'='WST-056'
    'SRV-080'='WST-057'
    'SRV-081'='WST-058'
    'SRV-082'='WST-059'
    'SRV-083'='WST-060'
    'SRV-084'='WST-061'
    'SRV-087'='WST-062'
    'SRV-090'='WST-063'
    'SRV-091'='WST-064'
    'SRV-092'='WST-065'
    'SRV-093'='WST-066'
    'SRV-094'='WST-067'
    'SRV-095'='WST-068'
    'SRV-096'='WST-069'
    'SRV-097'='WST-070'
    'SRV-101'='WST-071'
    'SRV-103'='WST-072'
    'SRV-104'='WST-073'
    'SRV-105'='WST-074'
    'SRV-108'='WST-075'
    'SRV-109'='WST-076'
    'SRV-112'='WST-077'
    'SRV-115'='WST-078'
    'SRV-116'='WST-079'
    'SRV-118'='WST-080'
    'SRV-119'='WST-081'
    'SRV-121'='WST-082'
    'SRV-122'='WST-083'
    'SRV-123'='WST-084'
    'SRV-125'='WST-085'
    'SRV-126'='WST-086'
    'SRV-127'='WST-087'
    'SRV-128'='WST-088'
    'SRV-129'='WST-089'
    'SRV-131'='WST-090'
    'SRV-133'='WST-091'
    'SRV-134'='WST-092'
    'SRV-135'='WST-093'
    'SRV-136'='WST-094'
    'SRV-137'='WST-095'
    'SRV-138'='WST-096'
    'SRV-139'='WST-097'
    'SRV-140'='WST-098'
    'SRV-142'='WST-099'
    'SRV-144'='WST-100'
    'SRV-147'='WST-101'
    'SRV-149'='WST-103'
    'SRV-150'='WST-104'
    'SRV-151'='WST-105'
    'SRV-152'='WST-106'
    'SRV-158'='WST-107'
    'SRV-161'='WST-108'
    'SRV-163'='WST-109'
    'SRV-164'='WST-110'
    'SRV-165'='WST-111'
    'SRV-166'='WST-112'
    'SRV-170'='WST-113'
    'SRV-171'='WST-114'
    'SRV-172'='WST-115'
    'SRV-173'='WST-116'
    'SRV-174'='WST-117'
    'SRV-175'='WST-118'
    'SRV-177'='WST-119'
    'SRV-178'='WST-120'
    'SRV-179'='WST-126'
}
$script:INAME = @{
    'WST-001'='안전한 네트워크 모니터링 서비스 사용'
    'WST-002'='네트워크 모니터링 서비스 접근통제 설정 적절성'
    'WST-003'='불필요한 SMTP 서비스 비활성화'
    'WST-004'='SMTP 서비스의 expn/vrfy 명령어 실행 제한 여부'
    'WST-005'='SMTP 서비스 로그 수준 설정 적절성'
    'WST-006'='SMTP 서비스 보안 패치 적용 여부'
    'WST-007'='SMTP 서비스의 DoS 방지 기능 설정 여부'
    'WST-008'='SMTP 서비스 스팸 메일 릴레이 제한 설정 여부'
    'WST-009'='SMTP 서비스의 메일 queue 처리 권한 설정 적절성'
    'WST-010'='시스템 관리자 계정의 FTP 사용 제한 여부'
    'WST-011'='.netrc 파일 내 중요 정보 미포함 여부'
    'WST-012'='Anonymous 계정의 FTP 서비스 접속 제한 여부'
    'WST-013'='NFS 접근통제 설정 적절성'
    'WST-014'='불필요한 NFS 서비스 비활성화'
    'WST-015'='불필요한 RPC 서비스 비활성화'
    'WST-016'='불필요한 하드디스크 기본 공유 비활성화'
    'WST-017'='공유 기능에 대한 접근통제 설정 적절성'
    'WST-018'='FTP 서비스 접근통제 설정 적절성'
    'WST-019'='계정의 비밀번호 미설정, 빈 암호 사용 관리 여부'
    'WST-020'='원격 터미널 서비스의 암호화 설정 적절성'
    'WST-021'='취약한 Telnet 인증 방식 사용 제한 여부'
    'WST-022'='hosts.equiv 또는 .rhosts 설정 제한 여부'
    'WST-023'='root 계정 원격 접속 제한 여부'
    'WST-024'='서비스 접근 IP 및 포트 제한 여부'
    'WST-025'='원격 터미널 접속 타임아웃 설정 여부'
    'WST-026'='SMB 세션 중단 관리 설정 여부'
    'WST-027'='계정 목록 및 네트워크 공유 이름 노출 방지 여부'
    'WST-028'='불필요한 서비스 비활성화'
    'WST-029'='취약한 서비스 비활성화'
    'WST-030'='취약한 FTP 서비스 비활성화'
    'WST-031'='웹 서비스 디렉터리 리스팅 방지 설정 여부'
    'WST-032'='웹 서비스 CGI 스크립트 관리 여부'
    'WST-033'='웹 서비스 상위 디렉터리 접근 제한 설정 여부'
    'WST-034'='웹 서비스 경로 내 불필요 파일 관리 여부'
    'WST-035'='웹 서비스 파일 업로드 및 다운로드 용량 제한 설정 여부'
    'WST-036'='웹 서비스 프로세스 권한 제한 여부'
    'WST-037'='웹 서비스 경로 설정 적절성'
    'WST-038'='웹 서비스 경로 내 불필요한 링크 파일 관리 여부'
    'WST-039'='불필요한 웹 서비스 비활성화'
    'WST-040'='웹 서비스 설정 파일 노출 방지 여부'
    'WST-041'='웹 서비스 경로 내 파일의 접근통제 설정 적절성'
    'WST-042'='웹 서비스의 불필요한 스크립트 매핑 제거'
    'WST-043'='웹 서비스 서버 명령 실행 기능 제한 설정 적절성'
    'WST-044'='웹 서비스 기본 계정(아이디 또는 비밀번호) 변경 여부'
    'WST-045'='DNS 서비스 정보 노출 방지 여부'
    'WST-046'='DNS Recursive Query 제한 설정 여부'
    'WST-047'='DNS 서비스 보안 패치 적용 여부'
    'WST-048'='DNS Zone Transfer 제한 설정 적절성'
    'WST-049'='비밀번호 관리정책 설정 적절성'
    'WST-050'='취약한 패스워드 저장 방식 사용 제한 여부'
    'WST-051'='기본 관리자 계정명(Administrator) 변경 여부'
    'WST-052'='관리자 그룹에 불필요한 사용자 제거'
    'WST-053'='불필요하거나 관리되지 않는 계정 제거'
    'WST-054'='비밀번호 복잡도 설정'
    'WST-055'='불필요한 Guest 계정 비활성화'
    'WST-056'='익명 사용자에게 부적절한 권한(Everyone) 제거'
    'WST-057'='일반 사용자의 프린터 드라이버 설치 제한 여부'
    'WST-058'='Crontab 설정파일 권한 설정 적절성'
    'WST-059'='시스템 주요 디렉터리 권한 설정 적절성'
    'WST-060'='시스템 스타트업 스크립트 권한 설정 적절성'
    'WST-061'='시스템 주요 파일 권한 설정 적절성'
    'WST-062'='설치된 C 컴파일러의 권한 설정 적절성'
    'WST-063'='불필요한 원격 레지스트리 서비스 비활성화'
    'WST-064'='불필요하게 SUID, SGID bit가 설정된 파일 제거'
    'WST-065'='사용자 홈 디렉터리 경로 및 권한 설정 적절성'
    'WST-066'='불필요한 world writable 파일 제거'
    'WST-067'='Crontab 참조파일 권한 설정 적절성'
    'WST-068'='존재하지 않는 소유자 및 그룹 권한을 가진 파일 또는 디렉터리 제거'
    'WST-069'='사용자 환경파일의 소유자 또는 권한 설정 적절성'
    'WST-070'='FTP 서비스 디렉터리 접근권한 설정 적절성'
    'WST-071'='불필요한 예약 작업 제거'
    'WST-072'='LAN Manager 인증 수준 적절성'
    'WST-073'='보안 채널 데이터 디지털 암호화 또는 서명 기능 설정 적절성'
    'WST-074'='불필요한 시작프로그램 제거'
    'WST-075'='로그에 대한 접근통제 및 관리 적절성'
    'WST-076'='시스템 주요 이벤트 로그 설정 적절성'
    'WST-077'='Cron 서비스 로깅 설정 적절성'
    'WST-078'='로그의 정기적 검토 및 보고 수행 여부'
    'WST-079'='“보안 감사를 수행할 수 없는 경우, 즉시 시스템 종료” 기능 비활성화'
    'WST-080'='주기적인 보안패치 및 벤더 권고사항 적용 여부'
    'WST-081'='백신 프로그램 업데이트 적용 여부'
    'WST-082'='root 계정의 PATH 환경변수 설정 적절성'
    'WST-083'='umask 설정 적절성'
    'WST-084'='최종 로그인 사용자 계정 노출 방지 여부'
    'WST-085'='화면보호기 설정 적절성'
    'WST-086'='자동 로그온 방지 설정 여부'
    'WST-087'='로그인 실패 횟수에 따른 접속 제한 설정'
    'WST-088'='NTFS 파일 시스템 사용 여부'
    'WST-089'='백신 프로그램 설치 여부'
    'WST-090'='SU 명령 사용가능 그룹 제한 설정 적절성'
    'WST-091'='Cron 서비스 사용 계정 제한 설정 적절성'
    'WST-092'='스택 영역 실행 방지 설정 여부'
    'WST-093'='TCP 보안 설정 여부'
    'WST-094'='로그온 단계에서 "시스템 종료" 기능 비활성화'
    'WST-095'='네트워크 서비스 접근 권한 적절성'
    'WST-096'='백업 및 복구 권한 설정 적절성'
    'WST-097'='시스템 자원 소유권 변경 권한 설정 적절성'
    'WST-098'='이동식 미디어 포맷 및 꺼내기 허용 정책 설정 적절성'
    'WST-099'='중복 UID가 부여된 계정 제한 여부'
    'WST-100'='/dev 경로에 불필요한 파일 제거'
    'WST-101'='불필요한 네트워크 모니터링 서비스 비활성화'
    'WST-102'='웹 서비스 정보 노출 방지 여부'
    'WST-103'='디스크 볼륨 암호화 적용 여부'
    'WST-104'='로컬 로그온 허용 계정 제한 여부'
    'WST-105'='익명 SID/이름 변환 설정 제한 여부'
    'WST-106'='원격터미널 접속 가능한 사용자 그룹 제한 여부'
    'WST-107'='불필요한 Telnet 서비스 비활성화'
    'WST-108'='ftpusers 파일의 소유자 및 권한 설정 적절성'
    'WST-109'='시스템 사용 주의사항 출력'
    'WST-110'='구성원이 존재하지 않는 GID 제거'
    'WST-111'='불필요하게 Shell이 부여된 계정 제거'
    'WST-112'='불필요한 숨김 파일 또는 디렉터리 제거'
    'WST-113'='SMTP 서비스 정보 노출 방지 여부'
    'WST-114'='FTP 서비스 정보 노출 방지 여부'
    'WST-115'='불필요한 시스템 자원 공유 제거'
    'WST-116'='DNS 서비스 동적 업데이트 설정 적절성'
    'WST-117'='불필요한 DNS 서비스 비활성화'
    'WST-118'='시간 동기화를 위한 NTP 설정'
    'WST-119'='sudo 명령어 접근 권한 설정 적절성'
    'WST-120'='개인 키 사용 시 passphrase 설정 여부'
    'WST-121'='웹 서비스 불필요한 프록시 설정 제한 여부'
    'WST-122'='웹 서비스 불필요한 SSI(Server Side Includes) 기능 비활성화'
    'WST-123'='웹 서비스 기본 에러 페이지 노출 방지 여부'
    'WST-124'='웹 서비스 부적절한 LDAP 알고리즘 설정 제한 여부'
    'WST-125'='웹 서비스 독립된 업로드 경로 및 권한 설정 여부'
    'WST-126'='서비스 지원이 종료된(EoS) 시스템 및 장비 교체 여부'
}
$script:KEEP = @('WST-031','WST-036','WST-102','WST-121','WST-122','WST-123','WST-125')
$script:NA_WIN_WST = @('WST-004','WST-005','WST-006','WST-007','WST-008','WST-009','WST-010','WST-011','WST-013','WST-014','WST-015','WST-022','WST-023','WST-029','WST-045','WST-047','WST-058','WST-060','WST-062','WST-064','WST-066','WST-067','WST-068','WST-069','WST-077','WST-082','WST-083','WST-090','WST-091','WST-092','WST-099','WST-100','WST-108','WST-110','WST-111','WST-119')
$script:HOLDC = @('WST-080','WST-126')
$script:HOLD = @{}
$script:PHASE = "os"
function RouteCode([string]$c) {
    if ($c -match '^SRV-\d{3}$') { if ($script:S2W.ContainsKey($c)) { return $script:S2W[$c] } else { return "REF-$c" } }
    if ($c -match '^\d{3}$') { $c = "WST-$c" }
    if ($c -match '^WST-' -and $script:PHASE -eq 'web' -and $script:KEEP -notcontains $c) { return "REF-" + $c.Substring(4) }
    return $c
}
function Emit([string]$code,[string]$res,[string]$msg) {
    $code = RouteCode $code
    $msg = ($msg -replace "[`r`n]+", " / ") -replace '\|', '/'
    if ($script:KMODE -eq 'mi' -and $code -notlike 'WEB-*' -and $code -notlike 'REF-*' -and -not ($script:PHASE -eq 'os' -and $script:HOLDC -contains $code)) {
        Append-Utf8 $script:EVD "[참고-주요정보 모드 제외] $code|$res|$msg"; Append-Utf8 $script:EVD ""; return }
    if ($script:KMODE -eq 'ef' -and $code -like 'WEB-*') { return }
    if ($code -like 'REF-*') { Append-Utf8 $script:EVD "[참고-평가기준 외] $code|$res|$msg"; Append-Utf8 $script:EVD ""; return }
    if ($script:PHASE -eq 'os' -and $script:HOLDC -contains $code) { $script:HOLD[$code] = "$res|$msg"; return }
    if ($script:NA_WIN_WST -contains $code -and $res -ne 'N-A') {
        Append-Utf8 $script:EVD "[평가대상 아님] $code 원 판정: $res|$msg"
        $res = 'N-A'; $msg = '평가대상 아님 (WIN 해당 없음 - 평가기준 평가대상 열)'
    }
    switch ($res) { '양호' { $script:cntPass++ } '취약' { $script:cntFail++ } '수동확인' { $script:cntMC++ } '점검불가' { $script:cntUnable++ } default { $script:cntNA++ } }
    Out-Res "$code|$res|$msg"
    $nm = $script:INAME[$code]
    if ($nm) { Append-Utf8 $script:EVD "[판정] $code ($nm)|$res|$msg" } else { Append-Utf8 $script:EVD "[판정] $code|$res|$msg" }
    Append-Utf8 $script:EVD ""
}
function Pass([string]$code,[string]$msg) { Emit $code '양호' $msg }
function Fail([string]$code,[string]$msg) { Emit $code '취약' $msg }
function NA  ([string]$code,[string]$msg) { Emit $code 'N-A' $msg }
function MC  ([string]$code,[string]$msg) { Emit $code '수동확인' $msg }
function Unable([string]$code,[string]$msg) { Emit $code "점검불가" $msg }   # 점검 자체를 못 한 경우(권한·cmdlet·설정 파일 부재·조회 오류) - 근거에 구체적 사유
function Evd([string]$item,[string]$cmd) {
    $item = RouteCode $item
    Append-Utf8 $script:EVD "[$item] $(Get-Date -Format 'HH:mm:ss') PS> $cmd"
    try { $r = Invoke-Expression $cmd 2>&1 | Out-String -Width 4096; Append-Utf8 $script:EVD (Limit-Lines $r) } catch { Append-Utf8 $script:EVD $_.Exception.Message }
    Append-Utf8 $script:EVD ""
}
function EvdQ([string]$item,[string]$desc,[string]$val) {
    $item = RouteCode $item
    Append-Utf8 $script:EVD "[$item] $(Get-Date -Format 'HH:mm:ss') $desc"
    Append-Utf8 $script:EVD (Limit-Lines $val)
    Append-Utf8 $script:EVD ""
}
function WorseR([string]$a,[string]$b) {
    $rk = @{ '취약'=5; '점검불가'=4; '수동확인'=3; '양호'=2; 'N-A'=1 }   # 여러 대상 병합: 취약 > 점검불가 > 수동확인 > 양호 > N-A
    if (-not $a) { return $b }; if (-not $b) { return $a }
    $ra = ($a -split '\|',2)[0]; $rb = ($b -split '\|',2)[0]
    if ($rk[$rb] -gt $rk[$ra]) { return "$b / $(($a -split '\|',2)[1])" } else { return "$a / $(($b -split '\|',2)[1])" }
}
function MergeHold([string]$code,[string]$wres,[string]$wmsg) {
    $os = $script:HOLD[$code]
    $o = if ($os) { "$(($os -split '\|',2)[0])|OS: $(($os -split '\|',2)[1])" } else { "" }
    $w = if ($wres) { "$wres|웹/WAS: $wmsg" } else { "" }
    $m = WorseR $o $w
    if (-not $m) { $m = '점검불가|판정 정보 없음 - OS 점검 결과와 웹/WAS 점검 결과가 모두 없음' }
    $script:PHASE = 'final'
    $p = $m -split '\|',2; Emit $code $p[0] $p[1]
}
# ── 환경 탐지: 여러 제품·여러 인스턴스를 모두 수집 (IIS+Apache+Nginx 동시, Tomcat 다중 인스턴스, Tomcat+JEUS 동시) ──
# 환경변수로 직접 지정 가능: WEB_SRV(iis|apache|nginx 로 제한) WAS_SRV(tomcat|jeus 로 제한) APACHE_CONF NGINX_CONF TOMCAT_HOME CATALINA_BASE CATALINA_HOME JEUS_HOME IIS_APPHOST
$HN = $env:COMPUTERNAME
$script:DetectNote = @()
function Add-Note([string]$t) { $script:DetectNote += $t }
function Get-FixedDrives { $d = @(); try { foreach ($x in [IO.DriveInfo]::GetDrives()) { if ("$($x.DriveType)" -eq 'Fixed') { $d += $x.Name.TrimEnd('\') } } } catch {}; if (-not $d.Count) { $d = @("$env:SystemDrive") }; return $d }
function Add-Uniq([ref]$list, [string]$v) { if ($v -and (@($list.Value) -notcontains $v)) { $list.Value = @($list.Value) + $v } }
$script:Procs = @(); try { $script:Procs = @(Get-WmiObject Win32_Process -EA SilentlyContinue | Select-Object ProcessId, Name, ExecutablePath, CommandLine) } catch {}
$script:Svcs  = @(); try { $script:Svcs  = @(Get-WmiObject Win32_Service -EA SilentlyContinue | Select-Object Name, DisplayName, PathName, State, StartName) } catch {}
$drives = Get-FixedDrives

# IIS
$IIS_INSTALLED = $false; $IIS_VERSION = ""
$APPCMD = "$env:SystemRoot\System32\inetsrv\appcmd.exe"
if ((Get-Service W3SVC -EA SilentlyContinue) -or (Test-Path "$env:SystemRoot\System32\inetsrv\config\applicationHost.config")) {
    $IIS_INSTALLED = $true
    $iisReg = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\InetStp" -EA SilentlyContinue
    $IIS_VERSION = if ($iisReg) { "$($iisReg.MajorVersion).$($iisReg.MinorVersion)" } else { "unknown" }
    Add-Note "IIS $IIS_VERSION"
}

# Apache (Windows): 실행/서비스 경로 → 알려진 경로. 설정을 못 찾으면 제품만 탐지 상태로 두고 '점검불가'
$APACHE_CONFS = @(); $APACHE_DETECTED = $false; $APACHE_HINT = ''
function Add-ApacheConf([string]$p, [string]$why) { if ($p -and (Test-Path $p)) { Add-Uniq ([ref]$script:APACHE_CONFS) ((Resolve-Path $p).Path); Add-Note "Apache: $why $p" } }
if ($env:APACHE_CONF) { Add-ApacheConf $env:APACHE_CONF '환경변수 APACHE_CONF' }
foreach ($pr in $script:Procs) {
    if ("$($pr.Name)" -match '^(httpd|apache)(\.exe)?$') {
        $script:APACHE_DETECTED = $true; $script:APACHE_HINT = "실행 프로세스 $($pr.ExecutablePath)"
        if ("$($pr.CommandLine)" -match '-f\s+"?([^"\s]+)"?') { Add-ApacheConf $matches[1] "프로세스 -f" }
        if ($pr.ExecutablePath) { $root = Split-Path (Split-Path $pr.ExecutablePath); Add-ApacheConf "$root\conf\httpd.conf" "프로세스 경로" }
    }
}
foreach ($sv in $script:Svcs) {
    if ("$($sv.PathName)" -match 'httpd(\.exe)?"?\s' -or "$($sv.Name)" -match '^Apache') {
        $script:APACHE_DETECTED = $true; if (-not $script:APACHE_HINT) { $script:APACHE_HINT = "서비스 $($sv.Name)" }
        if ("$($sv.PathName)" -match '^"?([^"]*?)\\bin\\httpd(\.exe)?') { Add-ApacheConf "$($matches[1])\conf\httpd.conf" "서비스 $($sv.Name)" }
    }
}
if (-not $script:APACHE_CONFS.Count) {
    foreach ($dv in $drives) {
        foreach ($rel in @('Apache24','Apache2','Apache2.2','Apache2.4','xampp\apache','Program Files\Apache Group\Apache2','Program Files (x86)\Apache Group\Apache2','Program Files\Apache Software Foundation\Apache2.4','Program Files\Apache Software Foundation\Apache2.2')) {
            Add-ApacheConf "$dv\$rel\conf\httpd.conf" "알려진 경로"
        }
    }
}

# Nginx (Windows)
$NGINX_CONFS = @(); $NGINX_DETECTED = $false; $NGINX_HINT = ''
function Add-NginxConf([string]$p, [string]$why) { if ($p -and (Test-Path $p)) { Add-Uniq ([ref]$script:NGINX_CONFS) ((Resolve-Path $p).Path); Add-Note "Nginx: $why $p" } }
if ($env:NGINX_CONF) { Add-NginxConf $env:NGINX_CONF '환경변수 NGINX_CONF' }
foreach ($pr in $script:Procs) {
    if ("$($pr.Name)" -match '^nginx(\.exe)?$') {
        $script:NGINX_DETECTED = $true; $script:NGINX_HINT = "실행 프로세스 $($pr.ExecutablePath)"
        if ("$($pr.CommandLine)" -match '-c\s+"?([^"\s]+)"?') { Add-NginxConf $matches[1] "프로세스 -c" }
        if ($pr.ExecutablePath) { Add-NginxConf "$(Split-Path $pr.ExecutablePath)\conf\nginx.conf" "프로세스 경로" }
    }
}
foreach ($sv in $script:Svcs) {
    if ("$($sv.PathName)" -match 'nginx') {
        $script:NGINX_DETECTED = $true; if (-not $script:NGINX_HINT) { $script:NGINX_HINT = "서비스 $($sv.Name)" }
        if ("$($sv.PathName)" -match '^"?([^"]*?nginx[^"]*?)\\nginx(\.exe)?') { Add-NginxConf "$($matches[1])\conf\nginx.conf" "서비스 $($sv.Name)" }
    }
}
if (-not $script:NGINX_CONFS.Count) {
    foreach ($dv in $drives) {
        foreach ($rel in @('nginx','Program Files\nginx')) { Add-NginxConf "$dv\$rel\conf\nginx.conf" "알려진 경로" }
        try { foreach ($d in @(Get-ChildItem "$dv\" -Filter 'nginx*' -EA SilentlyContinue | Where-Object { $_.PSIsContainer })) { Add-NginxConf "$($d.FullName)\conf\nginx.conf" "알려진 경로" } } catch {}
    }
}

# Tomcat: 서비스(Procrun 레지스트리 -Dcatalina.base) → 실행 프로세스 -Dcatalina.base → 환경변수 → 알려진 경로(모든 인스턴스)
$TOMCAT_HOMES = @(); $TOMCAT_HINT = ''
function Add-TomcatBase([string]$p, [string]$why) {
    if (-not $p) { return }
    $p = $p.Trim('"').TrimEnd('\')
    if ((Test-Path "$p\conf\server.xml")) { $rp = (Resolve-Path $p).Path.TrimEnd('\'); if (@($script:TOMCAT_HOMES) -notcontains $rp) { $script:TOMCAT_HOMES = @($script:TOMCAT_HOMES) + $rp; Add-Note "Tomcat: $why $rp" } }
    elseif (-not $script:TOMCAT_HINT) { $script:TOMCAT_HINT = "$why $p (conf\server.xml 없음)" }
}
foreach ($v in @($env:CATALINA_BASE, $env:CATALINA_HOME, $env:TOMCAT_HOME)) { if ($v) { Add-TomcatBase $v '환경변수' } }
foreach ($sv in $script:Svcs) {
    if ("$($sv.Name)" -match '^Tomcat' -or "$($sv.PathName)" -match 'tomcat\d*w?\.exe') {
        $script:TOMCAT_HINT = "서비스 $($sv.Name)"
        $opt = $null; foreach ($rk in @("HKLM:\SOFTWARE\Apache Software Foundation\Procrun 2.0\$($sv.Name)\Parameters\Java", "HKLM:\SOFTWARE\Wow6432Node\Apache Software Foundation\Procrun 2.0\$($sv.Name)\Parameters\Java")) { $o = (Get-ItemProperty $rk -EA SilentlyContinue).Options; if ($o) { $opt = ($o -join ' ') } }
        if ($opt -and $opt -match '-Dcatalina\.base=("[^"]+"|\S+)') { Add-TomcatBase $matches[1] "서비스 $($sv.Name)" }
        elseif ($opt -and $opt -match '-Dcatalina\.home=("[^"]+"|\S+)') { Add-TomcatBase $matches[1] "서비스 $($sv.Name)" }
        elseif ("$($sv.PathName)" -match '^"?([^"]*?)\\bin\\') { Add-TomcatBase $matches[1] "서비스 $($sv.Name)" }
    }
}
foreach ($pr in $script:Procs) {
    if ("$($pr.Name)" -match '^(java|javaw|tomcat\d*w?)(\.exe)?$') {
        if ("$($pr.CommandLine)" -match '-Dcatalina\.base=("[^"]+"|\S+)') { $script:TOMCAT_HINT = "실행 프로세스"; Add-TomcatBase $matches[1] "프로세스 catalina.base" }
        elseif ("$($pr.CommandLine)" -match '-Dcatalina\.home=("[^"]+"|\S+)') { $script:TOMCAT_HINT = "실행 프로세스"; Add-TomcatBase $matches[1] "프로세스 catalina.home" }
    }
}
foreach ($dv in $drives) {
    foreach ($root in @("$dv\Program Files\Apache Software Foundation", "$dv\Program Files (x86)\Apache Software Foundation", "$dv\", "$dv\opt", "$dv\apps", "$dv\app", "$dv\was", "$dv\Apache Software Foundation")) {
        if (-not (Test-Path $root)) { continue }
        try {
            foreach ($d in @(Get-ChildItem $root -EA SilentlyContinue | Where-Object { $_.PSIsContainer -and $_.Name -match 'tomcat' })) {
                Add-TomcatBase $d.FullName '알려진 경로'
                try { foreach ($s in @(Get-ChildItem $d.FullName -EA SilentlyContinue | Where-Object { $_.PSIsContainer })) { Add-TomcatBase $s.FullName '알려진 경로(하위)' } } catch {}
            }
        } catch {}
    }
}
$TOMCAT_HOME = ''; if ($TOMCAT_HOMES.Count) { $TOMCAT_HOME = $TOMCAT_HOMES[0] }

# JEUS
$JEUS_HOMES = @(); $JEUS_HINT = ''
function Add-JeusHome([string]$p, [string]$why) {
    if (-not $p) { return }; $p = $p.Trim('"').TrimEnd('\')
    if ((Test-Path "$p\bin\jeusadmin.exe") -or (Test-Path "$p\bin\jeusadmin.bat") -or (Test-Path "$p\bin\jeusadmin") -or (Test-Path "$p\domains")) {
        $rp = (Resolve-Path $p).Path.TrimEnd('\'); if (@($script:JEUS_HOMES) -notcontains $rp) { $script:JEUS_HOMES = @($script:JEUS_HOMES) + $rp; Add-Note "JEUS: $why $rp" }
    } elseif (-not $script:JEUS_HINT) { $script:JEUS_HINT = "$why $p (JEUS 설치 구조 아님)" }
}
if ($env:JEUS_HOME) { Add-JeusHome $env:JEUS_HOME '환경변수 JEUS_HOME' }
foreach ($pr in $script:Procs) { if ("$($pr.CommandLine)" -match '-Djeus\.home=("[^"]+"|\S+)') { $script:JEUS_HINT = '실행 프로세스'; Add-JeusHome $matches[1] '프로세스 jeus.home' } }
foreach ($dv in $drives) {
    foreach ($root in @("$dv\TmaxSoft", "$dv\")) {
        if (-not (Test-Path $root)) { continue }
        try { foreach ($d in @(Get-ChildItem $root -EA SilentlyContinue | Where-Object { $_.PSIsContainer -and $_.Name -match '^jeus' })) { Add-JeusHome $d.FullName '알려진 경로' } } catch {}
    }
}

# 제품 목록 (환경변수 WEB_SRV / WAS_SRV 로 제한 가능)
$WEB_LIST = @(); $WAS_LIST = @()
if ($IIS_INSTALLED) { $WEB_LIST += 'iis' }
if ($APACHE_CONFS.Count -or $APACHE_DETECTED) { $WEB_LIST += 'apache' }
if ($NGINX_CONFS.Count -or $NGINX_DETECTED) { $WEB_LIST += 'nginx' }
if ($TOMCAT_HOMES.Count -or ($TOMCAT_HINT -and -not $TOMCAT_HOMES.Count)) { $WAS_LIST += 'tomcat' }
if ($JEUS_HOMES.Count -or $JEUS_HINT) { $WAS_LIST += 'jeus' }
if ($env:WEB_SRV) { $WEB_LIST = @($WEB_LIST | Where-Object { $_ -eq $env:WEB_SRV.ToLower() }) }
if ($env:WAS_SRV) { $WAS_LIST = @($WAS_LIST | Where-Object { $_ -eq $env:WAS_SRV.ToLower() }) }
$WEB_SRV = if ($WEB_LIST.Count) { $WEB_LIST[0] } else { '' }
$WAS_SRV = if ($WAS_LIST.Count) { $WAS_LIST[0] } else { '' }

# IIS WebAdministration 모듈 로드 (없어도 applicationHost.config 직접 해석으로 점검)
$HAS_WEB_ADMIN = $false
if ($IIS_INSTALLED) {
    Import-Module WebAdministration -EA SilentlyContinue
    $HAS_WEB_ADMIN = (Get-Module WebAdministration -EA SilentlyContinue) -ne $null
}

$script:IsAdmin = Test-IsAdmin
$ipText = Get-HostIPv4
Get-CloudInfo
$acctName = "$env:USERDOMAIN\$env:USERNAME"
try { $acctName = [Security.Principal.WindowsIdentity]::GetCurrent().Name } catch {}
$acctText = if ($script:IsAdmin) { "$acctName (관리자)" } else { "$acctName (관리자 아님 - 일부 항목 점검불가)" }

$os     = (Get-CimInstance Win32_OperatingSystem -EA SilentlyContinue)
$build  = if ($os) { [int]$os.BuildNumber } else { [Environment]::OSVersion.Version.Build }
$ver    = switch ($build) {
    {$_ -le 7601}  {"2008R2"; break}; {$_ -le 9600}  {"2012R2"; break}; {$_ -le 14393} {"2016"; break}
    {$_ -le 17763} {"2019"; break};   {$_ -le 20348} {"2022"; break};   default          {"2025"}
}

Out-Res "# ================================================================"
Out-Res "# 점검 대상: $HN"
Out-Res "# IP: $ipText"
Out-Res "# 실행 계정: $acctText"
Out-Res "# 클라우드: $($script:CloudLine)"
Out-Res "# OS: $(if ($os) { $os.Caption } else { "Windows Server $ver" }) (Build $build)"
Out-Res "# 웹서버: $(if ($WEB_LIST.Count) { $WEB_LIST -join ' ' } else { '미탐지' })$(if ($IIS_INSTALLED) { " / IIS $IIS_VERSION" })"
Out-Res "# WAS: $(if ($WAS_LIST.Count) { $WAS_LIST -join ' ' } else { '미탐지' })"
if ($TOMCAT_HOMES.Count) { Out-Res "# Tomcat 인스턴스: $($TOMCAT_HOMES -join ' ')" }
if ($JEUS_HOMES.Count) { Out-Res "# JEUS 홈: $($JEUS_HOMES -join ' ')" }
if ($script:DetectNote.Count) { Out-Res "# 탐지 근거: $($script:DetectNote -join '; ')" }
Out-Res "# 점검 기준: $(switch ($script:KMODE) { 'ef' { '전자금융기반시설 보안 취약점 평가기준 제2026-1호 [웹서버-WAS]' } 'mi' { '주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드(2026) [웹 서비스 WEB-01~WEB-26]' } default { '전자금융기반시설 보안 취약점 평가기준 제2026-1호 [웹서버-WAS] + 주요정보통신기반시설 상세가이드(2026) [웹 서비스 WEB-01~WEB-26]' } })"
Out-Res "# 점검 일시: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
if (-not $script:IsAdmin) { Out-Res "# [경고] 관리자 권한 아님 - IIS 설정·SAM·감사 정책 등을 읽지 못하는 항목은 점검불가로 표시됨, 관리자 권한으로 재점검 권고" }
Out-Res "# ================================================================"

Start-Utf8File $script:EVD "# ================================================================"
Append-Utf8 $script:EVD "# 웹서버/WAS 증적 파일 (감사 추적용)"
Append-Utf8 $script:EVD "# 대상: $HN / Windows Server $ver (Build $build)"
Append-Utf8 $script:EVD "# 웹서버: $(if ($WEB_LIST.Count) { $WEB_LIST -join ' ' } else { '미탐지' }) / WAS: $(if ($WAS_LIST.Count) { $WAS_LIST -join ' ' } else { '미탐지' })"
Append-Utf8 $script:EVD "# 생성: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Append-Utf8 $script:EVD "# IP: $ipText"
Append-Utf8 $script:EVD "# 실행 계정: $acctText"
Append-Utf8 $script:EVD "# 클라우드: $($script:CloudLine)"
Append-Utf8 $script:EVD "# 탐지 근거: $($script:DetectNote -join '; ')"
Append-Utf8 $script:EVD "# ================================================================"
# 헬퍼
$seceditFile = "$env:TEMP\srv_secpol_${PID}.cfg"
$null = secedit /export /cfg $seceditFile /quiet 2>$null

function Get-SecPol([string]$Key) {
    if (Test-Path $seceditFile) {
        $line = Get-Content $seceditFile -EA Stop | Where-Object { $_ -match "^\s*$([regex]::Escape($Key))\s*=" }
        if ($line) { return ($line -split "=",2)[1].Trim() }
    }; return $null
}
function Get-Reg([string]$Path,[string]$Name) {
    try { return (Get-ItemProperty -Path $Path -Name $Name -EA Stop).$Name } catch { return $null }
}
function Test-SecPolGroups([string]$Key, [string[]]$Bad) {
    # secedit 사용자 권한 할당 값(SID 목록)에서 불필요 그룹 탐지. 반환: @(설정값, 발견된 불필요 그룹)
    $v = Get-SecPol $Key
    if ($null -eq $v) { return @($null, @()) }
    $map = @{ "*S-1-1-0"="Everyone"; "*S-1-5-32-545"="Users"; "*S-1-5-32-546"="Guests"; "*S-1-5-7"="Anonymous"; "*S-1-5-11"="Authenticated Users" }
    $found = @()
    foreach ($sid in ($v -split ",")) { $s = $sid.Trim(); if ($map.ContainsKey($s) -and ($Bad -contains $map[$s])) { $found += $map[$s] } }
    return @($v, $found)
}
function Get-SvcState([string]$Name) {
    try {
        $s = Get-Service -Name $Name -EA Stop
        $st = "$($s.StartType)"   # PS 2.0 은 StartType 속성 없음 → WMI StartMode
        if (-not $st) { $w = Get-CimInstance Win32_Service -Filter "Name='$Name'" -EA SilentlyContinue; if ($w) { $st = "$($w.StartMode)" } }
        return @{Status="$($s.Status)";Start=$st}
    } catch {
        # Get-CimInstance 우선, WMI 미사용 환경을 위한 레지스트리 폴백
        $s = Get-CimInstance Win32_Service -Filter "Name='$Name'" -EA SilentlyContinue
        if ($s) { return @{Status=$s.State;Start=$s.StartMode} }
        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$Name"
        if (Test-Path $regPath) {
            $r = Get-ItemProperty $regPath -EA SilentlyContinue
            $startMap = @{2="Auto";3="Manual";4="Disabled"}
            $st = $startMap[[int]($r.Start)]; if (-not $st) { $st = "Unknown" }
            return @{Status="Unknown";Start=$st}
        }
        return $null
    }
}
function Read-AllText([string]$Path) {   # Get-Content -Raw(PS 3.0+) 대체
    if (-not (Test-Path $Path)) { return "" }
    try { return [IO.File]::ReadAllText($Path) } catch { return "" }
}
function Get-AceSid($ace) {
    try { return $ace.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value } catch { return "$($ace.IdentityReference)" }
}
function Get-LocalAccounts {
    # 로컬 계정: Name, SID, Enabled, PasswordRequired, LastLogon, PasswordLastSet, Src (Get-LocalUser 없는 PS 2.0~4.0 은 WMI+ADSI)
    if (Get-Command Get-LocalUser -EA SilentlyContinue) {
        try {
            return @(Get-LocalUser -EA Stop | ForEach-Object {
                New-Object PSObject -Property @{ Name=$_.Name; SID=$_.SID.Value; Enabled=[bool]$_.Enabled; PasswordRequired=[bool]$_.PasswordRequired
                    LastLogon=$_.LastLogon; PasswordLastSet=$_.PasswordLastSet; Src='Get-LocalUser' } })
        } catch {}
    }
    $out = @()
    foreach ($u in @(Get-WmiObject Win32_UserAccount -Filter "LocalAccount=True AND Domain='$env:COMPUTERNAME'" -EA SilentlyContinue)) {
        $ll = $null; $pls = $null; $src = 'WMI+ADSI'
        try {
            $a = [ADSI]"WinNT://$env:COMPUTERNAME/$($u.Name),user"
            try { $v = $a.Properties['LastLogin'].Value; if ($v) { $ll = [datetime]$v } } catch {}
            $age = $a.Properties['PasswordAge'].Value; if ($null -ne $age) { $pls = (Get-Date).AddSeconds(-[double]$age) }
        } catch { $src = 'WMI(ADSI 실패)' }
        $out += New-Object PSObject -Property @{ Name=$u.Name; SID=$u.SID; Enabled=(-not $u.Disabled); PasswordRequired=[bool]$u.PasswordRequired
            LastLogon=$ll; PasswordLastSet=$pls; Src=$src }
    }
    return $out
}
function Resolve-SecPolEntry([string]$e) {   # secedit '*S-1-5-32-544' → 표시명
    $e = $e.Trim(); if (-not $e.StartsWith('*S-1-')) { return $e }
    try { return (New-Object Security.Principal.SecurityIdentifier ($e.TrimStart('*'))).Translate([Security.Principal.NTAccount]).Value } catch { return $e }
}
function Get-LocalGroupMemberNames([string]$sid) {   # 로캘 무관(SID → 그룹명 → ADSI 구성원), 실패 시 $null
    try {
        $gn = (New-Object Security.Principal.SecurityIdentifier $sid).Translate([Security.Principal.NTAccount]).Value.Split('\')[-1]
        $g  = [ADSI]"WinNT://$env:COMPUTERNAME/$gn,group"
        return @($g.psbase.Invoke('Members') | ForEach-Object { ($_.GetType().InvokeMember('ADsPath','GetProperty',$null,$_,$null) -replace '^WinNT://','') -replace '/','\' })
    } catch { return $null }
}
function Get-IisFtpSites {   # IIS 7+ FTP 사이트별 설정(siteDefaults 상속 반영). $null = 설정 파일 없음/파싱 실패, @() = FTP 바인딩 사이트 없음
    $f = "$env:windir\System32\inetsrv\config\applicationHost.config"
    if (-not (Test-Path $f)) { return $null }
    try { $x = [xml](Read-AllText $f) } catch { return $null }
    $sites = $x.configuration.'system.applicationHost'.sites; $d = $sites.siteDefaults.ftpServer
    $pick = { param($a,$b) if ("$a" -ne '') { "$a" } elseif ("$b" -ne '') { "$b" } else { $null } }
    $out = @()
    foreach ($s in @($sites.site)) {
        if (-not $s) { continue }
        if (-not (@($s.bindings.binding) | Where-Object { $_.protocol -eq 'ftp' })) { continue }
        $fs  = $s.ftpServer
        $loc = @($x.configuration.location) | Where-Object { $_ -and $_.path -eq $s.name } | Select-Object -First 1
        $ip  = $null; if ($loc) { $ip = $loc.'system.ftpServer'.security.ipSecurity }
        if (-not $ip) { $ip = $x.configuration.'system.ftpServer'.security.ipSecurity }
        $vd  = @(@($s.application) | Where-Object { $_.path -eq '/' } | ForEach-Object { $_.virtualDirectory } | Where-Object { $_.path -eq '/' })[0]
        $out += New-Object PSObject -Property @{
            Name    = $s.name
            Anon    = & $pick $fs.security.authentication.anonymousAuthentication.enabled $d.security.authentication.anonymousAuthentication.enabled
            Ctl     = & $pick $fs.security.ssl.controlChannelPolicy $d.security.ssl.controlChannelPolicy
            Dat     = & $pick $fs.security.ssl.dataChannelPolicy $d.security.ssl.dataChannelPolicy
            Banner  = & $pick $fs.messages.suppressDefaultBanner $d.messages.suppressDefaultBanner
            IpRestr = [bool]($ip -and ("$($ip.allowUnlisted)" -eq 'false' -or @($ip.add | Where-Object { $_ }).Count -gt 0))
            Root    = if ($vd) { [Environment]::ExpandEnvironmentVariables("$($vd.physicalPath)") } else { $null } }
    }
    return ,$out
}
# ════════════════════════════════════════════════════════════════
# [1] OS 공통 항목 — check_server.ps1 점검 로직 (평가기준 판단기준·방법 동일 항목)
# ════════════════════════════════════════════════════════════════
$script:PHASE = "os"
if ($script:KMODE -ne 'mi') {   # 주요정보 모드는 SRV 공통 점검(전자금융 WST 용)을 건너뜀 - 아래 SRV-COMMON 구간 안은 원본 그대로
# >>> SRV-COMMON-BEGIN — 원본: server/check_server.ps1. 사본(webwas/check_webwas.ps1)은 python tools/sync_common.py 로 갱신
# ── 공통 헬퍼 (이 구간 안에서 정의 - 웹/WAS 스크립트에서도 그대로 사용, 구간 밖 전용 변수에 의존하지 않는다) ──
function CantCheck([string]$code,[string]$msg) {   # 점검불가 (webwas 스크립트에 Unable 함수가 없으면 수동확인으로 대체 표기)
    if (Get-Command Unable -EA SilentlyContinue) { Unable $code $msg } else { MC $code "[점검불가] $msg" }
}
function SecWhy([string]$what) {   # secedit 값이 없을 때의 점검불가 사유
    if ($script:IsAdmin -eq $false) { return "$what 조회 불가 - 관리자 권한 아님(secedit 내보내기 불가)" }
    return "$what 조회 불가 - secedit 정책 내보내기 실패"
}
function Cnt($a) { if ($null -eq $a) { return 0 }; return @($a).Count }   # $null 은 0, 스칼라·배열은 개수 (PS 2.0 단일 원소 .Count 대응)
function Mask-Secret([string]$s) {   # 명령행/설정 문자열의 password=... 류 값을 가린다
    if (-not $s) { return $s }
    return [regex]::Replace($s, '(?i)(pass(?:word|wd)?|pwd|secret|token|api[_-]?key)(\s*[=:]\s*|\s+)("[^"]*"|\S+)', '$1$2****')
}
function Get-RdpDeny {   # fDenyTSConnections: 그룹 정책 우선 → 로컬 설정. 값 없으면 $null (문자열 반환)
    $v = Get-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' 'fDenyTSConnections'
    if ($null -ne $v) { return "$v" }
    $v = Get-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' 'fDenyTSConnections'
    if ($null -ne $v) { return "$v" }
    return $null
}
function Get-NetstatLines {   # netstat -ano 결과 (한 번만 실행해 캐시). Get-NetTCPConnection(2012+) 없는 2008 R2 대체
    if ($null -eq $script:NetstatLines) {
        $script:NetstatLines = @(); $script:NetstatOK = $false
        try { $script:NetstatLines = @(netstat -ano 2>$null | ForEach-Object { "$_" }); $script:NetstatOK = (@($script:NetstatLines | Where-Object { $_ -match '^\s*TCP\s' }).Count -gt 0) } catch {}
    }
    return ,$script:NetstatLines
}
function Get-Listen([int]$Port,[string]$Proto = 'TCP') {   # 리슨 항목(Addr/Port/PID) 배열, netstat 조회 자체가 안 되면 $null (로캘 무관 파싱: 외부 주소가 :0 인 TCP 행)
    $lines = Get-NetstatLines
    if (-not $script:NetstatOK) { return $null }
    $res = @()
    foreach ($l in $lines) {
        if ($Proto -eq 'TCP') { $m = [regex]::Match($l, '^\s*TCP\s+(\S+):(\d+)\s+\S+:0\s+.+?\s+(\d+)\s*$') }
        else { $m = [regex]::Match($l, '^\s*UDP\s+(\S+):(\d+)\s+\*:\*\s+(\d+)\s*$') }
        if ($m.Success -and [int]$m.Groups[2].Value -eq $Port) { $res += New-Object PSObject -Property @{ Addr=$m.Groups[1].Value; Port=$m.Groups[2].Value; PID=$m.Groups[3].Value } }
    }
    return ,$res
}
function Format-Listen($arr) {   # 증적용 문자열
    if ($null -eq $arr) { return '(netstat 조회 실패)' }
    if ((Cnt $arr) -eq 0) { return '(리슨 없음)' }
    return ((@($arr) | ForEach-Object { $pn = ''; try { $pn = (Get-Process -Id ([int]$_.PID) -EA Stop).ProcessName } catch {}; "$($_.Addr):$($_.Port) PID=$($_.PID) $pn" }) -join "`n")
}
function Get-ShareList {   # 공유 목록 (Name/Path/Special/Type/Src). Get-SmbShare(2012+) 없으면 Win32_Share. 조회 실패 시 $null
    try {
        if (Get-Command Get-SmbShare -EA SilentlyContinue) {
            $r = @(Get-SmbShare -EA Stop | ForEach-Object { New-Object PSObject -Property @{ Name="$($_.Name)"; Path="$($_.Path)"; Special=[bool]$_.Special; Type=$(if ("$($_.ShareType)" -match 'FileSystemDirectory|Disk') { 'Disk' } else { "$($_.ShareType)" }); Src='Get-SmbShare' } })
            return ,$r
        }
    } catch {}
    try {
        $w = @(Get-WmiObject Win32_Share -EA Stop)
        $r = @($w | ForEach-Object { New-Object PSObject -Property @{ Name="$($_.Name)"; Path="$($_.Path)"; Special=([uint32]$_.Type -ge 2147483648); Type=$(if ([uint32]$_.Type -eq 0 -or [uint32]$_.Type -eq 2147483648) { 'Disk' } else { "$($_.Type)" }); Src='Win32_Share' } })
        return ,$r
    } catch { return $null }
}
function Format-Shares($list) {
    if ($null -eq $list) { return '(공유 목록 조회 실패)' }
    if ((Cnt $list) -eq 0) { return '(공유 없음)' }
    return ((@($list) | ForEach-Object { "$($_.Name)`t$($_.Path)`tSpecial=$($_.Special)`t[$($_.Src)]" }) -join "`n")
}
function Get-ShareAceList([string]$Name) {   # 공유 권한(Account/Sid/Right/Type). Get-SmbShareAccess(2012+) 없으면 Win32_LogicalShareSecuritySetting DACL. 실패 시 $null
    if (Get-Command Get-SmbShareAccess -EA SilentlyContinue) {
        try {
            $out = @()
            foreach ($a in @(Get-SmbShareAccess -Name $Name -EA Stop)) {
                $sid = ''; try { $sid = (New-Object Security.Principal.NTAccount("$($a.AccountName)")).Translate([Security.Principal.SecurityIdentifier]).Value } catch {}
                $out += New-Object PSObject -Property @{ Account="$($a.AccountName)"; Sid=$sid; Right="$($a.AccessRight)"; Type="$($a.AccessControlType)" }
            }
            return ,$out
        } catch {}
    }
    try {
        $nm = $Name.Replace("'", "''")
        $s = Get-WmiObject Win32_LogicalShareSecuritySetting -Filter "Name='$nm'" -EA Stop
        if (-not $s) { return $null }
        $d = $s.GetSecurityDescriptor()
        if ($d.ReturnValue -ne 0) { return $null }
        $dacl = @($d.Descriptor.DACL)
        if ($dacl.Count -eq 0 -or -not $dacl[0]) { return ,@(New-Object PSObject -Property @{ Account='Everyone(DACL 없음=모두 허용)'; Sid='S-1-1-0'; Right='Full'; Type='Allow' }) }
        $out = @()
        foreach ($ace in $dacl) {
            $mk = [int64]$ace.AccessMask
            $rt = if (($mk -band 0x1F01FF) -eq 0x1F01FF) { 'Full' } elseif (($mk -band 0x1301BF) -eq 0x1301BF) { 'Change' } elseif (($mk -band 0x1200A9) -eq 0x1200A9) { 'Read' } else { '0x{0:X}' -f $mk }
            $out += New-Object PSObject -Property @{ Account="$($ace.Trustee.Domain)\$($ace.Trustee.Name)".TrimStart('\'); Sid="$($ace.Trustee.SIDString)"; Right=$rt; Type=$(if ([int]$ace.AceType -eq 1) { 'Deny' } else { 'Allow' }) }
        }
        return ,$out
    } catch { return $null }
}
function Format-Aces($aces) {
    if ($null -eq $aces) { return '    (ACL 조회 실패)' }
    if ((Cnt $aces) -eq 0) { return '    (ACE 없음)' }
    return ((@($aces) | ForEach-Object { "    $($_.Account) [$($_.Sid)] $($_.Right) $($_.Type)" }) -join "`n")
}
function Get-LocalGroupMemberNames([string]$sid) {   # 로캘 무관(SID → 그룹명 → ADSI 구성원). 반환: 구성원 배열(비어 있어도 배열), 조회 실패 시 $null
    try {
        $gn = (New-Object Security.Principal.SecurityIdentifier $sid).Translate([Security.Principal.NTAccount]).Value.Split('\')[-1]
        $g  = [ADSI]"WinNT://$env:COMPUTERNAME/$gn,group"
        $mem = @($g.psbase.Invoke('Members') | ForEach-Object { ($_.GetType().InvokeMember('ADsPath','GetProperty',$null,$_,$null) -replace '^WinNT://','') -replace '/','\' })
        return ,$mem   # 빈 배열이 $null 로 풀리지 않게 ',' 로 감싼다 (호출 측은 @() 없이 바로 받아 @($x).Count 로 센다)
    } catch { return $null }
}
function Get-IisFtpSites {   # IIS 7+ FTP 사이트별 설정(siteDefaults 상속 반영). $null = 설정 파일 없음/파싱 실패, @() = FTP 바인딩 사이트 없음
    $f = "$env:windir\System32\inetsrv\config\applicationHost.config"
    if (-not (Test-Path $f)) { return $null }
    try { $x = [xml](Read-AllText $f) } catch { return $null }
    if (-not $x -or -not $x.configuration) { return $null }
    $sites = $x.configuration.'system.applicationHost'.sites; $d = $sites.siteDefaults.ftpServer
    $pick = { param($a,$b) if ("$a" -ne '') { "$a" } elseif ("$b" -ne '') { "$b" } else { $null } }
    $out = @()
    foreach ($s in @($sites.site)) {
        if (-not $s) { continue }
        if (-not (@($s.bindings.binding) | Where-Object { $_.protocol -eq 'ftp' })) { continue }
        $fs  = $s.ftpServer
        $loc = @($x.configuration.location) | Where-Object { $_ -and $_.path -eq $s.name } | Select-Object -First 1
        $ip  = $null; if ($loc) { $ip = $loc.'system.ftpServer'.security.ipSecurity }
        if (-not $ip) { $ip = $x.configuration.'system.ftpServer'.security.ipSecurity }
        # IP 제한: allowUnlisted 기본값은 true(목록에 없는 IP 허용) → allowUnlisted=false 일 때만 '지정 IP 만 허용'. deny 목록만 있으면 일부 차단일 뿐 제한 아님
        $ipDet = '(ipSecurity 설정 없음 - 모든 IP 허용)'; $ipRestr = $false
        if ($ip) {
            $au = "$($ip.allowUnlisted)"; $ipRestr = ($au -eq 'false')
            $ipDet = "allowUnlisted=$(if ($au -eq '') { '기본(true)' } else { $au }) / " + ((@($ip.add | Where-Object { $_ } | ForEach-Object { "$($_.ipAddress)$(if ($_.subnetMask) { '/' + $_.subnetMask })($(if ("$($_.allowed)" -eq 'false') { '거부' } else { '허용' }))" }) -join ', '))
        }
        $vd  = @(@($s.application) | Where-Object { $_.path -eq '/' } | ForEach-Object { $_.virtualDirectory } | Where-Object { $_.path -eq '/' })[0]
        $out += New-Object PSObject -Property @{
            Name    = $s.name
            Anon    = & $pick $fs.security.authentication.anonymousAuthentication.enabled $d.security.authentication.anonymousAuthentication.enabled
            Ctl     = & $pick $fs.security.ssl.controlChannelPolicy $d.security.ssl.controlChannelPolicy
            Dat     = & $pick $fs.security.ssl.dataChannelPolicy $d.security.ssl.dataChannelPolicy
            Banner  = & $pick $fs.messages.suppressDefaultBanner $d.messages.suppressDefaultBanner
            IpRestr = $ipRestr
            IpDetail = $ipDet
            Root    = if ($vd) { [Environment]::ExpandEnvironmentVariables("$($vd.physicalPath)") } else { $null } }
    }
    return ,$out
}
function Format-FtpSites($sites) {
    if ($null -eq $sites) { return 'applicationHost.config 없음/파싱 실패' }
    if ((Cnt $sites) -eq 0) { return 'FTP 바인딩 사이트 없음' }
    return ((@($sites) | ForEach-Object { "$($_.Name): Anon=$($_.Anon) Ctl=$($_.Ctl) Dat=$($_.Dat) Banner=$($_.Banner) IpRestr=$($_.IpRestr) [$($_.IpDetail)] Root=$($_.Root)" }) -join "`n")
}
function Get-DnsZoneData {   # DNS 영역: Name/Type/Ds/Xfer(SecureSecondaries 0~3)/Upd(AllowUpdate 0~2). AD 통합 영역 포함 위해 Get-DnsServerZone → dnscmd → 레지스트리(비-AD 영역만) 순
    $r = New-Object PSObject -Property @{ Zones=@(); Method=''; Complete=$false; Note='' }
    $ssMap = @{ 'TransferAnyServer'='0'; 'TransferToZoneNameServer'='1'; 'TransferToSecureServers'='2'; 'NoTransfer'='3' }
    $duMap = @{ 'None'='0'; 'NonsecureAndSecure'='1'; 'Secure'='2' }
    if (Get-Command Get-DnsServerZone -EA SilentlyContinue) {
        try {
            $zs = @(Get-DnsServerZone -EA Stop | Where-Object { -not $_.IsAutoCreated -and "$($_.ZoneType)" -match 'Primary|Secondary' -and $_.ZoneName -ne 'TrustAnchors' })
            $r.Zones = @($zs | ForEach-Object { $xf = $ssMap["$($_.SecureSecondaries)"]; $up = ''; if ("$($_.ZoneType)" -eq 'Primary') { $up = $duMap["$($_.DynamicUpdate)"] }
                New-Object PSObject -Property @{ Name="$($_.ZoneName)"; Type="$($_.ZoneType)"; Ds=[bool]$_.IsDsIntegrated; Xfer="$xf"; Upd="$up" } })
            $r.Method = 'Get-DnsServerZone'; $r.Complete = $true
            return $r
        } catch { $r.Note = "Get-DnsServerZone 실패: $($_.Exception.Message)" }
    }
    if (Get-Command dnscmd.exe -EA SilentlyContinue) {
        try {
            $names = @()
            foreach ($l in @(& dnscmd.exe /EnumZones 2>&1 | ForEach-Object { "$_" })) {
                $m = [regex]::Match($l, '^\s*(\S+)\s+(Primary|Secondary)\s+\S+')
                if ($m.Success -and $m.Groups[1].Value -ne 'TrustAnchors') { $names += ,@($m.Groups[1].Value, $m.Groups[2].Value) }
            }
            if ($names.Count) {
                $zs = @()
                foreach ($n in $names) {
                    $zi = (& dnscmd.exe /ZoneInfo ($n[0]) 2>&1 | Out-String)
                    $xf = ''; $up = ''; $ds = $false
                    if ($zi -match '(?im)^\s*secure secs\s*=\s*(\d+)') { $xf = $matches[1] }
                    if ($zi -match '(?im)^\s*update\s*=\s*(\d+)') { $up = $matches[1] }
                    if ($zi -match '(?im)^\s*DS integrated\s*=\s*(\d+)') { $ds = ($matches[1] -ne '0') }
                    $zs += New-Object PSObject -Property @{ Name=$n[0]; Type=$n[1]; Ds=$ds; Xfer=$xf; Upd=$(if ($n[1] -eq 'Primary') { $up } else { '' }) }
                }
                $r.Zones = $zs; $r.Method = 'dnscmd'; $r.Complete = $true
                return $r
            }
            $r.Note += " dnscmd /EnumZones 결과 해석 실패(로캘 또는 DNS 서비스 상태)"
        } catch { $r.Note += " dnscmd 실패: $($_.Exception.Message)" }
    }
    $zr = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\DNS Server\Zones'
    if (Test-Path $zr) {
        $zs = @(Get-ChildItem $zr -EA SilentlyContinue | Where-Object { $_.PSChildName -notmatch '^(TrustAnchors|RootDNSServers)$' } | ForEach-Object {
            $p = Get-ItemProperty $_.PSPath -EA SilentlyContinue
            New-Object PSObject -Property @{ Name=$_.PSChildName; Type='(레지스트리)'; Ds=$false; Xfer="$($p.SecureSecondaries)"; Upd="$($p.AllowUpdate)" } })
        $r.Zones = $zs; $r.Method = '레지스트리(AD 통합 영역 제외)'; $r.Complete = $false
        $r.Note += ' Get-DnsServerZone·dnscmd 사용 불가 - 레지스트리는 AD 통합 영역을 담지 않음'
    } else { $r.Method = '없음'; $r.Note += ' 영역 조회 수단 없음' }
    return $r
}
function Format-DnsZones($zd) {
    if ($null -eq $zd) { return '(조회 실패)' }
    return ("조회 방법: $($zd.Method) / 완전한 목록: $($zd.Complete) $($zd.Note)`n" + ((@($zd.Zones) | ForEach-Object { "$($_.Name) [$($_.Type)] DS통합=$($_.Ds) SecureSecondaries=$($_.Xfer) AllowUpdate=$($_.Upd)" }) -join "`n"))
}
function Get-FwProfiles {   # 방화벽 프로필 (Name/Enabled/Inbound/Src). Get-NetFirewallProfile(2012+) 없으면 레지스트리(정책 우선). 실패 시 $null
    if (Get-Command Get-NetFirewallProfile -EA SilentlyContinue) {
        try {
            $r = @(Get-NetFirewallProfile -EA Stop | ForEach-Object { New-Object PSObject -Property @{ Name="$($_.Name)"; Enabled=("$($_.Enabled)" -eq 'True'); Inbound="$($_.DefaultInboundAction)"; Src='Get-NetFirewallProfile' } })
            if ($r.Count) { return ,$r }
        } catch {}
    }
    $base = 'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy'
    $pol  = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall'
    $out = @(); $known = 0
    foreach ($p in @(@{N='Domain';K='DomainProfile'}, @{N='Private';K='StandardProfile'}, @{N='Public';K='PublicProfile'})) {
        $en = Get-Reg "$pol\$($p.K)" 'EnableFirewall'; if ($null -eq $en) { $en = Get-Reg "$base\$($p.K)" 'EnableFirewall' }
        $di = Get-Reg "$pol\$($p.K)" 'DefaultInboundAction'; if ($null -eq $di) { $di = Get-Reg "$base\$($p.K)" 'DefaultInboundAction' }
        if ($null -ne $en) { $known++ }
        $out += New-Object PSObject -Property @{ Name=$p.N; Enabled=($null -eq $en -or [int]$en -ne 0); Inbound=$(if ($null -eq $di) { 'Block' } elseif ([int]$di -eq 0) { 'Allow' } else { 'Block' }); Src='레지스트리(SharedAccess/정책)' }
    }
    if ($known -eq 0) { return $null }
    return ,$out
}
function Get-FwInboundRules {   # 활성 인바운드 허용 규칙(레지스트리 FirewallRules + 정책). Any=원격 주소·로컬 포트·프로그램 제한이 모두 없는 전면 허용 규칙. 키가 없으면 $null
    $out = @(); $got = $false
    foreach ($k in 'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules','HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules') {
        if (-not (Test-Path $k)) { continue }
        try {
            $item = Get-Item $k -EA Stop; $got = $true
            foreach ($n in @($item.Property)) {
                $v = "$($item.GetValue($n))"
                if ($v -notmatch '\|Action=Allow\|' -or $v -notmatch '\|Active=TRUE\|' -or $v -notmatch '\|Dir=In\|') { continue }
                $f = @{}
                foreach ($pt in ($v -split '\|')) { $i = $pt.IndexOf('='); if ($i -gt 0) { $f[$pt.Substring(0, $i)] = $pt.Substring($i + 1) } }
                $anyRa = (@($f.Keys | Where-Object { $_ -like 'RA*' }).Count -eq 0)
                $anyPort = (-not $f.ContainsKey('LPort') -and -not $f.ContainsKey('LPort2_10'))
                $anyApp = (-not $f.ContainsKey('App') -and -not $f.ContainsKey('Svc'))
                $ra = (@($f.Keys | Where-Object { $_ -like 'RA*' } | ForEach-Object { "$_=$($f[$_])" }) -join ',')
                $out += New-Object PSObject -Property @{ Name="$($f['Name'])"; Proto="$($f['Protocol'])"; LPort="$($f['LPort'])"; RA=$ra; App="$($f['App'])$($f['Svc'])"; Any=($anyRa -and $anyPort -and $anyApp) }
            }
        } catch {}
    }
    if (-not $got) { return $null }
    return ,$out
}
function Get-LogMaxBytes([string]$ln) {   # 이벤트 로그 최대 크기(바이트). Get-WinEvent -ListLog → wevtutil 순, 실패 시 $null
    try { $l = Get-WinEvent -ListLog $ln -EA Stop; if ($l) { return [int64]$l.MaximumSizeInBytes } } catch {}
    try { $o = (wevtutil.exe gl $ln 2>$null | Out-String); if ($o -match '(?im)^\s*maxSize\s*:\s*(\d+)') { return [int64]$matches[1] } } catch {}
    return $null
}
function Get-StartupEntries {   # 시작 프로그램 (Run 키·시작 폴더). 명령행의 password=... 값은 마스킹
    $o = @()
    foreach ($k in 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run','HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce','HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run','HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run') {
        if (-not (Test-Path $k)) { continue }
        $it = Get-Item $k -EA SilentlyContinue; if (-not $it) { continue }
        foreach ($n in @($it.Property)) { $o += "[$k] $n = $(Mask-Secret "$($it.GetValue($n))")" }
    }
    foreach ($f in @(Get-ChildItem "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp" -Force -EA SilentlyContinue)) { $o += "[StartUp 폴더] $($f.Name)" }
    return ,$o
}

# ── SRV-001: SNMP 버전 ───────────────────────────────────────────
$snmpSvc   = Get-SvcState "SNMP"; $winSnmpOn = $snmpSvc -and $snmpSvc.Status -match "Running"
$udp161    = Get-Listen 161 'UDP'
$snmpProcs = @(Get-Process -EA SilentlyContinue | Where-Object { $p0 = $_; $p0.ProcessName -match '^snmpd$' -or @(@($udp161) | Where-Object { $_ -and "$($_.PID)" -eq "$($p0.Id)" -and $p0.ProcessName -ne 'snmp' }).Count })
$otherSnmp = (-not $winSnmpOn) -and ($snmpProcs.Count -gt 0)
$snmpPaths = @($snmpProcs | ForEach-Object { if ($_.Path) { $_.Path } else { $_.ProcessName } })
EvdQ "SRV-001" "SNMP 서비스 상태 / UDP 161 리슨 / 타사 snmpd 프로세스" "서비스: $(if ($snmpSvc) { "$($snmpSvc.Status)/$($snmpSvc.Start)" } else { '미설치' })`nUDP161: $(Format-Listen $udp161)`n타사 SNMP: $(if ($snmpPaths.Count) { $snmpPaths -join ', ' } else { '없음' })"
if ($otherSnmp) {
    foreach ($c in (@('C:\usr\etc\snmp\snmpd.conf') + @($snmpProcs | Where-Object { $_.Path } | ForEach-Object { Join-Path (Split-Path (Split-Path $_.Path)) 'etc\snmp\snmpd.conf' }) | Select-Object -Unique)) {
        if (Test-Path $c) { EvdQ "SRV-001" "$c (community·createUser 비밀번호 마스킹)" ((Select-String -Path $c -Pattern '^\s*(rocommunity|rwcommunity|com2sec|createUser|rouser|rwuser)' -EA SilentlyContinue | ForEach-Object { ($_.Line -replace '((community|com2sec)\S*\s+(\S+\s+){0,2})\S+\s*$','$1****') -replace '^(\s*createUser\s+\S+(\s+(MD5|SHA\S*))?)\s+.*$','$1 ****' }) -join "`n") }
    }
}
if ($otherSnmp) {
    MC  "SRV-001" "타사 SNMP 에이전트 실행($($snmpPaths -join ', ')) - snmpd.conf community 복잡도/v3 설정 확인"
} elseif (-not $winSnmpOn) {
    NA  "SRV-001" "SNMP 서비스 미실행"
} else {
    $comm = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\ValidCommunities" -EA SilentlyContinue).PSObject.Properties | Where-Object { @('PSPath','PSParentPath','PSChildName','PSDrive','PSProvider') -notcontains $_.Name }
    # 평가기준 판단방법: 기본값(public/private) 미사용 + 복잡도(2종 10자 이상 / 3종 8자 이상) 만족 여부 (보고서·증적에는 마스킹 표기)
    $weak = @(); $strong = @(); $ev001 = @()
    foreach ($c in $comm) {
        $n = $c.Name
        $cls = 0; if ($n -match '[A-Za-z]') { $cls++ }; if ($n -match '\d') { $cls++ }; if ($n -match '[^A-Za-z0-9]') { $cls++ }
        $mask = if ($n.Length -gt 2) { $n.Substring(0,2) + ('*' * ($n.Length - 2)) } else { '**' }
        $ev001 += "$mask ($($n.Length)자/${cls}종) 권한값=$($c.Value)"
        if ($n -match '^(public|private)$' -or -not (($cls -ge 2 -and $n.Length -ge 10) -or ($cls -ge 3 -and $n.Length -ge 8))) { $weak += "$mask($($n.Length)자/${cls}종)" }
        else { $strong += "$mask($($n.Length)자/${cls}종)" }
    }
    EvdQ "SRV-001" "ValidCommunities (community 마스킹: 앞 2자만 표시, 권한값 4=읽기 전용/8=읽기·쓰기)" $(if ($ev001.Count) { $ev001 -join "`n" } else { '(등록된 community 없음)' })
    if ($weak) { Fail "SRV-001" "SNMP Community 기본값 또는 복잡도 미달(2종 10자/3종 8자): $($weak -join ',')" }
    elseif ($strong) { Pass "SRV-001" "SNMP Community 복잡도 충족: $($strong -join ',')" }
    else { MC "SRV-001" "SNMP 실행 중 - Community 미등록(v3/설정) 수동 확인" }
}

# ── FTP 공통 (SRV-013/021/037/097/171): 서비스·21번 포트·IIS FTP 사이트 설정 ──
$ftpSvc = Get-SvcState "FTPSVC"; if (-not $ftpSvc) { $ftpSvc = Get-SvcState "MSFTPSVC" }
$l21 = Get-Listen 21
$ftpSvcRun = [bool]($ftpSvc -and "$($ftpSvc.Status)" -eq "Running")
$ftpRun = $ftpSvcRun -or ((Cnt $l21) -gt 0)
$ahc = "$env:windir\System32\inetsrv\config\applicationHost.config"
$ahcTxt = Read-AllText $ahc
$ftpSites = Get-IisFtpSites
$ftpIis = ($null -ne $ftpSites -and (Cnt $ftpSites) -gt 0)
# 모드: iis(IIS FTP 사이트 확인) / iis-none(FTPSVC 실행·사이트 미탐지) / iis-fail(설정 읽기 실패) / third(타사 FTP 가 21 리슨) / unknown(포트 조회 불가) / none
$ftpMode = if ($ftpSvcRun) { if ($null -eq $ftpSites) { 'iis-fail' } elseif ((Cnt $ftpSites) -eq 0) { 'iis-none' } else { 'iis' } } elseif ($null -eq $l21) { 'unknown' } elseif ((Cnt $l21) -gt 0) { 'third' } else { 'none' }
$ftpState = if ($ftpSvc) { "$($ftpSvc.Status)/$($ftpSvc.Start)" } else { '미설치' }
$ftpWhy = if (-not (Test-Path $ahc)) { 'applicationHost.config 없음(IIS 6 이하 FTP 이면 MetaBase.xml 수동 확인)' } else { 'applicationHost.config 파싱 실패' }
EvdQ "SRV-013" "FTP 공통: 서비스(FTPSVC/MSFTPSVC) 상태 / TCP 21 리슨 / 판정 모드" "서비스: $ftpState`nTCP21: $(Format-Listen $l21)`n모드: $ftpMode"
EvdQ "SRV-013" "IIS FTP 사이트별 설정 (Anon/Ctl/Dat/Banner/IpRestr/Root, siteDefaults 상속 반영)" (Format-FtpSites $ftpSites)

# ── SRV-013: Anonymous FTP ───────────────────────────────────────
# 판단방법: IIS 6 이하 metabase.xml AllowAnonymous / IIS 7 이상 applicationHost.config ftpServer anonymousAuthentication
switch ($ftpMode) {
    'none'     { Pass "SRV-013" "FTP 서비스 미사용 (FTPSVC/MSFTPSVC 중지, 21번 포트 리슨 없음)" }
    'unknown'  { CantCheck "SRV-013" "21번 포트 리슨 여부 조회 불가(netstat 실패)이고 FTPSVC 미실행 - FTP 사용 여부 수동 확인" }
    'third'    { MC "SRV-013" "21번 포트 리슨 중(FTPSVC 미실행, 타사 FTP 추정: $((Format-Listen $l21) -replace "`n",' / ')) - Anonymous 설정 수동 확인" }
    'iis-fail' { if (Test-Path $ahc) { CantCheck "SRV-013" "FTP 서비스 실행 중이나 IIS 설정(applicationHost.config) 파싱 실패 - Anonymous 설정 수동 확인" } else { MC "SRV-013" "FTP 서비스 실행 중 - $ftpWhy" } }
    'iis-none' { MC "SRV-013" "FTP 서비스 실행 중 - IIS FTP 사이트 미탐지(IIS 6 metabase) Anonymous 설정 수동 확인" }
    default {
        $a13 = @($ftpSites | Where-Object { $_.Anon -eq 'true' } | ForEach-Object { $_.Name })
        $u13 = @($ftpSites | Where-Object { $null -eq $_.Anon } | ForEach-Object { $_.Name })
        if ($a13.Count) { Fail "SRV-013" "IIS FTP Anonymous 인증 활성화 사이트: $($a13 -join ', ')" }
        elseif ($u13.Count) { MC "SRV-013" "IIS FTP Anonymous 설정 미확인 사이트: $($u13 -join ', ') - 수동 확인" }
        else { Pass "SRV-013" "IIS FTP 전 사이트 Anonymous 인증 비활성화" }
    }
}

# ── SRV-018: 하드디스크 기본 공유 비활성화 ──────────────────────
# 평가기준: Windows 2003 이상이면 양호 / 2003 미만은 기본 공유 부재 + AutoShareServer(Wks)=0 이어야 양호
$autoShare = Get-Reg "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" "AutoShareServer"
$shList = Get-ShareList
EvdQ "SRV-018" "공유 목록(Get-SmbShare 또는 Win32_Share) / AutoShareServer,AutoShareWks" ((Format-Shares $shList) + "`nAutoShareServer=$autoShare AutoShareWks=$(Get-Reg 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'AutoShareWks')")
$shares = @(@($shList) | Where-Object { $_ -and $_.Name -match '^\w\$$|^ADMIN\$|^IPC\$' })
if ($build -ge 3790) {
    Pass "SRV-018" "Windows 2003 이상 (Build $build) - 평가기준상 양호 (참고: 기본 공유 $(if ($null -eq $shList) { '목록 조회 실패' } elseif ($shares.Count) { ($shares | ForEach-Object { $_.Name }) -join ',' } else { '없음' }), AutoShareServer=$autoShare)"
} elseif ($null -eq $shList) { CantCheck "SRV-018" "공유 목록 조회 실패(Get-SmbShare·Win32_Share 모두 불가) - net share 로 기본 공유 확인"
} elseif ($shares.Count -or $autoShare -ne 0) {
    Fail "SRV-018" "Windows 2003 미만 - 기본 공유 $(if ($shares.Count) { ($shares | ForEach-Object { $_.Name }) -join ',' } else { '없음' }), AutoShareServer=$autoShare"
} else { Pass "SRV-018" "Windows 2003 미만 - 기본 공유 없음, AutoShareServer=0" }

# ── SRV-020: 공유 접근통제 ──────────────────────────────────────
if ($null -eq $shList) {
    EvdQ "SRV-020" "공유 권한" "(공유 목록 조회 실패)"
    CantCheck "SRV-020" "공유 목록 조회 실패(Get-SmbShare·Win32_Share 모두 불가) - net share 로 Everyone 권한 확인"
} else {
    $vuln020 = @(); $unk020 = @(); $ev020 = @()
    foreach ($s in @($shList | Where-Object { $_.Name -notmatch '^IPC\$$' })) {
        $aces = Get-ShareAceList $s.Name
        $ev020 += "$($s.Name) ($($s.Path))"; $ev020 += (Format-Aces $aces)
        if ($null -eq $aces) { $unk020 += $s.Name; continue }
        # Deny 판단은 AccessControlType 기준 (AccessRight 아님). Everyone 은 SID S-1-1-0 으로 로캘 무관 식별
        if (@($aces | Where-Object { ($_.Sid -eq 'S-1-1-0' -or $_.Account -match 'Everyone|모든 사용자') -and $_.Type -ne 'Deny' }).Count) { $vuln020 += $s.Name }
    }
    EvdQ "SRV-020" "공유별 권한 (계정 [SID] 권한 허용/거부)" ($ev020 -join "`n")
    if ($vuln020.Count) { Fail "SRV-020" "Everyone 접근 공유: $($vuln020 -join ',')$(if ($unk020.Count) { " (ACL 조회 실패 공유: $($unk020 -join ',')" + ')' })" }
    elseif ($unk020.Count) { CantCheck "SRV-020" "공유 ACL 조회 실패: $($unk020 -join ',') (Get-SmbShareAccess·Win32_LogicalShareSecuritySetting 불가) - net share 로 확인" }
    else { Pass "SRV-020" "공유 폴더 Everyone 허용 없음" }
}

# ── SRV-022: 패스워드 미설정 계정 ──────────────────────────────
$accts = @(Get-LocalAccounts)
EvdQ "SRV-022" "로컬 계정 (Name / Enabled / PasswordRequired / LastLogon / PasswordLastSet / 수집원)" (($accts | ForEach-Object { "$($_.Name) / $($_.Enabled) / $($_.PasswordRequired) / $($_.LastLogon) / $($_.PasswordLastSet) / $($_.Src)" }) -join "`n")
# 판단기준: 빈 암호 계정 없음 + '콘솔 로그온 시 로컬 계정에서 빈 암호 사용 제한'(LimitBlankPasswordUse=1)
$lbp = Get-Reg "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "LimitBlankPasswordUse"
EvdQ "SRV-022" "Lsa LimitBlankPasswordUse" "$lbp"
if ($accts.Count -eq 0) { CantCheck "SRV-022" "로컬 계정 조회 실패(Get-LocalUser·WMI 불가 또는 도메인 컨트롤러) - net user 로 확인" }
else {
    $noPw = @($accts | Where-Object { -not $_.PasswordRequired -and $_.Enabled })
    if ($noPw.Count) { Fail "SRV-022" "패스워드 미요구 계정: $(($noPw | ForEach-Object { $_.Name }) -join ',')" }
    elseif ("$lbp" -eq "0") { Fail "SRV-022" "빈 암호 사용 제한 정책 사용 안 함 (LimitBlankPasswordUse=0)" }
    else { Pass "SRV-022" "모든 활성 계정 패스워드 요구, 빈 암호 사용 제한 (LimitBlankPasswordUse=$(if ($null -eq $lbp) { '기본값 1' } else { $lbp }))" }
}

# ── SRV-023: 원격 터미널 암호화 수준 (MinEncryptionLevel ≥ 2 "클라이언트와 호환 가능(중간)") ──
Evd "SRV-023" "Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name MinEncryptionLevel,fDenyTSConnections -EA SilentlyContinue; Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name MinEncryptionLevel -EA SilentlyContinue; Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -EA SilentlyContinue"
$rdpDeny = Get-RdpDeny
$mel = Get-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "MinEncryptionLevel"
if ($null -eq $mel) { $mel = Get-Reg "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" "MinEncryptionLevel" }
if ("$rdpDeny" -eq "1") { Pass "SRV-023" "원격 터미널 서비스 미사용 (fDenyTSConnections=1)" }
elseif ($null -eq $mel) { MC "SRV-023" "MinEncryptionLevel 값 없음 (OS 기본값 적용) - 암호화 수준 수동 확인" }
elseif ([int]$mel -ge 2) { Pass "SRV-023" "RDP 암호화 수준 MinEncryptionLevel=$mel (중간 이상)" }
else { Fail "SRV-023" "RDP 암호화 수준 MinEncryptionLevel=$mel (낮음)" }

# ── SRV-024: 취약 Telnet 인증 ───────────────────────────────────
# 판단기준: 미실행 또는 인증 방법 NTLM만 허용 = 양호 (SecurityMechanism 2=NTLM, 4=Password, 6=둘 다)
Evd "SRV-024" "Get-Service TlntSvr -EA SilentlyContinue | Format-List Name,Status; Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\TelnetServer\1.0' -Name SecurityMechanism -EA SilentlyContinue; if (Get-Command tlntadmn.exe -EA SilentlyContinue) { tlntadmn config }"
$telnet = Get-SvcState "TlntSvr"
$sm024  = Get-Reg "HKLM:\SOFTWARE\Microsoft\TelnetServer\1.0" "SecurityMechanism"
EvdQ "SRV-024" "TlntSvr 상태 / SecurityMechanism" "$(if ($telnet) { "$($telnet.Status)/$($telnet.Start)" } else { '미설치' }) / $sm024"
if (-not $telnet -or $telnet.Status -notmatch "Running") { Pass "SRV-024" "Telnet 서비스 미실행" }
elseif ("$sm024" -eq "2") { Pass "SRV-024" "Telnet 실행 중 - 인증 방식 NTLM만 허용 (SecurityMechanism=2)" }
elseif ($null -eq $sm024) { MC "SRV-024" "Telnet 실행 중 - SecurityMechanism 값 없음, tlntadmn config 인증 방식 확인 (Password 지원 시 취약)" }
else { Fail "SRV-024" "Telnet 실행 중 - Password 인증 허용 (SecurityMechanism=$sm024, NTLM만(2) 필요)" }

# ── SRV-026: root(관리자) 원격 접속 제한 ───────────────────────
# RDP 기본 포트 및 관리자 그룹 원격 접근 확인 (fDenyTSConnections: 그룹 정책 우선)
Evd "SRV-026" "Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services','HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -EA SilentlyContinue | Format-List PSPath,fDenyTSConnections"
$rdpGroup = Get-RdpDeny
if ("$rdpGroup" -eq "1") { Pass "SRV-026" "RDP 원격 접속 비활성화됨 (fDenyTSConnections=1)" }
else { MC "SRV-026" "RDP 활성화(fDenyTSConnections=$(if ($null -eq $rdpGroup) { '값 없음' } else { $rdpGroup })) - 관리자 계정 원격 접속 허용 범위 수동 확인" }

# ── SRV-027: 서비스 접근 IP/포트 제한 (방화벽) ──────────────────
# 판단기준: Windows 방화벽 또는 3rd-Party 방화벽으로 접근통제 → Windows 방화벽이 꺼져 있으면 타사 제품 확인(수동)
# 프로필 켜짐만으로 양호 처리하지 않고 기본 인바운드 동작·전면 허용(any) 규칙도 확인. 클라우드면 보안그룹 병행 확인(수동확인)
$fwp = Get-FwProfiles
$fwRules = Get-FwInboundRules
Evd "SRV-027" "netsh advfirewall show allprofiles"
EvdQ "SRV-027" "방화벽 프로필 (Enabled / 기본 인바운드 / 수집원)" $(if ($null -eq $fwp) { '(Get-NetFirewallProfile·레지스트리 모두 조회 실패)' } else { (@($fwp) | ForEach-Object { "$($_.Name): Enabled=$($_.Enabled) 기본인바운드=$($_.Inbound) [$($_.Src)]" }) -join "`n" })
EvdQ "SRV-027" "활성 인바운드 허용 규칙 (이름 / 프로토콜 / 로컬포트 / 원격주소 / 프로그램 / 전면허용 여부)" $(if ($null -eq $fwRules) { '(FirewallRules 레지스트리 없음)' } else { (@($fwRules) | ForEach-Object { "$($_.Name) | proto=$($_.Proto) | LPort=$($_.LPort) | $($_.RA) | $($_.App) | Any=$($_.Any)" }) -join "`n" })
if ($null -eq $fwp) {
    $fw = netsh advfirewall show currentprofile state 2>$null
    if ($fw -match "State\s+OFF|상태\s+사용 안 함") { MC "SRV-027" "Windows 방화벽 비활성(현재 프로파일, netsh) - 3rd-Party 방화벽 등 접근통제 여부 확인, 없으면 취약" }
    elseif ($fw -match "State\s+ON|상태\s+사용") { MC "SRV-027" "Windows 방화벽 활성(현재 프로파일, netsh) - 기본 인바운드 동작·허용 규칙 수동 확인$(if ($script:CloudKind) { " (클라우드 $($script:CloudKind) 보안그룹: $($script:CloudSG))" })" }
    else { CantCheck "SRV-027" "방화벽 상태 조회 불가(Get-NetFirewallProfile·레지스트리·netsh 모두 실패) - 방화벽 사용 여부 수동 확인$(if ($script:CloudSG) { " (클라우드 보안그룹: $($script:CloudSG))" })" }
} else {
    $act027 = @(Get-NetConnectionProfile -EA SilentlyContinue | ForEach-Object { switch ("$($_.NetworkCategory)") { 'DomainAuthenticated' { 'Domain' } 'Private' { 'Private' } default { 'Public' } } } | Select-Object -Unique)
    EvdQ "SRV-027" "적용 중 네트워크 프로필 (Get-NetConnectionProfile, 2012+; 없으면 전 프로필 대상)" $(if ($act027.Count) { $act027 -join ', ' } else { '(조회 불가 - 모든 프로필을 적용 중으로 간주)' })
    $offAll = @($fwp | Where-Object { -not $_.Enabled } | ForEach-Object { "$($_.Name)" })
    $offAct = @($offAll | Where-Object { $act027.Count -eq 0 -or $act027 -contains $_ })
    $inAllow = @($fwp | Where-Object { $_.Enabled -and "$($_.Inbound)" -eq 'Allow' -and ($act027.Count -eq 0 -or $act027 -contains "$($_.Name)") } | ForEach-Object { "$($_.Name)" })
    $broad = @($fwRules | Where-Object { $_.Any } | ForEach-Object { $_.Name })
    $verdict = if ($offAct.Count) { "방화벽 비활성(프로파일: $($offAct -join ','))" } elseif ($inAllow.Count) { "기본 인바운드 허용(프로파일: $($inAllow -join ','))" } elseif ($broad.Count) { "전면 허용(any) 인바운드 규칙 $($broad.Count)개: $(($broad | Select-Object -First 5) -join ', ')$(if ($broad.Count -gt 5) { ' 외 ' + ($broad.Count - 5) + '건(증적 참조)' })" } else { '' }
    if ($script:CloudKind) {
        MC "SRV-027" "클라우드($($script:CloudKind)) 환경 - 보안그룹/방화벽 규칙(ID: $(if ($script:CloudSG) { $script:CloudSG } else { '확인 불가' }))과 Windows 방화벽 병행 수동 확인. Windows 방화벽: $(if ($verdict) { $verdict } else { '모든 적용 프로파일 활성, 기본 인바운드 차단, 전면 허용 규칙 없음' })"
    } elseif ($offAct.Count) { MC "SRV-027" "Windows 방화벽 비활성(적용 중 프로파일: $($offAct -join ',')) - 3rd-Party 방화벽 등 접근통제 여부 확인, 없으면 취약" }
    elseif ($inAllow.Count -or $broad.Count) { Fail "SRV-027" "Windows 방화벽 접근통제 미흡: $verdict" }
    elseif ($offAll.Count) { Pass "SRV-027" "적용 중 프로파일($($act027 -join ',')) 방화벽 활성, 기본 인바운드 차단 (미적용 프로파일 비활성: $($offAll -join ','))" }
    else { Pass "SRV-027" "Windows 방화벽 모든 프로파일 활성화, 기본 인바운드 차단, 전면 허용 규칙 없음" }
}

# ── SRV-028: 원격 터미널 세션 타임아웃 (RDP MaxIdleTime ≤ 900초) ──
Evd "SRV-028" "Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name MaxIdleTime -EA SilentlyContinue; Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name MaxIdleTime -EA SilentlyContinue"
# 그룹 정책 값이 정의되어 있으면(0=무제한 포함) 그 값이 우선, 없을 때만 로컬 설정
$idle = Get-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "MaxIdleTime"
if ($null -eq $idle) { $idle = Get-Reg "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" "MaxIdleTime" }
EvdQ "SRV-028" "RDP 사용 여부(fDenyTSConnections) / 유휴 제한 MaxIdleTime(ms)" "$(Get-RdpDeny) / $idle"
if ((Get-RdpDeny) -eq "1") { Pass "SRV-028" "RDP 미사용 (fDenyTSConnections=1)" }
elseif ($null -eq $idle -or $idle -eq 0) { Fail "SRV-028" "RDP 유휴 세션 타임아웃(MaxIdleTime) 미설정" }
elseif ($idle -le 900000) { Pass "SRV-028" "RDP 유휴 세션 타임아웃=$([int]($idle/1000))초 (900초 이하)" }
else { Fail "SRV-028" "RDP 유휴 세션 타임아웃=$([int]($idle/1000))초 (900초 초과)" }

# ── SRV-029: SMB 세션 중단 ("로그온 시간 만료 시 강제 로그오프" EnableForcedLogOff=1) ──
Evd "SRV-029" "Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name EnableForcedLogOff,AutoDisconnect -EA SilentlyContinue"
$forced = Get-Reg "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" "EnableForcedLogOff"
if ($null -eq $forced -or $forced -eq 1) { Pass "SRV-029" "로그온 시간 만료 시 강제 로그오프 사용 (EnableForcedLogOff=$(if ($null -eq $forced) { '미정의, OS 기본값 1' } else { 1 }))" }
else { Fail "SRV-029" "로그온 시간 만료 시 강제 로그오프 사용 안 함 (EnableForcedLogOff=$forced)" }

# ── SRV-031: 계정 목록 노출 방지 ───────────────────────────────
Evd "SRV-031" "Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name RestrictAnonymous,RestrictAnonymousSAM -EA SilentlyContinue | Select-Object RestrictAnonymous,RestrictAnonymousSAM"
$ra = Get-Reg "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "RestrictAnonymous"
if ($null -ne $ra -and $ra -ge 1) { Pass "SRV-031" "RestrictAnonymous=$ra (익명 열거 제한)" }
else { Fail "SRV-031" "RestrictAnonymous=$(if ($null -eq $ra) { '미설정' } else { $ra }) (계정 목록 노출 가능)" }

# ── SRV-034: 불필요 서비스 비활성화 ────────────────────────────
# 판단기준(WIN): 1) NetBIOS 2) Alerter·Clipbook·Messenger·Simple TCP/IP 3) WebDAV 4) RDS(ADCLaunch) 가 불필요하게 활성화
Evd "SRV-034" "Get-Service Alerter,ClipSrv,Messenger,simptcp -EA SilentlyContinue | Format-Table Name,Status -AutoSize; Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces' -EA SilentlyContinue | ForEach-Object { '{0} NetbiosOptions={1}' -f `$_.PSChildName,(Get-ItemProperty `$_.PSPath -EA SilentlyContinue).NetbiosOptions }; Get-Item 'HKLM:\SYSTEM\CurrentControlSet\Services\W3SVC\Parameters\ADCLaunch' -EA SilentlyContinue"
$found = @()
foreach ($svc in @(@{n="Alerter";d="Alerter"},@{n="ClipSrv";d="Clipbook"},@{n="Messenger";d="Messenger"},@{n="simptcp";d="Simple TCP/IP"})) {
    $s = Get-SvcState $svc.n
    if ($s -and $s.Status -match "Running") { $found += $svc.d }
}
$review = @()
$nbOn = @(Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces' -EA SilentlyContinue | Where-Object { (Get-ItemProperty $_.PSPath -EA SilentlyContinue).NetbiosOptions -ne 2 })
if ($nbOn.Count -gt 0) { $review += "NetBIOS 활성 인터페이스 $($nbOn.Count)개" }
$ahc34 = "$env:windir\System32\inetsrv\config\applicationHost.config"
$webdav34 = ((Read-AllText $ahc34) -match '<authoring[^>]*enabled="true"')
if ($webdav34) { $review += "WebDAV 활성" }
$adc34 = Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Services\W3SVC\Parameters\ADCLaunch'
EvdQ "SRV-034" "판정 요약 (실행 중 불필요 서비스 / NetBIOS 활성 인터페이스 / WebDAV authoring / ADCLaunch)" "서비스: $(if ($found) { $found -join ',' } else { '없음' }) / NetBIOS 비-2 인터페이스: $($nbOn.Count)개 ($(($nbOn | ForEach-Object { $_.PSChildName }) -join ', ')) / WebDAV: $webdav34 / ADCLaunch: $adc34"
if ($adc34) { $review += "RDS(ADCLaunch) 존재" }
if ($found) { Fail "SRV-034" "불필요 서비스 실행: $($found -join ',')$(if ($review) { ' / 추가 확인: ' + ($review -join ', ') })" }
elseif ($review) { MC "SRV-034" "$($review -join ', ') - 업무상 필요 여부 확인" }
else { Pass "SRV-034" "NetBIOS 비활성, Alerter/Clipbook/Messenger/Simple TCP/IP·WebDAV·RDS 미사용" }

# ── SRV-035: 취약 서비스 비활성화 (Telnet) ──────────────────────
Evd "SRV-035" "Get-Service TlntSvr -EA SilentlyContinue | Format-List Name,Status"
$t = Get-SvcState "TlntSvr"
EvdQ "SRV-035" "TlntSvr 상태" "$(if ($t) { "$($t.Status)/$($t.Start)" } else { '미설치' })"
if ($t -and $t.Status -match "Running") { Fail "SRV-035" "Telnet 서비스 실행 중" }
else { Pass "SRV-035" "Telnet 서비스 미실행" }

# ── SRV-069: 패스워드 최대 사용기간 ────────────────────────────
Evd "SRV-069" "net accounts 2>`$null"
$maxAge = Get-SecPol "MaximumPasswordAge"
if ($null -eq $maxAge) {
    $netOut = net accounts 2>$null
    $line = $netOut | Where-Object {$_ -match "Maximum password age|최대 암호"}
    if ($line) { $maxAge = ($line -replace "[^0-9]","").Trim() }
}
# 판단기준: 비밀번호 관련 정책(2종 10자 / 3종 8자, 변경 기간 90일 이하) 설정 — Windows 복잡도(PasswordComplexity)는 3종 이상 강제
$pwc69 = Get-SecPol "PasswordComplexity"; $min69 = Get-SecPol "MinimumPasswordLength"
EvdQ "SRV-069" "secedit MaximumPasswordAge / MinimumPasswordLength / PasswordComplexity" "$maxAge / $min69 / $pwc69"
if ($null -ne $maxAge -and $maxAge -match "^-?\d+$") {
    $d = [int]$maxAge
    $pol = "최대 사용기간=$(if ($d -le 0) { '무제한' } else { "${d}일" }), 최소 길이=$(if ($null -ne $min69) { "${min69}자" } else { '미확인' }), 복잡도=$(if ($null -ne $pwc69) { $pwc69 } else { '미확인' })"
    if ($d -le 0 -or $d -gt 90) { Fail "SRV-069" "$pol - 변경 기간 90일 이하 필요" }
    elseif ($null -eq $min69 -or $null -eq $pwc69) { CantCheck "SRV-069" "$pol - $(SecWhy '길이/복잡도 정책')" }
    elseif ("$pwc69".Trim() -eq "1" -and [int]$min69 -ge 8) { Pass "SRV-069" "$pol (3종 8자 이상 충족)" }
    elseif ([int]$min69 -ge 10) { MC "SRV-069" "$pol - 복잡도 미사용, 10자 이상: 2종 조합 강제 수단(외부 정책 등) 확인" }
    else { Fail "SRV-069" "$pol - 2종 10자 / 3종 8자 미달" }
} else { CantCheck "SRV-069" "패스워드 최대 사용기간 조회 실패(secedit·net accounts 모두 값 없음)" }

# ── SRV-070: 해독 가능한 암호화를 사용하여 암호 저장 (ClearTextPassword=0) ──
$ctp = Get-SecPol "ClearTextPassword"
EvdQ "SRV-070" "secedit ClearTextPassword" "$ctp"
if ($null -eq $ctp) { CantCheck "SRV-070" "$(SecWhy 'ClearTextPassword 정책') - secpol.msc 암호 정책 수동 확인" }
elseif ("$ctp" -eq "0") { Pass "SRV-070" "해독 가능한 암호화 사용 안 함 (ClearTextPassword=0)" }
else { Fail "SRV-070" "해독 가능한 암호화 사용 (ClearTextPassword=$ctp)" }

# ── SRV-072: Administrator 계정명 변경 ──────────────────────────
# 기본 관리자 계정의 기본 이름은 OS 언어마다 다르므로(Administrator/Administrateur/Administrador/관리자 ...) 알려진 기본 이름이면 '미변경'
$defAdm = @('Administrator','Administrateur','Administrador','Administratör','Amministratore','Beheerder','Administrátor','Rendszergazda','Yönetici','Администратор','管理员','管理者','관리자')
$admin = $accts | Where-Object { $_.SID -match '-500$' } | Select-Object -First 1
$na072 = "$(Get-SecPol 'NewAdministratorName')".Trim().Trim('"')
EvdQ "SRV-072" "기본 관리자(SID-500) / secedit NewAdministratorName" "$(if ($admin) { "$($admin.Name) [$($admin.Src)]" } else { '계정 조회 실패' }) / $na072"
$an072 = if ($admin) { $admin.Name } else { $na072 }
if (-not $an072) { CantCheck "SRV-072" "기본 관리자 계정(SID-500) 조회 실패(Get-LocalUser·WMI·secedit 모두 불가)" }
elseif ($defAdm -contains $an072) { Fail "SRV-072" "Administrator 기본 계정명 미변경 ($an072)" }
else { Pass "SRV-072" "Administrator 계정명 변경됨: $an072" }

# ── SRV-073: 관리자 그룹 불필요 사용자 ─────────────────────────
try {
    Evd "SRV-073" "net localgroup Administrators 2>`$null"
    $members073 = Get-LocalGroupMemberNames 'S-1-5-32-544'; $src073 = 'ADSI'
    if ($null -eq $members073 -or (Cnt $members073) -eq 0) {
        $members073 = @(); $started073 = $false; $src073 = 'net localgroup'
        foreach ($line in (net localgroup Administrators 2>$null)) {
            if ($line -match "^---") { $started073 = $true; continue }
            if ($started073 -and $line.Trim() -ne "" -and $line -notmatch "^The command|^명령을") {
                $members073 += $line.Trim()
            }
        }
    }
    # 평가기준: '불필요한' 관리자 계정 여부 (인원 수 기준 없음) → 구성원 목록 + 인터뷰
    $cnt = Cnt $members073
    EvdQ "SRV-073" "Administrators 구성원 ($src073)" (@($members073) -join "`n")
    if ($cnt -eq 0) { CantCheck "SRV-073" "Administrators 구성원 조회 실패(ADSI·net localgroup 모두 빈 결과)" }
    else { MC "SRV-073" "Administrators 구성원(${cnt}명): $(@($members073) -join ', ') - 불필요 계정 여부 확인" }
} catch { CantCheck "SRV-073" "관리자 그룹 구성원 조회 중 오류: $($_.Exception.Message)" }

# ── SRV-075: 패스워드 복잡도 ───────────────────────────────────
Evd "SRV-075" "net accounts 2>`$null"
$pwc = Get-SecPol "PasswordComplexity"
$minLen = Get-SecPol "MinimumPasswordLength"
EvdQ "SRV-075" "secedit PasswordComplexity / MinimumPasswordLength" "$pwc / $minLen"
# 평가기준: 모든 계정 비밀번호가 복잡도(2종 10자 / 3종 8자) 만족 — 실제 만족 여부는 크랙 시도 필요
if ($null -ne $pwc -and $pwc.Trim() -eq "0") { Fail "SRV-075" "비밀번호 복잡도 정책 비활성 (PasswordComplexity=0)" }
elseif ($null -ne $minLen -and [int]$minLen -lt 8) { Fail "SRV-075" "최소 비밀번호 길이=${minLen}자 (8자 미만)" }
elseif ($null -ne $pwc) { MC "SRV-075" "복잡도 정책 활성, 최소 길이=${minLen}자 - 기존 계정 비밀번호 복잡도 만족 여부(크랙 시도) 확인" }
else { CantCheck "SRV-075" "$(SecWhy '복잡도 정책') - secpol.msc 수동 확인" }

# ── SRV-078: Guest 계정 비활성화 ───────────────────────────────
$g078  = $accts | Where-Object { $_.SID -match '-501$' } | Select-Object -First 1
$eg078 = Get-SecPol "EnableGuestAccount"; $ng078 = "$(Get-SecPol 'NewGuestName')".Trim().Trim('"')
EvdQ "SRV-078" "Guest(SID-501) / secedit EnableGuestAccount / NewGuestName" "$(if ($g078) { "$($g078.Name) Enabled=$($g078.Enabled) [$($g078.Src)]" } else { '계정 조회 실패' }) / $eg078 / $ng078"
if ($g078) { if ($g078.Enabled) { Fail "SRV-078" "Guest 계정(SID-501, 이름 $($g078.Name)) 활성화" } else { Pass "SRV-078" "Guest 계정(이름 $($g078.Name)) 비활성화" } }
elseif ("$eg078".Trim() -eq "1") { Fail "SRV-078" "Guest 계정 활성화 (secedit EnableGuestAccount=1)" }
elseif ("$eg078".Trim() -eq "0") { Pass "SRV-078" "Guest 계정 비활성화 (secedit EnableGuestAccount=0)" }
else { CantCheck "SRV-078" "Guest 계정 상태 조회 실패(Get-LocalUser·WMI·secedit 모두 불가) - net user guest 로 확인" }

# ── SRV-079: Everyone 부적절 권한 ──────────────────────────────
# 판단기준: 'Everyone 사용 권한을 익명 사용자에게 적용' 정책(Lsa\EveryoneIncludesAnonymous) 0=양호 (공유 ACL은 참고 증적)
$ev079 = @()
if ($null -eq $shList) { $ev079 += '(공유 목록 조회 실패)' }
else {
    foreach ($s in @($shList | Where-Object { $_.Name -notmatch '^IPC\$$' })) {
        $aces = Get-ShareAceList $s.Name
        if ($null -eq $aces) { $ev079 += "$($s.Name): ACL 조회 실패"; continue }
        foreach ($a in @($aces | Where-Object { $_.Sid -eq 'S-1-1-0' -or $_.Account -match 'Everyone|모든 사용자' })) { $ev079 += "$($s.Name): $($a.Account) $($a.Right) $($a.Type)" }
    }
}
EvdQ "SRV-079" "공유 중 Everyone 권한 항목 (참고: 판정은 아래 정책값 기준)" $(if ($ev079.Count) { $ev079 -join "`n" } else { '(Everyone 권한이 부여된 공유 없음)' })
$eia = Get-Reg "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "EveryoneIncludesAnonymous"
EvdQ "SRV-079" "Lsa EveryoneIncludesAnonymous" "$eia"
if ("$eia" -eq "1") { Fail "SRV-079" "Everyone 사용 권한을 익명 사용자에게 적용 정책 사용 (EveryoneIncludesAnonymous=1)" }
else { Pass "SRV-079" "Everyone 사용 권한을 익명 사용자에게 적용 안 함 (EveryoneIncludesAnonymous=$(if ($null -eq $eia) { '기본값 0' } else { $eia }))" }

# ── SRV-080: 프린터 드라이버 설치 제한 ─────────────────────────
# 판단방법: LanMan Print Services\Servers AddPrinterDrivers 1=양호, 0=취약 (secedit [Registry Values]는 전체 경로 키라 Get-SecPol로 조회 불가)
$prt = Get-Reg "HKLM:\SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers" "AddPrinterDrivers"
EvdQ "SRV-080" "LanMan Print Services\Servers AddPrinterDrivers" "$prt"
if ("$prt" -eq "1") { Pass "SRV-080" "사용자가 프린터 드라이버를 설치할 수 없게 함 (AddPrinterDrivers=1)" }
elseif ("$prt" -eq "0") { Fail "SRV-080" "사용자 프린터 드라이버 설치 허용 (AddPrinterDrivers=0)" }
else { MC "SRV-080" "AddPrinterDrivers 값 없음 - '사용자가 프린터 드라이버를 설치할 수 없게 함' 정책 수동 확인" }

# ── SRV-084: 시스템 주요 파일 권한 ─────────────────────────────
# 판단기준: SAM 파일 접근 권한이 Administrator, System 그룹에게만 부여
$sam084 = "$env:windir\System32\config\SAM"
EvdQ "SRV-084" "icacls $sam084" ((icacls $sam084 2>&1) | Out-String)
$acl084 = $null; try { $acl084 = Get-Acl $sam084 -EA Stop } catch {}
if (-not $acl084) { CantCheck "SRV-084" "SAM ACL 조회 실패($(if ($script:IsAdmin -eq $false) { '관리자 권한 아님' } else { 'Get-Acl 오류' })) - icacls 증적 확인" }
else {
    $x084 = @()
    foreach ($ace in $acl084.Access) {
        if ("$($ace.AccessControlType)" -ne 'Allow') { continue }
        if (@('S-1-5-18','S-1-5-32-544') -notcontains (Get-AceSid $ace)) { $x084 += "$($ace.IdentityReference)($($ace.FileSystemRights))" }
    }
    if ($x084.Count) { Fail "SRV-084" "SAM 파일에 SYSTEM·Administrators 외 권한: $($x084 -join ', ')" }
    else { Pass "SRV-084" "SAM 파일 권한 SYSTEM·Administrators 만 부여" }
}

# ── SRV-090: 원격 레지스트리 서비스 ────────────────────────────
Evd "SRV-090" "Get-Service RemoteRegistry -EA SilentlyContinue | Format-List Name,Status"
$rr = Get-SvcState "RemoteRegistry"
EvdQ "SRV-090" "RemoteRegistry 상태/시작 유형" "$(if ($rr) { "$($rr.Status)/$($rr.Start)" } else { '미설치' })"
if ($null -eq $rr) { Pass "SRV-090" "RemoteRegistry 서비스 없음" }
elseif ($rr.Status -match "Running") { Fail "SRV-090" "원격 레지스트리 서비스 실행 중" }
elseif ($rr.Start -match "Disabled") { Pass "SRV-090" "원격 레지스트리 비활성화 (Disabled)" }
else { Pass "SRV-090" "원격 레지스트리 중지됨 ($($rr.Start))" }

# ── SRV-092: 사용자 홈 디렉토리 권한 ───────────────────────────
# 판단기준: 사용자별 홈 디렉터리에 Everyone 권한이 없는 경우 양호 (All Users, Default User, Public(공용 폴더) 제외)
$hr092 = "$env:SystemDrive\Users"; if (-not (Test-Path $hr092)) { $hr092 = "$env:SystemDrive\Documents and Settings" }
$hd092 = @(Get-ChildItem $hr092 -EA SilentlyContinue | Where-Object { $_.PSIsContainer -and $_.Name -notmatch '^(All Users|Default|Default User|Public)$' })
$ev092 = @(); $unk092 = @(); $acl092 = @()
foreach ($d in $hd092) {
    $acl = Get-Acl $d.FullName -EA SilentlyContinue
    if (-not $acl) { $unk092 += $d.Name; $acl092 += "$($d.FullName): ACL 조회 실패"; continue }
    $acl092 += "$($d.FullName)"
    foreach ($ace in $acl.Access) {
        $acl092 += "    $($ace.IdentityReference) $($ace.FileSystemRights) $($ace.AccessControlType)"
        if ("$($ace.AccessControlType)" -eq 'Allow' -and (Get-AceSid $ace) -eq 'S-1-1-0') { $ev092 += "$($d.Name)($($ace.FileSystemRights))" }
    }
}
EvdQ "SRV-092" "$hr092 하위 홈 디렉터리별 ACL (icacls 와 동일 정보, Public 제외)" $(if ($acl092.Count) { $acl092 -join "`n" } else { '(홈 디렉터리 없음)' })
if ($hd092.Count -eq 0) { CantCheck "SRV-092" "홈 디렉터리 목록 조회 실패($hr092) - 수동 확인" }
elseif ($ev092.Count) { Fail "SRV-092" "홈 디렉터리 Everyone 권한: $($ev092 -join ', ')" }
elseif ($unk092.Count) { CantCheck "SRV-092" "홈 디렉터리 ACL 조회 실패: $($unk092 -join ', ') (조회된 $($hd092.Count - $unk092.Count)개는 Everyone 권한 없음)" }
else { Pass "SRV-092" "사용자 홈 디렉터리 $($hd092.Count)개 Everyone 권한 없음" }

# ── SRV-097: FTP 디렉토리 접근권한 ─────────────────────────────
# 판단기준: FTP 홈 디렉터리에 Everyone 권한 등 불필요한 권한이 없는 경우 양호
$root097 = @($ftpSites | Where-Object { $_ -and $_.Root } | ForEach-Object { $_.Root } | Select-Object -Unique)
$ev097 = @(); $unk097 = @(); $acl097 = @()
foreach ($r in $root097) {
    $acl = $null; if (Test-Path $r) { $acl = Get-Acl $r -EA SilentlyContinue }
    if (-not $acl) { $unk097 += $r; $acl097 += "${r}: 경로 없음 또는 ACL 조회 실패"; continue }
    $acl097 += $r
    foreach ($ace in $acl.Access) {
        $acl097 += "    $($ace.IdentityReference) $($ace.FileSystemRights) $($ace.AccessControlType)"
        if ("$($ace.AccessControlType)" -eq 'Allow' -and (Get-AceSid $ace) -eq 'S-1-1-0') { $ev097 += "$r(Everyone:$($ace.FileSystemRights))" }
    }
}
EvdQ "SRV-097" "FTP 홈 디렉터리 ACL (IIS FTP 사이트 루트, icacls 와 동일 정보) / 서비스 모드 $ftpMode" $(if ($acl097.Count) { $acl097 -join "`n" } else { '(대상 없음)' })
switch ($ftpMode) {
    'none'     { NA "SRV-097" "FTP 서비스 미실행" }
    'unknown'  { CantCheck "SRV-097" "21번 포트 리슨 여부 조회 불가(netstat 실패)이고 FTPSVC 미실행 - FTP 사용 여부 수동 확인" }
    'third'    { MC "SRV-097" "21번 포트 리슨 중(FTPSVC 미실행, 타사 FTP 추정) - FTP 홈 디렉터리 접근 권한 수동 확인" }
    'iis-fail' { if (Test-Path $ahc) { CantCheck "SRV-097" "FTP 서비스 실행 중이나 IIS 설정 파싱 실패 - FTP 홈 디렉터리 확인 불가" } else { MC "SRV-097" "FTP 서비스 실행 중 - $ftpWhy" } }
    default {
        if ($root097.Count -eq 0) { MC "SRV-097" "FTP 서비스 실행 중 - FTP 홈 디렉터리 미탐지(IIS 외 FTP) 접근 권한 수동 확인" }
        elseif ($ev097.Count) { Fail "SRV-097" "FTP 홈 디렉터리 Everyone 권한: $($ev097 -join ', ')" }
        elseif ($unk097.Count) { CantCheck "SRV-097" "FTP 홈 디렉터리 ACL 조회 실패: $($unk097 -join ', ')" }
        else { Pass "SRV-097" "FTP 홈 디렉터리 Everyone 권한 없음: $($root097 -join ', ')" }
    }
}

# ── SRV-101: 불필요 예약 작업 ───────────────────────────────────
if (Get-Command Get-ScheduledTask -EA SilentlyContinue) {
    $tsk101 = @(Get-ScheduledTask -EA SilentlyContinue | Where-Object { $_.TaskPath -notlike '\Microsoft\*' } | ForEach-Object { Mask-Secret "$($_.TaskPath)$($_.TaskName) [$($_.State)] 실행=$(($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join '; ') 계정=$($_.Principal.UserId)" })
    EvdQ "SRV-101" "Microsoft 외 예약 작업 (Get-ScheduledTask: 경로+이름 [상태] 실행 명령 계정) - $($tsk101.Count)개" $(if ($tsk101.Count) { $tsk101 -join "`n" } else { '(없음)' })
} else { Evd "SRV-101" "schtasks /query /fo LIST /v" }
MC "SRV-101" "예약 작업(Microsoft 기본 작업 제외) 증적 확인 - 불필요 명령/파일 여부 판단"

# ── SRV-103: LAN Manager 인증 수준 ─────────────────────────────
Evd "SRV-103" "Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name LmCompatibilityLevel -EA SilentlyContinue | Select-Object LmCompatibilityLevel"
$lm = Get-Reg "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "LmCompatibilityLevel"
EvdQ "SRV-103" "LmCompatibilityLevel / OS 빌드" "$lm / Build $build"
if ($null -ne $lm -and $lm -ge 3) { Pass "SRV-103" "LM 인증 수준=${lm} (NTLMv2만 허용)" }
elseif ($null -ne $lm) { Fail "SRV-103" "LM 인증 수준=${lm} (3 이상 권고 - NTLMv2)" }
elseif ($build -ge 6001) { Pass "SRV-103" "LmCompatibilityLevel 미설정 - Windows 2008 이상 기본값 3(NTLMv2 응답만 보냄)" }
else { Fail "SRV-103" "LmCompatibilityLevel 미설정 (Windows 2003 이하 기본값=LM/NTLM 허용)" }

# ── SRV-104: 보안 채널 암호화 ───────────────────────────────────
Evd "SRV-104" "Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' -Name RequireSignOrSeal,SealSecureChannel,SignSecureChannel -EA SilentlyContinue"
$sc1 = Get-Reg "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" "RequireSignOrSeal"
$sc2 = Get-Reg "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" "SealSecureChannel"
$sc3 = Get-Reg "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" "SignSecureChannel"
# 판단기준: 3개 값 모두 1이면 양호, 또는 AD 환경이 아닌 경우 양호
$cs104 = Get-CimInstance Win32_ComputerSystem -EA SilentlyContinue
$inDomain = $cs104.PartOfDomain
EvdQ "SRV-104" "Netlogon RequireSignOrSeal / SealSecureChannel / SignSecureChannel, 도메인 가입(PartOfDomain) / 도메인·역할" "$sc1 / $sc2 / $sc3, $inDomain / $($cs104.Domain) 역할=$($cs104.DomainRole)"
if ($sc1 -eq 1 -and $sc2 -eq 1 -and $sc3 -eq 1) { Pass "SRV-104" "보안 채널 서명/암호화 필수 설정됨 (RequireSignOrSeal/SealSecureChannel/SignSecureChannel=1)" }
elseif ($null -ne $inDomain -and -not $inDomain) { Pass "SRV-104" "AD 도메인 미가입 서버 (평가기준상 AD 환경 아님 양호) - RequireSignOrSeal=$sc1, SealSecureChannel=$sc2, SignSecureChannel=$sc3" }
elseif ($null -eq $inDomain) { CantCheck "SRV-104" "도메인 가입 여부 조회 실패(Win32_ComputerSystem) - RequireSignOrSeal=$sc1, SealSecureChannel=$sc2, SignSecureChannel=$sc3" }
else { Fail "SRV-104" "보안 채널 서명/암호화 미설정 (RequireSignOrSeal=$sc1, SealSecureChannel=$sc2, SignSecureChannel=$sc3)" }

# ── SRV-105: 불필요 시작 프로그램 ──────────────────────────────
$st105 = Get-StartupEntries
EvdQ "SRV-105" "시작 프로그램 (Run/RunOnce 키·시작 폴더, 명령행의 password 값은 마스킹) - $($st105.Count)개" $(if ($st105.Count) { $st105 -join "`n" } else { '(없음)' })
MC "SRV-105" "시작 프로그램 $($st105.Count)개 목록(증적) 수동 확인 - 불필요 프로그램 여부 판단"

# ── SRV-108: 로그 접근통제 ──────────────────────────────────────
# 판단기준: Guest 접근(RestrictGuestAccess=0), 감사 및 보안 로그 관리(SeSecurityPrivilege)에 Everyone/Users, 로그 크기 10240KB 미만 → 취약
$bad108 = @(); $unk108 = @(); $inf108 = @()
foreach ($ln in 'Application','Security','System') {
    $svc = "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\$ln"; $pol = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\$ln"
    $rga = Get-Reg $svc 'RestrictGuestAccess'
    $mxK = Get-Reg $pol 'MaxSize'   # 그룹 정책: KB 단위(우선)
    $mxSrc = ''; $mxB = $null
    if ($null -ne $mxK) { $mxB = [int64]$mxK * 1KB; $mxSrc = '정책' }
    else {
        $mxB = Get-LogMaxBytes $ln; $mxSrc = '로그 설정(Get-WinEvent/wevtutil)'
        if ($null -eq $mxB) { $mx2 = Get-Reg $svc 'MaxSize'; if ($null -ne $mx2) { $mxB = [int64]$mx2; $mxSrc = 'EventLog 서비스 키' } }
    }
    $inf108 += "$ln RestrictGuestAccess=$rga MaxSize=$(if ($null -ne $mxB) { '{0}KB' -f [int64]($mxB/1KB) } else { '?' })$(if ($null -ne $mxB) { "($mxSrc)" })"
    if ("$rga" -eq '0') { $bad108 += "$ln Guest 접근 허용" } elseif ($null -eq $rga) { $unk108 += "$ln RestrictGuestAccess 없음" }
    if ($null -eq $mxB) { $unk108 += "$ln MaxSize 조회 불가" } elseif ([int64]$mxB -lt 10240KB) { $bad108 += "$ln 로그 크기 $([int64]($mxB/1KB))KB(<10240KB)" }
}
$sp108 = Test-SecPolGroups "SeSecurityPrivilege" @("Everyone","Users")
if ($sp108[1].Count) { $bad108 += "감사 및 보안 로그 관리 권한에 $($sp108[1] -join ',')" } elseif ($null -eq $sp108[0]) { $unk108 += "SeSecurityPrivilege 확인 실패" }
$sn108 = @(($sp108[0] -split ',') | Where-Object { $_ } | ForEach-Object { Resolve-SecPolEntry $_ })
EvdQ "SRV-108" "EventLog RestrictGuestAccess/MaxSize, secedit SeSecurityPrivilege" "$($inf108 -join "`n")`nSeSecurityPrivilege = $($sp108[0]) => $($sn108 -join ', ')"
if ($bad108.Count) { Fail "SRV-108" "$($bad108 -join ', ')" }
elseif ($unk108.Count) { MC "SRV-108" "$($unk108 -join ', ') - 이벤트 로그 접근 권한 수동 확인" }
else { Pass "SRV-108" "이벤트 로그 Guest 접근 제한, 보안 로그 관리 권한 Everyone/Users 없음, 크기 10240KB 이상" }

# ── SRV-109: 주요 이벤트 로그 설정 ─────────────────────────────
Evd "SRV-109" "auditpol /get /category:* 2>`$null"
# 판단기준 감사 파라미터: AccountManage 1|3, LogonEvents 3, DSAccess 1|3(도메인 컨트롤러만 해당), AccountLogon 1|3, SystemEvents 3, PolicyChange 1|3
$isDC = (Get-CimInstance Win32_ComputerSystem -EA SilentlyContinue).DomainRole -ge 4
$auditReq = @{ AuditAccountManage="13"; AuditLogonEvents="3"; AuditAccountLogon="13"; AuditSystemEvents="3"; AuditPolicyChange="13"; AuditDSAccess="13" }
$auditKeys = @('AuditAccountManage','AuditLogonEvents','AuditAccountLogon','AuditSystemEvents','AuditPolicyChange'); if ($isDC) { $auditKeys += 'AuditDSAccess' }
$auditVals = @(); $auditBad = @(); $auditNull = 0
foreach ($k in $auditKeys) {
    $v = Get-SecPol $k
    if ($null -eq $v) { $auditNull++; $auditVals += "$k=?"; continue }
    $v = "$v".Trim(); $auditVals += "$k=$v"
    if (-not $auditReq[$k].Contains($v) -or $v -eq "0") { $auditBad += "$k=$v" }
}
EvdQ "SRV-109" "secedit [Event Audit] 감사 파라미터$(if (-not $isDC) { ' (DSAccess: DC 아님 제외)' })" ($auditVals -join ", ")
if ($auditNull -eq $auditKeys.Count) { CantCheck "SRV-109" "$(SecWhy '감사 정책') - secpol.msc 감사 정책 수동 확인" }
elseif ($auditBad.Count -eq 0) { Pass "SRV-109" "감사 설정 기준 충족: $($auditVals -join ', ')" }
elseif ((auditpol /get /category:* 2>$null) -match "Success|Failure|성공|실패") { MC "SRV-109" "레거시 감사 정책 기준 미달($($auditBad -join ', ')) - 고급 감사 정책(auditpol) 설정 존재, 동등 여부 수동 확인" }
else { Fail "SRV-109" "감사 설정 기준 미달: $($auditBad -join ', ')" }

# ── SRV-116: 감사 실패 시 시스템 종료 ──────────────────────────
# 판단기준: crashonauditfail 0=양호, 0이 아님(1,2)=취약
$auditFail = Get-Reg "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "CrashOnAuditFail"
EvdQ "SRV-116" "Lsa CrashOnAuditFail" "$auditFail"
if ($null -eq $auditFail -or "$auditFail" -eq "0") { Pass "SRV-116" "보안 감사를 로그할 수 없는 경우 즉시 시스템 종료 사용 안 함 (CrashOnAuditFail=$(if ($null -eq $auditFail) { '기본값 0' } else { 0 }))" }
else { Fail "SRV-116" "보안 감사를 로그할 수 없는 경우 즉시 시스템 종료 사용 (CrashOnAuditFail=$auditFail)" }

# ── SRV-118: 보안패치 ───────────────────────────────────────────
Evd "SRV-118" "Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -EA SilentlyContinue | Select-Object CurrentBuild,UBR,DisplayVersion | Format-List; Get-HotFix -EA SilentlyContinue | Sort-Object InstalledOn -Descending | Select-Object HotFixID,Description,InstalledOn | Format-Table -AutoSize"
$hf118 = $null; $hfErr118 = ''
try { $hf118 = @(Get-HotFix -EA Stop) } catch { $hfErr118 = $_.Exception.Message }
$hotfix = $hf118 | Where-Object { $_.InstalledOn } | Sort-Object InstalledOn -Descending | Select-Object -First 1
if ($hfErr118 -and (Cnt $hf118) -eq 0) { CantCheck "SRV-118" "핫픽스 조회 실패(Get-HotFix/WMI QFE): $hfErr118 - 보안패치 현황 수동 확인" }
elseif ($hotfix) { MC "SRV-118" "최근 핫픽스: $($hotfix.HotFixID) ($($hotfix.InstalledOn)), 총 $(Cnt $hf118)건 - 최신 누적 업데이트 적용 여부 수동 확인" }
else { MC "SRV-118" "핫픽스 설치 이력 없음 또는 설치일 미확인(총 $(Cnt $hf118)건) - 보안패치 현황 수동 확인" }

# ── SRV-119: 백신 업데이트 ─────────────────────────────────────
# 백신 공통 수집: 실행 중 서비스(서비스 이름/표시명) + 설치 목록 + Defender 상태 (SecurityCenter2 는 클라이언트 SKU 전용)
$avKw  = '(?i)(microsoft|windows) defender|\bV3\b|ahnlab|alyac|virobot|hauri|sophos|symantec|endpoint protection|mcafee|trellix|trend ?micro|apex ?one|kaspersky|eset|bitdefender|avast|avira|cylance|crowdstrike|falcon|sentinel ?one|antivirus|anti-?malware|백신'
$avSvc = @(Get-Service -EA SilentlyContinue | Where-Object { "$($_.Status)" -eq 'Running' -and ($_.Name -match '^(WinDefend|WdNisSvc)$' -or ($_.DisplayName -match $avKw -and $_.DisplayName -notmatch '(?i)firewall|방화벽')) })
$mp    = if (Get-Command Get-MpComputerStatus -EA SilentlyContinue) { Get-MpComputerStatus -EA SilentlyContinue } else { $null }
$avUn  = @(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' -EA SilentlyContinue | Where-Object { $_.DisplayName -match $avKw } | ForEach-Object { "$($_.DisplayName) $($_.DisplayVersion)" })
$avSc  = @(Get-CimInstance -Namespace "root/SecurityCenter2" -ClassName AntiVirusProduct -EA SilentlyContinue)
EvdQ "SRV-119" "Defender 상태 (Get-MpComputerStatus)" $(if ($mp) { "AMServiceEnabled=$($mp.AMServiceEnabled) AntivirusEnabled=$($mp.AntivirusEnabled) RealTime=$($mp.RealTimeProtectionEnabled) SignatureVersion=$($mp.AntivirusSignatureVersion) SignatureLastUpdated=$($mp.AntivirusSignatureLastUpdated) EngineVersion=$($mp.AMEngineVersion)" } else { 'Get-MpComputerStatus 없음(2008 R2~2012 R2 또는 Defender 미사용)' })
EvdQ "SRV-119" "실행 중 백신 서비스 (이름 / 표시명)" $(if ($avSvc.Count) { (($avSvc | ForEach-Object { "$($_.Name) / $($_.DisplayName)" }) -join "`n") } else { '(없음)' })
EvdQ "SRV-119" "SecurityCenter2 AntiVirusProduct / 설치 프로그램 목록(백신 키워드 일치)" "SecurityCenter2: $(($avSc | ForEach-Object { $_.displayName }) -join ', ')`n설치 목록: $($avUn -join ', ')"
MC "SRV-119" "백신 업데이트 주기 확인 (엔진/패턴 버전·업데이트 절차)$(if ($mp) { " - Defender 서명 갱신: $($mp.AntivirusSignatureLastUpdated)" })"

# ── SRV-123: 최종 로그인 사용자 계정 노출 방지 ──────────────────
Evd "SRV-123" "Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System','HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name DontDisplayLastUserName -EA SilentlyContinue | Select-Object PSPath,DontDisplayLastUserName"
# 판단방법: Policies\System\DontDisplayLastUserName (1: 양호, 0: 취약), 구버전 Winlogon 경로 보조
$hideUser = Get-Reg "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "DontDisplayLastUserName"
if ($null -eq $hideUser) { $hideUser = Get-Reg "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" "DontDisplayLastUserName" }
if ($null -ne $hideUser -and $hideUser -eq 1) { Pass "SRV-123" "로그인 화면 마지막 사용자 표시 안 함 (DontDisplayLastUserName=1)" }
else { Fail "SRV-123" "로그인 화면에 마지막 사용자 계정 표시됨 (DontDisplayLastUserName=$(if ($null -eq $hideUser) { '미설정' } else { $hideUser }))" }

# ── SRV-125: 화면 보호기 ────────────────────────────────────────
# 실행 계정(HKCU) 기준. 대기 시간 상한은 W-47(주요정보)과 같은 10분(600초)
Evd "SRV-125" "Get-ItemProperty 'HKCU:\Control Panel\Desktop' -Name ScreenSaveActive,ScreenSaveTimeOut,ScreenSaverIsSecure -EA SilentlyContinue; Get-ItemProperty 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop' -EA SilentlyContinue"
$pol = "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop"; $usr = "HKCU:\Control Panel\Desktop"
$ssA = Get-Reg $pol "ScreenSaveActive";   if ($null -eq $ssA) { $ssA = Get-Reg $usr "ScreenSaveActive" }
$ssT = Get-Reg $pol "ScreenSaveTimeOut";  if ($null -eq $ssT) { $ssT = Get-Reg $usr "ScreenSaveTimeOut" }
$ssS = Get-Reg $pol "ScreenSaverIsSecure"; if ($null -eq $ssS) { $ssS = Get-Reg $usr "ScreenSaverIsSecure" }
EvdQ "SRV-125" "화면보호기 사용 / 대기(초) / 암호 (정책 우선 → 실행 계정 HKCU)" "$ssA / $ssT / $ssS"
if ("$ssA" -eq "1" -and "$ssS" -eq "1" -and $ssT -and [int]$ssT -gt 0 -and [int]$ssT -le 600) { Pass "SRV-125" "화면보호기 사용·자동 시작(${ssT}초)·암호 설정" }
else { Fail "SRV-125" "화면보호기 설정 미흡 (ScreenSaveActive=$ssA, ScreenSaveTimeOut=$ssT, ScreenSaverIsSecure=$ssS; 기준: 사용=1, 시작 시간 600초 이하, 암호=1; 실행 계정 기준)" }

# ── SRV-126: 자동 로그온 방지 ───────────────────────────────────
Evd "SRV-126" "Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name AutoAdminLogon,DefaultUserName -EA SilentlyContinue | Select-Object AutoAdminLogon,DefaultUserName"
$dp126 = Get-Reg "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" "DefaultPassword"
EvdQ "SRV-126" "Winlogon DefaultPassword (값·길이 비공개, 존재 여부만)" $(if ($null -eq $dp126) { '없음' } else { '존재 (값 비공개)' })
$autoLogon = Get-Reg "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" "AutoAdminLogon"
EvdQ "SRV-126" "Winlogon AutoAdminLogon" "$autoLogon"
if ($null -ne $autoLogon -and $autoLogon -eq "1") { Fail "SRV-126" "자동 로그온 활성화됨 (AutoAdminLogon=1)" }
else { Pass "SRV-126" "자동 로그온 비활성화됨 (AutoAdminLogon=$(if ($null -eq $autoLogon) { '없음' } else { $autoLogon }))" }

# ── SRV-127: 로그인 실패 횟수 제한 ─────────────────────────────
Evd "SRV-127" "net accounts 2>`$null"
$lockout = Get-SecPol "LockoutBadCount"
if ($null -eq $lockout) {
    $netOut = net accounts 2>$null
    $line   = $netOut | Where-Object {$_ -match "Lockout threshold|잠금 임계"}
    if ($line) { $lockout = ($line -replace "[^0-9]","").Trim() }
}
EvdQ "SRV-127" "계정 잠금 임계값 (secedit LockoutBadCount, 없으면 net accounts)" "$lockout"
if ($null -ne $lockout -and $lockout -match "^\d+$") {
    $cnt = [int]$lockout
    if ($cnt -eq 0) { Fail "SRV-127" "계정 잠금 임계값=0 (무제한)" }
    elseif ($cnt -le 5) { Pass "SRV-127" "계정 잠금 임계값=${cnt}회 설정" }
    else { Fail "SRV-127" "계정 잠금 임계값=${cnt}회 (5회 이하 필요 - W-04 와 동일 기준)" }
} else { CantCheck "SRV-127" "계정 잠금 임계값 조회 실패(secedit·net accounts 모두 값 없음)" }

# ── SRV-128: NTFS 파일 시스템 ───────────────────────────────────
$fixedVols = @()
if (Get-Command Get-Volume -EA SilentlyContinue) {
    $fixedVols = @(Get-Volume -EA SilentlyContinue | Where-Object { "$($_.DriveType)" -eq "Fixed" -and $_.DriveLetter } | ForEach-Object { New-Object PSObject -Property @{ Id="$($_.DriveLetter):"; FS="$($_.FileSystemType)"; Src='Get-Volume' } })
}
if ($fixedVols.Count -eq 0) {   # Get-Volume 없음(2008 R2)·실패 시 WMI
    $fixedVols = @(Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" -EA SilentlyContinue | ForEach-Object { New-Object PSObject -Property @{ Id="$($_.DeviceID)"; FS="$($_.FileSystem)"; Src='Win32_LogicalDisk' } })
}
EvdQ "SRV-128" "고정(로컬) 디스크 파일 시스템 (Get-Volume 또는 Win32_LogicalDisk)" $(if ($fixedVols.Count) { (($fixedVols | ForEach-Object { "$($_.Id) $($_.FS) [$($_.Src)]" }) -join "`n") } else { '(조회 결과 없음)' })
if ($fixedVols.Count -eq 0) { CantCheck "SRV-128" "드라이브 파일 시스템 조회 실패(Get-Volume·Win32_LogicalDisk 모두 불가) - 수동 확인" }
else {
    $fat = @($fixedVols | Where-Object { $_.FS -match '^(FAT|FAT16|FAT32|exFAT)$' })
    $odd = @($fixedVols | Where-Object { $_.FS -notmatch '^(NTFS|ReFS|CSVFS|FAT|FAT16|FAT32|exFAT)$' })   # RAW·빈 값·Unknown 포함
    if ($fat.Count) { Fail "SRV-128" "FAT 파일 시스템 로컬 드라이브: $(($fat | ForEach-Object { "$($_.Id)($($_.FS))" }) -join ',')" }
    elseif ($odd.Count) { MC "SRV-128" "파일 시스템 확인 필요(RAW·미확인 포함): $(($odd | ForEach-Object { "$($_.Id)($(if ($_.FS) { $_.FS } else { '빈 값' }))" }) -join ',')" }
    else { Pass "SRV-128" "로컬 드라이브 FAT 미사용 (NTFS/ReFS/CSVFS): $(($fixedVols | ForEach-Object { "$($_.Id)($($_.FS))" }) -join ',')" }
}

# ── SRV-129: 백신 설치 ──────────────────────────────────────────
# SRV-119와 동일 (별도 메시지)
EvdQ "SRV-129" "실행 중 백신 서비스 / 설치 목록 / SecurityCenter2" "$(($avSvc | ForEach-Object { "$($_.Name)($($_.DisplayName))" }) -join ', ') / $($avUn -join ', ') / $(($avSc | ForEach-Object { $_.displayName }) -join ', ')"
if ($avSvc.Count) { Pass "SRV-129" "백신 실행 중: $(($avSvc | ForEach-Object { $_.DisplayName }) -join ', ')" }
elseif ($avSc.Count) { Pass "SRV-129" "백신 설치됨: $(($avSc | Select-Object -First 1).displayName)" }
else { MC "SRV-129" "백신 서비스 미탐지 - 설치 프로그램 목록(증적)·tasklist 로 백신 설치 여부 확인" }

# ── SRV-135: TCP 보안 설정 ──────────────────────────────────────
Evd "SRV-135" "Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' -Name SynAttackProtect,TcpMaxHalfOpen,TcpMaxHalfOpenRetried,DeadGWDetectDefault,IPEnableRouter -EA SilentlyContinue"
# 판단기준: [2008 이상] IPEnableRouter=0 / [2008 미만] SynAttackProtect=1, TcpMaxHalfOpen≤0x500, TcpMaxHalfOpenRetried≤0x400, DeadGWDetectDefault=1, IPEnableRouter=0
$tcpP = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
$ipr = Get-Reg $tcpP "IPEnableRouter"
EvdQ "SRV-135" "Tcpip\Parameters IPEnableRouter (OS 빌드 $build)" "$ipr"
if ($build -ge 6001) {
    if ($null -eq $ipr -or "$ipr" -eq "0") { Pass "SRV-135" "IPEnableRouter=$(if ($null -eq $ipr) { '기본값 0' } else { 0 }) (Windows 2008 이상 기준)" }
    else { Fail "SRV-135" "IPEnableRouter=$ipr (IP 라우팅 활성 - 0 필요)" }
} else {
    $syn = Get-Reg $tcpP "SynAttackProtect"; $tho = Get-Reg $tcpP "TcpMaxHalfOpen"; $thr = Get-Reg $tcpP "TcpMaxHalfOpenRetried"; $dgw = Get-Reg $tcpP "DeadGWDetectDefault"
    EvdQ "SRV-135" "SynAttackProtect / TcpMaxHalfOpen / TcpMaxHalfOpenRetried / DeadGWDetectDefault" "$syn / $tho / $thr / $dgw"
    $bad135 = @()
    if ("$syn" -ne "1") { $bad135 += "SynAttackProtect=$syn" }
    if ($null -eq $tho -or $tho -gt 0x500) { $bad135 += "TcpMaxHalfOpen=$tho" }
    if ($null -eq $thr -or $thr -gt 0x400) { $bad135 += "TcpMaxHalfOpenRetried=$thr" }
    if ("$dgw" -ne "1") { $bad135 += "DeadGWDetectDefault=$dgw" }
    if ($null -ne $ipr -and "$ipr" -ne "0") { $bad135 += "IPEnableRouter=$ipr" }
    if ($bad135) { Fail "SRV-135" "DoS 방어 레지스트리 미설정(2008 미만): $($bad135 -join ', ')" }
    else { Pass "SRV-135" "DoS 방어 레지스트리 5개 값 기준 충족 (2008 미만)" }
}

# ── SRV-136: 로그온 단계 시스템 종료 기능 비활성화 ──────────────
# 판단기준: ShutdownWithoutLogon 0 + '원격 시스템에서 강제로 시스템 종료'(SeRemoteShutdownPrivilege) 불필요 부여 없음
$noShutdown = Get-Reg "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "ShutdownWithoutLogon"
if ($null -eq $noShutdown) { $noShutdown = Get-Reg "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" "ShutdownWithoutLogon" }
$rs = Test-SecPolGroups "SeRemoteShutdownPrivilege" @("Everyone","Users","Guests","Anonymous","Authenticated Users")
EvdQ "SRV-136" "ShutdownWithoutLogon / SeRemoteShutdownPrivilege" "$noShutdown / $($rs[0])"
if ("$noShutdown" -eq "1") { Fail "SRV-136" "로그온하지 않고 시스템 종료 허용 (ShutdownWithoutLogon=1)" }
elseif ($rs[1].Count -gt 0) { Fail "SRV-136" "원격 시스템에서 강제 종료 권한 불필요 부여: $($rs[1] -join ',')" }
elseif ($null -eq $noShutdown) { MC "SRV-136" "ShutdownWithoutLogon 값 없음 - 로그온하지 않고 시스템 종료 허용 정책 수동 확인 (원격 강제 종료 권한: $($rs[0]))" }
elseif ($null -eq $rs[0]) { CantCheck "SRV-136" "로그온 전 종료 사용 안 함(ShutdownWithoutLogon=0)이나 $(SecWhy '원격 강제 종료 권한(SeRemoteShutdownPrivilege)')" }
else { Pass "SRV-136" "로그온 전 종료 사용 안 함 (ShutdownWithoutLogon=0), 원격 강제 종료 권한 불필요 그룹 없음" }

# ── SRV-140: 이동식 미디어 제한 ─────────────────────────────────
Evd "SRV-140" "Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name AllocateDASD -EA SilentlyContinue | Select-Object AllocateDASD"
# 판단기준: '이동식 미디어 포맷 및 꺼내기 허용' = Administrators(AllocateDASD 0) 이면 양호 — 값 없음(정책 미정의)은 OS 기본 Administrators
$dasd = Get-Reg "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" "AllocateDASD"
EvdQ "SRV-140" "Winlogon AllocateDASD (0=Administrators, 1=+Power Users, 2=+Interactive Users)" "$dasd"
if ($null -eq $dasd -or "$dasd" -eq "" -or "$dasd" -eq "0") { Pass "SRV-140" "이동식 미디어 포맷 및 꺼내기 허용: Administrators (AllocateDASD=$(if ($null -eq $dasd -or "$dasd" -eq '') { '미정의(기본 Administrators)' } else { 0 }))" }
else { Fail "SRV-140" "이동식 미디어 포맷 및 꺼내기 허용이 Administrators 외 사용자에게 허용 (AllocateDASD=$dasd)" }

# ── SRV-149: 디스크 볼륨 암호화 ────────────────────────────────
# 모든 로컬 볼륨이 보호(On)여야 양호. Get-BitLockerVolume(2012+) 없으면 WMI(Win32_EncryptableVolume, 관리자 필요)
$blv = $null; $blSrc = ''; $blErr = ''
if (Get-Command Get-BitLockerVolume -EA SilentlyContinue) {
    try { $blv = @(Get-BitLockerVolume -EA Stop | ForEach-Object { New-Object PSObject -Property @{ Mount="$($_.MountPoint)"; Prot="$($_.ProtectionStatus)" } }); $blSrc = 'Get-BitLockerVolume' } catch { $blv = $null; $blErr = $_.Exception.Message }
}
if ($null -eq $blv) {
    try {
        $wv = @(Get-WmiObject -Namespace 'root\CIMV2\Security\MicrosoftVolumeEncryption' -Class Win32_EncryptableVolume -EA Stop)
        $blv = @($wv | ForEach-Object { $ps149 = $_.GetProtectionStatus(); New-Object PSObject -Property @{ Mount="$($_.DriveLetter)"; Prot=$(switch ([int]$ps149.ProtectionStatus) { 1 { 'On' } 0 { 'Off' } default { 'Unknown' } }) } })
        $blSrc = 'Win32_EncryptableVolume'
    } catch { $blv = $null; $blErr += " $($_.Exception.Message)" }
}
EvdQ "SRV-149" "BitLocker 볼륨 보호 상태 ($blSrc)" $(if ($null -ne $blv) { (($blv | ForEach-Object { "$($_.Mount) $($_.Prot)" }) -join "`n") } else { "(조회 실패) $blErr" })
if ($null -eq $blv) {
    if ($script:IsAdmin -eq $false) { CantCheck "SRV-149" "디스크 암호화 상태 조회 불가 - 관리자 권한 아님(BitLocker WMI/cmdlet 은 관리자 필요)" }
    else { MC "SRV-149" "BitLocker 기능/WMI 클래스 없음 또는 조회 오류($($blErr.Trim())) - 타사 디스크 암호화·TDE 적용 또는 예외(IDC 등 물리적 보호 장소, 디스크 폐기 규정) 해당 여부 수동 확인" }
} else {
    $blOn = @($blv | Where-Object { "$($_.Prot)" -match '^(On|1)$' }); $blOff = @($blv | Where-Object { "$($_.Prot)" -notmatch '^(On|1)$' })
    if ($blv.Count -gt 0 -and $blOff.Count -eq 0) { Pass "SRV-149" "BitLocker 전 볼륨 보호 적용: $(($blOn | ForEach-Object { $_.Mount }) -join ',')" }
    elseif ($blOn.Count) { MC "SRV-149" "BitLocker 일부 볼륨만 보호(적용: $(($blOn | ForEach-Object { $_.Mount }) -join ','), 미적용: $(($blOff | ForEach-Object { $_.Mount }) -join ',')) - 미적용 볼륨의 예외 사유 확인, 없으면 취약" }
    else { MC "SRV-149" "BitLocker 미적용 - 예외(IDC 등 물리적 보호 장소, 디스크 폐기 규정 수행) 해당 여부 확인, 미해당 시 취약" }
}

# ── SRV-150: 로컬 로그온 허용 계정 제한 ─────────────────────────
# 판단기준: 로컬 로그온 허용 정책에 Administrators, IUSR_ 만 존재하면 양호
$v150 = Get-SecPol "SeInteractiveLogonRight"
if ($null -eq $v150) { EvdQ "SRV-150" "secedit SeInteractiveLogonRight" "(조회 실패)"; CantCheck "SRV-150" "$(SecWhy '로컬 로그온 허용 정책') - secpol.msc 확인" }
else {
    $ents = @($v150 -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    EvdQ "SRV-150" "secedit SeInteractiveLogonRight" "$v150`n→ $(($ents | ForEach-Object { Resolve-SecPolEntry $_ }) -join ', ')"
    $extra = @($ents | Where-Object { $_ -ne '*S-1-5-32-544' -and $_ -ne '*S-1-5-17' -and $_ -notmatch '^IUSR' -and (Resolve-SecPolEntry $_) -notmatch '\\IUSR' })
    $gen   = @($extra | Where-Object { @('*S-1-1-0','*S-1-5-32-545','*S-1-5-32-546','*S-1-5-11') -contains $_ })
    if ($extra.Count -eq 0) { Pass "SRV-150" "로컬 로그온 허용: Administrators(및 IUSR)만 존재" }
    elseif ($gen.Count) { Fail "SRV-150" "로컬 로그온 허용에 일반 사용자 그룹: $(($gen | ForEach-Object { Resolve-SecPolEntry $_ }) -join ', ')" }
    else { MC "SRV-150" "로컬 로그온 허용에 Administrators 외: $(($extra | ForEach-Object { Resolve-SecPolEntry $_ }) -join ', ') - 불필요 여부 확인" }
}

# ── SRV-151: 익명 SID/이름 변환 제한 ───────────────────────────
# 판단기준: '네트워크 액세스: 익명 SID/이름 변환 허용' 사용 안 함 (secedit [System Access] LSAAnonymousNameLookup=0)
$sidEnum = Get-SecPol "LSAAnonymousNameLookup"
EvdQ "SRV-151" "secedit LSAAnonymousNameLookup" "$sidEnum"
if ($null -eq $sidEnum) { CantCheck "SRV-151" "$(SecWhy '익명 SID/이름 변환 허용 정책') - secpol.msc 수동 확인" }
elseif ("$sidEnum".Trim() -eq "0") { Pass "SRV-151" "익명 SID/이름 변환 허용 사용 안 함 (LSAAnonymousNameLookup=0)" }
else { Fail "SRV-151" "익명 SID/이름 변환 허용 사용 (LSAAnonymousNameLookup=$sidEnum)" }

# ── SRV-152: 원격 터미널 접속 그룹 제한 ────────────────────────
# 판단기준: 관리자 외 원격 접속 전용 계정이 있고 원격 접속 그룹에 불필요한 계정이 없으면 양호 / 별도 계정 없으면 취약
$deny152 = Get-RdpDeny
$rdu152 = Get-LocalGroupMemberNames 'S-1-5-32-555'
$rir152 = Get-SecPol 'SeRemoteInteractiveLogonRight'
EvdQ "SRV-152" "fDenyTSConnections / Remote Desktop Users(S-1-5-32-555) / SeRemoteInteractiveLogonRight" "$deny152 / $(if ($null -eq $rdu152) { '조회 실패' } elseif ((Cnt $rdu152) -eq 0) { '(구성원 없음)' } else { @($rdu152) -join ', ' }) / $rir152 → $((($rir152 -split ',') | Where-Object { $_ } | ForEach-Object { Resolve-SecPolEntry $_ }) -join ', ')"
if ("$deny152" -eq '1') { Pass "SRV-152" "원격 터미널 서비스 미사용 (fDenyTSConnections=1)" }
elseif ($null -eq $rdu152) { CantCheck "SRV-152" "Remote Desktop Users 구성원 조회 실패(ADSI) - 원격 접속 계정 수동 확인" }
elseif ((Cnt $rdu152) -eq 0) { Fail "SRV-152" "관리자 외 원격 접속 전용 계정 없음 (Remote Desktop Users 비어 있음)" }
else { MC "SRV-152" "Remote Desktop Users: $(@($rdu152) -join ', ') - 불필요 계정 여부 확인" }

# ── SRV-158: Telnet 서비스 비활성화 ─────────────────────────────
# SRV-035와 동일
Evd "SRV-158" "Get-Service TlntSvr -EA SilentlyContinue | Format-List Name,Status"
$t = Get-SvcState "TlntSvr"
$l23 = Get-Listen 23
EvdQ "SRV-158" "TlntSvr 상태 / TCP 23 리슨 (netstat -ano)" "$(if ($t) { "$($t.Status)/$($t.Start)" } else { '미설치' })`n$(Format-Listen $l23)"
if (($t -and $t.Status -match "Running") -or (Cnt $l23)) { Fail "SRV-158" "Telnet 서비스 동작 중 (TlntSvr/23번 포트)" }
elseif ($null -eq $l23) { CantCheck "SRV-158" "23번 포트 리슨 조회 불가(netstat 실패), TlntSvr 는 미실행" }
else { Pass "SRV-158" "Telnet 서비스 미실행 (23번 포트 리슨 없음)" }

# ── SRV-163: 시스템 배너 ─────────────────────────────────────────
# 판단방법: Winlogon 레지스트리 또는 secpol(보안 옵션 → Policies\System 에 저장)
$lnPol = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
$lnWl  = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
Evd "SRV-163" "Get-ItemProperty '$lnPol','$lnWl' -Name LegalNoticeCaption,LegalNoticeText -EA SilentlyContinue | Select-Object PSPath,LegalNoticeCaption,LegalNoticeText | Format-List"
$lnv = { param($p,$n) $v = Get-Reg $p $n; if ($v -is [array]) { $v = $v -join ' ' }; "$v".Trim() }   # REG_MULTI_SZ 대응
$capP = & $lnv $lnPol 'LegalNoticeCaption'; $txtP = & $lnv $lnPol 'LegalNoticeText'
$capW = & $lnv $lnWl  'LegalNoticeCaption'; $txtW = & $lnv $lnWl  'LegalNoticeText'
$banner = if ($capP) { $capP } else { $capW }; $bannerText = if ($txtP) { $txtP } else { $txtW }
$src163 = if ($capP -or $txtP) { '보안 정책(Policies\System)' } else { 'Winlogon' }
if ($banner -and $bannerText) { Pass "SRV-163" "시스템 사용 주의사항 배너 설정됨 ($src163): $banner" }
elseif ($banner -or $bannerText) { Fail "SRV-163" "로그온 경고 $(if ($banner) { '내용' } else { '제목' }) 미설정 ($src163)" }
else { Fail "SRV-163" "시스템 사용 주의사항(LegalNoticeCaption/Text) 미설정 (Policies\System·Winlogon 모두 빈 값)" }

# ── SRV-166: 불필요 숨김 파일 ───────────────────────────────────
Evd "SRV-166" "`$sys='^(\`$Recycle\.Bin|System Volume Information|pagefile\.sys|hiberfil\.sys|swapfile\.sys|Recovery|ProgramData|Documents and Settings|bootmgr|BOOTNXT|DumpStack\.log(\.tmp)?|Config\.Msi|AppData|NTUSER.*|ntuser.*|Application Data|Local Settings|Cookies|NetHood|PrintHood|Recent|SendTo|Templates|Start Menu|My Documents|desktop\.ini|Default|Default User|All Users)`$'; `$roots = @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' -EA SilentlyContinue | ForEach-Object { `$_.DeviceID + '\' }) + @(Get-ChildItem `"`$env:SystemDrive\Users`" -EA SilentlyContinue | Where-Object { `$_.PSIsContainer } | ForEach-Object { `$_.FullName }); foreach (`$r in `$roots) { Get-ChildItem `$r -Force -EA SilentlyContinue | Where-Object { (`$_.Attributes -band [IO.FileAttributes]::Hidden) -and `$_.Name -notmatch `$sys } | ForEach-Object { `$_.FullName } }"
MC "SRV-166" "숨김 파일/디렉터리(증적: 드라이브 루트·사용자 프로필, OS 기본 항목 제외) 불필요 여부 확인"

# ── SRV-172: 불필요 시스템 자원 공유 제거 ──────────────────────
EvdQ "SRV-172" "공유 목록 (Get-SmbShare 또는 Win32_Share)" (Format-Shares $shList)
# 판단기준: 공유폴더가 없거나 업무상 필요한 공유만 존재 — 기본 관리 공유(드라이브$·ADMIN$·IPC$·print$·SYSVOL·NETLOGON)는 SRV-018에서 판정
$vuln2 = @(@($shList) | Where-Object { $_ -and $_.Name -notmatch '^([A-Za-z]|ADMIN|IPC|print)\$$' -and $_.Name -notmatch '^(SYSVOL|NETLOGON)$' } | ForEach-Object { "$($_.Name)($($_.Path))" })
if ($null -eq $shList) { CantCheck "SRV-172" "공유 목록 조회 실패(Get-SmbShare·Win32_Share 모두 불가) - net share 결과로 불필요 공유 수동 확인" }
elseif ($vuln2.Count) { MC "SRV-172" "사용자 공유 $($vuln2.Count)개: $($vuln2 -join ', ') - 업무상 필요 여부 확인 (불필요 시 취약)" }
else { Pass "SRV-172" "기본 관리 공유 외 공유폴더 없음" }

# ── SRV-175: NTP 동기화 ─────────────────────────────────────────
try {
    Evd "SRV-175" "w32tm /query /status 2>`$null; w32tm /query /source 2>`$null; w32tm /query /configuration 2>`$null | Select-String 'NtpServer|Type'"
    $w32 = w32tm /query /status 2>$null
    # 한글 OS는 'Source:' 대신 '원본:' 으로 출력
    $srcLine = $w32 | Where-Object { $_ -match "^\s*(Source|원본)\s*:\s*(.+)$" } | Select-Object -First 1
    if ($srcLine -and $srcLine -match "^\s*(Source|원본)\s*:\s*(.+)$") {
        $src = $matches[2].Trim()
        if ($src -match "Local CMOS Clock|Free-running|로컬 CMOS") { Fail "SRV-175" "NTP 동기화 미설정 (시간 원본: $src)" }
        elseif ($src -match "\d{1,3}\.\d{1,3}|time\.|ntp\.") { Pass "SRV-175" "NTP 동기화: $src" }
        else { MC "SRV-175" "시간 원본: $src - NTP 서버(도메인 계층 등) 동기화 여부 확인" }
    } else {
        $tp175 = 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters'; $ty175 = "$(Get-Reg $tp175 'Type')"; $ns175 = "$(Get-Reg $tp175 'NtpServer')"; $ws175 = Get-SvcState 'W32Time'
        EvdQ "SRV-175" "W32Time Parameters Type / NtpServer / 서비스 상태" "$ty175 / $ns175 / $(if ($ws175) { $ws175.Status } else { '없음' })"
        if ($ty175 -eq 'NoSync' -or -not $ws175 -or $ws175.Status -notmatch 'Running') { Fail "SRV-175" "NTP 동기화 미설정 (W32Time $(if ($ws175) { $ws175.Status } else { '없음' }), Type=$ty175)" }
        else { MC "SRV-175" "w32tm 출력 해석 실패 - NTP 설정(Type=$ty175, NtpServer=$ns175) 동기화 여부 확인" }
    }
} catch { CantCheck "SRV-175" "NTP 상태 조회 중 오류($($_.Exception.Message)) - w32tm /query /status 수동 확인" }

# ── SRV-178: 개인키 passphrase ──────────────────────────────────
# 판단방법: ssh-keygen -y -P "" -f [키] 실행 시 passphrase 입력 없이 공개키가 출력되면 미설정 (호스트 키는 sshd 용이라 증적만)
# ssh-keygen 오류는 'incorrect passphrase'(= passphrase 있음)와 그 밖의 오류(권한·손상·형식)를 구분한다
$kg178 = Get-Command ssh-keygen.exe -EA SilentlyContinue | Select-Object -First 1
$k178  = @(Get-ChildItem "$env:SystemDrive\Users\*\.ssh\*" -Force -EA SilentlyContinue | Where-Object { -not $_.PSIsContainer -and $_.Name -notmatch '\.pub$|^known_hosts|^authorized_keys|^config$' } |
          Where-Object { (Get-Content $_.FullName -TotalCount 1 -EA SilentlyContinue) -match 'PRIVATE KEY|^PuTTY-User-Key-File' })
$np178 = @(); $pp178 = @(); $uk178 = @()
foreach ($k in $k178) {
    $h = @(Get-Content $k.FullName -TotalCount 3 -EA SilentlyContinue)
    if ($h[0] -match '^PuTTY') { if (($h -join "`n") -match 'Encryption:\s*none') { $np178 += $k.FullName } else { $pp178 += $k.FullName }; continue }
    if (-not $kg178) { $uk178 += "$($k.FullName)(ssh-keygen 없음)"; continue }
    $o = "$env:TEMP\kg_$PID.txt"
    try {
        $pr = Start-Process -FilePath $kg178.Path -ArgumentList "-y -P `"`" -f `"$($k.FullName)`"" -NoNewWindow -Wait -PassThru -RedirectStandardOutput $o -RedirectStandardError "$o.err"
        $errTxt = Read-AllText "$o.err"
        if ($pr.ExitCode -eq 0) { $np178 += $k.FullName }
        elseif ($errTxt -match '(?i)incorrect passphrase|passphrase') { $pp178 += $k.FullName }
        else { $uk178 += "$($k.FullName)(ssh-keygen 오류: $((($errTxt -split "`r?`n")[0]).Trim()))" }
    } catch { $uk178 += "$($k.FullName)(실행 실패: $($_.Exception.Message))" }
    Remove-Item $o,"$o.err" -EA SilentlyContinue
}
EvdQ "SRV-178" "사용자 개인 키 (passphrase 없음 / 있음 / 판정 불가) + 호스트 키 목록" "없음: $($np178 -join ', ')`n있음: $($pp178 -join ', ')`n판정 불가: $($uk178 -join ', ')`n검사한 키 파일: $(($k178 | ForEach-Object { $_.FullName }) -join ', ')`n호스트 키: $((Get-ChildItem "$env:ProgramData\ssh\ssh_host_*_key" -EA SilentlyContinue | ForEach-Object { $_.Name }) -join ', ')"
if ($np178.Count) { Fail "SRV-178" "passphrase 미설정 개인 키: $($np178 -join ', ')" }
elseif ($uk178.Count) { CantCheck "SRV-178" "개인 키 passphrase 판정 불가(수동 확인): $($uk178 -join '; ')" }
elseif ($pp178.Count) { Pass "SRV-178" "개인 키 $($pp178.Count)개 passphrase 설정" }
else { NA "SRV-178" "사용자 SSH 개인 키 없음 (개인 키 미사용)" }

# ── SRV-179: EoS 시스템 교체 ────────────────────────────────────
Evd "SRV-179" "Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -EA SilentlyContinue | Select-Object ProductName,EditionID,InstallationType,CurrentBuild,UBR,DisplayVersion,ReleaseId | Format-List; Get-CimInstance Win32_OperatingSystem -EA SilentlyContinue | Select-Object Caption,Version,OSArchitecture | Format-List"
MC "SRV-179" "Windows 버전 지원 종료 여부 수동 확인 (현재: $(if ($os) { $os.Caption } else { "Windows Server $ver" }) Build $build) - Microsoft 제품 수명 주기 페이지 참조"

# ── SRV-062/063/064/066: DNS 서버 점검 ─────────────────────────
Evd "SRV-062" "Get-Service DNS -EA SilentlyContinue | Format-List Name,Status"
$dnsSvc = Get-SvcState "DNS"
EvdQ "SRV-062" "DNS 서비스 상태" "$(if ($dnsSvc) { "$($dnsSvc.Status)/$($dnsSvc.Start)" } else { '미설치' })"
if (-not $dnsSvc -or $dnsSvc.Status -notmatch "Running") {
    NA  "SRV-062" "DNS 서비스 미실행"
    NA  "SRV-063" "DNS 서비스 미실행"
    NA  "SRV-064" "DNS 서비스 미실행"
    Pass "SRV-066" "DNS 서비스 미사용 (평가기준 양호 1)"
} else {
    MC "SRV-062" "Windows DNS Server 실행 중 - 버전 정보 노출 설정 수동 확인"
    # SRV-063 판단방법: DNS\Parameters NoRecursion = 1 양호, 아니면 신뢰 호스트 등록(재귀 범위·쿼리 정책)·방화벽 통제 확인
    $nr063 = Get-Reg 'HKLM:\SYSTEM\CurrentControlSet\Services\DNS\Parameters' 'NoRecursion'
    $rec063 = if (Get-Command Get-DnsServerRecursion -EA SilentlyContinue) { Get-DnsServerRecursion -EA SilentlyContinue } else { $null }
    Evd "SRV-063" "Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\DNS\Parameters' -Name NoRecursion -EA SilentlyContinue; Get-DnsServerRecursion -EA SilentlyContinue | Format-List *; Get-DnsServerRecursionScope -EA SilentlyContinue | Format-Table -AutoSize; Get-DnsServerQueryResolutionPolicy -EA SilentlyContinue | Format-Table -AutoSize"
    EvdQ "SRV-063" "NoRecursion / Get-DnsServerRecursion.Enable" "$nr063 / $(if ($rec063) { $rec063.Enable } else { '(cmdlet 없음 - 2012 이상 DnsServer 모듈 필요)' })"
    if ("$nr063" -eq '1' -or ($rec063 -and -not $rec063.Enable)) { Pass "SRV-063" "Recursive Query 비활성 (NoRecursion=1)" }
    else { MC "SRV-063" "Recursive Query 허용 (NoRecursion=$(if ($null -eq $nr063) { '없음' } else { $nr063 })) - 신뢰 호스트(재귀 범위·쿼리 정책) 또는 방화벽 통제 여부 확인, 없으면 취약" }
    MC "SRV-064" "Windows DNS Server 실행 중 - 최신 보안 패치 적용 여부 수동 확인"
    # SRV-066 판단방법: 각 zone SecureSecondaries (0=아무 서버 취약, 1=확인 필요, 2·3 양호). AD 통합 영역은 레지스트리에 없어 Get-DnsServerZone → dnscmd → 레지스트리 순으로 조회
    $script:DnsZD = Get-DnsZoneData
    $zd066 = $script:DnsZD; $z066 = @($zd066.Zones)
    EvdQ "SRV-066" "DNS 영역 전송 설정 (SecureSecondaries 0=모든 서버, 1=이름 서버 탭, 2=지정 서버, 3=전송 안 함)" (Format-DnsZones $zd066)
    $any066 = @($z066 | Where-Object { "$($_.Xfer)" -eq '0' } | ForEach-Object { $_.Name })
    $ns066  = @($z066 | Where-Object { "$($_.Xfer)" -eq '1' -or "$($_.Xfer)" -eq '' } | ForEach-Object { "$($_.Name)$(if ("$($_.Xfer)" -eq '') { '(값 없음)' })" })
    $ok066  = @($z066 | Where-Object { "$($_.Xfer)" -eq '2' -or "$($_.Xfer)" -eq '3' } | ForEach-Object { "$($_.Name)($(if ("$($_.Xfer)" -eq '2') { '지정 서버' } else { '전송 안 함' }))" })
    $zl066 = ($z066 | ForEach-Object { $_.Name }) -join ', '
    if ($any066.Count) { Fail "SRV-066" "영역 전송 아무 서버로나 허용(SecureSecondaries=0): $($any066 -join ', ')" }
    elseif (-not $zd066.Complete) { CantCheck "SRV-066" "DNS 영역 목록을 완전하게 조회하지 못함($($zd066.Method); $($zd066.Note.Trim())) - AD 통합 영역 포함 DNS 관리자에서 영역 전송 설정 확인$(if ($z066.Count) { " (조회된 영역: $zl066)" })" }
    elseif ($ns066.Count) { MC "SRV-066" "이름 서버 탭 서버로 전송(SecureSecondaries=1, 평가기준 '확인 필요') 또는 값 없음: $($ns066 -join ', ')" }
    elseif ($z066.Count -eq 0) { Pass "SRV-066" "DNS 사용자 영역 없음 ($($zd066.Method))" }
    else { Pass "SRV-066" "영역 전송 차단 또는 지정 서버만: $($ok066 -join ', ')" }
}

# ── 평가기준 [서버] WIN 평가대상 중 기존 미점검/오분류 항목 (판단기준·판단방법 기준) ──


# SRV-003: 네트워크 모니터링 서비스 접근통제 (SNMP PermittedManagers)
Evd "SRV-003" "Get-Service SNMP -EA SilentlyContinue | Format-List Name,Status; Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\PermittedManagers' -EA SilentlyContinue"
$snmp = Get-SvcState "SNMP"
if ($otherSnmp) { MC "SRV-003" "타사 SNMP 에이전트 실행($($snmpPaths -join ', ')) - snmpd.conf 출발지(com2sec source 등) 제한 확인" }
elseif (-not $snmp -or $snmp.Status -ne "Running") { NA "SRV-003" "SNMP 서비스 미실행" }
else {
    $pm = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\PermittedManagers' -EA SilentlyContinue
    $hosts = @(); if ($pm) { $hosts = @($pm.PSObject.Properties | Where-Object { $_.Name -match '^\d+$' } | ForEach-Object { $_.Value }) }
    EvdQ "SRV-003" "SNMP PermittedManagers (허용 호스트)" $(if ($hosts.Count) { $hosts -join "`n" } else { '(미설정 - 모든 호스트에서 수신)' })
    if ($hosts.Count -gt 0) { Pass "SRV-003" "SNMP 패킷 허용 호스트 지정됨: $($hosts -join ',')" }
    else { Fail "SRV-003" "SNMP PermittedManagers 미설정 (모든 호스트에서 SNMP 패킷 수신)" }
}

# SRV-004: 불필요한 SMTP 서비스 (25번 포트)
Evd "SRV-004" "Get-Service SMTPSVC -EA SilentlyContinue | Format-List Name,Status"
$smtp = Get-SvcState "SMTPSVC"
$l25 = Get-Listen 25
EvdQ "SRV-004" "SMTPSVC 상태 / TCP 25 리슨 (netstat -ano)" "$(if ($smtp) { "$($smtp.Status)/$($smtp.Start)" } else { '미설치' })`n$(Format-Listen $l25)"
if (($smtp -and $smtp.Status -eq "Running") -or (Cnt $l25)) { MC "SRV-004" "SMTP 서비스 동작 중 (25번 포트) - 업무상 필요 여부 확인" }
elseif ($null -eq $l25) { CantCheck "SRV-004" "25번 포트 리슨 조회 불가(netstat 실패), SMTPSVC 는 미실행" }
else { Pass "SRV-004" "SMTP 서비스 미동작 (25번 포트 리슨 없음)" }

# SRV-021: FTP 서비스 접근통제 (ipSecurity) — FTP 공통 변수($ftpMode 등)는 SRV-013 앞에서 수집
Evd "SRV-021" "Select-String -Path '$ahc' -Pattern 'ipSecurity|<add ipAddress' -EA SilentlyContinue"
EvdQ "SRV-021" "FTP 사이트별 IP 제한 (IpRestr=allowUnlisted=false 인 경우만 True)" $(if ($ftpIis) { (@($ftpSites) | ForEach-Object { "$($_.Name): IpRestr=$($_.IpRestr) $($_.IpDetail)" }) -join "`n" } else { "(IIS FTP 사이트 없음/미탐지: $ftpMode)" })
switch ($ftpMode) {
    'none'     { NA "SRV-021" "FTP 서비스 미실행" }
    'unknown'  { CantCheck "SRV-021" "21번 포트 리슨 여부 조회 불가(netstat 실패)이고 FTPSVC 미실행 - FTP 사용 여부 수동 확인" }
    'third'    { MC "SRV-021" "FTP 서비스 실행 중(타사 FTP 추정, 21번 포트 리슨) 접근제어 수동 확인" }
    'iis-fail' { if (Test-Path $ahc) { CantCheck "SRV-021" "FTP 서비스 실행 중이나 IIS 설정 파싱 실패 - 접근제어 수동 확인" } else { MC "SRV-021" "FTP 서비스 실행 중 - $ftpWhy" } }
    'iis-none' { MC "SRV-021" "FTP 서비스 실행 중 - IIS FTP 사이트 미탐지 접근제어 수동 확인" }
    default {
        $n021 = @($ftpSites | Where-Object { -not $_.IpRestr } | ForEach-Object { "$($_.Name)[$($_.IpDetail)]" })
        if ($n021.Count) { Fail "SRV-021" "FTP IP 접근제어(ipSecurity allowUnlisted=false 지정 IP 만 허용) 미설정 사이트: $($n021 -join ', ')" }
        else { Pass "SRV-021" "FTP 전 사이트 IP 주소/도메인 제한(ipSecurity, allowUnlisted=false) 설정됨" }
    }
}

# SRV-037: 취약한 FTP 서비스 (FTPS 적용 시 양호)
Evd "SRV-037" "sc.exe query FTPSVC; sc.exe query MSFTPSVC"
EvdQ "SRV-037" "TCP 21 리슨 (netstat -ano) / FTPS 정책 (사이트별 Ctl·Dat)" "$(Format-Listen $l21)`n$(Format-FtpSites $ftpSites)"
switch ($ftpMode) {
    'none'     { Pass "SRV-037" "FTP 서비스 비활성화" }
    'unknown'  { CantCheck "SRV-037" "21번 포트 리슨 여부 조회 불가(netstat 실패)이고 FTPSVC 미실행 - FTP 사용 여부 수동 확인" }
    'iis-fail' { if (Test-Path $ahc) { CantCheck "SRV-037" "FTP 서비스 실행 중이나 IIS 설정 파싱 실패 - FTPS 적용 여부 확인 불가" } else { Fail "SRV-037" "FTP 서비스 활성화 (IIS 6 이하 FTP - FTPS 미지원)" } }
    'iis'      {
        $n037 = @($ftpSites | Where-Object { $_.Ctl -ne 'SslRequire' -or $_.Dat -ne 'SslRequire' } | ForEach-Object { "$($_.Name)(Ctl=$($_.Ctl),Dat=$($_.Dat))" })
        if ($n037.Count) { Fail "SRV-037" "FTP 서비스 활성화 - FTPS(SSL 필수) 미적용 사이트: $($n037 -join ', ')" }
        else { Pass "SRV-037" "FTP 사용 중이나 전 사이트 FTPS(SSL 필수) 적용" }
    }
    default    { Fail "SRV-037" "FTP 서비스 활성화 (IIS 외 FTP - FTPS 적용 확인 불가 시 취약)" }
}

# SRV-074: 불필요하거나 관리되지 않는 계정 (분기 내 로그인·비밀번호 변경)
$act074 = @($accts | Where-Object { $_.Enabled })
EvdQ "SRV-074" "활성 로컬 계정 (Name / LastLogon / PasswordLastSet / 수집원)" (($act074 | ForEach-Object { "$($_.Name) / $($_.LastLogon) / $($_.PasswordLastSet) / $($_.Src)" }) -join "`n")
if ($accts.Count -eq 0) { CantCheck "SRV-074" "로컬 계정 조회 실패(또는 도메인 컨트롤러) - net user 계정별 로그인/비밀번호 변경일 확인" }
elseif (@($act074 | Where-Object { $_.Src -eq 'WMI(ADSI 실패)' }).Count) { CantCheck "SRV-074" "마지막 로그인/비밀번호 변경일 조회 실패(ADSI) - net user 로 확인" }
else {
    $stale = @($act074 | Where-Object { -not $_.LastLogon -or $_.LastLogon -lt (Get-Date).AddDays(-90) -or -not $_.PasswordLastSet -or $_.PasswordLastSet -lt (Get-Date).AddDays(-90) })
    if ($stale.Count -gt 0) { Fail "SRV-074" "분기 내 로그인/비밀번호 변경 없는 활성 계정: $(($stale | ForEach-Object { $_.Name }) -join ', ') (업무상 사용 여부 확인)" }
    else { Pass "SRV-074" "활성 계정 모두 분기 내 로그인 및 비밀번호 변경" }
}

# SRV-082: 시스템 주요 디렉터리(로그) 권한 - Users 등 불필요 권한
$dirs = @("$env:windir\system32\config", "$env:windir\system32\winevt\Logs", "$env:windir\system32\LogFiles")
Evd "SRV-082" "foreach (`$d in @('$($dirs -join "','")')) { icacls `$d }"
$bad082 = @(); $unk082 = @(); $ev082 = @()
foreach ($d in $dirs) {
    $acl = Get-Acl $d -EA SilentlyContinue
    if (-not $acl) { $unk082 += $d; $ev082 += "${d}: ACL 조회 실패"; continue }
    $ev082 += $d
    # 판단기준: Users 그룹과 같이 불필요한 권한 부여 여부 (권한 종류 한정 없음) — SID 기준(로캘 무관)
    foreach ($ace in $acl.Access) { $ev082 += "    $($ace.IdentityReference) $($ace.FileSystemRights) $($ace.AccessControlType)"; if ("$($ace.AccessControlType)" -ne 'Allow') { continue }; $sid = Get-AceSid $ace
        if (@('S-1-1-0','S-1-5-32-545','S-1-5-32-546') -contains $sid) { $bad082 += "$d($($ace.IdentityReference):$($ace.FileSystemRights))" } }
}
EvdQ "SRV-082" "로그 디렉터리별 ACL (Get-Acl)" ($ev082 -join "`n")
if ($bad082.Count -gt 0) { Fail "SRV-082" "로그 디렉터리 불필요 권한(Everyone/Users/Guests): $($bad082 -join ', ')" }
elseif ($unk082.Count) { CantCheck "SRV-082" "로그 디렉터리 ACL 조회 실패($($unk082 -join ', ')) - $(if ($script:IsAdmin -eq $false) { '관리자 권한 아님' } else { 'Get-Acl 오류' })" }
else { Pass "SRV-082" "로그 디렉터리에 Everyone/Users/Guests 권한 없음" }

# SRV-115: 로그 정기 검토 (인터뷰/보고서)
EvdQ "SRV-115" "판단방법" "로그 검토 보고서 확인 / 인터뷰"
MC "SRV-115" "로그 정기 검토·보고 수행 여부 수동 확인 (검토 보고서/인터뷰)"

# SRV-137: 네트워크 서비스 접근 권한 (네트워크에서 이 컴퓨터 액세스)
$r137 = Test-SecPolGroups "SeNetworkLogonRight" @("Everyone","Guests","Anonymous")
EvdQ "SRV-137" "SeNetworkLogonRight / SeDenyNetworkLogonRight" "$($r137[0]) / $(Get-SecPol 'SeDenyNetworkLogonRight')"
if ($null -eq $r137[0]) { CantCheck "SRV-137" "$(SecWhy '네트워크 액세스 권한 정책') - 로컬 보안 정책 수동 확인" }
elseif ($r137[1].Count -gt 0) { Fail "SRV-137" "'네트워크에서 이 컴퓨터 액세스'에 불필요 그룹: $($r137[1] -join ', ')" }
else { Pass "SRV-137" "'네트워크에서 이 컴퓨터 액세스' 불필요 그룹 없음" }

# SRV-138: 백업 및 복구 권한
$rb = Test-SecPolGroups "SeBackupPrivilege" @("Everyone","Guests","Users")
$rr = Test-SecPolGroups "SeRestorePrivilege" @("Everyone","Guests","Users")
EvdQ "SRV-138" "SeBackupPrivilege / SeRestorePrivilege" "$($rb[0]) / $($rr[0])"
$bad138 = @(@($rb[1]) + @($rr[1]) | Select-Object -Unique)   # 결과 1개여도 배열로 (PS 2.0 스칼라 .Count 대응)
if ($null -eq $rb[0] -and $null -eq $rr[0]) { CantCheck "SRV-138" "$(SecWhy '백업/복구 권한 정책') - 수동 확인" }
elseif ($bad138.Count -gt 0) { Fail "SRV-138" "백업/복구 권한에 불필요 그룹: $($bad138 -join ', ')" }
else { Pass "SRV-138" "백업/복구 권한에 Everyone/Guests/Users 없음" }

# SRV-139: 소유권 가져오기 권한 (Administrators만)
$rt = Test-SecPolGroups "SeTakeOwnershipPrivilege" @("Everyone","Users","Guests","Authenticated Users")
EvdQ "SRV-139" "SeTakeOwnershipPrivilege" "$($rt[0])"
if ($null -eq $rt[0]) { CantCheck "SRV-139" "$(SecWhy '소유권 가져오기 권한') - 수동 확인" }
elseif ($rt[1].Count -gt 0) { Fail "SRV-139" "소유권 가져오기 권한에 불필요 그룹: $($rt[1] -join ', ')" }
elseif ($rt[0] -eq "*S-1-5-32-544") { Pass "SRV-139" "소유권 가져오기 권한 Administrators만 존재" }
else { MC "SRV-139" "소유권 가져오기 권한 구성원($($rt[0])) 적정성 확인" }

# SRV-147: 불필요한 네트워크 모니터링 서비스 (SNMP / WMI)
Evd "SRV-147" "sc.exe query SNMP; sc.exe query winmgmt"
$snmp2 = Get-SvcState "SNMP"
EvdQ "SRV-147" "SNMP 서비스 상태 / 타사 SNMP 에이전트" "$(if ($snmp2) { "$($snmp2.Status)/$($snmp2.Start)" } else { '미설치' }) / $(if ($snmpPaths.Count) { $snmpPaths -join ', ' } else { '없음' })"
if ($snmp2 -and $snmp2.Status -eq "Running") { MC "SRV-147" "SNMP 서비스 실행 중 - 업무상 필요 여부 확인 (WMI는 OS 기본 서비스)" }
elseif ($otherSnmp) { MC "SRV-147" "타사 SNMP 에이전트 실행 중($($snmpPaths -join ', ')) - 업무상 필요 여부 확인" }
else { Pass "SRV-147" "SNMP 서비스 미실행 (WMI는 OS 기본 서비스)" }

# SRV-170: SMTP 배너 정보 노출
Evd "SRV-170" "Get-Service SMTPSVC -EA SilentlyContinue | Format-List Name,Status"
$mb170 = "$env:windir\System32\inetsrv\MetaBase.xml"
$cr170 = @([regex]::Matches((Read-AllText $mb170), '(?i)ConnectResponse="([^"]*)"') | ForEach-Object { $_.Groups[1].Value })
EvdQ "SRV-170" "SMTPSVC 상태 / TCP 25 리슨 / MetaBase.xml ConnectResponse" "$(if ($smtp) { "$($smtp.Status)/$($smtp.Start)" } else { '미설치' }) / $(Format-Listen $l25)`n$(if (Test-Path $mb170) { if ($cr170.Count) { $cr170 -join ' | ' } else { '(설정 없음 - 기본 배너)' } } else { 'MetaBase.xml 없음' })"
if (-not ($smtp -and $smtp.Status -eq "Running")) { if (Cnt $l25) { MC "SRV-170" "타사 SMTP(25번 포트) 실행 - 배너 서비스명/버전 노출 수동 확인" } elseif ($null -eq $l25) { CantCheck "SRV-170" "25번 포트 리슨 조회 불가(netstat 실패), SMTPSVC 는 미실행" } else { NA "SRV-170" "SMTP 서비스 미실행" } }
elseif (-not (Test-Path $mb170)) { MC "SRV-170" "IIS SMTP 실행 중 - MetaBase.xml 없음, 배너 수동 확인" }
elseif ($cr170.Count -eq 0 -or @($cr170 | Where-Object { $_ -eq '' }).Count) { Fail "SRV-170" "ConnectResponse 미설정 - 기본 배너(Microsoft ESMTP MAIL Service, Version) 노출" }
elseif (@($cr170 | Where-Object { $_ -match '(?i)microsoft|esmtp|smtpsvc|version|\d+\.\d+\.\d+' }).Count) { Fail "SRV-170" "ConnectResponse 에 서비스명/버전 포함: $($cr170 -join ' | ')" }
else { Pass "SRV-170" "SMTP 배너 사용자 지정 (서비스명·버전 미노출)" }

# SRV-171: FTP 배너 정보 노출 (suppressDefaultBanner)
Evd "SRV-171" "Select-String -Path '$ahc' -Pattern 'suppressDefaultBanner' -EA SilentlyContinue"
EvdQ "SRV-171" "FTP 사이트별 suppressDefaultBanner (siteDefaults 상속 반영)" $(if ($ftpIis) { (@($ftpSites) | ForEach-Object { "$($_.Name): Banner=$($_.Banner)" }) -join "`n" } else { "(IIS FTP 사이트 없음/미탐지: $ftpMode)" })
switch ($ftpMode) {
    'none'     { NA "SRV-171" "FTP 서비스 미실행" }
    'unknown'  { CantCheck "SRV-171" "21번 포트 리슨 여부 조회 불가(netstat 실패)이고 FTPSVC 미실행 - FTP 사용 여부 수동 확인" }
    'third'    { MC "SRV-171" "FTP 서비스 실행 중(타사 FTP 추정, 21번 포트 리슨) 배너 수동 확인" }
    'iis-fail' { if (Test-Path $ahc) { CantCheck "SRV-171" "FTP 서비스 실행 중이나 IIS 설정 파싱 실패 - 배너 설정 수동 확인" } else { MC "SRV-171" "FTP 서비스 실행 중 - $ftpWhy" } }
    'iis-none' { MC "SRV-171" "FTP 서비스 실행 중 - IIS FTP 사이트 미탐지 배너 수동 확인" }
    default {
        $n171 = @($ftpSites | Where-Object { $_.Banner -ne 'true' } | ForEach-Object { $_.Name })
        if ($n171.Count) { Fail "SRV-171" "FTP suppressDefaultBanner 미설정 사이트(기본 배너 노출): $($n171 -join ', ')" }
        else { Pass "SRV-171" "FTP 전 사이트 suppressDefaultBanner=true (배너 정보 미노출)" }
    }
}

# SRV-173 / SRV-174: DNS 동적 업데이트 / 불필요 DNS 서비스
$dns = Get-SvcState "DNS"
Evd "SRV-174" "sc.exe query dns"
if (-not ($dns -and $dns.Status -eq "Running")) {
    Pass "SRV-174" "DNS 서비스 미실행"
    NA "SRV-173" "DNS 서비스 미실행"
} else {
    MC "SRV-174" "DNS 서비스 실행 중 - 업무상 필요 여부 확인"
    if ($null -eq $script:DnsZD) { $script:DnsZD = Get-DnsZoneData }
    $zd173 = $script:DnsZD; $z173 = @($zd173.Zones | Where-Object { "$($_.Type)" -ne 'Secondary' })
    EvdQ "SRV-173" "DNS 영역 동적 업데이트 (AllowUpdate 0=없음, 1=비보안 포함, 2=보안만)" (Format-DnsZones $zd173)
    $nonsec = @($z173 | Where-Object { "$($_.Upd)" -eq '1' } | ForEach-Object { $_.Name })
    $unk173 = @($z173 | Where-Object { "$($_.Upd)" -eq '' } | ForEach-Object { $_.Name })
    if ($nonsec.Count -gt 0) { Fail "SRV-173" "보안되지 않은 동적 업데이트 허용 영역(AllowUpdate=1): $($nonsec -join ', ')" }
    elseif (-not $zd173.Complete) { CantCheck "SRV-173" "DNS 영역 목록을 완전하게 조회하지 못함($($zd173.Method); $($zd173.Note.Trim())) - AD 통합 영역 포함 DNS 관리자에서 동적 업데이트 설정 확인" }
    elseif ($unk173.Count) { MC "SRV-173" "동적 업데이트 설정 값을 읽지 못한 영역: $($unk173 -join ', ') - 수동 확인" }
    elseif ($z173.Count -eq 0) { Pass "SRV-173" "DNS 사용자 영역(Primary) 없음 ($($zd173.Method))" }
    else { Pass "SRV-173" "동적 업데이트 비활성 또는 보안 업데이트만 허용" }
}

# <<< SRV-COMMON-END
}
# ════════════════════════════════════════════════════════════════
# [2] 웹/WAS 공통 도구 — 설정 해석·다중 대상 병합·실제 HTTP 응답 수집
#     (구 [2] 기존 IIS/OS 점검 약 900행은 판정이 REF-(참고)로만 가서 결과에 영향이 없어 제거하고,
#      WST-031/036/102/121~125 등 웹 항목은 아래 [3] 에서 직접 판정한다)
# ════════════════════════════════════════════════════════════════
$script:PHASE = "final"
$script:PName = @{ 'iis'='IIS'; 'apache'='Apache'; 'nginx'='Nginx'; 'tomcat'='Tomcat'; 'jeus'='JEUS' }
function Has-Prod([string]$p) { return ((@($WEB_LIST) -contains $p) -or (@($WAS_LIST) -contains $p)) }
function Pt([string]$p,[string]$T) { if (-not (Has-Prod $p)) { return $false }; return ((" $T ") -like ("* " + $script:PName[$p] + " *")) }
function Lab([string]$lab,[string]$r) { if (-not $r) { return '' }; $p = $r -split '\|',2; return ($p[0] + "|[" + $lab + "] " + $p[1]) }
function Brief($items,[int]$n = 3) {
    $a = @($items | Where-Object { $_ -ne $null -and "$_" -ne '' })
    $s = ($a | Select-Object -First $n) -join '; '
    if ($a.Count -gt $n) { $s += " 외 $($a.Count - $n)건(증적 참조)" }
    return $s
}
function Sec([string]$title, $lines) {   # 증적 섹션: 제목 + 줄 수 + 내용 (내용이 없어도 제목·줄 수가 남아 상태가 보인다)
    $a = @($lines | Where-Object { $_ -ne $null -and "$_" -ne '' })
    "-- $title ($($a.Count)줄)"
    $a
}
function Read-FileText([string]$p) { try { return [IO.File]::ReadAllText($p) } catch { $script:LastReadErr = $_.Exception.Message; return $null } }
function Strip-XmlComments([string]$t) { if ($null -eq $t) { return '' }; return ([regex]::Replace($t, '(?s)<!--.*?-->', '')) }

# ── Apache/Nginx 설정 전개 (Include/include 를 따라가며 줄 단위 객체 생성) ──
function Expand-Conf([string]$kind, [string]$file, [string]$root, [int]$depth = 0) {
    $out = @()
    if ($depth -gt 8) { return $out }
    $lines = $null
    try { $lines = [IO.File]::ReadAllLines($file) } catch { $out += (New-Object PSObject -Property @{ File = $file; Line = 0; Text = '@@UNREADABLE' }); return $out }
    $n = 0
    foreach ($ln in $lines) {
        $n++; $t = $ln.Trim()
        if ($t -eq '' -or $t.StartsWith('#')) { continue }
        $pieces = @($t)
        if ($kind -eq 'nginx') {
            $t = $t -replace '\s+#.*$', ''
            $t = $t -replace '\{', "{`n"; $t = $t -replace '\}', "`n}`n"; $t = $t -replace ';', ";`n"
            $pieces = @($t -split "`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' })
        }
        foreach ($pc in $pieces) {
            $out += (New-Object PSObject -Property @{ File = $file; Line = $n; Text = $pc })
            $pat = $null
            if ($kind -eq 'apache' -and $pc -match '^(?i)Include(Optional)?\s+"?([^"\s]+)"?') { $pat = $matches[2] }
            if ($kind -eq 'nginx' -and $pc -match '^include\s+"?([^";\s]+)"?;?') { $pat = $matches[1] }
            if ($pat) {
                $pat = $pat -replace '/', '\'
                if ($pat -notmatch '^[A-Za-z]:\\' -and $pat -notmatch '^\\\\') { $pat = Join-Path $root $pat }
                $files = @()
                try {
                    foreach ($it in @(Get-ChildItem -Path $pat -EA SilentlyContinue)) {
                        if ($it.PSIsContainer) { $files += @(Get-ChildItem -Path $it.FullName -EA SilentlyContinue | Where-Object { -not $_.PSIsContainer } | ForEach-Object { $_.FullName }) }
                        else { $files += $it.FullName }
                    }
                } catch {}
                foreach ($f in $files) { $sub = @(Expand-Conf $kind $f $root ($depth + 1)); $out += $sub }
            }
        }
    }
    return $out
}
function Cq($lines, [string]$re) { return @($lines | Where-Object { $_ -and $_.Text -match $re }) }
function Cqf($lines, [string]$re) { return @(Cq $lines $re | ForEach-Object { "$($_.File):$($_.Line): $($_.Text)" }) }
function Conf-Files($lines) { return @($lines | ForEach-Object { $_.File } | Select-Object -Unique) }
$script:ConfCache = @{}
function Get-ConfLines([string]$kind, [string]$file) {   # 주설정 파일 하나의 전개 결과(캐시)
    $key = "$kind|$file"
    if (-not $script:ConfCache.ContainsKey($key)) {
        $root = Split-Path (Split-Path $file)
        if ($kind -eq 'apache') { $first = [IO.File]::ReadAllLines($file) | Where-Object { $_ -match '^\s*ServerRoot\s+"?([^"\s]+)"?' } | Select-Object -First 1; if ($first -and $first -match 'ServerRoot\s+"?([^"\s]+)"?') { $root = ($matches[1] -replace '/', '\') } }
        if ($kind -eq 'nginx') { $root = Split-Path $file }
        $script:ConfCache[$key] = @(Expand-Conf $kind $file $root 0)
    }
    return $script:ConfCache[$key]
}
function Conf-Unreadable($lines) { return @($lines | Where-Object { $_.Text -eq '@@UNREADABLE' } | ForEach-Object { $_.File } | Select-Object -Unique) }

# ── Tomcat 설정 파일 (인스턴스 conf → 없으면 home conf) ──────────
$script:CurTomcat = ''
function Tc-Home([string]$base) {   # catalina.base → catalina.home (프로세스 인자, 없으면 base)
    foreach ($pr in $script:Procs) { if ("$($pr.CommandLine)" -match [regex]::Escape("-Dcatalina.base=$base") -or "$($pr.CommandLine)" -match [regex]::Escape("-Dcatalina.base=`"$base`"")) { if ("$($pr.CommandLine)" -match '-Dcatalina\.home=("[^"]+"|\S+)') { return $matches[1].Trim('"') } } }
    return $base
}
function Tc-File([string]$name) { $p = "$($script:CurTomcat)\conf\$name"; if (Test-Path $p) { return $p }; $h = Tc-Home $script:CurTomcat; return "$h\conf\$name" }
function Tc-Text([string]$name) { $f = Tc-File $name; if (-not (Test-Path $f)) { return $null }; $t = Read-FileText $f; if ($null -eq $t) { return $null }; return (Strip-XmlComments $t) }
function Tc-Need([string[]]$names) {   # 읽을 수 없으면 '점검불가|사유', 문제 없으면 $null
    foreach ($n in $names) {
        $f = Tc-File $n
        if (-not (Test-Path $f)) { if (@('context.xml','tomcat-users.xml') -contains $n) { continue }; return "점검불가|Tomcat 설정 파일 없음: $f" }
        if ($null -eq (Read-FileText $f)) { return "점검불가|Tomcat 설정 파일 읽기 실패: $f ($($script:LastReadErr)) (실행 계정 $env:USERNAME)" }
    }
    return $null
}
function Tc-WebXmls { $o = @(); $f = Tc-File 'web.xml'; if (Test-Path $f) { $o += $f }; foreach ($w in @(Get-ChildItem "$($script:CurTomcat)\webapps\*\WEB-INF\web.xml" -EA SilentlyContinue)) { $o += $w.FullName }; return $o }
function Tc-WebXmlHit([string]$re) { $hit = @(); foreach ($f in @(Tc-WebXmls)) { $t = Read-FileText $f; if ($null -ne $t -and (Strip-XmlComments $t) -match $re) { $hit += $f } }; return $hit }

# JEUS 설정 파일 검색 (glob)
$script:CurJeus = ''
function Je-Find([string]$name) {
    $j = $script:CurJeus; $o = @()
    foreach ($pat in @("$j\$name", "$j\config\$name", "$j\config\*\$name", "$j\domains\*\config\$name", "$j\domains\*\config\*\$name", "$j\domains\*\config\*\*\$name", "$j\domains\*\servers\*\$name", "$j\domains\*\applications\*\WEB-INF\$name", "$j\domains\*\applications\*\*\WEB-INF\$name", "$j\webhome\*\WEB-INF\$name", "$j\*\WEB-INF\$name")) {
        foreach ($f in @(Get-ChildItem -Path $pat -EA SilentlyContinue | Where-Object { -not $_.PSIsContainer })) { if ($o -notcontains $f.FullName) { $o += $f.FullName } }
    }
    return $o
}

# ── 깊이 제한 파일 검색 (Get-ChildItem -Depth 는 PS 5+ 라서 직접 재귀) ──
function Find-Depth([string]$dir, [scriptblock]$pred, [int]$depth = 3, [int]$max = 200) {
    $res = @()
    if (-not (Test-Path $dir) -or $depth -lt 0) { return $res }
    foreach ($it in @(Get-ChildItem $dir -EA SilentlyContinue)) {
        if ($res.Count -ge $max) { break }
        if (& $pred $it) { $res += $it.FullName }
        if ($it.PSIsContainer -and $depth -gt 0 -and -not ($it.Attributes -band [IO.FileAttributes]::ReparsePoint)) { $res += @(Find-Depth $it.FullName $pred ($depth - 1) ($max - $res.Count)) }
    }
    return $res
}

# ── IIS 설정 모델: applicationHost.config + 사이트/응용 프로그램/가상 디렉터리별 web.config ──
$ahPath = if ($env:IIS_APPHOST) { $env:IIS_APPHOST } else { "$env:windir\System32\inetsrv\config\applicationHost.config" }   # IIS_APPHOST: 점검자 검증용 설정 경로
$iisK = [bool]($IIS_INSTALLED -or $env:IIS_APPHOST)
$script:IISX = $null; $script:IisErr = ''
if ($iisK) {
    if (-not (Test-Path $ahPath)) { $script:IisErr = "IIS 설정 파일 없음: $ahPath" }
    else {
        $tx = Read-FileText $ahPath
        if ($null -eq $tx) { $script:IisErr = "IIS 설정 파일($ahPath)을 읽지 못함: $($script:LastReadErr) (실행 계정 $env:USERNAME - 관리자 권한 필요)" }
        else { try { $script:IISX = [xml]$tx } catch { $script:IisErr = "IIS 설정 파일($ahPath) XML 파싱 실패: $($_.Exception.Message)" } }
    }
}
$script:WcCache = @{}; $script:WcErr = @()
function Get-WcXml([string]$path) {
    if ($script:WcCache.ContainsKey($path)) { return $script:WcCache[$path] }
    $x = $null
    $t = Read-FileText $path
    if ($null -eq $t) { $script:WcErr += "$path ($($script:LastReadErr))" }
    else { try { $x = [xml]$t } catch { $script:WcErr += "$path (XML 파싱 실패)" } }
    $script:WcCache[$path] = $x
    return $x
}
$script:Scopes = @(); $script:SkippedSites = @()
if ($script:IISX) {
    $sd = $script:IISX.configuration.'system.applicationHost'.sites
    $defPool = if ($sd.applicationDefaults.applicationPool) { "$($sd.applicationDefaults.applicationPool)" } else { 'DefaultAppPool' }
    foreach ($s in @($sd.site)) {
        if (-not $s) { continue }
        $bind = @(@($s.bindings.binding) | Where-Object { $_ } | ForEach-Object { "$($_.protocol)://$($_.bindingInformation)" })
        if (-not @($bind | Where-Object { $_ -match '^https?://' }).Count) { $script:SkippedSites += "$($s.name)(HTTP/HTTPS 바인딩 없음: $($bind -join ','))"; continue }   # FTP 전용 사이트 제외
        foreach ($a in @($s.application)) {
            if (-not $a) { continue }
            $pool = if ($a.applicationPool) { "$($a.applicationPool)" } else { $defPool }
            $ap = "$($a.path)"; if (-not $ap) { $ap = '/' }
            foreach ($vd in @($a.virtualDirectory)) {
                if (-not $vd) { continue }
                $vp = "$($vd.path)"; if (-not $vp) { $vp = '/' }
                $full = if ($vp -eq '/') { $ap } elseif ($ap -eq '/') { $vp } else { $ap.TrimEnd('/') + $vp }
                $kind = if ($vp -eq '/' -and $ap -eq '/') { '사이트' } elseif ($vp -eq '/') { '응용프로그램' } else { '가상디렉터리' }
                $script:Scopes += New-Object PSObject -Property @{ Site = "$($s.name)"; Path = $full; Root = [Environment]::ExpandEnvironmentVariables("$($vd.physicalPath)"); Kind = $kind; Pool = $pool; Bind = $bind }
            }
        }
    }
}
function Parent-Scope($sc) {
    $best = $null
    foreach ($c in $script:Scopes) {
        if ($c.Site -ne $sc.Site -or $c.Path -eq $sc.Path) { continue }
        if ($c.Path -eq '/' -or $sc.Path.StartsWith($c.Path.TrimEnd('/') + '/')) { if (-not $best -or $c.Path.Length -gt $best.Path.Length) { $best = $c } }
    }
    return $best
}
function Ws-Nodes($sc) {   # system.webServer 노드 우선순위: 자기 web.config → applicationHost location → 상위 범위 → 전역
    $out = @()
    if ($sc.Root) { $wc = Join-Path $sc.Root 'web.config'; if (Test-Path $wc) { $x = Get-WcXml $wc; if ($x -and $x.configuration.'system.webServer') { $out += $x.configuration.'system.webServer' } } }
    $lp = $sc.Site + $(if ($sc.Path -ne '/') { $sc.Path } else { '' })
    foreach ($l in @($script:IISX.configuration.location)) { if ($l -and "$($l.path)" -eq $lp -and $l.'system.webServer') { $out += $l.'system.webServer' } }
    $par = Parent-Scope $sc
    if ($par) { $out += @(Ws-Nodes $par) }
    else {
        foreach ($l in @($script:IISX.configuration.location)) { if ($l -and "$($l.path)" -eq $sc.Site -and $sc.Path -ne '/' -and $l.'system.webServer') { $out += $l.'system.webServer' } }
        if ($script:IISX.configuration.'system.webServer') { $out += $script:IISX.configuration.'system.webServer' }
    }
    return $out
}
function Ws-Val($sc, [scriptblock]$f) { foreach ($n in @(Ws-Nodes $sc)) { if (-not $n) { continue }; $v = & $f $n; if ("$v" -ne '') { return "$v" } }; return $null }
function Ws-Handlers($sc) { $h = @(); foreach ($n in @(Ws-Nodes $sc)) { if ($n) { $h += @($n.handlers.add | Where-Object { $_ } | ForEach-Object { "$($_.path)" }) } }; return @($h | Select-Object -Unique) }
function Scope-Ev([string]$label, [scriptblock]$f) {   # 증적: 범위(사이트/응용프로그램/가상디렉터리)별 유효 설정값
    foreach ($sc in $script:Scopes) {
        $v = Ws-Val $sc $f
        "$($sc.Site)$(if ($sc.Path -ne '/') { $sc.Path }) [$($sc.Kind)] [$($sc.Root)] $label=$(if ($null -ne $v) { $v } else { '(미설정 - 상속/기본값)' })"
    }
}
function Iis-Un { if ($script:IISX) { return $null }; return "점검불가|$($script:IisErr)" }
function Iis-Un2 { $u = Iis-Un; if ($u) { return $u }; if (-not $script:Scopes.Count) { return "N-A|HTTP/HTTPS 바인딩이 있는 IIS 사이트 없음 (제외: $($script:SkippedSites -join ', '))" }; if ($script:WcErr.Count) { return $null }; return $null }
function Iis-WcNote { if ($script:WcErr.Count) { return " (web.config 읽기/파싱 실패로 해당 범위는 상위 설정 기준: $(Brief $script:WcErr 2))" }; return '' }
function Scope-Ev-Head { "IIS 범위 $($script:Scopes.Count)개 (사이트·응용 프로그램·가상 디렉터리), 제외 사이트: $(if ($script:SkippedSites.Count) { $script:SkippedSites -join ', ' } else { '없음' })" }

# ── 실제 HTTP 응답 수집 (리슨 중인 로컬 HTTP/HTTPS 포트, 타임아웃 3초) ──────────────
#   GET / (상태코드·Server·Location·본문 목록), GET /없는경로 (기본 오류 페이지), TRACE /
try { [Net.ServicePointManager]::ServerCertificateValidationCallback = { $true } } catch {}
try { [Net.ServicePointManager]::SecurityProtocol = [Enum]::ToObject([Net.SecurityProtocolType], 3072 -bor 768 -bor 192 -bor 48) } catch {}
function Invoke-Probe([string]$Url, [string]$Method = 'GET', [string]$HostHdr = '') {
    $o = New-Object PSObject -Property @{ Url = $Url; Method = $Method; Status = 0; Headers = ''; Server = ''; Location = ''; Powered = ''; Body = ''; Error = ''; Cmd = "[Net.HttpWebRequest] $Method $Url (Timeout 3s, 리디렉션 미추적)$(if ($HostHdr) { " Host: $HostHdr" })" }
    try {
        $req = [Net.HttpWebRequest]::Create($Url)
        $req.Method = $Method; $req.Timeout = 3000; $req.ReadWriteTimeout = 3000; $req.AllowAutoRedirect = $false; $req.UserAgent = 'webwas-check/1.0'
        try { $req.Proxy = $null } catch {}
        if ($HostHdr) { try { $req.Host = $HostHdr } catch {} }
        $resp = $null
        try { $resp = $req.GetResponse() } catch [Net.WebException] { $resp = $_.Exception.Response; if (-not $resp) { $o.Error = $_.Exception.Message } }
        if ($resp) {
            $o.Status = [int]$resp.StatusCode
            $hl = @("HTTP/$($resp.ProtocolVersion) $([int]$resp.StatusCode) $($resp.StatusDescription)")
            foreach ($k in $resp.Headers.AllKeys) { $hl += "${k}: $($resp.Headers[$k])" }
            $o.Headers = $hl -join "`n"; $o.Server = "$($resp.Headers['Server'])"; $o.Location = "$($resp.Headers['Location'])"; $o.Powered = "$($resp.Headers['X-Powered-By'])"
            if ($Method -ne 'HEAD' -and $Method -ne 'TRACE') {
                try { $sr = New-Object IO.StreamReader($resp.GetResponseStream()); $buf = New-Object char[] 32768; $n = $sr.Read($buf, 0, 32768); if ($n -gt 0) { $o.Body = New-Object String($buf, 0, $n) }; $sr.Close() } catch {}
            }
            $resp.Close()
        }
    } catch { $o.Error = $_.Exception.Message }
    return $o
}
$script:HpTargets = @(); $script:HpRes = @{}; $script:HpNote = ''
function Get-ListenPorts {   # netstat -ano 파싱 (모든 Windows 버전): @{포트 = 바인드주소}
    $h = @{}
    try { foreach ($l in @(netstat -ano -p tcp 2>$null)) { if ("$l" -match '^\s*TCP\s+(\S+):(\d+)\s+\S+\s+LISTENING\s+(\d+)') { if (-not $h.ContainsKey([int]$matches[2])) { $h[[int]$matches[2]] = $matches[1] } } } } catch {}
    return $h
}
$script:Listen = Get-ListenPorts
function Hp-Add([string]$prod, [int]$port, [string]$scheme, [string]$origin, [string]$hostname = '') {
    if ($port -lt 1 -or $port -gt 65535) { return }
    foreach ($t in $script:HpTargets) { if ($t.Prod -eq $prod -and $t.Port -eq $port -and $t.Origin -eq $origin) { return } }
    $script:HpTargets += New-Object PSObject -Property @{ Prod = $prod; Port = $port; Scheme = $scheme; Origin = $origin; Hostname = $hostname }
}
function Hp-Collect {
    if (@($WEB_LIST) -contains 'iis' -and $script:Scopes.Count) {
        foreach ($sc in $script:Scopes) { foreach ($b in $sc.Bind) { if ($b -match '^(https?)://[^:]*:(\d+):(.*)$') { Hp-Add 'iis' ([int]$matches[2]) $matches[1] "IIS 사이트 $($sc.Site)" $matches[3] } } }
    }
    foreach ($cf in $APACHE_CONFS) {
        $ln = Get-ConfLines 'apache' $cf
        foreach ($l in (Cq $ln '^Listen\s+')) { if ($l.Text -match '^Listen\s+(\S+?:)?(\d+)(\s+(\w+))?') { $sch = 'http'; if ($matches[4] -eq 'https' -or $matches[2] -eq '443' -or $matches[2] -eq '8443') { $sch = 'https' }; Hp-Add 'apache' ([int]$matches[2]) $sch "Apache $cf" } }
    }
    foreach ($cf in $NGINX_CONFS) {
        $ln = Get-ConfLines 'nginx' $cf
        foreach ($l in (Cq $ln '^listen\s+')) { if ($l.Text -match '^listen\s+(\S+?:)?(\d+)(\s+[^;]*)?;?') { $sch = 'http'; if ("$($matches[3])" -match '\bssl\b') { $sch = 'https' }; Hp-Add 'nginx' ([int]$matches[2]) $sch "Nginx $cf" } }
    }
    foreach ($h in $TOMCAT_HOMES) {
        $f = "$h\conf\server.xml"; if (-not (Test-Path $f)) { continue }
        $t = Read-FileText $f; if ($null -eq $t) { continue }
        foreach ($m in [regex]::Matches((Strip-XmlComments $t), '(?s)<Connector\b[^>]*>')) {
            $c = $m.Value; if ($c -match 'protocol="AJP|ajp') { continue }
            if ($c -match '\bport="(\d+)"') { $sch = 'http'; if ($c -match 'SSLEnabled="true"|scheme="https"') { $sch = 'https' }; Hp-Add 'tomcat' ([int]$matches[1]) $sch "Tomcat $h" }
        }
    }
}
function Hp-Probe-All {
    if ($script:Listen.Count -eq 0) { $script:HpNote = 'netstat 으로 리슨 포트를 얻지 못해 구성된 포트를 모두 시도' }
    $done = @{}
    foreach ($t in $script:HpTargets) {
        $key = "$($t.Port)|$($t.Hostname)"
        if ($done.ContainsKey($key)) { continue }
        if ($script:Listen.Count -gt 0 -and -not $script:Listen.ContainsKey([int]$t.Port)) { continue }
        $done[$key] = 1
        $bind = '127.0.0.1'; if ($script:Listen.ContainsKey([int]$t.Port)) { $b = $script:Listen[[int]$t.Port]; if ($b -match '^\d+\.\d+\.\d+\.\d+$' -and $b -ne '0.0.0.0') { $bind = $b } }
        $other = if ($t.Scheme -eq 'https') { 'http' } else { 'https' }
        $sch = $t.Scheme
        $g = Invoke-Probe "${sch}://${bind}:$($t.Port)/" 'GET' $t.Hostname
        $g1 = $null
        if (-not $g.Status) { $g1 = $g; $g = Invoke-Probe "${other}://${bind}:$($t.Port)/" 'GET' $t.Hostname; if ($g.Status) { $sch = $other } }
        $r = New-Object PSObject -Property @{ Prod = $t.Prod; Port = $t.Port; Scheme = $sch; Bind = $bind; Hostname = $t.Hostname; Origin = $t.Origin; Get = $g; Get1 = $g1; Err = $null; Trace = $null }
        if ($g.Status) {
            $r.Err = Invoke-Probe "${sch}://${bind}:$($t.Port)/webwas-probe-$PID/none.html" 'GET' $t.Hostname
            $r.Trace = Invoke-Probe "${sch}://${bind}:$($t.Port)/" 'TRACE' $t.Hostname
        }
        $script:HpRes[$key] = $r
    }
}
function Hp-Results([string]$prod) { return @($script:HpRes.Values | Where-Object { $_.Prod -eq $prod } | Sort-Object Port) }
function Hp-Has([string]$prod) { return (@(Hp-Results $prod | Where-Object { $_.Get.Status }).Count -gt 0) }
function Hp-Leak([string]$srv) { if (-not $srv) { return $false }; $s = $srv -replace '(?i)Apache-Coyote/[\d.]+', ''; return ($s -match '[A-Za-z_-]+/\d+(\.\d+)+' -or $s -match '\((Ubuntu|Debian|Red Hat|CentOS|Unix|Win\w*|Amazon|SUSE)[^)]*\)') }
function Hp-Ev([string]$prod = '') {
    if (-not $script:HpTargets.Count) { "요청 대상 없음: 리슨 중인 HTTP/HTTPS 포트를 구성에서 찾지 못함 (netstat 리슨 포트 $($script:Listen.Count)개)"; return }
    $rs = if ($prod) { @(Hp-Results $prod) } else { @($script:HpRes.Values | Sort-Object Port) }
    if (-not $rs.Count) { "요청 결과 없음: $(if ($prod) { $prod } else { '웹 제품' }) 구성 포트가 리슨 중이 아님 (구성 포트: $(($script:HpTargets | Where-Object { (-not $prod) -or $_.Prod -eq $prod } | ForEach-Object { $_.Port }) -join ','))"; return }
    foreach ($r in $rs) {
        "== $($r.Prod) 포트 $($r.Port) ($($r.Origin)) 바인드 $($r.Bind)$(if ($r.Hostname) { " Host: $($r.Hostname)" })"
        foreach ($p in @($r.Get1, $r.Get, $r.Err, $r.Trace)) {
            if (-not $p) { continue }
            "-- $($p.Cmd)"
            if ($p.Status) { $p.Headers } else { "(응답 없음: $($p.Error))" }
            if ($p.Method -eq 'GET' -and $p.Body) { $bl = @($p.Body -split "`r?`n" | Where-Object { $_ -match 'Index of|Directory [Ll]isting|<title>|Apache Tomcat|nginx/|Server at|Detailed Error|HTTP Status' }); if ($bl.Count) { "-- 본문 중 목록/제품 표시 줄:"; $bl } }
        }
    }
}

# ── 점검 병합: V-<점검>-<제품> 은 한 대상(IIS 전체 / Apache·Nginx 설정 하나 / Tomcat 인스턴스 / JEUS 홈)의 "판정|근거" 를 반환 ──
$script:CurApache = ''; $script:CurNginx = ''; $script:ApL = @(); $script:NgL = @()
function Combine([string]$chk, [string]$T) {
    $r = ''
    foreach ($p in @('iis', 'apache', 'nginx', 'tomcat', 'jeus')) {
        if (-not (Pt $p $T)) { continue }
        $fn = "V-$chk-$p"; $has = [bool](Get-Command $fn -EA SilentlyContinue)
        $stub = "수동확인|$($script:PName[$p]) (Windows) 은 이 항목의 자동 판정을 지원하지 않음 - 증적의 설정 파일로 수동 확인"
        if ($p -eq 'iis') {
            $u = Iis-Un
            if ($u) { $r = WorseR $r (Lab 'IIS' $u) } elseif ($has) { $r = WorseR $r (Lab 'IIS' (& $fn)) } else { $r = WorseR $r (Lab 'IIS' $stub) }
        } elseif ($p -eq 'apache') {
            if (-not $APACHE_CONFS.Count) { $r = WorseR $r (Lab 'Apache' "점검불가|Apache 가 탐지됐으나($APACHE_HINT) 설정 파일(httpd.conf)을 찾지 못함 - 설정 경로 확인 필요") }
            else { foreach ($cf in $APACHE_CONFS) {
                $script:CurApache = $cf; $script:ApL = @(Get-ConfLines 'apache' $cf); $bad = @(Conf-Unreadable $script:ApL)
                if ($bad.Count) { $x = "점검불가|Apache 설정 파일 읽기 권한 없음/오류: $($bad -join ', ') (실행 계정 $env:USERNAME)" } elseif ($has) { $x = & $fn } else { $x = $stub }
                $r = WorseR $r (Lab "Apache $cf" $x) } }
        } elseif ($p -eq 'nginx') {
            if (-not $NGINX_CONFS.Count) { $r = WorseR $r (Lab 'Nginx' "점검불가|Nginx 가 탐지됐으나($NGINX_HINT) 설정 파일(nginx.conf)을 찾지 못함 - 설정 경로 확인 필요") }
            else { foreach ($cf in $NGINX_CONFS) {
                $script:CurNginx = $cf; $script:NgL = @(Get-ConfLines 'nginx' $cf); $bad = @(Conf-Unreadable $script:NgL)
                if ($bad.Count) { $x = "점검불가|Nginx 설정 파일 읽기 권한 없음/오류: $($bad -join ', ') (실행 계정 $env:USERNAME)" } elseif ($has) { $x = & $fn } else { $x = $stub }
                $r = WorseR $r (Lab "Nginx $cf" $x) } }
        } elseif ($p -eq 'tomcat') {
            if (-not $TOMCAT_HOMES.Count) { $r = WorseR $r (Lab 'Tomcat' "점검불가|Tomcat 이 탐지됐으나($TOMCAT_HINT) 설치 경로/설정(conf\server.xml)을 찾지 못함 - CATALINA_BASE 환경변수 지정 필요") }
            else { foreach ($h in $TOMCAT_HOMES) {
                $script:CurTomcat = $h
                if ($has) { $x = & $fn } else { $x = $stub }
                $r = WorseR $r (Lab "Tomcat $h" $x) } }
        } elseif ($p -eq 'jeus') {
            if (-not $JEUS_HOMES.Count) { $r = WorseR $r (Lab 'JEUS' "점검불가|JEUS 가 탐지됐으나($JEUS_HINT) 홈 디렉터리를 확인하지 못함 - JEUS_HOME 환경변수 지정 필요") }
            else { foreach ($h in $JEUS_HOMES) { $script:CurJeus = $h; if ($has) { $x = & $fn } else { $x = $stub }; $r = WorseR $r (Lab "JEUS $h" $x) } }
        }
    }
    return $r
}

# ── 응답 기반 판정 보정 ─────────────────────────────────────────
function Resp-Adjust([string]$cfg, [string]$rsp) {
    if (-not $rsp) { return $cfg }
    $rr = ($rsp -split '\|', 2)[0]; $cr = ($cfg -split '\|', 2)[0]
    if ($rr -eq '취약') { return (WorseR $cfg $rsp) }
    if ($rr -eq '양호' -and $cr -eq '취약') { return ("양호|" + ($rsp -split '\|', 2)[1] + " (설정 파일에서는 확인되지 않음: " + ($cfg -split '\|', 2)[1] + " - LB/프록시/상위 설정에서 처리되는 것으로 판단, 해당 구간 설정 증빙 확인 권고)") }
    if ($rr -eq '양호') { return ($cr + "|" + ($cfg -split '\|', 2)[1] + " / 응답: " + ($rsp -split '\|', 2)[1]) }
    return (WorseR $cfg $rsp)
}
function Resp-Server([string]$prod) {
    $leak = @(); $clean = @(); $trace = @()
    foreach ($r in @(Hp-Results $prod)) {
        if (-not $r.Get.Status) { continue }
        $tag = "$($r.Scheme):$($r.Port)"
        if (Hp-Leak $r.Get.Server) { $leak += "$tag[Server: $($r.Get.Server)]" } else { $clean += "$tag[Server: $(if ($r.Get.Server) { $r.Get.Server } else { '없음' })]" }
        if ($r.Get.Powered -match '/\d') { $leak += "$tag[X-Powered-By: $($r.Get.Powered)]" }
        if ($r.Trace -and $r.Trace.Status -eq 200) { $trace += ":$($r.Port)" }
    }
    if (-not ($leak.Count + $clean.Count)) { return '' }
    $tn = if ($trace.Count) { " (참고: TRACE 허용 응답 200 $($trace -join ' '))" } else { '' }
    if ($leak.Count) { return "취약|실제 응답 헤더에 서버 버전/OS 정보 노출: $($leak -join ' ')$tn" }
    return "양호|실제 응답 헤더에 버전 미노출: $($clean -join ' ')$tn"
}
function Resp-Listing([string]$prod) {
    $hit = @(); foreach ($r in @(Hp-Results $prod)) { if ($r.Get.Status -and $r.Get.Body -match 'Index of /|Directory [Ll]isting [Ff]or') { $hit += "$($r.Scheme):$($r.Port)" } }
    if ($hit.Count) { return "취약|실제 HTTP 응답에 디렉터리 목록 노출(포트 $($hit -join ' '))" }; return ''
}
function Resp-Err([string]$prod) {
    $bad = @(); $ok = @()
    foreach ($r in @(Hp-Results $prod)) {
        if (-not $r.Err -or -not ($r.Err.Status -ge 400)) { continue }
        $tag = "$($r.Scheme):$($r.Port)(상태 $($r.Err.Status))"
        if ($r.Err.Body -match 'The requested URL .* was not found on this server|Server at .* Port|<hr><center>nginx|HTTP Status \d+|Apache Tomcat/|<h1>Not Found</h1>') { $bad += $tag } else { $ok += $tag }
    }
    if ($bad.Count) { return "취약|존재하지 않는 경로 요청 시 제품 기본 오류 페이지가 응답됨: $($bad -join ' ')" }
    if ($ok.Count) { return "양호|존재하지 않는 경로 요청 시 기본 오류 페이지 아님(사용자 정의): $($ok -join ' ')" }
    return ''
}
function Resp-Redir([string]$prod) {
    $bad = @(); $okr = @(); $n = 0
    foreach ($r in @(Hp-Results $prod)) {
        if (-not $r.Get.Status -or $r.Scheme -ne 'http') { continue }; $n++
        $st = $r.Get.Status; $loc = $r.Get.Location
        if ($st -ge 301 -and $st -le 308 -and $loc -match '^https://') { $okr += ":$($r.Port)($st → $loc)" } else { $bad += ":$($r.Port)(상태 $st$(if ($loc) { " → $loc" } else { ', 리디렉션 아님' }))" }
    }
    if (-not $n) { if (@(Hp-Results $prod).Count) { return '양호|HTTP(비 TLS) 응답 포트 없음 - HTTPS 전용으로 보임' }; return '' }
    if ($bad.Count) { return "취약|실제 응답이 HTTPS 로 리디렉션되지 않음: $($bad -join ' ')$(if ($okr.Count) { " / 리디렉션 확인: $($okr -join ' ')" })" }
    return "양호|실제 응답이 HTTPS 로 리디렉션됨: $($okr -join ' ')"
}
function Resp-Ssl([string]$prod) {
    $ok = @(); foreach ($r in @(Hp-Results $prod)) { if ($r.Get.Status -and $r.Scheme -eq 'https') { $ok += ":$($r.Port)(상태 $($r.Get.Status))" } }
    if ($ok.Count) { return "양호|실제 HTTPS 응답 확인: $($ok -join ' ')" }; return ''
}
$script:Lbn = ' (로드밸런서·프록시에서 TLS 종료 시 해당 구간 설정 증빙으로 판단)'

# ═══ IIS ═══════════════════════════════════════════════════════
function V-listing-iis {
    $u = Iis-Un2; if ($u) { return $u }
    $on = @($script:Scopes | Where-Object { (Ws-Val $_ { param($n) $n.directoryBrowse.enabled }) -eq 'true' } | ForEach-Object { "$($_.Site)$(if ($_.Path -ne '/') { $_.Path })" })
    if ($on.Count) { $x = "취약|디렉터리 검색(directoryBrowse) 사용: $(Brief $on 5)" } else { $x = "양호|디렉터리 검색 사용 안 함 (사이트·응용 프로그램·가상 디렉터리 $($script:Scopes.Count)개 모두)$(Iis-WcNote)" }
    $rs = Resp-Listing 'iis'; if ($rs) { $x = WorseR $x $rs }
    return $x
}
function E-listing-iis { Scope-Ev-Head; Scope-Ev 'directoryBrowse.enabled' { param($n) $n.directoryBrowse.enabled } }
function V-updir-iis {
    $u = Iis-Un2; if ($u) { return $u }
    $pp = @($script:Scopes | Where-Object { (Ws-Val $_ { param($n) $n.asp.enableParentPaths }) -eq 'true' } | ForEach-Object { "$($_.Site)$(if ($_.Path -ne '/') { $_.Path })" })
    if ($pp.Count) { return "취약|ASP 부모 경로 사용(enableParentPaths=true): $(Brief $pp 5)" }
    return "양호|부모 경로 사용 안 함 (enableParentPaths 기본 false, 범위 $($script:Scopes.Count)개)$(Iis-WcNote)"
}
function E-updir-iis { Scope-Ev-Head; Scope-Ev 'asp.enableParentPaths' { param($n) $n.asp.enableParentPaths } }
function V-cgi-iis {
    $u = Iis-Un; if ($u) { return $u }
    $icr = $script:IISX.configuration.'system.webServer'.security.isapiCgiRestriction
    $nl = @(); if ($icr -and $icr.notListedIsapisAllowed -eq 'true') { $nl += 'ISAPI' }; if ($icr -and $icr.notListedCgisAllowed -eq 'true') { $nl += 'CGI' }
    $al = @(@($icr.add) | Where-Object { $_ -and $_.allowed -eq 'true' } | ForEach-Object { if ($_.description) { $_.description } else { Split-Path $_.path -Leaf } })
    if ($nl.Count) { return "취약|지정하지 않은 $($nl -join '·') 모듈 실행 허용 (notListed*Allowed=true)" }
    if ($al.Count) { return "수동확인|허용된 ISAPI/CGI 모듈: $($al -join ', ') - 사용하지 않는 모듈 허용 해제 여부 확인" }
    return '양호|허용된 ISAPI/CGI 모듈 없음'
}
function E-cgi-iis { $icr = $script:IISX.configuration.'system.webServer'.security.isapiCgiRestriction; Sec 'isapiCgiRestriction' @("notListedIsapisAllowed=$($icr.notListedIsapisAllowed) notListedCgisAllowed=$($icr.notListedCgisAllowed)"; @($icr.add) | Where-Object { $_ } | ForEach-Object { "$($_.description) $($_.path) allowed=$($_.allowed)" }) }
function V-unneeded-iis {
    $smp = @("$env:SystemDrive\inetpub\iissamples", "$env:SystemRoot\help\iishelp", "$env:ProgramFiles\Common Files\System\msadc\Samples", "$env:SystemRoot\System32\Inetsrv\IISADMPWD") | Where-Object { Test-Path $_ }
    if ($smp) { return "취약|샘플 디렉터리 존재: $(@($smp) -join ', ')" }
    return '양호|IIS 샘플 디렉터리 없음 (iissamples, iishelp, msadc\Samples, IISADMPWD 확인)'
}
function E-unneeded-iis { foreach ($p in @("$env:SystemDrive\inetpub\iissamples", "$env:SystemRoot\help\iishelp", "$env:ProgramFiles\Common Files\System\msadc\Samples", "$env:SystemRoot\System32\Inetsrv\IISADMPWD")) { "$p : $(if (Test-Path $p) { '존재' } else { '없음' })" } }
function V-upload-iis {
    $u = Iis-Un2; if ($u) { return $u }
    $lim = @(); $big = @()
    foreach ($sc in $script:Scopes) {
        $v = Ws-Val $sc { param($n) $n.security.requestFiltering.requestLimits.maxAllowedContentLength }
        $nm = "$($sc.Site)$(if ($sc.Path -ne '/') { $sc.Path })"
        if ($v -and [double]$v -ge 4294967295) { $big += $nm }
        $lim += "$nm=$(if ($v) { "$([math]::Round([double]$v/1MB,1))MB" } else { '기본 30MB' })"
    }
    if ($big.Count) { return "취약|요청 크기 제한 해제(최대값 4GB): $(Brief $big 5)" }
    return "양호|요청 크기 제한: $(Brief $lim 6)$(Iis-WcNote)"
}
function E-upload-iis { Scope-Ev-Head; Scope-Ev 'maxAllowedContentLength' { param($n) $n.security.requestFiltering.requestLimits.maxAllowedContentLength } }
function V-webproc-iis {
    $u = Iis-Un; if ($u) { return $u }
    $apd = $script:IISX.configuration.'system.applicationHost'.applicationPools
    $defId = if ($apd.applicationPoolDefaults.processModel.identityType) { "$($apd.applicationPoolDefaults.processModel.identityType)" } else { 'ApplicationPoolIdentity' }
    $pools = @(@($apd.add) | Where-Object { $_ } | ForEach-Object { New-Object PSObject -Property @{ N = "$($_.name)"; Id = $(if ($_.processModel.identityType) { "$($_.processModel.identityType)" } else { $defId }); U = "$($_.processModel.userName)" } })
    $ls = @($pools | Where-Object { $_.Id -eq 'LocalSystem' } | ForEach-Object { $_.N })
    $adm = Get-LocalGroupMemberNames 'S-1-5-32-544'
    $su = @(); $suAdm = @()
    foreach ($p in @($pools | Where-Object { $_.Id -eq 'SpecificUser' })) { $su += "$($p.N)($($p.U))"; if ($adm -ne $null -and (@($adm | Where-Object { $_ -ieq $p.U -or $_ -like "*\$($p.U)" }).Count)) { $suAdm += "$($p.N)($($p.U))" } }
    if ($ls.Count) { return "취약|관리자 권한(LocalSystem)으로 구동하는 응용 프로그램 풀: $($ls -join ', ')" }
    if ($suAdm.Count) { return "취약|로컬 Administrators 소속 계정으로 구동하는 응용 프로그램 풀: $($suAdm -join ', ')" }
    if ($su.Count -and $adm -eq $null) { return "점검불가|특정 사용자($($su -join ', '))로 구동하나 로컬 Administrators 구성원을 조회하지 못해 관리자 여부를 확인할 수 없음" }
    return "양호|응용 프로그램 풀 ID: $(($pools | ForEach-Object { "$($_.N):$($_.Id)" }) -join ', ')$(if ($su.Count) { " (특정 사용자 $($su -join ', ')는 Administrators 미소속)" })"
}
function E-webproc-iis {
    if ($script:IISX) { $apd = $script:IISX.configuration.'system.applicationHost'.applicationPools; Sec 'applicationHost 응용 프로그램 풀 ID' (@($apd.add) | Where-Object { $_ } | ForEach-Object { "$($_.name): identityType=$($_.processModel.identityType) userName=$($_.processModel.userName)" }) }
    Sec '로컬 Administrators 구성원' (Get-LocalGroupMemberNames 'S-1-5-32-544')
}
function V-proxy-iis {
    $u = Iis-Un2; if ($u) { return $u }
    $px = "$($script:IISX.configuration.'system.webServer'.proxy.enabled)" -eq 'true'
    $rw = @($script:Scopes | Where-Object { @(Ws-Nodes $_ | ForEach-Object { if ($_) { @($_.rewrite.rules.rule) } } | Where-Object { $_ -and "$($_.action.type)" -eq 'Rewrite' -and "$($_.action.url)" -match '^https?://' }).Count } | ForEach-Object { "$($_.Site)$(if ($_.Path -ne '/') { $_.Path })" })
    $arr = @($script:IISX.configuration.'system.webServer'.globalModules.add | Where-Object { $_ -and $_.name -eq 'ApplicationRequestRouting' }).Count
    if ($px -or $rw.Count) { return "수동확인|프록시 설정: $(if ($px) { 'ARR proxy enabled ' })$(if ($rw.Count) { "외부 URL Rewrite: $(Brief $rw 4)" }) - 업무상 필요 여부 확인 (불필요 시 취약)" }
    if ($arr) { return '수동확인|ARR(ApplicationRequestRouting) 모듈 설치됨 (proxy 비활성) - 사용 여부 확인' }
    return '양호|프록시(ARR)·외부 Rewrite 설정 없음 (ARR 모듈 미설치)'
}
function E-proxy-iis { if ($script:IISX) { Sec 'proxy/ARR/globalModules' @("proxy.enabled=$($script:IISX.configuration.'system.webServer'.proxy.enabled)"; @($script:IISX.configuration.'system.webServer'.globalModules.add | Where-Object { $_ -and $_.name -match 'ApplicationRequestRouting|Proxy' } | ForEach-Object { $_.name })) } else { 'IIS 설정 읽기 실패: ' + $script:IisErr } }
function V-docroot-iis {
    $u = Iis-Un2; if ($u) { return $u }
    $sys = @($script:Scopes | Where-Object { $_.Root -and ($_.Root.TrimEnd('\') -match '^[A-Za-z]:$' -or $_.Root -match '^[A-Za-z]:\\(Windows|Program Files|Users)(\\|$)') } | ForEach-Object { "$($_.Site)$($_.Path)($($_.Root))" })
    $def = @($script:Scopes | Where-Object { $_.Root -match '\\inetpub\\wwwroot\\?$' } | ForEach-Object { "$($_.Site)$($_.Path)($($_.Root))" })
    $adm = if ($script:IISX.OuterXml -match 'IISAdmin|IISAdmpwd') { ' + IISAdmin/IISAdmpwd 경로 존재' } else { '' }
    if ($sys.Count -or $adm) { return "취약|웹 서비스 경로가 시스템 영역과 분리되지 않음: $(Brief $sys 4)$adm" }
    if ($def.Count) { return "수동확인|설치 기본 경로 사용: $(Brief $def 4) - 업무 영역 분리·불필요 경로 확인 (가이드 조치: 별도 경로 지정)" }
    return "양호|별도 웹 서비스 경로 사용: $(Brief ($script:Scopes | ForEach-Object { $_.Root }) 6)"
}
function E-docroot-iis { Scope-Ev-Head; foreach ($sc in $script:Scopes) { "$($sc.Site)$(if ($sc.Path -ne '/') { $sc.Path }) [$($sc.Kind)] -> $($sc.Root) (풀 $($sc.Pool); 바인딩 $($sc.Bind -join ','))" } }
function V-links-iis {
    $u = Iis-Un2; if ($u) { return $u }
    $lnk = @(); foreach ($sc in $script:Scopes) { if ($sc.Root -and (Test-Path $sc.Root)) { $lnk += @(Find-Depth $sc.Root { param($i) (-not $i.PSIsContainer) -and $i.Name -like '*.lnk' } 4 100) } }
    $lnk = @($lnk | Select-Object -Unique)
    if ($lnk.Count) { return "취약|웹 서비스 경로(사이트·응용 프로그램·가상 디렉터리) 내 바로가기(.lnk) 파일: $(Brief $lnk 4)" }
    return "양호|웹 서비스 경로 $($script:Scopes.Count)개 범위(깊이 4) 내 바로가기(.lnk) 파일 없음"
}
function E-links-iis { Scope-Ev-Head; foreach ($sc in $script:Scopes) { if ($sc.Root -and (Test-Path $sc.Root)) { Sec ".lnk 검색: $($sc.Root)" (Find-Depth $sc.Root { param($i) (-not $i.PSIsContainer) -and $i.Name -like '*.lnk' } 4 100) } else { "경로 없음/접근 불가: $($sc.Root)" } } }
function V-confexp-iis {
    $u = Iis-Un2; if ($u) { return $u }
    $m = @($script:Scopes | Where-Object { @(Ws-Handlers $_ | Where-Object { $_ -match '^\*\.(asa|asax)$' }).Count } | ForEach-Object { "$($_.Site)$(if ($_.Path -ne '/') { $_.Path })" })
    $f = @($script:Scopes | Where-Object { @(Ws-Nodes $_ | ForEach-Object { if ($_) { @($_.security.requestFiltering.fileExtensions.add) } } | Where-Object { $_ -and "$($_.fileExtension)" -match '^\.(asa|asax)$' -and "$($_.allowed)" -eq 'true' }).Count } | ForEach-Object { "$($_.Site)$(if ($_.Path -ne '/') { $_.Path })" })
    if ($m.Count -or $f.Count) { return "취약|asa/asax $(if ($m.Count) { "처리기 매핑: $(Brief $m 4) " })$(if ($f.Count) { "요청 필터링 허용: $(Brief $f 4)" })" }
    return "양호|asa/asax 처리기 매핑·요청 필터링 허용 없음 (범위 $($script:Scopes.Count)개)$(Iis-WcNote)"
}
function E-confexp-iis { Scope-Ev-Head; foreach ($sc in $script:Scopes) { "$($sc.Site)$(if ($sc.Path -ne '/') { $sc.Path }) handlers(asa/asax)=$((Ws-Handlers $sc | Where-Object { $_ -match '\.(asa|asax)$' }) -join ',')" } }
function V-confperm-iis {
    $u = Iis-Un2; if ($u) { return $u }
    $e = @(); $unr = @(); $n = 0
    foreach ($sc in $script:Scopes) { foreach ($t in @($sc.Root, $(if ($sc.Root) { Join-Path $sc.Root 'web.config' }))) {
        if (-not $t -or -not (Test-Path $t)) { continue }; $n++
        $a = Get-Acl $t -EA SilentlyContinue
        if (-not $a) { $unr += $t; continue }
        if (@($a.Access | Where-Object { (Get-AceSid $_) -eq 'S-1-1-0' -and "$($_.AccessControlType)" -eq 'Allow' }).Count) { $e += $t } } }
    if ($e.Count) { return "취약|Everyone 권한이 있는 홈 디렉터리·web.config: $(Brief ($e | Select-Object -Unique) 4)" }
    if ($unr.Count) { return "점검불가|ACL 조회 실패: $(Brief $unr 3) (실행 계정 $env:USERNAME)" }
    return "양호|홈 디렉터리·web.config $n 개에 Everyone 권한 없음"
}
function E-confperm-iis { foreach ($sc in $script:Scopes) { foreach ($t in @($sc.Root, $(if ($sc.Root) { Join-Path $sc.Root 'web.config' }))) { if ($t -and (Test-Path $t)) { $a = Get-Acl $t -EA SilentlyContinue; "== $t"; if ($a) { $a.Access | ForEach-Object { "  $($_.IdentityReference) $($_.AccessControlType) $($_.FileSystemRights)" } } else { '  (ACL 조회 불가)' } } } } }
function V-scriptmap-iis {
    $u = Iis-Un2; if ($u) { return $u }
    $v = @($script:Scopes | ForEach-Object { $n = "$($_.Site)$(if ($_.Path -ne '/') { $_.Path })"; @(Ws-Handlers $_ | Where-Object { $_ -match '^\*\.(htr|idc|stm|shtm|shtml|printer|htw|ida|idq)$' } | ForEach-Object { "${n}:$_" }) })
    if ($v.Count) { return "취약|취약한 스크립트 매핑: $(Brief $v 5)" }
    return "양호|취약한 스크립트 매핑 없음 (범위 $($script:Scopes.Count)개)$(Iis-WcNote)"
}
function E-scriptmap-iis { Scope-Ev-Head; foreach ($sc in $script:Scopes) { "$($sc.Site)$(if ($sc.Path -ne '/') { $sc.Path }) handlers=$((Ws-Handlers $sc) -join ',')" } }
function V-servinfo-iis {
    $u = Iis-Un2; if ($u) { return $u }
    $noRm = @($script:Scopes | Where-Object { (Ws-Val $_ { param($n) $n.security.requestFiltering.removeServerHeader }) -ne 'true' } | ForEach-Object { "$($_.Site)$(if ($_.Path -ne '/') { $_.Path })" })
    $xp = @($script:Scopes | Where-Object { @(Ws-Nodes $_ | ForEach-Object { if ($_) { @($_.httpProtocol.customHeaders.add) } } | Where-Object { $_ -and "$($_.name)" -eq 'X-Powered-By' }).Count } | ForEach-Object { "$($_.Site)$(if ($_.Path -ne '/') { $_.Path })" })
    if ($noRm.Count -or $xp.Count) { $cfg = "취약|IIS 응답 헤더 정보 노출 설정: Server 헤더 제거(removeServerHeader) 미설정 $(Brief $noRm 3)$(if ($xp.Count) { " / X-Powered-By 헤더 사용 $(Brief $xp 3)" })" } else { $cfg = '양호|removeServerHeader=true 이고 X-Powered-By 헤더 미사용' }
    return (Resp-Adjust $cfg (Resp-Server 'iis'))
}
function E-servinfo-iis { Scope-Ev-Head; Scope-Ev 'removeServerHeader' { param($n) $n.security.requestFiltering.removeServerHeader }; Sec 'customHeaders (X-Powered-By 등)' $(foreach ($sc in $script:Scopes) { foreach ($n in @(Ws-Nodes $sc)) { if ($n) { @($n.httpProtocol.customHeaders.add) | Where-Object { $_ } | ForEach-Object { "$($sc.Site)$($sc.Path): $($_.name)=$($_.value)" } } } }); Hp-Ev 'iis' }
function V-webdav-iis {
    $u = Iis-Un; if ($u) { return $u }
    $dm = @($script:IISX.configuration.'system.webServer'.globalModules.add | Where-Object { $_ -and $_.name -eq 'WebDAVModule' }).Count
    $da = @($script:Scopes | Where-Object { (Ws-Val $_ { param($n) $n.webdav.authoring.enabled }) -eq 'true' } | ForEach-Object { "$($_.Site)$(if ($_.Path -ne '/') { $_.Path })" })
    if ($dm -and $da.Count) { return "취약|WebDAV 활성: 작성 사용 $(Brief $da 4)" }
    if ($dm) { return '양호|WebDAV 모듈 설치, 작성(authoring) 비활성' }
    return '양호|WebDAV 모듈 미설치'
}
function E-webdav-iis { if ($script:IISX) { Sec 'WebDAV 모듈' @($script:IISX.configuration.'system.webServer'.globalModules.add | Where-Object { $_ -and $_.name -match 'WebDAV' } | ForEach-Object { $_.name }); Scope-Ev 'webdav.authoring.enabled' { param($n) $n.webdav.authoring.enabled } } }
function V-ssi-iis {
    $u = Iis-Un2; if ($u) { return $u }
    $mod = @($script:IISX.configuration.'system.webServer'.globalModules.add | Where-Object { $_ -and $_.name -eq 'ServerSideIncludeModule' }).Count
    $v = @($script:Scopes | ForEach-Object { $n = "$($_.Site)$(if ($_.Path -ne '/') { $_.Path })"; @(Ws-Handlers $_ | Where-Object { $_ -match '^\*\.(shtml|shtm|stm)$' } | ForEach-Object { "${n}:$_" }) })
    if ($v.Count) { return "취약|SSI 확장자 매핑: $(Brief $v 5)" }
    if ($mod) { return '양호|SSI 모듈은 설치됐으나 .shtml/.shtm/.stm 처리기 매핑 없음' }
    return '양호|SSI 모듈 미설치, 확장자 매핑 없음'
}
function E-ssi-iis { E-scriptmap-iis }
function V-errpage-iis {
    $u = Iis-Un2; if ($u) { return $u }
    $nc = @($script:Scopes | Where-Object { (Ws-Val $_ { param($n) $n.httpErrors.errorMode }) -ne 'Custom' } | ForEach-Object { "$($_.Site)$(if ($_.Path -ne '/') { $_.Path })($(if ($m = Ws-Val $_ { param($n) $n.httpErrors.errorMode }) { $m } else { 'DetailedLocalOnly 기본' }))" })
    if ($nc.Count) { $cfg = "취약|'사용자 지정 오류 페이지' 미설정(errorMode≠Custom; DetailedLocalOnly 기본값 포함): $(Brief $nc 5)" } else { $cfg = '양호|전 범위 사용자 지정 오류 페이지(errorMode=Custom)' }
    return (Resp-Adjust $cfg (Resp-Err 'iis'))
}
function E-errpage-iis { Scope-Ev-Head; Scope-Ev 'httpErrors.errorMode' { param($n) $n.httpErrors.errorMode }; Hp-Ev 'iis' }
function V-ssl-iis {
    $u = Iis-Un2; if ($u) { return $u }
    $noS = @($script:Scopes | Where-Object { $_.Path -eq '/' -and -not @($_.Bind | Where-Object { $_ -like 'https://*' }).Count } | ForEach-Object { $_.Site })
    if ($noS.Count) { $cfg = "취약|HTTPS 바인딩 없는 사이트(FTP 전용 제외): $($noS -join ', ')$($script:Lbn)" } else { $cfg = '양호|HTTP 사이트 모두 HTTPS 바인딩 있음' }
    return (Resp-Adjust $cfg (Resp-Ssl 'iis'))
}
function E-ssl-iis { Scope-Ev-Head; foreach ($sc in $script:Scopes) { if ($sc.Path -eq '/') { "$($sc.Site): $($sc.Bind -join ', ')" } }; Hp-Ev 'iis' }
function V-redirect-iis {
    $u = Iis-Un2; if ($u) { return $u }
    $noR = @()
    foreach ($site in @($script:Scopes | Where-Object { $_.Path -eq '/' })) {
        $http = @($site.Bind | Where-Object { $_ -like 'http://*' }).Count
        if (-not $http) { continue }
        $redir = ((Ws-Val $site { param($n) if ($n.httpRedirect.enabled -eq 'true') { $n.httpRedirect.destination } }) -match '^https://') -or
                 (@(Ws-Nodes $site | ForEach-Object { if ($_) { @($_.rewrite.rules.rule) } } | Where-Object { $_ -and "$($_.action.type)" -eq 'Redirect' -and "$($_.action.url)" -match '^https://' }).Count -gt 0) -or
                 ((Ws-Val $site { param($n) $n.security.access.sslFlags }) -match 'Ssl')
        if (-not $redir) { $noR += $site.Site }
    }
    if ($noR.Count) { $cfg = "취약|HTTP 접근 시 HTTPS 리디렉션 미설정: $($noR -join ', ')$($script:Lbn)" } else { $cfg = '양호|HTTP 바인딩 사이트 HTTPS 리디렉션(또는 SSL 필요) 설정' }
    $rsp = Resp-Redir 'iis'
    if ($rsp -and ($rsp -split '\|')[0] -eq '취약' -and ($cfg -split '\|')[0] -eq '양호') { return ("수동확인|설정에는 HTTPS 리디렉션이 있으나 기본 호스트 실제 응답은 리디렉션 아님 - 호스트 헤더별 응답 확인 필요 (" + ($rsp -split '\|', 2)[1] + ")") }
    return (Resp-Adjust $cfg $rsp)
}
function E-redirect-iis { Scope-Ev-Head; Scope-Ev 'httpRedirect.enabled' { param($n) $n.httpRedirect.enabled }; Scope-Ev 'sslFlags' { param($n) $n.security.access.sslFlags }; Hp-Ev 'iis' }
function V-uploaddirs-iis {
    $u = Iis-Un2; if ($u) { return $u }
    $ud = @(); foreach ($sc in $script:Scopes) { if ($sc.Root -and (Test-Path $sc.Root)) { $ud += @(Find-Depth $sc.Root { param($i) $i.PSIsContainer -and $i.Name -match '^(upload|attach|userfile)' } 4 50) } }
    $ud = @($ud | Select-Object -Unique)
    if (-not $ud.Count) { return "수동확인|웹 경로 내 업로드 디렉터리(upload/attach) 미발견 (검색 $($script:Scopes.Count)개 범위) - 애플리케이션 업로드 경로(웹 외부)·권한 확인" }
    $bad = @(); $unr = @()
    foreach ($d in $ud) { $a = Get-Acl $d -EA SilentlyContinue; if (-not $a) { $unr += $d; continue }; if (@($a.Access | Where-Object { @('S-1-1-0', 'S-1-5-32-545') -contains (Get-AceSid $_) -and "$($_.AccessControlType)" -eq 'Allow' -and "$($_.FileSystemRights)" -match 'Write|Modify|FullControl' }).Count) { $bad += $d } }
    if ($bad.Count) { return "취약|업로드 디렉터리에 Everyone/Users 쓰기 권한: $(Brief $bad 4)" }
    if ($unr.Count) { return "점검불가|업로드 디렉터리 ACL 조회 실패: $(Brief $unr 3)" }
    return "수동확인|업로드 디렉터리 일반 사용자 쓰기 권한 없음: $(Brief $ud 4) - 웹 경로 내 위치 시 스크립트 실행 권한 제거 여부 확인"
}
function E-uploaddirs-iis { Scope-Ev-Head; foreach ($sc in $script:Scopes) { if ($sc.Root -and (Test-Path $sc.Root)) { $f = @(Find-Depth $sc.Root { param($i) $i.PSIsContainer -and $i.Name -match '^(upload|attach|userfile)' } 4 50); Sec "업로드 후보: $($sc.Root)" $f; foreach ($d in $f) { $a = Get-Acl $d -EA SilentlyContinue; "== $d"; if ($a) { $a.Access | ForEach-Object { "  $($_.IdentityReference) $($_.FileSystemRights)" } } } } else { "경로 없음: $($sc.Root)" } } }
function V-logperm-iis {
    $u = Iis-Un; if ($u) { return $u }
    $dirs = @(); $sd = $script:IISX.configuration.'system.applicationHost'.sites
    $def = [Environment]::ExpandEnvironmentVariables("$($sd.siteDefaults.logFile.directory)"); if (-not $def) { $def = "$env:SystemDrive\inetpub\logs\LogFiles" }
    $dirs += $def; foreach ($s in @($sd.site)) { if ($s -and $s.logFile.directory) { $dirs += [Environment]::ExpandEnvironmentVariables("$($s.logFile.directory)") } }
    $dirs = @($dirs | Select-Object -Unique)
    $bad = @(); $unr = @(); $ok = @()
    foreach ($d in $dirs) {
        if (-not (Test-Path $d)) { $unr += "$d(없음)"; continue }
        $a = Get-Acl $d -EA SilentlyContinue; if (-not $a) { $unr += "$d(ACL 조회 불가)"; continue }
        if (@($a.Access | Where-Object { (Get-AceSid $_) -eq 'S-1-1-0' }).Count) { $bad += $d } else { $ok += $d }
    }
    if ($bad.Count) { return "취약|IIS 로그 디렉터리 Everyone 권한: $($bad -join ', ')" }
    if ($unr.Count -and -not $ok.Count) { return "점검불가|IIS 로그 디렉터리 확인 불가: $($unr -join ', ') (실행 계정 $env:USERNAME)" }
    return "양호|IIS 로그 디렉터리 Everyone 권한 없음: $($ok -join ', ')$(if ($unr.Count) { " / 확인 불가: $($unr -join ', ')" })"
}
function E-logperm-iis { if ($script:IISX) { $sd = $script:IISX.configuration.'system.applicationHost'.sites; $d = [Environment]::ExpandEnvironmentVariables("$($sd.siteDefaults.logFile.directory)"); if (-not $d) { $d = "$env:SystemDrive\inetpub\logs\LogFiles" }; foreach ($x in @($d) + @(@($sd.site) | Where-Object { $_ -and $_.logFile.directory } | ForEach-Object { [Environment]::ExpandEnvironmentVariables("$($_.logFile.directory)") })) { "== $x"; $a = Get-Acl $x -EA SilentlyContinue; if ($a) { $a.Access | ForEach-Object { "  $($_.IdentityReference) $($_.FileSystemRights)" } } else { '  (없음/조회 불가)' } } } }
function V-pwfile-iis {
    $sam = "$env:SystemRoot\System32\config\SAM"; $a = Get-Acl $sam -EA SilentlyContinue
    if (-not $a) { return "점검불가|SAM 파일 ACL 조회 불가 - 관리자 권한 필요 (실행 계정 $env:USERNAME, 관리자 여부 $($script:IsAdmin))" }
    $x = @($a.Access | Where-Object { @('S-1-5-18', 'S-1-5-32-544') -notcontains (Get-AceSid $_) } | ForEach-Object { "$($_.IdentityReference)" })
    if ($x.Count) { return "취약|SAM 파일에 Administrators·SYSTEM 외 권한: $($x -join ', ')" }
    return '양호|SAM 파일 권한 Administrators·SYSTEM 만'
}
function E-pwfile-iis { $sam = "$env:SystemRoot\System32\config\SAM"; $a = Get-Acl $sam -EA SilentlyContinue; "== $sam"; if ($a) { $a.Access | ForEach-Object { "  $($_.IdentityReference) $($_.AccessControlType) $($_.FileSystemRights)" } } else { '  (ACL 조회 불가 - 관리자 권한 필요)' } }
function V-weakpw-iis { return '수동확인|IIS 관리는 Windows 계정 사용 - 관리자 비밀번호 복잡도(2종 10자/3종 8자)·유추 어려움 확인 (정책값은 증적 참조, Windows 서버 W-01·W-09 참고)' }
function E-weakpw-iis { "PasswordComplexity=$(Get-SecPol 'PasswordComplexity') MinimumPasswordLength=$(Get-SecPol 'MinimumPasswordLength') MaximumPasswordAge=$(Get-SecPol 'MaximumPasswordAge')" }
function V-eos-iis { $osn = (Get-CimInstance Win32_OperatingSystem -EA SilentlyContinue).Caption; if ($IIS_VERSION -ne '' -and $IIS_VERSION -ne 'unknown') { return "수동확인|IIS $IIS_VERSION (Windows Server 버전 종속) - OS EoS 는 OS 항목 참조: $osn" }; return '점검불가|IIS 버전을 레지스트리(HKLM:\SOFTWARE\Microsoft\InetStp)에서 확인하지 못함' }
function E-eos-iis { Sec 'IIS 버전' @("InetStp MajorVersion.MinorVersion=$IIS_VERSION", "VersionString=$(Get-Reg 'HKLM:\SOFTWARE\Microsoft\InetStp' 'VersionString')") }
function V-ldap-iis { return '수동확인|IIS 는 LDAP 알고리즘을 직접 설정하지 않음 - LDAP/LDAPS 연동 시 SCHANNEL(TLS1.0/1.1·RC4/3DES) 비활성 및 단순/익명 바인드 금지 여부 확인 (증적 참조)' }
function E-ldap-iis { Sec 'SCHANNEL 프로토콜' (Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols' -Recurse -EA SilentlyContinue | ForEach-Object { $p = Get-ItemProperty $_.PSPath -EA SilentlyContinue; "$($_.Name) Enabled=$($p.Enabled) DisabledByDefault=$($p.DisabledByDefault)" }) }
function V-wst044-iis { return '수동확인|IIS 관리자 계정 및 기본 자격증명 변경 여부 확인 (IIS 관리자 사용자는 administration.config 참조)' }
function E-wst044-iis { $f = "$env:windir\System32\inetsrv\config\administration.config"; if (Test-Path $f) { $t = Read-FileText $f; if ($null -ne $t) { Sec 'administration.config <users>' ([regex]::Matches($t, '<user [^>]*>') | ForEach-Object { $_.Value -replace '(password|salt)="[^"]*"', '$1="****"' }) } else { "administration.config 읽기 실패: $($script:LastReadErr)" } } else { 'administration.config 없음' } }

# ═══ Apache (Windows) ══════════════════════════════════════════
function V-listing-apache {
    $o = @(); $dir = $null
    foreach ($l in (Cq $script:ApL '^Options\s')) {
        $tok = @($l.Text -split '\s+' | Select-Object -Skip 1); $on = $false
        foreach ($w in $tok) { if ($w -match '^\+?Indexes$') { $on = $true } elseif ($w -match '^-Indexes$') { $on = $false } }
        if ($on) { $o += "$($l.File):$($l.Line): $($l.Text)" }
    }
    $x = if ($o.Count) { "취약|디렉터리 리스팅(Options Indexes) 허용: $(Brief $o 2)" } else { '양호|Options Indexes 미사용 (Options -Indexes 는 제외, 주석 제외, Include 전개 파일 ' + @(Conf-Files $script:ApL).Count + '개)' }
    $rs = Resp-Listing 'apache'; if ($rs) { $x = WorseR $x $rs }
    return $x
}
function E-listing-apache { Sec "Apache Options ($($script:CurApache), Include 전개 $(@(Conf-Files $script:ApL).Count)개 파일)" (Cqf $script:ApL '^Options\s') }
function V-servinfo-apache {
    $tk = (Cq $script:ApL '^ServerTokens\s' | Select-Object -Last 1); $sg = (Cq $script:ApL '^ServerSignature\s' | Select-Object -Last 1)
    $tv = if ($tk) { ($tk.Text -split '\s+')[1] } else { '' }; $sv = if ($sg) { ($sg.Text -split '\s+')[1] } else { 'Off' }
    if ($tv -match '^(Prod|ProductOnly)$' -and $sv -eq 'Off') { $cfg = "양호|ServerTokens $tv, ServerSignature $sv" } else { $cfg = "취약|헤더 정보 노출 설정 (ServerTokens=$(if ($tv) { $tv } else { '미설정(Full)' }), ServerSignature=$sv) - 가이드: ServerTokens Prod + ServerSignature Off" }
    return (Resp-Adjust $cfg (Resp-Server 'apache'))
}
function E-servinfo-apache { Sec 'Apache ServerTokens/ServerSignature' (Cqf $script:ApL '^Server(Tokens|Signature)\s'); Hp-Ev 'apache' }
function V-ssi-apache {
    $o = @(); foreach ($l in (Cq $script:ApL '^Options\s')) { $on = $false; foreach ($w in @($l.Text -split '\s+' | Select-Object -Skip 1)) { if ($w -match '^\+?Includes(NOEXEC)?$') { $on = $true } elseif ($w -match '^-Includes') { $on = $false } }; if ($on) { $o += "$($l.File):$($l.Line): $($l.Text)" } }
    if ($o.Count) { return "취약|SSI 활성: $(Brief $o 2)" }; return '양호|Options Includes 미사용 (SSI 비활성)'
}
function E-ssi-apache { Sec 'Apache Options/AddOutputFilter/AddHandler' (Cqf $script:ApL '^(Options|AddOutputFilter|AddHandler|AddType)\s') }
function V-proxy-apache {
    if (Cq $script:ApL '^ProxyRequests\s+On') { return '취약|ProxyRequests On (포워드/오픈 프록시 허용)' }
    $pp = @(Cqf $script:ApL '^ProxyPass(Match)?\s')
    if ($pp.Count) { return "수동확인|역프록시 설정: $(Brief $pp 2) - 업무상 필요 여부 확인 (불필요 시 취약)" }; return '양호|프록시 설정 없음'
}
function E-proxy-apache { Sec 'Apache 프록시' (Cqf $script:ApL '^(LoadModule\s+proxy|ProxyRequests|ProxyPass)') }
function V-errpage-apache {
    $ed = @(Cq $script:ApL '^ErrorDocument\s+[45]\d\d' | ForEach-Object { ($_.Text -split '\s+')[1] } | Select-Object -Unique)
    $miss = @(); if ($script:ErrStrict) { if ($ed -notcontains '404') { $miss += '404' }; if (-not @($ed | Where-Object { $_ -match '^5' }).Count) { $miss += '5xx' } } elseif (-not $ed.Count) { $miss += '전체' }
    if ($miss.Count) { $cfg = "취약|ErrorDocument 미설정 코드: $($miss -join ',') (설정: $($ed -join ' ')) - 기본 에러 페이지 노출" } else { $cfg = "양호|ErrorDocument 설정 ($($ed -join ' '))" }
    return (Resp-Adjust $cfg (Resp-Err 'apache'))
}
$script:ErrStrict = $false
function E-errpage-apache { Sec 'Apache ErrorDocument' (Cqf $script:ApL '^ErrorDocument\s'); Hp-Ev 'apache' }
function V-upload-apache { $l = @(Cq $script:ApL '^LimitRequestBody\s+[1-9]'); if ($l.Count) { return "양호|LimitRequestBody $((($l | Select-Object -First 1).Text -split '\s+')[1]) bytes" }; return '취약|LimitRequestBody 미설정(또는 0=무제한)' }
function E-upload-apache { Sec 'Apache LimitRequestBody' (Cqf $script:ApL '^LimitRequestBody') }
function V-webdav-apache { if (Cq $script:ApL '^Dav\s+On') { return '취약|WebDAV 활성 (Dav On)' }; return '양호|Dav On 설정 없음 (WebDAV 비활성)' }
function E-webdav-apache { Sec 'Apache Dav' (Cqf $script:ApL '^(Dav\s|LoadModule\s+dav)') }
function V-ssl-apache { if (Cq $script:ApL '^SSLEngine\s+on') { $cfg = '양호|SSLEngine on (SSL/TLS 활성)' } else { $cfg = "취약|SSL/TLS 미설정 (SSLEngine on 없음)$($script:Lbn)" }; return (Resp-Adjust $cfg (Resp-Ssl 'apache')) }
function E-ssl-apache { Sec 'Apache SSL/Listen' (Cqf $script:ApL '^(Listen|SSLEngine|SSLProtocol)\s'); Hp-Ev 'apache' }
function V-redirect-apache {
    if (Cq $script:ApL '^(Redirect(Permanent|Match)?\s.*https://|RewriteRule\s.*https://)') { $cfg = '양호|HTTP→HTTPS 리디렉션 설정' } else { $cfg = "취약|HTTP→HTTPS 리디렉션 미설정$($script:Lbn)" }
    $rsp = Resp-Redir 'apache'
    if ($rsp -and ($rsp -split '\|')[0] -eq '취약' -and ($cfg -split '\|')[0] -eq '양호') { return ("수동확인|설정에는 HTTPS 리디렉션이 있으나 기본 호스트 실제 응답은 리디렉션 아님 - 이름 기반 가상호스트별 응답 확인 필요 (" + ($rsp -split '\|', 2)[1] + ")") }
    return (Resp-Adjust $cfg $rsp)
}
function E-redirect-apache { Sec 'Apache 리디렉션' (Cqf $script:ApL '^(Redirect|RewriteRule|RewriteCond|RewriteEngine)'); Hp-Ev 'apache' }
function E-ldap-apache { Sec 'Apache LDAP' (Cqf $script:ApL '^(AuthLDAP|LDAPTrusted)') }
function V-ldap-apache { if (Cq $script:ApL '^(AuthLDAP|LDAPTrusted)') { return '수동확인|LDAP 인증 지시자 존재 - 알고리즘/ldaps 사용 확인' }; return '양호|LDAP 연동 지시자 없음' }
function V-dirtrav-apache {
    $exe = $null; foreach ($pr in $script:Procs) { if ("$($pr.Name)" -match '^httpd(\.exe)?$' -and $pr.ExecutablePath) { $exe = $pr.ExecutablePath; break } }
    if (-not $exe) { $exe = "$(Split-Path (Split-Path $script:CurApache))\bin\httpd.exe" }
    if (-not (Test-Path $exe)) { return '점검불가|Apache 버전 확인 실패(httpd.exe 를 찾지 못함) - Directory Traversal 취약 버전(2.4.49/2.4.50) 여부 판정 불가' }
    $v = (& $exe -v 2>&1 | Out-String); $ver = if ($v -match 'Apache/(\d+\.\d+\.\d+)') { $matches[1] } else { '' }
    if (-not $ver) { return "점검불가|Apache 버전 확인 실패(httpd -v 출력 없음: $exe)" }
    if ($ver -eq '2.4.49' -or $ver -eq '2.4.50') { return "취약|Apache $ver - Directory Traversal 취약 버전 (CVE-2021-41773/42013)" }
    return "양호|Apache $ver - Directory Traversal 취약 버전(2.4.49/2.4.50) 아님"
}
function E-dirtrav-apache { $exe = "$(Split-Path (Split-Path $script:CurApache))\bin\httpd.exe"; if (Test-Path $exe) { & $exe -v 2>&1 } else { "httpd.exe 없음: $exe" } }

# ═══ Nginx (Windows) ═══════════════════════════════════════════
function V-listing-nginx { if (Cq $script:NgL '^autoindex\s+on') { $x = "취약|autoindex on: $(Brief (Cqf $script:NgL '^autoindex\s+on') 2)" } else { $x = '양호|autoindex on 설정 없음 (기본 off, 주석 제외, include 전개 ' + @(Conf-Files $script:NgL).Count + '개 파일)' }; $rs = Resp-Listing 'nginx'; if ($rs) { $x = WorseR $x $rs }; return $x }
function E-listing-nginx { Sec "Nginx autoindex ($($script:CurNginx))" (Cqf $script:NgL '^autoindex\s') }
function V-servinfo-nginx { if (Cq $script:NgL '^server_tokens\s+off') { $cfg = '양호|server_tokens off' } else { $cfg = '취약|server_tokens off 미설정 (버전 노출)' }; return (Resp-Adjust $cfg (Resp-Server 'nginx')) }
function E-servinfo-nginx { Sec 'Nginx server_tokens' (Cqf $script:NgL '^server_tokens\s'); Hp-Ev 'nginx' }
function V-ssi-nginx { if (Cq $script:NgL '^ssi\s+on') { return '취약|Nginx ssi on' }; return '양호|Nginx ssi 미사용' }
function E-ssi-nginx { Sec 'Nginx ssi' (Cqf $script:NgL '^ssi\s') }
function V-proxy-nginx { $pp = @(Cqf $script:NgL '^proxy_pass\s'); if ($pp.Count) { return "수동확인|proxy_pass 설정: $(Brief $pp 2) - 업무상 필요 여부 확인 (불필요 시 취약)" }; return '양호|프록시 설정 없음' }
function E-proxy-nginx { Sec 'Nginx proxy_pass' (Cqf $script:NgL '^proxy_pass\s') }
function V-errpage-nginx {
    $ep = @(Cq $script:NgL '^error_page\s' | ForEach-Object { [regex]::Matches($_.Text, '\b[45]\d\d\b') | ForEach-Object { $_.Value } } | Select-Object -Unique)
    $miss = @(); if ($script:ErrStrict) { if ($ep -notcontains '404') { $miss += '404' }; if (-not @($ep | Where-Object { $_ -match '^5' }).Count) { $miss += '5xx' } } elseif (-not $ep.Count) { $miss += '전체' }
    if ($miss.Count) { $cfg = "취약|error_page 미설정 코드: $($miss -join ',') (설정: $($ep -join ' '))" } else { $cfg = "양호|error_page 설정 ($($ep -join ' '))" }
    return (Resp-Adjust $cfg (Resp-Err 'nginx'))
}
function E-errpage-nginx { Sec 'Nginx error_page' (Cqf $script:NgL '^error_page\s'); Hp-Ev 'nginx' }
function V-upload-nginx { if (Cq $script:NgL '^client_max_body_size\s+0[kKmMgG]?;?$') { return '취약|client_max_body_size 0 (제한 해제)' }; $v = @(Cq $script:NgL '^client_max_body_size\s' | ForEach-Object { ($_.Text -split '\s+')[1] }); return "양호|client_max_body_size $(if ($v.Count) { $v -join ' ' } else { '미설정(기본 1m 제한)' })" }
function E-upload-nginx { Sec 'Nginx client_max_body_size' (Cqf $script:NgL '^client_max_body_size') }
function V-webdav-nginx { if (@(@(Cq $script:NgL '^dav_methods\s') | Where-Object { $_.Text -notmatch 'off' }).Count) { return '취약|dav_methods 설정' }; return '양호|WebDAV(dav_methods) 미사용' }
function E-webdav-nginx { Sec 'Nginx dav' (Cqf $script:NgL '^dav_') }
function V-ssl-nginx { if (Cq $script:NgL '^listen\s.*\bssl\b') { $cfg = '양호|listen ssl (SSL/TLS 활성)' } else { $cfg = "취약|SSL/TLS 미설정 (listen ... ssl 없음)$($script:Lbn)" }; return (Resp-Adjust $cfg (Resp-Ssl 'nginx')) }
function E-ssl-nginx { Sec 'Nginx listen/ssl' (Cqf $script:NgL '^(listen|ssl_protocols|ssl_certificate\s)'); Hp-Ev 'nginx' }
function V-redirect-nginx {
    if (Cq $script:NgL '^(return\s+30[1278]\s+https://|rewrite\s.*https://)') { $cfg = '양호|HTTPS 리디렉션(return 301 https://) 설정' } else { $cfg = "취약|HTTP→HTTPS 리디렉션 미설정$($script:Lbn)" }
    $rsp = Resp-Redir 'nginx'
    if ($rsp -and ($rsp -split '\|')[0] -eq '취약' -and ($cfg -split '\|')[0] -eq '양호') { return ("수동확인|설정에는 HTTPS 리디렉션이 있으나 기본 호스트 실제 응답은 리디렉션 아님 - server 블록별 응답 확인 필요 (" + ($rsp -split '\|', 2)[1] + ")") }
    return (Resp-Adjust $cfg $rsp)
}
function E-redirect-nginx { Sec 'Nginx 리디렉션' (Cqf $script:NgL '^(return|rewrite)\s'); Hp-Ev 'nginx' }
function E-ldap-nginx { Sec 'Nginx ldap' (Cqf $script:NgL 'ldap') }
function V-ldap-nginx { if (Cq $script:NgL 'ldap') { return '수동확인|LDAP 관련 설정 존재 - 알고리즘/ldaps 사용 확인' }; return '양호|LDAP 연동 설정 없음' }

# ═══ Tomcat (Windows, 인스턴스별) ═══════════════════════════════
function V-listing-tomcat {
    $u = Tc-Need @('web.xml'); if ($u) { return $u }
    $hit = @(); foreach ($f in @(Tc-WebXmls)) { $t = Read-FileText $f; if ($null -ne $t -and (Strip-XmlComments $t) -match '(?s)<param-name>\s*listings\s*</param-name>\s*<param-value>\s*true') { $hit += $f } }
    if ($hit.Count) { $x = "취약|DefaultServlet listings=true: $($hit -join ', ')" } else { $x = "양호|listings=false(기본) - conf\web.xml·앱 web.xml $(@(Tc-WebXmls).Count)개 확인" }
    $rs = Resp-Listing 'tomcat'; if ($rs) { $x = WorseR $x $rs }; return $x
}
function E-listing-tomcat { foreach ($f in @(Tc-WebXmls)) { $t = Read-FileText $f; Sec "listings: $f" ([regex]::Matches((Strip-XmlComments $t), '(?s)<param-name>\s*listings\s*</param-name>\s*<param-value>[^<]*') | ForEach-Object { $_.Value -replace '\s+', ' ' }) } }
function V-servinfo-tomcat {
    $u = Tc-Need @('server.xml'); if ($u) { return $u }
    $t = Tc-Text 'server.xml'; $sv = $t -match '<Connector[^>]*\sserver="[^"]*"'; $si = $t -match 'showServerInfo="false"'
    if ($sv -and $si) { $cfg = '양호|Connector server 속성 변경 + ErrorReportValve showServerInfo=false' } elseif ($sv) { $cfg = '양호|Connector server 속성 변경 (showServerInfo=false 권고)' } else { $cfg = '취약|Connector server 속성 미설정 - 가이드: server 값을 임의 정보로 변경 + showServerInfo=false' }
    return (Resp-Adjust $cfg (Resp-Server 'tomcat'))
}
function E-servinfo-tomcat { $t = Tc-Text 'server.xml'; Sec "server.xml server=/showServerInfo ($($script:CurTomcat))" ([regex]::Matches("$t", '(server|showServerInfo|showReport)="[^"]*"') | ForEach-Object { $_.Value }); Hp-Ev 'tomcat' }
function V-ssi-tomcat { $u = Tc-Need @('web.xml'); if ($u) { return $u }; $h = @(Tc-WebXmlHit 'SSIServlet|SSIFilter'); if ($h.Count) { return "취약|SSI 활성: $($h -join ', ')" }; return '양호|SSIServlet/SSIFilter 미사용' }
function E-ssi-tomcat { foreach ($f in @(Tc-WebXmls)) { $t = Read-FileText $f; Sec "SSI: $f" ([regex]::Matches((Strip-XmlComments $t), 'SSIServlet|SSIFilter') | ForEach-Object { $_.Value }) } }
function V-errpage-tomcat {
    $u = Tc-Need @('web.xml', 'server.xml'); if ($u) { return $u }
    $hit = @(); foreach ($f in @(Tc-WebXmls)) { if ($f -match '\\webapps\\(manager|host-manager|docs|examples)\\') { continue }; $t = Read-FileText $f; if ($null -ne $t -and (Strip-XmlComments $t) -match '<error-page>') { $hit += $f } }
    $valve = (Tc-Text 'server.xml') -match 'ErrorReportValve[^>]*showReport="false"[^>]*showServerInfo="false"|ErrorReportValve[^>]*showServerInfo="false"[^>]*showReport="false"'
    if ($hit.Count) { $cfg = "양호|<error-page> 지정: $(Brief $hit 3)" } elseif ($valve) { $cfg = '양호|ErrorReportValve showReport=false·showServerInfo=false' } else { $cfg = '취약|<error-page> 미지정 (기본 에러 페이지·버전 노출; 번들 앱 manager/docs/examples 제외)' }
    return (Resp-Adjust $cfg (Resp-Err 'tomcat'))
}
function E-errpage-tomcat { foreach ($f in @(Tc-WebXmls)) { $t = Read-FileText $f; Sec "error-page: $f" ([regex]::Matches((Strip-XmlComments $t), '<error-page>') | ForEach-Object { $_.Value }) }; Hp-Ev 'tomcat' }
function V-upload-tomcat {
    $u = Tc-Need @('server.xml', 'web.xml'); if ($u) { return $u }
    $mp = @([regex]::Matches((Tc-Text 'server.xml'), 'maxPostSize="([^"]*)"') | ForEach-Object { $_.Groups[1].Value })
    $mf = $false; foreach ($f in @(Tc-WebXmls)) { $t = Read-FileText $f; if ($null -ne $t -and (Strip-XmlComments $t) -match '<max-(file|request)-size>') { $mf = $true } }
    if (@($mp | Where-Object { $_ -match '^-' }).Count) { return "취약|maxPostSize 음수(제한 해제): $($mp -join ' ')" }
    if ($mp.Count -or $mf) { return "양호|용량 제한 설정 (maxPostSize=$(if ($mp.Count) { $mp -join ' ' } else { '기본 2MB' })$(if ($mf) { ', multipart-config' }))" }
    return '수동확인|maxPostSize·multipart-config 미설정 (폼 POST 기본 2MB만 적용) - 애플리케이션 업로드 용량 제한 확인'
}
function E-upload-tomcat { $t = Tc-Text 'server.xml'; Sec "maxPostSize ($($script:CurTomcat))" ([regex]::Matches("$t", 'maxPostSize="[^"]*"') | ForEach-Object { $_.Value }); foreach ($f in @(Tc-WebXmls)) { $x = Read-FileText $f; Sec "multipart: $f" ([regex]::Matches((Strip-XmlComments $x), '<max-(file|request)-size>[^<]*') | ForEach-Object { $_.Value }) } }
function V-proxy-tomcat { $u = Tc-Need @('server.xml'); if ($u) { return $u }; if ((Tc-Text 'server.xml') -match 'proxyName=|proxyPort=') { return '수동확인|Connector proxyName/proxyPort 설정 - 업무상 필요 여부 확인' }; return '양호|Connector 프록시 설정 없음' }
function E-proxy-tomcat { $t = Tc-Text 'server.xml'; Sec 'Connector proxyName/proxyPort' ([regex]::Matches("$t", 'proxy(Name|Port)="[^"]*"') | ForEach-Object { $_.Value }) }
function V-cgi-tomcat { $u = Tc-Need @('web.xml'); if ($u) { return $u }; $h = @(Tc-WebXmlHit 'CGIServlet'); if ($h.Count) { return "취약|CGIServlet 매핑 활성: $($h -join ', ')" }; return '양호|CGI 매핑 비활성(기본)' }
function E-cgi-tomcat { E-ssi-tomcat }
function V-updir-tomcat { $u = Tc-Need @('server.xml', 'context.xml'); if ($u) { return $u }; if (((Tc-Text 'server.xml') + (Tc-Text 'context.xml')) -match 'allowLinking="true"') { return '취약|Context allowLinking=true' }; return '양호|allowLinking 미설정(false)' }
function E-updir-tomcat { Sec 'allowLinking' ([regex]::Matches((Tc-Text 'server.xml') + (Tc-Text 'context.xml'), 'allowLinking="[^"]*"') | ForEach-Object { $_.Value }) }
function V-links-tomcat { return (V-updir-tomcat) }
function E-links-tomcat { E-updir-tomcat }
function V-scriptmap-tomcat {
    $u = Tc-Need @('web.xml'); if ($u) { return $u }
    $sm = @([regex]::Matches((Tc-Text 'web.xml'), '(?s)<servlet-mapping>\s*<servlet-name>([^<]+)</servlet-name>') | ForEach-Object { $_.Groups[1].Value.Trim() } | Select-Object -Unique | Where-Object { $_ -ne 'default' -and $_ -ne 'jsp' })
    if ($sm.Count) { return "취약|conf\web.xml 기본 외 스크립트 매핑 활성: $($sm -join ' ')(cgi/ssi/invoker 등 불필요 시 제거)" }; return '양호|conf\web.xml 매핑 기본값(default, jsp)만 사용'
}
function E-scriptmap-tomcat { Sec 'servlet-mapping' ([regex]::Matches((Tc-Text 'web.xml'), '<servlet-name>[^<]*|<url-pattern>[^<]*') | ForEach-Object { $_.Value }) }
function V-unneeded-tomcat {
    $w = "$($script:CurTomcat)\webapps"; if (-not (Test-Path $w)) { return "점검불가|Tomcat webapps 디렉터리 없음/접근 불가: $w" }
    $df = @('docs', 'examples') | Where-Object { Test-Path "$w\$_" }
    if ($df) { return "취약|기본 매뉴얼·샘플 존재: $(($df | ForEach-Object { "$w\$_" }) -join ' ')" }; return "양호|기본 docs/examples 없음 (webapps: $((Get-ChildItem $w -EA SilentlyContinue | ForEach-Object { $_.Name }) -join ' '))"
}
function E-unneeded-tomcat { Sec "webapps 목록 ($($script:CurTomcat))" (Get-ChildItem "$($script:CurTomcat)\webapps" -EA SilentlyContinue | ForEach-Object { $_.Name }) }
function Tc-AclEveryone([string]$f) {   # Everyone/Users/Authenticated Users 읽기 이상 권한
    $a = Get-Acl $f -EA SilentlyContinue; if (-not $a) { return $null }
    return (@($a.Access | Where-Object { @('S-1-1-0', 'S-1-5-32-545', 'S-1-5-11') -contains (Get-AceSid $_) -and "$($_.AccessControlType)" -eq 'Allow' } | ForEach-Object { "$($_.IdentityReference):$($_.FileSystemRights)" }) -join ',')
}
function V-pwfile-tomcat {
    $f = Tc-File 'tomcat-users.xml'; if (-not (Test-Path $f)) { return '양호|비밀번호 파일(tomcat-users.xml) 없음' }
    $e = Tc-AclEveryone $f; if ($null -eq $e) { return "점검불가|ACL 조회 실패: $f (실행 계정 $env:USERNAME)" }
    if ($e) { return "취약|비밀번호 파일에 Everyone/Users 권한: $f ($e)" }; return "양호|비밀번호 파일에 Everyone/Users 권한 없음: $f"
}
function E-pwfile-tomcat { $f = Tc-File 'tomcat-users.xml'; if (Test-Path $f) { $a = Get-Acl $f -EA SilentlyContinue; "== $f"; if ($a) { $a.Access | ForEach-Object { "  $($_.IdentityReference) $($_.AccessControlType) $($_.FileSystemRights)" } } else { '  (ACL 조회 불가)' } } else { "tomcat-users.xml 없음: $f" } }
function Tc-Users { $f = Tc-File 'tomcat-users.xml'; if (-not (Test-Path $f)) { return $null }; $t = Read-FileText $f; if ($null -eq $t) { return $null }; return @([regex]::Matches((Strip-XmlComments $t), '<user\s[^>]*>') | ForEach-Object { $_.Value }) }
function V-admin-tomcat {
    $f = Tc-File 'tomcat-users.xml'; if (-not (Test-Path $f)) { return '양호|tomcat-users.xml 없음 (관리자 페이지 미사용)' }
    $us = Tc-Users; if ($null -eq $us) { return "점검불가|tomcat-users.xml 읽기 실패: $f (실행 계정 $env:USERNAME)" }; $us = @($us)
    $adm = @($us | Where-Object { $_ -match 'roles="[^"]*(manager-|admin-|admin"|manager")' })
    $bad = @($adm | ForEach-Object { if ($_ -match 'username="(admin|tomcat|manager|administrator|root|role1|both|test|user)"') { $matches[1] } })
    if (-not $adm.Count) { return '양호|관리자 페이지 미사용 (manager/admin 역할 계정 없음)' }
    if ($bad.Count) { return "취약|관리자 계정명이 기본/유추 가능: $($bad -join ' ')" }
    return "양호|관리자 계정명 기본값 아님: $(($adm | ForEach-Object { if ($_ -match 'username="([^"]*)"') { $matches[1] } }) -join ' ')"
}
function E-admin-tomcat { $f = Tc-File 'tomcat-users.xml'; if (Test-Path $f) { $us = Tc-Users; Sec "tomcat-users.xml <user> (비밀번호 마스킹: $f)" ($us | ForEach-Object { $_ -replace 'password="[^"]*"', 'password="****"' }) } else { "tomcat-users.xml 없음: $f" } }
function Pw-Strong([string]$pw, [string]$id) {
    if (-not $pw) { return $false }; $n = 0
    if ($pw -cmatch '[A-Z]') { $n++ }; if ($pw -cmatch '[a-z]') { $n++ }; if ($pw -match '\d') { $n++ }; if ($pw -match '[^A-Za-z0-9]') { $n++ }
    if ($pw -match '^(?i)(tomcat|admin|s3cret|password|manager|root|jeus|changeit|<must-be-changed>)') { return $false }
    if ($id -and $pw.ToLower().Contains($id.ToLower())) { return $false }
    if ($pw -match '(0123|1234|2345|3456|4567|5678|6789|abcd|qwer|1111|0000|aaaa)') { return $false }
    return (($n -ge 2 -and $pw.Length -ge 10) -or ($n -ge 3 -and $pw.Length -ge 8))
}
function V-weakpw-tomcat {
    $f = Tc-File 'tomcat-users.xml'; if (-not (Test-Path $f)) { return '양호|tomcat-users.xml 없음 (관리자 계정 없음)' }
    $us = Tc-Users; if ($null -eq $us) { return "점검불가|tomcat-users.xml 읽기 실패: $f (실행 계정 $env:USERNAME)" }; $us = @($us)
    $adm = @($us | Where-Object { $_ -match 'roles="[^"]*(manager-|admin-|admin"|manager")' }); $weak = @()
    $hash = (Tc-Text 'server.xml') -match 'CredentialHandler|digest="'
    foreach ($u in $adm) { $id = ''; $pw = ''; if ($u -match 'username="([^"]*)"') { $id = $matches[1] }; if ($u -match 'password="([^"]*)"') { $pw = $matches[1] }
        if ($hash -and $pw -match '^[0-9a-fA-F$:]{32,}$') { continue }; if (-not (Pw-Strong $pw $id)) { $weak += $id } }
    if (-not $adm.Count) { return '양호|관리자 계정 없음 (관리자 페이지 미사용)' }
    if ($weak.Count) { return "취약|관리자 비밀번호 평문 저장 + 복잡도 미충족(2종 10자/3종 8자, 기본값·계정명·연속 문자 금지): $($weak -join ' ')" }
    if ($hash) { return '양호|관리자 비밀번호 암호화 저장 (CredentialHandler/digest)' }
    return '양호|관리자 비밀번호 유추 어려운 값 (평문 저장 - 암호화(CredentialHandler SHA-256 이상) 권고)'
}
function E-weakpw-tomcat { E-admin-tomcat }
function V-wst044-tomcat {
    $f = Tc-File 'tomcat-users.xml'; if (-not (Test-Path $f)) { return '양호|tomcat-users.xml 없음 (활성 관리 계정 없음)' }
    $us = Tc-Users; if ($null -eq $us) { return "점검불가|tomcat-users.xml 읽기 실패: $f (실행 계정 $env:USERNAME)" }; $us = @($us)
    $def = @($us | Where-Object { $_ -match 'password="(tomcat|admin|s3cret|password|role1|both|manager|1234|123456|<must-be-changed>)"' -or $_ -match 'username="(tomcat|admin|both|role1)"' })
    if ($def.Count) { return "취약|기본/유추 가능 계정: $(($def | ForEach-Object { if ($_ -match 'username="([^"]*)"') { $matches[1] } }) -join ' ')" }
    if ($us.Count) { return "양호|관리 계정 디폴트 값 아님 ($($us.Count)개)" }; return '양호|활성 관리 계정 없음'
}
function E-wst044-tomcat { E-admin-tomcat }
function V-ldap-tomcat {
    $u = Tc-Need @('server.xml'); if ($u) { return $u }; $t = Tc-Text 'server.xml'
    if ($t -notmatch 'JNDIRealm') { return '양호|LDAP 연결 인증(JNDIRealm) 미사용 - 취약한 다이제스트 알고리즘 사용 대상 없음' }
    $dg = @([regex]::Matches($t, '(digest|algorithm)="([^"]*)"') | ForEach-Object { $_.Groups[2].Value })
    if (@($dg | Where-Object { $_ -match '^SHA-?(256|384|512)' }).Count) { return "양호|JNDIRealm 비밀번호 다이제스트 $($dg -join ' ')" }; return "취약|JNDIRealm 다이제스트 $(if ($dg.Count) { $dg -join ' ' } else { '미설정' }) - SHA-256 이상 필요 (MD5/SHA-1/SSHA 취약)"
}
function E-ldap-tomcat { $t = Tc-Text 'server.xml'; Sec 'JNDIRealm/digest' ([regex]::Matches("$t", 'JNDIRealm|(digest|algorithm)="[^"]*"') | ForEach-Object { $_.Value }) }
function V-webproc-tomcat {
    $sv = $null; foreach ($s in $script:Svcs) { if ("$($s.Name)" -match '^Tomcat' -or "$($s.PathName)" -match [regex]::Escape($script:CurTomcat) -or "$($s.PathName)" -match [regex]::Escape((Tc-Home $script:CurTomcat))) { $sv = $s; break } }
    if (-not $sv) { return '점검불가|Tomcat 윈도우 서비스를 찾지 못해 구동 계정을 확인할 수 없음 (수동 실행 인스턴스일 수 있음)' }
    $acc = "$($sv.StartName)"; if (-not $acc) { return "점검불가|서비스 $($sv.Name) 의 로그온 계정을 조회하지 못함" }
    if ($acc -match 'LocalSystem|NT AUTHORITY\\SYSTEM') { return "취약|서비스 $($sv.Name) 계정: $acc (전체 권한 - 전용 계정 권고)" }
    $adm = Get-LocalGroupMemberNames 'S-1-5-32-544'
    if ($adm -ne $null -and @($adm | Where-Object { $_ -ieq $acc -or $_ -like "*\$($acc.Split('\')[-1])" }).Count) { return "취약|서비스 $($sv.Name) 계정이 로컬 Administrators 소속: $acc" }
    if ($adm -eq $null) { return "점검불가|서비스 계정 $acc 의 Administrators 소속 여부를 조회하지 못함" }
    return "양호|서비스 $($sv.Name) 계정: $acc (Administrators 미소속)"
}
function E-webproc-tomcat { Sec 'Tomcat 서비스 계정' ($script:Svcs | Where-Object { "$($_.Name)" -match '^Tomcat' } | ForEach-Object { "$($_.Name) StartName=$($_.StartName) State=$($_.State)" }) }
function V-dbconf-tomcat {
    $b = $script:CurTomcat; $files = @()
    foreach ($pat in @("$b\conf\server.xml", "$b\conf\context.xml", "$b\conf\Catalina\*\*.xml", "$b\webapps\*\META-INF\context.xml", "$b\webapps\*\WEB-INF\classes\*.properties", "$b\webapps\*\WEB-INF\classes\*.xml", "$b\webapps\*\WEB-INF\classes\*.yml", "$b\webapps\*\WEB-INF\classes\*\*.properties", "$b\webapps\*\BOOT-INF\classes\application*.*", "$b\webapps\*\WEB-INF\classes\application*.*")) {
        foreach ($f in @(Get-ChildItem -Path $pat -EA SilentlyContinue | Where-Object { -not $_.PSIsContainer })) { if ($files -notcontains $f.FullName) { $files += $f.FullName } }
    }
    $hits = @(); $unr = @()
    foreach ($f in $files) { $t = Read-FileText $f; if ($null -eq $t) { $unr += $f; continue }; if ($t -match 'javax\.sql\.DataSource|jdbc:|spring\.datasource') { $hits += $f } }
    if ($unr.Count) { return "점검불가|DB 설정 후보 파일 읽기 실패: $(Brief $unr 3) (실행 계정 $env:USERNAME)" }
    if (-not $hits.Count) { if (-not (Test-Path "$b\webapps")) { return "점검불가|Tomcat webapps 를 찾지 못해 애플리케이션 DB 설정 파일을 확인할 수 없음" }; return '양호|DB 연결 정보가 담긴 설정 파일 없음 (검색: conf, webapps\*\WEB-INF·BOOT-INF\classes, META-INF\context.xml)' }
    $bad = @(); $noacl = @()
    foreach ($f in $hits) { $e = Tc-AclEveryone $f; if ($null -eq $e) { $noacl += $f } elseif ($e) { $bad += "$f($e)" } }
    if ($bad.Count) { return "취약|DB 연결 정보 포함 설정 파일에 Everyone/Users 권한: $(Brief $bad 3)" }
    if ($noacl.Count) { return "점검불가|ACL 조회 실패: $(Brief $noacl 3)" }
    return "양호|DB 연결 설정 파일에 Everyone/Users 권한 없음: $(Brief $hits 4)"
}
function E-dbconf-tomcat { $b = $script:CurTomcat; foreach ($pat in @("$b\conf\*.xml", "$b\webapps\*\WEB-INF\classes\*.properties", "$b\webapps\*\WEB-INF\classes\application*.*", "$b\webapps\*\META-INF\context.xml")) { foreach ($f in @(Get-ChildItem -Path $pat -EA SilentlyContinue | Where-Object { -not $_.PSIsContainer })) { $t = Read-FileText $f.FullName; if ($t -match 'jdbc:|DataSource|spring\.datasource') { "== $($f.FullName)"; ($t -split "`r?`n" | Where-Object { $_ -match 'jdbc:|DataSource|username|spring\.datasource|url' }) -replace '(?i)(password|credential|passwd)(\s*[=:]\s*)("[^"]*"|\S+)', '$1$2****' } } } }
function Tc-Ver([string]$base) {
    $h = Tc-Home $base
    foreach ($rn in @("$h\RELEASE-NOTES", "$base\RELEASE-NOTES")) { if (Test-Path $rn) { $l = Select-String -Path $rn -Pattern 'Apache Tomcat Version' -EA SilentlyContinue | Select-Object -First 1; if ($l -and $l.Line -match '(\d+\.\d+\.\d+)') { return $matches[1] } } }
    $j = "$h\lib\catalina.jar"; if (Test-Path $j) { try { Add-Type -AssemblyName System.IO.Compression.FileSystem -EA Stop; $z = [IO.Compression.ZipFile]::OpenRead($j); $en = $z.GetEntry('org/apache/catalina/util/ServerInfo.properties'); if ($en) { $sr = New-Object IO.StreamReader($en.Open()); $tx = $sr.ReadToEnd(); $sr.Close(); if ($tx -match 'server\.number=(\d+\.\d+\.\d+)') { $z.Dispose(); return $matches[1] } }; $z.Dispose() } catch {} }
    return ''
}
function Run-Eos([string]$prod, [string]$ver) {
    if (-not $ver) { return "점검불가|$prod 버전을 확인하지 못함 (RELEASE-NOTES/catalina.jar 조회 실패)" }
    $eos = Join-Path $script:ScriptDir 'eos_checker.py'; if (-not (Test-Path $eos)) { $eos = Join-Path $script:ScriptDir '..\converter\eos_checker.py' }
    if (-not (Test-Path $eos)) { return "점검불가|$prod ${ver}: eos_checker.py 없음 - EoS 판정 불가" }
    $py = Get-Command python3, python, py -EA SilentlyContinue | Select-Object -First 1
    if (-not $py) { return "점검불가|$prod ${ver}: python 미설치 - EoS 판정 불가" }
    $r = & $py.Path $eos $prod $ver 2>$null
    $st = (@($r | Where-Object { $_ -match '^결과:' }) | Select-Object -First 1) -replace '^결과:\s*', ''
    $ds = (@($r | Where-Object { $_ -match '^설명:' }) | Select-Object -First 1) -replace '^설명:\s*', ''
    if (-not $st) { return "점검불가|$prod ${ver}: EoS 판정 실패 ($ds)" }
    return "$($st.Trim())|$prod ${ver}: $($ds.Trim())"
}
function V-eos-tomcat { return (Run-Eos 'tomcat' (Tc-Ver $script:CurTomcat)) }
function E-eos-tomcat { "Tomcat 버전: $(Tc-Ver $script:CurTomcat) ($($script:CurTomcat))" }
function V-eos-apache { return '수동확인|Apache for Windows 버전 EoS 는 벤더 공지 대조 필요 (자동 판정 미지원)' }
function V-eos-nginx { return '수동확인|Nginx for Windows 버전 EoS 는 벤더 공지 대조 필요 (자동 판정 미지원)' }
function V-eos-jeus { return '수동확인|JEUS 버전 EoS 는 TmaxSoft 지원 정책 대조 필요' }
function E-eos-all { foreach ($h in $TOMCAT_HOMES) { $script:CurTomcat = $h; E-eos-tomcat }; Sec 'IIS' @("IIS $IIS_VERSION") }

# ═══ 프로세스 권한(Apache/Nginx), 문서 루트, WST 전용 ═══════════════════
function Proc-Owners([string]$exeRe) {
    $o = @(); $any = $false
    foreach ($pr in @(Get-WmiObject Win32_Process -EA SilentlyContinue | Where-Object { $_.Name -match $exeRe })) { $any = $true; try { $r = $pr.GetOwner(); if ($r.User) { $o += "$($r.Domain)\$($r.User)" } } catch {} }
    if (-not $any) { return $null }; return @($o | Select-Object -Unique)
}
function Webproc-Generic([string]$label, [string]$exeRe, [string]$svcRe) {
    $own = Proc-Owners $exeRe
    if ($null -eq $own) {
        $sv = $script:Svcs | Where-Object { $_.Name -match $svcRe -or $_.PathName -match $svcRe } | Select-Object -First 1
        if (-not $sv) { return "점검불가|$label 프로세스가 실행 중이 아니고 서비스도 찾지 못해 구동 계정을 확인할 수 없음" }
        $own = @("$($sv.StartName) (서비스 $($sv.Name), 상태 $($sv.State))")
    }
    $own = @($own)
    if (-not $own.Count) { return "점검불가|$label 프로세스 소유자를 조회하지 못함 (실행 계정 $env:USERNAME)" }
    if (@($own | Where-Object { $_ -match 'SYSTEM$|LocalSystem|\\Administrator$' }).Count) { return "취약|$label 가 SYSTEM/Administrator 권한으로 구동: $($own -join ', ')" }
    $adm = Get-LocalGroupMemberNames 'S-1-5-32-544'
    if ($adm -ne $null) { foreach ($a in $own) { $n = ($a -split '\s')[0].Split('\')[-1]; if (@($adm | Where-Object { $_ -like "*\$n" }).Count) { return "취약|$label 구동 계정이 로컬 Administrators 소속: $a" } } }
    else { return "점검불가|$label 구동 계정($($own -join ', '))의 Administrators 소속 여부를 조회하지 못함" }
    return "양호|$label 구동 계정: $($own -join ', ') (Administrators 미소속)"
}
function V-webproc-apache { return (Webproc-Generic 'Apache' '^(httpd|apache)(\.exe)?$' '^Apache|httpd') }
function V-webproc-nginx { return (Webproc-Generic 'Nginx' '^nginx(\.exe)?$' 'nginx') }
function E-webproc-apache { Sec 'httpd 프로세스 소유자' (Proc-Owners '^(httpd|apache)(\.exe)?$'); Sec 'Apache 서비스' ($script:Svcs | Where-Object { $_.Name -match '^Apache' -or $_.PathName -match 'httpd' } | ForEach-Object { "$($_.Name) StartName=$($_.StartName) State=$($_.State)" }) }
function E-webproc-nginx { Sec 'nginx 프로세스 소유자' (Proc-Owners '^nginx(\.exe)?$') }
function Docroot-Check([string[]]$roots, [string]$src) {
    $roots = @($roots | Where-Object { $_ } | Select-Object -Unique)
    if (-not $roots.Count) { return "점검불가|$src 에서 웹 서비스 경로(DocumentRoot/root/docBase)를 찾지 못함" }
    $bad = @($roots | Where-Object { $_.TrimEnd('\','/') -match '^[A-Za-z]:$' -or $_ -match '^[A-Za-z]:[\\/](Windows|Program Files|Users)([\\/]|$)' })
    if ($bad.Count) { return "취약|웹 서비스 경로가 시스템 영역과 분리되지 않음: $($bad -join ', ')" }
    return "양호|별도 웹 서비스 경로 사용: $(Brief $roots 5)"
}
function V-docroot-apache { return (Docroot-Check @(Cq $script:ApL '^DocumentRoot\s' | ForEach-Object { ($_.Text -replace '^DocumentRoot\s+', '').Trim('"') }) 'Apache 설정') }
function E-docroot-apache { Sec 'Apache DocumentRoot' (Cqf $script:ApL '^DocumentRoot\s') }
function V-docroot-nginx { return (Docroot-Check @(Cq $script:NgL '^root\s' | ForEach-Object { ($_.Text -replace '^root\s+', '').Trim(';', '"') }) 'Nginx 설정') }
function E-docroot-nginx { Sec 'Nginx root' (Cqf $script:NgL '^root\s') }
function V-docroot-tomcat { $t = Tc-Text 'server.xml'; if ($null -eq $t) { return "점검불가|server.xml 읽기 실패 ($($script:CurTomcat))" }; return (Docroot-Check @([regex]::Matches($t, '(docBase|appBase)="([^"]*)"') | ForEach-Object { $v = $_.Groups[2].Value; if ($v -and $v -notmatch '^[A-Za-z]:' -and $v -notmatch '^\\') { Join-Path $script:CurTomcat $v } else { $v } }) 'Tomcat server.xml') }
function E-docroot-tomcat { $t = Tc-Text 'server.xml'; Sec 'Tomcat appBase/docBase' ([regex]::Matches("$t", '(docBase|appBase)="[^"]*"') | ForEach-Object { $_.Value }) }
function V-wst034-iis {
    $u = Iis-Un2; if ($u) { return $u }
    $f = @(); $s = V-unneeded-iis; if ($s -like '취약*') { $f += ($s -split '\|', 2)[1] }
    foreach ($sc in $script:Scopes) { if ($sc.Root -and (Test-Path $sc.Root)) { $f += @(Find-Depth $sc.Root { param($i) (-not $i.PSIsContainer) -and $i.Name -match '\.(bak|old|tmp|orig)$|~$' } 3 5 | ForEach-Object { "임시/백업: $_" }) } }
    if ($script:IISX -and $script:IISX.OuterXml -match 'IISSamples|IISHelp') { $f += 'IISSamples/IISHelp 가상 디렉터리' }
    if ($f.Count) { return "취약|불필요 파일/샘플 존재: $(Brief $f 4)" }; return '양호|샘플 디렉터리·임시/백업 파일 미발견'
}
function E-wst034-iis { E-unneeded-iis; foreach ($sc in $script:Scopes) { if ($sc.Root -and (Test-Path $sc.Root)) { Sec "임시/백업 파일 (깊이 3): $($sc.Root)" (Find-Depth $sc.Root { param($i) (-not $i.PSIsContainer) -and $i.Name -match '\.(bak|old|tmp|orig)$|~$' } 3 200) } } }
function V-wst034-tomcat { if (Test-Path "$($script:CurTomcat)\webapps\examples") { return "취약|Tomcat webapps\examples 샘플 존재" }; return '양호|Tomcat 샘플(examples) 없음' }
function E-wst034-tomcat { E-unneeded-tomcat }
function V-wst041-iis {
    $u = Iis-Un2; if ($u) { return $u }
    $bad = @(); $unr = @()
    foreach ($sc in $script:Scopes) { if ($sc.Root -and (Test-Path $sc.Root)) { $a = Get-Acl $sc.Root -EA SilentlyContinue; if (-not $a) { $unr += $sc.Root; continue }; $a.Access | Where-Object { (Get-AceSid $_) -eq 'S-1-1-0' -and "$($_.AccessControlType)" -eq 'Allow' -and "$($_.FileSystemRights)" -match 'Write|Modify|FullControl' } | ForEach-Object { $bad += "$($sc.Root)(Everyone:$($_.FileSystemRights))" } } }
    if ($bad.Count) { return "취약|웹 디렉터리 Everyone 과도 권한: $(Brief $bad 4)" }; if ($unr.Count) { return "점검불가|ACL 조회 실패: $(Brief $unr 3)" }
    return '양호|웹 디렉터리 Everyone 쓰기/수정 권한 없음'
}
function E-wst041-iis { E-confperm-iis }
function V-wst043-iis { $ssi = Get-Reg 'HKLM:\SYSTEM\CurrentControlSet\Services\W3SVC\Parameters' 'SSIEnableCmdDirective'; $mj = if ($IIS_VERSION -match '^(\d+)') { [int]$matches[1] } else { 0 }
    if ($mj -ge 7 -or "$ssi" -eq '0') { return "양호|서버 명령 실행 제한 (IIS $IIS_VERSION / SSIEnableCmdDirective=$ssi)" }; if ($mj -eq 0) { return "점검불가|IIS 버전을 확인하지 못함" }; return "취약|IIS $IIS_VERSION 이면서 SSIEnableCmdDirective≠0 (서버 명령 실행 허용)" }
function E-wst043-iis { Sec 'IIS 버전 / SSIEnableCmdDirective' @("$IIS_VERSION / $(Get-Reg 'HKLM:\SYSTEM\CurrentControlSet\Services\W3SVC\Parameters' 'SSIEnableCmdDirective')") }
function V-wst032-iis {
    $u = Iis-Un; if ($u) { return $u }
    $cgi = @($script:IISX.configuration.'system.webServer'.globalModules.add | Where-Object { $_ -and $_.name -match '^Cgi' }).Count
    $dirs = @("$env:SystemDrive\inetpub\scripts") + @($script:Scopes | ForEach-Object { Join-Path $_.Root 'cgi-bin' }); $ev = @(); $unr = @()
    foreach ($d in ($dirs | Select-Object -Unique)) { if (Test-Path $d) { $a = Get-Acl $d -EA SilentlyContinue; if (-not $a) { $unr += $d; continue }; if (@($a.Access | Where-Object { (Get-AceSid $_) -eq 'S-1-1-0' -and "$($_.FileSystemRights)" -match 'Write|Modify|FullControl' }).Count) { $ev += $d } } }
    if ($ev.Count) { return "취약|CGI 스크립트 디렉터리에 Everyone 쓰기 권한: $($ev -join ', ')" }
    if ($unr.Count) { return "점검불가|CGI 디렉터리 ACL 조회 실패: $($unr -join ', ')" }
    if ($cgi) { return '수동확인|IIS CGI 모듈 설치됨 - CGI 스크립트 목록·취약 스크립트 존재 여부 확인' }
    return '양호|IIS CGI 모듈 미설치 / 스크립트 디렉터리 Everyone 쓰기 권한 없음'
}
function E-wst032-iis { if ($script:IISX) { Sec 'IIS CGI 모듈' @($script:IISX.configuration.'system.webServer'.globalModules.add | Where-Object { $_ -and $_.name -match '^Cgi' } | ForEach-Object { $_.name }) }; $d = "$env:SystemDrive\inetpub\scripts"; if (Test-Path $d) { (Get-Acl $d).Access | ForEach-Object { "  $($_.IdentityReference) $($_.FileSystemRights)" } } else { "없음: $d" } }
function V-wst039-all {
    $svc = @(Get-Service -EA SilentlyContinue | Where-Object { $_.Status -eq 'Running' -and ($_.Name -match '^(W3SVC|Apache|nginx|Tomcat|JEUS)' ) } | ForEach-Object { $_.Name })
    $pr = @($script:Procs | Where-Object { $_.Name -match '^(httpd|nginx|tomcat\d*w?)(\.exe)?$' } | ForEach-Object { $_.Name } | Select-Object -Unique)
    $all = @($svc + $pr | Select-Object -Unique)
    if ($all.Count) { return "수동확인|실행 중인 웹 서비스: $($all -join ', ') - 업무상 필요 여부 확인" }; return '양호|실행 중인 웹 서비스 없음'
}
function E-wst039-all { Sec '실행 중인 웹/WAS 서비스' (Get-Service -EA SilentlyContinue | Where-Object { $_.Name -match '^(W3SVC|WAS|Apache|nginx|Tomcat|JEUS)' } | ForEach-Object { "$($_.Name) $($_.Status)" }); Sec '웹 프로세스' ($script:Procs | Where-Object { $_.Name -match '^(httpd|nginx|tomcat\d*w?|w3wp)(\.exe)?$' } | ForEach-Object { "$($_.Name) PID=$($_.ProcessId) $($_.ExecutablePath)" }) }

# ═══ 항목 출력 ═════════════════════════════════════════════════
$ALLT = 'IIS Apache Nginx Tomcat JEUS'
function Kt([string]$T) { $o = @(); foreach ($p in @('iis', 'apache', 'nginx', 'tomcat', 'jeus')) { if (Pt $p $T) { $o += $script:PName[$p] } }; return ($o -join ' ') }
function Item([string]$code, [string]$chk, [string]$T, [bool]$wst) {   # 증적 함수 E-<chk>-<제품> 을 제품별로 호출해 한 블록으로 기록
    if (-not ($WEB_LIST.Count + $WAS_LIST.Count)) { EvdQ $code "탐지된 웹서버/WAS" "웹서버: 없음 / WAS: 없음 / 탐지 근거: $($script:DetectNote -join '; ')"; NA $code '웹서버/WAS 미탐지'; return }
    if (-not (Kt $T)) { EvdQ $code "탐지된 웹서버/WAS" "웹서버: $($WEB_LIST -join ' ') / WAS: $($WAS_LIST -join ' ') (이 항목의 점검 대상: $T)"; NA $code "점검 대상($T) 제품 미탐지 (탐지: $($WEB_LIST -join ' ') $($WAS_LIST -join ' '))"; return }
    $ev = New-Object System.Collections.ArrayList
    $evFn = {
        param($c, $tt)
        foreach ($p in @('iis', 'apache', 'nginx', 'tomcat', 'jeus')) {
            if (-not (Pt $p $tt)) { continue }
            $fn = "E-$c-$p"
            if (-not (Get-Command $fn -EA SilentlyContinue)) { "[$($script:PName[$p])] (이 제품은 전용 증적 함수가 없음 - 아래 설정 파일 목록 참조)"; continue }
            if ($p -eq 'apache') { foreach ($cf in $APACHE_CONFS) { $script:CurApache = $cf; $script:ApL = @(Get-ConfLines 'apache' $cf); "== [Apache] $cf"; & $fn } }
            elseif ($p -eq 'nginx') { foreach ($cf in $NGINX_CONFS) { $script:CurNginx = $cf; $script:NgL = @(Get-ConfLines 'nginx' $cf); "== [Nginx] $cf"; & $fn } }
            elseif ($p -eq 'tomcat') { foreach ($h in $TOMCAT_HOMES) { $script:CurTomcat = $h; "== [Tomcat 인스턴스] $h"; & $fn } }
            elseif ($p -eq 'jeus') { foreach ($h in $JEUS_HOMES) { $script:CurJeus = $h; "== [JEUS] $h"; & $fn } }
            else { "== [IIS]"; & $fn }
        }
        "-- 탐지: 웹서버 $($WEB_LIST -join ' ') / WAS $($WAS_LIST -join ' ') / Apache 설정 $($APACHE_CONFS -join ',') / Nginx 설정 $($NGINX_CONFS -join ',') / Tomcat $($TOMCAT_HOMES -join ',') / JEUS $($JEUS_HOMES -join ',')"
    }
    $txt = ''
    try { $txt = (& $evFn $chk $T | Out-String -Width 4096) } catch { $txt = "증적 수집 오류: $($_.Exception.Message)" }
    EvdQ $code "설정/응답 증적 (E-$chk)" $txt
    $r = Combine $chk $T
    if (-not $r) { $r = '수동확인|점검 결과 없음 - 수동 확인' }
    $p = $r -split '\|', 2; Emit $code $p[0] $p[1]
}
function ItemX([string]$code, [string]$T, [scriptblock]$ev, [scriptblock]$fn) {   # 제품 구분 없는 특수 항목
    if (-not ($WEB_LIST.Count + $WAS_LIST.Count)) { EvdQ $code "탐지된 웹서버/WAS" "웹서버: 없음 / WAS: 없음 / 탐지 근거: $($script:DetectNote -join '; ')"; NA $code '웹서버/WAS 미탐지'; return }
    if ($T -and -not (Kt $T)) { EvdQ $code "탐지된 웹서버/WAS" "웹서버: $($WEB_LIST -join ' ') / WAS: $($WAS_LIST -join ' ')"; NA $code "점검 대상($T) 제품 미탐지"; return }
    $txt = ''; try { $txt = (& $ev | Out-String -Width 4096) } catch { $txt = "증적 수집 오류: $($_.Exception.Message)" }
    EvdQ $code "설정/응답 증적" $txt
    $r = & $fn; if (-not $r) { $r = '수동확인|점검 결과 없음 - 수동 확인' }
    $p = $r -split '\|', 2; Emit $code $p[0] $p[1]
}

# ── 도우미 (WST-033 / WST-034 특수) ────────────────────────────
function Combine-Dirtrav {
    $r = ''
    if (Pt 'iis' 'IIS') { $u = Iis-Un2; if ($u) { $r = WorseR $r (Lab 'IIS' $u) } else { $r = WorseR $r (Lab 'IIS' (V-updir-iis)) } }
    if (Pt 'apache' 'Apache') { $r = WorseR $r (Combine-Only 'dirtrav' 'apache') }
    foreach ($p in @('nginx', 'tomcat', 'jeus')) { if (Has-Prod $p) { $r = WorseR $r "수동확인|[$($script:PName[$p])] 버전의 Directory Traversal 취약점 해당 여부 수동 확인" } }
    return $r
}
function Combine-Only([string]$chk, [string]$p) { return (Combine $chk $script:PName[$p]) }
function Combine-Ev-Dirtrav { Combine-Ev-Chk 'dirtrav' 'IIS Apache' }
function Combine-Ev-Chk([string]$chk, [string]$T) {
    foreach ($p in @('iis', 'apache', 'nginx', 'tomcat', 'jeus')) {
        if (-not (Pt $p $T)) { continue }; $fn = "E-$chk-$p"; if (-not (Get-Command $fn -EA SilentlyContinue)) { continue }
        if ($p -eq 'apache') { foreach ($cf in $APACHE_CONFS) { $script:CurApache = $cf; $script:ApL = @(Get-ConfLines 'apache' $cf); "== [Apache] $cf"; & $fn } }
        elseif ($p -eq 'tomcat') { foreach ($h in $TOMCAT_HOMES) { $script:CurTomcat = $h; "== [Tomcat] $h"; & $fn } }
        else { "== [$($script:PName[$p])]"; & $fn }
    }
    "-- 탐지: 웹서버 $($WEB_LIST -join ' ') / WAS $($WAS_LIST -join ' ')"
}
function E-dirtrav-iis { E-updir-iis }


# ═══ 추가 점검: 설정 파일 권한(Apache/Nginx/Tomcat), Spring Boot ═════════
function Conf-AclCheck([string[]]$files) {
    $bad = @(); $unr = @(); $n = 0
    foreach ($f in @($files | Where-Object { $_ } | Select-Object -Unique)) { if (-not (Test-Path $f)) { continue }; $n++; $e = Tc-AclEveryone $f; if ($null -eq $e) { $unr += $f } elseif ($e) { $bad += "$f($e)" } }
    if ($bad.Count) { return "취약|주요 설정 파일에 Everyone/Users/Authenticated Users 권한: $(Brief $bad 4)" }
    if ($unr.Count -and -not $n) { return "점검불가|설정 파일 ACL 조회 실패: $(Brief $unr 3) (실행 계정 $env:USERNAME)" }
    if (-not $n) { return '점검불가|주요 설정 파일을 확인하지 못함' }
    return "양호|주요 설정 파일 $n 개에 Everyone/Users 권한 없음$(if ($unr.Count) { " (ACL 조회 실패 $($unr.Count)건: $(Brief $unr 2))" })"
}
function V-confperm-apache { return (Conf-AclCheck (Conf-Files $script:ApL)) }
function E-confperm-apache { foreach ($f in (Conf-Files $script:ApL)) { "== $f"; $a = Get-Acl $f -EA SilentlyContinue; if ($a) { $a.Access | ForEach-Object { "  $($_.IdentityReference) $($_.FileSystemRights)" } } else { '  (ACL 조회 불가)' } } }
function V-confperm-nginx { return (Conf-AclCheck (Conf-Files $script:NgL)) }
function E-confperm-nginx { foreach ($f in (Conf-Files $script:NgL)) { "== $f"; $a = Get-Acl $f -EA SilentlyContinue; if ($a) { $a.Access | ForEach-Object { "  $($_.IdentityReference) $($_.FileSystemRights)" } } else { '  (ACL 조회 불가)' } } }
function V-confperm-tomcat { return (Conf-AclCheck @('server.xml', 'web.xml', 'context.xml', 'tomcat-users.xml' | ForEach-Object { Tc-File $_ })) }
function E-confperm-tomcat { foreach ($n in @('server.xml', 'web.xml', 'context.xml', 'tomcat-users.xml')) { $f = Tc-File $n; if (Test-Path $f) { "== $f"; $a = Get-Acl $f -EA SilentlyContinue; if ($a) { $a.Access | ForEach-Object { "  $($_.IdentityReference) $($_.FileSystemRights)" } } else { '  (ACL 조회 불가)' } } } }
function Spring-Cfgs {   # 실행 중 java -jar / spring.config.location 의 application*.properties|yml
    $o = @()
    foreach ($pr in $script:Procs) {
        $cl = "$($pr.CommandLine)"; if ($cl -notmatch 'java' -or $cl -notmatch '-jar\s|org\.springframework\.boot') { continue }
        $dirs = @(); if ($cl -match '-jar\s+"?([^"\s]+\.jar)"?') { $dirs += (Split-Path $matches[1]) }
        if ($cl -match 'spring\.config\.(location|additional-location)=("[^"]+"|\S+)') { foreach ($p in ($matches[2].Trim('"') -split ',')) { $dirs += ($p -replace '^file:', '') } }
        foreach ($d in $dirs) { if (-not $d) { continue }
            if (Test-Path $d -PathType Leaf) { $o += $d; continue }
            foreach ($pat in @("$d\application*.properties", "$d\application*.yml", "$d\application*.yaml", "$d\bootstrap*.properties", "$d\config\application*.*")) { foreach ($f in @(Get-ChildItem -Path $pat -EA SilentlyContinue)) { $o += $f.FullName } } }
    }
    return @($o | Select-Object -Unique)
}
function V-dbconf-spring {
    $hits = @(); $unr = @()
    foreach ($f in (Spring-Cfgs)) { $t = Read-FileText $f; if ($null -eq $t) { $unr += $f; continue }; if ($t -match 'jdbc:|spring\.datasource') { $hits += $f } }
    if (-not $hits.Count -and -not $unr.Count) { return '' }
    if ($unr.Count) { return "점검불가|[Spring Boot] 설정 파일 읽기 실패: $(Brief $unr 3)" }
    $bad = @(); foreach ($f in $hits) { $e = Tc-AclEveryone $f; if ($e) { $bad += "$f($e)" } }
    if ($bad.Count) { return "취약|[Spring Boot] DB 연결 정보 포함 설정 파일에 Everyone/Users 권한: $(Brief $bad 3)" }
    return "양호|[Spring Boot] DB 연결 설정 파일에 Everyone/Users 권한 없음: $(Brief $hits 3)"
}
function V-dbconf-jeus {
    $hits = @(); foreach ($n in @('domain.xml', 'jeus-web-dd.xml', 'JEUSMain.xml')) { foreach ($f in (Je-Find $n)) { $t = Read-FileText $f; if ($null -ne $t -and (Strip-XmlComments $t) -match '<data-?source|jdbc:') { $hits += $f } } }
    if (-not @(Je-Find 'domain.xml').Count) { return '점검불가|JEUS domain.xml 을 찾지 못함 - 도메인 경로 확인 필요' }
    if (-not $hits.Count) { return '양호|JEUS 설정 파일에 DB 연결 리소스(data-source/jdbc:) 없음' }
    $bad = @(); foreach ($f in $hits) { $e = Tc-AclEveryone $f; if ($e) { $bad += "$f($e)" } }
    if ($bad.Count) { return "취약|DB 연결 정보 포함 설정 파일에 Everyone/Users 권한: $(Brief $bad 3)" }; return "양호|DB 연결 설정 파일에 Everyone/Users 권한 없음: $(Brief $hits 3)"
}
function E-dbconf-jeus { foreach ($n in @('domain.xml', 'jeus-web-dd.xml', 'JEUSMain.xml')) { foreach ($f in (Je-Find $n)) { "== $f"; $t = Read-FileText $f; if ($null -ne $t) { ([regex]::Matches((Strip-XmlComments $t), '[^\r\n]*(jdbc:|data-?source)[^\r\n]*') | ForEach-Object { $_.Value -replace '(?i)(password|credential)(\s*[=>:]\s*)("[^"]*"|[^<\s]+)', '$1$2****' }) } } } }
function E-dbconf-spring { Sec 'Spring Boot 설정 파일 후보' (Spring-Cfgs) }
function V-admin-jeus { $af = @(Je-Find 'accounts.xml'); if (-not $af.Count) { return '점검불가|JEUS accounts.xml 을 찾지 못함 - 관리자 계정명 확인 필요' }; $t = ''; foreach ($f in $af) { $x = Read-FileText $f; if ($null -eq $x) { return "점검불가|JEUS accounts.xml 읽기 실패: $f (실행 계정 $env:USERNAME)" }; $t += $x }
    if ($t -match '(?i)<name>\s*(administrator|admin|jeus|root)\s*</name>') { return "취약|JEUS 기본 관리자 계정명 사용: $($matches[1])" }; return '양호|JEUS 관리자 계정명 기본값(administrator) 아님' }
function E-admin-jeus { foreach ($f in (Je-Find 'accounts.xml')) { "== $f"; $x = Read-FileText $f; if ($null -ne $x) { [regex]::Matches($x, '<name>[^<]*</name>') | ForEach-Object { $_.Value } } } }
function V-wst044-jeus { $a = V-admin-jeus; if ($a -like '점검불가*') { return $a }; return "수동확인|JEUS accounts.xml 관리자 계정/비밀번호 디폴트(jeusadmin 등) 여부 확인 ($(($a -split '\|', 2)[1]))" }
function E-wst044-jeus { E-admin-jeus }

# 응답 수집 (구성된 HTTP 포트 중 리슨 중인 것만)
Hp-Collect
Hp-Probe-All
Append-Utf8 $script:EVD "# HTTP 응답 수집: 대상 $($script:HpTargets.Count)건, 응답 결과 $($script:HpRes.Count)건 $($script:HpNote)"

if ($script:KMODE -ne 'mi') {
# ── 전자금융 평가기준 [웹서버-WAS] WST ───────────────────────────
Item 'WST-031' 'listing' $ALLT $true
ItemX 'WST-033' 'IIS Apache Nginx Tomcat JEUS' { Combine-Ev-Dirtrav } { Combine-Dirtrav }
ItemX 'WST-034' '' { Combine-Ev-Chk 'wst034' $ALLT } { $r = Combine 'wst034' $ALLT; if (-not $r) { '수동확인|Apache/Nginx/JEUS 는 불필요 파일 자동 판정 미지원 - 문서 루트 수동 확인' } else { $r } }
Item 'WST-035' 'upload' $ALLT $true
Item 'WST-036' 'webproc' $ALLT $true
Item 'WST-037' 'docroot' $ALLT $true
Item 'WST-038' 'links' $ALLT $true
ItemX 'WST-039' '' { E-wst039-all } { V-wst039-all }
if (-not ($WEB_LIST.Count + $WAS_LIST.Count)) { Item 'WST-044' 'wst044' 'Tomcat JEUS' $true }
elseif (-not (Kt 'Tomcat JEUS')) { Evd 'WST-044' 'Sec "탐지" @("Tomcat/JEUS 미탐지")'; NA 'WST-044' '관리 계정을 사용하는 WAS(Tomcat/JEUS) 미탐지' }
else { Item 'WST-044' 'wst044' 'Tomcat JEUS' $true }
Item 'WST-102' 'servinfo' $ALLT $true
Item 'WST-121' 'proxy' $ALLT $true
Item 'WST-122' 'ssi' $ALLT $true
$script:ErrStrict = $true; Item 'WST-123' 'errpage' $ALLT $true; $script:ErrStrict = $false
Item 'WST-124' 'ldap' $ALLT $true
Item 'WST-125' 'uploaddirs' $ALLT $true

# WST-032·040·041·042·043: IIS 평가대상 항목 (IIS 없으면 N-A)
foreach ($pair in @(@('WST-032', 'wst032'), @('WST-040', 'confexp'), @('WST-041', 'wst041'), @('WST-042', 'scriptmap'), @('WST-043', 'wst043'))) {
    $code = $pair[0]; $chk = $pair[1]
    if (-not (Has-Prod 'iis')) { EvdQ $code '탐지된 웹서버' "IIS 미설치 (웹서버: $($WEB_LIST -join ' '))"; NA $code 'IIS 미설치 (Windows IIS 평가대상 항목)'; continue }
    Item $code $chk 'IIS' $true
}

# WST-080: 주기적인 보안패치 (OS 판정 + 웹서버/WAS 버전 확인 병합)
EvdQ 'WST-080' 'IIS/Tomcat 버전' "IIS $IIS_VERSION / Tomcat $(($TOMCAT_HOMES | ForEach-Object { "$_ => $(Tc-Ver $_)" }) -join ', ')"
MergeHold 'WST-080' '수동확인' "웹 제품 보안패치 확인 필요 (IIS $IIS_VERSION$(foreach ($h in $TOMCAT_HOMES) { " / Tomcat[$h] $(Tc-Ver $h)" })) - 벤더 보안 공지 대조"

# WST-126: EoS (OS 판정 + 웹 제품)
$ev126 = (& { E-eos-all } | Out-String -Width 4096); EvdQ 'WST-126' '웹 제품 버전' $ev126
$w126 = if ($WEB_LIST.Count + $WAS_LIST.Count) { Combine 'eos' $ALLT } else { '' }
if ($w126) { MergeHold 'WST-126' (($w126 -split '\|', 2)[0]) (($w126 -split '\|', 2)[1]) } else { MergeHold 'WST-126' '' '' }

# 평가기준상 WIN 평가대상이 아닌 항목 중 미출력 항목은 N-A (증적 포함)
$emitted = @(); if (Test-Path $script:EVD) { $emitted = @([regex]::Matches((Read-FileText $script:EVD), '(?m)^\[판정\] (WST-\d{3})') | ForEach-Object { $_.Groups[1].Value }) }
foreach ($code in $script:NA_WIN_WST) { if ($emitted -notcontains $code) { EvdQ $code '평가대상 아님' 'WIN 해당 없음 (평가기준 평가대상 열) - 원 점검 수행 안 함'; Emit $code 'N-A' '평가대상 아님 (WIN 해당 없음 - 평가기준 평가대상 열)' } }
}
# ═══ 주요정보통신기반시설 상세가이드(2026) 웹 서비스 WEB-01 ~ WEB-26 ═══
if ($script:KMODE -ne 'ef') {
Item 'WEB-01' 'admin' 'Tomcat JEUS' $false
Item 'WEB-02' 'weakpw' 'Tomcat IIS JEUS' $false
Item 'WEB-03' 'pwfile' 'Tomcat IIS JEUS' $false
Item 'WEB-04' 'listing' $ALLT $false
Item 'WEB-05' 'cgi' 'Apache Tomcat Nginx IIS' $false
Item 'WEB-06' 'updir' 'Apache Tomcat Nginx IIS' $false
Item 'WEB-07' 'unneeded' $ALLT $false
Item 'WEB-08' 'upload' $ALLT $false
Item 'WEB-09' 'webproc' $ALLT $false
Item 'WEB-10' 'proxy' $ALLT $false
Item 'WEB-11' 'docroot' $ALLT $false
Item 'WEB-12' 'links' $ALLT $false
# WEB-13: IIS(.asa/.asax 매핑) + Tomcat·JEUS(DB 연결 설정 파일 권한) + Spring Boot 독립 실행 앱
$sp = V-dbconf-spring
if (-not (Kt 'Tomcat IIS JEUS') -and -not $sp) {
    EvdQ 'WEB-13' '탐지된 웹서버/WAS' "웹서버: $($WEB_LIST -join ' ') / WAS: $($WAS_LIST -join ' ') / Spring Boot 설정 후보: $(@(Spring-Cfgs).Count)개"
    if (-not ($WEB_LIST.Count + $WAS_LIST.Count)) { NA 'WEB-13' '웹서버/WAS 미탐지' } else { NA 'WEB-13' '가이드 점검 대상(Tomcat, IIS, JEUS) 제품 및 Spring Boot 설정 파일 미탐지' }
} else {
    $t13 = (& { Combine-Ev-Chk 'confexp' 'IIS'; Combine-Ev-Chk 'dbconf' 'Tomcat JEUS'; E-dbconf-spring } | Out-String -Width 4096)
    EvdQ 'WEB-13' '설정 파일 노출/DB 연결 설정 증적' $t13
    $r13 = ''; if (Pt 'iis' 'IIS') { $r13 = WorseR $r13 (Combine 'confexp' 'IIS') }; $r13 = WorseR $r13 (Combine 'dbconf' 'Tomcat JEUS'); if ($sp) { $r13 = WorseR $r13 $sp }
    $p = $r13 -split '\|', 2; Emit 'WEB-13' $p[0] $p[1]
}
Item 'WEB-14' 'confperm' $ALLT $false
Item 'WEB-15' 'scriptmap' 'Tomcat IIS JEUS' $false
Item 'WEB-16' 'servinfo' $ALLT $false
Item 'WEB-17' 'vdir' 'Apache Tomcat Nginx' $false
Item 'WEB-18' 'webdav' 'Apache Nginx IIS' $false
Item 'WEB-19' 'ssi' 'Apache Tomcat Nginx IIS' $false
Item 'WEB-20' 'ssl' 'Apache Nginx IIS' $false
Item 'WEB-21' 'redirect' 'Apache Nginx IIS' $false
$script:ErrStrict = $false; Item 'WEB-22' 'errpage' $ALLT $false
Item 'WEB-23' 'ldap' 'Tomcat' $false
Item 'WEB-24' 'uploaddirs' $ALLT $false
# WEB-25: 버전 EoS 판정 + 패치 이력 수동 확인
if (-not (Kt $ALLT)) { Item 'WEB-25' 'eos' $ALLT $false } else {
    EvdQ 'WEB-25' '웹 제품 버전' ((& { E-eos-all }) | Out-String -Width 4096)
    $r25 = Combine 'eos' $ALLT; $k = ($r25 -split '\|', 2)[0]
    if ($k -ne '취약' -and $k -ne '점검불가') { $r25 = "수동확인|$(($r25 -split '\|', 2)[1]) - 벤더 최신 보안 패치 적용 여부·패치 관리 정책(주기적 점검) 확인" }
    $p = $r25 -split '\|', 2; Emit 'WEB-25' $p[0] $p[1]
}
Item 'WEB-26' 'logperm' $ALLT $false
}

# secedit 보안 정책 export 임시 파일 정리
if ($seceditFile -and (Test-Path $seceditFile)) { Remove-Item $seceditFile -Force -EA SilentlyContinue }

$total = $script:cntPass + $script:cntFail + $script:cntMC + $script:cntNA + $script:cntUnable
Out-Res "# ================================================================"
Out-Res "# 점검 요약"
Out-Res "#   총 점검 항목: $total"
if ($total -gt 0) {
    Out-Res "#   양호:         $($script:cntPass)  ($([math]::Round($script:cntPass/$total*100,1))%)"
    Out-Res "#   취약:         $($script:cntFail)  ($([math]::Round($script:cntFail/$total*100,1))%)"
}
Out-Res "#   점검불가:     $($script:cntUnable)"
Out-Res "#   수동확인:     $($script:cntMC)"
Out-Res "#   N-A:          $($script:cntNA)"
Out-Res "# ================================================================"
Out-Res "# 점검 완료: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Out-Res "# 증적 파일: $($script:EVD)"
Out-Res "# 결과 파일: $($script:OUT)"
