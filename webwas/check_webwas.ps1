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
#   웹서버: IIS 8.5/10.0 / Apache(Windows) / Nginx(Windows)
#   WAS:    Tomcat(Windows) / JEUS(Windows)
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
#   .\check_webwas.ps1 > C:\Temp\$env:COMPUTERNAME_webwas.txt
#
# [산출물]
#   1) 표준출력 — 파이프 구분자 결과 (파일로 리다이렉트)
#      형식: WST-항목코드|결과|근거설명
#      결과: 양호 / 취약 / 수동확인 / N-A
#   2) 증적 파일 — $env:TEMP\<호스트명>_webwas_evidence.txt
#      점검 중 실행한 명령어·출력·판정 근거가 타임스탬프와 함께 기록됨
#
# ================================================================
param([string]$Mode = "")   # ef=전자금융(WST) / mi=주요정보 2026 상세가이드(WEB-01~26) / all=둘 다
$script:KMODE = "$Mode".ToLower()
if (-not $script:KMODE) {
    if ([Environment]::UserInteractive -and $Host.Name -eq 'ConsoleHost') {
        Write-Host "점검 기준을 선택하세요: 1) 전자금융기반시설(WST)  2) 주요정보통신기반시설 2026 상세가이드(WEB-01~WEB-26)  3) 둘 다"
        $sel = Read-Host "선택 [1/2/3] (Enter=3)"
        $script:KMODE = switch ("$sel".Trim()) { '1' { 'ef' } '2' { 'mi' } default { 'all' } }
    } else { $script:KMODE = 'all' }
}
$script:KMODE = switch ($script:KMODE) { '1' {'ef'} 'srv' {'ef'} '2' {'mi'} 'kisa' {'mi'} '3' {'all'} default { $script:KMODE } }
if (@('ef','mi','all') -notcontains $script:KMODE) { Write-Host "사용법: check_webwas.ps1 -Mode ef|mi|all"; exit 1 }
$ErrorActionPreference = "SilentlyContinue"
$ProgressPreference    = "SilentlyContinue"

$script:cntPass=0; $script:cntFail=0; $script:cntMC=0; $script:cntNA=0

$script:ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$script:EVD = "$script:ScriptDir\$($env:COMPUTERNAME)_webwas_evidence.txt"
"# ================================================================" | Out-File $script:EVD -Encoding UTF8
"# 웹서버/WAS 증적 파일 (감사 추적용)" | Add-Content $script:EVD -Encoding UTF8
"# 대상: $env:COMPUTERNAME" | Add-Content $script:EVD -Encoding UTF8
"# 생성: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" | Add-Content $script:EVD -Encoding UTF8
"# ================================================================" | Add-Content $script:EVD -Encoding UTF8


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
    if ($script:KMODE -eq 'mi' -and $code -notlike 'WEB-*' -and $code -notlike 'REF-*' -and -not ($script:PHASE -eq 'os' -and $script:HOLDC -contains $code)) {
        "[참고-주요정보 모드 제외] $code|$res|$msg`n" | Add-Content $script:EVD -Encoding UTF8; return }
    if ($script:KMODE -eq 'ef' -and $code -like 'WEB-*') { return }
    if ($code -like 'REF-*') { "[참고-평가기준 외] $code|$res|$msg`n" | Add-Content $script:EVD -Encoding UTF8; return }
    if ($script:PHASE -eq 'os' -and $script:HOLDC -contains $code) { $script:HOLD[$code] = "$res|$msg"; return }
    if ($script:NA_WIN_WST -contains $code -and $res -ne 'N-A') {
        "[평가대상 아님] $code 원 판정: $res|$msg" | Add-Content $script:EVD -Encoding UTF8
        $res = 'N-A'; $msg = '평가대상 아님 (WIN 해당 없음 - 평가기준 평가대상 열)'
    }
    switch ($res) { '양호' { $script:cntPass++ } '취약' { $script:cntFail++ } '수동확인' { $script:cntMC++ } default { $script:cntNA++ } }
    Write-Output "$code|$res|$msg"
    $nm = $script:INAME[$code]
    if ($nm) { "[판정] $code ($nm)|$res|$msg`n" | Add-Content $script:EVD -Encoding UTF8 } else { "[판정] $code|$res|$msg`n" | Add-Content $script:EVD -Encoding UTF8 }
}
function Pass([string]$code,[string]$msg) { Emit $code '양호' $msg }
function Fail([string]$code,[string]$msg) { Emit $code '취약' $msg }
function NA  ([string]$code,[string]$msg) { Emit $code 'N-A' $msg }
function MC  ([string]$code,[string]$msg) { Emit $code '수동확인' $msg }
function Evd([string]$item,[string]$cmd) {
    $item = RouteCode $item
    "[$item] $(Get-Date -Format 'HH:mm:ss') PS> $cmd" | Add-Content $script:EVD -Encoding UTF8
    try { $r = Invoke-Expression $cmd 2>&1 | Out-String; $r | Add-Content $script:EVD -Encoding UTF8 } catch { $_.Exception.Message | Add-Content $script:EVD -Encoding UTF8 }
    "" | Add-Content $script:EVD -Encoding UTF8
}
function EvdQ([string]$item,[string]$desc,[string]$val) {
    $item = RouteCode $item
    "[$item] $(Get-Date -Format 'HH:mm:ss') $desc`n$val`n" | Add-Content $script:EVD -Encoding UTF8
}
function WorseR([string]$a,[string]$b) {
    $rk = @{ '취약'=4; '수동확인'=3; '양호'=2; 'N-A'=1 }
    if (-not $a) { return $b }; if (-not $b) { return $a }
    $ra = ($a -split '\|',2)[0]; $rb = ($b -split '\|',2)[0]
    if ($rk[$rb] -gt $rk[$ra]) { return "$b / $(($a -split '\|',2)[1])" } else { return "$a / $(($b -split '\|',2)[1])" }
}
function MergeHold([string]$code,[string]$wres,[string]$wmsg) {
    $os = $script:HOLD[$code]
    $o = if ($os) { "$(($os -split '\|',2)[0])|OS: $(($os -split '\|',2)[1])" } else { "" }
    $w = if ($wres) { "$wres|웹/WAS: $wmsg" } else { "" }
    $m = WorseR $o $w
    if (-not $m) { $m = '수동확인|판정 정보 없음 - 수동 확인' }
    $script:PHASE = 'final'
    $p = $m -split '\|',2; Emit $code $p[0] $p[1]
}

# ── 환경 탐지 ───────────────────────────────────────────────────
$HN      = $env:COMPUTERNAME
$WEB_SRV = if ($env:WEB_SRV) { $env:WEB_SRV.ToLower() } else { "" }
$WAS_SRV = if ($env:WAS_SRV) { $env:WAS_SRV.ToLower() } else { "" }

# IIS 탐지
$IIS_INSTALLED = $false
$IIS_VERSION   = ""
$APPCMD        = "$env:SystemRoot\System32\inetsrv\appcmd.exe"
if (Get-Service W3SVC -EA SilentlyContinue) {
    $IIS_INSTALLED = $true
    $iisReg = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\InetStp" -EA SilentlyContinue
    $IIS_VERSION = if ($iisReg) { "$($iisReg.MajorVersion).$($iisReg.MinorVersion)" } else { "unknown" }
    if (-not $WEB_SRV) { $WEB_SRV = "iis" }
}

# Apache on Windows 탐지
$APACHE_CONF = ""
if (-not $WEB_SRV) {
    $apachePaths = @(
        "C:\Apache24\conf\httpd.conf",
        "C:\Apache2\conf\httpd.conf",
        "C:\Program Files\Apache Group\Apache2\conf\httpd.conf",
        "C:\Program Files (x86)\Apache Group\Apache2\conf\httpd.conf"
    )
    foreach ($p in $apachePaths) {
        if (Test-Path $p) { $APACHE_CONF = $p; $WEB_SRV = "apache"; break }
    }
}

# Nginx on Windows 탐지
$NGINX_CONF = ""
if (-not $WEB_SRV) {
    $nginxPaths = @("C:\nginx\conf\nginx.conf","C:\Program Files\nginx\conf\nginx.conf")
    foreach ($p in $nginxPaths) {
        if (Test-Path $p) { $NGINX_CONF = $p; $WEB_SRV = "nginx"; break }
    }
}

# Tomcat on Windows 탐지
$TOMCAT_HOME = $env:TOMCAT_HOME
if (-not $TOMCAT_HOME) {
    $tcPaths = @(
        "C:\Program Files\Apache Software Foundation\Tomcat 10.1",
        "C:\Program Files\Apache Software Foundation\Tomcat 10.0",
        "C:\Program Files\Apache Software Foundation\Tomcat 9.0",
        "C:\Program Files\Apache Software Foundation\Tomcat 8.5",
        "C:\tomcat","C:\opt\tomcat"
    )
    foreach ($p in $tcPaths) {
        if (Test-Path "$p\conf\server.xml") { $TOMCAT_HOME = $p; break }
    }
}
if ($TOMCAT_HOME -and -not $WAS_SRV) { $WAS_SRV = "tomcat" }

# JEUS on Windows 탐지
$JEUS_HOME = $env:JEUS_HOME
if ($JEUS_HOME -and -not $WAS_SRV) { $WAS_SRV = "jeus" }

# IIS WebAdministration 모듈 로드
$HAS_WEB_ADMIN = $false
if ($IIS_INSTALLED) {
    Import-Module WebAdministration -EA SilentlyContinue
    $HAS_WEB_ADMIN = (Get-Module WebAdministration -EA SilentlyContinue) -ne $null
}

Write-Output "# ================================================================"
Write-Output "# 점검 대상: $HN"
Write-Output "# OS: $((Get-WmiObject Win32_OperatingSystem -EA SilentlyContinue).Caption) (Build $([Environment]::OSVersion.Version.Build))"
Write-Output "# 웹서버: $(if ($WEB_SRV) { $WEB_SRV } else { '미탐지' })$(if ($IIS_INSTALLED) { " / IIS $IIS_VERSION" })"
Write-Output "# WAS: $(if ($WAS_SRV) { $WAS_SRV } else { '미탐지' })"
Write-Output "# Tomcat 홈: $(if ($TOMCAT_HOME) { $TOMCAT_HOME } else { '미탐지' })"
Write-Output "# 점검 기준: $(switch ($script:KMODE) { 'ef' { '전자금융기반시설 보안 취약점 평가기준 제2026-1호 [웹서버-WAS]' } 'mi' { '주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드(2026) [웹 서비스 WEB-01~WEB-26]' } default { '전자금융기반시설 보안 취약점 평가기준 제2026-1호 [웹서버-WAS] + 주요정보통신기반시설 상세가이드(2026) [웹 서비스 WEB-01~WEB-26]' } })"
Write-Output "# 점검 일시: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Output "# ================================================================"

$hn     = $env:COMPUTERNAME
# PS 2.0(2008 R2 기본) 호환: Get-CimInstance 가 없으면 Get-WmiObject 로 대체
if (-not (Get-Command Get-CimInstance -EA SilentlyContinue)) {
    function Get-CimInstance {
        param([Parameter(Position=0)][Alias('Class')][string]$ClassName, [string]$Namespace = 'root\cimv2', [string]$Filter, $ErrorAction)
        $p = @{ Class = $ClassName; Namespace = $Namespace; ErrorAction = 'SilentlyContinue' }
        if ($Filter) { $p.Filter = $Filter }
        Get-WmiObject @p
    }
}
$os     = (Get-CimInstance Win32_OperatingSystem -EA SilentlyContinue)
$build  = if ($os) { [int]$os.BuildNumber } else { [Environment]::OSVersion.Version.Build }
$ver    = switch ($build) {
    {$_ -le 7601}  {"2008R2"; break}; {$_ -le 9600}  {"2012R2"; break}; {$_ -le 14393} {"2016"; break}
    {$_ -le 17763} {"2019"; break};   {$_ -le 20348} {"2022"; break};   default          {"2025"}
}


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
# ── SRV-001: SNMP 버전 ───────────────────────────────────────────
Evd "SRV-001" "Get-Service SNMP -EA SilentlyContinue | Select-Object Status,StartType"
$snmpSvc   = Get-SvcState "SNMP"; $winSnmpOn = $snmpSvc -and $snmpSvc.Status -match "Running"
$udp161    = @(Get-NetUDPEndpoint -LocalPort 161 -EA SilentlyContinue)   # 2012+
$snmpProcs = @(Get-Process -EA SilentlyContinue | Where-Object { $p0 = $_; $p0.ProcessName -match '^snmpd$' -or @($udp161 | Where-Object { $_.OwningProcess -eq $p0.Id -and $p0.ProcessName -ne 'snmp' }).Count })
$otherSnmp = (-not $winSnmpOn) -and ($snmpProcs.Count -gt 0)
$snmpPaths = @($snmpProcs | ForEach-Object { if ($_.Path) { $_.Path } else { $_.ProcessName } })
if ($otherSnmp) {
    EvdQ "SRV-001" "타사 SNMP 에이전트 (snmpd / UDP 161)" "$($snmpPaths -join ', ') / UDP161 PID: $(($udp161 | ForEach-Object { $_.OwningProcess }) -join ',')"
    foreach ($c in (@('C:\usr\etc\snmp\snmpd.conf') + @($snmpProcs | Where-Object { $_.Path } | ForEach-Object { Join-Path (Split-Path (Split-Path $_.Path)) 'etc\snmp\snmpd.conf' }) | Select-Object -Unique)) {
        if (Test-Path $c) { EvdQ "SRV-001" "$c (community 마스킹)" ((Select-String -Path $c -Pattern '^\s*(rocommunity|rwcommunity|com2sec|createUser|rouser|rwuser)' -EA SilentlyContinue | ForEach-Object { $_.Line -replace '((community|com2sec)\S*\s+(\S+\s+){0,2})\S+\s*$','$1****' }) -join "`n") }
    }
}
if ($otherSnmp) {
    MC  "SRV-001" "타사 SNMP 에이전트 실행($($snmpPaths -join ', ')) - snmpd.conf community 복잡도/v3 설정 확인"
} elseif (-not $winSnmpOn) {
    NA  "SRV-001" "SNMP 서비스 미실행"
} else {
    $snmpReg = Get-Reg "HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\ValidCommunities" $null
    $comm = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\ValidCommunities" -EA SilentlyContinue).PSObject.Properties | Where-Object { @('PSPath','PSParentPath','PSChildName','PSDrive','PSProvider') -notcontains $_.Name }
    # 평가기준 판단방법: 기본값(public/private) 미사용 + 복잡도(2종 10자 이상 / 3종 8자 이상) 만족 여부 (보고서에는 마스킹 표기)
    $weak = @(); $strong = @()
    foreach ($c in $comm) {
        $n = $c.Name
        $cls = 0; if ($n -match '[A-Za-z]') { $cls++ }; if ($n -match '\d') { $cls++ }; if ($n -match '[^A-Za-z0-9]') { $cls++ }
        $mask = if ($n.Length -gt 2) { $n.Substring(0,2) + ('*' * ($n.Length - 2)) } else { '**' }
        if ($n -match '^(public|private)$' -or -not (($cls -ge 2 -and $n.Length -ge 10) -or ($cls -ge 3 -and $n.Length -ge 8))) { $weak += "$mask($($n.Length)자/$cls종)" }
        else { $strong += "$mask($($n.Length)자/$cls종)" }
    }
    if ($weak) { Fail "SRV-001" "SNMP Community 기본값 또는 복잡도 미달(2종 10자/3종 8자): $($weak -join ',')" }
    elseif ($strong) { Pass "SRV-001" "SNMP Community 복잡도 충족: $($strong -join ',')" }
    else { MC "SRV-001" "SNMP 실행 중 - Community 미등록(v3/설정) 수동 확인" }
}
Evd "SRV-001" "Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Ole' -Name LegacyAuthenticationLevel,LegacyImpersonationLevel -EA SilentlyContinue"

# ── SRV-013: Anonymous FTP ───────────────────────────────────────
# 판단방법: IIS 6 이하 metabase.xml AllowAnonymous / IIS 7 이상 applicationHost.config ftpServer anonymousAuthentication
Evd "SRV-013" "Get-Service FTPSVC,MSFTPSVC -EA SilentlyContinue | Select-Object Name,Status,StartType; Get-NetTCPConnection -LocalPort 21 -State Listen -EA SilentlyContinue | Select-Object LocalAddress,OwningProcess"
$ftp13 = Get-SvcState "FTPSVC"; if (-not $ftp13) { $ftp13 = Get-SvcState "MSFTPSVC" }
$ftp13Run = ($ftp13 -and $ftp13.Status -eq "Running") -or (Get-NetTCPConnection -LocalPort 21 -State Listen -EA SilentlyContinue)
$ahc13 = "$env:windir\System32\inetsrv\config\applicationHost.config"
$ftpSites = Get-IisFtpSites
EvdQ "SRV-013" "IIS FTP 사이트별 설정 (Anon/Ctl/Dat/Banner/IpRestr/Root, siteDefaults 상속 반영)" $(if ($null -eq $ftpSites) { 'applicationHost.config 없음/파싱 실패' } elseif ($ftpSites.Count -eq 0) { 'FTP 바인딩 사이트 없음' } else { ($ftpSites | ForEach-Object { "$($_.Name): Anon=$($_.Anon) Ctl=$($_.Ctl) Dat=$($_.Dat) Banner=$($_.Banner) IpRestr=$($_.IpRestr) Root=$($_.Root)" }) -join "`n" })
$ftpIis = ($null -ne $ftpSites -and $ftpSites.Count -gt 0)
if (-not $ftp13Run) {
    Pass "SRV-013" "FTP 서비스 미사용 (FTPSVC/MSFTPSVC 중지, 21번 포트 리슨 없음)"
} elseif (-not $ftpIis) {
    MC "SRV-013" "FTP 서비스 실행 중 - IIS FTP 사이트 미탐지(IIS 6 metabase/타사 FTP) Anonymous 설정 수동 확인"
} else {
    $a13 = @($ftpSites | Where-Object { $_.Anon -eq 'true' } | ForEach-Object { $_.Name })
    $u13 = @($ftpSites | Where-Object { $null -eq $_.Anon } | ForEach-Object { $_.Name })
    if ($a13.Count) { Fail "SRV-013" "IIS FTP Anonymous 인증 활성화 사이트: $($a13 -join ', ')" }
    elseif ($u13.Count) { MC "SRV-013" "IIS FTP Anonymous 설정 미확인 사이트: $($u13 -join ', ') - 수동 확인" }
    else { Pass "SRV-013" "IIS FTP 전 사이트 Anonymous 인증 비활성화" }
}

# ── SRV-018: 하드디스크 기본 공유 비활성화 ──────────────────────
Evd "SRV-018" "Get-SmbShare -EA SilentlyContinue | Select-Object Name,Path | Format-Table -AutoSize; Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name AutoShareServer,AutoShareWks -EA SilentlyContinue"
# 평가기준: Windows 2003 이상이면 양호 / 2003 미만은 기본 공유 부재 + AutoShareServer(Wks)=0 이어야 양호
$autoShare = Get-Reg "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" "AutoShareServer"
$shares = Get-SmbShare -EA SilentlyContinue | Where-Object { $_.Name -match '^\w\$$|^ADMIN\$|^IPC\$' }
if ($build -ge 3790) {
    Pass "SRV-018" "Windows 2003 이상 (Build $build) - 평가기준상 양호 (참고: 기본 공유 $(if ($shares) { ($shares | ForEach-Object { $_.Name }) -join ',' } else { '없음' }), AutoShareServer=$autoShare)"
} elseif ($shares -or $autoShare -ne 0) {
    Fail "SRV-018" "Windows 2003 미만 - 기본 공유 $(if ($shares) { ($shares | ForEach-Object { $_.Name }) -join ',' } else { '없음' }), AutoShareServer=$autoShare"
} else { Pass "SRV-018" "Windows 2003 미만 - 기본 공유 없음, AutoShareServer=0" }

# ── SRV-020: 공유 접근통제 ──────────────────────────────────────
try {
    Evd "SRV-020" "Get-SmbShare -EA SilentlyContinue | ForEach-Object { Write-Output `"Share: `$(`$_.Name)`"; Get-SmbShareAccess -Name `$_.Name -EA SilentlyContinue | Where-Object {`$_.AccountName -match 'Everyone'} }"
    $vuln020 = @()
    Get-SmbShare -EA Stop | Where-Object {$_.Name -notmatch "^IPC\$"} | ForEach-Object {
        $acl = Get-SmbShareAccess -Name $_.Name -EA SilentlyContinue
        if ($acl | Where-Object {$_.AccountName -match "Everyone" -and $_.AccessRight -ne "Deny"}) {
            $vuln020 += $_.Name
        }
    }
    if ($vuln020) { Fail "SRV-020" "Everyone 접근 공유: $($vuln020 -join ',')" }
    else { Pass "SRV-020" "공유 폴더 Everyone 허용 없음" }
} catch { MC "SRV-020" "공유 접근통제 수동 확인" }

# ── SRV-022: 패스워드 미설정 계정 ──────────────────────────────
$accts = @(Get-LocalAccounts)
EvdQ "SRV-022" "로컬 계정 (Name / Enabled / PasswordRequired / LastLogon / PasswordLastSet / 수집원)" (($accts | ForEach-Object { "$($_.Name) / $($_.Enabled) / $($_.PasswordRequired) / $($_.LastLogon) / $($_.PasswordLastSet) / $($_.Src)" }) -join "`n")
try {
    if ($accts.Count -eq 0) { throw "계정 조회 실패" }
    $noPw = @($accts | Where-Object { -not $_.PasswordRequired -and $_.Enabled })
    # 판단기준: 빈 암호 계정 없음 + '콘솔 로그온 시 로컬 계정에서 빈 암호 사용 제한'(LimitBlankPasswordUse=1)
    $lbp = Get-Reg "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "LimitBlankPasswordUse"
    EvdQ "SRV-022" "Lsa LimitBlankPasswordUse" "$lbp"
    if ($noPw.Count) { Fail "SRV-022" "패스워드 미요구 계정: $(($noPw | ForEach-Object { $_.Name }) -join ',')" }
    elseif ("$lbp" -eq "0") { Fail "SRV-022" "빈 암호 사용 제한 정책 사용 안 함 (LimitBlankPasswordUse=0)" }
    else { Pass "SRV-022" "모든 활성 계정 패스워드 요구, 빈 암호 사용 제한 (LimitBlankPasswordUse=$(if ($null -eq $lbp) { '기본값 1' } else { $lbp }))" }
} catch { MC "SRV-022" "패스워드 미설정 계정 수동 확인" }

# ── SRV-023: 원격 터미널 암호화 수준 (MinEncryptionLevel ≥ 2 "클라이언트와 호환 가능(중간)") ──
Evd "SRV-023" "Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name MinEncryptionLevel,fDenyTSConnections -EA SilentlyContinue; Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name MinEncryptionLevel -EA SilentlyContinue; Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -EA SilentlyContinue"
$rdpDeny = Get-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "fDenyTSConnections"
if ($null -eq $rdpDeny) { $rdpDeny = Get-Reg "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" "fDenyTSConnections" }
$mel = Get-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "MinEncryptionLevel"
if ($null -eq $mel) { $mel = Get-Reg "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" "MinEncryptionLevel" }
if ($rdpDeny -eq 1) { Pass "SRV-023" "원격 터미널 서비스 미사용 (fDenyTSConnections=1)" }
elseif ($null -eq $mel) { MC "SRV-023" "MinEncryptionLevel 값 없음 (OS 기본값 적용) - 암호화 수준 수동 확인" }
elseif ([int]$mel -ge 2) { Pass "SRV-023" "RDP 암호화 수준 MinEncryptionLevel=$mel (중간 이상)" }
else { Fail "SRV-023" "RDP 암호화 수준 MinEncryptionLevel=$mel (낮음)" }

# ── SRV-024: 취약 Telnet 인증 ───────────────────────────────────
# 판단기준: 미실행 또는 인증 방법 NTLM만 허용 = 양호 (SecurityMechanism 2=NTLM, 4=Password, 6=둘 다)
Evd "SRV-024" "Get-Service TlntSvr -EA SilentlyContinue | Select-Object Status,StartType; Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\TelnetServer\1.0' -Name SecurityMechanism -EA SilentlyContinue; if (Get-Command tlntadmn.exe -EA SilentlyContinue) { tlntadmn config }"
$telnet = Get-SvcState "TlntSvr"
$sm024  = Get-Reg "HKLM:\SOFTWARE\Microsoft\TelnetServer\1.0" "SecurityMechanism"
if (-not $telnet -or $telnet.Status -notmatch "Running") { Pass "SRV-024" "Telnet 서비스 미실행" }
elseif ("$sm024" -eq "2") { Pass "SRV-024" "Telnet 실행 중 - 인증 방식 NTLM만 허용 (SecurityMechanism=2)" }
elseif ($null -eq $sm024) { MC "SRV-024" "Telnet 실행 중 - SecurityMechanism 값 없음, tlntadmn config 인증 방식 확인 (Password 지원 시 취약)" }
else { Fail "SRV-024" "Telnet 실행 중 - Password 인증 허용 (SecurityMechanism=$sm024, NTLM만(2) 필요)" }

# ── SRV-026: root(관리자) 원격 접속 제한 ───────────────────────
# RDP 기본 포트 및 관리자 그룹 원격 접근 확인
Evd "SRV-026" "Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -EA SilentlyContinue | Select-Object fDenyTSConnections"
$rdpGroup = Get-Reg "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" "fDenyTSConnections"
if ($rdpGroup -eq 1) { Pass "SRV-026" "RDP 원격 접속 비활성화됨" }
else { MC "SRV-026" "RDP 활성화 - 관리자 계정 원격 접속 허용 범위 수동 확인" }

# ── SRV-027: 서비스 접근 IP/포트 제한 (방화벽) ──────────────────
# 판단기준: Windows 방화벽 또는 3rd-Party 방화벽으로 접근통제 → Windows 방화벽이 꺼져 있으면 타사 제품 확인(수동)
try {
    Evd "SRV-027" "Get-NetFirewallProfile -EA SilentlyContinue | Select-Object Name,Enabled,DefaultInboundAction | Format-Table -AutoSize; Get-NetConnectionProfile -EA SilentlyContinue | Select-Object InterfaceAlias,NetworkCategory | Format-Table -AutoSize"
    $fwProfiles = Get-NetFirewallProfile -EA Stop
    $act027 = @(Get-NetConnectionProfile -EA SilentlyContinue | ForEach-Object { switch ("$($_.NetworkCategory)") { 'DomainAuthenticated' { 'Domain' } 'Private' { 'Private' } default { 'Public' } } } | Select-Object -Unique)
    $offAll = @($fwProfiles | Where-Object { -not $_.Enabled } | ForEach-Object { "$($_.Name)" })
    $offAct = @($offAll | Where-Object { $act027.Count -eq 0 -or $act027 -contains $_ })
    if ($offAct.Count) { MC "SRV-027" "Windows 방화벽 비활성(적용 중 프로파일: $($offAct -join ',')) - 3rd-Party 방화벽 등 접근통제 여부 확인, 없으면 취약" }
    elseif ($offAll.Count) { Pass "SRV-027" "적용 중 프로파일($($act027 -join ',')) 방화벽 활성 (미적용 프로파일 비활성: $($offAll -join ','))" }
    else { Pass "SRV-027" "Windows 방화벽 모든 프로파일 활성화" }
} catch {
    Evd "SRV-027" "netsh advfirewall show currentprofile state"
    $fw = netsh advfirewall show currentprofile state 2>$null
    if ($fw -match "State\s+OFF|상태\s+사용 안 함") { MC "SRV-027" "Windows 방화벽 비활성(현재 프로파일, netsh) - 3rd-Party 방화벽 등 접근통제 여부 확인, 없으면 취약" }
    elseif ($fw -match "State\s+ON|상태\s+사용") { Pass "SRV-027" "Windows 방화벽 활성 (현재 프로파일, netsh)" }
    else { MC "SRV-027" "방화벽 상태 확인 실패 - 방화벽 사용 여부 수동 확인" }
}

# ── SRV-028: 원격 터미널 세션 타임아웃 (RDP MaxIdleTime ≤ 900초) ──
Evd "SRV-028" "Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name MaxIdleTime -EA SilentlyContinue; Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name MaxIdleTime -EA SilentlyContinue"
$idle = Get-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "MaxIdleTime"
if ($null -eq $idle -or $idle -eq 0) { $idle = Get-Reg "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" "MaxIdleTime" }
if ($null -eq $idle -or $idle -eq 0) { Fail "SRV-028" "RDP 유휴 세션 타임아웃(MaxIdleTime) 미설정" }
elseif ($idle -le 900000) { Pass "SRV-028" "RDP 유휴 세션 타임아웃=$([int]($idle/1000))초 (900초 이하)" }
else { Fail "SRV-028" "RDP 유휴 세션 타임아웃=$([int]($idle/1000))초 (900초 초과)" }

# ── SRV-029: SMB 세션 중단 ("로그온 시간 만료 시 강제 로그오프" EnableForcedLogOff=1) ──
Evd "SRV-029" "Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name EnableForcedLogOff,AutoDisconnect -EA SilentlyContinue"
$forced = Get-Reg "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" "EnableForcedLogOff"
if ($forced -eq 1) { Pass "SRV-029" "로그온 시간 만료 시 강제 로그오프 사용 (EnableForcedLogOff=1)" }
else { Fail "SRV-029" "로그온 시간 만료 시 강제 로그오프 사용 안 함 (EnableForcedLogOff=$forced)" }

# ── SRV-031: 계정 목록 노출 방지 ───────────────────────────────
Evd "SRV-031" "Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name RestrictAnonymous,RestrictAnonymousSAM -EA SilentlyContinue | Select-Object RestrictAnonymous,RestrictAnonymousSAM"
$ra = Get-Reg "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "RestrictAnonymous"
if ($null -ne $ra -and $ra -ge 1) { Pass "SRV-031" "RestrictAnonymous=$ra (익명 열거 제한)" }
else { Fail "SRV-031" "RestrictAnonymous=$(if ($null -eq $ra) { '미설정' } else { $ra }) (계정 목록 노출 가능)" }

# ── SRV-034: 불필요 서비스 비활성화 ────────────────────────────
# 판단기준(WIN): 1) NetBIOS 2) Alerter·Clipbook·Messenger·Simple TCP/IP 3) WebDAV 4) RDS(ADCLaunch) 가 불필요하게 활성화
Evd "SRV-034" "Get-Service Alerter,ClipSrv,Messenger,simptcp -EA SilentlyContinue | Select-Object Name,Status,StartType | Format-Table; Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces' -EA SilentlyContinue | ForEach-Object { '{0} NetbiosOptions={1}' -f `$_.PSChildName,(Get-ItemProperty `$_.PSPath -EA SilentlyContinue).NetbiosOptions }; Get-Item 'HKLM:\SYSTEM\CurrentControlSet\Services\W3SVC\Parameters\ADCLaunch' -EA SilentlyContinue"
$found = @()
foreach ($svc in @(@{n="Alerter";d="Alerter"},@{n="ClipSrv";d="Clipbook"},@{n="Messenger";d="Messenger"},@{n="simptcp";d="Simple TCP/IP"})) {
    $s = Get-SvcState $svc.n
    if ($s -and $s.Status -match "Running") { $found += $svc.d }
}
$review = @()
$nbOn = @(Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces' -EA SilentlyContinue | Where-Object { (Get-ItemProperty $_.PSPath -EA SilentlyContinue).NetbiosOptions -ne 2 })
if ($nbOn.Count -gt 0) { $review += "NetBIOS 활성 인터페이스 $($nbOn.Count)개" }
$ahc34 = "$env:windir\System32\inetsrv\config\applicationHost.config"
if ((Read-AllText $ahc34) -match '<authoring[^>]*enabled="true"') { $review += "WebDAV 활성" }
Evd "SRV-034" "Get-Content `"`$env:windir\msdfmap.ini`" -EA SilentlyContinue"
if (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Services\W3SVC\Parameters\ADCLaunch') { $review += "RDS(ADCLaunch) 존재" }
if ($found) { Fail "SRV-034" "불필요 서비스 실행: $($found -join ',')$(if ($review) { ' / 추가 확인: ' + ($review -join ', ') })" }
elseif ($review) { MC "SRV-034" "$($review -join ', ') - 업무상 필요 여부 확인" }
else { Pass "SRV-034" "NetBIOS 비활성, Alerter/Clipbook/Messenger/Simple TCP/IP·WebDAV·RDS 미사용" }

# ── SRV-035: 취약 서비스 비활성화 (Telnet) ──────────────────────
Evd "SRV-035" "Get-Service TlntSvr -EA SilentlyContinue | Select-Object Status,StartType"
$t = Get-SvcState "TlntSvr"
if ($t -and $t.Status -match "Running") { Fail "SRV-035" "Telnet 서비스 실행 중" }
else { Pass "SRV-035" "Telnet 서비스 미실행" }

# ── SRV-069: 패스워드 최대 사용기간 ────────────────────────────
Evd "SRV-069" "net accounts 2>`$null | Select-String 'password|암호'"
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
    elseif ($null -eq $min69 -or $null -eq $pwc69) { MC "SRV-069" "$pol - 길이/복잡도 정책 확인 실패(관리자 권한 필요)" }
    elseif ("$pwc69".Trim() -eq "1" -and [int]$min69 -ge 8) { Pass "SRV-069" "$pol (3종 8자 이상 충족)" }
    elseif ([int]$min69 -ge 10) { MC "SRV-069" "$pol - 복잡도 미사용, 10자 이상: 2종 조합 강제 수단(외부 정책 등) 확인" }
    else { Fail "SRV-069" "$pol - 2종 10자 / 3종 8자 미달" }
} else { MC "SRV-069" "패스워드 최대 사용기간 확인 실패" }

# ── SRV-070: 해독 가능한 암호화를 사용하여 암호 저장 (ClearTextPassword=0) ──
$ctp = Get-SecPol "ClearTextPassword"
EvdQ "SRV-070" "secedit ClearTextPassword" "$ctp"
if ($null -eq $ctp) { MC "SRV-070" "ClearTextPassword 정책 확인 실패 (관리자 권한 필요) - secpol.msc 암호 정책 수동 확인" }
elseif ("$ctp" -eq "0") { Pass "SRV-070" "해독 가능한 암호화 사용 안 함 (ClearTextPassword=0)" }
else { Fail "SRV-070" "해독 가능한 암호화 사용 (ClearTextPassword=$ctp)" }

# ── SRV-072: Administrator 계정명 변경 ──────────────────────────
$admin = $accts | Where-Object { $_.SID -match '-500$' } | Select-Object -First 1
$na072 = "$(Get-SecPol 'NewAdministratorName')".Trim().Trim('"')
EvdQ "SRV-072" "기본 관리자(SID-500) / secedit NewAdministratorName" "$(if ($admin) { "$($admin.Name) [$($admin.Src)]" } else { '계정 조회 실패' }) / $na072"
$an072 = if ($admin) { $admin.Name } else { $na072 }
if (-not $an072) { MC "SRV-072" "기본 관리자 계정(SID-500) 확인 실패" }
elseif ($an072 -eq "Administrator") { Fail "SRV-072" "Administrator 기본 계정명 미변경" }
else { Pass "SRV-072" "Administrator 계정명 변경됨: $an072" }

# ── SRV-073: 관리자 그룹 불필요 사용자 ─────────────────────────
try {
    Evd "SRV-073" "net localgroup Administrators 2>`$null"
    $members073 = @(Get-LocalGroupMemberNames 'S-1-5-32-544'); $started073 = $false
    if ($members073.Count -eq 0) { foreach ($line in (net localgroup Administrators 2>$null)) {
        if ($line -match "^---") { $started073 = $true; continue }
        if ($started073 -and $line.Trim() -ne "" -and $line -notmatch "^The command|^명령을") {
            $members073 += $line.Trim()
        }
    } }
    # 평가기준: '불필요한' 관리자 계정 여부 (인원 수 기준 없음) → 구성원 목록 + 인터뷰
    $cnt = $members073.Count
    MC "SRV-073" "Administrators 구성원(${cnt}명): $($members073 -join ', ') - 불필요 계정 여부 확인"
} catch { MC "SRV-073" "관리자 그룹 멤버 수동 확인" }

# ── SRV-075: 패스워드 복잡도 ───────────────────────────────────
Evd "SRV-075" "net accounts 2>`$null | Select-String 'complexity|복잡'"
$pwc = Get-SecPol "PasswordComplexity"
$minLen = Get-SecPol "MinimumPasswordLength"
# 평가기준: 모든 계정 비밀번호가 복잡도(2종 10자 / 3종 8자) 만족 — 실제 만족 여부는 크랙 시도 필요
if ($null -ne $pwc -and $pwc.Trim() -eq "0") { Fail "SRV-075" "비밀번호 복잡도 정책 비활성 (PasswordComplexity=0)" }
elseif ($null -ne $minLen -and [int]$minLen -lt 8) { Fail "SRV-075" "최소 비밀번호 길이=${minLen}자 (8자 미만)" }
elseif ($null -ne $pwc) { MC "SRV-075" "복잡도 정책 활성, 최소 길이=${minLen}자 - 기존 계정 비밀번호 복잡도 만족 여부(크랙 시도) 확인" }
else { MC "SRV-075" "복잡도 정책 확인 실패 (관리자 권한 필요) - 수동 확인" }

# ── SRV-078: Guest 계정 비활성화 ───────────────────────────────
$g078  = $accts | Where-Object { $_.SID -match '-501$' } | Select-Object -First 1
$eg078 = Get-SecPol "EnableGuestAccount"; $ng078 = "$(Get-SecPol 'NewGuestName')".Trim().Trim('"')
EvdQ "SRV-078" "Guest(SID-501) / secedit EnableGuestAccount / NewGuestName" "$(if ($g078) { "$($g078.Name) Enabled=$($g078.Enabled) [$($g078.Src)]" } else { '계정 조회 실패' }) / $eg078 / $ng078"
if ($g078) { if ($g078.Enabled) { Fail "SRV-078" "Guest 계정(SID-501, 이름 $($g078.Name)) 활성화" } else { Pass "SRV-078" "Guest 계정(이름 $($g078.Name)) 비활성화" } }
elseif ("$eg078".Trim() -eq "1") { Fail "SRV-078" "Guest 계정 활성화 (secedit EnableGuestAccount=1)" }
elseif ("$eg078".Trim() -eq "0") { Pass "SRV-078" "Guest 계정 비활성화 (secedit EnableGuestAccount=0)" }
else { MC "SRV-078" "Guest 계정 상태 확인 실패 - net user guest 로 확인" }

# ── SRV-079: Everyone 부적절 권한 ──────────────────────────────
Evd "SRV-079" "Get-SmbShare -EA SilentlyContinue | ForEach-Object { Get-SmbShareAccess -Name `$_.Name -EA SilentlyContinue | Where-Object {`$_.AccountName -match 'Everyone' -and `$_.AccessRight -eq 'Full'} }"
$evShare = $false
try {
    Get-SmbShare -EA Stop | Where-Object {$_.Name -notmatch "^IPC\$"} | ForEach-Object {
        $acl = Get-SmbShareAccess -Name $_.Name -EA SilentlyContinue
        if ($acl | Where-Object {$_.AccountName -match "Everyone" -and $_.AccessRight -eq "Full"}) { $evShare = $true }
    }
} catch {}
# 판단기준: 'Everyone 사용 권한을 익명 사용자에게 적용' 정책(Lsa\EveryoneIncludesAnonymous) 0=양호 (공유 ACL은 참고 증적)
$eia = Get-Reg "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "EveryoneIncludesAnonymous"
EvdQ "SRV-079" "Lsa EveryoneIncludesAnonymous (공유 Everyone Full: $evShare)" "$eia"
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
if (-not $acl084) { MC "SRV-084" "SAM ACL 조회 실패 - icacls 증적으로 SYSTEM·Administrators 외 권한 확인" }
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
Evd "SRV-090" "Get-Service RemoteRegistry -EA SilentlyContinue | Select-Object Status,StartType"
$rr = Get-SvcState "RemoteRegistry"
if ($null -eq $rr) { Pass "SRV-090" "RemoteRegistry 서비스 없음" }
elseif ($rr.Status -match "Running") { Fail "SRV-090" "원격 레지스트리 서비스 실행 중" }
elseif ($rr.Start -match "Disabled") { Pass "SRV-090" "원격 레지스트리 비활성화 (Disabled)" }
else { Pass "SRV-090" "원격 레지스트리 중지됨 ($($rr.Start))" }

# ── SRV-092: 사용자 홈 디렉토리 권한 ───────────────────────────
# 판단기준: 사용자별 홈 디렉터리에 Everyone 권한이 없는 경우 양호 (All Users, Default User 제외)
$hr092 = "$env:SystemDrive\Users"; if (-not (Test-Path $hr092)) { $hr092 = "$env:SystemDrive\Documents and Settings" }
$hd092 = @(Get-ChildItem $hr092 -EA SilentlyContinue | Where-Object { $_.PSIsContainer -and $_.Name -notmatch '^(All Users|Default|Default User)$' })
Evd "SRV-092" "Get-ChildItem '$hr092' -EA SilentlyContinue | Where-Object { `$_.PSIsContainer } | ForEach-Object { icacls `$_.FullName }"
$ev092 = @()
foreach ($d in $hd092) {
    $acl = Get-Acl $d.FullName -EA SilentlyContinue; if (-not $acl) { continue }
    foreach ($ace in $acl.Access) { if ("$($ace.AccessControlType)" -eq 'Allow' -and (Get-AceSid $ace) -eq 'S-1-1-0') { $ev092 += "$($d.Name)($($ace.FileSystemRights))" } }
}
if ($hd092.Count -eq 0) { MC "SRV-092" "홈 디렉터리 조회 실패 - 수동 확인" }
elseif ($ev092.Count) { Fail "SRV-092" "홈 디렉터리 Everyone 권한: $($ev092 -join ', ')" }
else { Pass "SRV-092" "사용자 홈 디렉터리 $($hd092.Count)개 Everyone 권한 없음" }

# ── SRV-097: FTP 디렉토리 접근권한 ─────────────────────────────
# 판단기준: FTP 홈 디렉터리에 Everyone 권한 등 불필요한 권한이 없는 경우 양호
$ftp97 = Get-SvcState "FTPSVC"; if (-not $ftp97) { $ftp97 = Get-SvcState "MSFTPSVC" }
$ftp97Run = ($ftp97 -and $ftp97.Status -eq "Running") -or (Get-NetTCPConnection -LocalPort 21 -State Listen -EA SilentlyContinue)
$root097 = @($ftpSites | Where-Object { $_.Root } | ForEach-Object { $_.Root } | Select-Object -Unique)
foreach ($r in $root097) { Evd "SRV-097" "icacls '$r'" }
$ev097 = @()
foreach ($r in $root097) {
    $acl = Get-Acl $r -EA SilentlyContinue; if (-not $acl) { continue }
    foreach ($ace in $acl.Access) { if ("$($ace.AccessControlType)" -eq 'Allow' -and (Get-AceSid $ace) -eq 'S-1-1-0') { $ev097 += "$r(Everyone:$($ace.FileSystemRights))" } }
}
if (-not $ftp97Run) { NA "SRV-097" "FTP 서비스 미실행" }
elseif ($root097.Count -eq 0) { MC "SRV-097" "FTP 서비스 실행 중 - FTP 홈 디렉터리 미탐지(IIS 외 FTP) 접근 권한 수동 확인" }
elseif ($ev097.Count) { Fail "SRV-097" "FTP 홈 디렉터리 Everyone 권한: $($ev097 -join ', ')" }
else { Pass "SRV-097" "FTP 홈 디렉터리 Everyone 권한 없음: $($root097 -join ', ')" }

# ── SRV-101: 불필요 예약 작업 ───────────────────────────────────
if (Get-Command Get-ScheduledTask -EA SilentlyContinue) {
    Evd "SRV-101" "Get-ScheduledTask | Where-Object { `$_.TaskPath -notlike '\Microsoft\*' } | Select-Object TaskPath,TaskName,State,@{n='Run';e={(`$_.Actions | ForEach-Object { `"`$(`$_.Execute) `$(`$_.Arguments)`" }) -join '; '}},@{n='User';e={`$_.Principal.UserId}} | Format-Table -AutoSize -Wrap"
} else { Evd "SRV-101" "schtasks /query /fo LIST /v" }
MC "SRV-101" "예약 작업(Microsoft 기본 작업 제외) 증적 확인 - 불필요 명령/파일 여부 판단"

# ── SRV-103: LAN Manager 인증 수준 ─────────────────────────────
Evd "SRV-103" "Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name LmCompatibilityLevel -EA SilentlyContinue | Select-Object LmCompatibilityLevel"
$lm = Get-Reg "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "LmCompatibilityLevel"
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
$inDomain = (Get-CimInstance Win32_ComputerSystem -EA SilentlyContinue).PartOfDomain
if ($sc1 -eq 1 -and $sc2 -eq 1 -and $sc3 -eq 1) { Pass "SRV-104" "보안 채널 서명/암호화 필수 설정됨 (RequireSignOrSeal/SealSecureChannel/SignSecureChannel=1)" }
elseif ($null -ne $inDomain -and -not $inDomain) { Pass "SRV-104" "AD 도메인 미가입 서버 (평가기준상 AD 환경 아님 양호) - RequireSignOrSeal=$sc1, SealSecureChannel=$sc2, SignSecureChannel=$sc3" }
else { Fail "SRV-104" "보안 채널 서명/암호화 미설정 (RequireSignOrSeal=$sc1, SealSecureChannel=$sc2, SignSecureChannel=$sc3)" }

# ── SRV-105: 불필요 시작 프로그램 ──────────────────────────────
Evd "SRV-105" "foreach (`$k in 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run','HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce','HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run','HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run') { `"# `$k`"; (Get-ItemProperty `$k -EA SilentlyContinue).PSObject.Properties | Where-Object { @('PSPath','PSParentPath','PSChildName','PSDrive','PSProvider') -notcontains `$_.Name } | ForEach-Object { `"  `$(`$_.Name) = `$(`$_.Value)`" } }; Get-ChildItem `"`$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp`" -Force -EA SilentlyContinue | Select-Object Name"
MC "SRV-105" "시작 프로그램 목록(증적) 수동 확인 - 불필요 프로그램 여부 판단"

# ── SRV-108: 로그 접근통제 ──────────────────────────────────────
# 판단기준: Guest 접근(RestrictGuestAccess=0), 감사 및 보안 로그 관리(SeSecurityPrivilege)에 Everyone/Users, 로그 크기 10240KB 미만 → 취약
$bad108 = @(); $unk108 = @(); $inf108 = @()
foreach ($ln in 'Application','Security','System') {
    $svc = "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\$ln"; $pol = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\$ln"
    $rga = Get-Reg $svc 'RestrictGuestAccess'
    $mxK = Get-Reg $pol 'MaxSize'   # 그룹 정책: KB 단위(우선)
    $mxB = if ($null -ne $mxK) { [int64]$mxK * 1KB } else { Get-Reg $svc 'MaxSize' }
    $inf108 += "$ln RestrictGuestAccess=$rga MaxSize=$(if ($null -ne $mxB) { '{0}KB' -f [int64]($mxB/1KB) } else { '?' })$(if ($null -ne $mxK) { '(정책)' })"
    if ("$rga" -eq '0') { $bad108 += "$ln Guest 접근 허용" } elseif ($null -eq $rga) { $unk108 += "$ln RestrictGuestAccess 없음" }
    if ($null -eq $mxB) { $unk108 += "$ln MaxSize 없음" } elseif ([int64]$mxB -lt 10240KB) { $bad108 += "$ln 로그 크기 $([int64]($mxB/1KB))KB(<10240KB)" }
}
$sp108 = Test-SecPolGroups "SeSecurityPrivilege" @("Everyone","Users")
if ($sp108[1].Count) { $bad108 += "감사 및 보안 로그 관리 권한에 $($sp108[1] -join ',')" } elseif ($null -eq $sp108[0]) { $unk108 += "SeSecurityPrivilege 확인 실패" }
EvdQ "SRV-108" "EventLog RestrictGuestAccess/MaxSize, secedit SeSecurityPrivilege" "$($inf108 -join "`n")`nSeSecurityPrivilege = $($sp108[0])"
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
if ($auditNull -eq $auditKeys.Count) { MC "SRV-109" "감사 정책 확인 실패 (관리자 권한 필요) - secpol.msc 감사 정책 수동 확인" }
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
$hotfix = Get-HotFix -EA SilentlyContinue | Sort-Object InstalledOn -Descending | Select-Object -First 1
if ($hotfix) { MC "SRV-118" "최근 핫픽스: $($hotfix.HotFixID) ($($hotfix.InstalledOn))" }
else { MC "SRV-118" "보안패치 현황 수동 확인" }

# ── SRV-119: 백신 업데이트 ─────────────────────────────────────
# 백신 공통 수집: 실행 중 서비스(서비스 이름/표시명) + 설치 목록 + Defender 상태 (SecurityCenter2 는 클라이언트 SKU 전용)
$avKw  = '(?i)(microsoft|windows) defender|\bV3\b|ahnlab|alyac|virobot|hauri|sophos|symantec|endpoint protection|mcafee|trellix|trend ?micro|apex ?one|kaspersky|eset|bitdefender|avast|avira|cylance|crowdstrike|falcon|sentinel ?one|antivirus|anti-?malware|백신'
$avSvc = @(Get-Service -EA SilentlyContinue | Where-Object { "$($_.Status)" -eq 'Running' -and ($_.Name -match '^(WinDefend|WdNisSvc)$' -or ($_.DisplayName -match $avKw -and $_.DisplayName -notmatch '(?i)firewall|방화벽')) })
$mp    = if (Get-Command Get-MpComputerStatus -EA SilentlyContinue) { Get-MpComputerStatus -EA SilentlyContinue } else { $null }
$avUn  = @(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' -EA SilentlyContinue | Where-Object { $_.DisplayName -match $avKw } | ForEach-Object { "$($_.DisplayName) $($_.DisplayVersion)" })
$avSc  = @(Get-CimInstance -Namespace "root/SecurityCenter2" -ClassName AntiVirusProduct -EA SilentlyContinue)
EvdQ "SRV-119" "Defender 상태 (Get-MpComputerStatus)" $(if ($mp) { "AMServiceEnabled=$($mp.AMServiceEnabled) AntivirusEnabled=$($mp.AntivirusEnabled) RealTime=$($mp.RealTimeProtectionEnabled) SignatureVersion=$($mp.AntivirusSignatureVersion) SignatureLastUpdated=$($mp.AntivirusSignatureLastUpdated) EngineVersion=$($mp.AMEngineVersion)" } else { 'Get-MpComputerStatus 없음' })
EvdQ "SRV-119" "SecurityCenter2 AntiVirusProduct / 설치 목록" "$(($avSc | ForEach-Object { $_.displayName }) -join ', ') / $($avUn -join ', ')"
MC "SRV-119" "백신 업데이트 주기 확인 (엔진/패턴 버전·업데이트 절차)$(if ($mp) { " - Defender 서명 갱신: $($mp.AntivirusSignatureLastUpdated)" })"

# ── SRV-123: 최종 로그인 사용자 계정 노출 방지 ──────────────────
Evd "SRV-123" "Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System','HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name DontDisplayLastUserName -EA SilentlyContinue | Select-Object PSPath,DontDisplayLastUserName"
# 판단방법: Policies\System\DontDisplayLastUserName (1: 양호, 0: 취약), 구버전 Winlogon 경로 보조
$hideUser = Get-Reg "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "DontDisplayLastUserName"
if ($null -eq $hideUser) { $hideUser = Get-Reg "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" "DontDisplayLastUserName" }
if ($null -ne $hideUser -and $hideUser -eq 1) { Pass "SRV-123" "로그인 화면 마지막 사용자 표시 안 함 (DontDisplayLastUserName=1)" }
else { Fail "SRV-123" "로그인 화면에 마지막 사용자 계정 표시됨 (DontDisplayLastUserName=$(if ($null -eq $hideUser) { '미설정' } else { $hideUser }))" }

# ── SRV-125: 화면 보호기 ────────────────────────────────────────
# SRV-028에서 이미 확인됨
Evd "SRV-125" "Get-ItemProperty 'HKCU:\Control Panel\Desktop' -Name ScreenSaveActive,ScreenSaveTimeOut,ScreenSaverIsSecure -EA SilentlyContinue; Get-ItemProperty 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop' -EA SilentlyContinue"
$pol = "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop"; $usr = "HKCU:\Control Panel\Desktop"
$ssA = Get-Reg $pol "ScreenSaveActive";   if ($null -eq $ssA) { $ssA = Get-Reg $usr "ScreenSaveActive" }
$ssT = Get-Reg $pol "ScreenSaveTimeOut";  if ($null -eq $ssT) { $ssT = Get-Reg $usr "ScreenSaveTimeOut" }
$ssS = Get-Reg $pol "ScreenSaverIsSecure"; if ($null -eq $ssS) { $ssS = Get-Reg $usr "ScreenSaverIsSecure" }
if ("$ssA" -eq "1" -and "$ssS" -eq "1" -and $ssT -and [int]$ssT -gt 0) { Pass "SRV-125" "화면보호기 사용·자동 시작(${ssT}초)·암호 설정" }
else { Fail "SRV-125" "화면보호기 설정 미흡 (ScreenSaveActive=$ssA, ScreenSaveTimeOut=$ssT, ScreenSaverIsSecure=$ssS; 기준: 사용=1, 시작 시간 설정, 암호=1)" }

# ── SRV-126: 자동 로그온 방지 ───────────────────────────────────
Evd "SRV-126" "Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name AutoAdminLogon,DefaultUserName -EA SilentlyContinue | Select-Object AutoAdminLogon,DefaultUserName"
$dp126 = Get-Reg "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" "DefaultPassword"
EvdQ "SRV-126" "Winlogon DefaultPassword (값 마스킹)" $(if ($null -eq $dp126) { '없음' } else { "존재 (길이 $("$dp126".Length))" })
$autoLogon = Get-Reg "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" "AutoAdminLogon"
if ($null -ne $autoLogon -and $autoLogon -eq "1") { Fail "SRV-126" "자동 로그온 활성화됨 (AutoAdminLogon=1)" }
else { Pass "SRV-126" "자동 로그온 비활성화됨" }

# ── SRV-127: 로그인 실패 횟수 제한 ─────────────────────────────
Evd "SRV-127" "net accounts 2>`$null | Select-String 'Lockout|잠금'"
$lockout = Get-SecPol "LockoutBadCount"
if ($null -eq $lockout) {
    $netOut = net accounts 2>$null
    $line   = $netOut | Where-Object {$_ -match "Lockout threshold|잠금 임계"}
    if ($line) { $lockout = ($line -replace "[^0-9]","").Trim() }
}
if ($null -ne $lockout -and $lockout -match "^\d+$") {
    $cnt = [int]$lockout
    if ($cnt -eq 0) { Fail "SRV-127" "계정 잠금 임계값=0 (무제한)" }
    elseif ($cnt -le 5) { Pass "SRV-127" "계정 잠금 임계값=${cnt}회 설정" }
    else { Pass "SRV-127" "계정 잠금 임계값=${cnt}회 설정 (5회 초과 - 내부 규정 기준 확인)" }
} else { MC "SRV-127" "계정 잠금 임계값 확인 실패" }

# ── SRV-128: NTFS 파일 시스템 ───────────────────────────────────
Evd "SRV-128" "Get-Volume -EA SilentlyContinue | Where-Object { `$_.DriveType -eq 'Fixed' -and `$_.DriveLetter } | Select-Object DriveLetter,FileSystemType | Format-Table"
$fixedVols = Get-Volume -EA SilentlyContinue | Where-Object { $_.DriveType -eq "Fixed" -and $_.DriveLetter }
if ($fixedVols) {
    $fat = @($fixedVols | Where-Object { "$($_.FileSystemType)" -match '^(FAT|FAT16|FAT32|exFAT)$' })
    $odd = @($fixedVols | Where-Object { "$($_.FileSystemType)" -notmatch '^(NTFS|ReFS|CSVFS|FAT|FAT16|FAT32|exFAT)$' })
    if ($fat.Count) { Fail "SRV-128" "FAT 파일 시스템 로컬 드라이브: $(($fat | ForEach-Object { "$($_.DriveLetter):($($_.FileSystemType))" }) -join ',')" }
    elseif ($odd.Count) { MC "SRV-128" "파일 시스템 확인 필요: $(($odd | ForEach-Object { "$($_.DriveLetter):($($_.FileSystemType))" }) -join ',')" }
    else { Pass "SRV-128" "로컬 드라이브 FAT 미사용 (NTFS/ReFS/CSVFS)" }
} else {
    # Get-Volume 실패 시 CimInstance 폴백
    $cimDrives = Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" -EA SilentlyContinue
    $nonNtfs2  = @($cimDrives | Where-Object { "$($_.FileSystem)" -match '^(FAT|FAT16|FAT32|exFAT)$' })
    if ($nonNtfs2.Count) { Fail "SRV-128" "FAT 파일 시스템 로컬 드라이브: $(($nonNtfs2 | ForEach-Object { "$($_.DeviceID)($($_.FileSystem))" }) -join ',')" }
    elseif ($cimDrives) { Pass "SRV-128" "로컬 드라이브 FAT 미사용" }
    else { MC "SRV-128" "드라이브 파일 시스템 확인 실패 - 수동 확인" }
}

# ── SRV-129: 백신 설치 ──────────────────────────────────────────
# SRV-119와 동일 (별도 메시지)
EvdQ "SRV-129" "실행 중 백신 서비스 / 설치 목록" "$(($avSvc | ForEach-Object { "$($_.Name)($($_.DisplayName))" }) -join ', ') / $($avUn -join ', ')"
if ($avSvc.Count) { Pass "SRV-129" "백신 실행 중: $(($avSvc | ForEach-Object { $_.DisplayName }) -join ', ')" }
elseif ($avSc.Count) { Pass "SRV-129" "백신 설치됨: $(($avSc | Select-Object -First 1).displayName)" }
else { MC "SRV-129" "백신 서비스 미탐지 - 설치 프로그램 목록(증적)·tasklist 로 백신 설치 여부 확인" }

# ── SRV-135: TCP 보안 설정 ──────────────────────────────────────
Evd "SRV-135" "Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' -Name SynAttackProtect,TcpMaxHalfOpen,TcpMaxHalfOpenRetried,DeadGWDetectDefault,IPEnableRouter -EA SilentlyContinue"
# 판단기준: [2008 이상] IPEnableRouter=0 / [2008 미만] SynAttackProtect=1, TcpMaxHalfOpen≤0x500, TcpMaxHalfOpenRetried≤0x400, DeadGWDetectDefault=1, IPEnableRouter=0
$tcpP = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
$ipr = Get-Reg $tcpP "IPEnableRouter"
if ($build -ge 6001) {
    if ($null -eq $ipr -or "$ipr" -eq "0") { Pass "SRV-135" "IPEnableRouter=$(if ($null -eq $ipr) { '기본값 0' } else { 0 }) (Windows 2008 이상 기준)" }
    else { Fail "SRV-135" "IPEnableRouter=$ipr (IP 라우팅 활성 - 0 필요)" }
} else {
    $syn = Get-Reg $tcpP "SynAttackProtect"; $tho = Get-Reg $tcpP "TcpMaxHalfOpen"; $thr = Get-Reg $tcpP "TcpMaxHalfOpenRetried"; $dgw = Get-Reg $tcpP "DeadGWDetectDefault"
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
elseif ($null -eq $rs[0]) { MC "SRV-136" "로그온 전 종료 사용 안 함 (ShutdownWithoutLogon=0) - 원격 강제 종료 권한 확인 실패(관리자 권한 필요)" }
else { Pass "SRV-136" "로그온 전 종료 사용 안 함 (ShutdownWithoutLogon=0), 원격 강제 종료 권한 불필요 그룹 없음" }

# ── SRV-140: 이동식 미디어 제한 ─────────────────────────────────
Evd "SRV-140" "Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name AllocateDASD -EA SilentlyContinue | Select-Object AllocateDASD"
# 판단기준: '이동식 미디어 포맷 및 꺼내기 허용' = Administrators(AllocateDASD 0) 이면 양호 — 값 없음(정책 미정의)은 OS 기본 Administrators
$dasd = Get-Reg "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" "AllocateDASD"
if ($null -eq $dasd -or "$dasd" -eq "" -or "$dasd" -eq "0") { Pass "SRV-140" "이동식 미디어 포맷 및 꺼내기 허용: Administrators (AllocateDASD=$(if ($null -eq $dasd -or "$dasd" -eq '') { '미정의(기본 Administrators)' } else { 0 }))" }
else { Fail "SRV-140" "이동식 미디어 포맷 및 꺼내기 허용이 Administrators 외 사용자에게 허용 (AllocateDASD=$dasd)" }

# ── SRV-149: 디스크 볼륨 암호화 ────────────────────────────────
try {
    Evd "SRV-149" "Get-BitLockerVolume -EA SilentlyContinue | Select-Object MountPoint,ProtectionStatus | Format-Table"
    $bl = Get-BitLockerVolume -EA Stop
    $protected = $bl | Where-Object {$_.ProtectionStatus -eq "On"}
    if ($protected) { Pass "SRV-149" "BitLocker 암호화 볼륨: $(($protected | ForEach-Object { $_.MountPoint }) -join ',')" }
    else { MC "SRV-149" "BitLocker 미적용 - 예외(IDC 등 물리적 보호 장소, 디스크 폐기 규정 수행) 해당 여부 확인, 미해당 시 취약" }
} catch { Evd "SRV-149" "manage-bde -status 2>&1"; MC "SRV-149" "디스크 암호화 상태 수동 확인 (BitLocker 또는 TDE)" }

# ── SRV-150: 로컬 로그온 허용 계정 제한 ─────────────────────────
# 판단기준: 로컬 로그온 허용 정책에 Administrators, IUSR_ 만 존재하면 양호
$v150 = Get-SecPol "SeInteractiveLogonRight"
if ($null -eq $v150) { MC "SRV-150" "로컬 로그온 허용 정책 확인 실패(관리자 권한 필요) - secpol.msc 확인" }
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
if ($null -eq $sidEnum) { MC "SRV-151" "익명 SID/이름 변환 허용 정책 확인 실패 (관리자 권한 필요) - secpol.msc 수동 확인" }
elseif ("$sidEnum".Trim() -eq "0") { Pass "SRV-151" "익명 SID/이름 변환 허용 사용 안 함 (LSAAnonymousNameLookup=0)" }
else { Fail "SRV-151" "익명 SID/이름 변환 허용 사용 (LSAAnonymousNameLookup=$sidEnum)" }

# ── SRV-152: 원격 터미널 접속 그룹 제한 ────────────────────────
# 판단기준: 관리자 외 원격 접속 전용 계정이 있고 원격 접속 그룹에 불필요한 계정이 없으면 양호 / 별도 계정 없으면 취약
$deny152 = Get-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' 'fDenyTSConnections'
if ($null -eq $deny152) { $deny152 = Get-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' 'fDenyTSConnections' }
$rdu152 = Get-LocalGroupMemberNames 'S-1-5-32-555'
$rir152 = Get-SecPol 'SeRemoteInteractiveLogonRight'
EvdQ "SRV-152" "fDenyTSConnections / Remote Desktop Users(S-1-5-32-555) / SeRemoteInteractiveLogonRight" "$deny152 / $(if ($null -eq $rdu152) { '조회 실패' } else { $rdu152 -join ', ' }) / $rir152 → $((($rir152 -split ',') | Where-Object { $_ } | ForEach-Object { Resolve-SecPolEntry $_ }) -join ', ')"
if ("$deny152" -eq '1') { Pass "SRV-152" "원격 터미널 서비스 미사용 (fDenyTSConnections=1)" }
elseif ($null -eq $rdu152) { MC "SRV-152" "Remote Desktop Users 구성원 조회 실패 - 원격 접속 계정 수동 확인" }
elseif ($rdu152.Count -eq 0) { Fail "SRV-152" "관리자 외 원격 접속 전용 계정 없음 (Remote Desktop Users 비어 있음)" }
else { MC "SRV-152" "Remote Desktop Users: $($rdu152 -join ', ') - 불필요 계정 여부 확인" }

# ── SRV-158: Telnet 서비스 비활성화 ─────────────────────────────
# SRV-035와 동일
Evd "SRV-158" "Get-Service TlntSvr -EA SilentlyContinue | Select-Object Status,StartType; Get-NetTCPConnection -LocalPort 23 -State Listen -EA SilentlyContinue | Select-Object LocalAddress,OwningProcess; netstat -an | Select-String ':23\s.*LISTEN'"
$t = Get-SvcState "TlntSvr"
$l23 = @(Get-NetTCPConnection -LocalPort 23 -State Listen -EA SilentlyContinue)
if ($l23.Count -eq 0 -and -not (Get-Command Get-NetTCPConnection -EA SilentlyContinue)) { $l23 = @(netstat -an 2>$null | Where-Object { $_ -match '^\s*TCP\s+\S+:23\s+\S+\s+LISTEN' }) }
if (($t -and $t.Status -match "Running") -or $l23.Count) { Fail "SRV-158" "Telnet 서비스 동작 중 (TlntSvr/23번 포트)" }
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
Evd "SRV-172" "Get-SmbShare -EA SilentlyContinue | Select-Object Name,Path | Format-Table"
# 판단기준: 공유폴더가 없거나 업무상 필요한 공유만 존재 — 기본 관리 공유(드라이브$·ADMIN$·IPC$·print$·SYSVOL·NETLOGON)는 SRV-018에서 판정
$vuln2 = @(); $shareOk = $true
try {
    Get-SmbShare -EA Stop | Where-Object {$_.Name -notmatch '^([A-Za-z]|ADMIN|IPC|print)\$$' -and $_.Name -notmatch '^(SYSVOL|NETLOGON)$'} | ForEach-Object { $vuln2 += "$($_.Name)($($_.Path))" }
} catch { $shareOk = $false }
if (-not $shareOk) { MC "SRV-172" "공유 목록 조회 실패 - net share 결과로 불필요 공유 수동 확인" }
elseif ($vuln2) { MC "SRV-172" "사용자 공유 $($vuln2.Count)개: $($vuln2 -join ', ') - 업무상 필요 여부 확인 (불필요 시 취약)" }
else { Pass "SRV-172" "기본 관리 공유 외 공유폴더 없음" }

# ── SRV-175: NTP 동기화 ─────────────────────────────────────────
try {
    Evd "SRV-175" "w32tm /query /status 2>`$null; w32tm /query /configuration 2>`$null | Select-String 'NtpServer|Type'"
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
} catch { MC "SRV-175" "NTP 상태 수동 확인 (w32tm /query /status)" }

# ── SRV-178: 개인키 passphrase ──────────────────────────────────
# 판단방법: ssh-keygen -y -f [키] 실행 시 passphrase 입력 없이 공개키가 출력되면 미설정 (호스트 키는 sshd 용이라 증적만)
$kg178 = Get-Command ssh-keygen.exe -EA SilentlyContinue | Select-Object -First 1
$k178  = @(Get-ChildItem "$env:SystemDrive\Users\*\.ssh\*" -Force -EA SilentlyContinue | Where-Object { -not $_.PSIsContainer -and $_.Name -notmatch '\.pub$|^known_hosts|^authorized_keys|^config$' } |
          Where-Object { (Get-Content $_.FullName -TotalCount 1 -EA SilentlyContinue) -match 'PRIVATE KEY|^PuTTY-User-Key-File' })
$np178 = @(); $pp178 = @(); $uk178 = @()
foreach ($k in $k178) {
    $h = @(Get-Content $k.FullName -TotalCount 3 -EA SilentlyContinue)
    if ($h[0] -match '^PuTTY') { if (($h -join "`n") -match 'Encryption:\s*none') { $np178 += $k.FullName } else { $pp178 += $k.FullName }; continue }
    if (-not $kg178) { $uk178 += $k.FullName; continue }
    $o = "$env:TEMP\kg_$PID.txt"
    try {
        $pr = Start-Process -FilePath $kg178.Path -ArgumentList "-y -P `"`" -f `"$($k.FullName)`"" -NoNewWindow -Wait -PassThru -RedirectStandardOutput $o -RedirectStandardError "$o.err"
        if ($pr.ExitCode -eq 0) { $np178 += $k.FullName } else { $pp178 += $k.FullName }
    } catch { $uk178 += $k.FullName }
    Remove-Item $o,"$o.err" -EA SilentlyContinue
}
EvdQ "SRV-178" "사용자 개인 키 (passphrase 없음 / 있음 / 판정 불가) + 호스트 키 목록" "$($np178 -join ', ') / $($pp178 -join ', ') / $($uk178 -join ', ')`n호스트 키: $((Get-ChildItem "$env:ProgramData\ssh\ssh_host_*_key" -EA SilentlyContinue | ForEach-Object { $_.Name }) -join ', ')"
if ($np178.Count) { Fail "SRV-178" "passphrase 미설정 개인 키: $($np178 -join ', ')" }
elseif ($uk178.Count) { MC "SRV-178" "개인 키 존재, ssh-keygen 없음 - passphrase 수동 확인: $($uk178 -join ', ')" }
elseif ($pp178.Count) { Pass "SRV-178" "개인 키 $($pp178.Count)개 passphrase 설정" }
else { NA "SRV-178" "사용자 SSH 개인 키 없음 (개인 키 미사용)" }

# ── SRV-179: EoS 시스템 교체 ────────────────────────────────────
Evd "SRV-179" "Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -EA SilentlyContinue | Select-Object ProductName,EditionID,InstallationType,CurrentBuild,UBR,DisplayVersion,ReleaseId | Format-List; Get-CimInstance Win32_OperatingSystem -EA SilentlyContinue | Select-Object Caption,Version,OSArchitecture | Format-List"
MC "SRV-179" "Windows 버전 지원 종료 여부 수동 확인 (Microsoft 제품 수명 주기 페이지 참조)"

# ── SRV-062/063/064/066: DNS 서버 점검 ─────────────────────────
Evd "SRV-062" "Get-Service DNS -EA SilentlyContinue | Select-Object Status,StartType"
$dnsSvc = Get-SvcState "DNS"
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
    if ("$nr063" -eq '1' -or ($rec063 -and -not $rec063.Enable)) { Pass "SRV-063" "Recursive Query 비활성 (NoRecursion=1)" }
    else { MC "SRV-063" "Recursive Query 허용 (NoRecursion=$(if ($null -eq $nr063) { '없음' } else { $nr063 })) - 신뢰 호스트(재귀 범위·쿼리 정책) 또는 방화벽 통제 여부 확인, 없으면 취약" }
    MC "SRV-064" "Windows DNS Server 실행 중 - 최신 보안 패치 적용 여부 수동 확인"
    # SRV-066 판단방법: 각 zone SecureSecondaries (0=아무 서버 취약, 1=확인 필요, 2·3 양호)
    $z066 = @(Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\DNS Server\Zones' -EA SilentlyContinue)
    $any066 = @(); $ns066 = @(); $ok066 = @(); $inf066 = @()
    foreach ($z in $z066) {
        $p = Get-ItemProperty $z.PSPath -EA SilentlyContinue; $ss = $p.SecureSecondaries; $n = $z.PSChildName
        $inf066 += "$n SecureSecondaries=$ss SecondaryServers=$(@($p.SecondaryServers) -join ' ')"
        switch ("$ss") { '0' { $any066 += $n } '1' { $ns066 += $n } '2' { $ok066 += "$n(지정 서버)" } '3' { $ok066 += "$n(전송 안 함)" } default { $ns066 += "$n(값 없음)" } }
    }
    EvdQ "SRV-066" "DNS Server\Zones SecureSecondaries (0=모든 서버, 1=이름 서버 탭, 2=지정 서버, 3=전송 안 함)" ($inf066 -join "`n")
    if ($z066.Count -eq 0) { MC "SRV-066" "DNS 영역 레지스트리 조회 실패 - DNS 관리자 영역 전송 설정 확인" }
    elseif ($any066.Count) { Fail "SRV-066" "영역 전송 아무 서버로나 허용(SecureSecondaries=0): $($any066 -join ', ')" }
    elseif ($ns066.Count) { MC "SRV-066" "이름 서버 탭 서버로 전송(SecureSecondaries=1, 평가기준 '확인 필요'): $($ns066 -join ', ')" }
    else { Pass "SRV-066" "영역 전송 차단 또는 지정 서버만: $($ok066 -join ', ')" }
}

# ── 평가기준 [서버] WIN 평가대상 중 기존 미점검/오분류 항목 (판단기준·판단방법 기준) ──


# SRV-003: 네트워크 모니터링 서비스 접근통제 (SNMP PermittedManagers)
Evd "SRV-003" "Get-Service SNMP -EA SilentlyContinue | Select-Object Status; Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\PermittedManagers' -EA SilentlyContinue"
Evd "SRV-003" "Get-NetFirewallRule -Name 'WMI-*' -EA SilentlyContinue | Select-Object Name,Enabled,Direction,Action,@{n='Remote';e={(`$_ | Get-NetFirewallAddressFilter).RemoteAddress}} | Format-Table -AutoSize"
$snmp = Get-SvcState "SNMP"
if ($otherSnmp) { MC "SRV-003" "타사 SNMP 에이전트 실행($($snmpPaths -join ', ')) - snmpd.conf 출발지(com2sec source 등) 제한 확인" }
elseif (-not $snmp -or $snmp.Status -ne "Running") { NA "SRV-003" "SNMP 서비스 미실행" }
else {
    $pm = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\PermittedManagers' -EA SilentlyContinue
    $hosts = @(); if ($pm) { $hosts = @($pm.PSObject.Properties | Where-Object { $_.Name -match '^\d+$' } | ForEach-Object { $_.Value }) }
    if ($hosts.Count -gt 0) { Pass "SRV-003" "SNMP 패킷 허용 호스트 지정됨: $($hosts -join ',')" }
    else { Fail "SRV-003" "SNMP PermittedManagers 미설정 (모든 호스트에서 SNMP 패킷 수신)" }
}

# SRV-004: 불필요한 SMTP 서비스 (25번 포트)
Evd "SRV-004" "Get-Service SMTPSVC -EA SilentlyContinue | Select-Object Status; Get-NetTCPConnection -LocalPort 25 -State Listen -EA SilentlyContinue"
$smtp = Get-SvcState "SMTPSVC"
$l25 = Get-NetTCPConnection -LocalPort 25 -State Listen -EA SilentlyContinue
if (($smtp -and $smtp.Status -eq "Running") -or $l25) { MC "SRV-004" "SMTP 서비스 동작 중 (25번 포트) - 업무상 필요 여부 확인" }
else { Pass "SRV-004" "SMTP 서비스 미동작 (25번 포트 리슨 없음)" }

# FTP 공통
$ftpSvc = Get-SvcState "FTPSVC"; if (-not $ftpSvc) { $ftpSvc = Get-SvcState "MSFTPSVC" }
$ftpRun = ($ftpSvc -and $ftpSvc.Status -eq "Running") -or (Get-NetTCPConnection -LocalPort 21 -State Listen -EA SilentlyContinue)
$ahc = "$env:windir\System32\inetsrv\config\applicationHost.config"
$ahcTxt = Read-AllText $ahc

# SRV-021: FTP 서비스 접근통제 (ipSecurity)
Evd "SRV-021" "Select-String -Path '$ahc' -Pattern 'ipSecurity|<add ipAddress' -EA SilentlyContinue | Select-Object -First 10"
if (-not $ftpRun) { NA "SRV-021" "FTP 서비스 미실행" }
elseif (-not $ftpIis) { MC "SRV-021" "FTP 서비스 실행 중 - IIS FTP 사이트 미탐지(타사 FTP) 접근제어 수동 확인" }
else {
    $n021 = @($ftpSites | Where-Object { -not $_.IpRestr } | ForEach-Object { $_.Name })
    if ($n021.Count) { Fail "SRV-021" "FTP IP 접근제어(ipSecurity) 미설정 사이트: $($n021 -join ', ')" }
    else { Pass "SRV-021" "FTP 전 사이트 IP 주소/도메인 제한(ipSecurity) 설정됨" }
}

# SRV-037: 취약한 FTP 서비스 (FTPS 적용 시 양호)
Evd "SRV-037" "sc.exe query FTPSVC; sc.exe query MSFTPSVC; netstat -an | findstr :21"
if (-not $ftpRun) { Pass "SRV-037" "FTP 서비스 비활성화" }
elseif (-not $ftpIis) { Fail "SRV-037" "FTP 서비스 활성화 (IIS 외 FTP - FTPS 적용 확인 불가 시 취약)" }
else {
    $n037 = @($ftpSites | Where-Object { $_.Ctl -ne 'SslRequire' -or $_.Dat -ne 'SslRequire' } | ForEach-Object { "$($_.Name)(Ctl=$($_.Ctl),Dat=$($_.Dat))" })
    if ($n037.Count) { Fail "SRV-037" "FTP 서비스 활성화 - FTPS(SSL 필수) 미적용 사이트: $($n037 -join ', ')" }
    else { Pass "SRV-037" "FTP 사용 중이나 전 사이트 FTPS(SSL 필수) 적용" }
}

# SRV-074: 불필요하거나 관리되지 않는 계정 (분기 내 로그인·비밀번호 변경)
$act074 = @($accts | Where-Object { $_.Enabled })
EvdQ "SRV-074" "활성 로컬 계정 (Name / LastLogon / PasswordLastSet / 수집원)" (($act074 | ForEach-Object { "$($_.Name) / $($_.LastLogon) / $($_.PasswordLastSet) / $($_.Src)" }) -join "`n")
if ($accts.Count -eq 0) { MC "SRV-074" "로컬 계정 조회 실패(또는 도메인 컨트롤러) - net user 계정별 로그인/비밀번호 변경일 확인" }
elseif (@($act074 | Where-Object { $_.Src -eq 'WMI(ADSI 실패)' }).Count) { MC "SRV-074" "마지막 로그인 조회 실패(ADSI) - net user 로 확인" }
else {
    $stale = @($act074 | Where-Object { -not $_.LastLogon -or $_.LastLogon -lt (Get-Date).AddDays(-90) -or -not $_.PasswordLastSet -or $_.PasswordLastSet -lt (Get-Date).AddDays(-90) })
    if ($stale.Count -gt 0) { Fail "SRV-074" "분기 내 로그인/비밀번호 변경 없는 활성 계정: $(($stale | ForEach-Object { $_.Name }) -join ', ') (업무상 사용 여부 확인)" }
    else { Pass "SRV-074" "활성 계정 모두 분기 내 로그인 및 비밀번호 변경" }
}

# SRV-082: 시스템 주요 디렉터리(로그) 권한 - Users 등 불필요 권한
$dirs = @("$env:windir\system32\config", "$env:windir\system32\winevt\Logs", "$env:windir\system32\LogFiles")
Evd "SRV-082" "foreach (`$d in @('$($dirs -join "','")')) { icacls `$d }"
$bad082 = @()
foreach ($d in $dirs) {
    $acl = Get-Acl $d -EA SilentlyContinue
    # 판단기준: Users 그룹과 같이 불필요한 권한 부여 여부 (권한 종류 한정 없음) — SID 기준(로캘 무관)
    if ($acl) { foreach ($ace in $acl.Access) { if ("$($ace.AccessControlType)" -ne 'Allow') { continue }; $sid = Get-AceSid $ace
        if (@('S-1-1-0','S-1-5-32-545','S-1-5-32-546') -contains $sid) { $bad082 += "$d($($ace.IdentityReference):$($ace.FileSystemRights))" } } }
}
if ($bad082.Count -gt 0) { Fail "SRV-082" "로그 디렉터리 불필요 권한(Everyone/Users/Guests): $($bad082 -join ', ')" } else { Pass "SRV-082" "로그 디렉터리에 Everyone/Users/Guests 권한 없음" }

# SRV-115: 로그 정기 검토 (인터뷰/보고서)
EvdQ "SRV-115" "판단방법" "로그 검토 보고서 확인 / 인터뷰"
MC "SRV-115" "로그 정기 검토·보고 수행 여부 수동 확인 (검토 보고서/인터뷰)"

# SRV-137: 네트워크 서비스 접근 권한 (네트워크에서 이 컴퓨터 액세스)
$r137 = Test-SecPolGroups "SeNetworkLogonRight" @("Everyone","Guests","Anonymous")
EvdQ "SRV-137" "SeNetworkLogonRight / SeDenyNetworkLogonRight" "$($r137[0]) / $(Get-SecPol 'SeDenyNetworkLogonRight')"
if ($null -eq $r137[0]) { MC "SRV-137" "네트워크 액세스 권한 정책 확인 실패 - 로컬 보안 정책 수동 확인" }
elseif ($r137[1].Count -gt 0) { Fail "SRV-137" "'네트워크에서 이 컴퓨터 액세스'에 불필요 그룹: $($r137[1] -join ', ')" }
else { Pass "SRV-137" "'네트워크에서 이 컴퓨터 액세스' 불필요 그룹 없음" }

# SRV-138: 백업 및 복구 권한
$rb = Test-SecPolGroups "SeBackupPrivilege" @("Everyone","Guests","Users")
$rr = Test-SecPolGroups "SeRestorePrivilege" @("Everyone","Guests","Users")
EvdQ "SRV-138" "SeBackupPrivilege / SeRestorePrivilege" "$($rb[0]) / $($rr[0])"
$bad138 = @($rb[1]) + @($rr[1]) | Select-Object -Unique
if ($null -eq $rb[0] -and $null -eq $rr[0]) { MC "SRV-138" "백업/복구 권한 정책 확인 실패 - 수동 확인" }
elseif ($bad138.Count -gt 0) { Fail "SRV-138" "백업/복구 권한에 불필요 그룹: $($bad138 -join ', ')" }
else { Pass "SRV-138" "백업/복구 권한에 Everyone/Guests/Users 없음" }

# SRV-139: 소유권 가져오기 권한 (Administrators만)
$rt = Test-SecPolGroups "SeTakeOwnershipPrivilege" @("Everyone","Users","Guests","Authenticated Users")
EvdQ "SRV-139" "SeTakeOwnershipPrivilege" "$($rt[0])"
if ($null -eq $rt[0]) { MC "SRV-139" "소유권 가져오기 권한 확인 실패 - 수동 확인" }
elseif ($rt[1].Count -gt 0) { Fail "SRV-139" "소유권 가져오기 권한에 불필요 그룹: $($rt[1] -join ', ')" }
elseif ($rt[0] -eq "*S-1-5-32-544") { Pass "SRV-139" "소유권 가져오기 권한 Administrators만 존재" }
else { MC "SRV-139" "소유권 가져오기 권한 구성원($($rt[0])) 적정성 확인" }

# SRV-147: 불필요한 네트워크 모니터링 서비스 (SNMP / WMI)
Evd "SRV-147" "sc.exe query SNMP; sc.exe query winmgmt"
$snmp2 = Get-SvcState "SNMP"
if ($snmp2 -and $snmp2.Status -eq "Running") { MC "SRV-147" "SNMP 서비스 실행 중 - 업무상 필요 여부 확인 (WMI는 OS 기본 서비스)" }
elseif ($otherSnmp) { MC "SRV-147" "타사 SNMP 에이전트 실행 중($($snmpPaths -join ', ')) - 업무상 필요 여부 확인" }
else { Pass "SRV-147" "SNMP 서비스 미실행 (WMI는 OS 기본 서비스)" }

# SRV-170: SMTP 배너 정보 노출
Evd "SRV-170" "Get-Service SMTPSVC -EA SilentlyContinue | Select-Object Status"
$mb170 = "$env:windir\System32\inetsrv\MetaBase.xml"
$cr170 = @([regex]::Matches((Read-AllText $mb170), '(?i)ConnectResponse="([^"]*)"') | ForEach-Object { $_.Groups[1].Value })
EvdQ "SRV-170" "MetaBase.xml ConnectResponse" "$(if (Test-Path $mb170) { if ($cr170.Count) { $cr170 -join ' | ' } else { '(설정 없음 - 기본 배너)' } } else { 'MetaBase.xml 없음' })"
if (-not ($smtp -and $smtp.Status -eq "Running")) { if ($l25) { MC "SRV-170" "타사 SMTP(25번 포트) 실행 - 배너 서비스명/버전 노출 수동 확인" } else { NA "SRV-170" "SMTP 서비스 미실행" } }
elseif (-not (Test-Path $mb170)) { MC "SRV-170" "IIS SMTP 실행 중 - MetaBase.xml 없음, 배너 수동 확인" }
elseif ($cr170.Count -eq 0 -or @($cr170 | Where-Object { $_ -eq '' }).Count) { Fail "SRV-170" "ConnectResponse 미설정 - 기본 배너(Microsoft ESMTP MAIL Service, Version) 노출" }
elseif (@($cr170 | Where-Object { $_ -match '(?i)microsoft|esmtp|smtpsvc|version|\d+\.\d+\.\d+' }).Count) { Fail "SRV-170" "ConnectResponse 에 서비스명/버전 포함: $($cr170 -join ' | ')" }
else { Pass "SRV-170" "SMTP 배너 사용자 지정 (서비스명·버전 미노출)" }

# SRV-171: FTP 배너 정보 노출 (suppressDefaultBanner)
Evd "SRV-171" "Select-String -Path '$ahc' -Pattern 'suppressDefaultBanner' -EA SilentlyContinue"
if (-not $ftpRun) { NA "SRV-171" "FTP 서비스 미실행" }
elseif (-not $ftpIis) { MC "SRV-171" "FTP 서비스 실행 중 - IIS FTP 사이트 미탐지(타사 FTP) 배너 수동 확인" }
else {
    $n171 = @($ftpSites | Where-Object { $_.Banner -ne 'true' } | ForEach-Object { $_.Name })
    if ($n171.Count) { Fail "SRV-171" "FTP suppressDefaultBanner 미설정 사이트(기본 배너 노출): $($n171 -join ', ')" }
    else { Pass "SRV-171" "FTP 전 사이트 suppressDefaultBanner=true (배너 정보 미노출)" }
}

# SRV-173 / SRV-174: DNS 동적 업데이트 / 불필요 DNS 서비스
$dns = Get-SvcState "DNS"
Evd "SRV-174" "sc.exe query dns"
if (-not ($dns -and $dns.Status -eq "Running")) {
    Pass "SRV-174" "DNS 서비스 미실행"
    NA "SRV-173" "DNS 서비스 미실행"
} else {
    MC "SRV-174" "DNS 서비스 실행 중 - 업무상 필요 여부 확인"
    Evd "SRV-173" "Get-DnsServerZone -EA SilentlyContinue | Select-Object ZoneName,DynamicUpdate"
    $zones = @(Get-DnsServerZone -EA SilentlyContinue | Where-Object { -not $_.IsAutoCreated })
    $nonsec = @($zones | Where-Object { $_.DynamicUpdate -eq "NonsecureAndSecure" } | ForEach-Object { $_.ZoneName })
    if ($zones.Count -eq 0) {   # DnsServer 모듈 없음(2008 R2 등) → 레지스트리 AllowUpdate (1 = 비보안 포함)
        $rz173 = @(Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\DNS Server\Zones' -EA SilentlyContinue)
        EvdQ "SRV-173" "DNS Server\Zones AllowUpdate" (($rz173 | ForEach-Object { "$($_.PSChildName) AllowUpdate=$((Get-ItemProperty $_.PSPath -EA SilentlyContinue).AllowUpdate)" }) -join "`n")
        $zones = $rz173; $nonsec = @($rz173 | Where-Object { "$((Get-ItemProperty $_.PSPath -EA SilentlyContinue).AllowUpdate)" -eq '1' } | ForEach-Object { $_.PSChildName })
    }
    if ($zones.Count -eq 0) { MC "SRV-173" "DNS 영역 조회 실패 - dnscmd /ExportSettings 로 AllowUpdate 수동 확인" }
    elseif ($nonsec.Count -gt 0) { Fail "SRV-173" "보안되지 않은 동적 업데이트 허용 영역(AllowUpdate=1): $($nonsec -join ', ')" }
    else { Pass "SRV-173" "동적 업데이트 비활성 또는 보안 업데이트만 허용" }
}

# ════════════════════════════════════════════════════════════════
# [2] 기존 IIS 점검 — 평가기준 일치 항목(KEEP)만 반영, 나머지는 REF-(참고)
# ════════════════════════════════════════════════════════════════
$script:PHASE = "web"
# ── secedit 보안 정책 내보내기 (1회) ────────────────────────────
$secTmp = "$env:TEMP\wst_secedit_${PID}.cfg"
$null = secedit /export /cfg $secTmp /quiet 2>$null
function Get-SecPol([string]$key) {
    if (-not (Test-Path $secTmp)) { return $null }
    $line = Select-String -Path $secTmp -Pattern "^\s*$key\s*=" -EA SilentlyContinue | Select-Object -First 1
    if ($line) { return ($line.Line -split "=",2)[1].Trim() }
    return $null
}

# ================================================================
# OS 레벨 점검 (Windows 기준)
# ================================================================

# WST-023: 관리자 원격 접속 제한 (RDP Administrator 로그인)
Evd "WST-023" "Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -EA SilentlyContinue | Select-Object fAllowToGetHelp"
$rdpAdminRestrict = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -EA SilentlyContinue
if ($rdpAdminRestrict -and $rdpAdminRestrict.fAllowToGetHelp -eq 0) {
    Pass "023" "원격 지원 비활성화됨 (Group Policy)"
} else {
    # Administrator 계정 직접 RDP 로그인 제한 여부 확인 (RestrictedAdmin 또는 계정 비활성화)
    $adminEnabled = (Get-LocalUser -Name "Administrator" -EA SilentlyContinue).Enabled
    if ($adminEnabled -eq $false) {
        Pass "023" "기본 Administrator 계정 비활성화됨"
    } else {
        MC "023" "Administrator 계정 활성 - RDP 접속 제한 수동 확인 (Remote Desktop Users 그룹 또는 GPO)"
    }
}

# WST-025: 원격 터미널 세션 타임아웃
Evd "WST-025" "Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name MaxIdleTime -EA SilentlyContinue | Select-Object MaxIdleTime"
$rdpTimeout = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -EA SilentlyContinue
$idleTimeout = if ($rdpTimeout) { $rdpTimeout.MaxIdleTime } else { $null }
if ($idleTimeout -and $idleTimeout -gt 0) {
    $idleSec = [int]($idleTimeout / 1000)
    if ($idleSec -le 600) { Pass "025" "RDP 유휴 세션 타임아웃=${idleSec}초 (10분 이하)" }
    else { Fail "025" "RDP 유휴 세션 타임아웃=${idleSec}초 (600초 초과)" }
} else {
    # 레지스트리 직접 확인
    $rdpTOLocal = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -EA SilentlyContinue).MaxIdleTime
    if ($rdpTOLocal -and $rdpTOLocal -gt 0) {
        $sec = [int]($rdpTOLocal / 1000)
        if ($sec -le 600) { Pass "025" "RDP 유휴 타임아웃=${sec}초" }
        else { Fail "025" "RDP 유휴 타임아웃=${sec}초 (600초 초과)" }
    } else {
        Fail "025" "RDP 세션 타임아웃 미설정"
    }
}

# WST-028: 불필요 서비스 (Telnet, Simple TCP/IP 등)
Evd "WST-028" "Get-Service TlntSvr,SimpTcp -EA SilentlyContinue | Select-Object Name,Status | Format-Table"
$dangerSvcs = @{
    "TlntSvr" = "Telnet 서버";
    "SimpTcp" = "Simple TCP/IP (chargen/daytime/echo 등)"
}
$foundSvcs = @()
foreach ($svc in $dangerSvcs.Keys) {
    $s = Get-Service $svc -EA SilentlyContinue
    if ($s -and $s.Status -eq "Running") { $foundSvcs += $dangerSvcs[$svc] }
}
if ($foundSvcs) { Fail "028" "불필요 서비스 실행: $($foundSvcs -join ', ')" }
else { Pass "028" "불필요 서비스(Telnet/Simple TCP 등) 미실행" }

# WST-049: 패스워드 최대 사용 기간 (90일 이하)
Evd "WST-049" "net accounts 2>`$null | Select-String 'password|암호'"
$maxPwAge = Get-SecPol "MaximumPasswordAge"
if ($maxPwAge -ne $null) {
    $days = [int]$maxPwAge
    if ($days -eq 0)       { Fail "049" "최대 패스워드 사용 기간 무제한(0)" }
    elseif ($days -le 90)  { Pass "049" "최대 패스워드 사용 기간=${days}일 (90일 이하)" }
    else                   { Fail "049" "최대 패스워드 사용 기간=${days}일 (90일 초과)" }
} else {
    $netAcc = net accounts 2>$null | Where-Object { $_ -match "Maximum password age|최대 암호 사용 기간" }
    if ($netAcc) {
        $val = ($netAcc -replace "[^0-9Unlimited무제한]","").Trim()
        if ($val -match "Unlimited|무제한") { Fail "049" "최대 패스워드 사용 기간 무제한" }
        elseif ($val -match "^\d+$" -and [int]$val -le 90) { Pass "049" "최대 패스워드 사용 기간=${val}일" }
        elseif ($val -match "^\d+$") { Fail "049" "최대 패스워드 사용 기간=${val}일 (90일 초과)" }
        else { MC "049" "패스워드 최대 사용 기간 수동 확인 (net accounts)" }
    } else { MC "049" "패스워드 최대 사용 기간 수동 확인" }
}

# WST-050: 패스워드 저장 방식 (LM 해시 사용 금지)
Evd "WST-050" "Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name NoLMHash,LmCompatibilityLevel -EA SilentlyContinue | Select-Object NoLMHash,LmCompatibilityLevel"
$noLM = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -EA SilentlyContinue).NoLMHash
$lmLevel = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -EA SilentlyContinue).LmCompatibilityLevel
if ($noLM -eq 1) { Pass "050" "LM 해시 저장 비활성화 (NoLMHash=1)" }
elseif ($lmLevel -ge 3) { Pass "050" "LAN Manager 인증 수준=$lmLevel (NTLMv2만 허용)" }
else {
    $lmSecPol = Get-SecPol "LmCompatibilityLevel"
    if ($lmSecPol -and [int]$lmSecPol -ge 3) { Pass "050" "LAN Manager 인증 수준=$lmSecPol" }
    else { Fail "050" "LM 해시 저장 허용 또는 하위 인증 수준 사용 (NoLMHash=0, LmCompat=$lmLevel)" }
}

# WST-052: 관리자 그룹 멤버 수
Evd "WST-052" "net localgroup Administrators 2>`$null"
$admins = Get-LocalGroupMember -Group "Administrators" -EA SilentlyContinue | Where-Object { $_ }
$adminCnt = if ($admins) { @($admins).Count } else { 0 }
if ($adminCnt -gt 5) {
    $adminNames = ($admins | Select-Object -ExpandProperty Name) -join ", "
    Fail "052" "Administrators 그룹 멤버 과다(${adminCnt}명): $adminNames - 불필요 계정 제거 필요"
} elseif ($adminCnt -gt 0) {
    $adminNames = ($admins | Select-Object -ExpandProperty Name) -join ", "
    MC "052" "Administrators 그룹 멤버(${adminCnt}명): $adminNames - 적정성 수동 확인"
} else {
    MC "052" "Administrators 그룹 멤버 확인 실패 - 수동 확인"
}

# WST-054: 패스워드 복잡도 설정
EvdQ "WST-054" "SecPol PasswordComplexity" (Get-SecPol "PasswordComplexity")
$pwComplexity = Get-SecPol "PasswordComplexity"
if ($pwComplexity -eq "1") { Pass "054" "패스워드 복잡도 설정 활성화됨 (PasswordComplexity=1)" }
elseif ($pwComplexity -eq "0") { Fail "054" "패스워드 복잡도 설정 비활성화됨 (PasswordComplexity=0)" }
else {
    $netAcc = net accounts 2>$null | Where-Object { $_ -match "complexity|복잡성" }
    if ($netAcc) { MC "054" "패스워드 복잡도: $($netAcc.Trim()) - 수동 확인" }
    else { MC "054" "패스워드 복잡도 설정 수동 확인 (로컬 보안 정책)" }
}

# WST-058: 예약 작업 (Task Scheduler) 권한
Evd "WST-058" "Get-Acl '$env:SystemRoot\System32\Tasks' -EA SilentlyContinue | Select-Object -ExpandProperty Access | Select-Object IdentityReference,FileSystemRights | Format-Table"
$taskPath = "$env:SystemRoot\System32\Tasks"
if (Test-Path $taskPath) {
    $taskAcl  = (Get-Acl $taskPath -EA SilentlyContinue).Access | Where-Object {
        $_.IdentityReference -notmatch "SYSTEM|Administrators|TrustedInstaller|CREATOR OWNER" -and
        $_.FileSystemRights -match "Write|FullControl|Modify"
    }
    if ($taskAcl) {
        Fail "058" "예약 작업 폴더에 불필요한 쓰기 권한: $($taskAcl | Select-Object -First 1 -ExpandProperty IdentityReference)"
    } else {
        Pass "058" "예약 작업 폴더 권한 적절 ($taskPath)"
    }
} else { MC "058" "Task Scheduler 폴더 미발견 - 수동 확인" }

# WST-064: 위험 프로그램 SUID 상당 (Windows: 일반 사용자 실행 가능한 위험 도구)
Evd "WST-064" "Get-Command nmap.exe,nc.exe,netcat.exe,ncat.exe,psexec.exe -EA SilentlyContinue | Select-Object Name,Source"
$dangerTools = @("nmap.exe","nc.exe","netcat.exe","ncat.exe","psexec.exe")
$foundTools  = @()
foreach ($tool in $dangerTools) {
    $cmd = Get-Command $tool -EA SilentlyContinue
    if ($cmd) { $foundTools += $cmd.Source }
}
if ($foundTools) { Fail "064" "위험 도구 발견: $($foundTools -join ', ')" }
else { Pass "064" "위험 도구(nmap/nc/psexec 등) 미발견" }

# WST-075: 로그 파일 접근 권한
Evd "WST-075" "Get-Acl '$env:SystemRoot\System32\winevt\Logs' -EA SilentlyContinue | Select-Object -ExpandProperty Access | Select-Object IdentityReference,FileSystemRights | Format-Table"
$evtLogAcl = (Get-Acl "$env:SystemRoot\System32\winevt\Logs" -EA SilentlyContinue).Access | Where-Object {
    $_.IdentityReference -notmatch "SYSTEM|Administrators|TrustedInstaller|EventLog" -and
    $_.FileSystemRights -match "Write|FullControl|Modify"
}
if ($evtLogAcl) {
    Fail "075" "이벤트 로그 폴더에 불필요 쓰기 권한: $($evtLogAcl | Select-Object -First 1 -ExpandProperty IdentityReference)"
} else {
    Pass "075" "이벤트 로그 폴더 권한 적절 (SYSTEM/Administrators만 쓰기)"
}

# WST-082: PATH에 현재 디렉토리(.) 포함 여부
EvdQ "WST-082" "System PATH" ([System.Environment]::GetEnvironmentVariable("PATH", "Machine"))
$sysPath = [System.Environment]::GetEnvironmentVariable("PATH", "Machine")
if ($sysPath -split ";" | Where-Object { $_ -eq "." -or $_ -eq "" }) {
    Fail "082" "시스템 PATH에 현재 디렉토리(.) 또는 빈 항목 포함"
} else {
    Pass "082" "시스템 PATH에 현재 디렉토리(.) 미포함"
}

# WST-083: 프로세스 기본 umask (Windows: N/A — NTFS ACL로 관리)
NA "083" "Windows 환경 umask 개념 미적용 (NTFS ACL 기반 권한 관리)"

# WST-087: 로그인 실패 횟수 제한 (계정 잠금 임계값)
Evd "WST-087" "net accounts 2>`$null | Select-String 'Lockout|잠금'"
$lockoutThresh = Get-SecPol "LockoutBadCount"
if ($lockoutThresh -ne $null) {
    $n = [int]$lockoutThresh
    if ($n -eq 0)      { Fail "087" "계정 잠금 임계값=0 (무제한)" }
    elseif ($n -le 5)  { Pass "087" "계정 잠금 임계값=${n}회 (5회 이하)" }
    else               { Fail "087" "계정 잠금 임계값=${n}회 (5회 이하 권고)" }
} else {
    $netAcc = net accounts 2>$null | Where-Object { $_ -match "Lockout threshold|잠금 임계" }
    if ($netAcc) {
        $val = ($netAcc -replace "[^0-9Never없음]","").Trim()
        if ($val -match "Never|없음") { Fail "087" "계정 잠금 임계값=Never (무제한)" }
        elseif ($val -match "^\d+$") {
            $n = [int]$val
            if ($n -le 5) { Pass "087" "계정 잠금 임계값=${n}회" }
            else { Fail "087" "계정 잠금 임계값=${n}회 (5회 이하 권고)" }
        } else { MC "087" "계정 잠금 임계값 수동 확인" }
    } else { MC "087" "계정 잠금 정책 수동 확인" }
}

# WST-090: su 명령어 제한 (Windows: UAC 설정 확인)
Evd "WST-090" "Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name EnableLUA -EA SilentlyContinue | Select-Object EnableLUA"
$uacEnable = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -EA SilentlyContinue).EnableLUA
if ($uacEnable -eq 1) { Pass "090" "UAC(User Account Control) 활성화됨" }
else { Fail "090" "UAC 비활성화됨 - 권한 상승 제어 미작동" }

# WST-099: 중복 SID (Windows 도메인 환경에서는 N/A, 로컬 계정만 확인)
Evd "WST-099" "Get-LocalUser -EA SilentlyContinue | Select-Object Name,SID | Format-Table"
$localUsers = Get-LocalUser -EA SilentlyContinue | Select-Object Name, SID
$dupSID = $localUsers | Group-Object -Property {$_.SID.Value} | Where-Object { $_.Count -gt 1 }
if ($dupSID) { Fail "099" "중복 SID 발견: $($dupSID | Select-Object -ExpandProperty Name -First 3)" }
else { Pass "099" "로컬 계정 중복 SID 없음" }

# WST-100: 불필요 파일 (Windows 임시 디렉토리)
NA "100" "Windows 환경 /dev 항목 미적용"

# WST-101: SNMP 서비스 버전 확인
Evd "WST-101" "Get-Service SNMP -EA SilentlyContinue | Select-Object Status,StartType"
$snmpSvc = Get-Service SNMP -EA SilentlyContinue
if ($snmpSvc -and $snmpSvc.Status -eq "Running") {
    $snmpCom = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\ValidCommunities" -EA SilentlyContinue
    if ($snmpCom) {
        $coms = $snmpCom.PSObject.Properties | Where-Object { $_.Name -notmatch "^PS" } | Select-Object -ExpandProperty Name
        Fail "101" "SNMP 실행 중, community 설정됨: $($coms -join ', ') - SNMPv3 전환 검토"
    } else { MC "101" "SNMP 서비스 실행 중 - community 설정 수동 확인" }
} else { Pass "101" "SNMP 서비스 미실행" }

# WST-107: Telnet 서비스 비활성화
Evd "WST-107" "Get-Service TlntSvr -EA SilentlyContinue | Select-Object Status,StartType"
$telnetSvc = Get-Service TlntSvr -EA SilentlyContinue
if ($telnetSvc -and $telnetSvc.Status -eq "Running") { Fail "107" "Telnet 서버 서비스 실행 중 (TlntSvr)" }
else { Pass "107" "Telnet 서버 미실행" }

# WST-109: 시스템 배너 설정
Evd "WST-109" "Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name legalnoticecaption,legalnoticetext -EA SilentlyContinue"
$legalNotice = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -EA SilentlyContinue).legalnoticecaption
$legalText   = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -EA SilentlyContinue).legalnoticetext
if ($legalNotice -and $legalText) { Pass "109" "로그인 경고 배너 설정됨 (legalnoticecaption: $legalNotice)" }
else { Fail "109" "로그인 경고 배너 미설정 (legalnoticecaption/legalnoticetext 없음)" }

# WST-118: NTP 동기화
Evd "WST-118" "w32tm /query /status 2>`$null"
$w32Status = w32tm /query /status 2>$null
if ($w32Status -match "Source|원본") {
    $src = ($w32Status | Where-Object { $_ -match "Source|원본" } | Select-Object -First 1).Trim()
    Pass "118" "Windows Time 동기화 활성: $src"
} else { Fail "118" "NTP 동기화 미설정 (w32tm 응답 없음)" }

# WST-119: sudo NOPASSWD 상당 (Windows: RunAs 자격증명 저장)
Evd "WST-119" "cmdkey /list 2>`$null | Select-String 'Target:'"
$savedCreds = cmdkey /list 2>$null | Where-Object { $_ -match "Target:" }
if ($savedCreds) {
    MC "119" "자격증명 저장 항목 발견: $($savedCreds.Count)개 - 불필요 항목 수동 확인 (cmdkey /list)"
} else {
    Pass "119" "저장된 자격증명(cmdkey) 없음"
}

# ================================================================
# IIS 전용 점검
# ================================================================

if (-not $IIS_INSTALLED) {
    foreach ($code in @("031","033","039","044","048","102","121","122","123","124","125")) {
        if ($WEB_SRV -eq "apache" -or $WEB_SRV -eq "nginx") { break }
        NA $code "IIS 미설치 - 웹서버 미탐지"
    }
}

if ($IIS_INSTALLED) {

    # WST-031: 디렉토리 리스팅 방지
    Evd "WST-031" "Get-WebConfigurationProperty 'system.webServer/directoryBrowse' -PSPath 'IIS:\' -Name 'enabled' -EA SilentlyContinue"
    if ($HAS_WEB_ADMIN) {
        $dirBrowse = Get-WebConfigurationProperty "system.webServer/directoryBrowse" -PSPath "IIS:\" -Name "enabled" -EA SilentlyContinue
        if ($dirBrowse -and $dirBrowse.Value -eq $true) {
            Fail "031" "IIS 디렉토리 브라우징 전역 활성화됨 - 비활성화 필요"
        } else {
            # 사이트별 확인
            $sites = Get-ChildItem "IIS:\Sites" -EA SilentlyContinue
            $vuln031 = @()
            foreach ($site in $sites) {
                $db = Get-WebConfigurationProperty "system.webServer/directoryBrowse" -PSPath "IIS:\Sites\$($site.Name)" -Name "enabled" -EA SilentlyContinue
                if ($db -and $db.Value -eq $true) { $vuln031 += $site.Name }
            }
            if ($vuln031) { Fail "031" "디렉토리 브라우징 활성 사이트: $($vuln031 -join ', ')" }
            else { Pass "031" "IIS 디렉토리 브라우징 비활성화됨 (전체 사이트)" }
        }
    } elseif (Test-Path $APPCMD) {
        $dbOut = & $APPCMD list config /section:directoryBrowse 2>$null
        if ($dbOut -match 'enabled="true"') { Fail "031" "IIS 디렉토리 브라우징 활성화됨 (appcmd 확인)" }
        else { Pass "031" "IIS 디렉토리 브라우징 비활성화됨" }
    } else { MC "031" "IIS 디렉토리 브라우징 설정 수동 확인 (WebAdministration 모듈 없음)" }

    # WST-033: 상위 디렉토리 접근 제한 (requestFiltering)
    Evd "WST-033" "Get-WebConfigurationProperty 'system.webServer/security/requestFiltering' -PSPath 'IIS:\' -Name 'allowDoubleEscaping' -EA SilentlyContinue"
    if ($HAS_WEB_ADMIN) {
        $allowDouble = Get-WebConfigurationProperty "system.webServer/security/requestFiltering" -PSPath "IIS:\" -Name "allowDoubleEscaping" -EA SilentlyContinue
        # ../  경로 이중 인코딩 차단 여부
        $allowDoubleVal = if ($allowDouble) { $allowDouble.Value } else { $null }
        if ($allowDoubleVal -eq $false) {
            Pass "033" "IIS allowDoubleEscaping=false (디렉토리 트래버설 차단)"
        } else {
            MC "033" "IIS 상위 디렉토리 접근 제한 수동 확인 (allowDoubleEscaping 설정)"
        }
    } else { MC "033" "상위 디렉토리 접근 제한 수동 확인" }

    # WST-036: 웹 서비스 프로세스 권한 (Application Pool Identity)
    Evd "WST-036" "Get-ChildItem 'IIS:\AppPools' -EA SilentlyContinue | Select-Object Name,@{n='Identity';e={`$_.processModel.identityType}} | Format-Table"
    if ($HAS_WEB_ADMIN) {
        $pools = Get-ChildItem "IIS:\AppPools" -EA SilentlyContinue
        $vuln036 = @()
        foreach ($pool in $pools) {
            $identity = $pool.processModel.userName
            $identityType = $pool.processModel.identityType
            if ($identityType -eq "LocalSystem" -or $identity -eq "LocalSystem") {
                $vuln036 += "$($pool.Name)(LocalSystem)"
            }
        }
        if ($vuln036) { Fail "036" "LocalSystem 권한 App Pool: $($vuln036 -join ', ') - 전용 계정 권고" }
        else { Pass "036" "App Pool LocalSystem 사용 없음 (ApplicationPoolIdentity 또는 전용 계정)" }
    } elseif (Test-Path $APPCMD) {
        $poolOut = & $APPCMD list apppool /processModel.identityType:LocalSystem 2>$null
        if ($poolOut) { Fail "036" "LocalSystem 권한 App Pool 존재: $poolOut" }
        else { Pass "036" "LocalSystem 권한 App Pool 없음" }
    } else { MC "036" "IIS Application Pool 실행 권한 수동 확인" }

    # WST-039: 불필요 IIS 모듈 비활성화
    Evd "WST-039" "Get-WebGlobalModule -Name 'WebDAVModule' -EA SilentlyContinue"
    if ($HAS_WEB_ADMIN) {
        $webdavMod  = Get-WebGlobalModule -Name "WebDAVModule" -EA SilentlyContinue
        $webdavConf = Get-WebConfigurationProperty "system.webServer/webdav/authoring" -PSPath "IIS:\" -Name "enabled" -EA SilentlyContinue
        if ($webdavMod -or ($webdavConf -and $webdavConf.Value -eq $true)) {
            Fail "039" "WebDAV 모듈/기능 활성화됨 - 불필요 시 비활성화 권고"
        } else {
            Pass "039" "WebDAV 모듈 비활성화됨"
        }
    } else { MC "039" "불필요 IIS 모듈(WebDAV 등) 수동 확인" }

    # WST-044: 기본 관리 계정 변경 (IIS Manager 사용자)
    MC "044" "IIS 관리자 계정 및 기본 자격증명 변경 여부 수동 확인"

    # WST-048: DNS Zone Transfer (IIS 서버에서 DNS 서비스 동시 실행 여부)
    $dnsSvc = Get-Service DNS -EA SilentlyContinue
    if ($dnsSvc -and $dnsSvc.Status -eq "Running") {
            MC "048" "DNS 서비스 실행 중 - Zone Transfer 제한 설정 수동 확인 (dnsmgmt.msc)"
    } else {
        NA "048" "DNS 서비스 미실행"
    }

    # WST-102: 서버 정보 노출 방지 (IIS Server 헤더)
    Evd "WST-102" "Get-WebConfigurationProperty 'system.webServer/security/requestFiltering' -PSPath 'IIS:\' -Name 'removeServerHeader' -EA SilentlyContinue"
    if ($HAS_WEB_ADMIN) {
        # IIS 10.0+ 에서는 removeServerHeader 설정 가능
        $removeHeader = Get-WebConfigurationProperty "system.webServer/security/requestFiltering" -PSPath "IIS:\" -Name "removeServerHeader" -EA SilentlyContinue
        if ($removeHeader -and $removeHeader.Value -eq $true) {
            Pass "102" "IIS Server 헤더 제거 설정됨 (removeServerHeader=true)"
        } else {
            Fail "102" "IIS Server 헤더 노출 가능 (removeServerHeader 미설정) - web.config 또는 URLRewrite로 제거 권고"
        }
    } else { MC "102" "IIS 서버 정보 노출 방지 수동 확인 (Server 헤더, X-Powered-By 헤더)" }

    # WST-121: IIS 역방향 프록시(ARR) 설정
    Evd "WST-121" "Get-WebGlobalModule -Name 'ApplicationRequestRouting' -EA SilentlyContinue"
    $arrMod = Get-WebGlobalModule -Name "ApplicationRequestRouting" -EA SilentlyContinue
    if ($arrMod) {
        MC "121" "IIS ARR(역방향 프록시) 모듈 설치됨 - 프록시 허용 범위 수동 확인"
    } else {
        Pass "121" "IIS ARR 역방향 프록시 모듈 미설치"
    }

    # WST-122: SSI (Server Side Includes) 비활성화
    Evd "WST-122" "Get-WebGlobalModule -Name 'ServerSideIncludeModule' -EA SilentlyContinue"
    if ($HAS_WEB_ADMIN) {
        $ssiMod = Get-WebGlobalModule -Name "ServerSideIncludeModule" -EA SilentlyContinue
        if ($ssiMod) { Fail "122" "SSI(Server Side Include) 모듈 활성화됨 - 불필요 시 제거 권고" }
        else { Pass "122" "SSI 모듈 비활성화됨" }
    } else { MC "122" "SSI 모듈 활성화 여부 수동 확인" }

    # WST-123: 기본 에러 페이지 노출 방지
    Evd "WST-123" "Get-WebConfigurationProperty 'system.webServer/httpErrors' -PSPath 'IIS:\' -Name 'errorMode' -EA SilentlyContinue"
    if ($HAS_WEB_ADMIN) {
        $errMode = Get-WebConfigurationProperty "system.webServer/httpErrors" -PSPath "IIS:\" -Name "errorMode" -EA SilentlyContinue
        $existMode = Get-WebConfigurationProperty "system.webServer/httpErrors" -PSPath "IIS:\" -Name "existingResponse" -EA SilentlyContinue
        $errModeVal = if ($errMode) { $errMode.Value } else { "" }
        if ($errModeVal -eq "Custom") {
            Pass "123" "IIS 커스텀 에러 페이지 설정됨 (errorMode=Custom)"
        } elseif ($errModeVal -eq "DetailedLocalOnly") {
            Pass "123" "IIS 에러 상세정보 로컬만 노출 (DetailedLocalOnly)"
        } else {
            Fail "123" "IIS 에러 페이지 설정 미흡 (errorMode=$errModeVal) - Custom 에러 페이지 설정 권고"
        }
    } else { MC "123" "IIS 에러 페이지 설정 수동 확인" }

    # WST-124: TRACE/OPTIONS HTTP 메서드 제한
    Evd "WST-124" "Get-WebConfigurationProperty 'system.webServer/security/requestFiltering/verbs' -PSPath 'IIS:\' -Name 'Collection' -EA SilentlyContinue | Select-Object verb,allowed | Format-Table"
    if ($HAS_WEB_ADMIN) {
        $verbs = Get-WebConfigurationProperty "system.webServer/security/requestFiltering/verbs" -PSPath "IIS:\" -Name "Collection" -EA SilentlyContinue
        $traceAllowed = $verbs | Where-Object { $_.verb -eq "TRACE" -and $_.allowed -eq $true }
        $allowUnlisted = Get-WebConfigurationProperty "system.webServer/security/requestFiltering/verbs" -PSPath "IIS:\" -Name "allowUnlisted" -EA SilentlyContinue
        if ($traceAllowed) {
            Fail "124" "TRACE 메서드 명시적 허용됨 - 차단 권고"
        } elseif ($allowUnlisted -and $allowUnlisted.Value -eq $false) {
            Pass "124" "HTTP 메서드 허용 목록(화이트리스트) 방식 적용됨 (allowUnlisted=false)"
        } else {
            MC "124" "위험 HTTP 메서드(TRACE/TRACK) 제한 수동 확인 (요청 필터링)"
        }
    } else { MC "124" "위험 HTTP 메서드 제한 수동 확인" }

    # WST-125: 파일 업로드 경로 실행 권한 제한
    MC "125" "IIS 업로드 경로 스크립트 실행 권한 수동 확인 (웹 디렉토리 실행 허용 없음 권고)"

    # WST-126: EoS 버전 점검 (IIS)
    if ($IIS_VERSION -ne "" -and $IIS_VERSION -ne "unknown") {
        # IIS 버전은 Windows Server 버전에 종속
        $osVer = (Get-CimInstance Win32_OperatingSystem -EA SilentlyContinue).Caption
        Pass "126" "IIS $IIS_VERSION (Windows Server 버전 종속) - OS EoS 수동 확인: $osVer"
    } else {
        MC "126" "IIS 버전 확인 실패 - 수동 확인"
    }

} # end IIS_INSTALLED

# Apache on Windows 점검
if ($WEB_SRV -eq "apache" -and $APACHE_CONF) {
    $confDir = Split-Path $APACHE_CONF

    # WST-031: 디렉토리 리스팅
    $dirIdx = Select-String -Path (Get-ChildItem $confDir -Filter "*.conf" -Recurse -EA SilentlyContinue).FullName -Pattern "Options.*Indexes" -EA SilentlyContinue | Where-Object { $_ -notmatch "#" }
    if ($dirIdx) { Fail "031" "Apache 디렉토리 리스팅 활성: $($dirIdx | Select-Object -First 1)" }
    else { Pass "031" "Apache 디렉토리 리스팅 비활성 (Options -Indexes)" }

    # WST-036: Apache 실행 계정
    $apacheProc = Get-Process httpd -EA SilentlyContinue | Select-Object -First 1
    if ($apacheProc) {
        $cimProc = Get-CimInstance Win32_Process -Filter "ProcessId=$($apacheProc.Id)" -EA SilentlyContinue
        $procUser = if ($cimProc) { (Invoke-CimMethod -InputObject $cimProc -MethodName GetOwner -EA SilentlyContinue).User } else { $null }
        if ($procUser -eq "SYSTEM" -or $procUser -eq "Administrator") {
            Fail "036" "Apache SYSTEM/Administrator 권한으로 실행 중"
        } else {
            Pass "036" "Apache 실행 계정: $procUser (비관리자)"
        }
    } else { MC "036" "Apache 실행 계정 수동 확인" }

    # WST-102: ServerTokens
    $srvTokens = Select-String -Path $APACHE_CONF -Pattern "^ServerTokens" -EA SilentlyContinue | Select-Object -First 1
    if ($srvTokens -match "Prod|Min") { Pass "102" "Apache ServerTokens=$($srvTokens.Line.Split()[-1]) (버전 최소 노출)" }
    elseif ($srvTokens -match "Full|OS|All|Major|Minor") { Fail "102" "Apache ServerTokens=$($srvTokens.Line.Split()[-1]) (버전 노출)" }
    else { MC "102" "Apache ServerTokens 설정 수동 확인" }

    # WST-123: ErrorDocument
    $errDoc = Select-String -Path (Get-ChildItem $confDir -Filter "*.conf" -Recurse -EA SilentlyContinue).FullName -Pattern "ErrorDocument" -EA SilentlyContinue | Where-Object { $_ -notmatch "#" }
    if ($errDoc) { Pass "123" "Apache ErrorDocument 설정됨" }
    else { Fail "123" "Apache ErrorDocument 미설정 (기본 에러 페이지 노출)" }

    foreach ($code in @("033","039","044","048","121","122","124","125","126")) {
        MC $code "Apache on Windows - $code 항목 수동 확인"
    }
}

# Nginx on Windows 점검
if ($WEB_SRV -eq "nginx" -and $NGINX_CONF) {
    $ngContent = Get-Content $NGINX_CONF -EA SilentlyContinue

    # WST-031: autoindex
    if ($ngContent -match "autoindex\s+on") { Fail "031" "Nginx autoindex on 설정됨" }
    else { Pass "031" "Nginx autoindex off (기본 또는 명시)" }

    # WST-102: server_tokens
    if ($ngContent -match "server_tokens\s+off") { Pass "102" "Nginx server_tokens off 설정됨" }
    else { Fail "102" "Nginx server_tokens off 미설정 (버전 노출)" }

    foreach ($code in @("033","036","039","044","048","121","122","123","124","125","126")) {
        MC $code "Nginx on Windows - $code 항목 수동 확인"
    }
}

# ================================================================
# Tomcat on Windows 점검
# ================================================================
if ($WAS_SRV -eq "tomcat" -and $TOMCAT_HOME -and (Test-Path "$TOMCAT_HOME\conf\server.xml")) {
    $serverXml = Get-Content "$TOMCAT_HOME\conf\server.xml" -Raw -EA SilentlyContinue

    # WST-059: Shutdown 포트 비활성화 (port="-1")
    EvdQ "WST-059" "server.xml <Server port=...>" ($serverXml | Select-String '<Server\s' | Out-String)
    if ($serverXml -match '<Server\s[^>]*port="-1"') {
        Pass "059" "Tomcat Shutdown 포트 비활성화됨 (port=-1)"
    } elseif ($serverXml -match '<Server\s[^>]*port="(\d+)"') {
        $shutdownPort = $matches[1]
        Fail "059" "Tomcat Shutdown 포트 활성화됨 (port=$shutdownPort) - -1로 변경 권고"
    } else { MC "059" "Tomcat Shutdown 포트 설정 수동 확인" }

    # WST-060: 기본 애플리케이션(manager, host-manager, examples, docs, ROOT) 제거
    Evd "WST-060" "Get-ChildItem '$TOMCAT_HOME\webapps' -Directory -EA SilentlyContinue | Select-Object Name"
    $defaultApps = @("manager","host-manager","examples","docs")
    $existApps   = @()
    foreach ($app in $defaultApps) {
        if (Test-Path "$TOMCAT_HOME\webapps\$app") { $existApps += $app }
    }
    if ($existApps) { Fail "060" "Tomcat 기본 애플리케이션 존재: $($existApps -join ', ') - 운영 서버에서 제거 권고" }
    else { Pass "060" "Tomcat 기본 애플리케이션(manager/examples/docs) 제거됨" }

    # WST-036: Tomcat 실행 계정 확인 (IIS 설치 시 IIS AppPool 결과를 우선함 - 중복 방지)
    if (-not $IIS_INSTALLED) {
        $tcSvc = Get-CimInstance Win32_Service -Filter "Name LIKE 'Tomcat%'" -EA SilentlyContinue | Select-Object -First 1
        $tcUser = $tcSvc.StartName
        if (-not $tcUser) {
            # CimInstance 실패 시 레지스트리 폴백
            $tcRegKey = Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Services" -EA SilentlyContinue |
                Where-Object { $_.PSChildName -match "^Tomcat" } | Select-Object -First 1
            $tcUser = if ($tcRegKey) { (Get-ItemProperty $tcRegKey.PSPath -EA SilentlyContinue).ObjectName } else { $null }
        }
        if ($tcUser) {
            if ($tcUser -match "LocalSystem|NT AUTHORITY\\SYSTEM") {
                Fail "036" "Tomcat 서비스 계정: $tcUser (전체 권한 - 전용 계정 권고)"
            } else {
                Pass "036" "Tomcat 서비스 계정: $tcUser (비관리자)"
            }
        } else { MC "036" "Tomcat 실행 계정 수동 확인 (서비스 등록 여부)" }
    }

    # WST-126: Tomcat EoS
    Evd "WST-126" "Get-ChildItem '$TOMCAT_HOME' -Filter 'RELEASE-NOTES' -EA SilentlyContinue | Select-Object Name,FullName"
    $releaseNotes = Get-ChildItem "$TOMCAT_HOME" -Filter "RELEASE-NOTES" -EA SilentlyContinue | Select-Object -First 1
    $tcVer = ""
    if ($releaseNotes) {
        $verLine = Select-String -Path $releaseNotes.FullName -Pattern "Apache Tomcat Version" -EA SilentlyContinue | Select-Object -First 1
        if ($verLine) { $tcVer = ($verLine.Line | Select-String -Pattern "[0-9]+\.[0-9]+\.[0-9]+").Matches[0].Value }
    }
    if (-not $tcVer) {
        # catalina.bat 버전 확인 시도
        $catBat = "$TOMCAT_HOME\bin\catalina.bat"
        if (Test-Path $catBat) {
            $verMatch = Select-String -Path $catBat -Pattern "version" -EA SilentlyContinue | Select-Object -First 1
            $tcVer = if ($verMatch) { ($verMatch.Line | Select-String -Pattern "[0-9]+\.[0-9]+\.[0-9]+").Matches[0].Value } else { "" }
        }
    }
    if ($tcVer) {
        $eosScript = Join-Path (Split-Path $MyInvocation.MyCommand.Path) "eos_checker.py"
        if (-not (Test-Path $eosScript)) { $eosScript = Join-Path $script:ScriptDir "..\converter\eos_checker.py" }   # 저장소 구조 그대로 실행 시
        if (Test-Path $eosScript) {
            $eosResult  = python3 $eosScript "tomcat" $tcVer 2>$null
            $eosStatus  = ($eosResult | Where-Object {$_ -match "^결과:"}) -replace "결과:\s*",""
            $eosDesc    = ($eosResult | Where-Object {$_ -match "^설명:"}) -replace "설명:\s*",""
            $eosStatus  = if ($eosStatus) { $eosStatus.Trim() } else { "" }
            $eosDesc    = if ($eosDesc)   { $eosDesc.Trim()   } else { "EoS 판정 실패" }
            if     ($eosStatus -eq "취약")    { Fail "126" "Tomcat $tcVer EoS: $eosDesc" }
            elseif ($eosStatus -eq "양호")    { Pass "126" "Tomcat $tcVer 지원기간 내: $eosDesc" }
            else                               { MC   "126" "Tomcat $tcVer EoS 수동 확인: $eosDesc" }
        } else { MC "126" "Tomcat $tcVer - eos_checker.py 없음, EoS 수동 확인" }
    } else { MC "126" "Tomcat 버전 확인 실패 - EoS 수동 확인" }

} elseif ($WAS_SRV -eq "jeus") {
    MC "059" "JEUS Shutdown 포트 설정 수동 확인"
    MC "060" "JEUS 기본 애플리케이션 제거 여부 수동 확인"
    MC "036" "JEUS 실행 계정 수동 확인"
    MC "126" "JEUS 버전 EoS 수동 확인 (TmaxSoft 지원 정책)"
} elseif (-not $WAS_SRV) {
    foreach ($code in @("059","060")) { NA $code "WAS 미탐지" }
    if (-not $IIS_INSTALLED -and $WEB_SRV -ne "apache" -and $WEB_SRV -ne "nginx") {
        NA "036" "웹서버/WAS 미탐지"
        NA "126" "웹서버/WAS 미탐지"
    }
}

# ================================================================
# 추가 자동 점검 항목 (Windows 전용)
# ================================================================

# WST-016: 불필요한 기본 공유 비활성화 (ADMIN$, C$ 등)
Evd "WST-016" "Get-SmbShare -EA SilentlyContinue | Select-Object Name,Path,ShareType | Format-Table"
$defaultShares = Get-SmbShare -EA SilentlyContinue | Where-Object {
    $_.Name -match '^\w\$$|^ADMIN\$$|^IPC\$$' -and $_.ShareType -eq "FileSystemDirectory"
} | Where-Object { $_.Name -ne "IPC$" }
if ($defaultShares) {
    $shareNames = ($defaultShares | Select-Object -ExpandProperty Name) -join ", "
    Fail "016" "기본 관리 공유 활성: $shareNames - 불필요 시 비활성화 권고 (AutoShareServer=0)"
} else {
    Pass "016" "기본 관리 공유(ADMIN\$, C\$ 등) 비활성화됨"
}

# WST-017: 공유 기능 접근통제 적절성
Evd "WST-017" "Get-SmbShare -EA SilentlyContinue | ForEach-Object { Get-SmbShareAccess `$_.Name -EA SilentlyContinue | Where-Object {`$_.AccountName -match 'Everyone' -and `$_.AccessRight -eq 'Full'} }"
$openShares = Get-SmbShare -EA SilentlyContinue | Where-Object { $_.Name -notmatch '^\w\$$|^ADMIN\$$|^IPC\$$' } |
    ForEach-Object {
        $perms = Get-SmbShareAccess $_.Name -EA SilentlyContinue
        $everyone = $perms | Where-Object { $_.AccountName -match "Everyone|모든 사용자" -and $_.AccessRight -eq "Full" }
        if ($everyone) { $_.Name }
    }
if ($openShares) { Fail "017" "Everyone 전체 권한 공유 존재: $($openShares -join ', ')" }
else { Pass "017" "공유 폴더 Everyone 전체 권한 없음" }

# WST-019: 비밀번호 미설정(빈 암호) 계정
Evd "WST-019" "Get-LocalUser -EA SilentlyContinue | Where-Object {`$_.PasswordRequired -eq `$false -and `$_.Enabled} | Select-Object Name,Enabled,PasswordRequired"
$emptyPw = Get-LocalUser -EA SilentlyContinue | Where-Object { $_.PasswordRequired -eq $false -and $_.Enabled -eq $true }
if ($emptyPw) {
    Fail "019" "비밀번호 불필요 설정 계정: $($emptyPw.Name -join ', ') - 비밀번호 필수화 권고"
} else {
    Pass "019" "활성 계정 모두 비밀번호 필수 설정됨"
}

# WST-020: 원격 터미널 서비스 암호화 설정 (RDP SecurityLayer)
Evd "WST-020" "Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name SecurityLayer -EA SilentlyContinue | Select-Object SecurityLayer"
$rdpSec = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -EA SilentlyContinue).SecurityLayer
# 0=RDP, 1=Negotiate, 2=SSL/TLS
if ($rdpSec -ge 2) { Pass "020" "RDP SecurityLayer=$rdpSec (SSL/TLS 암호화)" }
elseif ($rdpSec -eq 1) { Pass "020" "RDP SecurityLayer=1 (Negotiate - TLS 협상)" }
elseif ($rdpSec -eq 0) { Fail "020" "RDP SecurityLayer=0 (RDP 전용 암호화 - SSL 적용 권고)" }
else { MC "020" "RDP 암호화 설정 수동 확인" }

# WST-026: SMB 세션 자동 중단 설정 (AutoDisconnect)
Evd "WST-026" "Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name AutoDisconnect -EA SilentlyContinue | Select-Object AutoDisconnect"
$autoDiscon = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -EA SilentlyContinue).AutoDisconnect
if ($null -eq $autoDiscon) { MC "026" "SMB AutoDisconnect 설정 없음 (기본값 15분) - 수동 확인" }
elseif ($autoDiscon -eq -1) { Fail "026" "SMB AutoDisconnect=-1 (세션 자동 중단 비활성화)" }
elseif ($autoDiscon -le 30) { Pass "026" "SMB AutoDisconnect=${autoDiscon}분 (30분 이하)" }
else { Fail "026" "SMB AutoDisconnect=${autoDiscon}분 (30분 이하 권고)" }

# WST-027: 계정 목록 및 공유 이름 노출 방지 (RestrictAnonymous)
Evd "WST-027" "Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name RestrictAnonymous,RestrictAnonymousSAM -EA SilentlyContinue | Select-Object RestrictAnonymous,RestrictAnonymousSAM"
$raVal  = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -EA SilentlyContinue).RestrictAnonymous
$raSam  = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -EA SilentlyContinue).RestrictAnonymousSAM
if ($raVal -ge 1 -and $raSam -eq 1) {
    Pass "027" "익명 사용자 계정/공유 열거 차단됨 (RestrictAnonymous=$raVal, RestrictAnonymousSAM=$raSam)"
} elseif ($raVal -ge 1 -or $raSam -eq 1) {
    MC "027" "익명 열거 부분 제한 (RestrictAnonymous=$raVal, RestrictAnonymousSAM=$raSam) - 둘 다 설정 권고"
} else {
    Fail "027" "익명 계정 목록/공유 열거 허용 (RestrictAnonymous=$raVal)"
}

# WST-029: 취약한 서비스 비활성화 (Telnet, NetBIOS Helper)
Evd "WST-029" "Get-Service TlntSvr,lmhosts -EA SilentlyContinue | Select-Object Name,Status | Format-Table"
$vulnSvcs029 = @{ "TlntSvr" = "Telnet 서버"; "lmhosts" = "NetBIOS Helper" }
$found029 = @()
foreach ($s in $vulnSvcs029.Keys) {
    $svc = Get-Service $s -EA SilentlyContinue
    if ($svc -and $svc.Status -eq "Running") { $found029 += $vulnSvcs029[$s] }
}
if ($found029) { Fail "029" "취약 서비스 실행 중: $($found029 -join ', ')" }
else { Pass "029" "취약 서비스(Telnet/NetBIOS Helper) 미실행" }

# WST-030: 취약한 FTP 서비스 비활성화 (TFTP)
Evd "WST-030" "Get-Service tftpd -EA SilentlyContinue | Select-Object Status,StartType; Get-Process tftp* -EA SilentlyContinue | Select-Object Name,Id"
$tftpSvc = Get-Service "tftpd" -EA SilentlyContinue
$tftpProc = Get-Process "tftp*" -EA SilentlyContinue | Select-Object -First 1
if (($tftpSvc -and $tftpSvc.Status -eq "Running") -or $tftpProc) {
    Fail "030" "TFTP 서비스/프로세스 실행 중 - 비활성화 권고"
} else {
    Pass "030" "TFTP 서비스 미실행"
}

# WST-051: 기본 Administrator 계정명 변경 여부
Evd "WST-051" "Get-LocalUser -EA SilentlyContinue | Where-Object {`$_.SID.Value -match '-500`$'} | Select-Object Name,SID"
$builtinAdmin = Get-LocalUser -EA SilentlyContinue | Where-Object {
    $_.SID.Value -match "-500$"
}
if ($builtinAdmin -and $builtinAdmin.Name -eq "Administrator") {
    Fail "051" "기본 Administrator 계정명 변경되지 않음 - 이름 변경 권고"
} elseif ($builtinAdmin) {
    Pass "051" "Administrator 계정명 변경됨: $($builtinAdmin.Name)"
} else {
    MC "051" "기본 관리자 계정(SID *-500) 확인 실패 - 수동 확인"
}

# WST-055: Guest 계정 비활성화
Evd "WST-055" "Get-LocalUser -Name Guest -EA SilentlyContinue | Select-Object Name,Enabled"
$guestAcc = Get-LocalUser -Name "Guest" -EA SilentlyContinue
if (-not $guestAcc)         { Pass "055" "Guest 계정 없음" }
elseif (-not $guestAcc.Enabled) { Pass "055" "Guest 계정 비활성화됨" }
else                        { Fail "055" "Guest 계정 활성화됨 - 비활성화 권고" }

# WST-057: 일반 사용자 프린터 드라이버 설치 제한
Evd "WST-057" "Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers' -Name AddPrinterDrivers -EA SilentlyContinue | Select-Object AddPrinterDrivers"
$addPrinterDriver = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers" -EA SilentlyContinue).AddPrinterDrivers
if ($addPrinterDriver -eq 1) { Pass "057" "프린터 드라이버 설치 제한됨 (AddPrinterDrivers=1)" }
else { Fail "057" "일반 사용자 프린터 드라이버 설치 허용 (AddPrinterDrivers=$addPrinterDriver) - 제한 권고" }

# WST-063: 원격 레지스트리 서비스 비활성화
Evd "WST-063" "Get-Service RemoteRegistry -EA SilentlyContinue | Select-Object Status,StartType"
$remReg = Get-Service RemoteRegistry -EA SilentlyContinue
if (-not $remReg)                        { Pass "063" "RemoteRegistry 서비스 없음" }
elseif ($remReg.Status -eq "Stopped" -and $remReg.StartType -eq "Disabled") {
    Pass "063" "RemoteRegistry 서비스 비활성화됨 (Disabled)"
} elseif ($remReg.Status -eq "Running")  { Fail "063" "RemoteRegistry 서비스 실행 중 - 비활성화 권고" }
else { MC "063" "RemoteRegistry StartType=$($remReg.StartType) - 수동 확인" }

# WST-071: 불필요한 예약 작업 (비Microsoft 경로 작업 목록)
Evd "WST-071" "Get-ScheduledTask -EA SilentlyContinue | Where-Object {`$_.TaskPath -notmatch '^\\\\Microsoft\\\\' -and `$_.State -ne 'Disabled'} | Select-Object -First 5 TaskName,TaskPath,State | Format-Table"
$nonMsTasks = Get-ScheduledTask -EA SilentlyContinue | Where-Object {
    $_.TaskPath -notmatch "^\\Microsoft\\" -and $_.State -ne "Disabled" -and $_.TaskPath -ne "\"
}
if ($nonMsTasks) {
    $taskList = ($nonMsTasks | Select-Object -First 5 -ExpandProperty TaskName) -join ", "
    MC "071" "비Microsoft 예약 작업 $(@($nonMsTasks).Count)개: $taskList - 불필요 작업 수동 확인"
} else {
    Pass "071" "비Microsoft 활성 예약 작업 없음"
}

# WST-072: LAN Manager 인증 수준 (NTLMv2 이상 필요)
Evd "WST-072" "Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name LmCompatibilityLevel -EA SilentlyContinue | Select-Object LmCompatibilityLevel"
$lmCompat = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -EA SilentlyContinue).LmCompatibilityLevel
$lmSecPol2 = Get-SecPol "LmCompatibilityLevel"
$lmFinal = if ($null -ne $lmCompat) { $lmCompat } elseif ($lmSecPol2) { [int]$lmSecPol2 } else { $null }
if ($null -eq $lmFinal)     { MC "072" "LAN Manager 인증 수준 설정 확인 실패" }
elseif ($lmFinal -ge 5)     { Pass "072" "LAN Manager 인증 수준=$lmFinal (NTLMv2만 허용, 최고 보안)" }
elseif ($lmFinal -ge 3)     { Pass "072" "LAN Manager 인증 수준=$lmFinal (NTLMv2 응답만 전송)" }
else                        { Fail "072" "LAN Manager 인증 수준=$lmFinal (NTLMv2 미적용 - 3 이상 권고)" }

# WST-073: 보안 채널 데이터 암호화/서명
Evd "WST-073" "Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' -Name SealSecureChannel,SignSecureChannel,RequireStrongKey -EA SilentlyContinue"
$sealSec = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -EA SilentlyContinue).SealSecureChannel
$signSec = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -EA SilentlyContinue).SignSecureChannel
$reqSeal = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -EA SilentlyContinue).RequireStrongKey
if ($sealSec -eq 1 -and $signSec -eq 1) {
    Pass "073" "보안 채널 암호화($sealSec) 및 서명($signSec) 모두 활성화됨"
} elseif ($null -eq $sealSec -and $null -eq $signSec) {
    MC "073" "보안 채널 설정 없음 - 로컬 보안 정책 수동 확인"
} else {
    Fail "073" "보안 채널 암호화=$sealSec, 서명=$signSec - 둘 다 1(활성화) 필요"
}

# WST-074: 불필요한 시작 프로그램 제거
$runKeys = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
)
Evd "WST-074" "Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -EA SilentlyContinue; Get-ItemProperty 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -EA SilentlyContinue"
$startupItems = @()
foreach ($key in $runKeys) {
    $props = Get-ItemProperty $key -EA SilentlyContinue
    if ($props) {
        $items = $props.PSObject.Properties | Where-Object { $_.Name -notmatch "^PS" }
        $startupItems += $items | ForEach-Object { "$($_.Name)=$($_.Value)" }
    }
}
if ($startupItems) {
    MC "074" "시작 프로그램 $($startupItems.Count)개 등록됨: $($startupItems[0..2] -join '; ') - 불필요 항목 수동 확인"
} else {
    Pass "074" "레지스트리 시작 프로그램 없음"
}

# WST-079: "보안 감사 수행 불가 시 즉시 종료" 기능 비활성화 (CrashOnAuditFail)
Evd "WST-079" "Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name CrashOnAuditFail -EA SilentlyContinue | Select-Object CrashOnAuditFail"
$crashAudit = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -EA SilentlyContinue).CrashOnAuditFail
if ($crashAudit -eq 1) { Fail "079" "CrashOnAuditFail=1 - 감사 실패 시 시스템 종료 활성화됨 (0으로 변경 권고)" }
elseif ($crashAudit -eq 0 -or $null -eq $crashAudit) { Pass "079" "CrashOnAuditFail=0 (감사 실패 시 강제 종료 비활성화)" }
else { MC "079" "CrashOnAuditFail=$crashAudit - 수동 확인" }

# WST-084: 최종 로그인 사용자 계정 노출 방지
Evd "WST-084" "Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name DontDisplayLastUserName -EA SilentlyContinue | Select-Object DontDisplayLastUserName"
$dontDisplay = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -EA SilentlyContinue).DontDisplayLastUserName
if ($dontDisplay -eq 1) { Pass "084" "마지막 로그인 계정 표시 안 함 (DontDisplayLastUserName=1)" }
else { Fail "084" "마지막 로그인 계정 노출됨 (DontDisplayLastUserName=$dontDisplay) - 1로 설정 권고" }

# WST-085: 화면보호기 설정 (잠금 포함)
Evd "WST-085" "Get-ItemProperty 'HKCU:\Control Panel\Desktop' -Name ScreenSaveActive,ScreenSaverIsSecure,ScreenSaveTimeOut -EA SilentlyContinue"
$ssActive  = (Get-ItemProperty "HKCU:\Control Panel\Desktop" -EA SilentlyContinue).ScreenSaveActive
$ssSecure  = (Get-ItemProperty "HKCU:\Control Panel\Desktop" -EA SilentlyContinue).ScreenSaverIsSecure
$ssTimeout = (Get-ItemProperty "HKCU:\Control Panel\Desktop" -EA SilentlyContinue).ScreenSaveTimeOut
if ($ssActive -eq "1" -and $ssSecure -eq "1") {
    $tout = if ($ssTimeout) { "${ssTimeout}초" } else { "기본값" }
    Pass "085" "화면보호기 활성($tout) 및 잠금 설정됨"
} elseif ($ssActive -eq "1") {
    Fail "085" "화면보호기 활성이나 잠금 미설정 (ScreenSaverIsSecure=0)"
} else {
    Fail "085" "화면보호기 비활성화됨 (ScreenSaveActive=$ssActive)"
}

# WST-086: 자동 로그온 방지
Evd "WST-086" "Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name AutoAdminLogon -EA SilentlyContinue | Select-Object AutoAdminLogon"
$autoLogon = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -EA SilentlyContinue).AutoAdminLogon
if ($autoLogon -eq "1") { Fail "086" "자동 로그온 활성화됨 (AutoAdminLogon=1) - 비활성화 권고" }
else { Pass "086" "자동 로그온 비활성화됨 (AutoAdminLogon=$autoLogon)" }

# WST-088: NTFS 파일 시스템 사용 여부
Evd "WST-088" "Get-Volume -EA SilentlyContinue | Where-Object {`$_.DriveType -eq 'Fixed' -and `$_.DriveLetter} | Select-Object DriveLetter,FileSystemType | Format-Table"
$nonNtfs = Get-Volume -EA SilentlyContinue | Where-Object {
    $_.FileSystemType -ne "NTFS" -and $_.FileSystemType -ne "ReFS" -and
    $_.DriveType -eq "Fixed" -and $_.DriveLetter
}
if ($nonNtfs) {
    $ntfsList = ($nonNtfs | ForEach-Object { "$($_.DriveLetter):($($_.FileSystemType))" }) -join ', '
    Fail "088" "NTFS/ReFS 미사용 드라이브: $ntfsList"
} else {
    Pass "088" "모든 고정 드라이브 NTFS/ReFS 사용 중"
}

# WST-094: 로그온 화면에서 시스템 종료 버튼 비활성화
Evd "WST-094" "Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name ShutdownWithoutLogon -EA SilentlyContinue | Select-Object ShutdownWithoutLogon"
$shutdownBtn = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -EA SilentlyContinue).ShutdownWithoutLogon
if ($shutdownBtn -eq 0) { Pass "094" "로그온 화면 종료 버튼 비활성화됨 (ShutdownWithoutLogon=0)" }
elseif ($shutdownBtn -eq 1) { Fail "094" "로그온 화면 종료 버튼 활성화됨 - 0으로 설정 권고" }
else { MC "094" "ShutdownWithoutLogon 설정 없음 - 수동 확인" }

# WST-098: 이동식 미디어 포맷 및 꺼내기 권한 (일반 사용자 제한)
EvdQ "WST-098" "SecPol AllocateDASD" (Get-SecPol "AllocateDASD")
$allocDrives = Get-SecPol "AllocateDASD"
if ($allocDrives -eq "0") { Pass "098" "이동식 미디어 접근 관리자만 허용 (AllocateDASD=0)" }
elseif ($allocDrives -eq "1") { MC "098" "이동식 미디어 접근 관리자 및 인터랙티브 사용자 허용 (AllocateDASD=1) - 수동 확인" }
else { MC "098" "이동식 미디어 포맷/꺼내기 정책 수동 확인" }

# Linux/Unix 전용 항목 N-A 처리 (058/064/082/083/090/100은 위에서 별도 자동 체크)
foreach ($code in @("010","011","012","013","014","015","022","061","062",
                    "065","066","067","068","069","070","077",
                    "091","092","093","108","110","111","112")) {
    NA $code "Windows 환경 미해당 (Linux/Unix 전용 항목)"
}

# ================================================================
# 고도화 자동 점검 항목 (Windows)
# ================================================================

# WST-034: TLS 1.0/1.1 비활성화 확인
Evd "WST-034" "Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' -Name Enabled -EA SilentlyContinue; Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -Name Enabled -EA SilentlyContinue"
$tls10 = Get-Reg "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" "Enabled"
$tls11 = Get-Reg "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" "Enabled"
$vulnTLS = @()
if ($null -eq $tls10 -or $tls10 -ne 0) { $vulnTLS += "TLS 1.0" }
if ($null -eq $tls11 -or $tls11 -ne 0) { $vulnTLS += "TLS 1.1" }
if ($vulnTLS) { Fail "034" "취약한 TLS 버전 활성: $($vulnTLS -join ', ') - 레지스트리로 비활성화 필요" }
else { Pass "034" "TLS 1.0/1.1 비활성화됨 (TLS 1.2+ 전용)" }

# WST-035: HTTP 보안 헤더 확인 (IIS)
Evd "WST-035" "Get-WebConfigurationProperty 'system.webServer/httpProtocol/customHeaders' -PSPath 'IIS:\' -Name 'Collection' -EA SilentlyContinue | Select-Object name,value | Format-Table"
if ($IIS_INSTALLED -and $HAS_WEB_ADMIN) {
    $customHeaders = Get-WebConfigurationProperty "system.webServer/httpProtocol/customHeaders" -PSPath "IIS:\" -Name "Collection" -EA SilentlyContinue
    $headerNames = if ($customHeaders) { $customHeaders | Select-Object -ExpandProperty name } else { @() }
    $missingHeaders = @()
    if ($headerNames -notcontains "X-Content-Type-Options") { $missingHeaders += "X-Content-Type-Options" }
    if ($headerNames -notcontains "X-Frame-Options" -and $headerNames -notcontains "Content-Security-Policy") { $missingHeaders += "X-Frame-Options" }
    if ($headerNames -notcontains "Strict-Transport-Security") { $missingHeaders += "HSTS" }
    if ($missingHeaders) { Fail "035" "HTTP 보안 헤더 미설정: $($missingHeaders -join ', ')" }
    else { Pass "035" "HTTP 보안 헤더 설정됨 (X-Content-Type-Options, X-Frame-Options, HSTS)" }
} else { MC "035" "HTTP 보안 헤더 수동 확인" }

# WST-037: Tomcat AJP 커넥터 노출 확인 (Ghostcat CVE-2020-1938)
if ($WAS_SRV -eq "tomcat" -and $TOMCAT_HOME -and (Test-Path "$TOMCAT_HOME\conf\server.xml")) {
    EvdQ "WST-037" "server.xml AJP connector" (($serverXml | Select-String 'AJP' | Out-String))
    $srvXml = Get-Content "$TOMCAT_HOME\conf\server.xml" -Raw -EA SilentlyContinue
    $srvXmlClean = $srvXml -replace "<!--[\s\S]*?-->",""
    if ($srvXmlClean -match 'protocol="AJP') {
        if ($srvXmlClean -match 'protocol="AJP[^"]*"[^>]*address="0\.0\.0\.0"') {
            Fail "037" "Tomcat AJP 전체 IP 바인딩 (Ghostcat 위험) - address=localhost 및 secret 설정 필요"
        } elseif ($srvXmlClean -match 'protocol="AJP[^"]*"[^>]*(secret|requiredSecret)=') {
            Pass "037" "Tomcat AJP secret 설정됨"
        } else {
            Fail "037" "Tomcat AJP secret 미설정 - Ghostcat(CVE-2020-1938) 취약"
        }
    } else {
        Pass "037" "Tomcat AJP 커넥터 비활성화됨"
    }
} elseif ($WAS_SRV -eq "tomcat") {
    MC "037" "Tomcat AJP 설정 수동 확인"
}

# WST-038: TRACE/TRACK 메서드 차단 (IIS)
Evd "WST-038" "Get-WebConfigurationProperty 'system.webServer/security/requestFiltering/verbs' -PSPath 'IIS:\' -Name 'Collection' -EA SilentlyContinue | Where-Object {`$_.verb -match 'TRACE|TRACK'} | Select-Object verb,allowed"
if ($IIS_INSTALLED -and $HAS_WEB_ADMIN) {
    $verbs = Get-WebConfigurationProperty "system.webServer/security/requestFiltering/verbs" -PSPath "IIS:\" -Name "Collection" -EA SilentlyContinue
    $traceDenied = $verbs | Where-Object { $_.verb -eq "TRACE" -and $_.allowed -eq $false }
    $trackDenied = $verbs | Where-Object { $_.verb -eq "TRACK" -and $_.allowed -eq $false }
    if ($traceDenied -or $trackDenied) { Pass "038" "TRACE/TRACK 메서드 차단됨 (Request Filtering)" }
    else { MC "038" "TRACE/TRACK 메서드 차단 수동 확인 (요청 필터링에서 명시 차단 권고)" }
} else { MC "038" "TRACE/TRACK 메서드 차단 수동 확인" }

# WST-040: SSL 인증서 만료 확인 (IIS)
Evd "WST-040" "Get-ChildItem 'IIS:\Sites' -EA SilentlyContinue | ForEach-Object { `$_.Bindings.Collection | Where-Object {`$_.protocol -eq 'https'} } | Select-Object bindingInformation,certificateHash"
if ($IIS_INSTALLED -and $HAS_WEB_ADMIN) {
    $sites = Get-ChildItem "IIS:\Sites" -EA SilentlyContinue
    $expiring = @()
    foreach ($site in $sites) {
        $bindings = $site.Bindings.Collection | Where-Object { $_.protocol -eq "https" }
        foreach ($b in $bindings) {
            $thumbprint = $b.certificateHash
            if ($thumbprint) {
                $cert = Get-ChildItem "Cert:\LocalMachine\My\$thumbprint" -EA SilentlyContinue
                if ($cert) {
                    $daysLeft = ($cert.NotAfter - (Get-Date)).Days
                    if ($daysLeft -le 0) { $expiring += "$($site.Name)(만료됨)" }
                    elseif ($daysLeft -le 30) { $expiring += "$($site.Name)(${daysLeft}일 남음)" }
                }
            }
        }
    }
    if ($expiring) { Fail "040" "SSL 인증서 만료 임박/만료: $($expiring -join ', ')" }
    else { Pass "040" "SSL 인증서 유효 (30일 이상 잔여)" }
} else { MC "040" "SSL 인증서 만료일 수동 확인" }

# secedit 임시 파일 정리
if (Test-Path $secTmp) { Remove-Item $secTmp -Force -EA SilentlyContinue }

# ================================================================
# 수동확인 항목 일괄 출력 (자동 체크 불가 항목)
# ================================================================
$manualCodes = @(
    "001","002","003","004","005","006","007","008","009",
    "018","021",
    "032",
    "041","042","043","045","046","047",
    "053","076","078","080","081",
    "089","095","096","097",
    "103","104","105","106",
    "113","114","115","116","117"
)
foreach ($code in $manualCodes) {
    MC $code "수동 확인 필요"
}

# ════════════════════════════════════════════════════════════════
# [3] 웹 고유 항목 — 평가기준 [웹서버-WAS] WIN(IIS) 판단기준·판단방법 기준
# ════════════════════════════════════════════════════════════════
$script:PHASE = "final"
$ahc = "$env:windir\System32\inetsrv\config\applicationHost.config"
$ahcTxt = if (Test-Path $ahc) { Get-Content $ahc -Raw -EA SilentlyContinue } else { "" }
$webRoots = @()
if ($HAS_WEB_ADMIN) { $webRoots = @(Get-ChildItem 'IIS:\Sites' -EA SilentlyContinue | ForEach-Object { [Environment]::ExpandEnvironmentVariables($_.physicalPath) } | Where-Object { $_ }) }
if (-not $webRoots -and (Test-Path "C:\inetpub\wwwroot")) { $webRoots = @("C:\inetpub\wwwroot") }
if ($TOMCAT_HOME) { $webRoots += "$TOMCAT_HOME\webapps" }
function Worse([string]$a,[string]$b) {
    $rk = @{ "취약"=4; "수동확인"=3; "양호"=2; "N-A"=1 }
    if (-not $a) { return $b }; if (-not $b) { return $a }
    $ra = ($a -split "\|",2)[0]; $rb = ($b -split "\|",2)[0]
    if ($rk[$rb] -gt $rk[$ra]) { return "$b / $(($a -split '\|',2)[1])" } else { return "$a / $(($b -split '\|',2)[1])" }
}
function EmitPair([string]$code,[string]$pair) { $p = $pair -split "\|",2; Emit $code $p[0] $p[1] }

if (-not $IIS_INSTALLED -and -not $WEB_SRV -and -not $WAS_SRV) {
    foreach ($c in @("032","033","034","035","037","038","040","041","042","043","044","124")) { NA $c "웹서버/WAS 미탐지" }   # 031·036·102·121~123·125 는 기존 IIS 점검(KEEP)에서 출력
} else {
    # WST-032: CGI 스크립트 관리 (CGI 모듈·스크립트 디렉터리 Everyone 권한)
    Evd "WST-032" "Get-WindowsFeature Web-CGI -EA SilentlyContinue | Select-Object Name,InstallState; icacls C:\inetpub\scripts 2>`$null"
    $cgi = Get-WindowsFeature Web-CGI -EA SilentlyContinue
    $scr = "C:\inetpub\scripts"
    $ev = if (Test-Path $scr) { (Get-Acl $scr).Access | Where-Object { $_.IdentityReference -match 'Everyone' -and $_.FileSystemRights -match 'Write|Modify|FullControl' } } else { $null }
    if ($ev) { Fail "032" "CGI 스크립트 디렉터리($scr)에 Everyone 쓰기 권한" }
    elseif ($cgi -and $cgi.InstallState -eq "Installed") { MC "032" "IIS CGI 기능 설치됨 - CGI 스크립트 목록·취약 스크립트 존재 여부 수동 확인" }
    else { Pass "032" "IIS CGI 기능 미설치 / 스크립트 디렉터리 Everyone 권한 없음" }

    # WST-033: 상위 경로 사용(enableParentPaths)
    Evd "WST-033" "Select-String -Path '$ahc' -Pattern 'enableParentPaths' -EA SilentlyContinue"
    if ($ahcTxt -match 'enableParentPaths="true"') { Fail "033" "ASP 상위 경로 사용(enableParentPaths=true) 활성화" }
    elseif ($IIS_INSTALLED) { Pass "033" "ASP 상위 경로 사용 비활성 (enableParentPaths 미설정/false, 기본값 false)" }
    else { MC "033" "$WEB_SRV$WAS_SRV 상위 디렉터리 접근 제한 수동 확인" }

    # WST-034: 샘플 디렉터리·임시/백업 파일
    Evd "WST-034" "foreach (`$r in @('$($webRoots -join "','")')) { Get-ChildItem `$r -Recurse -Depth 2 -Include *.bak,*.old,*.tmp,*.orig,*~ -EA SilentlyContinue | Select-Object -First 10 FullName }; Get-ChildItem 'IIS:\Sites\*' -EA SilentlyContinue | Get-ChildItem -EA SilentlyContinue | Where-Object Name -match 'IISSamples|IISHelp|iissamples|examples|docs'"
    $f34 = @()
    foreach ($r in $webRoots) { $f34 += @(Get-ChildItem $r -Recurse -Depth 2 -Include *.bak,*.old,*.tmp,*.orig,*~ -EA SilentlyContinue | Select-Object -First 3 | ForEach-Object FullName) }
    if ($ahcTxt -match 'IISSamples|IISHelp') { $f34 += "IISSamples/IISHelp 가상 디렉터리" }
    if ($TOMCAT_HOME -and (Test-Path "$TOMCAT_HOME\webapps\examples")) { $f34 += "Tomcat webapps\examples" }
    if ($f34.Count -gt 0) { Fail "034" "불필요 파일/샘플 존재: $($f34 -join ', ')" } else { Pass "034" "샘플 디렉터리·임시/백업 파일 미발견" }

    # WST-035: 업로드/다운로드 용량 제한 (maxAllowedContentLength, bufferingLimit, maxRequestEntityAllowed)
    Evd "WST-035" "Select-String -Path '$ahc' -Pattern 'maxAllowedContentLength|bufferingLimit|maxRequestEntityAllowed' -EA SilentlyContinue"
    if ($IIS_INSTALLED) {
        if ($ahcTxt -match 'maxAllowedContentLength=|maxRequestEntityAllowed=|bufferingLimit=') { Pass "035" "IIS 업로드/다운로드 용량 제한 설정됨 (requestLimits/ASP limits)" }
        else { MC "035" "IIS 명시적 용량 제한 설정 없음 (기본 maxAllowedContentLength 30MB 적용) - 업무 기준 대비 적정성 확인" }
    } else { MC "035" "$WEB_SRV$WAS_SRV 용량 제한(LimitRequestBody/maxPostSize) 수동 확인" }

    # WST-036: 웹 서비스 프로세스 권한 (App Pool LocalSystem) — 기존 점검(_KEEP) 결과 사용

    # WST-037: 웹 서비스 경로 (업무 영역 미분리 경로·IISAdmin/IISAdmpwd)
    Evd "WST-037" "Get-ChildItem 'IIS:\Sites' -EA SilentlyContinue | Select-Object Name,physicalPath; Select-String -Path '$ahc' -Pattern 'IISAdmin|IISAdmpwd' -EA SilentlyContinue"
    $bad37 = @($webRoots | Where-Object { $_ -match '^[A-Za-z]:\\?$' -or $_ -match '^[A-Za-z]:\\(Windows|Program Files|Users)\\?$' })
    if ($ahcTxt -match 'IISAdmin|IISAdmpwd') { $bad37 += "IISAdmin/IISAdmpwd 경로" }
    if ($bad37.Count -gt 0) { Fail "037" "업무 영역과 분리되지 않은/불필요 경로: $($bad37 -join ', ')" } else { Pass "037" "웹 서비스 경로 분리됨: $($webRoots -join ', ')" }

    # WST-038: 웹 경로 내 바로가기(.lnk) 파일
    Evd "WST-038" "foreach (`$r in @('$($webRoots -join "','")')) { Get-ChildItem `$r -Recurse -Filter *.lnk -EA SilentlyContinue | Select-Object -First 10 FullName }"
    $lnk = @(); foreach ($r in $webRoots) { $lnk += @(Get-ChildItem $r -Recurse -Filter *.lnk -EA SilentlyContinue | Select-Object -First 3 | ForEach-Object FullName) }
    if ($lnk.Count -gt 0) { Fail "038" "웹 서비스 경로 내 바로가기 파일: $($lnk -join ', ')" } else { Pass "038" "웹 서비스 경로 내 바로가기(.lnk) 파일 없음" }

    # WST-040: 설정 파일 노출 방지 (.asa 매핑 / requestFiltering)
    Evd "WST-040" "Select-String -Path '$ahc' -Pattern '\.asa|hiddenSegments' -EA SilentlyContinue | Select-Object -First 10"
    if ($ahcTxt -match 'fileExtension="\.asa"\s+allowed="false"' -or $ahcTxt -match 'path="\*\.asa"') { Pass "040" ".asa 요청 차단/매핑 존재 (설정 파일 미노출)" }
    elseif ($IIS_INSTALLED) { MC "040" ".asa 매핑·requestFiltering 차단 확인 필요 - 설정 파일 경로 요청 시 노출 여부 수동 확인" }
    else { MC "040" "$WEB_SRV$WAS_SRV 설정 파일 노출 방지 수동 확인" }

    # WST-041: 웹 경로 내 파일 Everyone 과도 권한 (정적 파일 읽기만은 양호)
    Evd "WST-041" "foreach (`$r in @('$($webRoots -join "','")')) { icacls `$r }"
    $bad41 = @()
    foreach ($r in $webRoots) { $a = Get-Acl $r -EA SilentlyContinue; if ($a) { $a.Access | Where-Object { $_.IdentityReference -match 'Everyone' -and $_.FileSystemRights -match 'Write|Modify|FullControl' } | ForEach-Object { $bad41 += "$r(Everyone:$($_.FileSystemRights))" } } }
    if ($bad41.Count -gt 0) { Fail "041" "웹 디렉터리 Everyone 과도 권한: $($bad41 -join ', ')" } else { Pass "041" "웹 디렉터리 Everyone 쓰기/수정 권한 없음" }

    # WST-042: 불필요한 스크립트 매핑 (.htr .idc .stm .shtm .shtml .printer .htw .ida .idq)
    Evd "WST-042" "Select-String -Path '$ahc' -Pattern 'path=`"\*\.(htr|idc|stm|shtm|shtml|printer|htw|ida|idq)`"' -EA SilentlyContinue"
    $maps = [regex]::Matches($ahcTxt, 'path="\*\.(htr|idc|stm|shtm|shtml|printer|htw|ida|idq)"') | ForEach-Object { ".$($_.Groups[1].Value)" } | Select-Object -Unique
    if ($maps) { Fail "042" "취약한 스크립트 매핑 존재: $($maps -join ', ')" } elseif ($IIS_INSTALLED) { Pass "042" "취약한 스크립트 매핑 없음" } else { NA "042" "IIS 미설치" }

    # WST-043: 서버 명령 실행 제한 (IIS 7.0 이상 또는 SSIEnableCmdDirective=0 → 양호)
    $ssiCmd = Get-Reg "HKLM:\SYSTEM\CurrentControlSet\Services\W3SVC\Parameters" "SSIEnableCmdDirective"
    EvdQ "WST-043" "IIS 버전 / SSIEnableCmdDirective" "$IIS_VERSION / $ssiCmd"
    $iisMaj = if ($IIS_VERSION -match '^(\d+)') { [int]$Matches[1] } else { 0 }
    if (-not $IIS_INSTALLED) { NA "043" "IIS 미설치" }
    elseif ($iisMaj -ge 7 -or "$ssiCmd" -eq "0") { Pass "043" "서버 명령 실행 제한 (IIS $IIS_VERSION / SSIEnableCmdDirective=$ssiCmd)" }
    else { Fail "043" "IIS $IIS_VERSION 이면서 SSIEnableCmdDirective≠0 (서버 명령 실행 허용)" }

    # WST-044: 웹 서비스 기본 계정 (Tomcat tomcat-users.xml / JEUS)
    $tu = if ($TOMCAT_HOME) { "$TOMCAT_HOME\conf\tomcat-users.xml" } else { "" }
    Evd "WST-044" "if ('$tu' -and (Test-Path '$tu')) { Select-String -Path '$tu' -Pattern '<user ' }"
    if ($tu -and (Test-Path $tu)) {
        $x = (Get-Content $tu -Raw) -replace '(?s)<!--.*?-->',''
        $users = [regex]::Matches($x, '<user\s[^>]*>')
        $def = @($users | Where-Object { $_.Value -match 'password="(tomcat|admin|s3cret|password|role1|both|manager|1234|123456|<must-be-changed>)"' -or $_.Value -match 'username="(tomcat|admin|both|role1)"' })
        if ($def.Count -gt 0) { Fail "044" "Tomcat 기본/유추 가능 계정: $(($def | ForEach-Object { if ($_.Value -match 'username="([^"]*)"') { $Matches[1] } }) -join ', ')" }
        elseif ($users.Count -gt 0) { Pass "044" "Tomcat 관리 계정 디폴트 값 아님 ($($users.Count)개)" }
        else { Pass "044" "Tomcat 활성 관리 계정 없음" }
    } elseif ($WAS_SRV -eq "jeus") { MC "044" "JEUS 관리자 계정/비밀번호 디폴트 여부 수동 확인" }
    else { NA "044" "관리 계정을 사용하는 WAS(Tomcat/JEUS) 미탐지" }

    # WST-124: LDAP 알고리즘 (SCHANNEL 프로토콜·암호)
    Evd "WST-124" "Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols' -Recurse -EA SilentlyContinue | Get-ItemProperty -EA SilentlyContinue | Select-Object PSPath,Enabled,DisabledByDefault"
    MC "124" "LDAP/LDAPS 연동 시 SCHANNEL(TLS1.0/1.1·RC4/3DES) 비활성 및 단순/익명 바인드 금지 여부 수동 확인"
}

# WST-039: 불필요한 웹 서비스 실행 여부
Evd "WST-039" "Get-Service W3SVC,WAS,Apache*,Tomcat* -EA SilentlyContinue | Select-Object Name,Status"
$run39 = @(Get-Service W3SVC,Apache*,Tomcat*,nginx -EA SilentlyContinue | Where-Object Status -eq 'Running' | ForEach-Object Name)
if ($run39.Count -gt 0) { MC "039" "실행 중인 웹 서비스: $($run39 -join ', ') - 업무상 필요 여부 확인" } else { Pass "039" "실행 중인 웹 서비스 없음" }

# WST-080: 보안패치 (OS 판정 + 웹 제품)
EvdQ "WST-080" "IIS/Tomcat 버전" "IIS $IIS_VERSION / Tomcat $TOMCAT_HOME"
MergeHold "WST-080" "수동확인" "웹 제품 보안패치 확인 필요 (IIS $IIS_VERSION$(if ($TOMCAT_HOME) { " / Tomcat $TOMCAT_HOME" })) - 벤더 보안 공지 대조"

# WST-126: EoS (OS 판정 + 웹 제품)
$w126 = if ($IIS_INSTALLED) { "양호|IIS $IIS_VERSION (OS 지원 수명 종속)" } elseif ($WEB_SRV -or $WAS_SRV) { "수동확인|$WEB_SRV $WAS_SRV 버전 EoS 수동 확인" } else { "" }
if ($w126) { MergeHold "WST-126" (($w126 -split '\|',2)[0]) (($w126 -split '\|',2)[1]) } else { MergeHold "WST-126" "" "" }

# 평가기준상 WIN 평가대상이 아닌 항목 중 미출력 항목 N-A
$emitted = @(Get-Content $script:EVD -EA SilentlyContinue | Select-String '^\[판정\] (WST-\d{3})' | ForEach-Object { $_.Matches[0].Groups[1].Value })
foreach ($code in $script:NA_WIN_WST) { if ($emitted -notcontains $code) { Emit $code "N-A" "평가대상 아님 (WIN 해당 없음 - 평가기준 평가대상 열)" } }


# ════════════════════════════════════════════════════════════════
# [4] 주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드(2026) — 웹 서비스 WEB-01 ~ WEB-26 (IIS)
#     IIS 7+ 설정(applicationHost.config + 사이트 루트 web.config)을 가이드 점검 방법대로 판정
#     가이드 점검 대상에 IIS 가 없는 항목(WEB-01·17·23)은 N-A, Windows 용 Apache·Nginx·Tomcat 은 수동확인
# ════════════════════════════════════════════════════════════════
if ($script:KMODE -ne 'ef') {
$script:PHASE = 'final'
$ahPath = if ($env:IIS_APPHOST) { $env:IIS_APPHOST } else { "$env:windir\System32\inetsrv\config\applicationHost.config" }   # IIS_APPHOST: 점검자 검증용 설정 경로
$IISX = $null; if (Test-Path $ahPath) { try { $IISX = [xml](Read-AllText $ahPath) } catch {} }
$iisK = [bool]($IIS_INSTALLED -or $env:IIS_APPHOST)
$others = @(@($(if ($WEB_SRV -and $WEB_SRV -ne 'iis') { $WEB_SRV }), $(if ($WAS_SRV) { $WAS_SRV })) | Where-Object { $_ })
function KisaTarget([string]$code) {   # 가이드 점검 대상에 IIS 포함 여부
    return @('WEB-01','WEB-17','WEB-23') -notcontains $code
}
$ksites = @()
if ($IISX) {
    $sd = $IISX.configuration.'system.applicationHost'.sites
    foreach ($s in @($sd.site)) {
        if (-not $s) { continue }
        $app = @($s.application) | Where-Object { $_.path -eq '/' } | Select-Object -First 1
        $vd = if ($app) { @($app.virtualDirectory) | Where-Object { $_.path -eq '/' } | Select-Object -First 1 } else { $null }
        $pool = if ($app -and $app.applicationPool) { $app.applicationPool } elseif ($sd.applicationDefaults.applicationPool) { $sd.applicationDefaults.applicationPool } else { 'DefaultAppPool' }
        $ksites += New-Object PSObject -Property @{ Name = $s.name; Root = $(if ($vd) { [Environment]::ExpandEnvironmentVariables("$($vd.physicalPath)") } else { '' })
            Bind = @(@($s.bindings.binding) | Where-Object { $_ } | ForEach-Object { "$($_.protocol)://$($_.bindingInformation)" }); Pool = $pool }
    }
}
function WsNodes($site) {   # system.webServer 노드: 사이트 web.config → location → 전역 (우선순위 순)
    $out = @()
    if ($site.Root) { $wc = Join-Path $site.Root 'web.config'; if (Test-Path $wc) { try { $x = [xml](Read-AllText $wc); if ($x.configuration.'system.webServer') { $out += $x.configuration.'system.webServer' } } catch {} } }
    foreach ($l in @($IISX.configuration.location)) { if ($l -and ("$($l.path)" -eq $site.Name -or "$($l.path)" -like "$($site.Name)/*") -and $l.'system.webServer') { $out += $l.'system.webServer' } }
    if ($IISX.configuration.'system.webServer') { $out += $IISX.configuration.'system.webServer' }
    return $out
}
function WsVal($site, [scriptblock]$f) { foreach ($n in @(WsNodes $site)) { $v = & $f $n; if ("$v" -ne '') { return "$v" } }; return $null }
function WsHandlers($site) { $h = @(); foreach ($n in @(WsNodes $site)) { $h += @($n.handlers.add | Where-Object { $_ } | ForEach-Object { "$($_.path)" }) }; return ($h | Select-Object -Unique) }
function KRes([string]$code, [string]$r) {   # IIS 판정 + 다른 Windows 웹 제품(가이드 대상) 병합 출력
    if (-not $iisK -and -not $others.Count) { NA $code '웹서버/WAS 미탐지'; return }
    if (-not (KisaTarget $code)) {
        if ($others.Count) { $r = "수동확인|Windows 용 $($others -join ', ') - 가이드 점검 방법으로 설정 파일 수동 확인" } else { NA $code "가이드 점검 대상($(@{ 'WEB-01'='Tomcat, JEUS'; 'WEB-17'='Apache, Tomcat, Nginx, WebtoB'; 'WEB-23'='Tomcat' }[$code])) 제품 미탐지 (탐지: IIS)"; return }
    } elseif ($others.Count) { $r = WorseR $r "수동확인|Windows 용 $($others -join ', ') 설정은 가이드 점검 방법으로 수동 확인" }
    if (-not $r) { $r = '수동확인|IIS 설정 확인 불가' }
    $p = $r -split '\|',2; Emit $code $p[0] $p[1]
}
$cfgOK = [bool]$IISX
$noCfg = "수동확인|IIS 설정 파일($ahPath) 없음/파싱 실패 - IIS 관리자에서 확인"
EvdQ "WEB-04" "IIS 사이트 (이름 / 실제 경로 / 바인딩 / 응용 프로그램 풀)" (($ksites | ForEach-Object { "$($_.Name) / $($_.Root) / $($_.Bind -join ',') / $($_.Pool)" }) -join "`n")

# WEB-01 기본 관리자 계정명 (대상: Tomcat·JEUS)
KRes 'WEB-01' ''
# WEB-02 취약한 비밀번호 사용 제한 (IIS: 관리 계정 = Windows 계정)
KRes 'WEB-02' $(if ($iisK) { '수동확인|IIS 관리는 Windows 계정 사용 - 관리자 비밀번호 복잡도(2종 10자/3종 8자)·유추 어려움 확인 (Windows 서버 W-01·W-09 참고)' })
# WEB-03 비밀번호 파일 권한 (IIS: SAM 파일 Administrators·SYSTEM 만)
$sam = "$env:SystemRoot\System32\config\SAM"; $a03 = Get-Acl $sam -EA SilentlyContinue
EvdQ "WEB-03" "$sam ACL" "$(if ($a03) { ($a03.Access | ForEach-Object { "$($_.IdentityReference) $($_.FileSystemRights)" }) -join "`n" } else { '조회 불가' })"
$r = if (-not $iisK) { '' } elseif (-not $a03) { '수동확인|SAM 파일 권한 조회 불가(관리자 권한 필요) - Administrators·SYSTEM 외 권한 확인' } else {
    $x03 = @($a03.Access | Where-Object { @('S-1-5-18','S-1-5-32-544') -notcontains (Get-AceSid $_) } | ForEach-Object { "$($_.IdentityReference)" })
    if ($x03.Count) { "취약|SAM 파일에 Administrators·SYSTEM 외 권한: $($x03 -join ', ')" } else { '양호|SAM 파일 권한 Administrators·SYSTEM 만' } }
KRes 'WEB-03' $r

# WEB-04 디렉터리 리스팅 방지 (directoryBrowse enabled)
$r = if (-not $iisK) { '' } elseif (-not $cfgOK) { $noCfg } else {
    $on = @($ksites | Where-Object { (WsVal $_ { param($n) $n.directoryBrowse.enabled }) -eq 'true' } | ForEach-Object { $_.Name })
    if ($on.Count) { "취약|디렉터리 검색 사용: $($on -join ', ')" } else { '양호|디렉터리 검색 사용 안 함 (전 사이트)' } }
KRes 'WEB-04' $r

# WEB-05 지정하지 않은 CGI/ISAPI 실행 제한 (ISAPI 및 CGI 제한)
$icr = if ($IISX) { $IISX.configuration.'system.webServer'.security.isapiCgiRestriction } else { $null }
EvdQ "WEB-05" "isapiCgiRestriction (notListedIsapisAllowed / notListedCgisAllowed / 허용 항목)" "$(if ($icr) { "$($icr.notListedIsapisAllowed) / $($icr.notListedCgisAllowed) / $((@($icr.add) | Where-Object { $_ -and $_.allowed -eq 'true' } | ForEach-Object { $_.description + '=' + $_.path }) -join '; ')" })"
$r = if (-not $iisK) { '' } elseif (-not $cfgOK) { $noCfg } else {
    $nl = @(); if ($icr -and $icr.notListedIsapisAllowed -eq 'true') { $nl += 'ISAPI' }; if ($icr -and $icr.notListedCgisAllowed -eq 'true') { $nl += 'CGI' }
    $al = @(@($icr.add) | Where-Object { $_ -and $_.allowed -eq 'true' } | ForEach-Object { if ($_.description) { $_.description } else { Split-Path $_.path -Leaf } })
    if ($nl.Count) { "취약|지정하지 않은 $($nl -join '·') 모듈 실행 허용 (notListed*Allowed=true)" } elseif ($al.Count) { "수동확인|허용된 ISAPI/CGI 모듈: $($al -join ', ') - 사용하지 않는 모듈 허용 해제 여부 확인" } else { '양호|허용된 ISAPI/CGI 모듈 없음' } }
KRes 'WEB-05' $r

# WEB-06 상위 디렉터리 접근 제한 (ASP 부모 경로 사용 False)
$r = if (-not $iisK) { '' } elseif (-not $cfgOK) { $noCfg } else {
    $pp = @($ksites | Where-Object { (WsVal $_ { param($n) $n.asp.enableParentPaths }) -eq 'true' } | ForEach-Object { $_.Name })
    if ($pp.Count) { "취약|ASP 부모 경로 사용(enableParentPaths=true): $($pp -join ', ')" } else { '양호|부모 경로 사용 안 함 (enableParentPaths 기본 false)' } }
KRes 'WEB-06' $r

# WEB-07 웹 서비스 경로 내 불필요한 파일 (IIS 샘플 디렉터리)
$smp = @("$env:SystemDrive\inetpub\iissamples","$env:SystemRoot\help\iishelp","$env:ProgramFiles\Common Files\System\msadc\Samples","$env:SystemRoot\System32\Inetsrv\IISADMPWD") | Where-Object { Test-Path $_ }
EvdQ "WEB-07" "IIS 샘플 디렉터리" ($smp -join "`n")
KRes 'WEB-07' $(if (-not $iisK) { '' } elseif ($smp.Count) { "취약|샘플 디렉터리 존재: $($smp -join ', ')" } else { '양호|IIS 샘플 디렉터리 없음' })

# WEB-08 업로드·다운로드 용량 제한 (maxAllowedContentLength, 기본 30MB)
$r = if (-not $iisK) { '' } elseif (-not $cfgOK) { $noCfg } else {
    $lim = @($ksites | ForEach-Object { $v = WsVal $_ { param($n) $n.security.requestFiltering.requestLimits.maxAllowedContentLength }; "$($_.Name)=$(if ($v) { "$([math]::Round([double]$v/1MB,1))MB" } else { '기본 30MB' })" })
    $big = @($ksites | Where-Object { $v = WsVal $_ { param($n) $n.security.requestFiltering.requestLimits.maxAllowedContentLength }; $v -and [double]$v -ge 4294967295 } | ForEach-Object { $_.Name })
    if ($big.Count) { "취약|요청 크기 제한 해제(최대값 4GB): $($big -join ', ')" } else { "양호|요청 크기 제한: $($lim -join ', ')" } }
KRes 'WEB-08' $r

# WEB-09 웹 서비스 프로세스 권한 (응용 프로그램 풀 ID - LocalSystem 취약)
$r = if (-not $iisK) { '' } elseif (-not $cfgOK) { $noCfg } else {
    $apd = $IISX.configuration.'system.applicationHost'.applicationPools
    $defId = if ($apd.applicationPoolDefaults.processModel.identityType) { $apd.applicationPoolDefaults.processModel.identityType } else { 'ApplicationPoolIdentity' }
    $pools = @(@($apd.add) | Where-Object { $_ } | ForEach-Object { New-Object PSObject -Property @{ N = $_.name; Id = $(if ($_.processModel.identityType) { $_.processModel.identityType } else { $defId }); U = $_.processModel.userName } })
    EvdQ "WEB-09" "응용 프로그램 풀 ID" (($pools | ForEach-Object { "$($_.N): $($_.Id) $($_.U)" }) -join "`n")
    $ls = @($pools | Where-Object { $_.Id -eq 'LocalSystem' } | ForEach-Object { $_.N }); $su = @($pools | Where-Object { $_.Id -eq 'SpecificUser' } | ForEach-Object { "$($_.N)($($_.U))" })
    if ($ls.Count) { "취약|관리자 권한(LocalSystem)으로 구동하는 응용 프로그램 풀: $($ls -join ', ')" } elseif ($su.Count) { "수동확인|특정 사용자로 구동: $($su -join ', ') - 관리자 그룹 소속 여부 확인 (권고: ApplicationPoolIdentity)" } else { "양호|응용 프로그램 풀 ID: $((($pools | ForEach-Object { $_.Id }) | Select-Object -Unique) -join ', ')" } }
KRes 'WEB-09' $r

# WEB-10 불필요한 프록시 설정 (ARR proxy / 외부 rewrite)
$r = if (-not $iisK) { '' } elseif (-not $cfgOK) { $noCfg } else {
    $px = "$($IISX.configuration.'system.webServer'.proxy.enabled)" -eq 'true'
    $rw = @($ksites | Where-Object { @(WsNodes $_ | ForEach-Object { @($_.rewrite.rules.rule) } | Where-Object { $_ -and "$($_.action.type)" -eq 'Rewrite' -and "$($_.action.url)" -match '^https?://' }).Count } | ForEach-Object { $_.Name })
    if ($px -or $rw.Count) { "수동확인|프록시 설정: $(if ($px) { 'ARR proxy enabled ' })$(if ($rw.Count) { "외부 URL Rewrite: $($rw -join ', ')" }) - 업무상 필요 여부 확인 (불필요 시 취약)" } else { '양호|프록시(ARR)·외부 Rewrite 설정 없음' } }
KRes 'WEB-10' $r

# WEB-11 웹 서비스 경로 설정 (시스템·기본 경로)
$r = if (-not $iisK) { '' } elseif (-not $cfgOK) { $noCfg } else {
    $sys = @($ksites | Where-Object { $_.Root -and ($_.Root.TrimEnd('\') -match '^[A-Za-z]:$' -or $_.Root -match '^[A-Za-z]:\\(Windows|Program Files|Users)(\\|$)') } | ForEach-Object { "$($_.Name)($($_.Root))" })
    $def = @($ksites | Where-Object { $_.Root -match '\\inetpub\\wwwroot\\?$' } | ForEach-Object { "$($_.Name)($($_.Root))" })
    if ($sys.Count) { "취약|웹 서비스 경로가 시스템 영역과 분리되지 않음: $($sys -join ', ')" } elseif ($def.Count) { "수동확인|설치 기본 경로 사용: $($def -join ', ') - 업무 영역 분리·불필요 경로 확인 (가이드 조치: 별도 경로 지정)" } else { "양호|별도 웹 서비스 경로 사용: $(($ksites | ForEach-Object { $_.Root }) -join ', ')" } }
KRes 'WEB-11' $r

# WEB-12 웹 서비스 링크 사용 금지 (홈 디렉터리 바로가기 .lnk)
$lnk = @(); foreach ($s in $ksites) { if ($s.Root -and (Test-Path $s.Root)) { $lnk += @(Get-ChildItem $s.Root -Recurse -Filter *.lnk -EA SilentlyContinue | Select-Object -First 5 | ForEach-Object { $_.FullName }) } }
EvdQ "WEB-12" "홈 디렉터리 바로가기(.lnk)" ($lnk -join "`n")
KRes 'WEB-12' $(if (-not $iisK) { '' } elseif (-not $cfgOK) { $noCfg } elseif ($lnk.Count) { "취약|홈 디렉터리 바로가기 파일: $($lnk -join ', ')" } else { '양호|홈 디렉터리 바로가기 파일 없음' })

# WEB-13 설정 파일 노출 제한 (*.asa/*.asax 매핑·요청 필터링 허용)
$r = if (-not $iisK) { '' } elseif (-not $cfgOK) { $noCfg } else {
    $m13 = @($ksites | Where-Object { @(WsHandlers $_ | Where-Object { $_ -match '^\*\.(asa|asax)$' }).Count } | ForEach-Object { $_.Name })
    $f13 = @($ksites | Where-Object { @(WsNodes $_ | ForEach-Object { @($_.security.requestFiltering.fileExtensions.add) } | Where-Object { $_ -and "$($_.fileExtension)" -match '^\.(asa|asax)$' -and "$($_.allowed)" -eq 'true' }).Count } | ForEach-Object { $_.Name })
    if ($m13.Count -or $f13.Count) { "취약|asa/asax $(if ($m13.Count) { "처리기 매핑: $($m13 -join ', ') " })$(if ($f13.Count) { "요청 필터링 허용: $($f13 -join ', ')" })" } else { '양호|asa/asax 처리기 매핑·요청 필터링 허용 없음' } }
KRes 'WEB-13' $r

# WEB-14 웹 서비스 경로 내 파일 접근 통제 (web.config·홈 디렉터리 Everyone 권한)
$e14 = @(); foreach ($s in $ksites) { foreach ($t in @($s.Root, $(if ($s.Root) { Join-Path $s.Root 'web.config' }))) { if ($t -and (Test-Path $t)) { $a = Get-Acl $t -EA SilentlyContinue; if ($a -and @($a.Access | Where-Object { (Get-AceSid $_) -eq 'S-1-1-0' -and "$($_.AccessControlType)" -eq 'Allow' }).Count) { $e14 += $t } } } }
EvdQ "WEB-14" "Everyone 권한이 있는 홈 디렉터리·web.config" ($e14 -join "`n")
KRes 'WEB-14' $(if (-not $iisK) { '' } elseif (-not $cfgOK) { $noCfg } elseif ($e14.Count) { "취약|Everyone 권한: $($e14 -join ', ')" } else { '양호|홈 디렉터리·web.config 에 Everyone 권한 없음' })

# WEB-15 불필요한 스크립트 매핑 (.htr .idc .stm .shtm .shtml .printer .htw .ida .idq)
$r = if (-not $iisK) { '' } elseif (-not $cfgOK) { $noCfg } else {
    $v15 = @($ksites | ForEach-Object { $n = $_.Name; @(WsHandlers $_ | Where-Object { $_ -match '^\*\.(htr|idc|stm|shtm|shtml|printer|htw|ida|idq)$' } | ForEach-Object { "${n}:$_" }) })
    if ($v15.Count) { "취약|취약한 스크립트 매핑: $($v15 -join ', ')" } else { '양호|취약한 스크립트 매핑 없음' } }
KRes 'WEB-15' $r

# WEB-16 헤더 정보 노출 제한 / WEB-22 에러 페이지 관리 (가이드 IIS: 사용자 지정 오류 페이지)
$r = if (-not $iisK) { '' } elseif (-not $cfgOK) { $noCfg } else {
    $nc = @($ksites | Where-Object { (WsVal $_ { param($n) $n.httpErrors.errorMode }) -ne 'Custom' } | ForEach-Object { "$($_.Name)($(if ($m = WsVal $_ { param($n) $n.httpErrors.errorMode }) { $m } else { 'DetailedLocalOnly 기본' }))" })
    if ($nc.Count) { "취약|'사용자 지정 오류 페이지' 미설정(errorMode): $($nc -join ', ')" } else { "양호|전 사이트 사용자 지정 오류 페이지(errorMode=Custom)" } }
$rsh = if ($IISX) { "$($IISX.configuration.'system.webServer'.security.requestFiltering.removeServerHeader)" -eq 'true' } else { $false }
KRes 'WEB-16' $(if ($r) { "$r$(if (-not $rsh) { ' / 참고: Server 응답 헤더 제거(removeServerHeader) 미설정' })" })
KRes 'WEB-22' $r
# WEB-17 가상 디렉터리 삭제 (대상: Apache·Tomcat·Nginx·WebtoB)
KRes 'WEB-17' ''

# WEB-18 WebDAV 비활성화
$r = if (-not $iisK) { '' } elseif (-not $cfgOK) { $noCfg } else {
    $dm = @($IISX.configuration.'system.webServer'.globalModules.add | Where-Object { $_ -and $_.name -eq 'WebDAVModule' }).Count
    $da = @($ksites | Where-Object { (WsVal $_ { param($n) $n.webdav.authoring.enabled }) -eq 'true' } | ForEach-Object { $_.Name })
    $di = @(@($icr.add) | Where-Object { $_ -and "$($_.path)" -match 'webdav' -and $_.allowed -eq 'true' })
    if ($dm -and ($da.Count -or $di.Count)) { "취약|WebDAV 활성: $(if ($da.Count) { "작성 사용 $($da -join ', ') " })$(if ($di.Count) { 'ISAPI 확장 허용' })" } elseif ($dm) { '양호|WebDAV 모듈 설치, 작성(authoring) 비활성' } else { '양호|WebDAV 모듈 미설치' } }
KRes 'WEB-18' $r

# WEB-19 SSI 사용 제한 (.shtml/.shtm/.stm 매핑)
$r = if (-not $iisK) { '' } elseif (-not $cfgOK) { $noCfg } else {
    $v19 = @($ksites | ForEach-Object { $n = $_.Name; @(WsHandlers $_ | Where-Object { $_ -match '^\*\.(shtml|shtm|stm)$' } | ForEach-Object { "${n}:$_" }) })
    if ($v19.Count) { "취약|SSI 확장자 매핑: $($v19 -join ', ')" } else { '양호|SSI 확장자(.shtml/.shtm/.stm) 매핑 없음' } }
KRes 'WEB-19' $r

# WEB-20 SSL/TLS 활성화 / WEB-21 HTTP 리디렉션
$lbn = ' (로드밸런서·프록시에서 TLS 종료 시 해당 구간 증빙으로 판단)'
$r20 = $null; $r21 = $null
if ($iisK -and $cfgOK) {
    $noS = @($ksites | Where-Object { -not @($_.Bind | Where-Object { $_ -like 'https://*' }).Count } | ForEach-Object { $_.Name })
    $r20 = if ($noS.Count) { "취약|HTTPS 바인딩 없는 사이트: $($noS -join ', ')$lbn" } else { '양호|전 사이트 HTTPS 바인딩' }
    $noR = @($ksites | Where-Object { $site = $_; $http = @($_.Bind | Where-Object { $_ -like 'http://*' }).Count
        $redir = ((WsVal $site { param($n) if ($n.httpRedirect.enabled -eq 'true') { $n.httpRedirect.destination } }) -match '^https://') -or
                 @(WsNodes $site | ForEach-Object { @($_.rewrite.rules.rule) } | Where-Object { $_ -and "$($_.action.type)" -eq 'Redirect' -and "$($_.action.url)" -match '^https://' }).Count -or
                 ((WsVal $site { param($n) $n.security.access.sslFlags }) -match 'Ssl')
        $http -and -not $redir } | ForEach-Object { $_.Name })
    $r21 = if ($noR.Count) { "취약|HTTP 접근 시 HTTPS 리디렉션 미설정: $($noR -join ', ')$lbn" } else { '양호|HTTP 바인딩 사이트 HTTPS 리디렉션(또는 SSL 필요) 설정' }
} elseif ($iisK) { $r20 = $noCfg; $r21 = $noCfg }
KRes 'WEB-20' $r20
KRes 'WEB-21' $r21

# WEB-23 LDAP 알고리즘 (대상: Tomcat)
KRes 'WEB-23' ''

# WEB-24 별도 업로드 경로 사용 및 권한
$up = @(); foreach ($s in $ksites) { if ($s.Root -and (Test-Path $s.Root)) { $up += @(Get-ChildItem $s.Root -Recurse -EA SilentlyContinue | Where-Object { $_.PSIsContainer -and $_.Name -match '^(upload|attach|userfile)' } | Select-Object -First 5 | ForEach-Object { $_.FullName }) } }
EvdQ "WEB-24" "홈 디렉터리 내 업로드 디렉터리" ($up -join "`n")
KRes 'WEB-24' $(if (-not $iisK) { '' } elseif ($up.Count) { "수동확인|웹 경로 내 업로드 디렉터리: $($up -join ', ') - 가이드: 웹 서비스 외부 경로 사용, 일반 사용자 권한 없음·실행 권한 제거 확인" } else { '수동확인|웹 경로 내 업로드 디렉터리 미발견 - 애플리케이션 업로드 경로(웹 외부)·권한 확인' })

# WEB-25 주기적 보안 패치
$iv = Get-Reg 'HKLM:\SOFTWARE\Microsoft\InetStp' 'VersionString'
KRes 'WEB-25' $(if ($iisK) { "수동확인|IIS $(if ($iv) { $iv } else { $IIS_VERSION }) - OS 누적 업데이트로 패치(Windows 서버 W-38) 적용 여부·패치 관리 정책 확인" })

# WEB-26 로그 디렉터리 및 파일 권한 (Everyone)
$ld = if ($IISX) { [Environment]::ExpandEnvironmentVariables("$($IISX.configuration.'system.applicationHost'.sites.siteDefaults.logFile.directory)") } else { '' }
if (-not $ld) { $ld = "$env:SystemDrive\inetpub\logs\LogFiles" }
$a26 = Get-Acl $ld -EA SilentlyContinue
EvdQ "WEB-26" "$ld ACL" "$(if ($a26) { ($a26.Access | ForEach-Object { "$($_.IdentityReference) $($_.FileSystemRights)" }) -join "`n" } else { '없음/조회 불가' })"
KRes 'WEB-26' $(if (-not $iisK) { '' } elseif (-not $a26) { "수동확인|IIS 로그 디렉터리($ld) 권한 조회 불가 - Everyone 권한 확인" } elseif (@($a26.Access | Where-Object { (Get-AceSid $_) -eq 'S-1-1-0' }).Count) { "취약|IIS 로그 디렉터리 Everyone 권한: $ld" } else { "양호|IIS 로그 디렉터리 Everyone 권한 없음: $ld" })
}

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
