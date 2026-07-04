# ================================================================
# 전자금융기반시설 서버(Windows) 취약점 점검 스크립트 v4.0
# 기준: 전자금융기반시설 보안 취약점 평가기준 제2026-1호 [서버]
# 지원: Windows Server 2012/2016/2019/2022
#
# [사용법] PowerShell (관리자)
#   Set-ExecutionPolicy RemoteSigned -Scope Process -Force
#   .\check_server.ps1 > C:\Temp\$env:COMPUTERNAME.txt
#
# [출력 형식] SRV-항목코드|결과|근거
# ================================================================
$ErrorActionPreference = "SilentlyContinue"
$ProgressPreference    = "SilentlyContinue"

$hn     = $env:COMPUTERNAME
$os     = (Get-CimInstance Win32_OperatingSystem -EA SilentlyContinue)
$build  = if ($os) { [int]$os.BuildNumber } else { 0 }
$ver    = switch ($build) {
    {$_ -le 9600}  {"2012R2"}; {$_ -le 14393} {"2016"}
    {$_ -le 17763} {"2019"};   default          {"2022+"}
}

Write-Output "# ================================================================"
Write-Output "# 점검 대상: $hn"
Write-Output "# OS: Windows Server $ver (Build $build)"
Write-Output "# 점검 기준: 전자금융기반시설 보안 취약점 평가기준 제2026-1호 [서버]"
Write-Output "# 점검 일시: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Output "# ================================================================"

# 헬퍼
$seceditFile = "$env:TEMP\srv_secpol.cfg"
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
function Get-SvcState([string]$Name) {
    try { $s=Get-Service -Name $Name -EA Stop; return @{Status=$s.Status.ToString();Start=$s.StartType.ToString()} }
    catch {
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
function Pass([string]$code,[string]$msg) { Write-Output "$code|양호|$msg" }
function Fail([string]$code,[string]$msg) { Write-Output "$code|취약|$msg" }
function NA([string]$code,[string]$msg)   { Write-Output "$code|N-A|$msg" }
function MC([string]$code,[string]$msg)   { Write-Output "$code|수동확인|$msg" }

# ── SRV-001: SNMP 버전 ───────────────────────────────────────────
$snmpSvc = Get-SvcState "SNMP"
if (-not $snmpSvc -or $snmpSvc.Status -notmatch "Running") {
    NA  "SRV-001" "SNMP 서비스 미실행"
} else {
    $snmpReg = Get-Reg "HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\ValidCommunities" $null
    $comm = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\ValidCommunities" -EA SilentlyContinue).PSObject.Properties | Where-Object {$_.Name -notmatch "^PS"}
    if ($comm) { Fail "SRV-001" "SNMP v1/v2c Community 사용 중: $($comm.Name -join ',')" }
    else { MC "SRV-001" "SNMP 실행 중 - 버전 및 설정 수동 확인" }
}

# ── SRV-013: Anonymous FTP ───────────────────────────────────────
$ftpSvc = Get-SvcState "MSFTPSVC"
if (-not $ftpSvc -or $ftpSvc.Status -notmatch "Running") {
    NA "SRV-013" "IIS FTP 서비스 미실행"
} else { MC "SRV-013" "FTP 서비스 실행 중 - Anonymous 접속 설정 수동 확인 (IIS Manager)" }

# ── SRV-018: 하드디스크 기본 공유 비활성화 ──────────────────────
$autoShare = Get-Reg "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" "AutoShareServer"
if ($null -ne $autoShare -and $autoShare -eq 0) {
    Pass "SRV-018" "AutoShareServer=0 (기본 공유 비활성화)"
} else {
    $shares = Get-SmbShare -EA SilentlyContinue | Where-Object { $_.Name -match '^\w\$$|^ADMIN\$|^IPC\$' }
    if ($shares) { Fail "SRV-018" "기본 공유 활성: $($shares.Name -join ',')" }
    else { Pass "SRV-018" "관리 공유 없음" }
}

# ── SRV-020: 공유 접근통제 ──────────────────────────────────────
try {
    $vuln = @()
    Get-SmbShare -EA Stop | Where-Object {$_.Name -notmatch "^IPC\$"} | ForEach-Object {
        $acl = Get-SmbShareAccess -Name $_.Name -EA SilentlyContinue
        if ($acl | Where-Object {$_.AccountName -match "Everyone" -and $_.AccessRight -ne "Deny"}) {
            $vuln += $_.Name
        }
    }
    if ($vuln) { Fail "SRV-020" "Everyone 접근 공유: $($vuln -join ',')" }
    else { Pass "SRV-020" "공유 폴더 Everyone 허용 없음" }
} catch { MC "SRV-020" "공유 접근통제 수동 확인" }

# ── SRV-022: 패스워드 미설정 계정 ──────────────────────────────
try {
    $noPw = Get-LocalUser -EA Stop | Where-Object {$_.PasswordRequired -eq $false -and $_.Enabled}
    if ($noPw) { Fail "SRV-022" "패스워드 미요구 계정: $($noPw.Name -join ',')" }
    else { Pass "SRV-022" "모든 계정 패스워드 요구" }
} catch { MC "SRV-022" "패스워드 미설정 계정 수동 확인" }

# ── SRV-023: 원격 터미널 암호화 (RDP NLA) ──────────────────────
$nla = Get-Reg "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" "UserAuthentication"
if ($nla -eq 1) { Pass "SRV-023" "RDP NLA(Network Level Authentication) 활성화됨" }
else { Fail "SRV-023" "RDP NLA 미설정 - 취약한 RDP 인증 가능" }

# ── SRV-024: 취약 Telnet 인증 ───────────────────────────────────
$telnet = Get-SvcState "TlntSvr"
if (-not $telnet -or $telnet.Status -notmatch "Running") {
    Pass "SRV-024" "Telnet 서비스 미실행"
} else { Fail "SRV-024" "Telnet 서비스 실행 중 (취약)" }

# ── SRV-026: root(관리자) 원격 접속 제한 ───────────────────────
# RDP 기본 포트 및 관리자 그룹 원격 접근 확인
$rdpGroup = Get-Reg "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" "fDenyTSConnections"
if ($rdpGroup -eq 1) { Pass "SRV-026" "RDP 원격 접속 비활성화됨" }
else { MC "SRV-026" "RDP 활성화 - 관리자 계정 원격 접속 허용 범위 수동 확인" }

# ── SRV-027: 서비스 접근 IP/포트 제한 (방화벽) ──────────────────
try {
    $fwProfiles = Get-NetFirewallProfile -EA Stop
    $disabled = $fwProfiles | Where-Object {-not $_.Enabled} | Select-Object -ExpandProperty Name
    if ($disabled) { Fail "SRV-027" "방화벽 비활성 프로파일: $($disabled -join ',')" }
    else { Pass "SRV-027" "Windows 방화벽 모든 프로파일 활성화" }
} catch {
    $fw = netsh advfirewall show allprofiles state 2>$null
    if ($fw -match "State\s+OFF") { Fail "SRV-027" "방화벽 비활성 프로파일 발견" }
    else { Pass "SRV-027" "방화벽 활성 (netsh)" }
}

# ── SRV-028: 세션 타임아웃 (화면 보호기 잠금) ──────────────────
$ssActive = Get-Reg "HKCU:\Control Panel\Desktop" "ScreenSaveActive"
$ssSecure = Get-Reg "HKCU:\Control Panel\Desktop" "ScreenSaverIsSecure"
if (-not $ssActive) {
    $ssActive = Get-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop" "ScreenSaveActive"
    $ssSecure = Get-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop" "ScreenSaverIsSecure"
}
if ($ssActive -eq "1" -and $ssSecure -eq "1") { Pass "SRV-028" "화면 보호기 + 암호 잠금 설정" }
elseif ($ssActive -eq "1") { Fail "SRV-028" "화면 보호기 활성, 암호 잠금 미설정" }
else { Fail "SRV-028" "화면 보호기(세션 타임아웃) 미설정" }

# ── SRV-029: SMB 세션 중단 ──────────────────────────────────────
$smbSign = Get-Reg "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" "RequireSecuritySignature"
if ($smbSign -eq 1) { Pass "SRV-029" "SMB 서명 필수 설정" }
else { Fail "SRV-029" "SMB 서명 미필수 (RequireSecuritySignature=0)" }

# ── SRV-031: 계정 목록 노출 방지 ───────────────────────────────
$ra = Get-Reg "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "RestrictAnonymous"
if ($null -ne $ra -and $ra -ge 1) { Pass "SRV-031" "RestrictAnonymous=$ra (익명 열거 제한)" }
else { Fail "SRV-031" "RestrictAnonymous=0 (계정 목록 노출 가능)" }

# ── SRV-034: 불필요 서비스 비활성화 ────────────────────────────
$dangerSvc = @(
    @{n="TlntSvr";d="Telnet"},@{n="RshSvc";d="RSH"},
    @{n="TFTPService";d="TFTP"},@{n="FTPSVC";d="FTP(IIS)"}
)
$found = @()
foreach ($svc in $dangerSvc) {
    $s = Get-SvcState $svc.n
    if ($s -and $s.Status -match "Running") { $found += $svc.d }
}
if ($found) { Fail "SRV-034" "불필요 서비스 실행: $($found -join ',')" }
else { Pass "SRV-034" "주요 불필요 서비스 미실행" }

# ── SRV-035: 취약 서비스 비활성화 (Telnet) ──────────────────────
$t = Get-SvcState "TlntSvr"
if ($t -and $t.Status -match "Running") { Fail "SRV-035" "Telnet 서비스 실행 중" }
else { Pass "SRV-035" "Telnet 서비스 미실행" }

# ── SRV-069: 패스워드 최대 사용기간 ────────────────────────────
$maxAge = Get-SecPol "MaximumPasswordAge"
if ($null -eq $maxAge) {
    $netOut = net accounts 2>$null
    $line = $netOut | Where-Object {$_ -match "Maximum password age|최대 암호"}
    if ($line) { $maxAge = ($line -replace "[^0-9]","").Trim() }
}
if ($null -ne $maxAge -and $maxAge -match "^\d+$") {
    $d = [int]$maxAge
    if ($d -eq 0) { Fail "SRV-069" "패스워드 최대 사용기간=무제한" }
    elseif ($d -le 90) { Pass "SRV-069" "패스워드 최대 사용기간=${d}일 (90일 이하)" }
    else { Fail "SRV-069" "패스워드 최대 사용기간=${d}일 (90일 초과)" }
} else { MC "SRV-069" "패스워드 최대 사용기간 확인 실패" }

# ── SRV-070: 패스워드 저장 방식 (LM 해시) ─────────────────────
$lm = Get-Reg "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "NoLMHash"
if ($null -ne $lm -and $lm -eq 1) { Pass "SRV-070" "LM 해시 저장 비활성화됨 (NoLMHash=1)" }
else { Fail "SRV-070" "LM 해시 저장 가능 (NoLMHash 미설정 또는 0)" }

# ── SRV-072: Administrator 계정명 변경 ──────────────────────────
try {
    $admin = Get-LocalUser -EA Stop | Where-Object {$_.SID.Value -match "-500$"} | Select-Object -First 1
    if ($admin) {
        if ($admin.Name -eq "Administrator") { Fail "SRV-072" "Administrator 기본 계정명 미변경" }
        else { Pass "SRV-072" "Administrator 계정명 변경됨: $($admin.Name)" }
    } else { MC "SRV-072" "기본 관리자 계정(SID-500) 확인 실패" }
} catch { MC "SRV-072" "계정명 확인 실패" }

# ── SRV-073: 관리자 그룹 불필요 사용자 ─────────────────────────
try {
    $members = net localgroup Administrators 2>$null | Where-Object {$_ -match "^[^-]" -and $_ -notmatch "^(Members|The|Alias|Comment|members|\s*$|---)"} | Select-Object -Skip 1
    $cnt = ($members | Where-Object {$_}).Count
    if ($cnt -gt 5) { Fail "SRV-073" "관리자 그룹 멤버 과다(${cnt}명) - 불필요 계정 제거 필요: $($members -join ',')" }
    else { Pass "SRV-073" "관리자 그룹 멤버(${cnt}명): $($members -join ',')" }
} catch { MC "SRV-073" "관리자 그룹 멤버 수동 확인" }

# ── SRV-075: 패스워드 복잡도 ───────────────────────────────────
$pwc = Get-SecPol "PasswordComplexity"
if ($null -ne $pwc -and $pwc.Trim() -eq "1") { Pass "SRV-075" "패스워드 복잡도 요구 활성 (=1)" }
elseif ($null -ne $pwc) { Fail "SRV-075" "패스워드 복잡도 비활성 (=0)" }
else { MC "SRV-075" "패스워드 복잡도 설정 확인 실패" }

# ── SRV-078: Guest 계정 비활성화 ───────────────────────────────
try {
    $guest = Get-LocalUser -Name "Guest" -EA Stop
    if ($guest.Enabled) { Fail "SRV-078" "Guest 계정 활성화됨" }
    else { Pass "SRV-078" "Guest 계정 비활성화됨" }
} catch { Pass "SRV-078" "Guest 계정 없음" }

# ── SRV-079: Everyone 부적절 권한 ──────────────────────────────
$evShare = $false
try {
    Get-SmbShare -EA Stop | Where-Object {$_.Name -notmatch "^IPC\$"} | ForEach-Object {
        $acl = Get-SmbShareAccess -Name $_.Name -EA SilentlyContinue
        if ($acl | Where-Object {$_.AccountName -match "Everyone" -and $_.AccessRight -eq "Full"}) { $evShare = $true }
    }
} catch {}
if ($evShare) { Fail "SRV-079" "공유 폴더에 Everyone Full Control 존재" }
else { Pass "SRV-079" "Everyone Full Control 미발견" }

# ── SRV-080: 프린터 드라이버 설치 제한 ─────────────────────────
$prt = Get-SecPol "AddPrinters"
if ($null -ne $prt -and $prt.Trim() -eq "0") { Pass "SRV-080" "일반 사용자 프린터 드라이버 설치 제한됨" }
else { Fail "SRV-080" "일반 사용자 프린터 드라이버 설치 허용 가능 (AddPrinters 확인)" }

# ── SRV-084: 시스템 주요 파일 권한 ─────────────────────────────
MC "SRV-084" "시스템 파일 권한은 수동 확인 필요 (icacls C:\Windows\system32 등)"

# ── SRV-090: 원격 레지스트리 서비스 ────────────────────────────
$rr = Get-SvcState "RemoteRegistry"
if ($null -eq $rr) { Pass "SRV-090" "RemoteRegistry 서비스 없음" }
elseif ($rr.Status -match "Running") { Fail "SRV-090" "원격 레지스트리 서비스 실행 중" }
elseif ($rr.Start -match "Disabled") { Pass "SRV-090" "원격 레지스트리 비활성화 (Disabled)" }
else { Pass "SRV-090" "원격 레지스트리 중지됨 ($($rr.Start))" }

# ── SRV-092: 사용자 홈 디렉토리 권한 ───────────────────────────
MC "SRV-092" "사용자 홈 디렉토리 권한 수동 확인 (icacls C:\Users\* 등)"

# ── SRV-097: FTP 디렉토리 접근권한 ─────────────────────────────
MC "SRV-097" "FTP 루트 디렉토리 접근권한 수동 확인"

# ── SRV-101: 불필요 예약 작업 ───────────────────────────────────
MC "SRV-101" "예약 작업 목록 수동 확인 (schtasks /query 또는 작업 스케줄러)"

# ── SRV-103: LAN Manager 인증 수준 ─────────────────────────────
$lm = Get-Reg "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "LmCompatibilityLevel"
if ($null -ne $lm -and $lm -ge 3) { Pass "SRV-103" "LM 인증 수준=${lm} (NTLMv2만 허용)" }
elseif ($null -ne $lm) { Fail "SRV-103" "LM 인증 수준=${lm} (3 이상 권고 - NTLMv2)" }
else { Fail "SRV-103" "LmCompatibilityLevel 미설정 (기본값=LM/NTLM 허용)" }

# ── SRV-104: 보안 채널 암호화 ───────────────────────────────────
$sc1 = Get-Reg "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" "RequireSignOrSeal"
$sc2 = Get-Reg "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" "SealSecureChannel"
if ($sc1 -eq 1 -and $sc2 -eq 1) { Pass "SRV-104" "보안 채널 서명/암호화 필수 설정됨" }
else { Fail "SRV-104" "보안 채널 서명/암호화 미설정 (RequireSignOrSeal=$sc1, SealSecureChannel=$sc2)" }

# ── SRV-105: 불필요 시작 프로그램 ──────────────────────────────
MC "SRV-105" "시작 프로그램 목록 수동 확인 (msconfig / 작업 관리자 시작프로그램 탭)"

# ── SRV-108: 로그 접근통제 ──────────────────────────────────────
MC "SRV-108" "이벤트 로그 접근 권한 수동 확인 (로컬 보안 정책 > 감사 정책)"

# ── SRV-109: 주요 이벤트 로그 설정 ─────────────────────────────
$logonAudit = Get-SecPol "AuditLogonEvents"
if ($null -eq $logonAudit) {
    try {
        $ap = auditpol /get /subcategory:"Logon" 2>$null
        if ($ap -match "Success|Failure") { $logonAudit = "3" }
    } catch {}
}
if ($null -ne $logonAudit -and $logonAudit -match "[1-9]") {
    Pass "SRV-109" "로그온 이벤트 감사 설정됨 (AuditLogonEvents=$logonAudit)"
} else { Fail "SRV-109" "로그온 이벤트 감사 미설정" }

# ── SRV-116: 감사 실패 시 시스템 종료 ──────────────────────────
$auditFail = Get-SecPol "CrashOnAuditFail"
if ($null -ne $auditFail -and $auditFail -eq "1") { Pass "SRV-116" "감사 실패 시 즉시 차단 설정됨" }
else { MC "SRV-116" "CrashOnAuditFail 설정 수동 확인 (보안 요구 수준에 따라 설정)" }

# ── SRV-118: 보안패치 ───────────────────────────────────────────
$hotfix = Get-HotFix -EA SilentlyContinue | Sort-Object InstalledOn -Descending | Select-Object -First 1
if ($hotfix) { MC "SRV-118" "최근 핫픽스: $($hotfix.HotFixID) ($($hotfix.InstalledOn))" }
else { MC "SRV-118" "보안패치 현황 수동 확인" }

# ── SRV-119: 백신 업데이트 ─────────────────────────────────────
try {
    $av = Get-CimInstance -Namespace "root/SecurityCenter2" -ClassName AntiVirusProduct -EA Stop
    if ($av) { Pass "SRV-119" "백신 등록됨: $(($av | Select-Object -First 1).displayName)" }
    else { Fail "SRV-119" "등록된 백신 없음" }
} catch { MC "SRV-119" "백신 상태 수동 확인 (SecurityCenter2 접근 실패)" }

# ── SRV-123: 최종 로그인 사용자 계정 노출 방지 ──────────────────
$hideUser = Get-Reg "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" "DontDisplayLastUserName"
if ($null -ne $hideUser -and $hideUser -eq 1) { Pass "SRV-123" "로그인 화면 마지막 사용자 표시 비활성" }
else { Fail "SRV-123" "로그인 화면에 마지막 사용자 계정 표시됨 (DontDisplayLastUserName=0)" }

# ── SRV-125: 화면 보호기 ────────────────────────────────────────
# SRV-028에서 이미 확인됨
MC "SRV-125" "화면 보호기 설정 확인 - SRV-028 항목 참조"

# ── SRV-126: 자동 로그온 방지 ───────────────────────────────────
$autoLogon = Get-Reg "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" "AutoAdminLogon"
if ($null -ne $autoLogon -and $autoLogon -eq "1") { Fail "SRV-126" "자동 로그온 활성화됨 (AutoAdminLogon=1)" }
else { Pass "SRV-126" "자동 로그온 비활성화됨" }

# ── SRV-127: 로그인 실패 횟수 제한 ─────────────────────────────
$lockout = Get-SecPol "LockoutBadCount"
if ($null -eq $lockout) {
    $netOut = net accounts 2>$null
    $line   = $netOut | Where-Object {$_ -match "Lockout threshold|잠금 임계"}
    if ($line) { $lockout = ($line -replace "[^0-9]","").Trim() }
}
if ($null -ne $lockout -and $lockout -match "^\d+$") {
    $cnt = [int]$lockout
    if ($cnt -eq 0) { Fail "SRV-127" "계정 잠금 임계값=0 (무제한)" }
    elseif ($cnt -le 5) { Pass "SRV-127" "계정 잠금 임계값=${cnt}회 (5회 이하)" }
    else { Fail "SRV-127" "계정 잠금 임계값=${cnt}회 (5회 이하 권고)" }
} else { MC "SRV-127" "계정 잠금 임계값 확인 실패" }

# ── SRV-128: NTFS 파일 시스템 ───────────────────────────────────
$fixedVols = Get-Volume -EA SilentlyContinue | Where-Object { $_.DriveType -eq "Fixed" -and $_.DriveLetter }
if ($fixedVols) {
    $nonNtfs = $fixedVols | Where-Object { $_.FileSystemType -ne "NTFS" -and $_.FileSystemType -ne "ReFS" }
    if ($nonNtfs) { Fail "SRV-128" "NTFS/ReFS 미사용 드라이브: $(($nonNtfs | ForEach-Object { "$($_.DriveLetter):($($_.FileSystemType))" }) -join ',')" }
    else { Pass "SRV-128" "모든 드라이브 NTFS 사용" }
} else {
    # Get-Volume 실패 시 CimInstance 폴백
    $cimDrives = Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" -EA SilentlyContinue
    $nonNtfs2  = $cimDrives | Where-Object { $_.FileSystem -ne "NTFS" }
    if ($nonNtfs2) { Fail "SRV-128" "NTFS 미사용 드라이브: $($nonNtfs2.DeviceID -join ',')" }
    elseif ($cimDrives) { Pass "SRV-128" "모든 드라이브 NTFS 사용" }
    else { MC "SRV-128" "드라이브 파일 시스템 확인 실패 - 수동 확인" }
}

# ── SRV-129: 백신 설치 ──────────────────────────────────────────
# SRV-119와 동일 (별도 메시지)
try {
    $av = Get-CimInstance -Namespace "root/SecurityCenter2" -ClassName AntiVirusProduct -EA Stop
    if ($av) { Pass "SRV-129" "백신 설치됨: $(($av | Select-Object -First 1).displayName)" }
    else { Fail "SRV-129" "등록된 백신 없음" }
} catch { MC "SRV-129" "백신 설치 여부 수동 확인 (SecurityCenter2 접근 실패)" }

# ── SRV-135: TCP 보안 설정 ──────────────────────────────────────
$synAtk = Get-Reg "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" "SynAttackProtect"
if ($null -ne $synAtk -and $synAtk -ge 1) { Pass "SRV-135" "SynAttackProtect=$synAtk (TCP 보안 설정)" }
else { Fail "SRV-135" "SynAttackProtect 미설정 (SYN Flood 취약)" }

# ── SRV-136: 로그온 단계 시스템 종료 기능 비활성화 ──────────────
$noShutdown = Get-SecPol "ShutdownWithoutLogon"
if ($null -ne $noShutdown -and $noShutdown.Trim() -eq "0") { Pass "SRV-136" "로그온 전 종료 버튼 비활성화됨" }
else { Fail "SRV-136" "로그온 전 시스템 종료 버튼 활성화됨" }

# ── SRV-140: 이동식 미디어 제한 ─────────────────────────────────
$usbDisable = Get-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices" "Deny_All"
if ($null -ne $usbDisable -and $usbDisable -eq 1) { Pass "SRV-140" "이동식 미디어 GPO 차단 설정됨" }
else { MC "SRV-140" "이동식 미디어 포맷/꺼내기 권한 수동 확인 (그룹 정책 편집기)" }

# ── SRV-149: 디스크 볼륨 암호화 ────────────────────────────────
try {
    $bl = Get-BitLockerVolume -EA Stop
    $protected = $bl | Where-Object {$_.ProtectionStatus -eq "On"}
    if ($protected) { Pass "SRV-149" "BitLocker 암호화 볼륨: $($protected.MountPoint -join ',')" }
    else { Fail "SRV-149" "BitLocker 미적용 볼륨 존재" }
} catch { MC "SRV-149" "디스크 암호화 상태 수동 확인 (BitLocker 또는 TDE)" }

# ── SRV-150: 로컬 로그온 허용 계정 제한 ─────────────────────────
MC "SRV-150" "로컬 로그온 허용 계정 수동 확인 (로컬 보안 정책 > 로컬 로그온 허용)"

# ── SRV-151: 익명 SID/이름 변환 제한 ───────────────────────────
$sidEnum = Get-Reg "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "RestrictAnonymousSAM"
if ($null -ne $sidEnum -and $sidEnum -eq 1) { Pass "SRV-151" "익명 SAM 열거 제한됨 (RestrictAnonymousSAM=1)" }
else { Fail "SRV-151" "익명 SAM 열거 제한 미설정" }

# ── SRV-152: 원격 터미널 접속 그룹 제한 ────────────────────────
MC "SRV-152" "원격 데스크톱 사용자 그룹 멤버 수동 확인"

# ── SRV-158: Telnet 서비스 비활성화 ─────────────────────────────
# SRV-035와 동일
$t = Get-SvcState "TlntSvr"
if ($t -and $t.Status -match "Running") { Fail "SRV-158" "Telnet 서비스 실행 중" }
else { Pass "SRV-158" "Telnet 서비스 미실행" }

# ── SRV-163: 시스템 배너 ─────────────────────────────────────────
$banner = Get-Reg "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" "LegalNoticeCaption"
$bannerText = Get-Reg "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" "LegalNoticeText"
if ($banner -and $bannerText) { Pass "SRV-163" "시스템 사용 주의사항 배너 설정됨: $banner" }
else { Fail "SRV-163" "시스템 사용 주의사항(LegalNotice) 미설정" }

# ── SRV-166: 불필요 숨김 파일 ───────────────────────────────────
MC "SRV-166" "불필요 숨김 파일/디렉토리 수동 확인 (dir /a:h 또는 탐색기 숨김 파일 표시)"

# ── SRV-172: 불필요 시스템 자원 공유 제거 ──────────────────────
$vuln2 = @()
try {
    Get-SmbShare -EA Stop | Where-Object {$_.Name -match '^\w\$$' -and $_.Name -notmatch '^(ADMIN|IPC|SYSVOL|NETLOGON)\$'} | ForEach-Object { $vuln2 += $_.Name }
} catch {}
if ($vuln2) { Fail "SRV-172" "불필요 공유 발견: $($vuln2 -join ',')" }
else { Pass "SRV-172" "불필요 시스템 자원 공유 없음" }

# ── SRV-175: NTP 동기화 ─────────────────────────────────────────
try {
    $w32 = w32tm /query /status 2>$null
    if ($w32 -match "Source\s*:\s*(\S+)") {
        $src = $matches[1]
        if ($src -match "\d{1,3}\.\d{1,3}|time\.|ntp\.") { Pass "SRV-175" "NTP 동기화: $src" }
        else { MC "SRV-175" "NTP 소스 비정상: $src (수동 확인)" }
    } else { Fail "SRV-175" "NTP 동기화 미확인" }
} catch { MC "SRV-175" "NTP 상태 수동 확인 (w32tm /query /status)" }

# ── SRV-178: 개인키 passphrase ──────────────────────────────────
MC "SRV-178" "SSH 개인키 passphrase 설정 수동 확인 (사용 중인 경우)"

# ── SRV-179: EoS 시스템 교체 ────────────────────────────────────
MC "SRV-179" "Windows 버전 지원 종료 여부 수동 확인 (Microsoft 제품 수명 주기 페이지 참조)"
Write-Output "# OS 정보: $($os.Caption) Build $build"

# ── SRV-062/063/064/066: DNS 서버 점검 ─────────────────────────
$dnsSvc = Get-SvcState "DNS"
if (-not $dnsSvc -or $dnsSvc.Status -notmatch "Running") {
    NA  "SRV-062" "DNS 서비스 미실행"
    NA  "SRV-063" "DNS 서비스 미실행"
    NA  "SRV-064" "DNS 서비스 미실행"
    NA  "SRV-066" "DNS 서비스 미실행"
} else {
    MC "SRV-062" "Windows DNS Server 실행 중 - 버전 정보 노출 설정 수동 확인"
    MC "SRV-063" "Windows DNS Server 실행 중 - Recursive Query 제한 설정 수동 확인"
    MC "SRV-064" "Windows DNS Server 실행 중 - 최신 보안 패치 적용 여부 수동 확인"
    MC "SRV-066" "Windows DNS Server 실행 중 - Zone Transfer 제한 설정 수동 확인"
}

# Linux 전용 항목 N-A 처리
foreach ($code in @("SRV-001","SRV-003","SRV-004","SRV-005","SRV-006","SRV-007","SRV-008","SRV-009","SRV-010",
                    "SRV-011","SRV-012","SRV-013","SRV-014","SRV-015","SRV-016","SRV-021","SRV-022","SRV-025",
                    "SRV-081","SRV-083","SRV-087","SRV-091","SRV-092","SRV-093","SRV-094",
                    "SRV-095","SRV-096","SRV-121","SRV-122","SRV-131","SRV-133","SRV-134","SRV-142","SRV-144",
                    "SRV-161","SRV-164","SRV-165","SRV-177")) {
    NA $code "Linux/Unix 전용 항목 (Windows 해당 없음)"
}

Remove-Item $seceditFile -EA SilentlyContinue
Write-Output "# 점검 완료: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
