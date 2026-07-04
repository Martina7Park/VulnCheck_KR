# ================================================================
# 전자금융기반시설 Windows Web/WAS 취약점 점검 스크립트 v4.0
# 기준: 전자금융기반시설 보안 취약점 평가기준 제2026-1호 [웹서버-WAS]
#
# 지원: IIS 8.5/10.0 / Apache on Windows / Nginx on Windows
#       WAS: Tomcat on Windows / JEUS on Windows
#
# [사용법] PowerShell (관리자)
#   $env:WEB_SRV   = "iis"     # iis | apache | nginx  (기본: 자동탐지)
#   $env:WAS_SRV   = "tomcat"  # tomcat | jeus          (기본: 자동탐지)
#   $env:TOMCAT_HOME = "C:\Program Files\Apache Software Foundation\Tomcat 10.1"
#   .\check_webwas.ps1 > C:\Temp\WEBWAS.txt
#
# [출력] WST-항목코드|결과|근거
# ================================================================
$ErrorActionPreference = "SilentlyContinue"
$ProgressPreference    = "SilentlyContinue"

function Pass([string]$code,[string]$msg) { Write-Output "WST-${code}|양호|$msg" }
function Fail([string]$code,[string]$msg) { Write-Output "WST-${code}|취약|$msg" }
function NA  ([string]$code,[string]$msg) { Write-Output "WST-${code}|N-A|$msg" }
function MC  ([string]$code,[string]$msg) { Write-Output "WST-${code}|수동확인|$msg" }

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
Write-Output "# 웹서버: $(if ($WEB_SRV) { $WEB_SRV } else { '미탐지' }) / IIS $IIS_VERSION"
Write-Output "# WAS: $(if ($WAS_SRV) { $WAS_SRV } else { '미탐지' })"
Write-Output "# Tomcat 홈: $(if ($TOMCAT_HOME) { $TOMCAT_HOME } else { '미탐지' })"
Write-Output "# 점검 기준: 전자금융기반시설 보안 취약점 평가기준 제2026-1호 [웹서버-WAS]"
Write-Output "# 점검 일시: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Output "# ================================================================"

# ── secedit 보안 정책 내보내기 (1회) ────────────────────────────
$secTmp = "$env:TEMP\wst_secedit_$PID.cfg"
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
$pwComplexity = Get-SecPol "PasswordComplexity"
if ($pwComplexity -eq "1") { Pass "054" "패스워드 복잡도 설정 활성화됨 (PasswordComplexity=1)" }
elseif ($pwComplexity -eq "0") { Fail "054" "패스워드 복잡도 설정 비활성화됨 (PasswordComplexity=0)" }
else {
    $netAcc = net accounts 2>$null | Where-Object { $_ -match "complexity|복잡성" }
    if ($netAcc) { MC "054" "패스워드 복잡도: $($netAcc.Trim()) - 수동 확인" }
    else { MC "054" "패스워드 복잡도 설정 수동 확인 (로컬 보안 정책)" }
}

# WST-058: 예약 작업 (Task Scheduler) 권한
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
$dangerTools = @("nmap.exe","nc.exe","netcat.exe","ncat.exe","psexec.exe")
$foundTools  = @()
foreach ($tool in $dangerTools) {
    $cmd = Get-Command $tool -EA SilentlyContinue
    if ($cmd) { $foundTools += $cmd.Source }
}
if ($foundTools) { Fail "064" "위험 도구 발견: $($foundTools -join ', ')" }
else { Pass "064" "위험 도구(nmap/nc/psexec 등) 미발견" }

# WST-075: 로그 파일 접근 권한
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
$sysPath = [System.Environment]::GetEnvironmentVariable("PATH", "Machine")
if ($sysPath -split ";" | Where-Object { $_ -eq "." -or $_ -eq "" }) {
    Fail "082" "시스템 PATH에 현재 디렉토리(.) 또는 빈 항목 포함"
} else {
    Pass "082" "시스템 PATH에 현재 디렉토리(.) 미포함"
}

# WST-083: 프로세스 기본 umask (Windows: N/A — NTFS ACL로 관리)
NA "083" "Windows 환경 umask 개념 미적용 (NTFS ACL 기반 권한 관리)"

# WST-087: 로그인 실패 횟수 제한 (계정 잠금 임계값)
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
$uacEnable = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -EA SilentlyContinue).EnableLUA
if ($uacEnable -eq 1) { Pass "090" "UAC(User Account Control) 활성화됨" }
else { Fail "090" "UAC 비활성화됨 - 권한 상승 제어 미작동" }

# WST-099: 중복 SID (Windows 도메인 환경에서는 N/A, 로컬 계정만 확인)
$localUsers = Get-LocalUser -EA SilentlyContinue | Select-Object Name, SID
$dupSID = $localUsers | Group-Object -Property {$_.SID.Value} | Where-Object { $_.Count -gt 1 }
if ($dupSID) { Fail "099" "중복 SID 발견: $($dupSID | Select-Object -ExpandProperty Name -First 3)" }
else { Pass "099" "로컬 계정 중복 SID 없음" }

# WST-100: 불필요 파일 (Windows 임시 디렉토리)
NA "100" "Windows 환경 /dev 항목 미적용"

# WST-101: SNMP 서비스 버전 확인
$snmpSvc = Get-Service SNMP -EA SilentlyContinue
if ($snmpSvc -and $snmpSvc.Status -eq "Running") {
    $snmpCom = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\ValidCommunities" -EA SilentlyContinue
    if ($snmpCom) {
        $coms = $snmpCom.PSObject.Properties | Where-Object { $_.Name -notmatch "^PS" } | Select-Object -ExpandProperty Name
        Fail "101" "SNMP 실행 중, community 설정됨: $($coms -join ', ') - SNMPv3 전환 검토"
    } else { MC "101" "SNMP 서비스 실행 중 - community 설정 수동 확인" }
} else { Pass "101" "SNMP 서비스 미실행" }

# WST-107: Telnet 서비스 비활성화
$telnetSvc = Get-Service TlntSvr -EA SilentlyContinue
if ($telnetSvc -and $telnetSvc.Status -eq "Running") { Fail "107" "Telnet 서버 서비스 실행 중 (TlntSvr)" }
else { Pass "107" "Telnet 서버 미실행" }

# WST-109: 시스템 배너 설정
$legalNotice = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -EA SilentlyContinue).legalnoticecaption
$legalText   = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -EA SilentlyContinue).legalnoticetext
if ($legalNotice -and $legalText) { Pass "109" "로그인 경고 배너 설정됨 (legalnoticecaption: $legalNotice)" }
else { Fail "109" "로그인 경고 배너 미설정 (legalnoticecaption/legalnoticetext 없음)" }

# WST-118: NTP 동기화
$w32Status = w32tm /query /status 2>$null
if ($w32Status -match "Source|원본") {
    $src = ($w32Status | Where-Object { $_ -match "Source|원본" } | Select-Object -First 1).Trim()
    Pass "118" "Windows Time 동기화 활성: $src"
} else { Fail "118" "NTP 동기화 미설정 (w32tm 응답 없음)" }

# WST-119: sudo NOPASSWD 상당 (Windows: RunAs 자격증명 저장)
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
    foreach ($code in @("031","033","036","039","044","048","102","121","122","123","124","125","126")) {
        if ($WEB_SRV -eq "apache" -or $WEB_SRV -eq "nginx") { break }
        NA $code "IIS 미설치 - 웹서버 미탐지"
    }
}

if ($IIS_INSTALLED) {

    # WST-031: 디렉토리 리스팅 방지
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
    if ($HAS_WEB_ADMIN) {
        # IIS 10.0+ 에서는 removeServerHeader 설정 가능
        $removeHeader = Get-WebConfigurationProperty "system.webServer/security/requestFiltering" -PSPath "IIS:\" -Name "removeServerHeader" -EA SilentlyContinue
        if ($removeHeader -and $removeHeader.Value -eq $true) {
            Pass "102" "IIS Server 헤더 제거 설정됨 (removeServerHeader=true)"
        } else {
            # URL Rewrite를 통한 헤더 제거 또는 커스텀 헤더 확인
            $customHeaders = Get-WebConfigurationProperty "system.webServer/httpProtocol/customHeaders" -PSPath "IIS:\" -Name "Collection" -EA SilentlyContinue
            $xPowered = $customHeaders | Where-Object { $_.name -eq "X-Powered-By" -and $_ -match "remove" }
            Fail "102" "IIS Server 헤더 노출 가능 (removeServerHeader 미설정) - web.config 또는 URLRewrite로 제거 권고"
        }
    } else { MC "102" "IIS 서버 정보 노출 방지 수동 확인 (Server 헤더, X-Powered-By 헤더)" }

    # WST-121: IIS 역방향 프록시(ARR) 설정
    $arrMod = Get-WebGlobalModule -Name "ApplicationRequestRouting" -EA SilentlyContinue
    if ($arrMod) {
        MC "121" "IIS ARR(역방향 프록시) 모듈 설치됨 - 프록시 허용 범위 수동 확인"
    } else {
        Pass "121" "IIS ARR 역방향 프록시 모듈 미설치"
    }

    # WST-122: SSI (Server Side Includes) 비활성화
    if ($HAS_WEB_ADMIN) {
        $ssiMod = Get-WebGlobalModule -Name "ServerSideIncludeModule" -EA SilentlyContinue
        if ($ssiMod) { Fail "122" "SSI(Server Side Include) 모듈 활성화됨 - 불필요 시 제거 권고" }
        else { Pass "122" "SSI 모듈 비활성화됨" }
    } else { MC "122" "SSI 모듈 활성화 여부 수동 확인" }

    # WST-123: 기본 에러 페이지 노출 방지
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
    if ($serverXml -match '<Server\s[^>]*port="-1"') {
        Pass "059" "Tomcat Shutdown 포트 비활성화됨 (port=-1)"
    } elseif ($serverXml -match '<Server\s[^>]*port="(\d+)"') {
        $shutdownPort = $matches[1]
        Fail "059" "Tomcat Shutdown 포트 활성화됨 (port=$shutdownPort) - -1로 변경 권고"
    } else { MC "059" "Tomcat Shutdown 포트 설정 수동 확인" }

    # WST-060: 기본 애플리케이션(manager, host-manager, examples, docs, ROOT) 제거
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
        if (Test-Path $eosScript) {
            $eosResult  = python3 $eosScript "tomcat" $tcVer --no-api 2>$null
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
$openShares = Get-SmbShare -EA SilentlyContinue | Where-Object { $_.Name -notmatch '^\w\$$|^ADMIN\$$|^IPC\$$' } |
    ForEach-Object {
        $perms = Get-SmbShareAccess $_.Name -EA SilentlyContinue
        $everyone = $perms | Where-Object { $_.AccountName -match "Everyone|모든 사용자" -and $_.AccessRight -eq "Full" }
        if ($everyone) { $_.Name }
    }
if ($openShares) { Fail "017" "Everyone 전체 권한 공유 존재: $($openShares -join ', ')" }
else { Pass "017" "공유 폴더 Everyone 전체 권한 없음" }

# WST-019: 비밀번호 미설정(빈 암호) 계정
$emptyPw = Get-LocalUser -EA SilentlyContinue | Where-Object { $_.PasswordRequired -eq $false -and $_.Enabled -eq $true }
if ($emptyPw) {
    Fail "019" "비밀번호 불필요 설정 계정: $($emptyPw.Name -join ', ') - 비밀번호 필수화 권고"
} else {
    Pass "019" "활성 계정 모두 비밀번호 필수 설정됨"
}

# WST-020: 원격 터미널 서비스 암호화 설정 (RDP SecurityLayer)
$rdpSec = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -EA SilentlyContinue).SecurityLayer
# 0=RDP, 1=Negotiate, 2=SSL/TLS
if ($rdpSec -ge 2) { Pass "020" "RDP SecurityLayer=$rdpSec (SSL/TLS 암호화)" }
elseif ($rdpSec -eq 1) { Pass "020" "RDP SecurityLayer=1 (Negotiate - TLS 협상)" }
elseif ($rdpSec -eq 0) { Fail "020" "RDP SecurityLayer=0 (RDP 전용 암호화 - SSL 적용 권고)" }
else { MC "020" "RDP 암호화 설정 수동 확인" }

# WST-026: SMB 세션 자동 중단 설정 (AutoDisconnect)
$autoDiscon = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -EA SilentlyContinue).AutoDisconnect
if ($null -eq $autoDiscon) { MC "026" "SMB AutoDisconnect 설정 없음 (기본값 15분) - 수동 확인" }
elseif ($autoDiscon -eq -1) { Fail "026" "SMB AutoDisconnect=-1 (세션 자동 중단 비활성화)" }
elseif ($autoDiscon -le 30) { Pass "026" "SMB AutoDisconnect=${autoDiscon}분 (30분 이하)" }
else { Fail "026" "SMB AutoDisconnect=${autoDiscon}분 (30분 이하 권고)" }

# WST-027: 계정 목록 및 공유 이름 노출 방지 (RestrictAnonymous)
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
$vulnSvcs029 = @{ "TlntSvr" = "Telnet 서버"; "lmhosts" = "NetBIOS Helper" }
$found029 = @()
foreach ($s in $vulnSvcs029.Keys) {
    $svc = Get-Service $s -EA SilentlyContinue
    if ($svc -and $svc.Status -eq "Running") { $found029 += $vulnSvcs029[$s] }
}
if ($found029) { Fail "029" "취약 서비스 실행 중: $($found029 -join ', ')" }
else { Pass "029" "취약 서비스(Telnet/NetBIOS Helper) 미실행" }

# WST-030: 취약한 FTP 서비스 비활성화 (TFTP)
$tftpSvc = Get-Service "tftpd" -EA SilentlyContinue
$tftpProc = Get-Process "tftp*" -EA SilentlyContinue | Select-Object -First 1
if (($tftpSvc -and $tftpSvc.Status -eq "Running") -or $tftpProc) {
    Fail "030" "TFTP 서비스/프로세스 실행 중 - 비활성화 권고"
} else {
    Pass "030" "TFTP 서비스 미실행"
}

# WST-051: 기본 Administrator 계정명 변경 여부
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
$guestAcc = Get-LocalUser -Name "Guest" -EA SilentlyContinue
if (-not $guestAcc)         { Pass "055" "Guest 계정 없음" }
elseif (-not $guestAcc.Enabled) { Pass "055" "Guest 계정 비활성화됨" }
else                        { Fail "055" "Guest 계정 활성화됨 - 비활성화 권고" }

# WST-057: 일반 사용자 프린터 드라이버 설치 제한
$addPrinterDriver = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers" -EA SilentlyContinue).AddPrinterDrivers
if ($addPrinterDriver -eq 1) { Pass "057" "프린터 드라이버 설치 제한됨 (AddPrinterDrivers=1)" }
else { Fail "057" "일반 사용자 프린터 드라이버 설치 허용 (AddPrinterDrivers=$addPrinterDriver) - 제한 권고" }

# WST-063: 원격 레지스트리 서비스 비활성화
$remReg = Get-Service RemoteRegistry -EA SilentlyContinue
if (-not $remReg)                        { Pass "063" "RemoteRegistry 서비스 없음" }
elseif ($remReg.Status -eq "Stopped" -and $remReg.StartType -eq "Disabled") {
    Pass "063" "RemoteRegistry 서비스 비활성화됨 (Disabled)"
} elseif ($remReg.Status -eq "Running")  { Fail "063" "RemoteRegistry 서비스 실행 중 - 비활성화 권고" }
else { MC "063" "RemoteRegistry StartType=$($remReg.StartType) - 수동 확인" }

# WST-071: 불필요한 예약 작업 (비Microsoft 경로 작업 목록)
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
$lmCompat = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -EA SilentlyContinue).LmCompatibilityLevel
$lmSecPol2 = Get-SecPol "LmCompatibilityLevel"
$lmFinal = if ($null -ne $lmCompat) { $lmCompat } elseif ($lmSecPol2) { [int]$lmSecPol2 } else { $null }
if ($null -eq $lmFinal)     { MC "072" "LAN Manager 인증 수준 설정 확인 실패" }
elseif ($lmFinal -ge 5)     { Pass "072" "LAN Manager 인증 수준=$lmFinal (NTLMv2만 허용, 최고 보안)" }
elseif ($lmFinal -ge 3)     { Pass "072" "LAN Manager 인증 수준=$lmFinal (NTLMv2 응답만 전송)" }
else                        { Fail "072" "LAN Manager 인증 수준=$lmFinal (NTLMv2 미적용 - 3 이상 권고)" }

# WST-073: 보안 채널 데이터 암호화/서명
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
$crashAudit = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -EA SilentlyContinue).CrashOnAuditFail
if ($crashAudit -eq 1) { Fail "079" "CrashOnAuditFail=1 - 감사 실패 시 시스템 종료 활성화됨 (0으로 변경 권고)" }
elseif ($crashAudit -eq 0 -or $null -eq $crashAudit) { Pass "079" "CrashOnAuditFail=0 (감사 실패 시 강제 종료 비활성화)" }
else { MC "079" "CrashOnAuditFail=$crashAudit - 수동 확인" }

# WST-084: 최종 로그인 사용자 계정 노출 방지
$dontDisplay = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -EA SilentlyContinue).DontDisplayLastUserName
if ($dontDisplay -eq 1) { Pass "084" "마지막 로그인 계정 표시 안 함 (DontDisplayLastUserName=1)" }
else { Fail "084" "마지막 로그인 계정 노출됨 (DontDisplayLastUserName=$dontDisplay) - 1로 설정 권고" }

# WST-085: 화면보호기 설정 (잠금 포함)
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
$autoLogon = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -EA SilentlyContinue).AutoAdminLogon
if ($autoLogon -eq "1") { Fail "086" "자동 로그온 활성화됨 (AutoAdminLogon=1) - 비활성화 권고" }
else { Pass "086" "자동 로그온 비활성화됨 (AutoAdminLogon=$autoLogon)" }

# WST-088: NTFS 파일 시스템 사용 여부
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
$shutdownBtn = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -EA SilentlyContinue).ShutdownWithoutLogon
if ($shutdownBtn -eq 0) { Pass "094" "로그온 화면 종료 버튼 비활성화됨 (ShutdownWithoutLogon=0)" }
elseif ($shutdownBtn -eq 1) { Fail "094" "로그온 화면 종료 버튼 활성화됨 - 0으로 설정 권고" }
else { MC "094" "ShutdownWithoutLogon 설정 없음 - 수동 확인" }

# WST-098: 이동식 미디어 포맷 및 꺼내기 권한 (일반 사용자 제한)
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

# secedit 임시 파일 정리
if (Test-Path $secTmp) { Remove-Item $secTmp -Force -EA SilentlyContinue }

# ================================================================
# 수동확인 항목 일괄 출력 (자동 체크 불가 항목)
# ================================================================
$manualCodes = @(
    "001","002","003","004","005","006","007","008","009",
    "018","021",
    "032","034","035","037",
    "038","040","041","042","043","045","046","047",
    "053","076","078","080","081",
    "089","095","096","097",
    "103","104","105","106",
    "113","114","115","116","117"
)
foreach ($code in $manualCodes) {
    Write-Output "WST-${code}|수동확인|수동 확인 필요"
}

Write-Output "# 점검 완료: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
