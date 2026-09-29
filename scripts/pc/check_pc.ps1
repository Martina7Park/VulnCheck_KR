# ================================================================
# PC 단말(Windows) 보안 취약점 자동 점검 스크립트 v1.0
# ================================================================
#
# [용도]
#   전자금융기반시설 업무용 PC(Windows) 보안 점검. (주요정보 2026 상세가이드 PC-01~18 은 check_pc_kisa.ps1 사용)
#   기준: 전자금융기반시설 PC(업무용 단말) 자체 점검 항목 PC-01~18 (전자금융 평가기준에 PC 분야 없음)
#   macOS PC는 check_pc_mac.sh 사용.
#
# [대상 OS]
#   Windows 10 / 11 (Home / Pro / Enterprise)
#
# [사전 조건]
#   - 관리자 권한 PowerShell 권장
#   - 실행 정책 변경: Set-ExecutionPolicy RemoteSigned -Scope Process -Force
#
# [실행 방법]
#   .\check_pc.ps1 > C:\Temp\$env:COMPUTERNAME_pc.txt
#
# [산출물]
#   1) 표준출력 — 파이프 구분자 결과 (파일로 리다이렉트)
#      형식: PC-항목코드|결과|근거설명
#      결과: 양호 / 취약 / 수동확인 / N-A
#   2) 증적 파일 — 스크립트와 같은 폴더 <호스트명>_pc_evidence.txt (컨버터가 결과 파일 옆에서 자동 탐색)
#      점검 중 실행한 명령어·출력·판정 근거가 타임스탬프와 함께 기록됨
#
# ================================================================
$ErrorActionPreference = "SilentlyContinue"
$ProgressPreference    = "SilentlyContinue"

$hn      = $env:COMPUTERNAME
$os      = Get-CimInstance Win32_OperatingSystem -EA SilentlyContinue
$osName  = if ($os) { $os.Caption } else { "Unknown" }
$build   = if ($os) { [int]$os.BuildNumber } else { 0 }
$isHome  = $osName -match "Home"

Write-Output "# ============================================================"
Write-Output "# 점검 대상: $hn"
Write-Output "# OS: $osName (Build $build)"
Write-Output "# 에디션: $(if($isHome){'Home (로컬 보안 정책 제한)'}else{'Pro/Enterprise'})"
Write-Output "# 점검 기준: 전자금융기반시설 PC(업무용 단말) 자체 점검 항목 PC-01~18 (전자금융 평가기준에 PC 분야 없음)"
Write-Output "# 점검 일시: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Output "# ============================================================"

$seceditFile = "$env:TEMP\pc_secpol_$PID.cfg"
$null = secedit /export /cfg $seceditFile /quiet 2>$null
$hasSecEdit = Test-Path $seceditFile

function Get-SecPol([string]$Key) {
    if (-not $hasSecEdit) { return $null }
    $line = Get-Content $seceditFile -EA SilentlyContinue |
            Where-Object { $_ -match "^\s*$([regex]::Escape($Key))\s*=" }
    if ($line) { return ($line -split "=",2)[1].Trim() }
    return $null
}
function Get-Reg([string]$Path,[string]$Name) {
    try { return (Get-ItemProperty -Path $Path -Name $Name -EA Stop).$Name }
    catch { return $null }
}

$script:cntPass=0; $script:cntFail=0; $script:cntMC=0; $script:cntNA=0

$script:ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$script:EVD = "$script:ScriptDir\${hn}_pc_evidence.txt"
"# ================================================================" | Out-File $script:EVD -Encoding UTF8
"# PC 증적 파일 (감사 추적용)" | Add-Content $script:EVD -Encoding UTF8
"# 대상: $hn / $osName (Build $build)" | Add-Content $script:EVD -Encoding UTF8
"# 생성: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" | Add-Content $script:EVD -Encoding UTF8
"# ================================================================" | Add-Content $script:EVD -Encoding UTF8

function Pass([string]$code,[string]$msg) { $script:cntPass++; Write-Output "PC-$code|양호|$msg"; "[판정] PC-$code|양호|$msg`n" | Add-Content $script:EVD -Encoding UTF8 }
function Fail([string]$code,[string]$msg) { $script:cntFail++; Write-Output "PC-$code|취약|$msg"; "[판정] PC-$code|취약|$msg`n" | Add-Content $script:EVD -Encoding UTF8 }
function NA([string]$code,[string]$msg)   { $script:cntNA++;   Write-Output "PC-$code|N-A|$msg"; "[판정] PC-$code|N-A|$msg`n" | Add-Content $script:EVD -Encoding UTF8 }
function MC([string]$code,[string]$msg)   { $script:cntMC++;   Write-Output "PC-$code|수동확인|$msg"; "[판정] PC-$code|수동확인|$msg`n" | Add-Content $script:EVD -Encoding UTF8 }
function Evd([string]$item,[string]$cmd) {
    "[$item] $(Get-Date -Format 'HH:mm:ss') PS> $cmd" | Add-Content $script:EVD -Encoding UTF8
    try { $r = Invoke-Expression $cmd 2>&1 | Out-String; $r | Add-Content $script:EVD -Encoding UTF8 } catch { $_.Exception.Message | Add-Content $script:EVD -Encoding UTF8 }
    "" | Add-Content $script:EVD -Encoding UTF8
}
function EvdQ([string]$item,[string]$desc,[string]$val) {
    "[$item] $(Get-Date -Format 'HH:mm:ss') $desc`n$val`n" | Add-Content $script:EVD -Encoding UTF8
}

# ══════════════════════════════════════════════════════════════════
# PC-01: 패스워드 설정
# ══════════════════════════════════════════════════════════════════
Evd "PC-01" "Get-LocalUser -EA SilentlyContinue | Select-Object Name,Enabled,PasswordRequired | Format-Table"
$noPwUsers = @()
$pc01Done = $false
try {
    $users = Get-LocalUser -EA Stop | Where-Object { $_.Enabled }
    foreach ($u in $users) {
        if ($u.Name -match "^(DefaultAccount|WDAGUtilityAccount)$") { continue }
        if (-not $u.PasswordRequired) { $noPwUsers += $u.Name }
    }
    if ($noPwUsers.Count -gt 0) {
        Fail "01" "비밀번호 미필수 계정: $($noPwUsers -join ', ')"
    } else {
        $uList = ($users | Where-Object {$_.Name -notmatch "^(DefaultAccount|WDAGUtilityAccount)$"} |
                  ForEach-Object {$_.Name}) -join ", "
        Pass "01" "모든 활성 계정 비밀번호 필수 ($uList)"
    }
    $pc01Done = $true
} catch {}

if (-not $pc01Done) {
    # Get-LocalUser 미지원 시 net user 폴백
    $netOut = (net user 2>$null) -join "`n"
    $activeUsers = @()
    foreach ($line in (net user 2>$null)) {
        if ($line -match "^-" -or $line -match "^\\\\|^The command|^User accounts|^$") { continue }
        $names = $line.Trim() -split '\s{2,}'
        $activeUsers += $names | Where-Object { $_ -and $_ -notmatch "^(DefaultAccount|WDAGUtilityAccount)$" }
    }
    $guestStatus = net user Guest 2>$null | Where-Object { $_ -match "Account active" }
    if ($activeUsers.Count -gt 0) {
        MC "01" "활성 계정(net user): $($activeUsers -join ', ') - 비밀번호 설정 여부 수동 확인"
    } else {
        MC "01" "계정 목록 조회 실패 - 수동 확인"
    }
}

# ══════════════════════════════════════════════════════════════════
# PC-02: 패스워드 정책
# ══════════════════════════════════════════════════════════════════
Evd "PC-02" "net accounts 2>`$null"
$minLen  = Get-SecPol "MinimumPasswordLength"
$maxAge  = Get-SecPol "MaximumPasswordAge"
$complex = Get-SecPol "PasswordComplexity"
$history = Get-SecPol "PasswordHistorySize"

if ($null -eq $minLen) {
    # secedit 실패 시 net accounts 폴백 (Home 에디션 포함)
    $netAcct = net accounts 2>$null
    $naMinLen = ($netAcct | Where-Object {$_ -match "Minimum password length|최소 암호 길이"} | ForEach-Object {($_ -split ":\s*",2)[1].Trim()})
    $naMaxAge = ($netAcct | Where-Object {$_ -match "Maximum password age|최대 암호 사용 기간"} | ForEach-Object {($_ -split ":\s*",2)[1].Trim()})
    $naLockout = ($netAcct | Where-Object {$_ -match "Lockout threshold|잠금 임계값"} | ForEach-Object {($_ -split ":\s*",2)[1].Trim()})
    if ($naMinLen) {
        $issues = @()
        $ml = 0; [int]::TryParse($naMinLen, [ref]$ml) | Out-Null
        $ma = 0; [int]::TryParse(($naMaxAge -replace "[^\d]",""), [ref]$ma) | Out-Null
        if ($ml -lt 8)          { $issues += "최소길이=${ml}자(8자미만)" }
        if ($ma -gt 90 -or $ma -eq 0) { $issues += "최대사용기간=${ma}일" }
        if ($issues.Count -gt 0) {
            Fail "02" "(net accounts) 패스워드 정책 미흡: $($issues -join ', ')"
        } else {
            Pass "02" "(net accounts) 최소=${ml}자, 최대사용=${ma}일"
        }
    } else {
        MC "02" "secedit/net accounts 모두 실패 - 수동 확인"
    }
} else {
    $issues = @()
    if ([int]$minLen -lt 8)  { $issues += "최소길이=${minLen}자(8자미만)" }
    if ([int]$maxAge -gt 90 -or [int]$maxAge -eq 0) { $issues += "최대사용기간=${maxAge}일" }
    if ([int]$complex -eq 0) { $issues += "복잡도=비활성" }
    if ($issues.Count -gt 0) {
        Fail "02" "패스워드 정책 미흡: $($issues -join ', ')"
    } else {
        Pass "02" "최소=${minLen}자, 최대사용=${maxAge}일, 복잡도=활성, 기록=${history}개"
    }
}

# ══════════════════════════════════════════════════════════════════
# PC-03: 화면보호기 / 화면 잠금
# ══════════════════════════════════════════════════════════════════
Evd "PC-03" "Get-ItemProperty 'HKCU:\Control Panel\Desktop' -Name ScreenSaveActive,ScreenSaverIsSecure,ScreenSaveTimeOut -EA SilentlyContinue"
$ssActive  = Get-Reg "HKCU:\Control Panel\Desktop" "ScreenSaveActive"
$ssSecure  = Get-Reg "HKCU:\Control Panel\Desktop" "ScreenSaverIsSecure"
$ssTimeout = Get-Reg "HKCU:\Control Panel\Desktop" "ScreenSaveTimeOut"
$lockSecs  = Get-Reg "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "InactivityTimeoutSecs"

if ($ssActive -eq "1" -and $ssSecure -eq "1") {
    $t = if ($ssTimeout) { [int]$ssTimeout } else { 0 }
    if ($t -gt 0 -and $t -le 600) {
        Pass "03" "화면보호기 활성+암호잠금, 대기=${t}초"
    } else {
        Fail "03" "화면보호기 활성이나 대기시간 ${t}초(600초 이하 권장)"
    }
} elseif ($lockSecs -and [int]$lockSecs -gt 0 -and [int]$lockSecs -le 600) {
    Pass "03" "비활성 잠금 정책 적용: ${lockSecs}초"
} else {
    Fail "03" "화면 잠금 미설정 (ScreenSaveActive=$ssActive, Secure=$ssSecure, InactivityTimeout=${lockSecs})"
}

# ══════════════════════════════════════════════════════════════════
# PC-04: 공유폴더 제거
# ══════════════════════════════════════════════════════════════════
Evd "PC-04" "Get-SmbShare -EA SilentlyContinue | Select-Object Name,Path | Format-Table"
$autoShareWks = Get-Reg "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" "AutoShareWks"
$issues04 = @()

if ($null -eq $autoShareWks -or $autoShareWks -ne 0) {
    $issues04 += "기본관리공유(C$/ADMIN$) 활성(AutoShareWks=${autoShareWks})"
}

try {
    $userShares = Get-SmbShare -EA Stop |
        Where-Object { $_.Name -notmatch '^\w+\$$|^IPC\$$|^print\$$' }
    if ($userShares) {
        $issues04 += "사용자공유: $($userShares.Name -join ', ')"
    }
} catch {}

if ($issues04.Count -gt 0) {
    Fail "04" "$($issues04 -join ' / ')"
} else {
    Pass "04" "기본관리공유 비활성(AutoShareWks=0), 사용자 공유 없음"
}

# ══════════════════════════════════════════════════════════════════
# PC-05: 불필요 서비스 비활성화
# ══════════════════════════════════════════════════════════════════
Evd "PC-05" "Get-Service RemoteRegistry,TlntSvr,SSDPSRV,upnphost,WMPNetworkSvc,SharedAccess,SNMP,W3SVC,FTPSVC,simptcp,RpcLocator -EA SilentlyContinue | Select-Object Name,Status | Format-Table"
$dangerSvc = @(
    @{N="RemoteRegistry";    D="원격 레지스트리"},
    @{N="TlntSvr";           D="Telnet"},
    @{N="SSDPSRV";           D="SSDP Discovery"},
    @{N="upnphost";          D="UPnP Device Host"},
    @{N="WMPNetworkSvc";     D="WMP 네트워크공유"},
    @{N="SharedAccess";      D="인터넷연결공유(ICS)"},
    @{N="SNMP";              D="SNMP"},
    @{N="W3SVC";             D="IIS 웹서버"},
    @{N="FTPSVC";            D="FTP 서비스"},
    @{N="simptcp";           D="Simple TCP/IP"},
    @{N="RpcLocator";        D="RPC Locator"}
)
$runSvc = @()
foreach ($s in $dangerSvc) {
    $svc = Get-Service -Name $s.N -EA SilentlyContinue
    if ($svc -and $svc.Status -eq "Running") {
        $runSvc += "$($s.D)($($s.N))"
    }
}

if ($runSvc.Count -gt 0) {
    Fail "05" "실행 중 불필요 서비스 $($runSvc.Count)개: $($runSvc -join ', ')"
} else {
    Pass "05" "불필요 서비스 미실행 (RemoteRegistry/Telnet/SSDP/UPnP/SNMP 등)"
}

# ══════════════════════════════════════════════════════════════════
# PC-06: 백신 설치 및 실시간 감시
# ══════════════════════════════════════════════════════════════════
Evd "PC-06" "Get-CimInstance -Namespace 'root\SecurityCenter2' -ClassName 'AntiVirusProduct' -EA SilentlyContinue | Select-Object displayName,productState"
$avProducts = @()
try {
    $avProducts = Get-CimInstance -Namespace "root\SecurityCenter2" -ClassName "AntiVirusProduct" -EA Stop
} catch {}

$defender = $null
try { $defender = Get-MpComputerStatus -EA Stop } catch {}

# productState 비트마스크 해석 (WSC_SECURITY_PRODUCT_STATE)
# Byte 2 (bits 12-15): 실시간보호 상태 - 0x10=활성(ON), 0x00/0x01=비활성
# Byte 1 (bits 4-7):   정의 상태     - 0x00=최신, 0x10=오래됨
function Test-AVEnabled([int]$state) {
    $scanner = ($state -shr 12) -band 0xF
    return ($scanner -band 0x1) -eq 0 -and $scanner -ne 0  # ON=even nonzero (0x10)
}
function Test-AVUpToDate([int]$state) {
    $sigs = ($state -shr 4) -band 0xF
    return $sigs -eq 0  # 0=최신
}

if ($defender -and $defender.RealTimeProtectionEnabled) {
    $sigAge = ((Get-Date) - $defender.AntivirusSignatureLastUpdated).Days
    $sigDate = $defender.AntivirusSignatureLastUpdated.ToString("yyyy-MM-dd")
    if ($sigAge -le 7) {
        Pass "06" "Windows Defender 실시간보호 활성, 정의=$sigDate (${sigAge}일 전)"
    } else {
        Fail "06" "Defender 활성이나 정의 업데이트 오래됨: $sigDate (${sigAge}일 전, 7일 초과)"
    }
} elseif ($avProducts) {
    $names = ($avProducts | ForEach-Object { $_.displayName }) -join ", "
    $enabledAV = $avProducts | Where-Object {
        $ps = [int]$_.productState
        (($ps -shr 12) -band 0xF) -eq 0x1 -or   # WSC 등록 + 활성
        ($ps -band 0x1000) -eq 0x1000             # 레거시 비트 호환
    }
    if ($enabledAV) {
        $outOfDate = $enabledAV | Where-Object { -not (Test-AVUpToDate ([int]$_.productState)) }
        if ($outOfDate) {
            Fail "06" "백신 활성이나 정의 업데이트 필요: $($outOfDate.displayName -join ', ')"
        } else {
            Pass "06" "백신 실시간보호 활성: $names"
        }
    } else {
        Fail "06" "백신 설치됨($names)이나 실시간 보호 비활성 (productState: $($avProducts | ForEach-Object {'0x'+([int]$_.productState).ToString('X')}))"
    }
} else {
    Fail "06" "백신 프로그램 미감지 (SecurityCenter2 및 Defender 조회 실패)"
}

# ══════════════════════════════════════════════════════════════════
# PC-07: OS 보안 패치
# ══════════════════════════════════════════════════════════════════
Evd "PC-07" "Get-HotFix -EA SilentlyContinue | Sort-Object InstalledOn -Descending | Select-Object -First 3 HotFixID,InstalledOn | Format-Table"
$pc07Done = $false
try {
    # Get-HotFix (내부적으로 Win32_QuickFixEngineering WMI 사용)
    $hf = Get-HotFix -EA Stop | Where-Object { $_.InstalledOn } |
          Sort-Object InstalledOn -Descending
    if ($hf -and $hf.Count -gt 0) {
        $latest = $hf[0]
        $age = ((Get-Date) - $latest.InstalledOn).Days
        $hfDate = $latest.InstalledOn.ToString("yyyy-MM-dd")
        if ($age -le 90) {
            Pass "07" "최근 패치: $($latest.HotFixID) ($hfDate, ${age}일 전)"
        } else {
            Fail "07" "최근 패치 ${age}일 경과: $($latest.HotFixID) ($hfDate)"
        }
        $pc07Done = $true
    }
} catch {}

if (-not $pc07Done) {
    # Get-HotFix 실패 시 CIM 직접 조회 (WMIC 대체)
    try {
        $cimQfe = Get-CimInstance -ClassName Win32_QuickFixEngineering -EA Stop |
                  Where-Object { $_.InstalledOn } |
                  Sort-Object InstalledOn -Descending | Select-Object -First 1
        if ($cimQfe) {
            $age = ((Get-Date) - $cimQfe.InstalledOn).Days
            $hfDate = $cimQfe.InstalledOn.ToString("yyyy-MM-dd")
            if ($age -le 90) {
                Pass "07" "(CIM) 최근 패치: $($cimQfe.HotFixID) ($hfDate, ${age}일 전)"
            } else {
                Fail "07" "(CIM) 최근 패치 ${age}일 경과: $($cimQfe.HotFixID) ($hfDate)"
            }
            $pc07Done = $true
        }
    } catch {}
}

if (-not $pc07Done) {
    # 최후 수단: Windows Update 서비스 상태 확인
    $wuSvc = Get-Service -Name "wuauserv" -EA SilentlyContinue
    $wuAuto = Get-Reg "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" "AUOptions"
    MC "07" "패치 이력 조회 실패 - WU서비스=${wuSvc.Status}, AutoUpdate=${wuAuto} - 설정>Windows Update 수동 확인"
}

# ══════════════════════════════════════════════════════════════════
# PC-08: 방화벽 활성화
# ══════════════════════════════════════════════════════════════════
Evd "PC-08" "Get-NetFirewallProfile -EA SilentlyContinue | Select-Object Name,Enabled | Format-Table"
$fwOff = @()
foreach ($p in "DomainProfile","StandardProfile","PublicProfile") {
    $e = Get-Reg "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\$p" "EnableFirewall"
    if ($null -eq $e -or $e -eq 0) { $fwOff += ($p -replace "Profile","") }
}
if ($fwOff.Count -gt 0) {
    Fail "08" "방화벽 비활성 프로필: $($fwOff -join ', ')"
} else {
    Pass "08" "Windows 방화벽 전체 활성 (Domain/Standard/Public)"
}

# ══════════════════════════════════════════════════════════════════
# PC-09: 이벤트 로그 관리
# ══════════════════════════════════════════════════════════════════
Evd "PC-09" "Get-WinEvent -ListLog Security,System,Application -EA SilentlyContinue | Select-Object LogName,@{n='MaxMB';e={[math]::Round(`$_.MaximumSizeInBytes/1MB,1)}} | Format-Table"
$logIssues = @(); $logOK = @()
foreach ($n in "Security","System","Application") {
    try {
        $log = Get-WinEvent -ListLog $n -EA Stop
        $mb  = [math]::Round($log.MaximumSizeInBytes / 1MB, 1)
        if ($mb -lt 10) { $logIssues += "${n}=${mb}MB" } else { $logOK += "${n}=${mb}MB" }
    } catch {
        $regMax = Get-Reg "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\$n" "MaxSize"
        if ($regMax) {
            $mb = [math]::Round($regMax / 1MB, 1)
            if ($mb -lt 10) { $logIssues += "${n}=${mb}MB(reg)" } else { $logOK += "${n}=${mb}MB(reg)" }
        } else {
            $logIssues += "${n}=조회실패(관리자권한필요)"
        }
    }
}
if ($logIssues.Count -gt 0) {
    Fail "09" "이벤트 로그 점검: 이상=$($logIssues -join ', ') / 정상=$($logOK -join ', ')"
} else {
    Pass "09" "Security/System/Application 로그 10MB 이상 ($($logOK -join ', '))"
}

# ══════════════════════════════════════════════════════════════════
# PC-10: 원격 데스크톱 제한
# ══════════════════════════════════════════════════════════════════
Evd "PC-10" "Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -EA SilentlyContinue | Select-Object fDenyTSConnections"
$fDeny = Get-Reg "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" "fDenyTSConnections"
$nla   = Get-Reg "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" "UserAuthentication"

if ($fDeny -eq 1) {
    Pass "10" "원격 데스크톱 비활성(fDenyTSConnections=1)"
} elseif ($nla -eq 1) {
    MC "10" "원격 데스크톱 활성+NLA 적용 - 업무 필요성 확인"
} else {
    Fail "10" "원격 데스크톱 활성, NLA 미적용 (fDeny=$fDeny, NLA=$nla)"
}

# ══════════════════════════════════════════════════════════════════
# PC-11: 자동실행(AutoRun/AutoPlay) 비활성화
# ══════════════════════════════════════════════════════════════════
Evd "PC-11" "Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name NoDriveTypeAutoRun,NoAutorun -EA SilentlyContinue"
$ndta   = Get-Reg "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" "NoDriveTypeAutoRun"
$noAR   = Get-Reg "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" "NoAutorun"
$disAP  = Get-Reg "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" "DisableAutoplay"

if ($ndta -eq 255 -or $noAR -eq 1 -or $disAP -eq 1) {
    Pass "11" "자동실행 비활성화 (NoDriveTypeAutoRun=$ndta, NoAutorun=$noAR, DisableAutoplay=$disAP)"
} else {
    Fail "11" "자동실행 비활성화 미설정 (NoDriveTypeAutoRun=$ndta)"
}

# ══════════════════════════════════════════════════════════════════
# PC-12: 이동매체(USB) 제한
# ══════════════════════════════════════════════════════════════════
Evd "PC-12" "Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices' -EA SilentlyContinue; Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\USBSTOR' -Name Start -EA SilentlyContinue | Select-Object Start"
$usbDeny  = Get-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices" "Deny_All"
$usbWrite = Get-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices\{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}" "Deny_Write"
$usbStore = Get-Reg "HKLM:\SYSTEM\CurrentControlSet\Services\USBSTOR" "Start"

if ($usbDeny -eq 1 -or $usbStore -eq 4) {
    Pass "12" "이동매체 차단됨 (Deny_All=$usbDeny, USBSTOR Start=$usbStore)"
} elseif ($usbWrite -eq 1) {
    MC "12" "USB 쓰기 차단, 읽기 허용 - 조직 정책 부합 여부 확인"
} else {
    MC "12" "USB 제한 정책 미설정 (USBSTOR=$usbStore) - 조직 정책에 따라 판단"
}

# ══════════════════════════════════════════════════════════════════
# PC-13: Guest 계정 비활성화
# ══════════════════════════════════════════════════════════════════
Evd "PC-13" "Get-LocalUser -Name Guest -EA SilentlyContinue | Select-Object Name,Enabled"
$guestEnabled = $false
try {
    $guest = Get-LocalUser -Name "Guest" -EA Stop
    $guestEnabled = $guest.Enabled
} catch {}

if ($guestEnabled) {
    Fail "13" "Guest 계정 활성화됨"
} else {
    Pass "13" "Guest 계정 비활성"
}

# ══════════════════════════════════════════════════════════════════
# PC-14: UAC(사용자 계정 컨트롤) 활성화
# ══════════════════════════════════════════════════════════════════
Evd "PC-14" "Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name EnableLUA,ConsentPromptBehaviorAdmin -EA SilentlyContinue | Select-Object EnableLUA,ConsentPromptBehaviorAdmin"
$lua     = Get-Reg "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "EnableLUA"
$consent = Get-Reg "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "ConsentPromptBehaviorAdmin"

if ($null -eq $lua -or $lua -eq 1) {
    if ($null -ne $consent -and [int]$consent -ge 1) {
        Pass "14" "UAC 활성, 관리자 동의 프롬프트 레벨=$consent"
    } elseif ([int]$consent -eq 0) {
        Fail "14" "UAC 활성이나 관리자 자동 승격(레벨=0) - 프롬프트 비활성"
    } else {
        Pass "14" "UAC 활성 (EnableLUA=$lua)"
    }
} else {
    Fail "14" "UAC 비활성화됨 (EnableLUA=$lua)"
}

# ══════════════════════════════════════════════════════════════════
# PC-15: SmartScreen / 브라우저 보안
# ══════════════════════════════════════════════════════════════════
Evd "PC-15" "Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' -Name SmartScreenEnabled -EA SilentlyContinue | Select-Object SmartScreenEnabled"
$ss = Get-Reg "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" "SmartScreenEnabled"
if ($ss -eq "Off" -or $ss -eq "0") {
    Fail "15" "Windows SmartScreen 비활성 ($ss)"
} elseif ($ss) {
    Pass "15" "SmartScreen 활성 ($ss)"
} else {
    MC "15" "SmartScreen 상태 확인 불가 - 수동 확인"
}

# ══════════════════════════════════════════════════════════════════
# PC-16: 로그인 실패 잠금 임계값
# ══════════════════════════════════════════════════════════════════
Evd "PC-16" "net accounts 2>`$null | Select-String 'Lockout|잠금'"
$lockBad = Get-SecPol "LockoutBadCount"
if ($null -eq $lockBad) {
    # secedit 실패 시 net accounts 폴백
    if (-not $naLockout) {
        $netAcct2 = net accounts 2>$null
        $naLockout = ($netAcct2 | Where-Object {$_ -match "Lockout threshold|잠금 임계값"} | ForEach-Object {($_ -split ":\s*",2)[1].Trim()})
    }
    if ($naLockout -and $naLockout -notmatch "^(Never|없음)$") {
        $lockVal = 0; [int]::TryParse(($naLockout -replace "[^\d]",""), [ref]$lockVal) | Out-Null
        if ($lockVal -gt 0 -and $lockVal -le 5) {
            Pass "16" "(net accounts) 계정 잠금 임계값: ${lockVal}회"
        } elseif ($lockVal -gt 5) {
            Fail "16" "(net accounts) 잠금 임계값 과다: ${lockVal}회 (5회 이하 권장)"
        } else {
            Fail "16" "(net accounts) 잠금 임계값 미설정"
        }
    } elseif ($naLockout -match "^(Never|없음)$") {
        Fail "16" "(net accounts) 계정 잠금 임계값 미설정($naLockout)"
    } else {
        MC "16" "secedit/net accounts 모두 실패 - 수동 확인"
    }
} elseif ([int]$lockBad -eq 0) {
    Fail "16" "계정 잠금 임계값 미설정(0=무제한)"
} elseif ([int]$lockBad -le 5) {
    Pass "16" "계정 잠금 임계값: ${lockBad}회"
} else {
    Fail "16" "계정 잠금 임계값 과다: ${lockBad}회 (5회 이하 권장)"
}

# ══════════════════════════════════════════════════════════════════
# PC-17: 감사 정책
# ══════════════════════════════════════════════════════════════════
Evd "PC-17" "auditpol /get /category:'*' 2>`$null | Select-String 'Logon|Object|Privilege'"
$auditLogon = Get-SecPol "AuditLogonEvents"
$auditObj   = Get-SecPol "AuditObjectAccess"
$auditPriv  = Get-SecPol "AuditPrivilegeUse"

if ($null -eq $auditLogon) {
    if ($isHome) {
        MC "17" "Home 에디션 - 감사 정책(secpol) 미지원"
    } else {
        MC "17" "감사 정책 조회 실패"
    }
} else {
    $miss = @()
    if ([int]$auditLogon -eq 0) { $miss += "로그온이벤트" }
    if ([int]$auditObj -eq 0)   { $miss += "개체액세스" }
    if ([int]$auditPriv -eq 0)  { $miss += "권한사용" }
    if ($miss.Count -gt 0) {
        Fail "17" "감사 정책 미설정: $($miss -join ', ')"
    } else {
        Pass "17" "감사 정책 활성 (로그온=$auditLogon, 개체=$auditObj, 권한=$auditPriv)"
    }
}

# ══════════════════════════════════════════════════════════════════
# PC-18: 디스크 암호화 (BitLocker)
# ══════════════════════════════════════════════════════════════════
try {
    Evd "PC-18" "Get-BitLockerVolume -MountPoint 'C:' -EA SilentlyContinue | Select-Object MountPoint,ProtectionStatus,EncryptionMethod"
    $bl = Get-BitLockerVolume -MountPoint "C:" -EA Stop
    if ($bl.ProtectionStatus -eq "On") {
        Pass "18" "BitLocker 활성 (C: 암호화, 방식=$($bl.EncryptionMethod))"
    } else {
        MC "18" "BitLocker 비활성 (ProtectionStatus=$($bl.ProtectionStatus)) - 조직 정책에 따라 판단"
    }
} catch {
    if ($isHome) {
        MC "18" "Home 에디션 - BitLocker 미지원 (Device Encryption 수동 확인)"
    } else {
        MC "18" "BitLocker 상태 확인 실패 - 수동 확인"
    }
}

# ══════════════════════════════════════════════════════════════════
# 요약
# ══════════════════════════════════════════════════════════════════
Write-Output "# ============================================================"
Write-Output "# 점검 완료"
Write-Output "# 양호: $($script:cntPass) / 취약: $($script:cntFail) / 수동확인: $($script:cntMC) / N-A: $($script:cntNA)"
Write-Output "# 증적 파일: $($script:EVD)"
Write-Output "# ============================================================"

if (Test-Path $seceditFile) { Remove-Item $seceditFile -Force -EA SilentlyContinue }
