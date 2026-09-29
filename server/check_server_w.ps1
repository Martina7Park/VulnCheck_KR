# ================================================================
# Windows 서버 주요정보통신기반시설 취약점 점검 스크립트 (2026 상세가이드 W-01 ~ W-64)
# ================================================================
#
# [기준]
#   주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드(2026, 과기정통부 고시 제2025-62호)
#   [Windows 서버] W-01 ~ W-64 - 항목코드·판단기준 가이드 원문 그대로
#   전자금융기반시설(SRV) 점검은 check_server.ps1, 둘 다는 check_server.ps1 -Mode all
#
# [대상 OS]  Windows Server 2008 R2 ~ 2025 (PowerShell 2.0 이상), 관리자 권한 필요(secedit·SAM 권한 조회)
#
# [실행 방법]
#   run_server.bat 에서 2) 주요정보 선택  또는
#   powershell -ExecutionPolicy Bypass -File check_server_w.ps1 > %COMPUTERNAME%_w.txt
#
# [산출물]
#   1) 표준출력: W-항목코드|결과|근거설명 (양호/취약/수동확인/N-A)
#   2) 증적 파일: 스크립트와 같은 폴더 <호스트명>_w_evidence.txt
# ================================================================
$ErrorActionPreference = "SilentlyContinue"
$ProgressPreference    = "SilentlyContinue"

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

Write-Output "# ================================================================"
Write-Output "# 점검 대상: $hn"
Write-Output "# OS: $(if ($os) { $os.Caption } else { "Windows Server $ver" }) (Build $build)"
Write-Output "# OS 상세: $(if ($os) { "$($os.Caption) $($os.Version)" } else { "Windows Build $build" })"
Write-Output "# 점검 기준: 주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드(2026) [Windows 서버 W-01~W-64]"
Write-Output "# 점검 일시: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Output "# ================================================================"
# 헬퍼
$seceditFile = "$env:TEMP\srvw_secpol_${PID}.cfg"
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
$script:cntPass=0; $script:cntFail=0; $script:cntMC=0; $script:cntNA=0
$script:ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$script:EVD = "$script:ScriptDir\${hn}_w_evidence.txt"
"# ================================================================" | Out-File $script:EVD -Encoding UTF8
"# 증적 파일 (감사 추적용) - 주요정보통신기반시설 상세가이드(2026) W-01~W-64" | Add-Content $script:EVD -Encoding UTF8
"# 대상: $hn / $(if ($os) { $os.Caption } else { 'Windows' }) (Build $build)" | Add-Content $script:EVD -Encoding UTF8
"# 생성: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" | Add-Content $script:EVD -Encoding UTF8
"# ================================================================" | Add-Content $script:EVD -Encoding UTF8
function Emit([string]$code,[string]$res,[string]$msg) {
    $msg = ($msg -replace "[`r`n]+", " / ") -replace '\|', '/'
    switch ($res) { "양호" { $script:cntPass++ } "취약" { $script:cntFail++ } "수동확인" { $script:cntMC++ } default { $script:cntNA++ } }
    Write-Output "$code|$res|$msg"; "[판정] $code|$res|$msg`n" | Add-Content $script:EVD -Encoding UTF8
}
function Pass([string]$code,[string]$msg) { Emit $code "양호" $msg }
function Fail([string]$code,[string]$msg) { Emit $code "취약" $msg }
function NA([string]$code,[string]$msg)   { Emit $code "N-A" $msg }
function MC([string]$code,[string]$msg)   { Emit $code "수동확인" $msg }
function Evd([string]$item,[string]$cmd) {
    "[$item] $(Get-Date -Format 'HH:mm:ss') PS> $cmd" | Add-Content $script:EVD -Encoding UTF8
    try { $r = Invoke-Expression $cmd 2>&1 | Out-String; $r | Add-Content $script:EVD -Encoding UTF8 } catch { $_.Exception.Message | Add-Content $script:EVD -Encoding UTF8 }
    "" | Add-Content $script:EVD -Encoding UTF8
}
function EvdQ([string]$item,[string]$desc,[string]$val) {
    "[$item] $(Get-Date -Format 'HH:mm:ss') $desc`n$val`n" | Add-Content $script:EVD -Encoding UTF8
}
$secOK = Test-Path $seceditFile   # secedit 내보내기 성공 여부 (관리자 권한 필요)
$secMsg = "보안 정책(secedit) 조회 불가 - 관리자 권한으로 재실행 또는 secpol.msc 확인"
function Int0($v) { if ("$v" -match '^-?\d+$') { [int]"$v" } else { $null } }
function SidNames([string]$v) { if (-not $v) { return @() }; return @($v -split ',' | ForEach-Object { Resolve-SecPolEntry $_ } | Where-Object { $_ }) }
$lsa  = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
$pol  = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
$lmsv = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
$tsP  = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
$rdpOn = ("$(Get-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' 'fDenyTSConnections')" -eq '0')
$ftpSites = Get-IisFtpSites
$ftpSvc = Get-SvcState 'FTPSVC'; if (-not $ftpSvc) { $ftpSvc = Get-SvcState 'MSFTPSVC' }
$ftpOn = $ftpSvc -and "$($ftpSvc.Status)" -match 'Running'
$w3 = Get-SvcState 'W3SVC'; $iisOn = $w3 -and "$($w3.Status)" -match 'Running'
$dnsSvc = Get-SvcState 'DNS'; $dnsOn = $dnsSvc -and "$($dnsSvc.Status)" -match 'Running'
$snmpSvc = Get-SvcState 'SNMP'; $snmpOn = $snmpSvc -and "$($snmpSvc.Status)" -match 'Running'
$accts = @(Get-LocalAccounts)

# ═══════════════ 1. 계정 관리 ═══════════════
# W-01 Administrator 계정 이름 변경 등 보안성 강화
Evd "W-01" "Get-LocalAccounts | Where-Object { `$_.SID -match '-500$' } | Select-Object Name,Enabled,PasswordLastSet | Format-List"
$adm = $accts | Where-Object { "$($_.SID)" -match '-500$' } | Select-Object -First 1
$newName = Get-SecPol 'NewAdministratorName'
EvdQ "W-01" "secedit NewAdministratorName" "$newName"
if (-not $adm) { MC "W-01" "기본 관리자(RID 500) 계정 조회 실패 - 계정 이름 확인" }
elseif ($adm.Name -ne 'Administrator') { Pass "W-01" "기본 관리자 계정 이름 변경됨: $($adm.Name)$(if (-not $adm.Enabled) { ' (비활성)' })" }
else { MC "W-01" "기본 관리자 계정 이름이 'Administrator'$(if (-not $adm.Enabled) { ' (계정 비활성)' }) - 가이드: 이름 변경 또는 강화된 비밀번호 적용 시 양호 → 비밀번호 강도(2종 10자/3종 8자) 확인" }

# W-02 Guest 계정 비활성화
Evd "W-02" "Get-LocalAccounts | Where-Object { `$_.SID -match '-501$' } | Select-Object Name,Enabled | Format-List"
$gst = $accts | Where-Object { "$($_.SID)" -match '-501$' } | Select-Object -First 1
$eg = Get-SecPol 'EnableGuestAccount'
if ($gst) { if ($gst.Enabled) { Fail "W-02" "Guest 계정 활성: $($gst.Name)" } else { Pass "W-02" "Guest 계정 비활성: $($gst.Name)" } }
elseif ("$eg" -eq '0') { Pass "W-02" "Guest 계정 비활성 (EnableGuestAccount=0)" }
else { MC "W-02" "Guest 계정 조회 실패 - lusrmgr.msc 확인" }

# W-03 불필요한 계정 제거
Evd "W-03" "Get-LocalAccounts | Select-Object Name,Enabled,LastLogon,PasswordLastSet | Format-Table -AutoSize"
$act = @($accts | Where-Object { $_.Enabled -and "$($_.SID)" -notmatch '-(501|503|504)$' })
$test = @($act | Where-Object { $_.Name -match '^(test|temp|tmp|guest|demo|user\d*|sample)' } | ForEach-Object { $_.Name })
$old = @($act | Where-Object { $_.LastLogon -and ((Get-Date) - [datetime]$_.LastLogon).Days -gt 90 } | ForEach-Object { "$($_.Name)(최근 로그인 $(([datetime]$_.LastLogon).ToString('yyyy-MM-dd')))" })
if ($test.Count) { Fail "W-03" "테스트성 계정 활성: $($test -join ', ')" }
else { MC "W-03" "활성 계정: $(($act | ForEach-Object { $_.Name }) -join ', ')$(if ($old.Count) { " / 90일 이상 미사용: $($old -join ', ')" }) - 퇴직자·미사용·불필요 계정 여부 확인 (없으면 양호)" }

# W-04 계정 잠금 임계값 (5 이하)
if (-not $secOK) { MC "W-04" $secMsg } else {
    $lc = Int0 (Get-SecPol 'LockoutBadCount'); EvdQ "W-04" "secedit LockoutBadCount" "$lc"
    if ($lc -and $lc -ge 1 -and $lc -le 5) { Pass "W-04" "계정 잠금 임계값 ${lc}회" } else { Fail "W-04" "계정 잠금 임계값 $(if (-not $lc) { '미설정(0)' } else { "${lc}회 (5 초과)" })" }
}

# W-05 해독 가능한 암호화를 사용하여 암호 저장 해제
if (-not $secOK) { MC "W-05" $secMsg } else {
    $ct = Get-SecPol 'ClearTextPassword'; EvdQ "W-05" "secedit ClearTextPassword" "$ct"
    if ("$ct" -eq '1') { Fail "W-05" "'해독 가능한 암호화를 사용하여 암호 저장' 사용" } else { Pass "W-05" "'해독 가능한 암호화를 사용하여 암호 저장' 사용 안 함 (ClearTextPassword=$(if ($null -eq $ct) { '미정의=0' } else { $ct }))" }
}

# W-06 관리자 그룹에 최소한의 사용자 포함
$am = Get-LocalGroupMemberNames 'S-1-5-32-544'
EvdQ "W-06" "Administrators 구성원" (($am) -join "`n")
if ($null -eq $am) { MC "W-06" "Administrators 구성원 조회 실패 - lusrmgr.msc 확인" }
elseif (@($am).Count -le 1) { Pass "W-06" "Administrators 구성원 $(@($am).Count)명: $($am -join ', ')" }
else { MC "W-06" "Administrators 구성원 $(@($am).Count)명: $($am -join ', ') - 불필요한 관리자 계정 여부 확인 (없으면 양호)" }

# W-07 Everyone 사용 권한을 익명 사용자에 적용 (사용 안 함)
$eia = Get-Reg $lsa 'EveryoneIncludesAnonymous'; EvdQ "W-07" "Lsa EveryoneIncludesAnonymous" "$eia"
if ("$eia" -eq '1') { Fail "W-07" "'Everyone 사용 권한을 익명 사용자에게 적용' 사용" } else { Pass "W-07" "'Everyone 사용 권한을 익명 사용자에게 적용' 사용 안 함 (EveryoneIncludesAnonymous=$(if ($null -eq $eia) { '미정의=0' } else { $eia }))" }

# W-08 계정 잠금 기간 (잠금 기간·원래대로 설정 기간 60분 이상)
if (-not $secOK) { MC "W-08" $secMsg } else {
    $ld = Int0 (Get-SecPol 'LockoutDuration'); $rl = Int0 (Get-SecPol 'ResetLockoutCount'); EvdQ "W-08" "secedit LockoutDuration / ResetLockoutCount" "$ld / $rl"
    if ($ld -ne $null -and $rl -ne $null -and ($ld -ge 60 -or $ld -eq -1) -and $rl -ge 60) { Pass "W-08" "계정 잠금 기간 $(if ($ld -eq -1) { '관리자 해제' } else { "${ld}분" }), 원래대로 설정 ${rl}분" }
    else { Fail "W-08" "계정 잠금 기간 $(if ($null -eq $ld) { '미설정' } else { "${ld}분" }) / 원래대로 설정 기간 $(if ($null -eq $rl) { '미설정' } else { "${rl}분" }) (60분 이상 필요)" }
}

# W-09 비밀번호 관리 정책 (복잡성·최소 8자·최대 90일·최소 1일·최근 암호 4개)
if (-not $secOK) { MC "W-09" $secMsg } else {
    $cx = Get-SecPol 'PasswordComplexity'; $ml = Int0 (Get-SecPol 'MinimumPasswordLength'); $mx = Int0 (Get-SecPol 'MaximumPasswordAge'); $mn = Int0 (Get-SecPol 'MinimumPasswordAge'); $hs = Int0 (Get-SecPol 'PasswordHistorySize')
    EvdQ "W-09" "복잡성 / 최소길이 / 최대기간 / 최소기간 / 기억" "$cx / $ml / $mx / $mn / $hs"
    $b = @()
    if ("$cx" -ne '1') { $b += '복잡성 사용 안 함' }; if (-not $ml -or $ml -lt 8) { $b += "최소 길이 $ml(8 이상)" }
    if (-not $mx -or $mx -lt 1 -or $mx -gt 90) { $b += "최대 사용 기간 $(if ($mx -le 0) { '무제한' } else { $mx })(90일 이하)" }; if (-not $mn -or $mn -lt 1) { $b += "최소 사용 기간 $mn(1일 이상)" }
    if (-not $hs -or $hs -lt 4) { $b += "최근 암호 기억 $hs(4개 이상)" }
    if ($b.Count) { Fail "W-09" "비밀번호 관리 정책 미흡: $($b -join ', ')" } else { Pass "W-09" "복잡성 사용, 최소 ${ml}자, 최대 ${mx}일, 최소 ${mn}일, 기억 ${hs}개" }
}

# W-10 마지막 사용자 이름 표시 안 함
$dl = Get-Reg $pol 'DontDisplayLastUserName'; EvdQ "W-10" "DontDisplayLastUserName" "$dl"
if ("$dl" -eq '1') { Pass "W-10" "'마지막 사용자 이름 표시 안 함' 사용" } else { Fail "W-10" "'마지막 사용자 이름 표시 안 함' 사용 안 함 (DontDisplayLastUserName=$(if ($null -eq $dl) { '미정의=0' } else { $dl }))" }

# W-11 로컬 로그온 허용 (Administrators, IUSR_ 만)
if (-not $secOK) { MC "W-11" $secMsg } else {
    $il = Get-SecPol 'SeInteractiveLogonRight'; $n = SidNames $il; EvdQ "W-11" "SeInteractiveLogonRight" "$il => $($n -join ', ')"
    $ext = @(($il -split ',') | Where-Object { $_ -and $_.Trim() -ne '*S-1-5-32-544' } | ForEach-Object { Resolve-SecPolEntry $_ } | Where-Object { $_ -notmatch 'IUSR' })
    if ($ext.Count) { Fail "W-11" "로컬 로그온 허용에 Administrators·IUSR_ 외 계정/그룹: $($ext -join ', ')" } else { Pass "W-11" "로컬 로그온 허용: $($n -join ', ')" }
}

# W-12 익명 SID/이름 변환 허용 해제
if (-not $secOK) { MC "W-12" $secMsg } else {
    $an = Get-SecPol 'LSAAnonymousNameLookup'; EvdQ "W-12" "LSAAnonymousNameLookup" "$an"
    if ("$an" -eq '1') { Fail "W-12" "'익명 SID/이름 변환 허용' 사용" } else { Pass "W-12" "'익명 SID/이름 변환 허용' 사용 안 함" }
}

# W-13 콘솔 로그온 시 로컬 계정에서 빈 암호 사용 제한
$lb = Get-Reg $lsa 'LimitBlankPasswordUse'; EvdQ "W-13" "Lsa LimitBlankPasswordUse" "$lb"
if ("$lb" -eq '0') { Fail "W-13" "'콘솔 로그온 시 로컬 계정에서 빈 암호 사용 제한' 사용 안 함" } else { Pass "W-13" "'콘솔 로그온 시 로컬 계정에서 빈 암호 사용 제한' 사용 (LimitBlankPasswordUse=$(if ($null -eq $lb) { '미정의=1' } else { $lb }))" }

# W-14 원격터미널 접속 가능한 사용자 그룹 제한
$rdu = Get-LocalGroupMemberNames 'S-1-5-32-555'
EvdQ "W-14" "원격 데스크톱 사용 / Remote Desktop Users 구성원" "fDenyTSConnections=$(Get-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' 'fDenyTSConnections') / $(@($rdu) -join ', ')"
if (-not $rdpOn) { Pass "W-14" "원격 데스크톱 사용 안 함 (fDenyTSConnections=1)" }
elseif ($null -eq $rdu) { MC "W-14" "Remote Desktop Users 구성원 조회 실패 - 확인 필요" }
elseif (-not @($rdu).Count) { Fail "W-14" "원격 데스크톱 사용 중이나 관리자 외 원격 접속 전용 계정 없음 (Remote Desktop Users 비어 있음 - 관리자 계정으로 원격 접속)" }
else { MC "W-14" "원격 접속 사용자 그룹: $($rdu -join ', ') - 불필요한 계정 여부 확인 (없으면 양호)" }

# W-15 사용자 개인키 사용 시 암호 입력 (ForceKeyProtection=2)
$fk = Get-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Cryptography' 'ForceKeyProtection'; EvdQ "W-15" "ForceKeyProtection" "$fk"
if ("$fk" -eq '2') { Pass "W-15" "'강력한 키 보호' - 키를 사용할 때마다 암호 입력 (ForceKeyProtection=2)" } else { Fail "W-15" "'강력한 키 보호' 매번 암호 입력 미설정 (ForceKeyProtection=$(if ($null -eq $fk) { '미정의(입력 안 함)' } else { $fk }))" }

# ═══════════════ 2. 서비스 관리 ═══════════════
# W-16 공유 권한 및 사용자 그룹 설정 (일반 공유 Everyone 권한)
Evd "W-16" "Get-SmbShare -EA SilentlyContinue | Where-Object { `$_.Name -notmatch '\$$' } | ForEach-Object { Get-SmbShareAccess -Name `$_.Name } | Format-Table -AutoSize"
$shr = @(Get-CimInstance Win32_Share -EA SilentlyContinue | Where-Object { $_.Type -eq 0 -and $_.Name -notmatch '\$$' })
$ev16 = @()
foreach ($s in $shr) { $a = @(Get-SmbShareAccess -Name $s.Name -EA SilentlyContinue | Where-Object { "$($_.AccountName)" -match 'Everyone|모든 사용자' -and "$($_.AccessControlType)" -eq 'Allow' }); if ($a.Count) { $ev16 += $s.Name } }
if ($ev16.Count) { Fail "W-16" "Everyone 권한이 있는 공유: $($ev16 -join ', ')" } elseif ($shr.Count) { Pass "W-16" "일반 공유 $($shr.Count)개에 Everyone 권한 없음: $(($shr | ForEach-Object { $_.Name }) -join ', ')" } else { Pass "W-16" "일반 공유 디렉터리 없음" }

# W-17 하드디스크 기본 공유 제거 (AutoShareServer=0, C$ 등 없음)
$as = Get-Reg $lmsv 'AutoShareServer'; $dsh = @(Get-CimInstance Win32_Share -EA SilentlyContinue | Where-Object { $_.Name -match '^([A-Z]\$|ADMIN\$)$' } | ForEach-Object { $_.Name })
EvdQ "W-17" "AutoShareServer / 기본 공유" "$as / $($dsh -join ', ')"
if ("$as" -eq '0' -and -not $dsh.Count) { Pass "W-17" "기본 공유 제거 (AutoShareServer=0)" } else { Fail "W-17" "기본 공유 존재 또는 자동 생성 (AutoShareServer=$(if ($null -eq $as) { '미정의=1' } else { $as }), 기본 공유: $(if ($dsh.Count) { $dsh -join ', ' } else { '없음' }))" }

# W-18 불필요한 서비스 제거 (가이드 '일반적으로 불필요한 서비스')
$svcA = [ordered]@{ Alerter="Alerter"; ClipSrv="Clipbook"; Browser="Computer Browser"; Messenger="Messenger"; mnmsrvc="NetMeeting Remote Desktop Sharing"; simptcp="Simple TCP/IP Services"
    WZCSVC="Wireless Zero Configuration"; WmdmPmSN="Portable Media Serial Number"; ImapiService="IMAPI CD-Burning COM Service"; ERSvc="Error Reporting Service"; Irmon="Infrared Monitor"
    HidServ="Human Interface Device Access"; upnphost="Universal Plug and Play Device Host"; TrkWks="Distributed Link Tracking Client"; TrkSvr="Distributed Link Tracking Server" }
$svcB = [ordered]@{ wuauserv="Automatic Updates(패치 관리 서버·수동 패치 시 불필요)"; CryptSvc="Cryptographic Services"; Dhcp="DHCP Client(고정 IP 시 불필요)"; Dnscache="DNS Client"; Spooler="Print Spooler(프린터 미사용 시 불필요)" }
Evd "W-18" "Get-Service $((@($svcA.Keys)+@($svcB.Keys)) -join ',') -EA SilentlyContinue | Select-Object Name,DisplayName,Status,StartType | Format-Table -AutoSize"
$runA = @(); foreach ($k in $svcA.Keys) { $s = Get-Service $k -EA SilentlyContinue; if ($s -and "$($s.Status)" -eq 'Running') { $runA += "$($svcA[$k])($k)" } }
$runB = @(); foreach ($k in $svcB.Keys) { $s = Get-Service $k -EA SilentlyContinue; if ($s -and "$($s.Status)" -eq 'Running') { $runB += "$($svcB[$k])" } }
if ($runA.Count) { Fail "W-18" "불필요한 서비스 구동 중: $($runA -join ', ')$(if ($runB.Count) { " / 용도 확인 필요: $($runB -join ', ')" })" }
elseif ($runB.Count) { MC "W-18" "가이드 목록 중 용도에 따라 불필요한 서비스 구동: $($runB -join ', ') - 시스템 용도상 필요 여부 확인" }
else { Pass "W-18" "가이드 목록의 불필요한 서비스 미구동" }

# W-19 불필요한 IIS 서비스 구동 점검
EvdQ "W-19" "W3SVC 상태" "$(if ($w3) { "$($w3.Status)/$($w3.Start)" } else { '미설치' })"
if (-not $w3) { Pass "W-19" "IIS(W3SVC) 미설치" } elseif (-not $iisOn) { Pass "W-19" "IIS(W3SVC) 미구동 ($($w3.Start))" } else { MC "W-19" "IIS(W3SVC) 구동 중 - 업무상 필요 여부 확인 (필요 시 양호, 불필요 시 중지·제거)" }

# W-20 NetBIOS 바인딩 서비스 구동 점검 (TcpipNetbiosOptions=2)
$nics = @(Get-CimInstance Win32_NetworkAdapterConfiguration -Filter "IPEnabled=True" -EA SilentlyContinue)
EvdQ "W-20" "어댑터별 TcpipNetbiosOptions (0 기본/1 사용/2 사용 안 함)" (($nics | ForEach-Object { "$($_.Description): $($_.TcpipNetbiosOptions)" }) -join "`n")
$nb = @($nics | Where-Object { "$($_.TcpipNetbiosOptions)" -ne '2' } | ForEach-Object { "$($_.Description)($($_.TcpipNetbiosOptions))" })
if (-not $nics.Count) { MC "W-20" "IP 어댑터 조회 실패 - 네트워크 연결 속성 확인" } elseif ($nb.Count) { Fail "W-20" "TCP/IP-NetBIOS 바인딩 제거 안 됨: $($nb -join ', ')" } else { Pass "W-20" "모든 IP 어댑터 NetBIOS over TCP/IP 사용 안 함" }

# W-21 암호화되지 않는 FTP 서비스 비활성화 / W-22 FTP 디렉토리 접근권한 / W-23 FTP 익명 인증 / W-24 FTP 접근 제어
EvdQ "W-21" "FTP 서비스 / IIS FTP 사이트" "$(if ($ftpSvc) { "$($ftpSvc.Status)" } else { '미설치' }) / $(@($ftpSites | ForEach-Object { "$($_.Name) ssl=$($_.Ctl)/$($_.Dat) anon=$($_.Anon) ip제한=$($_.IpRestr) root=$($_.Root)" }) -join '; ')"
if (-not $ftpOn) {
    foreach ($c in "W-21","W-22","W-23","W-24") { Pass $c "FTP 서비스 미사용$(if ($ftpSvc) { " ($($ftpSvc.Status))" } else { ' (미설치)' })" }
} else {
    $plain = @($ftpSites | Where-Object { "$($_.Ctl)" -notmatch 'SslRequire' -or "$($_.Dat)" -notmatch 'SslRequire' } | ForEach-Object { $_.Name })
    if ($null -eq $ftpSites) { MC "W-21" "FTP 서비스 구동 - IIS 설정 파싱 실패, FTPS(SSL 필요) 여부 확인" } elseif ($plain.Count) { Fail "W-21" "암호화되지 않은 FTP 허용 사이트(SSL 필요 아님): $($plain -join ', ')" } else { Pass "W-21" "FTP 사이트 모두 SSL 필요(FTPS)" }
    $ev22 = @(); foreach ($s in @($ftpSites)) { if ($s.Root -and (Test-Path $s.Root)) { $ac = @((Get-Acl $s.Root -EA SilentlyContinue).Access | Where-Object { (Get-AceSid $_) -eq 'S-1-1-0' }); if ($ac.Count) { $ev22 += "$($s.Name)($($s.Root))" } } }
    if ($ev22.Count) { Fail "W-22" "FTP 홈 디렉터리 Everyone 권한: $($ev22 -join ', ')" } else { Pass "W-22" "FTP 홈 디렉터리 Everyone 권한 없음" }
    $an23 = @($ftpSites | Where-Object { "$($_.Anon)" -eq 'true' } | ForEach-Object { $_.Name })
    if ($an23.Count) { Fail "W-23" "FTP 익명 인증 사용: $($an23 -join ', ')" } else { Pass "W-23" "FTP 익명 인증 사용 안 함" }
    $ip24 = @($ftpSites | Where-Object { -not $_.IpRestr } | ForEach-Object { $_.Name })
    if ($ip24.Count) { Fail "W-24" "FTP IP 접근 제어 미설정: $($ip24 -join ', ')" } else { Pass "W-24" "FTP 사이트 IP 접근 제어 설정" }
}

# W-25 DNS Zone Transfer (SecureSecondaries 0=모두 허용) / W-32 DNS 동적 업데이트 (AllowUpdate 0=없음)
$zr = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\DNS Server\Zones'
$zones = @(if (Test-Path $zr) { Get-ChildItem $zr -EA SilentlyContinue | Where-Object { $_.PSChildName -notmatch '^(TrustAnchors|RootDNSServers)$' } })
EvdQ "W-25" "DNS 서비스 / 영역별 SecureSecondaries·AllowUpdate" "$(if ($dnsSvc) { $dnsSvc.Status } else { '미설치' }) / $(($zones | ForEach-Object { $p=Get-ItemProperty $_.PSPath; "$($_.PSChildName): xfer=$($p.SecureSecondaries) update=$($p.AllowUpdate)" }) -join '; ')"
if (-not $dnsOn) { Pass "W-25" "DNS 서비스 미사용"; Pass "W-32" "DNS 서비스 미사용" }
else {
    $x25 = @($zones | Where-Object { "$((Get-ItemProperty $_.PSPath).SecureSecondaries)" -eq '0' } | ForEach-Object { $_.PSChildName })
    if ($x25.Count) { Fail "W-25" "영역 전송을 모든 서버에 허용: $($x25 -join ', ')" } else { Pass "W-25" "영역 전송 허용 안 함 또는 특정 서버로 제한 ($($zones.Count)개 영역)" }
    $u32 = @($zones | Where-Object { @('','0') -notcontains "$((Get-ItemProperty $_.PSPath).AllowUpdate)" } | ForEach-Object { "$($_.PSChildName)($((Get-ItemProperty $_.PSPath).AllowUpdate))" })
    if ($u32.Count) { Fail "W-32" "동적 업데이트 설정 영역(1=비보안·보안, 2=보안만): $($u32 -join ', ') - 가이드: '없음'" } else { Pass "W-32" "모든 영역 동적 업데이트 없음" }
}

# W-26 RDS(Remote Data Services) 제거 - Windows 2008 이상이면 양호
if ($build -ge 6001) { Pass "W-26" "Windows 2008 이상(Build $build) - RDS 기본 제거 (가이드 양호 기준 2)" } else { MC "W-26" "Windows 2008 미만 - MSADC 가상 디렉터리·RDS 레지스트리 확인" }

# W-27 최신 Windows OS Build 버전 적용 (지원 종료 = 취약)
$ubr = Get-Reg 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' 'UBR'
$eos27 = @{ 7601='2020-01-14'; 9200='2023-10-10'; 9600='2023-10-10'; 14393='2027-01-12'; 17763='2029-01-09'; 20348='2031-10-14'; 26100='2034-10-10' }
EvdQ "W-27" "Build.UBR / 연장 지원 종료일" "$build.$ubr / $($eos27[$build])"
if ($os -and $os.ProductType -eq 1) { MC "W-27" "서버 OS 아님($($os.Caption), Build $build.$ubr) - 클라이언트는 PC 항목(PC-11) 참고" }
elseif ($eos27.ContainsKey($build) -and (Get-Date) -gt [datetime]$eos27[$build]) { Fail "W-27" "Windows Server Build $build 지원 종료($($eos27[$build])) - 보안 업데이트 미제공" }
else { MC "W-27" "Windows Build $build.$ubr$(if ($eos27.ContainsKey($build)) { " (연장 지원 ~$($eos27[$build]))" }) - 최신 누적 업데이트 적용 여부·적용 절차 수립 확인" }

# W-28 터미널 서비스 암호화 수준 (중간(2) 이상)
$mel = Get-Reg $tsP 'MinEncryptionLevel'; if ($null -eq $mel) { $mel = Get-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' 'MinEncryptionLevel' }
EvdQ "W-28" "RDP 사용 / MinEncryptionLevel" "$rdpOn / $mel"
if (-not $rdpOn) { Pass "W-28" "원격 데스크톱 사용 안 함" } elseif ($null -ne $mel -and [int]$mel -lt 2) { Fail "W-28" "원격 데스크톱 암호화 수준 '낮음'(MinEncryptionLevel=$mel)" } else { Pass "W-28" "원격 데스크톱 암호화 수준 $(switch ("$mel") { '2' {'클라이언트와 호환 가능(중간)'} '3' {'높음'} '4' {'FIPS'} default {'기본(중간)'} })" }

# W-29 불필요한 SNMP 서비스 / W-30 Community String / W-31 SNMP Access Control
$vc = @(); $vk = 'HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\ValidCommunities'
if (Test-Path $vk) { $vc = @((Get-Item $vk).Property) }
$pm = @(); $pk = 'HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\PermittedManagers'
if (Test-Path $pk) { $pmI = Get-ItemProperty $pk; $pm = @((Get-Item $pk).Property | ForEach-Object { $pmI.$_ } | Where-Object { $_ }) }
EvdQ "W-29" "SNMP 서비스 / 커뮤니티 수 / 허용 관리자" "$(if ($snmpSvc) { $snmpSvc.Status } else { '미설치' }) / $($vc.Count)개 / $($pm -join ', ')"
if (-not $snmpOn) { foreach ($c in "W-29","W-30","W-31") { Pass $c "SNMP 서비스 미사용" } }
else {
    if ($vc.Count) { MC "W-29" "SNMP 서비스 사용(Community String $($vc.Count)개 설정) - 업무상 필요 여부 확인 (필요 시 양호)" } else { Fail "W-29" "SNMP 서비스 사용 중이나 Community String 미설정" }
    $wk = @($vc | Where-Object { $_ -match '^(public|private)$' }); if ($wk.Count) { Fail "W-30" "기본 Community String 사용: $($wk -join ', ')" } else { Pass "W-30" "Community String 이 public·private 아님 ($($vc.Count)개, 값 비공개)" }
    if ($pm.Count) { Pass "W-31" "특정 호스트로부터만 SNMP 패킷 수신: $($pm -join ', ')" } else { Fail "W-31" "모든 호스트로부터 SNMP 패킷 받아들이기" }
}

# W-33 HTTP/FTP/SMTP 배너 차단
$b33 = @(); $o33 = @()
if ($iisOn) {
    $dsh2 = Get-Reg 'HKLM:\SYSTEM\CurrentControlSet\Services\HTTP\Parameters' 'DisableServerHeader'
    $rsh = (Read-AllText "$env:windir\System32\inetsrv\config\applicationHost.config") -match 'removeServerHeader="true"'
    if ("$dsh2" -eq '2' -or $rsh) { $o33 += 'HTTP' } else { $b33 += "HTTP(Server 헤더 노출: DisableServerHeader=$dsh2, removeServerHeader 미설정)" }
}
if ($ftpOn) { $nb33 = @($ftpSites | Where-Object { "$($_.Banner)" -ne 'true' } | ForEach-Object { $_.Name }); if ($nb33.Count) { $b33 += "FTP 기본 배너 노출: $($nb33 -join ', ')" } else { $o33 += 'FTP' } }
$smtp = Get-SvcState 'SMTPSVC'; if ($smtp -and "$($smtp.Status)" -match 'Running') { $b33 += 'SMTP(IIS SMTP 배너 - ConnectResponse 설정 확인)' }
EvdQ "W-33" "배너 점검 대상" "IIS=$iisOn FTP=$ftpOn SMTP=$(if ($smtp) { $smtp.Status } else { '미설치' })"
if ($b33.Count) { Fail "W-33" "배너 정보 노출: $($b33 -join ' / ')" } elseif ($o33.Count) { Pass "W-33" "배너 차단: $($o33 -join ', ')" } else { Pass "W-33" "HTTP·FTP·SMTP 서비스 미사용" }

# W-34 Telnet 서비스 (미구동 또는 NTLM 인증)
$tl = Get-SvcState 'TlntSvr'; $sm = Get-Reg 'HKLM:\SOFTWARE\Microsoft\TelnetServer\1.0' 'SecurityMechanism'
EvdQ "W-34" "Telnet 서비스 / SecurityMechanism(2=NTLM)" "$(if ($tl) { $tl.Status } else { '미설치' }) / $sm"
if (-not $tl -or "$($tl.Status)" -notmatch 'Running') { Pass "W-34" "Telnet 서비스 미구동" } elseif ("$sm" -eq '2') { Pass "W-34" "Telnet 인증 NTLM 만 사용" } else { Fail "W-34" "Telnet 서비스 구동, 인증 방법 NTLM 아님 (SecurityMechanism=$sm)" }

# W-35 불필요한 ODBC/OLE-DB 데이터 소스
$dsn = @(); foreach ($k in 'HKLM:\SOFTWARE\ODBC\ODBC.INI\ODBC Data Sources','HKLM:\SOFTWARE\WOW6432Node\ODBC\ODBC.INI\ODBC Data Sources') { if (Test-Path $k) { $dsn += @((Get-Item $k).Property) } }
EvdQ "W-35" "시스템 DSN" ($dsn -join "`n")
if (-not $dsn.Count) { Pass "W-35" "시스템 DSN 없음" } else { MC "W-35" "시스템 DSN $($dsn.Count)개: $($dsn -join ', ') - 현재 사용 여부 확인 (미사용 DSN 은 제거)" }

# W-36 원격터미널 접속 타임아웃 (30분 이하)
$mit = Get-Reg $tsP 'MaxIdleTime'; if ($null -eq $mit) { $mit = Get-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' 'MaxIdleTime' }
EvdQ "W-36" "RDP 사용 / MaxIdleTime(ms)" "$rdpOn / $mit"
if (-not $rdpOn) { Pass "W-36" "원격 데스크톱 사용 안 함" } elseif ($mit -and [int64]$mit -gt 0 -and [int64]$mit -le 1800000) { Pass "W-36" "유휴 세션 제한 $([int64]$mit/60000)분" } else { Fail "W-36" "유휴 세션 제한 $(if (-not $mit -or [int64]$mit -eq 0) { '미설정(무제한)' } else { "$([int64]$mit/60000)분 (30분 초과)" })" }

# W-37 예약된 작업 점검
$tk = @(Get-ScheduledTask -EA SilentlyContinue | Where-Object { $_.TaskPath -notmatch '^\\Microsoft\\' -and $_.State -ne 'Disabled' })
EvdQ "W-37" "Microsoft 외 예약 작업(작업 경로·이름·실행 명령)" (($tk | ForEach-Object { "$($_.TaskPath)$($_.TaskName) => $(@($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join ' ; ')" }) -join "`n")
if (-not (Get-Command Get-ScheduledTask -EA SilentlyContinue)) { MC "W-37" "예약 작업 조회 불가(PS 버전) - schtasks /query /v 로 확인" }
elseif ($tk.Count) { MC "W-37" "Microsoft 외 예약 작업 $($tk.Count)개: $(($tk | Select-Object -First 8 | ForEach-Object { $_.TaskName }) -join ', ') - 불필요·의심 명령 여부 확인 및 주기 점검 절차 확인" }
else { MC "W-37" "Microsoft 외 예약 작업 없음 - 예약 작업 주기 점검 절차 수립 여부 확인" }

# ═══════════════ 3. 패치 관리 ═══════════════
# W-38 주기적 보안 패치
$hf = Get-HotFix -EA SilentlyContinue | Where-Object { $_.InstalledOn } | Sort-Object InstalledOn -Descending | Select-Object -First 1
EvdQ "W-38" "최근 HOT FIX" "$(if ($hf) { "$($hf.HotFixID) $($hf.InstalledOn)" } else { '조회 실패' })"
if (-not $hf) { MC "W-38" "HOT FIX 설치 이력 조회 실패 - Windows 업데이트 기록 확인" }
else { $age = ((Get-Date) - [datetime]$hf.InstalledOn).Days
    if ($age -gt 90) { Fail "W-38" "최근 HOT FIX $($hf.HotFixID) 설치 후 ${age}일 경과 - 주기적 패치 미적용" } else { MC "W-38" "최근 HOT FIX $($hf.HotFixID) (${age}일 전) - 패치 절차 수립·주기적 확인 여부 인터뷰" } }

# W-39 백신 프로그램 업데이트 / W-45 백신 프로그램 설치
$mp = $null; try { $mp = Get-MpComputerStatus -EA Stop } catch {}
$avSvc = @(Get-Service -EA SilentlyContinue | Where-Object { "$($_.Status)" -eq 'Running' -and ($_.DisplayName -match 'AhnLab|V3 |ALYac|Symantec|McAfee|Trend Micro|Kaspersky|ESET|Sophos|CrowdStrike|SentinelOne|Trellix|Bitdefender|Cylance|Carbon Black' -or $_.Name -eq 'WinDefend') } | ForEach-Object { $_.DisplayName })
EvdQ "W-45" "Defender / 백신 서비스" "$(if ($mp) { "AMServiceEnabled=$($mp.AMServiceEnabled) RealTime=$($mp.RealTimeProtectionEnabled) Sig=$($mp.AntivirusSignatureLastUpdated)" } else { '조회 불가' }) / $($avSvc -join ', ')"
if (($mp -and $mp.AMServiceEnabled) -or $avSvc.Count) { Pass "W-45" "백신 설치: $(($avSvc + @(if ($mp -and $mp.AMServiceEnabled -and -not ($avSvc -match 'Defender')) { 'Microsoft Defender' })) -join ', ')" } else { Fail "W-45" "백신 프로그램 미탐지" }
if ($mp -and $mp.AMServiceEnabled -and $mp.AntivirusSignatureLastUpdated) { $sa = ((Get-Date) - $mp.AntivirusSignatureLastUpdated).Days
    if ($sa -le 7) { Pass "W-39" "Microsoft Defender 엔진·패턴 최신 (${sa}일 전 갱신)" } else { Fail "W-39" "Microsoft Defender 서명 ${sa}일 경과 - 망 격리 환경이면 업데이트 절차 확인" } }
elseif ($avSvc.Count) { MC "W-39" "백신($($avSvc -join ', ')) 최신 엔진 업데이트 여부 백신 콘솔에서 확인 (망 격리 시 업데이트 절차)" }
else { Fail "W-39" "백신 프로그램 미탐지 - 업데이트 불가" }

# ═══════════════ 4. 로그 관리 ═══════════════
# W-40 정책에 따른 시스템 로깅 (감사 정책 권고 기준)  secedit 값: 0 없음 / 1 성공 / 2 실패 / 3 성공·실패
if (-not $secOK) { MC "W-40" $secMsg } else {
    $need = [ordered]@{ AuditAccountManage=@(2,'계정 관리: 실패'); AuditAccountLogon=@(3,'계정 로그온 이벤트: 성공/실패'); AuditPrivilegeUse=@(3,'권한 사용: 성공/실패')
                        AuditDSAccess=@(2,'디렉터리 서비스 액세스: 실패'); AuditLogonEvents=@(3,'로그온 이벤트: 성공/실패'); AuditPolicyChange=@(3,'정책 변경: 성공/실패') }
    $miss = @(); $vals = @()
    foreach ($k in $need.Keys) { $v = Int0 (Get-SecPol $k); $vals += "$k=$v"; if ($null -eq $v -or (($v -band $need[$k][0]) -ne $need[$k][0])) { $miss += $need[$k][1] } }
    EvdQ "W-40" "secedit [Event Audit] (고급 감사 정책은 auditpol /get /category:* 증적 참고)" ($vals -join ', ')
    Evd "W-40" "auditpol /get /category:* 2>`$null"
    if ($miss.Count) { Fail "W-40" "감사 정책 권고 기준 미충족: $($miss -join ', ') (고급 감사 정책 사용 시 auditpol 증적으로 재확인)" } else { Pass "W-40" "감사 정책 권고 기준 충족" }
}

# W-41 NTP 및 시각 동기화
$wt = Get-SvcState 'W32Time'; $ty = Get-Reg 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters' 'Type'; $ns = Get-Reg 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters' 'NtpServer'
EvdQ "W-41" "W32Time / Type / NtpServer" "$(if ($wt) { $wt.Status }) / $ty / $ns"
if ($wt -and "$($wt.Status)" -match 'Running' -and "$ty" -match 'NTP|NT5DS|AllSync') { Pass "W-41" "시각 동기화 사용 (Type=$ty$(if ("$ty" -match 'NTP') { ", 서버 $ns" }))" } else { Fail "W-41" "시각 동기화 미설정 또는 W32Time 미구동 (Type=$ty, 상태 $(if ($wt) { $wt.Status } else { '없음' }))" }

# W-42 이벤트 로그 관리 (최대 크기 10,240KB 이상)
$lg = @('Application','Security','System' | ForEach-Object { $n=$_; try { Get-WinEvent -ListLog $n -EA Stop } catch { $null } } | Where-Object { $_ })
EvdQ "W-42" "로그 / 최대 크기(KB) / 모드" (($lg | ForEach-Object { "$($_.LogName) / $([int]($_.MaximumSizeInBytes/1KB)) / $($_.LogMode)" }) -join "`n")
$sm42 = @($lg | Where-Object { $_.MaximumSizeInBytes -lt 10MB } | ForEach-Object { "$($_.LogName)($([int]($_.MaximumSizeInBytes/1KB))KB)" })
if ($lg.Count -lt 3) { MC "W-42" "이벤트 로그 설정 조회 일부 실패 - 이벤트 뷰어에서 최대 크기 확인" } elseif ($sm42.Count) { Fail "W-42" "최대 로그 크기 10,240KB 미만: $($sm42 -join ', ')" } else { Pass "W-42" "Application·Security·System 최대 로그 크기 10,240KB 이상 (2008 이상은 덮어쓰기 기간 지정 불가 - 가이드 참고)" }

# W-43 이벤트 로그 파일 접근 통제 (Everyone 권한 없음)
$ld43 = "$env:SystemRoot\System32\winevt\Logs"; $acl43 = Get-Acl $ld43 -EA SilentlyContinue
EvdQ "W-43" "$ld43 ACL" "$(if ($acl43) { ($acl43.Access | ForEach-Object { "$($_.IdentityReference) $($_.FileSystemRights) $($_.AccessControlType)" }) -join "`n" } else { '조회 불가' })"
if (-not $acl43) { MC "W-43" "로그 디렉터리 권한 조회 불가(관리자 권한 필요) - $ld43 보안 탭 확인" } elseif (@($acl43.Access | Where-Object { (Get-AceSid $_) -eq 'S-1-1-0' }).Count) { Fail "W-43" "로그 디렉터리에 Everyone 권한: $ld43" } else { Pass "W-43" "로그 디렉터리 Everyone 권한 없음" }

# ═══════════════ 5. 보안 관리 ═══════════════
# W-44 원격으로 액세스할 수 있는 레지스트리 경로 (Remote Registry 중지)
$rr = Get-SvcState 'RemoteRegistry'; EvdQ "W-44" "RemoteRegistry" "$(if ($rr) { "$($rr.Status)/$($rr.Start)" } else { '없음' })"
if ($rr -and "$($rr.Status)" -match 'Running') { Fail "W-44" "Remote Registry 서비스 사용 중" } else { Pass "W-44" "Remote Registry 서비스 중지$(if ($rr) { " ($($rr.Start))" })" }

# W-46 SAM 파일 접근 통제 (Administrators·SYSTEM 만)
$sam = "$env:SystemRoot\System32\config\SAM"; $acl46 = Get-Acl $sam -EA SilentlyContinue
EvdQ "W-46" "$sam ACL" "$(if ($acl46) { ($acl46.Access | ForEach-Object { "$($_.IdentityReference) $($_.FileSystemRights)" }) -join "`n" } else { '조회 불가' })"
if (-not $acl46) { MC "W-46" "SAM 파일 권한 조회 불가(관리자 권한 필요) - icacls $sam 확인" }
else { $ext46 = @($acl46.Access | Where-Object { @('S-1-5-18','S-1-5-32-544') -notcontains (Get-AceSid $_) } | ForEach-Object { "$($_.IdentityReference)" })
    if ($ext46.Count) { Fail "W-46" "SAM 파일에 Administrators·SYSTEM 외 권한: $($ext46 -join ', ')" } else { Pass "W-46" "SAM 파일 권한 Administrators·SYSTEM 만" } }

# W-47 화면 보호기 (10분 이하 + 암호)
$cpd = 'HKCU:\Control Panel\Desktop'; $cpp = 'HKCU:\Software\Policies\Microsoft\Windows\Control Panel\Desktop'
$ssA = Get-Reg $cpp 'ScreenSaveActive'; if ($null -eq $ssA) { $ssA = Get-Reg $cpd 'ScreenSaveActive' }
$ssT = Get-Reg $cpp 'ScreenSaveTimeOut'; if ($null -eq $ssT) { $ssT = Get-Reg $cpd 'ScreenSaveTimeOut' }
$ssS = Get-Reg $cpp 'ScreenSaverIsSecure'; if ($null -eq $ssS) { $ssS = Get-Reg $cpd 'ScreenSaverIsSecure' }
$lk = Get-Reg $pol 'InactivityTimeoutSecs'
EvdQ "W-47" "ScreenSaveActive / TimeOut / IsSecure / InactivityTimeoutSecs" "$ssA / $ssT / $ssS / $lk"
if ("$ssA" -eq '1' -and "$ssS" -eq '1' -and $ssT -and [int]$ssT -gt 0 -and [int]$ssT -le 600) { Pass "W-47" "화면 보호기 $([int]$ssT/60)분, 해제 시 암호" }
elseif ($lk -and [int]$lk -gt 0 -and [int]$lk -le 600) { Pass "W-47" "컴퓨터 비활성 한도 ${lk}초 - 화면 잠금" }
else { Fail "W-47" "화면 보호기 설정 미흡 (사용=$ssA, 대기=${ssT}초, 암호=$ssS; 기준 10분 이하 + 암호) - 실행 계정 기준, 서버 GPO 확인" }

# W-48 로그온하지 않고 시스템 종료 허용 (사용 안 함)
$sw = Get-Reg $pol 'ShutdownWithoutLogon'; EvdQ "W-48" "ShutdownWithoutLogon" "$sw"
if ("$sw" -eq '1') { Fail "W-48" "'로그온하지 않고 시스템 종료 허용' 사용" } else { Pass "W-48" "'로그온하지 않고 시스템 종료 허용' 사용 안 함 (ShutdownWithoutLogon=$(if ($null -eq $sw) { '미정의(서버 기본 0)' } else { $sw }))" }

# W-49 원격 시스템에서 강제로 시스템 종료 (Administrators 만)
if (-not $secOK) { MC "W-49" $secMsg } else {
    $rs = Get-SecPol 'SeRemoteShutdownPrivilege'; EvdQ "W-49" "SeRemoteShutdownPrivilege" "$rs => $((SidNames $rs) -join ', ')"
    $ext49 = @(($rs -split ',') | Where-Object { $_ -and $_.Trim() -ne '*S-1-5-32-544' } | ForEach-Object { Resolve-SecPolEntry $_ })
    if ($ext49.Count) { Fail "W-49" "'원격 시스템에서 강제로 시스템 종료'에 Administrators 외: $($ext49 -join ', ')" } else { Pass "W-49" "'원격 시스템에서 강제로 시스템 종료': Administrators 만" }
}

# W-50 보안 감사를 로그 할 수 없는 경우 즉시 시스템 종료 (사용 안 함)
$ca = Get-Reg $lsa 'CrashOnAuditFail'; EvdQ "W-50" "CrashOnAuditFail" "$ca"
if (@('1','2') -contains "$ca") { Fail "W-50" "'보안 감사를 로그 할 수 없는 경우 즉시 시스템 종료' 사용 (CrashOnAuditFail=$ca)" } else { Pass "W-50" "'보안 감사를 로그 할 수 없는 경우 즉시 시스템 종료' 사용 안 함" }

# W-51 SAM 계정과 공유의 익명 열거 허용 안 함 (RestrictAnonymous=1)
$ra = Get-Reg $lsa 'RestrictAnonymous'; $ras = Get-Reg $lsa 'RestrictAnonymousSAM'; EvdQ "W-51" "RestrictAnonymous / RestrictAnonymousSAM" "$ra / $ras"
if (@('1','2') -contains "$ra") { Pass "W-51" "'SAM 계정과 공유의 익명 열거 허용 안 함' 사용 (RestrictAnonymous=$ra)" } else { Fail "W-51" "'SAM 계정과 공유의 익명 열거 허용 안 함' 사용 안 함 (RestrictAnonymous=$(if ($null -eq $ra) { '미정의=0' } else { $ra }))" }

# W-52 Autologon 기능 제어
$aal = Get-Reg 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' 'AutoAdminLogon'; EvdQ "W-52" "AutoAdminLogon" "$aal"
if ("$aal" -eq '1') { Fail "W-52" "AutoAdminLogon=1 (자동 로그온 사용)" } else { Pass "W-52" "AutoAdminLogon $(if ($null -eq $aal) { '없음' } else { "=$aal" })" }

# W-53 이동식 미디어 포맷 및 꺼내기 허용 (Administrators)
$ad = Get-Reg 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' 'AllocateDASD'; EvdQ "W-53" "AllocateDASD (0=Administrators, 1=+Power Users, 2=+Interactive Users)" "$ad"
if ($null -eq $ad -or "$ad" -eq '0') { Pass "W-53" "'이동식 미디어 포맷 및 꺼내기 허용': Administrators$(if ($null -eq $ad) { ' (미정의 = 기본 Administrators)' })" } else { Fail "W-53" "'이동식 미디어 포맷 및 꺼내기 허용'이 Administrators 외 허용 (AllocateDASD=$ad)" }

# W-54 DoS 공격 방어 레지스트리
$tp = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
$sa54 = Get-Reg $tp 'SynAttackProtect'; $dg = Get-Reg $tp 'EnableDeadGWDetect'; $ka = Get-Reg $tp 'KeepAliveTime'; $nr = Get-Reg 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters' 'NoNameReleaseOnDemand'
EvdQ "W-54" "SynAttackProtect / EnableDeadGWDetect / KeepAliveTime / NoNameReleaseOnDemand" "$sa54 / $dg / $ka / $nr"
$m54 = @(); if (-not ($sa54 -ge 1)) { $m54 += "SynAttackProtect=$sa54(1 이상)" }; if ("$dg" -ne '0') { $m54 += "EnableDeadGWDetect=$dg(0)" }; if ("$ka" -ne '300000') { $m54 += "KeepAliveTime=$ka(300000)" }; if ("$nr" -ne '1') { $m54 += "NoNameReleaseOnDemand=$nr(1)" }
if ($m54.Count) { Fail "W-54" "DoS 방어 레지스트리 미설정: $($m54 -join ', ')" } else { Pass "W-54" "DoS 방어 레지스트리 4종 설정" }

# W-55 사용자가 프린터 드라이버를 설치할 수 없게 함 (사용)
$apd = Get-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers' 'AddPrinterDrivers'; EvdQ "W-55" "AddPrinterDrivers" "$apd"
if ("$apd" -eq '1') { Pass "W-55" "'사용자가 프린터 드라이버를 설치할 수 없게 함' 사용" } else { Fail "W-55" "'사용자가 프린터 드라이버를 설치할 수 없게 함' 사용 안 함 (AddPrinterDrivers=$(if ($null -eq $apd) { '미정의' } else { $apd }))" }

# W-56 SMB 세션 중단 관리 (로그온 시간 만료 시 연결 끊기 + 유휴 15분 이하)
$efl = Get-Reg $lmsv 'EnableForcedLogOff'; $adc = Get-Reg $lmsv 'AutoDisconnect'; EvdQ "W-56" "EnableForcedLogOff / AutoDisconnect(분)" "$efl / $adc"
$adcDef = ($null -eq $adc); if ($adcDef) { $adc = 15 }   # 미정의 = Windows 기본 15분
if ("$efl" -ne '0' -and [int64]$adc -le 15) { Pass "W-56" "로그온 시간 만료 시 연결 끊기 사용$(if ($null -eq $efl) { '(기본값)' }), 유휴 ${adc}분$(if ($adcDef) { '(기본값)' })" } else { Fail "W-56" "SMB 세션 중단 설정 미흡 (EnableForcedLogOff=$efl, AutoDisconnect=${adc}분; 기준 사용 + 15분 이하)" }

# W-57 로그온 시 경고 메시지
$lc57 = Get-Reg $pol 'LegalNoticeCaption'; $lt57 = Get-Reg $pol 'LegalNoticeText'; EvdQ "W-57" "LegalNoticeCaption / LegalNoticeText" "$lc57 / $lt57"
if ("$lc57".Trim() -and "$lt57".Trim()) { Pass "W-57" "로그온 경고 메시지 제목·내용 설정" } else { Fail "W-57" "로그온 경고 메시지 $(if (-not "$lc57".Trim()) { '제목 ' })$(if (-not "$lt57".Trim()) { '내용 ' })미설정" }

# W-58 사용자별 홈 디렉터리 권한 (Everyone 없음)
$ev58 = @(); foreach ($d in @(Get-ChildItem "$env:SystemDrive\Users" -EA SilentlyContinue | Where-Object { $_.PSIsContainer -and $_.Name -notmatch '^(All Users|Default|Default User|Public)$' })) { $a = Get-Acl $d.FullName -EA SilentlyContinue; if ($a -and @($a.Access | Where-Object { (Get-AceSid $_) -eq 'S-1-1-0' -and "$($_.AccessControlType)" -eq 'Allow' }).Count) { $ev58 += $d.Name } }
EvdQ "W-58" "Everyone 권한이 있는 홈 디렉터리" ($ev58 -join ', ')
if ($ev58.Count) { Fail "W-58" "홈 디렉터리 Everyone 권한: $($ev58 -join ', ')" } else { Pass "W-58" "사용자 홈 디렉터리 Everyone 권한 없음" }

# W-59 LAN Manager 인증 수준 (NTLMv2 응답만 보냄 = 3 이상)
$lm = Get-Reg $lsa 'LmCompatibilityLevel'; EvdQ "W-59" "LmCompatibilityLevel" "$lm"
if ($null -eq $lm) { Pass "W-59" "LAN Manager 인증 수준 미정의 - Windows 2008 R2 이상 기본값 'NTLMv2 응답만 보냄'(3)" } elseif ([int]$lm -ge 3) { Pass "W-59" "LAN Manager 인증 수준 $lm (NTLMv2 응답만 보냄 이상)" } else { Fail "W-59" "LAN Manager 인증 수준 $lm (LM·NTLM 응답 허용)" }

# W-60 보안 채널 데이터 디지털 암호화 또는 서명 (3개 정책 사용)
$nl = 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'
$v60 = [ordered]@{ RequireSignOrSeal=(Get-Reg $nl 'RequireSignOrSeal'); SealSecureChannel=(Get-Reg $nl 'SealSecureChannel'); SignSecureChannel=(Get-Reg $nl 'SignSecureChannel') }
EvdQ "W-60" "Netlogon 보안 채널 정책" (($v60.Keys | ForEach-Object { "$_=$($v60[$_])" }) -join ', ')
$off60 = @($v60.Keys | Where-Object { "$($v60[$_])" -eq '0' })
if ($off60.Count) { Fail "W-60" "보안 채널 정책 사용 안 함: $($off60 -join ', ')" } else { Pass "W-60" "보안 채널 데이터 암호화·서명 3개 정책 사용 (미정의는 기본값 사용)" }

# W-61 파일 및 디렉토리 보호 (NTFS)
$vol = @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' -EA SilentlyContinue)
EvdQ "W-61" "로컬 디스크 파일 시스템" (($vol | ForEach-Object { "$($_.DeviceID) $($_.FileSystem)" }) -join ', ')
$fat = @($vol | Where-Object { $_.FileSystem -match 'FAT' } | ForEach-Object { "$($_.DeviceID)$($_.FileSystem)" })
if (-not $vol.Count) { MC "W-61" "로컬 디스크 조회 실패" } elseif ($fat.Count) { Fail "W-61" "FAT 파일 시스템 사용: $($fat -join ', ')" } else { Pass "W-61" "로컬 디스크 NTFS/ReFS: $(($vol | ForEach-Object { "$($_.DeviceID)$($_.FileSystem)" }) -join ', ')" }

# W-62 시작 프로그램 목록 분석
$st62 = @(); foreach ($k in 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run','HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run') { if (Test-Path $k) { $p = Get-ItemProperty $k; $st62 += @((Get-Item $k).Property | ForEach-Object { "$_=$($p.$_)" }) } }
$st62 += @(Get-ChildItem "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp" -EA SilentlyContinue | ForEach-Object { "StartUp: $($_.Name)" })
EvdQ "W-62" "시작 프로그램 (Run 키·시작프로그램 폴더)" ($st62 -join "`n")
MC "W-62" "시작 프로그램 $($st62.Count)개$(if ($st62.Count) { ": $(($st62 | Select-Object -First 6 | ForEach-Object { ($_ -split '=',2)[0] }) -join ', ')" }) - 정기 검사·불필요 항목 비활성화 여부 확인"

# W-63 도메인 컨트롤러-사용자의 시간 동기화 (Kerberos 최대 허용 오차 5분 이하)
$cs = Int0 (Get-SecPol 'MaxClockSkew'); EvdQ "W-63" "Kerberos MaxClockSkew" "$cs"
if ($null -eq $cs) { Pass "W-63" "컴퓨터 시계 동기화 최대 허용 오차 미정의 - 기본값 5분" } elseif ($cs -le 5) { Pass "W-63" "컴퓨터 시계 동기화 최대 허용 오차 ${cs}분" } else { Fail "W-63" "컴퓨터 시계 동기화 최대 허용 오차 ${cs}분 (5분 초과)" }

# W-64 윈도우 방화벽
$fw = @(Get-NetFirewallProfile -EA SilentlyContinue)
EvdQ "W-64" "방화벽 프로필" (($fw | ForEach-Object { "$($_.Name)=$($_.Enabled)" }) -join ', ')
$off = @($fw | Where-Object { -not $_.Enabled } | ForEach-Object { $_.Name })
if (-not $fw.Count) { MC "W-64" "방화벽 프로필 조회 실패 - netsh advfirewall show allprofiles 확인" } elseif ($off.Count) { Fail "W-64" "Windows 방화벽 사용 안 함: $($off -join ', ')" } else { Pass "W-64" "Windows 방화벽 전체 프로필 사용" }

# ── 요약 ──
Remove-Item $seceditFile -Force -EA SilentlyContinue
$tot = $script:cntPass + $script:cntFail + $script:cntMC + $script:cntNA
Write-Output "# ================================================================"
Write-Output "# 점검 요약 - 주요정보통신기반시설 상세가이드(2026) Windows 서버 W-01~W-64"
Write-Output "#   총 $tot / 양호: $($script:cntPass) / 취약: $($script:cntFail) / 수동확인: $($script:cntMC) / N-A: $($script:cntNA)"
Write-Output "# 증적 파일: $script:EVD"
Write-Output "# ================================================================"
