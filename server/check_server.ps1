# ================================================================
# 서버(Windows) 보안 취약점 자동 점검 스크립트 v4.0
# ================================================================
#
# [용도]
#   전자금융기반시설 Windows 서버 보안 점검. -Mode w 는 주요정보 2026 상세가이드(check_server_w.ps1), -Mode all 은 둘 다
#   기준: 전자금융기반시설 보안 취약점 평가기준 제2026-1호 [서버]
#   Unix/Linux 서버는 check_server.sh 사용.
#
# [대상 OS]
#   Windows Server 2008 R2 / 2012 / 2016 / 2019 / 2022 / 2025 (PowerShell 2.0 이상)
#
# [사전 조건]
#   - 관리자 권한 PowerShell 필요
#   - 실행 정책 변경: Set-ExecutionPolicy RemoteSigned -Scope Process -Force
#
# [실행 방법]
#   .\check_server.ps1 > C:\Temp\$env:COMPUTERNAME_server.txt
#
# [산출물]
#   1) 표준출력 — 파이프 구분자 결과 (파일로 리다이렉트)
#      형식: SRV-항목코드|결과|근거설명
#      결과: 양호 / 취약 / 수동확인 / N-A
#   2) 증적 파일 — $env:TEMP\<호스트명>_server_evidence.txt
#      점검 중 실행한 명령어·출력·판정 근거가 타임스탬프와 함께 기록됨
#
# ================================================================
param([string]$Mode = "")   # srv=전자금융(SRV) / w=주요정보 2026 상세가이드(W-01~64) / all=둘 다
$ErrorActionPreference = "SilentlyContinue"
$script:SelfDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
if (-not $Mode) {
    if ([Environment]::UserInteractive -and $Host.Name -eq 'ConsoleHost') {
        Write-Host "점검 기준을 선택하세요: 1) 전자금융기반시설(SRV)  2) 주요정보통신기반시설 2026 상세가이드(W-01~W-64)  3) 둘 다"
        $sel = Read-Host "선택 [1/2/3]"
        $Mode = switch ("$sel".Trim()) { '2' { 'w' } '3' { 'all' } default { 'srv' } }
    } else { $Mode = 'srv' }   # 비대화형(기존 호출 방식): 전자금융
}
$Mode = "$Mode".ToLower()
if (@('srv','w','all','1','2','3','ef','mi') -notcontains $Mode) { Write-Host "사용법: check_server.ps1 -Mode srv|w|all"; exit 1 }
$Mode = switch ($Mode) { '1' {'srv'} 'ef' {'srv'} '2' {'w'} 'mi' {'w'} '3' {'all'} default { $Mode } }
$wScript = Join-Path $script:SelfDir 'check_server_w.ps1'
if ($Mode -eq 'w') {   # 주요정보: 2026 상세가이드 전용 스크립트로 전환
    if (-not (Test-Path $wScript)) { Write-Output "# [ERROR] check_server_w.ps1 없음 - check_server.ps1 과 같은 폴더에 두세요"; exit 1 }
    & $wScript; exit
}
if ($Mode -eq 'all' -and (Test-Path $wScript)) {   # 둘 다: 주요정보 결과는 별도 파일 <호스트>_w.txt
    $wOut = Join-Path $script:SelfDir "$($env:COMPUTERNAME)_w.txt"
    & $wScript | Out-File $wOut -Encoding UTF8
    Write-Host "[주요정보 W 결과 저장] $wOut"
}
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
Write-Output "# 점검 기준: 전자금융기반시설 보안 취약점 평가기준 제2026-1호 [서버]"
Write-Output "# 점검 일시: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Output "# ================================================================"

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
$script:cntPass=0; $script:cntFail=0; $script:cntMC=0; $script:cntNA=0

$script:ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$script:EVD = "$script:ScriptDir\${hn}_server_evidence.txt"
"# ================================================================" | Out-File $script:EVD -Encoding UTF8
"# 증적 파일 (감사 추적용)" | Add-Content $script:EVD -Encoding UTF8
"# 대상: $hn / Windows Server $ver (Build $build)" | Add-Content $script:EVD -Encoding UTF8
"# 생성: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" | Add-Content $script:EVD -Encoding UTF8
"# ================================================================" | Add-Content $script:EVD -Encoding UTF8

# 평가기준 [서버] '평가대상(WIN)' 열 기준 비대상 항목 → 판정을 N-A로 강제 (점검·증적 수집은 수행)
$script:NA_WIN = @("SRV-005","SRV-006","SRV-007","SRV-008","SRV-009","SRV-010","SRV-011","SRV-012","SRV-014","SRV-015","SRV-016","SRV-025","SRV-026","SRV-035","SRV-062","SRV-064","SRV-081","SRV-083","SRV-087","SRV-091","SRV-093","SRV-094","SRV-095","SRV-096","SRV-112","SRV-121","SRV-122","SRV-131","SRV-133","SRV-134","SRV-142","SRV-144","SRV-161","SRV-164","SRV-165","SRV-177")
function Emit([string]$code,[string]$res,[string]$msg) {
    if ($script:NA_WIN -contains $code -and $res -ne "N-A") {
        "[평가대상 아님] $code 원 판정: $res|$msg" | Add-Content $script:EVD -Encoding UTF8
        $res = "N-A"; $msg = "평가대상 아님 (WIN 해당 없음 - 평가기준 평가대상 열)"
    }
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
Write-Output "# OS 정보: $($os.Caption) Build $build"

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

# 평가기준상 WIN 평가대상이 아닌 항목 중 위에서 출력되지 않은 항목 N-A
$emitted = @(Get-Content $script:EVD -EA SilentlyContinue | Select-String '^\[판정\] (SRV-\d{3})' | ForEach-Object { $_.Matches[0].Groups[1].Value })
foreach ($code in $script:NA_WIN) { if ($emitted -notcontains $code) { NA $code "평가대상 아님 (WIN 해당 없음 - 평가기준 평가대상 열)" } }

Remove-Item $seceditFile -EA SilentlyContinue
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
