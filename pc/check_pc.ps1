# ================================================================
# PC 단말(Windows) 보안 취약점 자동 점검 스크립트 v1.1
# ================================================================
#
# [용도]
#   전자금융기반시설 업무용 PC(Windows) 보안 점검. (주요정보 2026 상세가이드 PC-01~18 은 check_pc_kisa.ps1 사용)
#   기준: 전자금융기반시설 PC(업무용 단말) 자체 점검 항목 PC-01~18 (전자금융 평가기준에 PC 분야 없음)
#   macOS PC는 check_pc_mac.sh 사용.
#
# [대상 OS]
#   Windows 10 / 11 (Home / Pro / Enterprise). PowerShell 2.0 이상 (cmdlet 이 없으면 WMI·netsh·레지스트리로 대체)
#
# [사전 조건]
#   - 관리자 권한 PowerShell 권장 (비관리자면 보안 정책·감사 정책·BitLocker·공유 목록 등 일부 항목은 '점검불가')
#   - 실행 정책 변경: Set-ExecutionPolicy RemoteSigned -Scope Process -Force
#
# [실행 방법]
#   run_pc.bat 더블클릭 (관리자 권한 상승 + UTF-8 결과 저장)  또는 관리자 PowerShell 에서
#   powershell -ExecutionPolicy Bypass -Command "& .\check_pc.ps1 2>&1 | Out-File PC_$env:COMPUTERNAME.txt -Encoding UTF8"
#   (cmd 의 '>' 리다이렉트는 OEM 코드페이지로 저장되어 한글이 깨질 수 있으므로 Out-File -Encoding UTF8 사용)
#
# [산출물]
#   1) 표준출력 — 파이프 구분자 결과 (Out-File -Encoding UTF8 로 저장)
#      형식: PC-항목코드|결과|근거설명
#      결과: 양호 / 취약 / 수동확인 / 점검불가 / N-A
#      헤더: # IP / # 실행 계정 / # 클라우드 (컨버터가 사용)
#   2) 증적 파일 — 스크립트와 같은 폴더 <호스트명>_pc_evidence.txt (컨버터가 결과 파일 PC_<호스트명>.txt 옆에서 자동 탐색)
#      점검 중 실행한 명령어·출력 전체·판정 근거가 타임스탬프와 함께 기록됨
#
# ================================================================
$ErrorActionPreference = "SilentlyContinue"
$ProgressPreference    = "SilentlyContinue"

# ── 공통 헬퍼 (PowerShell 2.0 호환: 3.0+ 전용 cmdlet·연산자·문법 미사용 — cmdlet 은 Get-Command 로 존재 확인 후 호출) ──
# 결과 인코딩: 이 스크립트는 문자열로 출력만 한다. 파일 저장은 run_*.bat 의 `| Out-File -Encoding UTF8`(UTF-8 BOM)로 한다.
# (콘솔 OutputEncoding 을 UTF-8 로 바꾸면 net/bcdedit 같은 네이티브 명령의 OEM(cp949) 출력이 깨져 한글 라벨 파싱이 실패하므로 바꾸지 않는다.)

$script:isAdmin = $false; $script:runAs = "$env:USERDOMAIN\$env:USERNAME"
try {
    $wid = [Security.Principal.WindowsIdentity]::GetCurrent()
    $script:runAs = $wid.Name
    $script:isAdmin = (New-Object Security.Principal.WindowsPrincipal($wid)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
} catch {}
$script:NEED_ADMIN = "관리자 권한 필요 - 비관리자 권한으로 실행되어 점검불가"

# WMI 조회: Get-CimInstance 가 있으면 사용, 없으면(PS 2.0) Get-WmiObject. 오류 시 $script:wmiOk=$false (결과 없음과 구분).
#   ※ 결과는 일반 출력으로 내보내므로 파이프(| Format-Table 등)에 그대로 쓸 수 있다.
function Get-Wmi([string]$Class,[string]$Filter,[string]$Ns) {
    if (-not $Ns) { $Ns = "root\cimv2" }
    $script:wmiOk = $true
    try {
        $cimCmd = Get-Command Get-CimInstance -EA SilentlyContinue   # PS 3.0+ 에만 있음 — 호출 연산자로 간접 호출(PS 2.0 에서는 $null)
        if ($cimCmd) {
            if ($Filter) { & $cimCmd -Namespace $Ns -ClassName $Class -Filter $Filter -EA Stop } else { & $cimCmd -Namespace $Ns -ClassName $Class -EA Stop }
        } else {
            if ($Filter) { Get-WmiObject -Namespace $Ns -Class $Class -Filter $Filter -EA Stop } else { Get-WmiObject -Namespace $Ns -Class $Class -EA Stop }
        }
    } catch { $script:wmiOk = $false }
}
function Get-Reg([string]$Path,[string]$Name) {
    try { return (Get-ItemProperty -Path $Path -Name $Name -EA Stop).$Name } catch { return $null }
}
function Get-IPList {
    $ips = @()
    $nics = Get-Wmi "Win32_NetworkAdapterConfiguration" "IPEnabled=True"
    foreach ($n in @($nics)) { if (-not $n) { continue }; foreach ($a in @($n.IPAddress)) { if ($a -match '^\d{1,3}(\.\d{1,3}){3}$' -and $a -notmatch '^127\.') { $ips += $a } } }
    if ($ips.Count -eq 0) { return "미확인" }
    return (($ips | Select-Object -Unique) -join ", ")
}
function Invoke-Imds([string]$Url,[string]$Method,$Headers) {
    try {
        $req = [System.Net.WebRequest]::Create($Url)
        $req.Method = $Method; $req.Timeout = 2000; $req.ReadWriteTimeout = 2000
        try { $req.Proxy = $null } catch {}
        if ($Headers) { foreach ($k in $Headers.Keys) { $req.Headers.Add($k, [string]$Headers[$k]) } }
        if ($Method -eq 'PUT') { $req.ContentLength = 0 }
        $resp = $req.GetResponse()
        $sr = New-Object System.IO.StreamReader($resp.GetResponseStream())
        $body = $sr.ReadToEnd(); $sr.Close(); $resp.Close()
        return @{ Ok = $true; Body = $body; Net = $true }
    } catch [System.Net.WebException] {
        return @{ Ok = $false; Body = ''; Net = ($_.Exception.Response -ne $null) }   # HTTP 응답이 있으면 IMDS 주소에는 연결된 것
    } catch { return @{ Ok = $false; Body = ''; Net = $false } }
}
function Get-CloudInfo {
    # 메타데이터 주소(169.254.169.254) 타임아웃 2초. 응답이 없으면 클라우드 아님('없음').
    try {
        $t = Invoke-Imds 'http://169.254.169.254/latest/api/token' 'PUT' @{ 'X-aws-ec2-metadata-token-ttl-seconds' = '60' }
        if (-not $t.Net) { return "없음" }
        $h = @{}; if ($t.Ok) { $h['X-aws-ec2-metadata-token'] = $t.Body.Trim() }
        $id = Invoke-Imds 'http://169.254.169.254/latest/meta-data/instance-id' 'GET' $h
        if ($id.Ok -and $id.Body.Trim() -match '^i-') {
            $rg = Invoke-Imds 'http://169.254.169.254/latest/meta-data/placement/region' 'GET' $h
            $sg = ''
            $macs = Invoke-Imds 'http://169.254.169.254/latest/meta-data/network/interfaces/macs/' 'GET' $h
            if ($macs.Ok) {
                $mac = (($macs.Body -split "`n")[0]).Trim()
                if ($mac) { $s = Invoke-Imds ("http://169.254.169.254/latest/meta-data/network/interfaces/macs/" + $mac + "security-group-ids") 'GET' $h; if ($s.Ok) { $sg = (($s.Body -split "`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ }) -join ',') } }
            }
            return ("AWS (instance " + $id.Body.Trim() + ", region " + $(if ($rg.Ok) { $rg.Body.Trim() } else { '미확인' }) + ", SG: " + $(if ($sg) { $sg } else { '미확인' }) + ")")
        }
        $az = Invoke-Imds 'http://169.254.169.254/metadata/instance?api-version=2021-02-01' 'GET' @{ 'Metadata' = 'true' }
        if ($az.Ok -and $az.Body -match '"vmId"\s*:\s*"([^"]+)"') {
            $vm = $Matches[1]; $loc = ''; if ($az.Body -match '"location"\s*:\s*"([^"]+)"') { $loc = $Matches[1] }
            return ("Azure (vmId " + $vm + ", region " + $(if ($loc) { $loc } else { '미확인' }) + ")")
        }
        $g = Invoke-Imds 'http://169.254.169.254/computeMetadata/v1/instance/id' 'GET' @{ 'Metadata-Flavor' = 'Google' }
        if ($g.Ok) {
            $z = Invoke-Imds 'http://169.254.169.254/computeMetadata/v1/instance/zone' 'GET' @{ 'Metadata-Flavor' = 'Google' }
            return ("GCP (instance " + $g.Body.Trim() + ", zone " + $(if ($z.Ok) { ($z.Body.Trim() -split '/')[-1] } else { '미확인' }) + ")")
        }
        return "미확인"
    } catch { return "미확인" }
}
# 콘솔(대화형) 로그온 사용자의 레지스트리 hive — 관리자 상승 시 HKCU 는 관리자 프로필일 수 있어 HKU\<SID> 를 직접 읽는다.
function Get-UserHive {
    try {
        $cs = Get-Wmi "Win32_ComputerSystem"
        $u = $null; if ($cs) { $u = @($cs)[0].UserName }
        if ($u) {
            $sid = (New-Object System.Security.Principal.NTAccount($u)).Translate([System.Security.Principal.SecurityIdentifier]).Value
            if (Test-Path "Registry::HKEY_USERS\$sid") { return @{ Root = "Registry::HKEY_USERS\$sid"; Desc = "콘솔 로그온 사용자 $u (HKU\$sid)" } }
        }
    } catch {}
    return @{ Root = "HKCU:"; Desc = "현재 프로세스 사용자 $($script:runAs) (HKCU, 콘솔 로그온 사용자 확인 실패)" }
}
# net user <이름> 의 '마지막 암호 설정일' (PS 2.0/Get-LocalUser 없는 경로용, 로캘 무관): 라벨 대신 줄 위치로 읽는다
#   net user 출력의 비어 있지 않은 줄 순서 = User name, Full Name, Comment, User's comment, Country/region code, Account active, Account expires, Password last set ...
#   8번째 줄에서 날짜 패턴(yyyy-MM-dd / yyyy.MM.dd / M/d/yyyy)을 찾아 반환. 날짜를 못 읽으면 "?" (알 수 없음)
function Get-NetUserPwdSet([string]$name) {
    try {
        $vals = @(); foreach ($l in @(net user "$name" 2>$null)) { if ("$l".Trim() -ne '') { $vals += "$l" } }
        if ($vals.Count -lt 8) { return "?" }
        $ln = $vals[7]
        if ($ln -match '(\d{4})\s*[-./]\s*(\d{1,2})\s*[-./]\s*(\d{1,2})') { return ('{0}-{1:00}-{2:00}' -f $Matches[1], [int]$Matches[2], [int]$Matches[3]) }
        if ($ln -match '(\d{1,2}/\d{1,2}/\d{4})') { return $Matches[1] }
    } catch {}
    return "?"
}
# 로컬 계정 목록: Name, Enabled, PasswordRequired, SID, PasswordLastSet, PrincipalSource  (Get-LocalUser → 실패 시 WMI Win32_UserAccount + net user). 조회 실패는 $script:acctOk=$false.
#   PasswordLastSet: yyyy-MM-dd(설정 이력 있음) / ""(Get-LocalUser 가 설정 이력 없음으로 보고) / "?"(알 수 없음) / "-"(조회 불필요)
function Get-LocalAccts {
    $script:acctOk = $true
    if (Get-Command Get-LocalUser -EA SilentlyContinue) {
        $got = $false; $tmp = @()
        try {
            foreach ($u in @(Get-LocalUser -EA Stop)) {
                $got = $true
                $pls = ""; if ($u.PasswordLastSet) { try { $pls = ([datetime]$u.PasswordLastSet).ToString("yyyy-MM-dd") } catch { $pls = "$($u.PasswordLastSet)" } }
                $tmp += New-Object PSObject -Property @{ Name = "$($u.Name)"; Enabled = [bool]$u.Enabled; PasswordRequired = [bool]$u.PasswordRequired; SID = "$($u.SID)"; PasswordLastSet = $pls; PrincipalSource = "$($u.PrincipalSource)" }
            }
        } catch { $got = $false }
        if ($got) { $tmp; return }
    }
    $w = Get-Wmi "Win32_UserAccount" "LocalAccount=True"
    if (-not $script:wmiOk) { $script:acctOk = $false; return }
    foreach ($u in @($w)) { if ($u) {
        $pls = "-"; if (-not [bool]$u.PasswordRequired -and -not [bool]$u.Disabled) { $pls = Get-NetUserPwdSet "$($u.Name)" }
        New-Object PSObject -Property @{ Name = "$($u.Name)"; Enabled = (-not [bool]$u.Disabled); PasswordRequired = [bool]$u.PasswordRequired; SID = "$($u.SID)"; PasswordLastSet = $pls; PrincipalSource = "" }
    } }
}
# PasswordRequired=False 는 '빈 비밀번호 허용 플래그'일 뿐 실제로 비밀번호가 없다는 뜻이 아님 (Microsoft 계정 연결·설정 앱으로 만든 계정에서 흔함) → 실제 상태로 구분
#   msa: Microsoft 계정(비밀번호는 Microsoft 계정에서 관리) / empty: 비밀번호 설정 이력 없음(취약) / flag: 설정 이력 있고 플래그만 해제(수동확인) / unk: 설정일 확인 불가(수동확인)
function Get-PwdFlagState($a) {
    if ("$($a.PrincipalSource)" -eq "MicrosoftAccount") { return "msa" }
    $p = "$($a.PasswordLastSet)"
    if ($p -eq "?" -or $p -eq "-") { return "unk" }
    if ($p -eq "") { return "empty" }
    return "flag"
}
function Get-PwdFlagText($a) {
    switch (Get-PwdFlagState $a) {
        "msa"   { return "$($a.Name)(Microsoft 계정 - 비밀번호는 Microsoft 계정에서 관리)" }
        "empty" { return "$($a.Name)(PasswordRequired=False + 비밀번호 설정 이력 없음)" }
        "flag"  { return "$($a.Name)(PasswordRequired=False 이나 비밀번호는 설정됨 $($a.PasswordLastSet) - 빈 비밀번호 허용 플래그만 해제, 실제 빈 비밀번호 여부는 로그인 화면/net user 로 확인)" }
        default { return "$($a.Name)(PasswordRequired=False, 마지막 암호 설정일 확인 불가)" }
    }
}
# net accounts 값(로캘 무관): 영문/한글 라벨 → 실패 시 출력 순서(강제 로그오프, 최소기간, 최대기간, 최소길이, 기록, 잠금임계값, ...)
function Get-NetAcctMap {
    $m = @{ MaxAge = $null; MinLen = $null; Lockout = $null }
    $lines = @(net accounts 2>$null)
    if ($lines.Count -lt 5) { return $m }
    $vals = @(); foreach ($l in $lines) { if ($l -notmatch '^\s*$' -and $l -match '^[^:]+:\s*(.*)$') { $vals += $Matches[1].Trim() } }
    foreach ($l in $lines) {
        if ($l -match '^(Maximum password age|최대 암호 사용 기간)[^:]*:\s*(.*)$') { $m.MaxAge = $Matches[2].Trim() }
        elseif ($l -match '^(Minimum password length|최소 암호 길이)[^:]*:\s*(.*)$') { $m.MinLen = $Matches[2].Trim() }
        elseif ($l -match '^(Lockout threshold|잠금 임계값)[^:]*:\s*(.*)$') { $m.Lockout = $Matches[2].Trim() }
    }
    if ($null -eq $m.MaxAge -and $vals.Count -ge 6) { $m.MaxAge = $vals[2]; $m.MinLen = $vals[3]; $m.Lockout = $vals[5] }
    return $m
}
function ConvertTo-IntOrUnlimited($v,[int]$unl) {   # 숫자면 그 값, 'Unlimited/Never/제한 없음' 같은 문자열이면 $unl
    if ($null -eq $v) { return $null }
    if ("$v" -match '^\s*(\d+)\s*$') { return [int]$Matches[1] }
    return $unl
}
# 최근 HOT FIX: Get-HotFix → WMI Win32_QuickFixEngineering. 조회 실패 $null, 설치일 있는 항목 없음 = 빈 객체.
function Get-LatestHotfix {
    $list = @()
    $ok = $false
    try { foreach ($h in @(Get-HotFix -EA Stop)) { $ok = $true; $d = $null; if ($h.InstalledOn) { try { $d = [datetime]$h.InstalledOn } catch {} }; if ($d) { $list += New-Object PSObject -Property @{ ID = "$($h.HotFixID)"; Date = $d } } } } catch {}
    if (-not $ok) {
        $w = Get-Wmi "Win32_QuickFixEngineering"
        if (-not $script:wmiOk) { return $null }
        foreach ($h in @($w)) { if (-not $h) { continue }; $d = $null; if ($h.InstalledOn) { try { $d = [datetime]$h.InstalledOn } catch {} }; if ($d) { $list += New-Object PSObject -Property @{ ID = "$($h.HotFixID)"; Date = $d } } }
    }
    $s = @($list | Sort-Object Date -Descending)
    if ($s.Count -eq 0) { return (New-Object PSObject -Property @{ ID = $null; Date = $null }) }
    return $s[0]
}
# 공유 목록: Name, Path, Kind(FileSystemDirectory/PrintQueue/Device/NamedPipe/Other), Default(기본 관리 공유 여부), Source. 조회 실패는 $script:shareOk=$false.
function Get-ShareList {
    $script:shareOk = $true
    $defRe = '^([A-Za-z]\$|ADMIN\$|IPC\$|print\$)$'
    if ($script:isAdmin -and (Get-Command Get-SmbShare -EA SilentlyContinue)) {
        $got = $false; $tmp = @()
        try {
            foreach ($s in @(Get-SmbShare -EA Stop)) { $got = $true; $tmp += New-Object PSObject -Property @{ Name = "$($s.Name)"; Path = "$($s.Path)"; Kind = "$($s.ShareType)"; Source = "Get-SmbShare"; Default = ("$($s.Name)" -match $defRe) } }
        } catch { $got = $false }
        if ($got) { $tmp; return }
    }
    $w = Get-Wmi "Win32_Share"
    if (-not $script:wmiOk) { $script:shareOk = $false; return }
    foreach ($s in @($w)) {
        if (-not $s) { continue }
        $t = [int64]$s.Type -band 0xFFFF
        $kind = switch ($t) { 0 { "FileSystemDirectory" } 1 { "PrintQueue" } 2 { "Device" } 3 { "NamedPipe" } default { "Other" } }
        New-Object PSObject -Property @{ Name = "$($s.Name)"; Path = "$($s.Path)"; Kind = $kind; Source = "Win32_Share"; Default = ("$($s.Name)" -match $defRe) }
    }
}
# 방화벽 상태: Get-NetFirewallProfile(유효 상태) → 레지스트리(GPO 우선, 로컬) 순. 반환 { Profiles = @{이름=$true/$false/$null}; Source }
function Get-FwState {
    $r = @{ Profiles = @{}; Source = "" }
    if (Get-Command Get-NetFirewallProfile -EA SilentlyContinue) {
        try {
            foreach ($p in @(Get-NetFirewallProfile -EA Stop)) { $r.Profiles["$($p.Name)"] = [bool]($p.Enabled -eq $true -or "$($p.Enabled)" -eq "True") }
            if ($r.Profiles.Count -gt 0) { $r.Source = "Get-NetFirewallProfile"; return $r }
        } catch {}
    }
    $r.Profiles = @{}
    foreach ($p in "DomainProfile","StandardProfile","PublicProfile") {
        $pol = Get-Reg "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\$p" "EnableFirewall"
        $loc = Get-Reg "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\$p" "EnableFirewall"
        $v = if ($null -ne $pol) { $pol } else { $loc }
        $r.Profiles[($p -replace "Profile","")] = $(if ($null -eq $v) { $null } else { [int]$v -ne 0 })
    }
    $r.Source = "레지스트리(WindowsFirewall 정책 → FirewallPolicy)"
    return $r
}
# SecurityCenter2 productState 해석: 상태 바이트(비트 8~15) 0x10=켜짐, 서명 바이트(비트 0~7) 0x00=최신
function Test-WscOn([int]$s)  { return ((($s -shr 8) -band 0xFF) -eq 0x10) }
function Test-WscUpToDate([int]$s) { return (($s -band 0xFF) -eq 0) }

$hn      = $env:COMPUTERNAME
$osw     = @(Get-Wmi "Win32_OperatingSystem")
$os      = if ($osw.Count -gt 0) { $osw[0] } else { $null }
$osName  = if ($os) { $os.Caption } else { "Unknown" }
$build   = if ($os) { [int]$os.BuildNumber } else { 0 }
$isHome  = $osName -match "Home"

Write-Output "# ============================================================"
Write-Output "# 점검 대상: $hn"
Write-Output "# OS: $osName (Build $build)"
Write-Output "# 에디션: $(if($isHome){'Home (로컬 보안 정책 제한)'}else{'Pro/Enterprise'})"
Write-Output "# 점검 기준: 전자금융기반시설 PC(업무용 단말) 자체 점검 항목 PC-01~18 (전자금융 평가기준에 PC 분야 없음)"
Write-Output "# 점검 일시: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Output "# IP: $(Get-IPList)"
Write-Output "# 실행 계정: $($script:runAs)$(if (-not $script:isAdmin) { ' (관리자 아님 - 일부 항목 점검불가)' })"
Write-Output "# 클라우드: $(Get-CloudInfo)"
Write-Output "# ============================================================"

$seceditFile = "$env:TEMP\pc_secpol_$PID.cfg"
$null = secedit /export /cfg $seceditFile /quiet 2>$null
$hasSecEdit = (Test-Path $seceditFile) -and ((Get-Item $seceditFile -EA SilentlyContinue).Length -gt 0)

function Get-SecPol([string]$Key) {
    if (-not $hasSecEdit) { return $null }
    $line = Get-Content $seceditFile -EA SilentlyContinue |
            Where-Object { $_ -match "^\s*$([regex]::Escape($Key))\s*=" } | Select-Object -First 1
    if ($line) { return ($line -split "=",2)[1].Trim() }
    return $null
}

$script:cntPass=0; $script:cntFail=0; $script:cntMC=0; $script:cntNA=0; $script:cntNC=0

$script:ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$script:EVD = "$script:ScriptDir\${hn}_pc_evidence.txt"
"# ================================================================" | Out-File $script:EVD -Encoding UTF8
"# PC 증적 파일 (감사 추적용)" | Add-Content $script:EVD -Encoding UTF8
"# 대상: $hn / $osName (Build $build)" | Add-Content $script:EVD -Encoding UTF8
"# 실행 계정: $($script:runAs) / 관리자: $($script:isAdmin)" | Add-Content $script:EVD -Encoding UTF8
"# 생성: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" | Add-Content $script:EVD -Encoding UTF8
"# ================================================================" | Add-Content $script:EVD -Encoding UTF8

function Pass([string]$code,[string]$msg) { $script:cntPass++; Write-Output "PC-$code|양호|$msg"; "[판정] PC-$code|양호|$msg`n" | Add-Content $script:EVD -Encoding UTF8 }
function Fail([string]$code,[string]$msg) { $script:cntFail++; Write-Output "PC-$code|취약|$msg"; "[판정] PC-$code|취약|$msg`n" | Add-Content $script:EVD -Encoding UTF8 }
function NA([string]$code,[string]$msg)   { $script:cntNA++;   Write-Output "PC-$code|N-A|$msg"; "[판정] PC-$code|N-A|$msg`n" | Add-Content $script:EVD -Encoding UTF8 }
function MC([string]$code,[string]$msg)   { $script:cntMC++;   Write-Output "PC-$code|수동확인|$msg"; "[판정] PC-$code|수동확인|$msg`n" | Add-Content $script:EVD -Encoding UTF8 }
function NC([string]$code,[string]$msg)   { $script:cntNC++;   Write-Output "PC-$code|점검불가|$msg"; "[판정] PC-$code|점검불가|$msg`n" | Add-Content $script:EVD -Encoding UTF8 }
# 증적 본문 기록: 출력 전체(2000줄 초과분만 생략 표시), 비어 있으면 그 사실을 기록
function Add-EvdBody($text) {
    $t = "$text".TrimEnd()
    if ($t -eq '') { $t = '(출력 없음)' }
    $ls = @($t -split "`r?`n")
    if ($ls.Count -gt 2000) { $t = (($ls[0..1999]) -join "`n") + "`n(이하 $($ls.Count - 2000)줄 생략)" }
    Add-Content $script:EVD -Value $t -Encoding UTF8
}
function Evd([string]$item,[string]$cmd) {
    "[$item] $(Get-Date -Format 'HH:mm:ss') PS> $cmd" | Add-Content $script:EVD -Encoding UTF8
    $r = ''
    try { $r = Invoke-Expression $cmd 2>&1 | Out-String -Width 4096 } catch { $r = $_.Exception.Message }
    Add-EvdBody $r
    "" | Add-Content $script:EVD -Encoding UTF8
}
function EvdQ([string]$item,[string]$desc,[string]$val) {
    "[$item] $(Get-Date -Format 'HH:mm:ss') $desc" | Add-Content $script:EVD -Encoding UTF8
    Add-EvdBody $val
    "" | Add-Content $script:EVD -Encoding UTF8
}
$uh = Get-UserHive   # 사용자 설정(HKCU 계열)을 읽을 hive — 콘솔 로그온 사용자 우선

# ══════════════════════════════════════════════════════════════════
# PC-01: 패스워드 설정
# ══════════════════════════════════════════════════════════════════
Evd "PC-01" "Get-LocalAccts | Format-Table Name,Enabled,PasswordRequired,PasswordLastSet,PrincipalSource,SID -AutoSize"
$accts = Get-LocalAccts
if (-not $script:acctOk) {
    NC "01" "로컬 계정 조회 실패 (Get-LocalUser·Win32_UserAccount 모두 실패)"
} else {
    $act = @($accts | Where-Object { $_.Enabled -and $_.Name -notmatch "^(DefaultAccount|WDAGUtilityAccount)$" })
    $noPwAccts = @($act | Where-Object { -not $_.PasswordRequired })
    $empty01 = @($noPwAccts | Where-Object { (Get-PwdFlagState $_) -eq "empty" } | ForEach-Object { Get-PwdFlagText $_ })
    $check01 = @($noPwAccts | Where-Object { $s = Get-PwdFlagState $_; $s -eq "flag" -or $s -eq "unk" } | ForEach-Object { Get-PwdFlagText $_ })
    $msa01   = @($noPwAccts | Where-Object { (Get-PwdFlagState $_) -eq "msa" } | ForEach-Object { Get-PwdFlagText $_ })
    $info01 = ""; if ($msa01.Count) { $info01 = " / " + ($msa01 -join ', ') }
    if ($empty01.Count -gt 0) {
        Fail "01" "비밀번호 미설정 계정: $($empty01 -join ', ')$(if ($check01.Count) { ' / 확인 필요: ' + ($check01 -join ', ') })$info01"
    } elseif ($check01.Count -gt 0) {
        MC "01" "비밀번호 필수 플래그(PasswordRequired)가 꺼진 계정 - 실제 비밀번호 설정 여부 확인 필요: $($check01 -join ', ')$info01"
    } else {
        Pass "01" "모든 활성 계정 비밀번호 필수 또는 Microsoft 계정 ($(($act | ForEach-Object { $_.Name }) -join ', '))$info01"
    }
}

# ══════════════════════════════════════════════════════════════════
# PC-02: 패스워드 정책
# ══════════════════════════════════════════════════════════════════
$minLen  = Get-SecPol "MinimumPasswordLength"
$maxAge  = Get-SecPol "MaximumPasswordAge"
$complex = Get-SecPol "PasswordComplexity"
$history = Get-SecPol "PasswordHistorySize"
$na02    = Get-NetAcctMap
Evd "PC-02" "net accounts"
EvdQ "PC-02" "secedit 내보내기 사용 가능=$hasSecEdit / MinimumPasswordLength, MaximumPasswordAge, PasswordComplexity, PasswordHistorySize" "$minLen / $maxAge / $complex / $history"
$src02 = "secedit"
if ($null -eq $minLen) { $minLen = ConvertTo-IntOrUnlimited $na02.MinLen 0; $src02 = "net accounts" }
if ($null -eq $maxAge) { $maxAge = ConvertTo-IntOrUnlimited $na02.MaxAge -1; if ($src02 -eq "secedit") { $src02 = "secedit+net accounts" } }
if ($null -eq $minLen -and $null -eq $maxAge) {
    NC "02" "secedit·net accounts 모두 실패 - 패스워드 정책을 읽지 못함$(if (-not $script:isAdmin) { ' (' + $script:NEED_ADMIN + ')' })"
} else {
    $issues = @()
    # secedit MaximumPasswordAge: -1 = 사용 기간 제한 없음, 0 도 제한 없음으로 취급 (net accounts 의 Unlimited 도 동일)
    if ($null -ne $minLen -and [int]$minLen -lt 8) { $issues += "최소길이=${minLen}자(8자미만)" }
    if ($null -ne $maxAge) { if ([int]$maxAge -lt 1) { $issues += "최대사용기간=제한없음(${maxAge})" } elseif ([int]$maxAge -gt 90) { $issues += "최대사용기간=${maxAge}일" } }
    if ($null -ne $complex -and [int]$complex -eq 0) { $issues += "복잡도=비활성" }
    if ($issues.Count -gt 0) {
        Fail "02" "패스워드 정책 미흡($src02): $($issues -join ', ')"
    } elseif ($null -eq $complex) {
        NC "02" "복잡도(PasswordComplexity)를 읽지 못함 - secedit 내보내기에 관리자 권한 필요 (최소=${minLen}자, 최대사용=${maxAge}일은 기준 충족, $src02)"
    } else {
        Pass "02" "최소=${minLen}자, 최대사용=${maxAge}일, 복잡도=활성, 기록=${history}개 ($src02)"
    }
}

# ══════════════════════════════════════════════════════════════════
# PC-03: 화면보호기 / 화면 잠금  (콘솔 로그온 사용자 hive + 정책 경로)
# ══════════════════════════════════════════════════════════════════
$polDesk = "$($uh.Root)\Software\Policies\Microsoft\Windows\Control Panel\Desktop"
$usrDesk = "$($uh.Root)\Control Panel\Desktop"
$ssActive  = Get-Reg $polDesk "ScreenSaveActive";    if ($null -eq $ssActive)  { $ssActive  = Get-Reg $usrDesk "ScreenSaveActive" }
$ssSecure  = Get-Reg $polDesk "ScreenSaverIsSecure"; if ($null -eq $ssSecure)  { $ssSecure  = Get-Reg $usrDesk "ScreenSaverIsSecure" }
$ssTimeout = Get-Reg $polDesk "ScreenSaveTimeOut";   if ($null -eq $ssTimeout) { $ssTimeout = Get-Reg $usrDesk "ScreenSaveTimeOut" }
$lockSecs  = Get-Reg "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "InactivityTimeoutSecs"
EvdQ "PC-03" "읽은 hive: $($uh.Desc) / 정책 경로=$polDesk / 사용자 경로=$usrDesk" "ScreenSaveActive=$ssActive`nScreenSaverIsSecure=$ssSecure`nScreenSaveTimeOut=$ssTimeout`nInactivityTimeoutSecs(HKLM)=$lockSecs"
if ("$ssActive" -eq "1" -and "$ssSecure" -eq "1") {
    $t = if ($ssTimeout) { [int]$ssTimeout } else { 0 }
    if ($t -gt 0 -and $t -le 600) {
        Pass "03" "화면보호기 활성+암호잠금, 대기=${t}초 ($($uh.Desc))"
    } else {
        Fail "03" "화면보호기 활성이나 대기시간 ${t}초(600초 이하 권장) ($($uh.Desc))"
    }
} elseif ($lockSecs -and [int]$lockSecs -gt 0 -and [int]$lockSecs -le 600) {
    Pass "03" "비활성 잠금 정책 적용: ${lockSecs}초"
} else {
    Fail "03" "화면 잠금 미설정 (ScreenSaveActive=$ssActive, Secure=$ssSecure, InactivityTimeout=${lockSecs}; $($uh.Desc))"
}

# ══════════════════════════════════════════════════════════════════
# PC-04: 공유폴더 제거  (파일 공유 = 공유 유형 FileSystemDirectory 만, 숨김 사용자 공유 'data$' 포함, 기본 관리 공유만 제외)
# ══════════════════════════════════════════════════════════════════
Evd "PC-04" "Get-ShareList | Format-Table Name,Path,Kind,Default,Source -AutoSize"
$autoShareWks = Get-Reg "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" "AutoShareWks"
EvdQ "PC-04" "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters AutoShareWks" "$autoShareWks"
$shares04 = @(Get-ShareList)
if (-not $script:shareOk) {
    NC "04" "공유 목록 조회 실패 (Get-SmbShare/Win32_Share 모두 실패)$(if (-not $script:isAdmin) { ' - ' + $script:NEED_ADMIN })"
} else {
    $issues04 = @()
    if ($null -eq $autoShareWks -or $autoShareWks -ne 0) {
        $issues04 += 'AutoShareWks 기본관리공유(C$/ADMIN$) 활성(AutoShareWks=' + $autoShareWks + ')'
    }
    $fileShares = @($shares04 | Where-Object { $_.Kind -eq "FileSystemDirectory" -and -not $_.Default })
    $printShares = @($shares04 | Where-Object { $_.Kind -eq "PrintQueue" })
    if ($fileShares.Count -gt 0) {
        $issues04 += "사용자 파일 공유: " + (($fileShares | ForEach-Object { "$($_.Name)($($_.Path))" }) -join ', ')
    }
    $prn = if ($printShares.Count -gt 0) { " / 참고: 프린터 공유 $($printShares.Count)개(" + (($printShares | ForEach-Object { $_.Name }) -join ', ') + ") - 파일 공유 판정 제외" } else { "" }
    if ($issues04.Count -gt 0) {
        Fail "04" "$($issues04 -join ' / ')$prn"
    } else {
        Pass "04" "기본관리공유 비활성(AutoShareWks=0), 사용자 파일 공유 없음 (공유 $(@($shares04).Count)개 조회)$prn"
    }
}

# ══════════════════════════════════════════════════════════════════
# PC-05: 불필요 서비스 비활성화
# ══════════════════════════════════════════════════════════════════
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
Evd "PC-05" "Get-Service -Name $(($dangerSvc | ForEach-Object { $_.N }) -join ',') | Format-Table Name,DisplayName,Status -AutoSize"
$allSvc = @(Get-Service -EA SilentlyContinue)
if ($allSvc.Count -eq 0) {
    NC "05" "서비스 목록 조회 실패 (Get-Service)"
} else {
    $runSvc = @()
    foreach ($s in $dangerSvc) {
        $svc = $allSvc | Where-Object { $_.Name -eq $s.N } | Select-Object -First 1
        if ($svc -and "$($svc.Status)" -eq "Running") { $runSvc += "$($s.D)($($s.N))" }
    }
    if ($runSvc.Count -gt 0) {
        Fail "05" "실행 중 불필요 서비스 $($runSvc.Count)개: $($runSvc -join ', ')"
    } else {
        Pass "05" "불필요 서비스 미실행 (RemoteRegistry/Telnet/SSDP/UPnP/SNMP 등 $($dangerSvc.Count)종 확인)"
    }
}

# ══════════════════════════════════════════════════════════════════
# PC-06: 백신 설치 및 실시간 감시
# ══════════════════════════════════════════════════════════════════
$avProducts = @(Get-Wmi "AntiVirusProduct" "" "root\SecurityCenter2"); $scOk = $script:wmiOk
$defender = $null
try { $defender = Get-MpComputerStatus -EA Stop } catch {}
Evd "PC-06" "Get-Wmi AntiVirusProduct '' 'root\SecurityCenter2' | Format-Table displayName,@{n='productState';e={'0x'+([int]`$_.productState).ToString('X6')}} -AutoSize"
EvdQ "PC-06" "Defender (Get-MpComputerStatus)" $(if ($defender) { "AMServiceEnabled=$($defender.AMServiceEnabled) RealTimeProtectionEnabled=$($defender.RealTimeProtectionEnabled) AntivirusSignatureLastUpdated=$($defender.AntivirusSignatureLastUpdated)" } else { "조회 불가(cmdlet 없음 또는 오류)" })

if ($defender -and $defender.RealTimeProtectionEnabled) {
    $sigAge = ((Get-Date) - $defender.AntivirusSignatureLastUpdated).Days
    $sigDate = $defender.AntivirusSignatureLastUpdated.ToString("yyyy-MM-dd")
    if ($sigAge -le 7) {
        Pass "06" "Windows Defender 실시간보호 활성, 정의=$sigDate (${sigAge}일 전)"
    } else {
        Fail "06" "Defender 활성이나 정의 업데이트 오래됨: $sigDate (${sigAge}일 전, 7일 초과)"
    }
} elseif (-not $scOk -and -not $defender) {
    NC "06" "백신 상태 조회 실패 (SecurityCenter2 네임스페이스 없음/오류, Get-MpComputerStatus 실패) - 서버 SKU·구버전이거나 권한 문제"
} elseif ($avProducts.Count -gt 0) {
    $avl = $avProducts
    $names = ($avl | ForEach-Object { $_.displayName }) -join ", "
    $enabledAV = @($avl | Where-Object { Test-WscOn ([int]$_.productState) })
    if ($enabledAV.Count -gt 0) {
        $outOfDate = @($enabledAV | Where-Object { -not (Test-WscUpToDate ([int]$_.productState)) })
        if ($outOfDate.Count -gt 0) {
            Fail "06" "백신 활성이나 정의 업데이트 필요: $(($outOfDate | ForEach-Object { $_.displayName }) -join ', ')"
        } else {
            Pass "06" "백신 실시간보호 활성: $(($enabledAV | ForEach-Object { $_.displayName }) -join ', ')"
        }
    } else {
        Fail "06" "백신 설치됨($names)이나 실시간 보호 비활성 (productState: $(($avl | ForEach-Object {'0x'+([int]$_.productState).ToString('X6')}) -join ', '))"
    }
} else {
    Fail "06" "백신 프로그램 미감지 (SecurityCenter2 등록 제품 없음, Defender 실시간 보호 꺼짐/없음)"
}

# ══════════════════════════════════════════════════════════════════
# PC-07: OS 보안 패치
# ══════════════════════════════════════════════════════════════════
Evd "PC-07" "Get-HotFix | Sort-Object InstalledOn -Descending | Format-Table HotFixID,Description,InstalledOn -AutoSize"
$hf07 = Get-LatestHotfix
$wuSvc = Get-Service -Name "wuauserv" -EA SilentlyContinue
$wuAuto = Get-Reg "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" "AUOptions"
EvdQ "PC-07" "판정에 사용한 최근 HOT FIX / wuauserv 상태 / AUOptions" "$(if ($hf07) { "$($hf07.ID) $($hf07.Date)" } else { '조회 실패' }) / $($wuSvc.Status) / $wuAuto"
if ($null -eq $hf07 -or $null -eq $hf07.Date) {
    NC "07" "패치 이력 조회 실패 (Get-HotFix·Win32_QuickFixEngineering 결과 없음) - WU서비스=$($wuSvc.Status), AutoUpdate=${wuAuto} - 설정>Windows Update 기록 확인 필요"
} else {
    $age = ((Get-Date) - $hf07.Date).Days
    $hfDate = $hf07.Date.ToString("yyyy-MM-dd")
    if ($age -le 90) {
        Pass "07" "최근 패치: $($hf07.ID) ($hfDate, ${age}일 전)"
    } else {
        Fail "07" "최근 패치 ${age}일 경과: $($hf07.ID) ($hfDate)"
    }
}

# ══════════════════════════════════════════════════════════════════
# PC-08: 방화벽 활성화
# ══════════════════════════════════════════════════════════════════
$fw = Get-FwState
$fw3 = @(Get-Wmi "FirewallProduct" "" "root\SecurityCenter2")
$fw3on = @($fw3 | Where-Object { $_ -and (Test-WscOn ([int]$_.productState)) } | ForEach-Object { $_.displayName })
Evd "PC-08" "Get-FwState | ForEach-Object { `$_.Source; `$_.Profiles.GetEnumerator() | Sort-Object Key | Format-Table Key,Value -AutoSize }"
EvdQ "PC-08" "타사 방화벽(SecurityCenter2 FirewallProduct, 켜짐만)" ($fw3on -join ", ")
$fwOff = @(); $fwUnknown = @()
foreach ($k in $fw.Profiles.Keys) { if ($null -eq $fw.Profiles[$k]) { $fwUnknown += $k } elseif (-not $fw.Profiles[$k]) { $fwOff += $k } }
if ($fwUnknown.Count -eq $fw.Profiles.Count) {
    NC "08" "방화벽 상태 조회 실패 (Get-NetFirewallProfile 없음/오류, 레지스트리 값 없음)"
} elseif ($fwOff.Count -gt 0 -and $fw3on.Count -eq 0) {
    Fail "08" "방화벽 비활성 프로필: $($fwOff -join ', ') (타사 방화벽 미탐지; $($fw.Source))"
} elseif ($fwOff.Count -gt 0) {
    Pass "08" "Windows 방화벽 일부 비활성($($fwOff -join ', '))이나 타사 방화벽 사용: $($fw3on -join ', ')"
} else {
    Pass "08" "Windows 방화벽 전체 프로필 활성 ($($fw.Source)$(if ($fwUnknown.Count) { '; 미확인 프로필: ' + ($fwUnknown -join ',') }))"
}

# ══════════════════════════════════════════════════════════════════
# PC-09: 이벤트 로그 관리
# ══════════════════════════════════════════════════════════════════
Evd "PC-09" "Get-WinEvent -ListLog Security,System,Application | Format-Table LogName,MaximumSizeInBytes,LogMode,IsEnabled -AutoSize"
$logIssues = @(); $logOK = @(); $logNone = @()
foreach ($n in "Security","System","Application") {
    $mb = $null; $via = ""
    try { $log = Get-WinEvent -ListLog $n -EA Stop; $mb = [math]::Round($log.MaximumSizeInBytes / 1MB, 1) } catch {}
    if ($null -eq $mb) {
        $polKb = Get-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\$n" "MaxSize"      # GPO: KB
        $regB  = Get-Reg "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\$n" "MaxSize"          # 바이트
        if ($polKb) { $mb = [math]::Round($polKb / 1024, 1); $via = "(정책)" } elseif ($regB) { $mb = [math]::Round($regB / 1MB, 1); $via = "(reg)" }
    }
    if ($null -eq $mb) { $logNone += $n } elseif ($mb -lt 10) { $logIssues += "${n}=${mb}MB$via" } else { $logOK += "${n}=${mb}MB$via" }
}
if ($logIssues.Count -gt 0) {
    Fail "09" "이벤트 로그 10MB 미만: $($logIssues -join ', ') / 정상=$($logOK -join ', ')$(if ($logNone.Count) { ' / 조회불가=' + ($logNone -join ',') })"
} elseif ($logNone.Count -gt 0) {
    NC "09" "이벤트 로그 크기 조회 불가: $($logNone -join ', ') ($(if (-not $script:isAdmin) { $script:NEED_ADMIN } else { 'Get-WinEvent·레지스트리 모두 실패' })) / 확인된 로그=$($logOK -join ', ')"
} else {
    Pass "09" "Security/System/Application 로그 10MB 이상 ($($logOK -join ', '))"
}

# ══════════════════════════════════════════════════════════════════
# PC-10: 원격 데스크톱 제한
# ══════════════════════════════════════════════════════════════════
$fDenyPol = Get-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "fDenyTSConnections"
$fDenyLoc = Get-Reg "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" "fDenyTSConnections"
$fDeny = if ($null -ne $fDenyPol) { $fDenyPol } else { $fDenyLoc }
$nla   = Get-Reg "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" "UserAuthentication"
Evd "PC-10" "Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services','HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server','HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' | Format-List fDenyTSConnections,UserAuthentication"
if ($null -eq $fDeny) {
    NC "10" "fDenyTSConnections 레지스트리 값을 읽지 못함"
} elseif ($fDeny -eq 1) {
    Pass "10" "원격 데스크톱 비활성(fDenyTSConnections=1)"
} elseif ($nla -eq 1) {
    MC "10" "원격 데스크톱 활성+NLA 적용 - 업무 필요성 확인"
} else {
    Fail "10" "원격 데스크톱 활성, NLA 미적용 (fDeny=$fDeny, NLA=$nla)"
}

# ══════════════════════════════════════════════════════════════════
# PC-11: 자동실행(AutoRun/AutoPlay) 비활성화  (HKLM 정책 + 콘솔 사용자 hive)
# ══════════════════════════════════════════════════════════════════
$expPol = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
$ndta   = Get-Reg $expPol "NoDriveTypeAutoRun"
$noAR   = Get-Reg $expPol "NoAutorun"
$ndtaU  = Get-Reg "$($uh.Root)\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" "NoDriveTypeAutoRun"
$noARU  = Get-Reg "$($uh.Root)\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" "NoAutorun"
$disAP  = Get-Reg "$($uh.Root)\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" "DisableAutoplay"
EvdQ "PC-11" "읽은 값 (HKLM 정책 / 사용자 hive: $($uh.Desc))" "HKLM NoDriveTypeAutoRun=$ndta`nHKLM NoAutorun=$noAR`nUser NoDriveTypeAutoRun=$ndtaU`nUser NoAutorun=$noARU`nUser AutoplayHandlers DisableAutoplay=$disAP"
if ($ndta -eq 255 -or $ndtaU -eq 255 -or $noAR -eq 1 -or $noARU -eq 1 -or $disAP -eq 1) {
    Pass "11" "자동실행 비활성화 (NoDriveTypeAutoRun=$ndta/$ndtaU, NoAutorun=$noAR/$noARU, DisableAutoplay=$disAP)"
} else {
    Fail "11" "자동실행 비활성화 미설정 (NoDriveTypeAutoRun=$ndta/$ndtaU, DisableAutoplay=$disAP)"
}

# ══════════════════════════════════════════════════════════════════
# PC-12: 이동매체(USB) 제한
# ══════════════════════════════════════════════════════════════════
$rsd = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices"
$usbDeny  = Get-Reg $rsd "Deny_All"
$usbWrite = Get-Reg "$rsd\{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}" "Deny_Write"
$usbRead  = Get-Reg "$rsd\{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}" "Deny_Read"
$usbStore = Get-Reg "HKLM:\SYSTEM\CurrentControlSet\Services\USBSTOR" "Start"
EvdQ "PC-12" "RemovableStorageDevices Deny_All / Deny_Read / Deny_Write, USBSTOR Start" "Deny_All=$usbDeny`nDeny_Read=$usbRead`nDeny_Write=$usbWrite`nUSBSTOR Start=$usbStore"
if ($usbDeny -eq 1 -or $usbRead -eq 1 -or $usbStore -eq 4) {
    Pass "12" "이동매체 차단됨 (Deny_All=$usbDeny, Deny_Read=$usbRead, USBSTOR Start=$usbStore)"
} elseif ($usbWrite -eq 1) {
    MC "12" "USB 쓰기 차단, 읽기 허용 - 조직 정책 부합 여부 확인"
} elseif ($null -eq $usbStore) {
    NC "12" "USBSTOR 서비스 설정을 읽지 못함 (Deny_All=$usbDeny)"
} else {
    Fail "12" "이동매체(USB) 제한 정책 없음 (Deny_All/Deny_Read/Deny_Write 미설정, USBSTOR Start=$usbStore) - 타사 매체제어 솔루션 사용 시 증빙 확인"
}

# ══════════════════════════════════════════════════════════════════
# PC-13: Guest 계정 비활성화  (이름이 아니라 SID -501 로 식별)
# ══════════════════════════════════════════════════════════════════
Evd "PC-13" "Get-LocalAccts | Format-Table Name,Enabled,SID -AutoSize"
$accts13 = Get-LocalAccts
if (-not $script:acctOk) {
    NC "13" "로컬 계정 조회 실패 - Guest 계정 상태를 확인할 수 없음"
} else {
    $guestAcc = @($accts13 | Where-Object { $_.SID -match '-501$' })
    if ($guestAcc.Count -eq 0) {
        NC "13" "Guest 계정(SID -501)을 계정 목록에서 찾지 못함 - 수동 확인 필요"
    } elseif ($guestAcc[0].Enabled) {
        Fail "13" "Guest 계정($($guestAcc[0].Name)) 활성화됨"
    } else {
        Pass "13" "Guest 계정($($guestAcc[0].Name)) 비활성"
    }
}

# ══════════════════════════════════════════════════════════════════
# PC-14: UAC(사용자 계정 컨트롤) 활성화
# ══════════════════════════════════════════════════════════════════
$sysPol  = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$lua     = Get-Reg $sysPol "EnableLUA"
$consent = Get-Reg $sysPol "ConsentPromptBehaviorAdmin"
EvdQ "PC-14" "$sysPol  EnableLUA / ConsentPromptBehaviorAdmin (미설정 시 기본값 EnableLUA=1, ConsentPromptBehaviorAdmin=5)" "EnableLUA=$lua`nConsentPromptBehaviorAdmin=$consent"
$luaEff = if ($null -eq $lua) { 1 } else { [int]$lua }
$conEff = if ($null -eq $consent) { 5 } else { [int]$consent }
if ($luaEff -ne 1) {
    Fail "14" "UAC 비활성화됨 (EnableLUA=$lua)"
} elseif ($conEff -eq 0) {
    Fail "14" "UAC 활성이나 관리자 자동 승격(ConsentPromptBehaviorAdmin=0) - 프롬프트 비활성"
} else {
    Pass "14" "UAC 활성 (EnableLUA=$(if ($null -eq $lua) { '미설정(기본 1)' } else { $lua }), 관리자 동의 프롬프트 레벨=$(if ($null -eq $consent) { '미설정(기본 5)' } else { $consent }))"
}

# ══════════════════════════════════════════════════════════════════
# PC-15: SmartScreen / 브라우저 보안
# ══════════════════════════════════════════════════════════════════
$ss  = Get-Reg "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" "SmartScreenEnabled"
$ssp = Get-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "EnableSmartScreen"
EvdQ "PC-15" "SmartScreenEnabled(HKLM Explorer) / EnableSmartScreen(정책)" "SmartScreenEnabled=$ss`nEnableSmartScreen(policy)=$ssp"
if ($ssp -eq 0 -or "$ss" -eq "Off" -or "$ss" -eq "0") {
    Fail "15" "Windows SmartScreen 비활성 (SmartScreenEnabled=$ss, 정책 EnableSmartScreen=$ssp)"
} elseif ($ssp -eq 1 -or $ss) {
    Pass "15" "SmartScreen 활성 (SmartScreenEnabled=$ss, 정책 EnableSmartScreen=$ssp)"
} else {
    NC "15" "SmartScreen 설정 값을 읽지 못함 (레지스트리·정책 모두 없음) - 수동 확인"
}

# ══════════════════════════════════════════════════════════════════
# PC-16: 로그인 실패 잠금 임계값
# ══════════════════════════════════════════════════════════════════
Evd "PC-16" "net accounts"
$lockBad = Get-SecPol "LockoutBadCount"
EvdQ "PC-16" "secedit LockoutBadCount (secedit 사용 가능=$hasSecEdit)" "$lockBad"
$srcL = "secedit"
if ($null -eq $lockBad) { $lockBad = ConvertTo-IntOrUnlimited (Get-NetAcctMap).Lockout 0; $srcL = "net accounts" }
if ($null -eq $lockBad) {
    NC "16" "secedit/net accounts 모두 실패 - 계정 잠금 임계값을 읽지 못함$(if (-not $script:isAdmin) { ' (' + $script:NEED_ADMIN + ')' })"
} elseif ([int]$lockBad -eq 0) {
    Fail "16" "계정 잠금 임계값 미설정(0=무제한; $srcL)"
} elseif ([int]$lockBad -le 5) {
    Pass "16" "계정 잠금 임계값: ${lockBad}회 ($srcL)"
} else {
    Fail "16" "계정 잠금 임계값 과다: ${lockBad}회 (5회 이하 권장; $srcL)"
}

# ══════════════════════════════════════════════════════════════════
# PC-17: 감사 정책  (고급 감사 정책 auditpol — 서브카테고리 GUID 로 로캘 무관하게 식별)
# ══════════════════════════════════════════════════════════════════
Evd "PC-17" "auditpol /get /category:* /r"
if (-not $script:isAdmin) {
    NC "17" "auditpol 조회에 $($script:NEED_ADMIN)"
} else {
    $ap = @(auditpol /get /category:* /r 2>$null)
    $subs = @{ "{0CCE9215-69AE-11D9-BED3-505054503030}" = @("로그온(Logon)", $null); "{0CCE921D-69AE-11D9-BED3-505054503030}" = @("개체액세스-파일시스템(File System)", $null); "{0CCE9228-69AE-11D9-BED3-505054503030}" = @("권한사용-중요권한(Sensitive Privilege Use)", $null) }
    foreach ($l in $ap) {
        if ($l -match '(\{[0-9A-Fa-f-]{36}\}),([^,]*),') {
            $g = $Matches[1].ToUpper(); $setting = $Matches[2].Trim()
            foreach ($k in @($subs.Keys)) { if ($k.ToUpper() -eq $g) { $subs[$k] = @($subs[$k][0], $setting) } }
        }
    }
    $missing = @(); $notAudited = @(); $okList = @()
    foreach ($k in $subs.Keys) {
        $nm = $subs[$k][0]; $st = $subs[$k][1]
        if ($null -eq $st -or $st -eq '') { $missing += $nm }
        elseif ($st -match 'No Auditing|감사 안 ?함|감사 없음') { $notAudited += $nm }
        else { $okList += "$nm=$st" }
    }
    if ($missing.Count -eq $subs.Count) {
        $auditLogon = Get-SecPol "AuditLogonEvents"
        if ($null -eq $auditLogon) { NC "17" "auditpol 출력에서 대상 서브카테고리를 찾지 못했고 secedit 레거시 값도 없음 - 증적(auditpol 원문) 확인" }
        else {
            $auditObj = Get-SecPol "AuditObjectAccess"; $auditPriv = Get-SecPol "AuditPrivilegeUse"
            $miss = @(); if ([int]$auditLogon -eq 0) { $miss += "로그온이벤트" }; if ([int]$auditObj -eq 0) { $miss += "개체액세스" }; if ([int]$auditPriv -eq 0) { $miss += "권한사용" }
            if ($miss.Count) { Fail "17" "감사 정책 미설정(레거시 secedit 값): $($miss -join ', ')" } else { Pass "17" "감사 정책 활성(레거시 secedit 값; 로그온=$auditLogon, 개체=$auditObj, 권한=$auditPriv)" }
        }
    } elseif ($notAudited.Count -gt 0) {
        Fail "17" "감사 정책 미설정(감사 안 함): $($notAudited -join ', ')$(if ($okList.Count) { ' / 설정됨: ' + ($okList -join ', ') })"
    } elseif ($missing.Count -gt 0) {
        NC "17" "일부 서브카테고리를 auditpol 출력에서 찾지 못함: $($missing -join ', ') (설정됨: $($okList -join ', '))"
    } else {
        Pass "17" "감사 정책 활성 ($($okList -join ', '))"
    }
}

# ══════════════════════════════════════════════════════════════════
# PC-18: 디스크 암호화 (BitLocker)
# ══════════════════════════════════════════════════════════════════
Evd "PC-18" "if (Get-Command Get-BitLockerVolume -EA SilentlyContinue) { Get-BitLockerVolume -MountPoint 'C:' | Format-List MountPoint,VolumeStatus,ProtectionStatus,EncryptionMethod } else { Get-Wmi Win32_EncryptableVolume `"DriveLetter='C:'`" 'root\cimv2\Security\MicrosoftVolumeEncryption' | Format-List DriveLetter,ProtectionStatus,EncryptionMethod }"
$blState = $null; $blDesc = ""
if (Get-Command Get-BitLockerVolume -EA SilentlyContinue) {
    try { $bl = Get-BitLockerVolume -MountPoint "C:" -EA Stop; $blState = $(if ("$($bl.ProtectionStatus)" -eq "On" -or "$($bl.ProtectionStatus)" -eq "1") { 1 } else { 0 }); $blDesc = "방식=$($bl.EncryptionMethod), ProtectionStatus=$($bl.ProtectionStatus)" } catch {}
}
if ($null -eq $blState) {
    $ev = @(Get-Wmi "Win32_EncryptableVolume" "DriveLetter='C:'" "root\cimv2\Security\MicrosoftVolumeEncryption")
    if ($script:wmiOk -and $ev.Count -gt 0 -and $ev[0]) { $ps18 = [int]$ev[0].ProtectionStatus; if ($ps18 -ne 2) { $blState = $ps18; $blDesc = "WMI ProtectionStatus=$ps18" } }
}
if ($blState -eq 1) {
    Pass "18" "BitLocker 활성 (C: 암호화, $blDesc)"
} elseif ($blState -eq 0) {
    MC "18" "BitLocker 비활성 ($blDesc) - 조직 정책에 따라 판단"
} elseif ($isHome) {
    NC "18" "Home 에디션 - BitLocker 조회 미지원 (Device Encryption 은 설정>개인정보 및 보안>장치 암호화에서 수동 확인)"
} elseif (-not $script:isAdmin) {
    NC "18" "BitLocker 상태 조회에 $($script:NEED_ADMIN)"
} else {
    NC "18" "BitLocker 상태 조회 실패 (Get-BitLockerVolume·WMI Win32_EncryptableVolume 모두 실패) - 수동 확인"
}

# ══════════════════════════════════════════════════════════════════
# 요약
# ══════════════════════════════════════════════════════════════════
Write-Output "# ============================================================"
Write-Output "# 점검 완료"
Write-Output "# 양호: $($script:cntPass) / 취약: $($script:cntFail) / 수동확인: $($script:cntMC) / 점검불가: $($script:cntNC) / N-A: $($script:cntNA)"
Write-Output "# 증적 파일: $($script:EVD)"
Write-Output "# ============================================================"

if (Test-Path $seceditFile) { Remove-Item $seceditFile -Force -EA SilentlyContinue }
