# ================================================================
# PC(Windows) 보안 취약점 자동 점검 스크립트 — 주요정보통신기반시설
# ================================================================
#
# [용도]
#   주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드(한국인터넷진흥원, 2026)
#   [PC] PC-01 ~ PC-18 (가이드 항목코드·판단기준 그대로)
#   macOS 는 check_pc_mac_kisa.sh 사용. (전자금융용은 check_pc.ps1 — 항목코드 의미가 다르므로 혼용 금지)
#
# [대상 OS]
#   Windows 10 / 11 (가이드 점검 대상). PowerShell 2.0 이상 (cmdlet 이 없으면 WMI·netsh·레지스트리로 대체)
#
# [실행 방법]
#   run_pc_kisa.bat 더블클릭 (관리자 권한 상승 + UTF-8 결과 저장 — 보안 정책·BitLocker·bcdedit·공유 ACL 조회에 필요)
#   또는 관리자 PowerShell 에서
#   powershell -ExecutionPolicy Bypass -Command "& .\check_pc_kisa.ps1 2>&1 | Out-File PC_KISA_$env:COMPUTERNAME.txt -Encoding UTF8"
#   (cmd 의 '>' 리다이렉트는 OEM 코드페이지로 저장되어 한글이 깨질 수 있으므로 Out-File -Encoding UTF8 사용)
#   (비관리자 실행 시 관리자 권한이 필요한 항목은 '점검불가' 로 출력)
#
# [산출물]
#   1) 표준출력(Out-File -Encoding UTF8 로 저장): PC-항목코드|결과|근거설명 (양호/취약/수동확인/점검불가/N-A)
#      헤더: # IP / # 실행 계정 / # 클라우드
#   2) 증적 파일: 스크립트와 같은 폴더 <호스트명>_pc_kisa_evidence.txt (판정에 쓴 원자료 전체)
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

$hn     = $env:COMPUTERNAME
$osw    = @(Get-Wmi "Win32_OperatingSystem")
$os     = if ($osw.Count -gt 0) { $osw[0] } else { $null }
$osName = if ($os) { $os.Caption } else { "Unknown" }
$build  = if ($os) { [int]$os.BuildNumber } else { [Environment]::OSVersion.Version.Build }
$cv     = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -EA SilentlyContinue
$ubr    = if ($cv) { $cv.UBR } else { $null }
$disp   = if ($cv) { $cv.DisplayVersion } else { $null }

Write-Output "# ============================================================"
Write-Output "# 점검 대상: $hn"
Write-Output "# OS: $osName (Build $build$(if ($ubr) { ".$ubr" }) $disp)"
Write-Output "# 점검 기준: 주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드(2026) [PC PC-01~PC-18]"
Write-Output "# 점검 일시: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Output "# IP: $(Get-IPList)"
Write-Output "# 실행 계정: $($script:runAs)$(if (-not $script:isAdmin) { ' (관리자 아님 - 일부 항목 점검불가)' })"
Write-Output "# 클라우드: $(Get-CloudInfo)"
Write-Output "# ============================================================"

$seceditFile = "$env:TEMP\pc_kisa_secpol_$PID.cfg"
$null = secedit /export /cfg $seceditFile /quiet 2>$null
$hasSecEdit = (Test-Path $seceditFile) -and ((Get-Item $seceditFile -EA SilentlyContinue).Length -gt 0)
function Get-SecPol([string]$Key) {
    if (-not $hasSecEdit) { return $null }
    $line = Get-Content $seceditFile -EA SilentlyContinue | Where-Object { $_ -match "^\s*$([regex]::Escape($Key))\s*=" } | Select-Object -First 1
    if ($line) { return ($line -split "=",2)[1].Trim() }; return $null
}

$script:cnt = @{ "양호"=0; "취약"=0; "수동확인"=0; "점검불가"=0; "N-A"=0 }
$script:ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$script:EVD = "$script:ScriptDir\${hn}_pc_kisa_evidence.txt"
@("# ================================================================", "# PC 증적 파일 (주요정보통신기반시설 상세가이드 2026)",
  "# 대상: $hn / $osName (Build $build)", "# 실행 계정: $($script:runAs) / 관리자: $($script:isAdmin)", "# 생성: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')",
  "# ================================================================") | Out-File $script:EVD -Encoding UTF8
function Emit([string]$code,[string]$res,[string]$msg) {
    $script:cnt[$res]++
    Write-Output "$code|$res|$msg"; "[판정] $code|$res|$msg`n" | Add-Content $script:EVD -Encoding UTF8
}
function Pass([string]$c,[string]$m) { Emit $c "양호" $m }
function Fail([string]$c,[string]$m) { Emit $c "취약" $m }
function MC([string]$c,[string]$m)   { Emit $c "수동확인" $m }
function NC([string]$c,[string]$m)   { Emit $c "점검불가" $m }
function NA([string]$c,[string]$m)   { Emit $c "N-A" $m }
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

# ── PC-01 비밀번호의 주기적 변경 (최대 암호 사용 기간 90일 이하) ──
Evd "PC-01" "net accounts"
$maxAge = Get-SecPol "MaximumPasswordAge"
$src01 = "secedit"
if ($null -eq $maxAge) { $maxAge = ConvertTo-IntOrUnlimited (Get-NetAcctMap).MaxAge -1; $src01 = "net accounts" }
EvdQ "PC-01" "MaximumPasswordAge (secedit 사용 가능=$hasSecEdit → 실패 시 net accounts; -1/0=제한 없음)" "$maxAge ($src01)"
if ($null -eq $maxAge) { NC "PC-01" "최대 암호 사용 기간 조회 실패 (secedit·net accounts 모두 실패)$(if (-not $script:isAdmin) { ' - ' + $script:NEED_ADMIN })" }
elseif ([int]$maxAge -gt 0 -and [int]$maxAge -le 90) { Pass "PC-01" "최대 암호 사용 기간 ${maxAge}일 (90일 이하; $src01)" }
else { Fail "PC-01" "최대 암호 사용 기간 $(if ([int]$maxAge -le 0) { '제한 없음' } else { "${maxAge}일 (90일 초과)" }) ($src01)" }

# ── PC-02 비밀번호 관리정책 (복잡성 + 길이, 비밀번호 미사용 계정) ──
$cpx = Get-SecPol "PasswordComplexity"; $mnl = Get-SecPol "MinimumPasswordLength"
if ($null -eq $mnl) { $mnl = ConvertTo-IntOrUnlimited (Get-NetAcctMap).MinLen 0 }
$accts02 = Get-LocalAccts; $acctOk02 = $script:acctOk
$noPwA = @($accts02 | Where-Object { $_.Enabled -and -not $_.PasswordRequired -and $_.Name -notmatch '^(DefaultAccount|WDAGUtilityAccount)$' })
$noPw = @($noPwA | Where-Object { (Get-PwdFlagState $_) -eq "empty" } | ForEach-Object { Get-PwdFlagText $_ })
$chk02 = @($noPwA | Where-Object { $s = Get-PwdFlagState $_; $s -eq "flag" -or $s -eq "unk" } | ForEach-Object { Get-PwdFlagText $_ })
$msa02 = @($noPwA | Where-Object { (Get-PwdFlagState $_) -eq "msa" } | ForEach-Object { Get-PwdFlagText $_ })
$info02 = ""; if ($msa02.Count) { $info02 = " / " + ($msa02 -join ', ') }
Evd "PC-02" "Get-LocalAccts | Format-Table Name,Enabled,PasswordRequired,PasswordLastSet,PrincipalSource,SID -AutoSize"
EvdQ "PC-02" "PasswordComplexity / MinimumPasswordLength (secedit 사용 가능=$hasSecEdit; 복잡성은 secedit 에서만 조회)" "$cpx / $mnl"
$bad02 = @(); $unk02 = @()
if ($null -eq $cpx) { $unk02 += "암호 복잡성 정책(관리자 권한 secedit 필요)" } elseif ("$cpx" -ne "1") { $bad02 += "암호 복잡성 정책 사용 안 함" }
if ($null -eq $mnl) { $unk02 += "최소 암호 길이" } elseif ([int]$mnl -lt 8) { $bad02 += "최소 암호 길이 ${mnl}자 (8자 이상 필요)" }
if (-not $acctOk02) { $unk02 += "비밀번호 미요구 계정(계정 조회 실패)" } elseif ($noPw.Count) { $bad02 += "비밀번호 미설정 계정: $($noPw -join ', ')" }
if ($bad02.Count) { Fail "PC-02" (($bad02 -join ' / ') + $(if ($unk02.Count) { " (확인 불가: $($unk02 -join ', '))" } else { "" })) }
elseif ($unk02.Count) { NC "PC-02" "확인 불가 항목: $($unk02 -join ', ')$(if (-not $script:isAdmin) { ' - ' + $script:NEED_ADMIN })" }
elseif ($chk02.Count) { MC "PC-02" "암호 복잡성 사용, 최소 길이 ${mnl}자 / 비밀번호 필수 플래그가 꺼진 계정 - 실제 비밀번호 설정 여부 확인 필요: $($chk02 -join ', ')$info02" }
else { Pass "PC-02" "암호 복잡성 사용, 최소 길이 ${mnl}자, 비밀번호 미설정 계정 없음$info02" }

# ── PC-03 복구 콘솔 자동 로그온 금지 ──
$rc = Get-Reg 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Setup\RecoveryConsole' 'SecurityLevel'
EvdQ "PC-03" "HKLM\...\Setup\RecoveryConsole SecurityLevel (복구 콘솔: 자동 관리 로그온 허용)" "$rc"
if ("$rc" -eq "1") { Fail "PC-03" "복구 콘솔 자동 관리 로그온 허용 '사용' (SecurityLevel=1)" }
else { Pass "PC-03" "복구 콘솔 자동 관리 로그온 허용 '사용 안 함' (SecurityLevel=$(if ($null -eq $rc) { '미설정(기본 사용 안 함)' } else { $rc }))" }

# ── PC-04 공유 폴더 제거 (공유 유형 FileSystemDirectory 만 파일 공유로 판정, 숨김 사용자 공유 'data$' 포함, 기본 관리 공유 C$·ADMIN$·IPC$·print$ 만 제외) ──
function Get-ShareAcl([string]$name) {
    if ($script:isAdmin -and (Get-Command Get-SmbShareAccess -EA SilentlyContinue)) {
        $a = @(); try { $a = @(Get-SmbShareAccess -Name $name -EA Stop) } catch {}
        if ($a.Count -gt 0) { return @{ Ok = $true; Rows = @($a | ForEach-Object { "$($_.AccountName)|$($_.AccessControlType)|$($_.AccessRight)" }) } }
    }
    $rows = @(); $cap = $false
    foreach ($l in @(net share $name 2>$null)) {   # 대체: net share 의 권한 행 (영문 Permission / 한글 사용 권한)
        if ($l -match '^(Permission|사용 권한)\s{2,}(\S.*)$') { $rows += $Matches[2].Trim(); $cap = $true }
        elseif ($cap -and $l -match '^\s{8,}(\S.*)$') { $rows += $Matches[1].Trim() }
        else { $cap = $false }
    }
    if ($rows.Count -gt 0) { return @{ Ok = $true; Rows = $rows } }
    return @{ Ok = $false; Rows = @() }
}
Evd "PC-04" "Get-ShareList | Format-Table Name,Path,Kind,Default,Source -AutoSize"
$shares04 = @(Get-ShareList)
if (-not $script:shareOk) {
    NC "PC-04" "공유 목록 조회 실패 (Get-SmbShare/Win32_Share 모두 실패)$(if (-not $script:isAdmin) { ' - ' + $script:NEED_ADMIN })"
} else {
    $user04 = @($shares04 | Where-Object { $_.Kind -eq "FileSystemDirectory" -and -not $_.Default })
    $prn04 = @($shares04 | Where-Object { $_.Kind -eq "PrintQueue" })
    $prnNote = if ($prn04.Count) { " / 참고: 프린터 공유 $($prn04.Count)개($(($prn04 | ForEach-Object { $_.Name }) -join ', ')) - 파일 공유 판정 제외" } else { "" }
    if ($user04.Count -eq 0) {
        Pass "PC-04" "사용자 파일 공유 폴더 없음 (기본 관리 공유만 존재, 공유 $($shares04.Count)개 조회)$prnNote"
    } else {
        $ev04 = @(); $unk04 = @(); $aclTxt = @()
        foreach ($s in $user04) {
            $acl = Get-ShareAcl $s.Name
            $aclTxt += "[$($s.Name)] " + $(if ($acl.Ok) { $acl.Rows -join " ; " } else { "(ACL 조회 불가)" })
            if (-not $acl.Ok) { $unk04 += $s.Name }
            elseif (@($acl.Rows | Where-Object { $_ -match '(?i)^(Everyone|Guest|ANONYMOUS|익명)' -and $_ -notmatch '\|Deny\|' }).Count) { $ev04 += $s.Name }
        }
        EvdQ "PC-04" "사용자 파일 공유 접근 권한 (Get-SmbShareAccess → net share)" ($aclTxt -join "`n")
        $names04 = ($user04 | ForEach-Object { "$($_.Name)($($_.Path))" }) -join ', '
        if ($ev04.Count) { Fail "PC-04" "Everyone/Guest 접근 허용 공유 폴더: $($ev04 -join ', ') (전체 사용자 공유: $names04)$prnNote" }
        elseif ($unk04.Count) { NC "PC-04" "사용자 공유 폴더 ${names04} 의 접근 권한(ACL)을 조회하지 못함: $($unk04 -join ', ')$(if (-not $script:isAdmin) { ' - ' + $script:NEED_ADMIN })$prnNote" }
        else { MC "PC-04" "사용자 공유 폴더 $($user04.Count)개($names04) - 업무상 필요 여부 확인 (접근 권한 지정됨, Everyone/Guest 없음)$prnNote" }
    }
}

# ── PC-05 불필요한 서비스 제거 (가이드 '일반적으로 불필요한 서비스') ──
$svcList = @( @("Alerter","Alerter"), @("ClipSrv","Clipbook"), @("Browser","Computer Browser"), @("Messenger","Messenger"), @("mnmsrvc","NetMeeting Remote Desktop Sharing"),
    @("RemoteRegistry","Remote Registry"), @("simptcp","Simple TCP/IP Services"), @("WZCSVC","Wireless Zero Configuration"), @("TlntSvr","Telnet"), @("SNMP","SNMP"),
    @("WmdmPmSN","Portable Media Serial Number"), @("ImapiService","IMAPI CD-Burning COM Service"), @("ERSvc","Error Reporting Service"), @("WerSvc","Windows Error Reporting Service"),
    @("TrkWks","Distributed Link Tracking Client"), @("TrkSvr","Distributed Link Tracking Server"), @("hidserv","Human Interface Device Access"),
    @("Irmon","Infrared Monitor"), @("upnphost","Universal Plug and Play Device Host") )
$svcNames05 = @($svcList | ForEach-Object { $_[0] }) + 'Spooler'
Evd "PC-05" "Get-Service -Name $($svcNames05 -join ',') | Format-Table Name,DisplayName,Status -AutoSize"
$allSvc05 = @(Get-Service -EA SilentlyContinue)
if ($allSvc05.Count -eq 0) {
    NC "PC-05" "서비스 목록 조회 실패 (Get-Service)"
} else {
    $run05 = @()
    foreach ($e in $svcList) { $s = $allSvc05 | Where-Object { $_.Name -eq $e[0] } | Select-Object -First 1; if ($s -and "$($s.Status)" -eq 'Running') { $run05 += "$($e[1])($($e[0]))" } }
    $spool = $allSvc05 | Where-Object { $_.Name -eq 'Spooler' } | Select-Object -First 1
    $note05 = if ($spool -and "$($spool.Status)" -eq 'Running') { " / 참고: Print Spooler 실행 중 - 프린터 미사용 시 중지 권고" } else { "" }
    if ($run05.Count) { Fail "PC-05" "불필요한 서비스 실행 중: $($run05 -join ', ')$note05" }
    else { Pass "PC-05" "가이드 목록의 불필요한 서비스 $($svcList.Count)종 미실행$note05" }
}

# ── PC-06 비인가 상용 메신저 사용 금지 ──
$prev = Get-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Messenger\Client' 'PreventRun'
$msgKw = '(?i)kakaotalk|카카오톡|\bline\b|telegram|whatsapp|discord|skype|nateon|네이트온|wechat|signal|viber|messenger'
$msgs = @(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',"$($uh.Root)\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" -EA SilentlyContinue |
    Where-Object { $_.DisplayName -match $msgKw } | ForEach-Object { "$($_.DisplayName)" } | Select-Object -Unique)
if (Get-Command Get-AppxPackage -EA SilentlyContinue) { $msgs += @(Get-AppxPackage -EA SilentlyContinue | Where-Object { $_.Name -match '(?i)whatsapp|telegram|skype|discord|line' } | ForEach-Object { "$($_.Name)(Store)" }) }
$msgRun = @(Get-Process -EA SilentlyContinue | Where-Object { $_.ProcessName -match '(?i)^(kakaotalk|line|telegram|whatsapp|discord|skype|nateon|wechat|signal)$' } | ForEach-Object { $_.ProcessName } | Select-Object -Unique)
EvdQ "PC-06" "Windows Messenger PreventRun / 설치된 메신저(레지스트리 Uninstall, hive=$($uh.Desc); Appx) / 실행 중 메신저(프로세스)" "PreventRun=$prev`n설치: $($msgs -join ', ')`n실행 중: $($msgRun -join ', ')"
if ($msgs.Count -or $msgRun.Count) { MC "PC-06" "상용 메신저 설치/실행: $((@($msgs) + @($msgRun | ForEach-Object { "$_(실행 중)" })) -join ', ') - 기관 인가 메신저 여부 확인 (비인가 시 취약)" }
else { Pass "PC-06" "상용 메신저 미설치 (Windows Messenger 정책 PreventRun=$(if ($null -eq $prev) { '미설정(Windows 10/11 미포함)' } else { $prev }))" }

# WQL 질의 (ASSOCIATORS OF 등): Get-CimInstance -Query (PS 3.0+) → 없으면 Get-WmiObject -Query (PS 2.0). 오류 시 $script:wmiOk=$false
function Get-WmiQ([string]$Query) {
    $script:wmiOk = $true
    try {
        $cimCmd = Get-Command Get-CimInstance -EA SilentlyContinue
        if ($cimCmd) { & $cimCmd -Query $Query -EA Stop } else { Get-WmiObject -Query $Query -EA Stop }
    } catch { $script:wmiOk = $false }
}
# 볼륨이 내장인지 USB·외장 디스크인지: Win32_LogicalDisk → (Win32_LogicalDiskToPartition) → Win32_DiskPartition → (Win32_DiskDriveToDiskPartition) → Win32_DiskDrive 의 InterfaceType/MediaType/PNPDeviceID
#   (외장 USB 디스크는 Win32_LogicalDisk.DriveType=3(고정)으로 보고되므로 DriveType 만으로 구분할 수 없음)
function Get-VolBus([string]$dev) {
    $r = @{ Known = $false; External = $false; Desc = "" }
    $parts = @(Get-WmiQ "ASSOCIATORS OF {Win32_LogicalDisk.DeviceID='$dev'} WHERE AssocClass=Win32_LogicalDiskToPartition")
    if (-not $script:wmiOk -or -not $parts.Count) { $r.Desc = "WMI 연관 조회 실패"; return $r }
    $descs = @()
    foreach ($p in $parts) {
        $partId = "$($p.DeviceID)"
        $drv = @(Get-WmiQ "ASSOCIATORS OF {Win32_DiskPartition.DeviceID='$partId'} WHERE AssocClass=Win32_DiskDriveToDiskPartition")
        if (-not $script:wmiOk -or -not $drv.Count) { continue }
        foreach ($d in $drv) {
            $r.Known = $true
            if (("$($d.InterfaceType)" -eq "USB") -or ("$($d.MediaType)" -match "External|Removable") -or ("$($d.PNPDeviceID)" -match "^USBSTOR")) { $r.External = $true }
            $descs += "$($d.Model) [InterfaceType=$($d.InterfaceType), MediaType=$($d.MediaType), PNPDeviceID=$($d.PNPDeviceID)]"
        }
    }
    if (-not $r.Known) { $descs += "디스크 드라이브 연관 조회 결과 없음" }
    $r.Desc = $descs -join "; "
    return $r
}
# ── PC-07 파일 시스템 NTFS ──
Evd "PC-07" "Get-Wmi Win32_LogicalDisk 'DriveType=3' | Format-Table DeviceID,FileSystem,Size -AutoSize"
$vol = @(Get-Wmi "Win32_LogicalDisk" "DriveType=3"); $volOk = $script:wmiOk
# FAT 계열 볼륨은 내장 디스크인지 USB·외장 디스크인지 구분 (외장 USB 디스크도 DriveType=3 으로 보고됨). 시스템 드라이브는 외장 판정에서 제외
$fat = @(); $extv = @(); $unkv = @(); $busEvd = @()
foreach ($v in @($vol | Where-Object { "$($_.FileSystem)" -match '^(FAT|FAT32|exFAT)$' })) {
    $lbl = "$($v.DeviceID)($($v.FileSystem))"
    if ("$($v.DeviceID)" -eq "$env:SystemDrive") { $fat += $lbl; $busEvd += "$lbl : 시스템 드라이브 - 내장으로 간주"; continue }
    $b = Get-VolBus "$($v.DeviceID)"
    $kind = if ($b.External) { "USB·외장 디스크" } elseif ($b.Known) { "내장 디스크" } else { "구분 불가" }
    $busEvd += "$lbl : $kind - $($b.Desc)"
    if ($b.External) { $extv += $lbl } elseif ($b.Known) { $fat += $lbl } else { $unkv += $lbl }
}
if ($busEvd.Count) { EvdQ "PC-07" "FAT 계열 볼륨의 내장/외장 구분 (Win32_LogicalDiskToPartition → Win32_DiskDriveToDiskPartition → Win32_DiskDrive InterfaceType/MediaType/PNPDeviceID)" ($busEvd -join "`n") }
$extNote = ""; if ($extv.Count) { $extNote = " (이동식(USB) 외장 디스크 $($extv -join ', ') - 시스템·데이터 볼륨 아님, 판정 제외)" }
if (-not $volOk -or -not $vol.Count) { NC "PC-07" "로컬 디스크 조회 실패 (Win32_LogicalDisk) - 파일 시스템 수동 확인" }
elseif ($fat.Count) { Fail "PC-07" "NTFS 가 아닌 내장 로컬 볼륨: $($fat -join ', ')$extNote" }
elseif ($unkv.Count) { MC "PC-07" "NTFS 가 아닌 로컬 볼륨 $($unkv -join ', ') 의 내장/외장 구분 불가(WMI 연관 조회 실패) - 수동 확인$extNote" }
else { Pass "PC-07" "내장 로컬 디스크 파일 시스템: $(($vol | ForEach-Object { "$($_.DeviceID)$($_.FileSystem)" }) -join ', ')$extNote" }

# ── PC-08 멀티 부팅 (BCD 의 복구 항목 제외 OS 로더 수 + UEFI 펌웨어 부팅 항목의 타 OS) ──
Evd "PC-08" "bcdedit /enum osloader"
Evd "PC-08" "bcdedit /enum firmware"
$bcd = @(bcdedit /enum osloader 2>&1); $bcdRc = $LASTEXITCODE
$fwb = @(bcdedit /enum firmware 2>&1)
$bcdText = $bcd -join "`n"
if ($bcdRc -ne 0 -or $bcdText -match '(?i)access is denied|requires elevation|액세스가 거부|권한') {
    NC "PC-08" "bcdedit 조회 실패(종료코드 $bcdRc) - $(if (-not $script:isAdmin) { $script:NEED_ADMIN } else { 'BCD 저장소를 읽지 못함' }); msconfig [부팅] 탭에서 OS 개수 확인"
} else {
    $ldr = @($bcd | Where-Object { $_ -match '^(description|설명)\s+\S' } | ForEach-Object { ($_ -split '\s{2,}',2)[-1].Trim() } | Where-Object { $_ -notmatch '(?i)recovery|복구|setup|설치' })
    $otherOs = @($fwb | Where-Object { $_ -match '^(description|설명)\s+\S' } | ForEach-Object { ($_ -split '\s{2,}',2)[-1].Trim() } | Where-Object { $_ -match '(?i)ubuntu|linux|debian|fedora|centos|red ?hat|suse|grub|refind|mint|macos|boot ?camp' })
    if ($ldr.Count -gt 1) { Fail "PC-08" "OS 로더 $($ldr.Count)개 - 멀티 부팅 구성: $($ldr -join ', ')" }
    elseif ($otherOs.Count) { Fail "PC-08" "UEFI 부팅 항목에 다른 OS 존재(멀티 부팅 가능): $($otherOs -join ', ') (Windows 로더: $($ldr -join ', '))" }
    else { Pass "PC-08" "OS 로더 $($ldr.Count)개 (단일 OS: $($ldr -join ', ')), UEFI 부팅 항목에 타 OS 없음" }
}

# ── PC-09 브라우저 종료 시 임시 인터넷 파일 삭제 ──
$pp = Get-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Cache' 'Persistent'
$up = Get-Reg "$($uh.Root)\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Cache" 'Persistent'
$edge = Get-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' 'ClearBrowsingDataOnExit'
EvdQ "PC-09" "정책 Cache\Persistent / 사용자 Cache\Persistent (hive=$($uh.Desc)) / Edge ClearBrowsingDataOnExit" "$pp / $up / $edge"
if ("$pp" -eq "0" -or ("$pp" -eq "" -and "$up" -eq "0") -or "$edge" -eq "1") { Pass "PC-09" "브라우저 종료 시 임시 인터넷 파일 삭제 설정 (Persistent=$(if ("$pp" -ne '') { $pp } else { $up }), Edge ClearBrowsingDataOnExit=$edge)" }
else { Fail "PC-09" "'브라우저를 닫을 때 임시 인터넷 파일 폴더 비우기' 미설정 (Persistent=$(if ("$pp" -ne '') { $pp } else { "$up(미설정=기본 보존)" }), Edge ClearBrowsingDataOnExit=$edge)" }

# ── PC-10 주기적 보안 패치 (HOT FIX + 자동 업데이트) ──
Evd "PC-10" "Get-HotFix | Sort-Object InstalledOn -Descending | Format-Table HotFixID,Description,InstalledOn -AutoSize"
$hf = Get-LatestHotfix
$noAu = Get-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' 'NoAutoUpdate'
$wuStart = Get-Reg 'HKLM:\SYSTEM\CurrentControlSet\Services\wuauserv' 'Start'   # 4 = 사용 안 함
EvdQ "PC-10" "판정에 사용한 최근 HOT FIX / 자동 업데이트 정책 NoAutoUpdate / wuauserv Start(4=사용 안 함)" "$(if ($hf -and $hf.Date) { "$($hf.ID) $($hf.Date)" } else { '조회 실패/이력 없음' }) / $noAu / $wuStart"
if ($null -eq $hf -or $null -eq $hf.Date) { NC "PC-10" "HOT FIX 설치 이력 조회 실패 (Get-HotFix·Win32_QuickFixEngineering 결과 없음) - 설정 > Windows 업데이트 기록 확인" }
else {
    $age = ((Get-Date) - $hf.Date).Days
    $auOff = ("$noAu" -eq "1") -or ("$wuStart" -eq "4")
    if ($age -gt 90) { Fail "PC-10" "최근 HOT FIX $($hf.ID) 설치 후 ${age}일 경과 (자동 업데이트 $(if ($auOff) { '비활성' } else { '활성' }))" }
    elseif ($auOff) { Fail "PC-10" "자동 업데이트 비활성 (NoAutoUpdate=$noAu, wuauserv Start=$wuStart) - 최근 HOT FIX $($hf.ID) (${age}일 전)" }
    else { Pass "PC-10" "최근 HOT FIX $($hf.ID) ($($hf.Date.ToString('yyyy-MM-dd')), ${age}일 전), 자동 업데이트 활성 - 내부 관리 절차는 인터뷰 확인" }
}

# ── PC-11 지원이 종료되지 않은 Windows OS Build ──
$ed = Get-Reg 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' 'EditionID'
$ent = "$ed" -match '(?i)Enterprise|Education|IoT'
# 빌드별 서비스 종료일 (Microsoft 수명 주기: Home/Pro 기준, Enterprise·Education 은 별도)
$eos = @{ 19045 = @('2025-10-14','2025-10-14'); 19044 = @('2023-06-13','2024-06-11'); 22000 = @('2023-10-10','2024-10-08')
          22621 = @('2024-10-08','2025-10-14'); 22631 = @('2025-11-11','2026-11-10'); 26100 = @('2026-10-13','2027-10-12'); 26200 = @('2027-10-12','2028-10-10') }
EvdQ "PC-11" "Build / UBR / DisplayVersion / EditionID" "$build / $ubr / $disp / $ed"
# LTSC(EditionID EnterpriseS 계열) 는 일반 에디션과 수명 주기가 다름 (Enterprise LTSC 기준)
$ltscEos = @{ 17763 = '2029-01-09'; 19044 = '2027-01-12'; 26100 = '2029-10-09' }
if ("$ed" -match '(?i)EnterpriseS' -and $ltscEos.ContainsKey($build)) {
    $end = [datetime]$ltscEos[$build]
    if ((Get-Date) -gt $end) { Fail "PC-11" "$osName LTSC (Build $build) 서비스 종료 $($end.ToString('yyyy-MM-dd'))" }
    else { Pass "PC-11" "$osName LTSC (Build $build.$ubr) 지원 기간 내 (종료 $($end.ToString('yyyy-MM-dd')))" }
} elseif ($eos.ContainsKey($build)) {
    $end = [datetime]$eos[$build][[int]$ent]
    if ((Get-Date) -gt $end) { Fail "PC-11" "$osName $disp (Build $build) 서비스 종료 $($end.ToString('yyyy-MM-dd')) - 지원 빌드로 업데이트 필요$(if ($build -eq 19045) { ' (Windows 10 ESU 가입 시 예외 - 증빙 확인)' })" }
    else { Pass "PC-11" "$osName $disp (Build $build.$ubr) 지원 기간 내 (종료 $($end.ToString('yyyy-MM-dd')))" }
} elseif ($build -lt 19044) { Fail "PC-11" "$osName (Build $build) 서비스 종료 빌드" }
else { MC "PC-11" "$osName (Build $build) - Microsoft 수명 주기에서 지원 여부 확인" }

# ── PC-12 Windows 자동 로그인 ──
$al = Get-Reg 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' 'AutoAdminLogon'
$dp = Get-Reg 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' 'DefaultPassword'
EvdQ "PC-12" "Winlogon AutoAdminLogon / DefaultPassword(존재 여부만)" "$al / $(if ($null -eq $dp) { '없음' } else { '존재' })"
if ("$al" -eq "1") { Fail "PC-12" "Windows 자동 로그인 활성화 (AutoAdminLogon=1$(if ($null -ne $dp) { ', DefaultPassword 저장됨' }))" }
else { Pass "PC-12" "Windows 자동 로그인 비활성 (AutoAdminLogon=$(if ($null -eq $al) { '미설정' } else { $al }))" }

# ── PC-13 / PC-14 백신 설치·업데이트 / 실시간 감시 (제품별로 켜짐·최신 여부를 보고, 꺼진 타사 백신을 Defender 상태로 가리지 않음) ──
Evd "PC-13" "Get-Wmi AntiVirusProduct '' 'root\SecurityCenter2' | Format-Table displayName,@{n='productState';e={'0x'+([int]`$_.productState).ToString('X6')}} -AutoSize"
$avSc = @(Get-Wmi "AntiVirusProduct" "" "root\SecurityCenter2"); $scOk = $script:wmiOk
$mp = $null; try { $mp = Get-MpComputerStatus -EA Stop } catch {}
EvdQ "PC-13" "Defender (Get-MpComputerStatus)" $(if ($mp) { "AMServiceEnabled=$($mp.AMServiceEnabled) RealTime=$($mp.RealTimeProtectionEnabled) SignatureLastUpdated=$($mp.AntivirusSignatureLastUpdated) SignatureVersion=$($mp.AntivirusSignatureVersion)" } else { '조회 불가(cmdlet 없음 또는 오류)' })
$prod = @()
foreach ($p in $avSc) {
    if (-not $p) { continue }
    $isDef = "$($p.displayName)" -match '(?i)Windows Defender|Microsoft Defender'
    if ($isDef -and $mp) { continue }   # Defender 는 아래에서 Get-MpComputerStatus 값으로
    $prod += New-Object PSObject -Property @{ Name = "$($p.displayName)"; On = (Test-WscOn ([int]$p.productState)); Upd = (Test-WscUpToDate ([int]$p.productState)); Detail = "productState=0x$(([int]$p.productState).ToString('X6'))" }
}
if ($mp) {
    $sigAge = ((Get-Date) - $mp.AntivirusSignatureLastUpdated).Days
    $prod += New-Object PSObject -Property @{ Name = "Microsoft Defender"; On = [bool]($mp.RealTimeProtectionEnabled -and $mp.AMServiceEnabled); Upd = ($sigAge -le 7); Detail = "서명 갱신 $($mp.AntivirusSignatureLastUpdated.ToString('yyyy-MM-dd')) (${sigAge}일 전), 실시간=$($mp.RealTimeProtectionEnabled)" }
}
$prodTxt = (($prod | ForEach-Object { "$($_.Name) / 실시간=$($_.On) / 정의최신=$($_.Upd) / $($_.Detail)" }) -join "`n")
EvdQ "PC-13" "판정에 사용한 제품별 상태 (이름 / 실시간 감시 켜짐 / 정의 최신 / 상세)" $prodTxt
EvdQ "PC-14" "판정에 사용한 제품별 상태 (PC-13 과 동일 원자료: 이름 / 실시간 감시 켜짐 / 정의 최신 / 상세)" $prodTxt
if (-not $scOk -and -not $mp) {
    NC "PC-13" "백신 상태 조회 실패 (SecurityCenter2 네임스페이스 없음/오류, Get-MpComputerStatus 실패) - 서버 SKU·구버전이거나 권한 문제"
    NC "PC-14" "백신 상태 조회 실패 (SecurityCenter2 네임스페이스 없음/오류, Get-MpComputerStatus 실패)"
} elseif ($prod.Count -eq 0) {
    Fail "PC-13" "백신 프로그램 미탐지 (SecurityCenter2 등록 제품 없음, Defender 조회 불가)"; Fail "PC-14" "백신 프로그램 미탐지 - 실시간 감시 불가"
} else {
    $allNames = ($prod | ForEach-Object { "$($_.Name)[실시간=$(if ($_.On) { '켜짐' } else { '꺼짐' }), 정의=$(if ($_.Upd) { '최신' } else { '오래됨' })]" }) -join '; '
    $active = @($prod | Where-Object { $_.On })
    $cand = if ($active.Count) { $active } else { $prod }
    $old = @($cand | Where-Object { -not $_.Upd })
    if ($old.Count -eq 0) { Pass "PC-13" "백신 설치·정의 최신: $(($cand | ForEach-Object { "$($_.Name) ($($_.Detail))" }) -join '; ')" }
    else { Fail "PC-13" "백신 정의 업데이트 필요: $(($old | ForEach-Object { "$($_.Name) ($($_.Detail))" }) -join '; ') / 전체: $allNames" }
    if ($active.Count) { Pass "PC-14" "백신 실시간 감시 활성: $(($active | ForEach-Object { $_.Name }) -join ', ')" }
    else { Fail "PC-14" "백신 실시간 감시 비활성(설치된 모든 제품이 꺼짐): $allNames" }
}

# ── PC-15 OS 침입차단(방화벽) ──
$fw = Get-FwState
$fw3 = @(Get-Wmi "FirewallProduct" "" "root\SecurityCenter2")
$fw3on = @($fw3 | Where-Object { $_ -and (Test-WscOn ([int]$_.productState)) } | ForEach-Object { $_.displayName })
Evd "PC-15" "Get-FwState | ForEach-Object { `$_.Source; `$_.Profiles.GetEnumerator() | Sort-Object Key | Format-Table Key,Value -AutoSize }"
EvdQ "PC-15" "타사 방화벽(SecurityCenter2 FirewallProduct, 켜짐만)" ($fw3on -join ', ')
$fwOff = @(); $fwUnk = @()
foreach ($k in $fw.Profiles.Keys) { if ($null -eq $fw.Profiles[$k]) { $fwUnk += $k } elseif (-not $fw.Profiles[$k]) { $fwOff += $k } }
if ($fwUnk.Count -eq $fw.Profiles.Count) { NC "PC-15" "방화벽 상태 조회 실패 (Get-NetFirewallProfile 없음/오류, 레지스트리 값 없음)" }
elseif (-not $fwOff.Count) { Pass "PC-15" "Windows 방화벽 전체 프로필 사용 ($($fw.Source)$(if ($fwUnk.Count) { '; 미확인 프로필: ' + ($fwUnk -join ',') }))" }
elseif ($fw3on.Count) { Pass "PC-15" "Windows 방화벽 일부 비활성($($fwOff -join ',')) - 타사 방화벽 사용(켜짐): $($fw3on -join ', ')" }
else { Fail "PC-15" "Windows 방화벽 사용 안 함: $($fwOff -join ', ') (타사 방화벽 켜짐 미탐지; $($fw.Source))" }

# ── PC-16 화면보호기 (대기 10분 이하 + 암호 보호) — 콘솔 로그온 사용자 hive ──
$pol = "$($uh.Root)\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop"; $usr = "$($uh.Root)\Control Panel\Desktop"
$ssA = Get-Reg $pol 'ScreenSaveActive';    if ($null -eq $ssA) { $ssA = Get-Reg $usr 'ScreenSaveActive' }
$ssT = Get-Reg $pol 'ScreenSaveTimeOut';   if ($null -eq $ssT) { $ssT = Get-Reg $usr 'ScreenSaveTimeOut' }
$ssS = Get-Reg $pol 'ScreenSaverIsSecure'; if ($null -eq $ssS) { $ssS = Get-Reg $usr 'ScreenSaverIsSecure' }
$lock = Get-Reg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'InactivityTimeoutSecs'
EvdQ "PC-16" "읽은 hive: $($uh.Desc) / ScreenSaveActive / ScreenSaveTimeOut / ScreenSaverIsSecure / InactivityTimeoutSecs(컴퓨터 잠금)" "$ssA / $ssT / $ssS / $lock"
if ("$ssA" -eq "1" -and "$ssS" -eq "1" -and $ssT -and [int]$ssT -gt 0 -and [int]$ssT -le 600) { Pass "PC-16" "화면보호기 대기 $([int]$ssT/60)분, 재시작 시 암호 보호 ($($uh.Desc))" }
elseif ($lock -and [int]$lock -gt 0 -and [int]$lock -le 600) { Pass "PC-16" "컴퓨터 비활성 한도(잠금) ${lock}초 - 화면 잠금 적용" }
else { Fail "PC-16" "화면보호기 설정 미흡 (사용=$ssA, 대기=${ssT}초, 암호 보호=$ssS; 기준: 10분 이하 + 암호 보호; $($uh.Desc))" }

# ── PC-17 이동식 미디어 자동 실행 방지 — HKLM 정책 + 콘솔 로그온 사용자 hive ──
$nd = Get-Reg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'NoDriveTypeAutoRun'
$nar = Get-Reg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'NoAutorun'
$ndu = Get-Reg "$($uh.Root)\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" 'NoDriveTypeAutoRun'
$dap = Get-Reg "$($uh.Root)\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" 'DisableAutoplay'
EvdQ "PC-17" "NoDriveTypeAutoRun(HKLM/사용자) / NoAutorun / DisableAutoplay (사용자 hive: $($uh.Desc))" "$nd / $ndu / $nar / $dap"
if ("$nd" -eq "255" -or "$ndu" -eq "255" -or "$dap" -eq "1") { Pass "PC-17" "모든 드라이브 자동 실행 끄기 (NoDriveTypeAutoRun=$(if ("$nd" -ne '') { $nd } else { $ndu }), DisableAutoplay=$dap) - 이동식 미디어 관리 절차는 인터뷰 확인" }
else { Fail "PC-17" "미디어 자동 실행 방지 미설정 (NoDriveTypeAutoRun=$nd/$ndu, DisableAutoplay=$dap)" }

# ── PC-18 원격 지원 금지 ──
$rp = Get-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' 'fAllowToGetHelp'
$ra = Get-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance' 'fAllowToGetHelp'
EvdQ "PC-18" "정책 fAllowToGetHelp / 시스템 fAllowToGetHelp" "$rp / $ra"
$eff = if ("$rp" -ne "") { $rp } else { $ra }
if ("$eff" -eq "1") { Fail "PC-18" "원격 지원 허용 (fAllowToGetHelp=1)" }
else { Pass "PC-18" "원격 지원 사용 안 함 (fAllowToGetHelp=$(if ("$eff" -eq '') { '미설정' } else { $eff }))" }

Write-Output "# ============================================================"
Write-Output "# 점검 요약 - 주요정보통신기반시설 상세가이드(2026) PC"
Write-Output "#   양호: $($script:cnt['양호']) / 취약: $($script:cnt['취약']) / 수동확인: $($script:cnt['수동확인']) / 점검불가: $($script:cnt['점검불가']) / N-A: $($script:cnt['N-A'])"
Write-Output "# 증적 파일: $($script:EVD)"
Write-Output "# ============================================================"
if (Test-Path $seceditFile) { Remove-Item $seceditFile -Force -EA SilentlyContinue }
