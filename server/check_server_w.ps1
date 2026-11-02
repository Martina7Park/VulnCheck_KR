# ================================================================
# Windows 서버 주요정보통신기반시설 취약점 점검 스크립트 (2026 상세가이드 W-01 ~ W-64)
# ================================================================
#
# [기준]
#   주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드(2026, 과기정통부 고시 제2025-62호)
#   [Windows 서버] W-01 ~ W-64 - 항목코드·판단기준 가이드 원문 그대로
#   전자금융기반시설(SRV) 점검은 check_server.ps1, 둘 다는 check_server.ps1 -Mode all
#
# [대상 OS]  Windows Server 2008 R2 ~ 2025 (PowerShell 2.0 이상), 관리자 권한 권장(secedit·SAM 권한 조회 - 비관리자 실행 시 해당 항목은 '점검불가')
#
# [실행 방법]
#   run_server.bat 에서 2) 주요정보 선택  또는
#   powershell -ExecutionPolicy Bypass -File check_server_w.ps1
#   결과 파일은 스크립트가 UTF-8(BOM) 로 직접 저장한다 (cmd '>' 리다이렉트 불필요 - 한글 깨짐 방지).
#
# [산출물]
#   1) 결과 파일: 스크립트와 같은 폴더 <호스트명>_w.txt (표준출력에도 동일 내용 표시)
#      W-항목코드|결과|근거설명 (양호/취약/수동확인/점검불가/N-A)
#   2) 증적 파일: 스크립트와 같은 폴더 <호스트명>_w_evidence.txt
# ================================================================
$ErrorActionPreference = "SilentlyContinue"
$ProgressPreference    = "SilentlyContinue"
try { [Console]::OutputEncoding = [Text.Encoding]::UTF8 } catch {}

$hn     = $env:COMPUTERNAME
$script:SelfDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
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
$script:OUT = "$script:SelfDir\${hn}_w.txt"
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
Out-Res "# 점검 대상: $hn"
Out-Res "# IP: $ipText"
Out-Res "# 실행 계정: $acctText"
Out-Res "# 클라우드: $($script:CloudLine)"
Out-Res "# OS: $(if ($os) { $os.Caption } else { "Windows Server $ver" }) (Build $build)"
Out-Res "# OS 상세: $(if ($os) { "$($os.Caption) $($os.Version)" } else { "Windows Build $build" })"
Out-Res "# 점검 기준: 주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드(2026) [Windows 서버 W-01~W-64]"
Out-Res "# 점검 일시: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Out-Res "# ================================================================"
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

$script:cntPass=0; $script:cntFail=0; $script:cntMC=0; $script:cntNA=0; $script:cntUnable=0
$script:EVD = "$script:SelfDir\${hn}_w_evidence.txt"
Start-Utf8File $script:EVD "# ================================================================"
Append-Utf8 $script:EVD "# 증적 파일 (감사 추적용) - 주요정보통신기반시설 상세가이드(2026) W-01~W-64"
Append-Utf8 $script:EVD "# 대상: $hn / $(if ($os) { $os.Caption } else { 'Windows' }) (Build $build)"
Append-Utf8 $script:EVD "# IP: $ipText"
Append-Utf8 $script:EVD "# 실행 계정: $acctText"
Append-Utf8 $script:EVD "# 클라우드: $($script:CloudLine)"
Append-Utf8 $script:EVD "# 생성: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Append-Utf8 $script:EVD "# ================================================================"
function Emit([string]$code,[string]$res,[string]$msg) {
    $msg = ($msg -replace "[`r`n]+", " / ") -replace '\|', '/'
    switch ($res) { "양호" { $script:cntPass++ } "취약" { $script:cntFail++ } "수동확인" { $script:cntMC++ } "점검불가" { $script:cntUnable++ } default { $script:cntNA++ } }
    Out-Res "$code|$res|$msg"; Append-Utf8 $script:EVD "[판정] $code|$res|$msg"; Append-Utf8 $script:EVD ""
}
function Pass([string]$code,[string]$msg) { Emit $code "양호" $msg }
function Fail([string]$code,[string]$msg) { Emit $code "취약" $msg }
function NA([string]$code,[string]$msg)   { Emit $code "N-A" $msg }
function MC([string]$code,[string]$msg)   { Emit $code "수동확인" $msg }
function Unable([string]$code,[string]$msg) { Emit $code "점검불가" $msg }   # 점검 자체를 못 한 경우(권한·cmdlet·조회 오류) - 근거에 구체적 사유
function Evd([string]$item,[string]$cmd) {
    Append-Utf8 $script:EVD "[$item] $(Get-Date -Format 'HH:mm:ss') PS> $cmd"
    try { $r = Invoke-Expression $cmd 2>&1 | Out-String -Width 4096; Append-Utf8 $script:EVD (Limit-Lines $r) } catch { Append-Utf8 $script:EVD $_.Exception.Message }
    Append-Utf8 $script:EVD ""
}
function EvdQ([string]$item,[string]$desc,[string]$val) {
    Append-Utf8 $script:EVD "[$item] $(Get-Date -Format 'HH:mm:ss') $desc"
    Append-Utf8 $script:EVD (Limit-Lines $val)
    Append-Utf8 $script:EVD ""
}
$secOK = Test-Path $seceditFile   # secedit 내보내기 성공 여부 (관리자 권한 필요)
$secMsg = "$(if ($script:IsAdmin -eq $false) { '관리자 권한 아님 - ' } else { 'secedit 내보내기 실패 - ' })보안 정책(secedit) 조회 불가, 관리자 권한으로 재실행 또는 secpol.msc 확인"
$defAdm = @('Administrator','Administrateur','Administrador','Administratör','Amministratore','Beheerder','Administrátor','Rendszergazda','Yönetici','Администратор','管理员','管理者','관리자')   # 로캘별 기본 관리자 계정 이름
function Int0($v) { if ("$v" -match '^-?\d+$') { [int]"$v" } else { $null } }
function SidNames([string]$v) { if (-not $v) { return @() }; return @($v -split ',' | ForEach-Object { Resolve-SecPolEntry $_ } | Where-Object { $_ }) }
$lsa  = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
$pol  = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
$lmsv = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
$tsP  = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
$rdpDenyV = Get-RdpDeny   # 그룹 정책 우선 → 로컬 설정
$rdpOn = ("$rdpDenyV" -eq '0')
$ftpSites = Get-IisFtpSites
$ftpSvc = Get-SvcState 'FTPSVC'; if (-not $ftpSvc) { $ftpSvc = Get-SvcState 'MSFTPSVC' }
$l21 = Get-Listen 21
$ftpSvcRun = [bool]($ftpSvc -and "$($ftpSvc.Status)" -match 'Running')
$ftpOn = $ftpSvcRun -or ((Cnt $l21) -gt 0)   # IIS FTP 서비스 또는 21번 포트 리슨(타사 FTP 포함)
$ahc = "$env:windir\System32\inetsrv\config\applicationHost.config"
$ftpIis = ($null -ne $ftpSites -and (Cnt $ftpSites) -gt 0)
# 모드: iis / iis-none(FTPSVC 실행·사이트 미탐지) / iis-fail(설정 읽기 실패) / third(타사 FTP 가 21 리슨) / unknown(포트 조회 불가) / none
$ftpMode = if ($ftpSvcRun) { if ($null -eq $ftpSites) { 'iis-fail' } elseif ((Cnt $ftpSites) -eq 0) { 'iis-none' } else { 'iis' } } elseif ($null -eq $l21) { 'unknown' } elseif ((Cnt $l21) -gt 0) { 'third' } else { 'none' }
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
if (-not $adm) { Unable "W-01" "기본 관리자(RID 500) 계정 조회 실패(Get-LocalUser·WMI 불가 또는 도메인 컨트롤러) - 계정 이름 확인" }
elseif ($defAdm -notcontains $adm.Name) { Pass "W-01" "기본 관리자 계정 이름 변경됨: $($adm.Name)$(if (-not $adm.Enabled) { ' (비활성)' })" }
else { MC "W-01" "기본 관리자 계정 이름이 기본값('$($adm.Name)')$(if (-not $adm.Enabled) { ' (계정 비활성)' }) - 가이드: 이름 변경 또는 강화된 비밀번호 적용 시 양호 → 비밀번호 강도(2종 10자/3종 8자) 확인" }

# W-02 Guest 계정 비활성화
Evd "W-02" "Get-LocalAccounts | Where-Object { `$_.SID -match '-501$' } | Select-Object Name,Enabled | Format-List"
$gst = $accts | Where-Object { "$($_.SID)" -match '-501$' } | Select-Object -First 1
$eg = Get-SecPol 'EnableGuestAccount'
if ($gst) { if ($gst.Enabled) { Fail "W-02" "Guest 계정 활성: $($gst.Name)" } else { Pass "W-02" "Guest 계정 비활성: $($gst.Name)" } }
elseif ("$eg" -eq '0') { Pass "W-02" "Guest 계정 비활성 (EnableGuestAccount=0)" }
else { Unable "W-02" "Guest 계정 조회 실패(Get-LocalUser·WMI·secedit 모두 불가) - lusrmgr.msc 확인" }

# W-03 불필요한 계정 제거
Evd "W-03" "Get-LocalAccounts | Select-Object Name,Enabled,LastLogon,PasswordLastSet | Format-Table -AutoSize"
$act = @($accts | Where-Object { $_.Enabled -and "$($_.SID)" -notmatch '-(501|503|504)$' })
$test = @($act | Where-Object { $_.Name -match '^(test|temp|tmp|guest|demo|user|sample)[-_]?\d*$' } | ForEach-Object { $_.Name })   # 접두 일치가 아니라 이름 전체 일치 (username 등 오탐 방지)
$old = @($act | Where-Object { $_.LastLogon -and ((Get-Date) - [datetime]$_.LastLogon).Days -gt 90 } | ForEach-Object { "$($_.Name)(최근 로그인 $(([datetime]$_.LastLogon).ToString('yyyy-MM-dd')))" })
EvdQ "W-03" "활성 계정 목록 (테스트성 이름 패턴 일치 / 90일 이상 미사용)" "활성 계정: $(($act | ForEach-Object { $_.Name }) -join ', ')`n테스트성: $($test -join ', ')`n90일 이상 미사용: $($old -join ', ')"
if ($accts.Count -eq 0) { Unable "W-03" "로컬 계정 조회 실패(Get-LocalUser·WMI 불가 또는 도메인 컨트롤러) - lusrmgr.msc 확인" }
elseif ($test.Count) { Fail "W-03" "테스트성 계정 활성: $($test -join ', ')" }
else { MC "W-03" "활성 계정: $(($act | ForEach-Object { $_.Name }) -join ', ')$(if ($old.Count) { " / 90일 이상 미사용: $($old -join ', ')" }) - 퇴직자·미사용·불필요 계정 여부 확인 (없으면 양호)" }

# W-04 계정 잠금 임계값 (5 이하)
if (-not $secOK) { Unable "W-04" $secMsg } else {
    $lc = Int0 (Get-SecPol 'LockoutBadCount'); EvdQ "W-04" "secedit LockoutBadCount" "$lc"
    if ($null -eq $lc) { Unable "W-04" "LockoutBadCount 값 조회 실패(secedit 내보내기에 항목 없음)" }
    elseif ($lc -ge 1 -and $lc -le 5) { Pass "W-04" "계정 잠금 임계값 ${lc}회" } else { Fail "W-04" "계정 잠금 임계값 $(if ($lc -eq 0) { '미설정(0)' } else { "${lc}회 (5 초과)" })" }
}

# W-05 해독 가능한 암호화를 사용하여 암호 저장 해제
if (-not $secOK) { Unable "W-05" $secMsg } else {
    $ct = Get-SecPol 'ClearTextPassword'; EvdQ "W-05" "secedit ClearTextPassword" "$ct"
    if ("$ct" -eq '1') { Fail "W-05" "'해독 가능한 암호화를 사용하여 암호 저장' 사용" } else { Pass "W-05" "'해독 가능한 암호화를 사용하여 암호 저장' 사용 안 함 (ClearTextPassword=$(if ($null -eq $ct) { '미정의=0' } else { $ct }))" }
}

# W-06 관리자 그룹에 최소한의 사용자 포함
$am = Get-LocalGroupMemberNames 'S-1-5-32-544'
EvdQ "W-06" "Administrators 구성원" $(if ($null -eq $am) { '(조회 실패)' } else { @($am) -join "`n" })
if ($null -eq $am -or (Cnt $am) -eq 0) { Unable "W-06" "Administrators 구성원 조회 실패(ADSI) - lusrmgr.msc 확인" }
elseif ((Cnt $am) -le 1) { Pass "W-06" "Administrators 구성원 $(Cnt $am)명: $(@($am) -join ', ')" }
else { MC "W-06" "Administrators 구성원 $(Cnt $am)명: $(@($am) -join ', ') - 불필요한 관리자 계정 여부 확인 (없으면 양호)" }

# W-07 Everyone 사용 권한을 익명 사용자에 적용 (사용 안 함)
$eia = Get-Reg $lsa 'EveryoneIncludesAnonymous'; EvdQ "W-07" "Lsa EveryoneIncludesAnonymous" "$eia"
if ("$eia" -eq '1') { Fail "W-07" "'Everyone 사용 권한을 익명 사용자에게 적용' 사용" } else { Pass "W-07" "'Everyone 사용 권한을 익명 사용자에게 적용' 사용 안 함 (EveryoneIncludesAnonymous=$(if ($null -eq $eia) { '미정의=0' } else { $eia }))" }

# W-08 계정 잠금 기간 (잠금 기간·원래대로 설정 기간 60분 이상)
if (-not $secOK) { Unable "W-08" $secMsg } else {
    $ld = Int0 (Get-SecPol 'LockoutDuration'); $rl = Int0 (Get-SecPol 'ResetLockoutCount'); EvdQ "W-08" "secedit LockoutDuration / ResetLockoutCount" "$ld / $rl"
    if ($ld -ne $null -and $rl -ne $null -and ($ld -ge 60 -or $ld -eq -1) -and $rl -ge 60) { Pass "W-08" "계정 잠금 기간 $(if ($ld -eq -1) { '관리자 해제' } else { "${ld}분" }), 원래대로 설정 ${rl}분" }
    else { Fail "W-08" "계정 잠금 기간 $(if ($null -eq $ld) { '미설정' } else { "${ld}분" }) / 원래대로 설정 기간 $(if ($null -eq $rl) { '미설정' } else { "${rl}분" }) (60분 이상 필요)" }
}

# W-09 비밀번호 관리 정책 (복잡성·최소 8자·최대 90일·최소 1일·최근 암호 4개)
if (-not $secOK) { Unable "W-09" $secMsg } else {
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
if (-not $secOK) { Unable "W-11" $secMsg } else {
    $il = Get-SecPol 'SeInteractiveLogonRight'; $n = SidNames $il; EvdQ "W-11" "SeInteractiveLogonRight" "$il => $($n -join ', ')"
    $ext = @(($il -split ',') | Where-Object { $_ -and $_.Trim() -ne '*S-1-5-32-544' } | ForEach-Object { Resolve-SecPolEntry $_ } | Where-Object { $_ -notmatch 'IUSR' })
    if ($null -eq $il) { Unable "W-11" "SeInteractiveLogonRight 값 조회 실패(secedit 내보내기에 항목 없음)" } elseif ($ext.Count) { Fail "W-11" "로컬 로그온 허용에 Administrators·IUSR_ 외 계정/그룹: $($ext -join ', ')" } else { Pass "W-11" "로컬 로그온 허용: $($n -join ', ')" }
}

# W-12 익명 SID/이름 변환 허용 해제
if (-not $secOK) { Unable "W-12" $secMsg } else {
    $an = Get-SecPol 'LSAAnonymousNameLookup'; EvdQ "W-12" "LSAAnonymousNameLookup" "$an"
    if ($null -eq $an) { Unable "W-12" "LSAAnonymousNameLookup 값 조회 실패(secedit 내보내기에 항목 없음)" } elseif ("$an" -eq '1') { Fail "W-12" "'익명 SID/이름 변환 허용' 사용" } else { Pass "W-12" "'익명 SID/이름 변환 허용' 사용 안 함" }
}

# W-13 콘솔 로그온 시 로컬 계정에서 빈 암호 사용 제한
$lb = Get-Reg $lsa 'LimitBlankPasswordUse'; EvdQ "W-13" "Lsa LimitBlankPasswordUse" "$lb"
if ("$lb" -eq '0') { Fail "W-13" "'콘솔 로그온 시 로컬 계정에서 빈 암호 사용 제한' 사용 안 함" } else { Pass "W-13" "'콘솔 로그온 시 로컬 계정에서 빈 암호 사용 제한' 사용 (LimitBlankPasswordUse=$(if ($null -eq $lb) { '미정의=1' } else { $lb }))" }

# W-14 원격터미널 접속 가능한 사용자 그룹 제한
$rdu = Get-LocalGroupMemberNames 'S-1-5-32-555'
EvdQ "W-14" "원격 데스크톱 사용(fDenyTSConnections, 그룹 정책 우선) / Remote Desktop Users 구성원" "fDenyTSConnections=$rdpDenyV / $(if ($null -eq $rdu) { '조회 실패' } elseif ((Cnt $rdu) -eq 0) { '(구성원 없음)' } else { @($rdu) -join ', ' })"
if (-not $rdpOn) { Pass "W-14" "원격 데스크톱 사용 안 함 (fDenyTSConnections=$(if ($null -eq $rdpDenyV) { '값 없음' } else { $rdpDenyV }))" }
elseif ($null -eq $rdu) { Unable "W-14" "Remote Desktop Users 구성원 조회 실패(ADSI) - 확인 필요" }
elseif ((Cnt $rdu) -eq 0) { Fail "W-14" "원격 데스크톱 사용 중이나 관리자 외 원격 접속 전용 계정 없음 (Remote Desktop Users 비어 있음 - 관리자 계정으로 원격 접속)" }
else { MC "W-14" "원격 접속 사용자 그룹: $(@($rdu) -join ', ') - 불필요한 계정 여부 확인 (없으면 양호)" }

# W-15 사용자 개인키 사용 시 암호 입력 (ForceKeyProtection=2)
$fk = Get-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Cryptography' 'ForceKeyProtection'; EvdQ "W-15" "ForceKeyProtection" "$fk"
if ("$fk" -eq '2') { Pass "W-15" "'강력한 키 보호' - 키를 사용할 때마다 암호 입력 (ForceKeyProtection=2)" } else { Fail "W-15" "'강력한 키 보호' 매번 암호 입력 미설정 (ForceKeyProtection=$(if ($null -eq $fk) { '미정의(입력 안 함)' } else { $fk }))" }

# ═══════════════ 2. 서비스 관리 ═══════════════
# W-16 공유 권한 및 사용자 그룹 설정 (일반 공유 Everyone 권한)
$shL = Get-ShareList
$shr = @(@($shL) | Where-Object { $_ -and $_.Type -eq 'Disk' -and $_.Name -notmatch '\$$' })   # 일반 디스크 공유 ($ 로 끝나는 관리 공유 제외)
$ev16 = @(); $unk16 = @(); $evd16 = @()
foreach ($s in $shr) {
    $aces = Get-ShareAceList $s.Name
    $evd16 += "$($s.Name) ($($s.Path))"; $evd16 += (Format-Aces $aces)
    if ($null -eq $aces) { $unk16 += $s.Name; continue }
    if (@($aces | Where-Object { ($_.Sid -eq 'S-1-1-0' -or $_.Account -match 'Everyone|모든 사용자') -and $_.Type -ne 'Deny' }).Count) { $ev16 += $s.Name }
}
EvdQ "W-16" "일반 공유(관리 공유 제외)와 공유 권한 (Get-SmbShareAccess 또는 WMI DACL: 계정 [SID] 권한 허용/거부)" $(if ($null -eq $shL) { '(공유 목록 조회 실패)' } elseif ($evd16.Count) { $evd16 -join "`n" } else { '(일반 공유 없음)' })
if ($null -eq $shL) { Unable "W-16" "공유 목록 조회 실패(Get-SmbShare·Win32_Share 모두 불가) - net share 로 확인" }
elseif ($ev16.Count) { Fail "W-16" "Everyone 권한이 있는 공유: $($ev16 -join ', ')" }
elseif ($unk16.Count) { Unable "W-16" "공유 권한 조회 실패: $($unk16 -join ', ') (Get-SmbShareAccess·Win32_LogicalShareSecuritySetting 불가) - 공유 권한 수동 확인" }
elseif ($shr.Count) { Pass "W-16" "일반 공유 $($shr.Count)개에 Everyone 권한 없음: $(($shr | ForEach-Object { $_.Name }) -join ', ')" } else { Pass "W-16" "일반 공유 디렉터리 없음" }

# W-17 하드디스크 기본 공유 제거 (AutoShareServer=0, C$ 등 없음)
$as = Get-Reg $lmsv 'AutoShareServer'; $dsh = @(@($shL) | Where-Object { $_ -and $_.Name -match '^([A-Z]\$|ADMIN\$)$' } | ForEach-Object { $_.Name })
EvdQ "W-17" "AutoShareServer / 기본 공유 (공유 목록: Get-SmbShare 또는 Win32_Share)" "$as / $($dsh -join ', ')`n$(Format-Shares $shL)"
if ("$as" -ne '0') { Fail "W-17" "기본 공유 자동 생성 (AutoShareServer=$(if ($null -eq $as) { '미정의=1' } else { $as }), 기본 공유: $(if ($null -eq $shL) { '목록 조회 실패' } elseif ($dsh.Count) { $dsh -join ', ' } else { '없음' }))" }
elseif ($null -eq $shL) { Unable "W-17" "공유 목록 조회 실패(Get-SmbShare·Win32_Share 모두 불가), AutoShareServer=0 - net share 로 기본 공유 확인" }
elseif ($dsh.Count) { Fail "W-17" "기본 공유 존재 (AutoShareServer=0, 기본 공유: $($dsh -join ', '))" }
else { Pass "W-17" "기본 공유 제거 (AutoShareServer=0)" }

# W-18 불필요한 서비스 제거 (가이드 '일반적으로 불필요한 서비스')
$svcA = @{ Alerter="Alerter"; ClipSrv="Clipbook"; Browser="Computer Browser"; Messenger="Messenger"; mnmsrvc="NetMeeting Remote Desktop Sharing"; simptcp="Simple TCP/IP Services"
    WZCSVC="Wireless Zero Configuration"; WmdmPmSN="Portable Media Serial Number"; ImapiService="IMAPI CD-Burning COM Service"; ERSvc="Error Reporting Service"; Irmon="Infrared Monitor"
    HidServ="Human Interface Device Access"; upnphost="Universal Plug and Play Device Host"; TrkWks="Distributed Link Tracking Client"; TrkSvr="Distributed Link Tracking Server" }
$svcB = @{ wuauserv="Automatic Updates(패치 관리 서버·수동 패치 시 불필요)"; CryptSvc="Cryptographic Services"; Dhcp="DHCP Client(고정 IP 시 불필요)"; Dnscache="DNS Client"; Spooler="Print Spooler(프린터 미사용 시 불필요)" }
$allK18 = @($svcA.Keys) + @($svcB.Keys)
$w18 = @(Get-CimInstance Win32_Service -EA SilentlyContinue | Where-Object { $allK18 -contains $_.Name } | Sort-Object Name)
EvdQ "W-18" "가이드 대상 서비스 상태 (Win32_Service: 이름 [표시명] 상태 시작유형)" $(if ($w18.Count) { ($w18 | ForEach-Object { "$($_.Name) [$($_.DisplayName)] State=$($_.State) StartMode=$($_.StartMode)" }) -join "`n" } else { '(대상 서비스가 설치되어 있지 않거나 WMI 조회 실패)' })
$runA = @(); foreach ($k in @($svcA.Keys | Sort-Object)) { $s = Get-Service $k -EA SilentlyContinue; if ($s -and "$($s.Status)" -eq 'Running') { $runA += "$($svcA[$k])($k)" } }
$runB = @(); foreach ($k in @($svcB.Keys | Sort-Object)) { $s = Get-Service $k -EA SilentlyContinue; if ($s -and "$($s.Status)" -eq 'Running') { $runB += "$($svcB[$k])" } }
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
EvdQ "W-21" "FTP 서비스 / TCP 21 리슨 / IIS FTP 사이트별 설정 (SSL·익명·IP 제한·루트) / 판정 모드" "서비스: $(if ($ftpSvc) { "$($ftpSvc.Status)/$($ftpSvc.Start)" } else { '미설치' })`nTCP21: $(Format-Listen $l21)`n모드: $ftpMode`n$(Format-FtpSites $ftpSites)"
$ftpC = @("W-21","W-22","W-23","W-24")
switch ($ftpMode) {
    'none'     { foreach ($c in $ftpC) { Pass $c "FTP 서비스 미사용$(if ($ftpSvc) { " ($($ftpSvc.Status))" } else { ' (미설치)' }), 21번 포트 리슨 없음" } }
    'unknown'  { foreach ($c in $ftpC) { Unable $c "21번 포트 리슨 여부 조회 불가(netstat 실패)이고 FTPSVC 미실행 - FTP 사용 여부 수동 확인" } }
    'third'    { foreach ($c in $ftpC) { MC $c "21번 포트 리슨 중(FTPSVC 미실행, 타사 FTP 추정: $((Format-Listen $l21) -replace "`n",' / ')) - FTP 설정 수동 확인" } }
    'iis-fail' { if (Test-Path $ahc) { foreach ($c in $ftpC) { Unable $c "FTP 서비스 구동 중이나 IIS 설정(applicationHost.config) 파싱 실패 - FTP 설정 수동 확인" } } else { foreach ($c in $ftpC) { MC $c "FTP 서비스 구동 중 - applicationHost.config 없음(IIS 6 이하 FTP 이면 MetaBase.xml 수동 확인)" } } }
    'iis-none' { foreach ($c in $ftpC) { MC $c "FTP 서비스 구동 중 - IIS FTP 사이트 미탐지(IIS 6 metabase) 설정 수동 확인" } }
    default {
        $plain = @($ftpSites | Where-Object { "$($_.Ctl)" -notmatch 'SslRequire' -or "$($_.Dat)" -notmatch 'SslRequire' } | ForEach-Object { $_.Name })
        if ($plain.Count) { Fail "W-21" "암호화되지 않은 FTP 허용 사이트(SSL 필요 아님): $($plain -join ', ')" } else { Pass "W-21" "FTP 사이트 모두 SSL 필요(FTPS)" }
        $ev22 = @(); $unk22 = @(); $acl22 = @()
        foreach ($st in @($ftpSites)) {
            if (-not $st.Root) { $unk22 += "$($st.Name)(루트 경로 미확인)"; continue }
            $ac = $null; if (Test-Path $st.Root) { $ac = Get-Acl $st.Root -EA SilentlyContinue }
            if (-not $ac) { $unk22 += "$($st.Name)($($st.Root) 경로 없음/ACL 조회 실패)"; $acl22 += "$($st.Name) $($st.Root): ACL 조회 실패"; continue }
            $acl22 += "$($st.Name) $($st.Root)"
            foreach ($ace in $ac.Access) { $acl22 += "    $($ace.IdentityReference) $($ace.FileSystemRights) $($ace.AccessControlType)"; if ("$($ace.AccessControlType)" -eq 'Allow' -and (Get-AceSid $ace) -eq 'S-1-1-0') { $ev22 += "$($st.Name)($($st.Root))"; break } }
        }
        EvdQ "W-22" "FTP 사이트 홈 디렉터리 ACL" $(if ($acl22.Count) { $acl22 -join "`n" } else { '(대상 없음)' })
        if ($ev22.Count) { Fail "W-22" "FTP 홈 디렉터리 Everyone 권한: $($ev22 -join ', ')" } elseif ($unk22.Count) { Unable "W-22" "FTP 홈 디렉터리 확인 불가: $($unk22 -join ', ')" } else { Pass "W-22" "FTP 홈 디렉터리 Everyone 권한 없음" }
        $an23 = @($ftpSites | Where-Object { "$($_.Anon)" -eq 'true' } | ForEach-Object { $_.Name })
        EvdQ "W-23" "FTP 사이트별 익명 인증 (anonymousAuthentication, 미지정=IIS 기본값 비활성)" ((@($ftpSites) | ForEach-Object { "$($_.Name): Anon=$($_.Anon)" }) -join "`n")
        if ($an23.Count) { Fail "W-23" "FTP 익명 인증 사용: $($an23 -join ', ')" } else { Pass "W-23" "FTP 익명 인증 사용 안 함" }
        $ip24 = @($ftpSites | Where-Object { -not $_.IpRestr } | ForEach-Object { "$($_.Name)[$($_.IpDetail)]" })
        EvdQ "W-24" "FTP 사이트별 IP 제한 (allowUnlisted=false 일 때만 '지정 IP 만 허용')" ((@($ftpSites) | ForEach-Object { "$($_.Name): IpRestr=$($_.IpRestr) [$($_.IpDetail)]" }) -join "`n")
        if ($ip24.Count) { Fail "W-24" "FTP IP 접근 제어(allowUnlisted=false 지정 IP 만 허용) 미설정: $($ip24 -join ', ')" } else { Pass "W-24" "FTP 사이트 IP 접근 제어 설정" }
    }
}

# W-25 DNS Zone Transfer (SecureSecondaries 0=모두 허용) / W-32 DNS 동적 업데이트 (AllowUpdate 0=없음)
# AD 통합 영역은 레지스트리에 없으므로 Get-DnsServerZone → dnscmd → 레지스트리 순으로 조회 (레지스트리만 가능하면 '점검불가')
$zd = $null; if ($dnsOn) { $zd = Get-DnsZoneData }
EvdQ "W-25" "DNS 서비스 / 영역별 SecureSecondaries(0=모든 서버,1=이름 서버 탭,2=지정 서버,3=전송 안 함)·AllowUpdate(0=없음,1=비보안 포함,2=보안만)" "$(if ($dnsSvc) { $dnsSvc.Status } else { '미설치' })`n$(if ($zd) { Format-DnsZones $zd } else { '(DNS 서비스 미사용 - 영역 조회 안 함)' })"
if (-not $dnsOn) { Pass "W-25" "DNS 서비스 미사용"; Pass "W-32" "DNS 서비스 미사용" }
else {
    $zones = @($zd.Zones)
    $x25 = @($zones | Where-Object { "$($_.Xfer)" -eq '0' } | ForEach-Object { $_.Name })
    $zn25 = ($zones | ForEach-Object { $_.Name }) -join ', '
    if ($x25.Count) { Fail "W-25" "영역 전송을 모든 서버에 허용: $($x25 -join ', ')" }
    elseif (-not $zd.Complete) { Unable "W-25" "DNS 영역 목록을 완전하게 조회하지 못함($($zd.Method); $("$($zd.Note)".Trim())) - AD 통합 영역 포함 DNS 관리자에서 영역 전송 설정 확인 (조회된 영역: $zn25)" }
    else { Pass "W-25" "영역 전송 허용 안 함 또는 특정 서버로 제한 ($($zones.Count)개 영역: $zn25)" }
    $pz32 = @($zones | Where-Object { "$($_.Type)" -ne 'Secondary' })
    $u32 = @($pz32 | Where-Object { "$($_.Upd)" -eq '1' -or "$($_.Upd)" -eq '2' } | ForEach-Object { "$($_.Name)($($_.Upd))" })
    $unk32 = @($pz32 | Where-Object { "$($_.Upd)" -eq '' } | ForEach-Object { $_.Name })
    if ($u32.Count) { Fail "W-32" "동적 업데이트 설정 영역(1=비보안·보안, 2=보안만): $($u32 -join ', ') - 가이드: '없음'" }
    elseif (-not $zd.Complete) { Unable "W-32" "DNS 영역 목록을 완전하게 조회하지 못함($($zd.Method); $("$($zd.Note)".Trim())) - AD 통합 영역 포함 DNS 관리자에서 동적 업데이트 설정 확인" }
    elseif ($unk32.Count) { Unable "W-32" "동적 업데이트 값을 읽지 못한 영역: $($unk32 -join ', ')" }
    else { Pass "W-32" "모든 영역 동적 업데이트 없음" }
}

# W-26 RDS(Remote Data Services) 제거 - Windows 2008 이상이면 양호
EvdQ "W-26" "OS 빌드 (6001 이상=Windows 2008 이상)" "Build $build"
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
$vcM = @($vc | ForEach-Object { $n = "$_"; $mk = if ($n.Length -gt 2) { $n.Substring(0,2) + ('*' * ($n.Length - 2)) } else { '**' }; "$mk($($n.Length)자)" })   # community 는 앞 2자만 표시
EvdQ "W-29" "SNMP 서비스 / 커뮤니티 수 / 허용 관리자" "$(if ($snmpSvc) { $snmpSvc.Status } else { '미설치' }) / $($vc.Count)개 / $($pm -join ', ')"
EvdQ "W-30" "ValidCommunities (이름 마스킹: 앞 2자만 표시 / public·private 해당 여부)" $(if ($vc.Count) { "$($vcM -join ', ') / public·private: $(@($vc | Where-Object { $_ -match '^(public|private)$' }).Count)개" } else { '(등록된 community 없음 또는 SNMP 미설치)' })
EvdQ "W-31" "PermittedManagers (SNMP 패킷 허용 호스트)" $(if ($pm.Count) { $pm -join "`n" } else { '(미설정)' })
if (-not $snmpOn) { foreach ($c in "W-29","W-30","W-31") { Pass $c "SNMP 서비스 미사용" } }
else {
    if ($vc.Count) { MC "W-29" "SNMP 서비스 사용(Community String $($vc.Count)개 설정) - 업무상 필요 여부 확인 (필요 시 양호)" } else { Fail "W-29" "SNMP 서비스 사용 중이나 Community String 미설정" }
    $wk = @($vc | Where-Object { $_ -match '^(public|private)$' }); if ($wk.Count) { Fail "W-30" "기본 Community String 사용: $($wk -join ', ')" } else { Pass "W-30" "Community String 이 public·private 아님 ($($vc.Count)개, 값 비공개)" }
    if ($pm.Count) { Pass "W-31" "특정 호스트로부터만 SNMP 패킷 수신: $($pm -join ', ')" } else { Fail "W-31" "모든 호스트로부터 SNMP 패킷 받아들이기" }
}

# W-33 HTTP/FTP/SMTP 배너 차단
$b33 = @(); $o33 = @(); $u33 = @(); $m33 = @(); $dsh2 = $null; $rsh = $null
if ($iisOn) {
    $dsh2 = Get-Reg 'HKLM:\SYSTEM\CurrentControlSet\Services\HTTP\Parameters' 'DisableServerHeader'
    $rsh = (Read-AllText "$env:windir\System32\inetsrv\config\applicationHost.config") -match 'removeServerHeader="true"'
    if ("$dsh2" -eq '2' -or $rsh) { $o33 += 'HTTP' } else { $b33 += "HTTP(Server 헤더 노출: DisableServerHeader=$dsh2, removeServerHeader 미설정)" }
}
if ($ftpOn) {
    if ($ftpMode -eq 'iis') { $nb33 = @($ftpSites | Where-Object { "$($_.Banner)" -ne 'true' } | ForEach-Object { $_.Name }); if ($nb33.Count) { $b33 += "FTP 기본 배너 노출: $($nb33 -join ', ')" } else { $o33 += 'FTP' } }
    elseif ($ftpMode -eq 'iis-fail' -and (Test-Path $ahc)) { $u33 += 'FTP(IIS 설정 파싱 실패)' }
    else { $m33 += "FTP(모드 $ftpMode - 타사/IIS 6 FTP 배너 수동 확인)" }
}
$smtp = Get-SvcState 'SMTPSVC'; if ($smtp -and "$($smtp.Status)" -match 'Running') { $b33 += 'SMTP(IIS SMTP 배너 - ConnectResponse 설정 확인)' }
EvdQ "W-33" "배너 점검 대상 / HTTP DisableServerHeader·removeServerHeader / FTP 사이트 배너(suppressDefaultBanner)" "IIS=$iisOn FTP=$ftpOn(모드 $ftpMode) SMTP=$(if ($smtp) { $smtp.Status } else { '미설치' })`nDisableServerHeader=$dsh2 removeServerHeader=$rsh`nFTP 사이트: $(@($ftpSites | ForEach-Object { "$($_.Name) Banner=$($_.Banner)" }) -join '; ')"
if ($b33.Count) { Fail "W-33" "배너 정보 노출: $($b33 -join ' / ')" }
elseif ($u33.Count) { Unable "W-33" "배너 설정 확인 불가: $($u33 -join ' / ')" }
elseif ($m33.Count) { MC "W-33" "$($m33 -join ' / ')$(if ($o33.Count) { " (배너 차단 확인: $($o33 -join ', '))" })" }
elseif ($o33.Count) { Pass "W-33" "배너 차단: $($o33 -join ', ')" } else { Pass "W-33" "HTTP·FTP·SMTP 서비스 미사용" }

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
$tk37 = [bool](Get-Command Get-ScheduledTask -EA SilentlyContinue)
$tk = @(); if ($tk37) { $tk = @(Get-ScheduledTask -EA SilentlyContinue | Where-Object { $_.TaskPath -notmatch '^\\Microsoft\\' -and $_.State -ne 'Disabled' }) }
if ($tk37) { EvdQ "W-37" "Microsoft 외 활성 예약 작업(작업 경로·이름 => 실행 명령, 명령행의 password 값은 마스킹)" (($tk | ForEach-Object { Mask-Secret "$($_.TaskPath)$($_.TaskName) => $(@($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join ' ; ')" }) -join "`n") }
else { Evd "W-37" "schtasks /query /fo LIST /v" }
if (-not $tk37) { MC "W-37" "Get-ScheduledTask 없음(PS 2.0~2008 R2) - schtasks /query /fo LIST /v 증적으로 Microsoft 외 예약 작업·불필요 명령 확인" }
elseif ($tk.Count) { MC "W-37" "Microsoft 외 예약 작업 $($tk.Count)개: $(($tk | Select-Object -First 8 | ForEach-Object { $_.TaskName }) -join ', ')$(if ($tk.Count -gt 8) { " 외 $($tk.Count - 8)건(증적 참조)" }) - 불필요·의심 명령 여부 확인 및 주기 점검 절차 확인" }
else { MC "W-37" "Microsoft 외 예약 작업 없음 - 예약 작업 주기 점검 절차 수립 여부 확인" }

# ═══════════════ 3. 패치 관리 ═══════════════
# W-38 주기적 보안 패치
$hf38 = $null; $hfe = ''
try { $hf38 = @(Get-HotFix -EA Stop) } catch { $hfe = $_.Exception.Message }
$hf = $hf38 | Where-Object { $_.InstalledOn } | Sort-Object InstalledOn -Descending | Select-Object -First 1
EvdQ "W-38" "설치된 HOT FIX 전체 (HotFixID / 설치일 / 설명, 최신순)" $(if ($hf38.Count) { (@($hf38 | Sort-Object InstalledOn -Descending) | ForEach-Object { "$($_.HotFixID) / $($_.InstalledOn) / $($_.Description)" }) -join "`n" } else { "(조회 결과 없음) $hfe" })
if ($hfe -and (Cnt $hf38) -eq 0) { Unable "W-38" "HOT FIX 조회 실패(Get-HotFix/WMI QFE): $hfe - Windows 업데이트 기록 확인" }
elseif (-not $hf) { MC "W-38" "HOT FIX 설치 이력 없음 또는 설치일 미확인(총 $(Cnt $hf38)건) - Windows 업데이트 기록 확인" }
else { $age = ((Get-Date) - [datetime]$hf.InstalledOn).Days
    if ($age -gt 90) { Fail "W-38" "최근 HOT FIX $($hf.HotFixID) 설치 후 ${age}일 경과 - 주기적 패치 미적용" } else { MC "W-38" "최근 HOT FIX $($hf.HotFixID) (${age}일 전) - 패치 절차 수립·주기적 확인 여부 인터뷰" } }

# W-39 백신 프로그램 업데이트 / W-45 백신 프로그램 설치
# 백신 탐지: 실행 중 서비스 + 설치 프로그램 목록 + SecurityCenter2 + Defender 상태 (국내 백신 키워드 포함 - SRV-119/129 와 동일). 미탐지는 취약이 아니라 수동확인
$avKw  = '(?i)(microsoft|windows) defender|\bV3\b|ahnlab|alyac|virobot|hauri|sophos|symantec|endpoint protection|mcafee|trellix|trend ?micro|apex ?one|kaspersky|eset|bitdefender|avast|avira|cylance|crowdstrike|falcon|sentinel ?one|antivirus|anti-?malware|백신'
$mp = $null; if (Get-Command Get-MpComputerStatus -EA SilentlyContinue) { try { $mp = Get-MpComputerStatus -EA Stop } catch {} }
$avSvcO = @(Get-Service -EA SilentlyContinue | Where-Object { "$($_.Status)" -eq 'Running' -and ($_.Name -match '^(WinDefend|WdNisSvc)$' -or ($_.DisplayName -match $avKw -and $_.DisplayName -notmatch '(?i)firewall|방화벽')) })
$avSvc = @($avSvcO | ForEach-Object { $_.DisplayName })
$avUn  = @(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' -EA SilentlyContinue | Where-Object { $_.DisplayName -match $avKw } | ForEach-Object { "$($_.DisplayName) $($_.DisplayVersion)" })
$avSc  = @(Get-CimInstance -Namespace "root/SecurityCenter2" -ClassName AntiVirusProduct -EA SilentlyContinue)
$defTxt = $(if ($mp) { "AMServiceEnabled=$($mp.AMServiceEnabled) AntivirusEnabled=$($mp.AntivirusEnabled) RealTime=$($mp.RealTimeProtectionEnabled) SignatureVersion=$($mp.AntivirusSignatureVersion) Sig=$($mp.AntivirusSignatureLastUpdated) Engine=$($mp.AMEngineVersion)" } else { 'Get-MpComputerStatus 없음/실패' })
EvdQ "W-45" "Defender / 실행 중 백신 서비스 / 설치 목록(백신 키워드 일치) / SecurityCenter2" "$defTxt`n서비스: $($avSvc -join ', ')`n설치 목록: $($avUn -join ', ')`nSecurityCenter2: $(($avSc | ForEach-Object { $_.displayName }) -join ', ')"
EvdQ "W-39" "백신 엔진·패턴 갱신 근거 (Defender 서명 갱신 시각 / 타사 백신은 콘솔 확인)" "$defTxt`n실행 중 백신 서비스: $($avSvc -join ', ')"
if (($mp -and $mp.AMServiceEnabled) -or $avSvc.Count -or $avSc.Count -or $avUn.Count) {
    $names45 = @($avSvc) + @($avUn | Select-Object -First 3) + @($avSc | ForEach-Object { $_.displayName }) + @(if ($mp -and $mp.AMServiceEnabled -and -not ($avSvc -match 'Defender')) { 'Microsoft Defender' })
    Pass "W-45" "백신 설치: $((@($names45 | Where-Object { $_ } | Select-Object -Unique)) -join ', ')"
} else { MC "W-45" "백신 서비스·설치 목록 미탐지 - 가이드 외 제품이거나 미설치일 수 있어 백신 설치 여부 수동 확인" }
if ($mp -and $mp.AMServiceEnabled -and $mp.AntivirusSignatureLastUpdated) { $sa = ((Get-Date) - $mp.AntivirusSignatureLastUpdated).Days
    if ($sa -le 7) { Pass "W-39" "Microsoft Defender 엔진·패턴 최신 (${sa}일 전 갱신)" } else { Fail "W-39" "Microsoft Defender 서명 ${sa}일 경과 - 망 격리 환경이면 업데이트 절차 확인" } }
elseif ($avSvc.Count -or $avSc.Count -or $avUn.Count) { MC "W-39" "백신($((@($avSvc) + @($avUn | Select-Object -First 3)) -join ', ')) 최신 엔진 업데이트 여부 백신 콘솔에서 확인 (망 격리 시 업데이트 절차)" }
else { MC "W-39" "백신 프로그램 미탐지 - 업데이트 여부 수동 확인" }

# ═══════════════ 4. 로그 관리 ═══════════════
# W-40 정책에 따른 시스템 로깅 (감사 정책 권고 기준)  secedit 값: 0 없음 / 1 성공 / 2 실패 / 3 성공·실패
if (-not $secOK) { Unable "W-40" $secMsg } else {
    $need = @{ AuditAccountManage=@(2,'계정 관리: 실패'); AuditAccountLogon=@(3,'계정 로그온 이벤트: 성공/실패'); AuditPrivilegeUse=@(3,'권한 사용: 성공/실패')
                        AuditDSAccess=@(2,'디렉터리 서비스 액세스: 실패'); AuditLogonEvents=@(3,'로그온 이벤트: 성공/실패'); AuditPolicyChange=@(3,'정책 변경: 성공/실패') }
    $miss = @(); $vals = @()
    foreach ($k in @('AuditAccountManage','AuditAccountLogon','AuditPrivilegeUse','AuditDSAccess','AuditLogonEvents','AuditPolicyChange')) { $v = Int0 (Get-SecPol $k); $vals += "$k=$v"; if ($null -eq $v -or (($v -band $need[$k][0]) -ne $need[$k][0])) { $miss += $need[$k][1] } }
    EvdQ "W-40" "secedit [Event Audit] (고급 감사 정책은 auditpol /get /category:* 증적 참고)" ($vals -join ', ')
    Evd "W-40" "auditpol /get /category:* 2>`$null"
    if ($miss.Count) { Fail "W-40" "감사 정책 권고 기준 미충족: $($miss -join ', ') (고급 감사 정책 사용 시 auditpol 증적으로 재확인)" } else { Pass "W-40" "감사 정책 권고 기준 충족" }
}

# W-41 NTP 및 시각 동기화
$wt = Get-SvcState 'W32Time'; $ty = Get-Reg 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters' 'Type'; $ns = Get-Reg 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters' 'NtpServer'
$wsrc = ''; try { $wsrc = ((w32tm /query /source 2>&1) | Out-String).Trim() } catch {}
EvdQ "W-41" "W32Time / Type / NtpServer / 실제 시간 원본(w32tm /query /source)" "$(if ($wt) { $wt.Status }) / $ty / $ns / $wsrc"
$cmos41 = ($wsrc -match 'Local CMOS Clock|Free-running|로컬 CMOS|자유 실행')
if ($wt -and "$($wt.Status)" -match 'Running' -and "$ty" -match 'NTP|NT5DS|AllSync') {
    if ($cmos41) { Fail "W-41" "W32Time 구동·Type=$ty 이나 실제 시간 원본이 로컬 시계($wsrc) - NTP 동기화 안 됨" }
    else { Pass "W-41" "시각 동기화 사용 (Type=$ty$(if ("$ty" -match 'NTP') { ", 서버 $ns" }), 시간 원본: $(if ($wsrc) { $wsrc } else { '확인 불가' }))" }
} else { Fail "W-41" "시각 동기화 미설정 또는 W32Time 미구동 (Type=$ty, 상태 $(if ($wt) { $wt.Status } else { '없음' }))" }

# W-42 이벤트 로그 관리 (최대 크기 10,240KB 이상)
$lg = @(); foreach ($n42 in 'Application','Security','System') { $mb42 = Get-LogMaxBytes $n42; $md42 = ''; try { $md42 = "$((Get-WinEvent -ListLog $n42 -EA Stop).LogMode)" } catch {}; $lg += New-Object PSObject -Property @{ LogName=$n42; Max=$mb42; Mode=$md42 } }
EvdQ "W-42" "로그 / 최대 크기(KB) / 보존 모드(LogMode: Circular=덮어쓰기, Retain, AutoBackup)" (($lg | ForEach-Object { "$($_.LogName) / $(if ($null -ne $_.Max) { [int64]($_.Max/1KB) } else { '조회 실패' }) / $($_.Mode)" }) -join "`n")
$unk42 = @($lg | Where-Object { $null -eq $_.Max } | ForEach-Object { $_.LogName })
$sm42 = @($lg | Where-Object { $null -ne $_.Max -and $_.Max -lt 10MB } | ForEach-Object { "$($_.LogName)($([int64]($_.Max/1KB))KB)" })
if ($sm42.Count) { Fail "W-42" "최대 로그 크기 10,240KB 미만: $($sm42 -join ', ')" } elseif ($unk42.Count) { Unable "W-42" "이벤트 로그 최대 크기 조회 실패: $($unk42 -join ', ') (Get-WinEvent·wevtutil 불가) - 이벤트 뷰어에서 확인" } else { Pass "W-42" "Application·Security·System 최대 로그 크기 10,240KB 이상, 보존 모드: $(($lg | ForEach-Object { "$($_.LogName)=$($_.Mode)" }) -join ', ') (2008 이상은 덮어쓰기 기간 지정 불가 - 가이드 참고)" }

# W-43 이벤트 로그 파일 접근 통제 (Everyone 권한 없음)
$ld43 = "$env:SystemRoot\System32\winevt\Logs"; $acl43 = Get-Acl $ld43 -EA SilentlyContinue
EvdQ "W-43" "$ld43 ACL" "$(if ($acl43) { ($acl43.Access | ForEach-Object { "$($_.IdentityReference) $($_.FileSystemRights) $($_.AccessControlType)" }) -join "`n" } else { '조회 불가' })"
if (-not $acl43) { Unable "W-43" "로그 디렉터리 권한 조회 불가($(if ($script:IsAdmin -eq $false) { '관리자 권한 아님' } else { 'Get-Acl 오류' })) - $ld43 보안 탭 확인" } elseif (@($acl43.Access | Where-Object { (Get-AceSid $_) -eq 'S-1-1-0' -and "$($_.AccessControlType)" -eq 'Allow' }).Count) { Fail "W-43" "로그 디렉터리에 Everyone 권한: $ld43" } else { Pass "W-43" "로그 디렉터리 Everyone 권한 없음" }

# ═══════════════ 5. 보안 관리 ═══════════════
# W-44 원격으로 액세스할 수 있는 레지스트리 경로 (Remote Registry 중지)
$rr = Get-SvcState 'RemoteRegistry'; EvdQ "W-44" "RemoteRegistry" "$(if ($rr) { "$($rr.Status)/$($rr.Start)" } else { '없음' })"
if ($rr -and "$($rr.Status)" -match 'Running') { Fail "W-44" "Remote Registry 서비스 사용 중" } else { Pass "W-44" "Remote Registry 서비스 중지$(if ($rr) { " ($($rr.Start))" })" }

# W-46 SAM 파일 접근 통제 (Administrators·SYSTEM 만)
$sam = "$env:SystemRoot\System32\config\SAM"; $acl46 = Get-Acl $sam -EA SilentlyContinue
EvdQ "W-46" "$sam ACL" "$(if ($acl46) { ($acl46.Access | ForEach-Object { "$($_.IdentityReference) $($_.FileSystemRights)" }) -join "`n" } else { '조회 불가' })"
if (-not $acl46) { Unable "W-46" "SAM 파일 권한 조회 불가($(if ($script:IsAdmin -eq $false) { '관리자 권한 아님' } else { 'Get-Acl 오류' })) - icacls $sam 확인" }
else { $ext46 = @($acl46.Access | Where-Object { "$($_.AccessControlType)" -eq 'Allow' -and @('S-1-5-18','S-1-5-32-544') -notcontains (Get-AceSid $_) } | ForEach-Object { "$($_.IdentityReference)" })
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
if (-not $secOK) { Unable "W-49" $secMsg } else {
    $rs = Get-SecPol 'SeRemoteShutdownPrivilege'; EvdQ "W-49" "SeRemoteShutdownPrivilege" "$rs => $((SidNames $rs) -join ', ')"
    $ext49 = @(($rs -split ',') | Where-Object { $_ -and $_.Trim() -ne '*S-1-5-32-544' } | ForEach-Object { Resolve-SecPolEntry $_ })
    if ($null -eq $rs) { Unable "W-49" "SeRemoteShutdownPrivilege 값 조회 실패(secedit 내보내기에 항목 없음)" } elseif ($ext49.Count) { Fail "W-49" "'원격 시스템에서 강제로 시스템 종료'에 Administrators 외: $($ext49 -join ', ')" } else { Pass "W-49" "'원격 시스템에서 강제로 시스템 종료': Administrators 만" }
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
$adcNever = ((-not $adcDef) -and ([int64]$adc -lt 0 -or [int64]$adc -ge 99999))   # 0xffffffff(DWORD)는 -1 로 읽힘 = 무제한
if ($adcNever) { $adcTxt = '무제한(0xffffffff)' } else { $adcTxt = "${adc}분" }
if ("$efl" -ne '0' -and -not $adcNever -and [int64]$adc -le 15) { Pass "W-56" "로그온 시간 만료 시 연결 끊기 사용$(if ($null -eq $efl) { '(기본값)' }), 유휴 ${adc}분$(if ($adcDef) { '(기본값)' })" } else { Fail "W-56" "SMB 세션 중단 설정 미흡 (EnableForcedLogOff=$efl, AutoDisconnect=$adcTxt; 기준 사용 + 15분 이하)" }

# W-57 로그온 시 경고 메시지
$lc57 = Get-Reg $pol 'LegalNoticeCaption'; $lt57 = Get-Reg $pol 'LegalNoticeText'
$wl57 = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'   # 구버전 경로 보조
if (-not "$lc57".Trim()) { $lc57 = Get-Reg $wl57 'LegalNoticeCaption' }; if (-not "$lt57".Trim()) { $lt57 = Get-Reg $wl57 'LegalNoticeText' }
if ($lc57 -is [array]) { $lc57 = $lc57 -join ' ' }; if ($lt57 -is [array]) { $lt57 = $lt57 -join ' ' }
EvdQ "W-57" "LegalNoticeCaption / LegalNoticeText (Policies\System 우선 → Winlogon)" "$lc57 / $lt57"
if ("$lc57".Trim() -and "$lt57".Trim()) { Pass "W-57" "로그온 경고 메시지 제목·내용 설정" } else { Fail "W-57" "로그온 경고 메시지 $(if (-not "$lc57".Trim()) { '제목 ' })$(if (-not "$lt57".Trim()) { '내용 ' })미설정" }

# W-58 사용자별 홈 디렉터리 권한 (Everyone 없음)
$ev58 = @(); $unk58 = @(); $acl58 = @()
$hd58 = @(Get-ChildItem "$env:SystemDrive\Users" -EA SilentlyContinue | Where-Object { $_.PSIsContainer -and $_.Name -notmatch '^(All Users|Default|Default User|Public)$' })
foreach ($d in $hd58) {
    $a = Get-Acl $d.FullName -EA SilentlyContinue
    if (-not $a) { $unk58 += $d.Name; $acl58 += "$($d.FullName): ACL 조회 실패"; continue }
    $acl58 += $d.FullName
    foreach ($ace in $a.Access) { $acl58 += "    $($ace.IdentityReference) $($ace.FileSystemRights) $($ace.AccessControlType)" }
    if (@($a.Access | Where-Object { (Get-AceSid $_) -eq 'S-1-1-0' -and "$($_.AccessControlType)" -eq 'Allow' }).Count) { ${ev58} += $d.Name }
}
EvdQ "W-58" "홈 디렉터리별 ACL ($env:SystemDrive\Users, Public 등 제외) / Everyone 권한 보유 디렉터리" "$(if ($acl58.Count) { $acl58 -join "`n" } else { '(홈 디렉터리 없음)' })`nEveryone 보유: $($ev58 -join ', ')"
if ($ev58.Count) { Fail "W-58" "홈 디렉터리 Everyone 권한: $($ev58 -join ', ')" }
elseif ($hd58.Count -eq 0) { Unable "W-58" "홈 디렉터리 목록 조회 실패($env:SystemDrive\Users) - 수동 확인" }
elseif ($unk58.Count) { Unable "W-58" "홈 디렉터리 ACL 조회 실패: $($unk58 -join ', ') (조회된 $($hd58.Count - $unk58.Count)개는 Everyone 권한 없음)" }
else { Pass "W-58" "사용자 홈 디렉터리 Everyone 권한 없음" }

# W-59 LAN Manager 인증 수준 (NTLMv2 응답만 보냄 = 3 이상)
$lm = Get-Reg $lsa 'LmCompatibilityLevel'; EvdQ "W-59" "LmCompatibilityLevel" "$lm"
if ($null -eq $lm) { Pass "W-59" "LAN Manager 인증 수준 미정의 - Windows 2008 R2 이상 기본값 'NTLMv2 응답만 보냄'(3)" } elseif ([int]$lm -ge 3) { Pass "W-59" "LAN Manager 인증 수준 $lm (NTLMv2 응답만 보냄 이상)" } else { Fail "W-59" "LAN Manager 인증 수준 $lm (LM·NTLM 응답 허용)" }

# W-60 보안 채널 데이터 디지털 암호화 또는 서명 (3개 정책 사용)
$nl = 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'
$v60 = @{ RequireSignOrSeal=(Get-Reg $nl 'RequireSignOrSeal'); SealSecureChannel=(Get-Reg $nl 'SealSecureChannel'); SignSecureChannel=(Get-Reg $nl 'SignSecureChannel') }
$v60Keys = @('RequireSignOrSeal','SealSecureChannel','SignSecureChannel')   # PS 2.0 에는 [ordered] 가 없어 키 순서를 배열로 고정
EvdQ "W-60" "Netlogon 보안 채널 정책" (($v60Keys | ForEach-Object { "$_=$($v60[$_])" }) -join ', ')
$off60 = @($v60Keys | Where-Object { "$($v60[$_])" -eq '0' })
if ($off60.Count) { Fail "W-60" "보안 채널 정책 사용 안 함: $($off60 -join ', ')" } else { Pass "W-60" "보안 채널 데이터 암호화·서명 3개 정책 사용 (미정의는 기본값 사용)" }

# W-61 파일 및 디렉토리 보호 (NTFS)
$vol = @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' -EA SilentlyContinue)
EvdQ "W-61" "로컬 디스크 파일 시스템 (Win32_LogicalDisk: 드라이브 / 파일 시스템, 빈 값=RAW·미포맷)" (($vol | ForEach-Object { "$($_.DeviceID) $(if ("$($_.FileSystem)") { $_.FileSystem } else { '(빈 값/RAW)' })" }) -join "`n")
$fat = @($vol | Where-Object { $_.FileSystem -match 'FAT' } | ForEach-Object { "$($_.DeviceID)$($_.FileSystem)" })
$raw61 = @($vol | Where-Object { "$($_.FileSystem)" -notmatch '^(NTFS|ReFS|CSVFS|FAT|FAT32|exFAT)$' } | ForEach-Object { "$($_.DeviceID)($(if ("$($_.FileSystem)") { $_.FileSystem } else { '빈 값/RAW' }))" })
if (-not $vol.Count) { Unable "W-61" "로컬 디스크 조회 실패(Win32_LogicalDisk) - 디스크 관리에서 확인" } elseif ($fat.Count) { Fail "W-61" "FAT 파일 시스템 사용: $($fat -join ', ')" } elseif ($raw61.Count) { MC "W-61" "파일 시스템 확인 필요(RAW·미확인): $($raw61 -join ', ')" } else { Pass "W-61" "로컬 디스크 NTFS/ReFS: $(($vol | ForEach-Object { "$($_.DeviceID)$($_.FileSystem)" }) -join ', ')" }

# W-62 시작 프로그램 목록 분석
$st62 = @(Get-StartupEntries)   # Run 키·시작 폴더 (명령행의 password=... 값은 마스킹)
EvdQ "W-62" "시작 프로그램 (Run/RunOnce 키·시작프로그램 폴더, 명령행의 password 값은 마스킹)" ($st62 -join "`n")
MC "W-62" "시작 프로그램 $($st62.Count)개$(if ($st62.Count) { ": $((@($st62 | Select-Object -First 6 | ForEach-Object { ($_ -replace '^\[[^\]]*\]\s*','' -split ' = ',2)[0] })) -join ', ')$(if ($st62.Count -gt 6) { " 외 $($st62.Count - 6)건(증적 참조)" })" }) - 정기 검사·불필요 항목 비활성화 여부 확인"

# W-63 도메인 컨트롤러-사용자의 시간 동기화 (Kerberos 최대 허용 오차 5분 이하)
$cs = Int0 (Get-SecPol 'MaxClockSkew'); EvdQ "W-63" "Kerberos MaxClockSkew (secedit 내보내기 성공 여부 $secOK)" "$cs"
if (-not $secOK) { Unable "W-63" $secMsg }
elseif ($null -eq $cs) { Pass "W-63" "컴퓨터 시계 동기화 최대 허용 오차 미정의 - 기본값 5분" } elseif ($cs -le 5) { Pass "W-63" "컴퓨터 시계 동기화 최대 허용 오차 ${cs}분" } else { Fail "W-63" "컴퓨터 시계 동기화 최대 허용 오차 ${cs}분 (5분 초과)" }

# W-64 윈도우 방화벽
$fwp = Get-FwProfiles
$fwRules = Get-FwInboundRules
Evd "W-64" "netsh advfirewall show allprofiles"
EvdQ "W-64" "방화벽 프로필 (Enabled / 기본 인바운드 / 수집원)" $(if ($null -eq $fwp) { '(Get-NetFirewallProfile·레지스트리 모두 조회 실패)' } else { (@($fwp) | ForEach-Object { "$($_.Name): Enabled=$($_.Enabled) 기본인바운드=$($_.Inbound) [$($_.Src)]" }) -join "`n" })
EvdQ "W-64" "클라우드 보안그룹 / 활성 인바운드 허용 규칙(이름 | 프로토콜 | 로컬포트 | 원격주소 | 프로그램 | 전면허용 여부)" "클라우드: $($script:CloudLine)`n$(if ($null -eq $fwRules) { '(FirewallRules 레지스트리 없음)' } else { (@($fwRules) | ForEach-Object { "$($_.Name) | proto=$($_.Proto) | LPort=$($_.LPort) | $($_.RA) | $($_.App) | Any=$($_.Any)" }) -join "`n" })"
if ($null -eq $fwp) { Unable "W-64" "방화벽 프로필 조회 불가(Get-NetFirewallProfile·레지스트리 모두 실패) - netsh advfirewall show allprofiles 확인$(if ($script:CloudSG) { " (클라우드 보안그룹: $($script:CloudSG))" })" }
else {
    $off = @($fwp | Where-Object { -not $_.Enabled } | ForEach-Object { "$($_.Name)" })
    if ($script:CloudKind) { MC "W-64" "클라우드($($script:CloudKind)) 환경 - 보안그룹/방화벽 규칙(ID: $(if ($script:CloudSG) { $script:CloudSG } else { '확인 불가' }))과 Windows 방화벽 병행 수동 확인. Windows 방화벽: $(if ($off.Count) { "사용 안 함: $($off -join ',')" } else { '전체 프로필 사용' })" }
    elseif ($off.Count) { Fail "W-64" "Windows 방화벽 사용 안 함: $($off -join ', ')" } else { Pass "W-64" "Windows 방화벽 전체 프로필 사용" }
}

# ── 요약 ──
Remove-Item $seceditFile -Force -EA SilentlyContinue
$tot = $script:cntPass + $script:cntFail + $script:cntMC + $script:cntUnable + $script:cntNA
Out-Res "# ================================================================"
Out-Res "# 점검 요약 - 주요정보통신기반시설 상세가이드(2026) Windows 서버 W-01~W-64"
Out-Res "#   총 $tot / 양호: $($script:cntPass) / 취약: $($script:cntFail) / 수동확인: $($script:cntMC) / 점검불가: $($script:cntUnable) / N-A: $($script:cntNA)$(if ($script:cntUnable -gt 0 -and $script:IsAdmin -eq $false) { '  (관리자 권한 아님 - 관리자 권한으로 재실행 권장)' })"
Out-Res "# 증적 파일: $script:EVD"
Out-Res "# 결과 파일: $script:OUT"
Out-Res "# ================================================================"
