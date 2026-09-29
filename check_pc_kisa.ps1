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
#   Windows 10 / 11 (가이드 점검 대상), PowerShell 5.1
#
# [실행 방법]
#   run_pc_kisa.bat 더블클릭 (관리자 권한 권장 — 보안 정책·BitLocker·bcdedit 조회)
#   또는 powershell -ExecutionPolicy Bypass -File check_pc_kisa.ps1 > PC_KISA_%COMPUTERNAME%.txt
#
# [산출물]
#   1) 표준출력: PC-항목코드|결과|근거설명 (양호/취약/수동확인/N-A)
#   2) 증적 파일: 스크립트와 같은 폴더 <호스트명>_pc_kisa_evidence.txt
#
# ================================================================
$ErrorActionPreference = "SilentlyContinue"
$ProgressPreference    = "SilentlyContinue"

$hn     = $env:COMPUTERNAME
$os     = Get-CimInstance Win32_OperatingSystem -EA SilentlyContinue
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
Write-Output "# ============================================================"

$seceditFile = "$env:TEMP\pc_kisa_secpol_$PID.cfg"
$null = secedit /export /cfg $seceditFile /quiet 2>$null
function Get-SecPol([string]$Key) {
    if (-not (Test-Path $seceditFile)) { return $null }
    $line = Get-Content $seceditFile -EA SilentlyContinue | Where-Object { $_ -match "^\s*$([regex]::Escape($Key))\s*=" } | Select-Object -First 1
    if ($line) { return ($line -split "=",2)[1].Trim() }; return $null
}
function Get-Reg([string]$Path,[string]$Name) { try { return (Get-ItemProperty -Path $Path -Name $Name -EA Stop).$Name } catch { return $null } }
function Get-NetAccounts([string]$pattern) {
    $l = (net accounts 2>$null) | Where-Object { $_ -match $pattern } | Select-Object -First 1
    if ($l) { return ($l -split ":\s*",2)[1].Trim() }; return $null
}

$script:cnt = @{ "양호"=0; "취약"=0; "수동확인"=0; "N-A"=0 }
$script:ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$script:EVD = "$script:ScriptDir\${hn}_pc_kisa_evidence.txt"
@("# ================================================================", "# PC 증적 파일 (주요정보통신기반시설 상세가이드 2026)",
  "# 대상: $hn / $osName (Build $build)", "# 생성: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')",
  "# ================================================================") | Out-File $script:EVD -Encoding UTF8
function Emit([string]$code,[string]$res,[string]$msg) {
    $script:cnt[$res]++
    Write-Output "$code|$res|$msg"; "[판정] $code|$res|$msg`n" | Add-Content $script:EVD -Encoding UTF8
}
function Pass([string]$c,[string]$m) { Emit $c "양호" $m }
function Fail([string]$c,[string]$m) { Emit $c "취약" $m }
function MC([string]$c,[string]$m)   { Emit $c "수동확인" $m }
function NA([string]$c,[string]$m)   { Emit $c "N-A" $m }
function Evd([string]$item,[string]$cmd) {
    "[$item] $(Get-Date -Format 'HH:mm:ss') PS> $cmd" | Add-Content $script:EVD -Encoding UTF8
    try { (Invoke-Expression $cmd 2>&1 | Out-String) | Add-Content $script:EVD -Encoding UTF8 } catch { $_.Exception.Message | Add-Content $script:EVD -Encoding UTF8 }
    "" | Add-Content $script:EVD -Encoding UTF8
}
function EvdQ([string]$item,[string]$desc,[string]$val) { "[$item] $(Get-Date -Format 'HH:mm:ss') $desc`n$val`n" | Add-Content $script:EVD -Encoding UTF8 }

# ── PC-01 비밀번호의 주기적 변경 (최대 암호 사용 기간 90일 이하) ──
Evd "PC-01" "net accounts 2>`$null"
$maxAge = Get-SecPol "MaximumPasswordAge"
if ($null -eq $maxAge) { $v = Get-NetAccounts "Maximum password age|최대 암호 사용 기간"; if ($v) { $maxAge = if ($v -match '^\d+$') { $v } else { "-1" } } }
EvdQ "PC-01" "MaximumPasswordAge (secedit/net accounts)" "$maxAge"
if ($null -eq $maxAge) { MC "PC-01" "최대 암호 사용 기간 조회 실패 - secpol.msc 계정 정책 확인" }
elseif ([int]$maxAge -gt 0 -and [int]$maxAge -le 90) { Pass "PC-01" "최대 암호 사용 기간 ${maxAge}일 (90일 이하)" }
else { Fail "PC-01" "최대 암호 사용 기간 $(if ([int]$maxAge -le 0) { '제한 없음' } else { "${maxAge}일 (90일 초과)" })" }

# ── PC-02 비밀번호 관리정책 (복잡성 + 길이, 비밀번호 미사용 계정) ──
$cpx = Get-SecPol "PasswordComplexity"; $mnl = Get-SecPol "MinimumPasswordLength"
if ($null -eq $mnl) { $mnl = Get-NetAccounts "Minimum password length|최소 암호 길이" }
$noPw = @()
try { $noPw = @(Get-LocalUser -EA Stop | Where-Object { $_.Enabled -and -not $_.PasswordRequired -and $_.Name -notmatch '^(DefaultAccount|WDAGUtilityAccount)$' } | ForEach-Object { $_.Name }) } catch {}
Evd "PC-02" "Get-LocalUser -EA SilentlyContinue | Select-Object Name,Enabled,PasswordRequired,PasswordLastSet | Format-Table -AutoSize"
EvdQ "PC-02" "PasswordComplexity / MinimumPasswordLength" "$cpx / $mnl"
$bad02 = @()
if ("$cpx" -ne "1") { $bad02 += "암호 복잡성 정책 $(if ($null -eq $cpx) { '확인 불가' } else { '사용 안 함' })" }
if ($null -eq $mnl -or [int]$mnl -lt 8) { $bad02 += "최소 암호 길이 $(if ($null -eq $mnl) { '확인 불가' } else { "${mnl}자" }) (8자 이상 필요)" }
if ($noPw.Count) { $bad02 += "비밀번호 미요구 계정: $($noPw -join ', ')" }
if ($null -eq $cpx -and $null -eq $mnl) { MC "PC-02" "암호 정책 조회 실패(관리자 권한 필요) - secpol.msc 확인" }
elseif ($bad02.Count) { Fail "PC-02" ($bad02 -join ' / ') }
else { Pass "PC-02" "암호 복잡성 사용, 최소 길이 ${mnl}자, 비밀번호 미요구 계정 없음" }

# ── PC-03 복구 콘솔 자동 로그온 금지 ──
$rc = Get-Reg 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Setup\RecoveryConsole' 'SecurityLevel'
EvdQ "PC-03" "HKLM\...\Setup\RecoveryConsole SecurityLevel (복구 콘솔: 자동 관리 로그온 허용)" "$rc"
if ("$rc" -eq "1") { Fail "PC-03" "복구 콘솔 자동 관리 로그온 허용 '사용' (SecurityLevel=1)" }
else { Pass "PC-03" "복구 콘솔 자동 관리 로그온 허용 '사용 안 함' (SecurityLevel=$(if ($null -eq $rc) { '미설정(기본 사용 안 함)' } else { $rc }))" }

# ── PC-04 공유 폴더 제거 ──
Evd "PC-04" "Get-SmbShare -EA SilentlyContinue | Select-Object Name,Path,Description | Format-Table -AutoSize; Get-SmbShare -EA SilentlyContinue | Where-Object { `$_.Name -notmatch '\$$' } | ForEach-Object { Get-SmbShareAccess -Name `$_.Name -EA SilentlyContinue } | Format-Table -AutoSize"
$shares = @(Get-SmbShare -EA SilentlyContinue | Where-Object { $_.Name -notmatch '\$$' })
$ev04 = @()
foreach ($s in $shares) { if (Get-SmbShareAccess -Name $s.Name -EA SilentlyContinue | Where-Object { $_.AccountName -match 'Everyone|Guest|익명|ANONYMOUS' -and "$($_.AccessControlType)" -eq 'Allow' }) { $ev04 += $s.Name } }
if ($ev04.Count) { Fail "PC-04" "Everyone/Guest 접근 허용 공유 폴더: $($ev04 -join ', ')" }
elseif ($shares.Count) { MC "PC-04" "사용자 공유 폴더 $($shares.Count)개($(($shares | ForEach-Object { $_.Name }) -join ', ')) - 업무상 필요 여부 확인 (접근 권한 지정됨)" }
else { Pass "PC-04" "사용자 공유 폴더 없음 (기본 관리 공유만 존재)" }

# ── PC-05 불필요한 서비스 제거 (가이드 '일반적으로 불필요한 서비스') ──
$svcList = [ordered]@{ Alerter="Alerter"; ClipSrv="Clipbook"; Browser="Computer Browser"; Messenger="Messenger"; mnmsrvc="NetMeeting Remote Desktop Sharing"
    RemoteRegistry="Remote Registry"; simptcp="Simple TCP/IP Services"; WZCSVC="Wireless Zero Configuration"; TlntSvr="Telnet"; SNMP="SNMP"
    WmdmPmSN="Portable Media Serial Number"; ImapiService="IMAPI CD-Burning COM Service"; ERSvc="Error Reporting Service" }
Evd "PC-05" "Get-Service $((@($svcList.Keys) + 'Spooler') -join ',') -EA SilentlyContinue | Select-Object Name,DisplayName,Status,StartType | Format-Table -AutoSize"
$run05 = @()
foreach ($k in $svcList.Keys) { $s = Get-Service $k -EA SilentlyContinue; if ($s -and "$($s.Status)" -eq 'Running') { $run05 += "$($svcList[$k])($k)" } }
$spool = Get-Service Spooler -EA SilentlyContinue
$note05 = if ($spool -and "$($spool.Status)" -eq 'Running') { " / 참고: Print Spooler 실행 중 - 프린터 미사용 시 중지 권고" } else { "" }
if ($run05.Count) { Fail "PC-05" "불필요한 서비스 실행 중: $($run05 -join ', ')$note05" }
else { Pass "PC-05" "가이드 목록의 불필요한 서비스 미실행$note05" }

# ── PC-06 비인가 상용 메신저 사용 금지 ──
$prev = Get-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Messenger\Client' 'PreventRun'
$msgKw = '(?i)kakaotalk|카카오톡|\bline\b|telegram|whatsapp|discord|skype|nateon|네이트온|wechat|signal|viber|messenger'
$msgs = @(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*','HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*' -EA SilentlyContinue |
    Where-Object { $_.DisplayName -match $msgKw } | ForEach-Object { "$($_.DisplayName)" } | Select-Object -Unique)
$msgs += @(Get-AppxPackage -EA SilentlyContinue | Where-Object { $_.Name -match '(?i)whatsapp|telegram|skype|discord|line' } | ForEach-Object { "$($_.Name)(Store)" })
$msgRun = @(Get-Process -EA SilentlyContinue | Where-Object { $_.ProcessName -match '(?i)^(kakaotalk|line|telegram|whatsapp|discord|skype|nateon|wechat|signal)$' } | ForEach-Object { $_.ProcessName } | Select-Object -Unique)
EvdQ "PC-06" "Windows Messenger PreventRun / 설치된 메신저 / 실행 중 메신저" "$prev / $($msgs -join ', ') / $($msgRun -join ', ')"
if ($msgs.Count -or $msgRun.Count) { MC "PC-06" "상용 메신저 설치/실행: $((@($msgs) + @($msgRun | ForEach-Object { "$_(실행 중)" })) -join ', ') - 기관 인가 메신저 여부 확인 (비인가 시 취약)" }
else { Pass "PC-06" "상용 메신저 미설치 (Windows Messenger 정책 PreventRun=$(if ($null -eq $prev) { '미설정(Windows 10/11 미포함)' } else { $prev }))" }

# ── PC-07 파일 시스템 NTFS ──
Evd "PC-07" "Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' -EA SilentlyContinue | Select-Object DeviceID,FileSystem,Size | Format-Table -AutoSize"
$vol = @(Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" -EA SilentlyContinue)
$fat = @($vol | Where-Object { "$($_.FileSystem)" -match '^(FAT|FAT32|exFAT)$' } | ForEach-Object { "$($_.DeviceID)($($_.FileSystem))" })
if (-not $vol.Count) { MC "PC-07" "로컬 디스크 조회 실패 - 파일 시스템 수동 확인" }
elseif ($fat.Count) { Fail "PC-07" "NTFS 가 아닌 로컬 볼륨: $($fat -join ', ')" }
else { Pass "PC-07" "로컬 디스크 파일 시스템: $(($vol | ForEach-Object { "$($_.DeviceID)$($_.FileSystem)" }) -join ', ')" }

# ── PC-08 멀티 부팅 ──
$bcd = bcdedit /enum osloader 2>$null
$ldr = @($bcd | Where-Object { $_ -match '^(description|설명)\s' })
EvdQ "PC-08" "bcdedit /enum osloader (description)" (($ldr) -join "`n")
if (-not $bcd -or $LASTEXITCODE -ne 0) { MC "PC-08" "bcdedit 조회 실패(관리자 권한 필요) - msconfig [부팅] 탭에서 OS 개수 확인" }
elseif ($ldr.Count -gt 1) { Fail "PC-08" "OS 로더 $($ldr.Count)개 - 멀티 부팅 구성: $(($ldr | ForEach-Object { ($_ -split '\s{2,}',2)[-1] }) -join ', ')" }
else { Pass "PC-08" "OS 로더 1개 (단일 OS)" }

# ── PC-09 브라우저 종료 시 임시 인터넷 파일 삭제 ──
$pp = Get-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Cache' 'Persistent'
$up = Get-Reg 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Cache' 'Persistent'
$edge = Get-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' 'ClearBrowsingDataOnExit'
EvdQ "PC-09" "정책 Cache\Persistent / 사용자 Cache\Persistent / Edge ClearBrowsingDataOnExit" "$pp / $up / $edge"
if ("$pp" -eq "0" -or ("$pp" -eq "" -and "$up" -eq "0") -or "$edge" -eq "1") { Pass "PC-09" "브라우저 종료 시 임시 인터넷 파일 삭제 설정 (Persistent=$(if ("$pp" -ne '') { $pp } else { $up }), Edge ClearBrowsingDataOnExit=$edge)" }
else { Fail "PC-09" "'브라우저를 닫을 때 임시 인터넷 파일 폴더 비우기' 미설정 (Persistent=$(if ("$pp" -ne '') { $pp } else { "$up(미설정=기본 보존)" }), Edge ClearBrowsingDataOnExit=$edge)" }

# ── PC-10 주기적 보안 패치 (HOT FIX + 자동 업데이트) ──
Evd "PC-10" "Get-HotFix -EA SilentlyContinue | Sort-Object InstalledOn -Descending | Select-Object -First 10 HotFixID,Description,InstalledOn | Format-Table -AutoSize"
$hf = Get-HotFix -EA SilentlyContinue | Where-Object { $_.InstalledOn } | Sort-Object InstalledOn -Descending | Select-Object -First 1
$noAu = Get-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' 'NoAutoUpdate'
$wu = Get-Service wuauserv -EA SilentlyContinue
EvdQ "PC-10" "자동 업데이트 정책 NoAutoUpdate / wuauserv 시작 유형" "$noAu / $(if ($wu) { $wu.StartType })"
if (-not $hf) { MC "PC-10" "HOT FIX 설치 이력 조회 실패 - 설정 > Windows 업데이트 기록 확인" }
else {
    $age = ((Get-Date) - $hf.InstalledOn).Days
    $auOff = ("$noAu" -eq "1") -or ($wu -and "$($wu.StartType)" -eq 'Disabled')
    if ($age -gt 90) { Fail "PC-10" "최근 HOT FIX $($hf.HotFixID) 설치 후 ${age}일 경과 (자동 업데이트 $(if ($auOff) { '비활성' } else { '활성' }))" }
    elseif ($auOff) { Fail "PC-10" "자동 업데이트 비활성 (NoAutoUpdate=$noAu, wuauserv=$($wu.StartType)) - 최근 HOT FIX $($hf.HotFixID) (${age}일 전)" }
    else { Pass "PC-10" "최근 HOT FIX $($hf.HotFixID) ($($hf.InstalledOn.ToString('yyyy-MM-dd')), ${age}일 전), 자동 업데이트 활성 - 내부 관리 절차는 인터뷰 확인" }
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

# ── PC-13 / PC-14 백신 설치·업데이트 / 실시간 감시 ──
$avSc = @(Get-CimInstance -Namespace "root\SecurityCenter2" -ClassName AntiVirusProduct -EA SilentlyContinue)
$mp = $null; try { $mp = Get-MpComputerStatus -EA Stop } catch {}
EvdQ "PC-13" "SecurityCenter2 AntiVirusProduct (이름 / productState)" (($avSc | ForEach-Object { "$($_.displayName) / 0x$(([int]$_.productState).ToString('X6'))" }) -join "`n")
EvdQ "PC-13" "Defender (Get-MpComputerStatus)" $(if ($mp) { "AMServiceEnabled=$($mp.AMServiceEnabled) RealTime=$($mp.RealTimeProtectionEnabled) SignatureLastUpdated=$($mp.AntivirusSignatureLastUpdated) SignatureVersion=$($mp.AntivirusSignatureVersion)" } else { '조회 불가' })
$third = @($avSc | Where-Object { $_.displayName -notmatch '(?i)Windows Defender|Microsoft Defender' })
$act = @($avSc | Where-Object { ((([int]$_.productState) -shr 8) -band 0xF0) -eq 0x10 -or ((([int]$_.productState) -shr 12) -band 0x1) -eq 1 })
$upd = @($avSc | Where-Object { ((([int]$_.productState) -shr 4) -band 0xF) -eq 0 })
if (-not $avSc.Count -and -not $mp) { Fail "PC-13" "백신 프로그램 미탐지"; Fail "PC-14" "백신 프로그램 미탐지 - 실시간 감시 불가" }
else {
    $names = (@($avSc | ForEach-Object { $_.displayName }) | Select-Object -Unique) -join ', '
    if ($mp -and -not $third.Count) {
        $age = ((Get-Date) - $mp.AntivirusSignatureLastUpdated).Days
        if ($age -le 7) { Pass "PC-13" "Microsoft Defender 설치, 엔진·패턴 최신 (서명 갱신 $($mp.AntivirusSignatureLastUpdated.ToString('yyyy-MM-dd')), ${age}일 전)" }
        else { Fail "PC-13" "Microsoft Defender 서명 업데이트 ${age}일 경과 ($($mp.AntivirusSignatureLastUpdated.ToString('yyyy-MM-dd')))" }
        if ($mp.RealTimeProtectionEnabled) { Pass "PC-14" "Microsoft Defender 실시간 보호 활성" } else { Fail "PC-14" "Microsoft Defender 실시간 보호 비활성" }
    } else {
        if ($upd.Count) { Pass "PC-13" "백신 설치·정의 최신(보안 센터 기준): $names" } else { Fail "PC-13" "백신 설치($names)되었으나 보안 센터 기준 정의 업데이트 필요" }
        if ($act.Count) { Pass "PC-14" "백신 실시간 감시 활성: $(($act | ForEach-Object { $_.displayName }) -join ', ')" } else { Fail "PC-14" "백신 실시간 감시 비활성 (보안 센터 기준): $names" }
    }
}

# ── PC-15 OS 침입차단(방화벽) ──
Evd "PC-15" "Get-NetFirewallProfile -EA SilentlyContinue | Select-Object Name,Enabled,DefaultInboundAction | Format-Table -AutoSize"
$fwOff = @(Get-NetFirewallProfile -EA SilentlyContinue | Where-Object { -not $_.Enabled } | ForEach-Object { "$($_.Name)" })
$fw3 = @(Get-CimInstance -Namespace "root\SecurityCenter2" -ClassName FirewallProduct -EA SilentlyContinue | ForEach-Object { $_.displayName })
EvdQ "PC-15" "타사 방화벽(SecurityCenter2 FirewallProduct)" ($fw3 -join ', ')
if (-not $fwOff.Count) { Pass "PC-15" "Windows 방화벽 전체 프로필 사용" }
elseif ($fw3.Count) { Pass "PC-15" "Windows 방화벽 일부 비활성($($fwOff -join ',')) - 타사 방화벽 사용: $($fw3 -join ', ')" }
else { Fail "PC-15" "Windows 방화벽 사용 안 함: $($fwOff -join ', ') (타사 방화벽 미탐지)" }

# ── PC-16 화면보호기 (대기 10분 이하 + 암호 보호) ──
$pol = 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop'; $usr = 'HKCU:\Control Panel\Desktop'
$ssA = Get-Reg $pol 'ScreenSaveActive';    if ($null -eq $ssA) { $ssA = Get-Reg $usr 'ScreenSaveActive' }
$ssT = Get-Reg $pol 'ScreenSaveTimeOut';   if ($null -eq $ssT) { $ssT = Get-Reg $usr 'ScreenSaveTimeOut' }
$ssS = Get-Reg $pol 'ScreenSaverIsSecure'; if ($null -eq $ssS) { $ssS = Get-Reg $usr 'ScreenSaverIsSecure' }
$lock = Get-Reg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'InactivityTimeoutSecs'
EvdQ "PC-16" "ScreenSaveActive / ScreenSaveTimeOut / ScreenSaverIsSecure / InactivityTimeoutSecs(컴퓨터 잠금)" "$ssA / $ssT / $ssS / $lock"
if ("$ssA" -eq "1" -and "$ssS" -eq "1" -and $ssT -and [int]$ssT -gt 0 -and [int]$ssT -le 600) { Pass "PC-16" "화면보호기 대기 $([int]$ssT/60)분, 재시작 시 암호 보호" }
elseif ($lock -and [int]$lock -gt 0 -and [int]$lock -le 600) { Pass "PC-16" "컴퓨터 비활성 한도(잠금) ${lock}초 - 화면 잠금 적용" }
else { Fail "PC-16" "화면보호기 설정 미흡 (사용=$ssA, 대기=${ssT}초, 암호 보호=$ssS; 기준: 10분 이하 + 암호 보호)" }

# ── PC-17 이동식 미디어 자동 실행 방지 ──
$nd = Get-Reg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'NoDriveTypeAutoRun'
$nar = Get-Reg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'NoAutorun'
$ndu = Get-Reg 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'NoDriveTypeAutoRun'
$dap = Get-Reg 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers' 'DisableAutoplay'
EvdQ "PC-17" "NoDriveTypeAutoRun(HKLM/HKCU) / NoAutorun / DisableAutoplay" "$nd / $ndu / $nar / $dap"
if ("$nd" -eq "255" -or "$ndu" -eq "255" -or "$dap" -eq "1") { Pass "PC-17" "모든 드라이브 자동 실행 끄기 (NoDriveTypeAutoRun=$(if ("$nd" -ne '') { $nd } else { $ndu }), DisableAutoplay=$dap) - 이동식 미디어 관리 절차는 인터뷰 확인" }
else { Fail "PC-17" "미디어 자동 실행 방지 미설정 (NoDriveTypeAutoRun=$nd, DisableAutoplay=$dap)" }

# ── PC-18 원격 지원 금지 ──
$rp = Get-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' 'fAllowToGetHelp'
$ra = Get-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance' 'fAllowToGetHelp'
EvdQ "PC-18" "정책 fAllowToGetHelp / 시스템 fAllowToGetHelp" "$rp / $ra"
$eff = if ("$rp" -ne "") { $rp } else { $ra }
if ("$eff" -eq "1") { Fail "PC-18" "원격 지원 허용 (fAllowToGetHelp=1)" }
else { Pass "PC-18" "원격 지원 사용 안 함 (fAllowToGetHelp=$(if ("$eff" -eq '') { '미설정' } else { $eff }))" }

Write-Output "# ============================================================"
Write-Output "# 점검 요약 - 주요정보통신기반시설 상세가이드(2026) PC"
Write-Output "#   양호: $($script:cnt['양호']) / 취약: $($script:cnt['취약']) / 수동확인: $($script:cnt['수동확인']) / N-A: $($script:cnt['N-A'])"
Write-Output "# 증적 파일: $($script:EVD)"
Write-Output "# ============================================================"
if (Test-Path $seceditFile) { Remove-Item $seceditFile -Force -EA SilentlyContinue }
