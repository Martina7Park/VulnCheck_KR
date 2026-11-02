# ================================================================
# convert_v4.py 실행 환경 설치 (점검자 PC, Windows PowerShell 5.1 이상)
# ================================================================
#   필요 프로그램: Python 3.8 이상 + openpyxl  (eos_checker.py·compare_results.py 도 동일)
#   이미 설치돼 있으면 건너뜀
#
#   실행: Set-ExecutionPolicy RemoteSigned -Scope Process -Force
#         .\install_prereq.ps1
# ================================================================
$ErrorActionPreference = 'Stop'
$ProgressPreference    = 'SilentlyContinue'
try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12 } catch {}

# Python 설치 파일 (winget 매니페스트와 동일 URL·SHA256)
$PyUrl = 'https://www.python.org/ftp/python/3.12.10/python-3.12.10-amd64.exe'
$PySha = '67B5635E80EA51072B87941312D00EC8927C4DB9BA18938F7AD2D27B328B95FB'

function Find-Python {
    # py 런처 → python 순서, Microsoft Store 가짜 python(WindowsApps 별칭)은 실행 결과로 걸러냄
    foreach ($c in @(@('py','-3'), @('python'))) {
        if (-not (Get-Command $c[0] -EA SilentlyContinue)) { continue }
        $a = @($c | Select-Object -Skip 1)
        try { $v = & $c[0] @a -c "import sys; print('%d.%d' % sys.version_info[:2])" 2>$null } catch { continue }
        if ($LASTEXITCODE -eq 0 -and "$v" -match '^3\.(\d+)$' -and [int]$matches[1] -ge 8) { return @{ Cmd = $c[0]; Args = $a; Ver = "$v".Trim() } }
    }
    return $null
}
function Get-Sha256([string]$path) {
    # Get-FileHash 는 PowerShell 4.0+ 전용 - 없으면 .NET 으로 계산 (대문자 16진 문자열 반환)
    if (Get-Command Get-FileHash -EA SilentlyContinue) { return (Get-FileHash $path -Algorithm SHA256).Hash.ToUpper() }
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $fs = [System.IO.File]::OpenRead($path)
    try { return ([BitConverter]::ToString($sha.ComputeHash($fs)) -replace '-','').ToUpper() } finally { $fs.Close(); $sha.Dispose() }
}
function Py([string[]]$more) {
    $ErrorActionPreference = 'Continue'   # PS 5.1: Stop 이면 python 의 stderr 출력(모듈 없음 등)이 예외로 바뀜 → 종료코드로 판단
    $all = @($script:py.Args) + $more; & $script:py.Cmd @all
}

# 1) Python
$script:py = Find-Python
if ($script:py) {
    Write-Host "Python $($script:py.Ver) 이미 설치됨" -ForegroundColor Green
} else {
    $ok = $false
    if (Get-Command winget -EA SilentlyContinue) {
        Write-Host "winget 으로 Python 3.12 설치 중..."
        winget install --id Python.Python.3.12 --exact --silent --accept-package-agreements --accept-source-agreements
        $ok = ($LASTEXITCODE -eq 0)
    }
    if (-not $ok) {
        $exe = Join-Path $env:TEMP 'python-3.12.10-amd64.exe'
        Write-Host "python.org 에서 설치 파일 다운로드 중..."
        Invoke-WebRequest -Uri $PyUrl -OutFile $exe -UseBasicParsing
        $got = Get-Sha256 $exe
        if ($got -ne $PySha) {
            Remove-Item $exe -Force -ErrorAction SilentlyContinue   # 검증 실패 파일은 실행하지 않고 삭제
            throw ("Python 설치 파일의 SHA256 이 기대값과 다릅니다 - 설치를 중단했습니다 (받은 파일은 삭제함).`n" +
                   "  기대값: $PySha`n  실제값: $got`n" +
                   "  원인: 다운로드가 중간에 끊겼거나, 프록시/보안장비가 파일을 바꿨거나, 변조되었을 수 있습니다.`n" +
                   "  조치: 네트워크 상태를 확인한 뒤 다시 실행하거나, python.org 에서 3.12.10 설치 파일을 직접 받아 설치하십시오.")
        }
        $admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        $all = if ($admin) { 1 } else { 0 }   # 관리자면 전체 사용자, 아니면 현재 사용자
        $p = Start-Process -FilePath $exe -ArgumentList "/quiet InstallAllUsers=$all PrependPath=1 Include_launcher=1 Include_test=0" -Wait -PassThru
        if ($p.ExitCode -ne 0) { throw "Python 설치 실패 (exit $($p.ExitCode))" }
    }
    # 설치 프로그램이 갱신한 시스템·사용자 PATH 의 새 항목만 현재 프로세스 PATH 뒤에 추가 (기존 프로세스 PATH 는 덮어쓰지 않음)
    $have = @($env:Path -split ';' | Where-Object { $_ } | ForEach-Object { $_.TrimEnd('\').ToLower() })
    foreach ($scope in 'Machine','User') {
        foreach ($d in ([Environment]::GetEnvironmentVariable('Path',$scope) -split ';')) {
            if ($d -and ($have -notcontains $d.TrimEnd('\').ToLower())) {
                $env:Path = $env:Path.TrimEnd(';') + ';' + $d
                $have += $d.TrimEnd('\').ToLower()
            }
        }
    }
    $script:py = Find-Python
    if (-not $script:py) { throw "Python 설치 후에도 찾지 못함 - 새 PowerShell 창에서 다시 실행하세요" }
    Write-Host "Python $($script:py.Ver) 설치 완료" -ForegroundColor Green
}

# 2) openpyxl
Py @('-c','import openpyxl') 2>$null | Out-Null
if ($LASTEXITCODE -eq 0) {
    Write-Host "openpyxl 이미 설치됨" -ForegroundColor Green
} else {
    Write-Host "openpyxl 설치 중..."
    Py @('-m','pip','install','--upgrade','openpyxl')
    if ($LASTEXITCODE -ne 0) { throw "openpyxl 설치 실패 (프록시 환경이면: pip install --proxy http://주소:포트 openpyxl)" }
}
$ver = Py @('-c','import openpyxl; print(openpyxl.__version__)')
Write-Host "openpyxl $ver 확인 - 준비 완료: python convert_v4.py" -ForegroundColor Green
