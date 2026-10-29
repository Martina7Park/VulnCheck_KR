#!/bin/bash
if [ -z "$BASH_VERSION" ]; then for _b in /bin/bash /usr/bin/bash /opt/freeware/bin/bash /usr/local/bin/bash /usr/contrib/bin/bash; do [ -x $_b ] && exec $_b "$0" "$@"; done; echo "bash 필요 (AIX: AIX Toolbox bash / HP-UX: Porting Centre bash 설치 후 재실행)"; exit 1; fi
# ================================================================
# 서버(Unix/Linux) 보안 취약점 자동 점검 스크립트 — 주요정보통신기반시설
# ================================================================
#
# [용도]
#   주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드(한국인터넷진흥원, 2026)
#   [Unix 서버] U-01 ~ U-67 (가이드 항목코드·판단기준 그대로)
#   Windows Server는 check_server.ps1 사용.
#
# [대상 OS]
#   Linux (RHEL/CentOS/Rocky/Ubuntu/SLES/Amazon)
#   AIX 6.1~7.3 / HP-UX 11i / Solaris 10~11
#
# [사전 조건]
#   - root 권한 필요 (sudo bash 또는 root 로그인)
#
# [실행 방법]
#   bash check_server_u.sh > /tmp/$(hostname)_u.txt
#
# [산출물]
#   1) 표준출력: U-항목코드|결과|근거설명  (양호/취약/수동확인/N-A)
#   2) 증적 파일: /tmp/<호스트명>_u_evidence.txt
#
# ================================================================

# ── OS 탐지 ──────────────────────────────────────────────────────
detect_os() {
    OS_FAMILY="LINUX"    # LINUX / AIX / SOLARIS / HPUX / BSD
    OS_DISTRO="UNKNOWN"  # RHEL / CENTOS / UBUNTU / DEBIAN / SLES / AMZN / ORACLE
    OS_MAJOR=0

    case "$(uname -s)" in
    MINGW*|MSYS*|CYGWIN*)
        OS_FAMILY="WINDOWS"; OS_DISTRO="GITBASH"
        OS_MAJOR=$(uname -s | grep -oE '[0-9]+' | head -1); return ;;
    AIX)
        OS_FAMILY="AIX"; OS_DISTRO="AIX"
        OS_MAJOR=$(uname -v); return ;;
    SunOS)
        OS_FAMILY="SOLARIS"; OS_DISTRO="SOLARIS"
        OS_MAJOR=$(uname -r | cut -d. -f2); return ;;
    "HP-UX")
        OS_FAMILY="HPUX"; OS_DISTRO="HPUX"
        OS_MAJOR=$(uname -r | cut -d. -f2); return ;;
    FreeBSD|OpenBSD|NetBSD)
        OS_FAMILY="BSD"; OS_DISTRO="$(uname -s)"
        OS_MAJOR=$(uname -r | cut -d. -f1); return ;;
    esac

    if [ -f /etc/os-release ]; then
        . /etc/os-release
        case "$ID" in
        rhel|centos|rocky|almalinux|ol) OS_DISTRO="RHEL"; OS_MAJOR="${VERSION_ID%%.*}" ;;
        ubuntu)  OS_DISTRO="UBUNTU"; OS_MAJOR="${VERSION_ID%%.*}" ;;
        debian)  OS_DISTRO="DEBIAN"; OS_MAJOR="${VERSION_ID}" ;;
        sles|suse) OS_DISTRO="SLES"; OS_MAJOR="${VERSION_ID%%.*}" ;;
        amzn)    OS_DISTRO="AMZN";  OS_MAJOR="${VERSION_ID}" ;;
        *)       OS_DISTRO="${ID:-UNKNOWN}"; OS_MAJOR="${VERSION_ID%%.*}" ;;
        esac
    elif [ -f /etc/redhat-release ]; then
        OS_DISTRO="RHEL"; OS_MAJOR=$(grep -oE '[0-9]+' /etc/redhat-release | head -1)
    elif [ -f /etc/debian_version ]; then
        OS_DISTRO="DEBIAN"; OS_MAJOR=$(cut -d. -f1 /etc/debian_version)
    fi
}

detect_os
case "$OS_FAMILY" in   # Solaris 기본 grep/awk 는 -E/-q/-o·-v 미지원, AIX·HP-UX 는 GNU 도구 경로 우선
SOLARIS) PATH="/usr/gnu/bin:/usr/xpg4/bin:/opt/csw/gnu:/opt/csw/bin:/usr/sfw/bin:$PATH" ;;
AIX)     PATH="/opt/freeware/bin:$PATH" ;;
HPUX)    PATH="/usr/local/bin:$PATH" ;;
esac; export PATH
HN=$(hostname 2>/dev/null || uname -n)
# ── 결과 사본 자동 저장: '> 파일' 리다이렉트를 빠뜨려도 판정 결과가 증적과 같은 위치에 남도록 표준출력을 복사 ──
_RESF="/tmp/${HN}_u.txt"
if [ -z "$NO_RESULT_COPY" ] && ! [ /dev/fd/1 -ef "$_RESF" ] 2>/dev/null && ( : > "$_RESF" ) 2>/dev/null; then
    exec > >(tee "$_RESF"); _TEEPID=$!
else
    _RESF=""
fi

echo "# ============================================================"
echo "# 점검 대상: ${HN}"
echo "# OS: ${OS_FAMILY} / ${OS_DISTRO} ${OS_MAJOR}"
echo "# OS 상세: $( ( [ -r /etc/os-release ] && . /etc/os-release 2>/dev/null && echo "${PRETTY_NAME:-$NAME $VERSION_ID}" ) || ( command -v oslevel >/dev/null 2>&1 && echo "AIX $(oslevel -s 2>/dev/null)" ) || ( [ -r /etc/release ] && head -1 /etc/release | sed 's/^ *//' ) || uname -sr 2>/dev/null)"
echo "# 커널: $(uname -r 2>/dev/null)$( [ "$(uname -s 2>/dev/null)" = SunOS ] && echo " / $(uname -v 2>/dev/null)")"
echo "# 점검 기준: 주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드(2026) [Unix 서버 U-01~U-67]"
echo "# 점검 일시: $(date '+%Y-%m-%d %H:%M:%S')"
if [ "$OS_DISTRO" = "RHEL" ]; then
    _id=$(. /etc/os-release 2>/dev/null; echo "$ID")
    [ "$_id" = "centos" ] && echo "# [경고] CentOS는 전체 버전 EOL - 취약 판정 대상"
fi
if [ "$OS_FAMILY" = "WINDOWS" ]; then
    echo "# [경고] Windows 환경(Git Bash)에서 실행됨 — Linux/Unix 전용 스크립트"
    echo "# [경고] Windows Server 점검은 check_server.ps1 사용"
fi
echo "# ============================================================"

# ── 결과 카운터 ──────────────────────────────────────────────────
_CP=0; _CF=0; _CM=0; _CN=0
_EVD="/tmp/${HN}_u_evidence.txt"
echo "# ================================================================" > "$_EVD"
echo "# 증적 파일 (감사 추적용)" >> "$_EVD"
echo "# 대상: ${HN} / ${OS_FAMILY} ${OS_DISTRO} ${OS_MAJOR}" >> "$_EVD"
echo "# 생성: $(date '+%Y-%m-%d %H:%M:%S')" >> "$_EVD"
echo "# ================================================================" >> "$_EVD"

declare -A _INAME=(
    [U-01]='root 계정 원격 접속 제한'
    [U-02]='비밀번호 관리정책 설정'
    [U-03]='계정 잠금 임계값 설정'
    [U-04]='비밀번호 파일 보호'
    [U-05]='root 이외의 UID가 ‘0’ 금지'
    [U-06]='사용자 계정 su 기능 제한'
    [U-07]='불필요한 계정 제거'
    [U-08]='관리자 그룹에 최소한의 계정 포함'
    [U-09]='계정이 존재하지 않는 GID 금지'
    [U-10]='동일한 UID 금지'
    [U-11]='사용자 shell 점검'
    [U-12]='세션 종료 시간 설정'
    [U-13]='안전한 비밀번호 암호화 알고리즘 사용'
    [U-14]='root 홈, 패스 디렉터리 권한 및 패스 설정'
    [U-15]='파일 및 디렉터리 소유자 설정'
    [U-16]='/etc/passwd 파일 소유자 및 권한 설정'
    [U-17]='시스템 시작 스크립트 권한 설정'
    [U-18]='/etc/shadow 파일 소유자 및 권한 설정'
    [U-19]='/etc/hosts 파일 소유자 및 권한 설정'
    [U-20]='/etc/(x)inetd.conf 파일 소유자 및 권한 설정'
    [U-21]='/etc/(r)syslog.conf 파일 소유자 및 권한 설정'
    [U-22]='/etc/services 파일 소유자 및 권한 설정'
    [U-23]='SUID, SGID, Sticky bit 설정 파일 점검'
    [U-24]='사용자, 시스템 환경변수 파일 소유자 및 권한 설정'
    [U-25]='world writable 파일 점검'
    [U-26]='/dev에 존재하지 않는 device 파일 점검'
    [U-27]='$HOME/.rhosts, hosts.equiv 사용 금지'
    [U-28]='접속 IP 및 포트 제한'
    [U-29]='hosts.lpd 파일 소유자 및 권한 설정'
    [U-30]='UMASK 설정 관리'
    [U-31]='홈디렉토리 소유자 및 권한 설정'
    [U-32]='홈 디렉토리로 지정한 디렉토리의 존재 관리'
    [U-33]='숨겨진 파일 및 디렉토리 검색 및 제거'
    [U-34]='Finger 서비스 비활성화'
    [U-35]='공유 서비스에 대한 익명 접근 제한 설정'
    [U-36]='r 계열 서비스 비활성화'
    [U-37]='crontab 설정파일 권한 설정 미흡'
    [U-38]='DoS 공격에 취약한 서비스 비활성화'
    [U-39]='불필요한 NFS 서비스 비활성화'
    [U-40]='NFS 접근 통제'
    [U-41]='불필요한 automountd 제거'
    [U-42]='불필요한 RPC 서비스 비활성화'
    [U-43]='NIS, NIS+ 점검'
    [U-44]='tftp, talk 서비스 비활성화'
    [U-45]='메일 서비스 버전 점검'
    [U-46]='일반 사용자의 메일 서비스 실행 방지'
    [U-47]='스팸 메일 릴레이 제한'
    [U-48]='expn, vrfy 명령어 제한'
    [U-49]='DNS 보안 버전 패치'
    [U-50]='DNS ZoneTransfer 설정'
    [U-51]='DNS 서비스의 취약한 동적 업데이트 설정 금지'
    [U-52]='Telnet 서비스 비활성화'
    [U-53]='FTP 서비스 정보 노출 제한'
    [U-54]='암호화되지 않는 FTP 서비스 비활성화'
    [U-55]='FTP 계정 shell 제한'
    [U-56]='FTP 서비스 접근 제어 설정'
    [U-57]='Ftpusers 파일 설정'
    [U-58]='불필요한 SNMP 서비스 구동 점검'
    [U-59]='안전한 SNMP 버전 사용'
    [U-60]='SNMP Community String 복잡성 설정'
    [U-61]='SNMP Access Control 설정'
    [U-62]='로그인 시 경고 메시지 설정'
    [U-63]='sudo 명령어 접근 관리'
    [U-64]='주기적 보안 패치 및 벤더 권고사항 적용'
    [U-65]='NTP 및 시각 동기화 설정'
    [U-66]='정책에 따른 시스템 로깅 설정'
    [U-67]='로그 디렉터리 소유자 및 권한 설정'
)

# ── Windows 환경 조기 종료 ───────────────────────────────────────
if [ "$OS_FAMILY" = "WINDOWS" ]; then
    echo "# Windows 환경 — 전 항목 N-A 처리" >> "$_EVD"
    for _i in $(seq -w 1 67); do
        _CN=$((_CN+1))
        _code="U-${_i}"; _nm="${_INAME[U-${_i}]:-}"
        echo "${_code}|N-A|Windows 환경 — Linux/Unix 전용 항목"
        if [ -n "$_nm" ]; then
            printf '[판정] %s (%s)|N-A|Windows 환경 — Linux/Unix 전용 항목\n\n' "$_code" "$_nm" >> "$_EVD"
        else
            printf '[판정] %s|N-A|Windows 환경 — Linux/Unix 전용 항목\n\n' "$_code" >> "$_EVD"
        fi
    done
    _TOTAL=$((_CP + _CF + _CM + _CN))
    echo "# ================================================================"
    echo "# 점검 요약 — 주요정보통신기반시설 (U)"
    echo "#   총 점검 항목: ${_TOTAL}"
    echo "#   양호:         ${_CP}  (0%)"
    echo "#   취약:         ${_CF}  (0%)"
    echo "#   수동확인:     ${_CM}"
    echo "#   N-A:          ${_CN}"
    echo "# ================================================================"
    echo "# 점검 완료: $(date '+%Y-%m-%d %H:%M:%S')"
    echo "# 증적 파일: ${_EVD}"
    exit 0
fi
result() {
    echo "$1"
    case "$1" in
    *"|양호|"*)     _CP=$((_CP+1)) ;;
    *"|취약|"*)     _CF=$((_CF+1)) ;;
    *"|수동확인|"*) _CM=$((_CM+1)) ;;
    *"|N-A|"*)      _CN=$((_CN+1)) ;;
    esac
    local _code="${1%%|*}" _rest="${1#*|}"
    local _nm="${_INAME[$_code]:-}"
    if [ -n "$_nm" ]; then
        printf '[판정] %s (%s)|%s\n\n' "$_code" "$_nm" "$_rest" >> "$_EVD"
    else
        printf '[판정] %s\n\n' "$1" >> "$_EVD"
    fi
}
evd() {
    local item="$1"; shift
    printf '[%s] %s $ %s\n' "$item" "$(date '+%H:%M:%S')" "$*" >> "$_EVD"
    eval "$@" >> "$_EVD" 2>&1
    printf '\n' >> "$_EVD"
}
evd_file() {
    local item="$1" f="$2"
    if [ -f "$f" ] || [ -d "$f" ]; then
        printf '[%s] 파일: %s (존재)\n' "$item" "$f" >> "$_EVD"
    else
        printf '[%s] 파일: %s (미존재)\n' "$item" "$f" >> "$_EVD"
    fi
}

# ── 공통 함수 ────────────────────────────────────────────────────
get_perm() {
    local f="$1"; [ -e "$f" ] || [ -L "$f" ] || { echo ""; return; }
    if [ -L "$f" ]; then
        local rf; rf=$(readlink -f "$f" 2>/dev/null)
        [ -z "$rf" ] && rf=$(perl -MCwd -e 'print Cwd::abs_path($ARGV[0])' "$f" 2>/dev/null)
        [ -n "$rf" ] && [ -e "$rf" ] && f="$rf" || { echo ""; return; }
    fi
    case "$OS_FAMILY" in
    AIX)     istat "$f" 2>/dev/null | awk '/Mode/{print $NF}' | head -1 ;;
    BSD)     stat -f "%Lp" "$f" 2>/dev/null ;;
    SOLARIS|HPUX) ls -lL "$f" 2>/dev/null | awk '{p=substr($1,2);r=0;for(i=1;i<=9;i++){c=substr(p,i,1);if(c!="-")r+=2^(9-i)};printf "%03o\n",r}' ;;
    *)       stat -c "%a" "$f" 2>/dev/null ;;
    esac
}
get_owner() {
    local f="$1"; [ -e "$f" ] || [ -L "$f" ] || { echo ""; return; }
    if [ -L "$f" ]; then
        local rf; rf=$(readlink -f "$f" 2>/dev/null)
        [ -z "$rf" ] && rf=$(perl -MCwd -e 'print Cwd::abs_path($ARGV[0])' "$f" 2>/dev/null)
        [ -n "$rf" ] && [ -e "$rf" ] && f="$rf" || { echo ""; return; }
    fi
    case "$OS_FAMILY" in
    AIX)     istat "$f" 2>/dev/null | awk '/Owner/{print $2}' ;;
    BSD)     stat -f "%Su" "$f" 2>/dev/null ;;
    SOLARIS|HPUX) ls -lL "$f" 2>/dev/null | awk '{print $3}' ;;
    *)       stat -c "%U" "$f" 2>/dev/null ;;
    esac
}
_TO=$(command -v timeout 2>/dev/null)
_to() { local s="$1"; shift; if [ -n "$_TO" ]; then "$_TO" "$s" "$@"; else "$@"; fi; }   # timeout 없는 AIX·HP-UX·Solaris 10 은 제한 없이 실행
_aix_default() { awk '/^default:/{f=1;next} /^[^ 	*#]/{f=0} f' /etc/security/user 2>/dev/null; }   # AIX default 스탠자 본문 (awk 범위식은 시작행에서 바로 종료되는 결함)
is_running() {
    local svc="$1"
    command -v systemctl >/dev/null 2>&1 && systemctl is-active "$svc" 2>/dev/null | grep -q "^active" && return 0
    command -v service  >/dev/null 2>&1 && service "$svc" status 2>/dev/null | grep -qiE "running|started" && return 0
    command -v lssrc    >/dev/null 2>&1 && lssrc -s "$svc" 2>/dev/null | grep -qi "active" && return 0
    command -v svcs     >/dev/null 2>&1 && svcs -H "$svc" 2>/dev/null | grep -q "^online" && return 0
    ps -ef 2>/dev/null | grep -v grep | grep -qiw "$svc" && return 0
    return 1
}
get_pam_files() {
    case "$OS_FAMILY" in
    AIX)     echo "/etc/security/user /etc/security/login.cfg" ;;
    SOLARIS) echo "/etc/pam.conf /etc/security/policy.conf /etc/default/login" ;;
    HPUX)    echo "/etc/pam.conf /etc/default/security" ;;
    *)
        case "$OS_DISTRO" in
        RHEL|CENTOS|ORACLE|AMZN)
            [ "${OS_MAJOR:-0}" -ge 8 ] 2>/dev/null && \
                echo "/etc/pam.d/system-auth /etc/pam.d/password-auth" || \
                echo "/etc/pam.d/system-auth /etc/pam.d/password-auth" ;;
        UBUNTU|DEBIAN) echo "/etc/pam.d/common-auth /etc/pam.d/common-password" ;;
        SLES)   echo "/etc/pam.d/common-auth /etc/pam.d/login" ;;
        *)
            for _pf in /etc/pam.d/system-auth /etc/pam.d/password-auth /etc/pam.d/common-auth /etc/pam.d/common-password; do
                [ -f "$_pf" ] && printf '%s ' "$_pf"
            done
            echo ;;
        esac ;;
    esac
}
pkg_installed() {
    local pkg="$1"
    case "$OS_FAMILY" in
    AIX)     lslpp -l "$pkg" >/dev/null 2>&1 ;;
    SOLARIS) pkginfo "$pkg" >/dev/null 2>&1 ;;
    HPUX)    swlist "$pkg" >/dev/null 2>&1 ;;
    *)
        case "$OS_DISTRO" in
        UBUNTU|DEBIAN) dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null | grep -q "install ok installed" ;;
        *)             rpm -q "$pkg" >/dev/null 2>&1 ;;
        esac ;;
    esac
}
pkg_update_available() {
    local pkg="$1"
    case "$OS_DISTRO" in
    UBUNTU|DEBIAN) command -v apt >/dev/null 2>&1 && apt list --upgradable "$pkg" 2>/dev/null | awk 'NR>1{print $1}' | grep -Eq "^${pkg}(/|$)" ;;
    *)  if command -v dnf >/dev/null 2>&1; then
            dnf -q check-update "$pkg" 2>/dev/null | grep -q "^$pkg"
        elif command -v yum >/dev/null 2>&1; then
            yum -q check-update "$pkg" 2>/dev/null | grep -q "^$pkg"
        else return 1; fi ;;
    esac
}
service_exists_any() {
    for svc in "$@"; do
        if command -v systemctl >/dev/null 2>&1; then
            systemctl list-unit-files --type=service 2>/dev/null | awk '{print $1}' | grep -qx "${svc}.service" && return 0
        fi
        [ -f "/etc/init.d/$svc" ] && return 0
    done
    return 1
}

# ================================================================
# 주요정보통신기반시설 기술적 취약점 분석·평가 (U-시리즈) 함수
# ================================================================

_perm_over() { [ -n "$1" ] && [ $(( 8#$1 & ~8#$2 & 8#7777 )) -ne 0 ] 2>/dev/null; }   # 권한 $1 이 기준 $2 를 넘는 비트 보유
_check_file_perm() {
    local code="$1" file="$2" max="$3" req_owner="${4:-root}" desc="$5"
    evd "$code" "ls -la $file 2>/dev/null"
    [ -e "$file" ] || [ -L "$file" ] || { result "$code|양호|${desc} 미존재 - 권한을 점검할 파일 없음"; return; }
    local perm owner
    perm=$(get_perm "$file"); owner=$(get_owner "$file")
    if ! echo " ${req_owner//|/ } " | grep -q " ${owner} "; then
        result "$code|취약|${desc} 소유자=${owner} (${req_owner//|/ 또는 } 필요)"
    elif [ -z "$perm" ] || _perm_over "$perm" "$max"; then
        result "$code|취약|${desc} 권한=${perm:-확인불가} (${max} 이하 필요)"
    else
        result "$code|양호|${desc} 소유자=${owner}, 권한=${perm}"
    fi
}

check_U01() {
    evd "U-01" "grep -i PermitRootLogin /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf /opt/ssh/etc/sshd_config 2>/dev/null"
    local tel=0
    { is_running telnetd || is_running in.telnetd || grep -v '^#' /etc/inetd.conf 2>/dev/null | grep -q telnet; } && tel=1
    [ $tel -eq 1 ] && evd "U-01" "cat /etc/securetty 2>/dev/null | grep -E '^pts|^console'; grep pam_securetty /etc/pam.d/login 2>/dev/null"
    case "$OS_FAMILY" in
    AIX)
        local val=$(awk '/^root:/{f=1;next} /^[^ \t*#]/{f=0} f' /etc/security/user 2>/dev/null | grep -w "rlogin" | awk -F= '{gsub(/ /,"",$2);print $2}' | head -1)
        local sv=$(grep -i "^PermitRootLogin" /etc/ssh/sshd_config 2>/dev/null | awk '{print tolower($2)}' | head -1)
        if [ "$val" = "false" ] && [ "$sv" = "no" ]; then result "U-01|양호|root rlogin=false, PermitRootLogin=no"
        else result "U-01|취약|root rlogin=${val:-미설정(기본 true)}, PermitRootLogin=${sv:-미설정}"; fi ;;
    *)
        local val="" f
        for f in /etc/ssh/sshd_config.d/*.conf; do
            [ -f "$f" ] || continue
            val=$(grep -i "^[[:space:]]*PermitRootLogin" "$f" 2>/dev/null | awk '{print $2}' | head -1); [ -n "$val" ] && break
        done
        for f in /etc/ssh/sshd_config /opt/ssh/etc/sshd_config; do
            [ -z "$val" ] && [ -f "$f" ] && val=$(grep -i "^[[:space:]]*PermitRootLogin" "$f" 2>/dev/null | awk '{print $2}' | head -1)
        done
        local why=""
        if [ "$(echo "$val" | tr 'A-Z' 'a-z')" != "no" ]; then
            why="SSH PermitRootLogin=${val:-미설정(기본값 root 로그인 허용)}"
        fi
        if [ $tel -eq 1 ] && grep -qE '^pts' /etc/securetty 2>/dev/null; then why="${why:+${why} / }Telnet 사용, /etc/securetty 에 pts 허용"; fi
        if [ -n "$why" ]; then result "U-01|취약|${why} (가이드: PermitRootLogin No)"
        else result "U-01|양호|PermitRootLogin=no$([ $tel -eq 1 ] && echo ', Telnet securetty pts 미허용')"; fi ;;
    esac
}

check_U02() {
    evd "U-02" "grep -vE '^[[:space:]]*#' /etc/security/pwquality.conf 2>/dev/null | grep -v '^$'; grep -hE 'pam_pwquality|pam_cracklib|pam_pwhistory|remember=' /etc/pam.d/system-auth /etc/pam.d/password-auth /etc/pam.d/common-password 2>/dev/null | grep -v '^#'; grep -E '^PASS_(MAX|MIN)_DAYS|^PASS_MIN_LEN' /etc/login.defs 2>/dev/null; grep -E 'HISTORY|PASSLENGTH|MIN(DIGIT|UPPER|LOWER|SPECIAL|NONALPHA|ALPHA)|MAX(WEEKS|DAYS)|MIN(WEEKS|DAYS)' /etc/default/passwd 2>/dev/null; grep -E 'PASSWORD_(MIN|MAX|HISTORY)|MIN_PASSWORD_LENGTH' /etc/default/security 2>/dev/null"
    local bad="" cur="" ml="" mx="" mn="" hi="" cls=0
    case "$OS_FAMILY" in
    AIX)
        evd "U-02" "lsuser -a minlen minalpha minother maxage minage histsize default 2>/dev/null"
        _av() { _aix_default | grep -w "$1" | grep -oE '[0-9]+' | head -1; }
        ml=$(_av minlen); local ma=$(_av minalpha) mo=$(_av minother); mx=$(_av maxage); mn=$(_av minage); hi=$(_av histsize)
        [ "${ma:-0}" -ge 1 ] 2>/dev/null && cls=$((cls+1)); [ "${mo:-0}" -ge 1 ] 2>/dev/null && cls=$((cls+2))
        [ -n "$mx" ] && mx=$((mx*7)); [ -n "$mn" ] && mn=$((mn*7))
        cur="minlen=${ml:-미설정}, minalpha=${ma:-미설정}, minother=${mo:-미설정}, maxage=${mx:-미설정}일, minage=${mn:-미설정}일, histsize=${hi:-미설정}" ;;
    SOLARIS)
        local f=/etc/default/passwd
        ml=$(grep '^PASSLENGTH=' $f 2>/dev/null | cut -d= -f2); hi=$(grep '^HISTORY=' $f 2>/dev/null | cut -d= -f2)
        local w=$(grep '^MAXWEEKS=' $f 2>/dev/null | cut -d= -f2); [ -n "$w" ] && mx=$((w*7))
        w=$(grep '^MINWEEKS=' $f 2>/dev/null | cut -d= -f2); [ -n "$w" ] && mn=$((w*7))
        cls=$(grep -cE '^(MINDIGIT|MINSPECIAL|MINUPPER|MINLOWER|MINNONALPHA|MINALPHA)=[1-9]' $f 2>/dev/null)
        cur="PASSLENGTH=${ml:-미설정}, 문자종류 최소입력 ${cls}종, MAXWEEKS→${mx:-미설정}일, MINWEEKS→${mn:-미설정}일, HISTORY=${hi:-미설정}" ;;
    HPUX)
        local f=/etc/default/security
        ml=$(grep '^MIN_PASSWORD_LENGTH=' $f 2>/dev/null | cut -d= -f2); hi=$(grep '^PASSWORD_HISTORY_DEPTH=' $f 2>/dev/null | cut -d= -f2)
        mx=$(grep '^PASSWORD_MAXDAYS=' $f 2>/dev/null | cut -d= -f2); mn=$(grep '^PASSWORD_MINDAYS=' $f 2>/dev/null | cut -d= -f2)
        cls=$(grep -cE '^PASSWORD_MIN_(DIGIT|SPECIAL|UPPER_CASE|LOWER_CASE)_CHARS=[1-9]' $f 2>/dev/null)
        cur="MIN_PASSWORD_LENGTH=${ml:-미설정}, 문자종류 최소입력 ${cls}종, MAXDAYS=${mx:-미설정}, MINDAYS=${mn:-미설정}, HISTORY=${hi:-미설정}" ;;
    *)
        local cfg="" f
        for f in /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf; do
            [ -f "$f" ] && cfg="${cfg} $(grep -vE '^[[:space:]]*#' "$f" 2>/dev/null | tr '\n' ' ')"
        done
        for f in $(get_pam_files) /etc/pam.d/password-auth /etc/pam.d/common-password /etc/pam.d/system-auth; do
            [ -f "$f" ] && cfg="${cfg} $(grep -vE '^[[:space:]]*#' "$f" 2>/dev/null | grep -E 'pam_pwquality|pam_cracklib|pam_pwhistory|pam_unix' | tr '\n' ' ')"
        done
        _pv() { echo "$cfg" | grep -oE "(^|[[:space:]])$1[[:space:]]*=[[:space:]]*-?[0-9]+" | tail -1 | grep -oE -- '-?[0-9]+$'; }
        ml=$(_pv minlen); local dc=$(_pv dcredit) uc=$(_pv ucredit) lc=$(_pv lcredit) oc=$(_pv ocredit) mc=$(_pv minclass)
        hi=$(_pv remember)
        [ -z "$ml" ] && ml=$(grep '^PASS_MIN_LEN' /etc/login.defs 2>/dev/null | awk '{print $2}')
        mx=$(grep '^PASS_MAX_DAYS' /etc/login.defs 2>/dev/null | awk '{print $2}'); mn=$(grep '^PASS_MIN_DAYS' /etc/login.defs 2>/dev/null | awk '{print $2}')
        [ "${dc:-0}" -lt 0 ] 2>/dev/null && cls=$((cls+1)); [ "${oc:-0}" -lt 0 ] 2>/dev/null && cls=$((cls+1))
        { [ "${uc:-0}" -lt 0 ] 2>/dev/null || [ "${lc:-0}" -lt 0 ] 2>/dev/null; } && cls=$((cls+1))
        [ "${mc:-0}" -ge 3 ] 2>/dev/null && cls=3
        cur="minlen=${ml:-미설정}, dcredit=${dc:-미설정}, ucredit=${uc:-미설정}, lcredit=${lc:-미설정}, ocredit=${oc:-미설정}$([ -n "$mc" ] && echo ", minclass=${mc}"), PASS_MAX_DAYS=${mx:-미설정}, PASS_MIN_DAYS=${mn:-미설정}, remember=${hi:-미설정}" ;;
    esac
    [ "${ml:-0}" -ge 8 ] 2>/dev/null || bad="${bad}, 최소길이 8자 미만"
    [ "$cls" -ge 3 ] 2>/dev/null || bad="${bad}, 영문·숫자·특수문자 조합 미설정"
    { [ -n "$mx" ] && [ "$mx" -gt 0 ] 2>/dev/null && [ "$mx" -le 90 ] 2>/dev/null; } || bad="${bad}, 최대 사용기간 90일 초과/미설정"
    [ "${mn:-0}" -ge 1 ] 2>/dev/null || bad="${bad}, 최소 사용기간 1일 미만"
    [ "${hi:-0}" -ge 4 ] 2>/dev/null || bad="${bad}, 최근 비밀번호 기억 4회 미만/미설정"
    [ -n "$bad" ] && result "U-02|취약|비밀번호 관리정책 미흡: ${bad#, } (${cur})" || result "U-02|양호|비밀번호 관리정책 설정 (${cur})"
}

check_U03() {
    evd "U-03" "grep -E 'deny|pam_tally|pam_faillock' /etc/pam.d/system-auth /etc/pam.d/common-auth 2>/dev/null | grep -v '^#'"
    case "$OS_FAMILY" in
    AIX)
        local lc=$(_aix_default | grep "loginretries" | grep -oE '[0-9]+' | head -1)
        [ "${lc:-0}" -gt 0 ] 2>/dev/null && [ "${lc}" -le 10 ] 2>/dev/null && \
            result "U-03|양호|AIX loginretries=${lc}" || result "U-03|취약|AIX loginretries=${lc:-미설정}" ;;
    *)
        local deny=""
        for f in $(get_pam_files) /etc/pam.d/password-auth; do
            [ -f "$f" ] || continue
            deny=$(grep -v "^#" "$f" 2>/dev/null | grep -E "pam_faillock|pam_tally2" | grep -oE 'deny=[0-9]+' | head -1 | cut -d= -f2)
            [ -n "$deny" ] && break
        done
        [ -n "$deny" ] && [ "$deny" -le 10 ] 2>/dev/null && \
            result "U-03|양호|계정 잠금 임계값=${deny}" || result "U-03|취약|계정 잠금 임계값 미설정 (deny=${deny:-미설정})" ;;
    esac
}

check_U04() {
    evd "U-04" "ls -la /etc/shadow /etc/security/passwd /etc/passwd 2>/dev/null; awk -F: '\$2!=\"x\" && \$2!=\"*\" && \$2!=\"!\" {print \$1\": 비밀번호 필드=\"(\$2==\"\"?\"(빈 값)\":\"x 아님\")}' /etc/passwd 2>/dev/null"
    case "$OS_FAMILY" in
    AIX) [ -f /etc/security/passwd ] && result "U-04|양호|AIX 비밀번호를 /etc/security/passwd 에 분리 저장" || result "U-04|취약|AIX /etc/security/passwd 없음" ;;
    HPUX)
        if [ -f /etc/shadow ] || [ -d /tcb/files/auth ]; then result "U-04|양호|HP-UX $([ -d /tcb/files/auth ] && echo 'Trusted Mode(/tcb)' || echo '/etc/shadow') 사용"
        else result "U-04|취약|HP-UX shadow·Trusted Mode 미사용 (비밀번호가 /etc/passwd 에 저장)"; fi ;;
    *)
        local np; np=$(awk -F: '$2!="x" && $2!="*" && $2!="!" && $2!="!!" {print $1}' /etc/passwd 2>/dev/null | tr '\n' ' ')
        if [ ! -f /etc/shadow ]; then result "U-04|취약|/etc/shadow 없음 - 쉐도우 비밀번호 미사용"
        elif [ -n "$np" ]; then result "U-04|취약|/etc/passwd 에 비밀번호 필드가 x 가 아닌 계정: ${np% } (쉐도우 미사용 계정)"
        else result "U-04|양호|쉐도우 비밀번호 사용 (/etc/shadow, /etc/passwd 비밀번호 필드 x)"; fi ;;
    esac
}

check_U05() {
    evd "U-05" "awk -F: '\$3==0 && \$1!=\"root\"' /etc/passwd 2>/dev/null"
    local found=$(awk -F: '$3==0 && $1!="root" {print $1}' /etc/passwd 2>/dev/null)
    [ -n "$found" ] && result "U-05|취약|UID 0 계정: $(echo $found | tr '\n' ',')" || result "U-05|양호|root 외 UID 0 없음"
}

check_U06() {
    evd "U-06" "grep -v '^#' /etc/pam.d/su 2>/dev/null | grep pam_wheel; ls -l $(command -v su 2>/dev/null || echo /bin/su); awk -F: '\$3>=500 && \$7!~/(nologin|false)\$/ {print \$1, \$3, \$7}' /etc/passwd 2>/dev/null"
    local users; users=$(awk -F: '$3>=500 && $3<60000 && $7!~/(nologin|false)$/ {print $1}' /etc/passwd 2>/dev/null | tr '\n' ' ')
    local sub; sub=$(command -v su 2>/dev/null || echo /bin/su)
    local sp; sp=$(get_perm "$sub")
    if grep -v "^#" /etc/pam.d/su 2>/dev/null | grep -q "pam_wheel"; then
        result "U-06|양호|su 사용 그룹 제한 (pam_wheel)"
    elif [ -n "$sp" ] && ! _perm_over "$sp" 4750 && [ "$(ls -l "$sub" 2>/dev/null | awk '{print $4}')" != "root" ]; then
        result "U-06|양호|su 명령어 권한 ${sp}, 그룹 $(ls -l "$sub" | awk '{print $4}') 으로 사용 제한"
    elif [ -z "$users" ]; then
        result "U-06|양호|일반 사용자 계정 없음 (root 만 사용 - 가이드상 su 제한 불필요)"
    else
        result "U-06|취약|su 명령어 사용 그룹 제한 미설정 (일반 사용자: ${users% })"
    fi
}

check_U07() {
    evd "U-07" "lastlog 2>/dev/null | grep -v 'Never' | tail -20; awk -F: '\$7 !~ /nologin|false/ {print \$1,\$7}' /etc/passwd 2>/dev/null"
    local inactive=""
    while IFS= read -r line; do
        local user=$(echo "$line" | awk '{print $1}')
        local last_date=$(echo "$line" | awk '{print $(NF-2), $(NF-1), $NF}')
        [ -z "$last_date" ] && continue
        inactive="${inactive} ${user}"
    done < <(lastlog 2>/dev/null | awk 'NR>1 && /Never logged in/' | head -20)
    [ -n "$inactive" ] && result "U-07|수동확인|미로그인 계정:${inactive} (불필요 여부 확인)" || \
        result "U-07|수동확인|미사용 계정 수동 확인 (lastlog 결과 참조)"
}

check_U08() {
    evd "U-08" "grep -E '^(root|wheel|sudo|admin|system|sys):' /etc/group 2>/dev/null"
    local info="" grp members
    for grp in root wheel sudo admin system; do
        members=$(grep "^${grp}:" /etc/group 2>/dev/null | cut -d: -f4 | tr ',' '\n' | grep -vxE 'root|' | tr '\n' ',' | sed 's/,$//')
        [ -n "$members" ] && info="${info} ${grp}:[${members}]"
    done
    [ -n "$info" ] && result "U-08|수동확인|관리자 그룹 구성원:${info} - 불필요한 계정 여부 확인" || result "U-08|양호|관리자 그룹에 root 외 구성원 없음"
}

check_U09() {
    evd "U-09" "awk -F: '\$3>=500 {print \$1\":\"\$3\":\"\$4}' /etc/group 2>/dev/null; awk -F: '{print \$4}' /etc/passwd 2>/dev/null | sort -u | tr '\n' ' '"
    # 구성원이 없는 그룹(보조 구성원 없음 + 어떤 계정의 기본 그룹도 아님), 일반 그룹(GID 500 이상) 대상
    local prim; prim=" $(awk -F: '{print $4}' /etc/passwd 2>/dev/null | sort -u | tr '\n' ' ') "
    local empty; empty=$(awk -F: '$3>=500 && $3<60000 && $4=="" {print $1":"$3}' /etc/group 2>/dev/null | while IFS=: read -r g id; do case "$prim" in *" $id "*) ;; *) printf '%s(%s) ' "$g" "$id" ;; esac; done)
    [ -n "$empty" ] && result "U-09|수동확인|구성원이 없는 그룹: ${empty% } - 시스템 관리·운용에 불필요하면 제거" || result "U-09|양호|구성원이 없는 일반 그룹 없음"
}

check_U10() {
    evd "U-10" "awk -F: '{print \$3}' /etc/passwd | sort -n | uniq -d"
    local dup=$(awk -F: '{print $3}' /etc/passwd 2>/dev/null | sort -n | uniq -d)
    [ -n "$dup" ] && result "U-10|취약|중복 UID: $(echo $dup | tr '\n' ',')" || result "U-10|양호|중복 UID 없음"
}

check_U11() {
    evd "U-11" "grep -E '^(daemon|bin|sys|adm|listen|nobody|nobody4|noaccess|diag|operator|games|gopher):' /etc/passwd 2>/dev/null"
    local vuln=$(grep -E '^(daemon|bin|sys|adm|listen|nobody|nobody4|noaccess|diag|operator|games|gopher):' /etc/passwd 2>/dev/null | awk -F: '$7 !~ /(nologin|false)$/ {printf " %s(%s)", $1, ($7==""?"기본쉘":$7)}')
    [ -n "$vuln" ] && result "U-11|취약|로그인 불필요 계정에 쉘 부여:${vuln}" || result "U-11|양호|로그인 불필요 계정(daemon·bin·sys·adm·listen·nobody·operator·games 등)에 nologin/false 부여"
}

check_U12() {
    evd "U-12" "grep -rh TMOUT /etc/profile /etc/bashrc /root/.bashrc 2>/dev/null | grep -v '^#'"
    local tmout=""
    for f in /etc/profile /etc/bashrc /etc/bash.bashrc /etc/environment /root/.bashrc /root/.profile /etc/profile.d/*.sh; do
        [ -f "$f" ] || continue
        local t=$(grep -h "TMOUT\|tmout" "$f" 2>/dev/null | grep -v "^#" | grep -oE "[0-9]+" | head -1)
        [ -n "$t" ] && tmout=$t && break
    done
    if [ -z "$tmout" ]; then result "U-12|취약|TMOUT 미설정"
    elif [ "$tmout" -le 600 ] 2>/dev/null; then result "U-12|양호|TMOUT=${tmout}초"
    else result "U-12|취약|TMOUT=${tmout}초 (600초 초과)"; fi
}

check_U13() {
    evd "U-13" "grep -E '^ENCRYPT_METHOD|^MD5_CRYPT_ENAB' /etc/login.defs 2>/dev/null; awk -F: '\$2!~/^[!*]|^$/{print \$1,substr(\$2,1,4)}' /etc/shadow 2>/dev/null | head -10; grep -i PasswordAuthentication /etc/ssh/sshd_config 2>/dev/null | grep -v '^#'"
    local weak="" algo=""
    algo=$(grep -E '^\s*ENCRYPT_METHOD' /etc/login.defs 2>/dev/null | awk '{print $2}' | tail -1)
    while IFS=: read -r user hash rest; do
        case "$hash" in
            \$1\$*) weak="${weak} ${user}(MD5)" ;;
            \$2*|\$5\$*|\$6\$*|\$y\$*) ;;
            '!'*|'*'|''|'!!') ;;
            *) echo "$hash" | grep -qE '^[A-Za-z0-9./]{13}$' && weak="${weak} ${user}(DES)" ;;   # 잠금 표기(*LK*, !, x 등)는 제외
        esac
    done < /etc/shadow 2>/dev/null
    if [ -n "$weak" ]; then
        result "U-13|취약|취약한 해시 알고리즘 사용:${weak}"
    elif [ -f /etc/shadow ]; then
        result "U-13|양호|shadow 파일 사용, 암호화 방식=${algo:-SHA512}"
    else
        result "U-13|취약|/etc/shadow 미사용 (패스워드 암호화 불확실)"
    fi
}

check_U14() {
    evd "U-14" "echo \$PATH"
    if echo "$PATH" | grep -qE '(^|:)\.(:|$)'; then
        result "U-14|취약|PATH에 '.' 포함"
    else
        result "U-14|양호|PATH에 '.' 미포함"
    fi
}

check_U15() {
    evd "U-15" "_to 30 find / -xdev \\( -nouser -o -nogroup \\) ! -path '/proc/*' ! -path '/sys/*' 2>/dev/null | head -20"
    local cnt=$(_to 30 find / -xdev \( -nouser -o -nogroup \) ! -path "/proc/*" ! -path "/sys/*" 2>/dev/null | wc -l)
    [ "${cnt:-0}" -gt 0 ] 2>/dev/null && \
        result "U-15|취약|소유자/그룹 없는 파일 ${cnt}개" || result "U-15|양호|소유자/그룹 없는 파일 없음"
}

check_U16() { _check_file_perm "U-16" "/etc/passwd" 644 "root" "/etc/passwd"; }

check_U17() {
    local dirs="/etc/rc.d/init.d /etc/init.d /etc/rc.d /etc/rc.local /etc/rc.d/rc.local /sbin/init.d /etc/rc.config.d /etc/systemd/system /usr/lib/systemd/system"
    evd "U-17" "ls -l /etc/rc.local /etc/rc.d/rc.local 2>/dev/null; ls -l /etc/init.d/ /etc/rc.d/init.d/ /sbin/init.d/ 2>/dev/null | head -30; find /etc/systemd/system /usr/lib/systemd/system -maxdepth 1 -type f -perm -002 2>/dev/null | head -20"
    local vuln="" f
    for f in $(find $dirs -maxdepth 1 -type f 2>/dev/null); do
        local o=$(get_owner "$f") p=$(get_perm "$f")
        [ "$o" != "root" ] && [ "$o" != "bin" ] && vuln="${vuln} ${f}(소유자=${o})"
        _perm_over "$p" 7755 && vuln="${vuln} ${f}(${p})"
    done
    [ -n "$vuln" ] && result "U-17|취약|시작 스크립트 기준 위반(소유자 root, 일반 사용자 쓰기 권한 없음):$(echo $vuln | cut -c1-400)" || result "U-17|양호|시스템 시작 스크립트 소유자 root, 일반 사용자 쓰기 권한 없음"
}

check_U18() {
    case "$OS_FAMILY" in
    AIX) _check_file_perm "U-18" "/etc/security/passwd" 400 "root" "/etc/security/passwd" ;;
    *)   _check_file_perm "U-18" "/etc/shadow" 400 "root" "/etc/shadow" ;;
    esac
}

check_U19() { _check_file_perm "U-19" "/etc/hosts" 644 "root" "/etc/hosts"; }

check_U20() {
    local found=0 f
    for f in /etc/inetd.conf /etc/xinetd.conf; do
        [ -f "$f" ] && { found=1; _check_file_perm "U-20" "$f" 600 "root" "$f"; }
    done
    [ $found -eq 0 ] && { evd "U-20" "ls -la /etc/xinetd.conf /etc/inetd.conf 2>/dev/null"; result "U-20|양호|inetd/xinetd 미사용 (/etc/inetd.conf·/etc/xinetd.conf 없음 - 권한을 점검할 파일 없음)"; }
}

check_U21() {
    local found=0 f
    for f in /etc/syslog.conf /etc/rsyslog.conf; do
        [ -f "$f" ] && { found=1; _check_file_perm "U-21" "$f" 640 "root|bin|sys" "$f"; }
    done
    [ $found -eq 0 ] && { evd "U-21" "ls -la /etc/rsyslog.conf /etc/syslog.conf 2>/dev/null"; result "U-21|양호|syslog.conf 없음 - 권한을 점검할 파일 없음 (로깅 정책은 U-66)"; }
}

check_U22() { _check_file_perm "U-22" "/etc/services" 644 "root|bin|sys" "/etc/services"; }

check_U23() {
    evd "U-23" "_to 30 find / -perm /6000 -type f 2>/dev/null | head -30"
    local dangerous="nmap perl python python3 php ruby bash sh find wget curl nc netcat awk vim gdb strace"
    local found_vuln=""
    for bin in $dangerous; do
        local bp=$(command -v "$bin" 2>/dev/null); [ -z "$bp" ] && continue
        [ -u "$bp" ] && found_vuln="${found_vuln} ${bp}(SUID)"
        [ -g "$bp" ] && found_vuln="${found_vuln} ${bp}(SGID)"
    done
    [ -n "$found_vuln" ] && result "U-23|취약|위험 SUID/SGID:${found_vuln}" || {
        local cnt=$(_to 30 find / -perm /6000 -type f 2>/dev/null | wc -l)
        result "U-23|양호|위험 SUID/SGID 미발견 (전체 ${cnt}개)"
    }
}

check_U24() {
    evd "U-24" "for h in \$(awk -F: '\$7!~/(nologin|false)\$/{print \$6}' /etc/passwd | sort -u); do ls -l \$h/.profile \$h/.kshrc \$h/.cshrc \$h/.bashrc \$h/.bash_profile \$h/.login \$h/.exrc \$h/.netrc 2>/dev/null; done | head -40"
    local vuln="" user home f
    while IFS=: read -r user _ _ _ _ home shell; do
        case "$shell" in *nologin|*false) continue ;; esac
        [ -n "$home" ] && [ -d "$home" ] || continue
        for f in .profile .kshrc .cshrc .bashrc .bash_profile .login .exrc .netrc .bash_login; do
            [ -f "$home/$f" ] && [ ! -L "$home/$f" ] || continue
            local perm=$(get_perm "$home/$f") owner=$(get_owner "$home/$f")
            [ "$owner" != "root" ] && [ "$owner" != "$user" ] && vuln="${vuln} ${home}/${f}(소유자=${owner})"
            _perm_over "$perm" 755 && vuln="${vuln} ${home}/${f}(${perm})"
        done
    done < /etc/passwd
    [ -n "$vuln" ] && result "U-24|취약|환경변수 파일 소유자/쓰기 권한 이상:${vuln}" || result "U-24|양호|홈 디렉터리 환경변수 파일 소유자(root/해당 계정)·쓰기 권한(root·소유자만) 적절"
}

check_U25() {
    evd "U-25" "_to 30 find / -xdev -perm -0002 -type f ! -path '/proc/*' ! -path '/sys/*' ! -path '/dev/*' ! -path '/tmp/*' ! -path '/var/tmp/*' 2>/dev/null | head -30"
    local cnt=$(_to 30 find / -xdev -perm -0002 -type f ! -path "/proc/*" ! -path "/sys/*" ! -path "/dev/*" ! -path "/tmp/*" ! -path "/var/tmp/*" 2>/dev/null | wc -l)
    # 가이드: 존재 시 '설정 이유 인지' 여부로 판단 → 스크립트로 판단 불가, 목록 확인
    [ "${cnt:-0}" -gt 0 ] 2>/dev/null && result "U-25|수동확인|world writable 파일 ${cnt}개 (증적 목록) - 설정 이유 확인, 불필요 시 취약(o-w 제거)" || result "U-25|양호|world writable 파일 없음"
}

check_U26() {
    evd "U-26" "_to 15 find /dev -type f 2>/dev/null | head -20"
    local cnt=$(_to 15 find /dev -type f ! -name "MAKEDEV" ! -name ".udev" 2>/dev/null | wc -l)
    [ "${cnt:-0}" -gt 0 ] 2>/dev/null && result "U-26|취약|/dev 비정상 파일 ${cnt}개" || result "U-26|양호|/dev 비정상 파일 없음"
}

check_U27() {
    evd "U-27" "ls -la /etc/hosts.equiv 2>/dev/null; for h in \$(awk -F: '{print \$6}' /etc/passwd | sort -u); do ls -la \$h/.rhosts 2>/dev/null; done; grep -H '+' /etc/hosts.equiv 2>/dev/null"
    local vuln="" files="" user home f
    [ -f /etc/hosts.equiv ] && files="/etc/hosts.equiv:root"
    while IFS=: read -r user _ _ _ _ home _; do
        [ -n "$home" ] && [ -f "$home/.rhosts" ] && files="${files} ${home}/.rhosts:${user}"
    done < /etc/passwd
    [ -z "$files" ] && { result "U-27|양호|/etc/hosts.equiv·\$HOME/.rhosts 파일 없음"; return; }
    for e in $files; do
        f="${e%:*}"; user="${e##*:}"
        local perm=$(get_perm "$f") owner=$(get_owner "$f")
        [ "$owner" != "root" ] && [ "$owner" != "$user" ] && vuln="${vuln} ${f}(소유자=${owner})"
        _perm_over "$perm" 600 && vuln="${vuln} ${f}(${perm})"
        grep -vE '^[[:space:]]*#' "$f" 2>/dev/null | grep -q '+' && vuln="${vuln} ${f}('+' 설정)"
    done
    [ -n "$vuln" ] && result "U-27|취약|${vuln# }" || result "U-27|양호|hosts.equiv/.rhosts 소유자·권한(600 이하) 적절, '+' 설정 없음"
}

check_U28() {
    evd "U-28" "cat /etc/hosts.allow /etc/hosts.deny 2>/dev/null | head -20"
    local has=0
    [ -f /etc/hosts.allow ] && [ -s /etc/hosts.allow ] && has=1
    [ -f /etc/hosts.deny ] && [ -s /etc/hosts.deny ] && has=1
    command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state 2>/dev/null | grep -q "running" && has=1
    command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "active" && has=1
    command -v iptables >/dev/null 2>&1 && iptables -n -L 2>/dev/null | grep -qE "ACCEPT|DROP|REJECT" && has=1
    [ $has -eq 1 ] && result "U-28|양호|접속 IP/포트 제한 설정됨" || result "U-28|수동확인|접속 제한 수동 확인"
}

check_U29() {
    evd "U-29" "ls -la /etc/hosts.lpd 2>/dev/null; cat /etc/hosts.lpd 2>/dev/null"
    [ -f /etc/hosts.lpd ] && _check_file_perm "U-29" "/etc/hosts.lpd" 600 "root" "/etc/hosts.lpd" || result "U-29|양호|/etc/hosts.lpd 미존재"
}

check_U30() {
    evd "U-30" "grep -ih umask /etc/profile /etc/bashrc /etc/login.defs 2>/dev/null | grep -v '^#'"
    local um=""
    for f in /etc/profile /etc/bashrc /etc/bash.bashrc /etc/login.defs; do
        [ -f "$f" ] || continue
        um=$(grep -iE "^[[:space:]]*umask|^UMASK" "$f" 2>/dev/null | grep -v "^#" | grep -oE '[0-9]{3,4}' | tail -1)
        [ -n "$um" ] && break
    done
    if [ -z "$um" ]; then result "U-30|취약|UMASK 미설정"
    elif echo "$um" | grep -qE '^0?0[2-7][2-7]$'; then result "U-30|양호|UMASK=${um}"
    else result "U-30|취약|UMASK=${um} (022 이상 필요)"; fi
}

check_U31() {
    evd "U-31" "awk -F: '\$3>=500{print \$1,\$6}' /etc/passwd 2>/dev/null | head -20"
    local vuln="" min_uid=500
    { [ "$OS_DISTRO" = "UBUNTU" ] || [ "$OS_DISTRO" = "DEBIAN" ]; } && min_uid=1000
    while IFS=: read -r user _ uid _ _ homedir _; do
        [ "${uid:-0}" -lt "$min_uid" ] 2>/dev/null && continue
        [ -z "$homedir" ] || [ "$homedir" = "/" ] && continue
        [ -d "$homedir" ] || continue
        local perm=$(get_perm "$homedir") owner=$(get_owner "$homedir")
        [ "$owner" != "$user" ] && vuln="${vuln} ${homedir}(소유자=${owner})"
        _perm_over "$perm" 7775 && vuln="${vuln} ${homedir}(${perm}, 타 사용자 쓰기)"
    done < /etc/passwd
    [ -n "$vuln" ] && result "U-31|취약|홈 디렉토리 이상:${vuln}" || result "U-31|양호|홈 디렉토리 권한 적절"
}

check_U32() {
    evd "U-32" "awk -F: '\$3>=500{print \$1,\$6}' /etc/passwd 2>/dev/null | head -20"
    local vuln="" min_uid=500
    { [ "$OS_DISTRO" = "UBUNTU" ] || [ "$OS_DISTRO" = "DEBIAN" ]; } && min_uid=1000
    while IFS=: read -r user _ uid _ _ homedir _; do
        [ "${uid:-0}" -lt "$min_uid" ] 2>/dev/null && continue
        [ -z "$homedir" ] || [ "$homedir" = "/" ] && continue
        [ -d "$homedir" ] || vuln="${vuln} ${user}(${homedir})"
    done < /etc/passwd
    [ -n "$vuln" ] && result "U-32|취약|홈 디렉토리 미존재:${vuln}" || result "U-32|양호|모든 홈 디렉토리 존재"
}

check_U33() {
    evd "U-33" "_to 30 find / -name '.*' -not -path '/proc/*' -not -path '/sys/*' -not -path '/dev/*' -not -path '/run/*' -type f 2>/dev/null | grep -vE '/\.(bash|profile|cshrc|ssh|gnupg|cache|config|local)' | head -20"
    result "U-33|수동확인|숨겨진 파일/디렉토리 수동 확인 (위 현황 참조)"
}

check_U34() {
    evd "U-34" "ps -ef 2>/dev/null | grep finger | grep -v grep"
    is_running in.fingerd || is_running fingerd && { result "U-34|취약|finger 서비스 실행 중"; return; }
    grep -v "^#" /etc/inetd.conf 2>/dev/null | grep -q finger && { result "U-34|취약|finger inetd 등록"; return; }
    result "U-34|양호|finger 서비스 비활성화"
}

check_U35() {
    evd "U-35" "grep -iE 'anonymous_enable' /etc/vsftpd/vsftpd.conf /etc/vsftpd.conf 2>/dev/null; grep -E '^(ftp|anonymous):' /etc/passwd 2>/dev/null; grep -vE '^[[:space:]]*[#;]' /etc/samba/smb.conf 2>/dev/null | grep -iE 'guest ok|public|map to guest'; grep -vE '^[[:space:]]*#' /etc/exports 2>/dev/null"
    local vuln="" f used=""
    for f in /etc/vsftpd.conf /etc/vsftpd/vsftpd.conf; do
        [ -f "$f" ] || continue; used="${used} vsFTP"
        grep -qiE '^[[:space:]]*anonymous_enable[[:space:]]*=[[:space:]]*YES' "$f" 2>/dev/null && vuln="${vuln} vsFTP anonymous_enable=YES"
    done
    for f in /etc/proftpd.conf /etc/proftpd/proftpd.conf; do
        [ -f "$f" ] || continue; used="${used} ProFTP"
        awk '/<Anonymous/{a=1} /<\/Anonymous>/{a=0} a && /^[[:space:]]*(User|UserAlias)[[:space:]]/' "$f" 2>/dev/null | grep -q . && vuln="${vuln} ProFTP <Anonymous> 사용"
    done
    if is_running in.ftpd || grep -vE '^[[:space:]]*#' /etc/inetd.conf 2>/dev/null | grep -qw ftp; then
        used="${used} 기본FTP"; grep -qE '^(ftp|anonymous):' /etc/passwd 2>/dev/null && vuln="${vuln} 기본FTP ftp/anonymous 계정 존재"
    fi
    if [ -f /etc/samba/smb.conf ]; then
        used="${used} Samba"
        grep -vE '^[[:space:]]*[#;]' /etc/samba/smb.conf 2>/dev/null | grep -qiE '^[[:space:]]*(guest ok|public)[[:space:]]*=[[:space:]]*yes' && vuln="${vuln} Samba guest ok/public=yes"
    fi
    if [ -f /etc/exports ] && grep -vE '^[[:space:]]*#' /etc/exports 2>/dev/null | grep -qE 'anonuid|all_squash|\(.*insecure'; then used="${used} NFS"; fi
    if [ -n "$vuln" ]; then result "U-35|취약|공유 서비스 익명 접근 허용:${vuln}"
    elif [ -n "$used" ]; then result "U-35|양호|공유 서비스(${used# }) 익명 접근 제한"
    else result "U-35|양호|익명 접근 가능한 공유 서비스(FTP·Samba) 미사용"; fi
}

check_U36() {
    evd "U-36" "ps -ef 2>/dev/null | grep -E 'rsh|rlogin|rexec' | grep -v grep"
    local found=""
    for svc in rsh rlogin rexec in.rshd in.rlogind in.rexecd; do
        is_running "$svc" && found="${found} ${svc}"
    done
    grep -v "^#" /etc/inetd.conf 2>/dev/null | grep -qE "rsh|rlogin|rexec" && found="${found} [inetd]"
    [ -n "$found" ] && result "U-36|취약|r 서비스 실행:${found}" || result "U-36|양호|r 서비스 비활성화"
}

check_U37() {
    local cc=$(command -v crontab 2>/dev/null) ac=$(command -v at 2>/dev/null)
    evd "U-37" "ls -l ${cc:-/usr/bin/crontab} ${ac:-/usr/bin/at} /etc/crontab /etc/cron.allow /etc/cron.deny /etc/at.allow /etc/at.deny 2>/dev/null; ls -l /etc/cron.d /var/spool/cron /var/spool/cron/crontabs /var/spool/at /var/spool/cron/atjobs 2>/dev/null | head -30"
    local vuln="" f p o
    for f in $cc $ac; do
        p=$(get_perm "$f"); _perm_over "$p" 4750 && vuln="${vuln} ${f}(${p}, 일반 사용자 실행 가능)"
    done
    for f in /etc/crontab /etc/cron.allow /etc/cron.deny /etc/at.allow /etc/at.deny /etc/cron.d/* /var/spool/cron/* /var/spool/cron/crontabs/* /var/spool/at/* /var/spool/cron/atjobs/*; do
        [ -f "$f" ] || continue
        p=$(get_perm "$f"); o=$(get_owner "$f")
        case "$f" in /var/spool/*) ;; *) [ "$o" != "root" ] && vuln="${vuln} ${f}(소유자=${o})" ;; esac
        _perm_over "$p" 640 && vuln="${vuln} ${f}(${p})"
    done
    [ -n "$vuln" ] && result "U-37|취약|crontab·at 기준 위반(명령어 750 이하, 관련 파일 640 이하):$(echo $vuln | cut -c1-400)" || result "U-37|양호|crontab·at 명령어 일반 사용자 실행 제한, cron·at 관련 파일 640 이하"
}

check_U38() {
    evd "U-38" "grep -vE '^[[:space:]]*#' /etc/inetd.conf 2>/dev/null | grep -E '^(echo|discard|daytime|chargen)'; grep -lE 'disable[[:space:]]*=[[:space:]]*no' /etc/xinetd.d/* 2>/dev/null; systemctl list-units --all 2>/dev/null | grep -E '(echo|discard|daytime|chargen)[-@.]'; (ss -tuln 2>/dev/null || netstat -tuln 2>/dev/null) | grep -E '[:.](7|9|13|19|123|53|161|25)[[:space:]]'"
    local found="" f
    grep -vE '^[[:space:]]*#' /etc/inetd.conf 2>/dev/null | grep -qE '^(echo|discard|daytime|chargen)[[:space:]]' && found="${found} [inetd]"
    for f in /etc/xinetd.d/*; do
        [ -f "$f" ] || continue
        grep -qE 'service[[:space:]]+(echo|discard|daytime|chargen)' "$f" 2>/dev/null && grep -qiE 'disable[[:space:]]*=[[:space:]]*no' "$f" 2>/dev/null && found="${found} $(basename "$f")(xinetd)"
    done
    systemctl list-units --all --no-legend 2>/dev/null | awk '{print $1}' | grep -E '^(echo|discard|daytime|chargen)' | grep -q . && found="${found} [systemd]"
    command -v svcs >/dev/null 2>&1 && svcs -H 2>/dev/null | grep online | grep -qE 'network/(echo|discard|daytime|chargen)' && found="${found} [SMF]"
    (ss -tuln 2>/dev/null || netstat -tuln 2>/dev/null) | grep -qE '[:.](7|9|13|19)[[:space:]]' && found="${found} [7/9/13/19 포트 LISTEN]"
    local ref=""
    (ss -tuln 2>/dev/null || netstat -tuln 2>/dev/null) | grep -qE '[:.]53[[:space:]]' && ref="${ref} DNS(53)"
    (ss -uln 2>/dev/null || netstat -uln 2>/dev/null) | grep -qE '[:.]123[[:space:]]' && ref="${ref} NTP(123)"
    (ss -uln 2>/dev/null || netstat -uln 2>/dev/null) | grep -qE '[:.]161[[:space:]]' && ref="${ref} SNMP(161)"
    (ss -tln 2>/dev/null || netstat -tln 2>/dev/null) | grep -qE '[:.]25[[:space:]]' && ref="${ref} SMTP(25)"
    local note=""; [ -n "$ref" ] && note=" / 참고: 가이드 예시 서비스 사용 중${ref} - 불필요 시 중지"
    [ -n "$found" ] && result "U-38|취약|DoS 취약 서비스(echo·discard·daytime·chargen) 활성:${found}${note}" || result "U-38|양호|echo·discard·daytime·chargen 비활성화${note}"
}

check_U39() {
    evd "U-39" "ps -ef 2>/dev/null | grep -E 'nfsd|mountd' | grep -v grep"
    is_running nfsd || is_running nfs-server || is_running mountd && \
        result "U-39|수동확인|NFS 실행 중 (필요 여부 확인)" || result "U-39|양호|NFS 미실행"
}

check_U40() {
    evd "U-40" "ls -l /etc/exports /etc/dfs/dfstab 2>/dev/null; grep -vE '^[[:space:]]*#' /etc/exports /etc/dfs/dfstab 2>/dev/null"
    local f=/etc/exports; [ "$OS_FAMILY" = "SOLARIS" ] && f=/etc/dfs/dfstab
    if ! { is_running nfsd || is_running nfs-server || is_running mountd; } && ! grep -qvE '^[[:space:]]*(#|$)' "$f" 2>/dev/null; then
        result "U-40|양호|NFS 서비스 미사용·공유 설정 없음 (가이드 조치 방법: 미사용 시 서비스 중지·비활성화 → 조치 상태)"; return
    fi
    local vuln="" p=$(get_perm "$f") o=$(get_owner "$f")
    [ -f "$f" ] || { result "U-40|수동확인|NFS 실행 중이나 ${f} 없음 - 공유 설정 확인 필요"; return; }
    [ "$o" != "root" ] && vuln="${vuln} ${f} 소유자=${o}"
    _perm_over "$p" 644 && vuln="${vuln} ${f} 권한=${p}"
    grep -vE '^[[:space:]]*#' "$f" 2>/dev/null | grep -qE '(^|[[:space:]])\*(\(|[[:space:]]|$)|rw=\*|-rw[[:space:]]*$' && vuln="${vuln} 전체 호스트(*) 공유"
    grep -vE '^[[:space:]]*#' "$f" 2>/dev/null | grep -qE '^[[:space:]]*/[^[:space:]]*[[:space:]]*$' && vuln="${vuln} 접근 호스트 미지정 공유"
    [ -n "$vuln" ] && result "U-40|취약|NFS 접근 통제 미흡:${vuln}" || result "U-40|양호|NFS 공유 접근 대상 지정, ${f} 소유자 root·권한 ${p}(644 이하)"
}

check_U41() {
    evd "U-41" "ps -ef 2>/dev/null | grep automount | grep -v grep"
    is_running autofs || is_running automountd && result "U-41|취약|automountd 실행 중" || result "U-41|양호|automountd 미실행"
}

check_U42() {
    evd "U-42" "rpcinfo -p 2>/dev/null | head -30; grep -vE '^[[:space:]]*#' /etc/inetd.conf 2>/dev/null | grep -i rpc"
    local found="" svc
    for svc in rpc.cmsd rpc.ttdbserverd ttdbserverd sadmind rusersd rpc.rusersd walld rpc.rwalld sprayd rpc.sprayd rstatd rpc.rstatd rpc.nisd rexd rpc.rexd rpc.pcnfsd rpc.statd rpc.ypupdated rpc.rquotad rquotad kcms_server cachefsd; do
        ps -e -o comm= 2>/dev/null | grep -qx "$svc" && found="${found} ${svc}"
    done
    local rp=$(rpcinfo -p 2>/dev/null | awk 'NR>1{print $5}' | grep -xE 'rusersd|walld|sprayd|rstatd|rquotad|status|ypupdated|cmsd|ttdbserver|sadmind|rexd|pcnfsd' | sort -u | tr '\n' ' ')
    [ -n "$rp" ] && found="${found} [rpcinfo: ${rp% }]"
    grep -vE '^[[:space:]]*#' /etc/inetd.conf 2>/dev/null | grep -qE 'rpc\.(cmsd|ttdbserverd|rusersd|rwalld|sprayd|rstatd|rexd|pcnfsd)' && found="${found} [inetd]"
    [ -n "$found" ] && result "U-42|취약|불필요 RPC 서비스 활성:${found}" || result "U-42|양호|가이드 대상 불필요 RPC 서비스 미사용"
}

check_U43() {
    evd "U-43" "ps -ef 2>/dev/null | grep -E 'ypserv|ypbind|yppasswdd|rpc.nisd' | grep -v grep"
    local found=""
    for svc in ypserv ypbind yppasswdd rpc.nisd; do is_running "$svc" && found="${found} ${svc}"; done
    [ -n "$found" ] && result "U-43|취약|NIS 서비스:${found}" || result "U-43|양호|NIS 미실행"
}

check_U44() {
    evd "U-44" "ps -ef 2>/dev/null | grep -E 'tftpd|talk|ntalk' | grep -v grep"
    local found=""
    for svc in tftpd in.tftpd talk ntalk in.talkd; do is_running "$svc" && found="${found} ${svc}"; done
    [ -n "$found" ] && result "U-44|취약|불필요 서비스:${found}" || result "U-44|양호|tftp/talk 비활성화"
}

check_U45() {
    evd "U-45" "ps -ef 2>/dev/null | grep -E 'sendmail|postfix|exim' | grep -v grep; sendmail -d0.1 -bt < /dev/null 2>/dev/null | head -3; postconf mail_version 2>/dev/null; exim -bV 2>/dev/null | head -1"
    local ver=""
    if is_running sendmail; then ver="Sendmail $(sendmail -d0.1 -bt < /dev/null 2>/dev/null | grep -oE 'Version [0-9][^ ]*' | head -1 | cut -d' ' -f2)"
    elif is_running master || is_running postfix; then ver="Postfix $(postconf -h mail_version 2>/dev/null)"
    elif is_running exim || is_running exim4; then ver="$(exim -bV 2>/dev/null | head -1 | grep -oE 'Exim version [0-9.]+')"
    else result "U-45|양호|메일 서비스(Sendmail·Postfix·Exim) 미사용 (가이드 조치 방법: 미사용 시 서비스 중지·비활성화 → 조치 상태)"; return; fi
    result "U-45|수동확인|${ver} - 제조사 최신 버전·보안 패치 적용 여부 확인"
}

check_U46() {
    evd "U-46" "ls -la /usr/sbin/sendmail /usr/lib/sendmail 2>/dev/null"
    local vuln=""
    for sm in /usr/sbin/sendmail /usr/lib/sendmail /usr/lib/sendmail.sendmail; do
        [ -e "$sm" ] || [ -L "$sm" ] || continue
        local perm=$(get_perm "$sm")
        if [ -n "$perm" ]; then
            local other_x=$((perm % 10))
            [ $((other_x & 1)) -eq 1 ] 2>/dev/null && vuln="${vuln} ${sm}(${perm})"
        fi
    done
    if is_running sendmail; then
        local cf=$(find /etc /etc/mail -name "sendmail.cf" 2>/dev/null | head -1)
        [ -n "$cf" ] && ! grep -qiE "restrictqrun|PrivacyOptions.*restrictqrun" "$cf" 2>/dev/null && vuln="${vuln} [restrictqrun 미설정]"
    fi
    if [ -n "$vuln" ]; then
        result "U-46|취약|일반사용자 Sendmail 실행 가능:${vuln}"
    else
        local sm_exist=0
        for sm in /usr/sbin/sendmail /usr/lib/sendmail; do { [ -e "$sm" ] || [ -L "$sm" ]; } && sm_exist=1; done
        [ $sm_exist -eq 0 ] && result "U-46|양호|Sendmail 바이너리 미존재" || result "U-46|양호|Sendmail 실행 권한 제한됨"
    fi
}

check_U47() {
    is_running sendmail || is_running postfix || { evd "U-47" "ps -ef 2>/dev/null | grep -E 'sendmail|postfix' | grep -v grep"; result "U-47|양호|SMTP 미실행"; return; }
    evd "U-47" "postconf smtpd_relay_restrictions smtpd_recipient_restrictions 2>/dev/null; grep -i relay /etc/mail/access 2>/dev/null | head -5"
    if is_running sendmail; then
        [ -f /etc/mail/access ] && result "U-47|수동확인|sendmail relay 설정 수동 확인" || result "U-47|취약|sendmail 릴레이 제한 미확인"
    elif is_running postfix; then
        local relay=$(postconf smtpd_relay_restrictions 2>/dev/null | awk -F= '{print $2}')
        [ -n "$relay" ] && result "U-47|수동확인|postfix relay=${relay}" || result "U-47|취약|postfix relay 미설정"
    fi
}

check_U48() {
    is_running sendmail || is_running postfix || { evd "U-48" "ps -ef 2>/dev/null | grep -E 'sendmail|postfix' | grep -v grep"; result "U-48|양호|SMTP 미실행"; return; }
    evd "U-48" "postconf disable_vrfy_command 2>/dev/null; grep -i PrivacyOptions /etc/mail/sendmail.cf /etc/sendmail.cf 2>/dev/null"
    if is_running sendmail; then
        local cf=$(find /etc /etc/mail -name "sendmail.cf" 2>/dev/null | head -1)
        if [ -n "$cf" ]; then
            local priv=$(grep "^O PrivacyOptions" "$cf" 2>/dev/null)
            echo "$priv" | grep -qi "noexpn" && echo "$priv" | grep -qi "novrfy" && \
                { result "U-48|양호|sendmail expn/vrfy 제한됨"; return; }
            result "U-48|취약|sendmail expn/vrfy 미제한"
        else result "U-48|수동확인|sendmail.cf 미발견"; fi
    elif is_running postfix; then
        local v=$(postconf disable_vrfy_command 2>/dev/null | awk -F= '{print $2}' | tr -d ' ')
        [ "$v" = "yes" ] && result "U-48|양호|postfix vrfy 제한" || result "U-48|취약|postfix vrfy 미제한 (${v:-미설정})"
    fi
}

check_U49() {
    is_running named || { evd "U-49" "ps -ef 2>/dev/null | grep named | grep -v grep"; result "U-49|양호|DNS 미실행"; return; }
    evd "U-49" "named -v 2>/dev/null; rpm -qa bind 2>/dev/null; dpkg -l bind9 2>/dev/null | tail -1"
    local ver=$(named -v 2>/dev/null | grep -oE 'BIND [0-9][^ ]*' | head -1)
    result "U-49|수동확인|DNS ${ver:-버전 미확인} - 최신 패치 확인"
}

check_U50() {
    is_running named || { evd "U-50" "ps -ef 2>/dev/null | grep named | grep -v grep"; result "U-50|양호|DNS 미실행"; return; }
    evd "U-50" "grep -i allow-transfer /etc/named.conf /etc/bind/named.conf 2>/dev/null"
    for conf in /etc/named.conf /etc/bind/named.conf; do
        [ -f "$conf" ] || continue
        grep -q "allow-transfer.*none" "$conf" 2>/dev/null && { result "U-50|양호|Zone Transfer 차단"; return; }
        grep -q "allow-transfer" "$conf" 2>/dev/null && { result "U-50|수동확인|allow-transfer 허용 대상 확인"; return; }
        result "U-50|취약|Zone Transfer 제한 미설정"; return
    done
    result "U-50|수동확인|named.conf 수동 확인"
}

check_U51() {
    is_running named || { evd "U-51" "ps -ef 2>/dev/null | grep named | grep -v grep"; result "U-51|양호|DNS 서비스 미사용 (가이드 조치 방법: 미사용 시 서비스 중지·비활성화 → 조치 상태)"; return; }
    evd "U-51" "grep -i allow-update /etc/named.conf /etc/bind/named.conf 2>/dev/null"
    local vuln=0
    for conf in /etc/named.conf /etc/bind/named.conf /etc/named/named.conf; do
        [ -f "$conf" ] || continue
        if grep -v "^[[:space:]]*//" "$conf" | grep -v "^#" | grep -qi "allow-update"; then
            if grep -v "^[[:space:]]*//" "$conf" | grep -v "^#" | grep -i "allow-update" | grep -qi "any"; then
                vuln=1
            elif grep -v "^[[:space:]]*//" "$conf" | grep -v "^#" | grep -i "allow-update" | grep -qi "none"; then
                result "U-51|양호|DNS 동적 업데이트 차단 (allow-update none)"; return
            else
                result "U-51|수동확인|allow-update 설정 확인 필요"; return
            fi
        fi
    done
    [ $vuln -eq 1 ] && result "U-51|취약|DNS 동적 업데이트 any 허용" || \
        result "U-51|수동확인|allow-update 미설정 (기본값 확인)"
}

check_U52() {
    evd "U-52" "(ss -tln 2>/dev/null || netstat -an 2>/dev/null) | grep -E '[:.]23[[:space:]]'; ps -ef 2>/dev/null | grep -E 'telnetd' | grep -v grep; grep -vE '^[[:space:]]*#' /etc/inetd.conf 2>/dev/null | grep -w telnet; systemctl list-units --all 2>/dev/null | grep -i telnet"
    local on=""
    { is_running telnetd || is_running in.telnetd; } && on="${on} 프로세스"
    grep -vE '^[[:space:]]*#' /etc/inetd.conf 2>/dev/null | grep -qw telnet && on="${on} inetd"
    grep -qiE 'disable[[:space:]]*=[[:space:]]*no' /etc/xinetd.d/telnet 2>/dev/null && on="${on} xinetd"
    systemctl is-active telnet.socket 2>/dev/null | grep -qx active && on="${on} systemd"
    (ss -tln 2>/dev/null || netstat -an 2>/dev/null) | grep -qE '[:.]23[[:space:]].*LISTEN|[:.]23[[:space:]]+[^ ]*[[:space:]]*$' && on="${on} 23/tcp"
    [ -n "$on" ] && result "U-52|취약|Telnet 서비스 활성:${on}" || result "U-52|양호|Telnet 서비스 비활성화"
}

check_U53() {
    is_running vsftpd || is_running proftpd || is_running pure-ftpd || { evd "U-53" "ps -ef 2>/dev/null | grep -E 'vsftpd|proftpd|ftpd' | grep -v grep"; result "U-53|양호|FTP 서비스 미사용 (가이드 조치 방법: 미사용 시 서비스 중지·비활성화 → 조치 상태)"; return; }
    evd "U-53" "grep -i ftpd_banner /etc/vsftpd/vsftpd.conf /etc/vsftpd.conf 2>/dev/null; grep -i ServerName /etc/proftpd/proftpd.conf /etc/proftpd.conf 2>/dev/null"
    local vuln=0
    if is_running vsftpd; then
        for cf in /etc/vsftpd/vsftpd.conf /etc/vsftpd.conf; do
            [ -f "$cf" ] || continue
            if grep -qi "ftpd_banner" "$cf" 2>/dev/null; then
                result "U-53|양호|vsftpd 배너 커스터마이징됨"; return
            fi
        done
        vuln=1
    elif is_running proftpd; then
        for cf in /etc/proftpd/proftpd.conf /etc/proftpd.conf; do
            [ -f "$cf" ] || continue
            if grep -qi "ServerIdent.*off\|ServerName" "$cf" 2>/dev/null; then
                result "U-53|양호|ProFTPD 배너 제한됨"; return
            fi
        done
        vuln=1
    fi
    [ $vuln -eq 1 ] && result "U-53|취약|FTP 기본 배너 사용 (버전 정보 노출 가능)" || \
        result "U-53|수동확인|FTP 배너 설정 수동 확인"
}

check_U54() {
    evd "U-54" "ps -ef 2>/dev/null | grep -E 'vsftpd|proftpd|pure-ftpd|ftpd' | grep -v grep; grep -iE 'ssl_enable|force_local' /etc/vsftpd/vsftpd.conf /etc/vsftpd.conf 2>/dev/null; grep -iE 'TLSEngine|TLSRequired' /etc/proftpd.conf /etc/proftpd/proftpd.conf /etc/proftpd/tls.conf 2>/dev/null"
    if ! { is_running vsftpd || is_running proftpd || is_running pure-ftpd || is_running in.ftpd || grep -vE '^[[:space:]]*#' /etc/inetd.conf 2>/dev/null | grep -qw ftp; }; then
        result "U-54|양호|FTP 서비스 비활성화"; return
    fi
    if grep -qiE '^[[:space:]]*ssl_enable[[:space:]]*=[[:space:]]*YES' /etc/vsftpd/vsftpd.conf /etc/vsftpd.conf 2>/dev/null || grep -qiE '^[[:space:]]*TLSRequired[[:space:]]+on' /etc/proftpd.conf /etc/proftpd/proftpd.conf /etc/proftpd/tls.conf 2>/dev/null; then
        result "U-54|양호|FTP 사용 - FTPS(TLS) 설정 적용 (암호화 강제 여부 확인)"
    else result "U-54|취약|암호화되지 않은 FTP 서비스 활성화"; fi
}

check_U55() {
    evd "U-55" "grep '^ftp:' /etc/passwd 2>/dev/null"
    local shell=$(grep "^ftp:" /etc/passwd 2>/dev/null | awk -F: '{print $NF}')
    if [ -z "$shell" ]; then result "U-55|양호|ftp 계정 없음"
    elif echo "$shell" | grep -qE "nologin|false"; then result "U-55|양호|ftp shell 제한됨 (${shell})"
    else result "U-55|취약|ftp shell=${shell} (nologin 필요)"; fi
}

check_U56() {
    evd "U-56" "grep -iE 'tcp_wrappers' /etc/vsftpd/vsftpd.conf /etc/vsftpd.conf 2>/dev/null; grep -iE 'vsftpd|proftpd|in.ftpd|ftp' /etc/hosts.allow /etc/hosts.deny 2>/dev/null; grep -iE '<Limit LOGIN>|Allow from|Deny from' /etc/proftpd.conf /etc/proftpd/proftpd.conf 2>/dev/null"
    if ! { is_running vsftpd || is_running proftpd || is_running pure-ftpd || is_running in.ftpd || grep -vE '^[[:space:]]*#' /etc/inetd.conf 2>/dev/null | grep -qw ftp; }; then
        result "U-56|양호|FTP 서비스 미사용 (가이드 조치 방법: 미사용 시 서비스 중지·비활성화 → 조치 상태)"; return
    fi
    local acl=""
    grep -qiE '^[[:space:]]*(vsftpd|proftpd|in\.ftpd|ALL)[[:space:]]*:' /etc/hosts.allow 2>/dev/null && grep -qiE '^[[:space:]]*(vsftpd|proftpd|in\.ftpd|ALL)[[:space:]]*:[[:space:]]*ALL' /etc/hosts.deny 2>/dev/null && acl="tcp_wrappers(hosts.allow/deny)"
    grep -qiE '^[[:space:]]*Allow from' /etc/proftpd.conf /etc/proftpd/proftpd.conf 2>/dev/null && acl="${acl} ProFTP <Limit LOGIN>"
    [ -n "$acl" ] && result "U-56|양호|FTP 접근 제어 설정: ${acl}" || result "U-56|취약|FTP 서비스 사용, 특정 IP/호스트 접근 제어 설정 없음 (방화벽 적용 시 증빙 확인)"
}

check_U57() {
    evd "U-57" "grep -H '^root' /etc/ftpusers /etc/ftpd/ftpusers /etc/vsftpd/ftpusers /etc/vsftpd.ftpusers /etc/vsftpd/user_list 2>/dev/null; grep -iE 'RootLogin' /etc/proftpd.conf /etc/proftpd/proftpd.conf 2>/dev/null"
    if ! { is_running vsftpd || is_running proftpd || is_running pure-ftpd || is_running in.ftpd || grep -vE '^[[:space:]]*#' /etc/inetd.conf 2>/dev/null | grep -qw ftp; }; then
        result "U-57|양호|FTP 서비스 비활성화"; return
    fi
    local f
    for f in /etc/ftpusers /etc/ftpd/ftpusers /etc/vsftpd/ftpusers /etc/vsftpd.ftpusers; do
        [ -f "$f" ] && grep -q '^root' "$f" 2>/dev/null && { result "U-57|양호|FTP root 접속 차단 (${f})"; return; }
    done
    grep -qiE '^[[:space:]]*RootLogin[[:space:]]+off' /etc/proftpd.conf /etc/proftpd/proftpd.conf 2>/dev/null && { result "U-57|양호|ProFTPD RootLogin off"; return; }
    result "U-57|취약|FTP 서비스 사용, root 계정 접속 차단 설정 없음"
}

check_U58() {
    evd "U-58" "ps -ef 2>/dev/null | grep -E 'snmpd|snmpdm|snmpdv3' | grep -v grep"
    { is_running snmpd || is_running snmpdm || is_running snmpdv3; } && result "U-58|취약|SNMP 서비스 사용 중 (가이드: 미사용 시 중지 - 업무상 필요 여부 확인)" || result "U-58|양호|SNMP 서비스 미사용"
}

check_U59() {
    is_running snmpd || { evd "U-59" "ps -ef 2>/dev/null | grep snmpd | grep -v grep"; result "U-59|양호|SNMP 서비스 미사용 (가이드 조치 방법: 미사용 시 서비스 중지·비활성화 → 조치 상태)"; return; }
    evd "U-59" "grep -v '^#' /etc/snmp/snmpd.conf 2>/dev/null | grep -iE 'rouser|rwuser|createUser|v3|usm'"
    local v3=0
    for conf in /etc/snmpd.conf /etc/snmp/snmpd.conf; do
        [ -f "$conf" ] || continue
        grep -v "^#" "$conf" 2>/dev/null | grep -qiE "rouser|rwuser|createUser" && v3=1
    done
    [ $v3 -eq 1 ] && result "U-59|양호|SNMPv3 인증 설정 확인됨" || \
        result "U-59|취약|SNMPv3 미설정 (v1/v2c만 사용)"
}

check_U60() {
    { is_running snmpd || is_running snmpdm || is_running snmpdv3; } || { evd "U-60" "ps -ef 2>/dev/null | grep snmpd | grep -v grep"; result "U-60|양호|SNMP 서비스 미사용 (가이드 조치 방법: 미사용 시 서비스 중지·비활성화 → 조치 상태)"; return; }
    evd "U-60" "grep -vE '^[[:space:]]*#' /etc/snmp/snmpd.conf /etc/snmpd.conf /etc/SnmpAgent.d/snmpd.conf 2>/dev/null | grep -iE 'community|com2sec' | sed -E 's/(community6?|com2sec6?[[:space:]]+[^[:space:]]+[[:space:]]+[^[:space:]]+)[[:space:]]+([^[:space:]]{2})[^[:space:]]*/\1 \2****/I'"
    local weak="" n=0 c conf
    for conf in /etc/snmpd.conf /etc/snmp/snmpd.conf /etc/SnmpAgent.d/snmpd.conf; do
        [ -f "$conf" ] || continue
        for c in $(grep -vE '^[[:space:]]*#' "$conf" 2>/dev/null | awk 'tolower($1) ~ /^r[ow]community6?$/ {print $2} tolower($1) ~ /^com2sec6?$/ {print $4} tolower($1) ~ /^(get|set)-community-name:?$/ {print $2}'); do
            n=$((n+1))
            local cls=0 m="${c:0:2}****"
            echo "$c" | grep -q '[A-Za-z]' && cls=$((cls+1)); echo "$c" | grep -q '[0-9]' && cls=$((cls+1)); echo "$c" | grep -q '[^A-Za-z0-9]' && cls=$((cls+1))
            if echo "$c" | grep -qixE 'public|private'; then weak="${weak} ${c}(기본값)"
            elif ! { [ ${#c} -ge 10 ] && [ $cls -ge 2 ]; } && ! { [ ${#c} -ge 8 ] && [ $cls -ge 3 ]; }; then weak="${weak} ${m}(${#c}자/${cls}종)"; fi
        done
    done
    if [ -n "$weak" ]; then result "U-60|취약|Community String 복잡성 미달(영문·숫자 10자 또는 영문·숫자·특수 8자 이상):${weak}"
    elif [ $n -gt 0 ]; then result "U-60|양호|Community String ${n}개 복잡성 기준 충족"
    else result "U-60|수동확인|SNMP 실행 중 - Community 미설정(SNMPv3 전용 여부·인증 비밀번호 복잡도 확인)"; fi
}

check_U61() {
    is_running snmpd || { evd "U-61" "ps -ef 2>/dev/null | grep snmpd | grep -v grep"; result "U-61|양호|SNMP 서비스 미사용 (가이드 조치 방법: 미사용 시 서비스 중지·비활성화 → 조치 상태)"; return; }
    evd "U-61" "grep -v '^#' /etc/snmp/snmpd.conf 2>/dev/null | grep -iE 'com2sec|agentAddress|rocommunity|rwcommunity' | head -10"
    local acl=0
    for conf in /etc/snmpd.conf /etc/snmp/snmpd.conf; do
        [ -f "$conf" ] || continue
        grep -v "^#" "$conf" 2>/dev/null | grep -qiE "com2sec.*[0-9]+\.[0-9]+|agentAddress.*udp:[0-9]" && acl=1
    done
    [ $acl -eq 1 ] && result "U-61|양호|SNMP 접근통제 설정됨" || \
        result "U-61|취약|SNMP 접근통제 미설정 (IP 제한 없음)"
}

check_U62() {
    evd "U-62" "cat /etc/motd /etc/issue 2>/dev/null | head -10"
    for f in /etc/motd /etc/issue /etc/issue.net; do
        [ -f "$f" ] && [ -s "$f" ] && { result "U-62|양호|경고 메시지 설정됨 (${f})"; return; }
    done
    grep -qi "banner" /etc/ssh/sshd_config 2>/dev/null && { result "U-62|양호|SSH 배너 설정됨"; return; }
    result "U-62|취약|경고 메시지 미설정"
}

check_U63() {
    evd "U-63" "ls -l /etc/sudoers /usr/local/etc/sudoers 2>/dev/null; ls -l /etc/sudoers.d/ 2>/dev/null"
    local f=/etc/sudoers; [ -f "$f" ] || f=/usr/local/etc/sudoers
    [ -f "$f" ] || { result "U-63|양호|sudo 미설치 (/etc/sudoers 없음 - 권한을 점검할 파일 없음)"; return; }
    local p=$(get_perm "$f") o=$(get_owner "$f") vuln=""
    [ "$o" != "root" ] && vuln="${vuln} 소유자=${o}"
    _perm_over "$p" 640 && vuln="${vuln} 권한=${p}"
    [ -n "$vuln" ] && result "U-63|취약|${f}${vuln} (기준: 소유자 root, 640 이하)" || result "U-63|양호|${f} 소유자=${o}, 권한=${p}"
}

check_U64() {
    evd "U-64" "uname -r; rpm -qa --last 2>/dev/null | head -10; apt list --upgradable 2>/dev/null | head -10; yum updateinfo summary 2>/dev/null | head -10"
    result "U-64|수동확인|최신 보안패치 적용 여부 수동 확인 (위 현황 참조)"
}

check_U65() {
    evd "U-65" "timedatectl 2>/dev/null; chronyc sources 2>/dev/null | head -5; ntpq -p 2>/dev/null | head -5; grep -v '^#' /etc/ntp.conf /etc/chrony.conf /etc/chrony/chrony.conf 2>/dev/null | grep -i server | head -5"
    if command -v timedatectl >/dev/null 2>&1; then
        local ntp_sync=$(timedatectl 2>/dev/null | grep -iE "NTP sync|System clock sync" | grep -ci "yes")
        [ "${ntp_sync:-0}" -ge 1 ] && { result "U-65|양호|NTP 동기화 활성화"; return; }
    fi
    if is_running chronyd; then
        result "U-65|양호|chrony 실행 중"; return
    elif is_running ntpd; then
        result "U-65|양호|ntpd 실행 중"; return
    fi
    for cf in /etc/ntp.conf /etc/chrony.conf /etc/chrony/chrony.conf; do
        [ -f "$cf" ] && grep -qv "^#" "$cf" 2>/dev/null && grep -qi "server\|pool" "$cf" 2>/dev/null && {
            result "U-65|수동확인|NTP 설정 파일 존재 (${cf}) - 동기화 상태 확인"; return
        }
    done
    result "U-65|취약|NTP 미설정"
}

check_U66() {
    evd "U-66" "grep -E '^auth|^authpriv' /etc/rsyslog.conf /etc/rsyslog.d/*.conf /etc/syslog.conf 2>/dev/null | head -10"
    for f in /etc/rsyslog.conf /etc/rsyslog.d/*.conf /etc/syslog.conf; do
        [ -f "$f" ] || continue
        grep -qiE "^auth|^authpriv" "$f" 2>/dev/null && { result "U-66|양호|시스템 로깅 설정됨 (${f})"; return; }
    done
    result "U-66|취약|시스템 로깅 미설정"
}

check_U67() {
    local d=/var/log; [ "$OS_FAMILY" = "AIX" ] || [ "$OS_FAMILY" = "HPUX" ] || [ "$OS_FAMILY" = "SOLARIS" ] && [ -d /var/adm ] && d="/var/log /var/adm"
    evd "U-67" "ls -l $d 2>/dev/null | head -60"
    local vuln="" f
    for f in $(find $d -maxdepth 1 -type f 2>/dev/null); do
        local o=$(get_owner "$f") p=$(get_perm "$f")
        [ "$o" != "root" ] && vuln="${vuln} ${f}(소유자=${o})"
        _perm_over "$p" 644 && vuln="${vuln} ${f}(${p})"
    done
    [ -n "$vuln" ] && result "U-67|취약|로그 파일 기준 위반(소유자 root, 644 이하):$(echo $vuln | cut -c1-400)" || result "U-67|양호|${d} 내 로그 파일 소유자 root, 권한 644 이하"
}


# ── 실행 (U-01 ~ U-67, 2026 상세가이드) ─────────────────────────
check_U01; check_U02; check_U03; check_U04; check_U05; check_U06; check_U07; check_U08
check_U09; check_U10; check_U11; check_U12; check_U13; check_U14; check_U15; check_U16
check_U17; check_U18; check_U19; check_U20; check_U21; check_U22; check_U23; check_U24
check_U25; check_U26; check_U27; check_U28; check_U29; check_U30; check_U31; check_U32
check_U33; check_U34; check_U35; check_U36; check_U37; check_U38; check_U39; check_U40
check_U41; check_U42; check_U43; check_U44; check_U45; check_U46; check_U47; check_U48
check_U49; check_U50; check_U51; check_U52; check_U53; check_U54; check_U55; check_U56
check_U57; check_U58; check_U59; check_U60; check_U61; check_U62; check_U63; check_U64
check_U65; check_U66; check_U67

_TOTAL=$((_CP + _CF + _CM + _CN))
echo "# ================================================================"
echo "# 점검 요약 — 주요정보통신기반시설 (U-시리즈)"
echo "#   총 점검 항목: ${_TOTAL}"
[ "$_TOTAL" -gt 0 ] 2>/dev/null && {
echo "#   양호:         ${_CP}  ($((_CP * 100 / _TOTAL))%)"
echo "#   취약:         ${_CF}  ($((_CF * 100 / _TOTAL))%)"
echo "#   수동확인:     ${_CM}"
echo "#   N-A:          ${_CN}"
}
echo "# ================================================================"
[ -n "$_RESF" ] && echo "# 결과 파일(자동 저장): ${_RESF}  ← 증적 파일과 함께 회수"
[ -n "$_TEEPID" ] && { exec >&- 2>/dev/null; wait "$_TEEPID" 2>/dev/null; sleep 1; }
exit 0
