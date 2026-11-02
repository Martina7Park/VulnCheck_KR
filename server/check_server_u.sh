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
#   - root 권한 필요 (sudo bash 또는 root 로그인). 일반 계정으로 실행하면 읽지 못한 항목은 '점검불가' 로 표시
#
# [실행 방법]
#   bash check_server_u.sh > /tmp/$(hostname)_u.txt
#
# [산출물]
#   1) 표준출력: U-항목코드|결과|근거설명  (양호/취약/수동확인/점검불가/N-A)
#   2) 증적 파일: /tmp/<호스트명>_u_evidence.txt
#   3) 헤더: 점검 대상·OS·IP·실행 계정·클라우드 정보(# IP / # 실행 계정 / # 클라우드)
#
# ================================================================

umask 077

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
esac
PATH="$PATH:/sbin:/usr/sbin:/usr/local/sbin:/usr/local/bin"; export PATH   # sudo 환경에서 /sbin·/usr/sbin 이 빠지는 경우 대비
HN=$(hostname 2>/dev/null || uname -n)

# ── 임시 작업 디렉터리 (심볼릭 링크 선점 방어: 새 디렉터리를 만들어 사용) ──
_TMPD=$(mktemp -d /tmp/.vcu.XXXXXX 2>/dev/null)
if [ -z "$_TMPD" ] || [ ! -d "$_TMPD" ]; then
    _TMPD="/tmp/.vcu.$$"; rm -rf "$_TMPD" 2>/dev/null; mkdir -m 700 "$_TMPD" 2>/dev/null || { echo "임시 디렉터리 생성 실패(/tmp) - 점검 중단"; exit 1; }
fi
_TMPO="$_TMPD/o.out"
trap 'rm -rf "$_TMPD" 2>/dev/null' EXIT

# ── 결과 사본 자동 저장: '> 파일' 리다이렉트를 빠뜨려도 판정 결과가 증적과 같은 위치에 남도록 표준출력을 복사 ──
_RESF="/tmp/${HN}_u.txt"
[ -L "$_RESF" ] && rm -f "$_RESF"
if [ -z "$NO_RESULT_COPY" ] && ! [ /dev/fd/1 -ef "$_RESF" ] 2>/dev/null && ( : > "$_RESF" ) 2>/dev/null; then
    exec > >(tee "$_RESF"); _TEEPID=$!
else
    _RESF=""
fi

# ── 헤더 메타데이터: IP / 실행 계정 / 클라우드 ───────────────────
_ID_OUT=$(id 2>/dev/null)
_WHOAMI=$(echo "$_ID_OUT" | sed -n 's/^uid=[0-9]*(\([^)]*\)).*/\1/p')
[ -z "$_WHOAMI" ] && _WHOAMI=$(whoami 2>/dev/null)
_IS_ROOT=0; echo "$_ID_OUT" | grep -q '^uid=0(' && _IS_ROOT=1

_get_ips() {
    local ips=""
    if command -v ip >/dev/null 2>&1; then
        ips=$(ip -4 -o addr show 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="inet"){split($(i+1),a,"/"); print a[1]}}')
    fi
    if [ -z "$ips" ]; then
        ips=$( (ifconfig -a 2>/dev/null || /sbin/ifconfig -a 2>/dev/null || /usr/sbin/ifconfig -a 2>/dev/null) | awk '/inet /{for(i=1;i<=NF;i++) if($i=="inet"){v=$(i+1); sub(/^addr:/,"",v); print v; break}}')
    fi
    if [ -z "$ips" ] && command -v hostname >/dev/null 2>&1; then
        ips=$(hostname -I 2>/dev/null | tr ' ' '\n')
    fi
    if [ -z "$ips" ]; then   # HP-UX: netstat -in 의 Address 열
        ips=$(netstat -in 2>/dev/null | awk 'NR>1 && $4 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ {print $4}')
    fi
    if [ -z "$ips" ] && [ -r /proc/net/fib_trie ]; then   # ip·ifconfig·hostname 이 없는 최소 Linux: 커널 라우팅 트리의 로컬 주소
        ips=$(awk '$1=="|--"{ip=$2} /\/32 host LOCAL/{print ip}' /proc/net/fib_trie 2>/dev/null)
    fi
    echo "$ips" | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | grep -v '^127\.' | awk '!s[$0]++' | tr '\n' ',' | sed 's/,$//; s/,/, /g'
}

# 클라우드 메타데이터(IMDS) 조회: 2초 타임아웃, 실패해도 점검 계속
_http_req() {   # _http_req 메서드 URL [헤더...]
    local m="$1" url="$2" r h; shift 2
    if command -v curl >/dev/null 2>&1; then
        local -a a=(); for h in "$@"; do a+=(-H "$h"); done
        r=$(curl -sS -m 2 --connect-timeout 2 -X "$m" "${a[@]}" "$url" 2>/dev/null) || return 1
    elif command -v wget >/dev/null 2>&1; then
        local -a a=(); for h in "$@"; do a+=("--header=$h"); done
        if [ "$m" = "GET" ]; then r=$(wget -q -T 2 -t 1 -O - "${a[@]}" "$url" 2>/dev/null) || return 1
        else r=$(wget -q -T 2 -t 1 -O - --method="$m" "${a[@]}" "$url" 2>/dev/null) || return 1; fi
    else return 1; fi
    printf '%s' "$r"
}
_json_val() { sed -n "s/.*\"$1\"[[:space:]]*:[[:space:]]*\"\([^\"]*\)\".*/\1/p" | head -1; }
CLOUD_NAME=""; CLOUD_SG=""; CLOUD_LINE=""
_cloud_probe() {
    local B="${VC_IMDS_BASE:-http://169.254.169.254}" tok id reg mac macs sgs="" s t v n z tg
    if ! command -v curl >/dev/null 2>&1 && ! command -v wget >/dev/null 2>&1; then CLOUD_LINE="미확인 (curl/wget 없음)"; return; fi
    # AWS: IMDSv2 토큰 먼저, 실패하면 v1
    tok=$(_http_req PUT "$B/latest/api/token" "X-aws-ec2-metadata-token-ttl-seconds: 60")
    if [ -n "$tok" ]; then id=$(_http_req GET "$B/latest/meta-data/instance-id" "X-aws-ec2-metadata-token: $tok")
    else id=$(_http_req GET "$B/latest/meta-data/instance-id"); fi
    if echo "$id" | grep -qE '^i-[0-9a-f]+$'; then
        local -a H=(); [ -n "$tok" ] && H=("X-aws-ec2-metadata-token: $tok")
        reg=$(_http_req GET "$B/latest/meta-data/placement/region" "${H[@]}")
        echo "$reg" | grep -qE '^[a-z]{2}-[a-z]+-[0-9]+$' || { reg=$(_http_req GET "$B/latest/meta-data/placement/availability-zone" "${H[@]}" | sed 's/[a-z]$//'); }
        macs=$(_http_req GET "$B/latest/meta-data/network/interfaces/macs/" "${H[@]}")
        for mac in $macs; do
            s=$(_http_req GET "$B/latest/meta-data/network/interfaces/macs/${mac}security-group-ids" "${H[@]}" | tr '\n' ' ')
            sgs="$sgs $s"
        done
        sgs=$(echo $sgs | tr ' ' '\n' | grep -E '^sg-' | awk '!x[$0]++' | tr '\n' ',' | sed 's/,$//')
        CLOUD_NAME="AWS"; CLOUD_SG="$sgs"
        CLOUD_LINE="AWS (instance ${id}, region ${reg:-미확인}, SG: ${sgs:-미확인})"; return
    fi
    # Azure
    t=$(_http_req GET "$B/metadata/instance/compute?api-version=2021-02-01&format=json" "Metadata:true")
    if echo "$t" | grep -q '"vmId"'; then
        v=$(echo "$t" | _json_val vmId); n=$(echo "$t" | _json_val name); z=$(echo "$t" | _json_val location)
        CLOUD_NAME="Azure"; CLOUD_SG=""
        CLOUD_LINE="Azure (vm ${n:-$v}, region ${z:-미확인}, SG: 미확인(NSG 는 포털에서 확인))"; return
    fi
    # GCP
    id=$(_http_req GET "$B/computeMetadata/v1/instance/id" "Metadata-Flavor: Google")
    if echo "$id" | grep -qE '^[0-9]+$'; then
        n=$(_http_req GET "$B/computeMetadata/v1/instance/name" "Metadata-Flavor: Google")
        z=$(_http_req GET "$B/computeMetadata/v1/instance/zone" "Metadata-Flavor: Google" | sed 's|.*/||')
        tg=$(_http_req GET "$B/computeMetadata/v1/instance/tags" "Metadata-Flavor: Google" | tr -d '[]" \n')
        CLOUD_NAME="GCP"; CLOUD_SG="${tg}"
        CLOUD_LINE="GCP (instance ${n:-$id}, region ${z:-미확인}, SG: ${tg:-태그 없음(방화벽 규칙은 콘솔에서 확인)})"; return
    fi
    # 모두 실패: DMI 가 클라우드로 보이면 '미확인', 아니면 '없음'
    local dmi=""
    for s in sys_vendor product_name board_vendor bios_vendor chassis_asset_tag; do dmi="$dmi $(cat /sys/class/dmi/id/$s 2>/dev/null)"; done
    if echo "$dmi" | grep -qiE 'amazon|google|microsoft corporation|alibaba|openstack|oraclecloud|7783-7084'; then CLOUD_LINE="미확인 (DMI 상 클라우드로 보이나 메타데이터 조회 실패)"
    else CLOUD_LINE="없음"; fi
}
_cloud_probe 2>/dev/null
[ -z "$CLOUD_LINE" ] && CLOUD_LINE="미확인"

echo "# ============================================================"
echo "# 점검 대상: ${HN}"
echo "# OS: ${OS_FAMILY} / ${OS_DISTRO} ${OS_MAJOR}"
echo "# OS 상세: $( ( [ -r /etc/os-release ] && . /etc/os-release 2>/dev/null && echo "${PRETTY_NAME:-$NAME $VERSION_ID}" ) || ( command -v oslevel >/dev/null 2>&1 && echo "AIX $(oslevel -s 2>/dev/null)" ) || ( [ -r /etc/release ] && head -1 /etc/release | sed 's/^ *//' ) || uname -sr 2>/dev/null)"
echo "# 커널: $(uname -r 2>/dev/null)$( [ "$(uname -s 2>/dev/null)" = SunOS ] && echo " / $(uname -v 2>/dev/null)")"
echo "# IP: $(_ips=$(_get_ips); echo "${_ips:-미확인}")"
if [ "$_IS_ROOT" = 1 ]; then echo "# 실행 계정: ${_WHOAMI:-root}"
else echo "# 실행 계정: ${_WHOAMI:-미확인} (관리자 아님 - 일부 항목 점검불가)"; fi
echo "# 클라우드: ${CLOUD_LINE}"
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
_CP=0; _CF=0; _CM=0; _CN=0; _CU=0
_EVD="/tmp/${HN}_u_evidence.txt"
[ -L "$_EVD" ] && rm -f "$_EVD"
( : >> "$_EVD" ) 2>/dev/null || _EVD="/tmp/${HN}_u_evidence_${_WHOAMI:-user}.txt"   # 다른 계정(root)이 만든 파일이라 쓸 수 없으면 계정별 파일 사용
[ -L "$_EVD" ] && rm -f "$_EVD"
echo "# ================================================================" > "$_EVD"
echo "# 증적 파일 (감사 추적용)" >> "$_EVD"
echo "# 대상: ${HN} / ${OS_FAMILY} ${OS_DISTRO} ${OS_MAJOR}" >> "$_EVD"
echo "# 실행 계정: ${_WHOAMI:-미확인} / 클라우드: ${CLOUD_LINE}" >> "$_EVD"
echo "# 생성: $(date '+%Y-%m-%d %H:%M:%S')" >> "$_EVD"
echo "# ================================================================" >> "$_EVD"

# 항목명 (bash 3 호환을 위해 연관배열 대신 case 사용)
_iname() {
    case "$1" in
    U-01) echo 'root 계정 원격 접속 제한' ;;
    U-02) echo '비밀번호 관리정책 설정' ;;
    U-03) echo '계정 잠금 임계값 설정' ;;
    U-04) echo '비밀번호 파일 보호' ;;
    U-05) echo 'root 이외의 UID가 ‘0’ 금지' ;;
    U-06) echo '사용자 계정 su 기능 제한' ;;
    U-07) echo '불필요한 계정 제거' ;;
    U-08) echo '관리자 그룹에 최소한의 계정 포함' ;;
    U-09) echo '계정이 존재하지 않는 GID 금지' ;;
    U-10) echo '동일한 UID 금지' ;;
    U-11) echo '사용자 shell 점검' ;;
    U-12) echo '세션 종료 시간 설정' ;;
    U-13) echo '안전한 비밀번호 암호화 알고리즘 사용' ;;
    U-14) echo 'root 홈, 패스 디렉터리 권한 및 패스 설정' ;;
    U-15) echo '파일 및 디렉터리 소유자 설정' ;;
    U-16) echo '/etc/passwd 파일 소유자 및 권한 설정' ;;
    U-17) echo '시스템 시작 스크립트 권한 설정' ;;
    U-18) echo '/etc/shadow 파일 소유자 및 권한 설정' ;;
    U-19) echo '/etc/hosts 파일 소유자 및 권한 설정' ;;
    U-20) echo '/etc/(x)inetd.conf 파일 소유자 및 권한 설정' ;;
    U-21) echo '/etc/(r)syslog.conf 파일 소유자 및 권한 설정' ;;
    U-22) echo '/etc/services 파일 소유자 및 권한 설정' ;;
    U-23) echo 'SUID, SGID, Sticky bit 설정 파일 점검' ;;
    U-24) echo '사용자, 시스템 환경변수 파일 소유자 및 권한 설정' ;;
    U-25) echo 'world writable 파일 점검' ;;
    U-26) echo '/dev에 존재하지 않는 device 파일 점검' ;;
    U-27) echo '$HOME/.rhosts, hosts.equiv 사용 금지' ;;
    U-28) echo '접속 IP 및 포트 제한' ;;
    U-29) echo 'hosts.lpd 파일 소유자 및 권한 설정' ;;
    U-30) echo 'UMASK 설정 관리' ;;
    U-31) echo '홈디렉토리 소유자 및 권한 설정' ;;
    U-32) echo '홈 디렉토리로 지정한 디렉토리의 존재 관리' ;;
    U-33) echo '숨겨진 파일 및 디렉토리 검색 및 제거' ;;
    U-34) echo 'Finger 서비스 비활성화' ;;
    U-35) echo '공유 서비스에 대한 익명 접근 제한 설정' ;;
    U-36) echo 'r 계열 서비스 비활성화' ;;
    U-37) echo 'crontab 설정파일 권한 설정 미흡' ;;
    U-38) echo 'DoS 공격에 취약한 서비스 비활성화' ;;
    U-39) echo '불필요한 NFS 서비스 비활성화' ;;
    U-40) echo 'NFS 접근 통제' ;;
    U-41) echo '불필요한 automountd 제거' ;;
    U-42) echo '불필요한 RPC 서비스 비활성화' ;;
    U-43) echo 'NIS, NIS+ 점검' ;;
    U-44) echo 'tftp, talk 서비스 비활성화' ;;
    U-45) echo '메일 서비스 버전 점검' ;;
    U-46) echo '일반 사용자의 메일 서비스 실행 방지' ;;
    U-47) echo '스팸 메일 릴레이 제한' ;;
    U-48) echo 'expn, vrfy 명령어 제한' ;;
    U-49) echo 'DNS 보안 버전 패치' ;;
    U-50) echo 'DNS ZoneTransfer 설정' ;;
    U-51) echo 'DNS 서비스의 취약한 동적 업데이트 설정 금지' ;;
    U-52) echo 'Telnet 서비스 비활성화' ;;
    U-53) echo 'FTP 서비스 정보 노출 제한' ;;
    U-54) echo '암호화되지 않는 FTP 서비스 비활성화' ;;
    U-55) echo 'FTP 계정 shell 제한' ;;
    U-56) echo 'FTP 서비스 접근 제어 설정' ;;
    U-57) echo 'Ftpusers 파일 설정' ;;
    U-58) echo '불필요한 SNMP 서비스 구동 점검' ;;
    U-59) echo '안전한 SNMP 버전 사용' ;;
    U-60) echo 'SNMP Community String 복잡성 설정' ;;
    U-61) echo 'SNMP Access Control 설정' ;;
    U-62) echo '로그인 시 경고 메시지 설정' ;;
    U-63) echo 'sudo 명령어 접근 관리' ;;
    U-64) echo '주기적 보안 패치 및 벤더 권고사항 적용' ;;
    U-65) echo 'NTP 및 시각 동기화 설정' ;;
    U-66) echo '정책에 따른 시스템 로깅 설정' ;;
    U-67) echo '로그 디렉터리 소유자 및 권한 설정' ;;
    *) echo "" ;;
    esac
}

# ── Windows 환경 조기 종료 ───────────────────────────────────────
if [ "$OS_FAMILY" = "WINDOWS" ]; then
    echo "# Windows 환경 — 전 항목 N-A 처리" >> "$_EVD"
    for _i in $(seq -w 1 67); do
        _CN=$((_CN+1))
        _code="U-${_i}"; _nm=$(_iname "$_code")
        echo "${_code}|N-A|Windows 환경 — Linux/Unix 전용 항목"
        if [ -n "$_nm" ]; then
            printf '[판정] %s (%s)|N-A|Windows 환경 — Linux/Unix 전용 항목\n\n' "$_code" "$_nm" >> "$_EVD"
        else
            printf '[판정] %s|N-A|Windows 환경 — Linux/Unix 전용 항목\n\n' "$_code" >> "$_EVD"
        fi
    done
    _TOTAL=$((_CP + _CF + _CM + _CN + _CU))
    echo "# ================================================================"
    echo "# 점검 요약 — 주요정보통신기반시설 (U)"
    echo "#   총 점검 항목: ${_TOTAL}"
    echo "#   양호:         ${_CP}  (0%)"
    echo "#   취약:         ${_CF}  (0%)"
    echo "#   수동확인:     ${_CM}"
    echo "#   점검불가:     ${_CU}"
    echo "#   N-A:          ${_CN}"
    echo "# ================================================================"
    echo "# 점검 완료: $(date '+%Y-%m-%d %H:%M:%S')"
    echo "# 증적 파일: ${_EVD}"
    exit 0
fi

# ── 결과·증적 기록 ───────────────────────────────────────────────
result() {   # 항상 0 반환: 'A && result X || result Y' 이중 출력 방지
    echo "$1"
    case "$1" in
    *"|양호|"*)     _CP=$((_CP+1)) ;;
    *"|취약|"*)     _CF=$((_CF+1)) ;;
    *"|수동확인|"*) _CM=$((_CM+1)) ;;
    *"|점검불가|"*) _CU=$((_CU+1)) ;;
    *"|N-A|"*)      _CN=$((_CN+1)) ;;
    esac
    local _code="${1%%|*}" _rest="${1#*|}"
    local _nm; _nm=$(_iname "$_code")
    if [ -n "$_nm" ]; then
        printf '[판정] %s (%s)|%s\n\n' "$_code" "$_nm" "$_rest" >> "$_EVD"
    else
        printf '[판정] %s\n\n' "$1" >> "$_EVD"
    fi
    return 0
}
_evd_dump() {   # 파일 내용을 증적에 기록 (너무 큰 출력만 2000줄 상한)
    local n; n=$(wc -l < "$1" 2>/dev/null | tr -d ' ')
    if [ "${n:-0}" -gt 2000 ] 2>/dev/null; then
        sed -n '1,2000p' "$1" >> "$_EVD"
        echo "(이하 $((n-2000))줄 생략)" >> "$_EVD"
    else
        cat "$1" >> "$_EVD" 2>/dev/null
    fi
}
LAST="$_TMPD/last.out"
evd() {   # evd 항목코드 "명령" : 명령을 실행해 출력(오류 포함)을 증적에 기록하고 같은 출력을 $LAST 에 남김
    local item="$1"; shift
    printf '[%s] %s $ %s\n' "$item" "$(date '+%H:%M:%S')" "$*" >> "$_EVD"
    eval "$@" > "$LAST" 2>&1 < /dev/null
    _evd_dump "$LAST"
    printf '\n' >> "$_EVD"
    return 0
}
evd_f() {   # evd_f 항목코드 "명령 설명" 파일 : 이미 실행해 둔 결과 파일을 증적에 기록 (판정에 쓴 원자료와 동일)
    printf '[%s] %s $ %s\n' "$1" "$(date '+%H:%M:%S')" "$2" >> "$_EVD"
    _evd_dump "$3"
    printf '\n' >> "$_EVD"
    return 0
}
evd_ls() {   # evd_ls 항목코드 "대상설명" 목록파일 : 판정한 파일 전부의 소유자·권한
    if [ -s "$3" ]; then evd "$1" "xargs ls -ldL < $3 2>&1"
    else evd "$1" "echo '(대상 파일 없음: $2)'"; fi
}
_ls_state() { ls -ld "$@" 2>&1; }   # 존재 여부까지 보이는 ls

# ── 공통 함수 ────────────────────────────────────────────────────
_ls_octal() {   # ls -l 첫 열(예: -rwsr-xr-x)을 8진 권한으로 (setuid·setgid·sticky 포함, stat %a 형식)
    awk '{p=substr($1,2,9); if(length(p)<9) exit
        o=0; for(g=0;g<3;g++){ b=0
            if(substr(p,g*3+1,1)=="r") b+=4
            if(substr(p,g*3+2,1)=="w") b+=2
            c3=substr(p,g*3+3,1); if(c3=="x"||c3=="s"||c3=="t") b+=1
            o=o*8+b }
        sp=0
        if(substr(p,3,1)~/[sS]/) sp+=4
        if(substr(p,6,1)~/[sSl]/) sp+=2
        if(substr(p,9,1)~/[tT]/) sp+=1
        if(sp) printf "%d%03o\n", sp, o; else printf "%03o\n", o; exit}'
}
get_perm() {
    local f="$1"; [ -e "$f" ] || [ -L "$f" ] || { echo ""; return; }
    if [ -L "$f" ]; then
        local rf; rf=$(readlink -f "$f" 2>/dev/null)
        [ -z "$rf" ] && rf=$(perl -MCwd -e 'print Cwd::abs_path($ARGV[0])' "$f" 2>/dev/null)
        [ -n "$rf" ] && [ -e "$rf" ] && f="$rf" || { echo ""; return; }
    fi
    local out=""
    case "$OS_FAMILY" in
    AIX)     # istat: "Protection: rw-r--r--" (SUID/SGID/SVTX 표기가 따로 붙을 수 있음) → 실패하면 ls -lL 로 대체
        out=$(istat "$f" 2>/dev/null | awk '/Protection:/{ s=$0; p=""
            for(i=1;i<=NF;i++) if($i ~ /^[r-][w-][xsS-][r-][w-][xsS-][r-][w-][xtT-]$/){ p=$i; break }
            if(p=="") exit
            if(s ~ /SUID/ && substr(p,3,1) !~ /[sS]/){ c=substr(p,3,1); p=substr(p,1,2) (c=="x"?"s":"S") substr(p,4) }
            if(s ~ /SGID/ && substr(p,6,1) !~ /[sS]/){ c=substr(p,6,1); p=substr(p,1,5) (c=="x"?"s":"S") substr(p,7) }
            if(s ~ /SVTX/ && substr(p,9,1) !~ /[tT]/){ c=substr(p,9,1); p=substr(p,1,8) (c=="x"?"t":"T") }
            print "-" p; exit }' | _ls_octal)
        [ -z "$out" ] && out=$(ls -lL "$f" 2>/dev/null | _ls_octal) ;;
    BSD)     out=$(stat -f "%Lp" "$f" 2>/dev/null) ;;
    SOLARIS|HPUX) out=$(ls -lL "$f" 2>/dev/null | _ls_octal) ;;
    *)       out=$(stat -c "%a" "$f" 2>/dev/null)
             [ -z "$out" ] && out=$(ls -lL "$f" 2>/dev/null | _ls_octal) ;;
    esac
    case "$out" in [0-7]|[0-7][0-7]) out=$(printf '%03d' "$out") ;; esac   # stat 이 앞자리 0 을 생략(예: RHEL 계열 /etc/shadow 000 → "0")
    echo "$out"
}
get_owner() {
    local f="$1"; [ -e "$f" ] || [ -L "$f" ] || { echo ""; return; }
    if [ -L "$f" ]; then
        local rf; rf=$(readlink -f "$f" 2>/dev/null)
        [ -z "$rf" ] && rf=$(perl -MCwd -e 'print Cwd::abs_path($ARGV[0])' "$f" 2>/dev/null)
        [ -n "$rf" ] && [ -e "$rf" ] && f="$rf" || { echo ""; return; }
    fi
    local out=""
    case "$OS_FAMILY" in
    AIX)     # istat: "Owner: 0(root)   Group: 0(system)" → 괄호 안 이름, 없으면 숫자 / 실패하면 ls -lL
        out=$(istat "$f" 2>/dev/null | awk '/Owner:/{for(i=1;i<=NF;i++) if($i=="Owner:"){v=$(i+1); if(match(v,/\([^)]*\)/)) v=substr(v,RSTART+1,RLENGTH-2); else sub(/\(.*/,"",v); print v; exit}}')
        [ -z "$out" ] && out=$(ls -lL "$f" 2>/dev/null | awk '{print $3}') ;;
    BSD)     out=$(stat -f "%Su" "$f" 2>/dev/null) ;;
    SOLARIS|HPUX) out=$(ls -lL "$f" 2>/dev/null | awk '{print $3}') ;;
    *)       out=$(stat -c "%U" "$f" 2>/dev/null)
             [ -z "$out" ] && out=$(ls -lL "$f" 2>/dev/null | awk '{print $3}') ;;
    esac
    echo "$out"
}
_TO=$(command -v timeout 2>/dev/null)
_to() { local s="$1"; shift; if [ -n "$_TO" ]; then "$_TO" "$s" "$@"; else "$@"; fi; }   # timeout 없는 AIX·HP-UX·Solaris 10 은 제한 없이 실행
_aix_default() { awk '/^default:/{f=1;next} /^[^ 	*#]/{f=0} f' /etc/security/user 2>/dev/null; }   # AIX default 스탠자 본문 (awk 범위식은 시작행에서 바로 종료되는 결함)
_nc() { [ $# -gt 0 ] || return 0; grep -hvE '^[[:space:]]*(#|!|;|$)' "$@" 2>/dev/null < /dev/null; }   # 주석·빈 줄 제외한 설정 줄 (파일 인자 필수)
_unreadable() { local f; for f in "$@"; do [ -e "$f" ] && [ ! -r "$f" ] && return 0; done; return 1; }
_join() { awk 'BEGIN{n=0}{n++; if(n<=10) s=s (n>1?", ":"") $0; else m++} END{printf "%s", s; if(m) printf " 외 %d건(증적 참조)", m}'; }   # 줄 목록을 10건까지 쉼표로, 나머지는 '외 N건'

_ps_comm() {   # 프로세스 이름(comm) 목록
    local o
    o=$(ps -e -o comm= 2>/dev/null)
    [ -z "$o" ] && o=$(UNIX95=1 ps -e -o comm= 2>/dev/null)
    [ -z "$o" ] && o=$(ps -ef 2>/dev/null | awk 'NR>1{for(i=8;i<=NF;i++) if($i !~ /^-/){print $i; break}}')
    printf '%s\n' "$o" | sed 's|.*/||; s/[[:space:]]*$//'
}
_ps_has() { local n="$1" t; t=$(printf '%s' "$n" | cut -c1-15); _ps_comm | awk -v a="$n" -v b="$t" '$0==a||$0==b{f=1} END{exit !f}'; }
is_running() {
    local svc="$1" st="" alt=""
    if command -v systemctl >/dev/null 2>&1; then
        case "$svc" in *.socket|*.service) st=$(systemctl show -p LoadState "$svc" 2>/dev/null | cut -d= -f2) ;; *) st=$(systemctl show -p LoadState "$svc.service" 2>/dev/null | cut -d= -f2) ;; esac
        if [ "$st" = "loaded" ]; then   # systemd 가 아는 서비스는 is-active 결과만 신뢰
            case "$svc" in *.socket|*.service) systemctl is-active "$svc" 2>/dev/null | grep -qx active ;; *) systemctl is-active "$svc.service" 2>/dev/null | grep -qx active ;; esac
            return $?
        fi
    elif command -v service >/dev/null 2>&1; then
        service "$svc" status 2>&1 < /dev/null | grep -qiE 'is running|active \(running\)' && return 0
    fi
    [ "$OS_FAMILY" = "AIX" ] && [ "$svc" = "ntpd" ] && alt="xntpd"
    if command -v lssrc >/dev/null 2>&1; then
        lssrc -s "$svc" 2>/dev/null | awk 'NR>1 && $NF=="active"{f=1} END{exit !f}' && return 0
        [ -n "$alt" ] && lssrc -s "$alt" 2>/dev/null | awk 'NR>1 && $NF=="active"{f=1} END{exit !f}' && return 0
    fi
    command -v svcs >/dev/null 2>&1 && svcs -H -o state "$svc" 2>/dev/null | grep -qx online && return 0
    _ps_has "$svc" && return 0
    [ "$svc" = sendmail ] && { _ps_has sm-mta || _ps_has sendmail-mta; } && return 0   # Debian/Ubuntu sendmail 의 MTA 프로세스 이름
    [ -n "$alt" ] && _ps_has "$alt" && return 0
    return 1
}
_svc_status() {   # _svc_status 프로세스(comm)정규식 유닛... : 서비스 상태를 항상 출력 (증적용)
    local pat="$1" u; shift
    for u in "$@"; do
        if command -v systemctl >/dev/null 2>&1; then echo "systemctl is-active $u: $(systemctl is-active "$u" 2>&1)"
        elif command -v lssrc >/dev/null 2>&1; then echo "lssrc -s $u: $(lssrc -s "$u" 2>&1 | awk 'NR>1{print $NF}')"
        elif command -v svcs >/dev/null 2>&1; then echo "svcs $u: $(svcs -H "$u" 2>&1)"
        else echo "$u: (systemctl/lssrc/svcs 없음)"; fi
    done
    echo "실행 중 프로세스(comm 일치): $(_ps_comm | grep -xE "$pat" | sort -u | tr '\n' ' ')"
}
_listen() {   # _listen 포트... : 리슨 중인 포트 (tcp/udp)
    local p out=""
    local ls_out; ls_out=$( (ss -tuln 2>/dev/null || netstat -an 2>/dev/null) )
    for p in "$@"; do echo "$ls_out" | grep -qE "[:.]${p}[[:space:]]" && out="${out} ${p}"; done
    echo "${out# }"
}
_ports_ev() { echo "리슨 포트(ss -tuln 또는 netstat -an):"; (ss -tuln 2>&1 || netstat -an 2>&1); }
_inet_on() {   # inetd/xinetd/systemd socket/SMF 에서 활성화된 서비스 (인자: 서비스명...)
    local n f out=""
    for n in "$@"; do
        [ -f /etc/inetd.conf ] && grep -vE '^[[:space:]]*#' /etc/inetd.conf 2>/dev/null | grep -qE "^[[:space:]]*${n}[[:space:]]" && out="${out} inetd:${n}"
        for f in /etc/xinetd.d/$n; do
            [ -f "$f" ] || continue
            grep -vE '^[[:space:]]*#' "$f" 2>/dev/null | grep -qiE 'disable[[:space:]]*=[[:space:]]*yes' || out="${out} xinetd:${n}"
        done
        command -v systemctl >/dev/null 2>&1 && systemctl is-active "$n.socket" 2>/dev/null | grep -qx active && out="${out} systemd:${n}.socket"
        command -v svcs >/dev/null 2>&1 && svcs -H -o state,fmri 2>/dev/null | grep -E "^online" | grep -qE "network/([a-z0-9_-]+/)?${n}(:|$)" && out="${out} SMF:${n}"
    done
    echo "${out# }"
}
_inet_ev() {   # _inet_ev 서비스명... : inetd·xinetd·systemd socket·SMF 상태를 항상 출력 (증적용)
    local n
    echo "/etc/inetd.conf 활성 줄:"; grep -vE '^[[:space:]]*#' /etc/inetd.conf /dev/null 2>&1
    echo "/etc/xinetd.d:"; ls -l /etc/xinetd.d 2>&1
    for n in "$@"; do
        [ -f "/etc/xinetd.d/$n" ] && { echo "== /etc/xinetd.d/$n"; grep -vE '^[[:space:]]*#' "/etc/xinetd.d/$n" 2>&1; }
        command -v systemctl >/dev/null 2>&1 && echo "systemctl is-active $n.socket: $(systemctl is-active "$n.socket" 2>&1)"
    done
    command -v svcs >/dev/null 2>&1 && svcs -H -o state,fmri 2>&1 | grep -E "network/" ; true
}
get_pam_files() {
    case "$OS_FAMILY" in
    AIX)     echo "/etc/security/user /etc/security/login.cfg" ;;
    SOLARIS) echo "/etc/pam.conf /etc/security/policy.conf /etc/default/login" ;;
    HPUX)    echo "/etc/pam.conf /etc/default/security" ;;
    *)
        case "$OS_DISTRO" in
        RHEL|CENTOS|ORACLE|AMZN) echo "/etc/pam.d/system-auth /etc/pam.d/password-auth" ;;
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

# 일반 계정 UID 하한 (Linux: login.defs UID_MIN, 없으면 RHEL 6 이하 500/그 외 1000, AIX 200, Solaris 100, HP-UX 101)
_uidmin() {
    local v
    case "$OS_FAMILY" in
    AIX) echo 200 ;; SOLARIS) echo 100 ;; HPUX) echo 101 ;;
    *)
        v=$(awk '$1=="UID_MIN"{print $2}' /etc/login.defs 2>/dev/null | tail -1)
        if [ -z "$v" ]; then
            case "$OS_DISTRO" in
            RHEL|CENTOS|ORACLE) [ "${OS_MAJOR:-7}" -lt 7 ] 2>/dev/null && v=500 || v=1000 ;;
            *) v=1000 ;;
            esac
        fi
        echo "$v" ;;
    esac
}
_UIDMIN=$(_uidmin)

# 로컬 파일시스템 마운트 지점 (find -xdev 를 마운트별로 실행: GNU 전용 옵션 없이 전체 탐색)
_local_mounts() {
    local m
    m=$(df -lP 2>/dev/null | awk 'NR>1{print $NF}' | grep '^/' | grep -vE '^/(proc|sys|dev|run)(/|$)' | sort -u | tr '\n' ' ')
    [ -z "$m" ] && m=$(df -l 2>/dev/null | awk '/^\//{print $1}' | grep -vE '^/(proc|sys|dev|run)(/|$)' | sort -u | tr '\n' ' ')
    [ -z "$m" ] && m="/"
    echo "$m"
}
_FIND_TO=0; _FIND_NA=0
_FIND_NA_MSG="find 명령이 없어 파일을 검색하지 못함 (findutils 설치 후 재점검)"
_find_scan() {   # _find_scan 출력파일 find표현식... : 로컬 FS 별 실행. 타임아웃(124)이면 _FIND_TO=1, find 명령이 없으면 _FIND_NA=1
    local out="$1" m rc; shift
    : > "$out"; _FIND_TO=0; _FIND_NA=0
    command -v find >/dev/null 2>&1 || { _FIND_NA=1; return 0; }
    for m in $(_local_mounts); do
        _to 60 find "$m" -xdev "$@" >> "$out" 2>/dev/null; rc=$?
        [ $rc -eq 124 ] && _FIND_TO=1
    done
    return 0
}

# 권한이 기준을 넘는 비트를 가졌는지 ($1 권한, $2 기준)
_perm_over() { [ -n "$1" ] && [ $(( 8#$1 & ~8#$2 & 8#7777 )) -ne 0 ] 2>/dev/null; }

# 파일 하나의 소유자·권한 평가: _fp_eval 파일 최대권한 허용소유자('|' 구분)
#   반환 0=기준 충족, 1=기준 위반, 2=소유자·권한을 읽지 못함 / 결과 설명은 _FP_MSG, 값은 _FP_P _FP_O
_FP_MSG=""; _FP_P=""; _FP_O=""
_fp_eval() {
    local f="$1" max="$2" owners="${3:-root}"
    _FP_MSG=""; _FP_P=$(get_perm "$f"); _FP_O=$(get_owner "$f")
    if [ -z "$_FP_P" ] || [ -z "$_FP_O" ] || ! echo "$_FP_P" | grep -qE '^[0-7]{3,4}$'; then
        _FP_MSG="${f} 소유자/권한 조회 실패(owner=${_FP_O:-없음}, perm=${_FP_P:-없음})"; return 2
    fi
    local bad=""
    echo " ${owners//|/ } " | grep -q " ${_FP_O} " || bad="소유자=${_FP_O}(${owners//|/ 또는 } 필요)"
    _perm_over "$_FP_P" "$max" && bad="${bad:+${bad}, }권한=${_FP_P}(${max} 이하 필요)"
    if [ -n "$bad" ]; then _FP_MSG="${f} ${bad}"; return 1; fi
    _FP_MSG="${f} 소유자=${_FP_O}, 권한=${_FP_P}"; return 0
}
# _check_file_perm 코드 "파일1 파일2 ..." 최대권한 허용소유자 설명 : 여러 파일이어도 항목당 1줄만 출력
_check_file_perm() {
    local code="$1" files="$2" max="$3" req_owner="${4:-root}" desc="$5" f rc
    local ok="" bad="" unk="" none="" n=0
    evd "$code" "ls -ld $files 2>&1"
    for f in $files; do
        if [ ! -e "$f" ] && [ ! -L "$f" ]; then none="${none} ${f}"; continue; fi
        n=$((n+1)); _fp_eval "$f" "$max" "$req_owner"; rc=$?
        case $rc in 0) ok="${ok:+${ok} / }${_FP_MSG}" ;; 1) bad="${bad:+${bad} / }${_FP_MSG}" ;; *) unk="${unk:+${unk} / }${_FP_MSG}" ;; esac
    done
    if [ -n "$bad" ]; then result "$code|취약|${bad}${unk:+ / 조회실패: ${unk}}"
    elif [ -n "$unk" ]; then result "$code|점검불가|${unk} - 소유자·권한을 읽지 못함(권한 부족 또는 stat/istat/ls 실패)"
    elif [ $n -eq 0 ]; then result "$code|양호|${desc} 미존재 - 권한을 점검할 파일 없음"
    else result "$code|양호|${ok}"; fi
}
# 파일 목록(공백 구분)을 한꺼번에 평가해 위반/조회실패 목록을 전역에 누적: _fp_list 파일목록파일 최대권한 허용소유자
_V=""; _UK=""; _NV=0; _NUK=0; _NCHK=0
_fp_reset() { _V=""; _UK=""; _NV=0; _NUK=0; _NCHK=0; }
_fp_add() {   # _fp_add 파일 최대권한 허용소유자
    local rc; _NCHK=$((_NCHK+1)); _fp_eval "$1" "$2" "${3:-root}"; rc=$?
    case $rc in 1) _NV=$((_NV+1)); _V="${_V}${_FP_MSG}
" ;; 2) _NUK=$((_NUK+1)); _UK="${_UK}${_FP_MSG}
" ;; esac
}
_V_join() { printf '%s' "$_V" | grep -v '^$' | _join; }
_UK_join() { printf '%s' "$_UK" | grep -v '^$' | _join; }
# 위반/조회실패 누적 결과를 판정: _fp_verdict 코드 양호문구
_fp_verdict() {
    if [ "$_NV" -gt 0 ]; then result "$1|취약|기준 위반 ${_NV}건: $(_V_join)${_NUK:+ / 조회실패 ${_NUK}건}"
    elif [ "$_NUK" -gt 0 ]; then result "$1|점검불가|소유자·권한 조회 실패 ${_NUK}건: $(_UK_join)"
    else result "$1|양호|$2 (점검 ${_NCHK}건)"; fi
}

# SNMP 설정 줄 출력 (community·SNMPv3 비밀번호 마스킹: 앞 2자 + ***)
_snmp_dump() {
    local f
    for f in "$@"; do
        [ -f "$f" ] || continue
        grep -vE '^[[:space:]]*(#|$)' "$f" 2>/dev/null | awk -v F="$f" '
        function mk(s){ return substr(s,1,2) "***" }
        { l=tolower($1)
          if (l ~ /^r[ow]community6?$/) { $2=mk($2) }
          else if (l ~ /^com2sec6?$/) { i=2; while ($i ~ /^-/) i+=2; $(i+2)=mk($(i+2)) }
          else if (l ~ /^createuser$/) { for(i=4;i<=NF;i++) if ($i !~ /^(MD5|SHA|SHA-?[0-9]*|DES|AES|AES128|AES192|AES256|-.*)$/ ) $i="***" }
          else if (l == "community") { $2=mk($2); if (NF>=3 && $3 !~ /^[0-9.]+$/ && $3 !~ /(Auth|auth)/) $3=mk($3) }
          else if (l ~ /^(read|write|trap)-community$/ || l ~ /^(get|set)-community-name:?$/) { $2=mk($2) }
          print F ": " $0 }'
    done
    return 0
}

evd_cfg() { local it="$1"; shift; evd "$it" "ls -ld $* 2>&1; grep -vE '^[[:space:]]*(#|\$)' $* /dev/null 2>/dev/null"; }   # 파일 상태 + 활성 설정 줄(파일명 접두)
_sshd_conf_files() { local f; ls -d /etc/ssh/sshd_config.d/*.conf 2>/dev/null; for f in /etc/ssh/sshd_config /opt/ssh/etc/sshd_config /usr/local/etc/ssh/sshd_config /etc/sshd_config; do [ -f "$f" ] && echo "$f"; done; }
_sshd_present() { command -v sshd >/dev/null 2>&1 || [ -x /usr/sbin/sshd ] || [ -n "$(_sshd_conf_files)" ] || is_running sshd; }
_sshd_get() {   # _sshd_get 키 : 유효값 (sshd -T 우선, 실패하면 설정 파일의 첫 설정값, Match 블록 이전만)
    local key v="" f; key=$(echo "$1" | tr 'A-Z' 'a-z')
    if command -v sshd >/dev/null 2>&1 || [ -x /usr/sbin/sshd ]; then
        v=$( (sshd -T 2>/dev/null || /usr/sbin/sshd -T 2>/dev/null) | awk -v k="$key" '$1==k{print $2; exit}')
        [ -n "$v" ] && { echo "$v"; return; }
    fi
    for f in $(_sshd_conf_files); do
        v=$(awk -v k="$key" 'tolower($1)=="match"{exit} tolower($1)==k{print $2; exit}' "$f" 2>/dev/null)
        [ -n "$v" ] && { echo "$v"; return; }
    done
}

check_U01() {
    local sshf; sshf=$(_sshd_conf_files | tr '\n' ' ')
    local tel=""
    { is_running telnetd || is_running in.telnetd; } && tel="${tel} 프로세스"
    [ -n "$(_inet_on telnet)" ] && tel="${tel} $(_inet_on telnet)"
    [ -n "$(_listen 23)" ] && tel="${tel} 23/tcp"
    case "$OS_FAMILY" in
    AIX)
        evd "U-01" "lsuser -a rlogin root 2>&1; awk '/^root:/{f=1;print;next} /^[^ \t*#]/{f=0} f' /etc/security/user 2>&1; ls -l ${sshf:-/etc/ssh/sshd_config} 2>&1; grep -inE '^[[:space:]]*PermitRootLogin' ${sshf:-/etc/ssh/sshd_config} /dev/null 2>&1; sshd -T 2>&1 | grep -i permitrootlogin"
        local val sv
        val=$(awk '/^root:/{f=1;next} /^[^ \t*#]/{f=0} f' /etc/security/user 2>/dev/null | grep -w "rlogin" | awk -F= '{gsub(/ /,"",$2);print $2}' | tail -1)
        if [ ! -r /etc/security/user ]; then result "U-01|점검불가|/etc/security/user 를 읽지 못함(권한 부족 또는 파일 없음)"; return; fi
        sv=$(_sshd_get PermitRootLogin | tr 'A-Z' 'a-z')
        if _sshd_present && [ -z "$sv" ] && _unreadable $sshf; then result "U-01|점검불가|sshd 설정 파일을 읽지 못함(권한 부족)"; return; fi
        if [ "$val" = "false" ] && { [ "$sv" = "no" ] || ! _sshd_present; }; then result "U-01|양호|root rlogin=false, PermitRootLogin=${sv:-sshd 미설치}"
        else result "U-01|취약|root rlogin=${val:-미설정(기본 true)}, PermitRootLogin=${sv:-미설정} (가이드: rlogin=false, PermitRootLogin No)"; fi ;;
    *)
        evd "U-01" "ls -l ${sshf:-/etc/ssh/sshd_config} 2>&1; grep -inE '^[[:space:]]*(PermitRootLogin|Include|Match)' ${sshf:-/etc/ssh/sshd_config} /dev/null 2>&1; (sshd -T 2>&1 | grep -i permitrootlogin); echo \"telnet 활성 경로: ${tel:-없음}\""
        [ -n "$tel" ] && evd "U-01" "ls -l /etc/securetty /etc/pam.d/login /etc/default/login 2>&1; grep -nE '^[[:space:]]*[^#[:space:]]' /etc/securetty /dev/null 2>&1; grep -n pam_securetty /etc/pam.d/login /dev/null 2>&1; grep -n '^CONSOLE' /etc/default/login /dev/null 2>&1"
        local why="" rl="" sshp=0
        if _sshd_present; then
            sshp=1; rl=$(_sshd_get PermitRootLogin | tr 'A-Z' 'a-z')
            if [ -z "$rl" ] && _unreadable $sshf; then result "U-01|점검불가|sshd 설정 파일을 읽지 못함(권한 부족)"; return; fi
            [ "$rl" != "no" ] && why="SSH PermitRootLogin=${rl:-미설정(기본값: root 로그인 허용 또는 prohibit-password)}"
        fi
        if [ -n "$tel" ]; then
            case "$OS_FAMILY" in
            SOLARIS) grep -qE '^CONSOLE=[^[:space:]]' /etc/default/login 2>/dev/null || why="${why:+${why} / }Telnet 사용, /etc/default/login CONSOLE 미설정" ;;
            HPUX)    { [ -f /etc/securetty ] && ! grep -vE '^[[:space:]]*(#|$|console[[:space:]]*$)' /etc/securetty 2>/dev/null | grep -q .; } || why="${why:+${why} / }Telnet 사용, /etc/securetty 가 console 만 허용하지 않음" ;;
            *)
                grep -qE '^[[:space:]]*pts' /etc/securetty 2>/dev/null && why="${why:+${why} / }Telnet 사용, /etc/securetty 에 pts 허용"
                [ -f /etc/pam.d/login ] && ! grep -vE '^[[:space:]]*#' /etc/pam.d/login 2>/dev/null | grep -q pam_securetty && why="${why:+${why} / }Telnet 사용, /etc/pam.d/login 에 pam_securetty 미적용" ;;
            esac
        fi
        if [ -n "$why" ]; then result "U-01|취약|${why} (가이드: PermitRootLogin No, Telnet 은 securetty/pam_securetty)"
        elif [ $sshp -eq 0 ] && [ -z "$tel" ]; then result "U-01|양호|원격 접속 서비스(sshd·telnet) 미설치/미사용"
        else result "U-01|양호|$([ $sshp -eq 1 ] && echo 'SSH PermitRootLogin=no')$([ -n "$tel" ] && echo ', Telnet 사용 - securetty pts 미허용·pam_securetty 적용')"; fi ;;
    esac
}

check_U02() {
    local bad="" cur="" ml="" mx="" mn="" hi="" cls=0 pf="" f
    case "$OS_FAMILY" in
    AIX)
        evd "U-02" "lsuser -a minlen minalpha minother maxage minage histsize ALL 2>&1; awk '/^default:/{f=1;print;next} /^[^ \t*#]/{f=0} f' /etc/security/user 2>&1"
        _av() { _aix_default | grep -w "$1" | grep -oE '[0-9]+' | head -1; }
        [ -r /etc/security/user ] || { result "U-02|점검불가|/etc/security/user 를 읽지 못함"; return; }
        ml=$(_av minlen); local ma=$(_av minalpha) mo=$(_av minother); mx=$(_av maxage); mn=$(_av minage); hi=$(_av histsize)
        [ "${ma:-0}" -ge 1 ] 2>/dev/null && cls=$((cls+1)); [ "${mo:-0}" -ge 1 ] 2>/dev/null && cls=$((cls+2))
        [ -n "$mx" ] && mx=$((mx*7)); [ -n "$mn" ] && mn=$((mn*7))
        cur="minlen=${ml:-미설정}, minalpha=${ma:-미설정}, minother=${mo:-미설정}, maxage=${mx:-미설정}일, minage=${mn:-미설정}일, histsize=${hi:-미설정}" ;;
    SOLARIS)
        f=/etc/default/passwd
        evd_cfg "U-02" $f
        [ -r $f ] || { result "U-02|점검불가|$f 를 읽지 못함"; return; }
        ml=$(_nc $f | grep '^PASSLENGTH=' | tail -1 | cut -d= -f2); hi=$(_nc $f | grep '^HISTORY=' | tail -1 | cut -d= -f2)
        local w=$(_nc $f | grep '^MAXWEEKS=' | tail -1 | cut -d= -f2); [ -n "$w" ] && mx=$((w*7))
        w=$(_nc $f | grep '^MINWEEKS=' | tail -1 | cut -d= -f2); [ -n "$w" ] && mn=$((w*7))
        cls=$(_nc $f | grep -cE '^(MINDIGIT|MINSPECIAL|MINUPPER|MINLOWER)=[1-9]')
        local al; al=$(_nc $f | grep -cE '^MINALPHA=[1-9]'); local na; na=$(_nc $f | grep -cE '^MINNONALPHA=[1-9]')
        [ "$cls" -lt 4 ] && cls=$((cls + (al>0 && cls<2 ? 1 : 0) + (na>0 && cls<3 ? 1 : 0)))
        cur="PASSLENGTH=${ml:-미설정}, 문자종류 최소입력 ${cls}종(MINDIGIT/SPECIAL/UPPER/LOWER/ALPHA/NONALPHA 기준 근사), MAXWEEKS→${mx:-미설정}일, MINWEEKS→${mn:-미설정}일, HISTORY=${hi:-미설정}" ;;
    HPUX)
        f=/etc/default/security
        evd_cfg "U-02" $f
        [ -r $f ] || { result "U-02|점검불가|$f 를 읽지 못함"; return; }
        ml=$(_nc $f | grep '^MIN_PASSWORD_LENGTH=' | tail -1 | cut -d= -f2); hi=$(_nc $f | grep '^PASSWORD_HISTORY_DEPTH=' | tail -1 | cut -d= -f2)
        mx=$(_nc $f | grep '^PASSWORD_MAXDAYS=' | tail -1 | cut -d= -f2); mn=$(_nc $f | grep '^PASSWORD_MINDAYS=' | tail -1 | cut -d= -f2)
        cls=$(_nc $f | grep -cE '^PASSWORD_MIN_(DIGIT|SPECIAL|UPPER_CASE|LOWER_CASE)_CHARS=[1-9]')
        cur="MIN_PASSWORD_LENGTH=${ml:-미설정}, 문자종류 최소입력 ${cls}종, MAXDAYS=${mx:-미설정}, MINDAYS=${mn:-미설정}, HISTORY=${hi:-미설정}" ;;
    *)
        local cfg="" files=""
        for f in /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf /etc/security/pwhistory.conf /etc/security/pwhistory.conf.d/*.conf; do
            [ -f "$f" ] && { files="${files} $f"; cfg="${cfg} $(grep -vE '^[[:space:]]*#' "$f" 2>/dev/null | tr '\n' ' ')"; }
        done
        for f in $(get_pam_files) /etc/pam.d/password-auth /etc/pam.d/common-password /etc/pam.d/system-auth; do
            [ -f "$f" ] && { pf="${pf} $f"; cfg="${cfg} $(grep -vE '^[[:space:]]*#' "$f" 2>/dev/null | grep -E 'pam_pwquality|pam_cracklib|pam_pwhistory|pam_unix' | tr '\n' ' ')"; }
        done
        pf=$(echo $pf | tr ' ' '\n' | awk '!x[$0]++' | tr '\n' ' ')
        evd "U-02" "ls -l ${files} ${pf} /etc/login.defs 2>&1; grep -vE '^[[:space:]]*(#|\$)' ${files} /dev/null 2>/dev/null; grep -E '^[[:space:]]*[^#[:space:]].*(pam_pwquality|pam_cracklib|pam_pwhistory|pam_unix)' ${pf} /dev/null 2>/dev/null | sed 's|^\\([^:]*\\):|[\\1] |'; grep -E '^[[:space:]]*PASS_(MAX|MIN)_DAYS|^[[:space:]]*PASS_MIN_LEN|^[[:space:]]*ENCRYPT_METHOD' /etc/login.defs /dev/null 2>&1"
        [ -z "$files$pf" ] && { result "U-02|점검불가|비밀번호 정책 설정 파일(pwquality.conf·PAM)을 찾지 못함"; return; }
        _pv() { echo "$cfg" | grep -oE "(^|[[:space:]])$1[[:space:]]*=[[:space:]]*-?[0-9]+" | tail -1 | grep -oE -- '-?[0-9]+$'; }
        ml=$(_pv minlen); local dc=$(_pv dcredit) uc=$(_pv ucredit) lc=$(_pv lcredit) oc=$(_pv ocredit) mc=$(_pv minclass)
        hi=$(_pv remember)
        [ -z "$ml" ] && ml=$(awk '$1=="PASS_MIN_LEN"{print $2}' /etc/login.defs 2>/dev/null | tail -1)
        mx=$(awk '$1=="PASS_MAX_DAYS"{print $2}' /etc/login.defs 2>/dev/null | tail -1); mn=$(awk '$1=="PASS_MIN_DAYS"{print $2}' /etc/login.defs 2>/dev/null | tail -1)
        [ "${dc:-0}" -lt 0 ] 2>/dev/null && cls=$((cls+1)); [ "${oc:-0}" -lt 0 ] 2>/dev/null && cls=$((cls+1))
        [ "${uc:-0}" -lt 0 ] 2>/dev/null && cls=$((cls+1)); [ "${lc:-0}" -lt 0 ] 2>/dev/null && cls=$((cls+1))
        [ "${mc:-0}" -gt "$cls" ] 2>/dev/null && cls=$mc
        cur="minlen=${ml:-미설정}, dcredit=${dc:-미설정}, ucredit=${uc:-미설정}, lcredit=${lc:-미설정}, ocredit=${oc:-미설정}$([ -n "$mc" ] && echo ", minclass=${mc}"), PASS_MAX_DAYS=${mx:-미설정}, PASS_MIN_DAYS=${mn:-미설정}, remember=${hi:-미설정}" ;;
    esac
    # 가이드: 영문 대·소문자/숫자/특수문자 중 3종류 이상 조합 8자 이상 또는 2종류 이상 조합 10자 이상
    { { [ "${ml:-0}" -ge 8 ] 2>/dev/null && [ "$cls" -ge 3 ] 2>/dev/null; } || { [ "${ml:-0}" -ge 10 ] 2>/dev/null && [ "$cls" -ge 2 ] 2>/dev/null; }; } || bad="${bad}, 3종류 8자 이상(또는 2종류 10자 이상) 미충족"
    { [ -n "$mx" ] && [ "$mx" -gt 0 ] 2>/dev/null && [ "$mx" -le 90 ] 2>/dev/null; } || bad="${bad}, 최대 사용기간 90일 초과/미설정"
    [ "${mn:-0}" -ge 1 ] 2>/dev/null || bad="${bad}, 최소 사용기간 1일 미만"
    [ "${hi:-0}" -ge 4 ] 2>/dev/null || bad="${bad}, 최근 비밀번호 기억 4회 미만/미설정"
    if [ -n "$bad" ]; then result "U-02|취약|비밀번호 관리정책 미흡: ${bad#, } (${cur})"; else result "U-02|양호|비밀번호 관리정책 설정 (${cur})"; fi
}

check_U03() {
    local f deny="" src=""
    case "$OS_FAMILY" in
    AIX)
        evd "U-03" "lsuser -a loginretries ALL 2>&1; awk '/^default:/{f=1;print;next} /^[^ \t*#]/{f=0} f' /etc/security/user 2>&1"
        [ -r /etc/security/user ] || { result "U-03|점검불가|/etc/security/user 를 읽지 못함"; return; }
        local lc=$(_aix_default | grep "loginretries" | grep -oE '[0-9]+' | head -1)
        if [ "${lc:-0}" -gt 0 ] 2>/dev/null && [ "${lc}" -le 10 ] 2>/dev/null; then result "U-03|양호|AIX loginretries=${lc}"
        else result "U-03|취약|AIX loginretries=${lc:-미설정} (1~10 필요)"; fi ;;
    SOLARIS)
        evd_cfg "U-03" /etc/default/login /etc/security/policy.conf
        local lk rt; lk=$(_nc /etc/security/policy.conf | grep '^LOCK_AFTER_RETRIES=' | tail -1 | cut -d= -f2); rt=$(_nc /etc/default/login | grep '^RETRIES=' | tail -1 | cut -d= -f2)
        [ -r /etc/security/policy.conf ] || { result "U-03|점검불가|/etc/security/policy.conf 를 읽지 못함"; return; }
        if [ "$(echo "$lk" | tr 'a-z' 'A-Z')" = "YES" ] && [ "${rt:-5}" -le 10 ] 2>/dev/null; then result "U-03|양호|LOCK_AFTER_RETRIES=YES, RETRIES=${rt:-5(기본)}"
        else result "U-03|취약|LOCK_AFTER_RETRIES=${lk:-미설정}, RETRIES=${rt:-미설정} (YES 및 10 이하 필요)"; fi ;;
    HPUX)
        evd_cfg "U-03" /etc/default/security
        [ -r /etc/default/security ] || { result "U-03|점검불가|/etc/default/security 를 읽지 못함"; return; }
        deny=$(_nc /etc/default/security | grep '^AUTH_MAXTRIES=' | tail -1 | cut -d= -f2)
        if [ -n "$deny" ] && [ "$deny" -gt 0 ] 2>/dev/null && [ "$deny" -le 10 ] 2>/dev/null; then result "U-03|양호|AUTH_MAXTRIES=${deny}"
        else result "U-03|취약|AUTH_MAXTRIES=${deny:-미설정} (1~10 필요)"; fi ;;
    *)
        local pfs; pfs="$(get_pam_files) /etc/pam.d/password-auth /etc/pam.d/system-auth /etc/pam.d/common-auth /etc/pam.d/common-account"
        pfs=$(echo $pfs | tr ' ' '\n' | awk '!x[$0]++' | tr '\n' ' ')
        evd "U-03" "ls -l ${pfs} /etc/security/faillock.conf 2>&1; grep -HE '^[[:space:]]*[^#[:space:]].*(pam_faillock|pam_tally2?|pam_tally)' ${pfs} /dev/null 2>/dev/null; grep -vE '^[[:space:]]*(#|\$)' /etc/security/faillock.conf /dev/null 2>&1"
        local used=0 pamdeny="" fcdeny=""
        for f in $pfs; do
            [ -f "$f" ] || continue
            grep -vE '^[[:space:]]*#' "$f" 2>/dev/null | grep -qE 'pam_faillock|pam_tally2?' && used=1
            [ -z "$pamdeny" ] && pamdeny=$(grep -vE '^[[:space:]]*#' "$f" 2>/dev/null | grep -E 'pam_faillock|pam_tally2?' | grep -oE 'deny=[0-9]+' | head -1 | cut -d= -f2)
        done
        fcdeny=$(_nc /etc/security/faillock.conf | sed -n 's/^[[:space:]]*deny[[:space:]]*=[[:space:]]*\([0-9][0-9]*\).*/\1/p' | tail -1)
        deny="${pamdeny:-$fcdeny}"; [ -n "$pamdeny" ] && src="PAM 모듈 인자" || { [ -n "$fcdeny" ] && src="faillock.conf"; }
        if [ $used -eq 0 ]; then
            if ! _exist $pfs | grep -q "/"; then result "U-03|점검불가|PAM 설정 파일을 찾지 못함"; else result "U-03|취약|계정 잠금 모듈(pam_faillock/pam_tally2) 미적용"; fi
        else
            [ -z "$deny" ] && { deny=3; src="pam_faillock 기본값"; }
            if [ "$deny" -gt 0 ] 2>/dev/null && [ "$deny" -le 10 ] 2>/dev/null; then result "U-03|양호|계정 잠금 임계값 deny=${deny} (${src})"
            else result "U-03|취약|계정 잠금 임계값 deny=${deny} (${src}) - 1~10 필요(0 은 잠금 없음)"; fi
        fi ;;
    esac
}

check_U04() {
    evd "U-04" "ls -l /etc/shadow /etc/security/passwd /tcb/files/auth /etc/passwd 2>&1; awk -F: '{n++; if(\$2!=\"x\" && \$2!=\"*\" && \$2!=\"!\" && \$2!=\"!!\"){m++; print \$1\": 비밀번호 필드=\"(\$2==\"\"?\"(빈 값)\":\"x 아님\")}} END{print \"/etc/passwd 계정 \"n\"개, 비밀번호 필드가 x 가 아닌 계정 \"m+0\"개\"}' /etc/passwd 2>&1"
    case "$OS_FAMILY" in
    AIX) if [ -f /etc/security/passwd ]; then result "U-04|양호|AIX 비밀번호를 /etc/security/passwd 에 분리 저장"; else result "U-04|취약|AIX /etc/security/passwd 없음"; fi ;;
    HPUX)
        if [ -f /etc/shadow ] || [ -d /tcb/files/auth ]; then result "U-04|양호|HP-UX $([ -d /tcb/files/auth ] && echo 'Trusted Mode(/tcb)' || echo '/etc/shadow') 사용"
        else result "U-04|취약|HP-UX shadow·Trusted Mode 미사용 (비밀번호가 /etc/passwd 에 저장)"; fi ;;
    *)
        local np; np=$(awk -F: '$2!="x" && $2!="*" && $2!="!" && $2!="!!" {print $1}' /etc/passwd 2>/dev/null | tr '\n' ' ')
        if [ ! -r /etc/passwd ]; then result "U-04|점검불가|/etc/passwd 를 읽지 못함"
        elif [ ! -f /etc/shadow ]; then result "U-04|취약|/etc/shadow 없음 - 쉐도우 비밀번호 미사용"
        elif [ -n "$np" ]; then result "U-04|취약|/etc/passwd 에 비밀번호 필드가 x 가 아닌 계정: ${np% } (쉐도우 미사용 계정)"
        else result "U-04|양호|쉐도우 비밀번호 사용 (/etc/shadow, /etc/passwd 비밀번호 필드 x)"; fi ;;
    esac
}

check_U05() {
    evd "U-05" "awk -F: '\$3==0{print \$1\":UID=\"\$3}' /etc/passwd 2>&1"
    [ -r /etc/passwd ] || { result "U-05|점검불가|/etc/passwd 를 읽지 못함"; return; }
    local found; found=$(awk -F: '$3==0 && $1!="root" {print $1}' /etc/passwd 2>/dev/null | tr '\n' ',' | sed 's/,$//')
    if [ -n "$found" ]; then result "U-05|취약|root 외 UID 0 계정: ${found}"; else result "U-05|양호|root 외 UID 0 없음"; fi
}

check_U06() {
    local sub; sub=$(command -v su 2>/dev/null || echo /bin/su)
    evd "U-06" "grep -nE '^[[:space:]]*[^#[:space:]].*pam_wheel' /etc/pam.d/su /dev/null 2>&1; ls -lL $sub 2>&1; awk -F: -v m=$_UIDMIN '\$3>=m && \$3<60000 && \$7!~/(nologin|false)\$/ {n++; print \$1, \$3, \$7} END{print \"UID \"m\" 이상 로그인 가능 일반 계정: \"n+0\"개\"}' /etc/passwd 2>&1"
    local users; users=$(awk -F: -v m="$_UIDMIN" '$3>=m && $3<60000 && $7!~/(nologin|false)$/ {print $1}' /etc/passwd 2>/dev/null | tr '\n' ' ')
    local sp sg; sp=$(get_perm "$sub"); sg=$(ls -lL "$sub" 2>/dev/null | awk '{print $4}')
    if grep -vE '^[[:space:]]*#' /etc/pam.d/su 2>/dev/null | grep -qE '^[[:space:]]*auth[[:space:]]+(required|requisite)[[:space:]]+pam_wheel'; then
        result "U-06|양호|su 사용 그룹 제한 (pam_wheel)"
    elif [ -n "$sp" ] && ! _perm_over "$sp" 4750 && [ -n "$sg" ] && [ "$sg" != "root" ]; then
        result "U-06|양호|su 명령어 권한 ${sp}, 그룹 ${sg} 으로 사용 제한"
    elif [ -z "$users" ]; then
        result "U-06|양호|일반 사용자 계정 없음 (root 만 사용 - 가이드상 su 제한 불필요)"
    elif [ -z "$sp" ]; then
        result "U-06|점검불가|su 명령어($sub) 권한을 조회하지 못함"
    else
        result "U-06|취약|su 명령어 사용 그룹 제한 미설정 (su 권한 ${sp}, 일반 사용자: ${users% })"
    fi
}

check_U07() {
    local lastcmd
    if command -v lastlog >/dev/null 2>&1; then lastcmd="lastlog"
    elif command -v lsuser >/dev/null 2>&1; then lastcmd="lsuser -a time_last_login ALL"
    elif command -v logins >/dev/null 2>&1; then lastcmd="logins -x"
    elif command -v last >/dev/null 2>&1; then lastcmd="last"
    else lastcmd=""; fi
    evd "U-07" "awk -F: '\$7 !~ /nologin|false/ {print \$1,\$7}' /etc/passwd 2>&1"
    if [ -z "$lastcmd" ]; then result "U-07|점검불가|lastlog·lsuser·logins·last 명령이 없어 마지막 로그인 이력을 조회하지 못함"; return; fi
    evd "U-07" "$lastcmd 2>&1"
    local inactive=""
    if [ "$lastcmd" = "lastlog" ]; then
        inactive=$(lastlog 2>/dev/null | awk 'NR>1 && /Never logged in/{print $1}' | while read -r u; do awk -F: -v u="$u" '$1==u && $7 !~ /(nologin|false)$/ {print u}' /etc/passwd; done | tr '\n' ' ')
    fi
    if [ -n "$inactive" ]; then result "U-07|수동확인|로그인 가능 shell 이 있으나 로그인 이력 없는 계정: $(echo $inactive | tr ' ' '\n' | _join) (불필요 여부 확인 - 증적 참조)"
    else result "U-07|수동확인|미사용 계정 수동 확인 (${lastcmd%% *} 결과·로그인 가능 계정 목록은 증적 참조)"; fi
}

check_U08() {
    local lockcmd lastcmd
    if [ "$OS_FAMILY" = "AIX" ]; then lockcmd="lsuser -a account_locked ALL 2>&1"
    else lockcmd="awk -F: '{s=(\$2 ~ /^[!*]/)?\"잠김/로그인불가\":\"사용가능\"; print \$1, s}' /etc/shadow 2>&1"; fi
    if command -v lastlog >/dev/null 2>&1; then lastcmd="lastlog 2>&1"; elif command -v last >/dev/null 2>&1; then lastcmd="last 2>&1"; else lastcmd="echo 'lastlog·last 명령 없음'"; fi
    evd "U-08" "grep -E '^(root|wheel|sudo|admin|system|sys|adm):' /etc/group /dev/null 2>&1; awk -F: '\$4==0{print \$1\":기본GID=0\"}' /etc/passwd 2>&1; grep -vE '^[[:space:]]*(#|\$)' /etc/sudoers /etc/sudoers.d/* /dev/null 2>&1"
    evd "U-08" "$lockcmd"
    evd "U-08" "$lastcmd"
    [ -r /etc/group ] || { result "U-08|점검불가|/etc/group 를 읽지 못함"; return; }
    local info="" grp members gid0
    for grp in root wheel sudo admin system; do
        members=$(grep "^${grp}:" /etc/group 2>/dev/null | cut -d: -f4 | tr ',' '\n' | grep -vxE 'root|' | tr '\n' ',' | sed 's/,$//')
        [ -n "$members" ] && info="${info} ${grp}:[${members}]"
    done
    gid0=$(awk -F: '$4==0 && $1!="root"{print $1}' /etc/passwd 2>/dev/null | tr '\n' ',' | sed 's/,$//')
    [ -n "$gid0" ] && info="${info} 기본GID0:[${gid0}]"
    if [ -n "$info" ]; then result "U-08|수동확인|관리자 그룹 구성원:${info} - 불필요한 계정 여부 확인(sudoers·잠금 상태·최근 로그인은 증적 참조)"
    else result "U-08|양호|관리자 그룹(root·wheel·sudo·admin·system) 및 기본 GID 0 에 root 외 구성원 없음"; fi
}

check_U09() {
    evd "U-09" "awk -F: -v m=$_UIDMIN '\$3>=m && \$3<60000 {n++; print \$1\":\"\$3\":\"\$4} END{print \"GID \"m\" 이상 그룹: \"n+0\"개\"}' /etc/group 2>&1; awk -F: '{print \$4}' /etc/passwd 2>&1 | sort -u | tr '\n' ' '"
    local prim; prim=" $(awk -F: '{print $4}' /etc/passwd 2>/dev/null | sort -u | tr '\n' ' ') "
    local empty; empty=$(awk -F: -v m="$_UIDMIN" '$3>=m && $3<60000 && $4=="" {print $1":"$3}' /etc/group 2>/dev/null | while IFS=: read -r g id; do case "$prim" in *" $id "*) ;; *) printf '%s(%s) ' "$g" "$id" ;; esac; done)
    if [ -n "$empty" ]; then result "U-09|수동확인|구성원이 없는 그룹: ${empty% } - 시스템 관리·운용에 불필요하면 제거"; else result "U-09|양호|구성원이 없는 일반 그룹 없음"; fi
}

check_U10() {
    evd "U-10" "awk -F: '{c[\$3]++; n++} END{for(u in c) if(c[u]>1) d=d\" \"u; print \"계정 \"n\"개, 중복 UID:\"(d==\"\"?\" 없음\":d)}' /etc/passwd 2>&1"
    [ -r /etc/passwd ] || { result "U-10|점검불가|/etc/passwd 를 읽지 못함"; return; }
    local dup; dup=$(awk -F: '{print $3}' /etc/passwd 2>/dev/null | sort -n | uniq -d | tr '\n' ',' | sed 's/,$//')
    if [ -n "$dup" ]; then result "U-10|취약|중복 UID: ${dup}"; else result "U-10|양호|중복 UID 없음"; fi
}

check_U11() {
    evd "U-11" "awk -F: '\$1 ~ /^(daemon|bin|sys|adm|listen|nobody|nobody4|noaccess|diag|operator|games|gopher)\$/ {n++; print \$1\":\"\$7} END{print \"점검 대상 시스템 계정 \"n+0\"개\"}' /etc/passwd 2>&1"
    [ -r /etc/passwd ] || { result "U-11|점검불가|/etc/passwd 를 읽지 못함"; return; }
    local vuln; vuln=$(grep -E '^(daemon|bin|sys|adm|listen|nobody|nobody4|noaccess|diag|operator|games|gopher):' /etc/passwd 2>/dev/null | awk -F: '$7 !~ /(nologin|false)$/ {printf " %s(%s)", $1, ($7==""?"기본쉘":$7)}')
    if [ -n "$vuln" ]; then result "U-11|취약|로그인 불필요 계정에 쉘 부여:${vuln}"; else result "U-11|양호|로그인 불필요 계정(daemon·bin·sys·adm·listen·nobody·operator·games 등)에 nologin/false 부여"; fi
}

# TMOUT 우변 값을 숫자로 (산술식 $((..)) 지원, 해석 불가면 ?)
_tmout_val() {
    local r="$1"
    r=$(echo "$r" | sed "s/^[\"']//; s/[;[:space:]].*//; s/[\"']\$//")
    case "$r" in
    ''|*[!0-9]*) ;;
    *) echo "$r"; return ;;
    esac
    case "$r" in
    '$(('*'))') local e="${r#\$((}"; e="${e%))}"
        if echo "$e" | grep -qE '^[0-9+*/() -]+$'; then echo $(( e )) 2>/dev/null && return; fi ;;
    '${TMOUT:-'*'}'|'${TMOUT:='*'}') r="${r#*[-=]}"; r="${r%\}}"; echo "$r" | grep -qE '^[0-9]+$' && { echo "$r"; return; } ;;
    esac
    echo "?"
}
check_U12() {
    local files="" f
    for f in /etc/profile /etc/profile.d/*.sh /etc/bashrc /etc/bash.bashrc /etc/ksh.kshrc /etc/csh.cshrc /etc/csh.login /etc/csh.cshrc.d/* /etc/environment /root/.bash_profile /root/.bashrc /root/.profile /root/.kshrc /root/.cshrc /root/.login; do
        [ -f "$f" ] && files="${files} $f"
    done
    local sshf; sshf=$(_sshd_conf_files | tr '\n' ' ')
    evd "U-12" "ls -l ${files:-/etc/profile} 2>&1; grep -nE 'TMOUT|autologout' ${files:-/etc/profile} /dev/null 2>&1; echo \"TMOUT/autologout 포함 줄: \$(cat ${files:-/etc/profile} 2>/dev/null | grep -cE 'TMOUT|autologout')줄\"; grep -inE '^[[:space:]]*(ClientAliveInterval|ClientAliveCountMax)' ${sshf:-/etc/ssh/sshd_config} /dev/null 2>&1; sshd -T 2>&1 | grep -iE 'clientalive'"
    local tm="" tsrc="" cs="" csrc="" line v
    for f in $files; do
        case "$f" in
        *csh*|*/.login)
            line=$(grep -vE '^[[:space:]]*#' "$f" 2>/dev/null | grep -E 'autologout' | tail -1)
            if [ -n "$line" ]; then v=$(echo "$line" | grep -oE 'autologout[[:space:]]*=[[:space:]]*[0-9]+' | grep -oE '[0-9]+$'); [ -n "$v" ] && { cs=$v; csrc=$f; }; fi ;;
        *)
            line=$(grep -vE '^[[:space:]]*#' "$f" 2>/dev/null | grep -E '(^|[[:space:];])TMOUT=' | tail -1)
            if [ -n "$line" ]; then v=$(_tmout_val "$(echo "$line" | sed 's/.*TMOUT=//')"); tm="$v"; tsrc="$f"; fi ;;
        esac
    done
    # 일반 계정 홈 파일에서 TMOUT 을 해제(0)하거나 600초 초과로 재정의한 경우 (전역 설정을 무력화)
    local uo="" uh uf uv
    for uh in $(awk -F: '$7!~/(nologin|false|sync|shutdown|halt)$/ && $6!="" && $6!="/" && $6!="/root" {print $6}' /etc/passwd 2>/dev/null | sort -u); do
        for uf in "$uh/.profile" "$uh/.bash_profile" "$uh/.bashrc" "$uh/.kshrc"; do
            [ -f "$uf" ] && [ -r "$uf" ] || continue
            line=$(grep -vE '^[[:space:]]*#' "$uf" 2>/dev/null | grep -E '(^|[[:space:];])TMOUT=' | tail -1)
            [ -n "$line" ] || continue
            uv=$(_tmout_val "$(echo "$line" | sed 's/.*TMOUT=//')")
            if [ "$uv" = "?" ] || [ "$uv" = "0" ] || [ "$uv" -gt 600 ] 2>/dev/null; then uo="${uo} ${uf}(TMOUT=${uv})"; fi
        done
    done
    local ci cc sshp=""
    if _sshd_present; then
        ci=$(_sshd_get ClientAliveInterval); cc=$(_sshd_get ClientAliveCountMax)
        if [ -z "$ci" ] && _unreadable $sshf; then sshp="unreadable"
        else ci="${ci:-0}"; cc="${cc:-3}"; sshp="${ci}x${cc}"; fi
    fi
    local info="" ok=0 badmsg=""
    if [ -n "$tm" ]; then
        if [ "$tm" = "?" ]; then info="${info}TMOUT 값 해석 불가(${tsrc}) "
        elif [ "$tm" -gt 0 ] 2>/dev/null && [ "$tm" -le 600 ] 2>/dev/null; then ok=1; info="${info}TMOUT=${tm}초(${tsrc}) "
        elif [ "$tm" -eq 0 ] 2>/dev/null; then badmsg="TMOUT=0 (세션 종료 해제, ${tsrc})"
        else badmsg="TMOUT=${tm}초 (600초 초과, ${tsrc})"; fi
    fi
    if [ -n "$cs" ]; then
        if [ "$cs" -gt 0 ] 2>/dev/null && [ "$cs" -le 10 ] 2>/dev/null; then ok=1; info="${info}csh autologout=${cs}분(${csrc}) "; else badmsg="${badmsg:+${badmsg} / }csh autologout=${cs}분 (10분 초과 또는 해제, ${csrc})"; fi
    fi
    case "$sshp" in
    unreadable) info="${info}sshd 설정 읽기 실패 " ;;
    '') ;;
    *) if [ "$ci" -gt 0 ] 2>/dev/null && [ $((ci*cc)) -le 600 ] 2>/dev/null && [ "$cc" -gt 0 ] 2>/dev/null; then ok=1; info="${info}sshd ClientAliveInterval×CountMax=${ci}×${cc}=$((ci*cc))초 "
       else info="${info}sshd ClientAlive ${ci}×${cc} (유휴 종료 없음/600초 초과) "; fi ;;
    esac
    [ -n "$uo" ] && badmsg="${badmsg:+${badmsg} / }계정 홈 파일에서 TMOUT 해제·600초 초과:${uo}"
    if [ -n "$badmsg" ]; then result "U-12|취약|${badmsg} (600초 이하 필요)"
    elif [ $ok -eq 1 ]; then result "U-12|양호|세션 종료 시간 600초 이하 설정: ${info}"
    elif [ "$tm" = "?" ]; then result "U-12|수동확인|TMOUT 설정이 산술식·변수 등 해석 불가(${tsrc}) - 증적 확인"
    elif [ "$sshp" = "unreadable" ] && [ -z "$files" ]; then result "U-12|점검불가|세션 종료 설정 파일을 읽지 못함"
    else result "U-12|취약|TMOUT·autologout·sshd ClientAlive 어느 것도 600초 이하로 설정되지 않음 (${info:-미설정})"; fi
}

check_U13() {
    local hashsrc="/etc/shadow"
    case "$OS_FAMILY" in AIX) hashsrc="/etc/security/passwd" ;; esac
    if [ "$OS_FAMILY" = "AIX" ]; then
        evd "U-13" "ls -l /etc/security/passwd /etc/security/login.cfg 2>&1; grep -nE '^[[:space:]]*pwd_algorithm' /etc/security/login.cfg /dev/null 2>&1; awk '/^[A-Za-z0-9_.-]+:/{u=\$1} /password[[:space:]]*=/{v=\$3; if(substr(v,1,1)==\"{\"){i=index(v,\"}\"); print u, substr(v,1,i)} else print u, \"crypt(DES)\"}' /etc/security/passwd 2>&1"
        local alg; alg=$(_nc /etc/security/login.cfg | grep -E '^[[:space:]]*pwd_algorithm' | tail -1 | awk -F= '{gsub(/[ \t]/,"",$2);print $2}')
        [ -r /etc/security/passwd ] || { result "U-13|점검불가|/etc/security/passwd 를 읽지 못함(root 필요)"; return; }
        local weak; weak=$(awk '/^[A-Za-z0-9_.-]+:/{u=$1} /password[[:space:]]*=/{v=$3; if(substr(v,1,1)=="{"){ if(v !~ /^\{ssha(256|512)\}/) printf "%s%s ", u, substr(v,1,index(v,"}"))} else if (v != "*" && v != "!") printf "%s(crypt/DES) ", u}' /etc/security/passwd 2>/dev/null)
        if [ -n "$weak" ]; then result "U-13|취약|SHA-2 미만 알고리즘 사용 계정: $(echo $weak | tr ' ' '\n' | _join) (pwd_algorithm=${alg:-미설정(기본 crypt)})"
        elif [ "$alg" = "ssha256" ] || [ "$alg" = "ssha512" ]; then result "U-13|양호|pwd_algorithm=${alg}, 저장된 해시 모두 SHA-2"
        else result "U-13|취약|pwd_algorithm=${alg:-미설정(기본 crypt)} (ssha256/ssha512 필요)"; fi
        return
    fi
    if [ "$OS_FAMILY" = "HPUX" ] && [ ! -f /etc/shadow ]; then
        evd "U-13" "ls -ld /etc/shadow /tcb/files/auth 2>&1; grep -nE 'CRYPT|PASSWORD' /etc/default/security /dev/null 2>&1"
        result "U-13|수동확인|HP-UX Trusted Mode(/tcb) - 해시 알고리즘은 /etc/default/security(CRYPT_DEFAULT) 와 증적으로 확인"; return
    fi
    evd "U-13" "ls -l /etc/shadow 2>&1; grep -E '^[[:space:]]*(ENCRYPT_METHOD|MD5_CRYPT_ENAB)' /etc/login.defs /dev/null 2>&1; grep -E '^[[:space:]]*CRYPT_' /etc/security/policy.conf /dev/null 2>&1; grep -E '^[[:space:]]*password[[:space:]].*pam_unix' /etc/pam.d/system-auth /etc/pam.d/password-auth /etc/pam.d/common-password /dev/null 2>/dev/null | sed 's|^\\([^:]*\\):|[\\1] |'; awk -F: '{h=\$2; l=\"\"; if(h ~ /^!/){l=\"(잠김)\"; h=substr(h,2)}; if(h ~ /^\\\$/){i=index(substr(h,2),\"\\\$\"); a=substr(h,1,i+1)} else if(h==\"\"){a=\"(빈 값)\"} else if(h ~ /^[*]/ || h==\"x\"){a=\"(로그인불가/없음)\"} else {a=\"DES(13자)\"}; print \$1, a l}' /etc/shadow 2>&1"
    if [ ! -f /etc/shadow ]; then result "U-13|취약|/etc/shadow 미사용 (패스워드 암호화 불확실)"; return; fi
    if [ ! -r /etc/shadow ]; then result "U-13|점검불가|/etc/shadow 를 읽지 못함(root 필요, 실행 계정: ${_WHOAMI:-?})"; return; fi
    local weak="" algo="" user hash rest h
    algo=$(grep -E '^[[:space:]]*ENCRYPT_METHOD' /etc/login.defs 2>/dev/null | awk '{print $2}' | tail -1)
    local nreal=0
    while IFS=: read -r user hash rest; do
        h="${hash#!}"
        case "$h" in
            \$1\$*) weak="${weak} ${user}(MD5)"; nreal=$((nreal+1)) ;;
            \$md5*|\$sha1\$*) weak="${weak} ${user}(${h%%\$*}약한해시)"; nreal=$((nreal+1)) ;;
            \$2*|\$5\$*|\$6\$*|\$y\$*|\$gy\$*|\$7\$*) nreal=$((nreal+1)) ;;
            ''|'*'*|x|'!'*|NP|'*LK*') ;;
            *) echo "$h" | grep -qE '^[A-Za-z0-9./]{13}$' && { weak="${weak} ${user}(DES)"; nreal=$((nreal+1)); } ;;
        esac
    done < /etc/shadow
    if [ -n "$weak" ]; then result "U-13|취약|취약한 해시 알고리즘 사용: $(echo $weak | tr ' ' '\n' | _join)"
    elif [ $nreal -gt 0 ]; then result "U-13|양호|비밀번호 해시 ${nreal}개 모두 SHA-2 이상(또는 bcrypt/yescrypt), ENCRYPT_METHOD=${algo:-미설정}"
    else
        case "$(echo "$algo" | tr 'a-z' 'A-Z')" in
        SHA256|SHA512|YESCRYPT) result "U-13|양호|비밀번호 설정 계정 없음, ENCRYPT_METHOD=${algo}" ;;
        '') result "U-13|수동확인|비밀번호 설정 계정이 없고 ENCRYPT_METHOD 미지정 - PAM 설정(증적) 확인" ;;
        *) result "U-13|취약|비밀번호 설정 계정 없음, ENCRYPT_METHOD=${algo} (SHA256/SHA512/YESCRYPT 필요)" ;;
        esac
    fi
}

# 판정: PATH 문자열에서 . · 빈 요소 · 상대경로 검출 (결과: 위반 요소 설명)
_path_bad() {
    awk -v s="$1" 'BEGIN{n=split(s,a,":"); for(i=1;i<=n;i++){ e=a[i]
        if(e=="") { if(n>1 || i==1) r=r " 빈요소(" (i==1?"맨앞":(i==n?"맨뒤":"중간")) ")" }
        else if(e=="." || e=="./" || e==".." || e ~ /^\.\.?\//) r=r " ." (e=="."?"":"(" e ")")
        else if(e !~ /^(\/|\$|~|@)/) r=r " 상대경로(" e ")" }
        print r}'
}
check_U14() {
    local pf="" f
    for f in /root/.profile /root/.bash_profile /root/.bash_login /root/.bashrc /root/.kshrc /root/.cshrc /root/.login /etc/profile /etc/profile.d/*.sh /etc/bashrc /etc/bash.bashrc /etc/environment /etc/csh.cshrc /etc/csh.login /etc/default/login /etc/default/su; do [ -f "$f" ] && pf="${pf} $f"; done
    evd "U-14" "echo \"실행 프로세스 PATH=\$PATH\"; ls -ld /root 2>&1; grep -nE '(^|[[:space:];])(export[[:space:]]+)?(SU)?PATH=|setenv[[:space:]]+PATH|set[[:space:]]+path[[:space:]]*=' ${pf:-/etc/profile} /dev/null 2>&1"
    local vuln="" r e v
    r=$(_path_bad "$PATH"); [ -n "$r" ] && vuln="${vuln} [실행 프로세스 PATH:${r}]"
    for f in $pf; do
        while IFS= read -r e; do
            [ -n "$e" ] || continue
            v=$(echo "$e" | sed -E 's/^[[:space:]]*(export[[:space:]]+)?(SU)?PATH=//; s/^[[:space:]]*setenv[[:space:]]+PATH[[:space:]]+//' | sed "s/^[\"']//; s/[\"'][[:space:]]*;.*//; s/[\"']\$//; s/;.*//; s/[[:space:]].*//")
            v=$(echo "$v" | sed 's/\${\{0,1\}PATH}\{0,1\}/@/g')
            r=$(_path_bad "$v"); [ -n "$r" ] && vuln="${vuln} [${f}:${r}]"
        done < <(grep -vE '^[[:space:]]*#' "$f" 2>/dev/null | grep -E '(^|[[:space:]])(export[[:space:]]+)?(SU)?PATH=|setenv[[:space:]]+PATH')
    done
    if [ -n "$vuln" ]; then result "U-14|취약|PATH 에 '.'·빈 요소·상대경로 포함:${vuln}"
    elif [ "$_IS_ROOT" != 1 ] && ! [ -r /root/.profile -o -r /root/.bashrc -o -r /root/.bash_profile ]; then result "U-14|점검불가|일반 계정으로 실행되어 root 프로필(/root/*)을 읽지 못함 (프로세스 PATH 와 /etc 설정에서는 위반 없음)"
    else result "U-14|양호|root PATH('.'·빈 요소·상대경로 없음; 프로세스 PATH 와 프로필 ${pf:+$(echo $pf | wc -w | tr -d ' ')개} 확인)"; fi
}

check_U15() {
    local out="$_TMPD/u15.lst"
    _find_scan "$out" \( -nouser -o -nogroup \) ! -path "/proc/*" ! -path "/sys/*"
    evd "U-15" "df -lP 2>&1"
    evd_f "U-15" "find $(_local_mounts) -xdev \\( -nouser -o -nogroup \\) ! -path '/proc/*' ! -path '/sys/*' (마운트별 60초 제한)" "$out"
    local cnt; cnt=$(wc -l < "$out" | tr -d ' ')
    if [ "${cnt:-0}" -gt 0 ] 2>/dev/null; then result "U-15|취약|소유자/그룹 없는 파일 ${cnt}개: $(_join < "$out")$([ $_FIND_TO -eq 1 ] && echo ' (일부 탐색이 시간 초과로 중단됨)')"
    elif [ $_FIND_NA -eq 1 ]; then result "U-15|점검불가|${_FIND_NA_MSG}"
    elif [ $_FIND_TO -eq 1 ]; then result "U-15|점검불가|find 가 60초 제한으로 중단되어 전체 탐색을 완료하지 못함(발견 0건)"
    else result "U-15|양호|소유자/그룹 없는 파일 없음"; fi
}

check_U16() { _check_file_perm "U-16" "/etc/passwd" 644 "root" "/etc/passwd"; }

check_U17() {
    local lst="$_TMPD/u17.lst" g f dng=""
    : > "$lst"
    for g in /etc/rc.d/init.d/* /etc/init.d/* /etc/rc.d/rc*.d/* /etc/rc[0-6S].d/* /etc/rc.local /etc/rc.d/rc.local /sbin/init.d/* /sbin/rc*.d/* /etc/rc.config.d/* /etc/systemd/system/* /etc/systemd/system/*/* /usr/lib/systemd/system/* /lib/systemd/system/*; do
        [ -e "$g" ] || [ -L "$g" ] || continue
        [ -d "$g" ] && [ ! -L "$g" ] && continue
        [ -L "$g" ] && [ "$(readlink -f "$g" 2>/dev/null)" = "/dev/null" ] && continue   # 비활성(mask) 처리된 유닛
        [ -L "$g" ] && [ ! -e "$g" ] && { dng="${dng} ${g}"; continue; }   # 대상이 없는 깨진 링크는 실행되지 않으므로 소유자·권한 점검 제외(증적에 기록)
        echo "$g" >> "$lst"
    done
    sort -u "$lst" -o "$lst"
    evd "U-17" "ls -ld /etc/rc.d /etc/init.d /etc/rc.d/init.d /etc/rc.local /sbin/init.d /sbin/rc2.d /etc/rc.config.d /etc/systemd/system /usr/lib/systemd/system 2>&1; echo '# 대상 없는 깨진 심볼릭 링크(점검 제외):${dng:- 없음}'"
    evd_ls "U-17" "시작 스크립트 경로(/etc/rc*.d, /etc/init.d, /etc/systemd/system 등) 없음" "$lst"
    _fp_reset
    while IFS= read -r f; do
        [ -n "$f" ] || continue
        _fp_add "$f" 7755 "root|bin"
    done < "$lst"
    if [ "$_NCHK" -eq 0 ]; then result "U-17|양호|점검할 시스템 시작 스크립트 없음(/etc/rc*.d·init.d·systemd 미존재)"
    else _fp_verdict "U-17" "시스템 시작 스크립트 소유자 root, 일반 사용자 쓰기 권한 없음"; fi
}

check_U18() {
    case "$OS_FAMILY" in
    AIX) _check_file_perm "U-18" "/etc/security/passwd" 400 "root" "/etc/security/passwd" ;;
    *)   _check_file_perm "U-18" "/etc/shadow" 400 "root" "/etc/shadow" ;;
    esac
}

check_U19() { _check_file_perm "U-19" "/etc/hosts" 644 "root" "/etc/hosts"; }

check_U20() {
    local files="" f
    for f in /etc/inetd.conf /etc/xinetd.conf /etc/xinetd.d/* /etc/systemd/system.conf; do [ -f "$f" ] && files="${files} $f"; done
    if [ -z "$files" ]; then
        evd "U-20" "ls -ld /etc/inetd.conf /etc/xinetd.conf /etc/xinetd.d /etc/systemd/system.conf 2>&1"
        result "U-20|양호|inetd/xinetd 미사용 (/etc/inetd.conf·/etc/xinetd.conf·xinetd.d 없음 - 권한을 점검할 파일 없음)"
    else _check_file_perm "U-20" "${files# }" 600 "root" "inetd/xinetd 설정"; fi
}

check_U21() {
    local files="" f
    for f in /etc/syslog.conf /etc/rsyslog.conf; do [ -f "$f" ] && files="${files} $f"; done
    if [ -z "$files" ]; then
        evd "U-21" "ls -ld /etc/syslog.conf /etc/rsyslog.conf 2>&1; echo \"syslog 데몬 실행: \$(_ps_comm | grep -xE 'rsyslogd|syslogd|syslog-ng' | sort -u | tr '\\n' ' ')\""
        if _ps_has rsyslogd || _ps_has syslogd || _ps_has syslog-ng; then result "U-21|점검불가|syslog 데몬은 실행 중이나 /etc/syslog.conf·/etc/rsyslog.conf 를 찾지 못함"
        else result "U-21|양호|syslog.conf 없음 - 권한을 점검할 파일 없음 (로깅 정책은 U-66)"; fi
    else _check_file_perm "U-21" "${files# }" 640 "root|bin|sys" "(r)syslog.conf"; fi
}

check_U22() { _check_file_perm "U-22" "/etc/services" 644 "root|bin|sys" "/etc/services"; }

# 표준 SUID/SGID 파일 이름 (이 외의 파일은 수동 확인 대상)
_SUID_STD=" passwd chsh chfn chage gpasswd newgrp su sudo sudoedit mount umount fusermount fusermount3 ping ping6 traceroute traceroute6 pkexec polkit-agent-helper-1 crontab at atq atrm batch unix_chkpwd pam_timestamp_check userhelper usernetctl ssh-keysign dbus-daemon-launch-helper expiry wall write locate mlocate slocate ssh-agent staprun postdrop postqueue mount.nfs mount.cifs umount.nfs newuidmap newgidmap Xorg Xorg.wrap lockfile procmail utempter mail-lock mail-touchlock mail-unlock dotlockfile bsd-write chage ntfs-3g vmware-user-suid-wrapper snap-confine screen sendmail.sendmail unix2_chkpwd lppasswd mtr-packet bwrap abrt-action-install-debuginfo-to-abrt-cache cockpit-session mount.fuse sg vmmouse_detect lpr lprm lpq opiepasswd opieinfo ksu pt_chown rsh rcp rlogin login uuidd ctrlaltdel pppd cgexec "
_SUID_DANGER=" nmap perl python python2 python3 php ruby bash sh ksh csh zsh dash find wget curl nc ncat netcat awk gawk vim vi nano gdb strace ltrace tar cp mv dd env node lua tclsh expect less more man ed ex emacs "
check_U23() {
    local out="$_TMPD/u23.lst"
    _find_scan "$out" -type f \( -perm -4000 -o -perm -2000 \)
    evd "U-23" "df -lP 2>&1"
    evd_f "U-23" "find $(_local_mounts) -xdev -type f \\( -perm -4000 -o -perm -2000 \\) (마운트별 60초 제한)" "$out"
    local cnt; cnt=$(wc -l < "$out" | tr -d ' ')
    local danger="" nonstd="" f b
    while IFS= read -r f; do
        [ -n "$f" ] || continue
        b="${f##*/}"
        case "$_SUID_DANGER" in *" $b "*) danger="${danger} ${f}"; continue ;; esac
        case "$_SUID_STD" in *" $b "*) ;; *) nonstd="${nonstd} ${f}" ;; esac
    done < "$out"
    if [ -n "$danger" ]; then result "U-23|취약|위험 바이너리에 SUID/SGID 설정: $(echo $danger | tr ' ' '\n' | _join) (SUID/SGID 파일 전체 ${cnt}개, 증적 참조)"
    elif [ $_FIND_NA -eq 1 ]; then result "U-23|점검불가|${_FIND_NA_MSG}"
    elif [ $_FIND_TO -eq 1 ] && [ "${cnt:-0}" -eq 0 ]; then result "U-23|점검불가|find 가 60초 제한으로 중단되어 전체 탐색을 완료하지 못함"
    elif [ -n "$nonstd" ]; then result "U-23|수동확인|SUID/SGID 파일 ${cnt}개 중 표준 목록에 없는 파일 $(echo $nonstd | wc -w | tr -d ' ')개: $(echo $nonstd | tr ' ' '\n' | _join) - 불필요 여부 확인$([ $_FIND_TO -eq 1 ] && echo ' (일부 탐색 시간 초과)')"
    else result "U-23|양호|SUID/SGID 파일 ${cnt}개 모두 표준 시스템 바이너리, 위험 바이너리 설정 없음"; fi
}

check_U24() {
    local lst="$_TMPD/u24.lst" user home shell f n=0 unr=""
    : > "$lst"
    while IFS=: read -r user _ _ _ _ home shell; do
        case "$shell" in *nologin|*false) continue ;; esac
        [ -n "$home" ] && [ -d "$home" ] || continue
        n=$((n+1))
        [ -x "$home" ] || { unr="${unr} ${home}"; continue; }   # 비root: 타 계정 홈 접근 불가 → 점검불가(파일이 없는 것으로 보지 않음)
        for f in .profile .kshrc .cshrc .bashrc .bash_profile .bash_login .login .exrc .netrc; do
            [ -f "$home/$f" ] && [ ! -L "$home/$f" ] && echo "$user $home/$f" >> "$lst"
        done
    done < /etc/passwd
    awk '{print $2}' "$lst" > "$lst.f"
    evd "U-24" "awk -F: '\$7!~/(nologin|false)\$/ {n++; print \$1, \$6} END{print \"로그인 가능 계정 \"n+0\"개\"}' /etc/passwd 2>&1"
    evd_ls "U-24" "홈 디렉터리 환경변수 파일 없음(로그인 가능 계정 ${n}개 확인)" "$lst.f"
    _fp_reset
    while read -r user f; do
        [ -n "$f" ] || continue
        _fp_add "$f" 7775 "root|$user"
    done < "$lst"
    for f in $unr; do _NCHK=$((_NCHK+1)); _NUK=$((_NUK+1)); _UK="${_UK}${f} 홈 디렉터리 접근 권한 없음(실행 계정: ${_WHOAMI:-?}) - 환경파일 확인 불가 (root 로 재점검)
"; done
    _fp_verdict "U-24" "홈 디렉터리 환경변수 파일 소유자(root/해당 계정)·other 쓰기 권한 없음"
}

check_U25() {
    local out="$_TMPD/u25.lst"
    _find_scan "$out" -type f -perm -0002 ! -path "/proc/*" ! -path "/sys/*" ! -path "/dev/*" ! -path "/tmp/*" ! -path "/var/tmp/*"
    evd "U-25" "df -lP 2>&1"
    evd_f "U-25" "find $(_local_mounts) -xdev -type f -perm -0002 (/proc·/sys·/dev·/tmp·/var/tmp 제외, 마운트별 60초 제한)" "$out"
    local cnt; cnt=$(wc -l < "$out" | tr -d ' ')
    # 가이드: 존재 시 '설정 이유 인지' 여부로 판단 → 스크립트로 판단 불가, 목록 확인
    if [ "${cnt:-0}" -gt 0 ] 2>/dev/null; then result "U-25|수동확인|world writable 파일 ${cnt}개: $(_join < "$out") - 설정 이유 확인, 불필요 시 취약(o-w 제거)$([ $_FIND_TO -eq 1 ] && echo ' (일부 탐색 시간 초과)')"
    elif [ $_FIND_NA -eq 1 ]; then result "U-25|점검불가|${_FIND_NA_MSG}"
    elif [ $_FIND_TO -eq 1 ]; then result "U-25|점검불가|find 가 60초 제한으로 중단되어 전체 탐색을 완료하지 못함(발견 0건)"
    else result "U-25|양호|world writable 파일 없음"; fi
}

check_U26() {
    local out="$_TMPD/u26.lst"
    : > "$out"; _FIND_TO=0; _FIND_NA=0
    command -v find >/dev/null 2>&1 || _FIND_NA=1
    [ $_FIND_NA -eq 1 ] || _to 60 find /dev -type f ! -path "/dev/shm/*" ! -path "/dev/mqueue/*" ! -path "/dev/pts/*" ! -path "/dev/hugepages/*" ! -path "/dev/.udev/*" ! -path "/dev/.lxd-mounts/*" ! -name MAKEDEV >> "$out" 2>/dev/null
    [ $? -eq 124 ] && _FIND_TO=1
    evd "U-26" "ls -ld /dev 2>&1"
    evd_f "U-26" "find /dev -type f (/dev/shm·mqueue·pts·hugepages·.udev 제외, 60초 제한)" "$out"
    local cnt; cnt=$(wc -l < "$out" | tr -d ' ')
    if [ "${cnt:-0}" -gt 0 ] 2>/dev/null; then result "U-26|취약|/dev 에 device 가 아닌 일반 파일 ${cnt}개: $(_join < "$out")"
    elif [ $_FIND_NA -eq 1 ]; then result "U-26|점검불가|${_FIND_NA_MSG}"
    elif [ $_FIND_TO -eq 1 ]; then result "U-26|점검불가|find 가 60초 제한으로 중단됨"
    else result "U-26|양호|/dev 비정상 파일 없음"; fi
}

check_U27() {
    local vuln="" files="" user home f unk="" unh=""
    [ -f /etc/hosts.equiv ] && files="/etc/hosts.equiv:root"
    while IFS=: read -r user _ _ _ _ home _; do
        [ -n "$home" ] && [ -f "$home/.rhosts" ] && files="${files} ${home}/.rhosts:${user}"
        [ -n "$home" ] && [ -d "$home" ] && [ ! -x "$home" ] && unh="${unh} ${home}"
    done < /etc/passwd
    evd "U-27" "ls -l /etc/hosts.equiv 2>&1; for h in \$(awk -F: '{print \$6}' /etc/passwd | sort -u); do [ -f \$h/.rhosts ] && ls -l \$h/.rhosts; done; awk -F: 'END{print \"홈 디렉터리 점검 계정 \"NR\"개\"}' /etc/passwd"
    if [ -z "$files" ] && [ -n "$unh" ]; then result "U-27|점검불가|홈 디렉터리 접근 권한이 없어 .rhosts 존재 여부를 확인하지 못함:${unh} (실행 계정: ${_WHOAMI:-?}, root 로 재점검)"; return; fi
    if [ -z "$files" ]; then result "U-27|양호|/etc/hosts.equiv·\$HOME/.rhosts 파일 없음"; return; fi
    local e
    for e in $files; do
        f="${e%:*}"; user="${e##*:}"
        _fp_eval "$f" 600 "root|$user"; local rc=$?
        [ $rc -eq 1 ] && vuln="${vuln} ${_FP_MSG}"
        [ $rc -eq 2 ] && unk="${unk} ${_FP_MSG}"
        if [ -r "$f" ]; then
            grep -vE '^[[:space:]]*#' "$f" 2>/dev/null | grep -q '+' && vuln="${vuln} ${f}('+' 설정)"
        else unk="${unk} ${f} 읽기 실패"; fi
    done
    if [ -n "$vuln" ]; then result "U-27|취약|${vuln# }"
    elif [ -n "$unk" ]; then result "U-27|점검불가|${unk# }"
    elif [ -n "$unh" ]; then result "U-27|점검불가|확인된 파일은 기준 충족이나 홈 디렉터리 접근 권한이 없어 .rhosts 존재 여부를 확인하지 못함:${unh} (root 로 재점검)"
    else result "U-27|양호|hosts.equiv/.rhosts 소유자·권한(600 이하) 적절, '+' 설정 없음"; fi
}

check_U28() {
    local rules=0 detail="" unk="" n wa wd twr=0 fwtools=0 c
    for c in iptables nft firewall-cmd ufw ipfstat lsfilt; do command -v "$c" >/dev/null 2>&1 && fwtools=$((fwtools+1)); done
    evd "U-28" "for c in iptables nft firewall-cmd ufw ipfstat lsfilt; do command -v \$c >/dev/null 2>&1 && echo \"\$c: \$(command -v \$c)\" || echo \"\$c: 없음\"; done; echo \"클라우드: ${CLOUD_LINE}\""
    evd_cfg "U-28" /etc/hosts.allow /etc/hosts.deny
    wa=$(_nc /etc/hosts.allow | wc -l | tr -d ' '); wd=$(_nc /etc/hosts.deny | wc -l | tr -d ' ')
    if [ "${wa:-0}" -gt 0 ] || [ "${wd:-0}" -gt 0 ]; then twr=$((wa+wd)); rules=$((rules+wa+wd)); detail="${detail} TCP Wrapper(hosts.allow ${wa}줄/hosts.deny ${wd}줄);"; fi
    local denied='ermission denied|must be root|not permitted|are you root|Operation not|Unable to|cannot|can.t'
    if command -v iptables >/dev/null 2>&1; then
        evd "U-28" "iptables -S 2>&1"
        if grep -qiE "$denied" "$LAST"; then unk="${unk} iptables 조회 실패($(head -1 "$LAST"));"
        else
            n=$(grep -c '^-A INPUT' "$LAST"); local pol; pol=$(grep -E '^-P INPUT (DROP|REJECT)' "$LAST")
            if [ "${n:-0}" -gt 0 ] || [ -n "$pol" ]; then rules=$((rules+n+(${pol:+1}+0))); detail="${detail} iptables INPUT 규칙 ${n}건${pol:+, 기본정책 DROP};"; fi
        fi
    fi
    if command -v nft >/dev/null 2>&1; then
        evd "U-28" "nft list ruleset 2>&1"
        if grep -qiE "$denied" "$LAST"; then unk="${unk} nftables 조회 실패($(head -1 "$LAST"));"
        else n=$(grep -E '(accept|drop|reject)' "$LAST" | grep -vc 'policy'); [ "${n:-0}" -gt 0 ] && { rules=$((rules+n)); detail="${detail} nftables 규칙 ${n}건;"; }; fi
    fi
    if command -v firewall-cmd >/dev/null 2>&1; then
        evd "U-28" "firewall-cmd --state 2>&1; firewall-cmd --list-all 2>&1"
        if grep -qx running "$LAST"; then
            n=$(grep -E '^[[:space:]]*(services|ports|source-ports|sources|rich rules|protocols):' "$LAST" | sed 's/^[^:]*://' | wc -w | tr -d ' ')
            [ "${n:-0}" -gt 0 ] && { rules=$((rules+n)); detail="${detail} firewalld 실행 중(허용 항목 ${n}개);"; }
        elif grep -qiE "$denied" "$LAST"; then unk="${unk} firewalld 조회 실패;"; fi
    fi
    if command -v ufw >/dev/null 2>&1; then
        evd "U-28" "ufw status verbose 2>&1"
        if grep -qi 'Status: active' "$LAST"; then n=$(grep -cE 'ALLOW|DENY|REJECT|LIMIT' "$LAST"); rules=$((rules+n)); detail="${detail} ufw 활성(규칙 ${n}건);"
        elif grep -qiE "$denied" "$LAST"; then unk="${unk} ufw 조회 실패($(head -1 "$LAST"));"; fi
    fi
    if command -v ipfstat >/dev/null 2>&1; then
        evd "U-28" "ipfstat -io 2>&1"
        n=$(grep -cE '^(pass|block|log)' "$LAST"); [ "${n:-0}" -gt 0 ] && { rules=$((rules+n)); detail="${detail} IPFilter 규칙 ${n}건;"; }
    fi
    if command -v lsfilt >/dev/null 2>&1; then
        evd "U-28" "lsfilt -v 4 -O 2>&1"
        n=$(grep -ciE 'permit|deny' "$LAST"); [ "${n:-0}" -gt 0 ] && { rules=$((rules+n)); detail="${detail} AIX 필터 규칙 ${n}건;"; }
    fi
    local cloud=""
    case "$CLOUD_NAME" in
    AWS) cloud="클라우드 AWS 보안그룹 ID: ${CLOUD_SG:-미확인}" ;;
    Azure) cloud="클라우드 Azure NSG: 포털에서 확인" ;;
    GCP) cloud="클라우드 GCP 네트워크 태그: ${CLOUD_SG:-없음}(방화벽 규칙 콘솔 확인)" ;;
    esac
    if [ "$rules" -gt 0 ] && [ "$rules" -le "$twr" ] && { [ -n "$unk" ] || [ "$fwtools" -eq 0 ]; }; then
        # TCP Wrapper 규칙만 확인됨: 방화벽 조회가 실패했거나 조회 도구가 없으면 실제 접근통제 여부를 확정할 수 없음 (sshd 등은 libwrap 미지원일 수 있음)
        result "U-28|수동확인|TCP Wrapper 규칙만 확인됨(hosts.allow ${wa}줄/hosts.deny ${wd}줄) - $([ -n "$unk" ] && echo "방화벽 규칙 조회 실패:${unk}" || echo "방화벽 조회 도구(iptables·nft·firewall-cmd·ufw 등) 없음"), 방화벽 규칙(root 권한) 확인 필요"
    elif [ "$rules" -gt 0 ]; then
        result "U-28|양호|접속 IP/포트 제한 규칙 설정됨:${detail}${cloud:+ / ${cloud} 병행 확인}"
    elif [ -n "$cloud" ]; then
        result "U-28|수동확인|호스트 방화벽·TCP Wrapper 규칙 없음${unk:+ (${unk})} - ${cloud} 의 인바운드 규칙(허용 IP·포트)을 콘솔에서 확인"
    elif [ -n "$unk" ]; then
        result "U-28|점검불가|방화벽 규칙 조회 실패:${unk} (실행 계정: ${_WHOAMI:-?})"
    elif [ "$fwtools" -eq 0 ]; then
        result "U-28|수동확인|방화벽 조회 도구(iptables·nft·firewall-cmd·ufw·ipfstat·lsfilt)가 모두 없어 규칙을 확인하지 못함 - 호스트 방화벽 유무·상위 방화벽 수동 확인"
    else
        case "$CLOUD_LINE" in
        미확인*) result "U-28|수동확인|호스트 방화벽·TCP Wrapper 규칙 없음 - 클라우드 여부 미확인(${CLOUD_LINE}), 클라우드라면 보안그룹 확인" ;;
        *) result "U-28|취약|접속 IP/포트 제한 없음 (hosts.allow/deny·iptables·nftables·firewalld·ufw·IPFilter 에 활성 규칙 없음)" ;;
        esac
    fi
}

check_U29() {
    if [ -e /etc/hosts.lpd ] || [ -L /etc/hosts.lpd ]; then _check_file_perm "U-29" "/etc/hosts.lpd" 600 "root" "/etc/hosts.lpd"
    else evd "U-29" "ls -l /etc/hosts.lpd 2>&1"; result "U-29|양호|/etc/hosts.lpd 미존재"; fi
}

check_U30() {
    local files="" f v last="" lsrc="" vals="" fl
    for f in /etc/login.defs /etc/default/login /etc/default/security /etc/profile /etc/profile.d/*.sh /etc/bashrc /etc/bash.bashrc /etc/csh.cshrc /etc/csh.login /etc/pam.d/common-session /etc/pam.d/system-auth /etc/pam.d/login; do
        [ -f "$f" ] && files="${files} $f"
    done
    [ "$OS_FAMILY" = "AIX" ] && files="/etc/security/user ${files}"
    evd "U-30" "ls -l ${files:-/etc/profile} 2>&1; grep -inE '^[[:space:]]*umask|pam_umask' ${files:-/etc/profile} /dev/null 2>&1"
    for f in $files; do
        if [ "$f" = "/etc/security/user" ]; then v=$(_aix_default | sed -n 's/^[[:space:]]*[Uu][Mm][Aa][Ss][Kk][[:space:]]*=[[:space:]]*\([0-7][0-7][0-7][0-7]*\).*/\1/p' | tail -1)
        else
            v=$(grep -vE '^[[:space:]]*#' "$f" 2>/dev/null | sed -n 's/^[[:space:]]*[Uu][Mm][Aa][Ss][Kk][[:space:]=]*\([0-7][0-7][0-7][0-7]*\)\([^0-9].*\)\{0,1\}$/\1/p; s/.*pam_umask.*umask=\([0-7][0-7][0-7][0-7]*\).*/\1/p' | tail -1)
        fi
        [ -n "$v" ] && { vals="${vals} ${f}=${v}"; last="$v"; lsrc="$f"; }
    done
    if [ -z "$last" ]; then
        if [ -z "$files" ]; then result "U-30|점검불가|UMASK 설정 파일(/etc/profile·login.defs 등)을 찾지 못함"; else result "U-30|취약|UMASK 미설정 (확인한 파일: $(echo $files | wc -w | tr -d ' ')개)"; fi
    elif [ $(( 8#$last & 8#022 )) -eq $(( 8#022 )) ] 2>/dev/null; then result "U-30|양호|UMASK=${last} (${lsrc}; 그룹·기타 쓰기 제한) / 파일별:${vals}"
    else result "U-30|취약|UMASK=${last} (${lsrc}) - 022 이상(그룹·기타 쓰기 차단) 필요 / 파일별:${vals}"; fi
}

check_U31() {
    local lst="$_TMPD/u31.lst" user uid homedir
    : > "$lst"
    while IFS=: read -r user _ uid _ _ homedir _; do
        [ "${uid:-0}" -ge "$_UIDMIN" ] 2>/dev/null && [ "${uid:-0}" -lt 60000 ] 2>/dev/null || continue
        [ -z "$homedir" ] || [ "$homedir" = "/" ] && continue
        [ -d "$homedir" ] && echo "$user $homedir" >> "$lst"
    done < /etc/passwd
    awk '{print $2}' "$lst" > "$lst.f"
    evd "U-31" "awk -F: -v m=$_UIDMIN '\$3>=m && \$3<60000 {n++; print \$1,\$6} END{print \"UID \"m\" 이상 일반 계정 \"n+0\"개\"}' /etc/passwd 2>&1"
    evd_ls "U-31" "홈 디렉터리가 있는 일반 계정 없음" "$lst.f"
    _fp_reset
    while read -r user homedir; do [ -n "$homedir" ] && _fp_add "$homedir" 7775 "$user"; done < "$lst"
    _fp_verdict "U-31" "홈 디렉터리 소유자=해당 계정, 타 사용자 쓰기 권한 없음"
}

check_U32() {
    local lst="$_TMPD/u32.lst" vuln="" user uid homedir
    : > "$lst"
    while IFS=: read -r user _ uid _ _ homedir _; do
        [ "${uid:-0}" -ge "$_UIDMIN" ] 2>/dev/null && [ "${uid:-0}" -lt 60000 ] 2>/dev/null || continue
        if [ -z "$homedir" ]; then vuln="${vuln} ${user}(홈 미지정)"; continue; fi
        [ "$homedir" = "/" ] && continue
        echo "$homedir" >> "$lst"
        [ -d "$homedir" ] || vuln="${vuln} ${user}(${homedir})"
    done < /etc/passwd
    evd "U-32" "awk -F: -v m=$_UIDMIN '\$3>=m && \$3<60000 {n++; print \$1,\$6} END{print \"UID \"m\" 이상 일반 계정 \"n+0\"개\"}' /etc/passwd 2>&1"
    evd_ls "U-32" "홈 디렉터리를 가진 일반 계정 없음" "$lst"
    if [ -n "$vuln" ]; then result "U-32|취약|홈 디렉토리 미존재:${vuln}"; else result "U-32|양호|모든 일반 계정의 홈 디렉토리 존재"; fi
}

check_U33() {
    local out="$_TMPD/u33.lst" raw="$_TMPD/u33.raw"
    _find_scan "$raw" \( -type f -o -type d \) -name ".*" ! -name "." ! -path "/proc/*" ! -path "/sys/*" ! -path "/dev/*" ! -path "/run/*"
    grep -vE '/\.(bash|profile|cshrc|ssh|gnupg|cache|config|local|viminfo|lesshst|vim|zsh|git|npm|pki|mozilla|dbus|java|kshrc|login|exrc|forward|mysql_history|python_history|wget-hsts|sudo_as_admin_successful|hushlogin|netrc|mailcap|lesskey|inputrc|Xauthority|ICEauthority)' "$raw" > "$out" 2>/dev/null
    evd "U-33" "df -lP 2>&1"
    evd_f "U-33" "find $(_local_mounts) -xdev \\( -type f -o -type d \\) -name '.*' (/proc·/sys·/dev·/run 제외, 홈 디렉터리 표준 설정 파일 제외, 마운트별 60초 제한)" "$out"
    local cnt; cnt=$(wc -l < "$out" | tr -d ' ')
    [ $_FIND_NA -eq 1 ] && { result "U-33|점검불가|${_FIND_NA_MSG}"; return; }
    result "U-33|수동확인|숨겨진 파일/디렉토리 ${cnt}개 (증적 목록에서 의심 파일 확인)$([ $_FIND_TO -eq 1 ] && echo ' - 일부 탐색 시간 초과')"
}

_exist() { local f; for f in "$@"; do [ -f "$f" ] && printf '%s ' "$f"; done; echo; }   # 존재하는 파일만
_ftp_on() { local s o=""; for s in vsftpd proftpd pure-ftpd in.ftpd ftpd wu-ftpd; do is_running "$s" && o="${o} ${s}"; done; [ -n "$(_inet_on ftp)" ] && o="${o} $(_inet_on ftp)"; [ -n "$(_listen 21)" ] && o="${o} 21/tcp"; echo "${o# }"; }
_ftp_ev() { _svc_status 'vsftpd|proftpd|pure-ftpd|in.ftpd|ftpd|wu-ftpd' vsftpd proftpd pure-ftpd; _inet_ev ftp; _ports_ev; }

check_U34() {
    evd "U-34" "_svc_status 'in.fingerd|fingerd' fingerd in.fingerd finger.socket; _inet_ev finger; _ports_ev"
    local on; on=$(_inet_on finger)
    { is_running in.fingerd || is_running fingerd; } && on="${on} 프로세스"
    [ -n "$(_listen 79)" ] && on="${on} 79/tcp"
    if [ -n "$on" ]; then result "U-34|취약|finger 서비스 활성:${on}"; else result "U-34|양호|finger 서비스 비활성화"; fi
}

check_U35() {
    local vuln="" used="" f v vsf pro smb exp
    vsf=$(_exist /etc/vsftpd.conf /etc/vsftpd/vsftpd.conf); pro=$(_exist /etc/proftpd.conf /etc/proftpd/proftpd.conf); smb=$(_exist /etc/samba/smb.conf); exp=$(_exist /etc/exports /etc/dfs/dfstab)
    evd "U-35" "ls -ld ${vsf:-/etc/vsftpd.conf} ${pro:-/etc/proftpd.conf} ${smb:-/etc/samba/smb.conf} ${exp:-/etc/exports} 2>&1; grep -inE '^[[:space:]]*anonymous_enable' ${vsf:-/dev/null} /dev/null 2>&1; awk -F: '\$1==\"ftp\" || \$1==\"anonymous\" {print \"계정 \"\$1\": shell=\"\$7}' /etc/passwd 2>&1"
    [ -n "$pro" ] && evd "U-35" "awk '/<Anonymous/{a=1} a{print FILENAME\": \"\$0} /<\\/Anonymous>/{a=0}' $pro 2>&1"
    [ -n "$smb" ] && evd "U-35" "grep -inE '^[[:space:]]*(guest ok|public|guest only|map to guest)' $smb /dev/null 2>&1"
    [ -n "$exp" ] && evd "U-35" "grep -vE '^[[:space:]]*(#|\$)' $exp /dev/null 2>&1"
    for f in $vsf; do
        used="${used} vsFTP"
        v=$(_nc "$f" | awk -F= 'tolower($1) ~ /^[ \t]*anonymous_enable[ \t]*$/ {gsub(/[ \t]/,"",$2); x=toupper($2)} END{print x}')
        if [ -z "$v" ]; then vuln="${vuln} vsFTP anonymous_enable 미기재(기본값 YES)"; elif [ "$v" = "YES" ]; then vuln="${vuln} vsFTP anonymous_enable=YES"; fi
    done
    for f in $pro; do
        used="${used} ProFTP"
        awk '/<Anonymous/{a=1} /<\/Anonymous>/{a=0} a && /^[[:space:]]*(User|UserAlias)[[:space:]]/' "$f" 2>/dev/null | grep -q . && vuln="${vuln} ProFTP <Anonymous> 사용"
    done
    if is_running in.ftpd || [ -n "$(_inet_on ftp)" ]; then
        used="${used} 기본FTP"; grep -qE '^(ftp|anonymous):' /etc/passwd 2>/dev/null && vuln="${vuln} 기본FTP ftp/anonymous 계정 존재"
    fi
    for f in $smb; do
        used="${used} Samba"
        grep -vE '^[[:space:]]*[#;]' "$f" 2>/dev/null | grep -qiE '^[[:space:]]*(guest ok|public|guest only)[[:space:]]*=[[:space:]]*yes' && vuln="${vuln} Samba guest ok/public=yes"
    done
    for f in $exp; do
        used="${used} NFS"
        grep -vE '^[[:space:]]*#' "$f" 2>/dev/null | grep -qE 'anonuid=0([^0-9]|$)|anon=0([^0-9]|$)' && vuln="${vuln} NFS anonuid=0(익명 접근을 root 로 매핑)"
    done
    if [ -n "$vuln" ]; then result "U-35|취약|공유 서비스 익명 접근 허용:${vuln}"
    elif [ -n "$used" ]; then result "U-35|양호|공유 서비스(${used# }) 익명 접근 제한"
    else result "U-35|양호|익명 접근 가능한 공유 서비스(FTP·Samba·NFS) 미사용"; fi
}

check_U36() {
    evd "U-36" "_svc_status 'rshd|rlogind|rexecd|in.rshd|in.rlogind|in.rexecd|rsh-server' rsh.socket rlogin.socket rexec.socket; _inet_ev rsh shell rlogin login rexec exec; _ports_ev"
    local found="" svc o
    for svc in rshd rlogind rexecd in.rshd in.rlogind in.rexecd; do is_running "$svc" && found="${found} ${svc}"; done
    o=$(_inet_on rsh shell rlogin login rexec exec); [ -n "$o" ] && found="${found} ${o}"
    o=$(_listen 512 513 514); [ -n "$o" ] && found="${found} 리슨포트:${o}"
    if [ -n "$found" ]; then result "U-36|취약|r 서비스 실행:${found}"; else result "U-36|양호|r 서비스(rsh·rlogin·rexec) 비활성화"; fi
}

check_U37() {
    local cc ac lst="$_TMPD/u37.lst" lst2="$_TMPD/u37b.lst" f p o
    cc=$(command -v crontab 2>/dev/null); ac=$(command -v at 2>/dev/null)
    : > "$lst"; : > "$lst2"
    for f in $cc $ac; do echo "$f" >> "$lst"; done
    for f in /etc/crontab /etc/cron.allow /etc/cron.deny /etc/at.allow /etc/at.deny /etc/cron.d/* /var/adm/cron/cron.allow /var/adm/cron/cron.deny /var/adm/cron/at.allow /var/adm/cron/at.deny /var/spool/cron/* /var/spool/cron/crontabs/*; do
        [ -f "$f" ] && echo "$f" >> "$lst"
    done
    for f in /var/spool/at/* /var/spool/cron/atjobs/*; do [ -f "$f" ] && echo "$f" >> "$lst2"; done
    sort -u "$lst" -o "$lst"; cat "$lst" "$lst2" > "$lst.all"
    evd "U-37" "ls -l ${cc:-/usr/bin/crontab} ${ac:-/usr/bin/at} 2>&1"
    evd_ls "U-37" "cron·at 설정/스풀 파일 없음" "$lst.all"
    _fp_reset
    for f in $cc $ac; do _fp_add "$f" 4750 "root"; done
    while IFS= read -r f; do
        [ -n "$f" ] || continue
        case "$f" in
        /var/spool/*) _fp_add "$f" 640 "root|$(basename "$f")|daemon|bin|cron|crontab" ;;
        $cc|$ac) ;;
        *) _fp_add "$f" 640 "root" ;;
        esac
    done < "$lst"
    while IFS= read -r f; do [ -n "$f" ] && _fp_add "$f" 750 "root|daemon|bin"; done < "$lst2"   # at 작업 파일은 소유자 실행 비트(700) 정상
    if [ "$_NCHK" -eq 0 ]; then result "U-37|양호|crontab·at 명령어 및 관련 파일 없음(미설치)"
    else _fp_verdict "U-37" "crontab·at 명령어 750 이하, 관련 파일 640 이하(스풀 at 작업은 750 이하)"; fi
}

check_U38() {
    evd "U-38" "_inet_ev echo discard daytime chargen echo-dgram echo-stream discard-dgram discard-stream daytime-dgram daytime-stream chargen-dgram chargen-stream; _ports_ev"
    local found="" o n
    for n in echo discard daytime chargen echo-dgram echo-stream discard-dgram discard-stream daytime-dgram daytime-stream chargen-dgram chargen-stream; do
        o=$(_inet_on "$n"); [ -n "$o" ] && found="${found} ${o}"
    done
    o=$(_listen 7 9 13 19); [ -n "$o" ] && found="${found} 리슨포트:${o}"
    local ref="" p
    for p in 53:DNS 123:NTP 161:SNMP 25:SMTP; do [ -n "$(_listen "${p%%:*}")" ] && ref="${ref} ${p#*:}(${p%%:*})"; done
    local note=""; [ -n "$ref" ] && note=" / 참고: 가이드 예시 서비스 사용 중${ref} - 불필요 시 중지"
    if [ -n "$found" ]; then result "U-38|취약|DoS 취약 서비스(echo·discard·daytime·chargen) 활성:${found}${note}"
    else result "U-38|양호|echo·discard·daytime·chargen 비활성화${note}"; fi
}

check_U39() {
    evd "U-39" "_svc_status 'nfsd|rpc.nfsd|mountd|rpc.mountd|nfsd4|lockd' nfs-server nfs-kernel-server nfs nfsd; rpcinfo -p 2>&1; _ports_ev"
    local on=""
    for s in nfsd rpc.nfsd nfs-server nfs-kernel-server mountd rpc.mountd; do is_running "$s" && on="${on} ${s}"; done
    [ -n "$(_listen 2049)" ] && on="${on} 2049"
    if [ -n "$on" ]; then result "U-39|수동확인|NFS 실행 중:${on} (업무상 필요 여부 확인)"; else result "U-39|양호|NFS 미실행"; fi
}

_nfs_open_lines() {   # 접근 호스트를 제한하지 않은 공유 설정 줄
    awk -v os="$OS_FAMILY" '
    /^[ \t]*(#|$)/ {next}
    os=="SOLARIS" { if ($1!="share") next; o=""; for(i=1;i<=NF;i++) if($i=="-o") o=$(i+1)
        if (o !~ /(rw|ro|access)=[^,]+/ || o ~ /(rw|ro|access)=\*/) print FILENAME ": 전체/미지정 " $0; next }
    os=="AIX" || os=="HPUX" { if (NF==1) { print FILENAME ": 호스트 미지정 " $0; next }
        ho=0; for(i=2;i<=NF;i++){ if ($i ~ /(rw|ro|access|root)=[^,]+/) ho=1; if ($i ~ /(rw|ro|access)=\*/) ho=2 }
        if (ho!=1) print FILENAME ": 전체/미지정 " $0; next }
    { if (NF==1) { print FILENAME ": 호스트 미지정 " $0; next }
      for(i=2;i<=NF;i++){ h=$i; sub(/\(.*/,"",h); if (h=="" || h=="*" || h=="0.0.0.0/0") { print FILENAME ": 전체 호스트 " $0; break } } }' "$@" 2>/dev/null
}
check_U40() {
    local f=/etc/exports; [ "$OS_FAMILY" = "SOLARIS" ] && f=/etc/dfs/dfstab
    local fl="$f"; [ "$OS_FAMILY" = "LINUX" ] && fl="$f $(ls /etc/exports.d/*.exports 2>/dev/null | tr '\n' ' ')"
    evd "U-40" "ls -l $fl 2>&1; grep -vE '^[[:space:]]*(#|\$)' $fl /dev/null 2>&1; exportfs -v 2>&1"
    local running=0; { is_running nfsd || is_running nfs-server || is_running nfs-kernel-server || is_running mountd; } && running=1
    local nact=0; [ -f "$f" ] && nact=$(_nc $fl | wc -l | tr -d ' ')
    if [ $running -eq 0 ] && [ "${nact:-0}" -eq 0 ]; then
        result "U-40|양호|NFS 서비스 미사용·공유 설정 없음 (가이드 조치 방법: 미사용 시 서비스 중지·비활성화 → 조치 상태)"; return
    fi
    if [ ! -f "$f" ]; then result "U-40|수동확인|NFS 실행 중이나 ${f} 없음 - 공유 설정 확인 필요(증적 exportfs -v)"; return; fi
    _fp_eval "$f" 644 root; local rc=$?
    if [ $rc -eq 2 ]; then result "U-40|점검불가|${_FP_MSG}"; return; fi
    local vuln=""; [ $rc -eq 1 ] && vuln="${vuln} ${_FP_MSG}"
    local op; op=$(_nfs_open_lines $fl | _join)
    [ -n "$op" ] && vuln="${vuln} 접근 통제 미흡 공유: ${op}"
    if [ -n "$vuln" ]; then result "U-40|취약|NFS 접근 통제 미흡:${vuln}"; else result "U-40|양호|NFS 공유 접근 대상 지정, ${f} 소유자 ${_FP_O}·권한 ${_FP_P}(644 이하)"; fi
}

check_U41() {
    evd "U-41" "_svc_status 'automount|automountd|autofs' autofs automountd system/filesystem/autofs"
    local on=""; for s in autofs automountd automount; do is_running "$s" && on="${on} ${s}"; done
    if [ -n "$on" ]; then result "U-41|취약|automountd 실행 중:${on}"; else result "U-41|양호|automountd 미실행"; fi
}

check_U42() {
    evd "U-42" "rpcinfo -p 2>&1; _inet_ev rpc; _ps_comm | grep -xE 'rpc.cmsd|rpc.ttdbserverd|ttdbserverd|sadmind|rusersd|rpc.rusersd|walld|rpc.rwalld|sprayd|rpc.sprayd|rstatd|rpc.rstatd|rpc.nisd|rexd|rpc.rexd|rpc.pcnfsd|rpc.statd|rpc.ypupdated|rpc.rquotad|rquotad|kcms_server|cachefsd'; echo \"(위 프로세스 목록이 비어 있으면 가이드 대상 RPC 데몬 없음)\""
    local found="" svc
    for svc in rpc.cmsd rpc.ttdbserverd ttdbserverd sadmind rusersd rpc.rusersd walld rpc.rwalld sprayd rpc.sprayd rstatd rpc.rstatd rpc.nisd rexd rpc.rexd rpc.pcnfsd rpc.statd rpc.ypupdated rpc.rquotad rquotad kcms_server cachefsd; do
        _ps_has "$svc" && found="${found} ${svc}"
    done
    local rp; rp=$(rpcinfo -p 2>/dev/null | awk 'NR>1{print $5}' | grep -xE 'rusersd|walld|sprayd|rstatd|rquotad|status|ypupdated|cmsd|ttdbserver|sadmind|rexd|pcnfsd' | sort -u | tr '\n' ' ')
    [ -n "$rp" ] && found="${found} [rpcinfo: ${rp% }]"
    grep -vE '^[[:space:]]*#' /etc/inetd.conf 2>/dev/null | grep -qE 'rpc\.(cmsd|ttdbserverd|rusersd|rwalld|sprayd|rstatd|rexd|pcnfsd)' && found="${found} [inetd]"
    if [ -n "$found" ]; then result "U-42|취약|불필요 RPC 서비스 활성:${found}"; else result "U-42|양호|가이드 대상 불필요 RPC 서비스 미사용"; fi
}

check_U43() {
    evd "U-43" "_svc_status 'ypserv|ypbind|yppasswdd|rpc.yppasswdd|rpc.nisd|ypxfrd' ypserv ypbind yppasswdd rpc.yppasswdd ypxfrd"
    local found="" svc
    for svc in ypserv ypbind yppasswdd rpc.yppasswdd rpc.nisd ypxfrd; do is_running "$svc" && found="${found} ${svc}"; done
    if [ -n "$found" ]; then result "U-43|취약|NIS 서비스:${found}"; else result "U-43|양호|NIS 미실행"; fi
}

check_U44() {
    evd "U-44" "_svc_status 'tftpd|in.tftpd|talkd|in.talkd|ntalkd|talk' tftp.socket tftpd talk ntalk; _inet_ev tftp talk ntalk; _ports_ev"
    local found="" svc o
    for svc in tftpd in.tftpd talkd in.talkd ntalkd; do is_running "$svc" && found="${found} ${svc}"; done
    o=$(_inet_on tftp talk ntalk); [ -n "$o" ] && found="${found} ${o}"
    o=$(_listen 69 517 518); [ -n "$o" ] && found="${found} 리슨포트:${o}"
    if [ -n "$found" ]; then result "U-44|취약|불필요 서비스:${found}"; else result "U-44|양호|tftp/talk 비활성화"; fi
}

# ── 메일 서비스 ──
_mta_running() {
    local o=""
    is_running sendmail && o="${o} sendmail"
    { is_running postfix || { _ps_has master && command -v postconf >/dev/null 2>&1; }; } && o="${o} postfix"
    { is_running exim || is_running exim4; } && o="${o} exim"
    echo "${o# }"
}
_mta_ev() { echo "실행 중 MTA: $(_mta_running)"; _svc_status 'sendmail|master|exim|exim4' sendmail postfix exim4 exim; _ports_ev; }
_sm_cf() { local f; for f in /etc/mail/sendmail.cf /etc/sendmail.cf /usr/lib/sendmail.cf /usr/local/etc/mail/sendmail.cf; do [ -f "$f" ] && { echo "$f"; return; }; done; }
_pf_get() {   # postfix 설정값 (postconf 우선, 없으면 main.cf 파싱)
    local k="$1" f
    if command -v postconf >/dev/null 2>&1; then postconf -h "$k" 2>/dev/null; return 0; fi
    for f in /etc/postfix/main.cf /usr/local/etc/postfix/main.cf; do
        [ -f "$f" ] && { awk -v key="$k" '/^[ \t]*#/ {next} /^[ \t]+[^ \t]/ { if (cur!="") val[cur]=val[cur] " " $0; next } /^[A-Za-z_0-9]+[ \t]*=/ { kk=$0; sub(/[ \t]*=.*/,"",kk); cur=kk; v=$0; sub(/^[^=]*=[ \t]*/,"",v); val[kk]=v; next } { cur="" } END{print val[key]}' "$f"; return 0; }
    done
    return 1
}

check_U45() {
    evd "U-45" "_mta_ev; sendmail -d0.1 -bt < /dev/null 2>&1; postconf mail_version 2>&1; exim -bV 2>&1"
    local ver="" mta; mta=$(_mta_running)
    case " $mta " in
    *" sendmail "*) ver="Sendmail $(sendmail -d0.1 -bt < /dev/null 2>/dev/null | grep -oE 'Version [0-9][^ ]*' | head -1 | cut -d' ' -f2)" ;;
    *" postfix "*) ver="Postfix $(postconf -h mail_version 2>/dev/null)" ;;
    *" exim "*) ver="$(exim -bV 2>/dev/null | grep -oE 'Exim version [0-9.]+' | head -1)" ;;
    *) result "U-45|양호|메일 서비스(Sendmail·Postfix·Exim) 미사용 (가이드 조치 방법: 미사용 시 서비스 중지·비활성화 → 조치 상태)"; return ;;
    esac
    result "U-45|수동확인|${ver:-버전 미확인} - 제조사 최신 버전·보안 패치 적용 여부 확인"
}

check_U46() {
    local cf sm; cf=$(_sm_cf)
    sm=$(ls /usr/sbin/sendmail /usr/lib/sendmail 2>/dev/null | tr '\n' ' ')
    evd "U-46" "echo \"실행 중 MTA: \$(_mta_running)\"; ls -l ${sm:-/usr/sbin/sendmail} 2>&1; grep -inE 'PrivacyOptions' ${cf:-/etc/mail/sendmail.cf} /dev/null 2>&1"
    if ! is_running sendmail; then
        result "U-46|양호|Sendmail 미실행(일반 사용자 Sendmail 실행 대상 서비스 없음)"; return
    fi
    if [ -z "$cf" ]; then result "U-46|점검불가|Sendmail 실행 중이나 sendmail.cf 를 찾지 못함"; return; fi
    if [ ! -r "$cf" ]; then result "U-46|점검불가|${cf} 를 읽지 못함(권한 부족)"; return; fi
    local priv; priv=$(grep -vE '^[[:space:]]*#' "$cf" 2>/dev/null | grep -E '^O[[:space:]]*PrivacyOptions' | tail -1)
    if echo "$priv" | grep -qiE 'restrictqrun|goaway'; then result "U-46|양호|${cf} ${priv}"
    else result "U-46|취약|일반 사용자 Sendmail 실행 방지(restrictqrun) 미설정: ${priv:-PrivacyOptions 미설정} (${cf})"; fi
}

_B=""; _G=""; _M=""; _K=""
_u47_postfix() {
    local inet rr rc mn tok toks loop=1 prot=0 pos
    if ! command -v postconf >/dev/null 2>&1 && ! [ -f /etc/postfix/main.cf ] && ! [ -f /usr/local/etc/postfix/main.cf ]; then _K="${_K} postfix 설정(postconf/main.cf)을 찾지 못함;"; return; fi
    inet=$(_pf_get inet_interfaces); rr=$(_pf_get smtpd_relay_restrictions); rc=$(_pf_get smtpd_recipient_restrictions); mn=$(_pf_get mynetworks)
    inet="${inet:-all}"
    for tok in $(echo "$inet" | tr ',' ' '); do case "$tok" in loopback-only|localhost|127.0.0.1|::1|'[::1]') ;; *) loop=0 ;; esac; done
    if [ $loop -eq 1 ]; then _G="${_G} postfix inet_interfaces=${inet}(루프백 전용: 외부 릴레이 불가);"; return; fi
    if echo "$mn" | grep -qE '(^|[ ,])(0\.0\.0\.0/0|::/0)'; then _B="${_B} postfix mynetworks=${mn} (전체 허용);"; return; fi
    local p
    for p in "$rr" "$rc"; do
        toks=$(echo "$p" | tr ',' ' ')
        pos=0; local seen_permit=0 t
        for t in $toks; do
            case "$t" in
            permit) seen_permit=1 ;;
            reject_unauth_destination|defer_unauth_destination) [ $seen_permit -eq 0 ] && prot=1; pos=1; break ;;
            esac
        done
        [ $pos -eq 1 ] && [ $seen_permit -eq 1 ] && { _B="${_B} postfix 제한 목록에서 permit 이 reject_unauth_destination 보다 앞섬;"; return; }
    done
    if [ $prot -eq 1 ] || { [ -z "$rr" ] && [ -z "$rc" ]; }; then _G="${_G} postfix inet_interfaces=${inet}, relay/recipient_restrictions 에 reject/defer_unauth_destination 적용${rr:+ (relay=${rr})};"
    else _B="${_B} postfix smtpd_relay_restrictions/smtpd_recipient_restrictions 에 reject_unauth_destination·defer_unauth_destination 없음 (relay=${rr:-없음}, recipient=${rc:-없음});"; fi
}
_u47_sendmail() {
    local cf mc dpo
    cf=$(_sm_cf); mc=$(_exist /etc/mail/sendmail.mc /etc/sendmail.mc)
    [ -z "$cf" ] && { _K="${_K} sendmail.cf 를 찾지 못함;"; return; }
    [ -r "$cf" ] || { _K="${_K} ${cf} 읽기 실패;"; return; }
    if [ -n "$mc" ] && grep -vE '^[[:space:]]*dnl' $mc 2>/dev/null | grep -q 'promiscuous_relay'; then _B="${_B} sendmail promiscuous_relay 설정(${mc});"; return; fi
    dpo=$(grep -vE '^[[:space:]]*#' "$cf" 2>/dev/null | grep -E '^O[[:space:]]*DaemonPortOptions')
    if [ -n "$dpo" ] && ! echo "$dpo" | grep -qvE 'Addr=(127\.|::1)'; then _G="${_G} sendmail DaemonPortOptions 루프백 전용;"; return; fi
    if grep -vE '^[[:space:]]*#' "$cf" 2>/dev/null | grep -qiE 'Relaying (denied|not allowed)'; then _G="${_G} sendmail.cf 에 Relaying denied 규칙 존재$([ -f /etc/mail/access ] && echo ", access RELAY 항목 $(_nc /etc/mail/access | grep -c RELAY)건");"
    else _M="${_M} sendmail.cf(${cf})에서 릴레이 차단 규칙(Relaying denied)을 확인하지 못함 - 증적 확인;"; fi
}
_u47_exim() {
    local f cf="" li rf
    for f in /etc/exim/exim.conf /etc/exim4/exim4.conf /etc/exim4/exim4.conf.template /var/lib/exim4/config.autogenerated /usr/local/etc/exim/configure /etc/exim/exim4.conf /etc/exim.conf /etc/exim4/update-exim4.conf.conf; do [ -f "$f" ] && cf="${cf} $f"; done
    [ -z "$cf" ] && { _K="${_K} exim 설정 파일을 찾지 못함;"; return; }
    li=$(_nc $cf | grep -E '^[[:space:]]*(local_interfaces|dc_local_interfaces)' | tail -1 | sed "s/.*=[[:space:]]*//; s/'//g")
    rf=$(_nc $cf | grep -iE 'relay_from_hosts|dc_relay_nets|MAIN_RELAY_NETS' | grep -E "(^|[=[:space:]:'\"])(\*|0\.0\.0\.0/0)([[:space:]:'\";]|$)" | head -1)
    if [ -n "$rf" ]; then _B="${_B} exim 릴레이 허용 호스트에 전체(*) 포함: ${rf};"; return; fi
    if [ -n "$li" ] && ! echo "$li" | tr ';:,' '   ' | tr ' ' '\n' | grep -v '^$' | grep -qvE '^(127\.0\.0\.1|::1)$'; then _G="${_G} exim 루프백 전용(${li});"; return; fi
    if _nc $cf | grep -qi 'relay not permitted'; then _G="${_G} exim ACL 에 relay not permitted 적용;"
    else _M="${_M} exim 릴레이 ACL 을 설정 파일에서 확인하지 못함 - 증적 확인;"; fi
}
check_U47() {
    local mta lp cf mc; mta=$(_mta_running); lp=$(_listen 25 587)
    evd "U-47" "_mta_ev"
    if [ -z "$mta" ]; then
        if [ -n "$lp" ]; then result "U-47|수동확인|MTA 프로세스는 식별되지 않았으나 SMTP 포트(${lp}) 리슨 중 - 릴레이 설정 수동 확인(증적 리슨 포트)"
        else result "U-47|양호|SMTP 미실행"; fi
        return
    fi
    _B=""; _G=""; _M=""; _K=""
    case " $mta " in *" postfix "*)
        evd "U-47" "postconf -n 2>&1; postconf -h inet_interfaces mynetworks smtpd_relay_restrictions smtpd_recipient_restrictions 2>&1; grep -nE '^[[:space:]]*(inet_interfaces|mynetworks|smtpd_relay_restrictions|smtpd_recipient_restrictions)' /etc/postfix/main.cf /dev/null 2>&1"
        _u47_postfix ;; esac
    case " $mta " in *" sendmail "*)
        cf=$(_sm_cf); mc=$(_exist /etc/mail/sendmail.mc /etc/sendmail.mc)
        evd "U-47" "ls -l ${cf:-/etc/mail/sendmail.cf} ${mc} 2>&1; grep -nE 'Relaying|DaemonPortOptions|PrivacyOptions' ${cf:-/etc/mail/sendmail.cf} /dev/null 2>&1; grep -nE 'promiscuous_relay|relay' ${mc:-/dev/null} /dev/null 2>&1; grep -vE '^[[:space:]]*(#|\$)' /etc/mail/access /dev/null 2>&1"
        _u47_sendmail ;; esac
    case " $mta " in *" exim "*)
        evd "U-47" "grep -nE 'relay_from_hosts|dc_relay_nets|MAIN_RELAY_NETS|dc_relay_domains|local_interfaces|dc_local_interfaces|relay not permitted' /etc/exim/exim.conf /etc/exim4/exim4.conf /etc/exim4/exim4.conf.template /var/lib/exim4/config.autogenerated /etc/exim4/update-exim4.conf.conf /usr/local/etc/exim/configure /dev/null 2>&1; exim -bP relay_from_hosts local_interfaces 2>&1"
        _u47_exim ;; esac
    if [ -n "$_B" ]; then result "U-47|취약|스팸 메일 릴레이 제한 미흡:${_B}${_G:+ / 양호: ${_G}}"
    elif [ -n "$_M" ]; then result "U-47|수동확인|릴레이 제한을 자동 판정하지 못함:${_M}${_G:+ / 양호: ${_G}} (원자료는 증적 참조)"
    elif [ -n "$_K" ]; then result "U-47|점검불가|${_K}${_G:+ / 확인된 항목: ${_G}}"
    else result "U-47|양호|릴레이 제한 확인:${_G}"; fi
}

check_U48() {
    local mta cf; mta=$(_mta_running); cf=$(_sm_cf)
    evd "U-48" "_mta_ev; grep -inE 'PrivacyOptions' ${cf:-/etc/mail/sendmail.cf} /dev/null 2>&1; postconf -h disable_vrfy_command 2>&1; grep -nE 'acl_smtp_(vrfy|expn)|smtp_vrfy' /etc/exim/exim.conf /etc/exim4/exim4.conf /etc/exim4/exim4.conf.template /var/lib/exim4/config.autogenerated /dev/null 2>&1"
    if [ -z "$mta" ]; then result "U-48|양호|SMTP 미실행"; return; fi
    local bad="" good="" man="" unk=""
    case " $mta " in *" sendmail "*)
        if [ -z "$cf" ]; then unk="${unk} sendmail.cf 를 찾지 못함;"
        elif [ ! -r "$cf" ]; then unk="${unk} ${cf} 읽기 실패;"
        else
            local priv; priv=$(grep -vE '^[[:space:]]*#' "$cf" 2>/dev/null | grep -E '^O[[:space:]]*PrivacyOptions' | tail -1)
            if echo "$priv" | grep -qi 'goaway' || { echo "$priv" | grep -qi 'noexpn' && echo "$priv" | grep -qi 'novrfy'; }; then good="${good} sendmail expn/vrfy 제한(${priv});"
            else bad="${bad} sendmail expn/vrfy 미제한(${priv:-PrivacyOptions 미설정});"; fi
        fi ;; esac
    case " $mta " in *" postfix "*)
        local v; v=$(_pf_get disable_vrfy_command | tr -d ' ')
        if ! command -v postconf >/dev/null 2>&1 && [ ! -f /etc/postfix/main.cf ]; then unk="${unk} postfix 설정을 찾지 못함;"
        elif [ "$v" = "yes" ]; then good="${good} postfix vrfy 제한;"; else bad="${bad} postfix vrfy 미제한(disable_vrfy_command=${v:-미설정});"; fi ;; esac
    case " $mta " in *" exim "*)
        local ec; ec=$(_exist /etc/exim/exim.conf /etc/exim4/exim4.conf /etc/exim4/exim4.conf.template /var/lib/exim4/config.autogenerated /usr/local/etc/exim/configure)
        if [ -z "$ec" ]; then unk="${unk} exim 설정을 찾지 못함;"
        elif _nc $ec | grep -qE '^[[:space:]]*acl_smtp_(vrfy|expn)'; then man="${man} exim acl_smtp_vrfy/expn 정의됨 - ACL 내용 확인;"
        else good="${good} exim VRFY/EXPN ACL 미정의(기본 거부);"; fi ;; esac
    if [ -n "$bad" ]; then result "U-48|취약|expn/vrfy 제한 미흡:${bad}${good:+ / 양호: ${good}}"
    elif [ -n "$man" ]; then result "U-48|수동확인|${man}${good:+ / 양호: ${good}}"
    elif [ -n "$unk" ]; then result "U-48|점검불가|${unk}${good:+ / 확인된 항목: ${good}}"
    else result "U-48|양호|expn/vrfy 제한:${good}"; fi
}

check_U49() {
    evd "U-49" "_svc_status 'named' named bind9 named-chroot; named -v 2>&1; rpm -q bind 2>&1; dpkg -l bind9 2>&1"
    is_running named || is_running bind9 || { result "U-49|양호|DNS 미실행"; return; }
    local ver; ver=$(named -v 2>/dev/null | grep -oE 'BIND [0-9][^ ]*' | head -1)
    if [ -z "$ver" ] && ! command -v named >/dev/null 2>&1; then result "U-49|수동확인|DNS 실행 중이나 named 명령을 찾지 못해 버전 미확인 - 패키지·버전 수동 확인"; return; fi
    result "U-49|수동확인|DNS ${ver:-버전 미확인} - 최신 패치 확인"
}

# ── named.conf 파서 (주석 제거 + allow-transfer/allow-update/zone 추출) ──
_strip_c() {   # C/C++/shell 주석 제거
    awk '{ s=$0; r=""
        while (s != "") {
            if (inb) { i=index(s,"*/"); if (!i) { s=""; break } s=substr(s,i+2); inb=0; continue }
            a=index(s,"/*"); b=index(s,"//"); c=index(s,"#"); m=0; t=""
            if (a) { m=a; t="b" }
            if (b && (!m || b<m)) { m=b; t="l" }
            if (c && (!m || c<m)) { m=c; t="l" }
            if (!m) { r=r s; s=""; break }
            r=r substr(s,1,m-1)
            if (t=="l") { s=""; break }
            s=substr(s,m+2); inb=1
        }
        if (r ~ /[^ \t]/) print r }' "$1" 2>/dev/null
}
_named_files() {
    local f g out="" inc d pass
    for f in /etc/named.conf /etc/bind/named.conf /etc/named/named.conf /var/named/chroot/etc/named.conf /usr/local/etc/namedb/named.conf /var/named/etc/named.conf /etc/namedb/named.conf; do [ -f "$f" ] && out="${out} $f"; done
    for pass in 1 2; do
        for f in $out; do
            d=$(dirname "$f")
            for inc in $(_strip_c "$f" | grep -oE 'include[[:space:]]+"[^"]+"' | sed 's/.*"\(.*\)"/\1/'); do
                case "$inc" in /*) g="$inc" ;; *) g="$d/$inc" ;; esac
                [ -f "$g" ] && out="${out} $g"
            done
        done
    done
    echo $out | tr ' ' '\n' | awk 'NF && !x[$0]++' | tr '\n' ' '
}
_named_ev() { local f; for f in $(_named_files); do echo "== $f (주석 제거 후)"; _strip_c "$f"; done; }
_named_stmts() {
    local f; for f in $(_named_files); do _strip_c "$f"; done | awk '
    function trim(x){ gsub(/^[ \t\n]+/,"",x); gsub(/[ \t\n]+$/,"",x); return x }
    { buf = buf $0 "\n" }
    END { n=length(buf); d=0; stmt=""
        for (i=1;i<=n;i++) { c=substr(buf,i,1)
            if (c=="{") { d++; nm[d]=trim(stmt); body[d]=""; stmt="" }
            else if (c=="}") {
                content=body[d] trim(stmt) ";"; parent=(d>1?nm[d-1]:"global")
                if (nm[d] ~ /^allow-transfer/) print "AT|" parent "|" content
                else if (nm[d] ~ /^allow-update/) print "AU|" parent "|" content
                else if (nm[d] ~ /^update-policy/) print "UP|" parent "|" content
                else if (nm[d] ~ /^zone[ \t]/) { t=""; if (match(body[d] content, /type[ \t]+[a-z]+/)) { t=substr(body[d] content,RSTART,RLENGTH); sub(/type[ \t]+/,"",t) } print "Z|" nm[d] "|" t }
                d--; stmt=""
            }
            else if (c==";") { if (d>0) body[d]=body[d] trim(stmt) ";"; stmt="" }
            else stmt=stmt c } }'
}
_named_conf_ok() {   # named 설정 파일 확인: 반환 0 정상 / 1 없음 / 2 읽기 실패
    local f fl; fl=$(_named_files); [ -z "$fl" ] && return 1
    for f in $fl; do [ -r "$f" ] || return 2; done
    return 0
}

check_U50() {
    evd "U-50" "_svc_status 'named' named bind9 named-chroot; ls -l \$(_named_files) 2>&1; _named_ev"
    is_running named || is_running bind9 || { result "U-50|양호|DNS 미실행"; return; }
    _named_conf_ok; local rc=$?
    [ $rc -eq 1 ] && { result "U-50|점검불가|DNS 실행 중이나 named.conf 를 찾지 못함"; return; }
    [ $rc -eq 2 ] && { result "U-50|점검불가|named.conf 를 읽지 못함(권한 부족)"; return; }
    local st; st=$(_named_stmts)
    local anyl glob zones z missing=""
    anyl=$(echo "$st" | awk -F'|' '$1=="AT" && $3 ~ /(^|[^a-zA-Z-])any([^a-zA-Z-]|$)/ {print $2}' | tr '\n' ' ')
    glob=$(echo "$st" | awk -F'|' '$1=="AT" && ($2=="options" || $2 ~ /^view/) {print $3}' | head -1)
    zones=$(echo "$st" | awk -F'|' '$1=="Z" && $3 ~ /^(master|primary|slave|secondary)$/ && $2 !~ /^zone[ \t]+"(\.|localhost|localhost\.localdomain|127\.in-addr\.arpa|0\.in-addr\.arpa|255\.in-addr\.arpa)"/ {print $2}')
    while IFS= read -r z; do
        [ -n "$z" ] || continue
        echo "$st" | awk -F'|' -v z="$z" '$1=="AT" && $2==z {f=1} END{exit !f}' || missing="${missing} ${z#zone }"
    done <<EOF2
$zones
EOF2
    if [ -n "$anyl" ]; then result "U-50|취약|allow-transfer 에 any 허용 (범위: ${anyl% })"
    elif [ -n "$glob" ] || [ -z "$missing" ]; then
        if [ -z "$glob" ] && [ -z "$zones" ]; then result "U-50|양호|전송 대상 zone 없음(allow-transfer 전역 설정 없음)"
        else result "U-50|양호|Zone Transfer 제한 (전역 allow-transfer: ${glob:-없음}$([ -n "$missing" ] || echo ', 모든 zone 에 설정'))"; fi
    else result "U-50|취약|allow-transfer 미설정 zone(기본값 전체 허용):${missing}"; fi
}

check_U51() {
    evd "U-51" "_svc_status 'named' named bind9 named-chroot; ls -l \$(_named_files) 2>&1; _named_ev"
    is_running named || is_running bind9 || { result "U-51|양호|DNS 서비스 미사용 (가이드 조치 방법: 미사용 시 서비스 중지·비활성화 → 조치 상태)"; return; }
    _named_conf_ok; local rc=$?
    [ $rc -eq 1 ] && { result "U-51|점검불가|DNS 실행 중이나 named.conf 를 찾지 못함"; return; }
    [ $rc -eq 2 ] && { result "U-51|점검불가|named.conf 를 읽지 못함(권한 부족)"; return; }
    local st; st=$(_named_stmts)
    local anyu up au
    anyu=$(echo "$st" | awk -F'|' '$1=="AU" && $3 ~ /(^|[^a-zA-Z-])any([^a-zA-Z-]|$)/ {print $2}' | tr '\n' ' ')
    up=$(echo "$st" | awk -F'|' '$1=="UP" {print $2}' | tr '\n' ' ')
    au=$(echo "$st" | awk -F'|' '$1=="AU" {c++} END{print c+0}')
    if [ -n "$anyu" ]; then result "U-51|취약|DNS 동적 업데이트 any 허용 (allow-update, 범위: ${anyu% })"
    elif [ -n "$up" ]; then result "U-51|수동확인|update-policy 사용(${up% }) - 허용 규칙(grant) 범위 확인"
    elif [ "${au:-0}" -gt 0 ]; then result "U-51|양호|DNS 동적 업데이트 allow-update ${au}건 모두 특정 대상/none 으로 제한"
    else result "U-51|양호|allow-update/update-policy 미설정 (BIND 기본값: 동적 업데이트 거부)"; fi
}

check_U52() {
    evd "U-52" "_svc_status 'telnetd|in.telnetd' telnetd telnet.socket; _inet_ev telnet; _ports_ev"
    local on=""
    { is_running telnetd || is_running in.telnetd; } && on="${on} 프로세스"
    [ -n "$(_inet_on telnet)" ] && on="${on} $(_inet_on telnet)"
    [ -n "$(_listen 23)" ] && on="${on} 23/tcp"
    if [ -n "$on" ]; then result "U-52|취약|Telnet 서비스 활성:${on}"; else result "U-52|양호|Telnet 서비스 비활성화"; fi
}

check_U53() {
    local on vsf pro good="" vuln="" man="" unk="" f v
    on=$(_ftp_on)
    evd "U-53" "_ftp_ev"
    if [ -z "$on" ]; then result "U-53|양호|FTP 서비스 미사용 (가이드 조치 방법: 미사용 시 서비스 중지·비활성화 → 조치 상태)"; return; fi
    vsf=$(_exist /etc/vsftpd.conf /etc/vsftpd/vsftpd.conf); pro=$(_exist /etc/proftpd.conf /etc/proftpd/proftpd.conf)
    evd "U-53" "ls -l ${vsf:-/etc/vsftpd.conf} ${pro:-/etc/proftpd.conf} 2>&1; grep -inE '^[[:space:]]*(ftpd_banner|banner_file)' ${vsf:-/dev/null} /dev/null 2>&1; grep -inE '^[[:space:]]*(ServerIdent|ServerName|DisplayConnect)' ${pro:-/dev/null} /dev/null 2>&1"
    case " $on " in *" vsftpd "*)
        if [ -z "$vsf" ]; then unk="${unk} vsftpd 실행 중이나 vsftpd.conf 를 찾지 못함;"
        else for f in $vsf; do
            if _nc "$f" | grep -qiE '^[[:space:]]*(ftpd_banner|banner_file)[[:space:]]*='; then good="${good} vsftpd 배너 설정(${f});"
            else vuln="${vuln} vsftpd ftpd_banner/banner_file 미설정(기본 배너에 버전 노출, ${f});"; fi; done; fi ;; esac
    case " $on " in *" proftpd "*)
        if [ -z "$pro" ]; then unk="${unk} proftpd 실행 중이나 proftpd.conf 를 찾지 못함;"
        else for f in $pro; do
            v=$(_nc "$f" | grep -iE '^[[:space:]]*ServerIdent' | tail -1)
            if echo "$v" | grep -qiE 'ServerIdent[[:space:]]+(off|on[[:space:]]+"?[^"]+)'; then good="${good} proftpd ${v}(${f});"
            else vuln="${vuln} proftpd ServerIdent 미설정(기본 배너에 버전 노출, ${f});"; fi; done; fi ;; esac
    case " $on " in *vsftpd*|*proftpd*) ;; *) man="${man} FTP(${on}) 배너 설정 수동 확인;" ;; esac
    if [ -n "$vuln" ]; then result "U-53|취약|FTP 버전 정보 노출:${vuln}${good:+ / 양호:${good}}"
    elif [ -n "$unk" ]; then result "U-53|점검불가|${unk}${good:+ / 확인된 항목:${good}}"
    elif [ -n "$man" ]; then result "U-53|수동확인|${man}${good:+ / 양호:${good}}"
    else result "U-53|양호|FTP 배너 제한:${good}"; fi
}

check_U54() {
    local on vsf pro; on=$(_ftp_on)
    evd "U-54" "_ftp_ev"
    if [ -z "$on" ]; then result "U-54|양호|FTP 서비스 비활성화"; return; fi
    vsf=$(_exist /etc/vsftpd.conf /etc/vsftpd/vsftpd.conf); pro=$(_exist /etc/proftpd.conf /etc/proftpd/proftpd.conf /etc/proftpd/tls.conf)
    evd "U-54" "grep -inE '^[[:space:]]*(ssl_enable|force_local_logins_ssl|force_local_data_ssl|implicit_ssl)' ${vsf:-/dev/null} /dev/null 2>&1; grep -inE '^[[:space:]]*(TLSEngine|TLSRequired)' ${pro:-/dev/null} /dev/null 2>&1; ls -l ${vsf} ${pro} 2>&1"
    local good="" bad="" f s fl
    for f in $vsf; do
        s=$(_nc "$f" | awk -F= 'tolower($1) ~ /^[ \t]*ssl_enable[ \t]*$/ {gsub(/[ \t]/,"",$2); x=toupper($2)} END{print x}')
        fl=$(_nc "$f" | awk -F= 'tolower($1) ~ /^[ \t]*force_local_logins_ssl[ \t]*$/ {gsub(/[ \t]/,"",$2); x=toupper($2)} END{print x}')
        if [ "$s" = "YES" ] && [ "$fl" != "NO" ]; then good="${good} vsftpd ssl_enable=YES(강제);"; else bad="${bad} vsftpd ssl_enable=${s:-NO}, force_local_logins_ssl=${fl:-기본};"; fi
    done
    for f in $pro; do
        _nc "$f" | grep -qiE '^[[:space:]]*TLSRequired[[:space:]]+on' && good="${good} proftpd TLSRequired on;"
    done
    case " $on " in *" vsftpd "*|*" proftpd "*) ;; *) bad="${bad} FTP(${on}) 암호화 설정 없음;" ;; esac
    case " $on " in *" proftpd "*) echo "$good" | grep -q proftpd || bad="${bad} proftpd TLSRequired 미설정;" ;; esac
    if [ -n "$bad" ]; then result "U-54|취약|암호화되지 않은 FTP 서비스 사용:${bad}${good:+ / 양호:${good}}"; else result "U-54|양호|FTP 사용 - FTPS(TLS) 강제 설정:${good}"; fi
}

check_U55() {
    evd "U-55" "awk -F: '\$1==\"ftp\" || \$1==\"anonymous\" {print \"계정 \"\$1\": shell=\"(\$7==\"\"?\"(빈 값-기본 shell)\":\$7)} END{print \"/etc/passwd 계정 \"NR\"개 확인\"}' /etc/passwd 2>&1"
    [ -r /etc/passwd ] || { result "U-55|점검불가|/etc/passwd 를 읽지 못함"; return; }
    if ! awk -F: '$1=="ftp"{f=1} END{exit !f}' /etc/passwd; then result "U-55|양호|ftp 계정 없음"; return; fi
    local shell; shell=$(awk -F: '$1=="ftp"{print $7}' /etc/passwd)
    if echo "$shell" | grep -qE "(nologin|false)$"; then result "U-55|양호|ftp shell 제한됨 (${shell})"
    else result "U-55|취약|ftp shell=${shell:-(빈 값: 기본 shell 로그인 가능)} (nologin 필요)"; fi
}

check_U56() {
    local on fu f fl ul acl="" bad="" good="" unk=""; on=$(_ftp_on)
    evd "U-56" "_ftp_ev"
    if [ -z "$on" ]; then result "U-56|양호|FTP 서비스 미사용 (가이드 조치 방법: 미사용 시 서비스 중지·비활성화 → 조치 상태)"; return; fi
    fu=$(_exist /etc/ftpusers /etc/ftpd/ftpusers /etc/vsftpd/ftpusers /etc/vsftpd.ftpusers)
    local vsf pro; vsf=$(_exist /etc/vsftpd.conf /etc/vsftpd/vsftpd.conf); pro=$(_exist /etc/proftpd.conf /etc/proftpd/proftpd.conf)
    ul=$(_nc $vsf | awk -F= 'tolower($1) ~ /^[ \t]*userlist_enable/ {gsub(/[ \t]/,"",$2); x=toupper($2)} END{print x}')
    [ "$ul" = "YES" ] && fu="${fu} $(_exist /etc/vsftpd/user_list /etc/vsftpd.user_list)"
    evd "U-56" "ls -l ${fu:-/etc/ftpusers} 2>&1; grep -inE 'userlist_enable|userlist_deny|tcp_wrappers' ${vsf:-/dev/null} /dev/null 2>&1; grep -inE '<Limit LOGIN>|Allow from|Deny from|UseFtpUsers|RootLogin' ${pro:-/dev/null} /dev/null 2>&1; grep -inE 'ftp' /etc/hosts.allow /etc/hosts.deny /dev/null 2>&1"
    for f in $fu; do
        _fp_eval "$f" 640 root; case $? in 0) good="${good} ${_FP_MSG};" ;; 1) bad="${bad} ${_FP_MSG};" ;; *) unk="${unk} ${_FP_MSG};" ;; esac
    done
    if [ -n "$pro" ] && grep -qiE '^[[:space:]]*Allow from' $pro 2>/dev/null; then acl="${acl} ProFTP <Limit LOGIN>;"; fi
    if grep -qiE '^[[:space:]]*(vsftpd|proftpd|in\.ftpd|ALL)[[:space:]]*:' /etc/hosts.allow 2>/dev/null && grep -qiE '^[[:space:]]*(vsftpd|proftpd|in\.ftpd|ALL)[[:space:]]*:[[:space:]]*ALL' /etc/hosts.deny 2>/dev/null; then
        local vb; vb=$(command -v vsftpd 2>/dev/null)
        if [ -n "$vb" ] && command -v ldd >/dev/null 2>&1 && ! ldd "$vb" 2>/dev/null | grep -q libwrap; then acl="${acl} hosts.allow/deny 존재하나 vsftpd 에 libwrap 없음(미적용);"
        else acl="${acl} tcp_wrappers(hosts.allow/deny);"; fi
    fi
    if [ -n "$bad" ]; then result "U-56|취약|FTP 접근 제어 파일 기준 위반:${bad}"
    elif [ -n "$good" ]; then result "U-56|양호|FTP 접근 제어 파일 소유자 root·640 이하:${good}${acl:+ / 추가: ${acl}}"
    elif [ -n "$unk" ]; then result "U-56|점검불가|${unk}"
    elif echo "$acl" | grep -qE 'ProFTP|tcp_wrappers\('; then result "U-56|양호|ftpusers 파일 없음, 대체 접근 제어:${acl}"
    else result "U-56|취약|FTP 서비스 사용, ftpusers·user_list·접근 제어(IP/호스트) 설정 없음${acl:+ (${acl})} (방화벽 적용 시 증빙 확인)"; fi
}

check_U57() {
    local on fu vsf pro f ul; on=$(_ftp_on)
    evd "U-57" "_ftp_ev"
    if [ -z "$on" ]; then result "U-57|양호|FTP 서비스 비활성화"; return; fi
    fu=$(_exist /etc/ftpusers /etc/ftpd/ftpusers /etc/vsftpd/ftpusers /etc/vsftpd.ftpusers)
    vsf=$(_exist /etc/vsftpd.conf /etc/vsftpd/vsftpd.conf); pro=$(_exist /etc/proftpd.conf /etc/proftpd/proftpd.conf)
    ul=$(_nc $vsf | awk -F= 'tolower($1) ~ /^[ \t]*userlist_enable/ {gsub(/[ \t]/,"",$2); x=toupper($2)} END{print x}')
    local uld; uld=$(_nc $vsf | awk -F= 'tolower($1) ~ /^[ \t]*userlist_deny/ {gsub(/[ \t]/,"",$2); x=toupper($2)} END{print x}')
    local ulf; ulf=$(_exist /etc/vsftpd/user_list /etc/vsftpd.user_list)
    evd "U-57" "grep -nE '^[[:space:]]*#?[[:space:]]*root' ${fu:-/dev/null} ${ulf} /dev/null 2>&1; grep -inE 'userlist_enable|userlist_deny' ${vsf:-/dev/null} /dev/null 2>&1; grep -inE 'RootLogin|UseFtpUsers' ${pro:-/dev/null} /dev/null 2>&1; ls -l ${fu:-/etc/ftpusers} ${ulf} 2>&1"
    for f in $fu; do
        _nc "$f" | grep -qE '^root([[:space:]]|$)' && { result "U-57|양호|FTP root 접속 차단 (${f})"; return; }
    done
    if [ "$ul" = "YES" ] && [ "$uld" != "NO" ]; then
        for f in $ulf; do _nc "$f" | grep -qE '^root([[:space:]]|$)' && { result "U-57|양호|vsftpd userlist_enable=YES, user_list 에 root 차단 (${f})"; return; }; done
    fi
    for f in $pro; do _nc "$f" | grep -qiE '^[[:space:]]*RootLogin[[:space:]]+off' && { result "U-57|양호|ProFTPD RootLogin off (${f})"; return; }; done
    if [ -z "$fu$vsf$pro" ]; then result "U-57|점검불가|FTP 서비스(${on})는 사용 중이나 ftpusers·vsftpd.conf·proftpd.conf 를 찾지 못함"; return; fi
    result "U-57|취약|FTP 서비스 사용, root 계정 접속 차단 설정 없음 (ftpusers 에 root 없음)"
}

_snmp_confs() { _exist /etc/snmp/snmpd.conf /etc/snmpd.conf /etc/net-snmp/snmp/snmpd.conf /etc/snmpdv3.conf /etc/SnmpAgent.d/snmpd.conf /usr/local/etc/snmp/snmpd.conf; }
_snmp_on() { local s o=""; for s in snmpd snmpdm snmpdv3ne snmpdv3; do is_running "$s" && o="${o} ${s}"; done; [ -n "$(_listen 161)" ] && o="${o} 161/udp"; echo "${o# }"; }
_snmp_ev() { _svc_status 'snmpd|snmpdm|snmpdv3ne|snmpdv3' snmpd snmpdm snmpdv3ne; echo "리슨 161: $(_listen 161)"; }

_snmp_wr() {   # 표준입력 snmpd 설정에서 v1/v2c 로 쓰기(SET)가 가능한 설정 요약 (community 값은 출력하지 않음)
    awk '{ l=tolower($1) }
        l ~ /^rwcommunity6?$/ { print $1 }
        l ~ /^(set-community-name:?|write-community)$/ { print $1 }
        l=="access" && tolower($4)!="usm" && $8!="" && tolower($8)!="none" { print "access " $2 " (" $4 ", write view=" $8 ")" }' | sort -u | tr '\n' ',' | sed 's/,$//'
}
check_U58() {
    evd "U-58" "_snmp_ev"
    local on; on=$(_snmp_on)
    if [ -n "$on" ]; then result "U-58|취약|SNMP 서비스 사용 중 (${on}) (가이드: 미사용 시 중지 - 업무상 필요 여부 확인)"; else result "U-58|양호|SNMP 서비스 미사용"; fi
}

check_U59() {
    local on cf; on=$(_snmp_on); cf=$(_snmp_confs)
    evd "U-59" "_snmp_ev"
    if [ -z "$on" ]; then result "U-59|양호|SNMP 서비스 미사용 (가이드 조치 방법: 미사용 시 서비스 중지·비활성화 → 조치 상태)"; return; fi
    evd "U-59" "ls -l ${cf:-/etc/snmp/snmpd.conf} 2>&1; _snmp_dump ${cf:-/etc/snmp/snmpd.conf}"
    if [ -z "$cf" ]; then result "U-59|점검불가|SNMP 실행 중이나 snmpd.conf 를 찾지 못함"; return; fi
    _unreadable $cf && { result "U-59|점검불가|SNMP 설정 파일을 읽지 못함(권한 부족)"; return; }
    local v3=0 v12=0 f
    for f in $cf; do
        _nc "$f" | grep -qiE '^[[:space:]]*(rouser|rwuser|createUser|USM_USER)' && v3=1
        _nc "$f" | grep -qiE '^[[:space:]]*(rocommunity6?|rwcommunity6?|com2sec6?|community|read-community|write-community)[[:space:]]' && v12=1
    done
    if [ $v3 -eq 1 ] && [ $v12 -eq 0 ]; then result "U-59|양호|SNMPv3 인증(rouser/rwuser/USM)만 설정, v1/v2c community 없음"
    elif [ $v3 -eq 1 ]; then result "U-59|취약|SNMPv3 사용자와 함께 v1/v2c community 도 열려 있음"
    else result "U-59|취약|SNMPv3 미설정 (v1/v2c 만 사용)"; fi
}

check_U60() {
    local on cf; on=$(_snmp_on); cf=$(_snmp_confs)
    evd "U-60" "_snmp_ev"
    if [ -z "$on" ]; then result "U-60|양호|SNMP 서비스 미사용 (가이드 조치 방법: 미사용 시 서비스 중지·비활성화 → 조치 상태)"; return; fi
    evd "U-60" "ls -l ${cf:-/etc/snmp/snmpd.conf} 2>&1; _snmp_dump ${cf:-/etc/snmp/snmpd.conf}"
    if [ -z "$cf" ]; then result "U-60|점검불가|SNMP 실행 중이나 snmpd.conf 를 찾지 못함"; return; fi
    _unreadable $cf && { result "U-60|점검불가|SNMP 설정 파일을 읽지 못함(권한 부족)"; return; }
    local weak="" n=0 c conf cls m
    for conf in $cf; do
        for c in $(grep -vE '^[[:space:]]*#' "$conf" 2>/dev/null | awk 'tolower($1) ~ /^r[ow]community6?$/ {print $2} tolower($1) ~ /^com2sec6?$/ {i=2; while ($i ~ /^-/) i+=2; print $(i+2)} tolower($1) ~ /^(get|set)-community-name:?$/ {print $2} tolower($1) ~ /^(read|write|trap)-community$/ {print $2} tolower($1)=="community" {print $2}'); do
            n=$((n+1)); cls=0; m="${c:0:2}***"
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
    local on cf; on=$(_snmp_on); cf=$(_snmp_confs)
    evd "U-61" "_snmp_ev"
    if [ -z "$on" ]; then result "U-61|양호|SNMP 서비스 미사용 (가이드 조치 방법: 미사용 시 서비스 중지·비활성화 → 조치 상태)"; return; fi
    evd "U-61" "ls -l ${cf:-/etc/snmp/snmpd.conf} 2>&1; _snmp_dump ${cf:-/etc/snmp/snmpd.conf}; grep -inE '^[[:space:]]*agentaddress' ${cf:-/dev/null} /dev/null 2>&1"
    if [ -z "$cf" ]; then result "U-61|점검불가|SNMP 실행 중이나 snmpd.conf 를 찾지 못함"; return; fi
    _unreadable $cf && { result "U-61|점검불가|SNMP 설정 파일을 읽지 못함(권한 부족)"; return; }
    local open=0 restr=0 f r
    for f in $cf; do
        r=$(grep -vE '^[[:space:]]*#' "$f" 2>/dev/null | awk '
            { l=tolower($1) }
            l ~ /^r[ow]community6?$/ { s=$3; if (s=="" || s=="default" || s=="0.0.0.0/0" || s=="::/0" || s=="0.0.0.0") print "OPEN"; else print "RESTR" }
            l ~ /^com2sec6?$/ { i=2; while ($i ~ /^-/) i+=2; s=$(i+1); if (s=="default" || s=="0.0.0.0/0" || s=="::/0" || s=="0.0.0.0") print "OPEN"; else print "RESTR" }
            l == "community" { a=$3; b=$4; if (NF>=5) { a=$5; b=$6 } else { a=$3; b=$4 } if (a ~ /^[0-9.]+$/ && a!="0.0.0.0") print "RESTR"; else if (a=="0.0.0.0" || a=="") print "OPEN"; else print "RESTR" }')
        echo "$r" | grep -q OPEN && open=$((open+1))
        echo "$r" | grep -q RESTR && restr=$((restr+1))
    done
    local lo=0
    grep -vE '^[[:space:]]*#' $cf 2>/dev/null | grep -qiE '^[[:space:]]*agentaddress' && ! grep -vE '^[[:space:]]*#' $cf 2>/dev/null | grep -iE '^[[:space:]]*agentaddress' | grep -qvE '(127\.0\.0\.1|\[?::1\]?|localhost)' && lo=1
    if [ $open -gt 0 ]; then result "U-61|취약|SNMP community 에 허용 네트워크(source) 제한 없음(default/0.0.0.0/0) ${open}개 설정 파일"
    elif [ $restr -gt 0 ] && [ -n "$(_nc $cf | _snmp_wr)" ]; then result "U-61|수동확인|허용 네트워크는 제한되어 있으나 v1/v2c 쓰기(SET) 권한이 설정됨: $(_nc $cf | _snmp_wr) - 쓰기 필요성 확인, 불필요 시 제거·v3 전환"
    elif [ $restr -gt 0 ]; then result "U-61|양호|SNMP community 접근 허용 네트워크가 제한됨"
    elif [ $lo -eq 1 ]; then result "U-61|양호|agentAddress 가 루프백으로만 바인딩됨"
    elif grep -vE '^[[:space:]]*#' $cf 2>/dev/null | grep -qiE '^[[:space:]]*(rouser|rwuser|createUser|USM_USER)'; then result "U-61|수동확인|v1/v2c community 없음(SNMPv3 사용자만) - v3 접근 제어(view·허용 IP) 수동 확인"
    else result "U-61|취약|SNMP 접근통제 설정 없음 (IP 제한 없음; agentAddress 전체 바인딩은 접근통제 아님)"; fi
}

check_U62() {
    local sshf banner="" bf="" f
    sshf=$(_sshd_conf_files | tr '\n' ' ')
    banner=$(_sshd_get Banner); [ "$(echo "$banner" | tr 'A-Z' 'a-z')" = "none" ] && banner=""
    [ -n "$banner" ] && bf="$banner"
    evd "U-62" "for f in /etc/motd /etc/issue /etc/issue.net ${bf}; do echo \"== \$f\"; cat \$f 2>&1; done; grep -inE '^[[:space:]]*Banner' ${sshf:-/etc/ssh/sshd_config} /dev/null 2>&1; sshd -T 2>&1 | grep -i '^banner'"
    local kw='경고|주의|불법|허가|인가|접근|금지|무단|법|처벌|warning|authori[sz]ed|unauthori[sz]ed|prohibited|restricted|violat|monitor|logged|notice|private|property'
    local hit="" custom=""
    for f in /etc/motd /etc/issue /etc/issue.net $bf; do
        [ -s "$f" ] || continue
        grep -qiE "$kw" "$f" 2>/dev/null && hit="${hit} ${f}"
        [ "$f" != "/etc/issue" ] && custom="${custom} ${f}"
    done
    if [ -n "$hit" ]; then result "U-62|양호|경고 메시지 설정됨 (${hit# }$([ -n "$banner" ] && echo ", sshd Banner=${banner}"))"
    elif [ -n "$custom" ]; then result "U-62|수동확인|로그인 안내 문구 파일이 있으나 경고 문구 여부 불명(${custom# }) - 내용 확인(증적)"
    elif _unreadable /etc/motd /etc/issue /etc/issue.net; then result "U-62|점검불가|배너 파일을 읽지 못함(권한 부족)"
    else result "U-62|취약|경고 메시지 미설정 (/etc/motd·issue.net 비어 있음/없음, sshd Banner ${banner:-미설정}, /etc/issue 는 경고 문구 없음)"; fi
}

check_U63() {
    local f=/etc/sudoers; [ -f "$f" ] || f=/usr/local/etc/sudoers
    if [ ! -f "$f" ]; then evd "U-63" "ls -l /etc/sudoers /usr/local/etc/sudoers 2>&1; ls -ld /etc/sudoers.d 2>&1"; result "U-63|양호|sudo 미설치 (/etc/sudoers 없음 - 권한을 점검할 파일 없음)"; return; fi
    _check_file_perm "U-63" "$f" 640 "root" "$f"
}

check_U64() {
    local tool=""
    for t in rpm dpkg apt yum dnf zypper lslpp instfix pkg pkginfo showrev swlist; do command -v "$t" >/dev/null 2>&1 && tool="${tool} ${t}"; done
    evd "U-64" "uname -a 2>&1; cat /etc/os-release 2>&1; echo \"패키지 도구:${tool:- 없음}\""
    if [ -z "$tool" ]; then result "U-64|점검불가|패키지/패치 조회 명령(rpm·dpkg·lslpp·pkg·swlist 등)이 없음"; return; fi
    case "$OS_FAMILY" in
    AIX) evd "U-64" "oslevel -s 2>&1; instfix -i 2>&1" ;;
    SOLARIS) evd "U-64" "(pkg info entire 2>&1 || showrev -p 2>&1)" ;;
    HPUX) evd "U-64" "swlist -l bundle 2>&1" ;;
    *)
        command -v rpm >/dev/null 2>&1 && evd "U-64" "rpm -qa --last 2>&1"
        if command -v apt >/dev/null 2>&1; then evd "U-64" "apt list --upgradable 2>&1"
        elif command -v dnf >/dev/null 2>&1; then evd "U-64" "_to 30 dnf -C -q updateinfo summary 2>&1"
        elif command -v yum >/dev/null 2>&1; then evd "U-64" "_to 30 yum -C -q updateinfo summary 2>&1"; fi ;;
    esac
    result "U-64|수동확인|최신 보안패치 적용 여부 수동 확인 (패키지 목록·업데이트 현황은 증적 참조, 저장소 접속 없이 캐시 기준)"
}

check_U65() {
    local conf servers=0 run="" f sync=0 detail=""
    for s in chronyd chrony ntpd ntp xntpd systemd-timesyncd; do is_running "$s" && run="${run} ${s}"; done
    conf=$(_exist /etc/ntp.conf /etc/chrony.conf /etc/chrony/chrony.conf /etc/inet/ntp.conf /etc/systemd/timesyncd.conf)
    evd "U-65" "_svc_status 'chronyd|ntpd|xntpd|systemd-timesyncd' chronyd chrony ntpd ntp xntpd systemd-timesyncd; ls -l ${conf:-/etc/ntp.conf} 2>&1; grep -HEi '^[[:space:]]*(server|pool|peer|NTP=|FallbackNTP=)' ${conf:-/dev/null} /dev/null 2>&1"
    command -v timedatectl >/dev/null 2>&1 && evd "U-65" "timedatectl 2>&1"
    grep -qiE '(System clock|NTP) synchronized:[[:space:]]*yes' "$LAST" 2>/dev/null && command -v timedatectl >/dev/null 2>&1 && { sync=1; detail="${detail} timedatectl 동기화=yes;"; }
    if command -v chronyc >/dev/null 2>&1; then
        evd "U-65" "chronyc -n sources 2>&1; chronyc tracking 2>&1"
        grep -qE '^\^\*|Leap status[[:space:]]*:[[:space:]]*Normal' "$LAST" && { sync=1; detail="${detail} chrony 동기화;"; }
    fi
    if command -v ntpq >/dev/null 2>&1; then
        evd "U-65" "ntpq -pn 2>&1"
        grep -qE '^\*' "$LAST" && { sync=1; detail="${detail} ntpq 동기화(*);"; }
    fi
    for f in $conf; do
        servers=$((servers + $(grep -vE '^[[:space:]]*#' "$f" 2>/dev/null | grep -cEi '^[[:space:]]*(server|pool|peer)[[:space:]]+[^[:space:]]+|^[[:space:]]*NTP=[^[:space:]]+')))
    done
    if [ $sync -eq 1 ]; then result "U-65|양호|NTP 서버와 동기화됨:${detail}${run:+ 실행 중:${run}}, 설정된 서버 ${servers}개"
    elif [ -n "$run" ] && [ "$servers" -gt 0 ]; then result "U-65|수동확인|시각 동기화 서비스(${run# }) 실행·서버 ${servers}개 설정이나 동기화 상태 미확인 - 증적(ntpq/chronyc/timedatectl) 확인"
    elif [ -n "$run" ]; then result "U-65|취약|시각 동기화 서비스(${run# }) 실행 중이나 NTP 서버 설정이 없음"
    elif [ "$servers" -gt 0 ]; then result "U-65|취약|NTP 서버 ${servers}개 설정 파일은 있으나 동기화 서비스가 실행 중이 아님"
    else result "U-65|취약|NTP 미설정 (동기화 서비스 미실행, 서버 설정 없음)"; fi
}

check_U66() {
    local files="" f
    for f in /etc/rsyslog.conf /etc/rsyslog.d/*.conf /etc/syslog.conf /etc/syslog-ng/syslog-ng.conf; do [ -f "$f" ] && files="${files} $f"; done
    evd "U-66" "ls -l ${files:-/etc/rsyslog.conf} 2>&1; grep -HvE '^[[:space:]]*(#|\$)' ${files:-/etc/rsyslog.conf} /dev/null 2>&1; _svc_status 'rsyslogd|syslogd|syslog-ng|systemd-journald' rsyslog syslog syslog-ng systemd-journald; ls -ld /var/log/journal 2>&1; grep -E '^[[:space:]]*Storage' /etc/systemd/journald.conf /dev/null 2>&1"
    if [ -z "$files" ]; then
        if [ -d /var/log/journal ] || grep -qiE '^[[:space:]]*Storage=persistent' /etc/systemd/journald.conf 2>/dev/null; then result "U-66|수동확인|syslog 설정 파일 없음 - journald(영구 저장) 만 사용: 로깅 정책 수동 확인"
        elif _unreadable /etc/rsyslog.conf /etc/syslog.conf; then result "U-66|점검불가|syslog 설정 파일을 읽지 못함(권한 부족)"
        else result "U-66|취약|시스템 로깅 설정 파일(rsyslog/syslog)이 없음"; fi
        return
    fi
    local act; act=$(_nc $files)
    local sel; sel=$(echo "$act" | awk '{print $1}')
    local has_auth=0 has_gen=0 has_emerg=0 has_cron=0 has_mail=0
    echo "$sel" | tr ';' '\n' | grep -qE '(^|,)(auth|authpriv)(,[a-z]+)*\.[^n]|(^|,)(auth|authpriv)(,[a-z]+)*\.(\*|debug|info|notice|warning|warn|err|error|crit|alert|emerg)' && has_auth=1
    echo "$sel" | tr ';' '\n' | grep -qE '^\*\.(\*|debug|info|notice|warn|warning|err|error)' && has_gen=1
    echo "$sel" | tr ';' '\n' | grep -qE '(^|,)\*\.(emerg|alert)|\*\.emerg|\*\.alert' && has_emerg=1
    echo "$sel" | tr ';' '\n' | grep -qE '^cron(,[a-z]+)*\.[^n]' && has_cron=1
    echo "$sel" | tr ';' '\n' | grep -qE '^mail(,[a-z]+)*\.[^n]' && has_mail=1
    local miss=""; [ $has_cron -eq 0 ] && miss="${miss} cron"; [ $has_mail -eq 0 ] && miss="${miss} mail"
    if [ $has_auth -eq 1 ] && [ $has_gen -eq 1 ]; then result "U-66|양호|시스템 로깅 설정됨: auth/authpriv·일반(*.info 등) 규칙 있음$([ $has_emerg -eq 1 ] && echo ', emerg/alert')${miss:+ (참고: 별도 규칙 없는 시설:${miss})} ($(echo $files | wc -w | tr -d ' ')개 파일)"
    else result "U-66|취약|시스템 로깅 정책 미흡: auth/authpriv 규칙 $([ $has_auth -eq 1 ] && echo 있음 || echo 없음), 일반(*.info 등) 규칙 $([ $has_gen -eq 1 ] && echo 있음 || echo 없음) (가이드: authpriv·*.info·cron·mail·*.alert·*.emerg)"; fi
}

check_U67() {
    local dirs d f lst="$_TMPD/u67.lst"
    case "$OS_FAMILY" in
    AIX) dirs="/var/adm" ;;
    HPUX) dirs="/var/adm/syslog" ;;
    SOLARIS) dirs="/var/log /var/adm" ;;
    *) dirs="/var/log" ;;
    esac
    : > "$lst"
    for d in $dirs; do
        [ -d "$d" ] || continue
        for f in "$d"/*; do [ -f "$f" ] && echo "$f" >> "$lst"; done
    done
    evd "U-67" "ls -ld $dirs 2>&1"
    evd_ls "U-67" "$dirs 내 로그 파일 없음" "$lst"
    _fp_reset
    while IFS= read -r f; do [ -n "$f" ] && _fp_add "$f" 644 root; done < "$lst"
    if [ "$_NCHK" -eq 0 ]; then
        if [ -d "$(echo $dirs | awk '{print $1}')" ]; then result "U-67|양호|${dirs} 에 점검할 로그 파일 없음"; else result "U-67|점검불가|로그 디렉터리(${dirs})가 없음"; fi
    else _fp_verdict "U-67" "${dirs} 내 로그 파일 소유자 root, 권한 644 이하"; fi
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

_TOTAL=$((_CP + _CF + _CM + _CN + _CU))
echo "# ================================================================"
echo "# 점검 요약 — 주요정보통신기반시설 (U-시리즈)"
echo "#   총 점검 항목: ${_TOTAL}"
if [ "$_TOTAL" -gt 0 ] 2>/dev/null; then
    echo "#   양호:         ${_CP}  ($((_CP * 100 / _TOTAL))%)"
    echo "#   취약:         ${_CF}  ($((_CF * 100 / _TOTAL))%)"
fi
echo "#   수동확인:     ${_CM}"
echo "#   점검불가:     ${_CU}"
echo "#   N-A:          ${_CN}"
echo "# ================================================================"
echo "# 증적 파일: ${_EVD}"
[ -n "$_RESF" ] && echo "# 결과 파일(자동 저장): ${_RESF}  ← 증적 파일과 함께 회수"
[ -n "$_TEEPID" ] && { exec >&- 2>/dev/null; wait "$_TEEPID" 2>/dev/null; sleep 1; }
exit 0
