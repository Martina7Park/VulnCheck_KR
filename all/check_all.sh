#!/bin/bash
# ================================================================
# 통합 자동 점검 (Linux / AIX / HP-UX / Solaris) — check_all.sh
# ================================================================
#
# [용도]
#   서버 한 대에서 한 번 실행하면 OS·웹서버/WAS·DBMS 를 자동 탐지해
#   해당하는 점검(서버 / 웹·WAS / DBMS)을 모두 수행하고 결과를 압축 파일 하나로 만듭니다.
#   ※ 이 파일은 all/build.py 가 server/·webwas/·dbms/ 스크립트를 합쳐 생성합니다. 직접 수정하지 마세요.
#
# [실행 방법]
#   sudo bash check_all.sh            # 메뉴에서 기준 선택
#   sudo bash check_all.sh all        # ef=전자금융 / mi=주요정보 2026 가이드 / all=둘 다
#
# [선택 환경변수]
#   OUT_DIR=/경로          결과 저장 위치 (기본: 현재 폴더, 쓰기 불가면 /tmp)
#   WEBWAS=yes|no          웹서버/WAS 점검 강제 실행 / 생략 (기본: 자동 탐지)
#   DBMS_TYPES="mysql pgsql"  점검할 DBMS 직접 지정 (oracle mysql pgsql tibero mssql, 기본: 실행 중인 DB 자동 탐지)
#   DB 접속 정보는 dbms/check_dbms.sh 와 같음 (ORACLE_*, MYSQL_*, PGSQL_*, TIBERO_*, MSSQL_*)
#
# [산출물]
#   <호스트>_vulncheck_<일시>.tar.gz  — converter/ 폴더에서 풀면 server/ webwas/ dbms/ 의 output/ 에 바로 들어감
#   <호스트>_vulncheck_<일시>/          — 같은 내용의 폴더 (summary.txt: 탐지·실행 요약)
# ================================================================

_MODE="${1:-${CHECK_MODE:-}}"
if [ -z "$_MODE" ]; then
    if [ -t 0 ]; then
        { echo "점검 기준을 선택하세요:"
          echo "  1) 전자금융기반시설 (SRV / WST / DBM)"
          echo "  2) 주요정보통신기반시설 2026 상세가이드 (U / WEB / D)"
          echo "  3) 둘 다"
          printf "선택 [1/2/3] (Enter=3): "; } >&2
        read -r _sel; _MODE="${_sel:-3}"
    else
        _MODE="all"
    fi
fi
case "$(echo "$_MODE" | tr 'A-Z' 'a-z')" in
1|ef|srv) _MODE="ef" ;;
2|mi|kisa|u) _MODE="mi" ;;
3|all) _MODE="all" ;;
*) echo "사용법: $0 [ef|mi|all]  (ef=전자금융, mi=주요정보 2026 상세가이드, all=둘 다)" >&2; exit 1 ;;
esac

[ "$(id -u 2>/dev/null)" = "0" ] || echo "[경고] root 권한이 아닙니다 — 일부 항목이 수동확인으로 나올 수 있습니다 (sudo bash 권장)" >&2

HN=$(hostname 2>/dev/null || uname -n)
TS=$(date '+%Y%m%d_%H%M%S')
PKG="${HN}_vulncheck_${TS}"
BASE="${OUT_DIR:-$(pwd)}"
( : > "$BASE/.vc_w" ) 2>/dev/null && rm -f "$BASE/.vc_w" || BASE="/tmp"
OUT="$BASE/$PKG"
mkdir -p "$OUT" || { echo "[오류] 결과 폴더를 만들 수 없습니다: $OUT" >&2; exit 1; }
chmod 700 "$OUT" 2>/dev/null

WORK=$(mktemp -d "${TMPDIR:-/tmp}/vulncheck.XXXXXX" 2>/dev/null) || { WORK="/tmp/vulncheck.$$"; mkdir -p "$WORK"; }
chmod 700 "$WORK" 2>/dev/null
trap 'rm -rf "$WORK"' EXIT

# ── 내장: server/check_server.sh ──
cat > "$WORK/check_server.sh" <<'__VC_EOF_1__'
#!/bin/bash
if [ -z "$BASH_VERSION" ]; then for _b in /bin/bash /usr/bin/bash /opt/freeware/bin/bash /usr/local/bin/bash /usr/contrib/bin/bash; do [ -x $_b ] && exec $_b "$0" "$@"; done; echo "bash 필요 (AIX: AIX Toolbox bash / HP-UX: Porting Centre bash 설치 후 재실행)"; exit 1; fi   # sh 로 실행 시 bash 로 재실행 (declare -A 등 bash 전용 문법)
unset LC_ALL; export LC_MESSAGES=C LC_TIME=C          # apt/lastlog 등 명령 출력·날짜를 영문 고정 (ko_KR 로케일 판정 차이 방지)
# ================================================================
# 서버(Unix/Linux) 보안 취약점 자동 점검 스크립트 v4.0
# ================================================================
#
# [용도]
#   전자금융기반시설·주요정보통신기반시설 서버 보안 점검.
#   기준: 전자금융기반시설 보안 취약점 평가기준 제2026-1호 [서버]
#   Windows Server는 check_server.ps1 사용.
#
# [대상 OS]
#   Linux (RHEL/CentOS/Rocky/Ubuntu/SLES/Amazon)
#   AIX 6.1~7.3 / HP-UX 11i / Solaris 10~11
#
# [사전 조건]
#   - root 권한 필요 (sudo bash 또는 root 로그인)
#   - 별도 환경변수 없음 (OS 자동 탐지)
#
# [실행 방법]
#   ※ 이 파일은 통합 참조용입니다. 실제 점검에는 분리된 스크립트 사용:
#   bash check_server_srv.sh > /tmp/$(hostname)_srv.txt  → 전자금융기반시설
#   bash check_server_u.sh   > /tmp/$(hostname)_u.txt    → 주요정보통신기반시설
#
# [산출물]
#   1) 표준출력 — 파이프 구분자 결과 (파일로 리다이렉트)
#      형식: SRV-항목코드|결과|근거설명  (전자금융기반시설)
#             U-항목코드|결과|근거설명    (주요정보통신기반시설)
#      결과: 양호 / 취약 / 수동확인 / N-A
#   2) 증적 파일 — /tmp/<호스트명>_server_evidence.txt
#      점검 중 실행한 명령어·출력·판정 근거가 타임스탬프와 함께 기록됨
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
        *)       case " $ID_LIKE " in   # ProLinux(ID=pl) 등 파생 배포판
                 *" rhel "*|*" centos "*|*" fedora "*) OS_DISTRO="RHEL" ;;
                 *" debian "*|*" ubuntu "*) OS_DISTRO="DEBIAN" ;;
                 *" suse "*) OS_DISTRO="SLES" ;;
                 *) OS_DISTRO="${ID:-UNKNOWN}" ;;
                 esac; OS_MAJOR="${VERSION_ID%%.*}" ;;
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

# ── 모드 선택 ────────────────────────────────────────────────────
_MODE="${1:-}"
if [ -z "$_MODE" ]; then
    { echo "점검 기준을 선택하세요:"
      echo "  1) 전자금융기반시설 (SRV-001~179)"
      echo "  2) 주요정보통신기반시설 2026 상세가이드 (U-01~U-67, check_server_u.sh 실행)"
      echo "  3) 전체 (전자금융 결과 + 주요정보 결과 파일 각각 생성)"
      printf "선택 [1/2/3]: "; } >&2   # '> 파일' 리다이렉트 시에도 화면에 표시
    read -r _sel
    case "$_sel" in
    1) _MODE="srv" ;;
    2) _MODE="u" ;;
    3) _MODE="all" ;;
    *) echo "잘못된 선택. 종료합니다." >&2; exit 1 ;;
    esac
fi
_MODE=$(echo "$_MODE" | tr '[:upper:]' '[:lower:]')
case "$_MODE" in
srv|u|all) ;;
*) echo "사용법: $0 {srv|u|all}" >&2; exit 1 ;;
esac
_SELF_DIR=$(cd "$(dirname "$0")" 2>/dev/null && pwd)
if [ "$_MODE" = "u" ]; then   # 주요정보: 2026 상세가이드 전용 스크립트로 전환 (결과·증적은 그 스크립트가 생성)
    [ -f "$_SELF_DIR/check_server_u.sh" ] || { echo "# [오류] check_server_u.sh 가 같은 폴더에 없습니다 (주요정보 점검 불가)"; exit 1; }
    exec bash "$_SELF_DIR/check_server_u.sh"
fi
# ── 결과 사본 자동 저장: '> 파일' 리다이렉트를 빠뜨려도 판정 결과가 증적과 같은 위치에 남도록 표준출력을 복사 ──
_RESF="/tmp/${HN}_server.txt"
if [ -z "$NO_RESULT_COPY" ] && ! [ /dev/fd/1 -ef "$_RESF" ] 2>/dev/null && ( : > "$_RESF" ) 2>/dev/null; then
    exec > >(tee "$_RESF"); _TEEPID=$!
else
    _RESF=""
fi

case "$_MODE" in
srv) _STD_NAME="전자금융기반시설 보안 취약점 평가기준 제2026-1호 [서버]" ;;
all) _STD_NAME="전자금융기반시설 보안 취약점 평가기준 제2026-1호 [서버] (주요정보는 check_server_u.sh 결과 파일 별도)" ;;
esac

echo "# ============================================================"
echo "# 점검 대상: ${HN}"
echo "# OS: ${OS_FAMILY} / ${OS_DISTRO} ${OS_MAJOR}"
echo "# OS 상세: $( ( [ -r /etc/os-release ] && . /etc/os-release 2>/dev/null && echo "${PRETTY_NAME:-$NAME $VERSION_ID}" ) || ( command -v oslevel >/dev/null 2>&1 && echo "AIX $(oslevel -s 2>/dev/null)" ) || ( [ -r /etc/release ] && head -1 /etc/release | sed 's/^ *//' ) || uname -sr 2>/dev/null)"
echo "# 커널: $(uname -r 2>/dev/null)$( [ "$(uname -s 2>/dev/null)" = SunOS ] && echo " / $(uname -v 2>/dev/null)")"
echo "# 점검 기준: ${_STD_NAME}"
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
_EVD="/tmp/${HN}_server_evidence.txt"
# 증적 파일 쓰기 불가(다른 사용자 소유 기존 파일, /tmp 용량 부족 등) → 대체 경로 (쓰기 실패로 판정 중복 방지)
if ! ( : >> "$_EVD" ) 2>/dev/null; then
    _EVD=$(mktemp "${TMPDIR:-/tmp}/${HN}_evidence.XXXXXX" 2>/dev/null || echo "./${HN}_evidence_$$.txt")
    echo "# [경고] 기본 증적 파일에 쓸 수 없어 대체 경로 사용: $_EVD"
fi
_NONROOT=0; [ "$(id -u 2>/dev/null)" != "0" ] && { _NONROOT=1; echo "# [경고] root 권한 아님 — /etc/shadow·타 계정 홈 등 조회 불가 항목(SRV-022/074/096/122)은 수동확인 처리, root 로 재점검 권고"; }
echo "# ================================================================" > "$_EVD"
echo "# 증적 파일 (감사 추적용)" >> "$_EVD"
echo "# 대상: ${HN} / ${OS_FAMILY} ${OS_DISTRO} ${OS_MAJOR}" >> "$_EVD"
echo "# 생성: $(date '+%Y-%m-%d %H:%M:%S')" >> "$_EVD"
echo "# ================================================================" >> "$_EVD"

# ── Windows 환경 조기 종료 ───────────────────────────────────────
if [ "$OS_FAMILY" = "WINDOWS" ]; then
    echo "# Windows 환경 — 전 항목 N-A 처리" >> "$_EVD"
    if [ "$_MODE" = "srv" ] || [ "$_MODE" = "all" ]; then
        for _c in SRV-001 SRV-003 SRV-004 SRV-005 SRV-006 SRV-007 SRV-008 SRV-009 SRV-010 SRV-011 SRV-012 SRV-013 SRV-014 SRV-015 SRV-016 SRV-018 SRV-020 SRV-021 SRV-022 SRV-023 SRV-024 SRV-025 SRV-026 SRV-027 SRV-028 SRV-029 SRV-031 SRV-034 SRV-035 SRV-037 SRV-062 SRV-063 SRV-064 SRV-066 SRV-069 SRV-070 SRV-072 SRV-073 SRV-074 SRV-075 SRV-078 SRV-079 SRV-080 SRV-081 SRV-082 SRV-083 SRV-084 SRV-087 SRV-090 SRV-091 SRV-092 SRV-093 SRV-094 SRV-095 SRV-096 SRV-097 SRV-101 SRV-103 SRV-104 SRV-105 SRV-108 SRV-109 SRV-112 SRV-115 SRV-116 SRV-118 SRV-119 SRV-121 SRV-122 SRV-123 SRV-125 SRV-126 SRV-127 SRV-128 SRV-129 SRV-131 SRV-133 SRV-134 SRV-135 SRV-136 SRV-137 SRV-138 SRV-139 SRV-140 SRV-142 SRV-144 SRV-147 SRV-149 SRV-150 SRV-151 SRV-152 SRV-158 SRV-161 SRV-163 SRV-164 SRV-165 SRV-166 SRV-170 SRV-171 SRV-172 SRV-173 SRV-174 SRV-175 SRV-177 SRV-178 SRV-179; do
            _CN=$((_CN+1))
            echo "${_c}|N-A|Windows 환경 — Linux/Unix 전용 항목"
            printf '[판정] %s|N-A|Windows 환경 — Linux/Unix 전용 항목\n\n' "$_c" >> "$_EVD"
        done
    fi
    _TOTAL=$((_CP + _CF + _CM + _CN))
    echo "# ================================================================"
    echo "# 점검 요약"
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
# ── 평가대상 매핑 (전자금융기반시설 평가기준 제2026-1호 [서버] '평가대상' 열 기준) ──
# 해당 OS가 평가대상이 아닌 항목은 판정을 N-A로 강제 (점검·증적 수집은 그대로 수행)
_NA_LINUX=" SRV-018 SRV-020 SRV-023 SRV-024 SRV-029 SRV-031 SRV-072 SRV-078 SRV-079 SRV-080 SRV-090 SRV-097 SRV-101 SRV-103 SRV-104 SRV-105 SRV-116 SRV-119 SRV-123 SRV-125 SRV-126 SRV-128 SRV-129 SRV-134 SRV-135 SRV-136 SRV-137 SRV-138 SRV-139 SRV-140 SRV-149 SRV-150 SRV-151 SRV-152 SRV-172 SRV-178 "
_NA_AIX=" SRV-018 SRV-020 SRV-023 SRV-024 SRV-029 SRV-031 SRV-072 SRV-078 SRV-079 SRV-080 SRV-090 SRV-097 SRV-101 SRV-103 SRV-104 SRV-105 SRV-116 SRV-119 SRV-123 SRV-125 SRV-126 SRV-128 SRV-129 SRV-134 SRV-135 SRV-136 SRV-137 SRV-138 SRV-139 SRV-140 SRV-149 SRV-150 SRV-151 SRV-152 SRV-172 SRV-178 "
_NA_SOLARIS=" SRV-018 SRV-020 SRV-023 SRV-024 SRV-029 SRV-031 SRV-072 SRV-078 SRV-079 SRV-080 SRV-090 SRV-097 SRV-101 SRV-103 SRV-104 SRV-105 SRV-116 SRV-119 SRV-123 SRV-125 SRV-126 SRV-128 SRV-129 SRV-136 SRV-137 SRV-138 SRV-139 SRV-140 SRV-149 SRV-150 SRV-151 SRV-152 SRV-172 SRV-178 "
_NA_HPUX=" SRV-018 SRV-020 SRV-023 SRV-024 SRV-029 SRV-031 SRV-072 SRV-078 SRV-079 SRV-080 SRV-090 SRV-097 SRV-101 SRV-103 SRV-104 SRV-105 SRV-116 SRV-119 SRV-123 SRV-125 SRV-126 SRV-128 SRV-129 SRV-134 SRV-135 SRV-136 SRV-137 SRV-138 SRV-139 SRV-140 SRV-149 SRV-150 SRV-151 SRV-152 SRV-172 SRV-178 "
_not_target() {
    local _lst
    case "$OS_FAMILY" in
        LINUX)   _lst="$_NA_LINUX" ;;
        AIX)     _lst="$_NA_AIX" ;;
        SOLARIS) _lst="$_NA_SOLARIS" ;;
        HPUX)    _lst="$_NA_HPUX" ;;
        *)       return 1 ;;
    esac
    case "$_lst" in *" $1 "*) return 0 ;; esac
    return 1
}
_GUIDE_SRV=" SRV-001 SRV-003 SRV-004 SRV-005 SRV-006 SRV-007 SRV-008 SRV-009 SRV-010 SRV-011 SRV-012 SRV-013 SRV-014 SRV-015 SRV-016 SRV-018 SRV-020 SRV-021 SRV-022 SRV-023 SRV-024 SRV-025 SRV-026 SRV-027 SRV-028 SRV-029 SRV-031 SRV-034 SRV-035 SRV-037 SRV-062 SRV-063 SRV-064 SRV-066 SRV-069 SRV-070 SRV-072 SRV-073 SRV-074 SRV-075 SRV-078 SRV-079 SRV-080 SRV-081 SRV-082 SRV-083 SRV-084 SRV-087 SRV-090 SRV-091 SRV-092 SRV-093 SRV-094 SRV-095 SRV-096 SRV-097 SRV-101 SRV-103 SRV-104 SRV-105 SRV-108 SRV-109 SRV-112 SRV-115 SRV-116 SRV-118 SRV-119 SRV-121 SRV-122 SRV-123 SRV-125 SRV-126 SRV-127 SRV-128 SRV-129 SRV-131 SRV-133 SRV-134 SRV-135 SRV-136 SRV-137 SRV-138 SRV-139 SRV-140 SRV-142 SRV-144 SRV-147 SRV-149 SRV-150 SRV-151 SRV-152 SRV-158 SRV-161 SRV-163 SRV-164 SRV-165 SRV-166 SRV-170 SRV-171 SRV-172 SRV-173 SRV-174 SRV-175 SRV-177 SRV-178 SRV-179 "   # 평가기준 제2026-1호 [서버] 평가항목 106개 — 그 외 SRV 코드는 참고 점검(증적만 기록, 결과·집계 제외)
result() {
    # u 모드: SRV 점검 결과는 출력·집계 제외 (증적만)
    if [ "$_MODE" = "u" ]; then case "${1%%|*}" in SRV-*) printf '[참고-u 모드 제외] %s

' "$1" >> "$_EVD"; return 0 ;; esac; fi
    case "${1%%|*}" in SRV-*)
        case "$_GUIDE_SRV" in *" ${1%%|*} "*) ;; *)
            printf '[참고-평가기준 외] %s\n\n' "$1" >> "$_EVD"; return 0 ;; esac ;; esac
    if [ "$_NONROOT" = 1 ]; then
        case "${1%%|*}" in SRV-022|SRV-074|SRV-096|SRV-122)
            case "$1" in *"|양호|"*|*"|취약|"*)
                set -- "${1%%|*}|수동확인|root 권한 아님 - shadow·타 계정 파일 조회 불가로 판정 신뢰 불가, root 로 재점검 필요 (원 판정: ${1#*|})" ;; esac ;; esac
    fi
    local _code="${1%%|*}" _rest="${1#*|}"
    _code="${_code%% *}"
    if _not_target "$_code" && [ "${_rest%%|*}" != "N-A" ]; then
        printf '[평가대상 아님] %s 원 판정: %s
' "$_code" "$1" >> "$_EVD"
        set -- "${_code}|N-A|평가대상 아님 (${OS_FAMILY} 해당 없음 - 평가기준 평가대상 열)"
    fi
    echo "$1"
    case "$1" in
    *"|양호|"*)     _CP=$((_CP+1)) ;;
    *"|취약|"*)     _CF=$((_CF+1)) ;;
    *"|수동확인|"*) _CM=$((_CM+1)) ;;
    *"|N-A|"*)      _CN=$((_CN+1)) ;;
    esac
    printf '[판정] %s\n\n' "$1" >> "$_EVD"
    return 0
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

# 전체 파일시스템 탐색 시 네트워크/가상 파일시스템 제외 (NFS/CIFS/WSL 윈도우 드라이브 등)
_FP="( -fstype nfs -o -fstype nfs4 -o -fstype cifs -o -fstype smbfs -o -fstype 9p -o -fstype drvfs -o -fstype fuse.sshfs -o -fstype autofs -o -fstype proc -o -fstype sysfs ) -prune -o"
# ── 공통 함수 ────────────────────────────────────────────────────
get_perm() {
    local f="$1"; [ -e "$f" ] || [ -L "$f" ] || { echo ""; return; }
    if [ -L "$f" ]; then
        local rf; rf=$(readlink -f "$f" 2>/dev/null)
        [ -z "$rf" ] && rf=$(perl -MCwd -e 'print Cwd::abs_path($ARGV[0])' "$f" 2>/dev/null)
        [ -n "$rf" ] && [ -e "$rf" ] && f="$rf" || { echo ""; return; }
    fi
    case "$OS_FAMILY" in
    BSD)     stat -f "%Lp" "$f" 2>/dev/null ;;
    AIX|SOLARIS|HPUX) ls -lL "$f" 2>/dev/null | awk '{p=substr($1,2);r=0;for(i=1;i<=9;i++){c=substr(p,i,1);if(c!="-")r+=2^(9-i)};printf "%03o\n",r}' ;;
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
    BSD)     stat -f "%Su" "$f" 2>/dev/null ;;
    AIX|SOLARIS|HPUX) ls -lL "$f" 2>/dev/null | awk '{print $3}' ;;
    *)       stat -c "%U" "$f" 2>/dev/null ;;
    esac
}
is_running() {
    local svc="$1"
    command -v systemctl >/dev/null 2>&1 && systemctl is-active "$svc" 2>/dev/null | grep -q "^active" && return 0
    command -v service  >/dev/null 2>&1 && service "$svc" status 2>/dev/null | grep -qiE "running|started" && return 0
    command -v lssrc    >/dev/null 2>&1 && lssrc -s "$svc" 2>/dev/null | grep -qi "active" && return 0
    command -v svcs     >/dev/null 2>&1 && svcs -H "$svc" 2>/dev/null | grep -q "^online" && return 0
    ps -ef 2>/dev/null | grep -v grep | grep -qiw "$svc" && return 0
    command -v ps >/dev/null 2>&1 || { grep -qixF "$svc" /proc/[0-9]*/comm 2>/dev/null && return 0; }
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
# SRV-001: 네트워크 모니터링 서비스 (SNMP 버전)
# ================================================================
# ── 6차 공통 헬퍼 (가이드 판단기준 대조) ──
_perm_over() {
    local p; p=$(printf '%03d' "${1: -3}" 2>/dev/null || echo "$1"); p="${p: -3}"
    [ -z "$p" ] && return 1
    (( (8#$p & ~8#$2 & 8#777) != 0 ))
}
_snmp_confs() {
    local f
    for f in /etc/snmp/snmpd.conf /etc/snmpd.conf /etc/snmpdv3.conf /etc/net-snmp/snmp/snmpd.conf /etc/sma/snmp/snmpd.conf /etc/SnmpAgent.d/snmpd.conf /etc/opt/snmp/snmpd.conf /etc/sfw/snmp/snmpd.conf; do
        [ -f "$f" ] && echo "$f"
    done
}
_named_conf() {
    local c
    for c in /etc/named.conf /etc/bind/named.conf; do
        [ -f "$c" ] || continue
        named-checkconf -p "$c" 2>/dev/null | tr '\n\t' '  ' | sed 's/"//g; s/;/;\n/g' && return
        cat "$c" /etc/bind/named.conf.options /etc/bind/named.conf.local 2>/dev/null | grep -vE '^\s*(//|#)'
        return
    done
}
# ── 8차 공통 헬퍼 (실무 스크립트·UNIX 실장비 결과 대조) ──
_TO=$(command -v timeout 2>/dev/null)
_to() { local s="$1"; shift; if [ -n "$_TO" ]; then "$_TO" "$s" "$@"; else "$@"; fi; }   # timeout 없는 AIX·HP-UX·Solaris 10 은 제한 없이 실행
_aix_default() { awk '/^default:/{f=1;next} /^[^ \t*#]/{f=0} f' /etc/security/user 2>/dev/null; }   # AIX default 스탠자 본문
_aix_attr() { awk -v s="$1" -v a="$2" '/^[^ \t*#][^ \t]*:[ \t]*$/{sub(/:.*/,"");st=$0;next} st==s && $0 ~ ("^[ \t]+" a "[ \t]*=") {sub(/^[^=]*=[ \t]*/,"");sub(/[ \t]+$/,"");print;exit}' "${3:-/etc/security/user}" 2>/dev/null; }
_inetd_on() {   # inetd(AIX·HP-UX·Solaris≤9) / SMF(Solaris 10+) / xinetd 로 기동되는 활성 서비스
    local s
    for s in "$@"; do
        [ -f /etc/inetd.conf ] && awk -v s="$s" '$0!~/^[ \t]*#/ && $1==s {print "inetd.conf:" s; exit}' /etc/inetd.conf 2>/dev/null
        [ "$OS_FAMILY" = "SOLARIS" ] && command -v inetadm >/dev/null 2>&1 && \
            inetadm 2>/dev/null | awk -v s="$s" '$1=="enabled" && $NF ~ ("^svc:/network/" s "([:/]|$)") {print "smf:" $NF}'
        [ -f "/etc/xinetd.d/$s" ] && grep -qiE '^[[:space:]]*disable[[:space:]]*=[[:space:]]*no' "/etc/xinetd.d/$s" 2>/dev/null && echo "xinetd:$s"
    done
}
_listen() { { ss -tln 2>/dev/null || netstat -an 2>/dev/null; } | awk -v p="$1" '/LISTEN/ {for(i=1;i<=NF;i++) if ($i ~ ("[.:]" p "$")) {print; exit}}'; }   # TCP LISTEN (Linux ':23' / UNIX '*.23')
_sshd_cfg() { local c; for c in /etc/ssh/sshd_config /opt/ssh/etc/sshd_config /usr/local/etc/sshd_config /etc/openssh/sshd_config; do [ -f "$c" ] && { echo "$c"; return; }; done; }
_sshd_bin() { local b; for b in $(command -v sshd 2>/dev/null) /usr/sbin/sshd /opt/ssh/sbin/sshd /usr/lib/ssh/sshd /usr/local/sbin/sshd; do [ -x "$b" ] && { echo "$b"; return; }; done; }
_snmp_run() { is_running snmpd && return 0; ps -ef 2>/dev/null | grep -v grep | grep -qE '[/ ](snmpd|snmpdm|snmpdv3ne|snmpdv3e)( |$)'; }   # HP-UX snmpdm, AIX snmpdv3 (cmsnmpd·dsm_sa_snmpd 제외)
_comm() { if [ "$OS_FAMILY" = HPUX ]; then UNIX95=1 ps -e -o comm= 2>/dev/null; else ps -e -o comm= 2>/dev/null; fi | sed 's#.*/##'; }
_ftp_running() { is_running vsftpd || is_running proftpd || is_running pure-ftpd || is_running in.ftpd || is_running ftpd || [ -n "$(_inetd_on ftp)" ] || [ -n "$(_listen 21)" ]; }

check_SRV001() {
    # 평가기준: v2 이용 시(v3 사용 가능 환경) 취약, v3 사용 시 보안레벨 AuthPriv — net-snmp 문법(rocommunity/rwcommunity/com2sec)
    local confs; confs=$(_snmp_confs)
    evd "SRV-001" "for f in $(echo $confs); do echo \"# \$f\"; grep -vE '^\s*(#|\$)' \$f | head -20; done"
    evd "SRV-001" "ps -ef 2>/dev/null | grep -iE '[s]nmp'; lssrc -s snmpd 2>/dev/null; ls -l /var/lib/net-snmp/snmpd.conf /var/lib/snmp/snmpd.conf 2>/dev/null; grep -ciE '^\s*(usmUser|createUser)' /var/lib/net-snmp/snmpd.conf /var/lib/snmp/snmpd.conf 2>/dev/null"
    if [ -z "$confs" ] && ! _snmp_run; then result "SRV-001|N-A|SNMP 미설치/미실행"; return; fi
    _snmp_run || { result "SRV-001|N-A|SNMP 설정 파일은 있으나 snmpd 미실행"; return; }
    local v2 v3 v3weak
    v2=$(cat $confs 2>/dev/null | grep -vE '^\s*#' | grep -iE '^\s*(rocommunity6?|rwcommunity6?|com2sec6?|community)\s|^\s*(get|set)-community-name\s*:' | head -3)
    v3=$(cat $confs 2>/dev/null | grep -vE '^\s*#' | grep -iE '^\s*(rouser|rwuser|createUser)\s|^\s*access\s.*\susm\s|^\s*USM_USER' | head -5)
    v3weak=$(cat $confs 2>/dev/null | grep -vE '^\s*#' | grep -iE '^\s*(rouser|rwuser)\s+\S+(\s+(noauth|auth)\b|\s*$)|^\s*access\s.*\susm\s+(noauth|auth)\b|^\s*VACM_ACCESS\s.*\b(noAuthNoPriv|AuthNoPriv)\b|^\s*USM_USER\s+(\S+\s+){5}(-|none)\b' | head -3)
    if [ -n "$v2" ]; then result "SRV-001|취약|SNMP v1/v2c 사용: $(echo "$v2" | head -1 | awk '{print $1}') (v3 사용 가능 환경에서 v2 이용)"
    elif [ -n "$v3weak" ]; then result "SRV-001|취약|SNMPv3 보안레벨 AuthPriv 미적용: $(echo "$v3weak" | head -1)"
    elif [ -n "$v3" ]; then result "SRV-001|양호|SNMPv3 AuthPriv(priv) 사용"
    else result "SRV-001|수동확인|snmpd 실행 중 - 버전·보안레벨 설정 수동 확인 ($(echo $confs))"; fi
}

# ================================================================
# SRV-003: SNMP 접근통제 (ACL)
# ================================================================
check_SRV003() {
    # 평가기준 판단방법: rocommunity/rwcommunity/com2sec 출발지(source) 제한, 'rocommunity public' 출발지 없음 = 통제 미흡
    local confs; confs=$(_snmp_confs)
    evd "SRV-003" "grep -hiE '^\s*(agentAddress|rocommunity|rwcommunity|com2sec|group|view|access|rouser|rwuser|createUser)' $(echo ${confs:-/dev/null}) 2>/dev/null"
    if [ -z "$confs" ] || ! _snmp_run; then result "SRV-003|N-A|SNMP 미실행"; return; fi
    local open
    open=$(cat $confs 2>/dev/null | grep -vE '^\s*#' | awk 'tolower($1)~/^r[ow]community6?$/ && ($3=="" || $3=="default" || $3=="0.0.0.0/0" || $3=="::/0"){print $1" "$2} tolower($1)~/^com2sec6?$/ && ($3=="default" || $3=="0.0.0.0/0"){print $1" "$2" "$3}' | head -3)
    # HP-UX get/set-community-name 에 IP: 미지정 = 출발지 무제한, AIX community 주소·마스크 0.0.0.0 = 전체 허용
    [ "$OS_FAMILY" = "HPUX" ] && open="${open}$(cat $confs 2>/dev/null | grep -vE '^\s*#' | grep -iE '^\s*(get|set)-community-name\s*:' | grep -viE '\bIP:' | awk '{print $1" "$2}' | head -2)"
    [ "$OS_FAMILY" = "AIX" ] && open="${open}$(cat $confs 2>/dev/null | grep -vE '^\s*#' | awk 'tolower($1)=="community" && (($3=="0.0.0.0"&&$4=="0.0.0.0") || ($5=="0.0.0.0"&&$6=="0.0.0.0")){print $1" "$2}' | head -2)"
    if [ -n "$open" ]; then result "SRV-003|취약|출발지 제한 없는 community: $(echo "$open" | awk '{print $1" "substr($2,1,2)"***"}' | tr '\n' ',' | sed 's/,$//')"
    elif cat $confs 2>/dev/null | grep -vE '^\s*#' | grep -qiE '^\s*(rocommunity|rwcommunity|com2sec|rouser|rwuser|(get|set)-community-name)'; then result "SRV-003|양호|SNMP 접근 출발지 지정 또는 v3 사용자 인증"
    else result "SRV-003|수동확인|SNMP 접근통제 설정 수동 확인 ($(echo $confs))"; fi
}

# ================================================================
# SRV-004: SMTP 서비스 비활성화
# ================================================================
check_SRV004() {
    evd "SRV-004" "ps -ef 2>/dev/null | grep -E 'sendmail|postfix|exim' | grep -v grep"
    evd "SRV-004" "ss -tlnp 2>/dev/null | grep ':25 ' || netstat -tlnp 2>/dev/null | grep ':25 '"
    is_running sendmail || is_running postfix || is_running exim || \
        netstat -tlnp 2>/dev/null | grep -q ":25 " || \
        ss -tlnp 2>/dev/null | grep -q ":25 " && \
        result "SRV-004|수동확인|SMTP 서비스 실행 중 (업무상 필요 여부 확인)" && return
    result "SRV-004|양호|SMTP 서비스 미실행"
}

# ================================================================
# SRV-011: 시스템 관리자 FTP 접속 제한
# ================================================================
check_SRV011() {
    evd "SRV-011" "cat /etc/ftpusers /etc/ftpd/ftpusers /etc/vsftpd/ftpusers /etc/vsftpd.ftpusers 2>/dev/null; grep -vE '^\s*#' /etc/inetd.conf 2>/dev/null | grep -w ftp; inetadm 2>/dev/null | grep -i ftp; lssrc -ls inetd 2>/dev/null | grep -i ftp"
    for f in /etc/ftpusers /etc/ftpd/ftpusers /etc/vsftpd/ftpusers /etc/vsftpd.ftpusers; do
        [ -f "$f" ] || continue
        if grep -q "^root" "$f" 2>/dev/null; then
            result "SRV-011|양호|FTP root 계정 제한 (${f})"
        else
            result "SRV-011|취약|FTP root 제한 미설정 (${f})"
        fi
        return
    done
    _ftp_running || { evd "SRV-011" "ps -ef 2>/dev/null | grep -E 'vsftpd|proftpd|ftpd' | grep -v grep"; result "SRV-011|N-A|FTP 서비스 미실행"; return; }
    result "SRV-011|취약|ftpusers 파일 없음 (root FTP 접속 제한 불가)"
}

# ================================================================
# SRV-013: Anonymous FTP 제한
# ================================================================
check_SRV013() {
    evd "SRV-013" "grep -i anonymous /etc/vsftpd/vsftpd.conf /etc/vsftpd.conf /etc/proftpd/proftpd.conf /etc/proftpd.conf 2>/dev/null; grep '^ftp:' /etc/passwd 2>/dev/null"
    # 평가기준: FTP 미사용 또는 Anonymous 비활성 → 양호
    _ftp_running || { result "SRV-013|양호|FTP 서비스 미사용"; return; }
    local f
    for f in /etc/vsftpd/vsftpd.conf /etc/vsftpd.conf; do
        [ -f "$f" ] || continue
        grep -qiE "^\s*anonymous_enable\s*=\s*YES" "$f" 2>/dev/null && { result "SRV-013|취약|Anonymous FTP 활성화 (${f})"; return; }
        grep -qiE "^\s*anonymous_enable\s*=" "$f" 2>/dev/null || { result "SRV-013|취약|anonymous_enable 미설정 (vsftpd 기본값 YES) (${f})"; return; }
        result "SRV-013|양호|Anonymous FTP 비활성화 (${f})"; return
    done
    for f in /etc/proftpd/proftpd.conf /etc/proftpd.conf; do
        [ -f "$f" ] || continue
        grep -vE '^\s*#' "$f" 2>/dev/null | grep -qi "<Anonymous" && { result "SRV-013|취약|proftpd <Anonymous> 블록 활성 (${f})"; return; }
        result "SRV-013|양호|proftpd Anonymous 미설정 (${f})"; return
    done
    grep -q "^ftp:" /etc/passwd 2>/dev/null && result "SRV-013|취약|ftpd 실행 중이며 ftp(anonymous) 계정 존재" || result "SRV-013|수동확인|FTP 실행 중 - Anonymous 설정 수동 확인"
}

# ================================================================
# SRV-014: NFS 접근통제
# ================================================================
check_SRV014() {
    evd "SRV-014" "ls -l /etc/exports /etc/dfs/dfstab 2>/dev/null; cat /etc/exports /etc/dfs/dfstab 2>/dev/null"
    local exports_file="/etc/exports"
    [ "$OS_FAMILY" = "SOLARIS" ] && exports_file="/etc/dfs/dfstab"
    [ "$OS_FAMILY" = "HPUX" ] && [ -z "$(grep -vE '^\s*(#|$)' /etc/exports 2>/dev/null)" ] && [ -f /etc/dfs/dfstab ] && exports_file="/etc/dfs/dfstab"   # HP-UX 11iv3 share 명령
    evd "SRV-014" "share 2>/dev/null; cat /etc/dfs/sharetab 2>/dev/null; exportfs 2>/dev/null"
    # 평가기준: NFS 비활성화 또는 적절한 접근통제 → 양호
    { [ -f "$exports_file" ] && [ -n "$(grep -vE '^\s*(#|$)' "$exports_file" 2>/dev/null)" ]; } || { result "SRV-014|양호|NFS 공유 미사용 (${exports_file} 설정 없음)"; return; }
    { is_running nfsd || is_running rpc.nfsd || is_running mountd || is_running rpc.mountd || { command -v systemctl >/dev/null 2>&1 && systemctl is-active nfs-server 2>/dev/null | grep -q '^active'; }; } || \
        { result "SRV-014|양호|NFS 서비스 비활성 (${exports_file} 설정은 존재 - 참고)"; return; }
    local bad="" p o
    if [ "$exports_file" = "/etc/dfs/dfstab" ]; then
        bad=$(grep -vE '^\s*(#|$)' "$exports_file" | grep -vE 'rw=|ro=|access=' | head -2)
    else
        bad=$(grep -vE '^\s*(#|$)' "$exports_file" | awk '{ if (NF<2) {print; next} for(i=2;i<=NF;i++){ h=$i; sub(/\(.*/,"",h); if (h=="" || h=="*" || h=="0.0.0.0/0") {print; break} } }' | head -2)
    fi
    p=$(get_perm "$exports_file"); o=$(get_owner "$exports_file")
    { [ "$o" != "root" ] || _perm_over "$p" 644; } && bad="${bad:+$bad / }${exports_file}(${o}:${p})"
    [ -n "$bad" ] && result "SRV-014|취약|NFS 접근통제 미흡: $(echo "$bad" | head -2 | tr '\n' ' ')" || result "SRV-014|양호|NFS 공유 호스트 지정·설정 파일 root 644 이하"
}

# ================================================================
# SRV-015: 불필요 NFS 비활성화
# ================================================================
check_SRV015() {
    evd "SRV-015" "ps -ef 2>/dev/null | grep -E 'nfsd|nfs-server' | grep -v grep"
    is_running nfs || is_running nfsd || is_running nfs-server || \
        is_running nfs-kernel-server && \
        result "SRV-015|수동확인|NFS 서비스 실행 중 (업무상 필요 여부 확인)" && return
    result "SRV-015|양호|NFS 서비스 미실행"
}

# ================================================================
# SRV-016: 불필요 RPC 비활성화
# ================================================================
check_SRV016() {
    # 평가기준 15종: rpc.cmsd, rpc.ttdbserverd, sadmind, rusersd, walld, sprayd, rstatd, rpc.nisd, rexd, rpc.pcnfsd, rpc.statd, rpc.ypupdated, rpc.rquotad, kcms_server, cachefsd (업무상 사용 시 예외)
    evd "SRV-016" "rpcinfo -p 2>/dev/null | head -30; ps -ef 2>/dev/null | grep -E 'rpc\.|sadmind|rusersd|walld|sprayd|rstatd|rexd|kcms|cachefsd' | grep -v grep"
    local s bad="" nfs=""
    for s in rpc.cmsd rpc.ttdbserverd sadmind rusersd rpc.rusersd walld rpc.rwalld sprayd rpc.sprayd rstatd rpc.rstatd rpc.nisd rexd rpc.rexd rpc.pcnfsd rpc.ypupdated kcms_server cachefsd; do
        is_running "$s" && bad="${bad} ${s}"
    done
    for s in rpc.statd rpc.rquotad; do is_running "$s" && nfs="${nfs} ${s}"; done
    local rp; rp=$(rpcinfo -p 2>/dev/null | awk '{print $NF}' | grep -E '^(cmsd|ttdbserverd|sadmind|rusersd|walld|sprayd|rstatd|nisd|rexd|pcnfsd|ypupdated)$' | sort -u | tr '\n' ' ')
    [ -n "$rp" ] && bad="${bad} [rpcinfo:${rp% }]"
    local inet; inet=$(grep -vE '^[[:space:]]*#' /etc/inetd.conf 2>/dev/null | grep -oE 'rpc\.(cmsd|ttdbserverd|rusersd|rwalld|sprayd|rstatd|rexd|pcnfsd|ypupdated)|sadmind|kcms_server|cachefsd' | sort -u | tr '\n' ' ')
    [ -n "$inet" ] && bad="${bad} [inetd.conf:${inet% }]"
    if [ "$OS_FAMILY" = "SOLARIS" ]; then
        inet=$(_inetd_on rpc/rstat rpc/rusers rpc/spray rpc/wall rpc/rex rpc/cde-calendar-manager rpc/cde-ttdbserver | sed -n 's/^smf://p' | tr '\n' ' ')
        [ -n "$inet" ] && bad="${bad} [${inet% }]"
    fi
    if [ -n "$bad" ]; then result "SRV-016|취약|불필요 RPC 서비스 활성:${bad}"
    elif [ -n "$nfs" ]; then result "SRV-016|수동확인|NFS 동반 RPC 서비스 실행:${nfs} - 업무상 사용 여부 확인"
    else result "SRV-016|양호|기준 RPC 서비스(cmsd·ttdbserverd·sadmind 등 15종) 미실행"; fi
}

# ================================================================
# SRV-022: 패스워드 미설정 계정 관리
# ================================================================
check_SRV022() {
    evd "SRV-022" "awk -F: '\$2==\"\"' /etc/shadow 2>/dev/null || awk -F: '\$2==\"\"' /etc/passwd 2>/dev/null"
    case "$OS_FAMILY" in
    AIX)   # AIX 패스워드 파일 = /etc/security/passwd (스탠자 password = 공란)
        no_pw=$(awk '/^[^ \t*#][^ \t]*:[ \t]*$/{sub(/:.*/,"");u=$0;next} /^[ \t]+password[ \t]*=/{v=$0;sub(/^[^=]*=[ \t]*/,"",v);sub(/[ \t]+$/,"",v); if(v=="") print u}' /etc/security/passwd 2>/dev/null | head -5)
        ;;
    HPUX|SOLARIS)
        no_pw=$( { [ -f /etc/shadow ] && awk -F: '$2 == "" {print $1}' /etc/shadow 2>/dev/null; logins -p 2>/dev/null | awk '{print $1"(logins -p)"}'; } | sort -u | head -5)
        ;;
    *)
        [ -f /etc/shadow ] && \
            no_pw=$(awk -F: '$2 == "" {print $1}' /etc/shadow 2>/dev/null | head -5) || \
            no_pw=$(awk -F: '$2 == "" {print $1}' /etc/passwd 2>/dev/null | head -5)
        ;;
    esac
    _pwe=$(awk -F: '$2=="" && $1!="" {print $1"(passwd 필드 공란)"}' /etc/passwd 2>/dev/null | head -5)
    [ -n "$_pwe" ] && no_pw="$(printf '%s\n%s' "$no_pw" "$_pwe" | grep -v '^$')"
    [ -n "$no_pw" ] && result "SRV-022|취약|비밀번호 미설정 계정: $(echo $no_pw | tr '\n' ',')" || \
        result "SRV-022|양호|비밀번호 미설정 계정 없음"
}

# ================================================================
# SRV-025: hosts.equiv / .rhosts 설정 제한
# ================================================================
check_SRV025() {
    evd "SRV-025" "ls -la /etc/hosts.equiv /root/.rhosts /.rhosts 2>/dev/null"
    evd "SRV-025" "cat /etc/hosts.equiv /root/.rhosts 2>/dev/null"
    # 기준: 파일이 없거나 신뢰 호스트 목록만 있으면 양호, '+' 설정·불필요 계정/호스트가 있으면 취약
    local plus="" entries="" f
    for f in /etc/hosts.equiv /.rhosts $(awk -F: '$6!=""&&$6!="/"{print $6"/.rhosts"}' /etc/passwd 2>/dev/null | sort -u); do
        [ -f "$f" ] || continue
        grep -vE '^[[:space:]]*(#|$)' "$f" 2>/dev/null | grep -qE '(^|[[:space:]])\+' && plus="${plus} ${f}"
        [ -n "$(grep -vE '^[[:space:]]*(#|$)' "$f" 2>/dev/null)" ] && entries="${entries} ${f}($(grep -cvE '^[[:space:]]*(#|$)' "$f" 2>/dev/null)줄)"
    done
    if [ -n "$plus" ]; then result "SRV-025|취약|'+' 설정(모든 호스트/계정 신뢰) 존재:${plus}"
    elif [ -n "$entries" ]; then result "SRV-025|수동확인|신뢰 호스트 등록:${entries} - 불필요 계정/호스트 여부 확인"
    else result "SRV-025|양호|hosts.equiv/.rhosts 미존재 또는 설정 없음(주석만)"; fi
}

# ================================================================
# SRV-026: root 원격 접속 제한
# ================================================================
check_SRV026() {
    evd "SRV-026" "grep -i PermitRootLogin /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null; sshd -T 2>/dev/null | grep -i '^permitrootlogin'; ssh -V 2>&1; cat /etc/securetty 2>/dev/null | grep -E '^pts' | head -3"
    case "$OS_FAMILY" in
    AIX)
        # 평가기준(AIX): rlogin 사용 시 root rlogin=true, SSH 사용 시 PermitRootLogin yes → 하나라도 해당하면 취약
        val=$(awk '/^root:/{f=1;next} /^[^ \t*]/{f=0} f&&/rlogin/{sub(/.*=[ \t]*/,"");print;exit}' /etc/security/user 2>/dev/null)
        [ -z "$val" ] && val=$(awk '/^default:/{f=1;next} /^[^ \t*]/{f=0} f&&/rlogin/{sub(/.*=[ \t]*/,"");print;exit}' /etc/security/user 2>/dev/null)
        ssh_root=$(grep -iE "^\s*PermitRootLogin" "$(_sshd_cfg)" 2>/dev/null | awk '{print $2}' | head -1)
        if [ "${val:-true}" != "false" ]; then result "SRV-026|취약|AIX root rlogin=${val:-true(기본)}${ssh_root:+, SSH PermitRootLogin=${ssh_root}}"
        elif [ "${ssh_root,,}" = "yes" ]; then result "SRV-026|취약|AIX SSH PermitRootLogin=yes"
        else result "SRV-026|양호|AIX root rlogin=false, SSH PermitRootLogin=${ssh_root:-미설정(기본)}"; fi ;;
    SOLARIS)
        # 평가기준(Solaris): Telnet — /etc/default/login CONSOLE=/dev/console 없음/주석 이면 취약, SSH — PermitRootLogin yes 취약
        cons=$(grep -v "^#" /etc/default/login 2>/dev/null | grep "^CONSOLE")
        ssh_root=$(grep -iE "^\s*PermitRootLogin" "$(_sshd_cfg)" 2>/dev/null | awk '{print $2}' | head -1)
        if [ -z "$cons" ]; then result "SRV-026|취약|Solaris CONSOLE=/dev/console 미설정 (Telnet root 원격 접속 가능)${ssh_root:+, PermitRootLogin=${ssh_root}}"
        elif [ "${ssh_root,,}" = "yes" ]; then result "SRV-026|취약|Solaris SSH PermitRootLogin=yes"
        else result "SRV-026|양호|Solaris CONSOLE 제한, SSH PermitRootLogin=${ssh_root:-미설정}"; fi ;;
    HPUX)
        # 평가기준(HP-UX): Telnet 사용 시 /etc/securetty 없음·console 주석 → 취약, SSH PermitRootLogin yes → 취약
        local cf tel="" val sb; cf=$(_sshd_cfg); sb=$(_sshd_bin)
        evd "SRV-026" "grep -i PermitRootLogin $cf 2>/dev/null; cat /etc/securetty 2>/dev/null"
        [ -n "$sb" ] && val=$("$sb" -T 2>/dev/null | awk 'tolower($1)=="permitrootlogin"{print $2}')
        [ -z "$val" ] && val=$(grep -iE '^\s*PermitRootLogin' "$cf" 2>/dev/null | awk '{print $2}' | head -1)
        if is_running telnetd || [ -n "$(_inetd_on telnet; _listen 23)" ]; then
            grep -qE '^[[:space:]]*console[[:space:]]*$' /etc/securetty 2>/dev/null || tel="Telnet 사용 중 /etc/securetty console 미설정"
        fi
        if [ -n "$tel" ] || [ "${val,,}" = "yes" ]; then result "SRV-026|취약|HP-UX ${tel}${tel:+, }SSH PermitRootLogin=${val:-미확인} (${cf:-sshd_config 미발견})"
        elif [ -z "$val" ]; then result "SRV-026|수동확인|HP-UX PermitRootLogin 미설정·sshd -T 불가 (${cf:-sshd_config 미발견}) - 기본값 확인(HP-UX Secure Shell 구버전 기본 yes)"
        else result "SRV-026|양호|HP-UX PermitRootLogin=${val}, Telnet root 제한"; fi ;;
    *)
        # 평가기준: SSH는 PermitRootLogin yes 일 때만 취약, Telnet 사용 시 securetty 의 pts 허용 여부
        local src="sshd -T" val=""
        val=$(sshd -T 2>/dev/null | awk 'tolower($1)=="permitrootlogin"{print $2}' | tail -1)
        if [ -z "$val" ]; then
            src="설정파일"
            [ -d /etc/ssh/sshd_config.d ] && val=$(grep -rih "^\s*PermitRootLogin" /etc/ssh/sshd_config.d/ 2>/dev/null | awk '{print $2}' | head -1)
            [ -z "$val" ] && val=$(grep -i "^\s*PermitRootLogin" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' | head -1)
        fi
        local telnet_vuln=""
        if is_running telnetd || is_running in.telnetd || [ -n "$(_inetd_on telnet; _listen 23)" ]; then
            { [ ! -f /etc/securetty ] || grep -qE '^pts' /etc/securetty 2>/dev/null; } && telnet_vuln=" / Telnet 사용 중 securetty pts 허용"
        fi
        if [ -z "$val" ]; then
            local ov; ov=$( { ssh -V 2>&1; sshd -V 2>&1; rpm -q openssh-server 2>/dev/null; dpkg-query -W -f='OpenSSH_${Version}' openssh-server 2>/dev/null; } | grep -oE 'OpenSSH_[0-9]+\.[0-9]+|openssh-server-[0-9]+\.[0-9]+|OpenSSH_1:[0-9]+\.[0-9]+' | head -1 | grep -oE '[0-9]+\.[0-9]+$')
            if [ -n "$ov" ] && [ "${ov%%.*}" -ge 7 ] 2>/dev/null; then val="prohibit-password"; src="OpenSSH ${ov} 기본값"; fi
        fi
        case "${val,,}" in
        yes) result "SRV-026|취약|PermitRootLogin=yes (${src}) - root 원격 접속 허용${telnet_vuln}" ;;
        no|prohibit-password|without-password|forced-commands-only)
            [ -n "$telnet_vuln" ] && result "SRV-026|취약|PermitRootLogin=${val} (${src})${telnet_vuln}" \
                                  || result "SRV-026|양호|PermitRootLogin=${val} (${src})" ;;
        "") [ -n "$telnet_vuln" ] && result "SRV-026|취약|${telnet_vuln# / }" \
                                  || result "SRV-026|수동확인|PermitRootLogin 확인 불가 (sshd -T 실패, 설정 없음, OpenSSH 버전 미확인)" ;;
        *)  result "SRV-026|수동확인|PermitRootLogin=${val} (${src})" ;;
        esac ;;
    esac
}

# ================================================================
# SRV-027: 서비스 접근 IP/포트 제한 (TCP Wrapper / firewall)
# ================================================================
check_SRV027() {
    # 평가기준: 방화벽·tcp-wrapper·3rd-party 로 서비스 접근통제 — 규칙 유무로 판단, 없으면 상위 방화벽 등 확인(수동확인)
    evd "SRV-027" "grep -vE '^\s*(#|\$)' /etc/hosts.allow /etc/hosts.deny 2>/dev/null; grep -vE '^\s*(#|\$)' /var/adm/inetd.sec 2>/dev/null; ipfstat -io 2>/dev/null | head -20; inetadm -p 2>/dev/null | grep tcp_wrappers; lsfilt -a 2>/dev/null | head -20"
    evd "SRV-027" "firewall-cmd --list-all 2>/dev/null; ufw status numbered 2>/dev/null; iptables -S 2>/dev/null | head -40; nft list ruleset 2>/dev/null | head -40"
    local tw=0 fw="" n
    [ -n "$(grep -vE '^\s*(#|$)' /etc/hosts.allow /etc/hosts.deny 2>/dev/null)" ] && tw=1
    if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state 2>/dev/null | grep -q running; then
        n=$( { firewall-cmd --list-rich-rules 2>/dev/null; firewall-cmd --list-sources 2>/dev/null | tr ' ' '\n'; } | grep -c . ); fw="firewalld(zone=$(firewall-cmd --get-default-zone 2>/dev/null), rich/source ${n})"
    elif command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
        n=$(ufw status numbered 2>/dev/null | grep -c "^\["); [ "$n" -gt 0 ] && fw="ufw(${n} rules)"
    fi
    if [ -z "$fw" ]; then
        n=$(iptables -S 2>/dev/null | grep -c '^-A'); [ "${n:-0}" -gt 0 ] && fw="iptables(${n} rules)"
        [ -z "$fw" ] && { n=$(nft list ruleset 2>/dev/null | grep -cE '^\s+(ip|tcp|udp|iif|oif|meta|ct)\s'); [ "${n:-0}" -gt 0 ] && fw="nftables(${n} rules)"; }
        [ -z "$fw" ] && iptables -S 2>/dev/null | grep -qE '^-P INPUT (DROP|REJECT)' && fw="iptables(INPUT 기본 DROP)"
    fi
    if [ -n "$fw" ] || [ $tw -eq 1 ]; then result "SRV-027|양호|접근통제 규칙 존재 (tcp-wrapper=$([ $tw -eq 1 ] && echo 설정 || echo 없음), 방화벽=${fw:-없음})"
    else result "SRV-027|수동확인|호스트 방화벽·tcp-wrapper 규칙 없음 - 상위 방화벽·3rd-party 접근통제 여부 확인 (미통제 시 취약)"; fi
}

# ================================================================
# SRV-028: 원격 터미널 접속 타임아웃
# ================================================================
check_SRV028() {
    evd "SRV-028" "grep -rh 'TMOUT\\|tmout' /etc/profile /etc/bashrc /etc/bash.bashrc /etc/profile.d/ /root/.bashrc /root/.profile 2>/dev/null | grep -v '^#'"
    tmout=""
    for f in /etc/profile /etc/bashrc /etc/bash.bashrc /etc/environment \
              /root/.bashrc /root/.profile /etc/profile.d/*.sh; do
        [ -f "$f" ] || continue
        t=$(grep -h "TMOUT\|tmout" "$f" 2>/dev/null | grep -v "^\s*#" | grep -oE "[0-9]+" | head -1)
        [ -n "$t" ] && tmout=$t && break
    done
    case "$OS_FAMILY" in
    SOLARIS) [ -z "$tmout" ] && tmout=$(grep "^TIMEOUT" /etc/default/login 2>/dev/null | cut -d= -f2 | tr -d ' ') ;;
    AIX)     [ -z "$tmout" ] && tmout=$(grep "^TMOUT\|^tmout" /etc/profile /etc/environment 2>/dev/null | grep -oE "[0-9]+" | head -1) ;;
    esac
    # 평가기준: 900초(15분) 이하 양호 (내부 규정이 더 짧으면 그 기준 적용 - 수동 확인)
    if [ -z "$tmout" ] || [ "$tmout" = "0" ]; then
        result "SRV-028|취약|TMOUT 미설정 (세션 타임아웃 없음)"
    elif [ "$tmout" -le 900 ] 2>/dev/null; then
        result "SRV-028|양호|TMOUT=${tmout}초 (900초 이하, 내부 규정이 더 짧으면 그 기준으로 확인)"
    else
        result "SRV-028|취약|TMOUT=${tmout}초 (900초 초과)"
    fi
}

# ================================================================
# SRV-034: 불필요한 서비스 비활성화 (finger/chargen/daytime 등)
# ================================================================
check_SRV034() {
    # 평가기준(LINUX 등): 취약한 버전의 automountd 서비스가 불필요하게 활성화 / Solaris 는 dmi 서비스 추가
    evd "SRV-034" "ps -ef 2>/dev/null | grep -E 'autofs|automount|dmispd|snmpXdmid' | grep -v grep; grep -v '^#' /etc/inetd.conf 2>/dev/null | grep -i automount; systemctl is-active autofs 2>/dev/null; automount -V 2>/dev/null | head -1"
    local am="" dmi=""
    { is_running automount || is_running automountd || is_running autofs || grep -v '^#' /etc/inetd.conf 2>/dev/null | grep -qi automount || \
      { command -v systemctl >/dev/null 2>&1 && systemctl is-active autofs 2>/dev/null | grep -q '^active'; }; } && am="automount($(automount -V 2>/dev/null | head -1 | grep -oE '[0-9]+(\.[0-9]+)+' || echo 버전미확인))"
    [ "$OS_FAMILY" = "SOLARIS" ] && { is_running dmispd || is_running snmpXdmid; } && dmi="dmi(dmispd/snmpXdmid)"
    if [ -n "$dmi" ]; then result "SRV-034|취약|DMI 서비스 활성: ${dmi}${am:+ / $am}"
    elif [ -n "$am" ]; then result "SRV-034|수동확인|${am} 활성 - 업무상 필요 여부·취약 버전 여부 확인"
    else result "SRV-034|양호|automountd 서비스 비활성"; fi
}

# ================================================================
# SRV-035: 취약 서비스 비활성화 (telnet 등)
# ================================================================
check_SRV035() {
    # 평가기준: tftp·talk·ntalk / finger / rexec·rlogin·rsh / echo·discard·daytime·chargen / NIS·NIS+ (tftp 는 백업솔루션 필수 시 예외)
    evd "SRV-035" "grep -vE '^\s*#' /etc/inetd.conf 2>/dev/null | grep -E 'tftp|talk|finger|exec|login|shell|echo|discard|daytime|chargen'; ls /etc/xinetd.d 2>/dev/null; ps -ef 2>/dev/null | grep -E 'tftp|talk|finger|rexec|rlogin|rsh|ypserv|ypbind|yppasswdd|nisd' | grep -v grep"
    local found="" tftp="" s
    for s in talkd in.talkd ntalkd in.ntalkd fingerd in.fingerd rexecd in.rexecd rlogind in.rlogind rshd in.rshd ypserv ypbind yppasswdd rpc.nisd; do
        is_running "$s" && found="${found} ${s}"
    done
    { is_running tftpd || is_running in.tftpd || ss -uln 2>/dev/null | grep -q ':69 '; } && tftp="tftp"
    if command -v systemctl >/dev/null 2>&1; then
        for s in chargen daytime discard echo rsh rlogin rexec finger tftp talk ntalk; do
            systemctl is-active "${s}.socket" 2>/dev/null | grep -q "^active" && { [ "$s" = tftp ] && tftp="tftp" || found="${found} ${s}.socket"; }
        done
    fi
    local act; act=$(grep -vE '^\s*#' /etc/inetd.conf 2>/dev/null | awk '{print $1}' | grep -E '^(tftp|talk|ntalk|finger|exec|login|shell|echo|discard|daytime|chargen)$' | tr '\n' ' ')
    for s in $act; do [ "$s" = tftp ] && tftp="tftp" || found="${found} [inetd:${s}]"; done
    if [ "$OS_FAMILY" = "SOLARIS" ]; then
        for s in $(_inetd_on tftp talk finger login shell rexec echo discard daytime chargen | sed -n 's/^smf://p'); do
            case "$s" in */tftp/*|*/tftp:*) tftp="tftp" ;; *) found="${found} [smf:${s#svc:/network/}]" ;; esac
        done
        evd "SRV-035" "inetadm 2>/dev/null | grep -E 'tftp|talk|finger|login|shell|rexec|echo|discard|daytime|chargen'"
    fi
    if [ -d /etc/xinetd.d ]; then
        for s in /etc/xinetd.d/*; do
            [ -f "$s" ] || continue
            grep -qiE 'disable\s*=\s*no' "$s" 2>/dev/null || continue
            case "$(basename "$s")" in tftp*) tftp="tftp" ;; chargen*|daytime*|discard*|echo*|rsh|rlogin|rexec|finger|talk|ntalk) found="${found} [xinetd:$(basename "$s")]" ;; esac
        done
    fi
    if [ -n "$found" ]; then result "SRV-035|취약|취약 서비스 활성:${found}${tftp:+ / tftp}"
    elif [ -n "$tftp" ]; then result "SRV-035|수동확인|tftp 서비스 활성 - OS 백업솔루션 필수 사용 여부 확인 (불필요 시 취약)"
    else result "SRV-035|양호|tftp·talk·finger·r계열·echo/chargen 등·NIS 서비스 미실행"; fi
}

# ================================================================
# SRV-062: DNS 정보 노출 방지 (버전 노출)
# ================================================================
check_SRV062() {
    is_running named || { evd "SRV-062" "ps -ef 2>/dev/null | grep named | grep -v grep"; result "SRV-062|N-A|DNS 서비스 미실행"; return; }
    local nc; nc=$(_named_conf)
    evd "SRV-062" "echo '$(echo "$nc" | grep -iE 'version' | head -3)'"
    [ -z "$nc" ] && { result "SRV-062|수동확인|named.conf 위치 확인 필요"; return; }
    echo "$nc" | grep -qiE '(^|[[:space:]])version\s+("[^0-9"]*"|[^0-9;"]*)\s*;' && result "SRV-062|양호|DNS 버전 노출 차단 (version 문자열 대체)" || result "SRV-062|취약|DNS 버전 노출 차단 미설정 (version \"none\" 권고)"
}

# ================================================================
# SRV-066: DNS Zone Transfer 제한
# ================================================================
check_SRV066() {
    is_running named || { evd "SRV-066" "ps -ef 2>/dev/null | grep named | grep -v grep"; result "SRV-066|N-A|DNS 미실행"; return; }
    local nc; nc=$(_named_conf)
    evd "SRV-066" "echo '$(echo "$nc" | grep -iE 'allow-transfer' | head -5)'"
    [ -z "$nc" ] && { result "SRV-066|수동확인|named.conf 수동 확인"; return; }
    if echo "$nc" | grep -qiE 'allow-transfer\s*\{\s*any\s*;'; then result "SRV-066|취약|allow-transfer { any; } - 모든 호스트 Zone Transfer 허용"
    elif echo "$nc" | grep -qiE 'allow-transfer'; then result "SRV-066|양호|Zone Transfer 허용 대상 지정: $(echo "$nc" | grep -ioE 'allow-transfer\s*\{[^}]*\}' | head -1)"
    else result "SRV-066|취약|allow-transfer 미설정 (Zone Transfer 제한 없음)"; fi
}

# ================================================================
# SRV-063: DNS Recursive Query 제한 설정 여부
# ================================================================
check_SRV063() {
    is_running named || { evd "SRV-063" "ps -ef 2>/dev/null | grep named | grep -v grep"; result "SRV-063|양호|DNS 서비스 미실행"; return; }
    local nc; nc=$(_named_conf)
    evd "SRV-063" "echo '$(echo "$nc" | grep -iE 'recursion|allow-recursion|allow-query-cache' | head -5)'"
    [ -z "$nc" ] && { result "SRV-063|수동확인|named.conf 위치 확인 필요"; return; }
    # 평가기준: Recursive query 금지 또는 신뢰 호스트만 허용 → 양호 (BIND 9.4+ 기본 allow-recursion 은 localnets/localhost)
    if echo "$nc" | grep -qiE 'recursion\s+no\s*;'; then result "SRV-063|양호|recursion no"
    elif echo "$nc" | grep -qiE 'allow-recursion\s*\{\s*any\s*;'; then result "SRV-063|취약|allow-recursion { any; } - 모든 호스트 재귀 질의 허용"
    elif echo "$nc" | grep -qiE 'allow-recursion'; then result "SRV-063|양호|allow-recursion 신뢰 호스트 한정: $(echo "$nc" | grep -ioE 'allow-recursion\s*\{[^}]*\}' | head -1)"
    else result "SRV-063|수동확인|recursion 허용 대상 미지정 (BIND 기본 localnets·localhost) - 신뢰 호스트 한정 여부 확인"; fi
}

# ================================================================
# SRV-064: DNS 서비스 보안 패치 적용 여부
# ================================================================
check_SRV064() {
    is_running named || { result "SRV-064|양호|DNS 서비스 미실행"; return; }
    evd "SRV-064" "named -v 2>/dev/null; rpm -qa bind 2>/dev/null; dpkg -l bind9 2>/dev/null | tail -1"
    named_ver=$(named -v 2>/dev/null | grep -oE 'BIND [0-9][^ ]*' | head -1)
    if [ -n "$named_ver" ]; then
        result "SRV-064|수동확인|DNS 버전: ${named_ver} - 최신 보안 패치 적용 여부 수동 확인"
    else
        result "SRV-064|수동확인|DNS 서비스 실행 중 - 버전 및 보안 패치 수동 확인"
    fi
}

# ================================================================
# SRV-069: 비밀번호 관리정책 (최대 사용기간)
# ================================================================
_pw_policy() {
    # OS별 비밀번호 정책 (최소 길이 / 요구 문자 종류 수 / 출처) 출력: "<minlen> <classes> <label>"
    local ml=0 cls=0 who k
    case "$OS_FAMILY" in
    AIX)
        ml=$(_aix_default | grep -w "minlen" | grep -oE '[0-9]+' | head -1)
        cls=$(_aix_default | grep -wE "minalpha|minother|mindigit|minspecialchar" | grep -cE '= *[1-9]')
        who="AIX" ;;
    SOLARIS)
        # 평가기준 판단방법: MINALPHA 기본 2, MINNONALPHA(숫자+특수) 기본 1 — MINDIGIT·MINSPECIAL 과 함께 사용 불가
        local a u l d s n
        _sv() { sed -n "s/^$1=\([0-9]*\).*/\1/p" /etc/default/passwd 2>/dev/null | tail -1; }
        ml=$(_sv PASSLENGTH); ml=${ml:-6}
        a=$(_sv MINALPHA); u=$(_sv MINUPPER); l=$(_sv MINLOWER); d=$(_sv MINDIGIT); s=$(_sv MINSPECIAL); n=$(_sv MINNONALPHA)
        { [ "${a:-2}" -ge 1 ] || [ "${u:-0}" -ge 1 ] || [ "${l:-0}" -ge 1 ]; } 2>/dev/null && cls=1
        if [ -n "$d$s" ]; then [ "${d:-0}" -ge 1 ] 2>/dev/null && cls=$((cls+1)); [ "${s:-0}" -ge 1 ] 2>/dev/null && cls=$((cls+1))
        else [ "${n:-1}" -ge 1 ] 2>/dev/null && cls=$((cls+1)); fi
        who="Solaris" ;;
    HPUX)
        ml=$(grep -E "^\s*MIN_PASSWORD_LENGTH" /etc/default/security 2>/dev/null | cut -d= -f2 | tr -d ' ')
        for k in PASSWORD_MIN_LOWER_CASE_CHARS PASSWORD_MIN_UPPER_CASE_CHARS PASSWORD_MIN_DIGIT_CHARS PASSWORD_MIN_SPECIAL_CHARS; do
            grep -qE "^\s*${k}=[1-9]" /etc/default/security 2>/dev/null && cls=$((cls+1)); done
        who="HP-UX" ;;
    *)
        local pam_files f line="" conf="" c neg=0 mcl
        pam_files=$(get_pam_files)
        for f in $pam_files; do
            [ -f "$f" ] || continue
            line=$(grep -v "^\s*#" "$f" 2>/dev/null | grep -iE "pam_pwquality|pam_cracklib" | head -1)
            [ -n "$line" ] && break
        done
        [ -f /etc/security/pwquality.conf ] && conf=$(grep -vhE "^\s*(#|$)" /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf 2>/dev/null)
        if [ -z "$line" ] && [ -z "$conf" ]; then echo "0 0 모듈없음"; return; fi
        _pwv() { local x; x=$(echo "$line" | grep -oE "(^|\s)$1=-?[0-9]+" | tail -1 | cut -d= -f2)
                 [ -z "$x" ] && x=$(echo "$conf" | grep -E "^\s*$1\s*=" | tail -1 | grep -oE -- '-?[0-9]+'); echo "$x"; }
        ml=$(_pwv minlen); ml=${ml:-9}
        mcl=$(_pwv minclass); mcl=${mcl:-0}
        for c in dcredit ucredit lcredit ocredit; do [ "$(_pwv $c)" -lt 0 ] 2>/dev/null && neg=$((neg+1)); done
        [ "$neg" -gt "$mcl" ] && mcl=$neg
        cls=$mcl; who="pwquality" ;;
    esac
    echo "${ml:-0} ${cls:-0} ${who}"
}

_pw_policy_ok() {  # 평가기준 복잡도: 2종 10자 이상 또는 3종 8자 이상
    local ml="$1" cls="$2"
    { [ "$cls" -ge 3 ] && [ "$ml" -ge 8 ]; } 2>/dev/null || { [ "$cls" -ge 2 ] && [ "$ml" -ge 10 ]; } 2>/dev/null
}

check_SRV069() {
    # 평가기준: 비밀번호 관련 정책(2종 10자/3종 8자 복잡도 + 변경 기간 90일 이하)이 설정되어 있을 경우 양호
    evd "SRV-069" "grep -E '^PASS_MAX_DAYS|^MAXWEEKS|^maxage|PASSWORD_MAXDAYS|MIN_PASSWORD_LENGTH' /etc/login.defs /etc/default/passwd /etc/security/user /etc/default/security 2>/dev/null; grep -vE '^\s*(#|$)' /etc/security/pwquality.conf 2>/dev/null"
    local days="" src="" issues="" pol ml cls who
    case "$OS_FAMILY" in
    AIX)     local w; w=$(_aix_default | grep -w "maxage" | grep -oE '[0-9]+' | head -1)
             [ -n "$w" ] && days=$((w*7)); src="maxage=${w:-미설정}주" ;;
    SOLARIS) local w; w=$(grep "^MAXWEEKS" /etc/default/passwd 2>/dev/null | cut -d= -f2 | tr -d ' ')
             [ -n "$w" ] && days=$((w*7)); src="MAXWEEKS=${w:-미설정}주" ;;
    HPUX)    days=$(grep -E "^\s*PASSWORD_MAXDAYS" /etc/default/security 2>/dev/null | cut -d= -f2 | tr -d ' '); src="PASSWORD_MAXDAYS=${days:-미설정}" ;;
    *)       days=$(grep "^PASS_MAX_DAYS" /etc/login.defs 2>/dev/null | awk '{print $2}'); src="PASS_MAX_DAYS=${days:-미설정}" ;;
    esac
    if [ -z "$days" ] || [ "$days" = "0" ]; then issues="변경 기간 미설정(${src})"
    elif [ "$days" -gt 90 ] 2>/dev/null; then issues="변경 기간 ${days}일 초과(${src})"; fi
    pol=$(_pw_policy); ml=${pol%% *}; cls=$(echo "$pol" | awk '{print $2}'); who=$(echo "$pol" | awk '{print $3}')
    if [ "$who" = "모듈없음" ]; then issues="${issues:+$issues / }복잡도 모듈(pam_pwquality/pam_cracklib) 미설정"
    else _pw_policy_ok "$ml" "$cls" || issues="${issues:+$issues / }복잡도 정책 미달(${who}: 최소 ${ml}자, ${cls}종)"; fi
    if [ "$OS_FAMILY" = "LINUX" ] && [ -r /etc/shadow ]; then
        local _acc; _acc=$(awk -F: 'NR==FNR{if($7!~/(nologin|false|sync|shutdown|halt)$/)sh[$1]=1;next} ($1 in sh) && $2!~/^[!*]/ && ($5=="" || $5+0>90){print $1"("($5==""?"미설정":$5)")"}' /etc/passwd /etc/shadow 2>/dev/null | head -5 | tr '\n' ' ')
        [ -n "$_acc" ] && issues="${issues:+$issues / }기존 계정 최대 사용기간 90일 초과/미설정(chage): ${_acc}"
    fi
    if [ -n "$issues" ]; then result "SRV-069|취약|${issues} - 기준: 2종 10자/3종 8자 이상, 변경 기간 90일 이하"
    else result "SRV-069|양호|비밀번호 정책 설정 (${src}, ${who}: 최소 ${ml}자·${cls}종)"; fi
}

# ================================================================
# SRV-070: 취약한 패스워드 저장 방식
# ================================================================
check_SRV070() {
    evd "SRV-070" "awk -F: '{print \$1,substr(\$2,1,4)}' /etc/shadow 2>/dev/null | head -20; grep -E '^ENCRYPT_METHOD' /etc/login.defs 2>/dev/null; grep -E '^CRYPT_(DEFAULT|ALGORITHMS)' /etc/security/policy.conf /etc/default/security 2>/dev/null; grep -E '^[[:space:]]*pwd_algorithm' /etc/security/login.cfg 2>/dev/null; ls -ld /tcb/files/auth 2>/dev/null"
    local des="" alg weak
    case "$OS_FAMILY" in
    AIX)
        # 판단방법(AIX): login.cfg pwd_algorithm 이 112비트 이상 해시인지, /etc/security/passwd 해시 형식
        alg=$(_aix_attr usw pwd_algorithm /etc/security/login.cfg)
        des=$(awk '/^[^ \t*#][^ \t]*:[ \t]*$/{sub(/:.*/,"");u=$0;next} /^[ \t]+password[ \t]*=/{v=$0;sub(/^[^=]*=[ \t]*/,"",v);sub(/[ \t]+$/,"",v); if(v!="" && v!="*" && v!~/^\{/) print u}' /etc/security/passwd 2>/dev/null | head -5 | tr '\n' ' ')
        if [ -n "$des" ]; then result "SRV-070|취약|AIX crypt(DES) 해시 계정: ${des}(pwd_algorithm=${alg:-미설정=crypt})"
        elif [ -z "$alg" ] || [ "$alg" = "crypt" ]; then result "SRV-070|취약|AIX pwd_algorithm 미설정(crypt, 112비트 미만)"
        else result "SRV-070|양호|AIX pwd_algorithm=${alg}"; fi ;;
    HPUX)
        if [ -d /tcb/files/auth ] || [ -f /etc/shadow ]; then
            alg=$(grep -E '^[[:space:]]*CRYPT_DEFAULT' /etc/default/security 2>/dev/null | cut -d= -f2 | tr -d ' ')
            case "$alg" in __unix__|"") result "SRV-070|수동확인|HP-UX $( [ -d /tcb/files/auth ] && echo 'Trusted Mode' || echo shadow ) 사용, CRYPT_DEFAULT=${alg:-미설정} - 해시 강도 확인" ;;
                           *) result "SRV-070|양호|HP-UX shadow/Trusted Mode + CRYPT_DEFAULT=${alg}" ;; esac
        else result "SRV-070|취약|HP-UX shadow·Trusted Mode 미사용 (/etc/passwd 에 해시 저장)"; fi ;;
    *)
        if [ ! -f /etc/shadow ]; then
            result "SRV-070|취약|/etc/shadow 없음 (평문 패스워드 저장 가능)"
            return
        fi
        # DES(crypt 13자), MD5($1$) 는 취약 / SHA256($5$)·SHA512($6$)·bcrypt($2*)·yescrypt($y$) 양호
        des=$(awk -F: '$2!="" && $2!~/^(\$|\*|!|NP$|x$|LK)/ && length($2)==13 {print $1}' /etc/shadow 2>/dev/null | head -5 | tr '\n' ' ')
        weak=$(awk -F: '$2 ~ /^\$1\$/ {print $1}' /etc/shadow 2>/dev/null | head -5)
        if [ -n "$des" ]; then result "SRV-070|취약|DES(crypt) 해시 계정: ${des}$( [ "$OS_FAMILY" = SOLARIS ] && echo "(CRYPT_DEFAULT=$(sed -n 's/^CRYPT_DEFAULT=//p' /etc/security/policy.conf 2>/dev/null))")"
        elif [ -n "$weak" ]; then result "SRV-070|취약|MD5 해시 계정 존재: $(echo $weak | tr '\n' ',')"
        else result "SRV-070|양호|shadow 사용, SHA256/SHA512 등 안전한 해시 (DES·MD5 없음)"; fi ;;
    esac
}

# ================================================================
# SRV-073: 관리자 그룹 불필요 사용자 제거
# ================================================================
check_SRV073() {
    # 평가기준: 관리자 그룹에 '불필요한' 계정 존재 여부 (인원 수 기준 없음) → 구성원 목록 증적 + 인터뷰
    evd "SRV-073" "grep -E '^(root|wheel|sudo|admin|system):' /etc/group 2>/dev/null"
    local grps="root wheel sudo admin"
    [ "$OS_FAMILY" = "BSD" ] && grps="wheel operator"
    [ "$OS_FAMILY" = "AIX" ] && grps="system security"
    local info="" members
    for grp in $grps; do
        members=$(grep "^${grp}:" /etc/group 2>/dev/null | cut -d: -f4)
        [ -n "$members" ] && info="${info} ${grp}:[${members}]"
    done
    if [ -z "$info" ]; then
        result "SRV-073|양호|관리자 그룹에 추가 구성원 없음"
    else
        result "SRV-073|수동확인|관리자 그룹 구성원:${info} - 불필요 계정 여부 확인"
    fi
}

# ================================================================
# SRV-074: 불필요/미관리 계정 제거
# ================================================================
check_SRV074() {
    # 평가기준: 로그인 가능한 계정별 분기(90일) 내 로그인 기록 + 비밀번호 변경 여부 (업무상 사용 여부 확인 필요)
    evd "SRV-074" "awk -F: '\$7 !~ /(nologin|false|sync|shutdown|halt)\$/ {print \$1,\$3,\$7}' /etc/passwd 2>/dev/null; lastlog 2>/dev/null | head -30"
    local today; today=$(( $(date +%s) / 86400 ))
    local vuln="" manual="" user sh pw lchg ll lsec now; now=$(date +%s)
    [ "$OS_FAMILY" = "AIX" ] && evd "SRV-074" "lsuser -a time_last_login lastupdate account_locked ALL 2>/dev/null"
    while IFS=: read -r user _ _ _ _ _ sh; do
        case "$sh" in *nologin|*false|*/sync|*/shutdown|*/halt|"") continue ;; esac
        pw=$(awk -F: -v u="$user" '$1==u{print $2}' /etc/shadow 2>/dev/null)
        case "$pw" in "!"*|"*"*) continue ;; esac   # 잠긴 계정(로그인 불가) 제외
        lchg=$(awk -F: -v u="$user" '$1==u{print $3}' /etc/shadow 2>/dev/null)
        local why=""
        case "$OS_FAMILY" in
        AIX)   # lsuser epoch: time_last_login(마지막 로그인), lastupdate(비밀번호 변경)
            [ "$(lsuser -a account_locked "$user" 2>/dev/null | sed -n 's/.*account_locked=//p')" = "true" ] && continue
            ll=$(lsuser -a time_last_login "$user" 2>/dev/null | sed -n 's/.*time_last_login=//p')
            lsec=$(lsuser -a lastupdate "$user" 2>/dev/null | sed -n 's/.*lastupdate=//p')
            if [ -z "$ll" ]; then why="로그인 기록 없음"
            elif [ $(( (now-ll)/86400 )) -gt 90 ] 2>/dev/null; then why="최근 로그인 $(( (now-ll)/86400 ))일 전"; fi
            [ -n "$lsec" ] && [ $(( (now-lsec)/86400 )) -gt 90 ] 2>/dev/null && why="${why:+$why, }비밀번호 변경 $(( (now-lsec)/86400 ))일 전"
            lchg="" ;;
        SOLARIS|HPUX)   # lastlog 없음 — last 출력은 연도 미표기라 로그인 일자는 증적으로 수동 확인
            manual="${manual} ${user}" ;;
        *)
            ll=$(lastlog -u "$user" 2>/dev/null | awk 'NR==2')
            [ -z "$ll" ] && command -v lastlog2 >/dev/null 2>&1 && ll=$(lastlog2 -u "$user" 2>/dev/null | awk 'NR==2')
            if [ -z "$ll" ] && ! command -v lastlog >/dev/null 2>&1 && ! command -v lastlog2 >/dev/null 2>&1; then manual="${manual} ${user}"
            elif [ -z "$ll" ] || echo "$ll" | grep -q "Never logged in"; then why="로그인 기록 없음"
            else
                lsec=$(date -d "$(echo "$ll" | awk '{for(i=NF-5;i<=NF;i++) printf $i" "}')" +%s 2>/dev/null)
                [ -n "$lsec" ] && [ $(( today - lsec/86400 )) -gt 90 ] && why="최근 로그인 $(( today - lsec/86400 ))일 전"
            fi ;;
        esac
        if [ -n "$lchg" ] && [ "$lchg" -gt 0 ] 2>/dev/null && [ $(( today - lchg )) -gt 90 ]; then why="${why:+$why, }비밀번호 변경 $(( today - lchg ))일 전"; fi
        [ -n "$why" ] && vuln="${vuln} ${user}(${why})"
    done < /etc/passwd
    [ -n "$manual" ] && evd "SRV-074" "for u in $(echo $manual); do last -1 \$u 2>/dev/null | head -1; done"
    if [ -n "$vuln" ]; then result "SRV-074|취약|분기 내 로그인/비밀번호 변경 없는 로그인 가능 계정:${vuln} - 업무상 사용 여부 확인"
    elif [ -n "$manual" ]; then result "SRV-074|수동확인|로그인 기록 자동 조회 불가 계정:${manual} - last 증적으로 90일 내 로그인 확인"
    else result "SRV-074|양호|로그인 가능 계정 모두 분기 내 로그인 및 비밀번호 변경"; fi
}

# ================================================================
# SRV-075: 비밀번호 복잡도
# ================================================================
check_SRV075() {
    # 평가기준: 모든 계정이 복잡도(2종 10자 / 3종 8자) 만족 — 판단방법: 빈 비밀번호 계정 확인 + 크랙
    evd "SRV-075" "grep -v '^#' /etc/security/pwquality.conf 2>/dev/null | grep -v '^$'"
    evd "SRV-075" "grep -i 'pam_pwquality\\|pam_cracklib' /etc/pam.d/system-auth /etc/pam.d/password-auth /etc/pam.d/common-password 2>/dev/null"
    local empty pol ml cls who
    empty=$(awk -F: '($2==""){print $1}' /etc/shadow 2>/dev/null | tr '\n' ' ')
    [ -n "$empty" ] && { result "SRV-075|취약|비밀번호 미설정 계정: ${empty}"; return; }
    pol=$(_pw_policy); ml=${pol%% *}; cls=$(echo "$pol" | awk '{print $2}'); who=$(echo "$pol" | awk '{print $3}')
    if [ "$who" = "모듈없음" ]; then result "SRV-075|취약|비밀번호 복잡도 모듈(pam_pwquality/pam_cracklib) 미설정"
    elif _pw_policy_ok "$ml" "$cls"; then
        result "SRV-075|수동확인|${who} 정책 기준 충족 (최소 ${ml}자, 문자 종류 ${cls}종 이상) - 기존 계정 비밀번호 복잡도 만족 여부(크랙) 확인"
    else
        result "SRV-075|취약|${who} 정책 기준 미달 (최소 ${ml}자, 문자 종류 ${cls}종 요구) - 기준: 2종 10자 이상 또는 3종 8자 이상"
    fi
}

_srv075_judge() {
    local who="$1" ml="$2" cls="$3"
    if { [ "$cls" -ge 3 ] && [ "$ml" -ge 8 ]; } 2>/dev/null || { [ "$cls" -ge 2 ] && [ "$ml" -ge 10 ]; } 2>/dev/null; then
        result "SRV-075|수동확인|${who} 정책 기준 충족 (최소 ${ml}자, 문자 종류 ${cls}종 이상) - 기존 계정 비밀번호 복잡도 만족 여부(크랙) 확인"
    else
        result "SRV-075|취약|${who} 정책 기준 미달 (최소 ${ml}자, 문자 종류 ${cls}종 요구) - 기준: 2종 10자 이상 또는 3종 8자 이상"
    fi
}

# ================================================================
# SRV-081: Crontab 설정파일 권한
# ================================================================
check_SRV081() {
    # 평가기준: crontab 명령 750 이하 / crontab 파일 others 읽기·쓰기 없음 / at·cron allow·deny 소유자 root·640 이하
    evd "SRV-081" "ls -alL /usr/bin/crontab /etc/cron.allow /etc/cron.deny /etc/at.allow /etc/at.deny 2>/dev/null; ls -alL /var/spool/cron/crontabs/ /var/spool/cron/ 2>/dev/null"
    local vuln="" p o f
    for f in /usr/bin/crontab /bin/crontab; do
        [ -f "$f" ] || continue
        p=$(get_perm "$f"); p=${p: -3}
        # 750 이하: others 권한 0, group 쓰기 없음
        { [ "${p:2:1}" != "0" ] || [ $(( ${p:1:1} & 2 )) -ne 0 ]; } 2>/dev/null && vuln="${vuln} ${f}(${p})"
        break
    done
    for d in /var/spool/cron/crontabs /var/spool/cron; do
        [ -d "$d" ] || continue
        for f in "$d"/*; do
            [ -f "$f" ] || continue
            p=$(get_perm "$f"); p=${p: -1}
            [ $(( p & 6 )) -ne 0 ] 2>/dev/null && vuln="${vuln} ${f}(others:${p})"
        done
        break
    done
    for f in /etc/cron.allow /etc/cron.deny /etc/at.allow /etc/at.deny /var/adm/cron/cron.allow /var/adm/cron/cron.deny /var/adm/cron/at.allow /var/adm/cron/at.deny /etc/cron.d/cron.allow /etc/cron.d/cron.deny /etc/cron.d/at.allow /etc/cron.d/at.deny; do
        [ -f "$f" ] || continue
        o=$(get_owner "$f"); p=$(get_perm "$f"); p=${p: -3}
        if [ "$o" != "root" ] || [ "${p:0:1}" -gt 6 ] || [ "${p:1:1}" -gt 4 ] || [ "${p:2:1}" != "0" ]; then vuln="${vuln} ${f}(${o}:${p})"; fi 2>/dev/null
    done
    [ -n "$vuln" ] && result "SRV-081|취약|cron 관련 파일 권한 과다:${vuln}" \
                   || result "SRV-081|양호|crontab 명령·crontab 파일·at/cron 접근제어 파일 권한 기준 충족"
}

# ================================================================
# SRV-084: 시스템 주요 파일 권한
# ================================================================
check_SRV084() {
    # 평가기준: passwd 644 / shadow 600 / hosts 644 / (x)inetd.conf 600 / syslog.conf 644 / services 644 / hosts.lpd 640, 소유자 root (AIX /etc/security/passwd 600)
    evd "SRV-084" "ls -la /etc/passwd /etc/shadow /etc/group /etc/hosts /etc/services /etc/rsyslog.conf /etc/syslog.conf /etc/inetd.conf /etc/xinetd.conf /etc/hosts.lpd /etc/security/passwd 2>/dev/null"
    local vuln="" f max
    for f in /etc/passwd:644 /etc/shadow:600 /etc/hosts:644 /etc/services:644 /etc/rsyslog.conf:644 /etc/syslog.conf:644 \
             /etc/inetd.conf:600 /etc/xinetd.conf:600 /etc/hosts.lpd:640 /etc/security/passwd:600; do
        max=${f##*:}; f=${f%:*}
        [ -f "$f" ] || continue
        [ "$(get_owner "$f")" != "root" ] && vuln="${vuln} ${f}(소유자=$(get_owner "$f"))"
        _perm_over "$(get_perm "$f")" "$max" && vuln="${vuln} ${f}($(get_perm "$f")>${max})"
    done
    if [ "$OS_FAMILY" = "HPUX" ] && [ -d /tcb/files/auth ]; then   # 평가기준(HP-UX): /tcb/files/auth/[a-z]/* 664, 소유자 root
        local tn=0
        for f in /tcb/files/auth/[a-z]/*; do
            [ -f "$f" ] || continue
            { [ "$(get_owner "$f")" != "root" ] || _perm_over "$(get_perm "$f")" 664; } && { tn=$((tn+1)); [ $tn -le 5 ] && vuln="${vuln} ${f}($(get_owner "$f"):$(get_perm "$f"))"; }
        done
        [ $tn -gt 5 ] && vuln="${vuln} …/tcb 외 $((tn-5))건"
    fi
    [ -n "$vuln" ] && result "SRV-084|취약|주요 파일 권한 기준 초과:${vuln}" || result "SRV-084|양호|주요 파일 소유자 root·권한 기준 이하"
}

# ================================================================
# SRV-091: SUID/SGID 파일 관리
# ================================================================
check_SRV091() {
    # 평가기준: 불필요하게 SUID·SGID 설정된 파일
    evd "SRV-091" "_to 30 find / \$_FP \( -perm -4000 -o -perm -2000 \) -type f -print 2>/dev/null | head -40"
    local dangerous="nmap perl python python3 php ruby bash sh find wget curl nc netcat awk vim gdb strace less more cp mv tar zip" bin bp found="" f nopkg=""
    for bin in $dangerous; do
        bp=$(command -v "$bin" 2>/dev/null); [ -z "$bp" ] && continue
        { [ -u "$bp" ] || [ -g "$bp" ]; } && found="${found} ${bp}"
    done
    if [ -n "$found" ]; then result "SRV-091|취약|위험 SUID/SGID 파일:${found}"; return; fi
    while IFS= read -r f; do
        # usrmerge 배포판은 패키지 DB 에 /bin·/sbin 경로로 등록되어 있어 두 경로 모두 조회
        { rpm -qf "$f" >/dev/null 2>&1 || dpkg -S "$f" >/dev/null 2>&1 || dpkg -S "${f#/usr}" >/dev/null 2>&1 || dpkg -S "$(readlink -f "$f")" >/dev/null 2>&1; } || nopkg="${nopkg} ${f}"
    done < <(_to 30 find / $_FP \( -perm -4000 -o -perm -2000 \) -type f -print 2>/dev/null | grep -vE '^/(proc|sys|var/lib/(docker|containers))' | head -200)
    { command -v rpm >/dev/null 2>&1 || command -v dpkg >/dev/null 2>&1; } || nopkg=""
    [ -n "$nopkg" ] && result "SRV-091|수동확인|패키지 외 SUID/SGID 파일:$(echo $nopkg | cut -c1-200) - 필요 여부 확인" || result "SRV-091|양호|위험 SUID/SGID 없음, 패키지 기본 파일만 존재"
}

# ================================================================
# SRV-092: 사용자 홈 디렉토리 경로/권한
# ================================================================
check_SRV092() {
    # 평가기준: 홈 디렉터리 소유자 불일치·계정간 중복 홈·others 쓰기
    evd "SRV-092" "awk -F: '\$3>=1000 || \$3>=500{print \$1,\$3,\$6}' /etc/passwd 2>/dev/null | head -30"
    local vuln="" min_uid dup user uid homedir
    min_uid=$(awk '/^UID_MIN/{print $2}' /etc/login.defs 2>/dev/null)
    [ -z "$min_uid" ] && case "$OS_FAMILY" in AIX) min_uid=200 ;; SOLARIS|HPUX) min_uid=100 ;; *) min_uid=500 ;; esac   # UNIX 일반 사용자 UID 대역
    dup=$(awk -F: -v m="$min_uid" '$3>=m && $6!="" && $6!="/"{print $6}' /etc/passwd 2>/dev/null | sort | uniq -d | tr '\n' ' ')
    [ -n "$dup" ] && vuln="${vuln} 중복 홈:${dup}"
    while IFS=: read -r user _ uid _ _ homedir _; do
        [ "${uid:-0}" -lt "$min_uid" ] 2>/dev/null && continue
        { [ "${uid:-0}" -ge 60000 ] || [ "${uid:-0}" -lt 0 ]; } 2>/dev/null && continue   # nobody·noaccess 등
        [ -z "$homedir" ] || [ "$homedir" = "/" ] || [ ! -d "$homedir" ] && continue
        [ "$(get_owner "$homedir")" != "$user" ] && vuln="${vuln} ${homedir}(소유자:$(get_owner "$homedir"))"
        local p; p=$(get_perm "$homedir"); [ $(( ${p: -1} & 2 )) -ne 0 ] && vuln="${vuln} ${homedir}(others 쓰기:${p})"
    done < /etc/passwd
    [ -n "$vuln" ] && result "SRV-092|취약|홈 디렉터리 이상:${vuln}" || result "SRV-092|양호|홈 디렉터리 소유자 일치·중복 없음·others 쓰기 없음"
}

# ================================================================
# SRV-093: world writable 파일
# ================================================================
check_SRV093() {
    evd "SRV-093" "_to 60 find / \$_FP -perm -0002 -type f ! -path '/proc/*' ! -path '/sys/*' ! -path '/dev/*' ! -path '/tmp/*' ! -path '/var/tmp/*' -print 2>/dev/null | head -20"
    local _ww _rc
    _ww=$(_to 60 find / $_FP -perm -0002 -type f ! -path "/proc/*" ! -path "/sys/*" \
          ! -path "/dev/*" ! -path "/tmp/*" ! -path "/var/tmp/*" -print 2>/dev/null); _rc=$?
    cnt=$(printf '%s' "$_ww" | grep -c .)
    # timeout(124) 이고 0건이면 검색 미완료 — 양호로 단정하지 않음
    if [ "$_rc" = "124" ] && [ "${cnt:-0}" -eq 0 ]; then result "SRV-093|수동확인|파일 검색 시간 초과(60초) - world writable 파일 수동 확인"; return; fi
    [ "${cnt:-0}" -gt 0 ] 2>/dev/null && \
        result "SRV-093|취약|world writable 파일 ${cnt}개 (tmp 제외)" || \
        result "SRV-093|양호|world writable 파일 없음"
}

# ================================================================
# SRV-108: 로그 접근통제 및 관리
# ================================================================
check_SRV108() {
    evd "SRV-108" "ls -la /var/log/messages /var/log/secure /var/log/auth.log /var/log/syslog /var/log/wtmp /var/log/lastlog 2>/dev/null"
    # 기준: 로그 파일을 소유자 이외 사용자가 수정 가능(그룹/others 쓰기)하면 취약 — 예외: wtmp·lastlog 664, btmp 660 (권한 변경 불가)
    vuln=""
    for logf in $(find /var/log /var/adm $( [ "$OS_FAMILY" = "AIX" ] && echo /etc/security ) -type f \( -perm -020 -o -perm -002 \) 2>/dev/null | head -200); do
        perm=$(get_perm "$logf")
        case "$(basename "$logf")" in
        wtmp*|lastlog*|btmp*) [ "$(( 0${perm: -1} & 2 ))" -eq 0 ] 2>/dev/null && continue ;;
        esac
        vuln="${vuln} ${logf}(${perm})"
    done
    [ -n "$vuln" ] && result "SRV-108|취약|소유자 외 쓰기 가능한 로그 파일:${vuln}" || \
        result "SRV-108|양호|로그 파일 소유자 외 쓰기 권한 없음 (wtmp·lastlog 664, btmp 660 기준 예외)"
}

# ================================================================
# SRV-109: 주요 이벤트 로그 설정
# ================================================================
check_SRV109() {
    evd "SRV-109" "grep -ihE '^auth|^authpriv|\*\.' /etc/rsyslog.conf /etc/rsyslog.d/*.conf /etc/syslog.conf 2>/dev/null | head -10; cat /etc/default/su 2>/dev/null | grep -E 'SULOG|SYSLOG'"
    case "$OS_FAMILY" in
    SOLARIS)
        # 평가기준(Solaris): auth.info 활성 + /etc/default/su SULOG=경로, SYSLOG=YES
        local a=0 s=0
        grep -vE '^\s*#' /etc/syslog.conf 2>/dev/null | grep -qE 'auth\.(info|debug|\*)|\*\.(info|debug)' && a=1
        grep -qE '^SULOG=' /etc/default/su 2>/dev/null && grep -qE '^SYSLOG=YES' /etc/default/su 2>/dev/null && s=1
        [ $a -eq 1 ] && [ $s -eq 1 ] && result "SRV-109|수동확인|auth.info·SULOG·SYSLOG=YES 설정 - 내부 로그 정책 부합 여부 확인" || result "SRV-109|취약|Solaris auth.info(${a})·/etc/default/su SULOG·SYSLOG=YES(${s}) 미충족" ;;
    AIX|HPUX)
        grep -vE '^\s*\*|^\s*#' /etc/syslog.conf 2>/dev/null | grep -qiE "^auth|\*\.(info|debug)" && \
            result "SRV-109|수동확인|syslog auth 설정 존재 - 내부 로그 기록 정책 부합 여부 확인" || result "SRV-109|취약|syslog auth 로그 미설정" ;;
    *)
        local f
        for f in /etc/rsyslog.conf /etc/rsyslog.d/*.conf /etc/syslog.conf; do
            [ -f "$f" ] || continue
            grep -qiE "^auth|^authpriv" "$f" 2>/dev/null && { result "SRV-109|양호|auth/authpriv 로그 설정됨 (${f}) - 내부 로그 정책 부합 여부는 참고 확인"; return; }
        done
        [ -f /etc/syslog-ng/syslog-ng.conf ] && grep -qi "auth\|authpriv" /etc/syslog-ng/syslog-ng.conf 2>/dev/null && { result "SRV-109|양호|syslog-ng auth 로그 설정됨"; return; }
        result "SRV-109|취약|auth/authpriv 로그 설정 없음" ;;
    esac
}

# ================================================================
# SRV-118: 보안패치 적용
# ================================================================
check_SRV118() {
    evd "SRV-118" "uname -r; oslevel -s 2>/dev/null; instfix -i 2>/dev/null | grep -E 'ML|SP' | tail -3; emgr -l 2>/dev/null | head; swlist -l bundle 2>/dev/null | grep -iE 'QPK|HPUX'; showrev -p 2>/dev/null | tail -5; pkg info entire 2>/dev/null | grep -iE 'version|branch'"
    evd "SRV-118" "rpm -qa --last 2>/dev/null | head -10 || dpkg -l 2>/dev/null | tail -10"
    case "$OS_FAMILY" in
    LINUX)
        # 저장소 조회 실패(폐쇄망·미등록)·미지원 패키지 관리자는 건수 0 으로 보지 않고 수동확인
        _upd_cnt=""; _upd_out=""; _upd_rc=0
        if command -v dnf >/dev/null 2>&1 || command -v yum >/dev/null 2>&1; then
            _pm=$(command -v dnf >/dev/null 2>&1 && echo dnf || echo yum)
            _upd_out=$(timeout 120 $_pm -q check-update 2>/dev/null); _upd_rc=$?
            # check-update: 100=업데이트 있음, 0=없음, 그 외(1 등)=저장소 오류
            case "$_upd_rc" in 100) _upd_cnt=$(echo "$_upd_out" | grep -cE "^[a-zA-Z0-9]") ;; 0) _upd_cnt=0 ;; esac
        elif command -v apt-get >/dev/null 2>&1; then
            # apt-get update 는 저장소 접근 실패(W: Failed to fetch)에도 0 을 반환 → 출력으로 실패 판별
            _upd_out=$(timeout 120 apt-get update 2>&1); _upd_rc=$?
            if [ "$_upd_rc" -eq 0 ] && ! echo "$_upd_out" | grep -qE "^Err:|Failed to fetch|Some index files failed|Temporary failure resolving"; then
                _upd_cnt=$(apt-get -s upgrade 2>/dev/null | grep -c "^Inst ")
            fi
        elif command -v zypper >/dev/null 2>&1; then
            _upd_out=$(timeout 120 zypper -q --non-interactive list-updates 2>/dev/null); _upd_rc=$?
            [ "$_upd_rc" -eq 0 ] && _upd_cnt=$(echo "$_upd_out" | grep -c "^v ")
        fi
        evd "SRV-118" "echo 'package manager rc=${_upd_rc} upgradable=${_upd_cnt:-조회 실패}'"
        if [ -z "$_upd_cnt" ]; then
            result "SRV-118|수동확인|패키지 저장소 조회 실패(폐쇄망·저장소 미등록 등) 또는 미지원 패키지 관리자 - 보안패치 적용 현황·검토 절차 수동 확인"
        elif [ "${_upd_cnt:-0}" -gt 0 ] 2>/dev/null; then
            result "SRV-118|취약|미적용 보안패치 ${_upd_cnt}건 (수동 확인 병행 권고)"
        elif [ "${_upd_cnt:-0}" -eq 0 ] 2>/dev/null; then
            result "SRV-118|양호|패키지 매니저 기준 미적용 업데이트 없음"
        else
            result "SRV-118|수동확인|보안패치 적용 현황 수동 확인 필요"
        fi ;;
    *)
        result "SRV-118|수동확인|보안패치 적용 현황 수동 확인 필요" ;;
    esac
}

# ================================================================
# SRV-121: root PATH 환경변수
# ================================================================
check_SRV121() {
    # 평가기준: PATH 에 '.', '::'(빈 항목) 또는 불필요한 임의 경로
    evd "SRV-121" "echo \$PATH; grep -rhE '^\s*(export\s+)?PATH=' /root/.bashrc /root/.bash_profile /root/.profile /etc/profile /etc/environment /etc/bashrc /etc/profile.d/*.sh 2>/dev/null"
    local bad="" v e
    while IFS= read -r v; do
        v=$(echo "$v" | sed -E 's/^\s*(export\s+)?PATH=//; s/["'"'"']//g')
        [ -z "$v" ] && continue
        case ":$v:" in *"::"*) bad="${bad} [빈 항목] ${v}"; continue ;; esac
        local IFS=':'; for e in $v; do
            case "$e" in .|./*) bad="${bad} [.] ${v}"; break ;; esac
        done; unset IFS
    done < <( { grep -rhE '^\s*(export\s+)?PATH=' /root/.bashrc /root/.bash_profile /root/.profile /etc/profile /etc/environment /etc/bashrc /etc/profile.d/*.sh 2>/dev/null; echo "PATH=$PATH"; } )
    [ -n "$bad" ] && result "SRV-121|취약|PATH 에 현재 디렉터리(.) 또는 빈 항목:$(echo "$bad" | cut -c1-200)" || result "SRV-121|양호|PATH 에 '.'·'::' 미포함"
}

# ================================================================
# SRV-122: umask 설정
# ================================================================
check_SRV122() {
    # 평가기준: 모든 계정·설정 파일 umask 가 022 이상(group·others 쓰기 금지)
    evd "SRV-122" "umask; grep -rhE '^\s*umask|^UMASK' /etc/profile /etc/bashrc /etc/login.defs /etc/profile.d/*.sh /root/.bashrc /root/.profile 2>/dev/null"
    local vals v bad=""
    local _homes; _homes=$(awk -F: '$7!~/(nologin|false)$/ && $6!="" && $6!="/"{print $6}' /etc/passwd 2>/dev/null | sort -u)
    vals=$( { grep -rhE '^\s*umask\s+[0-7]+|^\s*UMASK\s+[0-7]+' /etc/profile /etc/bashrc /etc/bash.bashrc /etc/login.defs /etc/profile.d/*.sh $(for h in $_homes; do echo "$h/.profile $h/.bashrc $h/.bash_profile $h/.kshrc $h/.cshrc"; done) 2>/dev/null | grep -oE '[0-7]{2,4}';
              [ "$OS_FAMILY" = "AIX" ] && awk '/^[^ \t*#][^ \t]*:[ \t]*$/{next} /^[ \t]+umask[ \t]*=/{v=$0;sub(/^[^=]*=[ \t]*/,"",v);print v}' /etc/security/user 2>/dev/null;
              [ "$OS_FAMILY" = "HPUX" ] && sed -n 's/^[[:space:]]*UMASK=\([0-7]*\).*/\1/p' /etc/default/security 2>/dev/null; } | sort -u)
    [ "$OS_FAMILY" = "AIX" ] && evd "SRV-122" "lsuser -a umask ALL 2>/dev/null"
    [ -z "$vals" ] && vals=$(umask 2>/dev/null)
    for v in $vals; do
        (( (8#$v & 8#022) == 8#022 )) || bad="${bad} ${v}"
    done
    [ -n "$bad" ] && result "SRV-122|취약|group/others 쓰기 허용 umask:${bad} (022 이상 필요, 조건부 설정 포함)" || result "SRV-122|양호|umask $(echo $vals) (022 이상)"
}

# ================================================================
# SRV-127: 로그인 실패 횟수 접속 제한
# ================================================================
check_SRV127() {
    # 평가기준: 계정 잠금 임계값 설정이 존재하면 양호 (횟수는 내부 규정 확인)
    evd "SRV-127" "grep -i 'pam_faillock\\|pam_tally' /etc/pam.d/system-auth /etc/pam.d/password-auth /etc/pam.d/common-auth 2>/dev/null"
    evd "SRV-127" "cat /etc/security/faillock.conf 2>/dev/null | grep -v '^#' | grep -v '^$'"
    local val="" label=""
    case "$OS_FAMILY" in
    AIX)     label="AIX loginretries";      val=$(_aix_attr default loginretries)
             evd "SRV-127" "lsuser -a loginretries ALL 2>/dev/null"
             local z; z=$(awk '/^[^ \t*#][^ \t]*:[ \t]*$/{sub(/:.*/,"");st=$0;next} st!="default" && st!="root" && /^[ \t]+loginretries[ \t]*=[ \t]*0[ \t]*$/{print st}' /etc/security/user 2>/dev/null | tr '\n' ' ')
             [ -n "$z" ] && [ "${val:-0}" -gt 0 ] 2>/dev/null && { result "SRV-127|취약|AIX loginretries=${val}(default)이나 계정별 0 재정의: ${z}"; return; } ;;
    SOLARIS) # 평가기준(SOL): policy.conf LOCK_AFTER_RETRIES=YES + /etc/default/login RETRIES 설정
             evd "SRV-127" "grep -E 'LOCK_AFTER_RETRIES' /etc/security/policy.conf 2>/dev/null; grep -E 'RETRIES' /etc/default/login 2>/dev/null"
             if grep -qE '^[[:space:]]*LOCK_AFTER_RETRIES=YES' /etc/security/policy.conf 2>/dev/null; then
                 val=$(sed -n 's/^[[:space:]]*RETRIES=\([0-9]*\).*/\1/p' /etc/default/login 2>/dev/null | tail -1)
                 label="Solaris LOCK_AFTER_RETRIES=YES, RETRIES"
             else label="Solaris LOCK_AFTER_RETRIES 미설정(≠YES)"; val=""; fi ;;
    HPUX)    # Trusted Mode: /tcb/files/auth/system/default u_maxtries#N / Non Trusted: AUTH_MAXTRIES (/etc/default/security, /var/adm/userdb/*)
             if [ -f /tcb/files/auth/system/default ]; then label="HP-UX u_maxtries(Trusted)"; val=$(grep -oE 'u_maxtries#[0-9]+' /tcb/files/auth/system/default 2>/dev/null | head -1 | cut -d'#' -f2)
             else label="HP-UX AUTH_MAXTRIES"; val=$(grep -hE "^\s*AUTH_MAXTRIES" /etc/default/security /var/adm/userdb/* 2>/dev/null | head -1 | cut -d= -f2 | tr -d ' '); fi ;;
    *)
        local pam_files f d found=0
        pam_files=$(get_pam_files)
        for f in $pam_files; do
            [ -f "$f" ] || continue
            if grep -v "^\s*#" "$f" 2>/dev/null | grep -qi "pam_faillock"; then
                label="pam_faillock"; found=1
                val=$(grep -v "^\s*#" "$f" | grep -i "pam_faillock" | grep -oE 'deny=[0-9]+' | cut -d= -f2 | head -1)
                break
            fi
        done
        if [ -f /etc/security/faillock.conf ]; then
            d=$(grep -v "^\s*#" /etc/security/faillock.conf 2>/dev/null | grep -E "^\s*deny\s*=" | grep -oE '[0-9]+' | head -1)
            [ -n "$d" ] && { val=$d; label="faillock.conf deny"; }
            [ $found -eq 1 ] && [ -z "$val" ] && { val=3; label="pam_faillock(기본 deny=3)"; }
        fi
        if [ $found -eq 0 ] && [ -z "$d" ]; then
            for f in $pam_files; do
                [ -f "$f" ] || continue
                if grep -v "^\s*#" "$f" 2>/dev/null | grep -qi "pam_tally"; then
                    label="pam_tally2"; val=$(grep -v "^\s*#" "$f" | grep -i "pam_tally" | grep -oE 'deny=[0-9]+' | cut -d= -f2 | head -1); break
                fi
            done
        fi ;;
    esac
    if [ -z "$val" ] || [ "$val" = "0" ]; then
        result "SRV-127|취약|계정 잠금 임계값 미설정${label:+ (${label})}"
    elif [ "$val" -le 5 ] 2>/dev/null; then
        result "SRV-127|양호|${label}=${val}회 설정"
    else
        result "SRV-127|양호|${label}=${val}회 설정 (5회 초과 - 내부 규정 기준 확인)"
    fi
}

# ================================================================
# SRV-131: su 명령어 그룹 제한
# ================================================================
check_SRV131() {
    evd "SRV-131" "grep -v '^#' /etc/pam.d/su 2>/dev/null; ls -l /bin/su /usr/bin/su 2>/dev/null; awk '/^(root|default):/,/^\$/' /etc/security/user 2>/dev/null | grep sugroups; grep -i SU_ROOT_GROUP /etc/default/security 2>/dev/null; grep -i su_group /etc/pam.conf 2>/dev/null"
    local su p
    su=$(ls /bin/su /usr/bin/su 2>/dev/null | head -1); p=$(get_perm "$su")
    case "$OS_FAMILY" in
    AIX)
        local g; g=$(awk '/^root:/{f=1;next} /^[^ \t*]/{f=0} f&&/sugroups/{sub(/.*=[ \t]*/,"");print;exit}' /etc/security/user 2>/dev/null)
        [ -z "$g" ] && g=$(awk '/^default:/{f=1;next} /^[^ \t*]/{f=0} f&&/sugroups/{sub(/.*=[ \t]*/,"");print;exit}' /etc/security/user 2>/dev/null)
        [ -n "$g" ] && [ "${g^^}" != "ALL" ] && result "SRV-131|양호|AIX sugroups=${g}" || result "SRV-131|취약|AIX sugroups=${g:-미설정} (ALL/미설정)" ;;
    HPUX)
        local g; g=$(grep -E '^\s*SU_ROOT_GROUP' /etc/default/security 2>/dev/null | cut -d= -f2 | tr -d ' ')
        [ -n "$g" ] && [ "${g^^}" != "ALL" ] && result "SRV-131|양호|HP-UX SU_ROOT_GROUP=${g}" || result "SRV-131|취약|HP-UX SU_ROOT_GROUP 미지정" ;;
    SOLARIS)
        if grep -vE '^\s*#' /etc/pam.conf 2>/dev/null | grep -q su_group; then result "SRV-131|양호|pam.conf su_group 설정"
        elif [ -n "$p" ] && [ $(( ${p: -1} & 1 )) -eq 0 ]; then result "SRV-131|양호|${su} others 실행 권한 없음 (${p}, 그룹=$(ls -l "$su" | awk '{print $4}'))"
        else result "SRV-131|취약|${su:-su} others 실행 가능 (${p:-미확인})"; fi ;;
    *)
        if grep -vE '^\s*#' /etc/pam.d/su 2>/dev/null | grep -qE '^\s*auth\s+(required|requisite)\s+\S*pam_wheel\.so'; then
            result "SRV-131|양호|su pam_wheel required 설정 (그룹=$(grep -vE '^\s*#' /etc/pam.d/su | grep -oE 'group=\S+' | cut -d= -f2 | head -1 | sed 's/^$/wheel/'))"
        elif [ -n "$p" ] && [ $(( ${p: -1} & 1 )) -eq 0 ]; then result "SRV-131|양호|${su} others 실행 권한 없음 (${p})"
        else result "SRV-131|취약|su pam_wheel(required) 미설정, ${su} others 실행 가능 (${p:-미확인})"; fi ;;
    esac
}

# ================================================================
# SRV-133: Cron 서비스 사용 계정 제한
# ================================================================
check_SRV133() {
    # 평가기준: allow/deny 내부에 계정 존재 또는 둘 다 없음(root만 사용) → 양호 / allow 없고 deny 비어 있음 → 취약
    local allow=/etc/cron.allow deny=/etc/cron.deny
    { [ "$OS_FAMILY" = "AIX" ] || [ "$OS_FAMILY" = "HPUX" ]; } && { allow=/var/adm/cron/cron.allow; deny=/var/adm/cron/cron.deny; }
    [ "$OS_FAMILY" = "SOLARIS" ] && { allow=/etc/cron.d/cron.allow; deny=/etc/cron.d/cron.deny; }
    evd "SRV-133" "ls -la $allow $deny 2>/dev/null; echo '[allow]'; cat $allow 2>/dev/null; echo '[deny]'; cat $deny 2>/dev/null"
    local a_cnt d_cnt
    a_cnt=$(grep -vcE '^\s*(#|$)' "$allow" 2>/dev/null); d_cnt=$(grep -vcE '^\s*(#|$)' "$deny" 2>/dev/null)
    if [ -f "$allow" ] && [ "${a_cnt:-0}" -gt 0 ]; then result "SRV-133|양호|${allow} 허용 계정 ${a_cnt}개 관리"
    elif [ ! -f "$allow" ] && [ ! -f "$deny" ]; then result "SRV-133|양호|cron.allow/cron.deny 모두 없음 (root만 cron 사용 가능)"
    elif [ ! -f "$allow" ] && [ "${d_cnt:-0}" -eq 0 ]; then result "SRV-133|취약|cron.allow 없고 cron.deny 비어 있음 (모든 계정 cron 사용 가능)"
    elif [ ! -f "$allow" ]; then result "SRV-133|양호|${deny} 거부 계정 ${d_cnt}개 관리"
    else result "SRV-133|수동확인|${allow} 존재하나 허용 계정 없음 (cron 사용 불가) - 의도 확인"; fi
}

# ================================================================
# SRV-142: 중복 UID 계정 제한
# ================================================================
check_SRV142() {
    evd "SRV-142" "awk -F: '{print \$3}' /etc/passwd 2>/dev/null | sort | uniq -d"
    dup=$(awk -F: '{print $3}' /etc/passwd 2>/dev/null | sort | uniq -d)
    [ -n "$dup" ] && result "SRV-142|취약|중복 UID 발견: $(echo $dup | head -5)" || \
        result "SRV-142|양호|중복 UID 없음"
}

# ================================================================
# SRV-144: /dev 불필요 파일
# ================================================================
check_SRV144() {
    # 평가기준: /dev 에 존재하지 않는 불필요 device(일반) 파일 (mqueue, shm 예외)
    evd "SRV-144" "find /dev \\( -path /dev/shm -o -path /dev/mqueue \\) -prune -o -type f -print 2>/dev/null | head -20"
    local fl; fl=$(find /dev \( -path /dev/shm -o -path /dev/mqueue \) -prune -o -type f -print 2>/dev/null | head -10)
    [ -n "$fl" ] && result "SRV-144|취약|/dev 내 일반 파일: $(echo "$fl" | tr '\n' ' ' | cut -c1-200)" || result "SRV-144|양호|/dev 불필요 일반 파일 없음 (shm·mqueue 제외)"
}

# ================================================================
# SRV-158: 불필요 Telnet 서비스 비활성화
# ================================================================
check_SRV158() {
    evd "SRV-158" "grep -vE '^\s*#' /etc/inetd.conf 2>/dev/null | grep -w telnet; inetadm 2>/dev/null | grep -i telnet; lssrc -ls inetd 2>/dev/null | grep -i telnet; ss -tln 2>/dev/null | grep ':23 '; netstat -an 2>/dev/null | grep -E '[.:]23[[:space:]].*LISTEN'"
    local on; on=$( { _inetd_on telnet; _listen 23 | awk '{print "LISTEN:23"}'; } | tr '\n' ' ')
    if is_running telnetd || is_running in.telnetd || [ -n "$on" ]; then result "SRV-158|취약|Telnet 서비스 활성 (${on:-telnetd 프로세스})"
    else result "SRV-158|양호|Telnet 서비스 미실행"; fi
}

# ================================================================
# SRV-161: ftpusers 파일의 소유자 및 권한 설정 적절성
# ================================================================
check_SRV161() {
    evd "SRV-161" "ls -la /etc/ftpusers /etc/ftpd/ftpusers /etc/vsftpd/ftpusers /etc/vsftpd/user_list /etc/vsftpd.ftpusers /etc/vsftpd.user_list 2>/dev/null"
    local f found="" bad="" p o
    for f in /etc/ftpusers /etc/ftpd/ftpusers /etc/vsftpd/ftpusers /etc/vsftpd/user_list /etc/vsftpd.ftpusers /etc/vsftpd.user_list; do
        [ -f "$f" ] || continue
        found="${found} ${f}"; p=$(get_perm "$f"); o=$(get_owner "$f")
        { [ "$o" != "root" ] || _perm_over "$p" 640; } && bad="${bad} ${f}(소유자:${o},권한:${p})"
    done
    if [ -z "$found" ]; then
        _ftp_running && result "SRV-161|취약|ftpusers 파일 없음 (FTP 실행 중)" || result "SRV-161|양호|FTP 서비스 미실행"
        return
    fi
    [ -n "$bad" ] && result "SRV-161|취약|ftpusers 소유자/권한 이상:${bad}" || result "SRV-161|양호|${found# } 소유자=root, 권한 640 이하"
}

# ================================================================
# SRV-163: 시스템 사용 주의사항 출력 (Banner)
# ================================================================
check_SRV163() {
    # 평가기준: 로그온 시 경고 메시지 미출력 또는 문구 내 시스템 버전 정보 노출 시 취약
    evd "SRV-163" "grep -iE '^\s*Banner' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null; for f in /etc/issue /etc/issue.net /etc/motd; do echo \"# \$f\"; head -5 \$f 2>/dev/null; done; grep -i herald /etc/security/login.cfg 2>/dev/null"
    local files="" f txt="" ver
    local sb; sb=$(sshd -T 2>/dev/null | awk 'tolower($1)=="banner"{print $2}')
    [ -z "$sb" ] && sb=$(grep -vE '^\s*#' $(_sshd_cfg) /etc/ssh/sshd_config.d/*.conf 2>/dev/null | grep -iE '^\S*:?\s*Banner' | awk '{print $NF}' | tail -1)
    [ -n "$sb" ] && [ "$sb" != "none" ] && [ -f "$sb" ] && files="$sb"
    for f in /etc/issue /etc/issue.net /etc/motd; do [ -s "$f" ] && files="${files} ${f}"; done
    [ "$OS_FAMILY" = "AIX" ] && txt=$(grep -vE '^\s*\*' /etc/security/login.cfg 2>/dev/null | grep -i 'herald' | head -1)
    for f in $files; do txt="${txt}"$'\n'"$(cat "$f" 2>/dev/null)"; done
    if [ -z "$(echo "$txt" | tr -d '[:space:]')" ]; then result "SRV-163|취약|로그온 경고 메시지(배너) 미설정"; return; fi
    ver=$(echo "$txt" | grep -oiE 'SunOS[^ ]*|Solaris [0-9.]+|AIX( Version)? [0-9.]+|HP-UX|HP Release [A-Z]?\.?[0-9.]+|Ubuntu [0-9.]+|CentOS[^[:cntrl:]]*[0-9]|Red Hat[^[:cntrl:]]*[0-9]|Rocky[^[:cntrl:]]*[0-9]|Debian[^[:cntrl:]]*[0-9]|\\r|\\v|Kernel [0-9]' | head -1)
    if [ -n "$ver" ]; then result "SRV-163|취약|배너에 시스템 버전 정보 노출 (${ver}) - $(echo $files)"
    elif echo "$txt" | grep -qiE 'authori[sz]ed|unauthori[sz]ed|warning|경고|허가|불법|monitor'; then result "SRV-163|양호|경고 문구 배너 설정 ($(echo $files))"
    else result "SRV-163|수동확인|배너 존재하나 경고 문구 미확인 ($(echo $files)) - 내용 확인"; fi
}

# ================================================================
# SRV-165: 불필요 Shell 계정 제거
# ================================================================
check_SRV165() {
    # 평가기준: 로그인이 필요하지 않은 계정(daemon·bin·sys·adm·listen·nobody·noaccess·diag·operator·games·gopher 등 시스템 계정)에 shell 부여 시 취약
    evd "SRV-165" "awk -F: '{printf \"%-15s UID=%-5s Shell=%s\\n\",\$1,\$3,\$7}' /etc/passwd"
    local min_uid bad="" user uid sh
    min_uid=$(awk '/^UID_MIN/{print $2}' /etc/login.defs 2>/dev/null)
    [ -z "$min_uid" ] && case "$OS_FAMILY" in AIX) min_uid=200 ;; SOLARIS|HPUX) min_uid=100 ;; *) min_uid=500 ;; esac   # UNIX 일반 사용자 UID 대역
    while IFS=: read -r user _ uid _ _ _ sh; do
        [ "$user" = "root" ] && continue
        if [ "$OS_FAMILY" = "LINUX" ]; then
            { [ "${uid:-0}" -lt "$min_uid" ] 2>/dev/null || echo "$user" | grep -qE '^(daemon|bin|sys|adm|listen|nobody|nobody4|noaccess|diag|operator|games|gopher)$'; } || continue
        else   # UNIX: 가이드 판단방법 계정 목록만 (일반 사용자 UID 체계가 OS 마다 다름)
            echo "$user" | grep -qE '^(daemon|bin|sys|adm|listen|nobody|nobody4|noaccess|diag|operator|games|gopher|uucp|lp|smmsp|nuucp)$' || continue
            [ -z "$sh" ] && sh="/bin/sh"   # Solaris 등 셸 필드 공란 = /bin/sh
        fi
        case "$sh" in */sync|*/shutdown|*/halt|*nologin|*false|"") continue ;; esac
        grep -qx "$sh" /etc/shells 2>/dev/null || case "$sh" in */bash|*/sh|*/ksh|*/csh|*/tcsh|*/zsh|*/dash) ;; *) continue ;; esac
        bad="${bad} ${user}(${sh})"
    done < /etc/passwd
    [ -n "$bad" ] && result "SRV-165|취약|로그인 불필요 시스템 계정에 shell 부여:${bad}" || result "SRV-165|양호|시스템 계정에 대화형 shell 미부여"
}

# ================================================================
# SRV-175: NTP 설정
# ================================================================
check_SRV175() {
    evd "SRV-175" "chronyc tracking 2>/dev/null || ntpq -p 2>/dev/null || timedatectl 2>/dev/null | grep -i synch"
    # chrony
    command -v chronyc >/dev/null 2>&1 && \
        chronyc tracking 2>/dev/null | grep -q "Reference ID" && \
        result "SRV-175|양호|chronyc NTP 동기화 활성" && return
    # ntpq
    command -v ntpq >/dev/null 2>&1 && \
        ntpq -p 2>/dev/null | grep -q "^\*" && \
        result "SRV-175|양호|ntpq 활성 피어 확인" && return
    # timedatectl
    command -v timedatectl >/dev/null 2>&1 && \
        timedatectl 2>/dev/null | grep -q "synchronized: yes" && \
        result "SRV-175|양호|timedatectl NTP 동기화 활성" && return
    # AIX
    [ "$OS_FAMILY" = "AIX" ] && grep -q "server" /etc/ntp.conf 2>/dev/null && \
        result "SRV-175|수동확인|AIX ntp.conf 서버 설정됨 (동기화 상태 확인)" && return
    result "SRV-175|취약|NTP 동기화 설정 미확인"
}

# ================================================================
# SRV-177: sudo 명령어 접근 권한 설정
# ================================================================
check_SRV177() {
    # 평가기준: sudo 접근 제한 — 불필요한 사용자가 sudo 권한을 가지는지 확인
    evd "SRV-177" "ls -l /etc/sudoers; grep -vE '^\s*(#|Defaults|\$)' /etc/sudoers /etc/sudoers.d/* 2>/dev/null"
    command -v sudo >/dev/null 2>&1 || [ -f /etc/sudoers ] || { result "SRV-177|양호|sudo 미설치"; return; }
    local rules all="" who="" np=""
    rules=$(grep -hvE '^\s*(#|Defaults|$)|^\s*(User|Runas|Host|Cmnd)_Alias|^\s*@include|^\s*#include' /etc/sudoers /etc/sudoers.d/* 2>/dev/null | grep -E '=')
    all=$(echo "$rules" | awk '$1=="ALL" || $1=="%users" || $1=="%everyone" || $1=="%staff"{print $1}' | sort -u | tr '\n' ' ')
    who=$(echo "$rules" | awk '$1!="root"{print $1}' | sort -u | tr '\n' ' ')
    np=$(echo "$rules" | grep -c 'NOPASSWD')
    if [ -n "$all" ]; then result "SRV-177|취약|모든(또는 일반 사용자 그룹) 사용자 sudo 허용: ${all}"
    elif [ -n "$who" ]; then result "SRV-177|수동확인|sudo 권한 보유: ${who}(NOPASSWD 규칙 ${np}건) - 불필요 사용자 여부 확인"
    else result "SRV-177|양호|root 외 sudo 권한 없음"; fi
}

# ================================================================
# SRV-179: EoS 시스템 장비 교체 (자동 판정)
# ================================================================
check_SRV179() {
    evd "SRV-179" "uname -srm; cat /etc/os-release 2>/dev/null | head -5; oslevel -s 2>/dev/null; swlist -l product 2>/dev/null | grep -E '^\s*HP-UX' | head -3; pkg info entire 2>/dev/null | grep -iE 'version|branch'; cat /etc/release 2>/dev/null | head -2"
    EOS_SCRIPT="$(dirname "$0")/eos_checker.py"
    [ -f "$EOS_SCRIPT" ] || EOS_SCRIPT="$(dirname "$0")/../converter/eos_checker.py"   # 저장소 구조 그대로 실행 시
    [ ! -f "$EOS_SCRIPT" ] && {
        result "SRV-179|수동확인|eos_checker.py 없음 - 수동 확인 필요"
        return
    }

    product="" version=""
    case "$OS_FAMILY" in
    AIX)
        product="aix"; version="${OS_MAJOR}.$(uname -r)"
        ;;
    SOLARIS)
        product="solaris"
        version=$(uname -r | sed 's/5\.//')
        ;;
    HPUX)
        product="hp-ux"
        version=$(uname -r | sed 's/B\.//')
        ;;
    LINUX)
        case "$OS_DISTRO" in
        RHEL|CENTOS|ROCKY|ORACLE)
            case "$ID" in   # 파생 배포판은 각자의 수명 주기 (CentOS 8 은 2021-12-31 조기 종료, Stream 은 별도)
            centos)    product="centos"; version="$OS_MAJOR"; case "$NAME" in *Stream*) version="${OS_MAJOR}-stream" ;; esac ;;
            rocky)     product="rocky"; version="$OS_MAJOR" ;;
            almalinux) product="almalinux"; version="$OS_MAJOR" ;;
            rhel|"")   product="rhel"; version="$OS_MAJOR" ;;
            *) result "SRV-179|수동확인|${PRETTY_NAME:-$ID $VERSION_ID} (RHEL 계열 파생 배포판) EoS 수동 확인 - 벤더 Lifecycle 대조"; return ;;
            esac ;;
        UBUNTU)
            product="ubuntu"
            version=$(grep -oE '[0-9]+\.[0-9]+' /etc/os-release 2>/dev/null | head -1) ;;
        DEBIAN)
            product="debian"; version="$OS_MAJOR" ;;
        SLES)
            product="sles"; version="$OS_MAJOR" ;;
        AMZN)
            product="amazon-linux"; version="$OS_MAJOR" ;;
        *)
            result "SRV-179|수동확인|OS ${OS_DISTRO} ${OS_MAJOR} EoS 수동 확인"
            return ;;
        esac ;;
    *)
        result "SRV-179|수동확인|OS 종류 미탐지 - 수동 확인"
        return ;;
    esac

    _PY=$(command -v python3 2>/dev/null || { [ -x /usr/libexec/platform-python ] && echo /usr/libexec/platform-python; } || command -v python 2>/dev/null)
    if [ -z "$_PY" ]; then result "SRV-179|수동확인|python 미설치 - ${product} ${version} EoS 여부 수동 확인"; return; fi
    _eo=$("$_PY" "$EOS_SCRIPT" "$product" "$version" 2>/dev/null)   # 인터넷 연결 시 endoflife.date 조회, 아니면 내장 데이터
    eos_result=$(echo "$_eo" | grep "^결과:" | awk '{print $2}')
    eos_desc=$(echo "$_eo" | grep "^설명:" | cut -d: -f2- | sed "s/^ *//;s/ *$//")
    [ -z "$eos_result" ] && { result "SRV-179|수동확인|EoS 판정 실패 - 수동 확인"; return; }
    result "SRV-179|${eos_result}|${eos_desc}"
}

# ================================================================
# SRV-087: C 컴파일러 권한
# ================================================================
check_SRV087() {
    local _cc_list; _cc_list=$(for c in /usr/bin/gcc /usr/bin/cc /usr/bin/g++ /usr/local/bin/gcc /usr/vac/bin/xlc /usr/vac/bin/cc /opt/aCC/bin/aCC /opt/ansic/bin/cc /opt/SUNWspro/bin/cc /opt/developerstudio*/bin/cc /usr/sfw/bin/gcc $(command -v cc gcc 2>/dev/null); do echo "$c"; done | sort -u)   # /usr/ucb/cc 는 Studio 미설치 시 동작하지 않는 래퍼라 제외
    evd "SRV-087" "ls -laL $(echo $_cc_list) 2>/dev/null"
    _cc_vuln=""
    for cc in $_cc_list; do
        [ -x "$cc" ] || continue
        perm=$(get_perm "$cc")
        if echo "$perm" | grep -qE "[1357]$"; then
            _cc_vuln="${_cc_vuln} ${cc}(${perm})"
        fi
    done
    if [ -z "$_cc_vuln" ]; then
        _cc_found=0
        for cc in $_cc_list; do
            [ -x "$cc" ] && _cc_found=1 && break
        done
        [ $_cc_found -eq 0 ] && result "SRV-087|양호|C 컴파일러 미설치" || \
            result "SRV-087|양호|C 컴파일러 other 실행 권한 없음"
    else
        result "SRV-087|취약|C 컴파일러 other 실행 허용:${_cc_vuln}"
    fi
}

# ================================================================
# SMTP 공통 탐지 (SRV-005~010 공용)
# ================================================================
_smtp_type=""  # sendmail / postfix / exim / ""
_smtp_cf=""
_smtp_pids() { ps -ef 2>/dev/null | grep -v grep | grep -v defunct | grep -E "$1" | awk '{print $2}'; }
_in_container_only() {   # 모든 PID 가 '점검 스크립트와 다른' 컨테이너 cgroup 이면 참 (/proc 없는 UNIX 는 거짓 = 호스트 서비스)
    local p any=0 self; self=$(cat /proc/self/cgroup 2>/dev/null)
    for p in "$@"; do any=1; [ -r "/proc/$p/cgroup" ] || return 1
        grep -qE 'docker|containerd|kubepods|libpod' "/proc/$p/cgroup" 2>/dev/null || return 1
        [ "$(cat "/proc/$p/cgroup" 2>/dev/null)" = "$self" ] && return 1   # 스크립트와 같은 컨테이너 안의 MTA 는 대상 서비스
    done
    [ $any = 1 ]
}
_smtp_host() { local pids; pids=$(_smtp_pids "$1"); [ -n "$pids" ] || return 1; if _in_container_only $pids; then evd "SMTP" "echo '컨테이너 내부 MTA(${1}) - 호스트 판정 제외: '$(echo $pids)"; return 1; fi; return 0; }
_detect_smtp() {
    [ -n "$_smtp_type" ] && return
    if _smtp_host 'sendmail'; then
        _smtp_type="sendmail"
        for c in /etc/mail/sendmail.cf /etc/sendmail.cf /usr/lib/sendmail.cf; do
            [ -f "$c" ] && _smtp_cf="$c" && break
        done
    elif _smtp_host 'postfix|/master'; then
        _smtp_type="postfix"
        for c in /etc/postfix/main.cf /usr/local/etc/postfix/main.cf; do
            [ -f "$c" ] && _smtp_cf="$c" && break
        done
    elif _smtp_host 'exim'; then
        _smtp_type="exim"
        for c in /etc/exim4/exim4.conf /etc/exim/exim.conf; do
            [ -f "$c" ] && _smtp_cf="$c" && break
        done
    fi
}
_ver_lt() { [ "$1" != "$2" ] && [ "$(printf '%s\n%s\n' "$1" "$2" | sort -t. -k1,1n -k2,2n -k3,3n | head -1)" = "$1" ]; }
_smtp_running() {
    _detect_smtp
    [ -n "$_smtp_type" ] && return 0
    ss -tlnp 2>/dev/null | grep -q "[.:]25 " && return 0
    netstat -tlnp 2>/dev/null | grep -q ":25 " && return 0
    return 1
}

# ================================================================
# SRV-005: SMTP EXPN/VRFY 제한
# ================================================================
check_SRV005() {
    _smtp_running || { evd "SRV-005" "ps -ef 2>/dev/null | grep -E 'smtp|postfix|sendmail' | grep -v grep"; result "SRV-005|N-A|SMTP 서비스 미실행"; return; }
    _detect_smtp
    evd "SRV-005" "postconf disable_vrfy_command 2>/dev/null; grep -i PrivacyOptions $_smtp_cf 2>/dev/null"
    case "$_smtp_type" in
    postfix)
        local val=$(postconf -h disable_vrfy_command 2>/dev/null)
        [ "$val" = "yes" ] && result "SRV-005|양호|postfix disable_vrfy_command=yes" || \
            result "SRV-005|취약|postfix disable_vrfy_command=${val:-no}" ;;
    sendmail)
        # 평가기준: noexpn 과 novrfy 또는 goaway
        local po; po=$(grep -iE '^\s*O\s+PrivacyOptions' "$_smtp_cf" 2>/dev/null | tail -1)
        if echo "$po" | grep -qi "goaway" || { echo "$po" | grep -qi "noexpn" && echo "$po" | grep -qi "novrfy"; }; then
            result "SRV-005|양호|sendmail PrivacyOptions EXPN·VRFY 제한 (${po##*=})"
        else result "SRV-005|취약|sendmail PrivacyOptions noexpn·novrfy(또는 goaway) 미설정 (${po##*=})"; fi ;;
    *) result "SRV-005|수동확인|${_smtp_type:-SMTP} EXPN/VRFY 설정 수동 확인" ;;
    esac
}

# ================================================================
# SRV-006: SMTP 로그 수준
# ================================================================
check_SRV006() {
    _smtp_running || { evd "SRV-006" "ps -ef 2>/dev/null | grep -E 'smtp|postfix|sendmail' | grep -v grep"; result "SRV-006|N-A|SMTP 서비스 미실행"; return; }
    _detect_smtp
    evd "SRV-006" "postconf debug_peer_level syslog_facility 2>/dev/null; grep -i LogLevel $_smtp_cf 2>/dev/null"
    case "$_smtp_type" in
    postfix)
        # 평가기준: debug_peer_level 2 이상 (기본 2)
        local dl=$(postconf -h debug_peer_level 2>/dev/null)
        [ "${dl:-2}" -ge 2 ] 2>/dev/null && result "SRV-006|양호|postfix debug_peer_level=${dl:-2(기본)}" || result "SRV-006|취약|postfix debug_peer_level=${dl} (2 이상 필요)" ;;
    sendmail)
        # 평가기준: LogLevel 9 이상 (미설정 시 기본 9)
        local lv=$(grep -iE "^\s*O\s+LogLevel" "$_smtp_cf" 2>/dev/null | grep -oE '[0-9]+' | tail -1)
        [ "${lv:-9}" -ge 9 ] 2>/dev/null && result "SRV-006|양호|sendmail LogLevel=${lv:-9(기본)}" || result "SRV-006|취약|sendmail LogLevel=${lv} (9 이상 필요)" ;;
    *) result "SRV-006|수동확인|${_smtp_type:-SMTP} 로그 수준 수동 확인" ;;
    esac
}

# ================================================================
# SRV-007: SMTP 보안패치
# ================================================================
check_SRV007() {
    _smtp_running || { result "SRV-007|N-A|SMTP 서비스 미실행"; return; }
    _detect_smtp
    local ver=""
    case "$_smtp_type" in
    postfix) ver=$(postconf -h mail_version 2>/dev/null); evd "SRV-007" "postconf mail_version 2>/dev/null" ;;
    sendmail) ver=$(sendmail -d0.1 </dev/null 2>&1 | head -1 | grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)?' | head -1)
              [ -z "$ver" ] && ver=$(sed -n 's/^DZ\([0-9][0-9.]*\).*/\1/p' "$_smtp_cf" 2>/dev/null | head -1)
              evd "SRV-007" "sendmail -d0.1 </dev/null 2>&1 | head -1; grep '^DZ' $_smtp_cf 2>/dev/null" ;;
    exim) ver=$( { exim -bV 2>/dev/null || exim4 -bV 2>/dev/null; } | grep -oE 'version [0-9]+\.[0-9]+(\.[0-9]+)?' | head -1 | awk '{print $2}'); evd "SRV-007" "exim -bV 2>/dev/null | head -1; exim4 -bV 2>/dev/null | head -1" ;;
    esac
    # 평가기준 판단방법 최소 버전: Sendmail 8.14.9 / Postfix 2.5.13·2.6.10·2.7.4·2.8.3 / Exim 4.94.2 — 미만이면 알려진 취약점 미패치
    local min=""
    case "$_smtp_type" in
    sendmail) min="8.14.9" ;;
    exim) min="4.94.2" ;;
    postfix) case "$ver" in 2.5.*) min="2.5.13" ;; 2.6.*) min="2.6.10" ;; 2.7.*) min="2.7.4" ;; 2.8.*) min="2.8.3" ;; [01].*|2.[0-4].*) min="2.5.13" ;; esac ;;
    esac
    if [ -n "$ver" ] && [ -n "$min" ] && _ver_lt "$ver" "$min"; then result "SRV-007|취약|${_smtp_type} ${ver} - 평가기준 최소 버전 ${min} 미만 (보안 패치 미적용)"
    else result "SRV-007|수동확인|${_smtp_type} 버전=${ver:-미확인}${min:+ (평가기준 최소 ${min} 이상)} - 최신 버전·내부 패치 절차 확인"; fi
}

# ================================================================
# SRV-008: SMTP DoS 방지
# ================================================================
check_SRV008() {
    _smtp_running || { evd "SRV-008" "ps -ef 2>/dev/null | grep -E 'smtp|postfix|sendmail' | grep -v grep"; result "SRV-008|N-A|SMTP 서비스 미실행"; return; }
    _detect_smtp
    evd "SRV-008" "postconf message_size_limit header_size_limit default_process_limit local_destination_concurrency_limit smtpd_recipient_limit 2>/dev/null; grep -iE 'MaxDaemonChildren|ConnectionRateThrottle|MinFreeBlocks|MaxHeadersLength|MaxMessageSize' $_smtp_cf 2>/dev/null"
    case "$_smtp_type" in
    postfix)
        # 평가기준: 5개 파라미터는 기본값이 있어 미설정도 양호, 0(해제) 이면 취약
        local p z=""
        for p in message_size_limit header_size_limit default_process_limit local_destination_concurrency_limit smtpd_recipient_limit; do
            [ "$(postconf -h $p 2>/dev/null)" = "0" ] && z="${z} ${p}=0"
        done
        [ -n "$z" ] && result "SRV-008|취약|postfix 제한 해제(0):${z}" || result "SRV-008|양호|postfix DoS 제한 파라미터 기본값/설정값 유지 (0 해제 없음)" ;;
    sendmail)
        local p miss=""
        for p in MaxDaemonChildren ConnectionRateThrottle MinFreeBlocks MaxHeadersLength MaxMessageSize; do
            grep -qiE "^\s*O\s+${p}\s*=" "$_smtp_cf" 2>/dev/null || miss="${miss} ${p}"
        done
        [ -n "$miss" ] && result "SRV-008|취약|sendmail DoS 방지 파라미터 미설정:${miss}" || result "SRV-008|양호|sendmail DoS 방지 파라미터 5종 설정" ;;
    *) result "SRV-008|수동확인|${_smtp_type:-SMTP} DoS 방지 설정 수동 확인" ;;
    esac
}

# ================================================================
# SRV-009: SMTP 릴레이 제한
# ================================================================
check_SRV009() {
    _smtp_running || { evd "SRV-009" "ps -ef 2>/dev/null | grep -E 'smtp|postfix|sendmail' | grep -v grep"; result "SRV-009|N-A|SMTP 서비스 미실행"; return; }
    _detect_smtp
    evd "SRV-009" "postconf smtpd_relay_restrictions smtpd_recipient_restrictions mynetworks 2>/dev/null; grep -iE 'promiscuous_relay|relay_entire_domain|relay_local_from' $_smtp_cf /etc/mail/sendmail.mc 2>/dev/null; sendmail -d0.1 -bv root 2>/dev/null | head -1"
    case "$_smtp_type" in
    postfix)
        local mn=$(postconf -h mynetworks 2>/dev/null) rr=$(postconf -h smtpd_relay_restrictions 2>/dev/null)
        if echo "$mn $rr" | grep -qE '0\.0\.0\.0/0|static:all|\bpermit\s*(,|$)'; then result "SRV-009|취약|postfix 릴레이 전체 허용 (mynetworks=${mn})"
        else result "SRV-009|양호|postfix 릴레이 제한 (relay_restrictions=${rr:-기본 reject_unauth_destination})"; fi ;;
    sendmail)
        # 평가기준: 8.9 이상은 promiscuous_relay 비활성(기본)이면 양호, 8.9 미만은 access 파일 접근통제
        local ver; ver=$(sendmail -d0.1 -bv root 2>/dev/null | grep -oE 'Version [0-9]+\.[0-9]+' | awk '{print $2}' | head -1)
        [ -z "$ver" ] && ver=$(sed -n 's/^DZ\([0-9]*\.[0-9]*\).*/\1/p' "$_smtp_cf" 2>/dev/null | head -1)   # sendmail.cf 버전 매크로
        if grep -qiE 'promiscuous_relay|relay_entire_domain' "$_smtp_cf" /etc/mail/sendmail.mc 2>/dev/null; then result "SRV-009|취약|sendmail promiscuous_relay/relay_entire_domain 설정"
        elif [ -n "$ver" ] && { [ "${ver%%.*}" -gt 8 ] || { [ "${ver%%.*}" -eq 8 ] && [ "${ver#*.}" -ge 9 ]; }; } 2>/dev/null; then result "SRV-009|양호|sendmail ${ver} (8.9 이상 기본 릴레이 차단)"
        elif [ -f /etc/mail/access ]; then result "SRV-009|수동확인|sendmail ${ver:-버전 미확인} - /etc/mail/access 릴레이 접근통제 확인"
        else result "SRV-009|취약|sendmail ${ver:-버전 미확인} (8.9 미만 추정) - access 접근통제 파일 없음"; fi ;;
    *) result "SRV-009|수동확인|${_smtp_type:-SMTP} 릴레이 제한 수동 확인" ;;
    esac
}

# ================================================================
# SRV-010: SMTP 일반사용자 실행 방지
# ================================================================
check_SRV010() {
    _smtp_running || { evd "SRV-010" "ps -ef 2>/dev/null | grep -E 'smtp|postfix|sendmail' | grep -v grep"; result "SRV-010|N-A|SMTP 서비스 미실행"; return; }
    _detect_smtp
    evd "SRV-010" "ls -lL \$(postconf -h command_directory 2>/dev/null)/postsuper /usr/sbin/postsuper /usr/sbin/exim /usr/sbin/exim4 2>/dev/null; grep -i PrivacyOptions $_smtp_cf 2>/dev/null"
    case "$_smtp_type" in
    postfix)
        # 평가기준: postsuper 실행 파일 others 실행 권한 → 일반 사용자 queue 처리 가능
        local ps="$(postconf -h command_directory 2>/dev/null)/postsuper"; [ -f "$ps" ] || ps=/usr/sbin/postsuper
        if [ ! -f "$ps" ]; then result "SRV-010|수동확인|postsuper 실행 파일 확인 불가"
        else local p=$(get_perm "$ps"); [ $(( ${p: -1} & 1 )) -ne 0 ] && result "SRV-010|취약|${ps} others 실행 권한 (${p})" || result "SRV-010|양호|${ps} others 실행 권한 없음 (${p})"; fi ;;
    sendmail)
        grep -iE '^\s*O\s+PrivacyOptions' "$_smtp_cf" 2>/dev/null | grep -qi "restrictqrun" && \
            result "SRV-010|양호|sendmail PrivacyOptions restrictqrun 설정" || \
            result "SRV-010|취약|sendmail restrictqrun 미설정" ;;
    exim)
        local ex=$(command -v exim exim4 2>/dev/null | head -1); local p=$(get_perm "$ex")
        [ -n "$ex" ] && [ $(( ${p: -1} & 1 )) -ne 0 ] && result "SRV-010|취약|${ex} others 실행 권한 (${p})" || result "SRV-010|양호|exim others 실행 권한 없음 (${p:-미확인})" ;;
    *) result "SRV-010|수동확인|${_smtp_type:-SMTP} 일반사용자 실행 방지 수동 확인" ;;
    esac
}

# ================================================================
# SRV-012: .netrc 파일 점검
# ================================================================
check_SRV012() {
    # 평가기준: .netrc 내부에 아이디·패스워드 등 민감 정보 (전 계정 홈)
    local homes f found="" sens=""
    homes=$(awk -F: '$6!=""{print $6}' /etc/passwd 2>/dev/null | sort -u)
    for f in $(for h in $homes /root; do echo "${h%/}/.netrc"; done | sort -u); do
        [ -f "$f" ] || continue
        found="${found} ${f}"
        grep -qiE '\b(login|password)\b' "$f" 2>/dev/null && sens="${sens} ${f}"
    done
    evd "SRV-012" "echo '${found:- (없음)}'"
    if [ -n "$sens" ]; then result "SRV-012|취약|.netrc 에 계정·비밀번호 정보:${sens}"
    elif [ -n "$found" ]; then result "SRV-012|수동확인|.netrc 파일 존재(login/password 미발견):${found} - 내용 확인"
    else result "SRV-012|양호|.netrc 파일 미존재"; fi
}

# ================================================================
# SRV-021: FTP 접근통제
# ================================================================
check_SRV021() {
    _ftp_running || { evd "SRV-021" "ps -ef 2>/dev/null | grep -E 'vsftpd|proftpd|ftpd' | grep -v grep"; result "SRV-021|N-A|FTP 서비스 미실행"; return; }
    evd "SRV-021" "grep -iE 'tcp_wrappers|listen_address' /etc/vsftpd.conf /etc/vsftpd/vsftpd.conf 2>/dev/null; grep -iE 'vsftpd|ftp|ALL' /etc/hosts.allow /etc/hosts.deny 2>/dev/null; grep -iA3 '<Limit LOGIN>' /etc/proftpd/proftpd.conf /etc/proftpd.conf 2>/dev/null"
    # 평가기준: 특정 IP/호스트에서만 접속하도록 접근제어
    local conf tw hw
    conf=$(ls /etc/vsftpd.conf /etc/vsftpd/vsftpd.conf 2>/dev/null | head -1)
    if [ -n "$conf" ]; then
        tw=$(grep -iE "^\s*tcp_wrappers" "$conf" 2>/dev/null | tail -1 | cut -d= -f2 | tr -d ' ')
        hw=$(grep -vE '^\s*#' /etc/hosts.allow /etc/hosts.deny 2>/dev/null | grep -iE 'vsftpd|^\s*ALL\s*:' | head -2)
        [ "${tw^^}" = "YES" ] && [ -n "$hw" ] && { result "SRV-021|양호|vsftpd tcp_wrappers=YES + hosts.allow/deny 규칙"; return; }
    fi
    grep -vE '^\s*#' /etc/proftpd/proftpd.conf /etc/proftpd.conf 2>/dev/null | grep -iA3 "<Limit LOGIN>" | grep -qiE "Allow from|Deny from" && { result "SRV-021|양호|proftpd <Limit LOGIN> 접근 IP 제한"; return; }
    # 평가기준 판단방법(UNIX): AIX /etc/ftpaccess.ctl, HP-UX /etc/ftpd/ftphosts·ftpaccess, SOL /etc/ftpd/ftpaccess
    evd "SRV-021" "grep -vE '^\s*(#|\$)' /etc/ftpaccess.ctl /etc/ftpd/ftphosts 2>/dev/null; grep -iE '^\s*(allow|deny|class)' /etc/ftpd/ftpaccess 2>/dev/null"
    grep -qiE '^\s*(allow|deny)\s*:' /etc/ftpaccess.ctl 2>/dev/null && { result "SRV-021|양호|AIX /etc/ftpaccess.ctl allow/deny 설정"; return; }
    grep -qiE '^\s*(allow|deny)\s' /etc/ftpd/ftphosts 2>/dev/null && { result "SRV-021|양호|/etc/ftpd/ftphosts allow/deny 설정"; return; }
    result "SRV-021|수동확인|FTP 접근 IP 제한(tcp_wrappers 규칙·방화벽) 수동 확인 (vsftpd tcp_wrappers=${tw:-미설정})"
}

# ================================================================
# SRV-037: TFTP 서비스
# ================================================================
check_SRV037() {
    # 평가기준: FTP 서비스 활성 시 취약 (FTPS 등 통신 암호화 적용 시 양호)
    evd "SRV-037" "ps -ef 2>/dev/null | grep -E 'vsftpd|proftpd|pure-ftpd|ftpd' | grep -v grep; ss -tln 2>/dev/null | grep ':21 '; grep -iE '^\s*(ssl_enable|force_local_logins_ssl|force_local_data_ssl)' /etc/vsftpd.conf /etc/vsftpd/vsftpd.conf 2>/dev/null; grep -iE '^\s*TLS(Engine|Required)' /etc/proftpd/proftpd.conf /etc/proftpd/tls.conf 2>/dev/null"
    _ftp_running || { result "SRV-037|양호|FTP 서비스 비활성"; return; }
    local conf
    conf=$(ls /etc/vsftpd.conf /etc/vsftpd/vsftpd.conf 2>/dev/null | head -1)
    if [ -n "$conf" ] && is_running vsftpd; then
        if grep -qiE '^\s*ssl_enable\s*=\s*YES' "$conf" && ! grep -qiE '^\s*force_local_logins_ssl\s*=\s*NO' "$conf"; then result "SRV-037|양호|vsftpd FTPS(ssl_enable=YES) 적용"
        else result "SRV-037|취약|vsftpd 평문 FTP 서비스 활성 (ssl_enable 미설정 또는 SSL 로그인 강제 해제)"; fi
    elif is_running proftpd; then
        if grep -hiE '^\s*TLSEngine\s+on' /etc/proftpd/proftpd.conf /etc/proftpd/tls.conf 2>/dev/null | grep -q . && grep -hiE '^\s*TLSRequired\s+on' /etc/proftpd/proftpd.conf /etc/proftpd/tls.conf 2>/dev/null | grep -q .; then
            result "SRV-037|양호|proftpd TLSEngine on + TLSRequired on"
        else result "SRV-037|취약|proftpd 평문 FTP 허용 (TLSRequired 미설정)"; fi
    else result "SRV-037|취약|FTP 서비스 활성 (FTPS 적용 확인 불가 - 적용 시 수동 판정 변경)"; fi
}

# ================================================================
# SRV-082: 시스템 주요 디렉터리 권한
# ================================================================
check_SRV082() {
    # 평가기준: /usr /bin /sbin /etc /var 에 others 쓰기 권한이 있으면 취약
    evd "SRV-082" "ls -alLd /usr /bin /sbin /etc /var 2>/dev/null"
    local vuln="" d p
    for d in /usr /bin /sbin /etc /var; do
        [ -e "$d" ] || continue
        p=$(get_perm "$(readlink -f "$d" 2>/dev/null || echo "$d")"); p=${p: -1}
        [ $(( ${p:-0} & 2 )) -ne 0 ] 2>/dev/null && vuln="${vuln} ${d}(others 쓰기)"
    done
    [ -n "$vuln" ] && result "SRV-082|취약|시스템 주요 디렉터리 others 쓰기 권한:${vuln}" || \
        result "SRV-082|양호|시스템 주요 디렉터리(/usr /bin /sbin /etc /var) others 쓰기 권한 없음"
}

# ================================================================
# SRV-083: 시작 스크립트 권한
# ================================================================
check_SRV083() {
    # 평가기준: 시스템 스타트업 스크립트에 others 쓰기 권한 존재 시 취약 (소유자는 참고)
    evd "SRV-083" "ls -ld /etc/init.d /etc/rc.d /etc/rc.local 2>/dev/null; ls -la /etc/init.d/ /etc/systemd/system/*.service 2>/dev/null | head -20"
    local vuln="" f p
    while IFS= read -r f; do
        [ -f "$f" ] || continue
        p=$(get_perm "$f"); [ $(( ${p: -1} & 2 )) -ne 0 ] && vuln="${vuln} ${f}(${p}, 소유자=$(get_owner "$f"))"
    done < <( { for d in /etc/init.d /etc/rc.d/init.d /etc/rc.d/rc2.d /etc/rc.d/rc3.d /etc/rc2.d /etc/rc3.d /sbin/init.d /sbin/rc2.d /sbin/rc3.d; do [ -d "$d" ] && ls -1 "$d" 2>/dev/null | sed "s#^#$d/#"; done; ls /etc/rc.local /etc/systemd/system/*.service 2>/dev/null; } | sort -u | head -300)
    [ -n "$vuln" ] && result "SRV-083|취약|others 쓰기 가능 스타트업 스크립트:${vuln}" || result "SRV-083|양호|스타트업 스크립트 others 쓰기 권한 없음"
}

# ================================================================
# SRV-094: Crontab 참조 파일 권한
# ================================================================
check_SRV094() {
    # 평가기준: crontab 에서 실행하는 참조 파일에 others 쓰기 권한이 있으면 취약
    evd "SRV-094" "cat /etc/crontab /etc/cron.d/* /var/spool/cron/* /var/spool/cron/crontabs/* 2>/dev/null | grep -vE '^\s*(#|$)' | head -30"
    local vuln="" refs f p
    refs=$( { cat /etc/crontab /etc/cron.d/* 2>/dev/null | grep -vE '^\s*(#|$|[A-Z_]+=)' | awk '{for(i=7;i<=NF;i++) print $i}'
              cat /var/spool/cron/* /var/spool/cron/crontabs/* 2>/dev/null | grep -vE '^\s*(#|$|[A-Z_]+=)' | awk '{for(i=6;i<=NF;i++) print $i}'
              ls /etc/cron.hourly/* /etc/cron.daily/* /etc/cron.weekly/* /etc/cron.monthly/* 2>/dev/null
            } | grep -E '^/' | sort -u)
    for f in $refs; do
        [ -f "$f" ] || continue
        p=$(get_perm "$f"); p=${p: -1}
        [ $(( ${p:-0} & 2 )) -ne 0 ] 2>/dev/null && vuln="${vuln} ${f}"
    done
    local n; n=$(echo "$refs" | grep -c .)
    [ -n "$vuln" ] && result "SRV-094|취약|crontab 참조파일 others 쓰기 권한:${vuln}" || \
        result "SRV-094|양호|crontab 참조파일 ${n}개 others 쓰기 권한 없음"
}

# ================================================================
# SRV-095: 소유자/그룹 없는 파일
# ================================================================
check_SRV095() {
    evd "SRV-095" "_to 60 find / \$_FP \\( -nouser -o -nogroup \\) ! -path '/proc/*' ! -path '/sys/*' -print 2>/dev/null | head -10"
    local found="" _rc
    found=$(set -o pipefail; _to 60 find / $_FP \( -nouser -o -nogroup \) ! -path "/proc/*" ! -path "/sys/*" ! -path "/dev/*" ! -path "/run/*" ! -path "/var/lib/docker/*" ! -path "/var/lib/containers/*" -print 2>/dev/null | head -10); _rc=$?
    [ "$_rc" = "141" ] && _rc=0   # head 조기 종료(SIGPIPE)는 정상
    if [ -n "$found" ]; then
        result "SRV-095|취약|소유자/그룹 없는 파일 존재: $(echo "$found" | tr '\n' ',' | head -c 150)"
    elif [ "$_rc" = "124" ]; then
        result "SRV-095|수동확인|파일 검색 시간 초과(60초) - 소유자 없는 파일 수동 확인"
    else
        result "SRV-095|양호|소유자/그룹 없는 파일 없음"
    fi
}

# ================================================================
# SRV-096: 사용자 환경변수 파일 권한
# ================================================================
check_SRV096() {
    # 평가기준: 사용자 환경 파일에 others 권한(읽기/쓰기/실행)이 하나라도 있으면 취약
    evd "SRV-096" "for h in \$(awk -F: '\$7!~/(nologin|false)\$/{print \$6}' /etc/passwd | sort -u); do ls -l \$h/.profile \$h/.bashrc \$h/.bash_profile \$h/.kshrc \$h/.cshrc \$h/.login \$h/.*shrc 2>/dev/null; done | sort -u | head -40"
    local vuln="" user uid homedir sh df p o
    while IFS=: read -r user _ uid _ _ homedir sh; do
        case "$sh" in *nologin|*false) continue ;; esac
        [ -z "$homedir" ] || [ "$homedir" = "/" ] || [ ! -d "$homedir" ] && continue
        for df in "$homedir"/.profile "$homedir"/.login "$homedir"/.bash_profile "$homedir"/.bash_login "$homedir"/.*shrc; do
            [ -f "$df" ] || continue
            p=$(get_perm "$df"); o=$(get_owner "$df")
            [ "${p: -1}" != "0" ] && vuln="${vuln} ${df}(${p})"
            [ "$o" != "$user" ] && [ "$o" != "root" ] && vuln="${vuln} ${df}(소유자=${o})"
        done
    done < /etc/passwd
    [ -n "$vuln" ] && result "SRV-096|취약|사용자 환경파일 others 권한/소유자 이상:${vuln}" || \
        result "SRV-096|양호|사용자 환경파일 others 권한 없음"
}

# ================================================================
# SRV-112: Cron 로깅 설정
# ================================================================
check_SRV112() {
    evd "SRV-112" "grep -i cron /etc/rsyslog.conf /etc/rsyslog.d/*.conf /etc/syslog.conf 2>/dev/null | grep -v '^#'; grep CRONLOG /etc/default/cron 2>/dev/null"
    local found=0
    grep -rqiE "^\s*cron" /etc/rsyslog.conf /etc/rsyslog.d/*.conf /etc/syslog.conf 2>/dev/null && found=1
    [ "$OS_FAMILY" = "AIX" ] && grep -vE '^\s*(#|\*)' /etc/syslog.conf 2>/dev/null | grep -qi "cron" && found=1
    [ "$OS_FAMILY" = "SOLARIS" ] && grep -q '^CRONLOG=YES' /etc/default/cron 2>/dev/null && found=1
    [ $found -eq 1 ] && result "SRV-112|양호|cron 로그 기록 설정 (syslog 또는 CRONLOG=YES)" || \
        result "SRV-112|취약|cron 로그 기록 미설정"
}

# ================================================================
# SRV-115: 로그 검토/보고
# ================================================================
check_SRV115() {
    evd "SRV-115" "ls -la /var/log/messages /var/log/secure /var/log/auth.log /var/log/syslog 2>/dev/null | head -5"
    evd "SRV-115" "last -5 2>/dev/null"
    result "SRV-115|수동확인|로그 검토 수행 여부 수동 확인"
}

# ================================================================
# SRV-134: 스택 실행 방지
# ================================================================
check_SRV134() {
    case "$OS_FAMILY" in
    SOLARIS)
        evd "SRV-134" "grep noexec_user_stack /etc/system 2>/dev/null; sxadm status nxstack 2>/dev/null"
        if [ "${OS_MAJOR:-10}" -ge 11 ] 2>/dev/null && sxadm status nxstack 2>/dev/null | grep -qi "enabled"; then result "SRV-134|양호|Solaris 11 sxadm nxstack enabled"
        elif grep -qE '^\s*set\s+noexec_user_stack\s*=\s*1' /etc/system 2>/dev/null; then result "SRV-134|양호|/etc/system noexec_user_stack=1"
        else result "SRV-134|취약|스택 실행 방지 미설정 (noexec_user_stack / sxadm nxstack)"; fi ;;
    *)
        evd "SRV-134" "grep -o -m1 -w nx /proc/cpuinfo 2>/dev/null"
        if grep -q "nx" /proc/cpuinfo 2>/dev/null; then result "SRV-134|양호|CPU NX 비트 지원 (스택 실행 방지 활성)"
        else result "SRV-134|N-A|Linux 커널 기본 NX 보호 (확인 불필요)"; fi ;;
    esac
}

# ================================================================
# SRV-135: TCP 보안 설정
# ================================================================
check_SRV135() {
    case "$OS_FAMILY" in
    SOLARIS)
        # 평가기준(Solaris): TCP_STRONG_ISS=2 양호, 0/1 취약
        evd "SRV-135" "grep TCP_STRONG_ISS /etc/default/inetinit 2>/dev/null; ipadm show-prop -p _strong_iss tcp 2>/dev/null"
        local v; v=$(grep -E '^\s*TCP_STRONG_ISS' /etc/default/inetinit 2>/dev/null | cut -d= -f2 | tr -d ' ')
        [ -z "$v" ] && v=$(ipadm show-prop -p _strong_iss -co current tcp 2>/dev/null)
        case "$v" in 2) result "SRV-135|양호|TCP_STRONG_ISS=2" ;; 0|1) result "SRV-135|취약|TCP_STRONG_ISS=${v} (2 필요)" ;; *) result "SRV-135|수동확인|TCP_STRONG_ISS 확인 불가" ;; esac ;;
    *)
        evd "SRV-135" "sysctl net.ipv4.tcp_syncookies net.ipv4.conf.all.accept_redirects net.ipv4.conf.all.accept_source_route 2>/dev/null"
        result "SRV-135|N-A|평가대상 아님 (Solaris 전용 TCP_STRONG_ISS)" ;;
    esac
}

# ================================================================
# SRV-147: 네트워크 모니터링 서비스
# ================================================================
check_SRV147() {
    # 평가기준: 불필요한 네트워크 모니터링 서비스(SNMP 등)가 '실행 중'이면 취약 (판단방법: ps -ef | grep snmp)
    evd "SRV-147" "ps -ef 2>/dev/null | grep -E '[s]nmpd|[t]cpdump|[t]shark|[w]ireshark|[n]map' ; which tcpdump tshark wireshark nmap 2>/dev/null"
    local run_mon run_snmp inst=""
    run_snmp=$(_snmp_run && echo snmpd)
    run_mon=$(_comm | grep -xE 'tcpdump|tshark|wireshark|nmap|dumpcap' | sort -u | tr '\n' ' ')
    for t in tcpdump tshark wireshark nmap; do command -v $t >/dev/null 2>&1 && inst="${inst} ${t}"; done
    if [ -n "$run_mon" ]; then result "SRV-147|취약|네트워크 모니터링 도구 실행 중: ${run_mon}"
    elif [ -n "$run_snmp" ]; then result "SRV-147|수동확인|SNMP 서비스(snmpd) 실행 중 - 업무상 필요 여부 확인${inst:+ (설치된 도구:${inst})}"
    else result "SRV-147|양호|네트워크 모니터링 서비스 미실행${inst:+ (설치만 된 도구:${inst})}"; fi
}

# ================================================================
# SRV-164: GID 없는 계정
# ================================================================
check_SRV164() {
    # 평가기준: 구성원이 존재하지 않는 GID(보조 구성원도 없고 어떤 계정의 기본 그룹도 아닌 그룹) 존재 시 취약
    evd "SRV-164" "awk -F: '\$4==\"\"{print \$1\":\"\$3}' /etc/group 2>/dev/null | head -40; awk -F: '{print \$4}' /etc/passwd | sort -u | tr '\n' ' '"
    local umin; umin=$(awk '/^\s*GID_MIN/{print $2}' /etc/login.defs 2>/dev/null)
    [ -z "$umin" ] && case "$OS_FAMILY" in AIX) umin=200 ;; SOLARIS|HPUX) umin=100 ;; *) umin=1000 ;; esac   # UNIX 신규 그룹 GID 대역
    local pg; pg=" $(awk -F: '{print $4}' /etc/passwd 2>/dev/null | sort -u | tr '\n' ' ') "
    local empty_user="" empty_sys=0 g gid mem
    while IFS=: read -r g _ gid mem; do
        [ -z "$mem" ] || continue
        case "$pg" in *" $gid "*) continue ;; esac
        if [ "$gid" -ge "$umin" ] 2>/dev/null && [ "$gid" -lt 60000 ] 2>/dev/null; then empty_user="${empty_user} ${g}(${gid})"
        else empty_sys=$((empty_sys+1)); fi
    done < /etc/group
    if [ -n "$empty_user" ]; then result "SRV-164|취약|구성원 없는 그룹(GID ${umin} 이상):${empty_user} - 불필요 시 제거"
    else result "SRV-164|양호|신규 생성 GID(${umin} 이상) 중 구성원 없는 그룹 없음 (시스템 기본 그룹 ${empty_sys}개는 참고)"; fi
}

# ================================================================
# SRV-166: 숨김 파일/디렉터리
# ================================================================
check_SRV166() {
    evd "SRV-166" "find /home /root -maxdepth 2 -name '.*' ! -name '.bashrc' ! -name '.bash_profile' ! -name '.profile' ! -name '.bash_logout' ! -name '.ssh' ! -name '.bash_history' -type f 2>/dev/null | head -10"
    result "SRV-166|수동확인|불필요 숨김 파일 수동 확인"
}

# ================================================================
# SRV-170: SMTP 정보 노출
# ================================================================
check_SRV170() {
    _smtp_running || { evd "SRV-170" "ps -ef 2>/dev/null | grep -E 'smtp|postfix|sendmail' | grep -v grep"; result "SRV-170|N-A|SMTP 서비스 미실행"; return; }
    _detect_smtp
    evd "SRV-170" "postconf smtpd_banner 2>/dev/null; grep -i SmtpGreetingMessage $_smtp_cf 2>/dev/null; exim -bP smtp_banner 2>/dev/null"
    case "$_smtp_type" in
    postfix)
        local ban=$(postconf -h smtpd_banner 2>/dev/null)
        echo "$ban" | grep -qiE 'mail_version|version|[0-9]+\.[0-9]+' && result "SRV-170|취약|postfix 배너에 버전 정보 노출: ${ban}" || result "SRV-170|양호|SMTP 배너 버전 정보 노출 없음 (${ban})" ;;
    sendmail)
        # 평가기준: SmtpGreetingMessage 에 $v 포함 시 버전 노출 — 미설정 시 기본값('$j Sendmail $v/$Z; $b')도 노출
        local greet=$(grep -iE "^\s*O\s+SmtpGreetingMessage" "$_smtp_cf" 2>/dev/null | tail -1)
        if [ -z "$greet" ]; then result "SRV-170|취약|SmtpGreetingMessage 미설정 (기본 인사말에 버전 \$v 포함)"
        elif echo "$greet" | grep -qE '\$v|\$Z'; then result "SRV-170|취약|sendmail 배너에 버전(\$v/\$Z) 노출"
        else result "SRV-170|양호|sendmail 배너 버전 미노출"; fi ;;
    exim)
        exim -bP smtp_banner 2>/dev/null | grep -q 'version_number' && result "SRV-170|취약|exim smtp_banner 에 \$version_number 포함" || result "SRV-170|양호|exim 배너 버전 미노출" ;;
    *) result "SRV-170|수동확인|${_smtp_type:-SMTP} 배너 정보 수동 확인" ;;
    esac
}

# ================================================================
# SRV-171: FTP 배너 정보 노출
# ================================================================
check_SRV171() {
    _ftp_running || { evd "SRV-171" "ps -ef 2>/dev/null | grep -E 'vsftpd|proftpd|ftpd' | grep -v grep"; result "SRV-171|N-A|FTP 서비스 미실행"; return; }
    evd "SRV-171" "grep -iE 'ftpd_banner|banner_file|ServerIdent' /etc/vsftpd.conf /etc/vsftpd/vsftpd.conf /etc/proftpd/proftpd.conf /etc/proftpd.conf 2>/dev/null"
    local c b
    if is_running vsftpd; then
        c=$(ls /etc/vsftpd.conf /etc/vsftpd/vsftpd.conf 2>/dev/null | head -1)
        b=$(grep -iE '^\s*(ftpd_banner|banner_file)\s*=' "$c" 2>/dev/null | tail -1)
        if [ -z "$b" ]; then result "SRV-171|취약|vsftpd 배너 미설정 (기본 배너에 vsFTPd 버전 노출)"
        elif echo "$b" | grep -qiE 'vsftpd|[0-9]+\.[0-9]+\.[0-9]+'; then result "SRV-171|취약|vsftpd 배너에 서비스명·버전 노출: ${b}"
        else result "SRV-171|양호|vsftpd 배너 설정 (${b%%=*})"; fi
    elif is_running proftpd; then
        b=$(grep -hiE '^\s*ServerIdent' /etc/proftpd/proftpd.conf /etc/proftpd.conf 2>/dev/null | tail -1)
        if echo "$b" | grep -qiE 'ServerIdent\s+off|ServerIdent\s+on\s+"'; then result "SRV-171|양호|proftpd ${b}"
        else result "SRV-171|취약|proftpd ServerIdent 미설정 (기본 'ProFTPD x.y.z Server' 노출)"; fi
    elif [ -f /etc/ftpd/ftpaccess ]; then   # HP-UX·Solaris in.ftpd(wu-ftpd 계열) greeting
        b=$(grep -iE '^\s*greeting' /etc/ftpd/ftpaccess 2>/dev/null | awk '{print tolower($2)}' | tail -1)
        case "$b" in
        brief|terse|text) result "SRV-171|양호|ftpaccess greeting ${b} (버전 미노출)" ;;
        full) result "SRV-171|취약|ftpaccess greeting full (서비스명·버전 노출)" ;;
        *) result "SRV-171|수동확인|ftpaccess greeting 미설정 - 접속 배너 서비스명·버전 노출 확인" ;;
        esac
    else
        [ "$OS_FAMILY" = "AIX" ] && evd "SRV-171" "dspcat /usr/lib/nls/msg/\${LANG:-C}/ftpd.cat 2>/dev/null | grep -i 'ftp server' | head -3"
        result "SRV-171|수동확인|FTP 배너 서비스명·버전 노출 수동 확인"; fi
}

# ================================================================
# SRV-173: DNS 동적 업데이트
# ================================================================
check_SRV173() {
    is_running named || { evd "SRV-173" "ps -ef 2>/dev/null | grep named | grep -v grep"; result "SRV-173|N-A|DNS 서비스 미실행"; return; }
    local nc; nc=$(_named_conf)
    evd "SRV-173" "echo '$(echo "$nc" | grep -iE 'allow-update' | head -5)'"
    echo "$nc" | grep -qiE 'allow-update\s*\{\s*any\s*;' && result "SRV-173|취약|DNS allow-update any 설정됨" || result "SRV-173|양호|DNS 동적 업데이트 제한됨"
}

# ================================================================
# SRV-174: 불필요 DNS 서비스
# ================================================================
check_SRV174() {
    evd "SRV-174" "ps -ef 2>/dev/null | grep -E 'named|dnsmasq' | grep -v grep | head -5"
    # 평가기준: DNS 서비스가 실행 중이지 않거나 업무상 필요한 경우 양호
    if is_running named || is_running dnsmasq; then
        result "SRV-174|수동확인|DNS 서비스 실행 중 - 업무 필요성 확인"
    else
        result "SRV-174|양호|DNS 서비스 미실행"
    fi
}

# ================================================================
# SRV-176: 비밀번호 저장 암호화 방식
# ================================================================
check_SRV176() {
    evd "SRV-176" "grep -E '^ENCRYPT_METHOD|^MD5_CRYPT_ENAB' /etc/login.defs 2>/dev/null; awk -F: '\$2!~/^[!*]/{print \$1,substr(\$2,1,3)}' /etc/shadow 2>/dev/null | head -10"
    local algo=$(grep -E '^\s*ENCRYPT_METHOD' /etc/login.defs 2>/dev/null | awk '{print $2}' | tail -1)
    local weak=""
    while IFS=: read -r user hash rest; do
        [ -z "$hash" ] || echo "$hash" | grep -qE '^\$|^[!*]|^$' || continue
        case "$hash" in
            \$1\$*) weak="${weak} ${user}(MD5)" ;;
            \$2*) ;;
            \$5\$*) ;;
            \$6\$*) ;;
            \$y\$*) ;;
            '!'*|'*'|'') ;;
            *) weak="${weak} ${user}(DES/unknown)" ;;
        esac
    done < /etc/shadow 2>/dev/null
    if [ -n "$weak" ]; then
        result "SRV-176|취약|취약 해시 사용 계정:${weak} (기본 algo=${algo:-미설정})"
    elif [ -n "$algo" ]; then
        result "SRV-176|양호|비밀번호 암호화 방식=${algo}"
    else
        result "SRV-176|수동확인|ENCRYPT_METHOD 미설정 - shadow 해시 수동 확인"
    fi
}

# 주요정보통신기반시설(U-시리즈)은 2026 상세가이드 전용 스크립트 check_server_u.sh 가 담당 (u/all 모드에서 호출)


# ================================================================
# 추가 SRV 항목 (전자금융기반시설 전체 179항목 커버)
# ================================================================

# SRV-002: 패스워드 복잡성
check_SRV002() {
    evd "SRV-002" "grep -E '^\s*(PASS_MIN_LEN|MINLEN)' /etc/login.defs 2>/dev/null; grep -v '^#' $(get_pam_files) 2>/dev/null | grep -iE 'pam_pwquality|pam_cracklib'; cat /etc/security/pwquality.conf 2>/dev/null | grep -v '^#' | grep -v '^\s*$'"
    local minlen="" dcredit="" ucredit="" lcredit="" ocredit=""
    for pf in $(get_pam_files); do
        [ -f "$pf" ] || continue
        local ml=$(grep -v '^#' "$pf" 2>/dev/null | grep -oE 'minlen=[0-9]+' | head -1 | cut -d= -f2)
        [ -n "$ml" ] && minlen=$ml
    done
    if [ -f /etc/security/pwquality.conf ]; then
        [ -z "$minlen" ] && minlen=$(grep -E '^\s*minlen' /etc/security/pwquality.conf 2>/dev/null | grep -oE '[0-9]+' | head -1)
        dcredit=$(grep -E '^\s*dcredit' /etc/security/pwquality.conf 2>/dev/null | grep -oE '[-0-9]+' | head -1)
        ucredit=$(grep -E '^\s*ucredit' /etc/security/pwquality.conf 2>/dev/null | grep -oE '[-0-9]+' | head -1)
        lcredit=$(grep -E '^\s*lcredit' /etc/security/pwquality.conf 2>/dev/null | grep -oE '[-0-9]+' | head -1)
        ocredit=$(grep -E '^\s*ocredit' /etc/security/pwquality.conf 2>/dev/null | grep -oE '[-0-9]+' | head -1)
    fi
    [ -z "$minlen" ] && minlen=$(grep -E '^\s*PASS_MIN_LEN' /etc/login.defs 2>/dev/null | awk '{print $2}' | tail -1)
    local has_complexity=0
    grep -v '^#' $(get_pam_files) 2>/dev/null | grep -qiE 'pam_pwquality|pam_cracklib' && has_complexity=1
    if [ "${minlen:-0}" -ge 8 ] 2>/dev/null && [ $has_complexity -eq 1 ]; then
        result "SRV-002|양호|패스워드 복잡성 설정됨 (minlen=${minlen}, dcredit=${dcredit:--1}, ucredit=${ucredit:--1}, lcredit=${lcredit:--1}, ocredit=${ocredit:--1})"
    elif [ "${minlen:-0}" -ge 8 ] 2>/dev/null; then
        result "SRV-002|취약|패스워드 길이=${minlen} 이나 복잡성 모듈(pam_pwquality/cracklib) 미적용"
    else
        result "SRV-002|취약|패스워드 최소 길이=${minlen:-미설정} (8자리 이상 + 복잡성 필요)"
    fi
}

# SRV-017: 관리자 그룹 최소 계정
check_SRV017() {
    evd "SRV-017" "grep -E '^(wheel|sudo|admin|root):' /etc/group 2>/dev/null"
    local info="" total=0
    for grp in wheel sudo admin root; do
        local members=$(grep "^${grp}:" /etc/group 2>/dev/null | cut -d: -f4)
        if [ -n "$members" ]; then
            local cnt=$(echo "$members" | tr ',' '\n' | grep -v '^$' | wc -l)
            total=$((total + cnt))
            info="${info} ${grp}:[${members}](${cnt}명)"
        fi
    done
    [ "$total" -le 5 ] 2>/dev/null && result "SRV-017|양호|관리자 그룹 멤버 ${total}명${info}" || \
        result "SRV-017|취약|관리자 그룹 멤버 과다 (${total}명)${info}"
}

# SRV-018: su 제한
check_SRV018() {
    evd "SRV-018" "cat /etc/pam.d/su 2>/dev/null | grep -v '^#'"
    if grep -v "^#" /etc/pam.d/su 2>/dev/null | grep -qi "pam_wheel"; then
        local wg=$(grep -v "^#" /etc/pam.d/su 2>/dev/null | grep -i "pam_wheel" | grep -oE 'group=\S+' | cut -d= -f2 | head -1)
        result "SRV-018|양호|su pam_wheel 제한 설정됨 (그룹=${wg:-wheel})"
    else
        result "SRV-018|취약|su pam_wheel 미설정 (root 외 su 제한 없음)"
    fi
}

# SRV-019: 불필요 관리자 그룹 구성원
check_SRV019() {
    evd "SRV-019" "grep -E '^(wheel|sudo|admin):' /etc/group 2>/dev/null; id root 2>/dev/null"
    local info=""
    for grp in wheel sudo admin; do
        local members=$(grep "^${grp}:" /etc/group 2>/dev/null | cut -d: -f4)
        [ -n "$members" ] && info="${info} ${grp}:[${members}]"
    done
    [ -n "$info" ] && result "SRV-019|수동확인|관리자 그룹 구성원 확인:${info}" || \
        result "SRV-019|양호|관리자 그룹 구성원 없음"
}

# SRV-020: GID 없는 계정
check_SRV020() {
    evd "SRV-020" "awk -F: '{print \$1,\$4}' /etc/passwd 2>/dev/null | head -20"
    local found=""
    while IFS=: read -r user _ _ gid _ _ _; do
        getent group "$gid" >/dev/null 2>&1 || found="${found} ${user}(GID=${gid})"
    done < /etc/passwd 2>/dev/null
    [ -n "$found" ] && result "SRV-020|취약|존재하지 않는 GID:${found}" || \
        result "SRV-020|양호|모든 계정 GID 유효"
}

# SRV-023: 서비스 접근 IP/Port 제한
check_SRV023() {
    evd "SRV-023" "cat /etc/hosts.allow 2>/dev/null | grep -v '^#' | grep -v '^\s*$'; echo '---'; cat /etc/hosts.deny 2>/dev/null | grep -v '^#' | grep -v '^\s*$'; echo '---'; iptables -L -n 2>/dev/null | head -20; firewall-cmd --list-all 2>/dev/null"
    local ctrl=0
    [ -f /etc/hosts.deny ] && grep -qv "^#" /etc/hosts.deny 2>/dev/null && grep -qiE "ALL.*ALL|sshd" /etc/hosts.deny 2>/dev/null && ctrl=1
    iptables -L -n 2>/dev/null | grep -qiE "ACCEPT|DROP|REJECT" && ctrl=1
    firewall-cmd --state 2>/dev/null | grep -q "running" && ctrl=1
    [ $ctrl -eq 1 ] && result "SRV-023|수동확인|접근통제 설정 존재 (위 현황의 규칙 적정성 확인)" || \
        result "SRV-023|취약|TCP Wrapper/방화벽 접근통제 미설정"
}

# SRV-024: 계정 잠금
check_SRV024() {
    evd "SRV-024" "grep -v '^#' $(get_pam_files) 2>/dev/null | grep -iE 'pam_tally2|pam_faillock|faillock'; cat /etc/security/faillock.conf 2>/dev/null | grep -v '^#' | grep -v '^\s*$'"
    local lock=0 deny=""
    for pf in $(get_pam_files) /etc/pam.d/system-auth /etc/pam.d/password-auth /etc/pam.d/common-auth; do
        [ -f "$pf" ] || continue
        grep -v "^#" "$pf" 2>/dev/null | grep -qiE "pam_tally2|pam_faillock" && lock=1
        local d=$(grep -v "^#" "$pf" 2>/dev/null | grep -oE 'deny=[0-9]+' | head -1 | cut -d= -f2)
        [ -n "$d" ] && deny=$d
    done
    [ -z "$deny" ] && [ -f /etc/security/faillock.conf ] && deny=$(grep -E '^\s*deny' /etc/security/faillock.conf 2>/dev/null | grep -oE '[0-9]+' | head -1)
    if [ $lock -eq 1 ] && [ "${deny:-0}" -gt 0 ] 2>/dev/null; then
        result "SRV-024|양호|계정 잠금 설정됨 (deny=${deny})"
    elif [ $lock -eq 1 ]; then
        result "SRV-024|수동확인|잠금 모듈 로드되나 deny 값 확인 필요"
    else
        result "SRV-024|취약|계정 잠금 미설정 (pam_tally2/faillock 없음)"
    fi
}

# SRV-029: 불필요 서비스 (echo/discard/daytime/chargen)
check_SRV029() {
    evd "SRV-029" "systemctl list-unit-files 2>/dev/null | grep -iE 'echo|discard|daytime|chargen'; ls /etc/xinetd.d/ 2>/dev/null | grep -iE 'echo|discard|daytime|chargen'"
    local found=""
    for svc in echo-dgram echo-stream discard-dgram discard-stream daytime-dgram daytime-stream chargen-dgram chargen-stream; do
        if [ -f "/etc/xinetd.d/$svc" ]; then
            grep -q "disable.*=.*no" "/etc/xinetd.d/$svc" 2>/dev/null && found="${found} ${svc}(xinetd)"
        fi
        systemctl is-active "${svc}.socket" 2>/dev/null | grep -q "^active" && found="${found} ${svc}(systemd)"
    done
    [ -n "$found" ] && result "SRV-029|취약|불필요 서비스 활성화:${found}" || \
        result "SRV-029|양호|echo/discard/daytime/chargen 비활성화"
}

# SRV-030: NFS 비활성화
check_SRV030() {
    evd "SRV-030" "systemctl is-active nfs-server nfs 2>/dev/null; ps -ef 2>/dev/null | grep -E 'nfsd|rpc.nfsd' | grep -v grep"
    if is_running nfs-server || is_running nfs || is_running nfsd; then
        result "SRV-030|수동확인|NFS 서비스 실행 중 (업무 필요 여부 확인)"
    else
        result "SRV-030|양호|NFS 서비스 미실행"
    fi
}

# SRV-031: NFS 접근통제
check_SRV031() {
    evd "SRV-031" "cat /etc/exports 2>/dev/null; showmount -e 2>/dev/null"
    if [ ! -f /etc/exports ]; then
        result "SRV-031|양호|/etc/exports 미존재 (NFS 미사용)"; return
    fi
    local wide=""
    grep -v "^#" /etc/exports 2>/dev/null | grep -qE "\*|0\.0\.0\.0" && wide="yes"
    [ -n "$wide" ] && result "SRV-031|취약|NFS 전체 공유 허용 (* 또는 0.0.0.0)" || \
        result "SRV-031|수동확인|NFS exports 설정 확인 (위 현황 참조)"
}

# SRV-032: automountd 비활성화
check_SRV032() {
    evd "SRV-032" "systemctl is-active autofs 2>/dev/null; ps -ef 2>/dev/null | grep automount | grep -v grep"
    if is_running autofs || is_running automountd; then
        result "SRV-032|취약|automountd/autofs 서비스 실행 중"
    else
        result "SRV-032|양호|automountd/autofs 비활성화"
    fi
}

# SRV-033: 불필요 RPC 서비스
check_SRV033() {
    evd "SRV-033" "rpcinfo -p 2>/dev/null | head -20; ps -ef 2>/dev/null | grep -E 'rpc\\.cmsd|rpc\\.ttdbserverd|sadmind|rstatd|rusersd|rwalld|sprayd' | grep -v grep"
    local found=""
    for svc in rpc.cmsd rpc.ttdbserverd sadmind rstatd rusersd rwalld sprayd; do
        ps -ef 2>/dev/null | grep -v grep | grep -qw "$svc" && found="${found} ${svc}"
    done
    [ -n "$found" ] && result "SRV-033|취약|불필요 RPC 서비스:${found}" || \
        result "SRV-033|양호|불필요 RPC 서비스 미실행"
}

# SRV-036: Sendmail 일반사용자 실행 방지
check_SRV036() {
    evd "SRV-036" "ls -la /usr/sbin/sendmail /usr/lib/sendmail 2>/dev/null; grep -i restrictqrun /etc/mail/sendmail.cf /etc/sendmail.cf 2>/dev/null"
    if ! is_running sendmail; then
        result "SRV-036|양호|Sendmail 미실행"; return
    fi
    local vuln=""
    for sm in /usr/sbin/sendmail /usr/lib/sendmail; do
        [ -e "$sm" ] || continue
        local perm=$(get_perm "$sm")
        local other_x=$((${perm:-0} % 10))
        [ $((other_x & 1)) -eq 1 ] 2>/dev/null && vuln="${vuln} ${sm}(${perm})"
    done
    local cf=""
    for c in /etc/mail/sendmail.cf /etc/sendmail.cf; do [ -f "$c" ] && cf="$c" && break; done
    [ -n "$cf" ] && ! grep -qi "restrictqrun" "$cf" 2>/dev/null && vuln="${vuln} [restrictqrun 미설정]"
    [ -n "$vuln" ] && result "SRV-036|취약|Sendmail 실행방지 미흡:${vuln}" || \
        result "SRV-036|양호|Sendmail 실행 권한 제한됨"
}

# SRV-038: 웹서비스 디렉터리 리스팅
check_SRV038() {
    evd "SRV-038" "grep -riE 'Options.*Indexes|autoindex' /etc/httpd/conf/ /etc/apache2/ /etc/nginx/ 2>/dev/null | grep -v '^#' | head -10"
    local web_running=0
    is_running httpd || is_running apache2 && web_running=1
    is_running nginx && web_running=1
    if [ $web_running -eq 0 ]; then
        result "SRV-038|N-A|웹서비스 미실행"; return
    fi
    local vuln=""
    for cf in /etc/httpd/conf/httpd.conf /etc/apache2/apache2.conf /etc/apache2/sites-enabled/*.conf; do
        [ -f "$cf" ] || continue
        grep -v "^#" "$cf" 2>/dev/null | grep -qi "Options.*Indexes" && vuln="${vuln} ${cf}"
    done
    for cf in /etc/nginx/nginx.conf /etc/nginx/conf.d/*.conf /etc/nginx/sites-enabled/*; do
        [ -f "$cf" ] || continue
        grep -v "^#" "$cf" 2>/dev/null | grep -qi "autoindex.*on" && vuln="${vuln} ${cf}"
    done
    [ -n "$vuln" ] && result "SRV-038|취약|디렉터리 리스팅 활성화:${vuln}" || \
        result "SRV-038|양호|디렉터리 리스팅 비활성화"
}

# SRV-039: 웹프로세스 권한
check_SRV039() {
    evd "SRV-039" "grep -iE '^\s*(User|Group)' /etc/httpd/conf/httpd.conf /etc/apache2/envvars /etc/apache2/apache2.conf 2>/dev/null | grep -v '^#'; ps aux 2>/dev/null | grep -E 'httpd|apache2|nginx' | head -5"
    local web_running=0
    is_running httpd || is_running apache2 || is_running nginx && web_running=1
    if [ $web_running -eq 0 ]; then
        result "SRV-039|N-A|웹서비스 미실행"; return
    fi
    local web_user=$(ps aux 2>/dev/null | grep -E 'httpd|apache2|nginx' | grep -v grep | grep -v root | awk '{print $1}' | sort -u | head -1)
    if [ "$web_user" = "root" ] || [ -z "$web_user" ]; then
        local cfg_user=$(grep -iE '^\s*User\s' /etc/httpd/conf/httpd.conf /etc/apache2/apache2.conf 2>/dev/null | grep -v '^#' | awk '{print $NF}' | tail -1)
        [ "$cfg_user" = "root" ] && result "SRV-039|취약|웹프로세스 root 권한 실행" || \
            result "SRV-039|수동확인|웹프로세스 실행 사용자 확인 필요 (${cfg_user:-미확인})"
    else
        result "SRV-039|양호|웹프로세스 사용자=${web_user}"
    fi
}

# SRV-040: 상위 디렉터리 접근 금지
check_SRV040() {
    evd "SRV-040" "grep -riE 'AllowOverride|<Directory' /etc/httpd/conf/httpd.conf /etc/apache2/apache2.conf 2>/dev/null | grep -v '^#' | head -10"
    is_running httpd || is_running apache2 || { result "SRV-040|N-A|Apache 미실행"; return; }
    local vuln=""
    for cf in /etc/httpd/conf/httpd.conf /etc/apache2/apache2.conf; do
        [ -f "$cf" ] || continue
        grep -v "^#" "$cf" 2>/dev/null | grep -qi "AllowOverride.*All" && vuln="${vuln} ${cf}"
    done
    [ -n "$vuln" ] && result "SRV-040|수동확인|AllowOverride All 설정 확인:${vuln}" || \
        result "SRV-040|양호|AllowOverride 제한됨"
}

# SRV-041: 웹서비스 불필요 파일 제거
check_SRV041() {
    evd "SRV-041" "ls -d /var/www/manual /usr/share/httpd/manual /etc/httpd/conf.d/manual.conf /var/www/html/index.html 2>/dev/null"
    is_running httpd || is_running apache2 || { result "SRV-041|N-A|Apache 미실행"; return; }
    local found=""
    for d in /var/www/manual /usr/share/httpd/manual /usr/share/doc/apache2; do
        [ -d "$d" ] && found="${found} ${d}"
    done
    [ -f /etc/httpd/conf.d/manual.conf ] && found="${found} manual.conf"
    [ -n "$found" ] && result "SRV-041|취약|불필요 파일/디렉터리 존재:${found}" || \
        result "SRV-041|양호|불필요 매뉴얼/샘플 파일 미존재"
}

# SRV-042: 심볼릭 링크 사용 금지
check_SRV042() {
    evd "SRV-042" "grep -riE 'Options.*FollowSymLinks' /etc/httpd/conf/httpd.conf /etc/apache2/apache2.conf 2>/dev/null | grep -v '^#'"
    is_running httpd || is_running apache2 || { result "SRV-042|N-A|Apache 미실행"; return; }
    local vuln=""
    for cf in /etc/httpd/conf/httpd.conf /etc/apache2/apache2.conf; do
        [ -f "$cf" ] || continue
        grep -v "^#" "$cf" 2>/dev/null | grep -qi "Options.*FollowSymLinks" && \
            ! grep -v "^#" "$cf" 2>/dev/null | grep -qi "Options.*-FollowSymLinks" && vuln="${vuln} ${cf}"
    done
    [ -n "$vuln" ] && result "SRV-042|취약|FollowSymLinks 허용:${vuln}" || \
        result "SRV-042|양호|FollowSymLinks 제한됨"
}

# SRV-043: 파일 업로드/다운로드 제한
check_SRV043() {
    evd "SRV-043" "grep -riE 'LimitRequestBody|client_max_body_size' /etc/httpd/conf/ /etc/apache2/ /etc/nginx/ 2>/dev/null | grep -v '^#' | head -5"
    is_running httpd || is_running apache2 || is_running nginx || { result "SRV-043|N-A|웹서비스 미실행"; return; }
    local found=""
    grep -riE 'LimitRequestBody' /etc/httpd/conf/ /etc/apache2/ 2>/dev/null | grep -v "^#" | head -1 | grep -q "LimitRequestBody" && found="Apache"
    grep -riE 'client_max_body_size' /etc/nginx/ 2>/dev/null | grep -v "^#" | head -1 | grep -q "client_max_body_size" && found="${found:+$found/}Nginx"
    [ -n "$found" ] && result "SRV-043|양호|업로드 제한 설정됨 (${found})" || \
        result "SRV-043|취약|파일 업로드 크기 제한 미설정"
}

# SRV-044: 웹서비스 영역 분리
check_SRV044() {
    evd "SRV-044" "grep -iE '^\s*DocumentRoot' /etc/httpd/conf/httpd.conf /etc/apache2/sites-enabled/*.conf 2>/dev/null | grep -v '^#'; grep -iE '^\s*root\s' /etc/nginx/sites-enabled/* /etc/nginx/conf.d/*.conf 2>/dev/null | grep -v '^#'"
    is_running httpd || is_running apache2 || is_running nginx || { result "SRV-044|N-A|웹서비스 미실행"; return; }
    local docroot=""
    docroot=$(grep -iE '^\s*DocumentRoot' /etc/httpd/conf/httpd.conf /etc/apache2/sites-enabled/*.conf 2>/dev/null | grep -v '^#' | awk '{print $NF}' | tr -d '"' | tail -1)
    [ -z "$docroot" ] && docroot=$(grep -iE '^\s*root\s' /etc/nginx/sites-enabled/* /etc/nginx/conf.d/*.conf 2>/dev/null | grep -v '^#' | awk '{print $NF}' | tr -d ';' | tail -1)
    if [ "$docroot" = "/" ]; then
        result "SRV-044|취약|DocumentRoot=/ (루트 디렉터리 설정)"
    elif [ -n "$docroot" ]; then
        result "SRV-044|양호|DocumentRoot=${docroot}"
    else
        result "SRV-044|수동확인|DocumentRoot 확인 필요"
    fi
}

# SRV-045: 보안패치
check_SRV045() {
    evd "SRV-045" "uname -r; rpm -qa --last 2>/dev/null | head -10; apt list --upgradable 2>/dev/null | head -10; yum updateinfo summary 2>/dev/null | head -10"
    result "SRV-045|수동확인|최신 보안패치 적용 여부 수동 확인 (위 현황 참조)"
}

# SRV-046: 로그 검토/보고
check_SRV046() {
    evd "SRV-046" "ls -lt /var/log/syslog /var/log/messages /var/log/secure /var/log/auth.log /var/log/cron 2>/dev/null | head -10; last -5 2>/dev/null"
    result "SRV-046|수동확인|로그 정기 검토/보고 수동 확인 (위 현황 참조)"
}

# SRV-047: 시스템 로깅 설정
check_SRV047() {
    evd "SRV-047" "grep -vE '^#|^\s*$' /etc/rsyslog.conf /etc/rsyslog.d/*.conf /etc/syslog.conf 2>/dev/null | head -20"
    local logging=0
    for f in /etc/rsyslog.conf /etc/rsyslog.d/*.conf /etc/syslog.conf; do
        [ -f "$f" ] || continue
        grep -qiE "^auth|^authpriv|^kern|^cron" "$f" 2>/dev/null && logging=1
    done
    [ $logging -eq 1 ] && result "SRV-047|양호|시스템 로깅 설정됨 (auth/kern/cron)" || \
        result "SRV-047|취약|시스템 로깅 미설정"
}

# SRV-048: su 사용 로그
check_SRV048() {
    evd "SRV-048" "ls -la /var/log/sulog /var/log/auth.log /var/log/secure 2>/dev/null; grep -i 'SULOG_FILE\|su.*session' /etc/login.defs /etc/rsyslog.conf /etc/pam.d/su 2>/dev/null | grep -v '^#'"
    if [ -f /var/log/auth.log ] || [ -f /var/log/secure ]; then
        result "SRV-048|양호|su 사용 로그 기록됨 (auth.log/secure)"
    elif [ -f /var/log/sulog ]; then
        result "SRV-048|양호|su 사용 로그 기록됨 (/var/log/sulog)"
    else
        result "SRV-048|취약|su 사용 로그 미설정"
    fi
}

# SRV-049: 접속기록 파일 보호
check_SRV049() {
    evd "SRV-049" "ls -la /var/log/wtmp /var/log/btmp /var/log/lastlog /var/run/utmp 2>/dev/null"
    local vuln=""
    for f in /var/log/wtmp /var/log/btmp /var/log/lastlog; do
        [ -f "$f" ] || continue
        local perm=$(get_perm "$f") owner=$(get_owner "$f")
        [ "$owner" != "root" ] && vuln="${vuln} ${f}(소유자=${owner})"
        [ "${perm:-777}" -gt 644 ] 2>/dev/null && vuln="${vuln} ${f}(${perm})"
    done
    if [ -f /var/log/btmp ]; then
        local bp=$(get_perm "/var/log/btmp")
        [ "${bp:-777}" -gt 600 ] 2>/dev/null && vuln="${vuln} btmp(${bp},600이하필요)"
    fi
    [ -n "$vuln" ] && result "SRV-049|취약|접속기록 파일 권한 이상:${vuln}" || \
        result "SRV-049|양호|접속기록 파일 권한 적절"
}

# SRV-050: 로그인/로그아웃 기록
check_SRV050() {
    evd "SRV-050" "last -5 2>/dev/null; lastlog 2>/dev/null | head -15; ls -la /var/log/wtmp /var/log/lastlog 2>/dev/null"
    if [ -f /var/log/wtmp ] && [ -f /var/log/lastlog ]; then
        result "SRV-050|양호|로그인/로그아웃 기록 파일 존재 (wtmp/lastlog)"
    else
        result "SRV-050|취약|로그인/로그아웃 기록 파일 미존재"
    fi
}

# SRV-051: su 사용자 제한 (wheel 그룹)
check_SRV051() {
    evd "SRV-051" "grep -v '^#' /etc/pam.d/su 2>/dev/null | grep pam_wheel; grep '^wheel:' /etc/group 2>/dev/null"
    if grep -v "^#" /etc/pam.d/su 2>/dev/null | grep -qi "pam_wheel"; then
        local members=$(grep "^wheel:" /etc/group 2>/dev/null | cut -d: -f4)
        result "SRV-051|양호|su pam_wheel 제한됨 (wheel 멤버: ${members:-없음})"
    else
        result "SRV-051|취약|su 사용자 제한 미설정 (pam_wheel 없음)"
    fi
}

# SRV-052: SMTP 비활성화
check_SRV052() {
    evd "SRV-052" "systemctl is-active postfix sendmail exim4 2>/dev/null; ss -tlnp 2>/dev/null | grep ':25 '"
    _smtp_running && result "SRV-052|수동확인|SMTP 서비스 실행 중 (업무 필요 여부 확인)" || \
        result "SRV-052|양호|SMTP 서비스 미실행"
}

# SRV-053: SMTP Banner 정보 제한
check_SRV053() {
    _smtp_running || { result "SRV-053|N-A|SMTP 미실행"; return; }
    _detect_smtp
    evd "SRV-053" "postconf smtp_banner smtpd_banner 2>/dev/null; grep -i SmtpGreetingMessage /etc/mail/sendmail.cf /etc/sendmail.cf 2>/dev/null"
    case "$_smtp_type" in
    postfix)
        local banner=$(postconf -h smtpd_banner 2>/dev/null)
        echo "$banner" | grep -qiE "postfix|version|MTA" && \
            result "SRV-053|취약|SMTP 배너 버전 노출 (${banner})" || \
            result "SRV-053|양호|SMTP 배너 커스터마이징됨" ;;
    sendmail)
        local banner=$(grep -i "SmtpGreetingMessage\|O SmtpGreetingMessage" "$_smtp_cf" 2>/dev/null | head -1)
        [ -n "$banner" ] && result "SRV-053|수동확인|sendmail 배너=${banner}" || \
            result "SRV-053|취약|sendmail 배너 기본값 사용" ;;
    *) result "SRV-053|수동확인|${_smtp_type:-SMTP} 배너 수동 확인" ;;
    esac
}

# SRV-054: SMTP Relay 제한
check_SRV054() {
    _smtp_running || { result "SRV-054|N-A|SMTP 미실행"; return; }
    _detect_smtp
    evd "SRV-054" "postconf mynetworks smtpd_relay_restrictions smtpd_recipient_restrictions 2>/dev/null; grep -i relay /etc/mail/access 2>/dev/null | head -5"
    case "$_smtp_type" in
    postfix)
        local rr=$(postconf -h smtpd_relay_restrictions 2>/dev/null)
        local mn=$(postconf -h mynetworks 2>/dev/null)
        result "SRV-054|수동확인|postfix relay_restrictions=${rr:-미설정}, mynetworks=${mn:-미설정}" ;;
    sendmail)
        [ -f /etc/mail/access ] && result "SRV-054|수동확인|sendmail /etc/mail/access 존재 (relay 설정 확인)" || \
            result "SRV-054|취약|sendmail relay 제한 미설정 (/etc/mail/access 없음)" ;;
    *) result "SRV-054|수동확인|${_smtp_type:-SMTP} relay 설정 수동 확인" ;;
    esac
}

# SRV-055: SMTP ACCESS 설정
check_SRV055() {
    _smtp_running || { result "SRV-055|N-A|SMTP 미실행"; return; }
    _detect_smtp
    evd "SRV-055" "cat /etc/mail/access 2>/dev/null | grep -v '^#' | head -10; postconf smtpd_client_restrictions smtpd_sender_restrictions 2>/dev/null"
    case "$_smtp_type" in
    postfix)
        local cr=$(postconf -h smtpd_client_restrictions 2>/dev/null)
        [ -n "$cr" ] && result "SRV-055|수동확인|postfix client_restrictions=${cr}" || \
            result "SRV-055|취약|postfix 발송 제한 미설정" ;;
    sendmail)
        [ -f /etc/mail/access ] && [ -s /etc/mail/access ] && \
            result "SRV-055|수동확인|sendmail /etc/mail/access 설정 확인" || \
            result "SRV-055|취약|sendmail access DB 미설정" ;;
    *) result "SRV-055|수동확인|${_smtp_type:-SMTP} ACCESS 설정 수동 확인" ;;
    esac
}

# SRV-056: SMTP VRFY/EXPN 비활성화
check_SRV056() {
    _smtp_running || { result "SRV-056|N-A|SMTP 미실행"; return; }
    _detect_smtp
    evd "SRV-056" "postconf disable_vrfy_command 2>/dev/null; grep -i PrivacyOptions $_smtp_cf 2>/dev/null"
    case "$_smtp_type" in
    postfix)
        local val=$(postconf -h disable_vrfy_command 2>/dev/null)
        [ "$val" = "yes" ] && result "SRV-056|양호|postfix disable_vrfy_command=yes" || \
            result "SRV-056|취약|postfix disable_vrfy_command=${val:-no}" ;;
    sendmail)
        [ -n "$_smtp_cf" ] && grep -qi "PrivacyOptions.*noexpn\|PrivacyOptions.*novrfy\|PrivacyOptions.*goaway" "$_smtp_cf" 2>/dev/null && \
            result "SRV-056|양호|sendmail EXPN/VRFY 제한됨" || \
            result "SRV-056|취약|sendmail EXPN/VRFY 미제한" ;;
    *) result "SRV-056|수동확인|${_smtp_type:-SMTP} VRFY/EXPN 수동 확인" ;;
    esac
}

# SRV-057: SMTP TLS/보안
check_SRV057() {
    _smtp_running || { result "SRV-057|N-A|SMTP 미실행"; return; }
    _detect_smtp
    evd "SRV-057" "postconf smtpd_use_tls smtpd_tls_cert_file smtpd_tls_security_level 2>/dev/null; grep -i 'STARTTLS\|AuthMechanisms\|CACert' $_smtp_cf 2>/dev/null | head -5"
    case "$_smtp_type" in
    postfix)
        local tls=$(postconf -h smtpd_tls_security_level 2>/dev/null)
        local use_tls=$(postconf -h smtpd_use_tls 2>/dev/null)
        if [ "$tls" = "encrypt" ] || [ "$tls" = "may" ] || [ "$use_tls" = "yes" ]; then
            result "SRV-057|양호|SMTP TLS 설정됨 (level=${tls:-legacy}, use_tls=${use_tls})"
        else
            result "SRV-057|취약|SMTP TLS 미설정 (tls_security_level=${tls:-미설정})"
        fi ;;
    *) result "SRV-057|수동확인|${_smtp_type:-SMTP} TLS/보안 설정 수동 확인" ;;
    esac
}

# SRV-058: DNS 보안패치
check_SRV058() {
    is_running named || { result "SRV-058|N-A|DNS 미실행"; return; }
    evd "SRV-058" "named -v 2>/dev/null; rpm -qa bind 2>/dev/null; dpkg -l bind9 2>/dev/null | tail -1"
    local ver=$(named -v 2>/dev/null | grep -oE 'BIND [0-9][^ ]*' | head -1)
    result "SRV-058|수동확인|DNS ${ver:-버전 미확인} - 보안 패치 적용 여부 확인"
}

# SRV-059: DNS 영역전송 제한
check_SRV059() {
    is_running named || { result "SRV-059|N-A|DNS 미실행"; return; }
    evd "SRV-059" "grep -i allow-transfer /etc/named.conf /etc/bind/named.conf 2>/dev/null"
    for conf in /etc/named.conf /etc/bind/named.conf; do
        [ -f "$conf" ] || continue
        grep -q "allow-transfer.*none" "$conf" 2>/dev/null && { result "SRV-059|양호|Zone Transfer 차단"; return; }
        grep -q "allow-transfer" "$conf" 2>/dev/null && { result "SRV-059|수동확인|allow-transfer 허용 대상 확인"; return; }
        result "SRV-059|취약|Zone Transfer 제한 미설정"; return
    done
    result "SRV-059|수동확인|named.conf 수동 확인"
}

# SRV-060: DNS Dynamic Update 비활성화
check_SRV060() {
    is_running named || { result "SRV-060|N-A|DNS 미실행"; return; }
    evd "SRV-060" "grep -i allow-update /etc/named.conf /etc/bind/named.conf 2>/dev/null"
    local vuln=0
    for conf in /etc/named.conf /etc/bind/named.conf; do
        [ -f "$conf" ] || continue
        grep -v "^[[:space:]]*//" "$conf" | grep -v "^#" | grep -i "allow-update" | grep -qi "any" && vuln=1
        grep -v "^[[:space:]]*//" "$conf" | grep -v "^#" | grep -i "allow-update" | grep -qi "none" && { result "SRV-060|양호|DNS 동적 업데이트 차단"; return; }
    done
    [ $vuln -eq 1 ] && result "SRV-060|취약|DNS 동적 업데이트 any 허용" || \
        result "SRV-060|수동확인|allow-update 설정 확인 필요"
}

# SRV-061: DNS 최신 버전
check_SRV061() {
    is_running named || { result "SRV-061|N-A|DNS 미실행"; return; }
    evd "SRV-061" "named -v 2>/dev/null"
    local ver=$(named -v 2>/dev/null | grep -oE 'BIND [0-9][^ ]*' | head -1)
    result "SRV-061|수동확인|DNS ${ver:-버전 미확인} - 최신 버전 사용 여부 확인"
}


# SRV-065
check_SRV065() {
    evd "SRV-065" "ls -la /etc/cron.allow /etc/cron.deny /etc/at.allow /etc/at.deny 2>/dev/null; cat /etc/cron.allow 2>/dev/null; cat /etc/cron.deny 2>/dev/null"
    if [ -f /etc/cron.allow ]; then
        local perm=$(get_perm "/etc/cron.allow") owner=$(get_owner "/etc/cron.allow")
        [ "$owner" = "root" ] && [ "${perm:-777}" -le 640 ] 2>/dev/null && \
            result "SRV-065|양호|cron.allow 존재 (소유자=${owner}, 권한=${perm})" || \
            result "SRV-065|취약|cron.allow 권한 이상 (소유자=${owner}, 권한=${perm})"
    elif [ -f /etc/cron.deny ]; then
        result "SRV-065|수동확인|cron.deny만 존재 (cron.allow 권장)"
    else
        result "SRV-065|취약|cron.allow/cron.deny 미존재 (모든 사용자 cron 사용 가능)"
    fi
}

# SRV-067
check_SRV067() {
    evd "SRV-067" "cat /etc/motd 2>/dev/null | head -5; cat /etc/issue 2>/dev/null | head -3; cat /etc/issue.net 2>/dev/null | head -3; grep -i Banner /etc/ssh/sshd_config 2>/dev/null | grep -v '^#'"
    local found=0
    for f in /etc/motd /etc/issue /etc/issue.net; do
        [ -f "$f" ] && [ -s "$f" ] && found=1
    done
    grep -v '^#' /etc/ssh/sshd_config 2>/dev/null | grep -qi "^Banner" && found=1
    [ $found -eq 1 ] && result "SRV-067|양호|로그온 경고 메시지 설정됨" || \
        result "SRV-067|취약|로그온 경고 메시지 미설정 (/etc/motd, /etc/issue, SSH Banner 없음)"
}

# SRV-068
check_SRV068() {
    evd "SRV-068" "ls -la /etc/exports 2>/dev/null; cat /etc/exports 2>/dev/null"
    if [ ! -f /etc/exports ]; then
        result "SRV-068|N-A|/etc/exports 미존재"; return
    fi
    local perm=$(get_perm "/etc/exports") owner=$(get_owner "/etc/exports")
    if [ "$owner" != "root" ]; then
        result "SRV-068|취약|/etc/exports 소유자=${owner} (root 필요)"
    elif [ "${perm:-777}" -gt 644 ] 2>/dev/null; then
        result "SRV-068|취약|/etc/exports 권한=${perm} (644 이하 필요)"
    else
        result "SRV-068|양호|/etc/exports 소유자=${owner}, 권한=${perm}"
    fi
}

# SRV-071
check_SRV071() {
    evd "SRV-071" "grep -riE 'Indexes|autoindex' /etc/httpd/conf/ /etc/apache2/ /etc/nginx/ 2>/dev/null | grep -v '^#' | head -10"
    if ! is_running httpd && ! is_running apache2 && ! is_running nginx; then
        result "SRV-071|N-A|웹서버 미실행"; return
    fi
    local vuln=""
    for cf in /etc/httpd/conf/httpd.conf /etc/apache2/apache2.conf /etc/apache2/sites-enabled/*.conf; do
        [ -f "$cf" ] || continue
        grep -v '^\s*#' "$cf" 2>/dev/null | grep -qi "Options.*Indexes" && vuln="${vuln} ${cf}"
    done
    for cf in /etc/nginx/nginx.conf /etc/nginx/conf.d/*.conf /etc/nginx/sites-enabled/*; do
        [ -f "$cf" ] || continue
        grep -v '^\s*#' "$cf" 2>/dev/null | grep -qi "autoindex.*on" && vuln="${vuln} ${cf}"
    done
    [ -n "$vuln" ] && result "SRV-071|취약|디렉터리 인덱싱 활성화:${vuln}" || \
        result "SRV-071|양호|디렉터리 인덱싱 비활성화"
}

# SRV-076
check_SRV076() {
    is_running snmpd || { result "SRV-076|N-A|SNMP 미실행"; return; }
    evd "SRV-076" "grep -v '^#' /etc/snmp/snmpd.conf /etc/snmpd.conf 2>/dev/null | grep -iE 'com2sec|agentAddress|rocommunity|rwcommunity' | head -10"
    local acl=0
    for conf in /etc/snmpd.conf /etc/snmp/snmpd.conf; do
        [ -f "$conf" ] || continue
        grep -v '^#' "$conf" 2>/dev/null | grep -qiE 'com2sec.*[0-9]+\.[0-9]+|agentAddress.*udp:[0-9]' && acl=1
    done
    [ $acl -eq 1 ] && result "SRV-076|양호|SNMP 접근통제 설정됨 (IP 제한)" || \
        result "SRV-076|취약|SNMP 접근통제 미설정 (IP 제한 없음)"
}

# SRV-077
check_SRV077() {
    is_running snmpd || { result "SRV-077|N-A|SNMP 미실행"; return; }
    evd "SRV-077" "grep -v '^#' /etc/snmp/snmpd.conf /etc/snmpd.conf 2>/dev/null | grep -iE 'community|rocommunity|rwcommunity' | head -10"
    local vuln=""
    for conf in /etc/snmpd.conf /etc/snmp/snmpd.conf; do
        [ -f "$conf" ] || continue
        grep -v '^#' "$conf" 2>/dev/null | grep -qiE '(rocommunity|rwcommunity|community).*(public|private)' && vuln="$conf"
    done
    [ -n "$vuln" ] && result "SRV-077|취약|기본 커뮤니티 스트링 사용 (public/private) - ${vuln}" || \
        result "SRV-077|양호|기본 커뮤니티 스트링 미사용"
}

# SRV-085
check_SRV085() {
    evd "SRV-085" "echo \$PATH; grep -iE 'PATH=|export PATH' /etc/profile /root/.bashrc /root/.bash_profile 2>/dev/null | grep -v '^#' | head -10"
    if echo "$PATH" | tr ':' '\n' | grep -qx '\.'; then
        result "SRV-085|취약|PATH에 현재 디렉토리(.) 포함"
    else
        result "SRV-085|양호|PATH에 현재 디렉토리(.) 미포함"
    fi
}

# SRV-086
check_SRV086() {
    evd "SRV-086" "awk -F: '\$3>=500 || \$3==0 {print \$1,\$3,\$6}' /etc/passwd 2>/dev/null | head -20"
    local vuln="" min_uid=500
    [ -f /etc/debian_version ] && min_uid=1000
    while IFS=: read -r user _ uid _ _ homedir _; do
        [ "${uid:-0}" -lt "$min_uid" ] 2>/dev/null && [ "$uid" != "0" ] && continue
        [ -z "$homedir" ] || [ "$homedir" = "/" ] && continue
        [ -d "$homedir" ] || continue
        local perm=$(get_perm "$homedir") owner=$(get_owner "$homedir")
        [ "$owner" != "$user" ] && vuln="${vuln} ${homedir}(소유자=${owner})"
        [ "${perm:-0}" -gt 755 ] 2>/dev/null && vuln="${vuln} ${homedir}(${perm})"
    done < /etc/passwd 2>/dev/null
    [ -n "$vuln" ] && result "SRV-086|취약|홈 디렉토리 이상:${vuln}" || \
        result "SRV-086|양호|홈 디렉토리 소유자 및 권한 적절 (755 이하)"
}

# SRV-088
check_SRV088() {
    evd "SRV-088" "ls -la /etc/crontab /var/spool/cron/ /var/spool/cron/crontabs/ 2>/dev/null"
    local vuln=""
    if [ -f /etc/crontab ]; then
        local perm=$(get_perm "/etc/crontab")
        [ "${perm:-777}" -gt 640 ] 2>/dev/null && vuln="${vuln} /etc/crontab(${perm})"
    fi
    for d in /var/spool/cron /var/spool/cron/crontabs; do
        [ -d "$d" ] || continue
        local dperm=$(get_perm "$d")
        [ "${dperm:-777}" -gt 750 ] 2>/dev/null && vuln="${vuln} ${d}(${dperm})"
    done
    [ -n "$vuln" ] && result "SRV-088|취약|crontab 권한 이상:${vuln}" || \
        result "SRV-088|양호|crontab 파일 권한 적절 (640 이하)"
}

# SRV-089
check_SRV089() {
    evd "SRV-089" "ls -la /etc/hosts.equiv 2>/dev/null; cat /etc/hosts.equiv 2>/dev/null; find /home /root -name '.rhosts' -ls 2>/dev/null | head -10"
    local vuln=""
    [ -f /etc/hosts.equiv ] && vuln="${vuln} /etc/hosts.equiv"
    local rhosts=$(find /home /root -name '.rhosts' 2>/dev/null | head -5)
    [ -n "$rhosts" ] && vuln="${vuln} ${rhosts}"
    [ -n "$vuln" ] && result "SRV-089|취약|hosts.equiv/.rhosts 파일 존재:${vuln}" || \
        result "SRV-089|양호|hosts.equiv/.rhosts 파일 미존재"
}

# SRV-097
check_SRV097() {
    evd "SRV-097" "systemctl list-unit-files --type=service --state=enabled 2>/dev/null | head -30; chkconfig --list 2>/dev/null | grep ':on' | head -20"
    local cnt=$(systemctl list-unit-files --type=service --state=enabled 2>/dev/null | grep -c "enabled")
    result "SRV-097|수동확인|활성화된 서비스 ${cnt:-미확인}개 (불필요 서비스 확인 필요)"
}

# SRV-098
check_SRV098() {
    evd "SRV-098" "systemctl list-unit-files --type=service --state=enabled 2>/dev/null | head -40"
    local cnt=$(systemctl list-unit-files --type=service --state=enabled 2>/dev/null | grep -c "enabled")
    result "SRV-098|수동확인|활성 서비스 ${cnt:-미확인}개 - 최소 필요 서비스만 유지 확인"
}

# SRV-099
check_SRV099() {
    evd "SRV-099" "iptables -L -n 2>/dev/null | head -20; firewall-cmd --list-all 2>/dev/null; ufw status 2>/dev/null"
    local fw=0
    iptables -L -n 2>/dev/null | grep -qv "^Chain\|^target\|^$" && fw=1
    systemctl is-active firewalld >/dev/null 2>&1 && fw=1
    ufw status 2>/dev/null | grep -qi "active" && fw=1
    [ $fw -eq 1 ] && result "SRV-099|양호|네트워크 접근제어 설정됨 (방화벽 활성)" || \
        result "SRV-099|취약|네트워크 접근제어 미설정 (방화벽 비활성 또는 규칙 없음)"
}

# SRV-100
check_SRV100() {
    evd "SRV-100" "awk -F: '\$3<500 && \$3!=0 && \$7 !~ /nologin|false|sync/ {print \$1,\$3,\$7}' /etc/passwd 2>/dev/null"
    local vuln="" min_uid=500
    [ -f /etc/debian_version ] && min_uid=1000
    while IFS=: read -r user _ uid _ _ _ shell; do
        [ "$user" = "root" ] && continue
        [ "${uid:-999}" -ge "$min_uid" ] 2>/dev/null && continue
        case "$shell" in */nologin|*/false|/bin/false|/sbin/nologin|*/sync|"") ;; *) vuln="${vuln} ${user}(${shell})" ;; esac
    done < /etc/passwd 2>/dev/null
    [ -n "$vuln" ] && result "SRV-100|취약|시스템 계정 로그인 가능:${vuln}" || \
        result "SRV-100|양호|시스템 계정 로그인 제한됨 (nologin/false)"
}

# SRV-101
check_SRV101() {
    evd "SRV-101" "grep -i PermitRootLogin /etc/ssh/sshd_config 2>/dev/null | grep -v '^#'"
    local val=$(grep -v '^#' /etc/ssh/sshd_config 2>/dev/null | grep -i "PermitRootLogin" | awk '{print $2}' | tail -1)
    case "$val" in
        no|No|NO) result "SRV-101|양호|PermitRootLogin=no" ;;
        without-password|prohibit-password) result "SRV-101|양호|PermitRootLogin=${val} (키 인증만 허용)" ;;
        yes|Yes|YES) result "SRV-101|취약|PermitRootLogin=yes (root 원격접속 허용)" ;;
        "") result "SRV-101|취약|PermitRootLogin 미설정 (기본값 허용)" ;;
        *) result "SRV-101|수동확인|PermitRootLogin=${val}" ;;
    esac
}

# SRV-102
check_SRV102() {
    evd "SRV-102" "grep -rh TMOUT /etc/profile /etc/bashrc /root/.bashrc 2>/dev/null | grep -v '^#'; grep -i ClientAlive /etc/ssh/sshd_config 2>/dev/null | grep -v '^#'"
    local tmout=""
    for f in /etc/profile /etc/bashrc /etc/bash.bashrc /etc/environment /root/.bashrc /root/.profile; do
        [ -f "$f" ] || continue
        local t=$(grep -h 'TMOUT' "$f" 2>/dev/null | grep -v '^#' | grep -oE '[0-9]+' | head -1)
        [ -n "$t" ] && tmout=$t && break
    done
    local alive=$(grep -v '^#' /etc/ssh/sshd_config 2>/dev/null | grep -i "ClientAliveInterval" | awk '{print $2}' | tail -1)
    if [ -n "$tmout" ] && [ "$tmout" -le 600 ] 2>/dev/null; then
        result "SRV-102|양호|TMOUT=${tmout}초"
    elif [ -n "$alive" ] && [ "$alive" -le 600 ] 2>/dev/null && [ "$alive" -gt 0 ] 2>/dev/null; then
        result "SRV-102|양호|ClientAliveInterval=${alive}초"
    elif [ -n "$tmout" ]; then
        result "SRV-102|취약|TMOUT=${tmout}초 (600초 초과)"
    else
        result "SRV-102|취약|세션 타임아웃 미설정 (TMOUT/ClientAliveInterval 없음)"
    fi
}

# SRV-103
check_SRV103() {
    evd "SRV-103" "lastlog 2>/dev/null | head -30; awk -F: '\$7 !~ /nologin|false/ {print \$1,\$3,\$7}' /etc/passwd 2>/dev/null"
    local inactive=""
    while IFS= read -r line; do
        local user=$(echo "$line" | awk '{print $1}')
        [ -n "$user" ] && inactive="${inactive} ${user}"
    done < <(lastlog 2>/dev/null | awk 'NR>1 && /Never logged in/' | head -20)
    [ -n "$inactive" ] && result "SRV-103|수동확인|미로그인 계정:${inactive} (불필요 여부 검토)" || \
        result "SRV-103|수동확인|계정 목록 확인 (위 현황 참조)"
}

# SRV-104
check_SRV104() {
    evd "SRV-104" "grep -E '^wheel:|^sudo:|^admin:' /etc/group 2>/dev/null"
    local info="" total=0
    for grp in wheel sudo admin; do
        local members=$(grep "^${grp}:" /etc/group 2>/dev/null | cut -d: -f4)
        if [ -n "$members" ]; then
            local cnt=$(echo "$members" | tr ',' '\n' | grep -cv '^$')
            total=$((total + cnt))
            info="${info} ${grp}:[${members}](${cnt}명)"
        fi
    done
    [ "$total" -gt 5 ] 2>/dev/null && result "SRV-104|취약|관리자 그룹 멤버 과다(${total}명):${info}" || \
        result "SRV-104|양호|관리자 그룹 멤버(${total}명)${info}"
}

# SRV-105
check_SRV105() {
    evd "SRV-105" "grep -rh TMOUT /etc/profile /etc/bashrc 2>/dev/null | grep -v '^#'; grep -i ClientAliveCountMax /etc/ssh/sshd_config 2>/dev/null | grep -v '^#'"
    local tmout=""
    for f in /etc/profile /etc/bashrc /etc/bash.bashrc /root/.bashrc; do
        [ -f "$f" ] || continue
        local t=$(grep -h 'TMOUT' "$f" 2>/dev/null | grep -v '^#' | grep -oE '[0-9]+' | head -1)
        [ -n "$t" ] && tmout=$t && break
    done
    if [ -n "$tmout" ] && [ "$tmout" -le 600 ] 2>/dev/null; then
        result "SRV-105|양호|세션 종료 설정됨 (TMOUT=${tmout}초)"
    else
        result "SRV-105|취약|세션 종료 미설정 또는 600초 초과 (TMOUT=${tmout:-미설정})"
    fi
}

# SRV-106
check_SRV106() {
    evd "SRV-106" "awk -F: '\$3==0 {print \$1,\$3}' /etc/passwd 2>/dev/null"
    local found=$(awk -F: '$3==0 && $1!="root" {print $1}' /etc/passwd 2>/dev/null)
    [ -n "$found" ] && result "SRV-106|취약|root 외 UID 0 계정: $(echo $found | tr '\n' ',')" || \
        result "SRV-106|양호|root 외 UID 0 계정 없음"
}

# SRV-107
check_SRV107() {
    evd "SRV-107" "grep -E '^PASS_MIN_LEN|^MINLEN' /etc/login.defs 2>/dev/null; grep -iE 'pam_pwquality|pam_cracklib' $(get_pam_files) 2>/dev/null | grep -v '^#'"
    local minlen=$(grep -E '^\s*PASS_MIN_LEN' /etc/login.defs 2>/dev/null | awk '{print $2}' | tail -1)
    local pam_ml=$(grep -v '^#' $(get_pam_files) 2>/dev/null | grep -oE 'minlen=[0-9]+' | head -1 | cut -d= -f2)
    local elen=${pam_ml:-${minlen:-0}}
    [ "${elen:-0}" -ge 8 ] 2>/dev/null && result "SRV-107|양호|패스워드 최소 길이=${elen}" || \
        result "SRV-107|취약|패스워드 최소 길이=${elen:-미설정} (8자리 이상 필요)"
}

# SRV-110
check_SRV110() {
    evd "SRV-110" "_to 60 find / \$_FP \( -nouser -o -nogroup \) -print 2>/dev/null | head -20"
    local found=$(_to 60 find / $_FP \( -nouser -o -nogroup \) -print 2>/dev/null | grep -vE '^/proc|^/sys|^/dev|^/run' | head -10)
    [ -n "$found" ] && result "SRV-110|취약|소유자 없는 파일 존재: $(echo $found | head -c 200)" || \
        result "SRV-110|양호|소유자 없는 파일 미존재"
}

# SRV-111
check_SRV111() {
    evd "SRV-111" "cat /etc/logrotate.conf 2>/dev/null | head -15; ls -la /etc/logrotate.d/ 2>/dev/null | head -10; du -sh /var/log 2>/dev/null"
    if [ -f /etc/logrotate.conf ]; then
        local rotate=$(grep -E '^\s*rotate ' /etc/logrotate.conf 2>/dev/null | awk '{print $2}')
        result "SRV-111|수동확인|logrotate 설정됨 (보관=${rotate:-미확인}주기) - 정책 적합성 확인"
    else
        result "SRV-111|취약|logrotate 미설정 (로그 관리 부재)"
    fi
}

# SRV-113
check_SRV113() {
    evd "SRV-113" "iptables -L -n --line-numbers 2>/dev/null | head -30; firewall-cmd --list-all 2>/dev/null; ufw status verbose 2>/dev/null"
    local fw=0
    iptables -L -n 2>/dev/null | grep -qvE '^Chain|^target|^$|ACCEPT.*anywhere.*anywhere' && fw=1
    systemctl is-active firewalld >/dev/null 2>&1 && fw=1
    ufw status 2>/dev/null | grep -qi "active" && fw=1
    [ $fw -eq 1 ] && result "SRV-113|양호|네트워크 접근통제 설정됨" || \
        result "SRV-113|취약|네트워크 접근통제 미설정 (방화벽 규칙 없음)"
}

# SRV-114
check_SRV114() {
    evd "SRV-114" "ls -la /etc/xinetd.d/ 2>/dev/null; grep -l 'disable.*no' /etc/xinetd.d/* 2>/dev/null"
    if [ ! -d /etc/xinetd.d ]; then
        result "SRV-114|양호|xinetd 미설치"; return
    fi
    local enabled=$(grep -l 'disable.*=.*no' /etc/xinetd.d/* 2>/dev/null | sed "s#.*/##")
    [ -n "$enabled" ] && result "SRV-114|수동확인|활성 xinetd 서비스: ${enabled} (필요 여부 확인)" || \
        result "SRV-114|양호|활성화된 xinetd 서비스 없음"
}

# SRV-116
check_SRV116() {
    evd "SRV-116" "systemctl is-active rsh.socket rlogin.socket rexec.socket 2>/dev/null; ps -ef 2>/dev/null | grep -E 'rshd|rlogind|rexecd|fingerd|in.fingerd' | grep -v grep"
    local vuln=""
    for svc in rsh rlogin rexec finger in.rshd in.rlogind in.rexecd in.fingerd; do
        is_running "$svc" && vuln="${vuln} ${svc}"
    done
    for sock in rsh.socket rlogin.socket rexec.socket; do
        systemctl is-active "$sock" >/dev/null 2>&1 && vuln="${vuln} ${sock}"
    done
    [ -n "$vuln" ] && result "SRV-116|취약|취약 서비스 실행 중:${vuln}" || \
        result "SRV-116|양호|rsh/rlogin/rexec/finger 서비스 미실행"
}

# SRV-117
check_SRV117() {
    evd "SRV-117" "auditctl -l 2>/dev/null | grep -iE 'useradd|userdel|passwd|groupadd|groupdel|shadow' | head -10; systemctl is-active auditd 2>/dev/null"
    if ! is_running auditd; then
        result "SRV-117|취약|auditd 미실행 (계정 감사 불가)"; return
    fi
    local rules=$(auditctl -l 2>/dev/null | grep -ciE 'useradd|userdel|passwd|groupadd|shadow')
    [ "${rules:-0}" -gt 0 ] 2>/dev/null && result "SRV-117|양호|계정 관련 감사 규칙 ${rules}개 설정됨" || \
        result "SRV-117|취약|계정 관련 감사 규칙 미설정 (useradd/userdel/passwd 추적 없음)"
}

# SRV-119
check_SRV119() {
    evd "SRV-119" "rpm -qa aide tripwire 2>/dev/null; dpkg -l aide tripwire 2>/dev/null | grep '^ii'; which aide tripwire ossec-control 2>/dev/null; aide --check 2>/dev/null | head -5"
    local tool=""
    command -v aide >/dev/null 2>&1 && tool="AIDE"
    command -v tripwire >/dev/null 2>&1 && tool="${tool} Tripwire"
    command -v ossec-control >/dev/null 2>&1 && tool="${tool} OSSEC"
    [ -n "$tool" ] && result "SRV-119|양호|파일 변경 감지 도구 설치됨 (${tool})" || \
        result "SRV-119|취약|파일 변경 감지 도구 미설치 (AIDE/Tripwire/OSSEC 없음)"
}

# SRV-120
check_SRV120() {
    evd "SRV-120" "getenforce 2>/dev/null; sestatus 2>/dev/null; aa-status 2>/dev/null | head -5; cat /etc/selinux/config 2>/dev/null | grep -v '^#'"
    local se=$(getenforce 2>/dev/null)
    local aa=$(aa-status 2>/dev/null | head -1)
    if [ "$se" = "Enforcing" ]; then
        result "SRV-120|양호|SELinux Enforcing 모드"
    elif [ "$se" = "Permissive" ]; then
        result "SRV-120|수동확인|SELinux Permissive 모드 (Enforcing 권장)"
    elif echo "$aa" | grep -qi "apparmor module is loaded"; then
        result "SRV-120|양호|AppArmor 활성화"
    else
        result "SRV-120|취약|SELinux/AppArmor 비활성 (보안 모듈 미적용)"
    fi
}

# SRV-123
check_SRV123() {
    evd "SRV-123" "grep -i Protocol /etc/ssh/sshd_config 2>/dev/null | grep -v '^#'; sshd -T 2>/dev/null | grep -i protocol"
    local proto=$(grep -v '^#' /etc/ssh/sshd_config 2>/dev/null | grep -i "^Protocol" | awk '{print $2}' | tail -1)
    if [ "$proto" = "1" ]; then
        result "SRV-123|취약|SSH Protocol 1 사용 (Protocol 2 필요)"
    elif [ "$proto" = "2" ] || [ -z "$proto" ]; then
        result "SRV-123|양호|SSH Protocol 2 사용 (${proto:-기본값})"
    else
        result "SRV-123|수동확인|SSH Protocol=${proto}"
    fi
}

# SRV-124
check_SRV124() {
    evd "SRV-124" "ls -la /etc/shadow 2>/dev/null; stat -c '%a %U' /etc/shadow 2>/dev/null"
    if [ ! -f /etc/shadow ]; then
        result "SRV-124|취약|/etc/shadow 미존재 (패스워드 파일 보호 불가)"; return
    fi
    local perm=$(get_perm "/etc/shadow") owner=$(get_owner "/etc/shadow")
    if [ "$owner" != "root" ]; then
        result "SRV-124|취약|/etc/shadow 소유자=${owner} (root 필요)"
    elif [ "${perm:-777}" -gt 640 ] 2>/dev/null; then
        result "SRV-124|취약|/etc/shadow 권한=${perm} (640 이하 필요)"
    else
        result "SRV-124|양호|/etc/shadow 소유자=${owner}, 권한=${perm}"
    fi
}

# SRV-126
check_SRV126() {
    evd "SRV-126" "grep -i MaxAuthTries /etc/ssh/sshd_config 2>/dev/null | grep -v '^#'"
    local val=$(grep -v '^#' /etc/ssh/sshd_config 2>/dev/null | grep -i "MaxAuthTries" | awk '{print $2}' | tail -1)
    if [ -z "$val" ]; then
        result "SRV-126|취약|MaxAuthTries 미설정 (기본값 6)"
    elif [ "$val" -le 5 ] 2>/dev/null; then
        result "SRV-126|양호|MaxAuthTries=${val}"
    else
        result "SRV-126|취약|MaxAuthTries=${val} (5 이하 권장)"
    fi
}

# SRV-128
check_SRV128() {
    evd "SRV-128" "ulimit -a 2>/dev/null; grep -v '^#' /etc/security/limits.conf 2>/dev/null | grep -v '^$' | head -15"
    local limits=$(grep -v '^#' /etc/security/limits.conf 2>/dev/null | grep -cv '^$')
    [ "${limits:-0}" -gt 0 ] 2>/dev/null && result "SRV-128|수동확인|limits.conf 설정 ${limits}줄 (적정성 확인)" || \
        result "SRV-128|수동확인|limits.conf 설정 없음 (기본값 사용 중)"
}

# SRV-129
check_SRV129() {
    evd "SRV-129" "ip link show 2>/dev/null | grep -i promisc; ifconfig -a 2>/dev/null | grep -i promisc"
    if ip link show 2>/dev/null | grep -qi "PROMISC"; then
        result "SRV-129|취약|Promiscuous 모드 인터페이스 발견"
    else
        result "SRV-129|양호|Promiscuous 모드 인터페이스 없음"
    fi
}

# SRV-130
check_SRV130() {
    evd "SRV-130" "ss -tlnp 2>/dev/null | head -30; netstat -tlnp 2>/dev/null | head -30"
    local cnt=$(ss -tlnp 2>/dev/null | grep -c "LISTEN")
    result "SRV-130|수동확인|리스닝 서비스 ${cnt:-미확인}개 (불필요 서비스 확인)"
}

# SRV-132
check_SRV132() {
    evd "SRV-132" "timedatectl 2>/dev/null; chronyc sources 2>/dev/null | head -5; ntpq -p 2>/dev/null | head -5; systemctl is-active chronyd ntpd 2>/dev/null"
    if command -v timedatectl >/dev/null 2>&1; then
        local sync=$(timedatectl 2>/dev/null | grep -ciE 'NTP sync.*yes|System clock sync.*yes')
        [ "${sync:-0}" -ge 1 ] && { result "SRV-132|양호|NTP 동기화 활성화"; return; }
    fi
    is_running chronyd && { result "SRV-132|양호|chrony 실행 중"; return; }
    is_running ntpd && { result "SRV-132|양호|ntpd 실행 중"; return; }
    result "SRV-132|취약|NTP 시간 동기화 미설정"
}

# SRV-136
check_SRV136() {
    evd "SRV-136" "systemctl is-active auditd 2>/dev/null; auditctl -l 2>/dev/null | head -20"
    if is_running auditd; then
        local rules=$(auditctl -l 2>/dev/null | wc -l)
        [ "${rules:-0}" -gt 0 ] 2>/dev/null && result "SRV-136|양호|auditd 활성, 규칙 ${rules}개" || \
            result "SRV-136|취약|auditd 실행 중이나 감사 규칙 없음"
    else
        result "SRV-136|취약|auditd 미실행 (감사 로그 미설정)"
    fi
}

# SRV-137
check_SRV137() {
    evd "SRV-137" "grep -E 'max_log_file|num_logs|log_file' /etc/audit/auditd.conf 2>/dev/null | grep -v '^#'; ls -la /etc/logrotate.d/audit* 2>/dev/null"
    if [ -f /etc/audit/auditd.conf ]; then
        local maxf=$(grep -i 'max_log_file ' /etc/audit/auditd.conf 2>/dev/null | grep -v '^#' | awk -F= '{print $2}' | tr -d ' ')
        local numl=$(grep -i 'num_logs' /etc/audit/auditd.conf 2>/dev/null | grep -v '^#' | awk -F= '{print $2}' | tr -d ' ')
        result "SRV-137|수동확인|auditd 로그 관리: max_log_file=${maxf:-미설정}MB, num_logs=${numl:-미설정}"
    else
        result "SRV-137|취약|auditd.conf 미존재 (감사 로그 백업 미설정)"
    fi
}

# SRV-138
check_SRV138() {
    evd "SRV-138" "ls -la /var/log/faillog /var/log/btmp /var/log/tallylog 2>/dev/null; faillog -u root 2>/dev/null; lastb 2>/dev/null | tail -5"
    local found=0
    for f in /var/log/faillog /var/log/btmp /var/log/tallylog; do
        [ -f "$f" ] && found=1
    done
    [ $found -eq 1 ] && result "SRV-138|양호|로그인 실패 기록 파일 존재" || \
        result "SRV-138|취약|로그인 실패 기록 파일 미존재 (faillog/btmp 없음)"
}

# SRV-139
check_SRV139() {
    evd "SRV-139" "auditctl -l 2>/dev/null | wc -l; auditctl -l 2>/dev/null | head -20"
    if ! is_running auditd; then
        result "SRV-139|취약|auditd 미실행"; return
    fi
    local rules=$(auditctl -l 2>/dev/null | wc -l)
    [ "${rules:-0}" -ge 5 ] 2>/dev/null && result "SRV-139|수동확인|감사 규칙 ${rules}개 (범위 적절성 확인)" || \
        result "SRV-139|취약|감사 규칙 부족 (${rules:-0}개)"
}

# SRV-140
check_SRV140() {
    evd "SRV-140" "ls -ld /var/log/audit/ 2>/dev/null; ls -la /var/log/audit/audit.log 2>/dev/null"
    if [ -d /var/log/audit ]; then
        local perm=$(get_perm "/var/log/audit") owner=$(get_owner "/var/log/audit")
        if [ "$owner" = "root" ] && [ "${perm:-777}" -le 750 ] 2>/dev/null; then
            result "SRV-140|양호|감사 로그 디렉터리 보호됨 (소유자=${owner}, 권한=${perm})"
        else
            result "SRV-140|취약|감사 로그 디렉터리 보호 미흡 (소유자=${owner}, 권한=${perm})"
        fi
    else
        result "SRV-140|취약|/var/log/audit 디렉터리 미존재"
    fi
}

# SRV-141
check_SRV141() {
    evd "SRV-141" "grep -iE 'max_log_file|max_log_file_action|space_left_action' /etc/audit/auditd.conf 2>/dev/null | grep -v '^#'; du -sh /var/log/audit/ 2>/dev/null"
    if [ -f /etc/audit/auditd.conf ]; then
        local maxf=$(grep -i 'max_log_file ' /etc/audit/auditd.conf 2>/dev/null | grep -v '^#' | awk -F= '{print $2}' | tr -d ' ')
        local action=$(grep -i 'max_log_file_action' /etc/audit/auditd.conf 2>/dev/null | grep -v '^#' | awk -F= '{print $2}' | tr -d ' ')
        result "SRV-141|수동확인|감사 로그 용량: max=${maxf:-미설정}MB, action=${action:-미설정}"
    else
        result "SRV-141|취약|auditd.conf 미존재"
    fi
}

# SRV-143
check_SRV143() {
    evd "SRV-143" "lsmod 2>/dev/null | grep -iE 'dccp|sctp|rds|tipc'; cat /etc/modprobe.d/*.conf 2>/dev/null | grep -iE 'dccp|sctp|rds|tipc'; sysctl net.ipv6.conf.all.disable_ipv6 2>/dev/null"
    local loaded=""
    for mod in dccp sctp rds tipc; do
        lsmod 2>/dev/null | grep -qi "$mod" && loaded="${loaded} ${mod}"
    done
    if [ -n "$loaded" ]; then
        result "SRV-143|취약|불필요 프로토콜 모듈 로드됨:${loaded}"
    else
        result "SRV-143|양호|불필요 프로토콜 모듈 미로드 (dccp/sctp/rds/tipc)"
    fi
}

# SRV-145
check_SRV145() {
    evd "SRV-145" "rpm -qa aide tripwire 2>/dev/null; dpkg -l aide tripwire 2>/dev/null | grep '^ii'; which aide tripwire 2>/dev/null; ls -la /var/lib/aide/aide.db* /var/lib/tripwire/*.twd 2>/dev/null"
    local tool=""
    command -v aide >/dev/null 2>&1 && tool="AIDE"
    command -v tripwire >/dev/null 2>&1 && tool="${tool} Tripwire"
    rpm -qa 2>/dev/null | grep -q "aide\|tripwire" && tool="${tool} (RPM)"
    [ -n "$tool" ] && result "SRV-145|양호|파일 무결성 점검 도구: ${tool}" || \
        result "SRV-145|취약|파일 무결성 점검 도구 미설치"
}

# SRV-146
check_SRV146() {
    evd "SRV-146" "rpm -qa clamav 2>/dev/null; dpkg -l clamav 2>/dev/null | grep '^ii'; which clamscan freshclam 2>/dev/null; systemctl is-active clamav-daemon 2>/dev/null"
    local av=""
    command -v clamscan >/dev/null 2>&1 && av="ClamAV"
    command -v sophos >/dev/null 2>&1 && av="${av} Sophos"
    is_running clamd && av="${av} (clamd 실행중)"
    [ -n "$av" ] && result "SRV-146|양호|안티바이러스 설치됨 (${av})" || \
        result "SRV-146|수동확인|안티바이러스 미설치 (ClamAV 등 미발견 - 별도 솔루션 확인)"
}

# SRV-148
check_SRV148() {
    evd "SRV-148" "grep -i password /boot/grub2/grub.cfg /boot/grub/grub.cfg 2>/dev/null | head -5; grep -i SINGLE /etc/sysconfig/init /etc/default/grub 2>/dev/null; cat /etc/securetty 2>/dev/null | head -5"
    local grub_pw=0
    for f in /boot/grub2/grub.cfg /boot/grub/grub.cfg /boot/efi/EFI/*/grub.cfg; do
        [ -f "$f" ] && grep -qi "password" "$f" 2>/dev/null && grub_pw=1
    done
    [ -f /boot/grub2/user.cfg ] && grep -qi "GRUB2_PASSWORD" /boot/grub2/user.cfg 2>/dev/null && grub_pw=1
    [ $grub_pw -eq 1 ] && result "SRV-148|양호|GRUB 패스워드 설정됨" || \
        result "SRV-148|취약|GRUB 패스워드 미설정 (부팅 보안 미흡)"
}

# SRV-149
check_SRV149() {
    evd "SRV-149" "useradd -D 2>/dev/null | grep INACTIVE; awk -F: '\$7!=\"\" && \$7 !~ /nologin|false/ {print \$1,\$7}' /etc/shadow 2>/dev/null | head -10"
    local inactive=$(useradd -D 2>/dev/null | grep "INACTIVE" | awk -F= '{print $2}')
    if [ "${inactive:-}" = "-1" ] || [ -z "$inactive" ]; then
        result "SRV-149|취약|INACTIVE 미설정 (비활성 계정 자동 잠금 없음)"
    elif [ "${inactive:-0}" -ge 0 ] 2>/dev/null; then
        result "SRV-149|양호|INACTIVE=${inactive}일 (비활성 계정 자동 잠금)"
    else
        result "SRV-149|수동확인|INACTIVE=${inactive} (설정 확인 필요)"
    fi
}

# SRV-150
check_SRV150() {
    evd "SRV-150" "awk -F: '\$3<500 && \$3!=0 && \$7 !~ /nologin|false|sync/ {print \$1,\$3,\$7}' /etc/passwd 2>/dev/null"
    local vuln="" min_uid=500
    [ -f /etc/debian_version ] && min_uid=1000
    while IFS=: read -r user _ uid _ _ _ shell; do
        [ "$user" = "root" ] && continue
        [ "${uid:-999}" -ge "$min_uid" ] 2>/dev/null && continue
        case "$shell" in */nologin|*/false|/bin/false|/sbin/nologin|*/sync|"") ;; *) vuln="${vuln} ${user}(${shell})" ;; esac
    done < /etc/passwd 2>/dev/null
    [ -n "$vuln" ] && result "SRV-150|취약|시스템 계정 셸 미제한:${vuln}" || \
        result "SRV-150|양호|시스템 계정 셸 제한됨 (nologin/false)"
}

# SRV-151
check_SRV151() {
    evd "SRV-151" "systemctl is-active usbguard 2>/dev/null; cat /etc/modprobe.d/*.conf 2>/dev/null | grep -i usb; lsmod 2>/dev/null | grep usb_storage"
    local restricted=0
    systemctl is-active usbguard >/dev/null 2>&1 && restricted=1
    grep -rqi 'install usb-storage /bin/true\|blacklist usb-storage' /etc/modprobe.d/ 2>/dev/null && restricted=1
    [ $restricted -eq 1 ] && result "SRV-151|양호|외부 매체 접근 제한 설정됨" || \
        result "SRV-151|수동확인|외부 매체 제한 미설정 (USB 차단 정책 확인)"
}

# SRV-152
check_SRV152() {
    evd "SRV-152" "which monit nagios zabbix_agentd ossec-control 2>/dev/null; systemctl is-active zabbix-agent nagios monit 2>/dev/null; ps -ef 2>/dev/null | grep -iE 'monit|nagios|zabbix|prometheus|node_exporter' | grep -v grep | head -5"
    local tools=""
    for t in monit nagios zabbix_agentd node_exporter prometheus; do
        is_running "$t" && tools="${tools} ${t}"
    done
    command -v monit >/dev/null 2>&1 && tools="${tools} monit(설치)"
    [ -n "$tools" ] && result "SRV-152|양호|모니터링 도구:${tools}" || \
        result "SRV-152|수동확인|프로세스 모니터링 도구 미발견 (별도 솔루션 확인)"
}

# SRV-153
check_SRV153() {
    evd "SRV-153" "sysctl net.ipv4.ip_forward net.ipv4.conf.all.accept_source_route net.ipv4.conf.all.accept_redirects net.ipv4.icmp_echo_ignore_broadcasts 2>/dev/null; rpm -qa --last 2>/dev/null | head -5"
    local vuln=""
    local fwd=$(sysctl -n net.ipv4.ip_forward 2>/dev/null)
    [ "$fwd" = "1" ] && vuln="${vuln} ip_forward=1"
    local srcrt=$(sysctl -n net.ipv4.conf.all.accept_source_route 2>/dev/null)
    [ "$srcrt" = "1" ] && vuln="${vuln} accept_source_route=1"
    [ -n "$vuln" ] && result "SRV-153|취약|하드닝 미흡:${vuln}" || \
        result "SRV-153|양호|시스템 하드닝 기본 설정 적절"
}

# SRV-154
check_SRV154() {
    evd "SRV-154" "sysctl net.ipv4.conf.all.accept_redirects net.ipv4.conf.all.send_redirects net.ipv4.conf.all.log_martians net.ipv4.conf.default.rp_filter net.ipv4.tcp_syncookies 2>/dev/null"
    local vuln=""
    local redir=$(sysctl -n net.ipv4.conf.all.accept_redirects 2>/dev/null)
    [ "$redir" = "1" ] && vuln="${vuln} accept_redirects=1"
    local sendr=$(sysctl -n net.ipv4.conf.all.send_redirects 2>/dev/null)
    [ "$sendr" = "1" ] && vuln="${vuln} send_redirects=1"
    local syncook=$(sysctl -n net.ipv4.tcp_syncookies 2>/dev/null)
    [ "$syncook" = "0" ] && vuln="${vuln} tcp_syncookies=0"
    [ -n "$vuln" ] && result "SRV-154|취약|커널 보안 파라미터 미흡:${vuln}" || \
        result "SRV-154|양호|커널 보안 파라미터 적절"
}

# SRV-155
check_SRV155() {
    evd "SRV-155" "systemctl is-active firewalld iptables ufw 2>/dev/null; iptables -L -n 2>/dev/null | head -15; ufw status 2>/dev/null"
    local fw=""
    systemctl is-active firewalld >/dev/null 2>&1 && fw="firewalld"
    systemctl is-active iptables >/dev/null 2>&1 && fw="${fw} iptables"
    ufw status 2>/dev/null | grep -qi "active" && fw="${fw} ufw"
    iptables -L -n 2>/dev/null | grep -qvE '^Chain|^target|^$' && [ -z "$fw" ] && fw="iptables(규칙존재)"
    [ -n "$fw" ] && result "SRV-155|양호|방화벽 활성:${fw}" || \
        result "SRV-155|취약|방화벽 비활성 (firewalld/iptables/ufw 모두 비활성)"
}

# SRV-156
check_SRV156() {
    evd "SRV-156" "rpm -qa --last 2>/dev/null | head -10; apt list --upgradable 2>/dev/null | head -10; yum updateinfo summary 2>/dev/null | head -5; stat -c '%y' /var/lib/rpm/Packages /var/lib/dpkg/status 2>/dev/null"
    local last_update=""
    if [ -f /var/lib/rpm/Packages ]; then
        last_update=$(stat -c '%y' /var/lib/rpm/Packages 2>/dev/null | cut -d' ' -f1)
    elif [ -f /var/lib/dpkg/status ]; then
        last_update=$(stat -c '%y' /var/lib/dpkg/status 2>/dev/null | cut -d' ' -f1)
    fi
    result "SRV-156|수동확인|마지막 패키지 변경: ${last_update:-미확인} (패치 주기/절차 확인)"
}

# SRV-157
check_SRV157() {
    evd "SRV-157" "crontab -l 2>/dev/null | grep -iE 'backup|rsync|tar|dump'; ls /etc/cron.d/ 2>/dev/null | grep -i backup; ls -la /etc/cron.daily/*backup* /etc/cron.weekly/*backup* 2>/dev/null"
    local bak=""
    crontab -l 2>/dev/null | grep -qiE 'backup|rsync|tar|dump' && bak="crontab"
    ls /etc/cron.d/ 2>/dev/null | grep -qi backup && bak="${bak} cron.d"
    ls /etc/cron.daily/*backup* /etc/cron.weekly/*backup* 2>/dev/null | grep -q . && bak="${bak} cron.daily/weekly"
    [ -n "$bak" ] && result "SRV-157|수동확인|백업 설정 발견: ${bak} (주기/범위 확인)" || \
        result "SRV-157|수동확인|백업 cron 미발견 (별도 백업 솔루션 확인)"
}

# SRV-159
check_SRV159() {
    evd "SRV-159" "grep -i Banner /etc/ssh/sshd_config 2>/dev/null | grep -v '^#'; grep -i ftpd_banner /etc/vsftpd/vsftpd.conf /etc/vsftpd.conf 2>/dev/null; postconf smtpd_banner 2>/dev/null"
    local checked=0 configured=0
    if grep -v '^#' /etc/ssh/sshd_config 2>/dev/null | grep -qi "^Banner"; then configured=$((configured+1)); fi
    checked=$((checked+1))
    if is_running vsftpd; then
        checked=$((checked+1))
        for cf in /etc/vsftpd/vsftpd.conf /etc/vsftpd.conf; do
            [ -f "$cf" ] && grep -qi "ftpd_banner" "$cf" 2>/dev/null && configured=$((configured+1))
        done
    fi
    [ $configured -ge 1 ] && result "SRV-159|양호|서비스 배너 설정됨 (${configured}개 서비스)" || \
        result "SRV-159|취약|서비스 배너 미설정 (버전 정보 노출 가능)"
}

# SRV-160
check_SRV160() {
    evd "SRV-160" "grep -E '^PASS_MAX_DAYS|^PASS_MIN_DAYS|^PASS_WARN_AGE|^PASS_MIN_LEN' /etc/login.defs 2>/dev/null"
    local max=$(grep -E '^\s*PASS_MAX_DAYS' /etc/login.defs 2>/dev/null | awk '{print $2}' | tail -1)
    local min=$(grep -E '^\s*PASS_MIN_DAYS' /etc/login.defs 2>/dev/null | awk '{print $2}' | tail -1)
    local warn=$(grep -E '^\s*PASS_WARN_AGE' /etc/login.defs 2>/dev/null | awk '{print $2}' | tail -1)
    local vuln=""
    [ "${max:-99999}" -gt 90 ] 2>/dev/null && vuln="${vuln} MAX_DAYS=${max:-미설정}"
    [ "${min:-0}" -lt 1 ] 2>/dev/null && vuln="${vuln} MIN_DAYS=${min:-0}"
    [ "${warn:-0}" -lt 7 ] 2>/dev/null && vuln="${vuln} WARN_AGE=${warn:-0}"
    [ -n "$vuln" ] && result "SRV-160|취약|패스워드 정책 미흡:${vuln}" || \
        result "SRV-160|양호|패스워드 정책 적절 (MAX=${max}, MIN=${min}, WARN=${warn})"
}

# SRV-162
check_SRV162() {
    evd "SRV-162" "grep -E '/tmp|/var/tmp|/home|/dev/shm' /etc/fstab 2>/dev/null; mount 2>/dev/null | grep -E '/tmp|/var/tmp|/dev/shm'"
    local vuln=""
    for mp in /tmp /var/tmp /dev/shm; do
        local opts=$(mount 2>/dev/null | grep " ${mp} " | awk '{print $NF}')
        if [ -n "$opts" ]; then
            echo "$opts" | grep -q "nosuid" || vuln="${vuln} ${mp}(nosuid 미설정)"
            if [ "$mp" = "/tmp" ] || [ "$mp" = "/var/tmp" ]; then
                echo "$opts" | grep -q "noexec" || vuln="${vuln} ${mp}(noexec 미설정)"
            fi
        fi
    done
    [ -n "$vuln" ] && result "SRV-162|취약|마운트 옵션 미흡:${vuln}" || \
        result "SRV-162|양호|마운트 옵션 적절 (nosuid/noexec 설정)"
}

# SRV-167
check_SRV167() {
    evd "SRV-167" "cat /etc/exports 2>/dev/null; grep -v '^#' /etc/samba/smb.conf 2>/dev/null | grep -iE 'path|share' | head -10; showmount -e localhost 2>/dev/null"
    local shares=""
    [ -f /etc/exports ] && [ -s /etc/exports ] && shares="NFS"
    grep -qi '\[.*\]' /etc/samba/smb.conf 2>/dev/null && shares="${shares} Samba"
    [ -n "$shares" ] && result "SRV-167|수동확인|공유 설정 존재: ${shares} (불필요 공유 확인)" || \
        result "SRV-167|양호|NFS/Samba 공유 미설정"
}

# SRV-168
check_SRV168() {
    evd "SRV-168" "ls -la /etc/passwd /etc/shadow /etc/group /etc/gshadow /etc/ssh/sshd_config /etc/login.defs 2>/dev/null"
    local vuln=""
    local -A expected=(["/etc/passwd"]=644 ["/etc/shadow"]=640 ["/etc/group"]=644 ["/etc/gshadow"]=640 ["/etc/ssh/sshd_config"]=600)
    for f in "${!expected[@]}"; do
        [ -f "$f" ] || continue
        local perm=$(get_perm "$f") owner=$(get_owner "$f")
        [ "$owner" != "root" ] && vuln="${vuln} ${f}(소유자=${owner})"
        [ "${perm:-777}" -gt "${expected[$f]}" ] 2>/dev/null && vuln="${vuln} ${f}(${perm})"
    done
    [ -n "$vuln" ] && result "SRV-168|취약|설정파일 권한 이상:${vuln}" || \
        result "SRV-168|양호|주요 설정파일 권한 적절"
}

# SRV-169
check_SRV169() {
    evd "SRV-169" "find /home /root -name '.forward' -o -name '.exrc' -o -name '.netrc' 2>/dev/null | head -10"
    local found=$(find /home /root -name '.forward' -o -name '.exrc' -o -name '.netrc' 2>/dev/null | head -10)
    [ -n "$found" ] && result "SRV-169|취약|불필요 사용자 환경파일 존재: $(echo $found | head -c 200)" || \
        result "SRV-169|양호|.forward/.exrc/.netrc 파일 미존재"
}

# SRV-172
check_SRV172() {
    evd "SRV-172" "cat /etc/issue 2>/dev/null; cat /etc/issue.net 2>/dev/null; uname -a 2>/dev/null"
    local vuln=0
    for f in /etc/issue /etc/issue.net; do
        [ -f "$f" ] || continue
        grep -qiE 'kernel|ubuntu|centos|red hat|debian|amazon|suse' "$f" 2>/dev/null && vuln=1
    done
    [ $vuln -eq 1 ] && result "SRV-172|취약|배너에 OS/커널 정보 노출 (/etc/issue)" || \
        result "SRV-172|양호|배너에 시스템 정보 미노출"
}

# ── 실행 (SRV-001 ~ SRV-179 전체) ───────────────────────────────
check_SRV001
check_SRV002
check_SRV003
check_SRV004
check_SRV005
check_SRV006
check_SRV007
check_SRV008
check_SRV009
check_SRV010
check_SRV011
check_SRV012
check_SRV013
check_SRV014
check_SRV015
check_SRV016
check_SRV017
check_SRV018
check_SRV019
check_SRV020
check_SRV021
check_SRV022
check_SRV023
check_SRV024
check_SRV025
check_SRV026
check_SRV027
check_SRV028
check_SRV029
check_SRV030
check_SRV031
check_SRV032
check_SRV033
check_SRV034
check_SRV035
check_SRV036
check_SRV037
check_SRV038
check_SRV039
check_SRV040
check_SRV041
check_SRV042
check_SRV043
check_SRV044
check_SRV045
check_SRV046
check_SRV047
check_SRV048
check_SRV049
check_SRV050
check_SRV051
check_SRV052
check_SRV053
check_SRV054
check_SRV055
check_SRV056
check_SRV057
check_SRV058
check_SRV059
check_SRV060
check_SRV061
check_SRV062
check_SRV063
check_SRV064
check_SRV065
check_SRV066
check_SRV067
check_SRV068
check_SRV069
check_SRV070
check_SRV071
result "SRV-072|N-A|Windows 전용 항목 (Linux/Unix 해당 없음)"
check_SRV073
check_SRV074
check_SRV075
check_SRV076
check_SRV077
result "SRV-078|N-A|Windows Guest 계정 (Linux/Unix 해당 없음)"
result "SRV-079|N-A|Windows Everyone 권한 (Linux/Unix 해당 없음)"
result "SRV-080|N-A|Windows 프린터 드라이버 (Linux/Unix 해당 없음)"
check_SRV081
check_SRV082
check_SRV083
check_SRV084
check_SRV085
check_SRV086
check_SRV087
check_SRV088
check_SRV089
result "SRV-090|N-A|Windows 원격 레지스트리 (Linux/Unix 해당 없음)"
check_SRV091
check_SRV092
check_SRV093
check_SRV094
check_SRV095
check_SRV096
check_SRV097
check_SRV098
check_SRV099
check_SRV100
check_SRV101
check_SRV102
check_SRV103
check_SRV104
check_SRV105
check_SRV106
check_SRV107
check_SRV108
check_SRV109
check_SRV110
check_SRV111
check_SRV112
check_SRV113
check_SRV114
check_SRV115
check_SRV116
check_SRV117
check_SRV118
check_SRV119
check_SRV120
check_SRV121
check_SRV122
check_SRV123
check_SRV124
result "SRV-125|N-A|Windows 화면 보호기 (Linux/Unix 해당 없음)"
check_SRV126
check_SRV127
check_SRV128
check_SRV129
check_SRV130
check_SRV131
check_SRV132
check_SRV133
check_SRV134
check_SRV135
check_SRV136
check_SRV137
check_SRV138
check_SRV139
check_SRV140
check_SRV141
check_SRV142
check_SRV143
check_SRV144
check_SRV145
check_SRV146
check_SRV147
check_SRV148
check_SRV149
check_SRV150
check_SRV151
check_SRV152
check_SRV153
check_SRV154
check_SRV155
check_SRV156
check_SRV157
check_SRV158
check_SRV159
check_SRV160
check_SRV161
check_SRV162
check_SRV163
check_SRV164
check_SRV165
check_SRV166
check_SRV167
check_SRV168
check_SRV169
check_SRV170
check_SRV171
check_SRV172
check_SRV173
check_SRV174
check_SRV175
check_SRV176
check_SRV177
result "SRV-178|N-A|Windows 개인 키 passphrase (Linux/Unix 해당 없음)"
check_SRV179

# ── all 모드: 주요정보(2026 상세가이드) 점검을 check_server_u.sh 로 별도 실행 → 결과 /tmp/<호스트>_u.txt ──
if [ "$_MODE" = "all" ]; then
    if [ -f "$_SELF_DIR/check_server_u.sh" ]; then
        bash "$_SELF_DIR/check_server_u.sh" > "/tmp/${HN}_u.txt" 2>/dev/null
        echo "# 주요정보(U-01~U-67) 결과: /tmp/${HN}_u.txt / 증적: /tmp/${HN}_u_evidence.txt"
    else
        echo "# [경고] check_server_u.sh 없음 - 주요정보 점검 생략"
    fi
fi
_TOTAL=$((_CP + _CF + _CM + _CN))
echo "# ================================================================"
echo "# 점검 요약"
echo "#   총 점검 항목: ${_TOTAL}"
[ "$_TOTAL" -gt 0 ] 2>/dev/null && {
echo "#   양호:         ${_CP}  ($((_CP * 100 / _TOTAL))%)"
echo "#   취약:         ${_CF}  ($((_CF * 100 / _TOTAL))%)"
echo "#   수동확인:     ${_CM}"
echo "#   N-A:          ${_CN}"
}
echo "# ================================================================"
echo "# 점검 완료: $(date '+%Y-%m-%d %H:%M:%S')"
echo "# 증적 파일: ${_EVD}"
[ -n "$_RESF" ] && echo "# 결과 파일(자동 저장): ${_RESF}  ← 증적 파일과 함께 회수"
[ -n "$_TEEPID" ] && { exec >&- 2>/dev/null; wait "$_TEEPID" 2>/dev/null; sleep 1; }
exit 0
__VC_EOF_1__
# ── 내장: server/check_server_u.sh ──
cat > "$WORK/check_server_u.sh" <<'__VC_EOF_2__'
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
__VC_EOF_2__
# ── 내장: webwas/check_webwas.sh ──
cat > "$WORK/check_webwas.sh" <<'__VC_EOF_3__'
#!/bin/bash
[ -z "$BASH_VERSION" ] && exec bash "$0" "$@"   # sh/dash 로 실행 시 bash 로 재실행 (declare -A 등 bash 전용 문법)
unset LC_ALL; export LC_MESSAGES=C LC_TIME=C          # apt/lastlog 등 명령 출력·날짜를 영문 고정 (ko_KR 로케일 판정 차이 방지)
# ================================================================
# 웹서버/WAS(Unix/Linux) 보안 취약점 자동 점검 스크립트 v4.0
# ================================================================
#
# [용도]
#   전자금융기반시설·주요정보통신기반시설 웹서버 및 WAS 보안 점검.
#   기준: 전자금융기반시설 보안 취약점 평가기준 제2026-1호 [웹서버-WAS]
#         주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드(2026) [웹 서비스 WEB-01~26] (같은 실행에서 함께 출력)
#   Windows(IIS) 환경은 check_webwas.ps1 사용.
#
# [대상 소프트웨어]
#   웹서버: Apache / Nginx / WebtoB
#   WAS:    Tomcat / JEUS
#   OS:     Linux(RHEL/CentOS/Ubuntu) / AIX / HP-UX / Solaris
#
# [사전 조건]
#   - root 권한 필요 (sudo bash 또는 root 로그인)
#   - 웹서버/WAS가 설치되어 있어야 함 (자동 탐지)
#
# [실행 방법]
#   bash check_webwas.sh > /tmp/$(hostname)_webwas.txt
#
# [산출물]
#   1) 표준출력 — 파이프 구분자 결과 (파일로 리다이렉트)
#      형식: WST-항목코드|결과|근거설명  (전자금융)  /  WEB-항목코드|결과|근거설명  (주요정보 2026 가이드)
#      결과: 양호 / 취약 / 수동확인 / N-A
#   2) 증적 파일 — /tmp/<호스트명>_webwas_evidence.txt
#      점검 중 실행한 명령어·출력·판정 근거가 타임스탬프와 함께 기록됨
#
# ================================================================

# ── OS/서버 탐지 ────────────────────────────────────────────────
detect_os() {
    OS_FAMILY="LINUX"; OS_DISTRO="UNKNOWN"; OS_MAJOR=0
    case "$(uname -s)" in
    MINGW*|MSYS*|CYGWIN*)
        OS_FAMILY="WINDOWS"; OS_DISTRO="GITBASH"
        OS_MAJOR=$(uname -s | grep -oE '[0-9]+' | head -1); return ;;
    AIX)     OS_FAMILY="AIX";     OS_DISTRO="AIX";     OS_MAJOR=$(uname -v); return ;;
    SunOS)   OS_FAMILY="SOLARIS"; OS_DISTRO="SOLARIS"; OS_MAJOR=$(uname -r|cut -d.-f2); return ;;
    "HP-UX") OS_FAMILY="HPUX";    OS_DISTRO="HPUX";    OS_MAJOR=$(uname -r|cut -d.-f2); return ;;
    esac
    [ -f /etc/os-release ] && . /etc/os-release && case "$ID" in
        rhel|centos|rocky|almalinux) OS_DISTRO="RHEL"; OS_MAJOR="${VERSION_ID%%.*}" ;;
        ubuntu) OS_DISTRO="UBUNTU"; OS_MAJOR="${VERSION_ID%%.*}" ;;
        debian) OS_DISTRO="DEBIAN"; OS_MAJOR="${VERSION_ID}" ;;
        sles|suse) OS_DISTRO="SLES"; OS_MAJOR="${VERSION_ID%%.*}" ;;
        amzn)   OS_DISTRO="AMZN";  OS_MAJOR="${VERSION_ID}" ;;
        *)      OS_DISTRO="${ID:-UNKNOWN}"; OS_MAJOR="${VERSION_ID%%.*}" ;;
    esac
}
detect_os
HN=$(hostname 2>/dev/null || uname -n)
# ── 결과 사본 자동 저장: '> 파일' 리다이렉트를 빠뜨려도 판정 결과가 증적과 같은 위치에 남도록 표준출력을 복사 ──
# ── 점검 기준 선택: 인자 ef|mi|all (또는 1|2|3), 미지정 시 메뉴 / 터미널이 아니면(자동 실행) all ──
_KMODE="${1:-${CHECK_MODE:-}}"
if [ -z "$_KMODE" ]; then
    if [ -t 0 ]; then
        { echo "점검 기준을 선택하세요:"
          echo "  1) 전자금융기반시설 (WST-001~126)"
          echo "  2) 주요정보통신기반시설 2026 상세가이드 (WEB-01~WEB-26)"
          echo "  3) 전체 (두 기준 결과를 한 파일에)"
          printf "선택 [1/2/3] (Enter=3): "; } >&2
        read -r _sel; _KMODE="${_sel:-3}"
    else
        _KMODE="all"
    fi
fi
case "$(echo "$_KMODE" | tr 'A-Z' 'a-z')" in
1|ef|srv) _KMODE="ef" ;;
2|mi|kisa|u) _KMODE="mi" ;;
3|all) _KMODE="all" ;;
*) echo "사용법: $0 [ef|mi|all]  (ef=전자금융, mi=주요정보 2026 상세가이드, all=둘 다)" >&2; exit 1 ;;
esac
_RESF="/tmp/${HN}_webwas.txt"
if [ -z "$NO_RESULT_COPY" ] && ! [ /dev/fd/1 -ef "$_RESF" ] 2>/dev/null && ( : > "$_RESF" ) 2>/dev/null; then
    exec > >(tee "$_RESF"); _TEEPID=$!
else
    _RESF=""
fi

# 웹서버 종류 탐지
WEB_SRV=""  # apache/webtob/nginx/none
WAS_SRV=""  # tomcat/jeus/none
APACHE_CONF="" NGINX_CONF="" TOMCAT_HOME="" JEUS_HOME=""

# Apache 탐지
for d in /etc/httpd/conf /etc/apache2 /usr/local/apache/conf /usr/local/apache2/conf \
          /usr/local/httpd/conf /opt/httpd/conf; do
    [ -f "$d/httpd.conf" ] && APACHE_CONF="$d/httpd.conf" && WEB_SRV="apache" && break
    [ -f "$d/apache2.conf" ] && APACHE_CONF="$d/apache2.conf" && WEB_SRV="apache" && break
done
# Nginx 탐지
[ -z "$WEB_SRV" ] && [ -f /etc/nginx/nginx.conf ] && WEB_SRV="nginx" && NGINX_CONF="/etc/nginx/nginx.conf"
# WebtoB 탐지
[ -z "$WEB_SRV" ] && command -v wsadmin >/dev/null 2>&1 && WEB_SRV="webtob"

# Tomcat 탐지 - 실행중인 프로세스(catalina.base) 먼저, 없으면 설치 경로
for d in $(ps -eo args= 2>/dev/null | grep -oE '\-Dcatalina\.(base|home)=[^ ]+' | cut -d= -f2) \
         /opt/tomcat /usr/local/tomcat /srv/tomcat /var/lib/tomcat* /opt/apache-tomcat* \
         /home/*/tomcat* /home/*/apache-tomcat* /app/tomcat* /app/apache-tomcat*; do
    [ -f "$d/conf/server.xml" ] && TOMCAT_HOME="$d" && WAS_SRV="tomcat" && break
done
[ -z "$WAS_SRV" ] && [ -n "$CATALINA_HOME" ] && [ -f "$CATALINA_HOME/conf/server.xml" ] && \
    TOMCAT_HOME="$CATALINA_HOME" && WAS_SRV="tomcat"
# JEUS 탐지 (sudo 로 돌리면 JEUS_HOME 환경변수 없어서 프로세스에서도 찾음)
[ -z "$JEUS_HOME" ] && JEUS_HOME=$(ps -eo args= 2>/dev/null | grep -oE '\-Djeus\.home=[^ ]+' | head -1 | cut -d= -f2)
[ -z "$WAS_SRV" ] && [ -n "$JEUS_HOME" ] && WAS_SRV="jeus"

if [ "$OS_FAMILY" = "WINDOWS" ]; then
    echo "# [경고] Windows 환경(Git Bash)에서 실행됨 — Linux/Unix 전용 스크립트"
    echo "# [경고] Windows(IIS) 점검은 check_webwas.ps1 사용"
fi

echo "# ================================================================"
echo "# 점검 대상: ${HN}"
echo "# OS: ${OS_FAMILY} / ${OS_DISTRO} ${OS_MAJOR}"
echo "# OS 상세: $( ( [ -r /etc/os-release ] && . /etc/os-release 2>/dev/null && echo "${PRETTY_NAME:-$NAME $VERSION_ID}" ) || ( command -v oslevel >/dev/null 2>&1 && echo "AIX $(oslevel -s 2>/dev/null)" ) || ( [ -r /etc/release ] && head -1 /etc/release | sed 's/^ *//' ) || uname -sr 2>/dev/null)"
echo "# 커널: $(uname -r 2>/dev/null)$( [ "$(uname -s 2>/dev/null)" = SunOS ] && echo " / $(uname -v 2>/dev/null)")"
echo "# 웹서버: ${WEB_SRV:-미탐지}"
echo "# WAS: ${WAS_SRV:-미탐지}"
case "$_KMODE" in
ef)  echo "# 점검 기준: 전자금융기반시설 보안 취약점 평가기준 제2026-1호 [웹서버-WAS]" ;;
mi)  echo "# 점검 기준: 주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드(2026) [웹 서비스 WEB-01~WEB-26]" ;;
*)   echo "# 점검 기준: 전자금융기반시설 보안 취약점 평가기준 제2026-1호 [웹서버-WAS] + 주요정보통신기반시설 상세가이드(2026) [웹 서비스 WEB-01~WEB-26]" ;;
esac
echo "# 점검 일시: $(date '+%Y-%m-%d %H:%M:%S')"
echo "# ================================================================"

# ── 결과 카운터 ──────────────────────────────────────────────────
_CP=0; _CF=0; _CM=0; _CN=0

_EVD="/tmp/${HN}_webwas_evidence.txt"
# 증적 파일 쓰기 불가(다른 사용자 소유 기존 파일, /tmp 용량 부족 등) → 대체 경로 (쓰기 실패로 판정 중복 방지)
if ! ( : >> "$_EVD" ) 2>/dev/null; then
    _EVD=$(mktemp "${TMPDIR:-/tmp}/${HN}_evidence.XXXXXX" 2>/dev/null || echo "./${HN}_evidence_$$.txt")
    echo "# [경고] 기본 증적 파일에 쓸 수 없어 대체 경로 사용: $_EVD"
fi
_NONROOT=0; [ "$(id -u 2>/dev/null)" != "0" ] && { _NONROOT=1; echo "# [경고] root 권한 아님 — /etc/shadow·타 계정 홈 등 조회 불가 항목(WST 계정·환경파일·umask)은 수동확인 처리, root 로 재점검 권고"; }
echo "# ================================================================" > "$_EVD"
echo "# 웹서버/WAS 증적 파일 (감사 추적용)" >> "$_EVD"
echo "# 대상: ${HN} / ${OS_FAMILY} ${OS_DISTRO} ${OS_MAJOR}" >> "$_EVD"
echo "# 웹서버: ${WEB_SRV:-미탐지} / WAS: ${WAS_SRV:-미탐지}" >> "$_EVD"
echo "# 생성: $(date '+%Y-%m-%d %H:%M:%S')" >> "$_EVD"
echo "# ================================================================" >> "$_EVD"

# ── Windows 환경 조기 종료 ───────────────────────────────────────
if [ "$OS_FAMILY" = "WINDOWS" ]; then
    echo "# Windows 환경 — 전 항목 N-A 처리" >> "$_EVD"
    for _i in 001 002 003 004 005 006 007 008 009 010 011 012 013 014 015 \
              018 019 021 022 023 025 026 027 028 029 030 031 032 033 034 \
              035 036 037 038 039 040 041 042 043 044 045 046 047 048 049 \
              050 052 053 054 058 059 060 061 062 063 064 065 066 067 068 \
              069 070 071 072 073 074 075 076 077 078 079 080 081 082 083 \
              084 085 086 087 088 089 090 091 092 093 094 095 096 097 098 \
              099 100 101 102 103 104 105 106 107 108 109 110 111 112 113 \
              114 115 116 117 118 119 121 122 123 124 125 126; do
        _CN=$((_CN+1))
        echo "WST-${_i}|N-A|Windows 환경 — Linux/Unix 전용 항목"
        printf '[판정] WST-%s|N-A|Windows 환경 — Linux/Unix 전용 항목\n\n' "$_i" >> "$_EVD"
    done
    _TOTAL=$((_CP + _CF + _CM + _CN))
    echo "# ================================================================"
    echo "# 점검 요약 — 웹서버/WAS (WST)"
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

declare -A _INAME=(
    [WST-001]='안전한 네트워크 모니터링 서비스 사용'
    [WST-002]='네트워크 모니터링 서비스 접근통제 설정 적절성'
    [WST-003]='불필요한 SMTP 서비스 비활성화'
    [WST-004]='SMTP 서비스의 expn/vrfy 명령어 실행 제한 여부'
    [WST-005]='SMTP 서비스 로그 수준 설정 적절성'
    [WST-006]='SMTP 서비스 보안 패치 적용 여부'
    [WST-007]='SMTP 서비스의 DoS 방지 기능 설정 여부'
    [WST-008]='SMTP 서비스 스팸 메일 릴레이 제한 설정 여부'
    [WST-009]='SMTP 서비스의 메일 queue 처리 권한 설정 적절성'
    [WST-010]='시스템 관리자 계정의 FTP 사용 제한 여부'
    [WST-011]='.netrc 파일 내 중요 정보 미포함 여부'
    [WST-012]='Anonymous 계정의 FTP 서비스 접속 제한 여부'
    [WST-013]='NFS 접근통제 설정 적절성'
    [WST-014]='불필요한 NFS 서비스 비활성화'
    [WST-015]='불필요한 RPC 서비스 비활성화'
    [WST-016]='불필요한 하드디스크 기본 공유 비활성화'
    [WST-017]='공유 기능에 대한 접근통제 설정 적절성'
    [WST-018]='FTP 서비스 접근통제 설정 적절성'
    [WST-019]='계정의 비밀번호 미설정, 빈 암호 사용 관리 여부'
    [WST-020]='원격 터미널 서비스의 암호화 설정 적절성'
    [WST-021]='취약한 Telnet 인증 방식 사용 제한 여부'
    [WST-022]='hosts.equiv 또는 .rhosts 설정 제한 여부'
    [WST-023]='root 계정 원격 접속 제한 여부'
    [WST-024]='서비스 접근 IP 및 포트 제한 여부'
    [WST-025]='원격 터미널 접속 타임아웃 설정 여부'
    [WST-026]='SMB 세션 중단 관리 설정 여부'
    [WST-027]='계정 목록 및 네트워크 공유 이름 노출 방지 여부'
    [WST-028]='불필요한 서비스 비활성화'
    [WST-029]='취약한 서비스 비활성화'
    [WST-030]='취약한 FTP 서비스 비활성화'
    [WST-031]='웹 서비스 디렉터리 리스팅 방지 설정 여부'
    [WST-032]='웹 서비스 CGI 스크립트 관리 여부'
    [WST-033]='웹 서비스 상위 디렉터리 접근 제한 설정 여부'
    [WST-034]='웹 서비스 경로 내 불필요 파일 관리 여부'
    [WST-035]='웹 서비스 파일 업로드 및 다운로드 용량 제한 설정 여부'
    [WST-036]='웹 서비스 프로세스 권한 제한 여부'
    [WST-037]='웹 서비스 경로 설정 적절성'
    [WST-038]='웹 서비스 경로 내 불필요한 링크 파일 관리 여부'
    [WST-039]='불필요한 웹 서비스 비활성화'
    [WST-040]='웹 서비스 설정 파일 노출 방지 여부'
    [WST-041]='웹 서비스 경로 내 파일의 접근통제 설정 적절성'
    [WST-042]='웹 서비스의 불필요한 스크립트 매핑 제거'
    [WST-043]='웹 서비스 서버 명령 실행 기능 제한 설정 적절성'
    [WST-044]='웹 서비스 기본 계정(아이디 또는 비밀번호) 변경 여부'
    [WST-045]='DNS 서비스 정보 노출 방지 여부'
    [WST-046]='DNS Recursive Query 제한 설정 여부'
    [WST-047]='DNS 서비스 보안 패치 적용 여부'
    [WST-048]='DNS Zone Transfer 제한 설정 적절성'
    [WST-049]='비밀번호 관리정책 설정 적절성'
    [WST-050]='취약한 패스워드 저장 방식 사용 제한 여부'
    [WST-051]='기본 관리자 계정명(Administrator) 변경 여부'
    [WST-052]='관리자 그룹에 불필요한 사용자 제거'
    [WST-053]='불필요하거나 관리되지 않는 계정 제거'
    [WST-054]='비밀번호 복잡도 설정'
    [WST-055]='불필요한 Guest 계정 비활성화'
    [WST-056]='익명 사용자에게 부적절한 권한(Everyone) 제거'
    [WST-057]='일반 사용자의 프린터 드라이버 설치 제한 여부'
    [WST-058]='Crontab 설정파일 권한 설정 적절성'
    [WST-059]='시스템 주요 디렉터리 권한 설정 적절성'
    [WST-060]='시스템 스타트업 스크립트 권한 설정 적절성'
    [WST-061]='시스템 주요 파일 권한 설정 적절성'
    [WST-062]='설치된 C 컴파일러의 권한 설정 적절성'
    [WST-063]='불필요한 원격 레지스트리 서비스 비활성화'
    [WST-064]='불필요하게 SUID, SGID bit가 설정된 파일 제거'
    [WST-065]='사용자 홈 디렉터리 경로 및 권한 설정 적절성'
    [WST-066]='불필요한 world writable 파일 제거'
    [WST-067]='Crontab 참조파일 권한 설정 적절성'
    [WST-068]='존재하지 않는 소유자 및 그룹 권한을 가진 파일 또는 디렉터리 제거'
    [WST-069]='사용자 환경파일의 소유자 또는 권한 설정 적절성'
    [WST-070]='FTP 서비스 디렉터리 접근권한 설정 적절성'
    [WST-071]='불필요한 예약 작업 제거'
    [WST-072]='LAN Manager 인증 수준 적절성'
    [WST-073]='보안 채널 데이터 디지털 암호화 또는 서명 기능 설정 적절성'
    [WST-074]='불필요한 시작프로그램 제거'
    [WST-075]='로그에 대한 접근통제 및 관리 적절성'
    [WST-076]='시스템 주요 이벤트 로그 설정 적절성'
    [WST-077]='Cron 서비스 로깅 설정 적절성'
    [WST-078]='로그의 정기적 검토 및 보고 수행 여부'
    [WST-079]='“보안 감사를 수행할 수 없는 경우, 즉시 시스템 종료” 기능 비활성화'
    [WST-080]='주기적인 보안패치 및 벤더 권고사항 적용 여부'
    [WST-081]='백신 프로그램 업데이트 적용 여부'
    [WST-082]='root 계정의 PATH 환경변수 설정 적절성'
    [WST-083]='umask 설정 적절성'
    [WST-084]='최종 로그인 사용자 계정 노출 방지 여부'
    [WST-085]='화면보호기 설정 적절성'
    [WST-086]='자동 로그온 방지 설정 여부'
    [WST-087]='로그인 실패 횟수에 따른 접속 제한 설정'
    [WST-088]='NTFS 파일 시스템 사용 여부'
    [WST-089]='백신 프로그램 설치 여부'
    [WST-090]='SU 명령 사용가능 그룹 제한 설정 적절성'
    [WST-091]='Cron 서비스 사용 계정 제한 설정 적절성'
    [WST-092]='스택 영역 실행 방지 설정 여부'
    [WST-093]='TCP 보안 설정 여부'
    [WST-094]='로그온 단계에서 "시스템 종료" 기능 비활성화'
    [WST-095]='네트워크 서비스 접근 권한 적절성'
    [WST-096]='백업 및 복구 권한 설정 적절성'
    [WST-097]='시스템 자원 소유권 변경 권한 설정 적절성'
    [WST-098]='이동식 미디어 포맷 및 꺼내기 허용 정책 설정 적절성'
    [WST-099]='중복 UID가 부여된 계정 제한 여부'
    [WST-100]='/dev 경로에 불필요한 파일 제거'
    [WST-101]='불필요한 네트워크 모니터링 서비스 비활성화'
    [WST-102]='웹 서비스 정보 노출 방지 여부'
    [WST-103]='디스크 볼륨 암호화 적용 여부'
    [WST-104]='로컬 로그온 허용 계정 제한 여부'
    [WST-105]='익명 SID/이름 변환 설정 제한 여부'
    [WST-106]='원격터미널 접속 가능한 사용자 그룹 제한 여부'
    [WST-107]='불필요한 Telnet 서비스 비활성화'
    [WST-108]='ftpusers 파일의 소유자 및 권한 설정 적절성'
    [WST-109]='시스템 사용 주의사항 출력'
    [WST-110]='구성원이 존재하지 않는 GID 제거'
    [WST-111]='불필요하게 Shell이 부여된 계정 제거'
    [WST-112]='불필요한 숨김 파일 또는 디렉터리 제거'
    [WST-113]='SMTP 서비스 정보 노출 방지 여부'
    [WST-114]='FTP 서비스 정보 노출 방지 여부'
    [WST-115]='불필요한 시스템 자원 공유 제거'
    [WST-116]='DNS 서비스 동적 업데이트 설정 적절성'
    [WST-117]='불필요한 DNS 서비스 비활성화'
    [WST-118]='시간 동기화를 위한 NTP 설정'
    [WST-119]='sudo 명령어 접근 권한 설정 적절성'
    [WST-120]='개인 키 사용 시 passphrase 설정 여부'
    [WST-121]='웹 서비스 불필요한 프록시 설정 제한 여부'
    [WST-122]='웹 서비스 불필요한 SSI(Server Side Includes) 기능 비활성화'
    [WST-123]='웹 서비스 기본 에러 페이지 노출 방지 여부'
    [WST-124]='웹 서비스 부적절한 LDAP 알고리즘 설정 제한 여부'
    [WST-125]='웹 서비스 독립된 업로드 경로 및 권한 설정 여부'
    [WST-126]='서비스 지원이 종료된(EoS) 시스템 및 장비 교체 여부'
)
# ── 판정 라우팅 (평가기준 [웹서버-WAS] 기준) ──
# _PHASE=os    : check_server.sh 로직 재사용 → SRV 코드를 동일 판단기준의 WST 코드로 변환
# _PHASE=web   : 기존 웹 점검 중 평가기준 일치 항목만 반영, 그 외는 REF-(참고) 코드로 분리
# _PHASE=final : 평가기준 판단방법 기준 웹 고유 점검
declare -A _S2W=(
    [SRV-001]=WST-001
    [SRV-003]=WST-002
    [SRV-004]=WST-003
    [SRV-005]=WST-004
    [SRV-006]=WST-005
    [SRV-007]=WST-006
    [SRV-008]=WST-007
    [SRV-009]=WST-008
    [SRV-010]=WST-009
    [SRV-011]=WST-010
    [SRV-012]=WST-011
    [SRV-013]=WST-012
    [SRV-014]=WST-013
    [SRV-015]=WST-014
    [SRV-016]=WST-015
    [SRV-018]=WST-016
    [SRV-020]=WST-017
    [SRV-021]=WST-018
    [SRV-022]=WST-019
    [SRV-023]=WST-020
    [SRV-024]=WST-021
    [SRV-025]=WST-022
    [SRV-026]=WST-023
    [SRV-027]=WST-024
    [SRV-028]=WST-025
    [SRV-029]=WST-026
    [SRV-031]=WST-027
    [SRV-034]=WST-028
    [SRV-035]=WST-029
    [SRV-037]=WST-030
    [SRV-062]=WST-045
    [SRV-063]=WST-046
    [SRV-064]=WST-047
    [SRV-066]=WST-048
    [SRV-069]=WST-049
    [SRV-070]=WST-050
    [SRV-072]=WST-051
    [SRV-073]=WST-052
    [SRV-074]=WST-053
    [SRV-075]=WST-054
    [SRV-078]=WST-055
    [SRV-079]=WST-056
    [SRV-080]=WST-057
    [SRV-081]=WST-058
    [SRV-082]=WST-059
    [SRV-083]=WST-060
    [SRV-084]=WST-061
    [SRV-087]=WST-062
    [SRV-090]=WST-063
    [SRV-091]=WST-064
    [SRV-092]=WST-065
    [SRV-093]=WST-066
    [SRV-094]=WST-067
    [SRV-095]=WST-068
    [SRV-096]=WST-069
    [SRV-097]=WST-070
    [SRV-101]=WST-071
    [SRV-103]=WST-072
    [SRV-104]=WST-073
    [SRV-105]=WST-074
    [SRV-108]=WST-075
    [SRV-109]=WST-076
    [SRV-112]=WST-077
    [SRV-115]=WST-078
    [SRV-116]=WST-079
    [SRV-118]=WST-080
    [SRV-119]=WST-081
    [SRV-121]=WST-082
    [SRV-122]=WST-083
    [SRV-123]=WST-084
    [SRV-125]=WST-085
    [SRV-126]=WST-086
    [SRV-127]=WST-087
    [SRV-128]=WST-088
    [SRV-129]=WST-089
    [SRV-131]=WST-090
    [SRV-133]=WST-091
    [SRV-134]=WST-092
    [SRV-135]=WST-093
    [SRV-136]=WST-094
    [SRV-137]=WST-095
    [SRV-138]=WST-096
    [SRV-139]=WST-097
    [SRV-140]=WST-098
    [SRV-142]=WST-099
    [SRV-144]=WST-100
    [SRV-147]=WST-101
    [SRV-149]=WST-103
    [SRV-150]=WST-104
    [SRV-151]=WST-105
    [SRV-152]=WST-106
    [SRV-158]=WST-107
    [SRV-161]=WST-108
    [SRV-163]=WST-109
    [SRV-164]=WST-110
    [SRV-165]=WST-111
    [SRV-166]=WST-112
    [SRV-170]=WST-113
    [SRV-171]=WST-114
    [SRV-172]=WST-115
    [SRV-173]=WST-116
    [SRV-174]=WST-117
    [SRV-175]=WST-118
    [SRV-177]=WST-119
    [SRV-178]=WST-120
    [SRV-179]=WST-126
)
_NA_LINUX=" WST-016 WST-017 WST-020 WST-021 WST-026 WST-027 WST-032 WST-040 WST-041 WST-042 WST-043 WST-051 WST-055 WST-056 WST-057 WST-063 WST-070 WST-071 WST-072 WST-073 WST-074 WST-079 WST-081 WST-084 WST-085 WST-086 WST-088 WST-089 WST-092 WST-093 WST-094 WST-095 WST-096 WST-097 WST-098 WST-103 WST-104 WST-105 WST-106 WST-115 WST-120 "
_NA_AIX=" WST-016 WST-017 WST-020 WST-021 WST-026 WST-027 WST-032 WST-040 WST-041 WST-042 WST-043 WST-051 WST-055 WST-056 WST-057 WST-063 WST-070 WST-071 WST-072 WST-073 WST-074 WST-079 WST-081 WST-084 WST-085 WST-086 WST-088 WST-089 WST-092 WST-093 WST-094 WST-095 WST-096 WST-097 WST-098 WST-103 WST-104 WST-105 WST-106 WST-115 WST-120 "
_NA_SOLARIS=" WST-016 WST-017 WST-020 WST-021 WST-026 WST-027 WST-032 WST-040 WST-041 WST-042 WST-043 WST-051 WST-055 WST-056 WST-057 WST-063 WST-070 WST-071 WST-072 WST-073 WST-074 WST-079 WST-081 WST-084 WST-085 WST-086 WST-088 WST-089 WST-094 WST-095 WST-096 WST-097 WST-098 WST-103 WST-104 WST-105 WST-106 WST-115 WST-120 "
_NA_HPUX=" WST-016 WST-017 WST-020 WST-021 WST-026 WST-027 WST-032 WST-040 WST-041 WST-042 WST-043 WST-051 WST-055 WST-056 WST-057 WST-063 WST-070 WST-071 WST-072 WST-073 WST-074 WST-079 WST-081 WST-084 WST-085 WST-086 WST-088 WST-089 WST-092 WST-093 WST-094 WST-095 WST-096 WST-097 WST-098 WST-103 WST-104 WST-105 WST-106 WST-115 WST-120 "
_WEB_KEEP=" WST-036 WST-124 WST-125 "
_HOLD_CODES=" WST-080 WST-126 "
declare -A _HOLD=()
_PHASE="os"

_not_target() {
    local _lst
    case "$OS_FAMILY" in
        LINUX)   _lst="$_NA_LINUX" ;;
        AIX)     _lst="$_NA_AIX" ;;
        SOLARIS) _lst="$_NA_SOLARIS" ;;
        HPUX)    _lst="$_NA_HPUX" ;;
        *)       return 1 ;;
    esac
    case "$_lst" in *" $1 "*) return 0 ;; esac
    return 1
}

_route_code() {
    local c="$1"
    case "$c" in
    SRV-*) [ -n "${_S2W[$c]:-}" ] && echo "${_S2W[$c]}" || echo "REF-${c}" ;;
    WST-*) if [ "$_PHASE" = "web" ]; then
               case "$_WEB_KEEP" in *" $c "*) echo "$c" ;; *) echo "REF-${c#WST-}" ;; esac
           else echo "$c"; fi ;;
    *) echo "$c" ;;
    esac
}

_rank() { case "$1" in 취약) echo 4;; 수동확인) echo 3;; 양호) echo 2;; N-A) echo 1;; *) echo 0;; esac; }
_worse() {
    [ -z "$1" ] && { echo "$2"; return; }
    [ -z "$2" ] && { echo "$1"; return; }
    local a="${1%%|*}" b="${2%%|*}"
    if [ "$(_rank "$b")" -gt "$(_rank "$a")" ]; then echo "$2 / ${1#*|}"; else echo "$1 / ${2#*|}"; fi
}

result() {
    if [ "$_NONROOT" = 1 ]; then
        case "${1%%|*}" in SRV-022|SRV-074|SRV-096|SRV-122)
            case "$1" in *"|양호|"*|*"|취약|"*)
                set -- "${1%%|*}|수동확인|root 권한 아님 - shadow·타 계정 파일 조회 불가로 판정 신뢰 불가, root 로 재점검 필요 (원 판정: ${1#*|})" ;; esac ;; esac
    fi
    local _code="${1%%|*}" _rest="${1#*|}"
    _code="${_code%% *}"
    _code="$(_route_code "$_code")"
    case "$_code" in
    REF-*)
        printf '[참고-평가기준 외] %s|%s\n\n' "$_code" "$_rest" >> "$_EVD"
        return ;;
    esac
    if [ "$_PHASE" = "os" ]; then
        case "$_HOLD_CODES" in *" $_code "*) _HOLD[$_code]="$_rest"; return ;; esac
    fi
    case "$_KMODE:$_code" in
    mi:WEB-*) ;;
    mi:*) printf '[참고-주요정보 모드 제외] %s|%s\n\n' "$_code" "$_rest" >> "$_EVD"; return ;;
    ef:WEB-*) return ;;
    esac
    if _not_target "$_code" && [ "${_rest%%|*}" != "N-A" ]; then
        printf '[평가대상 아님] %s 원 판정: %s\n' "$_code" "$_rest" >> "$_EVD"
        _rest="N-A|평가대상 아님 (${OS_FAMILY} 해당 없음 - 평가기준 평가대상 열)"
    fi
    local _line="${_code}|${_rest}"
    echo "$_line"
    case "$_line" in
    *"|양호|"*)     _CP=$((_CP+1)) ;;
    *"|취약|"*)     _CF=$((_CF+1)) ;;
    *"|수동확인|"*) _CM=$((_CM+1)) ;;
    *"|N-A|"*)      _CN=$((_CN+1)) ;;
    esac
    local _nm="${_INAME[$_code]:-}"
    if [ -n "$_nm" ]; then printf '[판정] %s (%s)|%s\n\n' "$_code" "$_nm" "$_rest" >> "$_EVD"
    else printf '[판정] %s\n\n' "$_line" >> "$_EVD"; fi
    return 0
}

_merge_hold() {
    local code="$1" wres="$2" wwhy="$3" os="${_HOLD[$1]:-}" m
    if [ -n "$wres" ]; then m="$(_worse "${os:+${os%%|*}|OS: ${os#*|}}" "${wres}|웹/WAS: ${wwhy}")"
    else m="${os%%|*}|OS: ${os#*|}"; fi
    [ -z "$m" ] || [ "$m" = "|OS: " ] && m="수동확인|판정 정보 없음 - 수동 확인"
    _PHASE="final" result "${code}|${m}"
}

evd() {
    local item; item="$(_route_code "$1")"; shift
    printf '[%s] %s $ %s\n' "$item" "$(date '+%H:%M:%S')" "$*" >> "$_EVD"
    eval "$@" >> "$_EVD" 2>&1
    printf '\n' >> "$_EVD"
}

evd_file() {
    local item f="$2"; item="$(_route_code "$1")"
    if [ -f "$f" ] || [ -d "$f" ]; then printf '[%s] 파일: %s (존재)\n' "$item" "$f" >> "$_EVD"
    else printf '[%s] 파일: %s (미존재)\n' "$item" "$f" >> "$_EVD"; fi
}


_csv() { tr '\n' ',' | sed 's/,$//'; }


is_running() {
    local svc="$1"
    command -v systemctl >/dev/null 2>&1 && systemctl is-active "$svc" 2>/dev/null | grep -q "^active" && return 0
    ps -ef 2>/dev/null | grep -v grep | grep -qiw "$svc" && return 0
    return 1
}

get_perm() {
    local f="$1"
    case "$OS_FAMILY" in
    AIX)     istat "$f" 2>/dev/null | grep -i "mode" | grep -oE '[0-7]{3,4}' | tail -1 ;;
    SOLARIS) ls -l "$f" 2>/dev/null | awk '{k=0;for(i=2;i<=10;i++){c=substr($1,i,1);if(c~/[rwx]/)k+=2^(10-i)}printf "%o\n",k}' ;;
    HPUX)    ls -l "$f" 2>/dev/null | awk '{k=0;for(i=2;i<=10;i++){c=substr($1,i,1);if(c~/[rwx]/)k+=2^(10-i)}printf "%o\n",k}' ;;
    *)       stat -c "%a" "$f" 2>/dev/null ;;
    esac
}

get_owner() {
    local f="$1"
    case "$OS_FAMILY" in
    AIX)     istat "$f" 2>/dev/null | grep "Owner:" | awk '{print $2}' ;;
    SOLARIS|HPUX) ls -l "$f" 2>/dev/null | awk '{print $3}' ;;
    *)       stat -c "%U" "$f" 2>/dev/null ;;
    esac
}

# ════════════════════════════════════════════════════════════════
# [1] OS 공통 항목 — check_server.sh 점검 로직 (평가기준 판단기준·방법 동일 항목)
# ════════════════════════════════════════════════════════════════
# ── 공통 함수 ────────────────────────────────────────────────────
get_perm() {
    local f="$1"; [ -e "$f" ] || [ -L "$f" ] || { echo ""; return; }
    if [ -L "$f" ]; then
        local rf; rf=$(readlink -f "$f" 2>/dev/null)
        [ -z "$rf" ] && rf=$(perl -MCwd -e 'print Cwd::abs_path($ARGV[0])' "$f" 2>/dev/null)
        [ -n "$rf" ] && [ -e "$rf" ] && f="$rf" || { echo ""; return; }
    fi
    case "$OS_FAMILY" in
    BSD)     stat -f "%Lp" "$f" 2>/dev/null ;;
    AIX|SOLARIS|HPUX) ls -lL "$f" 2>/dev/null | awk '{p=substr($1,2);r=0;for(i=1;i<=9;i++){c=substr(p,i,1);if(c!="-")r+=2^(9-i)};printf "%03o\n",r}' ;;
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
    BSD)     stat -f "%Su" "$f" 2>/dev/null ;;
    AIX|SOLARIS|HPUX) ls -lL "$f" 2>/dev/null | awk '{print $3}' ;;
    *)       stat -c "%U" "$f" 2>/dev/null ;;
    esac
}
is_running() {
    local svc="$1"
    command -v systemctl >/dev/null 2>&1 && systemctl is-active "$svc" 2>/dev/null | grep -q "^active" && return 0
    command -v service  >/dev/null 2>&1 && service "$svc" status 2>/dev/null | grep -qiE "running|started" && return 0
    command -v lssrc    >/dev/null 2>&1 && lssrc -s "$svc" 2>/dev/null | grep -qi "active" && return 0
    command -v svcs     >/dev/null 2>&1 && svcs -H "$svc" 2>/dev/null | grep -q "^online" && return 0
    ps -ef 2>/dev/null | grep -v grep | grep -qiw "$svc" && return 0
    command -v ps >/dev/null 2>&1 || { grep -qixF "$svc" /proc/[0-9]*/comm 2>/dev/null && return 0; }
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
# SRV-001: 네트워크 모니터링 서비스 (SNMP 버전)
# ================================================================
# ── 6차 공통 헬퍼 (가이드 판단기준 대조) ──
_perm_over() {
    local p; p=$(printf '%03d' "${1: -3}" 2>/dev/null || echo "$1"); p="${p: -3}"
    [ -z "$p" ] && return 1
    (( (8#$p & ~8#$2 & 8#777) != 0 ))
}
_snmp_confs() {
    local f
    for f in /etc/snmp/snmpd.conf /etc/snmpd.conf /etc/snmpdv3.conf /etc/net-snmp/snmp/snmpd.conf /etc/sma/snmp/snmpd.conf /etc/SnmpAgent.d/snmpd.conf /etc/opt/snmp/snmpd.conf /etc/sfw/snmp/snmpd.conf; do
        [ -f "$f" ] && echo "$f"
    done
}
_named_conf() {
    local c
    for c in /etc/named.conf /etc/bind/named.conf; do
        [ -f "$c" ] || continue
        named-checkconf -p "$c" 2>/dev/null | tr '\n\t' '  ' | sed 's/"//g; s/;/;\n/g' && return
        cat "$c" /etc/bind/named.conf.options /etc/bind/named.conf.local 2>/dev/null | grep -vE '^\s*(//|#)'
        return
    done
}
# ── 8차 공통 헬퍼 (실무 스크립트·UNIX 실장비 결과 대조) ──
_TO=$(command -v timeout 2>/dev/null)
_to() { local s="$1"; shift; if [ -n "$_TO" ]; then "$_TO" "$s" "$@"; else "$@"; fi; }   # timeout 없는 AIX·HP-UX·Solaris 10 은 제한 없이 실행
_aix_default() { awk '/^default:/{f=1;next} /^[^ \t*#]/{f=0} f' /etc/security/user 2>/dev/null; }   # AIX default 스탠자 본문
_aix_attr() { awk -v s="$1" -v a="$2" '/^[^ \t*#][^ \t]*:[ \t]*$/{sub(/:.*/,"");st=$0;next} st==s && $0 ~ ("^[ \t]+" a "[ \t]*=") {sub(/^[^=]*=[ \t]*/,"");sub(/[ \t]+$/,"");print;exit}' "${3:-/etc/security/user}" 2>/dev/null; }
_inetd_on() {   # inetd(AIX·HP-UX·Solaris≤9) / SMF(Solaris 10+) / xinetd 로 기동되는 활성 서비스
    local s
    for s in "$@"; do
        [ -f /etc/inetd.conf ] && awk -v s="$s" '$0!~/^[ \t]*#/ && $1==s {print "inetd.conf:" s; exit}' /etc/inetd.conf 2>/dev/null
        [ "$OS_FAMILY" = "SOLARIS" ] && command -v inetadm >/dev/null 2>&1 && \
            inetadm 2>/dev/null | awk -v s="$s" '$1=="enabled" && $NF ~ ("^svc:/network/" s "([:/]|$)") {print "smf:" $NF}'
        [ -f "/etc/xinetd.d/$s" ] && grep -qiE '^[[:space:]]*disable[[:space:]]*=[[:space:]]*no' "/etc/xinetd.d/$s" 2>/dev/null && echo "xinetd:$s"
    done
}
_listen() { { ss -tln 2>/dev/null || netstat -an 2>/dev/null; } | awk -v p="$1" '/LISTEN/ {for(i=1;i<=NF;i++) if ($i ~ ("[.:]" p "$")) {print; exit}}'; }   # TCP LISTEN (Linux ':23' / UNIX '*.23')
_sshd_cfg() { local c; for c in /etc/ssh/sshd_config /opt/ssh/etc/sshd_config /usr/local/etc/sshd_config /etc/openssh/sshd_config; do [ -f "$c" ] && { echo "$c"; return; }; done; }
_sshd_bin() { local b; for b in $(command -v sshd 2>/dev/null) /usr/sbin/sshd /opt/ssh/sbin/sshd /usr/lib/ssh/sshd /usr/local/sbin/sshd; do [ -x "$b" ] && { echo "$b"; return; }; done; }
_snmp_run() { is_running snmpd && return 0; ps -ef 2>/dev/null | grep -v grep | grep -qE '[/ ](snmpd|snmpdm|snmpdv3ne|snmpdv3e)( |$)'; }   # HP-UX snmpdm, AIX snmpdv3 (cmsnmpd·dsm_sa_snmpd 제외)
_comm() { if [ "$OS_FAMILY" = HPUX ]; then UNIX95=1 ps -e -o comm= 2>/dev/null; else ps -e -o comm= 2>/dev/null; fi | sed 's#.*/##'; }
_ftp_running() { is_running vsftpd || is_running proftpd || is_running pure-ftpd || is_running in.ftpd || is_running ftpd || [ -n "$(_inetd_on ftp)" ] || [ -n "$(_listen 21)" ]; }

check_SRV001() {
    # 평가기준: v2 이용 시(v3 사용 가능 환경) 취약, v3 사용 시 보안레벨 AuthPriv — net-snmp 문법(rocommunity/rwcommunity/com2sec)
    local confs; confs=$(_snmp_confs)
    evd "SRV-001" "for f in $(echo $confs); do echo \"# \$f\"; grep -vE '^\s*(#|\$)' \$f | head -20; done"
    evd "SRV-001" "ps -ef 2>/dev/null | grep -iE '[s]nmp'; lssrc -s snmpd 2>/dev/null; ls -l /var/lib/net-snmp/snmpd.conf /var/lib/snmp/snmpd.conf 2>/dev/null; grep -ciE '^\s*(usmUser|createUser)' /var/lib/net-snmp/snmpd.conf /var/lib/snmp/snmpd.conf 2>/dev/null"
    if [ -z "$confs" ] && ! _snmp_run; then result "SRV-001|N-A|SNMP 미설치/미실행"; return; fi
    _snmp_run || { result "SRV-001|N-A|SNMP 설정 파일은 있으나 snmpd 미실행"; return; }
    local v2 v3 v3weak
    v2=$(cat $confs 2>/dev/null | grep -vE '^\s*#' | grep -iE '^\s*(rocommunity6?|rwcommunity6?|com2sec6?|community)\s|^\s*(get|set)-community-name\s*:' | head -3)
    v3=$(cat $confs 2>/dev/null | grep -vE '^\s*#' | grep -iE '^\s*(rouser|rwuser|createUser)\s|^\s*access\s.*\susm\s|^\s*USM_USER' | head -5)
    v3weak=$(cat $confs 2>/dev/null | grep -vE '^\s*#' | grep -iE '^\s*(rouser|rwuser)\s+\S+(\s+(noauth|auth)\b|\s*$)|^\s*access\s.*\susm\s+(noauth|auth)\b|^\s*VACM_ACCESS\s.*\b(noAuthNoPriv|AuthNoPriv)\b|^\s*USM_USER\s+(\S+\s+){5}(-|none)\b' | head -3)
    if [ -n "$v2" ]; then result "SRV-001|취약|SNMP v1/v2c 사용: $(echo "$v2" | head -1 | awk '{print $1}') (v3 사용 가능 환경에서 v2 이용)"
    elif [ -n "$v3weak" ]; then result "SRV-001|취약|SNMPv3 보안레벨 AuthPriv 미적용: $(echo "$v3weak" | head -1)"
    elif [ -n "$v3" ]; then result "SRV-001|양호|SNMPv3 AuthPriv(priv) 사용"
    else result "SRV-001|수동확인|snmpd 실행 중 - 버전·보안레벨 설정 수동 확인 ($(echo $confs))"; fi
}

# ================================================================
# SRV-003: SNMP 접근통제 (ACL)
# ================================================================
check_SRV003() {
    # 평가기준 판단방법: rocommunity/rwcommunity/com2sec 출발지(source) 제한, 'rocommunity public' 출발지 없음 = 통제 미흡
    local confs; confs=$(_snmp_confs)
    evd "SRV-003" "grep -hiE '^\s*(agentAddress|rocommunity|rwcommunity|com2sec|group|view|access|rouser|rwuser|createUser)' $(echo ${confs:-/dev/null}) 2>/dev/null"
    if [ -z "$confs" ] || ! _snmp_run; then result "SRV-003|N-A|SNMP 미실행"; return; fi
    local open
    open=$(cat $confs 2>/dev/null | grep -vE '^\s*#' | awk 'tolower($1)~/^r[ow]community6?$/ && ($3=="" || $3=="default" || $3=="0.0.0.0/0" || $3=="::/0"){print $1" "$2} tolower($1)~/^com2sec6?$/ && ($3=="default" || $3=="0.0.0.0/0"){print $1" "$2" "$3}' | head -3)
    # HP-UX get/set-community-name 에 IP: 미지정 = 출발지 무제한, AIX community 주소·마스크 0.0.0.0 = 전체 허용
    [ "$OS_FAMILY" = "HPUX" ] && open="${open}$(cat $confs 2>/dev/null | grep -vE '^\s*#' | grep -iE '^\s*(get|set)-community-name\s*:' | grep -viE '\bIP:' | awk '{print $1" "$2}' | head -2)"
    [ "$OS_FAMILY" = "AIX" ] && open="${open}$(cat $confs 2>/dev/null | grep -vE '^\s*#' | awk 'tolower($1)=="community" && (($3=="0.0.0.0"&&$4=="0.0.0.0") || ($5=="0.0.0.0"&&$6=="0.0.0.0")){print $1" "$2}' | head -2)"
    if [ -n "$open" ]; then result "SRV-003|취약|출발지 제한 없는 community: $(echo "$open" | awk '{print $1" "substr($2,1,2)"***"}' | tr '\n' ',' | sed 's/,$//')"
    elif cat $confs 2>/dev/null | grep -vE '^\s*#' | grep -qiE '^\s*(rocommunity|rwcommunity|com2sec|rouser|rwuser|(get|set)-community-name)'; then result "SRV-003|양호|SNMP 접근 출발지 지정 또는 v3 사용자 인증"
    else result "SRV-003|수동확인|SNMP 접근통제 설정 수동 확인 ($(echo $confs))"; fi
}

# ================================================================
# SRV-004: SMTP 서비스 비활성화
# ================================================================
check_SRV004() {
    evd "SRV-004" "ps -ef 2>/dev/null | grep -E 'sendmail|postfix|exim' | grep -v grep"
    evd "SRV-004" "ss -tlnp 2>/dev/null | grep ':25 ' || netstat -tlnp 2>/dev/null | grep ':25 '"
    is_running sendmail || is_running postfix || is_running exim || \
        netstat -tlnp 2>/dev/null | grep -q ":25 " || \
        ss -tlnp 2>/dev/null | grep -q ":25 " && \
        result "SRV-004|수동확인|SMTP 서비스 실행 중 (업무상 필요 여부 확인)" && return
    result "SRV-004|양호|SMTP 서비스 미실행"
}

# ================================================================
# SRV-011: 시스템 관리자 FTP 접속 제한
# ================================================================
check_SRV011() {
    evd "SRV-011" "cat /etc/ftpusers /etc/ftpd/ftpusers /etc/vsftpd/ftpusers /etc/vsftpd.ftpusers 2>/dev/null; grep -vE '^\s*#' /etc/inetd.conf 2>/dev/null | grep -w ftp; inetadm 2>/dev/null | grep -i ftp; lssrc -ls inetd 2>/dev/null | grep -i ftp"
    for f in /etc/ftpusers /etc/ftpd/ftpusers /etc/vsftpd/ftpusers /etc/vsftpd.ftpusers; do
        [ -f "$f" ] || continue
        if grep -q "^root" "$f" 2>/dev/null; then
            result "SRV-011|양호|FTP root 계정 제한 (${f})"
        else
            result "SRV-011|취약|FTP root 제한 미설정 (${f})"
        fi
        return
    done
    _ftp_running || { evd "SRV-011" "ps -ef 2>/dev/null | grep -E 'vsftpd|proftpd|ftpd' | grep -v grep"; result "SRV-011|N-A|FTP 서비스 미실행"; return; }
    result "SRV-011|취약|ftpusers 파일 없음 (root FTP 접속 제한 불가)"
}

# ================================================================
# SRV-013: Anonymous FTP 제한
# ================================================================
check_SRV013() {
    evd "SRV-013" "grep -i anonymous /etc/vsftpd/vsftpd.conf /etc/vsftpd.conf /etc/proftpd/proftpd.conf /etc/proftpd.conf 2>/dev/null; grep '^ftp:' /etc/passwd 2>/dev/null"
    # 평가기준: FTP 미사용 또는 Anonymous 비활성 → 양호
    _ftp_running || { result "SRV-013|양호|FTP 서비스 미사용"; return; }
    local f
    for f in /etc/vsftpd/vsftpd.conf /etc/vsftpd.conf; do
        [ -f "$f" ] || continue
        grep -qiE "^\s*anonymous_enable\s*=\s*YES" "$f" 2>/dev/null && { result "SRV-013|취약|Anonymous FTP 활성화 (${f})"; return; }
        grep -qiE "^\s*anonymous_enable\s*=" "$f" 2>/dev/null || { result "SRV-013|취약|anonymous_enable 미설정 (vsftpd 기본값 YES) (${f})"; return; }
        result "SRV-013|양호|Anonymous FTP 비활성화 (${f})"; return
    done
    for f in /etc/proftpd/proftpd.conf /etc/proftpd.conf; do
        [ -f "$f" ] || continue
        grep -vE '^\s*#' "$f" 2>/dev/null | grep -qi "<Anonymous" && { result "SRV-013|취약|proftpd <Anonymous> 블록 활성 (${f})"; return; }
        result "SRV-013|양호|proftpd Anonymous 미설정 (${f})"; return
    done
    grep -q "^ftp:" /etc/passwd 2>/dev/null && result "SRV-013|취약|ftpd 실행 중이며 ftp(anonymous) 계정 존재" || result "SRV-013|수동확인|FTP 실행 중 - Anonymous 설정 수동 확인"
}

# ================================================================
# SRV-014: NFS 접근통제
# ================================================================
check_SRV014() {
    evd "SRV-014" "ls -l /etc/exports /etc/dfs/dfstab 2>/dev/null; cat /etc/exports /etc/dfs/dfstab 2>/dev/null"
    local exports_file="/etc/exports"
    [ "$OS_FAMILY" = "SOLARIS" ] && exports_file="/etc/dfs/dfstab"
    [ "$OS_FAMILY" = "HPUX" ] && [ -z "$(grep -vE '^\s*(#|$)' /etc/exports 2>/dev/null)" ] && [ -f /etc/dfs/dfstab ] && exports_file="/etc/dfs/dfstab"   # HP-UX 11iv3 share 명령
    evd "SRV-014" "share 2>/dev/null; cat /etc/dfs/sharetab 2>/dev/null; exportfs 2>/dev/null"
    # 평가기준: NFS 비활성화 또는 적절한 접근통제 → 양호
    { [ -f "$exports_file" ] && [ -n "$(grep -vE '^\s*(#|$)' "$exports_file" 2>/dev/null)" ]; } || { result "SRV-014|양호|NFS 공유 미사용 (${exports_file} 설정 없음)"; return; }
    { is_running nfsd || is_running rpc.nfsd || is_running mountd || is_running rpc.mountd || { command -v systemctl >/dev/null 2>&1 && systemctl is-active nfs-server 2>/dev/null | grep -q '^active'; }; } || \
        { result "SRV-014|양호|NFS 서비스 비활성 (${exports_file} 설정은 존재 - 참고)"; return; }
    local bad="" p o
    if [ "$exports_file" = "/etc/dfs/dfstab" ]; then
        bad=$(grep -vE '^\s*(#|$)' "$exports_file" | grep -vE 'rw=|ro=|access=' | head -2)
    else
        bad=$(grep -vE '^\s*(#|$)' "$exports_file" | awk '{ if (NF<2) {print; next} for(i=2;i<=NF;i++){ h=$i; sub(/\(.*/,"",h); if (h=="" || h=="*" || h=="0.0.0.0/0") {print; break} } }' | head -2)
    fi
    p=$(get_perm "$exports_file"); o=$(get_owner "$exports_file")
    { [ "$o" != "root" ] || _perm_over "$p" 644; } && bad="${bad:+$bad / }${exports_file}(${o}:${p})"
    [ -n "$bad" ] && result "SRV-014|취약|NFS 접근통제 미흡: $(echo "$bad" | head -2 | tr '\n' ' ')" || result "SRV-014|양호|NFS 공유 호스트 지정·설정 파일 root 644 이하"
}

# ================================================================
# SRV-015: 불필요 NFS 비활성화
# ================================================================
check_SRV015() {
    evd "SRV-015" "ps -ef 2>/dev/null | grep -E 'nfsd|nfs-server' | grep -v grep"
    is_running nfs || is_running nfsd || is_running nfs-server || \
        is_running nfs-kernel-server && \
        result "SRV-015|수동확인|NFS 서비스 실행 중 (업무상 필요 여부 확인)" && return
    result "SRV-015|양호|NFS 서비스 미실행"
}

# ================================================================
# SRV-016: 불필요 RPC 비활성화
# ================================================================
check_SRV016() {
    # 평가기준 15종: rpc.cmsd, rpc.ttdbserverd, sadmind, rusersd, walld, sprayd, rstatd, rpc.nisd, rexd, rpc.pcnfsd, rpc.statd, rpc.ypupdated, rpc.rquotad, kcms_server, cachefsd (업무상 사용 시 예외)
    evd "SRV-016" "rpcinfo -p 2>/dev/null | head -30; ps -ef 2>/dev/null | grep -E 'rpc\.|sadmind|rusersd|walld|sprayd|rstatd|rexd|kcms|cachefsd' | grep -v grep"
    local s bad="" nfs=""
    for s in rpc.cmsd rpc.ttdbserverd sadmind rusersd rpc.rusersd walld rpc.rwalld sprayd rpc.sprayd rstatd rpc.rstatd rpc.nisd rexd rpc.rexd rpc.pcnfsd rpc.ypupdated kcms_server cachefsd; do
        is_running "$s" && bad="${bad} ${s}"
    done
    for s in rpc.statd rpc.rquotad; do is_running "$s" && nfs="${nfs} ${s}"; done
    local rp; rp=$(rpcinfo -p 2>/dev/null | awk '{print $NF}' | grep -E '^(cmsd|ttdbserverd|sadmind|rusersd|walld|sprayd|rstatd|nisd|rexd|pcnfsd|ypupdated)$' | sort -u | tr '\n' ' ')
    [ -n "$rp" ] && bad="${bad} [rpcinfo:${rp% }]"
    local inet; inet=$(grep -vE '^[[:space:]]*#' /etc/inetd.conf 2>/dev/null | grep -oE 'rpc\.(cmsd|ttdbserverd|rusersd|rwalld|sprayd|rstatd|rexd|pcnfsd|ypupdated)|sadmind|kcms_server|cachefsd' | sort -u | tr '\n' ' ')
    [ -n "$inet" ] && bad="${bad} [inetd.conf:${inet% }]"
    if [ "$OS_FAMILY" = "SOLARIS" ]; then
        inet=$(_inetd_on rpc/rstat rpc/rusers rpc/spray rpc/wall rpc/rex rpc/cde-calendar-manager rpc/cde-ttdbserver | sed -n 's/^smf://p' | tr '\n' ' ')
        [ -n "$inet" ] && bad="${bad} [${inet% }]"
    fi
    if [ -n "$bad" ]; then result "SRV-016|취약|불필요 RPC 서비스 활성:${bad}"
    elif [ -n "$nfs" ]; then result "SRV-016|수동확인|NFS 동반 RPC 서비스 실행:${nfs} - 업무상 사용 여부 확인"
    else result "SRV-016|양호|기준 RPC 서비스(cmsd·ttdbserverd·sadmind 등 15종) 미실행"; fi
}

# ================================================================
# SRV-022: 패스워드 미설정 계정 관리
# ================================================================
check_SRV022() {
    evd "SRV-022" "awk -F: '\$2==\"\"' /etc/shadow 2>/dev/null || awk -F: '\$2==\"\"' /etc/passwd 2>/dev/null"
    case "$OS_FAMILY" in
    AIX)   # AIX 패스워드 파일 = /etc/security/passwd (스탠자 password = 공란)
        no_pw=$(awk '/^[^ \t*#][^ \t]*:[ \t]*$/{sub(/:.*/,"");u=$0;next} /^[ \t]+password[ \t]*=/{v=$0;sub(/^[^=]*=[ \t]*/,"",v);sub(/[ \t]+$/,"",v); if(v=="") print u}' /etc/security/passwd 2>/dev/null | head -5)
        ;;
    HPUX|SOLARIS)
        no_pw=$( { [ -f /etc/shadow ] && awk -F: '$2 == "" {print $1}' /etc/shadow 2>/dev/null; logins -p 2>/dev/null | awk '{print $1"(logins -p)"}'; } | sort -u | head -5)
        ;;
    *)
        [ -f /etc/shadow ] && \
            no_pw=$(awk -F: '$2 == "" {print $1}' /etc/shadow 2>/dev/null | head -5) || \
            no_pw=$(awk -F: '$2 == "" {print $1}' /etc/passwd 2>/dev/null | head -5)
        ;;
    esac
    _pwe=$(awk -F: '$2=="" && $1!="" {print $1"(passwd 필드 공란)"}' /etc/passwd 2>/dev/null | head -5)
    [ -n "$_pwe" ] && no_pw="$(printf '%s\n%s' "$no_pw" "$_pwe" | grep -v '^$')"
    [ -n "$no_pw" ] && result "SRV-022|취약|비밀번호 미설정 계정: $(echo $no_pw | tr '\n' ',')" || \
        result "SRV-022|양호|비밀번호 미설정 계정 없음"
}

# ================================================================
# SRV-025: hosts.equiv / .rhosts 설정 제한
# ================================================================
check_SRV025() {
    evd "SRV-025" "ls -la /etc/hosts.equiv /root/.rhosts /.rhosts 2>/dev/null"
    evd "SRV-025" "cat /etc/hosts.equiv /root/.rhosts 2>/dev/null"
    # 기준: 파일이 없거나 신뢰 호스트 목록만 있으면 양호, '+' 설정·불필요 계정/호스트가 있으면 취약
    local plus="" entries="" f
    for f in /etc/hosts.equiv /.rhosts $(awk -F: '$6!=""&&$6!="/"{print $6"/.rhosts"}' /etc/passwd 2>/dev/null | sort -u); do
        [ -f "$f" ] || continue
        grep -vE '^[[:space:]]*(#|$)' "$f" 2>/dev/null | grep -qE '(^|[[:space:]])\+' && plus="${plus} ${f}"
        [ -n "$(grep -vE '^[[:space:]]*(#|$)' "$f" 2>/dev/null)" ] && entries="${entries} ${f}($(grep -cvE '^[[:space:]]*(#|$)' "$f" 2>/dev/null)줄)"
    done
    if [ -n "$plus" ]; then result "SRV-025|취약|'+' 설정(모든 호스트/계정 신뢰) 존재:${plus}"
    elif [ -n "$entries" ]; then result "SRV-025|수동확인|신뢰 호스트 등록:${entries} - 불필요 계정/호스트 여부 확인"
    else result "SRV-025|양호|hosts.equiv/.rhosts 미존재 또는 설정 없음(주석만)"; fi
}

# ================================================================
# SRV-026: root 원격 접속 제한
# ================================================================
check_SRV026() {
    evd "SRV-026" "grep -i PermitRootLogin /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null; sshd -T 2>/dev/null | grep -i '^permitrootlogin'; ssh -V 2>&1; cat /etc/securetty 2>/dev/null | grep -E '^pts' | head -3"
    case "$OS_FAMILY" in
    AIX)
        # 평가기준(AIX): rlogin 사용 시 root rlogin=true, SSH 사용 시 PermitRootLogin yes → 하나라도 해당하면 취약
        val=$(awk '/^root:/{f=1;next} /^[^ \t*]/{f=0} f&&/rlogin/{sub(/.*=[ \t]*/,"");print;exit}' /etc/security/user 2>/dev/null)
        [ -z "$val" ] && val=$(awk '/^default:/{f=1;next} /^[^ \t*]/{f=0} f&&/rlogin/{sub(/.*=[ \t]*/,"");print;exit}' /etc/security/user 2>/dev/null)
        ssh_root=$(grep -iE "^\s*PermitRootLogin" "$(_sshd_cfg)" 2>/dev/null | awk '{print $2}' | head -1)
        if [ "${val:-true}" != "false" ]; then result "SRV-026|취약|AIX root rlogin=${val:-true(기본)}${ssh_root:+, SSH PermitRootLogin=${ssh_root}}"
        elif [ "${ssh_root,,}" = "yes" ]; then result "SRV-026|취약|AIX SSH PermitRootLogin=yes"
        else result "SRV-026|양호|AIX root rlogin=false, SSH PermitRootLogin=${ssh_root:-미설정(기본)}"; fi ;;
    SOLARIS)
        # 평가기준(Solaris): Telnet — /etc/default/login CONSOLE=/dev/console 없음/주석 이면 취약, SSH — PermitRootLogin yes 취약
        cons=$(grep -v "^#" /etc/default/login 2>/dev/null | grep "^CONSOLE")
        ssh_root=$(grep -iE "^\s*PermitRootLogin" "$(_sshd_cfg)" 2>/dev/null | awk '{print $2}' | head -1)
        if [ -z "$cons" ]; then result "SRV-026|취약|Solaris CONSOLE=/dev/console 미설정 (Telnet root 원격 접속 가능)${ssh_root:+, PermitRootLogin=${ssh_root}}"
        elif [ "${ssh_root,,}" = "yes" ]; then result "SRV-026|취약|Solaris SSH PermitRootLogin=yes"
        else result "SRV-026|양호|Solaris CONSOLE 제한, SSH PermitRootLogin=${ssh_root:-미설정}"; fi ;;
    HPUX)
        # 평가기준(HP-UX): Telnet 사용 시 /etc/securetty 없음·console 주석 → 취약, SSH PermitRootLogin yes → 취약
        local cf tel="" val sb; cf=$(_sshd_cfg); sb=$(_sshd_bin)
        evd "SRV-026" "grep -i PermitRootLogin $cf 2>/dev/null; cat /etc/securetty 2>/dev/null"
        [ -n "$sb" ] && val=$("$sb" -T 2>/dev/null | awk 'tolower($1)=="permitrootlogin"{print $2}')
        [ -z "$val" ] && val=$(grep -iE '^\s*PermitRootLogin' "$cf" 2>/dev/null | awk '{print $2}' | head -1)
        if is_running telnetd || [ -n "$(_inetd_on telnet; _listen 23)" ]; then
            grep -qE '^[[:space:]]*console[[:space:]]*$' /etc/securetty 2>/dev/null || tel="Telnet 사용 중 /etc/securetty console 미설정"
        fi
        if [ -n "$tel" ] || [ "${val,,}" = "yes" ]; then result "SRV-026|취약|HP-UX ${tel}${tel:+, }SSH PermitRootLogin=${val:-미확인} (${cf:-sshd_config 미발견})"
        elif [ -z "$val" ]; then result "SRV-026|수동확인|HP-UX PermitRootLogin 미설정·sshd -T 불가 (${cf:-sshd_config 미발견}) - 기본값 확인(HP-UX Secure Shell 구버전 기본 yes)"
        else result "SRV-026|양호|HP-UX PermitRootLogin=${val}, Telnet root 제한"; fi ;;
    *)
        # 평가기준: SSH는 PermitRootLogin yes 일 때만 취약, Telnet 사용 시 securetty 의 pts 허용 여부
        local src="sshd -T" val=""
        val=$(sshd -T 2>/dev/null | awk 'tolower($1)=="permitrootlogin"{print $2}' | tail -1)
        if [ -z "$val" ]; then
            src="설정파일"
            [ -d /etc/ssh/sshd_config.d ] && val=$(grep -rih "^\s*PermitRootLogin" /etc/ssh/sshd_config.d/ 2>/dev/null | awk '{print $2}' | head -1)
            [ -z "$val" ] && val=$(grep -i "^\s*PermitRootLogin" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' | head -1)
        fi
        local telnet_vuln=""
        if is_running telnetd || is_running in.telnetd || [ -n "$(_inetd_on telnet; _listen 23)" ]; then
            { [ ! -f /etc/securetty ] || grep -qE '^pts' /etc/securetty 2>/dev/null; } && telnet_vuln=" / Telnet 사용 중 securetty pts 허용"
        fi
        if [ -z "$val" ]; then
            local ov; ov=$( { ssh -V 2>&1; sshd -V 2>&1; rpm -q openssh-server 2>/dev/null; dpkg-query -W -f='OpenSSH_${Version}' openssh-server 2>/dev/null; } | grep -oE 'OpenSSH_[0-9]+\.[0-9]+|openssh-server-[0-9]+\.[0-9]+|OpenSSH_1:[0-9]+\.[0-9]+' | head -1 | grep -oE '[0-9]+\.[0-9]+$')
            if [ -n "$ov" ] && [ "${ov%%.*}" -ge 7 ] 2>/dev/null; then val="prohibit-password"; src="OpenSSH ${ov} 기본값"; fi
        fi
        case "${val,,}" in
        yes) result "SRV-026|취약|PermitRootLogin=yes (${src}) - root 원격 접속 허용${telnet_vuln}" ;;
        no|prohibit-password|without-password|forced-commands-only)
            [ -n "$telnet_vuln" ] && result "SRV-026|취약|PermitRootLogin=${val} (${src})${telnet_vuln}" \
                                  || result "SRV-026|양호|PermitRootLogin=${val} (${src})" ;;
        "") [ -n "$telnet_vuln" ] && result "SRV-026|취약|${telnet_vuln# / }" \
                                  || result "SRV-026|수동확인|PermitRootLogin 확인 불가 (sshd -T 실패, 설정 없음, OpenSSH 버전 미확인)" ;;
        *)  result "SRV-026|수동확인|PermitRootLogin=${val} (${src})" ;;
        esac ;;
    esac
}

# ================================================================
# SRV-027: 서비스 접근 IP/포트 제한 (TCP Wrapper / firewall)
# ================================================================
check_SRV027() {
    # 평가기준: 방화벽·tcp-wrapper·3rd-party 로 서비스 접근통제 — 규칙 유무로 판단, 없으면 상위 방화벽 등 확인(수동확인)
    evd "SRV-027" "grep -vE '^\s*(#|\$)' /etc/hosts.allow /etc/hosts.deny 2>/dev/null; grep -vE '^\s*(#|\$)' /var/adm/inetd.sec 2>/dev/null; ipfstat -io 2>/dev/null | head -20; inetadm -p 2>/dev/null | grep tcp_wrappers; lsfilt -a 2>/dev/null | head -20"
    evd "SRV-027" "firewall-cmd --list-all 2>/dev/null; ufw status numbered 2>/dev/null; iptables -S 2>/dev/null | head -40; nft list ruleset 2>/dev/null | head -40"
    local tw=0 fw="" n
    [ -n "$(grep -vE '^\s*(#|$)' /etc/hosts.allow /etc/hosts.deny 2>/dev/null)" ] && tw=1
    if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state 2>/dev/null | grep -q running; then
        n=$( { firewall-cmd --list-rich-rules 2>/dev/null; firewall-cmd --list-sources 2>/dev/null | tr ' ' '\n'; } | grep -c . ); fw="firewalld(zone=$(firewall-cmd --get-default-zone 2>/dev/null), rich/source ${n})"
    elif command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
        n=$(ufw status numbered 2>/dev/null | grep -c "^\["); [ "$n" -gt 0 ] && fw="ufw(${n} rules)"
    fi
    if [ -z "$fw" ]; then
        n=$(iptables -S 2>/dev/null | grep -c '^-A'); [ "${n:-0}" -gt 0 ] && fw="iptables(${n} rules)"
        [ -z "$fw" ] && { n=$(nft list ruleset 2>/dev/null | grep -cE '^\s+(ip|tcp|udp|iif|oif|meta|ct)\s'); [ "${n:-0}" -gt 0 ] && fw="nftables(${n} rules)"; }
        [ -z "$fw" ] && iptables -S 2>/dev/null | grep -qE '^-P INPUT (DROP|REJECT)' && fw="iptables(INPUT 기본 DROP)"
    fi
    if [ -n "$fw" ] || [ $tw -eq 1 ]; then result "SRV-027|양호|접근통제 규칙 존재 (tcp-wrapper=$([ $tw -eq 1 ] && echo 설정 || echo 없음), 방화벽=${fw:-없음})"
    else result "SRV-027|수동확인|호스트 방화벽·tcp-wrapper 규칙 없음 - 상위 방화벽·3rd-party 접근통제 여부 확인 (미통제 시 취약)"; fi
}

# ================================================================
# SRV-028: 원격 터미널 접속 타임아웃
# ================================================================
check_SRV028() {
    evd "SRV-028" "grep -rh 'TMOUT\\|tmout' /etc/profile /etc/bashrc /etc/bash.bashrc /etc/profile.d/ /root/.bashrc /root/.profile 2>/dev/null | grep -v '^#'"
    tmout=""
    for f in /etc/profile /etc/bashrc /etc/bash.bashrc /etc/environment \
              /root/.bashrc /root/.profile /etc/profile.d/*.sh; do
        [ -f "$f" ] || continue
        t=$(grep -h "TMOUT\|tmout" "$f" 2>/dev/null | grep -v "^\s*#" | grep -oE "[0-9]+" | head -1)
        [ -n "$t" ] && tmout=$t && break
    done
    case "$OS_FAMILY" in
    SOLARIS) [ -z "$tmout" ] && tmout=$(grep "^TIMEOUT" /etc/default/login 2>/dev/null | cut -d= -f2 | tr -d ' ') ;;
    AIX)     [ -z "$tmout" ] && tmout=$(grep "^TMOUT\|^tmout" /etc/profile /etc/environment 2>/dev/null | grep -oE "[0-9]+" | head -1) ;;
    esac
    # 평가기준: 900초(15분) 이하 양호 (내부 규정이 더 짧으면 그 기준 적용 - 수동 확인)
    if [ -z "$tmout" ] || [ "$tmout" = "0" ]; then
        result "SRV-028|취약|TMOUT 미설정 (세션 타임아웃 없음)"
    elif [ "$tmout" -le 900 ] 2>/dev/null; then
        result "SRV-028|양호|TMOUT=${tmout}초 (900초 이하, 내부 규정이 더 짧으면 그 기준으로 확인)"
    else
        result "SRV-028|취약|TMOUT=${tmout}초 (900초 초과)"
    fi
}

# ================================================================
# SRV-034: 불필요한 서비스 비활성화 (finger/chargen/daytime 등)
# ================================================================
check_SRV034() {
    # 평가기준(LINUX 등): 취약한 버전의 automountd 서비스가 불필요하게 활성화 / Solaris 는 dmi 서비스 추가
    evd "SRV-034" "ps -ef 2>/dev/null | grep -E 'autofs|automount|dmispd|snmpXdmid' | grep -v grep; grep -v '^#' /etc/inetd.conf 2>/dev/null | grep -i automount; systemctl is-active autofs 2>/dev/null; automount -V 2>/dev/null | head -1"
    local am="" dmi=""
    { is_running automount || is_running automountd || is_running autofs || grep -v '^#' /etc/inetd.conf 2>/dev/null | grep -qi automount || \
      { command -v systemctl >/dev/null 2>&1 && systemctl is-active autofs 2>/dev/null | grep -q '^active'; }; } && am="automount($(automount -V 2>/dev/null | head -1 | grep -oE '[0-9]+(\.[0-9]+)+' || echo 버전미확인))"
    [ "$OS_FAMILY" = "SOLARIS" ] && { is_running dmispd || is_running snmpXdmid; } && dmi="dmi(dmispd/snmpXdmid)"
    if [ -n "$dmi" ]; then result "SRV-034|취약|DMI 서비스 활성: ${dmi}${am:+ / $am}"
    elif [ -n "$am" ]; then result "SRV-034|수동확인|${am} 활성 - 업무상 필요 여부·취약 버전 여부 확인"
    else result "SRV-034|양호|automountd 서비스 비활성"; fi
}

# ================================================================
# SRV-035: 취약 서비스 비활성화 (telnet 등)
# ================================================================
check_SRV035() {
    # 평가기준: tftp·talk·ntalk / finger / rexec·rlogin·rsh / echo·discard·daytime·chargen / NIS·NIS+ (tftp 는 백업솔루션 필수 시 예외)
    evd "SRV-035" "grep -vE '^\s*#' /etc/inetd.conf 2>/dev/null | grep -E 'tftp|talk|finger|exec|login|shell|echo|discard|daytime|chargen'; ls /etc/xinetd.d 2>/dev/null; ps -ef 2>/dev/null | grep -E 'tftp|talk|finger|rexec|rlogin|rsh|ypserv|ypbind|yppasswdd|nisd' | grep -v grep"
    local found="" tftp="" s
    for s in talkd in.talkd ntalkd in.ntalkd fingerd in.fingerd rexecd in.rexecd rlogind in.rlogind rshd in.rshd ypserv ypbind yppasswdd rpc.nisd; do
        is_running "$s" && found="${found} ${s}"
    done
    { is_running tftpd || is_running in.tftpd || ss -uln 2>/dev/null | grep -q ':69 '; } && tftp="tftp"
    if command -v systemctl >/dev/null 2>&1; then
        for s in chargen daytime discard echo rsh rlogin rexec finger tftp talk ntalk; do
            systemctl is-active "${s}.socket" 2>/dev/null | grep -q "^active" && { [ "$s" = tftp ] && tftp="tftp" || found="${found} ${s}.socket"; }
        done
    fi
    local act; act=$(grep -vE '^\s*#' /etc/inetd.conf 2>/dev/null | awk '{print $1}' | grep -E '^(tftp|talk|ntalk|finger|exec|login|shell|echo|discard|daytime|chargen)$' | tr '\n' ' ')
    for s in $act; do [ "$s" = tftp ] && tftp="tftp" || found="${found} [inetd:${s}]"; done
    if [ "$OS_FAMILY" = "SOLARIS" ]; then
        for s in $(_inetd_on tftp talk finger login shell rexec echo discard daytime chargen | sed -n 's/^smf://p'); do
            case "$s" in */tftp/*|*/tftp:*) tftp="tftp" ;; *) found="${found} [smf:${s#svc:/network/}]" ;; esac
        done
        evd "SRV-035" "inetadm 2>/dev/null | grep -E 'tftp|talk|finger|login|shell|rexec|echo|discard|daytime|chargen'"
    fi
    if [ -d /etc/xinetd.d ]; then
        for s in /etc/xinetd.d/*; do
            [ -f "$s" ] || continue
            grep -qiE 'disable\s*=\s*no' "$s" 2>/dev/null || continue
            case "$(basename "$s")" in tftp*) tftp="tftp" ;; chargen*|daytime*|discard*|echo*|rsh|rlogin|rexec|finger|talk|ntalk) found="${found} [xinetd:$(basename "$s")]" ;; esac
        done
    fi
    if [ -n "$found" ]; then result "SRV-035|취약|취약 서비스 활성:${found}${tftp:+ / tftp}"
    elif [ -n "$tftp" ]; then result "SRV-035|수동확인|tftp 서비스 활성 - OS 백업솔루션 필수 사용 여부 확인 (불필요 시 취약)"
    else result "SRV-035|양호|tftp·talk·finger·r계열·echo/chargen 등·NIS 서비스 미실행"; fi
}

# ================================================================
# SRV-062: DNS 정보 노출 방지 (버전 노출)
# ================================================================
check_SRV062() {
    is_running named || { evd "SRV-062" "ps -ef 2>/dev/null | grep named | grep -v grep"; result "SRV-062|N-A|DNS 서비스 미실행"; return; }
    local nc; nc=$(_named_conf)
    evd "SRV-062" "echo '$(echo "$nc" | grep -iE 'version' | head -3)'"
    [ -z "$nc" ] && { result "SRV-062|수동확인|named.conf 위치 확인 필요"; return; }
    echo "$nc" | grep -qiE '(^|[[:space:]])version\s+("[^0-9"]*"|[^0-9;"]*)\s*;' && result "SRV-062|양호|DNS 버전 노출 차단 (version 문자열 대체)" || result "SRV-062|취약|DNS 버전 노출 차단 미설정 (version \"none\" 권고)"
}

# ================================================================
# SRV-066: DNS Zone Transfer 제한
# ================================================================
check_SRV066() {
    is_running named || { evd "SRV-066" "ps -ef 2>/dev/null | grep named | grep -v grep"; result "SRV-066|N-A|DNS 미실행"; return; }
    local nc; nc=$(_named_conf)
    evd "SRV-066" "echo '$(echo "$nc" | grep -iE 'allow-transfer' | head -5)'"
    [ -z "$nc" ] && { result "SRV-066|수동확인|named.conf 수동 확인"; return; }
    if echo "$nc" | grep -qiE 'allow-transfer\s*\{\s*any\s*;'; then result "SRV-066|취약|allow-transfer { any; } - 모든 호스트 Zone Transfer 허용"
    elif echo "$nc" | grep -qiE 'allow-transfer'; then result "SRV-066|양호|Zone Transfer 허용 대상 지정: $(echo "$nc" | grep -ioE 'allow-transfer\s*\{[^}]*\}' | head -1)"
    else result "SRV-066|취약|allow-transfer 미설정 (Zone Transfer 제한 없음)"; fi
}

# ================================================================
# SRV-063: DNS Recursive Query 제한 설정 여부
# ================================================================
check_SRV063() {
    is_running named || { evd "SRV-063" "ps -ef 2>/dev/null | grep named | grep -v grep"; result "SRV-063|양호|DNS 서비스 미실행"; return; }
    local nc; nc=$(_named_conf)
    evd "SRV-063" "echo '$(echo "$nc" | grep -iE 'recursion|allow-recursion|allow-query-cache' | head -5)'"
    [ -z "$nc" ] && { result "SRV-063|수동확인|named.conf 위치 확인 필요"; return; }
    # 평가기준: Recursive query 금지 또는 신뢰 호스트만 허용 → 양호 (BIND 9.4+ 기본 allow-recursion 은 localnets/localhost)
    if echo "$nc" | grep -qiE 'recursion\s+no\s*;'; then result "SRV-063|양호|recursion no"
    elif echo "$nc" | grep -qiE 'allow-recursion\s*\{\s*any\s*;'; then result "SRV-063|취약|allow-recursion { any; } - 모든 호스트 재귀 질의 허용"
    elif echo "$nc" | grep -qiE 'allow-recursion'; then result "SRV-063|양호|allow-recursion 신뢰 호스트 한정: $(echo "$nc" | grep -ioE 'allow-recursion\s*\{[^}]*\}' | head -1)"
    else result "SRV-063|수동확인|recursion 허용 대상 미지정 (BIND 기본 localnets·localhost) - 신뢰 호스트 한정 여부 확인"; fi
}

# ================================================================
# SRV-064: DNS 서비스 보안 패치 적용 여부
# ================================================================
check_SRV064() {
    is_running named || { result "SRV-064|양호|DNS 서비스 미실행"; return; }
    evd "SRV-064" "named -v 2>/dev/null; rpm -qa bind 2>/dev/null; dpkg -l bind9 2>/dev/null | tail -1"
    named_ver=$(named -v 2>/dev/null | grep -oE 'BIND [0-9][^ ]*' | head -1)
    if [ -n "$named_ver" ]; then
        result "SRV-064|수동확인|DNS 버전: ${named_ver} - 최신 보안 패치 적용 여부 수동 확인"
    else
        result "SRV-064|수동확인|DNS 서비스 실행 중 - 버전 및 보안 패치 수동 확인"
    fi
}

# ================================================================
# SRV-069: 비밀번호 관리정책 (최대 사용기간)
# ================================================================
_pw_policy() {
    # OS별 비밀번호 정책 (최소 길이 / 요구 문자 종류 수 / 출처) 출력: "<minlen> <classes> <label>"
    local ml=0 cls=0 who k
    case "$OS_FAMILY" in
    AIX)
        ml=$(_aix_default | grep -w "minlen" | grep -oE '[0-9]+' | head -1)
        cls=$(_aix_default | grep -wE "minalpha|minother|mindigit|minspecialchar" | grep -cE '= *[1-9]')
        who="AIX" ;;
    SOLARIS)
        # 평가기준 판단방법: MINALPHA 기본 2, MINNONALPHA(숫자+특수) 기본 1 — MINDIGIT·MINSPECIAL 과 함께 사용 불가
        local a u l d s n
        _sv() { sed -n "s/^$1=\([0-9]*\).*/\1/p" /etc/default/passwd 2>/dev/null | tail -1; }
        ml=$(_sv PASSLENGTH); ml=${ml:-6}
        a=$(_sv MINALPHA); u=$(_sv MINUPPER); l=$(_sv MINLOWER); d=$(_sv MINDIGIT); s=$(_sv MINSPECIAL); n=$(_sv MINNONALPHA)
        { [ "${a:-2}" -ge 1 ] || [ "${u:-0}" -ge 1 ] || [ "${l:-0}" -ge 1 ]; } 2>/dev/null && cls=1
        if [ -n "$d$s" ]; then [ "${d:-0}" -ge 1 ] 2>/dev/null && cls=$((cls+1)); [ "${s:-0}" -ge 1 ] 2>/dev/null && cls=$((cls+1))
        else [ "${n:-1}" -ge 1 ] 2>/dev/null && cls=$((cls+1)); fi
        who="Solaris" ;;
    HPUX)
        ml=$(grep -E "^\s*MIN_PASSWORD_LENGTH" /etc/default/security 2>/dev/null | cut -d= -f2 | tr -d ' ')
        for k in PASSWORD_MIN_LOWER_CASE_CHARS PASSWORD_MIN_UPPER_CASE_CHARS PASSWORD_MIN_DIGIT_CHARS PASSWORD_MIN_SPECIAL_CHARS; do
            grep -qE "^\s*${k}=[1-9]" /etc/default/security 2>/dev/null && cls=$((cls+1)); done
        who="HP-UX" ;;
    *)
        local pam_files f line="" conf="" c neg=0 mcl
        pam_files=$(get_pam_files)
        for f in $pam_files; do
            [ -f "$f" ] || continue
            line=$(grep -v "^\s*#" "$f" 2>/dev/null | grep -iE "pam_pwquality|pam_cracklib" | head -1)
            [ -n "$line" ] && break
        done
        [ -f /etc/security/pwquality.conf ] && conf=$(grep -vhE "^\s*(#|$)" /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf 2>/dev/null)
        if [ -z "$line" ] && [ -z "$conf" ]; then echo "0 0 모듈없음"; return; fi
        _pwv() { local x; x=$(echo "$line" | grep -oE "(^|\s)$1=-?[0-9]+" | tail -1 | cut -d= -f2)
                 [ -z "$x" ] && x=$(echo "$conf" | grep -E "^\s*$1\s*=" | tail -1 | grep -oE -- '-?[0-9]+'); echo "$x"; }
        ml=$(_pwv minlen); ml=${ml:-9}
        mcl=$(_pwv minclass); mcl=${mcl:-0}
        for c in dcredit ucredit lcredit ocredit; do [ "$(_pwv $c)" -lt 0 ] 2>/dev/null && neg=$((neg+1)); done
        [ "$neg" -gt "$mcl" ] && mcl=$neg
        cls=$mcl; who="pwquality" ;;
    esac
    echo "${ml:-0} ${cls:-0} ${who}"
}

_pw_policy_ok() {  # 평가기준 복잡도: 2종 10자 이상 또는 3종 8자 이상
    local ml="$1" cls="$2"
    { [ "$cls" -ge 3 ] && [ "$ml" -ge 8 ]; } 2>/dev/null || { [ "$cls" -ge 2 ] && [ "$ml" -ge 10 ]; } 2>/dev/null
}

check_SRV069() {
    # 평가기준: 비밀번호 관련 정책(2종 10자/3종 8자 복잡도 + 변경 기간 90일 이하)이 설정되어 있을 경우 양호
    evd "SRV-069" "grep -E '^PASS_MAX_DAYS|^MAXWEEKS|^maxage|PASSWORD_MAXDAYS|MIN_PASSWORD_LENGTH' /etc/login.defs /etc/default/passwd /etc/security/user /etc/default/security 2>/dev/null; grep -vE '^\s*(#|$)' /etc/security/pwquality.conf 2>/dev/null"
    local days="" src="" issues="" pol ml cls who
    case "$OS_FAMILY" in
    AIX)     local w; w=$(_aix_default | grep -w "maxage" | grep -oE '[0-9]+' | head -1)
             [ -n "$w" ] && days=$((w*7)); src="maxage=${w:-미설정}주" ;;
    SOLARIS) local w; w=$(grep "^MAXWEEKS" /etc/default/passwd 2>/dev/null | cut -d= -f2 | tr -d ' ')
             [ -n "$w" ] && days=$((w*7)); src="MAXWEEKS=${w:-미설정}주" ;;
    HPUX)    days=$(grep -E "^\s*PASSWORD_MAXDAYS" /etc/default/security 2>/dev/null | cut -d= -f2 | tr -d ' '); src="PASSWORD_MAXDAYS=${days:-미설정}" ;;
    *)       days=$(grep "^PASS_MAX_DAYS" /etc/login.defs 2>/dev/null | awk '{print $2}'); src="PASS_MAX_DAYS=${days:-미설정}" ;;
    esac
    if [ -z "$days" ] || [ "$days" = "0" ]; then issues="변경 기간 미설정(${src})"
    elif [ "$days" -gt 90 ] 2>/dev/null; then issues="변경 기간 ${days}일 초과(${src})"; fi
    pol=$(_pw_policy); ml=${pol%% *}; cls=$(echo "$pol" | awk '{print $2}'); who=$(echo "$pol" | awk '{print $3}')
    if [ "$who" = "모듈없음" ]; then issues="${issues:+$issues / }복잡도 모듈(pam_pwquality/pam_cracklib) 미설정"
    else _pw_policy_ok "$ml" "$cls" || issues="${issues:+$issues / }복잡도 정책 미달(${who}: 최소 ${ml}자, ${cls}종)"; fi
    if [ "$OS_FAMILY" = "LINUX" ] && [ -r /etc/shadow ]; then
        local _acc; _acc=$(awk -F: 'NR==FNR{if($7!~/(nologin|false|sync|shutdown|halt)$/)sh[$1]=1;next} ($1 in sh) && $2!~/^[!*]/ && ($5=="" || $5+0>90){print $1"("($5==""?"미설정":$5)")"}' /etc/passwd /etc/shadow 2>/dev/null | head -5 | tr '\n' ' ')
        [ -n "$_acc" ] && issues="${issues:+$issues / }기존 계정 최대 사용기간 90일 초과/미설정(chage): ${_acc}"
    fi
    if [ -n "$issues" ]; then result "SRV-069|취약|${issues} - 기준: 2종 10자/3종 8자 이상, 변경 기간 90일 이하"
    else result "SRV-069|양호|비밀번호 정책 설정 (${src}, ${who}: 최소 ${ml}자·${cls}종)"; fi
}

# ================================================================
# SRV-070: 취약한 패스워드 저장 방식
# ================================================================
check_SRV070() {
    evd "SRV-070" "awk -F: '{print \$1,substr(\$2,1,4)}' /etc/shadow 2>/dev/null | head -20; grep -E '^ENCRYPT_METHOD' /etc/login.defs 2>/dev/null; grep -E '^CRYPT_(DEFAULT|ALGORITHMS)' /etc/security/policy.conf /etc/default/security 2>/dev/null; grep -E '^[[:space:]]*pwd_algorithm' /etc/security/login.cfg 2>/dev/null; ls -ld /tcb/files/auth 2>/dev/null"
    local des="" alg weak
    case "$OS_FAMILY" in
    AIX)
        # 판단방법(AIX): login.cfg pwd_algorithm 이 112비트 이상 해시인지, /etc/security/passwd 해시 형식
        alg=$(_aix_attr usw pwd_algorithm /etc/security/login.cfg)
        des=$(awk '/^[^ \t*#][^ \t]*:[ \t]*$/{sub(/:.*/,"");u=$0;next} /^[ \t]+password[ \t]*=/{v=$0;sub(/^[^=]*=[ \t]*/,"",v);sub(/[ \t]+$/,"",v); if(v!="" && v!="*" && v!~/^\{/) print u}' /etc/security/passwd 2>/dev/null | head -5 | tr '\n' ' ')
        if [ -n "$des" ]; then result "SRV-070|취약|AIX crypt(DES) 해시 계정: ${des}(pwd_algorithm=${alg:-미설정=crypt})"
        elif [ -z "$alg" ] || [ "$alg" = "crypt" ]; then result "SRV-070|취약|AIX pwd_algorithm 미설정(crypt, 112비트 미만)"
        else result "SRV-070|양호|AIX pwd_algorithm=${alg}"; fi ;;
    HPUX)
        if [ -d /tcb/files/auth ] || [ -f /etc/shadow ]; then
            alg=$(grep -E '^[[:space:]]*CRYPT_DEFAULT' /etc/default/security 2>/dev/null | cut -d= -f2 | tr -d ' ')
            case "$alg" in __unix__|"") result "SRV-070|수동확인|HP-UX $( [ -d /tcb/files/auth ] && echo 'Trusted Mode' || echo shadow ) 사용, CRYPT_DEFAULT=${alg:-미설정} - 해시 강도 확인" ;;
                           *) result "SRV-070|양호|HP-UX shadow/Trusted Mode + CRYPT_DEFAULT=${alg}" ;; esac
        else result "SRV-070|취약|HP-UX shadow·Trusted Mode 미사용 (/etc/passwd 에 해시 저장)"; fi ;;
    *)
        if [ ! -f /etc/shadow ]; then
            result "SRV-070|취약|/etc/shadow 없음 (평문 패스워드 저장 가능)"
            return
        fi
        # DES(crypt 13자), MD5($1$) 는 취약 / SHA256($5$)·SHA512($6$)·bcrypt($2*)·yescrypt($y$) 양호
        des=$(awk -F: '$2!="" && $2!~/^(\$|\*|!|NP$|x$|LK)/ && length($2)==13 {print $1}' /etc/shadow 2>/dev/null | head -5 | tr '\n' ' ')
        weak=$(awk -F: '$2 ~ /^\$1\$/ {print $1}' /etc/shadow 2>/dev/null | head -5)
        if [ -n "$des" ]; then result "SRV-070|취약|DES(crypt) 해시 계정: ${des}$( [ "$OS_FAMILY" = SOLARIS ] && echo "(CRYPT_DEFAULT=$(sed -n 's/^CRYPT_DEFAULT=//p' /etc/security/policy.conf 2>/dev/null))")"
        elif [ -n "$weak" ]; then result "SRV-070|취약|MD5 해시 계정 존재: $(echo $weak | tr '\n' ',')"
        else result "SRV-070|양호|shadow 사용, SHA256/SHA512 등 안전한 해시 (DES·MD5 없음)"; fi ;;
    esac
}

# ================================================================
# SRV-073: 관리자 그룹 불필요 사용자 제거
# ================================================================
check_SRV073() {
    # 평가기준: 관리자 그룹에 '불필요한' 계정 존재 여부 (인원 수 기준 없음) → 구성원 목록 증적 + 인터뷰
    evd "SRV-073" "grep -E '^(root|wheel|sudo|admin|system):' /etc/group 2>/dev/null"
    local grps="root wheel sudo admin"
    [ "$OS_FAMILY" = "BSD" ] && grps="wheel operator"
    [ "$OS_FAMILY" = "AIX" ] && grps="system security"
    local info="" members
    for grp in $grps; do
        members=$(grep "^${grp}:" /etc/group 2>/dev/null | cut -d: -f4)
        [ -n "$members" ] && info="${info} ${grp}:[${members}]"
    done
    if [ -z "$info" ]; then
        result "SRV-073|양호|관리자 그룹에 추가 구성원 없음"
    else
        result "SRV-073|수동확인|관리자 그룹 구성원:${info} - 불필요 계정 여부 확인"
    fi
}

# ================================================================
# SRV-074: 불필요/미관리 계정 제거
# ================================================================
check_SRV074() {
    # 평가기준: 로그인 가능한 계정별 분기(90일) 내 로그인 기록 + 비밀번호 변경 여부 (업무상 사용 여부 확인 필요)
    evd "SRV-074" "awk -F: '\$7 !~ /(nologin|false|sync|shutdown|halt)\$/ {print \$1,\$3,\$7}' /etc/passwd 2>/dev/null; lastlog 2>/dev/null | head -30"
    local today; today=$(( $(date +%s) / 86400 ))
    local vuln="" manual="" user sh pw lchg ll lsec now; now=$(date +%s)
    [ "$OS_FAMILY" = "AIX" ] && evd "SRV-074" "lsuser -a time_last_login lastupdate account_locked ALL 2>/dev/null"
    while IFS=: read -r user _ _ _ _ _ sh; do
        case "$sh" in *nologin|*false|*/sync|*/shutdown|*/halt|"") continue ;; esac
        pw=$(awk -F: -v u="$user" '$1==u{print $2}' /etc/shadow 2>/dev/null)
        case "$pw" in "!"*|"*"*) continue ;; esac   # 잠긴 계정(로그인 불가) 제외
        lchg=$(awk -F: -v u="$user" '$1==u{print $3}' /etc/shadow 2>/dev/null)
        local why=""
        case "$OS_FAMILY" in
        AIX)   # lsuser epoch: time_last_login(마지막 로그인), lastupdate(비밀번호 변경)
            [ "$(lsuser -a account_locked "$user" 2>/dev/null | sed -n 's/.*account_locked=//p')" = "true" ] && continue
            ll=$(lsuser -a time_last_login "$user" 2>/dev/null | sed -n 's/.*time_last_login=//p')
            lsec=$(lsuser -a lastupdate "$user" 2>/dev/null | sed -n 's/.*lastupdate=//p')
            if [ -z "$ll" ]; then why="로그인 기록 없음"
            elif [ $(( (now-ll)/86400 )) -gt 90 ] 2>/dev/null; then why="최근 로그인 $(( (now-ll)/86400 ))일 전"; fi
            [ -n "$lsec" ] && [ $(( (now-lsec)/86400 )) -gt 90 ] 2>/dev/null && why="${why:+$why, }비밀번호 변경 $(( (now-lsec)/86400 ))일 전"
            lchg="" ;;
        SOLARIS|HPUX)   # lastlog 없음 — last 출력은 연도 미표기라 로그인 일자는 증적으로 수동 확인
            manual="${manual} ${user}" ;;
        *)
            ll=$(lastlog -u "$user" 2>/dev/null | awk 'NR==2')
            [ -z "$ll" ] && command -v lastlog2 >/dev/null 2>&1 && ll=$(lastlog2 -u "$user" 2>/dev/null | awk 'NR==2')
            if [ -z "$ll" ] && ! command -v lastlog >/dev/null 2>&1 && ! command -v lastlog2 >/dev/null 2>&1; then manual="${manual} ${user}"
            elif [ -z "$ll" ] || echo "$ll" | grep -q "Never logged in"; then why="로그인 기록 없음"
            else
                lsec=$(date -d "$(echo "$ll" | awk '{for(i=NF-5;i<=NF;i++) printf $i" "}')" +%s 2>/dev/null)
                [ -n "$lsec" ] && [ $(( today - lsec/86400 )) -gt 90 ] && why="최근 로그인 $(( today - lsec/86400 ))일 전"
            fi ;;
        esac
        if [ -n "$lchg" ] && [ "$lchg" -gt 0 ] 2>/dev/null && [ $(( today - lchg )) -gt 90 ]; then why="${why:+$why, }비밀번호 변경 $(( today - lchg ))일 전"; fi
        [ -n "$why" ] && vuln="${vuln} ${user}(${why})"
    done < /etc/passwd
    [ -n "$manual" ] && evd "SRV-074" "for u in $(echo $manual); do last -1 \$u 2>/dev/null | head -1; done"
    if [ -n "$vuln" ]; then result "SRV-074|취약|분기 내 로그인/비밀번호 변경 없는 로그인 가능 계정:${vuln} - 업무상 사용 여부 확인"
    elif [ -n "$manual" ]; then result "SRV-074|수동확인|로그인 기록 자동 조회 불가 계정:${manual} - last 증적으로 90일 내 로그인 확인"
    else result "SRV-074|양호|로그인 가능 계정 모두 분기 내 로그인 및 비밀번호 변경"; fi
}

# ================================================================
# SRV-075: 비밀번호 복잡도
# ================================================================
check_SRV075() {
    # 평가기준: 모든 계정이 복잡도(2종 10자 / 3종 8자) 만족 — 판단방법: 빈 비밀번호 계정 확인 + 크랙
    evd "SRV-075" "grep -v '^#' /etc/security/pwquality.conf 2>/dev/null | grep -v '^$'"
    evd "SRV-075" "grep -i 'pam_pwquality\\|pam_cracklib' /etc/pam.d/system-auth /etc/pam.d/password-auth /etc/pam.d/common-password 2>/dev/null"
    local empty pol ml cls who
    empty=$(awk -F: '($2==""){print $1}' /etc/shadow 2>/dev/null | tr '\n' ' ')
    [ -n "$empty" ] && { result "SRV-075|취약|비밀번호 미설정 계정: ${empty}"; return; }
    pol=$(_pw_policy); ml=${pol%% *}; cls=$(echo "$pol" | awk '{print $2}'); who=$(echo "$pol" | awk '{print $3}')
    if [ "$who" = "모듈없음" ]; then result "SRV-075|취약|비밀번호 복잡도 모듈(pam_pwquality/pam_cracklib) 미설정"
    elif _pw_policy_ok "$ml" "$cls"; then
        result "SRV-075|수동확인|${who} 정책 기준 충족 (최소 ${ml}자, 문자 종류 ${cls}종 이상) - 기존 계정 비밀번호 복잡도 만족 여부(크랙) 확인"
    else
        result "SRV-075|취약|${who} 정책 기준 미달 (최소 ${ml}자, 문자 종류 ${cls}종 요구) - 기준: 2종 10자 이상 또는 3종 8자 이상"
    fi
}

_srv075_judge() {
    local who="$1" ml="$2" cls="$3"
    if { [ "$cls" -ge 3 ] && [ "$ml" -ge 8 ]; } 2>/dev/null || { [ "$cls" -ge 2 ] && [ "$ml" -ge 10 ]; } 2>/dev/null; then
        result "SRV-075|수동확인|${who} 정책 기준 충족 (최소 ${ml}자, 문자 종류 ${cls}종 이상) - 기존 계정 비밀번호 복잡도 만족 여부(크랙) 확인"
    else
        result "SRV-075|취약|${who} 정책 기준 미달 (최소 ${ml}자, 문자 종류 ${cls}종 요구) - 기준: 2종 10자 이상 또는 3종 8자 이상"
    fi
}

# ================================================================
# SRV-081: Crontab 설정파일 권한
# ================================================================
check_SRV081() {
    # 평가기준: crontab 명령 750 이하 / crontab 파일 others 읽기·쓰기 없음 / at·cron allow·deny 소유자 root·640 이하
    evd "SRV-081" "ls -alL /usr/bin/crontab /etc/cron.allow /etc/cron.deny /etc/at.allow /etc/at.deny 2>/dev/null; ls -alL /var/spool/cron/crontabs/ /var/spool/cron/ 2>/dev/null"
    local vuln="" p o f
    for f in /usr/bin/crontab /bin/crontab; do
        [ -f "$f" ] || continue
        p=$(get_perm "$f"); p=${p: -3}
        # 750 이하: others 권한 0, group 쓰기 없음
        { [ "${p:2:1}" != "0" ] || [ $(( ${p:1:1} & 2 )) -ne 0 ]; } 2>/dev/null && vuln="${vuln} ${f}(${p})"
        break
    done
    for d in /var/spool/cron/crontabs /var/spool/cron; do
        [ -d "$d" ] || continue
        for f in "$d"/*; do
            [ -f "$f" ] || continue
            p=$(get_perm "$f"); p=${p: -1}
            [ $(( p & 6 )) -ne 0 ] 2>/dev/null && vuln="${vuln} ${f}(others:${p})"
        done
        break
    done
    for f in /etc/cron.allow /etc/cron.deny /etc/at.allow /etc/at.deny /var/adm/cron/cron.allow /var/adm/cron/cron.deny /var/adm/cron/at.allow /var/adm/cron/at.deny /etc/cron.d/cron.allow /etc/cron.d/cron.deny /etc/cron.d/at.allow /etc/cron.d/at.deny; do
        [ -f "$f" ] || continue
        o=$(get_owner "$f"); p=$(get_perm "$f"); p=${p: -3}
        if [ "$o" != "root" ] || [ "${p:0:1}" -gt 6 ] || [ "${p:1:1}" -gt 4 ] || [ "${p:2:1}" != "0" ]; then vuln="${vuln} ${f}(${o}:${p})"; fi 2>/dev/null
    done
    [ -n "$vuln" ] && result "SRV-081|취약|cron 관련 파일 권한 과다:${vuln}" \
                   || result "SRV-081|양호|crontab 명령·crontab 파일·at/cron 접근제어 파일 권한 기준 충족"
}

# ================================================================
# SRV-084: 시스템 주요 파일 권한
# ================================================================
check_SRV084() {
    # 평가기준: passwd 644 / shadow 600 / hosts 644 / (x)inetd.conf 600 / syslog.conf 644 / services 644 / hosts.lpd 640, 소유자 root (AIX /etc/security/passwd 600)
    evd "SRV-084" "ls -la /etc/passwd /etc/shadow /etc/group /etc/hosts /etc/services /etc/rsyslog.conf /etc/syslog.conf /etc/inetd.conf /etc/xinetd.conf /etc/hosts.lpd /etc/security/passwd 2>/dev/null"
    local vuln="" f max
    for f in /etc/passwd:644 /etc/shadow:600 /etc/hosts:644 /etc/services:644 /etc/rsyslog.conf:644 /etc/syslog.conf:644 \
             /etc/inetd.conf:600 /etc/xinetd.conf:600 /etc/hosts.lpd:640 /etc/security/passwd:600; do
        max=${f##*:}; f=${f%:*}
        [ -f "$f" ] || continue
        [ "$(get_owner "$f")" != "root" ] && vuln="${vuln} ${f}(소유자=$(get_owner "$f"))"
        _perm_over "$(get_perm "$f")" "$max" && vuln="${vuln} ${f}($(get_perm "$f")>${max})"
    done
    if [ "$OS_FAMILY" = "HPUX" ] && [ -d /tcb/files/auth ]; then   # 평가기준(HP-UX): /tcb/files/auth/[a-z]/* 664, 소유자 root
        local tn=0
        for f in /tcb/files/auth/[a-z]/*; do
            [ -f "$f" ] || continue
            { [ "$(get_owner "$f")" != "root" ] || _perm_over "$(get_perm "$f")" 664; } && { tn=$((tn+1)); [ $tn -le 5 ] && vuln="${vuln} ${f}($(get_owner "$f"):$(get_perm "$f"))"; }
        done
        [ $tn -gt 5 ] && vuln="${vuln} …/tcb 외 $((tn-5))건"
    fi
    [ -n "$vuln" ] && result "SRV-084|취약|주요 파일 권한 기준 초과:${vuln}" || result "SRV-084|양호|주요 파일 소유자 root·권한 기준 이하"
}

# ================================================================
# SRV-091: SUID/SGID 파일 관리
# ================================================================
check_SRV091() {
    # 평가기준: 불필요하게 SUID·SGID 설정된 파일
    evd "SRV-091" "_to 30 find / \$_FP \( -perm -4000 -o -perm -2000 \) -type f -print 2>/dev/null | head -40"
    local dangerous="nmap perl python python3 php ruby bash sh find wget curl nc netcat awk vim gdb strace less more cp mv tar zip" bin bp found="" f nopkg=""
    for bin in $dangerous; do
        bp=$(command -v "$bin" 2>/dev/null); [ -z "$bp" ] && continue
        { [ -u "$bp" ] || [ -g "$bp" ]; } && found="${found} ${bp}"
    done
    if [ -n "$found" ]; then result "SRV-091|취약|위험 SUID/SGID 파일:${found}"; return; fi
    while IFS= read -r f; do
        # usrmerge 배포판은 패키지 DB 에 /bin·/sbin 경로로 등록되어 있어 두 경로 모두 조회
        { rpm -qf "$f" >/dev/null 2>&1 || dpkg -S "$f" >/dev/null 2>&1 || dpkg -S "${f#/usr}" >/dev/null 2>&1 || dpkg -S "$(readlink -f "$f")" >/dev/null 2>&1; } || nopkg="${nopkg} ${f}"
    done < <(_to 30 find / $_FP \( -perm -4000 -o -perm -2000 \) -type f -print 2>/dev/null | grep -vE '^/(proc|sys|var/lib/(docker|containers))' | head -200)
    { command -v rpm >/dev/null 2>&1 || command -v dpkg >/dev/null 2>&1; } || nopkg=""
    [ -n "$nopkg" ] && result "SRV-091|수동확인|패키지 외 SUID/SGID 파일:$(echo $nopkg | cut -c1-200) - 필요 여부 확인" || result "SRV-091|양호|위험 SUID/SGID 없음, 패키지 기본 파일만 존재"
}

# ================================================================
# SRV-092: 사용자 홈 디렉토리 경로/권한
# ================================================================
check_SRV092() {
    # 평가기준: 홈 디렉터리 소유자 불일치·계정간 중복 홈·others 쓰기
    evd "SRV-092" "awk -F: '\$3>=1000 || \$3>=500{print \$1,\$3,\$6}' /etc/passwd 2>/dev/null | head -30"
    local vuln="" min_uid dup user uid homedir
    min_uid=$(awk '/^UID_MIN/{print $2}' /etc/login.defs 2>/dev/null)
    [ -z "$min_uid" ] && case "$OS_FAMILY" in AIX) min_uid=200 ;; SOLARIS|HPUX) min_uid=100 ;; *) min_uid=500 ;; esac   # UNIX 일반 사용자 UID 대역
    dup=$(awk -F: -v m="$min_uid" '$3>=m && $6!="" && $6!="/"{print $6}' /etc/passwd 2>/dev/null | sort | uniq -d | tr '\n' ' ')
    [ -n "$dup" ] && vuln="${vuln} 중복 홈:${dup}"
    while IFS=: read -r user _ uid _ _ homedir _; do
        [ "${uid:-0}" -lt "$min_uid" ] 2>/dev/null && continue
        { [ "${uid:-0}" -ge 60000 ] || [ "${uid:-0}" -lt 0 ]; } 2>/dev/null && continue   # nobody·noaccess 등
        [ -z "$homedir" ] || [ "$homedir" = "/" ] || [ ! -d "$homedir" ] && continue
        [ "$(get_owner "$homedir")" != "$user" ] && vuln="${vuln} ${homedir}(소유자:$(get_owner "$homedir"))"
        local p; p=$(get_perm "$homedir"); [ $(( ${p: -1} & 2 )) -ne 0 ] && vuln="${vuln} ${homedir}(others 쓰기:${p})"
    done < /etc/passwd
    [ -n "$vuln" ] && result "SRV-092|취약|홈 디렉터리 이상:${vuln}" || result "SRV-092|양호|홈 디렉터리 소유자 일치·중복 없음·others 쓰기 없음"
}

# ================================================================
# SRV-093: world writable 파일
# ================================================================
check_SRV093() {
    evd "SRV-093" "_to 60 find / \$_FP -perm -0002 -type f ! -path '/proc/*' ! -path '/sys/*' ! -path '/dev/*' ! -path '/tmp/*' ! -path '/var/tmp/*' -print 2>/dev/null | head -20"
    local _ww _rc
    _ww=$(_to 60 find / $_FP -perm -0002 -type f ! -path "/proc/*" ! -path "/sys/*" \
          ! -path "/dev/*" ! -path "/tmp/*" ! -path "/var/tmp/*" -print 2>/dev/null); _rc=$?
    cnt=$(printf '%s' "$_ww" | grep -c .)
    # timeout(124) 이고 0건이면 검색 미완료 — 양호로 단정하지 않음
    if [ "$_rc" = "124" ] && [ "${cnt:-0}" -eq 0 ]; then result "SRV-093|수동확인|파일 검색 시간 초과(60초) - world writable 파일 수동 확인"; return; fi
    [ "${cnt:-0}" -gt 0 ] 2>/dev/null && \
        result "SRV-093|취약|world writable 파일 ${cnt}개 (tmp 제외)" || \
        result "SRV-093|양호|world writable 파일 없음"
}

# ================================================================
# SRV-108: 로그 접근통제 및 관리
# ================================================================
check_SRV108() {
    evd "SRV-108" "ls -la /var/log/messages /var/log/secure /var/log/auth.log /var/log/syslog /var/log/wtmp /var/log/lastlog 2>/dev/null"
    # 기준: 로그 파일을 소유자 이외 사용자가 수정 가능(그룹/others 쓰기)하면 취약 — 예외: wtmp·lastlog 664, btmp 660 (권한 변경 불가)
    vuln=""
    for logf in $(find /var/log /var/adm $( [ "$OS_FAMILY" = "AIX" ] && echo /etc/security ) -type f \( -perm -020 -o -perm -002 \) 2>/dev/null | head -200); do
        perm=$(get_perm "$logf")
        case "$(basename "$logf")" in
        wtmp*|lastlog*|btmp*) [ "$(( 0${perm: -1} & 2 ))" -eq 0 ] 2>/dev/null && continue ;;
        esac
        vuln="${vuln} ${logf}(${perm})"
    done
    [ -n "$vuln" ] && result "SRV-108|취약|소유자 외 쓰기 가능한 로그 파일:${vuln}" || \
        result "SRV-108|양호|로그 파일 소유자 외 쓰기 권한 없음 (wtmp·lastlog 664, btmp 660 기준 예외)"
}

# ================================================================
# SRV-109: 주요 이벤트 로그 설정
# ================================================================
check_SRV109() {
    evd "SRV-109" "grep -ihE '^auth|^authpriv|\*\.' /etc/rsyslog.conf /etc/rsyslog.d/*.conf /etc/syslog.conf 2>/dev/null | head -10; cat /etc/default/su 2>/dev/null | grep -E 'SULOG|SYSLOG'"
    case "$OS_FAMILY" in
    SOLARIS)
        # 평가기준(Solaris): auth.info 활성 + /etc/default/su SULOG=경로, SYSLOG=YES
        local a=0 s=0
        grep -vE '^\s*#' /etc/syslog.conf 2>/dev/null | grep -qE 'auth\.(info|debug|\*)|\*\.(info|debug)' && a=1
        grep -qE '^SULOG=' /etc/default/su 2>/dev/null && grep -qE '^SYSLOG=YES' /etc/default/su 2>/dev/null && s=1
        [ $a -eq 1 ] && [ $s -eq 1 ] && result "SRV-109|수동확인|auth.info·SULOG·SYSLOG=YES 설정 - 내부 로그 정책 부합 여부 확인" || result "SRV-109|취약|Solaris auth.info(${a})·/etc/default/su SULOG·SYSLOG=YES(${s}) 미충족" ;;
    AIX|HPUX)
        grep -vE '^\s*\*|^\s*#' /etc/syslog.conf 2>/dev/null | grep -qiE "^auth|\*\.(info|debug)" && \
            result "SRV-109|수동확인|syslog auth 설정 존재 - 내부 로그 기록 정책 부합 여부 확인" || result "SRV-109|취약|syslog auth 로그 미설정" ;;
    *)
        local f
        for f in /etc/rsyslog.conf /etc/rsyslog.d/*.conf /etc/syslog.conf; do
            [ -f "$f" ] || continue
            grep -qiE "^auth|^authpriv" "$f" 2>/dev/null && { result "SRV-109|양호|auth/authpriv 로그 설정됨 (${f}) - 내부 로그 정책 부합 여부는 참고 확인"; return; }
        done
        [ -f /etc/syslog-ng/syslog-ng.conf ] && grep -qi "auth\|authpriv" /etc/syslog-ng/syslog-ng.conf 2>/dev/null && { result "SRV-109|양호|syslog-ng auth 로그 설정됨"; return; }
        result "SRV-109|취약|auth/authpriv 로그 설정 없음" ;;
    esac
}

# ================================================================
# SRV-118: 보안패치 적용
# ================================================================
check_SRV118() {
    evd "SRV-118" "uname -r; oslevel -s 2>/dev/null; instfix -i 2>/dev/null | grep -E 'ML|SP' | tail -3; emgr -l 2>/dev/null | head; swlist -l bundle 2>/dev/null | grep -iE 'QPK|HPUX'; showrev -p 2>/dev/null | tail -5; pkg info entire 2>/dev/null | grep -iE 'version|branch'"
    evd "SRV-118" "rpm -qa --last 2>/dev/null | head -10 || dpkg -l 2>/dev/null | tail -10"
    case "$OS_FAMILY" in
    LINUX)
        # 저장소 조회 실패(폐쇄망·미등록)·미지원 패키지 관리자는 건수 0 으로 보지 않고 수동확인
        _upd_cnt=""; _upd_out=""; _upd_rc=0
        if command -v dnf >/dev/null 2>&1 || command -v yum >/dev/null 2>&1; then
            _pm=$(command -v dnf >/dev/null 2>&1 && echo dnf || echo yum)
            _upd_out=$(timeout 120 $_pm -q check-update 2>/dev/null); _upd_rc=$?
            # check-update: 100=업데이트 있음, 0=없음, 그 외(1 등)=저장소 오류
            case "$_upd_rc" in 100) _upd_cnt=$(echo "$_upd_out" | grep -cE "^[a-zA-Z0-9]") ;; 0) _upd_cnt=0 ;; esac
        elif command -v apt-get >/dev/null 2>&1; then
            # apt-get update 는 저장소 접근 실패(W: Failed to fetch)에도 0 을 반환 → 출력으로 실패 판별
            _upd_out=$(timeout 120 apt-get update 2>&1); _upd_rc=$?
            if [ "$_upd_rc" -eq 0 ] && ! echo "$_upd_out" | grep -qE "^Err:|Failed to fetch|Some index files failed|Temporary failure resolving"; then
                _upd_cnt=$(apt-get -s upgrade 2>/dev/null | grep -c "^Inst ")
            fi
        elif command -v zypper >/dev/null 2>&1; then
            _upd_out=$(timeout 120 zypper -q --non-interactive list-updates 2>/dev/null); _upd_rc=$?
            [ "$_upd_rc" -eq 0 ] && _upd_cnt=$(echo "$_upd_out" | grep -c "^v ")
        fi
        evd "SRV-118" "echo 'package manager rc=${_upd_rc} upgradable=${_upd_cnt:-조회 실패}'"
        if [ -z "$_upd_cnt" ]; then
            result "SRV-118|수동확인|패키지 저장소 조회 실패(폐쇄망·저장소 미등록 등) 또는 미지원 패키지 관리자 - 보안패치 적용 현황·검토 절차 수동 확인"
        elif [ "${_upd_cnt:-0}" -gt 0 ] 2>/dev/null; then
            result "SRV-118|취약|미적용 보안패치 ${_upd_cnt}건 (수동 확인 병행 권고)"
        elif [ "${_upd_cnt:-0}" -eq 0 ] 2>/dev/null; then
            result "SRV-118|양호|패키지 매니저 기준 미적용 업데이트 없음"
        else
            result "SRV-118|수동확인|보안패치 적용 현황 수동 확인 필요"
        fi ;;
    *)
        result "SRV-118|수동확인|보안패치 적용 현황 수동 확인 필요" ;;
    esac
}

# ================================================================
# SRV-121: root PATH 환경변수
# ================================================================
check_SRV121() {
    # 평가기준: PATH 에 '.', '::'(빈 항목) 또는 불필요한 임의 경로
    evd "SRV-121" "echo \$PATH; grep -rhE '^\s*(export\s+)?PATH=' /root/.bashrc /root/.bash_profile /root/.profile /etc/profile /etc/environment /etc/bashrc /etc/profile.d/*.sh 2>/dev/null"
    local bad="" v e
    while IFS= read -r v; do
        v=$(echo "$v" | sed -E 's/^\s*(export\s+)?PATH=//; s/["'"'"']//g')
        [ -z "$v" ] && continue
        case ":$v:" in *"::"*) bad="${bad} [빈 항목] ${v}"; continue ;; esac
        local IFS=':'; for e in $v; do
            case "$e" in .|./*) bad="${bad} [.] ${v}"; break ;; esac
        done; unset IFS
    done < <( { grep -rhE '^\s*(export\s+)?PATH=' /root/.bashrc /root/.bash_profile /root/.profile /etc/profile /etc/environment /etc/bashrc /etc/profile.d/*.sh 2>/dev/null; echo "PATH=$PATH"; } )
    [ -n "$bad" ] && result "SRV-121|취약|PATH 에 현재 디렉터리(.) 또는 빈 항목:$(echo "$bad" | cut -c1-200)" || result "SRV-121|양호|PATH 에 '.'·'::' 미포함"
}

# ================================================================
# SRV-122: umask 설정
# ================================================================
check_SRV122() {
    # 평가기준: 모든 계정·설정 파일 umask 가 022 이상(group·others 쓰기 금지)
    evd "SRV-122" "umask; grep -rhE '^\s*umask|^UMASK' /etc/profile /etc/bashrc /etc/login.defs /etc/profile.d/*.sh /root/.bashrc /root/.profile 2>/dev/null"
    local vals v bad=""
    local _homes; _homes=$(awk -F: '$7!~/(nologin|false)$/ && $6!="" && $6!="/"{print $6}' /etc/passwd 2>/dev/null | sort -u)
    vals=$( { grep -rhE '^\s*umask\s+[0-7]+|^\s*UMASK\s+[0-7]+' /etc/profile /etc/bashrc /etc/bash.bashrc /etc/login.defs /etc/profile.d/*.sh $(for h in $_homes; do echo "$h/.profile $h/.bashrc $h/.bash_profile $h/.kshrc $h/.cshrc"; done) 2>/dev/null | grep -oE '[0-7]{2,4}';
              [ "$OS_FAMILY" = "AIX" ] && awk '/^[^ \t*#][^ \t]*:[ \t]*$/{next} /^[ \t]+umask[ \t]*=/{v=$0;sub(/^[^=]*=[ \t]*/,"",v);print v}' /etc/security/user 2>/dev/null;
              [ "$OS_FAMILY" = "HPUX" ] && sed -n 's/^[[:space:]]*UMASK=\([0-7]*\).*/\1/p' /etc/default/security 2>/dev/null; } | sort -u)
    [ "$OS_FAMILY" = "AIX" ] && evd "SRV-122" "lsuser -a umask ALL 2>/dev/null"
    [ -z "$vals" ] && vals=$(umask 2>/dev/null)
    for v in $vals; do
        (( (8#$v & 8#022) == 8#022 )) || bad="${bad} ${v}"
    done
    [ -n "$bad" ] && result "SRV-122|취약|group/others 쓰기 허용 umask:${bad} (022 이상 필요, 조건부 설정 포함)" || result "SRV-122|양호|umask $(echo $vals) (022 이상)"
}

# ================================================================
# SRV-127: 로그인 실패 횟수 접속 제한
# ================================================================
check_SRV127() {
    # 평가기준: 계정 잠금 임계값 설정이 존재하면 양호 (횟수는 내부 규정 확인)
    evd "SRV-127" "grep -i 'pam_faillock\\|pam_tally' /etc/pam.d/system-auth /etc/pam.d/password-auth /etc/pam.d/common-auth 2>/dev/null"
    evd "SRV-127" "cat /etc/security/faillock.conf 2>/dev/null | grep -v '^#' | grep -v '^$'"
    local val="" label=""
    case "$OS_FAMILY" in
    AIX)     label="AIX loginretries";      val=$(_aix_attr default loginretries)
             evd "SRV-127" "lsuser -a loginretries ALL 2>/dev/null"
             local z; z=$(awk '/^[^ \t*#][^ \t]*:[ \t]*$/{sub(/:.*/,"");st=$0;next} st!="default" && st!="root" && /^[ \t]+loginretries[ \t]*=[ \t]*0[ \t]*$/{print st}' /etc/security/user 2>/dev/null | tr '\n' ' ')
             [ -n "$z" ] && [ "${val:-0}" -gt 0 ] 2>/dev/null && { result "SRV-127|취약|AIX loginretries=${val}(default)이나 계정별 0 재정의: ${z}"; return; } ;;
    SOLARIS) # 평가기준(SOL): policy.conf LOCK_AFTER_RETRIES=YES + /etc/default/login RETRIES 설정
             evd "SRV-127" "grep -E 'LOCK_AFTER_RETRIES' /etc/security/policy.conf 2>/dev/null; grep -E 'RETRIES' /etc/default/login 2>/dev/null"
             if grep -qE '^[[:space:]]*LOCK_AFTER_RETRIES=YES' /etc/security/policy.conf 2>/dev/null; then
                 val=$(sed -n 's/^[[:space:]]*RETRIES=\([0-9]*\).*/\1/p' /etc/default/login 2>/dev/null | tail -1)
                 label="Solaris LOCK_AFTER_RETRIES=YES, RETRIES"
             else label="Solaris LOCK_AFTER_RETRIES 미설정(≠YES)"; val=""; fi ;;
    HPUX)    # Trusted Mode: /tcb/files/auth/system/default u_maxtries#N / Non Trusted: AUTH_MAXTRIES (/etc/default/security, /var/adm/userdb/*)
             if [ -f /tcb/files/auth/system/default ]; then label="HP-UX u_maxtries(Trusted)"; val=$(grep -oE 'u_maxtries#[0-9]+' /tcb/files/auth/system/default 2>/dev/null | head -1 | cut -d'#' -f2)
             else label="HP-UX AUTH_MAXTRIES"; val=$(grep -hE "^\s*AUTH_MAXTRIES" /etc/default/security /var/adm/userdb/* 2>/dev/null | head -1 | cut -d= -f2 | tr -d ' '); fi ;;
    *)
        local pam_files f d found=0
        pam_files=$(get_pam_files)
        for f in $pam_files; do
            [ -f "$f" ] || continue
            if grep -v "^\s*#" "$f" 2>/dev/null | grep -qi "pam_faillock"; then
                label="pam_faillock"; found=1
                val=$(grep -v "^\s*#" "$f" | grep -i "pam_faillock" | grep -oE 'deny=[0-9]+' | cut -d= -f2 | head -1)
                break
            fi
        done
        if [ -f /etc/security/faillock.conf ]; then
            d=$(grep -v "^\s*#" /etc/security/faillock.conf 2>/dev/null | grep -E "^\s*deny\s*=" | grep -oE '[0-9]+' | head -1)
            [ -n "$d" ] && { val=$d; label="faillock.conf deny"; }
            [ $found -eq 1 ] && [ -z "$val" ] && { val=3; label="pam_faillock(기본 deny=3)"; }
        fi
        if [ $found -eq 0 ] && [ -z "$d" ]; then
            for f in $pam_files; do
                [ -f "$f" ] || continue
                if grep -v "^\s*#" "$f" 2>/dev/null | grep -qi "pam_tally"; then
                    label="pam_tally2"; val=$(grep -v "^\s*#" "$f" | grep -i "pam_tally" | grep -oE 'deny=[0-9]+' | cut -d= -f2 | head -1); break
                fi
            done
        fi ;;
    esac
    if [ -z "$val" ] || [ "$val" = "0" ]; then
        result "SRV-127|취약|계정 잠금 임계값 미설정${label:+ (${label})}"
    elif [ "$val" -le 5 ] 2>/dev/null; then
        result "SRV-127|양호|${label}=${val}회 설정"
    else
        result "SRV-127|양호|${label}=${val}회 설정 (5회 초과 - 내부 규정 기준 확인)"
    fi
}

# ================================================================
# SRV-131: su 명령어 그룹 제한
# ================================================================
check_SRV131() {
    evd "SRV-131" "grep -v '^#' /etc/pam.d/su 2>/dev/null; ls -l /bin/su /usr/bin/su 2>/dev/null; awk '/^(root|default):/,/^\$/' /etc/security/user 2>/dev/null | grep sugroups; grep -i SU_ROOT_GROUP /etc/default/security 2>/dev/null; grep -i su_group /etc/pam.conf 2>/dev/null"
    local su p
    su=$(ls /bin/su /usr/bin/su 2>/dev/null | head -1); p=$(get_perm "$su")
    case "$OS_FAMILY" in
    AIX)
        local g; g=$(awk '/^root:/{f=1;next} /^[^ \t*]/{f=0} f&&/sugroups/{sub(/.*=[ \t]*/,"");print;exit}' /etc/security/user 2>/dev/null)
        [ -z "$g" ] && g=$(awk '/^default:/{f=1;next} /^[^ \t*]/{f=0} f&&/sugroups/{sub(/.*=[ \t]*/,"");print;exit}' /etc/security/user 2>/dev/null)
        [ -n "$g" ] && [ "${g^^}" != "ALL" ] && result "SRV-131|양호|AIX sugroups=${g}" || result "SRV-131|취약|AIX sugroups=${g:-미설정} (ALL/미설정)" ;;
    HPUX)
        local g; g=$(grep -E '^\s*SU_ROOT_GROUP' /etc/default/security 2>/dev/null | cut -d= -f2 | tr -d ' ')
        [ -n "$g" ] && [ "${g^^}" != "ALL" ] && result "SRV-131|양호|HP-UX SU_ROOT_GROUP=${g}" || result "SRV-131|취약|HP-UX SU_ROOT_GROUP 미지정" ;;
    SOLARIS)
        if grep -vE '^\s*#' /etc/pam.conf 2>/dev/null | grep -q su_group; then result "SRV-131|양호|pam.conf su_group 설정"
        elif [ -n "$p" ] && [ $(( ${p: -1} & 1 )) -eq 0 ]; then result "SRV-131|양호|${su} others 실행 권한 없음 (${p}, 그룹=$(ls -l "$su" | awk '{print $4}'))"
        else result "SRV-131|취약|${su:-su} others 실행 가능 (${p:-미확인})"; fi ;;
    *)
        if grep -vE '^\s*#' /etc/pam.d/su 2>/dev/null | grep -qE '^\s*auth\s+(required|requisite)\s+\S*pam_wheel\.so'; then
            result "SRV-131|양호|su pam_wheel required 설정 (그룹=$(grep -vE '^\s*#' /etc/pam.d/su | grep -oE 'group=\S+' | cut -d= -f2 | head -1 | sed 's/^$/wheel/'))"
        elif [ -n "$p" ] && [ $(( ${p: -1} & 1 )) -eq 0 ]; then result "SRV-131|양호|${su} others 실행 권한 없음 (${p})"
        else result "SRV-131|취약|su pam_wheel(required) 미설정, ${su} others 실행 가능 (${p:-미확인})"; fi ;;
    esac
}

# ================================================================
# SRV-133: Cron 서비스 사용 계정 제한
# ================================================================
check_SRV133() {
    # 평가기준: allow/deny 내부에 계정 존재 또는 둘 다 없음(root만 사용) → 양호 / allow 없고 deny 비어 있음 → 취약
    local allow=/etc/cron.allow deny=/etc/cron.deny
    { [ "$OS_FAMILY" = "AIX" ] || [ "$OS_FAMILY" = "HPUX" ]; } && { allow=/var/adm/cron/cron.allow; deny=/var/adm/cron/cron.deny; }
    [ "$OS_FAMILY" = "SOLARIS" ] && { allow=/etc/cron.d/cron.allow; deny=/etc/cron.d/cron.deny; }
    evd "SRV-133" "ls -la $allow $deny 2>/dev/null; echo '[allow]'; cat $allow 2>/dev/null; echo '[deny]'; cat $deny 2>/dev/null"
    local a_cnt d_cnt
    a_cnt=$(grep -vcE '^\s*(#|$)' "$allow" 2>/dev/null); d_cnt=$(grep -vcE '^\s*(#|$)' "$deny" 2>/dev/null)
    if [ -f "$allow" ] && [ "${a_cnt:-0}" -gt 0 ]; then result "SRV-133|양호|${allow} 허용 계정 ${a_cnt}개 관리"
    elif [ ! -f "$allow" ] && [ ! -f "$deny" ]; then result "SRV-133|양호|cron.allow/cron.deny 모두 없음 (root만 cron 사용 가능)"
    elif [ ! -f "$allow" ] && [ "${d_cnt:-0}" -eq 0 ]; then result "SRV-133|취약|cron.allow 없고 cron.deny 비어 있음 (모든 계정 cron 사용 가능)"
    elif [ ! -f "$allow" ]; then result "SRV-133|양호|${deny} 거부 계정 ${d_cnt}개 관리"
    else result "SRV-133|수동확인|${allow} 존재하나 허용 계정 없음 (cron 사용 불가) - 의도 확인"; fi
}

# ================================================================
# SRV-142: 중복 UID 계정 제한
# ================================================================
check_SRV142() {
    evd "SRV-142" "awk -F: '{print \$3}' /etc/passwd 2>/dev/null | sort | uniq -d"
    dup=$(awk -F: '{print $3}' /etc/passwd 2>/dev/null | sort | uniq -d)
    [ -n "$dup" ] && result "SRV-142|취약|중복 UID 발견: $(echo $dup | head -5)" || \
        result "SRV-142|양호|중복 UID 없음"
}

# ================================================================
# SRV-144: /dev 불필요 파일
# ================================================================
check_SRV144() {
    # 평가기준: /dev 에 존재하지 않는 불필요 device(일반) 파일 (mqueue, shm 예외)
    evd "SRV-144" "find /dev \\( -path /dev/shm -o -path /dev/mqueue \\) -prune -o -type f -print 2>/dev/null | head -20"
    local fl; fl=$(find /dev \( -path /dev/shm -o -path /dev/mqueue \) -prune -o -type f -print 2>/dev/null | head -10)
    [ -n "$fl" ] && result "SRV-144|취약|/dev 내 일반 파일: $(echo "$fl" | tr '\n' ' ' | cut -c1-200)" || result "SRV-144|양호|/dev 불필요 일반 파일 없음 (shm·mqueue 제외)"
}

# ================================================================
# SRV-158: 불필요 Telnet 서비스 비활성화
# ================================================================
check_SRV158() {
    evd "SRV-158" "grep -vE '^\s*#' /etc/inetd.conf 2>/dev/null | grep -w telnet; inetadm 2>/dev/null | grep -i telnet; lssrc -ls inetd 2>/dev/null | grep -i telnet; ss -tln 2>/dev/null | grep ':23 '; netstat -an 2>/dev/null | grep -E '[.:]23[[:space:]].*LISTEN'"
    local on; on=$( { _inetd_on telnet; _listen 23 | awk '{print "LISTEN:23"}'; } | tr '\n' ' ')
    if is_running telnetd || is_running in.telnetd || [ -n "$on" ]; then result "SRV-158|취약|Telnet 서비스 활성 (${on:-telnetd 프로세스})"
    else result "SRV-158|양호|Telnet 서비스 미실행"; fi
}

# ================================================================
# SRV-161: ftpusers 파일의 소유자 및 권한 설정 적절성
# ================================================================
check_SRV161() {
    evd "SRV-161" "ls -la /etc/ftpusers /etc/ftpd/ftpusers /etc/vsftpd/ftpusers /etc/vsftpd/user_list /etc/vsftpd.ftpusers /etc/vsftpd.user_list 2>/dev/null"
    local f found="" bad="" p o
    for f in /etc/ftpusers /etc/ftpd/ftpusers /etc/vsftpd/ftpusers /etc/vsftpd/user_list /etc/vsftpd.ftpusers /etc/vsftpd.user_list; do
        [ -f "$f" ] || continue
        found="${found} ${f}"; p=$(get_perm "$f"); o=$(get_owner "$f")
        { [ "$o" != "root" ] || _perm_over "$p" 640; } && bad="${bad} ${f}(소유자:${o},권한:${p})"
    done
    if [ -z "$found" ]; then
        _ftp_running && result "SRV-161|취약|ftpusers 파일 없음 (FTP 실행 중)" || result "SRV-161|양호|FTP 서비스 미실행"
        return
    fi
    [ -n "$bad" ] && result "SRV-161|취약|ftpusers 소유자/권한 이상:${bad}" || result "SRV-161|양호|${found# } 소유자=root, 권한 640 이하"
}

# ================================================================
# SRV-163: 시스템 사용 주의사항 출력 (Banner)
# ================================================================
check_SRV163() {
    # 평가기준: 로그온 시 경고 메시지 미출력 또는 문구 내 시스템 버전 정보 노출 시 취약
    evd "SRV-163" "grep -iE '^\s*Banner' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null; for f in /etc/issue /etc/issue.net /etc/motd; do echo \"# \$f\"; head -5 \$f 2>/dev/null; done; grep -i herald /etc/security/login.cfg 2>/dev/null"
    local files="" f txt="" ver
    local sb; sb=$(sshd -T 2>/dev/null | awk 'tolower($1)=="banner"{print $2}')
    [ -z "$sb" ] && sb=$(grep -vE '^\s*#' $(_sshd_cfg) /etc/ssh/sshd_config.d/*.conf 2>/dev/null | grep -iE '^\S*:?\s*Banner' | awk '{print $NF}' | tail -1)
    [ -n "$sb" ] && [ "$sb" != "none" ] && [ -f "$sb" ] && files="$sb"
    for f in /etc/issue /etc/issue.net /etc/motd; do [ -s "$f" ] && files="${files} ${f}"; done
    [ "$OS_FAMILY" = "AIX" ] && txt=$(grep -vE '^\s*\*' /etc/security/login.cfg 2>/dev/null | grep -i 'herald' | head -1)
    for f in $files; do txt="${txt}"$'\n'"$(cat "$f" 2>/dev/null)"; done
    if [ -z "$(echo "$txt" | tr -d '[:space:]')" ]; then result "SRV-163|취약|로그온 경고 메시지(배너) 미설정"; return; fi
    ver=$(echo "$txt" | grep -oiE 'SunOS[^ ]*|Solaris [0-9.]+|AIX( Version)? [0-9.]+|HP-UX|HP Release [A-Z]?\.?[0-9.]+|Ubuntu [0-9.]+|CentOS[^[:cntrl:]]*[0-9]|Red Hat[^[:cntrl:]]*[0-9]|Rocky[^[:cntrl:]]*[0-9]|Debian[^[:cntrl:]]*[0-9]|\\r|\\v|Kernel [0-9]' | head -1)
    if [ -n "$ver" ]; then result "SRV-163|취약|배너에 시스템 버전 정보 노출 (${ver}) - $(echo $files)"
    elif echo "$txt" | grep -qiE 'authori[sz]ed|unauthori[sz]ed|warning|경고|허가|불법|monitor'; then result "SRV-163|양호|경고 문구 배너 설정 ($(echo $files))"
    else result "SRV-163|수동확인|배너 존재하나 경고 문구 미확인 ($(echo $files)) - 내용 확인"; fi
}

# ================================================================
# SRV-165: 불필요 Shell 계정 제거
# ================================================================
check_SRV165() {
    # 평가기준: 로그인이 필요하지 않은 계정(daemon·bin·sys·adm·listen·nobody·noaccess·diag·operator·games·gopher 등 시스템 계정)에 shell 부여 시 취약
    evd "SRV-165" "awk -F: '{printf \"%-15s UID=%-5s Shell=%s\\n\",\$1,\$3,\$7}' /etc/passwd"
    local min_uid bad="" user uid sh
    min_uid=$(awk '/^UID_MIN/{print $2}' /etc/login.defs 2>/dev/null)
    [ -z "$min_uid" ] && case "$OS_FAMILY" in AIX) min_uid=200 ;; SOLARIS|HPUX) min_uid=100 ;; *) min_uid=500 ;; esac   # UNIX 일반 사용자 UID 대역
    while IFS=: read -r user _ uid _ _ _ sh; do
        [ "$user" = "root" ] && continue
        if [ "$OS_FAMILY" = "LINUX" ]; then
            { [ "${uid:-0}" -lt "$min_uid" ] 2>/dev/null || echo "$user" | grep -qE '^(daemon|bin|sys|adm|listen|nobody|nobody4|noaccess|diag|operator|games|gopher)$'; } || continue
        else   # UNIX: 가이드 판단방법 계정 목록만 (일반 사용자 UID 체계가 OS 마다 다름)
            echo "$user" | grep -qE '^(daemon|bin|sys|adm|listen|nobody|nobody4|noaccess|diag|operator|games|gopher|uucp|lp|smmsp|nuucp)$' || continue
            [ -z "$sh" ] && sh="/bin/sh"   # Solaris 등 셸 필드 공란 = /bin/sh
        fi
        case "$sh" in */sync|*/shutdown|*/halt|*nologin|*false|"") continue ;; esac
        grep -qx "$sh" /etc/shells 2>/dev/null || case "$sh" in */bash|*/sh|*/ksh|*/csh|*/tcsh|*/zsh|*/dash) ;; *) continue ;; esac
        bad="${bad} ${user}(${sh})"
    done < /etc/passwd
    [ -n "$bad" ] && result "SRV-165|취약|로그인 불필요 시스템 계정에 shell 부여:${bad}" || result "SRV-165|양호|시스템 계정에 대화형 shell 미부여"
}

# ================================================================
# SRV-175: NTP 설정
# ================================================================
check_SRV175() {
    evd "SRV-175" "chronyc tracking 2>/dev/null || ntpq -p 2>/dev/null || timedatectl 2>/dev/null | grep -i synch"
    # chrony
    command -v chronyc >/dev/null 2>&1 && \
        chronyc tracking 2>/dev/null | grep -q "Reference ID" && \
        result "SRV-175|양호|chronyc NTP 동기화 활성" && return
    # ntpq
    command -v ntpq >/dev/null 2>&1 && \
        ntpq -p 2>/dev/null | grep -q "^\*" && \
        result "SRV-175|양호|ntpq 활성 피어 확인" && return
    # timedatectl
    command -v timedatectl >/dev/null 2>&1 && \
        timedatectl 2>/dev/null | grep -q "synchronized: yes" && \
        result "SRV-175|양호|timedatectl NTP 동기화 활성" && return
    # AIX
    [ "$OS_FAMILY" = "AIX" ] && grep -q "server" /etc/ntp.conf 2>/dev/null && \
        result "SRV-175|수동확인|AIX ntp.conf 서버 설정됨 (동기화 상태 확인)" && return
    result "SRV-175|취약|NTP 동기화 설정 미확인"
}

# ================================================================
# SRV-177: sudo 명령어 접근 권한 설정
# ================================================================
check_SRV177() {
    # 평가기준: sudo 접근 제한 — 불필요한 사용자가 sudo 권한을 가지는지 확인
    evd "SRV-177" "ls -l /etc/sudoers; grep -vE '^\s*(#|Defaults|\$)' /etc/sudoers /etc/sudoers.d/* 2>/dev/null"
    command -v sudo >/dev/null 2>&1 || [ -f /etc/sudoers ] || { result "SRV-177|양호|sudo 미설치"; return; }
    local rules all="" who="" np=""
    rules=$(grep -hvE '^\s*(#|Defaults|$)|^\s*(User|Runas|Host|Cmnd)_Alias|^\s*@include|^\s*#include' /etc/sudoers /etc/sudoers.d/* 2>/dev/null | grep -E '=')
    all=$(echo "$rules" | awk '$1=="ALL" || $1=="%users" || $1=="%everyone" || $1=="%staff"{print $1}' | sort -u | tr '\n' ' ')
    who=$(echo "$rules" | awk '$1!="root"{print $1}' | sort -u | tr '\n' ' ')
    np=$(echo "$rules" | grep -c 'NOPASSWD')
    if [ -n "$all" ]; then result "SRV-177|취약|모든(또는 일반 사용자 그룹) 사용자 sudo 허용: ${all}"
    elif [ -n "$who" ]; then result "SRV-177|수동확인|sudo 권한 보유: ${who}(NOPASSWD 규칙 ${np}건) - 불필요 사용자 여부 확인"
    else result "SRV-177|양호|root 외 sudo 권한 없음"; fi
}

# ================================================================
# SRV-179: EoS 시스템 장비 교체 (자동 판정)
# ================================================================
check_SRV179() {
    evd "SRV-179" "uname -srm; cat /etc/os-release 2>/dev/null | head -5; oslevel -s 2>/dev/null; swlist -l product 2>/dev/null | grep -E '^\s*HP-UX' | head -3; pkg info entire 2>/dev/null | grep -iE 'version|branch'; cat /etc/release 2>/dev/null | head -2"
    EOS_SCRIPT="$(dirname "$0")/eos_checker.py"
    [ -f "$EOS_SCRIPT" ] || EOS_SCRIPT="$(dirname "$0")/../converter/eos_checker.py"   # 저장소 구조 그대로 실행 시
    [ ! -f "$EOS_SCRIPT" ] && {
        result "SRV-179|수동확인|eos_checker.py 없음 - 수동 확인 필요"
        return
    }

    product="" version=""
    case "$OS_FAMILY" in
    AIX)
        product="aix"; version="${OS_MAJOR}.$(uname -r)"
        ;;
    SOLARIS)
        product="solaris"
        version=$(uname -r | sed 's/5\.//')
        ;;
    HPUX)
        product="hp-ux"
        version=$(uname -r | sed 's/B\.//')
        ;;
    LINUX)
        case "$OS_DISTRO" in
        RHEL|CENTOS|ROCKY|ORACLE)
            case "$ID" in   # 파생 배포판은 각자의 수명 주기 (CentOS 8 은 2021-12-31 조기 종료, Stream 은 별도)
            centos)    product="centos"; version="$OS_MAJOR"; case "$NAME" in *Stream*) version="${OS_MAJOR}-stream" ;; esac ;;
            rocky)     product="rocky"; version="$OS_MAJOR" ;;
            almalinux) product="almalinux"; version="$OS_MAJOR" ;;
            rhel|"")   product="rhel"; version="$OS_MAJOR" ;;
            *) result "SRV-179|수동확인|${PRETTY_NAME:-$ID $VERSION_ID} (RHEL 계열 파생 배포판) EoS 수동 확인 - 벤더 Lifecycle 대조"; return ;;
            esac ;;
        UBUNTU)
            product="ubuntu"
            version=$(grep -oE '[0-9]+\.[0-9]+' /etc/os-release 2>/dev/null | head -1) ;;
        DEBIAN)
            product="debian"; version="$OS_MAJOR" ;;
        SLES)
            product="sles"; version="$OS_MAJOR" ;;
        AMZN)
            product="amazon-linux"; version="$OS_MAJOR" ;;
        *)
            result "SRV-179|수동확인|OS ${OS_DISTRO} ${OS_MAJOR} EoS 수동 확인"
            return ;;
        esac ;;
    *)
        result "SRV-179|수동확인|OS 종류 미탐지 - 수동 확인"
        return ;;
    esac

    _PY=$(command -v python3 2>/dev/null || { [ -x /usr/libexec/platform-python ] && echo /usr/libexec/platform-python; } || command -v python 2>/dev/null)
    if [ -z "$_PY" ]; then result "SRV-179|수동확인|python 미설치 - ${product} ${version} EoS 여부 수동 확인"; return; fi
    _eo=$("$_PY" "$EOS_SCRIPT" "$product" "$version" 2>/dev/null)   # 인터넷 연결 시 endoflife.date 조회, 아니면 내장 데이터
    eos_result=$(echo "$_eo" | grep "^결과:" | awk '{print $2}')
    eos_desc=$(echo "$_eo" | grep "^설명:" | cut -d: -f2- | sed "s/^ *//;s/ *$//")
    [ -z "$eos_result" ] && { result "SRV-179|수동확인|EoS 판정 실패 - 수동 확인"; return; }
    result "SRV-179|${eos_result}|${eos_desc}"
}

# ================================================================
# SRV-087: C 컴파일러 권한
# ================================================================
check_SRV087() {
    local _cc_list; _cc_list=$(for c in /usr/bin/gcc /usr/bin/cc /usr/bin/g++ /usr/local/bin/gcc /usr/vac/bin/xlc /usr/vac/bin/cc /opt/aCC/bin/aCC /opt/ansic/bin/cc /opt/SUNWspro/bin/cc /opt/developerstudio*/bin/cc /usr/sfw/bin/gcc $(command -v cc gcc 2>/dev/null); do echo "$c"; done | sort -u)   # /usr/ucb/cc 는 Studio 미설치 시 동작하지 않는 래퍼라 제외
    evd "SRV-087" "ls -laL $(echo $_cc_list) 2>/dev/null"
    _cc_vuln=""
    for cc in $_cc_list; do
        [ -x "$cc" ] || continue
        perm=$(get_perm "$cc")
        if echo "$perm" | grep -qE "[1357]$"; then
            _cc_vuln="${_cc_vuln} ${cc}(${perm})"
        fi
    done
    if [ -z "$_cc_vuln" ]; then
        _cc_found=0
        for cc in $_cc_list; do
            [ -x "$cc" ] && _cc_found=1 && break
        done
        [ $_cc_found -eq 0 ] && result "SRV-087|양호|C 컴파일러 미설치" || \
            result "SRV-087|양호|C 컴파일러 other 실행 권한 없음"
    else
        result "SRV-087|취약|C 컴파일러 other 실행 허용:${_cc_vuln}"
    fi
}

# ================================================================
# SMTP 공통 탐지 (SRV-005~010 공용)
# ================================================================
_smtp_type=""  # sendmail / postfix / exim / ""
_smtp_cf=""
_smtp_pids() { ps -ef 2>/dev/null | grep -v grep | grep -v defunct | grep -E "$1" | awk '{print $2}'; }
_in_container_only() {   # 모든 PID 가 '점검 스크립트와 다른' 컨테이너 cgroup 이면 참 (/proc 없는 UNIX 는 거짓 = 호스트 서비스)
    local p any=0 self; self=$(cat /proc/self/cgroup 2>/dev/null)
    for p in "$@"; do any=1; [ -r "/proc/$p/cgroup" ] || return 1
        grep -qE 'docker|containerd|kubepods|libpod' "/proc/$p/cgroup" 2>/dev/null || return 1
        [ "$(cat "/proc/$p/cgroup" 2>/dev/null)" = "$self" ] && return 1   # 스크립트와 같은 컨테이너 안의 MTA 는 대상 서비스
    done
    [ $any = 1 ]
}
_smtp_host() { local pids; pids=$(_smtp_pids "$1"); [ -n "$pids" ] || return 1; if _in_container_only $pids; then evd "SMTP" "echo '컨테이너 내부 MTA(${1}) - 호스트 판정 제외: '$(echo $pids)"; return 1; fi; return 0; }
_detect_smtp() {
    [ -n "$_smtp_type" ] && return
    if _smtp_host 'sendmail'; then
        _smtp_type="sendmail"
        for c in /etc/mail/sendmail.cf /etc/sendmail.cf /usr/lib/sendmail.cf; do
            [ -f "$c" ] && _smtp_cf="$c" && break
        done
    elif _smtp_host 'postfix|/master'; then
        _smtp_type="postfix"
        for c in /etc/postfix/main.cf /usr/local/etc/postfix/main.cf; do
            [ -f "$c" ] && _smtp_cf="$c" && break
        done
    elif _smtp_host 'exim'; then
        _smtp_type="exim"
        for c in /etc/exim4/exim4.conf /etc/exim/exim.conf; do
            [ -f "$c" ] && _smtp_cf="$c" && break
        done
    fi
}
_ver_lt() { [ "$1" != "$2" ] && [ "$(printf '%s\n%s\n' "$1" "$2" | sort -t. -k1,1n -k2,2n -k3,3n | head -1)" = "$1" ]; }
_smtp_running() {
    _detect_smtp
    [ -n "$_smtp_type" ] && return 0
    ss -tlnp 2>/dev/null | grep -q "[.:]25 " && return 0
    netstat -tlnp 2>/dev/null | grep -q ":25 " && return 0
    return 1
}

# ================================================================
# SRV-005: SMTP EXPN/VRFY 제한
# ================================================================
check_SRV005() {
    _smtp_running || { evd "SRV-005" "ps -ef 2>/dev/null | grep -E 'smtp|postfix|sendmail' | grep -v grep"; result "SRV-005|N-A|SMTP 서비스 미실행"; return; }
    _detect_smtp
    evd "SRV-005" "postconf disable_vrfy_command 2>/dev/null; grep -i PrivacyOptions $_smtp_cf 2>/dev/null"
    case "$_smtp_type" in
    postfix)
        local val=$(postconf -h disable_vrfy_command 2>/dev/null)
        [ "$val" = "yes" ] && result "SRV-005|양호|postfix disable_vrfy_command=yes" || \
            result "SRV-005|취약|postfix disable_vrfy_command=${val:-no}" ;;
    sendmail)
        # 평가기준: noexpn 과 novrfy 또는 goaway
        local po; po=$(grep -iE '^\s*O\s+PrivacyOptions' "$_smtp_cf" 2>/dev/null | tail -1)
        if echo "$po" | grep -qi "goaway" || { echo "$po" | grep -qi "noexpn" && echo "$po" | grep -qi "novrfy"; }; then
            result "SRV-005|양호|sendmail PrivacyOptions EXPN·VRFY 제한 (${po##*=})"
        else result "SRV-005|취약|sendmail PrivacyOptions noexpn·novrfy(또는 goaway) 미설정 (${po##*=})"; fi ;;
    *) result "SRV-005|수동확인|${_smtp_type:-SMTP} EXPN/VRFY 설정 수동 확인" ;;
    esac
}

# ================================================================
# SRV-006: SMTP 로그 수준
# ================================================================
check_SRV006() {
    _smtp_running || { evd "SRV-006" "ps -ef 2>/dev/null | grep -E 'smtp|postfix|sendmail' | grep -v grep"; result "SRV-006|N-A|SMTP 서비스 미실행"; return; }
    _detect_smtp
    evd "SRV-006" "postconf debug_peer_level syslog_facility 2>/dev/null; grep -i LogLevel $_smtp_cf 2>/dev/null"
    case "$_smtp_type" in
    postfix)
        # 평가기준: debug_peer_level 2 이상 (기본 2)
        local dl=$(postconf -h debug_peer_level 2>/dev/null)
        [ "${dl:-2}" -ge 2 ] 2>/dev/null && result "SRV-006|양호|postfix debug_peer_level=${dl:-2(기본)}" || result "SRV-006|취약|postfix debug_peer_level=${dl} (2 이상 필요)" ;;
    sendmail)
        # 평가기준: LogLevel 9 이상 (미설정 시 기본 9)
        local lv=$(grep -iE "^\s*O\s+LogLevel" "$_smtp_cf" 2>/dev/null | grep -oE '[0-9]+' | tail -1)
        [ "${lv:-9}" -ge 9 ] 2>/dev/null && result "SRV-006|양호|sendmail LogLevel=${lv:-9(기본)}" || result "SRV-006|취약|sendmail LogLevel=${lv} (9 이상 필요)" ;;
    *) result "SRV-006|수동확인|${_smtp_type:-SMTP} 로그 수준 수동 확인" ;;
    esac
}

# ================================================================
# SRV-007: SMTP 보안패치
# ================================================================
check_SRV007() {
    _smtp_running || { result "SRV-007|N-A|SMTP 서비스 미실행"; return; }
    _detect_smtp
    local ver=""
    case "$_smtp_type" in
    postfix) ver=$(postconf -h mail_version 2>/dev/null); evd "SRV-007" "postconf mail_version 2>/dev/null" ;;
    sendmail) ver=$(sendmail -d0.1 </dev/null 2>&1 | head -1 | grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)?' | head -1)
              [ -z "$ver" ] && ver=$(sed -n 's/^DZ\([0-9][0-9.]*\).*/\1/p' "$_smtp_cf" 2>/dev/null | head -1)
              evd "SRV-007" "sendmail -d0.1 </dev/null 2>&1 | head -1; grep '^DZ' $_smtp_cf 2>/dev/null" ;;
    exim) ver=$( { exim -bV 2>/dev/null || exim4 -bV 2>/dev/null; } | grep -oE 'version [0-9]+\.[0-9]+(\.[0-9]+)?' | head -1 | awk '{print $2}'); evd "SRV-007" "exim -bV 2>/dev/null | head -1; exim4 -bV 2>/dev/null | head -1" ;;
    esac
    # 평가기준 판단방법 최소 버전: Sendmail 8.14.9 / Postfix 2.5.13·2.6.10·2.7.4·2.8.3 / Exim 4.94.2 — 미만이면 알려진 취약점 미패치
    local min=""
    case "$_smtp_type" in
    sendmail) min="8.14.9" ;;
    exim) min="4.94.2" ;;
    postfix) case "$ver" in 2.5.*) min="2.5.13" ;; 2.6.*) min="2.6.10" ;; 2.7.*) min="2.7.4" ;; 2.8.*) min="2.8.3" ;; [01].*|2.[0-4].*) min="2.5.13" ;; esac ;;
    esac
    if [ -n "$ver" ] && [ -n "$min" ] && _ver_lt "$ver" "$min"; then result "SRV-007|취약|${_smtp_type} ${ver} - 평가기준 최소 버전 ${min} 미만 (보안 패치 미적용)"
    else result "SRV-007|수동확인|${_smtp_type} 버전=${ver:-미확인}${min:+ (평가기준 최소 ${min} 이상)} - 최신 버전·내부 패치 절차 확인"; fi
}

# ================================================================
# SRV-008: SMTP DoS 방지
# ================================================================
check_SRV008() {
    _smtp_running || { evd "SRV-008" "ps -ef 2>/dev/null | grep -E 'smtp|postfix|sendmail' | grep -v grep"; result "SRV-008|N-A|SMTP 서비스 미실행"; return; }
    _detect_smtp
    evd "SRV-008" "postconf message_size_limit header_size_limit default_process_limit local_destination_concurrency_limit smtpd_recipient_limit 2>/dev/null; grep -iE 'MaxDaemonChildren|ConnectionRateThrottle|MinFreeBlocks|MaxHeadersLength|MaxMessageSize' $_smtp_cf 2>/dev/null"
    case "$_smtp_type" in
    postfix)
        # 평가기준: 5개 파라미터는 기본값이 있어 미설정도 양호, 0(해제) 이면 취약
        local p z=""
        for p in message_size_limit header_size_limit default_process_limit local_destination_concurrency_limit smtpd_recipient_limit; do
            [ "$(postconf -h $p 2>/dev/null)" = "0" ] && z="${z} ${p}=0"
        done
        [ -n "$z" ] && result "SRV-008|취약|postfix 제한 해제(0):${z}" || result "SRV-008|양호|postfix DoS 제한 파라미터 기본값/설정값 유지 (0 해제 없음)" ;;
    sendmail)
        local p miss=""
        for p in MaxDaemonChildren ConnectionRateThrottle MinFreeBlocks MaxHeadersLength MaxMessageSize; do
            grep -qiE "^\s*O\s+${p}\s*=" "$_smtp_cf" 2>/dev/null || miss="${miss} ${p}"
        done
        [ -n "$miss" ] && result "SRV-008|취약|sendmail DoS 방지 파라미터 미설정:${miss}" || result "SRV-008|양호|sendmail DoS 방지 파라미터 5종 설정" ;;
    *) result "SRV-008|수동확인|${_smtp_type:-SMTP} DoS 방지 설정 수동 확인" ;;
    esac
}

# ================================================================
# SRV-009: SMTP 릴레이 제한
# ================================================================
check_SRV009() {
    _smtp_running || { evd "SRV-009" "ps -ef 2>/dev/null | grep -E 'smtp|postfix|sendmail' | grep -v grep"; result "SRV-009|N-A|SMTP 서비스 미실행"; return; }
    _detect_smtp
    evd "SRV-009" "postconf smtpd_relay_restrictions smtpd_recipient_restrictions mynetworks 2>/dev/null; grep -iE 'promiscuous_relay|relay_entire_domain|relay_local_from' $_smtp_cf /etc/mail/sendmail.mc 2>/dev/null; sendmail -d0.1 -bv root 2>/dev/null | head -1"
    case "$_smtp_type" in
    postfix)
        local mn=$(postconf -h mynetworks 2>/dev/null) rr=$(postconf -h smtpd_relay_restrictions 2>/dev/null)
        if echo "$mn $rr" | grep -qE '0\.0\.0\.0/0|static:all|\bpermit\s*(,|$)'; then result "SRV-009|취약|postfix 릴레이 전체 허용 (mynetworks=${mn})"
        else result "SRV-009|양호|postfix 릴레이 제한 (relay_restrictions=${rr:-기본 reject_unauth_destination})"; fi ;;
    sendmail)
        # 평가기준: 8.9 이상은 promiscuous_relay 비활성(기본)이면 양호, 8.9 미만은 access 파일 접근통제
        local ver; ver=$(sendmail -d0.1 -bv root 2>/dev/null | grep -oE 'Version [0-9]+\.[0-9]+' | awk '{print $2}' | head -1)
        [ -z "$ver" ] && ver=$(sed -n 's/^DZ\([0-9]*\.[0-9]*\).*/\1/p' "$_smtp_cf" 2>/dev/null | head -1)   # sendmail.cf 버전 매크로
        if grep -qiE 'promiscuous_relay|relay_entire_domain' "$_smtp_cf" /etc/mail/sendmail.mc 2>/dev/null; then result "SRV-009|취약|sendmail promiscuous_relay/relay_entire_domain 설정"
        elif [ -n "$ver" ] && { [ "${ver%%.*}" -gt 8 ] || { [ "${ver%%.*}" -eq 8 ] && [ "${ver#*.}" -ge 9 ]; }; } 2>/dev/null; then result "SRV-009|양호|sendmail ${ver} (8.9 이상 기본 릴레이 차단)"
        elif [ -f /etc/mail/access ]; then result "SRV-009|수동확인|sendmail ${ver:-버전 미확인} - /etc/mail/access 릴레이 접근통제 확인"
        else result "SRV-009|취약|sendmail ${ver:-버전 미확인} (8.9 미만 추정) - access 접근통제 파일 없음"; fi ;;
    *) result "SRV-009|수동확인|${_smtp_type:-SMTP} 릴레이 제한 수동 확인" ;;
    esac
}

# ================================================================
# SRV-010: SMTP 일반사용자 실행 방지
# ================================================================
check_SRV010() {
    _smtp_running || { evd "SRV-010" "ps -ef 2>/dev/null | grep -E 'smtp|postfix|sendmail' | grep -v grep"; result "SRV-010|N-A|SMTP 서비스 미실행"; return; }
    _detect_smtp
    evd "SRV-010" "ls -lL \$(postconf -h command_directory 2>/dev/null)/postsuper /usr/sbin/postsuper /usr/sbin/exim /usr/sbin/exim4 2>/dev/null; grep -i PrivacyOptions $_smtp_cf 2>/dev/null"
    case "$_smtp_type" in
    postfix)
        # 평가기준: postsuper 실행 파일 others 실행 권한 → 일반 사용자 queue 처리 가능
        local ps="$(postconf -h command_directory 2>/dev/null)/postsuper"; [ -f "$ps" ] || ps=/usr/sbin/postsuper
        if [ ! -f "$ps" ]; then result "SRV-010|수동확인|postsuper 실행 파일 확인 불가"
        else local p=$(get_perm "$ps"); [ $(( ${p: -1} & 1 )) -ne 0 ] && result "SRV-010|취약|${ps} others 실행 권한 (${p})" || result "SRV-010|양호|${ps} others 실행 권한 없음 (${p})"; fi ;;
    sendmail)
        grep -iE '^\s*O\s+PrivacyOptions' "$_smtp_cf" 2>/dev/null | grep -qi "restrictqrun" && \
            result "SRV-010|양호|sendmail PrivacyOptions restrictqrun 설정" || \
            result "SRV-010|취약|sendmail restrictqrun 미설정" ;;
    exim)
        local ex=$(command -v exim exim4 2>/dev/null | head -1); local p=$(get_perm "$ex")
        [ -n "$ex" ] && [ $(( ${p: -1} & 1 )) -ne 0 ] && result "SRV-010|취약|${ex} others 실행 권한 (${p})" || result "SRV-010|양호|exim others 실행 권한 없음 (${p:-미확인})" ;;
    *) result "SRV-010|수동확인|${_smtp_type:-SMTP} 일반사용자 실행 방지 수동 확인" ;;
    esac
}

# ================================================================
# SRV-012: .netrc 파일 점검
# ================================================================
check_SRV012() {
    # 평가기준: .netrc 내부에 아이디·패스워드 등 민감 정보 (전 계정 홈)
    local homes f found="" sens=""
    homes=$(awk -F: '$6!=""{print $6}' /etc/passwd 2>/dev/null | sort -u)
    for f in $(for h in $homes /root; do echo "${h%/}/.netrc"; done | sort -u); do
        [ -f "$f" ] || continue
        found="${found} ${f}"
        grep -qiE '\b(login|password)\b' "$f" 2>/dev/null && sens="${sens} ${f}"
    done
    evd "SRV-012" "echo '${found:- (없음)}'"
    if [ -n "$sens" ]; then result "SRV-012|취약|.netrc 에 계정·비밀번호 정보:${sens}"
    elif [ -n "$found" ]; then result "SRV-012|수동확인|.netrc 파일 존재(login/password 미발견):${found} - 내용 확인"
    else result "SRV-012|양호|.netrc 파일 미존재"; fi
}

# ================================================================
# SRV-021: FTP 접근통제
# ================================================================
check_SRV021() {
    _ftp_running || { evd "SRV-021" "ps -ef 2>/dev/null | grep -E 'vsftpd|proftpd|ftpd' | grep -v grep"; result "SRV-021|N-A|FTP 서비스 미실행"; return; }
    evd "SRV-021" "grep -iE 'tcp_wrappers|listen_address' /etc/vsftpd.conf /etc/vsftpd/vsftpd.conf 2>/dev/null; grep -iE 'vsftpd|ftp|ALL' /etc/hosts.allow /etc/hosts.deny 2>/dev/null; grep -iA3 '<Limit LOGIN>' /etc/proftpd/proftpd.conf /etc/proftpd.conf 2>/dev/null"
    # 평가기준: 특정 IP/호스트에서만 접속하도록 접근제어
    local conf tw hw
    conf=$(ls /etc/vsftpd.conf /etc/vsftpd/vsftpd.conf 2>/dev/null | head -1)
    if [ -n "$conf" ]; then
        tw=$(grep -iE "^\s*tcp_wrappers" "$conf" 2>/dev/null | tail -1 | cut -d= -f2 | tr -d ' ')
        hw=$(grep -vE '^\s*#' /etc/hosts.allow /etc/hosts.deny 2>/dev/null | grep -iE 'vsftpd|^\s*ALL\s*:' | head -2)
        [ "${tw^^}" = "YES" ] && [ -n "$hw" ] && { result "SRV-021|양호|vsftpd tcp_wrappers=YES + hosts.allow/deny 규칙"; return; }
    fi
    grep -vE '^\s*#' /etc/proftpd/proftpd.conf /etc/proftpd.conf 2>/dev/null | grep -iA3 "<Limit LOGIN>" | grep -qiE "Allow from|Deny from" && { result "SRV-021|양호|proftpd <Limit LOGIN> 접근 IP 제한"; return; }
    # 평가기준 판단방법(UNIX): AIX /etc/ftpaccess.ctl, HP-UX /etc/ftpd/ftphosts·ftpaccess, SOL /etc/ftpd/ftpaccess
    evd "SRV-021" "grep -vE '^\s*(#|\$)' /etc/ftpaccess.ctl /etc/ftpd/ftphosts 2>/dev/null; grep -iE '^\s*(allow|deny|class)' /etc/ftpd/ftpaccess 2>/dev/null"
    grep -qiE '^\s*(allow|deny)\s*:' /etc/ftpaccess.ctl 2>/dev/null && { result "SRV-021|양호|AIX /etc/ftpaccess.ctl allow/deny 설정"; return; }
    grep -qiE '^\s*(allow|deny)\s' /etc/ftpd/ftphosts 2>/dev/null && { result "SRV-021|양호|/etc/ftpd/ftphosts allow/deny 설정"; return; }
    result "SRV-021|수동확인|FTP 접근 IP 제한(tcp_wrappers 규칙·방화벽) 수동 확인 (vsftpd tcp_wrappers=${tw:-미설정})"
}

# ================================================================
# SRV-037: TFTP 서비스
# ================================================================
check_SRV037() {
    # 평가기준: FTP 서비스 활성 시 취약 (FTPS 등 통신 암호화 적용 시 양호)
    evd "SRV-037" "ps -ef 2>/dev/null | grep -E 'vsftpd|proftpd|pure-ftpd|ftpd' | grep -v grep; ss -tln 2>/dev/null | grep ':21 '; grep -iE '^\s*(ssl_enable|force_local_logins_ssl|force_local_data_ssl)' /etc/vsftpd.conf /etc/vsftpd/vsftpd.conf 2>/dev/null; grep -iE '^\s*TLS(Engine|Required)' /etc/proftpd/proftpd.conf /etc/proftpd/tls.conf 2>/dev/null"
    _ftp_running || { result "SRV-037|양호|FTP 서비스 비활성"; return; }
    local conf
    conf=$(ls /etc/vsftpd.conf /etc/vsftpd/vsftpd.conf 2>/dev/null | head -1)
    if [ -n "$conf" ] && is_running vsftpd; then
        if grep -qiE '^\s*ssl_enable\s*=\s*YES' "$conf" && ! grep -qiE '^\s*force_local_logins_ssl\s*=\s*NO' "$conf"; then result "SRV-037|양호|vsftpd FTPS(ssl_enable=YES) 적용"
        else result "SRV-037|취약|vsftpd 평문 FTP 서비스 활성 (ssl_enable 미설정 또는 SSL 로그인 강제 해제)"; fi
    elif is_running proftpd; then
        if grep -hiE '^\s*TLSEngine\s+on' /etc/proftpd/proftpd.conf /etc/proftpd/tls.conf 2>/dev/null | grep -q . && grep -hiE '^\s*TLSRequired\s+on' /etc/proftpd/proftpd.conf /etc/proftpd/tls.conf 2>/dev/null | grep -q .; then
            result "SRV-037|양호|proftpd TLSEngine on + TLSRequired on"
        else result "SRV-037|취약|proftpd 평문 FTP 허용 (TLSRequired 미설정)"; fi
    else result "SRV-037|취약|FTP 서비스 활성 (FTPS 적용 확인 불가 - 적용 시 수동 판정 변경)"; fi
}

# ================================================================
# SRV-082: 시스템 주요 디렉터리 권한
# ================================================================
check_SRV082() {
    # 평가기준: /usr /bin /sbin /etc /var 에 others 쓰기 권한이 있으면 취약
    evd "SRV-082" "ls -alLd /usr /bin /sbin /etc /var 2>/dev/null"
    local vuln="" d p
    for d in /usr /bin /sbin /etc /var; do
        [ -e "$d" ] || continue
        p=$(get_perm "$(readlink -f "$d" 2>/dev/null || echo "$d")"); p=${p: -1}
        [ $(( ${p:-0} & 2 )) -ne 0 ] 2>/dev/null && vuln="${vuln} ${d}(others 쓰기)"
    done
    [ -n "$vuln" ] && result "SRV-082|취약|시스템 주요 디렉터리 others 쓰기 권한:${vuln}" || \
        result "SRV-082|양호|시스템 주요 디렉터리(/usr /bin /sbin /etc /var) others 쓰기 권한 없음"
}

# ================================================================
# SRV-083: 시작 스크립트 권한
# ================================================================
check_SRV083() {
    # 평가기준: 시스템 스타트업 스크립트에 others 쓰기 권한 존재 시 취약 (소유자는 참고)
    evd "SRV-083" "ls -ld /etc/init.d /etc/rc.d /etc/rc.local 2>/dev/null; ls -la /etc/init.d/ /etc/systemd/system/*.service 2>/dev/null | head -20"
    local vuln="" f p
    while IFS= read -r f; do
        [ -f "$f" ] || continue
        p=$(get_perm "$f"); [ $(( ${p: -1} & 2 )) -ne 0 ] && vuln="${vuln} ${f}(${p}, 소유자=$(get_owner "$f"))"
    done < <( { for d in /etc/init.d /etc/rc.d/init.d /etc/rc.d/rc2.d /etc/rc.d/rc3.d /etc/rc2.d /etc/rc3.d /sbin/init.d /sbin/rc2.d /sbin/rc3.d; do [ -d "$d" ] && ls -1 "$d" 2>/dev/null | sed "s#^#$d/#"; done; ls /etc/rc.local /etc/systemd/system/*.service 2>/dev/null; } | sort -u | head -300)
    [ -n "$vuln" ] && result "SRV-083|취약|others 쓰기 가능 스타트업 스크립트:${vuln}" || result "SRV-083|양호|스타트업 스크립트 others 쓰기 권한 없음"
}

# ================================================================
# SRV-094: Crontab 참조 파일 권한
# ================================================================
check_SRV094() {
    # 평가기준: crontab 에서 실행하는 참조 파일에 others 쓰기 권한이 있으면 취약
    evd "SRV-094" "cat /etc/crontab /etc/cron.d/* /var/spool/cron/* /var/spool/cron/crontabs/* 2>/dev/null | grep -vE '^\s*(#|$)' | head -30"
    local vuln="" refs f p
    refs=$( { cat /etc/crontab /etc/cron.d/* 2>/dev/null | grep -vE '^\s*(#|$|[A-Z_]+=)' | awk '{for(i=7;i<=NF;i++) print $i}'
              cat /var/spool/cron/* /var/spool/cron/crontabs/* 2>/dev/null | grep -vE '^\s*(#|$|[A-Z_]+=)' | awk '{for(i=6;i<=NF;i++) print $i}'
              ls /etc/cron.hourly/* /etc/cron.daily/* /etc/cron.weekly/* /etc/cron.monthly/* 2>/dev/null
            } | grep -E '^/' | sort -u)
    for f in $refs; do
        [ -f "$f" ] || continue
        p=$(get_perm "$f"); p=${p: -1}
        [ $(( ${p:-0} & 2 )) -ne 0 ] 2>/dev/null && vuln="${vuln} ${f}"
    done
    local n; n=$(echo "$refs" | grep -c .)
    [ -n "$vuln" ] && result "SRV-094|취약|crontab 참조파일 others 쓰기 권한:${vuln}" || \
        result "SRV-094|양호|crontab 참조파일 ${n}개 others 쓰기 권한 없음"
}

# ================================================================
# SRV-095: 소유자/그룹 없는 파일
# ================================================================
check_SRV095() {
    evd "SRV-095" "_to 60 find / \$_FP \\( -nouser -o -nogroup \\) ! -path '/proc/*' ! -path '/sys/*' -print 2>/dev/null | head -10"
    local found="" _rc
    found=$(set -o pipefail; _to 60 find / $_FP \( -nouser -o -nogroup \) ! -path "/proc/*" ! -path "/sys/*" ! -path "/dev/*" ! -path "/run/*" ! -path "/var/lib/docker/*" ! -path "/var/lib/containers/*" -print 2>/dev/null | head -10); _rc=$?
    [ "$_rc" = "141" ] && _rc=0   # head 조기 종료(SIGPIPE)는 정상
    if [ -n "$found" ]; then
        result "SRV-095|취약|소유자/그룹 없는 파일 존재: $(echo "$found" | tr '\n' ',' | head -c 150)"
    elif [ "$_rc" = "124" ]; then
        result "SRV-095|수동확인|파일 검색 시간 초과(60초) - 소유자 없는 파일 수동 확인"
    else
        result "SRV-095|양호|소유자/그룹 없는 파일 없음"
    fi
}

# ================================================================
# SRV-096: 사용자 환경변수 파일 권한
# ================================================================
check_SRV096() {
    # 평가기준: 사용자 환경 파일에 others 권한(읽기/쓰기/실행)이 하나라도 있으면 취약
    evd "SRV-096" "for h in \$(awk -F: '\$7!~/(nologin|false)\$/{print \$6}' /etc/passwd | sort -u); do ls -l \$h/.profile \$h/.bashrc \$h/.bash_profile \$h/.kshrc \$h/.cshrc \$h/.login \$h/.*shrc 2>/dev/null; done | sort -u | head -40"
    local vuln="" user uid homedir sh df p o
    while IFS=: read -r user _ uid _ _ homedir sh; do
        case "$sh" in *nologin|*false) continue ;; esac
        [ -z "$homedir" ] || [ "$homedir" = "/" ] || [ ! -d "$homedir" ] && continue
        for df in "$homedir"/.profile "$homedir"/.login "$homedir"/.bash_profile "$homedir"/.bash_login "$homedir"/.*shrc; do
            [ -f "$df" ] || continue
            p=$(get_perm "$df"); o=$(get_owner "$df")
            [ "${p: -1}" != "0" ] && vuln="${vuln} ${df}(${p})"
            [ "$o" != "$user" ] && [ "$o" != "root" ] && vuln="${vuln} ${df}(소유자=${o})"
        done
    done < /etc/passwd
    [ -n "$vuln" ] && result "SRV-096|취약|사용자 환경파일 others 권한/소유자 이상:${vuln}" || \
        result "SRV-096|양호|사용자 환경파일 others 권한 없음"
}

# ================================================================
# SRV-112: Cron 로깅 설정
# ================================================================
check_SRV112() {
    evd "SRV-112" "grep -i cron /etc/rsyslog.conf /etc/rsyslog.d/*.conf /etc/syslog.conf 2>/dev/null | grep -v '^#'; grep CRONLOG /etc/default/cron 2>/dev/null"
    local found=0
    grep -rqiE "^\s*cron" /etc/rsyslog.conf /etc/rsyslog.d/*.conf /etc/syslog.conf 2>/dev/null && found=1
    [ "$OS_FAMILY" = "AIX" ] && grep -vE '^\s*(#|\*)' /etc/syslog.conf 2>/dev/null | grep -qi "cron" && found=1
    [ "$OS_FAMILY" = "SOLARIS" ] && grep -q '^CRONLOG=YES' /etc/default/cron 2>/dev/null && found=1
    [ $found -eq 1 ] && result "SRV-112|양호|cron 로그 기록 설정 (syslog 또는 CRONLOG=YES)" || \
        result "SRV-112|취약|cron 로그 기록 미설정"
}

# ================================================================
# SRV-115: 로그 검토/보고
# ================================================================
check_SRV115() {
    evd "SRV-115" "ls -la /var/log/messages /var/log/secure /var/log/auth.log /var/log/syslog 2>/dev/null | head -5"
    evd "SRV-115" "last -5 2>/dev/null"
    result "SRV-115|수동확인|로그 검토 수행 여부 수동 확인"
}

# ================================================================
# SRV-134: 스택 실행 방지
# ================================================================
check_SRV134() {
    case "$OS_FAMILY" in
    SOLARIS)
        evd "SRV-134" "grep noexec_user_stack /etc/system 2>/dev/null; sxadm status nxstack 2>/dev/null"
        if [ "${OS_MAJOR:-10}" -ge 11 ] 2>/dev/null && sxadm status nxstack 2>/dev/null | grep -qi "enabled"; then result "SRV-134|양호|Solaris 11 sxadm nxstack enabled"
        elif grep -qE '^\s*set\s+noexec_user_stack\s*=\s*1' /etc/system 2>/dev/null; then result "SRV-134|양호|/etc/system noexec_user_stack=1"
        else result "SRV-134|취약|스택 실행 방지 미설정 (noexec_user_stack / sxadm nxstack)"; fi ;;
    *)
        evd "SRV-134" "grep -o -m1 -w nx /proc/cpuinfo 2>/dev/null"
        if grep -q "nx" /proc/cpuinfo 2>/dev/null; then result "SRV-134|양호|CPU NX 비트 지원 (스택 실행 방지 활성)"
        else result "SRV-134|N-A|Linux 커널 기본 NX 보호 (확인 불필요)"; fi ;;
    esac
}

# ================================================================
# SRV-135: TCP 보안 설정
# ================================================================
check_SRV135() {
    case "$OS_FAMILY" in
    SOLARIS)
        # 평가기준(Solaris): TCP_STRONG_ISS=2 양호, 0/1 취약
        evd "SRV-135" "grep TCP_STRONG_ISS /etc/default/inetinit 2>/dev/null; ipadm show-prop -p _strong_iss tcp 2>/dev/null"
        local v; v=$(grep -E '^\s*TCP_STRONG_ISS' /etc/default/inetinit 2>/dev/null | cut -d= -f2 | tr -d ' ')
        [ -z "$v" ] && v=$(ipadm show-prop -p _strong_iss -co current tcp 2>/dev/null)
        case "$v" in 2) result "SRV-135|양호|TCP_STRONG_ISS=2" ;; 0|1) result "SRV-135|취약|TCP_STRONG_ISS=${v} (2 필요)" ;; *) result "SRV-135|수동확인|TCP_STRONG_ISS 확인 불가" ;; esac ;;
    *)
        evd "SRV-135" "sysctl net.ipv4.tcp_syncookies net.ipv4.conf.all.accept_redirects net.ipv4.conf.all.accept_source_route 2>/dev/null"
        result "SRV-135|N-A|평가대상 아님 (Solaris 전용 TCP_STRONG_ISS)" ;;
    esac
}

# ================================================================
# SRV-147: 네트워크 모니터링 서비스
# ================================================================
check_SRV147() {
    # 평가기준: 불필요한 네트워크 모니터링 서비스(SNMP 등)가 '실행 중'이면 취약 (판단방법: ps -ef | grep snmp)
    evd "SRV-147" "ps -ef 2>/dev/null | grep -E '[s]nmpd|[t]cpdump|[t]shark|[w]ireshark|[n]map' ; which tcpdump tshark wireshark nmap 2>/dev/null"
    local run_mon run_snmp inst=""
    run_snmp=$(_snmp_run && echo snmpd)
    run_mon=$(_comm | grep -xE 'tcpdump|tshark|wireshark|nmap|dumpcap' | sort -u | tr '\n' ' ')
    for t in tcpdump tshark wireshark nmap; do command -v $t >/dev/null 2>&1 && inst="${inst} ${t}"; done
    if [ -n "$run_mon" ]; then result "SRV-147|취약|네트워크 모니터링 도구 실행 중: ${run_mon}"
    elif [ -n "$run_snmp" ]; then result "SRV-147|수동확인|SNMP 서비스(snmpd) 실행 중 - 업무상 필요 여부 확인${inst:+ (설치된 도구:${inst})}"
    else result "SRV-147|양호|네트워크 모니터링 서비스 미실행${inst:+ (설치만 된 도구:${inst})}"; fi
}

# ================================================================
# SRV-164: GID 없는 계정
# ================================================================
check_SRV164() {
    # 평가기준: 구성원이 존재하지 않는 GID(보조 구성원도 없고 어떤 계정의 기본 그룹도 아닌 그룹) 존재 시 취약
    evd "SRV-164" "awk -F: '\$4==\"\"{print \$1\":\"\$3}' /etc/group 2>/dev/null | head -40; awk -F: '{print \$4}' /etc/passwd | sort -u | tr '\n' ' '"
    local umin; umin=$(awk '/^\s*GID_MIN/{print $2}' /etc/login.defs 2>/dev/null)
    [ -z "$umin" ] && case "$OS_FAMILY" in AIX) umin=200 ;; SOLARIS|HPUX) umin=100 ;; *) umin=1000 ;; esac   # UNIX 신규 그룹 GID 대역
    local pg; pg=" $(awk -F: '{print $4}' /etc/passwd 2>/dev/null | sort -u | tr '\n' ' ') "
    local empty_user="" empty_sys=0 g gid mem
    while IFS=: read -r g _ gid mem; do
        [ -z "$mem" ] || continue
        case "$pg" in *" $gid "*) continue ;; esac
        if [ "$gid" -ge "$umin" ] 2>/dev/null && [ "$gid" -lt 60000 ] 2>/dev/null; then empty_user="${empty_user} ${g}(${gid})"
        else empty_sys=$((empty_sys+1)); fi
    done < /etc/group
    if [ -n "$empty_user" ]; then result "SRV-164|취약|구성원 없는 그룹(GID ${umin} 이상):${empty_user} - 불필요 시 제거"
    else result "SRV-164|양호|신규 생성 GID(${umin} 이상) 중 구성원 없는 그룹 없음 (시스템 기본 그룹 ${empty_sys}개는 참고)"; fi
}

# ================================================================
# SRV-166: 숨김 파일/디렉터리
# ================================================================
check_SRV166() {
    evd "SRV-166" "find /home /root -maxdepth 2 -name '.*' ! -name '.bashrc' ! -name '.bash_profile' ! -name '.profile' ! -name '.bash_logout' ! -name '.ssh' ! -name '.bash_history' -type f 2>/dev/null | head -10"
    result "SRV-166|수동확인|불필요 숨김 파일 수동 확인"
}

# ================================================================
# SRV-170: SMTP 정보 노출
# ================================================================
check_SRV170() {
    _smtp_running || { evd "SRV-170" "ps -ef 2>/dev/null | grep -E 'smtp|postfix|sendmail' | grep -v grep"; result "SRV-170|N-A|SMTP 서비스 미실행"; return; }
    _detect_smtp
    evd "SRV-170" "postconf smtpd_banner 2>/dev/null; grep -i SmtpGreetingMessage $_smtp_cf 2>/dev/null; exim -bP smtp_banner 2>/dev/null"
    case "$_smtp_type" in
    postfix)
        local ban=$(postconf -h smtpd_banner 2>/dev/null)
        echo "$ban" | grep -qiE 'mail_version|version|[0-9]+\.[0-9]+' && result "SRV-170|취약|postfix 배너에 버전 정보 노출: ${ban}" || result "SRV-170|양호|SMTP 배너 버전 정보 노출 없음 (${ban})" ;;
    sendmail)
        # 평가기준: SmtpGreetingMessage 에 $v 포함 시 버전 노출 — 미설정 시 기본값('$j Sendmail $v/$Z; $b')도 노출
        local greet=$(grep -iE "^\s*O\s+SmtpGreetingMessage" "$_smtp_cf" 2>/dev/null | tail -1)
        if [ -z "$greet" ]; then result "SRV-170|취약|SmtpGreetingMessage 미설정 (기본 인사말에 버전 \$v 포함)"
        elif echo "$greet" | grep -qE '\$v|\$Z'; then result "SRV-170|취약|sendmail 배너에 버전(\$v/\$Z) 노출"
        else result "SRV-170|양호|sendmail 배너 버전 미노출"; fi ;;
    exim)
        exim -bP smtp_banner 2>/dev/null | grep -q 'version_number' && result "SRV-170|취약|exim smtp_banner 에 \$version_number 포함" || result "SRV-170|양호|exim 배너 버전 미노출" ;;
    *) result "SRV-170|수동확인|${_smtp_type:-SMTP} 배너 정보 수동 확인" ;;
    esac
}

# ================================================================
# SRV-171: FTP 배너 정보 노출
# ================================================================
check_SRV171() {
    _ftp_running || { evd "SRV-171" "ps -ef 2>/dev/null | grep -E 'vsftpd|proftpd|ftpd' | grep -v grep"; result "SRV-171|N-A|FTP 서비스 미실행"; return; }
    evd "SRV-171" "grep -iE 'ftpd_banner|banner_file|ServerIdent' /etc/vsftpd.conf /etc/vsftpd/vsftpd.conf /etc/proftpd/proftpd.conf /etc/proftpd.conf 2>/dev/null"
    local c b
    if is_running vsftpd; then
        c=$(ls /etc/vsftpd.conf /etc/vsftpd/vsftpd.conf 2>/dev/null | head -1)
        b=$(grep -iE '^\s*(ftpd_banner|banner_file)\s*=' "$c" 2>/dev/null | tail -1)
        if [ -z "$b" ]; then result "SRV-171|취약|vsftpd 배너 미설정 (기본 배너에 vsFTPd 버전 노출)"
        elif echo "$b" | grep -qiE 'vsftpd|[0-9]+\.[0-9]+\.[0-9]+'; then result "SRV-171|취약|vsftpd 배너에 서비스명·버전 노출: ${b}"
        else result "SRV-171|양호|vsftpd 배너 설정 (${b%%=*})"; fi
    elif is_running proftpd; then
        b=$(grep -hiE '^\s*ServerIdent' /etc/proftpd/proftpd.conf /etc/proftpd.conf 2>/dev/null | tail -1)
        if echo "$b" | grep -qiE 'ServerIdent\s+off|ServerIdent\s+on\s+"'; then result "SRV-171|양호|proftpd ${b}"
        else result "SRV-171|취약|proftpd ServerIdent 미설정 (기본 'ProFTPD x.y.z Server' 노출)"; fi
    elif [ -f /etc/ftpd/ftpaccess ]; then   # HP-UX·Solaris in.ftpd(wu-ftpd 계열) greeting
        b=$(grep -iE '^\s*greeting' /etc/ftpd/ftpaccess 2>/dev/null | awk '{print tolower($2)}' | tail -1)
        case "$b" in
        brief|terse|text) result "SRV-171|양호|ftpaccess greeting ${b} (버전 미노출)" ;;
        full) result "SRV-171|취약|ftpaccess greeting full (서비스명·버전 노출)" ;;
        *) result "SRV-171|수동확인|ftpaccess greeting 미설정 - 접속 배너 서비스명·버전 노출 확인" ;;
        esac
    else
        [ "$OS_FAMILY" = "AIX" ] && evd "SRV-171" "dspcat /usr/lib/nls/msg/\${LANG:-C}/ftpd.cat 2>/dev/null | grep -i 'ftp server' | head -3"
        result "SRV-171|수동확인|FTP 배너 서비스명·버전 노출 수동 확인"; fi
}

# ================================================================
# SRV-173: DNS 동적 업데이트
# ================================================================
check_SRV173() {
    is_running named || { evd "SRV-173" "ps -ef 2>/dev/null | grep named | grep -v grep"; result "SRV-173|N-A|DNS 서비스 미실행"; return; }
    local nc; nc=$(_named_conf)
    evd "SRV-173" "echo '$(echo "$nc" | grep -iE 'allow-update' | head -5)'"
    echo "$nc" | grep -qiE 'allow-update\s*\{\s*any\s*;' && result "SRV-173|취약|DNS allow-update any 설정됨" || result "SRV-173|양호|DNS 동적 업데이트 제한됨"
}

# ================================================================
# SRV-174: 불필요 DNS 서비스
# ================================================================
check_SRV174() {
    evd "SRV-174" "ps -ef 2>/dev/null | grep -E 'named|dnsmasq' | grep -v grep | head -5"
    # 평가기준: DNS 서비스가 실행 중이지 않거나 업무상 필요한 경우 양호
    if is_running named || is_running dnsmasq; then
        result "SRV-174|수동확인|DNS 서비스 실행 중 - 업무 필요성 확인"
    else
        result "SRV-174|양호|DNS 서비스 미실행"
    fi
}

# ================================================================
# SRV-176: 비밀번호 저장 암호화 방식
# ================================================================
check_SRV176() {
    evd "SRV-176" "grep -E '^ENCRYPT_METHOD|^MD5_CRYPT_ENAB' /etc/login.defs 2>/dev/null; awk -F: '\$2!~/^[!*]/{print \$1,substr(\$2,1,3)}' /etc/shadow 2>/dev/null | head -10"
    local algo=$(grep -E '^\s*ENCRYPT_METHOD' /etc/login.defs 2>/dev/null | awk '{print $2}' | tail -1)
    local weak=""
    while IFS=: read -r user hash rest; do
        [ -z "$hash" ] || echo "$hash" | grep -qE '^\$|^[!*]|^$' || continue
        case "$hash" in
            \$1\$*) weak="${weak} ${user}(MD5)" ;;
            \$2*) ;;
            \$5\$*) ;;
            \$6\$*) ;;
            \$y\$*) ;;
            '!'*|'*'|'') ;;
            *) weak="${weak} ${user}(DES/unknown)" ;;
        esac
    done < /etc/shadow 2>/dev/null
    if [ -n "$weak" ]; then
        result "SRV-176|취약|취약 해시 사용 계정:${weak} (기본 algo=${algo:-미설정})"
    elif [ -n "$algo" ]; then
        result "SRV-176|양호|비밀번호 암호화 방식=${algo}"
    else
        result "SRV-176|수동확인|ENCRYPT_METHOD 미설정 - shadow 해시 수동 확인"
    fi
}

# ================================================================
# 주요정보통신기반시설 기술적 취약점 분석·평가 (U-시리즈) 함수
# ================================================================

_check_file_perm() {
    local code="$1" file="$2" max="$3" req_owner="${4:-root}" desc="$5"
    evd "$code" "ls -la $file 2>/dev/null"
    [ -e "$file" ] || [ -L "$file" ] || { result "$code|N-A|${desc} 미존재"; return; }
    local perm owner
    perm=$(get_perm "$file"); owner=$(get_owner "$file")
    if [ "$owner" != "$req_owner" ]; then
        result "$code|취약|${desc} 소유자=${owner} (${req_owner} 필요)"
    elif [ "${perm:-777}" -gt "$max" ] 2>/dev/null; then
        result "$code|취약|${desc} 권한=${perm} (${max} 이하 필요)"
    else
        result "$code|양호|${desc} 소유자=${owner}, 권한=${perm}"
    fi
}






























































# ================================================================
# U-74: 패스워드 암호화 사용 (잼팟 U-13)
# ================================================================

# ================================================================
# U-75: DNS 동적 업데이트 제한 (잼팟 U-51)
# ================================================================

# ================================================================
# U-76: FTP 배너 정보 노출 제한 (잼팟 U-53)
# ================================================================

# ================================================================
# U-77: SNMP 안전 버전 사용 (잼팟 U-59)
# ================================================================

# ================================================================
# U-78: SNMP 접근통제 (잼팟 U-61)
# ================================================================

# ================================================================
# U-79: /etc/sudoers 파일 권한 (잼팟 U-63)
# ================================================================

# ================================================================
# U-80: NTP 설정 (잼팟 U-65)
# ================================================================

# ================================================================
# U-81: 로그 디렉터리 권한 (잼팟 U-67)
# ================================================================


# ================================================================
# 추가 SRV 항목 (전자금융기반시설 전체 179항목 커버)
# ================================================================

# SRV-002: 패스워드 복잡성
check_SRV002() {
    evd "SRV-002" "grep -E '^\s*(PASS_MIN_LEN|MINLEN)' /etc/login.defs 2>/dev/null; grep -v '^#' $(get_pam_files) 2>/dev/null | grep -iE 'pam_pwquality|pam_cracklib'; cat /etc/security/pwquality.conf 2>/dev/null | grep -v '^#' | grep -v '^\s*$'"
    local minlen="" dcredit="" ucredit="" lcredit="" ocredit=""
    for pf in $(get_pam_files); do
        [ -f "$pf" ] || continue
        local ml=$(grep -v '^#' "$pf" 2>/dev/null | grep -oE 'minlen=[0-9]+' | head -1 | cut -d= -f2)
        [ -n "$ml" ] && minlen=$ml
    done
    if [ -f /etc/security/pwquality.conf ]; then
        [ -z "$minlen" ] && minlen=$(grep -E '^\s*minlen' /etc/security/pwquality.conf 2>/dev/null | grep -oE '[0-9]+' | head -1)
        dcredit=$(grep -E '^\s*dcredit' /etc/security/pwquality.conf 2>/dev/null | grep -oE '[-0-9]+' | head -1)
        ucredit=$(grep -E '^\s*ucredit' /etc/security/pwquality.conf 2>/dev/null | grep -oE '[-0-9]+' | head -1)
        lcredit=$(grep -E '^\s*lcredit' /etc/security/pwquality.conf 2>/dev/null | grep -oE '[-0-9]+' | head -1)
        ocredit=$(grep -E '^\s*ocredit' /etc/security/pwquality.conf 2>/dev/null | grep -oE '[-0-9]+' | head -1)
    fi
    [ -z "$minlen" ] && minlen=$(grep -E '^\s*PASS_MIN_LEN' /etc/login.defs 2>/dev/null | awk '{print $2}' | tail -1)
    local has_complexity=0
    grep -v '^#' $(get_pam_files) 2>/dev/null | grep -qiE 'pam_pwquality|pam_cracklib' && has_complexity=1
    if [ "${minlen:-0}" -ge 8 ] 2>/dev/null && [ $has_complexity -eq 1 ]; then
        result "SRV-002|양호|패스워드 복잡성 설정됨 (minlen=${minlen}, dcredit=${dcredit:--1}, ucredit=${ucredit:--1}, lcredit=${lcredit:--1}, ocredit=${ocredit:--1})"
    elif [ "${minlen:-0}" -ge 8 ] 2>/dev/null; then
        result "SRV-002|취약|패스워드 길이=${minlen} 이나 복잡성 모듈(pam_pwquality/cracklib) 미적용"
    else
        result "SRV-002|취약|패스워드 최소 길이=${minlen:-미설정} (8자리 이상 + 복잡성 필요)"
    fi
}

# SRV-017: 관리자 그룹 최소 계정
check_SRV017() {
    evd "SRV-017" "grep -E '^(wheel|sudo|admin|root):' /etc/group 2>/dev/null"
    local info="" total=0
    for grp in wheel sudo admin root; do
        local members=$(grep "^${grp}:" /etc/group 2>/dev/null | cut -d: -f4)
        if [ -n "$members" ]; then
            local cnt=$(echo "$members" | tr ',' '\n' | grep -v '^$' | wc -l)
            total=$((total + cnt))
            info="${info} ${grp}:[${members}](${cnt}명)"
        fi
    done
    [ "$total" -le 5 ] 2>/dev/null && result "SRV-017|양호|관리자 그룹 멤버 ${total}명${info}" || \
        result "SRV-017|취약|관리자 그룹 멤버 과다 (${total}명)${info}"
}

# SRV-018: su 제한
check_SRV018() {
    evd "SRV-018" "cat /etc/pam.d/su 2>/dev/null | grep -v '^#'"
    if grep -v "^#" /etc/pam.d/su 2>/dev/null | grep -qi "pam_wheel"; then
        local wg=$(grep -v "^#" /etc/pam.d/su 2>/dev/null | grep -i "pam_wheel" | grep -oE 'group=\S+' | cut -d= -f2 | head -1)
        result "SRV-018|양호|su pam_wheel 제한 설정됨 (그룹=${wg:-wheel})"
    else
        result "SRV-018|취약|su pam_wheel 미설정 (root 외 su 제한 없음)"
    fi
}

# SRV-019: 불필요 관리자 그룹 구성원
check_SRV019() {
    evd "SRV-019" "grep -E '^(wheel|sudo|admin):' /etc/group 2>/dev/null; id root 2>/dev/null"
    local info=""
    for grp in wheel sudo admin; do
        local members=$(grep "^${grp}:" /etc/group 2>/dev/null | cut -d: -f4)
        [ -n "$members" ] && info="${info} ${grp}:[${members}]"
    done
    [ -n "$info" ] && result "SRV-019|수동확인|관리자 그룹 구성원 확인:${info}" || \
        result "SRV-019|양호|관리자 그룹 구성원 없음"
}

# SRV-020: GID 없는 계정
check_SRV020() {
    evd "SRV-020" "awk -F: '{print \$1,\$4}' /etc/passwd 2>/dev/null | head -20"
    local found=""
    while IFS=: read -r user _ _ gid _ _ _; do
        getent group "$gid" >/dev/null 2>&1 || found="${found} ${user}(GID=${gid})"
    done < /etc/passwd 2>/dev/null
    [ -n "$found" ] && result "SRV-020|취약|존재하지 않는 GID:${found}" || \
        result "SRV-020|양호|모든 계정 GID 유효"
}

# SRV-023: 서비스 접근 IP/Port 제한
check_SRV023() {
    evd "SRV-023" "cat /etc/hosts.allow 2>/dev/null | grep -v '^#' | grep -v '^\s*$'; echo '---'; cat /etc/hosts.deny 2>/dev/null | grep -v '^#' | grep -v '^\s*$'; echo '---'; iptables -L -n 2>/dev/null | head -20; firewall-cmd --list-all 2>/dev/null"
    local ctrl=0
    [ -f /etc/hosts.deny ] && grep -qv "^#" /etc/hosts.deny 2>/dev/null && grep -qiE "ALL.*ALL|sshd" /etc/hosts.deny 2>/dev/null && ctrl=1
    iptables -L -n 2>/dev/null | grep -qiE "ACCEPT|DROP|REJECT" && ctrl=1
    firewall-cmd --state 2>/dev/null | grep -q "running" && ctrl=1
    [ $ctrl -eq 1 ] && result "SRV-023|수동확인|접근통제 설정 존재 (위 현황의 규칙 적정성 확인)" || \
        result "SRV-023|취약|TCP Wrapper/방화벽 접근통제 미설정"
}

# SRV-024: 계정 잠금
check_SRV024() {
    evd "SRV-024" "grep -v '^#' $(get_pam_files) 2>/dev/null | grep -iE 'pam_tally2|pam_faillock|faillock'; cat /etc/security/faillock.conf 2>/dev/null | grep -v '^#' | grep -v '^\s*$'"
    local lock=0 deny=""
    for pf in $(get_pam_files) /etc/pam.d/system-auth /etc/pam.d/password-auth /etc/pam.d/common-auth; do
        [ -f "$pf" ] || continue
        grep -v "^#" "$pf" 2>/dev/null | grep -qiE "pam_tally2|pam_faillock" && lock=1
        local d=$(grep -v "^#" "$pf" 2>/dev/null | grep -oE 'deny=[0-9]+' | head -1 | cut -d= -f2)
        [ -n "$d" ] && deny=$d
    done
    [ -z "$deny" ] && [ -f /etc/security/faillock.conf ] && deny=$(grep -E '^\s*deny' /etc/security/faillock.conf 2>/dev/null | grep -oE '[0-9]+' | head -1)
    if [ $lock -eq 1 ] && [ "${deny:-0}" -gt 0 ] 2>/dev/null; then
        result "SRV-024|양호|계정 잠금 설정됨 (deny=${deny})"
    elif [ $lock -eq 1 ]; then
        result "SRV-024|수동확인|잠금 모듈 로드되나 deny 값 확인 필요"
    else
        result "SRV-024|취약|계정 잠금 미설정 (pam_tally2/faillock 없음)"
    fi
}

# SRV-029: 불필요 서비스 (echo/discard/daytime/chargen)
check_SRV029() {
    evd "SRV-029" "systemctl list-unit-files 2>/dev/null | grep -iE 'echo|discard|daytime|chargen'; ls /etc/xinetd.d/ 2>/dev/null | grep -iE 'echo|discard|daytime|chargen'"
    local found=""
    for svc in echo-dgram echo-stream discard-dgram discard-stream daytime-dgram daytime-stream chargen-dgram chargen-stream; do
        if [ -f "/etc/xinetd.d/$svc" ]; then
            grep -q "disable.*=.*no" "/etc/xinetd.d/$svc" 2>/dev/null && found="${found} ${svc}(xinetd)"
        fi
        systemctl is-active "${svc}.socket" 2>/dev/null | grep -q "^active" && found="${found} ${svc}(systemd)"
    done
    [ -n "$found" ] && result "SRV-029|취약|불필요 서비스 활성화:${found}" || \
        result "SRV-029|양호|echo/discard/daytime/chargen 비활성화"
}

# SRV-030: NFS 비활성화
check_SRV030() {
    evd "SRV-030" "systemctl is-active nfs-server nfs 2>/dev/null; ps -ef 2>/dev/null | grep -E 'nfsd|rpc.nfsd' | grep -v grep"
    if is_running nfs-server || is_running nfs || is_running nfsd; then
        result "SRV-030|수동확인|NFS 서비스 실행 중 (업무 필요 여부 확인)"
    else
        result "SRV-030|양호|NFS 서비스 미실행"
    fi
}

# SRV-031: NFS 접근통제
check_SRV031() {
    evd "SRV-031" "cat /etc/exports 2>/dev/null; showmount -e 2>/dev/null"
    if [ ! -f /etc/exports ]; then
        result "SRV-031|양호|/etc/exports 미존재 (NFS 미사용)"; return
    fi
    local wide=""
    grep -v "^#" /etc/exports 2>/dev/null | grep -qE "\*|0\.0\.0\.0" && wide="yes"
    [ -n "$wide" ] && result "SRV-031|취약|NFS 전체 공유 허용 (* 또는 0.0.0.0)" || \
        result "SRV-031|수동확인|NFS exports 설정 확인 (위 현황 참조)"
}

# SRV-032: automountd 비활성화
check_SRV032() {
    evd "SRV-032" "systemctl is-active autofs 2>/dev/null; ps -ef 2>/dev/null | grep automount | grep -v grep"
    if is_running autofs || is_running automountd; then
        result "SRV-032|취약|automountd/autofs 서비스 실행 중"
    else
        result "SRV-032|양호|automountd/autofs 비활성화"
    fi
}

# SRV-033: 불필요 RPC 서비스
check_SRV033() {
    evd "SRV-033" "rpcinfo -p 2>/dev/null | head -20; ps -ef 2>/dev/null | grep -E 'rpc\\.cmsd|rpc\\.ttdbserverd|sadmind|rstatd|rusersd|rwalld|sprayd' | grep -v grep"
    local found=""
    for svc in rpc.cmsd rpc.ttdbserverd sadmind rstatd rusersd rwalld sprayd; do
        ps -ef 2>/dev/null | grep -v grep | grep -qw "$svc" && found="${found} ${svc}"
    done
    [ -n "$found" ] && result "SRV-033|취약|불필요 RPC 서비스:${found}" || \
        result "SRV-033|양호|불필요 RPC 서비스 미실행"
}

# SRV-036: Sendmail 일반사용자 실행 방지
check_SRV036() {
    evd "SRV-036" "ls -la /usr/sbin/sendmail /usr/lib/sendmail 2>/dev/null; grep -i restrictqrun /etc/mail/sendmail.cf /etc/sendmail.cf 2>/dev/null"
    if ! is_running sendmail; then
        result "SRV-036|양호|Sendmail 미실행"; return
    fi
    local vuln=""
    for sm in /usr/sbin/sendmail /usr/lib/sendmail; do
        [ -e "$sm" ] || continue
        local perm=$(get_perm "$sm")
        local other_x=$((${perm:-0} % 10))
        [ $((other_x & 1)) -eq 1 ] 2>/dev/null && vuln="${vuln} ${sm}(${perm})"
    done
    local cf=""
    for c in /etc/mail/sendmail.cf /etc/sendmail.cf; do [ -f "$c" ] && cf="$c" && break; done
    [ -n "$cf" ] && ! grep -qi "restrictqrun" "$cf" 2>/dev/null && vuln="${vuln} [restrictqrun 미설정]"
    [ -n "$vuln" ] && result "SRV-036|취약|Sendmail 실행방지 미흡:${vuln}" || \
        result "SRV-036|양호|Sendmail 실행 권한 제한됨"
}

# SRV-038: 웹서비스 디렉터리 리스팅
check_SRV038() {
    evd "SRV-038" "grep -riE 'Options.*Indexes|autoindex' /etc/httpd/conf/ /etc/apache2/ /etc/nginx/ 2>/dev/null | grep -v '^#' | head -10"
    local web_running=0
    is_running httpd || is_running apache2 && web_running=1
    is_running nginx && web_running=1
    if [ $web_running -eq 0 ]; then
        result "SRV-038|N-A|웹서비스 미실행"; return
    fi
    local vuln=""
    for cf in /etc/httpd/conf/httpd.conf /etc/apache2/apache2.conf /etc/apache2/sites-enabled/*.conf; do
        [ -f "$cf" ] || continue
        grep -v "^#" "$cf" 2>/dev/null | grep -qi "Options.*Indexes" && vuln="${vuln} ${cf}"
    done
    for cf in /etc/nginx/nginx.conf /etc/nginx/conf.d/*.conf /etc/nginx/sites-enabled/*; do
        [ -f "$cf" ] || continue
        grep -v "^#" "$cf" 2>/dev/null | grep -qi "autoindex.*on" && vuln="${vuln} ${cf}"
    done
    [ -n "$vuln" ] && result "SRV-038|취약|디렉터리 리스팅 활성화:${vuln}" || \
        result "SRV-038|양호|디렉터리 리스팅 비활성화"
}

# SRV-039: 웹프로세스 권한
check_SRV039() {
    evd "SRV-039" "grep -iE '^\s*(User|Group)' /etc/httpd/conf/httpd.conf /etc/apache2/envvars /etc/apache2/apache2.conf 2>/dev/null | grep -v '^#'; ps aux 2>/dev/null | grep -E 'httpd|apache2|nginx' | head -5"
    local web_running=0
    is_running httpd || is_running apache2 || is_running nginx && web_running=1
    if [ $web_running -eq 0 ]; then
        result "SRV-039|N-A|웹서비스 미실행"; return
    fi
    local web_user=$(ps aux 2>/dev/null | grep -E 'httpd|apache2|nginx' | grep -v grep | grep -v root | awk '{print $1}' | sort -u | head -1)
    if [ "$web_user" = "root" ] || [ -z "$web_user" ]; then
        local cfg_user=$(grep -iE '^\s*User\s' /etc/httpd/conf/httpd.conf /etc/apache2/apache2.conf 2>/dev/null | grep -v '^#' | awk '{print $NF}' | tail -1)
        [ "$cfg_user" = "root" ] && result "SRV-039|취약|웹프로세스 root 권한 실행" || \
            result "SRV-039|수동확인|웹프로세스 실행 사용자 확인 필요 (${cfg_user:-미확인})"
    else
        result "SRV-039|양호|웹프로세스 사용자=${web_user}"
    fi
}

# SRV-040: 상위 디렉터리 접근 금지
check_SRV040() {
    evd "SRV-040" "grep -riE 'AllowOverride|<Directory' /etc/httpd/conf/httpd.conf /etc/apache2/apache2.conf 2>/dev/null | grep -v '^#' | head -10"
    is_running httpd || is_running apache2 || { result "SRV-040|N-A|Apache 미실행"; return; }
    local vuln=""
    for cf in /etc/httpd/conf/httpd.conf /etc/apache2/apache2.conf; do
        [ -f "$cf" ] || continue
        grep -v "^#" "$cf" 2>/dev/null | grep -qi "AllowOverride.*All" && vuln="${vuln} ${cf}"
    done
    [ -n "$vuln" ] && result "SRV-040|수동확인|AllowOverride All 설정 확인:${vuln}" || \
        result "SRV-040|양호|AllowOverride 제한됨"
}

# SRV-041: 웹서비스 불필요 파일 제거
check_SRV041() {
    evd "SRV-041" "ls -d /var/www/manual /usr/share/httpd/manual /etc/httpd/conf.d/manual.conf /var/www/html/index.html 2>/dev/null"
    is_running httpd || is_running apache2 || { result "SRV-041|N-A|Apache 미실행"; return; }
    local found=""
    for d in /var/www/manual /usr/share/httpd/manual /usr/share/doc/apache2; do
        [ -d "$d" ] && found="${found} ${d}"
    done
    [ -f /etc/httpd/conf.d/manual.conf ] && found="${found} manual.conf"
    [ -n "$found" ] && result "SRV-041|취약|불필요 파일/디렉터리 존재:${found}" || \
        result "SRV-041|양호|불필요 매뉴얼/샘플 파일 미존재"
}

# SRV-042: 심볼릭 링크 사용 금지
check_SRV042() {
    evd "SRV-042" "grep -riE 'Options.*FollowSymLinks' /etc/httpd/conf/httpd.conf /etc/apache2/apache2.conf 2>/dev/null | grep -v '^#'"
    is_running httpd || is_running apache2 || { result "SRV-042|N-A|Apache 미실행"; return; }
    local vuln=""
    for cf in /etc/httpd/conf/httpd.conf /etc/apache2/apache2.conf; do
        [ -f "$cf" ] || continue
        grep -v "^#" "$cf" 2>/dev/null | grep -qi "Options.*FollowSymLinks" && \
            ! grep -v "^#" "$cf" 2>/dev/null | grep -qi "Options.*-FollowSymLinks" && vuln="${vuln} ${cf}"
    done
    [ -n "$vuln" ] && result "SRV-042|취약|FollowSymLinks 허용:${vuln}" || \
        result "SRV-042|양호|FollowSymLinks 제한됨"
}

# SRV-043: 파일 업로드/다운로드 제한
check_SRV043() {
    evd "SRV-043" "grep -riE 'LimitRequestBody|client_max_body_size' /etc/httpd/conf/ /etc/apache2/ /etc/nginx/ 2>/dev/null | grep -v '^#' | head -5"
    is_running httpd || is_running apache2 || is_running nginx || { result "SRV-043|N-A|웹서비스 미실행"; return; }
    local found=""
    grep -riE 'LimitRequestBody' /etc/httpd/conf/ /etc/apache2/ 2>/dev/null | grep -v "^#" | head -1 | grep -q "LimitRequestBody" && found="Apache"
    grep -riE 'client_max_body_size' /etc/nginx/ 2>/dev/null | grep -v "^#" | head -1 | grep -q "client_max_body_size" && found="${found:+$found/}Nginx"
    [ -n "$found" ] && result "SRV-043|양호|업로드 제한 설정됨 (${found})" || \
        result "SRV-043|취약|파일 업로드 크기 제한 미설정"
}

# SRV-044: 웹서비스 영역 분리
check_SRV044() {
    evd "SRV-044" "grep -iE '^\s*DocumentRoot' /etc/httpd/conf/httpd.conf /etc/apache2/sites-enabled/*.conf 2>/dev/null | grep -v '^#'; grep -iE '^\s*root\s' /etc/nginx/sites-enabled/* /etc/nginx/conf.d/*.conf 2>/dev/null | grep -v '^#'"
    is_running httpd || is_running apache2 || is_running nginx || { result "SRV-044|N-A|웹서비스 미실행"; return; }
    local docroot=""
    docroot=$(grep -iE '^\s*DocumentRoot' /etc/httpd/conf/httpd.conf /etc/apache2/sites-enabled/*.conf 2>/dev/null | grep -v '^#' | awk '{print $NF}' | tr -d '"' | tail -1)
    [ -z "$docroot" ] && docroot=$(grep -iE '^\s*root\s' /etc/nginx/sites-enabled/* /etc/nginx/conf.d/*.conf 2>/dev/null | grep -v '^#' | awk '{print $NF}' | tr -d ';' | tail -1)
    if [ "$docroot" = "/" ]; then
        result "SRV-044|취약|DocumentRoot=/ (루트 디렉터리 설정)"
    elif [ -n "$docroot" ]; then
        result "SRV-044|양호|DocumentRoot=${docroot}"
    else
        result "SRV-044|수동확인|DocumentRoot 확인 필요"
    fi
}

# SRV-045: 보안패치
check_SRV045() {
    evd "SRV-045" "uname -r; rpm -qa --last 2>/dev/null | head -10; apt list --upgradable 2>/dev/null | head -10; yum updateinfo summary 2>/dev/null | head -10"
    result "SRV-045|수동확인|최신 보안패치 적용 여부 수동 확인 (위 현황 참조)"
}

# SRV-046: 로그 검토/보고
check_SRV046() {
    evd "SRV-046" "ls -lt /var/log/syslog /var/log/messages /var/log/secure /var/log/auth.log /var/log/cron 2>/dev/null | head -10; last -5 2>/dev/null"
    result "SRV-046|수동확인|로그 정기 검토/보고 수동 확인 (위 현황 참조)"
}

# SRV-047: 시스템 로깅 설정
check_SRV047() {
    evd "SRV-047" "grep -vE '^#|^\s*$' /etc/rsyslog.conf /etc/rsyslog.d/*.conf /etc/syslog.conf 2>/dev/null | head -20"
    local logging=0
    for f in /etc/rsyslog.conf /etc/rsyslog.d/*.conf /etc/syslog.conf; do
        [ -f "$f" ] || continue
        grep -qiE "^auth|^authpriv|^kern|^cron" "$f" 2>/dev/null && logging=1
    done
    [ $logging -eq 1 ] && result "SRV-047|양호|시스템 로깅 설정됨 (auth/kern/cron)" || \
        result "SRV-047|취약|시스템 로깅 미설정"
}

# SRV-048: su 사용 로그
check_SRV048() {
    evd "SRV-048" "ls -la /var/log/sulog /var/log/auth.log /var/log/secure 2>/dev/null; grep -i 'SULOG_FILE\|su.*session' /etc/login.defs /etc/rsyslog.conf /etc/pam.d/su 2>/dev/null | grep -v '^#'"
    if [ -f /var/log/auth.log ] || [ -f /var/log/secure ]; then
        result "SRV-048|양호|su 사용 로그 기록됨 (auth.log/secure)"
    elif [ -f /var/log/sulog ]; then
        result "SRV-048|양호|su 사용 로그 기록됨 (/var/log/sulog)"
    else
        result "SRV-048|취약|su 사용 로그 미설정"
    fi
}

# SRV-049: 접속기록 파일 보호
check_SRV049() {
    evd "SRV-049" "ls -la /var/log/wtmp /var/log/btmp /var/log/lastlog /var/run/utmp 2>/dev/null"
    local vuln=""
    for f in /var/log/wtmp /var/log/btmp /var/log/lastlog; do
        [ -f "$f" ] || continue
        local perm=$(get_perm "$f") owner=$(get_owner "$f")
        [ "$owner" != "root" ] && vuln="${vuln} ${f}(소유자=${owner})"
        [ "${perm:-777}" -gt 644 ] 2>/dev/null && vuln="${vuln} ${f}(${perm})"
    done
    if [ -f /var/log/btmp ]; then
        local bp=$(get_perm "/var/log/btmp")
        [ "${bp:-777}" -gt 600 ] 2>/dev/null && vuln="${vuln} btmp(${bp},600이하필요)"
    fi
    [ -n "$vuln" ] && result "SRV-049|취약|접속기록 파일 권한 이상:${vuln}" || \
        result "SRV-049|양호|접속기록 파일 권한 적절"
}

# SRV-050: 로그인/로그아웃 기록
check_SRV050() {
    evd "SRV-050" "last -5 2>/dev/null; lastlog 2>/dev/null | head -15; ls -la /var/log/wtmp /var/log/lastlog 2>/dev/null"
    if [ -f /var/log/wtmp ] && [ -f /var/log/lastlog ]; then
        result "SRV-050|양호|로그인/로그아웃 기록 파일 존재 (wtmp/lastlog)"
    else
        result "SRV-050|취약|로그인/로그아웃 기록 파일 미존재"
    fi
}

# SRV-051: su 사용자 제한 (wheel 그룹)
check_SRV051() {
    evd "SRV-051" "grep -v '^#' /etc/pam.d/su 2>/dev/null | grep pam_wheel; grep '^wheel:' /etc/group 2>/dev/null"
    if grep -v "^#" /etc/pam.d/su 2>/dev/null | grep -qi "pam_wheel"; then
        local members=$(grep "^wheel:" /etc/group 2>/dev/null | cut -d: -f4)
        result "SRV-051|양호|su pam_wheel 제한됨 (wheel 멤버: ${members:-없음})"
    else
        result "SRV-051|취약|su 사용자 제한 미설정 (pam_wheel 없음)"
    fi
}

# SRV-052: SMTP 비활성화
check_SRV052() {
    evd "SRV-052" "systemctl is-active postfix sendmail exim4 2>/dev/null; ss -tlnp 2>/dev/null | grep ':25 '"
    _smtp_running && result "SRV-052|수동확인|SMTP 서비스 실행 중 (업무 필요 여부 확인)" || \
        result "SRV-052|양호|SMTP 서비스 미실행"
}

# SRV-053: SMTP Banner 정보 제한
check_SRV053() {
    _smtp_running || { result "SRV-053|N-A|SMTP 미실행"; return; }
    _detect_smtp
    evd "SRV-053" "postconf smtp_banner smtpd_banner 2>/dev/null; grep -i SmtpGreetingMessage /etc/mail/sendmail.cf /etc/sendmail.cf 2>/dev/null"
    case "$_smtp_type" in
    postfix)
        local banner=$(postconf -h smtpd_banner 2>/dev/null)
        echo "$banner" | grep -qiE "postfix|version|MTA" && \
            result "SRV-053|취약|SMTP 배너 버전 노출 (${banner})" || \
            result "SRV-053|양호|SMTP 배너 커스터마이징됨" ;;
    sendmail)
        local banner=$(grep -i "SmtpGreetingMessage\|O SmtpGreetingMessage" "$_smtp_cf" 2>/dev/null | head -1)
        [ -n "$banner" ] && result "SRV-053|수동확인|sendmail 배너=${banner}" || \
            result "SRV-053|취약|sendmail 배너 기본값 사용" ;;
    *) result "SRV-053|수동확인|${_smtp_type:-SMTP} 배너 수동 확인" ;;
    esac
}

# SRV-054: SMTP Relay 제한
check_SRV054() {
    _smtp_running || { result "SRV-054|N-A|SMTP 미실행"; return; }
    _detect_smtp
    evd "SRV-054" "postconf mynetworks smtpd_relay_restrictions smtpd_recipient_restrictions 2>/dev/null; grep -i relay /etc/mail/access 2>/dev/null | head -5"
    case "$_smtp_type" in
    postfix)
        local rr=$(postconf -h smtpd_relay_restrictions 2>/dev/null)
        local mn=$(postconf -h mynetworks 2>/dev/null)
        result "SRV-054|수동확인|postfix relay_restrictions=${rr:-미설정}, mynetworks=${mn:-미설정}" ;;
    sendmail)
        [ -f /etc/mail/access ] && result "SRV-054|수동확인|sendmail /etc/mail/access 존재 (relay 설정 확인)" || \
            result "SRV-054|취약|sendmail relay 제한 미설정 (/etc/mail/access 없음)" ;;
    *) result "SRV-054|수동확인|${_smtp_type:-SMTP} relay 설정 수동 확인" ;;
    esac
}

# SRV-055: SMTP ACCESS 설정
check_SRV055() {
    _smtp_running || { result "SRV-055|N-A|SMTP 미실행"; return; }
    _detect_smtp
    evd "SRV-055" "cat /etc/mail/access 2>/dev/null | grep -v '^#' | head -10; postconf smtpd_client_restrictions smtpd_sender_restrictions 2>/dev/null"
    case "$_smtp_type" in
    postfix)
        local cr=$(postconf -h smtpd_client_restrictions 2>/dev/null)
        [ -n "$cr" ] && result "SRV-055|수동확인|postfix client_restrictions=${cr}" || \
            result "SRV-055|취약|postfix 발송 제한 미설정" ;;
    sendmail)
        [ -f /etc/mail/access ] && [ -s /etc/mail/access ] && \
            result "SRV-055|수동확인|sendmail /etc/mail/access 설정 확인" || \
            result "SRV-055|취약|sendmail access DB 미설정" ;;
    *) result "SRV-055|수동확인|${_smtp_type:-SMTP} ACCESS 설정 수동 확인" ;;
    esac
}

# SRV-056: SMTP VRFY/EXPN 비활성화
check_SRV056() {
    _smtp_running || { result "SRV-056|N-A|SMTP 미실행"; return; }
    _detect_smtp
    evd "SRV-056" "postconf disable_vrfy_command 2>/dev/null; grep -i PrivacyOptions $_smtp_cf 2>/dev/null"
    case "$_smtp_type" in
    postfix)
        local val=$(postconf -h disable_vrfy_command 2>/dev/null)
        [ "$val" = "yes" ] && result "SRV-056|양호|postfix disable_vrfy_command=yes" || \
            result "SRV-056|취약|postfix disable_vrfy_command=${val:-no}" ;;
    sendmail)
        [ -n "$_smtp_cf" ] && grep -qi "PrivacyOptions.*noexpn\|PrivacyOptions.*novrfy\|PrivacyOptions.*goaway" "$_smtp_cf" 2>/dev/null && \
            result "SRV-056|양호|sendmail EXPN/VRFY 제한됨" || \
            result "SRV-056|취약|sendmail EXPN/VRFY 미제한" ;;
    *) result "SRV-056|수동확인|${_smtp_type:-SMTP} VRFY/EXPN 수동 확인" ;;
    esac
}

# SRV-057: SMTP TLS/보안
check_SRV057() {
    _smtp_running || { result "SRV-057|N-A|SMTP 미실행"; return; }
    _detect_smtp
    evd "SRV-057" "postconf smtpd_use_tls smtpd_tls_cert_file smtpd_tls_security_level 2>/dev/null; grep -i 'STARTTLS\|AuthMechanisms\|CACert' $_smtp_cf 2>/dev/null | head -5"
    case "$_smtp_type" in
    postfix)
        local tls=$(postconf -h smtpd_tls_security_level 2>/dev/null)
        local use_tls=$(postconf -h smtpd_use_tls 2>/dev/null)
        if [ "$tls" = "encrypt" ] || [ "$tls" = "may" ] || [ "$use_tls" = "yes" ]; then
            result "SRV-057|양호|SMTP TLS 설정됨 (level=${tls:-legacy}, use_tls=${use_tls})"
        else
            result "SRV-057|취약|SMTP TLS 미설정 (tls_security_level=${tls:-미설정})"
        fi ;;
    *) result "SRV-057|수동확인|${_smtp_type:-SMTP} TLS/보안 설정 수동 확인" ;;
    esac
}

# SRV-058: DNS 보안패치
check_SRV058() {
    is_running named || { result "SRV-058|N-A|DNS 미실행"; return; }
    evd "SRV-058" "named -v 2>/dev/null; rpm -qa bind 2>/dev/null; dpkg -l bind9 2>/dev/null | tail -1"
    local ver=$(named -v 2>/dev/null | grep -oE 'BIND [0-9][^ ]*' | head -1)
    result "SRV-058|수동확인|DNS ${ver:-버전 미확인} - 보안 패치 적용 여부 확인"
}

# SRV-059: DNS 영역전송 제한
check_SRV059() {
    is_running named || { result "SRV-059|N-A|DNS 미실행"; return; }
    evd "SRV-059" "grep -i allow-transfer /etc/named.conf /etc/bind/named.conf 2>/dev/null"
    for conf in /etc/named.conf /etc/bind/named.conf; do
        [ -f "$conf" ] || continue
        grep -q "allow-transfer.*none" "$conf" 2>/dev/null && { result "SRV-059|양호|Zone Transfer 차단"; return; }
        grep -q "allow-transfer" "$conf" 2>/dev/null && { result "SRV-059|수동확인|allow-transfer 허용 대상 확인"; return; }
        result "SRV-059|취약|Zone Transfer 제한 미설정"; return
    done
    result "SRV-059|수동확인|named.conf 수동 확인"
}

# SRV-060: DNS Dynamic Update 비활성화
check_SRV060() {
    is_running named || { result "SRV-060|N-A|DNS 미실행"; return; }
    evd "SRV-060" "grep -i allow-update /etc/named.conf /etc/bind/named.conf 2>/dev/null"
    local vuln=0
    for conf in /etc/named.conf /etc/bind/named.conf; do
        [ -f "$conf" ] || continue
        grep -v "^[[:space:]]*//" "$conf" | grep -v "^#" | grep -i "allow-update" | grep -qi "any" && vuln=1
        grep -v "^[[:space:]]*//" "$conf" | grep -v "^#" | grep -i "allow-update" | grep -qi "none" && { result "SRV-060|양호|DNS 동적 업데이트 차단"; return; }
    done
    [ $vuln -eq 1 ] && result "SRV-060|취약|DNS 동적 업데이트 any 허용" || \
        result "SRV-060|수동확인|allow-update 설정 확인 필요"
}

# SRV-061: DNS 최신 버전
check_SRV061() {
    is_running named || { result "SRV-061|N-A|DNS 미실행"; return; }
    evd "SRV-061" "named -v 2>/dev/null"
    local ver=$(named -v 2>/dev/null | grep -oE 'BIND [0-9][^ ]*' | head -1)
    result "SRV-061|수동확인|DNS ${ver:-버전 미확인} - 최신 버전 사용 여부 확인"
}


# SRV-065
check_SRV065() {
    evd "SRV-065" "ls -la /etc/cron.allow /etc/cron.deny /etc/at.allow /etc/at.deny 2>/dev/null; cat /etc/cron.allow 2>/dev/null; cat /etc/cron.deny 2>/dev/null"
    if [ -f /etc/cron.allow ]; then
        local perm=$(get_perm "/etc/cron.allow") owner=$(get_owner "/etc/cron.allow")
        [ "$owner" = "root" ] && [ "${perm:-777}" -le 640 ] 2>/dev/null && \
            result "SRV-065|양호|cron.allow 존재 (소유자=${owner}, 권한=${perm})" || \
            result "SRV-065|취약|cron.allow 권한 이상 (소유자=${owner}, 권한=${perm})"
    elif [ -f /etc/cron.deny ]; then
        result "SRV-065|수동확인|cron.deny만 존재 (cron.allow 권장)"
    else
        result "SRV-065|취약|cron.allow/cron.deny 미존재 (모든 사용자 cron 사용 가능)"
    fi
}

# SRV-067
check_SRV067() {
    evd "SRV-067" "cat /etc/motd 2>/dev/null | head -5; cat /etc/issue 2>/dev/null | head -3; cat /etc/issue.net 2>/dev/null | head -3; grep -i Banner /etc/ssh/sshd_config 2>/dev/null | grep -v '^#'"
    local found=0
    for f in /etc/motd /etc/issue /etc/issue.net; do
        [ -f "$f" ] && [ -s "$f" ] && found=1
    done
    grep -v '^#' /etc/ssh/sshd_config 2>/dev/null | grep -qi "^Banner" && found=1
    [ $found -eq 1 ] && result "SRV-067|양호|로그온 경고 메시지 설정됨" || \
        result "SRV-067|취약|로그온 경고 메시지 미설정 (/etc/motd, /etc/issue, SSH Banner 없음)"
}

# SRV-068
check_SRV068() {
    evd "SRV-068" "ls -la /etc/exports 2>/dev/null; cat /etc/exports 2>/dev/null"
    if [ ! -f /etc/exports ]; then
        result "SRV-068|N-A|/etc/exports 미존재"; return
    fi
    local perm=$(get_perm "/etc/exports") owner=$(get_owner "/etc/exports")
    if [ "$owner" != "root" ]; then
        result "SRV-068|취약|/etc/exports 소유자=${owner} (root 필요)"
    elif [ "${perm:-777}" -gt 644 ] 2>/dev/null; then
        result "SRV-068|취약|/etc/exports 권한=${perm} (644 이하 필요)"
    else
        result "SRV-068|양호|/etc/exports 소유자=${owner}, 권한=${perm}"
    fi
}

# SRV-071
check_SRV071() {
    evd "SRV-071" "grep -riE 'Indexes|autoindex' /etc/httpd/conf/ /etc/apache2/ /etc/nginx/ 2>/dev/null | grep -v '^#' | head -10"
    if ! is_running httpd && ! is_running apache2 && ! is_running nginx; then
        result "SRV-071|N-A|웹서버 미실행"; return
    fi
    local vuln=""
    for cf in /etc/httpd/conf/httpd.conf /etc/apache2/apache2.conf /etc/apache2/sites-enabled/*.conf; do
        [ -f "$cf" ] || continue
        grep -v '^\s*#' "$cf" 2>/dev/null | grep -qi "Options.*Indexes" && vuln="${vuln} ${cf}"
    done
    for cf in /etc/nginx/nginx.conf /etc/nginx/conf.d/*.conf /etc/nginx/sites-enabled/*; do
        [ -f "$cf" ] || continue
        grep -v '^\s*#' "$cf" 2>/dev/null | grep -qi "autoindex.*on" && vuln="${vuln} ${cf}"
    done
    [ -n "$vuln" ] && result "SRV-071|취약|디렉터리 인덱싱 활성화:${vuln}" || \
        result "SRV-071|양호|디렉터리 인덱싱 비활성화"
}

# SRV-076
check_SRV076() {
    is_running snmpd || { result "SRV-076|N-A|SNMP 미실행"; return; }
    evd "SRV-076" "grep -v '^#' /etc/snmp/snmpd.conf /etc/snmpd.conf 2>/dev/null | grep -iE 'com2sec|agentAddress|rocommunity|rwcommunity' | head -10"
    local acl=0
    for conf in /etc/snmpd.conf /etc/snmp/snmpd.conf; do
        [ -f "$conf" ] || continue
        grep -v '^#' "$conf" 2>/dev/null | grep -qiE 'com2sec.*[0-9]+\.[0-9]+|agentAddress.*udp:[0-9]' && acl=1
    done
    [ $acl -eq 1 ] && result "SRV-076|양호|SNMP 접근통제 설정됨 (IP 제한)" || \
        result "SRV-076|취약|SNMP 접근통제 미설정 (IP 제한 없음)"
}

# SRV-077
check_SRV077() {
    is_running snmpd || { result "SRV-077|N-A|SNMP 미실행"; return; }
    evd "SRV-077" "grep -v '^#' /etc/snmp/snmpd.conf /etc/snmpd.conf 2>/dev/null | grep -iE 'community|rocommunity|rwcommunity' | head -10"
    local vuln=""
    for conf in /etc/snmpd.conf /etc/snmp/snmpd.conf; do
        [ -f "$conf" ] || continue
        grep -v '^#' "$conf" 2>/dev/null | grep -qiE '(rocommunity|rwcommunity|community).*(public|private)' && vuln="$conf"
    done
    [ -n "$vuln" ] && result "SRV-077|취약|기본 커뮤니티 스트링 사용 (public/private) - ${vuln}" || \
        result "SRV-077|양호|기본 커뮤니티 스트링 미사용"
}

# SRV-085
check_SRV085() {
    evd "SRV-085" "echo \$PATH; grep -iE 'PATH=|export PATH' /etc/profile /root/.bashrc /root/.bash_profile 2>/dev/null | grep -v '^#' | head -10"
    if echo "$PATH" | tr ':' '\n' | grep -qx '\.'; then
        result "SRV-085|취약|PATH에 현재 디렉토리(.) 포함"
    else
        result "SRV-085|양호|PATH에 현재 디렉토리(.) 미포함"
    fi
}

# SRV-086
check_SRV086() {
    evd "SRV-086" "awk -F: '\$3>=500 || \$3==0 {print \$1,\$3,\$6}' /etc/passwd 2>/dev/null | head -20"
    local vuln="" min_uid=500
    [ -f /etc/debian_version ] && min_uid=1000
    while IFS=: read -r user _ uid _ _ homedir _; do
        [ "${uid:-0}" -lt "$min_uid" ] 2>/dev/null && [ "$uid" != "0" ] && continue
        [ -z "$homedir" ] || [ "$homedir" = "/" ] && continue
        [ -d "$homedir" ] || continue
        local perm=$(get_perm "$homedir") owner=$(get_owner "$homedir")
        [ "$owner" != "$user" ] && vuln="${vuln} ${homedir}(소유자=${owner})"
        [ "${perm:-0}" -gt 755 ] 2>/dev/null && vuln="${vuln} ${homedir}(${perm})"
    done < /etc/passwd 2>/dev/null
    [ -n "$vuln" ] && result "SRV-086|취약|홈 디렉토리 이상:${vuln}" || \
        result "SRV-086|양호|홈 디렉토리 소유자 및 권한 적절 (755 이하)"
}

# SRV-088
check_SRV088() {
    evd "SRV-088" "ls -la /etc/crontab /var/spool/cron/ /var/spool/cron/crontabs/ 2>/dev/null"
    local vuln=""
    if [ -f /etc/crontab ]; then
        local perm=$(get_perm "/etc/crontab")
        [ "${perm:-777}" -gt 640 ] 2>/dev/null && vuln="${vuln} /etc/crontab(${perm})"
    fi
    for d in /var/spool/cron /var/spool/cron/crontabs; do
        [ -d "$d" ] || continue
        local dperm=$(get_perm "$d")
        [ "${dperm:-777}" -gt 750 ] 2>/dev/null && vuln="${vuln} ${d}(${dperm})"
    done
    [ -n "$vuln" ] && result "SRV-088|취약|crontab 권한 이상:${vuln}" || \
        result "SRV-088|양호|crontab 파일 권한 적절 (640 이하)"
}

# SRV-089
check_SRV089() {
    evd "SRV-089" "ls -la /etc/hosts.equiv 2>/dev/null; cat /etc/hosts.equiv 2>/dev/null; find /home /root -name '.rhosts' -ls 2>/dev/null | head -10"
    local vuln=""
    [ -f /etc/hosts.equiv ] && vuln="${vuln} /etc/hosts.equiv"
    local rhosts=$(find /home /root -name '.rhosts' 2>/dev/null | head -5)
    [ -n "$rhosts" ] && vuln="${vuln} ${rhosts}"
    [ -n "$vuln" ] && result "SRV-089|취약|hosts.equiv/.rhosts 파일 존재:${vuln}" || \
        result "SRV-089|양호|hosts.equiv/.rhosts 파일 미존재"
}

# SRV-097
check_SRV097() {
    evd "SRV-097" "systemctl list-unit-files --type=service --state=enabled 2>/dev/null | head -30; chkconfig --list 2>/dev/null | grep ':on' | head -20"
    local cnt=$(systemctl list-unit-files --type=service --state=enabled 2>/dev/null | grep -c "enabled")
    result "SRV-097|수동확인|활성화된 서비스 ${cnt:-미확인}개 (불필요 서비스 확인 필요)"
}

# SRV-098
check_SRV098() {
    evd "SRV-098" "systemctl list-unit-files --type=service --state=enabled 2>/dev/null | head -40"
    local cnt=$(systemctl list-unit-files --type=service --state=enabled 2>/dev/null | grep -c "enabled")
    result "SRV-098|수동확인|활성 서비스 ${cnt:-미확인}개 - 최소 필요 서비스만 유지 확인"
}

# SRV-099
check_SRV099() {
    evd "SRV-099" "iptables -L -n 2>/dev/null | head -20; firewall-cmd --list-all 2>/dev/null; ufw status 2>/dev/null"
    local fw=0
    iptables -L -n 2>/dev/null | grep -qv "^Chain\|^target\|^$" && fw=1
    systemctl is-active firewalld >/dev/null 2>&1 && fw=1
    ufw status 2>/dev/null | grep -qi "active" && fw=1
    [ $fw -eq 1 ] && result "SRV-099|양호|네트워크 접근제어 설정됨 (방화벽 활성)" || \
        result "SRV-099|취약|네트워크 접근제어 미설정 (방화벽 비활성 또는 규칙 없음)"
}

# SRV-100
check_SRV100() {
    evd "SRV-100" "awk -F: '\$3<500 && \$3!=0 && \$7 !~ /nologin|false|sync/ {print \$1,\$3,\$7}' /etc/passwd 2>/dev/null"
    local vuln="" min_uid=500
    [ -f /etc/debian_version ] && min_uid=1000
    while IFS=: read -r user _ uid _ _ _ shell; do
        [ "$user" = "root" ] && continue
        [ "${uid:-999}" -ge "$min_uid" ] 2>/dev/null && continue
        case "$shell" in */nologin|*/false|/bin/false|/sbin/nologin|*/sync|"") ;; *) vuln="${vuln} ${user}(${shell})" ;; esac
    done < /etc/passwd 2>/dev/null
    [ -n "$vuln" ] && result "SRV-100|취약|시스템 계정 로그인 가능:${vuln}" || \
        result "SRV-100|양호|시스템 계정 로그인 제한됨 (nologin/false)"
}

# SRV-101
check_SRV101() {
    evd "SRV-101" "grep -i PermitRootLogin /etc/ssh/sshd_config 2>/dev/null | grep -v '^#'"
    local val=$(grep -v '^#' /etc/ssh/sshd_config 2>/dev/null | grep -i "PermitRootLogin" | awk '{print $2}' | tail -1)
    case "$val" in
        no|No|NO) result "SRV-101|양호|PermitRootLogin=no" ;;
        without-password|prohibit-password) result "SRV-101|양호|PermitRootLogin=${val} (키 인증만 허용)" ;;
        yes|Yes|YES) result "SRV-101|취약|PermitRootLogin=yes (root 원격접속 허용)" ;;
        "") result "SRV-101|취약|PermitRootLogin 미설정 (기본값 허용)" ;;
        *) result "SRV-101|수동확인|PermitRootLogin=${val}" ;;
    esac
}

# SRV-102
check_SRV102() {
    evd "SRV-102" "grep -rh TMOUT /etc/profile /etc/bashrc /root/.bashrc 2>/dev/null | grep -v '^#'; grep -i ClientAlive /etc/ssh/sshd_config 2>/dev/null | grep -v '^#'"
    local tmout=""
    for f in /etc/profile /etc/bashrc /etc/bash.bashrc /etc/environment /root/.bashrc /root/.profile; do
        [ -f "$f" ] || continue
        local t=$(grep -h 'TMOUT' "$f" 2>/dev/null | grep -v '^#' | grep -oE '[0-9]+' | head -1)
        [ -n "$t" ] && tmout=$t && break
    done
    local alive=$(grep -v '^#' /etc/ssh/sshd_config 2>/dev/null | grep -i "ClientAliveInterval" | awk '{print $2}' | tail -1)
    if [ -n "$tmout" ] && [ "$tmout" -le 600 ] 2>/dev/null; then
        result "SRV-102|양호|TMOUT=${tmout}초"
    elif [ -n "$alive" ] && [ "$alive" -le 600 ] 2>/dev/null && [ "$alive" -gt 0 ] 2>/dev/null; then
        result "SRV-102|양호|ClientAliveInterval=${alive}초"
    elif [ -n "$tmout" ]; then
        result "SRV-102|취약|TMOUT=${tmout}초 (600초 초과)"
    else
        result "SRV-102|취약|세션 타임아웃 미설정 (TMOUT/ClientAliveInterval 없음)"
    fi
}

# SRV-103
check_SRV103() {
    evd "SRV-103" "lastlog 2>/dev/null | head -30; awk -F: '\$7 !~ /nologin|false/ {print \$1,\$3,\$7}' /etc/passwd 2>/dev/null"
    local inactive=""
    while IFS= read -r line; do
        local user=$(echo "$line" | awk '{print $1}')
        [ -n "$user" ] && inactive="${inactive} ${user}"
    done < <(lastlog 2>/dev/null | awk 'NR>1 && /Never logged in/' | head -20)
    [ -n "$inactive" ] && result "SRV-103|수동확인|미로그인 계정:${inactive} (불필요 여부 검토)" || \
        result "SRV-103|수동확인|계정 목록 확인 (위 현황 참조)"
}

# SRV-104
check_SRV104() {
    evd "SRV-104" "grep -E '^wheel:|^sudo:|^admin:' /etc/group 2>/dev/null"
    local info="" total=0
    for grp in wheel sudo admin; do
        local members=$(grep "^${grp}:" /etc/group 2>/dev/null | cut -d: -f4)
        if [ -n "$members" ]; then
            local cnt=$(echo "$members" | tr ',' '\n' | grep -cv '^$')
            total=$((total + cnt))
            info="${info} ${grp}:[${members}](${cnt}명)"
        fi
    done
    [ "$total" -gt 5 ] 2>/dev/null && result "SRV-104|취약|관리자 그룹 멤버 과다(${total}명):${info}" || \
        result "SRV-104|양호|관리자 그룹 멤버(${total}명)${info}"
}

# SRV-105
check_SRV105() {
    evd "SRV-105" "grep -rh TMOUT /etc/profile /etc/bashrc 2>/dev/null | grep -v '^#'; grep -i ClientAliveCountMax /etc/ssh/sshd_config 2>/dev/null | grep -v '^#'"
    local tmout=""
    for f in /etc/profile /etc/bashrc /etc/bash.bashrc /root/.bashrc; do
        [ -f "$f" ] || continue
        local t=$(grep -h 'TMOUT' "$f" 2>/dev/null | grep -v '^#' | grep -oE '[0-9]+' | head -1)
        [ -n "$t" ] && tmout=$t && break
    done
    if [ -n "$tmout" ] && [ "$tmout" -le 600 ] 2>/dev/null; then
        result "SRV-105|양호|세션 종료 설정됨 (TMOUT=${tmout}초)"
    else
        result "SRV-105|취약|세션 종료 미설정 또는 600초 초과 (TMOUT=${tmout:-미설정})"
    fi
}

# SRV-106
check_SRV106() {
    evd "SRV-106" "awk -F: '\$3==0 {print \$1,\$3}' /etc/passwd 2>/dev/null"
    local found=$(awk -F: '$3==0 && $1!="root" {print $1}' /etc/passwd 2>/dev/null)
    [ -n "$found" ] && result "SRV-106|취약|root 외 UID 0 계정: $(echo $found | tr '\n' ',')" || \
        result "SRV-106|양호|root 외 UID 0 계정 없음"
}

# SRV-107
check_SRV107() {
    evd "SRV-107" "grep -E '^PASS_MIN_LEN|^MINLEN' /etc/login.defs 2>/dev/null; grep -iE 'pam_pwquality|pam_cracklib' $(get_pam_files) 2>/dev/null | grep -v '^#'"
    local minlen=$(grep -E '^\s*PASS_MIN_LEN' /etc/login.defs 2>/dev/null | awk '{print $2}' | tail -1)
    local pam_ml=$(grep -v '^#' $(get_pam_files) 2>/dev/null | grep -oE 'minlen=[0-9]+' | head -1 | cut -d= -f2)
    local elen=${pam_ml:-${minlen:-0}}
    [ "${elen:-0}" -ge 8 ] 2>/dev/null && result "SRV-107|양호|패스워드 최소 길이=${elen}" || \
        result "SRV-107|취약|패스워드 최소 길이=${elen:-미설정} (8자리 이상 필요)"
}

# SRV-110
check_SRV110() {
    evd "SRV-110" "_to 60 find / \$_FP \( -nouser -o -nogroup \) -print 2>/dev/null | head -20"
    local found=$(_to 60 find / $_FP \( -nouser -o -nogroup \) -print 2>/dev/null | grep -vE '^/proc|^/sys|^/dev|^/run' | head -10)
    [ -n "$found" ] && result "SRV-110|취약|소유자 없는 파일 존재: $(echo $found | head -c 200)" || \
        result "SRV-110|양호|소유자 없는 파일 미존재"
}

# SRV-111
check_SRV111() {
    evd "SRV-111" "cat /etc/logrotate.conf 2>/dev/null | head -15; ls -la /etc/logrotate.d/ 2>/dev/null | head -10; du -sh /var/log 2>/dev/null"
    if [ -f /etc/logrotate.conf ]; then
        local rotate=$(grep -E '^\s*rotate ' /etc/logrotate.conf 2>/dev/null | awk '{print $2}')
        result "SRV-111|수동확인|logrotate 설정됨 (보관=${rotate:-미확인}주기) - 정책 적합성 확인"
    else
        result "SRV-111|취약|logrotate 미설정 (로그 관리 부재)"
    fi
}

# SRV-113
check_SRV113() {
    evd "SRV-113" "iptables -L -n --line-numbers 2>/dev/null | head -30; firewall-cmd --list-all 2>/dev/null; ufw status verbose 2>/dev/null"
    local fw=0
    iptables -L -n 2>/dev/null | grep -qvE '^Chain|^target|^$|ACCEPT.*anywhere.*anywhere' && fw=1
    systemctl is-active firewalld >/dev/null 2>&1 && fw=1
    ufw status 2>/dev/null | grep -qi "active" && fw=1
    [ $fw -eq 1 ] && result "SRV-113|양호|네트워크 접근통제 설정됨" || \
        result "SRV-113|취약|네트워크 접근통제 미설정 (방화벽 규칙 없음)"
}

# SRV-114
check_SRV114() {
    evd "SRV-114" "ls -la /etc/xinetd.d/ 2>/dev/null; grep -l 'disable.*no' /etc/xinetd.d/* 2>/dev/null"
    if [ ! -d /etc/xinetd.d ]; then
        result "SRV-114|양호|xinetd 미설치"; return
    fi
    local enabled=$(grep -l 'disable.*=.*no' /etc/xinetd.d/* 2>/dev/null | sed "s#.*/##")
    [ -n "$enabled" ] && result "SRV-114|수동확인|활성 xinetd 서비스: ${enabled} (필요 여부 확인)" || \
        result "SRV-114|양호|활성화된 xinetd 서비스 없음"
}

# SRV-116
check_SRV116() {
    evd "SRV-116" "systemctl is-active rsh.socket rlogin.socket rexec.socket 2>/dev/null; ps -ef 2>/dev/null | grep -E 'rshd|rlogind|rexecd|fingerd|in.fingerd' | grep -v grep"
    local vuln=""
    for svc in rsh rlogin rexec finger in.rshd in.rlogind in.rexecd in.fingerd; do
        is_running "$svc" && vuln="${vuln} ${svc}"
    done
    for sock in rsh.socket rlogin.socket rexec.socket; do
        systemctl is-active "$sock" >/dev/null 2>&1 && vuln="${vuln} ${sock}"
    done
    [ -n "$vuln" ] && result "SRV-116|취약|취약 서비스 실행 중:${vuln}" || \
        result "SRV-116|양호|rsh/rlogin/rexec/finger 서비스 미실행"
}

# SRV-117
check_SRV117() {
    evd "SRV-117" "auditctl -l 2>/dev/null | grep -iE 'useradd|userdel|passwd|groupadd|groupdel|shadow' | head -10; systemctl is-active auditd 2>/dev/null"
    if ! is_running auditd; then
        result "SRV-117|취약|auditd 미실행 (계정 감사 불가)"; return
    fi
    local rules=$(auditctl -l 2>/dev/null | grep -ciE 'useradd|userdel|passwd|groupadd|shadow')
    [ "${rules:-0}" -gt 0 ] 2>/dev/null && result "SRV-117|양호|계정 관련 감사 규칙 ${rules}개 설정됨" || \
        result "SRV-117|취약|계정 관련 감사 규칙 미설정 (useradd/userdel/passwd 추적 없음)"
}

# SRV-119
check_SRV119() {
    evd "SRV-119" "rpm -qa aide tripwire 2>/dev/null; dpkg -l aide tripwire 2>/dev/null | grep '^ii'; which aide tripwire ossec-control 2>/dev/null; aide --check 2>/dev/null | head -5"
    local tool=""
    command -v aide >/dev/null 2>&1 && tool="AIDE"
    command -v tripwire >/dev/null 2>&1 && tool="${tool} Tripwire"
    command -v ossec-control >/dev/null 2>&1 && tool="${tool} OSSEC"
    [ -n "$tool" ] && result "SRV-119|양호|파일 변경 감지 도구 설치됨 (${tool})" || \
        result "SRV-119|취약|파일 변경 감지 도구 미설치 (AIDE/Tripwire/OSSEC 없음)"
}

# SRV-120
check_SRV120() {
    evd "SRV-120" "getenforce 2>/dev/null; sestatus 2>/dev/null; aa-status 2>/dev/null | head -5; cat /etc/selinux/config 2>/dev/null | grep -v '^#'"
    local se=$(getenforce 2>/dev/null)
    local aa=$(aa-status 2>/dev/null | head -1)
    if [ "$se" = "Enforcing" ]; then
        result "SRV-120|양호|SELinux Enforcing 모드"
    elif [ "$se" = "Permissive" ]; then
        result "SRV-120|수동확인|SELinux Permissive 모드 (Enforcing 권장)"
    elif echo "$aa" | grep -qi "apparmor module is loaded"; then
        result "SRV-120|양호|AppArmor 활성화"
    else
        result "SRV-120|취약|SELinux/AppArmor 비활성 (보안 모듈 미적용)"
    fi
}

# SRV-123
check_SRV123() {
    evd "SRV-123" "grep -i Protocol /etc/ssh/sshd_config 2>/dev/null | grep -v '^#'; sshd -T 2>/dev/null | grep -i protocol"
    local proto=$(grep -v '^#' /etc/ssh/sshd_config 2>/dev/null | grep -i "^Protocol" | awk '{print $2}' | tail -1)
    if [ "$proto" = "1" ]; then
        result "SRV-123|취약|SSH Protocol 1 사용 (Protocol 2 필요)"
    elif [ "$proto" = "2" ] || [ -z "$proto" ]; then
        result "SRV-123|양호|SSH Protocol 2 사용 (${proto:-기본값})"
    else
        result "SRV-123|수동확인|SSH Protocol=${proto}"
    fi
}

# SRV-124
check_SRV124() {
    evd "SRV-124" "ls -la /etc/shadow 2>/dev/null; stat -c '%a %U' /etc/shadow 2>/dev/null"
    if [ ! -f /etc/shadow ]; then
        result "SRV-124|취약|/etc/shadow 미존재 (패스워드 파일 보호 불가)"; return
    fi
    local perm=$(get_perm "/etc/shadow") owner=$(get_owner "/etc/shadow")
    if [ "$owner" != "root" ]; then
        result "SRV-124|취약|/etc/shadow 소유자=${owner} (root 필요)"
    elif [ "${perm:-777}" -gt 640 ] 2>/dev/null; then
        result "SRV-124|취약|/etc/shadow 권한=${perm} (640 이하 필요)"
    else
        result "SRV-124|양호|/etc/shadow 소유자=${owner}, 권한=${perm}"
    fi
}

# SRV-126
check_SRV126() {
    evd "SRV-126" "grep -i MaxAuthTries /etc/ssh/sshd_config 2>/dev/null | grep -v '^#'"
    local val=$(grep -v '^#' /etc/ssh/sshd_config 2>/dev/null | grep -i "MaxAuthTries" | awk '{print $2}' | tail -1)
    if [ -z "$val" ]; then
        result "SRV-126|취약|MaxAuthTries 미설정 (기본값 6)"
    elif [ "$val" -le 5 ] 2>/dev/null; then
        result "SRV-126|양호|MaxAuthTries=${val}"
    else
        result "SRV-126|취약|MaxAuthTries=${val} (5 이하 권장)"
    fi
}

# SRV-128
check_SRV128() {
    evd "SRV-128" "ulimit -a 2>/dev/null; grep -v '^#' /etc/security/limits.conf 2>/dev/null | grep -v '^$' | head -15"
    local limits=$(grep -v '^#' /etc/security/limits.conf 2>/dev/null | grep -cv '^$')
    [ "${limits:-0}" -gt 0 ] 2>/dev/null && result "SRV-128|수동확인|limits.conf 설정 ${limits}줄 (적정성 확인)" || \
        result "SRV-128|수동확인|limits.conf 설정 없음 (기본값 사용 중)"
}

# SRV-129
check_SRV129() {
    evd "SRV-129" "ip link show 2>/dev/null | grep -i promisc; ifconfig -a 2>/dev/null | grep -i promisc"
    if ip link show 2>/dev/null | grep -qi "PROMISC"; then
        result "SRV-129|취약|Promiscuous 모드 인터페이스 발견"
    else
        result "SRV-129|양호|Promiscuous 모드 인터페이스 없음"
    fi
}

# SRV-130
check_SRV130() {
    evd "SRV-130" "ss -tlnp 2>/dev/null | head -30; netstat -tlnp 2>/dev/null | head -30"
    local cnt=$(ss -tlnp 2>/dev/null | grep -c "LISTEN")
    result "SRV-130|수동확인|리스닝 서비스 ${cnt:-미확인}개 (불필요 서비스 확인)"
}

# SRV-132
check_SRV132() {
    evd "SRV-132" "timedatectl 2>/dev/null; chronyc sources 2>/dev/null | head -5; ntpq -p 2>/dev/null | head -5; systemctl is-active chronyd ntpd 2>/dev/null"
    if command -v timedatectl >/dev/null 2>&1; then
        local sync=$(timedatectl 2>/dev/null | grep -ciE 'NTP sync.*yes|System clock sync.*yes')
        [ "${sync:-0}" -ge 1 ] && { result "SRV-132|양호|NTP 동기화 활성화"; return; }
    fi
    is_running chronyd && { result "SRV-132|양호|chrony 실행 중"; return; }
    is_running ntpd && { result "SRV-132|양호|ntpd 실행 중"; return; }
    result "SRV-132|취약|NTP 시간 동기화 미설정"
}

# SRV-136
check_SRV136() {
    evd "SRV-136" "systemctl is-active auditd 2>/dev/null; auditctl -l 2>/dev/null | head -20"
    if is_running auditd; then
        local rules=$(auditctl -l 2>/dev/null | wc -l)
        [ "${rules:-0}" -gt 0 ] 2>/dev/null && result "SRV-136|양호|auditd 활성, 규칙 ${rules}개" || \
            result "SRV-136|취약|auditd 실행 중이나 감사 규칙 없음"
    else
        result "SRV-136|취약|auditd 미실행 (감사 로그 미설정)"
    fi
}

# SRV-137
check_SRV137() {
    evd "SRV-137" "grep -E 'max_log_file|num_logs|log_file' /etc/audit/auditd.conf 2>/dev/null | grep -v '^#'; ls -la /etc/logrotate.d/audit* 2>/dev/null"
    if [ -f /etc/audit/auditd.conf ]; then
        local maxf=$(grep -i 'max_log_file ' /etc/audit/auditd.conf 2>/dev/null | grep -v '^#' | awk -F= '{print $2}' | tr -d ' ')
        local numl=$(grep -i 'num_logs' /etc/audit/auditd.conf 2>/dev/null | grep -v '^#' | awk -F= '{print $2}' | tr -d ' ')
        result "SRV-137|수동확인|auditd 로그 관리: max_log_file=${maxf:-미설정}MB, num_logs=${numl:-미설정}"
    else
        result "SRV-137|취약|auditd.conf 미존재 (감사 로그 백업 미설정)"
    fi
}

# SRV-138
check_SRV138() {
    evd "SRV-138" "ls -la /var/log/faillog /var/log/btmp /var/log/tallylog 2>/dev/null; faillog -u root 2>/dev/null; lastb 2>/dev/null | tail -5"
    local found=0
    for f in /var/log/faillog /var/log/btmp /var/log/tallylog; do
        [ -f "$f" ] && found=1
    done
    [ $found -eq 1 ] && result "SRV-138|양호|로그인 실패 기록 파일 존재" || \
        result "SRV-138|취약|로그인 실패 기록 파일 미존재 (faillog/btmp 없음)"
}

# SRV-139
check_SRV139() {
    evd "SRV-139" "auditctl -l 2>/dev/null | wc -l; auditctl -l 2>/dev/null | head -20"
    if ! is_running auditd; then
        result "SRV-139|취약|auditd 미실행"; return
    fi
    local rules=$(auditctl -l 2>/dev/null | wc -l)
    [ "${rules:-0}" -ge 5 ] 2>/dev/null && result "SRV-139|수동확인|감사 규칙 ${rules}개 (범위 적절성 확인)" || \
        result "SRV-139|취약|감사 규칙 부족 (${rules:-0}개)"
}

# SRV-140
check_SRV140() {
    evd "SRV-140" "ls -ld /var/log/audit/ 2>/dev/null; ls -la /var/log/audit/audit.log 2>/dev/null"
    if [ -d /var/log/audit ]; then
        local perm=$(get_perm "/var/log/audit") owner=$(get_owner "/var/log/audit")
        if [ "$owner" = "root" ] && [ "${perm:-777}" -le 750 ] 2>/dev/null; then
            result "SRV-140|양호|감사 로그 디렉터리 보호됨 (소유자=${owner}, 권한=${perm})"
        else
            result "SRV-140|취약|감사 로그 디렉터리 보호 미흡 (소유자=${owner}, 권한=${perm})"
        fi
    else
        result "SRV-140|취약|/var/log/audit 디렉터리 미존재"
    fi
}

# SRV-141
check_SRV141() {
    evd "SRV-141" "grep -iE 'max_log_file|max_log_file_action|space_left_action' /etc/audit/auditd.conf 2>/dev/null | grep -v '^#'; du -sh /var/log/audit/ 2>/dev/null"
    if [ -f /etc/audit/auditd.conf ]; then
        local maxf=$(grep -i 'max_log_file ' /etc/audit/auditd.conf 2>/dev/null | grep -v '^#' | awk -F= '{print $2}' | tr -d ' ')
        local action=$(grep -i 'max_log_file_action' /etc/audit/auditd.conf 2>/dev/null | grep -v '^#' | awk -F= '{print $2}' | tr -d ' ')
        result "SRV-141|수동확인|감사 로그 용량: max=${maxf:-미설정}MB, action=${action:-미설정}"
    else
        result "SRV-141|취약|auditd.conf 미존재"
    fi
}

# SRV-143
check_SRV143() {
    evd "SRV-143" "lsmod 2>/dev/null | grep -iE 'dccp|sctp|rds|tipc'; cat /etc/modprobe.d/*.conf 2>/dev/null | grep -iE 'dccp|sctp|rds|tipc'; sysctl net.ipv6.conf.all.disable_ipv6 2>/dev/null"
    local loaded=""
    for mod in dccp sctp rds tipc; do
        lsmod 2>/dev/null | grep -qi "$mod" && loaded="${loaded} ${mod}"
    done
    if [ -n "$loaded" ]; then
        result "SRV-143|취약|불필요 프로토콜 모듈 로드됨:${loaded}"
    else
        result "SRV-143|양호|불필요 프로토콜 모듈 미로드 (dccp/sctp/rds/tipc)"
    fi
}

# SRV-145
check_SRV145() {
    evd "SRV-145" "rpm -qa aide tripwire 2>/dev/null; dpkg -l aide tripwire 2>/dev/null | grep '^ii'; which aide tripwire 2>/dev/null; ls -la /var/lib/aide/aide.db* /var/lib/tripwire/*.twd 2>/dev/null"
    local tool=""
    command -v aide >/dev/null 2>&1 && tool="AIDE"
    command -v tripwire >/dev/null 2>&1 && tool="${tool} Tripwire"
    rpm -qa 2>/dev/null | grep -q "aide\|tripwire" && tool="${tool} (RPM)"
    [ -n "$tool" ] && result "SRV-145|양호|파일 무결성 점검 도구: ${tool}" || \
        result "SRV-145|취약|파일 무결성 점검 도구 미설치"
}

# SRV-146
check_SRV146() {
    evd "SRV-146" "rpm -qa clamav 2>/dev/null; dpkg -l clamav 2>/dev/null | grep '^ii'; which clamscan freshclam 2>/dev/null; systemctl is-active clamav-daemon 2>/dev/null"
    local av=""
    command -v clamscan >/dev/null 2>&1 && av="ClamAV"
    command -v sophos >/dev/null 2>&1 && av="${av} Sophos"
    is_running clamd && av="${av} (clamd 실행중)"
    [ -n "$av" ] && result "SRV-146|양호|안티바이러스 설치됨 (${av})" || \
        result "SRV-146|수동확인|안티바이러스 미설치 (ClamAV 등 미발견 - 별도 솔루션 확인)"
}

# SRV-148
check_SRV148() {
    evd "SRV-148" "grep -i password /boot/grub2/grub.cfg /boot/grub/grub.cfg 2>/dev/null | head -5; grep -i SINGLE /etc/sysconfig/init /etc/default/grub 2>/dev/null; cat /etc/securetty 2>/dev/null | head -5"
    local grub_pw=0
    for f in /boot/grub2/grub.cfg /boot/grub/grub.cfg /boot/efi/EFI/*/grub.cfg; do
        [ -f "$f" ] && grep -qi "password" "$f" 2>/dev/null && grub_pw=1
    done
    [ -f /boot/grub2/user.cfg ] && grep -qi "GRUB2_PASSWORD" /boot/grub2/user.cfg 2>/dev/null && grub_pw=1
    [ $grub_pw -eq 1 ] && result "SRV-148|양호|GRUB 패스워드 설정됨" || \
        result "SRV-148|취약|GRUB 패스워드 미설정 (부팅 보안 미흡)"
}

# SRV-149
check_SRV149() {
    evd "SRV-149" "useradd -D 2>/dev/null | grep INACTIVE; awk -F: '\$7!=\"\" && \$7 !~ /nologin|false/ {print \$1,\$7}' /etc/shadow 2>/dev/null | head -10"
    local inactive=$(useradd -D 2>/dev/null | grep "INACTIVE" | awk -F= '{print $2}')
    if [ "${inactive:-}" = "-1" ] || [ -z "$inactive" ]; then
        result "SRV-149|취약|INACTIVE 미설정 (비활성 계정 자동 잠금 없음)"
    elif [ "${inactive:-0}" -ge 0 ] 2>/dev/null; then
        result "SRV-149|양호|INACTIVE=${inactive}일 (비활성 계정 자동 잠금)"
    else
        result "SRV-149|수동확인|INACTIVE=${inactive} (설정 확인 필요)"
    fi
}

# SRV-150
check_SRV150() {
    evd "SRV-150" "awk -F: '\$3<500 && \$3!=0 && \$7 !~ /nologin|false|sync/ {print \$1,\$3,\$7}' /etc/passwd 2>/dev/null"
    local vuln="" min_uid=500
    [ -f /etc/debian_version ] && min_uid=1000
    while IFS=: read -r user _ uid _ _ _ shell; do
        [ "$user" = "root" ] && continue
        [ "${uid:-999}" -ge "$min_uid" ] 2>/dev/null && continue
        case "$shell" in */nologin|*/false|/bin/false|/sbin/nologin|*/sync|"") ;; *) vuln="${vuln} ${user}(${shell})" ;; esac
    done < /etc/passwd 2>/dev/null
    [ -n "$vuln" ] && result "SRV-150|취약|시스템 계정 셸 미제한:${vuln}" || \
        result "SRV-150|양호|시스템 계정 셸 제한됨 (nologin/false)"
}

# SRV-151
check_SRV151() {
    evd "SRV-151" "systemctl is-active usbguard 2>/dev/null; cat /etc/modprobe.d/*.conf 2>/dev/null | grep -i usb; lsmod 2>/dev/null | grep usb_storage"
    local restricted=0
    systemctl is-active usbguard >/dev/null 2>&1 && restricted=1
    grep -rqi 'install usb-storage /bin/true\|blacklist usb-storage' /etc/modprobe.d/ 2>/dev/null && restricted=1
    [ $restricted -eq 1 ] && result "SRV-151|양호|외부 매체 접근 제한 설정됨" || \
        result "SRV-151|수동확인|외부 매체 제한 미설정 (USB 차단 정책 확인)"
}

# SRV-152
check_SRV152() {
    evd "SRV-152" "which monit nagios zabbix_agentd ossec-control 2>/dev/null; systemctl is-active zabbix-agent nagios monit 2>/dev/null; ps -ef 2>/dev/null | grep -iE 'monit|nagios|zabbix|prometheus|node_exporter' | grep -v grep | head -5"
    local tools=""
    for t in monit nagios zabbix_agentd node_exporter prometheus; do
        is_running "$t" && tools="${tools} ${t}"
    done
    command -v monit >/dev/null 2>&1 && tools="${tools} monit(설치)"
    [ -n "$tools" ] && result "SRV-152|양호|모니터링 도구:${tools}" || \
        result "SRV-152|수동확인|프로세스 모니터링 도구 미발견 (별도 솔루션 확인)"
}

# SRV-153
check_SRV153() {
    evd "SRV-153" "sysctl net.ipv4.ip_forward net.ipv4.conf.all.accept_source_route net.ipv4.conf.all.accept_redirects net.ipv4.icmp_echo_ignore_broadcasts 2>/dev/null; rpm -qa --last 2>/dev/null | head -5"
    local vuln=""
    local fwd=$(sysctl -n net.ipv4.ip_forward 2>/dev/null)
    [ "$fwd" = "1" ] && vuln="${vuln} ip_forward=1"
    local srcrt=$(sysctl -n net.ipv4.conf.all.accept_source_route 2>/dev/null)
    [ "$srcrt" = "1" ] && vuln="${vuln} accept_source_route=1"
    [ -n "$vuln" ] && result "SRV-153|취약|하드닝 미흡:${vuln}" || \
        result "SRV-153|양호|시스템 하드닝 기본 설정 적절"
}

# SRV-154
check_SRV154() {
    evd "SRV-154" "sysctl net.ipv4.conf.all.accept_redirects net.ipv4.conf.all.send_redirects net.ipv4.conf.all.log_martians net.ipv4.conf.default.rp_filter net.ipv4.tcp_syncookies 2>/dev/null"
    local vuln=""
    local redir=$(sysctl -n net.ipv4.conf.all.accept_redirects 2>/dev/null)
    [ "$redir" = "1" ] && vuln="${vuln} accept_redirects=1"
    local sendr=$(sysctl -n net.ipv4.conf.all.send_redirects 2>/dev/null)
    [ "$sendr" = "1" ] && vuln="${vuln} send_redirects=1"
    local syncook=$(sysctl -n net.ipv4.tcp_syncookies 2>/dev/null)
    [ "$syncook" = "0" ] && vuln="${vuln} tcp_syncookies=0"
    [ -n "$vuln" ] && result "SRV-154|취약|커널 보안 파라미터 미흡:${vuln}" || \
        result "SRV-154|양호|커널 보안 파라미터 적절"
}

# SRV-155
check_SRV155() {
    evd "SRV-155" "systemctl is-active firewalld iptables ufw 2>/dev/null; iptables -L -n 2>/dev/null | head -15; ufw status 2>/dev/null"
    local fw=""
    systemctl is-active firewalld >/dev/null 2>&1 && fw="firewalld"
    systemctl is-active iptables >/dev/null 2>&1 && fw="${fw} iptables"
    ufw status 2>/dev/null | grep -qi "active" && fw="${fw} ufw"
    iptables -L -n 2>/dev/null | grep -qvE '^Chain|^target|^$' && [ -z "$fw" ] && fw="iptables(규칙존재)"
    [ -n "$fw" ] && result "SRV-155|양호|방화벽 활성:${fw}" || \
        result "SRV-155|취약|방화벽 비활성 (firewalld/iptables/ufw 모두 비활성)"
}

# SRV-156
check_SRV156() {
    evd "SRV-156" "rpm -qa --last 2>/dev/null | head -10; apt list --upgradable 2>/dev/null | head -10; yum updateinfo summary 2>/dev/null | head -5; stat -c '%y' /var/lib/rpm/Packages /var/lib/dpkg/status 2>/dev/null"
    local last_update=""
    if [ -f /var/lib/rpm/Packages ]; then
        last_update=$(stat -c '%y' /var/lib/rpm/Packages 2>/dev/null | cut -d' ' -f1)
    elif [ -f /var/lib/dpkg/status ]; then
        last_update=$(stat -c '%y' /var/lib/dpkg/status 2>/dev/null | cut -d' ' -f1)
    fi
    result "SRV-156|수동확인|마지막 패키지 변경: ${last_update:-미확인} (패치 주기/절차 확인)"
}

# SRV-157
check_SRV157() {
    evd "SRV-157" "crontab -l 2>/dev/null | grep -iE 'backup|rsync|tar|dump'; ls /etc/cron.d/ 2>/dev/null | grep -i backup; ls -la /etc/cron.daily/*backup* /etc/cron.weekly/*backup* 2>/dev/null"
    local bak=""
    crontab -l 2>/dev/null | grep -qiE 'backup|rsync|tar|dump' && bak="crontab"
    ls /etc/cron.d/ 2>/dev/null | grep -qi backup && bak="${bak} cron.d"
    ls /etc/cron.daily/*backup* /etc/cron.weekly/*backup* 2>/dev/null | grep -q . && bak="${bak} cron.daily/weekly"
    [ -n "$bak" ] && result "SRV-157|수동확인|백업 설정 발견: ${bak} (주기/범위 확인)" || \
        result "SRV-157|수동확인|백업 cron 미발견 (별도 백업 솔루션 확인)"
}

# SRV-159
check_SRV159() {
    evd "SRV-159" "grep -i Banner /etc/ssh/sshd_config 2>/dev/null | grep -v '^#'; grep -i ftpd_banner /etc/vsftpd/vsftpd.conf /etc/vsftpd.conf 2>/dev/null; postconf smtpd_banner 2>/dev/null"
    local checked=0 configured=0
    if grep -v '^#' /etc/ssh/sshd_config 2>/dev/null | grep -qi "^Banner"; then configured=$((configured+1)); fi
    checked=$((checked+1))
    if is_running vsftpd; then
        checked=$((checked+1))
        for cf in /etc/vsftpd/vsftpd.conf /etc/vsftpd.conf; do
            [ -f "$cf" ] && grep -qi "ftpd_banner" "$cf" 2>/dev/null && configured=$((configured+1))
        done
    fi
    [ $configured -ge 1 ] && result "SRV-159|양호|서비스 배너 설정됨 (${configured}개 서비스)" || \
        result "SRV-159|취약|서비스 배너 미설정 (버전 정보 노출 가능)"
}

# SRV-160
check_SRV160() {
    evd "SRV-160" "grep -E '^PASS_MAX_DAYS|^PASS_MIN_DAYS|^PASS_WARN_AGE|^PASS_MIN_LEN' /etc/login.defs 2>/dev/null"
    local max=$(grep -E '^\s*PASS_MAX_DAYS' /etc/login.defs 2>/dev/null | awk '{print $2}' | tail -1)
    local min=$(grep -E '^\s*PASS_MIN_DAYS' /etc/login.defs 2>/dev/null | awk '{print $2}' | tail -1)
    local warn=$(grep -E '^\s*PASS_WARN_AGE' /etc/login.defs 2>/dev/null | awk '{print $2}' | tail -1)
    local vuln=""
    [ "${max:-99999}" -gt 90 ] 2>/dev/null && vuln="${vuln} MAX_DAYS=${max:-미설정}"
    [ "${min:-0}" -lt 1 ] 2>/dev/null && vuln="${vuln} MIN_DAYS=${min:-0}"
    [ "${warn:-0}" -lt 7 ] 2>/dev/null && vuln="${vuln} WARN_AGE=${warn:-0}"
    [ -n "$vuln" ] && result "SRV-160|취약|패스워드 정책 미흡:${vuln}" || \
        result "SRV-160|양호|패스워드 정책 적절 (MAX=${max}, MIN=${min}, WARN=${warn})"
}

# SRV-162
check_SRV162() {
    evd "SRV-162" "grep -E '/tmp|/var/tmp|/home|/dev/shm' /etc/fstab 2>/dev/null; mount 2>/dev/null | grep -E '/tmp|/var/tmp|/dev/shm'"
    local vuln=""
    for mp in /tmp /var/tmp /dev/shm; do
        local opts=$(mount 2>/dev/null | grep " ${mp} " | awk '{print $NF}')
        if [ -n "$opts" ]; then
            echo "$opts" | grep -q "nosuid" || vuln="${vuln} ${mp}(nosuid 미설정)"
            if [ "$mp" = "/tmp" ] || [ "$mp" = "/var/tmp" ]; then
                echo "$opts" | grep -q "noexec" || vuln="${vuln} ${mp}(noexec 미설정)"
            fi
        fi
    done
    [ -n "$vuln" ] && result "SRV-162|취약|마운트 옵션 미흡:${vuln}" || \
        result "SRV-162|양호|마운트 옵션 적절 (nosuid/noexec 설정)"
}

# SRV-167
check_SRV167() {
    evd "SRV-167" "cat /etc/exports 2>/dev/null; grep -v '^#' /etc/samba/smb.conf 2>/dev/null | grep -iE 'path|share' | head -10; showmount -e localhost 2>/dev/null"
    local shares=""
    [ -f /etc/exports ] && [ -s /etc/exports ] && shares="NFS"
    grep -qi '\[.*\]' /etc/samba/smb.conf 2>/dev/null && shares="${shares} Samba"
    [ -n "$shares" ] && result "SRV-167|수동확인|공유 설정 존재: ${shares} (불필요 공유 확인)" || \
        result "SRV-167|양호|NFS/Samba 공유 미설정"
}

# SRV-168
check_SRV168() {
    evd "SRV-168" "ls -la /etc/passwd /etc/shadow /etc/group /etc/gshadow /etc/ssh/sshd_config /etc/login.defs 2>/dev/null"
    local vuln=""
    local -A expected=(["/etc/passwd"]=644 ["/etc/shadow"]=640 ["/etc/group"]=644 ["/etc/gshadow"]=640 ["/etc/ssh/sshd_config"]=600)
    for f in "${!expected[@]}"; do
        [ -f "$f" ] || continue
        local perm=$(get_perm "$f") owner=$(get_owner "$f")
        [ "$owner" != "root" ] && vuln="${vuln} ${f}(소유자=${owner})"
        [ "${perm:-777}" -gt "${expected[$f]}" ] 2>/dev/null && vuln="${vuln} ${f}(${perm})"
    done
    [ -n "$vuln" ] && result "SRV-168|취약|설정파일 권한 이상:${vuln}" || \
        result "SRV-168|양호|주요 설정파일 권한 적절"
}

# SRV-169
check_SRV169() {
    evd "SRV-169" "find /home /root -name '.forward' -o -name '.exrc' -o -name '.netrc' 2>/dev/null | head -10"
    local found=$(find /home /root -name '.forward' -o -name '.exrc' -o -name '.netrc' 2>/dev/null | head -10)
    [ -n "$found" ] && result "SRV-169|취약|불필요 사용자 환경파일 존재: $(echo $found | head -c 200)" || \
        result "SRV-169|양호|.forward/.exrc/.netrc 파일 미존재"
}

# SRV-172
check_SRV172() {
    evd "SRV-172" "cat /etc/issue 2>/dev/null; cat /etc/issue.net 2>/dev/null; uname -a 2>/dev/null"
    local vuln=0
    for f in /etc/issue /etc/issue.net; do
        [ -f "$f" ] || continue
        grep -qiE 'kernel|ubuntu|centos|red hat|debian|amazon|suse' "$f" 2>/dev/null && vuln=1
    done
    [ $vuln -eq 1 ] && result "SRV-172|취약|배너에 OS/커널 정보 노출 (/etc/issue)" || \
        result "SRV-172|양호|배너에 시스템 정보 미노출"
}

_PHASE="os"
# ── 실행 (SRV-001 ~ SRV-179 전체) ───────────────────────────────
check_SRV001
check_SRV002
check_SRV003
check_SRV004
check_SRV005
check_SRV006
check_SRV007
check_SRV008
check_SRV009
check_SRV010
check_SRV011
check_SRV012
check_SRV013
check_SRV014
check_SRV015
check_SRV016
check_SRV017
check_SRV018
check_SRV019
check_SRV020
check_SRV021
check_SRV022
check_SRV023
check_SRV024
check_SRV025
check_SRV026
check_SRV027
check_SRV028
check_SRV029
check_SRV030
check_SRV031
check_SRV032
check_SRV033
check_SRV034
check_SRV035
check_SRV036
check_SRV037
check_SRV038
check_SRV039
check_SRV040
check_SRV041
check_SRV042
check_SRV043
check_SRV044
check_SRV045
check_SRV046
check_SRV047
check_SRV048
check_SRV049
check_SRV050
check_SRV051
check_SRV052
check_SRV053
check_SRV054
check_SRV055
check_SRV056
check_SRV057
check_SRV058
check_SRV059
check_SRV060
check_SRV061
check_SRV062
check_SRV063
check_SRV064
check_SRV065
check_SRV066
check_SRV067
check_SRV068
check_SRV069
check_SRV070
check_SRV071
result "SRV-072|N-A|Windows 전용 항목 (Linux/Unix 해당 없음)"
check_SRV073
check_SRV074
check_SRV075
check_SRV076
check_SRV077
result "SRV-078|N-A|Windows Guest 계정 (Linux/Unix 해당 없음)"
result "SRV-079|N-A|Windows Everyone 권한 (Linux/Unix 해당 없음)"
result "SRV-080|N-A|Windows 프린터 드라이버 (Linux/Unix 해당 없음)"
check_SRV081
check_SRV082
check_SRV083
check_SRV084
check_SRV085
check_SRV086
check_SRV087
check_SRV088
check_SRV089
result "SRV-090|N-A|Windows 원격 레지스트리 (Linux/Unix 해당 없음)"
check_SRV091
check_SRV092
check_SRV093
check_SRV094
check_SRV095
check_SRV096
check_SRV097
check_SRV098
check_SRV099
check_SRV100
check_SRV101
check_SRV102
check_SRV103
check_SRV104
check_SRV105
check_SRV106
check_SRV107
check_SRV108
check_SRV109
check_SRV110
check_SRV111
check_SRV112
check_SRV113
check_SRV114
check_SRV115
check_SRV116
check_SRV117
check_SRV118
check_SRV119
check_SRV120
check_SRV121
check_SRV122
check_SRV123
check_SRV124
result "SRV-125|N-A|Windows 화면 보호기 (Linux/Unix 해당 없음)"
check_SRV126
check_SRV127
check_SRV128
check_SRV129
check_SRV130
check_SRV131
check_SRV132
check_SRV133
check_SRV134
check_SRV135
check_SRV136
check_SRV137
check_SRV138
check_SRV139
check_SRV140
check_SRV141
check_SRV142
check_SRV143
check_SRV144
check_SRV145
check_SRV146
check_SRV147
check_SRV148
check_SRV149
check_SRV150
check_SRV151
check_SRV152
check_SRV153
check_SRV154
check_SRV155
check_SRV156
check_SRV157
check_SRV158
check_SRV159
check_SRV160
check_SRV161
check_SRV162
check_SRV163
check_SRV164
check_SRV165
check_SRV166
check_SRV167
check_SRV168
check_SRV169
check_SRV170
check_SRV171
check_SRV172
check_SRV173
check_SRV174
check_SRV175
check_SRV176
check_SRV177
result "SRV-178|N-A|Windows 개인 키 passphrase (Linux/Unix 해당 없음)"
check_SRV179

# ════════════════════════════════════════════════════════════════
# [2] 기존 웹 점검 — 평가기준 일치 항목(_WEB_KEEP)만 반영, 나머지는 REF-(참고)
# ════════════════════════════════════════════════════════════════
_PHASE="web"
if [ -n "$WEB_SRV$WAS_SRV" ]; then
# ── 웹서버 전용 점검 ─────────────────────────────────────────────

# WST-031: 디렉토리 리스팅 방지
check_dir_listing() {
    evd_file "WST-031" "${APACHE_CONF:-/etc/nginx/nginx.conf}"
    case "$WEB_SRV" in
    apache)
        [ -z "$APACHE_CONF" ] && { result "WST-031|수동확인|Apache 설정파일 미탐지"; return; }
        # 설정 파일 및 포함 디렉토리 검색
        confdir=$(dirname "$APACHE_CONF")
        if grep -r "Options.*Indexes" "$confdir"/ 2>/dev/null | grep -qv "^#"; then
            listing=$(grep -r "Options.*Indexes" "$confdir"/ 2>/dev/null | grep -v "^#" | head -1)
            result "WST-031|취약|디렉토리 리스팅 활성: ${listing}"
        else
            result "WST-031|양호|디렉토리 리스팅 비활성화 (Options -Indexes)"
        fi ;;
    nginx)
        if grep -r "autoindex on" /etc/nginx/ 2>/dev/null | grep -qv "^#"; then
            result "WST-031|취약|Nginx autoindex on 설정됨"
        else
            result "WST-031|양호|Nginx autoindex off (기본 또는 명시)"
        fi ;;
    webtob)
        # WebtoB: DIRECTORY.INDEX 설정
        wt_cfg=$(find /usr/local/tmax /opt/tmax -name "*.m" 2>/dev/null | head -1)
        if [ -n "$wt_cfg" ] && grep -qi "DIRECTORY.INDEX" "$wt_cfg" 2>/dev/null; then
            result "WST-031|양호|WebtoB DIRECTORY.INDEX 설정됨"
        else
            result "WST-031|수동확인|WebtoB 디렉토리 리스팅 수동 확인"
        fi ;;
    *) result "WST-031|N-A|웹서버 미탐지" ;;
    esac
}
check_dir_listing

# WST-033: 상위 디렉토리 접근 제한
check_dir_traverse() {
    evd "WST-033" "grep -rE 'AllowOverride|FollowSymLinks' ${APACHE_CONF:-/etc/nginx/nginx.conf} $(dirname ${APACHE_CONF:-/etc/nginx/nginx.conf}) 2>/dev/null | grep -v '^#' | head -5"
    case "$WEB_SRV" in
    apache)
        if grep -r "AllowOverride\s*All\|Options.*FollowSymLinks" "$APACHE_CONF" $(dirname "$APACHE_CONF") 2>/dev/null | grep -qv "^#"; then
            result "WST-033|수동확인|AllowOverride All 또는 FollowSymLinks 설정 - 상위 디렉토리 접근 수동 확인"
        else
            result "WST-033|양호|상위 디렉토리 접근 제한 설정됨"
        fi ;;
    nginx)
        result "WST-033|수동확인|Nginx 상위 디렉토리 접근 제한 수동 확인";;
    *) result "WST-033|N-A|웹서버 미탐지" ;;
    esac
}
check_dir_traverse

# WST-036: 웹 서비스 프로세스 권한
check_web_user() {
    evd "WST-036" "ps -ef 2>/dev/null | grep -E 'httpd|apache|nginx' | grep -v grep | head -3"
    case "$WEB_SRV" in
    apache)
        web_user=$(grep -hiE "^\s*User\s" "$APACHE_CONF" $(find $(dirname "$APACHE_CONF") -name "*.conf") 2>/dev/null | grep -v "^#" | awk '{print $2}' | head -1)
        case "$web_user" in \$*)
            _uv=$(echo "$web_user" | tr -d '${}')
            web_user=$(grep -hE "^\s*(export\s+)?${_uv}=" /etc/apache2/envvars /etc/sysconfig/httpd 2>/dev/null | tail -1 | cut -d= -f2 | tr -d "\"' ") ;;
        esac
        if [ -z "$web_user" ]; then
            web_user=$(ps -ef 2>/dev/null | grep -E "httpd|apache" | grep -v "root\|grep" | awk '{print $1}' | head -1)
        fi
        if [ "$web_user" = "root" ]; then
            result "WST-036|취약|Apache root 계정으로 실행됨"
        elif [ -n "$web_user" ]; then
            result "WST-036|양호|Apache 웹 사용자: ${web_user} (non-root)"
        else
            result "WST-036|수동확인|Apache 실행 계정 수동 확인"
        fi ;;
    nginx)
        nuser=$(grep -E "^\s*user\s" /etc/nginx/nginx.conf 2>/dev/null | awk '{print $2}' | tr -d ';')
        if [ "$nuser" = "root" ]; then
            result "WST-036|취약|Nginx root 계정으로 실행됨"
        elif [ -n "$nuser" ]; then
            result "WST-036|양호|Nginx 사용자: ${nuser}"
        else
            result "WST-036|수동확인|Nginx 실행 계정 수동 확인"
        fi ;;
    *) result "WST-036|N-A|웹서버 미탐지" ;;
    esac
}
check_web_user

# WST-039: 불필요 웹 서비스 비활성화
evd "WST-039" "httpd -M 2>/dev/null | grep -iE 'status|info|cgi|dav' || nginx -V 2>&1 | grep -oE 'with-[^ ]+' | head -10"
result "WST-039|수동확인|불필요 웹 서비스(mod_status, mod_info 등) 수동 확인 필요"

# WST-044: 기본 계정(아이디/비밀번호) 변경
evd "WST-044" "ls -la ${TOMCAT_HOME:-/opt/tomcat}/conf/tomcat-users.xml 2>/dev/null; grep -v '<!--' ${TOMCAT_HOME:-/opt/tomcat}/conf/tomcat-users.xml 2>/dev/null | grep -i 'user '"
result "WST-044|수동확인|웹서버/WAS 기본 관리 계정 변경 여부 수동 확인"

# WST-048: DNS Zone Transfer 제한
evd "WST-048" "grep -i 'allow-transfer' /etc/named.conf /etc/bind/named.conf 2>/dev/null"
is_running named && {
    for conf in /etc/named.conf /etc/bind/named.conf; do
        [ -f "$conf" ] || continue
        grep -q "allow-transfer.*none" "$conf" 2>/dev/null && \
            result "WST-048|양호|Zone Transfer 차단 설정됨" && break || \
            result "WST-048|취약|Zone Transfer 제한 미설정"
        break
    done
} || result "WST-048|N-A|DNS 미실행"

# WST-100: /dev 불필요 파일
evd "WST-100" "find /dev -type f 2>/dev/null | head -10"
cnt=$(find /dev -type f 2>/dev/null | wc -l)
[ "${cnt:-0}" -gt 5 ] 2>/dev/null && result "WST-100|수동확인|/dev에 일반 파일 ${cnt}개" || result "WST-100|양호|/dev 불필요 파일 없음"

# WST-101: 불필요 네트워크 모니터링 서비스 (SNMP)
evd "WST-101" "grep -iE '^rouser|^rwuser|^community' /etc/snmpd.conf /etc/snmp/snmpd.conf 2>/dev/null"
snmp_v=""
for conf in /etc/snmpd.conf /etc/snmp/snmpd.conf; do
    [ -f "$conf" ] || continue
    grep -qiE "^rouser|^rwuser" "$conf" && snmp_v="v3" && break
    grep -qiE "^community" "$conf" && snmp_v="v2c" && break
done
case "$snmp_v" in
v3) result "WST-101|양호|SNMP v3 사용 중" ;;
v2c) result "WST-101|취약|SNMP v1/v2c community 사용 중" ;;
*) is_running snmpd && result "WST-101|수동확인|SNMP 실행 중 버전 확인 필요" || result "WST-101|양호|SNMP 미실행" ;;
esac

# WST-102: 웹 서비스 정보 노출 방지
check_server_info() {
    evd "WST-102" "httpd -v 2>/dev/null || nginx -v 2>&1"
    case "$WEB_SRV" in
    apache)
        confdir=$(dirname "$APACHE_CONF")
        token=$(grep -r "ServerTokens" "$confdir"/ 2>/dev/null | grep -v "^#" | head -1)
        sig=$(grep -r "ServerSignature" "$confdir"/ 2>/dev/null | grep -v "^#" | head -1)
        if echo "$token" | grep -qi "Prod\|Min"; then
            result "WST-102|양호|Apache ServerTokens=$(echo "$token" | awk '{print $2}')"
        elif echo "$token" | grep -qi "Full\|OS\|All\|Major\|Minor"; then
            result "WST-102|취약|Apache ServerTokens=$(echo "$token" | awk '{print $2}') (버전 노출)"
        else
            result "WST-102|수동확인|ServerTokens 설정 수동 확인"
        fi ;;
    nginx)
        if grep -r "server_tokens off" /etc/nginx/ 2>/dev/null | grep -qv "^#"; then
            result "WST-102|양호|Nginx server_tokens off 설정됨"
        else
            result "WST-102|취약|Nginx server_tokens off 미설정 (버전 노출)"
        fi ;;
    webtob)
        result "WST-102|수동확인|WebtoB 서버 정보 노출 방지 수동 확인" ;;
    *) result "WST-102|N-A|웹서버 미탐지" ;;
    esac
}
check_server_info

# WST-121: 프록시 설정 제한
check_proxy() {
    evd "WST-121" "grep -rE 'ProxyRequests|proxy_pass' ${APACHE_CONF:-/etc/nginx/nginx.conf} $(dirname ${APACHE_CONF:-/etc/nginx/nginx.conf}) /etc/nginx/ 2>/dev/null | grep -v '^#' | head -5"
    case "$WEB_SRV" in
    apache)
        confdir=$(dirname "$APACHE_CONF")
        if grep -r "mod_proxy\|ProxyRequests On" "$confdir"/ 2>/dev/null | grep -qv "^#"; then
            proxy=$(grep -r "ProxyRequests" "$confdir"/ 2>/dev/null | grep -v "^#" | head -1)
            echo "$proxy" | grep -qi "Off" && result "WST-121|양호|ProxyRequests Off 설정됨" || \
                result "WST-121|취약|ProxyRequests On - 오픈 프록시 가능"
        else
            result "WST-121|양호|mod_proxy 미사용 또는 ProxyRequests Off"
        fi ;;
    *) result "WST-121|수동확인|프록시 설정 수동 확인" ;;
    esac
}
check_proxy

# WST-122: SSI(Server Side Include) 제한
check_ssi() {
    evd "WST-122" "grep -rE 'Includes|AddHandler.*shtml' ${APACHE_CONF:-/etc/nginx/nginx.conf} $(dirname ${APACHE_CONF:-/etc/nginx/nginx.conf}) 2>/dev/null | grep -v '^#' | head -5"
    case "$WEB_SRV" in
    apache)
        confdir=$(dirname "$APACHE_CONF")
        if grep -r "Options.*Includes\|AddHandler.*shtml" "$confdir"/ 2>/dev/null | grep -qv "^#"; then
            result "WST-122|취약|SSI(Includes) 활성화됨"
        else
            result "WST-122|양호|SSI 비활성 또는 미설정"
        fi ;;
    *) result "WST-122|수동확인|SSI 설정 수동 확인" ;;
    esac
}
check_ssi

# WST-123: 기본 에러 페이지 노출 방지
check_error_page() {
    evd "WST-123" "grep -rE 'ErrorDocument|error_page' ${APACHE_CONF:-/etc/nginx/nginx.conf} $(dirname ${APACHE_CONF:-/etc/nginx/nginx.conf}) /etc/nginx/ 2>/dev/null | grep -v '^#' | head -5"
    case "$WEB_SRV" in
    apache)
        confdir=$(dirname "$APACHE_CONF")
        ep=$(grep -r "ErrorDocument" "$confdir"/ 2>/dev/null | grep -v "^#" | head -1)
        [ -n "$ep" ] && result "WST-123|양호|ErrorDocument 설정됨: ${ep}" || \
            result "WST-123|취약|ErrorDocument 미설정 (기본 에러 페이지 노출)"  ;;
    nginx)
        ep=$(grep -r "error_page" /etc/nginx/ 2>/dev/null | grep -v "^#" | head -1)
        [ -n "$ep" ] && result "WST-123|양호|error_page 설정됨" || result "WST-123|취약|Nginx error_page 미설정" ;;
    *) result "WST-123|수동확인|에러 페이지 설정 수동 확인" ;;
    esac
}
check_error_page

# WST-124: LDAP 알고리즘 제한
evd "WST-124" "grep -rE 'ldap|LDAP' ${APACHE_CONF:-/dev/null} /etc/nginx/ ${TOMCAT_HOME:-/dev/null}/conf/ 2>/dev/null | grep -v '^#' | head -5"
result "WST-124|수동확인|웹 서비스 LDAP 연동 시 알고리즘 설정 수동 확인"

# WST-125: 업로드 경로/권한 설정
check_upload() {
    evd "WST-125" "find ${TOMCAT_HOME:-/opt/tomcat}/webapps /var/www/html -type d -name 'upload*' -o -name 'attach*' -o -name 'file*' 2>/dev/null | head -5"
    case "$WAS_SRV" in
    tomcat)
        [ -n "$TOMCAT_HOME" ] || { result "WST-125|수동확인|Tomcat 홈 미탐지 - 수동 확인"; return; }
        # webapps 내 upload 디렉토리 탐색
        upload_dirs=$(find "$TOMCAT_HOME/webapps" -type d -name "upload*" -o -name "attach*" 2>/dev/null | head -3)
        if [ -n "$upload_dirs" ]; then
            result "WST-125|수동확인|업로드 디렉토리 발견: $(echo "$upload_dirs" | head -1) - 스크립트 실행 권한 수동 확인"
        else
            result "WST-125|수동확인|업로드 경로 및 권한 수동 확인"
        fi ;;
    *) result "WST-125|수동확인|업로드 경로/권한 수동 확인" ;;
    esac
}
check_upload

# WST-126: EoS 시스템 교체 (자동 판정)
evd "WST-126" "httpd -v 2>/dev/null; nginx -v 2>&1; cat ${TOMCAT_HOME:-/dev/null}/RELEASE-NOTES 2>/dev/null | head -3"
EOS_SCRIPT="$(dirname "$0")/eos_checker.py"
[ -f "$EOS_SCRIPT" ] || EOS_SCRIPT="$(dirname "$0")/../converter/eos_checker.py"   # 저장소 구조 그대로 실행 시
check_webwas_eos() {
    local product="$1" version="$2"
    [ -f "$EOS_SCRIPT" ] || { result "WST-126|수동확인|eos_checker.py 없음"; return; }
    local _eo; _eo=$(python3 "$EOS_SCRIPT" "$product" "$version" 2>/dev/null)
    eos_result=$(echo "$_eo" | grep "^결과:" | awk '{print $2}')
    eos_desc=$(echo "$_eo" | grep "^설명:" | cut -d: -f2- | sed "s/^ *//;s/ *$//")
    result "WST-126|${eos_result:-수동확인}|${eos_desc:-EoS 판정 실패}"
}
case "$WEB_SRV" in
apache)
    ver=$(httpd -v 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || apache2 -v 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
    [ -n "$ver" ] && check_webwas_eos "apache" "$ver" || result "WST-126|수동확인|Apache 버전 확인 실패" ;;
nginx)
    ver=$(nginx -v 2>&1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
    [ -n "$ver" ] && check_webwas_eos "nginx" "$ver" || result "WST-126|수동확인|Nginx 버전 확인 실패" ;;
*)
    result "WST-126|수동확인|웹서버 버전 수동 확인 (Apache/Nginx/WebtoB/IIS)" ;;
esac
case "$WAS_SRV" in
tomcat)
    ver=$(find "$TOMCAT_HOME" /opt /usr/local -name "RELEASE-NOTES" 2>/dev/null | xargs grep -h "Apache Tomcat Version" 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
    [ -n "$ver" ] && check_webwas_eos "tomcat" "$ver" || result "WST-126|수동확인|Tomcat 버전 확인 필요" ;;
jeus)
    result "WST-126|수동확인|JEUS 버전 수동 확인 (jeus --version)" ;;
esac
[ -n "$WEB_SRV" ] && {   # 버전 정보는 증적에만 기록 (결과 파일에 섞이지 않도록)
    case "$WEB_SRV" in
    apache) httpd -v 2>/dev/null | head -1 || apache2 -v 2>/dev/null | head -1 ;;
    nginx)  nginx -v 2>&1 ;;
    esac
} >> "$_EVD" 2>&1
[ -n "$WAS_SRV" ] && {
    case "$WAS_SRV" in
    tomcat)
        [ -n "$TOMCAT_HOME" ] && cat "$TOMCAT_HOME/RELEASE-NOTES" 2>/dev/null | head -2 || \
            find /opt /usr/local -name "catalina.sh" 2>/dev/null | head -1 | xargs -I{} sh -c '. {}; echo "Tomcat version check"' 2>/dev/null
        ;;
    esac
} >> "$_EVD" 2>&1

# ── 자동 점검 추가 항목 ───────────────────────────────────────────

# WST-003: 불필요한 SMTP 서비스 비활성화
evd "WST-003" "ps -ef 2>/dev/null | grep -E 'sendmail|postfix|exim' | grep -v grep"
is_running sendmail || is_running postfix || is_running exim || is_running exim4 && \
    result "WST-003|취약|SMTP 서비스 실행 중 (불필요 시 비활성화 권고)" || \
    result "WST-003|양호|SMTP 서비스 미실행"

# WST-010: FTP root 접속 제한 (/etc/ftpusers)
evd "WST-010" "grep '^root' /etc/ftpusers 2>/dev/null"
if [ -f /etc/ftpusers ]; then
    grep -q "^root$" /etc/ftpusers 2>/dev/null && \
        result "WST-010|양호|/etc/ftpusers에 root 등록됨" || \
        result "WST-010|취약|/etc/ftpusers에 root 미등록"
else
    is_running vsftpd || is_running proftpd || is_running pure-ftpd && \
        result "WST-010|취약|FTP 실행 중이나 /etc/ftpusers 없음" || \
        result "WST-010|N-A|FTP 서비스 미실행"
fi

# WST-012: Anonymous FTP 접속 제한
evd "WST-012" "grep -i 'anonymous_enable' /etc/vsftpd.conf /etc/vsftpd/vsftpd.conf 2>/dev/null"
anon_ftp=""
for conf in /etc/vsftpd.conf /etc/vsftpd/vsftpd.conf /etc/proftpd.conf /etc/proftpd/proftpd.conf; do
    [ -f "$conf" ] || continue
    if grep -qi "^anonymous_enable\s*=\s*yes\|<Anonymous\s" "$conf" 2>/dev/null; then
        anon_ftp="${conf}"
    fi
    break
done
[ -n "$anon_ftp" ] && result "WST-012|취약|Anonymous FTP 허용 설정: ${anon_ftp}" || \
    { is_running vsftpd || is_running proftpd && \
        result "WST-012|양호|Anonymous FTP 비허용 (설정 확인됨)" || \
        result "WST-012|N-A|FTP 서비스 미실행"; }

# WST-013: NFS 접근통제 (wildcard 허용 여부)
evd "WST-013" "cat /etc/exports 2>/dev/null"
if [ -f /etc/exports ]; then
    wild=$(grep -v "^#" /etc/exports 2>/dev/null | grep -E "\*|\s0\.0\.0\.0")
    [ -n "$wild" ] && result "WST-013|취약|NFS wildcard 허용: $(echo "$wild" | head -1)" || \
        result "WST-013|양호|NFS 접근 IP 제한 설정됨"
else
    result "WST-013|N-A|/etc/exports 없음 (NFS 미사용)"
fi

# WST-014: NFS 서비스 비활성화
evd "WST-014" "ps -ef 2>/dev/null | grep -E 'nfsd|nfs-server' | grep -v grep"
is_running nfsd || is_running nfs-server || is_running nfs && \
    result "WST-014|취약|NFS 서비스 실행 중 (불필요 시 비활성화 권고)" || \
    result "WST-014|양호|NFS 서비스 미실행"

# WST-015: RPC 서비스 비활성화
evd "WST-015" "ps -ef 2>/dev/null | grep -E 'rpcbind|portmap' | grep -v grep"
is_running rpcbind || is_running portmap && \
    result "WST-015|취약|RPC(rpcbind/portmap) 서비스 실행 중 (불필요 시 비활성화 권고)" || \
    result "WST-015|양호|RPC 서비스 미실행"

# WST-019: 비밀번호 미설정(빈 암호) 계정
evd "WST-019" "awk -F: '(\$2==\"\"||  \$2==\"!!\"|| \$2==\"!\") && \$1!=\"root\" {print \$1}' /etc/shadow 2>/dev/null"
empty_pw=$(awk -F: '($2==""|$2=="!!"||$2=="!") && $1!="root" {print $1}' /etc/shadow 2>/dev/null | head -5)
[ -n "$empty_pw" ] && result "WST-019|취약|비밀번호 미설정 계정: $(echo "$empty_pw" | _csv)" || \
    result "WST-019|양호|비밀번호 미설정 계정 없음"

# WST-022: hosts.equiv / .rhosts 설정 제한
evd "WST-022" "ls -la /etc/hosts.equiv /root/.rhosts 2>/dev/null"
found_r=""
[ -f /etc/hosts.equiv ] && found_r="${found_r} /etc/hosts.equiv"
for home in $(awk -F: '$3>=1000 && $3<65534 {print $6}' /etc/passwd 2>/dev/null) /root; do
    [ -f "${home}/.rhosts" ] && found_r="${found_r} ${home}/.rhosts"
done
[ -n "$found_r" ] && result "WST-022|취약|r-명령 신뢰 파일 존재:${found_r}" || \
    result "WST-022|양호|hosts.equiv/.rhosts 없음"

# WST-029: 취약한 서비스 비활성화 (Telnet, rsh, rlogin, rexec)
evd "WST-029" "ps -ef 2>/dev/null | grep -E 'telnet|rsh|rlogin|rexec' | grep -v grep"
vuln_svc=""
for svc in telnet rsh rlogin rexec rshd rlogind; do
    is_running "$svc" && vuln_svc="${vuln_svc} ${svc}"
done
[ -n "$vuln_svc" ] && result "WST-029|취약|취약 서비스 실행 중:${vuln_svc}" || \
    result "WST-029|양호|취약 서비스(telnet/rsh/rlogin/rexec) 미실행"

# WST-030: 취약한 FTP 서비스 비활성화 (tftp, atftpd)
evd "WST-030" "ps -ef 2>/dev/null | grep -E 'tftp|atftpd|tftpd' | grep -v grep"
is_running tftp || is_running atftpd || is_running tftpd && \
    result "WST-030|취약|취약 FTP(tftp/atftpd) 서비스 실행 중" || \
    result "WST-030|양호|취약 FTP 서비스 미실행"

# WST-059: Tomcat Shutdown 포트 비활성화
evd_file "WST-059" "${TOMCAT_HOME:-/opt/tomcat}/conf/server.xml"
if [ -n "$TOMCAT_HOME" ] && [ -f "$TOMCAT_HOME/conf/server.xml" ]; then
    if grep -q 'port="-1"' "$TOMCAT_HOME/conf/server.xml" 2>/dev/null; then
        result "WST-059|양호|Tomcat Shutdown 포트 비활성화됨 (port=-1)"
    else
        _shutdown_port=$(grep '<Server ' "$TOMCAT_HOME/conf/server.xml" 2>/dev/null | grep -oE 'port="[0-9]+"' | grep -oE '[0-9]+' | head -1)
        result "WST-059|취약|Tomcat Shutdown 포트 활성화됨 (port=${_shutdown_port:-?}) - -1로 변경 권고"
    fi
elif [ "$WAS_SRV" = "tomcat" ]; then
    result "WST-059|수동확인|Tomcat 홈 미탐지 - Shutdown 포트 수동 확인"
else
    result "WST-059|N-A|WAS(Tomcat) 미탐지"
fi

# WST-060: Tomcat 기본 애플리케이션 제거 (manager, host-manager, examples, docs)
evd "WST-060" "ls -d ${TOMCAT_HOME:-/opt/tomcat}/webapps/manager ${TOMCAT_HOME:-/opt/tomcat}/webapps/examples ${TOMCAT_HOME:-/opt/tomcat}/webapps/docs 2>/dev/null"
if [ -n "$TOMCAT_HOME" ] && [ -d "$TOMCAT_HOME/webapps" ]; then
    _exist_apps=""
    for _app in manager host-manager examples docs ROOT; do
        [ -d "$TOMCAT_HOME/webapps/$_app" ] && _exist_apps="${_exist_apps} ${_app}"
    done
    if [ -n "$_exist_apps" ]; then
        result "WST-060|취약|Tomcat 기본 애플리케이션 존재:${_exist_apps} - 운영 서버에서 제거 권고"
    else
        result "WST-060|양호|Tomcat 기본 애플리케이션(manager/examples/docs) 제거됨"
    fi
elif [ "$WAS_SRV" = "tomcat" ]; then
    result "WST-060|수동확인|Tomcat webapps 디렉토리 미탐지 - 수동 확인"
else
    result "WST-060|N-A|WAS(Tomcat) 미탐지"
fi

# ── 고도화 자동 점검 항목 ─────────────────────────────────────────

# WST-AUTO-001: TLS 1.0/1.1 비활성화 확인
check_tls_version() {
    evd "WST-034" "grep -rE 'SSLProtocol|ssl_protocols' ${APACHE_CONF:-/dev/null} ${APACHE_CONF:+$(dirname "$APACHE_CONF")} /etc/nginx/ 2>/dev/null | grep -v '^#' | head -5"
    case "$WEB_SRV" in
    apache)
        confdir=$(dirname "$APACHE_CONF")
        proto=$(grep -r "SSLProtocol" "$confdir"/ 2>/dev/null | grep -v "^#" | head -1)
        if [ -n "$proto" ]; then
            echo "$proto" | grep -qiE "TLSv1\b|TLSv1\.0|SSLv3" && \
                result "WST-034|취약|취약한 TLS 버전 허용: ${proto}" || \
                result "WST-034|양호|TLS 프로토콜 설정: $(echo "$proto" | awk '{for(i=2;i<=NF;i++) printf $i" "}')"
        else
            result "WST-034|수동확인|SSLProtocol 설정 수동 확인"
        fi ;;
    nginx)
        proto=$(grep -r "ssl_protocols" /etc/nginx/ 2>/dev/null | grep -v "^#" | head -1)
        if [ -n "$proto" ]; then
            echo "$proto" | grep -qiE "TLSv1\b|TLSv1\.0|SSLv3" && \
                result "WST-034|취약|취약한 TLS 버전 허용: ${proto}" || \
                result "WST-034|양호|TLS 프로토콜 설정: $(echo "$proto" | awk '{for(i=2;i<=NF;i++) printf $i" "}')"
        else
            result "WST-034|수동확인|ssl_protocols 설정 수동 확인"
        fi ;;
    *) result "WST-034|수동확인|TLS 프로토콜 버전 수동 확인" ;;
    esac
}
check_tls_version

# WST-AUTO-002: HTTP 보안 헤더 설정 확인
check_security_headers() {
    evd "WST-035" "grep -rEi 'X-Content-Type|X-Frame-Options|Strict-Transport|Content-Security-Policy' ${APACHE_CONF:-/dev/null} ${APACHE_CONF:+$(dirname "$APACHE_CONF")} /etc/nginx/ 2>/dev/null | grep -v '^#' | head -5"
    case "$WEB_SRV" in
    apache)
        confdir=$(dirname "$APACHE_CONF")
        _missing=""
        grep -rqi "X-Content-Type-Options" "$confdir"/ 2>/dev/null || _missing="${_missing} X-Content-Type-Options"
        grep -rqi "X-Frame-Options\|Content-Security-Policy.*frame-ancestors" "$confdir"/ 2>/dev/null || _missing="${_missing} X-Frame-Options"
        grep -rqi "Strict-Transport-Security" "$confdir"/ 2>/dev/null || _missing="${_missing} HSTS"
        [ -n "$_missing" ] && result "WST-035|취약|HTTP 보안 헤더 미설정:${_missing}" || \
            result "WST-035|양호|HTTP 보안 헤더 설정됨 (X-Content-Type-Options, X-Frame-Options, HSTS)"
        ;;
    nginx)
        _missing=""
        grep -rqi "X-Content-Type-Options" /etc/nginx/ 2>/dev/null || _missing="${_missing} X-Content-Type-Options"
        grep -rqi "X-Frame-Options\|Content-Security-Policy.*frame-ancestors" /etc/nginx/ 2>/dev/null || _missing="${_missing} X-Frame-Options"
        grep -rqi "Strict-Transport-Security" /etc/nginx/ 2>/dev/null || _missing="${_missing} HSTS"
        [ -n "$_missing" ] && result "WST-035|취약|HTTP 보안 헤더 미설정:${_missing}" || \
            result "WST-035|양호|HTTP 보안 헤더 설정됨"
        ;;
    *) result "WST-035|수동확인|HTTP 보안 헤더 수동 확인" ;;
    esac
}
check_security_headers

# WST-AUTO-003: Tomcat AJP 커넥터 노출 확인 (Ghostcat CVE-2020-1938)
check_tomcat_ajp() {
    [ -z "$TOMCAT_HOME" ] && return
    evd "WST-037" "grep -v '<!--' ${TOMCAT_HOME}/conf/server.xml 2>/dev/null | grep 'AJP'"
    [ ! -f "$TOMCAT_HOME/conf/server.xml" ] && return
    if grep -v "<!--" "$TOMCAT_HOME/conf/server.xml" 2>/dev/null | grep -q 'protocol="AJP'; then
        _ajp_secret=$(grep -v "<!--" "$TOMCAT_HOME/conf/server.xml" 2>/dev/null | grep 'protocol="AJP' | grep -qi "secret\|requiredSecret")
        _ajp_addr=$(grep -v "<!--" "$TOMCAT_HOME/conf/server.xml" 2>/dev/null | grep 'protocol="AJP' | grep -oE 'address="[^"]*"' | head -1)
        if echo "$_ajp_addr" | grep -qE '0\.0\.0\.0|::'; then
            result "WST-037|취약|Tomcat AJP 전체 IP 바인딩 (Ghostcat 위험) - address=localhost 및 secret 설정 필요"
        elif grep -v "<!--" "$TOMCAT_HOME/conf/server.xml" 2>/dev/null | grep 'protocol="AJP' | grep -qi "secret\|requiredSecret"; then
            result "WST-037|양호|Tomcat AJP secret 설정됨 (${_ajp_addr:-address 미설정})"
        else
            result "WST-037|취약|Tomcat AJP secret 미설정 - Ghostcat(CVE-2020-1938) 취약"
        fi
    else
        result "WST-037|양호|Tomcat AJP 커넥터 비활성화됨"
    fi
}
check_tomcat_ajp

# WST-AUTO-004: 웹서버 TRACE/TRACK 메서드 차단 확인
check_trace_method() {
    evd "WST-038" "grep -rEi 'TraceEnable|request_method.*TRACE|LimitExcept' ${APACHE_CONF:-/dev/null} ${APACHE_CONF:+$(dirname "$APACHE_CONF")} /etc/nginx/ 2>/dev/null | grep -v '^#' | head -5"
    case "$WEB_SRV" in
    apache)
        confdir=$(dirname "$APACHE_CONF")
        if grep -rqi "TraceEnable Off\|RewriteRule.*TRACE\|LimitExcept.*TRACE" "$confdir"/ 2>/dev/null; then
            result "WST-038|양호|Apache TRACE 메서드 차단 설정됨"
        else
            result "WST-038|취약|Apache TRACE 메서드 차단 미설정 (TraceEnable Off 권고)"
        fi ;;
    nginx)
        if grep -rqE "if.*\\\$request_method.*TRACE|limit_except" /etc/nginx/ 2>/dev/null; then
            result "WST-038|양호|Nginx TRACE 메서드 제한 설정됨"
        else
            result "WST-038|수동확인|Nginx TRACE 메서드 제한 수동 확인 (Nginx 기본 차단)"
        fi ;;
    *) result "WST-038|수동확인|TRACE/TRACK 메서드 차단 수동 확인" ;;
    esac
}
check_trace_method

# WST-AUTO-005: 웹서버 SSL 인증서 만료 확인
check_ssl_cert_expiry() {
    evd "WST-040" "grep -rE 'SSLCertificateFile|ssl_certificate' ${APACHE_CONF:-/dev/null} ${APACHE_CONF:+$(dirname "$APACHE_CONF")} /etc/nginx/ 2>/dev/null | grep -v '^#' | head -3"
    case "$WEB_SRV" in
    apache)
        confdir=$(dirname "$APACHE_CONF")
        cert_file=$(grep -r "SSLCertificateFile" "$confdir"/ 2>/dev/null | grep -v "^#" | awk '{print $NF}' | head -1)
        ;;
    nginx)
        cert_file=$(grep -r "ssl_certificate\b" /etc/nginx/ 2>/dev/null | grep -v "^#\|ssl_certificate_key" | awk '{print $NF}' | tr -d ';' | head -1)
        ;;
    esac
    if [ -n "$cert_file" ] && [ -f "$cert_file" ]; then
        expire=$(openssl x509 -enddate -noout -in "$cert_file" 2>/dev/null | cut -d= -f2)
        if [ -n "$expire" ]; then
            expire_epoch=$(date -d "$expire" +%s 2>/dev/null || date -j -f "%b %d %T %Y %Z" "$expire" +%s 2>/dev/null)
            now_epoch=$(date +%s 2>/dev/null)
            if [ -n "$expire_epoch" ] && [ -n "$now_epoch" ]; then
                days_left=$(( (expire_epoch - now_epoch) / 86400 ))
                if [ "$days_left" -le 0 ] 2>/dev/null; then
                    result "WST-040|취약|SSL 인증서 만료됨 (${expire})"
                elif [ "$days_left" -le 30 ] 2>/dev/null; then
                    result "WST-040|취약|SSL 인증서 만료 임박 (${days_left}일 남음, ${expire})"
                else
                    result "WST-040|양호|SSL 인증서 유효 (${days_left}일 남음, ${expire})"
                fi
                return
            fi
        fi
    fi
    result "WST-040|수동확인|SSL 인증서 만료일 수동 확인"
}
check_ssl_cert_expiry

# WST-AUTO-006: Tomcat 로그 설정 확인
check_tomcat_logging() {
    [ -z "$TOMCAT_HOME" ] && return
    evd "WST-041" "grep -v '<!--' ${TOMCAT_HOME}/conf/server.xml 2>/dev/null | grep 'AccessLogValve'"
    if [ -f "$TOMCAT_HOME/conf/server.xml" ]; then
        if grep -v "<!--" "$TOMCAT_HOME/conf/server.xml" 2>/dev/null | grep -q 'className="org.apache.catalina.valves.AccessLogValve"'; then
            result "WST-041|양호|Tomcat 접근 로그(AccessLogValve) 설정됨"
        else
            result "WST-041|취약|Tomcat 접근 로그(AccessLogValve) 미설정"
        fi
    fi
}
check_tomcat_logging

# ── 수동확인 항목 (개별 증적 수집) ─────────────────────────────────

# WST-001: 웹서버 버전 관리
evd "WST-001" "httpd -v 2>/dev/null || apache2 -v 2>/dev/null || nginx -v 2>&1 || wsadmin -v 2>/dev/null"
result "WST-001|수동확인|웹서버 버전 관리 현황 수동 확인 (위 현황 참조)"

# WST-002: 불필요한 파일 제거
evd "WST-002" "find ${TOMCAT_HOME:-/opt/tomcat}/webapps ${APACHE_CONF:+$(dirname $APACHE_CONF)/../htdocs} /var/www/html -maxdepth 2 -name '*.bak' -o -name '*.old' -o -name '*.tmp' -o -name '*.orig' 2>/dev/null | head -10"
result "WST-002|수동확인|웹 루트 내 불필요 파일(백업/임시) 존재 여부 수동 확인 (위 현황 참조)"

# WST-004: DNS 보안 버전 관리
evd "WST-004" "named -v 2>/dev/null; ps -ef 2>/dev/null | grep named | grep -v grep"
result "WST-004|수동확인|DNS 소프트웨어 보안 버전 수동 확인 (위 현황 참조)"

# WST-005: SQL Injection 방지
evd "WST-005" "grep -rE 'mod_security|modsecurity' ${APACHE_CONF:-/dev/null} ${APACHE_CONF:+$(dirname "$APACHE_CONF")} /etc/nginx/ 2>/dev/null | grep -v '^#' | head -3"
result "WST-005|수동확인|SQL Injection 방지 설정(WAF/입력값 검증) 수동 확인 (위 현황 참조)"

# WST-006: XSS 방지
evd "WST-006" "grep -rEi 'X-XSS-Protection|Content-Security-Policy' ${APACHE_CONF:-/dev/null} ${APACHE_CONF:+$(dirname "$APACHE_CONF")} /etc/nginx/ 2>/dev/null | grep -v '^#' | head -3"
result "WST-006|수동확인|XSS 방지 설정(보안헤더/입력값 검증) 수동 확인 (위 현황 참조)"

# WST-007: 파일 업로드 제한
evd "WST-007" "grep -rEi 'LimitRequestBody|client_max_body_size|maxFileSize' ${APACHE_CONF:-/dev/null} ${APACHE_CONF:+$(dirname "$APACHE_CONF")} /etc/nginx/ ${TOMCAT_HOME:-/dev/null}/conf/ 2>/dev/null | grep -v '^#' | head -3"
result "WST-007|수동확인|파일 업로드 크기/확장자 제한 설정 수동 확인 (위 현황 참조)"

# WST-008: 쿠키 보안 설정
evd "WST-008" "grep -rEi 'HttpOnly|Secure|SameSite|session-config' ${APACHE_CONF:-/dev/null} ${APACHE_CONF:+$(dirname "$APACHE_CONF")} /etc/nginx/ ${TOMCAT_HOME:-/dev/null}/conf/web.xml 2>/dev/null | grep -v '^#' | head -5"
result "WST-008|수동확인|쿠키 보안 속성(HttpOnly/Secure/SameSite) 수동 확인 (위 현황 참조)"

# WST-009: 세션 관리
evd "WST-009" "grep -rEi 'session-timeout|session.gc_maxlifetime' ${TOMCAT_HOME:-/dev/null}/conf/web.xml /etc/php*/*/php.ini 2>/dev/null | grep -v '^#' | head -3"
result "WST-009|수동확인|세션 타임아웃/관리 설정 수동 확인 (위 현황 참조)"

# WST-011: FTP 서비스 접근 제한
evd "WST-011" "grep -v '^#' /etc/vsftpd.conf /etc/vsftpd/vsftpd.conf /etc/proftpd/proftpd.conf 2>/dev/null | grep -iE 'chroot|allow|deny|limit' | head -5"
result "WST-011|수동확인|FTP 서비스 접근 제한 설정 수동 확인 (위 현황 참조)"

# WST-018: 불필요 계정 제거
evd "WST-018" "awk -F: '{printf \"%-15s UID=%-5s Shell=%s\\n\",\$1,\$3,\$7}' /etc/passwd"
result "WST-018|수동확인|불필요 시스템/사용자 계정 존재 여부 수동 확인 (위 현황 참조)"

# WST-021: 계정 관리 정책
evd "WST-021" "grep -E '^PASS_|^LOGIN_|^UMASK|^UID_MIN' /etc/login.defs 2>/dev/null | head -10"
result "WST-021|수동확인|계정 관리 정책(암호 정책/계정 잠금) 수동 확인 (위 현황 참조)"

# WST-026: 접근 통제 설정
evd "WST-026" "cat /etc/hosts.allow /etc/hosts.deny 2>/dev/null | grep -v '^#' | grep -v '^$' | head -10"
result "WST-026|수동확인|네트워크 접근 통제(hosts.allow/deny, firewall) 수동 확인 (위 현황 참조)"

# WST-027: 보안 패치 적용
evd "WST-027" "rpm -qa --last 2>/dev/null | head -10 || dpkg -l 2>/dev/null | tail -10 || oslevel -s 2>/dev/null"
result "WST-027|수동확인|최신 보안 패치 적용 여부 수동 확인 (위 현황 참조)"

# WST-032: 심볼릭 링크 사용 제한
evd "WST-032" "find /var/www /opt/tomcat/webapps ${TOMCAT_HOME:-/dev/null}/webapps -type l 2>/dev/null | head -10"
result "WST-032|수동확인|웹 루트 내 심볼릭 링크 존재 여부 수동 확인 (위 현황 참조)"

# WST-042: 웹서버/WAS 보안 패치
evd "WST-042" "httpd -v 2>/dev/null; nginx -v 2>&1; cat ${TOMCAT_HOME:-/dev/null}/RELEASE-NOTES 2>/dev/null | head -3"
result "WST-042|수동확인|웹서버/WAS 최신 보안 패치 적용 여부 수동 확인 (위 현황 참조)"

# WST-043: 로그 관리 설정
evd "WST-043" "ls -la /var/log/httpd/ /var/log/apache2/ /var/log/nginx/ ${TOMCAT_HOME:-/dev/null}/logs/ 2>/dev/null | head -10"
result "WST-043|수동확인|웹서버/WAS 로그 검토/보관 정책 수동 확인 (위 현황 참조)"

# WST-045: Session Timeout 설정
evd "WST-045" "grep -rEi 'session-timeout|timeout|keepalive' ${TOMCAT_HOME:-/dev/null}/conf/web.xml ${APACHE_CONF:-/dev/null} /etc/nginx/ 2>/dev/null | grep -v '^#' | head -5"
result "WST-045|수동확인|웹 세션 타임아웃 설정 적정성 수동 확인 (위 현황 참조)"

# WST-046: 백업 관리
evd "WST-046" "ls -la /backup/ /var/backup/ 2>/dev/null | head -5; crontab -l 2>/dev/null | grep -i backup"
result "WST-046|수동확인|웹서버/WAS 백업 정책 및 수행 여부 수동 확인 (위 현황 참조)"

# WST-047: 서비스 영향 분석
evd "WST-047" "uptime; systemctl list-units --state=running --type=service 2>/dev/null | head -10"
result "WST-047|수동확인|서비스 영향 분석 및 변경 관리 절차 수동 확인"

# WST-053: 불필요 계정/그룹 제거
evd "WST-053" "awk -F: '\$3>=500 && \$3<65534 {printf \"%-15s UID=%s\\n\",\$1,\$3}' /etc/passwd; echo '---'; cat /etc/group | grep -v '^#' | head -20"
result "WST-053|수동확인|불필요 계정/그룹 존재 여부 수동 확인 (위 현황 참조)"

# WST-061: WAS 관리 콘솔 접근 제한
evd "WST-061" "grep -rE 'RemoteAddrValve|allow=|address=' ${TOMCAT_HOME:-/dev/null}/conf/ 2>/dev/null | grep -v '^#' | head -5"
result "WST-061|수동확인|WAS 관리 콘솔 접근 IP 제한 수동 확인 (위 현황 참조)"

# WST-062: WAS 설정파일 권한
evd "WST-062" "ls -la ${TOMCAT_HOME:-/opt/tomcat}/conf/ 2>/dev/null | head -10"
result "WST-062|수동확인|WAS 설정 파일 소유자/권한 수동 확인 (위 현황 참조)"

# WST-063: WAS 로그 설정
evd "WST-063" "ls -la ${TOMCAT_HOME:-/opt/tomcat}/logs/ 2>/dev/null | head -10; cat ${TOMCAT_HOME:-/dev/null}/conf/logging.properties 2>/dev/null | grep -v '^#' | head -10"
result "WST-063|수동확인|WAS 로그 설정/보관 수동 확인 (위 현황 참조)"

# WST-065: 세션 쿠키 보안 속성
evd "WST-065" "grep -A5 '<session-config>' ${TOMCAT_HOME:-/dev/null}/conf/web.xml 2>/dev/null; grep -rEi 'cookie.*secure|httponly' ${TOMCAT_HOME:-/dev/null}/conf/ 2>/dev/null | head -3"
result "WST-065|수동확인|세션 쿠키 보안 속성(Secure/HttpOnly) 수동 확인 (위 현황 참조)"

# WST-066: 웹 서비스 불필요 HTTP 메서드 제한
evd "WST-066" "grep -rEi 'LimitExcept|limit_except|http-method' ${APACHE_CONF:-/dev/null} ${APACHE_CONF:+$(dirname "$APACHE_CONF")} /etc/nginx/ ${TOMCAT_HOME:-/dev/null}/conf/web.xml 2>/dev/null | grep -v '^#' | head -5"
result "WST-066|수동확인|불필요 HTTP 메서드(PUT/DELETE/OPTIONS) 제한 수동 확인 (위 현황 참조)"

# WST-067: 웹 캐시 설정
evd "WST-067" "grep -rEi 'Cache-Control|Pragma|Expires|proxy_cache' ${APACHE_CONF:-/dev/null} ${APACHE_CONF:+$(dirname "$APACHE_CONF")} /etc/nginx/ 2>/dev/null | grep -v '^#' | head -5"
result "WST-067|수동확인|웹 캐시 보안 설정(Cache-Control) 수동 확인 (위 현황 참조)"

# WST-068: 웹 서비스 인증 설정
evd "WST-068" "grep -rEi 'AuthType|auth_basic|Realm' ${APACHE_CONF:-/dev/null} ${APACHE_CONF:+$(dirname "$APACHE_CONF")} /etc/nginx/ 2>/dev/null | grep -v '^#' | head -5"
result "WST-068|수동확인|웹 서비스 인증 메커니즘 수동 확인 (위 현황 참조)"

# WST-069: 웹 서비스 접근 로그 설정
evd "WST-069" "grep -rEi 'CustomLog|access_log|AccessLogValve' ${APACHE_CONF:-/dev/null} ${APACHE_CONF:+$(dirname "$APACHE_CONF")} /etc/nginx/ ${TOMCAT_HOME:-/dev/null}/conf/server.xml 2>/dev/null | grep -v '^#' | head -5"
result "WST-069|수동확인|웹 서비스 접근 로그 형식/저장 설정 수동 확인 (위 현황 참조)"

# WST-070: 웹 서비스 에러 로그 설정
evd "WST-070" "grep -rEi 'ErrorLog|error_log|logging.properties' ${APACHE_CONF:-/dev/null} ${APACHE_CONF:+$(dirname "$APACHE_CONF")} /etc/nginx/ 2>/dev/null | grep -v '^#' | head -5"
result "WST-070|수동확인|웹 서비스 에러 로그 설정 수동 확인 (위 현황 참조)"

# WST-071: 소스 코드 내 중요 정보 노출
evd "WST-071" "find /var/www/html ${TOMCAT_HOME:-/dev/null}/webapps -maxdepth 3 -name '*.jsp' -o -name '*.php' -o -name '*.conf' 2>/dev/null | head -5"
result "WST-071|수동확인|소스 코드 내 중요 정보(DB 접속, 암호) 노출 여부 수동 확인"

# WST-072: 디버그/테스트 페이지 노출
evd "WST-072" "find /var/www/html ${TOMCAT_HOME:-/dev/null}/webapps -maxdepth 2 -name 'test*' -o -name 'debug*' -o -name 'phpinfo*' -o -name 'info*' 2>/dev/null | head -5"
result "WST-072|수동확인|디버그/테스트 페이지 존재 여부 수동 확인 (위 현황 참조)"

# WST-073: 불필요 HTTP 헤더 노출
evd "WST-073" "grep -rEi 'ServerTokens|server_tokens|X-Powered-By' ${APACHE_CONF:-/dev/null} ${APACHE_CONF:+$(dirname "$APACHE_CONF")} /etc/nginx/ ${TOMCAT_HOME:-/dev/null}/conf/server.xml 2>/dev/null | grep -v '^#' | head -5"
result "WST-073|수동확인|불필요 HTTP 응답 헤더(X-Powered-By 등) 노출 수동 확인 (위 현황 참조)"

# WST-074: 웹 서비스 접속 포트 관리
evd "WST-074" "ss -tlnp 2>/dev/null | grep -E ':80 |:443 |:8080 |:8443 ' | head -5"
result "WST-074|수동확인|웹 서비스 접속 포트(80/443/8080/8443) 적정성 수동 확인 (위 현황 참조)"

# WST-076: 웹 서비스 프로세스 모니터링
evd "WST-076" "ps -ef 2>/dev/null | grep -E 'httpd|apache|nginx|tomcat|java' | grep -v grep | head -5"
result "WST-076|수동확인|웹 서비스 프로세스 모니터링 설정 수동 확인 (위 현황 참조)"

# WST-077: 로그 로테이션 설정
evd "WST-077" "cat /etc/logrotate.d/httpd /etc/logrotate.d/apache2 /etc/logrotate.d/nginx 2>/dev/null | head -10"
result "WST-077|수동확인|웹 로그 로테이션 설정 수동 확인 (위 현황 참조)"

# WST-078: 웹 애플리케이션 업데이트 관리
evd "WST-078" "ls -lt /var/www/html/ ${TOMCAT_HOME:-/dev/null}/webapps/ 2>/dev/null | head -5"
result "WST-078|수동확인|웹 애플리케이션 업데이트/패치 관리 수동 확인"

# WST-079: SSL/TLS 인증서 관리
evd "WST-079" "find /etc/ssl /etc/pki -name '*.crt' -o -name '*.pem' 2>/dev/null | head -5"
result "WST-079|수동확인|SSL/TLS 인증서 관리(갱신/폐기) 수동 확인 (위 현황 참조)"

# WST-080: 웹 서비스 가용성 관리
evd "WST-080" "grep -rEi 'MaxClients|MaxRequestWorkers|worker_connections|maxThreads' ${APACHE_CONF:-/dev/null} ${APACHE_CONF:+$(dirname "$APACHE_CONF")} /etc/nginx/ ${TOMCAT_HOME:-/dev/null}/conf/server.xml 2>/dev/null | grep -v '^#' | head -5"
result "WST-080|수동확인|웹 서비스 가용성 설정(MaxClients/worker) 수동 확인 (위 현황 참조)"

# WST-081: 웹 서비스 장애 대응 절차
evd "WST-081" "systemctl is-enabled httpd nginx tomcat 2>/dev/null; ls /etc/systemd/system/multi-user.target.wants/ 2>/dev/null | grep -iE 'http|nginx|tomcat'"
result "WST-081|수동확인|웹 서비스 장애 대응 및 복구 절차 수동 확인"

# WST-084: 웹 서비스 이중화 설정
evd "WST-084" "grep -rEi 'upstream|BalancerMember|ProxyPass' ${APACHE_CONF:-/dev/null} ${APACHE_CONF:+$(dirname "$APACHE_CONF")} /etc/nginx/ 2>/dev/null | grep -v '^#' | head -5"
result "WST-084|수동확인|웹 서비스 이중화/로드밸런싱 설정 수동 확인 (위 현황 참조)"

# WST-085: 웹 서비스 암호화 통신
evd "WST-085" "grep -rEi 'SSLEngine|ssl on|ssl_certificate' ${APACHE_CONF:-/dev/null} ${APACHE_CONF:+$(dirname "$APACHE_CONF")} /etc/nginx/ 2>/dev/null | grep -v '^#' | head -5"
result "WST-085|수동확인|웹 서비스 암호화 통신(HTTPS) 적용 수동 확인 (위 현황 참조)"

# WST-086: 웹 서비스 설정파일 백업
evd "WST-086" "find ${APACHE_CONF:+$(dirname $APACHE_CONF)} /etc/nginx /etc/httpd ${TOMCAT_HOME:-/dev/null}/conf -name '*.bak' -o -name '*.old' -o -name '*.orig' 2>/dev/null | head -5"
result "WST-086|수동확인|웹 서비스 설정파일 백업/변경 관리 수동 확인 (위 현황 참조)"

# WST-088: 웹 서비스 운영 계정 관리
evd "WST-088" "ps -ef 2>/dev/null | grep -E 'httpd|apache|nginx|tomcat|java' | grep -v grep | awk '{print \$1}' | sort -u"
result "WST-088|수동확인|웹 서비스 운영 전용 계정 분리 수동 확인 (위 현황 참조)"

# WST-089: 웹 서비스 접근 IP 제한
evd "WST-089" "grep -rEi 'Require ip|allow from|deny from|allow |deny ' ${APACHE_CONF:-/dev/null} ${APACHE_CONF:+$(dirname "$APACHE_CONF")} /etc/nginx/ 2>/dev/null | grep -v '^#' | head -5"
result "WST-089|수동확인|웹 서비스 관리 페이지 접근 IP 제한 수동 확인 (위 현황 참조)"

# WST-091: 웹 서비스 robots.txt 설정
evd "WST-091" "cat /var/www/html/robots.txt ${TOMCAT_HOME:-/dev/null}/webapps/ROOT/robots.txt 2>/dev/null | head -10"
result "WST-091|수동확인|robots.txt 중요 경로 노출 여부 수동 확인 (위 현황 참조)"

# WST-092: 웹 서비스 디렉토리 권한
evd "WST-092" "ls -ld /var/www/html ${TOMCAT_HOME:-/dev/null}/webapps 2>/dev/null"
result "WST-092|수동확인|웹 루트/WAS 디렉토리 권한 적정성 수동 확인 (위 현황 참조)"

# WST-093: CGI 스크립트 관리
evd "WST-093" "find /var/www/cgi-bin /usr/lib/cgi-bin ${APACHE_CONF:+$(dirname $APACHE_CONF)/../cgi-bin} -type f 2>/dev/null | head -5"
result "WST-093|수동확인|CGI 스크립트 존재/권한 수동 확인 (위 현황 참조)"

# WST-094: 웹 서비스 임시 파일 관리
evd "WST-094" "find /tmp /var/tmp -name 'sess_*' -o -name 'php*' -o -name 'tomcat*' 2>/dev/null | head -5"
result "WST-094|수동확인|웹 서비스 임시 파일 관리 수동 확인 (위 현황 참조)"

# WST-095: 웹 서비스 운영 문서화
evd "WST-095" "echo '운영 문서화 여부는 관리적 점검 항목'"
result "WST-095|수동확인|웹 서비스 운영 문서화 여부 수동 확인"

# WST-096: 웹 서비스 취약점 진단 이력
evd "WST-096" "echo '취약점 진단 이력은 관리적 점검 항목'"
result "WST-096|수동확인|웹 서비스 정기 취약점 진단 수행 여부 수동 확인"

# WST-097: 웹 서비스 사고 대응 절차
evd "WST-097" "echo '사고 대응 절차는 관리적 점검 항목'"
result "WST-097|수동확인|웹 서비스 보안 사고 대응 절차 수립 여부 수동 확인"

# WST-098: 웹 서비스 교육 훈련
evd "WST-098" "echo '보안 교육 훈련은 관리적 점검 항목'"
result "WST-098|수동확인|웹 서비스 운영자 보안 교육/훈련 수동 확인"

# WST-103: 웹 서비스 개인정보 보호
evd "WST-103" "grep -rEi 'SSLEngine|ssl on|https' ${APACHE_CONF:-/dev/null} ${APACHE_CONF:+$(dirname "$APACHE_CONF")} /etc/nginx/ 2>/dev/null | grep -v '^#' | head -3"
result "WST-103|수동확인|개인정보 전송 시 암호화 적용 여부 수동 확인 (위 현황 참조)"

# WST-104: 관리자 페이지 접근 제한
evd "WST-104" "grep -rEi 'manager|admin|console' ${APACHE_CONF:-/dev/null} ${APACHE_CONF:+$(dirname "$APACHE_CONF")} /etc/nginx/ ${TOMCAT_HOME:-/dev/null}/conf/ 2>/dev/null | grep -v '^#' | head -5"
result "WST-104|수동확인|관리자 페이지 접근 IP/인증 제한 수동 확인 (위 현황 참조)"

# WST-105: 웹 서비스 취약한 암호 알고리즘
evd "WST-105" "grep -rEi 'SSLCipherSuite|ssl_ciphers' ${APACHE_CONF:-/dev/null} ${APACHE_CONF:+$(dirname "$APACHE_CONF")} /etc/nginx/ 2>/dev/null | grep -v '^#' | head -3"
result "WST-105|수동확인|취약한 암호 알고리즘(DES/RC4/MD5) 사용 여부 수동 확인 (위 현황 참조)"

# WST-106: 웹 서비스 CORS 설정
evd "WST-106" "grep -rEi 'Access-Control-Allow-Origin|add_header.*Origin' ${APACHE_CONF:-/dev/null} ${APACHE_CONF:+$(dirname "$APACHE_CONF")} /etc/nginx/ 2>/dev/null | grep -v '^#' | head -3"
result "WST-106|수동확인|CORS 설정 적정성 수동 확인 (위 현황 참조)"

# WST-108: 웹 서비스 리다이렉트 설정
evd "WST-108" "grep -rEi 'Redirect|RewriteRule|return 301|return 302' ${APACHE_CONF:-/dev/null} ${APACHE_CONF:+$(dirname "$APACHE_CONF")} /etc/nginx/ 2>/dev/null | grep -v '^#' | head -5"
result "WST-108|수동확인|HTTP→HTTPS 리다이렉트 및 오픈 리다이렉트 수동 확인 (위 현황 참조)"

# WST-110: 웹 서비스 다운로드 제한
evd "WST-110" "grep -rEi 'download|attachment|X-Download' ${APACHE_CONF:-/dev/null} ${APACHE_CONF:+$(dirname "$APACHE_CONF")} /etc/nginx/ 2>/dev/null | grep -v '^#' | head -3"
result "WST-110|수동확인|웹 서비스 파일 다운로드 경로/권한 제한 수동 확인 (위 현황 참조)"

# WST-111: 웹 서비스 URI 길이 제한
evd "WST-111" "grep -rEi 'LimitRequestLine|large_client_header|maxHttpHeaderSize' ${APACHE_CONF:-/dev/null} ${APACHE_CONF:+$(dirname "$APACHE_CONF")} /etc/nginx/ ${TOMCAT_HOME:-/dev/null}/conf/server.xml 2>/dev/null | grep -v '^#' | head -3"
result "WST-111|수동확인|URI/요청 헤더 길이 제한 설정 수동 확인 (위 현황 참조)"

# WST-112: 웹 서비스 요청 본문 크기 제한
evd "WST-112" "grep -rEi 'LimitRequestBody|client_max_body|maxPostSize' ${APACHE_CONF:-/dev/null} ${APACHE_CONF:+$(dirname "$APACHE_CONF")} /etc/nginx/ ${TOMCAT_HOME:-/dev/null}/conf/server.xml 2>/dev/null | grep -v '^#' | head -3"
result "WST-112|수동확인|요청 본문(POST body) 크기 제한 수동 확인 (위 현황 참조)"

# WST-113: 웹 서비스 동시 연결 제한
evd "WST-113" "grep -rEi 'MaxClients|MaxRequestWorkers|worker_connections|maxThreads|acceptCount' ${APACHE_CONF:-/dev/null} ${APACHE_CONF:+$(dirname "$APACHE_CONF")} /etc/nginx/ ${TOMCAT_HOME:-/dev/null}/conf/server.xml 2>/dev/null | grep -v '^#' | head -5"
result "WST-113|수동확인|웹 서비스 동시 연결 수 제한 수동 확인 (위 현황 참조)"

# WST-114: 웹 서비스 Keep-Alive 설정
evd "WST-114" "grep -rEi 'KeepAlive|keepalive_timeout|connectionTimeout' ${APACHE_CONF:-/dev/null} ${APACHE_CONF:+$(dirname "$APACHE_CONF")} /etc/nginx/ ${TOMCAT_HOME:-/dev/null}/conf/server.xml 2>/dev/null | grep -v '^#' | head -5"
result "WST-114|수동확인|Keep-Alive/연결 타임아웃 설정 수동 확인 (위 현황 참조)"

# WST-115: 웹 서비스 로그 무결성
evd "WST-115" "ls -la /var/log/httpd/ /var/log/apache2/ /var/log/nginx/ ${TOMCAT_HOME:-/dev/null}/logs/ 2>/dev/null | head -5; stat -c '%a %U %G' /var/log/httpd /var/log/apache2 /var/log/nginx ${TOMCAT_HOME:-/dev/null}/logs 2>/dev/null"
result "WST-115|수동확인|웹 서비스 로그 무결성/변조 방지 수동 확인 (위 현황 참조)"

# WST-116: 웹 서비스 보안 모듈
evd "WST-116" "httpd -M 2>/dev/null | grep -iE 'security|evasive|modsec' || ls /etc/nginx/modsec* /etc/nginx/owasp* 2>/dev/null"
result "WST-116|수동확인|웹 서비스 보안 모듈(ModSecurity/WAF) 적용 수동 확인 (위 현황 참조)"

# WST-117: 웹 서비스 클라이언트 인증서 인증
evd "WST-117" "grep -rEi 'SSLVerifyClient|ssl_verify_client|clientAuth' ${APACHE_CONF:-/dev/null} ${APACHE_CONF:+$(dirname "$APACHE_CONF")} /etc/nginx/ ${TOMCAT_HOME:-/dev/null}/conf/server.xml 2>/dev/null | grep -v '^#' | head -3"
result "WST-117|수동확인|클라이언트 인증서 인증 설정 수동 확인 (위 현황 참조)"

fi
# ════════════════════════════════════════════════════════════════
# [3] 웹 고유 항목 — 평가기준 판단방법 기준
# ════════════════════════════════════════════════════════════════
# ── 웹서버-WAS 전용 점검 (평가기준 제2026-1호 [웹서버-WAS] 판단기준·판단방법 기준) ──
_PHASE="final"

_apache_root() {  # ServerRoot (Include 상대경로 기준)
    local r; r=$(grep -hiE '^\s*ServerRoot\s' "$APACHE_CONF" 2>/dev/null | head -1 | awk '{print $2}' | tr -d '"')
    [ -n "$r" ] && echo "$r" || dirname "$(dirname "$APACHE_CONF")"
}
_apache_includes() {  # Include/IncludeOptional 재귀 해석 (DUMP_INCLUDES 불가 시)
    local f="$1" depth="${2:-0}" pat p
    [ -f "$f" ] || return; echo "$f"
    [ "$depth" -ge 6 ] && return
    grep -hiE '^\s*Include(Optional)?\s+' "$f" 2>/dev/null | awk '{print $2}' | tr -d '"' | while read -r pat; do
        case "$pat" in /*) ;; *) pat="$(_apache_root)/$pat" ;; esac
        for p in $pat; do [ -f "$p" ] && _apache_includes "$p" $((depth+1)); [ -d "$p" ] && for q in "$p"/*; do _apache_includes "$q" $((depth+1)); done; done
    done
}
_web_conf_files() {  # 실제 로드되는 설정 파일만 (Apache: DUMP_INCLUDES → Include 재귀 해석)
    {
        if [ -n "$APACHE_CONF" ]; then
            local dump=""
            local out f
            for b in httpd apache2ctl apache2 apachectl; do
                command -v "$b" >/dev/null 2>&1 || continue
                out=$("$b" -t -D DUMP_INCLUDES 2>/dev/null)
                echo "$out" | grep -q "Included configuration files" || continue   # 안내문 등 비정상 출력 배제
                dump=$(echo "$out" | awk '/^[[:space:]]*\(/ {print $NF}' | while read -r f; do [ -f "$f" ] && echo "$f"; done)
                [ -n "$dump" ] && break
            done
            [ -n "$dump" ] && echo "$dump" || _apache_includes "$APACHE_CONF"
        fi
        if [ "$WEB_SRV" = "nginx" ]; then
            nginx -T 2>/dev/null | grep -E '^# configuration file ' | awk '{print $4}' | tr -d ':' | grep . || find /etc/nginx -name "*.conf" 2>/dev/null
        fi
    } | grep -v '^$' | sort -u
}
_grep_conf() {  # 로드되는 설정 파일에서 패턴 검색 (xargs 미사용)
    local f
    _web_conf_files | while read -r f; do [ -f "$f" ] && grep -hiE "$1" "$f" 2>/dev/null; done
}
_web_docroots() {
    {
        _grep_conf "^\s*DocumentRoot\s" | awk '{print $2}' | tr -d '"'
        [ "$WEB_SRV" = "nginx" ] && _grep_conf "^\s*root\s" | awk '{print $2}' | tr -d ';"'
        [ -n "$TOMCAT_HOME" ] && echo "$TOMCAT_HOME/webapps"
    } | grep -v '^$' | sort -u
}
_cgi_dirs() {  # ScriptAlias /cgi-bin/ 경로 + 배포판 기본 경로
    {
        _grep_conf '^\s*ScriptAlias\s+/cgi-bin/' | awk '{print $3}' | tr -d '"'
        [ -n "$APACHE_CONF" ] && echo "$(_apache_root)/cgi-bin"
        echo /var/www/cgi-bin; echo /usr/lib/cgi-bin
    } | sed 's#/$##' | sort -u
}
_apache_ver() {
    { httpd -v 2>/dev/null || apache2 -v 2>/dev/null || apachectl -v 2>/dev/null; } | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1
}
_tomcat_ver() {
    [ -n "$TOMCAT_HOME" ] || return
    { grep -h "Apache Tomcat Version" "$TOMCAT_HOME/RELEASE-NOTES" 2>/dev/null
      sh "$TOMCAT_HOME/bin/version.sh" 2>/dev/null | grep -i "Server number"; } | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1
}

if [ -z "$WEB_SRV$WAS_SRV" ]; then
    for _c in 031 033 034 035 036 037 038 044 102 121 122 123 124 125; do
        result "WST-${_c}|N-A|웹서버/WAS 미탐지"
    done
else
# WST-033: 상위 디렉터리 접근 제한 (Directory Traversal 취약 버전 여부)
evd "WST-033" "httpd -v 2>/dev/null || apache2 -v 2>/dev/null || nginx -v 2>&1"
case "$WEB_SRV" in
apache)
    _av=$(_apache_ver)
    case "$_av" in
    2.4.49|2.4.50) result "WST-033|취약|Apache ${_av} - Directory Traversal 취약 버전 (CVE-2021-41773/42013)" ;;
    "")            result "WST-033|수동확인|Apache 버전 확인 실패 - Directory Traversal 취약 버전 여부 수동 확인" ;;
    *)             result "WST-033|양호|Apache ${_av} - Directory Traversal 취약 버전(2.4.49/2.4.50) 아님" ;;
    esac ;;
nginx|webtob)
    result "WST-033|수동확인|${WEB_SRV} 버전의 Directory Traversal 취약점 해당 여부 수동 확인" ;;
*)
    [ -n "$WAS_SRV" ] && result "WST-033|수동확인|${WAS_SRV} 버전의 Directory Traversal 취약점 해당 여부 수동 확인" \
                     || result "WST-033|N-A|웹서버/WAS 미탐지" ;;
esac

# WST-034: 웹 서비스 경로 내 불필요 파일 (디폴트 cgi-bin / 임시·백업 파일 / JEUS·Tomcat 샘플)
_roots=$(_web_docroots | tr '\n' ' ')
evd "WST-034" "ls -la $(_cgi_dirs | tr '
' ' ') 2>/dev/null; for d in ${_roots:-/var/www/html}; do find \"\$d\" -maxdepth 3 -type f \( -name '*.bak' -o -name '*.old' -o -name '*.tmp' -o -name '*.orig' -o -name '*~' -o -name '*.swp' \) 2>/dev/null | head -10; done"
if [ -z "$WEB_SRV$WAS_SRV" ]; then
    result "WST-034|N-A|웹서버/WAS 미탐지"
else
    _f=""
    for d in $(_cgi_dirs); do
        [ -d "$d" ] && ls "$d" 2>/dev/null | grep -qE '^(printenv|test-cgi)' && _f="${_f} 디폴트cgi:${d}"
    done
    for d in ${_roots:-/var/www/html}; do
        _b=$(find "$d" -maxdepth 3 -type f \( -name '*.bak' -o -name '*.old' -o -name '*.tmp' -o -name '*.orig' -o -name '*~' -o -name '*.swp' \) 2>/dev/null | head -3 | tr '\n' ' ')
        [ -n "$_b" ] && _f="${_f} 임시/백업:${_b}"
    done
    # 평가대상: Apache·WebtoB·JEUS(Tomcat 비대상 - 샘플은 증적만)
    [ -n "$TOMCAT_HOME" ] && [ -d "$TOMCAT_HOME/webapps/examples" ] && printf '[WST-034] (참고-Tomcat 비대상) 샘플: %s/webapps/examples

' "$TOMCAT_HOME" >> "$_EVD"
    for d in ${JEUS_HOME:+$JEUS_HOME/samples $JEUS_HOME/examples}; do [ -d "$d" ] && _f="${_f} JEUS샘플:${d}"; done
    [ -n "$_f" ] && result "WST-034|취약|불필요 파일 존재:${_f}" || result "WST-034|양호|디폴트 cgi-bin·임시/백업 파일·샘플 디렉터리 미발견"
fi

# WST-035: 파일 업로드·다운로드 용량 제한 (LimitRequestBody / client_max_body_size / maxPostSize)
evd "WST-035" "$( [ -n "$APACHE_CONF" ] && echo "grep -rhiE '^\s*LimitRequestBody' $(dirname "$APACHE_CONF") 2>/dev/null;" ) grep -rhE 'client_max_body_size' /etc/nginx 2>/dev/null; grep -hoE 'maxPostSize=\"[^\"]*\"' ${TOMCAT_HOME:-/dev/null}/conf/server.xml 2>/dev/null"
_lim=""; _miss=""
case "$WEB_SRV" in
apache) _grep_conf "^\s*LimitRequestBody\s+[1-9]" 2>/dev/null | head -1 | grep -q . && _lim="${_lim} Apache LimitRequestBody" || _miss="${_miss} Apache(LimitRequestBody)" ;;
nginx)  # client_max_body_size 미설정 시 기본 1m 제한, 0 이면 제한 해제
        if grep -rhE "^\s*client_max_body_size\s+0\s*;" /etc/nginx 2>/dev/null | grep -q .; then _miss="${_miss} Nginx(client_max_body_size 0 - 제한 해제)"
        else _cmb=$(grep -rhoE '^\s*client_max_body_size\s+\S+' /etc/nginx 2>/dev/null | awk '{print $2}' | tr -d ';' | head -1); _lim="${_lim} Nginx client_max_body_size=${_cmb:-1m(기본)}"; fi ;;
esac
[ "$WAS_SRV" = "tomcat" ] && printf '[WST-035] (참고-Tomcat 비대상) maxPostSize: %s

' "$(grep -hoE 'maxPostSize="[^"]*"' ${TOMCAT_HOME:-/dev/null}/conf/server.xml 2>/dev/null | head -1)" >> "$_EVD"
if [ "$WAS_SRV" = "jeus" ] && [ -n "$JEUS_HOME" ]; then
    grep -rqE '<max-post-size>[0-9]+' "$JEUS_HOME"/domains/*/config/domain.xml 2>/dev/null && _lim="${_lim} JEUS max-post-size" || _miss="${_miss} JEUS(max-post-size)"
fi
if [ -z "$WEB_SRV$WAS_SRV" ]; then result "WST-035|N-A|웹서버/WAS 미탐지"
elif [ -n "$_miss" ]; then result "WST-035|취약|업로드/다운로드 용량 제한 미설정:${_miss}"
elif [ -n "$_lim" ]; then result "WST-035|양호|용량 제한 설정됨:${_lim}"
else result "WST-035|수동확인|${WEB_SRV:-$WAS_SRV} 용량 제한 설정 수동 확인"; fi

# WST-037: 웹 서비스 경로 설정 적절성 (DocumentRoot가 "/" 등 업무 영역과 분리되지 않은 경로)
evd "WST-037" "$( [ -n "$APACHE_CONF" ] && echo "grep -rhiE '^\s*DocumentRoot' $(dirname "$APACHE_CONF") 2>/dev/null;" ) grep -rhE '^\s*root\s' /etc/nginx 2>/dev/null; grep -hoE 'appBase=\"[^\"]*\"|docBase=\"[^\"]*\"' ${TOMCAT_HOME:-/dev/null}/conf/server.xml 2>/dev/null"
if [ -z "$WEB_SRV$WAS_SRV" ]; then
    result "WST-037|N-A|웹서버/WAS 미탐지"
else
    _bad=""
    for d in $(_web_docroots) $(grep -hoE 'docBase="[^"]*"' ${TOMCAT_HOME:-/dev/null}/conf/server.xml 2>/dev/null | cut -d'"' -f2); do
        case "${d%/}" in
        ""|/|/etc|/usr|/bin|/sbin|/root|/home|/var|/opt|/tmp|/boot|/lib|/lib64|/proc|/sys|/dev) _bad="${_bad} ${d}" ;;
        esac
    done
    [ -n "$_bad" ] && result "WST-037|취약|웹 서비스 경로가 업무 영역과 분리되지 않음:${_bad}" \
                   || result "WST-037|양호|웹 서비스 경로 분리됨: $(_web_docroots | tr '\n' ' ')"
fi

# WST-038: 웹 서비스 경로 내 불필요한 링크 파일 (FollowSymLinks 허용 + 링크 존재 시 취약)
evd "WST-038" "$( [ -n "$APACHE_CONF" ] && echo "grep -rhiE '^\s*Options' $(dirname "$APACHE_CONF") 2>/dev/null;" ) for d in $(_web_docroots | tr '\n' ' '); do find \"\$d\" -maxdepth 3 -type l -exec ls -l {} \; 2>/dev/null | head -5; done; grep -hoE 'allowLinking=\"[^\"]*\"' ${TOMCAT_HOME:-/dev/null}/conf/context.xml 2>/dev/null"
if [ -z "$WEB_SRV$WAS_SRV" ]; then
    result "WST-038|N-A|웹서버/WAS 미탐지"
else
    _links=""
    for d in $(_web_docroots); do
        _l=$(find "$d" -maxdepth 3 -type l 2>/dev/null | head -3 | tr '\n' ' ')
        [ -n "$_l" ] && _links="${_links} ${_l}"
    done
    _allow=""
    if [ "$WEB_SRV" = "apache" ]; then
        _grep_conf "^\s*Options" 2>/dev/null | grep -iE "(^|[ +])FollowSymLinks" | grep -qvi -- "-FollowSymLinks" && _allow="Apache FollowSymLinks"
        _grep_conf "^\s*Options" 2>/dev/null | grep -qi "SymLinksIfOwnerMatch" && _allow="${_allow:-Apache SymLinksIfOwnerMatch(소유자 일치 시 허용)}"
        _grep_conf "^\s*Options" 2>/dev/null | grep -q . || _allow="Apache Options 미설정(2.4 기본 FollowSymLinks)"
    fi
    [ -n "$TOMCAT_HOME" ] && grep -qiE 'allowLinking="true"' "$TOMCAT_HOME/conf/context.xml" 2>/dev/null && _allow="${_allow} Tomcat allowLinking"
    if [ -n "$_links" ] && [ -n "$_allow" ]; then result "WST-038|취약|링크 허용(${_allow}) + 링크 파일 존재:${_links}"
    elif [ -n "$_links" ]; then result "WST-038|양호|링크 파일 존재하나 링크 허용 설정 비활성화 (${_links})"
    else result "WST-038|양호|웹 서비스 경로 내 링크 파일 없음${_allow:+ (허용 설정: ${_allow})}"; fi
fi

# 주석 제외 활성 지시자 조회 (파일명 접두 없이 -h, 줄머리 공백 허용)
_active() { _grep_conf "^\s*$1"; }
_tc_webxml_active() {  # Tomcat conf/web.xml 및 앱 web.xml 에서 주석 블록 제거 후 패턴 검색
    local f
    for f in "$TOMCAT_HOME/conf/web.xml" "$TOMCAT_HOME"/webapps/*/WEB-INF/web.xml; do
        [ -f "$f" ] && awk '/<!--/{c=1} !c{print} /-->/{c=0}' "$f" 2>/dev/null | grep -qiE "$1" && { echo "$f"; return 0; }
    done
    return 1
}

# WST-031: 디렉터리 리스팅 (Apache Options Indexes / Nginx autoindex / Tomcat listings)
evd "WST-031" "$( [ -n "$APACHE_CONF" ] && echo "grep -rhiE '^\s*Options' $(dirname "$APACHE_CONF") 2>/dev/null;" ) grep -rhE '^\s*autoindex' /etc/nginx 2>/dev/null; grep -A1 -i '<param-name>listings' ${TOMCAT_HOME:-/dev/null}/conf/web.xml 2>/dev/null"
_r=""
case "$WEB_SRV" in
apache) _o=$(_active "Options\s" | grep -iE "(^|[[:space:]+])Indexes" | grep -vi -- "-Indexes" | head -1)
        [ -n "$_o" ] && _r="취약|Apache 디렉터리 리스팅 허용: $(echo $_o)" || _r="양호|Apache Options Indexes 미사용" ;;
nginx)  grep -rhE "^\s*autoindex\s+on" /etc/nginx 2>/dev/null | grep -q . && _r="취약|Nginx autoindex on" || _r="양호|Nginx autoindex off" ;;
webtob) _r="수동확인|WebtoB http.m Options INDEX 여부 수동 확인" ;;
esac
if [ "$WAS_SRV" = "tomcat" ] && [ -n "$TOMCAT_HOME" ]; then
    if grep -A1 -i "<param-name>listings</param-name>" "$TOMCAT_HOME/conf/web.xml" 2>/dev/null | grep -qi "<param-value>true"; then
        _r="$(_worse "$_r" "취약|Tomcat DefaultServlet listings=true")"
    else _r="$(_worse "$_r" "양호|Tomcat listings=false")"; fi
fi
result "WST-031|${_r:-수동확인|디렉터리 리스팅 설정 수동 확인}"

# WST-121: 불필요한 프록시 설정 (오픈 프록시=취약, 역프록시 매핑=필요성 확인)
evd "WST-121" "$( [ -n "$APACHE_CONF" ] && echo "grep -rhiE '^\s*(LoadModule proxy|ProxyRequests|ProxyPass)' $(dirname "$APACHE_CONF") /etc/httpd/conf.modules.d 2>/dev/null;" ) grep -rhE '^\s*proxy_pass' /etc/nginx 2>/dev/null"
case "$WEB_SRV" in
apache)
    if _active "ProxyRequests\s+On" | grep -q .; then result "WST-121|취약|ProxyRequests On (포워드/오픈 프록시 허용)"
    elif _active "ProxyPass(Match)?\s" | grep -q .; then result "WST-121|수동확인|역프록시 매핑 존재: $(_active 'ProxyPass(Match)?\s' | head -2 | tr '\n' ' ')- 필요성 확인"
    else result "WST-121|양호|프록시 설정(ProxyRequests On/ProxyPass) 없음"; fi ;;
nginx)
    grep -rhE "^\s*proxy_pass" /etc/nginx 2>/dev/null | grep -q . \
        && result "WST-121|수동확인|Nginx proxy_pass 매핑 존재 - 필요성 확인" || result "WST-121|양호|Nginx 프록시 설정 없음" ;;
*)  result "WST-121|수동확인|${WEB_SRV:-$WAS_SRV} 프록시 설정 수동 확인" ;;
esac

# WST-122: SSI (Apache Options Includes / AddOutputFilter INCLUDES, Tomcat SSIServlet·SSIFilter)
evd "WST-122" "$( [ -n "$APACHE_CONF" ] && echo "grep -rhiE '^\s*(Options|AddOutputFilter|AddHandler|AddType).*(Includes|INCLUDES|server-parsed|shtml)' $(dirname "$APACHE_CONF") 2>/dev/null;" ) grep -n -iE 'SSIServlet|SSIFilter' ${TOMCAT_HOME:-/dev/null}/conf/web.xml 2>/dev/null"
_r=""
if [ "$WEB_SRV" = "apache" ]; then
    # 평가기준: Options 에 Includes 가 있을 때만 SSI 허용 (AddOutputFilter INCLUDES 는 Options Includes 없이는 동작 안 함 → 증적만)
    _o=$(_active "Options\s" | grep -iE "(^|[[:space:]+])Includes(NOEXEC)?" | grep -vi -- "-Includes" | head -1)
    [ -n "$_o" ] && _r="취약|Apache SSI 활성: $(echo $_o)" || _r="양호|Apache Options Includes 미사용 (SSI 비활성)"
elif [ "$WEB_SRV" = "nginx" ]; then
    grep -rhE "^\s*ssi\s+on" /etc/nginx 2>/dev/null | grep -q . && _r="취약|Nginx ssi on" || _r="양호|Nginx ssi 미사용"
elif [ -n "$WEB_SRV" ]; then _r="수동확인|${WEB_SRV} SSI 설정 수동 확인"; fi
if [ "$WAS_SRV" = "tomcat" ] && [ -n "$TOMCAT_HOME" ]; then
    _f=$(_tc_webxml_active "SSIServlet|SSIFilter") && _r="$(_worse "$_r" "취약|Tomcat SSI 활성: ${_f}")" || _r="$(_worse "$_r" "양호|Tomcat SSIServlet/SSIFilter 미사용")"
fi
result "WST-122|${_r:-수동확인|SSI 설정 수동 확인}"

# WST-123: 기본 에러 페이지 노출 방지 (ErrorDocument / error_page / Tomcat <error-page>)
evd "WST-123" "$( [ -n "$APACHE_CONF" ] && echo "grep -rhiE '^\s*ErrorDocument' $(dirname "$APACHE_CONF") 2>/dev/null;" ) grep -rhE '^\s*error_page' /etc/nginx 2>/dev/null; grep -n '<error-page>' ${TOMCAT_HOME:-/dev/null}/conf/web.xml 2>/dev/null"
_r=""
case "$WEB_SRV" in
apache) _ed=$(_active "ErrorDocument\s+[45][0-9][0-9]" | grep -vE 'ErrorDocument\s+403\s+/\.noindex\.html' | awk '{print $2}' | sort -u | tr '
' ' ')
        _mis=""; echo " $_ed" | grep -q ' 404' || _mis="${_mis} 404"; echo " $_ed" | grep -qE ' 5[0-9][0-9]' || _mis="${_mis} 500"
        [ -z "$_mis" ] && _r="양호|Apache 사용자 정의 에러 페이지 설정 (ErrorDocument ${_ed% })" || _r="취약|Apache ErrorDocument 미설정 코드:${_mis} (기본 에러 페이지 노출${_ed:+, 설정: ${_ed% }})" ;;
nginx)  _ep=$(grep -rhE "^\s*error_page\s" /etc/nginx 2>/dev/null | grep -oE '\b[45][0-9][0-9]\b' | sort -u | tr '\n' ' ')
        _mis=""; echo " $_ep" | grep -q ' 404' || _mis="${_mis} 404"; echo " $_ep" | grep -qE ' 5[0-9][0-9]' || _mis="${_mis} 500"
        [ -z "$_mis" ] && _r="양호|Nginx error_page 설정 (${_ep% })" || _r="취약|Nginx error_page 미설정 코드:${_mis}${_ep:+ (설정: ${_ep% })}" ;;
webtob) _r="수동확인|WebtoB 상태코드별 에러 페이지 매핑 수동 확인" ;;
esac
if [ "$WAS_SRV" = "tomcat" ] && [ -n "$TOMCAT_HOME" ]; then
    _tc_webxml_active "<error-page>" >/dev/null && _r="$(_worse "$_r" "양호|Tomcat <error-page> 설정")" || _r="$(_worse "$_r" "취약|Tomcat <error-page> 미설정 (기본 에러 페이지·버전 노출)")"
fi
result "WST-123|${_r:-수동확인|에러 페이지 설정 수동 확인}"

# WST-044: 웹 서비스 기본 계정(아이디/비밀번호) 변경 여부
_tu="${TOMCAT_HOME:-/nonexistent}/conf/tomcat-users.xml"
evd "WST-044" "grep -v '^\s*<!--' $_tu 2>/dev/null | grep -iE '<user ' ; ls -la \${JEUS_HOME:-/nonexistent}/domains/*/config/security/*/accounts.xml 2>/dev/null"
if [ "$WAS_SRV" = "tomcat" ] && [ -f "$_tu" ]; then
    _users=$(sed 's/<!--.*-->//g' "$_tu" | awk '/<!--/{c=1} !c{print} /-->/{c=0}' | grep -iE '<user ')
    _def=$(echo "$_users" | grep -iE 'password="(tomcat|admin|s3cret|password|role1|both|<must-be-changed>|manager|1234|123456)"|username="(tomcat|admin|both|role1)"')
    if [ -n "$_def" ]; then result "WST-044|취약|Tomcat 기본/유추 가능 계정: $(echo "$_def" | grep -oE 'username="[^"]*"' | tr '\n' ' ')"
    elif [ -n "$_users" ]; then result "WST-044|양호|Tomcat 관리 계정 디폴트 값 아님 ($(echo "$_users" | wc -l)개)"
    else result "WST-044|양호|Tomcat 관리 계정 미설정 (tomcat-users.xml 활성 user 없음)"; fi
elif [ "$WAS_SRV" = "jeus" ]; then
    result "WST-044|수동확인|JEUS accounts.xml 관리자 계정/비밀번호 디폴트 여부 수동 확인"
elif [ -n "$WEB_SRV$WAS_SRV" ]; then
    result "WST-044|N-A|관리 계정을 사용하는 WAS(Tomcat/JEUS) 미탐지"
else
    result "WST-044|N-A|웹서버/WAS 미탐지"
fi

# WST-102: 웹 서비스 정보 노출 방지 (Apache: ServerTokens Prod 외 → 노출)
evd "WST-102" "$( [ -n "$APACHE_CONF" ] && echo "grep -rhiE '^\s*Server(Tokens|Signature)' $(dirname "$APACHE_CONF") 2>/dev/null;" ) grep -rh 'server_tokens' /etc/nginx 2>/dev/null; grep -hoE 'server=\"[^\"]*\"' ${TOMCAT_HOME:-/dev/null}/conf/server.xml 2>/dev/null"
case "$WEB_SRV" in
apache)
    _tok=$(_grep_conf "^\s*ServerTokens\s" 2>/dev/null | tail -1 | awk '{print $2}')
    case "${_tok,,}" in
    prod|productonly) result "WST-102|양호|Apache ServerTokens=${_tok} (서비스명만 노출)" ;;
    "")               result "WST-102|취약|Apache ServerTokens 미설정 (기본값 Full - 서비스명+버전 노출)" ;;
    *)                result "WST-102|취약|Apache ServerTokens=${_tok} (Prod 외 설정 - 버전 정보 노출)" ;;
    esac ;;
nginx)
    grep -rhE "^\s*server_tokens\s+off" /etc/nginx 2>/dev/null | grep -q . \
        && result "WST-102|양호|Nginx server_tokens off" || result "WST-102|취약|Nginx server_tokens off 미설정 (버전 노출)" ;;
webtob)
    result "WST-102|수동확인|WebtoB http.m ServerTokens(Min/OS/Full 여부) 수동 확인" ;;
*)
    if [ "$WAS_SRV" = "tomcat" ] && [ -n "$TOMCAT_HOME" ]; then
        grep -qE 'server="[^"]+"' "$TOMCAT_HOME/conf/server.xml" 2>/dev/null \
            && result "WST-102|양호|Tomcat Connector server 속성으로 서버 정보 대체" \
            || result "WST-102|수동확인|Tomcat 응답 헤더/에러 페이지 서버 정보 노출 수동 확인"
    else result "WST-102|N-A|웹서버/WAS 미탐지"; fi ;;
esac

fi

# WST-039: 불필요한 웹 서비스 비활성화 (실행 중인 웹 서비스의 업무 필요성)
evd "WST-039" "ps -eo user,pid,comm,args 2>/dev/null | grep -E '[h]ttpd|[a]pache2|[n]ginx|[w]sm|[h]tl|[o]rg.apache.catalina|[j]eus' | head -10"
if command -v ps >/dev/null 2>&1; then
    _comm=$(ps -eo comm= 2>/dev/null); _args=$(ps -eo args= 2>/dev/null)
else  # ps 미설치(최소 이미지) → /proc 로 대체
    _comm=$(cat /proc/[0-9]*/comm 2>/dev/null); _args=$(for f in /proc/[0-9]*/cmdline; do tr '\0' ' ' < "$f" 2>/dev/null; echo; done)
fi
_run=$( { echo "$_comm" | grep -xE 'httpd|apache2|nginx|wsm|htl'; echo "$_args" | grep -q 'org.apache.catalina' && echo tomcat; echo "$_args" | grep -q 'jeus' && echo jeus; } | sort -u | tr '
' ' ')
[ -n "$_run" ] && result "WST-039|수동확인|실행 중인 웹 서비스: ${_run}- 업무상 필요 여부 확인"                || result "WST-039|양호|실행 중인 웹 서비스 없음"


# WST-032·040·041·042·043: 평가기준상 Windows(IIS) 평가대상 항목 → Unix/Linux N-A
for _c in 032 040 041 042 043; do
    result "WST-${_c}|N-A|Windows(IIS) 평가대상 항목 (Unix/Linux 해당 없음)"
done

# WST-080: 주기적인 보안패치 (OS 판정 + 웹서버/WAS 버전 확인 병합)
evd "WST-080" "httpd -v 2>/dev/null || apache2 -v 2>/dev/null || nginx -v 2>&1; cat ${TOMCAT_HOME:-/dev/null}/RELEASE-NOTES 2>/dev/null | grep -i 'Tomcat Version'"
_wv="$(_apache_ver)"; _tv="$(_tomcat_ver)"
_merge_hold "WST-080" "수동확인" "웹 제품 보안패치 확인 필요 (Apache ${_wv:-미탐지} / Tomcat ${_tv:-미탐지}) - 벤더 보안 공지 대조"

# WST-126: EoS (OS 판정 + 웹서버/WAS 제품 EoS 병합)
evd "WST-126" "httpd -v 2>/dev/null || apache2 -v 2>/dev/null || nginx -v 2>&1; cat ${TOMCAT_HOME:-/dev/null}/RELEASE-NOTES 2>/dev/null | grep -i 'Tomcat Version'"
EOS_SCRIPT="$(dirname "$0")/eos_checker.py"
[ -f "$EOS_SCRIPT" ] || EOS_SCRIPT="$(dirname "$0")/../converter/eos_checker.py"   # 저장소 구조 그대로 실행 시
_eos_one() {
    local p="$1" v="$2" r d
    [ -n "$v" ] || { echo "수동확인|${p} 버전 확인 실패"; return; }
    [ -f "$EOS_SCRIPT" ] || { echo "수동확인|${p} ${v} (eos_checker.py 없음 - 수동 확인)"; return; }
    local _py _eo; _py=$(command -v python3 2>/dev/null || { [ -x /usr/libexec/platform-python ] && echo /usr/libexec/platform-python; } || command -v python 2>/dev/null)
    [ -n "$_py" ] || { echo "수동확인|${p} ${v} (python 미설치 - EoS 수동 확인)"; return; }
    _eo=$("$_py" "$EOS_SCRIPT" "$p" "$v" 2>/dev/null)   # 인터넷 연결 시 endoflife.date 조회, 아니면 내장 데이터
    r=$(echo "$_eo" | grep "^결과:" | awk '{print $2}')
    d=$(echo "$_eo" | grep "^설명:" | cut -d: -f2- | sed "s/^ *//;s/ *$//")
    echo "${r:-수동확인}|${p} ${v}: ${d:-EoS 판정 실패}"
}
_w126=""
case "$WEB_SRV" in
apache) _w126="$(_eos_one apache "$(_apache_ver)")" ;;
nginx)  _w126="$(_eos_one nginx "$(nginx -v 2>&1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)")" ;;
webtob) _w126="수동확인|WebtoB 버전 EoS 수동 확인" ;;
esac
case "$WAS_SRV" in
tomcat) _t="$(_eos_one tomcat "$(_tomcat_ver)")"
        _w126="$(_worse "${_w126}" "${_t}")" ;;
jeus)   _w126="$(_worse "${_w126}" "수동확인|JEUS 버전 EoS 수동 확인")" ;;
esac
[ -n "$_w126" ] && _merge_hold "WST-126" "${_w126%%|*}" "${_w126#*|}" || _merge_hold "WST-126" "" ""


# ════════════════════════════════════════════════════════════════
# [4] 주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드(2026) — 웹 서비스 WEB-01 ~ WEB-26
#     가이드 항목코드·판단기준 그대로 판정 (전자금융 WST 결과와 별개, 컨버터 주요정보 모드에서 사용)
#     제품별 점검 대상은 가이드 '점검 대상' 기준 (IIS 는 check_webwas.ps1)
# ════════════════════════════════════════════════════════════════
if [ "$_KMODE" != "ef" ]; then   # 전자금융 모드는 가이드 WEB 판정 생략
_PHASE="final"
exec </dev/null   # 설정 파일 목록이 비었을 때 grep 등이 표준입력을 기다리며 멈추지 않도록
# WebtoB 설정 파일(http.m) / JEUS 홈 추가 탐지
_WT_M=""
for _d in "$WEBTOBDIR" /home/tmax/webtob /root/webtob /opt/tmax/webtob /sw/webtob /sw/webtob5 /home/webtob/webtob; do
    [ -n "$_d" ] && [ -f "$_d/config/http.m" ] && { _WT_M="$_d/config/http.m"; _WT_HOME="$_d"; break; }
done
[ "$WEB_SRV" = "webtob" ] && [ -z "$_WT_M" ] && _WT_M=$(find /home /opt /sw /root -maxdepth 5 -name http.m -path '*config*' 2>/dev/null | head -1) && _WT_HOME="${_WT_M%/config/http.m}"
[ -n "$_WT_M" ] && [ -z "$WEB_SRV" ] && WEB_SRV="webtob"
if [ -z "$JEUS_HOME" ]; then
    JEUS_HOME=$(ps -eo args= 2>/dev/null | grep -oE '\-Djeus\.home=[^ ]+' | head -1 | cut -d= -f2)
    [ -n "$JEUS_HOME" ] && [ -z "$WAS_SRV" ] && WAS_SRV="jeus"
fi
_JX() { [ -n "$JEUS_HOME" ] && find "$JEUS_HOME" -maxdepth 7 -name "$1" 2>/dev/null | head -${2:-20}; }   # JEUS 설정 파일 검색
_wtm() { [ -f "$_WT_M" ] && grep -v '^[[:space:]]*#' "$_WT_M" 2>/dev/null | grep -iE "$1"; }        # WebtoB http.m 활성 줄
_tcx() { [ -n "$TOMCAT_HOME" ] && awk '/<!--/{c=1} !c{print} /-->/{c=0}' "$TOMCAT_HOME/conf/$1" 2>/dev/null; }   # Tomcat conf 파일(주석 제거)
_ngx() { if [ "$WEB_SRV" = nginx ]; then { nginx -T 2>/dev/null || cat /etc/nginx/nginx.conf /etc/nginx/conf.d/*.conf /etc/nginx/sites-enabled/* 2>/dev/null; } | sed 's/#.*//' | grep -iE "$1"; fi; }
_mask_pw() { sed -E 's/(password|credential)="[^"]*"/\1="****"/Ig; s#(<password>)[^<]*(</password>)#\1****\2#Ig'; }

# 탐지 제품 중 가이드 점검 대상 (대상 문자열: "Apache Tomcat Nginx JEUS WebtoB")
_KP=""
[ "$WEB_SRV" = apache ] && _KP="${_KP} Apache"; [ "$WEB_SRV" = nginx ] && _KP="${_KP} Nginx"; [ "$WEB_SRV" = webtob ] && _KP="${_KP} WebtoB"
[ "$WAS_SRV" = tomcat ] && _KP="${_KP} Tomcat"; [ "$WAS_SRV" = jeus ] && _KP="${_KP} JEUS"
_kt() {   # _kt 대상목록 → 탐지 제품 중 대상 (없으면 빈 값)
    local p o=""; for p in $_KP; do case " $1 " in *" $p "*) o="${o} ${p}" ;; esac; done; echo "${o# }"
}
_kres() {   # _kres 코드 대상목록 누적판정  → 제품별 판정 병합 결과 출력(대상 없음=N-A)
    local code="$1" tg="$2" r="$3"
    r=$(printf "%s" "$r" | tr -s " " | sed "s/ *|/|/g; s/| */|/g; s/[[:space:]]*$//")   # 공백 정리
    if [ -z "$_KP" ]; then result "${code}|N-A|웹서버/WAS 미탐지"
    elif [ -z "$(_kt "$tg")" ]; then result "${code}|N-A|가이드 점검 대상(${tg// /, }) 제품 미탐지 (탐지:${_KP})"
    else result "${code}|${r:-수동확인|설정 수동 확인}"; fi
}
_pw_strong() {   # 가이드 비밀번호 기준: 2종 10자 이상 또는 3종 8자 이상, 계정명·기본값·연속 문자 금지
    local pw="$1" id="$2" n=0
    [ -n "$pw" ] || return 1
    case "$pw" in *[A-Z]*) n=$((n+1)) ;; esac; case "$pw" in *[a-z]*) n=$((n+1)) ;; esac
    case "$pw" in *[0-9]*) n=$((n+1)) ;; esac; case "$pw" in *[!A-Za-z0-9]*) n=$((n+1)) ;; esac
    echo "$pw" | grep -qiE "^(tomcat|admin|s3cret|password|manager|root|jeus|webtob|changeit|<must-be-changed>)" && return 1
    [ -n "$id" ] && echo "$pw" | grep -qiF "$id" && return 1
    echo "$pw" | grep -qE '(0123|1234|2345|3456|4567|5678|6789|abcd|qwer|1111|0000|aaaa)' && return 1
    { [ "$n" -ge 2 ] && [ "${#pw}" -ge 10 ]; } || { [ "$n" -ge 3 ] && [ "${#pw}" -ge 8 ]; }
}
_TCU="${TOMCAT_HOME:+$TOMCAT_HOME/conf/tomcat-users.xml}"
_tc_admins() { [ -f "$_TCU" ] && _tcx tomcat-users.xml | grep -iE '<user ' | grep -iE 'roles="[^"]*(manager-|admin-|admin"|manager")'; }

# ── WEB-01 Default 관리자 계정명 변경 (Tomcat, JEUS) ──
evd "WEB-01" "[ -f \"$_TCU\" ] && grep -iE '<user |<role ' \"$_TCU\" | _mask_pw; for f in \$(_JX accounts.xml 5); do echo \"== \$f\"; grep -iE '<name>' \"\$f\"; done"
_r=""
if [ "$WAS_SRV" = tomcat ]; then
    _adm=$(_tc_admins)
    _bad=$(echo "$_adm" | grep -oiE 'username="(admin|tomcat|manager|administrator|root|role1|both|test|user)"' | tr '\n' ' ')
    if [ -z "$_adm" ]; then _r="양호|Tomcat 관리자 페이지 미사용 (manager/admin 역할 계정 없음)"
    elif [ -n "$_bad" ]; then _r="취약|Tomcat 관리자 계정명이 기본/유추 가능: ${_bad% }"
    else _r="양호|Tomcat 관리자 계정명 기본값 아님: $(echo "$_adm" | grep -oiE 'username="[^"]*"' | tr '\n' ' ')"; fi
fi
if [ "$WAS_SRV" = jeus ]; then
    _af=$(_JX accounts.xml 5)
    if [ -z "$_af" ]; then _j="수동확인|JEUS accounts.xml 미발견 - WebAdmin Security Domains > Users 관리자 계정명 확인"
    elif grep -hiE '<name>[[:space:]]*(administrator|admin|jeus|root)[[:space:]]*</name>' $_af >/dev/null 2>&1; then _j="취약|JEUS 기본 관리자 계정명 사용: $(grep -hoiE '<name>[[:space:]]*(administrator|admin|jeus|root)[[:space:]]*</name>' $_af | sort -u | tr '\n' ' ')"
    else _j="양호|JEUS 관리자 계정명 기본값(administrator) 아님"; fi
    _r="$(_worse "$_r" "$_j")"
fi
_kres "WEB-01" "Tomcat JEUS" "$_r"

# ── WEB-02 취약한 비밀번호 사용 제한 (Tomcat, IIS, JEUS) ──
evd "WEB-02" "[ -f \"$_TCU\" ] && grep -iE '<user ' \"$_TCU\" | _mask_pw; grep -hiE 'CredentialHandler|digest=' ${TOMCAT_HOME:-/dev/null}/conf/server.xml 2>/dev/null; for f in \$(_JX accounts.xml 5); do echo \"== \$f\"; grep -iE '<password>' \"\$f\" | sed -E 's#(<password>)(\{[A-Za-z0-9-]+\})?[^<]*#\1\2****#'; done"
_r=""
if [ "$WAS_SRV" = tomcat ]; then
    _adm=$(_tc_admins); _weak=""; _hash=0
    _tcx server.xml | grep -qiE 'CredentialHandler|digest="' && _hash=1
    while IFS= read -r _u; do
        [ -n "$_u" ] || continue
        _id=$(echo "$_u" | grep -oE 'username="[^"]*"' | cut -d'"' -f2); _pw=$(echo "$_u" | grep -oE 'password="[^"]*"' | cut -d'"' -f2)
        if [ "$_hash" = 1 ] && echo "$_pw" | grep -qE '^[0-9a-fA-F$:]{32,}$'; then continue; fi
        _pw_strong "$_pw" "$_id" || _weak="${_weak} ${_id}"
    done <<EOF
$_adm
EOF
    if [ -z "$_adm" ]; then _r="양호|Tomcat 관리자 계정 없음 (관리자 페이지 미사용)"
    elif [ -n "$_weak" ]; then _r="취약|Tomcat 관리자 비밀번호 평문 저장 + 복잡도 미충족(2종 10자/3종 8자, 기본값·계정명·연속 문자 금지):${_weak}"
    elif [ "$_hash" = 1 ]; then _r="양호|Tomcat 관리자 비밀번호 암호화 저장 (CredentialHandler/digest)"
    else _r="양호|Tomcat 관리자 비밀번호 유추 어려운 값 (평문 저장 - 암호화(CredentialHandler SHA-256 이상) 권고)"; fi
fi
if [ "$WAS_SRV" = jeus ]; then
    _af=$(_JX accounts.xml 5)
    if [ -z "$_af" ]; then _j="수동확인|JEUS accounts.xml 미발견 - 관리자 비밀번호 암호화 여부 확인"
    elif grep -hiE '<password>' $_af | grep -qviE '<password>[[:space:]]*\{(SHA-?(256|384|512)|AES|SEED|ARIA)'; then _j="취약|JEUS 관리자 비밀번호가 SHA-256 이상으로 암호화되지 않음 ({base64}/{SHA}/평문 등)"
    else _j="양호|JEUS 관리자 비밀번호 SHA-256 이상 암호화"; fi
    _r="$(_worse "$_r" "$_j")"
fi
_kres "WEB-02" "Tomcat IIS JEUS" "$_r"

# ── WEB-03 비밀번호 파일 권한 관리 (Tomcat, IIS, JEUS) : 600 이하 ──
_pf=""; [ -f "$_TCU" ] && _pf="$_TCU"
[ "$WAS_SRV" = jeus ] && _pf="${_pf} $(_JX accounts.xml 5 | tr '\n' ' ') $(_JX policies.xml 5 | tr '\n' ' ')"
evd "WEB-03" "ls -l $_pf 2>/dev/null"
_r=""; _o=""
for _f in $_pf; do _p=$(get_perm "$_f"); [ -n "$_p" ] && _perm_over "$_p" 600 && _o="${_o} ${_f}(${_p})"; done
if [ -n "$_o" ]; then _r="취약|비밀번호 파일 권한 600 초과:${_o}"
elif [ -n "${_pf// /}" ]; then _r="양호|비밀번호 파일 권한 600 이하: $(for _f in $_pf; do printf '%s(%s) ' "$_f" "$(get_perm "$_f")"; done)"
else _r="양호|비밀번호 파일(tomcat-users.xml/accounts.xml) 없음"; fi
_kres "WEB-03" "Tomcat IIS JEUS" "$_r"

# ── WEB-04 디렉터리 리스팅 방지 ──
evd "WEB-04" "_active 'Options\s'; _ngx 'autoindex'; grep -A1 -i '<param-name>listings' ${TOMCAT_HOME:-/dev/null}/conf/web.xml 2>/dev/null; grep -rh 'allow-indexing' /dev/null \$(_JX jeus-web-dd.xml) 2>/dev/null; _wtm 'Options'"
_r=""
[ "$WEB_SRV" = apache ] && { _o=$(_active "Options\s" | grep -iE "(^|[[:space:]+])Indexes" | grep -vi -- "-Indexes" | head -1)
    [ -n "$_o" ] && _r="취약|Apache 디렉터리 리스팅 설정: $(echo $_o)" || _r="양호|Apache Options Indexes 미설정"; }
[ "$WEB_SRV" = nginx ] && { _ngx '^\s*autoindex\s+on' | grep -q . && _r="취약|Nginx autoindex on" || _r="양호|Nginx autoindex 미설정/off"; }
[ "$WEB_SRV" = webtob ] && { _wtm 'Options' | grep -iE 'Indexes' | grep -qv -- '-Indexes' && _r="취약|WebtoB http.m Options Indexes" || _r="양호|WebtoB Options Indexes 미설정"; }
[ "$WAS_SRV" = tomcat ] && { _tcx web.xml | grep -A1 -i '<param-name>listings</param-name>' | grep -qi '<param-value>[[:space:]]*true' \
    && _r="$(_worse "$_r" "취약|Tomcat DefaultServlet listings=true")" || _r="$(_worse "$_r" "양호|Tomcat listings=false(기본)")"; }
[ "$WAS_SRV" = jeus ] && { grep -hiE '<allow-indexing>[[:space:]]*true' /dev/null $(_JX jeus-web-dd.xml) 2>/dev/null | grep -q . \
    && _r="$(_worse "$_r" "취약|JEUS jeus-web-dd.xml allow-indexing=true")" || _r="$(_worse "$_r" "양호|JEUS allow-indexing 미설정/false")"; }
_kres "WEB-04" "Apache Tomcat Nginx IIS JEUS WebtoB" "$_r"

# ── WEB-05 지정하지 않은 CGI/ISAPI 실행 제한 (Apache, Tomcat, Nginx, IIS, WebtoB) ──
evd "WEB-05" "{ httpd -M 2>/dev/null || apache2ctl -M 2>/dev/null; } | grep -i cgi; _active '(LoadModule\s+cgid?_module|ScriptAlias|AddHandler.*cgi-script|Options.*ExecCGI)'; _ngx '(fastcgi_pass|fcgiwrap|location.*\\.cgi)'; grep -n -iE 'CGIServlet|<servlet-name>cgi' ${TOMCAT_HOME:-/dev/null}/conf/web.xml 2>/dev/null; _wtm '(SVRTYPE|Svrtype)[[:space:]]*=[[:space:]]*CGI'"
_r=""
if [ "$WEB_SRV" = apache ]; then
    _cm=$( { httpd -M 2>/dev/null || apache2ctl -M 2>/dev/null || apachectl -M 2>/dev/null; } | grep -iE 'cgid?_module'; _active 'LoadModule\s+cgid?_module' )
    _ah=$(_active 'AddHandler\s.*cgi-script' | head -1); _ex=$(_active 'Options\s' | grep -iE '(^|[[:space:]+])ExecCGI' | grep -vi -- '-ExecCGI' | head -1)
    if [ -z "$_cm" ]; then _r="양호|Apache CGI 모듈(cgi/cgid) 미사용"
    elif [ -n "$_ah" ]; then _r="취약|Apache CGI 확장자 매핑으로 지정 디렉터리 외 실행 가능: $(echo $_ah)"
    elif [ -n "$_ex" ]; then _r="수동확인|Apache Options ExecCGI 설정: $(echo $_ex) - 지정한 CGI 디렉터리로만 제한되는지 확인"
    else _r="양호|Apache CGI 실행을 ScriptAlias 지정 디렉터리로 제한 ($(_active 'ScriptAlias\s' | awk '{print $2"→"$3}' | tr '\n' ' '))"; fi
fi
if [ "$WEB_SRV" = nginx ]; then
    if _ngx '(fcgiwrap|location[^{]*\\\.(cgi|pl)|location[^{]*cgi-bin)' | grep -q .; then _r="취약|Nginx CGI(fcgiwrap/.cgi location) 실행 설정: $(_ngx '(fcgiwrap|location[^{]*cgi)' | head -2 | tr -s ' ' | tr '\n' ' ')"
    elif _ngx 'fastcgi_pass' | grep -q .; then _r="수동확인|Nginx FastCGI 사용(PHP-FPM 등): $(_ngx 'fastcgi_pass' | head -2 | tr -s ' ' | tr '\n' ' ') - 실행 경로·확장자 제한 확인"
    else _r="양호|Nginx CGI/FastCGI 미사용"; fi
fi
[ "$WEB_SRV" = webtob ] && { _wtm '(SVRTYPE|Svrtype)[[:space:]]*=[[:space:]]*CGI' | grep -q . && _r="취약|WebtoB http.m CGI 서버 타입 활성: $(_wtm '(SVRTYPE|Svrtype)[[:space:]]*=[[:space:]]*CGI' | head -2 | tr -s ' ' | tr '\n' ' ')" || _r="양호|WebtoB CGI 서버 타입 미사용"; }
[ "$WAS_SRV" = tomcat ] && { _f=$(_tc_webxml_active "CGIServlet") && _r="$(_worse "$_r" "취약|Tomcat CGIServlet 매핑 활성: ${_f}")" || _r="$(_worse "$_r" "양호|Tomcat CGI 매핑 비활성(기본)")"; }
_kres "WEB-05" "Apache Tomcat Nginx IIS WebtoB" "$_r"

# ── WEB-06 상위 디렉터리 접근 제한 (Apache, Tomcat, Nginx, IIS, WebtoB) ──
evd "WEB-06" "_active 'AllowOverride'; _ngx 'auth_basic'; grep -hiE 'allowLinking' ${TOMCAT_HOME:-/dev/null}/conf/server.xml ${TOMCAT_HOME:-/dev/null}/conf/context.xml 2>/dev/null; _wtm 'UpperDirRestrict'"
_r=""
if [ "$WEB_SRV" = apache ]; then
    _ao=$(_active 'AllowOverride\s' | awk '{print $2}' | sort -uf | tr '\n' ' ')
    if echo " $_ao" | grep -qiE ' (AuthConfig|All)'; then _r="양호|Apache AllowOverride AuthConfig/All 설정 - .htaccess 사용자 인증으로 디렉터리 접근 제한 가능 (${_ao% })"
    else _r="취약|Apache AllowOverride ${_ao:-미설정(None)} - 가이드 조치: AllowOverride AuthConfig + .htaccess 사용자 인증으로 상위·주요 디렉터리 접근 제한"; fi
fi
[ "$WEB_SRV" = nginx ] && { _ngx '^\s*auth_basic\s' | grep -qv 'off' && _r="양호|Nginx auth_basic 으로 디렉터리 접근 제한 설정" || _r="수동확인|Nginx 디렉터리 접근 제한(auth_basic) 미설정 - 접근 제한이 필요한 디렉터리 존재 여부 확인"; }
[ "$WEB_SRV" = webtob ] && { _u=$(_wtm 'UpperDirRestrict' | head -1); [ -n "$_u" ] && _r="수동확인|WebtoB $(echo $_u) - 상위 디렉터리 접근 제한 설정 확인" || _r="수동확인|WebtoB UpperDirRestrict 미설정 - 상위 디렉터리 접근 제한 확인"; }
[ "$WAS_SRV" = tomcat ] && { { _tcx server.xml; _tcx context.xml; } | grep -qiE 'allowLinking="true"' && _r="$(_worse "$_r" "취약|Tomcat Context allowLinking=true")" || _r="$(_worse "$_r" "양호|Tomcat allowLinking 미설정(false)")"; }
_kres "WEB-06" "Apache Tomcat Nginx IIS WebtoB" "$_r"

# ── WEB-07 웹 서비스 경로 내 불필요한 파일 제거 (기본 매뉴얼·샘플) ──
_df=""
if [ "$WEB_SRV" = apache ]; then
    for _d in "$(_apache_root)/manual" "$(_apache_root)/htdocs/manual" /var/www/manual /usr/share/httpd/manual /usr/share/doc/apache2-doc/manual /usr/local/apache2/manual; do [ -d "$_d" ] && _df="${_df} ${_d}"; done
fi
if [ "$WEB_SRV" = nginx ]; then
    for _d in $(_web_docroots) /usr/share/nginx/html; do [ -f "$_d/index.html" ] && grep -qi 'Welcome to nginx' "$_d/index.html" 2>/dev/null && _df="${_df} ${_d}/index.html(기본 페이지)"; done
fi
[ -n "$TOMCAT_HOME" ] && for _d in docs examples; do [ -d "$TOMCAT_HOME/webapps/$_d" ] && _df="${_df} $TOMCAT_HOME/webapps/$_d"; done
[ -n "$JEUS_HOME" ] && for _d in docs/manuals samples; do [ -d "$JEUS_HOME/$_d" ] && _df="${_df} $JEUS_HOME/$_d"; done
[ -n "$_WT_HOME" ] && for _d in docs/manuals samples; do [ -d "$_WT_HOME/$_d" ] && _df="${_df} $_WT_HOME/$_d"; done
_df=$(echo $_df | tr ' ' '\n' | sort -u | tr '\n' ' ')
evd "WEB-07" "ls -ld $_df 2>/dev/null; ls ${TOMCAT_HOME:-/nonexistent}/webapps 2>/dev/null"
[ -n "${_df// /}" ] && _r="취약|기본 생성 매뉴얼·샘플 파일/디렉터리 존재: ${_df% }" || _r="양호|기본 매뉴얼·샘플 디렉터리 없음"
_kres "WEB-07" "Apache Tomcat Nginx IIS JEUS WebtoB" "$_r"

# ── WEB-08 파일 업로드·다운로드 용량 제한 ──
evd "WEB-08" "_active 'LimitRequestBody'; _ngx 'client_max_body_size'; grep -hoE 'maxPostSize=\"[^\"]*\"' ${TOMCAT_HOME:-/dev/null}/conf/server.xml 2>/dev/null; grep -rhE '<max-(file|request)-size>' ${TOMCAT_HOME:-/dev/null}/conf/web.xml ${TOMCAT_HOME:-/dev/null}/webapps/*/WEB-INF/web.xml \$(_JX web.xml) 2>/dev/null | head; _wtm 'LimitRequestBody'"
_r=""
[ "$WEB_SRV" = apache ] && { _v=$(_active 'LimitRequestBody\s+[0-9]' | awk '{print $2}' | sort -n | tail -1)
    [ -n "$_v" ] && [ "$_v" -gt 0 ] 2>/dev/null && _r="양호|Apache LimitRequestBody ${_v} bytes" || _r="취약|Apache LimitRequestBody 미설정(또는 0=무제한)"; }
[ "$WEB_SRV" = nginx ] && { _v=$(_ngx '^\s*client_max_body_size\s' | awk '{print $2}' | tr -d ';' | tr '\n' ' ')
    echo " $_v" | grep -qE ' 0( |$)' && _r="취약|Nginx client_max_body_size 0 (제한 해제)" || _r="양호|Nginx client_max_body_size ${_v:-미설정(기본 1m 제한)}"; }
[ "$WEB_SRV" = webtob ] && { _wtm 'LimitRequestBody' | grep -q . && _r="양호|WebtoB $(_wtm 'LimitRequestBody' | head -1 | tr -s ' ')" || _r="취약|WebtoB LimitRequestBody 미설정"; }
if [ "$WAS_SRV" = tomcat ]; then
    _mp=$(_tcx server.xml | grep -oE 'maxPostSize="[^"]*"' | cut -d'"' -f2 | tr '\n' ' ')
    _mf=$(grep -rhE '<max-(file|request)-size>' "$TOMCAT_HOME/conf/web.xml" "$TOMCAT_HOME"/webapps/*/WEB-INF/web.xml 2>/dev/null | head -1)
    if echo " $_mp" | grep -qE ' -[0-9]'; then _t="취약|Tomcat maxPostSize 음수(제한 해제): ${_mp}"
    elif [ -n "${_mp// /}" ] || [ -n "$_mf" ]; then _t="양호|Tomcat 용량 제한 설정 (maxPostSize=${_mp:-기본 2MB}${_mf:+, multipart-config })"
    else _t="수동확인|Tomcat maxPostSize·multipart-config 미설정 (폼 POST 기본 2MB만 적용) - 애플리케이션 업로드 용량 제한 확인"; fi
    _r="$(_worse "$_r" "$_t")"
fi
[ "$WAS_SRV" = jeus ] && { grep -hE '<max-file-size>[[:space:]]*[0-9]' /dev/null $(_JX web.xml) 2>/dev/null | grep -q . && _r="$(_worse "$_r" "양호|JEUS multipart max-file-size 설정")" || _r="$(_worse "$_r" "취약|JEUS web.xml max-file-size 미설정 (가이드: 출력값 없으면 취약)")"; }
_kres "WEB-08" "Apache Tomcat Nginx IIS JEUS WebtoB" "$_r"

# ── WEB-09 웹 서비스 프로세스 권한 제한 ──
evd "WEB-09" "ps -eo user,pid,ppid,args 2>/dev/null | grep -E '[h]ttpd|[a]pache2|[n]ginx|[c]atalina|[j]eus|[w]sm|[h]tl' | cut -c1-200"
_r=""
_puser() {   # 프로세스 구동 계정 (arg2=child: root 마스터 + 비root 작업 프로세스 구조면 작업 프로세스 계정만)
    local u nr; u=$(ps -eo user=,args= 2>/dev/null | grep -E "$1" | grep -v grep | awk '{print $1}' | sort -u | tr '\n' ' ')
    if [ "$2" = child ]; then nr=$(echo $u | tr ' ' '\n' | grep -vx root | tr '\n' ' '); [ -n "$nr" ] && u="$nr"; fi
    echo "$u"
}
_isroot() { local u; for u in $1; do [ "$u" = root ] || [ "$(id -u "$u" 2>/dev/null)" = 0 ] && return 0; done; return 1; }
if [ "$WEB_SRV" = apache ]; then   # 마스터는 root 기동이 정상(포트 바인딩), 요청 처리 작업 프로세스 계정 확인
    _u=$(_puser '(httpd|apache2)( |$)' child); [ -z "${_u// /}" ] && _u=$(_active 'User\s' | awk '{print $2}' | head -1)
    case "$_u" in \$*) _u=$(grep -hE "^\s*(export\s+)?APACHE_RUN_USER=" /etc/apache2/envvars 2>/dev/null | tail -1 | cut -d= -f2 | tr -d "\"' ") ;; esac
    if [ -z "${_u// /}" ]; then _r="수동확인|Apache 구동 계정 확인 불가"; elif _isroot "$_u"; then _r="취약|Apache 작업 프로세스가 관리자(root) 권한: ${_u}"; else _r="양호|Apache 작업 프로세스 계정: ${_u% }"; fi
fi
if [ "$WEB_SRV" = nginx ]; then
    _u=$(_puser 'nginx: (worker|master)' child); [ -z "${_u// /}" ] && _u=$(_ngx '^\s*user\s' | awk '{print $2}' | tr -d ';' | head -1)
    if [ -z "${_u// /}" ]; then _r="수동확인|Nginx worker 계정 확인 불가 (미실행)"; elif _isroot "$_u"; then _r="취약|Nginx worker 가 관리자(root) 권한: ${_u}"; else _r="양호|Nginx worker 계정: ${_u% }"; fi
fi
if [ "$WEB_SRV" = webtob ]; then
    _u=$(_puser '(wsm|htl|hth)( |$)' ''); if [ -z "${_u// /}" ]; then _r="수동확인|WebtoB 프로세스 미실행 - 구동 계정 확인"; elif _isroot "$_u"; then _r="취약|WebtoB 가 관리자(root) 권한으로 구동: ${_u}"; else _r="양호|WebtoB 구동 계정: ${_u% }"; fi
fi
if [ "$WAS_SRV" = tomcat ]; then
    _u=$(_puser 'org\.apache\.catalina' ''); if [ -z "${_u// /}" ]; then _t="수동확인|Tomcat 미실행 - tomcat.service User 확인"; elif _isroot "$_u"; then _t="취약|Tomcat 이 관리자(root) 권한으로 구동: ${_u}"; else _t="양호|Tomcat 구동 계정: ${_u% }"; fi
    _r="$(_worse "$_r" "$_t")"
fi
if [ "$WAS_SRV" = jeus ]; then
    _u=$(_puser 'jeus' ''); if [ -z "${_u// /}" ]; then _t="수동확인|JEUS 미실행 - 구동 계정 확인"; elif _isroot "$_u"; then _t="취약|JEUS 가 관리자(root) 권한으로 구동: ${_u}"; else _t="양호|JEUS 구동 계정: ${_u% }"; fi
    _r="$(_worse "$_r" "$_t")"
fi
_kres "WEB-09" "Apache Tomcat Nginx IIS JEUS WebtoB" "$_r"

# ── WEB-10 불필요한 프록시 설정 제한 ──
evd "WEB-10" "_active '(ProxyRequests|ProxyPass)'; _ngx 'proxy_pass'; grep -hoE 'proxy(Name|Port)=\"[^\"]*\"' ${TOMCAT_HOME:-/dev/null}/conf/server.xml 2>/dev/null; ls -d \${JEUS_HOME:-/nonexistent}/*/ReverseProxy 2>/dev/null; _wtm 'REVERSE_PROXY'"
_r=""
if [ "$WEB_SRV" = apache ]; then
    if _active 'ProxyRequests\s+On' | grep -q .; then _r="취약|Apache ProxyRequests On (포워드 프록시 허용)"
    elif _active 'ProxyPass(Match)?\s' | grep -q .; then _r="수동확인|Apache 역프록시 설정: $(_active 'ProxyPass(Match)?\s' | head -2 | tr -s ' ' | tr '\n' ' ')- 업무상 필요 여부 확인 (불필요 시 취약)"
    else _r="양호|Apache 프록시 설정 없음"; fi
fi
[ "$WEB_SRV" = nginx ] && { _ngx '^\s*proxy_pass\s' | grep -q . && _r="수동확인|Nginx proxy_pass 설정: $(_ngx '^\s*proxy_pass\s' | head -2 | tr -s ' ' | tr '\n' ' ')- 업무상 필요 여부 확인 (불필요 시 취약)" || _r="양호|Nginx 프록시 설정 없음"; }
[ "$WEB_SRV" = webtob ] && { _wtm 'REVERSE_PROXY' | grep -q . && _r="수동확인|WebtoB REVERSE_PROXY 설정 - 업무상 필요 여부 확인" || _r="양호|WebtoB 프록시 설정 없음"; }
[ "$WAS_SRV" = tomcat ] && { _tcx server.xml | grep -qE 'proxyName=|proxyPort=' && _r="$(_worse "$_r" "수동확인|Tomcat Connector proxyName/proxyPort 설정 - 업무상 필요 여부 확인")" || _r="$(_worse "$_r" "양호|Tomcat Connector 프록시 설정 없음")"; }
[ "$WAS_SRV" = jeus ] && { ls -d "$JEUS_HOME"/*/ReverseProxy "$JEUS_HOME"/ReverseProxy >/dev/null 2>&1 && _r="$(_worse "$_r" "수동확인|JEUS ReverseProxy 애플리케이션 존재 - 필요 여부 확인")" || _r="$(_worse "$_r" "양호|JEUS ReverseProxy 없음")"; }
_kres "WEB-10" "Apache Tomcat Nginx IIS JEUS WebtoB" "$_r"

# ── WEB-11 웹 서비스 경로 설정 (업무 영역 분리, 기본 경로) ──
_roots="$(_web_docroots | tr '\n' ' ') $(_tcx server.xml | grep -oE 'docBase="[^"]*"' | cut -d'"' -f2 | tr '\n' ' ') $(_wtm 'DOCROOT' | grep -oE '"[^"]*"' | tr -d '"' | tr '\n' ' ')"
evd "WEB-11" "echo 'DocumentRoot/root/docBase/DOCROOT: $_roots'"
_bad=""; _def=""
for _d in $_roots; do
    case "${_d%/}" in
    ""|/|/etc|/usr|/bin|/sbin|/root|/home|/var|/opt|/tmp|/boot|/lib|/lib64|/proc|/sys|/dev) _bad="${_bad} ${_d}" ;;
    /var/www/html|/var/www|/usr/local/apache*/htdocs|/usr/local/httpd/htdocs|/usr/share/nginx/html|/etc/nginx/html|*/webtob/docs|html) _def="${_def} ${_d}" ;;
    esac
done
if [ -n "$_bad" ]; then _r="취약|웹 서비스 경로가 시스템·업무 영역과 분리되지 않음:${_bad}"
elif [ -n "$_def" ]; then _r="수동확인|설치 기본 경로 사용:${_def} - 기타 업무와 분리 여부·불필요 경로 확인 (가이드 조치: 별도 경로 지정)"
elif [ -n "${_roots// /}" ]; then _r="양호|별도 웹 서비스 경로 사용: ${_roots}"
else _r="수동확인|웹 서비스 경로 확인 불가"; fi
_kres "WEB-11" "Apache Tomcat Nginx IIS JEUS WebtoB" "$_r"

# ── WEB-12 웹 서비스 링크 사용 금지 ──
evd "WEB-12" "_active 'Options\s'; _ngx 'disable_symlinks'; grep -hiE 'allowLinking' ${TOMCAT_HOME:-/dev/null}/conf/server.xml ${TOMCAT_HOME:-/dev/null}/conf/context.xml 2>/dev/null; grep -hA3 '<aliasing>' /dev/null \$(_JX jeus-web-dd.xml) 2>/dev/null; [ -f \"$_WT_M\" ] && grep -A3 '^\*ALIAS' \"$_WT_M\""
_r=""
if [ "$WEB_SRV" = apache ]; then
    _ol=$(_active 'Options\s')
    if [ -z "$_ol" ]; then _r="취약|Apache Options 미설정 (2.4 기본값 FollowSymLinks - 링크 허용)"
    elif echo "$_ol" | grep -iE '(^|[[:space:]+])FollowSymLinks' | grep -qvi -- '-FollowSymLinks'; then _r="취약|Apache FollowSymLinks 허용: $(echo "$_ol" | grep -i FollowSymLinks | grep -vi -- -FollowSymLinks | head -1 | tr -s ' ' | sed 's/^ //')"
    elif echo "$_ol" | grep -qi 'SymLinksIfOwnerMatch'; then _r="수동확인|Apache SymLinksIfOwnerMatch (소유자 일치 시 링크 허용) - 링크 사용 필요성 확인"
    else _r="양호|Apache FollowSymLinks 미허용"; fi
fi
[ "$WEB_SRV" = nginx ] && { _ngx '^\s*disable_symlinks\s+(on|if_not_owner)' | grep -q . && _r="양호|Nginx disable_symlinks 설정" || _r="취약|Nginx disable_symlinks 미설정 (기본값 off - 링크 허용)"; }
[ "$WEB_SRV" = webtob ] && { grep -A5 '^\*ALIAS' "$_WT_M" 2>/dev/null | grep -v '^[[:space:]]*#' | grep -qiE 'URI[[:space:]]*=' && _r="취약|WebtoB *ALIAS 설정 존재: $(grep -A5 '^\*ALIAS' "$_WT_M" | grep -iE 'URI[[:space:]]*=' | grep -v '^[[:space:]]*#' | head -2 | tr -s ' ' | tr '\n' ' ')" || _r="양호|WebtoB ALIAS 미사용"; }
[ "$WAS_SRV" = tomcat ] && { { _tcx server.xml; _tcx context.xml; } | grep -qiE 'allowLinking="true"' && _r="$(_worse "$_r" "취약|Tomcat allowLinking=true")" || _r="$(_worse "$_r" "양호|Tomcat allowLinking 미설정(false)")"; }
[ "$WAS_SRV" = jeus ] && { grep -hl '<aliasing>' /dev/null $(_JX jeus-web-dd.xml) 2>/dev/null | grep -q . && _r="$(_worse "$_r" "취약|JEUS jeus-web-dd.xml aliasing 설정 존재")" || _r="$(_worse "$_r" "양호|JEUS aliasing 미사용")"; }
_kres "WEB-12" "Apache Tomcat Nginx IIS JEUS WebtoB" "$_r"

# ── WEB-13 웹 서비스 설정 파일 노출 제한 (Tomcat, IIS, JEUS) : DB 연결 설정 파일 600 ──
_dbf=""
if [ -n "$TOMCAT_HOME" ]; then
    for _f in "$TOMCAT_HOME/conf/server.xml" "$TOMCAT_HOME/conf/context.xml" "$TOMCAT_HOME"/conf/Catalina/*/*.xml "$TOMCAT_HOME"/webapps/*/META-INF/context.xml; do
        [ -f "$_f" ] && awk '/<!--/{c=1} !c{print} /-->/{c=0}' "$_f" | grep -qiE 'javax\.sql\.DataSource|jdbc:' && _dbf="${_dbf} ${_f}"
    done
fi
[ "$WAS_SRV" = jeus ] && for _f in $(_JX domain.xml 5) $(_JX jeus-web-dd.xml); do grep -qiE '<data-?source|jdbc:' "$_f" 2>/dev/null && _dbf="${_dbf} ${_f}"; done
evd "WEB-13" "ls -l $_dbf 2>/dev/null; for f in $_dbf; do echo \"== \$f\"; grep -iE 'jdbc:|DataSource|username' \"\$f\" | _mask_pw | head -5; done"
_o=""; for _f in $_dbf; do _p=$(get_perm "$_f"); [ -n "$_p" ] && _perm_over "$_p" 600 && _o="${_o} ${_f}(${_p})"; done
if [ -n "$_o" ]; then _r="취약|DB 연결 정보 포함 설정 파일 권한 600 초과(일반 사용자 접근 가능):${_o}"
elif [ -n "$_dbf" ]; then _r="양호|DB 연결 설정 파일 권한 600 이하:${_dbf}"
else _r="양호|WAS 설정 파일에 DB 연결 리소스 없음"; fi
_kres "WEB-13" "Tomcat IIS JEUS" "$_r"

# ── WEB-14 웹 서비스 경로 내 파일 접근 통제 : 주요 설정 파일 750 이하(일반 사용자 권한 없음) ──
_cf="$(_web_conf_files | tr '\n' ' ')"
[ -n "$TOMCAT_HOME" ] && for _f in server.xml web.xml context.xml tomcat-users.xml; do [ -f "$TOMCAT_HOME/conf/$_f" ] && _cf="${_cf} $TOMCAT_HOME/conf/$_f"; done
[ "$WAS_SRV" = jeus ] && _cf="${_cf} $(_JX accounts.xml 5 | tr '\n' ' ') $(_JX domain.xml 5 | tr '\n' ' ')"
[ -n "$_WT_M" ] && _cf="${_cf} ${_WT_M}"
evd "WEB-14" "ls -l $_cf 2>/dev/null"
_o=""; for _f in $_cf; do _p=$(get_perm "$_f"); [ -n "$_p" ] && _perm_over "$_p" 750 && _o="${_o} ${_f}(${_p})"; done
if [ -n "$_o" ]; then _r="취약|주요 설정 파일에 일반 사용자 권한 부여(가이드 기준 750 이하):${_o}"
elif [ -n "${_cf// /}" ]; then _r="양호|주요 설정 파일 권한 750 이하 ($(echo $_cf | wc -w)개)"
else _r="수동확인|주요 설정 파일 확인 불가"; fi
_kres "WEB-14" "Apache Tomcat Nginx IIS JEUS WebtoB" "$_r"

# ── WEB-15 불필요한 스크립트 매핑 제거 (Tomcat, IIS, JEUS) ──
evd "WEB-15" "awk '/<!--/{c=1} !c{print} /-->/{c=0}' ${TOMCAT_HOME:-/dev/null}/conf/web.xml 2>/dev/null | grep -A2 '<servlet-mapping>' | grep -E 'servlet-name|url-pattern'; grep -hA2 '<servlet-mapping>' /dev/null \$(_JX web.xml) 2>/dev/null | grep -E 'servlet-name|url-pattern' | head -20"
_r=""
if [ "$WAS_SRV" = tomcat ]; then
    _sm=$(_tcx web.xml | grep -A1 '<servlet-mapping>' | grep -oE '<servlet-name>[^<]+' | sed 's/<servlet-name>//' | sort -u | grep -vxE 'default|jsp' | tr '\n' ' ')
    [ -n "$_sm" ] && _r="취약|Tomcat conf/web.xml 기본 외 스크립트 매핑 활성: ${_sm}(cgi/ssi/invoker 등 불필요 시 제거)" || _r="양호|Tomcat conf/web.xml 매핑 기본값(default, jsp)만 사용"
fi
[ "$WAS_SRV" = jeus ] && _r="$(_worse "$_r" "수동확인|JEUS web.xml servlet-mapping 목록(증적) 중 불필요 매핑 확인")"
_kres "WEB-15" "Tomcat IIS JEUS" "$_r"

# ── WEB-16 웹 서비스 헤더 정보 노출 제한 ──
evd "WEB-16" "_active 'Server(Tokens|Signature)'; _ngx 'server_tokens'; grep -hoE 'server=\"[^\"]*\"|showServerInfo=\"[^\"]*\"' ${TOMCAT_HOME:-/dev/null}/conf/server.xml 2>/dev/null; grep -rh 'serverInfo' /dev/null \$(_JX JEUSMain.xml) \$(_JX domain.xml) 2>/dev/null; _wtm 'Server(Tokens|Signature)'"
_r=""
if [ "$WEB_SRV" = apache ]; then
    _tk=$(_active 'ServerTokens\s' | tail -1 | awk '{print $2}'); _sg=$(_active 'ServerSignature\s' | tail -1 | awk '{print $2}')
    case "$(echo "$_tk" | tr 'A-Z' 'a-z')" in prod|productonly) _a=1 ;; *) _a=0 ;; esac
    if [ "$_a" = 1 ] && [ "$(echo "${_sg:-off}" | tr 'A-Z' 'a-z')" = off ]; then _r="양호|Apache ServerTokens ${_tk}, ServerSignature ${_sg:-Off(기본)}"
    else _r="취약|Apache 헤더 정보 노출 (ServerTokens=${_tk:-미설정(Full)}, ServerSignature=${_sg:-미설정}) - 가이드: ServerTokens Prod + ServerSignature Off"; fi
fi
[ "$WEB_SRV" = nginx ] && { _ngx '^\s*server_tokens\s+off' | grep -q . && _r="양호|Nginx server_tokens off" || _r="취약|Nginx server_tokens off 미설정 (버전 노출)"; }
[ "$WEB_SRV" = webtob ] && { _tk=$(_wtm 'ServerTokens' | head -1); echo "$_tk" | grep -qiE 'Prod|ProductOnly|Off' && _r="양호|WebtoB $(echo $_tk)" || _r="취약|WebtoB ServerTokens Prod(ProductOnly) 미설정: ${_tk:-미설정}"; }
if [ "$WAS_SRV" = tomcat ]; then
    _sv=$(_tcx server.xml | grep -oE '<Connector[^>]*server="[^"]*"' | head -1); _si=$(_tcx server.xml | grep -oE 'showServerInfo="false"' | head -1)
    if [ -n "$_sv" ] && [ -n "$_si" ]; then _t="양호|Tomcat Connector server 속성 변경 + ErrorReportValve showServerInfo=false"
    elif [ -n "$_sv" ]; then _t="양호|Tomcat Connector server 속성 변경 (에러 페이지 버전 노출은 WEB-22 참고, showServerInfo=false 권고)"
    else _t="취약|Tomcat Connector server 속성 미설정 - 가이드: server 값을 임의 정보로 변경 + showServerInfo=false"; fi
    _r="$(_worse "$_r" "$_t")"
fi
[ "$WAS_SRV" = jeus ] && { grep -rhiE 'serverInfo=false|<field-name>' /dev/null $(_JX JEUSMain.xml) $(_JX domain.xml) 2>/dev/null | grep -q . && _r="$(_worse "$_r" "양호|JEUS 서버 정보 헤더 제한 설정")" || _r="$(_worse "$_r" "취약|JEUS -Djeus.servlet.response.header.serverInfo=false / response-header 미설정")"; }
_kres "WEB-16" "Apache Tomcat Nginx IIS JEUS WebtoB" "$_r"

# ── WEB-17 가상 디렉터리 삭제 (Apache, Tomcat, Nginx, WebtoB) ──
evd "WEB-17" "_active 'Alias\s'; _ngx '^\s*alias\s'; grep -hoE '<Context[^>]*path=\"[^\"]*\"' ${TOMCAT_HOME:-/dev/null}/conf/server.xml 2>/dev/null; ls ${TOMCAT_HOME:-/nonexistent}/conf/Catalina/*/ 2>/dev/null; [ -f \"$_WT_M\" ] && grep -A5 '^\*ALIAS' \"$_WT_M\""
_r=""
if [ "$WEB_SRV" = apache ]; then
    _al=$(_active 'Alias\s' | awk '{print $2}' | sort -u | tr '\n' ' ')
    _dal=$(echo " $_al" | grep -oE ' /(icons|manual|error|noindex)/?' | tr -d ' ' | tr '\n' ' ')
    if [ -n "$_dal" ]; then _r="취약|Apache 기본 가상 디렉터리(Alias) 존재: ${_dal}(불필요 시 삭제)"
    elif [ -n "$_al" ]; then _r="수동확인|Apache Alias 가상 디렉터리: ${_al}- 업무상 필요 여부 확인"
    else _r="양호|Apache 가상 디렉터리(Alias) 없음"; fi
fi
[ "$WEB_SRV" = nginx ] && { _al=$(_ngx '^\s*alias\s' | awk '{print $2}' | tr -d ';' | tr '\n' ' '); [ -n "$_al" ] && _r="수동확인|Nginx alias 가상 디렉터리: ${_al}- 업무상 필요 여부 확인" || _r="양호|Nginx alias 가상 디렉터리 없음"; }
[ "$WEB_SRV" = webtob ] && { grep -A5 '^\*ALIAS' "$_WT_M" 2>/dev/null | grep -v '^[[:space:]]*#' | grep -qiE 'URI[[:space:]]*=' && _r="수동확인|WebtoB *ALIAS 가상 디렉터리 존재 - 업무상 필요 여부 확인" || _r="양호|WebtoB 가상 디렉터리 없음"; }
if [ "$WAS_SRV" = tomcat ]; then
    _cx=$( { _tcx server.xml | grep -oE '<Context[^>]*path="[^"]+"' | grep -oE 'path="[^"]*"'; ls "$TOMCAT_HOME"/conf/Catalina/*/*.xml 2>/dev/null | xargs -n1 basename 2>/dev/null; } | tr '\n' ' ')
    [ -n "${_cx// /}" ] && _r="$(_worse "$_r" "수동확인|Tomcat Context 가상 디렉터리: ${_cx}- 업무상 필요 여부 확인")" || _r="$(_worse "$_r" "양호|Tomcat 별도 Context 가상 디렉터리 없음")"
fi
_kres "WEB-17" "Apache Tomcat Nginx WebtoB" "$_r"

# ── WEB-18 WebDAV 비활성화 (Apache, Nginx, IIS, WebtoB) ──
evd "WEB-18" "_active '(Dav\s|LoadModule\s+dav)'; _ngx 'dav_'; _wtm 'Method'"
_r=""
[ "$WEB_SRV" = apache ] && { _dv=$(_active 'Dav\s+On' | head -1); [ -n "$_dv" ] && _r="취약|Apache WebDAV 활성 (Dav On)" || _r="양호|Apache Dav On 설정 없음 (WebDAV 비활성)"; }
[ "$WEB_SRV" = nginx ] && { _ngx '^\s*dav_methods\s' | grep -qvi 'off' && _r="취약|Nginx dav_methods 설정: $(_ngx '^\s*dav_methods' | head -1 | tr -s ' ')" || _r="양호|Nginx WebDAV(dav_methods) 미사용"; }
[ "$WEB_SRV" = webtob ] && { _wtm 'Method[[:space:]]*=' | grep -qiE 'PUT|DELETE|PROPFIND|MKCOL|COPY|MOVE' && _r="취약|WebtoB WebDAV 메소드 허용: $(_wtm 'Method[[:space:]]*=' | head -1 | tr -s ' ')" || _r="양호|WebtoB WebDAV 메소드 미허용"; }
_kres "WEB-18" "Apache Nginx IIS WebtoB" "$_r"

# ── WEB-19 SSI 사용 제한 (Apache, Tomcat, Nginx, IIS, WebtoB) ──
evd "WEB-19" "_active 'Options\s' | grep -i Includes; _ngx '^\s*ssi\s'; grep -n -iE 'SSIServlet|SSIFilter' ${TOMCAT_HOME:-/dev/null}/conf/web.xml 2>/dev/null; _wtm '(SvrType|SVRTYPE)[[:space:]]*=[[:space:]]*SSI'"
_r=""
[ "$WEB_SRV" = apache ] && { _o=$(_active 'Options\s' | grep -iE '(^|[[:space:]+])Includes(NOEXEC)?' | grep -vi -- '-Includes' | head -1); [ -n "$_o" ] && _r="취약|Apache SSI 활성: $(echo $_o)" || _r="양호|Apache Options Includes 미사용"; }
[ "$WEB_SRV" = nginx ] && { _ngx '^\s*ssi\s+on' | grep -q . && _r="취약|Nginx ssi on" || _r="양호|Nginx ssi 미사용"; }
[ "$WEB_SRV" = webtob ] && { _wtm '(SvrType|SVRTYPE)[[:space:]]*=[[:space:]]*SSI' | grep -q . && _r="취약|WebtoB SSI 서버 타입 활성" || _r="양호|WebtoB SSI 미사용"; }
[ "$WAS_SRV" = tomcat ] && { _f=$(_tc_webxml_active "SSIServlet|SSIFilter") && _r="$(_worse "$_r" "취약|Tomcat SSI 활성: ${_f}")" || _r="$(_worse "$_r" "양호|Tomcat SSIServlet/SSIFilter 미사용")"; }
_kres "WEB-19" "Apache Tomcat Nginx IIS WebtoB" "$_r"

# ── WEB-20 SSL/TLS 활성화 (Apache, Nginx, IIS, WebtoB) ──
evd "WEB-20" "{ httpd -M 2>/dev/null || apache2ctl -M 2>/dev/null; } | grep -i ssl; _active '(SSLEngine|Listen|SSLProtocol)'; _ngx '(listen|ssl_protocols|ssl_certificate\s)'; _wtm '(SSLFLAG|SSLNAME)'; { ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null; } | grep -E ':(443|8443) '"
_LBN=" (로드밸런서·프록시에서 TLS 종료 시 해당 구간 설정 증빙으로 판단)"
_r=""
[ "$WEB_SRV" = apache ] && { _active 'SSLEngine\s+on' | grep -q . && _r="양호|Apache SSLEngine on (SSL/TLS 활성)" || _r="취약|Apache SSL/TLS 미설정 (SSLEngine on 없음)${_LBN}"; }
[ "$WEB_SRV" = nginx ] && { _ngx '^\s*listen\s[^;]*\sssl|^\s*ssl\s+on' | grep -q . && _r="양호|Nginx listen ssl (SSL/TLS 활성)" || _r="취약|Nginx SSL/TLS 미설정 (listen ... ssl 없음)${_LBN}"; }
[ "$WEB_SRV" = webtob ] && { _wtm 'SSLFLAG[[:space:]]*=[[:space:]]*Y' | grep -q . && _r="양호|WebtoB SSLFLAG=Y" || _r="취약|WebtoB SSLFLAG 미설정${_LBN}"; }
_kres "WEB-20" "Apache Nginx IIS WebtoB" "$_r"

# ── WEB-21 HTTP 리디렉션 (Apache, Nginx, IIS, WebtoB) ──
evd "WEB-21" "_active '(Redirect|RewriteRule|RewriteCond)'; _ngx '(return\s+30[1278]|rewrite).*https'; _wtm 'URLRewrite'"
_r=""
[ "$WEB_SRV" = apache ] && { _active '(Redirect(Permanent|Match)?\s.*https://|RewriteRule\s.*https://)' | grep -q . && _r="양호|Apache HTTP→HTTPS 리디렉션 설정" || _r="취약|Apache HTTP→HTTPS 리디렉션 미설정${_LBN}"; }
[ "$WEB_SRV" = nginx ] && { _ngx '(return\s+30[1278]\s+https://|rewrite\s.*https://)' | grep -q . && _r="양호|Nginx HTTPS 리디렉션(return 301 https://) 설정" || _r="취약|Nginx HTTP→HTTPS 리디렉션 미설정${_LBN}"; }
if [ "$WEB_SRV" = webtob ]; then
    _rc=$(_wtm 'URLRewriteConfig' | grep -oE '"[^"]*"' | tr -d '"' | head -1); case "$_rc" in /*) ;; ?*) _rc="$_WT_HOME/$_rc" ;; esac
    _wtm 'URLRewrite[[:space:]]*=[[:space:]]*Y' | grep -q . && grep -qiE 'RewriteRule.*https://' "$_rc" 2>/dev/null && _r="양호|WebtoB URLRewrite HTTPS 리디렉션 (${_rc})" || _r="취약|WebtoB HTTPS 리디렉션(URLRewrite) 미설정${_LBN}"
fi
_kres "WEB-21" "Apache Nginx IIS WebtoB" "$_r"

# ── WEB-22 에러 페이지 관리 ──
evd "WEB-22" "_active 'ErrorDocument'; _ngx 'error_page'; grep -n '<error-page>' ${TOMCAT_HOME:-/dev/null}/conf/web.xml ${TOMCAT_HOME:-/dev/null}/webapps/*/WEB-INF/web.xml 2>/dev/null; grep -ln '<error-page>' /dev/null \$(_JX web.xml) \$(_JX webcommon.xml) 2>/dev/null; [ -f \"$_WT_M\" ] && grep -iA3 'ERRORDOCUMENT' \"$_WT_M\""
_r=""
[ "$WEB_SRV" = apache ] && { _ed=$(_active 'ErrorDocument\s+[45][0-9][0-9]' | grep -vE 'ErrorDocument\s+403\s+/\.noindex\.html' | awk '{print $2}' | sort -u | tr '\n' ' ')
    [ -n "$_ed" ] && _r="양호|Apache 에러 페이지 별도 지정 (ErrorDocument ${_ed% })" || _r="취약|Apache ErrorDocument 미지정 (기본 에러 페이지 - 서버 정보 노출)"; }
[ "$WEB_SRV" = nginx ] && { _ep=$(_ngx '^\s*error_page\s' | grep -oE '\b[45][0-9][0-9]\b' | sort -u | tr '\n' ' '); [ -n "$_ep" ] && _r="양호|Nginx error_page 지정 (${_ep% })" || _r="취약|Nginx error_page 미지정 (기본 에러 페이지 - 버전 노출)"; }
[ "$WEB_SRV" = webtob ] && { _wtm 'ERRORDOCUMENT' | grep -q . && _r="양호|WebtoB ERRORDOCUMENT 지정" || _r="취약|WebtoB ERRORDOCUMENT 미지정"; }
[ "$WAS_SRV" = tomcat ] && { _tc_webxml_active "<error-page>" >/dev/null && _r="$(_worse "$_r" "양호|Tomcat <error-page> 지정")" || _r="$(_worse "$_r" "취약|Tomcat <error-page> 미지정 (기본 에러 페이지 - 버전 노출)")"; }
[ "$WAS_SRV" = jeus ] && { grep -l '<error-page>' /dev/null $(_JX web.xml) $(_JX webcommon.xml) 2>/dev/null | grep -q . && _r="$(_worse "$_r" "양호|JEUS <error-page> 지정")" || _r="$(_worse "$_r" "취약|JEUS <error-page> 미지정")"; }
_kres "WEB-22" "Apache Tomcat Nginx IIS JEUS WebtoB" "$_r"

# ── WEB-23 LDAP 알고리즘 적절하게 구성 (Tomcat) : SHA-256 이상 ──
evd "WEB-23" "awk '/<!--/{c=1} !c{print} /-->/{c=0}' ${TOMCAT_HOME:-/dev/null}/conf/server.xml 2>/dev/null | grep -iE 'JNDIRealm|digest=|algorithm=' | _mask_pw"
_r=""
if [ "$WAS_SRV" = tomcat ]; then
    _jr=$(_tcx server.xml | grep -i 'JNDIRealm')
    if [ -z "$_jr" ]; then _r="양호|LDAP 연결 인증(JNDIRealm) 미사용 - 취약한 다이제스트 알고리즘 사용 대상 없음"
    else _dg=$(_tcx server.xml | grep -oiE '(digest|algorithm)="[^"]*"' | cut -d'"' -f2 | tr '\n' ' ')
        echo " $_dg" | grep -qiE ' SHA-?(256|384|512)' && _r="양호|Tomcat JNDIRealm 비밀번호 다이제스트 ${_dg% }" || _r="취약|Tomcat JNDIRealm 다이제스트 ${_dg:-미설정}- SHA-256 이상 필요 (MD5/SHA-1/SSHA 취약)"; fi
fi
_kres "WEB-23" "Tomcat" "$_r"

# ── WEB-24 별도 업로드 경로 사용 및 권한 (750 이하, 일반 사용자 권한 없음) ──
_ud=""
for _d in $(_web_docroots) $_roots; do [ -d "$_d" ] && _ud="${_ud} $(find "$_d" -maxdepth 4 -type d \( -iname 'upload*' -o -iname 'attach*' -o -iname 'userfile*' \) 2>/dev/null | head -5 | tr '\n' ' ')"; done
_ud=$(echo $_ud | tr ' ' '\n' | sort -u | tr '\n' ' ')
evd "WEB-24" "ls -ld $_ud 2>/dev/null; _active '<Directory.*upload'"
if [ -z "${_ud// /}" ]; then _r="수동확인|웹 경로 내 업로드 디렉터리(upload/attach) 미발견 - 애플리케이션 업로드 경로·권한 확인"
else _o=""; for _d in $_ud; do _p=$(get_perm "$_d"); [ -n "$_p" ] && _perm_over "$_p" 750 && _o="${_o} ${_d}(${_p})"; done
    [ -n "$_o" ] && _r="취약|업로드 디렉터리에 일반 사용자 권한 부여 (750 초과):${_o}" || _r="수동확인|업로드 디렉터리 권한 750 이하: ${_ud}- 웹 경로 내 위치 시 실행·직접 접근 제한(Require all denied 등) 확인"; fi
_kres "WEB-24" "Apache Tomcat Nginx IIS JEUS WebtoB" "$_r"

# ── WEB-25 주기적 보안 패치 및 벤더 권고사항 적용 ──
_jv=""; [ "$WAS_SRV" = jeus ] && _jv=$( { jeusadmin -version 2>/dev/null || "$JEUS_HOME/bin/jeusadmin" -version 2>/dev/null; } | head -1)
_wv2=""; [ "$WEB_SRV" = webtob ] && _wv2=$( { wscfl -version 2>&1 || "$_WT_HOME/bin/wscfl" -version 2>&1; } | grep -iE 'webtob|version' | head -1)
evd "WEB-25" "httpd -v 2>/dev/null || apache2 -v 2>/dev/null; nginx -v 2>&1; sh ${TOMCAT_HOME:-/nonexistent}/bin/version.sh 2>/dev/null | head -5; echo 'JEUS: $_jv'; echo 'WebtoB: $_wv2'"
_r=""
case "$WEB_SRV" in
apache) _r="$(_eos_one apache "$(_apache_ver)")" ;;
nginx)  _r="$(_eos_one nginx "$(nginx -v 2>&1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)")" ;;
webtob) _r="수동확인|WebtoB ${_wv2:-버전 확인 필요}" ;;
esac
case "$WAS_SRV" in
tomcat) _r="$(_worse "$_r" "$(_eos_one tomcat "$(_tomcat_ver)")")" ;;
jeus)   _r="$(_worse "$_r" "수동확인|JEUS ${_jv:-버전 확인 필요}")" ;;
esac
case "$_r" in 취약*) ;; *) _r="수동확인|${_r#*|} - 벤더 최신 보안 패치 적용 여부·패치 관리 정책(주기적 점검) 확인" ;; esac
_kres "WEB-25" "Apache Tomcat Nginx IIS JEUS WebtoB" "$_r"

# ── WEB-26 로그 디렉터리 및 파일 권한 (일반 사용자 접근 권한 없음) ──
_ld=""
[ "$WEB_SRV" = apache ] && _ld="$(for _d in /var/log/httpd /var/log/apache2 "$(_apache_root)/logs"; do [ -d "$_d" ] && echo "$_d"; done) $(_active '(ErrorLog|CustomLog)\s+/' | awk '{print $2}' | tr -d '"' | xargs -n1 dirname 2>/dev/null)"
[ "$WEB_SRV" = nginx ] && _ld="$(_ngx '^\s*(access|error)_log\s+/' | awk '{print $2}' | tr -d ';' | xargs -n1 dirname 2>/dev/null) /var/log/nginx"
[ -n "$TOMCAT_HOME" ] && _ld="${_ld} $TOMCAT_HOME/logs $(ls -d /var/log/tomcat* 2>/dev/null)"
[ -n "$JEUS_HOME" ] && _ld="${_ld} $(ls -d "$JEUS_HOME"/domains/*/servers/*/logs 2>/dev/null | tr '\n' ' ')"
[ -n "$_WT_HOME" ] && _ld="${_ld} $_WT_HOME/log"
_ld=$(for _d in $_ld; do [ -d "$_d" ] && readlink -f "$_d" 2>/dev/null || { [ -d "$_d" ] && echo "$_d"; }; done | sort -u | tr '\n' ' ')
evd "WEB-26" "for d in $_ld; do ls -ld \"\$d\"; ls -l \"\$d\" 2>/dev/null | head -8; done"
_o=""
for _d in $_ld; do
    _p=$(get_perm "$_d"); [ -n "$_p" ] && _perm_over "$_p" 770 && _o="${_o} ${_d}/(${_p})"
    for _f in $(find "$_d" -maxdepth 1 -type f ! -name '*.pid' ! -name '*.lock' 2>/dev/null | head -200); do _p=$(get_perm "$_f"); [ -n "$_p" ] && _perm_over "$_p" 770 && { _o="${_o} ${_f}(${_p})"; break; }; done
done
if [ -z "${_ld// /}" ]; then _r="수동확인|로그 디렉터리 확인 불가"
elif [ -n "$_o" ]; then _r="취약|로그 디렉터리/파일에 일반 사용자(other) 권한 존재:${_o} (가이드: o-rwx, 디렉터리 750·파일 640)"
else _r="양호|로그 디렉터리·파일에 일반 사용자 권한 없음: ${_ld}"; fi
_kres "WEB-26" "Apache Tomcat Nginx IIS JEUS WebtoB" "$_r"

fi   # [4] 주요정보 WEB 판정 끝

_TOTAL=$((_CP + _CF + _CM + _CN))
echo "# ================================================================"
echo "# 점검 요약"
echo "#   총 점검 항목: ${_TOTAL}"
[ "$_TOTAL" -gt 0 ] 2>/dev/null && {
echo "#   양호:         ${_CP}  ($((_CP * 100 / _TOTAL))%)"
echo "#   취약:         ${_CF}  ($((_CF * 100 / _TOTAL))%)"
echo "#   수동확인:     ${_CM}"
echo "#   N-A:          ${_CN}"
}
echo "# ================================================================"
echo "# 점검 완료: $(date '+%Y-%m-%d %H:%M:%S')"
echo "# 증적 파일: ${_EVD}"
[ -n "$_RESF" ] && echo "# 결과 파일(자동 저장): ${_RESF}  ← 증적 파일과 함께 회수"
[ -n "$_TEEPID" ] && { exec >&- 2>/dev/null; wait "$_TEEPID" 2>/dev/null; sleep 1; }
exit 0
__VC_EOF_3__
# ── 내장: dbms/check_dbms.sh ──
cat > "$WORK/check_dbms.sh" <<'__VC_EOF_4__'
#!/bin/bash
# ================================================================
# DBMS(Unix/Linux) 보안 취약점 자동 점검 스크립트 v4.7
# ================================================================
#
# [용도]
#   전자금융기반시설·주요정보통신기반시설 데이터베이스 보안 점검.
#   기준: 전자금융기반시설 보안 취약점 평가기준 제2026-1호 [데이터베이스]
#   Windows MSSQL은 check_dbms_mssql.ps1, Linux MSSQL은 이 스크립트 사용.
#
# [대상 DBMS]
#   Oracle 10g~21c / MySQL 5.6~8.0 / MariaDB 10.x
#   PostgreSQL 10~16 / Tibero 5~7
#   MSSQL(Linux) — SQL Server 2017~2022 on Linux (sqlcmd 기반)
#   (DBMS가 없으면 자동 탐지 후 미설치 안내)
#
# [사전 조건]
#   - root 권한 필요 (sudo bash 또는 root 로그인)
#   - DBMS 접속 정보를 환경변수로 전달 (아래 참고)
#
# [접속 정보 환경변수]
#   Oracle:  ORACLE_USER  ORACLE_PASS  ORACLE_SID  (ORACLE_PASS 미지정 시 '/ as sysdba' OS 인증 — root 실행이면 ora_pmon 구동 계정으로 실행)
#   MySQL:   MYSQL_USER   MYSQL_PASS   MYSQL_HOST  (MYSQL_PASS 미지정 시 소켓/OS 인증·~/.my.cnf 시도 → 대화형이면 숨김 입력)
#   PgSQL:   PGSQL_USER   PGSQL_DB     PGSQL_HOST  (PGPASSWORD/.pgpass 없으면 소켓+peer(root 실행 시 postgres 구동 계정) → localhost 순)
#   ※ 비밀번호는 환경변수 또는 실행 중 숨김 입력으로만 전달 (명령 인자·파일에 남기지 않음)
#   Tibero:  TIBERO_USER  TIBERO_PASS  TIBERO_DB
#   MSSQL:   MSSQL_USER   MSSQL_PASS   MSSQL_SERVER MSSQL_PORT (기본: sa/CHANGE_ME/localhost/1433)
#
# [실행 방법]
#   DBMS_TYPE=oracle  bash check_dbms.sh > /tmp/$(hostname)_oracle.txt
#   DBMS_TYPE=mysql   bash check_dbms.sh > /tmp/$(hostname)_mysql.txt
#   DBMS_TYPE=pgsql   bash check_dbms.sh > /tmp/$(hostname)_pgsql.txt
#   DBMS_TYPE=tibero  bash check_dbms.sh > /tmp/$(hostname)_tibero.txt
#   DBMS_TYPE=mssql   bash check_dbms.sh > /tmp/$(hostname)_mssql.txt
#   (DBMS_TYPE 생략 시 설치된 DBMS 자동 탐지)
#
# [산출물]
#   1) 표준출력 — 파이프 구분자 결과 (파일로 리다이렉트)
#      형식: DBM-항목코드|결과|근거설명
#      결과: 양호 / 취약 / 수동확인 / N-A
#   2) 증적 파일 — /tmp/<호스트명>_dbms_evidence.txt
#      점검 중 실행한 쿼리·명령어·출력·판정 근거가 타임스탬프와 함께 기록됨
#
# ================================================================

# ── DBMS 자동 탐지 ──────────────────────────────────────────────
_proc_has() { { ps -e -o comm= 2>/dev/null || cat /proc/[0-9]*/comm 2>/dev/null; } | sed 's#.*/##' | grep -qE "^($1)\$"; }
detect_dbms() {
    [ -n "$DBMS_TYPE" ] && return
    # 실행 중인 DB 프로세스 우선 (클라이언트만 설치된 서버·환경변수 없는 root/sudo 실행 대응)
    _proc_has 'ora_pmon_.*' && DBMS_TYPE="oracle" && return
    _proc_has 'tbsvr.*' && DBMS_TYPE="tibero" && return
    _proc_has 'mariadbd|mysqld' && DBMS_TYPE="mysql" && return
    _proc_has 'postgres|postmaster' && DBMS_TYPE="pgsql" && return
    _proc_has 'sqlservr' && DBMS_TYPE="mssql" && return

    # Oracle: ORACLE_HOME 또는 sqlplus
    [ -n "$ORACLE_HOME" ] && [ -x "$ORACLE_HOME/bin/sqlplus" ] && DBMS_TYPE="oracle" && return
    command -v sqlplus >/dev/null 2>&1 && DBMS_TYPE="oracle" && return
    # MySQL
    command -v mysql   >/dev/null 2>&1 && DBMS_TYPE="mysql"  && return
    # PostgreSQL
    command -v psql    >/dev/null 2>&1 && DBMS_TYPE="pgsql"  && return
    # MariaDB
    command -v mariadb >/dev/null 2>&1 && DBMS_TYPE="mariadb" && return
    # MSSQL (Linux)
    command -v sqlcmd >/dev/null 2>&1 && DBMS_TYPE="mssql" && return
    [ -x "/opt/mssql-tools/bin/sqlcmd" ] && DBMS_TYPE="mssql" && return
    [ -x "/opt/mssql-tools18/bin/sqlcmd" ] && DBMS_TYPE="mssql" && return
    # Tibero
    [ -n "$TB_HOME" ]  && DBMS_TYPE="tibero" && return

    DBMS_TYPE="unknown"
}
detect_dbms

detect_os() {
    OS_FAMILY="LINUX"
    case "$(uname -s)" in
    MINGW*|MSYS*|CYGWIN*) OS_FAMILY="WINDOWS" ;;
    AIX)     OS_FAMILY="AIX" ;;
    SunOS)   OS_FAMILY="SOLARIS" ;;
    "HP-UX") OS_FAMILY="HPUX" ;;
    esac
}
detect_os

get_perm() {
    local f="$1"
    case "$OS_FAMILY" in
    AIX|SOLARIS|HPUX) ls -lL "$f" 2>/dev/null | awk '{k=0;for(i=2;i<=10;i++){c=substr($1,i,1);if(c!="-")k+=2^(10-i)}printf "%o\n",k}' ;;   # istat 은 Protection: rw-r--r-- 형식이라 숫자 없음
    *)       stat -L -c "%a" "$f" 2>/dev/null ;;
    esac
}
# _perm_bad <권한(8진)> <금지 비트(8진, 예 022)> → 금지 비트가 있으면 참 (setuid 등 특수 비트는 제외하고 뒤 3자리만)
_perm_bad() {
    local p="${1: -3}"
    [ -z "$p" ] && return 0
    (( (8#$p & 8#$2) != 0 ))
}
# _perm_check <금지 비트> <파일...> → 위반 파일 목록 "파일(권한) " 은 _PC_BAD, 확인한 파일 수는 _PC_FOUND (서브셸 없이 호출)
_perm_check() {
    local mask="$1" f p; shift; _PC_FOUND=0; _PC_BAD=""
    for f in "$@"; do
        [ -e "$f" ] || continue
        _PC_FOUND=$((_PC_FOUND+1)); p=$(get_perm "$f")
        _perm_bad "$p" "$mask" && _PC_BAD="${_PC_BAD}${f}(${p}) "
    done
    return 0
}

get_owner() {
    local f="$1"
    case "$OS_FAMILY" in
    AIX|SOLARIS|HPUX) ls -lL "$f" 2>/dev/null | awk '{print $3}' ;;   # istat Owner: 0(root) 형식 회피
    *)       stat -c "%U" "$f" 2>/dev/null ;;
    esac
}

HN=$(hostname 2>/dev/null || uname -n)
# ── 결과 사본 자동 저장: '> 파일' 리다이렉트를 빠뜨려도 판정 결과가 증적과 같은 위치에 남도록 표준출력을 복사 ──
# ── 점검 기준 선택: 인자 ef|mi|all (또는 1|2|3), 미지정 시 메뉴 / 터미널이 아니면(자동 실행) all ──
_KMODE="${1:-${CHECK_MODE:-}}"
if [ -z "$_KMODE" ]; then
    if [ -t 0 ]; then
        { echo "점검 기준을 선택하세요:"
          echo "  1) 전자금융기반시설 (DBM-001~036)"
          echo "  2) 주요정보통신기반시설 2026 상세가이드 (D-01~D-26)"
          echo "  3) 전체 (두 기준 결과를 한 파일에)"
          printf "선택 [1/2/3] (Enter=3): "; } >&2
        read -r _sel; _KMODE="${_sel:-3}"
    else
        _KMODE="all"
    fi
fi
case "$(echo "$_KMODE" | tr 'A-Z' 'a-z')" in
1|ef|srv) _KMODE="ef" ;;
2|mi|kisa|u) _KMODE="mi" ;;
3|all) _KMODE="all" ;;
*) echo "사용법: $0 [ef|mi|all]  (ef=전자금융, mi=주요정보 2026 상세가이드, all=둘 다)" >&2; exit 1 ;;
esac
_RESF="/tmp/${HN}_dbms.txt"
if [ -z "$NO_RESULT_COPY" ] && ! [ /dev/fd/1 -ef "$_RESF" ] 2>/dev/null && ( : > "$_RESF" ) 2>/dev/null; then
    exec > >(tee "$_RESF"); _TEEPID=$!
else
    _RESF=""
fi

if [ "$OS_FAMILY" = "WINDOWS" ]; then
    echo "# [경고] Windows 환경(Git Bash)에서 실행됨 — Linux/Unix 전용 스크립트"
    echo "# [경고] MSSQL 점검은 check_dbms_mssql.ps1 사용"
fi

echo "# ================================================================"
echo "# 점검 대상: ${HN}"
echo "# DBMS 종류: ${DBMS_TYPE}"
echo "# OS: ${OS_FAMILY}"
echo "# OS 상세: $( ( [ -r /etc/os-release ] && . /etc/os-release 2>/dev/null && echo "${PRETTY_NAME:-$NAME $VERSION_ID}" ) || ( command -v oslevel >/dev/null 2>&1 && echo "AIX $(oslevel -s 2>/dev/null)" ) || ( [ -r /etc/release ] && head -1 /etc/release | sed 's/^ *//' ) || uname -sr 2>/dev/null)"
echo "# 커널: $(uname -r 2>/dev/null)$( [ "$(uname -s 2>/dev/null)" = SunOS ] && echo " / $(uname -v 2>/dev/null)")"
case "$_KMODE" in
ef)  echo "# 점검 기준: 전자금융기반시설 보안 취약점 평가기준 제2026-1호 [데이터베이스]" ;;
mi)  echo "# 점검 기준: 주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드(2026) [DBMS D-01~D-26]" ;;
*)   echo "# 점검 기준: 전자금융기반시설 보안 취약점 평가기준 제2026-1호 [데이터베이스] + 주요정보통신기반시설 상세가이드(2026) [DBMS D-01~D-26]" ;;
esac
echo "# 점검 일시: $(date '+%Y-%m-%d %H:%M:%S')"
echo "# ================================================================"

_CP=0; _CF=0; _CM=0; _CN=0

_EVD="/tmp/${HN}_dbms_evidence.txt"
# 증적 파일 쓰기 불가(다른 사용자 소유 기존 파일 — /tmp sticky·protected_regular 등) → 대체 경로
if ! ( : >> "$_EVD" ) 2>/dev/null; then
    _EVD=$(mktemp "${TMPDIR:-/tmp}/${HN}_dbms_evidence.XXXXXX" 2>/dev/null || echo "./${HN}_dbms_evidence_$$.txt")
    echo "# [경고] 기본 증적 파일에 쓸 수 없어 대체 경로 사용: $_EVD"
fi
echo "# ================================================================" > "$_EVD"
echo "# DBMS 증적 파일 (감사 추적용)" >> "$_EVD"
echo "# 대상: ${HN} / DBMS: ${DBMS_TYPE} / OS: ${OS_FAMILY}" >> "$_EVD"
echo "# 생성: $(date '+%Y-%m-%d %H:%M:%S')" >> "$_EVD"
echo "# ================================================================" >> "$_EVD"

declare -A _INAME=(
    [DBM-001]='취약하게 설정된 비밀번호 제거'
    [DBM-003]='불필요하거나 관리되지 않는 계정 제거'
    [DBM-004]='불필요한 관리자 계정 제거'
    [DBM-005]='데이터베이스 내 중요정보 안전한 암호화 적용 여부'
    [DBM-006]='로그인 실패 횟수에 따른 접속 제한 설정'
    [DBM-007]='비밀번호 복잡도 설정'
    [DBM-008]='비밀번호 변경 주기 충족 여부'
    [DBM-009]='사용되지 않는 세션 종료 여부'
    [DBM-011]='감사 로그 수집 및 백업 여부'
    [DBM-012]='Listener Control Utility(lsnrnctl) 보안 설정 여부'
    [DBM-013]='원격 접속에 대한 접근 제어 여부'
    [DBM-014]='취약한 운영체제 역할 인증 기능(OS_ROLES, REMOTE_OS_ROLES) 비활성화'
    [DBM-015]='Public Role에 불필요한 권한 제거'
    [DBM-016]='주기적인 보안패치 및 벤더 권고사항 적용 여부'
    [DBM-017]='업무상 불필요한 시스템 테이블 접근 권한 제거'
    [DBM-019]='이전 비밀번호 재사용 요구사항 충족 여부'
    [DBM-020]='사용자별 계정 분리'
    [DBM-021]='업무상 불필요한 ODBC/OLE-DB 데이터 소스 및 드라이버 제거'
    [DBM-022]='설정 파일 및 중요정보가 포함된 파일의 접근 권한 설정 적절성'
    [DBM-024]='불필요하게 WITH GRANT OPTION 옵션이 설정된 권한 제거'
    [DBM-025]='서비스 지원이 종료된(EoS) 시스템 및 장비 교체 여부'
    [DBM-026]='데이터베이스 구동 계정의 umask 설정 적절성'
    [DBM-028]='업무상 불필요한 데이터베이스 Object 제거'
    [DBM-029]='데이터베이스의 자원 사용 제한 설정 여부'
    [DBM-030]='Audit Table에 대한 접근 제어 설정 적절성'
    [DBM-031]='SA 계정에 대한 보안설정 적절성'
    [DBM-032]='데이터베이스 접속 시 통신구간에 비밀번호 평문 노출 방지 여부'
    [DBM-033]='DB 이중화 구성 시 비밀번호 평문 노출 방지 여부'
    [DBM-034]='DBMS 서비스의 구동 권한 적절성'
    [DBM-035]='xp_cmdshell 사용 비활성화'
    [DBM-036]='Registry Procedure 접근 권한 설정 적절성'
)
_dbm_verdict() {
    local _code="DBM-$1" _judge="$2" _reason="$3"
    local _nm="${_INAME[$_code]:-}"
    if [ -n "$_nm" ]; then
        printf '[판정] %s (%s)|%s|%s\n\n' "$_code" "$_nm" "$_judge" "$_reason" >> "$_EVD"
    else
        printf '[판정] %s|%s|%s\n\n' "$_code" "$_judge" "$_reason" >> "$_EVD"
    fi
}
# 판정 누적: 같은 항목에 여러 세부 점검이 있으면 가장 나쁜 결과(취약>수동확인>양호>N-A)로 합쳐 마지막에 1회 출력
declare -A _RES=()
_ORDER=""
_rank() { case "$1" in 취약) echo 4;; 수동확인) echo 3;; 양호) echo 2;; *) echo 1;; esac; }
declare -A _MIX=()
_emit() {
    local k="DBM-${1}" r="$2" w="$3" cur cr cw tail
    w="${w//$'
'/, }"; w="${w//|//}"   # 사유 내 줄바꿈·구분자(|)는 파이프 출력 형식을 깨므로 치환
    _dbm_verdict "$1" "$r" "$w"
    cur="${_RES[$k]:-}"
    if [ -z "$cur" ]; then _RES[$k]="${r}|${w}"; _FIRST[$k]="$r"; _ORDER="${_ORDER} ${k}"; return; fi
    cr="${cur%%|*}"; cw="${cur#*|}"
    # 반복되는 꼬리 문구(' - …') 는 한 번만
    tail="${w##* - }"; [ "$tail" != "$w" ] && [[ "$cw" == *"$tail"* ]] && w="${w% - *}"
    # 세부 판정이 서로 다르면 각 사유에 판정 표지 부착
    if [ "$r" != "${_FIRST[$k]}" ] || [ -n "${_MIX[$k]:-}" ]; then
        [ -z "${_MIX[$k]:-}" ] && cw="[${_FIRST[$k]}] ${cw}" && _MIX[$k]=1
        w="[${r}] ${w}"
    fi
    if [ "$(_rank "$r")" -gt "$(_rank "$cr")" ]; then _RES[$k]="${r}|${w} / ${cw}"
    else _RES[$k]="${cr}|${cw} / ${w}"; fi
}
declare -A _FIRST=()
_flush_results() {
    local k line _hasd=0
    case " $_ORDER" in *" D-"*) _hasd=1 ;; esac
    if [ "$_KMODE" = "mi" ] && [ "$_hasd" = 0 ]; then
        echo "# [안내] ${DBMS_TYPE:-DBMS}: 가이드 D 항목 직접 판정 미지원(MySQL·MariaDB·PostgreSQL 만 지원) - 전자금융 DBM 결과를 출력하며, 컨버터 주요정보 모드가 가이드 D 항목으로 변환"
    fi
    for k in $_ORDER; do
        case "$_KMODE:$k" in
        ef:D-*) continue ;;
        mi:DBM-*) [ "$_hasd" = 1 ] && continue ;;
        esac
        line="${k}|${_RES[$k]}"
        echo "$line"
        case "$line" in *"|양호|"*) _CP=$((_CP+1));; *"|취약|"*) _CF=$((_CF+1));; *"|수동확인|"*) _CM=$((_CM+1));; *) _CN=$((_CN+1));; esac
    done
}

# DB 접속 확인: 실패 시 빈 조회값으로 거짓 양호/취약이 나오지 않도록 전 항목 수동확인 처리
_DBM_CODES="001 003 004 005 006 007 008 009 011 012 013 014 015 016 017 019 020 021 022 024 025 026 028 029 030 031 032 033 034 035 036"
_conn_ok() {
    echo "$1" | grep -q "CONN_OK" && { _DB_CONN=1; return 0; }
    local i
    for i in $_DBM_CODES; do mc "$i" "DB 접속 실패($2) - 접속 정보(계정/권한/호스트) 확인 후 재점검 필요"; done
    echo "# [경고] $2 접속 실패 - 전 항목 수동확인 처리" >&2
    return 1
}
ok()  { _emit "$1" "양호" "$2"; }
ng()  { _emit "$1" "취약" "$2"; }
na()  { _emit "$1" "N-A" "$2"; }
mc()  { _emit "$1" "수동확인" "$2"; }

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
evd_q() {
    local item="$1" desc="$2" output="$3"
    printf '[%s] %s SQL: %s\n%s\n\n' "$item" "$(date '+%H:%M:%S')" "$desc" "$output" >> "$_EVD"
}

_csv() { tr '\n' ',' | sed 's/,$//'; }

_get_umask() {
    # $1=구동 계정, $2..=프로세스 이름 후보 — 실행 중 데몬의 실제 umask 우선, 모두 없을 때만 계정 로그인 umask
    local _user="$1" _umask="" _pid="" _n _c; shift
    for _n in "$@"; do
        _pid=$(pgrep -x "$_n" 2>/dev/null | head -1)
        if [ -z "$_pid" ]; then
            for _c in /proc/[0-9]*/comm; do case "$(cat "$_c" 2>/dev/null)" in "$_n"|"$_n"_*) _pid=${_c#/proc/}; _pid=${_pid%/comm}; break ;; esac; done
        fi
        [ -z "$_pid" ] && _pid=$(pgrep -f "$_n" 2>/dev/null | head -1)   # ora_pmon_<SID> 등 접미사 붙는 프로세스
        [ -n "$_pid" ] && [ -f "/proc/$_pid/status" ] && _umask=$(awk '/^Umask:/{print $2}' "/proc/$_pid/status" 2>/dev/null)
        [ -n "$_umask" ] && break
    done
    [ -z "$_umask" ] && [ -n "$_user" ] && _umask=$(su -c "umask" "$_user" 2>/dev/null)
    echo "$_umask"
}

_judge_umask() {
    local _umask="$1" _label="$2" _item="$3" _user="$4"
    if [ -n "$_umask" ]; then
        # group·others 쓰기(w) 비트가 모두 마스킹되어야 양호 (042 등 group 쓰기 허용은 취약)
        if (( (8#${_umask: -3} & 8#022) == 8#022 )) 2>/dev/null; then
            ok "$_item" "${_label} 구동 계정(${_user}) umask=${_umask} (022 이상)"
        else
            ng "$_item" "${_label} 구동 계정(${_user}) umask=${_umask} (022 이상 권고)"
        fi
    else
        mc "$_item" "${_label} 구동 계정 umask 수동 확인"
    fi
}

# ================================================================
# Oracle 점검
# ================================================================
_ora_env() {   # root/sudo 실행 등 환경변수 없음 → ora_pmon 프로세스·oratab 으로 ORACLE_HOME·SID·구동 계정 복원
    local c pm="" pid="" sid h s2
    for c in /proc/[0-9]*/comm; do case "$(cat "$c" 2>/dev/null)" in ora_pmon_*) pm=$(cat "$c"); pid=${c#/proc/}; pid=${pid%/comm}; break ;; esac; done
    [ -z "$pid" ] && read -r pid pm <<< "$(ps -e -o pid=,comm= 2>/dev/null | awk '$2 ~ /ora_pmon_/{print $1, $2; exit}')"
    pm=${pm##*/}
    [ -n "$pid" ] && _ORA_OS_USER=$(ps -o user= -p "$pid" 2>/dev/null | tr -d ' ')
    [ -n "$ORACLE_HOME" ] && [ -x "$ORACLE_HOME/bin/sqlplus" ] && [ -n "$ORACLE_SID$ORACLE_SERVICE" ] && return 0
    sid=${ORACLE_SID:-${pm#ora_pmon_}}
    [ -z "$sid" ] && return 1
    s2=$(awk -F: -v s="$sid" 'tolower($1)==tolower(s) && $2!="" {print $1; exit}' /etc/oratab /var/opt/oracle/oratab 2>/dev/null)
    h=${ORACLE_HOME:-$(awk -F: -v s="$sid" 'tolower($1)==tolower(s) && $2!="" {print $2; exit}' /etc/oratab /var/opt/oracle/oratab 2>/dev/null)}
    [ -z "$h" ] && [ -n "$pid" ] && h=$(tr '\0' '\n' < "/proc/$pid/environ" 2>/dev/null | sed -n 's/^ORACLE_HOME=//p')
    [ -z "$ORACLE_SID" ] && [ -n "$pid" ] && ORACLE_SID=$(tr '\0' '\n' < "/proc/$pid/environ" 2>/dev/null | sed -n 's/^ORACLE_SID=//p')
    [ -n "$h" ] || return 1
    export ORACLE_HOME="$h" ORACLE_SID="${ORACLE_SID:-${s2:-$sid}}" PATH="$h/bin:$PATH"
}
check_oracle() {
    ORACLE_USER="${ORACLE_USER:-system}"
    ORACLE_PASS="${ORACLE_PASS-}"
    _ORA_OS_USER=""; _ORA_SU=""; _ora_env
    ORACLE_SID="${ORACLE_SID:-}"
    ORACLE_SERVICE="${ORACLE_SERVICE:-}"
    ORACLE_HOST="${ORACLE_HOST:-localhost}"
    ORACLE_PORT="${ORACLE_PORT:-1521}"

    SQLPLUS=$(command -v sqlplus 2>/dev/null)
    [ -z "$SQLPLUS" ] && [ -n "$ORACLE_HOME" ] && SQLPLUS="$ORACLE_HOME/bin/sqlplus"
    if [ -z "$SQLPLUS" ] || [ ! -x "$SQLPLUS" ]; then
        printf '[FALLBACK] %s sqlplus 미탐지 - Oracle 전 항목 수동 확인 처리\n\n' "$(date '+%H:%M:%S')" >> "$_EVD"
        for i in 001 003 004 005 006 007 008 009 011 012 013 014 015 016 017 \
                 019 020 022 024 025 026 028 029 030 034; do
            mc "$i" "sqlplus 미탐지 - 수동 확인"
        done
        na "021" "Windows MSSQL 전용 항목"
        na "031" "MSSQL 전용 항목"
        mc "032" "Oracle 통신 암호화 수동 확인 (sqlplus 미탐지)"
        mc "033" "Oracle 이중화 구성 수동 확인 (sqlplus 미탐지)"
        na "035" "MSSQL 전용 항목"
        na "036" "MSSQL 전용 항목"
        return
    fi

    if [ -z "$ORACLE_PASS" ]; then   # 비밀번호 미지정 → 로컬 OS 인증(/ as sysdba), root 실행이면 ora_pmon 구동 계정으로 sqlplus 실행
        CONN="/ as sysdba"
        [ "$(id -u)" = 0 ] && [ -n "$_ORA_OS_USER" ] && [ "$_ORA_OS_USER" != "root" ] && _ORA_SU="$_ORA_OS_USER"
    elif [ -n "$ORACLE_SERVICE" ]; then
        CONN="${ORACLE_USER}/${ORACLE_PASS}@${ORACLE_HOST}:${ORACLE_PORT}/${ORACLE_SERVICE}"
    elif [ -n "$ORACLE_SID" ]; then
        CONN="${ORACLE_USER}/${ORACLE_PASS}@${ORACLE_SID}"
    else
        CONN="${ORACLE_USER}/${ORACLE_PASS}"
    fi

    _ora_exec() {   # 접속 문자열은 표준입력으로만 전달 (프로세스 인자 노출 없음)
        if [ -n "$_ORA_SU" ]; then su "$_ORA_SU" -s /bin/sh -c "ORACLE_HOME='$ORACLE_HOME' ORACLE_SID='$ORACLE_SID' TNS_ADMIN='$TNS_ADMIN' '$SQLPLUS' -s /nolog"
        else "$SQLPLUS" -s /nolog; fi
    }
    run_q() {   # SQL 오류 시 원문(SQL 에코·'*'·ERROR at line) 대신 첫 ORA-/SP2- 줄만 반환, 전체 오류는 증적에 기록
        local _o
        _o=$(printf 'CONNECT %s\nSET PAGESIZE 0 FEEDBACK OFF HEADING OFF LINESIZE 200 TRIMSPOOL ON\n%s\nEXIT\n' "$CONN" "$1" | _ora_exec 2>&1)
        if printf '%s\n' "$_o" | grep -qE '^(ORA|SP2)-[0-9]+'; then
            printf '[SQL오류] %s\n%s\n\n' "$(printf '%s' "$1" | head -c 200)" "$(printf '%s\n' "$_o" | grep -E '^(ORA|SP2)-')" >> "$_EVD"
            printf '%s\n' "$_o" | grep -E '^(ORA|SP2)-' | head -1
        else printf '%s\n' "$_o"; fi
    }
    if [ -z "$ORACLE_PASS" ] && ! run_q "SELECT 'CONN_'||'OK' FROM DUAL;" | grep -q CONN_OK && [ -t 0 ]; then
        read -rs -p "Oracle OS 인증 실패 - SYS 비밀번호: " ORACLE_PASS </dev/tty; echo >&2
        _ORA_SU=""; CONN="sys/${ORACLE_PASS}${ORACLE_SID:+@${ORACLE_SID}} as sysdba"
    fi
    echo "# Oracle 접속: $( [ "$CONN" = "/ as sysdba" ] && echo "OS 인증(/ as sysdba)${_ORA_SU:+ - ${_ORA_SU} 계정}" || echo "${CONN%%/*}@${ORACLE_SERVICE:-${ORACLE_SID:-local}}")"

    _conn_ok "$(run_q "SELECT 'CONN_'||'OK' FROM DUAL;")" "Oracle" || return
    DB_VER=$(run_q "SELECT VERSION FROM V\$INSTANCE;" | grep -oE '[0-9]+\.[0-9]+' | head -1)
    DB_MAJ=$(echo "$DB_VER" | cut -d. -f1)
    echo "# Oracle 버전: ${DB_VER}"
    # 12c+ 멀티테넌트: CDB$ROOT 접속 시 열린 PDB 전체를 순회 (DBA_* 뷰는 현재 컨테이너만 조회)
    _ORA_CONS=""
    if [ "$(run_q "SELECT SYS_CONTEXT('USERENV','CON_NAME') FROM DUAL;" | tr -d ' \n')" = 'CDB$ROOT' ]; then
        _ORA_CONS=$(run_q "SELECT NAME FROM V\$PDBS WHERE OPEN_MODE LIKE 'READ%' AND NAME<>'PDB\$SEED' ORDER BY CON_ID;" | grep -v "ORA-" | tr -d ' ' | grep -v '^$' | tr '\n' ' ')
        echo "# Oracle 컨테이너: CDB\$ROOT ${_ORA_CONS}"
        evd_q "DBM-003" "V\$PDBS 열린 PDB (계정·권한 항목은 CDB\$ROOT + PDB 별 [PDB명] 접두로 합산)" "${_ORA_CONS:-없음}"
    fi
    run_qa() {   # CDB$ROOT(또는 비CDB) + 열린 PDB 전체
        run_q "$1"
        local c
        for c in $_ORA_CONS; do
            run_q "ALTER SESSION SET CONTAINER=\"$c\";
$1" | grep -v '^$' | sed "s/^/[$c]/"
        done
    }

    # DBM-001: 취약 패스워드
    def_accounts=""
    [ "${DB_MAJ:-0}" -ge 12 ] 2>/dev/null && \
        ACCTS="'SYS','SYSTEM','DBSNMP','SCOTT','OUTLN','MDSYS','XDB','ANONYMOUS','CTXSYS'" || \
        ACCTS="'SYS','SYSTEM','DBSNMP','SCOTT','OUTLN','MDSYS','XDB','ANONYMOUS'"
    # 평가기준: 초기 설정(디폴트) 비밀번호·취약 비밀번호 사용 계정 존재 시 취약 (복잡도 만족 여부는 해시 크랙 필요)
    def_pwd=$(run_qa "SELECT d.USERNAME||'('||u.ACCOUNT_STATUS||')' FROM DBA_USERS_WITH_DEFPWD d JOIN DBA_USERS u ON u.USERNAME=d.USERNAME WHERE u.ACCOUNT_STATUS='OPEN';" 2>/dev/null | grep -v "^$" | grep -viE "ORA-|no rows" | head -10)
    def_accounts=$(run_qa "SELECT USERNAME||'('||ACCOUNT_STATUS||')' FROM DBA_USERS WHERE USERNAME IN (${ACCTS}) AND ACCOUNT_STATUS='OPEN';" | grep -v "^$" | head -5)
    evd_q "DBM-001" "DBA_USERS_WITH_DEFPWD(OPEN) / 기본 계정 OPEN" "디폴트 비밀번호 계정: ${def_pwd:-없음} / 기본 계정 OPEN: ${def_accounts:-없음}"
    if [ -n "$def_pwd" ]; then
        ng "001" "초기 설정(디폴트) 비밀번호 사용 계정: $(echo "$def_pwd" | _csv)"
    else
        mc "001" "디폴트 비밀번호 계정 없음 - 계정 비밀번호 복잡도·취약 비밀번호 여부는 해시 크랙으로 확인 필요 (기본 계정 OPEN: ${def_accounts:-없음})"
    fi

    # DBM-003: 불필요 계정
    _all_users=$(run_qa "SELECT USERNAME||' ('||ACCOUNT_STATUS||')' FROM DBA_USERS ORDER BY USERNAME;" | grep -v "^$" | grep -v "ORA-" | head -60)
    evd_q "DBM-003" "SELECT USERNAME,ACCOUNT_STATUS FROM DBA_USERS (CDB\$ROOT + [PDB])" "$_all_users"
    mc "003" "불필요 계정 목록 수동 확인 (위 현황 참조)"

    # DBM-004: 불필요 관리자 계정
    # 평가기준: DBA role·SYSDBA·시스템 권한 부여 계정 목록 → 인터뷰로 불필요 여부 판단
    dba=$(run_qa "SELECT GRANTEE FROM DBA_ROLE_PRIVS WHERE GRANTED_ROLE='DBA' AND GRANTEE NOT IN ('SYS','SYSTEM','DBA') ORDER BY GRANTEE;" | grep -v "^$" | grep -v "ORA-" | head -10)
    _sysdba=$(run_q "SELECT USERNAME FROM V\$PWFILE_USERS WHERE SYSDBA='TRUE' AND USERNAME<>'SYS';" 2>/dev/null | grep -v "^$" | grep -v "ORA-" | head -10)
    _sysprv=$(run_qa "SELECT DISTINCT p.GRANTEE FROM DBA_SYS_PRIVS p JOIN DBA_USERS u ON u.USERNAME=p.GRANTEE WHERE u.ORACLE_MAINTAINED='N' AND p.PRIVILEGE NOT IN ('CREATE SESSION') ORDER BY 1;" 2>/dev/null | grep -v "^$" | grep -v "ORA-" | head -10)
    evd_q "DBM-004" "DBA 역할 / SYSDBA / 시스템 권한 보유 계정" "DBA: ${dba:-없음} / SYSDBA: ${_sysdba:-없음} / 시스템 권한: ${_sysprv:-없음}"
    mc "004" "관리자 권한 계정 - DBA: $(echo "${dba:-없음}" | _csv), SYSDBA: $(echo "${_sysdba:-없음}" | _csv), 시스템 권한: $(echo "${_sysprv:-없음}" | _csv) - 업무상 필요 여부 인터뷰 확인"

    # DBM-005: 중요정보 암호화
    _enc_cols=$(run_qa "SELECT OWNER||'.'||TABLE_NAME||'.'||COLUMN_NAME FROM DBA_ENCRYPTED_COLUMNS ORDER BY 1;" 2>/dev/null | grep -v "^$" | head -20)
    evd_q "DBM-005" "SELECT OWNER,TABLE_NAME,COLUMN_NAME FROM DBA_ENCRYPTED_COLUMNS" "${_enc_cols:-암호화 컬럼 없음 또는 조회 불가}"
    mc "005" "테이블 컬럼별 암호화 적용 여부 수동 확인 (위 현황 참조)"

    # 계정별 적용 프로파일 값 (OPEN 계정, LIMIT=DEFAULT 는 DEFAULT 프로파일 값으로 대체) → "USER=VALUE" 줄
    _prof() {
        run_qa "SELECT u.USERNAME||'='||DECODE(p.LIMIT,'DEFAULT',d.LIMIT,p.LIMIT) FROM DBA_USERS u JOIN DBA_PROFILES p ON p.PROFILE=u.PROFILE AND p.RESOURCE_NAME='$1' JOIN DBA_PROFILES d ON d.PROFILE='DEFAULT' AND d.RESOURCE_NAME='$1' WHERE u.ACCOUNT_STATUS='OPEN' ORDER BY 1;" | grep "=" | grep -v "ORA-"
    }
    # DBM-006: 로그인 실패 횟수 제한 (평가기준: 계정별 적용 프로파일 FAILED_LOGIN_ATTEMPTS UNLIMITED 또는 5 초과 → 취약)
    _p6=$(_prof FAILED_LOGIN_ATTEMPTS); _lock=$(run_q "SELECT LIMIT FROM DBA_PROFILES WHERE PROFILE='DEFAULT' AND RESOURCE_NAME='PASSWORD_LOCK_TIME';" | tr -d ' \n')
    evd_q "DBM-006" "OPEN 계정별 FAILED_LOGIN_ATTEMPTS / DEFAULT PASSWORD_LOCK_TIME" "$(echo "$_p6" | _csv) / LOCK_TIME=${_lock}"
    _b6=$(echo "$_p6" | awk -F= '$2=="UNLIMITED" || $2+0>5 || $2=="" {print}' | head -8)
    if [ -z "$_p6" ]; then mc "006" "계정별 FAILED_LOGIN_ATTEMPTS 조회 실패 - 수동 확인"
    elif [ -n "$_b6" ]; then ng "006" "FAILED_LOGIN_ATTEMPTS UNLIMITED/5 초과 계정: $(echo "$_b6" | _csv) - 서비스 운영 계정은 평가 제외 가능"
    else ok "006" "OPEN 계정 FAILED_LOGIN_ATTEMPTS 5회 이하 (PASSWORD_LOCK_TIME=${_lock})"; fi

    # DBM-007: 비밀번호 검증 함수 — 미적용 계정 또는 기준(2종 10자/3종 8자) 미달 함수 → 취약
    _p7=$(_prof PASSWORD_VERIFY_FUNCTION)
    evd_q "DBM-007" "OPEN 계정별 PASSWORD_VERIFY_FUNCTION" "$(echo "$_p7" | _csv)"
    _n7=$(echo "$_p7" | awk -F= '$2=="" || $2=="NULL" {print $1}' | head -8)
    _w7=$(echo "$_p7" | awk -F= 'toupper($2) ~ /^(ORA12C_VERIFY_FUNCTION|VERIFY_FUNCTION_11G|VERIFY_FUNCTION)$/ {print}' | head -5)
    _c7=$(echo "$_p7" | awk -F= '$2!="" && $2!="NULL" && toupper($2) !~ /^(ORA12C_STRONG_VERIFY_FUNCTION|ORA12C_VERIFY_FUNCTION|VERIFY_FUNCTION_11G|VERIFY_FUNCTION)$/ {print $2}' | sort -u | head -3)
    if [ -z "$_p7" ]; then mc "007" "PASSWORD_VERIFY_FUNCTION 조회 실패 - 수동 확인"
    elif [ -n "$_n7" ]; then ng "007" "비밀번호 검증 함수 미적용 계정: $(echo "$_n7" | _csv)"
    elif [ -n "$_w7" ]; then ng "007" "검증 함수 기준 미달(8자·2종 조합, 기준 2종 10자/3종 8자): $(echo "$_w7" | _csv)"
    elif [ -n "$_c7" ]; then mc "007" "사용자 정의 검증 함수: $(echo "$_c7" | _csv) - 함수 내용이 복잡도 기준 충족하는지 확인"
    else ok "007" "전 OPEN 계정 ORA12C_STRONG_VERIFY_FUNCTION 적용"; fi

    # DBM-008: 최근 비밀번호 변경일(sys.user\$ ptime) 90일 이상 경과 계정 → 취약 (조회 불가 시 만료 정책으로 대체)
    _ptime=$(run_qa "SELECT USERNAME||'='||TO_CHAR(PASSWORD_CHANGE_DATE,'YYYY-MM-DD') FROM DBA_USERS WHERE ACCOUNT_STATUS='OPEN' AND PASSWORD_CHANGE_DATE < SYSDATE-90 ORDER BY 1;" 2>&1 | grep -v "^$")
    # PASSWORD_CHANGE_DATE(21c+) 미지원이면 sys.user$ ptime
    echo "$_ptime" | grep -q "ORA-" && _ptime=$(run_qa "SELECT u.name||'='||TO_CHAR(u.ptime,'YYYY-MM-DD') FROM sys.user\$ u JOIN DBA_USERS d ON d.USERNAME=u.name WHERE d.ACCOUNT_STATUS='OPEN' AND u.ptime < SYSDATE-90 ORDER BY 1;" 2>&1 | grep -v "^$")
    if echo "$_ptime" | grep -q "ORA-"; then
        _p8=$(_prof PASSWORD_LIFE_TIME)
        evd_q "DBM-008" "sys.user\$ 조회 불가 → OPEN 계정별 PASSWORD_LIFE_TIME" "$(echo "$_p8" | _csv)"
        _b8=$(echo "$_p8" | awk -F= '$2=="UNLIMITED" || $2+0>90 {print}' | head -8)
        if [ -z "$_p8" ]; then mc "008" "비밀번호 변경일·만료 정책 조회 실패 - 수동 확인"
        elif [ -n "$_b8" ]; then ng "008" "비밀번호 변경일 조회 권한 없음 - 만료 정책 90일 초과/무제한 계정: $(echo "$_b8" | _csv) - 서비스 운영 계정은 평가 제외 가능"
        else ok "008" "OPEN 계정 PASSWORD_LIFE_TIME 90일 이하 (변경일 조회 권한 없음 - 만료 정책 기준)"; fi
    else
        evd_q "DBM-008" "OPEN 계정 중 ptime 90일 이상 경과" "${_ptime:-없음}"
        [ -n "$_ptime" ] && ng "008" "최근 비밀번호 변경 후 90일 이상 경과 계정: $(echo "$_ptime" | head -8 | _csv) - 서비스 운영 계정은 평가 제외 가능" \
                        || ok "008" "OPEN 계정 모두 90일 이내 비밀번호 변경 (PASSWORD_CHANGE_DATE/ptime)"
    fi

    # DBM-009: 미사용 세션 종료 (resource_limit=TRUE + 계정별 IDLE_TIME 15분 이하)
    _res_lim=$(run_q "SELECT VALUE FROM V\$PARAMETER WHERE NAME='resource_limit';" | tr -d ' \n')
    _p9=$(_prof IDLE_TIME)
    evd_q "DBM-009" "resource_limit=${_res_lim}, OPEN 계정별 IDLE_TIME" "$(echo "$_p9" | _csv)"
    _b9=$(echo "$_p9" | awk -F= '$2=="UNLIMITED" || $2+0>15 {print}' | head -8)
    if [ "${_res_lim^^}" != "TRUE" ]; then ng "009" "resource_limit=${_res_lim:-FALSE} (프로파일 자원 제한 비활성 - IDLE_TIME 미적용)"
    elif [ -z "$_p9" ]; then mc "009" "IDLE_TIME 조회 실패 - 수동 확인"
    elif [ -n "$_b9" ]; then ng "009" "IDLE_TIME UNLIMITED/15분 초과 계정: $(echo "$_b9" | _csv) - 내부 규정 미명시 시 15분, 서비스 계정 평가 제외 가능"
    else ok "009" "resource_limit=TRUE, OPEN 계정 IDLE_TIME 15분 이하"; fi

    # DBM-011: 감사 로그
    if [ "${DB_MAJ:-0}" -ge 12 ] 2>/dev/null; then
        ua=$(run_q "SELECT VALUE FROM V\$OPTION WHERE PARAMETER='Unified Auditing';" | tr -d ' \n')
        if [ "$ua" = "TRUE" ]; then
            cnt=$(run_q "SELECT COUNT(DISTINCT POLICY_NAME) FROM AUDIT_UNIFIED_ENABLED_POLICIES;" 2>/dev/null | tr -d ' \n')
            [ -z "$cnt" ] && cnt=$(run_q "SELECT COUNT(*) FROM DBA_AUDIT_POLICY_COLUMNS;" 2>/dev/null | tr -d ' \n')
            evd_q "DBM-011" "Unified Auditing=TRUE, 활성 정책 수" "${cnt:-조회 불가}"
            [ "${cnt:-0}" -gt 0 ] 2>/dev/null && mc "011" "통합 감사 수집 중 (정책 ${cnt}개) - 주기적 백업 여부 인터뷰/증적 확인" || ng "011" "통합 감사 활성화됐으나 정책 없음"
        else
            at=$(run_q "SELECT VALUE FROM V\$PARAMETER WHERE NAME='audit_trail';" | tr -d ' \n')
            evd_q "DBM-011" "audit_trail" "$at"
            [ "$at" = "NONE" ] || [ -z "$at" ] && ng "011" "audit_trail=NONE" || mc "011" "audit_trail=${at} 수집 중 - 주기적 백업 여부 인터뷰/증적 확인"
        fi
    else
        at=$(run_q "SELECT VALUE FROM V\$PARAMETER WHERE NAME='audit_trail';" | tr -d ' \n')
        evd_q "DBM-011" "audit_trail" "$at"
        [ "$at" = "NONE" ] || [ -z "$at" ] && ng "011" "audit_trail=NONE" || mc "011" "audit_trail=${at} 수집 중 - 주기적 백업 여부 인터뷰/증적 확인"
    fi

    _ora_net() { local d; for d in "$TNS_ADMIN" "$("$ORACLE_HOME/bin/orabasehome" 2>/dev/null)/network/admin" "$ORACLE_HOME/network/admin"; do [ -n "$d" ] && [ -d "$d" ] && echo "$d"; done | awk '!s[$0]++'; }
    _ora_dbs() { local d; for d in "$("$ORACLE_HOME/bin/orabaseconfig" 2>/dev/null)/dbs" "$ORACLE_HOME/dbs"; do [ -d "$d" ] && echo "$d"; done | awk '!s[$0]++'; }
    # DBM-012: Listener Control Utility 접근 제한
    # 평가기준: Oracle 11.2 이상 양호 / 11.1 이하는 ADMIN_RESTRICTIONS_<리스너>=ON + lsnrctl 비밀번호(PASSWORDS_<리스너>) 설정
    evd_file "DBM-012" "$ORACLE_HOME/network/admin/listener.ora"
    evd "DBM-012" "lsnrctl status 2>/dev/null | grep -iE 'Version|Security'"
    _v1=$(echo "$DB_VER" | cut -d. -f1); _v2=$(echo "$DB_VER" | cut -d. -f2)
    if [ -z "$_v1" ]; then
        mc "012" "Oracle 버전 확인 실패 - Listener 보안 설정 수동 확인"
    elif [ "$_v1" -gt 11 ] 2>/dev/null || { [ "$_v1" -eq 11 ] && [ "${_v2:-0}" -ge 2 ]; } 2>/dev/null; then
        ok "012" "Oracle ${DB_VER} (11.2 이상 - 리스너 로컬 OS 인증 기본 적용)"
    else
        _lora=""; for lora in $(for n in $(_ora_net); do echo "$n/listener.ora"; done) "/etc/oracle/listener.ora"; do [ -f "$lora" ] && _lora="$lora" && break; done
        _ar=$(grep -iE '^\s*ADMIN_RESTRICTIONS_\S+\s*=\s*ON' "${_lora:-/nonexistent}" 2>/dev/null | head -1)
        _pw=$(grep -iE '^\s*PASSWORDS_\S+\s*=' "${_lora:-/nonexistent}" 2>/dev/null | head -1)
        if [ -z "$_lora" ]; then mc "012" "Oracle ${DB_VER} - listener.ora 미발견, 수동 확인"
        elif [ -n "$_ar" ] && [ -n "$_pw" ]; then ok "012" "Oracle ${DB_VER} - ADMIN_RESTRICTIONS=ON, lsnrctl 비밀번호 설정"
        else ng "012" "Oracle ${DB_VER} (11.1 이하) - ADMIN_RESTRICTIONS=${_ar:+ON}${_ar:-미설정/OFF}, lsnrctl 비밀번호 ${_pw:+설정}${_pw:-미설정}"; fi
    fi

    # DBM-013: 원격 접속 접근 제어
    # 평가기준: sqlnet.ora TCP.VALIDNODE_CHECKING=yes (+ INVITED/EXCLUDED_NODES) 또는 네트워크 장비·솔루션 접근제어
    _sqlnet=""
    for _sn in $(for n in $(_ora_net); do echo "$n/sqlnet.ora"; done) /etc/oracle/sqlnet.ora; do
        [ -n "$_sn" ] && [ -f "$_sn" ] && _sqlnet="$_sn" && break
    done
    evd "DBM-013" "grep -iE '^\s*TCP\.(VALIDNODE_CHECKING|INVITED_NODES|EXCLUDED_NODES)' ${_sqlnet:-/nonexistent} 2>/dev/null"
    _vnc=$(grep -iE '^\s*TCP\.VALIDNODE_CHECKING' "${_sqlnet:-/nonexistent}" 2>/dev/null | tail -1 | cut -d= -f2 | tr -d ' ')
    _inv=$(grep -iE '^\s*TCP\.(INVITED|EXCLUDED)_NODES' "${_sqlnet:-/nonexistent}" 2>/dev/null | head -2 | tr '\n' ' ')
    if [ "${_vnc,,}" = "yes" ] && [ -n "$_inv" ]; then ok "013" "TCP.VALIDNODE_CHECKING=yes, ${_inv}"
    elif [ -z "$_sqlnet" ]; then mc "013" "sqlnet.ora 미발견 - 원격 접근제어(TCP.VALIDNODE_CHECKING/방화벽/솔루션) 수동 확인"
    else ng "013" "TCP.VALIDNODE_CHECKING=${_vnc:-미설정} (${_sqlnet}) - 네트워크 장비·솔루션 접근제어 적용 시 수동 확인"; fi

    # DBM-014: OS 역할 인증 비활성화
    _osr=$(run_q "SELECT NAME||'='||VALUE FROM V\$PARAMETER WHERE NAME IN ('os_roles','remote_os_roles');" | grep "=" | tr -d ' ')
    evd_q "DBM-014" "os_roles / remote_os_roles" "$(echo "$_osr" | _csv)"
    if [ -z "$_osr" ]; then mc "014" "OS_ROLES/REMOTE_OS_ROLES 조회 실패 - 수동 확인"
    elif echo "$_osr" | grep -qi "=TRUE"; then ng "014" "운영체제 역할 인증 사용: $(echo "$_osr" | grep -i "=TRUE" | _csv)"
    else ok "014" "$(echo "$_osr" | _csv)"; fi

    # DBM-015: PUBLIC 불필요 권한
    pkgs=$(run_qa "SELECT TABLE_NAME FROM DBA_TAB_PRIVS WHERE GRANTEE='PUBLIC' AND PRIVILEGE='EXECUTE' AND TABLE_NAME IN ('UTL_HTTP','UTL_FILE','UTL_SMTP','UTL_TCP','DBMS_SCHEDULER');" | grep -v "^$" | grep -v "ORA-" | head -5)
    _pubrole=$(run_qa "SELECT GRANTED_ROLE FROM DBA_ROLE_PRIVS WHERE GRANTEE='PUBLIC';" | grep -v "^$" | grep -v "ORA-" | head -5)
    _pubsys=$(run_qa "SELECT PRIVILEGE FROM DBA_SYS_PRIVS WHERE GRANTEE='PUBLIC';" | grep -v "^$" | grep -v "ORA-" | head -5)
    evd_q "DBM-015" "PUBLIC 부여 Role / 시스템 권한 / 위험 패키지 EXECUTE" "Role: ${_pubrole:-없음} / SYS: ${_pubsys:-없음} / PKG: ${pkgs:-없음}"
    if [ -n "$_pubrole" ] || [ -n "$_pubsys" ]; then ng "015" "PUBLIC 에 Role/시스템 권한 부여: $(echo "$_pubrole $_pubsys" | tr ' ' '\n' | grep -v '^$' | _csv)"
    elif [ -n "$pkgs" ]; then ng "015" "PUBLIC EXECUTE 위험 패키지: $(echo "$pkgs" | _csv)"
    else mc "015" "PUBLIC 에 Role·시스템 권한·위험 패키지 없음 - 업무상 불필요한 Object 권한 여부 확인"; fi

    # DBM-016: 보안패치
    _patches=$(run_q "SELECT ACTION_TIME||' '||PATCH_ID||' '||DESCRIPTION FROM DBA_REGISTRY_SQLPATCH ORDER BY ACTION_TIME DESC;" 2>/dev/null | grep -v "^$" | head -10)
    evd_q "DBM-016" "SELECT ACTION_TIME,PATCH_ID,DESCRIPTION FROM DBA_REGISTRY_SQLPATCH" "${_patches:-패치 이력 없음 또는 조회 불가}"
    mc "016" "Oracle 보안패치 적용 현황 수동 확인 (위 현황 참조)"

    # DBM-017: 시스템 테이블 접근 권한
    _sys_grants=$(run_qa "SELECT GRANTEE||' → '||TABLE_NAME||' ('||PRIVILEGE||')' FROM DBA_TAB_PRIVS WHERE OWNER='SYS' AND GRANTEE<>'PUBLIC' AND GRANTEE NOT IN (SELECT USERNAME FROM DBA_USERS WHERE ORACLE_MAINTAINED='Y' UNION ALL SELECT ROLE FROM DBA_ROLES WHERE ORACLE_MAINTAINED='Y') ORDER BY 1;" | grep -v "^$")
    if echo "$_sys_grants" | grep -q "ORA-00904"; then   # 11g: ORACLE_MAINTAINED 열 없음 → 고정 목록 제외
        _sys_grants=$(run_q "SELECT GRANTEE||' → '||TABLE_NAME||' ('||PRIVILEGE||')' FROM DBA_TAB_PRIVS WHERE OWNER='SYS' AND GRANTEE NOT IN ('SYS','SYSTEM','PUBLIC','DBA','SELECT_CATALOG_ROLE') ORDER BY 1;" | grep -v "^$" | grep -v "ORA-")
    fi
    _sys_grants=$(echo "$_sys_grants" | grep -v "ORA-" | grep -v "^$")
    evd_q "DBM-017" "SYS 테이블 접근 권한 (Oracle 기본 제공 계정·역할 제외, ${_sys_grants:+$(echo "$_sys_grants" | wc -l)건})" "$(echo "${_sys_grants:-해당 권한 없음}" | head -40)"
    mc "017" "업무상 불필요한 시스템 뷰/테이블 접근 권한 수동 확인 (위 현황 참조)"

    # DBM-019: 패스워드 재사용 제한
    # 평가기준: PASSWORD_REUSE_TIME, PASSWORD_REUSE_MAX 둘 다 UNLIMITED 이면 취약 (계정별 적용 프로파일)
    _p19m=$(_prof PASSWORD_REUSE_MAX); _p19t=$(_prof PASSWORD_REUSE_TIME)
    evd_q "DBM-019" "OPEN 계정별 PASSWORD_REUSE_MAX / TIME" "$(echo "$_p19m" | _csv) / $(echo "$_p19t" | _csv)"
    _b19=$(join -t= <(echo "$_p19m" | sort) <(echo "$_p19t" | sort) 2>/dev/null | awk -F= '$2=="UNLIMITED" && $3=="UNLIMITED" {print $1}' | head -8)
    if [ -z "$_p19m" ]; then mc "019" "PASSWORD_REUSE 조회 실패 - 수동 확인"
    elif [ -n "$_b19" ]; then ng "019" "PASSWORD_REUSE_MAX·TIME 모두 UNLIMITED 계정: $(echo "$_b19" | _csv)"
    else ok "019" "OPEN 계정 비밀번호 재사용 제한 적용 (REUSE_MAX 또는 REUSE_TIME 설정)"; fi

    # DBM-020: 사용자별 계정 분리
    _user_list=$(run_qa "SELECT USERNAME||' ('||ACCOUNT_STATUS||', PROFILE='||PROFILE||')' FROM DBA_USERS WHERE ACCOUNT_STATUS LIKE '%OPEN%' ORDER BY USERNAME;" | grep -v "^$" | grep -v "ORA-" | head -40)
    evd_q "DBM-020" "OPEN 상태 사용자 목록 (CDB\$ROOT + [PDB])" "${_user_list:-조회 불가}"
    mc "020" "사용자별 개별 계정 사용 여부 수동 확인 (위 현황 참조)"

    # DBM-021: 불필요한 ODBC/OLE-DB 데이터 소스 및 드라이버 제거 (Windows MSSQL 전용)
    evd_q "DBM-021" "해당 없음 (Oracle)" "Windows MSSQL 전용 항목"
    na "021" "Windows MSSQL 전용 항목 (Oracle 해당 없음)"

    # DBM-022: 설정 파일 접근 권한 (바이너리 + 설정파일 종합)
    evd "DBM-022" "ls -la $ORACLE_HOME/network/admin/*.ora $ORACLE_HOME/bin/sqlplus $ORACLE_HOME/bin/lsnrctl $ORACLE_HOME/bin/oracle $ORACLE_HOME/dbs/init*.ora $ORACLE_HOME/dbs/spfile*.ora 2>/dev/null"
    # 평가기준: [755] bin 주요 파일 group·others 쓰기 금지 / [644] network/admin *.ora group·others 쓰기·실행 금지 / [640] spfile·init group 쓰기·실행 및 others 권한 금지
    _B=$ORACLE_HOME/bin; local _nf="" _df="" _n _spf _g644 _g640
    for _n in $(_ora_net); do _nf="$_nf $_n/listener.ora $_n/sqlnet.ora $_n/tnsnames.ora $_n/protocol.ora"; done
    for _n in $(_ora_dbs); do _df="$_df $_n/spfile*.ora $_n/init*.ora"; done
    _spf=$(run_q "SELECT VALUE FROM V\$PARAMETER WHERE NAME='spfile';" | grep '^/' | head -1)   # ASM(+DG) 경로 제외
    evd "DBM-022" "ls -laL $_nf $_df $_spf \$ORACLE_HOME/dbs/orapw* 2>/dev/null"
    _perm_check 022 $_B/oracle $_B/sqlplus $_B/sqlldr $_B/sqlload $_B/proc $_B/oraenv $_B/oerr $_B/exp $_B/imp $_B/tkprof $_B/tnsping $_B/wrap; _o22=$_PC_BAD; _f22=$_PC_FOUND
    _perm_check 033 $_nf; _o33=$_PC_BAD; _g644=$_PC_FOUND; _f22=$((_f22+_PC_FOUND))
    _perm_check 037 $(printf '%s\n' $_df $_spf | sort -u); _o37=$_PC_BAD; _g640=$_PC_FOUND; _f22=$((_f22+_PC_FOUND))
    if [ "$_f22" -eq 0 ]; then mc "022" "Oracle 설정 파일 미발견 - ORACLE_HOME 확인 필요"
    elif [ -z "$_o22$_o33$_o37" ] && [ "$_g644" -eq 0 ] && [ "$_g640" -eq 0 ]; then mc "022" "network/admin·파라미터 파일 미발견(TNS_ADMIN/읽기전용 홈 확인) - bin 권한은 적절"
    elif [ -n "$_o22$_o33$_o37" ]; then ng "022" "권한 기준 위반: ${_o22}${_o33}${_o37}"
    else ok "022" "기준 파일 ${_f22}개 권한 적절 (bin 755·network/admin 644·파라미터 파일 640 기준)"; fi

    # DBM-024: WITH GRANT OPTION
    # 평가기준 판단방법: 1) ADMIN_OPTION 시스템 권한 2) ADMIN_OPTION 역할 3) GRANTABLE 객체 권한 (Oracle 기본 제공 계정·역할 제외)
    _grant_opts=$(run_qa "SELECT 'SYSPRIV:'||GRANTEE||':'||PRIVILEGE FROM DBA_SYS_PRIVS WHERE ADMIN_OPTION='YES' AND GRANTEE NOT IN (SELECT USERNAME FROM DBA_USERS WHERE ORACLE_MAINTAINED='Y' UNION ALL SELECT ROLE FROM DBA_ROLES WHERE ORACLE_MAINTAINED='Y') UNION ALL SELECT 'ROLE:'||GRANTEE||':'||GRANTED_ROLE FROM DBA_ROLE_PRIVS WHERE ADMIN_OPTION='YES' AND GRANTEE NOT IN (SELECT USERNAME FROM DBA_USERS WHERE ORACLE_MAINTAINED='Y' UNION ALL SELECT ROLE FROM DBA_ROLES WHERE ORACLE_MAINTAINED='Y') UNION ALL SELECT 'OBJ:'||GRANTEE||':'||OWNER||'.'||TABLE_NAME||':'||PRIVILEGE FROM DBA_TAB_PRIVS WHERE GRANTABLE='YES' AND GRANTEE NOT IN (SELECT USERNAME FROM DBA_USERS WHERE ORACLE_MAINTAINED='Y' UNION ALL SELECT ROLE FROM DBA_ROLES WHERE ORACLE_MAINTAINED='Y') AND OWNER NOT IN (SELECT USERNAME FROM DBA_USERS WHERE ORACLE_MAINTAINED='Y');" | grep -v "^$")
    if echo "$_grant_opts" | grep -q "ORA-00904"; then   # 11g
        _grant_opts=$(run_q "SELECT 'SYSPRIV:'||GRANTEE||':'||PRIVILEGE FROM DBA_SYS_PRIVS WHERE ADMIN_OPTION='YES' AND GRANTEE NOT IN ('SYS','SYSTEM','DBA') UNION ALL SELECT 'ROLE:'||GRANTEE||':'||GRANTED_ROLE FROM DBA_ROLE_PRIVS WHERE ADMIN_OPTION='YES' AND GRANTEE NOT IN ('SYS','SYSTEM','DBA') UNION ALL SELECT 'OBJ:'||GRANTEE||':'||OWNER||'.'||TABLE_NAME||':'||PRIVILEGE FROM DBA_TAB_PRIVS WHERE GRANTABLE='YES' AND OWNER NOT IN ('SYS','SYSTEM','XDB','MDSYS','CTXSYS','ORDSYS','WMSYS','OLAPSYS','EXFSYS','DBSNMP','OUTLN','APEX_030200','FLOWS_FILES');" | grep -v "^$" | grep -v "ORA-")
    fi
    _grant_opts=$(echo "$_grant_opts" | grep -v "ORA-" | grep -v "^$" | head -40)
    evd_q "DBM-024" "ADMIN_OPTION 시스템 권한·역할 / GRANTABLE 객체 권한 (Oracle 기본 제공 제외)" "${_grant_opts:-해당 없음}"
    mc "024" "WITH GRANT OPTION 부여 현황 수동 확인 (위 현황 참조)"

    # DBM-025: EoS
    _ver_info=$(run_q "SELECT BANNER FROM V\$VERSION;" 2>/dev/null | head -3)
    evd_q "DBM-025" "Oracle 버전 정보 (EoS 판단용)" "${_ver_info:-${DB_VER}}"
    mc "025" "Oracle ${DB_VER} EoS 여부 수동 확인 (위 버전 참조)"

    # DBM-026: 구동 계정 umask
    evd "DBM-026" "ps -ef 2>/dev/null | grep ora_pmon | grep -v grep | head -3"
    _ora_user=$(ps -ef 2>/dev/null | grep ora_pmon | grep -v grep | awk '{print $1}' | head -1)
    [ -z "$_ora_user" ] && _ora_user="oracle"
    _ora_umask=$(_get_umask "$_ora_user" "ora_pmon")
    _judge_umask "$_ora_umask" "Oracle" "026" "$_ora_user"

    # DBM-028: 불필요 DB Object
    _pub_syn=$(run_qa "SELECT SYNONYM_NAME||' → '||TABLE_OWNER||'.'||TABLE_NAME FROM DBA_SYNONYMS WHERE OWNER='PUBLIC' AND TABLE_OWNER NOT IN ('SYS','SYSTEM','PUBLIC') ORDER BY 1;" 2>/dev/null | grep -v "^$" | head -20)
    evd_q "DBM-028" "PUBLIC synonym (비시스템 소유)" "${_pub_syn:-해당 없음}"
    mc "028" "불필요 DB Object(PUBLIC synonym 등) 수동 확인 (위 현황 참조)"

    # DBM-029: 자원 사용 제한 (프로파일)
    # 평가기준: 자원 사용 제한 설정(RESOURCE_LIMIT) FALSE 이면 취약
    sess=$(run_q "SELECT LIMIT FROM DBA_PROFILES WHERE PROFILE='DEFAULT' AND RESOURCE_NAME='SESSIONS_PER_USER';" | tr -d ' \n')
    evd_q "DBM-029" "resource_limit / (참고) DEFAULT SESSIONS_PER_USER" "${_res_lim} / ${sess}"
    case "${_res_lim^^}" in
    TRUE)  ok "029" "RESOURCE_LIMIT=TRUE (자원 사용 제한 활성)" ;;
    FALSE) ng "029" "RESOURCE_LIMIT=FALSE (자원 사용 제한 비활성)" ;;
    *)     mc "029" "RESOURCE_LIMIT 조회 실패 - 수동 확인" ;;
    esac

    # DBM-030: Audit Table 접근 제어
    # 평가기준: AUD$ 소유자가 관리자 계정이 아니거나 일반 계정에 삽입/수정/삭제 권한이 있으면 취약 (SELECT·관리 롤은 제외)
    _aud_own=$(run_q "SELECT OWNER FROM DBA_TABLES WHERE TABLE_NAME='AUD\$';" | grep -v "^$" | grep -v "ORA-" | _csv)
    _aud_grants=$(run_qa "SELECT GRANTEE||' → '||TABLE_NAME||' ('||PRIVILEGE||')' FROM DBA_TAB_PRIVS WHERE TABLE_NAME IN ('AUD\$','FGA_LOG\$') AND PRIVILEGE IN ('INSERT','UPDATE','DELETE') AND GRANTEE NOT IN ('SYS','SYSTEM','DBA','DELETE_CATALOG_ROLE','AUDIT_ADMIN','AUDSYS') ORDER BY 1;" 2>/dev/null | grep -v "^$" | head -10)
    evd_q "DBM-030" "AUD\$ 소유자 / 비관리 계정 INSERT·UPDATE·DELETE 권한" "owner=${_aud_own:-미확인} / ${_aud_grants:-없음}"
    if [ -n "$_aud_own" ] && ! echo "$_aud_own" | grep -qE '^(SYS|SYSTEM|AUDSYS)(,|$)'; then ng "030" "AUD\$ 소유자가 관리자 계정 아님: ${_aud_own}"
    elif [ -n "$_aud_grants" ]; then ng "030" "AUD\$ 수정/삭제 권한 보유 일반 계정: $(echo "$_aud_grants" | _csv)"
    else ok "030" "AUD\$ 소유자 ${_aud_own:-SYS}, 일반 계정 수정/삭제 권한 없음"; fi

    evd_q "DBM-031" "해당 없음 (Oracle)" "MSSQL 전용 항목"
    na "031" "MSSQL 전용 항목"

    # DBM-032: 통신구간 암호화 (SQLNET.ENCRYPTION)
    evd "DBM-032" "grep -i 'SQLNET.ENCRYPTION_SERVER\|SQLNET.CRYPTO_CHECKSUM_SERVER' $ORACLE_HOME/network/admin/sqlnet.ora 2>/dev/null || echo '(sqlnet.ora 미설정)'"
    _ora_enc=""
    for _sf in $(for n in $(_ora_net); do echo "$n/sqlnet.ora"; done) "/etc/oracle/sqlnet.ora"; do
        [ -f "$_sf" ] || continue
        _ora_enc=$(grep -i "SQLNET.ENCRYPTION_SERVER" "$_sf" 2>/dev/null | grep -oiE "(REQUIRED|REQUESTED|ACCEPTED|REJECTED)" | head -1)
        [ -n "$_ora_enc" ] && break
    done
    if [ -n "$_ora_enc" ]; then
        case "${_ora_enc^^}" in
        REQUIRED)  ok "032" "SQLNET.ENCRYPTION_SERVER=REQUIRED (네트워크 암호화 강제)" ;;
        REQUESTED) ok "032" "SQLNET.ENCRYPTION_SERVER=REQUESTED (네트워크 암호화 요청)" ;;
        ACCEPTED)  mc "032" "SQLNET.ENCRYPTION_SERVER=ACCEPTED (기본값) - 클라이언트 설정에 따라 암호화 수동 확인" ;;
        REJECTED)  ng "032" "SQLNET.ENCRYPTION_SERVER=REJECTED (네트워크 암호화 거부)" ;;
        esac
    else
        mc "032" "SQLNET.ENCRYPTION_SERVER 미설정 (기본: ACCEPTED) - sqlnet.ora 수동 확인"
    fi

    # DBM-033: 이중화 비밀번호 평문 노출 (Data Guard)
    _ora_dg=$(run_q "SELECT DEST_NAME||' (TYPE='||TYPE||')' FROM V\$ARCHIVE_DEST_STATUS WHERE STATUS='VALID' AND TYPE<>'LOCAL';" 2>/dev/null | grep -v "^$" | head -5)
    evd_q "DBM-033" "V\$ARCHIVE_DEST_STATUS (원격 전송)" "${_ora_dg:-해당 없음 (Data Guard 미구성)}"
    if [ -n "$_ora_dg" ]; then
        mc "033" "Data Guard 원격 전송 구성됨 - SSL/암호화 적용 여부 수동 확인 (위 현황 참조)"
    else
        na "033" "Data Guard/Streams 미구성"
    fi

    # DBM-034: DBMS 서비스 구동 권한
    evd "DBM-034" "ps -ef 2>/dev/null | grep ora_pmon | grep -v grep"
    oracle_proc=$(ps -ef 2>/dev/null | grep ora_pmon | grep -v grep | awk '{print $1}' | head -1)
    [ -n "$oracle_proc" ] && {
        [ "$oracle_proc" = "root" ] && ng "034" "Oracle 프로세스 root 계정으로 실행" || ok "034" "Oracle 구동 계정: ${oracle_proc}"
    } || mc "034" "Oracle 구동 계정 수동 확인"

    evd_q "DBM-035" "해당 없음 (Oracle)" "MSSQL 전용 항목 (xp_cmdshell)"
    na "035" "MSSQL 전용 항목"
    evd_q "DBM-036" "해당 없음 (Oracle)" "MSSQL 전용 항목 (Registry Procedure)"
    na "036" "MSSQL 전용 항목"
}

# ================================================================
# MySQL/MariaDB 점검
# ================================================================
check_mysql() {
    MYSQL_USER="${MYSQL_USER:-root}"
    MYSQL_PASS="${MYSQL_PASS-}"
    MYSQL_HOST="${MYSQL_HOST:-localhost}"
    MYSQL_PORT="${MYSQL_PORT:-3306}"
    MYSQL_SOCKET="${MYSQL_SOCKET:-}"

    MYSQL_CMD=$(command -v mysql 2>/dev/null || command -v mariadb 2>/dev/null)
    if [ -z "$MYSQL_CMD" ]; then
        printf '[FALLBACK] %s mysql 클라이언트 미탐지 - MySQL 전 항목 수동 확인 처리\n\n' "$(date '+%H:%M:%S')" >> "$_EVD"
        for i in 001 003 004 005 006 007 008 009 011 013 016 017 019 020 022 \
                 024 025 026 028 032 033 034; do mc "$i" "mysql 클라이언트 미탐지"; done
        na "012" "Oracle 전용 항목"
        na "014" "Oracle 전용 항목"
        na "015" "Oracle/MSSQL 전용 항목"
        na "021" "Windows MSSQL 전용 항목"
        na "029" "Oracle 전용 항목"
        na "030" "Oracle/Tibero 전용 항목"
        na "031" "MSSQL 전용 항목"
        na "035" "MSSQL 전용 항목"
        na "036" "MSSQL 전용 항목"
        return
    fi

    local _base
    if [ -n "$MYSQL_SOCKET" ]; then _base="-u ${MYSQL_USER} -S ${MYSQL_SOCKET}"
    elif [ "$MYSQL_HOST" = "localhost" ]; then _base="-u ${MYSQL_USER}"   # localhost = 유닉스 소켓
    else _base="-u ${MYSQL_USER} -h ${MYSQL_HOST} -P ${MYSQL_PORT}"; fi
    # 비밀번호 미지정: 소켓/OS 인증(auth_socket·unix_socket)·~/.my.cnf·빈 비밀번호 순으로 먼저 시도
    if [ -z "$MYSQL_PASS" ] && $MYSQL_CMD $_base -N --batch -e "SELECT CONCAT('CONN_','OK');" 2>/dev/null | grep -q CONN_OK; then
        OPTS="$_base -N --batch"
    else
        [ -z "$MYSQL_PASS" ] && [ -t 0 ] && { read -rs -p "MySQL ${MYSQL_USER} 비밀번호: " MYSQL_PASS </dev/tty; echo >&2; }
        _MYSQL_CNF=$(mktemp /tmp/.dbm_check_XXXXXX.cnf 2>/dev/null || echo "/tmp/.dbm_check_$$.cnf")
        (umask 077; printf '[client]\nuser=%s\n%s\n' "$MYSQL_USER" "${MYSQL_PASS:+password=$MYSQL_PASS}" > "$_MYSQL_CNF")
        chmod 600 "$_MYSQL_CNF" 2>/dev/null
        trap "rm -f '$_MYSQL_CNF'" EXIT
        OPTS="--defaults-extra-file=${_MYSQL_CNF} $_base -N --batch"
    fi

    run_q() { $MYSQL_CMD $OPTS -e "$1" 2>/dev/null | grep -v "^$"; }
    get_var() { $MYSQL_CMD $OPTS -e "SHOW VARIABLES LIKE '$1';" 2>/dev/null | awk '{print $2}'; }

    _conn_ok "$(run_q "SELECT CONCAT('CONN_','OK');")" "MySQL/MariaDB" || return
    DB_VER=$($MYSQL_CMD $OPTS -e "SELECT VERSION();" 2>/dev/null | head -1)
    IS_MARIADB=0; echo "$DB_VER" | grep -qi "mariadb" && IS_MARIADB=1
    [ $IS_MARIADB -eq 1 ] && echo "# DBMS 종류(판별): mariadb"
    echo "# MySQL/MariaDB 버전: ${DB_VER}"

    # DBM-001: 취약 패스워드 + 인증 플러그인 검증
    anon=$(run_q "SELECT COUNT(*) FROM mysql.user WHERE User='';" | tail -1)
    evd_q "DBM-001" "익명 계정 수" "$anon"
    [ "${anon:-0}" -gt 0 ] 2>/dev/null && ng "001" "익명 계정 ${anon}개 존재" || mc "001" "익명 계정 없음 - 계정 비밀번호 복잡도·취약 비밀번호 여부는 해시 크랙으로 확인 필요"

    _weak_auth=$($MYSQL_CMD $OPTS -e "SELECT CONCAT(User,'@',Host) FROM mysql.user WHERE plugin IS NULL OR plugin='' OR plugin NOT IN ('caching_sha2_password','sha256_password','auth_socket','unix_socket','mysql_native_password','ed25519','client_ed25519','pam','auth_pam');" 2>&1 | grep -v "^$" | head -5)
    evd_q "DBM-001" "비안전 인증 플러그인 계정" "$_weak_auth"
    if echo "$_weak_auth" | grep -q '^ERROR'; then   # plugin 열 없는 구버전(5.5.7 미만)
        _old=$(run_q "SELECT CONCAT(User,'@',Host) FROM mysql.user WHERE LENGTH(Password)=16;" 2>/dev/null | head -5)
        evd_q "DBM-001" "구형 해시(mysql_old_password 16자) 계정" "${_old:-없음}"
        mc "001" "인증 플러그인 정보 없음(구버전 ${DB_VER})${_old:+ - 구형 해시 계정: $(echo "$_old" | _csv)} - 계정 비밀번호 복잡도·취약 비밀번호 여부는 해시 크랙으로 확인 필요"
    elif [ -n "$_weak_auth" ]; then
        mc "001" "(참고) caching_sha2_password 미사용 계정: $(echo "$_weak_auth" | _csv) - 계정 비밀번호 복잡도·취약 비밀번호 여부는 해시 크랙으로 확인 필요"
    else
        _def_auth=$(get_var "default_authentication_plugin")
        mc "001" "전 계정 안전한 인증 플러그인 사용${_def_auth:+ (default=${_def_auth})} - 계정 비밀번호 복잡도·취약 비밀번호 여부는 해시 크랙으로 확인 필요"
    fi

    # DBM-003: 불필요 계정
    _all_users=$(run_q "SELECT CONCAT(User,'@',Host,' (',plugin,')') FROM mysql.user ORDER BY User;" | head -30)
    evd_q "DBM-003" "SELECT User,Host,plugin FROM mysql.user" "${_all_users:-조회 불가}"
    mc "003" "불필요/미사용 계정 수동 확인 (위 현황 참조)"

    # DBM-004: 불필요 관리자 계정
    # 평가기준: Global 수준 권한 부여 계정 목록 → 인터뷰 (mysql.user 전역 *_priv='Y')
    super=$(run_q "SELECT CONCAT(User,'@',Host) FROM mysql.user WHERE User NOT IN ('mysql.session','mysql.sys','mysql.infoschema','mariadb.sys','') AND (Super_priv='Y' OR Grant_priv='Y' OR Create_user_priv='Y' OR Process_priv='Y' OR File_priv='Y' OR Shutdown_priv='Y' OR Reload_priv='Y' OR Insert_priv='Y' OR Update_priv='Y' OR Delete_priv='Y' OR Drop_priv='Y' OR Alter_priv='Y') ORDER BY 1;" | head -10)
    evd_q "DBM-004" "Global 수준 권한 보유 계정" "$super"
    mc "004" "Global 수준 권한 계정: $(echo "${super:-없음}" | _csv) - 업무상 필요 여부 인터뷰 확인"

    # DBM-005: 중요정보 암호화
    _enc_info=$(run_q "SELECT TABLE_SCHEMA,TABLE_NAME,CREATE_OPTIONS FROM information_schema.TABLES WHERE CREATE_OPTIONS LIKE '%ENCRYPTION%';" 2>/dev/null | head -10)
    evd_q "DBM-005" "ENCRYPTION 옵션 사용 테이블" "${_enc_info:-암호화 테이블 없음 또는 조회 불가}"
    mc "005" "중요 컬럼(주민번호, 비밀번호 등) 암호화 여부 수동 확인 (위 현황 참조)"

    # DBM-006: 로그인 실패 횟수
    # 평가기준: 5회 연속 로그인 실패 시 일정시간 접속 제한 (failed_login_attempts≤5 또는 connection_control 플러그인)
    #   max_connect_errors 는 호스트 연결 오류 카운터로 로그인 실패 잠금이 아님 → 판정에 사용하지 않음
    _fla_err=$($MYSQL_CMD $OPTS -e "SELECT User_attributes FROM mysql.user LIMIT 1;" 2>&1 | grep '^ERROR')   # 8.0.19 미만·MariaDB 는 열 없음
    _fla=$(run_q "SELECT CONCAT(User,'@',Host,'=',IFNULL(JSON_EXTRACT(User_attributes,'\$.Password_locking.failed_login_attempts'),0),'/',IFNULL(JSON_EXTRACT(User_attributes,'\$.Password_locking.password_lock_time_days'),0)) FROM mysql.user WHERE account_locked='N' AND User NOT IN ('mysql.session','mysql.sys','mysql.infoschema','') AND plugin NOT IN ('auth_socket','unix_socket');" 2>/dev/null | grep -v "^$" | head -20)
    _cc=$(run_q "SELECT PLUGIN_NAME,PLUGIN_STATUS FROM information_schema.PLUGINS WHERE PLUGIN_NAME LIKE 'CONNECTION_CONTROL%';" 2>/dev/null | grep -v "^$")
    _cct=$(get_var "connection_control_failed_connections_threshold")
    evd_q "DBM-006" "failed_login_attempts / connection_control" "failed_login_attempts: ${_fla:-미설정} / plugin: ${_cc:-미로드} / threshold=${_cct:-N/A} / max_connect_errors(참고)=$(get_var max_connect_errors)"
    # 로그인 가능 계정별 failed_login_attempts(0=미설정) 5 초과/미설정 또는 lock_time 0 → 위반
    _fla_bad=$(echo "$_fla" | awk -F= '{split($NF,a,"/")} a[1]+0==0 || a[1]+0>5 || a[2]+0==0' | head -5)
    _mpe=""; [ "$IS_MARIADB" = "1" ] && _mpe=$(get_var "max_password_errors")
    # MariaDB 10.4+: max_password_errors 1~5 양호, 5 초과(기본 4294967295 포함) 취약
    if [ -n "$_mpe" ]; then
        evd_q "DBM-006" "MariaDB max_password_errors" "$_mpe"
        if [ "$_mpe" -ge 1 ] 2>/dev/null && [ "$_mpe" -le 5 ] 2>/dev/null; then ok "006" "MariaDB max_password_errors=${_mpe}"
        else ng "006" "MariaDB max_password_errors=${_mpe} (5 초과 - 로그인 실패 잠금 미흡)"; fi
    elif [ -n "$_fla" ] && [ -z "$_fla_bad" ]; then
        ok "006" "로그인 가능 계정 모두 failed_login_attempts≤5·잠금 시간 설정: $(echo "$_fla" | _csv)"
    elif [ -n "$_cct" ] && [ "$_cct" -gt 0 ] 2>/dev/null && [ "$_cct" -le 5 ] 2>/dev/null; then
        mc "006" "connection_control 플러그인(연속 실패 ${_cct}회 시 응답 지연) - 기준의 접속 제한(잠금/차단) 해당 여부 확인 / 계정 잠금 미설정: $(echo "$_fla_bad" | _csv)"
    elif [ -n "$_fla_err" ] && [ -z "$_fla" ]; then
        ng "006" "계정 잠금 기능 미지원 버전(${DB_VER}, failed_login_attempts 는 8.0.19+) - connection_control·장비·솔루션 적용 시 수동 확인"
    else
        ng "006" "계정 잠금 미설정/5회 초과 계정(failed_login_attempts/lock_days): $(echo "${_fla_bad:-전체}" | _csv) - 서비스 운영 계정은 평가 제외 가능, 외부 솔루션 적용 시 수동 확인"
    fi

    # DBM-007: 패스워드 복잡도
    # 평가기준 복잡도: 2종 10자 이상 / 3종 8자 이상 — 플러그인 로드 + 길이·문자 종류 설정값 확인
    if [ $IS_MARIADB -eq 1 ]; then
        sp_len=$(get_var "simple_password_check_minimal_length"); sp_d=$(get_var "simple_password_check_digits")
        sp_l=$(get_var "simple_password_check_letters_same_case"); sp_o=$(get_var "simple_password_check_other_characters")
        evd_q "DBM-007" "simple_password_check minimal_length/digits/letters_same_case/other_characters" "${sp_len:-미로드}/${sp_d}/${sp_l}/${sp_o}"
        # 요구 종류: 영문(대소문자 각 N 이상=letters_same_case) / 숫자 / 특수문자
        _cls=0; [ "${sp_d:-0}" -ge 1 ] 2>/dev/null && _cls=$((_cls+1)); [ "${sp_l:-0}" -ge 1 ] 2>/dev/null && _cls=$((_cls+1)); [ "${sp_o:-0}" -ge 1 ] 2>/dev/null && _cls=$((_cls+1))
        if [ -z "$sp_len" ]; then ng "007" "MariaDB simple_password_check 플러그인 미로드 - cracklib·솔루션 사용 시 수동 확인"
        elif { [ "$_cls" -ge 3 ] && [ "$sp_len" -ge 8 ]; } || { [ "$_cls" -ge 2 ] && [ "$sp_len" -ge 10 ]; }; then ok "007" "simple_password_check 최소 ${sp_len}자, 숫자 ${sp_d}·대소문자 ${sp_l}·특수 ${sp_o}"
        else ng "007" "simple_password_check 기준 미달 (최소 ${sp_len}자, 숫자 ${sp_d}·대소문자 ${sp_l}·특수 ${sp_o})"; fi
    else
        policy=$(get_var "validate_password.policy"); [ -z "$policy" ] && policy=$(get_var "validate_password_policy")
        vlen=$(get_var "validate_password.length"); [ -z "$vlen" ] && vlen=$(get_var "validate_password_length")
        evd_q "DBM-007" "validate_password.policy / length" "${policy:-미설치} / ${vlen:-}"
        if [ -z "$policy" ]; then
            ng "007" "validate_password 플러그인 미설치 - 솔루션 사용 시 수동 확인"
        else
            case "${policy^^}" in
            STRONG|2|MEDIUM|1)   # MEDIUM 이상: mixed_case/number/special_char_count 로 요구 문자 종류 산정 → 3종 8자 / 2종 10자
                local _mc _nc _sc _k=0
                _mc=$(get_var "validate_password.mixed_case_count"); _nc=$(get_var "validate_password.number_count"); _sc=$(get_var "validate_password.special_char_count")
                [ "${_mc:-1}" -ge 1 ] 2>/dev/null && _k=$((_k+1)); [ "${_nc:-1}" -ge 1 ] 2>/dev/null && _k=$((_k+1)); [ "${_sc:-1}" -ge 1 ] 2>/dev/null && _k=$((_k+1))
                if { [ "$_k" -ge 3 ] && [ "${vlen:-0}" -ge 8 ]; } || { [ "$_k" -ge 2 ] && [ "${vlen:-0}" -ge 10 ]; } 2>/dev/null; then
                    ok "007" "validate_password.policy=${policy}, length=${vlen}, 대소문자·숫자·특수 ${_mc}/${_nc}/${_sc}"
                else ng "007" "validate_password 기준 미달 (length=${vlen}, 대소문자·숫자·특수 ${_mc}/${_nc}/${_sc} - 3종 8자/2종 10자)"; fi ;;
            LOW|0) [ "${vlen:-0}" -ge 10 ] 2>/dev/null && mc "007" "validate_password.policy=LOW(길이만 검사), length=${vlen} - 문자 조합 강제 여부 확인" \
                                                        || ng "007" "validate_password.policy=LOW, length=${vlen} (문자 조합 미강제)" ;;
            *) mc "007" "validate_password.policy=${policy}" ;;
            esac
        fi
    fi

    # DBM-008: 패스워드 변경 주기
    expire=$(get_var "default_password_lifetime")
    _plc=""; _plc_err=""
    if [ $IS_MARIADB -eq 0 ]; then   # password_last_changed 는 5.7.4+ — 조회 오류는 '변경일 미제공'(가이드: 만료 정책 → 인터뷰)
        _plc=$($MYSQL_CMD $OPTS -e "SELECT CONCAT(User,'@',Host,'=',DATE(password_last_changed)) FROM mysql.user WHERE account_locked='N' AND User NOT IN ('mysql.session','mysql.sys','mysql.infoschema','') AND password_last_changed < NOW()-INTERVAL 90 DAY;" 2>&1 | grep -v "^$" | head -10)
        echo "$_plc" | grep -q '^ERROR' && { _plc_err="$_plc"; _plc=""; }
    fi
    evd_q "DBM-008" "default_password_lifetime / password_last_changed 90일 경과 계정" "${expire:-미지원} / ${_plc:-없음}${_plc_err:+ ($_plc_err)}"
    if [ $IS_MARIADB -eq 0 ] && [ -n "$_plc" ]; then
        ng "008" "최근 비밀번호 변경 후 90일 이상 경과 계정: $(echo "$_plc" | _csv) - 서비스 운영 계정은 평가 제외 가능"
    elif [ $IS_MARIADB -eq 0 ] && [ -n "$_plc_err" ]; then
        if [ "${expire:-0}" -gt 0 ] 2>/dev/null && [ "$expire" -le 90 ] 2>/dev/null; then ok "008" "변경일 미제공 - default_password_lifetime=${expire}일(90일 이하 만료)"
        else mc "008" "비밀번호 변경일(password_last_changed) 미제공 버전/조회 불가(${DB_VER}) - 인터뷰·증적으로 90일 내 변경 여부 확인"; fi
    elif [ $IS_MARIADB -eq 0 ]; then
        ok "008" "로그인 가능 계정 모두 90일 이내 비밀번호 변경 (password_last_changed, lifetime=${expire:-0})"
    elif [ -z "$expire" ]; then
        mc "008" "default_password_lifetime 미지원(MariaDB 10.4 미만, ${DB_VER})/조회 불가 - 인터뷰·증적으로 90일 내 변경 여부 확인"
    elif [ "$expire" = "0" ]; then
        ng "008" "default_password_lifetime=0 (비밀번호 만료 없음)"
    elif [ "$expire" -le 90 ] 2>/dev/null; then
        ok "008" "default_password_lifetime=${expire}일 (90일 이하)"
    else
        ng "008" "default_password_lifetime=${expire}일 (90일 초과)"
    fi

    # DBM-009: 미사용 세션 종료
    timeout=$(get_var "wait_timeout")
    itimeout=$(get_var "interactive_timeout")
    evd_q "DBM-009" "wait_timeout=${timeout:-N/A}, interactive_timeout=${itimeout:-N/A}" ""
    _t_max=${timeout:-28800}; [ "${itimeout:-28800}" -gt "$_t_max" ] 2>/dev/null && _t_max=$itimeout
    [ "$_t_max" -le 900 ] 2>/dev/null && ok "009" "wait_timeout=${timeout}초, interactive_timeout=${itimeout}초" || \
        ng "009" "세션 타임아웃 초과 (wait=${timeout}, interactive=${itimeout}, 900초(15분) 이하 - 내부 규정 미명시 시 15분 기준)"

    # DBM-011: 감사 로그 (MariaDB server_audit 포함)
    glog=$(get_var "general_log")
    alog=$(get_var "audit_log_policy")
    _sa_log=$(get_var "server_audit_logging")
    _apl=$(run_q "SELECT PLUGIN_NAME,PLUGIN_STATUS FROM information_schema.PLUGINS WHERE PLUGIN_NAME IN ('audit_log','SERVER_AUDIT') OR PLUGIN_NAME LIKE '%audit%';" 2>/dev/null | grep -v "^$")
    evd_q "DBM-011" "audit 플러그인 / audit_log_policy / server_audit_logging / general_log(참고)" "plugin: ${_apl:-미로드} / policy=${alog:-N/A} / server_audit=${_sa_log:-OFF} / general_log=${glog}"
    # 평가기준: 감사 로그(audit_log 플러그인 등) 수집 + 주기적 백업(인터뷰). general_log 는 감사 로그가 아님
    if echo "$_apl" | grep -qi "ACTIVE" || echo "${alog^^}" | grep -qE "ALL|LOGINS|QUERIES" || [ "${_sa_log^^}" = "ON" ]; then
        mc "011" "감사 로그 수집 중 (plugin=$(echo "$_apl" | head -1 | _csv), server_audit=${_sa_log:-N/A}) - 주기적 백업 여부 인터뷰/증적 확인"
    else
        ng "011" "감사 로그 플러그인 미로드 (general_log=${glog:-OFF}는 감사 로그 아님) - 써드파티 솔루션 사용 시 수동 확인"
    fi

    # DBM-013: 원격 접속 접근 제어
    # 평가기준: mysql.user Host 칼럼이 '%' 인 계정 존재 시 취약 (bind_address 는 참고 증적)
    bind=$(get_var "bind_address")
    _wild_host=$(run_q "SELECT CONCAT(User,'@',Host) FROM mysql.user WHERE Host='%' AND User NOT IN ('');" 2>/dev/null | head -5)
    evd_q "DBM-013" "host='%' 계정 / bind_address(참고)" "${_wild_host:-없음} / bind_address=${bind:-미설정}"
    case "$bind" in
    "127.0.0.1"|"localhost"|"::1") ok "013" "bind_address=${bind} (로컬 접속만 허용)" ;;
    *) if [ -n "$_wild_host" ]; then ng "013" "Host='%' 원격 접속 허용 계정: $(echo "$_wild_host" | _csv)"
       else ok "013" "Host='%' 계정 없음 (계정별 접속 호스트 제한, bind_address=${bind:-기본})"; fi ;;
    esac

    # DBM-016: 보안패치
    evd_q "DBM-016" "MySQL/MariaDB 버전 (패치 판단용)" "${DB_VER}"
    mc "016" "MySQL/MariaDB ${DB_VER} 보안패치 적용 현황 수동 확인"

    # DBM-017: 시스템 테이블 접근 권한
    _db_grants=$(run_q "SELECT CONCAT(User,'@',Host,' → *.* (global SELECT)') FROM mysql.user WHERE Select_priv='Y' AND User NOT IN ('root','mysql.sys','mysql.session','mysql.infoschema','mariadb.sys','') UNION ALL SELECT CONCAT(User,'@',Host,' → ',Db,'.* (',Select_priv,Insert_priv,Update_priv,Delete_priv,')') FROM mysql.db WHERE ('mysql' LIKE Db OR 'sys' LIKE Db OR 'performance_schema' LIKE Db) AND User NOT IN ('root','mysql.sys','mysql.session','mysql.infoschema','mariadb.sys','') UNION ALL SELECT CONCAT(User,'@',Host,' → ',Db,'.',Table_name,' (',Table_priv,')') FROM mysql.tables_priv WHERE Db IN ('mysql','sys','performance_schema') AND User NOT IN ('root','mysql.sys','mysql.session','mysql.infoschema','mariadb.sys','');" 2>/dev/null | head -20)
    evd_q "DBM-017" "시스템 DB 접근 권한 (비시스템 계정)" "${_db_grants:-해당 없음}"
    mc "017" "information_schema, mysql 데이터베이스 접근 권한 수동 확인 (위 현황 참조)"

    # DBM-019: 패스워드 재사용
    if [ $IS_MARIADB -eq 0 ]; then
        _pw_hist=$($MYSQL_CMD $OPTS -e "SELECT @@global.password_history;" 2>&1 | tail -1)
        _pw_reuse=$(run_q "SELECT @@global.password_reuse_interval;" 2>/dev/null | tail -1)
        evd_q "DBM-019" "password_history=${_pw_hist:-0}, password_reuse_interval=${_pw_reuse:-0}" ""
        # 평가기준: password_history 가 0 이거나 password_reuse_interval 이 0 이면 취약 → 둘 다 설정되어야 양호
        if echo "$_pw_hist" | grep -q 'ERROR'; then
            mc "019" "password_history 미지원(MySQL 8.0.3 미만, ${DB_VER}) - 플러그인·솔루션·내부 정책으로 재사용 제한 여부 확인(미제한 시 취약)"
        elif [ "${_pw_hist:-0}" -gt 0 ] 2>/dev/null && [ "${_pw_reuse:-0}" -gt 0 ] 2>/dev/null; then
            ok "019" "password_history=${_pw_hist}, password_reuse_interval=${_pw_reuse}일"
        else
            ng "019" "비밀번호 재사용 제한 미흡 (password_history=${_pw_hist:-0}, password_reuse_interval=${_pw_reuse:-0} - 둘 다 설정 필요)"
        fi
    else
        _prc=$(run_q "SELECT PLUGIN_STATUS FROM information_schema.PLUGINS WHERE PLUGIN_NAME='password_reuse_check';" 2>/dev/null | head -1)
        evd_q "DBM-019" "MariaDB password_reuse_check 플러그인" "${_prc:-미설치} (interval=$(get_var password_reuse_check_interval))"
        if [ "$_prc" = "ACTIVE" ]; then ok "019" "password_reuse_check 플러그인 활성 (password_reuse_check_interval=$(get_var password_reuse_check_interval)일, 0=기간 제한 없이 이력 재사용 금지)"
        else mc "019" "MariaDB password_reuse_check 미사용 - 플러그인·솔루션·내부 정책으로 재사용 제한 여부 확인(미제한 시 취약)"; fi
    fi

    # DBM-020: 사용자별 계정 분리
    _my_users=$(run_q "SELECT CONCAT(User,'@',Host) FROM mysql.user WHERE User NOT IN ('mysql.sys','mysql.session','mysql.infoschema','') ORDER BY User;" | head -20)
    evd_q "DBM-020" "전체 사용자 목록" "${_my_users:-조회 불가}"
    mc "020" "공용 계정 사용 여부 수동 확인 (위 현황 참조)"

    # DBM-021: 불필요한 ODBC/OLE-DB 데이터 소스 및 드라이버 제거 (Windows MSSQL 전용)
    evd_q "DBM-021" "해당 없음 (MySQL/MariaDB)" "Windows MSSQL 전용 항목"
    na "021" "Windows MSSQL 전용 항목 (MySQL/MariaDB 해당 없음)"

    # DBM-022: 설정 파일 권한
    evd "DBM-022" "ls -laL /etc/my.cnf /etc/my.cnf.d/*.cnf /etc/mysql/my.cnf /etc/mysql/conf.d/*.cnf /etc/mysql/mysql.conf.d/*.cnf /etc/mysql/mariadb.conf.d/*.cnf /etc/mysql/mariadb.cnf /etc/mysql/debian.cnf 2>/dev/null"
    # 평가기준 640: group 쓰기·실행 및 others 권한 금지 (심볼릭 링크는 대상 파일 권한)
    _perm_check 037 /etc/my.cnf /etc/my.ini /etc/my.cnf.d/*.cnf /etc/mysql/my.cnf /etc/mysql/conf.d/*.cnf \
                /etc/mysql/mysql.conf.d/*.cnf /etc/mysql/mariadb.conf.d/*.cnf /var/lib/mysql/my.cnf /etc/mysql/mariadb.cnf /etc/mysql/debian.cnf; _b22=$_PC_BAD
    if [ "$_PC_FOUND" -eq 0 ]; then
        mc "022" "MySQL 설정 파일 미발견 - 수동 확인 (my.cnf 위치)"
    elif [ -n "$_b22" ]; then
        ng "022" "설정 파일 권한 기준(640) 위반: ${_b22}"
    else
        ok "022" "설정 파일 ${_PC_FOUND}개 권한 640 기준 충족"
    fi

    # DBM-024: WITH GRANT OPTION
    _grant_users=$(run_q "SELECT CONCAT(GRANTEE,' ',PRIVILEGE_TYPE,' ON *.*') FROM information_schema.USER_PRIVILEGES WHERE IS_GRANTABLE='YES' AND SUBSTRING_INDEX(REPLACE(GRANTEE,CHAR(39),''),'@',1) NOT IN ('root','mariadb.sys') AND REPLACE(GRANTEE,CHAR(39),'') NOT LIKE 'mysql.%' UNION ALL SELECT CONCAT(GRANTEE,' ',PRIVILEGE_TYPE,' ON ',TABLE_SCHEMA,'.*') FROM information_schema.SCHEMA_PRIVILEGES WHERE IS_GRANTABLE='YES' UNION ALL SELECT CONCAT(GRANTEE,' ',PRIVILEGE_TYPE,' ON ',TABLE_SCHEMA,'.',TABLE_NAME) FROM information_schema.TABLE_PRIVILEGES WHERE IS_GRANTABLE='YES';" 2>/dev/null | head -20)
    evd_q "DBM-024" "IS_GRANTABLE=YES 권한 (전역·DB·테이블, root·시스템 계정 제외)" "${_grant_users:-해당 없음}"
    mc "024" "GRANT OPTION 부여 현황 수동 확인 (위 현황 참조)"

    # DBM-025: EoS
    evd_q "DBM-025" "MySQL/MariaDB 버전 (EoS 판단용)" "${DB_VER}"
    mc "025" "MySQL/MariaDB ${DB_VER} EoS 여부 수동 확인"

    # DBM-026: 구동 계정 umask
    evd "DBM-026" "ps -ef 2>/dev/null | grep -E 'mysqld|mariadbd' | grep -v grep | head -3"
    mysql_user=$(ps -ef 2>/dev/null | grep -E "mysqld|mariadbd" | grep -v "mysqld_safe" | grep -v grep | awk '{print $1}' | head -1)
    _my_umask=$(_get_umask "$mysql_user" mysqld mariadbd)
    _judge_umask "$_my_umask" "MySQL" "026" "${mysql_user:-mysql}"

    # DBM-028: 불필요 DB Object
    test_db=$(run_q "SELECT COUNT(*) FROM information_schema.SCHEMATA WHERE SCHEMA_NAME='test';" | tail -1)
    evd_q "DBM-028" "test DB 존재 여부" "$test_db"
    _schemas=$(run_q "SELECT SCHEMA_NAME FROM information_schema.SCHEMATA WHERE SCHEMA_NAME NOT IN ('mysql','information_schema','performance_schema','sys');" 2>/dev/null | head -20)
    evd_q "DBM-028" "사용자 스키마 목록" "${_schemas:-없음}"
    [ "${test_db:-0}" -gt 0 ] 2>/dev/null && ng "028" "test 데이터베이스 존재 (제거 권고)" || mc "028" "test DB 없음 - 인가되지 않은 Object 존재 여부 인터뷰 확인 (스키마: $(echo "${_schemas:-없음}" | _csv))"

    evd_q "DBM-012" "해당 없음 (MySQL/MariaDB)" "Oracle 전용 항목 (Listener Control Utility)"
    na "012" "Oracle 전용 항목 (Listener Control Utility)"
    evd_q "DBM-014" "해당 없음 (MySQL/MariaDB)" "Oracle 전용 항목 (OS_ROLES/REMOTE_OS_ROLES)"
    na "014" "Oracle 전용 항목 (OS_ROLES/REMOTE_OS_ROLES)"
    evd_q "DBM-015" "해당 없음 (MySQL/MariaDB)" "Oracle/MSSQL 전용 항목 (PUBLIC Role)"
    na "015" "Oracle/MSSQL 전용 항목 (PUBLIC Role)"
    evd_q "DBM-029" "해당 없음 (MySQL/MariaDB)" "Oracle 전용 항목 (자원 프로파일)"
    na "029" "Oracle 전용 항목 (자원 프로파일)"
    evd_q "DBM-030" "해당 없음 (MySQL/MariaDB)" "Oracle/Tibero 전용 항목 (감사 테이블)"
    na "030" "Oracle/Tibero 전용 항목 (감사 테이블)"
    evd_q "DBM-031" "해당 없음 (MySQL/MariaDB)" "MSSQL 전용 항목"
    na "031" "MSSQL 전용 항목"

    # DBM-032: 통신구간 암호화 (SSL/TLS)
    _have_ssl=$(get_var "have_ssl")
    _require_ssl=$(get_var "require_secure_transport")
    evd_q "DBM-032" "have_ssl=${_have_ssl}, require_secure_transport=${_require_ssl:-미설정}" ""
    if [ "${_require_ssl}" = "ON" ]; then
        ok "032" "SSL 필수 (require_secure_transport=ON)"
    elif [ "${_have_ssl}" = "YES" ]; then
        mc "032" "SSL 가능하나 필수 아님 (have_ssl=YES, require_secure_transport=${_require_ssl:-OFF})"
    else
        ng "032" "SSL 미지원 (have_ssl=${_have_ssl:-DISABLED})"
    fi

    # DBM-033: 이중화 비밀번호 평문 노출
    # 평가기준: slave_master_info(테이블/파일)에 비밀번호 평문 저장 시 취약, 동적 입력(START REPLICA ... PASSWORD) 시 양호
    _repl_info=$(run_q "SELECT CONCAT(Host,' user=',User_name,' pw=',IF(IFNULL(User_password,'')='','없음','저장됨')) FROM mysql.slave_master_info;" 2>/dev/null | head -3)
    _mi_file=$(ls "$(get_var datadir)"/master.info 2>/dev/null)
    evd_q "DBM-033" "slave_master_info 비밀번호 저장 여부 / master.info 파일" "${_repl_info:-행 없음} / ${_mi_file:-없음}"
    if echo "$_repl_info" | grep -q "pw=저장됨" || { [ -n "$_mi_file" ] && [ "$(sed -n 6p "$_mi_file" 2>/dev/null)" != "" ]; }; then
        ng "033" "복제 연결 비밀번호 평문 저장: $(echo "$_repl_info" | _csv)${_mi_file:+ / $_mi_file}"
    elif [ -n "$_repl_info" ]; then
        ok "033" "복제 구성, 비밀번호 미저장(동적 입력): $(echo "$_repl_info" | _csv)"
    else
        na "033" "이중화(복제) 미구성"
    fi

    # DBM-034: DBMS 서비스 구동 권한 (프로세스 UID + 설정파일 user 지시자 교차검증)
    evd "DBM-034" "ps -ef 2>/dev/null | grep -E 'mysqld|mariadbd' | grep -v grep"
    mysql_proc=$(ps -ef 2>/dev/null | grep -E "mysqld|mariadbd" | grep -v "mysqld_safe" | grep -v grep | awk '{print $1}' | head -1)
    _mycnf_user=""
    for _mc in /etc/my.cnf /etc/my.ini /etc/my.cnf.d/mysql-server.cnf \
               /etc/mysql/my.cnf /etc/mysql/mysql.conf.d/mysqld.cnf \
               /etc/mysql/mariadb.cnf; do
        [ -f "$_mc" ] || continue
        _mu=$(awk '/^[[:space:]]*\[/{sec=$0} tolower(sec)~"\\[mysqld\\]" && /^[[:space:]]*user[[:space:]]*=/{sub(/.*=[[:space:]]*/,""); sub(/[[:space:]]*[#;].*/,""); print; exit}' "$_mc" 2>/dev/null)
        [ -n "$_mu" ] && { _mycnf_user="$_mu"; break; }
    done
    if [ -n "$mysql_proc" ]; then
        if [ "$mysql_proc" = "root" ] || [ "$_mycnf_user" = "root" ]; then
            ng "034" "MySQL root 실행 (proc=${mysql_proc:-?}, cnf user=${_mycnf_user:-미설정})"
        else
            ok "034" "MySQL 구동 계정: proc=${mysql_proc}, cnf user=${_mycnf_user:-미설정}"
        fi
    elif [ -n "$_mycnf_user" ]; then
        [ "$_mycnf_user" = "root" ] && ng "034" "[mysqld] user=root 설정됨" || ok "034" "[mysqld] user=${_mycnf_user}"
    else
        mc "034" "MySQL 구동 계정 수동 확인 (프로세스/설정 미확인)"
    fi

    evd_q "DBM-035" "해당 없음 (MySQL/MariaDB)" "MSSQL 전용 항목 (xp_cmdshell)"
    na "035" "MSSQL 전용 항목"
    evd_q "DBM-036" "해당 없음 (MySQL/MariaDB)" "MSSQL 전용 항목 (Registry Procedure)"
    na "036" "MSSQL 전용 항목"
}

# ================================================================
# PostgreSQL 점검
# ================================================================
check_pgsql() {
    PGSQL_USER="${PGSQL_USER:-postgres}"
    PGSQL_DB="${PGSQL_DB:-postgres}"
    PGSQL_HOST="${PGSQL_HOST-}"
    PGSQL_PORT="${PGSQL_PORT:-5432}"

    PSQL=$(command -v psql 2>/dev/null)
    if [ -z "$PSQL" ]; then
        printf '[FALLBACK] %s psql 미탐지 - PostgreSQL 전 항목 수동 확인 처리\n\n' "$(date '+%H:%M:%S')" >> "$_EVD"
        for i in 001 003 004 005 006 007 008 009 011 013 016 017 019 020 022 \
                 024 025 026 028 032 034; do mc "$i" "psql 미탐지"; done
        na "012" "Oracle 전용 항목"; na "014" "Oracle 전용 항목"
        mc "015" "psql 미탐지 - PUBLIC 권한 수동 확인"; na "021" "Windows MSSQL 전용 항목"
        na "029" "Oracle 전용 항목"; na "030" "Oracle/Tibero 전용 항목"
        na "031" "MSSQL 전용 항목"; mc "033" "psql 미탐지"
        na "035" "MSSQL 전용 항목"; na "036" "MSSQL 전용 항목"
        return
    fi

    # 접속 순서: PGSQL_HOST 지정 → 그대로 / 비밀번호(PGPASSWORD·PGPASSFILE·~/.pgpass) 있으면 localhost / 없으면 소켓+peer(root 는 구동 계정으로) → localhost
    _PG_OS=""; _PG_HOSTS="$PGSQL_HOST"
    if [ -z "$PGSQL_HOST" ]; then
        if [ -n "$PGPASSWORD$PGPASSFILE" ] || [ -f "$HOME/.pgpass" ]; then _PG_HOSTS="localhost"
        else
            _PG_HOSTS="@sock localhost"
            [ "$(id -u)" = 0 ] && _PG_OS=$(ps -eo user=,comm= 2>/dev/null | awk '$2=="postgres"||$2=="postmaster"{print $1; exit}')
            [ "$_PG_OS" = "root" ] && _PG_OS=""
        fi
    fi
    _pg_exec() { if [ -n "$_PG_OS" ] && [ "$_PGH" = "@sock" ]; then su "$_PG_OS" -s /bin/sh -c "\"$PSQL\" $OPTS -f -"; else "$PSQL" $OPTS -f -; fi; }
    run_q() { printf '%s\n' "$1" | _pg_exec 2>/dev/null | grep -v "^$"; }
    get_conf() { run_q "SHOW $1;"; }
    local _pgc=""
    for _PGH in $_PG_HOSTS; do
        OPTS="-X -w -U ${PGSQL_USER} $( [ "$_PGH" != "@sock" ] && echo "-h $_PGH") -p ${PGSQL_PORT} -d ${PGSQL_DB} -tA"
        _pgc=$(run_q "SELECT 'CONN_'||'OK';"); echo "$_pgc" | grep -q CONN_OK && break
    done
    if ! echo "$_pgc" | grep -q CONN_OK && [ -t 0 ] && [ -z "$PGPASSWORD" ]; then
        read -rs -p "PostgreSQL ${PGSQL_USER} 비밀번호: " PGPASSWORD </dev/tty; echo >&2; export PGPASSWORD
        _PGH="${PGSQL_HOST:-localhost}"; OPTS="-X -w -U ${PGSQL_USER} -h $_PGH -p ${PGSQL_PORT} -d ${PGSQL_DB} -tA"
        _pgc=$(run_q "SELECT 'CONN_'||'OK';")
    fi
    echo "# PostgreSQL 접속: ${_PGH}${_PG_OS:+ (OS 계정 ${_PG_OS})}"
    _conn_ok "$_pgc" "PostgreSQL" || return
    DB_VER=$(run_q "SELECT version();" | head -1)
    echo "# PostgreSQL 버전: ${DB_VER}"

    # DBM-001: 취약 패스워드
    # 빈 비밀번호(md5(''||계정명)) 는 취약, 비밀번호 NULL 역할은 비밀번호 인증 불가 → trust 규칙 적용 시에만 취약
    no_pw=$(run_q "SELECT usename FROM pg_shadow WHERE passwd='' OR passwd='md5'||md5(''||usename);" | head -5)
    _nullpw=$(run_q "SELECT usename FROM pg_shadow WHERE passwd IS NULL;" | head -10)
    _trust=$(run_q "SELECT type||' '||array_to_string(user_name,',')||' '||coalesce(address,'') FROM pg_hba_file_rules WHERE error IS NULL AND auth_method='trust' AND type<>'local' AND coalesce(address,'') NOT IN ('127.0.0.1','::1','localhost');" 2>/dev/null | head -3)
    evd_q "DBM-001" "빈 비밀번호 계정 / 비밀번호 NULL 역할 / 원격 trust 규칙" "${no_pw:-없음} / ${_nullpw:-없음} / ${_trust:-없음}"
    if [ -n "$no_pw" ]; then ng "001" "빈 비밀번호 계정: $(echo "$no_pw" | _csv)"
    elif [ -n "$_trust" ]; then ng "001" "원격 trust 인증 규칙(비밀번호 없이 접속): $(echo "$_trust" | _csv)"
    else mc "001" "빈 비밀번호·원격 trust 없음 (비밀번호 미설정 역할: $(echo "${_nullpw:-없음}" | _csv)) - 비밀번호 복잡도·취약 비밀번호 여부는 해시 크랙으로 확인 필요"; fi

    # DBM-003: 불필요 계정
    _pg_roles=$(run_q "SELECT rolname||' (login='||rolcanlogin||', super='||rolsuper||')' FROM pg_roles ORDER BY rolname;" | head -30)
    evd_q "DBM-003" "SELECT rolname,rolcanlogin,rolsuper FROM pg_roles" "${_pg_roles:-조회 불가}"
    mc "003" "불필요 계정 수동 확인 (위 현황 참조)"

    # DBM-004: 불필요 관리자
    # 평가기준: rolsuper·rolcreaterole·rolcreatedb·rolreplication 부여 계정 목록 → 인터뷰
    supers=$(run_q "SELECT rolname||'('||concat_ws(',',CASE WHEN rolsuper THEN 'super' END,CASE WHEN rolcreaterole THEN 'createrole' END,CASE WHEN rolcreatedb THEN 'createdb' END,CASE WHEN rolreplication THEN 'replication' END)||')' FROM pg_roles WHERE (rolsuper OR rolcreaterole OR rolcreatedb OR rolreplication) AND rolname NOT LIKE 'pg\_%' ORDER BY 1;" | head -10)
    evd_q "DBM-004" "관리자 속성(super/createrole/createdb/replication) 보유 계정" "$supers"
    mc "004" "관리자 권한 계정: $(echo "${supers:-없음}" | _csv) - 업무상 필요 여부 인터뷰 확인"

    # DBM-005: 암호화
    _pgcrypto=$(run_q "SELECT extname||' ('||extversion||')' FROM pg_extension WHERE extname IN ('pgcrypto','pgsodium');" 2>/dev/null | head -5)
    evd_q "DBM-005" "암호화 확장(pgcrypto/pgsodium) 설치 여부" "${_pgcrypto:-암호화 확장 미설치}"
    mc "005" "중요 컬럼 암호화 여부 수동 확인 (위 현황 참조)"

    # DBM-006: 로그인 실패 제한 (PostgreSQL은 기본 제한 없음 - pg_auth_mon 또는 fail2ban)
    _pg_authmon=$(run_q "SELECT extname FROM pg_extension WHERE extname='pg_auth_mon';" 2>/dev/null | head -1)
    evd_q "DBM-006" "pg_auth_mon 확장 여부" "${_pg_authmon:-미설치 (PostgreSQL 기본 미지원)}"
    mc "006" "로그인 실패 횟수 제한은 PostgreSQL 기본 미지원 - fail2ban 또는 pg_auth_mon 설정 수동 확인"

    # DBM-007: 패스워드 복잡도 + SCRAM-SHA-256 검증
    _pg_spl=$(get_conf "shared_preload_libraries" 2>/dev/null)
    _pg_pwext=$(run_q "SELECT extname FROM pg_extension WHERE extname IN ('credcheck','supautils');" 2>/dev/null | head -1)
    evd_q "DBM-007" "shared_preload_libraries" "${_pg_spl:-없음}"
    # 평가기준: passwordcheck.so 로드 + 설정이 복잡도(2종 10자/3종 8자) 충족. 기본 passwordcheck 는 8자·문자+비문자(2종 8자)라 미달
    _pw_enc=$(get_conf "password_encryption")
    _pc_len=$(get_conf "passwordcheck.min_password_length" 2>/dev/null)
    evd_q "DBM-007" "passwordcheck.min_password_length / (참고) password_encryption" "${_pc_len:-N/A} / ${_pw_enc}"
    if echo "$_pg_spl" | grep -qi "passwordcheck" && [ "${_pc_len:-0}" -ge 10 ] 2>/dev/null; then
        ok "007" "passwordcheck 로드, min_password_length=${_pc_len} (문자+비문자 2종 10자 이상)"
    elif [ -n "$_pg_pwext" ] || echo "$_pg_spl" | grep -qi "credcheck"; then
        mc "007" "복잡도 모듈 로드(${_pg_spl}${_pg_pwext:+, $_pg_pwext}) - 설정값(최소 길이·문자 종류) 확인"
    elif echo "$_pg_spl" | grep -qi "passwordcheck"; then   # PG17 이하 passwordcheck = 고정 규칙(8자·문자+비문자), min_password_length 는 PG18+
        ng "007" "passwordcheck 기본 규칙(최소 ${_pc_len:-8}자·문자+비문자 2종) - 2종 10자/3종 8자 미달 (cracklib 빌드·솔루션 사용 시 수동 확인)"
    else
        ng "007" "passwordcheck/credcheck 미로드 (복잡도 미강제) - 솔루션 사용 시 수동 확인"
    fi

    # DBM-008: 패스워드 만료 (VALID UNTIL)
    # 평가기준: PostgreSQL 은 비밀번호 변경일자·만료 정책을 제공하지 않으므로 인터뷰/증적으로 판단
    _pg_noexpiry=$(run_q "SELECT rolname||' (valid_until='||coalesce(rolvaliduntil::text,'없음')||')' FROM pg_roles WHERE rolcanlogin ORDER BY 1;" | head -20)
    evd_q "DBM-008" "로그인 계정 VALID UNTIL (참고)" "${_pg_noexpiry:-없음}"
    mc "008" "PostgreSQL 비밀번호 변경일 미제공 - 최근 90일 내 변경 여부 인터뷰/증적 확인 (서비스 계정 평가 제외 가능)"

    # DBM-009: 세션 타임아웃 (PG14+ idle_session_timeout 포함)
    # 평가기준: idle_in_transaction_session_timeout 미설정 또는 부적절(내부 규정 미명시 시 15분) → 취약 (ms 단위 비교)
    _t_ms=$(run_q "SELECT setting FROM pg_settings WHERE name='idle_in_transaction_session_timeout';" | head -1)
    _s_ms=$(run_q "SELECT setting FROM pg_settings WHERE name='idle_session_timeout';" | head -1)
    evd_q "DBM-009" "idle_in_transaction_session_timeout(ms) / idle_session_timeout(ms, 참고)" "${_t_ms:-0} / ${_s_ms:-N/A}"
    if [ "${_t_ms:-0}" -gt 0 ] 2>/dev/null && [ "$_t_ms" -le 900000 ] 2>/dev/null; then
        ok "009" "idle_in_transaction_session_timeout=$((_t_ms/1000))초 (15분 이하)"
    elif [ "${_t_ms:-0}" -gt 900000 ] 2>/dev/null; then
        ng "009" "idle_in_transaction_session_timeout=$((_t_ms/1000))초 (15분 초과 - 내부 규정 미명시 시 15분 기준)"
    else
        ng "009" "idle_in_transaction_session_timeout 미설정(0) - 접근제어 솔루션으로 세션 종료 시 수동 확인"
    fi

    # DBM-011: 감사 로그 (logging_collector 포함)
    # 평가기준: pg_audit 등 플러그인·솔루션으로 감사 로그 수집 + 주기적 백업(인터뷰). 접속 로그는 참고 증적
    _log_col=$(get_conf "logging_collector"); log_conn=$(get_conf "log_connections"); log_disco=$(get_conf "log_disconnections")
    _pga=$(get_conf "pgaudit.log" 2>/dev/null)
    evd_q "DBM-011" "shared_preload_libraries / pgaudit.log / (참고) logging_collector·log_connections·log_disconnections" "${_pg_spl:-없음} / ${_pga:-N/A} / ${_log_col}·${log_conn}·${log_disco}"
    if echo "$_pg_spl" | grep -qi "pgaudit" && [ -n "$_pga" ] && [ "${_pga,,}" != "none" ]; then
        mc "011" "pgaudit 감사 로그 수집 중 (pgaudit.log=${_pga}) - 주기적 백업 여부 인터뷰/증적 확인"
    else
        ng "011" "pgaudit 미로드/미설정 - 감사 로그 미수집 (접속 로그 logging_collector=${_log_col}) - 써드파티 솔루션 사용 시 수동 확인"
    fi

    evd_q "DBM-012" "해당 없음 (PostgreSQL)" "Oracle 전용 항목 (Listener Control Utility)"
    na "012" "Oracle 전용 항목 (Listener Control Utility)"

    # DBM-013: 원격 접속
    # 평가기준: pg_hba.conf ADDRESS 0.0.0.0/0 레코드 존재 시 취약 (listen_addresses 는 참고 증적)
    listen=$(get_conf "listen_addresses")
    evd_q "DBM-013" "listen_addresses(참고)" "$listen"
    case "${listen}" in
    "localhost"|"127.0.0.1"|"::1") ok "013" "listen_addresses=${listen} (로컬 접속만 허용)" ;;
    esac

    evd_q "DBM-014" "해당 없음 (PostgreSQL)" "Oracle 전용 항목 (OS_ROLES/REMOTE_OS_ROLES)"
    na "014" "Oracle 전용 항목 (OS_ROLES/REMOTE_OS_ROLES)"

    local _hba_n _hf _hba_skip=""
    _hba_n=$(run_q "SELECT COUNT(*) FROM pg_hba_file_rules;" | head -1)
    if [ -n "$_hba_n" ]; then   # PG10+ (file_name·rule_number 열은 PG16+ 라 공통 열만 사용)
        _hba_wild=$(run_q "SELECT 'line '||line_number||' '||type||' '||coalesce(address,'')||coalesce('/'||netmask,'')||' '||auth_method FROM pg_hba_file_rules WHERE error IS NULL AND type<>'local' AND auth_method<>'reject' AND (lower(coalesce(address,'')) IN ('all','0.0.0.0','0.0.0.0/0','::0','::/0','::') OR coalesce(netmask,'x') IN ('0.0.0.0','::'));" | head -3)
    else   # PG 9.x 또는 뷰 권한 없음 → hba_file 직접
        _hf=$(run_q "SELECT current_setting('hba_file');" | head -1)
        _hba_wild=$(awk '!/^[[:space:]]*#/ && $1 ~ /^host/ && $NF!="reject" && ($4=="all" || $4=="0.0.0.0/0" || $4=="::/0" || ($4=="0.0.0.0" && $5=="0.0.0.0")) {print FILENAME":"FNR" "$0}' "$_hf" 2>/dev/null | head -3)
        [ -r "$_hf" ] || _hba_skip=1
    fi
    evd_q "DBM-013" "pg_hba 전체 IP 허용 규칙" "$_hba_wild"
    if [ -n "$_hba_skip" ] && [ -z "$_hba_wild" ]; then
        mc "013" "pg_hba_file_rules·pg_hba.conf 조회 불가 - ADDRESS 0.0.0.0/0 레코드 수동 확인"
    elif [ -n "$_hba_wild" ]; then
        ng "013" "pg_hba.conf 전체 IP 허용 규칙: $(echo "$_hba_wild" | head -1)"
    else
        ok "013" "pg_hba.conf 전체 IP(0.0.0.0/0) 허용 규칙 없음 (listen_addresses=${listen:-기본})"
    fi

    # DBM-015: PUBLIC 불필요 권한
    _pg_pub_exec=$(run_q "SELECT routine_schema||'.'||routine_name FROM information_schema.role_routine_grants WHERE grantee='PUBLIC' AND routine_schema NOT IN ('pg_catalog','information_schema') ORDER BY 1;" 2>/dev/null | head -10)
    _pg_dbs=$(run_q "SELECT datname FROM pg_database WHERE datallowconn AND NOT datistemplate ORDER BY 1;")
    evd_q "DBM-015" "점검 대상 DB (접속 가능·템플릿 제외)" "$(echo "$_pg_dbs" | _csv)"
    _pg_pub_create=""; _pg_pub_tbl=""
    for _d in $_pg_dbs; do   # PUBLIC 권한은 DB 별 카탈로그 — 전 DB 순회 (has_schema_privilege 의 PUBLIC 은 소문자 'public')
        _pg_pub_create="${_pg_pub_create}$(OPTS="${OPTS/-d ${PGSQL_DB}/-d $_d}" run_q "SELECT '$_d:'||nspname||' (CREATE)' FROM pg_namespace WHERE nspname='public' AND has_schema_privilege('public',nspname,'CREATE');")
"
        _pg_pub_tbl="${_pg_pub_tbl}$(OPTS="${OPTS/-d ${PGSQL_DB}/-d $_d}" run_q "SELECT '$_d:'||table_schema||'.'||table_name||' ('||privilege_type||')' FROM information_schema.role_table_grants WHERE grantee='PUBLIC' AND table_schema NOT IN ('pg_catalog','information_schema') ORDER BY 1;")
"
    done
    _pg_pub_create=$(echo "$_pg_pub_create" | grep -v "^$" | head -5); _pg_pub_tbl=$(echo "$_pg_pub_tbl" | grep -v "^$" | head -10)
    evd_q "DBM-015" "PUBLIC EXECUTE 권한 (비시스템)" "${_pg_pub_exec:-없음}"
    evd_q "DBM-015" "PUBLIC CREATE 권한 (public 스키마)" "${_pg_pub_create:-없음}"
    evd_q "DBM-015" "PUBLIC 테이블(Object) 권한 (비시스템)" "${_pg_pub_tbl:-없음}"
    if [ -n "$_pg_pub_tbl" ] || [ -n "$_pg_pub_exec" ] || [ -n "$_pg_pub_create" ]; then
        mc "015" "PUBLIC Object 권한: $(echo "${_pg_pub_tbl}${_pg_pub_exec:+ $_pg_pub_exec}${_pg_pub_create:+ $_pg_pub_create}" | _csv | head -c 150) - 업무상 필요 여부 확인"
    else
        ok "015" "PUBLIC 에 사용자 Object 권한 없음"
    fi

    # DBM-016: 보안패치
    evd_q "DBM-016" "PostgreSQL 버전 (패치 판단용)" "${DB_VER}"
    mc "016" "PostgreSQL 보안패치 수동 확인 (위 버전 참조)"

    # DBM-017: 시스템 테이블 접근
    _pg_sys_grants=$(run_q "SELECT c.relname||' → '||CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(a.grantee) END||' ('||a.privilege_type||')' FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace CROSS JOIN LATERAL aclexplode(c.relacl) a WHERE n.nspname='pg_catalog' AND c.relkind IN ('r','v','m') AND a.grantee<>c.relowner AND (a.grantee=0 OR pg_get_userbyid(a.grantee) NOT LIKE 'pg\\_%') AND NOT (a.grantee=0 AND a.privilege_type='SELECT' AND c.relname NOT IN ('pg_authid','pg_shadow','pg_statistic','pg_user_mapping','pg_hba_file_rules','pg_file_settings')) AND NOT (a.grantee=0 AND c.relname='pg_settings' AND a.privilege_type='UPDATE') ORDER BY 1;" | head -20)
    evd_q "DBM-017" "pg_catalog 테이블·뷰 비기본 접근 권한 (소유자·pg_ 기본 역할·PUBLIC 기본 SELECT 제외)" "${_pg_sys_grants:-별도 부여 없음 (기본 권한만)}"
    mc "017" "pg_shadow, pg_authid 등 시스템 카탈로그 접근 권한 수동 확인 (위 현황 참조)"

    # DBM-019: 패스워드 재사용
    evd_q "DBM-019" "PostgreSQL 패스워드 재사용 제한" "PostgreSQL 기본 미지원 (외부 모듈 필요)"
    mc "019" "PostgreSQL 패스워드 재사용 제한 수동 설정 확인"

    # DBM-020: 계정 분리
    _pg_login=$(run_q "SELECT rolname||' (super='||rolsuper||')' FROM pg_roles WHERE rolcanlogin ORDER BY rolname;" | head -20)
    evd_q "DBM-020" "로그인 가능 계정 목록" "${_pg_login:-조회 불가}"
    mc "020" "공용 계정 사용 여부 수동 확인 (위 현황 참조)"

    # DBM-021: 불필요한 ODBC/OLE-DB 데이터 소스 및 드라이버 제거 (Windows MSSQL 전용)
    evd_q "DBM-021" "해당 없음 (PostgreSQL)" "Windows MSSQL 전용 항목"
    na "021" "Windows MSSQL 전용 항목 (PostgreSQL 해당 없음)"

    # DBM-022: 설정 파일 권한 (DB에서 경로 조회 → 실제 파일 권한 확인)
    _pg_config=$(run_q "SELECT current_setting('config_file');" | head -1)
    evd_q "DBM-022" "config_file 경로" "$_pg_config"
    _pg_hba=$(run_q "SELECT current_setting('hba_file');" | head -1)
    _pg_data=$(run_q "SELECT current_setting('data_directory');" | head -1)
    [ -z "$_pg_config" ] && _pg_config=$(find /etc/postgresql /var/lib/postgresql -name "postgresql.conf" 2>/dev/null | head -1)
    # 평가기준 640: postgresql.conf·pg_hba.conf·pg_ident.conf 의 group 쓰기·실행 및 others 권한 금지
    _pg_ident=$(run_q "SELECT current_setting('ident_file');" | head -1)
    _perm_check 037 "$_pg_config" "$_pg_hba" "$_pg_ident"; _b22=$_PC_BAD
    if [ "$_PC_FOUND" -eq 0 ]; then
        mc "022" "PostgreSQL 설정 파일 미발견 - 수동 확인"
    elif [ -n "$_b22" ]; then
        ng "022" "설정 파일 권한 기준(640) 위반: ${_b22}"
    else
        ok "022" "postgresql.conf·pg_hba.conf·pg_ident.conf 권한 640 기준 충족"
    fi

    # DBM-024: WITH GRANT OPTION
    _pg_grants=""
    for _d in ${_pg_dbs:-$PGSQL_DB}; do
        _pg_grants="${_pg_grants}$(OPTS="${OPTS/-d ${PGSQL_DB}/-d $_d}" run_q "SELECT '$_d:table:'||grantee||' '||table_schema||'.'||table_name||' '||privilege_type FROM information_schema.role_table_grants WHERE is_grantable='YES' AND grantee<>(SELECT rolname FROM pg_roles WHERE oid=10) UNION ALL SELECT '$_d:routine:'||grantee||' '||routine_schema||'.'||routine_name FROM information_schema.role_routine_grants WHERE is_grantable='YES' AND routine_schema NOT IN ('pg_catalog','information_schema') AND grantee<>(SELECT rolname FROM pg_roles WHERE oid=10) UNION ALL SELECT '$_d:schema:'||pg_get_userbyid(a.grantee)||' '||n.nspname||' '||a.privilege_type FROM pg_namespace n CROSS JOIN LATERAL aclexplode(n.nspacl) a WHERE a.is_grantable AND a.grantee<>n.nspowner;")
"
    done
    _pg_grants="$(echo "$_pg_grants" | grep -v "^$")
$(run_q "SELECT 'role:'||pg_get_userbyid(m.member)||' ADMIN '||pg_get_userbyid(m.roleid) FROM pg_auth_members m WHERE m.admin_option AND pg_get_userbyid(m.roleid) NOT LIKE 'pg\\_%';")"
    _pg_grants=$(echo "$_pg_grants" | grep -v "^$" | head -20)
    evd_q "DBM-024" "WITH GRANT OPTION(테이블·함수·스키마, 전 DB)·WITH ADMIN OPTION(역할) — 부트스트랩 슈퍼유저 제외" "${_pg_grants:-해당 없음}"
    mc "024" "WITH GRANT OPTION 부여 현황 수동 확인 (위 현황 참조)"

    # DBM-025: EoS
    evd_q "DBM-025" "PostgreSQL 버전 (EoS 판단용)" "${DB_VER}"
    mc "025" "PostgreSQL EoS 여부 수동 확인 (위 버전 참조)"

    # DBM-026: 구동 계정 umask
    evd "DBM-026" "ps -ef 2>/dev/null | grep 'postgres' | grep -v grep | head -3"
    pg_user=$(ps -ef 2>/dev/null | grep -E "postgres: (postmaster|checkpointer)|postgres -D|/usr/lib/postgresql/.*/bin/postgres|bin/postgres " | grep -v grep | awk '{print $1}' | head -1)
    [ -z "$pg_user" ] && pg_user=$(ps -ef 2>/dev/null | awk '$NF=="postgres" || $NF~/\/postgres$/{print $1; exit}')
    _pg_umask=$(_get_umask "$pg_user" "postgres")
    _judge_umask "$_pg_umask" "PostgreSQL" "026" "${pg_user:-postgres}"

    # DBM-028: 불필요 Object
    _pg_schemas=$(run_q "SELECT schema_name FROM information_schema.schemata WHERE schema_name NOT IN ('pg_catalog','information_schema','pg_toast','public') ORDER BY 1;" 2>/dev/null | head -20)
    evd_q "DBM-028" "사용자 정의 스키마 목록" "${_pg_schemas:-기본 스키마만 존재}"
    mc "028" "불필요 스키마/테이블 수동 확인 (위 현황 참조)"

    evd_q "DBM-029" "해당 없음 (PostgreSQL)" "Oracle 전용 항목 (자원 프로파일)"
    na "029" "Oracle 전용 항목 (자원 프로파일)"
    evd_q "DBM-030" "해당 없음 (PostgreSQL)" "Oracle/Tibero 전용 항목 (감사 테이블)"
    na "030" "Oracle/Tibero 전용 항목 (감사 테이블)"
    evd_q "DBM-031" "해당 없음 (PostgreSQL)" "MSSQL 전용 항목"
    na "031" "MSSQL 전용 항목"

    # DBM-032: 비밀번호 평문 노출 방지
    # 평가기준: pg_hba type 이 hostssl 이외이면 취약(ssl 적용이 힘들면 비밀번호 암호화), auth-method 가 md5·password 인 레코드 존재 시 취약
    ssl=$(get_conf "ssl")
    _hba_pw=$(run_q "SELECT type||' '||coalesce(address,'')||' '||auth_method FROM pg_hba_file_rules WHERE error IS NULL AND type<>'local' AND auth_method IN ('md5','password') AND coalesce(address,'') NOT IN ('127.0.0.1','::1','localhost');" 2>/dev/null | head -3)
    _hba_nossl=$(run_q "SELECT type||' '||coalesce(address,'')||' '||auth_method FROM pg_hba_file_rules WHERE error IS NULL AND type IN ('host','hostnossl') AND auth_method NOT IN ('reject','scram-sha-256','cert','gss','sspi') AND coalesce(address,'') NOT IN ('127.0.0.1','::1','localhost');" 2>/dev/null | head -3)
    _hba_ok=$(run_q "SELECT COUNT(*) FROM pg_hba_file_rules WHERE error IS NULL;" 2>/dev/null | head -1)
    evd_q "DBM-032" "ssl / md5·password 레코드 / 비SSL 평문 위험 레코드" "${ssl} / ${_hba_pw:-없음} / ${_hba_nossl:-없음}"
    if [ -z "$_hba_ok" ]; then mc "032" "pg_hba_file_rules 조회 불가 - pg_hba.conf type(hostssl)·auth-method 수동 확인 (ssl=${ssl})"
    elif [ -n "$_hba_pw" ]; then ng "032" "auth-method md5/password 레코드: $(echo "$_hba_pw" | _csv)"
    elif [ -n "$_hba_nossl" ]; then ng "032" "hostssl 이외 원격 레코드(비밀번호 암호화 미적용): $(echo "$_hba_nossl" | _csv)"
    else ok "032" "원격 레코드 hostssl 또는 scram-sha-256/cert 인증 (ssl=${ssl})"; fi

    # DBM-033: 이중화 비밀번호 평문 노출 방지 (PG 스트리밍 복제)
    _pg_primary=$(run_q "SELECT conninfo FROM pg_stat_wal_receiver;" 2>/dev/null | head -1)
    if [ -n "$_pg_primary" ]; then
        evd_q "DBM-033" "pg_stat_wal_receiver conninfo" "$_pg_primary"
        if echo "$_pg_primary" | grep -qiE "sslmode=require|sslmode=verify"; then
            ok "033" "복제 SSL 사용 중 (sslmode 설정 확인됨)"
        else
            ng "033" "복제 SSL 미사용 가능 - sslmode 확인 필요"
        fi
    else
        _pg_repl_slots=$(run_q "SELECT slot_name||' (active='||active||')' FROM pg_replication_slots;" 2>/dev/null | head -5)
        evd_q "DBM-033" "pg_replication_slots" "${_pg_repl_slots:-복제 미구성}"
        [ -n "$_pg_repl_slots" ] && mc "033" "복제 구성됨 - SSL 적용 여부 수동 확인 (위 현황 참조)" || na "033" "복제 미구성"
    fi

    # DBM-034: DBMS 구동 권한
    evd "DBM-034" "ps -ef 2>/dev/null | grep 'postgres' | grep -v grep | head -3"
    pg_proc=$(ps -ef 2>/dev/null | grep -E "postgres: (postmaster|checkpointer)|postgres -D|/usr/lib/postgresql/.*/bin/postgres|bin/postgres " | grep -v grep | awk '{print $1}' | head -1)
    [ -z "$pg_proc" ] && pg_proc=$(ps -ef 2>/dev/null | awk '$NF=="postgres" || $NF~/\/postgres$/{print $1; exit}')
    [ -n "$pg_proc" ] && {
        [ "$pg_proc" = "root" ] && ng "034" "PostgreSQL root 실행" || ok "034" "구동 계정: ${pg_proc}"
    } || mc "034" "PostgreSQL 구동 계정 수동 확인"

    evd_q "DBM-035" "해당 없음 (PostgreSQL)" "MSSQL 전용 항목 (xp_cmdshell)"
    na "035" "MSSQL 전용 항목"
    evd_q "DBM-036" "해당 없음 (PostgreSQL)" "MSSQL 전용 항목 (Registry Procedure)"
    na "036" "MSSQL 전용 항목"
}

# ================================================================
# Tibero 점검 (Oracle 호환 SQL 기반 자동 판정)
# ================================================================
check_tibero() {
    # root/sudo 실행 시 tbsvr 프로세스 환경에서 TB_HOME·TB_SID 복원
    local _tbp; _tbp=$(for c in /proc/[0-9]*/comm; do case "$(cat "$c" 2>/dev/null)" in tbsvr*) c=${c#/proc/}; echo "${c%/comm}"; break ;; esac; done)
    if [ -n "$_tbp" ]; then
        [ -z "$TB_HOME" ] && TB_HOME=$(tr '\0' '\n' < "/proc/$_tbp/environ" 2>/dev/null | sed -n 's/^TB_HOME=//p')
        [ -z "$TB_SID" ] && TB_SID=$(tr '\0' '\n' < "/proc/$_tbp/environ" 2>/dev/null | sed -n 's/^TB_SID=//p')
        [ -n "$TB_HOME" ] && export TB_HOME TB_SID PATH="$TB_HOME/bin:$TB_HOME/client/bin:$PATH"
    fi
    TB_HOME="${TB_HOME:-/opt/tibero}"
    TB_USER="${TIBERO_USER:-tibero}"
    TB_PASS="${TIBERO_PASS-}"
    TB_DB="${TIBERO_DB-}"   # 미지정 시 별칭 없이 TB_SID 로컬 접속 후 tbdsn 별칭 'tibero' 시도
    [ -z "$TB_PASS" ] && [ -t 0 ] && { read -rs -p "Tibero ${TB_USER} 비밀번호: " TB_PASS </dev/tty; echo >&2; }

    TBSQL=$(command -v tbsql 2>/dev/null)
    [ -z "$TBSQL" ] && [ -d "$TB_HOME/bin" ] && TBSQL=$(find "$TB_HOME/bin" -name "tbsql" 2>/dev/null | head -1)
    if [ -z "$TBSQL" ] || [ ! -x "$TBSQL" ]; then
        printf '[FALLBACK] %s tbsql 미탐지 - Tibero 전 항목 수동 확인 처리\n\n' "$(date '+%H:%M:%S')" >> "$_EVD"
        for i in 001 003 004 005 006 007 008 009 011 012 013 014 015 016 017 \
                 019 020 022 024 025 026 028 029 030 034; do
            mc "$i" "tbsql 미탐지 - 수동 확인"
        done
        na "021" "Windows MSSQL 전용 항목"
        na "031" "MSSQL 전용 항목"
        mc "032" "Tibero 통신 암호화 수동 확인 (tbsql 미탐지)"
        mc "033" "Tibero 이중화 구성 수동 확인 (tbsql 미탐지)"
        na "035" "MSSQL 전용 항목"
        na "036" "MSSQL 전용 항목"
        return
    fi

    run_q() {
        "$TBSQL" "${TB_USER}/${TB_PASS}${TB_DB:+@${TB_DB}}" << EOF 2>/dev/null
SET PAGESIZE 0 FEEDBACK OFF HEADING OFF LINESIZE 200 TRIMSPOOL ON
$1
EXIT
EOF
    }
    _tbc=$(run_q "SELECT 'CONN_'||'OK' FROM DUAL;")
    if ! echo "$_tbc" | grep -q CONN_OK && [ -z "$TIBERO_DB" ]; then TB_DB="tibero"; _tbc=$(run_q "SELECT 'CONN_'||'OK' FROM DUAL;"); fi
    _conn_ok "$_tbc" "Tibero" || return
    # 파라미터는 V$PARAMETERS(대문자 이름) — 실무 스크립트 동일 표기, 조회 실패는 빈 값
    _tb_param() { run_q "SELECT VALUE FROM V\$PARAMETERS WHERE NAME=UPPER('$1');" | grep -v "^$" | grep -viE "TBR-|error" | head -1 | tr -d ' '; }
    DB_VER=$(run_q "SELECT VALUE FROM V\$VERSION WHERE NAME IN ('PRODUCT_VERSION','TB_MAJOR_VERSION','BUILD_NUMBER');" 2>/dev/null | grep -v "^$" | grep -viE "TBR-|error" | tr '\n' ' ')
    [ -z "$DB_VER" ] && DB_VER=$(run_q "SELECT TB_VERSION FROM DB_VERSION;" 2>/dev/null | grep -v "^$" | grep -viE "TBR-|error" | head -1)
    echo "# Tibero 버전: ${DB_VER}"

    # DBM-001: 기본 계정 비밀번호 (OPEN 상태인 기본 계정)
    _tb_open_def=$(run_q "SELECT USERNAME||'('||ACCOUNT_STATUS||')' FROM DBA_USERS WHERE USERNAME IN ('SYS','TIBERO','TIBERO1','OUTLN','SYSGIS') AND ACCOUNT_STATUS='OPEN' ORDER BY USERNAME;" | grep -v "^$" | head -10)
    evd_q "DBM-001" "Tibero 기본 계정 중 OPEN 상태" "${_tb_open_def:-기본 계정 OPEN 없음}"
    if [ -n "$_tb_open_def" ]; then
        mc "001" "기본 계정 OPEN: $(echo "$_tb_open_def" | _csv) - 비밀번호 변경 여부 수동 확인"
    else
        mc "001" "Tibero 기본 계정 OPEN 상태 없음 - 계정 비밀번호 복잡도·취약 비밀번호 여부는 해시 크랙으로 확인 필요"
    fi

    # DBM-003: 불필요 계정
    _tb_users=$(run_q "SELECT USERNAME||' ('||ACCOUNT_STATUS||')' FROM DBA_USERS ORDER BY USERNAME;" | grep -v "^$" | head -30)
    evd_q "DBM-003" "SELECT USERNAME,ACCOUNT_STATUS FROM DBA_USERS" "${_tb_users:-조회 불가}"
    mc "003" "불필요 계정 수동 확인 (위 현황 참조)"

    # DBM-004: 관리자 계정 최소화
    _tb_dba=$(run_q "SELECT GRANTEE FROM DBA_ROLE_PRIVS WHERE GRANTED_ROLE='DBA' AND GRANTEE NOT IN ('SYS','TIBERO') ORDER BY GRANTEE;" | grep -v "^$" | head -10)
    _tb_sysp=$(run_q "SELECT DISTINCT GRANTEE FROM DBA_SYS_PRIVS WHERE GRANTEE NOT IN ('SYS','TIBERO','DBA','PUBLIC') AND PRIVILEGE<>'CREATE SESSION' ORDER BY 1;" | grep -v "^$" | head -10)
    evd_q "DBM-004" "DBA 역할 / 시스템 권한 보유 계정" "${_tb_dba:-없음} / ${_tb_sysp:-없음}"
    mc "004" "관리자 권한 계정 - DBA: $(echo "${_tb_dba:-없음}" | _csv), 시스템 권한: $(echo "${_tb_sysp:-없음}" | _csv) - 업무상 필요 여부 인터뷰 확인"

    # DBM-005: 중요정보 암호화
    _tb_enc=$(run_q "SELECT OWNER||'.'||TABLE_NAME||'.'||COLUMN_NAME FROM DBA_ENCRYPTED_COLUMNS ORDER BY 1;" 2>/dev/null | grep -v "^$" | head -20)
    evd_q "DBM-005" "암호화 컬럼 현황" "${_tb_enc:-암호화 컬럼 없음 또는 조회 불가}"
    mc "005" "중요정보 암호화 수동 확인 (위 현황 참조)"

    # DBM-006: 로그인 실패 횟수 제한
    # 평가기준: 계정별 적용 프로파일 FAILED_LOGIN_ATTEMPTS UNLIMITED/5 초과 → 취약 (Oracle 호환 뷰, 조회 실패 시 DEFAULT 프로파일)
    _tp6=$(run_q "SELECT u.USERNAME||'='||DECODE(p.LIMIT,'DEFAULT',d.LIMIT,p.LIMIT) FROM DBA_USERS u JOIN DBA_PROFILES p ON p.PROFILE=u.PROFILE AND p.RESOURCE_NAME='FAILED_LOGIN_ATTEMPTS' JOIN DBA_PROFILES d ON d.PROFILE='DEFAULT' AND d.RESOURCE_NAME='FAILED_LOGIN_ATTEMPTS' WHERE u.ACCOUNT_STATUS='OPEN' ORDER BY 1;" | grep "=" | grep -vi "TBR-")
    failed=$(run_q "SELECT LIMIT FROM DBA_PROFILES WHERE PROFILE='DEFAULT' AND RESOURCE_NAME='FAILED_LOGIN_ATTEMPTS';" | tr -d ' \n')
    evd_q "DBM-006" "OPEN 계정별 FAILED_LOGIN_ATTEMPTS / DEFAULT" "$(echo "$_tp6" | _csv) / ${failed}"
    _tb6=$(echo "$_tp6" | awk -F= '$2=="UNLIMITED" || $2+0>5 || $2=="" {print}' | head -8)
    if [ -n "$_tp6" ]; then
        [ -n "$_tb6" ] && ng "006" "FAILED_LOGIN_ATTEMPTS UNLIMITED/5 초과 계정: $(echo "$_tb6" | _csv) - 서비스 운영 계정은 평가 제외 가능" \
                       || ok "006" "OPEN 계정 FAILED_LOGIN_ATTEMPTS 5회 이하"
    elif [ "$failed" = "UNLIMITED" ] || [ -z "$failed" ]; then
        ng "006" "FAILED_LOGIN_ATTEMPTS=${failed:-UNLIMITED(기본값)}"
    elif [ "$failed" -le 5 ] 2>/dev/null; then
        ok "006" "FAILED_LOGIN_ATTEMPTS=${failed} (5회 이하, DEFAULT 프로파일)"
    else
        ng "006" "FAILED_LOGIN_ATTEMPTS=${failed} (5회 이하 권고)"
    fi

    # 계정별 적용 프로파일 값 (OPEN 계정, LIMIT=DEFAULT 는 DEFAULT 프로파일 값) — 평가기준 '계정별 프로파일'
    _tb_prof() { run_q "SELECT u.USERNAME||'='||DECODE(p.LIMIT,'DEFAULT',d.LIMIT,p.LIMIT) FROM DBA_USERS u JOIN DBA_PROFILES p ON p.PROFILE=u.PROFILE AND p.RESOURCE_NAME='$1' JOIN DBA_PROFILES d ON d.PROFILE='DEFAULT' AND d.RESOURCE_NAME='$1' WHERE u.ACCOUNT_STATUS='OPEN' ORDER BY 1;" | grep "=" | grep -vi "TBR-"; }
    # DBM-007: 패스워드 복잡도
    _tb_pwfunc=$(run_q "SELECT LIMIT FROM DBA_PROFILES WHERE PROFILE='DEFAULT' AND RESOURCE_NAME='PASSWORD_VERIFY_FUNCTION';" | tr -d ' \n')
    _tp7=$(_tb_prof PASSWORD_VERIFY_FUNCTION)
    evd_q "DBM-007" "PASSWORD_VERIFY_FUNCTION (DEFAULT / OPEN 계정별)" "${_tb_pwfunc:-미설정} / $(echo "$_tp7" | _csv)"
    _tn7=$(echo "$_tp7" | awk -F= '$2=="" || toupper($2)=="NULL" {print $1}' | head -8)
    # 평가기준: 검증 함수 미적용 계정 존재 또는 함수 내용이 복잡도(2종 10자/3종 8자) 미충족 시 취약 → 적용 시 함수 내용 확인
    if [ -n "$_tp7" ] && [ -n "$_tn7" ]; then ng "007" "비밀번호 검증 함수 미적용 계정: $(echo "$_tn7" | _csv)"
    elif [ -n "$_tp7" ]; then mc "007" "OPEN 계정 검증 함수 적용: $(echo "$_tp7" | cut -d= -f2 | sort -u | _csv) - 함수 내용이 복잡도 기준(2종 10자/3종 8자) 충족하는지 확인"
    elif [ -z "$_tb_pwfunc" ] || [ "$_tb_pwfunc" = "NULL" ]; then ng "007" "PASSWORD_VERIFY_FUNCTION 미설정"
    else mc "007" "PASSWORD_VERIFY_FUNCTION=${_tb_pwfunc} - 함수 내용이 복잡도 기준(2종 10자/3종 8자) 충족하는지 확인"; fi

    # DBM-008: 패스워드 변경 주기
    # 평가기준: 만료 정책(PASSWORD_LIFE_TIME, PASSWORD_GRACE_TIME) — 변경 후 90일 이상 지나도 계정이 만료되지 않으면 취약
    _tb_life=$(run_q "SELECT LIMIT FROM DBA_PROFILES WHERE PROFILE='DEFAULT' AND RESOURCE_NAME='PASSWORD_LIFE_TIME';" | tr -d ' \n')
    _tb_grace=$(run_q "SELECT LIMIT FROM DBA_PROFILES WHERE PROFILE='DEFAULT' AND RESOURCE_NAME='PASSWORD_GRACE_TIME';" | tr -d ' \n')
    _tp8=$(join -t= <(_tb_prof PASSWORD_LIFE_TIME | sort) <(_tb_prof PASSWORD_GRACE_TIME | sort) 2>/dev/null)
    evd_q "DBM-008" "PASSWORD_LIFE_TIME / PASSWORD_GRACE_TIME (DEFAULT / OPEN 계정별 LIFE=GRACE)" "${_tb_life} / ${_tb_grace} / $(echo "$_tp8" | _csv)"
    _tb8=$(echo "$_tp8" | awk -F= '{l=$2; g=$3; if (g=="UNLIMITED") g=99999; if (l=="UNLIMITED" || l=="" || l+0+g>90) print $1"="$2"+"$3}' | head -8)
    _g=${_tb_grace}; [ "$_g" = "UNLIMITED" ] && _g=99999; [ -z "$_g" ] && _g=0
    if [ -n "$_tp8" ]; then
        [ -n "$_tb8" ] && ng "008" "90일 지나도 만료되지 않는 계정(LIFE+GRACE): $(echo "$_tb8" | _csv) - 서비스 운영 계정은 평가 제외 가능" \
                       || ok "008" "OPEN 계정 PASSWORD_LIFE_TIME+GRACE_TIME 90일 이내 만료"
    elif [ "$_tb_life" = "UNLIMITED" ] || [ -z "$_tb_life" ]; then
        ng "008" "PASSWORD_LIFE_TIME=${_tb_life:-UNLIMITED(기본값)} (무제한)"
    elif [ $((${_tb_life%%.*} + ${_g%%.*})) -le 90 ] 2>/dev/null; then
        ok "008" "PASSWORD_LIFE_TIME=${_tb_life}일 + GRACE_TIME=${_tb_grace:-0}일 (90일 이내 만료)"
    else
        ng "008" "PASSWORD_LIFE_TIME=${_tb_life}일 + GRACE_TIME=${_tb_grace:-0}일 (90일 지나도 만료되지 않음)"
    fi

    # DBM-009: 세션 타임아웃 (IDLE_TIME + resource_limit)
    # 평가기준: ACTIVE_SESSION_TIMEOUT (전체 접속 적용 - 운영 영향 고려). tip 파일 우선, 파라미터 뷰 보조
    _tb_ast=$(grep -hiE '^\s*ACTIVE_SESSION_TIMEOUT\s*=' "$TB_HOME"/config/*.tip 2>/dev/null | tail -1 | cut -d= -f2 | tr -d ' ')
    [ -z "$_tb_ast" ] && _tb_ast=$(_tb_param ACTIVE_SESSION_TIMEOUT)
    evd_q "DBM-009" "ACTIVE_SESSION_TIMEOUT (tip/V\$PARAMETERS)" "${_tb_ast:-미설정}"
    if [ -z "$_tb_ast" ] || [ "$_tb_ast" = "0" ]; then
        ng "009" "ACTIVE_SESSION_TIMEOUT 미설정 - 접근제어 솔루션으로 세션 종료 시 수동 확인"
    else
        mc "009" "ACTIVE_SESSION_TIMEOUT=${_tb_ast} - 15분(내부 규정) 이하 여부 및 전체 접속 적용에 따른 운영 영향 확인"
    fi

    # DBM-011: 감사 로그
    _tb_audit=$(_tb_param AUDIT_TRAIL)
    [ -z "$_tb_audit" ] && _tb_audit=$(grep -hiE '^\s*AUDIT_TRAIL\s*=' "$TB_HOME"/config/*.tip 2>/dev/null | tail -1 | cut -d= -f2 | tr -d ' ')
    evd_q "DBM-011" "AUDIT_TRAIL (V\$PARAMETERS / tip)" "${_tb_audit:-조회 실패}"
    if [ -z "$_tb_audit" ]; then mc "011" "AUDIT_TRAIL 조회 실패(V\$PARAMETERS/tip) - 수동 확인"
    elif [ "${_tb_audit^^}" = "NONE" ]; then ng "011" "AUDIT_TRAIL=NONE"
    else mc "011" "AUDIT_TRAIL=${_tb_audit} 수집 중 - 주기적 백업 여부 인터뷰/증적 확인"; fi

    # DBM-012: Tibero 리스너 보안 (tbnetmgr 기반)
    evd "DBM-012" "cat ${TB_HOME}/config/tbdsn.tbr 2>/dev/null | head -20 || echo '(tbdsn.tbr 미존재)'"
    if [ -f "${TB_HOME}/config/tbdsn.tbr" ]; then
        mc "012" "Tibero 리스너 설정 수동 확인 (${TB_HOME}/config/tbdsn.tbr)"
    else
        mc "012" "tbdsn.tbr 미존재 - 리스너 설정 수동 확인"
    fi

    # DBM-013: 원격 접속 제어
    # 평가기준: $TB_SID.tip 의 LSNR_INVITED_IP / LSNR_DENIED_IP (_FILE 포함) 설정 여부
    evd "DBM-013" "grep -hiE '^\s*LSNR_(INVITED|DENIED)_IP' ${TB_HOME}/config/*.tip 2>/dev/null"
    _tb_acl=$(grep -hiE '^\s*LSNR_(INVITED|DENIED)_IP(_FILE)?\s*=' "$TB_HOME"/config/*.tip 2>/dev/null | head -3 | tr '\n' ' ')
    if [ -n "$_tb_acl" ]; then ok "013" "리스너 IP 접근제어 설정: ${_tb_acl}"
    elif ls "$TB_HOME"/config/*.tip >/dev/null 2>&1; then ng "013" "LSNR_INVITED_IP/LSNR_DENIED_IP 미설정 - 네트워크 장비·솔루션 접근제어 적용 시 수동 확인"
    else mc "013" "tip 파일 미발견 - 원격 접근제어 수동 확인"; fi

    # DBM-014: OS 역할 인증 비활성화
    _tb_osroles=$(_tb_param OS_ROLES)
    evd_q "DBM-014" "OS_ROLES (V\$PARAMETERS)" "${_tb_osroles:-조회 실패}"
    case "${_tb_osroles^^}" in
    FALSE|N|NO) ok "014" "OS_ROLES=${_tb_osroles}" ;;
    TRUE|Y|YES) ng "014" "OS_ROLES=${_tb_osroles} (OS 기반 역할 인증 취약)" ;;
    "")    mc "014" "OS_ROLES 조회 실패 - 수동 확인" ;;
    *)     mc "014" "OS_ROLES=${_tb_osroles} - 수동 확인" ;;
    esac

    # DBM-015: PUBLIC 불필요 권한
    _tb_pub=$(run_q "SELECT TABLE_NAME||' ('||PRIVILEGE||')' FROM DBA_TAB_PRIVS WHERE GRANTEE='PUBLIC' AND PRIVILEGE='EXECUTE' AND TABLE_NAME IN ('UTL_HTTP','UTL_FILE','UTL_SMTP','UTL_TCP','DBMS_SCHEDULER');" | grep -v "^$" | head -10)
    _tb_pubrs=$(run_q "SELECT GRANTED_ROLE FROM DBA_ROLE_PRIVS WHERE GRANTEE='PUBLIC' UNION ALL SELECT PRIVILEGE FROM DBA_SYS_PRIVS WHERE GRANTEE='PUBLIC';" | grep -v "^$" | grep -vi "TBR-" | head -10)
    evd_q "DBM-015" "PUBLIC Role·시스템 권한 / 위험 패키지 EXECUTE" "${_tb_pubrs:-없음} / ${_tb_pub:-없음}"
    if [ -n "$_tb_pubrs" ]; then ng "015" "PUBLIC 에 Role/시스템 권한 부여: $(echo "$_tb_pubrs" | _csv)"
    elif [ -n "$_tb_pub" ]; then ng "015" "PUBLIC EXECUTE 위험 패키지: $(echo "$_tb_pub" | _csv)"
    else mc "015" "PUBLIC 에 Role·시스템 권한·위험 패키지 없음 - 업무상 불필요한 Object 권한 여부 확인"; fi

    # DBM-016: 보안패치
    evd_q "DBM-016" "Tibero 버전 (패치 판단용)" "${DB_VER}"
    mc "016" "Tibero ${DB_VER} 보안패치 수동 확인"

    # DBM-017: 시스템 테이블 접근 권한
    _tb_sysgrants=$(run_q "SELECT GRANTEE||' → '||TABLE_NAME||' ('||PRIVILEGE||')' FROM DBA_TAB_PRIVS WHERE OWNER='SYS' AND GRANTEE NOT IN ('SYS','TIBERO','PUBLIC','DBA') ORDER BY 1;" | grep -v "^$" | head -20)
    evd_q "DBM-017" "SYS 테이블 접근 권한 (비시스템 계정)" "${_tb_sysgrants:-해당 없음}"
    mc "017" "시스템 테이블 접근 권한 수동 확인 (위 현황 참조)"

    # DBM-019: 패스워드 재사용 제한
    _tb_rmax=$(run_q "SELECT LIMIT FROM DBA_PROFILES WHERE PROFILE='DEFAULT' AND RESOURCE_NAME='PASSWORD_REUSE_MAX';" | tr -d ' \n')
    _tb_rtime=$(run_q "SELECT LIMIT FROM DBA_PROFILES WHERE PROFILE='DEFAULT' AND RESOURCE_NAME='PASSWORD_REUSE_TIME';" | tr -d ' \n')
    _tp19=$(join -t= <(_tb_prof PASSWORD_REUSE_MAX | sort) <(_tb_prof PASSWORD_REUSE_TIME | sort) 2>/dev/null)
    _tb19=$(echo "$_tp19" | awk -F= '$2=="UNLIMITED" && $3=="UNLIMITED" {print $1}' | head -8)
    evd_q "DBM-019" "PASSWORD_REUSE_MAX=${_tb_rmax}, TIME=${_tb_rtime} (DEFAULT) / OPEN 계정별 MAX=TIME" "$(echo "$_tp19" | _csv)"
    # 평가기준: PASSWORD_REUSE_TIME, PASSWORD_REUSE_MAX 둘 다 UNLIMITED 이면 취약
    if [ -n "$_tb19" ]; then ng "019" "PASSWORD_REUSE_MAX·TIME 모두 UNLIMITED 계정: $(echo "$_tb19" | _csv)"
    elif [ -n "$_tp19" ]; then ok "019" "OPEN 계정 비밀번호 재사용 제한 적용 (REUSE_MAX 또는 REUSE_TIME 설정)"
    elif [ -z "$_tb_rmax" ] && [ -z "$_tb_rtime" ]; then mc "019" "PASSWORD_REUSE 조회 실패 - 수동 확인"
    elif [ "${_tb_rmax:-UNLIMITED}" = "UNLIMITED" ] && [ "${_tb_rtime:-UNLIMITED}" = "UNLIMITED" ]; then ng "019" "PASSWORD_REUSE_MAX/TIME 모두 UNLIMITED"
    else ok "019" "비밀번호 재사용 제한 설정 (REUSE_MAX=${_tb_rmax}, REUSE_TIME=${_tb_rtime})"; fi

    # DBM-020: 사용자별 계정 분리
    _tb_open=$(run_q "SELECT USERNAME||' ('||ACCOUNT_STATUS||', PROFILE='||PROFILE||')' FROM DBA_USERS WHERE ACCOUNT_STATUS LIKE '%OPEN%' ORDER BY USERNAME;" | grep -v "^$" | head -20)
    evd_q "DBM-020" "OPEN 상태 사용자 목록" "${_tb_open:-조회 불가}"
    mc "020" "사용자별 계정 분리 수동 확인 (위 현황 참조)"

    evd_q "DBM-021" "해당 없음 (Tibero)" "Windows MSSQL 전용 항목"
    na "021" "Windows MSSQL 전용 항목 (Tibero 해당 없음)"

    # DBM-022: 설정 파일 접근 권한
    evd "DBM-022" "ls -la ${TB_HOME}/config/*.tip ${TB_HOME}/config/tbdsn.tbr ${TB_HOME}/bin/tbsql ${TB_HOME}/bin/tbsvr 2>/dev/null"
    # 평가기준 700: /bin/tbboot·tbsvr·tblistener·tbctl·tbdown 의 group·others 권한 금지
    _perm_check 077 "$TB_HOME"/bin/tbboot "$TB_HOME"/bin/tbsvr "$TB_HOME"/bin/tblistener "$TB_HOME"/bin/tbctl "$TB_HOME"/bin/tbdown; _b22=$_PC_BAD
    if [ "$_PC_FOUND" -eq 0 ]; then
        mc "022" "Tibero 기준 파일(bin/tbboot 등) 미발견 - TB_HOME 확인 필요"
    elif [ -n "$_b22" ]; then
        ng "022" "기준 권한(700) 위반: ${_b22}"
    else
        ok "022" "tbboot·tbsvr·tblistener·tbctl·tbdown 권한 700 기준 충족 (${_PC_FOUND}개)"
    fi

    # DBM-024: WITH GRANT OPTION
    _tb_grants=$(run_q "SELECT GRANTEE||' → '||PRIVILEGE FROM DBA_SYS_PRIVS WHERE ADMIN_OPTION='YES' AND GRANTEE NOT IN ('SYS','TIBERO','DBA') ORDER BY 1;" | grep -v "^$" | head -20)
    evd_q "DBM-024" "ADMIN_OPTION='YES' 부여 (비시스템)" "${_tb_grants:-해당 없음}"
    mc "024" "WITH GRANT OPTION 수동 확인 (위 현황 참조)"

    # DBM-025: EoS
    _tb_ver=$(run_q "SELECT BANNER FROM V\$VERSION;" 2>/dev/null | head -3)
    evd_q "DBM-025" "Tibero 버전 정보 (EoS 판단용)" "${_tb_ver:-${DB_VER}}"
    mc "025" "Tibero EoS 여부 수동 확인 (위 버전 참조)"

    # DBM-026: 구동 계정 umask
    evd "DBM-026" "ps -ef 2>/dev/null | grep tbsvr | grep -v grep | head -3"
    _tb_proc_user=$(ps -ef 2>/dev/null | grep tbsvr | grep -v grep | awk '{print $1}' | head -1)
    _tb_umask=$(_get_umask "$_tb_proc_user" "tbsvr")
    _judge_umask "$_tb_umask" "Tibero" "026" "${_tb_proc_user:-tibero}"

    # DBM-028: 불필요 DB Object
    _tb_syn=$(run_q "SELECT SYNONYM_NAME||' → '||TABLE_OWNER||'.'||TABLE_NAME FROM DBA_SYNONYMS WHERE OWNER='PUBLIC' AND TABLE_OWNER NOT IN ('SYS','TIBERO','PUBLIC') ORDER BY 1;" | grep -v "^$" | head -20)
    evd_q "DBM-028" "PUBLIC synonym (비시스템 소유)" "${_tb_syn:-해당 없음}"
    mc "028" "불필요 DB Object 수동 확인 (위 현황 참조)"

    # DBM-029: 자원 사용 제한 (프로파일)
    _tb_sess=$(run_q "SELECT LIMIT FROM DBA_PROFILES WHERE PROFILE='DEFAULT' AND RESOURCE_NAME='SESSIONS_PER_USER';" | tr -d ' \n')
    evd_q "DBM-029" "SESSIONS_PER_USER" "$_tb_sess"
    [ "$_tb_sess" != "UNLIMITED" ] && [ -n "$_tb_sess" ] && ok "029" "SESSIONS_PER_USER=${_tb_sess}" || mc "029" "DBA_PROFILES 자원 제한 수동 확인"

    # DBM-030: Audit Table 접근 제어
    # 평가기준: Audit Table(SYS._DD_AUD) 소유자 관리자, 일반 계정 삽입/수정/삭제 권한 없음
    _tb_aud=$(run_q "SELECT GRANTEE||' → '||TABLE_NAME||' ('||PRIVILEGE||')' FROM DBA_TAB_PRIVS WHERE TABLE_NAME='_DD_AUD' AND PRIVILEGE IN ('INSERT','UPDATE','DELETE') AND GRANTEE NOT IN ('SYS','TIBERO','DBA') ORDER BY 1;" | grep -v "^$" | grep -vi "TBR-" | head -10)
    _tb_audown=$(run_q "SELECT OWNER FROM DBA_TABLES WHERE TABLE_NAME='_DD_AUD';" | grep -v "^$" | grep -vi "TBR-" | head -1 | tr -d ' ')
    evd_q "DBM-030" "SYS._DD_AUD 소유자 / 일반 계정 수정·삭제 권한" "${_tb_audown:-미확인} / ${_tb_aud:-없음}"
    if [ -n "$_tb_audown" ] && [ "$_tb_audown" != "SYS" ]; then ng "030" "_DD_AUD 소유자가 관리자 계정 아님: ${_tb_audown}"
    elif [ -n "$_tb_aud" ]; then ng "030" "_DD_AUD 수정/삭제 권한 보유 일반 계정: $(echo "$_tb_aud" | _csv)"
    elif [ -z "$_tb_audown" ]; then mc "030" "SYS._DD_AUD 조회 결과 없음 - 소유자·권한 수동 확인"
    else ok "030" "SYS._DD_AUD 소유자 SYS, 일반 계정 수정/삭제 권한 없음"; fi

    evd_q "DBM-031" "해당 없음 (Tibero)" "MSSQL 전용 항목"
    na "031" "MSSQL 전용 항목"

    # DBM-032: 통신구간 암호화 (Tibero SSL/TCPS)
    if [ -f "${TB_HOME}/config/tbdsn.tbr" ]; then
        _tb_ssl=$(grep -iE "SSL|TCPS|ENCRYPTION" "${TB_HOME}/config/tbdsn.tbr" 2>/dev/null | head -3)
        evd_q "DBM-032" "tbdsn.tbr 암호화 설정" "${_tb_ssl:-미설정}"
        [ -n "$_tb_ssl" ] && mc "032" "Tibero 통신 암호화 설정 존재 - 적정성 수동 확인 (위 현황 참조)" || \
            mc "032" "Tibero 통신 암호화 미설정 - tbdsn.tbr 수동 확인"
    else
        mc "032" "Tibero 통신 암호화 설정 수동 확인 (tbdsn.tbr 미존재)"
    fi

    # DBM-033: 이중화 비밀번호 평문 노출 (Tibero Standby)
    _tb_standby=$(run_q "SELECT DATABASE_ROLE FROM V\$DATABASE;" 2>/dev/null | tr -d ' \n')
    evd_q "DBM-033" "V\$DATABASE ROLE" "${_tb_standby:-PRIMARY 또는 조회불가}"
    if [ "${_tb_standby^^}" = "PHYSICAL STANDBY" ] || [ "${_tb_standby^^}" = "LOGICAL STANDBY" ]; then
        mc "033" "Standby 구성됨 - 복제 통신 암호화 수동 확인"
    else
        na "033" "Standby 미구성"
    fi

    # DBM-034: DBMS 구동 권한
    evd "DBM-034" "ps -ef 2>/dev/null | grep tbsvr | grep -v grep"
    _tb_proc=$(ps -ef 2>/dev/null | grep tbsvr | grep -v grep | awk '{print $1}' | head -1)
    [ -n "$_tb_proc" ] && {
        [ "$_tb_proc" = "root" ] && ng "034" "Tibero root 계정으로 실행" || ok "034" "Tibero 구동 계정: ${_tb_proc}"
    } || mc "034" "Tibero 구동 권한 수동 확인"

    evd_q "DBM-035" "해당 없음 (Tibero)" "MSSQL 전용 항목 (xp_cmdshell)"
    na "035" "MSSQL 전용 항목"
    evd_q "DBM-036" "해당 없음 (Tibero)" "MSSQL 전용 항목 (Registry Procedure)"
    na "036" "MSSQL 전용 항목"
}

# ================================================================
# MSSQL(Linux) 점검 — sqlcmd 기반
# ================================================================
check_mssql() {
    MSSQL_USER="${MSSQL_USER:-sa}"
    MSSQL_PASS="${MSSQL_PASS-CHANGE_ME}"
    MSSQL_SERVER="${MSSQL_SERVER:-localhost}"
    MSSQL_PORT="${MSSQL_PORT:-1433}"

    SQLCMD=$(command -v sqlcmd 2>/dev/null)
    [ -z "$SQLCMD" ] && [ -x "/opt/mssql-tools/bin/sqlcmd" ] && SQLCMD="/opt/mssql-tools/bin/sqlcmd"
    [ -z "$SQLCMD" ] && [ -x "/opt/mssql-tools18/bin/sqlcmd" ] && SQLCMD="/opt/mssql-tools18/bin/sqlcmd"
    if [ -z "$SQLCMD" ]; then
        printf '[FALLBACK] %s sqlcmd 미탐지 - MSSQL 전 항목 수동 확인 처리\n\n' "$(date '+%H:%M:%S')" >> "$_EVD"
        for i in 001 003 004 005 006 007 008 009 011 013 015 016 017 019 020 \
                 021 022 024 025 026 028 029 031 032 033 034 035 036; do
            mc "$i" "sqlcmd 미탐지 - 수동 확인"
        done
        na "012" "Oracle 전용 항목"
        na "014" "Oracle 전용 항목"
        na "030" "Oracle/Tibero 전용 항목"
        return
    fi

    _SQLCMD_OPTS="-S ${MSSQL_SERVER},${MSSQL_PORT} -U ${MSSQL_USER} -P ${MSSQL_PASS} -h -1 -W -s |"
    if [ -n "$MSSQL_ENCRYPT" ] && [ "$MSSQL_ENCRYPT" = "0" ]; then
        _SQLCMD_OPTS="$_SQLCMD_OPTS -N n"
    else
        _SQLCMD_OPTS="$_SQLCMD_OPTS -C"
    fi

    # -r 1: 오류(Msg nnn …)를 stderr 로 분리해 증적에만 기록 → 오류 문장이 결과(계정·권한 목록)로 섞이지 않음
    run_q() { $SQLCMD $_SQLCMD_OPTS -r 1 -Q "$1" 2>>"$_EVD" | grep -v "^$" | grep -v "^---" | grep -vE "^\([0-9]+ rows"; }

    _conn_ok "$(run_q "SELECT 'CONN_'+'OK'")" "MSSQL" || return
    DB_VER=$(run_q "SELECT @@VERSION" | head -1)
    _ver_num=""; echo "$DB_VER" | grep -oE "SQL Server [0-9]{4}" >/dev/null && _ver_num=$(echo "$DB_VER" | grep -oE "[0-9]{4}" | head -1)
    _build=""; echo "$DB_VER" | grep -oE "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" >/dev/null && _build=$(echo "$DB_VER" | grep -oE "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" | head -1)
    echo "# SQL Server 버전: ${_ver_num} (${_build})"

    if [ -z "$DB_VER" ]; then
        echo "# [ERROR] SQL Server 접속 실패 - 전 항목 수동확인 처리"
        printf '[FALLBACK] %s SQL Server 접속 실패 - 전 항목 수동 확인 처리\n\n' "$(date '+%H:%M:%S')" >> "$_EVD"
        for i in 001 003 004 005 006 007 008 009 011 013 015 016 017 019 020 \
                 021 022 024 025 026 028 029 031 032 033 034 035 036; do
            mc "$i" "SQL Server 접속 실패 - 수동 확인"
        done
        na "012" "Oracle 전용 항목"; na "014" "Oracle 전용 항목"
        na "030" "Oracle/Tibero 전용 항목"
        return
    fi

    # DBM-001: 취약 패스워드 (비밀번호 정책 미적용 계정)
    _ms_weakpw=$(run_q "SELECT COUNT(*) FROM sys.sql_logins WHERE is_policy_checked=0 AND is_disabled=0" | tail -1 | tr -d ' ')
    evd_q "DBM-001" "is_policy_checked=0 AND is_disabled=0 계정 수" "$_ms_weakpw"
    [ "${_ms_weakpw:-0}" -gt 0 ] 2>/dev/null && mc "001" "비밀번호 정책 미적용 활성 계정 ${_ms_weakpw}개 (크랙 우선 대상) - 계정 비밀번호 복잡도·취약 비밀번호 여부는 해시 크랙으로 확인 필요" || mc "001" "모든 SQL 계정 비밀번호 정책 적용됨 - 계정 비밀번호 복잡도·취약 비밀번호 여부는 해시 크랙으로 확인 필요"

    # DBM-003: 불필요 계정
    _ms_logins=$(run_q "SELECT name+' (type='+type_desc COLLATE DATABASE_DEFAULT+', disabled='+CAST(is_disabled AS VARCHAR)+')' FROM sys.server_principals WHERE type IN ('S','U') ORDER BY name" | head -30)
    evd_q "DBM-003" "sys.server_principals (SQL/Windows 로그인)" "${_ms_logins:-조회 불가}"
    mc "003" "불필요 계정 수동 확인 (위 현황 참조)"

    # DBM-004: sysadmin 역할 계정
    _ms_sysadmin=$(run_q "SELECT role.name+': '+p.name FROM sys.server_principals p JOIN sys.server_role_members r ON p.principal_id=r.member_principal_id JOIN sys.server_principals role ON r.role_principal_id=role.principal_id WHERE role.name IN ('sysadmin','serveradmin','securityadmin','processadmin','setupadmin','bulkadmin','diskadmin','dbcreator') AND p.name NOT LIKE '##%' AND p.name NOT LIKE 'NT SERVICE\%' AND p.name NOT LIKE 'NT AUTHORITY\%'" | grep -v "^$" | head -10)
    evd_q "DBM-004" "서버 수준 관리자 역할 구성원" "${_ms_sysadmin:-해당 없음}"
    mc "004" "서버 수준 관리자 역할 부여: $(echo "${_ms_sysadmin:-없음}" | _csv) - 업무상 필요 여부 인터뷰 확인"

    # DBM-005: TDE 암호화
    _ms_tde=$(run_q "SELECT COUNT(*) FROM sys.dm_database_encryption_keys WHERE encryption_state=3" | tail -1 | tr -d ' ')
    evd_q "DBM-005" "TDE encryption_state=3 count" "$_ms_tde"
    mc "005" "TDE 암호화 DB ${_ms_tde:-0}개 (참고) - 중요정보 컬럼 암호화(Always Encrypted·컬럼 암호화) 적용 여부 확인"

    # DBM-006: 로그인 실패 횟수 제한 (Linux 환경은 SQL Server 자체 정책)
    _ms_nopol=$(run_q "SELECT COUNT(*) FROM sys.sql_logins WHERE is_policy_checked=0 AND is_disabled=0" | tail -1 | tr -d ' ')
    evd_q "DBM-006" "is_policy_checked=0 (비밀번호 정책 미적용) 활성 계정 수" "$_ms_nopol"
    if [ "${_ms_nopol:-0}" -eq 0 ] 2>/dev/null; then
        mc "006" "모든 SQL 계정 is_policy_checked=1 - Linux 환경 PAM/OS 계정 잠금 정책 수동 확인"
    else
        ng "006" "비밀번호 정책 미적용 계정 ${_ms_nopol}개 (is_policy_checked=0 → 로그인 실패 제한 미적용)"
    fi

    # DBM-007: 비밀번호 복잡도
    _ms_nopwc=$(run_q "SELECT COUNT(*) FROM sys.sql_logins WHERE is_policy_checked=0 AND is_disabled=0 AND name NOT LIKE '##%'" | tail -1 | tr -d ' ')
    evd_q "DBM-007" "is_policy_checked=0 (sa 제외) 계정 수" "$_ms_nopwc"
    [ "${_ms_nopwc:-0}" -gt 0 ] 2>/dev/null && ng "007" "비밀번호 복잡도 정책 미적용 계정 ${_ms_nopwc}개" || ok "007" "모든 SQL 계정 비밀번호 복잡도 정책 적용됨"

    # DBM-008: 비밀번호 변경 주기
    _ms_noexp=$(run_q "SELECT COUNT(*) FROM sys.sql_logins WHERE is_expiration_checked=0 AND is_disabled=0 AND name NOT IN ('sa','##MS_PolicyEventProcessingLogin##')" | tail -1 | tr -d ' ')
    evd_q "DBM-008" "is_expiration_checked=0 계정 수" "$_ms_noexp"
    # 평가기준: PasswordLastSetTime 90일 이상 경과 계정 존재 시 취약
    _ms_old=$(run_q "SELECT name+' ('+CONVERT(varchar(10),CAST(LOGINPROPERTY(name,'PasswordLastSetTime') AS datetime),120)+')' FROM sys.sql_logins WHERE is_disabled=0 AND name NOT LIKE '##%' AND DATEDIFF(DAY,CAST(LOGINPROPERTY(name,'PasswordLastSetTime') AS datetime),GETDATE())>=90" | head -10)
    evd_q "DBM-008" "PasswordLastSetTime 90일 이상 경과 활성 로그인" "${_ms_old:-없음}"
    if [ -n "$_ms_old" ]; then ng "008" "비밀번호 변경 후 90일 이상 경과 계정: $(echo "$_ms_old" | _csv) - 서비스 운영 계정은 평가 제외 가능"
    elif [ "${_ms_noexp:-0}" -gt 0 ] 2>/dev/null; then mc "008" "90일 이상 경과 계정 없음, CHECK_EXPIRATION 미설정 ${_ms_noexp}개 - 주기적 변경 관리 확인"
    else ok "008" "활성 SQL 로그인 모두 90일 이내 비밀번호 변경"; fi

    # DBM-009: 미사용 세션 종료 (SQL Server는 글로벌 유휴 세션 타임아웃 미지원)
    _ms_rg=$(run_q "SELECT COUNT(*) FROM sys.resource_governor_configuration WHERE is_enabled=1" 2>/dev/null | tail -1 | tr -d ' ')
    _ms_rqt=$(run_q "SELECT value_in_use FROM sys.configurations WHERE name='remote query timeout'" | tail -1 | tr -d ' ')
    evd_q "DBM-009" "Resource Governor=${_ms_rg:-미확인}, remote_query_timeout=${_ms_rqt:-미확인}" "SQL Server는 글로벌 유휴 세션 타임아웃 미지원 (Resource Governor 또는 응용 프로그램 레벨 설정)"
    _ms_idle=$(run_q "SELECT login_name+' (idle '+CAST(DATEDIFF(MINUTE,last_request_end_time,GETDATE()) AS varchar)+'분)' FROM sys.dm_exec_sessions WHERE is_user_process=1 AND status='sleeping' AND DATEDIFF(MINUTE,last_request_end_time,GETDATE())>15" | head -5)
    evd_q "DBM-009" "15분 초과 유휴 사용자 세션" "${_ms_idle:-없음}"
    [ -n "$_ms_idle" ] && ng "009" "15분 초과 유휴 세션: $(echo "$_ms_idle" | _csv) - 서비스 계정은 평가 제외 가능" \
                       || mc "009" "현재 15분 초과 유휴 세션 없음 - 자동 종료 설정(접근제어 솔루션 등) 여부 확인"

    # DBM-011: 감사 로그
    _ms_audit=$(run_q "SELECT COUNT(*) FROM sys.server_audits WHERE is_state_enabled=1" | tail -1 | tr -d ' ')
    evd_q "DBM-011" "server_audits enabled count" "$_ms_audit"
    _ms_spec=$(run_q "SELECT COUNT(*) FROM sys.server_audit_specifications s JOIN sys.server_audit_specification_details d ON s.server_specification_id=d.server_specification_id WHERE s.is_state_enabled=1 AND d.audit_action_name IN ('FAILED_LOGIN_GROUP','SUCCESSFUL_LOGIN_GROUP')" | tail -1 | tr -d ' ')
    evd_q "DBM-011" "로그인 성공/실패 감사 사양 수" "${_ms_spec:-0}"
    if [ "${_ms_audit:-0}" -gt 0 ] 2>/dev/null && [ "${_ms_spec:-0}" -gt 0 ] 2>/dev/null; then
        mc "011" "서버 감사 ${_ms_audit}개·로그인 감사 사양 ${_ms_spec}건 수집 중 - 주기적 백업 여부 인터뷰/증적 확인"
    elif [ "${_ms_audit:-0}" -gt 0 ] 2>/dev/null; then
        ng "011" "서버 감사 활성이나 로그인 성공/실패 감사 사양 미설정"
    else
        _ms_c2=$(run_q "SELECT value_in_use FROM sys.configurations WHERE name='c2 audit mode'" | tail -1 | tr -d ' ')
        [ "$_ms_c2" = "1" ] && mc "011" "C2 감사 모드 활성 - 주기적 백업 여부 인터뷰/증적 확인" || ng "011" "서버 감사(Server Audit) 미설정"
    fi

    evd_q "DBM-012" "해당 없음 (MSSQL)" "Oracle 전용 항목 (Listener Control Utility)"
    na "012" "Oracle 전용 항목 (Listener Control Utility)"

    # DBM-013: 원격 접속 접근 제어
    # 평가기준: DB 포트에 대한 방화벽·네트워크 장비·솔루션 원격 접근제어 ('remote access'는 서버 간 원격 프로시저 호출 옵션으로 무관)
    _ms_port=$(run_q "SET NOCOUNT ON; SELECT TOP 1 local_tcp_port FROM sys.dm_exec_connections WHERE local_tcp_port IS NOT NULL" | grep -oE '^[0-9]+' | head -1); _ms_port=${_ms_port:-1433}
    evd "DBM-013" "iptables -S 2>/dev/null | grep -E '$_ms_port' | head -5; firewall-cmd --list-all 2>/dev/null | head -20; ufw status 2>/dev/null | grep $_ms_port"
    _ms_fw=$( { iptables -S 2>/dev/null | grep -E -- "--dport $_ms_port" | grep -E -- '-s [0-9]'; firewall-cmd --list-rich-rules 2>/dev/null | grep "$_ms_port"; ufw status 2>/dev/null | grep "$_ms_port" | grep -v Anywhere; } | head -3 | tr '\n' ' ')
    [ -n "$_ms_fw" ] && ok "013" "DB 포트(${_ms_port}) 출발지 제한 규칙: ${_ms_fw}" \
                     || mc "013" "DB 포트(${_ms_port}) 호스트 방화벽 출발지 제한 미확인 - 네트워크 장비·솔루션 접근제어 수동 확인"

    evd_q "DBM-014" "해당 없음 (MSSQL)" "Oracle 전용 항목 (OS_ROLES/REMOTE_OS_ROLES)"
    na "014" "Oracle 전용 항목 (OS_ROLES/REMOTE_OS_ROLES)"

    # DBM-015: Public Role 불필요 권한
    # 기본 설치의 시스템 개체(is_ms_shipped) public GRANT·기본 DB/엔드포인트 권한 제외 (SQL Server 2022 검증: 기본 0건)
    # DB 수준 권한은 DB 별 카탈로그 → 온라인·접근 가능 DB 전체 순회 (기본 설치 0건 검증)
    _ms_dbs=$(run_q "SET NOCOUNT ON; SELECT name+' ('+state_desc COLLATE DATABASE_DEFAULT+')' FROM sys.databases" | _csv)
    _ms_pubpriv=$( { run_q "SET NOCOUNT ON; DECLARE @s nvarchar(max)=N''; SELECT @s=@s+N'SELECT N'''+REPLACE(name,'''','''''')+N':''+p.class_desc COLLATE DATABASE_DEFAULT+N'':''+ISNULL(o.name,N''-'') COLLATE DATABASE_DEFAULT+N'':''+p.permission_name COLLATE DATABASE_DEFAULT FROM '+QUOTENAME(name)+N'.sys.database_permissions p LEFT JOIN '+QUOTENAME(name)+N'.sys.all_objects o ON p.class=1 AND o.object_id=p.major_id WHERE p.grantee_principal_id=0 AND p.state IN (''G'',''W'') AND p.permission_name NOT IN (''CONNECT'',''VIEW ANY COLUMN ENCRYPTION KEY DEFINITION'',''VIEW ANY COLUMN MASTER KEY DEFINITION'') AND (p.class<>1 OR o.is_ms_shipped=0) UNION ALL ' FROM sys.databases WHERE state_desc='ONLINE' AND HAS_DBACCESS(name)=1; IF LEN(@s)>0 BEGIN SET @s=LEFT(@s,LEN(@s)-10); EXEC(@s); END"; run_q "SET NOCOUNT ON; SELECT 'SERVER:'+class_desc+' '+permission_name FROM sys.server_permissions WHERE grantee_principal_id=2 AND permission_name NOT IN ('VIEW ANY DATABASE','CONNECT SQL') AND NOT (class_desc='ENDPOINT' AND permission_name='CONNECT') AND state IN ('G','W')"; } | head -10)
    evd_q "DBM-015" "public 역할 비기본 권한 (전 DB: ${_ms_dbs} + 서버 수준)" "${_ms_pubpriv:-없음}"
    [ -n "$_ms_pubpriv" ] && mc "015" "public 역할 비기본 권한: $(echo "$_ms_pubpriv" | _csv) - 업무상 필요 여부 확인 (불필요 시 취약)" || ok "015" "public 역할에 기본 외 권한 없음"

    # DBM-016: 보안패치
    evd_q "DBM-016" "SQL Server version" "${_ver_num} (${_build})"
    mc "016" "SQL Server ${_ver_num} 보안패치(CU/SP) 적용 현황 수동 확인"

    # DBM-017: 시스템 테이블 접근 권한
    _ms_syslist=$(run_q "SET NOCOUNT ON; DECLARE @s nvarchar(max)=N''; SELECT @s=@s+N'SELECT N'''+REPLACE(name,'''','''''')+N':''+o.name COLLATE DATABASE_DEFAULT+N'':''+d.name COLLATE DATABASE_DEFAULT+N'':''+p.permission_name COLLATE DATABASE_DEFAULT FROM '+QUOTENAME(name)+N'.sys.database_permissions p JOIN '+QUOTENAME(name)+N'.sys.all_objects o ON o.object_id=p.major_id AND p.class=1 JOIN '+QUOTENAME(name)+N'.sys.database_principals d ON d.principal_id=p.grantee_principal_id WHERE (o.schema_id=4 OR o.type=''S'') AND p.state IN (''G'',''W'') AND p.grantee_principal_id<>0 AND d.is_fixed_role=0 AND d.name NOT IN (''dbo'',''sys'',''INFORMATION_SCHEMA'',''guest'') AND d.name NOT LIKE ''##%'' UNION ALL ' FROM sys.databases WHERE state_desc='ONLINE' AND HAS_DBACCESS(name)=1; IF LEN(@s)>0 BEGIN SET @s=LEFT(@s,LEN(@s)-10); EXEC(@s); END" | head -20)
    _ms_systbl=$(echo "$_ms_syslist" | grep -c .)
    evd_q "DBM-017" "sys 스키마·시스템 테이블 권한 (전 DB, 고정 역할·dbo·guest·## 제외)" "${_ms_syslist:-없음}"
    if [ "${_ms_systbl:-0}" -gt 0 ] 2>/dev/null; then
        mc "017" "시스템 테이블/뷰 접근 권한 ${_ms_systbl}건: $(echo "$_ms_syslist" | head -5 | _csv) - 적정성 수동 확인"
    else
        ok "017" "일반 사용자의 시스템 테이블 직접 접근 권한 없음"
    fi

    # DBM-019: 비밀번호 재사용
    evd_q "DBM-019" "SQL Server 비밀번호 히스토리" "SQL Server 자체 미지원 (OS PAM 또는 is_policy_checked 연계)"
    mc "019" "SQL Server 자체 비밀번호 히스토리 미지원 - OS 정책(PAM) 또는 3rd party로 관리"

    # DBM-020: 계정 분리
    _ms_users=$(run_q "SELECT name+' (type='+type_desc COLLATE DATABASE_DEFAULT+')' FROM sys.server_principals WHERE type IN ('S','U') AND is_disabled=0 ORDER BY name" | head -20)
    evd_q "DBM-020" "활성 로그인 계정 목록" "${_ms_users:-조회 불가}"
    mc "020" "공용 계정 사용 여부 수동 확인 (위 현황 참조)"

    # DBM-021: 연결 서버(Linked Server)
    # 평가기준: ODBC 데이터 소스(DSN) 중 불필요 항목 (Linux: /etc/odbc.ini, ~/.odbc.ini) — Linked Server 는 참고
    _ms_linked=$(run_q "SELECT COUNT(*) FROM sys.servers WHERE is_linked=1" | tail -1 | tr -d ' ')
    _ms_dsn=$( { odbcinst -q -s 2>/dev/null; grep -h '^\[' /etc/odbc.ini "$HOME/.odbc.ini" 2>/dev/null; } | grep '^\[' | sort -u | tr -d '[]' | head -10)
    evd_q "DBM-021" "ODBC DSN / (참고) Linked Server 수" "${_ms_dsn:-없음} / ${_ms_linked:-0}"
    [ -n "$_ms_dsn" ] && mc "021" "ODBC 데이터 소스: $(echo "$_ms_dsn" | _csv) - 업무상 불필요 항목 확인 (존재 시 취약)" || ok "021" "등록된 ODBC 데이터 소스(DSN) 없음"

    # DBM-022: 설정 파일 권한 (Linux MSSQL: /var/opt/mssql/)
    evd "DBM-022" "ls -la /var/opt/mssql/mssql.conf /var/opt/mssql/secrets/ /etc/mssql-conf.py 2>/dev/null"
    # 평가기준: 설정 파일·데이터 파일(master.mdf, *.mdf, *.ndf 등)을 허용 계정 외 사용자가 읽기/쓰기 불가 (others 권한 금지)
    _perm_check 007 /var/opt/mssql/mssql.conf /var/opt/mssql/secrets/machine-key /var/opt/mssql/data/*.mdf /var/opt/mssql/data/*.ndf /var/opt/mssql/data/*.ldf; _b22=$_PC_BAD
    if [ "$_PC_FOUND" -eq 0 ]; then
        mc "022" "MSSQL 설정/데이터 파일 미발견 - 수동 확인"
    elif [ -n "$_b22" ]; then
        ng "022" "others 접근 가능 파일: ${_b22}"
    else
        ok "022" "설정·데이터 파일 ${_PC_FOUND}개 others 권한 없음"
    fi

    # DBM-024: WITH GRANT OPTION
    _ms_goptlist=$(run_q "SET NOCOUNT ON; DECLARE @s nvarchar(max)=N''; SELECT @s=@s+N'SELECT N'''+REPLACE(name,'''','''''')+N':''+dp.name COLLATE DATABASE_DEFAULT+N'':''+p.class_desc COLLATE DATABASE_DEFAULT+N'':''+ISNULL(OBJECT_NAME(p.major_id,'+CAST(database_id AS nvarchar(10))+N'),N''-'') COLLATE DATABASE_DEFAULT+N'':''+p.permission_name COLLATE DATABASE_DEFAULT FROM '+QUOTENAME(name)+N'.sys.database_permissions p JOIN '+QUOTENAME(name)+N'.sys.database_principals dp ON dp.principal_id=p.grantee_principal_id WHERE p.state=''W'' UNION ALL ' FROM sys.databases WHERE state_desc='ONLINE' AND HAS_DBACCESS(name)=1; IF LEN(@s)>0 BEGIN SET @s=LEFT(@s,LEN(@s)-10); EXEC(@s); END" | head -20)
    _ms_grantopt=$(echo "$_ms_goptlist" | grep -c .)
    evd_q "DBM-024" "WITH GRANT OPTION(state=W) 권한 (전 DB db:grantee:class:object:permission)" "${_ms_goptlist:-없음}"
    [ "${_ms_grantopt:-0}" -gt 0 ] 2>/dev/null && mc "024" "WITH GRANT OPTION ${_ms_grantopt}건: $(echo "$_ms_goptlist" | head -5 | _csv) - 업무상 필요 여부 확인(불필요 시 취약)" || ok "024" "WITH GRANT OPTION 설정 권한 없음"

    # DBM-025: EoS
    evd_q "DBM-025" "SQL Server version (EoS)" "${_ver_num} (${_build})"
    mc "025" "SQL Server ${_ver_num} EoS 여부 수동 확인"

    # DBM-026: 구동 계정 umask (Linux)
    evd "DBM-026" "ps -ef 2>/dev/null | grep sqlservr | grep -v grep | head -3"
    _ms_proc_user=$(ps -ef 2>/dev/null | grep "sqlservr" | grep -v grep | awk '{print $1}' | head -1)
    _ms_umask=$(_get_umask "$_ms_proc_user" "sqlservr")
    _judge_umask "$_ms_umask" "MSSQL" "026" "${_ms_proc_user:-mssql}"

    # DBM-028: 불필요 DB Object (xp_cmdshell, Ole Automation)
    _ms_xp=$(run_q "SELECT value_in_use FROM sys.configurations WHERE name='xp_cmdshell'" | tail -1 | tr -d ' ')
    _ms_ole=$(run_q "SELECT value_in_use FROM sys.configurations WHERE name='Ole Automation Procedures'" | tail -1 | tr -d ' ')
    evd_q "DBM-028" "xp_cmdshell=${_ms_xp}, Ole Automation=${_ms_ole}" ""
    _issues28=""
    [ "$_ms_xp" = "1" ] && _issues28="xp_cmdshell(활성)"
    [ "$_ms_ole" = "1" ] && _issues28="${_issues28:+$_issues28, }Ole Automation(활성)"
    # 평가기준: 인가되지 않은 Object/Owner 존재 여부(인터뷰) - xp_cmdshell 은 DBM-035 항목
    _ms_obj=$(run_q "SELECT TOP 20 s.name+'.'+o.name+' ('+o.type_desc COLLATE DATABASE_DEFAULT+')' FROM sys.objects o JOIN sys.schemas s ON o.schema_id=s.schema_id WHERE o.is_ms_shipped=0 ORDER BY o.create_date DESC" 2>/dev/null | grep -v "^$" | head -20)
    evd_q "DBM-028" "사용자 생성 Object 목록(최근 20)" "${_ms_obj:-조회 결과 없음}"
    mc "028" "사용자 생성 Object/Owner 인가 여부 인터뷰 확인 (위 현황 참조)"

    # DBM-029: 자원 사용 제한
    _ms_maxmem=$(run_q "SELECT value_in_use FROM sys.configurations WHERE name='max server memory (MB)'" | tail -1 | tr -d ' ')
    evd_q "DBM-029" "max server memory (MB)" "$_ms_maxmem"
    mc "029" "자원 사용 제한 수동 확인 (max server memory=${_ms_maxmem:-미확인}MB)"

    evd_q "DBM-030" "해당 없음 (MSSQL)" "Oracle/Tibero 전용 항목 (Audit Table)"
    na "030" "Oracle/Tibero 전용 항목 (Audit Table)"

    # DBM-031: SA 계정 보안설정 (MSSQL 전용)
    _ms_sa=$(run_q "SELECT CAST(is_disabled AS VARCHAR)+'|'+name FROM sys.server_principals WHERE sid=0x01" | head -1)
    evd_q "DBM-031" "SA account status" "$_ms_sa"
    # 평가기준: sa 비활성 → 양호 / 활성 시 Windows password policy(is_policy_checked) 적용 여부로 판정
    _ms_sapol=$(run_q "SELECT CAST(is_policy_checked AS VARCHAR) FROM sys.sql_logins WHERE sid=0x01" | head -1 | tr -d ' ')
    evd_q "DBM-031" "sa is_policy_checked" "${_ms_sapol:-조회 불가}"
    case "$_ms_sa" in
    1*) ok "031" "SA 계정 비활성화됨 (is_disabled=1)" ;;
    0*) if [ "$_ms_sapol" = "1" ]; then ok "031" "SA 계정 활성, 비밀번호 정책 적용됨 (is_policy_checked=1) - 복잡도 정책은 증적 확인"
        else ng "031" "SA 계정 활성, 비밀번호 정책 미적용 (is_policy_checked=${_ms_sapol:-미확인})"; fi ;;
    *)  mc "031" "SA 계정 상태 수동 확인" ;;
    esac

    # DBM-032: 통신구간 암호화 (MSSQL TLS — force encryption은 mssql-conf 레벨)
    _ms_encrypt=$(run_q "SELECT DISTINCT encrypt_option FROM sys.dm_exec_connections WHERE session_id=@@SPID" 2>/dev/null | tail -1 | tr -d ' ')
    _ms_forceenc=""
    [ -x "/opt/mssql/bin/mssql-conf" ] && _ms_forceenc=$(/opt/mssql/bin/mssql-conf get network.forceencryption 2>/dev/null | grep -oE '[01]' | head -1)
    [ -z "$_ms_forceenc" ] && [ -f /var/opt/mssql/mssql.conf ] && _ms_forceenc=$(grep -i "forceencryption" /var/opt/mssql/mssql.conf 2>/dev/null | grep -oE "[01]" | head -1)
    evd_q "DBM-032" "encrypt_option=${_ms_encrypt:-미확인}, forceencryption=${_ms_forceenc:-미설정}" ""
    if [ "$_ms_forceenc" = "1" ]; then
        ok "032" "강제 암호화 설정됨 (forceencryption=1)"
    elif [ "$_ms_encrypt" = "TRUE" ]; then
        mc "032" "현재 연결 암호화됨 - 전체 연결 강제 암호화(forceencryption) 여부 수동 확인"
    else
        ng "032" "연결 암호화 미확인 (encrypt_option=${_ms_encrypt:-FALSE})"
    fi

    # DBM-033: 이중화 비밀번호 평문 노출 (Always On / Mirroring)
    _ms_ag=$(run_q "SELECT COUNT(*) FROM sys.availability_groups" 2>/dev/null | tail -1 | tr -d ' ')
    _ms_mirror=$(run_q "SELECT COUNT(*) FROM sys.database_mirroring WHERE mirroring_state IS NOT NULL" 2>/dev/null | tail -1 | tr -d ' ')
    evd_q "DBM-033" "AG count=${_ms_ag}, Mirroring count=${_ms_mirror:-0}" ""
    if [ "${_ms_ag:-0}" -gt 0 ] 2>/dev/null || [ "${_ms_mirror:-0}" -gt 0 ] 2>/dev/null; then
        mc "033" "이중화 구성됨 (AG=${_ms_ag:-0}, Mirror=${_ms_mirror:-0}) - 암호화 수동 확인"
    else
        na "033" "Always On/Mirroring 미구성"
    fi

    # DBM-034: 서비스 구동 권한
    evd "DBM-034" "ps -ef 2>/dev/null | grep sqlservr | grep -v grep"
    _ms_svc=$(ps -ef 2>/dev/null | grep "sqlservr" | grep -v grep | awk '{print $1}' | head -1)
    if [ -n "$_ms_svc" ]; then
        if [ "$_ms_svc" = "root" ]; then
            ng "034" "SQL Server root 계정으로 실행 (전용 계정 mssql 권고)"
        else
            ok "034" "SQL Server 구동 계정: ${_ms_svc}"
        fi
    else
        mc "034" "SQL Server 구동 계정 수동 확인"
    fi

    # DBM-035: xp_cmdshell 비활성화 (MSSQL 전용)
    evd_q "DBM-035" "xp_cmdshell value_in_use" "$_ms_xp"
    [ "${_ms_xp:-0}" = "0" ] && ok "035" "xp_cmdshell 비활성화됨 (=0)" || ng "035" "xp_cmdshell 활성화됨 (=1) - 보안 위험"

    # DBM-036: Registry Procedure 접근 권한 (MSSQL 전용)
    # 평가기준: 제한 목록 7종 확장 프로시저가 DBA 외 guest/public 에 부여되면 취약 (Linux 인스턴스에도 xp_reg* 존재·기본 public 부여 확인)
    _ms_regpub=$(run_q "SET NOCOUNT ON; SELECT o.name+':'+dp.name+':'+p.state_desc COLLATE DATABASE_DEFAULT FROM master.sys.database_permissions p JOIN master.sys.all_objects o ON o.object_id=p.major_id JOIN master.sys.database_principals dp ON dp.principal_id=p.grantee_principal_id WHERE p.class=1 AND p.type='EX' AND p.state IN ('G','W') AND dp.name IN ('public','guest') AND o.name IN ('xp_regaddmultistring','xp_regdeletekey','xp_regdeletevalue','xp_regenumvalues','xp_regread','xp_regremovemultistring','xp_regwrite')")
    _ms_regcnt=$(run_q "SET NOCOUNT ON; SELECT COUNT(*) FROM master.sys.all_objects WHERE type='X' AND name LIKE 'xp_reg%'" | tail -1 | tr -d ' ')
    evd_q "DBM-036" "레지스트리 확장 프로시저 수 / public·guest 부여" "${_ms_regcnt:-조회 실패} / ${_ms_regpub:-없음}"
    if [ -z "$_ms_regcnt" ]; then mc "036" "레지스트리 확장 프로시저 조회 실패 - 수동 확인"
    elif [ -n "$_ms_regpub" ]; then ng "036" "레지스트리 확장 프로시저 public/guest 부여: $(echo "$_ms_regpub" | _csv)"
    else ok "036" "제한 대상 레지스트리 확장 프로시저 public/guest 부여 없음"; fi
}

# ════════════════════════════════════════════════════════════════
# 주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드(2026) — DBMS D-01 ~ D-26
#   전자금융(DBM) 점검과 같은 DB 접속으로 가이드 항목코드·판단기준 그대로 판정 (MySQL·MariaDB·PostgreSQL)
#   가이드 '점검 대상'에 없는 제품은 N-A. Oracle·Tibero·MSSQL 은 컨버터가 DBM 결과로 가이드 항목 판정
# ════════════════════════════════════════════════════════════════
_kput() {   # 가이드 항목 판정 1회 기록 (코드 전체: D-xx)
    local k="$1" r="$2" w="$3"
    w=$(printf '%s' "$w" | tr -s ' ' | sed 's/[[:space:]]*$//')   # 공백 정리
    w="${w//$'\n'/, }"; w="${w//|//}"
    printf '[판정] %s|%s|%s\n\n' "$k" "$r" "$w" >> "$_EVD"
    _RES[$k]="${r}|${w}"; _ORDER="${_ORDER} ${k}"
}
_KNA() { local c; for c in "$@"; do _kput "$c" "N-A" "가이드 점검 대상 제품 아님 (${_KDB})"; done; }
_kisa_perm_w() {   # 파일 목록 중 그룹·일반 사용자 수정(쓰기) 권한 보유 파일
    local f p o=""
    for f in "$@"; do [ -e "$f" ] || continue; p=$(get_perm "$f"); [ -n "$p" ] && (( (8#${p: -3} & 8#022) != 0 )) && o="${o} ${f}(${p})"; done
    echo "${o# }"
}
_kisa_d25() {   # D-25: EoS(보안 패치 미제공) = 취약, 그 외 최신 패치 여부 확인
    local e="${_RES[DBM-025]:-}"
    evd_q "D-25" "DBMS 버전 / EoS 판정(DBM-025)" "${DB_VER:-미확인} / ${e:-없음}"
    case "$e" in 취약*) _kput "D-25" "취약" "보안 패치가 제공되지 않는 버전(EoS): ${e#*|}" ;;
    *) _kput "D-25" "수동확인" "${DB_VER:-버전 미확인}${e:+ (${e#*|})} - 벤더 최신 보안 패치 적용 여부 확인" ;; esac
}
_kisa_fail() { local c; for c in $2; do _kput "$c" "수동확인" "$1"; done; }
_D_ALL="D-01 D-02 D-03 D-04 D-05 D-06 D-07 D-08 D-09 D-10 D-11 D-12 D-13 D-14 D-15 D-16 D-17 D-18 D-19 D-20 D-21 D-22 D-23 D-24 D-25 D-26"

kisa_mysql() {
    _KDB="$([ "${IS_MARIADB:-0}" = 1 ] && echo MariaDB || echo MySQL)"
    local _sys="'mysql.session','mysql.sys','mysql.infoschema','mariadb.sys','PUBLIC'"
    if [ "${_DB_CONN:-0}" != 1 ]; then
        _KNA D-05 D-09 D-12 D-13 D-15 D-16 D-17 D-18 D-19 D-20 D-22 D-23 D-24 D-26
        _kisa_fail "DB 접속 실패/클라이언트 미탐지 - 접속 정보 확인 후 재점검" "D-01 D-02 D-03 D-04 D-06 D-07 D-08 D-10 D-11 D-14 D-21 D-25"
        return
    fi
    # 계정 현황 (MySQL 5.7+/MariaDB 10.4+: authentication_string·account_locked, 구버전: Password)
    local _u; _u=$(run_q "SELECT CONCAT(User,'@',Host,'|',IFNULL(plugin,''),'|',IF(IFNULL(authentication_string,'')='','EMPTY','SET'),'|',IFNULL(account_locked,'N')) FROM mysql.user WHERE User NOT IN (${_sys});")
    [ -z "$_u" ] && _u=$(run_q "SELECT CONCAT(User,'@',Host,'|',IFNULL(plugin,''),'|',IF(IFNULL(authentication_string,'')='','EMPTY','SET'),'|N') FROM mysql.user WHERE User NOT IN (${_sys});")
    [ -z "$_u" ] && _u=$(run_q "SELECT CONCAT(User,'@',Host,'||',IF(IFNULL(Password,'')='','EMPTY','SET'),'|N') FROM mysql.user;")
    evd_q "D-01" "계정@호스트|인증 플러그인|비밀번호 설정|잠금 (mysql.user)" "${_u:-조회 불가}"

    # D-01 기본 계정(root) 초기 비밀번호 변경 또는 잠금
    local _r; _r=$(echo "$_u" | awk -F'|' '$1 ~ /^root@/ && $3=="EMPTY" && $4!="Y" && $2!~/(auth_socket|unix_socket)/ {print $1}' | tr '\n' ' ')
    if [ -z "$_u" ]; then _kput "D-01" "수동확인" "mysql.user 조회 불가 - root 비밀번호 변경 여부 확인"
    elif [ -n "$_r" ]; then _kput "D-01" "취약" "기본 계정 비밀번호 미설정(초기값): ${_r% }"
    else _kput "D-01" "양호" "기본 계정(root) 비밀번호 설정 또는 OS 인증(socket)·잠금: $(echo "$_u" | awk -F'|' '$1~/^root@/{print $1"("($3=="SET"?"비밀번호":"")($2~/socket/?" socket":"")($4=="Y"?" 잠금":"")")"}' | tr '\n' ' ')"; fi

    # D-02 불필요 계정 (익명·테스트 계정 = 취약, 그 외 인가 여부 확인)
    local _anon _test _act
    _anon=$(echo "$_u" | awk -F'|' '$1 ~ /^@/ {print $1}' | tr '\n' ' ')
    _test=$(echo "$_u" | awk -F'|' '$4!="Y"{print $1}' | grep -iE '^(test|guest|demo|temp|tmp|sample|user[0-9]*)[0-9_]*@' | tr '\n' ' ')
    _act=$(echo "$_u" | awk -F'|' '$4!="Y"{print $1}' | tr '\n' ' ')
    evd_q "D-02" "활성(잠금 아님) 계정" "${_act:-없음}"
    if [ -n "$_anon$_test" ]; then _kput "D-02" "취약" "불필요 계정 존재:${_anon:+ 익명 계정 ${_anon}}${_test:+ 테스트성 계정 ${_test}}"
    else _kput "D-02" "수동확인" "활성 계정: ${_act:-없음}- 인가되지 않은 계정·퇴직자·미사용 계정 여부 확인 (없으면 양호)"; fi

    # D-03 비밀번호 사용 기간 및 복잡도
    local _vp _lt _cx="" _ln=""
    _vp=$(run_q "SHOW VARIABLES WHERE Variable_name REGEXP '^(validate_password|simple_password_check|cracklib_password_check)';" | tr '\t' '=' | tr '\n' ' ')
    _lt=$(get_var "default_password_lifetime")
    evd_q "D-03" "validate_password*/simple_password_check* / default_password_lifetime" "${_vp:-미설치} / ${_lt:-없음}"
    _ln=$(echo "$_vp" | grep -oE '(validate_password[._]length|simple_password_check_minimal_length)=[0-9]+' | head -1 | cut -d= -f2)
    if echo "$_vp" | grep -qE 'validate_password[._]policy=(MEDIUM|STRONG|1|2)'; then _cx="validate_password MEDIUM 이상"
    elif echo "$_vp" | grep -qE 'simple_password_check_digits=[1-9]' && echo "$_vp" | grep -qE 'simple_password_check_other_characters=[1-9]'; then _cx="simple_password_check"
    elif echo "$_vp" | grep -q 'cracklib_password_check'; then _cx="cracklib_password_check"; fi
    local _bad3=""
    { [ -z "$_cx" ] || [ "${_ln:-0}" -lt 8 ]; } && _bad3="${_bad3} 복잡도 정책 미흡(${_cx:-미설치}, 최소 길이 ${_ln:-미설정})"
    { [ -z "$_lt" ] || [ "$_lt" -eq 0 ] || [ "$_lt" -gt 90 ]; } 2>/dev/null && _bad3="${_bad3} 사용 기간 default_password_lifetime=${_lt:-미지원}(0=무제한, 90일 이하 필요)"
    [ -n "$_bad3" ] && _kput "D-03" "취약" "비밀번호 정책 미적용:${_bad3}" || _kput "D-03" "양호" "복잡도(${_cx}, 최소 ${_ln}자)·사용 기간(${_lt}일) 설정"

    # D-04 관리자 권한(SUPER 등)은 필요한 계정에만
    local _su; _su=$(run_q "SELECT CONCAT(User,'@',Host) FROM mysql.user WHERE Super_priv='Y' AND User NOT IN (${_sys}) ORDER BY 1;" | tr '\n' ' ')
    evd_q "D-04" "SUPER 권한 보유 계정 (mysql.user Super_priv / INFORMATION_SCHEMA.USER_PRIVILEGES)" "${_su:-없음}"
    local _sun; _sun=$(echo "$_su" | tr ' ' '\n' | grep -v '^root@' | grep . | tr '\n' ' ')
    [ -n "$_sun" ] && _kput "D-04" "수동확인" "root 외 SUPER(관리자) 권한 계정: ${_sun}- 관리자 권한 필요성 확인 (불필요 시 취약, 필요한 권한만 부여)" \
                   || _kput "D-04" "양호" "관리자(SUPER) 권한이 root 에만 부여: ${_su:-없음}"

    _KNA D-05
    # D-06 사용자별 계정 사용 (공용 계정 여부)
    evd_q "D-06" "활성 계정" "${_act:-없음}"
    _kput "D-06" "수동확인" "활성 계정: ${_act:-없음}- 사용자·응용프로그램별 개별 계정 사용 여부(공용 계정 사용 시 취약) 확인"

    # D-07 root 권한으로 서비스 구동 제한
    local _pu _cu="" _c
    _pu=$(ps -eo user=,comm= 2>/dev/null | awk '$2 ~ /^(mysqld|mariadbd|mysqld_safe)$/ && $2!="mysqld_safe" {print $1}' | sort -u | tr '\n' ' ')
    for _c in /etc/my.cnf /etc/mysql/my.cnf /etc/my.cnf.d/*.cnf /etc/mysql/mysql.conf.d/*.cnf /etc/mysql/mariadb.conf.d/*.cnf; do
        [ -f "$_c" ] && _cu=$(awk '/^[[:space:]]*\[/{s=$0} tolower(s)~/\[(mysqld|server|mariadb)\]/ && /^[[:space:]]*user[[:space:]]*=/{sub(/.*=[[:space:]]*/,"");print;exit}' "$_c") && [ -n "$_cu" ] && break
    done
    evd_q "D-07" "mysqld 구동 계정 / [mysqld] user" "${_pu:-미실행} / ${_cu:-미설정}"
    if echo " $_pu $_cu" | grep -qw root; then _kput "D-07" "취약" "DBMS 가 root 권한으로 구동 (프로세스=${_pu:-?}, user=${_cu:-미설정})"
    elif [ -n "$_pu$_cu" ]; then _kput "D-07" "양호" "별도 계정으로 구동 (프로세스=${_pu:-미확인}, user=${_cu:-미설정})"
    else _kput "D-07" "수동확인" "구동 계정 확인 불가"; fi

    # D-08 안전한 암호화 알고리즘 (SHA-256 이상)
    local _wk; _wk=$(echo "$_u" | awk -F'|' '$3=="SET" && $2!~/(caching_sha2_password|sha256_password|ed25519|auth_socket|unix_socket|pam|gssapi|ldap)/ {print $1"("($2==""?"구형 해시":$2)")"}' | tr '\n' ' ')
    evd_q "D-08" "비밀번호 계정별 인증 플러그인" "$(echo "$_u" | awk -F'|' '$3=="SET"{print $1" "$2}')"
    if [ -z "$_u" ]; then _kput "D-08" "수동확인" "계정 인증 플러그인 조회 불가"
    elif [ -n "$_wk" ]; then _kput "D-08" "취약" "SHA-256 미만 해시 알고리즘 계정 (mysql_native_password=SHA-1): ${_wk% }"
    else _kput "D-08" "양호" "비밀번호 계정 전부 SHA-256 이상(caching_sha2_password/sha256_password/ed25519) 또는 OS 인증"; fi

    _KNA D-09
    # D-10 원격 접속 제한 (Host='%' 계정)
    local _any; _any=$(echo "$_u" | awk -F'|' '$1 ~ /@%$/ {print $1}' | tr '\n' ' ')
    evd_q "D-10" "모든 호스트(%) 허용 계정 / bind_address" "${_any:-없음} / $(get_var bind_address)"
    [ -n "$_any" ] && _kput "D-10" "취약" "모든 클라이언트(%)에서 접속 가능한 계정: ${_any% } - 지정 IP 로 제한 필요" \
                   || _kput "D-10" "양호" "모든 계정이 지정 호스트에서만 접속 가능 (Host='%' 없음)"

    # D-11 시스템 테이블(mysql 스키마) 접근 제한
    local _st
    _st=$( { run_q "SELECT CONCAT(User,'@',Host,'(전역 SELECT)') FROM mysql.user WHERE Select_priv='Y' AND Super_priv<>'Y' AND User NOT IN (${_sys},'root');"
             run_q "SELECT CONCAT(User,'@',Host,'(mysql DB)') FROM mysql.db WHERE Db IN ('mysql','sys','performance_schema') AND User NOT IN (${_sys},'root');"
             run_q "SELECT CONCAT(User,'@',Host,'(',Table_name,')') FROM mysql.tables_priv WHERE Db='mysql' AND User NOT IN (${_sys},'root');"; } | sort -u | tr '\n' ' ')
    evd_q "D-11" "DBA 외 시스템 스키마(mysql/sys) 접근 권한 계정" "${_st:-없음}"
    [ -n "$_st" ] && _kput "D-11" "취약" "DBA 외 계정의 시스템 테이블 접근 권한: ${_st% }" || _kput "D-11" "양호" "시스템 테이블(mysql 스키마) 접근 권한이 DBA 에만 부여"

    _KNA D-12 D-13
    # D-14 주요 설정 파일 권한 (가이드 MySQL 절차: my.cnf 600/640, 판단: 일반 사용자 수정 권한 제거)
    local _cf; _cf=$(ls /etc/my.cnf /etc/mysql/my.cnf /etc/mysql/debian.cnf /etc/my.cnf.d/*.cnf /etc/mysql/conf.d/*.cnf /etc/mysql/mysql.conf.d/*.cnf /etc/mysql/mariadb.conf.d/*.cnf /root/.my.cnf 2>/dev/null | tr '\n' ' ')
    evd "D-14" "ls -lL $_cf 2>/dev/null"
    local _w; _w=$(_kisa_perm_w $_cf)
    if [ -z "$_cf" ]; then _kput "D-14" "수동확인" "설정 파일(my.cnf) 미발견"
    elif [ -n "$_w" ]; then _kput "D-14" "취약" "설정 파일에 그룹·일반 사용자 수정 권한: ${_w}"
    else _kput "D-14" "양호" "설정 파일 일반 사용자 수정 권한 없음 ($(for f in $_cf; do printf '%s(%s) ' "$f" "$(get_perm "$f")"; done| sed 's/ $//'); 가이드 권고 600/640)"; fi

    _KNA D-15 D-16 D-17 D-18 D-19 D-20
    # D-21 GRANT OPTION 제한 (Grant_priv 계정 = 취약, root 제외)
    local _gp; _gp=$( { run_q "SELECT CONCAT(User,'@',Host) FROM mysql.user WHERE Grant_priv='Y' AND User NOT IN (${_sys},'root');"; run_q "SELECT CONCAT(User,'@',Host,'(',Db,')') FROM mysql.db WHERE Grant_priv='Y' AND User NOT IN (${_sys},'root');"; } | sort -u | tr '\n' ' ')
    evd_q "D-21" "SELECT user, grant_priv FROM mysql.user/mysql.db (root 제외)" "${_gp:-없음}"
    [ -n "$_gp" ] && _kput "D-21" "취약" "GRANT OPTION 보유 계정: ${_gp% }" || _kput "D-21" "양호" "root 외 GRANT OPTION 보유 계정 없음"

    _KNA D-22 D-23 D-24
    _kisa_d25
    _KNA D-26
}

kisa_pgsql() {
    _KDB="PostgreSQL"
    if [ "${_DB_CONN:-0}" != 1 ]; then
        _KNA D-05 D-07 D-09 D-12 D-13 D-15 D-16 D-17 D-18 D-19 D-21 D-22 D-23 D-24
        _kisa_fail "DB 접속 실패/psql 미탐지 - 접속 정보 확인 후 재점검" "D-01 D-02 D-03 D-04 D-06 D-08 D-10 D-11 D-14 D-20 D-25 D-26"
        return
    fi
    local _hba _roles
    _hba=$(run_q "SELECT type||' '||array_to_string(database,',')||' '||array_to_string(user_name,',')||' '||COALESCE(address,'')||COALESCE('/'||netmask,'')||' '||auth_method FROM pg_hba_file_rules WHERE error IS NULL;")
    _roles=$(run_q "SELECT rolname||'|'||CASE WHEN rolcanlogin THEN 't' ELSE 'f' END||'|'||CASE WHEN rolsuper THEN 't' ELSE 'f' END||'|'||CASE WHEN (rolcreaterole OR rolcreatedb OR rolreplication OR rolbypassrls) THEN 't' ELSE 'f' END||'|'||CASE WHEN rolpassword IS NULL THEN 'NULL' WHEN rolpassword LIKE 'SCRAM-SHA-256%' THEN 'SCRAM' WHEN rolpassword LIKE 'md5%' THEN 'MD5' ELSE 'OTHER' END||'|'||COALESCE(rolvaliduntil::text,'') FROM pg_authid WHERE rolname NOT LIKE 'pg\\_%';")
    evd_q "D-01" "역할|로그인|슈퍼유저|관리권한|비밀번호 해시|유효기간 (pg_authid)" "${_roles:-조회 불가(슈퍼유저 권한 필요)}"
    evd_q "D-01" "pg_hba_file_rules" "${_hba:-조회 불가}"

    # D-01 기본 계정(postgres) 초기 비밀번호 변경 또는 잠금
    local _pg; _pg=$(echo "$_roles" | awk -F'|' '$1=="postgres"')
    local _trust _ltrust
    _trust=$(echo "$_hba" | awk '$NF=="trust" && $1!="local" && $4 !~ /^(127\.0\.0\.1|::1)\//')
    _ltrust=$(echo "$_hba" | awk '$NF=="trust" && ($1=="local" || $4 ~ /^(127\.0\.0\.1|::1)\//)' | wc -l)
    if [ -z "$_roles" ]; then _kput "D-01" "수동확인" "pg_authid 조회 불가 - postgres 비밀번호 설정 여부 확인"
    elif [ -n "$_trust" ]; then _kput "D-01" "취약" "비밀번호 없이 접속 가능한 원격 trust 인증: $(echo "$_trust" | tr '\n' ',' | sed 's/,$//')"
    elif echo "$_pg" | awk -F'|' '$5=="NULL"' | grep -q .; then _kput "D-01" "양호" "기본 계정 postgres 비밀번호 미설정 - 비밀번호 인증 불가(peer 등 OS 인증만 허용, 잠금과 동일)"
    else _kput "D-01" "양호" "기본 계정 postgres 비밀번호 설정 ($(echo "$_pg" | cut -d'|' -f5))$( [ "${_ltrust:-0}" -gt 0 ] && echo " - 참고: 로컬(소켓·루프백) trust 규칙 ${_ltrust}개는 비밀번호 없이 접속 가능하므로 필요성 확인")"; fi

    # D-02 불필요 계정
    local _login _test
    _login=$(echo "$_roles" | awk -F'|' '$2=="t"{print $1}' | tr '\n' ' ')
    _test=$(echo "$_login" | tr ' ' '\n' | grep -iE '^(test|guest|demo|temp|tmp|sample|user[0-9]*)[0-9_]*$' | tr '\n' ' ')
    evd_q "D-02" "로그인 가능 역할" "${_login:-없음}"
    [ -n "$_test" ] && _kput "D-02" "취약" "테스트성 계정 존재: ${_test% }" || _kput "D-02" "수동확인" "로그인 가능 역할: ${_login:-없음}- 인가되지 않은 계정·퇴직자·미사용 계정 여부 확인 (없으면 양호)"

    # D-03 비밀번호 사용 기간(VALID UNTIL) 및 복잡도(passwordcheck/credcheck)
    local _spl _nov
    _spl=$(run_q "SHOW shared_preload_libraries;")
    _nov=$(echo "$_roles" | awk -F'|' '$2=="t" && $5!="NULL" && $6=="" {print $1}' | tr '\n' ' ')
    evd_q "D-03" "shared_preload_libraries / 비밀번호 사용 기간(VALID UNTIL) 미설정 로그인 역할" "${_spl:-없음} / ${_nov:-없음}"
    local _b3=""
    echo "$_spl" | grep -qiE 'passwordcheck|credcheck|passwordpolicy' || _b3="${_b3} 복잡도 모듈(passwordcheck/credcheck) 미적용"
    [ -n "$_nov" ] && _b3="${_b3} 사용 기간(VALID UNTIL) 미설정: ${_nov% }"
    [ -n "$_b3" ] && _kput "D-03" "취약" "비밀번호 정책 미적용:${_b3}" || _kput "D-03" "양호" "복잡도 모듈(${_spl}) 적용, 비밀번호 역할 전부 사용 기간 설정"

    # D-04 관리자 권한
    local _adm; _adm=$(echo "$_roles" | awk -F'|' '$1!="postgres" && ($3=="t" || $4=="t") {print $1"("($3=="t"?"SUPERUSER":"CREATEROLE/CREATEDB/REPLICATION/BYPASSRLS")")"}' | tr '\n' ' ')
    evd_q "D-04" "postgres 외 관리 권한 역할" "${_adm:-없음}"
    [ -n "$_adm" ] && _kput "D-04" "수동확인" "postgres 외 관리자 권한 역할: ${_adm}- 필요성 확인 (불필요 시 취약)" || _kput "D-04" "양호" "관리자 권한이 postgres 에만 부여"

    _KNA D-05
    evd_q "D-06" "로그인 가능 역할" "${_login:-없음}"
    _kput "D-06" "수동확인" "로그인 가능 역할: ${_login:-없음}- 사용자·응용프로그램별 개별 계정 사용 여부(공용 계정 사용 시 취약) 확인"
    _KNA D-07

    # D-08 SCRAM-SHA-256
    local _pe _md5; _pe=$(run_q "SHOW password_encryption;"); _md5=$(echo "$_roles" | awk -F'|' '$5=="MD5"||$5=="OTHER"{print $1}' | tr '\n' ' ')
    evd_q "D-08" "password_encryption / MD5 해시 역할" "${_pe} / ${_md5:-없음}"
    if [ -n "$_md5" ]; then _kput "D-08" "취약" "SHA-256 미만(MD5) 해시 비밀번호 역할: ${_md5% } (password_encryption=${_pe})"
    elif [ "$_pe" = "md5" ]; then _kput "D-08" "취약" "password_encryption=md5 (신규 비밀번호가 MD5 로 저장)"
    else _kput "D-08" "양호" "password_encryption=${_pe}, 저장 비밀번호 SCRAM-SHA-256"; fi

    _KNA D-09
    # D-10 원격 접속 제한 (listen_addresses + pg_hba 전체 허용 규칙)
    local _la _open; _la=$(run_q "SHOW listen_addresses;")
    _open=$(echo "$_hba" | awk '$1 ~ /^host/ && ($4 ~ /^(0\.0\.0\.0\/0|::\/0|0\.0\.0\.0\/0\.0\.0\.0|all)$/ || $4 ~ /^0\.0\.0\.0\/0/)')
    evd_q "D-10" "listen_addresses / 전체 대역 허용 pg_hba 규칙" "${_la} / ${_open:-없음}"
    if [ -n "$_open" ] && [ "$_la" != "localhost" ]; then _kput "D-10" "취약" "모든 IP 에서 접속 허용 (listen_addresses=${_la}, pg_hba: $(echo "$_open" | tr '\n' ',' | sed 's/,$//'))"
    else _kput "D-10" "양호" "지정 IP 에서만 접속 허용 (listen_addresses=${_la}$( [ -n "$_open" ] && echo ', 전체 허용 규칙 있으나 로컬 수신만'))"; fi

    # D-11 시스템 테이블 접근 (pg_catalog·information_schema 테이블에 개별 역할 권한 부여)
    local _st; _st=$(run_q "SELECT DISTINCT grantee||'('||table_schema||'.'||table_name||':'||privilege_type||')' FROM information_schema.role_table_grants WHERE table_schema IN ('pg_catalog','information_schema') AND grantee NOT IN ('PUBLIC','postgres') AND grantee NOT LIKE 'pg\\_%' AND grantee NOT IN (SELECT rolname FROM pg_roles WHERE rolsuper) LIMIT 20;" | tr '\n' ' ')
    evd_q "D-11" "시스템 스키마 테이블 권한 (PUBLIC·슈퍼유저 제외)" "${_st:-없음}"
    [ -n "$_st" ] && _kput "D-11" "취약" "DBA 외 역할에 시스템 테이블 권한 부여: ${_st% }" || _kput "D-11" "양호" "시스템 테이블 권한이 DBA 에만 부여 (PUBLIC 기본 카탈로그 조회 권한 제외)"

    _KNA D-12 D-13
    # D-14 주요 설정 파일 권한 (postgresql.conf·pg_hba.conf·pg_ident.conf·.psql_history: 일반 사용자 수정 권한 제거)
    local _cf _w _hf; _cf=$(run_q "SELECT setting FROM pg_settings WHERE name IN ('config_file','hba_file','ident_file');" | tr '\n' ' ')
    for _hf in /root/.psql_history /var/lib/pgsql/.psql_history /var/lib/postgresql/.psql_history; do [ -f "$_hf" ] && _cf="${_cf} ${_hf}"; done
    evd "D-14" "ls -lL $_cf 2>/dev/null"
    _w=$(_kisa_perm_w $_cf)
    if [ -z "${_cf// /}" ]; then _kput "D-14" "수동확인" "설정 파일 경로 조회 불가"
    elif [ -n "$_w" ]; then _kput "D-14" "취약" "설정 파일에 그룹·일반 사용자 수정 권한: ${_w}"
    else _kput "D-14" "양호" "설정 파일 일반 사용자 수정 권한 없음 ($(for f in $_cf; do [ -e "$f" ] && printf '%s(%s) ' "$f" "$(get_perm "$f")"; done | sed 's/ $//'); 가이드 권고 640 이하·.psql_history 600)"; fi

    _KNA D-15 D-16 D-17 D-18 D-19
    # D-20 Object Owner 제한 (슈퍼유저 외 소유 객체)
    local _ow; _ow=$(run_q "SELECT r.rolname||'('||count(*)||')' FROM pg_class c JOIN pg_roles r ON r.oid=c.relowner WHERE NOT r.rolsuper GROUP BY r.rolname ORDER BY 1;" | tr '\n' ' ')
    evd_q "D-20" "슈퍼유저 외 Object Owner (pg_class)" "${_ow:-없음}"
    [ -n "$_ow" ] && _kput "D-20" "취약" "일반 사용자 소유 Object 존재: ${_ow% } - 가이드: Object Owner 를 관리자 계정으로 제한" || _kput "D-20" "양호" "Object Owner 가 관리자(슈퍼유저)로 제한"

    _KNA D-21 D-22 D-23 D-24
    _kisa_d25
    # D-26 감사 기록 (logging_collector)
    local _lc _ls; _lc=$(run_q "SHOW logging_collector;"); _ls=$(run_q "SHOW log_statement;")
    evd_q "D-26" "logging_collector / log_statement / shared_preload_libraries" "${_lc} / ${_ls} / ${_spl}"
    [ "$_lc" = "on" ] && _kput "D-26" "양호" "logging_collector=on (log_statement=${_ls}$(echo "$_spl" | grep -qi pgaudit && echo ', pgaudit')) - 기관 감사 기록 정책 수립 여부는 인터뷰 확인" \
                     || _kput "D-26" "취약" "logging_collector=${_lc:-확인 불가} - 감사 로그 저장 미설정"
}

# ── 실행 분기 ────────────────────────────────────────────────────
case "$DBMS_TYPE" in
oracle)  check_oracle ;;
mysql|mariadb) check_mysql ;;
pgsql|postgresql) check_pgsql ;;
tibero)  check_tibero ;;
mssql|sqlserver) check_mssql ;;
*)
    if [ "$OS_FAMILY" = "WINDOWS" ]; then
        echo "# Windows 환경 — DBMS 전 항목 N-A 처리"
        echo "# Windows 환경 — 전 항목 N-A 처리" >> "$_EVD"
        for i in 001 003 004 005 006 007 008 009 011 012 013 014 015 016 \
                 017 019 020 021 022 024 025 026 028 029 030 031 032 033 034 035 036; do
            na "$i" "Windows 환경 — Linux/Unix 전용 항목"
        done
    else
        echo "# DBMS를 자동 탐지할 수 없습니다."
        echo "# DBMS_TYPE=oracle|mysql|pgsql|tibero|mssql 환경변수를 설정하고 재실행하세요."
        _dbp=$( { ps -e -o comm= 2>/dev/null || cat /proc/[0-9]*/comm 2>/dev/null; } | sed 's#.*/##' | grep -iE 'pmon|mysqld|mariadbd|postgres|sqlservr|tbsvr' | sort -u | tr '\n' ' ')
        for i in 001 003 004 005 006 007 008 009 011 012 013 014 015 016 \
                 017 019 020 021 022 024 025 026 028 029 030 031 032 033 034 035 036; do
            if [ -n "$_dbp" ]; then mc "$i" "DBMS 프로세스(${_dbp% }) 존재하나 종류/클라이언트 미탐지 - DBMS_TYPE 지정 후 재점검"
            else na "$i" "DBMS 미설치"; fi
        done
    fi ;;
esac

# 주요정보 상세가이드(2026) D-01~26 (MySQL·MariaDB·PostgreSQL)
[ "$_KMODE" != "ef" ] && case "$DBMS_TYPE" in
mysql|mariadb) kisa_mysql ;;
pgsql|postgresql) kisa_pgsql ;;
esac
_flush_results
_TOTAL=$((_CP + _CF + _CM + _CN))
echo "# ================================================================"
echo "# 점검 요약"
echo "#   총 점검 항목: ${_TOTAL}"
[ "$_TOTAL" -gt 0 ] 2>/dev/null && {
echo "#   양호:         ${_CP}  ($((_CP * 100 / _TOTAL))%)"
echo "#   취약:         ${_CF}  ($((_CF * 100 / _TOTAL))%)"
echo "#   수동확인:     ${_CM}"
echo "#   N-A:          ${_CN}"
}
echo "# ================================================================"
echo "# 점검 완료: $(date '+%Y-%m-%d %H:%M:%S')"
echo "# 증적 파일: ${_EVD}"
[ -n "$_RESF" ] && echo "# 결과 파일(자동 저장): ${_RESF}  ← 증적 파일과 함께 회수"
[ -n "$_TEEPID" ] && { exec >&- 2>/dev/null; wait "$_TEEPID" 2>/dev/null; sleep 1; }
exit 0
__VC_EOF_4__
# ── 내장: converter/eos_checker.py ──
cat > "$WORK/eos_checker.py" <<'__VC_EOF_5__'
#!/usr/bin/env python3
# ================================================================
# EoS (End of Support) 자동 판정 모듈 v2.0
# 데이터 기준일: 2026-09-28 (endoflife.date 스냅샷 + 벤더 공지 수기 데이터)
# 판정 기준일 : 실행일(오늘) — 환경변수 EOS_CHECK_DATE=YYYY-MM-DD 로 고정 가능
#
# [조회 순서]
#   1) 인터넷 연결 시 endoflife.date 제품 전체 목록(/api/<제품>.json) 조회 → 버전(cycle) 매칭
#   2) 실패·미연결 시 내장 스냅샷(EOL_SNAPSHOT, 2026-09-28 수집) 사용
#   3) endoflife.date 에 없는 제품(HP-UX·JEUS·WebtoB·Tibero·Cisco IOS·Junos 등)은 MANUAL_DB
#   EOS_OFFLINE=1 이면 온라인 조회 생략
#
# [사용법]
#   python eos_checker.py mysql 8.0.46
#   python eos_checker.py amazon-linux 2
#   python eos_checker.py mssql 2016
#   python eos_checker.py --no-api postgresql 13.22
#   python eos_checker.py            (EoS 현황 목록)
#
# [반환] check_eos() → (결과, EoS일자, 설명)   결과: 양호 / 취약 / 수동확인
# ================================================================
import re, sys, os, datetime, json
try:
    from urllib.request import urlopen, Request
    HAS_URLLIB = True
except ImportError:
    HAS_URLLIB = False

DATA_DATE = datetime.date(2026, 9, 28)   # 내장 데이터 수집일


def _check_date():
    v = os.environ.get("EOS_CHECK_DATE", "")
    try:
        return datetime.date.fromisoformat(v) if v else datetime.date.today()
    except ValueError:
        return datetime.date.today()


CHECK_DATE = _check_date()
RESULT_GOOD, RESULT_BAD, RESULT_MANUAL = "양호", "취약", "수동확인"
IMMINENT_DAYS = 90   # 종료 임박(수동확인) 기준

# 입력 제품명 → endoflife.date 제품 식별자
ALIASES = {
    "rhel": "rhel", "redhat": "rhel", "red hat": "rhel", "centos": "centos", "centos-stream": "centos-stream",
    "rocky": "rocky-linux", "rocky-linux": "rocky-linux", "almalinux": "almalinux", "alma": "almalinux",
    "ubuntu": "ubuntu", "debian": "debian", "sles": "sles", "suse": "sles",
    "amazon-linux": "amazon-linux", "amazon": "amazon-linux", "amzn": "amazon-linux",
    "oracle-linux": "oracle-linux", "ol": "oracle-linux", "aix": "ibm-aix", "ibm-aix": "ibm-aix", "solaris": "solaris",
    "windows-server": "windows-server", "windows": "windows-server",
    "oracle": "oracle-database", "oracle-database": "oracle-database", "mysql": "mysql", "mariadb": "mariadb",
    "postgresql": "postgresql", "postgres": "postgresql", "pgsql": "postgresql",
    "mssql": "mssqlserver", "sqlserver": "mssqlserver", "mssqlserver": "mssqlserver",
    "apache": "apache-http-server", "httpd": "apache-http-server", "apache-http-server": "apache-http-server",
    "nginx": "nginx", "tomcat": "tomcat", "cisco-ios-xe": "cisco-ios-xe", "ios-xe": "cisco-ios-xe",
    "redis": "redis", "mongodb": "mongodb", "linux": "linux", "kernel": "linux",
}

# endoflife.date 미등재 제품 (벤더 공지 기준, 2026-09-28) — 버전 prefix: 종료일 | None(지원 중)
MANUAL_DB = {
    "hp-ux":    {"11i v1": "2012-12-31", "11i v2": "2015-12-31", "11i v3": "2025-12-31", "11.11": "2012-12-31", "11.23": "2015-12-31", "11.31": "2025-12-31"},
    "jeus":     {"5": "2016-12-31", "6": "2019-12-31", "7": "2022-12-31", "8": None, "9": None},
    "webtob":   {"3": "2016-12-31", "4": "2019-12-31", "5": None},
    "tibero":   {"4": "2016-12-31", "5": "2021-12-31", "6": None, "7": None},
    "cisco-ios": {"12": "2016-04-29", "15.0": "2019-07-31", "15.1": "2022-08-31", "15.2": "2023-03-31", "15.4": "2022-10-31",
                  "15.5": "2023-06-30", "15.6": "2023-04-29", "15.7": None, "15.8": None, "15.9": None},
    "cisco-asa": {"9.8": "2022-09-30", "9.12": "2024-03-31", "9.14": "2024-09-30", "9.16": None, "9.18": None, "9.20": None},
    "junos":    {"18": "2023-10-31", "20": "2024-10-31", "21": "2025-10-31", "22": None, "23": None, "24": None},
}

_ONLINE_CACHE = {}
LAST_SOURCE = ""


def fetch_online(slug):
    """endoflife.date 제품 전체 목록 조회 (성공 시 [(cycle, label, eol)], 실패 시 None). 리다이렉트 추적"""
    if slug in _ONLINE_CACHE:
        return _ONLINE_CACHE[slug]
    data = None
    if HAS_URLLIB and os.environ.get("EOS_OFFLINE") != "1":
        try:
            req = Request(f"https://endoflife.date/api/{slug}.json",
                          headers={"Accept": "application/json", "User-Agent": "eos-checker/2.0"})
            with urlopen(req, timeout=5) as resp:
                raw = json.loads(resp.read().decode("utf-8"))
            if isinstance(raw, list) and raw:
                data = [(str(x.get("cycle")), (x.get("releaseLabel") or "").replace("'__CODENAME__'", "").strip(),
                         x.get("eol")) for x in raw]
        except Exception:
            data = None
    _ONLINE_CACHE[slug] = data
    return data


def _cycle_candidates(slug, version):
    """입력 버전 → endoflife.date cycle 후보 (긴 것 우선)"""
    v = version.strip().lower()
    v = re.sub(r"^v", "", v)
    out = []
    if slug == "oracle-database":
        m = re.match(r"(\d+)(?:\.(\d+))?\s*([cgi]|ai)?", v)
        if m:
            if m.group(2) and m.group(1) in ("10", "11", "12", "9"):
                out.append(f"{m.group(1)}.{m.group(2)}")
            out.append(m.group(1))
            if m.group(1) in ("10", "11", "12"):
                out.append(m.group(1) + ".2")
        return out
    if slug == "windows-server":
        m = re.search(r"(2003|2008|2012|2016|2019|2022|2025)\s*-?\s*(r2)?", v)
        if m:
            return [f"{m.group(1)}-r2" if m.group(2) else m.group(1), m.group(1)]
    if slug == "mssqlserver":
        return [v]   # 연도(2016 등)는 releaseLabel 로 매칭
    if slug == "amazon-linux":
        if re.match(r"^20(1[0-9])\.\d+", v):
            return [re.match(r"^\d{4}\.\d+", v).group()]
        if v.startswith("2023"):
            return ["2023"]
        if re.match(r"^2(\.|$)", v):
            return ["2"]
        if re.match(r"^1(\.|$)", v):
            return ["2018.03"]
    parts = re.findall(r"\d+", v)
    for n in range(min(len(parts), 3), 0, -1):
        out.append(".".join(parts[:n]))
    return out


def _match(slug, rows, version):
    """rows 에서 버전에 맞는 (cycle, label, eol) 반환"""
    if slug == "mssqlserver":
        y = re.search(r"(2008|2012|2014|2016|2017|2019|2022|2025)", version)
        if y:
            cand = [r for r in rows if r[1].startswith(y.group(1))]
            sp = re.search(r"sp\s*(\d)", version, re.I)
            if sp:
                c2 = [r for r in cand if f"SP{sp.group(1)}" in r[1]]
                cand = c2 or cand
            if cand:   # 서비스팩 미지정 → 최신 SP(종료일 가장 늦은 행) 기준
                return max(cand, key=lambda r: str(r[2]))
        return None
    cmap = {r[0]: r for r in rows}
    for c in _cycle_candidates(slug, version):
        if c in cmap:
            return cmap[c]
    # AIX 7.2 → 7.2.x 중 최신 TL
    m = re.match(r"^(\d+\.\d+)$", version.strip())
    if m:
        tl = [r for r in rows if r[0].startswith(m.group(1) + ".")]
        if tl:
            return max(tl, key=lambda r: [int(x) for x in re.findall(r"\d+", r[0])])
    return None


def _judge(product, version, eol, src, cycle=""):
    tag = f"{product} {version}" + (f" (주기 {cycle})" if cycle and cycle != version else "")
    if eol is False or eol is None:
        return RESULT_GOOD, None, f"{tag} 지원 기간 내 [{src}]"
    if eol is True:
        return RESULT_BAD, "종료", f"{tag} 지원 종료 [{src}]"
    try:
        d = datetime.date.fromisoformat(str(eol)[:10])
    except ValueError:
        return RESULT_MANUAL, str(eol), f"{tag} 종료일 형식 확인 필요({eol}) [{src}]"
    days = (d - CHECK_DATE).days
    if days < 0:
        return RESULT_BAD, str(d), f"{tag} EoS {d} ({-days}일 경과) [{src}]"
    if days <= IMMINENT_DAYS:
        return RESULT_MANUAL, str(d), f"{tag} EoS {d} ({days}일 남음, 임박) [{src}]"
    return RESULT_GOOD, str(d), f"{tag} 지원 기간 내 (EoS {d}) [{src}]"


def check_eos(product, version, use_api=True):
    """EoS 판정 → (결과, EoS일자|None, 설명)"""
    global LAST_SOURCE
    p = (product or "").lower().strip()
    v = (version or "").strip()
    if not v:
        return RESULT_MANUAL, None, f"{product} 버전 미확인 - 수동 확인"
    slug = ALIASES.get(p) or next((s for k, s in ALIASES.items() if k in p), None)
    if slug:
        rows, src = None, ""
        if use_api:
            rows = fetch_online(slug)
            src = "endoflife.date 온라인 조회" if rows else ""
        if not rows:
            rows = EOL_SNAPSHOT.get(slug)
            src = f"내장 데이터 {DATA_DATE}"
        if rows:
            hit = _match(slug, rows, v)
            if hit:
                LAST_SOURCE = src
                return _judge(product, v, hit[2], src, hit[1] or hit[0])
            return RESULT_MANUAL, None, f"{product} {v} 버전 주기 미등재 - 벤더 지원 정책 수동 확인 [{src}]"
    key = next((k for k in MANUAL_DB if k == p or k in p), None)
    if key:
        db = MANUAL_DB[key]
        vv = v.lower()
        for k in sorted(db, key=len, reverse=True):
            if vv == k or vv.startswith(k + ".") or vv.startswith(k + " ") or vv.startswith(k):
                return _judge(product, v, db[k] if db[k] else False, f"벤더 공지 수기 데이터 {DATA_DATE}", k)
        return RESULT_MANUAL, None, f"{product} {v} 버전 정보 없음 - 벤더 지원 정책 수동 확인"
    return RESULT_MANUAL, None, f"{product} {v} EoS 정보 없음 - 벤더 지원 정책 수동 확인"


def kernel_status(kernel, use_api=True):
    """리눅스 커널 버전 → 업스트림(kernel.org) 기준 지원 상태 (참고용: 배포판 커널은 배포판 지원 정책을 따름)"""
    m = re.match(r"(\d+)\.(\d+)", kernel or "")
    if not m:
        return RESULT_MANUAL, None, "커널 버전 미확인"
    r, e, d = check_eos("linux", f"{m.group(1)}.{m.group(2)}", use_api)
    return r, e, d.replace("linux ", "커널 ")


def detect_and_check(product, version):
    result, _, desc = check_eos(product, version)
    return f"{result}|{desc}"


def batch_check(items):
    return [(code,) + check_eos(product, version) for product, version, code in items]


EOL_SNAPSHOT = {   # endoflife.date /api/<제품>.json 스냅샷 (2026-09-28 수집) - (cycle, releaseLabel, eol[날짜|True=종료|False=지원중])
    "almalinux": [
        ('10', '', '2035-05-31'), ('9', '', '2032-05-31'), ('8', '', '2029-05-31'),
    ],
    "amazon-linux": [
        ('2023', '', '2029-06-30'), ('2', '', '2026-06-30'), ('2018.03', 'AMI 2018.03', '2023-12-31'),
        ('2017.09', 'AMI 2017.09', '2023-12-31'), ('2017.03', 'AMI 2017.03', '2023-12-31'), ('2016.09', 'AMI 2016.09', '2023-12-31'),
        ('2016.03', 'AMI 2016.03', '2023-12-31'), ('2015.09', 'AMI 2015.09', '2023-12-31'), ('2015.03', 'AMI 2015.03', '2023-12-31'),
        ('2014.09', 'AMI 2014.09', '2023-12-31'), ('2014.03', 'AMI 2014.03', '2023-12-31'), ('2013.09', 'AMI 2013.09', '2023-12-31'),
        ('2013.03', 'AMI 2013.03', '2023-12-31'), ('2012.09', 'AMI 2012.09', '2023-12-31'), ('2012.03', 'AMI 2012.03', '2023-12-31'),
        ('2011.09', 'AMI 2011.09', '2023-12-31'), ('2010.11', 'AMI 2010.11', '2023-12-31'),
    ],
    "apache-http-server": [
        ('2.4', '', False), ('2.2', '', '2017-07-11'), ('2.0', '', '2013-07-10'),
        ('1.3', '', '2010-02-03'),
    ],
    "centos-stream": [
        ('10', '', '2030-05-31'), ('9', '', '2027-05-31'), ('8', '', '2024-05-31'),
    ],
    "centos": [
        ('8', '', '2021-12-31'), ('7', '', '2024-06-30'), ('6', '', '2020-11-30'),
        ('5', '', '2017-03-31'),
    ],
    "cisco-ios-xe": [
        ('26.1', '', False), ('17.18', '', '2029-08-08'), ('17.17', '', '2026-07-30'),
        ('17.16', '', '2026-01-13'), ('17.15', '', '2028-09-30'), ('17.14', '', '2025-05-31'),
        ('17.13', '', '2024-12-31'), ('17.12', '', '2027-09-30'), ('17.11', '', '2024-05-14'),
        ('17.10', '', '2024-01-03'), ('17.9', '', '2026-09-30'), ('17.8', '', '2023-05-30'),
        ('17.7', '', '2023-01-30'), ('17.6', '', '2024-09-30'), ('17.5', '', '2022-05-30'),
        ('17.4', '', '2022-01-28'), ('17.3', '', '2023-09-30'), ('17.2', '', '2021-07-15'),
        ('17.1', '', '2020-12-30'), ('16.12', '', '2022-08-18'),
    ],
    "debian": [
        ('13', '', '2030-06-30'), ('12', '', '2028-06-30'), ('11', '', '2026-08-31'),
        ('10', '', '2024-06-30'), ('9', '', '2022-07-01'), ('8', '', '2020-06-30'),
        ('7', '', '2018-05-31'), ('6', '', '2016-02-29'), ('5', '', '2012-02-06'),
        ('4', '', '2010-02-15'), ('3.1', '', '2008-03-31'), ('3.0', '', '2006-06-30'),
        ('2.2', '', '2003-06-30'), ('2.1', '', '2000-10-30'), ('2.0', '', '1999-02-15'),
        ('1.3', '', '1998-12-08'), ('1.2', '', '1997-10-23'), ('1.1', '', '1996-12-12'),
    ],
    "ibm-aix": [
        ('7.3.4', '', '2028-12-31'), ('7.3.3', '', '2027-12-31'), ('7.3.2', '', '2026-11-30'),
        ('7.3.1', '', '2025-12-31'), ('7.3.0', '', '2024-12-31'), ('7.2.5', '', False),
        ('7.2.4', '', '2022-11-30'), ('7.2.3', '', '2021-09-30'), ('7.2.2', '', '2020-10-31'),
        ('7.2.1', '', '2019-11-30'), ('7.2.0', '', '2018-12-31'), ('7.1.5', '', '2023-04-30'),
        ('6.1.9', '', '2017-04-30'),
    ],
    "linux": [
        ('7.2', '', False), ('7.1', '', '2026-09-02'), ('7.0', '', '2026-06-27'),
        ('6.19', '', '2026-04-22'), ('6.18', '', '2028-12-31'), ('6.17', '', '2025-12-18'),
        ('6.16', '', '2025-10-12'), ('6.15', '', '2025-08-20'), ('6.14', '', '2025-06-10'),
        ('6.13', '', '2025-04-20'), ('6.12', '', '2028-12-31'), ('6.11', '', '2024-12-05'),
        ('6.10', '', '2024-10-10'), ('6.9', '', '2024-07-27'), ('6.8', '', '2024-05-30'),
        ('6.7', '', '2024-04-03'), ('6.6', '', '2027-12-31'), ('6.5', '', '2023-11-28'),
        ('6.4', '', '2023-09-13'), ('6.3', '', '2023-07-11'), ('6.2', '', '2023-05-17'),
        ('6.1', '', '2027-12-31'), ('6.0', '', '2023-01-12'), ('5.19', '', '2022-10-24'),
        ('5.18', '', '2022-08-21'), ('5.17', '', '2022-06-14'), ('5.16', '', '2022-04-13'),
        ('5.15', '', '2026-12-31'), ('5.14', '', '2021-11-21'), ('5.13', '', '2021-09-18'),
        ('5.12', '', '2021-07-20'), ('5.11', '', '2021-05-19'), ('5.10', '', '2026-12-31'),
        ('5.4', '', '2025-12-03'), ('4.19', '', '2024-12-05'), ('4.14', '', '2024-01-10'),
        ('4.9', '', '2023-01-07'),
    ],
    "mariadb": [
        ('13.0', '', '2026-12-31'), ('12.3', '', '2029-06-12'), ('12.2', '', '2026-05-28'),
        ('12.1', '', '2026-02-13'), ('12.0', '', '2025-11-18'), ('11.8', '', '2028-06-04'),
        ('11.7', '', '2025-05-12'), ('11.6', '', '2025-02-13'), ('11.5', '', '2024-11-21'),
        ('11.4', '', '2029-05-29'), ('11.3', '', '2024-05-29'), ('11.2', '', '2024-11-21'),
        ('11.1', '', '2024-08-21'), ('11.0', '', '2024-06-06'), ('10.11', '', '2028-02-16'),
        ('10.10', '', '2023-11-17'), ('10.9', '', '2023-08-22'), ('10.8', '', '2023-05-20'),
        ('10.7', '', '2023-02-09'), ('10.6', '', '2026-07-06'), ('10.5', '', '2025-06-24'),
        ('10.4', '', '2024-06-18'), ('10.3', '', '2023-05-25'), ('10.2', '', '2022-05-23'),
        ('10.1', '', '2020-10-17'), ('10.0', '', '2019-03-31'), ('5.5', '', '2020-04-11'),
        ('5.3', '', '2017-03-01'), ('5.2', '', '2015-11-10'), ('5.1', '', '2015-02-01'),
    ],
    "mongodb": [
        ('8.3', '', '2029-10-31'), ('8.2', '8.2 (Rapid Release)', '2026-07-31'), ('8.1', '8.1 (Rapid Release)', '2025-09-30'),
        ('8.0', '', '2029-10-31'), ('7.3', '7.3 (Rapid Release)', '2024-10-02'), ('7.2', '7.2 (Rapid Release)', '2024-03-27'),
        ('7.1', '7.1 (Rapid Release)', '2024-01-23'), ('7.0', '', '2027-08-31'), ('6.3', '6.3 (Rapid Release)', '2023-08-31'),
        ('6.2', '6.2 (Rapid Release)', '2023-04-24'), ('6.1', '6.1 (Rapid Release)', '2023-02-09'), ('6.0', '', '2025-07-31'),
        ('5.3', '5.3 (Rapid Release)', '2022-07-19'), ('5.2', '5.2 (Rapid Release)', '2022-03-23'), ('5.1', '5.1 (Rapid Release)', '2022-01-19'),
        ('5.0', '', '2024-10-31'), ('4.4', '', '2024-02-29'), ('4.2', '', '2023-04-30'),
        ('4.0', '', '2022-04-30'), ('3.6', '', '2021-04-30'), ('3.4', '', '2020-01-31'),
        ('3.2', '', '2018-09-30'), ('3.0', '', '2018-02-28'), ('2.6', '', '2016-10-31'),
        ('2.4', '', '2013-03-31'), ('2.2', '', '2014-02-28'), ('2.0', '', '2013-03-31'),
        ('1.8', '', '2012-09-30'), ('1.6', '', '2012-02-28'), ('1.4', '', '2012-09-30'),
        ('1.2', '', '2011-06-30'), ('1.0', '', '2010-08-31'),
    ],
    "mssqlserver": [
        ('17.0', '2025', '2036-01-06'), ('16.0', '2022', '2033-01-11'), ('13.0-sp3-acp', '2016 SP3 Azure Connect Pack', '2026-07-14'),
        ('13.0-sp3', '2016 SP3', '2026-07-14'), ('15.0', '2019', '2030-01-08'), ('12.0-sp3', '2014  SP3', '2024-07-09'),
        ('13.0-sp2', '2016 SP2', '2022-10-11'), ('11.0-sp4', '2012  SP4', '2022-07-12'), ('14.0', '2017', '2027-10-12'),
        ('13.0-sp1', '2016 SP1', '2019-07-09'), ('12.0-sp2', '2014  SP2', '2020-01-14'), ('13.0', '2016', '2018-01-09'),
        ('11.0-sp3', '2012  SP3', '2018-10-09'), ('12.0-sp1', '2014  SP1', '2017-10-10'), ('10.50-sp3', '2008 R2  SP3', '2019-07-09'),
        ('10.0-sp4', '2008  SP4', '2019-07-09'), ('11.0-sp2', '2012  SP2', '2017-01-10'), ('12.0', '2014', '2016-07-12'),
        ('11.0-sp1', '2012  SP1', '2015-07-14'), ('10.50-sp2', '2008 R2  SP2', '2015-10-13'), ('11.0', '2012', '2014-01-14'),
        ('10.00-sp3', '2008  SP3', '2015-10-13'), ('10.50-sp1', '2008 R2  SP1', '2013-10-08'), ('9.0-sp4', '2005  SP4', '2016-04-12'),
        ('10.00-sp2', '2008  SP2', '2012-10-09'), ('10.50-r2', '2008  R2', '2012-07-10'), ('10.00-sp1', '2008  SP1', '2011-10-11'),
        ('9.00-sp3', '2005  SP3', '2012-01-10'), ('10.00', '2008', '2010-04-13'), ('9.00-sp2', '2005  SP2', '2010-01-12'),
        ('9.0-sp1', '2005  SP1', '2008-04-08'), ('9.0', '2005', '2007-07-10'), ('8.0-sp4', '2000  SP4', '2013-04-09'),
        ('7.0-sp4', '7.0  SP4', '2011-01-11'), ('6.50-sp5a', '6.5  SP5a', '2002-01-01'), ('6.0-sp3', '6.0  SP3', '1999-03-31'),
    ],
    "mysql": [
        ('9.7', '', '2034-04-30'), ('9.6', '', '2026-04-21'), ('9.5', '', '2026-01-20'),
        ('9.4', '', '2025-10-21'), ('9.3', '', '2025-07-22'), ('9.2', '', '2025-04-15'),
        ('9.1', '', '2025-01-21'), ('9.0', '', '2024-10-15'), ('8.4', '', '2032-04-30'),
        ('8.3', '', '2024-04-30'), ('8.2', '', '2024-01-16'), ('8.1', '', '2023-10-25'),
        ('8.0', '', '2026-04-30'), ('5.7', '', '2023-10-31'), ('5.6', '', '2021-02-28'),
        ('5.5', '', '2018-12-31'),
    ],
    "nginx": [
        ('1.31', '', False), ('1.30', '', False), ('1.29', '', '2026-05-13'),
        ('1.28', '', '2026-04-14'), ('1.27', '', '2025-06-24'), ('1.26', '', '2025-04-23'),
        ('1.25', '', '2024-05-29'), ('1.24', '', '2024-04-23'), ('1.23', '', '2023-05-23'),
        ('1.22', '', '2023-04-11'), ('1.21', '', '2022-06-21'), ('1.20', '', '2022-05-24'),
        ('1.19', '', '2021-05-25'), ('1.18', '', '2021-04-20'), ('1.16', '', '2020-04-20'),
        ('1.14', '', '2019-04-23'), ('1.12', '', '2018-04-17'), ('1.10', '', '2017-04-12'),
        ('1.8', '', '2016-04-26'), ('1.6', '', '2015-04-21'), ('1.4', '', '2014-04-24'),
        ('1.2', '', '2013-04-24'), ('1.0', '', '2012-04-23'),
    ],
    "oracle-database": [
        ('23', '26ai', '2031-12-31'), ('21', '21c', '2027-07-31'), ('19', '19c', '2029-12-31'),
        ('18', '18c', '2021-06-30'), ('12.2', '12c Release 2', '2022-03-31'), ('12.1', '12c Release 1', '2018-07-31'),
        ('11.2', '11g Release 2', '2015-01-31'), ('11.1', '11g Release 1', '2012-08-31'), ('10.2', '10g Release 2', '2010-07-31'),
        ('10.1', '10g Release 1', '2009-01-31'), ('9.2', '9i Release 2', '2007-07-31'), ('9.0', '9i Release 1', '2003-12-31'),
    ],
    "oracle-linux": [
        ('10', '', '2035-06-30'), ('9', '', '2032-06-30'), ('8', '', '2029-07-31'),
        ('7', '', '2024-12-31'), ('6', '', '2021-03-31'),
    ],
    "postgresql": [
        ('18', '', '2030-11-14'), ('17', '', '2029-11-08'), ('16', '', '2028-11-09'),
        ('15', '', '2027-11-11'), ('14', '', '2026-11-12'), ('13', '', '2025-11-13'),
        ('12', '', '2024-11-21'), ('11', '', '2023-11-09'), ('10', '', '2022-11-10'),
        ('9.6', '', '2021-11-11'), ('9.5', '', '2021-02-11'), ('9.4', '', '2020-02-13'),
        ('9.3', '', '2018-11-08'), ('9.2', '', '2017-11-09'), ('9.1', '', '2016-10-27'),
        ('9.0', '', '2015-10-08'), ('8.4', '', '2014-07-24'), ('8.3', '', '2013-02-07'),
        ('8.2', '', '2011-12-05'), ('8.1', '', '2010-11-08'), ('8.0', '', '2010-10-01'),
        ('7.4', '', '2010-10-01'), ('7.3', '', '2007-11-27'), ('7.2', '', '2007-02-04'),
        ('7.1', '', '2006-04-13'), ('7.0', '', '2005-05-08'), ('6.5', '', '2004-06-09'),
        ('6.4', '', '2003-10-30'), ('6.3', '', '2003-03-01'),
    ],
    "redis": [
        ('8.10', '', False), ('8.8', '', False), ('8.6', '', False),
        ('8.4', '', False), ('8.2', '', '2030-09-01'), ('8.0', '', '2026-12-01'),
        ('7.4', '', '2029-12-01'), ('7.2', '', '2029-12-01'), ('7.0', '', '2024-07-29'),
        ('6.2', '', '2027-04-01'), ('6.0', '', '2022-05-31'), ('5.0', '', '2022-04-27'),
    ],
    "rhel": [
        ('10', '', '2035-05-31'), ('9', '', '2032-05-31'), ('8', '', '2029-05-31'),
        ('7', '', '2024-06-30'), ('6', '', '2020-11-30'), ('5', '', '2017-03-31'),
        ('4', '', '2012-02-29'),
    ],
    "rocky-linux": [
        ('10', '', '2035-05-31'), ('9', '', '2032-05-31'), ('8', '', '2029-05-31'),
    ],
    "sles": [
        ('16.0', '', '2027-11-30'), ('15.7', '', '2031-07-31'), ('15.6', '', '2025-12-31'),
        ('15.5', '', '2024-12-31'), ('15.4', '', '2023-12-31'), ('15.3', '', '2022-12-31'),
        ('15.2', '', '2021-12-31'), ('12.5', '', '2024-10-31'), ('15.1', '', '2021-01-31'),
        ('12.4', '', '2020-06-30'), ('15.0', '', '2019-12-31'), ('12.3', '', '2019-06-30'),
        ('12.2', '', '2018-03-31'), ('12.1', '', '2017-05-31'), ('11.4', '', '2019-03-31'),
        ('12.0', '', '2016-06-30'), ('11.3', '', '2016-01-31'), ('11.2', '', '2014-01-31'),
        ('10.4', '', '2013-07-31'), ('11.1', '', '2012-08-31'), ('10.3', '', '2011-10-11'),
        ('11.0', '', '2010-12-31'), ('10.2', '', '2010-04-11'), ('10.1', '', '2008-11-30'),
        ('10.0', '', '2007-12-31'),
    ],
    "solaris": [
        ('11.4', '', '2031-11-01'), ('11.3', '', '2021-01-01'), ('11.2', '', True),
        ('11.1', '', True), ('11', '', True), ('10', '', '2018-01-01'),
        ('9', '', '2011-10-01'), ('8', '', '2009-03-01'),
    ],
    "tomcat": [
        ('11.0', '', False), ('10.1', '', False), ('10.0', '', '2022-10-31'),
        ('9.0', '', '2027-03-31'), ('8.5', '', '2024-03-31'), ('8.0', '', '2018-06-30'),
        ('7', '', '2021-03-31'), ('6', '', '2016-12-31'), ('5', '', '2012-09-30'),
    ],
    "ubuntu": [
        ('26.04', '', '2031-05-29'), ('25.10', '', '2026-07-01'), ('25.04', '', '2026-01-17'),
        ('24.10', '', '2025-07-10'), ('24.04', '', '2029-05-31'), ('23.10', '', '2024-07-12'),
        ('23.04', '', '2024-01-20'), ('22.10', '', '2023-07-20'), ('22.04', '', '2027-06-01'),
        ('21.10', '', '2022-07-14'), ('21.04', '', '2022-01-20'), ('20.10', '', '2021-07-22'),
        ('20.04', '', '2025-05-31'), ('19.10', '', '2020-07-06'), ('19.04', '', '2020-01-23'),
        ('18.10', '', '2019-07-18'), ('18.04', '', '2023-05-31'), ('17.10', '', '2018-07-19'),
        ('17.04', '', '2018-01-13'), ('16.10', '', '2017-07-20'), ('16.04', '', '2021-04-02'),
        ('15.10', '', '2016-07-28'), ('15.04', '', '2016-02-04'), ('14.10', '', '2015-07-23'),
        ('14.04', '', '2019-04-02'), ('13.10', '', '2014-07-17'), ('13.04', '', '2014-01-27'),
        ('12.10', '', '2014-05-16'), ('12.04', '', '2017-04-28'), ('11.10', '', '2013-05-09'),
        ('11.04', '', '2012-10-28'), ('10.10', '', '2012-04-10'), ('10.04', '', '2013-05-09'),
        ('9.10', '', '2011-04-30'), ('9.04', '', '2010-10-23'), ('8.10', '', '2010-04-30'),
        ('8.04', '', '2013-05-09'), ('7.10', '', '2009-04-18'), ('7.04', '', '2008-10-19'),
        ('6.10', '', '2008-04-26'), ('6.06', '', '2011-06-01'), ('5.10', '', '2007-04-13'),
        ('5.04', '', '2006-10-31'), ('4.10', '', '2006-04-30'),
    ],
    "windows-server": [
        ('2025', '', '2034-11-14'), ('23h2-ac', 'Windows Server 23H2 AC', '2026-05-12'), ('2022', '', '2031-10-14'),
        ('20h2-sac', 'Windows Server 20H2 SAC', '2022-08-09'), ('2004-sac', 'Windows Server 2004 SAC', '2021-12-14'), ('1909-sac', 'Windows Server 1909 SAC', '2021-05-11'),
        ('1903-sac', 'Windows Server 1903 SAC', '2020-12-08'), ('1809-sac', 'Windows Server 1809 SAC', '2020-11-10'), ('2019', '', '2029-01-09'),
        ('1803-sac', 'Windows Server 1803 SAC', '2019-11-12'), ('1709-sac', 'Windows Server 1709 SAC', '2019-04-09'), ('2016', '', '2027-01-12'),
        ('2012-r2', 'Windows Server 2012 R2', '2023-10-10'), ('2012', '', '2023-10-10'), ('2008-r2-sp1', 'Windows Server 2008 R2 SP1', '2020-01-14'),
        ('2008-sp2', 'Windows Server 2008 SP2', '2020-01-14'), ('2003-sp2', 'Windows Server 2003 SP2', '2015-07-14'), ('2003-sp1', 'Windows Server 2003 SP1', '2009-04-14'),
        ('2003', '', '2007-04-10'), ('2000', '', '2010-07-13'),
    ],
}


# ================================================================
# CLI
# ================================================================
if __name__ == "__main__":
    args = [a for a in sys.argv[1:] if a != "--no-api"]
    use_api = "--no-api" not in sys.argv
    if len(args) < 2:
        print("사용법: python eos_checker.py [--no-api] <제품> <버전>")
        print("  예) mysql 8.0.46 / postgresql 13.22 / amazon-linux 2 / rhel 7.9 / mssql 2016 / tomcat 9.0.85 / windows-server 2012r2")
        print("=" * 70)
        print(f"  EoS 현황 (판정 기준일 {CHECK_DATE}, 내장 데이터 {DATA_DATE}) - 최근 종료·임박 주기")
        print("=" * 70)
        rows = []
        for slug, lst in EOL_SNAPSHOT.items():
            for cyc, lab, eol in lst:
                if isinstance(eol, str):
                    d = datetime.date.fromisoformat(eol[:10])
                    if datetime.date(2024, 1, 1) <= d <= CHECK_DATE + datetime.timedelta(days=365):
                        rows.append((d, slug, lab or cyc))
        for d, slug, c in sorted(rows, reverse=True):
            flag = "종료" if d < CHECK_DATE else "예정"
            print(f"  [{flag}] {slug:20} {c:28} {d}")
        sys.exit(0)
    r, e, d = check_eos(args[0], args[1], use_api)
    print(f"제품:   {args[0]} {args[1]}")
    print(f"결과:   {r}")
    print(f"EoS:    {e or 'N/A'}")
    print(f"설명:   {d}")
__VC_EOF_5__

SUMMARY="$OUT/summary.txt"
say() { echo "$*" >&2; echo "$*" >> "$SUMMARY"; }

# 결과 파일의 '# 증적 파일:' 경로를 결과 옆으로 옮김 (<결과이름>_evidence.txt → 컨버터가 자동 매칭)
collect_evidence() {   # collect_evidence <결과파일> <기본 증적 경로>
    local res="$1" evd
    evd=$(grep -E '^# (증적 파일:|\[경고\] 기본 증적 파일에 쓸 수 없어 대체 경로 사용:)' "$res" 2>/dev/null | tail -1 | sed 's/^.*:[[:space:]]*//')
    [ -n "$evd" ] && [ -f "$evd" ] || evd="$2"
    # 이번 점검 중 기록된 파일만 (다른 사용자·이전 실행의 증적을 가져오지 않도록)
    [ -f "$evd" ] && [ -n "$(find "$evd" -newer "$WORK/.start" 2>/dev/null)" ] && mv -f "$evd" "${res%.txt}_evidence.txt" 2>/dev/null
}
count() { grep -c "|$2|" "$1" 2>/dev/null; }
report() {
    local f="$1" label="$2"
    say "  - ${label}: $(basename "$f")  (양호 $(count "$f" 양호) / 취약 $(count "$f" 취약) / 수동확인 $(count "$f" 수동확인) / N-A $(count "$f" N-A))"
}
run() {   # run <라벨> <결과파일> <기본 증적 경로> <스크립트> [인자...]
    local label="$1" res="$2" evd="$3"; shift 3
    echo "" >&2; echo "▶ ${label} 점검 중..." >&2
    : > "$WORK/.start"
    NO_RESULT_COPY=1 bash "$@" > "$res"
    collect_evidence "$res" "$evd"
    report "$res" "$label"
}

_procs() { { ps -e -o comm= 2>/dev/null || cat /proc/[0-9]*/comm 2>/dev/null; } | sed 's#.*/##'; }
_args()  { ps -eo args= 2>/dev/null || ps -ef 2>/dev/null; }

# ── OS ─────────────────────────────────────────────────────────
OS_NAME=$(uname -s 2>/dev/null)
OS_DETAIL=$( ( [ -r /etc/os-release ] && . /etc/os-release 2>/dev/null && echo "${PRETTY_NAME:-$NAME $VERSION_ID}" ) || ( command -v oslevel >/dev/null 2>&1 && echo "AIX $(oslevel -s 2>/dev/null)" ) || ( [ -r /etc/release ] && head -1 /etc/release | sed 's/^ *//' ) || uname -sr 2>/dev/null)
: > "$SUMMARY"
say "================================================================"
say " 통합 자동 점검 — ${HN}"
say "   OS     : ${OS_DETAIL:-$OS_NAME}"
say "   기준   : $(case $_MODE in ef) echo 전자금융기반시설;; mi) echo '주요정보통신기반시설 (2026 상세가이드)';; *) echo '전자금융 + 주요정보';; esac)"
say "   일시   : $(date '+%Y-%m-%d %H:%M:%S')"
say "================================================================"

# ── 웹서버 / WAS 탐지 ──────────────────────────────────────────
WEB_FOUND=""
_p=$(_procs)
echo "$_p" | grep -qE '^(httpd|apache2|httpd\.worker|httpd-prefork)$' && WEB_FOUND="$WEB_FOUND Apache"
echo "$_p" | grep -qE '^nginx$' && WEB_FOUND="$WEB_FOUND Nginx"
echo "$_p" | grep -qE '^(wsm|htl|hth|htmls)$' && WEB_FOUND="$WEB_FOUND WebtoB"
_a=$(_args)
echo "$_a" | grep -q 'org.apache.catalina' && WEB_FOUND="$WEB_FOUND Tomcat"
echo "$_a" | grep -q 'jeus.home' && WEB_FOUND="$WEB_FOUND JEUS"
if [ -z "$WEB_FOUND" ]; then   # 프로세스가 없어도 설치돼 있으면 점검 (중지 상태 서버)
    for f in /etc/httpd/conf/httpd.conf /etc/apache2/apache2.conf /usr/local/apache*/conf/httpd.conf /opt/apache*/conf/httpd.conf; do
        [ -f "$f" ] && WEB_FOUND=" Apache(설치)" && break
    done
    [ -f /etc/nginx/nginx.conf ] && WEB_FOUND="$WEB_FOUND Nginx(설치)"
    [ -n "$CATALINA_HOME" ] && WEB_FOUND="$WEB_FOUND Tomcat(설치)"
    [ -n "$JEUS_HOME" ] && WEB_FOUND="$WEB_FOUND JEUS(설치)"
    [ -n "$WEBTOBDIR" ] && WEB_FOUND="$WEB_FOUND WebtoB(설치)"
fi
case "$(echo "$WEBWAS" | tr 'A-Z' 'a-z')" in
yes|y|1) [ -z "$WEB_FOUND" ] && WEB_FOUND=" (WEBWAS=yes 지정)" ;;
no|n|0)  WEB_FOUND="" ;;
esac

# ── DBMS 탐지 (실행 중인 DB 프로세스 기준, 여러 개면 모두) ──────
if [ -n "$DBMS_TYPES" ]; then
    DB_FOUND="$DBMS_TYPES"
else
    DB_FOUND=""
    echo "$_p" | grep -qE '^ora_pmon_' && DB_FOUND="$DB_FOUND oracle"
    echo "$_p" | grep -qE '^tbsvr' && DB_FOUND="$DB_FOUND tibero"
    echo "$_p" | grep -qE '^(mysqld|mariadbd)$' && DB_FOUND="$DB_FOUND mysql"
    echo "$_p" | grep -qE '^(postgres|postmaster)$' && DB_FOUND="$DB_FOUND pgsql"
    echo "$_p" | grep -qE '^sqlservr$' && DB_FOUND="$DB_FOUND mssql"
fi

say ""
say "[탐지 결과]"
say "  웹서버/WAS :${WEB_FOUND:- 없음 → 생략}"
say "  DBMS       :${DB_FOUND:- 없음 → 생략}"
say ""
say "[결과 파일]"

# ── 1. 서버 (항상) ─────────────────────────────────────────────
mkdir -p "$OUT/server/output"
[ "$_MODE" != "mi" ] && run "서버 (전자금융 SRV)" "$OUT/server/output/${HN}_server.txt" "/tmp/${HN}_server_evidence.txt" "$WORK/check_server.sh" srv
[ "$_MODE" != "ef" ] && run "서버 (주요정보 U)"   "$OUT/server/output/${HN}_u.txt"      "/tmp/${HN}_u_evidence.txt" "$WORK/check_server_u.sh"

# ── 2. 웹서버 / WAS ────────────────────────────────────────────
if [ -n "$WEB_FOUND" ]; then
    mkdir -p "$OUT/webwas/output"
    run "웹서버/WAS" "$OUT/webwas/output/${HN}_webwas.txt" "/tmp/${HN}_webwas_evidence.txt" "$WORK/check_webwas.sh" "$_MODE"
fi

# ── 3. DBMS (탐지된 종류별로 각각) ─────────────────────────────
for t in $DB_FOUND; do
    mkdir -p "$OUT/dbms/output"
    DBMS_TYPE="$t" run "DBMS ($t)" "$OUT/dbms/output/${HN}_${t}.txt" "/tmp/${HN}_dbms_evidence.txt" "$WORK/check_dbms.sh" "$_MODE"
done

# ── 압축 ───────────────────────────────────────────────────────
_dirs=$(cd "$OUT" && ls -d server webwas dbms 2>/dev/null | tr '\n' ' ')
ARC=""
if command -v gzip >/dev/null 2>&1; then
    ( cd "$OUT" && tar cf - $_dirs summary.txt ) | gzip -c > "$BASE/$PKG.tar.gz" && ARC="$BASE/$PKG.tar.gz"
else
    ( cd "$OUT" && tar cf "$BASE/$PKG.tar" $_dirs summary.txt ) && ARC="$BASE/$PKG.tar"
fi
[ -n "$ARC" ] && chmod 600 "$ARC" 2>/dev/null

say ""
say "================================================================"
say " 완료"
say "   결과 폴더 : $OUT"
[ -n "$ARC" ] && say "   압축 파일 : $ARC   ← 이 파일 하나만 회수하세요"
say "   점검자 PC : converter/ 폴더에서 압축을 풀면 분야별 output/ 에 바로 들어갑니다"
say "================================================================"
exit 0
