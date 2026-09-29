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
        chmod 600 "$_MYSQL_CNF" 2>/dev/null
        printf '[client]\nuser=%s\n%s\n' "$MYSQL_USER" "${MYSQL_PASS:+password=$MYSQL_PASS}" > "$_MYSQL_CNF"
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
