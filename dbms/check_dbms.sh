#!/bin/bash
# ================================================================
# DBMS(Unix/Linux) 보안 취약점 자동 점검 스크립트 v5.0
# ================================================================
#
# [용도]
#   전자금융기반시설·주요정보통신기반시설 데이터베이스 보안 점검.
#   기준: 전자금융기반시설 보안 취약점 평가기준 제2026-1호 [데이터베이스]
#   Windows MSSQL은 check_dbms_mssql.ps1, Linux MSSQL은 이 스크립트 사용.
#
# [대상 DBMS]
#   Oracle 10g~21c / MySQL 5.6~8.4 / MariaDB 10.x / PostgreSQL 10~17 / Tibero 5~7
#   MSSQL(Linux) — SQL Server 2017~2022 on Linux (sqlcmd 기반)
#   관리형 DB — AWS RDS / Aurora (MySQL·MariaDB·PostgreSQL·Oracle·MSSQL), Azure SQL·Azure DB for MySQL/PostgreSQL
#   (DBMS가 없으면 자동 탐지 후 미설치 안내)
#
# [사전 조건]
#   - 설치형 DB 를 로컬에서 점검할 때는 root 권한 필요 (sudo bash 또는 root 로그인)
#   - DBMS 접속 계정·비밀번호는 실행 중 입력 (터미널 실행 시 '[DBMS] DB 접속 계정' → '비밀번호(숨김)' 순으로 질문,
#     Enter = 기본 계정/OS 인증). 아래 환경변수로 미리 지정한 값은 묻지 않음 (자동 실행·터미널 아님 → 환경변수만 사용)
#
# [접속 정보 환경변수]
#   Oracle:  ORACLE_USER  ORACLE_PASS  ORACLE_SID  ORACLE_SERVICE  ORACLE_HOST  ORACLE_PORT
#            (ORACLE_PASS 미지정 시 '/ as sysdba' OS 인증 — root 실행이면 ora_pmon 구동 계정으로 실행. 원격 접속은 비밀번호 필요)
#   MySQL:   MYSQL_USER   MYSQL_PASS   MYSQL_HOST  MYSQL_PORT  MYSQL_SOCKET  MYSQL_EXTRA_OPTS(예: --ssl-ca=rds-ca.pem)
#            (MYSQL_PASS 미지정 시 소켓/OS 인증·~/.my.cnf 시도 → 대화형이면 숨김 입력)
#   PgSQL:   PGSQL_USER   PGSQL_DB     PGSQL_HOST  PGSQL_PORT  (PGPASSWORD/.pgpass 없으면 소켓+peer → localhost 순)
#   Tibero:  TIBERO_USER  TIBERO_PASS  TIBERO_DB(tbdsn 별칭)  TIBERO_HOST(원격 대상 호스트 — 대상 식별·원격 판별용, 선택)
#   MSSQL:   MSSQL_USER   MSSQL_PASS   MSSQL_SERVER MSSQL_PORT (기본: sa/미지정(대화형이면 숨김 입력)/localhost/1433)
#   ※ 비밀번호는 환경변수 또는 실행 중 숨김 입력으로만 전달 (명령 인자에 남기지 않음 — sqlplus/tbsql 은 표준입력, mysql 은 600 임시 파일,
#     psql 은 PGPASSWORD, sqlcmd 는 SQLCMDPASSWORD)
#
# [관리형 DB(RDS·Aurora·Azure) / 원격 실행]
#   DBMS_ENV=rds|aurora|azure  — 관리형 지정 (미지정이어도 접속 호스트가 *.rds.amazonaws.com, *.cluster-*, *.database.windows.net,
#                                *.database.azure.com 이면 자동 탐지). 설치형이면 DBMS_ENV=onprem
#   DBMS_REMOTE=1|0            — 접속 대상이 실행 호스트와 다른 서버임을 강제 지정(1) / 로컬로 강제(0). SSH 터널(127.0.0.1:포트)로 접속하면 1 지정
#   관리형: 운영체제(파일·프로세스·umask·로컬 방화벽) 항목은 N-A(관리형 DB - 운영체제 접근 불가, 파라미터 그룹·콘솔 설정으로 확인) 로 내고,
#           DB 안에서 조회되는 관리형 전용 통제(require_secure_transport, rds.force_ssl, 감사 플러그인/pgaudit, 통합 감사 등)로 판정.
#           rdsadmin·rdsrepladmin·rds_superuser 등 관리형 예약 계정은 계정 점검에서 제외하고 근거에 표시.
#   원격(설치형): 로컬 파일·프로세스·방화벽 항목은 실행 호스트 기준으로 판정하지 않고 '점검불가'. 대상 서버에서 직접 실행 필요.
#
# [실행 방법]
#   DBMS_TYPE=oracle  bash check_dbms.sh [ef|mi|all]
#   DBMS_TYPE=mysql   bash check_dbms.sh [ef|mi|all]
#   DBMS_TYPE=pgsql | tibero | mssql ... (DBMS_TYPE 생략 시 설치된 DBMS 자동 탐지)
#
# [산출물]
#   1) 표준출력 — 파이프 구분자 결과 (파일로 리다이렉트하지 않아도 아래 /tmp 에 사본 저장)
#      형식: 항목코드|결과|근거설명
#      결과: 양호 / 취약 / 수동확인 / 점검불가 / N-A
#        점검불가 = 쿼리 오류·권한 부족·접속 끊김·명령 없음 등으로 점검 자체를 못 한 경우 (오류 원문은 증적)
#   2) 결과 사본 — /tmp/<실행호스트>_<dbms>_<대상>_dbms.txt            (영숫자·점·하이픈만)
#      증적 파일 — /tmp/<실행호스트>_<dbms>_<대상>_dbms_evidence.txt
#      점검 중 실행한 SQL(전문)·열 이름·결과 행 전체·오류 원문·판정 근거가 타임스탬프와 함께 기록됨
#
# ================================================================

umask 077

# ── 임시 디렉터리 (600/700, 예측 불가 이름) ─────────────────────
_TMPD=""
_mk_tmpd() {
    local d i
    d=$(mktemp -d "${TMPDIR:-/tmp}/.dbm_check_XXXXXX" 2>/dev/null) && [ -d "$d" ] && { _TMPD="$d"; return 0; }
    for i in 1 2 3 4 5; do
        d="${TMPDIR:-/tmp}/.dbm_check_$$_${RANDOM}${RANDOM}"
        mkdir -m 700 "$d" 2>/dev/null && { _TMPD="$d"; return 0; }
    done
    return 1
}
_mk_tmpd || { echo "[오류] 임시 디렉터리를 만들 수 없어 중단합니다 (TMPDIR 확인)" >&2; exit 1; }
_cleanup() { [ -n "$_TMPD" ] && [ -d "$_TMPD" ] && rm -rf "$_TMPD"; }
trap _cleanup EXIT
_QERRF="$_TMPD/qerr"; : > "$_QERRF"

# bash 3.x(AIX·HP-UX·Solaris) 호환: 대소문자 변환은 tr, 연관 배열은 변수 이름 규칙으로 대체
_up()  { printf '%s' "$1" | tr 'a-z' 'A-Z'; }
_low() { printf '%s' "$1" | tr 'A-Z' 'a-z'; }
_kvn() { printf '_KV_%s_%s' "$1" "$(printf '%s' "$2" | tr -c 'A-Za-z0-9\n' '_')"; }
_kv_set() { eval "$(_kvn "$1" "$2")=\$3"; }
_kv_get() { eval "printf '%s' \"\${$(_kvn "$1" "$2"):-}\""; }

# ── DBMS 자동 탐지 ──────────────────────────────────────────────
_proc_has() { { ps -e -o comm= 2>/dev/null || cat /proc/[0-9]*/comm 2>/dev/null; } | sed 's#.*/##' | grep -qE "^($1)\$"; }
detect_dbms() {
    [ -n "$DBMS_TYPE" ] && return
    # 접속 대상이 원격(호스트 지정)이면 클라이언트 도구 기준으로 판별
    [ -n "$ORACLE_HOST" ] && DBMS_TYPE="oracle" && return
    [ -n "$MYSQL_HOST" ] && [ "$MYSQL_HOST" != "localhost" ] && DBMS_TYPE="mysql" && return
    [ -n "$PGSQL_HOST" ] && DBMS_TYPE="pgsql" && return
    [ -n "$MSSQL_SERVER" ] && [ "$MSSQL_SERVER" != "localhost" ] && DBMS_TYPE="mssql" && return
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
        [ -n "$f" ] && [ -e "$f" ] || continue
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

# ── 프로세스 조회 (comm 정확 일치 — mysqld_exporter 등 유사 이름 제외) ──
_ps_ucp() { UNIX95=1 ps -eo user=,pid=,comm= 2>/dev/null; }   # HP-UX 는 UNIX95=1 이어야 -o 지원
_proc_users() {   # $1=comm 정규식 → 구동 계정(고유, 공백 구분)
    _ps_ucp | awk -v re="^($1)\$" '{n=$3; sub(/.*\//,"",n); if (n ~ re) print $1}' | sort -u | tr '\n' ' ' | sed 's/ $//'
}

HN=$(hostname 2>/dev/null || uname -n)
_san() { printf '%s' "$1" | tr -c 'A-Za-z0-9.\n-' '_' | sed 's/__*/_/g; s/^_//; s/_$//'; }

# ── 실행 호스트 메타데이터 (IP / 실행 계정 / 클라우드) ───────────
_local_ips() {   # 루프백 제외 IPv4 전부 (중복 제거)
    { ip -o -4 addr show 2>/dev/null | awk '{print $4}' | sed 's#/.*##'
      ifconfig -a 2>/dev/null | sed -n 's/.*inet \(addr:\)\{0,1\}\([0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\).*/\2/p'
      hostname -I 2>/dev/null | tr ' ' '\n'
      [ -r /proc/net/fib_trie ] && awk '$1=="|--"{ip=$2} /\/32 host LOCAL/{print ip}' /proc/net/fib_trie 2>/dev/null   # ip·ifconfig·hostname 이 없는 최소 Linux
    } | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | grep -v '^127\.' | awk '!s[$0]++'
}
_ip_header() { local l; l=$(_local_ips | tr '\n' ',' | sed 's/,$//; s/,/, /g'); echo "${l:-미확인}"; }
_acct_header() {
    if [ "$(id -u 2>/dev/null)" = 0 ]; then echo "root"; else echo "$(id -un 2>/dev/null || echo unknown) (관리자 아님 - 일부 항목 점검불가)"; fi
}
_http() {   # _http [-X PUT] URL [헤더...]  (타임아웃 2초)
    local method="" url h
    if [ "$1" = "-X" ]; then method="$2"; shift 2; fi
    url="$1"; shift
    if command -v curl >/dev/null 2>&1; then
        local a=(-s -m 2 --connect-timeout 1); [ -n "$method" ] && a+=(-X "$method")
        for h in "$@"; do a+=(-H "$h"); done
        curl "${a[@]}" "$url" 2>/dev/null
    elif command -v wget >/dev/null 2>&1; then
        local b=(-q -T 2 -t 1 -O -); [ -n "$method" ] && b+=(--method="$method")
        for h in "$@"; do b+=(--header="$h"); done
        wget "${b[@]}" "$url" 2>/dev/null
    else
        return 99
    fi
}
_cloud_header() {
    local base="http://169.254.169.254" tok id reg sg="" macs m j vm loc rg nm zone
    if ! command -v curl >/dev/null 2>&1 && ! command -v wget >/dev/null 2>&1; then echo "미확인"; return; fi
    # AWS (IMDSv2 토큰 → 실패 시 v1)
    tok=$(_http -X PUT "$base/latest/api/token" "X-aws-ec2-metadata-token-ttl-seconds: 60")
    if [ -n "$tok" ]; then id=$(_http "$base/latest/meta-data/instance-id" "X-aws-ec2-metadata-token: $tok"); else id=$(_http "$base/latest/meta-data/instance-id"); fi
    if printf '%s' "$id" | grep -qE '^i-[0-9a-f]+$'; then
        if [ -n "$tok" ]; then
            reg=$(_http "$base/latest/meta-data/placement/region" "X-aws-ec2-metadata-token: $tok")
            macs=$(_http "$base/latest/meta-data/network/interfaces/macs/" "X-aws-ec2-metadata-token: $tok")
            for m in $macs; do sg="${sg}$(_http "${base}/latest/meta-data/network/interfaces/macs/${m}security-group-ids" "X-aws-ec2-metadata-token: $tok" | tr '\n' ',')"; done
        else
            reg=$(_http "$base/latest/meta-data/placement/region")
            macs=$(_http "$base/latest/meta-data/network/interfaces/macs/")
            for m in $macs; do sg="${sg}$(_http "${base}/latest/meta-data/network/interfaces/macs/${m}security-group-ids" | tr '\n' ',')"; done
        fi
        sg=$(printf '%s' "$sg" | sed 's/,,*/,/g; s/,$//; s/^,//')
        echo "AWS (instance ${id}, region ${reg:-미확인}, SG: ${sg:-미확인})"; return
    fi
    # Azure
    j=$(_http "$base/metadata/instance?api-version=2021-02-01" "Metadata:true")
    if printf '%s' "$j" | grep -q '"vmId"'; then
        vm=$(printf '%s' "$j" | sed -n 's/.*"vmId"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -1)
        nm=$(printf '%s' "$j" | sed -n 's/.*"name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -1)
        loc=$(printf '%s' "$j" | sed -n 's/.*"location"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -1)
        rg=$(printf '%s' "$j" | sed -n 's/.*"resourceGroupName"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -1)
        echo "Azure (vm ${nm:-$vm}, region ${loc:-미확인}, resource group: ${rg:-미확인})"; return
    fi
    # GCP
    id=$(_http "$base/computeMetadata/v1/instance/id" "Metadata-Flavor: Google")
    if printf '%s' "$id" | grep -qE '^[0-9]+$'; then
        nm=$(_http "$base/computeMetadata/v1/instance/name" "Metadata-Flavor: Google")
        zone=$(_http "$base/computeMetadata/v1/instance/zone" "Metadata-Flavor: Google" | sed 's#.*/##')
        echo "GCP (instance ${nm:-$id}, zone ${zone:-미확인})"; return
    fi
    echo "없음"
}

# ── 접속 대상 판별: 로컬/원격, 관리형(RDS·Aurora·Azure) ──────────
_is_local_host() {   # $1=호스트 → 이 실행 호스트 자신이면 0
    local h; h=$(_low "$1")
    case "$h" in ""|localhost|127.*|::1|"[::1]") return 0 ;; esac
    [ "$h" = "$(_low "$HN")" ] && return 0
    [ "$h" = "$(_low "$(hostname -s 2>/dev/null)")" ] && return 0
    _local_ips | grep -qxF "$h" && return 0
    local r; r=$(getent hosts "$1" 2>/dev/null | awk '{print $1; exit}')
    [ -n "$r" ] && { case "$r" in 127.*|::1) return 0 ;; esac; _local_ips | grep -qxF "$r" && return 0; }
    return 1
}
_T_HOST=""; _T_PORT=""; _T_SVC=""; _T_ID=""; _REMOTE=0; _MANAGED=""; _MANAGED_LABEL=""
_tb_alias_host() {   # tbdsn.tbr 에서 별칭의 HOST/PORT 추출 → "host port"
    local f d al="$1"
    for d in "${TB_HOME:-/nonexistent}/client/config" "${TB_HOME:-/nonexistent}/config" "${TB_CONFIG:-/nonexistent}"; do
        f="$d/tbdsn.tbr"; [ -r "$f" ] || continue
        tr -d '\n\r\t ' < "$f" | sed 's/)\([A-Za-z0-9_.-]*=(\)/)\n\1/g' | awk -F= -v a="$al" 'tolower($1)==tolower(a){print; exit}' | \
            sed -n 's/.*(HOST=\([^)]*\)).*(PORT=\([0-9]*\)).*/\1 \2/p'
        return
    done
}
_detect_target() {
    local h="" p="" s="" kind k
    case "$DBMS_TYPE" in
    oracle)  h="${ORACLE_HOST:-}"; p="${ORACLE_PORT:-1521}"; s="${ORACLE_SERVICE:-${ORACLE_SID:-}}" ;;
    mysql|mariadb) h="${MYSQL_HOST:-}"; p="${MYSQL_PORT:-3306}"; [ -n "$MYSQL_SOCKET" ] && h="" ;;
    pgsql|postgresql) h="${PGSQL_HOST:-}"; p="${PGSQL_PORT:-5432}"; s="${PGSQL_DB:-postgres}" ;;
    mssql|sqlserver) h="${MSSQL_SERVER:-localhost}"; p="${MSSQL_PORT:-1433}"; h="${h#tcp:}" ;;
    tibero)
        h="${TIBERO_HOST:-}"; p="${TIBERO_PORT:-8629}"; s="${TIBERO_DB:-}"
        if [ -z "$h" ] && [ -n "$s" ]; then k=$(_tb_alias_host "$s"); [ -n "$k" ] && { h=${k% *}; p=${k#* }; }; fi ;;
    esac
    _T_HOST="$h"; _T_PORT="$p"; _T_SVC="$s"
    # 로컬/원격
    if [ "$DBMS_REMOTE" = "1" ]; then _REMOTE=1
    elif [ "$DBMS_REMOTE" = "0" ]; then _REMOTE=0
    elif [ -n "$h" ] && ! _is_local_host "$h"; then _REMOTE=1
    else _REMOTE=0; fi
    # 관리형: DBMS_ENV 지정 우선, 없으면 엔드포인트 패턴
    kind=$(_low "${DBMS_ENV:-}")
    case "$kind" in rds|aurora|azure) ;; onprem|installed|none|local|"") [ -z "$kind" ] && kind="" || kind="installed" ;; *) kind="" ;; esac
    if [ -z "$kind" ]; then
        k=$(_low "$h")
        case "$k" in
        *.cluster-*) kind=aurora ;;
        *.rds.amazonaws.com|*.rds.amazonaws.com.cn|*.rds.*.amazonaws.com*) kind=rds ;;
        *.database.windows.net|*.database.azure.com|*.database.chinacloudapi.cn|*.database.usgovcloudapi.net) kind=azure ;;
        esac
    fi
    [ "$kind" = "installed" ] && kind=""
    if [ -n "$kind" ]; then
        _REMOTE=1
        _MANAGED="$kind"
        case "$DBMS_TYPE:$kind" in
        mysql:rds) _MANAGED_LABEL="RDS-MySQL" ;;       mariadb:rds) _MANAGED_LABEL="RDS-MariaDB" ;;
        mysql:aurora|mariadb:aurora) _MANAGED_LABEL="Aurora-MySQL" ;;
        pgsql:rds|postgresql:rds) _MANAGED_LABEL="RDS-PgSQL" ;;
        pgsql:aurora|postgresql:aurora) _MANAGED_LABEL="Aurora-PgSQL" ;;
        oracle:rds|oracle:aurora) _MANAGED_LABEL="RDS-Oracle" ;;
        mssql:rds|mssql:aurora|sqlserver:rds) _MANAGED_LABEL="RDS-MSSQL" ;;
        mssql:azure|sqlserver:azure) _MANAGED_LABEL="Azure-SQL" ;;
        mysql:azure|mariadb:azure) _MANAGED_LABEL="Azure-MySQL" ;;
        pgsql:azure|postgresql:azure) _MANAGED_LABEL="Azure-PgSQL" ;;
        *) _MANAGED_LABEL="${kind}-${DBMS_TYPE}" ;;
        esac
    fi
    # 대상 식별자 (헤더 '# 점검 대상')
    if [ "$_REMOTE" = 1 ] && [ -n "$h" ]; then
        _T_ID="${h}:${p}${s:+/$s}"
    elif [ "$_REMOTE" = 1 ]; then
        _T_ID="${DBMS_ENV:-원격}(엔드포인트 미지정)"
    else
        _T_ID="$HN"
    fi
}
_detect_target
_TFILE_ID="local"; [ "$_REMOTE" = 1 ] && _TFILE_ID=$(_san "${_T_HOST:-remote}_${_T_PORT}${_T_SVC:+_$_T_SVC}")
_FBASE="${HN:+$(_san "$HN")}_$(_san "$DBMS_TYPE")_${_TFILE_ID}"

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
case "$(_low "$_KMODE")" in
1|ef|srv) _KMODE="ef" ;;
2|mi|kisa|u) _KMODE="mi" ;;
3|all) _KMODE="all" ;;
*) echo "사용법: $0 [ef|mi|all]  (ef=전자금융, mi=주요정보 2026 상세가이드, all=둘 다)" >&2; exit 1 ;;
esac

# ── DB 접속 계정·비밀번호 입력 (터미널 실행 시) ──────────────────
# $1=표시명 $2=계정 변수명 $3=비밀번호 변수명 $4=계정 Enter 시 동작 $5=비밀번호 Enter 시 동작 $6=1 이면 계정 Enter 시 비밀번호 질문 생략(OS 인증)
# 환경변수로 이미 지정한 계정·비밀번호는 묻지 않음. 비밀번호는 숨김 입력, 화면·결과·증적에 남기지 않음. 터미널이 아니면(자동 실행) 묻지 않음.
_CRED_ASKED=""
_ask_cred() {
    local _u="" _p=""
    [ -t 0 ] || return 0
    _CRED_ASKED=1
    if [ -z "${!2}" ]; then
        read -r -p "[$1] DB 접속 계정 (Enter=$4): " _u </dev/tty
        [ -n "$_u" ] && printf -v "$2" '%s' "$_u"
        [ -z "$_u" ] && [ "$6" = 1 ] && return 0
    fi
    if [ -z "${!3}" ]; then
        read -rs -p "[$1] ${!2:+${!2} }비밀번호 (Enter=$5): " _p </dev/tty; echo >&2
        [ -n "$_p" ] && printf -v "$3" '%s' "$_p"
    fi
    return 0
}

# ── 결과 사본 / 증적 파일 (심볼릭 링크·기존 파일 방어: 지우고 O_EXCL 로 새로 생성, umask 077) ──
_new_file() {   # $1=경로 → 새 빈 파일 생성 성공 시 0
    local f="$1"
    [ -L "$f" ] && rm -f "$f"
    [ -e "$f" ] && rm -f "$f" 2>/dev/null
    ( set -C; : > "$f" ) 2>/dev/null
}
_RESF="/tmp/${_FBASE}_dbms.txt"
if [ -z "$NO_RESULT_COPY" ] && ! [ /dev/fd/1 -ef "$_RESF" ] 2>/dev/null && _new_file "$_RESF"; then
    exec > >(tee "$_RESF"); _TEEPID=$!
else
    _RESF=""
fi

if [ "$OS_FAMILY" = "WINDOWS" ]; then
    _HDRX="# [경고] Windows 환경(Git Bash)에서 실행됨 — Linux/Unix 전용 스크립트
# [경고] MSSQL 점검은 check_dbms_mssql.ps1 사용
"
else _HDRX=""; fi
_hnote() { _HDRX="${_HDRX}$1
"; }

_CP=0; _CF=0; _CM=0; _CN=0; _CX=0

_EVD="/tmp/${_FBASE}_dbms_evidence.txt"
if ! _new_file "$_EVD"; then   # 다른 사용자 소유 기존 파일 등 → 대체 경로
    _EVD=$(mktemp "${TMPDIR:-/tmp}/${_FBASE}_dbms_evidence.XXXXXX" 2>/dev/null || echo "$_TMPD/evidence.txt")
    _hnote "# [경고] 기본 증적 파일에 쓸 수 없어 대체 경로 사용: $_EVD"
fi
{ echo "# ================================================================"
  echo "# DBMS 증적 파일 (감사 추적용)"
  echo "# 점검 대상: ${_T_ID} / 실행 호스트: ${HN} / DBMS: ${DBMS_TYPE} / 환경: $( [ -n "$_MANAGED" ] && echo "관리형 (${_MANAGED_LABEL})" || { [ "$_REMOTE" = 1 ] && echo "설치형(원격 접속)" || echo "설치형(로컬)"; } ) / OS: ${OS_FAMILY}"
  echo "# 생성: $(date '+%Y-%m-%d %H:%M:%S')"
  echo "# 각 블록: [항목] 시각 SQL: <실행한 SQL 전문> → 열 이름(첫 줄)과 결과 행 전체 → 오류 시 [stderr]/오류 원문"
  echo "# ================================================================"; } > "$_EVD"

_iname() {
    case "$1" in
    DBM-001) echo '취약하게 설정된 비밀번호 제거' ;;
    DBM-003) echo '불필요하거나 관리되지 않는 계정 제거' ;;
    DBM-004) echo '불필요한 관리자 계정 제거' ;;
    DBM-005) echo '데이터베이스 내 중요정보 안전한 암호화 적용 여부' ;;
    DBM-006) echo '로그인 실패 횟수에 따른 접속 제한 설정' ;;
    DBM-007) echo '비밀번호 복잡도 설정' ;;
    DBM-008) echo '비밀번호 변경 주기 충족 여부' ;;
    DBM-009) echo '사용되지 않는 세션 종료 여부' ;;
    DBM-011) echo '감사 로그 수집 및 백업 여부' ;;
    DBM-012) echo 'Listener Control Utility(lsnrnctl) 보안 설정 여부' ;;
    DBM-013) echo '원격 접속에 대한 접근 제어 여부' ;;
    DBM-014) echo '취약한 운영체제 역할 인증 기능(OS_ROLES, REMOTE_OS_ROLES) 비활성화' ;;
    DBM-015) echo 'Public Role에 불필요한 권한 제거' ;;
    DBM-016) echo '주기적인 보안패치 및 벤더 권고사항 적용 여부' ;;
    DBM-017) echo '업무상 불필요한 시스템 테이블 접근 권한 제거' ;;
    DBM-019) echo '이전 비밀번호 재사용 요구사항 충족 여부' ;;
    DBM-020) echo '사용자별 계정 분리' ;;
    DBM-021) echo '업무상 불필요한 ODBC/OLE-DB 데이터 소스 및 드라이버 제거' ;;
    DBM-022) echo '설정 파일 및 중요정보가 포함된 파일의 접근 권한 설정 적절성' ;;
    DBM-024) echo '불필요하게 WITH GRANT OPTION 옵션이 설정된 권한 제거' ;;
    DBM-025) echo '서비스 지원이 종료된(EoS) 시스템 및 장비 교체 여부' ;;
    DBM-026) echo '데이터베이스 구동 계정의 umask 설정 적절성' ;;
    DBM-028) echo '업무상 불필요한 데이터베이스 Object 제거' ;;
    DBM-029) echo '데이터베이스의 자원 사용 제한 설정 여부' ;;
    DBM-030) echo 'Audit Table에 대한 접근 제어 설정 적절성' ;;
    DBM-031) echo 'SA 계정에 대한 보안설정 적절성' ;;
    DBM-032) echo '데이터베이스 접속 시 통신구간에 비밀번호 평문 노출 방지 여부' ;;
    DBM-033) echo 'DB 이중화 구성 시 비밀번호 평문 노출 방지 여부' ;;
    DBM-034) echo 'DBMS 서비스의 구동 권한 적절성' ;;
    DBM-035) echo 'xp_cmdshell 사용 비활성화' ;;
    DBM-036) echo 'Registry Procedure 접근 권한 설정 적절성' ;;
    esac
}

# ── 쿼리 오류 추적 ──────────────────────────────────────────────
# run_q(엄격): 오류(ORA-/ERROR/TBR-/권한 부족/접속 끊김) 시 출력 없이 오류 원문을 증적에 남기고 오류 파일에 기록 →
#              해당 항목은 _emit 에서 양호/취약/수동확인 대신 '점검불가'. 서브셸($(...))에서도 파일이라 전달됨.
# run_qo(선택): 버전별로 있을 수도 없을 수도 있는 뷰·열 조회 — 오류는 증적에만 남기고 항목을 점검불가로 만들지 않음 (출력은 비어 있음)
_ITEM="DBM-000"
_it() {   # 항목 시작: 현재 항목 지정 + 오류 기록 초기화
    case "$1" in [0-9][0-9][0-9]) _ITEM="DBM-$1" ;; *) _ITEM="$1" ;; esac
    : > "$_QERRF"
}
_qerr_add()   { printf '%s\n' "$1" >> "$_QERRF"; }
_qerr_first() { [ -s "$_QERRF" ] && sed -n '1p' "$_QERRF" | cut -c1-300; }
# 선택 조회(run_qo) 출력이 오류면 0 — 허용 오류 정규식($2: 버전 차이로 정상인 오류) 외의 오류는 항목 오류로 기록 → 점검불가
_qo_err() {
    printf '%s\n' "$1" | grep -qE '^(ERROR|FATAL)' || return 1
    { [ -n "$2" ] && printf '%s\n' "$1" | grep -qiE "$2"; } || _qerr_add "$(printf '%s\n' "$1" | grep -E '^(ERROR|FATAL)' | head -1)"
    return 0
}
_sel_cols() {   # SQL 의 최상위 SELECT 절(열 목록) 추출 — 0행이어서 열 이름 줄이 없을 때 증적에 열 정의를 남김
    local c
    c=$(printf '%s' "$1" | tr '\n\r' '  ' | awk '{s=$0; u=toupper(s); d=0; for(i=1;i<=length(s);i++){c=substr(s,i,1); if(c=="(")d++; else if(c==")")d--; else if(d==0 && substr(u,i,6)==" FROM ") {print substr(s,1,i-1); exit}}}' | sed 's/^[[:space:]]*[Ss][Ee][Ll][Ee][Cc][Tt][[:space:]]*\(DISTINCT \)\{0,1\}//')
    if [ -z "$c" ]; then   # SHOW VARIABLES/STATUS 는 SELECT 절이 없음 → 고정 열 이름
        case "$(printf '%s' "$1" | tr 'a-z' 'A-Z' | tr '\n\r' '  ' | sed 's/^[[:space:]]*//')" in
        "SHOW VARIABLES"*|"SHOW SESSION STATUS"*|"SHOW GLOBAL STATUS"*|"SHOW STATUS"*) c="Variable_name, Value" ;;
        esac
    fi
    [ -n "$c" ] && printf ' - 조회한 열: %s' "$c"
}
_qrecord() {   # $1=SQL $2=원본 출력(열 이름 포함) $3=stderr $4=종료코드 $5=선택 여부
    local _s
    _s=$(printf '%s' "$1" | tr '\n\r' '  ' | tr -s ' ')
    {
        printf '[%s] %s SQL: %s\n' "${_ITEM:-DBM-000}" "$(date '+%H:%M:%S')" "$_s"
        if [ -n "$2" ]; then printf '%s\n' "$2"
        else printf '(결과 0행%s)\n' "$(_sel_cols "$1")"; fi
        [ -n "$3" ] && printf '[오류 원문] %s\n' "$3"
        [ "$4" != "0" ] && [ -n "$4" ] && printf '[종료코드] %s\n' "$4"
        printf '\n'
    } >> "$_EVD"
}

# 판정 누적: 같은 항목에 여러 세부 점검이 있으면 가장 나쁜 결과(취약>점검불가>수동확인>양호>N-A)로 합쳐 마지막에 1회 출력
_ORDER=""
_rank() { case "$1" in 취약) echo 5;; 점검불가) echo 4;; 수동확인) echo 3;; 양호) echo 2;; *) echo 1;; esac; }
_emit() {
    local k="$1" r="$2" w="$3" cur cr cw tail qe
    case "$k" in D-*) ;; *) k="DBM-${1}" ;; esac
    w="${w//$'\n'/, }"; w="${w//|//}"   # 사유 내 줄바꿈·구분자(|)는 파이프 출력 형식을 깨므로 치환
    # 이 항목에서 쿼리 오류가 있었으면 값을 쓰지 않고 점검불가 (부분 결과가 취약이면 근거에 함께 표시)
    qe=$(_qerr_first)
    if [ -n "$qe" ] && [ "$r" = "점검불가" ]; then
        case "$w" in *"$qe"*) ;; *) w="${w} [조회 오류: ${qe}]" ;; esac
    elif [ -n "$qe" ] && [ "$r" != "N-A" ]; then
        if [ "$r" = "취약" ]; then w="조회 오류/권한 부족으로 점검 불가 - ${qe} (증적의 SQL·오류 원문 참조) [참고: 오류 이전 판정 취약 - ${w}]"
        else w="조회 오류/권한 부족으로 점검 불가 - ${qe} (증적의 SQL·오류 원문 참조)"; fi
        r="점검불가"
    fi
    # 이 항목의 증적 블록이 아직 없으면(SQL·파일 조회 없이 판정한 경우: 대상 아님·관리형·원격·버전 기준 등) 판정 근거 자체를 증적에 남김
    grep -q "^\[$k\] [0-9][0-9]:" "$_EVD" 2>/dev/null || printf '[%s] %s 판정근거(%s): 조회 없이 판정\n%s\n\n' "$k" "$(date '+%H:%M:%S')" "$r" "$w" >> "$_EVD"
    printf '[참고-세부판정] %s|%s|%s\n\n' "$k" "$r" "$w" >> "$_EVD"
    cur=$(_kv_get RES "$k")
    if [ -z "$cur" ]; then _kv_set RES "$k" "${r}|${w}"; _kv_set FIRST "$k" "$r"; _ORDER="${_ORDER} ${k}"; return; fi
    cr="${cur%%|*}"; cw="${cur#*|}"
    # 반복되는 꼬리 문구(' - …') 는 한 번만
    tail="${w##* - }"; [ "$tail" != "$w" ] && [[ "$cw" == *"$tail"* ]] && w="${w% - *}"
    # 세부 판정이 서로 다르면 각 사유에 판정 표지 부착
    if [ "$r" != "$(_kv_get FIRST "$k")" ] || [ -n "$(_kv_get MIX "$k")" ]; then
        [ -z "$(_kv_get MIX "$k")" ] && cw="[$(_kv_get FIRST "$k")] ${cw}" && _kv_set MIX "$k" 1
        w="[${r}] ${w}"
    fi
    if [ "$(_rank "$r")" -gt "$(_rank "$cr")" ]; then _kv_set RES "$k" "${r}|${w} / ${cw}"
    else _kv_set RES "$k" "${cr}|${cw} / ${w}"; fi
    return 0   # 항상 0: 'A && ok || ng' 형태에서 같은 항목이 두 번 출력되지 않게
}
_flush_results() {
    local k line _hasd=0 _nm
    case " $_ORDER" in *" D-"*) _hasd=1 ;; esac
    for k in $_ORDER; do
        case "$_KMODE:$k" in
        ef:D-*) continue ;;
        mi:DBM-*) [ "$_hasd" = 1 ] && continue ;;
        esac
        line="${k}|$(_kv_get RES "$k")"
        _nm=$(_iname "$k")
        printf '[판정] %s%s|%s\n\n' "$k" "${_nm:+ ($_nm)}" "$(_kv_get RES "$k")" >> "$_EVD"
        echo "$line"
        case "$line" in *"|양호|"*) _CP=$((_CP+1));; *"|취약|"*) _CF=$((_CF+1));; *"|수동확인|"*) _CM=$((_CM+1));; *"|점검불가|"*) _CX=$((_CX+1));; *) _CN=$((_CN+1));; esac
    done
}

# DB 접속 확인: 실패 시 빈 조회값으로 거짓 양호/취약이 나오지 않도록 전 항목 점검불가 처리 (사유=접속 오류 원문)
_DBM_CODES="001 003 004 005 006 007 008 009 011 012 013 014 015 016 017 019 020 021 022 024 025 026 028 029 030 031 032 033 034 035 036"
_conn_ok() {
    local i why
    printf '%s' "$1" | grep -q "CONN_OK" && { _DB_CONN=1; return 0; }
    why=$(_qerr_first); [ -z "$why" ] && why="응답 없음/예상 외 출력"
    _CONN_WHY="$why"   # D-항목(kisa_*)이 _it 로 오류 기록을 지운 뒤에도 사유를 쓰도록 보존
    for i in $_DBM_CODES; do nc "$i" "DB 접속 실패($2): ${why} - 접속 정보(계정/권한/호스트·방화벽·SSL) 확인 후 재점검 (증적의 접속 시도 SQL·오류 원문 참조)"; done
    _hnote "# [경고] $2 접속 실패 - 전 항목 점검불가 처리: ${why}"
    echo "# [경고] $2 접속 실패: ${why}" >&2
    return 1
}
ok()  { _emit "$1" "양호" "$2"; return 0; }
ng()  { _emit "$1" "취약" "$2"; return 0; }
na()  { _emit "$1" "N-A" "$2"; return 0; }
mc()  { _emit "$1" "수동확인" "$2"; return 0; }
nc()  { _emit "$1" "점검불가" "$2"; return 0; }

# OS 의존 항목(로컬 파일·프로세스·umask·방화벽) 게이트: 관리형 → N-A, 원격(설치형) → 점검불가. 게이트가 적용되면 0 반환(호출부는 점검을 건너뜀)
_os_gate() {   # $1=항목코드 $2=설명
    if [ -n "$_MANAGED" ]; then
        na "$1" "N-A(관리형 DB - 운영체제 접근 불가, 파라미터 그룹·콘솔 설정으로 확인) - ${2} [${_MANAGED_LABEL}]"; return 0
    elif [ "$_REMOTE" = 1 ]; then
        nc "$1" "원격 접속 대상(${_T_ID})이라 실행 호스트(${HN})의 파일·프로세스를 판정하지 않음 - 대상 서버에서 직접 실행 필요 - ${2}"; return 0
    fi
    return 1
}

evd() {   # 임의 명령 실행 결과를 증적에 (잘림 없음)
    local item="$1"; shift
    printf '[%s] %s $ %s\n' "$item" "$(date '+%H:%M:%S')" "$*" >> "$_EVD"
    eval "$@" >> "$_EVD" 2>&1
    printf '\n' >> "$_EVD"
}
evd_ls() {   # evd_ls 항목 파일... — 존재하는 파일만 ls -lL, 없으면 실행하지 않고 (대상 없음) 기록
    local item="$1" f ex="" ; shift
    for f in "$@"; do [ -n "$f" ] && [ -e "$f" ] && ex="$ex $f"; done
    if [ -n "$ex" ]; then
        printf '[%s] %s $ ls -lL%s\n' "$item" "$(date '+%H:%M:%S')" "$ex" >> "$_EVD"
        # shellcheck disable=SC2086
        ls -lL $ex >> "$_EVD" 2>&1
    else
        printf '[%s] %s (대상 없음) 점검 대상 파일이 없어 ls 를 실행하지 않음 (후보: %s)\n(대상 없음)\n' "$item" "$(date '+%H:%M:%S')" "$*" >> "$_EVD"
    fi
    printf '\n' >> "$_EVD"
}
evd_ps() {   # evd_ps 항목 comm정규식 — 해당 프로세스 구동 계정 전체 목록
    local item="$1" re="$2" out
    printf '[%s] %s $ ps -eo user=,pid=,comm=   # comm 이 ^(%s)$ 인 프로세스 전체\n' "$item" "$(date '+%H:%M:%S')" "$re" >> "$_EVD"
    out=$(_ps_ucp | awk -v re="^($re)\$" '{n=$3; sub(/.*\//,"",n); if (n ~ re) print}')
    printf 'USER PID COMM\n%s\n\n' "${out:-(해당 프로세스 없음)}" >> "$_EVD"
}
evd_file() {
    local item="$1" f="$2"
    if [ -f "$f" ] || [ -d "$f" ]; then
        printf '[%s] %s 파일: %s (존재)\n\n' "$item" "$(date '+%H:%M:%S')" "$f" >> "$_EVD"
    else
        printf '[%s] %s 파일: %s (미존재)\n\n' "$item" "$(date '+%H:%M:%S')" "$f" >> "$_EVD"
    fi
}
evd_q() {   # 판정에 쓴 값 요약 (실제 SQL·열 이름·결과 행은 run_q 가 이미 'SQL:' 블록으로 기록). $2=설명, $3=값
    local item="$1" desc="$2" output="$3" qe
    qe=$(_qerr_first)   # 이 항목에서 조회 오류가 있었으면 '없음/0건' 이 실제 결과가 아님을 명시
    [ -n "$qe" ] && output="[조회 오류 있음 - 아래 값은 실제 0건/없음이 아닐 수 있음] ${qe}"$'\n'"${output}"
    printf '[%s] %s 판정값: %s\n%s\n\n' "$item" "$(date '+%H:%M:%S')" "$desc" "${output:-(없음)}" >> "$_EVD"
}

_csv() { tr '\n' ',' | sed 's/,$//'; }
# 목록이 길면 근거에는 앞부분만 (전체는 증적) — 근거 문자열 요약 전용
_brief() { local n; n=$(printf '%s\n' "$1" | grep -c .); if [ "${n:-0}" -gt "$2" ]; then printf '%s\n' "$1" | sed -n "1,${2}p" | _csv; printf ' 외 %s건(증적 참조)' "$((n-$2))"; else printf '%s\n' "$1" | _csv; fi; }

# 정렬 로캘 고정 join (UNLIMITED 계정이 로캘 정렬 차이로 누락되지 않도록)
_join_eq() { LC_ALL=C join -t= <(printf '%s\n' "$1" | LC_ALL=C sort) <(printf '%s\n' "$2" | LC_ALL=C sort) 2>/dev/null; }

# ── EoS(지원 종료) 표: 제품·버전 → 종료일(YYYY-MM-DD), 모르면 빈 문자열 ──
_eos_date() {   # $1=mysql|mariadb|pgsql|mssql $2=버전 문자열
    local v="$2" mj mn
    case "$1" in
    mysql)
        mj=$(printf '%s' "$v" | sed -n 's/^[^0-9]*\([0-9][0-9]*\)\.\([0-9][0-9]*\).*/\1.\2/p')
        case "$mj" in 4.*|5.0|5.1|5.5) echo "2018-12-31" ;; 5.6) echo "2021-02-28" ;; 5.7) echo "2023-10-31" ;; 8.0) echo "2026-04-30" ;; 8.4) echo "2032-04-30" ;; esac ;;
    mariadb)
        mj=$(printf '%s' "$v" | sed -n 's/^[^0-9]*\([0-9][0-9]*\)\.\([0-9][0-9]*\).*/\1.\2/p')
        case "$mj" in 5.*|10.0|10.1|10.2|10.3) echo "2023-05-25" ;; 10.4) echo "2024-06-18" ;; 10.5) echo "2025-06-24" ;; 10.6) echo "2026-07-06" ;; 10.11) echo "2028-02-16" ;; 11.4) echo "2029-05-29" ;; 11.8) echo "2028-06-04" ;; esac ;;
    pgsql)
        mj=$(printf '%s' "$v" | sed -n 's/^[^0-9]*\([0-9][0-9]*\)\(\.[0-9][0-9]*\)\{0,1\}.*/\1/p')
        case "$mj" in [0-9]) echo "2021-11-11" ;; 10) echo "2022-11-10" ;; 11) echo "2023-11-09" ;; 12) echo "2024-11-14" ;; 13) echo "2025-11-13" ;; 14) echo "2026-11-12" ;; 15) echo "2027-11-11" ;; 16) echo "2028-11-09" ;; 17) echo "2029-11-08" ;; 18) echo "2030-11-14" ;; esac ;;
    mssql)
        case "$v" in 2005) echo "2016-04-12" ;; 2008) echo "2019-07-09" ;; 2012) echo "2022-07-12" ;; 2014) echo "2024-07-09" ;; 2016) echo "2026-07-14" ;; 2017) echo "2027-10-12" ;; 2019) echo "2030-01-08" ;; 2022) echo "2033-01-11" ;; 2025) echo "2036-01-06" ;; esac ;;
    esac
}
# _eos_judge <제품> <버전> → EOS_RES(취약|수동확인) / EOS_WHY
_eos_judge() {
    local d today vs; d=$(_eos_date "$1" "$2"); today=$(date '+%Y-%m-%d')
    vs=$(printf '%s' "$2" | grep -oE '[0-9]+(\.[0-9]+)+' | head -1); [ -n "$vs" ] && set -- "$1" "$vs"
    if [ -z "$d" ]; then EOS_RES="수동확인"; EOS_WHY="${2} - 지원 종료일 정보 없음, 벤더 EoS 정책 수동 확인 (최신 보안 패치 적용 여부 포함)"
    elif [ "$today" \> "$d" ]; then EOS_RES="취약"; EOS_WHY="${2} - 벤더 지원 종료(${d}) 경과, 보안 패치 미제공 (점검일 ${today})"
    else EOS_RES="수동확인"; EOS_WHY="${2} - 지원 종료 예정일 ${d} (점검일 ${today}) - 최신 보안 패치 적용 여부 수동 확인"; fi
}

_get_umask() {
    # $1=구동 계정, $2..=프로세스 이름 후보 — 실행 중 데몬의 실제 umask 우선, 모두 없을 때만 계정 로그인 umask
    local _user="$1" _umask="" _pid="" _n _c; shift
    for _n in "$@"; do
        _pid=$(pgrep -x "$_n" 2>/dev/null | head -1)
        if [ -z "$_pid" ]; then
            for _c in /proc/[0-9]*/comm; do case "$(cat "$_c" 2>/dev/null)" in "$_n"|"$_n"_*) _pid=${_c#/proc/}; _pid=${_pid%/comm}; break ;; esac; done
        fi
        [ -z "$_pid" ] && _pid=$(pgrep -f "^[^ ]*${_n}" 2>/dev/null | head -1)   # ora_pmon_<SID> 등 접미사 붙는 프로세스
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
        nc "$_item" "${_label} 구동 계정(${_user}) umask 를 읽지 못함(/proc/<pid>/status Umask·su 모두 실패, root 권한/프로세스 확인) - 수동 확인"
    fi
}

# DB 프로세스 구동 계정 / umask 판정 (comm 정확 일치, 여러 인스턴스는 전부 확인)
_umask_pid() { awk '/^Umask:/{print $2}' "/proc/$1/status" 2>/dev/null; }
_judge_umask_procs() {   # $1=항목(026) $2=라벨 $3=comm 정규식
    local u pid cm um bad="" good="" unk="" n=0 src
    evd_ps "DBM-$1" "$3"
    while read -r u pid cm; do
        [ -z "$pid" ] && continue
        n=$((n+1)); src="/proc"
        um=$(_umask_pid "$pid")
        if [ -z "$um" ]; then um=$(su -c "umask" "$u" 2>/dev/null); src="로그인 umask"; fi
        if [ -z "$um" ]; then unk="${unk}${u}(pid ${pid}) "
        elif (( (8#${um: -3} & 8#022) == 8#022 )) 2>/dev/null; then good="${good}${u}(pid ${pid}) umask=${um}[${src}] "
        else bad="${bad}${u}(pid ${pid}) umask=${um}[${src}] "; fi
    done <<< "$(_ps_ucp | awk -v re="^($3)\$" '{x=$3; sub(/.*\//,"",x); if (x ~ re && !s[$1]++) print}')"
    if [ "$n" -eq 0 ]; then nc "$1" "${2} 구동 프로세스(${3})를 찾지 못해 구동 계정 umask 확인 불가 (ps 권한·프로세스명 확인)"
    elif [ -n "$bad" ]; then ng "$1" "${2} 구동 계정 umask 022 이상 권고 위반: ${bad}${good:+/ 적합: $good}"
    elif [ -n "$unk" ]; then nc "$1" "${2} 구동 계정 umask 를 읽지 못함: ${unk}(/proc/<pid>/status·su 실패, root 권한 확인)${good:+ / 적합: $good}"
    else ok "$1" "${2} 구동 계정 umask 022 이상: ${good}"; fi
}
_judge_runuser() {   # $1=항목(034) $2=라벨 $3=comm 정규식 — root 구동이면 취약
    local us
    evd_ps "DBM-$1" "$3"
    us=$(_proc_users "$3")
    if [ -z "$us" ]; then nc "$1" "${2} 구동 프로세스(${3})를 찾지 못해 구동 계정 확인 불가 (ps 권한·프로세스명 확인)"
    elif printf ' %s ' "$us" | grep -q ' root '; then ng "$1" "${2} 가 root 계정으로 실행 (구동 계정: ${us})"
    else ok "$1" "${2} 구동 계정: ${us} (root 아님)"; fi
}

# 일반 사용자 계정으로 DB 프로세스 사용자 전환 실행 (su -s 는 Linux 전용 옵션)
_su_run() {   # $1=OS 계정 $2=명령 문자열 (표준입력 그대로 전달)
    if [ "$OS_FAMILY" = "LINUX" ]; then su -s /bin/sh "$1" -c "$2"; else su "$1" -c "$2"; fi
}

# ── 결과 헤더 (점검이 끝난 뒤 DB 버전까지 채워 출력) ──────────────
_print_header() {
    local _envl _osd
    if [ -n "$_MANAGED" ]; then _envl="관리형 (${_MANAGED_LABEL})"; else _envl="설치형"; fi
    _osd=$( ( [ -r /etc/os-release ] && . /etc/os-release 2>/dev/null && echo "${PRETTY_NAME:-$NAME $VERSION_ID}" ) || ( command -v oslevel >/dev/null 2>&1 && echo "AIX $(oslevel -s 2>/dev/null)" ) || ( [ -r /etc/release ] && sed -n '1p' /etc/release | sed 's/^ *//' ) || uname -sr 2>/dev/null)
    echo "# ================================================================"
    echo "# 점검 대상: ${_T_ID}"
    echo "# 실행 호스트: ${HN}"
    echo "# IP: $(_ip_header)"
    echo "# 실행 계정: $(_acct_header)"
    echo "# 클라우드: $(_cloud_header)"
    echo "# DBMS 환경: ${_envl}"
    echo "# DBMS 종류: ${DBMS_KIND:-$DBMS_TYPE}"
    echo "# DB 버전: ${DB_VER:-미확인}"
    if [ -n "$_MANAGED" ] || [ "$_REMOTE" = 1 ]; then
        echo "# 점검 방식: 원격 접속 - OS 항목(파일·프로세스·umask·로컬 방화벽)은 실행 호스트 기준으로 판정하지 않음(관리형=N-A, 설치형 원격=점검불가)"
    fi
    echo "# OS: ${OS_FAMILY}$( [ -n "$_MANAGED" ] || [ "$_REMOTE" = 1 ] && echo " (실행 호스트 - 점검 대상 OS 아님)")"
    echo "# OS 상세: ${_osd}"
    echo "# 커널: $(uname -r 2>/dev/null)$( [ "$(uname -s 2>/dev/null)" = SunOS ] && echo " / $(uname -v 2>/dev/null)")"
    case "$_KMODE" in
    ef)  echo "# 점검 기준: 전자금융기반시설 보안 취약점 평가기준 제2026-1호 [데이터베이스]" ;;
    mi)  echo "# 점검 기준: 주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드(2026) [DBMS D-01~D-26]" ;;
    *)   echo "# 점검 기준: 전자금융기반시설 보안 취약점 평가기준 제2026-1호 [데이터베이스] + 주요정보통신기반시설 상세가이드(2026) [DBMS D-01~D-26]" ;;
    esac
    echo "# 점검 일시: $(date '+%Y-%m-%d %H:%M:%S')"
    case " $_ORDER" in *" D-"*) _hd=1 ;; *) _hd=0 ;; esac
    if [ "$_KMODE" = "mi" ] && [ "$_hd" = 0 ]; then
        echo "# [안내] ${DBMS_TYPE:-DBMS}: 가이드 D 항목 직접 판정 미지원(MySQL·MariaDB·PostgreSQL·MSSQL 만 지원) - 전자금융 DBM 결과를 출력하며, 컨버터 주요정보 모드가 가이드 D 항목으로 변환"
    fi
    printf '%s' "$_HDRX"
    echo "# ================================================================"
    { echo "# DBMS 환경: ${_envl} / DBMS 종류: ${DBMS_KIND:-$DBMS_TYPE} / DB 버전: ${DB_VER:-미확인}"; } >> "$_EVD"
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
    if [ "$_REMOTE" = 1 ]; then _ask_cred "Oracle" ORACLE_USER ORACLE_PASS "system" "비밀번호 없음"
    else _ask_cred "Oracle" ORACLE_USER ORACLE_PASS "OS 인증(/ as sysdba)" "OS 인증(/ as sysdba)" 1; fi
    ORACLE_USER="${ORACLE_USER:-system}"
    ORACLE_PASS="${ORACLE_PASS-}"
    _ORA_OS_USER=""; _ORA_SU=""
    [ "$_REMOTE" = 1 ] || _ora_env   # 원격·관리형은 로컬 Oracle 홈 복원 불필요 (sqlplus 클라이언트만 사용)
    ORACLE_SID="${ORACLE_SID:-}"
    ORACLE_SERVICE="${ORACLE_SERVICE:-}"
    local _o_host="${ORACLE_HOST:-}"
    ORACLE_PORT="${ORACLE_PORT:-1521}"
    DBMS_KIND="oracle"

    SQLPLUS=$(command -v sqlplus 2>/dev/null)
    [ -z "$SQLPLUS" ] && [ -n "$ORACLE_HOME" ] && SQLPLUS="$ORACLE_HOME/bin/sqlplus"
    if [ -z "$SQLPLUS" ] || [ ! -x "$SQLPLUS" ]; then
        printf '[FALLBACK] %s sqlplus 미탐지 - Oracle 전 항목 점검불가 처리\n\n' "$(date '+%H:%M:%S')" >> "$_EVD"
        for i in 001 003 004 005 006 007 008 009 011 012 013 014 015 016 017 \
                 019 020 022 024 025 026 028 029 030 032 033 034; do
            nc "$i" "sqlplus 명령을 찾지 못해 점검 불가 (ORACLE_HOME/PATH 또는 Instant Client 설치 확인)"
        done
        na "021" "Windows MSSQL 전용 항목"
        na "031" "MSSQL 전용 항목"
        na "035" "MSSQL 전용 항목"
        na "036" "MSSQL 전용 항목"
        return
    fi

    # 관리형(RDS) 예약 계정은 계정 점검에서 제외
    local _xu="" _xd="" _xn=""
    if [ -n "$_MANAGED" ]; then
        _xu=" AND u.USERNAME NOT IN ('RDSADMIN','RDS_DATAGUARD')"
        _xd=" AND d.USERNAME NOT IN ('RDSADMIN','RDS_DATAGUARD')"
        _xn=" (관리형 예약 계정 제외: RDSADMIN, RDS_DATAGUARD)"
    fi

    _ora_conn() {   # $1=사용자 $2=비밀번호 $3=sysdba 여부 → 접속 문자열 (비밀번호는 큰따옴표로 감싸 @ / # \ 등 특수문자 허용)
        local u="$1" p="$2" tgt="" pq
        if [ -n "$_o_host" ]; then tgt="@//${_o_host}:${ORACLE_PORT}/${ORACLE_SERVICE:-$ORACLE_SID}"
        elif [ -n "$ORACLE_SERVICE" ]; then tgt="@//localhost:${ORACLE_PORT}/${ORACLE_SERVICE}"
        elif [ -n "$ORACLE_SID" ]; then tgt="@${ORACLE_SID}"; fi
        case "$p" in *\"*) pq="$p"; _hnote "# [경고] Oracle 비밀번호에 큰따옴표(\")가 있어 따옴표 없이 접속 시도 - 특수문자 포함 시 접속 실패 가능" ;; *) pq="\"$p\"" ;; esac
        printf '%s/%s%s%s' "$u" "$pq" "$tgt" "${3:+ as sysdba}"
    }
    if [ -z "$ORACLE_PASS" ] && [ "$_REMOTE" != 1 ]; then   # 비밀번호 미지정 → 로컬 OS 인증(/ as sysdba), root 실행이면 ora_pmon 구동 계정으로 sqlplus 실행
        CONN="/ as sysdba"
        [ "$(id -u)" = 0 ] && [ -n "$_ORA_OS_USER" ] && [ "$_ORA_OS_USER" != "root" ] && _ORA_SU="$_ORA_OS_USER"
    else
        CONN=$(_ora_conn "$ORACLE_USER" "$ORACLE_PASS" "$( [ "$(_up "$ORACLE_USER")" = SYS ] && echo 1)")   # SYS 는 as sysdba 로만 접속 가능
    fi

    _ora_exec() {   # 접속 문자열은 표준입력으로만 전달 (프로세스 인자 노출 없음)
        if [ -n "$_ORA_SU" ]; then _su_run "$_ORA_SU" "ORACLE_HOME='$ORACLE_HOME' ORACLE_SID='$ORACLE_SID' TNS_ADMIN='$TNS_ADMIN' '$SQLPLUS' -s /nolog"
        else "$SQLPLUS" -s /nolog; fi
    }
    # $1=선택 여부(0 엄격/1 선택) $2=SQL → 결과 행(열 이름 줄 제외). 오류 시 엄격=출력 없음+오류 기록, 선택=첫 ORA- 줄만 출력
    _oq() {
        local _o _err _s="$2"
        case "${_s%"${_s##*[![:space:]]}"}" in *\;) ;; *) _s="${_s};" ;; esac   # sqlplus 는 ; 로 끝나야 실행
        _o=$(printf 'CONNECT %s\nSET PAGESIZE 50000 NEWPAGE NONE FEEDBACK OFF HEADING ON LINESIZE 4000 TRIMOUT ON TAB OFF VERIFY OFF\n%s\nEXIT\n' "$CONN" "$_s" | _ora_exec 2>&1)
        _o=$(printf '%s\n' "$_o" | sed 's/[[:space:]]*$//' | grep -v '^$')
        _err=$(printf '%s\n' "$_o" | grep -E '^(ORA|SP2|TNS)-[0-9]+|^ERROR' | head -3)
        if [ -n "$_err" ]; then
            _qrecord "$2" "$_o" "" 1
            if [ "$1" = 1 ]; then printf '%s\n' "$_err" | grep -E '^(ORA|SP2|TNS)-' | head -1
            else _qerr_add "$(printf '%s\n' "$_err" | grep -E '^(ORA|SP2|TNS)-' | head -1)"; fi
            return 1
        fi
        _qrecord "$2" "$_o" "" 0
        printf '%s\n' "$_o" | awk 'NF{a[++n]=$0} END{s=1; if (n>=2 && a[2] ~ /^[- ]+$/) s=3; for (i=s;i<=n;i++) print a[i]}'
    }
    run_q()  { _oq 0 "$1"; }
    run_qo() { _oq 1 "$1"; }
    _ORA_CONS=""
    _oqa() {   # CDB$ROOT(또는 비CDB) + 열린 PDB 전체
        _oq "$1" "$2"
        local c
        for c in $_ORA_CONS; do
            _oq "$1" "ALTER SESSION SET CONTAINER=\"$c\";
$2" | grep -v '^$' | sed "s/^/[$c]/"
        done
    }
    run_qa()  { _oqa 0 "$1"; }
    run_qao() { _oqa 1 "$1"; }

    _it "DBM-000"
    if [ -z "$ORACLE_PASS" ] && [ "$_REMOTE" != 1 ] && ! run_q "SELECT 'CONN_'||'OK' FROM DUAL" | grep -q CONN_OK && [ -t 0 ]; then
        read -rs -p "Oracle OS 인증 실패 - SYS 비밀번호: " ORACLE_PASS </dev/tty; echo >&2
        _ORA_SU=""; CONN=$(_ora_conn "sys" "$ORACLE_PASS" 1)
    elif [ -z "$ORACLE_PASS" ] && [ "$_REMOTE" = 1 ] && [ -z "$_CRED_ASKED" ] && [ -t 0 ]; then
        read -rs -p "Oracle ${ORACLE_USER} 비밀번호: " ORACLE_PASS </dev/tty; echo >&2
        CONN=$(_ora_conn "$ORACLE_USER" "$ORACLE_PASS" "$( [ "$(_up "$ORACLE_USER")" = SYS ] && echo 1)")
    fi
    _hnote "# Oracle 접속: $( [ "$CONN" = "/ as sysdba" ] && echo "OS 인증(/ as sysdba)${_ORA_SU:+ - ${_ORA_SU} 계정}" || echo "${ORACLE_USER}@${_T_ID}")"

    _it "DBM-000"
    _conn_ok "$(run_q "SELECT 'CONN_'||'OK' FROM DUAL")" "Oracle" || return
    _ORA_VER=$(run_q "SELECT VERSION FROM V\$INSTANCE" | grep -oE '[0-9]+\.[0-9]+' | head -1)
    [ -z "$_ORA_VER" ] && _ORA_VER=$(run_qo "SELECT VERSION FROM PRODUCT_COMPONENT_VERSION WHERE PRODUCT LIKE 'Oracle%'" | grep -oE '[0-9]+\.[0-9]+' | head -1)
    DB_MAJ=$(echo "$_ORA_VER" | cut -d. -f1)
    DB_VER="${_ORA_VER}"
    _ban=$(run_qo "SELECT BANNER FROM V\$VERSION WHERE ROWNUM=1" | head -1)
    [ -n "$_ban" ] && DB_VER="${_ORA_VER} (${_ban})"
    _hnote "# Oracle 버전: ${DB_VER}"
    # 12c+ 멀티테넌트: CDB$ROOT 접속 시 열린 PDB 전체를 순회 (DBA_* 뷰는 현재 컨테이너만 조회)
    if [ "$(run_qo "SELECT SYS_CONTEXT('USERENV','CON_NAME') FROM DUAL" | tr -d ' \n')" = 'CDB$ROOT' ]; then
        _ORA_CONS=$(run_q "SELECT NAME FROM V\$PDBS WHERE OPEN_MODE LIKE 'READ%' AND NAME<>'PDB\$SEED' ORDER BY CON_ID" | tr -d ' ' | grep -v '^$' | tr '\n' ' ')
        _hnote "# Oracle 컨테이너: CDB\$ROOT ${_ORA_CONS}"
        evd_q "DBM-003" "열린 PDB (계정·권한 항목은 CDB\$ROOT + PDB 별 [PDB명] 접두로 합산)" "${_ORA_CONS:-없음}"
    fi

    # 계정별 적용 프로파일 값 (OPEN·EXPIRED(GRACE) 계정, LIMIT=DEFAULT 는 DEFAULT 프로파일 값으로 대체) → "USER=VALUE" 줄
    _prof() {
        run_qa "SELECT u.USERNAME||'='||DECODE(p.LIMIT,'DEFAULT',d.LIMIT,p.LIMIT) FROM DBA_USERS u JOIN DBA_PROFILES p ON p.PROFILE=u.PROFILE AND p.RESOURCE_NAME='$1' JOIN DBA_PROFILES d ON d.PROFILE='DEFAULT' AND d.RESOURCE_NAME='$1' WHERE u.ACCOUNT_STATUS IN ('OPEN','EXPIRED(GRACE)')${_xu} ORDER BY 1" | grep "="
    }

    # DBM-001: 취약 패스워드
    _it 001
    if [ "${DB_MAJ:-0}" -ge 12 ] 2>/dev/null; then
        ACCTS="'SYS','SYSTEM','DBSNMP','SCOTT','OUTLN','MDSYS','XDB','ANONYMOUS','CTXSYS'"
    else
        ACCTS="'SYS','SYSTEM','DBSNMP','SCOTT','OUTLN','MDSYS','XDB','ANONYMOUS'"
    fi
    # 평가기준: 초기 설정(디폴트) 비밀번호·취약 비밀번호 사용 계정 존재 시 취약 (복잡도 만족 여부는 해시 크랙 필요)
    def_pwd=$(run_qa "SELECT d.USERNAME||'('||u.ACCOUNT_STATUS||')' FROM DBA_USERS_WITH_DEFPWD d JOIN DBA_USERS u ON u.USERNAME=d.USERNAME WHERE u.ACCOUNT_STATUS IN ('OPEN','EXPIRED(GRACE)')${_xd} ORDER BY 1")
    def_accounts=$(run_qa "SELECT u.USERNAME||'('||u.ACCOUNT_STATUS||')' FROM DBA_USERS u WHERE u.USERNAME IN (${ACCTS}) AND u.ACCOUNT_STATUS='OPEN'${_xu} ORDER BY 1")
    evd_q "DBM-001" "DBA_USERS_WITH_DEFPWD 해당 계정 / 기본 계정 OPEN" "디폴트 비밀번호 계정: ${def_pwd:-없음} / 기본 계정 OPEN: ${def_accounts:-없음}"
    if [ -n "$def_pwd" ]; then
        ng "001" "초기 설정(디폴트) 비밀번호 사용 계정: $(_brief "$def_pwd" 20)${_xn}"
    else
        mc "001" "디폴트 비밀번호 계정 없음 - 계정 비밀번호 복잡도·취약 비밀번호 여부는 해시 크랙으로 확인 필요 (기본 계정 OPEN: $(_brief "${def_accounts:-없음}" 20))${_xn}"
    fi

    # DBM-003: 불필요 계정
    _it 003
    _all_users=$(run_qa "SELECT USERNAME||' ('||ACCOUNT_STATUS||')' FROM DBA_USERS ORDER BY USERNAME")
    evd_q "DBM-003" "DBA_USERS 전체 계정 (CDB\$ROOT + [PDB])" "$(printf '%s\n' "$_all_users" | grep -c .)개"
    mc "003" "불필요 계정 목록 수동 확인 (계정 $(printf '%s\n' "$_all_users" | grep -c .)개, 증적 참조)${_xn}"

    # DBM-004: 불필요 관리자 계정
    # 평가기준: DBA role·SYSDBA·시스템 권한 부여 계정 목록 → 인터뷰로 불필요 여부 판단
    _it 004
    dba=$(run_qa "SELECT GRANTEE FROM DBA_ROLE_PRIVS WHERE GRANTED_ROLE='DBA' AND GRANTEE NOT IN ('SYS','SYSTEM','DBA'${_xn:+,'RDSADMIN','RDS_DATAGUARD'}) ORDER BY GRANTEE")
    _sysdba=$(run_q "SELECT USERNAME FROM V\$PWFILE_USERS WHERE SYSDBA='TRUE' AND USERNAME<>'SYS'${_xn:+ AND USERNAME NOT IN ('RDSADMIN','RDS_DATAGUARD')}")
    if [ "${DB_MAJ:-0}" -ge 12 ] 2>/dev/null; then
        _sysprv=$(run_qa "SELECT DISTINCT p.GRANTEE FROM DBA_SYS_PRIVS p JOIN DBA_USERS u ON u.USERNAME=p.GRANTEE WHERE u.ORACLE_MAINTAINED='N' AND p.PRIVILEGE NOT IN ('CREATE SESSION')${_xn:+ AND u.USERNAME NOT IN ('RDSADMIN','RDS_DATAGUARD')} ORDER BY 1")
    else
        _sysprv=$(run_q "SELECT DISTINCT p.GRANTEE FROM DBA_SYS_PRIVS p JOIN DBA_USERS u ON u.USERNAME=p.GRANTEE WHERE u.USERNAME NOT IN ('SYS','SYSTEM','DBSNMP','OUTLN','MDSYS','CTXSYS','XDB','WMSYS','EXFSYS','ORDSYS','OLAPSYS','SYSMAN','APPQOSSYS','DIP','ORACLE_OCM') AND p.PRIVILEGE NOT IN ('CREATE SESSION') ORDER BY 1")
    fi
    evd_q "DBM-004" "DBA 역할 / SYSDBA / 시스템 권한 보유 계정" "DBA: ${dba:-없음} / SYSDBA: ${_sysdba:-없음} / 시스템 권한: ${_sysprv:-없음}"
    mc "004" "관리자 권한 계정 - DBA: $(_brief "${dba:-없음}" 20), SYSDBA: $(_brief "${_sysdba:-없음}" 20), 시스템 권한: $(_brief "${_sysprv:-없음}" 20) - 업무상 필요 여부 인터뷰 확인${_xn}"

    # DBM-005: 중요정보 암호화
    _it 005
    _enc_cols=$(run_qa "SELECT OWNER||'.'||TABLE_NAME||'.'||COLUMN_NAME FROM DBA_ENCRYPTED_COLUMNS ORDER BY 1")
    evd_q "DBM-005" "DBA_ENCRYPTED_COLUMNS 암호화 컬럼" "${_enc_cols:-암호화 컬럼 없음}"
    mc "005" "테이블 컬럼별 암호화 적용 여부 수동 확인 (암호화 컬럼 $(printf '%s\n' "$_enc_cols" | grep -c .)개: $(_brief "${_enc_cols:-없음}" 10))"

    # DBM-006: 로그인 실패 횟수 제한 (평가기준: 계정별 적용 프로파일 FAILED_LOGIN_ATTEMPTS UNLIMITED 또는 5 초과 → 취약)
    _it 006
    _p6=$(_prof FAILED_LOGIN_ATTEMPTS); _lock=$(run_q "SELECT LIMIT FROM DBA_PROFILES WHERE PROFILE='DEFAULT' AND RESOURCE_NAME='PASSWORD_LOCK_TIME'" | tr -d ' \n')
    evd_q "DBM-006" "계정별 FAILED_LOGIN_ATTEMPTS / DEFAULT PASSWORD_LOCK_TIME" "$(echo "$_p6" | _csv) / LOCK_TIME=${_lock}"
    _b6=$(echo "$_p6" | awk -F= '$2=="UNLIMITED" || $2+0>5 || $2=="" {print}')
    if [ -z "$_p6" ]; then nc "006" "계정별 FAILED_LOGIN_ATTEMPTS 조회 결과 없음 - 수동 확인"
    elif [ -n "$_b6" ]; then ng "006" "FAILED_LOGIN_ATTEMPTS UNLIMITED/5 초과 계정: $(_brief "$_b6" 20) - 서비스 운영 계정은 평가 제외 가능${_xn}"
    else ok "006" "OPEN 계정 FAILED_LOGIN_ATTEMPTS 5회 이하 (PASSWORD_LOCK_TIME=${_lock})${_xn}"; fi

    # DBM-007: 비밀번호 검증 함수 — 미적용 계정 또는 기준(2종 10자/3종 8자) 미달 함수 → 취약
    _it 007
    _p7=$(_prof PASSWORD_VERIFY_FUNCTION)
    evd_q "DBM-007" "계정별 PASSWORD_VERIFY_FUNCTION" "$(echo "$_p7" | _csv)"
    _n7=$(echo "$_p7" | awk -F= '$2=="" || $2=="NULL" {print $1}')
    _w7=$(echo "$_p7" | awk -F= 'toupper($2) ~ /^(ORA12C_VERIFY_FUNCTION|VERIFY_FUNCTION_11G|VERIFY_FUNCTION)$/ {print}')
    _c7=$(echo "$_p7" | awk -F= '$2!="" && $2!="NULL" && toupper($2) !~ /^(ORA12C_STRONG_VERIFY_FUNCTION|ORA12C_VERIFY_FUNCTION|VERIFY_FUNCTION_11G|VERIFY_FUNCTION)$/ {print $2}' | sort -u)
    if [ -z "$_p7" ]; then nc "007" "PASSWORD_VERIFY_FUNCTION 조회 결과 없음 - 수동 확인"
    elif [ -n "$_n7" ]; then ng "007" "비밀번호 검증 함수 미적용 계정: $(_brief "$_n7" 20)${_xn}"
    elif [ -n "$_w7" ]; then ng "007" "검증 함수 기준 미달(8자·2종 조합, 기준 2종 10자/3종 8자): $(_brief "$_w7" 20)${_xn}"
    elif [ -n "$_c7" ]; then mc "007" "사용자 정의 검증 함수: $(echo "$_c7" | _csv) - 함수 내용이 복잡도 기준 충족하는지 확인"
    else ok "007" "전 OPEN 계정 ORA12C_STRONG_VERIFY_FUNCTION 적용${_xn}"; fi

    # DBM-008: 최근 비밀번호 변경일(DBA_USERS.PASSWORD_CHANGE_DATE → sys.user$ ptime) 90일 이상 경과 계정 → 취약 (조회 불가 시 만료 정책으로 대체)
    _it 008
    _ptime=$(run_qao "SELECT USERNAME||'='||TO_CHAR(PASSWORD_CHANGE_DATE,'YYYY-MM-DD') FROM DBA_USERS WHERE ACCOUNT_STATUS IN ('OPEN','EXPIRED(GRACE)') AND PASSWORD_CHANGE_DATE < SYSDATE-90 ORDER BY 1")
    # PASSWORD_CHANGE_DATE(21c+) 미지원이면 sys.user$ ptime
    echo "$_ptime" | grep -q "ORA-" && _ptime=$(run_qao "SELECT u.name||'='||TO_CHAR(u.ptime,'YYYY-MM-DD') FROM sys.user\$ u JOIN DBA_USERS d ON d.USERNAME=u.name WHERE d.ACCOUNT_STATUS IN ('OPEN','EXPIRED(GRACE)') AND u.ptime < SYSDATE-90 ORDER BY 1")
    if echo "$_ptime" | grep -q "ORA-"; then
        _p8=$(_prof PASSWORD_LIFE_TIME)
        evd_q "DBM-008" "비밀번호 변경일 조회 불가(${_ptime}) → 계정별 PASSWORD_LIFE_TIME" "$(echo "$_p8" | _csv)"
        _b8=$(echo "$_p8" | awk -F= '$2=="UNLIMITED" || $2+0>90 {print}')
        if [ -z "$_p8" ]; then nc "008" "비밀번호 변경일·만료 정책 조회 결과 없음 - 수동 확인"
        elif [ -n "$_b8" ]; then ng "008" "비밀번호 변경일 조회 권한 없음 - 만료 정책 90일 초과/무제한 계정: $(_brief "$_b8" 20) - 서비스 운영 계정은 평가 제외 가능${_xn}"
        else ok "008" "OPEN 계정 PASSWORD_LIFE_TIME 90일 이하 (변경일 조회 권한 없음 - 만료 정책 기준)${_xn}"; fi
    else
        evd_q "DBM-008" "OPEN 계정 중 비밀번호 변경 90일 이상 경과" "${_ptime:-없음}"
        if [ -n "$_ptime" ]; then ng "008" "최근 비밀번호 변경 후 90일 이상 경과 계정: $(_brief "$_ptime" 20) - 서비스 운영 계정은 평가 제외 가능${_xn}"
        else ok "008" "OPEN 계정 모두 90일 이내 비밀번호 변경 (PASSWORD_CHANGE_DATE/ptime)${_xn}"; fi
    fi

    # DBM-009: 미사용 세션 종료 (resource_limit=TRUE + 계정별 IDLE_TIME 15분 이하)
    _it 009
    _res_lim=$(run_q "SELECT VALUE FROM V\$PARAMETER WHERE NAME='resource_limit'" | tr -d ' \n')
    _p9=$(_prof IDLE_TIME)
    evd_q "DBM-009" "resource_limit=${_res_lim}, 계정별 IDLE_TIME" "$(echo "$_p9" | _csv)"
    _b9=$(echo "$_p9" | awk -F= '$2=="UNLIMITED" || $2+0>15 {print}')
    if [ -z "$_res_lim" ]; then nc "009" "resource_limit 조회 결과 없음 - 수동 확인"
    elif [ "$(_up "$_res_lim")" != "TRUE" ]; then ng "009" "resource_limit=${_res_lim} (프로파일 자원 제한 비활성 - IDLE_TIME 미적용)"
    elif [ -z "$_p9" ]; then nc "009" "IDLE_TIME 조회 결과 없음 - 수동 확인"
    elif [ -n "$_b9" ]; then ng "009" "IDLE_TIME UNLIMITED/15분 초과 계정: $(_brief "$_b9" 20) - 내부 규정 미명시 시 15분, 서비스 계정 평가 제외 가능${_xn}"
    else ok "009" "resource_limit=TRUE, OPEN 계정 IDLE_TIME 15분 이하${_xn}"; fi

    # DBM-011: 감사 로그
    _it 011
    if [ "${DB_MAJ:-0}" -ge 12 ] 2>/dev/null; then
        ua=$(run_q "SELECT VALUE FROM V\$OPTION WHERE PARAMETER='Unified Auditing'" | tr -d ' \n')
        if [ "$ua" = "TRUE" ]; then
            cnt=$(run_q "SELECT COUNT(DISTINCT POLICY_NAME) FROM AUDIT_UNIFIED_ENABLED_POLICIES" | tr -d ' \n')
            evd_q "DBM-011" "Unified Auditing=TRUE, 활성 정책 수" "${cnt:-조회 불가}"
            [ "${cnt:-0}" -gt 0 ] 2>/dev/null && mc "011" "통합 감사 수집 중 (정책 ${cnt}개) - 주기적 백업 여부 인터뷰/증적 확인" || ng "011" "통합 감사 활성화됐으나 정책 없음"
        else
            at=$(run_q "SELECT VALUE FROM V\$PARAMETER WHERE NAME='audit_trail'" | tr -d ' \n')
            evd_q "DBM-011" "Unified Auditing=${ua:-미확인}, audit_trail" "$at"
            if [ -z "$at" ]; then nc "011" "audit_trail 조회 결과 없음 - 수동 확인"
            elif [ "$at" = "NONE" ]; then ng "011" "audit_trail=NONE"
            else mc "011" "audit_trail=${at} 수집 중 - 주기적 백업 여부 인터뷰/증적 확인"; fi
        fi
    else
        at=$(run_q "SELECT VALUE FROM V\$PARAMETER WHERE NAME='audit_trail'" | tr -d ' \n')
        evd_q "DBM-011" "audit_trail" "$at"
        if [ -z "$at" ]; then nc "011" "audit_trail 조회 결과 없음 - 수동 확인"
        elif [ "$at" = "NONE" ]; then ng "011" "audit_trail=NONE"
        else mc "011" "audit_trail=${at} 수집 중 - 주기적 백업 여부 인터뷰/증적 확인"; fi
    fi

    _ora_net() { local d; for d in "$TNS_ADMIN" "$("$ORACLE_HOME/bin/orabasehome" 2>/dev/null)/network/admin" "$ORACLE_HOME/network/admin"; do [ -n "$d" ] && [ -d "$d" ] && echo "$d"; done | awk '!s[$0]++'; }
    _ora_dbs() { local d; for d in "$("$ORACLE_HOME/bin/orabaseconfig" 2>/dev/null)/dbs" "$ORACLE_HOME/dbs"; do [ -d "$d" ] && echo "$d"; done | awk '!s[$0]++'; }
    # DBM-012: Listener Control Utility 접근 제한
    # 평가기준: Oracle 11.2 이상 양호 / 11.1 이하는 ADMIN_RESTRICTIONS_<리스너>=ON + lsnrctl 비밀번호(PASSWORDS_<리스너>) 설정
    _it 012
    _v1=$(echo "$_ORA_VER" | cut -d. -f1); _v2=$(echo "$_ORA_VER" | cut -d. -f2)
    if [ -n "$_MANAGED" ]; then
        _os_gate 012 "Listener(listener.ora/lsnrctl)는 관리형 서비스가 관리 - 보안그룹·옵션 그룹으로 접근 통제"
    elif [ -z "$_v1" ]; then
        nc "012" "Oracle 버전 확인 실패 - Listener 보안 설정 수동 확인"
    elif [ "$_v1" -gt 11 ] 2>/dev/null || { [ "$_v1" -eq 11 ] && [ "${_v2:-0}" -ge 2 ]; } 2>/dev/null; then
        ok "012" "Oracle ${_ORA_VER} (11.2 이상 - 리스너 로컬 OS 인증 기본 적용)$( [ "$_REMOTE" = 1 ] && echo ' [원격 접속: 버전 기준 판정, listener.ora 는 미확인]')"
    elif _os_gate 012 "Oracle ${_ORA_VER}(11.1 이하)는 listener.ora 의 ADMIN_RESTRICTIONS·PASSWORDS 확인 필요"; then
        :
    else
        _lora=""; for lora in $(for n in $(_ora_net); do echo "$n/listener.ora"; done) "/etc/oracle/listener.ora"; do [ -f "$lora" ] && _lora="$lora" && break; done
        # lsnrctl 은 root 로 실행하지 않고 Oracle 구동 계정으로만 실행 (증적용)
        _lu="${_ORA_SU:-$_ORA_OS_USER}"; _lsn="(lsnrctl 미발견)"
        if [ -x "$ORACLE_HOME/bin/lsnrctl" ]; then
            if [ "$(id -u)" != 0 ]; then _lsn=$("$ORACLE_HOME/bin/lsnrctl" status 2>&1)
            elif [ -n "$_lu" ] && [ "$_lu" != root ]; then _lsn=$(_su_run "$_lu" "ORACLE_HOME='$ORACLE_HOME' '$ORACLE_HOME/bin/lsnrctl' status" 2>&1)
            else _lsn="(root 로 lsnrctl 을 실행하지 않음 - Oracle 구동 계정 미확인)"; fi
        fi
        printf '[DBM-012] %s $ lsnrctl status  # Oracle 구동 계정(%s)으로 실행\n%s\n\n' "$(date '+%H:%M:%S')" "${_lu:-현재 계정}" "$_lsn" >> "$_EVD"
        if [ -n "$_lora" ]; then evd "DBM-012" "grep -v '^[[:space:]]*\$' '$_lora'"; else printf '[DBM-012] %s (대상 없음) listener.ora 를 찾지 못해 내용을 기록하지 못함\n(대상 없음)\n\n' "$(date '+%H:%M:%S')" >> "$_EVD"; fi
        _ar=$(grep -iE '^[[:space:]]*ADMIN_RESTRICTIONS_[^[:space:]]+[[:space:]]*=[[:space:]]*ON' "$_lora" </dev/null 2>/dev/null | head -1)
        _pw=$(grep -iE '^[[:space:]]*PASSWORDS_[^[:space:]]+[[:space:]]*=' "$_lora" </dev/null 2>/dev/null | head -1)
        if [ -z "$_lora" ]; then nc "012" "Oracle ${_ORA_VER} - listener.ora 를 찾지 못해 점검 불가 (TNS_ADMIN/ORACLE_HOME 확인)"
        elif [ -n "$_ar" ] && [ -n "$_pw" ]; then ok "012" "Oracle ${_ORA_VER} - ADMIN_RESTRICTIONS=ON, lsnrctl 비밀번호 설정"
        else ng "012" "Oracle ${_ORA_VER} (11.1 이하) - ADMIN_RESTRICTIONS=${_ar:+ON}${_ar:-미설정/OFF}, lsnrctl 비밀번호 ${_pw:+설정}${_pw:-미설정}"; fi
    fi

    # DBM-013: 원격 접속 접근 제어
    # 평가기준: sqlnet.ora TCP.VALIDNODE_CHECKING=yes (+ INVITED/EXCLUDED_NODES) 또는 네트워크 장비·솔루션 접근제어
    _it 013
    if _os_gate 013 "sqlnet.ora TCP.VALIDNODE_CHECKING 은 서버 파일"; then
        :
    else
        _sqlnet=""
        for _sn in $(for n in $(_ora_net); do echo "$n/sqlnet.ora"; done) /etc/oracle/sqlnet.ora; do
            [ -n "$_sn" ] && [ -f "$_sn" ] && _sqlnet="$_sn" && break
        done
        if [ -n "$_sqlnet" ]; then evd "DBM-013" "grep -v '^[[:space:]]*\$' '$_sqlnet'"; else printf '[DBM-013] %s (대상 없음) sqlnet.ora 를 찾지 못함\n(대상 없음)\n\n' "$(date '+%H:%M:%S')" >> "$_EVD"; fi
        _vnc=$(grep -iE '^[[:space:]]*TCP\.VALIDNODE_CHECKING' "${_sqlnet:-/dev/null}" </dev/null 2>/dev/null | tail -1 | cut -d= -f2 | tr -d ' ')
        _inv=$(grep -iE '^[[:space:]]*TCP\.(INVITED|EXCLUDED)_NODES' "${_sqlnet:-/dev/null}" </dev/null 2>/dev/null | tr '\n' ' ')
        if [ "$(_low "$_vnc")" = "yes" ] && [ -n "$_inv" ]; then ok "013" "TCP.VALIDNODE_CHECKING=yes, ${_inv}"
        elif [ -z "$_sqlnet" ]; then nc "013" "sqlnet.ora 를 찾지 못해 점검 불가 - 원격 접근제어(TCP.VALIDNODE_CHECKING/방화벽/솔루션) 수동 확인"
        else ng "013" "TCP.VALIDNODE_CHECKING=${_vnc:-미설정} (${_sqlnet}) - 네트워크 장비·솔루션 접근제어 적용 시 수동 확인"; fi
    fi

    # DBM-014: OS 역할 인증 비활성화 (OS_ROLES / REMOTE_OS_ROLES / REMOTE_OS_AUTHENT)
    _it 014
    _osr=$(run_q "SELECT NAME||'='||VALUE FROM V\$PARAMETER WHERE NAME IN ('os_roles','remote_os_roles','remote_os_authent') ORDER BY NAME" | grep "=" | tr -d ' ')
    evd_q "DBM-014" "os_roles / remote_os_roles / remote_os_authent (12c 이후 remote_os_authent 는 없을 수 있음)" "$(echo "$_osr" | _csv)"
    if ! echo "$_osr" | grep -qi '^os_roles=' || ! echo "$_osr" | grep -qi '^remote_os_roles='; then nc "014" "OS_ROLES/REMOTE_OS_ROLES 조회 결과 불완전($(echo "$_osr" | _csv)) - 수동 확인"
    elif echo "$_osr" | grep -qi "=TRUE"; then ng "014" "운영체제 역할 인증 사용: $(echo "$_osr" | grep -i "=TRUE" | _csv)"
    else ok "014" "$(echo "$_osr" | _csv)"; fi

    # DBM-015: PUBLIC 불필요 권한
    _it 015
    pkgs=$(run_qa "SELECT TABLE_NAME FROM DBA_TAB_PRIVS WHERE GRANTEE='PUBLIC' AND PRIVILEGE='EXECUTE' AND TABLE_NAME IN ('UTL_HTTP','UTL_FILE','UTL_SMTP','UTL_TCP','DBMS_SCHEDULER')")
    _pubrole=$(run_qa "SELECT GRANTED_ROLE FROM DBA_ROLE_PRIVS WHERE GRANTEE='PUBLIC'")
    _pubsys=$(run_qa "SELECT PRIVILEGE FROM DBA_SYS_PRIVS WHERE GRANTEE='PUBLIC'")
    evd_q "DBM-015" "PUBLIC 부여 Role / 시스템 권한 / 위험 패키지 EXECUTE" "Role: ${_pubrole:-없음} / SYS: ${_pubsys:-없음} / PKG: ${pkgs:-없음}"
    if [ -n "$_pubrole" ] || [ -n "$_pubsys" ]; then ng "015" "PUBLIC 에 Role/시스템 권한 부여: $(printf '%s\n%s\n' "$_pubrole" "$_pubsys" | grep -v '^$' | _csv)"
    elif [ -n "$pkgs" ]; then ng "015" "PUBLIC EXECUTE 위험 패키지: $(echo "$pkgs" | _csv)"
    else mc "015" "PUBLIC 에 Role·시스템 권한·위험 패키지 없음 - 업무상 불필요한 Object 권한 여부 확인"; fi

    # DBM-016: 보안패치
    _it 016
    if [ "${DB_MAJ:-0}" -ge 12 ] 2>/dev/null; then
        _patches=$(run_q "SELECT ACTION_TIME||' '||PATCH_ID||' '||DESCRIPTION FROM DBA_REGISTRY_SQLPATCH ORDER BY ACTION_TIME DESC")
    else
        _patches=$(run_q "SELECT ACTION_TIME||' '||ID||' '||COMMENTS FROM DBA_REGISTRY_HISTORY ORDER BY ACTION_TIME DESC")
    fi
    evd_q "DBM-016" "패치 이력" "${_patches:-패치 이력 없음}"
    mc "016" "Oracle 보안패치 적용 현황 수동 확인 (패치 이력 $(printf '%s\n' "$_patches" | grep -c .)건, 증적 참조)"

    # DBM-017: 시스템 테이블 접근 권한
    _it 017
    if [ "${DB_MAJ:-0}" -ge 12 ] 2>/dev/null; then
        _sys_grants=$(run_qa "SELECT GRANTEE||' → '||TABLE_NAME||' ('||PRIVILEGE||')' FROM DBA_TAB_PRIVS WHERE OWNER='SYS' AND GRANTEE<>'PUBLIC' AND GRANTEE NOT IN (SELECT USERNAME FROM DBA_USERS WHERE ORACLE_MAINTAINED='Y' UNION ALL SELECT ROLE FROM DBA_ROLES WHERE ORACLE_MAINTAINED='Y') ORDER BY 1")
    else   # 11g: ORACLE_MAINTAINED 열 없음 → 고정 목록 제외
        _sys_grants=$(run_q "SELECT GRANTEE||' → '||TABLE_NAME||' ('||PRIVILEGE||')' FROM DBA_TAB_PRIVS WHERE OWNER='SYS' AND GRANTEE NOT IN ('SYS','SYSTEM','PUBLIC','DBA','SELECT_CATALOG_ROLE') ORDER BY 1")
    fi
    evd_q "DBM-017" "SYS 테이블 접근 권한 (Oracle 기본 제공 계정·역할 제외)" "${_sys_grants:-해당 권한 없음} ($(printf '%s\n' "$_sys_grants" | grep -c .)건)"
    mc "017" "업무상 불필요한 시스템 뷰/테이블 접근 권한 수동 확인 ($(printf '%s\n' "$_sys_grants" | grep -c .)건, 증적 참조)"

    # DBM-019: 패스워드 재사용 제한
    # 평가기준: PASSWORD_REUSE_TIME, PASSWORD_REUSE_MAX 둘 다 UNLIMITED 이면 취약 (계정별 적용 프로파일)
    _it 019
    _p19m=$(_prof PASSWORD_REUSE_MAX); _p19t=$(_prof PASSWORD_REUSE_TIME)
    evd_q "DBM-019" "계정별 PASSWORD_REUSE_MAX / TIME" "$(echo "$_p19m" | _csv) / $(echo "$_p19t" | _csv)"
    _b19=$(_join_eq "$_p19m" "$_p19t" | awk -F= '$2=="UNLIMITED" && $3=="UNLIMITED" {print $1}')
    if [ -z "$_p19m" ]; then nc "019" "PASSWORD_REUSE 조회 결과 없음 - 수동 확인"
    elif [ -n "$_b19" ]; then ng "019" "PASSWORD_REUSE_MAX·TIME 모두 UNLIMITED 계정: $(_brief "$_b19" 20)${_xn}"
    else ok "019" "OPEN 계정 비밀번호 재사용 제한 적용 (REUSE_MAX 또는 REUSE_TIME 설정)${_xn}"; fi

    # DBM-020: 사용자별 계정 분리
    _it 020
    _user_list=$(run_qa "SELECT USERNAME||' ('||ACCOUNT_STATUS||', PROFILE='||PROFILE||')' FROM DBA_USERS WHERE ACCOUNT_STATUS IN ('OPEN','EXPIRED(GRACE)') ORDER BY USERNAME")
    evd_q "DBM-020" "OPEN·EXPIRED(GRACE) 사용자 목록 (CDB\$ROOT + [PDB])" "${_user_list:-없음}"
    mc "020" "사용자별 개별 계정 사용 여부 수동 확인 (사용자 $(printf '%s\n' "$_user_list" | grep -c .)개, 증적 참조)${_xn}"

    # DBM-021: 불필요한 ODBC/OLE-DB 데이터 소스 및 드라이버 제거 (Windows MSSQL 전용)
    _it 021
    na "021" "Windows MSSQL 전용 항목 (Oracle 해당 없음)"

    # DBM-022: 설정 파일 접근 권한 (바이너리 + 설정파일 종합)
    _it 022
    if _os_gate 022 "ORACLE_HOME 바이너리·network/admin·spfile/init/orapw 파일 권한"; then
        :
    else
        # 평가기준: [755] bin 주요 파일 group·others 쓰기 금지 / [644] network/admin *.ora group·others 쓰기·실행 금지 / [640] spfile·init·orapw group 쓰기·실행 및 others 권한 금지
        _B=$ORACLE_HOME/bin; local _nf="" _df="" _n _spf _g644 _g640 _asm=""
        for _n in $(_ora_net); do _nf="$_nf $_n/listener.ora $_n/sqlnet.ora $_n/tnsnames.ora $_n/protocol.ora"; done
        for _n in $(_ora_dbs); do _df="$_df $_n/spfile*.ora $_n/init*.ora $_n/orapw*"; done
        _spf=$(run_q "SELECT VALUE FROM V\$PARAMETER WHERE NAME='spfile'" | head -1)
        case "$_spf" in +*) _asm="$_spf"; _spf="" ;; esac   # ASM(+DG) 경로는 파일시스템 점검 대상 아님
        # shellcheck disable=SC2086
        evd_ls "DBM-022" $_B/oracle $_B/sqlplus $_B/sqlldr $_B/sqlload $_B/proc $_B/oraenv $_B/oerr $_B/exp $_B/imp $_B/tkprof $_B/tnsping $_B/wrap $_nf $_df $_spf
        # shellcheck disable=SC2086
        _perm_check 022 $_B/oracle $_B/sqlplus $_B/sqlldr $_B/sqlload $_B/proc $_B/oraenv $_B/oerr $_B/exp $_B/imp $_B/tkprof $_B/tnsping $_B/wrap; _o22=$_PC_BAD; _f22=$_PC_FOUND
        # shellcheck disable=SC2086
        _perm_check 033 $_nf; _o33=$_PC_BAD; _g644=$_PC_FOUND; _f22=$((_f22+_PC_FOUND))
        # shellcheck disable=SC2086,SC2046
        _perm_check 037 $(printf '%s\n' $_df $_spf | sort -u); _o37=$_PC_BAD; _g640=$_PC_FOUND; _f22=$((_f22+_PC_FOUND))
        if [ "$_f22" -eq 0 ]; then nc "022" "Oracle 설정 파일 미발견 - ORACLE_HOME(${ORACLE_HOME:-미설정}) 확인 필요"
        elif [ -n "$_o22$_o33$_o37" ]; then ng "022" "권한 기준 위반: ${_o22}${_o33}${_o37}"
        elif [ "$_g644" -eq 0 ] || [ "$_g640" -eq 0 ]; then
            nc "022" "일부 기준 파일을 찾지 못해 점검 불가 (network/admin 파일 ${_g644}개, spfile·init·orapw 파일 ${_g640}개 확인${_asm:+, spfile 이 ASM(${_asm})에 있어 파일시스템 점검 불가})"
        else ok "022" "기준 파일 ${_f22}개 권한 적절 (bin 755·network/admin 644·spfile/init/orapw 640 기준)"; fi
    fi

    # DBM-024: WITH GRANT OPTION
    # 평가기준 판단방법: 1) ADMIN_OPTION 시스템 권한 2) ADMIN_OPTION 역할 3) GRANTABLE 객체 권한 (Oracle 기본 제공 계정·역할 제외)
    _it 024
    if [ "${DB_MAJ:-0}" -ge 12 ] 2>/dev/null; then
        _grant_opts=$(run_qa "SELECT 'SYSPRIV:'||GRANTEE||':'||PRIVILEGE FROM DBA_SYS_PRIVS WHERE ADMIN_OPTION='YES' AND GRANTEE NOT IN (SELECT USERNAME FROM DBA_USERS WHERE ORACLE_MAINTAINED='Y' UNION ALL SELECT ROLE FROM DBA_ROLES WHERE ORACLE_MAINTAINED='Y') UNION ALL SELECT 'ROLE:'||GRANTEE||':'||GRANTED_ROLE FROM DBA_ROLE_PRIVS WHERE ADMIN_OPTION='YES' AND GRANTEE NOT IN (SELECT USERNAME FROM DBA_USERS WHERE ORACLE_MAINTAINED='Y' UNION ALL SELECT ROLE FROM DBA_ROLES WHERE ORACLE_MAINTAINED='Y') UNION ALL SELECT 'OBJ:'||GRANTEE||':'||OWNER||'.'||TABLE_NAME||':'||PRIVILEGE FROM DBA_TAB_PRIVS WHERE GRANTABLE='YES' AND GRANTEE NOT IN (SELECT USERNAME FROM DBA_USERS WHERE ORACLE_MAINTAINED='Y' UNION ALL SELECT ROLE FROM DBA_ROLES WHERE ORACLE_MAINTAINED='Y') AND OWNER NOT IN (SELECT USERNAME FROM DBA_USERS WHERE ORACLE_MAINTAINED='Y')")
    else   # 11g
        _grant_opts=$(run_q "SELECT 'SYSPRIV:'||GRANTEE||':'||PRIVILEGE FROM DBA_SYS_PRIVS WHERE ADMIN_OPTION='YES' AND GRANTEE NOT IN ('SYS','SYSTEM','DBA') UNION ALL SELECT 'ROLE:'||GRANTEE||':'||GRANTED_ROLE FROM DBA_ROLE_PRIVS WHERE ADMIN_OPTION='YES' AND GRANTEE NOT IN ('SYS','SYSTEM','DBA') UNION ALL SELECT 'OBJ:'||GRANTEE||':'||OWNER||'.'||TABLE_NAME||':'||PRIVILEGE FROM DBA_TAB_PRIVS WHERE GRANTABLE='YES' AND OWNER NOT IN ('SYS','SYSTEM','XDB','MDSYS','CTXSYS','ORDSYS','WMSYS','OLAPSYS','EXFSYS','DBSNMP','OUTLN','APEX_030200','FLOWS_FILES')")
    fi
    evd_q "DBM-024" "ADMIN_OPTION 시스템 권한·역할 / GRANTABLE 객체 권한 (Oracle 기본 제공 제외)" "${_grant_opts:-해당 없음}"
    mc "024" "WITH GRANT OPTION 부여 현황 수동 확인 ($(printf '%s\n' "$_grant_opts" | grep -c .)건, 증적 참조)"

    # DBM-025: EoS
    _it 025
    _ver_info=$(run_q "SELECT BANNER FROM V\$VERSION")
    evd_q "DBM-025" "Oracle 버전 정보 (EoS 판단용)" "${_ver_info:-${DB_VER}}"
    mc "025" "Oracle ${_ORA_VER} EoS 여부 수동 확인 (V\$VERSION 증적 참조)"

    # DBM-026: 구동 계정 umask
    _it 026
    if _os_gate 026 "Oracle 구동 계정 umask 는 서버 OS 설정"; then :; else _judge_umask_procs 026 "Oracle" 'ora_pmon_.*'; fi

    # DBM-028: 불필요 DB Object
    _it 028
    _pub_syn=$(run_qa "SELECT SYNONYM_NAME||' → '||TABLE_OWNER||'.'||TABLE_NAME FROM DBA_SYNONYMS WHERE OWNER='PUBLIC' AND TABLE_OWNER NOT IN ('SYS','SYSTEM','PUBLIC') ORDER BY 1")
    evd_q "DBM-028" "PUBLIC synonym (비시스템 소유)" "${_pub_syn:-해당 없음}"
    mc "028" "불필요 DB Object(PUBLIC synonym 등) 수동 확인 (PUBLIC synonym $(printf '%s\n' "$_pub_syn" | grep -c .)건, 증적 참조)"

    # DBM-029: 자원 사용 제한 (프로파일) — 평가기준: RESOURCE_LIMIT FALSE 이면 취약
    _it 029
    sess=$(run_q "SELECT LIMIT FROM DBA_PROFILES WHERE PROFILE='DEFAULT' AND RESOURCE_NAME='SESSIONS_PER_USER'" | tr -d ' \n')
    evd_q "DBM-029" "resource_limit / (참고) DEFAULT SESSIONS_PER_USER" "${_res_lim} / ${sess}"
    case "$(_up "$_res_lim")" in
    TRUE)  ok "029" "RESOURCE_LIMIT=TRUE (자원 사용 제한 활성)" ;;
    FALSE) ng "029" "RESOURCE_LIMIT=FALSE (자원 사용 제한 비활성)" ;;
    *)     nc "029" "RESOURCE_LIMIT 조회 결과 없음 - 수동 확인" ;;
    esac

    # DBM-030: Audit Table 접근 제어
    # 평가기준: AUD$ 소유자가 관리자 계정이 아니거나 일반 계정에 삽입/수정/삭제 권한이 있으면 취약 (SELECT·관리 롤은 제외)
    _it 030
    _aud_own=$(run_q "SELECT OWNER FROM DBA_TABLES WHERE TABLE_NAME='AUD\$'" | _csv)
    _aud_grants=$(run_qa "SELECT GRANTEE||' → '||TABLE_NAME||' ('||PRIVILEGE||')' FROM DBA_TAB_PRIVS WHERE TABLE_NAME IN ('AUD\$','FGA_LOG\$') AND PRIVILEGE IN ('INSERT','UPDATE','DELETE') AND GRANTEE NOT IN ('SYS','SYSTEM','DBA','DELETE_CATALOG_ROLE','AUDIT_ADMIN','AUDSYS') ORDER BY 1")
    evd_q "DBM-030" "AUD\$ 소유자 / 비관리 계정 INSERT·UPDATE·DELETE 권한" "owner=${_aud_own:-미확인} / ${_aud_grants:-없음}"
    if [ -n "$_aud_own" ] && ! echo "$_aud_own" | grep -qE '^(SYS|SYSTEM|AUDSYS)(,|$)'; then ng "030" "AUD\$ 소유자가 관리자 계정 아님: ${_aud_own}"
    elif [ -n "$_aud_grants" ]; then ng "030" "AUD\$ 수정/삭제 권한 보유 일반 계정: $(_brief "$_aud_grants" 20)"
    elif [ -z "$_aud_own" ]; then nc "030" "AUD\$ 소유자 조회 결과 없음 - 수동 확인"
    else ok "030" "AUD\$ 소유자 ${_aud_own}, 일반 계정 수정/삭제 권한 없음"; fi

    _it 031
    na "031" "MSSQL 전용 항목"

    # DBM-032: 통신구간 암호화 (SQLNET.ENCRYPTION_SERVER / 현재 세션 암호화 어댑터)
    _it 032
    _banner=$(run_qo "SELECT NETWORK_SERVICE_BANNER FROM V\$SESSION_CONNECT_INFO WHERE SID=SYS_CONTEXT('USERENV','SID')")
    if echo "$_banner" | grep -q "ORA-"; then _banner=""; fi
    _enc_sess=$(echo "$_banner" | grep -iE 'Encryption service adapter|TCPS|SSL' | head -1)
    if [ -n "$_MANAGED" ] || [ "$_REMOTE" = 1 ]; then
        # 관리형·원격: 서버 sqlnet.ora(관리형은 옵션 그룹 SQLNET.ENCRYPTION_SERVER / SSL 옵션)에 접근할 수 없으므로 이 접속 세션의 암호화 어댑터로 판정
        if [ -z "$_banner" ]; then nc "032" "V\$SESSION_CONNECT_INFO 조회 불가 - 세션 암호화 여부 확인 못 함 (관리형은 옵션 그룹의 SQLNET.ENCRYPTION_SERVER/SSL 옵션을 콘솔에서 확인)"
        elif [ -n "$_enc_sess" ]; then mc "032" "현재 접속 세션 암호화 적용(${_enc_sess}) - 서버 강제 여부(SQLNET.ENCRYPTION_SERVER=REQUIRED/옵션 그룹)는 콘솔에서 확인"
        else ng "032" "현재 접속 세션이 암호화 없이 연결됨(NETWORK_SERVICE_BANNER: $(echo "$_banner" | grep -iE 'Protocol|Adapter' | head -1 | cut -c1-120)) - 서버가 암호화를 요구하지 않음. 클라이언트 sqlnet.ora 에서 암호화 거부(REJECTED) 설정 시 오탐 가능"; fi
    else
        _ora_enc=""; _sf_used=""
        for _sf in $(for n in $(_ora_net); do echo "$n/sqlnet.ora"; done) "/etc/oracle/sqlnet.ora"; do
            [ -f "$_sf" ] || continue
            _sf_used="$_sf_used $_sf"
            _ora_enc=$(grep -iE '^[[:space:]]*SQLNET\.ENCRYPTION_SERVER[[:space:]]*=' "$_sf" </dev/null 2>/dev/null | tail -1 | grep -oiE "(REQUIRED|REQUESTED|ACCEPTED|REJECTED)" | head -1)
            [ -n "$_ora_enc" ] && break
        done
        if [ -n "$_sf_used" ]; then evd "DBM-032" "grep -iE '^[[:space:]]*SQLNET\\.(ENCRYPTION|CRYPTO_CHECKSUM)' $_sf_used"; else printf '[DBM-032] %s (대상 없음) sqlnet.ora 를 찾지 못함\n(대상 없음)\n\n' "$(date '+%H:%M:%S')" >> "$_EVD"; fi
        if [ -n "$_ora_enc" ]; then
            case "$(_up "$_ora_enc")" in
            REQUIRED)  ok "032" "SQLNET.ENCRYPTION_SERVER=REQUIRED (네트워크 암호화 강제)" ;;
            REQUESTED) ok "032" "SQLNET.ENCRYPTION_SERVER=REQUESTED (네트워크 암호화 요청)" ;;
            ACCEPTED)  mc "032" "SQLNET.ENCRYPTION_SERVER=ACCEPTED (기본값) - 클라이언트 설정에 따라 암호화 수동 확인" ;;
            REJECTED)  ng "032" "SQLNET.ENCRYPTION_SERVER=REJECTED (네트워크 암호화 거부)" ;;
            esac
        elif [ -z "$_sf_used" ]; then nc "032" "sqlnet.ora 를 찾지 못해 점검 불가 - 수동 확인"
        else mc "032" "SQLNET.ENCRYPTION_SERVER 미설정(주석 제외, 기본: ACCEPTED) - sqlnet.ora 수동 확인"; fi
    fi

    # DBM-033: 이중화 비밀번호 평문 노출 (Data Guard)
    _it 033
    _ora_dg=$(run_q "SELECT DEST_NAME||' (TYPE='||TYPE||')' FROM V\$ARCHIVE_DEST_STATUS WHERE STATUS='VALID' AND TYPE<>'LOCAL'")
    evd_q "DBM-033" "V\$ARCHIVE_DEST_STATUS (원격 전송)" "${_ora_dg:-해당 없음 (Data Guard 미구성)}"
    if [ -n "$_ora_dg" ]; then
        mc "033" "Data Guard 원격 전송 구성됨 - SSL/암호화 적용 여부 수동 확인 (증적 참조)"
    else
        na "033" "Data Guard/Streams 미구성"
    fi

    # DBM-034: DBMS 서비스 구동 권한
    _it 034
    if _os_gate 034 "Oracle 프로세스 구동 계정은 서버 OS 설정"; then :; else _judge_runuser 034 "Oracle" 'ora_pmon_.*'; fi

    _it 035
    na "035" "MSSQL 전용 항목"
    _it 036
    na "036" "MSSQL 전용 항목"
}

# ================================================================
# MySQL/MariaDB 점검
# ================================================================
check_mysql() {
    _ask_cred "MySQL/MariaDB" MYSQL_USER MYSQL_PASS "root" "소켓/OS 인증·~/.my.cnf 시도"
    MYSQL_USER="${MYSQL_USER:-root}"
    MYSQL_PASS="${MYSQL_PASS-}"
    MYSQL_HOST="${MYSQL_HOST:-localhost}"
    MYSQL_PORT="${MYSQL_PORT:-3306}"
    MYSQL_SOCKET="${MYSQL_SOCKET:-}"

    MYSQL_CMD=$(command -v mysql 2>/dev/null || command -v mariadb 2>/dev/null)
    if [ -z "$MYSQL_CMD" ]; then
        printf '[FALLBACK] %s mysql 클라이언트 미탐지 - MySQL 전 항목 점검불가 처리\n\n' "$(date '+%H:%M:%S')" >> "$_EVD"
        _CONN_WHY="mysql/mariadb 클라이언트 명령을 찾지 못함 (client 패키지 설치 또는 PATH 확인)"
        for i in 001 003 004 005 006 007 008 009 011 013 016 017 019 020 022 \
                 024 025 026 028 032 033 034; do nc "$i" "mysql/mariadb 클라이언트 명령을 찾지 못해 점검 불가 (client 패키지 설치 또는 PATH 확인)"; done
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
    DBMS_KIND="mysql"

    local _base
    if [ -n "$MYSQL_SOCKET" ]; then _base="-u ${MYSQL_USER} -S ${MYSQL_SOCKET}"
    elif [ "$MYSQL_HOST" = "localhost" ] && [ "$_REMOTE" != 1 ]; then _base="-u ${MYSQL_USER}"   # localhost = 유닉스 소켓
    else _base="-u ${MYSQL_USER} -h ${MYSQL_HOST} -P ${MYSQL_PORT}"; fi
    _base="$_base --batch ${MYSQL_EXTRA_OPTS:-}"
    OPTS="$_base"

    # $1=선택 여부(0 엄격/1 선택) $2=SQL → 결과 행(열 이름 줄 제외). 오류 시 엄격=출력 없음+오류 기록, 선택=오류 줄 출력
    _mq() {
        local _o _e _rc _ef="$_TMPD/mysql.err" _first
        # shellcheck disable=SC2086
        _o=$($MYSQL_CMD $OPTS -e "$2" 2>"$_ef"); _rc=$?
        _e=$(sed 's/\r$//' "$_ef" 2>/dev/null)
        _o=$(printf '%s\n' "$_o" | grep -v '^$')
        _qrecord "$2" "$_o" "$_e" "$_rc"
        if [ "$_rc" != 0 ] || printf '%s\n' "$_e" | grep -q '^ERROR'; then
            _first=$(printf '%s\n' "$_e" | grep '^ERROR' | head -1); [ -z "$_first" ] && _first=$(printf '%s\n' "$_e" | head -1)
            [ -z "$_first" ] && _first="mysql 종료코드 ${_rc}"
            if [ "$1" = 1 ]; then printf '%s\n' "$_first"; else _qerr_add "$_first"; fi
            return 1
        fi
        printf '%s\n' "$_o" | sed '1d'
    }
    run_q()  { _mq 0 "$1"; }
    run_qo() { _mq 1 "$1"; }
    get_var() { run_q "SHOW VARIABLES LIKE '$1'" | awk -F'\t' '{print $2}'; }
    _gv2() { local v; v=$(get_var "$1"); [ -z "$v" ] && v=$(get_var "$2"); echo "$v"; }   # 8.0 점 표기 / 5.7 밑줄 표기 변수명
    _it "DBM-000"
    # 비밀번호 미지정: 소켓/OS 인증(auth_socket·unix_socket)·~/.my.cnf·빈 비밀번호 순으로 먼저 시도 (원격은 건너뜀)
    if [ -z "$MYSQL_PASS" ] && [ "$_REMOTE" != 1 ] && run_qo "SELECT CONCAT('CONN_','OK')" | grep -q CONN_OK; then
        :
    else
        [ -z "$MYSQL_PASS" ] && [ -t 0 ] && { read -rs -p "MySQL ${MYSQL_USER} 비밀번호: " MYSQL_PASS </dev/tty; echo >&2; }
        if [ -n "$MYSQL_PASS" ] || [ -n "$MYSQL_USER" ]; then
            _MYSQL_CNF="$_TMPD/client.cnf"
            # 옵션 파일 값은 큰따옴표로 감싸고 \ " 를 이스케이프 (비밀번호에 # ; @ / \ " 가 있어도 안전)
            ( umask 077; printf '[client]\nuser="%s"\n%s\n' "$(printf '%s' "$MYSQL_USER" | sed 's/\\/\\\\/g; s/"/\\"/g')" \
                "${MYSQL_PASS:+password=\"$(printf '%s' "$MYSQL_PASS" | sed 's/\\/\\\\/g; s/"/\\"/g')\"}" > "$_MYSQL_CNF" )
            chmod 600 "$_MYSQL_CNF" 2>/dev/null
            OPTS="--defaults-extra-file=${_MYSQL_CNF} ${_base/-u ${MYSQL_USER}/}"
        fi
    fi

    _conn_ok "$(run_q "SELECT CONCAT('CONN_','OK')")" "MySQL/MariaDB" || return
    DB_VER=$(run_q "SELECT VERSION()" | head -1)
    IS_MARIADB=0; echo "$DB_VER" | grep -qi "mariadb" && IS_MARIADB=1
    [ $IS_MARIADB -eq 1 ] && DBMS_KIND="mariadb"
    _hnote "# MySQL/MariaDB 버전: ${DB_VER}"
    # 관리형 구분 보정: Aurora MySQL 은 @@aurora_version 이 있음
    if [ "$_MANAGED" = "rds" ]; then
        _av=$(run_qo "SELECT @@aurora_version")
        if [ -n "$_av" ] && ! _qo_err "$_av" "1193"; then _MANAGED_LABEL="Aurora-MySQL"; fi
    fi
    # 관리형 예약 계정 (계정 점검에서 제외)
    _MYX="'mysql.session','mysql.sys','mysql.infoschema','mariadb.sys'"
    _MYXN=""
    if [ -n "$_MANAGED" ]; then
        _MYX="${_MYX},'rdsadmin','rdsrepladmin','rds_superuser_role','azure_superuser','azuresu'"
        _MYXN=" (관리형 예약 계정 제외: rdsadmin, rdsrepladmin, rds_superuser_role)"
    fi
    # mysql.user 열 구성 (버전별: 5.5 Password / 5.7+ authentication_string / account_locked 5.7.6+)
    _cols=$(run_q "SELECT COLUMN_NAME FROM information_schema.COLUMNS WHERE TABLE_SCHEMA='mysql' AND TABLE_NAME='user' AND COLUMN_NAME IN ('plugin','authentication_string','Password','account_locked')")
    _E_PLUGIN="''"; echo "$_cols" | grep -qx plugin && _E_PLUGIN="IFNULL(plugin,'')"
    _hA=0; _hP=0; echo "$_cols" | grep -qx authentication_string && _hA=1; echo "$_cols" | grep -qx Password && _hP=1
    if [ $_hA = 1 ] && [ $_hP = 1 ]; then _E_HASH="COALESCE(NULLIF(authentication_string,''),NULLIF(Password,''),'')"
    elif [ $_hA = 1 ]; then _E_HASH="IFNULL(authentication_string,'')"
    elif [ $_hP = 1 ]; then _E_HASH="IFNULL(Password,'')"
    else _E_HASH="''"; fi
    _E_LOCK="'N'"; echo "$_cols" | grep -qx account_locked && _E_LOCK="IFNULL(account_locked,'N')"
    _MY_COLS_ERR=$(_qerr_first)
    # 권한 프로브: mysql.user 를 못 읽는 계정은 information_schema(USER_PRIVILEGES·SCHEMATA 등)도 자기에게 보이는 행만 돌려줘
    #   '0건/없음' 이 실제 0건이 아님 → 해당 항목은 양호/없음 대신 점검불가 (오류 원문은 증적)
    _MY_LIMITED=""; _lim=$(run_qo "SELECT COUNT(*) FROM mysql.user")
    if printf '%s\n' "$_lim" | grep -qE '^ERROR'; then _MY_LIMITED=$(printf '%s\n' "$_lim" | sed -n '1p'); fi

    # DBM-001: 취약 패스워드 + 인증 플러그인 검증
    # 익명 계정 / 빈 비밀번호 / 자주 쓰는 약한 비밀번호(root·password·mysql·admin·123456·계정명 등, mysql_native_password SHA1 해시 비교 — 해시 값은 출력하지 않음)
    _it 001
    anon=$(run_q "SELECT COUNT(*) FROM mysql.user WHERE User=''" | tail -1)
    _empty=$(run_q "SELECT CONCAT(User,'@',Host) FROM mysql.user WHERE User<>'' AND User NOT IN (${_MYX}) AND ${_E_LOCK}<>'Y' AND ${_E_HASH}='' AND ${_E_PLUGIN} IN ('','mysql_native_password','caching_sha2_password','sha256_password','mysql_old_password') ORDER BY 1")
    _wl=""; for _w in root password mysql admin 123456 1234 12345678 qwerty test; do _wl="${_wl:+$_wl,}CONCAT('*',UPPER(SHA1(UNHEX(SHA1('${_w}')))))"; done
    _weakpw=$(run_q "SELECT CONCAT(User,'@',Host) FROM mysql.user WHERE User<>'' AND User NOT IN (${_MYX}) AND ${_E_LOCK}<>'Y' AND ${_E_PLUGIN} IN ('','mysql_native_password') AND ${_E_HASH} LIKE '*%' AND (${_E_HASH}=CONCAT('*',UPPER(SHA1(UNHEX(SHA1(User))))) OR ${_E_HASH} IN (${_wl})) ORDER BY 1")
    _weak_auth=$(run_qo "SELECT CONCAT(User,'@',Host,' (',${_E_PLUGIN},')') FROM mysql.user WHERE ${_E_PLUGIN} NOT IN ('caching_sha2_password','sha256_password','auth_socket','unix_socket','mysql_native_password','ed25519','client_ed25519','pam','auth_pam','authentication_pam','mysql_no_login') AND User NOT IN (${_MYX}) ORDER BY 1")
    _qo_err "$_weak_auth" "1054" && _weak_auth=""
    evd_q "DBM-001" "익명 계정 수 / 빈 비밀번호 계정 / 약한 비밀번호(해시 비교) 계정 / 비안전 플러그인 계정" "익명 ${anon:-?}개 / ${_empty:-없음} / ${_weakpw:-없음} / ${_weak_auth:-없음}"
    if [ "${anon:-0}" -gt 0 ] 2>/dev/null || [ -n "$_empty" ] || [ -n "$_weakpw" ]; then
        ng "001" "$( [ "${anon:-0}" -gt 0 ] 2>/dev/null && echo "익명 계정 ${anon}개 ")${_empty:+빈 비밀번호 계정: $(_brief "$_empty" 20) }${_weakpw:+약한(기본/계정명/흔한) 비밀번호 계정: $(_brief "$_weakpw" 20)}${_MYXN}"
    else
        mc "001" "익명·빈 비밀번호·흔한 약한 비밀번호 계정 없음 - 계정 비밀번호 복잡도·취약 비밀번호 여부는 해시 크랙으로 확인 필요${_weak_auth:+ (참고: 비권장 인증 플러그인 계정 $(_brief "$_weak_auth" 10))}${_MYXN}"
    fi

    # DBM-003: 불필요 계정
    _it 003
    _all_users=$(run_q "SELECT CONCAT(User,'@',Host,' (',${_E_PLUGIN},')') FROM mysql.user ORDER BY User")
    evd_q "DBM-003" "mysql.user 전체 계정" "$(printf '%s\n' "$_all_users" | grep -c .)개"
    mc "003" "불필요/미사용 계정 수동 확인 (계정 $(printf '%s\n' "$_all_users" | grep -c .)개, 증적 참조)${_MYXN}"

    # DBM-004: 불필요 관리자 계정
    # 평가기준: Global 수준 권한 부여 계정 목록 → 인터뷰 (mysql.user 전역 *_priv='Y')
    _it 004
    super=$(run_q "SELECT CONCAT(User,'@',Host) FROM mysql.user WHERE User NOT IN (${_MYX},'') AND (Super_priv='Y' OR Grant_priv='Y' OR Create_user_priv='Y' OR Process_priv='Y' OR File_priv='Y' OR Shutdown_priv='Y' OR Reload_priv='Y' OR Insert_priv='Y' OR Update_priv='Y' OR Delete_priv='Y' OR Drop_priv='Y' OR Alter_priv='Y') ORDER BY 1")
    evd_q "DBM-004" "Global 수준 권한 보유 계정" "$super"
    mc "004" "Global 수준 권한 계정: $(_brief "${super:-없음}" 20) - 업무상 필요 여부 인터뷰 확인${_MYXN}"

    # DBM-005: 중요정보 암호화
    _it 005
    _enc_info=$(run_q "SELECT TABLE_SCHEMA,TABLE_NAME,CREATE_OPTIONS FROM information_schema.TABLES WHERE CREATE_OPTIONS LIKE '%ENCRYPTION%'")
    _tde=$(get_var default_table_encryption); [ -z "$_tde" ] && _tde=$(get_var innodb_encrypt_tables)
    evd_q "DBM-005" "ENCRYPTION 옵션 사용 테이블 / default_table_encryption(innodb_encrypt_tables)" "${_enc_info:-암호화 테이블 없음} / ${_tde:-미지원}"
    mc "005" "중요 컬럼(주민번호, 비밀번호 등) 암호화 여부 수동 확인 (암호화 테이블 $(printf '%s\n' "$_enc_info" | grep -c .)개, 기본 테이블 암호화=${_tde:-미지원}; 증적 참조)"

    # DBM-006: 로그인 실패 횟수
    # 평가기준: 5회 연속 로그인 실패 시 일정시간 접속 제한 (failed_login_attempts≤5 또는 connection_control 플러그인)
    #   max_connect_errors 는 호스트 연결 오류 카운터로 로그인 실패 잠금이 아님 → 판정에 사용하지 않음
    _it 006
    _fla_o=$(run_qo "SELECT CONCAT(User,'@',Host,'=',IFNULL(JSON_EXTRACT(User_attributes,'\$.Password_locking.failed_login_attempts'),0),'/',IFNULL(JSON_EXTRACT(User_attributes,'\$.Password_locking.password_lock_time_days'),0)) FROM mysql.user WHERE ${_E_LOCK}='N' AND User NOT IN (${_MYX},'') AND ${_E_PLUGIN} NOT IN ('auth_socket','unix_socket') ORDER BY 1")
    _fla=""; _fla_err=""
    if _qo_err "$_fla_o" "1054|1064"; then _fla_err="$_fla_o"; else _fla="$_fla_o"; fi   # User_attributes: 8.0.19+ (그 외 버전은 열 없음 1054)
    _cc=$(run_q "SELECT PLUGIN_NAME,PLUGIN_STATUS FROM information_schema.PLUGINS WHERE PLUGIN_NAME LIKE 'CONNECTION_CONTROL%'")
    _cct=$(get_var "connection_control_failed_connections_threshold")
    evd_q "DBM-006" "failed_login_attempts / connection_control" "failed_login_attempts: ${_fla:-${_fla_err:-미설정}} / plugin: ${_cc:-미로드} / threshold=${_cct:-N/A} / max_connect_errors(참고)=$(get_var max_connect_errors)"
    # 로그인 가능 계정별 failed_login_attempts(0=미설정) 5 초과/미설정 또는 lock_time 0 → 위반
    _fla_bad=$(echo "$_fla" | awk -F= '{split($NF,a,"/")} a[1]+0==0 || a[1]+0>5 || a[2]+0==0')
    _mpe=""; [ "$IS_MARIADB" = "1" ] && _mpe=$(get_var "max_password_errors")
    # MariaDB 10.4+: max_password_errors 1~5 양호, 5 초과(기본 4294967295 포함) 취약
    if [ -n "$_mpe" ]; then
        evd_q "DBM-006" "MariaDB max_password_errors" "$_mpe"
        if [ "$_mpe" -ge 1 ] 2>/dev/null && [ "$_mpe" -le 5 ] 2>/dev/null; then ok "006" "MariaDB max_password_errors=${_mpe}"
        else ng "006" "MariaDB max_password_errors=${_mpe} (5 초과 - 로그인 실패 잠금 미흡)"; fi
    elif [ -n "$_fla" ] && [ -z "$_fla_bad" ]; then
        ok "006" "로그인 가능 계정 모두 failed_login_attempts≤5·잠금 시간 설정: $(_brief "$_fla" 20)${_MYXN}"
    elif [ -n "$_cct" ] && [ "$_cct" -gt 0 ] 2>/dev/null && [ "$_cct" -le 5 ] 2>/dev/null; then
        mc "006" "connection_control 플러그인(연속 실패 ${_cct}회 시 응답 지연) - 기준의 접속 제한(잠금/차단) 해당 여부 확인 / 계정 잠금 미설정: $(_brief "$_fla_bad" 20)"
    elif [ -n "$_fla_err" ]; then
        ng "006" "계정 잠금 기능 미지원 버전(${DB_VER}, failed_login_attempts 는 8.0.19+) - connection_control·장비·솔루션 적용 시 수동 확인"
    else
        ng "006" "계정 잠금 미설정/5회 초과 계정(failed_login_attempts/lock_days): $(_brief "${_fla_bad:-전체}" 20) - 서비스 운영 계정은 평가 제외 가능, 외부 솔루션 적용 시 수동 확인${_MYXN}"
    fi

    # DBM-007: 패스워드 복잡도
    # 평가기준 복잡도: 2종 10자 이상 / 3종 8자 이상 — 플러그인 로드 + 길이·문자 종류 설정값 확인
    _it 007
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
        policy=$(_gv2 "validate_password.policy" "validate_password_policy")
        vlen=$(_gv2 "validate_password.length" "validate_password_length")
        evd_q "DBM-007" "validate_password.policy(5.7: validate_password_policy) / length" "${policy:-미설치} / ${vlen:-}"
        if [ -z "$policy" ]; then
            ng "007" "validate_password 플러그인/컴포넌트 미설치 - 솔루션 사용 시 수동 확인"
        else
            case "$(_up "$policy")" in
            STRONG|2|MEDIUM|1)   # MEDIUM 이상: mixed_case/number/special_char_count 로 요구 문자 종류 산정 → 3종 8자 / 2종 10자
                local _mc _nc _sc _k=0
                _mc=$(_gv2 "validate_password.mixed_case_count" "validate_password_mixed_case_count"); _nc=$(_gv2 "validate_password.number_count" "validate_password_number_count"); _sc=$(_gv2 "validate_password.special_char_count" "validate_password_special_char_count")
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
    _it 008
    expire=$(get_var "default_password_lifetime")
    _plc=""; _plc_err=""
    if [ $IS_MARIADB -eq 0 ]; then   # password_last_changed 는 5.7.4+ — 열 없음(1054)만 '변경일 미제공', 다른 오류는 점검불가
        _plc_o=$(run_qo "SELECT CONCAT(User,'@',Host,'=',DATE(password_last_changed)) FROM mysql.user WHERE ${_E_LOCK}='N' AND User NOT IN (${_MYX},'') AND ${_E_PLUGIN} NOT IN ('auth_socket','unix_socket') AND password_last_changed < NOW()-INTERVAL 90 DAY ORDER BY 1")
        if _qo_err "$_plc_o" "1054"; then _plc_err="$_plc_o"; else _plc="$_plc_o"; fi
    fi
    evd_q "DBM-008" "default_password_lifetime / password_last_changed 90일 경과 계정(auth_socket 제외)" "${expire:-미지원} / ${_plc:-없음}${_plc_err:+ ($_plc_err)}"
    if [ $IS_MARIADB -eq 0 ] && [ -n "$_plc" ]; then
        ng "008" "최근 비밀번호 변경 후 90일 이상 경과 계정: $(_brief "$_plc" 20) - 서비스 운영 계정은 평가 제외 가능${_MYXN}"
    elif [ $IS_MARIADB -eq 0 ] && [ -n "$_plc_err" ]; then
        if [ "${expire:-0}" -gt 0 ] 2>/dev/null && [ "$expire" -le 90 ] 2>/dev/null; then ok "008" "변경일 미제공 - default_password_lifetime=${expire}일(90일 이하 만료)"
        else mc "008" "비밀번호 변경일(password_last_changed) 미제공 버전(${DB_VER}) - 인터뷰·증적으로 90일 내 변경 여부 확인"; fi
    elif [ $IS_MARIADB -eq 0 ]; then
        ok "008" "로그인 가능 계정(auth_socket 제외) 모두 90일 이내 비밀번호 변경 (password_last_changed, lifetime=${expire:-0})${_MYXN}"
    elif [ -z "$expire" ]; then
        mc "008" "default_password_lifetime 미지원(MariaDB 10.4 미만, ${DB_VER}) - 인터뷰·증적으로 90일 내 변경 여부 확인"
    elif [ "$expire" = "0" ]; then
        ng "008" "default_password_lifetime=0 (비밀번호 만료 없음)"
    elif [ "$expire" -le 90 ] 2>/dev/null; then
        ok "008" "default_password_lifetime=${expire}일 (90일 이하)"
    else
        ng "008" "default_password_lifetime=${expire}일 (90일 초과)"
    fi

    # DBM-009: 미사용 세션 종료
    _it 009
    timeout=$(get_var "wait_timeout")
    itimeout=$(get_var "interactive_timeout")
    evd_q "DBM-009" "wait_timeout / interactive_timeout" "wait_timeout=${timeout:-조회 실패}, interactive_timeout=${itimeout:-조회 실패}"
    if [ -z "$timeout" ] && [ -z "$itimeout" ]; then nc "009" "wait_timeout/interactive_timeout 조회 결과 없음 - 수동 확인"
    else
        _t_max=${timeout:-28800}; [ "${itimeout:-28800}" -gt "$_t_max" ] 2>/dev/null && _t_max=$itimeout
        if [ "$_t_max" -le 900 ] 2>/dev/null; then ok "009" "wait_timeout=${timeout}초, interactive_timeout=${itimeout}초"
        else ng "009" "세션 타임아웃 초과 (wait=${timeout}, interactive=${itimeout}, 900초(15분) 이하 - 내부 규정 미명시 시 15분 기준)"; fi
    fi

    # DBM-011: 감사 로그 (MariaDB server_audit·MySQL audit_log 플러그인·RDS 옵션/Aurora 파라미터 server_audit_logging 포함)
    _it 011
    glog=$(get_var "general_log")
    alog=$(get_var "audit_log_policy")
    _sa_log=$(get_var "server_audit_logging")
    _sa_ev=$(get_var "server_audit_events")
    _apl=$(run_q "SELECT PLUGIN_NAME,PLUGIN_STATUS FROM information_schema.PLUGINS WHERE PLUGIN_NAME IN ('audit_log','SERVER_AUDIT') OR PLUGIN_NAME LIKE '%audit%'")
    evd_q "DBM-011" "audit 플러그인 / audit_log_policy / server_audit_logging(events) / general_log(참고)" "plugin: ${_apl:-미로드} / policy=${alog:-N/A} / server_audit=${_sa_log:-OFF}(${_sa_ev:-N/A}) / general_log=${glog}"
    # 평가기준: 감사 로그(audit_log 플러그인 등) 수집 + 주기적 백업(인터뷰). general_log 는 감사 로그가 아님
    if echo "$_apl" | awk -F'\t' '$2=="ACTIVE"{f=1} END{exit !f}' || echo "$(_up "$alog")" | grep -qE "ALL|LOGINS|QUERIES" || [ "$(_up "$_sa_log")" = "ON" ]; then
        mc "011" "감사 로그 수집 중 (plugin=$(echo "$_apl" | awk -F'\t' '$2=="ACTIVE"{print $1}' | _csv), server_audit=${_sa_log:-N/A}${_MANAGED:+; 관리형: 로그 게시(CloudWatch 등)·보관 기간 콘솔 확인}) - 주기적 백업 여부 인터뷰/증적 확인"
    else
        ng "011" "감사 로그 플러그인 비활성/미로드 (general_log=${glog:-OFF}는 감사 로그 아님)${_MANAGED:+ - 관리형은 옵션 그룹(MARIADB_AUDIT_PLUGIN)/파라미터 그룹(server_audit_logging)에서 활성화} - 써드파티 솔루션 사용 시 수동 확인"
    fi

    # DBM-013: 원격 접속 접근 제어
    # 평가기준: mysql.user Host 칼럼이 '%' 인 계정 존재 시 취약 (bind_address 는 참고 증적)
    _it 013
    bind=$(get_var "bind_address")
    _wild_host=$(run_q "SELECT CONCAT(User,'@',Host) FROM mysql.user WHERE Host='%' AND User NOT IN ('') AND User NOT IN (${_MYX}) ORDER BY 1")
    evd_q "DBM-013" "host='%' 계정 / bind_address(참고)" "${_wild_host:-없음} / bind_address=${bind:-미설정}"
    case "$bind" in
    "127.0.0.1"|"localhost"|"::1") ok "013" "bind_address=${bind} (로컬 접속만 허용)" ;;
    *) if [ -n "$_wild_host" ]; then ng "013" "Host='%' 원격 접속 허용 계정: $(_brief "$_wild_host" 20)${_MANAGED:+ - 관리형은 보안그룹/NACL 로 네트워크 접근을 함께 제한해야 함}${_MYXN}"
       else ok "013" "Host='%' 계정 없음 (계정별 접속 호스트 제한, bind_address=${bind:-기본})${_MYXN}"; fi ;;
    esac

    # DBM-016: 보안패치
    _it 016
    evd_q "DBM-016" "MySQL/MariaDB 버전 (패치 판단용)" "${DB_VER}"
    mc "016" "MySQL/MariaDB ${DB_VER} 보안패치 적용 현황 수동 확인"

    # DBM-017: 시스템 테이블 접근 권한
    _it 017
    _db_grants=$(run_q "SELECT CONCAT(User,'@',Host,' → *.* (global SELECT)') FROM mysql.user WHERE Select_priv='Y' AND User NOT IN ('root',${_MYX},'') UNION ALL SELECT CONCAT(User,'@',Host,' → ',Db,'.* (',Select_priv,Insert_priv,Update_priv,Delete_priv,')') FROM mysql.db WHERE ('mysql' LIKE Db OR 'sys' LIKE Db OR 'performance_schema' LIKE Db) AND User NOT IN ('root',${_MYX},'') UNION ALL SELECT CONCAT(User,'@',Host,' → ',Db,'.',Table_name,' (',Table_priv,')') FROM mysql.tables_priv WHERE Db IN ('mysql','sys','performance_schema') AND User NOT IN ('root',${_MYX},'')")
    evd_q "DBM-017" "시스템 DB 접근 권한 (비시스템 계정)" "${_db_grants:-해당 없음}"
    mc "017" "information_schema, mysql 데이터베이스 접근 권한 수동 확인 ($(printf '%s\n' "$_db_grants" | grep -c .)건, 증적 참조)${_MYXN}"

    # DBM-019: 패스워드 재사용
    _it 019
    if [ $IS_MARIADB -eq 0 ]; then
        _pw_hist=$(run_qo "SELECT @@global.password_history")
        _pw_reuse=$(run_qo "SELECT @@global.password_reuse_interval")
        evd_q "DBM-019" "password_history / password_reuse_interval" "${_pw_hist:-?} / ${_pw_reuse:-?}"
        # 평가기준: password_history 가 0 이거나 password_reuse_interval 이 0 이면 취약 → 둘 다 설정되어야 양호
        if _qo_err "$_pw_hist" "1193"; then
            mc "019" "password_history 미지원(MySQL 8.0.3 미만, ${DB_VER}) - 플러그인·솔루션·내부 정책으로 재사용 제한 여부 확인(미제한 시 취약)"
        elif _qo_err "$_pw_reuse" "1193"; then
            mc "019" "password_reuse_interval 미지원 - 재사용 제한 여부 수동 확인"
        elif [ "${_pw_hist:-0}" -gt 0 ] 2>/dev/null && [ "${_pw_reuse:-0}" -gt 0 ] 2>/dev/null; then
            ok "019" "password_history=${_pw_hist}, password_reuse_interval=${_pw_reuse}일"
        else
            ng "019" "비밀번호 재사용 제한 미흡 (password_history=${_pw_hist:-0}, password_reuse_interval=${_pw_reuse:-0} - 둘 다 설정 필요)"
        fi
    else
        _prc=$(run_q "SELECT PLUGIN_STATUS FROM information_schema.PLUGINS WHERE PLUGIN_NAME='password_reuse_check'" | head -1)
        _pri=$(get_var password_reuse_check_interval)
        evd_q "DBM-019" "MariaDB password_reuse_check 플러그인" "${_prc:-미설치} (interval=${_pri})"
        if [ "$_prc" = "ACTIVE" ]; then ok "019" "password_reuse_check 플러그인 활성 (password_reuse_check_interval=${_pri}일, 0=기간 제한 없이 이력 재사용 금지)"
        else mc "019" "MariaDB password_reuse_check 미사용 - 플러그인·솔루션·내부 정책으로 재사용 제한 여부 확인(미제한 시 취약)"; fi
    fi

    # DBM-020: 사용자별 계정 분리
    _it 020
    _my_users=$(run_q "SELECT CONCAT(User,'@',Host) FROM mysql.user WHERE User NOT IN (${_MYX},'') ORDER BY User")
    evd_q "DBM-020" "전체 사용자 목록" "${_my_users:-조회 결과 없음}"
    mc "020" "공용 계정 사용 여부 수동 확인 (사용자 $(printf '%s\n' "$_my_users" | grep -c .)개, 증적 참조)${_MYXN}"

    # DBM-021: 불필요한 ODBC/OLE-DB 데이터 소스 및 드라이버 제거 (Windows MSSQL 전용)
    _it 021
    na "021" "Windows MSSQL 전용 항목 (MySQL/MariaDB 해당 없음)"

    # DBM-022: 설정 파일 권한
    _it 022
    if _os_gate 022 "my.cnf 등 설정 파일 권한"; then
        :
    else
        # 평가기준 640: group 쓰기·실행 및 others 권한 금지 (심볼릭 링크는 대상 파일 권한)
        _mycnfs="/etc/my.cnf /etc/my.ini /etc/my.cnf.d/*.cnf /etc/mysql/my.cnf /etc/mysql/conf.d/*.cnf /etc/mysql/mysql.conf.d/*.cnf /etc/mysql/mariadb.conf.d/*.cnf /var/lib/mysql/my.cnf /etc/mysql/mariadb.cnf /etc/mysql/debian.cnf"
        # shellcheck disable=SC2086
        evd_ls "DBM-022" $_mycnfs
        # shellcheck disable=SC2086
        _perm_check 037 $_mycnfs; _b22=$_PC_BAD
        if [ "$_PC_FOUND" -eq 0 ]; then
            nc "022" "MySQL 설정 파일(my.cnf 등)을 찾지 못해 점검 불가 - 설정 파일 위치 수동 확인"
        elif [ -n "$_b22" ]; then
            ng "022" "설정 파일 권한 기준(640) 위반: ${_b22}"
        else
            ok "022" "설정 파일 ${_PC_FOUND}개 권한 640 기준 충족"
        fi
    fi

    # DBM-024: WITH GRANT OPTION
    _it 024
    _gx=""; [ -n "$_MANAGED" ] && _gx=",'rdsadmin','rdsrepladmin','rds_superuser_role','azure_superuser','azuresu'"
    _grant_users=$(run_q "SELECT CONCAT(GRANTEE,' ',PRIVILEGE_TYPE,' ON *.*') FROM information_schema.USER_PRIVILEGES WHERE IS_GRANTABLE='YES' AND SUBSTRING_INDEX(REPLACE(GRANTEE,CHAR(39),''),'@',1) NOT IN ('root','mariadb.sys'${_gx}) AND REPLACE(GRANTEE,CHAR(39),'') NOT LIKE 'mysql.%' UNION ALL SELECT CONCAT(GRANTEE,' ',PRIVILEGE_TYPE,' ON ',TABLE_SCHEMA,'.*') FROM information_schema.SCHEMA_PRIVILEGES WHERE IS_GRANTABLE='YES' UNION ALL SELECT CONCAT(GRANTEE,' ',PRIVILEGE_TYPE,' ON ',TABLE_SCHEMA,'.',TABLE_NAME) FROM information_schema.TABLE_PRIVILEGES WHERE IS_GRANTABLE='YES'")
    evd_q "DBM-024" "IS_GRANTABLE=YES 권한 (전역·DB·테이블, root·시스템 계정 제외)" "${_grant_users:-해당 없음}"
    if [ -n "$_MY_LIMITED" ]; then
        _qerr_add "$_MY_LIMITED"; nc "024" "접속 계정이 mysql.user 를 조회할 수 없어 다른 계정의 GRANT OPTION 보유 여부를 확인하지 못함 (information_schema 는 본인에게 보이는 권한만 반환하므로 ${_grant_users:+조회된 $(printf '%s\n' "$_grant_users" | grep -c .)건은 일부, }0건이어도 실제 0건 아님) - ${_MY_LIMITED}"
    else
        mc "024" "GRANT OPTION 부여 현황 수동 확인 ($(printf '%s\n' "$_grant_users" | grep -c .)건, 증적 참조)${_MYXN}"
    fi

    # DBM-025: EoS
    _it 025
    _eos_judge "$( [ $IS_MARIADB -eq 1 ] && echo mariadb || echo mysql )" "$DB_VER"
    evd_q "DBM-025" "MySQL/MariaDB 버전 (EoS 판단용)" "${DB_VER} → ${EOS_RES}: ${EOS_WHY}"
    if [ "$EOS_RES" = "취약" ] && [ -n "$_MANAGED" ]; then mc "025" "커뮤니티 기준 ${EOS_WHY} - 관리형(${_MANAGED_LABEL})은 벤더 지원 일정(RDS Extended Support 포함)을 콘솔에서 확인"
    elif [ "$EOS_RES" = "취약" ]; then ng "025" "MySQL/MariaDB ${EOS_WHY}"
    else mc "025" "MySQL/MariaDB ${EOS_WHY}"; fi

    # DBM-026: 구동 계정 umask
    _it 026
    if _os_gate 026 "mysqld 구동 계정 umask 는 서버 OS 설정"; then :; else _judge_umask_procs 026 "MySQL" 'mysqld|mariadbd'; fi

    # DBM-028: 불필요 DB Object
    _it 028
    test_db=$(run_q "SELECT COUNT(*) FROM information_schema.SCHEMATA WHERE SCHEMA_NAME='test'" | tail -1)
    _schemas=$(run_q "SELECT SCHEMA_NAME FROM information_schema.SCHEMATA WHERE SCHEMA_NAME NOT IN ('mysql','information_schema','performance_schema','sys')")
    evd_q "DBM-028" "test DB 존재 여부 / 사용자 스키마 목록" "test=${test_db:-?} / ${_schemas:-없음}"
    if [ "${test_db:-0}" -gt 0 ] 2>/dev/null; then ng "028" "test 데이터베이스 존재 (제거 권고)"
    elif [ -n "$_MY_LIMITED" ]; then _qerr_add "$_MY_LIMITED"; nc "028" "접속 계정 권한 부족으로 일부 스키마만 보여 test DB 존재 여부를 확인하지 못함 (보이는 스키마: $(_brief "${_schemas:-없음}" 20)) - ${_MY_LIMITED}"
    else mc "028" "test DB 없음 - 인가되지 않은 Object 존재 여부 인터뷰 확인 (스키마: $(_brief "${_schemas:-없음}" 20))"; fi

    _it 012; na "012" "Oracle 전용 항목 (Listener Control Utility)"
    _it 014; na "014" "Oracle 전용 항목 (OS_ROLES/REMOTE_OS_ROLES)"
    _it 015; na "015" "Oracle/MSSQL 전용 항목 (PUBLIC Role)"
    _it 029; na "029" "Oracle 전용 항목 (자원 프로파일)"
    _it 030; na "030" "Oracle/Tibero 전용 항목 (감사 테이블)"
    _it 031; na "031" "MSSQL 전용 항목"

    # DBM-032: 통신구간 암호화 (SSL/TLS) — have_ssl 은 8.0.26 deprecated·8.4 제거 → 세션 Ssl_cipher·ssl_cert·tls_version 으로 보완
    _it 032
    _have_ssl=$(get_var "have_ssl")
    _require_ssl=$(get_var "require_secure_transport")
    _tlsv=$(get_var "tls_version"); _sslcert=$(get_var "ssl_cert")
    _cipher=$(run_q "SHOW SESSION STATUS LIKE 'Ssl_cipher'" | awk -F'\t' '{print $2}')
    evd_q "DBM-032" "have_ssl / require_secure_transport / tls_version / ssl_cert / 현재 세션 Ssl_cipher" "have_ssl=${_have_ssl:-(변수 없음)} / require_secure_transport=${_require_ssl:-미설정} / tls_version=${_tlsv:-N/A} / ssl_cert=${_sslcert:-N/A} / Ssl_cipher=${_cipher:-(비어 있음)}"
    case "$(_up "$_require_ssl")" in
    ON|1) ok "032" "SSL 필수 (require_secure_transport=ON, tls_version=${_tlsv:-N/A})" ;;
    *)
        if [ "$(_up "$_have_ssl")" = "YES" ] || [ -n "$_cipher" ] || { [ -n "$_sslcert" ] && [ "$(_up "$_have_ssl")" != "DISABLED" ]; }; then
            mc "032" "SSL 가능하나 필수 아님 (have_ssl=${_have_ssl:-N/A}, 세션 Ssl_cipher=${_cipher:-없음}, require_secure_transport=${_require_ssl:-OFF})${_MANAGED:+ - 관리형은 파라미터 그룹에서 require_secure_transport=ON 설정 권고}"
        elif [ "$(_up "$_have_ssl")" = "DISABLED" ] || [ "$(_up "$_have_ssl")" = "NO" ]; then
            ng "032" "SSL 미지원 (have_ssl=${_have_ssl})"
        else
            mc "032" "SSL 지원 여부 판별 불가 (have_ssl 변수 없음, 세션 Ssl_cipher 없음, ssl_cert 없음) - 수동 확인"
        fi ;;
    esac

    # DBM-033: 이중화 비밀번호 평문 노출
    # 평가기준: slave_master_info(테이블/파일)에 비밀번호 평문 저장 시 취약, 동적 입력(START REPLICA ... PASSWORD) 시 양호
    _it 033
    _repl_o=$(run_qo "SELECT CONCAT(Host,' user=',User_name,' pw=',IF(IFNULL(User_password,'')='','없음','저장됨')) FROM mysql.slave_master_info")
    _repl_info=""
    if _qo_err "$_repl_o" "1146|1049"; then _repl_info=""; else _repl_info="$_repl_o"; fi
    _mi_file=""
    if [ "$_REMOTE" != 1 ] && [ -n "$(get_var datadir)" ]; then _mi_file=$(ls "$(get_var datadir)"/master.info 2>/dev/null); fi
    evd_q "DBM-033" "slave_master_info 비밀번호 저장 여부 / master.info 파일" "${_repl_info:-행 없음(또는 테이블 없음: ${_repl_o})} / ${_mi_file:-없음}$( [ "$_REMOTE" = 1 ] && echo ' (원격/관리형: 파일 미점검)')"
    if echo "$_repl_info" | grep -q "pw=저장됨" || { [ -n "$_mi_file" ] && [ "$(sed -n 6p "$_mi_file" 2>/dev/null)" != "" ]; }; then
        ng "033" "복제 연결 비밀번호 평문 저장: $(echo "$_repl_info" | _csv)${_mi_file:+ / $_mi_file}"
    elif [ -n "$_repl_info" ]; then
        ok "033" "복제 구성, 비밀번호 미저장(동적 입력): $(echo "$_repl_info" | _csv)"
    elif [ -n "$(_qerr_first)" ]; then
        nc "033" "복제 설정(mysql.slave_master_info) 조회 불가로 이중화 구성 여부 확인 못함 - $(_qerr_first) (증적의 SQL·오류 원문 참조)"
    else
        na "033" "이중화(복제) 미구성"
    fi

    # DBM-034: DBMS 서비스 구동 권한 (프로세스 UID + 설정파일 user 지시자 교차검증, mysqld_exporter 등 유사 이름 제외)
    _it 034
    if _os_gate 034 "mysqld 구동 계정은 서버 OS 설정"; then
        :
    else
        evd_ps "DBM-034" 'mysqld|mariadbd'
        mysql_proc=$(_proc_users 'mysqld|mariadbd')
        _mycnf_user=""
        for _mcf in /etc/my.cnf /etc/my.ini /etc/my.cnf.d/mysql-server.cnf /etc/mysql/my.cnf /etc/mysql/mysql.conf.d/mysqld.cnf /etc/mysql/mariadb.cnf; do
            [ -f "$_mcf" ] || continue
            _mu=$(awk '/^[[:space:]]*\[/{sec=$0} tolower(sec)~"\\[mysqld\\]" && /^[[:space:]]*user[[:space:]]*=/{sub(/.*=[[:space:]]*/,""); sub(/[[:space:]]*[#;].*/,""); print; exit}' "$_mcf" 2>/dev/null)
            [ -n "$_mu" ] && { _mycnf_user="$_mu"; break; }
        done
        if [ -n "$mysql_proc" ]; then
            if printf ' %s ' "$mysql_proc" | grep -q ' root ' || [ "$_mycnf_user" = "root" ]; then
                ng "034" "MySQL root 실행 (proc=${mysql_proc}, cnf user=${_mycnf_user:-미설정})"
            else
                ok "034" "MySQL 구동 계정: proc=${mysql_proc}, cnf user=${_mycnf_user:-미설정}"
            fi
        elif [ -n "$_mycnf_user" ]; then
            [ "$_mycnf_user" = "root" ] && ng "034" "[mysqld] user=root 설정됨 (프로세스 미확인)" || ok "034" "[mysqld] user=${_mycnf_user} (프로세스 미확인)"
        else
            nc "034" "mysqld/mariadbd 프로세스와 설정 파일 user 지시자를 모두 확인하지 못해 점검 불가"
        fi
    fi

    _it 035; na "035" "MSSQL 전용 항목"
    _it 036; na "036" "MSSQL 전용 항목"
}

# ================================================================
# PostgreSQL 점검
# ================================================================
check_pgsql() {
    _ask_cred "PostgreSQL" PGSQL_USER PGPASSWORD "postgres" "peer 인증·~/.pgpass 시도"
    [ -n "$PGPASSWORD" ] && export PGPASSWORD
    PGSQL_USER="${PGSQL_USER:-postgres}"
    PGSQL_DB="${PGSQL_DB:-postgres}"
    PGSQL_HOST="${PGSQL_HOST-}"
    PGSQL_PORT="${PGSQL_PORT:-5432}"

    PSQL=$(command -v psql 2>/dev/null)
    if [ -z "$PSQL" ]; then
        printf '[FALLBACK] %s psql 미탐지 - PostgreSQL 전 항목 점검불가 처리\n\n' "$(date '+%H:%M:%S')" >> "$_EVD"
        _CONN_WHY="psql 명령을 찾지 못함 (postgresql-client 설치 또는 PATH 확인)"
        for i in 001 003 004 005 006 007 008 009 011 013 015 016 017 019 020 022 \
                 024 025 026 028 032 033 034; do nc "$i" "psql 명령을 찾지 못해 점검 불가 (postgresql-client 설치 또는 PATH 확인)"; done
        na "012" "Oracle 전용 항목"; na "014" "Oracle 전용 항목"
        na "021" "Windows MSSQL 전용 항목"
        na "029" "Oracle 전용 항목"; na "030" "Oracle/Tibero 전용 항목"
        na "031" "MSSQL 전용 항목"
        na "035" "MSSQL 전용 항목"; na "036" "MSSQL 전용 항목"
        return
    fi
    DBMS_KIND="pgsql"

    # 접속 순서: PGSQL_HOST 지정 → 그대로 / 비밀번호(PGPASSWORD·PGPASSFILE·~/.pgpass) 있으면 localhost / 없으면 소켓+peer(root 는 구동 계정으로) → localhost
    _PG_OS=""; _PG_HOSTS="$PGSQL_HOST"
    if [ -z "$PGSQL_HOST" ]; then
        if [ -n "$PGPASSWORD$PGPASSFILE" ] || [ -f "$HOME/.pgpass" ]; then _PG_HOSTS="localhost"
        else
            _PG_HOSTS="@sock localhost"
            [ "$(id -u)" = 0 ] && _PG_OS=$(_ps_ucp | awk '{n=$3; sub(/.*\//,"",n)} n=="postgres"||n=="postmaster"{print $1; exit}')
            [ "$_PG_OS" = "root" ] && _PG_OS=""
        fi
    fi
    # shellcheck disable=SC2086
    _pg_exec() { if [ -n "$_PG_OS" ] && [ "$_PGH" = "@sock" ]; then _su_run "$_PG_OS" "\"$PSQL\" $OPTS -f -"; else "$PSQL" $OPTS -f -; fi; }
    # $1=선택 여부(0 엄격/1 선택) $2=SQL → 결과 행(열 이름 줄 제외). 오류 시 엄격=출력 없음+오류 기록, 선택=오류 줄 출력
    _pq() {
        local _o _e _rc _ef="$_TMPD/pg.err" _first
        _o=$(printf '%s\n' "$2" | _pg_exec 2>"$_ef"); _rc=$?
        _e=$(sed 's/\r$//' "$_ef" 2>/dev/null)
        _o=$(printf '%s\n' "$_o" | grep -v '^$')
        _qrecord "$2" "$_o" "$_e" "$_rc"
        if [ "$_rc" != 0 ] || printf '%s\n' "$_e" | grep -qE 'ERROR:|FATAL:'; then
            _first=$(printf '%s\n' "$_e" | grep -E 'ERROR:|FATAL:' | head -1 | sed 's/^.*\(ERROR:\|FATAL:\)/\1/')
            [ -z "$_first" ] && _first=$(printf '%s\n' "$_e" | head -1 | sed 's/^psql: //; s/^error: //; s/^/FATAL: /')
            [ "$_first" = "FATAL: " ] && _first="FATAL: psql 종료코드 ${_rc}"
            if [ "$1" = 1 ]; then printf '%s\n' "$_first"; else _qerr_add "$_first"; fi
            return 1
        fi
        printf '%s\n' "$_o" | sed '1d'
    }
    run_q()  { _pq 0 "$1"; }
    run_qo() { _pq 1 "$1"; }
    get_conf() { run_q "SHOW $1"; }
    _pg_guc() { local v; v=$(run_qo "SHOW $1"); if _qo_err "$v" "unrecognized configuration parameter"; then echo ""; else echo "$v"; fi; }   # 모듈 미로드 시 없는 설정은 빈 값
    _pg_set_opts() { OPTS="-X -w -U ${PGSQL_USER} $( [ "$1" != "@sock" ] && echo "-h $1") -p ${PGSQL_PORT} -d ${PGSQL_DB} -A -P footer=off -v ON_ERROR_STOP=1"; }

    _it "DBM-000"
    local _pgc=""
    for _PGH in $_PG_HOSTS; do
        _pg_set_opts "$_PGH"
        _pgc=$(run_qo "SELECT 'CONN_'||'OK'"); echo "$_pgc" | grep -q CONN_OK && break
    done
    if ! echo "$_pgc" | grep -q CONN_OK && [ -t 0 ] && [ -z "$PGPASSWORD" ]; then
        read -rs -p "PostgreSQL ${PGSQL_USER} 비밀번호: " PGPASSWORD </dev/tty; echo >&2; export PGPASSWORD
        _PGH="${PGSQL_HOST:-localhost}"; _pg_set_opts "$_PGH"
    fi
    : > "$_QERRF"
    _hnote "# PostgreSQL 접속: ${_PGH}${_PG_OS:+ (OS 계정 ${_PG_OS})}"
    _conn_ok "$(run_q "SELECT 'CONN_'||'OK'")" "PostgreSQL" || return
    DB_VER=$(run_q "SELECT version()" | head -1)
    _hnote "# PostgreSQL 버전: ${DB_VER}"
    # 관리형 구분 보정: Aurora PostgreSQL 은 aurora_version() 이 있음
    if [ "$_MANAGED" = "rds" ]; then
        _av=$(run_qo "SELECT aurora_version()")
        if [ -n "$_av" ] && ! _qo_err "$_av" "does not exist"; then _MANAGED_LABEL="Aurora-PgSQL"; fi
    fi
    # 관리형 예약 역할 (계정 점검에서 제외)
    _PGX="'__none__'"; _PGXN=""
    if [ -n "$_MANAGED" ]; then
        _PGX="'rdsadmin','rdsrepladmin','rds_superuser','rds_replication','rds_password','rds_iam','rds_ad','rds_reserved','rds_pgaudit','azure_pg_admin','azuresu','azure_superuser'"
        _PGXN=" (관리형 예약 역할 제외: rdsadmin, rdsrepladmin, rds_superuser 등)"
    fi

    # DBM-001: 취약 패스워드
    # 빈 비밀번호(md5(''||계정명)) 는 취약, 비밀번호 NULL 역할은 비밀번호 인증 불가 → trust 규칙 적용 시에만 취약
    _it 001
    no_pw=$(run_q "SELECT usename FROM pg_shadow WHERE (passwd='' OR passwd='md5'||md5(''||usename)) AND usename NOT IN (${_PGX}) ORDER BY 1")
    _nullpw=$(run_q "SELECT usename FROM pg_shadow WHERE passwd IS NULL AND usename NOT IN (${_PGX}) ORDER BY 1")
    _trust_o=$(run_qo "SELECT type||' '||array_to_string(user_name,',')||' '||coalesce(address,'') FROM pg_hba_file_rules WHERE error IS NULL AND auth_method='trust' AND type<>'local' AND coalesce(address,'') NOT IN ('127.0.0.1','::1','localhost')")
    _trust=""; _trust_err=""
    if _qo_err "$_trust_o" "permission denied|does not exist"; then _trust_err="$_trust_o"; else _trust="$_trust_o"; fi   # pg_hba_file_rules: 슈퍼유저 전용 (관리형은 접근 불가)
    evd_q "DBM-001" "빈 비밀번호 계정 / 비밀번호 NULL 역할 / 원격 trust 규칙" "${no_pw:-없음} / ${_nullpw:-없음} / ${_trust:-${_trust_err:-없음}}"
    if [ -n "$no_pw" ]; then ng "001" "빈 비밀번호 계정: $(_brief "$no_pw" 20)${_PGXN}"
    elif [ -n "$_trust" ]; then ng "001" "원격 trust 인증 규칙(비밀번호 없이 접속): $(_brief "$_trust" 10)"
    else mc "001" "빈 비밀번호·원격 trust 없음 (비밀번호 미설정 역할: $(_brief "${_nullpw:-없음}" 20))${_trust_err:+ [pg_hba 규칙은 조회 권한 없어 미확인]} - 비밀번호 복잡도·취약 비밀번호 여부는 해시 크랙으로 확인 필요${_PGXN}"; fi

    # DBM-003: 불필요 계정
    _it 003
    _pg_roles=$(run_q "SELECT rolname||' (login='||rolcanlogin||', super='||rolsuper||')' FROM pg_roles ORDER BY rolname")
    evd_q "DBM-003" "pg_roles 전체 역할" "$(printf '%s\n' "$_pg_roles" | grep -c .)개"
    mc "003" "불필요 계정 수동 확인 (역할 $(printf '%s\n' "$_pg_roles" | grep -c .)개, 증적 참조)${_PGXN}"

    # DBM-004: 불필요 관리자
    # 평가기준: rolsuper·rolcreaterole·rolcreatedb·rolreplication 부여 계정 목록 → 인터뷰
    _it 004
    supers=$(run_q "SELECT rolname||'('||concat_ws(',',CASE WHEN rolsuper THEN 'super' END,CASE WHEN rolcreaterole THEN 'createrole' END,CASE WHEN rolcreatedb THEN 'createdb' END,CASE WHEN rolreplication THEN 'replication' END)||')' FROM pg_roles WHERE (rolsuper OR rolcreaterole OR rolcreatedb OR rolreplication) AND rolname NOT LIKE 'pg\\_%' AND rolname NOT IN (${_PGX}) ORDER BY 1")
    evd_q "DBM-004" "관리자 속성(super/createrole/createdb/replication) 보유 계정" "${supers:-없음}"
    mc "004" "관리자 권한 계정: $(_brief "${supers:-없음}" 20) - 업무상 필요 여부 인터뷰 확인${_PGXN}"

    # DBM-005: 암호화
    _it 005
    _pgcrypto=$(run_q "SELECT extname||' ('||extversion||')' FROM pg_extension WHERE extname IN ('pgcrypto','pgsodium')")
    evd_q "DBM-005" "암호화 확장(pgcrypto/pgsodium) 설치 여부" "${_pgcrypto:-암호화 확장 미설치}"
    mc "005" "중요 컬럼 암호화 여부 수동 확인 (암호화 확장: ${_pgcrypto:-미설치}; 증적 참조)"

    # DBM-006: 로그인 실패 제한 (PostgreSQL은 기본 제한 없음 - pg_auth_mon 또는 fail2ban)
    _it 006
    _pg_authmon=$(run_q "SELECT extname FROM pg_extension WHERE extname='pg_auth_mon'" | head -1)
    evd_q "DBM-006" "pg_auth_mon 확장 여부" "${_pg_authmon:-미설치 (PostgreSQL 기본 미지원)}"
    mc "006" "로그인 실패 횟수 제한은 PostgreSQL 기본 미지원 - fail2ban 또는 pg_auth_mon 설정 수동 확인"

    # DBM-007: 패스워드 복잡도 + SCRAM-SHA-256 검증
    _it 007
    _pg_spl=$(get_conf "shared_preload_libraries")
    _pg_pwext=$(run_q "SELECT extname FROM pg_extension WHERE extname IN ('credcheck','supautils')" | head -1)
    # 평가기준: passwordcheck.so 로드 + 설정이 복잡도(2종 10자/3종 8자) 충족. 기본 passwordcheck 는 8자·문자+비문자(2종 8자)라 미달
    _pw_enc=$(get_conf "password_encryption")
    _pc_len=$(_pg_guc "passwordcheck.min_password_length")
    evd_q "DBM-007" "shared_preload_libraries / passwordcheck.min_password_length / (참고) password_encryption" "${_pg_spl:-없음} / ${_pc_len:-N/A} / ${_pw_enc}"
    if echo "$_pg_spl" | grep -qi "passwordcheck" && [ "${_pc_len:-0}" -ge 10 ] 2>/dev/null; then
        ok "007" "passwordcheck 로드, min_password_length=${_pc_len} (문자+비문자 2종 10자 이상)"
    elif [ -n "$_pg_pwext" ] || echo "$_pg_spl" | grep -qi "credcheck"; then
        mc "007" "복잡도 모듈 로드(${_pg_spl}${_pg_pwext:+, $_pg_pwext}) - 설정값(최소 길이·문자 종류) 확인"
    elif echo "$_pg_spl" | grep -qi "passwordcheck"; then   # PG17 이하 passwordcheck = 고정 규칙(8자·문자+비문자), min_password_length 는 PG18+
        ng "007" "passwordcheck 기본 규칙(최소 ${_pc_len:-8}자·문자+비문자 2종) - 2종 10자/3종 8자 미달 (cracklib 빌드·솔루션 사용 시 수동 확인)"
    else
        ng "007" "passwordcheck/credcheck 미로드 (복잡도 미강제)${_MANAGED:+ - 관리형은 지원 확장·IAM/AD 인증 정책을 콘솔에서 확인} - 솔루션 사용 시 수동 확인"
    fi

    # DBM-008: 패스워드 만료 (VALID UNTIL)
    # 평가기준: PostgreSQL 은 비밀번호 변경일자·만료 정책을 제공하지 않으므로 인터뷰/증적으로 판단
    _it 008
    _pg_noexpiry=$(run_q "SELECT rolname||' (valid_until='||coalesce(rolvaliduntil::text,'없음')||')' FROM pg_roles WHERE rolcanlogin AND rolname NOT IN (${_PGX}) ORDER BY 1")
    evd_q "DBM-008" "로그인 계정 VALID UNTIL (참고)" "${_pg_noexpiry:-없음}"
    mc "008" "PostgreSQL 비밀번호 변경일 미제공 - 최근 90일 내 변경 여부 인터뷰/증적 확인 (서비스 계정 평가 제외 가능; 로그인 역할 $(printf '%s\n' "$_pg_noexpiry" | grep -c .)개 VALID UNTIL 증적 참조)${_PGXN}"

    # DBM-009: 세션 타임아웃 (PG14+ idle_session_timeout 포함)
    # 평가기준: idle_in_transaction_session_timeout 미설정 또는 부적절(내부 규정 미명시 시 15분) → 취약 (ms 단위 비교)
    _it 009
    _t_ms=$(run_q "SELECT setting FROM pg_settings WHERE name='idle_in_transaction_session_timeout'" | head -1)
    _s_ms=$(run_q "SELECT setting FROM pg_settings WHERE name='idle_session_timeout'" | head -1)
    evd_q "DBM-009" "idle_in_transaction_session_timeout(ms) / idle_session_timeout(ms, 참고)" "${_t_ms:-조회 결과 없음} / ${_s_ms:-N/A}"
    if [ -z "$_t_ms" ]; then nc "009" "idle_in_transaction_session_timeout 설정을 조회하지 못함 (PG 9.6 미만 등) - 수동 확인"
    elif [ "${_t_ms:-0}" -gt 0 ] 2>/dev/null && [ "$_t_ms" -le 900000 ] 2>/dev/null; then
        ok "009" "idle_in_transaction_session_timeout=$((_t_ms/1000))초 (15분 이하)"
    elif [ "${_t_ms:-0}" -gt 900000 ] 2>/dev/null; then
        ng "009" "idle_in_transaction_session_timeout=$((_t_ms/1000))초 (15분 초과 - 내부 규정 미명시 시 15분 기준)"
    else
        ng "009" "idle_in_transaction_session_timeout 미설정(0) - 접근제어 솔루션으로 세션 종료 시 수동 확인"
    fi

    # DBM-011: 감사 로그 (logging_collector 포함)
    # 평가기준: pg_audit 등 플러그인·솔루션으로 감사 로그 수집 + 주기적 백업(인터뷰). 접속 로그는 참고 증적
    _it 011
    _log_col=$(get_conf "logging_collector"); log_conn=$(get_conf "log_connections"); log_disco=$(get_conf "log_disconnections")
    _pga=$(_pg_guc "pgaudit.log")
    _pg_spl=$(run_qo "SHOW shared_preload_libraries"); _spl_err=""   # 일반 계정은 PG15+ 에서 읽기 거부 → 빈 값을 '미로드'로 오판하지 않고 점검불가
    if printf '%s\n' "$_pg_spl" | grep -qE '^(ERROR|FATAL)'; then _spl_err="$_pg_spl"; _pg_spl=""; fi
    evd_q "DBM-011" "shared_preload_libraries / pgaudit.log / (참고) logging_collector·log_connections·log_disconnections" "${_pg_spl:-${_spl_err:-없음}} / ${_pga:-N/A} / ${_log_col}·${log_conn}·${log_disco}"
    if [ -n "$_spl_err" ] && ! { [ -n "$_pga" ] && [ "$(_low "$_pga")" != "none" ]; }; then
        _qerr_add "$_spl_err"; nc "011" "shared_preload_libraries 를 조회하지 못해 pgaudit 로드 여부 확인 불가 (권한 부족: superuser 또는 pg_read_all_settings 필요) - ${_spl_err}"
    elif echo "$_pg_spl" | grep -qi "pgaudit" && [ -n "$_pga" ] && [ "$(_low "$_pga")" != "none" ]; then
        mc "011" "pgaudit 감사 로그 수집 중 (pgaudit.log=${_pga})${_MANAGED:+, 관리형: 로그 게시·보관 기간(rds.log_retention_period 등) 콘솔 확인} - 주기적 백업 여부 인터뷰/증적 확인"
    else
        ng "011" "pgaudit 미로드/미설정 - 감사 로그 미수집 (접속 로그 logging_collector=${_log_col})${_MANAGED:+ - 관리형은 파라미터 그룹 shared_preload_libraries 에 pgaudit 추가 후 pgaudit.log 설정} - 써드파티 솔루션 사용 시 수동 확인"
    fi

    _it 012
    na "012" "Oracle 전용 항목 (Listener Control Utility)"

    # DBM-013: 원격 접속
    # 평가기준: pg_hba.conf ADDRESS 0.0.0.0/0 레코드 존재 시 취약 (listen_addresses 는 참고 증적)
    _it 013
    if [ -n "$_MANAGED" ]; then
        _os_gate 013 "pg_hba.conf 는 관리형 서비스가 관리 - 보안그룹·네트워크 ACL·rds.force_ssl 로 접근 통제"
    else
        listen=$(get_conf "listen_addresses")
        evd_q "DBM-013" "listen_addresses(참고)" "$listen"
        _hba_skip=""; _hba_wild=""
        _hba_o=$(run_qo "SELECT 'line '||line_number||' '||type||' '||coalesce(address,'')||coalesce('/'||netmask,'')||' '||auth_method FROM pg_hba_file_rules WHERE error IS NULL AND type<>'local' AND auth_method<>'reject' AND (lower(coalesce(address,''))='all' OR coalesce(netmask,'x') IN ('0.0.0.0','::')) ORDER BY line_number")
        if _qo_err "$_hba_o" "permission denied|does not exist"; then   # PG 9.x 또는 뷰 권한 없음 → hba_file 직접 (로컬 서버일 때만)
            _hf=$(run_q "SHOW hba_file" | head -1)
            if [ "$_REMOTE" != 1 ] && [ -r "$_hf" ]; then
                evd "DBM-013" "grep -v '^[[:space:]]*#' '$_hf'"
                _hba_wild=$(awk '!/^[[:space:]]*#/ && $1 ~ /^host/ && $NF!="reject" && ($4=="all" || $4=="0.0.0.0/0" || $4=="::/0" || ($4=="0.0.0.0" && $5=="0.0.0.0")) {print FILENAME":"FNR" "$0}' "$_hf" 2>/dev/null)
            else _hba_skip=1; _qerr_add "pg_hba_file_rules 조회 권한 없음/원격이라 pg_hba.conf 파일 직접 확인 불가: ${_hba_o}"; fi
        else _hba_wild="$_hba_o"; fi
        evd_q "DBM-013" "pg_hba 전체 IP 허용 규칙" "${_hba_wild:-없음}"
        if [ -n "$_hba_wild" ]; then
            ng "013" "pg_hba.conf 전체 IP 허용 규칙: $(_brief "$_hba_wild" 5)"
        elif [ -n "$_hba_skip" ]; then
            nc "013" "pg_hba.conf ADDRESS 0.0.0.0/0 레코드 수동 확인 필요"
        else
            case "${listen}" in
            "localhost"|"127.0.0.1"|"::1") ok "013" "listen_addresses=${listen} (로컬 접속만 허용), pg_hba.conf 전체 IP 허용 규칙 없음" ;;
            *) ok "013" "pg_hba.conf 전체 IP(0.0.0.0/0, ::/0) 허용 규칙 없음 (listen_addresses=${listen:-기본})" ;;
            esac
        fi
    fi

    _it 014
    na "014" "Oracle 전용 항목 (OS_ROLES/REMOTE_OS_ROLES)"

    # DBM-015: PUBLIC 불필요 권한
    _it 015
    _pg_pub_exec=$(run_q "SELECT n.nspname||'.'||p.proname FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace CROSS JOIN LATERAL aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a WHERE a.grantee=0 AND a.privilege_type='EXECUTE' AND n.nspname NOT IN ('pg_catalog','information_schema') ORDER BY 1")
    _pg_dbs=$(run_q "SELECT datname FROM pg_database WHERE datallowconn AND NOT datistemplate AND has_database_privilege(datname,'CONNECT') AND datname NOT IN ('rdsadmin','azure_maintenance','azure_sys') ORDER BY 1")
    evd_q "DBM-015" "점검 대상 DB (접속 가능·템플릿 제외)" "$(echo "$_pg_dbs" | _csv)"
    _pg_pub_create=""; _pg_pub_tbl=""
    for _d in $_pg_dbs; do   # PUBLIC 권한은 DB 별 카탈로그 — 전 DB 순회 (has_schema_privilege 의 PUBLIC 은 소문자 'public')
        _pg_pub_create="${_pg_pub_create}$(OPTS="${OPTS/-d ${PGSQL_DB}/-d $_d}" run_q "SELECT '$_d:'||nspname||' (CREATE)' FROM pg_namespace WHERE nspname='public' AND has_schema_privilege('public',nspname,'CREATE')")
"
        _pg_pub_tbl="${_pg_pub_tbl}$(OPTS="${OPTS/-d ${PGSQL_DB}/-d $_d}" run_q "SELECT '$_d:'||n.nspname||'.'||c.relname||' ('||a.privilege_type||')' FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace CROSS JOIN LATERAL aclexplode(c.relacl) a WHERE a.grantee=0 AND c.relkind IN ('r','v','m','p','f') AND n.nspname NOT IN ('pg_catalog','information_schema') AND n.nspname NOT LIKE 'pg\\_toast%' ORDER BY 1")
"
    done
    _pg_pub_create=$(echo "$_pg_pub_create" | grep -v "^$"); _pg_pub_tbl=$(echo "$_pg_pub_tbl" | grep -v "^$")
    evd_q "DBM-015" "PUBLIC EXECUTE / CREATE(public 스키마) / 테이블 권한 (비시스템)" "EXECUTE: ${_pg_pub_exec:-없음} / CREATE: ${_pg_pub_create:-없음} / TABLE: ${_pg_pub_tbl:-없음}"
    if [ -n "$_pg_pub_tbl" ] || [ -n "$_pg_pub_exec" ] || [ -n "$_pg_pub_create" ]; then
        mc "015" "PUBLIC Object 권한: $(_brief "$(printf '%s\n%s\n%s\n' "$_pg_pub_tbl" "$_pg_pub_exec" "$_pg_pub_create" | grep -v '^$')" 10) - 업무상 필요 여부 확인"
    else
        ok "015" "PUBLIC 에 사용자 Object 권한 없음 (점검 DB: $(echo "$_pg_dbs" | _csv))"
    fi

    # DBM-016: 보안패치
    _it 016
    evd_q "DBM-016" "PostgreSQL 버전 (패치 판단용)" "${DB_VER}"
    mc "016" "PostgreSQL 보안패치 수동 확인 (위 버전 참조)"

    # DBM-017: 시스템 테이블 접근
    _it 017
    _pg_sys_grants=$(run_q "SELECT c.relname||' → '||CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(a.grantee) END||' ('||a.privilege_type||')' FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace CROSS JOIN LATERAL aclexplode(c.relacl) a WHERE n.nspname='pg_catalog' AND c.relkind IN ('r','v','m') AND a.grantee<>c.relowner AND (a.grantee=0 OR (pg_get_userbyid(a.grantee) NOT LIKE 'pg\\_%' AND pg_get_userbyid(a.grantee) NOT IN (${_PGX}))) AND NOT (a.grantee=0 AND a.privilege_type='SELECT' AND c.relname NOT IN ('pg_authid','pg_shadow','pg_statistic','pg_user_mapping','pg_hba_file_rules','pg_file_settings')) AND NOT (a.grantee=0 AND c.relname='pg_settings' AND a.privilege_type='UPDATE') ORDER BY 1")
    evd_q "DBM-017" "pg_catalog 테이블·뷰 비기본 접근 권한 (소유자·pg_ 기본 역할·PUBLIC 기본 SELECT 제외)" "${_pg_sys_grants:-별도 부여 없음 (기본 권한만)}"
    mc "017" "pg_shadow, pg_authid 등 시스템 카탈로그 접근 권한 수동 확인 ($(printf '%s\n' "$_pg_sys_grants" | grep -c .)건, 증적 참조)${_PGXN}"

    # DBM-019: 패스워드 재사용
    _it 019
    evd_q "DBM-019" "PostgreSQL 패스워드 재사용 제한" "PostgreSQL 기본 미지원 (외부 모듈 필요)"
    mc "019" "PostgreSQL 패스워드 재사용 제한 수동 설정 확인"

    # DBM-020: 계정 분리
    _it 020
    _pg_login=$(run_q "SELECT rolname||' (super='||rolsuper||')' FROM pg_roles WHERE rolcanlogin AND rolname NOT IN (${_PGX}) ORDER BY rolname")
    evd_q "DBM-020" "로그인 가능 계정 목록" "${_pg_login:-조회 결과 없음}"
    mc "020" "공용 계정 사용 여부 수동 확인 (로그인 역할 $(printf '%s\n' "$_pg_login" | grep -c .)개, 증적 참조)${_PGXN}"

    # DBM-021: 불필요한 ODBC/OLE-DB 데이터 소스 및 드라이버 제거 (Windows MSSQL 전용)
    _it 021
    na "021" "Windows MSSQL 전용 항목 (PostgreSQL 해당 없음)"

    # DBM-022: 설정 파일 권한 (DB에서 경로 조회 → 실제 파일 권한 확인)
    _it 022
    if _os_gate 022 "postgresql.conf·pg_hba.conf·pg_ident.conf 권한"; then
        :
    else
        _pg_config=$(run_q "SHOW config_file" | head -1)
        _pg_hba=$(run_q "SHOW hba_file" | head -1)
        _pg_ident=$(run_q "SHOW ident_file" | head -1)
        # 평가기준 640: postgresql.conf·pg_hba.conf·pg_ident.conf 의 group 쓰기·실행 및 others 권한 금지
        evd_ls "DBM-022" "$_pg_config" "$_pg_hba" "$_pg_ident"
        _perm_check 037 "$_pg_config" "$_pg_hba" "$_pg_ident"; _b22=$_PC_BAD
        if [ "$_PC_FOUND" -eq 0 ]; then
            nc "022" "PostgreSQL 설정 파일(config_file=${_pg_config:-?})을 읽을 수 없어 점검 불가 - 수동 확인"
        elif [ -n "$_b22" ]; then
            ng "022" "설정 파일 권한 기준(640) 위반: ${_b22}"
        else
            ok "022" "postgresql.conf·pg_hba.conf·pg_ident.conf 권한 640 기준 충족 (${_PC_FOUND}개)"
        fi
    fi

    # DBM-024: WITH GRANT OPTION
    _it 024
    _pg_grants=""
    for _d in ${_pg_dbs:-$PGSQL_DB}; do
        _pg_grants="${_pg_grants}$(OPTS="${OPTS/-d ${PGSQL_DB}/-d $_d}" run_q "SELECT '$_d:table:'||pg_get_userbyid(a.grantee)||' '||n.nspname||'.'||c.relname||' '||a.privilege_type FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace CROSS JOIN LATERAL aclexplode(coalesce(c.relacl,acldefault('r',c.relowner))) a WHERE a.is_grantable AND a.grantee NOT IN (0,10,c.relowner) AND c.relkind IN ('r','v','m','p','f') AND n.nspname NOT IN ('pg_catalog','information_schema') AND pg_get_userbyid(a.grantee) NOT IN (${_PGX}) UNION ALL SELECT '$_d:routine:'||pg_get_userbyid(a.grantee)||' '||n.nspname||'.'||p.proname FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace CROSS JOIN LATERAL aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a WHERE a.is_grantable AND a.grantee NOT IN (0,10,p.proowner) AND n.nspname NOT IN ('pg_catalog','information_schema') AND pg_get_userbyid(a.grantee) NOT IN (${_PGX}) UNION ALL SELECT '$_d:schema:'||pg_get_userbyid(a.grantee)||' '||n.nspname||' '||a.privilege_type FROM pg_namespace n CROSS JOIN LATERAL aclexplode(n.nspacl) a WHERE a.is_grantable AND a.grantee<>n.nspowner AND pg_get_userbyid(a.grantee) NOT IN (${_PGX})")
"
    done
    _pg_rolegrants=$(run_q "SELECT 'role:'||pg_get_userbyid(m.member)||' ADMIN '||pg_get_userbyid(m.roleid) FROM pg_auth_members m WHERE m.admin_option AND pg_get_userbyid(m.roleid) NOT LIKE 'pg\\_%' AND pg_get_userbyid(m.member) NOT IN (${_PGX})")
    _pg_grants=$(printf '%s\n%s\n' "$_pg_grants" "$_pg_rolegrants" | grep -v "^$")
    evd_q "DBM-024" "WITH GRANT OPTION(테이블·함수·스키마, 전 DB)·WITH ADMIN OPTION(역할) — 부트스트랩 슈퍼유저 제외" "${_pg_grants:-해당 없음}"
    mc "024" "WITH GRANT OPTION 부여 현황 수동 확인 ($(printf '%s\n' "$_pg_grants" | grep -c .)건, 증적 참조)${_PGXN}"

    # DBM-025: EoS
    _it 025
    _eos_judge pgsql "$DB_VER"
    evd_q "DBM-025" "PostgreSQL 버전 (EoS 판단용)" "${DB_VER} → ${EOS_RES}: ${EOS_WHY}"
    if [ "$EOS_RES" = "취약" ] && [ -n "$_MANAGED" ]; then mc "025" "커뮤니티 기준 ${EOS_WHY} - 관리형(${_MANAGED_LABEL})은 벤더 지원 일정(RDS Extended Support 포함)을 콘솔에서 확인"
    elif [ "$EOS_RES" = "취약" ]; then ng "025" "PostgreSQL ${EOS_WHY}"
    else mc "025" "PostgreSQL ${EOS_WHY}"; fi

    # DBM-026: 구동 계정 umask
    _it 026
    if _os_gate 026 "postgres 구동 계정 umask 는 서버 OS 설정"; then :; else _judge_umask_procs 026 "PostgreSQL" 'postgres|postmaster'; fi

    # DBM-028: 불필요 Object
    _it 028
    _pg_schemas=$(run_q "SELECT nspname FROM pg_namespace WHERE nspname NOT IN ('pg_catalog','information_schema','pg_toast','public') AND nspname NOT LIKE 'pg\\_toast%' AND nspname NOT LIKE 'pg\\_temp%' ORDER BY 1")
    evd_q "DBM-028" "사용자 정의 스키마 목록" "${_pg_schemas:-기본 스키마만 존재}"
    mc "028" "불필요 스키마/테이블 수동 확인 (사용자 스키마 $(printf '%s\n' "$_pg_schemas" | grep -c .)개, 증적 참조)"

    _it 029; na "029" "Oracle 전용 항목 (자원 프로파일)"
    _it 030; na "030" "Oracle/Tibero 전용 항목 (감사 테이블)"
    _it 031; na "031" "MSSQL 전용 항목"

    # DBM-032: 비밀번호 평문 노출 방지
    # 평가기준: pg_hba type 이 hostssl 이외이면 취약(ssl 적용이 힘들면 비밀번호 암호화), auth-method 가 md5·password 인 레코드 존재 시 취약
    _it 032
    ssl=$(get_conf "ssl")
    if [ -n "$_MANAGED" ]; then
        # 관리형: pg_hba.conf 를 볼 수 없으므로 파라미터 그룹 통제(rds.force_ssl / require_secure_transport)와 password_encryption 으로 판정
        _force=$(_pg_guc "rds.force_ssl"); [ -z "$_force" ] && _force=$(_pg_guc "require_secure_transport")
        _minv=$(_pg_guc "ssl_min_protocol_version")
        evd_q "DBM-032" "ssl / rds.force_ssl(또는 require_secure_transport) / ssl_min_protocol_version / password_encryption" "${ssl} / ${_force:-(파라미터 없음)} / ${_minv:-N/A} / ${_pw_enc}"
        case "$(_low "$_force")" in
        1|on|true) [ "$ssl" = "on" ] && ok "032" "SSL 강제 (rds.force_ssl/require_secure_transport=${_force}, ssl=on, 최소 TLS=${_minv:-기본}, password_encryption=${_pw_enc})" \
                                     || nc "032" "SSL 강제 파라미터=${_force} 이나 ssl=${ssl} - 수동 확인" ;;
        0|off|false) if [ "$_pw_enc" = "scram-sha-256" ]; then mc "032" "SSL 강제 아님 (rds.force_ssl=${_force}) - 비밀번호는 SCRAM 이라 평문 노출은 없으나 파라미터 그룹에서 rds.force_ssl=1 설정 권고"
                     else ng "032" "SSL 강제 아님 (rds.force_ssl=${_force}) 이고 password_encryption=${_pw_enc} - 파라미터 그룹에서 rds.force_ssl=1 및 scram-sha-256 설정 필요"; fi ;;
        *) mc "032" "SSL 강제 파라미터(rds.force_ssl/require_secure_transport)를 조회하지 못함 (ssl=${ssl}) - 파라미터 그룹 수동 확인" ;;
        esac
    else
        _hba_pw=$(run_qo "SELECT type||' '||coalesce(address,'')||' '||auth_method FROM pg_hba_file_rules WHERE error IS NULL AND type<>'local' AND auth_method IN ('md5','password') AND coalesce(address,'') NOT IN ('127.0.0.1','::1','localhost')")
        _hba_nossl=$(run_qo "SELECT type||' '||coalesce(address,'')||' '||auth_method FROM pg_hba_file_rules WHERE error IS NULL AND type IN ('host','hostnossl') AND auth_method NOT IN ('reject','scram-sha-256','cert','gss','sspi') AND coalesce(address,'') NOT IN ('127.0.0.1','::1','localhost')")
        _hba_cnt=$(run_qo "SELECT COUNT(*) FROM pg_hba_file_rules WHERE error IS NULL")
        evd_q "DBM-032" "ssl / md5·password 레코드 / 비SSL 평문 위험 레코드" "${ssl} / ${_hba_pw:-없음} / ${_hba_nossl:-없음}"
        if _qo_err "$_hba_cnt" "permission denied|does not exist"; then nc "032" "pg_hba_file_rules 조회 권한 없음 - pg_hba.conf type(hostssl)·auth-method 수동 확인 (ssl=${ssl}): ${_hba_cnt}"
        elif [ -n "$_hba_pw" ]; then ng "032" "auth-method md5/password 레코드: $(_brief "$_hba_pw" 5)"
        elif [ -n "$_hba_nossl" ]; then ng "032" "hostssl 이외 원격 레코드(비밀번호 암호화 미적용): $(_brief "$_hba_nossl" 5)"
        else ok "032" "원격 레코드 hostssl 또는 scram-sha-256/cert 인증 (ssl=${ssl})"; fi
    fi

    # DBM-033: 이중화 비밀번호 평문 노출 방지 (PG 스트리밍 복제)
    # 평가기준: 복제 접속 정보(primary_conninfo)에 비밀번호가 평문으로 설정 파일에 저장되면 취약, passfile(.pgpass)·인증서·SCRAM 등 비평문 방식이면 양호
    _it 033
    _pg_primary=$(run_qo "SELECT conninfo FROM pg_stat_wal_receiver")
    _qo_err "$_pg_primary" "permission denied|does not exist" && _pg_primary=""
    _pg_pci=$(_pg_guc "primary_conninfo")
    _pg_stdby=$(run_qo "SELECT client_addr||' '||state||' '||sync_state FROM pg_stat_replication")
    _qo_err "$_pg_stdby" "permission denied|does not exist" && _pg_stdby=""
    _pg_repl_slots=$(run_qo "SELECT slot_name||' (active='||active||')' FROM pg_replication_slots")
    _qo_err "$_pg_repl_slots" "permission denied|does not exist" && _pg_repl_slots=""
    evd_q "DBM-033" "pg_stat_wal_receiver.conninfo / primary_conninfo / pg_stat_replication / pg_replication_slots" "${_pg_primary:-(없음)} / ${_pg_pci:-(없음)} / ${_pg_stdby:-(없음)} / ${_pg_repl_slots:-(없음)}"
    _ci="${_pg_pci:-$_pg_primary}"
    if [ -n "$_ci" ]; then
        if echo "$_ci" | grep -qiE 'password='; then
            ng "033" "복제(대기 서버) 접속 정보에 password= 가 포함됨(primary_conninfo 설정 파일 평문 저장 가능) - passfile(.pgpass)·SCRAM·인증서 방식으로 변경 권고 $(echo "$_ci" | grep -oE 'sslmode=[a-z-]+' | head -1 | sed 's/^/ (/; s/$/)/')"
        else
            ok "033" "복제 접속 정보에 비밀번호 평문(password=) 없음 (passfile/인증서/trust 등 사용)$(echo "$_ci" | grep -oE 'sslmode=[a-z-]+' | head -1 | sed 's/^/ - /')"
        fi
    elif [ -n "$_pg_stdby" ] || [ -n "$_pg_repl_slots" ]; then
        mc "033" "주(Primary) 서버 - 복제 구성됨(${_pg_stdby:-슬롯 $(echo "$_pg_repl_slots" | _csv)}) - 대기 서버의 primary_conninfo 에 비밀번호 평문 저장 여부를 대기 서버에서 확인"
    elif [ -n "$(_qerr_first)" ]; then
        nc "033" "복제 구성 여부를 조회하지 못함(권한 부족) - $(_qerr_first) (증적의 SQL·오류 원문 참조)"
    else
        na "033" "복제 미구성"
    fi

    # DBM-034: DBMS 구동 권한
    _it 034
    if _os_gate 034 "postgres 구동 계정은 서버 OS 설정"; then :; else _judge_runuser 034 "PostgreSQL" 'postgres|postmaster'; fi

    _it 035; na "035" "MSSQL 전용 항목 (xp_cmdshell)"
    _it 036; na "036" "MSSQL 전용 항목 (Registry Procedure)"
}

# ================================================================
# Tibero 점검 (Oracle 호환 SQL 기반 자동 판정)
# ================================================================
check_tibero() {
    # root/sudo 실행 시 tbsvr 프로세스 환경에서 TB_HOME·TB_SID 복원
    local _tbp; _tbp=$(for c in /proc/[0-9]*/comm; do case "$(cat "$c" 2>/dev/null)" in tbsvr*) c=${c#/proc/}; echo "${c%/comm}"; break ;; esac; done)
    if [ -n "$_tbp" ] && [ "$_REMOTE" != 1 ]; then
        [ -z "$TB_HOME" ] && TB_HOME=$(tr '\0' '\n' < "/proc/$_tbp/environ" 2>/dev/null | sed -n 's/^TB_HOME=//p')
        [ -z "$TB_SID" ] && TB_SID=$(tr '\0' '\n' < "/proc/$_tbp/environ" 2>/dev/null | sed -n 's/^TB_SID=//p')
        [ -n "$TB_HOME" ] && export TB_HOME TB_SID PATH="$TB_HOME/bin:$TB_HOME/client/bin:$PATH"
    fi
    TB_HOME="${TB_HOME:-/opt/tibero}"
    _ask_cred "Tibero" TIBERO_USER TIBERO_PASS "tibero" "비밀번호 없음"
    TB_USER="${TIBERO_USER:-tibero}"
    TB_PASS="${TIBERO_PASS-}"
    TB_DB="${TIBERO_DB-}"   # 미지정 시 별칭 없이 TB_SID 로컬 접속 후 tbdsn 별칭 'tibero' 시도
    DBMS_KIND="tibero"
    [ -z "$TB_PASS" ] && [ -z "$_CRED_ASKED" ] && [ -t 0 ] && { read -rs -p "Tibero ${TB_USER} 비밀번호: " TB_PASS </dev/tty; echo >&2; }

    TBSQL=$(command -v tbsql 2>/dev/null)
    [ -z "$TBSQL" ] && [ -d "$TB_HOME/bin" ] && TBSQL=$(find "$TB_HOME/bin" -name "tbsql" 2>/dev/null | head -1)
    if [ -z "$TBSQL" ] || [ ! -x "$TBSQL" ]; then
        printf '[FALLBACK] %s tbsql 미탐지 - Tibero 전 항목 점검불가 처리\n\n' "$(date '+%H:%M:%S')" >> "$_EVD"
        for i in 001 003 004 005 006 007 008 009 011 012 013 014 015 016 017 \
                 019 020 022 024 025 026 028 029 030 032 033 034; do
            nc "$i" "tbsql 명령을 찾지 못해 점검 불가 (TB_HOME/PATH 확인)"
        done
        na "021" "Windows MSSQL 전용 항목"
        na "031" "MSSQL 전용 항목"
        na "035" "MSSQL 전용 항목"
        na "036" "MSSQL 전용 항목"
        return
    fi

    # tbsql 은 /nolog 로 시작하고 접속 문자열(비밀번호 포함)은 표준입력의 CONNECT 로만 전달 (명령 인자·ps 에 노출되지 않음), -s 로 배너 억제
    _tb_conn() {
        local pw="$TB_PASS"
        case "$pw" in *[!A-Za-z0-9_]*) [ "${pw#*\"}" = "$pw" ] && pw="\"$pw\"" ;; esac   # 특수문자는 큰따옴표로 감쌈
        printf '%s/%s%s' "$TB_USER" "$pw" "${TB_DB:+@$TB_DB}"
    }
    # $1=선택 여부(0 엄격/1 선택) $2=SQL → 결과 행(열 이름 줄 제외). 오류 시 엄격=출력 없음+오류 기록, 선택=첫 오류 줄 출력
    _tq() {
        local _o _err _s="$2"
        case "${_s%"${_s##*[![:space:]]}"}" in *\;) ;; *) _s="${_s};" ;; esac
        _o=$(printf 'CONNECT %s\nSET PAGESIZE 50000\nSET HEADING ON\nSET FEEDBACK OFF\nSET LINESIZE 4000\nSET TRIMSPOOL ON\n%s\nEXIT\n' "$(_tb_conn)" "$_s" | "$TBSQL" -s /nolog 2>&1)
        _o=$(printf '%s\n' "$_o" | sed 's/[[:space:]]*$//' | grep -v '^$')
        _err=$(printf '%s\n' "$_o" | grep -E '^(TBR|TBS|TBC|TBP)-[0-9]+|^(Error|ERROR)[: ]|tbsql: ' | head -3)
        if [ -n "$_err" ]; then
            _qrecord "$2" "$_o" "" 1
            if [ "$1" = 1 ]; then printf '%s\n' "$_err" | head -1; else _qerr_add "$(printf '%s\n' "$_err" | head -1)"; fi
            return 1
        fi
        _qrecord "$2" "$_o" "" 0
        printf '%s\n' "$_o" | awk 'NF{a[++n]=$0} END{s=1; if (n>=2 && a[2] ~ /^[- ]+$/) s=3; for (i=s;i<=n;i++) print a[i]}'
    }
    run_q()  { _tq 0 "$1"; }
    run_qo() { _tq 1 "$1"; }
    _it "DBM-000"
    _tbc=$(run_qo "SELECT 'CONN_'||'OK' FROM DUAL")
    if ! echo "$_tbc" | grep -q CONN_OK && [ -z "$TIBERO_DB" ]; then TB_DB="tibero"; _tbc=$(run_qo "SELECT 'CONN_'||'OK' FROM DUAL"); fi
    : > "$_QERRF"
    _conn_ok "$(run_q "SELECT 'CONN_'||'OK' FROM DUAL")" "Tibero" || return
    # 파라미터는 V$PARAMETERS(대문자 이름) — 조회 실패는 항목 오류로 기록
    _tb_param() { run_q "SELECT VALUE FROM V\$PARAMETERS WHERE NAME=UPPER('$1')" | head -1 | tr -d ' '; }
    DB_VER=$(run_qo "SELECT VALUE FROM V\$VERSION WHERE NAME IN ('PRODUCT_VERSION','TB_MAJOR_VERSION','BUILD_NUMBER')" | tr '\n' ' ')
    echo "$DB_VER" | grep -qE '^(TBR|TBS)-' && DB_VER=""
    [ -z "$DB_VER" ] && DB_VER=$(run_qo "SELECT TB_VERSION FROM DB_VERSION" | head -1)
    echo "$DB_VER" | grep -qE '^(TBR|TBS)-' && DB_VER=""
    _hnote "# Tibero 버전: ${DB_VER:-미확인}"

    # DBM-001: 기본 계정 비밀번호 (OPEN 상태인 기본 계정)
    _it 001
    _tb_open_def=$(run_q "SELECT USERNAME||'('||ACCOUNT_STATUS||')' FROM DBA_USERS WHERE USERNAME IN ('SYS','TIBERO','TIBERO1','OUTLN','SYSGIS') AND ACCOUNT_STATUS='OPEN' ORDER BY USERNAME")
    evd_q "DBM-001" "Tibero 기본 계정 중 OPEN 상태" "${_tb_open_def:-기본 계정 OPEN 없음}"
    if [ -n "$_tb_open_def" ]; then
        mc "001" "기본 계정 OPEN: $(_brief "$_tb_open_def" 20) - 비밀번호 변경 여부 수동 확인"
    else
        mc "001" "Tibero 기본 계정 OPEN 상태 없음 - 계정 비밀번호 복잡도·취약 비밀번호 여부는 해시 크랙으로 확인 필요"
    fi

    # DBM-003: 불필요 계정
    _it 003
    _tb_users=$(run_q "SELECT USERNAME||' ('||ACCOUNT_STATUS||')' FROM DBA_USERS ORDER BY USERNAME")
    evd_q "DBM-003" "DBA_USERS 전체 계정" "$(printf '%s\n' "$_tb_users" | grep -c .)개"
    mc "003" "불필요 계정 수동 확인 (계정 $(printf '%s\n' "$_tb_users" | grep -c .)개, 증적 참조)"

    # DBM-004: 관리자 계정 최소화
    _it 004
    _tb_dba=$(run_q "SELECT GRANTEE FROM DBA_ROLE_PRIVS WHERE GRANTED_ROLE='DBA' AND GRANTEE NOT IN ('SYS','TIBERO') ORDER BY GRANTEE")
    _tb_sysp=$(run_q "SELECT DISTINCT GRANTEE FROM DBA_SYS_PRIVS WHERE GRANTEE NOT IN ('SYS','TIBERO','DBA','PUBLIC') AND PRIVILEGE<>'CREATE SESSION' ORDER BY 1")
    evd_q "DBM-004" "DBA 역할 / 시스템 권한 보유 계정" "${_tb_dba:-없음} / ${_tb_sysp:-없음}"
    mc "004" "관리자 권한 계정 - DBA: $(_brief "${_tb_dba:-없음}" 20), 시스템 권한: $(_brief "${_tb_sysp:-없음}" 20) - 업무상 필요 여부 인터뷰 확인"

    # DBM-005: 중요정보 암호화
    _it 005
    _tb_enc=$(run_q "SELECT OWNER||'.'||TABLE_NAME||'.'||COLUMN_NAME FROM DBA_ENCRYPTED_COLUMNS ORDER BY 1")
    evd_q "DBM-005" "암호화 컬럼 현황" "${_tb_enc:-암호화 컬럼 없음}"
    mc "005" "중요정보 암호화 수동 확인 (암호화 컬럼 $(printf '%s\n' "$_tb_enc" | grep -c .)개, 증적 참조)"

    # 계정별 적용 프로파일 값 (OPEN 계정, LIMIT=DEFAULT 는 DEFAULT 프로파일 값) — 평가기준 '계정별 프로파일'
    _tb_prof() { run_q "SELECT u.USERNAME||'='||DECODE(p.LIMIT,'DEFAULT',d.LIMIT,p.LIMIT) FROM DBA_USERS u JOIN DBA_PROFILES p ON p.PROFILE=u.PROFILE AND p.RESOURCE_NAME='$1' JOIN DBA_PROFILES d ON d.PROFILE='DEFAULT' AND d.RESOURCE_NAME='$1' WHERE u.ACCOUNT_STATUS IN ('OPEN','EXPIRED(GRACE)') ORDER BY 1" | grep "="; }

    # DBM-006: 로그인 실패 횟수 제한
    # 평가기준: 계정별 적용 프로파일 FAILED_LOGIN_ATTEMPTS UNLIMITED/5 초과 → 취약 (Oracle 호환 뷰, 조회 실패 시 DEFAULT 프로파일)
    _it 006
    _tp6=$(_tb_prof FAILED_LOGIN_ATTEMPTS)
    failed=$(run_q "SELECT LIMIT FROM DBA_PROFILES WHERE PROFILE='DEFAULT' AND RESOURCE_NAME='FAILED_LOGIN_ATTEMPTS'" | tr -d ' \n')
    evd_q "DBM-006" "계정별 FAILED_LOGIN_ATTEMPTS / DEFAULT" "$(echo "$_tp6" | _csv) / ${failed}"
    _tb6=$(echo "$_tp6" | awk -F= '$2=="UNLIMITED" || $2+0>5 || $2=="" {print}')
    if [ -n "$_tp6" ]; then
        if [ -n "$_tb6" ]; then ng "006" "FAILED_LOGIN_ATTEMPTS UNLIMITED/5 초과 계정: $(_brief "$_tb6" 20) - 서비스 운영 계정은 평가 제외 가능"
        else ok "006" "OPEN 계정 FAILED_LOGIN_ATTEMPTS 5회 이하"; fi
    elif [ -z "$failed" ]; then nc "006" "FAILED_LOGIN_ATTEMPTS 조회 결과 없음 - 수동 확인"
    elif [ "$failed" = "UNLIMITED" ]; then
        ng "006" "FAILED_LOGIN_ATTEMPTS=${failed}"
    elif [ "$failed" -le 5 ] 2>/dev/null; then
        ok "006" "FAILED_LOGIN_ATTEMPTS=${failed} (5회 이하, DEFAULT 프로파일)"
    else
        ng "006" "FAILED_LOGIN_ATTEMPTS=${failed} (5회 이하 권고)"
    fi

    # DBM-007: 패스워드 복잡도
    _it 007
    _tb_pwfunc=$(run_q "SELECT LIMIT FROM DBA_PROFILES WHERE PROFILE='DEFAULT' AND RESOURCE_NAME='PASSWORD_VERIFY_FUNCTION'" | tr -d ' \n')
    _tp7=$(_tb_prof PASSWORD_VERIFY_FUNCTION)
    evd_q "DBM-007" "PASSWORD_VERIFY_FUNCTION (DEFAULT / OPEN 계정별)" "${_tb_pwfunc:-미설정} / $(echo "$_tp7" | _csv)"
    _tn7=$(echo "$_tp7" | awk -F= '$2=="" || toupper($2)=="NULL" {print $1}')
    # 평가기준: 검증 함수 미적용 계정 존재 또는 함수 내용이 복잡도(2종 10자/3종 8자) 미충족 시 취약 → 적용 시 함수 내용 확인
    if [ -n "$_tp7" ] && [ -n "$_tn7" ]; then ng "007" "비밀번호 검증 함수 미적용 계정: $(_brief "$_tn7" 20)"
    elif [ -n "$_tp7" ]; then mc "007" "OPEN 계정 검증 함수 적용: $(echo "$_tp7" | cut -d= -f2 | sort -u | _csv) - 함수 내용이 복잡도 기준(2종 10자/3종 8자) 충족하는지 확인"
    elif [ -z "$_tb_pwfunc" ] || [ "$_tb_pwfunc" = "NULL" ]; then ng "007" "PASSWORD_VERIFY_FUNCTION 미설정"
    else mc "007" "PASSWORD_VERIFY_FUNCTION=${_tb_pwfunc} - 함수 내용이 복잡도 기준(2종 10자/3종 8자) 충족하는지 확인"; fi

    # DBM-008: 패스워드 변경 주기
    # 평가기준: 만료 정책(PASSWORD_LIFE_TIME, PASSWORD_GRACE_TIME) — 변경 후 90일 이상 지나도 계정이 만료되지 않으면 취약
    _it 008
    _tb_life=$(run_q "SELECT LIMIT FROM DBA_PROFILES WHERE PROFILE='DEFAULT' AND RESOURCE_NAME='PASSWORD_LIFE_TIME'" | tr -d ' \n')
    _tb_grace=$(run_q "SELECT LIMIT FROM DBA_PROFILES WHERE PROFILE='DEFAULT' AND RESOURCE_NAME='PASSWORD_GRACE_TIME'" | tr -d ' \n')
    _tp8=$(_join_eq "$(_tb_prof PASSWORD_LIFE_TIME)" "$(_tb_prof PASSWORD_GRACE_TIME)")
    evd_q "DBM-008" "PASSWORD_LIFE_TIME / PASSWORD_GRACE_TIME (DEFAULT / OPEN 계정별 LIFE=GRACE)" "${_tb_life} / ${_tb_grace} / $(echo "$_tp8" | _csv)"
    _tb8=$(echo "$_tp8" | awk -F= '{l=$2; g=$3; if (g=="UNLIMITED") g=99999; if (l=="UNLIMITED" || l=="" || l+0+g>90) print $1"="$2"+"$3}')
    _g=${_tb_grace}; [ "$_g" = "UNLIMITED" ] && _g=99999; [ -z "$_g" ] && _g=0
    if [ -n "$_tp8" ]; then
        if [ -n "$_tb8" ]; then ng "008" "90일 지나도 만료되지 않는 계정(LIFE+GRACE): $(_brief "$_tb8" 20) - 서비스 운영 계정은 평가 제외 가능"
        else ok "008" "OPEN 계정 PASSWORD_LIFE_TIME+GRACE_TIME 90일 이내 만료"; fi
    elif [ -z "$_tb_life" ]; then nc "008" "PASSWORD_LIFE_TIME 조회 결과 없음 - 수동 확인"
    elif [ "$_tb_life" = "UNLIMITED" ]; then
        ng "008" "PASSWORD_LIFE_TIME=${_tb_life} (무제한)"
    elif [ $((${_tb_life%%.*} + ${_g%%.*})) -le 90 ] 2>/dev/null; then
        ok "008" "PASSWORD_LIFE_TIME=${_tb_life}일 + GRACE_TIME=${_tb_grace:-0}일 (90일 이내 만료)"
    else
        ng "008" "PASSWORD_LIFE_TIME=${_tb_life}일 + GRACE_TIME=${_tb_grace:-0}일 (90일 지나도 만료되지 않음)"
    fi

    # DBM-009: 세션 타임아웃 (IDLE_TIME + resource_limit)
    # 평가기준: ACTIVE_SESSION_TIMEOUT (전체 접속 적용 - 운영 영향 고려). 파라미터 뷰 우선, 로컬이면 tip 파일 보조
    _it 009
    _tb_ast=$(_tb_param ACTIVE_SESSION_TIMEOUT)
    if [ -z "$_tb_ast" ] && [ "$_REMOTE" != 1 ]; then
        _tb_ast=$(grep -hiE '^[[:space:]]*ACTIVE_SESSION_TIMEOUT[[:space:]]*=' "$TB_HOME"/config/*.tip </dev/null 2>/dev/null | tail -1 | cut -d= -f2 | tr -d ' ')
    fi
    evd_q "DBM-009" "ACTIVE_SESSION_TIMEOUT (V\$PARAMETERS$( [ "$_REMOTE" = 1 ] || echo " / 로컬 tip"))" "${_tb_ast:-미설정}"
    if [ -z "$_tb_ast" ] || [ "$_tb_ast" = "0" ]; then
        ng "009" "ACTIVE_SESSION_TIMEOUT 미설정 - 접근제어 솔루션으로 세션 종료 시 수동 확인"
    else
        mc "009" "ACTIVE_SESSION_TIMEOUT=${_tb_ast} - 15분(내부 규정) 이하 여부 및 전체 접속 적용에 따른 운영 영향 확인"
    fi

    # DBM-011: 감사 로그
    _it 011
    _tb_audit=$(_tb_param AUDIT_TRAIL)
    if [ -z "$_tb_audit" ] && [ "$_REMOTE" != 1 ]; then _tb_audit=$(grep -hiE '^[[:space:]]*AUDIT_TRAIL[[:space:]]*=' "$TB_HOME"/config/*.tip </dev/null 2>/dev/null | tail -1 | cut -d= -f2 | tr -d ' '); fi
    evd_q "DBM-011" "AUDIT_TRAIL (V\$PARAMETERS / 로컬 tip)" "${_tb_audit:-조회 결과 없음}"
    if [ -z "$_tb_audit" ]; then nc "011" "AUDIT_TRAIL 조회 결과 없음(V\$PARAMETERS$( [ "$_REMOTE" = 1 ] && echo "·원격이라 tip 미확인")) - 수동 확인"
    elif [ "$(_up "$_tb_audit")" = "NONE" ]; then ng "011" "AUDIT_TRAIL=NONE"
    else mc "011" "AUDIT_TRAIL=${_tb_audit} 수집 중 - 주기적 백업 여부 인터뷰/증적 확인"; fi

    # DBM-012: Tibero 리스너 보안 (tbnetmgr 기반)
    _it 012
    if _os_gate 012 "tbdsn.tbr/리스너 설정은 서버 파일"; then
        :
    else
        if [ -f "${TB_HOME}/config/tbdsn.tbr" ]; then
            evd "DBM-012" "cat '${TB_HOME}/config/tbdsn.tbr'"
            mc "012" "Tibero 리스너 설정 수동 확인 (${TB_HOME}/config/tbdsn.tbr)"
        else
            printf '[DBM-012] %s (대상 없음) tbdsn.tbr 를 찾지 못함: %s\n(대상 없음)\n\n' "$(date '+%H:%M:%S')" "${TB_HOME}/config/tbdsn.tbr" >> "$_EVD"
            nc "012" "tbdsn.tbr 를 찾지 못해 점검 불가 (${TB_HOME}/config) - 리스너 설정 수동 확인"
        fi
    fi

    # DBM-013: 원격 접속 제어
    # 평가기준: $TB_SID.tip 의 LSNR_INVITED_IP / LSNR_DENIED_IP (_FILE 포함) 설정 여부
    _it 013
    _tb_acl=$(run_q "SELECT NAME||'='||VALUE FROM V\$PARAMETERS WHERE NAME IN ('LSNR_INVITED_IP','LSNR_DENIED_IP','LSNR_INVITED_IP_FILE','LSNR_DENIED_IP_FILE') ORDER BY NAME")
    _tb_acl_set=$(echo "$_tb_acl" | awk -F= 'NF>1 && $2!="" && $2!=" " {print}')
    if [ "$_REMOTE" != 1 ]; then evd "DBM-013" "grep -hiE '^[[:space:]]*LSNR_(INVITED|DENIED)_IP' ${TB_HOME}/config/*.tip </dev/null"; fi
    _tb_acl_tip=""; [ "$_REMOTE" != 1 ] && _tb_acl_tip=$(grep -hiE '^[[:space:]]*LSNR_(INVITED|DENIED)_IP(_FILE)?[[:space:]]*=' "$TB_HOME"/config/*.tip </dev/null 2>/dev/null | tr '\n' ' ')
    evd_q "DBM-013" "V\$PARAMETERS LSNR_*_IP / 로컬 tip" "${_tb_acl:-(행 없음)} / ${_tb_acl_tip:-(없음)}"
    if [ -n "$_tb_acl_set" ] || [ -n "$_tb_acl_tip" ]; then ok "013" "리스너 IP 접근제어 설정: $(echo "$_tb_acl_set" | _csv) ${_tb_acl_tip}"
    elif [ -n "$_tb_acl" ] || ls "$TB_HOME"/config/*.tip >/dev/null 2>&1; then ng "013" "LSNR_INVITED_IP/LSNR_DENIED_IP 미설정 - 네트워크 장비·솔루션 접근제어 적용 시 수동 확인"
    else nc "013" "LSNR_*_IP 파라미터 행과 tip 파일을 모두 확인하지 못함 - 원격 접근제어 수동 확인"; fi

    # DBM-014: OS 역할 인증 비활성화
    _it 014
    _tb_osroles=$(_tb_param OS_ROLES)
    evd_q "DBM-014" "OS_ROLES (V\$PARAMETERS)" "${_tb_osroles:-조회 결과 없음}"
    case "$(_up "$_tb_osroles")" in
    FALSE|N|NO) ok "014" "OS_ROLES=${_tb_osroles}" ;;
    TRUE|Y|YES) ng "014" "OS_ROLES=${_tb_osroles} (OS 기반 역할 인증 취약)" ;;
    "")    nc "014" "OS_ROLES 조회 결과 없음 - 수동 확인" ;;
    *)     mc "014" "OS_ROLES=${_tb_osroles} - 수동 확인" ;;
    esac

    # DBM-015: PUBLIC 불필요 권한
    _it 015
    _tb_pub=$(run_q "SELECT TABLE_NAME||' ('||PRIVILEGE||')' FROM DBA_TAB_PRIVS WHERE GRANTEE='PUBLIC' AND PRIVILEGE='EXECUTE' AND TABLE_NAME IN ('UTL_HTTP','UTL_FILE','UTL_SMTP','UTL_TCP','DBMS_SCHEDULER')")
    _tb_pubrs=$(run_q "SELECT GRANTED_ROLE FROM DBA_ROLE_PRIVS WHERE GRANTEE='PUBLIC' UNION ALL SELECT PRIVILEGE FROM DBA_SYS_PRIVS WHERE GRANTEE='PUBLIC'")
    evd_q "DBM-015" "PUBLIC Role·시스템 권한 / 위험 패키지 EXECUTE" "${_tb_pubrs:-없음} / ${_tb_pub:-없음}"
    if [ -n "$_tb_pubrs" ]; then ng "015" "PUBLIC 에 Role/시스템 권한 부여: $(_brief "$_tb_pubrs" 20)"
    elif [ -n "$_tb_pub" ]; then ng "015" "PUBLIC EXECUTE 위험 패키지: $(echo "$_tb_pub" | _csv)"
    else mc "015" "PUBLIC 에 Role·시스템 권한·위험 패키지 없음 - 업무상 불필요한 Object 권한 여부 확인"; fi

    # DBM-016: 보안패치
    _it 016
    evd_q "DBM-016" "Tibero 버전 (패치 판단용)" "${DB_VER}"
    mc "016" "Tibero ${DB_VER} 보안패치 수동 확인"

    # DBM-017: 시스템 테이블 접근 권한
    _it 017
    _tb_sysgrants=$(run_q "SELECT GRANTEE||' → '||TABLE_NAME||' ('||PRIVILEGE||')' FROM DBA_TAB_PRIVS WHERE OWNER='SYS' AND GRANTEE NOT IN ('SYS','TIBERO','PUBLIC','DBA') ORDER BY 1")
    evd_q "DBM-017" "SYS 테이블 접근 권한 (비시스템 계정)" "${_tb_sysgrants:-해당 없음}"
    mc "017" "시스템 테이블 접근 권한 수동 확인 ($(printf '%s\n' "$_tb_sysgrants" | grep -c .)건, 증적 참조)"

    # DBM-019: 패스워드 재사용 제한
    _it 019
    _tb_rmax=$(run_q "SELECT LIMIT FROM DBA_PROFILES WHERE PROFILE='DEFAULT' AND RESOURCE_NAME='PASSWORD_REUSE_MAX'" | tr -d ' \n')
    _tb_rtime=$(run_q "SELECT LIMIT FROM DBA_PROFILES WHERE PROFILE='DEFAULT' AND RESOURCE_NAME='PASSWORD_REUSE_TIME'" | tr -d ' \n')
    _tp19=$(_join_eq "$(_tb_prof PASSWORD_REUSE_MAX)" "$(_tb_prof PASSWORD_REUSE_TIME)")
    _tb19=$(echo "$_tp19" | awk -F= '$2=="UNLIMITED" && $3=="UNLIMITED" {print $1}')
    evd_q "DBM-019" "PASSWORD_REUSE_MAX=${_tb_rmax}, TIME=${_tb_rtime} (DEFAULT) / OPEN 계정별 MAX=TIME" "$(echo "$_tp19" | _csv)"
    # 평가기준: PASSWORD_REUSE_TIME, PASSWORD_REUSE_MAX 둘 다 UNLIMITED 이면 취약
    if [ -n "$_tb19" ]; then ng "019" "PASSWORD_REUSE_MAX·TIME 모두 UNLIMITED 계정: $(_brief "$_tb19" 20)"
    elif [ -n "$_tp19" ]; then ok "019" "OPEN 계정 비밀번호 재사용 제한 적용 (REUSE_MAX 또는 REUSE_TIME 설정)"
    elif [ -z "$_tb_rmax" ] && [ -z "$_tb_rtime" ]; then nc "019" "PASSWORD_REUSE 조회 결과 없음 - 수동 확인"
    elif [ "${_tb_rmax:-UNLIMITED}" = "UNLIMITED" ] && [ "${_tb_rtime:-UNLIMITED}" = "UNLIMITED" ]; then ng "019" "PASSWORD_REUSE_MAX/TIME 모두 UNLIMITED"
    else ok "019" "비밀번호 재사용 제한 설정 (REUSE_MAX=${_tb_rmax}, REUSE_TIME=${_tb_rtime})"; fi

    # DBM-020: 사용자별 계정 분리
    _it 020
    _tb_open=$(run_q "SELECT USERNAME||' ('||ACCOUNT_STATUS||', PROFILE='||PROFILE||')' FROM DBA_USERS WHERE ACCOUNT_STATUS IN ('OPEN','EXPIRED(GRACE)') ORDER BY USERNAME")
    evd_q "DBM-020" "OPEN 상태 사용자 목록" "${_tb_open:-조회 결과 없음}"
    mc "020" "사용자별 계정 분리 수동 확인 (사용자 $(printf '%s\n' "$_tb_open" | grep -c .)개, 증적 참조)"

    _it 021
    na "021" "Windows MSSQL 전용 항목 (Tibero 해당 없음)"

    # DBM-022: 설정 파일 접근 권한
    _it 022
    if _os_gate 022 "tbboot·tbsvr 등 바이너리 권한은 서버 파일"; then
        :
    else
        # 평가기준 700: /bin/tbboot·tbsvr·tblistener·tbctl·tbdown 의 group·others 권한 금지
        evd_ls "DBM-022" "$TB_HOME"/bin/tbboot "$TB_HOME"/bin/tbsvr "$TB_HOME"/bin/tblistener "$TB_HOME"/bin/tbctl "$TB_HOME"/bin/tbdown
        _perm_check 077 "$TB_HOME"/bin/tbboot "$TB_HOME"/bin/tbsvr "$TB_HOME"/bin/tblistener "$TB_HOME"/bin/tbctl "$TB_HOME"/bin/tbdown; _b22=$_PC_BAD
        if [ "$_PC_FOUND" -eq 0 ]; then
            nc "022" "Tibero 기준 파일(bin/tbboot 등)을 찾지 못해 점검 불가 - TB_HOME(${TB_HOME}) 확인 필요"
        elif [ -n "$_b22" ]; then
            ng "022" "기준 권한(700) 위반: ${_b22}"
        else
            ok "022" "tbboot·tbsvr·tblistener·tbctl·tbdown 권한 700 기준 충족 (${_PC_FOUND}개)"
        fi
    fi

    # DBM-024: WITH GRANT OPTION
    _it 024
    _tb_grants=$(run_q "SELECT GRANTEE||' → '||PRIVILEGE FROM DBA_SYS_PRIVS WHERE ADMIN_OPTION='YES' AND GRANTEE NOT IN ('SYS','TIBERO','DBA') ORDER BY 1")
    evd_q "DBM-024" "ADMIN_OPTION='YES' 부여 (비시스템)" "${_tb_grants:-해당 없음}"
    mc "024" "WITH GRANT OPTION 수동 확인 ($(printf '%s\n' "$_tb_grants" | grep -c .)건, 증적 참조)"

    # DBM-025: EoS
    _it 025
    _tb_ver=$(run_qo "SELECT BANNER FROM V\$VERSION" | head -3)
    evd_q "DBM-025" "Tibero 버전 정보 (EoS 판단용)" "${_tb_ver:-${DB_VER}}"
    mc "025" "Tibero EoS 여부 수동 확인 (위 버전 참조)"

    # DBM-026: 구동 계정 umask
    _it 026
    if _os_gate 026 "tbsvr 구동 계정 umask 는 서버 OS 설정"; then :; else _judge_umask_procs 026 "Tibero" 'tbsvr.*'; fi

    # DBM-028: 불필요 DB Object
    _it 028
    _tb_syn=$(run_q "SELECT SYNONYM_NAME||' → '||TABLE_OWNER||'.'||TABLE_NAME FROM DBA_SYNONYMS WHERE OWNER='PUBLIC' AND TABLE_OWNER NOT IN ('SYS','TIBERO','PUBLIC') ORDER BY 1")
    evd_q "DBM-028" "PUBLIC synonym (비시스템 소유)" "${_tb_syn:-해당 없음}"
    mc "028" "불필요 DB Object 수동 확인 (PUBLIC synonym $(printf '%s\n' "$_tb_syn" | grep -c .)건, 증적 참조)"

    # DBM-029: 자원 사용 제한 (프로파일)
    _it 029
    _tb_sess=$(run_q "SELECT LIMIT FROM DBA_PROFILES WHERE PROFILE='DEFAULT' AND RESOURCE_NAME='SESSIONS_PER_USER'" | tr -d ' \n')
    evd_q "DBM-029" "DEFAULT SESSIONS_PER_USER" "${_tb_sess:-조회 결과 없음}"
    if [ -n "$_tb_sess" ] && [ "$_tb_sess" != "UNLIMITED" ]; then ok "029" "SESSIONS_PER_USER=${_tb_sess}"; else mc "029" "DBA_PROFILES 자원 제한 수동 확인 (SESSIONS_PER_USER=${_tb_sess:-조회 결과 없음})"; fi

    # DBM-030: Audit Table 접근 제어
    # 평가기준: Audit Table(SYS._DD_AUD) 소유자 관리자, 일반 계정 삽입/수정/삭제 권한 없음
    _it 030
    _tb_aud=$(run_q "SELECT GRANTEE||' → '||TABLE_NAME||' ('||PRIVILEGE||')' FROM DBA_TAB_PRIVS WHERE TABLE_NAME='_DD_AUD' AND PRIVILEGE IN ('INSERT','UPDATE','DELETE') AND GRANTEE NOT IN ('SYS','TIBERO','DBA') ORDER BY 1")
    _tb_audown=$(run_q "SELECT OWNER FROM DBA_TABLES WHERE TABLE_NAME='_DD_AUD'" | head -1 | tr -d ' ')
    evd_q "DBM-030" "SYS._DD_AUD 소유자 / 일반 계정 수정·삭제 권한" "${_tb_audown:-미확인} / ${_tb_aud:-없음}"
    if [ -n "$_tb_audown" ] && [ "$_tb_audown" != "SYS" ]; then ng "030" "_DD_AUD 소유자가 관리자 계정 아님: ${_tb_audown}"
    elif [ -n "$_tb_aud" ]; then ng "030" "_DD_AUD 수정/삭제 권한 보유 일반 계정: $(_brief "$_tb_aud" 20)"
    elif [ -z "$_tb_audown" ]; then nc "030" "SYS._DD_AUD 조회 결과 없음 - 소유자·권한 수동 확인"
    else ok "030" "SYS._DD_AUD 소유자 SYS, 일반 계정 수정/삭제 권한 없음"; fi

    _it 031
    na "031" "MSSQL 전용 항목"

    # DBM-032: 통신구간 암호화 (Tibero SSL/TCPS)
    _it 032
    if _os_gate 032 "tbdsn.tbr·tip 의 SSL/TCPS 설정은 서버 파일"; then
        :
    elif [ -f "${TB_HOME}/config/tbdsn.tbr" ]; then
        _tb_ssl=$(grep -iE "^[[:space:]]*[^#[:space:]].*(SSL|TCPS|ENCRYPTION)" "${TB_HOME}/config/tbdsn.tbr" </dev/null 2>/dev/null)
        evd "DBM-032" "grep -iE '^[[:space:]]*[^#[:space:]].*(SSL|TCPS|ENCRYPTION)' '${TB_HOME}/config/tbdsn.tbr' </dev/null"
        if [ -n "$_tb_ssl" ]; then mc "032" "Tibero 통신 암호화 설정 존재 - 적정성 수동 확인 (증적 참조)"
        else mc "032" "Tibero 통신 암호화 미설정 - tbdsn.tbr 수동 확인"; fi
    else
        nc "032" "tbdsn.tbr 를 찾지 못해 점검 불가 (${TB_HOME}/config) - 통신 암호화 설정 수동 확인"
    fi

    # DBM-033: 이중화 비밀번호 평문 노출 (Tibero Standby)
    _it 033
    _tb_standby=$(run_q "SELECT DATABASE_ROLE FROM V\$DATABASE" | tr -d '\n')
    evd_q "DBM-033" "V\$DATABASE DATABASE_ROLE" "${_tb_standby:-조회 결과 없음}"
    if [ "$(_up "$_tb_standby")" = "PHYSICAL STANDBY" ] || [ "$(_up "$_tb_standby")" = "LOGICAL STANDBY" ]; then
        mc "033" "Standby 구성됨 - 복제 통신 암호화 수동 확인"
    elif [ -z "$_tb_standby" ]; then
        nc "033" "V\$DATABASE 조회 결과 없음 - 이중화(Standby) 구성 수동 확인"
    else
        na "033" "Standby 미구성 (DATABASE_ROLE=${_tb_standby})"
    fi

    # DBM-034: DBMS 구동 권한
    _it 034
    if _os_gate 034 "tbsvr 구동 계정은 서버 OS 설정"; then :; else _judge_runuser 034 "Tibero" 'tbsvr.*'; fi

    _it 035; na "035" "MSSQL 전용 항목 (xp_cmdshell)"
    _it 036; na "036" "MSSQL 전용 항목 (Registry Procedure)"
}

# ================================================================
# MSSQL(Linux) 점검 — sqlcmd 기반
# ================================================================
check_mssql() {
    _ask_cred "MSSQL" MSSQL_USER MSSQL_PASS "sa" "비밀번호 없음"
    MSSQL_USER="${MSSQL_USER:-sa}"
    MSSQL_PASS="${MSSQL_PASS-}"
    MSSQL_SERVER="${MSSQL_SERVER:-localhost}"; MSSQL_SERVER="${MSSQL_SERVER#tcp:}"
    MSSQL_PORT="${MSSQL_PORT:-1433}"
    DBMS_KIND="mssql"

    SQLCMD=$(command -v sqlcmd 2>/dev/null)
    [ -z "$SQLCMD" ] && [ -x "/opt/mssql-tools18/bin/sqlcmd" ] && SQLCMD="/opt/mssql-tools18/bin/sqlcmd"
    [ -z "$SQLCMD" ] && [ -x "/opt/mssql-tools/bin/sqlcmd" ] && SQLCMD="/opt/mssql-tools/bin/sqlcmd"
    if [ -z "$SQLCMD" ]; then
        printf '[FALLBACK] %s sqlcmd 미탐지 - MSSQL 전 항목 점검불가 처리\n\n' "$(date '+%H:%M:%S')" >> "$_EVD"
        for i in 001 003 004 005 006 007 008 009 011 013 015 016 017 019 020 \
                 021 022 024 025 026 028 029 031 032 033 034 035 036; do
            nc "$i" "sqlcmd 명령을 찾지 못해 점검 불가 (mssql-tools 설치 또는 PATH 확인)"
        done
        na "012" "Oracle 전용 항목"
        na "014" "Oracle 전용 항목"
        na "030" "Oracle/Tibero 전용 항목"
        return
    fi

    # 비밀번호는 -P 인자 대신 SQLCMDPASSWORD 환경변수로만 전달 (ps 에 노출되지 않음)
    [ -z "$MSSQL_PASS" ] && [ -z "$_CRED_ASKED" ] && [ -t 0 ] && { read -rs -p "SQL Server ${MSSQL_USER} 비밀번호: " MSSQL_PASS </dev/tty; echo >&2; }
    if [ -n "$MSSQL_PASS" ]; then export SQLCMDPASSWORD="$MSSQL_PASS"; else unset SQLCMDPASSWORD; fi
    # -b: 오류 시 종료코드 1, -r 1: 오류 메시지를 stderr 로 분리, 열 이름 줄 포함(-h 기본) → 증적에 열 이름 기록
    _SQLCMD_OPTS="-S ${MSSQL_SERVER},${MSSQL_PORT} -U ${MSSQL_USER} -W -s | -b -r 1"
    if [ -n "$MSSQL_ENCRYPT" ] && [ "$MSSQL_ENCRYPT" = "0" ]; then
        _SQLCMD_OPTS="$_SQLCMD_OPTS -N n"
    else
        _SQLCMD_OPTS="$_SQLCMD_OPTS -C"
    fi

    # $1=선택 여부(0 엄격/1 선택) $2=SQL → 결과 행(열 이름·구분선 제외). 오류 시 엄격=출력 없음+오류 기록, 선택=오류 줄 출력
    _sq() {
        local _o _e _rc _ef="$_TMPD/mssql.err" _first
        # shellcheck disable=SC2086
        _o=$("$SQLCMD" $_SQLCMD_OPTS -Q "SET NOCOUNT ON; $2" 2>"$_ef"); _rc=$?
        _e=$(sed 's/\r$//' "$_ef" 2>/dev/null)
        _o=$(printf '%s\n' "$_o" | sed 's/\r$//' | grep -v '^$' | grep -vE '^\([0-9]+ rows? affected\)')
        _qrecord "$2" "$_o" "$_e" "$_rc"
        if [ "$_rc" != 0 ]; then
            _first=$(printf '%s\n%s\n' "$_e" "$_o" | grep -E 'Msg [0-9]+|Sqlcmd: Error|Error|Login failed|error' | head -1)
            [ -z "$_first" ] && _first=$(printf '%s\n' "$_e" | head -1)
            [ -z "$_first" ] && _first="sqlcmd 종료코드 ${_rc}"
            if [ "$1" = 1 ]; then printf 'ERROR: %s\n' "$_first"; else _qerr_add "$_first"; fi
            return 1
        fi
        printf '%s\n' "$_o" | awk 'NF{a[++n]=$0} END{s=1; if (n>=2 && a[2] ~ /^[-|]+$/) s=3; for (i=s;i<=n;i++) print a[i]}'
    }
    run_q()  { _sq 0 "$1"; }
    run_qo() { _sq 1 "$1"; }

    _it "DBM-000"
    _conn_ok "$(run_q "SELECT 'CONN_'+'OK'")" "MSSQL" || return
    DB_VER=$(run_q "SELECT @@VERSION" | head -1)
    _ver_num=""; echo "$DB_VER" | grep -oE "SQL Server [0-9]{4}" >/dev/null && _ver_num=$(echo "$DB_VER" | grep -oE "[0-9]{4}" | head -1)
    _build=""; echo "$DB_VER" | grep -oE "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" >/dev/null && _build=$(echo "$DB_VER" | grep -oE "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" | head -1)
    _hnote "# SQL Server 버전: ${_ver_num} (${_build})"
    # 권한 확인: 서버 수준 뷰/비밀번호 해시는 sysadmin(CONTROL SERVER) 필요 — 없으면 NULL 로 조용히 비어 보이므로 미리 점검
    _ms_ctl=$(run_q "SELECT CAST(HAS_PERMS_BY_NAME(NULL,NULL,'CONTROL SERVER') AS varchar(1))" | head -1 | tr -d ' ')
    evd_q "DBM-000" "CONTROL SERVER 권한 보유(1=예) — 0 이면 password_hash 등이 NULL 로 보여 일부 항목 점검불가" "${_ms_ctl:-조회 실패}"
    # 관리형(RDS·Azure) 예약 로그인 제외
    _MSX="'##none##'"; _MSXN=""
    if [ -n "$_MANAGED" ]; then _MSX="'rdsa','rdsadmin','##none##'"; _MSXN=" (관리형 예약 로그인 제외: rdsa, rdsadmin)"; fi

    # DBM-001: 취약 패스워드 (비밀번호 정책 미적용 계정 + 빈 값·계정명·흔한 비밀번호와 해시 일치 — PWDCOMPARE, 해시 값은 출력하지 않음)
    _it 001
    _ms_weakpw=$(run_q "SELECT name FROM sys.sql_logins WHERE is_policy_checked=0 AND is_disabled=0 AND name NOT LIKE '##%' AND name NOT IN (${_MSX}) ORDER BY name")
    _ms_cmp=$(run_q "SELECT name FROM sys.sql_logins WHERE is_disabled=0 AND name NOT LIKE '##%' AND name NOT IN (${_MSX}) AND (PWDCOMPARE('',password_hash)=1 OR PWDCOMPARE(name,password_hash)=1 OR PWDCOMPARE('password',password_hash)=1 OR PWDCOMPARE('sa',password_hash)=1 OR PWDCOMPARE('Password1',password_hash)=1 OR PWDCOMPARE('P@ssw0rd',password_hash)=1 OR PWDCOMPARE('123456',password_hash)=1 OR PWDCOMPARE('1234',password_hash)=1) ORDER BY name")
    [ "${_ms_ctl:-0}" != "1" ] && _qerr_add "CONTROL SERVER 권한 없음(HAS_PERMS_BY_NAME=${_ms_ctl:-?}) - password_hash 조회 불가로 빈/기본 비밀번호 검사를 수행하지 못함"
    evd_q "DBM-001" "is_policy_checked=0 활성 로그인 / 빈·계정명·흔한 비밀번호와 해시 일치 로그인" "${_ms_weakpw:-없음} / ${_ms_cmp:-없음}"
    if [ -n "$_ms_cmp" ]; then ng "001" "빈 비밀번호·계정명·기본(password/sa/123456 등) 비밀번호와 일치하는 SQL 로그인: $(_brief "$_ms_cmp" 20)${_MSXN}"
    elif [ -n "$_ms_weakpw" ]; then mc "001" "비밀번호 정책 미적용 활성 계정 $(printf '%s\n' "$_ms_weakpw" | grep -c .)개: $(_brief "$_ms_weakpw" 10) (크랙 우선 대상) - 계정 비밀번호 복잡도·취약 비밀번호 여부는 해시 크랙으로 확인 필요${_MSXN}"
    else mc "001" "빈·기본 비밀번호 로그인 없음, 모든 SQL 계정 비밀번호 정책 적용됨 - 계정 비밀번호 복잡도·취약 비밀번호 여부는 해시 크랙으로 확인 필요${_MSXN}"; fi

    # DBM-003: 불필요 계정
    _it 003
    _ms_logins=$(run_q "SELECT name+' (type='+type_desc COLLATE DATABASE_DEFAULT+', disabled='+CAST(is_disabled AS VARCHAR)+')' AS login_info FROM sys.server_principals WHERE type IN ('S','U','G') AND name NOT LIKE '##%' ORDER BY name")
    evd_q "DBM-003" "sys.server_principals (SQL/Windows 로그인)" "$(printf '%s\n' "$_ms_logins" | grep -c .)개"
    mc "003" "불필요 계정 수동 확인 (로그인 $(printf '%s\n' "$_ms_logins" | grep -c .)개, 증적 참조)${_MSXN}"

    # DBM-004: sysadmin 역할 계정
    _it 004
    _ms_sysadmin=$(run_q "SELECT role.name+': '+p.name AS role_member FROM sys.server_principals p JOIN sys.server_role_members r ON p.principal_id=r.member_principal_id JOIN sys.server_principals role ON r.role_principal_id=role.principal_id WHERE role.name IN ('sysadmin','serveradmin','securityadmin','processadmin','setupadmin','bulkadmin','diskadmin','dbcreator') AND p.name NOT LIKE '##%' AND p.name NOT LIKE 'NT SERVICE\\%' AND p.name NOT LIKE 'NT AUTHORITY\\%' AND p.name NOT IN (${_MSX})")
    evd_q "DBM-004" "서버 수준 관리자 역할 구성원" "${_ms_sysadmin:-해당 없음}"
    mc "004" "서버 수준 관리자 역할 부여: $(_brief "${_ms_sysadmin:-없음}" 20) - 업무상 필요 여부 인터뷰 확인${_MSXN}"

    # DBM-005: TDE 암호화
    _it 005
    _ms_tde=$(run_q "SELECT DB_NAME(database_id) AS db_name, encryption_state FROM sys.dm_database_encryption_keys ORDER BY 1")
    evd_q "DBM-005" "TDE 암호화 키 보유 DB (encryption_state=3 이 암호화 완료)" "${_ms_tde:-없음}"
    mc "005" "TDE 암호화 DB $(printf '%s\n' "$_ms_tde" | awk '$NF==3' | grep -c .)개(참고) - 중요정보 컬럼 암호화(Always Encrypted·컬럼 암호화) 적용 여부 확인"

    # DBM-006: 로그인 실패 횟수 제한 (Linux 환경은 SQL Server 자체 정책)
    _it 006
    _ms_nopol=$(run_q "SELECT name FROM sys.sql_logins WHERE is_policy_checked=0 AND is_disabled=0 AND name NOT LIKE '##%' AND name NOT IN (${_MSX}) ORDER BY name")
    evd_q "DBM-006" "is_policy_checked=0 (비밀번호 정책 미적용) 활성 로그인" "${_ms_nopol:-없음}"
    if [ -z "$_ms_nopol" ]; then
        mc "006" "모든 SQL 계정 is_policy_checked=1 - Linux 환경 PAM/OS 계정 잠금 정책 수동 확인${_MSXN}"
    else
        ng "006" "비밀번호 정책 미적용 계정 $(printf '%s\n' "$_ms_nopol" | grep -c .)개: $(_brief "$_ms_nopol" 10) (is_policy_checked=0 → 로그인 실패 제한 미적용)${_MSXN}"
    fi

    # DBM-007: 비밀번호 복잡도
    _it 007
    _ms_nopwc=$(run_q "SELECT name FROM sys.sql_logins WHERE is_policy_checked=0 AND is_disabled=0 AND name NOT LIKE '##%' AND name NOT IN (${_MSX}) ORDER BY name")
    evd_q "DBM-007" "is_policy_checked=0 활성 로그인" "${_ms_nopwc:-없음}"
    if [ -n "$_ms_nopwc" ]; then ng "007" "비밀번호 복잡도 정책 미적용 계정 $(printf '%s\n' "$_ms_nopwc" | grep -c .)개: $(_brief "$_ms_nopwc" 10)${_MSXN}"
    else ok "007" "모든 SQL 계정 비밀번호 복잡도 정책 적용됨${_MSXN}"; fi

    # DBM-008: 비밀번호 변경 주기
    _it 008
    _ms_noexp=$(run_q "SELECT name FROM sys.sql_logins WHERE is_expiration_checked=0 AND is_disabled=0 AND name NOT IN ('sa','##MS_PolicyEventProcessingLogin##') AND name NOT LIKE '##%' AND name NOT IN (${_MSX}) ORDER BY name")
    # 평가기준: PasswordLastSetTime 90일 이상 경과 계정 존재 시 취약
    _ms_old=$(run_q "SELECT name+' ('+CONVERT(varchar(10),CAST(LOGINPROPERTY(name,'PasswordLastSetTime') AS datetime),120)+')' AS login_pwdset FROM sys.sql_logins WHERE is_disabled=0 AND name NOT LIKE '##%' AND name NOT IN (${_MSX}) AND DATEDIFF(DAY,CAST(LOGINPROPERTY(name,'PasswordLastSetTime') AS datetime),GETDATE())>=90 ORDER BY name")
    evd_q "DBM-008" "is_expiration_checked=0 로그인 / PasswordLastSetTime 90일 이상 경과 활성 로그인" "${_ms_noexp:-없음} / ${_ms_old:-없음}"
    if [ -n "$_ms_old" ]; then ng "008" "비밀번호 변경 후 90일 이상 경과 계정: $(_brief "$_ms_old" 20) - 서비스 운영 계정은 평가 제외 가능${_MSXN}"
    elif [ -n "$_ms_noexp" ]; then mc "008" "90일 이상 경과 계정 없음, CHECK_EXPIRATION 미설정 $(printf '%s\n' "$_ms_noexp" | grep -c .)개 - 주기적 변경 관리 확인"
    else ok "008" "활성 SQL 로그인 모두 90일 이내 비밀번호 변경${_MSXN}"; fi

    # DBM-009: 미사용 세션 종료 (SQL Server는 글로벌 유휴 세션 타임아웃 미지원)
    _it 009
    _ms_idle=$(run_q "SELECT login_name+' (idle '+CAST(DATEDIFF(MINUTE,last_request_end_time,GETDATE()) AS varchar)+'분)' AS idle_session FROM sys.dm_exec_sessions WHERE is_user_process=1 AND status='sleeping' AND DATEDIFF(MINUTE,last_request_end_time,GETDATE())>15 ORDER BY 1")
    evd_q "DBM-009" "15분 초과 유휴 사용자 세션 (SQL Server는 글로벌 유휴 세션 타임아웃 미지원 — Resource Governor 또는 응용 프로그램 레벨 설정)" "${_ms_idle:-없음}"
    if [ -n "$_ms_idle" ]; then ng "009" "15분 초과 유휴 세션 $(printf '%s\n' "$_ms_idle" | grep -c .)개: $(_brief "$_ms_idle" 5) - 서비스 계정은 평가 제외 가능"
    else mc "009" "현재 15분 초과 유휴 세션 없음 - 자동 종료 설정(접근제어 솔루션 등) 여부 수동 확인"; fi

    # DBM-011: 감사 로그 (서버 감사 + 로그인 감사 사양 또는 로그인 감사 수준 AuditLevel=3)
    _it 011
    _ms_audit=$(run_q "SELECT name, is_state_enabled FROM sys.server_audits")
    _ms_spec=$(run_q "SELECT s.name+': '+d.audit_action_name AS audit_spec FROM sys.server_audit_specifications s JOIN sys.server_audit_specification_details d ON s.server_specification_id=d.server_specification_id WHERE s.is_state_enabled=1")
    _ms_al=$(run_qo "DECLARE @v int; EXEC master.dbo.xp_instance_regread N'HKEY_LOCAL_MACHINE', N'Software\\Microsoft\\MSSQLServer\\MSSQLServer', N'AuditLevel', @v OUTPUT; SELECT CAST(@v AS varchar(3)) AS audit_level" | head -1 | tr -d ' ')
    case "$_ms_al" in ERROR*) _ms_al="" ;; esac
    _ms_c2=$(run_q "SELECT CAST(value_in_use AS varchar(2)) AS c2_audit_mode FROM sys.configurations WHERE name='c2 audit mode'" | head -1 | tr -d ' ')
    _ms_audn=$(printf '%s\n' "$_ms_audit" | awk -F'|' '$2==1' | grep -c .)
    _ms_logaud=$(printf '%s\n' "$_ms_spec" | grep -cE "FAILED_LOGIN_GROUP|SUCCESSFUL_LOGIN_GROUP")
    evd_q "DBM-011" "활성 서버 감사 수 / 로그인 감사 사양 수 / 로그인 감사 수준 AuditLevel(0 없음·1 성공·2 실패·3 모두) / C2" "${_ms_audn} / ${_ms_logaud} / ${_ms_al:-N/A} / ${_ms_c2:-N/A}"
    if [ "${_ms_audn:-0}" -gt 0 ] && [ "${_ms_logaud:-0}" -eq 0 ] && [ "$_ms_al" != "3" ]; then
        ng "011" "서버 감사 ${_ms_audn}개 활성이나 로그인 성공/실패 감사 사양(FAILED_LOGIN_GROUP/SUCCESSFUL_LOGIN_GROUP) 미설정, 로그인 감사 수준=${_ms_al:-N/A}"
    elif [ "${_ms_audn:-0}" -gt 0 ]; then
        mc "011" "서버 감사 ${_ms_audn}개·로그인 감사 사양 ${_ms_logaud}건(AuditLevel=${_ms_al:-N/A}) 수집 중 - 주기적 백업 여부 인터뷰/증적 확인"
    elif [ "$_ms_al" = "3" ] || [ "$_ms_c2" = "1" ]; then
        mc "011" "$( [ "$_ms_al" = "3" ] && echo "로그인 감사 수준=3(성공·실패 모두)" || echo "C2 감사 모드 활성") - 주기적 백업 여부 인터뷰/증적 확인"
    elif [ -z "$_ms_al" ]; then
        nc "011" "활성 서버 감사가 없고 로그인 감사 수준(AuditLevel, xp_instance_regread)도 조회하지 못해 점검 불가 - 로그인 감사 설정 수동 확인"
    else
        ng "011" "서버 감사(Server Audit) 미설정, 로그인 감사 수준=${_ms_al} - 감사 로그 미수집"
    fi

    _it 012
    na "012" "Oracle 전용 항목 (Listener Control Utility)"

    # DBM-013: 원격 접속 접근 제어
    # 평가기준: DB 포트에 대한 방화벽·네트워크 장비·솔루션 원격 접근제어 ('remote access'는 서버 간 원격 프로시저 호출 옵션으로 무관)
    _it 013
    if _os_gate 013 "호스트 방화벽(iptables/firewalld/ufw)은 서버 OS 설정"; then
        :
    else
        _ms_port=$(run_q "SELECT TOP 1 local_tcp_port FROM sys.dm_exec_connections WHERE local_tcp_port IS NOT NULL" | grep -oE '^[0-9]+' | head -1); _ms_port=${_ms_port:-$MSSQL_PORT}
        _ms_fwtool=""; for _t in iptables firewall-cmd ufw; do command -v "$_t" >/dev/null 2>&1 && _ms_fwtool="$_ms_fwtool $_t"; done
        evd "DBM-013" "{ iptables -S; firewall-cmd --list-all; ufw status verbose; } 2>&1"
        _ms_fw=$( { iptables -S 2>/dev/null | grep -E -- "--dport $_ms_port" | grep -E -- '-s [0-9]'; firewall-cmd --list-rich-rules 2>/dev/null | grep "$_ms_port"; ufw status 2>/dev/null | grep "$_ms_port" | grep -v Anywhere; } | tr '\n' ' ')
        if [ -n "$_ms_fw" ]; then ok "013" "DB 포트(${_ms_port}) 출발지 제한 규칙: ${_ms_fw}"
        elif [ -z "$_ms_fwtool" ]; then nc "013" "호스트 방화벽 도구(iptables/firewall-cmd/ufw)를 실행하지 못해 점검 불가 (root 권한·설치 확인) - 네트워크 장비·솔루션 접근제어 수동 확인"
        else mc "013" "DB 포트(${_ms_port}) 호스트 방화벽 출발지 제한 미확인(${_ms_fwtool# } 조회) - 네트워크 장비·솔루션 접근제어 수동 확인"; fi
    fi

    _it 014
    na "014" "Oracle 전용 항목 (OS_ROLES/REMOTE_OS_ROLES)"

    # DBM-015: Public Role 불필요 권한
    # 기본 설치의 시스템 개체(is_ms_shipped) public GRANT·기본 DB/엔드포인트 권한 제외 (SQL Server 2022 검증: 기본 0건)
    # DB 수준 권한은 DB 별 카탈로그 → 온라인·접근 가능 DB 전체 순회
    _it 015
    _ms_dbs=$(run_q "SELECT name+' ('+state_desc COLLATE DATABASE_DEFAULT+')' AS db FROM sys.databases" | _csv)
    _ms_pubdb=$(run_q "DECLARE @s nvarchar(max)=N''; SELECT @s=@s+N'SELECT N'''+REPLACE(name,'''','''''')+N':''+p.class_desc COLLATE DATABASE_DEFAULT+N'':''+ISNULL(o.name,N''-'') COLLATE DATABASE_DEFAULT+N'':''+p.permission_name COLLATE DATABASE_DEFAULT AS public_perm FROM '+QUOTENAME(name)+N'.sys.database_permissions p LEFT JOIN '+QUOTENAME(name)+N'.sys.all_objects o ON p.class=1 AND o.object_id=p.major_id WHERE p.grantee_principal_id=0 AND p.state IN (''G'',''W'') AND p.permission_name NOT IN (''CONNECT'',''VIEW ANY COLUMN ENCRYPTION KEY DEFINITION'',''VIEW ANY COLUMN MASTER KEY DEFINITION'') AND (p.class<>1 OR o.is_ms_shipped=0) UNION ALL ' FROM sys.databases WHERE state_desc='ONLINE' AND HAS_DBACCESS(name)=1; IF LEN(@s)>0 BEGIN SET @s=LEFT(@s,LEN(@s)-10); EXEC(@s); END")
    _ms_pubsrv=$(run_q "SELECT 'SERVER:'+class_desc+' '+permission_name AS public_perm FROM sys.server_permissions WHERE grantee_principal_id=2 AND permission_name NOT IN ('VIEW ANY DATABASE','CONNECT SQL') AND NOT (class_desc='ENDPOINT' AND permission_name='CONNECT') AND state IN ('G','W')")
    _ms_pubpriv=$(printf '%s\n%s\n' "$_ms_pubdb" "$_ms_pubsrv" | grep -v '^$')
    evd_q "DBM-015" "public 역할 비기본 권한 (전 DB: ${_ms_dbs} + 서버 수준)" "${_ms_pubpriv:-없음}"
    if [ -n "$_ms_pubpriv" ]; then mc "015" "public 역할 비기본 권한 $(printf '%s\n' "$_ms_pubpriv" | grep -c .)건: $(_brief "$_ms_pubpriv" 10) - 업무상 필요 여부 확인 (불필요 시 취약)"
    else ok "015" "public 역할에 기본 외 권한 없음"; fi

    # DBM-016: 보안패치
    _it 016
    evd_q "DBM-016" "SQL Server version" "${_ver_num} (${_build})"
    mc "016" "SQL Server ${_ver_num} 보안패치(CU/SP) 적용 현황 수동 확인"

    # DBM-017: 시스템 테이블 접근 권한
    _it 017
    _ms_syslist=$(run_q "DECLARE @s nvarchar(max)=N''; SELECT @s=@s+N'SELECT N'''+REPLACE(name,'''','''''')+N':''+o.name COLLATE DATABASE_DEFAULT+N'':''+d.name COLLATE DATABASE_DEFAULT+N'':''+p.permission_name COLLATE DATABASE_DEFAULT AS sys_perm FROM '+QUOTENAME(name)+N'.sys.database_permissions p JOIN '+QUOTENAME(name)+N'.sys.all_objects o ON o.object_id=p.major_id AND p.class=1 JOIN '+QUOTENAME(name)+N'.sys.database_principals d ON d.principal_id=p.grantee_principal_id WHERE (o.schema_id=4 OR o.type=''S'') AND p.state IN (''G'',''W'') AND p.grantee_principal_id<>0 AND d.is_fixed_role=0 AND d.name NOT IN (''dbo'',''sys'',''INFORMATION_SCHEMA'',''guest'') AND d.name NOT LIKE ''##%'' UNION ALL ' FROM sys.databases WHERE state_desc='ONLINE' AND HAS_DBACCESS(name)=1; IF LEN(@s)>0 BEGIN SET @s=LEFT(@s,LEN(@s)-10); EXEC(@s); END")
    _ms_systbl=$(printf '%s\n' "$_ms_syslist" | grep -c .)
    evd_q "DBM-017" "sys 스키마·시스템 테이블 권한 (전 DB db:object:grantee:permission, 고정 역할·dbo·guest·## 제외)" "${_ms_syslist:-없음}"
    if [ "${_ms_systbl:-0}" -gt 0 ] 2>/dev/null; then
        mc "017" "시스템 테이블/뷰 접근 권한 ${_ms_systbl}건: $(_brief "$_ms_syslist" 5) - 적정성 수동 확인"
    else
        ok "017" "일반 사용자의 시스템 테이블 직접 접근 권한 없음"
    fi

    # DBM-019: 비밀번호 재사용
    _it 019
    evd_q "DBM-019" "SQL Server 비밀번호 히스토리" "SQL Server 자체 미지원 (OS PAM 또는 is_policy_checked 연계)"
    mc "019" "SQL Server 자체 비밀번호 히스토리 미지원 - OS 정책(PAM) 또는 3rd party로 관리"

    # DBM-020: 계정 분리
    _it 020
    _ms_users=$(run_q "SELECT name+' (type='+type_desc COLLATE DATABASE_DEFAULT+')' AS login_info FROM sys.server_principals WHERE type IN ('S','U','G') AND is_disabled=0 AND name NOT LIKE '##%' AND name NOT IN (${_MSX}) ORDER BY name")
    evd_q "DBM-020" "활성 로그인 계정 목록" "${_ms_users:-조회 결과 없음}"
    mc "020" "공용 계정 사용 여부 수동 확인 (활성 로그인 $(printf '%s\n' "$_ms_users" | grep -c .)개, 증적 참조)${_MSXN}"

    # DBM-021: 연결 서버(Linked Server)
    # 평가기준: ODBC 데이터 소스(DSN) 중 불필요 항목 (Linux: /etc/odbc.ini, ~/.odbc.ini) — Linked Server 는 참고
    _it 021
    _ms_linked=$(run_q "SELECT name+' ('+provider+')' AS linked_server FROM sys.servers WHERE is_linked=1")
    if _os_gate 021 "ODBC 데이터 소스(DSN)는 서버 OS 설정 (참고: 연결 서버 ${_ms_linked:-없음})"; then
        :
    else
        evd "DBM-021" "{ odbcinst -q -s; cat /etc/odbc.ini \"\$HOME/.odbc.ini\"; } 2>&1"
        _ms_dsn=$( { odbcinst -q -s 2>/dev/null; grep -h '^\[' /etc/odbc.ini "$HOME/.odbc.ini" 2>/dev/null; } | grep '^\[' | sort -u | tr -d '[]')
        evd_q "DBM-021" "ODBC DSN / (참고) Linked Server" "${_ms_dsn:-없음} / ${_ms_linked:-없음}"
        if [ -n "$_ms_dsn" ]; then mc "021" "ODBC 데이터 소스: $(_brief "$_ms_dsn" 10) - 업무상 불필요 항목 확인 (존재 시 취약)"
        else ok "021" "등록된 ODBC 데이터 소스(DSN) 없음"; fi
    fi

    # DBM-022: 설정 파일 권한 — DB 파일 경로는 sys.master_files(+ErrorLog)로 조회, 설정 파일은 /var/opt/mssql
    _it 022
    if _os_gate 022 "mssql.conf·데이터/로그 파일 권한은 서버 파일시스템"; then
        :
    else
        # 평가기준: 설정 파일·데이터 파일(master.mdf, *.mdf, *.ndf 등)을 허용 계정 외 사용자가 읽기/쓰기 불가 (others 권한 금지)
        _ms_files=$(run_q "SELECT RTRIM(physical_name) AS physical_name FROM sys.master_files UNION SELECT CAST(SERVERPROPERTY('ErrorLogFileName') AS nvarchar(260))")
        _ms_flist=$(printf '%s\n' "$_ms_files" /var/opt/mssql/mssql.conf /var/opt/mssql/secrets/machine-key | grep -v '^$')
        evd_q "DBM-022" "sys.master_files 물리 파일 + ErrorLog + 설정 파일" "$_ms_flist"
        # shellcheck disable=SC2046
        evd_ls "DBM-022" $(printf '%s\n' "$_ms_flist" | tr '\n' ' ')
        # shellcheck disable=SC2046
        _perm_check 007 $(printf '%s\n' "$_ms_flist" | tr '\n' ' '); _b22=$_PC_BAD
        if [ "$_PC_FOUND" -eq 0 ]; then
            nc "022" "MSSQL 설정/데이터 파일(sys.master_files 경로)을 파일시스템에서 찾지 못해 점검 불가 - 수동 확인"
        elif [ -n "$_b22" ]; then
            ng "022" "others 접근 가능 파일: ${_b22}"
        else
            ok "022" "설정·데이터 파일 ${_PC_FOUND}개 others 권한 없음"
        fi
    fi

    # DBM-024: WITH GRANT OPTION
    _it 024
    _ms_goptlist=$(run_q "DECLARE @s nvarchar(max)=N''; SELECT @s=@s+N'SELECT N'''+REPLACE(name,'''','''''')+N':''+dp.name COLLATE DATABASE_DEFAULT+N'':''+p.class_desc COLLATE DATABASE_DEFAULT+N'':''+ISNULL(OBJECT_NAME(p.major_id,'+CAST(database_id AS nvarchar(10))+N'),N''-'') COLLATE DATABASE_DEFAULT+N'':''+p.permission_name COLLATE DATABASE_DEFAULT AS grant_option_perm FROM '+QUOTENAME(name)+N'.sys.database_permissions p JOIN '+QUOTENAME(name)+N'.sys.database_principals dp ON dp.principal_id=p.grantee_principal_id WHERE p.state=''W'' UNION ALL ' FROM sys.databases WHERE state_desc='ONLINE' AND HAS_DBACCESS(name)=1; IF LEN(@s)>0 BEGIN SET @s=LEFT(@s,LEN(@s)-10); EXEC(@s); END")
    _ms_grantopt=$(printf '%s\n' "$_ms_goptlist" | grep -c .)
    evd_q "DBM-024" "WITH GRANT OPTION(state=W) 권한 (전 DB db:grantee:class:object:permission)" "${_ms_goptlist:-없음}"
    if [ "${_ms_grantopt:-0}" -gt 0 ] 2>/dev/null; then mc "024" "WITH GRANT OPTION ${_ms_grantopt}건: $(_brief "$_ms_goptlist" 5) - 업무상 필요 여부 확인(불필요 시 취약)"
    else ok "024" "WITH GRANT OPTION 설정 권한 없음"; fi

    # DBM-025: EoS
    _it 025
    _eos_judge mssql "$_ver_num"
    evd_q "DBM-025" "SQL Server version (EoS)" "${_ver_num} (${_build}) → ${EOS_RES}: ${EOS_WHY}"
    if [ "$EOS_RES" = "취약" ] && [ -n "$_MANAGED" ]; then mc "025" "커뮤니티 기준 SQL Server ${EOS_WHY} - 관리형(${_MANAGED_LABEL})은 벤더 지원 일정을 콘솔에서 확인"
    elif [ "$EOS_RES" = "취약" ]; then ng "025" "SQL Server ${EOS_WHY}"
    else mc "025" "SQL Server ${EOS_WHY}"; fi

    # DBM-026: 구동 계정 umask (Linux)
    _it 026
    if _os_gate 026 "sqlservr 구동 계정 umask 는 서버 OS 설정"; then :; else _judge_umask_procs 026 "MSSQL" 'sqlservr'; fi

    # DBM-028: 불필요 DB Object (xp_cmdshell, Ole Automation)
    _it 028
    _ms_xp=$(run_q "SELECT CAST(value_in_use AS varchar(2)) AS xp_cmdshell FROM sys.configurations WHERE name='xp_cmdshell'" | head -1 | tr -d ' ')
    _ms_ole=$(run_q "SELECT CAST(value_in_use AS varchar(2)) AS ole_automation FROM sys.configurations WHERE name='Ole Automation Procedures'" | head -1 | tr -d ' ')
    # 평가기준: 인가되지 않은 Object/Owner 존재 여부(인터뷰) - xp_cmdshell 은 DBM-035 항목
    _ms_obj=$(run_q "SELECT TOP 20 s.name+'.'+o.name+' ('+o.type_desc COLLATE DATABASE_DEFAULT+')' AS user_object FROM sys.objects o JOIN sys.schemas s ON o.schema_id=s.schema_id WHERE o.is_ms_shipped=0 ORDER BY o.create_date DESC")
    evd_q "DBM-028" "xp_cmdshell=${_ms_xp:-?}, Ole Automation=${_ms_ole:-?} / 사용자 생성 Object(최근 20)" "${_ms_obj:-조회 결과 없음}"
    mc "028" "사용자 생성 Object/Owner 인가 여부 인터뷰 확인 (현재 DB 사용자 Object 최근 20건 증적 참조; Ole Automation=${_ms_ole:-?})"

    # DBM-029: 자원 사용 제한
    _it 029
    _ms_maxmem=$(run_q "SELECT CAST(value_in_use AS varchar(20)) AS max_server_memory FROM sys.configurations WHERE name='max server memory (MB)'" | head -1 | tr -d ' ')
    _ms_rg=$(run_qo "SELECT CAST(is_enabled AS varchar(1)) AS resource_governor FROM sys.resource_governor_configuration" | head -1)
    case "$_ms_rg" in ERROR*) _ms_rg="" ;; esac
    evd_q "DBM-029" "max server memory (MB) / Resource Governor 사용" "${_ms_maxmem:-?} / ${_ms_rg:-N/A}"
    mc "029" "자원 사용 제한 수동 확인 (max server memory=${_ms_maxmem:-미확인}MB, Resource Governor=${_ms_rg:-N/A})"

    _it 030
    na "030" "Oracle/Tibero 전용 항목 (Audit Table)"

    # DBM-031: SA 계정 보안설정 (MSSQL 전용)
    _it 031
    _ms_sa=$(run_q "SELECT CAST(is_disabled AS VARCHAR)+'|'+name AS sa_status FROM sys.server_principals WHERE sid=0x01" | head -1)
    # 평가기준: sa 비활성 → 양호 / 활성 시 Windows password policy(is_policy_checked) 적용 여부로 판정
    _ms_sapol=$(run_q "SELECT CAST(is_policy_checked AS VARCHAR) AS sa_policy FROM sys.sql_logins WHERE sid=0x01" | head -1 | tr -d ' ')
    evd_q "DBM-031" "SA 계정 상태(is_disabled|name) / sa is_policy_checked" "${_ms_sa:-조회 결과 없음} / ${_ms_sapol:-조회 불가}"
    case "$_ms_sa" in
    1*) ok "031" "SA 계정 비활성화됨 (is_disabled=1)" ;;
    0*) if [ "$_ms_sapol" = "1" ]; then ok "031" "SA 계정 활성, 비밀번호 정책 적용됨 (is_policy_checked=1) - 복잡도 정책은 증적 확인"
        else ng "031" "SA 계정 활성, 비밀번호 정책 미적용 (is_policy_checked=${_ms_sapol:-미확인})"; fi ;;
    *)  nc "031" "SA 계정(sid=0x01) 조회 결과 없음 - 수동 확인" ;;
    esac

    # DBM-032: 통신구간 암호화 (MSSQL TLS — force encryption은 mssql-conf 레벨, 관리형은 파라미터 그룹)
    _it 032
    _ms_encrypt=$(run_q "SELECT DISTINCT CAST(encrypt_option AS varchar(10)) AS encrypt_option FROM sys.dm_exec_connections WHERE session_id=@@SPID" | head -1 | tr -d ' ')
    _ms_forceenc=""
    if [ "$_REMOTE" != 1 ]; then
        [ -x "/opt/mssql/bin/mssql-conf" ] && _ms_forceenc=$(/opt/mssql/bin/mssql-conf get network.forceencryption 2>&1 | grep -oE '[01]' | head -1)
        [ -z "$_ms_forceenc" ] && [ -f /var/opt/mssql/mssql.conf ] && _ms_forceenc=$(grep -iE '^[[:space:]]*forceencryption[[:space:]]*=' /var/opt/mssql/mssql.conf </dev/null 2>/dev/null | grep -oE "[01]" | head -1)
    fi
    evd_q "DBM-032" "현재 세션 encrypt_option / network.forceencryption(로컬 mssql.conf)" "${_ms_encrypt:-미확인} / ${_ms_forceenc:-미설정$( [ "$_REMOTE" = 1 ] && echo '(원격/관리형: 서버 설정 파일 미점검)')}"
    if [ "$_ms_forceenc" = "1" ]; then
        ok "032" "강제 암호화 설정됨 (forceencryption=1)"
    elif [ "$(_up "$_ms_encrypt")" = "TRUE" ]; then
        mc "032" "현재 연결 암호화됨(encrypt_option=TRUE) - 전체 연결 강제 암호화(forceencryption${_MANAGED:+; 관리형은 파라미터 그룹 rds.force_ssl / 서버 방화벽 TLS 최소 버전}) 여부 수동 확인"
    elif [ -z "$_ms_encrypt" ]; then
        nc "032" "encrypt_option 조회 결과 없음 - 수동 확인"
    else
        ng "032" "연결 암호화 미확인 (encrypt_option=${_ms_encrypt}) - 평문 접속 허용"
    fi

    # DBM-033: 이중화 비밀번호 평문 노출 (Always On / Mirroring)
    _it 033
    _ms_ag=$(run_q "SELECT COUNT(*) AS ag_count FROM sys.availability_groups" | tail -1 | tr -d ' ')
    _ms_mirror=$(run_q "SELECT COUNT(*) AS mirror_count FROM sys.database_mirroring WHERE mirroring_state IS NOT NULL" | tail -1 | tr -d ' ')
    evd_q "DBM-033" "AG count / Mirroring count" "${_ms_ag:-조회 실패} / ${_ms_mirror:-조회 실패}"
    if [ "${_ms_ag:-0}" -gt 0 ] 2>/dev/null || [ "${_ms_mirror:-0}" -gt 0 ] 2>/dev/null; then
        mc "033" "이중화 구성됨 (AG=${_ms_ag:-0}, Mirror=${_ms_mirror:-0}) - 암호화 수동 확인"
    else
        na "033" "Always On/Mirroring 미구성"
    fi

    # DBM-034: 서비스 구동 권한
    _it 034
    if _os_gate 034 "sqlservr 구동 계정은 서버 OS 설정"; then :; else _judge_runuser 034 "SQL Server" 'sqlservr'; fi

    # DBM-035: xp_cmdshell 비활성화 (MSSQL 전용)
    _it 035
    evd_q "DBM-035" "xp_cmdshell value_in_use" "${_ms_xp:-조회 실패}"
    if ! printf '%s' "$_ms_xp" | grep -qE '^[01]$'; then nc "035" "xp_cmdshell 설정 조회 실패 - 수동 확인"
    elif [ "$_ms_xp" = "0" ]; then ok "035" "xp_cmdshell 비활성화됨 (=0)"
    else ng "035" "xp_cmdshell 활성화됨 (=1) - 보안 위험"; fi

    # DBM-036: Registry Procedure 접근 권한 (MSSQL 전용)
    # 평가기준: 제한 목록 7종 확장 프로시저가 DBA 외 guest/public 에 부여되면 취약 (Linux 인스턴스에도 xp_reg* 존재·기본 public 부여 확인)
    _it 036
    _ms_regpub=$(run_q "SELECT o.name+':'+dp.name+':'+p.state_desc COLLATE DATABASE_DEFAULT AS reg_perm FROM master.sys.database_permissions p JOIN master.sys.all_objects o ON o.object_id=p.major_id JOIN master.sys.database_principals dp ON dp.principal_id=p.grantee_principal_id WHERE p.class=1 AND p.type='EX' AND p.state IN ('G','W') AND dp.name IN ('public','guest') AND o.name IN ('xp_regaddmultistring','xp_regdeletekey','xp_regdeletevalue','xp_regenumvalues','xp_regread','xp_regremovemultistring','xp_regwrite')")
    _ms_regcnt=$(run_q "SELECT COUNT(*) AS xp_reg_count FROM master.sys.all_objects WHERE type='X' AND name LIKE 'xp_reg%'" | tail -1 | tr -d ' ')
    evd_q "DBM-036" "레지스트리 확장 프로시저 수 / public·guest 부여" "${_ms_regcnt:-조회 실패} / ${_ms_regpub:-없음}"
    if [ -z "$_ms_regcnt" ]; then nc "036" "레지스트리 확장 프로시저 조회 실패 - 수동 확인"
    elif [ -n "$_ms_regpub" ]; then ng "036" "레지스트리 확장 프로시저 public/guest 부여: $(_brief "$_ms_regpub" 10)"
    else ok "036" "제한 대상 레지스트리 확장 프로시저 public/guest 부여 없음"; fi
}

# ════════════════════════════════════════════════════════════════
# 주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드(2026) — DBMS D-01 ~ D-26
#   전자금융(DBM) 점검과 같은 DB 접속으로 가이드 항목코드·판단기준 그대로 판정 (MySQL·MariaDB·PostgreSQL·MSSQL)
#   가이드 '점검 대상'에 없는 제품은 N-A. Oracle·Tibero 는 컨버터가 DBM 결과로 가이드 항목 판정
# ════════════════════════════════════════════════════════════════
_kput() {   # 가이드 항목 판정 1회 기록 (코드 전체: D-xx) — 쿼리 오류가 있었던 항목은 _emit 이 점검불가로 바꿈
    local k="$1" r="$2" w="$3"
    w=$(printf '%s' "$w" | tr -s ' ' | sed 's/[[:space:]]*$//')   # 공백 정리
    _emit "$k" "$r" "$w"
}
_KNA() { local c; for c in "$@"; do _it "$c"; _kput "$c" "N-A" "가이드 점검 대상 제품 아님 (${_KDB})"; done; }
_kisa_fail() { local c; for c in $2; do _kput "$c" "점검불가" "$1"; done; }
_qerr_carry() { [ -n "$1" ] && _qerr_add "$1"; return 0; }   # 이전 단계(공용 조회)의 오류를 현재 항목에 이어받음
_kisa_d25() {   # D-25: EoS(보안 패치 미제공) = 취약, 그 외 최신 패치 여부 확인  $1=mysql|mariadb|pgsql|mssql  $2=버전
    _it D-25
    _eos_judge "$1" "$2"
    evd_q "D-25" "DBMS 버전 / 지원 종료일 표 대조" "${2:-미확인} → ${EOS_RES}: ${EOS_WHY}"
    if [ -z "$2" ]; then _kput "D-25" "점검불가" "DBMS 버전을 확인하지 못함 - 수동 확인"
    elif [ "$EOS_RES" = "취약" ] && [ -n "$_MANAGED" ]; then _kput "D-25" "수동확인" "커뮤니티 기준 ${EOS_WHY} - 관리형(${_MANAGED_LABEL})은 벤더 지원 일정(Extended Support 포함)을 콘솔에서 확인"
    elif [ "$EOS_RES" = "취약" ]; then _kput "D-25" "취약" "보안 패치가 제공되지 않는 버전(EoS): ${EOS_WHY}"
    else _kput "D-25" "수동확인" "${EOS_WHY}"; fi
}
_D_ALL="D-01 D-02 D-03 D-04 D-05 D-06 D-07 D-08 D-09 D-10 D-11 D-12 D-13 D-14 D-15 D-16 D-17 D-18 D-19 D-20 D-21 D-22 D-23 D-24 D-25 D-26"

kisa_mysql() {
    _KDB="$([ "${IS_MARIADB:-0}" = 1 ] && echo MariaDB || echo MySQL)"
    if [ "${_DB_CONN:-0}" != 1 ]; then
        _KNA D-05 D-09 D-12 D-13 D-15 D-16 D-17 D-18 D-19 D-20 D-22 D-23 D-24 D-26
        _kisa_fail "DB 접속 실패/클라이언트 미탐지로 점검 불가: ${_CONN_WHY:-$(_qerr_first)} - 접속 정보 확인 후 재점검 (오류 원문은 증적)" "D-01 D-02 D-03 D-04 D-06 D-07 D-08 D-10 D-11 D-14 D-21 D-25"
        return
    fi
    local _sys="${_MYX}"
    # 계정 현황 (5.5 Password / 5.7+ authentication_string / account_locked 5.7.6+ — 열 구성은 check_mysql 에서 information_schema 로 확인한 표현식 사용)
    _it D-01
    local _u _u_err; _u=$(run_q "SELECT CONCAT(User,'@',Host,'|',${_E_PLUGIN},'|',IF(${_E_HASH}='','EMPTY','SET'),'|',${_E_LOCK},'|',LENGTH(${_E_HASH})) FROM mysql.user WHERE User NOT IN (${_sys},'PUBLIC') ORDER BY 1")
    _u_err=$(_qerr_first)
    evd_q "D-01" "계정@호스트|인증 플러그인|비밀번호 설정|잠금|해시 길이 (mysql.user)" "${_u:-조회 불가}"

    # D-01 기본 계정(root) 초기 비밀번호 변경 또는 잠금 (빈 비밀번호 + 흔한 약한 비밀번호의 SHA1 해시 비교 — 해시 값은 출력하지 않음)
    local _r _wl="" _w _rootweak
    for _w in root password mysql admin 123456 1234 12345678 qwerty test; do _wl="${_wl:+$_wl,}CONCAT('*',UPPER(SHA1(UNHEX(SHA1('${_w}')))))"; done
    _rootweak=$(run_q "SELECT CONCAT(User,'@',Host) FROM mysql.user WHERE User='root' AND ${_E_LOCK}<>'Y' AND ${_E_PLUGIN} IN ('','mysql_native_password') AND ${_E_HASH} LIKE '*%' AND ${_E_HASH} IN (${_wl}) ORDER BY 1" | tr '\n' ' ')
    _r=$(echo "$_u" | awk -F'|' '$1 ~ /^root@/ && $3=="EMPTY" && $4!="Y" && $2!~/(auth_socket|unix_socket)/ {print $1}' | tr '\n' ' ')
    if [ -z "$_u" ]; then _kput "D-01" "점검불가" "mysql.user 조회 결과 없음 - root 비밀번호 변경 여부 확인"
    elif [ -n "$_r" ]; then _kput "D-01" "취약" "기본 계정 비밀번호 미설정(초기값): ${_r% }"
    elif [ -n "$_rootweak" ]; then _kput "D-01" "취약" "기본 계정 root 비밀번호가 흔한 약한 값(root/password/mysql/admin/123456 등)과 일치: ${_rootweak% }"
    else _kput "D-01" "양호" "기본 계정(root) 비밀번호 설정 또는 OS 인증(socket)·잠금: $(echo "$_u" | awk -F'|' '$1~/^root@/{t=""; if($3=="SET")t="비밀번호"; if($2~/socket/)t=t (t==""?"":" ") "socket"; if($4=="Y")t=t (t==""?"":" ") "잠금"; print $1"("t")"}' | tr '\n' ' ')"; fi

    # D-02 불필요 계정 (익명·테스트 계정 = 취약, 그 외 인가 여부 확인)
    _it D-02; _qerr_carry "$_u_err"
    local _anon _test _act
    _anon=$(echo "$_u" | awk -F'|' '$1 ~ /^@/ {print $1}' | tr '\n' ' ')
    _test=$(echo "$_u" | awk -F'|' '$4!="Y"{print $1}' | grep -iE '^(test|guest|demo|temp|tmp|sample|user[0-9]*)[0-9_]*@' | tr '\n' ' ')
    _act=$(echo "$_u" | awk -F'|' '$4!="Y"{print $1}' | tr '\n' ' ')
    evd_q "D-02" "활성(잠금 아님) 계정" "${_act:-없음}"
    if [ -n "$_anon$_test" ]; then _kput "D-02" "취약" "불필요 계정 존재:${_anon:+ 익명 계정 ${_anon}}${_test:+ 테스트성 계정 ${_test}}"
    else _kput "D-02" "수동확인" "활성 계정: ${_act:-없음}- 인가되지 않은 계정·퇴직자·미사용 계정 여부 확인 (없으면 양호)${_MYXN}"; fi

    # D-03 비밀번호 사용 기간 및 복잡도
    _it D-03
    local _vp _lt _cx="" _ln=""
    _vp=$(run_q "SHOW VARIABLES WHERE Variable_name REGEXP '^(validate_password|simple_password_check|cracklib_password_check)'" | tr '\t' '=' | tr '\n' ' ')
    _lt=$(get_var "default_password_lifetime")
    evd_q "D-03" "validate_password*/simple_password_check* / default_password_lifetime" "${_vp:-미설치} / ${_lt:-없음}"
    _ln=$(echo "$_vp" | grep -oE '(validate_password[._]length|simple_password_check_minimal_length)=[0-9]+' | head -1 | cut -d= -f2)
    if echo "$_vp" | grep -qE 'validate_password[._]policy=(MEDIUM|STRONG|1|2)'; then _cx="validate_password MEDIUM 이상"
    elif echo "$_vp" | grep -qE 'simple_password_check_digits=[1-9]' && echo "$_vp" | grep -qE 'simple_password_check_other_characters=[1-9]'; then _cx="simple_password_check"
    elif echo "$_vp" | grep -q 'cracklib_password_check'; then _cx="cracklib_password_check"; fi
    local _bad3=""
    { [ -z "$_cx" ] || [ "${_ln:-0}" -lt 8 ]; } && _bad3="${_bad3} 복잡도 정책 미흡(${_cx:-미설치}, 최소 길이 ${_ln:-미설정})"
    { [ -z "$_lt" ] || [ "$_lt" -eq 0 ] || [ "$_lt" -gt 90 ]; } 2>/dev/null && _bad3="${_bad3} 사용 기간 default_password_lifetime=${_lt:-미지원}(0=무제한, 90일 이하 필요)"
    if [ -n "$_bad3" ]; then _kput "D-03" "취약" "비밀번호 정책 미적용:${_bad3}"; else _kput "D-03" "양호" "복잡도(${_cx}, 최소 ${_ln}자)·사용 기간(${_lt}일) 설정"; fi

    # D-04 관리자 권한(SUPER 등)은 필요한 계정에만
    _it D-04
    local _su _sun; _su=$(run_q "SELECT CONCAT(User,'@',Host) FROM mysql.user WHERE Super_priv='Y' AND User NOT IN (${_sys}) ORDER BY 1" | tr '\n' ' ')
    evd_q "D-04" "SUPER 권한 보유 계정 (mysql.user Super_priv)" "${_su:-없음}"
    _sun=$(echo "$_su" | tr ' ' '\n' | grep -v '^root@' | grep . | tr '\n' ' ')
    if [ -n "$_sun" ]; then _kput "D-04" "수동확인" "root 외 SUPER(관리자) 권한 계정: ${_sun}- 관리자 권한 필요성 확인 (불필요 시 취약, 필요한 권한만 부여)${_MYXN}"
    else _kput "D-04" "양호" "관리자(SUPER) 권한이 root 에만 부여: ${_su:-없음}${_MYXN}"; fi

    _KNA D-05
    # D-06 사용자별 계정 사용 (공용 계정 여부)
    _it D-06; _qerr_carry "$_u_err"
    evd_q "D-06" "활성 계정" "${_act:-없음}"
    _kput "D-06" "수동확인" "활성 계정: ${_act:-없음}- 사용자·응용프로그램별 개별 계정 사용 여부(공용 계정 사용 시 취약) 확인${_MYXN}"

    # D-07 root 권한으로 서비스 구동 제한
    _it D-07
    if _os_gate D-07 "DBMS 구동 계정은 서버 OS 설정"; then
        :
    else
        local _pu _cu="" _c
        evd_ps "D-07" 'mysqld|mariadbd'
        _pu=$(_proc_users 'mysqld|mariadbd')
        for _c in /etc/my.cnf /etc/mysql/my.cnf /etc/my.cnf.d/*.cnf /etc/mysql/mysql.conf.d/*.cnf /etc/mysql/mariadb.conf.d/*.cnf; do
            [ -f "$_c" ] && _cu=$(awk '/^[[:space:]]*\[/{s=$0} tolower(s)~/\[(mysqld|server|mariadb)\]/ && /^[[:space:]]*user[[:space:]]*=/{sub(/.*=[[:space:]]*/,"");print;exit}' "$_c") && [ -n "$_cu" ] && break
        done
        evd_q "D-07" "mysqld 구동 계정 / [mysqld] user" "${_pu:-미실행} / ${_cu:-미설정}"
        if echo " $_pu $_cu" | grep -qw root; then _kput "D-07" "취약" "DBMS 가 root 권한으로 구동 (프로세스=${_pu:-?}, user=${_cu:-미설정})"
        elif [ -n "$_pu$_cu" ]; then _kput "D-07" "양호" "별도 계정으로 구동 (프로세스=${_pu:-미확인}, user=${_cu:-미설정})"
        else _kput "D-07" "점검불가" "mysqld/mariadbd 프로세스와 설정 파일 user 지시자를 확인하지 못함"; fi
    fi

    # D-08 안전한 암호화 알고리즘 (SHA-256 이상)
    _it D-08; _qerr_carry "$_u_err"
    local _wk; _wk=$(echo "$_u" | awk -F'|' '$3=="SET" && $2!~/(caching_sha2_password|sha256_password|ed25519|auth_socket|unix_socket|pam|gssapi|ldap)/ {print $1"("($2==""?($5==16?"구형 16자 해시":"기본 해시"):$2)")"}' | tr '\n' ' ')
    evd_q "D-08" "비밀번호 계정별 인증 플러그인(계정 플러그인)" "$(echo "$_u" | awk -F'|' '$3=="SET"{print $1" "$2}')"
    if [ -z "$_u" ]; then _kput "D-08" "점검불가" "계정 인증 플러그인 조회 결과 없음"
    elif [ -n "$_wk" ]; then _kput "D-08" "취약" "SHA-256 미만 해시 알고리즘 계정 (mysql_native_password=SHA-1 등): ${_wk% }"
    else _kput "D-08" "양호" "비밀번호 계정 전부 SHA-256 이상(caching_sha2_password/sha256_password/ed25519) 또는 OS 인증"; fi

    _KNA D-09
    # D-10 원격 접속 제한 (Host='%' 계정)
    _it D-10; _qerr_carry "$_u_err"
    local _any; _any=$(echo "$_u" | awk -F'|' '$1 ~ /@%$/ {print $1}' | tr '\n' ' ')
    evd_q "D-10" "모든 호스트(%) 허용 계정 / bind_address" "${_any:-없음} / $(get_var bind_address)"
    if [ -n "$_any" ]; then _kput "D-10" "취약" "모든 클라이언트(%)에서 접속 가능한 계정: ${_any% } - 지정 IP 로 제한 필요${_MANAGED:+ (관리형은 보안그룹/NACL 도 함께 제한)}${_MYXN}"
    else _kput "D-10" "양호" "모든 계정이 지정 호스트에서만 접속 가능 (Host='%' 없음)${_MYXN}"; fi

    # D-11 시스템 테이블(mysql 스키마) 접근 제한
    _it D-11
    local _st
    _st=$( { run_q "SELECT CONCAT(User,'@',Host,'(전역 SELECT)') FROM mysql.user WHERE Select_priv='Y' AND Super_priv<>'Y' AND User NOT IN (${_sys},'root')"
             run_q "SELECT CONCAT(User,'@',Host,'(mysql DB)') FROM mysql.db WHERE Db IN ('mysql','sys','performance_schema') AND User NOT IN (${_sys},'root')"
             run_q "SELECT CONCAT(User,'@',Host,'(',Table_name,')') FROM mysql.tables_priv WHERE Db='mysql' AND User NOT IN (${_sys},'root')"; } | sort -u | tr '\n' ' ')
    evd_q "D-11" "DBA 외 시스템 스키마(mysql/sys) 접근 권한 계정" "${_st:-없음}"
    if [ -n "$_st" ]; then _kput "D-11" "취약" "DBA 외 계정의 시스템 테이블 접근 권한: ${_st% }"; else _kput "D-11" "양호" "시스템 테이블(mysql 스키마) 접근 권한이 DBA 에만 부여"; fi

    _KNA D-12 D-13
    # D-14 주요 설정 파일 권한 (가이드 MySQL 절차: my.cnf 600/640 — group 쓰기·실행, others 모든 권한 제거)
    _it D-14
    if _os_gate D-14 "my.cnf 등 설정 파일 권한"; then
        :
    else
        local _cfg="/etc/my.cnf /etc/mysql/my.cnf /etc/mysql/debian.cnf /etc/my.cnf.d/*.cnf /etc/mysql/conf.d/*.cnf /etc/mysql/mysql.conf.d/*.cnf /etc/mysql/mariadb.conf.d/*.cnf /root/.my.cnf"
        # shellcheck disable=SC2086
        evd_ls "D-14" $_cfg
        # shellcheck disable=SC2086
        _perm_check 037 $_cfg
        if [ "$_PC_FOUND" -eq 0 ]; then _kput "D-14" "점검불가" "설정 파일(my.cnf)을 찾지 못해 점검 불가"
        elif [ -n "$_PC_BAD" ]; then _kput "D-14" "취약" "설정 파일 권한 가이드(600/640) 위반 - group 쓰기·실행 또는 others 권한: ${_PC_BAD}"
        else _kput "D-14" "양호" "설정 파일 ${_PC_FOUND}개 group 쓰기·실행/others 권한 없음 (가이드 권고 600/640)"; fi
    fi

    _KNA D-15 D-16 D-17 D-18 D-19 D-20
    # D-21 GRANT OPTION 제한 (Grant_priv 계정 = 취약, root 제외)
    _it D-21
    local _gp; _gp=$( { run_q "SELECT CONCAT(User,'@',Host) FROM mysql.user WHERE Grant_priv='Y' AND User NOT IN (${_sys},'root')"; run_q "SELECT CONCAT(User,'@',Host,'(',Db,')') FROM mysql.db WHERE Grant_priv='Y' AND User NOT IN (${_sys},'root')"; } | sort -u | tr '\n' ' ')
    evd_q "D-21" "mysql.user / mysql.db 의 Grant_priv='Y' 계정 (root 제외)" "${_gp:-없음}"
    if [ -n "$_gp" ]; then _kput "D-21" "취약" "GRANT OPTION 보유 계정: ${_gp% }"; else _kput "D-21" "양호" "root 외 GRANT OPTION 보유 계정 없음"; fi

    _KNA D-22 D-23 D-24
    _kisa_d25 "$( [ "${IS_MARIADB:-0}" = 1 ] && echo mariadb || echo mysql )" "$DB_VER"
    _KNA D-26
}

kisa_pgsql() {
    _KDB="PostgreSQL"
    if [ "${_DB_CONN:-0}" != 1 ]; then
        _KNA D-05 D-07 D-09 D-12 D-13 D-15 D-16 D-17 D-18 D-19 D-21 D-22 D-23 D-24
        _kisa_fail "DB 접속 실패/psql 미탐지로 점검 불가: ${_CONN_WHY:-$(_qerr_first)} - 접속 정보 확인 후 재점검 (오류 원문은 증적)" "D-01 D-02 D-03 D-04 D-06 D-08 D-10 D-11 D-14 D-20 D-25 D-26"
        return
    fi
    local _hba _roles _hba_o _hba_err="" _roles_err
    _it D-01
    _hba_o=$(run_qo "SELECT type||' '||array_to_string(database,',')||' '||array_to_string(user_name,',')||' '||COALESCE(address,'')||COALESCE('/'||netmask,'')||' '||auth_method FROM pg_hba_file_rules WHERE error IS NULL")
    if _qo_err "$_hba_o" "permission denied|does not exist"; then _hba_err="$_hba_o"; _hba=""; else _hba="$_hba_o"; fi   # 슈퍼유저 전용 뷰 — 관리형·일반 계정은 접근 불가
    _roles=$(run_q "SELECT rolname||'|'||CASE WHEN rolcanlogin THEN 't' ELSE 'f' END||'|'||CASE WHEN rolsuper THEN 't' ELSE 'f' END||'|'||CASE WHEN (rolcreaterole OR rolcreatedb OR rolreplication OR rolbypassrls) THEN 't' ELSE 'f' END||'|'||CASE WHEN rolpassword IS NULL THEN 'NULL' WHEN rolpassword LIKE 'SCRAM-SHA-256%' THEN 'SCRAM' WHEN rolpassword LIKE 'md5%' THEN 'MD5' ELSE 'OTHER' END||'|'||COALESCE(rolvaliduntil::text,'') FROM pg_authid WHERE rolname NOT LIKE 'pg\\_%' AND rolname NOT IN (${_PGX}) ORDER BY 1")
    _roles_err=$(_qerr_first)
    evd_q "D-01" "역할|로그인|슈퍼유저|관리권한|비밀번호 해시 종류|유효기간 (pg_authid, 해시 값은 수집하지 않음)" "${_roles:-조회 불가(슈퍼유저 권한 필요)}"
    evd_q "D-01" "pg_hba_file_rules" "${_hba:-${_hba_err:-조회 결과 없음}}"

    # D-01 기본 계정(postgres) 초기 비밀번호 변경 또는 잠금
    local _pg _trust _ltrust
    _pg=$(echo "$_roles" | awk -F'|' '$1=="postgres"')
    _trust=$(echo "$_hba" | awk '$NF=="trust" && $1!="local" && $4 !~ /^(127\.0\.0\.1|::1)\//')
    _ltrust=$(echo "$_hba" | awk '$NF=="trust" && ($1=="local" || $4 ~ /^(127\.0\.0\.1|::1)\//)' | wc -l)
    if [ -z "$_roles" ]; then _kput "D-01" "점검불가" "pg_authid 조회 결과 없음(슈퍼유저/rds_superuser 권한 필요) - postgres 비밀번호 설정 여부 확인"
    elif [ -n "$_trust" ]; then _kput "D-01" "취약" "비밀번호 없이 접속 가능한 원격 trust 인증: $(echo "$_trust" | tr '\n' ',' | sed 's/,$//')"
    elif echo "$_pg" | awk -F'|' '$5=="NULL"' | grep -q .; then _kput "D-01" "양호" "기본 계정 postgres 비밀번호 미설정 - 비밀번호 인증 불가(peer 등 OS 인증만 허용, 잠금과 동일)"
    else _kput "D-01" "양호" "기본 계정 postgres 비밀번호 설정 ($(echo "$_pg" | cut -d'|' -f5))$( [ "${_ltrust:-0}" -gt 0 ] && echo " - 참고: 로컬(소켓·루프백) trust 규칙 ${_ltrust}개는 비밀번호 없이 접속 가능하므로 필요성 확인")${_hba_err:+ [pg_hba 규칙은 조회 권한 없어 trust 규칙 미확인]}${_PGXN}"; fi

    # D-02 불필요 계정
    _it D-02; _qerr_carry "$_roles_err"
    local _login _test
    _login=$(echo "$_roles" | awk -F'|' '$2=="t"{print $1}' | tr '\n' ' ')
    _test=$(echo "$_login" | tr ' ' '\n' | grep -iE '^(test|guest|demo|temp|tmp|sample|user[0-9]*)[0-9_]*$' | tr '\n' ' ')
    evd_q "D-02" "로그인 가능 역할" "${_login:-없음}"
    if [ -n "$_test" ]; then _kput "D-02" "취약" "테스트성 계정 존재: ${_test% }"; else _kput "D-02" "수동확인" "로그인 가능 역할: ${_login:-없음}- 인가되지 않은 계정·퇴직자·미사용 계정 여부 확인 (없으면 양호)${_PGXN}"; fi

    # D-03 비밀번호 사용 기간(VALID UNTIL) 및 복잡도(passwordcheck/credcheck)
    _it D-03; _qerr_carry "$_roles_err"
    local _spl _nov
    _spl=$(get_conf "shared_preload_libraries")
    _nov=$(echo "$_roles" | awk -F'|' '$2=="t" && $5!="NULL" && $6=="" {print $1}' | tr '\n' ' ')
    evd_q "D-03" "shared_preload_libraries / 비밀번호 사용 기간(VALID UNTIL) 미설정 로그인 역할" "${_spl:-없음} / ${_nov:-없음}"
    local _b3=""
    echo "$_spl" | grep -qiE 'passwordcheck|credcheck|passwordpolicy' || _b3="${_b3} 복잡도 모듈(passwordcheck/credcheck) 미적용"
    [ -n "$_nov" ] && _b3="${_b3} 사용 기간(VALID UNTIL) 미설정: ${_nov% }"
    if [ -n "$_b3" ]; then _kput "D-03" "취약" "비밀번호 정책 미적용:${_b3}"; else _kput "D-03" "양호" "복잡도 모듈(${_spl}) 적용, 비밀번호 역할 전부 사용 기간 설정"; fi

    # D-04 관리자 권한
    _it D-04; _qerr_carry "$_roles_err"
    local _adm; _adm=$(echo "$_roles" | awk -F'|' '$1!="postgres" && ($3=="t" || $4=="t") {print $1"("($3=="t"?"SUPERUSER":"CREATEROLE/CREATEDB/REPLICATION/BYPASSRLS")")"}' | tr '\n' ' ')
    evd_q "D-04" "postgres 외 관리 권한 역할" "${_adm:-없음}"
    if [ -n "$_adm" ]; then _kput "D-04" "수동확인" "postgres 외 관리자 권한 역할: ${_adm}- 필요성 확인 (불필요 시 취약)${_PGXN}"; else _kput "D-04" "양호" "관리자 권한이 postgres 에만 부여${_PGXN}"; fi

    _KNA D-05
    _it D-06; _qerr_carry "$_roles_err"
    evd_q "D-06" "로그인 가능 역할" "${_login:-없음}"
    _kput "D-06" "수동확인" "로그인 가능 역할: ${_login:-없음}- 사용자·응용프로그램별 개별 계정 사용 여부(공용 계정 사용 시 취약) 확인${_PGXN}"
    _KNA D-07

    # D-08 SCRAM-SHA-256
    _it D-08; _qerr_carry "$_roles_err"
    local _pe _md5; _pe=$(get_conf "password_encryption"); _md5=$(echo "$_roles" | awk -F'|' '$5=="MD5"||$5=="OTHER"{print $1}' | tr '\n' ' ')
    evd_q "D-08" "password_encryption / MD5 해시 역할" "${_pe} / ${_md5:-없음}"
    if [ -n "$_md5" ]; then _kput "D-08" "취약" "SHA-256 미만(MD5) 해시 비밀번호 역할: ${_md5% } (password_encryption=${_pe})"
    elif [ "$_pe" = "md5" ]; then _kput "D-08" "취약" "password_encryption=md5 (신규 비밀번호가 MD5 로 저장)"
    else _kput "D-08" "양호" "password_encryption=${_pe}, 저장 비밀번호 SCRAM-SHA-256"; fi

    _KNA D-09
    # D-10 원격 접속 제한 (listen_addresses + pg_hba 전체 허용 규칙, IPv4 0.0.0.0/0 · IPv6 ::/0 · all)
    _it D-10
    if [ -n "$_MANAGED" ]; then
        _os_gate D-10 "pg_hba.conf 는 관리형 서비스가 관리 - 보안그룹·네트워크 ACL 로 접근 통제 (listen_addresses=$(get_conf listen_addresses))"
    else
        local _la _open; _la=$(get_conf "listen_addresses")
        _open=$(echo "$_hba" | awk '$1 ~ /^host/ && $4 ~ /^(0\.0\.0\.0\/(0\.0\.0\.0|0)|::\/(::|0)|::0\/0|all)$/')
        evd_q "D-10" "listen_addresses / 전체 대역 허용 pg_hba 규칙" "${_la} / ${_open:-없음}"
        if [ -n "$_hba_err" ]; then _qerr_add "pg_hba_file_rules 조회 권한 없음: ${_hba_err}"; _kput "D-10" "점검불가" "pg_hba 규칙을 조회하지 못함(${_hba_err}) - listen_addresses=${_la}"
        elif [ -n "$_open" ] && [ "$_la" != "localhost" ]; then _kput "D-10" "취약" "모든 IP 에서 접속 허용 (listen_addresses=${_la}, pg_hba: $(echo "$_open" | tr '\n' ',' | sed 's/,$//'))"
        else _kput "D-10" "양호" "지정 IP 에서만 접속 허용 (listen_addresses=${_la}$( [ -n "$_open" ] && echo ', 전체 허용 규칙 있으나 로컬 수신만'))"; fi
    fi

    # D-11 시스템 테이블 접근 (pg_catalog·information_schema 테이블에 개별 역할 권한 부여)
    _it D-11
    local _st; _st=$(run_q "SELECT DISTINCT pg_get_userbyid(a.grantee)||'('||n.nspname||'.'||c.relname||':'||a.privilege_type||')' FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace CROSS JOIN LATERAL aclexplode(c.relacl) a WHERE n.nspname IN ('pg_catalog','information_schema') AND a.grantee<>0 AND c.relkind IN ('r','v','m','p','f') AND pg_get_userbyid(a.grantee) NOT IN ('postgres') AND pg_get_userbyid(a.grantee) NOT LIKE 'pg\\_%' AND pg_get_userbyid(a.grantee) NOT IN (${_PGX}) AND a.grantee<>c.relowner AND a.grantee NOT IN (SELECT oid FROM pg_roles WHERE rolsuper) ORDER BY 1" | tr '\n' ' ')
    evd_q "D-11" "시스템 스키마 테이블 권한 (PUBLIC·슈퍼유저 제외)" "${_st:-없음}"
    if [ -n "$_st" ]; then _kput "D-11" "취약" "DBA 외 역할에 시스템 테이블 권한 부여: ${_st% }"; else _kput "D-11" "양호" "시스템 테이블 권한이 DBA 에만 부여 (PUBLIC 기본 카탈로그 조회 권한 제외)"; fi

    _KNA D-12 D-13
    # D-14 주요 설정 파일 권한 (postgresql.conf·pg_hba.conf·pg_ident.conf 640, .psql_history 600)
    _it D-14
    if _os_gate D-14 "postgresql.conf·pg_hba.conf·pg_ident.conf·.psql_history 권한"; then
        :
    else
        local _cfg1 _cfg2="" _hf _b14="" _n14=0
        _cfg1="$(get_conf config_file) $(get_conf hba_file) $(get_conf ident_file)"
        for _hf in /root/.psql_history /var/lib/pgsql/.psql_history /var/lib/postgresql/.psql_history; do [ -f "$_hf" ] && _cfg2="${_cfg2} ${_hf}"; done
        # shellcheck disable=SC2086
        evd_ls "D-14" $_cfg1 $_cfg2
        # shellcheck disable=SC2086
        _perm_check 037 $_cfg1; _b14="$_PC_BAD"; _n14=$_PC_FOUND
        # shellcheck disable=SC2086
        _perm_check 077 $_cfg2; _b14="${_b14}${_PC_BAD}"; _n14=$((_n14+_PC_FOUND))
        if [ "$_n14" -eq 0 ]; then _kput "D-14" "점검불가" "설정 파일 경로(${_cfg1})를 읽을 수 없어 점검 불가"
        elif [ -n "$_b14" ]; then _kput "D-14" "취약" "설정 파일 권한 가이드 위반(설정 파일 640, .psql_history 600): ${_b14}"
        else _kput "D-14" "양호" "설정 파일 ${_n14}개 권한 적정 (설정 파일 640 이하, .psql_history 600)"; fi
    fi

    _KNA D-15 D-16 D-17 D-18 D-19
    # D-20 Object Owner 제한 — 접속 가능한 전체 DB 의 사용자 Object 소유자가 관리자(슈퍼유저; 관리형은 rds_superuser 구성원)인지
    _it D-20
    local _ow="" _d _dbs20 _adm20="NOT r.rolsuper"
    [ -n "$_MANAGED" ] && _adm20="NOT r.rolsuper AND NOT pg_has_role(r.rolname,'rds_superuser','member') AND r.rolname NOT IN (${_PGX})"
    _dbs20=$(run_q "SELECT datname FROM pg_database WHERE datallowconn AND NOT datistemplate AND has_database_privilege(datname,'CONNECT') AND datname NOT IN ('rdsadmin','azure_maintenance','azure_sys') ORDER BY 1")
    for _d in $_dbs20; do
        _ow="${_ow}$(OPTS="${OPTS/-d ${PGSQL_DB}/-d $_d}" run_q "SELECT '$_d:'||r.rolname||'('||count(*)||')' FROM pg_class c JOIN pg_roles r ON r.oid=c.relowner JOIN pg_namespace n ON n.oid=c.relnamespace WHERE ${_adm20} AND n.nspname NOT IN ('pg_catalog','information_schema') AND n.nspname NOT LIKE 'pg\\_toast%' AND n.nspname NOT LIKE 'pg\\_temp%' GROUP BY r.rolname ORDER BY 1")
"
    done
    _ow=$(echo "$_ow" | grep -v '^$')
    evd_q "D-20" "전체 DB(${_dbs20:+$(echo $_dbs20 | tr ' ' ',')}) 슈퍼유저 외 Object Owner (pg_class)" "${_ow:-없음}"
    if [ -z "$_dbs20" ]; then _kput "D-20" "점검불가" "점검 가능한 DB 목록을 조회하지 못함"
    elif [ -n "$_ow" ]; then _kput "D-20" "취약" "일반 사용자 소유 Object 존재: $(_brief "$_ow" 20) - 가이드: Object Owner 를 관리자 계정으로 제한${_PGXN}"
    else _kput "D-20" "양호" "전체 DB(${_dbs20}) Object Owner 가 관리자(슈퍼유저)로 제한${_PGXN}"; fi

    _KNA D-21 D-22 D-23 D-24
    _kisa_d25 pgsql "$DB_VER"
    # D-26 감사 기록 (logging_collector / pgaudit)
    _it D-26
    local _lc _ls _pga26 _spl26e=""; _lc=$(get_conf "logging_collector"); _ls=$(get_conf "log_statement"); _pga26=$(_pg_guc "pgaudit.log")
    _spl=$(run_qo "SHOW shared_preload_libraries")
    if printf '%s\n' "$_spl" | grep -qE '^(ERROR|FATAL)'; then _spl26e="$_spl"; _spl=""; fi
    evd_q "D-26" "logging_collector / log_statement / shared_preload_libraries / pgaudit.log" "${_lc} / ${_ls} / ${_spl} / ${_pga26:-N/A}"
    if [ "$_lc" = "on" ] || { echo "$_spl" | grep -qi pgaudit && [ -n "$_pga26" ] && [ "$(_low "$_pga26")" != "none" ]; }; then
        _kput "D-26" "양호" "logging_collector=${_lc} (log_statement=${_ls}$(echo "$_spl" | grep -qi pgaudit && echo ", pgaudit.log=${_pga26}")) - 기관 감사 기록 정책 수립 여부는 인터뷰 확인"
    elif [ -n "$_spl26e" ] && [ -z "$_pga26" ]; then _qerr_add "$_spl26e"; _kput "D-26" "점검불가" "logging_collector=${_lc:-확인 불가} 이고 shared_preload_libraries 를 조회하지 못해 pgaudit 로드 여부 확인 불가 (권한 부족) - ${_spl26e}"
    else _kput "D-26" "취약" "logging_collector=${_lc:-확인 불가}, pgaudit 미설정 - 감사 로그 저장 미설정${_MANAGED:+ (관리형은 파라미터 그룹에서 pgaudit/로그 설정)}"; fi
}

kisa_mssql() {
    _KDB="MSSQL"
    if [ "${_DB_CONN:-0}" != 1 ]; then
        _KNA D-05 D-07 D-09 D-12 D-14 D-15 D-17 D-18 D-19 D-20 D-21 D-22
        _kisa_fail "DB 접속 실패/sqlcmd 미탐지로 점검 불가: ${_CONN_WHY:-$(_qerr_first)} - 접속 정보 확인 후 재점검 (오류 원문은 증적)" "D-01 D-02 D-03 D-04 D-06 D-08 D-10 D-11 D-13 D-16 D-23 D-24 D-25 D-26"
        return
    fi
    _KNA D-05 D-07 D-09 D-12 D-14 D-15 D-17 D-18 D-19 D-20 D-21 D-22
    local _lg _sl _lg_err _sl_err _sa _saName _saOff
    _it D-01
    _lg=$(run_q "SELECT name COLLATE DATABASE_DEFAULT + '|' + type COLLATE DATABASE_DEFAULT + '|' + CAST(is_disabled AS varchar(1)) AS login_info FROM sys.server_principals WHERE type IN ('S','U','G') AND name NOT LIKE '##%' AND name NOT LIKE 'NT SERVICE\\%' AND name NOT LIKE 'NT AUTHORITY\\%' AND name NOT IN (${_MSX}) ORDER BY name")
    _lg_err=$(_qerr_first)
    _sl=$(run_q "SELECT name COLLATE DATABASE_DEFAULT + '|' + CAST(is_disabled AS varchar(1)) + '|' + CAST(is_policy_checked AS varchar(1)) + '|' + CAST(is_expiration_checked AS varchar(1)) + '|' + ISNULL(CONVERT(varchar(6), password_hash, 1),'-') + '|' + CAST(principal_id AS varchar(10)) AS sql_login FROM sys.sql_logins WHERE name NOT LIKE '##%' AND name NOT IN (${_MSX}) ORDER BY name")
    _sl_err=$(_qerr_first)
    evd_q "D-01" "로그인 (이름|유형 S=SQL U=Windows G=그룹|비활성)" "${_lg:-조회 결과 없음}"
    evd_q "D-01" "SQL 로그인 (이름|비활성|암호정책|만료|해시접두(알고리즘)|principal_id)" "${_sl:-조회 결과 없음}"
    _sa=$(echo "$_sl" | awk -F'|' '$6=="1"' | head -1)
    _saName="sa"; [ -n "$_sa" ] && _saName=$(echo "$_sa" | cut -d'|' -f1)
    _saOff=0; [ -n "$_sa" ] && [ "$(echo "$_sa" | cut -d'|' -f2)" = "1" ] && _saOff=1

    # D-01 기본 계정(sa) 초기 비밀번호 변경 또는 잠금 (PWDCOMPARE 로 빈 값·계정명·기본값 일치 여부만 확인, 값 비공개)
    local _wk
    _wk=$(run_q "SELECT name FROM sys.sql_logins WHERE principal_id = 1 AND (PWDCOMPARE('', password_hash) = 1 OR PWDCOMPARE(name, password_hash) = 1 OR PWDCOMPARE('password', password_hash) = 1 OR PWDCOMPARE('sa', password_hash) = 1)")
    [ "${_ms_ctl:-0}" != "1" ] && _qerr_add "CONTROL SERVER 권한 없음(HAS_PERMS_BY_NAME=${_ms_ctl:-?}) - password_hash 조회 불가로 빈/기본 비밀번호 검사 불가"
    evd_q "D-01" "sa 빈·기본 비밀번호 일치 여부 (PWDCOMPARE, 값 비공개)" "$( [ -n "$_wk" ] && echo '일치' || echo '불일치')"
    if [ -z "$_sa" ]; then _kput "D-01" "점검불가" "기본 관리자(sa) SQL 로그인 조회 결과 없음 - 비밀번호 변경·비활성 확인"
    elif [ "$_saOff" = 1 ]; then _kput "D-01" "양호" "기본 관리자 계정(${_saName}) 비활성(잠금)"
    elif [ -n "$_wk" ]; then _kput "D-01" "취약" "기본 관리자 계정(${_saName}) 비밀번호가 빈 값 또는 기본값(계정명·password)과 일치"
    else _kput "D-01" "양호" "기본 관리자 계정(${_saName}) 비밀번호 변경됨 (빈 값·기본값 불일치)$( [ "$_saName" = sa ] && echo ' - 이름 변경 권고')"; fi

    # D-02 불필요 계정
    _it D-02; _qerr_carry "$_lg_err"
    local _act _tst
    _act=$(echo "$_lg" | awk -F'|' '$3=="0"{print $1}' | tr '\n' ' ')
    _tst=$(echo "$_act" | tr ' ' '\n' | grep -iE '^(test|guest|demo|temp|tmp|sample|user[0-9]*)[0-9_]*$' | tr '\n' ' ')   # 끝을 고정해 userdb·tempmon 같은 정상 로그인 제외
    evd_q "D-02" "활성 로그인" "${_act:-없음}"
    if [ -n "$_tst" ]; then _kput "D-02" "취약" "테스트성 로그인 활성: ${_tst% }"; else _kput "D-02" "수동확인" "활성 로그인: ${_act:-없음}- 인가되지 않은 계정·퇴직자·미사용 계정 여부 확인 (없으면 양호)${_MSXN}"; fi

    # D-03 비밀번호 사용 기간 및 복잡도 (SQL 로그인 CHECK_POLICY·CHECK_EXPIRATION; Linux 에는 OS 암호 정책(secedit)이 없어 인터뷰)
    _it D-03; _qerr_carry "$_sl_err"
    local _np; _np=$(echo "$_sl" | awk -F'|' '$2=="0" && ($3!="1" || $4!="1") {print $1"(정책="$3",만료="$4")"}' | tr '\n' ' ')
    evd_q "D-03" "CHECK_POLICY/CHECK_EXPIRATION 미적용 활성 SQL 로그인" "${_np:-없음}"
    if [ -n "$_np" ]; then _kput "D-03" "취약" "비밀번호 정책 미흡: 암호 정책·만료 강제 미적용 SQL 로그인: ${_np% }"
    else _kput "D-03" "수동확인" "SQL 로그인 암호 정책·만료 강제 적용 - Linux 는 OS 암호 정책(secedit) 없음: SQL Server 자체 정책의 최대 사용 기간(90일 이하)·복잡도 설정을 인터뷰/증적으로 확인"; fi

    # D-04 관리자 권한(sysadmin)은 필요한 계정에만
    _it D-04
    local _sy _syx
    _sy=$(run_q "SELECT m.name AS sysadmin_member FROM sys.server_role_members rm JOIN sys.server_principals r ON r.principal_id = rm.role_principal_id JOIN sys.server_principals m ON m.principal_id = rm.member_principal_id WHERE r.name = 'sysadmin' ORDER BY 1")
    evd_q "D-04" "sysadmin 구성원" "${_sy:-없음}"
    _syx=$(echo "$_sy" | grep -v '^$' | grep -vxF "$_saName" | grep -vE '^NT (SERVICE|AUTHORITY)\\' | grep -vE "^($(printf '%s' "$_MSX" | tr -d "'" | tr ',' '|'))$" | tr '\n' ' ')
    if [ -n "$_syx" ]; then _kput "D-04" "수동확인" "sa·서비스 계정 외 sysadmin: ${_syx}- 관리자 권한 필요성 확인 (불필요 시 취약)"
    else _kput "D-04" "양호" "sysadmin 이 sa·서비스 계정에만 부여: $(echo "$_sy" | tr '\n' ' ')"; fi

    # D-06 사용자별 계정 사용
    _it D-06; _qerr_carry "$_lg_err"
    _kput "D-06" "수동확인" "활성 로그인: ${_act:-없음}- 사용자·응용프로그램별 개별 계정 사용 여부(공용 계정 사용 시 취약) 확인${_MSXN}"

    # D-08 안전한 암호화 알고리즘 (SQL 2012 이상 SHA-512 = 해시 0x0200, 0x0100 = SHA-1)
    _it D-08; _qerr_carry "$_sl_err"
    local _old
    _old=$(echo "$_sl" | awk -F'|' '$5=="0x0100" {print $1}' | tr '\n' ' ')
    if [ "${_ms_ctl:-0}" != "1" ] && [ -n "$_sl" ]; then _qerr_add "CONTROL SERVER 권한 없음 - password_hash 를 볼 수 없어 해시 알고리즘 확인 불가"; fi
    if [ -z "$_sl" ] && [ -z "$_sl_err" ]; then _kput "D-08" "양호" "SQL 로그인 없음 (Windows 인증만 사용)"
    elif [ -n "$_old" ]; then _kput "D-08" "취약" "SHA-1(0x0100) 해시 비밀번호 로그인: ${_old% } - 비밀번호 재설정 필요"
    else _kput "D-08" "양호" "SQL 로그인 비밀번호 SHA-512(0x0200) 해시 ($(echo "$_sl" | grep -c .)개)"; fi

    # D-10 원격 접속 제한 (Linux 호스트 방화벽에서 DB 포트 접근 IP 지정; 관리형은 보안그룹)
    _it D-10
    if _os_gate D-10 "호스트 방화벽(iptables/firewalld/ufw)은 서버 OS 설정"; then
        :
    else
        local _p10 _fw10 _tool10=""
        _p10=$(run_q "SELECT TOP 1 local_tcp_port FROM sys.dm_exec_connections WHERE local_tcp_port IS NOT NULL" | grep -oE '^[0-9]+' | head -1); _p10=${_p10:-$MSSQL_PORT}
        for _t in iptables firewall-cmd ufw; do command -v "$_t" >/dev/null 2>&1 && _tool10="$_tool10 $_t"; done
        evd "D-10" "{ iptables -S; firewall-cmd --list-all; ufw status verbose; } 2>&1"
        _fw10=$( { iptables -S 2>/dev/null | grep -E -- "--dport $_p10" | grep -E -- '-s [0-9]'; firewall-cmd --list-rich-rules 2>/dev/null | grep "$_p10"; ufw status 2>/dev/null | grep "$_p10" | grep -v Anywhere; } | tr '\n' ' ')
        if [ -n "$_fw10" ]; then _kput "D-10" "양호" "DB 포트(${_p10}) 출발지 지정 규칙: ${_fw10}"
        elif [ -z "$_tool10" ]; then _kput "D-10" "점검불가" "호스트 방화벽 도구를 실행하지 못해 점검 불가 (root 권한·설치 확인) - 네트워크 장비·보안그룹 확인"
        else _kput "D-10" "수동확인" "DB 포트(${_p10}) 지정 IP 방화벽 규칙 미발견(${_tool10# } 조회) - 네트워크 장비·보안그룹 등에서 지정 IP 접근 제한 여부 확인"; fi
    fi

    # D-11 시스템 테이블 접근 제한 (PUBLIC·GUEST 권한 - 설치 기본 부여분 제외)
    _it D-11
    local _pg
    _pg=$(run_q "SELECT dp.name COLLATE DATABASE_DEFAULT + ':' + o.name COLLATE DATABASE_DEFAULT + ':' + p.permission_name COLLATE DATABASE_DEFAULT AS sys_perm FROM master.sys.database_permissions p JOIN master.sys.all_objects o ON o.object_id = p.major_id JOIN master.sys.database_principals dp ON dp.principal_id = p.grantee_principal_id WHERE p.class = 1 AND dp.name IN ('public','guest') AND p.state IN ('G','W') AND o.type IN ('S','U') AND o.name NOT IN ('trace_xe_action_map','trace_xe_event_map','spt_fallback_db','spt_fallback_dev','spt_fallback_usg','spt_monitor')")
    evd_q "D-11" "master 시스템 테이블 PUBLIC·GUEST 권한 (설치 기본 6개 제외)" "${_pg:-없음}"
    if [ -n "$_pg" ]; then _kput "D-11" "취약" "PUBLIC·GUEST 에 시스템 테이블 권한 부여: $(_brief "$_pg" 10)"; else _kput "D-11" "양호" "PUBLIC·GUEST 에 추가 부여된 시스템 테이블 권한 없음 (설치 기본 권한 제외)"; fi

    # D-13 불필요한 ODBC/OLE-DB 데이터 소스 (Linux: /etc/odbc.ini, ~/.odbc.ini)
    _it D-13
    if _os_gate D-13 "ODBC 데이터 소스(DSN)는 서버 OS 설정"; then
        :
    else
        local _dsn13
        evd "D-13" "{ odbcinst -q -s; cat /etc/odbc.ini \"\$HOME/.odbc.ini\"; } 2>&1"
        _dsn13=$( { odbcinst -q -s 2>/dev/null; grep -h '^\[' /etc/odbc.ini "$HOME/.odbc.ini" 2>/dev/null; } | grep '^\[' | sort -u | tr -d '[]' | tr '\n' ' ')
        if [ -n "$_dsn13" ]; then _kput "D-13" "수동확인" "ODBC 데이터 소스 DSN: ${_dsn13}- 사용하지 않는 데이터 소스 제거 여부 확인"; else _kput "D-13" "양호" "등록된 ODBC 데이터 소스(DSN) 없음"; fi
    fi

    # D-16 Windows 인증 모드 사용 (혼합 모드면 sa 비활성 또는 강력한 암호 정책)
    _it D-16; _qerr_carry "$_sl_err"
    local _iso _sapol=0
    _iso=$(run_q "SELECT CAST(SERVERPROPERTY('IsIntegratedSecurityOnly') AS varchar(1)) AS integrated_only" | head -1 | tr -d ' ')
    [ -n "$_sa" ] && [ "$(echo "$_sa" | cut -d'|' -f3)" = "1" ] && _sapol=1
    evd_q "D-16" "IsIntegratedSecurityOnly / sa 비활성 / sa 암호 정책" "${_iso} / ${_saOff} / ${_sapol}"
    if [ "$_iso" = "1" ]; then _kput "D-16" "양호" "Windows 인증 모드 사용"
    elif [ -z "$_iso" ]; then _kput "D-16" "점검불가" "인증 모드(IsIntegratedSecurityOnly) 조회 결과 없음"
    elif [ "$_saOff" = 1 ]; then _kput "D-16" "양호" "혼합 인증 모드, sa 비활성"
    elif [ "$_sapol" = 1 ]; then _kput "D-16" "양호" "혼합 인증 모드, sa 활성 - 암호 정책(CHECK_POLICY) 적용"
    else _kput "D-16" "취약" "혼합 인증 모드 사용, sa 활성이며 암호 정책(CHECK_POLICY) 미적용"; fi

    # D-23 xp_cmdshell 사용 제한 (비활성, 또는 활성 시 public 실행 권한 없음 + 서비스 계정 sysadmin 아님)
    _it D-23
    local _xp _xpPub
    _xp=$(run_q "SELECT CAST(value_in_use AS varchar(1)) AS xp_cmdshell FROM sys.configurations WHERE name = 'xp_cmdshell'" | head -1 | tr -d ' ')
    _xpPub=$(run_q "SELECT dp.name AS grantee FROM master.sys.database_permissions p JOIN master.sys.all_objects o ON o.object_id = p.major_id JOIN master.sys.database_principals dp ON dp.principal_id = p.grantee_principal_id WHERE o.name = 'xp_cmdshell' AND p.state IN ('G','W') AND dp.name IN ('public','guest')" | tr '\n' ',')
    evd_q "D-23" "xp_cmdshell value_in_use / public·guest 실행 권한" "${_xp:-?} / ${_xpPub:-없음}"
    if ! printf '%s' "$_xp" | grep -qE '^[01]$'; then _kput "D-23" "점검불가" "xp_cmdshell 설정 조회 결과 없음"
    elif [ "$_xp" != "1" ]; then _kput "D-23" "양호" "xp_cmdshell 비활성"
    elif [ -n "$_xpPub" ]; then _kput "D-23" "취약" "xp_cmdshell 활성 + public·guest 실행 권한: ${_xpPub%,}"
    else _kput "D-23" "수동확인" "xp_cmdshell 활성 (public 실행 권한 없음) - 응용프로그램 연동 서비스 계정의 sysadmin 권한 여부 확인 (sysadmin: $(echo "$_sy" | tr '\n' ' '))"; fi

    # D-24 Registry Procedure 권한 제한 (7종 확장 프로시저 public·guest 부여)
    _it D-24
    local _rp
    _rp=$(run_q "SELECT o.name COLLATE DATABASE_DEFAULT + ':' + dp.name COLLATE DATABASE_DEFAULT AS reg_perm FROM master.sys.database_permissions p JOIN master.sys.all_objects o ON o.object_id = p.major_id JOIN master.sys.database_principals dp ON dp.principal_id = p.grantee_principal_id WHERE p.class = 1 AND p.type = 'EX' AND p.state IN ('G','W') AND dp.name IN ('public','guest') AND o.name IN ('xp_regaddmultistring','xp_regdeletekey','xp_regdeletevalue','xp_regenumvalues','xp_regread','xp_regremovemultistring','xp_regwrite')" | tr '\n' ' ')
    evd_q "D-24" "레지스트리 확장 프로시저 public·guest 부여" "${_rp:-없음}"
    if [ -n "$_rp" ]; then _kput "D-24" "취약" "DBA 외 public·guest 에 부여: ${_rp% }"; else _kput "D-24" "양호" "제한 대상 레지스트리 확장 프로시저 public·guest 부여 없음"; fi

    # D-25 주기적 보안 패치 (지원 종료 버전 = 취약)
    _kisa_d25 mssql "$_ver_num"

    # D-26 감사 기록 (로그인 감사 '실패한 로그인과 성공한 로그인 모두' = AuditLevel 3 + 로그인 감사 사양, 또는 서버 감사 + 로그인 감사 사양)
    _it D-26
    local _al _sau _lspec
    _al=$(run_qo "DECLARE @v int; EXEC master.dbo.xp_instance_regread N'HKEY_LOCAL_MACHINE', N'Software\\Microsoft\\MSSQLServer\\MSSQLServer', N'AuditLevel', @v OUTPUT; SELECT CAST(@v AS varchar(3)) AS audit_level" | head -1 | tr -d ' ')
    case "$_al" in ERROR*) _al="" ;; esac
    _sau=$(run_q "SELECT name FROM sys.server_audits WHERE is_state_enabled = 1" | tr '\n' ',')
    _lspec=$(run_q "SELECT s.name+': '+d.audit_action_name AS audit_spec FROM sys.server_audit_specifications s JOIN sys.server_audit_specification_details d ON s.server_specification_id=d.server_specification_id WHERE s.is_state_enabled=1 AND d.audit_action_name IN ('FAILED_LOGIN_GROUP','SUCCESSFUL_LOGIN_GROUP')" | tr '\n' ',')
    evd_q "D-26" "로그인 감사 AuditLevel(0 없음/1 성공/2 실패/3 모두) / 활성 서버 감사 / 로그인 감사 사양" "${_al:-N/A} / ${_sau:-없음} / ${_lspec:-없음}"
    if [ "$_al" = "3" ] || { [ -n "$_sau" ] && [ -n "$_lspec" ]; }; then
        _kput "D-26" "양호" "감사 설정: $( [ "$_al" = 3 ] && echo '로그인 감사 성공·실패 모두 ')$( [ -n "$_sau" ] && echo "서버 감사 ${_sau%,} (로그인 감사 사양 ${_lspec%,})") - 감사 기록 정책(보관·백업) 수립 여부는 인터뷰"
    elif [ -z "$_al" ] && [ -z "$_sau" ]; then _kput "D-26" "점검불가" "활성 서버 감사가 없고 로그인 감사 수준(AuditLevel, xp_instance_regread)도 조회하지 못해 점검 불가 - 로그인 감사 설정 수동 확인"
    elif [ -n "$_sau" ]; then _kput "D-26" "취약" "서버 감사 ${_sau%,} 활성이나 로그인 성공/실패 감사 사양 없음, 로그인 감사 수준=${_al:-N/A} - 가이드: 실패·성공 모두 감사"
    else _kput "D-26" "취약" "로그인 감사 '$(case "$_al" in 0) echo 없음;; 1) echo 성공한 로그인만;; 2) echo 실패한 로그인만;; *) echo "확인 불가(${_al:-N/A})";; esac)', 활성 서버 감사 없음 - 가이드: 실패·성공 모두 감사"; fi
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
        _hnote "# Windows 환경 — DBMS 전 항목 N-A 처리"
        for i in $_DBM_CODES; do
            na "$i" "Windows 환경 — Linux/Unix 전용 항목"
        done
    else
        _hnote "# DBMS를 자동 탐지할 수 없습니다."
        _hnote "# DBMS_TYPE=oracle|mysql|pgsql|tibero|mssql 환경변수를 설정하고 재실행하세요."
        _dbp=$( { ps -e -o comm= 2>/dev/null || cat /proc/[0-9]*/comm 2>/dev/null; } | sed 's#.*/##' | grep -iE 'pmon|mysqld|mariadbd|postgres|sqlservr|tbsvr' | sort -u | tr '\n' ' ')
        for i in $_DBM_CODES; do
            if [ -n "$_dbp" ]; then nc "$i" "DBMS 프로세스(${_dbp% })는 있으나 종류/클라이언트를 탐지하지 못해 점검 불가 - DBMS_TYPE 지정 후 재점검"
            else na "$i" "DBMS 미설치"; fi
        done
    fi ;;
esac

# 주요정보 상세가이드(2026) D-01~26 (MySQL·MariaDB·PostgreSQL·MSSQL)
[ "$_KMODE" != "ef" ] && case "$DBMS_TYPE" in
mysql|mariadb) kisa_mysql ;;
pgsql|postgresql) kisa_pgsql ;;
mssql|sqlserver) kisa_mssql ;;
esac
_print_header
_flush_results
_TOTAL=$((_CP + _CF + _CM + _CX + _CN))
_SUMMARY="# ================================================================
# 점검 요약
#   총 점검 항목: ${_TOTAL}"
if [ "$_TOTAL" -gt 0 ] 2>/dev/null; then
_SUMMARY="${_SUMMARY}
#   양호:         ${_CP}  ($((_CP * 100 / _TOTAL))%)
#   취약:         ${_CF}  ($((_CF * 100 / _TOTAL))%)
#   수동확인:     ${_CM}
#   점검불가:     ${_CX}
#   N-A:          ${_CN}"
fi
printf '%s\n' "$_SUMMARY"
echo "# ================================================================"
echo "# 점검 완료: $(date '+%Y-%m-%d %H:%M:%S')"
echo "# 증적 파일: ${_EVD}"
[ -n "$_RESF" ] && echo "# 결과 파일(자동 저장): ${_RESF}  ← 증적 파일과 함께 회수"
{ printf '%s\n' "$_SUMMARY"; echo "# 점검 완료: $(date '+%Y-%m-%d %H:%M:%S')"; } >> "$_EVD"
[ -n "$_TEEPID" ] && { exec >&- 2>/dev/null; wait "$_TEEPID" 2>/dev/null; sleep 1; }
exit 0
