#!/bin/bash
# ================================================================
# 전자금융기반시설 DBMS 취약점 점검 스크립트 v4.0
# 기준: 전자금융기반시설 보안 취약점 평가기준 제2026-1호 [데이터베이스]
#
# 지원 DBMS: Oracle(10g~21c) / MSSQL(별도 ps1) /
#            MySQL(5.6~8.0) / MariaDB(10.x) / PostgreSQL(10~16) /
#            Tibero(5~7)
#
# [사용법]
#   DBMS_TYPE=oracle  bash check_dbms.sh > /tmp/hostname_oracle.txt
#   DBMS_TYPE=mysql   bash check_dbms.sh > /tmp/hostname_mysql.txt
#   DBMS_TYPE=pgsql   bash check_dbms.sh > /tmp/hostname_pgsql.txt
#   DBMS_TYPE=tibero  bash check_dbms.sh > /tmp/hostname_tibero.txt
#
# 또는 자동 탐지:
#   bash check_dbms.sh > /tmp/hostname_dbms.txt
#
# [접속 정보 환경변수]
#   Oracle:  ORACLE_USER ORACLE_PASS ORACLE_SID  (기본: system/CHANGE_ME)
#   MySQL:   MYSQL_USER  MYSQL_PASS  MYSQL_HOST  (기본: root/CHANGE_ME/localhost)
#   PgSQL:   PGSQL_USER  PGSQL_DB    PGSQL_HOST  (기본: postgres/postgres/localhost)
#   Tibero:  TIBERO_USER TIBERO_PASS TIBERO_DB
#
# [출력] DBM-항목코드|결과|근거
# ================================================================

# ── DBMS 자동 탐지 ──────────────────────────────────────────────
detect_dbms() {
    [ -n "$DBMS_TYPE" ] && return

    # Oracle: ORACLE_HOME 또는 sqlplus
    [ -n "$ORACLE_HOME" ] && [ -x "$ORACLE_HOME/bin/sqlplus" ] && DBMS_TYPE="oracle" && return
    command -v sqlplus >/dev/null 2>&1 && DBMS_TYPE="oracle" && return
    # MySQL
    command -v mysql   >/dev/null 2>&1 && DBMS_TYPE="mysql"  && return
    # PostgreSQL
    command -v psql    >/dev/null 2>&1 && DBMS_TYPE="pgsql"  && return
    # MariaDB
    command -v mariadb >/dev/null 2>&1 && DBMS_TYPE="mariadb" && return
    # Tibero
    [ -n "$TB_HOME" ]  && DBMS_TYPE="tibero" && return

    DBMS_TYPE="unknown"
}
detect_dbms

HN=$(hostname 2>/dev/null || uname -n)
echo "# ================================================================"
echo "# 점검 대상: ${HN}"
echo "# DBMS 종류: ${DBMS_TYPE}"
echo "# 점검 기준: 전자금융기반시설 보안 취약점 평가기준 제2026-1호 [데이터베이스]"
echo "# 점검 일시: $(date '+%Y-%m-%d %H:%M:%S')"
echo "# ================================================================"

ok()  { echo "DBM-${1}|양호|${2}"; }
ng()  { echo "DBM-${1}|취약|${2}"; }
na()  { echo "DBM-${1}|N-A|${2}"; }
mc()  { echo "DBM-${1}|수동확인|${2}"; }

# ================================================================
# Oracle 점검
# ================================================================
check_oracle() {
    ORACLE_USER="${ORACLE_USER:-system}"
    ORACLE_PASS="${ORACLE_PASS:-CHANGE_ME}"
    ORACLE_SID="${ORACLE_SID:-}"
    ORACLE_SERVICE="${ORACLE_SERVICE:-}"
    ORACLE_HOST="${ORACLE_HOST:-localhost}"
    ORACLE_PORT="${ORACLE_PORT:-1521}"

    SQLPLUS=$(command -v sqlplus 2>/dev/null)
    [ -z "$SQLPLUS" ] && [ -n "$ORACLE_HOME" ] && SQLPLUS="$ORACLE_HOME/bin/sqlplus"
    if [ -z "$SQLPLUS" ] || [ ! -x "$SQLPLUS" ]; then
        for i in 001 003 004 005 006 007 008 009 011 012 013 014 015 016 017 \
                 019 020 022 024 025 026 028 029 030 031; do
            echo "DBM-${i}|수동확인|sqlplus 미탐지 - 수동 확인"
        done
        return
    fi

    if [ -n "$ORACLE_SERVICE" ]; then
        CONN="${ORACLE_USER}/${ORACLE_PASS}@${ORACLE_HOST}:${ORACLE_PORT}/${ORACLE_SERVICE}"
    elif [ -n "$ORACLE_SID" ]; then
        CONN="${ORACLE_USER}/${ORACLE_PASS}@${ORACLE_SID}"
    else
        CONN="${ORACLE_USER}/${ORACLE_PASS}"
    fi

    run_q() {
        "$SQLPLUS" -s /nolog << EOF 2>/dev/null
CONNECT ${CONN}
SET PAGESIZE 0 FEEDBACK OFF HEADING OFF LINESIZE 200 TRIMSPOOL ON
$1
EXIT
EOF
    }

    DB_VER=$(run_q "SELECT VERSION FROM V\$INSTANCE;" | grep -oE '[0-9]+\.[0-9]+' | head -1)
    DB_MAJ=$(echo "$DB_VER" | cut -d. -f1)
    echo "# Oracle 버전: ${DB_VER}"

    # DBM-001: 취약 패스워드
    def_accounts=""
    [ "${DB_MAJ:-0}" -ge 12 ] 2>/dev/null && \
        ACCTS="'SYS','SYSTEM','DBSNMP','SCOTT','OUTLN','MDSYS','XDB','ANONYMOUS','CTXSYS'" || \
        ACCTS="'SYS','SYSTEM','DBSNMP','SCOTT','OUTLN','MDSYS','XDB','ANONYMOUS'"
    def_accounts=$(run_q "SELECT USERNAME||'('||ACCOUNT_STATUS||')' FROM DBA_USERS WHERE USERNAME IN (${ACCTS}) AND ACCOUNT_STATUS='OPEN';")
    def_accounts=$(echo "$def_accounts" | grep -v "^$" | head -5)
    [ -n "$def_accounts" ] && ng "001" "기본 계정 OPEN: $(echo $def_accounts | tr '\n' ',')" || ok "001" "Oracle 기본 계정 OPEN 상태 없음"

    # DBM-003: 불필요 계정
    mc "003" "불필요 계정 목록 수동 확인 (SELECT USERNAME,ACCOUNT_STATUS FROM DBA_USERS)"

    # DBM-004: 불필요 관리자 계정
    dba=$(run_q "SELECT GRANTEE FROM DBA_ROLE_PRIVS WHERE GRANTED_ROLE='DBA' AND GRANTEE NOT IN ('SYS','SYSTEM','DBA') ORDER BY GRANTEE;" | grep -v "^$" | head -5)
    [ -n "$dba" ] && mc "004" "DBA 권한 계정: $(echo $dba | tr '\n' ',') - 적정성 수동 확인" || ok "004" "SYS/SYSTEM 외 DBA 권한 부여 없음"

    # DBM-005: 중요정보 암호화
    mc "005" "테이블 컬럼별 암호화 적용 여부 수동 확인 (주민번호, 비밀번호 등)"

    # DBM-006: 로그인 실패 횟수 제한
    failed=$(run_q "SELECT LIMIT FROM DBA_PROFILES WHERE PROFILE='DEFAULT' AND RESOURCE_NAME='FAILED_LOGIN_ATTEMPTS';" | tr -d ' \n')
    if [ "$failed" = "UNLIMITED" ] || [ -z "$failed" ]; then
        ng "006" "DEFAULT 프로파일 FAILED_LOGIN_ATTEMPTS=UNLIMITED"
    elif [ "$failed" -gt 5 ] 2>/dev/null; then
        ng "006" "FAILED_LOGIN_ATTEMPTS=${failed} (5회 이하 권고)"
    else
        ok "006" "FAILED_LOGIN_ATTEMPTS=${failed} (5회 이하)"
    fi

    # DBM-007: 패스워드 복잡도
    func=$(run_q "SELECT LIMIT FROM DBA_PROFILES WHERE PROFILE='DEFAULT' AND RESOURCE_NAME='PASSWORD_VERIFY_FUNCTION';" | tr -d ' \n')
    [ -z "$func" ] || [ "$func" = "NULL" ] && ng "007" "PASSWORD_VERIFY_FUNCTION 미설정" || ok "007" "PASSWORD_VERIFY_FUNCTION=${func}"

    # DBM-008: 패스워드 변경 주기
    life=$(run_q "SELECT LIMIT FROM DBA_PROFILES WHERE PROFILE='DEFAULT' AND RESOURCE_NAME='PASSWORD_LIFE_TIME';" | tr -d ' \n')
    if [ "$life" = "UNLIMITED" ] || [ -z "$life" ]; then
        ng "008" "PASSWORD_LIFE_TIME=UNLIMITED (무제한)"
    elif [ "$life" -le 90 ] 2>/dev/null; then
        ok "008" "PASSWORD_LIFE_TIME=${life}일 (90일 이하)"
    else
        ng "008" "PASSWORD_LIFE_TIME=${life}일 (90일 초과)"
    fi

    # DBM-009: 미사용 세션 종료
    mc "009" "세션 타임아웃 설정 수동 확인 (DBA_PROFILES IDLE_TIME)"

    # DBM-011: 감사 로그
    if [ "${DB_MAJ:-0}" -ge 12 ] 2>/dev/null; then
        ua=$(run_q "SELECT VALUE FROM V\$OPTION WHERE PARAMETER='Unified Auditing';" | tr -d ' \n')
        if [ "$ua" = "TRUE" ]; then
            cnt=$(run_q "SELECT COUNT(*) FROM AUDIT_UNIFIED_POLICIES WHERE ENABLED_OPT IS NOT NULL;" | tr -d ' \n')
            [ "${cnt:-0}" -gt 0 ] 2>/dev/null && ok "011" "통합 감사 활성 (정책 ${cnt}개)" || ng "011" "통합 감사 활성화됐으나 정책 없음"
        else
            at=$(run_q "SELECT VALUE FROM V\$PARAMETER WHERE NAME='audit_trail';" | tr -d ' \n')
            [ "$at" = "NONE" ] || [ -z "$at" ] && ng "011" "audit_trail=NONE" || ok "011" "audit_trail=${at}"
        fi
    else
        at=$(run_q "SELECT VALUE FROM V\$PARAMETER WHERE NAME='audit_trail';" | tr -d ' \n')
        [ "$at" = "NONE" ] || [ -z "$at" ] && ng "011" "audit_trail=NONE" || ok "011" "audit_trail=${at}"
    fi

    # DBM-012: Listener Control Utility 접근 제한
    _found_lora=0
    for lora in "$ORACLE_HOME/network/admin/listener.ora" "/etc/oracle/listener.ora"; do
        [ -f "$lora" ] || continue
        if grep -qi "tcp.validnode_checking\s*=\s*yes" "$lora" 2>/dev/null; then
            ok "012" "tcp.validnode_checking=yes (${lora})"
        else
            ng "012" "tcp.validnode_checking 미설정 (${lora})"
        fi
        _found_lora=1
        break
    done
    [ $_found_lora -eq 0 ] && mc "012" "listener.ora 수동 확인 (파일 미발견)"

    # DBM-013: 원격 접속 접근 제어
    remote_os=$(run_q "SELECT VALUE FROM V\$PARAMETER WHERE NAME='remote_os_authent';" | tr -d ' \n')
    case "${remote_os^^}" in
    FALSE) ok "013" "remote_os_authent=FALSE" ;;
    TRUE)  ng "013" "remote_os_authent=TRUE (FALSE 권고)" ;;
    *)     mc "013" "remote_os_authent=${remote_os:-미발견}" ;;
    esac

    # DBM-014: OS 역할 인증 비활성화
    os_roles=$(run_q "SELECT VALUE FROM V\$PARAMETER WHERE NAME='os_roles';" | tr -d ' \n')
    case "${os_roles^^}" in
    FALSE) ok "014" "os_roles=FALSE" ;;
    TRUE)  ng "014" "os_roles=TRUE (OS 기반 역할 인증 취약)" ;;
    *)     ok "014" "os_roles=${os_roles:-FALSE(기본값)}" ;;
    esac

    # DBM-015: PUBLIC 불필요 권한
    pkgs=$(run_q "SELECT TABLE_NAME FROM DBA_TAB_PRIVS WHERE GRANTEE='PUBLIC' AND PRIVILEGE='EXECUTE' AND TABLE_NAME IN ('UTL_HTTP','UTL_FILE','UTL_SMTP','UTL_TCP','DBMS_SCHEDULER');" | grep -v "^$" | head -5)
    [ -n "$pkgs" ] && ng "015" "PUBLIC EXECUTE 권한: $(echo $pkgs | tr '\n' ',')" || ok "015" "PUBLIC 위험 패키지 EXECUTE 없음"

    # DBM-016: 보안패치
    mc "016" "Oracle 보안패치 적용 현황 수동 확인"

    # DBM-017: 시스템 테이블 접근 권한
    mc "017" "업무상 불필요한 시스템 뷰/테이블 접근 권한 수동 확인"

    # DBM-019: 패스워드 재사용 제한
    rmax=$(run_q "SELECT LIMIT FROM DBA_PROFILES WHERE PROFILE='DEFAULT' AND RESOURCE_NAME='PASSWORD_REUSE_MAX';" | tr -d ' \n')
    rtime=$(run_q "SELECT LIMIT FROM DBA_PROFILES WHERE PROFILE='DEFAULT' AND RESOURCE_NAME='PASSWORD_REUSE_TIME';" | tr -d ' \n')
    if [ "$rmax" = "UNLIMITED" ] && [ "$rtime" = "UNLIMITED" ]; then
        ng "019" "PASSWORD_REUSE_MAX/TIME 모두 UNLIMITED"
    elif [ "${rmax:-0}" -ge 3 ] 2>/dev/null || [ "${rtime:-0}" -ge 60 ] 2>/dev/null; then
        ok "019" "PASSWORD_REUSE_MAX=${rmax}, TIME=${rtime}"
    else
        ng "019" "패스워드 재사용 제한 미흡: MAX=${rmax}, TIME=${rtime}"
    fi

    # DBM-020: 사용자별 계정 분리
    mc "020" "사용자별 개별 계정 사용 여부 수동 확인 (공용 계정 제거)"

    # DBM-021: 불필요한 ODBC/OLE-DB 데이터 소스 및 드라이버 제거 (Windows MSSQL 전용)
    na "021" "Windows MSSQL 전용 항목 (Oracle 해당 없음)"

    # DBM-022: 설정 파일 접근 권한
    if [ -f "$ORACLE_HOME/network/admin/tnsnames.ora" ]; then
        perm=$(stat -c "%a" "$ORACLE_HOME/network/admin/tnsnames.ora" 2>/dev/null)
        owner=$(stat -c "%U" "$ORACLE_HOME/network/admin/tnsnames.ora" 2>/dev/null)
        [ "${perm:-777}" -le 640 ] 2>/dev/null && ok "022" "tnsnames.ora 권한=${perm}" || ng "022" "tnsnames.ora 권한=${perm} (640 이하 권고)"
    else
        mc "022" "설정 파일 접근 권한 수동 확인 (tnsnames.ora, listener.ora)"
    fi

    # DBM-024: WITH GRANT OPTION
    mc "024" "WITH GRANT OPTION 부여 현황 수동 확인 (SELECT * FROM DBA_SYS_PRIVS WHERE ADMIN_OPTION='YES')"

    # DBM-025: EoS
    mc "025" "Oracle ${DB_VER} EoS 여부 수동 확인 (Oracle 제품 수명 주기 페이지 참조)"

    # DBM-026: 구동 계정 umask
    oracle_umask=$(su -c "umask" oracle 2>/dev/null)
    [ -n "$oracle_umask" ] && {
        um=$(echo "$oracle_umask" | tr -d '0' | head -1)
        [ "${um:-0}" -ge 22 ] 2>/dev/null && ok "026" "oracle 계정 umask=${oracle_umask}" || ng "026" "oracle umask=${oracle_umask} (022 이상 권고)"
    } || mc "026" "Oracle 구동 계정 umask 수동 확인"

    # DBM-028: 불필요 DB Object
    mc "028" "불필요 DB Object(PUBLIC synonym 등) 수동 확인"

    # DBM-029: 자원 사용 제한 (프로파일)
    sess=$(run_q "SELECT LIMIT FROM DBA_PROFILES WHERE PROFILE='DEFAULT' AND RESOURCE_NAME='SESSIONS_PER_USER';" | tr -d ' \n')
    [ "$sess" != "UNLIMITED" ] && [ -n "$sess" ] && ok "029" "SESSIONS_PER_USER=${sess}" || mc "029" "DBA_PROFILES 자원 제한 수동 확인"

    # DBM-030: Audit Table 접근 제어
    mc "030" "AUD\$ / FGA_LOG\$ 테이블 접근 제어 수동 확인"

    na "031" "MSSQL 전용 항목"
    na "032" "PostgreSQL 전용 항목"
    na "033" "MySQL/MariaDB 전용 항목"

    # DBM-034: DBMS 서비스 구동 권한
    oracle_proc=$(ps -ef 2>/dev/null | grep ora_pmon | grep -v grep | awk '{print $1}' | head -1)
    [ -n "$oracle_proc" ] && {
        [ "$oracle_proc" = "root" ] && ng "034" "Oracle 프로세스 root 계정으로 실행" || ok "034" "Oracle 구동 계정: ${oracle_proc}"
    } || mc "034" "Oracle 구동 계정 수동 확인"

    na "035" "MSSQL 전용 항목"
    na "036" "MSSQL 전용 항목"
}

# ================================================================
# MySQL/MariaDB 점검
# ================================================================
check_mysql() {
    MYSQL_USER="${MYSQL_USER:-root}"
    MYSQL_PASS="${MYSQL_PASS:-CHANGE_ME}"
    MYSQL_HOST="${MYSQL_HOST:-localhost}"
    MYSQL_PORT="${MYSQL_PORT:-3306}"
    MYSQL_SOCKET="${MYSQL_SOCKET:-}"

    MYSQL_CMD=$(command -v mysql 2>/dev/null || command -v mariadb 2>/dev/null)
    if [ -z "$MYSQL_CMD" ]; then
        for i in 001 003 004 005 006 007 008 009 011 013 016 017 019 020 022 \
                 024 025 026 028 033 034; do echo "DBM-${i}|수동확인|mysql 클라이언트 미탐지"; done
        return
    fi

    if [ -n "$MYSQL_SOCKET" ]; then
        OPTS="-u${MYSQL_USER} -p${MYSQL_PASS} -S ${MYSQL_SOCKET} -N --batch"
    else
        OPTS="-u${MYSQL_USER} -p${MYSQL_PASS} -h ${MYSQL_HOST} -P ${MYSQL_PORT} -N --batch"
    fi

    run_q() { $MYSQL_CMD $OPTS -e "$1" 2>/dev/null | grep -v "^$"; }
    get_var() { $MYSQL_CMD $OPTS -e "SHOW VARIABLES LIKE '$1';" 2>/dev/null | awk '{print $2}'; }

    DB_VER=$($MYSQL_CMD $OPTS -e "SELECT VERSION();" 2>/dev/null | head -1)
    IS_MARIADB=0; echo "$DB_VER" | grep -qi "mariadb" && IS_MARIADB=1
    echo "# MySQL/MariaDB 버전: ${DB_VER}"

    # DBM-001: 취약 패스워드
    anon=$(run_q "SELECT COUNT(*) FROM mysql.user WHERE User='';" | tail -1)
    [ "${anon:-0}" -gt 0 ] 2>/dev/null && ng "001" "익명 계정 ${anon}개 존재" || ok "001" "익명 계정 없음"

    # DBM-003: 불필요 계정
    mc "003" "불필요/미사용 계정 수동 확인 (SELECT User,Host FROM mysql.user)"

    # DBM-004: 불필요 관리자 계정
    super=$(run_q "SELECT User,Host FROM mysql.user WHERE Super_priv='Y' AND User NOT IN ('root','mysql');" | head -5)
    [ -n "$super" ] && mc "004" "SUPER 권한 계정: $(echo $super | tr '\n' ',')" || ok "004" "SUPER 권한 추가 계정 없음"

    # DBM-005: 중요정보 암호화
    mc "005" "중요 컬럼(주민번호, 비밀번호 등) 암호화 여부 수동 확인"

    # DBM-006: 로그인 실패 횟수
    mce=$(get_var "max_connect_errors")
    [ "${mce:-100000}" -le 100 ] 2>/dev/null && ok "006" "max_connect_errors=${mce} (100 이하)" || \
        ng "006" "max_connect_errors=${mce} (100 이하 권고)"

    # DBM-007: 패스워드 복잡도
    if [ $IS_MARIADB -eq 1 ]; then
        sp=$(get_var "simple_password_check_digits")
        [ -n "$sp" ] && ok "007" "MariaDB simple_password_check 활성" || ng "007" "MariaDB 패스워드 복잡도 미설정"
    else
        # MySQL 8.0: validate_password.policy / 5.7: validate_password_policy
        policy=$(get_var "validate_password.policy")
        [ -z "$policy" ] && policy=$(get_var "validate_password_policy")
        if [ -z "$policy" ]; then
            ng "007" "validate_password 플러그인 미설치"
        else
            case "${policy^^}" in
            STRONG|2) ok "007" "validate_password.policy=STRONG" ;;
            MEDIUM|1) ok "007" "validate_password.policy=MEDIUM" ;;
            LOW|0)    ng "007" "validate_password.policy=LOW (MEDIUM 이상 권고)" ;;
            *)        mc "007" "validate_password.policy=${policy}" ;;
            esac
        fi
    fi

    # DBM-008: 패스워드 변경 주기
    expire=$(get_var "default_password_lifetime")
    if [ -z "$expire" ] || [ "$expire" = "0" ]; then
        ng "008" "default_password_lifetime=0 (패스워드 만료 없음)"
    elif [ "$expire" -le 90 ] 2>/dev/null; then
        ok "008" "default_password_lifetime=${expire}일 (90일 이하)"
    else
        ng "008" "default_password_lifetime=${expire}일 (90일 초과)"
    fi

    # DBM-009: 미사용 세션 종료
    timeout=$(get_var "wait_timeout")
    [ "${timeout:-28800}" -le 3600 ] 2>/dev/null && ok "009" "wait_timeout=${timeout}초" || \
        ng "009" "wait_timeout=${timeout}초 (3600초 이하 권고)"

    # DBM-011: 감사 로그
    glog=$(get_var "general_log")
    alog=$(get_var "audit_log_policy")
    if [ "$glog" = "ON" ] || echo "${alog^^}" | grep -qE "ALL|LOGINS|QUERIES"; then
        ok "011" "감사 로그: general_log=${glog}, audit_log_policy=${alog}"
    else
        ng "011" "감사 로그 미설정 (general_log=${glog:-OFF})"
    fi

    # DBM-013: 원격 접속 접근 제어
    bind=$(get_var "bind_address")
    case "$bind" in
    "0.0.0.0"|"*"|"::")  ng "013" "bind_address=${bind} (전체 IP 허용)" ;;
    "127.0.0.1"|"localhost"|"::1") ok "013" "bind_address=${bind} (로컬만 허용)" ;;
    "") ng "013" "bind_address 미설정 (기본 0.0.0.0)" ;;
    *) ok "013" "bind_address=${bind}" ;;
    esac

    # DBM-016: 보안패치
    mc "016" "MySQL/MariaDB 보안패치 적용 현황 수동 확인"

    # DBM-017: 시스템 테이블 접근 권한
    mc "017" "information_schema, mysql 데이터베이스 접근 권한 수동 확인"

    # DBM-019: 패스워드 재사용
    mc "019" "password_history 설정 수동 확인 (MySQL 8.0+: password_reuse_interval)"

    # DBM-020: 사용자별 계정 분리
    mc "020" "공용 계정 사용 여부 수동 확인"

    # DBM-021: 불필요한 ODBC/OLE-DB 데이터 소스 및 드라이버 제거 (Windows MSSQL 전용)
    na "021" "Windows MSSQL 전용 항목 (MySQL/MariaDB 해당 없음)"

    # DBM-022: 설정 파일 권한
    _found_mycnf=0
    for conf in /etc/my.cnf /etc/mysql/my.cnf /etc/mysql/mysql.conf.d/mysqld.cnf; do
        [ -f "$conf" ] || continue
        perm=$(stat -c "%a" "$conf" 2>/dev/null)
        owner=$(stat -c "%U" "$conf" 2>/dev/null)
        [ "${perm:-777}" -le 640 ] 2>/dev/null && ok "022" "${conf} 권한=${perm}" || ng "022" "${conf} 권한=${perm} (640 이하 권고)"
        _found_mycnf=1
        break
    done
    [ $_found_mycnf -eq 0 ] && mc "022" "MySQL 설정 파일 미발견 - 수동 확인 (my.cnf 위치)"

    # DBM-024: WITH GRANT OPTION
    mc "024" "GRANT OPTION 부여 현황 수동 확인 (SELECT * FROM mysql.user WHERE Grant_priv='Y')"

    # DBM-025: EoS
    mc "025" "MySQL ${DB_VER} EoS 여부 수동 확인 (dev.mysql.com/support/eol 참조)"

    # DBM-026: 구동 계정 umask
    mysql_user=$(ps -ef 2>/dev/null | grep -E "mysqld|mariadbd" | grep -v grep | awk '{print $1}' | head -1)
    [ -n "$mysql_user" ] && {
        mysql_umask=$(su -c "umask" "$mysql_user" 2>/dev/null)
        [ -n "$mysql_umask" ] && {
            um=$(echo "$mysql_umask" | tr -d '0' | head -1)
            [ "${um:-0}" -ge 22 ] 2>/dev/null && ok "026" "MySQL 구동 계정(${mysql_user}) umask=${mysql_umask} (022 이상)" || \
                ng "026" "MySQL 구동 계정(${mysql_user}) umask=${mysql_umask} (022 이상 권고)"
        } || mc "026" "MySQL 구동 계정(${mysql_user}) umask 수동 확인"
    } || mc "026" "MySQL 구동 계정 umask 수동 확인"

    # DBM-028: 불필요 DB Object
    test_db=$(run_q "SELECT COUNT(*) FROM information_schema.SCHEMATA WHERE SCHEMA_NAME='test';" | tail -1)
    [ "${test_db:-0}" -gt 0 ] 2>/dev/null && ng "028" "test 데이터베이스 존재 (제거 권고)" || ok "028" "test 데이터베이스 없음"

    na "029" "Oracle 전용 항목 (자원 프로파일)"
    na "030" "Oracle/Tibero 전용 항목 (감사 테이블)"
    na "031" "MSSQL 전용 항목"
    na "032" "PostgreSQL 전용 항목"

    # DBM-033: 이중화 비밀번호 평문 노출
    mc "033" "MySQL 복제(Replication) 구성 시 비밀번호 평문 노출 여부 수동 확인"

    # DBM-034: DBMS 서비스 구동 권한
    mysql_proc=$(ps -ef 2>/dev/null | grep -E "mysqld$|mariadbd$" | grep -v grep | awk '{print $1}' | head -1)
    [ -n "$mysql_proc" ] && {
        [ "$mysql_proc" = "root" ] && ng "034" "MySQL 프로세스 root 계정으로 실행" || ok "034" "MySQL 구동 계정: ${mysql_proc}"
    } || mc "034" "MySQL 구동 계정 수동 확인"

    na "035" "MSSQL 전용 항목"
    na "036" "MSSQL 전용 항목"
}

# ================================================================
# PostgreSQL 점검
# ================================================================
check_pgsql() {
    PGSQL_USER="${PGSQL_USER:-postgres}"
    PGSQL_DB="${PGSQL_DB:-postgres}"
    PGSQL_HOST="${PGSQL_HOST:-localhost}"
    PGSQL_PORT="${PGSQL_PORT:-5432}"

    PSQL=$(command -v psql 2>/dev/null)
    if [ -z "$PSQL" ]; then
        for i in 001 003 004 005 006 007 008 009 011 013 016 017 019 020 022 \
                 024 025 026 028 032 034; do echo "DBM-${i}|수동확인|psql 미탐지"; done
        return
    fi

    OPTS="-U ${PGSQL_USER} -h ${PGSQL_HOST} -p ${PGSQL_PORT} -d ${PGSQL_DB} -tA"
    run_q() { "$PSQL" $OPTS -c "$1" 2>/dev/null | grep -v "^$"; }
    get_conf() { "$PSQL" $OPTS -c "SHOW $1;" 2>/dev/null | grep -v "^$"; }

    DB_VER=$(run_q "SELECT version();" | head -1)
    echo "# PostgreSQL 버전: ${DB_VER}"

    # DBM-001: 취약 패스워드
    no_pw=$(run_q "SELECT COUNT(*) FROM pg_shadow WHERE passwd IS NULL OR passwd='' OR passwd='md5'||md5('');" | tail -1)
    [ "${no_pw:-0}" -gt 0 ] 2>/dev/null && ng "001" "패스워드 없거나 빈 값 계정 ${no_pw}개" || ok "001" "패스워드 미설정 계정 없음"

    # DBM-003: 불필요 계정
    mc "003" "불필요 계정 수동 확인 (SELECT rolname FROM pg_roles)"

    # DBM-004: 불필요 관리자
    supers=$(run_q "SELECT rolname FROM pg_roles WHERE rolsuper='t' AND rolname NOT IN ('postgres');" | head -5)
    [ -n "$supers" ] && mc "004" "superuser 계정: $(echo $supers | tr '\n' ',') - 적정성 수동 확인" || ok "004" "postgres 외 superuser 없음"

    # DBM-005: 암호화
    mc "005" "중요 컬럼 암호화 여부 수동 확인 (pgcrypto 등)"

    # DBM-006: 로그인 실패 제한 (PostgreSQL은 기본 제한 없음 - pg_auth_mon 또는 fail2ban)
    mc "006" "로그인 실패 횟수 제한은 PostgreSQL 기본 미지원 - fail2ban 또는 pg_auth_mon 설정 수동 확인"

    # DBM-007: 패스워드 복잡도
    check_pw=$(run_q "SELECT name FROM pg_available_extensions WHERE name IN ('passwordcheck','cracklib_postgresql');" | head -1)
    [ -n "$check_pw" ] && ok "007" "패스워드 복잡도 확장 설치됨: ${check_pw}" || ng "007" "passwordcheck 확장 미설치 (복잡도 미설정)"

    # DBM-008: 패스워드 만료
    mc "008" "PostgreSQL 패스워드 만료는 VALID UNTIL로 계정별 설정 - 수동 확인 (SELECT rolname,rolvaliduntil FROM pg_roles)"

    # DBM-009: 세션 타임아웃
    timeout=$(get_conf "idle_in_transaction_session_timeout")
    [ "${timeout:-0}" != "0" ] 2>/dev/null && ok "009" "idle_in_transaction_session_timeout=${timeout}" || \
        ng "009" "idle_in_transaction_session_timeout=0 (미설정)"

    # DBM-011: 감사 로그
    log_dst=$(get_conf "log_destination")
    log_conn=$(get_conf "log_connections")
    log_disco=$(get_conf "log_disconnections")
    [ "$log_conn" = "on" ] && [ "$log_disco" = "on" ] && ok "011" "log_connections=on, log_disconnections=on" || \
        ng "011" "감사 로그 미설정 (log_connections=${log_conn}, log_disconnections=${log_disco})"

    # DBM-013: 원격 접속
    listen=$(get_conf "listen_addresses")
    case "${listen}" in
    "*"|"0.0.0.0") ng "013" "listen_addresses=* (전체 허용)" ;;
    "localhost"|"127.0.0.1") ok "013" "listen_addresses=${listen} (로컬만)" ;;
    *) ok "013" "listen_addresses=${listen}" ;;
    esac

    # DBM-015: PUBLIC 불필요 권한
    mc "015" "PUBLIC 스키마 접근 권한 수동 확인 (\\du+ 또는 REVOKE ALL ON schema public FROM public)"

    # DBM-016: 보안패치
    mc "016" "PostgreSQL 보안패치 수동 확인"

    # DBM-017: 시스템 테이블 접근
    mc "017" "pg_shadow, pg_authid 등 시스템 카탈로그 접근 권한 수동 확인"

    # DBM-019: 패스워드 재사용
    mc "019" "PostgreSQL 패스워드 재사용 제한 수동 설정 확인"

    # DBM-020: 계정 분리
    mc "020" "공용 계정 사용 여부 수동 확인"

    # DBM-021: 불필요한 ODBC/OLE-DB 데이터 소스 및 드라이버 제거 (Windows MSSQL 전용)
    na "021" "Windows MSSQL 전용 항목 (PostgreSQL 해당 없음)"

    # DBM-022: 설정 파일 권한
    pg_conf=$(find /etc/postgresql /var/lib/postgresql -name "postgresql.conf" 2>/dev/null | head -1)
    [ -n "$pg_conf" ] && {
        perm=$(stat -c "%a" "$pg_conf" 2>/dev/null)
        [ "${perm:-777}" -le 640 ] 2>/dev/null && ok "022" "postgresql.conf 권한=${perm}" || ng "022" "postgresql.conf 권한=${perm} (640 이하 권고)"
    } || mc "022" "postgresql.conf 위치 확인"

    # DBM-024: WITH GRANT OPTION
    mc "024" "WITH GRANT OPTION 부여 현황 수동 확인 (SELECT grantee,table_name,with_grant_option FROM information_schema.role_table_grants WHERE with_grant_option='YES')"

    # DBM-025: EoS
    mc "025" "PostgreSQL EoS 여부 수동 확인 (https://www.postgresql.org/support/versioning/)"

    # DBM-026: 구동 계정 umask
    pg_user=$(ps -ef 2>/dev/null | grep "postgres: postmaster\|postgres -D" | grep -v grep | awk '{print $1}' | head -1)
    [ -n "$pg_user" ] && {
        pg_umask=$(su -c "umask" "$pg_user" 2>/dev/null)
        [ -n "$pg_umask" ] && {
            um=$(echo "$pg_umask" | tr -d '0' | head -1)
            [ "${um:-0}" -ge 22 ] 2>/dev/null && ok "026" "PostgreSQL 구동 계정(${pg_user}) umask=${pg_umask} (022 이상)" || \
                ng "026" "PostgreSQL 구동 계정(${pg_user}) umask=${pg_umask} (022 이상 권고)"
        } || mc "026" "PostgreSQL 구동 계정(${pg_user}) umask 수동 확인"
    } || mc "026" "PostgreSQL 구동 계정 umask 수동 확인"

    # DBM-028: 불필요 Object
    mc "028" "불필요 스키마/테이블 수동 확인"

    na "029" "Oracle 전용 항목 (자원 프로파일)"
    na "030" "Oracle/Tibero 전용 항목 (감사 테이블)"
    na "031" "MSSQL 전용 항목"

    # DBM-032: 비밀번호 평문 노출 방지
    ssl=$(get_conf "ssl")
    [ "$ssl" = "on" ] && ok "032" "SSL 활성화됨 (통신구간 암호화)" || ng "032" "SSL 미설정 (비밀번호 평문 노출 가능)"

    na "033" "MySQL/MariaDB 전용 항목 (복제 비밀번호)"

    # DBM-034: DBMS 구동 권한
    pg_proc=$(ps -ef 2>/dev/null | grep "postgres: postmaster\|postmaster" | grep -v grep | awk '{print $1}' | head -1)
    [ -n "$pg_proc" ] && {
        [ "$pg_proc" = "root" ] && ng "034" "PostgreSQL root 실행" || ok "034" "구동 계정: ${pg_proc}"
    } || mc "034" "PostgreSQL 구동 계정 수동 확인"

    na "035" "MSSQL 전용 항목"
    na "036" "MSSQL 전용 항목"
}

# ================================================================
# Tibero 점검
# ================================================================
check_tibero() {
    TB_HOME="${TB_HOME:-/opt/tibero}"
    TB_USER="${TIBERO_USER:-tibero}"
    TB_PASS="${TIBERO_PASS:-CHANGE_ME}"
    TB_DB="${TIBERO_DB:-tibero}"

    TBSQL=$(command -v tbsql 2>/dev/null || find "$TB_HOME" -name "tbsql" 2>/dev/null | head -1)
    if [ -z "$TBSQL" ]; then
        for i in 001 003 004 005 006 007 008 011 013 016 017 019 020 022 024 025 034; do
            echo "DBM-${i}|수동확인|tbsql 미탐지 - 수동 확인"
        done
        return
    fi

    run_q() {
        "$TBSQL" "${TB_USER}/${TB_PASS}@${TB_DB}" << EOF 2>/dev/null
SET PAGESIZE 0 FEEDBACK OFF HEADING OFF
$1
EXIT
EOF
    }

    DB_VER=$(run_q "SELECT TB_VERSION FROM DB_VERSION;" | head -1)
    echo "# Tibero 버전: ${DB_VER}"

    # DBM-001~034 Tibero 전용 점검 (Oracle 유사)
    failed=$(run_q "SELECT LIMIT FROM DBA_PROFILES WHERE PROFILE='DEFAULT' AND RESOURCE_NAME='FAILED_LOGIN_ATTEMPTS';" | tr -d ' \n')
    [ "$failed" = "UNLIMITED" ] || [ -z "$failed" ] && ng "006" "FAILED_LOGIN_ATTEMPTS=UNLIMITED" || \
        { [ "$failed" -le 5 ] 2>/dev/null && ok "006" "FAILED_LOGIN_ATTEMPTS=${failed}" || ng "006" "FAILED_LOGIN_ATTEMPTS=${failed} (5회 이하 권고)"; }

    mc "001" "Tibero 기본 계정 비밀번호 변경 여부 수동 확인"
    mc "003" "불필요 계정 수동 확인"
    mc "004" "관리자 계정 최소화 수동 확인"
    mc "005" "중요정보 암호화 수동 확인"
    mc "007" "패스워드 복잡도(PASSWORD_VERIFY_FUNCTION) 수동 확인"
    mc "008" "패스워드 만료 기간 수동 확인 (PASSWORD_LIFE_TIME)"
    mc "009" "세션 타임아웃 수동 확인"
    mc "011" "감사 로그 설정 수동 확인 (AUDIT_TRAIL)"
    mc "013" "원격 접속 제어 수동 확인 (tbdsn.tbr)"
    mc "015" "PUBLIC 권한 수동 확인"
    mc "016" "Tibero 보안패치 수동 확인"
    mc "017" "시스템 테이블 접근 권한 수동 확인"
    mc "019" "패스워드 재사용 제한 수동 확인"
    mc "020" "사용자별 계정 분리 수동 확인"
    na "021" "Windows MSSQL 전용 항목 (Tibero 해당 없음)"
    mc "022" "설정 파일 접근 권한 수동 확인"
    mc "024" "WITH GRANT OPTION 수동 확인"
    mc "025" "Tibero EoS 여부 수동 확인 (TmaxSoft 지원 정책 참조)"
    mc "026" "Tibero 구동 계정 umask 수동 확인"
    mc "028" "불필요 DB Object 수동 확인"
    mc "029" "자원 사용 제한 (SESSIONS_PER_USER 등) 수동 확인"
    mc "030" "Audit Table 접근 제어 수동 확인"
    na "031" "MSSQL 전용 항목"
    na "032" "PostgreSQL 전용 항목"
    na "033" "MySQL/MariaDB 전용 항목"
    mc "034" "Tibero 구동 권한 수동 확인"
    na "035" "MSSQL 전용 항목"
    na "036" "MSSQL 전용 항목"
}

# ── 실행 분기 ────────────────────────────────────────────────────
case "$DBMS_TYPE" in
oracle)  check_oracle ;;
mysql|mariadb) check_mysql ;;
pgsql|postgresql) check_pgsql ;;
tibero)  check_tibero ;;
*)
    echo "# DBMS를 자동 탐지할 수 없습니다."
    echo "# DBMS_TYPE=oracle|mysql|pgsql|tibero 환경변수를 설정하고 재실행하세요."
    for i in 001 003 004 005 006 007 008 009 011 012 013 014 015 016 \
             017 019 020 021 022 024 025 026 028 029 030 031 032 033 034 035 036; do
        printf "DBM-%03d|수동확인|DBMS 탐지 실패 - 수동 확인\n" "${i#0}"
    done ;;
esac

echo "# 점검 완료: $(date '+%Y-%m-%d %H:%M:%S')"
