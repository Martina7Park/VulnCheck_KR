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

#@@EMBED@@

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
