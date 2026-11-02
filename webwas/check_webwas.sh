#!/bin/bash
[ -z "$BASH_VERSION" ] && exec bash "$0" "$@"   # sh/dash 로 실행 시 bash 로 재실행 (declare -A 등 bash 전용 문법)
_UMASK_ORIG=$(umask 2>/dev/null)   # SRV-122 가 점검하는 실행 계정의 원래 umask
umask 077                                              # 결과·증적 파일은 소유자만 읽도록
[ "$(uname -s 2>/dev/null)" = SunOS ] && PATH="/usr/xpg4/bin:/usr/sfw/bin:$PATH"   # Solaris: POSIX grep -E/awk 사용
_BV="${BASH_VERSINFO[0]:-0}"; [ "$_BV" -ge 3 ] 2>/dev/null || { echo "[오류] bash 3 이상이 필요합니다 (현재 ${BASH_VERSION})" >&2; exit 1; }   # 연관 배열(bash 4)은 쓰지 않는다
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
#   웹서버: Apache / Nginx / WebtoB (동시 설치 시 모두 점검)
#   WAS:    Tomcat(모든 인스턴스) / JEUS / Spring Boot 설정
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
#      결과: 양호 / 취약 / 점검불가 / 수동확인 / N-A  (점검불가 = 명령·권한·설정 파일 부재로 점검 자체를 못 한 경우, 근거에 사유)
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
    SunOS)   OS_FAMILY="SOLARIS"; OS_DISTRO="SOLARIS"; OS_MAJOR=$(uname -r|cut -d. -f2); return ;;
    "HP-UX") OS_FAMILY="HPUX";    OS_DISTRO="HPUX";    OS_MAJOR=$(uname -r|cut -d. -f2); return ;;
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
_safe_file() {   # /tmp 의 예측 가능한 파일명 보호: 심볼릭 링크·타 사용자 소유 파일은 지우고 새로 만들고, 권한을 600 으로 제한
    [ -L "$1" ] && rm -f "$1" 2>/dev/null
    [ -e "$1" ] && [ ! -O "$1" ] && rm -f "$1" 2>/dev/null
    ( : >> "$1" ) 2>/dev/null && chmod 600 "$1" 2>/dev/null
}
_RESF="/tmp/${HN}_webwas.txt"
if [ -z "$NO_RESULT_COPY" ] && ! [ /dev/fd/1 -ef "$_RESF" ] 2>/dev/null && _safe_file "$_RESF"; then
    exec > >(tee "$_RESF"); _TEEPID=$!
else
    _RESF=""
fi

# ── 웹서버/WAS 탐지: 여러 제품·여러 인스턴스를 모두 수집 (Apache+Nginx 동시, Tomcat 다중 인스턴스, Tomcat+JEUS 동시) ──
# 환경변수로 직접 지정 가능: APACHE_CONF NGINX_CONF CATALINA_BASE CATALINA_HOME CATALINA_BASES(공백 구분 다중) JEUS_HOME WEBTOBDIR
WEB_SRV=""; WAS_SRV=""            # 첫 번째 탐지 제품(호환용). 전체는 WEB_LIST / WAS_LIST
WEB_LIST=""; WAS_LIST=""
APACHE_CONF="${APACHE_CONF:-}"; NGINX_CONF="${NGINX_CONF:-}"; TOMCAT_HOME=""; TOMCAT_HOMES=""; JEUS_HOME="${JEUS_HOME:-}"; JEUS_HOMES=""
_WT_M=""; _WT_HOME=""; _AP_BIN=""; _NG_BIN=""
DETECT_NOTE=""; DETECT_AP=""; DETECT_NG=""; DETECT_WT=""
_list_add() { local _cur; eval "_cur=\$$1"; case " $_cur " in *" $2 "*) return 0 ;; esac; eval "$1=\"\${_cur:+\$_cur }\$2\""; }
_canon_dir() { ( cd "$1" 2>/dev/null && pwd -P ) || echo "$1"; }
_note() { DETECT_NOTE="${DETECT_NOTE:+$DETECT_NOTE; }$1"; }
# 실행 중 프로세스 인자 전체 (ps 가 없으면 /proc)
_PSALL=$( { UNIX95=1 ps -eo args= 2>/dev/null || ps -ef 2>/dev/null; } )
[ -n "$_PSALL" ] || _PSALL=$(for _f in /proc/[0-9]*/cmdline; do tr '\0' ' ' 2>/dev/null < "$_f"; echo; done)

# Apache: 환경변수 → 실행 프로세스 -f → 바이너리 -V → 알려진 경로
_apf=""
if [ -z "$APACHE_CONF" ]; then
    _apf=$(printf '%s\n' "$_PSALL" | grep -E '^([^[:space:]]*/)?(httpd|apache2|httpd\.worker|httpd\.event|httpd\.prefork|httpd2)([[:space:]]|$)' | grep -oE -- '-f[[:space:]]+[^[:space:]]+' | awk '{print $2}' | sed -n 1p)
    [ -n "$_apf" ] && [ -f "$_apf" ] && { APACHE_CONF="$_apf"; _note "Apache: 프로세스 -f $_apf"; }
fi
for _b in httpd apache2ctl apache2 apachectl /usr/sbin/httpd /usr/sbin/apache2 /usr/local/apache2/bin/httpd /usr/local/apache/bin/httpd /opt/IBM/HTTPServer/bin/httpd /usr/IBM/HTTPServer/bin/httpd /opt/apache/bin/httpd; do
    command -v "$_b" >/dev/null 2>&1 || continue
    [ -n "$_AP_BIN" ] || _AP_BIN="$_b"
    [ -z "$APACHE_CONF" ] || break
    _apv=$("$_b" -V 2>/dev/null); [ -n "$_apv" ] || continue
    _apr=$(echo "$_apv" | sed -n 's/.*HTTPD_ROOT="\(.*\)".*/\1/p' | sed -n 1p); _apc=$(echo "$_apv" | sed -n 's/.*SERVER_CONFIG_FILE="\(.*\)".*/\1/p' | sed -n 1p)
    case "$_apc" in /*) ;; ?*) _apc="$_apr/$_apc" ;; esac
    [ -n "$_apc" ] && [ -f "$_apc" ] && { APACHE_CONF="$_apc"; _note "Apache: $_b -V"; }
done
if [ -z "$APACHE_CONF" ]; then
    for _d in /etc/httpd/conf /etc/apache2 /usr/local/apache/conf /usr/local/apache2/conf /usr/local/httpd/conf /opt/httpd/conf /opt/apache/conf /opt/apache2/conf \
              /opt/IBM/HTTPServer/conf /usr/IBM/HTTPServer/conf /usr/local/etc/apache2*/ /usr/local/etc/httpd /opt/*/apache*/conf /opt/apache*/conf /usr/local/apache*/conf \
              /home/*/apache*/conf /app/apache*/conf /sw/apache*/conf /data/apache*/conf /Applications/XAMPP/xamppfiles/etc /etc/apache2; do
        for _n in httpd.conf apache2.conf; do [ -f "$_d/$_n" ] && { APACHE_CONF="$_d/$_n"; _note "Apache: 알려진 경로 $_d/$_n"; break 2; }; done
    done
fi
if [ -n "$APACHE_CONF" ]; then _list_add WEB_LIST apache; case "$DETECT_NOTE" in *Apache:*) ;; *) _note "Apache: ${APACHE_CONF} (환경변수/지정)" ;; esac
elif [ -n "$_AP_BIN" ]; then _list_add WEB_LIST apache; DETECT_AP="바이너리 $_AP_BIN"
elif printf '%s\n' "$_PSALL" | grep -qE '^([^[:space:]]*/)?(httpd|apache2)([[:space:]]|$)'; then _list_add WEB_LIST apache; DETECT_AP="실행 프로세스"; fi

# Nginx: 환경변수 → 프로세스 -c → nginx -V --conf-path → 알려진 경로
if [ -z "$NGINX_CONF" ]; then
    _ngc=$(printf '%s\n' "$_PSALL" | grep -E '^nginx: master process' | grep -oE -- '-c[[:space:]]+[^[:space:]]+' | awk '{print $2}' | sed -n 1p)
    [ -n "$_ngc" ] && [ -f "$_ngc" ] && { NGINX_CONF="$_ngc"; _note "Nginx: 프로세스 -c $_ngc"; }
fi
for _b in nginx /usr/sbin/nginx /usr/local/nginx/sbin/nginx /usr/local/sbin/nginx /opt/nginx/sbin/nginx /opt/homebrew/bin/nginx; do
    command -v "$_b" >/dev/null 2>&1 || continue
    [ -n "$_NG_BIN" ] || _NG_BIN="$_b"
    [ -z "$NGINX_CONF" ] || break
    _ngc=$("$_b" -V 2>&1 | grep -oE -- '--conf-path=[^[:space:]]+' | cut -d= -f2)
    [ -n "$_ngc" ] && [ -f "$_ngc" ] && { NGINX_CONF="$_ngc"; _note "Nginx: $_b -V --conf-path"; }
done
if [ -z "$NGINX_CONF" ]; then
    for _f in /etc/nginx/nginx.conf /usr/local/nginx/conf/nginx.conf /usr/local/etc/nginx/nginx.conf /opt/nginx/conf/nginx.conf /opt/homebrew/etc/nginx/nginx.conf \
              /opt/*/nginx*/conf/nginx.conf /usr/local/nginx*/conf/nginx.conf /home/*/nginx*/conf/nginx.conf /app/nginx*/conf/nginx.conf /sw/nginx*/conf/nginx.conf /data/nginx*/conf/nginx.conf; do
        [ -f "$_f" ] && { NGINX_CONF="$_f"; _note "Nginx: 알려진 경로 $_f"; break; }
    done
fi
if [ -n "$NGINX_CONF" ]; then _list_add WEB_LIST nginx; case "$DETECT_NOTE" in *Nginx:*) ;; *) _note "Nginx: ${NGINX_CONF} (환경변수/지정)" ;; esac
elif [ -n "$_NG_BIN" ]; then _list_add WEB_LIST nginx; DETECT_NG="바이너리 $_NG_BIN"
elif printf '%s\n' "$_PSALL" | grep -qE '^nginx: (master|worker) process'; then _list_add WEB_LIST nginx; DETECT_NG="실행 프로세스"; fi

# WebtoB: WEBTOBDIR → 알려진 경로 → wsadmin/프로세스
for _d in "$WEBTOBDIR" /home/tmax/webtob /root/webtob /opt/tmax/webtob /sw/webtob /sw/webtob5 /home/webtob/webtob /home/*/webtob* /opt/*/webtob* /sw/*/webtob* /app/webtob* /usr/local/webtob*; do
    [ -n "$_d" ] && [ -f "$_d/config/http.m" ] && { _WT_M="$_d/config/http.m"; _WT_HOME="$_d"; _note "WebtoB: $_d/config/http.m"; break; }
done
if [ -n "$_WT_M" ]; then _list_add WEB_LIST webtob
elif command -v wsadmin >/dev/null 2>&1; then _list_add WEB_LIST webtob; DETECT_WT="wsadmin $(command -v wsadmin)"
elif printf '%s\n' "$_PSALL" | grep -qE '^([^[:space:]]*/)?(wsm|htl|hth)([[:space:]]|$)'; then _list_add WEB_LIST webtob; DETECT_WT="실행 프로세스(wsm/htl)"; fi

# Tomcat: 실행 중 프로세스의 catalina.base/home → 환경변수 → conf/server.xml 이 있는 디렉터리를 3단계 깊이까지 모두 수집
_tc_add() {   # _tc_add 디렉터리 [force] : force(실행 중 프로세스의 catalina.base, 비root 의 알려진 패키지 경로)는 conf 를 읽거나 열람할 수 없어도 등록 → 항목에서 '점검불가(권한 없음)' 로 표시
    local d="${1%/}"; [ -n "$d" ] || return 0
    if [ -f "$d/conf/server.xml" ]; then
        if [ -r "$d/conf/server.xml" ]; then grep -q '<Server' "$d/conf/server.xml" 2>/dev/null || return 0; fi
    elif [ -n "$2" ] && [ -d "$d" ] && { [ -d "$d/conf" ] || [ -L "$d/conf" ] || [ "$2" = proc ]; }; then :
    else return 0; fi
    _list_add TOMCAT_HOMES "$(_canon_dir "$d")"
}
for _d in $(printf '%s\n' "$_PSALL" | grep -oE -- '-Dcatalina\.base=[^[:space:]]+' | cut -d= -f2); do _tc_add "$_d" proc; done
for _d in $(printf '%s\n' "$_PSALL" | grep -oE -- '-Dcatalina\.home=[^[:space:]]+' | cut -d= -f2) \
          "$CATALINA_BASE" "$CATALINA_HOME" $CATALINA_BASES; do _tc_add "$_d"; done
_tcf=""; [ "$(id -u 2>/dev/null)" != "0" ] && _tcf=known
for _d in /var/lib/tomcat* /usr/share/tomcat* /opt/tomcat* /opt/apache-tomcat* /usr/local/tomcat* /usr/local/apache-tomcat* /srv/tomcat*; do _tc_add "$_d" "$_tcf"; done
for _r in /opt /usr/local /srv /app /apps /data /sw /engn /was /svc /webapps /home; do
    [ -d "$_r" ] || continue
    for _d in "$_r"/* "$_r"/*/* "$_r"/*/*/*; do [ -f "$_d/conf/server.xml" ] && _tc_add "$_d"; done
done
if [ -n "$TOMCAT_HOMES" ]; then
    _list_add WAS_LIST tomcat; TOMCAT_HOME="${TOMCAT_HOMES%% *}"
    _note "Tomcat 인스턴스 $(echo $TOMCAT_HOMES | wc -w)개: $TOMCAT_HOMES"
elif printf '%s\n' "$_PSALL" | grep -qE 'org\.apache\.catalina\.startup\.Bootstrap|-Dcatalina\.(base|home)='; then
    _list_add WAS_LIST tomcat; _note "Tomcat: 프로세스는 실행 중이나 conf/server.xml 을 찾지 못함"
fi

# JEUS: JEUS_HOME 환경변수 → 프로세스 -Djeus.home → 알려진 경로 (bin/jeusadmin 또는 domains 디렉터리가 있는 홈)
_je_add() { local d="${1%/}"; [ -d "$d" ] || return 0; [ -f "$d/bin/jeusadmin" ] || [ -d "$d/domains" ] || [ -f "$d/bin/jeus" ] || return 0; _list_add JEUS_HOMES "$(_canon_dir "$d")"; }
for _d in "$JEUS_HOME" $(printf '%s\n' "$_PSALL" | grep -oE -- '-Djeus\.home=[^[:space:]]+' | cut -d= -f2); do _je_add "$_d"; done
for _r in /opt /usr/local /home /app /apps /sw /data /engn /was; do
    [ -d "$_r" ] || continue
    for _d in "$_r"/jeus* "$_r"/*/jeus* "$_r"/*/*/jeus* "$_r"/tmax/jeus*; do _je_add "$_d"; done
done
if [ -n "$JEUS_HOMES" ]; then _list_add WAS_LIST jeus; JEUS_HOME="${JEUS_HOMES%% *}"; _note "JEUS 홈: $JEUS_HOMES"
elif printf '%s\n' "$_PSALL" | grep -q -- '-Djeus\.home='; then _list_add WAS_LIST jeus; _note "JEUS: 프로세스는 실행 중이나 홈 디렉터리를 확인하지 못함"; fi
[ -n "$APACHE_CONF$_AP_BIN" ] || :
WEB_SRV="${WEB_LIST%% *}"; WAS_SRV="${WAS_LIST%% *}"

# ── 헤더 메타데이터: IP / 실행 계정 / 클라우드 (수집 실패해도 점검은 계속) ──
_ip_list() {   # 루프백을 제외한 IPv4 전부 (Linux ip / UNIX ifconfig -a / HP-UX netstat -in)
    local l
    l=$(ip -4 -o addr show 2>/dev/null | awk '{split($4,a,"/"); print a[1]}')
    [ -z "$l" ] && l=$( { ifconfig -a 2>/dev/null || /usr/sbin/ifconfig -a 2>/dev/null; } | awk '{for(i=1;i<NF;i++) if($i=="inet"){v=$(i+1); sub(/^addr:/,"",v); print v}}')
    [ -z "$l" ] && l=$(netstat -in 2>/dev/null | awk 'NR>1 && $4 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ {print $4}')
    [ -z "$l" ] && l=$(hostname -I 2>/dev/null | tr ' ' '\n')
    [ -z "$l" ] && [ -r /proc/net/fib_trie ] && l=$(awk '$1=="|--"{ip=$2} /\/32 host LOCAL/{print ip}' /proc/net/fib_trie 2>/dev/null)   # ip·ifconfig·hostname 이 없는 최소 Linux
    l=$(echo "$l" | awk '$1 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ && $1 !~ /^127\./ && $1 != "0.0.0.0" && !s[$1]++ {printf "%s%s", (n++?", ":""), $1}')
    echo "${l:-미확인}"
}
_imds_req() {   # $1=메서드(GET|PUT) $2=URL 나머지=헤더('이름: 값', 빈 값은 무시) — 타임아웃 2초, 실패 시 비어 있음·rc≠0
    local m="$1" url="$2" h; shift 2
    if command -v curl >/dev/null 2>&1; then
        local a=(); for h in "$@"; do [ -n "$h" ] && a+=(-H "$h"); done
        curl -s -f -X "$m" --noproxy '*' --connect-timeout 2 -m 2 "${a[@]}" "$url" 2>/dev/null
    elif command -v wget >/dev/null 2>&1; then
        local a=(); for h in "$@"; do [ -n "$h" ] && a+=(--header="$h"); done
        [ "$m" = PUT ] && a+=(--method=PUT --body-data=)
        wget -q -O - --no-proxy -T 2 -t 1 "${a[@]}" "$url" 2>/dev/null
    else return 127; fi
}
_CLOUD="미확인"; _CLOUD_ID=""; _CLOUD_REGION=""; _CLOUD_SG=""   # 방화벽 항목(SRV-027·155)에서 ${_CLOUD:-} 로 참조
_cloud_detect() {
    local base="${_IMDS_BASE:-http://169.254.169.254}" tok th r mac hint sgs="" rc unreach=0   # _IMDS_BASE 는 시험용 재정의
    command -v curl >/dev/null 2>&1 || command -v wget >/dev/null 2>&1 || return 0   # 조회 수단 없음 = 미확인
    # AWS (IMDSv2 토큰 먼저, 실패하면 v1)
    tok=$(_imds_req PUT "$base/latest/api/token" "X-aws-ec2-metadata-token-ttl-seconds: 60"); rc=$?
    case "$rc" in 7|28|4) unreach=1 ;; esac   # 연결 거부·타임아웃: IMDS 주소에 접속 자체가 안 되면 Azure·GCP 시도는 생략 (최대 2초)
    th=""; [ -n "$tok" ] && th="X-aws-ec2-metadata-token: $tok"
    [ "$unreach" = 1 ] || r=$(_imds_req GET "$base/latest/meta-data/instance-id" "$th")
    case "$r" in i-[0-9a-f]*)
        _CLOUD="AWS"; _CLOUD_ID="$r"
        r=$(_imds_req GET "$base/latest/meta-data/placement/region" "$th")
        [ -z "$r" ] && r=$(_imds_req GET "$base/latest/meta-data/placement/availability-zone" "$th" | sed 's/[a-z]$//')
        _CLOUD_REGION="$r"
        for mac in $(_imds_req GET "$base/latest/meta-data/network/interfaces/macs/" "$th" | tr -d '/'); do
            sgs="${sgs}
$(_imds_req GET "$base/latest/meta-data/network/interfaces/macs/$mac/security-group-ids" "$th")"
        done
        _CLOUD_SG=$(echo "$sgs" | awk 'NF && !s[$1]++ {printf "%s%s", (n++?",":""), $1}')
        return 0 ;;
    esac
    # Azure (Metadata:true, 인스턴스 메타데이터에는 NSG 정보가 없음)
    [ "$unreach" = 1 ] || r=$(_imds_req GET "$base/metadata/instance/compute?api-version=2021-02-01&format=json" "Metadata: true")
    case "$r" in *vmId*)
        _CLOUD="Azure"
        _CLOUD_ID=$(echo "$r" | sed -n 's/.*"vmId" *: *"\([^"]*\)".*/\1/p')
        _CLOUD_REGION=$(echo "$r" | sed -n 's/.*"location" *: *"\([^"]*\)".*/\1/p')
        return 0 ;;
    esac
    # GCP (Metadata-Flavor: Google, 방화벽 규칙은 네트워크 태그로 적용)
    [ "$unreach" = 1 ] && r="" || r=$(_imds_req GET "$base/computeMetadata/v1/instance/id" "Metadata-Flavor: Google")
    case "$r" in [0-9]*)
        _CLOUD="GCP"; _CLOUD_ID="$r"
        _CLOUD_REGION=$(_imds_req GET "$base/computeMetadata/v1/instance/zone" "Metadata-Flavor: Google" | sed 's#.*/##; s/-[a-z]$//')
        _CLOUD_SG=$(_imds_req GET "$base/computeMetadata/v1/instance/tags" "Metadata-Flavor: Google" | tr -d '[]" \n')
        [ -n "$_CLOUD_SG" ] && _CLOUD_SG="네트워크 태그 ${_CLOUD_SG}"
        return 0 ;;
    esac
    # 응답 없음: DMI 가 클라우드 가상머신을 가리키면 IMDS 차단 등으로 확인 불가, 아니면 클라우드 아님
    hint=$(cat /sys/class/dmi/id/sys_vendor /sys/class/dmi/id/product_name /sys/class/dmi/id/chassis_asset_tag 2>/dev/null | tr '\n' ' ')
    case "$hint" in *[Aa]mazon*|*Google*|*"Virtual Machine"*|*OpenStack*|*Alibaba*|*"7783-7084"*) _CLOUD="미확인" ;; *) _CLOUD="없음" ;; esac
    return 0
}
_cloud_line() {
    case "$_CLOUD" in
    AWS|Azure|GCP)
        echo "${_CLOUD} (instance ${_CLOUD_ID:-미확인}, region ${_CLOUD_REGION:-미확인}, SG: ${_CLOUD_SG:-$([ "$_CLOUD" = Azure ] && echo 'NSG 는 IMDS 미제공' || echo 미확인)})" ;;
    *) echo "$_CLOUD" ;;
    esac
}
_cloud_detect
_NONROOT=0; _WHO=$(id -un 2>/dev/null || echo "?")
[ "$(id -u 2>/dev/null)" != "0" ] && { _NONROOT=1; _WHO="${_WHO} (관리자 아님 - 일부 항목 점검불가)"; }

if [ "$OS_FAMILY" = "WINDOWS" ]; then
    echo "# [경고] Windows 환경(Git Bash)에서 실행됨 — Linux/Unix 전용 스크립트"
    echo "# [경고] Windows(IIS) 점검은 check_webwas.ps1 사용"
fi

echo "# ================================================================"
echo "# 점검 대상: ${HN}"
echo "# IP: $(_ip_list)"
echo "# 실행 계정: ${_WHO}"
echo "# 클라우드: $(_cloud_line)"
echo "# OS: ${OS_FAMILY} / ${OS_DISTRO} ${OS_MAJOR}"
echo "# OS 상세: $( ( [ -r /etc/os-release ] && . /etc/os-release 2>/dev/null && echo "${PRETTY_NAME:-$NAME $VERSION_ID}" ) || ( command -v oslevel >/dev/null 2>&1 && echo "AIX $(oslevel -s 2>/dev/null)" ) || ( [ -r /etc/release ] && sed -n 1p /etc/release | sed 's/^ *//' ) || uname -sr 2>/dev/null)"
echo "# 커널: $(uname -r 2>/dev/null)$( [ "$(uname -s 2>/dev/null)" = SunOS ] && echo " / $(uname -v 2>/dev/null)")"
echo "# 웹서버: ${WEB_LIST:-미탐지}"
echo "# WAS: ${WAS_LIST:-미탐지}"
[ -n "$TOMCAT_HOMES" ] && echo "# Tomcat 인스턴스: ${TOMCAT_HOMES}"
[ -n "$JEUS_HOMES" ] && echo "# JEUS 홈: ${JEUS_HOMES}"
[ -n "$DETECT_NOTE" ] && echo "# 탐지 근거: ${DETECT_NOTE}"
case "$_KMODE" in
ef)  echo "# 점검 기준: 전자금융기반시설 보안 취약점 평가기준 제2026-1호 [웹서버-WAS]" ;;
mi)  echo "# 점검 기준: 주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드(2026) [웹 서비스 WEB-01~WEB-26]" ;;
*)   echo "# 점검 기준: 전자금융기반시설 보안 취약점 평가기준 제2026-1호 [웹서버-WAS] + 주요정보통신기반시설 상세가이드(2026) [웹 서비스 WEB-01~WEB-26]" ;;
esac
echo "# 점검 일시: $(date '+%Y-%m-%d %H:%M:%S')"
echo "# ================================================================"

# ── 결과 카운터 ──────────────────────────────────────────────────
_CP=0; _CF=0; _CM=0; _CN=0; _CU=0

_EVD="/tmp/${HN}_webwas_evidence.txt"
_safe_file "$_EVD"   # 심볼릭 링크·타 사용자 소유 파일 방어, 권한 600
# 증적 파일 쓰기 불가(다른 사용자 소유 기존 파일, /tmp 용량 부족 등) → 대체 경로 (쓰기 실패로 판정 중복 방지)
if ! ( : >> "$_EVD" ) 2>/dev/null; then
    _EVD=$(mktemp "${TMPDIR:-/tmp}/${HN}_evidence.XXXXXX" 2>/dev/null || echo "./${HN}_evidence_$$.txt")
    echo "# [경고] 기본 증적 파일에 쓸 수 없어 대체 경로 사용: $_EVD"
fi
[ "$_NONROOT" = 1 ] && { echo "# [경고] root 권한 아님 — 600 설정 파일·/etc/shadow·타 계정 홈 등을 읽지 못하는 항목은 점검불가로 표시됨, root 로 재점검 권고"; }
echo "# ================================================================" > "$_EVD"
echo "# 웹서버/WAS 증적 파일 (감사 추적용)" >> "$_EVD"
echo "# 대상: ${HN} / ${OS_FAMILY} ${OS_DISTRO} ${OS_MAJOR}" >> "$_EVD"
echo "# 웹서버: ${WEB_LIST:-미탐지} / WAS: ${WAS_LIST:-미탐지}" >> "$_EVD"
echo "# 생성: $(date '+%Y-%m-%d %H:%M:%S')" >> "$_EVD"
echo "# IP: $(_ip_list) / 실행 계정: ${_WHO} / 클라우드: $(_cloud_line)" >> "$_EVD"
echo "# 탐지 근거: ${DETECT_NOTE:-없음}" >> "$_EVD"
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
    _TOTAL=$((_CP + _CF + _CM + _CN + _CU))
    echo "# ================================================================"
    echo "# 점검 요약 — 웹서버/WAS (WST)"
    echo "#   총 점검 항목: ${_TOTAL}"
    echo "#   양호:         ${_CP}  (0%)"
    echo "#   취약:         ${_CF}  (0%)"
    echo "#   점검불가:     ${_CU}"
    echo "#   수동확인:     ${_CM}"
    echo "#   N-A:          ${_CN}"
    echo "# ================================================================"
    echo "# 점검 완료: $(date '+%Y-%m-%d %H:%M:%S')"
    echo "# 증적 파일: ${_EVD}"
    exit 0
fi
_iname() {   # 항목명 (bash 3 호환: 연관 배열 대신 case)
    case "$1" in
    WST-001) echo '안전한 네트워크 모니터링 서비스 사용' ;;
    WST-002) echo '네트워크 모니터링 서비스 접근통제 설정 적절성' ;;
    WST-003) echo '불필요한 SMTP 서비스 비활성화' ;;
    WST-004) echo 'SMTP 서비스의 expn/vrfy 명령어 실행 제한 여부' ;;
    WST-005) echo 'SMTP 서비스 로그 수준 설정 적절성' ;;
    WST-006) echo 'SMTP 서비스 보안 패치 적용 여부' ;;
    WST-007) echo 'SMTP 서비스의 DoS 방지 기능 설정 여부' ;;
    WST-008) echo 'SMTP 서비스 스팸 메일 릴레이 제한 설정 여부' ;;
    WST-009) echo 'SMTP 서비스의 메일 queue 처리 권한 설정 적절성' ;;
    WST-010) echo '시스템 관리자 계정의 FTP 사용 제한 여부' ;;
    WST-011) echo '.netrc 파일 내 중요 정보 미포함 여부' ;;
    WST-012) echo 'Anonymous 계정의 FTP 서비스 접속 제한 여부' ;;
    WST-013) echo 'NFS 접근통제 설정 적절성' ;;
    WST-014) echo '불필요한 NFS 서비스 비활성화' ;;
    WST-015) echo '불필요한 RPC 서비스 비활성화' ;;
    WST-016) echo '불필요한 하드디스크 기본 공유 비활성화' ;;
    WST-017) echo '공유 기능에 대한 접근통제 설정 적절성' ;;
    WST-018) echo 'FTP 서비스 접근통제 설정 적절성' ;;
    WST-019) echo '계정의 비밀번호 미설정, 빈 암호 사용 관리 여부' ;;
    WST-020) echo '원격 터미널 서비스의 암호화 설정 적절성' ;;
    WST-021) echo '취약한 Telnet 인증 방식 사용 제한 여부' ;;
    WST-022) echo 'hosts.equiv 또는 .rhosts 설정 제한 여부' ;;
    WST-023) echo 'root 계정 원격 접속 제한 여부' ;;
    WST-024) echo '서비스 접근 IP 및 포트 제한 여부' ;;
    WST-025) echo '원격 터미널 접속 타임아웃 설정 여부' ;;
    WST-026) echo 'SMB 세션 중단 관리 설정 여부' ;;
    WST-027) echo '계정 목록 및 네트워크 공유 이름 노출 방지 여부' ;;
    WST-028) echo '불필요한 서비스 비활성화' ;;
    WST-029) echo '취약한 서비스 비활성화' ;;
    WST-030) echo '취약한 FTP 서비스 비활성화' ;;
    WST-031) echo '웹 서비스 디렉터리 리스팅 방지 설정 여부' ;;
    WST-032) echo '웹 서비스 CGI 스크립트 관리 여부' ;;
    WST-033) echo '웹 서비스 상위 디렉터리 접근 제한 설정 여부' ;;
    WST-034) echo '웹 서비스 경로 내 불필요 파일 관리 여부' ;;
    WST-035) echo '웹 서비스 파일 업로드 및 다운로드 용량 제한 설정 여부' ;;
    WST-036) echo '웹 서비스 프로세스 권한 제한 여부' ;;
    WST-037) echo '웹 서비스 경로 설정 적절성' ;;
    WST-038) echo '웹 서비스 경로 내 불필요한 링크 파일 관리 여부' ;;
    WST-039) echo '불필요한 웹 서비스 비활성화' ;;
    WST-040) echo '웹 서비스 설정 파일 노출 방지 여부' ;;
    WST-041) echo '웹 서비스 경로 내 파일의 접근통제 설정 적절성' ;;
    WST-042) echo '웹 서비스의 불필요한 스크립트 매핑 제거' ;;
    WST-043) echo '웹 서비스 서버 명령 실행 기능 제한 설정 적절성' ;;
    WST-044) echo '웹 서비스 기본 계정(아이디 또는 비밀번호) 변경 여부' ;;
    WST-045) echo 'DNS 서비스 정보 노출 방지 여부' ;;
    WST-046) echo 'DNS Recursive Query 제한 설정 여부' ;;
    WST-047) echo 'DNS 서비스 보안 패치 적용 여부' ;;
    WST-048) echo 'DNS Zone Transfer 제한 설정 적절성' ;;
    WST-049) echo '비밀번호 관리정책 설정 적절성' ;;
    WST-050) echo '취약한 패스워드 저장 방식 사용 제한 여부' ;;
    WST-051) echo '기본 관리자 계정명(Administrator) 변경 여부' ;;
    WST-052) echo '관리자 그룹에 불필요한 사용자 제거' ;;
    WST-053) echo '불필요하거나 관리되지 않는 계정 제거' ;;
    WST-054) echo '비밀번호 복잡도 설정' ;;
    WST-055) echo '불필요한 Guest 계정 비활성화' ;;
    WST-056) echo '익명 사용자에게 부적절한 권한(Everyone) 제거' ;;
    WST-057) echo '일반 사용자의 프린터 드라이버 설치 제한 여부' ;;
    WST-058) echo 'Crontab 설정파일 권한 설정 적절성' ;;
    WST-059) echo '시스템 주요 디렉터리 권한 설정 적절성' ;;
    WST-060) echo '시스템 스타트업 스크립트 권한 설정 적절성' ;;
    WST-061) echo '시스템 주요 파일 권한 설정 적절성' ;;
    WST-062) echo '설치된 C 컴파일러의 권한 설정 적절성' ;;
    WST-063) echo '불필요한 원격 레지스트리 서비스 비활성화' ;;
    WST-064) echo '불필요하게 SUID, SGID bit가 설정된 파일 제거' ;;
    WST-065) echo '사용자 홈 디렉터리 경로 및 권한 설정 적절성' ;;
    WST-066) echo '불필요한 world writable 파일 제거' ;;
    WST-067) echo 'Crontab 참조파일 권한 설정 적절성' ;;
    WST-068) echo '존재하지 않는 소유자 및 그룹 권한을 가진 파일 또는 디렉터리 제거' ;;
    WST-069) echo '사용자 환경파일의 소유자 또는 권한 설정 적절성' ;;
    WST-070) echo 'FTP 서비스 디렉터리 접근권한 설정 적절성' ;;
    WST-071) echo '불필요한 예약 작업 제거' ;;
    WST-072) echo 'LAN Manager 인증 수준 적절성' ;;
    WST-073) echo '보안 채널 데이터 디지털 암호화 또는 서명 기능 설정 적절성' ;;
    WST-074) echo '불필요한 시작프로그램 제거' ;;
    WST-075) echo '로그에 대한 접근통제 및 관리 적절성' ;;
    WST-076) echo '시스템 주요 이벤트 로그 설정 적절성' ;;
    WST-077) echo 'Cron 서비스 로깅 설정 적절성' ;;
    WST-078) echo '로그의 정기적 검토 및 보고 수행 여부' ;;
    WST-079) echo '“보안 감사를 수행할 수 없는 경우, 즉시 시스템 종료” 기능 비활성화' ;;
    WST-080) echo '주기적인 보안패치 및 벤더 권고사항 적용 여부' ;;
    WST-081) echo '백신 프로그램 업데이트 적용 여부' ;;
    WST-082) echo 'root 계정의 PATH 환경변수 설정 적절성' ;;
    WST-083) echo 'umask 설정 적절성' ;;
    WST-084) echo '최종 로그인 사용자 계정 노출 방지 여부' ;;
    WST-085) echo '화면보호기 설정 적절성' ;;
    WST-086) echo '자동 로그온 방지 설정 여부' ;;
    WST-087) echo '로그인 실패 횟수에 따른 접속 제한 설정' ;;
    WST-088) echo 'NTFS 파일 시스템 사용 여부' ;;
    WST-089) echo '백신 프로그램 설치 여부' ;;
    WST-090) echo 'SU 명령 사용가능 그룹 제한 설정 적절성' ;;
    WST-091) echo 'Cron 서비스 사용 계정 제한 설정 적절성' ;;
    WST-092) echo '스택 영역 실행 방지 설정 여부' ;;
    WST-093) echo 'TCP 보안 설정 여부' ;;
    WST-094) echo '로그온 단계에서 "시스템 종료" 기능 비활성화' ;;
    WST-095) echo '네트워크 서비스 접근 권한 적절성' ;;
    WST-096) echo '백업 및 복구 권한 설정 적절성' ;;
    WST-097) echo '시스템 자원 소유권 변경 권한 설정 적절성' ;;
    WST-098) echo '이동식 미디어 포맷 및 꺼내기 허용 정책 설정 적절성' ;;
    WST-099) echo '중복 UID가 부여된 계정 제한 여부' ;;
    WST-100) echo '/dev 경로에 불필요한 파일 제거' ;;
    WST-101) echo '불필요한 네트워크 모니터링 서비스 비활성화' ;;
    WST-102) echo '웹 서비스 정보 노출 방지 여부' ;;
    WST-103) echo '디스크 볼륨 암호화 적용 여부' ;;
    WST-104) echo '로컬 로그온 허용 계정 제한 여부' ;;
    WST-105) echo '익명 SID/이름 변환 설정 제한 여부' ;;
    WST-106) echo '원격터미널 접속 가능한 사용자 그룹 제한 여부' ;;
    WST-107) echo '불필요한 Telnet 서비스 비활성화' ;;
    WST-108) echo 'ftpusers 파일의 소유자 및 권한 설정 적절성' ;;
    WST-109) echo '시스템 사용 주의사항 출력' ;;
    WST-110) echo '구성원이 존재하지 않는 GID 제거' ;;
    WST-111) echo '불필요하게 Shell이 부여된 계정 제거' ;;
    WST-112) echo '불필요한 숨김 파일 또는 디렉터리 제거' ;;
    WST-113) echo 'SMTP 서비스 정보 노출 방지 여부' ;;
    WST-114) echo 'FTP 서비스 정보 노출 방지 여부' ;;
    WST-115) echo '불필요한 시스템 자원 공유 제거' ;;
    WST-116) echo 'DNS 서비스 동적 업데이트 설정 적절성' ;;
    WST-117) echo '불필요한 DNS 서비스 비활성화' ;;
    WST-118) echo '시간 동기화를 위한 NTP 설정' ;;
    WST-119) echo 'sudo 명령어 접근 권한 설정 적절성' ;;
    WST-120) echo '개인 키 사용 시 passphrase 설정 여부' ;;
    WST-121) echo '웹 서비스 불필요한 프록시 설정 제한 여부' ;;
    WST-122) echo '웹 서비스 불필요한 SSI(Server Side Includes) 기능 비활성화' ;;
    WST-123) echo '웹 서비스 기본 에러 페이지 노출 방지 여부' ;;
    WST-124) echo '웹 서비스 부적절한 LDAP 알고리즘 설정 제한 여부' ;;
    WST-125) echo '웹 서비스 독립된 업로드 경로 및 권한 설정 여부' ;;
    WST-126) echo '서비스 지원이 종료된(EoS) 시스템 및 장비 교체 여부' ;;
    esac
}
# ── 판정 라우팅 (평가기준 [웹서버-WAS] 기준) ──
# _PHASE=os    : check_server.sh 로직 재사용 → SRV 코드를 동일 판단기준의 WST 코드로 변환
# _PHASE=web   : 기존 웹 점검 중 평가기준 일치 항목만 반영, 그 외는 REF-(참고) 코드로 분리
# _PHASE=final : 평가기준 판단방법 기준 웹 고유 점검
_s2w() {   # SRV → WST 코드 변환 (bash 3 호환)
    case "$1" in
    SRV-001) echo WST-001 ;;
    SRV-003) echo WST-002 ;;
    SRV-004) echo WST-003 ;;
    SRV-005) echo WST-004 ;;
    SRV-006) echo WST-005 ;;
    SRV-007) echo WST-006 ;;
    SRV-008) echo WST-007 ;;
    SRV-009) echo WST-008 ;;
    SRV-010) echo WST-009 ;;
    SRV-011) echo WST-010 ;;
    SRV-012) echo WST-011 ;;
    SRV-013) echo WST-012 ;;
    SRV-014) echo WST-013 ;;
    SRV-015) echo WST-014 ;;
    SRV-016) echo WST-015 ;;
    SRV-018) echo WST-016 ;;
    SRV-020) echo WST-017 ;;
    SRV-021) echo WST-018 ;;
    SRV-022) echo WST-019 ;;
    SRV-023) echo WST-020 ;;
    SRV-024) echo WST-021 ;;
    SRV-025) echo WST-022 ;;
    SRV-026) echo WST-023 ;;
    SRV-027) echo WST-024 ;;
    SRV-028) echo WST-025 ;;
    SRV-029) echo WST-026 ;;
    SRV-031) echo WST-027 ;;
    SRV-034) echo WST-028 ;;
    SRV-035) echo WST-029 ;;
    SRV-037) echo WST-030 ;;
    SRV-062) echo WST-045 ;;
    SRV-063) echo WST-046 ;;
    SRV-064) echo WST-047 ;;
    SRV-066) echo WST-048 ;;
    SRV-069) echo WST-049 ;;
    SRV-070) echo WST-050 ;;
    SRV-072) echo WST-051 ;;
    SRV-073) echo WST-052 ;;
    SRV-074) echo WST-053 ;;
    SRV-075) echo WST-054 ;;
    SRV-078) echo WST-055 ;;
    SRV-079) echo WST-056 ;;
    SRV-080) echo WST-057 ;;
    SRV-081) echo WST-058 ;;
    SRV-082) echo WST-059 ;;
    SRV-083) echo WST-060 ;;
    SRV-084) echo WST-061 ;;
    SRV-087) echo WST-062 ;;
    SRV-090) echo WST-063 ;;
    SRV-091) echo WST-064 ;;
    SRV-092) echo WST-065 ;;
    SRV-093) echo WST-066 ;;
    SRV-094) echo WST-067 ;;
    SRV-095) echo WST-068 ;;
    SRV-096) echo WST-069 ;;
    SRV-097) echo WST-070 ;;
    SRV-101) echo WST-071 ;;
    SRV-103) echo WST-072 ;;
    SRV-104) echo WST-073 ;;
    SRV-105) echo WST-074 ;;
    SRV-108) echo WST-075 ;;
    SRV-109) echo WST-076 ;;
    SRV-112) echo WST-077 ;;
    SRV-115) echo WST-078 ;;
    SRV-116) echo WST-079 ;;
    SRV-118) echo WST-080 ;;
    SRV-119) echo WST-081 ;;
    SRV-121) echo WST-082 ;;
    SRV-122) echo WST-083 ;;
    SRV-123) echo WST-084 ;;
    SRV-125) echo WST-085 ;;
    SRV-126) echo WST-086 ;;
    SRV-127) echo WST-087 ;;
    SRV-128) echo WST-088 ;;
    SRV-129) echo WST-089 ;;
    SRV-131) echo WST-090 ;;
    SRV-133) echo WST-091 ;;
    SRV-134) echo WST-092 ;;
    SRV-135) echo WST-093 ;;
    SRV-136) echo WST-094 ;;
    SRV-137) echo WST-095 ;;
    SRV-138) echo WST-096 ;;
    SRV-139) echo WST-097 ;;
    SRV-140) echo WST-098 ;;
    SRV-142) echo WST-099 ;;
    SRV-144) echo WST-100 ;;
    SRV-147) echo WST-101 ;;
    SRV-149) echo WST-103 ;;
    SRV-150) echo WST-104 ;;
    SRV-151) echo WST-105 ;;
    SRV-152) echo WST-106 ;;
    SRV-158) echo WST-107 ;;
    SRV-161) echo WST-108 ;;
    SRV-163) echo WST-109 ;;
    SRV-164) echo WST-110 ;;
    SRV-165) echo WST-111 ;;
    SRV-166) echo WST-112 ;;
    SRV-170) echo WST-113 ;;
    SRV-171) echo WST-114 ;;
    SRV-172) echo WST-115 ;;
    SRV-173) echo WST-116 ;;
    SRV-174) echo WST-117 ;;
    SRV-175) echo WST-118 ;;
    SRV-177) echo WST-119 ;;
    SRV-178) echo WST-120 ;;
    SRV-179) echo WST-126 ;;
    esac
}
_NA_LINUX=" WST-016 WST-017 WST-020 WST-021 WST-026 WST-027 WST-032 WST-040 WST-041 WST-042 WST-043 WST-051 WST-055 WST-056 WST-057 WST-063 WST-070 WST-071 WST-072 WST-073 WST-074 WST-079 WST-081 WST-084 WST-085 WST-086 WST-088 WST-089 WST-092 WST-093 WST-094 WST-095 WST-096 WST-097 WST-098 WST-103 WST-104 WST-105 WST-106 WST-115 WST-120 "
_NA_AIX=" WST-016 WST-017 WST-020 WST-021 WST-026 WST-027 WST-032 WST-040 WST-041 WST-042 WST-043 WST-051 WST-055 WST-056 WST-057 WST-063 WST-070 WST-071 WST-072 WST-073 WST-074 WST-079 WST-081 WST-084 WST-085 WST-086 WST-088 WST-089 WST-092 WST-093 WST-094 WST-095 WST-096 WST-097 WST-098 WST-103 WST-104 WST-105 WST-106 WST-115 WST-120 "
_NA_SOLARIS=" WST-016 WST-017 WST-020 WST-021 WST-026 WST-027 WST-032 WST-040 WST-041 WST-042 WST-043 WST-051 WST-055 WST-056 WST-057 WST-063 WST-070 WST-071 WST-072 WST-073 WST-074 WST-079 WST-081 WST-084 WST-085 WST-086 WST-088 WST-089 WST-094 WST-095 WST-096 WST-097 WST-098 WST-103 WST-104 WST-105 WST-106 WST-115 WST-120 "
_NA_HPUX=" WST-016 WST-017 WST-020 WST-021 WST-026 WST-027 WST-032 WST-040 WST-041 WST-042 WST-043 WST-051 WST-055 WST-056 WST-057 WST-063 WST-070 WST-071 WST-072 WST-073 WST-074 WST-079 WST-081 WST-084 WST-085 WST-086 WST-088 WST-089 WST-092 WST-093 WST-094 WST-095 WST-096 WST-097 WST-098 WST-103 WST-104 WST-105 WST-106 WST-115 WST-120 "
_WEB_KEEP=" WST-036 WST-124 WST-125 "
_HOLD_CODES=" WST-080 WST-126 "
_WEB_KEEP=" WST-036 WST-124 WST-125 "
_HOLD_CODES=" WST-080 WST-126 "
_hold_key() { printf '_HOLD_%s' "$(printf '%s' "$1" | tr -c 'A-Za-z0-9\n' '_')"; }   # bash 3 호환: 연관 배열 대신 변수 사용
_hold_set() { eval "$(_hold_key "$1")=\$2"; }
_hold_get() { eval "printf '%s' \"\${$(_hold_key "$1"):-}\""; }
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
    SRV-*) local _w; _w="$(_s2w "$c")"; [ -n "$_w" ] && echo "$_w" || echo "REF-${c}" ;;
    WST-*) if [ "$_PHASE" = "web" ]; then
               case "$_WEB_KEEP" in *" $c "*) echo "$c" ;; *) echo "REF-${c#WST-}" ;; esac
           else echo "$c"; fi ;;
    *) echo "$c" ;;
    esac
}

# 판정 우선순위: 취약 > 점검불가 > 수동확인 > 양호 > N-A (여러 대상 병합 시 더 나쁜 쪽을 앞에)
_rank() { case "$1" in 취약) echo 5;; 점검불가) echo 4;; 수동확인) echo 3;; 양호) echo 2;; N-A) echo 1;; *) echo 0;; esac; }
_worse() {
    [ -z "$1" ] && { echo "$2"; return; }
    [ -z "$2" ] && { echo "$1"; return; }
    local a="${1%%|*}" b="${2%%|*}"
    if [ "$(_rank "$b")" -gt "$(_rank "$a")" ]; then echo "$2 / ${1#*|}"; else echo "$1 / ${2#*|}"; fi
}

# result 는 항상 0 을 반환한다 (A && result X || result Y 이중 출력 방지)
result() {
    if [ "$_NONROOT" = 1 ]; then
        case "${1%%|*}" in SRV-022|SRV-074|SRV-096|SRV-122)
            case "$1" in *"|양호|"*|*"|취약|"*)
                set -- "${1%%|*}|점검불가|root 권한 아님 - shadow·타 계정 파일을 읽지 못해 판정할 수 없음, root 로 재점검 필요 (원 판정: ${1#*|})" ;; esac ;; esac
    fi
    local _code="${1%%|*}" _rest="${1#*|}"
    _code="${_code%% *}"
    _code="$(_route_code "$_code")"
    # 결과 줄 형식(코드|결과|근거)이 깨지지 않게 근거 속의 '|' 와 줄바꿈을 '/'·공백으로 치환
    case "$_rest" in *"|"*) _rest="${_rest%%|*}|$(printf '%s' "${_rest#*|}" | tr '|\n' '/ ')" ;; esac
    case "$_code" in
    REF-*)
        printf '[참고-평가기준 외] %s|%s\n\n' "$_code" "$_rest" >> "$_EVD"
        return 0 ;;
    esac
    if [ "$_PHASE" = "os" ]; then
        case "$_HOLD_CODES" in *" $_code "*) _hold_set "$_code" "$_rest"; return 0 ;; esac
    fi
    case "$_KMODE:$_code" in
    mi:WEB-*) ;;
    mi:*) printf '[참고-주요정보 모드 제외] %s|%s\n\n' "$_code" "$_rest" >> "$_EVD"; return 0 ;;
    ef:WEB-*) return 0 ;;
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
    *"|점검불가|"*) _CU=$((_CU+1)) ;;
    *"|수동확인|"*) _CM=$((_CM+1)) ;;
    *"|N-A|"*)      _CN=$((_CN+1)) ;;
    esac
    local _nm; _nm="$(_iname "$_code")"
    if [ -n "$_nm" ]; then printf '[판정] %s (%s)|%s\n\n' "$_code" "$_nm" "$_rest" >> "$_EVD"
    else printf '[판정] %s\n\n' "$_line" >> "$_EVD"; fi
    return 0
}

_merge_hold() {
    local code="$1" wres="$2" wwhy="$3" os m; os="$(_hold_get "$1")"
    if [ -n "$wres" ]; then m="$(_worse "${os:+${os%%|*}|OS: ${os#*|}}" "${wres}|웹/WAS: ${wwhy}")"
    else m="${os%%|*}|OS: ${os#*|}"; fi
    [ -z "$m" ] || [ "$m" = "|OS: " ] && m="점검불가|판정 정보 없음 - OS 점검 결과와 웹/WAS 점검 결과가 모두 없음"
    _PHASE="final" result "${code}|${m}"
    return 0
}

# 증적 기록: 명령 출력은 자르지 않고 남기되 너무 큰 출력만 2000줄 상한(+생략 줄 수 표시).
# 빈 인자로 현재 디렉터리를 나열하게 되는 명령(ls/find 에 경로 없음)은 실행하지 않는다. 표준입력은 막아 대기하지 않게 한다.
evd() {
    local item; item="$(_route_code "$1")"; shift
    printf '[%s] %s $ %s\n' "$item" "$(date '+%H:%M:%S')" "$*" >> "$_EVD"
    if printf '%s\n' "$*" | tr ';|&' '\n\n\n' | grep -qE '^[[:space:]]*(ls([[:space:]]+-[A-Za-z0-9]+)*|find[[:space:]]+-[A-Za-z]+.*)[[:space:]]*(2>[^[:space:]]*)?[[:space:]]*$'; then
        echo "(대상 경로가 비어 있어 명령을 실행하지 않음)" >> "$_EVD"; printf '\n' >> "$_EVD"; return 0
    fi
    if declare -F _evcap >/dev/null 2>&1; then
        eval "$@" </dev/null 2>&1 | _evcap >> "$_EVD"   # 표준입력을 닫아 빈 인자 grep 이 입력 대기하지 않게, 출력은 마스킹·2000줄 상한 (_evcap 은 SRV-COMMON 구간에 정의)
    else
        { eval "$@" 2>&1 </dev/null; } | awk -v max=2000 'NR <= max { print } END { if (NR > max) printf "(이하 %d줄 생략)\n", NR - max }' >> "$_EVD"
    fi
    printf '\n' >> "$_EVD"
    return 0
}

evd_file() {
    local item f="$2"; item="$(_route_code "$1")"
    if [ -f "$f" ] || [ -d "$f" ]; then printf '[%s] 파일: %s (존재)\n' "$item" "$f" >> "$_EVD"
    else printf '[%s] 파일: %s (미존재)\n' "$item" "$f" >> "$_EVD"; fi
    return 0
}


_csv() { tr '\n' ',' | sed 's/,$//'; }



# ════════════════════════════════════════════════════════════════
# [1] OS 공통 항목 — check_server.sh 점검 로직 (평가기준 판단기준·방법 동일 항목)
# ════════════════════════════════════════════════════════════════
# >>> SRV-COMMON-BEGIN — 원본: server/check_server_srv.sh. 사본(webwas/check_webwas.sh)은 python tools/sync_common.py 로 갱신
# 전체 파일시스템 탐색 시 네트워크/가상 파일시스템 제외 (NFS/CIFS/WSL 윈도우 드라이브 등)
_FP="( -fstype nfs -o -fstype nfs4 -o -fstype cifs -o -fstype smbfs -o -fstype 9p -o -fstype drvfs -o -fstype fuse.sshfs -o -fstype autofs -o -fstype proc -o -fstype sysfs ) -prune -o"
# ── 증적·문자열 공통 헬퍼 ───────────────────────────────────────
_lc() { printf '%s' "$1" | tr '[:upper:]' '[:lower:]'; }   # ${v,,} 대체 (bash 3·Solaris 호환)
_uc() { printf '%s' "$1" | tr '[:lower:]' '[:upper:]'; }
_mask() {   # 증적 비밀정보 마스킹: 패스워드 해시는 알고리즘 접두만, SNMP community·createUser 는 앞 2자+***, password=값, DB 클라이언트 -p비밀번호
    awk '
    function mk(x) { return substr(x,1,2) "***" }
    function join(f,n,   i,r) { r=f[1]; for (i=2;i<=n;i++) r=r " " f[i]; return r }
    {
        line=$0; out=""
        sub(/^[^: ]*\.sh: line [0-9]+: /, "", line)   # bash 오류 메시지의 스크립트 경로·줄번호 접두 제거
        while (match(line, /\$(1|2[aby]|5|6|y|gy|7)\$[^:[:space:]]+/)) {
            h=substr(line,RSTART,RLENGTH); n=index(substr(h,2),"$")+1
            out=out substr(line,1,RSTART-1) substr(h,1,n) "***"; line=substr(line,RSTART+RLENGTH)
        }
        line=out line
        n=split(line,f," "); t=tolower(f[1])
        if (t ~ /^(ro|rw)community6?$/ || t=="community") { f[2]=mk(f[2]); line=join(f,n) }
        else if (t ~ /^com2sec6?$/) { f[4]=mk(f[4]); line=join(f,n) }
        else if (t=="createuser") { for (i=3;i<=n;i++) if (f[i] !~ /^(MD5|SHA|SHA-?[0-9]*|DES|AES|AES-?[0-9]*)$/) f[i]="***"; line=join(f,n) }
        else if (t=="usmuser" || t=="usmuser6") { line="usmUser *** (키 마스킹)" }
        else if (t ~ /^(get|set)-community-name:?$/) { sub(/:[ \t]*[^ \t]+/, ": ***", line) }
        else if (tolower(line) ~ /snmp-server community/) { sub(/[Cc]ommunity[ \t]+[^ \t]+/, "community ***", line) }
        if (tolower(line) ~ /(mysql|mysqldump|mysqladmin|psql|pg_dump|sqlplus)/) gsub(/[ \t]-p[^ \t]+/, " -p***", line)
        gsub(/[Pp]ass(word|wd)[ \t]*[=:][ \t]*[^ \t]+/, "password=***", line)
        gsub(/grub\.pbkdf2\.[^ \t]+/, "grub.pbkdf2.***", line)
        print line
    }'
}
_evcap() {   # 증적 출력: 비밀정보 마스킹 후 너무 큰 목록만 2000줄 상한 (생략 줄 수 표시)
    _mask | awk 'NR<=2000 {print} END {if (NR>2000) print "(이하 " NR-2000 "줄 생략)"}'
}
_unreadable() {   # 존재하지만 현재 계정으로 읽을 수 없는 파일 (비root 실행·권한 부족 → 점검불가 판단용)
    local f
    for f in "$@"; do [ -e "$f" ] && [ ! -r "$f" ] && { echo "$f"; return 0; }; done
    return 1
}
_cfg() {   # 주석(#, !, ;)·빈 줄을 제외한 설정 줄 (여러 파일 가능, 없는 파일은 무시)
    local f
    for f in "$@"; do [ -f "$f" ] && grep -vE '^[[:space:]]*([#!;]|$)' "$f" 2>/dev/null; done
    return 0
}
_pid_comm() { UNIX95=1 ps -e -o pid=,comm=,args= 2>/dev/null | awk '{c=$2; sub(/.*\//,"",c); $2=c; print}'; }   # "PID 프로세스명 인자..." (프로세스명 기준 매칭용)
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
    local svc="$1" ls out
    if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
        # systemd: 유닛이 로드되어 있으면 is-active 결과만 신뢰 (inactive/failed 면 바로 '실행 중 아님' — 로그의 'Started …' 문구 등으로 오판하지 않음)
        ls=$(systemctl show -p LoadState "$svc" 2>/dev/null | sed 's/^LoadState=//')
        if [ "$ls" = "loaded" ]; then
            case "$(systemctl is-active "$svc" 2>/dev/null)" in active|activating|reloading) return 0 ;; *) return 1 ;; esac
        fi
    elif command -v service >/dev/null 2>&1 && [ -x "/etc/init.d/$svc" ]; then
        # SysV: 명확한 상태 문구만 인정 ('is not running'·'stopped'·'dead' 등은 실행 중 아님)
        out=$(service "$svc" status 2>&1 </dev/null)
        if ! echo "$out" | grep -qiE 'not running|stopped|inactive|dead|failed|not found|unrecognized|usage'; then
            echo "$out" | grep -qiE 'is running|active \(running\)|running\.\.\.|\(pid +[0-9]+\)' && return 0
        fi
    fi
    command -v lssrc >/dev/null 2>&1 && [ "$(lssrc -s "$svc" 2>/dev/null | awk 'NR>1{print $NF}')" = "active" ] && return 0
    command -v svcs  >/dev/null 2>&1 && svcs -H "$svc" 2>/dev/null | grep -q "^online" && return 0
    # 프로세스: 인자가 아니라 프로세스 이름(comm) 정확 일치 (comm 은 15자까지만 기록되는 OS 가 있어 15자 접두도 인정)
    if command -v ps >/dev/null 2>&1; then
        _comm | grep -qxF -e "$svc" -e "$(printf '%s' "$svc" | cut -c1-15)" && return 0
    else
        grep -qxF -e "$svc" -e "$(printf '%s' "$svc" | cut -c1-15)" /proc/[0-9]*/comm 2>/dev/null && return 0
    fi
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
        SLES)   echo "/etc/pam.d/common-auth /etc/pam.d/common-password /etc/pam.d/login" ;;
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
_named_conf() {   # 호환용: named 설정(주석 제거, include 포함) 출력 — 실제 로직은 _named_load
    _named_load
    printf '%s\n' "$_NC"
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
_snmp_run() { is_running snmpd && return 0; _comm | grep -qxE 'snmpd|snmpdm|snmpdv3ne|snmpdv3e'; }   # HP-UX snmpdm, AIX snmpdv3 (cmsnmpd·dsm_sa_snmpd 제외) — 프로세스 이름 정확 일치
_comm() { if [ "$OS_FAMILY" = HPUX ]; then UNIX95=1 ps -e -o comm= 2>/dev/null; else ps -e -o comm= 2>/dev/null; fi | sed 's#.*/##'; }
_ftp_running() { is_running vsftpd || is_running proftpd || is_running pure-ftpd || is_running in.ftpd || is_running ftpd || [ -n "$(_inetd_on ftp)" ] || [ -n "$(_listen 21)" ]; }

check_SRV001() {
    # 평가기준: v2 이용 시(v3 사용 가능 환경) 취약, v3 사용 시 보안레벨 AuthPriv — net-snmp 문법(rocommunity/rwcommunity/com2sec)
    local confs; confs=$(_snmp_confs)
    evd "SRV-001" "_svc_state snmpd snmpdm snmpdv3ne snmpdv3e; UNIX95=1 ps -e -o pid,comm,args 2>&1 | grep '[s]nmpd'"
    evd "SRV-001" "_show_cfg ${confs:-/etc/snmp/snmpd.conf /etc/snmpd.conf /etc/snmpdv3.conf}"
    if [ -z "$confs" ] && ! _snmp_run; then result "SRV-001|N-A|SNMP 미설치/미실행"; return; fi
    _snmp_run || { result "SRV-001|N-A|SNMP 설정 파일은 있으나 snmpd 미실행"; return; }
    [ -z "$confs" ] && { result "SRV-001|점검불가|snmpd 가 실행 중이나 설정 파일을 찾지 못해 버전·보안레벨 확인 불가 (/etc/snmp/snmpd.conf 등 8개 경로 없음)"; return; }
    local u; u=$(_unreadable $confs) && { result "SRV-001|점검불가|SNMP 설정 파일 읽기 권한 없음: ${u} (root 로 재점검 필요)"; return; }
    local cl v2 v3 v3weak
    cl=$(_cfg $confs)
    v2=$(echo "$cl" | grep -iE '^[[:space:]]*(rocommunity6?|rwcommunity6?|com2sec6?|community)[[:space:]]|^[[:space:]]*(get|set)-community-name[[:space:]]*:')
    v3=$(echo "$cl" | grep -iE '^[[:space:]]*(rouser|rwuser|createUser)[[:space:]]|^[[:space:]]*access[[:space:]].*[[:space:]]usm[[:space:]]|^[[:space:]]*USM_USER')
    v3weak=$(echo "$cl" | grep -iE '^[[:space:]]*(rouser|rwuser)[[:space:]]+[^[:space:]]+([[:space:]]+(noauth|auth)([[:space:]]|$)|[[:space:]]*$)|^[[:space:]]*access[[:space:]].*[[:space:]]usm[[:space:]]+(noauth|auth)([[:space:]]|$)|^[[:space:]]*VACM_ACCESS[[:space:]].*(noAuthNoPriv|AuthNoPriv)|^[[:space:]]*USM_USER[[:space:]]+([^[:space:]]+[[:space:]]+){5}(-|none)([[:space:]]|$)')
    if [ -n "$v2" ]; then result "SRV-001|취약|SNMP v1/v2c 사용 $(echo "$v2" | grep -c .)건 ($(echo "$v2" | awk '{print $1}' | sort -u | _csv)) - v3 사용 가능 환경에서 v2 이용"
    elif [ -n "$v3weak" ]; then result "SRV-001|취약|SNMPv3 보안레벨 AuthPriv 미적용 $(echo "$v3weak" | grep -c .)건: $(echo "$v3weak" | _mask | _csv)"
    elif [ -n "$v3" ]; then result "SRV-001|양호|SNMPv3 AuthPriv(priv) 사용"
    else result "SRV-001|수동확인|snmpd 실행 중 - 버전·보안레벨 설정 수동 확인 ($(echo $confs))"; fi
}

# ================================================================
# SRV-003: SNMP 접근통제 (ACL)
# ================================================================
check_SRV003() {
    # 평가기준 판단방법: rocommunity/rwcommunity/com2sec 출발지(source) 제한, 'rocommunity public' 출발지 없음 = 통제 미흡
    local confs; confs=$(_snmp_confs)
    evd "SRV-003" "_svc_state snmpd snmpdm snmpdv3ne snmpdv3e"
    evd "SRV-003" "_show_cfg ${confs:-/etc/snmp/snmpd.conf /etc/snmpd.conf /etc/snmpdv3.conf}"
    _snmp_run || { result "SRV-003|N-A|SNMP 미실행"; return; }
    [ -z "$confs" ] && { result "SRV-003|점검불가|snmpd 가 실행 중이나 설정 파일을 찾지 못해 접근통제 확인 불가"; return; }
    local u; u=$(_unreadable $confs) && { result "SRV-003|점검불가|SNMP 설정 파일 읽기 권한 없음: ${u} (root 로 재점검 필요)"; return; }
    local cl open n
    cl=$(_cfg $confs)
    open=$(echo "$cl" | awk 'tolower($1)~/^r[ow]community6?$/ && ($3=="" || $3=="default" || $3=="0.0.0.0/0" || $3=="::/0"){print $1" "$2} tolower($1)~/^com2sec6?$/ && ($3=="default" || $3=="0.0.0.0/0"){print $1" "$4}')
    # HP-UX get/set-community-name 에 IP: 미지정 = 출발지 무제한, AIX community 주소·마스크 0.0.0.0 = 전체 허용
    [ "$OS_FAMILY" = "HPUX" ] && open="${open}$(echo "$cl" | grep -iE '^[[:space:]]*(get|set)-community-name[[:space:]]*:' | grep -viE 'IP:' | awk '{print $1" "$2}')"
    [ "$OS_FAMILY" = "AIX" ] && open="${open}$(echo "$cl" | awk 'tolower($1)=="community" && (($3=="0.0.0.0"&&$4=="0.0.0.0") || ($5=="0.0.0.0"&&$6=="0.0.0.0")){print $1" "$2}')"
    n=$(echo "$open" | grep -c .)
    if [ "$n" -gt 0 ]; then result "SRV-003|취약|출발지 제한 없는 community ${n}건: $(echo "$open" | awk '{print $1" "substr($2,1,2)"***"}' | _csv)"
    elif echo "$cl" | grep -qiE '^[[:space:]]*(rocommunity|rwcommunity|com2sec|rouser|rwuser|(get|set)-community-name)'; then result "SRV-003|양호|SNMP 접근 출발지 지정 또는 v3 사용자 인증"
    else result "SRV-003|수동확인|SNMP 접근통제 설정 수동 확인 ($(echo $confs))"; fi
}

# ================================================================
# SRV-004: SMTP 서비스 비활성화
# ================================================================
check_SRV004() {
    evd "SRV-004" "_svc_state sendmail postfix exim exim4"
    evd "SRV-004" "_listen_all"
    local on=""
    is_running sendmail && on="${on} sendmail"; is_running postfix && on="${on} postfix"
    is_running exim && on="${on} exim"; is_running exim4 && on="${on} exim4"
    [ -n "$(_listen 25)" ] && on="${on} LISTEN:25"
    if [ -n "$on" ]; then result "SRV-004|수동확인|SMTP 서비스 실행 중:${on} (업무상 필요 여부 확인)"
    else result "SRV-004|양호|SMTP 서비스 미실행 (sendmail·postfix·exim 미실행, 25번 포트 미수신)$(_portnote)"; fi
}

# ================================================================
# SRV-011: 시스템 관리자 FTP 접속 제한
# ================================================================
check_SRV011() {
    # 평가기준: FTP 서비스 사용 시 root(관리자) 계정의 FTP 접속 제한 (ftpusers 등에 root 등록)
    local fl="/etc/ftpusers /etc/ftpd/ftpusers /etc/vsftpd/ftpusers /etc/vsftpd.ftpusers" f
    evd "SRV-011" "_svc_state vsftpd proftpd pure-ftpd in.ftpd ftpd; _listen_all; inetadm 2>&1 | grep -i ftp; lssrc -ls inetd 2>&1 | grep -i ftp"
    evd "SRV-011" "_show_cfg $fl"
    _ftp_running || { result "SRV-011|N-A|FTP 서비스 미실행"; return; }
    local found="" miss="" u
    for f in $fl; do
        [ -f "$f" ] || continue
        found="${found} ${f}"
        [ -r "$f" ] || { u="${u} ${f}"; continue; }
        grep -qE '^[[:space:]]*root[[:space:]]*$' "$f" 2>/dev/null || miss="${miss} ${f}"
    done
    [ -n "$u" ] && { result "SRV-011|점검불가|ftpusers 읽기 권한 없음:${u}"; return; }
    if [ -n "$miss" ]; then result "SRV-011|취약|FTP root 제한 미설정 (root 항목 없음):${miss}"
    elif [ -n "$found" ]; then result "SRV-011|양호|FTP root 계정 제한 (${found# })"
    elif grep -qiE '^[[:space:]]*RootLogin[[:space:]]+off' /etc/proftpd/proftpd.conf /etc/proftpd.conf 2>/dev/null; then result "SRV-011|양호|proftpd RootLogin off"
    else result "SRV-011|취약|ftpusers 파일 없음 (FTP 실행 중, root FTP 접속 제한 불가)"; fi
}

# ================================================================
# SRV-013: Anonymous FTP 제한
# ================================================================
check_SRV013() {
    # 평가기준: FTP 미사용 또는 Anonymous 비활성 → 양호
    evd "SRV-013" "_svc_state vsftpd proftpd pure-ftpd in.ftpd ftpd; _listen_all"
    evd "SRV-013" "_show_cfg /etc/vsftpd/vsftpd.conf /etc/vsftpd.conf /etc/proftpd/proftpd.conf /etc/proftpd.conf; grep '^ftp:' /etc/passwd 2>&1"
    _ftp_running || { result "SRV-013|양호|FTP 서비스 미사용$(_portnote)"; return; }
    local f
    for f in /etc/vsftpd/vsftpd.conf /etc/vsftpd.conf; do
        [ -f "$f" ] || continue
        [ -r "$f" ] || { result "SRV-013|점검불가|${f} 읽기 권한 없음"; return; }
        grep -qiE "^[[:space:]]*anonymous_enable[[:space:]]*=[[:space:]]*YES" "$f" 2>/dev/null && { result "SRV-013|취약|Anonymous FTP 활성화 (${f})"; return; }
        grep -qiE "^[[:space:]]*anonymous_enable[[:space:]]*=" "$f" 2>/dev/null || { result "SRV-013|취약|anonymous_enable 미설정 (vsftpd 기본값 YES) (${f})"; return; }
        result "SRV-013|양호|Anonymous FTP 비활성화 (${f})"; return
    done
    for f in /etc/proftpd/proftpd.conf /etc/proftpd.conf; do
        [ -f "$f" ] || continue
        [ -r "$f" ] || { result "SRV-013|점검불가|${f} 읽기 권한 없음"; return; }
        _cfg "$f" | grep -qi "<Anonymous" && { result "SRV-013|취약|proftpd <Anonymous> 블록 활성 (${f})"; return; }
        result "SRV-013|양호|proftpd Anonymous 미설정 (${f})"; return
    done
    grep -q "^ftp:" /etc/passwd 2>/dev/null && result "SRV-013|취약|ftpd 실행 중이며 ftp(anonymous) 계정 존재" || result "SRV-013|수동확인|FTP 실행 중 - Anonymous 설정 수동 확인"
}

# ================================================================
# SRV-014: NFS 접근통제
# ================================================================
check_SRV014() {
    # 평가기준: NFS 비활성화 또는 적절한 접근통제(공유 대상 호스트 지정, 설정 파일 root 644 이하) → 양호
    local files="/etc/exports" f lines="" bad="" p o x
    case "$OS_FAMILY" in
    SOLARIS) files="/etc/dfs/dfstab" ;;
    HPUX)    files="/etc/exports /etc/dfs/dfstab" ;;   # HP-UX 11iv3 은 share 명령(dfstab)
    *)       for x in /etc/exports.d/*.exports; do [ -f "$x" ] && files="${files} ${x}"; done ;;
    esac
    evd "SRV-014" "_svc_state nfsd rpc.nfsd rpc.mountd mountd nfs-server nfs-kernel-server"
    evd "SRV-014" "_show_cfg $files; echo '# exportfs -v'; exportfs -v 2>&1; echo '# share'; share 2>&1; cat /etc/dfs/sharetab 2>&1"
    local rd; rd=$(_unreadable $files) && { result "SRV-014|점검불가|NFS 설정 파일 읽기 권한 없음: ${rd}"; return; }
    for f in $files; do [ -f "$f" ] && lines="${lines}$(_cfg "$f" | sed "s#^#${f}: #")
"; done
    lines=$(echo "$lines" | grep -v '^$')
    [ -n "$lines" ] || { result "SRV-014|양호|NFS 공유 미사용 (${files} 에 공유 설정 없음)"; return; }
    is_running nfsd || is_running rpc.nfsd || is_running mountd || is_running rpc.mountd || is_running nfs-server || is_running nfs-kernel-server || \
        { result "SRV-014|양호|NFS 서비스 비활성 (${files} 설정은 존재 - 참고)"; return; }
    # 호스트 미지정(*·공란·0.0.0.0/0) 공유 / Solaris·HP-UX share 는 rw=·ro=·access= 없는 공유
    case "$OS_FAMILY" in
    SOLARIS|HPUX)
        bad=$(echo "$lines" | grep -E 'share[[:space:]]|-F[[:space:]]+nfs' | grep -vE 'rw=|ro=|access=|root=' | sed 's/^[^:]*: //') ;;
    *)  bad=$(echo "$lines" | sed 's/^[^:]*: //' | awk '{ if (NF<2) {print; next} for(i=2;i<=NF;i++){ h=$i; sub(/\(.*/,"",h); if (h=="" || h=="*" || h=="0.0.0.0/0") {print; break} } }') ;;
    esac
    command -v exportfs >/dev/null 2>&1 && exportfs -v 2>/dev/null | grep -q '<world>' && bad="${bad}
exportfs -v: <world> 전체 허용 공유 존재"
    bad=$(echo "$bad" | grep -v '^$')
    for f in $files; do
        [ -f "$f" ] || continue
        p=$(get_perm "$f"); o=$(get_owner "$f")
        { [ "$o" != "root" ] || _perm_over "$p" 644; } && bad="${bad:+$bad
}${f}(${o}:${p})"
    done
    if [ -n "$bad" ]; then result "SRV-014|취약|NFS 접근통제 미흡 $(echo "$bad" | grep -c .)건: $(echo "$bad" | _csv)"
    else result "SRV-014|양호|NFS 공유 호스트 지정·설정 파일 root 644 이하"; fi
}

# ================================================================
# SRV-015: 불필요 NFS 비활성화
# ================================================================
check_SRV015() {
    evd "SRV-015" "_svc_state nfs nfsd rpc.nfsd nfs-server nfs-kernel-server"
    local on="" s
    for s in nfs nfsd rpc.nfsd nfs-server nfs-kernel-server; do is_running "$s" && on="${on} ${s}"; done
    if [ -n "$on" ]; then result "SRV-015|수동확인|NFS 서비스 실행 중:${on} (업무상 필요 여부 확인)"
    else result "SRV-015|양호|NFS 서비스 미실행"; fi
}

# ================================================================
# SRV-016: 불필요 RPC 비활성화
# ================================================================
check_SRV016() {
    # 평가기준 15종: rpc.cmsd, rpc.ttdbserverd, sadmind, rusersd, walld, sprayd, rstatd, rpc.nisd, rexd, rpc.pcnfsd, rpc.statd, rpc.ypupdated, rpc.rquotad, kcms_server, cachefsd (업무상 사용 시 예외)
    local svcs="rpc.cmsd rpc.ttdbserverd sadmind rusersd rpc.rusersd walld rpc.rwalld sprayd rpc.sprayd rstatd rpc.rstatd rpc.nisd rexd rpc.rexd rpc.pcnfsd rpc.ypupdated kcms_server cachefsd rpc.statd rpc.rquotad"
    evd "SRV-016" "_svc_state $svcs"
    evd "SRV-016" "rpcinfo -p 2>&1; grep -vE '^[[:space:]]*#' /etc/inetd.conf 2>&1"
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
        evd "SRV-016" "inetadm 2>&1"
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
    local no_pw="" pwf="/etc/shadow" u pwe
    case "$OS_FAMILY" in AIX) pwf=/etc/security/passwd ;; *) [ -e /etc/shadow ] || pwf=/etc/passwd ;; esac
    evd "SRV-022" "_pw_status"
    u=$(_unreadable "$pwf") && { result "SRV-022|점검불가|${pwf} 읽기 권한 없음 - 비밀번호 미설정 계정 확인 불가 (root 로 재점검 필요)"; return; }
    case "$OS_FAMILY" in
    AIX)   # AIX 패스워드 파일 = /etc/security/passwd (스탠자 password = 공란)
        no_pw=$(awk '/^[^ \t*#][^ \t]*:[ \t]*$/{sub(/:.*/,"");u=$0;next} /^[ \t]+password[ \t]*=/{v=$0;sub(/^[^=]*=[ \t]*/,"",v);sub(/[ \t]+$/,"",v); if(v=="") print u}' /etc/security/passwd 2>/dev/null)
        ;;
    HPUX|SOLARIS)
        no_pw=$( { [ -f /etc/shadow ] && awk -F: '$2 == "" {print $1}' /etc/shadow 2>/dev/null; logins -p 2>/dev/null | awk '{print $1"(logins -p)"}'; } | sort -u)
        ;;
    *)
        no_pw=$(awk -F: '$2 == "" {print $1}' "$pwf" 2>/dev/null)
        ;;
    esac
    pwe=$(awk -F: '$2=="" && $1!="" {print $1"(passwd 필드 공란)"}' /etc/passwd 2>/dev/null)
    [ -n "$pwe" ] && no_pw="$(printf '%s\n%s' "$no_pw" "$pwe" | grep -v '^$' | sort -u)"
    [ -n "$no_pw" ] && result "SRV-022|취약|비밀번호 미설정 계정 $(echo "$no_pw" | grep -c .)건: $(echo "$no_pw" | _sum 10)" || \
        result "SRV-022|양호|비밀번호 미설정 계정 없음 (${pwf} 전 계정 확인)"
}

# ================================================================
# SRV-025: hosts.equiv / .rhosts 설정 제한
# ================================================================
check_SRV025() {
    # 기준: 파일이 없거나 신뢰 호스트 목록만 있으면 양호, '+' 설정·불필요 계정/호스트가 있으면 취약
    local plus="" entries="" f files na
    files="/etc/hosts.equiv /.rhosts /root/.rhosts $(awk -F: '$6!=""&&$6!="/"{print $6}' /etc/passwd 2>/dev/null | sort -u | while read -r h; do [ -d "$h" ] && echo "${h%/}/.rhosts"; done | tr '\n' ' ')"
    files=$(echo $files | tr ' ' '\n' | sort -u | tr '\n' ' ')
    evd "SRV-025" "_show_exist $files"
    for f in $files; do
        [ -f "$f" ] || continue
        [ -r "$f" ] || { na="${na} ${f}"; continue; }
        _cfg "$f" | grep -qE '(^|[[:space:]])\+' && plus="${plus} ${f}"
        [ -n "$(_cfg "$f")" ] && entries="${entries} ${f}($(_cfg "$f" | grep -c .)줄)"
    done
    na="${na}$(_noaccess_homes | sed 's#.*#& (.rhosts 열람 불가)#' | tr '\n' ' ')"
    if [ -n "$plus" ]; then result "SRV-025|취약|'+' 설정(모든 호스트/계정 신뢰) 존재:${plus}"
    elif [ -n "$entries" ]; then result "SRV-025|수동확인|신뢰 호스트 등록:${entries} - 불필요 계정/호스트 여부 확인"
    elif [ -n "$(echo $na)" ]; then result "SRV-025|점검불가|열람 권한 없는 경로가 있어 확인 불가:${na} (root 로 재점검 필요)"
    else result "SRV-025|양호|hosts.equiv/.rhosts 미존재 또는 설정 없음(주석만)"; fi
}

# ================================================================
# SRV-026: root 원격 접속 제한
# ================================================================
check_SRV026() {
    local cf sb; cf=$(_sshd_cfg); sb=$(_sshd_bin)
    evd "SRV-026" "_show_cfg ${cf:-/etc/ssh/sshd_config} $(ls /etc/ssh/sshd_config.d/*.conf 2>/dev/null | tr '\n' ' ') /etc/securetty; echo '# sshd -T'; sshd -T 2>&1 | grep -iE 'permitrootlogin|sshd:|rror|denied'; ssh -V 2>&1"
    case "$OS_FAMILY" in
    AIX)
        # 평가기준(AIX): rlogin 사용 시 root rlogin=true, SSH 사용 시 PermitRootLogin yes → 하나라도 해당하면 취약
        evd "SRV-026" "grep -A12 '^root:' /etc/security/user 2>&1 | grep -E '^root:|rlogin'; grep -A30 '^default:' /etc/security/user 2>&1 | grep -E '^default:|rlogin'"
        val=$(awk '/^root:/{f=1;next} /^[^ \t*]/{f=0} f&&/rlogin/{sub(/.*=[ \t]*/,"");print;exit}' /etc/security/user 2>/dev/null)
        [ -z "$val" ] && val=$(awk '/^default:/{f=1;next} /^[^ \t*]/{f=0} f&&/rlogin/{sub(/.*=[ \t]*/,"");print;exit}' /etc/security/user 2>/dev/null)
        ssh_root=$([ -n "$cf" ] && grep -iE "^[[:space:]]*PermitRootLogin" "$cf" 2>/dev/null | awk '{print $2}' | head -1)
        if [ "${val:-true}" != "false" ]; then result "SRV-026|취약|AIX root rlogin=${val:-true(기본)}${ssh_root:+, SSH PermitRootLogin=${ssh_root}}"
        elif [ "$(_lc "$ssh_root")" = "yes" ]; then result "SRV-026|취약|AIX SSH PermitRootLogin=yes"
        else result "SRV-026|양호|AIX root rlogin=false, SSH PermitRootLogin=${ssh_root:-미설정(기본)}"; fi ;;
    SOLARIS)
        # 평가기준(Solaris): Telnet — /etc/default/login CONSOLE=/dev/console 없음/주석 이면 취약, SSH — PermitRootLogin yes 취약
        evd "SRV-026" "_show_cfg /etc/default/login"
        cons=$(grep -v "^#" /etc/default/login 2>/dev/null | grep "^CONSOLE")
        ssh_root=$([ -n "$cf" ] && grep -iE "^[[:space:]]*PermitRootLogin" "$cf" 2>/dev/null | awk '{print $2}' | head -1)
        if [ -z "$cons" ]; then result "SRV-026|취약|Solaris CONSOLE=/dev/console 미설정 (Telnet root 원격 접속 가능)${ssh_root:+, PermitRootLogin=${ssh_root}}"
        elif [ "$(_lc "$ssh_root")" = "yes" ]; then result "SRV-026|취약|Solaris SSH PermitRootLogin=yes"
        else result "SRV-026|양호|Solaris CONSOLE 제한, SSH PermitRootLogin=${ssh_root:-미설정}"; fi ;;
    HPUX)
        # 평가기준(HP-UX): Telnet 사용 시 /etc/securetty 없음·console 주석 → 취약, SSH PermitRootLogin yes → 취약
        local tel="" val
        [ -n "$sb" ] && val=$("$sb" -T 2>/dev/null | awk 'tolower($1)=="permitrootlogin"{print $2}')
        [ -z "$val" ] && [ -n "$cf" ] && val=$(grep -iE '^[[:space:]]*PermitRootLogin' "$cf" 2>/dev/null | awk '{print $2}' | head -1)
        if is_running telnetd || [ -n "$(_inetd_on telnet; _listen 23)" ]; then
            grep -qE '^[[:space:]]*console[[:space:]]*$' /etc/securetty 2>/dev/null || tel="Telnet 사용 중 /etc/securetty console 미설정"
        fi
        if [ -n "$tel" ] || [ "$(_lc "$val")" = "yes" ]; then result "SRV-026|취약|HP-UX ${tel}${tel:+, }SSH PermitRootLogin=${val:-미확인} (${cf:-sshd_config 미발견})"
        elif [ -z "$val" ]; then result "SRV-026|점검불가|HP-UX PermitRootLogin 미설정·sshd -T 불가 (${cf:-sshd_config 미발견}) - 설정값 확인 불가(HP-UX Secure Shell 구버전 기본 yes)"
        else result "SRV-026|양호|HP-UX PermitRootLogin=${val}, Telnet root 제한"; fi ;;
    *)
        # 평가기준: SSH는 PermitRootLogin yes 일 때만 취약, Telnet 사용 시 securetty 의 pts 허용 여부
        local src="sshd -T" val=""
        val=$(sshd -T 2>/dev/null | awk 'tolower($1)=="permitrootlogin"{print $2}' | tail -1)
        if [ -z "$val" ]; then
            src="설정파일"
            [ -d /etc/ssh/sshd_config.d ] && val=$(cat /etc/ssh/sshd_config.d/*.conf 2>/dev/null | grep -i "^[[:space:]]*PermitRootLogin" | awk '{print $2}' | head -1)
            [ -z "$val" ] && [ -n "$cf" ] && val=$(grep -i "^[[:space:]]*PermitRootLogin" "$cf" 2>/dev/null | awk '{print $2}' | head -1)
        fi
        local telnet_vuln=""
        if is_running telnetd || is_running in.telnetd || [ -n "$(_inetd_on telnet; _listen 23)" ]; then
            { [ ! -f /etc/securetty ] || grep -qE '^pts' /etc/securetty 2>/dev/null; } && telnet_vuln=" / Telnet 사용 중 securetty pts 허용"
        fi
        if [ -z "$val" ]; then
            local ov; ov=$( { ssh -V 2>&1; sshd -V 2>&1; rpm -q openssh-server 2>/dev/null; dpkg-query -W -f='OpenSSH_${Version}' openssh-server 2>/dev/null; } | grep -oE 'OpenSSH_[0-9]+\.[0-9]+|openssh-server-[0-9]+\.[0-9]+|OpenSSH_1:[0-9]+\.[0-9]+' | head -1 | grep -oE '[0-9]+\.[0-9]+$')
            if [ -n "$ov" ] && [ "${ov%%.*}" -ge 7 ] 2>/dev/null; then val="prohibit-password"; src="OpenSSH ${ov} 기본값"; fi
        fi
        case "$(_lc "$val")" in
        yes) result "SRV-026|취약|PermitRootLogin=yes (${src}) - root 원격 접속 허용${telnet_vuln}" ;;
        no|prohibit-password|without-password|forced-commands-only)
            [ -n "$telnet_vuln" ] && result "SRV-026|취약|PermitRootLogin=${val} (${src})${telnet_vuln}" \
                                  || result "SRV-026|양호|PermitRootLogin=${val} (${src})" ;;
        "") if [ -n "$telnet_vuln" ]; then result "SRV-026|취약|${telnet_vuln# / }"
            elif [ -z "$cf" ] && [ -z "$sb" ] && ! is_running sshd && ! is_running ssh; then result "SRV-026|양호|SSH·Telnet 원격 접속 서비스 없음 (sshd 미설치·미실행)"
            else result "SRV-026|점검불가|PermitRootLogin 설정값 확인 불가 (sshd -T 실패, 설정 파일에 값 없음, OpenSSH 버전 미확인)"; fi ;;
        *)  result "SRV-026|수동확인|PermitRootLogin=${val} (${src})" ;;
        esac ;;
    esac
}

# ================================================================
# SRV-027: 서비스 접근 IP/포트 제한 (TCP Wrapper / firewall)
# ================================================================
check_SRV027() {
    # 평가기준: 방화벽·tcp-wrapper·3rd-party 로 서비스 접근통제 — 규칙 유무로 판단, 없으면 상위 방화벽 등 확인(수동확인)
    evd "SRV-027" "_show_cfg /etc/hosts.allow /etc/hosts.deny /var/adm/inetd.sec; inetadm -p 2>&1 | grep tcp_wrappers; ipfstat -io 2>&1; lsfilt -a 2>&1"
    evd "SRV-027" "firewall-cmd --state 2>&1; firewall-cmd --list-all 2>&1; ufw status numbered 2>&1; iptables -S 2>&1; nft list ruleset 2>&1"
    local tw=0 fw="" n
    [ -n "$(_cfg /etc/hosts.allow /etc/hosts.deny /var/adm/inetd.sec)" ] && tw=1
    if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state 2>/dev/null | grep -q running; then
        n=$( { firewall-cmd --list-rich-rules 2>/dev/null; firewall-cmd --list-sources 2>/dev/null | tr ' ' '\n'; } | grep -c . ); fw="firewalld(zone=$(firewall-cmd --get-default-zone 2>/dev/null), rich/source ${n})"
    elif command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
        n=$(ufw status numbered 2>/dev/null | grep -c "^\["); [ "$n" -gt 0 ] && fw="ufw(${n} rules)"
    fi
    if [ -z "$fw" ]; then
        n=$(iptables -S 2>/dev/null | grep -c '^-A'); [ "${n:-0}" -gt 0 ] && fw="iptables(${n} rules)"
        [ -z "$fw" ] && { n=$(nft list ruleset 2>/dev/null | grep -cE '^[[:space:]]+(ip|tcp|udp|iif|oif|meta|ct)[[:space:]]'); [ "${n:-0}" -gt 0 ] && fw="nftables(${n} rules)"; }
        [ -z "$fw" ] && iptables -S 2>/dev/null | grep -qE '^-P INPUT (DROP|REJECT)' && fw="iptables(INPUT 기본 DROP)"
    fi
    [ -z "$fw" ] && command -v ipfstat >/dev/null 2>&1 && [ -n "$(ipfstat -io 2>/dev/null | grep -E '^(pass|block)')" ] && fw="ipfilter"
    if [ -n "$fw" ] || [ $tw -eq 1 ]; then result "SRV-027|양호|접근통제 규칙 존재 (tcp-wrapper=$([ $tw -eq 1 ] && echo 설정 || echo 없음), 방화벽=${fw:-없음})"
    elif [ "$_NONROOT" = 1 ] && ! command -v firewall-cmd >/dev/null 2>&1 && [ -z "$(iptables -S 2>/dev/null)" ]; then
        result "SRV-027|점검불가|방화벽 규칙 조회 권한 없음 (비root 실행: iptables/nft/firewall-cmd 조회 불가) - root 로 재점검 필요"
    elif [ -n "${_CLOUD:-}" ] && [ "${_CLOUD:-}" != "없음" ] && [ "${_CLOUD:-}" != "미확인" ]; then
        result "SRV-027|수동확인|호스트 방화벽·tcp-wrapper 규칙 없음 - ${_CLOUD} 환경: 보안그룹(${_CLOUD_SG:-ID 미확인})의 인바운드 규칙으로 접근통제 시 양호 가능, 규칙 수동 확인 필요"
    else result "SRV-027|수동확인|호스트 방화벽·tcp-wrapper 규칙 없음 - 상위 방화벽·3rd-party 접근통제 여부 확인 (미통제 시 취약)"; fi
}

# ================================================================
# SRV-028: 원격 터미널 접속 타임아웃
# ================================================================
check_SRV028() {
    # 평가기준: 900초(15분) 이하 양호 (내부 규정이 더 짧으면 그 기준 적용 - 수동 확인)
    local gfiles="/etc/profile /etc/environment /etc/bashrc /etc/bash.bashrc $(ls /etc/profile.d/*.sh 2>/dev/null | tr '\n' ' ')" ufiles="" h
    for h in $(awk -F: '$7!~/(nologin|false|sync|shutdown|halt)$/ && $6!="" {print $6}' /etc/passwd 2>/dev/null | sort -u); do
        h="${h%/}"; ufiles="${ufiles} $h/.profile $h/.bash_profile $h/.bashrc $h/.kshrc"
    done
    ufiles="${ufiles} /root/.profile /root/.bash_profile /root/.bashrc"; ufiles=$(echo $ufiles | tr ' ' '\n' | sort -u | tr '\n' ' ')
    evd "SRV-028" "_ls_exist $gfiles; echo '# TMOUT 설정 줄 (전역)'; _tmout_lines $gfiles"
    evd "SRV-028" "echo '# TMOUT 설정 줄 (계정 홈 파일)'; _tmout_lines $ufiles; echo '# 점검한 홈 파일 수: $(echo $ufiles | wc -w)'"
    local tmout="" t src="" ov="" l v f
    # 전역 설정: 파일 적용 순서대로 마지막 대입값이 유효
    t=$(_tmout_scan $gfiles | tail -1); [ -n "$t" ] && { tmout="${t#*:}"; src="${t%%:*}"; }
    case "$OS_FAMILY" in
    SOLARIS) [ -z "$tmout" ] && tmout=$(grep "^TIMEOUT" /etc/default/login 2>/dev/null | cut -d= -f2 | tr -d ' ') && src="/etc/default/login(TIMEOUT)" ;;
    AIX)     [ -z "$tmout" ] && tmout=$(grep "^TMOUT\|^tmout" /etc/profile /etc/environment 2>/dev/null | grep -oE "[0-9]+" | head -1) ;;
    esac
    # 계정별 홈 파일에서 제한을 풀거나(0·900 초과) 전역 설정이 없을 때 root 에만 설정한 경우
    for l in $(_tmout_scan $ufiles); do
        f="${l%%:*}"; v="${l#*:}"
        if [ "$v" = "0" ] || { [ "$v" -gt 900 ] 2>/dev/null; } || [ -z "$v" ]; then ov="${ov} ${f}(TMOUT=${v:-계산불가})"; fi
    done
    local noacc; noacc=$(_noaccess_homes | tr '\n' ' ')
    if [ -z "$tmout" ] || [ "$tmout" = "0" ]; then
        if [ -n "$(_tmout_scan $ufiles)" ]; then result "SRV-028|취약|전역 TMOUT 미설정 (계정별 파일에만 설정:$(_tmout_scan $ufiles | _sum 5)) - 전체 계정 미적용"
        else result "SRV-028|취약|TMOUT 미설정 (세션 타임아웃 없음, 점검 파일: 전역 $(echo $gfiles | wc -w)개·계정 홈 $(echo $ufiles | wc -w)개)"; fi
    elif [ -n "$ov" ]; then result "SRV-028|취약|전역 TMOUT=${tmout}초(${src})이나 계정 파일에서 해제/초과:${ov}"
    elif ! [ "$tmout" -le 900 ] 2>/dev/null; then
        if [ "$tmout" -gt 900 ] 2>/dev/null; then result "SRV-028|취약|TMOUT=${tmout}초 (900초 초과, ${src})"
        else result "SRV-028|점검불가|TMOUT 값 해석 불가 (${tmout}, ${src})"; fi
    elif [ -n "$noacc" ]; then result "SRV-028|점검불가|전역 TMOUT=${tmout}초(${src}, 900초 이하)이나 열람 권한 없는 계정 홈의 TMOUT 재정의 확인 불가:${noacc} (root 로 재점검 필요)"
    else result "SRV-028|양호|TMOUT=${tmout}초 (${src}, 900초 이하, 내부 규정이 더 짧으면 그 기준으로 확인)"; fi
}

# ================================================================
# SRV-034: automountd 서비스 비활성화 (Solaris 는 dmi 서비스 포함)
# ================================================================
check_SRV034() {
    # 평가기준(LINUX 등): 취약한 버전의 automountd 서비스가 불필요하게 활성화 / Solaris 는 dmi 서비스 추가
    evd "SRV-034" "_svc_state automount automountd autofs dmispd snmpXdmid; _cfg /etc/inetd.conf 2>&1 | grep -i automount; automount -V 2>&1"
    local am="" dmi=""
    { is_running automount || is_running automountd || is_running autofs || _cfg /etc/inetd.conf | grep -qi automount; } && am="automount($(automount -V 2>/dev/null | head -1 | grep -oE '[0-9]+(\.[0-9]+)+' || echo 버전미확인))"
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
    local names="talkd in.talkd ntalkd in.ntalkd fingerd in.fingerd rexecd in.rexecd rlogind in.rlogind rshd in.rshd ypserv ypbind yppasswdd rpc.nisd tftpd in.tftpd"
    evd "SRV-035" "_svc_state $names"
    evd "SRV-035" "_show_cfg /etc/inetd.conf; ls -l /etc/xinetd.d 2>&1; grep -iH 'disable' /etc/xinetd.d/* 2>&1; ss -uln 2>&1"
    local found="" tftp="" s
    for s in talkd in.talkd ntalkd in.ntalkd fingerd in.fingerd rexecd in.rexecd rlogind in.rlogind rshd in.rshd ypserv ypbind yppasswdd rpc.nisd; do
        is_running "$s" && found="${found} ${s}"
    done
    { is_running tftpd || is_running in.tftpd || ss -uln 2>/dev/null | grep -q ':69 '; } && tftp="tftp"
    if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
        evd "SRV-035" "for s in chargen daytime discard echo rsh rlogin rexec finger tftp talk ntalk; do echo \"\$s.socket: \$(systemctl is-active \$s.socket 2>&1)\"; done"
        for s in chargen daytime discard echo rsh rlogin rexec finger tftp talk ntalk; do
            systemctl is-active "${s}.socket" 2>/dev/null | grep -q "^active" && { [ "$s" = tftp ] && tftp="tftp" || found="${found} ${s}.socket"; }
        done
    fi
    local act; act=$(_cfg /etc/inetd.conf | awk '{print $1}' | grep -E '^(tftp|talk|ntalk|finger|exec|login|shell|echo|discard|daytime|chargen)$' | tr '\n' ' ')
    for s in $act; do [ "$s" = tftp ] && tftp="tftp" || found="${found} [inetd:${s}]"; done
    if [ "$OS_FAMILY" = "SOLARIS" ]; then
        for s in $(_inetd_on tftp talk finger login shell rexec echo discard daytime chargen | sed -n 's/^smf://p'); do
            case "$s" in */tftp/*|*/tftp:*) tftp="tftp" ;; *) found="${found} [smf:${s#svc:/network/}]" ;; esac
        done
        evd "SRV-035" "inetadm 2>&1"
    fi
    if [ -d /etc/xinetd.d ]; then
        for s in /etc/xinetd.d/*; do
            [ -f "$s" ] || continue
            grep -qiE 'disable[[:space:]]*=[[:space:]]*no' "$s" 2>/dev/null || continue
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
    _dns_pre SRV-062 || return
    local v vv
    v=$(echo "$_NC" | _dns_stmt version | grep -E '^options')
    vv=$(echo "$v" | head -1 | cut -d'|' -f2- | tr -d '"')
    if [ -z "$v" ]; then result "SRV-062|취약|DNS 버전 노출 차단 미설정 (options 에 version \"none\" 없음, 기본 응답에 BIND 버전 노출)"
    elif echo "$vv" | grep -q '[0-9]'; then result "SRV-062|취약|DNS version 문자열에 버전 포함: ${vv}"
    else result "SRV-062|양호|DNS 버전 노출 차단 (version \"${vv}\")"; fi
}

# ================================================================
# SRV-066: DNS Zone Transfer 제한
# ================================================================
check_SRV066() {
    _dns_pre SRV-066 || return
    local at zones z own glob="" anyv="" miss="" zc=0
    at=$(echo "$_NC" | _dns_stmt allow-transfer)
    zones=$(echo "$_NC" | _dns_stmt type | grep -E '^zone' | grep -E '\|(master|slave|primary|secondary)$' | cut -d'|' -f1)
    anyv=$(echo "$at" | awk -F'|' '{n=split($2,a," "); for(i=1;i<=n;i++) if (a[i]=="any" || a[i]=="0.0.0.0/0" || a[i]=="::/0") {print $1; break}}')
    glob=$(echo "$at" | grep -E '^(options|view)' | head -1)
    while IFS= read -r z; do
        [ -z "$z" ] && continue
        zc=$((zc+1))
        own=$(echo "$at" | grep -F "$z|" | head -1)
        [ -z "$own" ] && [ -z "$glob" ] && miss="${miss}${z}"$'\001'
    done <<EOF
$zones
EOF
    miss=$(printf '%s' "$miss" | tr '\001' '\n')
    if [ -n "$anyv" ]; then result "SRV-066|취약|allow-transfer 에 any 포함(모든 호스트 Zone Transfer 허용): $(echo "$anyv" | _csv)"
    elif [ -n "$miss" ]; then result "SRV-066|취약|allow-transfer 미설정 zone(기본 전체 허용): $(echo "$miss" | _sum 8)"
    elif [ "$zc" -eq 0 ]; then result "SRV-066|양호|master/slave zone 없음 (캐시·포워딩 전용) - 전송 대상 zone 없음"
    else result "SRV-066|양호|Zone Transfer 허용 대상 지정 (${zc}개 zone): $(echo "$at" | sed "s/|/=/" | _sum 8)"; fi
}

# ================================================================
# SRV-063: DNS Recursive Query 제한 설정 여부
# ================================================================
check_SRV063() {
    _dns_pre SRV-063 양호 || return
    local rec ar
    rec=$(echo "$_NC" | _dns_stmt recursion | grep -E '^(options|view)')
    ar=$(echo "$_NC" | _dns_stmt allow-recursion)
    # 평가기준: Recursive query 금지 또는 신뢰 호스트만 허용 → 양호 (BIND 9.4+ 기본 allow-recursion 은 localnets/localhost)
    if echo "$ar" | awk -F'|' '{n=split($2,a," "); for(i=1;i<=n;i++) if (a[i]=="any" || a[i]=="0.0.0.0/0") f=1} END{exit !f}'; then result "SRV-063|취약|allow-recursion 에 any 포함 - 모든 호스트 재귀 질의 허용"
    elif [ -n "$rec" ] && ! echo "$rec" | grep -qE '\|(yes|true|1)$'; then result "SRV-063|양호|recursion no ($(echo "$rec" | sed "s/|/=/" | _csv))"
    elif [ -n "$ar" ]; then result "SRV-063|양호|allow-recursion 신뢰 호스트 한정: $(echo "$ar" | sed "s/|/=/" | _sum 8)"
    else result "SRV-063|수동확인|recursion 허용 대상 미지정 (BIND 기본 localnets·localhost) - 신뢰 호스트 한정 여부 확인"; fi
}

# ================================================================
# SRV-064: DNS 서비스 보안 패치 적용 여부
# ================================================================
check_SRV064() {
    is_running named || { evd "SRV-064" "_svc_state named"; result "SRV-064|양호|DNS 서비스 미실행"; return; }
    evd "SRV-064" "_svc_state named; named -v 2>&1; rpm -q bind 2>&1; dpkg -l bind9 2>&1"
    local named_ver
    named_ver=$(named -v 2>/dev/null | grep -oE 'BIND [0-9][^ ]*' | head -1)
    if [ -n "$named_ver" ]; then
        result "SRV-064|수동확인|DNS 버전: ${named_ver} - 최신 보안 패치 적용 여부 수동 확인"
    else
        result "SRV-064|점검불가|named 가 실행 중이나 named -v 로 버전을 확인하지 못함 - 보안 패치 적용 여부 확인 불가"
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
        ml=$(grep -E "^[[:space:]]*MIN_PASSWORD_LENGTH" /etc/default/security 2>/dev/null | cut -d= -f2 | tr -d ' ')
        for k in PASSWORD_MIN_LOWER_CASE_CHARS PASSWORD_MIN_UPPER_CASE_CHARS PASSWORD_MIN_DIGIT_CHARS PASSWORD_MIN_SPECIAL_CHARS; do
            grep -qE "^[[:space:]]*${k}=[1-9]" /etc/default/security 2>/dev/null && cls=$((cls+1)); done
        who="HP-UX" ;;
    *)
        local pam_files f line="" conf="" c neg=0 mcl
        pam_files=$(get_pam_files)
        for f in $pam_files; do
            [ -f "$f" ] || continue
            line=$(grep -v "^[[:space:]]*#" "$f" 2>/dev/null | grep -iE "pam_pwquality|pam_cracklib" | head -1)
            [ -n "$line" ] && break
        done
        conf=$(grep -vhE "^[[:space:]]*(#|$)" /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf 2>/dev/null)
        if [ -z "$line" ] && [ -z "$conf" ]; then echo "0 0 모듈없음"; return; fi
        _pwv() { local x; x=$(echo "$line" | grep -oE "(^|[[:space:]])$1=-?[0-9]+" | tail -1 | cut -d= -f2)
                 [ -z "$x" ] && x=$(echo "$conf" | grep -E "^[[:space:]]*$1[[:space:]]*=" | tail -1 | grep -oE -- '-?[0-9]+'); echo "$x"; }
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
    evd "SRV-069" "_show_cfg /etc/login.defs /etc/default/passwd /etc/security/user /etc/default/security /etc/security/pwquality.conf $(ls /etc/security/pwquality.conf.d/*.conf 2>/dev/null | tr '\n' ' ') $(get_pam_files)"
    local days="" src="" issues="" pol ml cls who shadow_na=""
    case "$OS_FAMILY" in
    AIX)     local w; w=$(_aix_default | grep -w "maxage" | grep -oE '[0-9]+' | head -1)
             [ -n "$w" ] && days=$((w*7)); src="maxage=${w:-미설정}주" ;;
    SOLARIS) local w; w=$(grep "^MAXWEEKS" /etc/default/passwd 2>/dev/null | cut -d= -f2 | tr -d ' ')
             [ -n "$w" ] && days=$((w*7)); src="MAXWEEKS=${w:-미설정}주" ;;
    HPUX)    days=$(grep -E "^[[:space:]]*PASSWORD_MAXDAYS" /etc/default/security 2>/dev/null | cut -d= -f2 | tr -d ' '); src="PASSWORD_MAXDAYS=${days:-미설정}" ;;
    *)       days=$(grep "^PASS_MAX_DAYS" /etc/login.defs 2>/dev/null | awk '{print $2}'); src="PASS_MAX_DAYS=${days:-미설정}" ;;
    esac
    if [ -z "$days" ] || [ "$days" = "0" ]; then issues="변경 기간 미설정(${src})"
    elif [ "$days" -gt 90 ] 2>/dev/null; then issues="변경 기간 ${days}일 초과(${src})"; fi
    pol=$(_pw_policy); ml=${pol%% *}; cls=$(echo "$pol" | awk '{print $2}'); who=$(echo "$pol" | awk '{print $3}')
    if [ "$who" = "모듈없음" ]; then issues="${issues:+$issues / }복잡도 모듈(pam_pwquality/pam_cracklib) 미설정"
    else _pw_policy_ok "$ml" "$cls" || issues="${issues:+$issues / }복잡도 정책 미달(${who}: 최소 ${ml}자, ${cls}종)"; fi
    if [ "$OS_FAMILY" = "LINUX" ]; then
        if [ -r /etc/shadow ]; then
            local _acc; _acc=$(awk -F: 'NR==FNR{if($7!~/(nologin|false|sync|shutdown|halt)$/)sh[$1]=1;next} ($1 in sh) && $2!~/^[!*]/ && ($5=="" || $5+0>90){print $1"("($5==""?"미설정":$5)")"}' /etc/passwd /etc/shadow 2>/dev/null)
            evd "SRV-069" "echo '# 로그인 가능 계정의 최대 사용기간(shadow 5번째 필드, 잠긴 계정 제외, 90일 초과·미설정만)'; awk -F: 'NR==FNR{if(\$7!~/(nologin|false|sync|shutdown|halt)\$/)sh[\$1]=1;next} (\$1 in sh) && \$2!~/^[!*]/ {print \$1\": \"(\$5==\"\"?\"미설정\":\$5)}' /etc/passwd /etc/shadow 2>&1"
            [ -n "$_acc" ] && issues="${issues:+$issues / }기존 계정 최대 사용기간 90일 초과/미설정(chage) $(echo "$_acc" | grep -c .)건: $(echo "$_acc" | _sum 5)"
        else shadow_na="1"; fi
    fi
    if [ -n "$issues" ]; then result "SRV-069|취약|${issues} - 기준: 2종 10자/3종 8자 이상, 변경 기간 90일 이하"
    elif [ -n "$shadow_na" ]; then result "SRV-069|점검불가|전역 정책은 충족(${src}, ${who}: ${ml}자·${cls}종)하나 /etc/shadow 읽기 권한 없어 기존 계정 사용기간 확인 불가 (root 로 재점검 필요)"
    else result "SRV-069|양호|비밀번호 정책 설정 (${src}, ${who}: 최소 ${ml}자·${cls}종)"; fi
}

# ================================================================
# SRV-070: 취약한 패스워드 저장 방식
# ================================================================
check_SRV070() {
    local des="" alg weak u
    evd "SRV-070" "_hash_algs; grep -E '^[[:space:]]*(ENCRYPT_METHOD|MD5_CRYPT_ENAB)' /etc/login.defs 2>&1; grep -E '^CRYPT_(DEFAULT|ALGORITHMS)' /etc/security/policy.conf /etc/default/security 2>&1; grep -E '^[[:space:]]*pwd_algorithm' /etc/security/login.cfg 2>&1; ls -ld /tcb/files/auth 2>&1"
    case "$OS_FAMILY" in
    AIX)
        # 판단방법(AIX): login.cfg pwd_algorithm 이 112비트 이상 해시인지, /etc/security/passwd 해시 형식
        u=$(_unreadable /etc/security/passwd) && { result "SRV-070|점검불가|/etc/security/passwd 읽기 권한 없음"; return; }
        alg=$(_aix_attr usw pwd_algorithm /etc/security/login.cfg)
        des=$(awk '/^[^ \t*#][^ \t]*:[ \t]*$/{sub(/:.*/,"");u=$0;next} /^[ \t]+password[ \t]*=/{v=$0;sub(/^[^=]*=[ \t]*/,"",v);sub(/[ \t]+$/,"",v); if(v!="" && v!="*" && v!~/^\{/) print u}' /etc/security/passwd 2>/dev/null | _sum 5)
        if [ -n "$des" ]; then result "SRV-070|취약|AIX crypt(DES) 해시 계정: ${des}(pwd_algorithm=${alg:-미설정=crypt})"
        else
            case "$alg" in
            ""|crypt|smd5|ssha1) result "SRV-070|취약|AIX pwd_algorithm=${alg:-미설정(crypt)} - 112비트 이상 안전한 해시(ssha256·ssha512) 아님" ;;
            *) result "SRV-070|양호|AIX pwd_algorithm=${alg}" ;;
            esac
        fi ;;
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
        u=$(_unreadable /etc/shadow) && { result "SRV-070|점검불가|/etc/shadow 읽기 권한 없음 - 해시 방식 확인 불가 (root 로 재점검 필요)"; return; }
        # DES(crypt 13자), MD5($1$, Solaris $md5$) 는 취약 / SHA256($5$)·SHA512($6$)·bcrypt($2*)·yescrypt($y$) 양호
        des=$(awk -F: '$2!="" && $2!~/^(\$|\*|!|NP$|x$|LK)/ && length($2)==13 {print $1}' /etc/shadow 2>/dev/null)
        weak=$(awk -F: '$2 ~ /^\$(1|md5|sunmd5)\$/ {print $1}' /etc/shadow 2>/dev/null)
        if [ -n "$des" ]; then result "SRV-070|취약|DES(crypt) 해시 계정 $(echo "$des" | grep -c .)건: $(echo "$des" | _sum 5)$( [ "$OS_FAMILY" = SOLARIS ] && echo " (CRYPT_DEFAULT=$(sed -n 's/^CRYPT_DEFAULT=//p' /etc/security/policy.conf 2>/dev/null))")"
        elif [ -n "$weak" ]; then result "SRV-070|취약|MD5 해시 계정 $(echo "$weak" | grep -c .)건: $(echo "$weak" | _sum 5)"
        else result "SRV-070|양호|shadow 사용, SHA256/SHA512 등 안전한 해시 (DES·MD5 없음)"; fi ;;
    esac
}

# ================================================================
# SRV-073: 관리자 그룹 불필요 사용자 제거
# ================================================================
check_SRV073() {
    # 평가기준: 관리자 그룹에 '불필요한' 계정 존재 여부 (인원 수 기준 없음) → 구성원 목록 증적 + 인터뷰
    local grps="root wheel sudo admin" grp gid members prim info=""
    [ "$OS_FAMILY" = "BSD" ] && grps="wheel operator"
    [ "$OS_FAMILY" = "AIX" ] && grps="system security"
    evd "SRV-073" "grep -E '^($(echo $grps | tr ' ' '|')):' /etc/group 2>&1; echo '# 기본 그룹이 관리자 그룹인 계정(GID 일치)'; awk -F: '\$3==0 || \$1==\"root\" {print \$1\":\"\$4}' /etc/passwd 2>&1"
    for grp in $grps; do
        members=$(grep "^${grp}:" /etc/group 2>/dev/null | cut -d: -f4)
        gid=$(grep "^${grp}:" /etc/group 2>/dev/null | cut -d: -f3)
        prim=""; [ -n "$gid" ] && prim=$(awk -F: -v g="$gid" '$4==g && $1!="root" {print $1}' /etc/passwd 2>/dev/null | tr '\n' ',' | sed 's/,$//')
        members="${members}${prim:+${members:+,}${prim}(기본그룹)}"
        [ -n "$members" ] && info="${info} ${grp}:[${members}]"
    done
    local zero; zero=$(awk -F: '$3==0 && $1!="root" {print $1}' /etc/passwd 2>/dev/null | tr '\n' ',' | sed 's/,$//')
    [ -n "$zero" ] && info="${info} UID0:[${zero}]"
    if [ -z "$info" ]; then
        result "SRV-073|양호|관리자 그룹(${grps})에 추가 구성원 없음"
    else
        result "SRV-073|수동확인|관리자 그룹 구성원:${info} - 불필요 계정 여부 확인"
    fi
}

# ================================================================
# SRV-074: 불필요/미관리 계정 제거
# ================================================================
check_SRV074() {
    # 평가기준: 로그인 가능한 계정별 분기(90일) 내 로그인 기록 + 비밀번호 변경 여부 (업무상 사용 여부 확인 필요)
    evd "SRV-074" "awk -F: '\$7 !~ /(nologin|false|sync|shutdown|halt)\$/ {print \$1,\$3,\$7}' /etc/passwd 2>&1; echo '# 비밀번호 상태(shadow 3번째 필드=마지막 변경일, 해시 제외)'; awk -F: '{print \$1\": \"(\$2 ~ /^[!*]/ ? \"잠김\" : \"사용\")\", 변경일(1970-01-01 기준 일수)=\"\$3}' /etc/shadow 2>&1; echo '# lastlog'; lastlog 2>&1; lastlog2 2>&1"
    local u; u=$(_unreadable /etc/shadow) && { result "SRV-074|점검불가|/etc/shadow 읽기 권한 없음 - 비밀번호 변경일·잠금 상태 확인 불가 (root 로 재점검 필요)"; return; }
    local today; today=$(( $(date +%s) / 86400 ))
    local vuln="" manual="" unk="" user sh pw lchg ll lsec now; now=$(date +%s)
    [ "$OS_FAMILY" = "AIX" ] && evd "SRV-074" "lsuser -a time_last_login lastupdate account_locked ALL 2>&1"
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
            if [ -z "$ll" ] && ! command -v lastlog >/dev/null 2>&1 && ! command -v lastlog2 >/dev/null 2>&1; then unk="${unk} ${user}(lastlog 명령 없음)"
            elif [ -z "$ll" ] || echo "$ll" | grep -q "Never logged in"; then why="로그인 기록 없음"
            else
                lsec=$(date -d "$(echo "$ll" | awk '{for(i=NF-5;i<=NF;i++) printf $i" "}')" +%s 2>/dev/null)
                if [ -z "$lsec" ]; then unk="${unk} ${user}(로그인 일시 해석 실패)"
                elif [ $(( today - lsec/86400 )) -gt 90 ]; then why="최근 로그인 $(( today - lsec/86400 ))일 전"; fi
            fi ;;
        esac
        if [ -n "$lchg" ] && [ "$lchg" -gt 0 ] 2>/dev/null && [ $(( today - lchg )) -gt 90 ]; then why="${why:+$why, }비밀번호 변경 $(( today - lchg ))일 전"; fi
        [ -n "$why" ] && vuln="${vuln} ${user}(${why})"
    done < /etc/passwd
    [ -n "$manual" ] && evd "SRV-074" "for u in $(echo $manual); do last -1 \$u 2>&1; done"
    if [ -n "$vuln" ]; then result "SRV-074|취약|분기 내 로그인/비밀번호 변경 없는 로그인 가능 계정:${vuln}${unk:+ (조회 불가:${unk})} - 업무상 사용 여부 확인"
    elif [ -n "$unk" ]; then result "SRV-074|점검불가|로그인 기록 조회/해석 불가 계정:${unk}"
    elif [ -n "$manual" ]; then result "SRV-074|수동확인|로그인 기록 자동 조회 불가 계정:${manual} - last 증적으로 90일 내 로그인 확인"
    else result "SRV-074|양호|로그인 가능 계정 모두 분기 내 로그인 및 비밀번호 변경"; fi
}

# ================================================================
# SRV-075: 비밀번호 복잡도
# ================================================================
check_SRV075() {
    # 평가기준: 모든 계정이 복잡도(2종 10자 / 3종 8자) 만족 — 판단방법: 빈 비밀번호 계정 확인 + 크랙
    evd "SRV-075" "_show_cfg /etc/security/pwquality.conf $(ls /etc/security/pwquality.conf.d/*.conf 2>/dev/null | tr '\n' ' ') $(get_pam_files)"
    evd "SRV-075" "_pw_status"
    local empty pol ml cls who u
    u=$(_unreadable /etc/shadow) && { result "SRV-075|점검불가|/etc/shadow 읽기 권한 없음 - 빈 비밀번호 계정 확인 불가 (root 로 재점검 필요)"; return; }
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
    local cfl="/etc/cron.allow /etc/cron.deny /etc/at.allow /etc/at.deny /var/adm/cron/cron.allow /var/adm/cron/cron.deny /var/adm/cron/at.allow /var/adm/cron/at.deny /etc/cron.d/cron.allow /etc/cron.d/cron.deny /etc/cron.d/at.allow /etc/cron.d/at.deny"
    local sd="" d cex="" vuln="" p o f na=""
    for d in /var/spool/cron/crontabs /var/spool/cron; do [ -d "$d" ] && { sd="$d"; break; }; done
    for f in $cfl; do [ -e "$f" ] && cex="${cex} ${f}"; done
    evd "SRV-081" "ls -alL /usr/bin/crontab /bin/crontab 2>&1; echo '# 접근제어 파일 후보 12개 중 존재 $(echo $cex | wc -w)개'; ${cex:+ls -alL $cex 2>&1}; echo '# crontab 파일 디렉터리: ${sd:-없음}'; ls -alL ${sd:-/var/spool/cron} 2>&1"
    for f in /usr/bin/crontab /bin/crontab; do
        [ -f "$f" ] || continue
        p=$(get_perm "$f"); p=${p: -3}
        # 750 이하: others 권한 0, group 쓰기 없음
        { [ "${p:2:1}" != "0" ] || [ $(( ${p:1:1} & 2 )) -ne 0 ]; } 2>/dev/null && vuln="${vuln} ${f}(${p})"
        break
    done
    if [ -n "$sd" ]; then
        if [ ! -r "$sd" ] || [ ! -x "$sd" ]; then na="${sd} 열람 권한 없음"
        else
            for f in "$sd"/*; do
                [ -f "$f" ] || continue
                p=$(get_perm "$f"); p=${p: -1}
                [ $(( p & 6 )) -ne 0 ] 2>/dev/null && vuln="${vuln} ${f}(others:${p})"
            done
        fi
    fi
    for f in $cfl; do
        [ -f "$f" ] || continue
        o=$(get_owner "$f"); p=$(get_perm "$f"); p=${p: -3}
        if [ "$o" != "root" ] || [ "${p:0:1}" -gt 6 ] || [ "${p:1:1}" -gt 4 ] || [ "${p:2:1}" != "0" ]; then vuln="${vuln} ${f}(${o}:${p})"; fi 2>/dev/null
    done
    if [ -n "$vuln" ]; then result "SRV-081|취약|cron 관련 파일 권한 과다:${vuln}"
    elif [ -n "$na" ]; then result "SRV-081|점검불가|${na} - crontab 파일 권한 확인 불가 (root 로 재점검 필요)"
    else result "SRV-081|양호|crontab 명령·crontab 파일·at/cron 접근제어 파일 권한 기준 충족"; fi
}

# ================================================================
# SRV-084: 시스템 주요 파일 권한
# ================================================================
check_SRV084() {
    # 평가기준: passwd 644 / shadow 600 / hosts 644 / (x)inetd.conf 600 / syslog.conf 644 / services 644 / hosts.lpd 640, 소유자 root (AIX /etc/security/passwd 600)
    evd "SRV-084" "ls -la /etc/passwd /etc/shadow /etc/hosts /etc/services /etc/rsyslog.conf /etc/syslog.conf /etc/inetd.conf /etc/xinetd.conf /etc/hosts.lpd /etc/security/passwd 2>&1"
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
        evd "SRV-084" "ls -la /tcb/files/auth/[a-z]/* 2>&1"
        for f in /tcb/files/auth/[a-z]/*; do
            [ -f "$f" ] || continue
            { [ "$(get_owner "$f")" != "root" ] || _perm_over "$(get_perm "$f")" 664; } && { tn=$((tn+1)); [ $tn -le 5 ] && vuln="${vuln} ${f}($(get_owner "$f"):$(get_perm "$f"))"; }
        done
        [ $tn -gt 5 ] && vuln="${vuln} …/tcb 외 $((tn-5))건(증적 참조)"
    fi
    [ -n "$vuln" ] && result "SRV-084|취약|주요 파일 권한 기준 초과:${vuln}" || result "SRV-084|양호|주요 파일 소유자 root·권한 기준 이하"
}

# ================================================================
# SRV-091: SUID/SGID 파일 관리
# ================================================================
check_SRV091() {
    # 평가기준: 불필요하게 SUID·SGID 설정된 파일
    local dangerous="nmap perl python python3 php ruby bash sh find wget curl nc netcat awk vim gdb strace less more cp mv tar zip" bin bp found="" f nopkg="" _rc _all _n pkgtool=0
    _all=$(_to 30 find / $_FP \( -perm -4000 -o -perm -2000 \) -type f -print 2>/dev/null); _rc=$?
    _all=$(printf '%s\n' "$_all" | grep -vE '^/(proc|sys|var/lib/(docker|containers))')
    _n=$(printf '%s' "$_all" | grep -c .)
    for bin in $dangerous; do
        bp=$(command -v "$bin" 2>/dev/null); [ -z "$bp" ] && continue
        { [ -u "$bp" ] || [ -g "$bp" ]; } && found="${found} ${bp}"
    done
    { command -v rpm >/dev/null 2>&1 || command -v dpkg >/dev/null 2>&1; } && pkgtool=1
    if [ "$pkgtool" = 1 ]; then
        while IFS= read -r f; do
            [ -z "$f" ] && continue
            # usrmerge 배포판은 패키지 DB 에 /bin·/sbin 경로로 등록되어 있어 두 경로 모두 조회
            { rpm -qf "$f" >/dev/null 2>&1 || dpkg -S "$f" >/dev/null 2>&1 || dpkg -S "${f#/usr}" >/dev/null 2>&1 || dpkg -S "$(readlink -f "$f")" >/dev/null 2>&1; } || nopkg="${nopkg}${f}
"
        done <<EOF
$_all
EOF
    fi
    _SUID_ALL="$_all"; _SUID_NOPKG="$nopkg"
    evd "SRV-091" "echo '# find 종료코드=${_rc} (124=30초 시간 초과), SUID/SGID 파일 ${_n}개, 패키지 소유 검증 도구=$([ $pkgtool = 1 ] && echo rpm/dpkg || echo 없음)'; printf '%s\\n' \"\$_SUID_ALL\""
    evd "SRV-091" "echo '# 위험 명령 SUID/SGID: ${found:-없음}'; echo '# 패키지에 속하지 않은 SUID/SGID 파일'; printf '%s' \"\$_SUID_NOPKG\""
    if [ -n "$found" ]; then result "SRV-091|취약|위험 SUID/SGID 파일:${found}"; return; fi
    if [ "$_rc" = "124" ]; then result "SRV-091|점검불가|SUID/SGID 파일 검색 시간 초과(30초, 발견 ${_n}개까지만 확인) - 전체 확인 불가"; return; fi
    if [ "$pkgtool" = 0 ]; then result "SRV-091|수동확인|SUID/SGID 파일 ${_n}개 - 패키지 검증 도구(rpm/dpkg) 없어 필요 여부 자동 판단 불가, 증적 목록 확인"; return; fi
    nopkg=$(printf '%s' "$nopkg" | grep -v '^$')
    [ -n "$nopkg" ] && result "SRV-091|수동확인|패키지 외 SUID/SGID 파일 $(echo "$nopkg" | grep -c .)건: $(echo "$nopkg" | _sum 5) - 필요 여부 확인" || result "SRV-091|양호|위험 SUID/SGID 없음, 패키지 기본 파일만 존재 (${_n}개)"
}

# ================================================================
# SRV-092: 사용자 홈 디렉토리 경로/권한
# ================================================================
check_SRV092() {
    # 평가기준: 홈 디렉터리 소유자 불일치·계정간 중복 홈·others 쓰기
    local vuln="" min_uid dup user uid homedir p
    min_uid=$(awk '/^UID_MIN/{print $2}' /etc/login.defs 2>/dev/null)
    [ -z "$min_uid" ] && case "$OS_FAMILY" in AIX) min_uid=200 ;; SOLARIS|HPUX) min_uid=100 ;; *) min_uid=500 ;; esac   # UNIX 일반 사용자 UID 대역
    evd "SRV-092" "echo '# 기준 UID ${min_uid} 이상 일반 계정: 계정 UID 홈 (홈 소유자·권한)'; awk -F: -v m=${min_uid} '\$3>=m && \$3<60000 {print \$1,\$3,\$6}' /etc/passwd | while read -r u i h; do echo \"\$u \$i \$h (\$(get_owner \"\$h\") \$(get_perm \"\$h\"))\"; done"
    dup=$(awk -F: -v m="$min_uid" '$3>=m && $3<60000 && $6!="" && $6!="/" && $7!~/(nologin|false|sync|shutdown|halt)$/ {print $6}' /etc/passwd 2>/dev/null | sort | uniq -d | tr '\n' ' ')
    [ -n "$dup" ] && vuln="${vuln} 중복 홈:${dup}"
    while IFS=: read -r user _ uid _ _ homedir _; do
        [ "${uid:-0}" -lt "$min_uid" ] 2>/dev/null && continue
        { [ "${uid:-0}" -ge 60000 ] || [ "${uid:-0}" -lt 0 ]; } 2>/dev/null && continue   # nobody·noaccess 등
        [ -z "$homedir" ] || [ "$homedir" = "/" ] || [ ! -d "$homedir" ] && continue
        [ "$(get_owner "$homedir")" != "$user" ] && vuln="${vuln} ${homedir}(소유자:$(get_owner "$homedir"))"
        p=$(get_perm "$homedir"); [ -n "$p" ] && [ $(( ${p: -1} & 2 )) -ne 0 ] && vuln="${vuln} ${homedir}(others 쓰기:${p})"
    done < /etc/passwd
    [ -n "$vuln" ] && result "SRV-092|취약|홈 디렉터리 이상:${vuln}" || result "SRV-092|양호|홈 디렉터리 소유자 일치·중복 없음·others 쓰기 없음"
}

# ================================================================
# SRV-093: world writable 파일
# ================================================================
check_SRV093() {
    local _ww _rc cnt
    _ww=$(_to 60 find / $_FP -perm -0002 -type f ! -path "/proc/*" ! -path "/sys/*" \
          ! -path "/dev/*" ! -path "/tmp/*" ! -path "/var/tmp/*" -print 2>/dev/null); _rc=$?
    cnt=$(printf '%s' "$_ww" | grep -c .)
    _WW_LIST="$_ww"
    evd "SRV-093" "echo '# find / -perm -0002 -type f (tmp 제외) 종료코드=${_rc} (124=60초 시간 초과), 발견 ${cnt}개'; printf '%s\\n' \"\$_WW_LIST\""
    # timeout(124) 이고 0건이면 검색 미완료 — 양호로 단정하지 않음
    if [ "$_rc" = "124" ] && [ "${cnt:-0}" -eq 0 ]; then result "SRV-093|점검불가|파일 검색 시간 초과(60초) - world writable 파일 확인 불가"; return; fi
    [ "${cnt:-0}" -gt 0 ] 2>/dev/null && \
        result "SRV-093|취약|world writable 파일 ${cnt}개 (tmp 제외)$([ "$_rc" = 124 ] && echo ', 검색 시간 초과로 일부만 확인'): $(echo "$_ww" | _sum 5)" || \
        result "SRV-093|양호|world writable 파일 없음"
}

# ================================================================
# SRV-108: 로그 접근통제 및 관리
# ================================================================
check_SRV108() {
    # 기준: 로그 파일을 소유자 이외 사용자가 수정 가능(그룹/others 쓰기)하면 취약 — 예외: wtmp·lastlog 664, btmp 660 (권한 변경 불가)
    local dirs="" d out err files logf perm vuln="" cnt
    for d in /var/log /var/adm; do [ -d "$d" ] && dirs="${dirs} ${d}"; done
    [ "$OS_FAMILY" = "AIX" ] && dirs="$dirs /etc/security"
    [ -z "$dirs" ] && { evd "SRV-108" "ls -ld /var/log /var/adm 2>&1"; result "SRV-108|점검불가|로그 디렉터리(/var/log·/var/adm)가 없음"; return; }
    out=$(find $dirs -type f \( -perm -020 -o -perm -002 \) 2>&1)
    err=$(echo "$out" | grep '^find:')
    files=$(echo "$out" | grep -v '^find:' | grep -v '^$')
    cnt=$(echo "$files" | grep -c .)
    _LOGW_LIST="$files"
    evd "SRV-108" "ls -la /var/log/messages /var/log/secure /var/log/auth.log /var/log/syslog /var/log/wtmp /var/log/lastlog 2>&1; echo '# ${dirs} 에서 group/others 쓰기 가능한 파일 ${cnt}개 (예외 포함): 권한 소유자 경로'; _pstat \$(printf '%s\\n' \"\$_LOGW_LIST\")"
    for logf in $files; do
        perm=$(get_perm "$logf")
        case "$(basename "$logf")" in
        wtmp*|lastlog*|btmp*) [ "$(( 0${perm: -1} & 2 ))" -eq 0 ] 2>/dev/null && continue ;;
        esac
        vuln="${vuln} ${logf}(${perm})"
    done
    if [ -n "$vuln" ]; then result "SRV-108|취약|소유자 외 쓰기 가능한 로그 파일 $(echo $vuln | wc -w)건:$(echo $vuln | tr ' ' '\n' | _sum 5)"
    elif [ -n "$err" ]; then result "SRV-108|점검불가|로그 디렉터리 일부를 탐색하지 못함 ($(echo "$err" | head -1)) - root 로 재점검 필요"
    else result "SRV-108|양호|로그 파일 소유자 외 쓰기 권한 없음 (wtmp·lastlog 664, btmp 660 기준 예외)"; fi
}

# ================================================================
# SRV-109: 주요 이벤트 로그 설정
# ================================================================
check_SRV109() {
    local rf="/etc/rsyslog.conf $(ls /etc/rsyslog.d/*.conf 2>/dev/null | tr '\n' ' ') /etc/syslog.conf /etc/syslog-ng/syslog-ng.conf"
    evd "SRV-109" "_svc_state rsyslog syslog-ng syslogd systemd-journald; _show_cfg $rf /etc/default/su; ls -ld /var/log/journal 2>&1"
    case "$OS_FAMILY" in
    SOLARIS)
        # 평가기준(Solaris): auth.info 활성 + /etc/default/su SULOG=경로, SYSLOG=YES
        local a=0 s=0
        _cfg /etc/syslog.conf | grep -qE 'auth\.(info|debug|\*)|\*\.(info|debug)' && a=1
        grep -qE '^SULOG=' /etc/default/su 2>/dev/null && grep -qE '^SYSLOG=YES' /etc/default/su 2>/dev/null && s=1
        [ $a -eq 1 ] && [ $s -eq 1 ] && result "SRV-109|수동확인|auth.info·SULOG·SYSLOG=YES 설정 - 내부 로그 정책 부합 여부 확인" || result "SRV-109|취약|Solaris auth.info(${a})·/etc/default/su SULOG·SYSLOG=YES(${s}) 미충족" ;;
    AIX|HPUX)
        [ -r /etc/syslog.conf ] || { result "SRV-109|점검불가|/etc/syslog.conf 없음 또는 읽기 불가"; return; }
        _cfg /etc/syslog.conf | grep -qiE "^auth|\*\.(info|debug)" && \
            result "SRV-109|수동확인|syslog auth 설정 존재 - 내부 로그 기록 정책 부합 여부 확인" || result "SRV-109|취약|syslog auth 로그 미설정" ;;
    *)
        local f u
        u=$(_unreadable $rf) && { result "SRV-109|점검불가|syslog 설정 파일 읽기 권한 없음: ${u}"; return; }
        for f in $rf; do
            [ -f "$f" ] || continue
            _cfg "$f" | grep -qiE "^[[:space:]]*(auth|authpriv)|^[[:space:]]*\*\.\*;auth" && { result "SRV-109|양호|auth/authpriv 로그 설정됨 (${f}) - 내부 로그 정책 부합 여부는 참고 확인"; return; }
            _cfg "$f" | grep -qiE "auth" && [ "$f" = /etc/syslog-ng/syslog-ng.conf ] && { result "SRV-109|양호|syslog-ng auth 로그 설정됨"; return; }
        done
        # syslog 데몬이 없는 journald 전용 배포판(AL2023 등): 인증 로그가 journal 에 기록됨 — 영구 저장(/var/log/journal) 여부로 판단
        if is_running systemd-journald && ! is_running rsyslog && ! is_running syslog-ng && ! is_running syslogd; then
            if [ -d /var/log/journal ]; then result "SRV-109|양호|journald 전용(rsyslog 없음), /var/log/journal 영구 저장으로 인증 이벤트 로그 기록"
            else result "SRV-109|수동확인|journald 전용(rsyslog 없음)이나 영구 저장(/var/log/journal) 없음 - 재부팅 시 로그 소실, Storage=persistent 설정 확인"; fi
            return
        fi
        result "SRV-109|취약|auth/authpriv 로그 설정 없음" ;;
    esac
}

# ================================================================
# SRV-118: 보안패치 적용
# ================================================================
check_SRV118() {
    # 평가기준: 보안 패치 적용 — 보안 업데이트(security advisory)만 집계. 저장소 캐시 갱신은 최소화(가능하면 캐시 기준), 저장소 접근 실패·미등록은 점검불가
    case "$OS_FAMILY" in
    AIX)     evd "SRV-118" "uname -r; oslevel -s 2>&1; instfix -i 2>&1 | grep -E 'ML|SP'; emgr -l 2>&1" ;;
    HPUX)    evd "SRV-118" "uname -r; swlist -l bundle 2>&1 | grep -iE 'QPK|HPUX'" ;;
    SOLARIS) evd "SRV-118" "uname -r; cat /etc/release 2>&1; showrev -p 2>&1 | grep -c Patch; pkg info entire 2>&1 | grep -iE 'version|branch'" ;;
    *)       evd "SRV-118" "uname -r; cat /etc/os-release 2>&1" ;;
    esac
    case "$OS_FAMILY" in
    LINUX)
        local _pm="" _cnt="" _rc="" _out="" _mode="" _lines=""
        if command -v dnf >/dev/null 2>&1 || command -v yum >/dev/null 2>&1; then
            _pm=$(command -v dnf >/dev/null 2>&1 && echo dnf || echo yum)
            evd "SRV-118" "$_pm repolist 2>&1"
            # check-update --security: 100=보안 업데이트 있음, 0=없음, 그 외(1 등)=저장소 오류. 먼저 캐시 기준(-C)으로 조회하고, 캐시가 없을 때만 메타데이터를 갱신
            _mode="캐시 기준(-C)"
            _out=$(_to 120 $_pm -q -C --security check-update 2>&1); _rc=$?
            if [ "$_rc" != 0 ] && [ "$_rc" != 100 ]; then
                _mode="메타데이터 갱신 포함"
                _out=$(_to 120 $_pm -q --security check-update 2>&1); _rc=$?
            fi
            _lines=$(echo "$_out" | grep -E '^[A-Za-z0-9_.+-]+\.[A-Za-z0-9_]+[[:space:]]+[0-9]' )
            case "$_rc" in 100) _cnt=$(echo "$_lines" | grep -c .) ;; 0) _cnt=0 ;; esac
            # 활성 저장소 없음(미등록)은 0건으로 보지 않음
            [ "$_cnt" = 0 ] && [ "$($_pm repolist 2>/dev/null | awk 'NR>1' | grep -c .)" = 0 ] && _cnt=""
        elif command -v apt-get >/dev/null 2>&1; then
            _pm="apt"; _mode="로컬 패키지 목록 기준(apt-get update 미수행)"
            local _lst; _lst=$(ls /var/lib/apt/lists 2>/dev/null | grep -c 'Packages\|Release')
            evd "SRV-118" "apt-cache policy 2>&1 | grep -iE 'security|origin' ; ls -l /var/lib/apt/periodic/update-success-stamp 2>&1"
            if [ "${_lst:-0}" -gt 0 ] && apt-cache policy 2>/dev/null | grep -qi 'security'; then
                _out=$(apt-get -s upgrade 2>&1); _rc=$?
                [ "$_rc" = 0 ] && { _lines=$(echo "$_out" | grep '^Inst ' | grep -i 'security'); _cnt=$(echo "$_lines" | grep -c .); }
            else _rc="보안 저장소 미등록 또는 패키지 목록 없음"; fi
        elif command -v zypper >/dev/null 2>&1; then
            _pm="zypper"; _mode="캐시 기준(--no-refresh)"
            _out=$(_to 120 zypper -q --non-interactive --no-refresh list-patches --category security 2>&1); _rc=$?
            [ "$_rc" = 0 ] && { _lines=$(echo "$_out" | grep -E '^[^|]*\|[^|]*\|[[:space:]]*security'); _cnt=$(echo "$_lines" | grep -c .); }
        fi
        _SEC_LINES="$_lines"; _SEC_OUT=""; [ -z "$_cnt" ] && _SEC_OUT="$_out"
        evd "SRV-118" "echo '# 패키지 관리자=${_pm:-없음}, 조회 방식=${_mode:-없음}, 종료코드=${_rc:-없음}, 보안 업데이트=${_cnt:-조회 실패}건'; printf '%s\\n' \"\$_SEC_LINES\"; printf '%s\\n' \"\$_SEC_OUT\""
        if [ -z "$_pm" ]; then
            result "SRV-118|점검불가|지원하는 패키지 관리자(dnf·yum·apt·zypper)를 찾지 못함 - 보안패치 적용 현황 자동 확인 불가"
        elif [ -z "$_cnt" ]; then
            result "SRV-118|점검불가|${_pm} 보안 업데이트 조회 실패 (rc=${_rc}: 저장소 접근 실패·미등록·폐쇄망 등) - 보안패치 적용 현황 수동 확인 필요"
        elif [ "$_cnt" -gt 0 ] 2>/dev/null; then
            result "SRV-118|취약|미적용 보안 업데이트 ${_cnt}건 (${_pm}, ${_mode}): $(echo "$_lines" | awk '{print $1=="Inst"?$2:$1}' | _sum 5)"
        else
            result "SRV-118|양호|미적용 보안 업데이트 없음 (${_pm}, ${_mode})"
        fi ;;
    *)
        result "SRV-118|수동확인|보안패치 적용 현황 수동 확인 필요 (${OS_FAMILY} 는 증적의 패치 레벨 확인)" ;;
    esac
}

# ================================================================
# SRV-121: root PATH 환경변수
# ================================================================
check_SRV121() {
    # 평가기준: PATH 에 '.', '::'(빈 항목) 또는 불필요한 임의 경로
    local files="/root/.bashrc /root/.bash_profile /root/.profile /etc/profile /etc/environment /etc/bashrc /etc/bash.bashrc $(ls /etc/profile.d/*.sh 2>/dev/null | tr '\n' ' ')"
    [ "$(awk -F: '$1=="root"{print $6}' /etc/passwd 2>/dev/null)" = "/" ] && files="$files /.profile /.bash_profile /.bashrc /.kshrc"   # UNIX root 홈 '/'
    local ex="" f
    for f in $files; do [ -f "$f" ] && ex="${ex} ${f}"; done
    evd "SRV-121" "echo \"현재 실행 셸 PATH=\$PATH\"; _ls_exist $files; echo '# PATH 대입 줄'; grep -nHE '^[[:space:]]*(export[[:space:]]+)?PATH=' ${ex:-/dev/null} 2>&1"
    local bad="" v e
    while IFS= read -r v; do
        v=$(echo "$v" | sed -E 's/^[[:space:]]*(export[[:space:]]+)?PATH=//; s/["'"'"']//g')
        [ -z "$v" ] && continue
        case ":$v:" in *"::"*) bad="${bad} [빈 항목] ${v}"; continue ;; esac
        local IFS=':'; for e in $v; do
            case "$e" in .|./*) bad="${bad} [.] ${v}"; break ;; esac
        done; unset IFS
    done < <( { grep -hE '^[[:space:]]*(export[[:space:]]+)?PATH=' $files 2>/dev/null; echo "PATH=$PATH"; } )
    [ -n "$bad" ] && result "SRV-121|취약|PATH 에 현재 디렉터리(.) 또는 빈 항목:$(echo "$bad" | cut -c1-200)" || result "SRV-121|양호|PATH 에 '.'·'::' 미포함"
}

# ================================================================
# SRV-122: umask 설정
# ================================================================
check_SRV122() {
    # 평가기준: 모든 계정·설정 파일 umask 가 022 이상(group·others 쓰기 금지)
    local hf="" h files vals v bad="" cur na
    for h in $(awk -F: '$7!~/(nologin|false|sync|shutdown|halt)$/ && $6!="" {print $6}' /etc/passwd 2>/dev/null | sort -u); do
        h="${h%/}"; hf="${hf} $h/.profile $h/.bashrc $h/.bash_profile $h/.kshrc $h/.cshrc"
    done
    files="/etc/profile /etc/bashrc /etc/bash.bashrc /etc/login.defs $(ls /etc/profile.d/*.sh 2>/dev/null | tr '\n' ' ')${hf}"
    cur="${_UMASK_ORIG:-$(umask)}"
    evd "SRV-122" "echo '현재 로그인 셸 umask=${cur}'; echo '# 파일별 umask 설정 (주석 제외)'; _umask_scan $files; echo '# 점검 파일 수: $(echo $files | wc -w)'"
    vals=$( { _umask_scan $files | sed 's/^.*: //'
              [ "$OS_FAMILY" = "AIX" ] && awk '/^[^ \t*#][^ \t]*:[ \t]*$/{next} /^[ \t]+umask[ \t]*=/{v=$0;sub(/^[^=]*=[ \t]*/,"",v);print v}' /etc/security/user 2>/dev/null;
              [ "$OS_FAMILY" = "HPUX" ] && sed -n 's/^[[:space:]]*UMASK=\([0-7]*\).*/\1/p' /etc/default/security 2>/dev/null; } | sort -u)
    [ "$OS_FAMILY" = "AIX" ] && evd "SRV-122" "lsuser -a umask ALL 2>&1"
    [ -z "$vals" ] && vals="$cur"
    for v in $vals; do
        (( (8#$v & 8#022) == 8#022 )) 2>/dev/null || bad="${bad} ${v}"
    done
    na=$(_noaccess_homes | tr '\n' ' ')
    if [ -n "$bad" ]; then result "SRV-122|취약|group/others 쓰기 허용 umask:${bad} (022 이상 필요, 조건부 설정 포함; 설정 위치는 증적 참조)"
    elif [ -n "$na" ]; then result "SRV-122|점검불가|열람 권한 없는 홈 디렉터리의 umask 확인 불가: ${na}(root 로 재점검 필요) - 확인된 값: $(echo $vals)"
    else result "SRV-122|양호|umask $(echo $vals) (022 이상)"; fi
}

# ================================================================
# SRV-127: 로그인 실패 횟수 접속 제한
# ================================================================
check_SRV127() {
    # 평가기준: 계정 잠금 임계값 설정이 존재하면 양호 (횟수는 내부 규정 확인) — 5회 초과는 사실상 미설정과 같아 수동확인
    evd "SRV-127" "_show_cfg /etc/security/faillock.conf $(get_pam_files)"
    local val="" label=""
    case "$OS_FAMILY" in
    AIX)     label="AIX loginretries";      val=$(_aix_attr default loginretries)
             evd "SRV-127" "lsuser -a loginretries ALL 2>&1"
             local z; z=$(awk '/^[^ \t*#][^ \t]*:[ \t]*$/{sub(/:.*/,"");st=$0;next} st!="default" && st!="root" && /^[ \t]+loginretries[ \t]*=[ \t]*0[ \t]*$/{print st}' /etc/security/user 2>/dev/null | tr '\n' ' ')
             [ -n "$z" ] && [ "${val:-0}" -gt 0 ] 2>/dev/null && { result "SRV-127|취약|AIX loginretries=${val}(default)이나 계정별 0 재정의: ${z}"; return; } ;;
    SOLARIS) # 평가기준(SOL): policy.conf LOCK_AFTER_RETRIES=YES + /etc/default/login RETRIES 설정
             evd "SRV-127" "_show_cfg /etc/security/policy.conf /etc/default/login"
             if grep -qE '^[[:space:]]*LOCK_AFTER_RETRIES=YES' /etc/security/policy.conf 2>/dev/null; then
                 val=$(sed -n 's/^[[:space:]]*RETRIES=\([0-9]*\).*/\1/p' /etc/default/login 2>/dev/null | tail -1)
                 label="Solaris LOCK_AFTER_RETRIES=YES, RETRIES"
             else label="Solaris LOCK_AFTER_RETRIES 미설정(≠YES)"; val=""; fi ;;
    HPUX)    # Trusted Mode: /tcb/files/auth/system/default u_maxtries#N / Non Trusted: AUTH_MAXTRIES (/etc/default/security, /var/adm/userdb/*)
             evd "SRV-127" "_show_cfg /etc/default/security; grep -H u_maxtries /tcb/files/auth/system/default 2>&1"
             if [ -f /tcb/files/auth/system/default ]; then label="HP-UX u_maxtries(Trusted)"; val=$(grep -oE 'u_maxtries#[0-9]+' /tcb/files/auth/system/default 2>/dev/null | head -1 | cut -d'#' -f2)
             else label="HP-UX AUTH_MAXTRIES"; val=$(grep -hE "^[[:space:]]*AUTH_MAXTRIES" /etc/default/security /var/adm/userdb/* 2>/dev/null | head -1 | cut -d= -f2 | tr -d ' '); fi ;;
    *)
        local pam_files f d="" found=0 pamval=""
        pam_files=$(get_pam_files)
        for f in $pam_files; do
            [ -f "$f" ] || continue
            if _cfg "$f" | grep -qi "pam_faillock"; then
                label="pam_faillock"; found=1
                pamval=$(_cfg "$f" | grep -i "pam_faillock" | grep -oE 'deny=[0-9]+' | cut -d= -f2 | head -1)
                break
            fi
        done
        # pam 줄의 deny= 옵션이 faillock.conf 보다 우선, 둘 다 없으면 pam_faillock 기본값 3
        d=$(_cfg /etc/security/faillock.conf | grep -E "^[[:space:]]*deny[[:space:]]*=" | grep -oE '[0-9]+' | tail -1)
        if [ $found -eq 1 ]; then
            if [ -n "$pamval" ]; then val=$pamval; label="pam_faillock deny"
            elif [ -n "$d" ]; then val=$d; label="faillock.conf deny"
            else val=3; label="pam_faillock(기본 deny=3)"; fi
        fi
        if [ $found -eq 0 ]; then
            for f in $pam_files; do
                [ -f "$f" ] || continue
                if _cfg "$f" | grep -qi "pam_tally"; then
                    label="pam_tally2"; val=$(_cfg "$f" | grep -i "pam_tally" | grep -oE 'deny=[0-9]+' | cut -d= -f2 | head -1); break
                fi
            done
        fi ;;
    esac
    if [ -z "$val" ] || [ "$val" = "0" ]; then
        result "SRV-127|취약|계정 잠금 임계값 미설정${label:+ (${label})}"
    elif [ "$val" -le 5 ] 2>/dev/null; then
        result "SRV-127|양호|${label}=${val}회 설정"
    else
        result "SRV-127|수동확인|${label}=${val}회 설정 - 5회 초과, 내부 규정 기준 확인 필요"
    fi
}

# ================================================================
# SRV-131: su 명령어 그룹 제한
# ================================================================
check_SRV131() {
    evd "SRV-131" "_show_cfg /etc/pam.d/su /etc/default/security /etc/pam.conf; ls -l /bin/su /usr/bin/su 2>&1; grep -E '^(root|default):|sugroups' /etc/security/user 2>&1"
    local su p
    su=$(ls /bin/su /usr/bin/su 2>/dev/null | head -1); p=$(get_perm "$su")
    case "$OS_FAMILY" in
    AIX)
        local g; g=$(awk '/^root:/{f=1;next} /^[^ \t*]/{f=0} f&&/sugroups/{sub(/.*=[ \t]*/,"");print;exit}' /etc/security/user 2>/dev/null)
        [ -z "$g" ] && g=$(awk '/^default:/{f=1;next} /^[^ \t*]/{f=0} f&&/sugroups/{sub(/.*=[ \t]*/,"");print;exit}' /etc/security/user 2>/dev/null)
        [ -n "$g" ] && [ "$(_uc "$g")" != "ALL" ] && result "SRV-131|양호|AIX sugroups=${g}" || result "SRV-131|취약|AIX sugroups=${g:-미설정} (ALL/미설정)" ;;
    HPUX)
        local g; g=$(grep -E '^[[:space:]]*SU_ROOT_GROUP' /etc/default/security 2>/dev/null | cut -d= -f2 | tr -d ' ')
        [ -n "$g" ] && [ "$(_uc "$g")" != "ALL" ] && result "SRV-131|양호|HP-UX SU_ROOT_GROUP=${g}" || result "SRV-131|취약|HP-UX SU_ROOT_GROUP 미지정" ;;
    SOLARIS)
        if _cfg /etc/pam.conf | grep -q su_group; then result "SRV-131|양호|pam.conf su_group 설정"
        elif [ -n "$p" ] && [ $(( ${p: -1} & 1 )) -eq 0 ]; then result "SRV-131|양호|${su} others 실행 권한 없음 (${p}, 그룹=$(ls -l "$su" | awk '{print $4}'))"
        elif [ -z "$p" ]; then result "SRV-131|점검불가|su 명령의 권한을 확인하지 못함 (pam.conf su_group 설정도 없음)"
        else result "SRV-131|취약|${su} others 실행 가능 (${p})"; fi ;;
    *)
        if _cfg /etc/pam.d/su | grep -qE '^[[:space:]]*auth[[:space:]]+(required|requisite)[[:space:]]+[^[:space:]]*pam_wheel\.so'; then
            result "SRV-131|양호|su pam_wheel required 설정 (그룹=$(_cfg /etc/pam.d/su | grep -oE 'group=[^[:space:]]+' | cut -d= -f2 | head -1 | sed 's/^$/wheel/'))"
        elif [ -n "$p" ] && [ $(( ${p: -1} & 1 )) -eq 0 ]; then result "SRV-131|양호|${su} others 실행 권한 없음 (${p})"
        elif [ -z "$p" ]; then result "SRV-131|점검불가|su 명령(/bin/su·/usr/bin/su)의 권한을 확인하지 못함 (pam_wheel 설정도 없음)"
        else result "SRV-131|취약|su pam_wheel(required) 미설정, ${su} others 실행 가능 (${p})"; fi ;;
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
    evd "SRV-133" "ls -la $allow $deny 2>&1; echo '[allow]'; cat $allow 2>&1; echo '[deny]'; cat $deny 2>&1"
    local a_cnt d_cnt u
    u=$(_unreadable $allow $deny) && { result "SRV-133|점검불가|${u} 읽기 권한 없음"; return; }
    a_cnt=$(_cfg "$allow" | grep -c .); d_cnt=$(_cfg "$deny" | grep -c .)
    if [ -f "$allow" ] && [ "${a_cnt:-0}" -gt 0 ]; then result "SRV-133|양호|${allow} 허용 계정 ${a_cnt}개 관리"
    elif [ ! -f "$allow" ] && [ ! -f "$deny" ]; then
        case "$OS_DISTRO" in
        UBUNTU|DEBIAN) result "SRV-133|취약|cron.allow/cron.deny 모두 없음 (Debian 계열은 모든 계정 cron 사용 가능)" ;;
        *) result "SRV-133|양호|cron.allow/cron.deny 모두 없음 (root만 cron 사용 가능)" ;;
        esac
    elif [ ! -f "$allow" ] && [ "${d_cnt:-0}" -eq 0 ]; then result "SRV-133|취약|cron.allow 없고 cron.deny 비어 있음 (모든 계정 cron 사용 가능)"
    elif [ ! -f "$allow" ]; then result "SRV-133|양호|${deny} 거부 계정 ${d_cnt}개 관리"
    else result "SRV-133|수동확인|${allow} 존재하나 허용 계정 없음 (cron 사용 불가) - 의도 확인"; fi
}

# ================================================================
# SRV-142: 중복 UID 계정 제한
# ================================================================
check_SRV142() {
    evd "SRV-142" "echo '# UID:계정 (전체, UID 순)'; awk -F: '{print \$3\":\"\$1}' /etc/passwd | sort -n"
    local dup
    dup=$(awk -F: '{c[$3]++; n[$3]=n[$3] (n[$3]==""?"":",") $1} END{for(u in c) if (c[u]>1) print "UID "u"("n[u]")"}' /etc/passwd 2>/dev/null | sort)
    [ -n "$dup" ] && result "SRV-142|취약|중복 UID 발견 $(echo "$dup" | grep -c .)건: $(echo "$dup" | _sum 5)" || \
        result "SRV-142|양호|중복 UID 없음"
}

# ================================================================
# SRV-144: /dev 불필요 파일
# ================================================================
check_SRV144() {
    # 평가기준: /dev 에 존재하지 않는 불필요 device(일반) 파일 (mqueue, shm 예외)
    local fl cnt
    fl=$(find /dev \( -path /dev/shm -o -path /dev/mqueue \) -prune -o -type f -print 2>/dev/null)
    cnt=$(printf '%s' "$fl" | grep -c .)
    _DEVF_LIST="$fl"
    evd "SRV-144" "echo '# /dev 아래 일반 파일(shm·mqueue 제외) ${cnt}개'; printf '%s\\n' \"\$_DEVF_LIST\""
    [ "$cnt" -gt 0 ] && result "SRV-144|취약|/dev 내 일반 파일 ${cnt}개: $(echo "$fl" | _sum 5)" || result "SRV-144|양호|/dev 불필요 일반 파일 없음 (shm·mqueue 제외)"
}

# ================================================================
# SRV-158: 불필요 Telnet 서비스 비활성화
# ================================================================
check_SRV158() {
    evd "SRV-158" "_svc_state telnetd in.telnetd; _listen_all; echo \"inetd·xinetd·SMF 활성 telnet: $(_inetd_on telnet | tr '\n' ' ')\"; inetadm 2>&1 | grep -i telnet; lssrc -ls inetd 2>&1 | grep -i telnet"
    local on; on=$( { _inetd_on telnet; _listen 23 | awk '{print "LISTEN:23"}'; } | tr '\n' ' ')
    if is_running telnetd || is_running in.telnetd || [ -n "$on" ]; then result "SRV-158|취약|Telnet 서비스 활성 (${on:-telnetd 프로세스})"
    else result "SRV-158|양호|Telnet 서비스 미실행$(_portnote)"; fi
}

# ================================================================
# SRV-161: ftpusers 파일의 소유자 및 권한 설정 적절성
# ================================================================
check_SRV161() {
    local fl="/etc/ftpusers /etc/ftpd/ftpusers /etc/vsftpd/ftpusers /etc/vsftpd/user_list /etc/vsftpd.ftpusers /etc/vsftpd.user_list"
    local f found="" bad="" p o ex=""
    for f in $fl; do [ -f "$f" ] && ex="${ex} ${f}"; done
    evd "SRV-161" "echo '# ftpusers 계열 파일 $(echo $ex | wc -w)개 존재 (후보 6개)'; _pstat $ex; _svc_state vsftpd proftpd in.ftpd ftpd"
    for f in $fl; do
        [ -f "$f" ] || continue
        found="${found} ${f}"; p=$(get_perm "$f"); o=$(get_owner "$f")
        { [ "$o" != "root" ] || _perm_over "$p" 640; } && bad="${bad} ${f}(소유자:${o},권한:${p})"
    done
    if [ -z "$found" ]; then
        _ftp_running && result "SRV-161|취약|ftpusers 파일 없음 (FTP 실행 중)" || result "SRV-161|양호|FTP 서비스 미실행 (ftpusers 파일 없음)"
        return
    fi
    [ -n "$bad" ] && result "SRV-161|취약|ftpusers 소유자/권한 이상:${bad}" || result "SRV-161|양호|${found# } 소유자=root, 권한 640 이하"
}

# ================================================================
# SRV-163: 시스템 사용 주의사항 출력 (Banner)
# ================================================================
check_SRV163() {
    # 평가기준: 로그온 시 경고 메시지 미출력 또는 문구 내 시스템 버전 정보 노출 시 취약
    local cf; cf=$(_sshd_cfg)
    evd "SRV-163" "sshd -T 2>&1 | grep -iE 'banner|sshd:|rror'; _show_cfg ${cf:-/etc/ssh/sshd_config} $(ls /etc/ssh/sshd_config.d/*.conf 2>/dev/null | tr '\n' ' '); for f in /etc/issue /etc/issue.net /etc/motd; do echo \"# \$f\"; cat \$f 2>&1; done; grep -i herald /etc/security/login.cfg 2>&1"
    local files="" f txt="" ver sshon=0 sbf=""
    local sb; sb=$(sshd -T 2>/dev/null | awk 'tolower($1)=="banner"{print $2}')
    [ -z "$sb" ] && sb=$( { [ -n "$cf" ] && grep -vE '^[[:space:]]*#' "$cf"; cat /etc/ssh/sshd_config.d/*.conf 2>/dev/null | grep -vE '^[[:space:]]*#'; } | grep -iE '^[[:space:]]*Banner' | awk '{print $NF}' | tail -1)
    { [ -n "$cf" ] || is_running sshd || is_running ssh; } && sshon=1
    [ -n "$sb" ] && [ "$sb" != "none" ] && [ -s "$sb" ] && { files="$sb"; sbf="$sb"; }
    for f in /etc/issue /etc/issue.net /etc/motd; do [ -s "$f" ] && files="${files} ${f}"; done
    [ "$OS_FAMILY" = "AIX" ] && txt=$(grep -vE '^[[:space:]]*\*' /etc/security/login.cfg 2>/dev/null | grep -i 'herald' | head -1)
    for f in $files; do txt="${txt}"$'\n'"$(cat "$f" 2>/dev/null)"; done
    if [ -z "$(echo "$txt" | tr -d '[:space:]')" ]; then result "SRV-163|취약|로그온 경고 메시지(배너) 미설정 (sshd Banner·/etc/issue·/etc/motd 모두 비어 있음)"; return; fi
    # SSH 로 접속하는 서버는 sshd Banner 가 로그인 전 경고 문구 (/etc/issue 는 콘솔·텔넷에만 표시)
    if [ "$sshon" = 1 ] && [ "$OS_FAMILY" != "AIX" ] && [ -z "$sbf" ]; then
        result "SRV-163|취약|SSH 사용 중이나 sshd Banner 미설정(${sb:-none}) - /etc/issue 등은 SSH 로그인 시 표시되지 않음 ($(echo $files))"; return
    fi
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
    # 평가기준: 시간 동기화를 위한 NTP 설정 — 데몬이 상위 서버와 실제 동기화된 상태인지 확인
    evd "SRV-175" "_svc_state chronyd chrony ntpd ntp xntpd systemd-timesyncd; chronyc tracking 2>&1; chronyc sources 2>&1; ntpq -pn 2>&1; timedatectl 2>&1; lssrc -ls xntpd 2>&1"
    evd "SRV-175" "_show_cfg /etc/chrony.conf /etc/chrony/chrony.conf /etc/ntp.conf /etc/inet/ntp.conf /etc/systemd/timesyncd.conf"
    local synced="" cfgd="" ct
    if command -v chronyc >/dev/null 2>&1; then
        ct=$(chronyc tracking 2>/dev/null)
        # 동기화 안 됨: 'Leap status : Not synchronised' 또는 Reference ID 00000000 / Stratum 0
        echo "$ct" | grep -qiE 'Leap status[[:space:]]*:[[:space:]]*Normal' && ! echo "$ct" | grep -qE 'Reference ID[[:space:]]*:[[:space:]]*0{8}' && synced="chrony($(echo "$ct" | awk -F': ' '/^Reference ID/{print $2}'))"
    fi
    [ -z "$synced" ] && command -v ntpq >/dev/null 2>&1 && ntpq -pn 2>/dev/null | grep -qE '^[*o]' && synced="ntpd 활성 피어"
    [ -z "$synced" ] && command -v timedatectl >/dev/null 2>&1 && timedatectl 2>/dev/null | grep -qiE '(System clock|NTP) synchronized:[[:space:]]*yes' && synced="timedatectl(systemd-timesyncd 등)"
    [ -n "$(_cfg /etc/chrony.conf /etc/chrony/chrony.conf /etc/ntp.conf /etc/inet/ntp.conf | grep -iE '^[[:space:]]*(server|pool|peer)[[:space:]]')" ] && cfgd="ntp/chrony 서버 설정"
    [ -z "$cfgd" ] && grep -qE '^[[:space:]]*NTP=[^[:space:]]' /etc/systemd/timesyncd.conf 2>/dev/null && cfgd="timesyncd NTP= 설정"
    if [ -n "$synced" ]; then result "SRV-175|양호|NTP 동기화 확인: ${synced}"
    elif [ -n "$cfgd" ]; then
        if is_running chronyd || is_running ntpd || is_running xntpd || is_running systemd-timesyncd; then result "SRV-175|수동확인|NTP 데몬 실행·서버 설정(${cfgd})이나 동기화 상태를 확인하지 못함 - 증적의 sources/tracking 확인"
        else result "SRV-175|취약|NTP 서버는 설정(${cfgd})되었으나 동기화 데몬 미실행"; fi
    else result "SRV-175|취약|NTP 동기화 설정 없음 (chrony·ntpd·systemd-timesyncd 서버 설정·동기화 상태 모두 확인되지 않음)"; fi
}

# ================================================================
# SRV-177: sudo 명령어 접근 권한 설정
# ================================================================
check_SRV177() {
    # 평가기준: sudo 접근 제한 — 불필요한 사용자가 sudo 권한을 가지는지 확인
    local sf="/etc/sudoers $(ls /etc/sudoers.d/* 2>/dev/null | tr '\n' ' ')" u
    evd "SRV-177" "command -v sudo 2>&1; ls -l $sf 2>&1; grep -vE '^[[:space:]]*(#|Defaults|\$)' $sf 2>&1"
    command -v sudo >/dev/null 2>&1 || [ -f /etc/sudoers ] || { result "SRV-177|양호|sudo 미설치 (sudoers 없음)"; return; }
    u=$(_unreadable $sf) && { result "SRV-177|점검불가|sudoers 읽기 권한 없음: ${u} (root 로 재점검 필요)"; return; }
    local rules all="" who="" np=""
    rules=$(grep -hvE '^[[:space:]]*(#|Defaults|$)|^[[:space:]]*(User|Runas|Host|Cmnd)_Alias|^[[:space:]]*@include|^[[:space:]]*#include' $sf 2>/dev/null | grep -E '=')
    all=$(echo "$rules" | awk '$1=="ALL" || $1=="%users" || $1=="%everyone" || $1=="%staff"{print $1}' | sort -u | tr '\n' ' ')
    who=$(echo "$rules" | awk '$1!="root"{print $1}' | sort -u | tr '\n' ' ')
    np=$(echo "$rules" | grep -c 'NOPASSWD')
    if [ -n "$all" ]; then result "SRV-177|취약|모든(또는 일반 사용자 그룹) 사용자 sudo 허용: ${all}"
    elif [ -n "$(echo $who)" ]; then result "SRV-177|수동확인|sudo 권한 보유: ${who}(NOPASSWD 규칙 ${np}건) - 불필요 사용자 여부 확인"
    else result "SRV-177|양호|root 외 sudo 권한 없음"; fi
}

# ================================================================
# SRV-179: EoS 시스템 장비 교체 (자동 판정)
# ================================================================
check_SRV179() {
    local EOS_SCRIPT product="" version="" _PY _eo eos_result eos_desc
    EOS_SCRIPT="$(dirname "$0")/eos_checker.py"
    [ -f "$EOS_SCRIPT" ] || EOS_SCRIPT="$(dirname "$0")/../converter/eos_checker.py"   # 저장소 구조 그대로 실행 시
    evd "SRV-179" "uname -srm; cat /etc/os-release 2>&1; oslevel -s 2>&1; swlist -l product 2>&1 | grep -E '^[[:space:]]*HP-UX'; pkg info entire 2>&1 | grep -iE 'version|branch'; cat /etc/release 2>&1; ls -l ${EOS_SCRIPT} 2>&1"
    [ ! -f "$EOS_SCRIPT" ] && {
        result "SRV-179|점검불가|eos_checker.py 를 찾지 못해 EoS 자동 판정 불가 - 수동 확인 필요"
        return
    }

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
            result "SRV-179|수동확인|OS ${OS_DISTRO} ${OS_MAJOR} EoS 수동 확인 (EoS 데이터에 없는 배포판)"
            return ;;
        esac ;;
    *)
        result "SRV-179|점검불가|OS 종류(${OS_FAMILY})를 판별하지 못해 EoS 확인 불가"
        return ;;
    esac

    _PY=$(command -v python3 2>/dev/null || { [ -x /usr/libexec/platform-python ] && echo /usr/libexec/platform-python; } || command -v python 2>/dev/null)
    if [ -z "$_PY" ]; then result "SRV-179|점검불가|python 미설치로 EoS 판정 도구 실행 불가 - ${product} ${version} EoS 여부 수동 확인"; return; fi
    # 점검 대상 서버에서 외부(endoflife.date) 접속을 하지 않도록 --no-api: 내장 EoS 데이터로만 판정 (폐쇄망 정책)
    _eo=$("$_PY" "$EOS_SCRIPT" --no-api "$product" "$version" 2>&1)
    _EOS_OUT="$_eo"
    evd "SRV-179" "echo '# eos_checker.py --no-api ${product} ${version}'; printf '%s\\n' \"\$_EOS_OUT\""
    eos_result=$(echo "$_eo" | grep "^결과:" | awk '{print $2}')
    eos_desc=$(echo "$_eo" | grep "^설명:" | cut -d: -f2- | sed "s/^ *//;s/ *$//")
    [ -z "$eos_result" ] && { result "SRV-179|점검불가|EoS 판정 도구 결과를 해석하지 못함 (${product} ${version}) - 수동 확인"; return; }
    result "SRV-179|${eos_result}|${eos_desc} (내장 EoS 데이터 기준, 외부 조회 안 함)"
}

# ================================================================
# SRV-087: C 컴파일러 권한
# ================================================================
check_SRV087() {
    local _cc_list _cc_ex="" c _all=0
    _cc_list=$(for c in /usr/bin/gcc /usr/bin/cc /usr/bin/g++ /usr/local/bin/gcc /usr/vac/bin/xlc /usr/vac/bin/cc /opt/aCC/bin/aCC /opt/ansic/bin/cc /opt/SUNWspro/bin/cc /opt/developerstudio*/bin/cc /usr/sfw/bin/gcc $(command -v cc gcc 2>/dev/null); do echo "$c"; done | sort -u)   # /usr/ucb/cc 는 Studio 미설치 시 동작하지 않는 래퍼라 제외
    for c in $_cc_list; do _all=$((_all+1)); [ -e "$c" ] && _cc_ex="${_cc_ex} ${c}"; done
    evd "SRV-087" "echo '# C 컴파일러 후보 경로 ${_all}개 중 존재 $(echo $_cc_ex | wc -w)개'; $([ -n "$_cc_ex" ] && echo "ls -laL ${_cc_ex}" || echo "command -v gcc cc 2>&1")"
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
_smtp_pids() {   # MTA PID 목록 — 프로세스 이름(comm) 기준 (인자에 sendmail 등이 들어간 vim·grep 은 제외)
    case "$1" in
    sendmail) _pid_comm | awk '$2=="sendmail" || $2=="sm-mta" {print $1}' ;;
    postfix*) _pid_comm | awk '($2=="master" && /postfix/) || $2=="postfix" {print $1}' ;;
    exim)     _pid_comm | awk '$2 ~ /^exim4?$/ {print $1}' ;;
    esac
}
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
    [ -n "$(_listen 25)" ] && return 0
    return 1
}

# ================================================================
# SRV-005: SMTP EXPN/VRFY 제한
# ================================================================
check_SRV005() {
    _smtp_gate SRV-005 || return
    _detect_smtp
    evd "SRV-005" "postconf disable_vrfy_command 2>&1; _smtp_cf_show '^[[:space:]]*O[[:space:]]+PrivacyOptions'"
    case "$_smtp_type" in
    postfix)
        command -v postconf >/dev/null 2>&1 || { result "SRV-005|점검불가|postfix 실행 중이나 postconf 명령을 찾지 못함"; return; }
        local val; val=$(postconf -h disable_vrfy_command 2>/dev/null)
        [ "$val" = "yes" ] && result "SRV-005|양호|postfix disable_vrfy_command=yes" || \
            result "SRV-005|취약|postfix disable_vrfy_command=${val:-no}" ;;
    sendmail)
        [ -f "$_smtp_cf" ] || { result "SRV-005|점검불가|sendmail 설정 파일(sendmail.cf)을 찾지 못함"; return; }
        # 평가기준: noexpn 과 novrfy 또는 goaway
        local po; po=$(grep -iE '^[[:space:]]*O[[:space:]]+PrivacyOptions' "$_smtp_cf" 2>/dev/null | tail -1)
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
    _smtp_gate SRV-006 || return
    _detect_smtp
    evd "SRV-006" "postconf debug_peer_level syslog_facility 2>&1; _smtp_cf_show '^[[:space:]]*O[[:space:]]+LogLevel'"
    case "$_smtp_type" in
    postfix)
        command -v postconf >/dev/null 2>&1 || { result "SRV-006|점검불가|postfix 실행 중이나 postconf 명령을 찾지 못함"; return; }
        # 평가기준: debug_peer_level 2 이상 (기본 2)
        local dl; dl=$(postconf -h debug_peer_level 2>/dev/null)
        [ "${dl:-2}" -ge 2 ] 2>/dev/null && result "SRV-006|양호|postfix debug_peer_level=${dl:-2(기본)}" || result "SRV-006|취약|postfix debug_peer_level=${dl} (2 이상 필요)" ;;
    sendmail)
        [ -f "$_smtp_cf" ] || { result "SRV-006|점검불가|sendmail 설정 파일(sendmail.cf)을 찾지 못함"; return; }
        # 평가기준: LogLevel 9 이상 (미설정 시 기본 9)
        local lv; lv=$(grep -iE "^[[:space:]]*O[[:space:]]+LogLevel" "$_smtp_cf" 2>/dev/null | grep -oE '[0-9]+' | tail -1)
        [ "${lv:-9}" -ge 9 ] 2>/dev/null && result "SRV-006|양호|sendmail LogLevel=${lv:-9(기본)}" || result "SRV-006|취약|sendmail LogLevel=${lv} (9 이상 필요)" ;;
    *) result "SRV-006|수동확인|${_smtp_type:-SMTP} 로그 수준 수동 확인" ;;
    esac
}

# ================================================================
# SRV-007: SMTP 보안패치
# ================================================================
check_SRV007() {
    _smtp_gate SRV-007 || return
    _detect_smtp
    local ver=""
    case "$_smtp_type" in
    postfix) ver=$(postconf -h mail_version 2>/dev/null); evd "SRV-007" "postconf mail_version 2>&1" ;;
    sendmail) ver=$(sendmail -d0.1 </dev/null 2>&1 | head -1 | grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)?' | head -1)
              [ -z "$ver" ] && [ -f "$_smtp_cf" ] && ver=$(sed -n 's/^DZ\([0-9][0-9.]*\).*/\1/p' "$_smtp_cf" 2>/dev/null | head -1)
              evd "SRV-007" "sendmail -d0.1 </dev/null 2>&1; _smtp_cf_show '^DZ'" ;;
    exim) ver=$( { exim -bV 2>/dev/null || exim4 -bV 2>/dev/null; } | grep -oE 'version [0-9]+\.[0-9]+(\.[0-9]+)?' | head -1 | awk '{print $2}'); evd "SRV-007" "exim -bV 2>&1; exim4 -bV 2>&1" ;;
    *) evd "SRV-007" "echo 'MTA 종류 미식별'" ;;
    esac
    # 평가기준 판단방법 최소 버전: Sendmail 8.14.9 / Postfix 2.5.13·2.6.10·2.7.4·2.8.3 / Exim 4.94.2 — 미만이면 알려진 취약점 미패치
    local min=""
    case "$_smtp_type" in
    sendmail) min="8.14.9" ;;
    exim) min="4.94.2" ;;
    postfix) case "$ver" in 2.5.*) min="2.5.13" ;; 2.6.*) min="2.6.10" ;; 2.7.*) min="2.7.4" ;; 2.8.*) min="2.8.3" ;; [01].*|2.[0-4].*) min="2.5.13" ;; esac ;;
    esac
    if [ -z "$ver" ]; then result "SRV-007|점검불가|${_smtp_type:-SMTP} 버전을 확인하지 못함 (sendmail -d0.1·postconf·exim -bV 실패) - 보안 패치 수준 확인 불가"
    elif [ -n "$min" ] && _ver_lt "$ver" "$min"; then result "SRV-007|취약|${_smtp_type} ${ver} - 평가기준 최소 버전 ${min} 미만 (보안 패치 미적용)"
    else result "SRV-007|수동확인|${_smtp_type} 버전=${ver}${min:+ (평가기준 최소 ${min} 이상)} - 최신 버전·내부 패치 절차 확인"; fi
}

# ================================================================
# SRV-008: SMTP DoS 방지
# ================================================================
check_SRV008() {
    _smtp_gate SRV-008 || return
    _detect_smtp
    evd "SRV-008" "postconf message_size_limit header_size_limit default_process_limit local_destination_concurrency_limit smtpd_recipient_limit 2>&1; _smtp_cf_show 'MaxDaemonChildren|ConnectionRateThrottle|MinFreeBlocks|MaxHeadersLength|MaxMessageSize'"
    case "$_smtp_type" in
    postfix)
        command -v postconf >/dev/null 2>&1 || { result "SRV-008|점검불가|postfix 실행 중이나 postconf 명령을 찾지 못함"; return; }
        # 평가기준: 5개 파라미터는 기본값이 있어 미설정도 양호, 0(해제) 이면 취약
        local p z=""
        for p in message_size_limit header_size_limit default_process_limit local_destination_concurrency_limit smtpd_recipient_limit; do
            [ "$(postconf -h $p 2>/dev/null)" = "0" ] && z="${z} ${p}=0"
        done
        [ -n "$z" ] && result "SRV-008|취약|postfix 제한 해제(0):${z}" || result "SRV-008|양호|postfix DoS 제한 파라미터 기본값/설정값 유지 (0 해제 없음)" ;;
    sendmail)
        [ -f "$_smtp_cf" ] || { result "SRV-008|점검불가|sendmail 설정 파일(sendmail.cf)을 찾지 못함"; return; }
        local p miss=""
        for p in MaxDaemonChildren ConnectionRateThrottle MinFreeBlocks MaxHeadersLength MaxMessageSize; do
            grep -qiE "^[[:space:]]*O[[:space:]]+${p}[[:space:]]*=" "$_smtp_cf" 2>/dev/null || miss="${miss} ${p}"
        done
        [ -n "$miss" ] && result "SRV-008|취약|sendmail DoS 방지 파라미터 미설정:${miss}" || result "SRV-008|양호|sendmail DoS 방지 파라미터 5종 설정" ;;
    *) result "SRV-008|수동확인|${_smtp_type:-SMTP} DoS 방지 설정 수동 확인" ;;
    esac
}

# ================================================================
# SRV-009: SMTP 릴레이 제한
# ================================================================
check_SRV009() {
    _smtp_gate SRV-009 || return
    _detect_smtp
    local mc=""; [ -f /etc/mail/sendmail.mc ] && mc="/etc/mail/sendmail.mc"
    evd "SRV-009" "postconf smtpd_relay_restrictions smtpd_recipient_restrictions mynetworks 2>&1; _smtp_cf_show 'promiscuous_relay|relay_entire_domain|relay_local_from|^[[:space:]]*V[0-9]'; ${mc:+grep -iE 'promiscuous_relay|relay_entire_domain|relay_local_from' $mc 2>&1}"
    case "$_smtp_type" in
    postfix)
        command -v postconf >/dev/null 2>&1 || { result "SRV-009|점검불가|postfix 실행 중이나 postconf 명령을 찾지 못함"; return; }
        local mn rr; mn=$(postconf -h mynetworks 2>/dev/null); rr=$(postconf -h smtpd_relay_restrictions 2>/dev/null)
        if echo "$mn $rr" | grep -qE '0\.0\.0\.0/0|static:all|(^|[^[:alnum:]_])permit[[:space:]]*(,|$)'; then result "SRV-009|취약|postfix 릴레이 전체 허용 (mynetworks=${mn})"
        else result "SRV-009|양호|postfix 릴레이 제한 (relay_restrictions=${rr:-기본 reject_unauth_destination})"; fi ;;
    sendmail)
        [ -f "$_smtp_cf" ] || { result "SRV-009|점검불가|sendmail 설정 파일(sendmail.cf)을 찾지 못함"; return; }
        # 평가기준: 8.9 이상은 promiscuous_relay 비활성(기본)이면 양호, 8.9 미만은 access 파일 접근통제
        local ver; ver=$(sendmail -d0.1 -bv root 2>/dev/null | grep -oE 'Version [0-9]+\.[0-9]+' | awk '{print $2}' | head -1)
        [ -z "$ver" ] && ver=$(sed -n 's/^DZ\([0-9]*\.[0-9]*\).*/\1/p' "$_smtp_cf" 2>/dev/null | head -1)   # sendmail.cf 버전 매크로
        if { grep -vE '^[[:space:]]*#' "$_smtp_cf"; [ -n "$mc" ] && grep -vE '^[[:space:]]*dnl' "$mc"; } 2>/dev/null | grep -qiE 'promiscuous_relay|relay_entire_domain'; then result "SRV-009|취약|sendmail promiscuous_relay/relay_entire_domain 설정"
        elif [ -n "$ver" ] && { [ "${ver%%.*}" -gt 8 ] || { [ "${ver%%.*}" -eq 8 ] && [ "${ver#*.}" -ge 9 ]; }; } 2>/dev/null; then result "SRV-009|양호|sendmail ${ver} (8.9 이상 기본 릴레이 차단)"
        elif [ -z "$ver" ]; then result "SRV-009|점검불가|sendmail 버전을 확인하지 못함 (sendmail -d0.1 -bv·DZ 매크로 실패) - 릴레이 기본 차단 여부 확인 불가"
        elif [ -f /etc/mail/access ]; then result "SRV-009|수동확인|sendmail ${ver} - /etc/mail/access 릴레이 접근통제 확인"
        else result "SRV-009|취약|sendmail ${ver} (8.9 미만) - access 접근통제 파일 없음"; fi ;;
    *) result "SRV-009|수동확인|${_smtp_type:-SMTP} 릴레이 제한 수동 확인" ;;
    esac
}

# ================================================================
# SRV-010: SMTP 일반사용자 실행 방지
# ================================================================
check_SRV010() {
    _smtp_gate SRV-010 || return
    _detect_smtp
    evd "SRV-010" "ls -lL \$(postconf -h command_directory 2>/dev/null)/postsuper /usr/sbin/postsuper /usr/sbin/exim /usr/sbin/exim4 2>&1; _smtp_cf_show '^[[:space:]]*O[[:space:]]+PrivacyOptions'"
    case "$_smtp_type" in
    postfix)
        # 평가기준: postsuper 실행 파일 others 실행 권한 → 일반 사용자 queue 처리 가능
        local ps; ps="$(postconf -h command_directory 2>/dev/null)/postsuper"; [ -f "$ps" ] || ps=/usr/sbin/postsuper
        if [ ! -f "$ps" ]; then result "SRV-010|점검불가|postsuper 실행 파일을 찾지 못함"
        else local p; p=$(get_perm "$ps"); [ $(( ${p: -1} & 1 )) -ne 0 ] && result "SRV-010|취약|${ps} others 실행 권한 (${p})" || result "SRV-010|양호|${ps} others 실행 권한 없음 (${p})"; fi ;;
    sendmail)
        [ -f "$_smtp_cf" ] || { result "SRV-010|점검불가|sendmail 설정 파일(sendmail.cf)을 찾지 못함"; return; }
        grep -iE '^[[:space:]]*O[[:space:]]+PrivacyOptions' "$_smtp_cf" 2>/dev/null | grep -qi "restrictqrun" && \
            result "SRV-010|양호|sendmail PrivacyOptions restrictqrun 설정" || \
            result "SRV-010|취약|sendmail restrictqrun 미설정" ;;
    exim)
        local ex p; ex=$(command -v exim exim4 2>/dev/null | head -1); p=$(get_perm "$ex")
        if [ -z "$ex" ] || [ -z "$p" ]; then result "SRV-010|점검불가|exim 실행 파일 또는 권한을 확인하지 못함"
        elif [ $(( ${p: -1} & 1 )) -ne 0 ]; then result "SRV-010|취약|${ex} others 실행 권한 (${p})"
        else result "SRV-010|양호|exim others 실행 권한 없음 (${p})"; fi ;;
    *) result "SRV-010|수동확인|${_smtp_type:-SMTP} 일반사용자 실행 방지 수동 확인" ;;
    esac
}

# ================================================================
# SRV-012: .netrc 파일 점검
# ================================================================
check_SRV012() {
    # 평가기준: .netrc 내부에 아이디·패스워드 등 민감 정보 (전 계정 홈)
    local homes f found="" sens="" files="" na
    homes=$(awk -F: '$6!=""{print $6}' /etc/passwd 2>/dev/null | sort -u)
    files=$(for h in $homes /root; do [ -d "$h" ] && echo "${h%/}/.netrc"; done | sort -u | tr '\n' ' ')   # 홈 디렉터리가 있는 계정만 (/nonexistent 등 제외)
    evd "SRV-012" "_ls_exist $files; _netrc_show $files"
    for f in $files; do
        [ -f "$f" ] || continue
        found="${found} ${f}"
        grep -qiE '(^|[^[:alnum:]_])(login|password)([^[:alnum:]_]|$)' "$f" 2>/dev/null && sens="${sens} ${f}"
    done
    na=$(_noaccess_homes | tr '\n' ' ')
    if [ -n "$sens" ]; then result "SRV-012|취약|.netrc 에 계정·비밀번호 정보:${sens}"
    elif [ -n "$found" ]; then result "SRV-012|수동확인|.netrc 파일 존재(login/password 미발견):${found} - 내용 확인"
    elif [ -n "$(echo $na)" ]; then result "SRV-012|점검불가|열람 권한 없는 홈 디렉터리의 .netrc 확인 불가: ${na}(root 로 재점검 필요)"
    else result "SRV-012|양호|.netrc 파일 미존재"; fi
}

# ================================================================
# SRV-021: FTP 접근통제
# ================================================================
check_SRV021() {
    _ftp_running || { evd "SRV-021" "_svc_state vsftpd proftpd pure-ftpd in.ftpd ftpd; _listen_all"; result "SRV-021|N-A|FTP 서비스 미실행"; return; }
    evd "SRV-021" "_show_cfg /etc/vsftpd.conf /etc/vsftpd/vsftpd.conf /etc/hosts.allow /etc/hosts.deny /etc/ftpaccess.ctl /etc/ftpd/ftphosts; grep -iA3 '<Limit LOGIN>' /etc/proftpd/proftpd.conf /etc/proftpd.conf 2>&1"
    # 평가기준: 특정 IP/호스트에서만 접속하도록 접근제어
    local conf tw hw
    conf=$(ls /etc/vsftpd.conf /etc/vsftpd/vsftpd.conf 2>/dev/null | head -1)
    if [ -n "$conf" ]; then
        tw=$(grep -iE "^[[:space:]]*tcp_wrappers" "$conf" 2>/dev/null | tail -1 | cut -d= -f2 | tr -d ' ')
        hw=$(_cfg /etc/hosts.allow /etc/hosts.deny | grep -iE 'vsftpd|^[[:space:]]*ALL[[:space:]]*:' | head -2)
        [ "$(_uc "$tw")" = "YES" ] && [ -n "$hw" ] && { result "SRV-021|양호|vsftpd tcp_wrappers=YES + hosts.allow/deny 규칙"; return; }
    fi
    # proftpd: <Limit LOGIN> 에서 특정 주소만 Allow ('Allow from all' 은 제한 아님)
    for f in /etc/proftpd/proftpd.conf /etc/proftpd.conf; do
        [ -f "$f" ] || continue
        _cfg "$f" | grep -iA6 "<Limit LOGIN>" | grep -iE "Allow[[:space:]]+from" | grep -viE "Allow[[:space:]]+from[[:space:]]+all" | grep -q . && { result "SRV-021|양호|proftpd <Limit LOGIN> 접근 IP 제한 (${f})"; return; }
    done
    # 평가기준 판단방법(UNIX): AIX /etc/ftpaccess.ctl, HP-UX /etc/ftpd/ftphosts·ftpaccess, SOL /etc/ftpd/ftpaccess
    grep -qiE '^[[:space:]]*(allow|deny)[[:space:]]*:' /etc/ftpaccess.ctl 2>/dev/null && { result "SRV-021|양호|AIX /etc/ftpaccess.ctl allow/deny 설정"; return; }
    grep -qiE '^[[:space:]]*(allow|deny)[[:space:]]' /etc/ftpd/ftphosts 2>/dev/null && { result "SRV-021|양호|/etc/ftpd/ftphosts allow/deny 설정"; return; }
    result "SRV-021|수동확인|FTP 접근 IP 제한(tcp_wrappers 규칙·방화벽) 수동 확인 (vsftpd tcp_wrappers=${tw:-미설정})"
}

# ================================================================
# SRV-037: 취약한 FTP 서비스 비활성화 (FTPS 등 암호화 적용 시 양호)
# ================================================================
check_SRV037() {
    # 평가기준: FTP 서비스 활성 시 취약 (FTPS 등 통신 암호화 적용 시 양호)
    evd "SRV-037" "_svc_state vsftpd proftpd pure-ftpd in.ftpd ftpd; _listen_all; _show_cfg /etc/vsftpd.conf /etc/vsftpd/vsftpd.conf /etc/proftpd/proftpd.conf /etc/proftpd/tls.conf"
    _ftp_running || { result "SRV-037|양호|FTP 서비스 비활성"; return; }
    local conf
    conf=$(ls /etc/vsftpd.conf /etc/vsftpd/vsftpd.conf 2>/dev/null | head -1)
    if [ -n "$conf" ] && is_running vsftpd; then
        if grep -qiE '^[[:space:]]*ssl_enable[[:space:]]*=[[:space:]]*YES' "$conf" && ! grep -qiE '^[[:space:]]*force_local_logins_ssl[[:space:]]*=[[:space:]]*NO' "$conf"; then result "SRV-037|양호|vsftpd FTPS(ssl_enable=YES) 적용"
        else result "SRV-037|취약|vsftpd 평문 FTP 서비스 활성 (ssl_enable 미설정 또는 SSL 로그인 강제 해제)"; fi
    elif is_running proftpd; then
        if grep -hiE '^[[:space:]]*TLSEngine[[:space:]]+on' /etc/proftpd/proftpd.conf /etc/proftpd/tls.conf 2>/dev/null | grep -q . && grep -hiE '^[[:space:]]*TLSRequired[[:space:]]+on' /etc/proftpd/proftpd.conf /etc/proftpd/tls.conf 2>/dev/null | grep -q .; then
            result "SRV-037|양호|proftpd TLSEngine on + TLSRequired on"
        else result "SRV-037|취약|proftpd 평문 FTP 허용 (TLSRequired 미설정)"; fi
    elif is_running vsftpd; then result "SRV-037|점검불가|vsftpd 가 실행 중이나 vsftpd.conf 를 찾지 못해 FTPS(ssl_enable) 적용 여부 확인 불가"
    else result "SRV-037|점검불가|FTP 서비스 활성이나 지원하는 FTP 데몬(vsftpd·proftpd)이 아니어서 FTPS 적용 여부 자동 확인 불가 - 수동 확인 필요"; fi
}

# ================================================================
# SRV-082: 시스템 주요 디렉터리 권한
# ================================================================
check_SRV082() {
    # 평가기준: /usr /bin /sbin /etc /var 에 others 쓰기 권한이 있으면 취약
    evd "SRV-082" "ls -alLd /usr /bin /sbin /etc /var 2>&1"
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
    local vuln="" f p d list="" unres="" cnt=0
    list=$( { for d in /etc/init.d /etc/rc.d/init.d /etc/rc.d/rc2.d /etc/rc.d/rc3.d /etc/rc2.d /etc/rc3.d /sbin/init.d /sbin/rc2.d /sbin/rc3.d; do [ -d "$d" ] && ls -1 "$d" 2>/dev/null | sed "s#^#$d/#"; done; ls /etc/rc.local /etc/systemd/system/*.service /usr/lib/systemd/system/*.service /lib/systemd/system/*.service 2>/dev/null; } | sort -u)
    _SU_LIST="$list"
    evd "SRV-083" "echo '# 점검 대상 스타트업 스크립트: 권한 소유자 경로'; printf '%s\\n' \"\$_SU_LIST\" | while IFS= read -r f; do [ -n \"\$f\" ] && echo \"\$(get_perm \"\$f\") \$(get_owner \"\$f\") \$f\"; done"
    while IFS= read -r f; do
        [ -n "$f" ] || continue
        [ -f "$f" ] || continue
        cnt=$((cnt+1))
        p=$(get_perm "$f")
        [ -z "$p" ] && { unres="${unres} ${f}"; continue; }   # 대상이 없는 심볼릭 링크 등
        [ $(( ${p: -1} & 2 )) -ne 0 ] && vuln="${vuln} ${f}(${p}, 소유자=$(get_owner "$f"))"
    done <<EOF
$list
EOF
    if [ -n "$vuln" ]; then result "SRV-083|취약|others 쓰기 가능 스타트업 스크립트:${vuln}"
    else result "SRV-083|양호|스타트업 스크립트 ${cnt}개 others 쓰기 권한 없음${unres:+ (권한 조회 불가 링크 $(echo $unres | wc -w)건 제외)}"; fi
}

# ================================================================
# SRV-094: Crontab 참조 파일 권한
# ================================================================
check_SRV094() {
    # 평가기준: crontab 에서 실행하는 참조 파일에 others 쓰기 권한이 있으면 취약
    local sysf="/etc/crontab $(ls /etc/cron.d/* 2>/dev/null | tr '\n' ' ')" usrf="" d f refs p vuln="" n na=""
    for d in /var/spool/cron/crontabs /var/spool/cron; do
        [ -d "$d" ] || continue
        [ -r "$d" ] && [ -x "$d" ] || { na="${d} 열람 권한 없음"; continue; }
        usrf="${usrf} $(ls "$d"/* 2>/dev/null | tr '\n' ' ')"
    done
    refs=$( {
        for f in $sysf; do [ -f "$f" ] && _cfg "$f" | grep -vE '^[[:space:]]*[A-Za-z_]+=' | awk '{s=7; if ($1 ~ /^@/) s=3; for(i=s;i<=NF;i++) print $i}'; done
        for f in $usrf; do [ -f "$f" ] && _cfg "$f" | grep -vE '^[[:space:]]*[A-Za-z_]+=' | awk '{s=6; if ($1 ~ /^@/) s=2; for(i=s;i<=NF;i++) print $i}'; done
        ls /etc/cron.hourly/* /etc/cron.daily/* /etc/cron.weekly/* /etc/cron.monthly/* 2>/dev/null
    } | sed 's/^[<>;|&("'"'"']*//; s/[;|&)"'"'"']*$//' | grep -E '^/' | sort -u)
    evd "SRV-094" "_show_cfg $sysf $usrf"
    evd "SRV-094" "echo '# 참조 파일 (권한 소유자 경로)'; _pstat $(echo $refs)"
    for f in $refs; do
        [ -f "$f" ] || continue
        p=$(get_perm "$f"); p=${p: -1}
        [ -n "$p" ] && [ $(( p & 2 )) -ne 0 ] 2>/dev/null && vuln="${vuln} ${f}"
    done
    n=$(echo "$refs" | grep -c .)
    if [ -n "$vuln" ]; then result "SRV-094|취약|crontab 참조파일 others 쓰기 권한:${vuln}"
    elif [ -n "$na" ]; then result "SRV-094|점검불가|${na} - 사용자 crontab 참조 파일 확인 불가 (root 로 재점검 필요)"
    else result "SRV-094|양호|crontab 참조파일 ${n}개 others 쓰기 권한 없음"; fi
}

# ================================================================
# SRV-095: 소유자/그룹 없는 파일
# ================================================================
check_SRV095() {
    local found _rc cnt
    found=$(_to 60 find / $_FP \( -nouser -o -nogroup \) ! -path "/proc/*" ! -path "/sys/*" ! -path "/dev/*" ! -path "/run/*" ! -path "/var/lib/docker/*" ! -path "/var/lib/containers/*" -print 2>/dev/null); _rc=$?
    cnt=$(printf '%s' "$found" | grep -c .)
    _NOUSER_LIST="$found"
    evd "SRV-095" "echo '# find / ( -nouser -o -nogroup ) 종료코드=${_rc} (124=60초 시간 초과), 발견 ${cnt}개'; printf '%s\\n' \"\$_NOUSER_LIST\""
    if [ "$cnt" -gt 0 ]; then
        result "SRV-095|취약|소유자/그룹 없는 파일 ${cnt}개: $(echo "$found" | _sum 5)"
    elif [ "$_rc" = "124" ]; then
        result "SRV-095|점검불가|파일 검색 시간 초과(60초) - 소유자 없는 파일 확인 불가"
    else
        result "SRV-095|양호|소유자/그룹 없는 파일 없음"
    fi
}

# ================================================================
# SRV-096: 사용자 환경변수 파일 권한
# ================================================================
check_SRV096() {
    # 평가기준: 사용자 환경 파일에 others 권한(읽기/쓰기/실행)이 하나라도 있으면 취약
    # 판단: 배포판 기본 환경파일은 644(others 읽기)이므로 others 쓰기 권한 또는 소유자(해당 계정·root 외) 이상만 취약, others 읽기만 있으면 근거에 표시하고 양호
    local vuln="" ro="" gw="" user uid homedir sh df p o n=0 nf=0 hd
    local fl=".profile .login .bash_profile .bash_login .bashrc .kshrc .cshrc .zshrc .zprofile .zshenv .bash_logout"
    evd "SRV-096" "echo '# 로그인 가능 계정 환경파일: 권한 소유자 경로'; awk -F: '\$7!~/(nologin|false|sync|shutdown|halt)\$/ && \$6!=\"\" {print \$1\":\"\$6}' /etc/passwd | while IFS=: read -r u h; do h=\${h%/}; for f in $fl; do _pstat \"\$h/\$f\"; done; done"
    while IFS=: read -r user _ uid _ _ homedir sh; do
        case "$sh" in *nologin|*false|*/sync|*/shutdown|*/halt) continue ;; esac
        [ -z "$homedir" ] && continue
        [ "$homedir" = "/" ] && [ "$user" != "root" ] && continue
        [ -d "$homedir" ] || continue
        n=$((n+1)); hd="${homedir%/}"
        for df in $fl; do
            df="$hd/$df"
            [ -f "$df" ] || continue
            nf=$((nf+1))
            p=$(get_perm "$df"); o=$(get_owner "$df")
            [ $(( ${p: -1} & 2 )) -ne 0 ] 2>/dev/null && vuln="${vuln} ${df}(others 쓰기:${p})"
            [ $(( ${p: -1} & 1 )) -ne 0 ] 2>/dev/null && vuln="${vuln} ${df}(others 실행:${p})"
            [ $(( ${p: -1} & 4 )) -ne 0 ] 2>/dev/null && ro="${ro} ${df}(${p})"
            [ $(( ${p: -2:1} & 2 )) -ne 0 ] 2>/dev/null && gw="${gw} ${df}(${p})"
            [ "$o" != "$user" ] && [ "$o" != "root" ] && vuln="${vuln} ${df}(소유자=${o})"
        done
    done < /etc/passwd
    local na; na=$(_noaccess_homes | tr '\n' ' ')
    local note=""
    [ -n "$ro" ] && note=" [참고: others 읽기만 있는 파일 $(echo $ro | wc -w)건(배포판 기본 644) - 쓰기 권한 없어 양호 처리]"
    [ -n "$gw" ] && note="${note} [참고: group 쓰기 $(echo $gw | wc -w)건]"
    if [ -n "$vuln" ]; then result "SRV-096|취약|사용자 환경파일 others 쓰기/실행 권한 또는 소유자 이상:${vuln}${note}"
    elif [ -n "$(echo $na)" ]; then result "SRV-096|점검불가|열람 권한 없는 홈 디렉터리의 환경파일 확인 불가: ${na}(root 로 재점검 필요)${note}"
    else result "SRV-096|양호|환경파일 ${nf}개(계정 ${n}개) others 쓰기·실행 권한 및 소유자 이상 없음${note}"; fi
}

# ================================================================
# SRV-112: Cron 로깅 설정
# ================================================================
check_SRV112() {
    local rf="/etc/rsyslog.conf $(ls /etc/rsyslog.d/*.conf 2>/dev/null | tr '\n' ' ') /etc/syslog.conf"
    evd "SRV-112" "_show_cfg $rf /etc/default/cron; ls -l /var/log/cron /var/log/cron.log /var/adm/cron/log 2>&1; _svc_state rsyslog syslogd systemd-journald"
    local rules u found="" explicit catch
    u=$(_unreadable $rf) && { result "SRV-112|점검불가|syslog 설정 읽기 권한 없음: ${u}"; return; }
    rules=$(_cfg $rf)
    # (a) cron 전용 규칙 (cron.none 제외)  (b) cron 을 제외하지 않는 포괄 규칙(*.*, *.info 등)이 파일에 기록
    explicit=$(echo "$rules" | grep -iE '(^|[;,[:space:]])cron\.[^n[:space:]][^[:space:]]*[[:space:]]+-?[/@]|^[[:space:]]*cron\.[^n[:space:]]')
    catch=$(echo "$rules" | grep -E '^[[:space:]]*\*\.(\*|debug|info|notice)[^[:space:]]*[[:space:]]+-?/' | grep -vi 'cron\.none')
    [ -n "$explicit" ] && found="cron 전용 규칙"
    [ -z "$found" ] && [ -n "$catch" ] && found="포괄 규칙(*.* 등)으로 cron 로그 기록"
    [ "$OS_FAMILY" = "AIX" ] || [ "$OS_FAMILY" = "HPUX" ] && [ -f /var/adm/cron/log ] && found="${found:-cron 자체 로그 /var/adm/cron/log}"
    [ "$OS_FAMILY" = "SOLARIS" ] && grep -q '^CRONLOG=YES' /etc/default/cron 2>/dev/null && found="CRONLOG=YES"
    [ -z "$found" ] && is_running systemd-journald && ! is_running rsyslog && [ -d /var/log/journal ] && found="journald 영구 저장(syslog 데몬 없음)"
    [ -n "$found" ] && result "SRV-112|양호|cron 로그 기록 설정 (${found})" || \
        result "SRV-112|취약|cron 로그 기록 미설정 (cron 전용 규칙·포괄 규칙·CRONLOG 모두 없음)"
}

# ================================================================
# SRV-115: 로그 검토/보고
# ================================================================
check_SRV115() {
    evd "SRV-115" "ls -la /var/log/messages /var/log/secure /var/log/auth.log /var/log/syslog 2>&1"
    evd "SRV-115" "last -5 2>&1"
    result "SRV-115|수동확인|로그 검토 수행 여부 수동 확인"
}

# ================================================================
# SRV-134: 스택 실행 방지
# ================================================================
check_SRV134() {
    case "$OS_FAMILY" in
    SOLARIS)
        evd "SRV-134" "grep noexec_user_stack /etc/system 2>&1; sxadm status nxstack 2>&1"
        if [ "${OS_MAJOR:-10}" -ge 11 ] 2>/dev/null && sxadm status nxstack 2>/dev/null | grep -qi "enabled"; then result "SRV-134|양호|Solaris 11 sxadm nxstack enabled"
        elif grep -qE '^[[:space:]]*set[[:space:]]+noexec_user_stack[[:space:]]*=[[:space:]]*1' /etc/system 2>/dev/null; then result "SRV-134|양호|/etc/system noexec_user_stack=1"
        else result "SRV-134|취약|스택 실행 방지 미설정 (noexec_user_stack / sxadm nxstack)"; fi ;;
    *)
        evd "SRV-134" "grep -o -m1 -w nx /proc/cpuinfo 2>&1; uname -s"
        result "SRV-134|N-A|평가대상 아님 (Solaris 전용 스택 실행 방지 항목)" ;;
    esac
}

# ================================================================
# SRV-135: TCP 보안 설정
# ================================================================
check_SRV135() {
    case "$OS_FAMILY" in
    SOLARIS)
        # 평가기준(Solaris): TCP_STRONG_ISS=2 양호, 0/1 취약
        evd "SRV-135" "grep TCP_STRONG_ISS /etc/default/inetinit 2>&1; ipadm show-prop -p _strong_iss tcp 2>&1"
        local v; v=$(grep -E '^[[:space:]]*TCP_STRONG_ISS' /etc/default/inetinit 2>/dev/null | cut -d= -f2 | tr -d ' ')
        [ -z "$v" ] && v=$(ipadm show-prop -p _strong_iss -co current tcp 2>/dev/null)
        case "$v" in 2) result "SRV-135|양호|TCP_STRONG_ISS=2" ;; 0|1) result "SRV-135|취약|TCP_STRONG_ISS=${v} (2 필요)" ;; *) result "SRV-135|점검불가|TCP_STRONG_ISS 값을 확인하지 못함 (inetinit·ipadm 조회 실패)" ;; esac ;;
    *)
        evd "SRV-135" "uname -s"
        result "SRV-135|N-A|평가대상 아님 (Solaris 전용 TCP_STRONG_ISS)" ;;
    esac
}

# ================================================================
# SRV-147: 네트워크 모니터링 서비스
# ================================================================
check_SRV147() {
    # 평가기준: 불필요한 네트워크 모니터링 서비스가 '실행 중'이면 취약 — 스니핑 도구(tcpdump 등) 실행은 취약, SNMP(snmpd)는 SRV-001·003 에서 버전·접근통제를 점검하므로 여기서는 업무상 필요 여부 확인(수동확인)
    evd "SRV-147" "_svc_state snmpd tcpdump tshark wireshark nmap dumpcap; command -v tcpdump tshark wireshark nmap 2>&1"
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
    evd "SRV-164" "echo '# 구성원 목록이 빈 그룹(그룹:GID)'; awk -F: '\$4==\"\"{print \$1\":\"\$3}' /etc/group 2>&1; echo '# 계정이 기본 그룹으로 쓰는 GID'; awk -F: '{print \$4}' /etc/passwd | sort -un | tr '\n' ' '"
    local umin; umin=$(awk '/^[[:space:]]*GID_MIN/{print $2}' /etc/login.defs 2>/dev/null)
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
    # 평가기준: 불필요한 숨김 파일 또는 디렉터리 — 로그인 가능 계정 홈의 최상위 숨김 항목 중 환경 표준 파일 외를 목록화
    local h list="" l all="" n=0
    for h in $(awk -F: '$7!~/(nologin|false|sync|shutdown|halt)$/ && $6!="" && $6!="/" {print $6}' /etc/passwd 2>/dev/null | sort -u) /root; do
        [ -d "$h" ] && [ -r "$h" ] && [ -x "$h" ] || continue
        n=$((n+1))
        l=$(find "$h/." ! -name . -prune -name '.*' ! -name '.bashrc' ! -name '.bash_profile' ! -name '.bash_login' ! -name '.profile' ! -name '.bash_logout' ! -name '.ssh' ! -name '.bash_history' ! -name '.cache' ! -name '.config' ! -name '.local' ! -name '.viminfo' ! -name '.lesshst' ! -name '.sudo_as_admin_successful' ! -name '.selected_editor' ! -name '.gnupg' ! -name '.zshrc' ! -name '.kshrc' ! -name '.cshrc' ! -name '.login' ! -name '.sh_history' ! -name '.wget-hsts' ! -name '.python_history' 2>/dev/null | sed 's#/\./#/#')
        [ -n "$l" ] && list="${list}${l}
"
    done
    list=$(printf '%s' "$list" | sort -u | grep -v '^$')
    _HIDDEN_LIST="$list"
    local na; na=$(_noaccess_homes | tr '\n' ' ')
    evd "SRV-166" "echo '# 점검한 홈 디렉터리 ${n}개, 표준 환경 파일 외 숨김 항목 $(printf '%s\n' "$list" | grep -c .)개 (열람 불가 홈: ${na:-없음})'; printf '%s\\n' \"\$_HIDDEN_LIST\""
    if [ -n "$list" ]; then result "SRV-166|수동확인|표준 환경 파일 외 숨김 파일/디렉터리 $(echo "$list" | grep -c .)건: $(echo "$list" | _sum 5) - 불필요 여부 확인"
    elif [ -n "$(echo $na)" ]; then result "SRV-166|점검불가|열람 권한 없는 홈 디렉터리 확인 불가: ${na}(root 로 재점검 필요)"
    else result "SRV-166|양호|홈 디렉터리 ${n}개에 표준 환경 파일 외 숨김 항목 없음"; fi
}

# ================================================================
# SRV-170: SMTP 정보 노출
# ================================================================
check_SRV170() {
    _smtp_gate SRV-170 || return
    _detect_smtp
    evd "SRV-170" "postconf smtpd_banner 2>&1; _smtp_cf_show 'SmtpGreetingMessage'; exim -bP smtp_banner 2>&1"
    case "$_smtp_type" in
    postfix)
        command -v postconf >/dev/null 2>&1 || { result "SRV-170|점검불가|postfix 실행 중이나 postconf 명령을 찾지 못함"; return; }
        local ban; ban=$(postconf -h smtpd_banner 2>/dev/null)
        [ -z "$ban" ] && { result "SRV-170|점검불가|postconf smtpd_banner 조회 결과 없음"; return; }
        echo "$ban" | grep -qiE 'mail_version|version|[0-9]+\.[0-9]+' && result "SRV-170|취약|postfix 배너에 버전 정보 노출: ${ban}" || result "SRV-170|양호|SMTP 배너 버전 정보 노출 없음 (${ban})" ;;
    sendmail)
        [ -f "$_smtp_cf" ] || { result "SRV-170|점검불가|sendmail 설정 파일(sendmail.cf)을 찾지 못함"; return; }
        # 평가기준: SmtpGreetingMessage 에 $v 포함 시 버전 노출 — 미설정 시 기본값('$j Sendmail $v/$Z; $b')도 노출
        local greet; greet=$(grep -iE "^[[:space:]]*O[[:space:]]+SmtpGreetingMessage" "$_smtp_cf" 2>/dev/null | tail -1)
        if [ -z "$greet" ]; then result "SRV-170|취약|SmtpGreetingMessage 미설정 (기본 인사말에 버전 \$v 포함)"
        elif echo "$greet" | grep -qE '\$v|\$Z'; then result "SRV-170|취약|sendmail 배너에 버전(\$v/\$Z) 노출"
        else result "SRV-170|양호|sendmail 배너 버전 미노출"; fi ;;
    exim)
        local eb; eb=$(exim -bP smtp_banner 2>/dev/null || exim4 -bP smtp_banner 2>/dev/null)
        [ -z "$eb" ] && { result "SRV-170|점검불가|exim -bP smtp_banner 조회 실패"; return; }
        echo "$eb" | grep -q 'version_number' && result "SRV-170|취약|exim smtp_banner 에 \$version_number 포함" || result "SRV-170|양호|exim 배너 버전 미노출" ;;
    *) result "SRV-170|수동확인|${_smtp_type:-SMTP} 배너 정보 수동 확인" ;;
    esac
}

# ================================================================
# SRV-171: FTP 배너 정보 노출
# ================================================================
check_SRV171() {
    _ftp_running || { evd "SRV-171" "_svc_state vsftpd proftpd pure-ftpd in.ftpd ftpd; _listen_all"; result "SRV-171|N-A|FTP 서비스 미실행"; return; }
    local c b bf bt
    c=$(ls /etc/vsftpd.conf /etc/vsftpd/vsftpd.conf 2>/dev/null | head -1)
    bf=$([ -n "$c" ] && grep -iE '^[[:space:]]*banner_file[[:space:]]*=' "$c" 2>/dev/null | tail -1 | cut -d= -f2- | tr -d ' ')
    evd "SRV-171" "_show_cfg ${c:-/etc/vsftpd.conf} /etc/proftpd/proftpd.conf /etc/proftpd.conf /etc/ftpd/ftpaccess; ${bf:+echo \"# banner_file ${bf}\"; cat ${bf} 2>&1}"
    if is_running vsftpd; then
        [ -n "$c" ] || { result "SRV-171|점검불가|vsftpd 가 실행 중이나 vsftpd.conf 를 찾지 못함"; return; }
        b=$(grep -iE '^[[:space:]]*ftpd_banner[[:space:]]*=' "$c" 2>/dev/null | tail -1)
        bt=""; [ -n "$bf" ] && [ -r "$bf" ] && bt=$(cat "$bf" 2>/dev/null)
        if [ -z "$b" ] && [ -z "$bt" ]; then result "SRV-171|취약|vsftpd 배너 미설정 (기본 배너에 vsFTPd 버전 노출)"
        elif echo "${b} ${bt}" | grep -qiE 'vsftpd|[0-9]+\.[0-9]+\.[0-9]+'; then result "SRV-171|취약|vsftpd 배너에 서비스명·버전 노출: ${b:-banner_file ${bf}}"
        else result "SRV-171|양호|vsftpd 배너 설정 (${b:+ftpd_banner}${bt:+ banner_file ${bf}}) 서비스명·버전 미노출"; fi
    elif is_running proftpd; then
        b=$(grep -hiE '^[[:space:]]*ServerIdent' /etc/proftpd/proftpd.conf /etc/proftpd.conf 2>/dev/null | tail -1)
        if echo "$b" | grep -qiE 'ServerIdent[[:space:]]+off|ServerIdent[[:space:]]+on[[:space:]]+"'; then result "SRV-171|양호|proftpd ${b}"
        else result "SRV-171|취약|proftpd ServerIdent 미설정 (기본 'ProFTPD x.y.z Server' 노출)"; fi
    elif [ -f /etc/ftpd/ftpaccess ]; then   # HP-UX·Solaris in.ftpd(wu-ftpd 계열) greeting
        b=$(grep -iE '^[[:space:]]*greeting' /etc/ftpd/ftpaccess 2>/dev/null | awk '{print tolower($2)}' | tail -1)
        case "$b" in
        brief|terse|text) result "SRV-171|양호|ftpaccess greeting ${b} (버전 미노출)" ;;
        full) result "SRV-171|취약|ftpaccess greeting full (서비스명·버전 노출)" ;;
        *) result "SRV-171|수동확인|ftpaccess greeting 미설정 - 접속 배너 서비스명·버전 노출 확인" ;;
        esac
    else
        [ "$OS_FAMILY" = "AIX" ] && evd "SRV-171" "dspcat /usr/lib/nls/msg/\${LANG:-C}/ftpd.cat 2>&1 | grep -i 'ftp server'"
        result "SRV-171|수동확인|FTP 배너 서비스명·버전 노출 수동 확인"; fi
}

# ================================================================
# SRV-173: DNS 동적 업데이트
# ================================================================
check_SRV173() {
    _dns_pre SRV-173 || return
    local au bad
    au=$(echo "$_NC" | _dns_stmt allow-update)
    bad=$(echo "$au" | awk -F'|' '{n=split($2,a," "); for(i=1;i<=n;i++) if (a[i]=="any" || a[i]=="0.0.0.0/0" || a[i]=="::/0") {print $1; break}}')
    if [ -n "$bad" ]; then result "SRV-173|취약|DNS allow-update any 설정됨: $(echo "$bad" | _csv)"
    elif [ -n "$au" ]; then result "SRV-173|양호|DNS 동적 업데이트 대상 제한: $(echo "$au" | sed "s/|/=/" | _sum 8)"
    else result "SRV-173|양호|allow-update 미설정 (동적 업데이트 기본 거부)"; fi
}

# ================================================================
# SRV-174: 불필요 DNS 서비스
# ================================================================
check_SRV174() {
    evd "SRV-174" "_svc_state named dnsmasq"
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
    # 참고용(평가기준 평가항목 아님): shadow 해시 방식 — DES(13자)·MD5 는 취약, 해시가 없는 잠긴 계정은 제외
    evd "SRV-176" "_hash_algs; grep -E '^[[:space:]]*(ENCRYPT_METHOD|MD5_CRYPT_ENAB)' /etc/login.defs 2>&1"
    local u; u=$(_unreadable /etc/shadow) && { result "SRV-176|점검불가|/etc/shadow 읽기 권한 없음"; return; }
    [ -f /etc/shadow ] || { result "SRV-176|점검불가|/etc/shadow 없음"; return; }
    local algo weak
    algo=$(grep -E '^[[:space:]]*ENCRYPT_METHOD' /etc/login.defs 2>/dev/null | awk '{print $2}' | tail -1)
    weak=$(awk -F: '$2!="" && $2!~/^[!*]/ { if ($2 ~ /^\$1\$/) print $1"(MD5)"; else if ($2 !~ /^\$/ && length($2)==13) print $1"(DES)"; else if ($2 !~ /^\$(2|5|6|y|gy)/ && $2 ~ /^\$/) print $1"(기타)" }' /etc/shadow 2>/dev/null)
    case "$algo" in MD5|DES) weak="${weak:+$weak }[ENCRYPT_METHOD=${algo}]" ;; esac
    if [ -n "$weak" ]; then result "SRV-176|취약|취약 해시 사용: ${weak} (기본 algo=${algo:-미설정})"
    elif [ -n "$algo" ]; then result "SRV-176|양호|비밀번호 암호화 방식=${algo}, 취약 해시 계정 없음"
    else result "SRV-176|양호|취약 해시 계정 없음 (ENCRYPT_METHOD 미설정)"; fi
}

# ================================================================
# 참고용 SRV 항목 함수 — 평가기준 평가항목(_GUIDE_SRV 106개) 밖이거나 평가대상 아님(N-A)이라 SRV-RUN 에서 실행하지 않음 (필요 시 직접 호출)
# ================================================================

# SRV-002: 패스워드 복잡성
check_SRV002() {
    evd "SRV-002" "grep -E '^[[:space:]]*(PASS_MIN_LEN|MINLEN)' /etc/login.defs 2>/dev/null; grep -v '^#' $(get_pam_files) 2>/dev/null | grep -iE 'pam_pwquality|pam_cracklib'; cat /etc/security/pwquality.conf 2>/dev/null | grep -v '^#' | grep -v '^[[:space:]]*$'"
    local minlen="" dcredit="" ucredit="" lcredit="" ocredit=""
    for pf in $(get_pam_files); do
        [ -f "$pf" ] || continue
        local ml=$(grep -v '^#' "$pf" 2>/dev/null | grep -oE 'minlen=[0-9]+' | head -1 | cut -d= -f2)
        [ -n "$ml" ] && minlen=$ml
    done
    if [ -f /etc/security/pwquality.conf ]; then
        [ -z "$minlen" ] && minlen=$(grep -E '^[[:space:]]*minlen' /etc/security/pwquality.conf 2>/dev/null | grep -oE '[0-9]+' | head -1)
        dcredit=$(grep -E '^[[:space:]]*dcredit' /etc/security/pwquality.conf 2>/dev/null | grep -oE '[-0-9]+' | head -1)
        ucredit=$(grep -E '^[[:space:]]*ucredit' /etc/security/pwquality.conf 2>/dev/null | grep -oE '[-0-9]+' | head -1)
        lcredit=$(grep -E '^[[:space:]]*lcredit' /etc/security/pwquality.conf 2>/dev/null | grep -oE '[-0-9]+' | head -1)
        ocredit=$(grep -E '^[[:space:]]*ocredit' /etc/security/pwquality.conf 2>/dev/null | grep -oE '[-0-9]+' | head -1)
    fi
    [ -z "$minlen" ] && minlen=$(grep -E '^[[:space:]]*PASS_MIN_LEN' /etc/login.defs 2>/dev/null | awk '{print $2}' | tail -1)
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
        local wg=$(grep -v "^#" /etc/pam.d/su 2>/dev/null | grep -i "pam_wheel" | grep -oE 'group=[^[:space:]]+' | cut -d= -f2 | head -1)
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
    evd "SRV-023" "cat /etc/hosts.allow 2>/dev/null | grep -v '^#' | grep -v '^[[:space:]]*$'; echo '---'; cat /etc/hosts.deny 2>/dev/null | grep -v '^#' | grep -v '^[[:space:]]*$'; echo '---'; iptables -L -n 2>/dev/null | head -20; firewall-cmd --list-all 2>/dev/null"
    local ctrl=0
    [ -f /etc/hosts.deny ] && grep -qv "^#" /etc/hosts.deny 2>/dev/null && grep -qiE "ALL.*ALL|sshd" /etc/hosts.deny 2>/dev/null && ctrl=1
    iptables -L -n 2>/dev/null | grep -qiE "ACCEPT|DROP|REJECT" && ctrl=1
    firewall-cmd --state 2>/dev/null | grep -q "running" && ctrl=1
    [ $ctrl -eq 1 ] && result "SRV-023|수동확인|접근통제 설정 존재 (위 현황의 규칙 적정성 확인)" || \
        result "SRV-023|취약|TCP Wrapper/방화벽 접근통제 미설정"
}

# SRV-024: 계정 잠금
check_SRV024() {
    evd "SRV-024" "grep -v '^#' $(get_pam_files) 2>/dev/null | grep -iE 'pam_tally2|pam_faillock|faillock'; cat /etc/security/faillock.conf 2>/dev/null | grep -v '^#' | grep -v '^[[:space:]]*$'"
    local lock=0 deny=""
    for pf in $(get_pam_files) /etc/pam.d/system-auth /etc/pam.d/password-auth /etc/pam.d/common-auth; do
        [ -f "$pf" ] || continue
        grep -v "^#" "$pf" 2>/dev/null | grep -qiE "pam_tally2|pam_faillock" && lock=1
        local d=$(grep -v "^#" "$pf" 2>/dev/null | grep -oE 'deny=[0-9]+' | head -1 | cut -d= -f2)
        [ -n "$d" ] && deny=$d
    done
    [ -z "$deny" ] && [ -f /etc/security/faillock.conf ] && deny=$(grep -E '^[[:space:]]*deny' /etc/security/faillock.conf 2>/dev/null | grep -oE '[0-9]+' | head -1)
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
    evd "SRV-039" "grep -iE '^[[:space:]]*(User|Group)' /etc/httpd/conf/httpd.conf /etc/apache2/envvars /etc/apache2/apache2.conf 2>/dev/null | grep -v '^#'; ps aux 2>/dev/null | grep -E 'httpd|apache2|nginx' | head -5"
    local web_running=0
    is_running httpd || is_running apache2 || is_running nginx && web_running=1
    if [ $web_running -eq 0 ]; then
        result "SRV-039|N-A|웹서비스 미실행"; return
    fi
    local web_user=$(ps aux 2>/dev/null | grep -E 'httpd|apache2|nginx' | grep -v grep | grep -v root | awk '{print $1}' | sort -u | head -1)
    if [ "$web_user" = "root" ] || [ -z "$web_user" ]; then
        local cfg_user=$(grep -iE '^[[:space:]]*User[[:space:]]' /etc/httpd/conf/httpd.conf /etc/apache2/apache2.conf 2>/dev/null | grep -v '^#' | awk '{print $NF}' | tail -1)
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
    evd "SRV-044" "grep -iE '^[[:space:]]*DocumentRoot' /etc/httpd/conf/httpd.conf /etc/apache2/sites-enabled/*.conf 2>/dev/null | grep -v '^#'; grep -iE '^[[:space:]]*root[[:space:]]' /etc/nginx/sites-enabled/* /etc/nginx/conf.d/*.conf 2>/dev/null | grep -v '^#'"
    is_running httpd || is_running apache2 || is_running nginx || { result "SRV-044|N-A|웹서비스 미실행"; return; }
    local docroot=""
    docroot=$(grep -iE '^[[:space:]]*DocumentRoot' /etc/httpd/conf/httpd.conf /etc/apache2/sites-enabled/*.conf 2>/dev/null | grep -v '^#' | awk '{print $NF}' | tr -d '"' | tail -1)
    [ -z "$docroot" ] && docroot=$(grep -iE '^[[:space:]]*root[[:space:]]' /etc/nginx/sites-enabled/* /etc/nginx/conf.d/*.conf 2>/dev/null | grep -v '^#' | awk '{print $NF}' | tr -d ';' | tail -1)
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
    evd "SRV-047" "grep -vE '^#|^[[:space:]]*$' /etc/rsyslog.conf /etc/rsyslog.d/*.conf /etc/syslog.conf 2>/dev/null | head -20"
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
    _smtp_running || { evd "SRV-053" "ps -ef 2>/dev/null | grep -E 'smtp|postfix|sendmail' | grep -v grep"; result "SRV-053|N-A|SMTP 미실행"; return; }
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
    _smtp_running || { evd "SRV-054" "ps -ef 2>/dev/null | grep -E 'smtp|postfix|sendmail' | grep -v grep"; result "SRV-054|N-A|SMTP 미실행"; return; }
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
    _smtp_running || { evd "SRV-055" "ps -ef 2>/dev/null | grep -E 'smtp|postfix|sendmail' | grep -v grep"; result "SRV-055|N-A|SMTP 미실행"; return; }
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
    _smtp_running || { evd "SRV-056" "ps -ef 2>/dev/null | grep -E 'smtp|postfix|sendmail' | grep -v grep"; result "SRV-056|N-A|SMTP 미실행"; return; }
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
    _smtp_running || { evd "SRV-057" "ps -ef 2>/dev/null | grep -E 'smtp|postfix|sendmail' | grep -v grep"; result "SRV-057|N-A|SMTP 미실행"; return; }
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
    is_running named || { evd "SRV-058" "ps -ef 2>/dev/null | grep named | grep -v grep"; result "SRV-058|N-A|DNS 미실행"; return; }
    evd "SRV-058" "named -v 2>/dev/null; rpm -qa bind 2>/dev/null; dpkg -l bind9 2>/dev/null | tail -1"
    local ver=$(named -v 2>/dev/null | grep -oE 'BIND [0-9][^ ]*' | head -1)
    result "SRV-058|수동확인|DNS ${ver:-버전 미확인} - 보안 패치 적용 여부 확인"
}

# SRV-059: DNS 영역전송 제한
check_SRV059() {
    is_running named || { evd "SRV-059" "ps -ef 2>/dev/null | grep named | grep -v grep"; result "SRV-059|N-A|DNS 미실행"; return; }
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
    is_running named || { evd "SRV-060" "ps -ef 2>/dev/null | grep named | grep -v grep"; result "SRV-060|N-A|DNS 미실행"; return; }
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
    is_running named || { evd "SRV-061" "ps -ef 2>/dev/null | grep named | grep -v grep"; result "SRV-061|N-A|DNS 미실행"; return; }
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
        grep -v '^[[:space:]]*#' "$cf" 2>/dev/null | grep -qi "Options.*Indexes" && vuln="${vuln} ${cf}"
    done
    for cf in /etc/nginx/nginx.conf /etc/nginx/conf.d/*.conf /etc/nginx/sites-enabled/*; do
        [ -f "$cf" ] || continue
        grep -v '^[[:space:]]*#' "$cf" 2>/dev/null | grep -qi "autoindex.*on" && vuln="${vuln} ${cf}"
    done
    [ -n "$vuln" ] && result "SRV-071|취약|디렉터리 인덱싱 활성화:${vuln}" || \
        result "SRV-071|양호|디렉터리 인덱싱 비활성화"
}

# SRV-076
check_SRV076() {
    is_running snmpd || { evd "SRV-076" "ps -ef 2>/dev/null | grep snmpd | grep -v grep"; result "SRV-076|N-A|SNMP 미실행"; return; }
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
    is_running snmpd || { evd "SRV-077" "ps -ef 2>/dev/null | grep snmpd | grep -v grep"; result "SRV-077|N-A|SNMP 미실행"; return; }
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
    evd "SRV-100" "awk -F: '{printf \"%-15s UID=%-5s Shell=%s\\n\",\$1,\$3,\$7}' /etc/passwd 2>/dev/null"
    result "SRV-100|수동확인|시스템 계정 Shell 현황 수동 확인 (위 현황 참조)"
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
    [ -n "$found" ] && result "SRV-106|취약|root 외 UID 0 계정: $(echo "$found" | _csv)" || \
        result "SRV-106|양호|root 외 UID 0 계정 없음"
}

# SRV-107
check_SRV107() {
    evd "SRV-107" "grep -E '^PASS_MIN_LEN|^MINLEN' /etc/login.defs 2>/dev/null; grep -iE 'pam_pwquality|pam_cracklib' $(get_pam_files) 2>/dev/null | grep -v '^#'"
    local minlen=$(grep -E '^[[:space:]]*PASS_MIN_LEN' /etc/login.defs 2>/dev/null | awk '{print $2}' | tail -1)
    local pam_ml=$(grep -v '^#' $(get_pam_files) 2>/dev/null | grep -oE 'minlen=[0-9]+' | head -1 | cut -d= -f2)
    local elen=${pam_ml:-${minlen:-0}}
    [ "${elen:-0}" -ge 8 ] 2>/dev/null && result "SRV-107|양호|패스워드 최소 길이=${elen}" || \
        result "SRV-107|취약|패스워드 최소 길이=${elen:-미설정} (8자리 이상 필요)"
}

# SRV-110
check_SRV110() {
    evd "SRV-110" "_to 60 find / \$_FP \( -nouser -o -nogroup \) -print 2>/dev/null | head -20"
    local found=$(_to 60 find / $_FP \( -nouser -o -nogroup \) -print 2>/dev/null | grep -vE '^/proc|^/sys|^/dev|^/run' | head -10)
    [ -n "$found" ] && result "SRV-110|취약|소유자 없는 파일 존재: $(echo "$found" | head -c 200)" || \
        result "SRV-110|양호|소유자 없는 파일 미존재"
}

# SRV-111
check_SRV111() {
    evd "SRV-111" "cat /etc/logrotate.conf 2>/dev/null | head -15; ls -la /etc/logrotate.d/ 2>/dev/null | head -10; du -sh /var/log 2>/dev/null"
    if [ -f /etc/logrotate.conf ]; then
        local rotate=$(grep -E '^[[:space:]]*rotate ' /etc/logrotate.conf 2>/dev/null | awk '{print $2}')
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
    evd "SRV-119" "rpm -qa aide tripwire 2>&1; dpkg -l aide tripwire 2>&1 | grep '^ii'; command -v aide tripwire ossec-control 2>&1"   # aide --check(전체 무결성 검사)는 부하가 커서 실행하지 않음
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
    evd "SRV-148" "grep -i password /boot/grub2/grub.cfg /boot/grub/grub.cfg 2>&1; grep -i SINGLE /etc/sysconfig/init /etc/default/grub 2>&1"
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
    evd "SRV-150" "awk -F: '{printf \"%-15s UID=%-5s Shell=%s\\n\",\$1,\$3,\$7}' /etc/passwd 2>/dev/null"
    result "SRV-150|수동확인|시스템 계정 Shell 현황 수동 확인 (위 현황 참조)"
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
    evd "SRV-155" "systemctl is-active firewalld iptables ufw nftables 2>&1; iptables -L -n 2>&1; ufw status 2>&1; nft list ruleset 2>&1"
    local fw=""
    systemctl is-active firewalld >/dev/null 2>&1 && fw="firewalld"
    systemctl is-active iptables >/dev/null 2>&1 && fw="${fw} iptables"
    ufw status 2>/dev/null | grep -qi "Status: active" && fw="${fw} ufw"
    [ -z "$fw" ] && iptables -L -n 2>/dev/null | grep -qvE '^Chain|^target|^$' && fw="iptables(규칙존재)"
    [ -z "$fw" ] && nft list ruleset 2>/dev/null | grep -qE '^[[:space:]]+(ip|tcp|udp|iif|oif|meta|ct)[[:space:]]' && fw="nftables(규칙존재)"
    if [ -n "$fw" ]; then result "SRV-155|양호|방화벽 활성:${fw}"
    elif [ "$_NONROOT" = 1 ]; then result "SRV-155|점검불가|방화벽 규칙 조회 권한 없음 (비root 실행) - root 로 재점검 필요"
    elif [ -n "${_CLOUD:-}" ] && [ "${_CLOUD:-}" != "없음" ] && [ "${_CLOUD:-}" != "미확인" ]; then
        result "SRV-155|수동확인|호스트 방화벽 비활성 - ${_CLOUD} 환경: 보안그룹(${_CLOUD_SG:-ID 미확인})의 인바운드 규칙으로 접근통제 시 양호 가능, 규칙 수동 확인 필요"
    else result "SRV-155|취약|방화벽 비활성 (firewalld/iptables/ufw/nftables 모두 비활성)"; fi
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
    local max=$(grep -E '^[[:space:]]*PASS_MAX_DAYS' /etc/login.defs 2>/dev/null | awk '{print $2}' | tail -1)
    local min=$(grep -E '^[[:space:]]*PASS_MIN_DAYS' /etc/login.defs 2>/dev/null | awk '{print $2}' | tail -1)
    local warn=$(grep -E '^[[:space:]]*PASS_WARN_AGE' /etc/login.defs 2>/dev/null | awk '{print $2}' | tail -1)
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
    [ -n "$found" ] && result "SRV-169|취약|불필요 사용자 환경파일 존재: $(echo "$found" | head -c 200)" || \
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

_show_cfg() {   # 증적용: 파일별 ls -l + 주석·빈 줄을 제외한 설정 내용 (없는 파일은 'No such file' 이 그대로 기록되어 부재도 증적이 됨)
    local f
    for f in "$@"; do
        echo "# $f"
        if [ -f "$f" ]; then ls -l "$f" 2>&1; _cfg "$f" 2>&1; else ls -ld "$f" 2>&1; fi
    done
}

_svc_state() {   # 증적용: 서비스별 실행 상태(systemd·lssrc·svcs·프로세스명)와 최종 실행 판정 — 미실행도 상태로 기록
    local s
    for s in "$@"; do
        if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
            echo "$s: systemd LoadState=$(systemctl show -p LoadState "$s" 2>/dev/null | sed 's/.*=//') ActiveState=$(systemctl is-active "$s" 2>&1)"
        fi
        command -v lssrc >/dev/null 2>&1 && lssrc -s "$s" 2>&1 | sed -n 2p
        command -v svcs >/dev/null 2>&1 && svcs -H "$s" 2>&1
        echo "$s: 프로세스 $(_comm | grep -cxF -e "$s")개, 실행 판정=$(is_running "$s" && echo 실행중 || echo 미실행)"
    done
}

_listen_all() {   # 증적용: TCP LISTEN 목록 전체 (_listen 판정 근거)
    if command -v ss >/dev/null 2>&1; then ss -tln 2>&1
    elif command -v netstat >/dev/null 2>&1; then netstat -an 2>&1
    else echo "ss/netstat 명령 없음 - 수신 포트 조회 불가 (프로세스 기준으로만 판정)"; fi
}
_portnote() { command -v ss >/dev/null 2>&1 || command -v netstat >/dev/null 2>&1 || echo " [ss/netstat 없음 - 수신 포트 미확인, 프로세스 기준]"; }
_noaccess_homes() {   # 로그인 계정 홈 중 현재 계정으로 열람할 수 없는 디렉터리 (비root 실행 시 점검불가 판단용)
    awk -F: '$7!~/(nologin|false|sync|shutdown|halt)$/ && $6!="" && $6!="/" {print $6}' /etc/passwd 2>/dev/null | sort -u | while read -r _h; do
        [ -d "$_h" ] && { [ -x "$_h" ] && [ -r "$_h" ] || echo "$_h"; }
    done
}

_sum() {   # 긴 목록 요약: 표준입력 줄을 쉼표로 이어 max(기본 10)개까지만, 나머지는 '외 N건(증적 참조)'
    awk -v m="${1:-10}" 'NF {n++; if (n<=m) printf "%s%s", (n>1?",":""), $0} END {if (n>m) printf " 외 %d건(증적 참조)", n-m}'
}

_show_exist() {   # 증적용: 여러 경로 중 존재하는 파일은 내용(주석 제외)을, 없는 경로는 목록으로 기록
    local f n=0 e=0 miss=""
    for f in "$@"; do
        n=$((n+1))
        if [ -e "$f" ]; then e=$((e+1)); _show_cfg "$f"; else miss="${miss} ${f}"; fi
    done
    echo "# 점검 경로 ${n}개 중 존재 ${e}개"
    [ -n "$miss" ] && echo "# 미존재:${miss}"
    return 0
}

_ls_exist() {   # 증적용: 여러 경로 중 존재하는 파일은 ls -l 로, 없는 경로는 목록으로 기록 (파일 내용은 기록하지 않음)
    local f n=0 e="" miss=""
    for f in "$@"; do n=$((n+1)); if [ -e "$f" ]; then e="${e} ${f}"; else miss="${miss} ${f}"; fi; done
    echo "# 점검 경로 ${n}개 중 존재 $(echo $e | wc -w)개"
    [ -n "$e" ] && ls -l $e 2>&1
    [ -n "$miss" ] && echo "# 미존재:${miss}"
    return 0
}
_pw_status() {   # 증적용: 계정별 비밀번호 필드 상태 (해시 값은 출력하지 않음)
    case "$OS_FAMILY" in
    AIX)
        echo "# /etc/security/passwd"
        awk '/^[^ \t*#][^ \t]*:[ \t]*$/{sub(/:.*/,"");u=$0;next} /^[ \t]+password[ \t]*=/{v=$0;sub(/^[^=]*=[ \t]*/,"",v);sub(/[ \t]+$/,"",v); print u": " (v==""?"비밀번호 공란":"설정됨")}' /etc/security/passwd 2>&1 ;;
    *)
        local f=/etc/shadow; [ -e "$f" ] || f=/etc/passwd
        echo "# $f"
        awk -F: '{s=($2==""?"비밀번호 공란":($2=="x"?"shadow 파일로 위임":(($2 ~ /^[!*]/ || $2=="NP" || $2=="LK")?"잠김/비활성":"설정됨"))); print $1": "s}' "$f" 2>&1
        [ "$OS_FAMILY" = "SOLARIS" ] || [ "$OS_FAMILY" = "HPUX" ] && { echo "# logins -p"; logins -p 2>&1; } ;;
    esac
    return 0
}

_tmout_scan() {   # 파일별 TMOUT 대입 (파일:값) — 주석 제외, export·readonly·typeset 접두 허용, $((a*b)) 계산식은 값으로 평가
    local f line v
    for f in "$@"; do
        [ -f "$f" ] || continue
        grep -E '(^|[[:space:];])TMOUT=' "$f" 2>/dev/null | grep -vE '^[[:space:]]*#' | while IFS= read -r line; do
            v=$(printf '%s' "$line" | sed -n 's/.*TMOUT=\([^[:space:];]*\).*/\1/p' | tr -d "\"'")
            case "$v" in
            ''|*[!0-9*+/\(\)\$\ -]*) ;;
            *) case "$v" in \$\(\(*\)\)) v=$(eval "echo $v" 2>/dev/null) ;; esac ;;
            esac
            printf '%s:%s\n' "$f" "$v"
        done
    done
}

_tmout_lines() {   # 증적용: TMOUT 설정 줄 (파일:줄번호:내용, 주석 제외)
    local f
    for f in "$@"; do [ -f "$f" ] && grep -nH -iE 'TMOUT' "$f" 2>&1 | grep -vE '^[^:]*:[0-9]+:[[:space:]]*#'; done
    return 0
}

_strip_c_comments() {   # named.conf 주석(/* */, //, #) 제거 후 내용이 있는 줄만 출력
    awk 'BEGIN{inc=0}
    { line=$0; res=""
      while (length(line)>0) {
        if (inc) { e=index(line,"*/"); if (e==0) { line=""; break } line=substr(line,e+2); inc=0; continue }
        a=index(line,"/*"); b=index(line,"//"); c=index(line,"#"); m=0; t=""
        if (a>0) { m=a; t="b" }
        if (b>0 && (m==0 || b<m)) { m=b; t="l" }
        if (c>0 && (m==0 || c<m)) { m=c; t="l" }
        if (m==0) { res=res line; line=""; break }
        res=res substr(line,1,m-1)
        if (t=="l") { line=""; break }
        line=substr(line,m+2); inc=1
      }
      if (res ~ /[^ \t]/) print res }'
}

_named_load() {   # named 설정을 전역 _NC(주석 제거된 내용), _NC_SRC(출처)에 읽어 둔다. 설정을 못 찾으면 비어 있음, 읽지 못하면 _NC_ERR
    local c i out
    _NC=""; _NC_SRC=""; _NC_ERR=""
    for c in /etc/named.conf /etc/bind/named.conf /var/named/chroot/etc/named.conf /etc/namedb/named.conf /usr/local/etc/namedb/named.conf; do
        [ -f "$c" ] || continue
        _NC_SRC="$c"
        [ -r "$c" ] || { _NC_ERR="$c 읽기 권한 없음"; return 0; }
        if command -v named-checkconf >/dev/null 2>&1; then
            out=$(named-checkconf -p "$c" 2>/dev/null)
            if [ -n "$out" ]; then _NC="$out"; _NC_SRC="named-checkconf -p $c (include 포함 유효 설정)"; return 0; fi
        fi
        # named-checkconf 없음/실패: named.conf 와 include 파일을 직접 읽고 주석 제거
        _NC=$( { cat "$c"; for i in $(sed -n 's/^[[:space:]]*include[[:space:]]*"\([^"]*\)".*/\1/p' "$c" 2>/dev/null); do cat "$i" 2>/dev/null; done; cat /etc/bind/named.conf.options /etc/bind/named.conf.local 2>/dev/null; } | _strip_c_comments)
        _NC_SRC="$c + include 파일 (주석 제거)"
        return 0
    done
    return 0
}

_dns_stmt() {   # 표준입력 named 설정에서 문장 $1 의 값을 'ctx|값' 으로 출력 (ctx = 포함 블록 머리글, 목록은 항목을 공백으로 연결)
    awk -v NAME="$1" '
    { gsub(/\{/," { "); gsub(/\}/," } "); gsub(/;/," ; "); n=split($0,t," "); for(i=1;i<=n;i++) tok[++N]=t[i] }
    END {
        d=0; hdr=""
        for (i=1;i<=N;i++) {
            x=tok[i]
            if (x=="{") { d++; ctx[d]=hdr; hdr=""; continue }
            if (x=="}") { d--; hdr=""; continue }
            if (x==";") { hdr=""; continue }
            if (hdr=="" && x==NAME && d>=1) {
                j=i+1; v=""
                if (tok[j]=="{") { j++; while (j<=N && tok[j]!="}") { if (tok[j]!=";") v=v (v==""?"":" ") tok[j]; j++ } }
                else { while (j<=N && tok[j]!=";" && tok[j]!="}") { v=v (v==""?"":" ") tok[j]; j++ } }
                print ctx[d] "|" v; i=j; hdr=""; continue
            }
            hdr=hdr (hdr==""?"":" ") x
        }
    }'
}

_dns_pre() {   # DNS 항목 공통 선행 처리: 미실행 N-A / 설정 미발견·읽기 불가 점검불가. 계속 진행해도 되면 0
    local id="$1" na="${2:-N-A}"
    _named_load
    evd "$id" "_svc_state named; echo '# 설정 출처: ${_NC_SRC:-named.conf 미발견}'; printf '%s\\n' \"\$_NC\""
    is_running named || { result "${id}|${na}|DNS 서비스 미실행"; return 1; }
    [ -n "$_NC_ERR" ] && { result "${id}|점검불가|named.conf 읽기 불가: ${_NC_ERR}"; return 1; }
    [ -z "$_NC" ] && { result "${id}|점검불가|named 가 실행 중이나 named.conf(/etc/named.conf·/etc/bind/named.conf 등)를 찾지 못함 - 설정 확인 불가"; return 1; }
    return 0
}

_hash_algs() {   # 증적용: 계정별 비밀번호 해시 알고리즘 (해시 값 자체는 출력하지 않음)
    local f=/etc/shadow
    echo "# $f"
    awk -F: '{h=$2; a=(h==""?"비밀번호 공란":(h ~ /^[!*]/?"잠김/비활성":(h ~ /^\$1\$/?"MD5($1$)":(h ~ /^\$5\$/?"SHA-256($5$)":(h ~ /^\$6\$/?"SHA-512($6$)":(h ~ /^\$y\$/?"yescrypt($y$)":(h ~ /^\$2/?"bcrypt($2)":(h ~ /^\$(md5|sunmd5)\$/?"Solaris MD5":(length(h)==13?"DES(crypt 13자)":"기타")))))))));  print $1": "a}' "$f" 2>&1
}

_pstat() {   # 증적용: 파일마다 '권한 소유자 경로' 한 줄 (get_perm·get_owner 와 같은 방식)
    local f
    for f in "$@"; do [ -e "$f" ] || [ -L "$f" ] && echo "$(get_perm "$f") $(get_owner "$f") $f"; done
    return 0
}

_umask_scan() {   # 파일별 umask 대입 '파일: 값' (주석 제외, umask 키워드 뒤의 8진수만 값으로 인정)
    local f
    for f in "$@"; do
        [ -f "$f" ] || continue
        awk -v f="$f" '
            /^[[:space:]]*#/ {next}
            tolower($1)=="umask" && $2 ~ /^[0-7]+$/ {print f": "$2; next}
            $1 ~ /^[Uu][Mm][Aa][Ss][Kk]=[0-7]+/ {v=$1; sub(/^[^=]*=/,"",v); print f": "v}' "$f" 2>/dev/null
    done
    return 0
}

_smtp_gate() {   # SMTP 항목 공통: 미실행이면 N-A 결과를 내고 1 반환 (계속 진행하면 0)
    _smtp_running && return 0
    evd "$1" "_svc_state sendmail postfix exim exim4; _listen_all"
    result "${1}|N-A|SMTP 서비스 미실행"
    return 1
}

_smtp_cf_show() {   # 증적용: MTA 설정 파일 존재·권한과 지정 키워드 줄 (인자: 정규식)
    if [ -n "$_smtp_cf" ] && [ -f "$_smtp_cf" ]; then ls -l "$_smtp_cf" 2>&1; grep -iE "$1" "$_smtp_cf" 2>&1
    else echo "MTA(${_smtp_type:-미식별}) 설정 파일을 찾지 못함"; fi
    return 0
}

_netrc_show() {   # 증적용: .netrc 항목 (machine/login 은 기록, password·account 값은 마스킹)
    local f
    for f in "$@"; do
        [ -f "$f" ] || continue
        echo "# $f"; ls -l "$f" 2>&1
        [ -r "$f" ] && awk '{for(i=1;i<NF;i++) if ($i=="password" || $i=="passwd" || $i=="account") $(i+1)="***"; print}' "$f" 2>&1
    done
    return 0
}

# <<< SRV-COMMON-END
_PHASE="os"
# ── 실행 (SRV-001 ~ SRV-179 전체) ───────────────────────────────
if [ "$_KMODE" != "mi" ]; then   # 주요정보 모드는 SRV 공통 점검(전자금융 WST 용)을 건너뜀 - 아래 구간 안은 원본 그대로
# >>> SRV-RUN-BEGIN — 원본: server/check_server_srv.sh. 사본(webwas/check_webwas.sh)은 python tools/sync_common.py 로 갱신
check_SRV001
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
evd "SRV-018" "uname -s"
result "SRV-018|N-A|불필요한 하드디스크 기본 공유 비활성화 - 평가기준 평가대상 아님 (Linux/Unix 해당 없음)"
evd "SRV-020" "uname -s"
result "SRV-020|N-A|공유 기능에 대한 접근통제 설정 적절성 - 평가기준 평가대상 아님 (Linux/Unix 해당 없음)"
check_SRV021
check_SRV022
evd "SRV-023" "uname -s"
result "SRV-023|N-A|원격 터미널 서비스의 암호화 설정 적절성 - 평가기준 평가대상 아님 (Linux/Unix 해당 없음)"
evd "SRV-024" "uname -s"
result "SRV-024|N-A|취약한 Telnet 인증 방식 사용 제한 여부 - 평가기준 평가대상 아님 (Linux/Unix 해당 없음)"
check_SRV025
check_SRV026
check_SRV027
check_SRV028
evd "SRV-029" "uname -s"
result "SRV-029|N-A|SMB 세션 중단 관리 설정 여부 - 평가기준 평가대상 아님 (Linux/Unix 해당 없음)"
evd "SRV-031" "uname -s"
result "SRV-031|N-A|계정 목록 및 네트워크 공유 이름 노출 방지 여부 - 평가기준 평가대상 아님 (Linux/Unix 해당 없음)"
check_SRV034
check_SRV035
check_SRV037
check_SRV062
check_SRV063
check_SRV064
check_SRV066
check_SRV069
check_SRV070
evd "SRV-072" "uname -s"
result "SRV-072|N-A|Windows 전용 항목 (Linux/Unix 해당 없음)"
check_SRV073
check_SRV074
check_SRV075
evd "SRV-078" "uname -s"
result "SRV-078|N-A|Windows Guest 계정 (Linux/Unix 해당 없음)"
evd "SRV-079" "uname -s"
result "SRV-079|N-A|Windows Everyone 권한 (Linux/Unix 해당 없음)"
evd "SRV-080" "uname -s"
result "SRV-080|N-A|Windows 프린터 드라이버 (Linux/Unix 해당 없음)"
check_SRV081
check_SRV082
check_SRV083
check_SRV084
check_SRV087
evd "SRV-090" "uname -s"
result "SRV-090|N-A|Windows 원격 레지스트리 (Linux/Unix 해당 없음)"
check_SRV091
check_SRV092
check_SRV093
check_SRV094
check_SRV095
check_SRV096
evd "SRV-097" "uname -s"
result "SRV-097|N-A|FTP 서비스 디렉터리 접근권한 설정 적절성 - 평가기준 평가대상 아님 (Linux/Unix 해당 없음)"
evd "SRV-101" "uname -s"
result "SRV-101|N-A|불필요한 예약 작업 제거 - 평가기준 평가대상 아님 (Linux/Unix 해당 없음)"
evd "SRV-103" "uname -s"
result "SRV-103|N-A|LAN Manager 인증 수준 적절성 - 평가기준 평가대상 아님 (Linux/Unix 해당 없음)"
evd "SRV-104" "uname -s"
result "SRV-104|N-A|보안 채널 데이터 디지털 암호화 또는 서명 기능 설정 적절성 - 평가기준 평가대상 아님 (Linux/Unix 해당 없음)"
evd "SRV-105" "uname -s"
result "SRV-105|N-A|불필요한 시작프로그램 제거 - 평가기준 평가대상 아님 (Linux/Unix 해당 없음)"
check_SRV108
check_SRV109
check_SRV112
check_SRV115
evd "SRV-116" "uname -s"
result "SRV-116|N-A|“보안 감사를 수행할 수 없는 경우, 즉시 시스템 종료” 기능 비활성화 - 평가기준 평가대상 아님 (Linux/Unix 해당 없음)"
check_SRV118
evd "SRV-119" "uname -s"
result "SRV-119|N-A|백신 프로그램 업데이트 적용 여부 - 평가기준 평가대상 아님 (Linux/Unix 해당 없음)"
check_SRV121
check_SRV122
evd "SRV-123" "uname -s"
result "SRV-123|N-A|최종 로그인 사용자 계정 노출 방지 여부 - 평가기준 평가대상 아님 (Linux/Unix 해당 없음)"
evd "SRV-125" "uname -s"
result "SRV-125|N-A|Windows 화면 보호기 (Linux/Unix 해당 없음)"
evd "SRV-126" "uname -s"
result "SRV-126|N-A|자동 로그온 방지 설정 여부 - 평가기준 평가대상 아님 (Linux/Unix 해당 없음)"
check_SRV127
evd "SRV-128" "uname -s"
result "SRV-128|N-A|NTFS 파일 시스템 사용 여부 - 평가기준 평가대상 아님 (Linux/Unix 해당 없음)"
evd "SRV-129" "uname -s"
result "SRV-129|N-A|백신 프로그램 설치 여부 - 평가기준 평가대상 아님 (Linux/Unix 해당 없음)"
check_SRV131
check_SRV133
check_SRV134
check_SRV135
evd "SRV-136" "uname -s"
result "SRV-136|N-A|로그온 단계에서 시스템 종료 기능 비활성화 - 평가기준 평가대상 아님 (Linux/Unix 해당 없음)"
evd "SRV-137" "uname -s"
result "SRV-137|N-A|네트워크 서비스 접근 권한 적절성 - 평가기준 평가대상 아님 (Linux/Unix 해당 없음)"
evd "SRV-138" "uname -s"
result "SRV-138|N-A|백업 및 복구 권한 설정 적절성 - 평가기준 평가대상 아님 (Linux/Unix 해당 없음)"
evd "SRV-139" "uname -s"
result "SRV-139|N-A|시스템 자원 소유권 변경 권한 설정 적절성 - 평가기준 평가대상 아님 (Linux/Unix 해당 없음)"
evd "SRV-140" "uname -s"
result "SRV-140|N-A|이동식 미디어 포맷 및 꺼내기 허용 정책 설정 적절성 - 평가기준 평가대상 아님 (Linux/Unix 해당 없음)"
check_SRV142
check_SRV144
check_SRV147
evd "SRV-149" "uname -s"
result "SRV-149|N-A|디스크 볼륨 암호화 적용 여부 - 평가기준 평가대상 아님 (Linux/Unix 해당 없음)"
evd "SRV-150" "uname -s"
result "SRV-150|N-A|로컬 로그온 허용 계정 제한 여부 - 평가기준 평가대상 아님 (Linux/Unix 해당 없음)"
evd "SRV-151" "uname -s"
result "SRV-151|N-A|익명 SID/이름 변환 설정 제한 여부 - 평가기준 평가대상 아님 (Linux/Unix 해당 없음)"
evd "SRV-152" "uname -s"
result "SRV-152|N-A|원격터미널 접속 가능한 사용자 그룹 제한 여부 - 평가기준 평가대상 아님 (Linux/Unix 해당 없음)"
check_SRV158
check_SRV161
check_SRV163
check_SRV164
check_SRV165
check_SRV166
check_SRV170
check_SRV171
evd "SRV-172" "uname -s"
result "SRV-172|N-A|불필요한 시스템 자원 공유 제거 - 평가기준 평가대상 아님 (Linux/Unix 해당 없음)"
check_SRV173
check_SRV174
check_SRV175
check_SRV177
evd "SRV-178" "uname -s"
result "SRV-178|N-A|Windows 개인 키 passphrase (Linux/Unix 해당 없음)"
check_SRV179
# <<< SRV-RUN-END
fi

# ════════════════════════════════════════════════════════════════
# [2] 웹/WAS 공통 도구 — 설정 해석·다중 대상 병합·실제 HTTP 응답 수집
#     (구 [2] 기존 웹 점검 약 800행은 판정이 전부 REF-(참고)로만 가서 결과에 영향이 없어 제거하고,
#      WST-036/124/125 를 아래 [3] 에서 직접 판정한다)
# ════════════════════════════════════════════════════════════════
_PHASE="final"

# 제품 탐지 여부 / 표시명 / 점검 대상 필터 (WEB_LIST·WAS_LIST 는 상단 탐지 구간에서 채움)
_hasw() { case " $WEB_LIST $WAS_LIST " in *" $1 "*) return 0 ;; esac; return 1; }
_pname() { case "$1" in apache) echo Apache ;; nginx) echo Nginx ;; webtob) echo WebtoB ;; tomcat) echo Tomcat ;; jeus) echo JEUS ;; esac; }
_pt() { _hasw "$1" || return 1; case " $2 " in *" $(_pname "$1") "*) return 0 ;; esac; return 1; }   # _pt 제품 대상목록 : 탐지됐고 대상이면 참
_brief() {   # _brief 목록 [개수] : 목록 앞 N줄만 한 줄로, 넘치면 '외 N건(증적 참조)'
    local n="${2:-3}" t; t=$(printf '%s\n' "$1" | grep -c .)
    printf '%s\n' "$1" | grep . | sed -n "1,${n}p" | tr '\n' ';' | sed 's/;$//; s/;/; /g'
    [ "$t" -gt "$n" ] && printf ' 외 %d건(증적 참조)' $((t - n))
    return 0
}
_me() { id -un 2>/dev/null || echo "?"; }
_pat() { printf '%s' "$1" | sed 's/\\s/[[:space:]]/g; s/\\S/[^[:space:]]/g'; }   # GNU 전용 \s \S → POSIX 클래스

# _perm_over 재정의: 마커 구간의 사본은 3자리 미만 권한(044·007)에서 빈 값이 되므로 여기서 보정
_perm_over() {
    local p; p=$(printf '%03d' "$1" 2>/dev/null) || return 1; p="${p#"${p%???}"}"
    [ -z "$p" ] && return 1
    (( (8#$p & ~8#$2 & 8#777) != 0 ))
}

# 읽을 수 없는 파일 목록 (존재하지만 읽기 불가 → 점검불가 판단용)
_unreadable() { local f o=""; for f in "$@"; do [ -e "$f" ] && [ ! -r "$f" ] && o="${o} ${f}"; done; echo "${o# }"; }

# 증적: 경로 목록을 ls -ld 로 (목록이 비면 호출하지 않음)
_ls_ev() { [ $# -gt 0 ] || { echo "대상 경로 없음"; return 0; }; ls -ld "$@" 2>&1; }

# ── XML 주석 제거 / 비밀 마스킹 ─────────────────────────────────
_xml_nc() { awk '{ s=$0; out=""; while (1) { if (c) { i=index(s,"-->"); if (!i) { s=""; break } s=substr(s,i+3); c=0 } else { i=index(s,"<!--"); if (!i) { out=out s; s=""; break } out=out substr(s,1,i-1); s=substr(s,i+4); c=1 } } print out }'; }
_MASK_AWK='
function mk(s, re, kind,    low, out, m, pre, eq, q, rest, br) {
  out = ""
  while (1) {
    low = tolower(s)
    if (!match(low, re)) break
    pre = substr(s, 1, RSTART - 1); m = substr(s, RSTART, RLENGTH); rest = substr(s, RSTART + RLENGTH)
    if (kind == 1) { eq = index(m, "="); q = substr(m, length(m), 1); m = substr(m, 1, eq) q "****" q }
    else if (kind == 2) { eq = 0; if (match(m, /[:=]/)) eq = RSTART; m = substr(m, 1, eq) "****" }
    else { br = ""; if (match(m, /\{[A-Za-z0-9-]+\}/)) br = substr(m, RSTART, RLENGTH); eq = index(m, ">"); m = substr(m, 1, eq) br "****</" }
    out = out pre m; s = rest
  }
  return out s
}
{ s = $0
  s = mk(s, "(password|credential|passwd|pwd|secret)[ \t]*=[ \t]*\"[^\"]*\"", 1)
  s = mk(s, "(password|credential|passwd|pwd|secret)[ \t]*=[ \t]*\047[^\047]*\047", 1)
  s = mk(s, "[?&;](password|pwd|passwd)=[^&; \t\"\047<]+", 2)
  s = mk(s, "(password|credential|passwd)[ \t]*[:=][ \t]*[^ \t\"\047,;{}]+", 2)
  s = mk(s, "<(password|credential)>[^<]*</", 3)
  print s }'
_mask_pw() { awk "$_MASK_AWK"; }

# ── 설정 파일 전개: Include/include 를 따라가며 "파일<TAB>줄<TAB>내용" 스트림 생성 ──
_TAB=$(printf '\t')
_expand_conf() {   # _expand_conf apache|nginx 주설정 기준경로
    [ -r "$2" ] || return 0
    awk -v kind="$1" -v root="$3" -v main="$2" '
    function trim(s) { sub(/^[ \t\r]+/, "", s); sub(/[ \t\r]+$/, "", s); return s }
    function emit(f, ln, t) { printf "%s\t%d\t%s\n", f, ln, t }
    function incl(pat, d,    cmd, p) {
        gsub(/^"|"$/, "", pat); gsub(/^\047|\047$/, "", pat)
        if (pat ~ "[^]A-Za-z0-9_./*?[{}~+@%:,=-]") return
        if (pat !~ /^\//) pat = root "/" pat
        cmd = "for p in " pat "; do if [ -d \"$p\" ]; then for q in \"$p\"/*; do [ -f \"$q\" ] && echo \"$q\"; done; elif [ -f \"$p\" ]; then echo \"$p\"; fi; done 2>/dev/null"
        while ((cmd | getline p) > 0) dofile(p, d + 1)
        close(cmd)
    }
    function handle(f, ln, t, d,    a, n) {
        t = trim(t); if (t == "") return
        emit(f, ln, t)
        n = split(t, a, /[ \t]+/)
        if (kind == "apache" && tolower(a[1]) ~ /^include(optional)?$/ && n >= 2) incl(a[2], d)
        if (kind == "nginx" && a[1] == "include" && n >= 2) { sub(/;$/, "", a[2]); incl(a[2], d) }
    }
    function dofile(f, d,    ln, line, t, t2, k, pc, i, p, r) {
        if (d > 8) return
        ln = 0
        while ((r = (getline line < f)) > 0) {
            ln++; t = trim(line)
            if (t == "" || t ~ /^#/) continue
            if (kind == "nginx") {
                sub(/[ \t]+#.*$/, "", t)
                gsub(/\{/, "{\n", t); gsub(/\}/, "\n}\n", t); gsub(/;/, ";\n", t)
                k = split(t, pc, "\n")
                for (i = 1; i <= k; i++) handle(f, ln, pc[i], d)
            } else handle(f, ln, t, d)
        }
        if (r < 0) emit(f, 0, "@@UNREADABLE")   # 읽기 권한 없음/오류 → 점검불가 사유
        close(f)
    }
    BEGIN { dofile(main, 0) }' </dev/null
}

# Apache: 섹션 문맥(VirtualHost/Directory 등)을 붙인 스트림 "문맥<TAB>디렉터리<TAB>파일<TAB>줄<TAB>내용"
_ap_scoped() {
    printf '%s\n' "$_APX" | awk -F'\t' '
    BEGIN { ctx = "global" }
    { t = $3; lt = tolower(t) }
    lt ~ /^<[a-z]/ {
        name = lt; sub(/^</, "", name); sub(/[ >].*$/, "", name)
        if (name == "virtualhost") {
            vn++; ctx = "vhost#" vn " " substr(t, 13); sub(/>$/, "", ctx); sp++; stk[sp] = "v"
            printf "%s\t\t%s\t%s\t%s\n", ctx, $1, $2, t
        } else {
            sp++; stk[sp] = "d"; dd[sp] = ""
            if (name ~ /^(directory|directorymatch|location|locationmatch|files|filesmatch|proxy|proxymatch)$/) {
                dd[sp] = t; sub(/^<[A-Za-z]+[ \t]+/, "", dd[sp]); sub(/>$/, "", dd[sp]); gsub(/"/, "", dd[sp]) }
        }
        next }
    lt ~ /^<\// {
        if (lt ~ /^<\/virtualhost/) ctx = "global"
        if (sp > 0) sp--
        next }
    { d = ""; for (i = sp; i >= 1; i--) if (stk[i] == "d" && dd[i] != "") { d = dd[i]; break }
      c = "global"; for (i = 1; i <= sp; i++) if (stk[i] == "v") c = ctx
      printf "%s\t%s\t%s\t%s\t%s\n", c, d, $1, $2, t }'
}
# Apache: 가상호스트 단위 설정 유무 "문맥<TAB>있음(1/0)<TAB>일치 내용" (global 포함, 대소문자 무시)
_ap_vh() {   # _ap_vh 정규식
    _ap_scoped | awk -F'\t' -v re="$(_pat "$1" | tr 'A-Z' 'a-z')" '
    { if (!($1 in seen)) { seen[$1] = 1; order[++n] = $1 } if (tolower($5) ~ re) { has[$1] = 1; txt[$1] = (txt[$1] == "" ? $5 : txt[$1]) } }
    END { if (!("global" in seen)) { seen["global"] = 1; order[++n] = "global" } for (i = 1; i <= n; i++) printf "%s\t%d\t%s\n", order[i], (order[i] in has) ? 1 : 0, txt[order[i]] }'
}
# Apache VirtualHost 문맥 목록 (설정이 없는 가상호스트도 포함하려면 _ap_scoped 에 한 줄이라도 있어야 하므로 별도 추출)
_ap_vhosts() { printf '%s\n' "$_APX" | awk -F'\t' 'tolower($3) ~ /^<virtualhost/ { n++; t = $3; sub(/^<[Vv][Ii][Rr][Tt][Uu][Aa][Ll][Hh][Oo][Ss][Tt][ \t]+/, "", t); sub(/>$/, "", t); printf "vhost#%d %s\t%s:%s\n", n, t, $1, $2 }'; }

# Nginx: 문맥 스트림 "문맥<TAB>location<TAB>파일<TAB>줄<TAB>내용" (문맥 = main/http 또는 server#N)
_ng_scoped() {
    printf '%s\n' "$_NGX" | awk -F'\t' '
    function flush(   i) { }
    { t = $3; sub(/;$/, "", t) }
    t ~ /^[A-Za-z_]+[^{]*\{$/ { name = t; sub(/[ \t]*\{$/, "", name); split(name, w, /[ \t]+/)
        sp++; kind[sp] = w[1]; arg[sp] = substr(name, length(w[1]) + 2)
        if (w[1] == "server" && sp >= 1) { sn++; srv = "server#" sn; sctx[sp] = srv }
        next }
    t == "}" { if (sp > 0) sp--; next }
    { c = "main"; loc = ""
      for (i = 1; i <= sp; i++) { if (kind[i] == "http") c = "http"; if (kind[i] == "server") c = sctx[i]; if (kind[i] == "location") loc = arg[i] }
      printf "%s\t%s\t%s\t%s\t%s\n", c, loc, $1, $2, t }
    BEGIN { sp = 0 }'
}
_ng_vh() {   # server 블록 단위 설정 유무 "문맥<TAB>있음<TAB>listen<TAB>server_name<TAB>일치 내용" (http/main 문맥 포함)
    _ng_scoped | awk -F'\t' -v re="$(_pat "$1" | tr 'A-Z' 'a-z')" '
    { c = $1; if (!(c in seen)) { seen[c] = 1; order[++n] = c }
      if ($5 ~ /^listen[ \t]/) { l = $5; sub(/^listen[ \t]+/, "", l); lis[c] = (lis[c] == "" ? l : lis[c] ", " l) }
      if ($5 ~ /^server_name[ \t]/) { s = $5; sub(/^server_name[ \t]+/, "", s); nm[c] = s }
      if (tolower($5) ~ re) { has[c] = 1; if (txt[c] == "") txt[c] = $5 } }
    END { for (i = 1; i <= n; i++) { c = order[i]; printf "%s\t%d\t%s\t%s\t%s\n", c, (c in has) ? 1 : 0, lis[c], nm[c], txt[c] } }'
}

# 설정 한 줄 검색 (판정용 _active/_ngx = 내용만, 증적용 _activef/_ngxf = 파일:줄 포함) — 같은 필터를 쓴다
_cfgre() {   # 패턴 → "파일:줄<TAB>내용" 줄에 적용할 정규식 (^ 로 시작하면 내용의 줄머리 기준)
    local p="$1" a=""
    case "$p" in \^*) a=1; p="${p#^}" ;; esac
    p=$(_pat "$p")
    if [ -n "$a" ]; then printf '^[^%s]*%s(%s)' "$_TAB" "$_TAB" "$p"; else printf '^[^%s]*%s.*(%s)' "$_TAB" "$_TAB" "$p"; fi
}
_cq() {   # _cq 스트림 p|f 패턴
    printf '%s\n' "$1" | awk -F'\t' '{ print $1 ":" $2 "\t" $3 }' | grep -iE -- "$(_cfgre "$3")" | { if [ "$2" = f ]; then awk -F'\t' '{ print $1 ": " $2 }'; else cut -f2; fi; }
}
_active() { _cq "$_APX" p "^$1"; }
_activef() { _cq "$_APX" f "^$1"; }
_ngx() { _cq "$_NGX" p "$1"; }
_ngxf() { _cq "$_NGX" f "$1"; }
_ap_files() { printf '%s\n' "$_APX" | awk -F'\t' '{ print $1 }' | sort -u; }
_ng_files() { printf '%s\n' "$_NGX" | awk -F'\t' '{ print $1 }' | sort -u; }
_cfg_scope() {   # 증적: 검색에 사용한 설정 파일 목록 (판정 범위)
    [ -n "$_APX" ] && { echo "[Apache] 주설정 ${APACHE_CONF} / Include 전개 파일 $(_ap_files | grep -c .)개:"; _ap_files | sed 's/^/  /'; }
    [ -n "$_NGX" ] && { echo "[Nginx] 주설정 ${NGINX_CONF} / include 전개 파일 $(_ng_files | grep -c .)개:"; _ng_files | sed 's/^/  /'; }
    [ -n "$_WT_M" ] && echo "[WebtoB] 설정 ${_WT_M}"
    [ -n "$_AP_UN" ] && echo "[Apache] 설정을 읽지 못해 점검불가: ${_AP_UN}"
    [ -n "$_NG_UN" ] && echo "[Nginx] 설정을 읽지 못해 점검불가: ${_NG_UN}"
    [ -n "$_WT_UN" ] && echo "[WebtoB] 설정을 읽지 못해 점검불가: ${_WT_UN}"
    [ -n "$_JE_UN" ] && echo "[JEUS] 설정을 읽지 못해 점검불가: ${_JE_UN}"
    return 0
}
_wtm() { [ -f "$_WT_M" ] && [ -r "$_WT_M" ] && grep -v '^[[:space:]]*#' "$_WT_M" 2>/dev/null | grep -iE -- "$(_pat "$1")"; }       # WebtoB http.m 활성 줄
_wtmf() { [ -f "$_WT_M" ] && [ -r "$_WT_M" ] && grep -nv '^[[:space:]]*#' "$_WT_M" 2>/dev/null | grep -iE -- "$(_pat "$1")" | sed "s|^|${_WT_M}:|"; }

# 문서 루트 / CGI 경로 / 버전 / 로그 경로
_ap_default_root() {   # ServerRoot 지시자가 없을 때 상대 Include 의 기준: 설정 파일이 conf/ 아래면 그 상위, 아니면 컴파일 기본값(HTTPD_ROOT, Debian/Ubuntu 는 /etc/apache2), 그것도 없으면 설정 파일 디렉터리
    local r b; r=$(dirname "$APACHE_CONF")
    case "$(basename "$r")" in conf|config) dirname "$r"; return ;; esac
    for b in "$_AP_BIN" apache2ctl httpd apache2 apachectl; do
        [ -n "$b" ] && command -v "$b" >/dev/null 2>&1 || continue
        b=$("$b" -V 2>/dev/null </dev/null | sed -n 's/.*HTTPD_ROOT="\(.*\)".*/\1/p' | sed -n 1p)
        [ -n "$b" ] && [ -d "$b" ] && { echo "$b"; return; }
    done
    echo "$r"
}
_apache_root() {
    local r; r=$(printf '%s\n' "$_APX" | awk -F'\t' 'tolower($3) ~ /^serverroot[ \t]/ { print $3; exit }' | awk '{print $2}' | tr -d '"')
    [ -n "$r" ] && echo "$r" || { [ -n "$APACHE_CONF" ] && _ap_default_root; }
}
_web_docroots() {
    {
        _active "DocumentRoot[[:space:]]" | awk '{print $2}' | tr -d '"'
        _ngx '^root[[:space:]]' | awk '{print $2}' | tr -d ';"'
        _wtm 'DOCROOT' | grep -ioE 'DOCROOT[[:space:]]*=[[:space:]]*"[^"]*"' | grep -oE '"[^"]*"' | tr -d '"'
        for _h in $TOMCAT_HOMES; do echo "$_h/webapps"; done
    } | grep -v '^$' | sort -u
}
_cgi_dirs() {
    {
        _active 'ScriptAlias[[:space:]]' | awk '{print $3}' | tr -d '"'
        [ -n "$APACHE_CONF" ] && echo "$(_apache_root)/cgi-bin"
        echo /var/www/cgi-bin; echo /usr/lib/cgi-bin
    } | sed 's#/$##' | sort -u
}
_apache_ver() {
    { httpd -v 2>/dev/null || apache2 -v 2>/dev/null || apachectl -v 2>/dev/null || "$_AP_BIN" -v 2>/dev/null; } | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | sed -n 1p
}
_nginx_ver() { { nginx -v 2>&1 || "$_NG_BIN" -v 2>&1; } | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | sed -n 1p; }
_tc_home() {   # catalina.base → catalina.home (프로세스 인자에서, 없으면 base 자체. 중지된 패키지형 인스턴스(/var/lib/tomcatN)는 /usr/share/tomcatN 를 home 으로)
    local h; h=$(printf '%s\n' "$_PSALL" | grep -F -- "-Dcatalina.base=$1" | grep -oE '\-Dcatalina\.home=[^ ]+' | sed -n 1p | cut -d= -f2)
    if [ -z "$h" ] && [ ! -e "$1/lib/catalina.jar" ] && [ ! -e "$1/bin/catalina.sh" ]; then
        case "$(basename "$1")" in tomcat*) [ -e "/usr/share/$(basename "$1")/bin/catalina.sh" ] && h="/usr/share/$(basename "$1")" ;; esac
    fi
    [ -n "$h" ] && echo "$h" || echo "$1"
}
_tomcat_ver() {   # _tomcat_ver [base] : 버전 문자열 (RELEASE-NOTES → ServerInfo.properties → version.sh)
    local b="${1:-$TOMCAT_HOME}" h v j
    [ -n "$b" ] || return 0
    h=$(_tc_home "$b")
    v=$(grep -h "Apache Tomcat Version" "$h/RELEASE-NOTES" "$b/RELEASE-NOTES" 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | sed -n 1p)
    if [ -z "$v" ] && command -v unzip >/dev/null 2>&1; then
        for j in "$h/lib/catalina.jar" "$b/lib/catalina.jar"; do
            [ -r "$j" ] && v=$(unzip -p "$j" org/apache/catalina/util/ServerInfo.properties 2>/dev/null | grep -i '^server.number' | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | sed -n 1p)
            [ -n "$v" ] && break
        done
    fi
    [ -z "$v" ] && [ -f "$h/bin/version.sh" ] && v=$(sh "$h/bin/version.sh" 2>/dev/null | grep -i "Server number" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | sed -n 1p)
    echo "$v"
}

# ── 다중 인스턴스 순회 ──────────────────────────────────────────
_worse_lab() { echo "${1%%|*}|[$2] ${1#*|}"; }
_tc_each() {   # _tc_each 함수 : Tomcat 인스턴스마다 함수 실행(TOMCAT_HOME 설정) → 판정 병합, 근거 앞에 [인스턴스 경로]
    local fn="$1" h out acc="" many=0 _keep="$TOMCAT_HOME"
    many=1   # 단일 인스턴스도 근거에 대상 경로를 표시
    for h in $TOMCAT_HOMES; do
        TOMCAT_HOME="$h"; _HP_FILTER="$h"
        out=""
        case "$fn" in _v_webproc_tomcat|_v_eos_tomcat) ;; *)   # conf 디렉터리를 열람할 수 없으면(비root) 설정 파일 유무를 알 수 없으므로 '없음/양호' 가 아니라 점검불가
            if [ -d "$h/conf" ] && [ ! -x "$h/conf" ]; then out="점검불가|Tomcat conf 디렉터리 접근 권한 없음: $h/conf (실행 계정 $(_me))"; fi ;;
        esac
        [ -n "$out" ] || out=$($fn </dev/null)
        [ -n "$out" ] || continue
        [ "$many" = 1 ] && out=$(_worse_lab "$out" "Tomcat $h")
        acc=$(_worse "$acc" "$out")
    done
    TOMCAT_HOME="$_keep"; _HP_FILTER=""; echo "$acc"
}
_tc_ev() {   # 증적: 인스턴스마다 명령 실행 (명령 안에서 $TOMCAT_HOME 사용)
    local h; [ -n "$TOMCAT_HOMES" ] || { echo "Tomcat 인스턴스 없음"; return 0; }
    for h in $TOMCAT_HOMES; do echo "== [Tomcat 인스턴스] $h (home: $(_tc_home "$h"))"; ( TOMCAT_HOME="$h"; eval "$1" ) 2>&1; done
}
_je_each() {
    local fn="$1" h out acc="" many=0 _keep="$JEUS_HOME"
    many=1
    for h in $JEUS_HOMES; do
        JEUS_HOME="$h"; _HP_FILTER="$h"; out=$($fn </dev/null)
        [ -n "$out" ] || continue
        [ "$many" = 1 ] && out=$(_worse_lab "$out" "JEUS $h")
        acc=$(_worse "$acc" "$out")
    done
    JEUS_HOME="$_keep"; _HP_FILTER=""; echo "$acc"
}
_je_ev() { local h; [ -n "$JEUS_HOMES" ] || { echo "JEUS 홈 없음"; return 0; }; for h in $JEUS_HOMES; do echo "== [JEUS] $h"; ( JEUS_HOME="$h"; eval "$1" ) 2>&1; done; }

# Tomcat 설정 파일 (인스턴스 conf → 없으면 home conf)
_tc_f() { if [ -e "$TOMCAT_HOME/conf/$1" ]; then echo "$TOMCAT_HOME/conf/$1"; else echo "$(_tc_home "$TOMCAT_HOME")/conf/$1"; fi; }
_tcx() { local f; f=$(_tc_f "$1"); [ -r "$f" ] && _xml_nc < "$f"; }                  # 주석 제거한 설정 내용
_tc_need() {   # _tc_need 파일... : 없거나 읽을 수 없으면 '점검불가|사유' 출력 후 실패
    local f p
    for f in "$@"; do
        p=$(_tc_f "$f")
        if [ ! -e "$p" ]; then
            case "$f" in context.xml|tomcat-users.xml) continue ;; esac   # 선택 파일(없을 수 있음)
            echo "점검불가|Tomcat 설정 파일 없음: $p"; return 1
        elif [ ! -r "$p" ]; then echo "점검불가|Tomcat 설정 파일 읽기 권한 없음: $p (실행 계정 $(_me))"; return 1; fi
    done
    return 0
}
_tc_apps() { ls -d "$TOMCAT_HOME"/webapps/*/ 2>/dev/null | sed 's#/$##'; }
_tc_webxmls() { local f; for f in "$(_tc_f web.xml)" "$TOMCAT_HOME"/webapps/*/WEB-INF/web.xml; do [ -f "$f" ] && echo "$f"; done; }
_tc_webxml_active() {   # _tc_webxml_active 패턴 : 주석 제외 후 일치하는 web.xml 경로 출력(없으면 실패)
    local f hit=""
    for f in $(_tc_webxmls); do [ -r "$f" ] && _xml_nc < "$f" | grep -qiE "$1" && hit="${hit} ${f}"; done
    [ -n "$hit" ] && { echo "${hit# }"; return 0; }; return 1
}
_TCU() { _tc_f tomcat-users.xml; }
_tc_admins() { local f; f=$(_TCU); [ -r "$f" ] && _xml_nc < "$f" | grep -iE '<user ' | grep -iE 'roles="[^"]*(manager-|admin-|admin"|manager")'; }

# JEUS 설정 파일 검색 (find -maxdepth 대신 glob)
_JX() {   # _JX 파일명 [최대개수]
    local n="$1" J="$JEUS_HOME" p f
    [ -n "$J" ] || return 0
    for p in "$J/$n" "$J/config/$n" "$J/config/"*"/$n" "$J/domains/"*"/config/$n" "$J/domains/"*"/config/"*"/$n" "$J/domains/"*"/config/"*"/"*"/$n" \
             "$J/domains/"*"/servers/"*"/$n" "$J/domains/"*"/servers/"*"/"*"/$n" "$J/domains/"*"/applications/"*"/WEB-INF/$n" \
             "$J/domains/"*"/applications/"*"/"*"/WEB-INF/$n" "$J/webhome/"*"/WEB-INF/$n" "$J/webhome/"*"/"*"/WEB-INF/$n" "$J/"*"/WEB-INF/$n" "$J/"*"/"*"/WEB-INF/$n" "$J/samples/"*"/WEB-INF/$n"; do
        [ -f "$p" ] && echo "$p"
    done | sort -u | sed -n "1,${2:-20}p"
}

# 비밀번호 강도 (가이드: 2종 10자 이상 또는 3종 8자 이상, 계정명·기본값·연속 문자 금지)
_pw_strong() {
    local pw="$1" id="$2" n=0
    [ -n "$pw" ] || return 1
    case "$pw" in *[A-Z]*) n=$((n+1)) ;; esac; case "$pw" in *[a-z]*) n=$((n+1)) ;; esac
    case "$pw" in *[0-9]*) n=$((n+1)) ;; esac; case "$pw" in *[!A-Za-z0-9]*) n=$((n+1)) ;; esac
    echo "$pw" | grep -qiE "^(tomcat|admin|s3cret|password|manager|root|jeus|webtob|changeit|<must-be-changed>)" && return 1
    [ -n "$id" ] && echo "$pw" | grep -qiF -- "$id" && return 1
    echo "$pw" | grep -qE '(0123|1234|2345|3456|4567|5678|6789|abcd|qwer|1111|0000|aaaa)' && return 1
    { [ "$n" -ge 2 ] && [ "${#pw}" -ge 10 ]; } || { [ "$n" -ge 3 ] && [ "${#pw}" -ge 8 ]; }
}

# ── 증적 요약 ──────────────────────────────────────────────────
_detect_summary() {
    echo "웹서버: ${WEB_LIST:-없음} / WAS: ${WAS_LIST:-없음}"
    echo "Apache 설정: ${APACHE_CONF:-미발견}  Nginx 설정: ${NGINX_CONF:-미발견}  WebtoB http.m: ${_WT_M:-미발견}"
    echo "Tomcat 인스턴스(catalina.base): ${TOMCAT_HOMES:-없음}  JEUS 홈: ${JEUS_HOMES:-없음}"
    echo "탐지 근거: ${DETECT_NOTE:-없음}"
}

# ── 설정 사용 가능 여부 (제품은 탐지됐는데 설정을 못 읽으면 점검불가) ──────────
_AP_UN=""; _NG_UN=""; _WT_UN=""; _JE_UN=""
_APX=""; _NGX=""
_setup_conf() {
    local bad
    if _hasw apache; then
        if [ -z "$APACHE_CONF" ]; then _AP_UN="Apache 가 탐지됐으나(${DETECT_AP:-프로세스/바이너리}) 설정 파일(httpd.conf/apache2.conf)을 찾지 못함 - 설정 경로 확인 필요"
        elif [ ! -e "$APACHE_CONF" ]; then _AP_UN="Apache 설정 파일 없음: ${APACHE_CONF} - 설정 경로(APACHE_CONF) 확인 필요"
        elif [ ! -r "$APACHE_CONF" ]; then _AP_UN="Apache 설정 파일 읽기 권한 없음: ${APACHE_CONF} (실행 계정 $(_me))"
        else
            _APX=$(_expand_conf apache "$APACHE_CONF" "$(_ap_default_root)")
            [ -n "$_APX" ] || _AP_UN="Apache 설정 파일을 읽지 못함: ${APACHE_CONF}"
            # ServerRoot 지정이 있으면 상대 Include 를 다시 전개
            local sr; sr=$(printf '%s\n' "$_APX" | awk -F'\t' 'tolower($3) ~ /^serverroot[ \t]/ { print $3; exit }' | awk '{print $2}' | tr -d '"')
            [ -n "$sr" ] && [ -d "$sr" ] && _APX=$(_expand_conf apache "$APACHE_CONF" "$sr")
            bad=$(printf '%s\n' "$_APX" | awk -F'\t' '$3 == "@@UNREADABLE" { printf "%s ", $1 }'); [ -n "$bad" ] && _AP_UN="Apache Include 설정 파일 읽기 권한 없음: ${bad}(실행 계정 $(_me))"
        fi
    fi
    if _hasw nginx; then
        if [ -z "$NGINX_CONF" ]; then _NG_UN="Nginx 가 탐지됐으나(${DETECT_NG:-프로세스/바이너리}) 설정 파일(nginx.conf)을 찾지 못함 - 설정 경로 확인 필요"
        elif [ ! -e "$NGINX_CONF" ]; then _NG_UN="Nginx 설정 파일 없음: ${NGINX_CONF} - 설정 경로(NGINX_CONF) 확인 필요"
        elif [ ! -r "$NGINX_CONF" ]; then _NG_UN="Nginx 설정 파일 읽기 권한 없음: ${NGINX_CONF} (실행 계정 $(_me))"
        else
            _NGX=$(_expand_conf nginx "$NGINX_CONF" "$(dirname "$NGINX_CONF")")
            [ -n "$_NGX" ] || _NG_UN="Nginx 설정 파일을 읽지 못함: ${NGINX_CONF}"
            bad=$(printf '%s\n' "$_NGX" | awk -F'\t' '$3 == "@@UNREADABLE" { printf "%s ", $1 }'); [ -n "$bad" ] && _NG_UN="Nginx include 설정 파일 읽기 권한 없음: ${bad}(실행 계정 $(_me))"
        fi
    fi
    if _hasw webtob; then
        if [ -z "$_WT_M" ]; then _WT_UN="WebtoB 가 탐지됐으나(${DETECT_WT:-wsadmin/프로세스}) 설정 파일 http.m 을 찾지 못함 - WEBTOBDIR 확인 필요"
        elif [ ! -r "$_WT_M" ]; then _WT_UN="WebtoB http.m 읽기 권한 없음: ${_WT_M} (실행 계정 $(_me))"; fi
    fi
    if _hasw jeus; then
        if [ -z "$(for _h in $JEUS_HOMES; do JEUS_HOME=$_h _JX domain.xml 1; done)" ]; then
            _JE_UN="JEUS 홈(${JEUS_HOMES})에서 domain.xml 등 설정 파일을 찾지 못함 - 도메인 경로 확인 필요"
        fi
    fi
}

# ── 실제 HTTP 응답 수집 (리슨 중인 로컬 HTTP/HTTPS 포트에 3초 타임아웃으로 요청) ──────────────────
#   GET /  (상태코드·Server·Location 등 헤더, 본문 목록 노출 여부) / GET /없는경로 (기본 에러 페이지) / TRACE /
#   curl → 없으면 wget. 응답은 임시 디렉터리에 저장하고 증적에는 요청 명령과 응답 헤더를 그대로 남긴다.
_HPD=""; _HP_TOOL=""; _HP_TARGETS=""; _HP_NOTE=""
_hp_init() {
    _HPD=$(mktemp -d "${TMPDIR:-/tmp}/webwas_http.XXXXXX" 2>/dev/null) || { _HPD="${TMPDIR:-/tmp}/webwas_http.$$"; rm -rf "$_HPD"; mkdir "$_HPD" 2>/dev/null || _HPD=""; }
    if command -v curl >/dev/null 2>&1; then _HP_TOOL=curl
    elif command -v wget >/dev/null 2>&1; then _HP_TOOL=wget; fi
    [ -n "$_HPD" ] || _HP_NOTE="임시 디렉터리 생성 실패"
    [ -n "$_HP_TOOL" ] || _HP_NOTE="${_HP_NOTE:+$_HP_NOTE, }curl/wget 없음"
}
_hp_cleanup() { [ -n "$_HPD" ] && [ -d "$_HPD" ] && rm -rf "$_HPD"; }

# 리슨 중인 TCP 포트 표 "포트<TAB>바인드주소" (ss → netstat). 도구가 없으면 비어 있고 _HP_LISTEN_OK=0
_HP_LISTEN_OK=0; _HP_LISTEN=""
_hp_listen_load() {
    local raw=""
    if command -v ss >/dev/null 2>&1; then raw=$(ss -ltn 2>/dev/null); fi
    if [ -z "$raw" ] && command -v netstat >/dev/null 2>&1; then raw=$(netstat -an 2>/dev/null | grep -i 'LISTEN'); fi
    [ -n "$raw" ] || return 0
    _HP_LISTEN_OK=1
    _HP_LISTEN=$(printf '%s\n' "$raw" | awk '/LISTEN/ { for (i = 1; i <= NF; i++) if ($i ~ /[.:][0-9]+$/ && $i !~ /^[0-9]+$/) { a = $i; p = $i; sub(/.*[.:]/, "", p); sub(/[.:][0-9]+$/, "", a); gsub(/[\[\]]/, "", a); print p "\t" a; break } }' | sort -u)
}
_hp_bind() {   # 포트의 연결 대상 주소 (와일드카드 → 127.0.0.1, 특정 IPv4 바인드 → 그 주소)
    local a; a=$(printf '%s\n' "$_HP_LISTEN" | awk -F'\t' -v p="$1" '$1 == p { print $2 }' | sort -u)
    case " $(echo $a) " in *" 0.0.0.0 "*|*" * "*|*" :: "*|*" "*":"*) echo 127.0.0.1; return ;; esac
    case "$(echo $a | awk '{print $1}')" in [0-9]*.[0-9]*.[0-9]*.[0-9]*) echo $a | awk '{print $1}' ;; *) echo 127.0.0.1 ;; esac
}
_hp_is_listening() { [ "$_HP_LISTEN_OK" = 1 ] || return 0; printf '%s\n' "$_HP_LISTEN" | awk -F'\t' -v p="$1" '$1 == p { f = 1 } END { exit !f }'; }

# 대상 등록: _hp_add 제품 포트 http|https 출처
_hp_add() {
    case "$2" in ''|*[!0-9]*) return ;; esac
    [ "$2" -ge 1 ] && [ "$2" -le 65535 ] || return
    case "
$_HP_TARGETS
" in *"
$1|$2|"*) return ;; esac
    _HP_TARGETS="${_HP_TARGETS:+$_HP_TARGETS
}$1|$2|$3|$4"
}
_hp_collect_targets() {
    local l p s h c
    if _hasw apache && [ -z "$_AP_UN" ]; then
        # Listen 지시자 + 443 계열 가상호스트(SSLEngine on)
        _active 'Listen[[:space:]]' | while read -r _ _a _b; do
            p="${_a##*:}"; s=http; [ "$_b" = https ] && s=https; case "$p" in 443|8443|9443) s=https ;; esac
            echo "apache|$p|$s|Listen $_a"
        done > "$_HPD/apache.t" 2>/dev/null
        _ap_vh 'SSLEngine[[:space:]]+on' | awk -F'\t' '$2 == 1 && $1 ~ /^vhost/ { print $1 }' | while read -r _ v; do
            p=$(echo "$v" | sed 's/^[^ ]* //; s/.*:\([0-9]*\)>*$/\1/'); echo "apache|$p|https|SSLEngine on 가상호스트"
        done >> "$_HPD/apache.t" 2>/dev/null
        while IFS='|' read -r h p s l; do _hp_add "$h" "$p" "$s" "$l"; done < "$_HPD/apache.t"
    fi
    if _hasw nginx && [ -z "$_NG_UN" ]; then
        _ngx '^listen[[:space:]]' | while read -r _ a rest; do
            a="${a%;}"; rest="${rest%;}"
            case "$a" in unix:*) continue ;; esac
            p="${a##*:}"; case "$p" in ''|*[!0-9]*) continue ;; esac
            s=http; case " $rest " in *" ssl "*) s=https ;; esac
            echo "nginx|$p|$s|listen $a $rest"
        done > "$_HPD/nginx.t" 2>/dev/null
        while IFS='|' read -r h p s l; do _hp_add "$h" "$p" "$s" "$l"; done < "$_HPD/nginx.t"
    fi
    if _hasw webtob && [ -z "$_WT_UN" ]; then
        s=http; _wtm 'SSLFLAG[[:space:]]*=[[:space:]]*Y' >/dev/null 2>&1 && s=https
        _wtm '^[[:space:]]*PORT[[:space:]]*=' | grep -oE '[0-9]+' | while read -r p; do echo "webtob|$p|$s|http.m PORT"; done > "$_HPD/webtob.t" 2>/dev/null
        while IFS='|' read -r h p s l; do _hp_add "$h" "$p" "$s" "$l"; done < "$_HPD/webtob.t"
    fi
    if _hasw tomcat; then
        for h in $TOMCAT_HOMES; do
            [ -r "$h/conf/server.xml" ] || continue
            _xml_nc < "$h/conf/server.xml" | tr '\n' ' ' | grep -oE '<Connector[^>]*>' | grep -viE 'protocol="AJP|protocol="org.apache.coyote.ajp' | while read -r l; do
                p=$(echo "$l" | grep -oE ' port="[0-9]+"' | grep -oE '[0-9]+'); [ -n "$p" ] || continue
                s=http; echo "$l" | grep -qiE 'SSLEnabled="true"|scheme="https"' && s=https
                echo "tomcat|$p|$s|Connector $h"
            done > "$_HPD/tomcat.t" 2>/dev/null
            while IFS='|' read -r c p s l; do _hp_add "$c" "$p" "$s" "$l"; done < "$_HPD/tomcat.t"
        done
    fi
    if _hasw jeus; then
        for h in $JEUS_HOMES; do
            for f in $(JEUS_HOME=$h _JX domain.xml 5); do
                [ -r "$f" ] || continue
                _xml_nc < "$f" | tr '\n' ' ' | grep -oE '<(http-listener|web-connection|listener)>.*</(http-listener|web-connection|listener)>' | grep -oE '<(listen-)?port>[0-9]+' | grep -oE '[0-9]+' | while read -r p; do
                    echo "jeus|$p|http|JEUS $f"
                done > "$_HPD/jeus.t" 2>/dev/null
                while IFS='|' read -r c p s l; do _hp_add "$c" "$p" "$s" "$l"; done < "$_HPD/jeus.t"
            done
        done
    fi
    # 리슨 중이 아닌 포트(서버 중지·다른 인터페이스 전용)는 제외 — 리슨 목록을 얻지 못했으면 전부 시도
    local keep="" line pp
    while IFS= read -r line; do
        [ -n "$line" ] || continue
        pp=$(echo "$line" | cut -d'|' -f2)
        _hp_is_listening "$pp" && keep="${keep:+$keep
}$line"
    done <<EOF
$_HP_TARGETS
EOF
    _HP_TARGETS="$keep"
}

# 요청 한 건: _hp_req 메서드 URL 출력파일 → 헤더(+요청 명령)를 출력파일에, 본문은 출력파일.body. 상태코드를 출력
_hp_req() {
    local m="$1" url="$2" out="$3" rc=0 cmd
    : > "$out"; : > "$out.body"
    if [ "$_HP_TOOL" = curl ]; then
        cmd="curl -s -k --noproxy '*' -m 3 --connect-timeout 3 -X $m -D - -o <본문> $url"
        printf '$ %s\n' "$cmd" > "$out"
        curl -s -k --noproxy '*' -m 3 --connect-timeout 3 -X "$m" -D - -o "$out.body" "$url" 2>/dev/null </dev/null | tr -d '\r' >> "$out"; rc=${PIPESTATUS[0]}
    else
        cmd="wget -S -q -T 3 -t 1 --no-proxy --no-check-certificate --max-redirect=0 -O <본문> $url"
        [ "$m" = GET ] || cmd="wget -S -q -T 3 -t 1 --no-proxy --no-check-certificate --max-redirect=0 --method=$m -O <본문> $url"
        printf '$ %s\n' "$cmd" > "$out"
        if [ "$m" = GET ]; then wget -S -q -T 3 -t 1 --no-proxy --no-check-certificate --max-redirect=0 -O "$out.body" "$url" 2>&1 </dev/null | tr -d '\r' | sed 's/^  //' >> "$out"; rc=${PIPESTATUS[0]}
        else wget -S -q -T 3 -t 1 --no-proxy --no-check-certificate --max-redirect=0 --method="$m" -O "$out.body" "$url" 2>&1 </dev/null | tr -d '\r' | sed 's/^  //' >> "$out"; rc=${PIPESTATUS[0]}; fi
    fi
    local st; st=$(awk 'toupper($0) ~ /^HTTP\// { c = $2 } END { print c }' "$out")
    if [ -z "$st" ]; then printf '(응답 없음: %s 종료코드 %s - 연결 거부/시간 초과/프로토콜 불일치)\n' "$_HP_TOOL" "$rc" >> "$out"; fi
    echo "$st"
}
_hp_probe_all() {
    local line prod port sch org bind st alt other rnd
    [ -n "$_HP_TARGETS" ] || return 0
    [ -n "$_HP_TOOL" ] && [ -n "$_HPD" ] || return 0
    _hp_listen_done=""
    while IFS='|' read -r prod port sch org; do
        [ -n "$port" ] || continue
        case " $_hp_listen_done " in *" $port "*) continue ;; esac
        _hp_listen_done="$_hp_listen_done $port"
        bind=$(_hp_bind "$port")
        other=http; [ "$sch" = http ] && other=https
        st=$(_hp_req GET "$sch://$bind:$port/" "$_HPD/p$port.get")
        alt="$sch"
        if [ -z "$st" ]; then
            st=$(_hp_req GET "$other://$bind:$port/" "$_HPD/p$port.get2")
            if [ -n "$st" ]; then alt="$other"; mv "$_HPD/p$port.get2" "$_HPD/p$port.get"; mv "$_HPD/p$port.get2.body" "$_HPD/p$port.get.body" 2>/dev/null
            else cat "$_HPD/p$port.get2" >> "$_HPD/p$port.get"; rm -f "$_HPD/p$port.get2" "$_HPD/p$port.get2.body"; fi
        fi
        printf '%s\t%s\t%s\n' "$alt" "$bind" "${st:-}" > "$_HPD/p$port.meta"
        [ -n "$st" ] || continue
        rnd="webwas-probe-$$-${RANDOM:-1}"
        _hp_req GET "$alt://$bind:$port/$rnd/none.html" "$_HPD/p$port.err" >/dev/null
        _hp_req TRACE "$alt://$bind:$port/" "$_HPD/p$port.trc" >/dev/null
    done <<EOF
$_HP_TARGETS
EOF
}
# 응답 조회 도우미
_HP_FILTER=""   # 인스턴스 경로(Tomcat/JEUS 다중 인스턴스에서 해당 인스턴스 포트만)
_hp_ports() { printf '%s\n' "$_HP_TARGETS" | awk -F'|' -v p="$1" -v h="$_HP_FILTER" '$1 == p && (h == "" || index($4, h)) { print $2 }' | sort -un; }          # 제품의 포트 목록
_hp_ok() { [ -s "$_HPD/p$1.meta" ] && [ -n "$(cut -f3 "$_HPD/p$1.meta")" ]; }                                  # 응답을 받았는지
_hp_scheme() { cut -f1 "$_HPD/p$1.meta" 2>/dev/null; }
_hp_status() { awk 'toupper($0) ~ /^HTTP\// { c = $2 } END { print c }' "$_HPD/p$1.$2" 2>/dev/null; }          # 포트 종류(get|err|trc)
_hp_hdr() {   # _hp_hdr 포트 종류 헤더명 : 마지막 응답의 헤더 값
    awk -v n="$(echo "$3" | tr 'A-Z' 'a-z')" 'toupper($0) ~ /^HTTP\// { v = "" } { i = index($0, ":"); if (i > 0 && tolower(substr($0, 1, i - 1)) == n) { v = substr($0, i + 1); sub(/^[ \t]+/, "", v) } } END { print v }' "$_HPD/p$1.$2" 2>/dev/null
}
_hp_body_has() { [ -s "$_HPD/p$1.$2.body" ] && grep -qiE -- "$3" "$_HPD/p$1.$2.body" 2>/dev/null; }
_hp_body_lines() { [ -s "$_HPD/p$1.$2.body" ] && grep -iE -- "$3" "$_HPD/p$1.$2.body" 2>/dev/null; }
_hp_have() { [ -n "$_HP_TOOL" ] && [ -n "$(_hp_ports "$1")" ]; }
# 서버 헤더의 버전/OS 노출: 제품명/숫자.숫자 또는 (OS) 표기. Apache-Coyote/1.1 은 프로토콜 표기라 제외
_hp_server_leak() { printf '%s' "$1" | sed 's#Apache-Coyote/[0-9.]*##I' | grep -qE '[A-Za-z_-]+/[0-9]+(\.[0-9]+)+|\((Ubuntu|Debian|Red Hat|CentOS|Unix|Win[0-9a-z]*|Amazon|SUSE|FreeBSD)[^)]*\)'; }

# 증적 출력: _hp_ev [제품] [종류...] — 요청 명령과 응답 헤더를 그대로
_hp_ev() {
    local prod="$1"; shift
    local kinds="${*:-get err trc}" ports p k f line
    if [ -z "$_HP_TOOL" ]; then echo "HTTP 응답 수집 불가: ${_HP_NOTE:-curl/wget 없음}"; return 0; fi
    ports=$([ -n "$prod" ] && _hp_ports "$prod" || printf '%s\n' "$_HP_TARGETS" | awk -F'|' '{ print $2 }' | sort -un)
    if [ -z "$(echo $ports)" ]; then
        echo "요청 대상 없음: ${prod:-웹 제품}의 리슨 중인 HTTP 포트를 찾지 못함 (리슨 목록 $( [ "$_HP_LISTEN_OK" = 1 ] && echo '수집' || echo '수집 실패(ss/netstat 없음)' ))"; return 0
    fi
    for p in $ports; do
        echo "== ${prod:-전체} 포트 $p ($(printf '%s\n' "$_HP_TARGETS" | awk -F'|' -v p="$p" '$2 == p { printf "%s:%s ", $1, $4 }'))"
        for k in $kinds; do
            f="$_HPD/p$p.$k"
            [ -s "$f" ] && { echo "-- $k"; cat "$f"; }
            if [ "$k" = get ] && [ -s "$f.body" ]; then echo "-- 본문 중 디렉터리 목록/제품 표시 줄:"; grep -iE 'Index of|Directory [Ll]isting|<title>' "$f.body" 2>/dev/null; fi
            if [ "$k" = err ] && [ -s "$f.body" ]; then echo "-- 오류 페이지 본문 중 서버/버전 표시 줄:"; grep -iE 'Apache Tomcat|Apache/[0-9]|nginx/[0-9]|Server at|Jetty|JBoss|JEUS|WebtoB|Internal Server Error|Not Found|HTTP Status' "$f.body" 2>/dev/null; fi
        done
    done
    return 0
}

# ════════════════════════════════════════════════════════════════
# 점검 함수: _v_<점검>_<제품> 은 한 제품(인스턴스)에 대한 "판정|근거" 를 출력한다.
#   _combine <점검> <대상목록> 이 탐지된 제품마다(Tomcat·JEUS 는 인스턴스마다) 실행해 병합한다.
#   제품이 탐지됐는데 설정을 못 읽으면 '점검불가' (사유 포함). WST/WEB 두 기준이 같은 함수를 공유한다.
# ════════════════════════════════════════════════════════════════
_combine() {
    local chk="$1" T="$2" r="" x p
    for p in apache nginx webtob tomcat jeus; do
        _pt "$p" "$T" || continue
        declare -F "_v_${chk}_$p" >/dev/null 2>&1 || continue
        x=""
        case "$p" in
        apache) [ -n "$_AP_UN" ] && x="점검불가|$_AP_UN" ;;
        nginx)  [ -n "$_NG_UN" ] && x="점검불가|$_NG_UN" ;;
        webtob) [ -n "$_WT_UN" ] && x="점검불가|$_WT_UN" ;;
        tomcat) if [ -z "$TOMCAT_HOMES" ]; then x="점검불가|Tomcat 프로세스는 실행 중이나 인스턴스(catalina.base)의 conf/server.xml 을 찾지 못함 (실행 계정 $(_me))"; r=$(_worse "$r" "$(_worse_lab "$x" Tomcat)")
                else x=$(_tc_each "_v_${chk}_tomcat"); r=$(_worse "$r" "$x"); fi; continue ;;
        jeus)   if [ -n "$_JE_UN" ]; then x="점검불가|$_JE_UN"; else x=$(_je_each "_v_${chk}_jeus"); r=$(_worse "$r" "$x"); continue; fi ;;
        esac
        [ -n "$x" ] || x=$("_v_${chk}_$p" </dev/null)
        [ -n "$x" ] && r=$(_worse "$r" "$(_worse_lab "$x" "$(_pname "$p")")")
    done
    echo "$r"
}
_show() { local t="$1" o; shift; o=$("$@" 2>&1 </dev/null); printf -- '-- %s (%d줄)\n' "$t" "$(printf '%s' "$o" | grep -c '')"; [ -n "$o" ] && printf '%s\n' "$o"; return 0; }
# 응답 요약 "http:80=200 https:443=200" (증적/근거용)
_hp_sum() {
    local p o=""; _hp_have "$1" || return 0
    for p in $(_hp_ports "$1"); do _hp_ok "$p" && o="${o} $(_hp_scheme "$p"):${p}=$(_hp_status "$p" get)" || o="${o} :${p}=응답없음"; done
    echo "${o# }"
}
# 응답 보정: 설정 판정 $1 과 응답 기반 판정 $2("판정|근거") 병합.
#   응답이 취약이면 취약 우선, 응답이 양호인데 설정만 취약이면 응답을 근거로 양호(다른 구간에서 처리) 로 보정
_resp_adjust() {
    local cfg="$1" rsp="$2"
    [ -n "$rsp" ] || { echo "$cfg"; return; }
    case "${rsp%%|*}" in
    취약) _worse "$cfg" "$rsp" ;;
    양호) case "${cfg%%|*}" in 취약) echo "양호|${rsp#*|} (설정 파일에서는 확인되지 않음: ${cfg#*|} - LB/프록시/상위 설정에서 처리되는 것으로 판단, 해당 구간 설정 증빙 확인 권고)" ;; *) echo "${cfg%%|*}|${cfg#*|} / 응답: ${rsp#*|}" ;; esac ;;
    *) _worse "$cfg" "$rsp" ;;
    esac
}

# ── 디렉터리 리스팅 (WST-031 / WEB-04) ──────────────────────────
_ap_indexes() {
    _ap_scoped | awk -F'\t' '{ t = tolower($5) }
        t ~ /^options[ \t]/ { n = split(t, a, /[ \t]+/); on = 0
            for (i = 2; i <= n; i++) { if (a[i] == "indexes" || a[i] == "+indexes") on = 1; if (a[i] == "-indexes") on = 0 }
            if (on && $2 !~ /icons|noindex|\/error|manual/) printf "%s %s:%s: %s%s\n", $1, $3, $4, $5, ($2 != "" ? "  [" $2 "]" : "") }'
}
_hp_listing_hit() { local p o=""; for p in $(_hp_ports "$1"); do _hp_ok "$p" && _hp_body_has "$p" get 'Index of /|Directory [Ll]isting [Ff]or' && o="${o} $(_hp_scheme "$p"):${p}"; done; echo "${o# }"; }
_v_listing_apache() {
    local o x h; o=$(_ap_indexes)
    if [ -n "$o" ]; then x="취약|디렉터리 리스팅(Options Indexes) 허용: $(_brief "$o" 2)"
    else x="양호|Options Indexes 미사용 (아이콘·오류 샘플 디렉터리 제외)"; fi
    h=$(_hp_listing_hit apache); [ -n "$h" ] && x=$(_worse "$x" "취약|실제 HTTP 응답에 디렉터리 목록 노출(포트 $h)")
    echo "$x"
}
_v_listing_nginx() {
    local o x h; o=$(_ngxf '^autoindex[[:space:]]+on')
    if [ -n "$o" ]; then x="취약|autoindex on: $(_brief "$o" 2)"; else x="양호|autoindex on 설정 없음 (기본 off)"; fi
    h=$(_hp_listing_hit nginx); [ -n "$h" ] && x=$(_worse "$x" "취약|실제 HTTP 응답에 디렉터리 목록 노출(포트 $h)")
    echo "$x"
}
_v_listing_webtob() { if _wtm 'Options' | grep -iE 'Indexes' | grep -qv -- '-Indexes'; then echo "취약|http.m Options Indexes"; else echo "양호|http.m Options Indexes 미설정"; fi; }
_v_listing_tomcat() {
    local u f hit="" n=0 x h
    u=$(_tc_need web.xml) || { echo "$u"; return; }
    for f in $(_tc_webxmls); do
        [ -r "$f" ] || continue; n=$((n+1))
        _xml_nc < "$f" | tr '\n' ' ' | grep -qiE '<param-name>[[:space:]]*listings[[:space:]]*</param-name>[[:space:]]*<param-value>[[:space:]]*true' && hit="${hit} ${f}"
    done
    if [ -n "$hit" ]; then x="취약|DefaultServlet listings=true:${hit}"; else x="양호|listings=false(기본) - conf/web.xml·앱 web.xml ${n}개 확인"; fi
    h=$(_hp_listing_hit tomcat); [ -n "$h" ] && x=$(_worse "$x" "취약|실제 HTTP 응답에 디렉터리 목록 노출(포트 $h)")
    echo "$x"
}
_v_listing_jeus() {
    local f hit="" n=0
    for f in $(_JX jeus-web-dd.xml 50); do n=$((n+1)); [ -r "$f" ] && _xml_nc < "$f" | grep -qiE '<allow-indexing>[[:space:]]*true' && hit="${hit} ${f}"; done
    [ -n "$hit" ] && echo "취약|jeus-web-dd.xml allow-indexing=true:${hit}" || echo "양호|allow-indexing 미설정/false (jeus-web-dd.xml ${n}개)"
}
_ev_listing() {
    _cfg_scope
    _hasw apache && _show "Apache: Options Indexes 유효 위치 (Directory/VirtualHost 문맥 포함)" _ap_indexes
    _hasw apache && _show "Apache: 모든 Options 지시자" _activef 'Options[[:space:]]'
    _hasw nginx && _show "Nginx: autoindex" _ngxf '^autoindex'
    _hasw webtob && _show "WebtoB: Options" _wtmf 'Options'
    _hasw tomcat && _tc_ev 'for f in $(_tc_webxmls); do echo "-- $f"; _xml_nc < "$f" | tr "\n" " " | grep -oiE "<param-name>[[:space:]]*listings[[:space:]]*</param-name>[[:space:]]*<param-value>[^<]*"; done'
    _hasw jeus && _je_ev 'for f in $(_JX jeus-web-dd.xml 50); do echo "-- $f"; grep -iE "allow-indexing" "$f"; done'
    _hp_ev "" get
}

# ── CGI/ISAPI 실행 제한 (WEB-05) ───────────────────────────────
_v_cgi_apache() {
    local cm ah ex
    cm=$( { httpd -M 2>/dev/null || apache2ctl -M 2>/dev/null || apachectl -M 2>/dev/null; } | grep -iE 'cgid?_module'; _active 'LoadModule[[:space:]]+cgid?_module' )
    ah=$(_active 'AddHandler[[:space:]].*cgi-script' | sed -n 1p); ex=$(_active 'Options[[:space:]]' | grep -iE '(^|[[:space:]+])ExecCGI' | grep -vi -- '-ExecCGI' | sed -n 1p)
    if [ -z "$cm" ]; then echo "양호|CGI 모듈(cgi/cgid) 미사용"
    elif [ -n "$ah" ]; then echo "취약|CGI 확장자 매핑으로 지정 디렉터리 외 실행 가능: $(echo $ah)"
    elif [ -n "$ex" ]; then echo "수동확인|Options ExecCGI 설정: $(echo $ex) - 지정한 CGI 디렉터리로만 제한되는지 확인"
    else echo "양호|CGI 실행을 ScriptAlias 지정 디렉터리로 제한 ($(_active 'ScriptAlias[[:space:]]' | awk '{print $2"→"$3}' | tr '\n' ' '))"; fi
}
_v_cgi_nginx() {
    if _ngx '(fcgiwrap|location[^{]*\.(cgi|pl)|location[^{]*cgi-bin)' | grep -q .; then echo "취약|Nginx CGI(fcgiwrap/.cgi location) 실행 설정: $(_brief "$(_ngxf '(fcgiwrap|location[^{]*cgi)')" 2)"
    elif _ngx '^fastcgi_pass' | grep -q .; then echo "수동확인|FastCGI 사용(PHP-FPM 등): $(_brief "$(_ngxf '^fastcgi_pass')" 2) - 실행 경로·확장자 제한 확인"
    else echo "양호|CGI/FastCGI 미사용"; fi
}
_v_cgi_webtob() { _wtm '(SVRTYPE|Svrtype)[[:space:]]*=[[:space:]]*CGI' | grep -q . && echo "취약|http.m CGI 서버 타입 활성: $(_brief "$(_wtmf '(SVRTYPE|Svrtype)[[:space:]]*=[[:space:]]*CGI')" 2)" || echo "양호|CGI 서버 타입 미사용"; }
_v_cgi_tomcat() {
    local u f; u=$(_tc_need web.xml) || { echo "$u"; return; }
    f=$(_tc_webxml_active "CGIServlet") && echo "취약|CGIServlet 매핑 활성: ${f}" || echo "양호|CGI 매핑 비활성(기본)"
}
_ev_cgi() {
    _cfg_scope
    _hasw apache && _show "Apache: 로드된 CGI 모듈 (httpd -M)" sh -c '{ httpd -M 2>/dev/null || apache2ctl -M 2>/dev/null || apachectl -M 2>/dev/null; } | grep -i cgi'
    _hasw apache && _show "Apache: CGI 관련 지시자" _activef '(LoadModule[[:space:]]+cgid?_module|ScriptAlias|AddHandler.*cgi-script|Options.*ExecCGI)'
    _hasw nginx && _show "Nginx: CGI/FastCGI" _ngxf '(fastcgi_pass|fcgiwrap|location.*\.cgi)'
    _hasw webtob && _show "WebtoB: CGI 서버 타입" _wtmf '(SVRTYPE|Svrtype)[[:space:]]*=[[:space:]]*CGI'
    _hasw tomcat && _tc_ev 'for f in $(_tc_webxmls); do echo "-- $f"; _xml_nc < "$f" | grep -niE "CGIServlet|<servlet-name>cgi"; done'
}

# ── 상위 디렉터리 접근 제한 (WEB-06) ────────────────────────────
_v_updir_apache() {
    local ao; ao=$(_active 'AllowOverride[[:space:]]' | awk '{print $2}' | sort -uf | tr '\n' ' ')
    if echo " $ao" | grep -qiE ' (AuthConfig|All)'; then echo "양호|AllowOverride AuthConfig/All 설정 - .htaccess 사용자 인증으로 디렉터리 접근 제한 가능 (${ao% })"
    else echo "취약|AllowOverride ${ao:-미설정(None)} - 가이드 조치: AllowOverride AuthConfig + .htaccess 사용자 인증으로 상위·주요 디렉터리 접근 제한"; fi
}
_v_updir_nginx() { if _ngx '^auth_basic[[:space:]]' | grep -qv 'off'; then echo "양호|auth_basic 으로 디렉터리 접근 제한 설정"; else echo "수동확인|auth_basic 미설정 - 접근 제한이 필요한 디렉터리 존재 여부 확인"; fi; }
_v_updir_webtob() { local u; u=$(_wtm 'UpperDirRestrict' | sed -n 1p); [ -n "$u" ] && echo "수동확인|$(echo $u) - 상위 디렉터리 접근 제한 설정 확인" || echo "수동확인|UpperDirRestrict 미설정 - 상위 디렉터리 접근 제한 확인"; }
_v_updir_tomcat() {
    local u; u=$(_tc_need server.xml context.xml) || { echo "$u"; return; }
    { _tcx server.xml; _tcx context.xml; } | grep -qiE 'allowLinking="true"' && echo "취약|Context allowLinking=true" || echo "양호|allowLinking 미설정(false)"
}
_ev_updir() {
    _cfg_scope
    _hasw apache && _show "Apache: AllowOverride" _activef 'AllowOverride'
    _hasw nginx && _show "Nginx: auth_basic" _ngxf '^auth_basic'
    _hasw webtob && _show "WebtoB: UpperDirRestrict" _wtmf 'UpperDirRestrict'
    _hasw tomcat && _tc_ev 'echo "-- allowLinking"; { _tcx server.xml; _tcx context.xml; } | grep -nE "allowLinking"; ls -l "$(_tc_f server.xml)" "$(_tc_f context.xml)"'
}

# ── 웹 서비스 경로 내 불필요한 파일 (WEB-07) ─────────────────────
_v_unneeded_apache() {
    local r d df=""; r=$(_apache_root)
    [ -n "$r" ] || { echo "점검불가|Apache ServerRoot 를 확인하지 못해 기본 매뉴얼 경로를 점검할 수 없음"; return; }
    for d in "$r/manual" "$r/htdocs/manual" /var/www/manual /usr/share/httpd/manual /usr/share/doc/apache2-doc/manual /usr/local/apache2/manual $(_web_docroots_of apache | sed 's#$#/manual#'); do [ -d "$d" ] && df="${df} ${d}"; done
    df=$(echo $df | tr ' ' '\n' | sort -u | tr '\n' ' ')
    [ -n "${df// /}" ] && echo "취약|기본 매뉴얼 디렉터리 존재: ${df% }" || echo "양호|기본 매뉴얼 디렉터리 없음 (확인 경로: $r/manual 등)"
}
_web_docroots_of() { case "$1" in apache) _active 'DocumentRoot[[:space:]]' | awk '{print $2}' | tr -d '"' ;; nginx) _ngx '^root[[:space:]]' | awk '{print $2}' | tr -d ';"' ;; esac | grep -v '^$' | sort -u; }
_v_unneeded_nginx() {
    local d df="" roots; roots="$( { _web_docroots_of nginx; echo /usr/share/nginx/html; } | sort -u | tr '\n' ' ')"
    [ -n "$(_web_docroots_of nginx)" ] || [ -d /usr/share/nginx/html ] || { echo "점검불가|Nginx 문서 루트(root)를 설정에서 찾지 못해 기본 페이지를 점검할 수 없음"; return; }
    for d in $roots; do [ -f "$d/index.html" ] && grep -qi 'Welcome to nginx' "$d/index.html" 2>/dev/null && df="${df} ${d}/index.html(기본 페이지)"; done
    [ -n "$df" ] && echo "취약|기본 생성 파일 존재:${df}" || echo "양호|Nginx 기본 페이지 없음 (확인: $roots)"
}
_v_unneeded_webtob() {
    local d df=""; [ -n "$_WT_HOME" ] || { echo "점검불가|WebtoB 설치 경로를 확인하지 못함"; return; }
    for d in docs/manuals samples; do [ -d "$_WT_HOME/$d" ] && df="${df} $_WT_HOME/$d"; done
    [ -n "$df" ] && echo "취약|기본 매뉴얼·샘플 존재:${df}" || echo "양호|기본 매뉴얼·샘플 없음 ($_WT_HOME)"
}
_v_unneeded_tomcat() {
    local d df=""; [ -d "$TOMCAT_HOME/webapps" ] || { echo "점검불가|Tomcat webapps 디렉터리 없음/접근 불가: $TOMCAT_HOME/webapps"; return; }
    [ -r "$TOMCAT_HOME/webapps" ] || { echo "점검불가|Tomcat webapps 읽기 권한 없음 (실행 계정 $(_me))"; return; }
    for d in docs examples; do [ -d "$TOMCAT_HOME/webapps/$d" ] && df="${df} $TOMCAT_HOME/webapps/$d"; done
    [ -n "$df" ] && echo "취약|기본 매뉴얼·샘플 존재:${df}" || echo "양호|기본 docs/examples 없음 (webapps: $(ls "$TOMCAT_HOME/webapps" 2>/dev/null | tr '\n' ' '))"
}
_v_unneeded_jeus() {
    local d df=""; for d in docs/manuals samples; do [ -d "$JEUS_HOME/$d" ] && df="${df} $JEUS_HOME/$d"; done
    [ -n "$df" ] && echo "취약|기본 매뉴얼·샘플 존재:${df}" || echo "양호|기본 매뉴얼·샘플 없음 ($JEUS_HOME)"
}
_ev_unneeded() {
    local d
    if _hasw apache; then
        if [ -n "$(_apache_root)" ]; then
            _show "Apache: ServerRoot / DocumentRoot" sh -c "echo ServerRoot=$(_apache_root); echo DocumentRoot=$(_web_docroots_of apache | tr '\n' ' ')"
            _show "Apache: 매뉴얼 후보 경로 존재 여부" sh -c "for d in $(_apache_root)/manual $(_apache_root)/htdocs/manual /var/www/manual /usr/share/httpd/manual /usr/share/doc/apache2-doc/manual /usr/local/apache2/manual; do if [ -d \"\$d\" ]; then echo \"존재: \$d\"; else echo \"없음: \$d\"; fi; done"
        else echo "Apache ServerRoot 를 확인하지 못해 매뉴얼 경로를 점검하지 못함 (${_AP_UN:-설정 파일 미발견})"; fi
    fi
    _hasw nginx && _show "Nginx: 문서 루트의 index.html 기본 문구" sh -c "for d in $(_web_docroots_of nginx | tr '\n' ' ') /usr/share/nginx/html; do if [ -f \"\$d/index.html\" ]; then echo \"== \$d/index.html\"; grep -i 'Welcome to nginx' \"\$d/index.html\"; else echo \"없음: \$d/index.html\"; fi; done"
    _hasw tomcat && _tc_ev 'ls -l "$TOMCAT_HOME/webapps"'
    _hasw jeus && _je_ev 'for d in docs/manuals samples; do if [ -d "$JEUS_HOME/$d" ]; then echo "존재: $JEUS_HOME/$d"; else echo "없음: $JEUS_HOME/$d"; fi; done'
    if _hasw webtob; then
        if [ -n "$_WT_HOME" ]; then _show "WebtoB: 매뉴얼·샘플" sh -c "for d in docs/manuals samples; do if [ -d \"$_WT_HOME/\$d\" ]; then echo \"존재: $_WT_HOME/\$d\"; else echo \"없음: $_WT_HOME/\$d\"; fi; done"
        else echo "WebtoB 설치 경로를 확인하지 못해 매뉴얼·샘플 경로를 점검하지 못함 (${_WT_UN:-http.m 미발견})"; fi
    fi
}

# ── 파일 업로드·다운로드 용량 제한 (WST-035 / WEB-08) ─────────────
_v_upload_apache() {
    local vh glob miss
    vh=$(_ap_vh 'LimitRequestBody[[:space:]]+[1-9]')
    glob=$(echo "$vh" | awk -F'\t' '$1 == "global" { print $2 }')
    miss=$(echo "$vh" | awk -F'\t' '$1 != "global" && $2 == 0 { print $1 }' | tr '\n' ',' | sed 's/,$//')
    if [ "$glob" = 1 ]; then echo "양호|LimitRequestBody 전역 설정: $(echo "$vh" | awk -F'\t' '$1 == "global" { print $3 }')"
    elif [ -z "$(echo "$vh" | grep -v '^global')" ]; then echo "취약|LimitRequestBody 미설정(또는 0=무제한)"
    elif [ -n "$miss" ]; then echo "취약|LimitRequestBody 미설정 가상호스트: ${miss} (전역 설정 없음)"
    else echo "양호|모든 가상호스트에 LimitRequestBody 설정"; fi
}
_v_upload_nginx() {
    local z v; z=$(_ng_scoped | awk -F'\t' '$5 ~ /^client_max_body_size[ \t]+0[kKmMgG]?$/ { print $1 ":" $5 }' | tr '\n' ' ')
    v=$(_ngx '^client_max_body_size[[:space:]]' | awk '{print $2}' | tr '\n' ' ')
    [ -n "$z" ] && echo "취약|client_max_body_size 0 (제한 해제): ${z}" || echo "양호|client_max_body_size ${v:-미설정(기본 1m 제한)}"
}
_v_upload_webtob() { _wtm 'LimitRequestBody' | grep -q . && echo "양호|$(_wtm 'LimitRequestBody' | sed -n 1p | tr -s ' ')" || echo "취약|LimitRequestBody 미설정"; }
_v_upload_tomcat() {
    local u mp mf; u=$(_tc_need server.xml web.xml) || { echo "$u"; return; }
    mp=$(_tcx server.xml | grep -oE 'maxPostSize="[^"]*"' | cut -d'"' -f2 | tr '\n' ' ')
    mf=$(for f in $(_tc_webxmls); do _xml_nc < "$f" | grep -hE '<max-(file|request)-size>' ; done | sed -n 1p)
    if echo " $mp" | grep -qE ' -[0-9]'; then echo "취약|maxPostSize 음수(제한 해제): ${mp}"
    elif [ -n "${mp// /}" ] || [ -n "$mf" ]; then echo "양호|용량 제한 설정 (maxPostSize=${mp:-기본 2MB}${mf:+, multipart-config })"
    else echo "수동확인|maxPostSize·multipart-config 미설정 (폼 POST 기본 2MB만 적용) - 애플리케이션 업로드 용량 제한 확인"; fi
}
_v_upload_jeus() {
    local f hit=""; for f in $(_JX web.xml 50) $(_JX domain.xml 5); do [ -r "$f" ] && _xml_nc < "$f" | grep -qE '<max-(file|post)-size>[[:space:]]*[0-9]' && hit="${hit} ${f}"; done
    [ -n "$hit" ] && echo "양호|JEUS 용량 제한(max-file-size/max-post-size) 설정:${hit}" || echo "취약|JEUS web.xml max-file-size 미설정 (가이드: 출력값 없으면 취약)"
}
_ev_upload() {
    _cfg_scope
    _hasw apache && _show "Apache: LimitRequestBody 가상호스트별 (문맥 / 설정여부 / 내용)" _ap_vh 'LimitRequestBody[[:space:]]+[1-9]'
    _hasw apache && _show "Apache: LimitRequestBody 모든 지시자" _activef 'LimitRequestBody'
    _hasw nginx && _show "Nginx: client_max_body_size" _ngxf '^client_max_body_size'
    _hasw webtob && _show "WebtoB: LimitRequestBody" _wtmf 'LimitRequestBody'
    _hasw tomcat && _tc_ev 'echo "-- maxPostSize"; _tcx server.xml | grep -noE "maxPostSize=\"[^\"]*\""; echo "-- multipart-config/max-file-size"; for f in $(_tc_webxmls); do _xml_nc < "$f" | grep -HnE "multipart-config|max-(file|request)-size" | sed "s#^(standard input)#$f#"; done'
    _hasw jeus && _je_ev 'for f in $(_JX web.xml 50) $(_JX domain.xml 5); do echo "-- $f"; _xml_nc < "$f" | grep -nE "max-(file|post)-size"; done'
}

# ── 웹 서비스 프로세스 권한 (WST-036 / WEB-09) ───────────────────
_PSUSR=""
_psu() {   # _psu 실행파일명정규식 : 해당 이름으로 실행 중인 프로세스의 계정 목록
    printf '%s\n' "$_PSUSR" | awk -v re="$1" '{ c = $2; sub(/.*\//, "", c); if (c ~ re) print $1 }' | sort -u | tr '\n' ' '
}
_psu_java() {   # _psu_java 인자부분문자열 : java 로 실행 중이고 인자에 부분문자열(뒤가 공백/끝)이 있는 프로세스 계정
    printf '%s\n' "$_PSUSR" | awk -v k="$1" '{ c = $2; sub(/.*\//, "", c); if (c !~ /^(java|jsvc|jeus.*|jrunscript)$/) next
        i = index($0, k); if (i == 0) next; r = substr($0, i + length(k), 1); if (r == "" || r == " ") print $1 }' | sort -u | tr '\n' ' '
}
_isroot() { local u; for u in $1; do { [ "$u" = root ] || [ "$(id -u "$u" 2>/dev/null)" = 0 ]; } && return 0; done; return 1; }
_v_webproc_apache() {
    local u; u=$(_psu '^(httpd|apache2|httpd\.(worker|event|prefork)|apache)$')
    local nr; nr=$(echo $u | tr ' ' '\n' | grep -vx root | tr '\n' ' ')   # 마스터는 root 기동이 정상(포트 바인딩), 작업 프로세스 계정 확인
    [ -n "$nr" ] && u="$nr"
    if [ -z "${u// /}" ]; then
        u=$(_active 'User[[:space:]]' | awk '{print $2}' | sed -n 1p)
        case "$u" in \$*) u=$(grep -hE "^[[:space:]]*(export[[:space:]]+)?APACHE_RUN_USER=" /etc/apache2/envvars /etc/sysconfig/httpd 2>/dev/null | tail -1 | cut -d= -f2 | tr -d "\"' ") ;; esac
        [ -n "$u" ] && { if _isroot "$u"; then echo "취약|미실행 - 설정 User 가 root: ${u}"; else echo "양호|미실행 - 설정 User=${u} (비관리자)"; fi; return; }
        echo "점검불가|Apache 프로세스가 실행 중이 아니고 설정에도 User 가 없어 구동 계정을 확인하지 못함"; return
    fi
    if _isroot "$u"; then echo "취약|Apache 작업 프로세스가 관리자(root) 권한: ${u}"; else echo "양호|Apache 작업 프로세스 계정: ${u% }"; fi
}
_v_webproc_nginx() {
    local u; u=$(_psu '^nginx:?$'); local nr; nr=$(echo $u | tr ' ' '\n' | grep -vx root | tr '\n' ' '); [ -n "$nr" ] && u="$nr"
    if [ -z "${u// /}" ]; then
        u=$(_ngx '^user[[:space:]]' | awk '{print $2}' | tr -d ';' | sed -n 1p)
        [ -n "$u" ] && { if _isroot "$u"; then echo "취약|미실행 - 설정 user 가 root: ${u}"; else echo "양호|미실행 - 설정 user=${u} (비관리자)"; fi; return; }
        echo "점검불가|Nginx 프로세스가 실행 중이 아니고 설정에도 user 지시자가 없어 worker 계정을 확인하지 못함"; return
    fi
    if _isroot "$u"; then echo "취약|Nginx worker 가 관리자(root) 권한: ${u}"; else echo "양호|Nginx worker 계정: ${u% }"; fi
}
_v_webproc_webtob() {
    local u; u=$(_psu '^(wsm|htl|hth|hts)$')
    if [ -z "${u// /}" ]; then echo "점검불가|WebtoB 프로세스(wsm/htl/hth)가 실행 중이 아니어서 구동 계정을 확인하지 못함"
    elif _isroot "$u"; then echo "취약|WebtoB 가 관리자(root) 권한으로 구동: ${u}"; else echo "양호|WebtoB 구동 계정: ${u% }"; fi
}
_v_webproc_tomcat() {
    local u; u=$(_psu_java "-Dcatalina.base=$TOMCAT_HOME")
    if [ -z "${u// /}" ]; then echo "점검불가|Tomcat 인스턴스가 실행 중이 아니어서 구동 계정을 확인하지 못함 (서비스 유닛 User 확인 필요)"
    elif _isroot "$u"; then echo "취약|Tomcat 이 관리자(root) 권한으로 구동: ${u}"; else echo "양호|Tomcat 구동 계정: ${u% }"; fi
}
_v_webproc_jeus() {
    local u; u=$(_psu_java "-Djeus.home=$JEUS_HOME")
    if [ -z "${u// /}" ]; then echo "점검불가|JEUS 가 실행 중이 아니어서 구동 계정을 확인하지 못함"
    elif _isroot "$u"; then echo "취약|JEUS 가 관리자(root) 권한으로 구동: ${u}"; else echo "양호|JEUS 구동 계정: ${u% }"; fi
}
_ps_web() {   # 웹/WAS 프로세스만(실행 파일명 기준) 전체 인자 출력 - 비밀번호 계열 인자는 마스킹
    UNIX95=1 ps -eo user=,pid=,ppid=,args= 2>/dev/null | awk '{ c = $4; sub(/.*\//, "", c)
        if (c ~ /^(httpd|apache2|nginx:?|wsm|htl|hth|hts|httpd\.(worker|event|prefork))$/ || (c ~ /^(java|jsvc)$/ && $0 ~ /catalina|jeus\.home/)) print }' | _mask_pw
}
_ev_webproc() {
    _show "웹/WAS 프로세스 (계정 PID PPID 명령 전체, 비밀번호 인자는 마스킹)" _ps_web
    _hasw apache && _show "Apache: User/Group 지시자" _activef '(User|Group)[[:space:]]'
    _hasw nginx && _show "Nginx: user 지시자" _ngxf '^user[[:space:]]'
}

# ── 불필요한 프록시 설정 (WST-121 / WEB-10) ──────────────────────
_v_proxy_apache() {
    if _active 'ProxyRequests[[:space:]]+On' | grep -q .; then echo "취약|ProxyRequests On (포워드/오픈 프록시 허용)"
    elif _active 'ProxyPass(Match)?[[:space:]]' | grep -q .; then echo "수동확인|역프록시 설정: $(_brief "$(_activef 'ProxyPass(Match)?[[:space:]]')" 2) - 업무상 필요 여부 확인 (불필요 시 취약)"
    else echo "양호|프록시 설정 없음"; fi
}
_v_proxy_nginx() { _ngx '^proxy_pass[[:space:]]' | grep -q . && echo "수동확인|proxy_pass 설정: $(_brief "$(_ngxf '^proxy_pass[[:space:]]')" 2) - 업무상 필요 여부 확인 (불필요 시 취약)" || echo "양호|프록시 설정 없음"; }
_v_proxy_webtob() { _wtm 'REVERSE_PROXY' | grep -q . && echo "수동확인|REVERSE_PROXY 설정 - 업무상 필요 여부 확인" || echo "양호|프록시 설정 없음"; }
_v_proxy_tomcat() {
    local u; u=$(_tc_need server.xml) || { echo "$u"; return; }
    _tcx server.xml | grep -qE 'proxyName=|proxyPort=' && echo "수동확인|Connector proxyName/proxyPort 설정 - 업무상 필요 여부 확인" || echo "양호|Connector 프록시 설정 없음"
}
_v_proxy_jeus() { local d f=""; for d in "$JEUS_HOME"/*/ReverseProxy "$JEUS_HOME"/ReverseProxy; do [ -e "$d" ] && f="${f} ${d}"; done; [ -n "$f" ] && echo "수동확인|ReverseProxy 애플리케이션 존재:${f} - 필요 여부 확인" || echo "양호|ReverseProxy 없음"; }
_ev_proxy() {
    _cfg_scope
    _hasw apache && _show "Apache: 프록시 모듈/지시자" _activef '(LoadModule[[:space:]]+proxy|ProxyRequests|ProxyPass)'
    _hasw nginx && _show "Nginx: proxy_pass" _ngxf '^proxy_pass'
    _hasw webtob && _show "WebtoB: REVERSE_PROXY" _wtmf 'REVERSE_PROXY'
    _hasw tomcat && _tc_ev 'echo "-- proxyName/proxyPort"; _tcx server.xml | grep -noE "proxy(Name|Port)=\"[^\"]*\""; ls -l "$(_tc_f server.xml)"'
    _hasw jeus && _je_ev 'for d in "$JEUS_HOME"/*/ReverseProxy "$JEUS_HOME"/ReverseProxy; do if [ -e "$d" ]; then echo "존재: $d"; else echo "없음: $d"; fi; done'
}

# ── 웹 서비스 경로 설정 (WST-037 / WEB-11) ───────────────────────
_SYSDIRS=''
_v_docroot_all_core() {   # 제품 구분 없이 문서 루트 전체를 한 번 판정 (docroot 는 제품이 공유)
    local roots d bad="" def=""
    roots="$( { _web_docroots; for h in $TOMCAT_HOMES; do TOMCAT_HOME=$h _tcx server.xml | grep -oE 'docBase="[^"]*"' | cut -d'"' -f2; done; } | sort -u | tr '\n' ' ')"
    if [ -z "${roots// /}" ]; then echo "점검불가|웹 서비스 경로(DocumentRoot/root/docBase/DOCROOT)를 설정에서 찾지 못함"; return; fi
    for d in $roots; do
        case "${d%/}" in
        ""|/|/etc|/usr|/bin|/sbin|/root|/home|/var|/opt|/tmp|/boot|/lib|/lib64|/proc|/sys|/dev) bad="${bad} ${d}" ;;
        /var/www/html|/var/www|/usr/local/apache*/htdocs|/usr/local/httpd/htdocs|/usr/share/nginx/html|/etc/nginx/html|*/webtob/docs|html) def="${def} ${d}" ;;
        esac
    done
    if [ -n "$bad" ]; then echo "취약|웹 서비스 경로가 시스템·업무 영역과 분리되지 않음:${bad}"
    elif [ -n "$def" ]; then echo "수동확인|설치 기본 경로 사용:${def} - 기타 업무와 분리 여부·불필요 경로 확인 (가이드 조치: 별도 경로 지정)"
    else echo "양호|별도 웹 서비스 경로 사용: ${roots}"; fi
}
_ev_docroot() {
    _cfg_scope
    _hasw apache && _show "Apache: DocumentRoot" _activef 'DocumentRoot'
    _hasw nginx && _show "Nginx: root" _ngxf '^root[[:space:]]'
    _hasw webtob && _show "WebtoB: DOCROOT" _wtmf 'DOCROOT'
    _hasw tomcat && _tc_ev 'echo "-- appBase/docBase"; _tcx server.xml | grep -noE "(appBase|docBase)=\"[^\"]*\""'
    _show "판정에 사용한 경로 목록" _web_docroots
}

# ── 웹 서비스 링크 (WEB-12) / 링크 파일 (WST-038) ────────────────
_findd() {   # _findd 깊이 디렉터리 find식… : -maxdepth 대신 prune 으로 깊이 제한 (POSIX)
    local n="$1" d="$2" pr="$2" i; shift 2
    for i in $(seq 1 "$n"); do pr="$pr/*"; done
    find "$d" -path "$pr/*" -prune -o "$@" -print 2>/dev/null
}
_v_links_apache() {
    local ol; ol=$(_ap_scoped | awk -F'\t' 'tolower($5) ~ /^options[ \t]/ && $2 !~ /icons|noindex|\/error|manual/ { print $5 }')   # 배포판 기본 아이콘·오류 샘플 디렉터리의 Options 는 제외 (WEB-04 와 동일)
    if [ -z "$ol" ]; then echo "취약|Options 미설정 (2.4 기본값 FollowSymLinks - 링크 허용)"
    elif echo "$ol" | grep -iE '(^|[[:space:]+])FollowSymLinks' | grep -qvi -- '-FollowSymLinks'; then echo "취약|FollowSymLinks 허용: $(echo "$ol" | grep -i FollowSymLinks | grep -vi -- -FollowSymLinks | sed -n 1p | tr -s ' ')"
    elif echo "$ol" | grep -qi 'SymLinksIfOwnerMatch'; then echo "수동확인|SymLinksIfOwnerMatch (소유자 일치 시 링크 허용) - 링크 사용 필요성 확인"
    else echo "양호|FollowSymLinks 미허용"; fi
}
_v_links_nginx() { _ngx '^disable_symlinks[[:space:]]+(on|if_not_owner)' | grep -q . && echo "양호|disable_symlinks 설정" || echo "취약|disable_symlinks 미설정 (기본값 off - 링크 허용)"; }
_v_links_webtob() {
    if _wtm '.' >/dev/null 2>&1 && grep -A5 '^\*ALIAS' "$_WT_M" 2>/dev/null | grep -v '^[[:space:]]*#' | grep -qiE 'URI[[:space:]]*='; then echo "취약|*ALIAS 설정 존재: $(grep -A5 '^\*ALIAS' "$_WT_M" | grep -iE 'URI[[:space:]]*=' | grep -v '^[[:space:]]*#' | sed -n 1,2p | tr -s ' ' | tr '\n' ' ')"
    else echo "양호|ALIAS 미사용"; fi
}
_v_links_tomcat() {
    local u; u=$(_tc_need server.xml context.xml) || { echo "$u"; return; }
    { _tcx server.xml; _tcx context.xml; } | grep -qiE 'allowLinking="true"' && echo "취약|allowLinking=true" || echo "양호|allowLinking 미설정(false)"
}
_v_links_jeus() {
    local f hit=""; for f in $(_JX jeus-web-dd.xml 50); do [ -r "$f" ] && _xml_nc < "$f" | grep -q '<aliasing>' && hit="${hit} ${f}"; done
    [ -n "$hit" ] && echo "취약|jeus-web-dd.xml aliasing 설정 존재:${hit}" || echo "양호|aliasing 미사용"
}
_wt_alias_ev() { if [ -r "$_WT_M" ]; then grep -nA5 '^\*ALIAS' "$_WT_M"; else echo "WebtoB http.m 을 읽을 수 없음: ${_WT_M:-(미발견)}"; fi; }
_ev_links() {
    _cfg_scope
    _hasw apache && _show "Apache: Options" _activef 'Options[[:space:]]'
    _hasw nginx && _show "Nginx: disable_symlinks" _ngxf '^disable_symlinks'
    _hasw webtob && _show "WebtoB: *ALIAS" _wt_alias_ev
    _hasw tomcat && _tc_ev 'echo "-- allowLinking"; { _tcx server.xml; _tcx context.xml; } | grep -nE "allowLinking"'
    _hasw jeus && _je_ev 'for f in $(_JX jeus-web-dd.xml 50); do echo "-- $f"; grep -n "aliasing" "$f"; done'
}
# WST-038: 링크 허용 + 링크 파일 존재
_v_wst038() {
    local d lk="" ln allow="" r x p
    for d in $(_web_docroots); do [ -d "$d" ] && { ln=$(_findd 3 "$d" -type l | sed -n 1,3p | tr '\n' ' '); [ -n "$ln" ] && lk="${lk} ${ln}"; }; done
    _hasw apache && [ -z "$_AP_UN" ] && { x=$(_v_links_apache); case "$x" in 취약*) allow="${allow} Apache(${x#*|})" ;; esac; }
    _hasw nginx && [ -z "$_NG_UN" ] && { x=$(_v_links_nginx); case "$x" in 취약*) allow="${allow} Nginx(disable_symlinks 미설정)" ;; esac; }
    for p in $TOMCAT_HOMES; do TOMCAT_HOME=$p; x=$(_v_links_tomcat); case "$x" in 취약*) allow="${allow} Tomcat($p allowLinking)" ;; esac; done
    r=""; [ -n "$_AP_UN" ] && r=$(_worse "$r" "점검불가|$_AP_UN"); [ -n "$_NG_UN" ] && r=$(_worse "$r" "점검불가|$_NG_UN")
    if [ -n "$lk" ] && [ -n "$allow" ]; then r=$(_worse "$r" "취약|링크 허용${allow} + 링크 파일 존재:${lk}")
    elif [ -n "$lk" ]; then r=$(_worse "$r" "양호|링크 파일 존재하나 링크 허용 설정 비활성화 (${lk})")
    else r=$(_worse "$r" "양호|웹 서비스 경로 내 링크 파일 없음${allow:+ (허용 설정: ${allow})}"); fi
    echo "$r"
}
_ev_wst038() {
    _ev_links
    local d; for d in $(_web_docroots); do _show "심볼릭 링크 (깊이 3): $d" sh -c "if [ -d '$d' ]; then find '$d' -path '$d/*/*/*/*' -prune -o -type l -exec ls -l {} \\; ; else echo '디렉터리 없음: $d'; fi"; done
}

# ── 웹 서비스 정보 노출 (WST-102 / WEB-16) ───────────────────────
_hp_err_ver() {   # 포트의 오류 응답(4xx/5xx) 본문에서 제품 버전 표시 부분 (없으면 빈 값)
    case "$(_hp_status "$1" err)" in 4*|5*) ;; *) return 0 ;; esac
    [ -s "$_HPD/p$1.err.body" ] || return 0
    grep -ioE 'Apache Tomcat/[0-9][0-9.]*[^<]*|Apache/[0-9][0-9.]* \([^)]*\)|nginx/[0-9][0-9.]*|Jetty\([0-9][^)]*\)|WebtoB/[0-9][0-9.]*' "$_HPD/p$1.err.body" 2>/dev/null | sed -n 1p
}
_hp_server_resp() {   # _hp_server_resp 제품 : 응답의 Server 헤더 판정 "판정|근거" (응답 없으면 빈 값)
    local p v leak="" clean="" any=0 xp trace=""
    _hp_have "$1" || return 0
    for p in $(_hp_ports "$1"); do
        _hp_ok "$p" || continue; any=1
        v=$(_hp_hdr "$p" get Server); xp=$(_hp_hdr "$p" get X-Powered-By)
        if _hp_server_leak "$v"; then leak="${leak} $(_hp_scheme "$p"):${p}[Server: ${v}]"; else clean="${clean} $(_hp_scheme "$p"):${p}[Server: ${v:-없음}]"; fi
        [ -n "$xp" ] && echo "$xp" | grep -qE '/[0-9]' && leak="${leak} $(_hp_scheme "$p"):${p}[X-Powered-By: ${xp}]"
        v=$(_hp_err_ver "$p"); [ -n "$v" ] && leak="${leak} $(_hp_scheme "$p"):${p}[오류 페이지 본문 버전 표시: ${v}]"   # 헤더가 깨끗해도 오류 페이지 서명에 버전이 보이면 노출 (Tomcat showServerInfo, Apache ServerSignature, nginx server_tokens)
        case "$(_hp_status "$p" trc)" in 200) trace="${trace} :${p}" ;; esac
    done
    [ "$any" = 1 ] || return 0
    if [ -n "$leak" ]; then echo "취약|실제 응답(헤더·오류 페이지)에 서버 버전/OS 정보 노출:${leak}${trace:+ (참고: TRACE 허용 응답 200${trace})}"
    else echo "양호|실제 응답(헤더·오류 페이지)에 버전 미노출:${clean}${trace:+ (참고: TRACE 허용 응답 200${trace})}"; fi
}
_ap_sigbad() {   # ServerSignature 가 Off 가 아닌 문맥 "문맥=값 ..." (가상호스트가 전역 값을 덮어쓸 수 있으므로 문맥별 마지막 값, 지정이 없으면 전역값 → 기본 Off)
    _ap_scoped | awk -F'\t' '
    { if (!($1 in seen)) { seen[$1] = 1; order[++n] = $1 } t = tolower($5)
      if (t ~ /^serversignature[ \t]/) { split(t, a, /[ \t]+/); v[$1] = a[2] } }
    END { g = ("global" in v) ? v["global"] : "off"
          for (i = 1; i <= n; i++) { c = order[i]; e = (c in v) ? v[c] : g; if (e != "off") { printf "%s=%s ", c, e; shown = 1 } }
          if (!shown && g != "off") printf "global=%s ", g }'
}
_v_servinfo_apache() {
    local tk sg a cfg sb
    tk=$(_active 'ServerTokens[[:space:]]' | tail -1 | awk '{print $2}'); sg=$(_active 'ServerSignature[[:space:]]' | tail -1 | awk '{print $2}'); sb=$(_ap_sigbad)
    case "$(echo "$tk" | tr 'A-Z' 'a-z')" in prod|productonly) a=1 ;; *) a=0 ;; esac
    if [ "$a" = 1 ] && [ -z "$sb" ]; then cfg="양호|ServerTokens ${tk}, ServerSignature ${sg:-Off(기본)}"
    else cfg="취약|헤더 정보 노출 설정 (ServerTokens=${tk:-미설정(Full)}, ServerSignature=${sg:-미설정}${sb:+, Off 아닌 가상호스트/문맥: ${sb% }}) - 가이드: ServerTokens Prod + ServerSignature Off"; fi
    # 가상호스트 단위 설정 결함은 기본 호스트(127.0.0.1) 응답만으로 양호 보정하지 않는다 (이름 기반 가상호스트는 응답 수집이 닿지 않음)
    if [ "$a" = 1 ] && [ -n "$sb" ]; then _worse "$cfg" "$(_hp_server_resp apache)"; else _resp_adjust "$cfg" "$(_hp_server_resp apache)"; fi
}
_ng_tokbad() {   # server_tokens 가 off 가 아닌 server 블록 "server#N(listen)=값 ..." (server 값이 http 값을 덮어씀, 기본 on)
    _ng_scoped | awk -F'\t' '
    { c = $1; if (!(c in seen)) { seen[c] = 1; order[++n] = c } t = $5
      if (t ~ /^listen[ \t]/ && !(c in lis)) { l = t; sub(/^listen[ \t]+/, "", l); lis[c] = l }
      if (tolower(t) ~ /^server_tokens[ \t]/) { split(tolower(t), a, /[ \t]+/); v[c] = a[2] } }
    END { g = ("http" in v) ? v["http"] : (("main" in v) ? v["main"] : "on"); ns = 0
          for (i = 1; i <= n; i++) { c = order[i]; if (c !~ /^server#/) continue; ns++; e = (c in v) ? v[c] : g
              if (e != "off") printf "%s(%s)=%s ", c, lis[c], e }
          if (!ns && g != "off") printf "http=%s ", g }'
}
_v_servinfo_nginx() {
    local cfg tb
    tb=$(_ng_tokbad)
    if [ -z "$tb" ]; then cfg="양호|server_tokens off (모든 server 블록)"
    else cfg="취약|server_tokens off 아님 (버전 노출; 미설정 시 기본 on): ${tb% }"; fi
    # 응답을 받은 포트 수보다 결함 server 블록이 많으면(이름 기반 server 포함) 기본 호스트 응답만으로 양호 보정하지 않는다
    if [ -n "$tb" ] && [ "$(echo "$tb" | tr ' ' '\n' | grep -c 'server#')" -gt "$(_hp_ports nginx | grep -c .)" ]; then _worse "$cfg" "$(_hp_server_resp nginx)"; else _resp_adjust "$cfg" "$(_hp_server_resp nginx)"; fi
}
_v_servinfo_webtob() {
    local tk cfg; tk=$(_wtm 'ServerTokens' | sed -n 1p)
    if echo "$tk" | grep -qiE 'Prod|ProductOnly|Off'; then cfg="양호|$(echo $tk)"; else cfg="취약|ServerTokens Prod(ProductOnly) 미설정: ${tk:-미설정}"; fi
    _resp_adjust "$cfg" "$(_hp_server_resp webtob)"
}
_v_servinfo_tomcat() {
    local u sv si cfg; u=$(_tc_need server.xml) || { echo "$u"; return; }
    sv=$(_tcx server.xml | grep -oE '<Connector[^>]*server="[^"]*"' | sed -n 1p); si=$(_tcx server.xml | grep -oE 'showServerInfo="false"' | sed -n 1p)
    if [ -n "$sv" ] && [ -n "$si" ]; then cfg="양호|Connector server 속성 변경 + ErrorReportValve showServerInfo=false"
    elif [ -n "$sv" ]; then cfg="양호|Connector server 속성 변경 (에러 페이지 버전 노출은 WEB-22 참고, showServerInfo=false 권고)"
    else cfg="취약|Connector server 속성 미설정 - 가이드: server 값을 임의 정보로 변경 + showServerInfo=false"; fi
    _resp_adjust "$cfg" "$(_hp_server_resp tomcat)"
}
_v_servinfo_jeus() {
    local cfg; if grep -rhiE 'serverInfo=false|<field-name>' $(_JX JEUSMain.xml) $(_JX domain.xml) </dev/null 2>/dev/null | grep -q .; then cfg="양호|서버 정보 헤더 제한 설정"; else cfg="취약|-Djeus.servlet.response.header.serverInfo=false / response-header 미설정"; fi
    _resp_adjust "$cfg" "$(_hp_server_resp jeus)"
}
_ev_servinfo() {
    _cfg_scope
    _hasw apache && _show "Apache: ServerTokens/ServerSignature" _activef 'Server(Tokens|Signature)'
    _hasw nginx && _show "Nginx: server_tokens" _ngxf '^server_tokens'
    _hasw webtob && _show "WebtoB: ServerTokens" _wtmf 'Server(Tokens|Signature)'
    _hasw tomcat && _tc_ev 'echo "-- Connector server= / showServerInfo"; _tcx server.xml | grep -noE "(server|showServerInfo|showReport)=\"[^\"]*\""'
    _hasw jeus && _je_ev 'for f in $(_JX JEUSMain.xml 5) $(_JX domain.xml 5); do echo "-- $f"; grep -nE "serverInfo|field-name" "$f"; done'
    _hp_ev "" get err trc
}

# ── 기본 에러 페이지 (WST-123 / WEB-22) ──────────────────────────
_ERRSTRICT=0
_hp_err_resp() {   # 오류 응답 본문이 제품 기본 페이지인지
    local p o="" ok="" any=0
    _hp_have "$1" || return 0
    for p in $(_hp_ports "$1"); do
        [ -s "$_HPD/p$p.err" ] || continue
        case "$(_hp_status "$p" err)" in 4*|5*) ;; *) continue ;; esac   # 오류 응답(4xx/5xx)만 판단 대상
        any=1
        # Tomcat 은 'HTTP Status NNN' 제목만 남는 showReport=false 페이지(Type/Message/Description·버전 없음)는 기본 보고서가 아니므로 제외
        if _hp_body_has "$p" err 'The requested URL .* was not found on this server|Server at .* Port|<hr><center>nginx|Apache Tomcat/|<h1>Not Found</h1>' || { _hp_body_has "$p" err 'HTTP Status [0-9]+' && _hp_body_has "$p" err '<b>(Type|Message|Description)</b>'; }; then o="${o} $(_hp_scheme "$p"):${p}(상태 $(_hp_status "$p" err))"
        else ok="${ok} $(_hp_scheme "$p"):${p}(상태 $(_hp_status "$p" err))"; fi
    done
    [ "$any" = 1 ] || return 0
    [ -n "$o" ] && echo "취약|존재하지 않는 경로 요청 시 제품 기본 오류 페이지가 응답됨:${o}" || echo "양호|존재하지 않는 경로 요청 시 기본 오류 페이지 아님(사용자 정의):${ok}"
}
_v_errpage_apache() {
    local vh miss="" ctx has glob codes cfg
    codes='ErrorDocument[[:space:]]+[45][0-9][0-9]'
    vh=$(_ap_vh "$codes"); glob=$(echo "$vh" | awk -F'\t' '$1 == "global" { print $2 }')
    if [ "$_ERRSTRICT" = 1 ]; then
        local g4 g5; g4=$(_ap_vh 'ErrorDocument[[:space:]]+404' | awk -F'\t' '$1 == "global" { print $2 }'); g5=$(_ap_vh 'ErrorDocument[[:space:]]+5[0-9][0-9]' | awk -F'\t' '$1 == "global" { print $2 }')
        local v4 v5; v4=$(_ap_vh 'ErrorDocument[[:space:]]+404'); v5=$(_ap_vh 'ErrorDocument[[:space:]]+5[0-9][0-9]')
        miss=$({ echo "$v4" | awk -F'\t' -v g="$g4" '$1 != "global" && $2 == 0 && g != 1 { print $1 " 404" }'; echo "$v5" | awk -F'\t' -v g="$g5" '$1 != "global" && $2 == 0 && g != 1 { print $1 " 5xx" }'; } | tr '\n' ',' | sed 's/,$//')
        [ -z "$(echo "$vh" | grep -v '^global')" ] && { [ "$g4" = 1 ] && [ "$g5" = 1 ] || miss="전역 $([ "$g4" = 1 ] || echo 404) $([ "$g5" = 1 ] || echo 5xx)"; }
    else
        miss=$(echo "$vh" | awk -F'\t' -v g="$glob" '$1 != "global" && $2 == 0 && g != 1 { print $1 }' | tr '\n' ',' | sed 's/,$//')
        [ -z "$(echo "$vh" | grep -v '^global')" ] && [ "$glob" != 1 ] && miss="전역"
    fi
    if [ -z "${miss// /}" ]; then cfg="양호|ErrorDocument 설정 ($(_brief "$(_active "$codes" | awk '{print $2}' | sort -u)" 6))"
    else cfg="취약|ErrorDocument 미설정 대상: ${miss} (기본 에러 페이지 노출)"; fi
    _resp_adjust "$cfg" "$(_hp_err_resp apache)"
}
_v_errpage_nginx() {
    local vh miss glob ep cfg rd
    vh=$(_ng_vh '^error_page[[:space:]]+.*[45][0-9][0-9]')
    glob=$(echo "$vh" | awk -F'\t' '$1 == "http" || $1 == "main" { if ($2 == 1) g = 1 } END { print g + 0 }')
    rd=$(_ng_vh '^return[[:space:]]+30[1278][[:space:]]' | awk -F'\t' '$1 ~ /^server#/ && $2 == 1 { printf "%s ", $1 }')   # return 30x 만 하는 리디렉션 전용 server 는 오류 페이지를 내보내지 않음
    miss=$(echo "$vh" | awk -F'\t' -v g="$glob" -v rd="$rd" 'BEGIN { n = split(rd, a, " "); for (i = 1; i <= n; i++) r[a[i]] = 1 } $1 ~ /^server#/ && $2 == 0 && g != 1 && !($1 in r) { print $1 "(" $4 ")" }' | tr '\n' ',' | sed 's/,$//')
    ep=$(_ngx '^error_page[[:space:]]' | grep -oE '[45][0-9][0-9]' | sort -u | tr '\n' ' ')
    if [ "$_ERRSTRICT" = 1 ]; then echo " $ep" | grep -q ' 404' || miss="${miss:+$miss, }404 미지정"; echo " $ep" | grep -qE ' 5[0-9][0-9]' || miss="${miss:+$miss, }5xx 미지정"; fi
    [ -z "$(echo "$vh" | grep '^server#')" ] && [ "$glob" != 1 ] && [ -z "$ep" ] && miss="${miss:-error_page 없음}"
    if [ -z "$miss" ]; then cfg="양호|error_page 설정 (${ep% })"; else cfg="취약|error_page 미설정 대상: ${miss}${ep:+ (설정 코드: ${ep% })}"; fi
    _resp_adjust "$cfg" "$(_hp_err_resp nginx)"
}
_v_errpage_webtob() { _wtm 'ERRORDOCUMENT' | grep -q . && echo "양호|ERRORDOCUMENT 지정" || echo "취약|ERRORDOCUMENT 미지정"; }
_v_errpage_tomcat() {
    local u apps f hit="" cfg valve; u=$(_tc_need web.xml server.xml) || { echo "$u"; return; }
    for f in "$(_tc_f web.xml)" "$TOMCAT_HOME"/webapps/*/WEB-INF/web.xml; do   # 기본 번들 앱(manager 등)은 업무 앱이 아니므로 제외
        [ -r "$f" ] || continue
        case "$f" in "$TOMCAT_HOME"/webapps/manager/*|"$TOMCAT_HOME"/webapps/host-manager/*|"$TOMCAT_HOME"/webapps/docs/*|"$TOMCAT_HOME"/webapps/examples/*) continue ;; esac
        _xml_nc < "$f" | grep -qi '<error-page>' && hit="${hit} ${f}"
    done
    valve=$(_tcx server.xml | tr '\n' ' ' | grep -oE '<Valve[^>]*ErrorReportValve[^>]*>' | grep -E 'showReport="false"' | grep -E 'showServerInfo="false"' | sed -n 1p)
    if [ -n "$hit" ]; then cfg="양호|<error-page> 지정:${hit}"
    elif [ -n "$valve" ]; then cfg="양호|ErrorReportValve showReport=false·showServerInfo=false (기본 오류 보고서 비노출)"
    else cfg="취약|<error-page> 미지정 (기본 에러 페이지·버전 노출; 번들 앱 manager/docs/examples 제외)"; fi
    _resp_adjust "$cfg" "$(_hp_err_resp tomcat)"
}
_v_errpage_jeus() {
    local f hit=""; for f in $(_JX web.xml 50) $(_JX webcommon.xml 5); do [ -r "$f" ] && _xml_nc < "$f" | grep -qi '<error-page>' && hit="${hit} ${f}"; done
    [ -n "$hit" ] && echo "양호|<error-page> 지정:${hit}" || echo "취약|<error-page> 미지정"
}
_ev_errpage() {
    _cfg_scope
    _hasw apache && _show "Apache: ErrorDocument 가상호스트별 (문맥 / 설정여부 / 내용)" _ap_vh 'ErrorDocument[[:space:]]+[45][0-9][0-9]'
    _hasw apache && _show "Apache: ErrorDocument 지시자" _activef 'ErrorDocument'
    _hasw nginx && _show "Nginx: server 별 error_page (문맥 / 설정여부 / listen / server_name / 내용)" _ng_vh '^error_page'
    _hasw nginx && _show "Nginx: error_page 지시자" _ngxf '^error_page'
    _hasw webtob && _show "WebtoB: ERRORDOCUMENT" _wtmf 'ERRORDOCUMENT'
    _hasw tomcat && _tc_ev 'for f in $(_tc_webxmls); do echo "-- $f"; _xml_nc < "$f" | grep -nE "<error-page>"; done; echo "-- server.xml ErrorReportValve"; _tcx server.xml | grep -noE "<Valve[^>]*ErrorReportValve[^>]*>"'
    _hasw jeus && _je_ev 'for f in $(_JX web.xml 50) $(_JX webcommon.xml 5); do echo "-- $f"; grep -n "<error-page>" "$f"; done'
    _hp_ev "" err
}

# ── SSI (WST-122 / WEB-19) ───────────────────────────────────
_v_ssi_apache() {
    local o; o=$(_active 'Options[[:space:]]' | grep -iE '(^|[[:space:]+])Includes(NOEXEC)?' | grep -vi -- '-Includes' | sed -n 1p)
    [ -n "$o" ] && echo "취약|SSI 활성: $(echo $o)" || echo "양호|Options Includes 미사용 (SSI 비활성)"
}
_v_ssi_nginx() { _ngx '^ssi[[:space:]]+on' | grep -q . && echo "취약|Nginx ssi on" || echo "양호|Nginx ssi 미사용"; }
_v_ssi_webtob() { _wtm '(SvrType|SVRTYPE)[[:space:]]*=[[:space:]]*SSI' | grep -q . && echo "취약|SSI 서버 타입 활성" || echo "양호|SSI 미사용"; }
_v_ssi_tomcat() { local u f; u=$(_tc_need web.xml) || { echo "$u"; return; }; f=$(_tc_webxml_active "SSIServlet|SSIFilter") && echo "취약|SSI 활성: ${f}" || echo "양호|SSIServlet/SSIFilter 미사용"; }
_ev_ssi() {
    _cfg_scope
    _hasw apache && _show "Apache: Options/AddOutputFilter/AddHandler" _activef '(Options|AddOutputFilter|AddHandler|AddType)[[:space:]]'
    _hasw nginx && _show "Nginx: ssi" _ngxf '^ssi[[:space:]]'
    _hasw webtob && _show "WebtoB: SSI 서버 타입" _wtmf '(SvrType|SVRTYPE)[[:space:]]*=[[:space:]]*SSI'
    _hasw tomcat && _tc_ev 'for f in $(_tc_webxmls); do echo "-- $f"; _xml_nc < "$f" | grep -nE "SSIServlet|SSIFilter"; done'
}

# ── 별도 설정: WEB-17 가상 디렉터리 / WEB-18 WebDAV ───────────────
_v_vdir_apache() {
    local al dal; al=$(_active 'Alias[[:space:]]' | awk '{print $2}' | sort -u | tr '\n' ' ')
    dal=$(echo " $al" | grep -oE ' /(icons|manual|error|noindex)/?' | tr -d ' ' | tr '\n' ' ')
    if [ -n "$dal" ]; then echo "취약|기본 가상 디렉터리(Alias) 존재: ${dal}(불필요 시 삭제)"
    elif [ -n "$al" ]; then echo "수동확인|Alias 가상 디렉터리: ${al}- 업무상 필요 여부 확인"
    else echo "양호|가상 디렉터리(Alias) 없음"; fi
}
_v_vdir_nginx() { local al; al=$(_ngx '^alias[[:space:]]' | awk '{print $2}' | tr -d ';' | tr '\n' ' '); [ -n "$al" ] && echo "수동확인|alias 가상 디렉터리: ${al}- 업무상 필요 여부 확인" || echo "양호|alias 가상 디렉터리 없음"; }
_v_vdir_webtob() { grep -A5 '^\*ALIAS' "$_WT_M" 2>/dev/null | grep -v '^[[:space:]]*#' | grep -qiE 'URI[[:space:]]*=' && echo "수동확인|*ALIAS 가상 디렉터리 존재 - 업무상 필요 여부 확인" || echo "양호|가상 디렉터리 없음"; }
_v_vdir_tomcat() {
    local u cx; u=$(_tc_need server.xml) || { echo "$u"; return; }
    cx=$( { _tcx server.xml | grep -oE '<Context[^>]*path="[^"]+"' | grep -oE 'path="[^"]*"'; for f in "$TOMCAT_HOME"/conf/Catalina/*/*.xml; do [ -f "$f" ] && basename "$f"; done; } | tr '\n' ' ')
    [ -n "${cx// /}" ] && echo "수동확인|Context 가상 디렉터리: ${cx}- 업무상 필요 여부 확인" || echo "양호|별도 Context 가상 디렉터리 없음"
}
_ev_vdir() {
    _cfg_scope
    _hasw apache && _show "Apache: Alias" _activef 'Alias[[:space:]]'
    _hasw nginx && _show "Nginx: alias" _ngxf '^alias[[:space:]]'
    _hasw webtob && _show "WebtoB: *ALIAS" _wt_alias_ev
    _hasw tomcat && _tc_ev 'echo "-- server.xml Context path"; _tcx server.xml | grep -noE "<Context[^>]*path=\"[^\"]*\""; echo "-- conf/Catalina/*/*.xml"; ls -l "$TOMCAT_HOME"/conf/Catalina/*/ 2>&1'
}
_v_webdav_apache() { _active 'Dav[[:space:]]+On' | grep -q . && echo "취약|WebDAV 활성 (Dav On)" || echo "양호|Dav On 설정 없음 (WebDAV 비활성)"; }
_v_webdav_nginx() { _ngx '^dav_methods[[:space:]]' | grep -qvi 'off' && echo "취약|dav_methods 설정: $(_ngx '^dav_methods' | sed -n 1p | tr -s ' ')" || echo "양호|WebDAV(dav_methods) 미사용"; }
_v_webdav_webtob() { _wtm 'Method[[:space:]]*=' | grep -qiE 'PUT|DELETE|PROPFIND|MKCOL|COPY|MOVE' && echo "취약|WebDAV 메소드 허용: $(_wtm 'Method[[:space:]]*=' | sed -n 1p | tr -s ' ')" || echo "양호|WebDAV 메소드 미허용"; }
_ev_webdav() {
    _cfg_scope
    _hasw apache && _show "Apache: Dav/dav 모듈" _activef '(Dav[[:space:]]|LoadModule[[:space:]]+dav)'
    _hasw nginx && _show "Nginx: dav_*" _ngxf '^dav_'
    _hasw webtob && _show "WebtoB: Method" _wtmf 'Method[[:space:]]*='
}

# ── SSL/TLS (WEB-20) / HTTP 리디렉션 (WEB-21) ────────────────────
_LBN=" (로드밸런서·프록시에서 TLS 종료 시 해당 구간 설정 증빙으로 판단)"
_hp_ssl_resp() {   # 제품의 HTTPS 응답 여부 "판정|근거"
    local p ok="" no=""
    _hp_have "$1" || return 0
    for p in $(_hp_ports "$1"); do _hp_ok "$p" && [ "$(_hp_scheme "$p")" = https ] && ok="${ok} :${p}(상태 $(_hp_status "$p" get))"; done
    [ -n "$ok" ] && echo "양호|실제 HTTPS 응답 확인:${ok}"
}
_v_ssl_apache() {
    local cfg ssl vhs; ssl=$(_ap_vh 'SSLEngine[[:space:]]+on')
    if echo "$ssl" | awk -F'\t' '$2 == 1 { f = 1 } END { exit !f }'; then cfg="양호|SSLEngine on (SSL/TLS 활성): $(echo "$ssl" | awk -F'\t' '$2 == 1 { printf "%s; ", $1 }')"
    else cfg="취약|SSL/TLS 미설정 (SSLEngine on 없음)${_LBN}"; fi
    _resp_adjust "$cfg" "$(_hp_ssl_resp apache)"
}
_v_ssl_nginx() {
    local cfg n; n=$(_ng_vh '^listen[[:space:]].*ssl' | awk -F'\t' '$1 ~ /^server#/ && $2 == 1 { printf "%s(%s); ", $1, $3 }')
    if [ -n "$n" ] || _ngx '^ssl[[:space:]]+on' | grep -q .; then cfg="양호|listen ssl (SSL/TLS 활성): ${n}"; else cfg="취약|SSL/TLS 미설정 (listen ... ssl 없음)${_LBN}"; fi
    _resp_adjust "$cfg" "$(_hp_ssl_resp nginx)"
}
_v_ssl_webtob() {
    local cfg; if _wtm 'SSLFLAG[[:space:]]*=[[:space:]]*Y' | grep -q .; then cfg="양호|WebtoB SSLFLAG=Y"; else cfg="취약|WebtoB SSLFLAG 미설정${_LBN}"; fi
    _resp_adjust "$cfg" "$(_hp_ssl_resp webtob)"
}
_ev_ssl() {
    _cfg_scope
    _hasw apache && _show "Apache: ssl 모듈" sh -c '{ httpd -M 2>/dev/null || apache2ctl -M 2>/dev/null || apachectl -M 2>/dev/null; } | grep -i ssl'
    _hasw apache && _show "Apache: SSLEngine 가상호스트별 (문맥 / 설정여부 / 내용)" _ap_vh 'SSLEngine[[:space:]]+on'
    _hasw apache && _show "Apache: Listen/SSL 지시자" _activef '(Listen|SSLEngine|SSLProtocol)[[:space:]]'
    _hasw nginx && _show "Nginx: listen/ssl_protocols/ssl_certificate" _ngxf '^(listen|ssl_protocols|ssl_certificate[[:space:]]|ssl[[:space:]])'
    _hasw webtob && _show "WebtoB: SSLFLAG/SSLNAME" _wtmf '(SSLFLAG|SSLNAME)'
    _show "리슨 중인 TCP 포트 표 (포트 / 바인드)" printf '%s\n' "$_HP_LISTEN"
    _hp_ev "" get
}
_hp_redir_resp() {   # HTTP(비 TLS) 포트 응답이 https 로 리디렉션하는지 "판정|근거"
    local p st loc bad="" okr="" n=0
    _hp_have "$1" || return 0
    for p in $(_hp_ports "$1"); do
        _hp_ok "$p" || continue; [ "$(_hp_scheme "$p")" = http ] || continue; n=$((n+1))
        st=$(_hp_status "$p" get); loc=$(_hp_hdr "$p" get Location)
        case "$st" in 301|302|303|307|308) echo "$loc" | grep -qi '^https://' && okr="${okr} :${p}(${st} → ${loc})" || bad="${bad} :${p}(${st} → ${loc:-Location 없음})" ;; *) bad="${bad} :${p}(상태 ${st}, 리디렉션 아님)" ;; esac
    done
    [ "$n" -gt 0 ] || { echo "양호|HTTP(비 TLS) 응답 포트 없음 - HTTPS 전용으로 보임"; return; }
    [ -n "$bad" ] && echo "취약|실제 응답이 HTTPS 로 리디렉션되지 않음:${bad}${okr:+ / 리디렉션 확인:${okr}}" || echo "양호|실제 응답이 HTTPS 로 리디렉션됨:${okr}"
}
_v_redirect_apache() {
    local pat vh miss glob cfg
    pat='(Redirect(Permanent|Match)?[[:space:]].*https://|RewriteRule[[:space:]].*https://)'
    vh=$(_ap_vh "$pat"); glob=$(echo "$vh" | awk -F'\t' '$1 == "global" { print $2 }')
    miss=$(echo "$vh" | awk -F'\t' -v g="$glob" '$1 ~ /^vhost/ && $1 !~ /:443|:8443/ && $2 == 0 && g != 1 { print $1 }' | tr '\n' ',' | sed 's/,$//')
    if [ "$glob" = 1 ] && [ -z "$(echo "$vh" | grep '^vhost')" ]; then cfg="양호|HTTP→HTTPS 리디렉션 전역 설정"
    elif [ -z "$(echo "$vh" | grep '^vhost')" ]; then [ "$glob" = 1 ] && cfg="양호|HTTP→HTTPS 리디렉션 설정" || cfg="취약|HTTP→HTTPS 리디렉션 미설정${_LBN}"
    elif [ -n "$miss" ]; then cfg="취약|HTTP→HTTPS 리디렉션 미설정 가상호스트: ${miss}${_LBN}"
    else cfg="양호|모든 HTTP 가상호스트에 HTTPS 리디렉션 설정"; fi
    _resp_adjust_redirect "$cfg" "$(_hp_redir_resp apache)"
}
_v_redirect_nginx() {
    local vh miss cfg
    vh=$(_ng_vh '^(return[[:space:]]+30[1278][[:space:]]+https://|rewrite[[:space:]].*https://)')
    miss=$(echo "$vh" | awk -F'\t' '$1 ~ /^server#/ && $2 == 0 && $3 !~ /ssl/ { print $1 "(" $3 ")" }' | tr '\n' ',' | sed 's/,$//')
    if [ -z "$(echo "$vh" | grep '^server#')" ]; then cfg="취약|server 블록을 찾지 못함 - 리디렉션 설정 확인 불가${_LBN}"
    elif [ -n "$miss" ]; then cfg="취약|HTTP→HTTPS 리디렉션 미설정 server: ${miss}${_LBN}"
    else cfg="양호|HTTP(non-ssl) server 블록에 HTTPS 리디렉션(return 30x https://) 설정"; fi
    _resp_adjust_redirect "$cfg" "$(_hp_redir_resp nginx)"
}
_v_redirect_webtob() {
    local rc cfg; rc=$(_wtm 'URLRewriteConfig' | grep -oE '"[^"]*"' | tr -d '"' | sed -n 1p); case "$rc" in /*) ;; ?*) rc="$_WT_HOME/$rc" ;; esac
    if _wtm 'URLRewrite[[:space:]]*=[[:space:]]*Y' | grep -q . && [ -n "$rc" ] && grep -qiE 'RewriteRule.*https://' "$rc" 2>/dev/null; then cfg="양호|URLRewrite HTTPS 리디렉션 (${rc})"; else cfg="취약|HTTPS 리디렉션(URLRewrite) 미설정${_LBN}"; fi
    _resp_adjust_redirect "$cfg" "$(_hp_redir_resp webtob)"
}
_resp_adjust_redirect() {   # 응답이 리디렉션이면 양호, 설정만 있고 응답이 리디렉션 아니면 수동확인(가상호스트/Host 기반 가능)
    local cfg="$1" rsp="$2"
    [ -n "$rsp" ] || { echo "$cfg"; return; }
    case "${rsp%%|*}:${cfg%%|*}" in
    양호:*) _resp_adjust "$cfg" "$rsp" ;;
    취약:양호) echo "수동확인|설정에는 HTTPS 리디렉션이 있으나 기본 호스트(127.0.0.1) 실제 응답은 리디렉션 아님 - 이름 기반 가상호스트/Host 헤더별 응답 확인 필요 (${rsp#*|}; 설정: ${cfg#*|})" ;;
    *) _worse "$cfg" "$rsp" ;;
    esac
}
_ev_redirect() {
    _cfg_scope
    _hasw apache && _show "Apache: 리디렉션 지시자 (RewriteRule/Redirect)" _activef '(Redirect|RewriteRule|RewriteCond|RewriteEngine)'
    _hasw apache && _show "Apache: 가상호스트별 https 리디렉션 (문맥 / 설정여부 / 내용)" _ap_vh '(Redirect(Permanent|Match)?[[:space:]].*https://|RewriteRule[[:space:]].*https://)'
    _hasw nginx && _show "Nginx: server 별 https 리디렉션 (문맥 / 설정여부 / listen / server_name / 내용)" _ng_vh '^(return[[:space:]]+30[1278][[:space:]]+https://|rewrite[[:space:]].*https://)'
    _hasw webtob && _show "WebtoB: URLRewrite" _wtmf 'URLRewrite'
    _hp_ev "" get
}

# ── LDAP (WEB-23 / WST-124) ───────────────────────────────────
_v_ldap_tomcat() {
    local u jr dg; u=$(_tc_need server.xml) || { echo "$u"; return; }
    jr=$(_tcx server.xml | grep -i 'JNDIRealm')
    if [ -z "$jr" ]; then echo "양호|LDAP 연결 인증(JNDIRealm) 미사용 - 취약한 다이제스트 알고리즘 사용 대상 없음"
    else dg=$(_tcx server.xml | grep -oiE '(digest|algorithm)="[^"]*"' | cut -d'"' -f2 | tr '\n' ' ')
        echo " $dg" | grep -qiE ' SHA-?(256|384|512)' && echo "양호|JNDIRealm 비밀번호 다이제스트 ${dg% }" || echo "취약|JNDIRealm 다이제스트 ${dg:-미설정}- SHA-256 이상 필요 (MD5/SHA-1/SSHA 취약)"; fi
}
_v_ldap_apache() { _active '(AuthLDAP|LDAPTrusted|AuthnProviderAlias.*ldap)' | grep -q . && echo "수동확인|LDAP 인증 지시자 존재: $(_brief "$(_activef 'AuthLDAP')" 2) - 알고리즘/ldaps 사용 확인" || echo "양호|LDAP 연동 지시자 없음"; }
_v_ldap_nginx() { _ngx '(ldap)' | grep -q . && echo "수동확인|LDAP 관련 설정 존재: $(_brief "$(_ngxf 'ldap')" 2) - 알고리즘/ldaps 사용 확인" || echo "양호|LDAP 연동 설정 없음"; }
_ev_ldap() {
    _cfg_scope
    _hasw apache && _show "Apache: LDAP" _activef '(AuthLDAP|LDAPTrusted)'
    _hasw nginx && _show "Nginx: ldap" _ngxf 'ldap'
    _hasw tomcat && _tc_ev 'echo "-- JNDIRealm/digest"; _tcx server.xml | grep -niE "JNDIRealm|digest=|algorithm=" | _mask_pw'
}

# ── 업로드 디렉터리 (WEB-24 / WST-125) ───────────────────────────
_UPD=""
_upload_dirs() {
    local d
    for d in $(_web_docroots); do [ -d "$d" ] && _findd 4 "$d" -type d \( -iname 'upload*' -o -iname 'attach*' -o -iname 'userfile*' \) ; done | sort -u
}
_v_upload_dirs_core() {
    local ud o="" d p roots; roots=$(_web_docroots | tr '\n' ' ')
    if [ -z "${roots// /}" ]; then echo "점검불가|웹 서비스 경로를 확인하지 못해 업로드 디렉터리를 찾을 수 없음"; return; fi
    ud=$(_upload_dirs | tr '\n' ' ')
    if [ -z "${ud// /}" ]; then echo "수동확인|웹 경로 내 업로드 디렉터리(upload/attach) 미발견(검색: ${roots}) - 애플리케이션 업로드 경로·권한 확인"; return; fi
    for d in $ud; do p=$(get_perm "$d"); [ -n "$p" ] && _perm_over "$p" 750 && o="${o} ${d}(${p})"; done
    [ -n "$o" ] && echo "취약|업로드 디렉터리에 일반 사용자 권한 부여 (750 초과):${o}" || echo "수동확인|업로드 디렉터리 권한 750 이하: $(_brief "$(echo $ud | tr ' ' '\n')" 4) - 웹 경로 내 위치 시 실행·직접 접근 제한(Require all denied 등) 확인"
}
_ev_upload_dirs() {
    _show "문서 루트 목록" _web_docroots
    _show "업로드 디렉터리 후보 (이름 upload*/attach*/userfile*, 깊이 4)" _upload_dirs
    local d; for d in $(_upload_dirs); do ls -ld "$d"; done
    _hasw apache && _show "Apache: Directory upload 설정" _activef '<Directory.*upload'
}

# ── 관리자 계정명 / 비밀번호 / 비밀번호 파일 (WEB-01·02·03, WST-044) ──────────
_v_admin_tomcat() {   # WEB-01
    local f adm bad; f=$(_TCU)
    [ -e "$f" ] || { echo "양호|tomcat-users.xml 없음 (관리자 페이지 미사용)"; return; }
    [ -r "$f" ] || { echo "점검불가|tomcat-users.xml 읽기 권한 없음: $f (실행 계정 $(_me))"; return; }
    adm=$(_tc_admins); bad=$(echo "$adm" | grep -oiE 'username="(admin|tomcat|manager|administrator|root|role1|both|test|user)"' | tr '\n' ' ')
    if [ -z "$adm" ]; then echo "양호|관리자 페이지 미사용 (manager/admin 역할 계정 없음)"
    elif [ -n "$bad" ]; then echo "취약|관리자 계정명이 기본/유추 가능: ${bad% }"
    else echo "양호|관리자 계정명 기본값 아님: $(echo "$adm" | grep -oiE 'username="[^"]*"' | tr '\n' ' ')"; fi
}
_v_admin_jeus() {
    local af; af=$(_JX accounts.xml 5)
    [ -n "$af" ] || { echo "점검불가|JEUS accounts.xml 을 찾지 못함 - WebAdmin Security Domains > Users 에서 관리자 계정명 확인 필요"; return; }
    [ -z "$(_unreadable $af)" ] || { echo "점검불가|JEUS accounts.xml 읽기 권한 없음: $(_unreadable $af) (실행 계정 $(_me))"; return; }
    if grep -hiE '<name>[[:space:]]*(administrator|admin|jeus|root)[[:space:]]*</name>' $af >/dev/null 2>&1; then echo "취약|JEUS 기본 관리자 계정명 사용: $(grep -hoiE '<name>[[:space:]]*(administrator|admin|jeus|root)[[:space:]]*</name>' $af | sort -u | tr '\n' ' ')"
    else echo "양호|JEUS 관리자 계정명 기본값(administrator) 아님"; fi
}
_ev_admin() {
    _hasw tomcat && _tc_ev 'f=$(_TCU); if [ -e "$f" ]; then ls -l "$f"; _xml_nc < "$f" | grep -iE "<user |<role " | _mask_pw; else echo "tomcat-users.xml 없음: $f"; fi'
    _hasw jeus && _je_ev 'for f in $(_JX accounts.xml 5); do echo "-- $f"; grep -iE "<name>" "$f"; done; echo "accounts.xml 후보: $(_JX accounts.xml 5 | grep -c .)개"'
}
_v_weakpw_tomcat() {   # WEB-02
    local f adm weak="" hash=0 u id pw; f=$(_TCU)
    [ -e "$f" ] || { echo "양호|tomcat-users.xml 없음 (관리자 계정 없음)"; return; }
    [ -r "$f" ] || { echo "점검불가|tomcat-users.xml 읽기 권한 없음: $f (실행 계정 $(_me))"; return; }
    adm=$(_tc_admins); _tcx server.xml | grep -qiE 'CredentialHandler|digest="' && hash=1
    while IFS= read -r u; do
        [ -n "$u" ] || continue
        id=$(echo "$u" | grep -oE 'username="[^"]*"' | cut -d'"' -f2); pw=$(echo "$u" | grep -oE 'password="[^"]*"' | cut -d'"' -f2)
        if [ "$hash" = 1 ] && echo "$pw" | grep -qE '^[0-9a-fA-F$:]{32,}$'; then continue; fi
        _pw_strong "$pw" "$id" || weak="${weak} ${id}"
    done <<EOF
$adm
EOF
    if [ -z "$adm" ]; then echo "양호|관리자 계정 없음 (관리자 페이지 미사용)"
    elif [ -n "$weak" ]; then echo "취약|관리자 비밀번호 평문 저장 + 복잡도 미충족(2종 10자/3종 8자, 기본값·계정명·연속 문자 금지):${weak}"
    elif [ "$hash" = 1 ]; then echo "양호|관리자 비밀번호 암호화 저장 (CredentialHandler/digest)"
    else echo "양호|관리자 비밀번호 유추 어려운 값 (평문 저장 - 암호화(CredentialHandler SHA-256 이상) 권고)"; fi
}
_v_weakpw_jeus() {
    local af; af=$(_JX accounts.xml 5)
    [ -n "$af" ] || { echo "점검불가|JEUS accounts.xml 을 찾지 못함 - 관리자 비밀번호 암호화 여부 확인 필요"; return; }
    [ -z "$(_unreadable $af)" ] || { echo "점검불가|JEUS accounts.xml 읽기 권한 없음: $(_unreadable $af) (실행 계정 $(_me))"; return; }
    if grep -hiE '<password>' $af | grep -qviE '<password>[[:space:]]*\{(SHA-?(256|384|512)|AES|SEED|ARIA)'; then echo "취약|JEUS 관리자 비밀번호가 SHA-256 이상으로 암호화되지 않음 ({base64}/{SHA}/평문 등)"
    else echo "양호|JEUS 관리자 비밀번호 SHA-256 이상 암호화"; fi
}
_ev_weakpw() {
    _hasw tomcat && _tc_ev 'f=$(_TCU); if [ -e "$f" ]; then _xml_nc < "$f" | grep -iE "<user " | _mask_pw; else echo "tomcat-users.xml 없음: $f"; fi; echo "-- CredentialHandler/digest"; _tcx server.xml | grep -nE "CredentialHandler|digest=" | _mask_pw'
    _hasw jeus && _je_ev 'for f in $(_JX accounts.xml 5); do echo "-- $f"; grep -iE "<password>" "$f" | _mask_pw; done'
}
_v_pwfile_tomcat() {   # WEB-03
    local f p; f=$(_TCU)
    [ -e "$f" ] || { echo "양호|비밀번호 파일(tomcat-users.xml) 없음"; return; }
    p=$(get_perm "$f"); [ -n "$p" ] || { echo "점검불가|권한 조회 실패: $f"; return; }
    _perm_over "$p" 600 && echo "취약|비밀번호 파일 권한 600 초과: ${f}(${p})" || echo "양호|비밀번호 파일 권한 600 이하: ${f}(${p})"
}
_v_pwfile_jeus() {
    local f p o="" l=""; for f in $(_JX accounts.xml 5) $(_JX policies.xml 5); do p=$(get_perm "$f"); [ -n "$p" ] || continue; l="${l} ${f}(${p})"; _perm_over "$p" 600 && o="${o} ${f}(${p})"; done
    [ -n "$l" ] || { echo "점검불가|JEUS 비밀번호 파일(accounts.xml/policies.xml)을 찾지 못함"; return; }
    [ -n "$o" ] && echo "취약|비밀번호 파일 권한 600 초과:${o}" || echo "양호|비밀번호 파일 권한 600 이하:${l}"
}
_ev_pwfile() {
    _hasw tomcat && _tc_ev 'f=$(_TCU); if [ -e "$f" ]; then ls -l "$f"; else echo "tomcat-users.xml 없음: $f"; fi'
    _hasw jeus && _je_ev 'for f in $(_JX accounts.xml 5) $(_JX policies.xml 5); do ls -l "$f"; done; echo "비밀번호 파일 후보: $(_JX accounts.xml 5 | grep -c .)개(accounts.xml) $(_JX policies.xml 5 | grep -c .)개(policies.xml)"'
}
_v_wst044_tomcat() {
    local f users def; f=$(_TCU)
    [ -e "$f" ] || { echo "양호|tomcat-users.xml 없음 (활성 관리 계정 없음)"; return; }
    [ -r "$f" ] || { echo "점검불가|tomcat-users.xml 읽기 권한 없음: $f (실행 계정 $(_me))"; return; }
    users=$(_xml_nc < "$f" | grep -iE '<user ')
    def=$(echo "$users" | grep -iE 'password="(tomcat|admin|s3cret|password|role1|both|<must-be-changed>|manager|1234|123456)"|username="(tomcat|admin|both|role1)"')
    if [ -n "$def" ]; then echo "취약|기본/유추 가능 계정: $(echo "$def" | grep -oE 'username="[^"]*"' | tr '\n' ' ')"
    elif [ -n "$users" ]; then echo "양호|관리 계정 디폴트 값 아님 ($(echo "$users" | grep -c .)개)"
    else echo "양호|활성 관리 계정 없음 (tomcat-users.xml 에 활성 user 없음)"; fi
}
_v_wst044_jeus() {
    local af; af=$(_JX accounts.xml 5)
    [ -n "$af" ] || { echo "점검불가|JEUS accounts.xml 을 찾지 못함 - 관리자 계정/비밀번호 디폴트 여부 확인 필요"; return; }
    [ -z "$(_unreadable $af)" ] || { echo "점검불가|JEUS accounts.xml 읽기 권한 없음: $(_unreadable $af) (실행 계정 $(_me))"; return; }
    echo "수동확인|JEUS accounts.xml 관리자 계정/비밀번호 디폴트(jeusadmin 등) 여부 확인: $(grep -hoiE '<name>[^<]*</name>' $af | tr '\n' ' ')"
}

# ── DB 연결 정보가 담긴 설정 파일 권한 (WEB-13) ───────────────────
_spring_cfgs() {   # 실행 중 java -jar / WEB-INF·BOOT-INF classes 의 Spring Boot 설정 파일
    local d f pid
    {
        printf '%s\n' "$_PSALL" | grep -E 'java.* -jar ' | grep -oE -- '-jar[[:space:]]+[^[:space:]]+' | awk '{print $2}' | while read -r j; do dirname "$j"; done
        printf '%s\n' "$_PSALL" | grep -oE -- '--?spring\.config\.(location|additional-location)=[^[:space:]]+' | cut -d= -f2- | tr ',' '\n' | sed 's#^file:##'
        for pid in $(ls /proc 2>/dev/null | grep -E '^[0-9]+$'); do
            tr '\0' ' ' 2>/dev/null < /proc/$pid/cmdline | grep -qE 'java.*(-jar |org\.springframework\.boot)' && readlink "/proc/$pid/cwd" 2>/dev/null
        done
    } | sort -u | while read -r d; do
        [ -n "$d" ] || continue
        if [ -f "$d" ]; then echo "$d"; continue; fi
        for f in "$d"/application*.properties "$d"/application*.yml "$d"/application*.yaml "$d"/bootstrap*.properties "$d"/bootstrap*.yml "$d"/config/application*.properties "$d"/config/application*.yml "$d"/config/application*.yaml; do [ -f "$f" ] && echo "$f"; done
    done | sort -u
}
_tc_appcfgs() {   # Tomcat 앱의 WEB-INF/classes·BOOT-INF/classes 설정 파일 (깊이 3)
    local c f
    for c in "$TOMCAT_HOME"/webapps/*/WEB-INF/classes "$TOMCAT_HOME"/webapps/*/BOOT-INF/classes "$TOMCAT_HOME"/conf; do
        [ -d "$c" ] || continue
        for f in "$c"/*.properties "$c"/*.xml "$c"/*.yml "$c"/*.yaml "$c"/*/*.properties "$c"/*/*.xml "$c"/*/*.yml "$c"/*/*/*.properties "$c"/*/*/*.xml "$c"/*/*/*.yml; do [ -f "$f" ] && echo "$f"; done
    done
    for f in "$TOMCAT_HOME"/webapps/*/META-INF/context.xml "$TOMCAT_HOME"/conf/Catalina/*/*.xml; do [ -f "$f" ] && echo "$f"; done
}
_dbcfg_hits() {   # 파일 목록(표준입력) 중 DB 연결 정보 포함 파일
    local f; while read -r f; do [ -r "$f" ] || continue
        case "$f" in *.xml) _xml_nc < "$f" ;; *) grep -v '^[[:space:]]*[#!;]' "$f" ;; esac | grep -qiE 'javax\.sql\.DataSource|jdbc:|spring\.datasource|datasource\.(url|password)|db[._]?(password|url)' && echo "$f"
    done
}
_v_dbconf_tomcat() {
    local c u l=0 o="" f p hits
    [ -d "$TOMCAT_HOME/conf" ] || { echo "점검불가|Tomcat conf 디렉터리 없음: $TOMCAT_HOME/conf"; return; }
    hits=$(_tc_appcfgs | sort -u | _dbcfg_hits)
    u=$(_unreadable "$TOMCAT_HOME"/conf/server.xml "$TOMCAT_HOME"/conf/context.xml)
    [ -n "$u" ] && { echo "점검불가|Tomcat 설정 파일 읽기 권한 없음: ${u} (실행 계정 $(_me))"; return; }
    if [ -z "$hits" ]; then
        [ -d "$TOMCAT_HOME/webapps" ] && [ -r "$TOMCAT_HOME/webapps" ] || { echo "점검불가|Tomcat webapps 를 읽을 수 없어 애플리케이션 DB 설정 파일을 찾지 못함"; return; }
        echo "양호|DB 연결 정보가 담긴 설정 파일 없음 (검색: conf, webapps/*/WEB-INF·BOOT-INF/classes, META-INF/context.xml)"; return
    fi
    for f in $hits; do p=$(get_perm "$f"); [ -n "$p" ] && _perm_over "$p" 600 && o="${o} ${f}(${p})"; done
    [ -n "$o" ] && echo "취약|DB 연결 정보 포함 설정 파일 권한 600 초과(일반 사용자 접근 가능):${o}" || echo "양호|DB 연결 설정 파일 권한 600 이하: $(echo $hits | tr ' ' '\n' | while read -r f; do printf '%s(%s) ' "$f" "$(get_perm "$f")"; done)"
}
_v_dbconf_jeus() {
    local f hits="" o="" p
    for f in $(_JX domain.xml 5) $(_JX jeus-web-dd.xml 50) $(_JX JEUSMain.xml 5); do [ -r "$f" ] && _xml_nc < "$f" | grep -qiE '<data-?source|jdbc:' && hits="${hits} ${f}"; done
    [ -z "$(_unreadable $(_JX domain.xml 5))" ] || { echo "점검불가|JEUS domain.xml 읽기 권한 없음 (실행 계정 $(_me))"; return; }
    [ -n "$hits" ] || { echo "양호|JEUS 설정 파일에 DB 연결 리소스(data-source/jdbc:) 없음"; return; }
    for f in $hits; do p=$(get_perm "$f"); [ -n "$p" ] && _perm_over "$p" 600 && o="${o} ${f}(${p})"; done
    [ -n "$o" ] && echo "취약|DB 연결 정보 포함 설정 파일 권한 600 초과:${o}" || echo "양호|DB 연결 설정 파일 권한 600 이하:${hits}"
}
_spring_procs() {   # 스프링 부트로 보이는 실행 중 프로세스의 jar (인자에 org.springframework.boot / --spring. / -Dspring. 가 있거나, -jar 대상 jar 안에 BOOT-INF 가 있는 것)
    local l j
    printf '%s\n' "$_PSALL" | grep -E '(^|[[:space:]/])java[[:space:]].*(-jar |org\.springframework\.boot)' | while read -r l; do
        j=$(printf '%s\n' "$l" | grep -oE -- '-jar[[:space:]]+[^[:space:]]+' | awk '{print $2}' | sed -n 1p)
        if printf '%s\n' "$l" | grep -qE 'org\.springframework\.boot|(^|[[:space:]])(--|-D)spring\.'; then echo "${j:-spring-boot}"; continue; fi
        [ -n "$j" ] && [ -r "$j" ] && grep -qa 'BOOT-INF/' "$j" 2>/dev/null && echo "$j"
    done | sort -u
}
_v_dbconf_spring() {   # Spring Boot 독립 실행 앱 (제품 탐지와 무관). 스프링 프로세스·설정 파일이 모두 없으면 출력 없음(대상 아님)
    local hits cfgs procs f p j d o="" l="" n miss="" r=""
    cfgs=$(_spring_cfgs); procs=$(_spring_procs)
    for j in $procs; do   # 실행 중인 앱 중 jar 위치에서 외부 설정 파일을 찾지 못한 것
        case "$j" in /*) d=$(dirname "$j"); printf '%s\n' "$cfgs" | awk -v d="$d/" 'index($0, d) == 1 { f = 1 } END { exit !f }' || miss="${miss} ${j}" ;; *) [ -n "$cfgs" ] || miss="${miss} ${j}" ;; esac
    done
    [ -n "$miss" ] && r="점검불가|[Spring Boot] 실행 중인 앱(${miss# })은 탐지됐으나 외부 설정 파일(application*.properties/yml)을 찾지 못함 - jar 내부(BOOT-INF/classes) 설정이거나 설정 경로 확인 필요"
    if [ -n "$cfgs" ]; then
        hits=$(printf '%s\n' "$cfgs" | _dbcfg_hits)
        n=$(printf '%s\n' "$cfgs" | grep -c .)
        if [ -z "$hits" ]; then r=$(_worse "$r" "양호|[Spring Boot] 설정 파일 ${n}개에 DB 연결 정보 없음: $(_brief "$cfgs" 3)")
        else
            for f in $hits; do p=$(get_perm "$f"); l="${l} ${f}(${p})"; [ -n "$p" ] && _perm_over "$p" 600 && o="${o} ${f}(${p})"; done
            if [ -n "$o" ]; then r=$(_worse "$r" "취약|[Spring Boot] DB 연결 정보 포함 설정 파일 권한 600 초과:${o}"); else r=$(_worse "$r" "양호|[Spring Boot] DB 연결 설정 파일 권한 600 이하:${l}"); fi
        fi
    fi
    [ -n "$r" ] && echo "$r"
    return 0
}
_ev_dbconf() {
    _hasw tomcat && _tc_ev '_tc_appcfgs | sort -u | _dbcfg_hits | while read -r f; do echo "== $f ($(get_perm "$f"))"; ls -l "$f"; case "$f" in *.xml) _xml_nc < "$f" ;; *) grep -v "^[[:space:]]*[#!;]" "$f" ;; esac | grep -iE "jdbc:|DataSource|spring\.datasource|username|url" | _mask_pw; done; echo "후보 파일 수: $(_tc_appcfgs | sort -u | grep -c .)"'
    _hasw jeus && _je_ev 'for f in $(_JX domain.xml 5) $(_JX jeus-web-dd.xml 50) $(_JX JEUSMain.xml 5); do echo "== $f ($(get_perm "$f"))"; ls -l "$f"; _xml_nc < "$f" | grep -iE "jdbc:|data-?source|user" | _mask_pw; done'
    echo "-- Spring Boot 실행 프로세스 jar: $(_spring_procs | tr '\n' ' ')"
    echo "-- Spring Boot 설정 파일 (실행 중 java -jar / cwd / spring.config.location), 후보 $(_spring_cfgs | grep -c .)개"
    _spring_cfgs | _dbcfg_hits | while read -r f; do echo "== $f ($(get_perm "$f"))"; ls -l "$f"; grep -v '^[[:space:]]*[#!;]' "$f" | grep -iE 'jdbc:|spring\.datasource|username|url' | _mask_pw; done
}

# ── 주요 설정 파일 권한 (WEB-14) ──────────────────────────────
_conf_files_all() {
    local h
    [ -n "$APACHE_CONF" ] && [ -z "$_AP_UN" ] && _ap_files
    [ -n "$NGINX_CONF" ] && [ -z "$_NG_UN" ] && _ng_files
    for h in $TOMCAT_HOMES; do for f in server.xml web.xml context.xml tomcat-users.xml; do [ -f "$h/conf/$f" ] && echo "$h/conf/$f"; done; done
    for h in $JEUS_HOMES; do JEUS_HOME=$h _JX accounts.xml 5; JEUS_HOME=$h _JX domain.xml 5; done
    [ -n "$_WT_M" ] && echo "$_WT_M"
}
_v_confperm_all_core() {
    local cf f p o="" n=0 l=""
    cf=$(_conf_files_all | sort -u)
    [ -n "$cf" ] || { echo "점검불가|주요 설정 파일을 확인하지 못함"; return; }
    for f in $cf; do p=$(get_perm "$f"); [ -n "$p" ] || continue; n=$((n+1)); _perm_over "$p" 750 && o="${o} ${f}(${p})"; done
    if [ -n "$o" ]; then echo "취약|주요 설정 파일에 일반 사용자 권한 부여(가이드 기준 750 이하):$(_brief "$(echo $o | tr ' ' '\n')" 5)"
    elif [ "$n" -gt 0 ]; then echo "양호|주요 설정 파일 권한 750 이하 (${n}개 확인)"
    else echo "점검불가|주요 설정 파일 권한을 조회하지 못함"; fi
}
_ev_confperm() {
    local f; for f in $(_conf_files_all | sort -u); do ls -l "$f"; done
    echo "대상 파일 수: $(_conf_files_all | sort -u | grep -c .)"
}

# ── 불필요한 스크립트 매핑 (WEB-15) ───────────────────────────────
_v_scriptmap_tomcat() {
    local u sm; u=$(_tc_need web.xml) || { echo "$u"; return; }
    sm=$(_tcx web.xml | grep -A1 '<servlet-mapping>' | grep -oE '<servlet-name>[^<]+' | sed 's/<servlet-name>//' | sort -u | grep -vxE 'default|jsp' | tr '\n' ' ')
    [ -n "$sm" ] && echo "취약|conf/web.xml 기본 외 스크립트 매핑 활성: ${sm}(cgi/ssi/invoker 등 불필요 시 제거)" || echo "양호|conf/web.xml 매핑 기본값(default, jsp)만 사용"
}
_v_scriptmap_jeus() {
    local f n=0 l=""; for f in $(_JX web.xml 50); do n=$((n+1)); done
    [ "$n" -gt 0 ] && echo "수동확인|JEUS web.xml ${n}개의 servlet-mapping 목록(증적) 중 불필요 매핑 확인" || echo "점검불가|JEUS web.xml 을 찾지 못함"
}
_ev_scriptmap() {
    _hasw tomcat && _tc_ev 'echo "-- conf/web.xml servlet-mapping (주석 제외)"; _tcx web.xml | grep -A2 "<servlet-mapping>" | grep -E "servlet-name|url-pattern"'
    _hasw jeus && _je_ev 'for f in $(_JX web.xml 50); do echo "-- $f"; _xml_nc < "$f" | grep -A2 "<servlet-mapping>" | grep -E "servlet-name|url-pattern"; done'
}

# ── 버전/EoS (WEB-25, WST-080/126) ────────────────────────────
EOS_SCRIPT="$(dirname "$0")/eos_checker.py"
[ -f "$EOS_SCRIPT" ] || EOS_SCRIPT="$(dirname "$0")/../converter/eos_checker.py"   # 저장소 구조 그대로 실행 시
_eos_one() {
    local p="$1" v="$2" r d
    [ -n "$v" ] || { echo "점검불가|${p} 버전을 확인하지 못함 (버전 명령/RELEASE-NOTES 조회 실패)"; return; }
    [ -f "$EOS_SCRIPT" ] || { echo "점검불가|${p} ${v}: eos_checker.py 없음 - EoS 판정 불가"; return; }
    local _py _eo; _py=$(command -v python3 2>/dev/null || { [ -x /usr/libexec/platform-python ] && echo /usr/libexec/platform-python; } || command -v python 2>/dev/null)
    [ -n "$_py" ] || { echo "점검불가|${p} ${v}: python 미설치 - EoS 판정 불가"; return; }
    _eo=$("$_py" "$EOS_SCRIPT" "$p" "$v" 2>/dev/null)   # 인터넷 연결 시 endoflife.date 조회, 아니면 내장 데이터
    r=$(echo "$_eo" | grep "^결과:" | awk '{print $2}')
    d=$(echo "$_eo" | grep "^설명:" | cut -d: -f2- | sed "s/^ *//;s/ *$//")
    [ -n "$r" ] || { echo "점검불가|${p} ${v}: EoS 판정 실패 (${d:-eos_checker 출력 없음})"; return; }
    echo "${r}|${p} ${v}: ${d}"
}
_v_eos_apache() { _eos_one apache "$(_apache_ver)"; }
_v_eos_nginx() { _eos_one nginx "$(_nginx_ver)"; }
_v_eos_webtob() { echo "수동확인|WebtoB ${_wv2:-버전 확인 필요}"; }
_v_eos_tomcat() { _eos_one tomcat "$(_tomcat_ver "$TOMCAT_HOME")"; }
_v_eos_jeus() { local jv; jv=$( { jeusadmin -version 2>/dev/null || "$JEUS_HOME/bin/jeusadmin" -version 2>/dev/null; } | sed -n 1p); echo "수동확인|JEUS ${jv:-버전 확인 필요(jeusadmin -version 실행 불가)} - 벤더 지원 정책 대조"; }
_ev_eos() {
    _hasw apache && _show "Apache 버전" sh -c 'httpd -v 2>&1 || apache2 -v 2>&1 || apachectl -v 2>&1'
    _hasw nginx && _show "Nginx 버전" sh -c 'nginx -v 2>&1'
    _hasw webtob && _show "WebtoB 버전" sh -c "wscfl -version 2>&1 || { [ -n '$_WT_HOME' ] && '$_WT_HOME/bin/wscfl' -version 2>&1; } || echo 'wscfl 실행 불가 (WebtoB 설치 경로 ${_WT_HOME:-미확인})'"
    _hasw tomcat && _tc_ev 'echo "버전: $(_tomcat_ver "$TOMCAT_HOME")"; h=$(_tc_home "$TOMCAT_HOME"); grep -h "Apache Tomcat Version" "$h/RELEASE-NOTES" "$TOMCAT_HOME/RELEASE-NOTES" 2>&1'
    _hasw jeus && _je_ev 'jeusadmin -version 2>&1 || "$JEUS_HOME/bin/jeusadmin" -version 2>&1'
}
_v_patch_all() {   # WEB-25: 버전 EoS 판정 + 패치 이력 수동 확인
    local r; r=$(_combine eos "Apache Tomcat Nginx JEUS WebtoB")
    case "${r%%|*}" in 취약|점검불가) echo "$r" ;; *) echo "수동확인|${r#*|} - 벤더 최신 보안 패치 적용 여부·패치 관리 정책(주기적 점검) 확인" ;; esac
}

# ── 로그 디렉터리 권한 (WEB-26) ───────────────────────────────
_realdir() { readlink -f "$1" 2>/dev/null || ( cd "$1" 2>/dev/null && pwd -P ) || echo "$1"; }
_log_dirs() {
    local d h
    _hasw apache && [ -z "$_AP_UN" ] && { for d in /var/log/httpd /var/log/apache2 "$(_apache_root)/logs"; do [ -d "$d" ] && echo "$d"; done
        _active '(ErrorLog|CustomLog)[[:space:]]+/' | awk '{print $2}' | tr -d '"' | while read -r d; do dirname "$d"; done; }
    _hasw nginx && [ -z "$_NG_UN" ] && { _ngx '^(access|error)_log[[:space:]]+/' | awk '{print $2}' | tr -d ';' | while read -r d; do dirname "$d"; done; [ -d /var/log/nginx ] && echo /var/log/nginx; }
    for h in $TOMCAT_HOMES; do echo "$h/logs"; done
    for d in /var/log/tomcat*; do [ -d "$d" ] && echo "$d"; done
    for h in $JEUS_HOMES; do for d in "$h"/domains/*/servers/*/logs; do [ -d "$d" ] && echo "$d"; done; done
    [ -n "$_WT_HOME" ] && echo "$_WT_HOME/log"
}
_log_dirs_real() { _log_dirs | while read -r d; do [ -d "$d" ] && _realdir "$d"; done | sort -u; }
_v_logperm_all_core() {
    local ld d p f o="" un="" n=0
    ld=$(_log_dirs_real | tr '\n' ' ')
    if [ -z "${ld// /}" ]; then echo "점검불가|로그 디렉터리를 확인하지 못함"; return; fi
    for d in $ld; do
        if [ ! -r "$d" ] || [ ! -x "$d" ]; then un="${un} ${d}"; continue; fi
        p=$(get_perm "$d"); n=$((n+1)); [ -n "$p" ] && _perm_over "$p" 770 && o="${o} ${d}/(${p})"
        for f in $(_findd 1 "$d" -type f ! -name '*.pid' ! -name '*.lock' | sed -n 1,200p); do p=$(get_perm "$f"); [ -n "$p" ] && _perm_over "$p" 770 && { o="${o} ${f}(${p})"; break; }; done
    done
    if [ -n "$o" ]; then echo "취약|로그 디렉터리/파일에 일반 사용자(other) 권한 존재:${o} (가이드: o-rwx, 디렉터리 750·파일 640)${un:+ / 점검불가(읽기 권한 없음):${un}}"
    elif [ -n "$un" ] && [ "$n" -eq 0 ]; then echo "점검불가|로그 디렉터리 접근 권한 없음:${un} (실행 계정 $(_me))"
    elif [ -n "$un" ]; then echo "점검불가|일부 로그 디렉터리 접근 권한 없음:${un} (확인한 ${n}개는 other 권한 없음)"
    else echo "양호|로그 디렉터리·파일에 일반 사용자 권한 없음: ${ld}"; fi
}
# 제품 구분 없이 경로·파일을 합산하는 판정은 설정을 읽지 못한 제품(Apache/Nginx/WebtoB/JEUS)을 조용히 빼지 않고 '점검불가' 사유를 함께 낸다
_un_all() {
    local o=""
    _hasw apache && [ -n "$_AP_UN" ] && o="${o:+$o / }[Apache] $_AP_UN"
    _hasw nginx && [ -n "$_NG_UN" ] && o="${o:+$o / }[Nginx] $_NG_UN"
    _hasw webtob && [ -n "$_WT_UN" ] && o="${o:+$o / }[WebtoB] $_WT_UN"
    _hasw jeus && [ -n "$_JE_UN" ] && o="${o:+$o / }[JEUS] $_JE_UN"
    [ -n "$o" ] && echo "점검불가|$o"
    return 0
}
_v_docroot_all() { _worse "$(_v_docroot_all_core)" "$(_un_all)"; }
_v_confperm_all() { _worse "$(_v_confperm_all_core)" "$(_un_all)"; }
_v_upload_dirs() { _worse "$(_v_upload_dirs_core)" "$(_un_all)"; }
_v_wst034() { _worse "$(_v_wst034_core)" "$(_un_all)"; }
_v_logperm_all() { _worse "$(_v_logperm_all_core)" "$(_un_all)"; }
_ev_logperm() {
    local d; for d in $(_log_dirs_real); do echo "== $d"; ls -ld "$d"; ls -l "$d" 2>&1; done
    echo "대상 로그 디렉터리 수: $(_log_dirs_real | grep -c .)"
}

# ── WST 전용 ─────────────────────────────────────────────────
_v_dirtrav() {   # WST-033: 상위 디렉터리 접근 제한 (Directory Traversal 취약 버전)
    local r="" x av h _nv _tv; _nv=$(_nginx_ver)
    if _hasw apache; then
        if [ -n "$_AP_UN" ]; then x="점검불가|$_AP_UN"; else
        av=$(_apache_ver)
        case "$av" in
        2.4.49|2.4.50) x="취약|Apache ${av} - Directory Traversal 취약 버전 (CVE-2021-41773/42013)" ;;
        "")            x="점검불가|Apache 버전 확인 실패(httpd -v / apache2 -v 실행 불가) - Directory Traversal 취약 버전 여부 판정 불가" ;;
        *)             x="양호|Apache ${av} - Directory Traversal 취약 버전(2.4.49/2.4.50) 아님" ;;
        esac; fi
        r=$(_worse "$r" "$(_worse_lab "$x" Apache)")
    fi
    _hasw nginx && r=$(_worse "$r" "수동확인|[Nginx] ${_nv:-버전 확인 실패}: Directory Traversal 취약점 해당 여부 수동 확인")
    _hasw webtob && r=$(_worse "$r" "수동확인|[WebtoB] 버전의 Directory Traversal 취약점 해당 여부 수동 확인")
    for h in $TOMCAT_HOMES; do _tv=$(_tomcat_ver "$h"); r=$(_worse "$r" "수동확인|[Tomcat $h] 버전 ${_tv:-확인 실패} 의 Directory Traversal 취약점 해당 여부 수동 확인"); done
    _hasw jeus && r=$(_worse "$r" "수동확인|[JEUS] 버전의 Directory Traversal 취약점 해당 여부 수동 확인")
    echo "$r"
}
_ev_dirtrav() {
    _hasw apache && _show "Apache 버전" sh -c 'httpd -v 2>&1 || apache2 -v 2>&1 || apachectl -v 2>&1'
    _hasw nginx && _show "Nginx 버전" sh -c 'nginx -v 2>&1'
    _hasw tomcat && _tc_ev 'echo "Tomcat 버전: $(_tomcat_ver "$TOMCAT_HOME")"'
}
_v_wst034_core() {
    local r="" f d b cg="" tmp="" x ex
    for d in $(_cgi_dirs); do [ -d "$d" ] && ls "$d" 2>/dev/null | grep -qE '^(printenv|test-cgi)' && cg="${cg} 디폴트cgi:${d}"; done
    for d in $(_web_docroots); do
        [ -d "$d" ] || continue
        b=$(_findd 3 "$d" -type f \( -name '*.bak' -o -name '*.old' -o -name '*.tmp' -o -name '*.orig' -o -name '*~' -o -name '*.swp' \) | sed -n 1,3p | tr '\n' ' ')
        [ -n "$b" ] && tmp="${tmp} 임시/백업:${b}"
    done
    for d in $JEUS_HOMES; do for x in samples examples; do [ -d "$d/$x" ] && cg="${cg} JEUS샘플:$d/$x"; done; done
    if [ -z "$(_web_docroots)" ] && [ -z "$cg" ]; then echo "점검불가|웹 서비스 경로(DocumentRoot 등)를 확인하지 못해 임시/백업 파일을 점검할 수 없음"; return; fi
    [ -n "$cg$tmp" ] && echo "취약|불필요 파일 존재:${cg}${tmp}" || echo "양호|디폴트 cgi-bin·임시/백업 파일·샘플 디렉터리 미발견 (점검 경로: $(_web_docroots | tr '\n' ' '))"
}
_ev_wst034() {
    _show "CGI 후보 디렉터리 존재/내용" sh -c "for d in $(_cgi_dirs | tr '\n' ' '); do if [ -d \"\$d\" ]; then echo \"== \$d\"; ls -l \"\$d\"; else echo \"없음: \$d\"; fi; done"
    local d; for d in $(_web_docroots); do _show "임시/백업 파일 (깊이 3): $d" sh -c "if [ -d '$d' ]; then find '$d' -path '$d/*/*/*/*' -prune -o -type f \\( -name '*.bak' -o -name '*.old' -o -name '*.tmp' -o -name '*.orig' -o -name '*~' -o -name '*.swp' \\) -print; else echo '디렉터리 없음: $d'; fi"; done
}
_v_wst039() {
    local run
    [ -n "$_PSUSR" ] || { echo "점검불가|프로세스 목록(ps) 조회 실패"; return; }
    run=$( { printf '%s\n' "$_PSUSR" | awk '{ c = $2; sub(/.*\//, "", c); print c }' | grep -xE 'httpd|apache2|nginx:?|wsm|htl|hth|httpd\.(worker|event|prefork)'
             printf '%s\n' "$_PSUSR" | grep -q 'org.apache.catalina' && echo tomcat; printf '%s\n' "$_PSUSR" | grep -q -- '-Djeus.home' && echo jeus; } | sort -u | tr '\n' ' ')
    [ -n "$run" ] && echo "수동확인|실행 중인 웹 서비스: ${run}- 업무상 필요 여부 확인" || echo "양호|실행 중인 웹 서비스 없음"
}
_ev_wst039() { _show "실행 중인 웹/WAS 프로세스 (비밀번호 인자 마스킹)" _ps_web; _show "서비스 상태" sh -c 'systemctl list-units --type=service --state=running 2>/dev/null | grep -iE "httpd|apache|nginx|tomcat|jeus|webtob"'; }
_v_ldap_all() {
    local r; r=$(_combine ldap "Apache Tomcat Nginx")
    [ -n "$r" ] && echo "$r" || echo "수동확인|LDAP 연동 설정 수동 확인 (JEUS/WebtoB 설정은 자동 해석 불가)"
}
_ev_ldap_all() { _ev_ldap; }

# ════════════════════════════════════════════════════════════════
# [3] 실행: 설정 해석 → HTTP 응답 수집 → 평가기준(WST) → 주요정보 상세가이드(WEB-01~26)
# ════════════════════════════════════════════════════════════════
exec </dev/null   # 설정 파일 목록이 비었을 때 grep 등이 표준입력을 기다리며 멈추지 않도록
_PSUSR=$( { UNIX95=1 ps -eo user=,args= 2>/dev/null || ps -ef 2>/dev/null | awk '{ u = $1; c = ""; for (i = 8; i <= NF; i++) c = c " " $i; print u c }'; } )
_KP=""; for _p in apache nginx webtob tomcat jeus; do _hasw "$_p" && _KP="${_KP} $(_pname "$_p")"; done
_kt() { local p o=""; for p in $_KP; do case " $1 " in *" $p "*) o="${o} ${p}" ;; esac; done; echo "${o# }"; }   # 탐지 제품 중 대상
_ALLT="Apache Nginx WebtoB Tomcat JEUS"

if [ -n "$WEB_LIST$WAS_LIST" ]; then
    _hp_init; _hp_listen_load; _setup_conf
    [ -n "$_HPD" ] && _hp_collect_targets
    _hp_probe_all
    {
        echo "# 설정 해석: Apache ${_AP_UN:+(점검불가: $_AP_UN)}${APACHE_CONF:+$APACHE_CONF}, Nginx ${_NG_UN:+(점검불가: $_NG_UN)}${NGINX_CONF:+$NGINX_CONF}, WebtoB ${_WT_UN:+(점검불가: $_WT_UN)}${_WT_M:+$_WT_M}, JEUS ${_JE_UN:+(점검불가: $_JE_UN)}${JEUS_HOMES}"
        echo "# HTTP 응답 수집: 도구=${_HP_TOOL:-없음}${_HP_NOTE:+ ($_HP_NOTE)}, 대상 포트=$(printf '%s\n' "$_HP_TARGETS" | awk -F'|' '{ printf "%s:%s ", $1, $2 }')"
    } >> "$_EVD"
fi
trap '_hp_cleanup' EXIT

_wstx() {   # _wstx 코드 증적함수 판정함수  (판정함수는 "판정|근거" 출력)
    local code="$1" ev="$2" fn="$3" r
    if [ -z "$WEB_LIST$WAS_LIST" ]; then evd "$code" "_detect_summary"; result "${code}|N-A|웹서버/WAS 미탐지"; return 0; fi
    evd "$code" "$ev"
    r=$($fn </dev/null)
    result "${code}|${r:-수동확인|점검 결과 없음 - 수동 확인}"
}
_wst() {   # _wst 코드 점검명 증적함수 [대상목록]
    local code="$1" chk="$2" ev="$3" tg="${4:-$_ALLT}" r
    if [ -z "$WEB_LIST$WAS_LIST" ]; then evd "$code" "_detect_summary"; result "${code}|N-A|웹서버/WAS 미탐지"; return 0; fi
    if [ -z "$(_kt "$tg")" ]; then evd "$code" "_detect_summary"; result "${code}|N-A|점검 대상(${tg// /, }) 제품 미탐지 (탐지:${_KP})"; return 0; fi
    evd "$code" "$ev"
    r=$(_combine "$chk" "$tg")
    result "${code}|${r:-수동확인|점검 결과 없음 - 수동 확인}"
}

if [ "$_KMODE" != "mi" ]; then
# ── 전자금융 평가기준 [웹서버-WAS] WST ───────────────────────────
_wstx WST-033 _ev_dirtrav _v_dirtrav
_wstx WST-034 _ev_wst034 _v_wst034
_wst  WST-035 upload _ev_upload
_wst  WST-036 webproc _ev_webproc
_wstx WST-037 _ev_docroot _v_docroot_all
_wstx WST-038 _ev_wst038 _v_wst038
_wstx WST-039 _ev_wst039 _v_wst039
if [ -z "$WEB_LIST$WAS_LIST" ]; then _wst WST-044 wst044 _detect_summary
elif [ -z "$(_kt "Tomcat JEUS")" ]; then evd "WST-044" "_detect_summary"; result "WST-044|N-A|관리 계정을 사용하는 WAS(Tomcat/JEUS) 미탐지"
else _wst WST-044 wst044 _ev_wst044 "Tomcat JEUS"; fi
_wst  WST-031 listing _ev_listing
_wst  WST-102 servinfo _ev_servinfo
_wst  WST-121 proxy _ev_proxy
_wst  WST-122 ssi _ev_ssi
_ERRSTRICT=1; _wst WST-123 errpage _ev_errpage; _ERRSTRICT=0
_wstx WST-124 _ev_ldap_all _v_ldap_all
_wstx WST-125 _ev_upload_dirs _v_upload_dirs

# WST-032·040·041·042·043: 평가기준상 Windows(IIS) 평가대상 항목 → Unix/Linux N-A
for _c in 032 040 041 042 043; do
    evd "WST-${_c}" "uname -s"
    result "WST-${_c}|N-A|Windows(IIS) 평가대상 항목 (Unix/Linux 해당 없음)"
done

# WST-080: 주기적인 보안패치 (OS 판정 + 웹서버/WAS 버전 확인 병합)
evd "WST-080" "_ev_eos"
_wver=""
_hasw apache && _wver="Apache $(_apache_ver)"
_hasw nginx && _wver="${_wver:+$_wver / }Nginx $(_nginx_ver)"
_hasw webtob && _wver="${_wver:+$_wver / }WebtoB"
for _h in $TOMCAT_HOMES; do _wver="${_wver:+$_wver / }Tomcat[${_h}] $(_tomcat_ver "$_h")"; done
_hasw jeus && _wver="${_wver:+$_wver / }JEUS"
if [ -n "$_wver" ]; then _merge_hold "WST-080" "수동확인" "웹 제품 보안패치 확인 필요 (${_wver}) - 벤더 보안 공지 대조"   # 웹/WAS 미탐지 호스트는 OS 판정만
else _merge_hold "WST-080" "" ""; fi

# WST-126: EoS (OS 판정 + 웹서버/WAS 제품 EoS 병합)
evd "WST-126" "_ev_eos"
_w126=""; [ -n "$WEB_LIST$WAS_LIST" ] && _w126=$(_combine eos "$_ALLT")
if [ -n "$_w126" ]; then _merge_hold "WST-126" "${_w126%%|*}" "${_w126#*|}"; else _merge_hold "WST-126" "" ""; fi
fi   # WST 끝

# ════════════════════════════════════════════════════════════════
# [4] 주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드(2026) — 웹 서비스 WEB-01 ~ WEB-26
#     가이드 항목코드·판단기준 그대로 판정 (전자금융 WST 결과와 별개, 컨버터 주요정보 모드에서 사용)
#     제품별 점검 대상은 가이드 '점검 대상' 기준 (IIS 는 check_webwas.ps1)
# ════════════════════════════════════════════════════════════════
_web() {   # _web 코드 대상목록 점검명 증적함수
    local code="$1" tg="$2" chk="$3" ev="$4" r
    if [ -z "$WEB_LIST$WAS_LIST" ]; then evd "$code" "_detect_summary"; result "${code}|N-A|웹서버/WAS 미탐지"; return 0; fi
    if [ -z "$(_kt "$tg")" ]; then evd "$code" "_detect_summary"; result "${code}|N-A|가이드 점검 대상(${tg// /, }) 제품 미탐지 (탐지:${_KP})"; return 0; fi
    evd "$code" "$ev"
    r=$(_combine "$chk" "$tg")
    result "${code}|${r:-수동확인|점검 결과 없음 - 수동 확인}"
}
_webx() {   # _webx 코드 대상목록 증적함수 판정함수
    local code="$1" tg="$2" ev="$3" fn="$4" r
    if [ -z "$WEB_LIST$WAS_LIST" ]; then evd "$code" "_detect_summary"; result "${code}|N-A|웹서버/WAS 미탐지"; return 0; fi
    if [ -z "$(_kt "$tg")" ]; then evd "$code" "_detect_summary"; result "${code}|N-A|가이드 점검 대상(${tg// /, }) 제품 미탐지 (탐지:${_KP})"; return 0; fi
    evd "$code" "$ev"
    r=$($fn </dev/null)
    result "${code}|${r:-수동확인|점검 결과 없음 - 수동 확인}"
}
if [ "$_KMODE" != "ef" ]; then   # 전자금융 모드는 가이드 WEB 판정 생략
_web  WEB-01 "Tomcat JEUS" admin _ev_admin
_web  WEB-02 "Tomcat IIS JEUS" weakpw _ev_weakpw
_web  WEB-03 "Tomcat IIS JEUS" pwfile _ev_pwfile
_web  WEB-04 "$_ALLT IIS" listing _ev_listing
_web  WEB-05 "Apache Tomcat Nginx IIS WebtoB" cgi _ev_cgi
_web  WEB-06 "Apache Tomcat Nginx IIS WebtoB" updir _ev_updir
_web  WEB-07 "$_ALLT IIS" unneeded _ev_unneeded
_web  WEB-08 "$_ALLT IIS" upload _ev_upload
_web  WEB-09 "$_ALLT IIS" webproc _ev_webproc
_web  WEB-10 "$_ALLT IIS" proxy _ev_proxy
_webx WEB-11 "$_ALLT IIS" _ev_docroot _v_docroot_all
_web  WEB-12 "$_ALLT IIS" links _ev_links
# WEB-13: Tomcat·JEUS 설정 + Spring Boot 독립 실행 앱(application.properties/yml)
_sp=$(_v_dbconf_spring </dev/null)
if [ -z "$(_kt "Tomcat JEUS")" ] && [ -z "$_sp" ]; then
    evd "WEB-13" "_ev_dbconf"; result "WEB-13|N-A|가이드 점검 대상(Tomcat, JEUS) 제품 및 Spring Boot 앱 미탐지 (탐지:${_KP:- 없음})"
else
    evd "WEB-13" "_ev_dbconf"
    _r13=$(_combine dbconf "Tomcat JEUS"); [ -n "$_sp" ] && _r13=$(_worse "$_r13" "$_sp")
    result "WEB-13|${_r13:-수동확인|점검 결과 없음 - 수동 확인}"
fi
_webx WEB-14 "$_ALLT IIS" _ev_confperm _v_confperm_all
_web  WEB-15 "Tomcat IIS JEUS" scriptmap _ev_scriptmap
_web  WEB-16 "$_ALLT IIS" servinfo _ev_servinfo
_web  WEB-17 "Apache Tomcat Nginx WebtoB" vdir _ev_vdir
_web  WEB-18 "Apache Nginx IIS WebtoB" webdav _ev_webdav
_web  WEB-19 "Apache Tomcat Nginx IIS WebtoB" ssi _ev_ssi
_web  WEB-20 "Apache Nginx IIS WebtoB" ssl _ev_ssl
_web  WEB-21 "Apache Nginx IIS WebtoB" redirect _ev_redirect
_ERRSTRICT=0; _web WEB-22 "$_ALLT IIS" errpage _ev_errpage
_web  WEB-23 "Tomcat" ldap _ev_ldap
_webx WEB-24 "$_ALLT IIS" _ev_upload_dirs _v_upload_dirs
_webx WEB-25 "$_ALLT IIS" _ev_eos _v_patch_all
_webx WEB-26 "$_ALLT IIS" _ev_logperm _v_logperm_all
fi   # [4] 주요정보 WEB 판정 끝

_TOTAL=$((_CP + _CF + _CM + _CN + _CU))
echo "# ================================================================"
echo "# 점검 요약"
echo "#   총 점검 항목: ${_TOTAL}"
[ "$_TOTAL" -gt 0 ] 2>/dev/null && {
echo "#   양호:         ${_CP}  ($((_CP * 100 / _TOTAL))%)"
echo "#   취약:         ${_CF}  ($((_CF * 100 / _TOTAL))%)"
echo "#   점검불가:     ${_CU}"
echo "#   수동확인:     ${_CM}"
echo "#   N-A:          ${_CN}"
}
echo "# ================================================================"
echo "# 점검 완료: $(date '+%Y-%m-%d %H:%M:%S')"
echo "# 증적 파일: ${_EVD}"
[ -n "$_RESF" ] && echo "# 결과 파일(자동 저장): ${_RESF}  ← 증적 파일과 함께 회수"
[ -n "$_TEEPID" ] && { exec >&- 2>/dev/null; wait "$_TEEPID" 2>/dev/null; sleep 1; }
exit 0
