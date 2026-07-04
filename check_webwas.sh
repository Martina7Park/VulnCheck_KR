#!/bin/bash
# ================================================================
# 전자금융기반시설 웹서버/WAS 취약점 점검 스크립트 v4.0
# 기준: 전자금융기반시설 보안 취약점 평가기준 제2026-1호 [웹서버-WAS]
#
# 지원: Apache, WebtoB, Nginx / Tomcat, JEUS / Windows IIS
#       OS: AIX/HP-UX/Linux/Solaris
#
# [사용법] bash check_webwas.sh > /tmp/$(hostname)_webwas.txt
# [출력]   WST-항목코드|결과|근거
# ================================================================

# ── OS/서버 탐지 ────────────────────────────────────────────────
detect_os() {
    OS_FAMILY="LINUX"; OS_DISTRO="UNKNOWN"; OS_MAJOR=0
    case "$(uname -s)" in
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

# Tomcat 탐지
for d in /opt/tomcat /usr/local/tomcat /srv/tomcat /var/lib/tomcat* /opt/apache-tomcat*; do
    [ -f "$d/conf/server.xml" ] && TOMCAT_HOME="$d" && WAS_SRV="tomcat" && break
done
[ -z "$WAS_SRV" ] && [ -n "$CATALINA_HOME" ] && [ -f "$CATALINA_HOME/conf/server.xml" ] && \
    TOMCAT_HOME="$CATALINA_HOME" && WAS_SRV="tomcat"
# JEUS 탐지
[ -z "$WAS_SRV" ] && [ -n "$JEUS_HOME" ] && WAS_SRV="jeus"

echo "# ================================================================"
echo "# 점검 대상: ${HN}"
echo "# OS: ${OS_FAMILY} / ${OS_DISTRO} ${OS_MAJOR}"
echo "# 웹서버: ${WEB_SRV:-미탐지}"
echo "# WAS: ${WAS_SRV:-미탐지}"
echo "# 점검 기준: 전자금융기반시설 보안 취약점 평가기준 제2026-1호 [웹서버-WAS]"
echo "# 점검 일시: $(date '+%Y-%m-%d %H:%M:%S')"
echo "# ================================================================"

is_running() {
    local svc="$1"
    command -v systemctl >/dev/null 2>&1 && systemctl is-active "$svc" 2>/dev/null | grep -q "^active" && return 0
    ps -ef 2>/dev/null | grep -v grep | grep -qi "$svc" && return 0
    return 1
}

# ── OS 레벨 점검 (SRV와 동일 항목, WST 코드로 출력) ─────────────

# WST-023: root 원격 접속 제한
val=""
[ -d /etc/ssh/sshd_config.d ] && val=$(grep -rih "^PermitRootLogin" /etc/ssh/sshd_config.d/ 2>/dev/null | awk '{print $2}' | tail -1)
[ -z "$val" ] && val=$(grep -i "^PermitRootLogin" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' | tail -1)
case "${val,,}" in
no|prohibit-password|forced-commands-only) echo "WST-023|양호|PermitRootLogin=${val}" ;;
yes)  echo "WST-023|취약|PermitRootLogin=yes" ;;
*)    echo "WST-023|취약|PermitRootLogin 미설정" ;;
esac

# WST-025: 원격 터미널 타임아웃
tmout=""
for f in /etc/profile /etc/bashrc /etc/bash.bashrc /root/.bashrc /root/.profile /etc/profile.d/*.sh; do
    [ -f "$f" ] || continue
    t=$(grep -h "TMOUT" "$f" 2>/dev/null | grep -v "^#" | grep -oE "[0-9]+" | head -1)
    [ -n "$t" ] && tmout=$t && break
done
[ -z "$tmout" ] && echo "WST-025|취약|TMOUT 미설정" || {
    [ "$tmout" -le 600 ] 2>/dev/null && echo "WST-025|양호|TMOUT=${tmout}초" || echo "WST-025|취약|TMOUT=${tmout}초 (600초 초과)"
}

# WST-028: 불필요 서비스
found=""
for svc in chargen daytime discard rsh rlogin rexec; do
    is_running "$svc" && found="${found} ${svc}"
done
[ -n "$found" ] && echo "WST-028|취약|불필요 서비스 실행:${found}" || echo "WST-028|양호|불필요 서비스 미실행"

# WST-049: 패스워드 최대 사용기간
v=$(grep "^PASS_MAX_DAYS" /etc/login.defs 2>/dev/null | awk '{print $2}')
case "$OS_FAMILY" in
AIX)   v=$(awk '/^default:/,/^[^ \t]/' /etc/security/user 2>/dev/null | grep "maxage" | grep -oE '[0-9]+' | head -1)
        [ -z "$v" ] && echo "WST-049|취약|AIX maxage 미설정" || \
        { [ "$v" -le 12 ] 2>/dev/null && echo "WST-049|양호|AIX maxage=${v}주 ($((v*7))일)" || echo "WST-049|취약|AIX maxage=${v}주($((v*7))일) - 12주(84일) 이하 필요 (기준: 90일 이하)"; } ;;
SOLARIS) v=$(grep "^MAXWEEKS" /etc/default/passwd 2>/dev/null | cut -d= -f2 | tr -d ' ')
        [ -z "$v" ] && echo "WST-049|취약|Solaris MAXWEEKS 미설정" || \
        { [ "$v" -le 12 ] 2>/dev/null && echo "WST-049|양호|Solaris MAXWEEKS=${v}주 ($((v*7))일)" || echo "WST-049|취약|Solaris MAXWEEKS=${v}주($((v*7))일) - 12주(84일) 이하 필요 (기준: 90일 이하)"; } ;;
*)      if [ -z "$v" ]; then echo "WST-049|취약|PASS_MAX_DAYS 미설정"
        elif [ "$v" -eq 0 ] 2>/dev/null; then echo "WST-049|취약|PASS_MAX_DAYS=0 (무제한)"
        elif [ "$v" -le 90 ] 2>/dev/null; then echo "WST-049|양호|PASS_MAX_DAYS=${v}일"
        else echo "WST-049|취약|PASS_MAX_DAYS=${v}일 (90일 초과)"; fi ;;
esac

# WST-050: 패스워드 저장 방식
if [ ! -f /etc/shadow ] && [ "$OS_FAMILY" = "LINUX" ]; then
    echo "WST-050|취약|/etc/shadow 없음"
else
    weak=$(awk -F: '$2 ~ /^\$1\$/ {print $1}' /etc/shadow 2>/dev/null | head -3)
    [ -n "$weak" ] && echo "WST-050|취약|MD5 해시 계정: $(echo $weak | tr '\n' ',')" || echo "WST-050|양호|SHA256/SHA512 해시 사용"
fi

# WST-052: 관리자 그룹 불필요 계정
_wst052_all=""
for grp in wheel sudo admin; do
    members=$(grep "^${grp}:" /etc/group 2>/dev/null | cut -d: -f4)
    [ -n "$members" ] && _wst052_all="${_wst052_all}${grp}:[${members}] "
done
if [ -z "$_wst052_all" ]; then
    echo "WST-052|N-A|관리자 그룹 없음"
else
    cnt=$(for grp in wheel sudo admin; do
        grep "^${grp}:" /etc/group 2>/dev/null | cut -d: -f4 | tr ',' '\n'
    done | grep -v '^$' | sort -u | wc -l)
    if [ "$cnt" -gt 5 ] 2>/dev/null; then
        echo "WST-052|취약|관리자 그룹 멤버 과다(${cnt}명): ${_wst052_all}- 불필요 계정 제거 필요"
    else
        echo "WST-052|수동확인|관리자 그룹: ${_wst052_all}(${cnt}명) - 적정성 수동 확인"
    fi
fi

# WST-054: 패스워드 복잡도
pam_files=""
case "$OS_DISTRO" in
RHEL|CENTOS) pam_files="/etc/pam.d/system-auth /etc/pam.d/password-auth" ;;
UBUNTU|DEBIAN) pam_files="/etc/pam.d/common-auth /etc/pam.d/common-password" ;;
*) pam_files="/etc/pam.d/system-auth" ;;
esac
found="" minlen=0
for f in $pam_files /etc/security/pwquality.conf; do
    [ -f "$f" ] || continue
    grep -qi "pam_pwquality\|pam_cracklib" "$f" 2>/dev/null && found="$f" && \
        ml=$(grep -v "^#" "$f" | grep -oE 'minlen=([0-9]+)' | cut -d= -f2 | head -1) && [ -n "$ml" ] && minlen=$ml && break
done
[ -z "$found" ] && echo "WST-054|취약|pam_pwquality/pam_cracklib 미설정" || \
    { [ "$minlen" -ge 8 ] 2>/dev/null && echo "WST-054|양호|패스워드 복잡도 설정 (minlen=${minlen})" || \
      echo "WST-054|취약|minlen=${minlen} (8자 이상 권고)"; }

# WST-058: Crontab 권한
[ -f /etc/crontab ] && {
    perm=$(stat -c "%a" /etc/crontab 2>/dev/null)
    owner=$(stat -c "%U" /etc/crontab 2>/dev/null)
    [ "$owner" = "root" ] && [ "${perm:-777}" -le 640 ] 2>/dev/null && echo "WST-058|양호|/etc/crontab 권한=${perm}" || \
        echo "WST-058|취약|/etc/crontab 소유자=${owner}, 권한=${perm}"
} || echo "WST-058|N-A|/etc/crontab 없음"

# WST-064: SUID/SGID
dangerous="nmap perl python python3 php find wget curl nc bash gdb strace"
found_vuln=""
for bin in $dangerous; do
    binpath=$(command -v "$bin" 2>/dev/null)
    [ -z "$binpath" ] && continue
    [ -u "$binpath" ] && found_vuln="${found_vuln} ${binpath}"
done
[ -n "$found_vuln" ] && echo "WST-064|취약|위험 SUID:${found_vuln}" || echo "WST-064|양호|위험 SUID 미발견"

# WST-075: 로그 접근통제
vuln=""
for logf in /var/log/messages /var/log/secure /var/log/auth.log /var/log/syslog; do
    [ -f "$logf" ] || continue
    perm=$(stat -c "%a" "$logf" 2>/dev/null)
    [ "${perm:-0}" -gt 644 ] 2>/dev/null && vuln="${vuln} ${logf}(${perm})"
done
[ -n "$vuln" ] && echo "WST-075|취약|로그 권한 이상:${vuln}" || echo "WST-075|양호|로그 파일 권한 적절"

# WST-082: root PATH
path_lines=$(grep -rh "^PATH\|^export PATH" /root/.bashrc /root/.profile /etc/profile /etc/profile.d/*.sh 2>/dev/null | head -3)
echo "$path_lines" | grep -qE ':\.:|\.\.$|^\.:' && echo "WST-082|취약|PATH에 현재 디렉토리(.) 포함" || echo "WST-082|양호|PATH 현재 디렉토리 미포함"

# WST-083: umask
cur=$(umask 2>/dev/null | sed 's/^0*//'); cur=${cur:-22}
[ "${cur:-0}" -ge 22 ] 2>/dev/null && echo "WST-083|양호|umask=${cur}" || echo "WST-083|취약|umask=${cur} (022 이상 권고)"

# WST-087: 로그인 실패 횟수
deny=0; found_pam=0
for f in /etc/security/faillock.conf; do
    [ -f "$f" ] && d=$(grep -v "^#" "$f" | grep "^deny" | grep -oE '[0-9]+' | head -1) && [ -n "$d" ] && deny=$d && found_pam=1 && break
done
for f in /etc/pam.d/system-auth /etc/pam.d/password-auth /etc/pam.d/common-auth; do
    [ -f "$f" ] || continue
    grep -qi "pam_faillock\|pam_tally" "$f" 2>/dev/null && {
        d=$(grep -i "pam_faillock\|pam_tally" "$f" | grep -oE 'deny=([0-9]+)' | cut -d= -f2 | head -1)
        [ -n "$d" ] && deny=$d && found_pam=1 && break
    }
done
[ $found_pam -eq 0 ] && echo "WST-087|취약|로그인 실패 제한 미설정" || \
    { [ "$deny" -le 5 ] 2>/dev/null && echo "WST-087|양호|로그인 실패 제한 deny=${deny}" || echo "WST-087|취약|deny=${deny} (5회 이하 권고)"; }

# WST-090: su 명령어 그룹 제한
grep -qi "pam_wheel" /etc/pam.d/su 2>/dev/null && echo "WST-090|양호|su wheel 그룹 제한" || echo "WST-090|취약|su pam_wheel 미설정"

# WST-099: 중복 UID
dup=$(awk -F: '{print $3}' /etc/passwd | sort | uniq -d)
[ -n "$dup" ] && echo "WST-099|취약|중복 UID: $dup" || echo "WST-099|양호|중복 UID 없음"

# WST-107: Telnet 비활성화
netstat -tlnp 2>/dev/null | grep -q ":23 " && echo "WST-107|취약|Telnet 서비스 실행 중 (포트 23)" || echo "WST-107|양호|Telnet 미실행"

# WST-109: 시스템 배너
grep -qi "banner\|Warning\|Authorized" /etc/ssh/sshd_config 2>/dev/null && \
    echo "WST-109|양호|SSH 배너 설정됨" || \
    { [ -f /etc/issue ] && [ -s /etc/issue ] && echo "WST-109|양호|/etc/issue 배너 설정됨" || echo "WST-109|취약|시스템 배너 미설정"; }

# WST-118: NTP
command -v chronyc >/dev/null 2>&1 && chronyc tracking 2>/dev/null | grep -q "Reference ID" && \
    echo "WST-118|양호|chrony NTP 동기화 활성" && T_DONE=1
[ -z "$T_DONE" ] && command -v ntpq >/dev/null 2>&1 && ntpq -p 2>/dev/null | grep -q "^\*" && \
    echo "WST-118|양호|ntpq 활성 피어 확인" && T_DONE=1
[ -z "$T_DONE" ] && echo "WST-118|취약|NTP 동기화 미설정"

# WST-119: sudo NOPASSWD
vuln=""
for f in /etc/sudoers $(find /etc/sudoers.d/ -type f 2>/dev/null); do
    [ -f "$f" ] || continue
    grep -v "^#" "$f" 2>/dev/null | grep "NOPASSWD:\s*ALL" | head -1 | grep -q "." && vuln="${vuln} ${f}"
done
[ -n "$vuln" ] && echo "WST-119|취약|NOPASSWD ALL 설정:${vuln}" || echo "WST-119|양호|sudoers NOPASSWD ALL 미설정"

# ── 웹서버 전용 점검 ─────────────────────────────────────────────

# WST-031: 디렉토리 리스팅 방지
check_dir_listing() {
    case "$WEB_SRV" in
    apache)
        [ -z "$APACHE_CONF" ] && { echo "WST-031|수동확인|Apache 설정파일 미탐지"; return; }
        # 설정 파일 및 포함 디렉토리 검색
        confdir=$(dirname "$APACHE_CONF")
        if grep -r "Options.*Indexes" "$confdir"/ 2>/dev/null | grep -qv "^#"; then
            listing=$(grep -r "Options.*Indexes" "$confdir"/ 2>/dev/null | grep -v "^#" | head -1)
            echo "WST-031|취약|디렉토리 리스팅 활성: ${listing}"
        else
            echo "WST-031|양호|디렉토리 리스팅 비활성화 (Options -Indexes)"
        fi ;;
    nginx)
        if grep -r "autoindex on" /etc/nginx/ 2>/dev/null | grep -qv "^#"; then
            echo "WST-031|취약|Nginx autoindex on 설정됨"
        else
            echo "WST-031|양호|Nginx autoindex off (기본 또는 명시)"
        fi ;;
    webtob)
        # WebtoB: DIRECTORY.INDEX 설정
        wt_cfg=$(find /usr/local/tmax /opt/tmax -name "*.m" 2>/dev/null | head -1)
        if [ -n "$wt_cfg" ] && grep -qi "DIRECTORY.INDEX" "$wt_cfg" 2>/dev/null; then
            echo "WST-031|양호|WebtoB DIRECTORY.INDEX 설정됨"
        else
            echo "WST-031|수동확인|WebtoB 디렉토리 리스팅 수동 확인"
        fi ;;
    *) echo "WST-031|N-A|웹서버 미탐지" ;;
    esac
}
check_dir_listing

# WST-033: 상위 디렉토리 접근 제한
check_dir_traverse() {
    case "$WEB_SRV" in
    apache)
        if grep -r "AllowOverride\s*All\|Options.*FollowSymLinks" "$APACHE_CONF" $(dirname "$APACHE_CONF") 2>/dev/null | grep -qv "^#"; then
            echo "WST-033|수동확인|AllowOverride All 또는 FollowSymLinks 설정 - 상위 디렉토리 접근 수동 확인"
        else
            echo "WST-033|양호|상위 디렉토리 접근 제한 설정됨"
        fi ;;
    nginx)
        echo "WST-033|수동확인|Nginx 상위 디렉토리 접근 제한 수동 확인";;
    *) echo "WST-033|N-A|웹서버 미탐지" ;;
    esac
}
check_dir_traverse

# WST-036: 웹 서비스 프로세스 권한
check_web_user() {
    case "$WEB_SRV" in
    apache)
        web_user=$(grep -iE "^\s*User\s" "$APACHE_CONF" $(find $(dirname "$APACHE_CONF") -name "*.conf") 2>/dev/null | grep -v "^#" | awk '{print $2}' | head -1)
        if [ -z "$web_user" ]; then
            web_user=$(ps -ef 2>/dev/null | grep -E "httpd|apache" | grep -v "root\|grep" | awk '{print $1}' | head -1)
        fi
        if [ "$web_user" = "root" ]; then
            echo "WST-036|취약|Apache root 계정으로 실행됨"
        elif [ -n "$web_user" ]; then
            echo "WST-036|양호|Apache 웹 사용자: ${web_user} (non-root)"
        else
            echo "WST-036|수동확인|Apache 실행 계정 수동 확인"
        fi ;;
    nginx)
        nuser=$(grep -E "^\s*user\s" /etc/nginx/nginx.conf 2>/dev/null | awk '{print $2}' | tr -d ';')
        if [ "$nuser" = "root" ]; then
            echo "WST-036|취약|Nginx root 계정으로 실행됨"
        elif [ -n "$nuser" ]; then
            echo "WST-036|양호|Nginx 사용자: ${nuser}"
        else
            echo "WST-036|수동확인|Nginx 실행 계정 수동 확인"
        fi ;;
    *) echo "WST-036|N-A|웹서버 미탐지" ;;
    esac
}
check_web_user

# WST-039: 불필요 웹 서비스 비활성화
echo "WST-039|수동확인|불필요 웹 서비스(mod_status, mod_info 등) 수동 확인 필요"

# WST-044: 기본 계정(아이디/비밀번호) 변경
echo "WST-044|수동확인|웹서버/WAS 기본 관리 계정 변경 여부 수동 확인"

# WST-048: DNS Zone Transfer 제한
is_running named && {
    for conf in /etc/named.conf /etc/bind/named.conf; do
        [ -f "$conf" ] || continue
        grep -q "allow-transfer.*none" "$conf" 2>/dev/null && \
            echo "WST-048|양호|Zone Transfer 차단 설정됨" && break || \
            echo "WST-048|취약|Zone Transfer 제한 미설정"
        break
    done
} || echo "WST-048|N-A|DNS 미실행"

# WST-100: /dev 불필요 파일
cnt=$(find /dev -type f 2>/dev/null | wc -l)
[ "${cnt:-0}" -gt 5 ] 2>/dev/null && echo "WST-100|수동확인|/dev에 일반 파일 ${cnt}개" || echo "WST-100|양호|/dev 불필요 파일 없음"

# WST-101: 불필요 네트워크 모니터링 서비스 (SNMP)
snmp_v=""
for conf in /etc/snmpd.conf /etc/snmp/snmpd.conf; do
    [ -f "$conf" ] || continue
    grep -qiE "^rouser|^rwuser" "$conf" && snmp_v="v3" && break
    grep -qiE "^community" "$conf" && snmp_v="v2c" && break
done
case "$snmp_v" in
v3) echo "WST-101|양호|SNMP v3 사용 중" ;;
v2c) echo "WST-101|취약|SNMP v1/v2c community 사용 중" ;;
*) is_running snmpd && echo "WST-101|수동확인|SNMP 실행 중 버전 확인 필요" || echo "WST-101|양호|SNMP 미실행" ;;
esac

# WST-102: 웹 서비스 정보 노출 방지
check_server_info() {
    case "$WEB_SRV" in
    apache)
        confdir=$(dirname "$APACHE_CONF")
        token=$(grep -r "ServerTokens" "$confdir"/ 2>/dev/null | grep -v "^#" | head -1)
        sig=$(grep -r "ServerSignature" "$confdir"/ 2>/dev/null | grep -v "^#" | head -1)
        if echo "$token" | grep -qi "Prod\|Min"; then
            echo "WST-102|양호|Apache ServerTokens=$(echo $token | awk '{print $2}')"
        elif echo "$token" | grep -qi "Full\|OS\|All\|Major\|Minor"; then
            echo "WST-102|취약|Apache ServerTokens=$(echo $token | awk '{print $2}') (버전 노출)"
        else
            echo "WST-102|수동확인|ServerTokens 설정 수동 확인"
        fi ;;
    nginx)
        if grep -r "server_tokens off" /etc/nginx/ 2>/dev/null | grep -qv "^#"; then
            echo "WST-102|양호|Nginx server_tokens off 설정됨"
        else
            echo "WST-102|취약|Nginx server_tokens off 미설정 (버전 노출)"
        fi ;;
    webtob)
        echo "WST-102|수동확인|WebtoB 서버 정보 노출 방지 수동 확인" ;;
    *) echo "WST-102|N-A|웹서버 미탐지" ;;
    esac
}
check_server_info

# WST-121: 프록시 설정 제한
check_proxy() {
    case "$WEB_SRV" in
    apache)
        confdir=$(dirname "$APACHE_CONF")
        if grep -r "mod_proxy\|ProxyRequests On" "$confdir"/ 2>/dev/null | grep -qv "^#"; then
            proxy=$(grep -r "ProxyRequests" "$confdir"/ 2>/dev/null | grep -v "^#" | head -1)
            echo "$proxy" | grep -qi "Off" && echo "WST-121|양호|ProxyRequests Off 설정됨" || \
                echo "WST-121|취약|ProxyRequests On - 오픈 프록시 가능"
        else
            echo "WST-121|양호|mod_proxy 미사용 또는 ProxyRequests Off"
        fi ;;
    *) echo "WST-121|수동확인|프록시 설정 수동 확인" ;;
    esac
}
check_proxy

# WST-122: SSI(Server Side Include) 제한
check_ssi() {
    case "$WEB_SRV" in
    apache)
        confdir=$(dirname "$APACHE_CONF")
        if grep -r "Options.*Includes\|AddHandler.*shtml" "$confdir"/ 2>/dev/null | grep -qv "^#"; then
            echo "WST-122|취약|SSI(Includes) 활성화됨"
        else
            echo "WST-122|양호|SSI 비활성 또는 미설정"
        fi ;;
    *) echo "WST-122|수동확인|SSI 설정 수동 확인" ;;
    esac
}
check_ssi

# WST-123: 기본 에러 페이지 노출 방지
check_error_page() {
    case "$WEB_SRV" in
    apache)
        confdir=$(dirname "$APACHE_CONF")
        ep=$(grep -r "ErrorDocument" "$confdir"/ 2>/dev/null | grep -v "^#" | head -1)
        [ -n "$ep" ] && echo "WST-123|양호|ErrorDocument 설정됨: ${ep}" || \
            echo "WST-123|취약|ErrorDocument 미설정 (기본 에러 페이지 노출)"  ;;
    nginx)
        ep=$(grep -r "error_page" /etc/nginx/ 2>/dev/null | grep -v "^#" | head -1)
        [ -n "$ep" ] && echo "WST-123|양호|error_page 설정됨" || echo "WST-123|취약|Nginx error_page 미설정" ;;
    *) echo "WST-123|수동확인|에러 페이지 설정 수동 확인" ;;
    esac
}
check_error_page

# WST-124: LDAP 알고리즘 제한
echo "WST-124|수동확인|웹 서비스 LDAP 연동 시 알고리즘 설정 수동 확인"

# WST-125: 업로드 경로/권한 설정
check_upload() {
    case "$WAS_SRV" in
    tomcat)
        [ -n "$TOMCAT_HOME" ] || { echo "WST-125|수동확인|Tomcat 홈 미탐지 - 수동 확인"; return; }
        # webapps 내 upload 디렉토리 탐색
        upload_dirs=$(find "$TOMCAT_HOME/webapps" -type d -name "upload*" -o -name "attach*" 2>/dev/null | head -3)
        if [ -n "$upload_dirs" ]; then
            echo "WST-125|수동확인|업로드 디렉토리 발견: $(echo $upload_dirs | head -1) - 스크립트 실행 권한 수동 확인"
        else
            echo "WST-125|수동확인|업로드 경로 및 권한 수동 확인"
        fi ;;
    *) echo "WST-125|수동확인|업로드 경로/권한 수동 확인" ;;
    esac
}
check_upload

# WST-126: EoS 시스템 교체 (자동 판정)
EOS_SCRIPT="$(dirname "$0")/eos_checker.py"
check_webwas_eos() {
    local product="$1" version="$2"
    [ -f "$EOS_SCRIPT" ] || { echo "WST-126|수동확인|eos_checker.py 없음"; return; }
    result=$(python3 "$EOS_SCRIPT" "$product" "$version" --no-api 2>/dev/null | grep "^결과:" | awk '{print $2}')
    desc=$(python3 "$EOS_SCRIPT" "$product" "$version" --no-api 2>/dev/null | grep "^설명:" | cut -d: -f2- | xargs)
    echo "WST-126|${result:-수동확인}|${desc:-EoS 판정 실패}"
}
case "$WEB_SRV" in
apache)
    ver=$(httpd -v 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || apache2 -v 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
    [ -n "$ver" ] && check_webwas_eos "apache" "$ver" || echo "WST-126|수동확인|Apache 버전 확인 실패" ;;
nginx)
    ver=$(nginx -v 2>&1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
    [ -n "$ver" ] && check_webwas_eos "nginx" "$ver" || echo "WST-126|수동확인|Nginx 버전 확인 실패" ;;
*)
    echo "WST-126|수동확인|웹서버 버전 수동 확인 (Apache/Nginx/WebtoB/IIS)" ;;
esac
case "$WAS_SRV" in
tomcat)
    ver=$(find "$TOMCAT_HOME" /opt /usr/local -name "RELEASE-NOTES" 2>/dev/null | xargs grep -h "Apache Tomcat Version" 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
    [ -n "$ver" ] && check_webwas_eos "tomcat" "$ver" || echo "WST-126|수동확인|Tomcat 버전 확인 필요" ;;
jeus)
    echo "WST-126|수동확인|JEUS 버전 수동 확인 (jeus --version)" ;;
esac
[ -n "$WEB_SRV" ] && {
    case "$WEB_SRV" in
    apache) httpd -v 2>/dev/null | head -1 || apache2 -v 2>/dev/null | head -1 ;;
    nginx)  nginx -v 2>/dev/null ;;
    esac
}
[ -n "$WAS_SRV" ] && {
    case "$WAS_SRV" in
    tomcat)
        [ -n "$TOMCAT_HOME" ] && cat "$TOMCAT_HOME/RELEASE-NOTES" 2>/dev/null | head -2 || \
            find /opt /usr/local -name "catalina.sh" 2>/dev/null | head -1 | xargs -I{} sh -c '. {}; echo "Tomcat version check"' 2>/dev/null
        ;;
    esac
}

# ── 자동 점검 추가 항목 ───────────────────────────────────────────

# WST-003: 불필요한 SMTP 서비스 비활성화
is_running sendmail || is_running postfix || is_running exim || is_running exim4 && \
    echo "WST-003|취약|SMTP 서비스 실행 중 (불필요 시 비활성화 권고)" || \
    echo "WST-003|양호|SMTP 서비스 미실행"

# WST-010: FTP root 접속 제한 (/etc/ftpusers)
if [ -f /etc/ftpusers ]; then
    grep -q "^root$" /etc/ftpusers 2>/dev/null && \
        echo "WST-010|양호|/etc/ftpusers에 root 등록됨" || \
        echo "WST-010|취약|/etc/ftpusers에 root 미등록"
else
    is_running vsftpd || is_running proftpd || is_running pure-ftpd && \
        echo "WST-010|취약|FTP 실행 중이나 /etc/ftpusers 없음" || \
        echo "WST-010|N-A|FTP 서비스 미실행"
fi

# WST-012: Anonymous FTP 접속 제한
anon_ftp=""
for conf in /etc/vsftpd.conf /etc/vsftpd/vsftpd.conf /etc/proftpd.conf /etc/proftpd/proftpd.conf; do
    [ -f "$conf" ] || continue
    if grep -qi "^anonymous_enable\s*=\s*yes\|<Anonymous\s" "$conf" 2>/dev/null; then
        anon_ftp="${conf}"
    fi
    break
done
[ -n "$anon_ftp" ] && echo "WST-012|취약|Anonymous FTP 허용 설정: ${anon_ftp}" || \
    { is_running vsftpd || is_running proftpd && \
        echo "WST-012|양호|Anonymous FTP 비허용 (설정 확인됨)" || \
        echo "WST-012|N-A|FTP 서비스 미실행"; }

# WST-013: NFS 접근통제 (wildcard 허용 여부)
if [ -f /etc/exports ]; then
    wild=$(grep -v "^#" /etc/exports 2>/dev/null | grep -E "\*|\s0\.0\.0\.0")
    [ -n "$wild" ] && echo "WST-013|취약|NFS wildcard 허용: $(echo $wild | head -1)" || \
        echo "WST-013|양호|NFS 접근 IP 제한 설정됨"
else
    echo "WST-013|N-A|/etc/exports 없음 (NFS 미사용)"
fi

# WST-014: NFS 서비스 비활성화
is_running nfsd || is_running nfs-server || is_running nfs && \
    echo "WST-014|취약|NFS 서비스 실행 중 (불필요 시 비활성화 권고)" || \
    echo "WST-014|양호|NFS 서비스 미실행"

# WST-015: RPC 서비스 비활성화
is_running rpcbind || is_running portmap && \
    echo "WST-015|취약|RPC(rpcbind/portmap) 서비스 실행 중 (불필요 시 비활성화 권고)" || \
    echo "WST-015|양호|RPC 서비스 미실행"

# WST-019: 비밀번호 미설정(빈 암호) 계정
empty_pw=$(awk -F: '($2==""|$2=="!!"||$2=="!") && $1!="root" {print $1}' /etc/shadow 2>/dev/null | head -5)
[ -n "$empty_pw" ] && echo "WST-019|취약|비밀번호 미설정 계정: $(echo $empty_pw | tr '\n' ',')" || \
    echo "WST-019|양호|비밀번호 미설정 계정 없음"

# WST-022: hosts.equiv / .rhosts 설정 제한
found_r=""
[ -f /etc/hosts.equiv ] && found_r="${found_r} /etc/hosts.equiv"
for home in $(awk -F: '$3>=1000 && $3<65534 {print $6}' /etc/passwd 2>/dev/null) /root; do
    [ -f "${home}/.rhosts" ] && found_r="${found_r} ${home}/.rhosts"
done
[ -n "$found_r" ] && echo "WST-022|취약|r-명령 신뢰 파일 존재:${found_r}" || \
    echo "WST-022|양호|hosts.equiv/.rhosts 없음"

# WST-029: 취약한 서비스 비활성화 (Telnet, rsh, rlogin, rexec)
vuln_svc=""
for svc in telnet rsh rlogin rexec rshd rlogind; do
    is_running "$svc" && vuln_svc="${vuln_svc} ${svc}"
done
[ -n "$vuln_svc" ] && echo "WST-029|취약|취약 서비스 실행 중:${vuln_svc}" || \
    echo "WST-029|양호|취약 서비스(telnet/rsh/rlogin/rexec) 미실행"

# WST-030: 취약한 FTP 서비스 비활성화 (tftp, atftpd)
is_running tftp || is_running atftpd || is_running tftpd && \
    echo "WST-030|취약|취약 FTP(tftp/atftpd) 서비스 실행 중" || \
    echo "WST-030|양호|취약 FTP 서비스 미실행"

# WST-059: Tomcat Shutdown 포트 비활성화
if [ -n "$TOMCAT_HOME" ] && [ -f "$TOMCAT_HOME/conf/server.xml" ]; then
    if grep -q 'port="-1"' "$TOMCAT_HOME/conf/server.xml" 2>/dev/null; then
        echo "WST-059|양호|Tomcat Shutdown 포트 비활성화됨 (port=-1)"
    else
        _shutdown_port=$(grep '<Server ' "$TOMCAT_HOME/conf/server.xml" 2>/dev/null | grep -oE 'port="[0-9]+"' | grep -oE '[0-9]+' | head -1)
        echo "WST-059|취약|Tomcat Shutdown 포트 활성화됨 (port=${_shutdown_port:-?}) - -1로 변경 권고"
    fi
elif [ "$WAS_SRV" = "tomcat" ]; then
    echo "WST-059|수동확인|Tomcat 홈 미탐지 - Shutdown 포트 수동 확인"
else
    echo "WST-059|N-A|WAS(Tomcat) 미탐지"
fi

# WST-060: Tomcat 기본 애플리케이션 제거 (manager, host-manager, examples, docs)
if [ -n "$TOMCAT_HOME" ] && [ -d "$TOMCAT_HOME/webapps" ]; then
    _exist_apps=""
    for _app in manager host-manager examples docs ROOT; do
        [ -d "$TOMCAT_HOME/webapps/$_app" ] && _exist_apps="${_exist_apps} ${_app}"
    done
    if [ -n "$_exist_apps" ]; then
        echo "WST-060|취약|Tomcat 기본 애플리케이션 존재:${_exist_apps} - 운영 서버에서 제거 권고"
    else
        echo "WST-060|양호|Tomcat 기본 애플리케이션(manager/examples/docs) 제거됨"
    fi
elif [ "$WAS_SRV" = "tomcat" ]; then
    echo "WST-060|수동확인|Tomcat webapps 디렉토리 미탐지 - 수동 확인"
else
    echo "WST-060|N-A|WAS(Tomcat) 미탐지"
fi

# 수동확인 항목 일괄 출력
for code in WST-001 WST-002 WST-004 WST-005 WST-006 WST-007 WST-008 WST-009 \
            WST-011 WST-018 WST-021 \
            WST-026 WST-027 WST-032 WST-034 WST-035 WST-037 \
            WST-038 WST-040 WST-041 WST-042 WST-043 WST-045 WST-046 WST-047 \
            WST-053 WST-061 WST-062 WST-063 WST-065 WST-066 \
            WST-067 WST-068 WST-069 WST-070 WST-071 WST-072 WST-073 WST-074 \
            WST-076 WST-077 WST-078 WST-079 WST-080 WST-081 WST-084 WST-085 \
            WST-086 WST-088 WST-089 WST-091 WST-092 WST-093 WST-094 WST-095 \
            WST-096 WST-097 WST-098 WST-103 WST-104 WST-105 WST-106 WST-108 \
            WST-110 WST-111 WST-112 WST-113 WST-114 WST-115 WST-116 WST-117; do
    echo "${code}|수동확인|수동 확인 필요"
done

echo "# 점검 완료: $(date '+%Y-%m-%d %H:%M:%S')"
