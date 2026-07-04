#!/bin/bash
# ================================================================
# 전자금융기반시설 / 주요정보통신기반시설
# 서버 취약점 점검 스크립트 v4.0
#
# 지원 OS: AIX 6.1~7.3 / HP-UX 11i / Linux(RHEL/CentOS/Ubuntu/SLES/Amazon)
#           Solaris 10~11 / Windows Server (별도 ps1 스크립트 사용)
#
# [사용법]
#   bash check_server.sh > /tmp/$(hostname).txt
#   결과 파일을 convert/server/output/ 에 복사
#
# [출력 형식]
#   SRV-026|양호|PermitRootLogin no
#   SRV-069|취약|PASS_MAX_DAYS=99999 (90일 초과)
#   SRV-001|수동확인|인터뷰를 통해 백업 여부 확인 필요
# ================================================================

# ── OS 탐지 ──────────────────────────────────────────────────────
detect_os() {
    OS_FAMILY="LINUX"    # LINUX / AIX / SOLARIS / HPUX / BSD
    OS_DISTRO="UNKNOWN"  # RHEL / CENTOS / UBUNTU / DEBIAN / SLES / AMZN / ORACLE
    OS_MAJOR=0

    case "$(uname -s)" in
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
HN=$(hostname 2>/dev/null || uname -n)

echo "# ============================================================"
echo "# 점검 대상: ${HN}"
echo "# OS: ${OS_FAMILY} / ${OS_DISTRO} ${OS_MAJOR}"
echo "# 점검 기준: 전자금융기반시설 보안 취약점 평가기준 제2026-1호 [서버]"
echo "# 점검 일시: $(date '+%Y-%m-%d %H:%M:%S')"
echo "# ============================================================"

# ── 공통 함수 ────────────────────────────────────────────────────
get_perm() {
    local f="$1"; [ -f "$f" ] || { echo ""; return; }
    case "$OS_FAMILY" in
    AIX)     istat "$f" 2>/dev/null | awk '/Mode/{print $NF}' | head -1 ;;
    BSD)     stat -f "%Lp" "$f" 2>/dev/null ;;
    SOLARIS|HPUX) ls -l "$f" 2>/dev/null | awk '{p=substr($1,2);r=0;for(i=1;i<=9;i++){c=substr(p,i,1);if(c!="-")r+=2^(9-i)};printf "%03o\n",r}' ;;
    *)       stat -c "%a" "$f" 2>/dev/null ;;
    esac
}
get_owner() {
    local f="$1"; [ -f "$f" ] || { echo ""; return; }
    case "$OS_FAMILY" in
    AIX)     istat "$f" 2>/dev/null | awk '/Owner/{print $2}' ;;
    BSD)     stat -f "%Su" "$f" 2>/dev/null ;;
    SOLARIS|HPUX) ls -l "$f" 2>/dev/null | awk '{print $3}' ;;
    *)       stat -c "%U" "$f" 2>/dev/null ;;
    esac
}
is_running() {
    local svc="$1"
    command -v systemctl >/dev/null 2>&1 && systemctl is-active "$svc" 2>/dev/null | grep -q "^active" && return 0
    command -v service  >/dev/null 2>&1 && service "$svc" status 2>/dev/null | grep -qiE "running|started" && return 0
    command -v lssrc    >/dev/null 2>&1 && lssrc -s "$svc" 2>/dev/null | grep -qi "active" && return 0
    command -v svcs     >/dev/null 2>&1 && svcs -H "$svc" 2>/dev/null | grep -q "^online" && return 0
    ps -ef 2>/dev/null | grep -v grep | grep -qi "$svc" && return 0
    return 1
}
get_pam_files() {
    case "$OS_FAMILY" in
    AIX)     echo "/etc/security/user /etc/security/login.cfg" ;;
    SOLARIS) echo "/etc/pam.conf /etc/security/policy.conf /etc/default/login" ;;
    HPUX)    echo "/etc/pam.conf /etc/default/security" ;;
    *)
        case "$OS_DISTRO" in
        RHEL|CENTOS|ORACLE)
            [ "${OS_MAJOR:-0}" -ge 8 ] 2>/dev/null && \
                echo "/etc/pam.d/system-auth /etc/pam.d/password-auth" || \
                echo "/etc/pam.d/system-auth" ;;
        UBUNTU|DEBIAN) echo "/etc/pam.d/common-auth /etc/pam.d/common-password" ;;
        SLES)   echo "/etc/pam.d/common-auth /etc/pam.d/login" ;;
        *)      find /etc/pam.d/ -type f 2>/dev/null | head -5 ;;
        esac ;;
    esac
}

# ================================================================
# SRV-001: 네트워크 모니터링 서비스 (SNMP 버전)
# ================================================================
check_SRV001() {
    case "$OS_FAMILY" in
    AIX)
        v=$(lslpp -l 2>/dev/null | grep -i snmp | head -1)
        cfg=$(grep -h "version" /etc/snmpd.conf 2>/dev/null | head -1)
        if echo "$cfg $v" | grep -qi "v3\|version 3"; then
            echo "SRV-001|양호|AIX SNMP v3 설정됨"
        elif echo "$cfg" | grep -qi "community"; then
            echo "SRV-001|취약|AIX SNMP v1/v2c community 사용 중"
        else
            echo "SRV-001|수동확인|AIX SNMP 설정 수동 확인"
        fi ;;
    HPUX)
        cfg=$(grep -h "version" /etc/snmpd.conf /etc/opt/OV/share/conf/snmpd.conf 2>/dev/null | head -1)
        if echo "$cfg" | grep -qi "v3\|version 3"; then echo "SRV-001|양호|HP-UX SNMP v3 설정됨"
        else echo "SRV-001|수동확인|HP-UX SNMP 설정 수동 확인"; fi ;;
    SOLARIS)
        if [ -f /etc/net-snmp/snmp/snmpd.conf ] || [ -f /etc/sma/snmp/snmpd.conf ]; then
            cfg=$(cat /etc/net-snmp/snmp/snmpd.conf /etc/sma/snmp/snmpd.conf 2>/dev/null | grep -i "rouser\|rwuser\|authpriv" | head -1)
            if [ -n "$cfg" ]; then echo "SRV-001|양호|Solaris SNMP v3 설정됨"
            else echo "SRV-001|취약|Solaris SNMP v3 미설정 (v1/v2c 또는 미설정)"; fi
        else echo "SRV-001|N-A|SNMP 미설치"; fi ;;
    *)  # Linux
        for conf in /etc/snmpd.conf /etc/snmp/snmpd.conf; do
            [ -f "$conf" ] || continue
            if grep -qiE "^rouser|^rwuser|^com2sec.*v3" "$conf" 2>/dev/null; then
                echo "SRV-001|양호|Linux SNMP v3 설정됨 (${conf})"; return
            elif grep -qiE "^community" "$conf" 2>/dev/null; then
                echo "SRV-001|취약|SNMP v1/v2c community 사용 중 (${conf})"; return
            fi
        done
        is_running snmpd && echo "SRV-001|수동확인|snmpd 실행 중 - 설정 수동 확인" || echo "SRV-001|N-A|SNMP 미실행" ;;
    esac
}

# ================================================================
# SRV-003: SNMP 접근통제 (ACL)
# ================================================================
check_SRV003() {
    case "$OS_FAMILY" in
    AIX)
        acl=$(grep -h "viewDefinition\|com2sec\|agentaddress" /etc/snmpd.conf 2>/dev/null | head -2)
        [ -n "$acl" ] && echo "SRV-003|양호|AIX SNMP 접근 제어 설정됨" || echo "SRV-003|수동확인|AIX SNMP ACL 수동 확인" ;;
    *)
        for conf in /etc/snmpd.conf /etc/snmp/snmpd.conf; do
            [ -f "$conf" ] || continue
            acl=$(grep -iE "^com2sec|^agentaddress|^rocommunity|rouser" "$conf" 2>/dev/null | head -2)
            if [ -n "$acl" ]; then
                echo "SRV-003|양호|SNMP 접근 제어 설정됨 (${conf})"
            else
                echo "SRV-003|취약|SNMP 접근 통제 미설정 (${conf})"
            fi
            return
        done
        echo "SRV-003|N-A|SNMP 미설치/미설정" ;;
    esac
}

# ================================================================
# SRV-004: SMTP 서비스 비활성화
# ================================================================
check_SRV004() {
    is_running sendmail || is_running postfix || is_running exim || \
        netstat -tlnp 2>/dev/null | grep -q ":25 " || \
        ss -tlnp 2>/dev/null | grep -q ":25 " && \
        echo "SRV-004|수동확인|SMTP 서비스 실행 중 (업무상 필요 여부 확인)" && return
    echo "SRV-004|양호|SMTP 서비스 미실행"
}

# ================================================================
# SRV-011: 시스템 관리자 FTP 접속 제한
# ================================================================
check_SRV011() {
    for f in /etc/ftpusers /etc/vsftpd/ftpusers /etc/vsftpd.ftpusers; do
        [ -f "$f" ] || continue
        if grep -q "^root" "$f" 2>/dev/null; then
            echo "SRV-011|양호|FTP root 계정 제한 (${f})"
        else
            echo "SRV-011|취약|FTP root 제한 미설정 (${f})"
        fi
        return
    done
    # FTP 자체 미설치
    is_running vsftpd || is_running proftpd || is_running ftpd 2>/dev/null || \
        { echo "SRV-011|N-A|FTP 서비스 미실행"; return; }
    echo "SRV-011|취약|ftpusers 파일 없음 (root FTP 접속 제한 불가)"
}

# ================================================================
# SRV-013: Anonymous FTP 제한
# ================================================================
check_SRV013() {
    for f in /etc/vsftpd/vsftpd.conf /etc/vsftpd.conf; do
        [ -f "$f" ] || continue
        if grep -q "^anonymous_enable=YES" "$f" 2>/dev/null; then
            echo "SRV-013|취약|Anonymous FTP 활성화됨 (${f})"
        else
            echo "SRV-013|양호|Anonymous FTP 비활성화 (${f})"
        fi
        return
    done
    echo "SRV-013|N-A|FTP 서비스 미설치"
}

# ================================================================
# SRV-014: NFS 접근통제
# ================================================================
check_SRV014() {
    local exports_file="/etc/exports"
    [ "$OS_FAMILY" = "SOLARIS" ] && exports_file="/etc/dfs/dfstab"
    [ -f "$exports_file" ] || { echo "SRV-014|N-A|NFS 미사용 (${exports_file} 없음)"; return; }
    world=$(grep -v "^#" "$exports_file" 2>/dev/null | grep "\*")
    [ -n "$world" ] && echo "SRV-014|취약|NFS 전체 허용(*) 설정: $(echo $world | head -1)" || \
        echo "SRV-014|양호|NFS 전체 허용(*) 미발견"
}

# ================================================================
# SRV-015: 불필요 NFS 비활성화
# ================================================================
check_SRV015() {
    is_running nfs || is_running nfsd || is_running nfs-server || \
        is_running nfs-kernel-server && \
        echo "SRV-015|수동확인|NFS 서비스 실행 중 (업무상 필요 여부 확인)" && return
    echo "SRV-015|양호|NFS 서비스 미실행"
}

# ================================================================
# SRV-016: 불필요 RPC 비활성화
# ================================================================
check_SRV016() {
    found=""
    for svc in rpcbind portmap rusersd rstatd rwalld sprayd rquotad; do
        is_running "$svc" && found="${found} ${svc}"
    done
    [ -n "$found" ] && echo "SRV-016|취약|불필요 RPC 서비스 실행:${found}" || \
        echo "SRV-016|양호|불필요 RPC 서비스 미실행"
}

# ================================================================
# SRV-022: 패스워드 미설정 계정 관리
# ================================================================
check_SRV022() {
    case "$OS_FAMILY" in
    AIX)
        no_pw=$(awk -F: '$2 == "" && $1 != "" {print $1}' /etc/passwd 2>/dev/null | head -5)
        ;;
    *)
        [ -f /etc/shadow ] && \
            no_pw=$(awk -F: '$2 == "" || $2 == "!" {print $1}' /etc/shadow 2>/dev/null | head -5) || \
            no_pw=$(awk -F: '$2 == "" {print $1}' /etc/passwd 2>/dev/null | head -5)
        ;;
    esac
    [ -n "$no_pw" ] && echo "SRV-022|취약|비밀번호 미설정 계정: $(echo $no_pw | tr '\n' ',')" || \
        echo "SRV-022|양호|비밀번호 미설정 계정 없음"
}

# ================================================================
# SRV-025: hosts.equiv / .rhosts 설정 제한
# ================================================================
check_SRV025() {
    found=""
    [ -f /etc/hosts.equiv ] && found="${found} /etc/hosts.equiv"
    [ -f /root/.rhosts    ] && found="${found} /root/.rhosts"
    [ -f /.rhosts         ] && found="${found} /.rhosts"
    [ -n "$found" ] && echo "SRV-025|취약|${found} 파일 존재" || \
        echo "SRV-025|양호|hosts.equiv/.rhosts 미존재"
}

# ================================================================
# SRV-026: root 원격 접속 제한
# ================================================================
check_SRV026() {
    case "$OS_FAMILY" in
    AIX)
        val=$(grep -A20 "^root:" /etc/security/user 2>/dev/null | grep "rlogin" | awk '{print $3}')
        [ "$val" = "false" ] && echo "SRV-026|양호|AIX root rlogin=false" && return
        echo "SRV-026|취약|AIX root rlogin=${val:-미설정}" ;;
    SOLARIS)
        cons=$(grep -v "^#" /etc/default/login 2>/dev/null | grep "^CONSOLE")
        ssh_root=$(grep -i "^PermitRootLogin" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}')
        if [ -n "$cons" ] || echo "${ssh_root,,}" | grep -qE "^no$|^prohibit-password$"; then
            echo "SRV-026|양호|Solaris root 원격 접속 제한됨"
        else
            echo "SRV-026|취약|Solaris root 원격 접속 제한 미설정"
        fi ;;
    *)
        val=""; sshd_cfg=/etc/ssh/sshd_config
        [ -d /etc/ssh/sshd_config.d ] && \
            val=$(grep -rih "^PermitRootLogin" /etc/ssh/sshd_config.d/ 2>/dev/null | awk '{print $2}' | tail -1)
        [ -z "$val" ] && val=$(grep -i "^PermitRootLogin" "$sshd_cfg" 2>/dev/null | awk '{print $2}' | tail -1)
        case "${val,,}" in
        no|prohibit-password|forced-commands-only) echo "SRV-026|양호|PermitRootLogin=${val}" ;;
        yes)   echo "SRV-026|취약|PermitRootLogin=yes (root 원격 접속 허용)" ;;
        "")    echo "SRV-026|취약|PermitRootLogin 미설정" ;;
        *)     echo "SRV-026|수동확인|PermitRootLogin=${val}" ;;
        esac ;;
    esac
}

# ================================================================
# SRV-027: 서비스 접근 IP/포트 제한 (TCP Wrapper / firewall)
# ================================================================
check_SRV027() {
    has_tcp_wrap=0
    [ -f /etc/hosts.allow ] && [ -s /etc/hosts.allow ] && has_tcp_wrap=1
    has_fw=0
    command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state 2>/dev/null | grep -q "running" && has_fw=1
    command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "active" && has_fw=1
    command -v iptables >/dev/null 2>&1 && iptables -n -L 2>/dev/null | grep -qiE "ACCEPT|DROP|REJECT" && has_fw=1
    if [ $has_tcp_wrap -eq 1 ] || [ $has_fw -eq 1 ]; then
        echo "SRV-027|양호|서비스 접근 제한 설정됨 (TCP Wrapper 또는 Firewall)"
    else
        echo "SRV-027|수동확인|서비스 접근 IP/포트 제한 수동 확인 필요"
    fi
}

# ================================================================
# SRV-028: 원격 터미널 접속 타임아웃
# ================================================================
check_SRV028() {
    tmout=""
    for f in /etc/profile /etc/bashrc /etc/bash.bashrc /etc/environment \
              /root/.bashrc /root/.profile /etc/profile.d/*.sh; do
        [ -f "$f" ] || continue
        t=$(grep -h "TMOUT\|tmout" "$f" 2>/dev/null | grep -v "^#" | grep -oE "[0-9]+" | head -1)
        [ -n "$t" ] && tmout=$t && break
    done
    case "$OS_FAMILY" in
    SOLARIS) [ -z "$tmout" ] && tmout=$(grep "^TIMEOUT" /etc/default/login 2>/dev/null | cut -d= -f2 | tr -d ' ') ;;
    AIX)     [ -z "$tmout" ] && tmout=$(grep "^TMOUT\|^tmout" /etc/profile /etc/environment 2>/dev/null | grep -oE "[0-9]+" | head -1) ;;
    esac
    if [ -z "$tmout" ]; then
        echo "SRV-028|취약|TMOUT 미설정 (세션 타임아웃 없음)"
    elif [ "$tmout" -le 600 ] 2>/dev/null; then
        echo "SRV-028|양호|TMOUT=${tmout}초 (10분 이하)"
    else
        echo "SRV-028|취약|TMOUT=${tmout}초 (600초 초과)"
    fi
}

# ================================================================
# SRV-034: 불필요한 서비스 비활성화 (finger/chargen/daytime 등)
# ================================================================
check_SRV034() {
    found=""
    for svc in chargen daytime discard echo time rsh rlogin rexec \
                rstatd rusersd rwalld ident; do
        is_running "$svc" && found="${found} ${svc}"
    done
    # inetd.conf 확인
    for conf in /etc/inetd.conf /etc/xinetd.conf; do
        [ -f "$conf" ] || continue
        active=$(grep -v "^#" "$conf" 2>/dev/null | grep -E "chargen|daytime|discard|echo\s|time\s" | head -3)
        [ -n "$active" ] && found="${found} [inetd:$(echo $active | head -1 | awk '{print $1}')]"
    done
    [ -n "$found" ] && echo "SRV-034|취약|불필요 서비스 실행:${found}" || \
        echo "SRV-034|양호|불필요 서비스(chargen/daytime/rsh 등) 미실행"
}

# ================================================================
# SRV-035: 취약 서비스 비활성화 (telnet 등)
# ================================================================
check_SRV035() {
    found=""
    is_running telnet  && found="${found} telnet"
    is_running in.telnetd && found="${found} telnetd"
    netstat -tlnp 2>/dev/null | grep ":23 " | grep -q LISTEN && found="${found} port23"
    [ -n "$found" ] && echo "SRV-035|취약|취약 서비스 실행:${found}" || \
        echo "SRV-035|양호|취약 서비스(Telnet 등) 미실행"
}

# ================================================================
# SRV-062: DNS 정보 노출 방지 (버전 노출)
# ================================================================
check_SRV062() {
    is_running named || { echo "SRV-062|N-A|DNS 서비스 미실행"; return; }
    for conf in /etc/named.conf /etc/bind/named.conf; do
        [ -f "$conf" ] || continue
        if grep -qiE 'version\s+"none"|version\s+""' "$conf" 2>/dev/null; then
            echo "SRV-062|양호|DNS 버전 노출 차단 설정됨"
        else
            echo "SRV-062|취약|DNS 버전 노출 차단 미설정 (version none 권고)"
        fi
        return
    done
    echo "SRV-062|수동확인|named.conf 위치 확인 필요"
}

# ================================================================
# SRV-066: DNS Zone Transfer 제한
# ================================================================
check_SRV066() {
    is_running named || { echo "SRV-066|N-A|DNS 미실행"; return; }
    for conf in /etc/named.conf /etc/bind/named.conf; do
        [ -f "$conf" ] || continue
        if grep -q "allow-transfer.*none" "$conf" 2>/dev/null; then
            echo "SRV-066|양호|Zone Transfer 차단 (allow-transfer none)"
        elif grep -q "allow-transfer" "$conf" 2>/dev/null; then
            echo "SRV-066|수동확인|allow-transfer 설정됨 - 허용 대상 확인 필요"
        else
            echo "SRV-066|취약|Zone Transfer 제한 미설정"
        fi
        return
    done
    echo "SRV-066|수동확인|named.conf 수동 확인"
}

# ================================================================
# SRV-063: DNS Recursive Query 제한 설정 여부
# ================================================================
check_SRV063() {
    is_running named || { echo "SRV-063|양호|DNS 서비스 미실행"; return; }
    for conf in /etc/named.conf /etc/bind/named.conf /etc/bind/named.conf.options; do
        [ -f "$conf" ] || continue
        if grep -v "^[[:space:]]*#" "$conf" 2>/dev/null | grep -q "recursion yes"; then
            echo "SRV-063|취약|recursion yes 설정됨 (DNS Recursive Query 허용)"
        else
            echo "SRV-063|양호|recursion yes 미설정 (Recursive Query 제한됨)"
        fi
        return
    done
    echo "SRV-063|수동확인|named.conf 위치 확인 필요"
}

# ================================================================
# SRV-064: DNS 서비스 보안 패치 적용 여부
# ================================================================
check_SRV064() {
    is_running named || { echo "SRV-064|양호|DNS 서비스 미실행"; return; }
    named_ver=$(named -v 2>/dev/null | grep -oE 'BIND [0-9][^ ]*' | head -1)
    if [ -n "$named_ver" ]; then
        echo "SRV-064|수동확인|DNS 버전: ${named_ver} - 최신 보안 패치 적용 여부 수동 확인"
    else
        echo "SRV-064|수동확인|DNS 서비스 실행 중 - 버전 및 보안 패치 수동 확인"
    fi
}

# ================================================================
# SRV-069: 비밀번호 관리정책 (최대 사용기간)
# ================================================================
check_SRV069() {
    case "$OS_FAMILY" in
    AIX)
        maxage=$(awk '/^default:/,/^[^ \t]/' /etc/security/user 2>/dev/null | grep "maxage" | grep -oE '[0-9]+' | head -1)
        [ -z "$maxage" ] && { echo "SRV-069|취약|AIX maxage 미설정"; return; }
        [ "$maxage" -le 12 ] 2>/dev/null && echo "SRV-069|양호|AIX maxage=${maxage}주 ($((maxage*7))일)" || \
            echo "SRV-069|취약|AIX maxage=${maxage}주($((maxage*7))일) - 12주(84일) 이하 필요 (기준: 90일 이하)" ;;
    SOLARIS)
        maxw=$(grep "^MAXWEEKS" /etc/default/passwd 2>/dev/null | cut -d= -f2 | tr -d ' ')
        [ -z "$maxw" ] && { echo "SRV-069|취약|Solaris MAXWEEKS 미설정"; return; }
        [ "$maxw" -le 12 ] 2>/dev/null && echo "SRV-069|양호|Solaris MAXWEEKS=${maxw}주 ($((maxw*7))일)" || \
            echo "SRV-069|취약|Solaris MAXWEEKS=${maxw}주($((maxw*7))일) - 12주(84일) 이하 필요 (기준: 90일 이하)" ;;
    HPUX)
        maxl=$(grep "^MAX_PASSWORD_LIFETIME" /etc/default/security 2>/dev/null | cut -d= -f2 | tr -d ' ')
        if [ -z "$maxl" ] || [ "$maxl" -eq 0 ] 2>/dev/null; then
            echo "SRV-069|취약|HP-UX MAX_PASSWORD_LIFETIME 미설정/0(무제한)"
        elif [ "$maxl" -le 90 ] 2>/dev/null; then
            echo "SRV-069|양호|HP-UX MAX_PASSWORD_LIFETIME=${maxl}일"
        else
            echo "SRV-069|취약|HP-UX MAX_PASSWORD_LIFETIME=${maxl}일 (90일 이하 권고)"
        fi ;;
    *)
        v=$(grep "^PASS_MAX_DAYS" /etc/login.defs 2>/dev/null | awk '{print $2}')
        if [ -z "$v" ]; then
            echo "SRV-069|취약|PASS_MAX_DAYS 미설정"
        elif [ "$v" -eq 0 ] 2>/dev/null; then
            echo "SRV-069|취약|PASS_MAX_DAYS=0 (무제한)"
        elif [ "$v" -le 90 ] 2>/dev/null; then
            echo "SRV-069|양호|PASS_MAX_DAYS=${v}일"
        else
            echo "SRV-069|취약|PASS_MAX_DAYS=${v}일 (90일 초과)"
        fi ;;
    esac
}

# ================================================================
# SRV-070: 취약한 패스워드 저장 방식
# ================================================================
check_SRV070() {
    case "$OS_FAMILY" in
    AIX)
        if [ -f /etc/security/passwd ]; then
            echo "SRV-070|양호|AIX /etc/security/passwd (shadow 방식)"
        else
            echo "SRV-070|취약|AIX shadow 파일 없음"
        fi ;;
    *)
        if [ ! -f /etc/shadow ]; then
            echo "SRV-070|취약|/etc/shadow 없음 (평문 패스워드 저장 가능)"
            return
        fi
        # MD5(1$), SHA256(5$), SHA512(6$) 확인
        weak=$(awk -F: '$2 ~ /^\$1\$/ {print $1}' /etc/shadow 2>/dev/null | head -5)
        [ -n "$weak" ] && echo "SRV-070|취약|MD5 해시 계정 존재: $(echo $weak | tr '\n' ',')" || \
            echo "SRV-070|양호|SHA256/SHA512 해시 사용 중" ;;
    esac
}

# ================================================================
# SRV-073: 관리자 그룹 불필요 사용자 제거
# ================================================================
check_SRV073() {
    local grps="wheel sudo admin"
    [ "$OS_FAMILY" = "BSD" ] && grps="wheel operator"
    info=""
    for grp in $grps; do
        members=$(grep "^${grp}:" /etc/group 2>/dev/null | cut -d: -f4)
        [ -n "$members" ] && info="${info} ${grp}:[${members}]"
    done
    if [ -z "$info" ]; then
        echo "SRV-073|N-A|관리자 그룹 없음"
    else
        # 그룹별 멤버를 쉼표 분리 후 중복 제거하여 정확히 집계
        cnt=$(for grp in $grps; do
            grep "^${grp}:" /etc/group 2>/dev/null | cut -d: -f4 | tr ',' '\n'
        done | grep -v '^$' | sort -u | wc -l)
        [ "$cnt" -gt 5 ] 2>/dev/null && \
            echo "SRV-073|취약|관리자 그룹 멤버 과다(${cnt}명):${info}" || \
            echo "SRV-073|양호|관리자 그룹 멤버(${cnt}명):${info}"
    fi
}

# ================================================================
# SRV-074: 불필요/미관리 계정 제거
# ================================================================
check_SRV074() {
    echo "SRV-074|수동확인|미사용 계정 목록 수동 확인 필요 (최근 90일 미로그인 계정 검토)"
}

# ================================================================
# SRV-075: 비밀번호 복잡도
# ================================================================
check_SRV075() {
    case "$OS_FAMILY" in
    AIX)
        minlen=$(awk '/^default:/,/^[^ \t]/' /etc/security/user 2>/dev/null | grep "minlen" | grep -oE '[0-9]+' | head -1)
        [ "${minlen:-0}" -ge 8 ] 2>/dev/null && echo "SRV-075|양호|AIX minlen=${minlen}" || \
            echo "SRV-075|취약|AIX minlen=${minlen:-미설정}" ;;
    SOLARIS)
        minlen=$(grep "^PASSLENGTH" /etc/default/passwd 2>/dev/null | cut -d= -f2 | tr -d ' ')
        [ "${minlen:-0}" -ge 8 ] 2>/dev/null && echo "SRV-075|양호|Solaris PASSLENGTH=${minlen}" || \
            echo "SRV-075|취약|Solaris PASSLENGTH=${minlen:-미설정}" ;;
    HPUX)
        minlen=$(grep "^MIN_PASSWORD_LENGTH" /etc/default/security 2>/dev/null | cut -d= -f2 | tr -d ' ')
        [ "${minlen:-0}" -ge 8 ] 2>/dev/null && echo "SRV-075|양호|HP-UX MIN_PASSWORD_LENGTH=${minlen}" || \
            echo "SRV-075|취약|HP-UX MIN_PASSWORD_LENGTH=${minlen:-미설정}" ;;
    *)
        pam_files=$(get_pam_files)
        found="" minlen=0
        for f in $pam_files; do
            [ -f "$f" ] || continue
            line=$(grep -i "pam_pwquality\|pam_cracklib" "$f" 2>/dev/null | grep -v "^#" | head -1)
            [ -n "$line" ] && found="$line" && ml=$(echo "$line" | grep -oE 'minlen=([0-9]+)' | cut -d= -f2) && [ -n "$ml" ] && minlen=$ml && break
        done
        [ -f /etc/security/pwquality.conf ] && ml=$(grep -v "^#" /etc/security/pwquality.conf 2>/dev/null | grep "^minlen" | grep -oE '[0-9]+' | head -1) && [ -n "$ml" ] && minlen=$ml
        if [ -z "$found" ] && [ "$minlen" -eq 0 ] 2>/dev/null; then
            echo "SRV-075|취약|pam_pwquality/pam_cracklib 미설정"
        elif [ "$minlen" -ge 8 ] 2>/dev/null; then
            echo "SRV-075|양호|패스워드 복잡도 설정됨 (minlen=${minlen})"
        elif [ "$minlen" -gt 0 ] 2>/dev/null; then
            echo "SRV-075|취약|minlen=${minlen} (8자 이상 필요)"
        else
            echo "SRV-075|양호|패스워드 복잡도 설정됨 (minlen 미지정)"
        fi ;;
    esac
}

# ================================================================
# SRV-081: Crontab 설정파일 권한
# ================================================================
check_SRV081() {
    target="/etc/crontab"
    [ -f "$target" ] || { echo "SRV-081|N-A|/etc/crontab 없음"; return; }
    owner=$(get_owner "$target"); perm=$(get_perm "$target")
    if [ "$owner" != "root" ] || [ "${perm:-777}" -gt 640 ] 2>/dev/null; then
        echo "SRV-081|취약|/etc/crontab 소유자=${owner}, 권한=${perm}"
    else
        echo "SRV-081|양호|/etc/crontab 소유자=root, 권한=${perm}"
    fi
}

# ================================================================
# SRV-084: 시스템 주요 파일 권한
# ================================================================
check_SRV084() {
    vuln=""
    declare -A expected=(["/etc/passwd"]="644" ["/etc/group"]="644")
    case "$OS_FAMILY" in
    AIX)     expected["/etc/security/passwd"]="400" ;;
    *)       expected["/etc/shadow"]="400" ;;
    esac
    for f in "${!expected[@]}"; do
        [ -f "$f" ] || continue
        perm=$(get_perm "$f"); owner=$(get_owner "$f")
        max="${expected[$f]}"
        if [ "$owner" != "root" ]; then
            vuln="${vuln} ${f}(소유자=${owner})"
        elif [ "${perm:-777}" -gt "$max" ] 2>/dev/null; then
            vuln="${vuln} ${f}(권한=${perm})"
        fi
    done
    [ -n "$vuln" ] && echo "SRV-084|취약|주요 파일 권한 이상:${vuln}" || \
        echo "SRV-084|양호|시스템 주요 파일 권한 적절"
}

# ================================================================
# SRV-091: SUID/SGID 파일 관리
# ================================================================
check_SRV091() {
    dangerous="nmap perl python python3 php ruby bash sh find wget curl nc netcat awk vim gdb strace"
    found_vuln=""
    for bin in $dangerous; do
        binpath=$(command -v "$bin" 2>/dev/null)
        [ -z "$binpath" ] && continue
        [ -u "$binpath" ] && found_vuln="${found_vuln} ${binpath}(SUID)"
    done
    if [ -n "$found_vuln" ]; then
        echo "SRV-091|취약|위험 SUID 파일:${found_vuln}"
    else
        cnt=$(find / -perm /4000 -type f 2>/dev/null | wc -l)
        echo "SRV-091|양호|위험 SUID 미발견 (전체 SUID ${cnt}개 - 목록 수동 확인 권고)"
    fi
}

# ================================================================
# SRV-092: 사용자 홈 디렉토리 경로/권한
# ================================================================
check_SRV092() {
    vuln=""
    min_uid=500
    { [ "$OS_DISTRO" = "UBUNTU" ] || [ "$OS_DISTRO" = "DEBIAN" ]; } && min_uid=1000
    while IFS=: read -r user _ uid _ _ homedir _; do
        [ "${uid:-0}" -lt "$min_uid" ] 2>/dev/null && continue
        [ -z "$homedir" ] || [ "$homedir" = "/" ] && continue
        [ -d "$homedir" ] || continue
        perm=$(get_perm "$homedir"); owner=$(get_owner "$homedir")
        [ "$owner" != "$user" ] && vuln="${vuln} ${homedir}(소유자불일치:${owner})"
        [ "${perm:-0}" -gt 755 ] 2>/dev/null && vuln="${vuln} ${homedir}(권한:${perm})"
    done < /etc/passwd
    [ -n "$vuln" ] && echo "SRV-092|취약|홈 디렉토리 이상:${vuln}" || \
        echo "SRV-092|양호|사용자 홈 디렉토리 소유자/권한 적절"
}

# ================================================================
# SRV-093: world writable 파일
# ================================================================
check_SRV093() {
    cnt=$(find / -perm -0002 -type f ! -path "/proc/*" ! -path "/sys/*" \
          ! -path "/dev/*" ! -path "/tmp/*" ! -path "/var/tmp/*" 2>/dev/null | wc -l)
    [ "${cnt:-0}" -gt 0 ] 2>/dev/null && \
        echo "SRV-093|취약|world writable 파일 ${cnt}개 (tmp 제외)" || \
        echo "SRV-093|양호|world writable 파일 없음"
}

# ================================================================
# SRV-108: 로그 접근통제 및 관리
# ================================================================
check_SRV108() {
    vuln=""
    for logf in /var/log/messages /var/log/secure /var/log/auth.log \
                /var/log/syslog /var/log/wtmp /var/log/lastlog \
                /var/adm/messages /var/adm/syslog; do
        [ -f "$logf" ] || continue
        perm=$(get_perm "$logf")
        [ "${perm:-0}" -gt 644 ] 2>/dev/null && vuln="${vuln} ${logf}(${perm})"
    done
    [ -n "$vuln" ] && echo "SRV-108|취약|로그 파일 권한 이상:${vuln}" || \
        echo "SRV-108|양호|주요 로그 파일 권한 적절 (644 이하)"
}

# ================================================================
# SRV-109: 주요 이벤트 로그 설정
# ================================================================
check_SRV109() {
    case "$OS_FAMILY" in
    AIX|SOLARIS|HPUX)
        for f in /etc/syslog.conf /etc/rsyslog.conf; do
            [ -f "$f" ] && grep -qiE "^auth|^authpriv|\*\.\*" "$f" 2>/dev/null && \
                echo "SRV-109|양호|auth/authpriv 로그 설정됨 (${f})" && return
        done
        echo "SRV-109|취약|syslog auth 로그 미설정" ;;
    *)
        for f in /etc/rsyslog.conf /etc/rsyslog.d/*.conf /etc/syslog.conf; do
            [ -f "$f" ] || continue
            grep -qiE "^auth|^authpriv" "$f" 2>/dev/null && \
                echo "SRV-109|양호|auth/authpriv 로그 설정됨 (${f})" && return
        done
        [ -f /etc/syslog-ng/syslog-ng.conf ] && \
            grep -qi "auth\|authpriv" /etc/syslog-ng/syslog-ng.conf 2>/dev/null && \
            echo "SRV-109|양호|syslog-ng auth 로그 설정됨" && return
        echo "SRV-109|취약|auth/authpriv 로그 설정 없음" ;;
    esac
}

# ================================================================
# SRV-118: 보안패치 적용
# ================================================================
check_SRV118() {
    echo "SRV-118|수동확인|보안패치 적용 현황 수동 확인 필요"
}

# ================================================================
# SRV-121: root PATH 환경변수
# ================================================================
check_SRV121() {
    path_lines=$(grep -rh "^PATH\|^export PATH" \
                 /root/.bashrc /root/.bash_profile /root/.profile \
                 /etc/profile /etc/environment /etc/bashrc \
                 /etc/profile.d/*.sh 2>/dev/null | head -5)
    if echo "$path_lines" | grep -qE ':\.:|\.\.$|^\.:'; then
        echo "SRV-121|취약|PATH에 현재 디렉토리(.) 포함: $(echo $path_lines | head -1)"
    elif echo "$path_lines" | grep -qE '::|^:'; then
        echo "SRV-121|취약|PATH에 빈 항목(::) 포함"
    else
        echo "SRV-121|양호|PATH에 현재 디렉토리(.) 미포함"
    fi
}

# ================================================================
# SRV-122: umask 설정
# ================================================================
check_SRV122() {
    cur_umask=$(umask 2>/dev/null | sed 's/^0*//')
    cur_umask=${cur_umask:-22}
    file_umask=$(grep -rh "umask\|UMASK" \
                 /etc/profile /etc/bashrc /etc/environment /root/.bashrc \
                 /root/.profile /etc/profile.d/*.sh 2>/dev/null | \
                 grep -v "^#" | grep -oE "(umask|UMASK)\s*[=]?\s*([0-9]+)" | \
                 grep -oE "[0-9]+" | tail -1)
    check_val=${file_umask:-$cur_umask}
    [ "${check_val:-0}" -ge 22 ] 2>/dev/null && \
        echo "SRV-122|양호|umask=${check_val} (022 이상)" || \
        echo "SRV-122|취약|umask=${check_val} (022 이상 권고)"
}

# ================================================================
# SRV-127: 로그인 실패 횟수 접속 제한
# ================================================================
check_SRV127() {
    case "$OS_FAMILY" in
    AIX)
        val=$(awk '/^default:/,/^[^ \t]/' /etc/security/user 2>/dev/null | grep "loginretries" | grep -oE '[0-9]+' | head -1)
        [ -z "$val" ] && { echo "SRV-127|취약|AIX loginretries 미설정"; return; }
        [ "$val" -le 5 ] 2>/dev/null && echo "SRV-127|양호|AIX loginretries=${val}" || \
            echo "SRV-127|취약|AIX loginretries=${val} (5회 이하 권고)" ;;
    SOLARIS)
        val=$(grep "^LOCK_AFTER_RETRIES\|^logindisable" /etc/security/policy.conf /etc/default/login 2>/dev/null | grep -oE '[0-9]+' | head -1)
        [ -z "$val" ] && { echo "SRV-127|취약|Solaris 로그인 실패 제한 미설정"; return; }
        [ "$val" -le 5 ] 2>/dev/null && echo "SRV-127|양호|Solaris 잠금 임계값=${val}" || \
            echo "SRV-127|취약|Solaris 잠금 임계값=${val} (5회 이하 권고)" ;;
    HPUX)
        val=$(grep "^AUTH_MAXTRIES" /etc/default/security 2>/dev/null | cut -d= -f2 | tr -d ' ')
        [ -z "$val" ] && { echo "SRV-127|취약|HP-UX AUTH_MAXTRIES 미설정"; return; }
        [ "$val" -le 5 ] 2>/dev/null && echo "SRV-127|양호|HP-UX AUTH_MAXTRIES=${val}" || \
            echo "SRV-127|취약|HP-UX AUTH_MAXTRIES=${val} (5회 이하 권고)" ;;
    *)
        pam_files=$(get_pam_files)
        deny=0; found=0; module=""
        for f in $pam_files; do
            [ -f "$f" ] || continue
            if grep -qi "pam_faillock" "$f" 2>/dev/null; then
                module="pam_faillock"
                deny=$(grep -i "pam_faillock" "$f" 2>/dev/null | grep -v "^#" | grep -oE 'deny=([0-9]+)' | cut -d= -f2 | head -1)
                found=1; break
            fi
        done
        [ -f /etc/security/faillock.conf ] && \
            d=$(grep -v "^#" /etc/security/faillock.conf 2>/dev/null | grep "^deny" | grep -oE '[0-9]+' | head -1) && \
            [ -n "$d" ] && deny=$d && module="faillock.conf" && found=1
        if [ $found -eq 0 ]; then
            for f in $pam_files; do
                [ -f "$f" ] || continue
                grep -qi "pam_tally2\|pam_tally\b" "$f" 2>/dev/null && \
                    module="pam_tally2" && \
                    deny=$(grep -i "pam_tally" "$f" 2>/dev/null | grep -v "^#" | grep -oE 'deny=([0-9]+)' | cut -d= -f2 | head -1) && \
                    found=1 && break
            done
        fi
        if [ $found -eq 0 ]; then
            echo "SRV-127|취약|pam_faillock/pam_tally2 미설정"
        elif [ -z "$deny" ] || [ "$deny" -eq 0 ] 2>/dev/null; then
            echo "SRV-127|취약|${module} deny=0 (잠금 없음)"
        elif [ "$deny" -le 5 ] 2>/dev/null; then
            echo "SRV-127|양호|${module} deny=${deny} (5회 이하)"
        else
            echo "SRV-127|취약|${module} deny=${deny} (5회 이하 권고)"
        fi ;;
    esac
}

# ================================================================
# SRV-131: su 명령어 그룹 제한
# ================================================================
check_SRV131() {
    case "$OS_FAMILY" in
    AIX|SOLARIS|HPUX)
        grep -qi "pam_wheel\|pam_rootok" /etc/pam.d/su /etc/pam.conf 2>/dev/null && \
            echo "SRV-131|양호|su pam_wheel 제한 설정됨" || \
            echo "SRV-131|취약|su pam_wheel 제한 미설정" ;;
    *)
        grep -qi "pam_wheel\|pam_rootok" /etc/pam.d/su 2>/dev/null && \
            echo "SRV-131|양호|su wheel 그룹 제한 (pam_wheel)" || \
            echo "SRV-131|취약|su pam_wheel 미설정" ;;
    esac
}

# ================================================================
# SRV-133: Cron 서비스 사용 계정 제한
# ================================================================
check_SRV133() {
    [ -f /etc/cron.allow ] && echo "SRV-133|양호|cron.allow 존재 (허용 계정 관리)" && return
    [ -f /etc/cron.deny  ] && echo "SRV-133|양호|cron.deny 존재 (거부 계정 관리)" && return
    [ "$OS_FAMILY" = "AIX" ] && [ -f /var/adm/cron/allow ] && \
        echo "SRV-133|양호|AIX cron.allow 존재" && return
    echo "SRV-133|취약|cron.allow/cron.deny 미설정"
}

# ================================================================
# SRV-142: 중복 UID 계정 제한
# ================================================================
check_SRV142() {
    dup=$(awk -F: '{print $3}' /etc/passwd 2>/dev/null | sort | uniq -d)
    [ -n "$dup" ] && echo "SRV-142|취약|중복 UID 발견: $(echo $dup | head -5)" || \
        echo "SRV-142|양호|중복 UID 없음"
}

# ================================================================
# SRV-144: /dev 불필요 파일
# ================================================================
check_SRV144() {
    cnt=$(find /dev -type f ! -name "*.lock" ! -name "*.pid" 2>/dev/null | wc -l)
    [ "${cnt:-0}" -gt 5 ] 2>/dev/null && \
        echo "SRV-144|수동확인|/dev에 일반 파일 ${cnt}개 (정상 여부 확인)" || \
        echo "SRV-144|양호|/dev 불필요 일반 파일 미존재"
}

# ================================================================
# SRV-158: 불필요 Telnet 서비스 비활성화
# ================================================================
check_SRV158() {
    is_running telnetd || is_running in.telnetd || \
        netstat -tlnp 2>/dev/null | grep -q ":23 " || \
        ss -tlnp 2>/dev/null | grep -q ":23 " && \
        echo "SRV-158|취약|Telnet 서비스 실행 중 (포트 23)" && return
    echo "SRV-158|양호|Telnet 서비스 미실행"
}

# ================================================================
# SRV-161: ftpusers 파일의 소유자 및 권한 설정 적절성
# ================================================================
check_SRV161() {
    local ftp_files="
        /etc/ftpusers /etc/ftpd/ftpusers
        /etc/vsftpd/ftpusers /etc/vsftpd/user_list
        /etc/vsftpd.ftpusers /etc/vsftpd.user_list"
    local found="" bad=""
    for f in $ftp_files; do
        [ -f "$f" ] || continue
        found="${found} ${f}"
        perm=$(get_perm "$f"); owner=$(get_owner "$f")
        if [ "$owner" != "root" ] || [ "${perm:-777}" -gt 640 ] 2>/dev/null; then
            bad="${bad} ${f}(소유자:${owner},권한:${perm})"
        fi
    done
    if [ -z "$found" ]; then
        is_running vsftpd || is_running proftpd || is_running ftpd 2>/dev/null && \
            echo "SRV-161|취약|ftpusers 파일 없음 (FTP 실행 중)" || \
            echo "SRV-161|양호|FTP 서비스 미실행"
        return
    fi
    if [ -n "$bad" ]; then
        echo "SRV-161|취약|ftpusers 소유자/권한 이상:${bad}"
    else
        echo "SRV-161|양호|$(echo "$found" | tr '\n' ' ' | sed 's/^ //')소유자=root, 권한≤640"
    fi
}

# ================================================================
# SRV-163: 시스템 사용 주의사항 출력 (Banner)
# ================================================================
check_SRV163() {
    case "$OS_FAMILY" in
    AIX)
        [ -f /etc/security/login.cfg ] && grep -qi "herald\|banner" /etc/security/login.cfg 2>/dev/null && \
            echo "SRV-163|양호|AIX 로그인 배너 설정됨" && return ;;
    SOLARIS)
        [ -f /etc/motd ] && [ -s /etc/motd ] && echo "SRV-163|양호|Solaris /etc/motd 배너 설정됨" && return ;;
    esac
    for f in /etc/ssh/sshd_config /etc/issue /etc/issue.net; do
        [ -f "$f" ] || continue
        grep -qi "banner\|Warning\|Authorized" "$f" 2>/dev/null && \
            echo "SRV-163|양호|배너 설정됨 (${f})" && return
    done
    echo "SRV-163|취약|시스템 사용 주의사항 미설정 (배너 없음)"
}

# ================================================================
# SRV-165: 불필요 Shell 계정 제거
# ================================================================
check_SRV165() {
    vuln=""
    while IFS=: read -r user _ uid _ _ _ shell; do
        [ "$user" = "root" ] && continue
        [ "${uid:-999}" -ge 500 ] 2>/dev/null && continue
        case "$shell" in
        */nologin|*/false|/bin/false|/sbin/nologin|*/sync|"") ;;
        *) vuln="${vuln} ${user}(${shell})" ;;
        esac
    done < /etc/passwd
    [ -n "$vuln" ] && echo "SRV-165|취약|불필요 Shell 시스템 계정:${vuln}" || \
        echo "SRV-165|양호|시스템 계정 로그인 Shell 비허용"
}

# ================================================================
# SRV-175: NTP 설정
# ================================================================
check_SRV175() {
    # chrony
    command -v chronyc >/dev/null 2>&1 && \
        chronyc tracking 2>/dev/null | grep -q "Reference ID" && \
        echo "SRV-175|양호|chronyc NTP 동기화 활성" && return
    # ntpq
    command -v ntpq >/dev/null 2>&1 && \
        ntpq -p 2>/dev/null | grep -q "^\*" && \
        echo "SRV-175|양호|ntpq 활성 피어 확인" && return
    # timedatectl
    command -v timedatectl >/dev/null 2>&1 && \
        timedatectl 2>/dev/null | grep -q "synchronized: yes" && \
        echo "SRV-175|양호|timedatectl NTP 동기화 활성" && return
    # AIX
    [ "$OS_FAMILY" = "AIX" ] && grep -q "server" /etc/ntp.conf 2>/dev/null && \
        echo "SRV-175|수동확인|AIX ntp.conf 서버 설정됨 (동기화 상태 확인)" && return
    echo "SRV-175|취약|NTP 동기화 설정 미확인"
}

# ================================================================
# SRV-177: sudo 명령어 접근 권한 설정
# ================================================================
check_SRV177() {
    vuln=""
    for f in /etc/sudoers $(find /etc/sudoers.d/ -type f 2>/dev/null); do
        [ -f "$f" ] || continue
        line=$(grep -v "^#" "$f" 2>/dev/null | grep "NOPASSWD:\s*ALL" | head -2)
        [ -n "$line" ] && vuln="${vuln} ${f}"
    done
    [ -n "$vuln" ] && echo "SRV-177|취약|NOPASSWD ALL 설정 파일:${vuln}" || \
        echo "SRV-177|양호|sudoers NOPASSWD ALL 미설정"
}

# ================================================================
# SRV-179: EoS 시스템 장비 교체 (자동 판정)
# ================================================================
check_SRV179() {
    EOS_SCRIPT="$(dirname "$0")/eos_checker.py"
    [ ! -f "$EOS_SCRIPT" ] && {
        echo "SRV-179|수동확인|eos_checker.py 없음 - 수동 확인 필요"
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
            product="rhel"; version="$OS_MAJOR" ;;
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
            echo "SRV-179|수동확인|OS ${OS_DISTRO} ${OS_MAJOR} EoS 수동 확인"
            return ;;
        esac ;;
    *)
        echo "SRV-179|수동확인|OS 종류 미탐지 - 수동 확인"
        return ;;
    esac

    result=$(python3 "$EOS_SCRIPT" "$product" "$version" --no-api 2>/dev/null | grep "^결과:" | awk '{print $2}')
    desc=$(python3 "$EOS_SCRIPT" "$product" "$version" --no-api 2>/dev/null | grep "^설명:" | cut -d: -f2- | xargs)
    [ -z "$result" ] && { echo "SRV-179|수동확인|EoS 판정 실패 - 수동 확인"; return; }
    echo "SRV-179|${result}|${desc}"
}

# ── 실행 ─────────────────────────────────────────────────────────
check_SRV001
check_SRV003
check_SRV004
echo "SRV-005|수동확인|SMTP expn/vrfy 제한 수동 확인"
echo "SRV-006|수동확인|SMTP 로그 수준 수동 확인"
echo "SRV-007|수동확인|SMTP 보안패치 수동 확인"
echo "SRV-008|수동확인|SMTP DoS 방지 수동 확인"
echo "SRV-009|수동확인|SMTP 릴레이 제한 수동 확인"
echo "SRV-010|수동확인|SMTP queue 권한 수동 확인"
check_SRV011
echo "SRV-012|수동확인|.netrc 파일 내용 수동 확인"
check_SRV013
check_SRV014
check_SRV015
check_SRV016
echo "SRV-021|수동확인|FTP 서비스 접근 통제 수동 확인"
check_SRV022
check_SRV025
check_SRV026
check_SRV027
check_SRV028
check_SRV034
check_SRV035
echo "SRV-037|수동확인|취약 FTP 서비스(tftp 등) 수동 확인"
check_SRV062
check_SRV063
check_SRV064
check_SRV066
check_SRV069
check_SRV070
echo "SRV-072|N-A|Windows 전용 항목 (Linux/Unix 해당 없음)"
check_SRV073
check_SRV074
check_SRV075
echo "SRV-078|N-A|Windows Guest 계정 (Linux/Unix 해당 없음)"
echo "SRV-079|N-A|Windows Everyone 권한 (Linux/Unix 해당 없음)"
echo "SRV-080|N-A|Windows 프린터 드라이버 (Linux/Unix 해당 없음)"
check_SRV081
echo "SRV-082|수동확인|시스템 주요 디렉토리 권한 수동 확인"
echo "SRV-083|수동확인|시스템 스타트업 스크립트 권한 수동 확인"
check_SRV084
echo "SRV-087|수동확인|C 컴파일러 권한 수동 확인"
echo "SRV-090|N-A|Windows 원격 레지스트리 (Linux/Unix 해당 없음)"
check_SRV091
check_SRV092
check_SRV093
echo "SRV-094|수동확인|Crontab 참조파일 권한 수동 확인"
echo "SRV-095|수동확인|소유자 없는 파일 수동 확인"
echo "SRV-096|수동확인|환경변수 파일 권한 수동 확인"
check_SRV108
check_SRV109
echo "SRV-112|수동확인|Cron 로깅 설정 수동 확인"
echo "SRV-115|수동확인|로그 검토 수행 여부 수동 확인"
check_SRV118
check_SRV121
check_SRV122
echo "SRV-125|N-A|Windows 화면 보호기 (Linux/Unix 해당 없음)"
check_SRV127
check_SRV131
check_SRV133
echo "SRV-134|수동확인|Solaris 스택 실행 방지 수동 확인"
echo "SRV-135|수동확인|TCP 보안 설정 수동 확인"
check_SRV142
check_SRV144
echo "SRV-147|수동확인|불필요 네트워크 모니터링 서비스 수동 확인"
check_SRV158
check_SRV161
check_SRV163
echo "SRV-164|수동확인|구성원 없는 GID 수동 확인"
check_SRV165
echo "SRV-166|수동확인|불필요 숨김 파일 수동 확인"
echo "SRV-170|수동확인|SMTP 정보 노출 방지 수동 확인"
echo "SRV-171|수동확인|FTP 정보 노출 방지 수동 확인"
echo "SRV-173|수동확인|DNS 동적 업데이트 수동 확인"
echo "SRV-174|수동확인|불필요 DNS 서비스 수동 확인"
check_SRV175
check_SRV177
echo "SRV-178|N-A|Windows 개인 키 passphrase (Linux/Unix 해당 없음)"
check_SRV179

echo "# 점검 완료: $(date '+%Y-%m-%d %H:%M:%S')"
