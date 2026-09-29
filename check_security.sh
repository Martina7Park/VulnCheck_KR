#!/bin/bash
# ================================================================
# 보안장비(정보보호시스템) 취약점 점검 반자동 스크립트 v2.0
#
# 평가기준: 전자금융기반시설 보안 취약점 평가기준 제2026-1호
#           [정보보호시스템 장비] ISS-001 ~ ISS-043 (43항목)
#
# 지원 벤더: FortiGate, Palo Alto, 일반(generic)
# 지원 장비: FW(방화벽), VPN, IDS, IPS, DDoS, WAF
#
# [사용법]
#   bash check_security.sh <config_file.txt> [vendor] [device_type]
#
#   vendor:      fortigate | paloalto | generic  (미지정 시 자동 탐지)
#   device_type: FW | VPN | IDS | IPS | DDoS | WAF  (미지정 시 FW)
#
# [출력 형식]
#   표준출력: ISS-xxx|결과|근거설명
#   증적파일: /tmp/<config파일명>_iss_evidence.txt
# ================================================================

if [ $# -lt 1 ]; then
    echo "사용법: bash check_security.sh <config_file.txt> [fortigate|paloalto|generic] [FW|VPN|IDS|IPS|DDoS|WAF]"
    exit 1
fi

CONFIG="$1"
VENDOR="${2:-auto}"
DEV_TYPE="${3:-FW}"
[ -z "$3" ] && echo "[경고] 장비유형 인자 미지정 → FW 로 점검합니다. IDS/IPS/DDoS/WAF/VPN 장비는 3번째 인자로 지정하세요 (평가대상 N-A 판정이 달라짐)" >&2

if [ ! -f "$CONFIG" ]; then
    echo "[ERROR] 파일 없음: $CONFIG"
    exit 1
fi

DEV_TYPE=$(echo "$DEV_TYPE" | tr '[:lower:]' '[:upper:]')
case "$DEV_TYPE" in
    FW|VPN|IDS|IPS|DDOS|WAF) ;;
    *) echo "[ERROR] 지원하지 않는 장비 유형: $DEV_TYPE (FW|VPN|IDS|IPS|DDoS|WAF)"; exit 1 ;;
esac

TEXT=$(cat "$CONFIG")
CFG_BASE=$(basename "$CONFIG" .txt)
# ── 결과 사본 자동 저장: '> 파일' 리다이렉트를 빠뜨려도 판정 결과가 증적과 같은 위치에 남도록 표준출력을 복사 ──
_RESF="/tmp/${CFG_BASE}_iss.txt"
if [ -z "$NO_RESULT_COPY" ] && ! [ /dev/fd/1 -ef "$_RESF" ] 2>/dev/null && ( : > "$_RESF" ) 2>/dev/null; then
    exec > >(tee "$_RESF"); _TEEPID=$!
else
    _RESF=""
fi

# ── 벤더 자동 탐지 ──────────────────────────────────────────────
detect_vendor() {
    if echo "$TEXT" | grep -qi "config system global\|FortiOS\|fortigate\|config firewall policy\|^#config-version=FG"; then
        echo "fortigate"
    elif echo "$TEXT" | grep -qi "paloaltonetworks\|set deviceconfig\|<policy>\|panorama\|vsys"; then
        echo "paloalto"
    else
        echo "generic"
    fi
}

if [ "$VENDOR" = "auto" ]; then
    VENDOR=$(detect_vendor)
fi

# ── 배너 ────────────────────────────────────────────────────────
echo "# ============================================================"
echo "# 보안장비 취약점 점검 결과"
echo "# 점검 기준: 전자금융기반시설 보안 취약점 평가기준 제2026-1호"
echo "#            [정보보호시스템 장비] ISS-001 ~ ISS-043"
echo "# 벤더: $VENDOR"
echo "# 장비유형: $DEV_TYPE$([ -z "$3" ] && echo " (기본값 - 장비유형 인자 미지정)")"
echo "# 파일: $(basename "$CONFIG")"
echo "# 점검일: $(date '+%Y-%m-%d %H:%M:%S')"
echo "#"

# ── 결과 카운터 / 증적 파일 ────────────────────────────────────
_CP=0; _CF=0; _CM=0; _CN=0
_EVD="/tmp/${CFG_BASE}_iss_evidence.txt"
echo "# ================================================================" > "$_EVD"
echo "# 증적 파일 (감사 추적용)" >> "$_EVD"
echo "# 대상: $(basename "$CONFIG") / 벤더: $VENDOR / 유형: $DEV_TYPE" >> "$_EVD"
echo "# 생성: $(date '+%Y-%m-%d %H:%M:%S')" >> "$_EVD"
echo "# ================================================================" >> "$_EVD"

declare -A _INAME=(
    [ISS-001]='보안장비 정책 및 로그 백업 설정 여부'
    [ISS-002]='원격 로그 서버 사용 여부'
    [ISS-003]='DMZ 구간 설정 여부'
    [ISS-004]='NAT 정책 설정 적정성'
    [ISS-005]='주기적인 보안패치 및 벤더 권고사항 적용 여부'
    [ISS-006]='보안장비 사용량의 주기적인 점검 및 보고 여부'
    [ISS-007]='보안장비 장애/보안이벤트 모니터링 실시 여부'
    [ISS-008]='탐지된 이벤트 및 로그에 대한 정기적 분석 및 보고 여부'
    [ISS-009]='위험도가 높은 이벤트 및 로그에 대한 RAW 패킷 저장 여부'
    [ISS-010]='TCP/UDP/ICMP 탐지/차단 패턴 적용 여부'
    [ISS-011]='Port Scan 탐지/차단 패턴 적용 여부'
    [ISS-012]='해킹 툴 탐지/차단 패턴 적용 여부'
    [ISS-013]='불필요한 Source Routing 차단 설정 여부'
    [ISS-014]='사용하지 않는 SNMP 비활성화 여부'
    [ISS-015]='안전한 네트워크 모니터링 서비스 사용 여부'
    [ISS-016]='보안장비 접속 시 보안 접속 사용 여부'
    [ISS-017]='보안장비 Default 계정 변경 여부'
    [ISS-018]='보안장비 Default 비밀번호 변경 여부'
    [ISS-019]='보안장비 계정 관리 적정성'
    [ISS-020]='보안장비 계정별 권한 설정 여부'
    [ISS-021]='보안장비 원격 관리 접근 통제 여부'
    [ISS-022]='보안장비 접속성공/실패 로깅 여부'
    [ISS-023]='로그인 실패횟수 제한 설정 여부'
    [ISS-024]='세션 타임아웃 설정 여부'
    [ISS-025]='시간 동기화를 위한 NTP 설정'
    [ISS-026]='주요 파일에 대한 주기적인 무결성 검사 여부'
    [ISS-027]='보안장비 기능외 서비스 제한 여부'
    [ISS-028]='보안장비 정책 변경통제 절차 수립 여부'
    [ISS-029]='보안장비 변경요청 정책의 기술적 검토 여부'
    [ISS-030]='모든 목적지 및 서비스로의 허용 정책 금지 여부'
    [ISS-031]='취약한 서비스의 네트워크 대역 단위 허용 금지 여부'
    [ISS-032]='서비스 포트 허용 정책 적정성'
    [ISS-033]='불필요한 양방향 정책 금지 여부'
    [ISS-034]='정책 적용 순서의 적절성'
    [ISS-035]='출발지 포트 기반의 정책 금지 여부'
    [ISS-036]='취약한 원격 서비스 금지 여부'
    [ISS-037]='불필요한 정책 제거 여부'
    [ISS-038]='서버간 관리포트 허용 금지 여부'
    [ISS-039]='단말과 서버간 접근통제를 우회한 접속 금지 여부'
    [ISS-040]='보안장비 비밀번호의 주기적인 변경 여부'
    [ISS-041]='불필요한 네트워크 대역 단위 설정 금지 여부'
    [ISS-042]='차단 기능 활성화 여부'
    [ISS-043]='서비스 지원이 종료된(EoS) 시스템 및 장비 교체 여부'
)
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
    return 0   # 증적 쓰기 실패가 `조건 && result A || result B` 에서 B 중복 출력을 일으키지 않도록
}
evd() {
    local item="$1"; shift
    printf '[%s] %s $ %s\n' "$item" "$(date '+%H:%M:%S')" "$*" >> "$_EVD"
    eval "$@" >> "$_EVD" 2>&1
    printf '\n' >> "$_EVD"
}

# ── 장비유형별 적용여부 판별 ────────────────────────────────────
# 해당 ISS 항목이 현재 장비유형에 적용되는지 확인
# 적용 안 되면 N-A 처리 후 return 1
check_applicable() {
    local code="$1" name="$2"
    local apply=1
    case "$code" in
        ISS-003|ISS-004|ISS-013) # FW,VPN only
            case "$DEV_TYPE" in FW|VPN) apply=1 ;; *) apply=0 ;; esac ;;
        ISS-008|ISS-009) # IDS,IPS,DDoS,WAF only
            case "$DEV_TYPE" in IDS|IPS|DDOS|WAF) apply=1 ;; *) apply=0 ;; esac ;;
        ISS-010|ISS-011) # IDS,IPS,DDoS only
            case "$DEV_TYPE" in IDS|IPS|DDOS) apply=1 ;; *) apply=0 ;; esac ;;
        ISS-012) # IDS,IPS,WAF only
            case "$DEV_TYPE" in IDS|IPS|WAF) apply=1 ;; *) apply=0 ;; esac ;;
        ISS-028|ISS-029|ISS-030|ISS-031|ISS-032|ISS-033|ISS-034|ISS-035|ISS-036|ISS-037|ISS-038|ISS-039|ISS-041) # FW,VPN only
            case "$DEV_TYPE" in FW|VPN) apply=1 ;; *) apply=0 ;; esac ;;
        ISS-042) # WAF only
            case "$DEV_TYPE" in WAF) apply=1 ;; *) apply=0 ;; esac ;;
    esac
    if [ "$apply" -eq 0 ]; then
        evd "$code" "echo '장비유형 ${DEV_TYPE} — ${name} 평가대상 아님'"
        result "${code}|N-A|장비유형 ${DEV_TYPE} — 해당 항목 평가대상 아님"
        return 1
    fi
    return 0
}

# ── FortiGate 설정 파서 (정책·서비스 객체 단위 판정용) ─────────
# fg_policies: config firewall policy 의 edit 단위 → "id<TAB>action<TAB>status<TAB>srcaddr<TAB>dstaddr<TAB>service"
#   (FortiOS 기본값: action=deny, status=enable — show 백업에는 기본값 줄이 생략됨)
fg_policies() {
    echo "$TEXT" | tr -d '\r' | awk '
        function flush() { if (id != "") printf "%s\t%s\t%s\t%s\t%s\t%s\n", id, act, st, src, dst, svc; id="" }
        function val(l) { sub(/^[ \t]*set [^ ]+[ \t]*/, "", l); gsub(/"/, "", l); return l }
        /^[ \t]*config firewall policy[ \t]*$/ { inp=1; nest=0; next }
        !inp { next }
        /^[ \t]*config / { nest++; next }
        /^[ \t]*end[ \t]*$/ { if (nest > 0) { nest--; next } flush(); inp=0; next }
        nest > 0 { next }
        /^[ \t]*edit / { flush(); id=$2; gsub(/"/, "", id); act="deny"; st="enable"; src=""; dst=""; svc=""; next }
        /^[ \t]*next[ \t]*$/ { flush(); next }
        /^[ \t]*set action / { act=val($0) }
        /^[ \t]*set status / { st=val($0) }
        /^[ \t]*set srcaddr / { src=val($0) }
        /^[ \t]*set dstaddr / { dst=val($0) }
        /^[ \t]*set service / { svc=val($0) }'
}
# fg_accept: 활성(accept, status enable) 정책만
fg_accept() { fg_policies | awk -F'\t' '$2=="accept" && $3!="disable"'; }
# fg_services: config firewall service custom → "name<TAB>tcp/udp/sctp portrange 값들"
fg_services() {
    echo "$TEXT" | tr -d '\r' | awk '
        /^[ \t]*config firewall service custom[ \t]*$/ { ins=1; next }
        !ins { next }
        /^[ \t]*end[ \t]*$/ { if (n != "") print n "\t" r; ins=0; n=""; next }
        /^[ \t]*edit / { if (n != "") print n "\t" r; n=$0; sub(/^[ \t]*edit[ \t]*/, "", n); gsub(/"/, "", n); r=""; next }
        /^[ \t]*set (tcp|udp|sctp)-portrange / { l=$0; sub(/^[ \t]*set [^ ]+[ \t]*/, "", l); r=r " " l }'
}
# 정책 서비스 목록에 지정 이름(공백 구분 토큰, 대소문자 무시)이 있는 accept 정책 id 목록
fg_accept_with_svc() {  # $1: 정규식(토큰 전체 일치)
    fg_accept | awk -F'\t' -v re="^($1)$" '{ n=split($6, a, " "); for (i=1;i<=n;i++) if (toupper(a[i]) ~ toupper(re)) { printf "%s ", $1; break } }'
}
# 복잡도: 2종 10자 이상 또는 3종 8자 이상 (영문/숫자/특수문자)
str_complex() {
    local s="$1" c=0
    echo "$s" | grep -q '[A-Za-z]' && c=$((c+1))
    echo "$s" | grep -q '[0-9]' && c=$((c+1))
    echo "$s" | grep -q '[^A-Za-z0-9]' && c=$((c+1))
    { [ "$c" -ge 2 ] && [ "${#s}" -ge 10 ]; } || { [ "$c" -ge 3 ] && [ "${#s}" -ge 8 ]; }
}
# pa_tags: PAN-OS XML 을 태그 단위 줄로 정규화 (한 줄/여러 줄 XML 모두 처리)
pa_tags() { echo "$TEXT" | tr -d '\r\n' | sed 's/</\n</g' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | grep -v '^$'; }
mask_str() { local s="$1"; [ "${#s}" -gt 2 ] && printf '%s%s' "${s:0:2}" "$(printf '%*s' $(( ${#s} - 2 )) '' | tr ' ' '*')" || printf '**'; }

# ================================================================
# FortiGate 점검
# ================================================================
check_fortigate() {

# ISS-001: 보안장비 정책 및 로그 백업 설정 여부
check_applicable "ISS-001" "정책 및 로그 백업" && {
    evd "ISS-001" "echo \"\$TEXT\" | grep -i 'backup\|auto-backup\|config backup\|log.*disk\|logdisk' | head -10"
    result "ISS-001|수동확인|정책/로그 백업 주기 및 절차 수동 확인 필요 (인터뷰 기반)"
}

# ISS-002: 원격 로그 서버 사용 여부
check_applicable "ISS-002" "원격 로그 서버" && {
    evd "ISS-002" "echo \"\$TEXT\" | grep -i 'config log syslogd\|config log fortianalyzer\|set server\|set status' | head -15"
    LOG_SYSLOG=$(echo "$TEXT" | grep -ci "config log syslogd" 2>/dev/null || true)
    LOG_FAZ=$(echo "$TEXT" | grep -ci "config log fortianalyzer" 2>/dev/null || true)
    SYSLOG_STATUS=$(echo "$TEXT" | grep -A3 "config log syslogd" 2>/dev/null | grep -i "set status enable" | head -1)
    FAZ_STATUS=$(echo "$TEXT" | grep -A3 "config log fortianalyzer" 2>/dev/null | grep -i "set status enable" | head -1)
    if [ -n "$SYSLOG_STATUS" ] || [ -n "$FAZ_STATUS" ]; then
        result "ISS-002|양호|원격 로그서버 연동됨 (syslog: ${LOG_SYSLOG}, FortiAnalyzer: ${LOG_FAZ})"
    elif [ "$LOG_SYSLOG" -gt 0 ] || [ "$LOG_FAZ" -gt 0 ]; then
        result "ISS-002|수동확인|로그서버 설정 존재 — 활성화 상태 수동 확인 필요"
    else
        result "ISS-002|취약|원격 로그서버(syslog/FortiAnalyzer) 미설정"
    fi
}

# ISS-003: DMZ 구간 설정 여부
check_applicable "ISS-003" "DMZ 구간 설정" && {
    evd "ISS-003" "echo \"\$TEXT\" | grep -i 'dmz\|config system zone\|config system interface' | head -10"
    ZONES=$(echo "$TEXT" | grep -ci "config system zone" 2>/dev/null || true)
    # 데스크톱 모델 기본 인터페이스 'dmz' 는 미사용이어도 존재 → dmz 인터페이스/존을 쓰는 accept 정책이 있어야 양호
    DMZ_POL=$(echo "$TEXT" | tr -d '\r' | awk '/^[ \t]*config firewall policy[ \t]*$/{p=1} p&&/^[ \t]*edit /{id=$2} p&&/^[ \t]*set (srcintf|dstintf) .*[Dd][Mm][Zz]/{print id}' | sort -u | tr '\n' ' ')
    DMZ=$(echo "$TEXT" | grep -ci "dmz" 2>/dev/null || true)
    if [ -n "$DMZ_POL" ]; then
        result "ISS-003|양호|DMZ 인터페이스/존 사용 정책 확인됨 (정책 ${DMZ_POL% })"
    else
        result "ISS-003|수동확인|DMZ 사용 정책 미탐지 (dmz 키워드 ${DMZ}건, zone ${ZONES}건) — 공개용 서버 구간 분리 여부 수동 확인"
    fi
}

# ISS-004: NAT 정책 설정 적정성
check_applicable "ISS-004" "NAT 정책 적정성" && {
    evd "ISS-004" "echo \"\$TEXT\" | grep -i 'set nat enable\|config firewall vip\|set extip\|set mappedip' | head -15"
    NAT_COUNT=$(echo "$TEXT" | grep -ci "set nat enable" 2>/dev/null || true)
    VIP_COUNT=$(echo "$TEXT" | grep -ci "config firewall vip" 2>/dev/null || true)
    result "ISS-004|수동확인|NAT 정책 ${NAT_COUNT}건, VIP ${VIP_COUNT}건 — 불필요 NAT 존재 여부 수동 확인"
}

# ISS-005: 주기적인 보안패치 및 벤더 권고사항 적용 여부
check_applicable "ISS-005" "보안패치 적용" && {
    evd "ISS-005" "echo \"\$TEXT\" | grep -i 'config-version=\|set version\|#config-version\|FortiOS\|build' | head -5"
    FW_VER=$(echo "$TEXT" | grep -iE 'config-version=|#config-version|FortiOS|build[0-9]' 2>/dev/null | head -1)
    result "ISS-005|수동확인|펌웨어 버전: ${FW_VER:-미탐지} — 최신 패치 적용 여부 수동 확인 (벤더 권고사항 대조)"
}

# ISS-006: 보안장비 사용량의 주기적인 점검 및 보고 여부
check_applicable "ISS-006" "사용량 점검/보고" && {
    evd "ISS-006" "echo \"\$TEXT\" | grep -i 'snmp\|monitoring\|alert\|diagnose\|syslog' | head -10"
    result "ISS-006|수동확인|CPU/메모리 사용량 모니터링 및 주기적 보고 여부 수동 확인 (인터뷰 기반)"
}

# ISS-007: 보안장비 장애/보안이벤트 모니터링 실시 여부
check_applicable "ISS-007" "장애/이벤트 모니터링" && {
    evd "ISS-007" "echo \"\$TEXT\" | grep -i 'config alertemail\|config system alert\|set alert\|set mailto\|set snmp-index' | head -10"
    ALERT=$(echo "$TEXT" | grep -ci "alert\|mailto\|notification" 2>/dev/null || true)
    if [ "$ALERT" -gt 0 ]; then
        result "ISS-007|수동확인|알림/알람 설정 ${ALERT}건 발견 — 모니터링 체계 수동 확인"
    else
        result "ISS-007|수동확인|알림 설정 미탐지 — 이벤트 모니터링 체계 수동 확인"
    fi
}

# ISS-008: 탐지된 이벤트 및 로그에 대한 정기적 분석 및 보고 여부
check_applicable "ISS-008" "이벤트 분석/보고" && {
    evd "ISS-008" "echo \"\$TEXT\" | grep -i 'log\|report\|analytics\|fortianalyzer' | head -10"
    result "ISS-008|수동확인|보안이벤트 정기 분석/보고 여부 수동 확인 (보안관제보고서 확인)"
}

# ISS-009: 위험도가 높은 이벤트 및 로그에 대한 RAW 패킷 저장 여부
check_applicable "ISS-009" "RAW 패킷 저장" && {
    evd "ISS-009" "echo \"\$TEXT\" | grep -i 'packet-log\|netscan\|full-archive\|capture\|pcap' | head -10"
    PCAP=$(echo "$TEXT" | grep -ci "packet-log\|full-archive\|capture\|pcap" 2>/dev/null || true)
    if [ "$PCAP" -gt 0 ]; then
        result "ISS-009|수동확인|패킷 저장 관련 설정 ${PCAP}건 — 위험도 높은 이벤트 RAW 저장 여부 수동 확인"
    else
        result "ISS-009|수동확인|패킷 저장 설정 미탐지 — RAW 패킷 저장 기능 수동 확인"
    fi
}

# ISS-010: TCP/UDP/ICMP 탐지/차단 패턴 적용 여부
check_applicable "ISS-010" "Flooding 탐지/차단" && {
    evd "ISS-010" "echo \"\$TEXT\" | grep -i 'dos-policy\|anomaly\|flood\|icmp\|syn.*cookie\|rate-based' | head -10"
    DOS=$(echo "$TEXT" | grep -ci "dos-policy\|anomaly\|flood" 2>/dev/null || true)
    if [ "$DOS" -gt 0 ]; then
        result "ISS-010|수동확인|DoS/Flooding 관련 설정 ${DOS}건 — TCP/UDP/ICMP 패턴 적용 여부 수동 확인"
    else
        result "ISS-010|수동확인|DoS/Flooding 설정 미탐지 — 탐지/차단 패턴 수동 확인"
    fi
}

# ISS-011: Port Scan 탐지/차단 패턴 적용 여부
check_applicable "ISS-011" "Port Scan 탐지/차단" && {
    evd "ISS-011" "echo \"\$TEXT\" | grep -i 'port.*scan\|scan.*detect\|portscan\|reconnaissance' | head -10"
    SCAN=$(echo "$TEXT" | grep -ci "port.*scan\|scan.*detect\|portscan" 2>/dev/null || true)
    if [ "$SCAN" -gt 0 ]; then
        result "ISS-011|수동확인|Port Scan 탐지 설정 ${SCAN}건 — 차단 정책 수동 확인"
    else
        result "ISS-011|수동확인|Port Scan 탐지 설정 미탐지 — 탐지/차단 패턴 수동 확인"
    fi
}

# ISS-012: 해킹 툴 탐지/차단 패턴 적용 여부
check_applicable "ISS-012" "해킹 툴 탐지/차단" && {
    evd "ISS-012" "echo \"\$TEXT\" | grep -i 'ips.*sensor\|config ips\|malware\|antivirus\|botnet\|application-control' | head -10"
    IPS=$(echo "$TEXT" | grep -ci "ips.*sensor\|config ips\|antivirus\|botnet" 2>/dev/null || true)
    if [ "$IPS" -gt 0 ]; then
        result "ISS-012|수동확인|IPS/악성코드 탐지 설정 ${IPS}건 — 패턴 최신 여부 수동 확인"
    else
        result "ISS-012|수동확인|IPS/악성코드 탐지 설정 미탐지 — 해킹 툴 차단 기능 수동 확인"
    fi
}

# ISS-013: 불필요한 Source Routing 차단 설정 여부
check_applicable "ISS-013" "Source Routing 차단" && {
    evd "ISS-013" "echo \"\$TEXT\" | grep -i 'source.*rout\|ip.*option\|strict-src-check\|asymroute' | head -10"
    SRCRT=$(echo "$TEXT" | grep -ci "source.*rout\|strict-src-check" 2>/dev/null || true)
    ASYM=$(echo "$TEXT" | grep -i "set asymroute" 2>/dev/null | head -1)
    if [ -n "$ASYM" ]; then
        result "ISS-013|수동확인|asymroute 설정: ${ASYM} — Source Routing 차단 여부 수동 확인"
    else
        result "ISS-013|수동확인|Source Routing 관련 설정 수동 확인"
    fi
}

# ISS-014: 사용하지 않는 SNMP 비활성화 여부
check_applicable "ISS-014" "SNMP 비활성화" && {
    evd "ISS-014" "echo \"\$TEXT\" | grep -i 'config system snmp\|snmp.*community\|snmp.*user\|set name' | head -15"
    SNMP_EN=$(echo "$TEXT" | grep -ci "config system snmp" 2>/dev/null || true)
    SNMP_COMM=$(echo "$TEXT" | grep -ci "config system snmp community" 2>/dev/null || true)
    if [ "$SNMP_EN" -eq 0 ]; then
        result "ISS-014|양호|SNMP 미사용 (설정 없음)"
    else
        result "ISS-014|수동확인|SNMP 설정 존재 (community ${SNMP_COMM}건) — 사용 필요성 수동 확인"
    fi
}

# ISS-015: 안전한 네트워크 모니터링 서비스 사용 여부 (SNMPv3)
check_applicable "ISS-015" "SNMP 안전 버전" && {
    evd "ISS-015" "echo \"\$TEXT\" | grep -i 'snmp.*user\|snmp.*community\|set name.*public\|set name.*private\|auth-proto\|priv-proto' | head -15"
    # community 이름 / v3 사용자별 security-level (FortiOS 기본값 no-auth-no-priv)
    COMMS=$(echo "$TEXT" | tr -d '\r' | awk '/^[ \t]*config system snmp community[ \t]*$/{c=1;next} c&&/^[ \t]*config /{n++} c&&/^[ \t]*end[ \t]*$/{if(n>0){n--;next} c=0} c&&n==0&&/^[ \t]*set name /{l=$0; sub(/^[ \t]*set name[ \t]*/,"",l); gsub(/"/,"",l); print l}')
    V3=$(echo "$TEXT" | tr -d '\r' | awk '/^[ \t]*config system snmp user[ \t]*$/{u=1;next} u&&/^[ \t]*end[ \t]*$/{if(id!="")print id"\t"lv; u=0} u&&/^[ \t]*edit /{if(id!="")print id"\t"lv; id=$2; gsub(/"/,"",id); lv="no-auth-no-priv"} u&&/^[ \t]*set security-level /{lv=$3}')
    V3_WEAK=$(echo "$V3" | awk -F'\t' 'NF>1 && $2!="auth-priv"{printf "%s(%s) ", $1, $2}')
    C_DEF=""; C_WEAK=""; C_OK=""
    while IFS= read -r cm; do
        [ -z "$cm" ] && continue
        if echo "$cm" | grep -qiE '^(public|private)$'; then C_DEF="${C_DEF}$(mask_str "$cm") "
        elif str_complex "$cm"; then C_OK="${C_OK}$(mask_str "$cm") "
        else C_WEAK="${C_WEAK}$(mask_str "$cm")(${#cm}자) "; fi
    done <<< "$COMMS"
    if [ -n "$C_DEF" ]; then
        result "ISS-015|취약|SNMP 기본 community(public/private) 사용: ${C_DEF% }"
    elif [ -n "$C_WEAK" ]; then
        result "ISS-015|취약|SNMPv2 community 복잡도 미달(2종 10자/3종 8자): ${C_WEAK% }"
    elif [ -n "$V3_WEAK" ]; then
        result "ISS-015|취약|SNMPv3 보안설정(auth-priv) 미적용 사용자: ${V3_WEAK% }"
    elif [ -n "$C_OK" ]; then
        result "ISS-015|수동확인|SNMPv2 community 복잡도 충족(${C_OK% }) — SNMPv3 사용 가능 환경에서 v2 사용 여부 확인 (가능 시 취약)"
    elif [ -n "$V3" ]; then
        result "ISS-015|양호|SNMPv3 사용자 모두 auth-priv 적용, v2 community 없음"
    else
        result "ISS-015|양호|SNMP 미사용 (community/v3 사용자 없음)"
    fi
}

# ISS-016: 보안장비 접속 시 보안 접속 사용 여부
check_applicable "ISS-016" "보안 접속" && {
    evd "ISS-016" "echo \"\$TEXT\" | grep -i 'set allowaccess\|set admin-sport\|set admin-ssh' | head -15"
    HAS_HTTP=$(echo "$TEXT" | grep -i "set allowaccess" 2>/dev/null | grep -oiE '\bhttp\b' | grep -civ "https" 2>/dev/null || true)
    TELNET=$(echo "$TEXT" | grep -i "set allowaccess" 2>/dev/null | grep -ci "telnet" 2>/dev/null || true)
    if [ "$HAS_HTTP" -gt 0 ] || [ "$TELNET" -gt 0 ]; then
        WEAK=""
        [ "$HAS_HTTP" -gt 0 ] && WEAK="HTTP "
        [ "$TELNET" -gt 0 ] && WEAK="${WEAK}Telnet"
        result "ISS-016|취약|평문 관리 프로토콜 허용: ${WEAK} — HTTPS/SSH 전용 사용 필요"
    else
        result "ISS-016|양호|HTTPS/SSH 전용 관리 접속 확인"
    fi
}

# ISS-017: 보안장비 Default 계정 변경 여부
check_applicable "ISS-017" "Default 계정 변경" && {
    evd "ISS-017" "echo \"\$TEXT\" | grep -i 'config system admin\|set name\|set accprofile' | head -15"
    DEFAULT_ADMIN=$(echo "$TEXT" | grep -iE 'edit "admin"|set name "admin"' 2>/dev/null | head -1)
    ADMIN_LIST=$(echo "$TEXT" | grep -iE 'edit "|set name "' 2>/dev/null | grep -v '#' | head -10)
    if [ -n "$DEFAULT_ADMIN" ]; then
        result "ISS-017|취약|기본 admin 계정명 미변경 — 계정명 변경 필요"
    else
        result "ISS-017|양호|기본 admin 계정명 변경됨"
    fi
}

# ISS-018: 보안장비 Default 비밀번호 변경 여부
check_applicable "ISS-018" "Default 비밀번호 변경" && {
    evd "ISS-018" "echo \"\$TEXT\" | grep -i 'password-policy\|minimum-length\|min-length\|change-4-characters' | head -10"
    PW_POLICY=$(echo "$TEXT" | grep -i "password-policy" 2>/dev/null | head -1)
    # FortiOS config system password-policy 키는 minimum-length (min-length 는 구버전 표기 대비)
    MIN_LEN=$(echo "$TEXT" | grep -iE "set (minimum-length|min-length) " 2>/dev/null | head -1 | grep -oE '[0-9]+' | head -1)
    if [ -n "$MIN_LEN" ] && [ "$MIN_LEN" -ge 8 ]; then
        result "ISS-018|수동확인|비밀번호 최소 길이 ${MIN_LEN}자 — 기본 비밀번호 변경 여부 수동 확인"
    else
        result "ISS-018|수동확인|비밀번호 복잡도 정책 수동 확인 (최소길이: ${MIN_LEN:-미설정})"
    fi
}

# ISS-019: 보안장비 계정 관리 적정성
check_applicable "ISS-019" "계정 관리 적정성" && {
    evd "ISS-019" "echo \"\$TEXT\" | grep -i 'config system admin' -A20 | grep -i 'edit\|set name\|set accprofile\|set trusthost' | head -20"
    ADMIN_COUNT=$(echo "$TEXT" | grep -c 'edit ' 2>/dev/null | head -1)
    result "ISS-019|수동확인|관리자 계정 현황 수동 확인 — 개인별 계정 사용 및 공용 계정 사용 여부 점검"
}

# ISS-020: 보안장비 계정별 권한 설정 여부
check_applicable "ISS-020" "계정별 권한 설정" && {
    evd "ISS-020" "echo \"\$TEXT\" | grep -i 'set accprofile\|config system accprofile\|set adminprof' | head -15"
    PROF=$(echo "$TEXT" | grep -ci "set accprofile\|config system accprofile" 2>/dev/null || true)
    if [ "$PROF" -gt 0 ]; then
        result "ISS-020|수동확인|권한 프로파일 설정 ${PROF}건 — 최소권한 원칙 준수 여부 수동 확인"
    else
        result "ISS-020|수동확인|권한 프로파일 미탐지 — 계정별 권한 설정 수동 확인"
    fi
}

# ISS-021: 보안장비 원격 관리 접근 통제 여부
check_applicable "ISS-021" "원격 관리 접근 통제" && {
    evd "ISS-021" "echo \"\$TEXT\" | grep -i 'set trusthost\|set trusted\|set admin-sport\|set admin-server-cert\|config firewall local-in-policy' | head -15"
    # 관리자 계정별 trusthost (0.0.0.0 0.0.0.0 = 전체 허용은 미설정으로 간주)
    ADM=$(echo "$TEXT" | tr -d '\r' | awk '/^[ \t]*config system admin[ \t]*$/{a=1;next} a&&/^[ \t]*config /{n++} a&&/^[ \t]*end[ \t]*$/{if(n>0){n--;next} if(id!="")print id"\t"t; a=0} a&&n==0&&/^[ \t]*edit /{if(id!="")print id"\t"t; id=$2; gsub(/"/,"",id); t=0} a&&/^[ \t]*set (ip6-)?trusthost[0-9]* /{if($0 !~ /0\.0\.0\.0[ \/]+0\.0\.0\.0/ && $0 !~ /::\/0/) t++}')
    ADM_ALL=$(echo "$ADM" | awk 'NF' | wc -l | tr -d ' ')
    ADM_OPEN=$(echo "$ADM" | awk -F'\t' 'NF>1 && $2==0{printf "%s ", $1}')
    LIP=$(echo "$TEXT" | grep -ci "config firewall local-in-policy" 2>/dev/null || true)
    if [ "$ADM_ALL" -gt 0 ] && [ -z "$ADM_OPEN" ]; then
        result "ISS-021|양호|관리자 ${ADM_ALL}개 계정 모두 trusthost(관리 IP) 제한 설정"
    elif [ "$ADM_ALL" -gt 0 ]; then
        result "ISS-021|수동확인|trusthost 미설정(또는 0.0.0.0/0) 관리자: ${ADM_OPEN% } — local-in-policy(${LIP}건)·상위 방화벽 등 장비 접근제어 여부 확인 (미통제 시 취약)"
    else
        result "ISS-021|수동확인|관리자 계정 설정 미탐지 — 관리 IP 제한(trusthost) 및 상위 접근제어 수동 확인"
    fi
}

# ISS-022: 보안장비 접속성공/실패 로깅 여부
check_applicable "ISS-022" "접속 로깅" && {
    evd "ISS-022" "echo \"\$TEXT\" | grep -i 'set log.*admin\|config log.*setting\|set admin-log\|set login-log' | head -10"
    LOG_ADMIN=$(echo "$TEXT" | grep -ci "log.*admin\|admin.*log\|event.*log\|set status enable" 2>/dev/null || true)
    result "ISS-022|수동확인|관리자 접속 성공/실패 로깅 설정 수동 확인 (로그 관련 설정 ${LOG_ADMIN}건)"
}

# ISS-023: 로그인 실패횟수 제한 설정 여부
check_applicable "ISS-023" "로그인 실패 제한" && {
    evd "ISS-023" "echo \"\$TEXT\" | grep -i 'admin-lockout-threshold\|admin-lockout-duration\|set lockout' | head -5"
    LOCKOUT=$(echo "$TEXT" | grep -i "set admin-lockout-threshold" 2>/dev/null | head -1 | grep -oE '[0-9]+' | head -1)
    if [ -n "$LOCKOUT" ] && [ "$LOCKOUT" -le 5 ] && [ "$LOCKOUT" -gt 0 ]; then
        result "ISS-023|양호|로그인 실패 잠금 임계값 ${LOCKOUT}회 설정 (5회 이내)"
    elif [ -n "$LOCKOUT" ] && [ "$LOCKOUT" -gt 5 ]; then
        result "ISS-023|취약|로그인 실패 잠금 임계값 ${LOCKOUT}회 — 5회 이내 설정 필요"
    elif [ -z "$LOCKOUT" ] && echo "$TEXT" | grep -q "^[[:space:]]*config system global"; then
        result "ISS-023|양호|admin-lockout-threshold 미표기 — FortiOS 기본값 3회 적용 (show 백업은 기본값 생략)"
    else
        result "ISS-023|수동확인|admin-lockout-threshold 설정 수동 확인"
    fi
}

# ISS-024: 세션 타임아웃 설정 여부
check_applicable "ISS-024" "세션 타임아웃" && {
    evd "ISS-024" "echo \"\$TEXT\" | grep -i 'set admintimeout\|set idle-timeout\|set auth-timeout' | head -5"
    TIMEOUT=$(echo "$TEXT" | grep -i "set admintimeout" 2>/dev/null | head -1 | grep -oE '[0-9]+' | head -1)
    if [ -n "$TIMEOUT" ] && [ "$TIMEOUT" -le 15 ] && [ "$TIMEOUT" -gt 0 ]; then
        result "ISS-024|양호|관리자 세션 타임아웃 ${TIMEOUT}분 설정"
    elif [ -n "$TIMEOUT" ] && [ "$TIMEOUT" -gt 15 ]; then
        result "ISS-024|취약|관리자 세션 타임아웃 ${TIMEOUT}분 — 15분 이하 설정 필요 (내부 규정이 더 짧으면 그 기준)"
    elif [ "$TIMEOUT" = "0" ]; then
        result "ISS-024|취약|관리자 세션 타임아웃 무제한(0) — 15분 이하 설정 필요 (내부 규정이 더 짧으면 그 기준)"
    elif [ -z "$TIMEOUT" ] && echo "$TEXT" | grep -q "^[[:space:]]*config system global"; then
        result "ISS-024|양호|admintimeout 미표기 — FortiOS 기본값 5분 적용 (show 백업은 기본값 생략)"
    else
        result "ISS-024|수동확인|admintimeout 설정 수동 확인"
    fi
}

# ISS-025: 시간 동기화를 위한 NTP 설정
check_applicable "ISS-025" "NTP 설정" && {
    evd "ISS-025" "echo \"\$TEXT\" | grep -i 'set ntpserver\|set ntpsync\|set type ntp\|config system ntp' | head -10"
    NTP_SYNC=$(echo "$TEXT" | grep -i "set ntpsync enable\|set type ntp" 2>/dev/null | head -1)
    if [ -n "$NTP_SYNC" ]; then
        result "ISS-025|양호|NTP 동기화 활성화됨"
    else
        result "ISS-025|취약|NTP 동기화 미설정 — 시간 동기화 필요"
    fi
}

# ISS-026: 주요 파일에 대한 주기적인 무결성 검사 여부
check_applicable "ISS-026" "무결성 검사" && {
    evd "ISS-026" "echo \"\$TEXT\" | grep -i 'file-integrity\|integrity\|checksum\|hash' | head -5"
    result "ISS-026|수동확인|주요 파일 무결성 검사 수행 여부 수동 확인 (기능 미지원 시 N-A)"
}

# ISS-027: 보안장비 기능외 서비스 제한 여부
check_applicable "ISS-027" "기능외 서비스 제한" && {
    evd "ISS-027" "echo \"\$TEXT\" | grep -i 'set allowaccess\|set service\|config system interface' | head -15"
    ALLOW=$(echo "$TEXT" | grep -i "set allowaccess" 2>/dev/null | head -5)
    result "ISS-027|수동확인|운영 목적 외 불필요 서비스 구동 여부 수동 확인"
}

# ISS-028: 보안장비 정책 변경통제 절차 수립 여부
check_applicable "ISS-028" "정책 변경통제 절차" && {
    evd "ISS-028" "echo '변경통제 절차 — 인터뷰 기반 점검 항목 (config 파일 기반 판단 불가)'"
    result "ISS-028|수동확인|정책 변경 시 내부 변경절차(신청서/작업계획서) 준수 여부 수동 확인"
}

# ISS-029: 보안장비 변경요청 정책의 기술적 검토 여부
check_applicable "ISS-029" "기술적 검토" && {
    evd "ISS-029" "echo '기술적 검토 — 인터뷰 기반 점검 항목 (config 파일 기반 판단 불가)'"
    result "ISS-029|수동확인|정책 변경 시 담당자 기술검토 후 적용 여부 수동 확인"
}

# ISS-030: 모든 목적지 및 서비스로의 허용 정책 금지 여부
check_applicable "ISS-030" "ANY/ALL 허용 금지" && {
    evd "ISS-030" "echo \"\$TEXT\" | grep -i 'set dstaddr \"all\"\|set service \"ALL\"\|set srcaddr \"all\"' | head -20"
    evd "ISS-030" "fg_policies | awk -F'\t' '{print \"policy \"\$1\": action=\"\$2\" status=\"\$3\" src=\"\$4\" dst=\"\$5\" svc=\"\$6}' | head -40"
    # 정책 단위: 활성 accept 정책 중 목적지 all + 서비스 ALL (deny 정리 정책·서비스 정의 제외)
    P_BOTH=$(fg_accept | awk -F'\t' '(" "$5" ") ~ / all / && (" "toupper($6)" ") ~ / ALL / {printf "%s ", $1}')
    P_DST=$(fg_accept | awk -F'\t' '(" "$5" ") ~ / all / {printf "%s ", $1}')
    P_SVC=$(fg_accept | awk -F'\t' '(" "toupper($6)" ") ~ / ALL / {printf "%s ", $1}')
    if [ -n "$P_BOTH" ]; then
        result "ISS-030|취약|목적지 all + 서비스 ALL 허용 정책: ${P_BOTH% }"
    elif [ -n "$P_DST" ] || [ -n "$P_SVC" ]; then
        result "ISS-030|수동확인|목적지 all 허용 정책(${P_DST:-없음}), 서비스 ALL 허용 정책(${P_SVC:-없음}) — 정당성 수동 확인"
    else
        result "ISS-030|양호|모든 목적지/서비스 허용(accept) 정책 없음 ($(fg_accept | wc -l | tr -d ' ')개 허용 정책 검사)"
    fi
}

# ISS-031: 취약한 서비스의 네트워크 대역 단위 허용 금지 여부
check_applicable "ISS-031" "취약 서비스 대역 허용" && {
    evd "ISS-031" "echo \"\$TEXT\" | grep -iE 'set (dst|src)addr.*subnet|set service.*(FTP|SSH|Telnet|RDP|MSSQL|MYSQL|ORACLE)' | head -15"
    result "ISS-031|수동확인|출발지/목적지 네트워크 대역 + 관리용/취약 포트 허용 정책 수동 확인"
}

# ISS-032: 서비스 포트 허용 정책 적정성
check_applicable "ISS-032" "서비스 포트 적정성" && {
    evd "ISS-032" "echo \"\$TEXT\" | grep -i 'set service \"ALL\"\|set service \"ALL_TCP\"\|set service \"ALL_UDP\"' | head -10"
    # 과도한 서비스: ALL/ALL_TCP/ALL_UDP 또는 포트 범위 1000개 이상 커스텀 서비스(예: 1024-65535)를 쓰는 활성 accept 정책
    WIDE=$(fg_services | awk -F'\t' '{ n=split($2, r, " "); for (i=1;i<=n;i++) { d=r[i]; sub(/:.*/, "", d); split(d, b, "-"); hi=(b[2]==""?b[1]:b[2]); if (hi-b[1]+1 >= 1000) { printf "%s|", $1; break } } }')
    RE="ALL|ALL_TCP|ALL_UDP"; [ -n "$WIDE" ] && RE="${RE}|${WIDE%|}"
    P_WIDE=$(fg_accept_with_svc "$RE")
    if [ -n "$P_WIDE" ]; then
        result "ISS-032|취약|과도한 서비스(ALL/ALL_TCP/ALL_UDP/광범위 포트${WIDE:+: ${WIDE%|}}) 허용 정책: ${P_WIDE% }"
    else
        result "ISS-032|수동확인|ALL/광범위 포트 허용 정책 없음 — 개별 서비스 포트 허용 적정성 수동 확인"
    fi
}

# ISS-033: 불필요한 양방향 정책 금지 여부
check_applicable "ISS-033" "양방향 정책 금지" && {
    evd "ISS-033" "echo \"\$TEXT\" | grep -i 'config firewall policy' -A50 | grep -i 'set srcaddr\|set dstaddr\|set service' | head -20"
    result "ISS-033|수동확인|불필요 양방향 정책 존재 여부 수동 확인 (관리용/DB 포트 21,22,23,3389,1521,1433,3306 등)"
}

# ISS-034: 정책 적용 순서의 적절성
check_applicable "ISS-034" "정책 적용 순서" && {
    evd "ISS-034" "echo \"\$TEXT\" | grep -i 'config firewall policy' -A5 | grep -i 'edit\|set action' | head -20"
    result "ISS-034|수동확인|정책 적용 순서 적절성 수동 확인 (Blacklist/차단 정책 상위 배치 여부)"
}

# ISS-035: 출발지 포트 기반의 정책 금지 여부
check_applicable "ISS-035" "출발지 포트 정책 금지" && {
    evd "ISS-035" "fg_services | grep ':'"
    # FortiOS 출발지 포트는 서비스 객체 portrange '<목적지>:<출발지>' 로 지정 → 해당 객체를 쓰는 활성 accept 정책
    SRCP=$(fg_services | awk -F'\t' '$2 ~ /:/ {printf "%s|", $1}')
    P_SRCP=""; [ -n "$SRCP" ] && P_SRCP=$(fg_accept_with_svc "${SRCP%|}")
    if [ -n "$P_SRCP" ]; then
        result "ISS-035|취약|출발지 포트 지정 서비스(${SRCP%|}) 사용 허용 정책: ${P_SRCP% }"
    elif [ -n "$SRCP" ]; then
        result "ISS-035|양호|출발지 포트 지정 서비스 객체(${SRCP%|})는 있으나 사용하는 허용 정책 없음"
    else
        result "ISS-035|양호|출발지 포트 기반 서비스/정책 없음"
    fi
}

# ISS-036: 취약한 원격 서비스 금지 여부
check_applicable "ISS-036" "취약 원격 서비스 금지" && {
    evd "ISS-036" "fg_accept | awk -F'\t' '{print \"policy \"\$1\": svc=\"\$6}' | grep -iE 'TFTP|RLOGIN|RSH|REXEC|FINGER'"
    # 기본 서비스 객체 정의(TFTP/RLOGIN 등)는 제외 — 활성 accept 정책의 set service 값만 비교
    P_WEAK=$(fg_accept_with_svc "TFTP|RLOGIN|RSH|REXEC|FINGER")
    if [ -n "$P_WEAK" ]; then
        result "ISS-036|취약|취약 원격 서비스(r-계열/TFTP/Finger) 허용 정책: ${P_WEAK% }"
    else
        result "ISS-036|양호|취약 원격 서비스 허용 정책 없음"
    fi
}

# ISS-037: 불필요한 정책 제거 여부
check_applicable "ISS-037" "불필요 정책 제거" && {
    evd "ISS-037" "echo \"\$TEXT\" | grep -i 'set status disable\|set logtraffic disable\|config firewall policy' | head -10"
    DISABLED=$(echo "$TEXT" | grep -c 'set status disable' 2>/dev/null || true)
    result "ISS-037|수동확인|비활성 정책 ${DISABLED}건 — 6개월 이상 미사용/불필요 정책 수동 확인 (히트카운트 기반)"
}

# ISS-038: 서버간 관리포트 허용 금지 여부
check_applicable "ISS-038" "서버간 관리포트 금지" && {
    evd "ISS-038" "echo \"\$TEXT\" | grep -iE 'set service.*(FTP|SSH|Telnet|RDP|MSSQL|MySQL|Oracle-DB)' | head -15"
    result "ISS-038|수동확인|서버 ↔ 서버 간 관리포트(21,22,23,3389,1433,1521,3306) 허용 정책 수동 확인"
}

# ISS-039: 단말과 서버간 접근통제를 우회한 접속 금지 여부
check_applicable "ISS-039" "접근통제 우회 금지" && {
    evd "ISS-039" "echo \"\$TEXT\" | grep -i 'config firewall policy' -A10 | grep -i 'set srcaddr\|set dstaddr' | head -15"
    result "ISS-039|수동확인|단말 → 서버 직접 접속(접근통제시스템 우회) 정책 존재 여부 수동 확인"
}

# ISS-040: 보안장비 비밀번호의 주기적인 변경 여부
check_applicable "ISS-040" "비밀번호 주기적 변경" && {
    evd "ISS-040" "echo \"\$TEXT\" | grep -i 'password-expire\|set password\|passwd-time\|passwd-policy' | head -10"
    PW_EXPIRE=$(echo "$TEXT" | grep -i "password-expire\|passwd-time" 2>/dev/null | head -1)
    result "ISS-040|수동확인|비밀번호 주기적 변경(분기별 1회 이상) 여부 수동 확인: ${PW_EXPIRE:-설정 미탐지}"
}

# ISS-041: 불필요한 네트워크 대역 단위 설정 금지 여부
check_applicable "ISS-041" "네트워크 대역 설정 금지" && {
    evd "ISS-041" "echo \"\$TEXT\" | grep -i 'set srcaddr \"all\"\|set dstaddr \"all\"\|subnet.*0.0.0.0\|/0\|255.255.0.0\|/16' | head -15"
    P_ANY=$(fg_accept | awk -F'\t' '(" "$4" "$5" ") ~ / all / {printf "%s ", $1}')
    if [ -n "$P_ANY" ]; then
        result "ISS-041|수동확인|출발지/목적지 all 허용 정책: ${P_ANY% } — 불필요 대역 적용 여부 수동 확인"
    else
        result "ISS-041|수동확인|출발지/목적지 all 허용 정책 없음 — 네트워크 대역(서브넷) 주소 객체 사용 정책 적정성 수동 확인"
    fi
}

# ISS-042: 차단 기능 활성화 여부
check_applicable "ISS-042" "차단 기능 활성화" && {
    evd "ISS-042" "echo \"\$TEXT\" | grep -i 'bypass\|set mode.*transparent\|set mode.*offline\|set action.*block\|set action.*deny' | head -10"
    BYPASS=$(echo "$TEXT" | grep -ci "bypass.*enable\|hw-bypass\|sw-bypass" 2>/dev/null || true)
    if [ "$BYPASS" -gt 0 ]; then
        result "ISS-042|취약|Bypass 모드 활성화 ${BYPASS}건 — 차단 기능 비활성 상태"
    else
        result "ISS-042|수동확인|차단 기능 활성화 및 최근 1개월 차단 로그 수동 확인"
    fi
}

# ISS-043: EoS 시스템 및 장비 교체 여부
check_applicable "ISS-043" "EoS 장비 교체" && {
    evd "ISS-043" "echo \"\$TEXT\" | grep -iE 'config-version=|#config-version|FortiOS|build[0-9]|set version' | head -5"
    FW_VER=$(echo "$TEXT" | grep -iE 'config-version=|#config-version|FortiOS|build[0-9]' 2>/dev/null | head -1)
    result "ISS-043|수동확인|펌웨어 버전: ${FW_VER:-미탐지} — 벤더사 Lifecycle 표 대조 필요"
}
}

# ================================================================
# Palo Alto 점검
# ================================================================
check_paloalto() {

# ISS-001: 보안장비 정책 및 로그 백업 설정 여부
check_applicable "ISS-001" "정책 및 로그 백업" && {
    evd "ISS-001" "echo \"\$TEXT\" | grep -i 'backup\|export\|log.*setting\|scheduled' | head -10"
    result "ISS-001|수동확인|정책/로그 백업 주기 및 절차 수동 확인 필요 (인터뷰 기반)"
}

# ISS-002: 원격 로그 서버 사용 여부
check_applicable "ISS-002" "원격 로그 서버" && {
    evd "ISS-002" "echo \"\$TEXT\" | grep -i 'syslog\|log-collector\|panorama\|log-forwarding\|server-profile' | head -15"
    SYSLOG=$(echo "$TEXT" | grep -ci "syslog\|log-collector" 2>/dev/null || true)
    PANORAMA=$(echo "$TEXT" | grep -ci "panorama" 2>/dev/null || true)
    if [ "$SYSLOG" -gt 0 ] || [ "$PANORAMA" -gt 0 ]; then
        result "ISS-002|양호|원격 로그서버 연동됨 (syslog: ${SYSLOG}, Panorama: ${PANORAMA})"
    else
        result "ISS-002|취약|원격 로그서버 미설정"
    fi
}

# ISS-003: DMZ 구간 설정 여부
check_applicable "ISS-003" "DMZ 구간 설정" && {
    evd "ISS-003" "echo \"\$TEXT\" | grep -i 'dmz\|zone\|<zone>' | head -10"
    DMZ=$(echo "$TEXT" | grep -ci "dmz" 2>/dev/null || true)
    ZONES=$(echo "$TEXT" | grep -ci "<zone>" 2>/dev/null || true)
    if [ "$DMZ" -gt 0 ]; then
        result "ISS-003|양호|DMZ 구간 설정 확인됨 (DMZ 키워드 ${DMZ}건)"
    else
        result "ISS-003|수동확인|DMZ 구간 설정 여부 수동 확인 (zone: ${ZONES}건)"
    fi
}

# ISS-004: NAT 정책 설정 적정성
check_applicable "ISS-004" "NAT 정책 적정성" && {
    evd "ISS-004" "echo \"\$TEXT\" | grep -i 'nat\|<source-translation>\|<destination-translation>' | head -15"
    NAT=$(echo "$TEXT" | grep -ci "nat\|source-translation\|destination-translation" 2>/dev/null || true)
    result "ISS-004|수동확인|NAT 설정 ${NAT}건 — 불필요 NAT 존재 여부 수동 확인"
}

# ISS-005: 주기적인 보안패치 및 벤더 권고사항 적용 여부
check_applicable "ISS-005" "보안패치 적용" && {
    evd "ISS-005" "echo \"\$TEXT\" | grep -i 'version\|sw-version\|PAN-OS\|app-version\|threat-version' | head -5"
    PA_VER=$(echo "$TEXT" | grep -i "sw-version\|PAN-OS" 2>/dev/null | head -1)
    result "ISS-005|수동확인|PAN-OS 버전: ${PA_VER:-미탐지} — 최신 패치 적용 여부 수동 확인"
}

# ISS-006: 보안장비 사용량의 주기적인 점검 및 보고 여부
check_applicable "ISS-006" "사용량 점검/보고" && {
    evd "ISS-006" "echo \"\$TEXT\" | grep -i 'snmp\|monitoring\|report' | head -10"
    result "ISS-006|수동확인|CPU/메모리 사용량 모니터링 및 주기적 보고 여부 수동 확인 (인터뷰 기반)"
}

# ISS-007: 보안장비 장애/보안이벤트 모니터링 실시 여부
check_applicable "ISS-007" "장애/이벤트 모니터링" && {
    evd "ISS-007" "echo \"\$TEXT\" | grep -i 'email-scheduler\|snmp-trap\|notification\|alert' | head -10"
    ALERT=$(echo "$TEXT" | grep -ci "alert\|notification\|snmp-trap\|email-scheduler" 2>/dev/null || true)
    result "ISS-007|수동확인|알림 설정 ${ALERT}건 — 이벤트 모니터링 체계 수동 확인"
}

# ISS-008: 탐지된 이벤트 및 로그에 대한 정기적 분석 및 보고 여부
check_applicable "ISS-008" "이벤트 분석/보고" && {
    evd "ISS-008" "echo \"\$TEXT\" | grep -i 'log-forwarding\|report\|analytics' | head -10"
    result "ISS-008|수동확인|보안이벤트 정기 분석/보고 여부 수동 확인 (보안관제보고서 확인)"
}

# ISS-009: RAW 패킷 저장 여부
check_applicable "ISS-009" "RAW 패킷 저장" && {
    evd "ISS-009" "echo \"\$TEXT\" | grep -i 'packet-capture\|pcap\|extended-capture\|threat-pcap' | head -10"
    PCAP=$(echo "$TEXT" | grep -ci "packet-capture\|pcap\|extended-capture" 2>/dev/null || true)
    result "ISS-009|수동확인|패킷 캡처 설정 ${PCAP}건 — RAW 패킷 저장 여부 수동 확인"
}

# ISS-010: TCP/UDP/ICMP 탐지/차단 패턴 적용 여부
check_applicable "ISS-010" "Flooding 탐지/차단" && {
    evd "ISS-010" "echo \"\$TEXT\" | grep -i 'flood\|zone-protection\|dos-protection\|icmp\|syn-cookies' | head -10"
    DOS=$(echo "$TEXT" | grep -ci "flood\|zone-protection\|dos-protection" 2>/dev/null || true)
    result "ISS-010|수동확인|DoS/Flooding 설정 ${DOS}건 — TCP/UDP/ICMP 탐지/차단 패턴 수동 확인"
}

# ISS-011: Port Scan 탐지/차단 패턴 적용 여부
check_applicable "ISS-011" "Port Scan 탐지/차단" && {
    evd "ISS-011" "echo \"\$TEXT\" | grep -i 'port.*scan\|reconnaissance\|zone-protection' | head -10"
    SCAN=$(echo "$TEXT" | grep -ci "port.*scan\|reconnaissance" 2>/dev/null || true)
    result "ISS-011|수동확인|Port Scan 탐지 설정 ${SCAN}건 — 차단 정책 수동 확인"
}

# ISS-012: 해킹 툴 탐지/차단 패턴 적용 여부
check_applicable "ISS-012" "해킹 툴 탐지/차단" && {
    evd "ISS-012" "echo \"\$TEXT\" | grep -i 'threat\|anti-spyware\|vulnerability\|antivirus\|wildfire' | head -10"
    THREAT=$(echo "$TEXT" | grep -ci "threat\|anti-spyware\|vulnerability\|antivirus\|wildfire" 2>/dev/null || true)
    result "ISS-012|수동확인|Threat/AV 설정 ${THREAT}건 — 해킹 툴 탐지/차단 패턴 수동 확인"
}

# ISS-013: Source Routing 차단
check_applicable "ISS-013" "Source Routing 차단" && {
    evd "ISS-013" "echo \"\$TEXT\" | grep -i 'source.*rout\|ip-option\|strict-ip' | head -10"
    result "ISS-013|수동확인|Source Routing 차단 설정 수동 확인"
}

# ISS-014: SNMP 비활성화
check_applicable "ISS-014" "SNMP 비활성화" && {
    evd "ISS-014" "echo \"\$TEXT\" | grep -i 'snmp\|community\|snmp-trap' | head -15"
    SNMP=$(echo "$TEXT" | grep -ci "snmp" 2>/dev/null || true)
    if [ "$SNMP" -eq 0 ]; then
        result "ISS-014|양호|SNMP 미사용 (설정 없음)"
    else
        result "ISS-014|수동확인|SNMP 설정 ${SNMP}건 — 사용 필요성 수동 확인"
    fi
}

# ISS-015: SNMP 안전 버전
check_applicable "ISS-015" "SNMP 안전 버전" && {
    evd "ISS-015" "echo \"\$TEXT\" | grep -i 'snmp.*v3\|snmp.*version\|community\|auth-profile' | head -10"
    SNMP=$(echo "$TEXT" | grep -ci "snmp" 2>/dev/null || true)
    if [ "$SNMP" -eq 0 ]; then
        result "ISS-015|양호|SNMP 미사용"
    else
        result "ISS-015|수동확인|SNMP 설정 ${SNMP}건 — SNMPv3 사용 및 보안 설정 수동 확인"
    fi
}

# ISS-016: 보안 접속
check_applicable "ISS-016" "보안 접속" && {
    evd "ISS-016" "echo \"\$TEXT\" | grep -i 'http[^s]\|telnet\|ssh\|https\|management-profile\|permitted-ip\|interface-management-profile' | head -15"
    # MGT 서비스 <disable-http>/<disable-telnet> no, 인터페이스 관리 프로파일 <http>/<telnet> yes → 평문 관리 접속 허용
    PLAIN=$(pa_tags | grep -iE '^<(disable-http|disable-telnet)>no$|^<(http|telnet)>yes$' | tr -d '<' | sort -u | tr '\n' ' ')
    if [ -n "$PLAIN" ]; then
        result "ISS-016|취약|평문 관리 프로토콜 허용 설정: ${PLAIN% } — HTTPS/SSH 전용 사용 필요"
    else
        result "ISS-016|양호|HTTP/Telnet 관리 접속 허용 설정 없음 (PAN-OS 기본 비활성)"
    fi
}

# ISS-017: Default 계정 변경
check_applicable "ISS-017" "Default 계정 변경" && {
    evd "ISS-017" "echo \"\$TEXT\" | grep -i 'admin\|user\|<entry name=' | head -15"
    ADMIN=$(echo "$TEXT" | grep -ci '<entry name=\"admin\">' 2>/dev/null || true)
    result "ISS-017|수동확인|관리자 계정 현황 수동 확인 — 기본 계정명 변경 여부 점검"
}

# ISS-018: Default 비밀번호 변경
check_applicable "ISS-018" "Default 비밀번호 변경" && {
    evd "ISS-018" "echo \"\$TEXT\" | grep -i 'password-complexity\|min-length\|min-uppercase\|phash' | head -10"
    PW=$(echo "$TEXT" | grep -ci "password-complexity\|min-length" 2>/dev/null || true)
    if [ "$PW" -gt 0 ]; then
        result "ISS-018|수동확인|비밀번호 복잡도 정책 설정됨 — 기본 비밀번호 변경 여부 수동 확인"
    else
        result "ISS-018|수동확인|비밀번호 복잡도 정책 수동 확인"
    fi
}

# ISS-019: 계정 관리 적정성
check_applicable "ISS-019" "계정 관리 적정성" && {
    evd "ISS-019" "echo \"\$TEXT\" | grep -i '<users>\|<entry name=\|<role>\|admin-role' | head -15"
    result "ISS-019|수동확인|관리자 계정 현황 — 개인별 계정 사용 및 공용 계정 여부 수동 확인"
}

# ISS-020: 계정별 권한 설정
check_applicable "ISS-020" "계정별 권한 설정" && {
    evd "ISS-020" "echo \"\$TEXT\" | grep -i 'admin-role\|role-based\|<role>\|superuser\|deviceadmin' | head -10"
    ROLE=$(echo "$TEXT" | grep -ci "admin-role\|role-based\|superuser\|deviceadmin" 2>/dev/null || true)
    result "ISS-020|수동확인|권한 설정 ${ROLE}건 — 계정별 최소권한 원칙 준수 수동 확인"
}

# ISS-021: 원격 관리 접근 통제
check_applicable "ISS-021" "원격 관리 접근 통제" && {
    evd "ISS-021" "echo \"\$TEXT\" | grep -i 'permitted-ip\|access-management\|management-only\|login-setting' | head -15"
    PERM_IP=$(pa_tags | awk '/<permitted-ip>/{p=1} p&&/<entry name=/{n++} /<\/permitted-ip>/{p=0} END{print n+0}')
    if [ "$PERM_IP" -gt 0 ]; then
        result "ISS-021|양호|관리 접근 IP 제한 설정됨 (permitted-ip ${PERM_IP}건)"
    else
        result "ISS-021|수동확인|permitted-ip 미설정 — 관리 인터페이스 망 분리·상위 방화벽 등 장비 접근제어 여부 확인 (미통제 시 취약)"
    fi
}

# ISS-022: 접속 로깅
check_applicable "ISS-022" "접속 로깅" && {
    evd "ISS-022" "echo \"\$TEXT\" | grep -i 'auth.*log\|system.*log\|login\|log-setting' | head -10"
    result "ISS-022|수동확인|관리자 접속 성공/실패 로깅 설정 수동 확인"
}

# ISS-023: 로그인 실패 제한
check_applicable "ISS-023" "로그인 실패 제한" && {
    evd "ISS-023" "echo \"\$TEXT\" | grep -i 'lockout\|failed-attempts\|login-setting' | head -10"
    LOCKOUT=$(echo "$TEXT" | grep -i "lockout\|failed-attempts" 2>/dev/null | head -1)
    result "ISS-023|수동확인|로그인 실패 잠금 수동 확인: ${LOCKOUT:-설정 미탐지}"
}

# ISS-024: 세션 타임아웃
check_applicable "ISS-024" "세션 타임아웃" && {
    evd "ISS-024" "echo \"\$TEXT\" | grep -i 'idle-timeout\|timeout\|login-setting' | head -10"
    TIMEOUT=$(echo "$TEXT" | grep -i "idle-timeout\|timeout" 2>/dev/null | grep -i "admin\|manage" | head -1)
    result "ISS-024|수동확인|세션 타임아웃 수동 확인: ${TIMEOUT:-설정 미탐지}"
}

# ISS-025: NTP 설정
check_applicable "ISS-025" "NTP 설정" && {
    evd "ISS-025" "echo \"\$TEXT\" | grep -i 'ntp\|ntp-server\|<ntp>' | head -10"
    NTP=$(echo "$TEXT" | grep -ci "ntp-server\|<ntp>" 2>/dev/null || true)
    if [ "$NTP" -gt 0 ]; then
        result "ISS-025|양호|NTP 설정됨 (${NTP}건)"
    else
        result "ISS-025|취약|NTP 미설정"
    fi
}

# ISS-026: 무결성 검사
check_applicable "ISS-026" "무결성 검사" && {
    evd "ISS-026" "echo \"\$TEXT\" | grep -i 'integrity\|file-hash\|wildfire' | head -5"
    result "ISS-026|수동확인|주요 파일 무결성 검사 여부 수동 확인 (기능 미지원 시 N-A)"
}

# ISS-027: 기능외 서비스 제한
check_applicable "ISS-027" "기능외 서비스 제한" && {
    evd "ISS-027" "echo \"\$TEXT\" | grep -i 'interface-management-profile\|http-server\|telnet\|dns-proxy' | head -10"
    result "ISS-027|수동확인|운영 목적 외 불필요 서비스 구동 여부 수동 확인"
}

# ISS-028~029: 절차 기반 (인터뷰)
check_applicable "ISS-028" "정책 변경통제 절차" && {
    evd "ISS-028" "echo '변경통제 절차 — 인터뷰 기반 점검 항목'"
    result "ISS-028|수동확인|정책 변경 시 내부 변경절차 준수 여부 수동 확인"
}
check_applicable "ISS-029" "기술적 검토" && {
    evd "ISS-029" "echo '기술적 검토 — 인터뷰 기반 점검 항목'"
    result "ISS-029|수동확인|정책 변경 시 담당자 기술검토 후 적용 여부 수동 확인"
}

# ISS-030: ANY/ALL 허용 금지
check_applicable "ISS-030" "ANY/ALL 허용 금지" && {
    evd "ISS-030" "echo \"\$TEXT\" | grep -i '<member>any</member>\|<application>.*any\|<service>.*any' | head -20"
    # security rule 단위: action allow + destination any + (service any 또는 application any)
    RULES=$(pa_tags | awk '
        /<security>/{s=1} /<\/security>/{s=0}
        s&&/<rules>/{r=1} s&&/<\/rules>/{r=0}
        in_e&&/^<entry[ >]/&&!/\/>$/{dep++}
        r&&/^<entry name=/&&!in_e{in_e=1; dep=0; nm=$0; sub(/^<entry name="/,"",nm); sub(/".*/,"",nm); sec=""; d=0; sv=0; ap=0; al=0; dis=0; next}
        in_e&&/^<(destination|service|application)>/{sec=$0; gsub(/[<>]/,"",sec)}
        in_e&&/^<\/(destination|service|application)>/{sec=""}
        in_e&&/^<member>any$/{ if(sec=="destination")d=1; if(sec=="service")sv=1; if(sec=="application")ap=1 }
        in_e&&/^<action>allow$/{al=1}
        in_e&&/^<disabled>yes$/{dis=1}
        in_e&&/^<\/entry>/{ if(dep>0){dep--; next} if(al&&!dis) printf "%s\t%d\t%d\t%d\n", nm, d, sv, ap; in_e=0 }')
    P_BOTH=$(echo "$RULES" | awk -F'\t' 'NF>1 && $2==1 && ($3==1 || $4==1){printf "%s ", $1}')
    P_ONE=$(echo "$RULES" | awk -F'\t' 'NF>1 && ($2==1 || $3==1){printf "%s ", $1}')
    if [ -n "$P_BOTH" ]; then
        result "ISS-030|취약|목적지 any + 서비스/애플리케이션 any 허용 규칙: ${P_BOTH% }"
    elif [ -n "$P_ONE" ]; then
        result "ISS-030|수동확인|목적지 또는 서비스 any 허용 규칙: ${P_ONE% } — 정당성 수동 확인"
    else
        result "ISS-030|양호|모든 목적지/서비스 허용(allow) 규칙 없음 ($(echo "$RULES" | awk 'NF' | wc -l | tr -d ' ')개 허용 규칙 검사)"
    fi
}

# ISS-031~039, 041: 정책 분석 (FW/VPN only)
check_applicable "ISS-031" "취약 서비스 대역 허용" && {
    evd "ISS-031" "echo \"\$TEXT\" | grep -i '<entry name=\|<source>\|<destination>\|<service>' | head -15"
    result "ISS-031|수동확인|취약 서비스 네트워크 대역 허용 정책 수동 확인"
}
check_applicable "ISS-032" "서비스 포트 적정성" && {
    evd "ISS-032" "echo \"\$TEXT\" | grep -i 'application-default\|<service>' | head -10"
    result "ISS-032|수동확인|과도한 서비스 포트 허용 정책 수동 확인"
}
check_applicable "ISS-033" "양방향 정책 금지" && {
    evd "ISS-033" "echo \"\$TEXT\" | grep -i '<entry name=\|<source>\|<destination>' | head -15"
    result "ISS-033|수동확인|불필요 양방향 정책 존재 여부 수동 확인"
}
check_applicable "ISS-034" "정책 적용 순서" && {
    evd "ISS-034" "echo \"\$TEXT\" | grep -i '<entry name=' | head -20"
    result "ISS-034|수동확인|정책 적용 순서 적절성 수동 확인"
}
check_applicable "ISS-035" "출발지 포트 정책 금지" && {
    evd "ISS-035" "echo \"\$TEXT\" | grep -i 'source-port\|src-port' | head -10"
    SRC_PORT=$(echo "$TEXT" | grep -ci "source-port\|src-port" 2>/dev/null || true)
    if [ "$SRC_PORT" -gt 0 ]; then
        result "ISS-035|취약|출발지 포트 기반 정책 ${SRC_PORT}건 발견"
    else
        result "ISS-035|양호|출발지 포트 기반 정책 없음"
    fi
}
check_applicable "ISS-036" "취약 원격 서비스 금지" && {
    evd "ISS-036" "echo \"\$TEXT\" | grep -iE 'tftp|rlogin|rsh|rexec|finger' | head -10"
    # 단어 단위 일치 (fingerprint 등 오탐 방지): 규칙의 application/service 멤버
    WEAK=$(pa_tags | grep -ciE "^<member>(tftp|rlogin|rsh|rexec|finger)(-.*)?$" 2>/dev/null || true)
    if [ "$WEAK" -gt 0 ]; then
        result "ISS-036|취약|취약 원격 서비스 허용 ${WEAK}건"
    else
        result "ISS-036|양호|취약 원격 서비스 허용 없음"
    fi
}
check_applicable "ISS-037" "불필요 정책 제거" && {
    evd "ISS-037" "echo \"\$TEXT\" | grep -i 'disabled.*yes\|<disabled>' | head -10"
    DISABLED=$(echo "$TEXT" | grep -ci "disabled.*yes\|<disabled>" 2>/dev/null || true)
    result "ISS-037|수동확인|비활성 정책 ${DISABLED}건 — 미사용/불필요 정책 수동 확인"
}
check_applicable "ISS-038" "서버간 관리포트 금지" && {
    evd "ISS-038" "echo \"\$TEXT\" | grep -iE 'ftp|ssh|telnet|rdp|mssql|mysql|oracle' | head -10"
    result "ISS-038|수동확인|서버 ↔ 서버 간 관리포트 허용 정책 수동 확인"
}
check_applicable "ISS-039" "접근통제 우회 금지" && {
    evd "ISS-039" "echo \"\$TEXT\" | grep -i '<source>\|<destination>' | head -15"
    result "ISS-039|수동확인|접근통제시스템 우회 접속 정책 수동 확인"
}

# ISS-040: 비밀번호 주기적 변경
check_applicable "ISS-040" "비밀번호 주기적 변경" && {
    evd "ISS-040" "echo \"\$TEXT\" | grep -i 'password-profile\|expiration\|password-change' | head -10"
    result "ISS-040|수동확인|비밀번호 주기적 변경(분기별 1회 이상) 여부 수동 확인"
}

# ISS-041: 네트워크 대역 설정 금지
check_applicable "ISS-041" "네트워크 대역 설정 금지" && {
    evd "ISS-041" "echo \"\$TEXT\" | grep -i '<member>any</member>\|0.0.0.0' | head -15"
    ANY=$(echo "$TEXT" | grep -c '<member>any</member>' 2>/dev/null || true)
    result "ISS-041|수동확인|any 멤버 ${ANY}건 — 불필요 네트워크 대역 설정 수동 확인"
}

# ISS-042: 차단 기능 활성화
check_applicable "ISS-042" "차단 기능 활성화" && {
    evd "ISS-042" "echo \"\$TEXT\" | grep -i 'tap\|virtual-wire\|bypass\|mode' | head -10"
    TAP=$(echo "$TEXT" | grep -ci "tap\|bypass" 2>/dev/null || true)
    if [ "$TAP" -gt 0 ]; then
        result "ISS-042|수동확인|TAP/Bypass 모드 ${TAP}건 — 차단 기능 활성 여부 수동 확인"
    else
        result "ISS-042|수동확인|차단 기능 활성 및 최근 차단 로그 수동 확인"
    fi
}

# ISS-043: EoS 장비 교체
check_applicable "ISS-043" "EoS 장비 교체" && {
    evd "ISS-043" "echo \"\$TEXT\" | grep -i 'sw-version\|PAN-OS\|model\|serial' | head -5"
    PA_VER=$(echo "$TEXT" | grep -i "sw-version\|PAN-OS" 2>/dev/null | head -1)
    result "ISS-043|수동확인|PAN-OS 버전: ${PA_VER:-미탐지} — 벤더사 Lifecycle 표 대조 필요"
}
}

# ================================================================
# 일반 (벤더 불문 공통 기본 점검)
# ================================================================
check_generic() {

check_applicable "ISS-001" "정책 및 로그 백업" && {
    evd "ISS-001" "echo \"\$TEXT\" | grep -i 'backup\|log.*server\|archive' | head -10"
    result "ISS-001|수동확인|정책/로그 백업 주기 및 절차 수동 확인 (벤더 미식별)"
}
check_applicable "ISS-002" "원격 로그 서버" && {
    evd "ISS-002" "echo \"\$TEXT\" | grep -i 'syslog\|log.*server\|remote.*log' | head -10"
    SYSLOG=$(echo "$TEXT" | grep -ci "syslog\|log.*server\|remote.*log" 2>/dev/null || true)
    if [ "$SYSLOG" -gt 0 ]; then
        result "ISS-002|수동확인|로그서버 관련 설정 ${SYSLOG}건 — 연동 상태 수동 확인"
    else
        result "ISS-002|수동확인|원격 로그서버 설정 수동 확인"
    fi
}
check_applicable "ISS-003" "DMZ 구간 설정" && {
    evd "ISS-003" "echo \"\$TEXT\" | grep -i 'dmz\|zone' | head -10"
    result "ISS-003|수동확인|DMZ 구간 설정 여부 수동 확인"
}
check_applicable "ISS-004" "NAT 정책 적정성" && {
    evd "ISS-004" "echo \"\$TEXT\" | grep -i 'nat\|static\|dynamic' | head -10"
    result "ISS-004|수동확인|NAT 정책 적정성 수동 확인"
}
check_applicable "ISS-005" "보안패치 적용" && {
    evd "ISS-005" "echo \"\$TEXT\" | grep -i 'version\|firmware\|build\|release' | head -5"
    result "ISS-005|수동확인|펌웨어/패치 현황 수동 확인"
}
check_applicable "ISS-006" "사용량 점검/보고" && {
    evd "ISS-006" "echo \"\$TEXT\" | grep -i 'monitor\|resource\|cpu\|memory' | head -5"
    result "ISS-006|수동확인|사용량 모니터링 및 보고 절차 수동 확인"
}
check_applicable "ISS-007" "장애/이벤트 모니터링" && {
    evd "ISS-007" "echo \"\$TEXT\" | grep -i 'alert\|notification\|trap\|alarm' | head -10"
    result "ISS-007|수동확인|장애/이벤트 모니터링 체계 수동 확인"
}
check_applicable "ISS-008" "이벤트 분석/보고" && {
    evd "ISS-008" "echo \"\$TEXT\" | grep -i 'report\|log.*analysis\|analytics' | head -5"
    result "ISS-008|수동확인|보안이벤트 정기 분석/보고 수동 확인"
}
check_applicable "ISS-009" "RAW 패킷 저장" && {
    evd "ISS-009" "echo \"\$TEXT\" | grep -i 'packet\|capture\|pcap' | head -5"
    result "ISS-009|수동확인|RAW 패킷 저장 설정 수동 확인"
}
check_applicable "ISS-010" "Flooding 탐지/차단" && {
    evd "ISS-010" "echo \"\$TEXT\" | grep -i 'flood\|dos\|rate.*limit\|threshold' | head -10"
    result "ISS-010|수동확인|TCP/UDP/ICMP Flooding 탐지/차단 패턴 수동 확인"
}
check_applicable "ISS-011" "Port Scan 탐지/차단" && {
    evd "ISS-011" "echo \"\$TEXT\" | grep -i 'scan\|reconnaissance\|probe' | head -5"
    result "ISS-011|수동확인|Port Scan 탐지/차단 패턴 수동 확인"
}
check_applicable "ISS-012" "해킹 툴 탐지/차단" && {
    evd "ISS-012" "echo \"\$TEXT\" | grep -i 'ips\|ids\|malware\|antivirus\|signature' | head -10"
    result "ISS-012|수동확인|해킹 툴/악성코드 탐지/차단 패턴 수동 확인"
}
check_applicable "ISS-013" "Source Routing 차단" && {
    evd "ISS-013" "echo \"\$TEXT\" | grep -i 'source.*rout\|ip.*option' | head -5"
    result "ISS-013|수동확인|Source Routing 차단 설정 수동 확인"
}
check_applicable "ISS-014" "SNMP 비활성화" && {
    evd "ISS-014" "echo \"\$TEXT\" | grep -i 'snmp' | head -10"
    SNMP=$(echo "$TEXT" | grep -ci "snmp" 2>/dev/null || true)
    result "ISS-014|수동확인|SNMP 설정 ${SNMP}건 — 사용 필요성 수동 확인"
}
check_applicable "ISS-015" "SNMP 안전 버전" && {
    evd "ISS-015" "echo \"\$TEXT\" | grep -i 'snmp.*v3\|snmp.*version\|community' | head -10"
    result "ISS-015|수동확인|SNMP 버전 및 community 설정 수동 확인 (v3/AuthPriv 권장)"
}
check_applicable "ISS-016" "보안 접속" && {
    evd "ISS-016" "echo \"\$TEXT\" | grep -i 'ssh\|https\|telnet\|http[^s]' | head -10"
    result "ISS-016|수동확인|보안 접속(SSH/HTTPS) 사용 여부 수동 확인"
}
check_applicable "ISS-017" "Default 계정 변경" && {
    evd "ISS-017" "echo \"\$TEXT\" | grep -i 'admin\|user\|account\|login' | head -10"
    result "ISS-017|수동확인|Default 계정 변경 여부 수동 확인"
}
check_applicable "ISS-018" "Default 비밀번호 변경" && {
    evd "ISS-018" "echo \"\$TEXT\" | grep -i 'password\|passwd\|secret' | head -10"
    result "ISS-018|수동확인|Default 비밀번호 변경 및 복잡도 수동 확인"
}
check_applicable "ISS-019" "계정 관리 적정성" && {
    evd "ISS-019" "echo \"\$TEXT\" | grep -i 'user\|admin\|account\|privilege' | head -10"
    result "ISS-019|수동확인|계정 관리(개인별 계정, 공용 계정 금지) 수동 확인"
}
check_applicable "ISS-020" "계정별 권한 설정" && {
    evd "ISS-020" "echo \"\$TEXT\" | grep -i 'privilege\|role\|level\|access' | head -10"
    result "ISS-020|수동확인|계정별 권한 설정 수동 확인"
}
check_applicable "ISS-021" "원격 관리 접근 통제" && {
    evd "ISS-021" "echo \"\$TEXT\" | grep -i 'access.*list\|acl\|permit\|trusted\|management' | head -10"
    result "ISS-021|수동확인|원격 관리 접근 IP 제한 수동 확인"
}
check_applicable "ISS-022" "접속 로깅" && {
    evd "ISS-022" "echo \"\$TEXT\" | grep -i 'log.*login\|auth.*log\|audit' | head -10"
    result "ISS-022|수동확인|접속 성공/실패 로깅 수동 확인"
}
check_applicable "ISS-023" "로그인 실패 제한" && {
    evd "ISS-023" "echo \"\$TEXT\" | grep -i 'lockout\|login.*fail\|attempts' | head -5"
    result "ISS-023|수동확인|로그인 실패 제한(5회 이내) 수동 확인"
}
check_applicable "ISS-024" "세션 타임아웃" && {
    evd "ISS-024" "echo \"\$TEXT\" | grep -i 'timeout\|idle\|session.*time' | head -10"
    result "ISS-024|수동확인|세션 타임아웃 설정 수동 확인"
}
check_applicable "ISS-025" "NTP 설정" && {
    evd "ISS-025" "echo \"\$TEXT\" | grep -i 'ntp\|clock\|time.*server' | head -10"
    result "ISS-025|수동확인|NTP 설정 수동 확인"
}
check_applicable "ISS-026" "무결성 검사" && {
    evd "ISS-026" "echo \"\$TEXT\" | grep -i 'integrity\|hash\|checksum' | head -5"
    result "ISS-026|수동확인|주요 파일 무결성 검사 수동 확인"
}
check_applicable "ISS-027" "기능외 서비스 제한" && {
    evd "ISS-027" "echo \"\$TEXT\" | grep -i 'service\|server\|enable' | head -10"
    result "ISS-027|수동확인|불필요 서비스 구동 여부 수동 확인"
}
check_applicable "ISS-028" "정책 변경통제 절차" && {
    evd "ISS-028" "echo '인터뷰 기반 점검 항목'"
    result "ISS-028|수동확인|정책 변경통제 절차 수립 여부 수동 확인"
}
check_applicable "ISS-029" "기술적 검토" && {
    evd "ISS-029" "echo '인터뷰 기반 점검 항목'"
    result "ISS-029|수동확인|정책 변경 기술적 검토 여부 수동 확인"
}
check_applicable "ISS-030" "ANY/ALL 허용 금지" && {
    evd "ISS-030" "echo \"\$TEXT\" | grep -i 'any\|all\|permit' | head -15"
    result "ISS-030|수동확인|ANY 목적지/ALL 서비스 허용 정책 수동 확인"
}
check_applicable "ISS-031" "취약 서비스 대역 허용" && {
    evd "ISS-031" "echo \"\$TEXT\" | grep -iE 'ftp|ssh|telnet|rdp|mssql|mysql|oracle' | head -10"
    result "ISS-031|수동확인|취약 서비스 네트워크 대역 허용 수동 확인"
}
check_applicable "ISS-032" "서비스 포트 적정성" && {
    evd "ISS-032" "echo \"\$TEXT\" | grep -i 'port\|service.*all\|1024.*65535' | head -10"
    result "ISS-032|수동확인|서비스 포트 허용 정책 적정성 수동 확인"
}
check_applicable "ISS-033" "양방향 정책 금지" && {
    evd "ISS-033" "echo \"\$TEXT\" | grep -i 'bidirect\|both\|inbound\|outbound' | head -10"
    result "ISS-033|수동확인|불필요 양방향 정책 수동 확인"
}
check_applicable "ISS-034" "정책 적용 순서" && {
    evd "ISS-034" "echo \"\$TEXT\" | grep -i 'rule\|policy\|seq\|priority' | head -10"
    result "ISS-034|수동확인|정책 적용 순서 적절성 수동 확인"
}
check_applicable "ISS-035" "출발지 포트 정책 금지" && {
    evd "ISS-035" "echo \"\$TEXT\" | grep -i 'source.*port\|src.*port' | head -5"
    result "ISS-035|수동확인|출발지 포트 기반 정책 수동 확인"
}
check_applicable "ISS-036" "취약 원격 서비스 금지" && {
    evd "ISS-036" "echo \"\$TEXT\" | grep -iE 'tftp|rlogin|rsh|rexec|finger|512|513|514' | head -5"
    result "ISS-036|수동확인|취약 원격 서비스(r-계열/TFTP) 허용 수동 확인"
}
check_applicable "ISS-037" "불필요 정책 제거" && {
    evd "ISS-037" "echo \"\$TEXT\" | grep -i 'disable\|inactive\|unused' | head -10"
    result "ISS-037|수동확인|미사용/불필요 정책 존재 수동 확인"
}
check_applicable "ISS-038" "서버간 관리포트 금지" && {
    evd "ISS-038" "echo \"\$TEXT\" | grep -iE 'ftp|ssh|telnet|rdp|mssql|mysql|oracle|3389|1433|1521|3306' | head -10"
    result "ISS-038|수동확인|서버간 관리포트 허용 수동 확인"
}
check_applicable "ISS-039" "접근통제 우회 금지" && {
    evd "ISS-039" "echo \"\$TEXT\" | grep -i 'policy\|rule\|permit\|source\|destination' | head -10"
    result "ISS-039|수동확인|접근통제 우회 접속 정책 수동 확인"
}
check_applicable "ISS-040" "비밀번호 주기적 변경" && {
    evd "ISS-040" "echo \"\$TEXT\" | grep -i 'password.*expire\|passwd.*age\|rotation' | head -5"
    result "ISS-040|수동확인|비밀번호 주기적 변경(분기별 1회 이상) 수동 확인"
}
check_applicable "ISS-041" "네트워크 대역 설정 금지" && {
    evd "ISS-041" "echo \"\$TEXT\" | grep -i 'any\|0.0.0.0\|subnet\|/0\|/8\|/16' | head -10"
    result "ISS-041|수동확인|불필요 네트워크 대역 설정 수동 확인"
}
check_applicable "ISS-042" "차단 기능 활성화" && {
    evd "ISS-042" "echo \"\$TEXT\" | grep -i 'bypass\|tap\|monitor\|inline\|block\|deny' | head -10"
    result "ISS-042|수동확인|차단 기능 활성화 및 차단 로그 수동 확인"
}
check_applicable "ISS-043" "EoS 장비 교체" && {
    evd "ISS-043" "echo \"\$TEXT\" | grep -i 'version\|firmware\|model\|serial\|build' | head -5"
    result "ISS-043|수동확인|장비 버전 EoS 대조 수동 확인"
}
}

# ── 메인 분기 ────────────────────────────────────────────────────
case "$VENDOR" in
    fortigate)  check_fortigate ;;
    paloalto)   check_paloalto ;;
    *)          check_generic ;;
esac

# ── 요약 ────────────────────────────────────────────────────────
_TOTAL=$((_CP + _CF + _CM + _CN))
echo "# ================================================================"
echo "# 점검 요약 — 전자금융기반시설 (ISS)"
echo "#   총 점검 항목: ${_TOTAL} / 43"
echo "#   장비유형: ${DEV_TYPE} / 벤더: ${VENDOR}"
[ "$_TOTAL" -gt 0 ] && {
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
