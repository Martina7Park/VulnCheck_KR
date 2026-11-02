#!/bin/bash
# ================================================================
# 보안장비(정보보호시스템) 취약점 점검 반자동 스크립트 v2.1
#
# 평가기준: 전자금융기반시설 보안 취약점 평가기준 제2026-1호
#           [정보보호시스템 장비] ISS-001 ~ ISS-043 (43항목)
#
# 지원 벤더: FortiGate, Palo Alto(XML / set 형식), 일반(generic)
# 지원 장비: FW(방화벽), VPN, IDS, IPS, DDoS, WAF
#
# [사용법]
#   bash check_security.sh <config_file.txt> [vendor] [device_type] [result_file]
#
#   vendor:      fortigate | paloalto | generic  (미지정 시 자동 탐지, 대소문자 무시)
#   device_type: FW | VPN | IDS | IPS | DDoS | WAF  (미지정 시 FW)
#   result_file: 표준출력을 저장할 결과 파일 경로(선택). 증적 파일명을 정하는 데만 쓰며,
#                '> 파일' 로 리다이렉트하면 스크립트가 그 파일을 알아내므로 보통 생략한다.
#
# [출력 형식]
#   표준출력: ISS-xxx|결과|근거설명   (결과: 양호 / 취약 / 수동확인 / 점검불가 / N-A)
#   증적파일: 결과 파일과 같은 폴더의 <결과파일명(확장자 제외)>_iss_evidence.txt
#             (결과 파일을 알 수 없으면 /tmp/<config파일명>_iss.txt 로 결과 사본을 만들고
#              /tmp/<config파일명>_iss_evidence.txt 에 증적 기록 — 컨버터가 결과 파일명 기준으로 탐색)
#   점검불가: config 에 해당 섹션이 없거나(부분 config) 형식을 해석하지 못해 점검 자체를 못 한 경우
# ================================================================

umask 077
# 로케일 고정: UTF-8 로케일에서 EUC-KR(CP949) 한글 주석·배너가 든 config 를 grep 하면 'binary file matches' 로 줄이 사라지므로 바이트 단위로 처리
export LC_ALL=C

if [ $# -lt 1 ]; then
    echo "사용법: bash check_security.sh <config_file.txt> [fortigate|paloalto|generic] [FW|VPN|IDS|IPS|DDoS|WAF] [result_file]"
    exit 1
fi

CONFIG="$1"
VENDOR=$(printf '%s' "${2:-auto}" | tr '[:upper:]' '[:lower:]')
DEV_TYPE="${3:-FW}"
RESULT_ARG="$4"
[ -z "$3" ] && echo "[경고] 장비유형 인자 미지정 → FW 로 점검합니다. IDS/IPS/DDoS/WAF/VPN 장비는 3번째 인자로 지정하세요 (평가대상 N-A 판정이 달라짐)" >&2

if [ ! -f "$CONFIG" ]; then
    echo "[ERROR] 파일 없음: $CONFIG" >&2
    exit 1
fi
if [ ! -s "$CONFIG" ]; then
    echo "[ERROR] 빈 파일: $CONFIG" >&2
    exit 1
fi

DEV_TYPE=$(echo "$DEV_TYPE" | tr '[:lower:]' '[:upper:]')
case "$DEV_TYPE" in
    FW|VPN|IDS|IPS|DDOS|WAF) ;;
    *) echo "[ERROR] 지원하지 않는 장비 유형: $DEV_TYPE (FW|VPN|IDS|IPS|DDoS|WAF)" >&2; exit 1 ;;
esac
case "$VENDOR" in
    auto|"") VENDOR=auto ;;
    fortigate|fortinet|forti|fgt|fg) VENDOR=fortigate ;;
    paloalto|palo|pan|panos|pa|paloaltonetworks) VENDOR=paloalto ;;
    generic) VENDOR=generic ;;
    *) echo "[경고] 알 수 없는 벤더 '$2' → generic 으로 점검합니다 (fortigate|paloalto|generic)" >&2; VENDOR=generic ;;
esac

# config 본문: UTF-16(Windows 리다이렉트 등)이면 UTF-8 로 변환, CR 제거 + BOM 제거
_bom=$(head -c 2 "$CONFIG" 2>/dev/null | od -An -tx1 | tr -d ' \n')
if [ "$_bom" = "fffe" ] || [ "$_bom" = "feff" ]; then
    TEXT=$( { iconv -f UTF-16 -t UTF-8 "$CONFIG" 2>/dev/null || tr -d '\000' < "$CONFIG"; } | tr -d '\r' | sed $'1s/^\xef\xbb\xbf//;1s/^\xff\xfe//;1s/^\xfe\xff//')
else
    TEXT=$(tr -d '\r' < "$CONFIG" | sed $'1s/^\xef\xbb\xbf//')
fi
CFG_FILE=$(basename "$CONFIG")
CFG_BASE=$(basename "$CONFIG" .txt)

# ── 결과 파일 경로 파악 (증적 파일명을 컨버터 규칙 <결과파일 basename>_iss_evidence.txt 에 맞추기 위함) ──
_RESULT_PATH=""
if [ -n "$RESULT_ARG" ]; then
    _RESULT_PATH="$RESULT_ARG"
else
    _fd1=$(readlink /proc/$$/fd/1 2>/dev/null)
    [ -z "$_fd1" ] && _fd1=$(lsof -a -p $$ -d 1 -Fn 2>/dev/null | sed -n 's/^n//p' | head -1)
    case "$_fd1" in /*) [ -f "$_fd1" ] && _RESULT_PATH="$_fd1" ;; esac
fi
_safe_new() { [ -L "$1" ] && rm -f "$1"; return 0; }   # 심볼릭 링크는 따라가지 않고 지운 뒤 새로 만든다
_RESF=""
if [ -n "$_RESULT_PATH" ]; then
    _RD=$(cd "$(dirname "$_RESULT_PATH")" 2>/dev/null && pwd); [ -z "$_RD" ] && _RD="."
    _RB=$(basename "$_RESULT_PATH"); _RB="${_RB%.*}"
    _EVD="${_RD}/${_RB}_iss_evidence.txt"
else
    # 결과 사본 자동 저장: '> 파일' 리다이렉트를 빠뜨려도 판정 결과가 증적과 같은 위치에 남도록 표준출력을 복사
    _RESF="/tmp/${CFG_BASE}_iss.txt"
    _EVD="/tmp/${CFG_BASE}_iss_evidence.txt"
    _safe_new "$_RESF"
    if [ -z "$NO_RESULT_COPY" ] && ( : > "$_RESF" ) 2>/dev/null; then
        exec > >(tee "$_RESF"); _TEEPID=$!
    else
        _RESF=""
    fi
fi
_safe_new "$_EVD"

# ── 비밀정보 마스킹본 (증적 전용): 해시는 알고리즘 접두만, community 는 앞 2자+*** ──
mask_text() {
    printf '%s\n' "$TEXT" | awk '
    function mv(v) { if (v ~ /^\$[0-9A-Za-z]+\$/) { p = v; sub(/^\$[0-9A-Za-z]+\$.*/, "", p); n = index(substr(v, 2), "$"); return substr(v, 1, n + 1) "***" } return "***" }
    function mc(v) { return (length(v) > 2) ? substr(v, 1, 2) "***" : "***" }
    BEGIN { KEYS = "^(password|passwd|phash|psksecret|secret|auth-pwd|priv-pwd|auth-password|priv-password|pre-shared-key|passphrase|bind-password|md5-key|sha-key|private-key|api-key|apikey|token|auth-key|enc-key|key)$" }
    {
        line = $0
        # FortiGate private-key 처럼 따옴표 값이 여러 줄에 걸친 경우: 본문 줄을 통째로 가림
        if (inkey) { if (index(line, "\"") > 0) inkey = 0; print "***"; next }
        # FortiGate / Palo Alto set 형식:  [set ]<key> [ENC] <value>
        if (match(line, /^[ \t]*(set[ \t]+)?[A-Za-z0-9-]+[ \t]+/)) {
            lead = substr(line, 1, RLENGTH); rest = substr(line, RLENGTH + 1)
            k = lead; sub(/^[ \t]*(set[ \t]+)?/, "", k); sub(/[ \t]+$/, "", k)
            if (k ~ KEYS) { if (rest ~ /^"/ && gsub(/"/, "&", rest) == 1) inkey = 1; n = split(rest, a, /[ \t]+/); if (a[1] == "ENC") print lead "ENC ***"; else print lead mv(a[1]); next }
            if (k == "snmp-community-string") { n = split(rest, a, /[ \t]+/); print lead mc(a[1]); next }
            if (k == "name" && incomm) { v = rest; gsub(/"/, "", v); print lead "\"" mc(v) "\""; next }
        }
        if (line ~ /^[ \t]*config system snmp community[ \t]*$/) incomm = 1
        else if (incomm && line ~ /^[ \t]*config /) incomm = 2
        else if (incomm && line ~ /^[ \t]*end[ \t]*$/) { if (incomm == 2) incomm = 1; else incomm = 0 }
        # Cisco 류: snmp-server community X / rocommunity X
        if (match(line, /(snmp-server community|rocommunity|rwcommunity)[ \t]+[^ \t]+/)) {
            seg = substr(line, RSTART, RLENGTH); n = split(seg, a, /[ \t]+/); pre = substr(line, 1, RSTART - 1); post = substr(line, RSTART + RLENGTH)
            sub(/[ \t]+[^ \t]+$/, "", seg); line = pre seg " " mc(a[n]) post
        }
        # Cisco 류: snmp-server host <주소> [traps|informs] [version 1|2c] <community> ... (version 3 은 community 가 아니라 사용자)
        if (match(line, /snmp-server host[ \t]+[^ \t]/)) {
            pre = substr(line, 1, RSTART + 15) " "; rest = substr(line, RSTART + 16); sub(/^[ \t]+/, "", rest); n = split(rest, a, /[ \t]+/)
            k = 2; if (a[k] == "traps" || a[k] == "informs") k++
            if (a[k] == "version") { ver = a[k + 1]; k += 2 } else ver = ""
            if (ver != "3" && a[k] != "" && a[k] !~ /^(udp-port|port)$/) { cm = a[k]; out = pre; for (q = 1; q < k; q++) out = out a[q] " "; for (q = k + 1; q <= n; q++) tail = tail " " a[q]; line = out mc(cm) tail; tail = "" }
        }
        # Cisco 류: snmp-server user ... auth <알고리즘> <키> priv <알고리즘> [비트] <키>
        out = ""; rest = line
        while (match(rest, /[ \t](auth|priv)[ \t]+(md5|sha|sha256|sha384|sha512|aes|des|3des)([ \t]+(128|192|256))?[ \t]+[^ \t]+/)) {
            seg = substr(rest, RSTART, RLENGTH); n = split(seg, a, /[ \t]+/)
            sub(/[ \t]+[^ \t]+$/, "", seg); out = out substr(rest, 1, RSTART - 1) seg " ***"
            rest = substr(rest, RSTART + RLENGTH)
        }
        line = out rest
        # Cisco 류: tacacs-server / radius-server / crypto isakmp ... key [유형 숫자] <키>
        if (line ~ /^[ \t]*(tacacs-server|radius-server|crypto isakmp|tacacs|radius)([ \t].*)?[ \t]key[ \t]/) {
            if (match(line, /[ \t]key[ \t]+([0-9][ \t]+)?[^ \t]+/)) {
                seg = substr(line, RSTART, RLENGTH); n = split(seg, a, /[ \t]+/)
                pre = substr(line, 1, RSTART - 1); post = substr(line, RSTART + RLENGTH)
                line = pre " key " ((n >= 4) ? a[3] " " : "") "***" post
            }
        }
        # Cisco 류: password|secret|passwd <유형 숫자> <값> → 유형은 남기고 값만 가림
        out = ""; rest = line
        while (match(rest, /(password|secret|passwd)[ \t]+[0-9][ \t]+[^ \t]+/)) {
            seg = substr(rest, RSTART, RLENGTH); n = split(seg, a, /[ \t]+/)
            out = out substr(rest, 1, RSTART - 1) a[1] " " a[2] " ***"
            rest = substr(rest, RSTART + RLENGTH)
        }
        line = out rest
        # Palo Alto set 형식: ... phash <값> / snmp-community-string <값> 등 줄 중간의 키-값
        out = ""; rest = line
        while (match(rest, /[ \t](phash|password|authpwd|privpwd|auth-password|priv-password|secret|pre-shared-key|passphrase|bind-password|private-key|snmp-community-string|community-string|community)[ \t]+[^ \t]+/)) {
            seg = substr(rest, RSTART, RLENGTH); n = split(seg, a, /[ \t]+/); k = a[2]; v = a[3]
            if (v ~ /^[0-9]$/ || v == "***") out = out substr(rest, 1, RSTART + RLENGTH - 1)   # Cisco 암호 유형 숫자·이미 가린 값은 그대로
            else out = out substr(rest, 1, RSTART) k " " ((k ~ /community/) ? mc(v) : mv(v))
            rest = substr(rest, RSTART + RLENGTH)
        }
        line = out rest
        if (line ~ /^[ \t]*(enable )?(password|secret)[ \t]+/) { sub(/(password|secret)[ \t]+.*/, "&", line); n = split(line, a, /[ \t]+/); line = substr(line, 1, index(line, a[n]) - 1) "***" }
        # XML 요소: <phash>..</phash> 등
        out = ""; rest = line
        while (match(rest, /<(phash|password|authpwd|privpwd|auth-password|priv-password|secret|pre-shared-key|passphrase|bind-password|private-key|key|snmp-community-string|community-string|community)>[^<]+</)) {
            seg = substr(rest, RSTART, RLENGTH); t = seg; sub(/^</, "", t); tag = t; sub(/>.*/, "", tag); val = t; sub(/^[^>]*>/, "", val); sub(/<\/?$/, "", val)
            newv = (tag ~ /community/) ? mc(val) : mv(val)
            out = out substr(rest, 1, RSTART - 1) "<" tag ">" newv "</"
            rest = substr(rest, RSTART + RLENGTH)
        }
        line = out rest
        print line
    }'
}
TEXT_M=$(mask_text)

# ── Palo Alto 형식 판별 / 정규화 (XML · set 모두 "탭으로 구분한 설정 경로" 한 줄 한 레코드로 변환) ──
PA_FMT="none"
pa_detect_fmt() {
    if printf '%s\n' "$TEXT" | grep -qE '^[[:space:]]*(set[[:space:]]+(deviceconfig|rulebase|network|shared|vsys|zone|mgt-config|device-group|service|address|template|profiles)[[:space:]]|set[[:space:]]+(pre-|post-)rulebase)'; then echo set
    elif printf '%s\n' "$TEXT" | grep -qE '<(config|devices|deviceconfig|rulebase|vsys|entry)[ >/]'; then echo xml
    else echo none; fi
}
# XML → 경로 레코드:  devices<TAB>localhost.localdomain<TAB>vsys<TAB>vsys1<TAB>rulebase<TAB>security<TAB>rules<TAB>r1<TAB>action<TAB>allow
pa_flat_xml() {
    tr -d '\r\n' | sed 's/</\n</g' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | awk '
    function path(   i, s) { s = ""; for (i = 1; i <= n; i++) if (tk[i] != "") s = s (s == "" ? "" : "\t") tk[i]; return s }
    function emit(p, v) { if (v != "") print p "\t" v; else if (p != "") print p }
    /^$/ { next }
    /^<\?|^<!/ { next }
    /^<\// { if (n > 0) { if (!kids[n] && !hastext[n]) emit(path(), ""); n-- } next }
    /^</ {
        line = $0; selfc = (line ~ /\/>[ \t]*$/)
        t = line; sub(/^</, "", t); tag = t; sub(/[ \t\/>].*/, "", tag)
        nm = ""; if (match(line, /name="[^"]*"/)) { nm = substr(line, RSTART + 6, RLENGTH - 7) }
        txt = line; sub(/^<[^>]*>/, "", txt); if (selfc) txt = ""
        gsub(/&lt;/, "<", txt); gsub(/&gt;/, ">", txt); gsub(/&amp;/, "\\&", txt); gsub(/&quot;/, "\"", txt)
        if (tag == "config" || tag == "devices") { if (!selfc) { n++; tk[n] = ""; kids[n] = 0; hastext[n] = 0 } next }
        if (tag == "member") { if (n > 0) kids[n]++; emit(path(), txt); if (!selfc) { n++; tk[n] = ""; kids[n] = 0; hastext[n] = 1 } next }
        if (n > 0) kids[n]++
        tok = (tag == "entry" && nm != "") ? nm : tag
        if (selfc) { n++; tk[n] = tok; emit(path(), ""); n--; next }
        n++; tk[n] = tok; kids[n] = 0; hastext[n] = 0
        if (txt != "") { hastext[n] = 1; emit(path(), txt) }
    }'
}
# set 형식 → 경로 레코드 ('set ' 제거, [ a b ] 목록은 값마다 한 줄, 따옴표 토큰 보존)
pa_flat_set() {
    awk '
    {
        line = $0; sub(/^[ \t]*/, "", line)
        if (line !~ /^set[ \t]+/) next
        sub(/^set[ \t]+/, "", line)
        nt = 0; inlist = 0; nl = 0
        while (length(line) > 0) {
            sub(/^[ \t]+/, "", line)
            if (line == "") break
            if (substr(line, 1, 1) == "\"") { rest = substr(line, 2); p = index(rest, "\""); if (p == 0) { tokv = rest; line = "" } else { tokv = substr(rest, 1, p - 1); line = substr(rest, p + 1) } }
            else { match(line, /^[^ \t]+/); tokv = substr(line, 1, RLENGTH); line = substr(line, RLENGTH + 1) }
            if (tokv == "[" ) { inlist = 1; continue }
            if (tokv == "]") { inlist = 0; continue }
            if (inlist) { nl++; lst[nl] = tokv } else { nt++; t[nt] = tokv }
        }
        base = ""; for (i = 1; i <= nt; i++) base = base (i > 1 ? "\t" : "") t[i]
        if (nl > 0) { for (j = 1; j <= nl; j++) print base "\t" lst[j] } else print base
    }'
}
if [ "$VENDOR" = "paloalto" ] || [ "$VENDOR" = "auto" ]; then
    PA_FMT=$(pa_detect_fmt)
fi
PA_FLAT=""; PA_FLAT_M=""
pa_build_flat() {
    if [ "$PA_FMT" = "xml" ]; then PA_FLAT=$(printf '%s\n' "$TEXT" | pa_flat_xml); PA_FLAT_M=$(printf '%s\n' "$TEXT_M" | pa_flat_xml)
    elif [ "$PA_FMT" = "set" ]; then PA_FLAT=$(printf '%s\n' "$TEXT" | pa_flat_set); PA_FLAT_M=$(printf '%s\n' "$TEXT_M" | pa_flat_set); fi
}
pa_build_flat

# ── 벤더 자동 탐지 (제품 고유 구문 점수 비교 — 본문에 'fortigate' 단어가 있다고 FortiGate 로 보지 않음) ──
detect_vendor() {
    local fs ps
    fs=$(printf '%s\n' "$TEXT" | grep -cE '^[[:space:]]*#config-version=FG|^[[:space:]]*config system global[[:space:]]*$|^[[:space:]]*config firewall policy[[:space:]]*$|^[[:space:]]*config system interface[[:space:]]*$|^[[:space:]]*config firewall address[[:space:]]*$|^[[:space:]]*config system admin[[:space:]]*$')
    ps=$(printf '%s\n' "$TEXT" | grep -cE '<deviceconfig>|<rulebase>|<devices>|<entry name="localhost\.localdomain"|<config version=|^[[:space:]]*set[[:space:]]+(deviceconfig|rulebase|mgt-config|vsys|device-group|zone|(pre-|post-)rulebase)[[:space:]]')
    if [ "${fs:-0}" -gt 0 ] && [ "${ps:-0}" -eq 0 ]; then echo fortigate
    elif [ "${ps:-0}" -gt 0 ] && [ "${fs:-0}" -eq 0 ]; then echo paloalto
    elif [ "${fs:-0}" -gt "${ps:-0}" ]; then echo fortigate
    elif [ "${ps:-0}" -gt "${fs:-0}" ]; then echo paloalto
    else echo generic; fi
}

if [ "$VENDOR" = "auto" ]; then
    VENDOR=$(detect_vendor)
    [ "$VENDOR" = "paloalto" ] && [ "$PA_FMT" = "none" ] && PA_FMT=$(pa_detect_fmt)
fi
[ "$VENDOR" = "paloalto" ] && [ -z "$PA_FLAT" ] && { PA_FMT=$(pa_detect_fmt); pa_build_flat; }

# ── config 의 관리 IP (헤더 '# IP:') ──
mgmt_ips() {
    local ips=""
    case "$VENDOR" in
    fortigate)
        ips=$(printf '%s\n' "$TEXT" | awk '
            /^[ \t]*config system interface[ \t]*$/ { ins = 1; next }
            !ins { next }
            /^[ \t]*end[ \t]*$/ { if (nest > 0) { nest--; next } if (ip != "") { all = all " " ip; if (aa) adm = adm " " ip } ins = 0; next }
            /^[ \t]*config / { nest++; next }
            nest > 0 { next }
            /^[ \t]*edit / { if (ip != "") { all = all " " ip; if (aa) adm = adm " " ip } ip = ""; aa = 0; next }
            /^[ \t]*set ip [0-9]/ { if ($3 != "0.0.0.0") ip = $3 }
            /^[ \t]*set allowaccess / { if ($0 ~ /ssh|https|http|telnet|snmp/) aa = 1 }
            END { r = (adm != "") ? adm : all; print r }')
        ;;
    paloalto)
        ips=$(printf '%s\n' "$PA_FLAT" | awk -F'\t' '{ for (i = 1; i < NF; i++) if ($i == "deviceconfig" && $(i+1) == "system" && $(i+2) == "ip-address") print $(i+3) }' | sort -u | tr '\n' ' ')
        ;;
    *)
        ips=$(printf '%s\n' "$TEXT" | grep -iE 'mgmt|management|manage' | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | grep -v '^0\.0\.0\.0$' | sort -u | tr '\n' ' ')
        ;;
    esac
    ips=$(printf '%s' "$ips" | tr ' ' '\n' | awk 'NF && !seen[$0]++' | tr '\n' ',' | sed 's/,/, /g;s/, $//')
    echo "${ips:-미확인}"
}

# ── 배너 ────────────────────────────────────────────────────────
echo "# ============================================================"
echo "# 보안장비 취약점 점검 결과"
echo "# 점검 기준: 전자금융기반시설 보안 취약점 평가기준 제2026-1호"
echo "#            [정보보호시스템 장비] ISS-001 ~ ISS-043"
echo "# 벤더: $VENDOR$([ "$VENDOR" = "paloalto" ] && echo " (config 형식: $PA_FMT)")"
echo "# 장비유형: $DEV_TYPE$([ -z "$3" ] && echo " (기본값 - 장비유형 인자 미지정)")"
echo "# 파일: ${CFG_FILE}"
echo "# IP: $(mgmt_ips)"
echo "# 점검일: $(date '+%Y-%m-%d %H:%M:%S')"
echo "#"

# ── 결과 카운터 / 증적 파일 ────────────────────────────────────
_CP=0; _CF=0; _CM=0; _CN=0; _CU=0
echo "# ================================================================" > "$_EVD"
echo "# 증적 파일 (감사 추적용)" >> "$_EVD"
echo "# 대상: ${CFG_FILE} / 벤더: $VENDOR / 유형: $DEV_TYPE" >> "$_EVD"
echo "# 생성: $(date '+%Y-%m-%d %H:%M:%S')" >> "$_EVD"
echo "# 비밀번호 해시·SNMP community 는 마스킹됨(해시=알고리즘 접두만, community=앞 2자+***)" >> "$_EVD"
echo "# ================================================================" >> "$_EVD"

iss_name() {
    case "$1" in
        ISS-001) echo '보안장비 정책 및 로그 백업 설정 여부' ;;
        ISS-002) echo '원격 로그 서버 사용 여부' ;;
        ISS-003) echo 'DMZ 구간 설정 여부' ;;
        ISS-004) echo 'NAT 정책 설정 적정성' ;;
        ISS-005) echo '주기적인 보안패치 및 벤더 권고사항 적용 여부' ;;
        ISS-006) echo '보안장비 사용량의 주기적인 점검 및 보고 여부' ;;
        ISS-007) echo '보안장비 장애/보안이벤트 모니터링 실시 여부' ;;
        ISS-008) echo '탐지된 이벤트 및 로그에 대한 정기적 분석 및 보고 여부' ;;
        ISS-009) echo '위험도가 높은 이벤트 및 로그에 대한 RAW 패킷 저장 여부' ;;
        ISS-010) echo 'TCP/UDP/ICMP 탐지/차단 패턴 적용 여부' ;;
        ISS-011) echo 'Port Scan 탐지/차단 패턴 적용 여부' ;;
        ISS-012) echo '해킹 툴 탐지/차단 패턴 적용 여부' ;;
        ISS-013) echo '불필요한 Source Routing 차단 설정 여부' ;;
        ISS-014) echo '사용하지 않는 SNMP 비활성화 여부' ;;
        ISS-015) echo '안전한 네트워크 모니터링 서비스 사용 여부' ;;
        ISS-016) echo '보안장비 접속 시 보안 접속 사용 여부' ;;
        ISS-017) echo '보안장비 Default 계정 변경 여부' ;;
        ISS-018) echo '보안장비 Default 비밀번호 변경 여부' ;;
        ISS-019) echo '보안장비 계정 관리 적정성' ;;
        ISS-020) echo '보안장비 계정별 권한 설정 여부' ;;
        ISS-021) echo '보안장비 원격 관리 접근 통제 여부' ;;
        ISS-022) echo '보안장비 접속성공/실패 로깅 여부' ;;
        ISS-023) echo '로그인 실패횟수 제한 설정 여부' ;;
        ISS-024) echo '세션 타임아웃 설정 여부' ;;
        ISS-025) echo '시간 동기화를 위한 NTP 설정' ;;
        ISS-026) echo '주요 파일에 대한 주기적인 무결성 검사 여부' ;;
        ISS-027) echo '보안장비 기능외 서비스 제한 여부' ;;
        ISS-028) echo '보안장비 정책 변경통제 절차 수립 여부' ;;
        ISS-029) echo '보안장비 변경요청 정책의 기술적 검토 여부' ;;
        ISS-030) echo '모든 목적지 및 서비스로의 허용 정책 금지 여부' ;;
        ISS-031) echo '취약한 서비스의 네트워크 대역 단위 허용 금지 여부' ;;
        ISS-032) echo '서비스 포트 허용 정책 적정성' ;;
        ISS-033) echo '불필요한 양방향 정책 금지 여부' ;;
        ISS-034) echo '정책 적용 순서의 적절성' ;;
        ISS-035) echo '출발지 포트 기반의 정책 금지 여부' ;;
        ISS-036) echo '취약한 원격 서비스 금지 여부' ;;
        ISS-037) echo '불필요한 정책 제거 여부' ;;
        ISS-038) echo '서버간 관리포트 허용 금지 여부' ;;
        ISS-039) echo '단말과 서버간 접근통제를 우회한 접속 금지 여부' ;;
        ISS-040) echo '보안장비 비밀번호의 주기적인 변경 여부' ;;
        ISS-041) echo '불필요한 네트워크 대역 단위 설정 금지 여부' ;;
        ISS-042) echo '차단 기능 활성화 여부' ;;
        ISS-043) echo '서비스 지원이 종료된(EoS) 시스템 및 장비 교체 여부' ;;
        *) echo '' ;;
    esac
}

result() {
    echo "$1"
    local _r="${1#*|}"; _r="${_r%%|*}"
    case "$_r" in
    양호)     _CP=$((_CP+1)) ;;
    취약)     _CF=$((_CF+1)) ;;
    수동확인) _CM=$((_CM+1)) ;;
    점검불가) _CU=$((_CU+1)) ;;
    N-A)      _CN=$((_CN+1)) ;;
    esac
    local _code="${1%%|*}" _rest="${1#*|}"
    local _nm; _nm=$(iss_name "$_code")
    if [ -n "$_nm" ]; then
        printf '[판정] %s (%s)|%s\n\n' "$_code" "$_nm" "$_rest" >> "$_EVD"
    else
        printf '[판정] %s\n\n' "$1" >> "$_EVD"
    fi
    return 0   # 증적 쓰기 실패가 `조건 && result A || result B` 에서 B 중복 출력을 일으키지 않도록
}
# evd <항목> <명령>: 명령을 실행해 출력 전체를 증적에 기록 (2000줄 초과분만 생략 표시, 출력이 없으면 그 사실을 기록)
evd() {
    local item="$1"; shift
    printf '[%s] %s $ %s\n' "$item" "$(date '+%H:%M:%S')" "$*" >> "$_EVD"
    local _o _n
    _o=$(eval "$@" 2>&1)
    if [ -z "$_o" ]; then
        printf '(해당 줄 없음 - 출력 없음)\n' >> "$_EVD"
    else
        _n=$(printf '%s\n' "$_o" | wc -l | tr -d ' ')
        if [ "$_n" -gt 2000 ]; then
            printf '%s\n' "$_o" | awk 'NR<=2000' >> "$_EVD"
            printf '(이하 %s줄 생략)\n' "$((_n-2000))" >> "$_EVD"
        else
            printf '%s\n' "$_o" >> "$_EVD"
        fi
    fi
    printf '\n' >> "$_EVD"
}
# kw <항목> <ERE>: config(마스킹본)에서 패턴 줄을 증적에 전부 기록하고, 같은 패턴의 건수를 KW_N 에 담는다 (증적=판정 일치)
kw() {
    evd "$1" "echo \"\$TEXT_M\" | grep -iE -- '$2'"
    KW_N=$(printf '%s\n' "$TEXT" | grep -ciE -- "$2"); KW_N=${KW_N:-0}
}
# paf <항목> <ERE>: Palo Alto 정규화 레코드(경로를 공백으로 표시)에서 패턴 줄을 기록, 건수를 PAF_N 에 담는다
paf() {
    evd "$1" "echo \"\$PA_FLAT_M\" | tr '\\t' ' ' | grep -iE -- '$2'"
    PAF_N=$(printf '%s\n' "$PA_FLAT" | tr '\t' ' ' | grep -ciE -- "$2"); PAF_N=${PAF_N:-0}
}
# has_sec <'config ...'>: FortiGate config 에 해당 섹션 줄이 있는지
has_sec() { printf '%s\n' "$TEXT" | grep -qE "^[[:space:]]*$1[[:space:]]*\$"; }

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
# fg_policies: config firewall policy / policy6 / policy46·64 / security-policy / proxy-policy 의 edit 단위 → "id<TAB>action<TAB>status<TAB>srcaddr<TAB>dstaddr<TAB>service<TAB>srcintf<TAB>dstintf<TAB>service(서비스 그룹 전개)"
#   (FortiOS 기본값: action=deny, status=enable — show 백업에는 기본값 줄이 생략됨. IPv6 정책 id 는 v6/<번호>, 그 밖은 v46/ v64/ sec/ proxy/ 접두)
fg_policies() {
    { fg_svcgroups | awk '{ print "@@GRP@@\t" $0 }'; printf '%s\n' "$TEXT" | tr -d '\r'; } | awk '
        function flush(   i, e, k, x, xn, q) {
            if (id == "") return
            e = svc
            # 서비스 그룹 멤버를 최대 4단계까지 펼침
            for (k = 0; k < 4; k++) { q = ""; xn = split(e, x, " "); for (i = 1; i <= xn; i++) if (x[i] in grp) q = q " " grp[x[i]]; if (q == "") break; e = e q }
            printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", id, act, st, src, dst, svc, si, di, e; id=""
        }
        function val(l) { sub(/^[ \t]*set [^ ]+[ \t]*/, "", l); gsub(/"/, "", l); return l }
        /^@@GRP@@\t/ { split($0, gf, "\t"); grp[gf[2]] = gf[3]; next }
        /^[ \t]*config firewall (policy|policy6|policy46|policy64|security-policy|proxy-policy)[ \t]*$/ {
            inp=1; nest=0; pre = ""; t = $3
            if (t == "policy6") pre = "v6/"; else if (t == "policy46") pre = "v46/"; else if (t == "policy64") pre = "v64/"; else if (t == "security-policy") pre = "sec/"; else if (t == "proxy-policy") pre = "proxy/"
            next }
        !inp { next }
        /^[ \t]*config / { nest++; next }
        /^[ \t]*end[ \t]*$/ { if (nest > 0) { nest--; next } flush(); inp=0; next }
        nest > 0 { next }
        /^[ \t]*edit / { flush(); id=$2; gsub(/"/, "", id); id = pre id; act="deny"; st="enable"; src=""; dst=""; svc=""; si=""; di=""; next }
        /^[ \t]*next[ \t]*$/ { flush(); next }
        /^[ \t]*set action / { act=val($0) }
        /^[ \t]*set status / { st=val($0) }
        /^[ \t]*set srcaddr / { src=val($0) }
        /^[ \t]*set dstaddr / { dst=val($0) }
        /^[ \t]*set service / { svc=val($0) }
        /^[ \t]*set srcintf / { si=val($0) }
        /^[ \t]*set dstintf / { di=val($0) }'
}
# fg_svcgroups: config firewall service group → "그룹명<TAB>멤버들(공백 구분)"
fg_svcgroups() {
    printf '%s\n' "$TEXT" | tr -d '\r' | awk '
        /^[ \t]*config firewall service group[ \t]*$/ { ins=1; next }
        !ins { next }
        /^[ \t]*end[ \t]*$/ { if (n != "") print n "\t" m; ins=0; n=""; next }
        /^[ \t]*edit / { if (n != "") print n "\t" m; n=$0; sub(/^[ \t]*edit[ \t]*/, "", n); gsub(/"/, "", n); m=""; next }
        /^[ \t]*set member / { l=$0; sub(/^[ \t]*set member[ \t]*/, "", l); gsub(/"/, "", l); m=m " " l }'
}
# fg_accept: 활성(accept·ipsec·ssl-vpn, status enable) 정책만
fg_accept() { fg_policies | awk -F'\t' '($2=="accept" || $2=="ipsec" || $2=="ssl-vpn") && $3!="disable"'; }
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
    fg_accept | awk -F'\t' -v re="^($1)$" '{ n=split($9, a, " "); for (i=1;i<=n;i++) if (toupper(a[i]) ~ toupper(re)) { printf "%s ", $1; break } }'
}
# fg_block <'config ...'>: 섹션 본문(중첩 config 포함) 줄 그대로 출력
fg_block() {
    printf '%s\n' "$TEXT" | awk -v hdr="$1" '
        $0 ~ "^[ \t]*" hdr "[ \t]*$" { ins=1; nest=0; print; next }
        !ins { next }
        /^[ \t]*config / { nest++ }
        { print }
        /^[ \t]*end[ \t]*$/ { if (nest > 0) nest--; else ins=0 }'
}
# 복잡도: 2종 10자 이상 또는 3종 8자 이상 (영문/숫자/특수문자)
str_complex() {
    local s="$1" c=0
    echo "$s" | grep -q '[A-Za-z]' && c=$((c+1))
    echo "$s" | grep -q '[0-9]' && c=$((c+1))
    echo "$s" | grep -q '[^A-Za-z0-9]' && c=$((c+1))
    { [ "$c" -ge 2 ] && [ "${#s}" -ge 10 ]; } || { [ "$c" -ge 3 ] && [ "${#s}" -ge 8 ]; }
}
mask_str() { local s="$1"; [ "${#s}" -gt 2 ] && printf '%s***' "${s:0:2}" || printf '***'; }

# ── Palo Alto 보안 규칙 추출 (XML·set 공통) ───────────────────────
# pa_rules: "이름<TAB>action<TAB>disabled<TAB>from<TAB>to<TAB>source<TAB>destination<TAB>application<TAB>service" (멤버는 공백 연결, 소문자 비교용 원문 유지)
pa_rules() {
    printf '%s\n' "$PA_FLAT" | awk -F'\t' '
    {
        for (i = 1; i + 3 <= NF; i++) if ($i ~ /rulebase$/ && $(i+1) == "security" && $(i+2) == "rules") {
            sc = ""; for (j = 1; j < i; j++) sc = sc $j "/"
            nm = $(i+3); key = sc nm
            if (!(key in seen)) { seen[key] = 1; order[++cnt] = key; disp[key] = nm; act[key] = "allow"; dis[key] = "no" }
            if (i + 5 <= NF) {
                f = $(i+4); v = $(i+5)
                if (f == "action") act[key] = v
                else if (f == "disabled") dis[key] = v
                else if (f == "from") fr[key] = fr[key] " " v
                else if (f == "to") to[key] = to[key] " " v
                else if (f == "source") so[key] = so[key] " " v
                else if (f == "destination") de[key] = de[key] " " v
                else if (f == "application") ap[key] = ap[key] " " v
                else if (f == "service") sv[key] = sv[key] " " v
            }
            break
        }
    }
    END { for (k = 1; k <= cnt; k++) { key = order[k]; printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", disp[key], act[key], dis[key], fr[key], to[key], so[key], de[key], ap[key], sv[key] } }'
}
PA_RULES=""
[ "$VENDOR" = "paloalto" ] && PA_RULES=$(pa_rules)
# 활성 allow 규칙만
pa_allow() { printf '%s\n' "$PA_RULES" | awk -F'\t' 'NF>1 && $2=="allow" && $3!="yes"'; }

# ================================================================
# FortiGate 점검
# ================================================================
# fg_blockm: fg_block 의 마스킹본(증적용) / fg_pol_dump: 정책 요약(증적·판정 공용)
fg_blockm() { printf '%s\n' "$TEXT_M" | awk -v hdr="$1" '
        $0 ~ "^[ \t]*" hdr "[ \t]*$" { ins=1; nest=0; print; next }
        !ins { next }
        /^[ \t]*config / { nest++ }
        { print }
        /^[ \t]*end[ \t]*$/ { if (nest > 0) nest--; else ins=0 }'; }
fg_pol_dump() { fg_policies | awk -F'\t' '{print "policy " $1 ": action=" $2 " status=" $3 " srcintf=" $7 " dstintf=" $8 " src=" $4 " dst=" $5 " svc=" $6 (($9 != $6) ? " (서비스 그룹 전개: " $9 ")" : "")}'; }
# FG_FULL=1: 장비 전체 config 로 볼 수 있음(config system global 존재) → 기본값 생략·섹션 부재를 '미설정'으로 해석 가능
FG_FULL=0; has_sec 'config system global' && FG_FULL=1
FG_NOPOL=""
# fg_pol_ok: 정책(config firewall policy / policy6 등)을 읽을 수 있는가. 섹션이 없거나 파싱 결과가 비면 실패(FG_NOPOL 에 사유) → 호출부가 '점검불가' 로 처리
fg_pol_ok() {
    local _n _raw
    if ! printf '%s\n' "$TEXT" | grep -qE '^[[:space:]]*config firewall (policy|policy6|policy46|policy64|security-policy|proxy-policy)[[:space:]]*$'; then
        FG_NOPOL="config firewall policy 섹션 없음(부분 config) — show full-configuration 으로 전체 설정을 다시 추출해 점검 필요"; return 1
    fi
    _n=$(fg_policies | wc -l | tr -d ' ')
    # 정책 섹션 안의 최상위 edit 개수(원본)와 파싱된 정책 수가 다르면 해석 실패
    _raw=$(printf '%s\n' "$TEXT" | tr -d '\r' | awk '/^[ \t]*config firewall (policy|policy6|policy46|policy64|security-policy|proxy-policy)[ \t]*$/ { inp=1; nest=0; next } !inp { next } /^[ \t]*config / { nest++; next } /^[ \t]*end[ \t]*$/ { if (nest > 0) { nest--; next } inp=0; next } nest == 0 && /^[ \t]*edit / { c++ } END { print c + 0 }')
    if [ "${_n:-0}" -ne "${_raw:-0}" ]; then
        FG_NOPOL="config firewall policy 의 정책(edit) ${_raw}건 중 ${_n}건만 해석됨 — 형식 확인 필요"; return 1
    fi
    return 0
}

check_fortigate() {

# ISS-001: 보안장비 정책 및 로그 백업 설정 여부
check_applicable "ISS-001" "정책 및 로그 백업" && {
    kw "ISS-001" 'backup|auto-backup|config backup|log.*disk|logdisk'
    result "ISS-001|수동확인|정책/로그 백업 주기 및 절차 수동 확인 필요 (인터뷰 기반)"
}

# ISS-002: 원격 로그 서버 사용 여부
check_applicable "ISS-002" "원격 로그 서버" && {
    kw "ISS-002" 'config log (syslogd|fortianalyzer|forticloud)|set server|set status'
    LOG_ON=""; LOG_OFF=""; LOG_NOSRV=""
    for _h in syslogd syslogd2 syslogd3 syslogd4 fortianalyzer fortianalyzer2 fortianalyzer3 fortianalyzer-cloud; do
        has_sec "config log $_h setting" || continue
        evd "ISS-002" "fg_blockm 'config log $_h setting'"
        if fg_block "config log $_h setting" | grep -qiE '^[[:space:]]*set status enable'; then
            # 서버 주소(set server)가 있어야 실제 전송 (FortiAnalyzer Cloud/FortiCloud 는 주소 대신 계정 연동)
            if fg_block "config log $_h setting" | grep -qiE '^[[:space:]]*set server[[:space:]]+[^[:space:]]' || echo "$_h" | grep -qE 'cloud'; then LOG_ON="${LOG_ON}${_h} "; else LOG_NOSRV="${LOG_NOSRV}${_h} "; fi
        else LOG_OFF="${LOG_OFF}${_h} "; fi
    done
    if [ -n "$LOG_ON" ]; then
        result "ISS-002|양호|원격 로그서버 연동(status enable): ${LOG_ON% }${LOG_OFF:+ / 비활성: ${LOG_OFF% }}"
    elif [ -n "$LOG_NOSRV" ]; then
        result "ISS-002|취약|원격 로그 설정이 enable 이나 서버 주소(set server) 미지정: ${LOG_NOSRV% }${LOG_OFF:+ / 비활성: ${LOG_OFF% }}"
    elif [ -n "$LOG_OFF" ]; then
        result "ISS-002|취약|원격 로그서버 설정은 있으나 활성(set status enable) 아님: ${LOG_OFF% } (FortiOS 기본값 disable)"
    elif [ "$FG_FULL" -eq 1 ]; then
        result "ISS-002|취약|원격 로그서버(syslogd/FortiAnalyzer) 설정 섹션 없음 — 미설정"
    else
        result "ISS-002|점검불가|config log syslogd/fortianalyzer 섹션 및 config system global 없음(부분 config) — 전체 설정 재추출 필요"
    fi
}

# ISS-003: DMZ 구간 설정 여부
check_applicable "ISS-003" "DMZ 구간 설정" && {
    kw "ISS-003" 'dmz|config system zone'
    evd "ISS-003" "fg_pol_dump"
    if ! fg_pol_ok; then
        result "ISS-003|점검불가|${FG_NOPOL}"
    else
        # 데스크톱 모델 기본 인터페이스 'dmz' 는 미사용이어도 존재 → dmz 인터페이스/존을 쓰는 활성 accept 정책이 있어야 양호 (비활성·deny 정책 제외)
        DMZ_POL=$(fg_accept | awk -F'\t' 'tolower($7 " " $8) ~ /dmz/ {printf "%s ", $1}')
        ZONES=$(printf '%s\n' "$TEXT" | grep -ci "config system zone" 2>/dev/null || true)
        if [ -n "$DMZ_POL" ]; then
            result "ISS-003|양호|DMZ 인터페이스/존을 쓰는 활성 허용 정책 확인됨 (정책 ${DMZ_POL% })"
        else
            result "ISS-003|수동확인|DMZ 사용 활성 허용 정책 미탐지 (dmz 키워드 ${KW_N}건, zone ${ZONES}건) — 공개용 서버 구간 분리 여부 수동 확인"
        fi
    fi
}

# ISS-004: NAT 정책 설정 적정성
check_applicable "ISS-004" "NAT 정책 적정성" && {
    kw "ISS-004" 'set nat enable|config firewall vip|set extip|set mappedip'
    NAT_COUNT=$(printf '%s\n' "$TEXT" | grep -ci "set nat enable" 2>/dev/null || true)
    VIP_COUNT=$(printf '%s\n' "$TEXT" | grep -ci "config firewall vip" 2>/dev/null || true)
    result "ISS-004|수동확인|NAT 정책 ${NAT_COUNT}건, VIP ${VIP_COUNT}건 — 불필요 NAT 존재 여부 수동 확인"
}

# ISS-005: 주기적인 보안패치 및 벤더 권고사항 적용 여부
check_applicable "ISS-005" "보안패치 적용" && {
    kw "ISS-005" 'config-version=|FortiOS|build[0-9]|set version'
    FW_VER=$(printf '%s\n' "$TEXT" | grep -iE 'config-version=|#config-version|FortiOS|build[0-9]' 2>/dev/null | head -1)
    result "ISS-005|수동확인|펌웨어 버전: ${FW_VER:-미탐지} — 최신 패치 적용 여부 수동 확인 (벤더 권고사항 대조)"
}

# ISS-006: 보안장비 사용량의 주기적인 점검 및 보고 여부
check_applicable "ISS-006" "사용량 점검/보고" && {
    kw "ISS-006" 'snmp|monitoring|alert|diagnose|syslog'
    result "ISS-006|수동확인|CPU/메모리 사용량 모니터링 및 주기적 보고 여부 수동 확인 (인터뷰 기반)"
}

# ISS-007: 보안장비 장애/보안이벤트 모니터링 실시 여부
check_applicable "ISS-007" "장애/이벤트 모니터링" && {
    kw "ISS-007" 'config alertemail|config system alert|set alert|set mailto|alert|mailto|notification'
    if [ "$KW_N" -gt 0 ]; then
        result "ISS-007|수동확인|알림/알람 설정 ${KW_N}건 발견 — 모니터링 체계 수동 확인"
    else
        result "ISS-007|수동확인|알림 설정 미탐지 — 이벤트 모니터링 체계 수동 확인"
    fi
}

# ISS-008: 탐지된 이벤트 및 로그에 대한 정기적 분석 및 보고 여부
check_applicable "ISS-008" "이벤트 분석/보고" && {
    kw "ISS-008" 'log|report|analytics|fortianalyzer'
    result "ISS-008|수동확인|보안이벤트 정기 분석/보고 여부 수동 확인 (보안관제보고서 확인)"
}

# ISS-009: 위험도가 높은 이벤트 및 로그에 대한 RAW 패킷 저장 여부
check_applicable "ISS-009" "RAW 패킷 저장" && {
    kw "ISS-009" 'packet-log|netscan|full-archive|capture|pcap'
    if [ "$KW_N" -gt 0 ]; then
        result "ISS-009|수동확인|패킷 저장 관련 설정 ${KW_N}건 — 위험도 높은 이벤트 RAW 저장 여부 수동 확인"
    else
        result "ISS-009|수동확인|패킷 저장 설정 미탐지 — RAW 패킷 저장 기능 수동 확인"
    fi
}

# ISS-010: TCP/UDP/ICMP 탐지/차단 패턴 적용 여부
check_applicable "ISS-010" "Flooding 탐지/차단" && {
    kw "ISS-010" 'dos-policy|anomaly|flood|icmp|syn.*cookie|rate-based'
    if [ "$KW_N" -gt 0 ]; then
        result "ISS-010|수동확인|DoS/Flooding 관련 설정 ${KW_N}건 — TCP/UDP/ICMP 패턴 적용 여부 수동 확인"
    else
        result "ISS-010|수동확인|DoS/Flooding 설정 미탐지 — 탐지/차단 패턴 수동 확인"
    fi
}

# ISS-011: Port Scan 탐지/차단 패턴 적용 여부
check_applicable "ISS-011" "Port Scan 탐지/차단" && {
    kw "ISS-011" 'port.*scan|scan.*detect|portscan|reconnaissance'
    if [ "$KW_N" -gt 0 ]; then
        result "ISS-011|수동확인|Port Scan 탐지 설정 ${KW_N}건 — 차단 정책 수동 확인"
    else
        result "ISS-011|수동확인|Port Scan 탐지 설정 미탐지 — 탐지/차단 패턴 수동 확인"
    fi
}

# ISS-012: 해킹 툴 탐지/차단 패턴 적용 여부
check_applicable "ISS-012" "해킹 툴 탐지/차단" && {
    kw "ISS-012" 'ips.*sensor|config ips|malware|antivirus|botnet|application-control'
    if [ "$KW_N" -gt 0 ]; then
        result "ISS-012|수동확인|IPS/악성코드 탐지 설정 ${KW_N}건 — 패턴 최신 여부 수동 확인"
    else
        result "ISS-012|수동확인|IPS/악성코드 탐지 설정 미탐지 — 해킹 툴 차단 기능 수동 확인"
    fi
}

# ISS-013: 불필요한 Source Routing 차단 설정 여부
check_applicable "ISS-013" "Source Routing 차단" && {
    kw "ISS-013" 'source.*rout|ip.*option|strict-src-check|asymroute'
    ASYM=$(printf '%s\n' "$TEXT" | grep -i "set asymroute" 2>/dev/null | head -1)
    if [ -n "$ASYM" ]; then
        result "ISS-013|수동확인|asymroute 설정: ${ASYM} — Source Routing 차단 여부 수동 확인"
    else
        result "ISS-013|수동확인|Source Routing 관련 설정 수동 확인"
    fi
}

# ISS-014: 사용하지 않는 SNMP 비활성화 여부
check_applicable "ISS-014" "SNMP 비활성화" && {
    kw "ISS-014" 'config system snmp|set status|snmp.*community|snmp.*user'
    evd "ISS-014" "fg_blockm 'config system snmp sysinfo'; fg_blockm 'config system snmp community'; fg_blockm 'config system snmp user'"
    SNMP_SYS=0; fg_block 'config system snmp sysinfo' | grep -qiE '^[[:space:]]*set status enable' && SNMP_SYS=1
    SNMP_COMM=$(fg_block 'config system snmp community' | awk '/^[ \t]*config /{if(!f){f=1;next} n++} /^[ \t]*end[ \t]*$/{if(n>0)n--} n==0&&/^[ \t]*edit /{c++} END{print c+0}')
    SNMP_USER=$(fg_block 'config system snmp user' | awk '/^[ \t]*config /{if(!f){f=1;next} n++} /^[ \t]*end[ \t]*$/{if(n>0)n--} n==0&&/^[ \t]*edit /{c++} END{print c+0}')
    SNMP_ANY=$(printf '%s\n' "$TEXT" | grep -ciE '^[[:space:]]*config system snmp')
    if [ "$SNMP_SYS" -eq 1 ] || [ "$SNMP_COMM" -gt 0 ] || [ "$SNMP_USER" -gt 0 ]; then
        result "ISS-014|수동확인|SNMP 사용 설정 존재 (에이전트 enable=${SNMP_SYS}, v2c community ${SNMP_COMM}건, v3 사용자 ${SNMP_USER}건) — 사용 필요성 수동 확인"
    elif [ "$SNMP_ANY" -gt 0 ] || [ "$FG_FULL" -eq 1 ]; then
        result "ISS-014|양호|SNMP 에이전트 비활성 (community/v3 사용자 없음, sysinfo status 미enable)"
    else
        result "ISS-014|점검불가|config system snmp 섹션 및 config system global 없음(부분 config) — SNMP 사용 여부를 판단할 수 없음"
    fi
}

# ISS-015: 안전한 네트워크 모니터링 서비스 사용 여부 (SNMPv3)
check_applicable "ISS-015" "SNMP 안전 버전" && {
    kw "ISS-015" 'snmp.*user|snmp.*community|set name|security-level|auth-proto|priv-proto'
    evd "ISS-015" "fg_blockm 'config system snmp community'; fg_blockm 'config system snmp user'"
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
    elif [ "$FG_FULL" -eq 1 ] || has_sec 'config system snmp sysinfo'; then
        result "ISS-015|양호|SNMP 미사용 (community/v3 사용자 없음)"
    else
        result "ISS-015|점검불가|config system snmp 섹션 및 config system global 없음(부분 config) — SNMP 설정을 판단할 수 없음"
    fi
}

# ISS-016: 보안장비 접속 시 보안 접속 사용 여부
check_applicable "ISS-016" "보안 접속" && {
    kw "ISS-016" 'set allowaccess|set admin-sport|set admin-ssh|set admin-telnet|set admin-port'
    if ! has_sec 'config system interface' && ! has_sec 'config system global'; then
        result "ISS-016|점검불가|config system interface/global 섹션 없음(부분 config) — 관리 접속 프로토콜을 판단할 수 없음"
    else
        # 인터페이스별 allowaccess 토큰 단위로 http/telnet 판정 (https 와 구분), global 의 admin-telnet 포함
        WEAK_IF=$(fg_block 'config system interface' | awk '
            /^[ \t]*config / { nst++ }
            /^[ \t]*end[ \t]*$/ { if (nst > 1) nst-- }
            nst == 1 && /^[ \t]*edit / { nm=$2; gsub(/"/,"",nm) }
            /^[ \t]*set allowaccess / { w=""; for (i=3;i<=NF;i++) { if ($i=="http") w=w " http"; if ($i=="telnet") w=w " telnet" } if (w!="") printf "%s(%s) ", nm, substr(w,2) }')
        GLOB_TEL=$(fg_block 'config system global' | grep -iE '^[[:space:]]*set admin-telnet enable')
        if [ -n "$WEAK_IF" ] || [ -n "$GLOB_TEL" ]; then
            result "ISS-016|취약|평문 관리 프로토콜 허용: ${WEAK_IF}${GLOB_TEL:+전역 admin-telnet enable} — HTTPS/SSH 전용 사용 필요"
        else
            result "ISS-016|양호|HTTPS/SSH 전용 관리 접속 확인 (인터페이스 allowaccess 에 http/telnet 없음)"
        fi
    fi
}

# ISS-017: 보안장비 Default 계정 변경 여부
check_applicable "ISS-017" "Default 계정 변경" && {
    evd "ISS-017" "fg_blockm 'config system admin'"
    if ! has_sec 'config system admin'; then
        result "ISS-017|점검불가|config system admin 섹션 없음(부분 config) — 관리자 계정명을 확인할 수 없음"
    else
        # config system admin 최상위 edit 이름만 (다른 테이블의 edit "admin" 오탐 방지)
        ADM_NAMES=$(fg_block 'config system admin' | awk '/^[ \t]*config /&&!first{first=1;next} /^[ \t]*config /{n++} /^[ \t]*end[ \t]*$/{if(n>0)n--} n==0&&/^[ \t]*edit /{v=$2; gsub(/"/,"",v); printf "%s ", v}')
        if echo " $ADM_NAMES" | grep -qiE ' (admin|administrator|root) '; then
            result "ISS-017|취약|기본 관리자 계정명 미변경 (계정: ${ADM_NAMES% }) — 계정명 변경 필요"
        else
            result "ISS-017|양호|기본 admin 계정명 변경됨 (계정: ${ADM_NAMES% })"
        fi
    fi
}

# ISS-018: 보안장비 Default 비밀번호 변경 여부
check_applicable "ISS-018" "Default 비밀번호 변경" && {
    kw "ISS-018" 'password-policy|minimum-length|min-length|change-4-characters'
    evd "ISS-018" "fg_blockm 'config system password-policy'"
    # FortiOS config system password-policy 키는 minimum-length (min-length 는 구버전 표기 대비)
    MIN_LEN=$(printf '%s\n' "$TEXT" | grep -iE "set (minimum-length|min-length) " 2>/dev/null | head -1 | grep -oE '[0-9]+' | head -1)
    if [ -n "$MIN_LEN" ] && [ "$MIN_LEN" -ge 8 ]; then
        result "ISS-018|수동확인|비밀번호 최소 길이 ${MIN_LEN}자 — 기본 비밀번호 변경 여부 수동 확인"
    else
        result "ISS-018|수동확인|비밀번호 복잡도 정책 수동 확인 (최소길이: ${MIN_LEN:-미설정})"
    fi
}

# ISS-019: 보안장비 계정 관리 적정성
check_applicable "ISS-019" "계정 관리 적정성" && {
    evd "ISS-019" "fg_blockm 'config system admin'"
    ADMIN_COUNT=$(fg_block 'config system admin' | grep -cE '^[[:space:]]*edit ')
    result "ISS-019|수동확인|관리자 계정 ${ADMIN_COUNT}개 — 개인별 계정 사용 및 공용 계정 사용 여부 점검 (증적 참조)"
}

# ISS-020: 보안장비 계정별 권한 설정 여부
check_applicable "ISS-020" "계정별 권한 설정" && {
    kw "ISS-020" 'set accprofile|config system accprofile'
    if [ "$KW_N" -gt 0 ]; then
        result "ISS-020|수동확인|권한 프로파일 설정 ${KW_N}건 — 최소권한 원칙 준수 여부 수동 확인"
    else
        result "ISS-020|수동확인|권한 프로파일 미탐지 — 계정별 권한 설정 수동 확인"
    fi
}

# ISS-021: 보안장비 원격 관리 접근 통제 여부
check_applicable "ISS-021" "원격 관리 접근 통제" && {
    kw "ISS-021" 'set (ip6-)?trusthost|set trusted|set admin-sport|set admin-server-cert|config firewall local-in-policy'
    evd "ISS-021" "fg_blockm 'config system admin'"
    # 관리자 계정별 trusthost (0.0.0.0 0.0.0.0 = 전체 허용은 미설정으로 간주)
    ADM=$(echo "$TEXT" | tr -d '\r' | awk '/^[ \t]*config system admin[ \t]*$/{a=1;next} a&&/^[ \t]*config /{n++} a&&/^[ \t]*end[ \t]*$/{if(n>0){n--;next} if(id!="")print id"\t"t; a=0} a&&n==0&&/^[ \t]*edit /{if(id!="")print id"\t"t; id=$2; gsub(/"/,"",id); t=0} a&&/^[ \t]*set (ip6-)?trusthost[0-9]* /{if($0 !~ /0\.0\.0\.0[ \/]+0\.0\.0\.0/ && $0 !~ /::\/0/) t++}')
    ADM_ALL=$(echo "$ADM" | awk 'NF' | wc -l | tr -d ' ')
    ADM_OPEN=$(echo "$ADM" | awk -F'\t' 'NF>1 && $2==0{printf "%s ", $1}')
    LIP=$(printf '%s\n' "$TEXT" | grep -ci "config firewall local-in-policy" 2>/dev/null || true)
    if [ "$ADM_ALL" -gt 0 ] && [ -z "$ADM_OPEN" ]; then
        result "ISS-021|양호|관리자 ${ADM_ALL}개 계정 모두 trusthost(관리 IP) 제한 설정"
    elif [ "$ADM_ALL" -gt 0 ]; then
        result "ISS-021|수동확인|trusthost 미설정(또는 0.0.0.0/0) 관리자: ${ADM_OPEN% } — local-in-policy(${LIP}건)·상위 방화벽 등 장비 접근제어 여부 확인 (미통제 시 취약)"
    else
        result "ISS-021|점검불가|config system admin 섹션 없음(부분 config) — 관리 IP 제한(trusthost)을 확인할 수 없음"
    fi
}

# ISS-022: 보안장비 접속성공/실패 로깅 여부
check_applicable "ISS-022" "접속 로깅" && {
    kw "ISS-022" 'config log eventfilter|set event |set system |set user |admin-log|login-log|log.*admin|admin.*log'
    result "ISS-022|수동확인|관리자 접속 성공/실패 로깅 설정 수동 확인 (로그 관련 설정 ${KW_N}건)"
}

# ISS-023: 로그인 실패횟수 제한 설정 여부
check_applicable "ISS-023" "로그인 실패 제한" && {
    kw "ISS-023" 'admin-lockout-threshold|admin-lockout-duration|set lockout|config system global'
    LOCKOUT=$(printf '%s\n' "$TEXT" | grep -i "^[[:space:]]*set admin-lockout-threshold" 2>/dev/null | head -1 | grep -oE '[0-9]+' | head -1)
    if [ -n "$LOCKOUT" ] && [ "$LOCKOUT" -le 5 ] && [ "$LOCKOUT" -gt 0 ]; then
        result "ISS-023|양호|로그인 실패 잠금 임계값 ${LOCKOUT}회 설정 (5회 이내)"
    elif [ -n "$LOCKOUT" ] && [ "$LOCKOUT" -gt 5 ]; then
        result "ISS-023|취약|로그인 실패 잠금 임계값 ${LOCKOUT}회 — 5회 이내 설정 필요"
    elif [ -z "$LOCKOUT" ] && [ "$FG_FULL" -eq 1 ]; then
        result "ISS-023|양호|admin-lockout-threshold 미표기 — FortiOS 기본값 3회 적용 (show 백업은 기본값 생략)"
    else
        result "ISS-023|점검불가|config system global 섹션 없음(부분 config) — admin-lockout-threshold 를 확인할 수 없음"
    fi
}

# ISS-024: 세션 타임아웃 설정 여부
check_applicable "ISS-024" "세션 타임아웃" && {
    kw "ISS-024" 'set admintimeout|set idle-timeout|set auth-timeout|config system global'
    TIMEOUT=$(printf '%s\n' "$TEXT" | grep -i "^[[:space:]]*set admintimeout" 2>/dev/null | head -1 | grep -oE '[0-9]+' | head -1)
    if [ -n "$TIMEOUT" ] && [ "$TIMEOUT" -le 15 ] && [ "$TIMEOUT" -gt 0 ]; then
        result "ISS-024|양호|관리자 세션 타임아웃 ${TIMEOUT}분 설정"
    elif [ -n "$TIMEOUT" ] && [ "$TIMEOUT" -gt 15 ]; then
        result "ISS-024|취약|관리자 세션 타임아웃 ${TIMEOUT}분 — 15분 이하 설정 필요 (내부 규정이 더 짧으면 그 기준)"
    elif [ "$TIMEOUT" = "0" ]; then
        result "ISS-024|취약|관리자 세션 타임아웃 무제한(0) — 15분 이하 설정 필요 (내부 규정이 더 짧으면 그 기준)"
    elif [ -z "$TIMEOUT" ] && [ "$FG_FULL" -eq 1 ]; then
        result "ISS-024|양호|admintimeout 미표기 — FortiOS 기본값 5분 적용 (show 백업은 기본값 생략)"
    else
        result "ISS-024|점검불가|config system global 섹션 없음(부분 config) — admintimeout 을 확인할 수 없음"
    fi
}

# ISS-025: 시간 동기화를 위한 NTP 설정
check_applicable "ISS-025" "NTP 설정" && {
    kw "ISS-025" 'set ntpserver|set ntpsync|set type |config system ntp|set server '
    evd "ISS-025" "fg_blockm 'config system ntp'"
    if ! has_sec 'config system ntp'; then
        result "ISS-025|점검불가|config system ntp 섹션 없음 — 기본값 생략(show)인지 부분 config 인지 구분 불가, NTP 설정을 확인할 수 없음 (show full-configuration 으로 재추출)"
    else
        NTP_BLK=$(fg_block 'config system ntp')
        NTP_SYNC=$(printf '%s\n' "$NTP_BLK" | grep -iE '^[[:space:]]*set ntpsync' | head -1 | awk '{print $3}')
        NTP_TYPE=$(printf '%s\n' "$NTP_BLK" | grep -iE '^[[:space:]]*set type ' | head -1 | awk '{print $3}')
        NTP_SRV=$(printf '%s\n' "$NTP_BLK" | grep -cE '^[[:space:]]*set server ')
        # FortiOS 기본값: ntpsync enable, type fortiguard (show 에는 기본값 줄 생략)
        if [ "$NTP_SYNC" = "disable" ]; then
            result "ISS-025|취약|NTP 동기화 비활성(set ntpsync disable)"
        elif [ "$NTP_TYPE" = "custom" ] && [ "$NTP_SRV" -eq 0 ]; then
            result "ISS-025|취약|NTP type custom 이나 NTP 서버(set server) 미지정"
        else
            result "ISS-025|양호|NTP 동기화 활성 (ntpsync=${NTP_SYNC:-enable(기본)}, type=${NTP_TYPE:-fortiguard(기본)}, 서버 ${NTP_SRV}개)"
        fi
    fi
}

# ISS-026: 주요 파일에 대한 주기적인 무결성 검사 여부
check_applicable "ISS-026" "무결성 검사" && {
    kw "ISS-026" 'file-integrity|integrity|checksum|hash'
    result "ISS-026|수동확인|주요 파일 무결성 검사 수행 여부 수동 확인 (기능 미지원 시 N-A)"
}

# ISS-027: 보안장비 기능외 서비스 제한 여부
check_applicable "ISS-027" "기능외 서비스 제한" && {
    kw "ISS-027" 'set allowaccess|set service|config system interface'
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
    evd "ISS-030" "fg_pol_dump"
    if ! fg_pol_ok; then
        result "ISS-030|점검불가|${FG_NOPOL}"
    else
        # 정책 단위: 활성 accept 정책 중 목적지 all + 서비스 ALL (deny 정리 정책·서비스 정의 제외)
        P_BOTH=$(fg_accept | awk -F'\t' '(" "$5" ") ~ / all / && (" "toupper($9)" ") ~ / ALL / {printf "%s ", $1}')
        P_DST=$(fg_accept | awk -F'\t' '(" "$5" ") ~ / all / {printf "%s ", $1}')
        P_SVC=$(fg_accept | awk -F'\t' '(" "toupper($9)" ") ~ / ALL / {printf "%s ", $1}')
        if [ -n "$P_BOTH" ]; then
            result "ISS-030|취약|목적지 all + 서비스 ALL 허용 정책: ${P_BOTH% }"
        elif [ -n "$P_DST" ] || [ -n "$P_SVC" ]; then
            P_DST="${P_DST% }"; P_SVC="${P_SVC% }"
            result "ISS-030|수동확인|목적지 all 허용 정책(${P_DST:-없음}), 서비스 ALL 허용 정책(${P_SVC:-없음}) — 정당성 수동 확인"
        else
            result "ISS-030|양호|모든 목적지/서비스 허용(accept) 정책 없음 ($(fg_accept | wc -l | tr -d ' ')개 활성 허용 정책 검사)"
        fi
    fi
}

# ISS-031: 취약한 서비스의 네트워크 대역 단위 허용 금지 여부
check_applicable "ISS-031" "취약 서비스 대역 허용" && {
    evd "ISS-031" "fg_pol_dump"
    kw "ISS-031" 'set (dst|src)addr.*subnet|set service.*(FTP|SSH|Telnet|RDP|MSSQL|MYSQL|ORACLE)'
    result "ISS-031|수동확인|출발지/목적지 네트워크 대역 + 관리용/취약 포트 허용 정책 수동 확인"
}

# ISS-032: 서비스 포트 허용 정책 적정성
check_applicable "ISS-032" "서비스 포트 적정성" && {
    evd "ISS-032" "fg_pol_dump"
    evd "ISS-032" "fg_services"
    if ! fg_pol_ok; then
        result "ISS-032|점검불가|${FG_NOPOL}"
    else
        # 과도한 서비스: ALL/ALL_TCP/ALL_UDP 또는 포트 범위 1000개 이상 커스텀 서비스(예: 1024-65535)를 쓰는 활성 accept 정책
        WIDE=$(fg_services | awk -F'\t' '{ n=split($2, r, " "); for (i=1;i<=n;i++) { d=r[i]; sub(/:.*/, "", d); split(d, b, "-"); hi=(b[2]==""?b[1]:b[2]); if (hi-b[1]+1 >= 1000) { printf "%s|", $1; break } } }')
        RE="ALL|ALL_TCP|ALL_UDP"; [ -n "$WIDE" ] && RE="${RE}|${WIDE%|}"
        P_WIDE=$(fg_accept_with_svc "$RE")
        if [ -n "$P_WIDE" ]; then
            result "ISS-032|취약|과도한 서비스(ALL/ALL_TCP/ALL_UDP/광범위 포트${WIDE:+: ${WIDE%|}}) 허용 정책: ${P_WIDE% }"
        else
            result "ISS-032|수동확인|ALL/광범위 포트 허용 정책 없음 — 개별 서비스 포트 허용 적정성 수동 확인"
        fi
    fi
}

# ISS-033: 불필요한 양방향 정책 금지 여부
check_applicable "ISS-033" "양방향 정책 금지" && {
    evd "ISS-033" "fg_pol_dump"
    result "ISS-033|수동확인|불필요 양방향 정책 존재 여부 수동 확인 (관리용/DB 포트 21,22,23,3389,1521,1433,3306 등)"
}

# ISS-034: 정책 적용 순서의 적절성
check_applicable "ISS-034" "정책 적용 순서" && {
    evd "ISS-034" "fg_pol_dump"
    result "ISS-034|수동확인|정책 적용 순서 적절성 수동 확인 (Blacklist/차단 정책 상위 배치 여부)"
}

# ISS-035: 출발지 포트 기반의 정책 금지 여부
check_applicable "ISS-035" "출발지 포트 정책 금지" && {
    evd "ISS-035" "fg_services"
    evd "ISS-035" "fg_pol_dump"
    if ! fg_pol_ok; then
        result "ISS-035|점검불가|${FG_NOPOL}"
    else
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
    fi
}

# ISS-036: 취약한 원격 서비스 금지 여부
check_applicable "ISS-036" "취약 원격 서비스 금지" && {
    evd "ISS-036" "fg_pol_dump"
    if ! fg_pol_ok; then
        result "ISS-036|점검불가|${FG_NOPOL}"
    else
        # 기본 서비스 객체 정의(TFTP/RLOGIN 등)는 제외 — 활성 accept 정책의 set service 값만 비교
        P_WEAK=$(fg_accept_with_svc "TFTP|RLOGIN|RSH|REXEC|FINGER")
        if [ -n "$P_WEAK" ]; then
            result "ISS-036|취약|취약 원격 서비스(r-계열/TFTP/Finger) 허용 정책: ${P_WEAK% }"
        else
            result "ISS-036|양호|취약 원격 서비스 허용 정책 없음 ($(fg_accept | wc -l | tr -d ' ')개 활성 허용 정책 검사)"
        fi
    fi
}

# ISS-037: 불필요한 정책 제거 여부
check_applicable "ISS-037" "불필요 정책 제거" && {
    kw "ISS-037" 'set status disable|set logtraffic disable|config firewall policy'
    DISABLED=$(printf '%s\n' "$TEXT" | grep -c 'set status disable' 2>/dev/null || true)
    result "ISS-037|수동확인|비활성 정책 ${DISABLED}건 — 6개월 이상 미사용/불필요 정책 수동 확인 (히트카운트 기반)"
}

# ISS-038: 서버간 관리포트 허용 금지 여부
check_applicable "ISS-038" "서버간 관리포트 금지" && {
    kw "ISS-038" 'set service.*(FTP|SSH|Telnet|RDP|MSSQL|MySQL|Oracle-DB)'
    result "ISS-038|수동확인|서버 ↔ 서버 간 관리포트(21,22,23,3389,1433,1521,3306) 허용 정책 수동 확인"
}

# ISS-039: 단말과 서버간 접근통제를 우회한 접속 금지 여부
check_applicable "ISS-039" "접근통제 우회 금지" && {
    evd "ISS-039" "fg_pol_dump"
    result "ISS-039|수동확인|단말 → 서버 직접 접속(접근통제시스템 우회) 정책 존재 여부 수동 확인"
}

# ISS-040: 보안장비 비밀번호의 주기적인 변경 여부
check_applicable "ISS-040" "비밀번호 주기적 변경" && {
    kw "ISS-040" 'password-expire|set password|passwd-time|passwd-policy'
    PW_EXPIRE=$(printf '%s\n' "$TEXT" | grep -iE "password-expire|passwd-time" 2>/dev/null | head -1)
    result "ISS-040|수동확인|비밀번호 주기적 변경(분기별 1회 이상) 여부 수동 확인: ${PW_EXPIRE:-설정 미탐지}"
}

# ISS-041: 불필요한 네트워크 대역 단위 설정 금지 여부
check_applicable "ISS-041" "네트워크 대역 설정 금지" && {
    evd "ISS-041" "fg_pol_dump"
    P_ANY=$(fg_accept | awk -F'\t' '(" "$4" "$5" ") ~ / all / {printf "%s ", $1}')
    if [ -n "$P_ANY" ]; then
        result "ISS-041|수동확인|출발지/목적지 all 허용 정책: ${P_ANY% } — 불필요 대역 적용 여부 수동 확인"
    elif ! fg_pol_ok; then
        result "ISS-041|점검불가|${FG_NOPOL}"
    else
        result "ISS-041|수동확인|출발지/목적지 all 허용 정책 없음 — 네트워크 대역(서브넷) 주소 객체 사용 정책 적정성 수동 확인"
    fi
}

# ISS-042: 차단 기능 활성화 여부
check_applicable "ISS-042" "차단 기능 활성화" && {
    kw "ISS-042" 'bypass|set mode.*transparent|set mode.*offline|set action.*block|set action.*deny'
    # 'hw-bypass disable' 은 정상 — 값이 enable 인 bypass 설정만 집계
    BYPASS=$(printf '%s\n' "$TEXT" | grep -ciE '^[[:space:]]*set [a-z-]*bypass[a-z-]* (enable|forced)' 2>/dev/null || true)
    if [ "$BYPASS" -gt 0 ]; then
        result "ISS-042|취약|Bypass 모드 활성화(enable) ${BYPASS}건 — 차단 기능 비활성 상태"
    else
        result "ISS-042|수동확인|Bypass 활성 설정 없음 — 차단 기능 활성화 및 최근 1개월 차단 로그 수동 확인"
    fi
}

# ISS-043: EoS 시스템 및 장비 교체 여부
check_applicable "ISS-043" "EoS 장비 교체" && {
    kw "ISS-043" 'config-version=|FortiOS|build[0-9]|set version'
    FW_VER=$(printf '%s\n' "$TEXT" | grep -iE 'config-version=|#config-version|FortiOS|build[0-9]' 2>/dev/null | head -1)
    result "ISS-043|수동확인|펌웨어 버전: ${FW_VER:-미탐지} — 벤더사 Lifecycle 표 대조 필요"
}
}

# ================================================================
# Palo Alto 점검 (XML · set 형식 공통: PA_FLAT 정규화 레코드 기준)
# ================================================================
pa_rules_dump() { pa_rules | awk -F'\t' '{print "rule " $1 ": action=" $2 " disabled=" $3 " from=" $4 " to=" $5 " source=" $6 " destination=" $7 " application=" $8 " service=" $9}'; }
pa_cnt() { printf '%s\n' "$PA_FLAT" | tr '\t' ' ' | grep -ciE -- "$1"; }
PA_NORULE="보안 정책(rulebase security rules) 섹션 없음(부분 config 또는 형식 미인식) — 정책 포함 전체 config 를 다시 추출해 점검 필요"
PA_NOSYS="deviceconfig system 섹션 없음(부분 config 또는 형식 미인식) — 장비 관리 설정을 포함한 전체 config 를 다시 추출해 점검 필요"

check_paloalto() {

# config 형식을 알 수 없으면 모든 항목 점검불가
if [ -z "$PA_FLAT" ]; then
    local _n=0 _c
    while [ "$_n" -lt 43 ]; do
        _n=$((_n+1)); _c=$(printf 'ISS-%03d' "$_n")
        check_applicable "$_c" "$(iss_name "$_c")" && {
            evd "$_c" "echo 'PAN-OS config 형식(XML 또는 set)을 인식하지 못함 — 파일: ${CFG_FILE}'"
            result "${_c}|점검불가|PAN-OS config 형식(XML 또는 set)을 인식하지 못해 점검할 수 없음 — show config running (XML) 또는 set 형식으로 다시 추출"
        }
    done
    return 0
fi
PA_SYSN=$(pa_cnt 'deviceconfig system')
PA_RULEN=$(printf '%s\n' "$PA_RULES" | awk 'NF' | wc -l | tr -d ' ')

# ISS-001: 보안장비 정책 및 로그 백업 설정 여부
check_applicable "ISS-001" "정책 및 로그 백업" && {
    paf "ISS-001" 'backup|export|log.*setting|scheduled'
    result "ISS-001|수동확인|정책/로그 백업 주기 및 절차 수동 확인 필요 (인터뷰 기반)"
}

# ISS-002: 원격 로그 서버 사용 여부
check_applicable "ISS-002" "원격 로그 서버" && {
    paf "ISS-002" 'syslog|log-collector|panorama|log-forwarding|server-profile|log-settings'
    SYSLOG_SRV=$(pa_cnt 'syslog .*server .*server [^ ]+')
    PANORAMA=$(pa_cnt 'panorama-server [^ ]+|log-collector [^ ]+')
    SYSLOG_KW=$(pa_cnt 'syslog')
    SYSLOG_REF=$(pa_cnt 'send-syslog [^ ]+|syslog-profile [^ ]+')   # 로그 설정/log-forwarding 프로파일이 syslog 프로파일을 실제로 참조
    if [ "$PANORAMA" -gt 0 ] || { [ "$SYSLOG_SRV" -gt 0 ] && [ "$SYSLOG_REF" -gt 0 ]; }; then
        result "ISS-002|양호|원격 로그서버 지정됨 (syslog 서버 항목 ${SYSLOG_SRV}건·로그 설정 연결 ${SYSLOG_REF}건, Panorama/Log Collector 지정 ${PANORAMA}건)"
    elif [ "$SYSLOG_SRV" -gt 0 ]; then
        result "ISS-002|수동확인|syslog 서버 프로파일(${SYSLOG_SRV}건)은 있으나 로그 설정/log-forwarding 프로파일에서 참조(send-syslog)하는 설정 미확인 — 실제 로그 전송 연결 수동 확인"
    elif [ "$SYSLOG_KW" -gt 0 ]; then
        result "ISS-002|수동확인|syslog 관련 설정 ${SYSLOG_KW}건이나 서버 주소 항목 미확인 — 서버 프로파일·log-forwarding 연결 수동 확인"
    elif [ "$PA_SYSN" -gt 0 ]; then
        result "ISS-002|취약|원격 로그서버(syslog/Panorama) 미설정"
    else
        result "ISS-002|점검불가|${PA_NOSYS}"
    fi
}

# ISS-003: DMZ 구간 설정 여부
check_applicable "ISS-003" "DMZ 구간 설정" && {
    paf "ISS-003" 'dmz|zone'
    evd "ISS-003" "pa_rules_dump"
    if [ "$PA_RULEN" -eq 0 ]; then
        result "ISS-003|점검불가|${PA_NORULE}"
    else
        DMZ_RULES=$(pa_allow | awk -F'\t' 'tolower($4 " " $5) ~ /dmz/ {printf "%s ", $1}')
        if [ -n "$DMZ_RULES" ]; then
            result "ISS-003|양호|DMZ 존을 출발/목적지로 쓰는 활성 allow 규칙 확인됨 (규칙 ${DMZ_RULES% })"
        else
            result "ISS-003|수동확인|DMZ 존을 쓰는 활성 allow 규칙 미탐지 (dmz/zone 키워드 ${PAF_N}건) — 공개용 서버 구간 분리 여부 수동 확인"
        fi
    fi
}

# ISS-004: NAT 정책 설정 적정성
check_applicable "ISS-004" "NAT 정책 적정성" && {
    paf "ISS-004" 'nat|source-translation|destination-translation'
    result "ISS-004|수동확인|NAT 설정 ${PAF_N}건 — 불필요 NAT 존재 여부 수동 확인"
}

# ISS-005: 주기적인 보안패치 및 벤더 권고사항 적용 여부
check_applicable "ISS-005" "보안패치 적용" && {
    paf "ISS-005" 'version|sw-version|PAN-OS|app-version|threat-version'
    PA_VER=$(printf '%s\n' "$PA_FLAT" | tr '\t' ' ' | grep -iE "sw-version|PAN-OS" | head -1)
    [ -z "$PA_VER" ] && PA_VER=$(printf '%s\n' "$TEXT" | sed -n 's/.*<config version="\([^"]*\)".*/config version \1/p' | head -1)
    result "ISS-005|수동확인|PAN-OS 버전: ${PA_VER:-미탐지} — 최신 패치 적용 여부 수동 확인"
}

# ISS-006: 보안장비 사용량의 주기적인 점검 및 보고 여부
check_applicable "ISS-006" "사용량 점검/보고" && {
    paf "ISS-006" 'snmp|monitoring|report'
    result "ISS-006|수동확인|CPU/메모리 사용량 모니터링 및 주기적 보고 여부 수동 확인 (인터뷰 기반)"
}

# ISS-007: 보안장비 장애/보안이벤트 모니터링 실시 여부
check_applicable "ISS-007" "장애/이벤트 모니터링" && {
    paf "ISS-007" 'email-scheduler|snmp-trap|notification|alert'
    result "ISS-007|수동확인|알림 설정 ${PAF_N}건 — 이벤트 모니터링 체계 수동 확인"
}

# ISS-008: 탐지된 이벤트 및 로그에 대한 정기적 분석 및 보고 여부
check_applicable "ISS-008" "이벤트 분석/보고" && {
    paf "ISS-008" 'log-forwarding|report|analytics'
    result "ISS-008|수동확인|보안이벤트 정기 분석/보고 여부 수동 확인 (보안관제보고서 확인)"
}

# ISS-009: RAW 패킷 저장 여부
check_applicable "ISS-009" "RAW 패킷 저장" && {
    paf "ISS-009" 'packet-capture|pcap|extended-capture|threat-pcap'
    result "ISS-009|수동확인|패킷 캡처 설정 ${PAF_N}건 — RAW 패킷 저장 여부 수동 확인"
}

# ISS-010: TCP/UDP/ICMP 탐지/차단 패턴 적용 여부
check_applicable "ISS-010" "Flooding 탐지/차단" && {
    paf "ISS-010" 'flood|zone-protection|dos-protection|icmp|syn-cookies'
    result "ISS-010|수동확인|DoS/Flooding 설정 ${PAF_N}건 — TCP/UDP/ICMP 탐지/차단 패턴 수동 확인"
}

# ISS-011: Port Scan 탐지/차단 패턴 적용 여부
check_applicable "ISS-011" "Port Scan 탐지/차단" && {
    paf "ISS-011" 'port.*scan|reconnaissance|zone-protection'
    result "ISS-011|수동확인|Port Scan 탐지 설정 ${PAF_N}건 — 차단 정책 수동 확인"
}

# ISS-012: 해킹 툴 탐지/차단 패턴 적용 여부
check_applicable "ISS-012" "해킹 툴 탐지/차단" && {
    paf "ISS-012" 'threat|anti-spyware|vulnerability|antivirus|wildfire'
    result "ISS-012|수동확인|Threat/AV 설정 ${PAF_N}건 — 해킹 툴 탐지/차단 패턴 수동 확인"
}

# ISS-013: Source Routing 차단
check_applicable "ISS-013" "Source Routing 차단" && {
    paf "ISS-013" 'source.*rout|ip-option|strict-ip'
    result "ISS-013|수동확인|Source Routing 차단 설정 수동 확인"
}

# ISS-014: SNMP 비활성화
check_applicable "ISS-014" "SNMP 비활성화" && {
    paf "ISS-014" 'snmp|community'
    if [ "$PAF_N" -gt 0 ]; then
        result "ISS-014|수동확인|SNMP 설정 ${PAF_N}건 — 사용 필요성 수동 확인"
    elif [ "$PA_SYSN" -gt 0 ]; then
        result "ISS-014|양호|SNMP 미사용 (deviceconfig system 에 snmp 설정 없음)"
    else
        result "ISS-014|점검불가|${PA_NOSYS}"
    fi
}

# ISS-015: SNMP 안전 버전
check_applicable "ISS-015" "SNMP 안전 버전" && {
    paf "ISS-015" 'snmp|community|version'
    PA_COMMS=$(printf '%s\n' "$PA_FLAT" | awk -F'\t' '{for(i=1;i<NF;i++) if($i=="snmp-community-string") print $(i+1)}')
    PA_V3=$(pa_cnt 'snmp.* v3|snmp.*authpwd|snmp.*privpwd')
    C_DEF=""; C_WEAK=""; C_OK=""
    while IFS= read -r cm; do
        [ -z "$cm" ] && continue
        if echo "$cm" | grep -qiE '^(public|private)$'; then C_DEF="${C_DEF}$(mask_str "$cm") "
        elif str_complex "$cm"; then C_OK="${C_OK}$(mask_str "$cm") "
        else C_WEAK="${C_WEAK}$(mask_str "$cm")(${#cm}자) "; fi
    done <<< "$PA_COMMS"
    if [ -n "$C_DEF" ]; then
        result "ISS-015|취약|SNMP 기본 community(public/private) 사용: ${C_DEF% }"
    elif [ -n "$C_WEAK" ]; then
        result "ISS-015|취약|SNMPv2c community 복잡도 미달(2종 10자/3종 8자): ${C_WEAK% }"
    elif [ -n "$C_OK" ]; then
        result "ISS-015|수동확인|SNMPv2c community 복잡도 충족(${C_OK% }) — SNMPv3 사용 가능 환경에서 v2c 사용 여부 확인 (가능 시 취약)"
    elif [ "$PAF_N" -gt 0 ]; then
        result "ISS-015|수동확인|SNMP 설정 ${PAF_N}건(v3 항목 ${PA_V3}건) — SNMPv3 사용 및 인증/암호화 설정 수동 확인"
    elif [ "$PA_SYSN" -gt 0 ]; then
        result "ISS-015|양호|SNMP 미사용"
    else
        result "ISS-015|점검불가|${PA_NOSYS}"
    fi
}

# ISS-016: 보안 접속
check_applicable "ISS-016" "보안 접속" && {
    paf "ISS-016" 'disable-http|disable-telnet|disable-ssh|disable-https|management-profile|interface-management-profile|permitted-ip|(^| )(http|telnet|ssh|https) (yes|no)$'
    # 관리 서비스 disable-http/disable-telnet 가 no(=허용), 인터페이스 관리 프로파일에서 http/telnet 이 yes → 평문 관리 접속 허용 (PAN-OS 기본은 비활성)
    PLAIN=$(printf '%s\n' "$PA_FLAT" | tr '\t' ' ' | grep -iE '(^| )(disable-http|disable-telnet) no$|(^| )(http|telnet) yes$' | sed -E 's/^(.* )?(disable-http|disable-telnet|http|telnet) (no|yes)$/\2=\3/' | sort -u | tr '\n' ' ')
    if [ -n "$PLAIN" ]; then
        result "ISS-016|취약|평문 관리 프로토콜 허용 설정: ${PLAIN% } — HTTPS/SSH 전용 사용 필요"
    elif [ "$PA_SYSN" -gt 0 ] || [ "$(pa_cnt 'interface-management-profile')" -gt 0 ]; then
        result "ISS-016|양호|HTTP/Telnet 관리 접속 허용 설정 없음 (PAN-OS 기본 비활성)"
    else
        result "ISS-016|점검불가|${PA_NOSYS}"
    fi
}

# ISS-017: Default 계정 변경
check_applicable "ISS-017" "Default 계정 변경" && {
    paf "ISS-017" 'mgt-config users|admin'
    PA_USERS=$(printf '%s\n' "$PA_FLAT" | awk -F'\t' '{for(i=1;i<NF;i++) if($i=="mgt-config" && $(i+1)=="users") print $(i+2)}' | sort -u | tr '\n' ' ')
    if [ -z "$PA_USERS" ]; then
        result "ISS-017|점검불가|mgt-config users 섹션 없음(부분 config) — 관리자 계정명을 확인할 수 없음"
    elif echo " $PA_USERS" | grep -qiE ' (admin|administrator) '; then
        result "ISS-017|취약|기본 관리자 계정명(admin) 미변경 (계정: ${PA_USERS% })"
    else
        result "ISS-017|양호|기본 admin 계정명 변경됨 (계정: ${PA_USERS% })"
    fi
}

# ISS-018: Default 비밀번호 변경
check_applicable "ISS-018" "Default 비밀번호 변경" && {
    paf "ISS-018" 'password-complexity|min-length|min-uppercase|phash'
    PW=$(pa_cnt 'password-complexity|min-length')
    if [ "$PW" -gt 0 ]; then
        result "ISS-018|수동확인|비밀번호 복잡도 정책 설정됨 — 기본 비밀번호 변경 여부 수동 확인"
    else
        result "ISS-018|수동확인|비밀번호 복잡도 정책 수동 확인"
    fi
}

# ISS-019: 계정 관리 적정성
check_applicable "ISS-019" "계정 관리 적정성" && {
    paf "ISS-019" 'mgt-config users|role|admin-role'
    result "ISS-019|수동확인|관리자 계정 현황 — 개인별 계정 사용 및 공용 계정 여부 수동 확인 (증적 참조)"
}

# ISS-020: 계정별 권한 설정
check_applicable "ISS-020" "계정별 권한 설정" && {
    paf "ISS-020" 'admin-role|role-based|role|superuser|deviceadmin'
    result "ISS-020|수동확인|권한 설정 ${PAF_N}건 — 계정별 최소권한 원칙 준수 수동 확인"
}

# ISS-021: 원격 관리 접근 통제
check_applicable "ISS-021" "원격 관리 접근 통제" && {
    paf "ISS-021" 'permitted-ip|access-management|management-only|login-setting'
    # 전체 허용(0.0.0.0/0, ::/0, any)은 제한으로 보지 않음
    PERM_DEV=$(printf '%s\n' "$PA_FLAT" | awk -F'\t' '{for(i=1;i<NF;i++) if($i=="deviceconfig" && $(i+1)=="system" && $(i+2)=="permitted-ip") print $(i+3)}' | grep -vE '^(0\.0\.0\.0/0|::/0|any)$' | awk 'NF' | wc -l | tr -d ' ')
    PERM_PRF=$(printf '%s\n' "$PA_FLAT" | awk -F'\t' '{for(i=1;i<NF;i++) if($i=="permitted-ip" && $(i-1)!="system") print $(i+1)}' | grep -vE '^(0\.0\.0\.0/0|::/0|any)$' | awk 'NF' | wc -l | tr -d ' ')
    if [ "$PERM_DEV" -gt 0 ] || [ "$PERM_PRF" -gt 0 ]; then
        result "ISS-021|양호|관리 접근 IP 제한 설정됨 (장비 permitted-ip ${PERM_DEV}건, 인터페이스 관리 프로파일 permitted-ip ${PERM_PRF}건; 0.0.0.0/0 제외)"
    elif [ "$PA_SYSN" -gt 0 ]; then
        result "ISS-021|수동확인|permitted-ip 미설정(또는 0.0.0.0/0) — 관리 인터페이스 망 분리·상위 방화벽 등 장비 접근제어 여부 확인 (미통제 시 취약)"
    else
        result "ISS-021|점검불가|${PA_NOSYS}"
    fi
}

# ISS-022: 접속 로깅
check_applicable "ISS-022" "접속 로깅" && {
    paf "ISS-022" 'auth.*log|system.*log|login|log-setting'
    result "ISS-022|수동확인|관리자 접속 성공/실패 로깅 설정 수동 확인"
}

# ISS-023: 로그인 실패 제한 (PAN-OS 기본값: failed-attempts 0 = 제한 없음)
check_applicable "ISS-023" "로그인 실패 제한" && {
    paf "ISS-023" 'lockout|failed-attempts|login-setting'
    # 장비(관리자) 잠금: deviceconfig setting management admin-lockout failed-attempts, 인증 프로파일: lockout failed-attempts (관리자에게 지정된 경우에만 적용)
    LOCKOUT=$(printf '%s\n' "$PA_FLAT" | awk -F'\t' '{for(i=1;i<NF;i++) if($i=="failed-attempts" && $(i-1)=="admin-lockout") print $(i+1)}' | head -1)
    LOCK_PRF=$(printf '%s\n' "$PA_FLAT" | awk -F'\t' '{for(i=1;i<NF;i++) if($i=="failed-attempts" && $(i-1)!="admin-lockout") printf "%s ", $(i+1)}')
    if [ -n "$LOCKOUT" ] && [ "$LOCKOUT" -ge 1 ] 2>/dev/null && [ "$LOCKOUT" -le 5 ]; then
        result "ISS-023|양호|로그인 실패 잠금 임계값 failed-attempts ${LOCKOUT}회 (5회 이내)"
    elif [ -n "$LOCKOUT" ] && [ "$LOCKOUT" -gt 5 ] 2>/dev/null; then
        result "ISS-023|취약|로그인 실패 잠금 임계값 ${LOCKOUT}회 — 5회 이내 설정 필요"
    elif [ -n "$LOCKOUT" ]; then
        result "ISS-023|취약|로그인 실패 잠금 임계값 ${LOCKOUT} (0=제한 없음) — 5회 이내 설정 필요"
    elif [ -n "$LOCK_PRF" ]; then
        result "ISS-023|수동확인|장비 공통 admin-lockout 미설정(기본값 0=잠금 없음), 인증 프로파일 lockout failed-attempts ${LOCK_PRF% }회 — 해당 프로파일이 관리자 계정에 적용되는지 수동 확인"
    elif [ "$PA_SYSN" -gt 0 ]; then
        result "ISS-023|취약|failed-attempts 미설정 — PAN-OS 기본값 0(잠금 없음) 적용, 인증 프로파일별 lockout 은 증적 참조"
    else
        result "ISS-023|점검불가|${PA_NOSYS}"
    fi
}

# ISS-024: 세션 타임아웃 (PAN-OS 기본값: 관리자 idle-timeout 60분)
check_applicable "ISS-024" "세션 타임아웃" && {
    paf "ISS-024" 'idle-timeout|timeout|login-setting'
    # 관리자 세션: deviceconfig setting management idle-timeout (GlobalProtect 등 다른 idle-timeout 은 제외)
    TIMEOUT=$(printf '%s\n' "$PA_FLAT" | awk -F'\t' '{for(i=2;i<NF;i++) if($i=="idle-timeout" && $(i-1)=="management") print $(i+1)}' | head -1)
    if [ -n "$TIMEOUT" ] && [ "$TIMEOUT" -ge 1 ] 2>/dev/null && [ "$TIMEOUT" -le 15 ]; then
        result "ISS-024|양호|관리자 idle-timeout ${TIMEOUT}분 설정"
    elif [ -n "$TIMEOUT" ] && [ "$TIMEOUT" -gt 15 ] 2>/dev/null; then
        result "ISS-024|취약|관리자 idle-timeout ${TIMEOUT}분 — 15분 이하 설정 필요 (내부 규정이 더 짧으면 그 기준)"
    elif [ -n "$TIMEOUT" ]; then
        result "ISS-024|취약|관리자 idle-timeout ${TIMEOUT} (0=제한 없음) — 15분 이하 설정 필요"
    elif [ "$PA_SYSN" -gt 0 ]; then
        result "ISS-024|취약|idle-timeout 미설정 — PAN-OS 기본값 60분 적용(15분 초과), 관리자 역할별 timeout 은 증적 참조"
    else
        result "ISS-024|점검불가|${PA_NOSYS}"
    fi
}

# ISS-025: NTP 설정
check_applicable "ISS-025" "NTP 설정" && {
    paf "ISS-025" 'ntp'
    NTP_ADDR=$(printf '%s\n' "$PA_FLAT" | awk -F'\t' '{for(i=1;i<NF;i++) if($i=="ntp-server-address") print $(i+1)}' | tr '\n' ' ')
    if [ -n "$NTP_ADDR" ]; then
        result "ISS-025|양호|NTP 서버 지정됨 (${NTP_ADDR% })"
    elif [ "$PAF_N" -gt 0 ]; then
        result "ISS-025|수동확인|NTP 관련 설정 ${PAF_N}건이나 서버 주소(ntp-server-address) 미확인 — 수동 확인"
    elif [ "$PA_SYSN" -gt 0 ]; then
        result "ISS-025|취약|NTP 미설정"
    else
        result "ISS-025|점검불가|${PA_NOSYS}"
    fi
}

# ISS-026: 무결성 검사
check_applicable "ISS-026" "무결성 검사" && {
    paf "ISS-026" 'integrity|file-hash|wildfire'
    result "ISS-026|수동확인|주요 파일 무결성 검사 여부 수동 확인 (기능 미지원 시 N-A)"
}

# ISS-027: 기능외 서비스 제한
check_applicable "ISS-027" "기능외 서비스 제한" && {
    paf "ISS-027" 'interface-management-profile|http-server|telnet|dns-proxy'
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

# ISS-030: ANY/ALL 허용 금지 — 활성 allow 규칙 단위: destination any + (service any 또는 application any)
check_applicable "ISS-030" "ANY/ALL 허용 금지" && {
    evd "ISS-030" "pa_rules_dump"
    if [ "$PA_RULEN" -eq 0 ]; then
        result "ISS-030|점검불가|${PA_NORULE}"
    else
        P_BOTH=$(pa_allow | awk -F'\t' '(" " tolower($7) " ") ~ / any / && ((" " tolower($9) " ") ~ / any / || (" " tolower($8) " ") ~ / any /) {printf "%s ", $1}')
        P_ONE=$(pa_allow | awk -F'\t' '(" " tolower($7) " ") ~ / any / || (" " tolower($9) " ") ~ / any / {printf "%s ", $1}')
        if [ -n "$P_BOTH" ]; then
            result "ISS-030|취약|목적지 any + 서비스/애플리케이션 any 허용 규칙: ${P_BOTH% }"
        elif [ -n "$P_ONE" ]; then
            result "ISS-030|수동확인|목적지 또는 서비스 any 허용 규칙: ${P_ONE% } — 정당성 수동 확인"
        else
            result "ISS-030|양호|모든 목적지/서비스 허용(allow) 규칙 없음 ($(pa_allow | wc -l | tr -d ' ')개 활성 허용 규칙 검사)"
        fi
    fi
}

# ISS-031~039, 041: 정책 분석 (FW/VPN only)
check_applicable "ISS-031" "취약 서비스 대역 허용" && {
    evd "ISS-031" "pa_rules_dump"
    result "ISS-031|수동확인|취약 서비스 네트워크 대역 허용 정책 수동 확인"
}
check_applicable "ISS-032" "서비스 포트 적정성" && {
    evd "ISS-032" "pa_rules_dump"
    result "ISS-032|수동확인|과도한 서비스 포트 허용 정책 수동 확인"
}
check_applicable "ISS-033" "양방향 정책 금지" && {
    evd "ISS-033" "pa_rules_dump"
    result "ISS-033|수동확인|불필요 양방향 정책 존재 여부 수동 확인"
}
check_applicable "ISS-034" "정책 적용 순서" && {
    evd "ISS-034" "pa_rules_dump"
    result "ISS-034|수동확인|정책 적용 순서 적절성 수동 확인"
}
# ISS-035: source-port 가 지정된 서비스 객체(서비스 그룹 포함)를 쓰는 활성 allow 규칙이 있어야 취약 (객체만 정의돼 있으면 양호)
#          규칙이 참조한 서비스 객체의 정의가 config 에 없으면(부분 config) 판단할 수 없으므로 점검불가
pa_svc_scan() {  # 출력: USED:<이름들> / UNDEF:<이름들> / SRC:<이름들>
    { pa_allow | awk '{ print "@@RULE@@\t" $0 }'; printf '%s\n' "$PA_FLAT"; } | awk -F'\t' '
    $1 == "@@RULE@@" { rl[++nr] = $0; next }
    {
        isrule = 0; for (i = 1; i <= NF; i++) if ($i == "rules") isrule = 1
        if (isrule) next
        for (i = 1; i < NF; i++) {
            if ($i == "service" && $(i+1) != "") { def[$(i+1)] = 1; if ($(i+2) == "protocol") for (j = i + 3; j < NF; j++) if ($j == "source-port") srcp[$(i+1)] = 1 }
            if ($i == "service-group" && $(i+1) != "") { def[$(i+1)] = 1; if ($(i+2) == "members" && i + 3 <= NF) grp[$(i+1)] = grp[$(i+1)] " " $(i+3) }
        }
    }
    END {
        for (r = 1; r <= nr; r++) {
            split(rl[r], f, "\t"); e = f[10]
            for (k = 0; k < 4; k++) { q = ""; xn = split(e, x, " "); for (i = 1; i <= xn; i++) if (x[i] in grp) q = q " " grp[x[i]]; if (q == "") break; e = e q }
            xn = split(e, x, " ")
            for (i = 1; i <= xn; i++) {
                t = x[i]
                if (t in srcp) { if (!(t in used)) { used[t] = 1; us = us t " " } }
                else if (!(t in def) && t !~ /^(any|application-default|service-http|service-https)$/) { if (!(t in undef)) { undef[t] = 1; ud = ud t " " } }
            }
        }
        for (k in srcp) sp = sp k " "
        print "USED:" us; print "UNDEF:" ud; print "SRC:" sp
    }'
}
check_applicable "ISS-035" "출발지 포트 정책 금지" && {
    paf "ISS-035" 'source-port|src-port'
    evd "ISS-035" "pa_rules_dump"
    evd "ISS-035" "pa_svc_scan"
    if [ "$PA_RULEN" -eq 0 ]; then
        result "ISS-035|점검불가|${PA_NORULE}"
    else
        _scan=$(pa_svc_scan)
        USED=$(printf '%s\n' "$_scan" | sed -n 's/^USED://p'); UNDEF=$(printf '%s\n' "$_scan" | sed -n 's/^UNDEF://p'); SRC_SVC=$(printf '%s\n' "$_scan" | sed -n 's/^SRC://p')
        if [ -n "$USED" ]; then
            result "ISS-035|취약|출발지 포트(source-port) 지정 서비스(${USED% })를 쓰는 활성 allow 규칙 존재"
        elif [ -n "$UNDEF" ]; then
            result "ISS-035|점검불가|활성 allow 규칙이 참조한 서비스 객체(${UNDEF% })의 정의가 config 에 없어 source-port 사용 여부를 판단할 수 없음(부분 config) — service 객체를 포함한 전체 config 로 다시 추출"
        elif [ -n "$SRC_SVC" ]; then
            result "ISS-035|양호|source-port 지정 서비스 객체(${SRC_SVC% })는 있으나 사용하는 활성 allow 규칙 없음"
        else
            result "ISS-035|양호|출발지 포트 기반 서비스/정책 없음"
        fi
    fi
}
# ISS-036: 활성 allow 규칙의 application/service 멤버만 대상 (deny 규칙·비활성 규칙의 tftp 는 제외)
check_applicable "ISS-036" "취약 원격 서비스 금지" && {
    evd "ISS-036" "pa_rules_dump"
    if [ "$PA_RULEN" -eq 0 ]; then
        result "ISS-036|점검불가|${PA_NORULE}"
    else
        WEAK_R=$(pa_allow | awk -F'\t' '{ n=split($8 " " $9, a, " "); for (i=1;i<=n;i++) if (tolower(a[i]) ~ /^(tftp|rlogin|rsh|rexec|finger)(-.*)?$/) { printf "%s(%s) ", $1, a[i]; break } }')
        if [ -n "$WEAK_R" ]; then
            result "ISS-036|취약|취약 원격 서비스(r-계열/TFTP/Finger)를 허용하는 활성 allow 규칙: ${WEAK_R% }"
        else
            result "ISS-036|양호|취약 원격 서비스 허용 규칙 없음 ($(pa_allow | wc -l | tr -d ' ')개 활성 allow 규칙 검사)"
        fi
    fi
}
check_applicable "ISS-037" "불필요 정책 제거" && {
    paf "ISS-037" 'disabled'
    evd "ISS-037" "pa_rules_dump"
    DISABLED=$(pa_rules | awk -F'\t' '$3=="yes"' | wc -l | tr -d ' ')
    result "ISS-037|수동확인|비활성 규칙 ${DISABLED}건 — 미사용/불필요 정책 수동 확인"
}
check_applicable "ISS-038" "서버간 관리포트 금지" && {
    paf "ISS-038" 'ftp|ssh|telnet|rdp|mssql|mysql|oracle'
    result "ISS-038|수동확인|서버 ↔ 서버 간 관리포트 허용 정책 수동 확인"
}
check_applicable "ISS-039" "접근통제 우회 금지" && {
    evd "ISS-039" "pa_rules_dump"
    result "ISS-039|수동확인|접근통제시스템 우회 접속 정책 수동 확인"
}

# ISS-040: 비밀번호 주기적 변경
check_applicable "ISS-040" "비밀번호 주기적 변경" && {
    paf "ISS-040" 'password-profile|expiration|password-change|password-complexity'
    result "ISS-040|수동확인|비밀번호 주기적 변경(분기별 1회 이상) 여부 수동 확인"
}

# ISS-041: 네트워크 대역 설정 금지
check_applicable "ISS-041" "네트워크 대역 설정 금지" && {
    evd "ISS-041" "pa_rules_dump"
    ANYR=$(pa_allow | awk -F'\t' '(" " tolower($6) " " tolower($7) " ") ~ / any / {printf "%s ", $1}')
    if [ -n "$ANYR" ]; then
        result "ISS-041|수동확인|source/destination any 인 활성 allow 규칙: ${ANYR% } — 불필요 네트워크 대역 설정 수동 확인"
    elif [ "$PA_RULEN" -eq 0 ]; then
        result "ISS-041|점검불가|${PA_NORULE}"
    else
        result "ISS-041|수동확인|source/destination any 활성 allow 규칙 없음 — 네트워크 대역 객체 적정성 수동 확인"
    fi
}

# ISS-042: 차단 기능 활성화
check_applicable "ISS-042" "차단 기능 활성화" && {
    paf "ISS-042" '(^| )tap( |$)|virtual-wire|bypass|mode'
    TAP=$(pa_cnt '(^| )tap( |$)|bypass')
    if [ "$TAP" -gt 0 ]; then
        result "ISS-042|수동확인|TAP/Bypass 모드 ${TAP}건 — 차단 기능 활성 여부 수동 확인"
    else
        result "ISS-042|수동확인|차단 기능 활성 및 최근 차단 로그 수동 확인"
    fi
}

# ISS-043: EoS 장비 교체
check_applicable "ISS-043" "EoS 장비 교체" && {
    paf "ISS-043" 'sw-version|PAN-OS|model|serial'
    PA_VER=$(printf '%s\n' "$PA_FLAT" | tr '\t' ' ' | grep -iE "sw-version|PAN-OS" | head -1)
    [ -z "$PA_VER" ] && PA_VER=$(printf '%s\n' "$TEXT" | sed -n 's/.*<config version="\([^"]*\)".*/config version \1/p' | head -1)
    result "ISS-043|수동확인|PAN-OS 버전: ${PA_VER:-미탐지} — 벤더사 Lifecycle 표 대조 필요"
}
}


# ================================================================
# 일반 (벤더 불문 공통 기본 점검)
# ================================================================
check_generic() {

check_applicable "ISS-001" "정책 및 로그 백업" && {
    evd "ISS-001" "echo \"\$TEXT_M\" | grep -i 'backup\|log.*server\|archive'"
    result "ISS-001|수동확인|정책/로그 백업 주기 및 절차 수동 확인 (벤더 미식별)"
}
check_applicable "ISS-002" "원격 로그 서버" && {
    evd "ISS-002" "echo \"\$TEXT_M\" | grep -i 'syslog\|log.*server\|remote.*log'"
    SYSLOG=$(echo "$TEXT" | grep -ci "syslog\|log.*server\|remote.*log" 2>/dev/null || true)
    if [ "$SYSLOG" -gt 0 ]; then
        result "ISS-002|수동확인|로그서버 관련 설정 ${SYSLOG}건 — 연동 상태 수동 확인"
    else
        result "ISS-002|수동확인|원격 로그서버 설정 수동 확인"
    fi
}
check_applicable "ISS-003" "DMZ 구간 설정" && {
    evd "ISS-003" "echo \"\$TEXT_M\" | grep -i 'dmz\|zone'"
    result "ISS-003|수동확인|DMZ 구간 설정 여부 수동 확인"
}
check_applicable "ISS-004" "NAT 정책 적정성" && {
    evd "ISS-004" "echo \"\$TEXT_M\" | grep -i 'nat\|static\|dynamic'"
    result "ISS-004|수동확인|NAT 정책 적정성 수동 확인"
}
check_applicable "ISS-005" "보안패치 적용" && {
    evd "ISS-005" "echo \"\$TEXT_M\" | grep -i 'version\|firmware\|build\|release'"
    result "ISS-005|수동확인|펌웨어/패치 현황 수동 확인"
}
check_applicable "ISS-006" "사용량 점검/보고" && {
    evd "ISS-006" "echo \"\$TEXT_M\" | grep -i 'monitor\|resource\|cpu\|memory'"
    result "ISS-006|수동확인|사용량 모니터링 및 보고 절차 수동 확인"
}
check_applicable "ISS-007" "장애/이벤트 모니터링" && {
    evd "ISS-007" "echo \"\$TEXT_M\" | grep -i 'alert\|notification\|trap\|alarm'"
    result "ISS-007|수동확인|장애/이벤트 모니터링 체계 수동 확인"
}
check_applicable "ISS-008" "이벤트 분석/보고" && {
    evd "ISS-008" "echo \"\$TEXT_M\" | grep -i 'report\|log.*analysis\|analytics'"
    result "ISS-008|수동확인|보안이벤트 정기 분석/보고 수동 확인"
}
check_applicable "ISS-009" "RAW 패킷 저장" && {
    evd "ISS-009" "echo \"\$TEXT_M\" | grep -i 'packet\|capture\|pcap'"
    result "ISS-009|수동확인|RAW 패킷 저장 설정 수동 확인"
}
check_applicable "ISS-010" "Flooding 탐지/차단" && {
    evd "ISS-010" "echo \"\$TEXT_M\" | grep -i 'flood\|dos\|rate.*limit\|threshold'"
    result "ISS-010|수동확인|TCP/UDP/ICMP Flooding 탐지/차단 패턴 수동 확인"
}
check_applicable "ISS-011" "Port Scan 탐지/차단" && {
    evd "ISS-011" "echo \"\$TEXT_M\" | grep -i 'scan\|reconnaissance\|probe'"
    result "ISS-011|수동확인|Port Scan 탐지/차단 패턴 수동 확인"
}
check_applicable "ISS-012" "해킹 툴 탐지/차단" && {
    evd "ISS-012" "echo \"\$TEXT_M\" | grep -i 'ips\|ids\|malware\|antivirus\|signature'"
    result "ISS-012|수동확인|해킹 툴/악성코드 탐지/차단 패턴 수동 확인"
}
check_applicable "ISS-013" "Source Routing 차단" && {
    evd "ISS-013" "echo \"\$TEXT_M\" | grep -i 'source.*rout\|ip.*option'"
    result "ISS-013|수동확인|Source Routing 차단 설정 수동 확인"
}
check_applicable "ISS-014" "SNMP 비활성화" && {
    evd "ISS-014" "echo \"\$TEXT_M\" | grep -i 'snmp'"
    SNMP=$(echo "$TEXT" | grep -ci "snmp" 2>/dev/null || true)
    result "ISS-014|수동확인|SNMP 설정 ${SNMP}건 — 사용 필요성 수동 확인"
}
check_applicable "ISS-015" "SNMP 안전 버전" && {
    evd "ISS-015" "echo \"\$TEXT_M\" | grep -i 'snmp.*v3\|snmp.*version\|community'"
    result "ISS-015|수동확인|SNMP 버전 및 community 설정 수동 확인 (v3/AuthPriv 권장)"
}
check_applicable "ISS-016" "보안 접속" && {
    evd "ISS-016" "echo \"\$TEXT_M\" | grep -i 'ssh\|https\|telnet\|http[^s]'"
    result "ISS-016|수동확인|보안 접속(SSH/HTTPS) 사용 여부 수동 확인"
}
check_applicable "ISS-017" "Default 계정 변경" && {
    evd "ISS-017" "echo \"\$TEXT_M\" | grep -i 'admin\|user\|account\|login'"
    result "ISS-017|수동확인|Default 계정 변경 여부 수동 확인"
}
check_applicable "ISS-018" "Default 비밀번호 변경" && {
    evd "ISS-018" "echo \"\$TEXT_M\" | grep -i 'password\|passwd\|secret'"
    result "ISS-018|수동확인|Default 비밀번호 변경 및 복잡도 수동 확인"
}
check_applicable "ISS-019" "계정 관리 적정성" && {
    evd "ISS-019" "echo \"\$TEXT_M\" | grep -i 'user\|admin\|account\|privilege'"
    result "ISS-019|수동확인|계정 관리(개인별 계정, 공용 계정 금지) 수동 확인"
}
check_applicable "ISS-020" "계정별 권한 설정" && {
    evd "ISS-020" "echo \"\$TEXT_M\" | grep -i 'privilege\|role\|level\|access'"
    result "ISS-020|수동확인|계정별 권한 설정 수동 확인"
}
check_applicable "ISS-021" "원격 관리 접근 통제" && {
    evd "ISS-021" "echo \"\$TEXT_M\" | grep -i 'access.*list\|acl\|permit\|trusted\|management'"
    result "ISS-021|수동확인|원격 관리 접근 IP 제한 수동 확인"
}
check_applicable "ISS-022" "접속 로깅" && {
    evd "ISS-022" "echo \"\$TEXT_M\" | grep -i 'log.*login\|auth.*log\|audit'"
    result "ISS-022|수동확인|접속 성공/실패 로깅 수동 확인"
}
check_applicable "ISS-023" "로그인 실패 제한" && {
    evd "ISS-023" "echo \"\$TEXT_M\" | grep -i 'lockout\|login.*fail\|attempts'"
    result "ISS-023|수동확인|로그인 실패 제한(5회 이내) 수동 확인"
}
check_applicable "ISS-024" "세션 타임아웃" && {
    evd "ISS-024" "echo \"\$TEXT_M\" | grep -i 'timeout\|idle\|session.*time'"
    result "ISS-024|수동확인|세션 타임아웃 설정 수동 확인"
}
check_applicable "ISS-025" "NTP 설정" && {
    evd "ISS-025" "echo \"\$TEXT_M\" | grep -i 'ntp\|clock\|time.*server'"
    result "ISS-025|수동확인|NTP 설정 수동 확인"
}
check_applicable "ISS-026" "무결성 검사" && {
    evd "ISS-026" "echo \"\$TEXT_M\" | grep -i 'integrity\|hash\|checksum'"
    result "ISS-026|수동확인|주요 파일 무결성 검사 수동 확인"
}
check_applicable "ISS-027" "기능외 서비스 제한" && {
    evd "ISS-027" "echo \"\$TEXT_M\" | grep -i 'service\|server\|enable'"
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
    evd "ISS-030" "echo \"\$TEXT_M\" | grep -i 'any\|all\|permit'"
    result "ISS-030|수동확인|ANY 목적지/ALL 서비스 허용 정책 수동 확인"
}
check_applicable "ISS-031" "취약 서비스 대역 허용" && {
    evd "ISS-031" "echo \"\$TEXT_M\" | grep -iE 'ftp|ssh|telnet|rdp|mssql|mysql|oracle'"
    result "ISS-031|수동확인|취약 서비스 네트워크 대역 허용 수동 확인"
}
check_applicable "ISS-032" "서비스 포트 적정성" && {
    evd "ISS-032" "echo \"\$TEXT_M\" | grep -i 'port\|service.*all\|1024.*65535'"
    result "ISS-032|수동확인|서비스 포트 허용 정책 적정성 수동 확인"
}
check_applicable "ISS-033" "양방향 정책 금지" && {
    evd "ISS-033" "echo \"\$TEXT_M\" | grep -i 'bidirect\|both\|inbound\|outbound'"
    result "ISS-033|수동확인|불필요 양방향 정책 수동 확인"
}
check_applicable "ISS-034" "정책 적용 순서" && {
    evd "ISS-034" "echo \"\$TEXT_M\" | grep -i 'rule\|policy\|seq\|priority'"
    result "ISS-034|수동확인|정책 적용 순서 적절성 수동 확인"
}
check_applicable "ISS-035" "출발지 포트 정책 금지" && {
    evd "ISS-035" "echo \"\$TEXT_M\" | grep -i 'source.*port\|src.*port'"
    result "ISS-035|수동확인|출발지 포트 기반 정책 수동 확인"
}
check_applicable "ISS-036" "취약 원격 서비스 금지" && {
    evd "ISS-036" "echo \"\$TEXT_M\" | grep -iE 'tftp|rlogin|rsh|rexec|finger|512|513|514'"
    result "ISS-036|수동확인|취약 원격 서비스(r-계열/TFTP) 허용 수동 확인"
}
check_applicable "ISS-037" "불필요 정책 제거" && {
    evd "ISS-037" "echo \"\$TEXT_M\" | grep -i 'disable\|inactive\|unused'"
    result "ISS-037|수동확인|미사용/불필요 정책 존재 수동 확인"
}
check_applicable "ISS-038" "서버간 관리포트 금지" && {
    evd "ISS-038" "echo \"\$TEXT_M\" | grep -iE 'ftp|ssh|telnet|rdp|mssql|mysql|oracle|3389|1433|1521|3306'"
    result "ISS-038|수동확인|서버간 관리포트 허용 수동 확인"
}
check_applicable "ISS-039" "접근통제 우회 금지" && {
    evd "ISS-039" "echo \"\$TEXT_M\" | grep -i 'policy\|rule\|permit\|source\|destination'"
    result "ISS-039|수동확인|접근통제 우회 접속 정책 수동 확인"
}
check_applicable "ISS-040" "비밀번호 주기적 변경" && {
    evd "ISS-040" "echo \"\$TEXT_M\" | grep -i 'password.*expire\|passwd.*age\|rotation'"
    result "ISS-040|수동확인|비밀번호 주기적 변경(분기별 1회 이상) 수동 확인"
}
check_applicable "ISS-041" "네트워크 대역 설정 금지" && {
    evd "ISS-041" "echo \"\$TEXT_M\" | grep -i 'any\|0.0.0.0\|subnet\|/0\|/8\|/16'"
    result "ISS-041|수동확인|불필요 네트워크 대역 설정 수동 확인"
}
check_applicable "ISS-042" "차단 기능 활성화" && {
    evd "ISS-042" "echo \"\$TEXT_M\" | grep -i 'bypass\|tap\|monitor\|inline\|block\|deny'"
    result "ISS-042|수동확인|차단 기능 활성화 및 차단 로그 수동 확인"
}
check_applicable "ISS-043" "EoS 장비 교체" && {
    evd "ISS-043" "echo \"\$TEXT_M\" | grep -i 'version\|firmware\|model\|serial\|build'"
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
_TOTAL=$((_CP + _CF + _CM + _CN + _CU))
echo "# ================================================================"
echo "# 점검 요약 — 전자금융기반시설 (ISS)"
echo "#   총 점검 항목: ${_TOTAL} / 43"
echo "#   장비유형: ${DEV_TYPE} / 벤더: ${VENDOR}"
[ "$_TOTAL" -gt 0 ] && {
echo "#   양호:         ${_CP}  ($((_CP * 100 / _TOTAL))%)"
echo "#   취약:         ${_CF}  ($((_CF * 100 / _TOTAL))%)"
echo "#   수동확인:     ${_CM}"
echo "#   점검불가:     ${_CU}"
echo "#   N-A:          ${_CN}"
}
echo "# ================================================================"
echo "# 점검 완료: $(date '+%Y-%m-%d %H:%M:%S')"
echo "# 증적 파일: ${_EVD}"
[ -n "$_RESF" ] && echo "# 결과 파일(자동 저장): ${_RESF}  ← 증적 파일과 함께 회수"
[ -n "$_TEEPID" ] && { exec >&- 2>/dev/null; wait "$_TEEPID" 2>/dev/null; sleep 1; }
exit 0
