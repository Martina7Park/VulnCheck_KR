#!/bin/bash
# ================================================================
# PC 단말(macOS) 보안 취약점 자동 점검 스크립트 v1.1
# ================================================================
#
# [용도]
#   전자금융기반시설 업무용 PC(macOS) 보안 점검. (주요정보 2026 상세가이드 PC-01~18 은 check_pc_mac_kisa.sh 사용)
#   기준: 전자금융기반시설 PC(업무용 단말) 자체 점검 항목 PC-01~18 (전자금융 평가기준에 PC 분야 없음)
#   Windows PC는 check_pc.ps1 사용.
#
# [대상 OS]
#   macOS 12 (Monterey) 이상 (bash 3.2 호환)
#
# [사전 조건]
#   - sudo(root) 실행 권장: 시스템 데몬(launchctl)·원격 로그인(systemsetup)·암호 정책(pwpolicy) 조회에 필요.
#     비root 로 실행하면 이들을 확인할 수 없는 항목은 '점검불가' 로 출력된다.
#   - sudo 로 실행해도 사용자 설정(화면 잠금·Safari 등)은 SUDO_USER 또는 콘솔 로그인 사용자 기준으로 읽는다.
#
# [실행 방법]
#   sudo bash check_pc_mac.sh > ~/Desktop/PC_$(scutil --get ComputerName | tr ' /' '__').txt
#
# [산출물]
#   1) 표준출력 — 파이프 구분자 결과 (파일로 리다이렉트하지 않아도 스크립트 폴더에 PC_<호스트명>.txt 사본이 자동 저장됨)
#      형식: PC-항목코드|결과|근거설명
#      결과: 양호 / 취약 / 수동확인 / 점검불가 / N-A
#      헤더: # IP / # 실행 계정 / # 클라우드 (컨버터가 사용)
#   2) 증적 파일 — 스크립트와 같은 디렉터리/<호스트명>_pc_mac_evidence.txt
#      점검 중 실행한 명령어·출력 전체·판정 근거가 타임스탬프와 함께 기록됨
#
# ================================================================

umask 077
# bash 3.2 (macOS 기본) 호환 — declare -A, ${v,,} 등 bash 4 전용 구문 미사용

HN=$(scutil --get ComputerName 2>/dev/null || hostname -s 2>/dev/null || echo Unknown)
HN=$(echo "$HN" | tr ' /' '__')
_DIR="$(cd "$(dirname "$0")" && pwd)"
_safe_new() { [ -L "$1" ] && rm -f "$1"; return 0; }   # 심볼릭 링크는 따라가지 않고 지운 뒤 새로 만든다

# ── 실행 권한 / 사용자 설정을 읽을 대상 계정 ──
#   root(sudo) : 시스템 데몬·공유·보안 정책까지 조회 가능. 사용자 설정은 SUDO_USER 또는 콘솔 사용자 기준으로 읽는다
#   비root     : launchctl 시스템 도메인·systemsetup·pwpolicy 등은 조회 불가 → 해당 항목은 '점검불가'
IS_ROOT=0; [ "$(id -u)" -eq 0 ] && IS_ROOT=1
RUN_USER=$(id -un 2>/dev/null)
CON_USER=$(stat -f %Su /dev/console 2>/dev/null)
if [ "$IS_ROOT" -eq 1 ]; then
    TUSER="${SUDO_USER:-}"
    { [ -z "$TUSER" ] || [ "$TUSER" = "root" ]; } && TUSER="$CON_USER"
    [ "$TUSER" = "root" ] && TUSER=""        # 콘솔에 로그인한 사용자 없음(로그인 창)
else
    TUSER="$RUN_USER"
fi
NEED_ROOT="root 권한 필요 - 비root(sudo 없이) 실행되어 점검불가"

# urd <defaults 인자...>: 대상 사용자의 설정을 읽는다 (sudo -n: 암호 프롬프트로 멈추지 않음). 예) urd read com.apple.screensaver askForPassword
urd() {
    if [ "$IS_ROOT" -eq 1 ]; then
        [ -n "$TUSER" ] || return 3
        sudo -n -H -u "$TUSER" defaults "$@" 2>/dev/null
    else
        defaults "$@" 2>/dev/null
    fi
}
# 로컬 포트 리슨 여부 (비root 에서도 가능): 열려 있으면 서비스가 켜진 것
port_open() { nc -z -w 1 127.0.0.1 "$1" >/dev/null 2>&1; }
# svc_state <launchd 라벨> <포트>: on / off / unk  (root: launchctl 적재 여부, 비root: 포트가 열려 있으면 on, 아니면 unk)
svc_state() {
    if [ "$IS_ROOT" -eq 1 ]; then
        if launchctl list 2>/dev/null | awk -v l="$1" '$3==l{f=1} END{exit f?0:1}'; then echo on; else echo off; fi
    else
        if [ -n "$2" ] && port_open "$2"; then echo on; else echo unk; fi
    fi
}

# ── 헤더 메타데이터: IP / 실행 계정 / 클라우드 ──
ip_list() {
    local ips
    ips=$(ifconfig 2>/dev/null | awk '/inet /{print $2}' | grep -v '^127\.' | awk '!s[$0]++' | tr '\n' ',' | sed 's/,/, /g;s/, $//')
    echo "${ips:-미확인}"
}
cloud_info() {
    command -v curl >/dev/null 2>&1 || { echo "미확인"; return; }
    local base="http://169.254.169.254" tok rc id rg sg mac az vm loc g z
    local H; H=()
    tok=$(curl -s -m 2 --connect-timeout 2 -X PUT -H "X-aws-ec2-metadata-token-ttl-seconds: 60" "$base/latest/api/token" 2>/dev/null); rc=$?
    # 6=DNS, 7=연결 실패, 28=타임아웃 → 메타데이터 주소에 연결 불가(온프레미스)
    if [ "$rc" -eq 6 ] || [ "$rc" -eq 7 ] || [ "$rc" -eq 28 ]; then echo "없음"; return; fi
    [ -n "$tok" ] && H=(-H "X-aws-ec2-metadata-token: $tok")
    id=$(curl -s -m 2 --connect-timeout 2 ${H[@]+"${H[@]}"} "$base/latest/meta-data/instance-id" 2>/dev/null)
    case "$id" in
        i-*)
            rg=$(curl -s -m 2 --connect-timeout 2 ${H[@]+"${H[@]}"} "$base/latest/meta-data/placement/region" 2>/dev/null)
            mac=$(curl -s -m 2 --connect-timeout 2 ${H[@]+"${H[@]}"} "$base/latest/meta-data/network/interfaces/macs/" 2>/dev/null | awk 'NF{print; exit}')
            sg=""; [ -n "$mac" ] && sg=$(curl -s -m 2 --connect-timeout 2 ${H[@]+"${H[@]}"} "$base/latest/meta-data/network/interfaces/macs/${mac}security-group-ids" 2>/dev/null | awk 'NF' | tr '\n' ',' | sed 's/,$//')
            echo "AWS (instance $id, region ${rg:-미확인}, SG: ${sg:-미확인})"; return ;;
    esac
    az=$(curl -s -m 2 --connect-timeout 2 -H "Metadata: true" "$base/metadata/instance?api-version=2021-02-01" 2>/dev/null)
    if echo "$az" | grep -q '"vmId"'; then
        vm=$(echo "$az" | sed -n 's/.*"vmId"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | awk 'NR==1')
        loc=$(echo "$az" | sed -n 's/.*"location"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | awk 'NR==1')
        echo "Azure (vmId ${vm:-미확인}, region ${loc:-미확인})"; return
    fi
    g=$(curl -s -m 2 --connect-timeout 2 -H "Metadata-Flavor: Google" "$base/computeMetadata/v1/instance/id" 2>/dev/null)
    if [ -n "$g" ] && ! echo "$g" | grep -qi '<html'; then
        z=$(curl -s -m 2 --connect-timeout 2 -H "Metadata-Flavor: Google" "$base/computeMetadata/v1/instance/zone" 2>/dev/null | awk -F/ '{print $NF}')
        echo "GCP (instance $g, zone ${z:-미확인})"; return
    fi
    echo "미확인"
}

# ── 증적 기록: 출력 전체(2000줄 초과분만 생략 표시), 비어 있으면 그 사실을 기록 ──
evd() {
    local item="$1"; shift
    printf '[%s] %s $ %s\n' "$item" "$(date '+%H:%M:%S')" "$*" >> "$_EVD"
    local _o _n
    _o=$(eval "$@" 2>&1)
    if [ -z "$_o" ]; then
        printf '(출력 없음)\n' >> "$_EVD"
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
# evq <항목> <설명> <값...>: 판정에 쓴 계산값(변수)을 증적에 그대로 기록
evq() {
    local item="$1" desc="$2"; shift 2
    printf '[%s] %s %s\n' "$item" "$(date '+%H:%M:%S')" "$desc" >> "$_EVD"
    if [ $# -eq 0 ] || [ -z "$*" ]; then printf '(값 없음)\n' >> "$_EVD"; else printf '%s\n' "$@" >> "$_EVD"; fi
    printf '\n' >> "$_EVD"
}
# result 는 항상 0 을 반환 — `조건 && result A || result B` 에서 B 가 중복 출력되지 않도록
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
    printf '[판정] %s\n\n' "$1" >> "$_EVD"
    return 0
}

# ── 결과 사본 자동 저장: '> 파일' 리다이렉트를 빠뜨려도 판정 결과가 증적과 같은 위치에 남도록 표준출력을 복사 ──
_RESF="${_DIR}/PC_${HN}.txt"
_safe_new "$_RESF"
if [ -z "$NO_RESULT_COPY" ] && ! [ /dev/fd/1 -ef "$_RESF" ] 2>/dev/null && ( : > "$_RESF" ) 2>/dev/null; then
    exec > >(tee "$_RESF"); _TEEPID=$!
else
    _RESF=""
fi
OS_VER=$(sw_vers -productVersion 2>/dev/null || echo "Unknown")
OS_BUILD=$(sw_vers -buildVersion 2>/dev/null || echo "")
OS_MAJOR=${OS_VER%%.*}

echo "# ============================================================"
echo "# 점검 대상: ${HN}"
echo "# OS: macOS ${OS_VER} (${OS_BUILD})"
echo "# 점검 기준: 전자금융기반시설 PC(업무용 단말) 자체 점검 항목 PC-01~18 (전자금융 평가기준에 PC 분야 없음)"
echo "# 점검 일시: $(date '+%Y-%m-%d %H:%M:%S')"
echo "# IP: $(ip_list)"
if [ "$IS_ROOT" -eq 1 ]; then echo "# 실행 계정: root"; else echo "# 실행 계정: ${RUN_USER} (관리자 아님 - 일부 항목 점검불가)"; fi
echo "# 사용자 설정 기준 계정: ${TUSER:-없음(콘솔 로그인 사용자 없음)}"
echo "# 클라우드: $(cloud_info)"
echo "# ============================================================"

_CP=0; _CF=0; _CM=0; _CN=0; _CU=0

_EVD="${_DIR}/${HN}_pc_mac_evidence.txt"
_safe_new "$_EVD"
{ echo "# ================================================================"
  echo "# macOS PC 증적 파일 (감사 추적용)"
  echo "# 대상: ${HN} / macOS ${OS_VER}"
  echo "# 실행 계정: ${RUN_USER} (root=${IS_ROOT}) / 사용자 설정 기준 계정: ${TUSER:-없음}"
  echo "# 생성: $(date '+%Y-%m-%d %H:%M:%S')"
  echo "# ================================================================"; } > "$_EVD"

# ── PC-01: 패스워드 설정 ────────────────────────────────────────
# 로컬 사용자(UID 500 이상)별 인증 방식 확인 — macOS 는 빈 암호 여부를 직접 조회할 수 없으므로 게스트 활성 시 취약, 그 외 수동확인
evd "PC-01" "dscl . -list /Users UniqueID"
users=$(dscl . -list /Users UniqueID 2>/dev/null | awk '$2>=500 && $1!~/^_/{print $1}' | tr '\n' ' ')
for u in $users; do evd "PC-01" "dscl . -read /Users/$u AuthenticationAuthority"; done
evd "PC-01" "defaults read /Library/Preferences/com.apple.loginwindow GuestEnabled"
evd "PC-01" "sysadminctl -guestAccount status"
guest=$(defaults read /Library/Preferences/com.apple.loginwindow GuestEnabled 2>/dev/null)
if [ -z "$users" ]; then
    result "PC-01|점검불가|로컬 사용자 목록(dscl) 조회 실패 - 계정·암호 설정 수동 확인"
elif [ "$guest" = "1" ]; then
    result "PC-01|취약|게스트 계정 활성화 (암호 없이 로그인 가능) — 로컬 사용자: ${users}"
else
    result "PC-01|수동확인|로컬 사용자: ${users} — 계정별 8자 이상 영문·숫자·특수문자 조합 암호 설정 여부 확인 (게스트 비활성)"
fi

# ── PC-02: 패스워드 정책 ──────────────────────────────────────────
evd "PC-02" "pwpolicy getaccountpolicies"
pw_policy=$(pwpolicy getaccountpolicies 2>/dev/null)
if [ -n "$pw_policy" ] && echo "$pw_policy" | grep -q "policyAttribute"; then
    # 기준(PC-02 개선방안): 최소 길이 8자 이상, 최대 사용기간 90일 이하
    # 최소 길이: policyContent "matches '.{8,}+'" 또는 policyParameters <key>minimumLength</key><integer>N
    min_len=$(echo "$pw_policy" | grep -oE "matches '\.\{[0-9]+," | grep -oE '[0-9]+' | awk 'NR==1')
    [ -z "$min_len" ] && min_len=$(echo "$pw_policy" | tr -d '\n\t ' | grep -oE '<key>minimumLength</key><integer>[0-9]+' | grep -oE '[0-9]+$' | awk 'NR==1')
    # 만료: policyParameters <key>policyAttributeExpiresEveryNDays</key><integer>N (분 단위 ...EveryNMinutes 대비)
    exp_days=$(echo "$pw_policy" | tr -d '\n\t ' | grep -oE '<key>policyAttributeExpiresEveryNDays</key><integer>[0-9]+' | grep -oE '[0-9]+$' | awk 'NR==1')
    [ -z "$exp_days" ] && { m=$(echo "$pw_policy" | tr -d '\n\t ' | grep -oE '<key>policyAttributeExpiresEveryNMinutes</key><integer>[0-9]+' | grep -oE '[0-9]+$' | awk 'NR==1'); [ -n "$m" ] && exp_days=$(( m / 1440 )); }
    evq "PC-02" "pwpolicy 에서 추출한 값 (최소 길이 / 만료 일수)" "min_len=${min_len:-미확인} exp_days=${exp_days:-미설정}"
    desc="최소 길이=${min_len:-미확인}자, 만료=${exp_days:-미설정}일"
    if [ -n "$min_len" ] && [ "$min_len" -ge 8 ] && [ -n "$exp_days" ] && [ "$exp_days" -gt 0 ] && [ "$exp_days" -le 90 ]; then
        result "PC-02|양호|패스워드 정책 적용: ${desc}"
    elif { [ -n "$min_len" ] && [ "$min_len" -lt 8 ]; } || { [ -n "$exp_days" ] && [ "$exp_days" -gt 90 ]; }; then
        result "PC-02|취약|패스워드 정책 기준 미달: ${desc} (8자 이상, 90일 이하 필요)"
    else
        result "PC-02|수동확인|패스워드 정책 일부 확인 불가: ${desc} — MDM/프로파일 정책 확인"
    fi
else
    if [ "$IS_ROOT" -eq 1 ]; then
        result "PC-02|점검불가|패스워드 정책(pwpolicy getaccountpolicies) 조회 결과 없음 - MDM/프로파일 기반 정책이면 수동 확인"
    else
        result "PC-02|점검불가|패스워드 정책(pwpolicy) 조회 불가: ${NEED_ROOT}"
    fi
fi

# ── PC-03: 화면보호기 / 화면 잠금 (대상 사용자 설정 + 전원 소스별 디스플레이 절전) ──────────
evd "PC-03" "urd read com.apple.screensaver askForPassword"
evd "PC-03" "urd read com.apple.screensaver askForPasswordDelay"
evd "PC-03" "urd -currentHost read com.apple.screensaver idleTime"
evd "PC-03" "sysadminctl -screenLock status"
evd "PC-03" "pmset -g custom"
if [ "$IS_ROOT" -eq 1 ] && [ -z "$TUSER" ]; then
    result "PC-03|점검불가|콘솔에 로그인한 사용자가 없어 사용자 화면 잠금 설정을 읽을 수 없음 (SUDO_USER·콘솔 사용자 없음)"
else
    ask_pw=$(urd read com.apple.screensaver askForPassword)
    ask_delay=$(urd read com.apple.screensaver askForPasswordDelay)
    ss_idle=$(urd -currentHost read com.apple.screensaver idleTime)
    # 배터리·AC 모두 확인: 하나라도 0(끄지 않음)이면 0, 아니면 최댓값
    ds_all=$(pmset -g custom 2>/dev/null | awk '/displaysleep/{print $2}')
    display_sleep=""
    for v in $ds_all; do
        if [ "$v" = "0" ]; then display_sleep=0; break; fi
        { [ -z "$display_sleep" ] || [ "$v" -gt "$display_sleep" ]; } 2>/dev/null && display_sleep=$v
    done
    evq "PC-03" "판정에 사용한 값 (대상 사용자=${TUSER}) askForPassword / askForPasswordDelay / screensaver idleTime(초) / displaysleep(분, 배터리·AC 중 최악)" "askForPassword=${ask_pw:-미설정} askForPasswordDelay=${ask_delay:-미설정} idleTime=${ss_idle:-미설정} displaysleep=${display_sleep:-미확인}"
    ss_ok=0; { [ -n "$ss_idle" ] && [ "$ss_idle" -gt 0 ] && [ "$ss_idle" -le 600 ]; } 2>/dev/null && ss_ok=1
    ds_ok=0; { [ -n "$display_sleep" ] && [ "$display_sleep" -gt 0 ] && [ "$display_sleep" -le 10 ]; } 2>/dev/null && ds_ok=1
    if [ "$ask_pw" = "1" ]; then
        if [ "$ss_ok" -eq 1 ] || [ "$ds_ok" -eq 1 ]; then
            result "PC-03|양호|화면잠금 암호 활성 (사용자 ${TUSER}), 화면보호기=${ss_idle:-미설정}초, 디스플레이절전=${display_sleep:-미확인}분, 암호지연=${ask_delay:-0}초"
        else
            result "PC-03|취약|화면잠금 암호 활성이나 화면보호기(${ss_idle:-미설정}초)·디스플레이절전(${display_sleep:-미확인}분) 모두 10분 이하 아님"
        fi
    else
        result "PC-03|취약|화면잠금 시 암호 요구 비활성 (askForPassword=${ask_pw:-미설정}, 사용자 ${TUSER})"
    fi
fi

# ── PC-04: 공유폴더 (파일 공유 서비스) ──────────────────────────────
evd "PC-04" "sharing -l"
evd "PC-04" "launchctl list"
evd "PC-04" "nc -z -w 1 127.0.0.1 445 && echo 'port 445 open' || echo 'port 445 closed'; nc -z -w 1 127.0.0.1 548 && echo 'port 548 open' || echo 'port 548 closed'"
smb=$(svc_state com.apple.smbd 445)
afp=$(svc_state com.apple.AppleFileServer 548)
shared_list=$(sharing -l 2>/dev/null | grep "name:" | sed 's/.*name:[[:space:]]*//' | tr '\n' ',' | sed 's/,$//')
if [ "$smb" = "on" ] || [ "$afp" = "on" ]; then
    result "PC-04|취약|파일 공유 활성: $([ "$smb" = on ] && echo 'SMB ')$([ "$afp" = on ] && echo 'AFP ')공유=${shared_list:-목록 조회 불가($([ "$IS_ROOT" -eq 1 ] || echo "$NEED_ROOT"))}"
elif [ "$IS_ROOT" -eq 1 ]; then
    result "PC-04|양호|파일 공유 서비스(SMB/AFP) 비활성 (launchctl 시스템 도메인 기준)"
else
    result "PC-04|점검불가|파일 공유 서비스 상태 조회 불가: ${NEED_ROOT} (로컬 포트 445/548 은 닫혀 있으나 launchctl 시스템 도메인을 볼 수 없어 단정 불가)"
fi

# ── PC-05: 불필요 서비스 비활성화 ──────────────────────────────────
bad_svc=""; unk_svc=0
evd "PC-05" "launchctl list"
for entry in com.apple.screensharing:5900 com.apple.RemoteDesktop.agent: com.apple.VNCServer:5900 com.apple.tftpd:69 com.apple.bootpd: org.postfix.master:25 com.apple.ftp-proxy:; do
    svc=${entry%%:*}; port=${entry##*:}
    st=$(svc_state "$svc" "$port")
    evq "PC-05" "서비스 상태 (root: launchctl 적재 여부 / 비root: 포트 ${port:-없음} 리슨 여부)" "$svc = $st"
    [ "$st" = "on" ] && bad_svc="${bad_svc} ${svc##com.apple.}"
    [ "$st" = "unk" ] && unk_svc=1
done
if [ -n "$bad_svc" ]; then
    result "PC-05|취약|실행 중 불필요 서비스:${bad_svc}"
elif [ "$unk_svc" -eq 1 ]; then
    result "PC-05|점검불가|불필요 서비스 적재 여부 조회 불가: ${NEED_ROOT} (포트 리슨 확인된 서비스 없음)"
else
    result "PC-05|양호|불필요 서비스 미실행 (화면공유/VNC/TFTP/BOOTP/FTP 등)"
fi

# ── PC-06: 백신 / Gatekeeper ──────────────────────────────────────
evd "PC-06" "spctl --status"
evd "PC-06" "ls /Applications"
gk_status=$(spctl --status 2>/dev/null)
# 앱 이름 앞부분 일치(부분 문자열 오탐 방지: 예 'V3' 가 다른 앱 이름 중간에 있는 경우)
av_apps=$(ls /Applications 2>/dev/null | sed 's/\.app$//' | grep -iE '^(crowdstrike|falcon|sentinel ?one|symantec|norton|mcafee|sophos|eset|avast|kaspersky|ahnlab|v3( |lite|365|$)|trend ?micro|bitdefender|malwarebytes|microsoft defender)' | tr '\n' ',' | sed 's/,$//')
if echo "$gk_status" | grep -qi "assessments enabled"; then
    if [ -n "$av_apps" ]; then
        result "PC-06|양호|Gatekeeper 활성 + 백신: ${av_apps}"
    else
        result "PC-06|수동확인|Gatekeeper 활성, 백신 미탐지 (XProtect 내장 보호만 확인) — 백신 설치 및 실시간 감시 여부 확인"
    fi
elif [ -z "$gk_status" ]; then
    result "PC-06|점검불가|Gatekeeper 상태(spctl --status) 조회 실패"
else
    result "PC-06|취약|Gatekeeper 비활성 ($gk_status)"
fi

# ── PC-07: OS 보안 패치 (자동 업데이트) ──────────────────────────────
evd "PC-07" "defaults read /Library/Preferences/com.apple.SoftwareUpdate"
evd "PC-07" "defaults read '/Library/Managed Preferences/com.apple.SoftwareUpdate'"
evd "PC-07" "sw_vers"
auto_check=$(defaults read "/Library/Managed Preferences/com.apple.SoftwareUpdate" AutomaticCheckEnabled 2>/dev/null)
[ -z "$auto_check" ] && auto_check=$(defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled 2>/dev/null)
auto_install=$(defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticallyInstallMacOSUpdates 2>/dev/null)
crit_install=$(defaults read /Library/Preferences/com.apple.SoftwareUpdate CriticalUpdateInstall 2>/dev/null)
if [ "$auto_check" = "0" ]; then
    result "PC-07|취약|자동 업데이트 비활성 (AutomaticCheckEnabled=0)"
else
    # 키가 없으면 macOS 기본값(자동 확인 사용) 적용
    result "PC-07|양호|자동 업데이트 활성 (AutomaticCheckEnabled=${auto_check:-미설정(기본 1)}, AutoInstall=${auto_install:-미설정}, 긴급패치=${crit_install:-미설정}), OS=${OS_VER}"
fi

# ── PC-08: 방화벽 활성화 ──────────────────────────────────────────
evd "PC-08" "/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate"
evd "PC-08" "/usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode"
evd "PC-08" "/usr/libexec/ApplicationFirewall/socketfilterfw --getloggingmode"
fw_state=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null)
fw_stealth=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode 2>/dev/null)
fw_logging=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getloggingmode 2>/dev/null)
if [ -z "$fw_state" ]; then
    result "PC-08|점검불가|방화벽 상태(socketfilterfw --getglobalstate) 조회 실패"
elif echo "$fw_state" | grep -qE 'State = [12]|is enabled'; then
    result "PC-08|양호|macOS 방화벽 활성 (${fw_state}; 스텔스=${fw_stealth:-미확인}, 로깅=${fw_logging:-미확인})"
else
    result "PC-08|취약|macOS 방화벽 비활성 (${fw_state})"
fi

# ── PC-09: 감사 로그 관리 (audit_control 은 항상 존재하므로 flags 값으로 판정) ──────────────
evd "PC-09" "cat /etc/security/audit_control"
evd "PC-09" "ps -axo comm"
if [ -f /etc/security/audit_control ]; then
    flags=$(grep "^flags:" /etc/security/audit_control 2>/dev/null | awk 'NR==1')
    expire=$(grep "^expire-after:" /etc/security/audit_control 2>/dev/null | awk 'NR==1')
    filesz=$(grep "^filesz:" /etc/security/audit_control 2>/dev/null | awk 'NR==1')
    auditd_run=$(ps -axo comm 2>/dev/null | awk -F/ '$NF=="auditd"{f=1} END{print f?"실행 중":"미실행"}')
    if [ -z "$flags" ]; then
        result "PC-09|취약|감사 로그 flags 미설정 (audit_control 에 flags: 줄 없음), auditd ${auditd_run}"
    elif echo "$flags" | grep -qE '(^|[:,])lo([,]|$)'; then
        result "PC-09|양호|감사 로그 설정: ${flags}, ${filesz:-크기미설정}, ${expire:-만료미설정}, auditd ${auditd_run} (로그인/로그아웃 'lo' 포함)"
    else
        result "PC-09|취약|감사 로그 flags 에 로그인/로그아웃(lo) 없음: ${flags}, auditd ${auditd_run}"
    fi
else
    result "PC-09|수동확인|/etc/security/audit_control 없음 - Unified Logging 환경 수동 확인"
fi

# ── PC-10: 원격 접속 제한 ──────────────────────────────────────────
evd "PC-10" "systemsetup -getremotelogin"
evd "PC-10" "launchctl list"
evd "PC-10" "ps -axo comm"
evd "PC-10" "nc -z -w 1 127.0.0.1 22 && echo 'port 22 open' || echo 'port 22 closed'; nc -z -w 1 127.0.0.1 5900 && echo 'port 5900 open' || echo 'port 5900 closed'"
issues10=""; unk10=0
if [ "$IS_ROOT" -eq 1 ]; then
    systemsetup -getremotelogin 2>/dev/null | grep -qi ': on' && issues10="${issues10} SSH활성"
    svc_state com.apple.screensharing 5900 | grep -q on && issues10="${issues10} 화면공유활성"
else
    port_open 22 && issues10="${issues10} SSH활성(포트22 리슨)" || unk10=1
    port_open 5900 && issues10="${issues10} 화면공유/VNC활성(포트5900 리슨)" || unk10=1
fi
ps -axo comm 2>/dev/null | awk -F/ '$NF=="ARDAgent"{f=1} END{exit f?0:1}' && issues10="${issues10} 원격관리(ARD)활성"
if [ -n "$issues10" ]; then
    result "PC-10|취약|원격 접속 서비스 활성:${issues10}"
elif [ "$unk10" -eq 1 ]; then
    result "PC-10|점검불가|원격 로그인(SSH)/화면공유 설정 조회 불가: ${NEED_ROOT} (systemsetup·launchctl 시스템 도메인 필요; 로컬 포트 22/5900 닫힘, ARD 프로세스 없음)"
else
    result "PC-10|양호|원격 로그인(SSH)/원격관리/화면공유 모두 비활성"
fi

# ── PC-11: 자동실행 비활성화 ───────────────────────────────────────
evd "PC-11" "echo 'macOS 에는 Windows AutoRun/AutoPlay 가 없음 - 점검 대상 아님'"
result "PC-11|N-A|macOS는 Windows AutoRun/AutoPlay 해당 없음 (Gatekeeper로 실행 제어)"

# ── PC-12: 이동매체 제한 ──────────────────────────────────────────
evd "PC-12" "defaults read '/Library/Managed Preferences/com.apple.systemuiserver'"
evd "PC-12" "ls '/Library/Managed Preferences'"
usb_restrict=$(defaults read "/Library/Managed Preferences/com.apple.systemuiserver" 2>/dev/null | grep -i "mount-controls")
if [ -n "$usb_restrict" ]; then
    result "PC-12|양호|MDM 기반 이동매체 제한 정책 적용 (mount-controls)"
else
    result "PC-12|수동확인|이동매체 제한 정책(mount-controls) 미탐지 - MDM/프로파일 기반 정책 수동 확인"
fi

# ── PC-13: Guest 계정 비활성화 ─────────────────────────────────────
evd "PC-13" "defaults read /Library/Preferences/com.apple.loginwindow GuestEnabled"
evd "PC-13" "sysadminctl -guestAccount status"
guest_enabled=$(defaults read /Library/Preferences/com.apple.loginwindow GuestEnabled 2>/dev/null)
sa_guest=$(sysadminctl -guestAccount status 2>&1)
if [ "$guest_enabled" = "1" ] || [ "$guest_enabled" = "true" ] || echo "$sa_guest" | grep -qi 'enabled'; then
    result "PC-13|취약|Guest 계정 활성화됨 (GuestEnabled=${guest_enabled:-미설정}; ${sa_guest})"
else
    result "PC-13|양호|Guest 계정 비활성 (GuestEnabled=${guest_enabled:-미설정(기본 비활성)})"
fi

# ── PC-14: SIP(System Integrity Protection) ───────────────────────
evd "PC-14" "csrutil status"
sip_status=$(csrutil status 2>&1)
if [ -z "$sip_status" ]; then
    result "PC-14|점검불가|csrutil status 조회 실패"
elif echo "$sip_status" | grep -qi 'custom configuration'; then
    result "PC-14|취약|SIP 일부 보호 해제(Custom Configuration): $sip_status"
elif echo "$sip_status" | grep -qiE 'status: enabled\.?$'; then
    result "PC-14|양호|SIP 활성: $sip_status"
else
    result "PC-14|취약|SIP 비활성: ${sip_status}"
fi

# ── PC-15: 브라우저 보안 (Safari) ──────────────────────────────────
evd "PC-15" "urd read com.apple.Safari WarnAboutFraudulentWebsites"
evd "PC-15" "urd read com.apple.Safari WebKitJavaScriptCanOpenWindowsAutomatically"
evd "PC-15" "urd read com.apple.Safari"
if [ "$IS_ROOT" -eq 1 ] && [ -z "$TUSER" ]; then
    result "PC-15|점검불가|콘솔에 로그인한 사용자가 없어 Safari 설정을 읽을 수 없음"
else
    safari_dom=$(urd read com.apple.Safari)
    safari_fraud=$(urd read com.apple.Safari WarnAboutFraudulentWebsites)
    safari_popup=$(urd read com.apple.Safari WebKitJavaScriptCanOpenWindowsAutomatically)
    if [ "$safari_fraud" = "1" ] || [ "$safari_fraud" = "true" ]; then
        result "PC-15|양호|Safari 사기 사이트 경고 활성 (사용자 ${TUSER}), 팝업 자동 열기=${safari_popup:-미설정}"
    elif [ "$safari_fraud" = "0" ] || [ "$safari_fraud" = "false" ]; then
        result "PC-15|취약|Safari 사기 사이트 경고 비활성 (사용자 ${TUSER})"
    elif [ -n "$safari_dom" ]; then
        result "PC-15|양호|Safari 사기 사이트 경고 키 미설정 - 기본값(활성) 적용 (사용자 ${TUSER}, 설정 도메인 읽힘)"
    else
        result "PC-15|점검불가|Safari 설정(com.apple.Safari)을 읽지 못함 (사용자 ${TUSER}) - Safari 샌드박스 설정은 터미널에 전체 디스크 접근 권한 필요, 브라우저 설정 수동 확인"
    fi
fi

# ── PC-16: 로그인 실패 임계값 ──────────────────────────────────────
evd "PC-16" "pwpolicy getaccountpolicies"
pw16=$(pwpolicy getaccountpolicies 2>/dev/null)
if [ -z "$pw16" ] || ! echo "$pw16" | grep -q "policyAttribute"; then
    if [ "$IS_ROOT" -eq 1 ]; then
        result "PC-16|점검불가|로그인 실패 임계값 조회 불가: pwpolicy getaccountpolicies 결과 없음 - MDM/프로파일 수동 확인"
    else
        result "PC-16|점검불가|로그인 실패 임계값 조회 불가: ${NEED_ROOT}"
    fi
else
    max_fail=$(echo "$pw16" | tr -d '\n\t ' | grep -oE '<key>policyAttributeMaximumFailedAuthentications</key><integer>[0-9]+' | grep -oE '[0-9]+$' | awk 'NR==1')
    [ -z "$max_fail" ] && max_fail=$(echo "$pw16" | grep -oE 'policyAttributeFailedAuthentications[[:space:]]*<[[:space:]]*[0-9]+' | grep -oE '[0-9]+$' | awk 'NR==1')
    evq "PC-16" "pwpolicy 에서 추출한 로그인 실패 허용 횟수" "max_fail=${max_fail:-미설정}"
    if [ -z "$max_fail" ]; then
        result "PC-16|취약|로그인 실패 잠금 임계값 미설정 (pwpolicy 정책에 policyAttributeMaximumFailedAuthentications 없음)"
    elif [ "$max_fail" -ge 1 ] && [ "$max_fail" -le 5 ]; then
        result "PC-16|양호|로그인 실패 잠금 임계값 ${max_fail}회 (5회 이하)"
    else
        result "PC-16|취약|로그인 실패 잠금 임계값 ${max_fail}회 (1~5회 필요)"
    fi
fi

# ── PC-17: 감사 정책 (auditd) ──────────────────────────────────────
evd "PC-17" "ps -axo comm"
evd "PC-17" "ls /var/audit"
auditd_proc=$(ps -axo comm 2>/dev/null | awk -F/ '$NF=="auditd"{f=1} END{print f?"y":""}')
if [ -n "$auditd_proc" ]; then
    result "PC-17|양호|auditd 실행 중 (BSM 감사 활성)"
else
    result "PC-17|수동확인|auditd 프로세스 미실행 - macOS Unified Logging 기반 환경 수동 확인"
fi

# ── PC-18: FileVault (디스크 암호화) ────────────────────────────────
evd "PC-18" "fdesetup status"
fv_status=$(fdesetup status 2>&1)
if [ -z "$fv_status" ]; then
    result "PC-18|점검불가|fdesetup status 조회 실패"
elif echo "$fv_status" | grep -qi 'FileVault is On'; then
    result "PC-18|양호|FileVault 활성: $fv_status"
elif echo "$fv_status" | grep -qi 'Encryption in progress'; then
    result "PC-18|수동확인|FileVault 암호화 진행 중: $fv_status"
else
    result "PC-18|취약|FileVault 비활성: ${fv_status}"
fi

# ── 요약 ──────────────────────────────────────────────────────────
echo "# ============================================================"
echo "# 점검 완료"
echo "# 양호: ${_CP} / 취약: ${_CF} / 수동확인: ${_CM} / 점검불가: ${_CU} / N-A: ${_CN}"
echo "# 증적 파일: ${_EVD}"
echo "# ============================================================"
[ -n "$_RESF" ] && echo "# 결과 파일(자동 저장): ${_RESF}  ← 증적 파일과 함께 회수"
[ -n "$_TEEPID" ] && { exec >&- 2>/dev/null; wait "$_TEEPID" 2>/dev/null; sleep 1; }
exit 0
