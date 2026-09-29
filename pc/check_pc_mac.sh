#!/bin/bash
# ================================================================
# PC 단말(macOS) 보안 취약점 자동 점검 스크립트 v1.0
# ================================================================
#
# [용도]
#   전자금융기반시설 업무용 PC(macOS) 보안 점검. (주요정보 2026 상세가이드 PC-01~18 은 check_pc_mac_kisa.sh 사용)
#   기준: 전자금융기반시설 PC(업무용 단말) 자체 점검 항목 PC-01~18 (전자금융 평가기준에 PC 분야 없음)
#   Windows PC는 check_pc.ps1 사용.
#
# [대상 OS]
#   macOS 12 (Monterey) ~ macOS 15 (Sequoia)
#
# [사전 조건]
#   - 관리자(sudo) 권한 권장 (일부 항목은 일반 사용자로도 점검 가능)
#
# [실행 방법]
#   bash check_pc_mac.sh > ~/Desktop/$(hostname)_pc.txt
#
# [산출물]
#   1) 표준출력 — 파이프 구분자 결과 (파일로 리다이렉트)
#      형식: PC-항목코드|결과|근거설명
#      결과: 양호 / 취약 / 수동확인 / N-A
#   2) 증적 파일 — 스크립트와 같은 디렉터리/<호스트명>_pc_evidence.txt
#      점검 중 실행한 명령어·출력·판정 근거가 타임스탬프와 함께 기록됨
#
# ================================================================

HN=$(scutil --get ComputerName 2>/dev/null || hostname -s 2>/dev/null || echo Unknown)   # 주요정보판(check_pc_mac_kisa.sh)과 같은 호스트명
HN=$(echo "$HN" | tr ' /' '__')
# ── 결과 사본 자동 저장: '> 파일' 리다이렉트를 빠뜨려도 판정 결과가 증적과 같은 위치에 남도록 표준출력을 복사 ──
_RESF="$(cd "$(dirname "$0")" && pwd)/PC_${HN}.txt"
if [ -z "$NO_RESULT_COPY" ] && ! [ /dev/fd/1 -ef "$_RESF" ] 2>/dev/null && ( : > "$_RESF" ) 2>/dev/null; then
    exec > >(tee "$_RESF"); _TEEPID=$!
else
    _RESF=""
fi
OS_VER=$(sw_vers -productVersion 2>/dev/null || echo "Unknown")
OS_BUILD=$(sw_vers -buildVersion 2>/dev/null || echo "")

echo "# ============================================================"
echo "# 점검 대상: ${HN}"
echo "# OS: macOS ${OS_VER} (${OS_BUILD})"
echo "# 점검 기준: 전자금융기반시설 PC(업무용 단말) 자체 점검 항목 PC-01~18 (전자금융 평가기준에 PC 분야 없음)"
echo "# 점검 일시: $(date '+%Y-%m-%d %H:%M:%S')"
echo "# ============================================================"

_CP=0; _CF=0; _CM=0; _CN=0

_SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
_EVD="${_SCRIPT_DIR}/${HN}_pc_mac_evidence.txt"
echo "# ================================================================" > "$_EVD"
echo "# macOS PC 증적 파일 (감사 추적용)" >> "$_EVD"
echo "# 대상: ${HN} / macOS ${OS_VER}" >> "$_EVD"
echo "# 생성: $(date '+%Y-%m-%d %H:%M:%S')" >> "$_EVD"
echo "# ================================================================" >> "$_EVD"

result() {
    echo "$1"
    case "$1" in
    *"|양호|"*)     _CP=$((_CP+1)) ;;
    *"|취약|"*)     _CF=$((_CF+1)) ;;
    *"|수동확인|"*) _CM=$((_CM+1)) ;;
    *"|N-A|"*)      _CN=$((_CN+1)) ;;
    esac
    printf '[판정] %s\n\n' "$1" >> "$_EVD"
}
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

# ── PC-01: 패스워드 설정 ────────────────────────────────────────
evd "PC-01" "dscl . -list /Users UniqueID 2>/dev/null | awk '\$2>=500'; defaults read /Library/Preferences/com.apple.loginwindow GuestEnabled 2>/dev/null; sysadminctl -guestAccount status 2>&1"
# 로컬 사용자(UID 500 이상)별 인증 방식 확인 — macOS 는 빈 암호 여부를 직접 조회할 수 없으므로 게스트 활성 시 취약, 그 외 수동확인
guest=$(defaults read /Library/Preferences/com.apple.loginwindow GuestEnabled 2>/dev/null)
users=$(dscl . -list /Users UniqueID 2>/dev/null | awk '$2>=500 && $1!~/^_/{print $1}' | tr '\n' ' ')
for u in $users; do evd "PC-01" "dscl . -read /Users/$u AuthenticationAuthority 2>/dev/null | head -3"; done
if [ "$guest" = "1" ]; then
    result "PC-01|취약|게스트 계정 활성화 (암호 없이 로그인 가능) — 로컬 사용자: ${users:-미확인}"
else
    result "PC-01|수동확인|로컬 사용자: ${users:-미확인} — 계정별 8자 이상 영문·숫자·특수문자 조합 암호 설정 여부 확인 (게스트 비활성)"
fi

# ── PC-02: 패스워드 정책 ──────────────────────────────────────────
evd "PC-02" "pwpolicy getaccountpolicies 2>/dev/null | head -20"
pw_policy=$(pwpolicy getaccountpolicies 2>/dev/null)
if [ -n "$pw_policy" ] && echo "$pw_policy" | grep -q "policyAttribute"; then
    # 기준(PC-02 개선방안): 최소 길이 8자 이상, 최대 사용기간 90일 이하
    # 최소 길이: policyContent "matches '.{8,}+'" 또는 policyParameters <key>minimumLength</key><integer>N
    min_len=$(echo "$pw_policy" | grep -oE "matches '\.\{[0-9]+," | grep -oE '[0-9]+' | head -1)
    [ -z "$min_len" ] && min_len=$(echo "$pw_policy" | tr -d '\n\t ' | grep -oE '<key>minimumLength</key><integer>[0-9]+' | grep -oE '[0-9]+$' | head -1)
    # 만료: policyParameters <key>policyAttributeExpiresEveryNDays</key><integer>N (분 단위 ...EveryNMinutes 대비)
    exp_days=$(echo "$pw_policy" | tr -d '\n\t ' | grep -oE '<key>policyAttributeExpiresEveryNDays</key><integer>[0-9]+' | grep -oE '[0-9]+$' | head -1)
    [ -z "$exp_days" ] && { m=$(echo "$pw_policy" | tr -d '\n\t ' | grep -oE '<key>policyAttributeExpiresEveryNMinutes</key><integer>[0-9]+' | grep -oE '[0-9]+$' | head -1); [ -n "$m" ] && exp_days=$(( m / 1440 )); }
    desc="최소 길이=${min_len:-미확인}자, 만료=${exp_days:-미설정}일"
    if [ -n "$min_len" ] && [ "$min_len" -ge 8 ] && [ -n "$exp_days" ] && [ "$exp_days" -gt 0 ] && [ "$exp_days" -le 90 ]; then
        result "PC-02|양호|패스워드 정책 적용: ${desc}"
    elif { [ -n "$min_len" ] && [ "$min_len" -lt 8 ]; } || { [ -n "$exp_days" ] && [ "$exp_days" -gt 90 ]; }; then
        result "PC-02|취약|패스워드 정책 기준 미달: ${desc} (8자 이상, 90일 이하 필요)"
    else
        result "PC-02|수동확인|패스워드 정책 일부 확인 불가: ${desc} — MDM/프로파일 정책 확인"
    fi
else
    result "PC-02|수동확인|패스워드 정책(pwpolicy) 조회 불가 - MDM/프로파일 기반 정책 수동 확인"
fi

# ── PC-03: 화면보호기 / 화면 잠금 ─────────────────────────────────
evd "PC-03" "defaults read com.apple.screensaver askForPassword 2>/dev/null; pmset -g custom 2>/dev/null | grep displaysleep"
ask_pw=$(defaults read com.apple.screensaver askForPassword 2>/dev/null)
ask_delay=$(defaults read com.apple.screensaver askForPasswordDelay 2>/dev/null)
display_sleep=$(pmset -g custom 2>/dev/null | awk '/displaysleep/{print $2; exit}')

if [ "$ask_pw" = "1" ]; then
    delay_sec=${ask_delay:-0}
    if [ -n "$display_sleep" ] && [ "$display_sleep" -gt 0 ] 2>/dev/null && [ "$display_sleep" -le 10 ]; then
        result "PC-03|양호|화면잠금 암호 활성, 디스플레이절전=${display_sleep}분, 암호지연=${delay_sec}초"
    elif [ -n "$display_sleep" ] && [ "$display_sleep" -gt 0 ] 2>/dev/null; then
        result "PC-03|취약|화면잠금 암호 활성이나 디스플레이절전=${display_sleep}분(10분 이하 권장)"
    else
        result "PC-03|취약|화면잠금 암호 활성이나 디스플레이절전 미설정(${display_sleep:-미확인})"
    fi
else
    result "PC-03|취약|화면잠금 시 암호 요구 비활성 (askForPassword=${ask_pw:-미설정})"
fi

# ── PC-04: 공유폴더 (파일 공유 서비스) ──────────────────────────────
evd "PC-04" "launchctl list 2>/dev/null | grep -E 'smbd|AppleFileServer'"
smb_running=$(launchctl list 2>/dev/null | grep "com.apple.smbd")
afp_running=$(launchctl list 2>/dev/null | grep "com.apple.AppleFileServer")

if [ -z "$smb_running" ] && [ -z "$afp_running" ]; then
    result "PC-04|양호|파일 공유 서비스(SMB/AFP) 비활성"
else
    shared_list=$(sharing -l 2>/dev/null | grep "name:" | sed 's/.*name:[[:space:]]*//' | tr '\n' ',' | sed 's/,$//')
    result "PC-04|취약|파일 공유 활성: ${smb_running:+SMB }${afp_running:+AFP }공유=${shared_list:-없음}"
fi

# ── PC-05: 불필요 서비스 비활성화 ──────────────────────────────────
evd "PC-05" "launchctl list 2>/dev/null | grep -E 'screensharing|RemoteDesktop|VNCServer|tftpd|bootpd|postfix|ftp-proxy'"
bad_svc=""
for svc in com.apple.screensharing \
           com.apple.RemoteDesktop.agent \
           com.apple.VNCServer \
           com.apple.tftpd \
           com.apple.bootpd \
           org.postfix.master \
           com.apple.ftp-proxy; do
    if launchctl list 2>/dev/null | grep -q "$svc"; then
        bad_svc="${bad_svc} ${svc##com.apple.}"
    fi
done

if [ -z "$bad_svc" ]; then
    result "PC-05|양호|불필요 서비스 미실행 (화면공유/VNC/TFTP/BOOTP/FTP 등)"
else
    result "PC-05|취약|실행 중 불필요 서비스:${bad_svc}"
fi

# ── PC-06: 백신 / Gatekeeper ──────────────────────────────────────
evd "PC-06" "spctl --status 2>/dev/null; ls /Applications/ 2>/dev/null | grep -iE 'CrowdStrike|SentinelOne|AhnLab|V3'"
gk_status=$(spctl --status 2>/dev/null)
av_apps=""
for app in CrowdStrike SentinelOne Symantec McAfee Sophos ESET Avast Kaspersky AhnLab V3 Trend; do
    if ls /Applications/ 2>/dev/null | grep -qi "$app"; then
        av_apps="${av_apps} ${app}"
    fi
done

if echo "$gk_status" | grep -qi "enabled"; then
    if [ -n "$av_apps" ]; then
        result "PC-06|양호|Gatekeeper 활성 + 백신:${av_apps}"
    else
        result "PC-06|수동확인|Gatekeeper 활성, 백신 미탐지 (XProtect 내장 보호만 확인) — 백신 설치 및 실시간 감시 여부 확인"
    fi
else
    result "PC-06|취약|Gatekeeper 비활성 ($gk_status)"
fi

# ── PC-07: OS 보안 패치 (자동 업데이트) ──────────────────────────────
evd "PC-07" "defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled 2>/dev/null; sw_vers 2>/dev/null"
auto_check=$(defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled 2>/dev/null)
auto_install=$(defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticallyInstallMacOSUpdates 2>/dev/null)
crit_install=$(defaults read /Library/Preferences/com.apple.SoftwareUpdate CriticalUpdateInstall 2>/dev/null)

if [ "$auto_check" = "1" ]; then
    result "PC-07|양호|자동 업데이트 활성 (AutoCheck=1, AutoInstall=${auto_install:-미설정}, 긴급패치=${crit_install:-미설정}), OS=${OS_VER}"
else
    result "PC-07|취약|자동 업데이트 비활성 (AutoCheck=${auto_check:-미설정})"
fi

# ── PC-08: 방화벽 활성화 ──────────────────────────────────────────
evd "PC-08" "/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null"
fw_state=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null)
fw_stealth=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode 2>/dev/null)
fw_logging=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getloggingmode 2>/dev/null)

if echo "$fw_state" | grep -qi "enabled"; then
    result "PC-08|양호|macOS 방화벽 활성 (스텔스=${fw_stealth:-미확인}, 로깅=${fw_logging:-미확인})"
else
    result "PC-08|취약|macOS 방화벽 비활성"
fi

# ── PC-09: 감사 로그 관리 ──────────────────────────────────────────
evd "PC-09" "cat /etc/security/audit_control 2>/dev/null"
if [ -f /etc/security/audit_control ]; then
    flags=$(grep "^flags:" /etc/security/audit_control 2>/dev/null | head -1)
    expire=$(grep "^expire-after:" /etc/security/audit_control 2>/dev/null | head -1)
    filesz=$(grep "^filesz:" /etc/security/audit_control 2>/dev/null | head -1)
    result "PC-09|양호|감사 로그 설정: ${flags:-flags미설정}, ${filesz:-크기미설정}, ${expire:-만료미설정}"
else
    result "PC-09|수동확인|/etc/security/audit_control 없음 - Unified Logging 환경 수동 확인"
fi

# ── PC-10: 원격 접속 제한 ──────────────────────────────────────────
evd "PC-10" "systemsetup -getremotelogin 2>/dev/null; launchctl list 2>/dev/null | grep -E 'RemoteDesktop|screensharing'"
remote_login=$(systemsetup -getremotelogin 2>/dev/null)
remote_mgmt=$(launchctl list 2>/dev/null | grep "com.apple.RemoteDesktop.agent")
screen_share=$(launchctl list 2>/dev/null | grep "com.apple.screensharing")

issues10=""
echo "$remote_login" | grep -qi "on" && issues10="${issues10} SSH활성"
[ -n "$remote_mgmt" ] && issues10="${issues10} 원격관리활성"
[ -n "$screen_share" ] && issues10="${issues10} 화면공유활성"

if [ -z "$issues10" ]; then
    result "PC-10|양호|원격 로그인(SSH)/원격관리/화면공유 모두 비활성"
else
    result "PC-10|취약|원격 접속 서비스 활성:${issues10}"
fi

# ── PC-11: 자동실행 비활성화 ───────────────────────────────────────
result "PC-11|N-A|macOS는 Windows AutoRun/AutoPlay 해당 없음 (Gatekeeper로 실행 제어)"

# ── PC-12: 이동매체 제한 ──────────────────────────────────────────
usb_restrict=$(defaults read /Library/Managed\ Preferences/com.apple.systemuiserver 2>/dev/null | grep -i "mount-controls")
if [ -n "$usb_restrict" ]; then
    result "PC-12|양호|MDM 기반 이동매체 제한 정책 적용"
else
    result "PC-12|수동확인|이동매체 제한 정책 미탐지 - MDM/프로파일 기반 정책 수동 확인"
fi

# ── PC-13: Guest 계정 비활성화 ─────────────────────────────────────
evd "PC-13" "defaults read /Library/Preferences/com.apple.loginwindow GuestEnabled 2>/dev/null"
guest_enabled=$(defaults read /Library/Preferences/com.apple.loginwindow GuestEnabled 2>/dev/null)
if [ "$guest_enabled" = "1" ] || [ "$guest_enabled" = "true" ]; then
    result "PC-13|취약|Guest 계정 활성화됨"
else
    result "PC-13|양호|Guest 계정 비활성"
fi

# ── PC-14: SIP(System Integrity Protection) ───────────────────────
evd "PC-14" "csrutil status 2>/dev/null"
sip_status=$(csrutil status 2>/dev/null)
if echo "$sip_status" | grep -qi "enabled"; then
    result "PC-14|양호|SIP 활성: $sip_status"
else
    result "PC-14|취약|SIP 비활성: ${sip_status:-확인불가}"
fi

# ── PC-15: 브라우저 보안 (Safari) ──────────────────────────────────
safari_fraud=$(defaults read com.apple.Safari WarnAboutFraudulentWebsites 2>/dev/null)
safari_popup=$(defaults read com.apple.Safari WebKitJavaScriptCanOpenWindowsAutomatically 2>/dev/null)

if [ "$safari_fraud" = "1" ] || [ "$safari_fraud" = "true" ]; then
    result "PC-15|양호|Safari 사기 사이트 경고 활성, 팝업차단=${safari_popup:-미확인}"
elif [ "$safari_fraud" = "0" ] || [ "$safari_fraud" = "false" ]; then
    result "PC-15|취약|Safari 사기 사이트 경고 비활성"
else
    result "PC-15|수동확인|Safari 보안 설정 확인 불가 - 브라우저 설정 수동 확인"
fi

# ── PC-16: 로그인 실패 임계값 ──────────────────────────────────────
max_fail=$(pwpolicy getaccountpolicies 2>/dev/null | grep -oE 'policyAttributeMaximumFailedAuthentications[^<]*' | head -1)
if [ -n "$max_fail" ]; then
    result "PC-16|양호|로그인 실패 임계값: $max_fail"
else
    result "PC-16|수동확인|로그인 실패 임계값 미설정 또는 확인 불가 - MDM/프로파일 수동 확인"
fi

# ── PC-17: 감사 정책 (auditd) ──────────────────────────────────────
audit_running=$(launchctl list 2>/dev/null | grep "com.apple.auditd")
if [ -n "$audit_running" ]; then
    result "PC-17|양호|auditd 실행 중 (BSM 감사 활성)"
else
    result "PC-17|수동확인|auditd 미실행 - macOS Unified Logging 기반 환경 수동 확인"
fi

# ── PC-18: FileVault (디스크 암호화) ────────────────────────────────
evd "PC-18" "fdesetup status 2>/dev/null"
fv_status=$(fdesetup status 2>/dev/null)
if echo "$fv_status" | grep -qi "on"; then
    result "PC-18|양호|FileVault 활성: $fv_status"
else
    result "PC-18|취약|FileVault 비활성: ${fv_status:-확인불가}"
fi

# ── 요약 ──────────────────────────────────────────────────────────
echo "# ============================================================"
echo "# 점검 완료"
echo "# 양호: ${_CP} / 취약: ${_CF} / 수동확인: ${_CM} / N-A: ${_CN}"
echo "# 증적 파일: ${_EVD}"
echo "# ============================================================"
[ -n "$_RESF" ] && echo "# 결과 파일(자동 저장): ${_RESF}  ← 증적 파일과 함께 회수"
[ -n "$_TEEPID" ] && { exec >&- 2>/dev/null; wait "$_TEEPID" 2>/dev/null; sleep 1; }
exit 0
