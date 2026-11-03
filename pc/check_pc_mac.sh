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
#   macOS 12 ~ 27 (bash 3.2 호환) — PC-07 은 Apple 보안 릴리스 목록을 조회해 지원 종료(EoS)·미적용 패치 판정
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

CUSER=$(stat -f %Su /dev/console 2>/dev/null)
_evd_raw() { printf '[참고] %s\n%s\n\n' "$1" "$2" >> "$_EVD"; }
# 서비스 실제 활성 여부: system 도메인에 로드됐거나 포트 수신 중일 때만 활성
#  ※ 'launchctl list' 의 com.apple.screensharing.agent / RemoteDesktop.agent 는 모든 사용자 세션에 항상 로드되는 보조 에이전트라 활성 근거가 아님
_svc_on() { launchctl print "system/$1" >/dev/null 2>&1; }
_listen() { netstat -an -p tcp 2>/dev/null | awk '$NF=="LISTEN"{print $4}' | grep -qE "[.:]$1\$"; }
FS_ON=""; { _svc_on com.apple.smbd || _listen 445; } && FS_ON="${FS_ON} SMB"; { _svc_on com.apple.AppleFileServer || _listen 548; } && FS_ON="${FS_ON} AFP"
SS_ON=0; { _svc_on com.apple.screensharing || _listen 5900; } && SS_ON=1
ARD_ON=0; { pgrep -x ARDAgent >/dev/null 2>&1 || _listen 3283; } && ARD_ON=1
# 백신: 앱 이름·실행 파일 이름(경로 제외)으로만 판별 — /Applications/AhnLab/ASTx(안랩 세이프 트랜잭션, 금융 보안 모듈)는 백신 아님
AV_APP_RE='^(v3|ahnlab ?v3)|kaspersky|alyac|sophos|symantec|norton|mcafee|^eset|bitdefender|crowdstrike|falcon|sentinel|defender|malwarebytes|avast|avira|trend ?micro'
AV_PROC_RE='^(v3|ahnlab ?v3)|kav|kaspersky|sophos|symantec|norton|mcafee|^eset|esets|bitdefender|bdldaemon|^falcon|com\.crowdstrike|sentinel|wdav|malwarebytes|^rtprotection|avast|avira|alyac|trend ?micro|^icoreservice'
AV_APPS=$(find /Applications "/Users/${CUSER:-$USER}/Applications" -maxdepth 2 -name '*.app' 2>/dev/null | sed 's#.*/##' | grep -iE "$AV_APP_RE" | sort -u | tr '\n' ',' | sed 's/,$//')
AV_PROCS=$(ps -axco comm 2>/dev/null | grep -iE "$AV_PROC_RE" | sort -u | tr '\n' ',' | sed 's/,$//')
# ── macOS 지원(EoS) 판정: Apple 보안 릴리스 페이지(support.apple.com/100100) 실시간 조회 ──
# Apple 은 macOS 지원 종료일을 공지하지 않으므로 '실제 보안 업데이트 배포 여부'로 판정:
#   최신 주요 버전(N) 최초 출시일 이후에도 CVE 포함 보안 업데이트를 받은 주요 버전 = 지원 중, 그 외 = 지원 종료
#   (예: macOS 27 출시 2026-09-14 이후 15·26·27 만 보안 업데이트 → 14 이하 종료)
# 결과 변수: EOS_RES(양호/취약/수동확인) EOS_DESC / PATCH_LATEST(같은 주요 버전 최신 보안 릴리스, 미적용 시)
#           PATCH_DATE·PATCH_AGE(미적용 보안 릴리스 중 가장 오래된 것의 배포일·경과일) — 조회 실패 시 오프라인 추정
# MAC_EOS_OFFLINE=1 이면 온라인 조회 생략, PATCH_GRACE_DAYS(기본 30) 경과한 보안 릴리스 미적용 시 패치 미흡
mac_eos_check() {
    local rows="" major=${OS_VER%%.*} src="Apple 보안 릴리스(support.apple.com/100100) 실시간 조회"
    EOS_RES=""; EOS_DESC=""; PATCH_LATEST=""; PATCH_DATE=""; PATCH_AGE=""
    if [ -z "$MAC_EOS_OFFLINE" ]; then
        rows=$(curl -sL -m 20 -A "Mozilla/5.0" "https://support.apple.com/en-us/100100" 2>/dev/null | tr -d '\r\n' | sed 's#</tr>#\
#g' | sed -e 's/<[^>]*>/|/g' -e 's/&nbsp;/ /g' -e 's/|[| ]*/|/g' | awk -F'|' '
            BEGIN{split("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec",M," "); for(i=1;i<=12;i++) m[M[i]]=sprintf("%02d",i)}
            $2 ~ /^macOS [A-Z][A-Za-z ]* [0-9]+(\.[0-9]+)*$/ {
                nc = ($0 ~ /no published CVE/) ? 1 : 0
                v=$2; sub(/.* /,"",v); d=$(NF-1)
                if (split(d,a," ")==3 && (a[2] in m)) print v, a[3] m[a[2]] sprintf("%02d",a[1]), nc
            }')
    fi
    _evd_raw "macOS 보안 릴리스 목록(버전 날짜 CVE없음여부)" "${rows:-조회 실패 - 내장 기준 사용}"
    if [ -n "$rows" ] && [ "$(echo "$rows" | wc -l)" -ge 5 ]; then
        local today; today=$(date +%Y%m%d)
        eval "$(echo "$rows" | awk -v cur="$OS_VER" -v mj="$major" -v today="$today" '
            function vcmp(a,b,  x,y,i,n){n=split(a,x,".");split(b,y,".");if(n<length(y))n=length(y);for(i=1;i<=n;i++){if((x[i]+0)<(y[i]+0))return -1;if((x[i]+0)>(y[i]+0))return 1}return 0}
            function jd(s,  y,mo,d){y=substr(s,1,4)+0;mo=substr(s,5,2)+0;d=substr(s,7,2)+0;if(mo<3){y--;mo+=12};return int(365.25*(y+4716))+int(30.6001*(mo+1))+d}
            { split($1,p,"."); M=p[1]+0; if(M>N)N=M
              if(!($3)){ if($2>last[M]) last[M]=$2; if(lv[M]=="" || vcmp($1,lv[M])>0) lv[M]=$1 }
              if($1==M"" && (n0[M]==""||$2<n0[M])) n0[M]=$2
              if(!($3) && vcmp($1,cur)>0 && M==mj){ if(pl==""||vcmp($1,pl)>0) pl=$1; if(pd==""||$2<pd) pd=$2 } }
            END{ n0d=n0[N]; if(n0d==""){for(k in last) if(k+0==N) n0d=last[k]}
              sup=""; for(k=N;k>=10;k--) if(k in last && (k==N || last[k]>=n0d)) sup=sup (sup==""?"":"·") k
              printf "EOS_N=%d; EOS_N0=%s; EOS_SUP=\"%s\"; EOS_LASTV=\"%s\"; EOS_LASTD=\"%s\"; ", N, n0d, sup, lv[mj], last[mj]
              if (mj+0>N) r="양호"; else if (mj in last && (mj==N || last[mj]>=n0d)) r="양호"; else r="취약"
              printf "EOS_RES=%s; PATCH_LATEST=\"%s\"; PATCH_DATE=\"%s\"; PATCH_AGE=\"%s\"\n", r, pl, pd, (pd==""?"":jd(today)-jd(pd)) }')"
        local fd; fd=$(echo "$EOS_N0" | sed 's/\(....\)\(..\)\(..\)/\1-\2-\3/')
        local ld; ld=$(echo "$EOS_LASTD" | sed 's/\(....\)\(..\)\(..\)/\1-\2-\3/')
        if [ "$EOS_RES" = "양호" ]; then
            EOS_DESC="macOS ${OS_VER} - Apple 보안 업데이트 지원 중 (지원 주요 버전: ${EOS_SUP}, 해당 버전 최근 보안 릴리스 ${EOS_LASTV:-미확인}${ld:+ ${ld}}) [${src}]"
        else
            EOS_DESC="macOS ${OS_VER} - Apple 보안 업데이트 지원 종료 (최종 보안 릴리스 ${EOS_LASTV:-최근 3년 목록에 없음}${ld:+ ${ld}}, macOS ${EOS_N} 출시(${fd}) 이후 업데이트 없음) - 지원 버전(${EOS_SUP})으로 업그레이드 필요 [${src}]"
        fi
        PATCH_DATE=$(echo "$PATCH_DATE" | sed 's/\(....\)\(..\)\(..\)/\1-\2-\3/')
    else
        # 오프라인 추정: Apple 은 매년 9월 새 주요 버전 출시(26=2025, 27=2026 …) 후 최신 3개 주요 버전만 보안 업데이트
        local y m n list sup oldest
        y=$(date +%Y); m=$(date +%m); m=${m#0}
        n=$((y - 2000)); [ "$m" -ge 9 ] && n=$((n + 1))
        list="11 12 13 14 15"; local k=26; while [ $k -le $n ]; do list="$list $k"; k=$((k+1)); done
        sup=$(echo $list | awk '{print $(NF-2), $(NF-1), $NF}'); oldest=${sup%% *}
        if [ "${major:-0}" -gt "$n" ] 2>/dev/null || echo " $sup " | grep -q " $major "; then
            if [ "$major" = "$oldest" ] && [ "$m" -ge 9 ] && [ "$m" -le 10 ]; then EOS_RES="수동확인"; EOS_DESC="macOS ${OS_VER} - 신규 주요 버전 출시 전환기(지원 종료 가능) - Apple 보안 릴리스 확인 필요 (Apple 서버 조회 실패, 추정 지원 버전: ${sup// /·})"
            else EOS_RES="양호"; EOS_DESC="macOS ${OS_VER} - 보안 업데이트 지원 버전 (Apple 서버 조회 실패 → 추정 지원 버전: ${sup// /·}, support.apple.com/100100 확인 권장)"; fi
        else
            EOS_RES="취약"; EOS_DESC="macOS ${OS_VER} - 보안 업데이트 지원 종료 버전 (Apple 서버 조회 실패 → 추정 지원 버전: ${sup// /·})"
        fi
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
evd "PC-03" "sysadminctl -screenLock status 2>&1; defaults read com.apple.screensaver askForPassword 2>/dev/null; pmset -g custom 2>/dev/null | grep displaysleep"
# macOS 13+ 는 askForPassword 키를 쓰지 않음(설정 앱 '잠금 화면') → sysadminctl -screenLock 우선, 실패 시 구 키 사용
lk=$(sysadminctl -screenLock status 2>&1 | grep -oiE 'immediate|off|[0-9]+ seconds' | head -1)
if [ -z "$lk" ]; then ask_pw=$(defaults read com.apple.screensaver askForPassword 2>/dev/null); [ "$ask_pw" = "1" ] && lk="$(defaults read com.apple.screensaver askForPasswordDelay 2>/dev/null || echo 0) seconds"; [ "$ask_pw" = "0" ] && lk="off"; fi
display_sleep=$(pmset -g custom 2>/dev/null | awk '/displaysleep/{print $2}' | sort -n | tail -1)

if echo "$lk" | grep -qiE 'immediate|seconds'; then
    if [ -n "$display_sleep" ] && [ "$display_sleep" -gt 0 ] 2>/dev/null && [ "$display_sleep" -le 10 ]; then
        result "PC-03|양호|화면잠금 암호 요구(${lk}), 디스플레이절전=${display_sleep}분"
    elif [ -n "$display_sleep" ] && [ "$display_sleep" -gt 0 ] 2>/dev/null; then
        result "PC-03|취약|화면잠금 암호 요구(${lk})이나 디스플레이절전=${display_sleep}분(10분 이하 권장)"
    else
        result "PC-03|취약|화면잠금 암호 요구(${lk})이나 디스플레이절전 미설정(${display_sleep:-미확인})"
    fi
else
    result "PC-03|취약|화면잠금 시 암호 요구 비활성 (screenLock=${lk:-미확인})"
fi

# ── PC-04: 공유폴더 (파일 공유 서비스) ──────────────────────────────
evd "PC-04" "launchctl print system/com.apple.smbd 2>&1 | head -3; netstat -an -p tcp 2>/dev/null | grep LISTEN | grep -E '[.:](445|548) '; sharing -l 2>/dev/null"
# 일반 사용자 'launchctl list' 로는 system 도메인의 smbd 가 보이지 않음 → system 도메인 로드·포트 수신으로 판정
if [ -z "$FS_ON" ]; then
    result "PC-04|양호|파일 공유 서비스(SMB/AFP) 비활성"
else
    shared_list=$(sharing -l 2>/dev/null | awk -F':[ \t]*' '/^name:/{print $2}' | tr '\n' ',' | sed 's/,$//')
    result "PC-04|취약|파일 공유 활성:${FS_ON} 공유=${shared_list:-확인 필요(sudo)}"
fi

# ── PC-05: 불필요 서비스 비활성화 ──────────────────────────────────
evd "PC-05" "launchctl print system/com.apple.screensharing 2>&1 | head -3; netstat -an -p tcp 2>/dev/null | grep LISTEN | grep -E '[.:](5900|3283|69|21) '; pgrep -lx ARDAgent; launchctl list 2>/dev/null | grep -E 'VNCServer|tftpd|bootpd|postfix|ftp-proxy'"
bad_svc=""
[ "$SS_ON" = 1 ] && bad_svc="${bad_svc} 화면공유(VNC)"
[ "$ARD_ON" = 1 ] && bad_svc="${bad_svc} 원격관리(ARD)"
for svc in com.apple.VNCServer \
           com.apple.tftpd \
           com.apple.bootpd \
           org.postfix.master \
           com.apple.ftp-proxy; do
    if launchctl list 2>/dev/null | grep -q "$svc" || _svc_on "$svc"; then
        bad_svc="${bad_svc} ${svc##com.apple.}"
    fi
done

if [ -z "$bad_svc" ]; then
    result "PC-05|양호|불필요 서비스 미실행 (화면공유/VNC/TFTP/BOOTP/FTP 등)"
else
    result "PC-05|취약|실행 중 불필요 서비스:${bad_svc}"
fi

# ── PC-06: 백신 / Gatekeeper ──────────────────────────────────────
evd "PC-06" "spctl --status 2>/dev/null; find /Applications -maxdepth 2 -name '*.app' 2>/dev/null | sed 's#.*/##' | grep -iE '$AV_APP_RE'; ps -axco comm 2>/dev/null | grep -iE '$AV_PROC_RE' | sort -u"
gk_status=$(spctl --status 2>/dev/null)
av_apps="${AV_APPS:+ ${AV_APPS}}"
if echo "$gk_status" | grep -qi "enabled"; then
    if [ -n "$av_apps" ]; then
        result "PC-06|양호|Gatekeeper 활성 + 백신:${av_apps}$([ -n "$AV_PROCS" ] && echo " (실행: ${AV_PROCS})" || echo " (실시간 감시 프로세스 미확인 - 백신 설정 확인)")"
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
# 키 미설정 = macOS 기본값(자동 확인 켜짐). softwareupdate --schedule 결과를 우선 사용
sched=$(softwareupdate --schedule 2>/dev/null)
if echo "$sched" | grep -qi 'turned on'; then auto_on=1
elif echo "$sched" | grep -qi 'turned off'; then auto_on=0
elif [ "$auto_check" = "0" ]; then auto_on=0; else auto_on=1; fi
mac_eos_check   # Apple 보안 릴리스 목록 조회 → 지원 종료(EoS)·미적용 보안 패치
GRACE=${PATCH_GRACE_DAYS:-30}
pmiss=""; [ -n "$PATCH_LATEST" ] && pmiss="미적용 보안 릴리스 ${OS_VER} → ${PATCH_LATEST} (가장 오래된 미적용 배포 ${PATCH_DATE}, ${PATCH_AGE}일 경과)"
au="AutoCheck=${auto_check:-기본 1}, AutoInstall=${auto_install:-미설정}, 긴급패치=${crit_install:-기본 1}"

if [ "$EOS_RES" = "취약" ]; then
    result "PC-07|취약|${EOS_DESC}"
elif [ -n "$PATCH_LATEST" ] && [ "${PATCH_AGE:-0}" -gt "$GRACE" ] 2>/dev/null; then
    result "PC-07|취약|${pmiss} - ${GRACE}일 이상 보안 패치 미적용 (${au})"
elif [ "$auto_on" != "1" ]; then
    result "PC-07|취약|자동 업데이트 확인 비활성 (${au}), OS=${OS_VER}"
else
    result "PC-07|양호|자동 업데이트 활성 (${au}), OS=${OS_VER} 지원 버전$([ -n "$pmiss" ] && echo ", ${pmiss}(유예 ${GRACE}일 이내)")"
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
evd "PC-10" "systemsetup -getremotelogin 2>/dev/null; launchctl print system/com.openssh.sshd 2>&1 | head -2; netstat -an -p tcp 2>/dev/null | grep LISTEN | grep -E '[.:](22|5900|3283) '; pgrep -lx ARDAgent"
remote_login=$(systemsetup -getremotelogin 2>/dev/null)

issues10=""
# systemsetup 은 관리자 권한 없으면 'You need administrator access' 출력('on' 오탐 방지) → ': On' 만 인정, sshd 로드·22 포트 보조 확인
{ echo "$remote_login" | grep -qi ': On' || _svc_on com.openssh.sshd || _listen 22; } && issues10="${issues10} SSH활성"
[ "$ARD_ON" = 1 ] && issues10="${issues10} 원격관리활성"
[ "$SS_ON" = 1 ] && issues10="${issues10} 화면공유활성"

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
