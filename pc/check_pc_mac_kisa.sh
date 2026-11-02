#!/bin/bash
# ================================================================
# PC(macOS) 보안 취약점 자동 점검 스크립트 — 주요정보통신기반시설
# ================================================================
#
# [용도]
#   주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드(한국인터넷진흥원, 2026)
#   [PC] PC-01 ~ PC-18 항목코드·판단기준을 macOS 에 대응하여 점검
#   ※ 가이드 PC 점검 대상은 Windows 10/11 — macOS 에 해당 기능이 없는 항목은 N-A, 대응 기능이 있으면 그 설정으로 판정
#   Windows 는 check_pc_kisa.ps1 사용. (전자금융용 check_pc_mac.sh 와 항목코드 의미가 다르므로 혼용 금지)
#
# [대상 OS]  macOS 12 이상 (bash 3.2 호환)
# [실행 방법]
#   sudo bash check_pc_mac_kisa.sh > ~/Desktop/PC_KISA_$(scutil --get ComputerName | tr ' /' '__').txt
#   - sudo(root) 실행 권장: 시스템 데몬(launchctl)·원격 로그인(systemsetup)·암호 정책(pwpolicy)·공유 목록(sharing)은 root 만 조회 가능.
#     비root 로 실행하면 이들을 볼 수 없는 항목은 '점검불가' 로 출력된다.
#   - sudo 로 실행해도 사용자 설정(화면 잠금·브라우저 등)은 SUDO_USER 또는 콘솔 로그인 사용자 기준으로 읽는다.
# [산출물]
#   1) 표준출력: PC-항목코드|결과|근거설명 (양호/취약/수동확인/점검불가/N-A) + 헤더 # IP / # 실행 계정 / # 클라우드
#      (스크립트 폴더에 PC_KISA_<호스트명>.txt 사본이 자동 저장됨)
#   2) 증적 파일: 스크립트와 같은 폴더 <호스트명>_pc_kisa_evidence.txt (판정에 쓴 원자료 전체)
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
_RESF="${_DIR}/PC_KISA_${HN}.txt"
_safe_new "$_RESF"
if [ -z "$NO_RESULT_COPY" ] && ! [ /dev/fd/1 -ef "$_RESF" ] 2>/dev/null && ( : > "$_RESF" ) 2>/dev/null; then
    exec > >(tee "$_RESF"); _TEEPID=$!
else
    _RESF=""
fi
OS_VER=$(sw_vers -productVersion 2>/dev/null || echo Unknown)
OS_BUILD=$(sw_vers -buildVersion 2>/dev/null || echo "")
OS_MAJOR=${OS_VER%%.*}

echo "# ============================================================"
echo "# 점검 대상: ${HN}"
echo "# OS: macOS ${OS_VER} (${OS_BUILD})"
echo "# 점검 기준: 주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드(2026) [PC PC-01~PC-18]"
echo "# 점검 일시: $(date '+%Y-%m-%d %H:%M:%S')"
echo "# IP: $(ip_list)"
if [ "$IS_ROOT" -eq 1 ]; then echo "# 실행 계정: root"; else echo "# 실행 계정: ${RUN_USER} (관리자 아님 - 일부 항목 점검불가)"; fi
echo "# 사용자 설정 기준 계정: ${TUSER:-없음(콘솔 로그인 사용자 없음)}"
echo "# 클라우드: $(cloud_info)"
echo "# ============================================================"

_CP=0; _CF=0; _CM=0; _CN=0; _CU=0
_EVD="${_DIR}/${HN}_pc_kisa_evidence.txt"
_safe_new "$_EVD"
{ echo "# ================================================================"; echo "# PC(macOS) 증적 파일 (주요정보통신기반시설 상세가이드 2026)"
  echo "# 대상: ${HN} / macOS ${OS_VER}"; echo "# 실행 계정: ${RUN_USER} (root=${IS_ROOT}) / 사용자 설정 기준 계정: ${TUSER:-없음}"
  echo "# 생성: $(date '+%Y-%m-%d %H:%M:%S')"
  echo "# ================================================================"; } > "$_EVD"

# urun <명령...>: 대상 사용자 권한으로 명령 실행 (sudo -n: 암호 프롬프트로 멈추지 않음)
urun() {
    if [ "$IS_ROOT" -eq 1 ]; then
        [ -n "$TUSER" ] || return 3
        sudo -n -H -u "$TUSER" "$@" 2>&1
    else
        "$@" 2>&1
    fi
}
# xint <키> <plist 텍스트>: <key>키</key><integer>N</integer> 의 N (수식 문자열 속 숫자와 혼동하지 않도록 값 요소만 읽음)
xint() { printf '%s\n' "$2" | tr -d '\n\t ' | grep -oE "<key>$1</key><integer>[0-9]+" | grep -oE '[0-9]+$' | awk 'NR==1'; }
USERS=$(dscl . -list /Users UniqueID 2>/dev/null | awk '$2>=500 && $1!~/^_/{print $1}' | tr '\n' ' ')
# 암호 정책: root 만 조회 가능 (전역 정책 + 대상 사용자 정책)
POL=$(pwpolicy getaccountpolicies 2>/dev/null)
POLU=""; [ -n "$TUSER" ] && POLU=$(pwpolicy -u "$TUSER" getaccountpolicies 2>/dev/null)
PROF=""; [ "$IS_ROOT" -eq 1 ] && PROF=$(profiles -P -o stdout 2>/dev/null)

# ── PC-01 비밀번호의 주기적 변경 (최대 사용 기간 90일 이하) ──
evd "PC-01" "pwpolicy getaccountpolicies"
[ -n "$TUSER" ] && evd "PC-01" "pwpolicy -u '$TUSER' getaccountpolicies"
evd "PC-01" "profiles -P -o stdout"
days=$(xint policyAttributeExpiresEveryNDays "$POL$POLU")
[ -z "$days" ] && { m=$(xint maxMinutesUntilChangePassword "$POL$POLU"); [ -n "$m" ] && days=$((m/1440)); }
[ -z "$days" ] && days=$(echo "$PROF" | grep -i maxPINAgeInDays | grep -oE '[0-9]+' | awk 'NR==1')
evq "PC-01" "정책에서 추출한 최대 사용 기간(일) — policyParameters 의 값 요소만 사용" "days=${days:-미설정}"
if [ -z "$POL$POLU$PROF" ]; then result "PC-01|점검불가|암호 정책 조회 불가(pwpolicy/profiles 결과 없음): ${NEED_ROOT}"
elif [ -n "$days" ] && [ "$days" -gt 0 ] && [ "$days" -le 90 ]; then result "PC-01|양호|최대 암호 사용 기간 ${days}일 (90일 이하)"
elif [ -n "$days" ]; then result "PC-01|취약|최대 암호 사용 기간 ${days}일 (90일 초과 또는 제한 없음)"
else result "PC-01|취약|최대 암호 사용 기간 미설정(제한 없음) - 암호 정책에 만료 항목 없음"; fi

# ── PC-02 비밀번호 관리정책 (복잡성·길이) ──
evd "PC-02" "pwpolicy getaccountpolicies"
evd "PC-02" "profiles -P -o stdout"
ALL="$POL$POLU$PROF"
ml=$(echo "$ALL" | grep -oE "\.\{[0-9]+," | grep -oE '[0-9]+' | sort -n | tail -1)
[ -z "$ml" ] && ml=$(xint minChars "$ALL")
[ -z "$ml" ] && ml=$(echo "$PROF" | grep -iE 'minLength' | grep -oE '[0-9]+' | sort -n | tail -1)
alpha=0; num=0; sym=0
{ echo "$ALL" | grep -qE '\[A-Za-z\]|\[a-zA-Z\]'; } && alpha=1
[ "$(xint requiresAlpha "$ALL")" -ge 1 ] 2>/dev/null && alpha=1
{ echo "$ALL" | grep -qE '\[0-9\]'; } && num=1
[ "$(xint requiresNumeric "$ALL")" -ge 1 ] 2>/dev/null && num=1
{ echo "$ALL" | grep -qE '\[\^a-zA-Z0-9\]|\[\^A-Za-z0-9\]'; } && sym=1
[ "$(xint requiresSymbol "$ALL")" -ge 1 ] 2>/dev/null && sym=1
# 구성 프로파일: requireAlphanumeric 이 1(true)일 때만 영문+숫자 충족 (0 은 미충족), minComplexChars 는 1 이상일 때 특수문자
if echo "$PROF" | grep -iE 'requireAlphanumeric' | grep -qE '=[[:space:]]*(1|true)'; then alpha=1; num=1; fi
mcc=$(echo "$PROF" | grep -iE 'minComplexChars' | grep -oE '[0-9]+' | awk 'NR==1')
[ -n "$mcc" ] && [ "$mcc" -ge 1 ] && sym=1
cls=$((alpha+num+sym))
evq "PC-02" "추출한 값 (최소 길이 / 영문 / 숫자 / 특수문자 요구)" "min_len=${ml:-미설정} alpha=$alpha numeric=$num symbol=$sym"
if [ -z "$ALL" ]; then result "PC-02|점검불가|암호 정책 조회 불가(pwpolicy/profiles 결과 없음): ${NEED_ROOT}"
elif [ "${ml:-0}" -ge 8 ] && [ "$cls" -ge 3 ]; then result "PC-02|양호|암호 정책: 최소 ${ml}자, 영문·숫자·특수문자 요구"
else result "PC-02|취약|암호 복잡성 정책 미흡 (최소 길이=${ml:-미설정}, 요구 문자 종류=${cls}종; 기준: 8자 이상·영문·숫자·특수문자)"; fi

# ── PC-03 복구 콘솔 자동 로그온 — Windows 기능 ──
evd "PC-03" "fdesetup status"
evd "PC-03" "firmwarepasswd -check"
result "PC-03|N-A|가이드 점검 대상(Windows 10, Windows 11) 아님 - macOS 는 Windows 복구 콘솔 기능 없음 (참고: FileVault/복구 잠금 상태 증적 확인)"

# ── PC-04 공유 폴더 ──
evd "PC-04" "sharing -l"
evd "PC-04" "launchctl list"
evd "PC-04" "defaults read /Library/Preferences/SystemConfiguration/com.apple.smb.server"
evd "PC-04" "nc -z -w 1 127.0.0.1 445 && echo 'port 445 open' || echo 'port 445 closed'"
SHARING=$(sharing -l 2>/dev/null)
shares=$(echo "$SHARING" | awk -F':[ \t]*' '/^name:/{print $2}' | tr '\n' ',' | sed 's/,$//')
# 공유별 게스트 접근: 'List of Share Points' 블록의 smb/afp 'guest access: 1'
gshare=$(echo "$SHARING" | awk -F':[ \t]*' '/^name:/{n=$2} /guest access/{gsub(/[ \t]/,"",$2); if($2=="1") print n}' | sort -u | tr '\n' ',' | sed 's/,$//')
smb=$(svc_state com.apple.smbd 445)
guest=$(defaults read /Library/Preferences/SystemConfiguration/com.apple.smb.server AllowGuestAccess 2>/dev/null)
if [ "$guest" = "1" ]; then result "PC-04|취약|파일 공유 게스트 접근 허용 (AllowGuestAccess=1), 공유: ${shares:-목록 조회 불가}"
elif [ "$IS_ROOT" -eq 1 ]; then
    if [ -n "$gshare" ]; then result "PC-04|취약|공유 폴더 게스트 접근 허용 (비밀번호 없이 접근): ${gshare}"
    elif [ -z "$shares" ] && [ "$smb" = "off" ]; then result "PC-04|양호|파일 공유 비활성 (공유 폴더 없음)"
    else result "PC-04|수동확인|파일 공유 사용: ${shares:-공유 목록 없음(SMB 서비스 적재: $smb)} - 불필요 공유 여부·접근 권한 확인"; fi
else
    result "PC-04|점검불가|공유 폴더 목록(sharing -l)·SMB 서비스 상태 조회 불가: ${NEED_ROOT} (SMB 포트 445 $([ "$smb" = on ] && echo 열림 || echo 닫힘), AllowGuestAccess=${guest:-미설정})"
fi

# ── PC-05 불필요한 서비스 (원격 로그인·원격 Apple 이벤트·인터넷 공유·원격 관리 등) ──
evd "PC-05" "systemsetup -getremotelogin"
evd "PC-05" "systemsetup -getremoteappleevents"
evd "PC-05" "launchctl list"
evd "PC-05" "cupsctl"
bad=""; unk05=0
if [ "$IS_ROOT" -eq 1 ]; then
    systemsetup -getremotelogin 2>/dev/null | grep -qi ': On' && bad="${bad} 원격 로그인(SSH)"
    systemsetup -getremoteappleevents 2>/dev/null | grep -qi ': On' && bad="${bad} 원격 Apple 이벤트"
    launchctl list 2>/dev/null | awk '$3=="com.apple.InternetSharing"{f=1} END{exit f?0:1}' && bad="${bad} 인터넷 공유"
    launchctl list 2>/dev/null | awk '$3 ~ /^com\.apple\.(tftpd|ftpd|telnetd|bootpd)$/{f=1} END{exit f?0:1}' && bad="${bad} TFTP/FTP/Telnet/BOOTP"
else
    if port_open 22; then bad="${bad} 원격 로그인(SSH, 포트22 리슨)"; else unk05=1; fi
    if port_open 69; then bad="${bad} TFTP(포트69)"; fi
    unk05=1   # Apple 이벤트·인터넷 공유·ftpd/bootpd 적재 여부는 root 필요
fi
cups=$(cupsctl 2>/dev/null | grep -c '_share_printers=1')
[ "${cups:-0}" -gt 0 ] && bad="${bad} 프린터 공유"
if [ -n "$bad" ]; then result "PC-05|취약|불필요한 서비스 사용:${bad} (업무상 필요 시 예외)"
elif [ "$unk05" -eq 1 ]; then result "PC-05|점검불가|원격 Apple 이벤트·인터넷 공유·TFTP/FTP 등 시스템 서비스 상태 조회 불가: ${NEED_ROOT} (포트 22 닫힘, 프린터 공유 없음만 확인)"
else result "PC-05|양호|불필요한 공유·원격 서비스(원격 로그인·Apple 이벤트·인터넷/프린터 공유·TFTP 등) 미사용"; fi

# ── PC-06 비인가 상용 메신저 ──
UAPP=""; [ -n "$TUSER" ] && [ -d "/Users/$TUSER/Applications" ] && UAPP="/Users/$TUSER/Applications"
evd "PC-06" "ls /Applications $UAPP"
msg=$(ls /Applications $UAPP 2>/dev/null | sed 's/\.app$//' | grep -iE '^(kakao|line$|line |telegram|whatsapp|discord|skype|nateon|wechat|signal|viber)' | tr '\n' ',' | sed 's/,$//')
[ -n "$msg" ] && result "PC-06|수동확인|상용 메신저 설치: ${msg} - 기관 인가 메신저 여부 확인 (비인가 시 취약)" || result "PC-06|양호|상용 메신저 미설치"

# ── PC-07 파일 시스템 (NTFS 대응: APFS/HFS+ 저널링) ──
evd "PC-07" "diskutil list internal"
evd "PC-07" "mount"
dl=$(diskutil list internal 2>/dev/null)
fat=$(mount 2>/dev/null | grep -E '^/dev/disk' | grep -iE 'msdos|exfat' | awk '{print $3"("$NF")"}' | tr '\n' ' ')
intfat=$(echo "$dl" | grep -iE 'DOS_FAT|Windows_FAT|ExFAT' | awk '{print $NF}' | tr '\n' ' ')
if [ -z "$dl" ]; then result "PC-07|점검불가|내장 디스크 목록(diskutil list internal) 조회 실패"
elif [ -n "$intfat" ]; then result "PC-07|취약|내장 디스크에 FAT/exFAT 볼륨: ${intfat}"
else result "PC-07|양호|내장 디스크 APFS/HFS+ 사용 (접근 권한 지원 파일 시스템)$([ -n "$fat" ] && echo " / 참고: 외장 FAT 마운트 ${fat}")"; fi

# ── PC-08 멀티 부팅 ──
evd "PC-08" "diskutil list"
evd "PC-08" "bless --info --getboot"
mb=$(diskutil list internal 2>/dev/null | grep -iE 'Microsoft Basic Data|BOOTCAMP|Linux Filesystem' | awk '{print $NF}' | tr '\n' ' ')
if [ -z "$dl" ]; then result "PC-08|점검불가|디스크 목록(diskutil list) 조회 실패"
elif [ -n "$mb" ]; then result "PC-08|취약|다른 OS 파티션 존재(멀티 부팅 가능): ${mb}"
else result "PC-08|양호|단일 OS (Boot Camp·타 OS 파티션 없음)"; fi

# ── PC-09 브라우저 종료 시 임시 파일 삭제 (관리 정책 plist 우선, 대상 사용자 설정) ──
evd "PC-09" "defaults read '/Library/Managed Preferences/com.google.Chrome' ClearBrowsingDataOnExitList"
evd "PC-09" "urd read com.google.Chrome ClearBrowsingDataOnExitList"
evd "PC-09" "defaults read '/Library/Managed Preferences/com.microsoft.Edge' ClearBrowsingDataOnExit"
evd "PC-09" "urd read com.microsoft.Edge ClearBrowsingDataOnExit"
evd "PC-09" "ls /Applications"
ch=$( { defaults read "/Library/Managed Preferences/com.google.Chrome" ClearBrowsingDataOnExitList 2>/dev/null; urd read com.google.Chrome ClearBrowsingDataOnExitList; } | grep -c cached_images_and_files)
ed=$(defaults read "/Library/Managed Preferences/com.microsoft.Edge" ClearBrowsingDataOnExit 2>/dev/null)
[ -z "$ed" ] && ed=$(urd read com.microsoft.Edge ClearBrowsingDataOnExit)
if [ "${ch:-0}" -gt 0 ] || [ "$ed" = "1" ]; then result "PC-09|양호|브라우저 종료 시 캐시 삭제 정책 적용 (Chrome=${ch}, Edge=${ed:-미설정})"
else result "PC-09|수동확인|브라우저 종료 시 임시 파일(캐시) 삭제 정책 미확인 - 사용 브라우저별 설정 확인 (Safari 는 해당 설정 없음)"; fi

# ── PC-10 주기적 보안 패치 (자동 업데이트 + 마지막 설치일 90일 이내) ──
evd "PC-10" "defaults read /Library/Preferences/com.apple.SoftwareUpdate"
evd "PC-10" "softwareupdate --history"
ac=$(defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled 2>/dev/null)
cr=$(defaults read /Library/Preferences/com.apple.SoftwareUpdate CriticalUpdateInstall 2>/dev/null)
last=$(softwareupdate --history 2>/dev/null | awk 'NR>2{
    if (match($0, /[0-9][0-9][0-9][0-9][.\/-] ?[0-9][0-9]?[.\/-] ?[0-9][0-9]?/)) { d=substr($0,RSTART,RLENGTH); gsub(/ /,"",d); split(d,a,/[.\/-]/); printf "%04d-%02d-%02d\n", a[1],a[2],a[3] }
    else if (match($0, /[0-9][0-9]?\/[0-9][0-9]?\/[0-9][0-9][0-9][0-9]/)) { split(substr($0,RSTART,RLENGTH),a,"/"); printf "%04d-%02d-%02d\n", a[3],a[1],a[2] }
}' | sort | tail -1)
age=""
if [ -n "$last" ]; then
    le=$(date -j -f '%Y-%m-%d' "$last" '+%s' 2>/dev/null)
    [ -n "$le" ] && age=$(( ($(date '+%s') - le) / 86400 ))
fi
evq "PC-10" "자동 업데이트 설정 / 마지막 설치일(softwareupdate --history) / 경과일" "AutomaticCheckEnabled=${ac:-미설정(기본 1)} CriticalUpdateInstall=${cr:-미설정(기본 1)} last=${last:-확인 불가} age_days=${age:-확인 불가}"
if [ "$ac" = "0" ] || [ "$cr" = "0" ]; then result "PC-10|취약|자동 업데이트 비활성 (AutomaticCheckEnabled=${ac:-기본}, CriticalUpdateInstall=${cr:-기본}) - 최근 설치 ${last:-확인 불가}"
elif [ -n "$age" ] && [ "$age" -gt 90 ]; then result "PC-10|취약|최근 업데이트 설치일 ${last} 로부터 ${age}일 경과 (90일 초과; 자동 업데이트 설정은 활성)"
else result "PC-10|양호|자동 업데이트·보안 응답 설치 활성 (AutomaticCheck=${ac:-기본 1}, Critical=${cr:-기본 1}), 최근 설치 ${last:-확인 불가}${age:+ (${age}일 전)} - 내부 관리 절차는 인터뷰 확인"; fi

# ── PC-11 지원이 종료되지 않은 OS (Windows Build → macOS 버전) ──
evd "PC-11" "sw_vers"
# Apple 은 최신 3개 주요 버전에 보안 업데이트 제공. 지원 최소 주 버전은 MAC_MIN_SUPPORTED 환경변수로 조정 (기본 15: 2026-09 기준 macOS 27·26·15)
MIN_SUP="${MAC_MIN_SUPPORTED:-15}"
evq "PC-11" "판정에 쓴 값 (OS 주 버전 / 지원 최소 주 버전 기준)" "OS_MAJOR=${OS_MAJOR} MIN_SUPPORTED=${MIN_SUP}"
if ! [ "${OS_MAJOR:-0}" -ge 1 ] 2>/dev/null; then result "PC-11|점검불가|macOS 버전(sw_vers) 조회 실패"
elif [ "$OS_MAJOR" -ge "$MIN_SUP" ]; then result "PC-11|양호|macOS ${OS_VER} - 보안 업데이트 지원 버전 (기준: 주 버전 ${MIN_SUP} 이상)"
elif [ "$OS_MAJOR" -eq $((MIN_SUP-1)) ]; then result "PC-11|수동확인|macOS ${OS_VER} - 최신 3개 버전에서 제외(보안 업데이트 종료 전환) - Apple 보안 릴리스 확인, macOS ${MIN_SUP} 이상 업그레이드 권고"
else result "PC-11|취약|macOS ${OS_VER} - 보안 업데이트 지원 종료 버전 (macOS ${MIN_SUP} 이상 필요)"; fi

# ── PC-12 자동 로그인 ──
evd "PC-12" "defaults read /Library/Preferences/com.apple.loginwindow autoLoginUser"
evd "PC-12" "ls -l /etc/kcpassword"
al=$(defaults read /Library/Preferences/com.apple.loginwindow autoLoginUser 2>/dev/null)
if [ -n "$al" ] || [ -f /etc/kcpassword ]; then result "PC-12|취약|자동 로그인 활성 (autoLoginUser=${al:-설정됨}, kcpassword $([ -f /etc/kcpassword ] && echo 존재 || echo 없음))"
else result "PC-12|양호|자동 로그인 비활성"; fi

# ── PC-13 / PC-14 백신 설치·업데이트 / 실시간 감시 ──
AVRE='kaspersky|ahnlab|^v3( |lite|365|$)|alyac|sophos|symantec|norton|mcafee|trend ?micro|eset|bitdefender|crowdstrike|falcon|sentinel|defender|malwarebytes|avast|avira'
evd "PC-13" "ls /Applications"
evd "PC-13" "ps -axo comm"
evd "PC-13" "system_profiler SPInstallHistoryDataType"
evd "PC-14" "ps -axo comm"
evd "PC-14" "ls /Applications"
av=$(ls /Applications 2>/dev/null | sed 's/\.app$//' | grep -iE "$AVRE" | tr '\n' ',' | sed 's/,$//')
# 실행 중 프로세스: 실행 파일 이름 앞부분 일치 (부분 문자열 오탐 방지)
avp=$(ps -axo comm 2>/dev/null | awk -F/ '{print $NF}' | grep -iE '^(wdav|falcond|falcon-sensor|sentinelagent|sentineld|sophos|savd|symantec|norton|mcafee|eset|esets|bdagent|bdservicehost|kav|kaspersky|ahnlab|v3|avast|avgd|malwarebytes|mbam|avira)' | sort -u | tr '\n' ',' | sed 's/,$//')
xp=$(system_profiler SPInstallHistoryDataType 2>/dev/null | grep -A4 'XProtectPlistConfigData' | grep -i 'Install Date' | tail -1 | sed 's/.*: //')
if [ -n "$av" ]; then
    result "PC-13|수동확인|백신 설치: ${av} - 엔진·패턴 최신 업데이트 여부 백신 콘솔에서 확인 (XProtect 최근 갱신: ${xp:-미확인})"
    if [ -n "$avp" ]; then result "PC-14|양호|백신 실시간 감시 프로세스 실행: ${avp}"; else result "PC-14|수동확인|백신(${av}) 실시간 감시 프로세스 미확인 - 백신 설정에서 실시간 보호 확인"; fi
else
    result "PC-13|수동확인|별도 백신 미설치 - macOS 내장 XProtect 만 존재(최근 갱신: ${xp:-미확인}) → 기관 정책상 인정 여부 판단 (미인정 시 취약)"
    result "PC-14|수동확인|별도 백신 미설치 - XProtect 는 실행 시점 검사(상시 감시 설정 없음) → 기관 정책상 인정 여부 판단 (미인정 시 취약)"
fi

# ── PC-15 OS 침입차단 기능(방화벽) ──
evd "PC-15" "/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate"
evd "PC-15" "/usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode"
fw=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null)
if [ -z "$fw" ]; then result "PC-15|점검불가|방화벽 상태(socketfilterfw --getglobalstate) 조회 실패"
elif echo "$fw" | grep -qE 'State = [12]|is enabled'; then result "PC-15|양호|macOS 방화벽 사용 (${fw})"
else result "PC-15|취약|macOS 방화벽 사용 안 함 (${fw})"; fi

# ── PC-16 화면보호기 대기 10분 이하 + 암호 (대상 사용자 설정 + 전원 소스별 디스플레이 절전) ──
evd "PC-16" "urd -currentHost read com.apple.screensaver idleTime"
evd "PC-16" "urd read com.apple.screensaver askForPassword"
evd "PC-16" "urd read com.apple.screensaver askForPasswordDelay"
evd "PC-16" "urun sysadminctl -screenLock status"
evd "PC-16" "pmset -g custom"
if [ "$IS_ROOT" -eq 1 ] && [ -z "$TUSER" ]; then
    result "PC-16|점검불가|콘솔에 로그인한 사용자가 없어 사용자 화면 잠금 설정을 읽을 수 없음"
else
    idle=$(urd -currentHost read com.apple.screensaver idleTime)
    askpw=$(urd read com.apple.screensaver askForPassword)
    askdl=$(urd read com.apple.screensaver askForPasswordDelay)
    lkst=$(urun sysadminctl -screenLock status)
    ds_all=$(pmset -g custom 2>/dev/null | awk '/displaysleep/{print $2}')
    dsl=""
    for v in $ds_all; do
        if [ "$v" = "0" ]; then dsl=0; break; fi
        { [ -z "$dsl" ] || [ "$v" -gt "$dsl" ]; } 2>/dev/null && dsl=$v
    done
    t=${idle:-0}; [ "$t" -eq 0 ] 2>/dev/null && [ -n "$dsl" ] && [ "$dsl" -gt 0 ] && t=$((dsl*60))
    pwok=0
    [ "$askpw" = "1" ] && pwok=1
    echo "$lkst" | grep -qiE 'immediate|[0-9]+ (seconds|minutes)' && pwok=1
    evq "PC-16" "판정에 쓴 값 (사용자 ${TUSER}) idleTime(초) / askForPassword / askForPasswordDelay / sysadminctl -screenLock / displaysleep(분, 배터리·AC 최악)" "idleTime=${idle:-미설정} askForPassword=${askpw:-미설정} askForPasswordDelay=${askdl:-미설정} screenLock=[${lkst}] displaysleep=${dsl:-미확인} → 유효 대기=${t}초 암호요구=${pwok}"
    if [ "$t" -gt 0 ] 2>/dev/null && [ "$t" -le 600 ] && [ "$pwok" -eq 1 ]; then result "PC-16|양호|화면보호기/디스플레이 끄기 $((t/60))분, 해제 시 암호 요구 (사용자 ${TUSER}, askForPassword=${askpw:-미설정}, delay=${askdl:-미설정}초)"
    else result "PC-16|취약|화면보호기 설정 미흡 (대기=${idle:-미설정}초, 디스플레이 끄기=${dsl:-미확인}분, 암호 요구=${askpw:-미설정}/${lkst:-미확인}; 기준: 10분 이하 + 암호)"; fi
fi

# ── PC-17 이동식 미디어 자동 실행 방지 ──
evd "PC-17" "urd read com.apple.digihub"
if [ "$IS_ROOT" -eq 1 ] && [ -z "$TUSER" ]; then
    result "PC-17|점검불가|콘솔에 로그인한 사용자가 없어 디스크 삽입 동작(com.apple.digihub) 설정을 읽을 수 없음"
else
    dh=$(urd read com.apple.digihub | grep -E 'action' | grep -vE '= 1;')
    if [ -n "$dh" ]; then result "PC-17|수동확인|CD/DVD 삽입 시 동작 설정 존재(사용자 ${TUSER}): $(echo $dh) - 자동 실행 여부 확인"
    else result "PC-17|양호|macOS 는 이동식 미디어 자동 실행(AutoRun) 기능 없음 (digihub 동작 설정 없음) - 이동식 미디어 관리 절차는 인터뷰 확인"; fi
fi

# ── PC-18 원격 지원(화면 공유·원격 관리) 금지 ──
evd "PC-18" "launchctl list"
evd "PC-18" "ps -axo comm"
evd "PC-18" "nc -z -w 1 127.0.0.1 5900 && echo 'port 5900 open' || echo 'port 5900 closed'"
rs=""; unk18=0
case "$(svc_state com.apple.screensharing 5900)" in on) rs="${rs} 화면 공유" ;; unk) unk18=1 ;; esac
ps -axo comm 2>/dev/null | awk -F/ '$NF=="ARDAgent"{f=1} END{exit f?0:1}' && rs="${rs} 원격 관리(ARD)"
tp=$(ps -axo comm 2>/dev/null | awk -F/ '{print $NF}' | grep -iE '^(TeamViewer|AnyDesk|RemoteView|Chrome Remote|remoting_host)' | sort -u | tr '\n' ',' | sed 's/,$//')
[ -n "$tp" ] && rs="${rs} 원격 지원 프로그램(${tp})"
if [ -n "$rs" ]; then result "PC-18|취약|원격 지원 기능 사용:${rs}"
elif [ "$unk18" -eq 1 ]; then result "PC-18|점검불가|화면 공유 서비스 적재 여부 조회 불가: ${NEED_ROOT} (포트 5900 닫힘, ARD·원격 지원 프로세스 없음만 확인)"
else result "PC-18|양호|화면 공유·원격 관리·원격 지원 프로그램 미사용"; fi

echo "# ============================================================"
echo "# 점검 요약 - 주요정보통신기반시설 상세가이드(2026) PC(macOS)"
echo "#   양호: ${_CP} / 취약: ${_CF} / 수동확인: ${_CM} / 점검불가: ${_CU} / N-A: ${_CN}"
echo "# 증적 파일: ${_EVD}"
echo "# ============================================================"
[ -n "$_RESF" ] && echo "# 결과 파일(자동 저장): ${_RESF}  ← 증적 파일과 함께 회수"
[ -n "$_TEEPID" ] && { exec >&- 2>/dev/null; wait "$_TEEPID" 2>/dev/null; sleep 1; }
exit 0
