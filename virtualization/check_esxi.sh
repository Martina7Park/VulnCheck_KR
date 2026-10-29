#!/bin/sh
# ================================================================
# 가상화(VMware ESXi 하이퍼바이저) 보안 취약점 자동 점검 스크립트
# ================================================================
#
# [용도]
#   VMware ESXi 호스트 설정을 ESX-01 ~ ESX-30 항목으로 점검 (전자금융·주요정보 공통 자체 항목)
#   항목 근거: VMware vSphere 보안 구성 가이드(SCG)·CIS VMware ESXi 벤치마크, 판단 수치는 국내 기준에 맞춤
#   (비밀번호 3종류 8자/2종류 10자, 잠금 5회, 세션 10분, 사용 기간 90일)
#   ※ 기관 기준표에 가상화 항목이 따로 있으면 컨버터 HV_ITEMS 의 항목명·기준을 그에 맞춰 조정
#
# [대상]   ESXi 6.5 / 6.7 / 7.0 / 8.0 / 9.0 — ESXi Shell(busybox sh) 호환, bash 불필요
#          vCenter Server(VCSA)는 이 스크립트 대상 아님 → server/check_server.sh (Photon OS) 로 점검
# [실행 방법]
#   1) SSH(또는 ESXi Shell) 를 임시로 켜고 스크립트를 데이터스토어에 복사
#        scp check_esxi.sh root@<ESXi>:/vmfs/volumes/datastore1/
#   2) 실행 (root)
#        ssh root@<ESXi> 'sh /vmfs/volumes/datastore1/check_esxi.sh'
#   3) 스크립트 폴더의 결과·증적 2개 파일 회수 → 점검 후 스크립트·결과 삭제, SSH 다시 중지
#   잠금 모드(Lockdown)가 켜진 호스트는 예외 사용자(Exception Users) 계정으로 실행하거나 점검 시간 동안만 해제
# [산출물]
#   1) 표준출력 + 결과 파일: <호스트>_esxi.txt          ESX-항목코드|결과|근거설명 (양호/취약/수동확인/N-A)
#   2) 증적 파일          : <호스트>_esxi_evidence.txt  항목별 실행 명령·출력
#   저장 위치: 스크립트 폴더 (쓰기 불가 시 /tmp) — OUT_DIR=<경로> 로 변경 가능
# [안전성]
#   조회 명령(esxcli ... get/list, vim-cmd ... 조회)만 실행 — 설정을 바꾸지 않음
# ================================================================

if [ "$(uname -s 2>/dev/null)" != "VMkernel" ] && [ -z "$ESXI_CHECK_FORCE" ]; then
    echo "# [오류] VMware ESXi 호스트가 아닙니다 ($(uname -sr 2>/dev/null))."
    echo "#        vCenter Server(VCSA)·일반 Linux 는 server/check_server.sh 로 점검하십시오."
    exit 1
fi

# ── 호스트 식별 (FQDN, 관리 IP) ─────────────────────────────────
HN=$(esxcli system hostname get 2>/dev/null | awk -F': ' '/Fully Qualified Domain Name/{print $2}')
[ -z "$HN" ] && HN=$(hostname 2>/dev/null || uname -n)
MGMT_IP=$(esxcli network ip interface ipv4 get 2>/dev/null | awk 'NR>2 && $1=="vmk0"{print $2; exit}')
[ -z "$MGMT_IP" ] && MGMT_IP=$(esxcli network ip interface ipv4 get 2>/dev/null | awk 'NR>2 && $2 ~ /^[0-9]+\./{print $2; exit}')
case "$HN" in   # 기본 호스트명은 대상끼리 겹침 → 관리 IP 를 붙여 결과 파일·보고서에서 구분
localhost|localhost.*|"") [ -n "$MGMT_IP" ] && HN="${HN:-localhost}_${MGMT_IP}" ;;
esac
HN=$(echo "$HN" | tr ' /' '__')

VER_RAW=$(esxcli system version get 2>/dev/null)
ESX_VER=$(echo "$VER_RAW" | awk -F': ' '/^ *Version:/{print $2}')
ESX_BUILD=$(echo "$VER_RAW" | awk -F': ' '/^ *Build:/{print $2}' | sed 's/^Releasebuild-//')
ESX_UPD=$(echo "$VER_RAW" | awk -F': ' '/^ *Update:/{print $2}')
[ -z "$ESX_VER" ] && ESX_VER=$(vmware -v 2>/dev/null | awk '{print $3}')
[ -z "$ESX_BUILD" ] && ESX_BUILD=$(vmware -v 2>/dev/null | sed -n 's/.*build-\([0-9]*\).*/\1/p')
ESX_MAJ=$(echo "$ESX_VER" | cut -d. -f1)
ESX_MIN=$(echo "$ESX_VER" | cut -d. -f2)
case "$ESX_MAJ" in ''|*[!0-9]*) ESX_MAJ=0 ;; esac
case "$ESX_MIN" in ''|*[!0-9]*) ESX_MIN=0 ;; esac

_DIR=${OUT_DIR:-$(cd "$(dirname "$0")" 2>/dev/null && pwd)}
( : > "${_DIR}/.esxi_w" ) 2>/dev/null && rm -f "${_DIR}/.esxi_w" || _DIR=/tmp
_RESF="${_DIR}/${HN}_esxi.txt"
_EVD="${_DIR}/${HN}_esxi_evidence.txt"

# ── 공통 함수 ────────────────────────────────────────────────────
_CP=0; _CF=0; _CM=0; _CN=0
result() {   # result <코드> <결과> <근거>
    _line="$1|$2|$3"
    echo "$_line"
    case "$2" in 양호) _CP=$((_CP+1)) ;; 취약) _CF=$((_CF+1)) ;; 수동확인) _CM=$((_CM+1)) ;; *) _CN=$((_CN+1)) ;; esac
    printf '[판정] %s\n\n' "$_line" >> "$_EVD"
}
evd() {   # evd <코드> <명령> — 명령과 출력을 증적에 기록
    _item="$1"; shift
    printf '[%s] %s $ %s\n' "$_item" "$(date '+%H:%M:%S')" "$*" >> "$_EVD"
    eval "$@" >> "$_EVD" 2>&1
    printf '\n' >> "$_EVD"
}
adv() {   # adv <고급 설정 경로> → ADV_OK(1/0), ADV_VAL
    _o=$(esxcli system settings advanced list -o "$1" 2>/dev/null)
    if [ -z "$_o" ] || ! echo "$_o" | grep -q 'Path:'; then ADV_OK=0; ADV_VAL=""; return 1; fi
    ADV_OK=1
    ADV_VAL=$(echo "$_o" | awk '
        /^ *Type:/         { t = substr($0, index($0, ":") + 2) }
        /^ *Int Value:/    { iv = substr($0, index($0, ":") + 2) }
        /^ *String Value:/ { sv = substr($0, index($0, ":") + 2) }
        END { if (t ~ /string/) print sv; else if (iv != "") print iv; else print sv }')
    return 0
}
isnum() { case "$1" in ''|*[!0-9]*) return 1 ;; *) return 0 ;; esac; }
istrue() { case "$(echo "$1" | tr 'A-Z' 'a-z')" in true|1|yes|on) return 0 ;; *) return 1 ;; esac; }

HOSTCFG=$(vim-cmd hostsvc/hostconfig 2>/dev/null)
HSUM=$(vim-cmd hostsvc/hostsummary 2>/dev/null)
svc_state() {   # svc_state <vim 서비스 키> <init.d 이름> → SVC_RUN(1/0/?), SVC_POL(on/off/automatic/?), SVC_FOUND(1/0)
    SVC_RUN="?"; SVC_POL="?"; SVC_FOUND=0
    _b=$(echo "$HOSTCFG" | awk -v k="$1" '
        index($0, "key = \"" k "\"") { f = 1; next }
        f && /key = "/               { exit }
        f && /running = /            { r = $0 }
        f && /policy = /             { print r; print $0; exit }')
    if [ -n "$_b" ]; then
        SVC_FOUND=1
        echo "$_b" | grep -q 'running = true' && SVC_RUN=1
        echo "$_b" | grep -q 'running = false' && SVC_RUN=0
        SVC_POL=$(echo "$_b" | sed -n 's/.*policy = "\([^"]*\)".*/\1/p')
        [ -z "$SVC_POL" ] && SVC_POL="?"
    fi
    if [ -x "/etc/init.d/$2" ]; then
        SVC_FOUND=1
        if [ "$SVC_RUN" = "?" ]; then
            _s=$(/etc/init.d/$2 status 2>&1)
            case "$_s" in *"not running"*|*stopped*|*"is not"*) SVC_RUN=0 ;; *running*) SVC_RUN=1 ;; esac
        fi
        if [ "$SVC_POL" = "?" ] && command -v chkconfig >/dev/null 2>&1; then
            _c=$(chkconfig --list "$2" 2>/dev/null | awk '{print $NF}')
            case "$_c" in on) SVC_POL=on ;; off) SVC_POL=off ;; esac
        fi
    fi
}
svc_desc() { # 현재 상태 문구
    _r="상태 미확인"; [ "$SVC_RUN" = 1 ] && _r="실행 중"; [ "$SVC_RUN" = 0 ] && _r="중지"
    case "$SVC_POL" in on) _p="호스트와 함께 시작(on)" ;; automatic) _p="포트 사용 시 자동 시작(automatic)" ;; off) _p="수동 시작(off)" ;; *) _p="시작 정책 미확인" ;; esac
    echo "${_r}, ${_p}"
}

TODAY=$(date '+%Y%m%d')
isnum "$TODAY" || TODAY=0

{
echo "# ================================================================"
echo "# 가상화(VMware ESXi) 증적 파일"
echo "# 대상: ${HN} / IP ${MGMT_IP:-미확인} / ESXi ${ESX_VER} build-${ESX_BUILD}"
echo "# 생성: $(date '+%Y-%m-%d %H:%M:%S')"
echo "# ================================================================"
} > "$_EVD"

main() {
echo "# ============================================================"
echo "# 점검 대상: ${HN}"
echo "# OS: VMware ESXi ${ESX_VER:-미확인} build-${ESX_BUILD:-미확인}$( [ -n "$ESX_UPD" ] && [ "$ESX_UPD" != 0 ] && echo " (Update ${ESX_UPD})")"
echo "# IP: ${MGMT_IP:-미확인}"
echo "# 점검 기준: 가상화(VMware ESXi) 점검 항목 ESX-01~ESX-30 [VMware vSphere 보안 구성 가이드·CIS ESXi 벤치마크 기반, 전자금융·주요정보 공통]"
echo "# 점검 일시: $(date '+%Y-%m-%d %H:%M:%S')"
echo "# ============================================================"
evd "INFO-01" "vmware -vl; esxcli system version get; esxcli system hostname get; esxcli network ip interface ipv4 get"

# ================================================================
# 1. 계정 관리
# ================================================================

# ── ESX-01 불필요한 로컬 계정 제거 ──
evd "ESX-01" "esxcli system account list; esxcli system permission list"
ACC=$(esxcli system account list 2>/dev/null | awk 'NR>2 && NF{print $1}')
extra=$(echo "$ACC" | grep -vE '^(root|dcui|vpxuser)$' | grep -v '^$' | tr '\n' ',' | sed 's/,$//')
if [ -z "$ACC" ]; then result "ESX-01" "수동확인" "로컬 계정 목록 조회 실패 - Host Client [관리]→[보안 및 사용자]→[사용자]에서 불필요 계정 확인"
elif [ -z "$extra" ]; then result "ESX-01" "양호" "기본 계정(root·dcui·vpxuser)만 존재: $(echo $ACC | tr ' ' ',')"
else result "ESX-01" "수동확인" "기본(root·dcui·vpxuser) 외 로컬 계정: ${extra} - 사용자·용도·권한 확인 (퇴직자·공용·미사용 계정이면 취약)"; fi

# ── ESX-02 비밀번호 복잡성 설정 (pam_passwdqc min=N0,N1,N2,N3,N4) ──
evd "ESX-02" "esxcli system settings advanced list -o /Security/PasswordQualityControl; grep -h pam_passwdqc /etc/pam.d/passwd /etc/pam.d/system-auth 2>/dev/null"
adv /Security/PasswordQualityControl; PQ="$ADV_VAL"
[ "$ADV_OK" = 1 ] || PQ=$(grep -h pam_passwdqc /etc/pam.d/passwd /etc/pam.d/system-auth 2>/dev/null | head -1)
PQMIN=$(echo "$PQ" | sed -n 's/.*min=\([^ ]*\).*/\1/p')
# N0 1종류=disabled, N1 2종류>=10, N2 패스프레이즈>=10, N3 3종류>=8, N4 4종류>=8 (disabled 는 해당 조합 금지 = 더 엄격)
PQV=$(echo "$PQMIN" | awk -F, '
    NF < 5 { print "?"; exit }
    { split("0 10 10 8 8", t, " "); bad = ""
      if ($1 != "disabled") bad = bad " 1종류 허용(" $1 ")"
      for (i = 2; i <= 5; i++) if ($i != "disabled" && $i + 0 < t[i]) bad = bad " N" i-1 "=" $i "(기준 " t[i] "자 이상)"
      print (bad == "" ? "ok" : bad) }')
if [ -z "$PQMIN" ] || [ "$PQV" = "?" ]; then result "ESX-02" "수동확인" "비밀번호 복잡성 정책(pam_passwdqc min=) 확인 불가 (${PQ:-값 없음})"
elif [ "$PQV" = "ok" ]; then result "ESX-02" "양호" "비밀번호 복잡성: min=${PQMIN} (3종류 8자·2종류 10자 이상, 1종류 금지)"
else result "ESX-02" "취약" "비밀번호 복잡성 미흡: min=${PQMIN} -${PQV} - 기준: 영문·숫자·특수문자 3종류 8자 이상 또는 2종류 10자 이상 (예: min=disabled,disabled,disabled,8,8)"; fi

# ── ESX-03 비밀번호 최대 사용 기간 ──
evd "ESX-03" "esxcli system settings advanced list -o /Security/PasswordMaxDays"
if adv /Security/PasswordMaxDays && isnum "$ADV_VAL"; then
    if [ "$ADV_VAL" -ge 1 ] && [ "$ADV_VAL" -le 90 ]; then result "ESX-03" "양호" "비밀번호 최대 사용 기간 ${ADV_VAL}일 (90일 이하)"
    else result "ESX-03" "취약" "비밀번호 최대 사용 기간 ${ADV_VAL}일 (기준 90일 이하, Security.PasswordMaxDays)"; fi
else result "ESX-03" "수동확인" "Security.PasswordMaxDays 미지원 버전(ESXi 7.0 U2 미만) - 비밀번호 주기 변경 관리 절차 인터뷰 확인"; fi

# ── ESX-04 비밀번호 재사용 제한 ──
evd "ESX-04" "esxcli system settings advanced list -o /Security/PasswordHistory; grep -h remember= /etc/pam.d/passwd /etc/pam.d/system-auth 2>/dev/null"
if adv /Security/PasswordHistory && isnum "$ADV_VAL"; then PH="$ADV_VAL"
else PH=$(grep -h -o 'remember=[0-9]*' /etc/pam.d/passwd /etc/pam.d/system-auth 2>/dev/null | head -1 | cut -d= -f2); fi
if ! isnum "$PH"; then result "ESX-04" "수동확인" "비밀번호 재사용 제한 설정 확인 불가 (Security.PasswordHistory 미지원 버전)"
elif [ "$PH" -ge 5 ]; then result "ESX-04" "양호" "최근 비밀번호 ${PH}개 재사용 금지"
else result "ESX-04" "취약" "최근 비밀번호 재사용 제한 ${PH}개 (기준 5개 이상, Security.PasswordHistory)"; fi

# ── ESX-05 계정 잠금 임계값 설정 ──
evd "ESX-05" "esxcli system settings advanced list -o /Security/AccountLockFailures; esxcli system settings advanced list -o /Security/AccountUnlockTime"
adv /Security/AccountLockFailures; LF="$ADV_VAL"
adv /Security/AccountUnlockTime; LU="$ADV_VAL"
if ! isnum "$LF"; then result "ESX-05" "수동확인" "Security.AccountLockFailures 조회 불가 - 계정 잠금 정책 확인"
elif [ "$LF" -ge 1 ] && [ "$LF" -le 5 ]; then result "ESX-05" "양호" "로그인 ${LF}회 실패 시 잠금 (잠금 해제 ${LU:-?}초)"
elif [ "$LF" -eq 0 ]; then result "ESX-05" "취약" "계정 잠금 미사용 (Security.AccountLockFailures=0, 기준 5회 이하)"
else result "ESX-05" "취약" "계정 잠금 임계값 ${LF}회 (기준 5회 이하)"; fi

# ── ESX-06 AD 연동 시 관리자 그룹(ESX Admins) 자동 권한 제한 (CVE-2024-37085) ──
evd "ESX-06" "/usr/lib/vmware/likewise/bin/domainjoin-cli query 2>/dev/null; esxcli system settings advanced list -o /Config/HostAgent/plugins/hostsvc/esxAdminsGroup; esxcli system settings advanced list -o /Config/HostAgent/plugins/hostsvc/esxAdminsGroupAutoAdd"
DOM=$(/usr/lib/vmware/likewise/bin/domainjoin-cli query 2>/dev/null | awk -F'= *' '/^Domain/{print $2; exit}' | tr -d ' ')
[ -z "$DOM" ] && DOM=$(echo "$HOSTCFG" | sed -n 's/.*joinedDomain = "\([^"]\{1,\}\)".*/\1/p' | head -1)
adv /Config/HostAgent/plugins/hostsvc/esxAdminsGroup; AG="$ADV_VAL"
adv /Config/HostAgent/plugins/hostsvc/esxAdminsGroupAutoAdd; AA_OK=$ADV_OK; AA="$ADV_VAL"
if [ -z "$DOM" ]; then result "ESX-06" "양호" "Active Directory 미연동 - 'ESX Admins' 그룹 자동 관리자 권한 취약점(CVE-2024-37085) 해당 없음"
elif [ "$AA_OK" = 1 ] && ! istrue "$AA"; then result "ESX-06" "양호" "AD(${DOM}) 연동, 관리자 그룹 자동 추가 비활성 (esxAdminsGroupAutoAdd=${AA})"
elif [ -n "$AG" ] && [ "$AG" != "ESX Admins" ]; then result "ESX-06" "양호" "AD(${DOM}) 연동, 관리자 그룹을 기본값이 아닌 '${AG}' 로 지정 - 그룹 구성원 관리 절차 확인"
else result "ESX-06" "취약" "AD(${DOM}) 연동, 기본 그룹 '${AG:-ESX Admins}' 자동 관리자 권한 허용 - CVE-2024-37085 (esxAdminsGroupAutoAdd=false 또는 그룹명 변경, 패치 적용)"; fi

# ================================================================
# 2. 서비스 관리
# ================================================================

# ── ESX-07 SSH 서비스 상시 활성화 제한 ──
evd "ESX-07" "echo \"\$HOSTCFG\" | grep -A8 'key = \"TSM-SSH\"'; chkconfig --list SSH 2>/dev/null; /etc/init.d/SSH status 2>&1; ls -l /etc/ssh/keys-root/authorized_keys 2>/dev/null; grep -c . /etc/ssh/keys-root/authorized_keys 2>/dev/null"
svc_state "TSM-SSH" "SSH"
NKEY=$(grep -cE '^(ssh-|ecdsa-|sk-)' /etc/ssh/keys-root/authorized_keys 2>/dev/null); isnum "$NKEY" || NKEY=0
KNOTE=""; [ "$NKEY" -gt 0 ] && KNOTE=" / root 공개키 ${NKEY}개 등록(/etc/ssh/keys-root/authorized_keys)"
case "$SVC_POL" in
on|automatic) result "ESX-07" "취약" "SSH 서비스 상시 사용: $(svc_desc)${KNOTE} - 시작 정책 '수동(off)'으로 변경, 작업 시에만 시작" ;;
off) if [ "$NKEY" -gt 0 ]; then result "ESX-07" "수동확인" "SSH $(svc_desc)${KNOTE} - 등록 키의 소유자·용도 확인 (불필요 시 삭제)"
     elif [ "$SVC_RUN" = 1 ]; then result "ESX-07" "양호" "SSH $(svc_desc) - 점검을 위한 임시 실행이면 점검 후 중지"
     else result "ESX-07" "양호" "SSH $(svc_desc)"; fi ;;
*) result "ESX-07" "수동확인" "SSH 서비스 시작 정책 확인 불가 ($(svc_desc))${KNOTE} - Host Client [관리]→[서비스]에서 TSM-SSH 정책 확인" ;;
esac

# ── ESX-08 ESXi Shell 상시 활성화 제한 ──
evd "ESX-08" "echo \"\$HOSTCFG\" | grep -A8 'key = \"TSM\"'; chkconfig --list ESXShell 2>/dev/null; /etc/init.d/ESXShell status 2>&1"
svc_state "TSM" "ESXShell"
case "$SVC_POL" in
on|automatic) result "ESX-08" "취약" "ESXi Shell 상시 사용: $(svc_desc) - 시작 정책 '수동(off)'으로 변경" ;;
off) result "ESX-08" "양호" "ESXi Shell $(svc_desc)$( [ "$SVC_RUN" = 1 ] && echo ' - 점검을 위한 임시 실행이면 점검 후 중지')" ;;
*) result "ESX-08" "수동확인" "ESXi Shell 시작 정책 확인 불가 ($(svc_desc))" ;;
esac

# ── ESX-09 SLP 서비스 비활성화 (OpenSLP 원격 코드 실행: CVE-2021-21974 등, ESXiArgs 랜섬웨어) ──
evd "ESX-09" "echo \"\$HOSTCFG\" | grep -A8 'key = \"slpd\"'; /etc/init.d/slpd status 2>&1; chkconfig --list slpd 2>/dev/null; esxcli network firewall ruleset list -r CIMSLP 2>/dev/null"
svc_state "slpd" "slpd"
SLPFW=$(esxcli network firewall ruleset list -r CIMSLP 2>/dev/null | awk 'NR>2{print $2}')
if [ "$SVC_FOUND" = 0 ]; then result "ESX-09" "양호" "SLP 서비스(slpd) 없음"
elif [ "$SVC_RUN" = 1 ] || [ "$SVC_POL" = on ] || [ "$SVC_POL" = automatic ]; then
    result "ESX-09" "취약" "SLP 서비스 사용: $(svc_desc), 방화벽 CIMSLP=${SLPFW:-?} - slpd 중지·chkconfig slpd off·CIMSLP 규칙 비활성 (ESXiArgs 랜섬웨어 악용 경로)"
elif [ "$SVC_RUN" = 0 ]; then result "ESX-09" "양호" "SLP 서비스 $(svc_desc), 방화벽 CIMSLP=${SLPFW:-?}"
else result "ESX-09" "수동확인" "SLP 서비스 상태 확인 불가 ($(svc_desc))"; fi

# ── ESX-10 SNMP 서비스 보안 설정 ──
evd "ESX-10" "esxcli system snmp get 2>/dev/null | sed 's/^\\( *Communities: *[^ ,]\\{0,2\\}\\)[^ ]*/\\1****(마스킹)/'"
SNMP=$(esxcli system snmp get 2>/dev/null)
SN_EN=$(echo "$SNMP" | awk -F': ' '/^ *Enable:/{print $2}')
SN_COM=$(echo "$SNMP" | awk -F': ' '/^ *Communities:/{print $2}' | tr -d ' ')
SN_USR=$(echo "$SNMP" | awk -F': ' '/^ *Users:/{print $2}' | tr -d ' ')
if [ -z "$SNMP" ]; then result "ESX-10" "수동확인" "SNMP 설정 조회 실패"
elif ! istrue "$SN_EN"; then result "ESX-10" "양호" "SNMP 서비스 미사용"
else
    weak=$(echo "$SN_COM" | tr ',' '\n' | awk 'NF{ l=tolower($0); if (l=="public" || l=="private" || length($0) < 8) n++ } END{print n+0}')
    if [ "$weak" -gt 0 ]; then result "ESX-10" "취약" "SNMP v1/v2c 커뮤니티 문자열이 기본값(public/private)이거나 8자 미만 (${weak}개) - 추측 어려운 값 또는 SNMPv3(인증·암호화) 사용"
    elif [ -n "$SN_COM" ]; then result "ESX-10" "양호" "SNMP 사용, 커뮤니티 문자열 기본값 아님 (v2c 평문 전송 - SNMPv3 전환 권고)"
    elif [ -n "$SN_USR" ]; then result "ESX-10" "양호" "SNMPv3 사용자 인증 사용"
    else result "ESX-10" "수동확인" "SNMP 사용, 커뮤니티·v3 사용자 설정 확인 필요"; fi
fi

# ── ESX-11 MOB(Managed Object Browser) 비활성화 ──
evd "ESX-11" "esxcli system settings advanced list -o /Config/HostAgent/plugins/solo/enableMob"
if adv /Config/HostAgent/plugins/solo/enableMob; then
    if istrue "$ADV_VAL"; then result "ESX-11" "취약" "MOB 활성 (Config.HostAgent.plugins.solo.enableMob=${ADV_VAL}) - https://<호스트>/mob 로 내부 객체 조회·조작 가능, false 로 변경"
    else result "ESX-11" "양호" "MOB 비활성 (enableMob=${ADV_VAL})"; fi
else result "ESX-11" "수동확인" "enableMob 옵션 조회 불가 - https://<호스트>/mob 접속 가능 여부 확인"; fi

# ── ESX-12 불필요한 CIM 서비스 비활성화 ──
evd "ESX-12" "echo \"\$HOSTCFG\" | grep -A8 'key = \"sfcbd-watchdog\"'; /etc/init.d/sfcbd-watchdog status 2>&1; esxcli system wbem get 2>/dev/null"
svc_state "sfcbd-watchdog" "sfcbd-watchdog"
WB=$(esxcli system wbem get 2>/dev/null | awk -F': ' '/^ *Enabled:/{print $2}')
if [ "$SVC_FOUND" = 0 ] && [ -z "$WB" ]; then result "ESX-12" "양호" "CIM 서비스 없음"
elif [ "$SVC_RUN" = 1 ] || istrue "$WB"; then result "ESX-12" "수동확인" "CIM(sfcbd) 서비스 사용: $(svc_desc) - 하드웨어 모니터링(서버 벤더 관리 도구) 용도 확인, 불필요 시 esxcli system wbem set -e 0"
else result "ESX-12" "양호" "CIM 서비스 $(svc_desc)"; fi

# ================================================================
# 3. 접근 통제
# ================================================================

# ── ESX-13 방화벽 사용 및 관리 서비스 접근 IP 제한 ──
evd "ESX-13" "esxcli network firewall get; esxcli network firewall ruleset list; esxcli network firewall ruleset allowedip list"
FW=$(esxcli network firewall get 2>/dev/null)
FW_EN=$(echo "$FW" | awk -F': ' '/^ *Enabled:/{print $2}')
FW_DA=$(echo "$FW" | awk -F': ' '/Default Action:/{print $2}')
RS=$(esxcli network firewall ruleset list 2>/dev/null)
AIP=$(esxcli network firewall ruleset allowedip list 2>/dev/null)
open=""; lim=""
for r in sshServer vSphereClient webAccess CIMHttpServer CIMHttpsServer snmp; do
    e=$(echo "$RS" | awk -v r="$r" '$1==r{print $2}')
    istrue "$e" || continue
    a=$(echo "$AIP" | awk -v r="$r" '$1==r{$1=""; sub(/^ +/, ""); print}')
    if [ "$a" = "All" ] || [ -z "$a" ]; then open="${open} ${r}"; else lim="${lim} ${r}(${a})"; fi
done
if [ -z "$FW" ]; then result "ESX-13" "수동확인" "방화벽 설정 조회 실패"
elif ! istrue "$FW_EN"; then result "ESX-13" "취약" "ESXi 방화벽 비활성 (Enabled=${FW_EN})"
elif [ "$FW_DA" = "PASS" ]; then result "ESX-13" "취약" "방화벽 기본 동작 PASS (허용) - DROP 으로 변경"
elif [ -n "$open" ]; then result "ESX-13" "취약" "관리 서비스 접근 IP 미제한(All):${open}$( [ -n "$lim" ] && echo " / 제한됨:${lim}") - 관리자·vCenter IP 만 허용 (상위 방화벽에서 통제하면 증빙 확인 후 예외)"
else result "ESX-13" "양호" "방화벽 사용(기본 ${FW_DA}), 관리 서비스 접근 IP 제한:${lim:- 활성 관리 서비스 없음}"; fi

# ── ESX-14 잠금 모드(Lockdown Mode) 설정 ──
evd "ESX-14" "echo \"\$HOSTCFG\$HSUM\" | grep -E 'lockdownMode|adminDisabled|managementServerIp'; vim-cmd -U dcui vimsvc/auth/lockdown_is_enabled 2>/dev/null; esxcli system settings advanced list -o /DCUI/Access"
LD=$(echo "$HOSTCFG$HSUM" | sed -n 's/.*lockdownMode = "\([^"]*\)".*/\1/p' | head -1)
if [ -z "$LD" ]; then
    _x=$(vim-cmd -U dcui vimsvc/auth/lockdown_is_enabled 2>/dev/null)
    case "$_x" in *true*) LD=lockdownNormal ;; *false*) LD=lockdownDisabled ;; esac
fi
VC=$(echo "$HSUM$HOSTCFG" | sed -n 's/.*managementServerIp = "\([^"]\{1,\}\)".*/\1/p' | head -1)
if [ -z "$VC" ]; then result "ESX-14" "N-A" "vCenter 미연동(단독 호스트) - 잠금 모드는 vCenter 관리 호스트에 적용 (ESX-13 접근 IP 제한으로 통제)"
else case "$LD" in
    lockdownNormal|lockdownStrict) result "ESX-14" "양호" "잠금 모드 ${LD} (vCenter ${VC} 관리)" ;;
    lockdownDisabled) result "ESX-14" "취약" "잠금 모드 미사용 (vCenter ${VC} 관리 호스트) - 일반(Normal) 이상 잠금 모드 설정, 예외 사용자 최소화" ;;
    *) result "ESX-14" "수동확인" "잠금 모드 상태 확인 불가 (vCenter ${VC}) - vCenter [호스트]→[구성]→[보안 프로파일] 확인" ;;
    esac
fi

# ── ESX-15 세션 타임아웃 설정 (Shell·DCUI·Host Client) ──
evd "ESX-15" "for o in ESXiShellInteractiveTimeOut ESXiShellTimeOut DcuiTimeOut HostClientSessionTimeout; do esxcli system settings advanced list -o /UserVars/\$o; done"
tbad=""; tinfo=""
for spec in "ESXiShellInteractiveTimeOut:600" "ESXiShellTimeOut:3600" "DcuiTimeOut:600" "HostClientSessionTimeout:900"; do
    o=${spec%%:*}; lim=${spec#*:}
    adv "/UserVars/$o" || continue
    v="$ADV_VAL"; isnum "$v" || continue
    tinfo="${tinfo} ${o}=${v}"
    if [ "$v" -eq 0 ] || [ "$v" -gt "$lim" ]; then tbad="${tbad} ${o}=${v}(기준 1~${lim}초)"; fi
done
if [ -z "$tinfo" ]; then result "ESX-15" "수동확인" "세션 타임아웃 설정 조회 불가"
elif [ -n "$tbad" ]; then result "ESX-15" "취약" "세션 타임아웃 미흡:${tbad} (0=제한 없음)"
else result "ESX-15" "양호" "세션 타임아웃 설정:${tinfo}"; fi

# ── ESX-16 로그온 경고 메시지 설정 ──
evd "ESX-16" "esxcli system settings advanced list -o /Annotations/WelcomeMessage; esxcli system settings advanced list -o /Config/Etc/issue; cat /etc/issue 2>/dev/null"
adv /Annotations/WelcomeMessage; WM="$ADV_VAL"
adv /Config/Etc/issue; IS="$ADV_VAL"
[ -z "$IS" ] && IS=$(grep -v '^[[:space:]]*$' /etc/issue 2>/dev/null | head -1)
if [ -n "$WM" ] || [ -n "$IS" ]; then result "ESX-16" "양호" "로그온 경고 메시지 설정 ($( [ -n "$WM" ] && echo 'DCUI·Host Client WelcomeMessage')$( [ -n "$WM" ] && [ -n "$IS" ] && echo ' / ')$( [ -n "$IS" ] && echo 'SSH 배너(issue)'))"
else result "ESX-16" "취약" "로그온 경고 메시지 미설정 (Annotations.WelcomeMessage·Config.Etc.issue 비어 있음) - 비인가 사용 금지 경고 문구 설정"; fi

# ── ESX-17 취약한 TLS 프로토콜 비활성화 ──
evd "ESX-17" "esxcli system settings advanced list -o /UserVars/ESXiVPsDisabledProtocols; esxcli system tls server get 2>/dev/null"
if adv /UserVars/ESXiVPsDisabledProtocols; then
    dp=",$(echo "$ADV_VAL" | tr -d ' ' | tr 'A-Z' 'a-z'),"
    en=""
    case "$dp" in *,sslv3,*) ;; *) en="${en} SSLv3" ;; esac
    case "$dp" in *,tlsv1,*) ;; *) en="${en} TLS1.0" ;; esac
    case "$dp" in *,tlsv1.1,*) ;; *) en="${en} TLS1.1" ;; esac
    if [ -n "$en" ]; then result "ESX-17" "취약" "취약 프로토콜 허용:${en} (ESXiVPsDisabledProtocols=${ADV_VAL}) - sslv3,tlsv1,tlsv1.1 비활성 후 재부팅"
    else result "ESX-17" "양호" "SSLv3·TLS1.0·TLS1.1 비활성 (ESXiVPsDisabledProtocols=${ADV_VAL})"; fi
elif [ "$ESX_MAJ" -ge 8 ]; then result "ESX-17" "양호" "ESXi ${ESX_VER} - TLS 1.2 이상만 지원 (TLS 1.0/1.1 제거)"
else result "ESX-17" "수동확인" "TLS 프로토콜 설정 조회 불가 - 관리 포트(443) TLS 1.0/1.1 허용 여부 외부 스캔으로 확인"; fi

# ── ESX-18 관리 네트워크 분리 ──
evd "ESX-18" "esxcli network ip interface list; for v in \$(esxcli network ip interface list 2>/dev/null | awk -F': ' '/^ *Name:/{print \$2}'); do echo \"[\$v]\"; esxcli network ip interface tag get -i \$v; done; esxcli network vswitch standard portgroup list; esxcli network vswitch dvs vmware list 2>/dev/null | grep -E '^[^ ]|Name:'"
IFL=$(esxcli network ip interface list 2>/dev/null | awk -F': ' '
    /^ *Name:/      { n = $2 }
    /^ *Portset:/   { ps = $2 }
    /^ *Portgroup:/ { pg = $2 }
    /^ *VDS Name:/  { vd = $2; print n "|" pg "|" ps "|" vd }')
PGL=$(esxcli network vswitch standard portgroup list 2>/dev/null | awk '
    NR == 2 { s = $0; pos = 1; n = 0
              while (match(s, /-+/)) { n++; st[n] = pos + RSTART - 1; ln[n] = RLENGTH; pos += RSTART + RLENGTH - 1; s = substr(s, RSTART + RLENGTH) }
              next }
    NR > 2 && NF { a = substr($0, st[1], ln[1]); b = substr($0, st[2], ln[2]); c = substr($0, st[4])
              gsub(/^ +| +$/, "", a); gsub(/^ +| +$/, "", b); gsub(/^ +| +$/, "", c); print a "|" b "|" c }')
VMKPG=$(echo "$IFL" | awk -F'|' '{print $2}')
mgmt=""; shared=""
for v in $(echo "$IFL" | awk -F'|' '{print $1}'); do
    esxcli network ip interface tag get -i "$v" 2>/dev/null | grep -q Management || continue
    pg=$(echo "$IFL" | awk -F'|' -v v="$v" '$1==v{print $2}')
    vd=$(echo "$IFL" | awk -F'|' -v v="$v" '$1==v{print $4}')
    if [ -n "$vd" ] && [ "$vd" != "N/A" ]; then mgmt="${mgmt} ${v}(분산스위치 ${vd})"; continue; fi
    vs=$(echo "$PGL" | awk -F'|' -v p="$pg" '$1==p{print $2}')
    vl=$(echo "$PGL" | awk -F'|' -v p="$pg" '$1==p{print $3}')
    mgmt="${mgmt} ${v}(${pg}/${vs}/VLAN ${vl:-?})"
    sh_=$(echo "$PGL" | awk -F'|' -v s="$vs" -v l="$vl" -v p="$pg" '$2==s && $3==l && $1!=p{print $1}' | while read -r q; do
            echo "$VMKPG" | grep -qxF "$q" || echo "$q"; done | tr '\n' ',' | sed 's/,$//')
    [ -n "$sh_" ] && shared="${shared} ${pg}↔${sh_}"
done
if [ -z "$mgmt" ]; then result "ESX-18" "수동확인" "관리(Management) VMkernel 인터페이스 확인 불가 - 관리망 분리 구성 인터뷰 확인"
elif [ -n "$shared" ]; then result "ESX-18" "취약" "관리망과 가상머신 포트그룹이 같은 vSwitch·VLAN:${shared} - 관리 VMkernel 을 전용 VLAN/물리망으로 분리"
else result "ESX-18" "양호" "관리 VMkernel:${mgmt} - 가상머신 포트그룹과 VLAN 분리 (물리망·상위 스위치 구성은 인터뷰 확인)"; fi

# ── ESX-19 가상 스위치 보안 정책 (무차별 모드·MAC 변경·위조 전송 거부) ──
evd "ESX-19" "for s in \$(esxcli network vswitch standard list 2>/dev/null | awk -F': ' '/^ *Name:/{print \$2}'); do echo \"[vSwitch \$s]\"; esxcli network vswitch standard policy security get -v \$s; done; esxcli network vswitch standard portgroup list"
sbad=""
for s in $(esxcli network vswitch standard list 2>/dev/null | awk -F': ' '/^ *Name:/{print $2}'); do
    b=$(esxcli network vswitch standard policy security get -v "$s" 2>/dev/null | awk -F': ' '
        /^ *Allow Promiscuous:/ && $2=="true" { o = o "무차별," }
        /^ *Allow MAC Address Change:/ && $2=="true" { o = o "MAC변경," }
        /^ *Allow Forged Transmits:/ && $2=="true" { o = o "위조전송," }
        END { sub(/,$/, "", o); print o }')
    [ -n "$b" ] && sbad="${sbad} vSwitch ${s}(${b})"
done
pbad=$(echo "$PGL" | while IFS='|' read -r pg vs vl; do
    [ -z "$pg" ] && continue
    printf '[%s] %s $ %s\n' "ESX-19" "$(date '+%H:%M:%S')" "esxcli network vswitch standard portgroup policy security get -p \"$pg\"" >> "$_EVD"
    o=$(esxcli network vswitch standard portgroup policy security get -p "$pg" 2>/dev/null)
    printf '%s\n\n' "$o" >> "$_EVD"
    b=$(echo "$o" | awk -F': ' '
        /^ *Allow Promiscuous:/ && $2=="true" { o = o "무차별," }
        /^ *Allow MAC Address Change:/ && $2=="true" { o = o "MAC변경," }
        /^ *Allow Forged Transmits:/ && $2=="true" { o = o "위조전송," }
        END { sub(/,$/, "", o); print o }')
    [ -n "$b" ] && printf ' 포트그룹 %s(%s)' "$pg" "$b"
done)
DVS=$(esxcli network vswitch dvs vmware list 2>/dev/null | awk -F': ' '/^ *Name:/{print $2}' | tr '\n' ',' | sed 's/,$//')
DNOTE=""; [ -n "$DVS" ] && DNOTE=" / 분산 스위치(${DVS})는 vCenter 에서 확인"
if [ -z "$PGL" ] && [ -z "$DVS" ]; then result "ESX-19" "수동확인" "가상 스위치 정보 조회 실패"
elif [ -n "$sbad$pbad" ]; then result "ESX-19" "취약" "보안 정책 허용(Accept):${sbad}${pbad}${DNOTE} - 거부(Reject)로 변경 (IDS 미러링·중첩 가상화 등 업무상 필요 포트그룹은 예외 근거 확인)"
elif [ -z "$PGL" ]; then result "ESX-19" "수동확인" "표준 스위치 없음${DNOTE}"
else result "ESX-19" "양호" "표준 vSwitch·포트그룹 무차별 모드·MAC 변경·위조 전송 모두 거부${DNOTE}"; fi

# ── ESX-20 iSCSI CHAP 인증 ──
evd "ESX-20" "esxcli iscsi software get 2>/dev/null; esxcli iscsi adapter list 2>/dev/null; for a in \$(esxcli iscsi adapter list 2>/dev/null | awk 'NR>2{print \$1}'); do echo \"[\$a]\"; esxcli iscsi adapter auth chap get -A \$a -d uni 2>/dev/null | grep -v -i secret; done"
IAD=$(esxcli iscsi adapter list 2>/dev/null | awk 'NR>2 && $1 ~ /^vmhba/{print $1}')
if [ -z "$IAD" ]; then result "ESX-20" "N-A" "iSCSI 어댑터 미사용"
else
    cbad=""; cinfo=""
    for a in $IAD; do
        lv=$(esxcli iscsi adapter auth chap get -A "$a" -d uni 2>/dev/null | awk -F': ' '/^ *Level:/{print $2; exit}')
        cinfo="${cinfo} ${a}=${lv:-?}"
        case "$lv" in required|preferred) ;; *) cbad="${cbad} ${a}(${lv:-미확인})" ;; esac
    done
    if [ -n "$cbad" ]; then result "ESX-20" "취약" "iSCSI CHAP 인증 미사용:${cbad} - CHAP(가능하면 상호 CHAP) required 로 설정"
    else result "ESX-20" "양호" "iSCSI CHAP 인증 사용:${cinfo}"; fi
fi

# ================================================================
# 4. 로그 관리
# ================================================================
SYSL=$(esxcli system syslog config get 2>/dev/null)

# ── ESX-21 원격 로그 서버(Syslog) 설정 ──
evd "ESX-21" "esxcli system syslog config get; esxcli network firewall ruleset list -r syslog 2>/dev/null"
RH=$(echo "$SYSL" | awk -F': ' '/^ *Remote Host:/{print $2}')
SLFW=$(esxcli network firewall ruleset list -r syslog 2>/dev/null | awk 'NR>2{print $2}')
if [ -z "$SYSL" ]; then result "ESX-21" "수동확인" "Syslog 설정 조회 실패"
elif [ -z "$RH" ] || [ "$RH" = "<none>" ]; then result "ESX-21" "취약" "원격 로그 서버 미설정 (Syslog.global.logHost) - 중앙 로그 서버로 전송 설정"
elif [ -n "$SLFW" ] && ! istrue "$SLFW"; then result "ESX-21" "취약" "원격 로그 서버(${RH}) 설정했으나 방화벽 syslog 규칙 비활성 → 전송 차단"
else result "ESX-21" "양호" "원격 로그 서버: ${RH}"; fi

# ── ESX-22 로그 영구 저장소 설정 ──
evd "ESX-22" "esxcli system syslog config get | grep -i 'Local Log'; esxcli system settings advanced list -o /Syslog/global/logDir"
LP=$(echo "$SYSL" | awk -F': ' '/Local Log Output Is Persistent:/{print $2}')
LO=$(echo "$SYSL" | awk -F': ' '/^ *Local Log Output:/{print $2}')
if istrue "$LP"; then result "ESX-22" "양호" "로그 영구 저장소 사용 (${LO:-경로 미확인})"
elif [ -n "$LP" ]; then result "ESX-22" "취약" "로그가 휘발성 저장소(${LO:-ramdisk})에 저장 - 재부팅 시 소실, Syslog.global.logDir 를 데이터스토어로 지정"
else case "$LO" in
    /vmfs/*|/scratch/*) result "ESX-22" "양호" "로그 저장 위치 ${LO}" ;;
    "") result "ESX-22" "수동확인" "로그 저장 위치 확인 불가" ;;
    *) result "ESX-22" "수동확인" "로그 저장 위치 ${LO} - 영구 저장소 여부 확인" ;;
    esac
fi

# ── ESX-23 NTP 시간 동기화 ──
evd "ESX-23" "esxcli system ntp get 2>/dev/null; esxcli system ptp get 2>/dev/null; grep -E '^(server|pool)' /etc/ntp.conf 2>/dev/null; /etc/init.d/ntpd status 2>&1"
NTP=$(esxcli system ntp get 2>/dev/null)
N_EN=$(echo "$NTP" | awk -F': ' '/^ *Enabled:/{print $2}')
N_SV=$(echo "$NTP" | awk -F': ' '/^ *Server:/{print $2}')
[ -z "$N_SV" ] && N_SV=$(grep -E '^(server|pool)' /etc/ntp.conf 2>/dev/null | awk '{print $2}' | tr '\n' ',' | sed 's/,$//')
svc_state "ntpd" "ntpd"
PTP=$(esxcli system ptp get 2>/dev/null | awk -F': ' '/^ *Enabled:/{print $2}')
if [ -n "$N_SV" ] && { istrue "$N_EN" || [ "$SVC_RUN" = 1 ]; }; then result "ESX-23" "양호" "NTP 시간 동기화 사용: ${N_SV}"
elif istrue "$PTP"; then result "ESX-23" "양호" "PTP 시간 동기화 사용"
elif [ -n "$N_SV" ]; then result "ESX-23" "취약" "NTP 서버(${N_SV}) 지정했으나 서비스 미실행 ($(svc_desc))"
else result "ESX-23" "취약" "시간 동기화(NTP/PTP) 미설정 - 로그 시각 신뢰성 확보 위해 내부 NTP 서버 지정"; fi

# ================================================================
# 5. 패치 관리
# ================================================================

# ── ESX-24 지원 종료(EoS) 버전 사용 금지 — Broadcom 일반 지원 종료일(EoGS) 기준 ──
evd "ESX-24" "vmware -vl; esxcli system version get"
EOS_RES=""
case "${ESX_MAJ}.${ESX_MIN}" in
0.0) EOS_RES="수동확인|ESXi 버전 확인 불가" ;;
[1-5].*|6.0) EOS_RES="취약|ESXi ${ESX_VER} - 지원 종료 (6.0: 2020-03-12, 5.5: 2018-09-19 종료)" ;;
6.5|6.7) EOS_RES="취약|ESXi ${ESX_VER} - 일반 지원 종료 2022-10-15 (보안 패치 미제공)" ;;
7.*) if [ "$TODAY" -ge 20251002 ]; then EOS_RES="취약|ESXi ${ESX_VER} - 일반 지원 종료 2025-10-02 (보안 패치 미제공, 8.0 이상 업그레이드)"
     else EOS_RES="수동확인|ESXi ${ESX_VER} - 일반 지원 종료 예정 2025-10-02 (업그레이드 계획 확인)"; fi ;;
8.*) if [ "$TODAY" -ge 20271011 ]; then EOS_RES="취약|ESXi ${ESX_VER} - 일반 지원 종료 2027-10-11"
     elif [ "$TODAY" -ge 20270713 ]; then EOS_RES="수동확인|ESXi ${ESX_VER} - 일반 지원 종료 임박 2027-10-11 (업그레이드 계획 확인)"
     else EOS_RES="양호|ESXi ${ESX_VER} - 지원 기간 내 (일반 지원 종료 2027-10-11)"; fi ;;
*) EOS_RES="양호|ESXi ${ESX_VER} - 지원 중인 버전 (Broadcom 제품 수명주기 확인)" ;;
esac
result "ESX-24" "${EOS_RES%%|*}" "${EOS_RES#*|}"

# ── ESX-25 최신 보안 패치 적용 ──
evd "ESX-25" "esxcli software profile get 2>/dev/null | head -8; esxcli software vib get -n esx-base 2>/dev/null | grep -E 'Version|Install Date'; esxcli software vib list 2>/dev/null | sort -k5 | tail -5"
PROF=$(esxcli software profile get 2>/dev/null | awk -F': ' '/^ *Name:/{print $2; exit}')
[ -z "$PROF" ] && PROF=$(esxcli software profile get 2>/dev/null | awk 'NF{print; exit}' | sed 's/^ *//')
IDATE=$(esxcli software vib get -n esx-base 2>/dev/null | awk -F': ' '/Install Date:/{print $2; exit}')
ID_N=$(echo "$IDATE" | cut -c1-10 | tr -d '-')
if [ "${EOS_RES%%|*}" = "취약" ]; then result "ESX-25" "취약" "지원 종료 버전(ESXi ${ESX_VER} build-${ESX_BUILD}) - 신규 보안 패치 미제공"
elif isnum "$ID_N" && [ "$TODAY" -gt 0 ] && [ "$ID_N" -lt $((TODAY - 10000)) ]; then
    result "ESX-25" "취약" "최근 1년간 패치 이력 없음 (esx-base 설치일 ${IDATE}, build-${ESX_BUILD}, 프로파일 ${PROF:-?}) - VMware 보안 권고(VMSA) 최신 패치 적용"
else result "ESX-25" "수동확인" "ESXi ${ESX_VER} build-${ESX_BUILD} (프로파일 ${PROF:-?}, esx-base 설치일 ${IDATE:-?}) - Broadcom VMSA·빌드 목록(KB 316595)의 최신 빌드와 비교"; fi

# ================================================================
# 6. 호스트·가상머신 보안
# ================================================================

# ── ESX-26 VIB 허용 수준 (Acceptance Level) ──
evd "ESX-26" "esxcli software acceptance get; esxcli software vib list 2>/dev/null | grep -i CommunitySupported"
AL=$(esxcli software acceptance get 2>/dev/null | head -1 | tr -d ' ')
CV=$(esxcli software vib list 2>/dev/null | grep -i CommunitySupported | awk '{print $1}' | tr '\n' ',' | sed 's/,$//')
case "$AL" in
CommunitySupported) result "ESX-26" "취약" "VIB 허용 수준 CommunitySupported - 서명 검증 없는 패키지 설치 가능$( [ -n "$CV" ] && echo " (설치된 커뮤니티 VIB: ${CV})") - PartnerSupported 이상으로 변경" ;;
VMwareCertified|VMwareAccepted|PartnerSupported) result "ESX-26" "양호" "VIB 허용 수준 ${AL}$( [ -n "$CV" ] && echo " / 참고: 커뮤니티 VIB ${CV}")" ;;
*) result "ESX-26" "수동확인" "VIB 허용 수준 확인 불가 (${AL:-값 없음})" ;;
esac

# ── ESX-27 비인가 실행 파일 차단 (execInstalledOnly) ──
evd "ESX-27" "esxcli system settings kernel list -o execInstalledOnly; esxcli system settings encryption get 2>/dev/null"
EIO=$(esxcli system settings kernel list -o execInstalledOnly 2>/dev/null | awk '$1=="execInstalledOnly"{print $4}')
if [ -z "$EIO" ]; then result "ESX-27" "N-A" "execInstalledOnly 옵션 미지원 버전 (ESXi ${ESX_VER})"
elif istrue "$EIO"; then result "ESX-27" "양호" "설치된 VIB 외 실행 파일 차단 (execInstalledOnly=TRUE)"
else result "ESX-27" "취약" "임의 실행 파일 실행 허용 (execInstalledOnly=FALSE) - 랜섬웨어 바이너리 실행 차단을 위해 TRUE 설정 (esxcli system settings kernel set -s execInstalledOnly -v TRUE, 재부팅)"; fi

# ── ESX-28 가상머신 콘솔 복사·붙여넣기·끌어놓기 제한 ──
VML=$(vim-cmd vmsvc/getallvms 2>/dev/null | sed -n 's/^\([0-9][0-9]*\) .*\[\([^]]*\)\] \(.*\.vmx\).*/\1|\2|\3/p')
evd "ESX-28" "vim-cmd vmsvc/getallvms 2>/dev/null | head -100"
if [ -z "$VML" ]; then result "ESX-28" "N-A" "등록된 가상머신 없음"
else
    R28=$(echo "$VML" | while IFS='|' read -r vid ds vp; do
        f="${VMFS_ROOT:-/vmfs/volumes}/${ds}/${vp}"
        [ -r "$f" ] || continue
        echo "OK"
        h=$(grep -iE '^ *isolation\.tools\.(copy|paste|dnd)\.disable *= *"?false|^ *isolation\.tools\.setGUIOptions\.enable *= *"?true' "$f" 2>/dev/null)
        if [ -n "$h" ]; then
            echo "BAD $(basename "$vp" .vmx)"
            printf '[%s] 파일: %s\n%s\n\n' "ESX-28" "$f" "$h" >> "$_EVD"
        fi
    done)
    nvm=$(echo "$R28" | grep -c '^OK')
    vbad=$(echo "$R28" | sed -n 's/^BAD / /p' | tr -d '\n')
    if [ "$nvm" -eq 0 ]; then result "ESX-28" "수동확인" "가상머신 설정 파일(.vmx) 읽기 실패"
    elif [ -n "$vbad" ]; then result "ESX-28" "취약" "콘솔 복사·붙여넣기 허용 가상머신:${vbad} - isolation.tools.copy/paste/dnd.disable=TRUE"
    else result "ESX-28" "양호" "가상머신 ${nvm}대 모두 콘솔 복사·붙여넣기 기본 차단 유지"; fi
fi

# ── ESX-29 가상머신 간 메모리 페이지 공유 제한 (Mem.ShareForceSalting) ──
evd "ESX-29" "esxcli system settings advanced list -o /Mem/ShareForceSalting"
if adv /Mem/ShareForceSalting && isnum "$ADV_VAL"; then
    if [ "$ADV_VAL" -eq 2 ]; then result "ESX-29" "양호" "가상머신 간 투명 페이지 공유 제한 (Mem.ShareForceSalting=2)"
    else result "ESX-29" "취약" "Mem.ShareForceSalting=${ADV_VAL} - 가상머신 간 메모리 페이지 공유 허용 (부채널 정보 유출), 2 로 설정"; fi
else result "ESX-29" "수동확인" "Mem.ShareForceSalting 조회 불가"; fi

# ── ESX-30 dvFilter 네트워크 API 제한 ──
evd "ESX-30" "esxcli system settings advanced list -o /Net/DVFilterBindIpAddress"
if adv /Net/DVFilterBindIpAddress; then
    if [ -z "$ADV_VAL" ]; then result "ESX-30" "양호" "dvFilter 네트워크 API 미사용 (Net.DVFilterBindIpAddress 비어 있음)"
    else result "ESX-30" "수동확인" "dvFilter 바인드 주소 ${ADV_VAL} - 보안 어플라이언스(가상 방화벽 등) 사용 여부 확인, 미사용이면 취약"; fi
else result "ESX-30" "수동확인" "Net.DVFilterBindIpAddress 조회 불가"; fi

echo "# ============================================================"
echo "# 점검 요약 - 가상화(VMware ESXi) ESX-01~ESX-30"
echo "#   양호: ${_CP} / 취약: ${_CF} / 수동확인: ${_CM} / N-A: ${_CN}"
echo "# 결과 파일: ${_RESF}"
echo "# 증적 파일: ${_EVD}"
echo "# ※ 결과·증적 2개 파일을 회수한 뒤 호스트에서 스크립트·결과를 삭제하고 SSH 를 다시 중지하십시오."
echo "# ============================================================"
}

if [ -z "$NO_RESULT_COPY" ] && ! [ /dev/fd/1 -ef "$_RESF" ] 2>/dev/null && ( : > "$_RESF" ) 2>/dev/null; then
    main | tee "$_RESF"
else
    main
fi
exit 0
