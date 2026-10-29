#!/bin/sh
# ================================================================
# 가상화 장비(VMware ESXi) 보안 취약점 자동 점검 스크립트 v1.0
# ================================================================
#
# [용도]
#   주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드(2026)
#   [11. 가상화 장비 HV-01~HV-25] 기준 VMware ESXi 호스트 점검.
#
# [대상]
#   VMware ESXi 6.5 / 6.7 / 7.0 / 8.0
#   ESXi Shell(busybox sh)에서 그대로 실행 — bash·추가 설치 불필요
#   (vCenter·XenServer·KVM·Nutanix 는 대상 아님)
#
# [사전 조건]
#   - root(또는 Administrator 역할) 계정으로 ESXi 에 SSH 접속
#   - SSH(TSM-SSH)는 점검 동안만 켜고 점검 후 다시 중지 (HV-12)
#
# [실행 방법]
#   ① 점검자 PC 에서 SSH 로 바로 실행 — ESXi 에 파일이 남지 않고, 결과와 증적이 한 파일에 저장됨
#      ssh root@<ESXi IP> 'HV_INLINE=1 sh -s' < check_hv_esxi.sh > <ESXi호스트명>_hv.txt
#   ② ESXi 에 복사해 실행
#      sh /tmp/check_hv_esxi.sh > /tmp/<ESXi호스트명>_hv.txt
#      → 결과와 증적(/tmp/<호스트명>_hv_evidence.txt) 회수 후 ESXi 에서 삭제
#   여러 대: run_hv_esxi.sh (Linux/macOS) / run_hv_esxi.bat (Windows) 에 호스트 목록 지정
#
# [선택 환경변수]
#   HV_INLINE=1     증적을 결과 뒤에 이어서 출력하고 ESXi 의 증적 파일은 삭제 (방법 ①)
#   HV_SSH_TEMP=1   SSH 를 점검 때문에 잠시 켠 경우 (시작 정책 off) — HV-12 를 양호로 판정하고 점검 후 중지 안내
#
# [산출물]
#   1) 표준출력 — 파이프 구분자 결과
#      형식: HV-항목코드|결과|근거설명   결과: 양호 / 취약 / 수동확인 / N-A
#   2) 증적 — /tmp/<호스트명>_hv_evidence.txt (HV_INLINE=1 이면 결과 뒤 '# ==== EVIDENCE BEGIN ====' 아래)
#      점검 중 실행한 명령어·출력·판정 근거가 타임스탬프와 함께 기록됨
#
# ================================================================

_has() { command -v "$1" >/dev/null 2>&1; }
ts() { date '+%H:%M:%S'; }

# ── 증적·판정 ──────────────────────────────────────────────────
# 명령 실행 → 증적 기록 + 출력 반환 (VAR=$(run_e HV-xx "명령"))
run_e() {
    _rc=$1; shift
    _ro=$(eval "$@" 2>&1)
    printf '[%s] %s $ %s\n%s\n\n' "$_rc" "$(ts)" "$*" "$_ro" >> "$_EVD"
    printf '%s\n' "$_ro"
}
# 값·요약 증적 (설명 + 값)
evd_v() { printf '[%s] %s %s\n%s\n\n' "$1" "$(ts)" "$2" "$3" >> "$_EVD"; }

iname() {
    case "$1" in
    HV-01) echo '계정 로그오프/세션 관리' ;;
    HV-02) echo '가상화 장비 외부접속 차단' ;;
    HV-03) echo '가상화 장비 루트계정 관리' ;;
    HV-04) echo '가상화 장비 계정 권한 관리' ;;
    HV-05) echo '가상화 장비 사용자 인증 강화' ;;
    HV-06) echo '비밀번호 관리정책 설정' ;;
    HV-07) echo '계정 잠금 임계값 설정' ;;
    HV-08) echo '시스템 사용 주의사항 출력 설정' ;;
    HV-09) echo 'NTP 및 시각 동기화 설정' ;;
    HV-10) echo 'SNMP Community String 복잡성 적용' ;;
    HV-11) echo 'MOB(Managed Object Browser) 서비스 비활성화' ;;
    HV-12) echo 'ESXi Shell 비활성화' ;;
    HV-13) echo 'ESXi Shell 세션 종료 시간 설정' ;;
    HV-14) echo '원격 로그 서버 이용' ;;
    HV-15) echo '시스템 주요 이벤트 로그 설정' ;;
    HV-16) echo '비휘발성 경로 내 로그 파일 저장' ;;
    HV-17) echo '코어덤프 수집 기능 활성화' ;;
    HV-18) echo '가상 머신의 장치 변경 제한 설정' ;;
    HV-19) echo '가상 머신의 불필요한 장치 제거' ;;
    HV-20) echo '가상 머신 콘솔 클립보드 복사&붙여넣기 기능 비활성화' ;;
    HV-21) echo '가상 머신 콘솔 드래그 앤 드롭 기능 비활성화' ;;
    HV-22) echo '가상 스위치 MAC 주소 변경 정책 비활성화' ;;
    HV-23) echo '가상 스위치 무차별(Promiscuous) 모드 정책 비활성화' ;;
    HV-24) echo '가상 스위치 위조전송(Forged Transmits) 모드 정책 비활성화' ;;
    HV-25) echo '주기적 보안 패치 및 벤더 권고사항 적용' ;;
    esac
}

CP=0; CF=0; CM=0; CN=0
put() {   # put HV-xx 결과 사유 — 결과 1줄 출력 + 증적 [판정]
    _pw=$(printf '%s' "$3" | tr '\n|' ' /')
    printf '%s|%s|%s\n' "$1" "$2" "$_pw"
    printf '[판정] %s (%s)|%s|%s\n\n' "$1" "$(iname "$1")" "$2" "$_pw" >> "$_EVD"
    case "$2" in 양호) CP=$((CP+1)) ;; 취약) CF=$((CF+1)) ;; 수동확인) CM=$((CM+1)) ;; *) CN=$((CN+1)) ;; esac
}
ok() { put "$1" "양호" "$2"; }
ng() { put "$1" "취약" "$2"; }
mc() { put "$1" "수동확인" "$2"; }

# ── ESXi 출력 해석 ─────────────────────────────────────────────
# 고급 설정 값 (호스트 > 관리 > 시스템 > 고급 설정): vim-cmd(hostd) 우선, 없으면 esxcli. 미존재 시 빈 값 + 반환값 1
adv() {
    _ak=$1; _ac=$2
    _ao=$(vim-cmd hostsvc/advopt/view "$_ak" 2>&1)
    [ -n "$_ac" ] && printf '[%s] %s $ vim-cmd hostsvc/advopt/view %s\n%s\n\n' "$_ac" "$(ts)" "$_ak" "$_ao" >> "$_EVD"
    if printf '%s\n' "$_ao" | grep -q '^ *value = '; then
        printf '%s\n' "$_ao" | sed -n 's/^ *value = //p' | head -1 | sed 's/[, ]*$//; s/^"//; s/"$//; s/^<unset>$//'
        return 0
    fi
    _ap="/$(printf '%s' "$_ak" | tr '.' '/')"
    _ao=$(esxcli system settings advanced list -o "$_ap" 2>&1)
    [ -n "$_ac" ] && printf '[%s] %s $ esxcli system settings advanced list -o %s\n%s\n\n' "$_ac" "$(ts)" "$_ap" "$_ao" >> "$_EVD"
    printf '%s\n' "$_ao" | grep -q '^ *Type: ' || return 1
    case "$(printf '%s\n' "$_ao" | sed -n 's/^ *Type: //p' | head -1)" in
    int*) printf '%s\n' "$_ao" | sed -n 's/^ *Int Value: //p' | head -1 ;;
    *)    printf '%s\n' "$_ao" | sed -n 's/^ *String Value: //p' | head -1 ;;
    esac
}
# 'Key: value' 형식 출력에서 값 (kv "Enabled" "$출력")
kv() { printf '%s\n' "$2" | sed -n "s/^ *$1: *//p" | head -1; }
# esxcli 표 출력 → '|' 구분 행 (머리글 아래 '----' 줄로 열 경계 계산 — 값에 공백이 있어도 안전)
#   esx_tbl          : 전체 열
#   esx_tbl "머리글" : 해당 열만
esx_tbl() {
    awk -v H="$1" '
    NR == 1 { hdr = $0; next }
    NR == 2 && /^-/ {
        L = length($0); i = 1; n = 0
        while (i <= L) {
            while (i <= L && substr($0, i, 1) == " ") i++
            if (i > L) break
            n++; st[n] = i
            while (i <= L && substr($0, i, 1) == "-") i++
        }
        if (H != "") for (c = 1; c <= n; c++) {
            f = (c < n) ? substr(hdr, st[c], st[c+1] - st[c]) : substr(hdr, st[c]); gsub(/^ +| +$/, "", f)
            if (f == H) col = c
        }
        next
    }
    n > 0 {
        out = ""
        for (c = 1; c <= n; c++) {
            if (H != "" && c != col) continue
            f = (c < n) ? substr($0, st[c], st[c+1] - st[c]) : substr($0, st[c]); gsub(/^ +| +$/, "", f)
            out = (out == "" && (H != "" || c == 1)) ? f : out "|" f
        }
        if (H == "" || col) print out
    }'
}
# 목록 요약: 최대 N개 + '외 M개'
_head_list() {
    _hn=${2:-8}
    printf '%s\n' "$1" | sed '/^$/d' | awk -v N="$_hn" '{ if (NR <= N) s = (s == "" ? $0 : s ", " $0) } END { if (NR > N) s = s " 외 " NR - N "개"; print s }'
}
_count() { printf '%s\n' "$1" | sed '/^$/d' | wc -l | tr -d ' '; }
_is_int() { case "$1" in ''|*[!0-9]*) return 1 ;; *) return 0 ;; esac; }
_lc() { printf '%s' "$1" | tr 'A-Z' 'a-z'; }
# 문자열 복잡도: 2종 10자 이상 또는 3종 8자 이상 (영대문자·영소문자·숫자·특수문자)
_cplx_ok() {
    _s=$1; _n=${#_s}; _c=0
    printf '%s' "$_s" | grep -q '[A-Z]' && _c=$((_c+1))
    printf '%s' "$_s" | grep -q '[a-z]' && _c=$((_c+1))
    printf '%s' "$_s" | grep -q '[0-9]' && _c=$((_c+1))
    printf '%s' "$_s" | grep -q '[^A-Za-z0-9]' && _c=$((_c+1))
    { [ "$_c" -ge 3 ] && [ "$_n" -ge 8 ]; } || { [ "$_c" -ge 2 ] && [ "$_n" -ge 10 ]; }
}
_mask() { printf '%s' "$1" | awk '{ print (length($0) > 2 ? substr($0, 1, 2) : "") "***(" length($0) "자)" }'; }

# ================================================================
main() {
if ! _has esxcli || ! _has vim-cmd; then
    echo "# [오류] VMware ESXi 가 아닙니다 (esxcli·vim-cmd 없음) - ESXi 호스트의 ESXi Shell(SSH)에서 실행하세요."
    exit 1
fi

_VG=$(esxcli system version get 2>/dev/null)
PROD=$(kv Product "$_VG"); VER=$(kv Version "$_VG"); BUILD=$(kv Build "$_VG" | sed 's/^Releasebuild-//'); UPD=$(kv Update "$_VG")
FQDN=$(esxcli system hostname get 2>/dev/null | sed -n 's/^ *Fully Qualified Domain Name: *//p' | head -1)
HN=${FQDN:-$(hostname 2>/dev/null || uname -n)}
_IPS=$(esxcli network ip interface ipv4 get 2>/dev/null | esx_tbl)
IP=$(printf '%s\n' "$_IPS" | awk -F'|' '$1 == "vmk0" && $2 != "" { print $2; exit }')
[ -z "$IP" ] && IP=$(printf '%s\n' "$_IPS" | awk -F'|' '$2 ~ /^[0-9]/ { print $2; exit }')
VCIP=$(sed -n 's:.*<serverIp>\(.*\)</serverIp>.*:\1:p' /etc/vmware/vpxa/vpxa.cfg 2>/dev/null | head -1)

_EVD="/tmp/${HN}_hv_evidence.txt"
if ! ( : > "$_EVD" ) 2>/dev/null; then _EVD="./${HN}_hv_evidence_$$.txt"; : > "$_EVD"; fi
HC="/tmp/.hv_hostconfig.$$"; VMR="/tmp/.hv_vm.$$"
trap 'rm -f "$HC" "$VMR"' EXIT INT TERM

echo "# ================================================================"
echo "# 가상화 장비(VMware ESXi) 보안 취약점 점검 결과"
echo "# ================================================================"
echo "# 점검 대상: ${HN}"
echo "# IP: ${IP:-확인 불가}"
echo "# OS: ${PROD:-VMware ESXi} ${VER}${BUILD:+ build-$BUILD}${UPD:+ (Update $UPD)}"
echo "# 버전: ${VER}"
echo "# vCenter: ${VCIP:-미연결 (단독 ESXi)}"
echo "# 점검 기준: 주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드(2026) [가상화 장비 HV-01~HV-25]"
echo "# 점검 일시: $(date '+%Y-%m-%d %H:%M:%S')"
echo "# ================================================================"
[ "$(id -u 2>/dev/null)" != "0" ] && echo "# [경고] root 가 아닌 계정으로 실행 - 일부 설정 조회가 실패하면 수동확인으로 처리됩니다"

{
    echo "# ================================================================"
    echo "# 가상화 장비(VMware ESXi) 증적 파일 (감사 추적용)"
    echo "# 대상: ${HN} / ${PROD:-VMware ESXi} ${VER}${BUILD:+ build-$BUILD}"
    echo "# 생성: $(date '+%Y-%m-%d %H:%M:%S')"
    echo "# ================================================================"
} > "$_EVD"
run_e INFO "vmware -vl; esxcli system version get; esxcli system hostname get; esxcli network ip interface ipv4 get" >/dev/null
vim-cmd hostsvc/hostconfig > "$HC" 2>/dev/null

# ── 1. 계정 관리 ───────────────────────────────────────────────
# HV-01 웹 콘솔 세션 타임아웃 (UserVars.HostClientSessionTimeout ≤ 600초)
v=$(adv UserVars.HostClientSessionTimeout HV-01)
if ! _is_int "$v"; then mc HV-01 "UserVars.HostClientSessionTimeout 조회 불가 - Host Client 고급 설정에서 600초 이하 여부 확인"
elif [ "$v" -eq 0 ]; then ng HV-01 "UserVars.HostClientSessionTimeout=0 (세션 만료 없음) - 600초 이하로 설정 필요"
elif [ "$v" -le 600 ]; then ok HV-01 "UserVars.HostClientSessionTimeout=${v}초 (600초 이하)"
else ng HV-01 "UserVars.HostClientSessionTimeout=${v}초 - 600초(10분) 초과"; fi

# HV-02 관리 서비스 접속 IP 제한 (ESXi 방화벽 sshServer·vSphereClient·webAccess 허용 IP)
fw=$(run_e HV-02 "esxcli network firewall get")
rs=$(run_e HV-02 "esxcli network firewall ruleset list" | esx_tbl)
aip=$(run_e HV-02 "esxcli network firewall ruleset allowedip list" | esx_tbl)
open=""; lim=""
for r in sshServer vSphereClient webAccess; do
    en=$(printf '%s\n' "$rs" | awk -F'|' -v R="$r" '$1 == R { print $2 }')
    [ "$en" = "true" ] || continue
    a=$(printf '%s\n' "$aip" | awk -F'|' -v R="$r" '$1 == R { print $2 }')
    case "$a" in ''|All|all) open="${open}${open:+, }${r}" ;; *) lim="${lim}${lim:+, }${r}=${a}" ;; esac
done
if [ "$(kv Enabled "$fw")" != "true" ]; then ng HV-02 "ESXi 방화벽 비활성(Enabled=$(kv Enabled "$fw")) - 모든 IP 에서 관리 서비스 접속 가능"
elif [ -n "$open" ]; then ng HV-02 "모든 IP 에서 접속 허용: ${open}${lim:+ (제한: $lim)} - 네트워킹 > 방화벽 규칙에서 허용 IP 지정 필요"
elif [ -n "$lim" ]; then ok HV-02 "관리 서비스 접속 IP 제한: ${lim} (방화벽 기본 동작 $(kv 'Default Action' "$fw"))"
else mc HV-02 "관리 서비스 방화벽 규칙(sshServer·vSphereClient·webAccess) 조회 불가 - 허용 IP 수동 확인"; fi

# 계정·권한 (HV-03~05)
perm=$(run_e HV-03 "esxcli system permission list" | esx_tbl)        # Principal|Is Group|Role|Role Description
acct=$(run_e HV-04 "esxcli system account list" | esx_tbl)           # User ID|Description
lockd=$(run_e HV-03 "vim-cmd -U dcui vimsvc/auth/lockdown_is_enabled" | tail -1)
evd_v HV-03 "vCenter 관리 여부 (/etc/vmware/vpxa/vpxa.cfg serverIp)" "${VCIP:-없음}"
sysre='^(root|dcui|vpxuser)$'
adm_o=$(printf '%s\n' "$perm" | awk -F'|' -v S="$sysre" '$3 == "Admin" && $1 !~ S && $1 != "" { print $1 }')
root_adm=$(printf '%s\n' "$perm" | awk -F'|' '$1 == "root" && $3 == "Admin" { print "y" }')

# HV-03 별도 관리자 계정 사용 (root 관리자 권한 제거 또는 비활성)
if [ -z "$perm" ]; then mc HV-03 "권한 목록 조회 불가 - 호스트 > 작업 > 사용 권한에서 별도 관리자 계정 여부 확인"
elif [ "$lockd" = "true" ]; then ok HV-03 "잠금 모드(Lockdown) 사용 - root 직접 접속 차단$( [ -n "$adm_o" ] && echo ", 별도 관리자: $(_head_list "$adm_o")" )"
elif [ -n "$adm_o" ] && [ -z "$root_adm" ]; then ok HV-03 "별도 관리자 계정 사용: $(_head_list "$adm_o") / root 관리자 권한 제거됨"
elif [ -n "$adm_o" ]; then mc HV-03 "별도 관리자 계정 $(_head_list "$adm_o") 존재하나 root 관리자(Admin) 권한 유지 - root 실사용 여부 확인 (가이드 조치: root 권한 제거 또는 비활성화)"
elif [ -n "$VCIP" ]; then mc HV-03 "로컬 관리자 계정은 root 뿐 / vCenter(${VCIP}) 관리 호스트 - vCenter 개별 관리자 계정으로 관리하는지 확인 (ESXi 직접 관리 시 별도 계정 생성·잠금 모드 권고)"
else ng HV-03 "root 외 관리자(Admin) 권한 계정 없음 - root 계정으로 가상화 장비 관리"; fi

# HV-04 불필요한 공용·퇴사자 계정
users=$(printf '%s\n' "$acct" | awk -F'|' -v S="$sysre" '$1 !~ S && $1 != "" { print $1 }')
shared=$(printf '%s\n' "$users" | grep -iE '^(guest|temp|tmp|demo|sample|share|shared|common|public|user[0-9]*)$|test')
if [ -z "$acct" ]; then mc HV-04 "로컬 계정 목록 조회 불가 - 호스트 > 관리 > 보안 및 사용자에서 확인"
elif [ -n "$shared" ]; then ng HV-04 "공용·테스트성 계정 존재: $(_head_list "$shared") - 불필요 시 삭제 (1인 1계정)"
elif [ -n "$users" ]; then mc HV-04 "로컬 계정 $(_count "$users")개: $(_head_list "$users" 10) - 퇴사자·공용·미사용 계정 여부 확인 (없으면 양호)"
else ok HV-04 "기본 계정(root·dcui·vpxuser) 외 로컬 계정 없음"; fi

# HV-05 계정별 권한 (관리자 권한 최소화)
others=$(printf '%s\n' "$perm" | awk -F'|' -v S="$sysre" '$1 !~ S && $1 != "" { print $1 "(" $3 ")" }')
evd_v HV-05 "계정별 역할 (esxcli system permission list → Principal|Is Group|Role|Role Description)" "${perm:-조회 불가}"
n_adm=$(_count "$adm_o")
if [ -z "$perm" ]; then mc HV-05 "권한 목록 조회 불가 - 호스트 > 작업 > 사용 권한에서 계정별 역할 확인"
elif [ "$n_adm" -ge 2 ]; then mc HV-05 "관리자(Admin) 역할 계정 ${n_adm}개: $(_head_list "$adm_o") - 업무상 필요성 확인 (불필요 시 취약), 전체: $(_head_list "$others" 10)"
elif [ -n "$others" ]; then ok HV-05 "계정별 역할 부여: $(_head_list "$others" 10) (관리자 권한 ${n_adm}개)"
else ok HV-05 "기본 계정 외 권한 부여 계정 없음 (root·dcui·vpxuser)"; fi

# HV-06 비밀번호 정책 (2종 10자 / 3종 8자 이상, 최대 사용 기간 90일 이하)
pqc=$(adv Security.PasswordQualityControl HV-06)
pmd=$(adv Security.PasswordMaxDays HV-06)
mins=$(printf '%s\n' "$pqc" | sed -n 's/.*min=\([^ ]*\).*/\1/p')
bad6=""
if [ -n "$mins" ]; then
    IFS_O=$IFS; IFS=,; set -- $mins; IFS=$IFS_O
    _n0=$1; _n1=$2; _n3=$4; _n4=$5
    _is_int "$_n0" && bad6="${bad6}1종 문자 비밀번호 허용(N0=${_n0}), "
    _is_int "$_n1" && [ "$_n1" -lt 10 ] && bad6="${bad6}2종 조합 최소 ${_n1}자(10자 미만), "
    _is_int "$_n3" && [ "$_n3" -lt 8 ] && bad6="${bad6}3종 조합 최소 ${_n3}자(8자 미만), "
    _is_int "$_n4" && [ "$_n4" -lt 8 ] && bad6="${bad6}4종 조합 최소 ${_n4}자(8자 미만), "
fi
if _is_int "$pmd"; then [ "$pmd" -gt 90 ] || [ "$pmd" -eq 0 ] && bad6="${bad6}최대 사용 기간 ${pmd}일(90일 초과), "; fi
bad6=${bad6%, }
if [ -z "$mins" ]; then mc HV-06 "Security.PasswordQualityControl 조회 불가(값: ${pqc:-없음}) - 비밀번호 복잡도·사용 기간 수동 확인"
elif [ -n "$bad6" ]; then ng HV-06 "${bad6} (PasswordQualityControl=\"${pqc}\", PasswordMaxDays=${pmd:-미지원})"
elif ! _is_int "$pmd"; then mc HV-06 "복잡도 양호(${pqc}) / Security.PasswordMaxDays 미지원(ESXi ${VER}) - 비밀번호 변경 주기(90일 이하) 관리 절차 확인"
else ok HV-06 "PasswordQualityControl=\"${pqc}\" (2종 10자·3종 8자 이상), PasswordMaxDays=${pmd}일"; fi

# HV-07 계정 잠금 (AccountLockFailures 1~5회, AccountUnlockTime 600초 이상)
alf=$(adv Security.AccountLockFailures HV-07)
aut=$(adv Security.AccountUnlockTime HV-07)
if ! _is_int "$alf"; then mc HV-07 "Security.AccountLockFailures 미지원·조회 불가(ESXi ${VER}) - 계정 잠금 내부 정책 확인"
elif [ "$alf" -eq 0 ]; then ng HV-07 "Security.AccountLockFailures=0 (계정 잠금 미사용) - 5회 이하로 설정 필요"
elif [ "$alf" -gt 5 ]; then ng HV-07 "Security.AccountLockFailures=${alf}회 (5회 초과)"
elif _is_int "$aut" && [ "$aut" -lt 600 ]; then ng HV-07 "Security.AccountLockFailures=${alf}회 / AccountUnlockTime=${aut}초 (600초 미만)"
else ok HV-07 "Security.AccountLockFailures=${alf}회, AccountUnlockTime=${aut:-?}초"; fi

# ── 2. 시스템 서비스 관리 ──────────────────────────────────────
# HV-08 로그인 주의사항 (Annotations.WelcomeMessage / Config.Etc.issue — 버전 정보 노출 금지)
wm=$(adv Annotations.WelcomeMessage HV-08)
iss=$(adv Config.Etc.issue HV-08)
[ -z "$iss" ] && [ -s /etc/issue ] && iss=$(head -5 /etc/issue)
motd=$(adv Config.Etc.motd HV-08)
evd_v HV-08 "sshd Banner" "$(grep -i '^ *Banner' /etc/ssh/sshd_config 2>/dev/null)"
case "$motd" in *"VMware offers supported"*|*"All commands run on the ESXi shell are logged"*) motd="" ;; esac   # VMware 기본 문구
banner=$(printf '%s\n' "$wm" "$iss" "$motd" | sed '/^$/d' | tr '\n' ' ' | sed 's/ $//')
verre='(ESXi?|vSphere|VMkernel)[ -]?[0-9]|[Bb]uild[ -]?[0-9]{4,}|[Vv]ersion[ :]*[0-9]'
if [ -z "$banner" ]; then ng HV-08 "로그인 주의사항 미설정 (Annotations.WelcomeMessage·Config.Etc.issue 빈 값)"
elif printf '%s' "$banner" | grep -qE "$verre"; then ng HV-08 "로그인 주의사항에 시스템 버전 정보 노출: $(printf '%s' "$banner" | grep -oE "$verre" | head -1)…"
else ok HV-08 "로그인 주의사항 설정: $( [ -n "$wm" ] && echo 'WelcomeMessage ' )$( [ -n "$iss" ] && echo 'SSH 배너(issue) ' )$( [ -n "$motd" ] && echo 'motd' )- \"$(printf '%s' "$banner" | cut -c1-80)\""; fi

# HV-09 NTP 시간 동기화
ntp=$(run_e HV-09 "esxcli system ntp get")
srv=$(kv Servers "$ntp"); nen=$(kv Enabled "$ntp")
if [ -z "$srv" ] && [ -z "$nen" ]; then   # ESXi 7.0 U1 이전: ntp.conf + ntpd
    srv=$(run_e HV-09 "grep -E '^ *(server|pool) ' /etc/ntp.conf" | awk '$1 == "server" || $1 == "pool" { print $2 }' | tr '\n' ' ' | sed 's/ $//')
    /etc/init.d/ntpd status 2>/dev/null | grep -qi 'is running' && nen=true || nen=false
    evd_v HV-09 "/etc/init.d/ntpd status" "$(/etc/init.d/ntpd status 2>&1)"
fi
if [ -z "$srv" ]; then ng HV-09 "NTP 서버 미설정 - 호스트 > 관리 > 시스템 > 시간 및 날짜에서 NTP 서버 지정"
elif [ "$nen" != "true" ]; then ng HV-09 "NTP 서버(${srv}) 설정되었으나 NTP 서비스 미실행 - 시각 동기화 미적용"
else ok HV-09 "NTP 시각 동기화 적용: ${srv}"; fi

# HV-10 SNMP Community String 복잡도 (커뮤니티 값은 증적에서도 마스킹)
_sn=$(esxcli system snmp get 2>&1)
printf '[HV-10] %s $ esxcli system snmp get   (Communities 마스킹)\n%s\n\n' "$(ts)" "$(printf '%s\n' "$_sn" | sed 's/^\( *Communities: *\).\{1,\}$/\1***(마스킹)/')" >> "$_EVD"
sen=$(kv Enable "$_sn"); comm=$(kv Communities "$_sn" | tr ',' ' '); v3u=$(kv Users "$_sn")
weak=""; cn=0
for c in $comm; do
    cn=$((cn+1))
    case "$(_lc "$c")" in public|private) weak="${weak}${weak:+, }기본값($(_mask "$c"))"; continue ;; esac
    _cplx_ok "$c" || weak="${weak}${weak:+, }복잡도 미달($(_mask "$c"))"
done
if [ -z "$sen" ]; then mc HV-10 "SNMP 설정 조회 불가 - esxcli system snmp get 확인"
elif [ "$sen" != "true" ]; then ok HV-10 "SNMP 미사용 (Enable=false)"
elif [ -n "$weak" ]; then ng HV-10 "SNMP 사용 중 Community String 취약: ${weak} - 2종 10자/3종 8자 이상, 기본값 금지 (SNMP v3 사용 권고)"
elif [ "$cn" -gt 0 ]; then ok HV-10 "SNMP Community String ${cn}개 복잡도 충족$( [ -n "$v3u" ] && echo ', SNMPv3 사용자 설정' )"
else ok HV-10 "SNMP v1/v2c Community 미설정$( [ -n "$v3u" ] && echo ' (SNMPv3 사용)' )"; fi

# HV-11 MOB 비활성화
mob=$(adv Config.HostAgent.plugins.solo.enableMob HV-11)
case "$(_lc "$mob")" in
false) ok HV-11 "Config.HostAgent.plugins.solo.enableMob=false (MOB 비활성)" ;;
true)  ng HV-11 "Config.HostAgent.plugins.solo.enableMob=true (MOB 활성) - false 로 설정" ;;
*)     mc HV-11 "Config.HostAgent.plugins.solo.enableMob 조회 불가 - https://<ESXi>/mob 접속 가능 여부 확인" ;;
esac

# HV-12 ESXi Shell(TSM)·SSH(TSM-SSH) 비활성화
svc() {   # svc 키 → "실행여부 시작정책" (hostconfig 서비스 목록)
    awk -v K="$1" '$0 ~ "key = \"" K "\"" { f = 1; next }
        f && /running = / { r = $3; gsub(/[",]/, "", r) }
        f && /policy = /  { p = $3; gsub(/[",]/, "", p); print r " " p; exit }' "$HC"
}
st_tsm=$(svc TSM); st_ssh=$(svc TSM-SSH)
[ -z "$st_tsm" ] && st_tsm="$( /etc/init.d/ESXShell status 2>/dev/null | grep -qi 'is running' && echo true || echo false ) ?"
[ -z "$st_ssh" ] && st_ssh="$( /etc/init.d/SSH status 2>/dev/null | grep -qi 'is running' && echo true || echo false ) ?"
evd_v HV-12 "서비스 상태 (vim-cmd hostsvc/hostconfig: 실행여부 시작정책)" "TSM(ESXi Shell): ${st_tsm}
TSM-SSH(SSH): ${st_ssh}
SSH_CONNECTION: ${SSH_CONNECTION:-없음}"
sto=$(adv UserVars.ESXiShellTimeOut HV-12)
on_pol=""; run=""
for p in "TSM:${st_tsm}" "TSM-SSH:${st_ssh}"; do
    k=${p%%:*}; s=${p#*:}; r=${s%% *}; pol=${s#* }
    case "$pol" in on|automatic) on_pol="${on_pol}${on_pol:+, }${k}(시작 정책 ${pol})" ;; esac
    [ "$r" = "true" ] && run="${run}${run:+, }${k}"
done
_sto=$( _is_int "$sto" && [ "$sto" -gt 0 ] && echo " / ESXiShellTimeOut=${sto}초 후 자동 중지" )
if [ -n "$on_pol" ]; then ng HV-12 "ESXi Shell 상시 활성: ${on_pol} - 서비스 중지 및 시작 정책 '수동' 설정 필요"
elif [ -n "$run" ] && [ "${HV_SSH_TEMP:-0}" = "1" ] && [ "$run" = "TSM-SSH" ]; then ok HV-12 "SSH 는 점검을 위해 일시 실행 중(시작 정책 off, HV_SSH_TEMP=1)${_sto} - 점검 종료 후 SSH 서비스 중지 필요"
elif [ -n "$run" ]; then mc HV-12 "실행 중: ${run} (시작 정책 off - 수동 기동)${_sto} - 점검을 위한 일시 실행이면 점검 후 중지 시 양호, 상시 운영이면 취약"
else ok HV-12 "ESXi Shell(TSM)·SSH(TSM-SSH) 중지, 시작 정책 off"; fi

# HV-13 ESXi Shell 세션 타임아웃 (UserVars.ESXiShellInteractiveTimeOut 1~600초)
v=$(adv UserVars.ESXiShellInteractiveTimeOut HV-13)
if ! _is_int "$v"; then mc HV-13 "UserVars.ESXiShellInteractiveTimeOut 조회 불가 - 고급 설정에서 600초 이하 여부 확인"
elif [ "$v" -eq 0 ]; then ng HV-13 "UserVars.ESXiShellInteractiveTimeOut=0 (유휴 세션 종료 없음) - 600초 이하로 설정 필요"
elif [ "$v" -le 600 ]; then ok HV-13 "UserVars.ESXiShellInteractiveTimeOut=${v}초 (600초 이하)"
else ng HV-13 "UserVars.ESXiShellInteractiveTimeOut=${v}초 - 600초 초과"; fi

# 로그 (HV-14~16)
slc=$(run_e HV-14 "esxcli system syslog config get")
lh=$(adv Syslog.global.logHost HV-14)
[ -z "$lh" ] && lh=$(kv 'Remote Host' "$slc" | sed 's/^<none>$//')
slfw=$(printf '%s\n' "$rs" | awk -F'|' '$1 == "syslog" { print $2 }')
# HV-14 원격 로그 서버
if [ -z "$lh" ]; then ng HV-14 "원격 로그 서버 미설정 (Syslog.global.logHost 빈 값)"
elif [ "$slfw" = "false" ]; then mc HV-14 "Syslog.global.logHost=${lh} 설정되었으나 방화벽 syslog 규칙 비활성 - 전송 여부 확인"
else ok HV-14 "원격 로그 서버 연동: ${lh}"; fi

# HV-15 hostd 로그 레벨 (내부 정책 부합)
ll=$(adv Config.HostAgent.log.level HV-15)
case "$(_lc "$ll")" in
info|verbose|trivia) ok HV-15 "Config.HostAgent.log.level=${ll} (정보 수준 이상 기록) - 기관 로그 기록 정책과 부합 여부 확인" ;;
none|quiet|panic|error) ng HV-15 "Config.HostAgent.log.level=${ll} - 주요 이벤트 미기록 (info 이상 권고)" ;;
warning) mc HV-15 "Config.HostAgent.log.level=warning - 정보성 이벤트 미기록, 기관 로그 기록 정책과 비교 확인" ;;
*) mc HV-15 "Config.HostAgent.log.level 조회 불가 - 고급 설정에서 로그 수준 확인" ;;
esac

# HV-16 비휘발성 로그 경로 (Syslog.global.logDir)
ld=$(adv Syslog.global.logDir HV-16)
lpers=$(kv 'Local Log Output Is Persistent' "$slc")
case "$ld" in
"[] "*) lp=$(printf '%s' "$ld" | sed 's/^\[\] *//') ;;
"["*"] "*) _ds=$(printf '%s' "$ld" | sed 's/^\[\([^]]*\)\] .*/\1/'); lp="/vmfs/volumes/${_ds}/$(printf '%s' "$ld" | sed 's/^\[[^]]*\] *//')" ;;
*) lp=$ld ;;
esac
lreal=$( [ -n "$lp" ] && { readlink -f "$lp" 2>/dev/null || echo "$lp"; } )
evd_v HV-16 "로그 경로 실제 위치 (readlink -f) / 영구 저장 여부" "${ld} → ${lreal:-없음} / Local Log Output Is Persistent: ${lpers:-?}
$(ls -ld /scratch 2>&1)"
case "$lreal" in
"") ng HV-16 "로그 파일 경로 미설정 (Syslog.global.logDir 빈 값)" ;;
/tmp*|/var/tmp*|/run*|/dev/shm*|/dev/pts*) ng HV-16 "로그 경로가 휘발성 경로: ${ld} → ${lreal}" ;;
*)  if [ "$lpers" = "false" ]; then ng HV-16 "로그 경로 ${ld} → ${lreal} 비영구(Local Log Output Is Persistent=false) - 재시작 시 로그 유실"
    else
        case "$lp" in
        /scratch*) mc HV-16 "로그 경로 ${ld} (실제 ${lreal}, 영구 저장=${lpers:-?}) - 가이드는 /scratch 를 휘발성 경로로 분류, 데이터스토어 경로([datastore] /logs) 지정 권고" ;;
        *) ok HV-16 "로그 경로 ${ld} → ${lreal} (비휘발성)" ;;
        esac
    fi ;;
esac

# ── 3. 가상 머신 관리 ──────────────────────────────────────────
# HV-17 코어덤프 수집
cdn=$(run_e HV-17 "esxcli system coredump network get")
cdp=$(kv Active "$(run_e HV-17 "esxcli system coredump partition get")")
cdf=$(kv Active "$(run_e HV-17 "esxcli system coredump file get")")
if [ "$(kv Enabled "$cdn")" = "true" ]; then ok HV-17 "네트워크 코어덤프 활성: $(kv 'Network Server IP' "$cdn"):$(kv 'Network Server Port' "$cdn") ($(kv 'Host VNic' "$cdn"))"
elif [ -n "$cdp$cdf" ]; then mc HV-17 "네트워크 코어덤프 비활성 / 로컬 코어덤프 활성(${cdp:+파티션 $cdp}${cdf:+ 파일 $cdf}) - 가이드 조치: 네트워크 코어덤프 서버 지정, 내부 정책 확인"
else ng HV-17 "코어덤프 수집 비활성 (네트워크·파티션·파일 코어덤프 모두 미설정)"; fi

# HV-18~21 가상 머신 .vmx 설정
vms=$(run_e HV-18 "vim-cmd vmsvc/getallvms" | awk '/^[0-9]+ / && match($0, /\[[^]]*\] .*\.vmt?x( |$)/) {
        f = substr($0, RSTART, RLENGTH); sub(/ $/, "", f)
        nm = substr($0, length($1) + 1, RSTART - length($1) - 1); gsub(/^ +| +$/, "", nm)
        print $1 "|" nm "|" f }')
: > "$VMR"
nvm=0; nerr=0
while IFS='|' read -r id nm f; do
    [ -z "$id" ] && continue
    nvm=$((nvm+1))
    ds=$(printf '%s' "$f" | sed 's/^\[\([^]]*\)\] .*/\1/'); rel=$(printf '%s' "$f" | sed 's/^\[[^]]*\] *//')
    vmx="/vmfs/volumes/${ds}/${rel}"
    if [ ! -r "$vmx" ]; then nerr=$((nerr+1)); echo "${nm}|ERR|||||||" >> "$VMR"; continue; fi
    # 이름|edit|connectable|copy|paste|setGUIOptions|dnd|불필요 장치 목록
    awk -v N="$nm" '
        { k = $0; sub(/=.*/, "", k); gsub(/^[ \t]+|[ \t]+$/, "", k); k = tolower(k)
          v = $0; sub(/^[^=]*=/, "", v); gsub(/^[ \t]*"|"[ \t]*$/, "", v); v = tolower(v); K[k] = v }
        END {
            d = ""
            for (k in K) {
                if (k ~ /^floppy[0-9]+\.present$/ && K[k] == "true") d = d " 플로피(" substr(k, 1, index(k, ".") - 1) ")"
                else if (k ~ /^serial[0-9]+\.present$/ && K[k] == "true") d = d " 직렬포트(" substr(k, 1, index(k, ".") - 1) ")"
                else if (k ~ /^parallel[0-9]+\.present$/ && K[k] == "true") d = d " 병렬포트(" substr(k, 1, index(k, ".") - 1) ")"
                else if (k ~ /^(usb|ehci|usb_xhci)\.present$/ && K[k] == "true") d = d " USB(" substr(k, 1, index(k, ".") - 1) ")"
                else if (k ~ /^(ide|sata|scsi|nvme)[0-9]+:[0-9]+\.devicetype$/ && K[k] ~ /cdrom/) {
                    b = substr(k, 1, index(k, ".") - 1)
                    if (K[b ".present"] != "false" && K[b ".startconnected"] != "false") d = d " CD/DVD(" b ")"
                }
            }
            # floppy0.present 미기재 + floppy0 설정 존재 → 장치 있음 (VMX 기본값 present)
            if (!("floppy0.present" in K)) for (k in K) if (k ~ /^floppy0\./) { d = d " 플로피(floppy0)"; break }
            sub(/^ /, "", d)
            e = K["isolation.device.edit.disable"] "|" K["isolation.device.connectable.disable"]
            t = K["isolation.tools.copy.disable"] "|" K["isolation.tools.paste.disable"] "|" K["isolation.tools.setguioptions.enable"] "|" K["isolation.tools.dnd.disable"]
            print N "|" e "|" t "|" d
        }' "$vmx" >> "$VMR"
done <<EOF
$vms
EOF
vmtab=$(cat "$VMR")
evd_v HV-18 "가상 머신별 VMX 설정 (이름|device.edit.disable|device.connectable.disable|copy.disable|paste.disable|setGUIOptions.enable|dnd.disable|연결된 장치) — ERR: vmx 읽기 불가" "${vmtab:-등록된 가상 머신 없음}"
vm_cols() { printf '%s\n' "$vmtab" | awk -F'|' -v C="$1" 'NF { if ($2 == "ERR") { print $1 "|VMX 읽기 불가"; next }; n = split(C, c, ","); o = $1; for (i = 1; i <= n; i++) o = o "|" $(c[i]); print o }'; }
evd_v HV-19 "가상 머신별 연결 장치 (이름|플로피·직렬·병렬·USB·연결된 CD/DVD)" "$( [ "$nvm" -gt 0 ] && vm_cols 8 || echo '등록된 가상 머신 없음' )"
evd_v HV-20 "가상 머신별 콘솔 복사·붙여넣기 (이름|isolation.tools.copy.disable|paste.disable|setGUIOptions.enable)" "$( [ "$nvm" -gt 0 ] && vm_cols 4,5,6 || echo '등록된 가상 머신 없음' )"
evd_v HV-21 "가상 머신별 드래그 앤 드롭 (이름|isolation.tools.dnd.disable)" "$( [ "$nvm" -gt 0 ] && vm_cols 7 || echo '등록된 가상 머신 없음' )"
vm_fail() { printf '%s\n' "$vmtab" | awk -F'|' "\$2 != \"ERR\" && ($1) { print \$1 }"; }
vm_judge() {   # vm_judge 코드 '실패조건(awk)' 양호문구 취약문구
    _vf=$(vm_fail "$2")
    if [ "$nvm" -eq 0 ]; then ok "$1" "등록된 가상 머신 없음"
    elif [ -n "$_vf" ]; then ng "$1" "$4: $(_count "$_vf")/${nvm}대 - $(_head_list "$_vf")"
    elif [ "$nerr" -gt 0 ]; then mc "$1" "$3 ($((nvm-nerr))대) / VMX 읽기 불가 ${nerr}대 - 해당 VM 수동 확인"
    else ok "$1" "$3 (가상 머신 ${nvm}대 전체)"; fi
}
vm_judge HV-18 '$2 != "true" || $3 != "true"' "isolation.device.edit.disable·connectable.disable=TRUE" "장치 변경 방지 미설정(isolation.device.edit/connectable.disable≠TRUE)"
_vf=$(printf '%s\n' "$vmtab" | awk -F'|' '$2 != "ERR" && $8 != "" { print $1 ": " $8 }')
if [ "$nvm" -eq 0 ]; then ok HV-19 "등록된 가상 머신 없음"
elif [ -n "$_vf" ]; then ng HV-19 "불필요 장치 연결 $(_count "$_vf")/${nvm}대 - $(_head_list "$_vf" 6) - 업무상 필요 장치는 사유 확인"
elif [ "$nerr" -gt 0 ]; then mc HV-19 "USB·CD/DVD·플로피·직렬·병렬 장치 미연결 ($((nvm-nerr))대) / VMX 읽기 불가 ${nerr}대 - 수동 확인"
else ok HV-19 "USB·CD/DVD·플로피·직렬·병렬 장치 미연결 (가상 머신 ${nvm}대 전체)"; fi
vm_judge HV-20 '$4 != "true" || $5 != "true" || $6 == "true"' "isolation.tools.copy·paste.disable=TRUE, setGUIOptions.enable≠TRUE" "콘솔 복사·붙여넣기 제한 미설정(isolation.tools.copy/paste.disable≠TRUE 또는 setGUIOptions.enable=TRUE)"
vm_judge HV-21 '$7 != "true"' "isolation.tools.dnd.disable=TRUE" "콘솔 드래그 앤 드롭 제한 미설정(isolation.tools.dnd.disable≠TRUE)"

# ── 4. 가상 네트워크 관리 ──────────────────────────────────────
# 표준 스위치·포트 그룹 보안 정책 (포트 그룹은 상속 반영 값) + 분산 스위치(net-dvs)
secs=""
for v in $(esxcli network vswitch standard list 2>/dev/null | sed -n 's/^ *Name: *//p'); do
    o=$(run_e HV-22 "esxcli network vswitch standard policy security get -v '$v'")
    secs="${secs}vSwitch ${v}|$(kv 'Allow MAC Address Change' "$o")|$(kv 'Allow Promiscuous' "$o")|$(kv 'Allow Forged Transmits' "$o")
"
done
pgs=$(run_e HV-22 "esxcli network vswitch standard portgroup list" | esx_tbl Name)
while IFS= read -r pg; do
    [ -z "$pg" ] && continue
    o=$(run_e HV-22 "esxcli network vswitch standard portgroup policy security get -p '$pg'")
    secs="${secs}포트그룹 ${pg}|$(kv 'Allow MAC Address Change' "$o")|$(kv 'Allow Promiscuous' "$o")|$(kv 'Allow Forged Transmits' "$o")
"
done <<EOF
$pgs
EOF
dvs=$(esxcli network vswitch dvs vmware list 2>/dev/null | sed -n 's/^ *Name: *//p' | tr '\n' ' ' | sed 's/ $//')
dsec=""
if [ -n "$dvs" ] && _has net-dvs; then
    dsec=$(run_e HV-22 "net-dvs -l | grep -E '^switch |port.security'" | grep 'port.security' | sed 's/.*port\.security *= *//' | sort | uniq -c)
fi
evd_v HV-22 "가상 스위치 보안 정책 (대상|MAC 주소 변경|무차별 모드|위조 전송) / 분산 스위치: ${dvs:-없음}" "${secs}${dsec:+분산 스위치 포트 보안(개수 정책):
$dsec}"
evd_v HV-23 "가상 스위치 보안 정책 (대상|MAC 주소 변경|무차별 모드|위조 전송)" "${secs}${dsec:+분산 스위치 포트 보안(개수 정책):
$dsec}"
evd_v HV-24 "가상 스위치 보안 정책 (대상|MAC 주소 변경|무차별 모드|위조 전송)" "${secs}${dsec:+분산 스위치 포트 보안(개수 정책):
$dsec}"
sw_judge() {   # sw_judge 코드 열번호 정책명 net-dvs키워드
    _sb=$(printf '%s' "$secs" | awk -F'|' -v C="$2" '$1 != "" && $C == "true" { print $1 }')
    _su=$(printf '%s' "$secs" | awk -F'|' -v C="$2" '$1 != "" && $C == "" { print $1 }')
    _db=$(printf '%s\n' "$dsec" | grep -c "allow $4")
    _n=$(printf '%s' "$secs" | awk -F'|' '$1 != ""' | wc -l | tr -d ' ')
    if [ -n "$_sb" ] || [ "$_db" -gt 0 ]; then
        ng "$1" "$3 '허용(Accept)': $(_head_list "$_sb")$( [ "$_db" -gt 0 ] && echo "${_sb:+ / }분산 스위치(${dvs}) 포트 정책 allow $4" ) - '거부(Reject)'로 변경"
    elif [ "$_n" -eq 0 ] && [ -z "$dvs" ]; then mc "$1" "가상 스위치 정보 조회 불가 - 네트워킹 > 가상 스위치 > 보안에서 $3 확인"
    elif [ -n "$_su" ] || { [ -n "$dvs" ] && [ -z "$dsec" ]; }; then
        mc "$1" "$3 거부 확인(표준 ${_n}개)$( [ -n "$_su" ] && echo " / 조회 불가: $(_head_list "$_su")" )$( [ -n "$dvs" ] && [ -z "$dsec" ] && echo " / 분산 스위치(${dvs}) 정책은 vCenter 에서 확인" )"
    else ok "$1" "$3 '거부': 표준 스위치·포트 그룹 ${_n}개$( [ -n "$dvs" ] && echo " + 분산 스위치(${dvs})" )"; fi
}
sw_judge HV-22 2 "MAC 주소 변경" "mac change"
sw_judge HV-23 3 "무차별(Promiscuous) 모드" "promiscuous"
sw_judge HV-24 4 "위조 전송(Forged Transmits)" "forged"

# HV-25 보안 패치 (버전·빌드·지원 종료, 패치 이력)
prof=$(run_e HV-25 "esxcli software profile get" | head -1)
idt=$(run_e HV-25 "esxcli software vib list" | esx_tbl "Install Date" | grep -E '^[0-9]{4}-' | sort | tail -1)
today=$(date '+%Y%m%d')
case "$VER" in
[0-5].*|6.*) eog="20221015" ;;          # 6.5·6.7 일반 지원 종료 2022-10-15 (6.0 이하 그 이전)
7.0*)        eog="20251002" ;;          # vSphere 7.0 일반 지원 종료 2025-10-02
8.0*)        eog="20271011" ;;          # vSphere 8.0 일반 지원 종료 2027-10-11
*)           eog="" ;;
esac
pinfo="ESXi ${VER} build-${BUILD}${UPD:+ U$UPD}, 이미지 프로파일: ${prof:-?}, 최근 패치 설치일: ${idt:-?}"
if [ -n "$eog" ] && [ "$today" -gt "$eog" ]; then
    ng HV-25 "일반 지원 종료(EoGS $(echo "$eog" | sed 's/\(....\)\(..\)\(..\)/\1-\2-\3/')) 버전 - 보안 패치 미제공, 지원 버전으로 업그레이드 필요 (${pinfo})"
else
    mc HV-25 "${pinfo} - 패치 절차 수립·주기 적용 여부 인터뷰 확인, Broadcom 보안 권고(VMSA) 대비 최신 빌드 여부 확인"
fi

# ── 요약 ─────────────────────────────────────────────────────
_T=$((CP + CF + CM + CN))
echo "# ================================================================"
echo "# 점검 요약 — 가상화 장비 (HV)"
echo "#   총 점검 항목: ${_T}"
[ "$_T" -gt 0 ] && echo "#   양호: ${CP}  취약: ${CF}  수동확인: ${CM}  N-A: ${CN}"
echo "# ================================================================"
echo "# 점검 완료: $(date '+%Y-%m-%d %H:%M:%S')"
if [ "${HV_INLINE:-0}" = "1" ]; then
    echo "# ==== EVIDENCE BEGIN ===="
    cat "$_EVD"
    rm -f "$_EVD"
else
    echo "# 증적 파일: ${_EVD}  ← 결과와 함께 회수 후 ESXi 에서 삭제"
fi
}

# 'ssh … sh -s < 이 파일' 실행 시 하위 명령이 표준입력(스크립트 본문)을 읽지 않도록 /dev/null 연결
main "$@" </dev/null
exit 0
