#!/bin/sh
# ================================================================
# 가상화(VMware ESXi) 보안 취약점 자동 점검 스크립트 v1.0
# ================================================================
#
# [용도]
#   전자금융기반시설·주요정보통신기반시설 점검 대상 중 가상화(하이퍼바이저) 장비 점검.
#   기준: 가상화(ESXi) 점검항목 HV-01~HV-34
#         VMware vSphere Security Configuration & Hardening Guide(7/8)·CIS VMware ESXi Benchmark 의
#         호스트 설정 항목을 서버 평가항목 분류(계정·서비스·로그·패치 관리)에 맞춰 정리한 자체 항목.
#         항목명·판단기준은 converter/convert_v4.py 의 VIRT_ITEMS 와 같음.
#
# [대상]
#   VMware ESXi 6.5 / 6.7 / 7.0 / 8.0 (ESXi Shell = BusyBox ash, bash 없음 → POSIX sh 문법만 사용)
#   vCenter Server Appliance(VCSA) 는 대상 아님 (Photon OS → server/check_server.sh 로 OS 점검)
#
# [사전 조건]
#   - root(또는 Administrator 역할) 계정으로 ESXi Shell/SSH 접속
#   - SSH 는 점검 동안만 활성화하고 점검 후 비활성화 (HV-01)
#
# [실행 방법]  ※ ESXi 8 은 execInstalledOnly 로 ./check_esxi.sh 직접 실행이 막힘 → 반드시 'sh' 로 실행
#   1) ESXi 에 업로드 후:   sh ./check_esxi.sh                        (결과 /tmp/<호스트>_esxi.txt 자동 저장)
#   2) 업로드 없이(점검자 PC): ssh root@<ESXi> 'sh -s' < check_esxi.sh > <호스트>_esxi.txt
#      증적: scp root@<ESXi>:/tmp/<호스트>_esxi_evidence.txt .
#   3) 여러 대 한 번에:      bash ./run_esxi_remote.sh hosts.txt        (결과·증적 자동 회수)
#
# [산출물]
#   1) 표준출력 — 파이프 구분자 결과   형식: HV-항목코드|결과|근거설명   결과: 양호 / 취약 / 수동확인 / N-A
#      (터미널에서 실행하면 /tmp/<호스트>_esxi.txt 에도 같은 내용 저장)
#   2) 증적 파일 — /tmp/<호스트>_esxi_evidence.txt (실행 명령·출력·판정 근거, 타임스탬프 포함)
#   ESXI_EMIT_EVIDENCE=1 이면 결과 뒤에 증적을 구분선과 함께 표준출력으로 이어서 출력하고 대상의 증적 파일은 삭제
#   (run_esxi_remote.sh 가 사용)
#
# ================================================================

_TMPD="${TMPDIR:-/tmp}"
_HC="${_TMPD}/.esxi_hostconfig.$$"
_CP=0; _CF=0; _CM=0; _CN=0

# ── 공통 함수 ────────────────────────────────────────────────────
_out() {   # 결과 줄: 표준출력 + (터미널 실행 시) 결과 파일
    printf '%s\n' "$1"
    [ -n "$_RESF" ] && printf '%s\n' "$1" >> "$_RESF"
    return 0
}
_isnum() { case "$1" in ''|*[!0-9]*) return 1 ;; esac; return 0; }
_one() { tr '\n' ' ' | sed 's/  */ /g; s/^ //; s/ $//'; }   # 여러 줄 → 한 줄 (판정 근거용)

_iname() {
    case "$1" in
    HV-01) echo "SSH 서비스 비활성화" ;;
    HV-02) echo "ESXi Shell 비활성화" ;;
    HV-03) echo "패스워드 복잡성 설정" ;;
    HV-04) echo "패스워드 최대 사용 기간 설정" ;;
    HV-05) echo "패스워드 재사용 제한" ;;
    HV-06) echo "계정 잠금 임계값 설정" ;;
    HV-07) echo "계정 잠금 해제 시간 설정" ;;
    HV-08) echo "불필요한 로컬 계정 및 권한 관리" ;;
    HV-09) echo "SSH 공개키(authorized_keys) 관리" ;;
    HV-10) echo "잠금 모드(Lockdown Mode) 설정" ;;
    HV-11) echo "AD 연동 'ESX Admins' 그룹 자동 권한 부여 제한" ;;
    HV-12) echo "세션 타임아웃 설정" ;;
    HV-13) echo "SSH 서비스 보안 설정" ;;
    HV-14) echo "MOB(Managed Object Browser) 비활성화" ;;
    HV-15) echo "SLP 서비스 비활성화" ;;
    HV-16) echo "CIM(WBEM) 서비스 제한" ;;
    HV-17) echo "SNMP 서비스 보안 설정" ;;
    HV-18) echo "방화벽 활성화 및 접근 IP 제한" ;;
    HV-19) echo "취약한 TLS 프로토콜 비활성화" ;;
    HV-20) echo "SSL 인증서 관리" ;;
    HV-21) echo "로그인 경고 배너 설정" ;;
    HV-22) echo "NTP 시간 동기화 설정" ;;
    HV-23) echo "원격 로그 서버 설정" ;;
    HV-24) echo "로그 영구 저장소 설정" ;;
    HV-25) echo "감사 기록(Audit Record) 설정" ;;
    HV-26) echo "보안 패치 및 지원 종료(EoS) 버전 관리" ;;
    HV-27) echo "VIB 수용 수준 설정" ;;
    HV-28) echo "설치된 실행 파일만 실행 허용(execInstalledOnly)" ;;
    HV-29) echo "가상 스위치 보안 정책 설정" ;;
    HV-30) echo "관리·vMotion 네트워크 분리" ;;
    HV-31) echo "iSCSI CHAP 인증 설정" ;;
    HV-32) echo "가상머신(VMX) 보안 설정" ;;
    HV-33) echo "가상머신 간 메모리 페이지 공유 제한" ;;
    HV-34) echo "가상머신 BPDU 차단" ;;
    esac
}

result() {   # result 코드 결과 근거
    _out "$1|$2|$3"
    case "$2" in
    양호) _CP=$((_CP+1)) ;; 취약) _CF=$((_CF+1)) ;; 수동확인) _CM=$((_CM+1)) ;; N-A) _CN=$((_CN+1)) ;;
    esac
    printf '[판정] %s (%s)|%s|%s\n\n' "$1" "$(_iname "$1")" "$2" "$3" >> "$_EVD"
}

_run() {   # _run 코드 '명령' → 출력은 $_O, 증적에 명령·출력 기록
    local c="$1"; shift
    _O=$(eval "$*" 2>&1)
    { printf '[%s] %s $ %s\n' "$c" "$(date '+%H:%M:%S')" "$*"
      [ -n "$_O" ] && printf '%s\n' "$_O"
      printf '\n'; } >> "$_EVD"
}

_note() {   # _note 코드 설명 → 증적에 설명 줄
    printf '[%s] %s %s\n\n' "$1" "$(date '+%H:%M:%S')" "$2" >> "$_EVD"
}

_optval() {   # _optval 고급옵션명(예: Security.AccountLockFailures) → 현재 값 (없으면 빈 값)
    local v
    v=$(vim-cmd hostsvc/advopt/view "$1" 2>/dev/null | sed -n 's/^ *value = //p' | head -1 | sed 's/,$//; s/^"//; s/"$//')
    [ "$v" = "<unset>" ] && v=""
    if [ -z "$v" ]; then   # hostd 응답 없음·옵션 미노출 → esxcli (VMkernel·UserVars 옵션)
        v=$(esxcli system settings advanced list -o "/$(echo "$1" | sed 's#\.#/#')" 2>/dev/null | awk '
            /^ *Type:/ {t=$0; sub(/^ *Type: */, "", t)}
            /^ *Int Value:/ {i=$0; sub(/^ *Int Value: */, "", i)}
            /^ *String Value:/ {s=$0; sub(/^ *String Value: */, "", s)}
            END {if (t == "string") print s; else print i}')
    fi
    printf '%s' "$v"
}

_opt() {   # _opt 코드 옵션명 → 값 출력 + 증적 기록
    local v
    v=$(_optval "$2")
    printf '[%s] %s $ vim-cmd hostsvc/advopt/view %s\n%s = %s\n\n' "$1" "$(date '+%H:%M:%S')" "$2" "$2" "${v:-(미설정/미지원)}" >> "$_EVD"
    printf '%s' "$v"
}

_svc() {   # _svc 서비스키(TSM-SSH) → "실행여부 시작정책" (예: "true on"), hostconfig 에 없으면 빈 값
    [ -s "$_HC" ] || return 0
    awk -v k="$1" '
        index($0, "key = \"" k "\"") {f=1; r=""; next}
        f && /running = / {r=$3; gsub(/[",]/, "", r)}
        f && /policy = / {p=$3; gsub(/[",]/, "", p); print r, p; exit}
        f && /key = "/ {f=0}' "$_HC"
}

_svcshow() {   # 증적용: 서비스 실행 상태·시작 정책
    local s
    s=$(_svc "$1")
    if [ -n "$s" ]; then echo "$1: running=${s%% *} policy=${s#* }"
    else echo "$1: hostconfig 서비스 정보 없음"; fi
    [ -n "$2" ] && [ -x "/etc/init.d/$2" ] && "/etc/init.d/$2" status 2>&1
    return 0
}

_judge_svc() {   # _judge_svc 코드 서비스키 init스크립트 표시명
    local s run pol st
    _O=$(_svcshow "$2" "$3")
    printf '[%s] %s $ vim-cmd hostsvc/hostconfig (서비스 %s 실행 여부·시작 정책); /etc/init.d/%s status\n%s\n\n' \
        "$1" "$(date '+%H:%M:%S')" "$2" "$3" "$_O" >> "$_EVD"
    s=$(_svc "$2"); run="${s%% *}"; pol="${s#* }"
    if [ -z "$s" ]; then   # hostconfig 없음 → init 스크립트 상태만
        st=$( [ -x "/etc/init.d/$3" ] && "/etc/init.d/$3" status 2>&1 | head -1)
        case "$st" in
        *"not running"*) result "$1" "양호" "$4 미실행 (시작 정책 확인 불가 - Host Client 관리>서비스에서 '수동으로 시작 및 중지' 확인)" ;;
        *running*) result "$1" "수동확인" "$4 실행 중 (시작 정책 확인 불가) - 점검용 임시 활성화가 아니면 비활성화 필요" ;;
        *) result "$1" "수동확인" "$4 상태 확인 불가" ;;
        esac
        return
    fi
    case "$pol" in
    on|automatic) result "$1" "취약" "$4 시작 정책 '${pol}' (호스트와 함께 자동 시작, 실행=${run}) - 정책 'off'(수동) 로 변경 후 필요 시에만 사용" ;;
    *) if [ "$run" = "true" ]; then
           result "$1" "수동확인" "$4 실행 중 (시작 정책 off) - 점검용 임시 활성화면 점검 후 중지, 상시 사용이면 취약"
       else
           result "$1" "양호" "$4 미실행·시작 정책 off"
       fi ;;
    esac
}

_tbl_col1() {   # esxcli 표 출력 → 첫 열 값 (구분선 너비 기준, 이름에 공백 허용)
    awk 'NR==2 {w = index($0, " ") - 1; if (w < 1) w = length($0); next}
         NR>2 && w {n = substr($0, 1, w); sub(/ +$/, "", n); if (n != "") print n}'
}

# ════════════════════════════════════════════════════════════════
# 1. 계정 관리
# ════════════════════════════════════════════════════════════════
chk_HV01() { _judge_svc "HV-01" "TSM-SSH" "SSH" "SSH 서비스"; }
chk_HV02() { _judge_svc "HV-02" "TSM" "ESXShell" "ESXi Shell"; }

chk_HV03() {
    local pqc mins n0 n1 n2 n3 n4 bad=""
    pqc=$(_opt HV-03 Security.PasswordQualityControl)
    if [ -z "$pqc" ]; then   # ESXi 6.0 이하: pam_passwdqc 설정
        _run HV-03 "grep -i passwdqc /etc/pam.d/passwd /etc/pam.d/system-password /etc/pam.d/system-auth 2>/dev/null"
        pqc=$(printf '%s\n' "$_O" | grep -o 'min=[^ ]*' | head -1)
    fi
    mins=$(printf '%s' "$pqc" | sed -n 's/.*min=\([^ ]*\).*/\1/p')
    if [ -z "$mins" ]; then
        result "HV-03" "수동확인" "패스워드 복잡성 설정(Security.PasswordQualityControl) 확인 불가"
        return
    fi
    n0=$(echo "$mins" | cut -d, -f1); n1=$(echo "$mins" | cut -d, -f2); n2=$(echo "$mins" | cut -d, -f3)
    n3=$(echo "$mins" | cut -d, -f4); n4=$(echo "$mins" | cut -d, -f5)
    # min=N0(1종),N1(2종),N2(패스프레이즈),N3(3종),N4(4종) — 기준: 1종 금지, 2종 10자 이상, 3·4종 8자 이상
    [ "$n0" != "disabled" ] && bad="${bad} 1종류 문자 ${n0}자 허용,"
    [ "$n1" != "disabled" ] && { _isnum "$n1" && [ "$n1" -ge 10 ] || bad="${bad} 2종류 조합 ${n1}자 허용(10자 미만),"; }
    [ "$n2" != "disabled" ] && { _isnum "$n2" && [ "$n2" -ge 10 ] || bad="${bad} 패스프레이즈 ${n2}자 허용(10자 미만),"; }
    [ "$n3" != "disabled" ] && { _isnum "$n3" && [ "$n3" -ge 8 ] || bad="${bad} 3종류 조합 ${n3}자 허용(8자 미만),"; }
    [ "$n4" != "disabled" ] && { _isnum "$n4" && [ "$n4" -ge 8 ] || bad="${bad} 4종류 조합 ${n4}자 허용(8자 미만),"; }
    if [ -n "$bad" ]; then result "HV-03" "취약" "패스워드 복잡성 미흡 (${pqc}):${bad%,} - 기준: 영문·숫자·특수문자 3종 이상 8자 이상(2종은 10자 이상)"
    else result "HV-03" "양호" "패스워드 복잡성 설정: ${pqc}"; fi
}

chk_HV04() {
    local v
    v=$(_opt HV-04 Security.PasswordMaxDays)
    if ! _isnum "$v"; then result "HV-04" "수동확인" "Security.PasswordMaxDays 미지원 버전 - 계정 패스워드 변경 주기 관리 절차 확인"
    elif [ "$v" -ge 1 ] && [ "$v" -le 90 ]; then result "HV-04" "양호" "패스워드 최대 사용 기간 ${v}일 (90일 이하)"
    else result "HV-04" "취약" "패스워드 최대 사용 기간 ${v}일 (기준 90일 이하, 기본값 99999)"; fi
}

chk_HV05() {
    local v
    v=$(_opt HV-05 Security.PasswordHistory)
    if ! _isnum "$v"; then result "HV-05" "수동확인" "Security.PasswordHistory 미지원 버전 - 이전 패스워드 재사용 제한 확인"
    elif [ "$v" -ge 5 ]; then result "HV-05" "양호" "최근 패스워드 ${v}개 재사용 금지"
    else result "HV-05" "취약" "패스워드 재사용 제한 ${v}개 (기준 최근 5개 이상)"; fi
}

chk_HV06() {
    local v
    v=$(_opt HV-06 Security.AccountLockFailures)
    if ! _isnum "$v"; then result "HV-06" "수동확인" "Security.AccountLockFailures 확인 불가"
    elif [ "$v" -eq 0 ]; then result "HV-06" "취약" "계정 잠금 미사용 (Security.AccountLockFailures=0)"
    elif [ "$v" -le 5 ]; then result "HV-06" "양호" "로그인 ${v}회 실패 시 계정 잠금 (5회 이하)"
    else result "HV-06" "취약" "계정 잠금 임계값 ${v}회 (기준 5회 이하)"; fi
}

chk_HV07() {
    local v
    v=$(_opt HV-07 Security.AccountUnlockTime)
    if ! _isnum "$v"; then result "HV-07" "수동확인" "Security.AccountUnlockTime 확인 불가"
    elif [ "$v" -ge 900 ]; then result "HV-07" "양호" "계정 잠금 해제 시간 ${v}초 (15분 이상)"
    else result "HV-07" "취약" "계정 잠금 해제 시간 ${v}초 (기준 900초(15분) 이상)"; fi
}

chk_HV08() {
    local acc extra adm
    _run HV-08 "esxcli system account list"
    acc=$(printf '%s\n' "$_O" | _tbl_col1)
    _run HV-08 "esxcli system permission list"
    # 표 열 위치는 구분선 기준 (주체명에 공백 허용: 'DOMAIN\ESX Admins')
    adm=$(printf '%s\n' "$_O" | awk '
        NR==2 {n=0; for (i=1; i<=length($0); i++) if (substr($0,i,1)=="-" && (i==1 || substr($0,i-1,1)==" ")) s[++n]=i; next}
        NR>2 && n>=3 {p=substr($0,s[1],s[2]-s[1]); r=substr($0,s[3],(n>=4 ? s[4] : length($0)+1)-s[3])
                      gsub(/^ +| +$/,"",p); gsub(/^ +| +$/,"",r); if (r=="Admin") print p}' \
          | grep -vxE 'root|dcui|vpxuser' | _one)
    extra=$(printf '%s\n' "$acc" | grep -vxE 'root|dcui|vpxuser' | _one)
    if [ -z "$acc" ]; then result "HV-08" "수동확인" "로컬 계정 목록 확인 불가"
    elif [ -z "$extra" ] && [ -z "$adm" ]; then result "HV-08" "양호" "기본 계정(root, dcui, vpxuser)만 존재"
    else result "HV-08" "수동확인" "추가 로컬 계정: ${extra:-없음} / 기본 외 Admin 권한: ${adm:-없음} - 업무상 필요 여부·공용/퇴직자 계정 확인"; fi
}

chk_HV09() {
    local f n=0 c keys=""
    _run HV-09 "ls -l /etc/ssh/keys-*/authorized_keys 2>/dev/null; for f in /etc/ssh/keys-*/authorized_keys; do [ -f \"\$f\" ] && echo \"== \$f\" && grep -vE '^[[:space:]]*(#|\$)' \"\$f\" | awk '{print \$1, substr(\$2,1,20) \"...\", \$3}'; done"
    for f in /etc/ssh/keys-*/authorized_keys; do
        [ -f "$f" ] || continue
        c=$(grep -cvE '^[[:space:]]*(#|$)' "$f" 2>/dev/null)
        _isnum "$c" && [ "$c" -gt 0 ] && { n=$((n+c)); keys="${keys} $(echo "$f" | sed 's#/etc/ssh/keys-\([^/]*\)/.*#\1#')(${c}개)"; }
    done
    if [ "$n" -eq 0 ]; then result "HV-09" "양호" "등록된 SSH 공개키 없음"
    else result "HV-09" "수동확인" "SSH 공개키 ${n}개 등록:${keys} - 승인된 관리자 키인지 확인, 불필요한 키 삭제"; fi
}

chk_HV10() {
    local vc lk lm acc
    _run HV-10 "grep -i '<serverIp>' /etc/vmware/vpxa/vpxa.cfg 2>/dev/null"
    vc=$(printf '%s\n' "$_O" | sed -n 's#.*<serverIp>\([^<]*\)</serverIp>.*#\1#p' | head -1)
    _run HV-10 "vim-cmd -U dcui vimsvc/auth/lockdown_is_enabled; grep -i 'lockdownMode' $_HC"
    lk=$(printf '%s\n' "$_O" | grep -ixE 'true|false' | head -1)
    lm=$(printf '%s\n' "$_O" | sed -n 's/.*lockdownMode = "\([^"]*\)".*/\1/p' | head -1)
    acc=$(_opt HV-10 DCUI.Access)
    case "$lm" in
    lockdownNormal|lockdownStrict) result "HV-10" "양호" "잠금 모드 ${lm#lockdown} 적용 (DCUI.Access=${acc:-기본})" ; return ;;
    esac
    [ -z "$lm" ] && [ "$lk" = "true" ] && { result "HV-10" "양호" "잠금 모드 적용 (DCUI.Access=${acc:-기본})"; return; }
    if [ -z "$lm" ] && [ -z "$lk" ]; then result "HV-10" "수동확인" "잠금 모드 상태 확인 불가 - vCenter 에서 호스트 '보안 프로파일 > 잠금 모드' 확인"
    elif [ -n "$vc" ]; then result "HV-10" "취약" "vCenter(${vc}) 관리 호스트인데 잠금 모드 미사용 - 일반(Normal) 이상 잠금 모드 적용, 예외 사용자 최소화"
    else result "HV-10" "수동확인" "vCenter 미연결 단독 호스트 - 잠금 모드는 vCenter 관리 시 적용 가능, 관리망 접근 통제 등 대체 수단 확인"; fi
}

chk_HV11() {
    local dom grp auto
    _run HV-11 "/usr/lib/vmware/likewise/bin/domainjoin-cli query 2>/dev/null"
    dom=$(printf '%s\n' "$_O" | sed -n 's/^ *Domain *= *//p' | head -1)
    if [ -z "$dom" ]; then result "HV-11" "N-A" "AD(Active Directory) 도메인 미가입"; return; fi
    grp=$(_opt HV-11 Config.HostAgent.plugins.hostsvc.esxAdminsGroup)
    auto=$(_opt HV-11 Config.HostAgent.plugins.hostsvc.esxAdminsGroupAutoAdd)
    _opt HV-11 Config.HostAgent.plugins.vimsvc.authValidateInterval >/dev/null
    if [ "$auto" = "false" ]; then result "HV-11" "양호" "AD(${dom}) 가입 - esxAdminsGroupAutoAdd=false (그룹 자동 관리자 권한 부여 해제)"
    elif [ -n "$grp" ] && [ "$grp" != "ESX Admins" ]; then result "HV-11" "양호" "AD(${dom}) 가입 - 관리자 그룹을 기본값이 아닌 '${grp}' 로 지정"
    else result "HV-11" "취약" "AD(${dom}) 가입, esxAdminsGroup='${grp:-ESX Admins}'·자동 권한 부여(AutoAdd=${auto:-미지원}) - CVE-2024-37085 (그룹 생성만으로 관리자 권한 획득)"; fi
}

# ════════════════════════════════════════════════════════════════
# 2. 서비스 관리
# ════════════════════════════════════════════════════════════════
chk_HV12() {
    local nm v bad="" ok=""
    for nm in UserVars.ESXiShellInteractiveTimeOut:900 UserVars.ESXiShellTimeOut:900 UserVars.DcuiTimeOut:600 UserVars.HostClientSessionTimeout:900; do
        v=$(_opt HV-12 "${nm%%:*}")
        _isnum "$v" || continue
        if [ "$v" -ge 1 ] && [ "$v" -le "${nm##*:}" ]; then ok="${ok} ${nm%%:*}=${v}"
        else bad="${bad} ${nm%%:*}=${v}(기준 1~${nm##*:}초),"; fi
    done
    ok=$(echo "$ok" | sed 's/UserVars\.//g'); bad=$(echo "$bad" | sed 's/UserVars\.//g')
    if [ -n "$bad" ]; then result "HV-12" "취약" "세션 타임아웃 미흡:${bad%,} (0=무제한)"
    elif [ -n "$ok" ]; then result "HV-12" "양호" "세션 타임아웃 설정:${ok}"
    else result "HV-12" "수동확인" "세션 타임아웃 옵션 확인 불가"; fi
}

chk_HV13() {
    local cf bad="" kv
    cf=/etc/ssh/sshd_config
    _run HV-13 "esxcli system ssh server config list 2>/dev/null; grep -vE '^[[:space:]]*(#|\$)' $cf 2>/dev/null"
    if [ ! -f "$cf" ]; then result "HV-13" "수동확인" "sshd_config 확인 불가"; return; fi
    _sshv() { grep -iE "^[[:space:]]*$1[[:space:]]" "$cf" 2>/dev/null | tail -1 | awk '{print tolower($2)}'; }
    [ "$(_sshv PermitEmptyPasswords)" = "yes" ] && bad="${bad} PermitEmptyPasswords yes,"
    [ "$(_sshv HostbasedAuthentication)" = "yes" ] && bad="${bad} HostbasedAuthentication yes,"
    [ "$(_sshv IgnoreRhosts)" = "no" ] && bad="${bad} IgnoreRhosts no,"
    [ "$(_sshv PermitUserEnvironment)" = "yes" ] && bad="${bad} PermitUserEnvironment yes,"
    [ "$(_sshv GatewayPorts)" = "yes" ] && bad="${bad} GatewayPorts yes,"
    [ "$(_sshv X11Forwarding)" = "yes" ] && bad="${bad} X11Forwarding yes,"
    case "$(_sshv PermitTunnel)" in yes|point-to-point|ethernet) bad="${bad} PermitTunnel $(_sshv PermitTunnel)," ;; esac
    [ "$(_sshv Protocol)" = "1" ] && bad="${bad} Protocol 1,"
    kv=$(grep -iE '^[[:space:]]*Ciphers[[:space:]]' "$cf" 2>/dev/null | tail -1 | awk '{print $2}')
    printf '%s' "$kv" | grep -qiE 'cbc|3des|arcfour|blowfish' && bad="${bad} 취약 암호화 알고리즘(Ciphers ${kv}),"
    if [ -n "$bad" ]; then result "HV-13" "취약" "SSH 보안 설정 미흡:${bad%,}"
    else result "HV-13" "양호" "빈 패스워드·호스트 기반 인증·포워딩·취약 암호 알고리즘 미허용"; fi
}

chk_HV14() {
    local v
    v=$(_opt HV-14 Config.HostAgent.plugins.solo.enableMob)
    case "$v" in
    false) result "HV-14" "양호" "MOB 비활성화 (enableMob=false)" ;;
    true)  result "HV-14" "취약" "MOB 활성화 (enableMob=true) - 인증 후 객체·설정 정보 노출 및 변경 가능" ;;
    *)     result "HV-14" "수동확인" "MOB 설정 확인 불가 - https://<호스트>/mob 접근 차단 여부 확인" ;;
    esac
}

chk_HV15() {
    local st pol
    _run HV-15 "/etc/init.d/slpd status 2>&1; chkconfig --list 2>/dev/null | grep -i slpd; esxcli network firewall ruleset list -r CIMSLP 2>/dev/null"
    if [ ! -e /etc/init.d/slpd ]; then result "HV-15" "양호" "SLP 서비스(slpd) 미설치"; return; fi
    st=$(/etc/init.d/slpd status 2>&1 | head -1)
    pol=$(chkconfig --list 2>/dev/null | awk 'tolower($1)=="slpd"{print tolower($2)}')
    case "$st" in
    *"not running"*) if [ "$pol" = "on" ]; then result "HV-15" "취약" "SLP 미실행이나 부팅 시 자동 시작(chkconfig on) - ESXiArgs 랜섬웨어(CVE-2021-21974) 공격 경로"
                     else result "HV-15" "양호" "SLP 서비스 중지${pol:+·시작 정책 ${pol}}"; fi ;;
    *running*) result "HV-15" "취약" "SLP 서비스 실행 중 - ESXiArgs 랜섬웨어(CVE-2021-21974) 공격 경로, 중지·chkconfig slpd off" ;;
    *) result "HV-15" "수동확인" "SLP 서비스 상태 확인 불가" ;;
    esac
}

chk_HV16() {
    local en
    _run HV-16 "esxcli system wbem get 2>/dev/null; /etc/init.d/sfcbd-watchdog status 2>&1"
    en=$(printf '%s\n' "$_O" | sed -n 's/^ *Enabled: *//p' | head -1)
    case "$en" in
    false) result "HV-16" "양호" "CIM(WBEM) 서비스 비활성화" ;;
    true)  result "HV-16" "수동확인" "CIM(WBEM) 서비스 활성화 - 하드웨어 모니터링 등 업무상 필요 여부 확인 (불필요 시 esxcli system wbem set --enable false)" ;;
    *) case "$_O" in
       *"not running"*) result "HV-16" "양호" "CIM(sfcbd) 서비스 미실행" ;;
       *running*) result "HV-16" "수동확인" "CIM(sfcbd) 서비스 실행 중 - 업무상 필요 여부 확인" ;;
       *) result "HV-16" "수동확인" "CIM 서비스 상태 확인 불가" ;;
       esac ;;
    esac
}

chk_HV17() {
    local en com c bad=""
    _run HV-17 "esxcli system snmp get"
    en=$(printf '%s\n' "$_O" | sed -n 's/^ *Enable: *//p' | head -1)
    com=$(printf '%s\n' "$_O" | sed -n 's/^ *Communities: *//p' | head -1 | tr ',' ' ')
    if [ "$en" != "true" ]; then
        [ -n "$en" ] && result "HV-17" "양호" "SNMP 서비스 미사용" || result "HV-17" "수동확인" "SNMP 설정 확인 불가"
        return
    fi
    for c in $com; do
        case "$(echo "$c" | tr 'A-Z' 'a-z')" in public|private) bad="${bad} ${c}(기본값)," ; continue ;; esac
        [ "${#c}" -lt 8 ] && bad="${bad} ${c}(8자 미만),"
    done
    if [ -n "$bad" ]; then result "HV-17" "취약" "SNMP Community 취약:${bad%,} - 추측 어려운 값으로 변경 또는 SNMPv3 사용"
    elif [ -n "$com" ]; then result "HV-17" "양호" "SNMP v1/v2c Community 기본값·8자 미만 아님 - SNMPv3(인증·암호화) 전환 권고"
    else result "HV-17" "양호" "SNMP 사용 (Community 미설정 - SNMPv3 사용)"; fi
}

chk_HV18() {
    local en act rs all
    _run HV-18 "esxcli network firewall get"
    en=$(printf '%s\n' "$_O" | sed -n 's/^ *Enabled: *//p' | head -1)
    act=$(printf '%s\n' "$_O" | sed -n 's/^ *Default Action: *//p' | head -1)
    _run HV-18 "esxcli network firewall ruleset list"
    rs=$(printf '%s\n' "$_O" | awk 'NR>2 && $NF=="true" {print $1}')
    _run HV-18 "esxcli network firewall ruleset allowedip list"
    # 관리 접속용 인바운드 규칙 중 모든 IP 허용
    all=$(printf '%s\n' "$_O" | awk 'NR>2 && $2=="All" {print $1}' | grep -xE 'sshServer|webAccess|vSphereClient|snmp|CIMHttpServer|CIMHttpsServer|CIMSLP' \
          | while read -r r; do printf '%s\n' "$rs" | grep -qx "$r" && echo "$r"; done | _one)
    if [ "$en" = "false" ]; then result "HV-18" "취약" "ESXi 방화벽 비활성화"
    elif [ "$act" = "PASS" ]; then result "HV-18" "취약" "ESXi 방화벽 기본 동작 PASS (허용) - DROP 으로 변경"
    elif [ -z "$en" ]; then result "HV-18" "수동확인" "방화벽 상태 확인 불가"
    elif [ -n "$all" ]; then result "HV-18" "취약" "관리 서비스 접근 IP 미제한(All): ${all} - 허용 IP 지정 (관리망 분리·상위 방화벽으로 통제 시 증빙 후 양호)"
    else result "HV-18" "양호" "방화벽 활성화(기본 DROP), 관리 서비스 접근 IP 제한"; fi
}

chk_HV19() {
    local v p
    if [ "$_MAJ" -ge 8 ] 2>/dev/null; then
        _run HV-19 "esxcli system tls server get 2>/dev/null"
        p=$(printf '%s\n' "$_O" | sed -n 's/^ *Profile: *//p' | head -1)
        v=$(_opt HV-19 UserVars.ESXiVPsDisabledProtocols)
        case "$p" in
        NIST_2024|COMPATIBLE) result "HV-19" "양호" "TLS 프로파일 ${p} (TLS 1.2 이상)" ;;
        MANUAL) result "HV-19" "수동확인" "TLS 프로파일 MANUAL - 허용 프로토콜·암호 목록 확인 (esxcli system tls server get --show-current-boot-profile)" ;;
        "") result "HV-19" "양호" "ESXi ${_VER} - TLS 1.0/1.1 미지원(TLS 1.2 이상만 사용)${v:+, 비활성 프로토콜: ${v}}" ;;
        *) result "HV-19" "수동확인" "TLS 프로파일 ${p} - 허용 프로토콜 확인" ;;
        esac
        return
    fi
    v=$(_opt HV-19 UserVars.ESXiVPsDisabledProtocols)
    if [ -z "$v" ]; then result "HV-19" "수동확인" "UserVars.ESXiVPsDisabledProtocols 확인 불가 - 허용 TLS 버전 확인"; return; fi
    p=",$(echo "$v" | tr -d ' ' | tr 'A-Z' 'a-z'),"
    case "$p" in
    *,tlsv1,*) case "$p" in *,tlsv1.1,*) result "HV-19" "양호" "취약 프로토콜 비활성화: ${v}"; return ;; esac ;;
    esac
    result "HV-19" "취약" "TLS 1.0/1.1 허용 (비활성 프로토콜: ${v}) - sslv3,tlsv1,tlsv1.1 비활성화 필요"
}

chk_HV20() {
    local crt sub iss
    crt=/etc/vmware/ssl/rui.crt
    if [ ! -f "$crt" ] || ! command -v openssl >/dev/null 2>&1; then
        _run HV-20 "ls -l $crt"
        result "HV-20" "수동확인" "인증서(${crt}) 또는 openssl 확인 불가 - Host Client '관리 > 보안 및 사용자 > 인증서' 확인"
        return
    fi
    _run HV-20 "openssl x509 -in $crt -noout -subject -issuer -startdate -enddate"
    sub=$(openssl x509 -in "$crt" -noout -subject 2>/dev/null | sed 's/^subject= *//')
    iss=$(openssl x509 -in "$crt" -noout -issuer 2>/dev/null | sed 's/^issuer= *//')
    if ! openssl x509 -in "$crt" -noout -checkend 0 >/dev/null 2>&1; then
        result "HV-20" "취약" "인증서 만료 ($(openssl x509 -in "$crt" -noout -enddate 2>/dev/null | cut -d= -f2))"
    elif ! openssl x509 -in "$crt" -noout -checkend 2592000 >/dev/null 2>&1; then
        result "HV-20" "수동확인" "인증서 30일 이내 만료 예정 ($(openssl x509 -in "$crt" -noout -enddate 2>/dev/null | cut -d= -f2)) - 갱신 필요"
    elif [ "$sub" = "$iss" ]; then
        result "HV-20" "수동확인" "자체 서명 인증서 (발급자=주체: ${iss}) - VMCA 또는 사설·공인 CA 발급 인증서로 교체 권고"
    else
        result "HV-20" "양호" "CA 발급 인증서 (발급자: ${iss}, 만료 $(openssl x509 -in "$crt" -noout -enddate 2>/dev/null | cut -d= -f2))"
    fi
}

chk_HV21() {
    local w i
    w=$(_opt HV-21 Annotations.WelcomeMessage)
    i=$(_opt HV-21 Config.Etc.issue)
    [ -z "$i" ] && [ -s /etc/issue ] && i=$(head -3 /etc/issue | _one)
    if [ -n "$w$i" ]; then result "HV-21" "양호" "로그인 배너 설정: $(printf '%s' "${w:-$i}" | _one | cut -c1-60)"
    else result "HV-21" "취약" "로그인 경고 배너 미설정 (Annotations.WelcomeMessage·Config.Etc.issue 빈 값)"; fi
}

chk_HV22() {
    local en sv st
    _run HV-22 "esxcli system ntp get 2>/dev/null; esxcli system ptp get 2>/dev/null; grep -E '^[[:space:]]*(server|pool)' /etc/ntp.conf 2>/dev/null; /etc/init.d/ntpd status 2>&1"
    en=$(printf '%s\n' "$_O" | sed -n 's/^ *Enabled: *//p' | head -1)
    sv=$(printf '%s\n' "$_O" | sed -n 's/^ *Servers: *//p' | head -1)
    [ -z "$sv" ] && sv=$(grep -E '^[[:space:]]*(server|pool)' /etc/ntp.conf 2>/dev/null | awk '{print $2}' | _one)
    st=$(/etc/init.d/ntpd status 2>&1 | head -1)
    if [ -z "$sv" ]; then result "HV-22" "취약" "NTP 서버 미설정"
    elif [ "$en" = "false" ]; then result "HV-22" "취약" "NTP 서버(${sv}) 설정되었으나 비활성화"
    else case "$st" in
         *"not running"*) result "HV-22" "취약" "NTP 서버(${sv}) 설정되었으나 ntpd 미실행" ;;
         *) result "HV-22" "양호" "NTP 시간 동기화: ${sv}" ;;
         esac
    fi
}

# ════════════════════════════════════════════════════════════════
# 3. 로그 관리
# ════════════════════════════════════════════════════════════════
chk_HV23() {
    local rh fw
    _run HV-23 "esxcli system syslog config get"
    _SYSLOG="$_O"
    rh=$(printf '%s\n' "$_O" | sed -n 's/^ *Remote Host: *//p' | head -1)
    _run HV-23 "esxcli network firewall ruleset list -r syslog"
    fw=$(printf '%s\n' "$_O" | awk '$1=="syslog"{print $2}')
    case "$rh" in
    ""|"<none>") result "HV-23" "취약" "원격 로그 서버(Syslog.global.logHost) 미설정" ;;
    *) if [ "$fw" = "false" ]; then result "HV-23" "취약" "원격 로그 서버(${rh}) 설정되었으나 방화벽 syslog 규칙 비활성 - 로그 전송 불가"
       else result "HV-23" "양호" "원격 로그 서버: ${rh}"; fi ;;
    esac
}

chk_HV24() {
    local pe dir sc
    pe=$(printf '%s\n' "$_SYSLOG" | sed -n 's/^ *Local Log Output Is Persistent: *//p' | head -1)
    dir=$(printf '%s\n' "$_SYSLOG" | sed -n 's/^ *Local Log Output: *//p' | head -1)
    sc=$(_opt HV-24 ScratchConfig.CurrentScratchLocation)
    case "$pe" in
    true)  result "HV-24" "양호" "로그 영구 저장소 사용 (${dir:-$sc})" ;;
    false) result "HV-24" "취약" "로그가 휘발성 저장소에 저장 (${dir:-$sc}) - 재부팅 시 로그 소실, Syslog.global.logDir 를 데이터스토어로 지정" ;;
    *) case "$sc" in
       /tmp/*|"") result "HV-24" "수동확인" "로그 저장 위치 영구 여부 확인 불가 (스크래치: ${sc:-미확인})" ;;
       *) result "HV-24" "양호" "스크래치(로그) 위치: ${sc}" ;;
       esac ;;
    esac
}

chk_HV25() {
    local st
    _run HV-25 "esxcli system auditrecords get 2>&1"
    st=$(printf '%s\n' "$_O" | sed -n 's/^ *AuditRecordStorageActive: *//p' | head -1)
    case "$st" in
    true)  result "HV-25" "양호" "감사 기록 저장 활성화 ($(printf '%s\n' "$_O" | sed -n 's/^ *AuditRecordStorageDirectory: *//p' | head -1))" ;;
    false) result "HV-25" "취약" "감사 기록 저장 비활성화 - esxcli system auditrecords local enable" ;;
    *)     result "HV-25" "N-A" "감사 기록(esxcli system auditrecords) 미지원 버전 (ESXi ${_VER:-버전 미확인})" ;;
    esac
}

# ════════════════════════════════════════════════════════════════
# 4. 패치 관리
# ════════════════════════════════════════════════════════════════
chk_HV26() {
    local mm eos today
    _run HV-26 "vmware -vl; esxcli system version get"
    mm=$(echo "$_VER" | cut -d. -f1-2)
    today=$(date '+%Y%m%d')
    case "$mm" in   # 일반 지원 종료(End of General Support) - Broadcom(VMware) 제품 수명주기
    [1-5].*) eos=20180919 ;;
    6.0) eos=20200312 ;;
    6.5|6.7) eos=20221015 ;;
    7.0) eos=20251002 ;;
    8.0) eos=20271011 ;;
    *) eos="" ;;
    esac
    if [ -z "$_VER" ]; then result "HV-26" "수동확인" "ESXi 버전 확인 불가"; return; fi
    if [ -n "$eos" ] && [ "$today" -gt "$eos" ] 2>/dev/null; then
        result "HV-26" "취약" "ESXi ${_VER} build-${_BUILD} 일반 지원 종료(EoGS $(echo "$eos" | sed 's/\(....\)\(..\)\(..\)/\1-\2-\3/')) - 보안 패치 미제공, 지원 버전으로 업그레이드"
    elif [ "$mm" = "8.0" ] && _isnum "$_BUILD" && [ "$_BUILD" -lt 24585300 ]; then
        result "HV-26" "취약" "ESXi ${_VER} build-${_BUILD} - VMSA-2025-0004(CVE-2025-22224~22226, 실제 공격 확인) 패치 미적용 빌드 (8.0 U3d 24585383 / U2d 24585300 이상 필요)"
    else
        result "HV-26" "수동확인" "ESXi ${_VER} build-${_BUILD}${eos:+ (EoGS $(echo "$eos" | sed 's/\(....\)\(..\)\(..\)/\1-\2-\3/'))} - 최신 VMSA 보안 권고 대비 패치 적용 여부 확인"
    fi
}

chk_HV27() {
    local lv cv
    _run HV-27 "esxcli software acceptance get"
    lv=$(printf '%s\n' "$_O" | grep -E '[A-Za-z]' | tail -1 | tr -d ' ')
    _run HV-27 "esxcli software vib list 2>/dev/null | grep -i CommunitySupported"
    cv=$(printf '%s\n' "$_O" | awk 'NF {print $1}' | _one)
    if [ "$lv" = "CommunitySupported" ]; then result "HV-27" "취약" "VIB 수용 수준 CommunitySupported (미검증 VIB 설치 허용)${cv:+ / 커뮤니티 VIB: ${cv}}"
    elif [ -n "$cv" ]; then result "HV-27" "취약" "CommunitySupported VIB 설치됨: ${cv} (수용 수준 ${lv:-미확인})"
    elif [ -n "$lv" ]; then result "HV-27" "양호" "VIB 수용 수준 ${lv}"
    else result "HV-27" "수동확인" "VIB 수용 수준 확인 불가"; fi
}

chk_HV28() {
    local rt req sb
    _run HV-28 "esxcli system settings kernel list -o execinstalledonly"
    rt=$(printf '%s\n' "$_O" | awk 'NR==1 {for (i=1; i<=NF; i++) if ($i=="Runtime") c=i} tolower($1)=="execinstalledonly" && c {print toupper($c)}')
    _run HV-28 "esxcli system settings encryption get 2>/dev/null; /usr/lib/vmware/secureboot/bin/secureBoot.py -s 2>/dev/null"
    req=$(printf '%s\n' "$_O" | sed -n 's/^ *Require Executables Only From Installed VIBs: *//p' | head -1)
    sb=$(printf '%s\n' "$_O" | grep -iE '^(Enabled|Disabled)' | head -1)
    case "$rt" in
    TRUE)  result "HV-28" "양호" "execInstalledOnly 적용 (설치된 VIB 외 실행 차단)${req:+, 강제(Require)=${req}}${sb:+, 보안 부팅 ${sb}}" ;;
    FALSE) result "HV-28" "취약" "execInstalledOnly 미적용 - 랜섬웨어 등 비인가 바이너리 실행 가능 (esxcli system settings kernel set -s execInstalledOnly -v TRUE)" ;;
    *) case "$req" in
       true) result "HV-28" "양호" "설치된 VIB 실행 파일만 허용(Require Executables Only From Installed VIBs=true)" ;;
       *) result "HV-28" "수동확인" "execInstalledOnly 상태 확인 불가" ;;
       esac ;;
    esac
}

# ════════════════════════════════════════════════════════════════
# 5. 가상화 보안
# ════════════════════════════════════════════════════════════════
_secbad() {   # 보안 정책 출력 → 허용(true)된 항목명
    printf '%s\n' "$1" | awk -F': *' '/^ *Allow Promiscuous:/ && $2=="true" {printf "무차별모드 "}
                                      /^ *Allow MAC Address Change:/ && $2=="true" {printf "MAC주소변경 "}
                                      /^ *Allow Forged Transmits:/ && $2=="true" {printf "위조전송 "}' | sed 's/ $//'
}

chk_HV29() {
    local vs pg b bad="" dvs
    _run HV-29 "esxcli network vswitch standard list"
    for vs in $(printf '%s\n' "$_O" | sed -n 's/^ *Name: *//p'); do
        _run HV-29 "esxcli network vswitch standard policy security get -v '$vs'"
        b=$(_secbad "$_O"); [ -n "$b" ] && bad="${bad} ${vs}(${b}),"
    done
    _run HV-29 "esxcli network vswitch standard portgroup list"
    printf '%s\n' "$_O" | _tbl_col1 > "${_TMPD}/.esxi_pg.$$"
    while read -r pg; do
        [ -n "$pg" ] || continue
        _run HV-29 "esxcli network vswitch standard portgroup policy security get -p '$pg'"
        b=$(_secbad "$_O"); [ -n "$b" ] && bad="${bad} '${pg}'(${b}),"
    done < "${_TMPD}/.esxi_pg.$$"
    rm -f "${_TMPD}/.esxi_pg.$$"
    _run HV-29 "esxcli network vswitch dvs vmware list 2>/dev/null"
    dvs=$(printf '%s\n' "$_O" | sed -n 's/^ *Name: *//p' | _one)
    if [ -n "$bad" ]; then result "HV-29" "취약" "가상 스위치 보안 정책 허용:${bad%,} - 무차별 모드·MAC 주소 변경·위조 전송 거부(Reject)"
    elif [ -n "$dvs" ]; then result "HV-29" "수동확인" "표준 스위치 보안 정책 양호 / 분산 스위치(${dvs}) 포트그룹 보안 정책은 vCenter 에서 확인"
    else result "HV-29" "양호" "표준 스위치·포트그룹 무차별 모드·MAC 주소 변경·위조 전송 모두 거부"; fi
}

chk_HV30() {
    local vmk t bad="" lst=""
    _run HV-30 "esxcli network ip interface list; esxcli network ip interface ipv4 get"
    for vmk in $(printf '%s\n' "$_O" | grep -oE '^vmk[0-9]+' | sort -u); do
        _run HV-30 "esxcli network ip interface tag get -i $vmk"
        t=$(printf '%s\n' "$_O" | sed -n 's/^ *Tags: *//p' | head -1)
        lst="${lst} ${vmk}[${t:-없음}]"
        case "$t" in *Management*) printf '%s' "$t" | grep -qE 'VMotion|VSAN|faultToleranceLogging|vSphereReplication|vSphereProvisioning' \
            && bad="${bad} ${vmk}(${t})," ;; esac
    done
    if [ -z "$lst" ]; then result "HV-30" "수동확인" "VMkernel 인터페이스 확인 불가"
    elif [ -n "$bad" ]; then result "HV-30" "취약" "관리 트래픽과 vMotion·vSAN 등 동일 인터페이스 사용:${bad%,} - 용도별 VMkernel·VLAN 분리"
    else result "HV-30" "양호" "VMkernel 용도 분리:${lst} (VLAN·물리 망 분리 여부는 네트워크 구성도로 확인)"; fi
}

chk_HV31() {
    local ad lv bad="" ok=""
    _run HV-31 "esxcli iscsi adapter list 2>/dev/null"
    for ad in $(printf '%s\n' "$_O" | awk 'NR>2 && $1 ~ /^vmhba/ {print $1}'); do
        _run HV-31 "esxcli iscsi adapter auth chap get -A $ad"
        lv=$(printf '%s\n' "$_O" | awk '/^ *Direction: *uni/ {u=1; next} u && /^ *Level:/ {sub(/^ *Level: */, ""); print; exit}')
        [ -z "$lv" ] && lv=$(printf '%s\n' "$_O" | sed -n 's/^ *Level: *//p' | head -1)
        case "$lv" in
        prohibited|"") bad="${bad} ${ad}(${lv:-미확인})," ;;
        *) ok="${ok} ${ad}(${lv})" ;;
        esac
    done
    if [ -z "$bad$ok" ]; then result "HV-31" "N-A" "iSCSI 어댑터 미사용"
    elif [ -n "$bad" ]; then result "HV-31" "취약" "iSCSI CHAP 인증 미사용:${bad%,} (대상(target)별 CHAP 설정 시 증빙 후 양호)"
    else result "HV-31" "양호" "iSCSI CHAP 인증 사용:${ok}"; fi
}

chk_HV32() {
    local n=0 nb=0 vm ds vmx b bad=""
    _run HV-32 "vim-cmd vmsvc/getallvms 2>/dev/null"
    printf '%s\n' "$_O" | sed -n 's/^\([0-9][0-9]*\) *\(.*[^ ]\) *\[\([^]]*\)\] \(.*\.vmx\).*/\2|\3|\4/p' > "${_TMPD}/.esxi_vm.$$"
    while IFS='|' read -r vm ds vmx; do
        [ -n "$vmx" ] || continue
        n=$((n+1)); [ "$n" -gt 300 ] && break
        vmx="/vmfs/volumes/${ds}/${vmx}"
        [ -r "$vmx" ] || continue
        b=$(grep -iE '^[[:space:]]*(isolation\.tools\.(copy|paste|dnd)\.disable[[:space:]]*=[[:space:]]*"false"|isolation\.tools\.setGUIOptions\.enable[[:space:]]*=[[:space:]]*"true"|RemoteDisplay\.vnc\.enabled[[:space:]]*=[[:space:]]*"true"|tools\.guestlib\.enableHostInfo[[:space:]]*=[[:space:]]*"true")' "$vmx" 2>/dev/null \
            | sed 's/[[:space:]]*=.*//; s/isolation\.tools\.//; s/\.disable//; s/RemoteDisplay\.vnc\.enabled/VNC/; s/tools\.guestlib\.enableHostInfo/HostInfo/' | _one)
        if [ -n "$b" ]; then
            nb=$((nb+1)); printf '[HV-32] %s 취약 설정: %s (%s)\n' "$vm" "$b" "$vmx" >> "$_EVD"
            [ "$nb" -le 10 ] && bad="${bad} ${vm}(${b}),"
        fi
    done < "${_TMPD}/.esxi_vm.$$"
    rm -f "${_TMPD}/.esxi_vm.$$"
    printf '\n' >> "$_EVD"
    if [ "$n" -eq 0 ]; then result "HV-32" "N-A" "등록된 가상머신 없음"
    elif [ "$nb" -gt 0 ]; then result "HV-32" "취약" "VMX 보안 설정 해제 가상머신 ${nb}대:${bad%,}$( [ "$nb" -gt 10 ] && echo ' 외') - 복사·붙여넣기·끌어놓기·VNC·호스트 정보 노출 비활성화"
    else result "HV-32" "양호" "가상머신 ${n}대 VMX 보안 설정 이상 없음 (복사·붙여넣기·VNC 등 허용 설정 없음)"; fi
}

chk_HV33() {
    local v
    v=$(_opt HV-33 Mem.ShareForceSalting)
    case "$v" in
    2)   result "HV-33" "양호" "Mem.ShareForceSalting=2 (가상머신 간 페이지 공유 차단)" ;;
    0|1) result "HV-33" "취약" "Mem.ShareForceSalting=${v} - 가상머신 간 메모리 페이지 공유(TPS) 허용, 2 로 설정" ;;
    *)   result "HV-33" "수동확인" "Mem.ShareForceSalting 확인 불가" ;;
    esac
}

chk_HV34() {
    local v
    v=$(_opt HV-34 Net.BlockGuestBPDU)
    case "$v" in
    1) result "HV-34" "양호" "Net.BlockGuestBPDU=1 (가상머신 BPDU 차단)" ;;
    0) result "HV-34" "취약" "Net.BlockGuestBPDU=0 - 가상머신이 BPDU 전송 시 물리 스위치 포트 차단(서비스 거부) 위험" ;;
    *) result "HV-34" "수동확인" "Net.BlockGuestBPDU 확인 불가" ;;
    esac
}

# ════════════════════════════════════════════════════════════════
_main() {
    if [ "$(uname -s 2>/dev/null)" != "VMkernel" ]; then
        echo "[오류] VMware ESXi(VMkernel) 가 아닙니다 ($(uname -s 2>/dev/null))." >&2
        [ -d /etc/vmware-vpx ] || [ -f /etc/applmgmt/appliance/appliance.conf ] && \
            echo "       vCenter Server Appliance 는 이 스크립트 대상이 아닙니다 - OS 는 server/check_server.sh 로 점검하세요." >&2
        exit 1
    fi
    HN=$(esxcli system hostname get 2>/dev/null | sed -n 's/^ *Fully Qualified Domain Name: *//p' | head -1)
    [ -z "$HN" ] && HN=$(hostname 2>/dev/null || uname -n)
    _EVD="${_TMPD}/${HN}_esxi_evidence.txt"
    ( : > "$_EVD" ) 2>/dev/null || { _EVD="./${HN}_esxi_evidence.txt"; : > "$_EVD"; }
    _RESF=""
    [ -t 1 ] && [ -z "$NO_RESULT_COPY" ] && { _RESF="${_TMPD}/${HN}_esxi.txt"; ( : > "$_RESF" ) 2>/dev/null || _RESF=""; }

    _VRAW=$(vmware -v 2>/dev/null)                                       # VMware ESXi 8.0.3 build-24585383
    _VER=$(echo "$_VRAW" | sed -n 's/.*ESXi \([0-9][0-9.]*\).*/\1/p')
    _BUILD=$(echo "$_VRAW" | sed -n 's/.*build-\([0-9]*\).*/\1/p')
    _MAJ=${_VER%%.*}
    _VLAB=$(vmware -l 2>/dev/null | head -1)                              # VMware ESXi 8.0 Update 3
    _VCIP=$(sed -n 's#.*<serverIp>\([^<]*\)</serverIp>.*#\1#p' /etc/vmware/vpxa/vpxa.cfg 2>/dev/null | head -1)

    _out "# ================================================================"
    _out "# 점검 대상: ${HN}"
    _out "# IP: $(esxcli network ip interface ipv4 get 2>/dev/null | awk 'NR>2 && $1=="vmk0" {print $2; exit}')"
    _out "# OS: ESXI / ${_VRAW:-VMware ESXi (버전 미확인)}"
    _out "# OS 상세: ${_VRAW:-VMware ESXi}${_VLAB:+ (${_VLAB#VMware ESXi })}"
    if [ -n "$_VCIP" ]; then _out "# 관리: vCenter ${_VCIP}"; else _out "# 관리: 단독 호스트(vCenter 미연결)"; fi
    _out "# 점검 기준: 가상화(VMware ESXi) 점검항목 HV-01~HV-34 (vSphere 보안 구성 가이드 기반)"
    _out "# 점검 일시: $(date '+%Y-%m-%d %H:%M:%S')"
    _out "# ================================================================"
    [ "$(id -u 2>/dev/null)" = "0" ] || _out "# [경고] root 가 아닌 계정으로 실행 - 일부 설정 조회 실패 시 수동확인 처리"

    {
        echo "# 가상화(ESXi) 점검 증적 - ${HN} - $(date '+%Y-%m-%d %H:%M:%S')"
        echo "# ${_VRAW} / ${_VLAB}"
        echo
    } >> "$_EVD"
    vim-cmd hostsvc/hostconfig > "$_HC" 2>/dev/null

    for c in 01 02 03 04 05 06 07 08 09 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31 32 33 34; do
        "chk_HV$c"
    done
    rm -f "$_HC"

    _T=$((_CP + _CF + _CM + _CN))
    _out "# ================================================================"
    _out "# 점검 요약"
    _out "#   총 점검 항목: ${_T}"
    [ "$_T" -gt 0 ] && {
    _out "#   양호:         ${_CP}  ($((_CP * 100 / _T))%)"
    _out "#   취약:         ${_CF}  ($((_CF * 100 / _T))%)"
    _out "#   수동확인:     ${_CM}"
    _out "#   N-A:          ${_CN}"
    }
    _out "# ================================================================"
    _out "# 점검 완료: $(date '+%Y-%m-%d %H:%M:%S')"
    _out "# 증적 파일: ${_EVD}"
    [ -n "$_RESF" ] && _out "# 결과 파일(자동 저장): ${_RESF}  ← 증적 파일과 함께 회수"
    if [ -n "$ESXI_EMIT_EVIDENCE" ]; then   # 원격 실행기가 증적까지 받아 가므로 대상에는 남기지 않음
        echo "### ESXI-EVIDENCE-BEGIN ${HN}"
        cat "$_EVD" && rm -f "$_EVD"
    fi
    return 0
}

# 'ssh ... sh -s < check_esxi.sh' 로 실행할 때 점검 명령이 남은 스크립트(표준입력)를 읽지 않도록 /dev/null 연결
_main "$@" </dev/null
