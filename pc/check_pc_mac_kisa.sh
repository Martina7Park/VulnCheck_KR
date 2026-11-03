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
# [대상 OS]  macOS 12 ~ 26 (bash 3.2 호환)
# [실행 방법]
#   sudo bash check_pc_mac_kisa.sh > ~/Desktop/PC_KISA_$(hostname -s).txt
#   (sudo 없이도 실행되나 암호 정책·공유 설정 일부는 수동확인 처리)
#   PC-10/PC-11 은 Apple 보안 릴리스 목록(support.apple.com/100100)을 조회해 지원 종료·미적용 패치 판정
#   (인터넷 불가 시 연도 기반 추정, MAC_EOS_OFFLINE=1 로 조회 생략, PATCH_GRACE_DAYS=30 패치 유예일)
# [산출물]
#   1) 표준출력: PC-항목코드|결과|근거설명 (양호/취약/수동확인/N-A)
#   2) 증적 파일: 스크립트와 같은 폴더 <호스트명>_pc_kisa_evidence.txt
# ================================================================

HN=$(scutil --get ComputerName 2>/dev/null || hostname -s 2>/dev/null || echo Unknown)
HN=$(echo "$HN" | tr ' /' '__')
# ── 결과 사본 자동 저장: '> 파일' 리다이렉트를 빠뜨려도 판정 결과가 증적과 같은 위치에 남도록 표준출력을 복사 ──
_RESF="$(cd "$(dirname "$0")" && pwd)/PC_KISA_${HN}.txt"
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
echo "# ============================================================"

_CP=0; _CF=0; _CM=0; _CN=0
_DIR="$(cd "$(dirname "$0")" && pwd)"
_EVD="${_DIR}/${HN}_pc_kisa_evidence.txt"
{ echo "# ================================================================"; echo "# PC(macOS) 증적 파일 (주요정보통신기반시설 상세가이드 2026)"
  echo "# 대상: ${HN} / macOS ${OS_VER}"; echo "# 생성: $(date '+%Y-%m-%d %H:%M:%S')"
  echo "# ================================================================"; } > "$_EVD"
result() {
    echo "$1"
    case "$1" in
    *"|양호|"*) _CP=$((_CP+1)) ;; *"|취약|"*) _CF=$((_CF+1)) ;; *"|수동확인|"*) _CM=$((_CM+1)) ;; *) _CN=$((_CN+1)) ;;
    esac
    printf '[판정] %s\n\n' "$1" >> "$_EVD"
}
evd() {
    local item="$1"; shift
    printf '[%s] %s $ %s\n' "$item" "$(date '+%H:%M:%S')" "$*" >> "$_EVD"
    eval "$@" >> "$_EVD" 2>&1
    printf '\n' >> "$_EVD"
}
USERS=$(dscl . -list /Users UniqueID 2>/dev/null | awk '$2>=500 && $1!~/^_/{print $1}' | tr '\n' ' ')
CUSER=$(stat -f %Su /dev/console 2>/dev/null)
POL=$(pwpolicy getaccountpolicies 2>/dev/null)
[ -n "$CUSER" ] && [ "$CUSER" != "root" ] && POLU=$(pwpolicy -u "$CUSER" getaccountpolicies 2>/dev/null)
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
_rd() { if [ -n "$CUSER" ] && [ "$CUSER" != "root" ] && [ "$(id -u)" -eq 0 ]; then sudo -u "$CUSER" defaults read "$@" 2>/dev/null; else defaults read "$@" 2>/dev/null; fi; }

# ── PC-01 비밀번호의 주기적 변경 (최대 사용 기간 90일 이하) ──
evd "PC-01" "pwpolicy getaccountpolicies 2>/dev/null | grep -iE 'ExpiresEveryNDays|maxMinutesUntilChangePassword|policyAttributeLastPasswordChangeTime' ; profiles -P -o stdout 2>/dev/null | grep -iE 'maxPINAgeInDays|maxGracePeriod' | head -5"
days=$(echo "$POL$POLU" | grep -oE 'policyAttributeExpiresEveryNDays[^0-9]*[0-9]+' | grep -oE '[0-9]+$' | head -1)
[ -z "$days" ] && { m=$(echo "$POL$POLU" | grep -oE 'maxMinutesUntilChangePassword[^0-9]*[0-9]+' | grep -oE '[0-9]+$' | head -1); [ -n "$m" ] && days=$((m/1440)); }
[ -z "$days" ] && days=$(profiles -P -o stdout 2>/dev/null | grep -i maxPINAgeInDays | grep -oE '[0-9]+' | head -1)
if [ -z "$POL$POLU" ] && [ -z "$days" ]; then result "PC-01|수동확인|암호 정책 조회 불가(sudo 필요) - pwpolicy/MDM 프로파일의 최대 사용 기간 확인"
elif [ -n "$days" ] && [ "$days" -gt 0 ] && [ "$days" -le 90 ]; then result "PC-01|양호|최대 암호 사용 기간 ${days}일 (90일 이하)"
else result "PC-01|취약|최대 암호 사용 기간 ${days:-미설정(제한 없음)}$([ -n "$days" ] && echo '일 (90일 초과)')"; fi

# ── PC-02 비밀번호 관리정책 (복잡성·길이) ──
evd "PC-02" "pwpolicy getaccountpolicies 2>/dev/null | grep -iE 'policyAttributePassword matches|minChars|requiresAlpha|requiresNumeric|requiresSymbol|policyContent' | head -20; profiles -P -o stdout 2>/dev/null | grep -iE 'minLength|requireAlphanumeric|minComplexChars' | head -5"
ALL="$POL$POLU$(profiles -P -o stdout 2>/dev/null | grep -iE 'minLength|requireAlphanumeric|minComplexChars')"
ml=$(echo "$ALL" | grep -oE "\.\{[0-9]+," | grep -oE '[0-9]+' | sort -n | tail -1)
[ -z "$ml" ] && ml=$(echo "$ALL" | grep -oE 'minLength[^0-9]*[0-9]+|minChars[^0-9]*[0-9]+' | grep -oE '[0-9]+$' | sort -n | tail -1)
cls=0
echo "$ALL" | grep -qE '\[A-Za-z\]|\[a-zA-Z\]|requiresAlpha|requireAlphanumeric' && cls=$((cls+1))
echo "$ALL" | grep -qE '\[0-9\]|requiresNumeric|requireAlphanumeric' && cls=$((cls+1))
echo "$ALL" | grep -qE '\[\^a-zA-Z0-9\]|\[\^A-Za-z0-9\]|requiresSymbol|minComplexChars[^0-9]*[1-9]' && cls=$((cls+1))
if [ -z "$ALL" ]; then result "PC-02|수동확인|암호 정책 조회 불가(sudo 필요) - 최소 8자·영문·숫자·특수문자 조합 정책 확인"
elif [ "${ml:-0}" -ge 8 ] && [ $cls -ge 3 ]; then result "PC-02|양호|암호 정책: 최소 ${ml}자, 영문·숫자·특수문자 요구"
else result "PC-02|취약|암호 복잡성 정책 미흡 (최소 길이=${ml:-미설정}, 요구 문자 종류=${cls}종; 기준: 8자 이상·영문·숫자·특수문자)"; fi

# ── PC-03 복구 콘솔 자동 로그온 — Windows 기능 ──
evd "PC-03" "fdesetup status 2>/dev/null; firmwarepasswd -check 2>/dev/null"
result "PC-03|N-A|가이드 점검 대상(Windows 10, Windows 11) 아님 - macOS 는 Windows 복구 콘솔 기능 없음 (참고: FileVault/복구 잠금 상태 증적 확인)"

# ── PC-04 공유 폴더 ──
evd "PC-04" "sharing -l 2>/dev/null; launchctl print system/com.apple.smbd 2>&1 | head -3; netstat -an -p tcp 2>/dev/null | grep LISTEN | grep -E '[.:](445|548) '"
shares=$(sharing -l 2>/dev/null | awk -F':[ \t]*' '/^name:/{print $2}' | tr '\n' ',' | sed 's/,$//')
# 공유별 게스트 접근: 'List of Share Points' 블록의 smb/afp 'guest access: 1'
gshare=$(sharing -l 2>/dev/null | awk -F':[ \t]*' '/^name:/{n=$2} /guest access/{gsub(/[ \t]/,"",$2); if($2=="1") print n}' | sort -u | tr '\n' ',' | sed 's/,$//')
guest=$(defaults read /Library/Preferences/SystemConfiguration/com.apple.smb.server AllowGuestAccess 2>/dev/null)
# 공유 폴더가 정의돼 있어도 파일 공유 서비스(SMB/AFP)가 꺼져 있으면 외부 접근 불가 → 양호
if [ -z "$FS_ON" ]; then result "PC-04|양호|파일 공유 서비스(SMB/AFP) 비활성$([ -n "$shares" ] && echo " (정의된 공유 ${shares} 는 서비스 꺼짐으로 접근 불가$([ -n "$gshare" ] && echo ", 게스트 허용 설정 존재 - 재활성 시 취약"))")"
elif [ -n "$gshare" ]; then result "PC-04|취약|파일 공유(${FS_ON# }) 활성 + 공유 폴더 게스트 접근 허용 (비밀번호 없이 접근): ${gshare}"
elif [ "$guest" = "1" ]; then result "PC-04|취약|파일 공유 게스트 접근 허용 (AllowGuestAccess=1), 공유: ${shares:-확인 필요}"
else result "PC-04|수동확인|파일 공유 사용: ${shares:-공유 목록 확인 필요(sudo)} - 불필요 공유 여부·접근 권한 확인"; fi

# ── PC-05 불필요한 서비스 (원격 로그인·원격 Apple 이벤트·인터넷 공유·원격 관리 등) ──
evd "PC-05" "systemsetup -getremotelogin 2>/dev/null; systemsetup -getremoteappleevents 2>/dev/null; launchctl list 2>/dev/null | grep -E 'com.apple.(screensharing|RemoteDesktop|smbd|ftpd|tftpd|bootpd|InternetSharing|telnetd|cupsd)|ARDAgent'"
bad=""
systemsetup -getremotelogin 2>/dev/null | grep -qi ': On' && bad="${bad} 원격 로그인(SSH)"
systemsetup -getremoteappleevents 2>/dev/null | grep -qi ': On' && bad="${bad} 원격 Apple 이벤트"
launchctl list 2>/dev/null | grep -q 'com.apple.InternetSharing' && bad="${bad} 인터넷 공유"
launchctl list 2>/dev/null | grep -qE 'com.apple.(tftpd|ftpd|telnetd|bootpd)' && bad="${bad} TFTP/FTP/Telnet/BOOTP"
cups=$(cupsctl 2>/dev/null | grep -c '_share_printers=1')
[ "${cups:-0}" -gt 0 ] && bad="${bad} 프린터 공유"
[ -n "$bad" ] && result "PC-05|취약|불필요한 서비스 사용:${bad} (업무상 필요 시 예외)" || result "PC-05|양호|불필요한 공유·원격 서비스(원격 로그인·Apple 이벤트·인터넷/프린터 공유·TFTP 등) 미사용"

# ── PC-06 비인가 상용 메신저 ──
evd "PC-06" "ls /Applications \"/Users/${CUSER}/Applications\" 2>/dev/null | grep -iE 'kakao|line|telegram|whatsapp|discord|skype|nateon|wechat|signal|viber'"
msg=$(ls /Applications "/Users/${CUSER}/Applications" 2>/dev/null | grep -iE 'kakao|^line|telegram|whatsapp|discord|skype|nateon|wechat|signal|viber' | tr '\n' ',' | sed 's/,$//')
[ -n "$msg" ] && result "PC-06|수동확인|상용 메신저 설치: ${msg} - 기관 인가 메신저 여부 확인 (비인가 시 취약)" || result "PC-06|양호|상용 메신저 미설치"

# ── PC-07 파일 시스템 (NTFS 대응: APFS/HFS+ 저널링) ──
evd "PC-07" "diskutil list internal 2>/dev/null; mount | grep -E '^/dev/disk' "
fat=$(mount 2>/dev/null | grep -E '^/dev/disk' | grep -iE 'msdos|exfat' | awk '{print $3"("$NF")"}' | tr '\n' ' ')
intfat=$(diskutil list internal 2>/dev/null | grep -iE 'DOS_FAT|Windows_FAT|ExFAT' | awk '{print $NF}' | tr '\n' ' ')
[ -n "$intfat" ] && result "PC-07|취약|내장 디스크에 FAT/exFAT 볼륨: ${intfat}" || result "PC-07|양호|내장 디스크 APFS/HFS+ 사용 (접근 권한 지원 파일 시스템)$([ -n "$fat" ] && echo " / 참고: 외장 FAT 마운트 ${fat}")"

# ── PC-08 멀티 부팅 ──
evd "PC-08" "diskutil list 2>/dev/null | grep -iE 'Microsoft Basic Data|BOOTCAMP|Linux|EFI' ; bless --info --getboot 2>/dev/null"
mb=$(diskutil list internal 2>/dev/null | grep -iE 'Microsoft Basic Data|BOOTCAMP|Linux Filesystem' | awk '{print $NF}' | tr '\n' ' ')
[ -n "$mb" ] && result "PC-08|취약|다른 OS 파티션 존재(멀티 부팅 가능): ${mb}" || result "PC-08|양호|단일 OS (Boot Camp·타 OS 파티션 없음)"

# ── PC-09 브라우저 종료 시 임시 파일 삭제 ──
evd "PC-09" "defaults read com.google.Chrome ClearBrowsingDataOnExitList 2>/dev/null; defaults read com.microsoft.Edge ClearBrowsingDataOnExit 2>/dev/null; ls /Applications | grep -iE 'chrome|edge|firefox|whale|safari'"
ch=$(defaults read com.google.Chrome ClearBrowsingDataOnExitList 2>/dev/null | grep -c cached_images_and_files)
ed=$(defaults read com.microsoft.Edge ClearBrowsingDataOnExit 2>/dev/null)
if [ "${ch:-0}" -gt 0 ] || [ "$ed" = "1" ]; then result "PC-09|양호|브라우저 종료 시 캐시 삭제 정책 적용 (Chrome=${ch}, Edge=${ed:-미설정})"
else result "PC-09|수동확인|브라우저 종료 시 임시 파일(캐시) 삭제 정책 미확인 - 사용 브라우저별 설정 확인 (Safari 는 해당 설정 없음)"; fi

# ── PC-10 주기적 보안 패치 ──
evd "PC-10" "defaults read /Library/Preferences/com.apple.SoftwareUpdate 2>/dev/null; softwareupdate --history 2>/dev/null | head -10"
ac=$(defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled 2>/dev/null)
cr=$(defaults read /Library/Preferences/com.apple.SoftwareUpdate CriticalUpdateInstall 2>/dev/null)
last=$(softwareupdate --history 2>/dev/null | awk 'NR>2{
    if (match($0, /[0-9][0-9][0-9][0-9][.\/-] ?[0-9][0-9]?[.\/-] ?[0-9][0-9]?/)) { d=substr($0,RSTART,RLENGTH); gsub(/ /,"",d); split(d,a,/[.\/-]/); printf "%04d-%02d-%02d\n", a[1],a[2],a[3] }
    else if (match($0, /[0-9][0-9]?\/[0-9][0-9]?\/[0-9][0-9][0-9][0-9]/)) { split(substr($0,RSTART,RLENGTH),a,"/"); printf "%04d-%02d-%02d\n", a[3],a[1],a[2] }
}' | sort | tail -1)
mac_eos_check   # PC-10(보안 릴리스 적용)·PC-11(지원 종료) 공용 — Apple 보안 릴리스 목록 조회
GRACE=${PATCH_GRACE_DAYS:-30}
pmiss=""; [ -n "$PATCH_LATEST" ] && pmiss="미적용 보안 릴리스: ${OS_VER} → ${PATCH_LATEST} (가장 오래된 미적용 배포 ${PATCH_DATE}, ${PATCH_AGE}일 경과)"
if [ -n "$PATCH_LATEST" ] && [ "${PATCH_AGE:-0}" -gt "$GRACE" ] 2>/dev/null; then result "PC-10|취약|${pmiss} - ${GRACE}일 이상 보안 패치 미적용 (AutomaticCheck=${ac:-기본 1}, Critical=${cr:-기본 1}, 최근 설치 ${last:-확인 불가})"
elif [ "$ac" = "0" ] || [ "$cr" = "0" ]; then result "PC-10|취약|자동 업데이트 비활성 (AutomaticCheckEnabled=${ac:-기본}, CriticalUpdateInstall=${cr:-기본}) - 최근 설치 ${last:-확인 불가}"
else result "PC-10|양호|자동 업데이트·보안 응답 설치 활성 (AutomaticCheck=${ac:-기본 1}, Critical=${cr:-기본 1}), 최근 설치 ${last:-확인 불가}$([ -n "$pmiss" ] && echo ", ${pmiss}(유예 ${GRACE}일 이내)") - 내부 관리 절차는 인터뷰 확인"; fi

# ── PC-11 지원이 종료되지 않은 OS (Windows Build → macOS 버전) ──
evd "PC-11" "sw_vers 2>/dev/null"
# Apple 은 macOS 지원 종료일을 공지하지 않음 → 보안 릴리스 페이지에서 '최신 주요 버전 출시 이후에도 보안 업데이트를 받는지'로 판정 (mac_eos_check)
result "PC-11|${EOS_RES}|${EOS_DESC}"

# ── PC-12 자동 로그인 ──
evd "PC-12" "defaults read /Library/Preferences/com.apple.loginwindow autoLoginUser 2>/dev/null; ls -l /etc/kcpassword 2>/dev/null"
al=$(defaults read /Library/Preferences/com.apple.loginwindow autoLoginUser 2>/dev/null)
[ -n "$al" ] || [ -f /etc/kcpassword ] && result "PC-12|취약|자동 로그인 활성 (autoLoginUser=${al:-설정됨})" || result "PC-12|양호|자동 로그인 비활성"

# ── PC-13 / PC-14 백신 설치·업데이트 / 실시간 감시 ──
evd "PC-13" "find /Applications -maxdepth 2 -name '*.app' 2>/dev/null | sed 's#.*/##' | grep -iE '$AV_APP_RE'; ps -axco comm 2>/dev/null | grep -iE '$AV_PROC_RE' | sort -u; system_profiler SPInstallHistoryDataType 2>/dev/null | grep -A3 -E 'XProtect' | tail -4"
av="$AV_APPS"; avp="$AV_PROCS"
xp=$(system_profiler SPInstallHistoryDataType 2>/dev/null | grep -A4 'XProtectPlistConfigData' | grep -i 'Install Date' | tail -1 | sed 's/.*: //')
if [ -n "$av" ]; then
    result "PC-13|수동확인|백신 설치: ${av} - 엔진·패턴 최신 업데이트 여부 백신 콘솔에서 확인 (XProtect 최근 갱신: ${xp:-미확인})"
    [ -n "$avp" ] && result "PC-14|양호|백신 실시간 감시 프로세스 실행: ${avp}" || result "PC-14|수동확인|백신(${av}) 실시간 감시 프로세스 미확인 - 백신 설정에서 실시간 보호 확인"
else
    result "PC-13|수동확인|별도 백신 미설치 - macOS 내장 XProtect 만 존재(최근 갱신: ${xp:-미확인}) → 기관 정책상 인정 여부 판단 (미인정 시 취약)"
    result "PC-14|수동확인|별도 백신 미설치 - XProtect 는 실행 시점 검사(상시 감시 설정 없음) → 기관 정책상 인정 여부 판단 (미인정 시 취약)"
fi

# ── PC-15 OS 침입차단 기능(방화벽) ──
evd "PC-15" "/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null; /usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode 2>/dev/null"
fw=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null)
echo "$fw" | grep -qiE 'enabled|State = [12]' && result "PC-15|양호|macOS 방화벽 사용" || result "PC-15|취약|macOS 방화벽 사용 안 함 (${fw:-조회 실패})"

# ── PC-16 화면보호기 대기 10분 이하 + 암호 ──
evd "PC-16" "sudo -u \"$CUSER\" defaults -currentHost read com.apple.screensaver idleTime 2>/dev/null; sysadminctl -screenLock status 2>&1; pmset -g custom 2>/dev/null | grep -E 'displaysleep'"
idle=$( ( [ -n "$CUSER" ] && sudo -u "$CUSER" defaults -currentHost read com.apple.screensaver idleTime 2>/dev/null ) || defaults -currentHost read com.apple.screensaver idleTime 2>/dev/null)
dsl=$(pmset -g custom 2>/dev/null | awk '/displaysleep/{print $2}' | sort -n | tail -1)
lk=$(sysadminctl -screenLock status 2>&1 | grep -oiE 'immediate|off|[0-9]+ seconds')
[ -z "$lk" ] && lk=$(_rd com.apple.screensaver askForPassword)
t=${idle:-0}; [ "$t" -eq 0 ] 2>/dev/null && [ -n "$dsl" ] && t=$((dsl*60))
pwok=0; echo "$lk" | grep -qiE 'immediate|seconds|^1$' && pwok=1
if [ "$t" -gt 0 ] 2>/dev/null && [ "$t" -le 600 ] && [ $pwok -eq 1 ]; then result "PC-16|양호|화면보호기/디스플레이 끄기 $((t/60))분, 해제 시 암호 요구(${lk})"
else result "PC-16|취약|화면보호기 설정 미흡 (대기=${idle:-미설정}초, 디스플레이 끄기=${dsl:-미확인}분, 암호 요구=${lk:-미확인}; 기준: 10분 이하 + 암호)"; fi

# ── PC-17 이동식 미디어 자동 실행 방지 ──
evd "PC-17" "_rd com.apple.digihub 2>/dev/null"
dh=$(_rd com.apple.digihub | grep -E 'action' | grep -vE '= 1;' | head -3)
[ -n "$dh" ] && result "PC-17|수동확인|CD/DVD 삽입 시 동작 설정 존재: $(echo $dh) - 자동 실행 여부 확인" || result "PC-17|양호|macOS 는 이동식 미디어 자동 실행(AutoRun) 기능 없음 - 이동식 미디어 관리 절차는 인터뷰 확인"

# ── PC-18 원격 지원(화면 공유·원격 관리) 금지 ──
evd "PC-18" "launchctl print system/com.apple.screensharing 2>&1 | head -3; netstat -an -p tcp 2>/dev/null | grep LISTEN | grep -E '[.:](5900|3283) '; pgrep -lx ARDAgent; ps -axo comm 2>/dev/null | grep -iE 'ARDAgent|screensharingd|TeamViewer|AnyDesk|RemoteView' | sort -u"
rs=""
[ "$SS_ON" = 1 ] && rs="${rs} 화면 공유"
[ "$ARD_ON" = 1 ] && rs="${rs} 원격 관리(ARD)"
tp=$(ps -axo comm 2>/dev/null | grep -iE 'TeamViewer|AnyDesk|RemoteView|Chrome Remote' | awk -F/ '{print $NF}' | sort -u | tr '\n' ',' | sed 's/,$//')
[ -n "$tp" ] && rs="${rs} 원격 지원 프로그램(${tp})"
[ -n "$rs" ] && result "PC-18|취약|원격 지원 기능 사용:${rs}" || result "PC-18|양호|화면 공유·원격 관리·원격 지원 프로그램 미사용"

echo "# ============================================================"
echo "# 점검 요약 - 주요정보통신기반시설 상세가이드(2026) PC(macOS)"
echo "#   양호: ${_CP} / 취약: ${_CF} / 수동확인: ${_CM} / N-A: ${_CN}"
echo "# 증적 파일: ${_EVD}"
echo "# ============================================================"
[ -n "$_RESF" ] && echo "# 결과 파일(자동 저장): ${_RESF}  ← 증적 파일과 함께 회수"
[ -n "$_TEEPID" ] && { exec >&- 2>/dev/null; wait "$_TEEPID" 2>/dev/null; sleep 1; }
exit 0
