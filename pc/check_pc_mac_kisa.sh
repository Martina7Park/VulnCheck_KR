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
#   PC-10/PC-11 은 Apple 보안 릴리스 목록(support.apple.com/100100)을 조회해 미적용 보안 릴리스·지원 종료 판정
#   (인터넷 불가 시 연도 기반 추정, MAC_EOS_OFFLINE=1 로 조회 생략, PATCH_GRACE_DAYS=30 패치 유예일)
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
#   비root     : systemsetup·pwpolicy·profiles 등은 조회 불가 → 해당 항목은 '점검불가' (launchctl system 도메인 적재 여부는 비root 도 조회 가능 → SYSVIS)
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
# have <명령>: 명령이 있는지 (없으면 그 사실을 '점검불가' 사유로 쓰고, 빈 출력을 양호/취약으로 오판하지 않는다)
have() { command -v "$1" >/dev/null 2>&1; }
# 로컬 포트 수신(LISTEN) 여부: netstat -an -p tcp 의 LISTEN 행 '로컬 주소' 끝 포트만 인정 (외부로 나가는 연결의 원격 포트 5900 등은 서비스 활성 근거가 아님). netstat 에서 못 찾으면 로컬 연결 시도(nc)
listening() {
    if have netstat && netstat -an -p tcp 2>/dev/null | awk -v p="$1" '$NF=="LISTEN"{n=split($4,a,/[.:]/); if(a[n]==p) f=1} END{exit f?0:1}'; then return 0; fi
    port_open "$1"
}
# svc_state <launchd 라벨> <포트>: on / off / unk
#  ※ 'launchctl list' 에 보이는 com.apple.screensharing.agent / com.apple.RemoteDesktop.agent 는 모든 사용자 세션에 항상 로드되는 보조 에이전트라 서비스 활성 근거가 아님
#    → 서비스 데몬이 system 도메인에 로드됐는지(launchctl print system/<라벨>) 또는 포트가 LISTEN 중인지로만 판정
#  on: 포트 LISTEN 또는 system 도메인 로드 / off: system 도메인 조회 가능(root 또는 SYSVIS=1)한데 미로드·포트 닫힘 / unk: system 도메인을 못 보거나 launchctl 없음 (단정 불가)
# 비root 도 'launchctl print system/<라벨>' 로 system 도메인 적재 여부를 읽을 수 있음
#  (macOS 26.6 실기 확인: 비root 에서 적재된 com.apple.coreservicesd 는 조회되고, 미적재 서비스는 "Could not find service")
#  → system 도메인이 조회되면(SYSVIS=1) 비root 라도 '미적재 + 포트 닫힘 = off' 로 판정 (점검불가 남발 방지)
SYSVIS=0; have launchctl && launchctl print system/com.apple.coreservicesd >/dev/null 2>&1 && SYSVIS=1
svc_state() {
    if [ -n "$2" ] && listening "$2"; then echo on; return; fi
    if have launchctl; then
        if launchctl print "system/$1" >/dev/null 2>&1; then echo on; return; fi
        { [ "$IS_ROOT" -eq 1 ] || [ "$SYSVIS" -eq 1 ]; } && { echo off; return; }
    fi
    echo unk
}
# remote_tools: 3rd-party 원격 지원 프로그램 실행 여부 (프로세스 이름 기준) — Chrome 원격 데스크톱 호스트는 remoting_me2me_host 로 실행됨
#  + Chrome 원격 데스크톱 '원격 액세스' 켜짐 표시 파일(/Library/PrivilegedHelperTools/org.chromium.chromoting.me2me_enabled)
remote_tools() {
    local t
    t=$(ps -axo comm 2>/dev/null | awk -F/ '{print $NF}' | grep -iE '^(TeamViewer|AnyDesk|RemoteView|Chrome Remote|remoting_(me2me_)?host$|rustdesk|Splashtop|ScreenConnect|LogMeIn|GoToAssist|RealVNC|vncserver)' | sort -u | tr '\n' ',' | sed 's/,$//')
    [ -e /Library/PrivilegedHelperTools/org.chromium.chromoting.me2me_enabled ] && t="${t:+${t},}Chrome 원격 데스크톱(원격 액세스 켜짐)"
    echo "$t"
}
# ard_state: 원격 관리(ARD) on / off / unk — ARDAgent 프로세스(ps 는 모든 사용자 프로세스가 보임) 또는 3283 포트 LISTEN 이면 on
ard_state() {
    if have ps && ps -axo comm 2>/dev/null | awk -F/ '$NF=="ARDAgent"{f=1} END{exit f?0:1}'; then echo on; return; fi
    if listening 3283; then echo on; return; fi
    if have ps; then echo off; else echo unk; fi
}

# ── 백신 판별: 앱 이름·실행 파일 이름(경로 제외)으로만 판별 ──
#  /Applications/AhnLab/ASTx(안랩 세이프 트랜잭션, 금융 보안 모듈)처럼 폴더·경로에 제조사명이 있어도 백신이 아닌 것을 백신으로 오탐하지 않도록
#  ※ 'AhnLab' 단독 일치는 쓰지 않음 (V3 제품은 'V3'/'AhnLab V3' 로 시작하는 앱 이름으로 판별)
AV_APP_RE='^(ahnlab ?)?v3( |lite|365|$)|kaspersky|alyac|sophos|symantec|norton|mcafee|^eset|bitdefender|crowdstrike|^falcon|^sentinel|defender|malwarebytes|avast|avira|trend ?micro'
AV_PROC_RE='^(v3|ahnlab ?v3)|^kav|kaspersky|sophos|symantec|norton|mcafee|^eset|bitdefender|^bdldaemon|^falcon|com\.crowdstrike|^sentinel|^wdav|malwarebytes|^rtprotection|avast|avira|alyac|trend ?micro|^icoreservice'
# av_scan: AV_DIRS(검색한 폴더) / AV_APPS(백신 앱 이름) / AV_PROCS(백신 프로세스 이름) 설정
av_scan() {
    AV_DIRS="/Applications"
    if [ "$IS_ROOT" -eq 1 ]; then
        case "$TUSER" in ''|*[!A-Za-z0-9._-]*) ;; *) AV_DIRS="$AV_DIRS /Users/$TUSER/Applications" ;; esac
    else
        case "$HOME" in ''|*[!A-Za-z0-9._/-]*) ;; *) AV_DIRS="$AV_DIRS $HOME/Applications" ;; esac
    fi
    AV_APPS=$(find $AV_DIRS -maxdepth 2 -name '*.app' 2>/dev/null | sed 's#.*/##;s/\.app$//' | grep -iE "$AV_APP_RE" | sort -u | tr '\n' ',' | sed 's/,$//')
    AV_PROCS=$(ps -axo comm 2>/dev/null | awk -F/ '{print $NF}' | grep -iE "$AV_PROC_RE" | sort -u | tr '\n' ',' | sed 's/,$//')
}

# ── macOS 지원 종료(EoS) 판정: Apple 보안 릴리스 페이지(support.apple.com/100100) 조회 ──
# Apple 은 macOS 지원 종료일을 공지하지 않으므로 '실제 보안 업데이트 배포 여부'로 판정:
#   최신 주요 버전(N) 최초 출시 이후에도 CVE 가 포함된 보안 업데이트를 받은 주요 버전 = 지원 중, 그 외 = 지원 종료
#   (N-3 은 N 출시 당일 마지막 업데이트를 받고 끝나므로 '출시일 당일 릴리스'만 있는 경우는 PATCH_GRACE_DAYS 동안만 전환기(수동확인), 이후 지원 종료)
# 결과 변수: EOS_RES(양호/취약/수동확인/점검불가) EOS_DESC(근거 한 줄) EOS_EVD(증적용 원자료) /
#           PATCH_LATEST(같은 주요 버전의 더 새 보안 릴리스 중 최신), PATCH_DATE·PATCH_AGE(미적용 보안 릴리스 중 가장 오래된 것의 배포일·경과일)
# MAC_EOS_OFFLINE=1 이면 온라인 조회를 생략하고, 조회·해석에 실패하면 연도 기반 '추정'으로 판정한다. PATCH_GRACE_DAYS(기본 30)
# 조회한 페이지 내용은 awk 로 숫자·날짜만 뽑아 검증한 값만 사용 (eval 사용 안 함)
mac_eos_check() {
    local major=${OS_VER%%.*} url="https://support.apple.com/en-us/100100" grace why="" page="" crc=0 raw="" parsed="" rows="" out="" nrows=0
    local e_ok e_n e_n0 e_sup e_lv e_ld e_r e_pl e_pd e_age e_nr e_nm fd ld bad=0 x today
    EOS_RES=""; EOS_DESC=""; EOS_EVD=""; PATCH_LATEST=""; PATCH_DATE=""; PATCH_AGE=""
    grace=${PATCH_GRACE_DAYS:-30}; case "$grace" in ''|*[!0-9]*) grace=30 ;; esac
    case "$major" in
        ''|*[!0-9]*) EOS_RES="점검불가"; EOS_DESC="macOS 버전(sw_vers) 조회 실패 (${OS_VER}) - 지원 종료 여부 판정 불가"; EOS_EVD="OS_VER=${OS_VER}"; return 0 ;;
    esac
    today=$(date +%Y%m%d)
    if [ -n "$MAC_EOS_OFFLINE" ]; then why="MAC_EOS_OFFLINE 설정으로 온라인 조회 생략"
    elif ! have curl; then why="curl 명령 없음"
    else
        page=$(curl -sfL -m 20 --connect-timeout 8 -A "Mozilla/5.0" "$url" 2>/dev/null); crc=$?
        if [ "$crc" -ne 0 ] || [ -z "$page" ]; then why="Apple 보안 릴리스 페이지 조회 실패 (curl 종료코드 ${crc})"
        else
            # 1) macOS 행만 뽑아 태그 제거 (칸은 | 로 구분) — 증적 원자료
            raw=$(printf '%s\n' "$page" | tr '\r\n' '  ' | sed 's#</[Tt][Rr]>#&\
#g' | sed -e 's/<[^>]*>/|/g' -e 's/&nbsp;/ /g' -e 's/&amp;/\&/g' | awk -F'|' '
                { n=0; for(i=1;i<=NF;i++){ f=$i; gsub(/^[ \t]+/,"",f); gsub(/[ \t]+$/,"",f); gsub(/[ \t]+/," ",f); if(f!=""){ n++; c[n]=f } }
                  if (n>0 && c[1] ~ /^macOS [A-Z][A-Za-z ]* [0-9]+(\.[0-9]+)*$/) { s=c[1]; for(i=2;i<=n;i++) s=s "|" c[i]; print s } }')
            # 2) 버전·날짜(YYYYMMDD)·CVE 없음 여부(1) 로 정규화하고 형식이 맞는 줄만 사용
            parsed=$(printf '%s\n' "$raw" | awk -F'|' '
                BEGIN{split("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec",M," "); for(i=1;i<=12;i++) m[M[i]]=sprintf("%02d",i)}
                NF>0 { v=$1; sub(/.* /,"",v); nc=($0 ~ /no published CVE/)?1:0; d=""
                  for(i=2;i<=NF;i++){ if (split($i,a," ")==3 && a[1] ~ /^[0-9][0-9]?$/ && (a[2] in m) && a[3] ~ /^20[0-9][0-9]$/) { d=a[3] m[a[2]] sprintf("%02d",a[1]+0); break } }
                  if (d!="") print v, d, nc }')
            rows=$(printf '%s\n' "$parsed" | grep -E '^[0-9]+(\.[0-9]+)* 20[0-9]{6} [01]$')
            if [ -n "$rows" ]; then nrows=$(printf '%s\n' "$rows" | wc -l | tr -d ' '); fi
            EOS_EVD="[원문: macOS 행 (HTML 태그 제거, 칸 구분 |) - 조회 ${url}, 수신 ${#page}자]
${raw:-(macOS 행 없음)}
[정규화: 버전 날짜(YYYYMMDD) CVE없음여부(1=This update has no published CVE entries)]
${rows:-(해석된 행 없음)}"
            if [ "$nrows" -lt 10 ]; then why="목록 해석 실패 (해석된 macOS 릴리스 ${nrows}개 - 페이지 형식 변경 가능)"
            else
                out=$(printf '%s\n' "$rows" | awk -v cur="$OS_VER" -v mj="$major" -v today="$today" -v grace="$grace" '
                    function vcmp(a,b,  x,y,i,n,m,p,q){n=split(a,x,".");m=split(b,y,".");if(m>n)n=m;for(i=1;i<=n;i++){p=x[i]+0;q=y[i]+0;if(p<q)return -1;if(p>q)return 1}return 0}
                    function jd(s,  y,mo,d){y=int(s/10000);mo=int((s%10000)/100);d=s%100;if(mo<3){y--;mo+=12};return int(365.25*(y+4716))+int(30.6001*(mo+1))+d}
                    { split($1,p,"."); M=p[1]+0; d=$2+0; nrows++
                      if(!(M in seen)){seen[M]=1; nmaj++}
                      if(M>N) N=M
                      if(!(M in first) || d<first[M]) first[M]=d
                      if(vcmp($1,M".0")==0 && (!(M in n0) || d<n0[M])) n0[M]=d
                      if($3==0){ if(!(M in last) || d>last[M]) last[M]=d
                                 if(!(M in lv) || vcmp($1,lv[M])>0) lv[M]=$1 }
                      if(d>newest) newest=d
                      if($3==0 && M==mj+0 && vcmp($1,cur)>0){ if(pl==""||vcmp($1,pl)>0) pl=$1; if(pd==""||d<pd) pd=d } }
                    END{ ok=1
                      if(nrows<10 || nmaj<3 || N<10) ok=0
                      if(jd(today)-jd(newest)>400 || jd(newest)-jd(today)>7) ok=0
                      n0d=(N in n0)?n0[N]:first[N]; age0=jd(today)-jd(n0d)
                      sup=""; for(k=N;k>=10;k--) if(k==N || ((k in last) && (last[k]>n0d || (last[k]==n0d && age0<=grace+0)))) sup=sup (sup==""?"":",") k
                      mn=mj+0
                      if(mn>N) r="N"
                      else if(mn==N) r="G"
                      else if((mn in last) && last[mn]>n0d) r="G"
                      else if((mn in last) && last[mn]==n0d && age0<=grace+0) r="M"
                      else r="B"
                      printf "%d|%d|%d|%s|%s|%s|%s|%s|%s|%s|%d|%d\n", ok, N, n0d, sup, lv[mn], last[mn], r, pl, pd, (pd==""?"":jd(today)-jd(pd)), nrows, nmaj }')
                IFS='|' read -r e_ok e_n e_n0 e_sup e_lv e_ld e_r e_pl e_pd e_age e_nr e_nm <<EOF
$out
EOF
                # awk 출력 검증: 숫자·버전·날짜 형식이 아니면 사용하지 않음
                for x in "$e_ok" "$e_n" "$e_n0" "$e_nr" "$e_nm"; do case "$x" in ''|*[!0-9]*) bad=1 ;; esac; done
                for x in "$e_lv" "$e_pl"; do case "$x" in *[!0-9.]*) bad=1 ;; esac; done
                for x in "$e_ld" "$e_pd" "$e_age"; do case "$x" in *[!0-9]*) bad=1 ;; esac; done
                case "$e_sup" in ''|*[!0-9,]*) bad=1 ;; esac
                case "$e_r" in G|B|M|N) ;; *) bad=1 ;; esac
                if [ "$bad" -ne 0 ]; then why="목록 해석 결과 검증 실패"
                elif [ "$e_ok" != 1 ]; then why="목록 내용 이상 (macOS 릴리스 ${e_nr}개, 주요 버전 ${e_nm}종, 최신 ${e_n} - 오래된 페이지이거나 형식 변경)"
                else
                    fd="${e_n0:0:4}-${e_n0:4:2}-${e_n0:6:2}"; ld=""; [ -n "$e_ld" ] && ld=" ${e_ld:0:4}-${e_ld:4:2}-${e_ld:6:2}"
                    case "$e_r" in
                        G) EOS_RES="양호"; EOS_DESC="macOS ${OS_VER} - Apple 보안 업데이트 지원 중 (지원 주요 버전: ${e_sup}, 해당 버전 최근 보안 릴리스 ${e_lv:-미확인}${ld}) [Apple 보안 릴리스 목록 support.apple.com/100100 조회]" ;;
                        N) EOS_RES="양호"; EOS_DESC="macOS ${OS_VER} - 보안 릴리스 목록의 최신 주요 버전(${e_n})보다 높은 버전(베타·목록 지연 가능)으로 지원 중으로 간주 [Apple 보안 릴리스 목록 support.apple.com/100100 조회]" ;;
                        M) EOS_RES="수동확인"; EOS_DESC="macOS ${OS_VER} - macOS ${e_n} 출시(${fd}) 직후 전환기: 최종 보안 릴리스(${e_lv}${ld})가 출시일과 같아 지원 종료 여부 미확정 (${grace}일 후 재확인) - Apple 보안 릴리스 확인 [support.apple.com/100100 조회]" ;;
                        *) EOS_RES="취약"; EOS_DESC="macOS ${OS_VER} - Apple 보안 업데이트 지원 종료 (최종 보안 릴리스 ${e_lv:-최근 3년 목록에 없음}${ld}, macOS ${e_n} 최초 출시(${fd}) 이후 추가 보안 업데이트 없음) - 지원 버전(${e_sup})으로 업그레이드 필요 [Apple 보안 릴리스 목록 support.apple.com/100100 조회]" ;;
                    esac
                    if [ -n "$e_pl" ]; then PATCH_LATEST="$e_pl"; PATCH_DATE="${e_pd:0:4}-${e_pd:4:2}-${e_pd:6:2}"; PATCH_AGE="$e_age"; fi
                    EOS_EVD="${EOS_EVD}
[판정 입력] 주요 버전=${major} 현재=${OS_VER} 최신 주요 버전=${e_n}(최초 출시 ${fd}) 지원 주요 버전=${e_sup} 유예일=${grace} 같은 주요 버전의 미적용 보안 릴리스=${e_pl:-없음}${e_pd:+ (가장 오래된 배포일 ${PATCH_DATE}, ${e_age}일 경과)}"
                    return 0
                fi
            fi
        fi
    fi
    # ── 오프라인 추정: Apple 은 매년 9월 새 주요 버전 출시(26=2025, 27=2026 …) 후 최신 3개 주요 버전만 보안 업데이트 ──
    local y m n list sup oldest k
    y=$(date +%Y); m=$(date +%m); m=${m#0}
    EOS_EVD="${EOS_EVD:+${EOS_EVD}
}[오프라인 추정] 사유: ${why}. 시스템 날짜 ${y}-${m}, 주요 버전=${major} (연도 기반 추정 - Apple 서버 조회 불가)"
    if [ "$y" -lt 2025 ] 2>/dev/null; then
        EOS_RES="수동확인"; EOS_DESC="macOS ${OS_VER} - 지원 여부 추정 불가 (${why}; 시스템 날짜 ${y} 가 비정상) - support.apple.com/100100 에서 직접 확인"; return 0
    fi
    n=$((y - 2000)); [ "$m" -ge 9 ] && n=$((n + 1))
    list="11 12 13 14 15"; k=26; while [ $k -le $n ]; do list="$list $k"; k=$((k+1)); done
    sup=$(echo $list | awk '{print $(NF-2), $(NF-1), $NF}'); oldest=${sup%% *}
    if [ "$major" -gt "$n" ] 2>/dev/null || echo " $sup " | grep -q " $major "; then
        if [ "$major" = "$oldest" ] && [ "$m" -ge 9 ] && [ "$m" -le 10 ]; then
            EOS_RES="수동확인"; EOS_DESC="macOS ${OS_VER} - 신규 주요 버전 출시 전환기(지원 종료 가능) - Apple 보안 릴리스 확인 필요 (${why} → 연도 기반 추정, 추정 지원 버전: ${sup// /·})"
        else
            EOS_RES="양호"; EOS_DESC="macOS ${OS_VER} - 보안 업데이트 지원 버전으로 추정 (${why} → 연도 기반 추정, 추정 지원 버전: ${sup// /·}; support.apple.com/100100 확인 권장)"
        fi
    else
        EOS_RES="취약"; EOS_DESC="macOS ${OS_VER} - 보안 업데이트 지원 종료 버전으로 추정 (${why} → 연도 기반 추정, 추정 지원 버전: ${sup// /·}; support.apple.com/100100 확인 권장)"
    fi
    return 0
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
    g=$(curl -s -f -m 2 --connect-timeout 2 -H "Metadata-Flavor: Google" "$base/computeMetadata/v1/instance/id" 2>/dev/null)
    # GCP 인스턴스 ID 는 숫자 — 프록시·캡티브 포털의 오류 문구를 GCP 로 오인하지 않도록 숫자만 인정
    if [ -n "$g" ] && ! echo "$g" | grep -q '[^0-9]'; then
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
    # 결과는 항목당 정확히 1줄 — 명령 출력(csrutil·fdesetup 등 여러 줄)이 근거에 섞여도 줄바꿈·탭을 공백으로 접는다
    local _m _r
    _m=$(printf '%s' "$1" | tr '\r\n\t' '   ' | sed 's/  */ /g;s/ $//')
    echo "$_m"
    _r="${_m#*|}"; _r="${_r%%|*}"
    case "$_r" in
    양호)     _CP=$((_CP+1)) ;;
    취약)     _CF=$((_CF+1)) ;;
    수동확인) _CM=$((_CM+1)) ;;
    점검불가) _CU=$((_CU+1)) ;;
    N-A)      _CN=$((_CN+1)) ;;
    esac
    printf '[판정] %s\n\n' "$_m" >> "$_EVD"
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
# 암호 정책을 읽었는가: root 이고 pwpolicy/profiles 가 응답했거나, 비root 라도 policyAttribute 가 실제로 조회된 경우
POL_READ=0
if echo "$POL$POLU" | grep -q "policyAttribute"; then POL_READ=1
elif [ "$IS_ROOT" -eq 1 ] && [ -n "$POL$POLU$PROF" ]; then POL_READ=1; fi
# sysonoff <systemsetup 출력> <라벨>: on / off / unk (권한·전체 디스크 접근 부족으로 값을 못 읽으면 unk)
sysonoff() {
    if echo "$1" | grep -qiE "$2:[[:space:]]*On"; then echo on
    elif echo "$1" | grep -qiE "$2:[[:space:]]*Off"; then echo off
    else echo unk; fi
}

# ── PC-01 비밀번호의 주기적 변경 (최대 사용 기간 90일 이하) ──
evd "PC-01" "pwpolicy getaccountpolicies"
[ -n "$TUSER" ] && evd "PC-01" "pwpolicy -u '$TUSER' getaccountpolicies"
evd "PC-01" "profiles -P -o stdout"
days=$(xint policyAttributeExpiresEveryNDays "$POL$POLU")
[ -z "$days" ] && { m=$(xint maxMinutesUntilChangePassword "$POL$POLU"); [ -n "$m" ] && days=$((m/1440)); }
[ -z "$days" ] && days=$(echo "$PROF" | grep -i maxPINAgeInDays | grep -oE '[0-9]+' | awk 'NR==1')
evq "PC-01" "정책에서 추출한 최대 사용 기간(일) — policyParameters 의 값 요소만 사용" "days=${days:-미설정}"
if [ "$POL_READ" -eq 0 ]; then result "PC-01|점검불가|암호 정책 조회 불가(pwpolicy/profiles 결과 없음): ${NEED_ROOT}"
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
if [ "$POL_READ" -eq 0 ]; then result "PC-02|점검불가|암호 정책 조회 불가(pwpolicy/profiles 결과 없음): ${NEED_ROOT}"
elif [ "${ml:-0}" -ge 8 ] && [ "$cls" -ge 3 ]; then result "PC-02|양호|암호 정책: 최소 ${ml}자, 영문·숫자·특수문자 요구"
else result "PC-02|취약|암호 복잡성 정책 미흡 (최소 길이=${ml:-미설정}, 요구 문자 종류=${cls}종; 기준: 8자 이상·영문·숫자·특수문자)"; fi

# ── PC-03 복구 콘솔 자동 로그온 — Windows 기능 ──
evd "PC-03" "fdesetup status"
evd "PC-03" "firmwarepasswd -check"
result "PC-03|N-A|가이드 점검 대상(Windows 10, Windows 11) 아님 - macOS 는 Windows 복구 콘솔 기능 없음 (참고: FileVault/복구 잠금 상태 증적 확인)"

# ── PC-04 공유 폴더 ──
evd "PC-04" "sharing -l"
evd "PC-04" "launchctl print system/com.apple.smbd"
evd "PC-04" "launchctl print system/com.apple.AppleFileServer"
evd "PC-04" "netstat -an -p tcp"
evd "PC-04" "defaults read /Library/Preferences/SystemConfiguration/com.apple.smb.server"
evd "PC-04" "nc -z -w 1 127.0.0.1 445 && echo 'port 445 open' || echo 'port 445 closed'; nc -z -w 1 127.0.0.1 548 && echo 'port 548 open' || echo 'port 548 closed'"
SHARING=$(sharing -l 2>/dev/null)
shares=$(echo "$SHARING" | awk -F':[ \t]*' '/^name:/{print $2}' | tr '\n' ',' | sed 's/,$//')
# 공유별 게스트 접근: 'List of Share Points' 블록의 smb/afp 'guest access: 1'
gshare=$(echo "$SHARING" | awk -F':[ \t]*' '/^name:/{n=$2} /guest access/{gsub(/[ \t]/,"",$2); if($2=="1") print n}' | sort -u | tr '\n' ',' | sed 's/,$//')
smb=$(svc_state com.apple.smbd 445)
afp=$(svc_state com.apple.AppleFileServer 548)
guest=$(defaults read /Library/Preferences/SystemConfiguration/com.apple.smb.server AllowGuestAccess 2>/dev/null)
fson=""; [ "$smb" = on ] && fson="${fson} SMB"; [ "$afp" = on ] && fson="${fson} AFP"
if [ -n "$fson" ]; then
    if [ -n "$gshare" ]; then result "PC-04|취약|파일 공유(${fson# }) 활성 + 공유 폴더 게스트 접근 허용 (비밀번호 없이 접근): ${gshare}"
    elif [ "$guest" = "1" ]; then result "PC-04|취약|파일 공유(${fson# }) 활성 + 게스트 접근 허용 (AllowGuestAccess=1), 공유: ${shares:-목록 조회 불가}"
    elif [ "$IS_ROOT" -eq 1 ] || [ -n "$SHARING" ]; then result "PC-04|수동확인|파일 공유 사용(${fson# }): ${shares:-공유 목록 없음} - 불필요 공유 여부·접근 권한 확인"
    else result "PC-04|점검불가|파일 공유(${fson# }) 활성이나 공유 폴더 목록(sharing -l)·공유별 게스트 설정 조회 불가: ${NEED_ROOT} (AllowGuestAccess=${guest:-미설정})"; fi
elif [ "$smb" = "off" ] && [ "$afp" = "off" ]; then
    # 공유 폴더가 정의돼 있어도 파일 공유 서비스(SMB/AFP)가 꺼져 있으면 외부 접근 불가 → 양호
    result "PC-04|양호|파일 공유 서비스(SMB/AFP) 비활성 (system 도메인 미적재, 포트 445/548 닫힘)$([ -n "$shares" ] && echo " - 정의된 공유 ${shares} 는 서비스가 꺼져 있어 접근 불가")$({ [ -n "$gshare" ] || [ "$guest" = "1" ]; } && echo ", 게스트 허용 설정 존재(${gshare:-AllowGuestAccess=1}) - 재활성 시 취약")"
elif [ "$IS_ROOT" -eq 1 ]; then result "PC-04|점검불가|SMB/AFP 서비스 상태(launchctl)를 조회하지 못함 (launchctl 명령 없음 또는 오류, 포트 445/548 닫힘)"
else
    result "PC-04|점검불가|공유 폴더 목록(sharing -l)·SMB 서비스 상태 조회 불가: ${NEED_ROOT} (포트 445/548 닫힘, AllowGuestAccess=${guest:-미설정})"
fi

# ── PC-05 불필요한 서비스 (원격 로그인·원격 Apple 이벤트·인터넷 공유·원격 관리 등) ──
evd "PC-05" "systemsetup -getremotelogin"
evd "PC-05" "systemsetup -getremoteappleevents"
evd "PC-05" "launchctl list"
evd "PC-05" "cupsctl"
bad=""; unk05=0; why05=""
if [ "$IS_ROOT" -eq 1 ]; then
    rl=$(systemsetup -getremotelogin 2>&1); ra=$(systemsetup -getremoteappleevents 2>&1)
    st=$(sysonoff "$rl" "Remote Login")
    if [ "$st" = "unk" ] && { launchctl list 2>/dev/null | awk '$3=="com.openssh.sshd"{f=1} END{exit f?0:1}' || port_open 22; }; then st=on; fi
    [ "$st" = "on" ] && bad="${bad} 원격 로그인(SSH)"
    [ "$st" = "unk" ] && { unk05=1; why05="systemsetup -getremotelogin 판독 불가: ${rl}"; }
    st=$(sysonoff "$ra" "Remote Apple Events")
    [ "$st" = "on" ] && bad="${bad} 원격 Apple 이벤트"
    [ "$st" = "unk" ] && { unk05=1; why05="${why05} / systemsetup -getremoteappleevents 판독 불가: ${ra}"; }
    have launchctl || { unk05=1; why05="${why05} / launchctl 명령 없음"; }
    launchctl list 2>/dev/null | awk '$3=="com.apple.InternetSharing"{f=1} END{exit f?0:1}' && bad="${bad} 인터넷 공유"
    launchctl list 2>/dev/null | awk '$3 ~ /^com\.apple\.(tftpd|ftpd|telnetd|bootpd)$/{f=1} END{exit f?0:1}' && bad="${bad} TFTP/FTP/Telnet/BOOTP"
else
    # 비root: systemsetup 은 관리자 권한 필요 → launchd system 도메인 적재·포트 LISTEN 으로 판정 (SYSVIS=0 이면 점검불가)
    # 인터넷 공유 데몬(com.apple.NetworkSharing)은 꺼져 있어도 system 도메인에 항상 적재(not running)되므로 적재 여부가 아니라 NAT 설정·프로세스로 판정
    nat=$(defaults read /Library/Preferences/SystemConfiguration/com.apple.nat NAT 2>/dev/null | awk '/Enabled/{gsub(/[ ;]/,"",$3); print $3; exit}')
    evq "PC-05" "인터넷 공유 (com.apple.nat NAT Enabled / InternetSharing 프로세스)" "NAT Enabled=${nat:-미설정} 프로세스=$(ps -axo comm 2>/dev/null | awk -F/ '$NF=="InternetSharing"{print "실행"; exit}')"
    { [ "$nat" = "1" ] || ps -axo comm 2>/dev/null | awk -F/ '$NF=="InternetSharing"{f=1} END{exit f?0:1}'; } && bad="${bad} 인터넷 공유"
    for entry in "com.openssh.sshd:22:원격 로그인(SSH)" "com.apple.AEServer:3031:원격 Apple 이벤트" \
                 "com.apple.tftpd:69:TFTP" "com.apple.ftpd:21:FTP" "com.apple.telnetd:23:Telnet" "com.apple.bootpd::BOOTP"; do
        lb=${entry%%:*}; rest=${entry#*:}; pt=${rest%%:*}; nm=${rest#*:}
        st=$(svc_state "$lb" "$pt")
        evq "PC-05" "서비스 상태 (system 도메인 적재 / 포트 ${pt:-없음} LISTEN, 비root SYSVIS=${SYSVIS})" "$lb = $st"
        case "$st" in on) case "$bad" in *"$nm"*) ;; *) bad="${bad} ${nm}" ;; esac ;; unk) unk05=1 ;; esac
    done
fi
cups=$(cupsctl 2>/dev/null | grep -c '_share_printers=1')
[ "${cups:-0}" -gt 0 ] && bad="${bad} 프린터 공유"
if [ -n "$bad" ]; then result "PC-05|취약|불필요한 서비스 사용:${bad} (업무상 필요 시 예외)"
elif [ "$unk05" -eq 1 ] && [ "$IS_ROOT" -eq 1 ]; then result "PC-05|점검불가|원격 로그인/Apple 이벤트 설정 조회 불가: ${why05} (터미널에 전체 디스크 접근 권한이 필요할 수 있음)"
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

# ── PC-10 주기적 보안 패치 (자동 업데이트 + 마지막 설치일 90일 이내 + 미적용 보안 릴리스) ──
evd "PC-10" "defaults read /Library/Preferences/com.apple.SoftwareUpdate"
evd "PC-10" "softwareupdate --schedule"
evd "PC-10" "softwareupdate --history"
ac=$(defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled 2>/dev/null)
cr=$(defaults read /Library/Preferences/com.apple.SoftwareUpdate CriticalUpdateInstall 2>/dev/null)
# 키 미설정 = macOS 기본값(자동 확인 켜짐) — softwareupdate --schedule 로 대조
if [ -z "$ac" ] && softwareupdate --schedule 2>&1 | grep -qiE 'turned off|check is off'; then ac=0; ac_src=" (키 없음, softwareupdate --schedule 이 꺼짐으로 응답)"; else ac_src=""; fi
last=$(softwareupdate --history 2>/dev/null | awk 'NR>2{
    if (match($0, /[0-9][0-9][0-9][0-9][.\/-] ?[0-9][0-9]?[.\/-] ?[0-9][0-9]?/)) { d=substr($0,RSTART,RLENGTH); gsub(/ /,"",d); split(d,a,/[.\/-]/); printf "%04d-%02d-%02d\n", a[1],a[2],a[3] }
    else if (match($0, /[0-9][0-9]?\/[0-9][0-9]?\/[0-9][0-9][0-9][0-9]/)) { split(substr($0,RSTART,RLENGTH),a,"/"); printf "%04d-%02d-%02d\n", a[3],a[1],a[2] }
}' | sort | tail -1)
age=""
if [ -n "$last" ]; then
    le=$(date -j -f '%Y-%m-%d' "$last" '+%s' 2>/dev/null)
    [ -n "$le" ] && age=$(( ($(date '+%s') - le) / 86400 ))
fi
evq "PC-10" "자동 업데이트 설정 / 마지막 설치일(softwareupdate --history) / 경과일" "AutomaticCheckEnabled=${ac:-미설정(기본 1)}${ac_src} CriticalUpdateInstall=${cr:-미설정(기본 1)} last=${last:-확인 불가} age_days=${age:-확인 불가}"
mac_eos_check   # PC-10(보안 릴리스 적용)·PC-11(지원 종료) 공용 — Apple 보안 릴리스 목록 조회
evq "PC-10" "Apple 보안 릴리스 목록 조회·해석 원자료 (PC-10 미적용 보안 릴리스 / PC-11 지원 종료 공용)" "$EOS_EVD"
GRACE=${PATCH_GRACE_DAYS:-30}; case "$GRACE" in ''|*[!0-9]*) GRACE=30 ;; esac
pmiss=""; [ -n "$PATCH_LATEST" ] && pmiss="미적용 보안 릴리스: ${OS_VER} → ${PATCH_LATEST} (가장 오래된 미적용 배포 ${PATCH_DATE}, ${PATCH_AGE}일 경과)"
if [ -n "$PATCH_LATEST" ] && [ "${PATCH_AGE:-0}" -gt "$GRACE" ] 2>/dev/null; then result "PC-10|취약|${pmiss} - ${GRACE}일 이상 보안 패치 미적용 (AutomaticCheck=${ac:-기본 1}, Critical=${cr:-기본 1}, 최근 설치 ${last:-확인 불가})"
elif ! have defaults; then result "PC-10|점검불가|defaults 명령이 없어 자동 업데이트 설정을 읽을 수 없음"
elif [ "$ac" = "0" ] || [ "$cr" = "0" ]; then result "PC-10|취약|자동 업데이트 비활성 (AutomaticCheckEnabled=${ac:-기본}${ac_src}, CriticalUpdateInstall=${cr:-기본}) - 최근 설치 ${last:-확인 불가}"
elif [ -n "$age" ] && [ "$age" -gt 90 ]; then result "PC-10|취약|최근 업데이트 설치일 ${last} 로부터 ${age}일 경과 (90일 초과; 자동 업데이트 설정은 활성)"
else result "PC-10|양호|자동 업데이트·보안 응답 설치 활성 (AutomaticCheck=${ac:-기본 1}, Critical=${cr:-기본 1}), 최근 설치 ${last:-확인 불가}${age:+ (${age}일 전)}$([ -n "$pmiss" ] && echo ", ${pmiss}(유예 ${GRACE}일 이내)") - 내부 관리 절차는 인터뷰 확인"; fi

# ── PC-11 지원이 종료되지 않은 OS (Windows Build → macOS 버전) ──
evd "PC-11" "sw_vers"
# Apple 은 macOS 지원 종료일을 공지하지 않음 → 보안 릴리스 페이지에서 '최신 주요 버전 출시 이후에도 보안 업데이트를 받는지'로 판정 (mac_eos_check, PC-10 에서 조회)
evq "PC-11" "Apple 보안 릴리스 목록 조회·해석 원자료 (결과: ${EOS_RES})" "$EOS_EVD"
result "PC-11|${EOS_RES}|${EOS_DESC}"

# ── PC-12 자동 로그인 ──
evd "PC-12" "defaults read /Library/Preferences/com.apple.loginwindow autoLoginUser"
evd "PC-12" "ls -l /etc/kcpassword"
al=$(defaults read /Library/Preferences/com.apple.loginwindow autoLoginUser 2>/dev/null)
if ! have defaults; then result "PC-12|점검불가|defaults 명령이 없어 자동 로그인 설정을 읽을 수 없음"
elif [ -n "$al" ] || [ -f /etc/kcpassword ]; then result "PC-12|취약|자동 로그인 활성 (autoLoginUser=${al:-설정됨}, kcpassword $([ -f /etc/kcpassword ] && echo 존재 || echo 없음))"
else result "PC-12|양호|자동 로그인 비활성"; fi

# ── PC-13 / PC-14 백신 설치·업데이트 / 실시간 감시 ──
av_scan
evd "PC-13" "find $AV_DIRS -maxdepth 2 -name '*.app'"
evd "PC-13" "ps -axo comm"
evd "PC-13" "system_profiler SPInstallHistoryDataType"
evd "PC-14" "ps -axo comm"
evd "PC-14" "find $AV_DIRS -maxdepth 2 -name '*.app'"
evq "PC-13" "백신 판별 결과 (앱 이름·실행 파일 이름만으로 판별, 경로 제외 - /Applications/AhnLab/ASTx 는 안랩 세이프 트랜잭션(금융 보안 모듈)으로 백신 아님)" "앱=${AV_APPS:-없음}" "앱 패턴=${AV_APP_RE}"
evq "PC-14" "백신 실행 프로세스 판별 결과 (실행 파일 이름만 사용)" "프로세스=${AV_PROCS:-없음}" "프로세스 패턴=${AV_PROC_RE}"
av="$AV_APPS"; avp="$AV_PROCS"
xp=$(system_profiler SPInstallHistoryDataType 2>/dev/null | grep -A4 'XProtectPlistConfigData' | grep -i 'Install Date' | tail -1 | sed 's/.*: //')
if ! have find; then
    result "PC-13|점검불가|find 명령이 없어 설치된 백신 앱을 조사할 수 없음"
    result "PC-14|점검불가|find 명령이 없어 설치된 백신 앱을 조사할 수 없음 - 백신 실시간 감시 수동 확인"
elif [ -n "$av" ]; then
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
if ! have defaults; then
    result "PC-16|점검불가|defaults 명령이 없어 화면보호기 설정을 읽을 수 없음"
elif [ "$IS_ROOT" -eq 1 ] && [ -z "$TUSER" ]; then
    result "PC-16|점검불가|콘솔에 로그인한 사용자가 없어 사용자 화면 잠금 설정을 읽을 수 없음"
else
    idle=$(urd -currentHost read com.apple.screensaver idleTime)
    askpw=$(urd read com.apple.screensaver askForPassword)
    askdl=$(urd read com.apple.screensaver askForPasswordDelay)
    lkst=$(urun sysadminctl -screenLock status | sed 's/^.*\] //')   # 'YYYY-MM-DD hh:mm:ss sysadminctl[pid] ' 로그 머리 제거
    ds_all=$(pmset -g custom 2>/dev/null | awk '/displaysleep/{print $2}')
    dsl=""
    for v in $ds_all; do
        if [ "$v" = "0" ]; then dsl=0; break; fi
        { [ -z "$dsl" ] || [ "$v" -gt "$dsl" ]; } 2>/dev/null && dsl=$v
    done
    t=${idle:-0}; [ "$t" -eq 0 ] 2>/dev/null && [ -n "$dsl" ] && [ "$dsl" -gt 0 ] && t=$((dsl*60))
    # sysadminctl -screenLock 을 우선(macOS 13+ 는 askForPassword 키가 비었거나 이전 값이 남을 수 있음), 해석 불가일 때만 키 사용
    pwok=0
    if echo "$lkst" | grep -qiE 'immediate|delay is [0-9]+|[0-9]+ (seconds|minutes)'; then pwok=1
    elif echo "$lkst" | grep -qiwE 'off|disabled'; then pwok=0
    elif [ "$askpw" = "1" ]; then pwok=1; fi
    evq "PC-16" "판정에 쓴 값 (사용자 ${TUSER}) idleTime(초) / askForPassword / askForPasswordDelay / sysadminctl -screenLock / displaysleep(분, 배터리·AC 최악)" "idleTime=${idle:-미설정} askForPassword=${askpw:-미설정} askForPasswordDelay=${askdl:-미설정} screenLock=[${lkst}] displaysleep=${dsl:-미확인} → 유효 대기=${t}초 암호요구=${pwok}"
    if [ "$t" -gt 0 ] 2>/dev/null && [ "$t" -le 600 ] && [ "$pwok" -eq 1 ]; then result "PC-16|양호|화면보호기/디스플레이 끄기 $((t/60))분, 해제 시 암호 요구 (사용자 ${TUSER}, askForPassword=${askpw:-미설정}, delay=${askdl:-미설정}초)"
    else result "PC-16|취약|화면보호기 설정 미흡 (대기=${idle:-미설정}초, 디스플레이 끄기=${dsl:-미확인}분, 암호 요구=${askpw:-미설정}/${lkst:-미확인}; 기준: 10분 이하 + 암호)"; fi
fi

# ── PC-17 이동식 미디어 자동 실행 방지 ──
evd "PC-17" "urd read com.apple.digihub"
if ! have defaults; then
    result "PC-17|점검불가|defaults 명령이 없어 디스크 삽입 동작 설정을 읽을 수 없음"
elif [ "$IS_ROOT" -eq 1 ] && [ -z "$TUSER" ]; then
    result "PC-17|점검불가|콘솔에 로그인한 사용자가 없어 디스크 삽입 동작(com.apple.digihub) 설정을 읽을 수 없음"
else
    dh=$(urd read com.apple.digihub | grep -E 'action' | grep -vE '= 1;')
    if [ -n "$dh" ]; then result "PC-17|수동확인|CD/DVD 삽입 시 동작 설정 존재(사용자 ${TUSER}): $(echo $dh) - 자동 실행 여부 확인"
    else result "PC-17|양호|macOS 는 이동식 미디어 자동 실행(AutoRun) 기능 없음 (digihub 동작 설정 없음) - 이동식 미디어 관리 절차는 인터뷰 확인"; fi
fi

# ── PC-18 원격 지원(화면 공유·원격 관리) 금지 ──
evd "PC-18" "launchctl print system/com.apple.screensharing"
evd "PC-18" "netstat -an -p tcp"
evd "PC-18" "ps -axo comm"
evd "PC-18" "ls -l /Library/PrivilegedHelperTools 2>/dev/null | grep -i chromoting; launchctl print system 2>/dev/null | grep -i chromoting"
evd "PC-18" "nc -z -w 1 127.0.0.1 5900 && echo 'port 5900 open' || echo 'port 5900 closed'; nc -z -w 1 127.0.0.1 3283 && echo 'port 3283 open' || echo 'port 3283 closed'"
rs=""; unk18=0
case "$(svc_state com.apple.screensharing 5900)" in on) rs="${rs} 화면 공유" ;; unk) unk18=1 ;; esac
case "$(ard_state)" in on) rs="${rs} 원격 관리(ARD)" ;; unk) unk18=1 ;; esac
tp=$(remote_tools)
[ -n "$tp" ] && rs="${rs} 원격 지원 프로그램(${tp})"
if [ -n "$rs" ]; then result "PC-18|취약|원격 지원 기능 사용:${rs}"
elif [ "$unk18" -eq 1 ] && [ "$IS_ROOT" -eq 1 ]; then result "PC-18|점검불가|화면 공유 서비스 적재 여부 조회 불가: launchctl 명령 없음/조회 실패"
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
