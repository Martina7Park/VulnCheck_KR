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
#   macOS 12 이상 (bash 3.2 호환) - PC-07 은 Apple 보안 릴리스 목록(support.apple.com/100100)을 조회해 지원 종료(EoS)·미적용 보안 패치 판정
#   (인터넷 불가 시 연도 기반 추정, MAC_EOS_OFFLINE=1 로 조회 생략, PATCH_GRACE_DAYS=30 패치 유예일)
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
evd "PC-02" "profiles -P -o stdout"
pw_policy=$(pwpolicy getaccountpolicies 2>/dev/null); pw_rc=$?
prof=""; [ "$IS_ROOT" -eq 1 ] && prof=$(profiles -P -o stdout 2>/dev/null)
# 기준(PC-02 개선방안): 최소 길이 8자 이상, 최대 사용기간 90일 이하
# 최소 길이: policyContent "matches '.{8,}+'" 또는 policyParameters <key>minimumLength</key><integer>N, 구성 프로파일 minLength
min_len=$(echo "$pw_policy" | grep -oE "matches '\.\{[0-9]+," | grep -oE '[0-9]+' | awk 'NR==1')
[ -z "$min_len" ] && min_len=$(echo "$pw_policy" | tr -d '\n\t ' | grep -oE '<key>minimumLength</key><integer>[0-9]+' | grep -oE '[0-9]+$' | awk 'NR==1')
[ -z "$min_len" ] && min_len=$(echo "$prof" | grep -iE '(^|[[:space:]])minLength[[:space:]]*=' | grep -oE '[0-9]+' | sort -n | tail -1)
# 만료: policyParameters <key>policyAttributeExpiresEveryNDays</key><integer>N (분 단위 ...EveryNMinutes 대비), 구성 프로파일 maxPINAgeInDays
exp_days=$(echo "$pw_policy" | tr -d '\n\t ' | grep -oE '<key>policyAttributeExpiresEveryNDays</key><integer>[0-9]+' | grep -oE '[0-9]+$' | awk 'NR==1')
[ -z "$exp_days" ] && { m=$(echo "$pw_policy" | tr -d '\n\t ' | grep -oE '<key>policyAttributeExpiresEveryNMinutes</key><integer>[0-9]+' | grep -oE '[0-9]+$' | awk 'NR==1'); [ -n "$m" ] && exp_days=$(( m / 1440 )); }
[ -z "$exp_days" ] && exp_days=$(echo "$prof" | grep -iE 'maxPINAgeInDays' | grep -oE '[0-9]+' | awk 'NR==1')
if echo "$pw_policy" | grep -q "policyAttribute" || [ -n "$min_len" ] || [ -n "$exp_days" ]; then
    evq "PC-02" "pwpolicy·구성 프로파일에서 추출한 값 (최소 길이 / 만료 일수)" "min_len=${min_len:-미확인} exp_days=${exp_days:-미설정}"
    desc="최소 길이=${min_len:-미확인}자, 만료=${exp_days:-미설정}일"
    if [ -n "$min_len" ] && [ "$min_len" -ge 8 ] && [ -n "$exp_days" ] && [ "$exp_days" -gt 0 ] && [ "$exp_days" -le 90 ]; then
        result "PC-02|양호|패스워드 정책 적용: ${desc}"
    elif { [ -n "$min_len" ] && [ "$min_len" -lt 8 ]; } || { [ -n "$exp_days" ] && [ "$exp_days" -gt 90 ]; }; then
        result "PC-02|취약|패스워드 정책 기준 미달: ${desc} (8자 이상, 90일 이하 필요)"
    else
        result "PC-02|수동확인|패스워드 정책 일부 확인 불가: ${desc} — MDM/프로파일 정책 확인"
    fi
elif [ "$IS_ROOT" -eq 1 ] && [ "$pw_rc" -eq 0 ]; then
    evq "PC-02" "판정에 사용한 값" "pwpolicy 종료코드=${pw_rc} 정책(policyAttribute) 없음, 구성 프로파일 암호 정책 없음"
    result "PC-02|취약|패스워드 정책 미설정 (pwpolicy 계정 정책·구성 프로파일에 암호 길이/만료 정책 없음)"
else
    if [ "$IS_ROOT" -eq 1 ]; then
        result "PC-02|점검불가|패스워드 정책(pwpolicy getaccountpolicies) 조회 실패 (종료코드 ${pw_rc}) - MDM/프로파일 기반 정책이면 수동 확인"
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
if ! have defaults; then
    result "PC-03|점검불가|defaults 명령이 없어 화면 잠금 설정을 읽을 수 없음"
elif [ "$IS_ROOT" -eq 1 ] && [ -z "$TUSER" ]; then
    result "PC-03|점검불가|콘솔에 로그인한 사용자가 없어 사용자 화면 잠금 설정을 읽을 수 없음 (SUDO_USER·콘솔 사용자 없음)"
else
    ask_key=$(urd read com.apple.screensaver askForPassword)
    # macOS 13+ 는 설정 앱 '잠금 화면' 값을 askForPassword 키로 저장하지 않아 키가 비었거나 이전 버전 값이 남아 있을 수 있음
    #  → sysadminctl -screenLock status(대상 사용자 권한) 를 우선하고, 해석할 수 없을 때만 키를 사용 (둘이 다르면 sysadminctl 기준)
    sa_lock=$(if [ "$IS_ROOT" -eq 1 ]; then sudo -n -H -u "$TUSER" sysadminctl -screenLock status 2>&1; else sysadminctl -screenLock status 2>&1; fi)
    ask_pw=""; lk_src=""
    if echo "$sa_lock" | grep -qiE 'immediate|delay is [0-9]+'; then ask_pw=1; lk_src="sysadminctl"
    elif echo "$sa_lock" | grep -qiwE 'off|disabled'; then ask_pw=0; lk_src="sysadminctl"
    elif [ -n "$ask_key" ]; then ask_pw="$ask_key"; lk_src="askForPassword 키"; fi
    lk_note=""; [ "$lk_src" = "sysadminctl" ] && [ -n "$ask_key" ] && [ "$ask_key" != "$ask_pw" ] && lk_note=" (askForPassword 키=${ask_key} 와 불일치 - sysadminctl 기준)"
    ask_delay=$(urd read com.apple.screensaver askForPasswordDelay)
    ss_idle=$(urd -currentHost read com.apple.screensaver idleTime)
    # 배터리·AC 모두 확인: 하나라도 0(끄지 않음)이면 0, 아니면 최댓값
    ds_all=$(pmset -g custom 2>/dev/null | awk '/displaysleep/{print $2}')
    display_sleep=""
    for v in $ds_all; do
        if [ "$v" = "0" ]; then display_sleep=0; break; fi
        { [ -z "$display_sleep" ] || [ "$v" -gt "$display_sleep" ]; } 2>/dev/null && display_sleep=$v
    done
    evq "PC-03" "판정에 사용한 값 (대상 사용자=${TUSER:-현재 사용자}) 암호 요구(${lk_src:-판독 불가}) / askForPasswordDelay / screensaver idleTime(초) / displaysleep(분, 배터리·AC 중 최악)" "sysadminctl=[${sa_lock}] askForPassword키=${ask_key:-미설정} → 암호요구=${ask_pw:-미확인}${lk_note}" "askForPasswordDelay=${ask_delay:-미설정} idleTime=${ss_idle:-미설정} displaysleep=${display_sleep:-미확인}"
    ss_ok=0; { [ -n "$ss_idle" ] && [ "$ss_idle" -gt 0 ] && [ "$ss_idle" -le 600 ]; } 2>/dev/null && ss_ok=1
    ds_ok=0; { [ -n "$display_sleep" ] && [ "$display_sleep" -gt 0 ] && [ "$display_sleep" -le 10 ]; } 2>/dev/null && ds_ok=1
    if [ "$ask_pw" = "1" ]; then
        if [ "$ss_ok" -eq 1 ] || [ "$ds_ok" -eq 1 ]; then
            result "PC-03|양호|화면잠금 암호 활성 (${lk_src}, 사용자 ${TUSER:-현재}), 화면보호기=${ss_idle:-미설정}초, 디스플레이절전=${display_sleep:-미확인}분, 암호지연=${ask_delay:-0}초${lk_note}"
        else
            result "PC-03|취약|화면잠금 암호 활성이나 화면보호기(${ss_idle:-미설정}초)·디스플레이절전(${display_sleep:-미확인}분) 모두 10분 이하 아님${lk_note}"
        fi
    else
        result "PC-03|취약|화면잠금 시 암호 요구 비활성 (${lk_src:-askForPassword}=${ask_pw:-미설정}, 사용자 ${TUSER:-현재})${lk_note}"
    fi
fi

# ── PC-04: 공유폴더 (파일 공유 서비스) ──────────────────────────────
evd "PC-04" "sharing -l"
evd "PC-04" "launchctl print system/com.apple.smbd"
evd "PC-04" "launchctl print system/com.apple.AppleFileServer"
evd "PC-04" "netstat -an -p tcp"
evd "PC-04" "nc -z -w 1 127.0.0.1 445 && echo 'port 445 open' || echo 'port 445 closed'; nc -z -w 1 127.0.0.1 548 && echo 'port 548 open' || echo 'port 548 closed'"
evd "PC-04" "defaults read /Library/Preferences/SystemConfiguration/com.apple.smb.server"
smb=$(svc_state com.apple.smbd 445)
afp=$(svc_state com.apple.AppleFileServer 548)
shared_list=$(sharing -l 2>/dev/null | sed -n 's/^name:[[:space:]]*//p' | awk '!s[$0]++' | tr '\n' ',' | sed 's/,$//')
gshare=$(sharing -l 2>/dev/null | awk -F':[ \t]*' '/^name:/{n=$2} /guest access/{gsub(/[ \t]/,"",$2); if($2=="1") print n}' | sort -u | tr '\n' ',' | sed 's/,$//')
guest04=$(defaults read /Library/Preferences/SystemConfiguration/com.apple.smb.server AllowGuestAccess 2>/dev/null)
if [ "$smb" = "on" ] || [ "$afp" = "on" ]; then
    result "PC-04|취약|파일 공유 활성: $([ "$smb" = on ] && echo 'SMB ')$([ "$afp" = on ] && echo 'AFP ')공유=${shared_list:-목록 조회 불가($([ "$IS_ROOT" -eq 1 ] || echo "$NEED_ROOT"))}"
elif [ "$smb" = "off" ] && [ "$afp" = "off" ]; then
    # 공유 폴더 정의만 있고 SMB/AFP 서비스가 꺼져 있으면 외부에서 접근할 수 없음 → 양호 (게스트 허용 설정이 남아 있으면 재활성 시 위험)
    result "PC-04|양호|파일 공유 서비스(SMB/AFP) 비활성 (system 도메인 미적재, 포트 445/548 닫힘)$([ -n "$shared_list" ] && echo " - 정의된 공유 ${shared_list} 는 서비스가 꺼져 있어 접근 불가")$({ [ -n "$gshare" ] || [ "$guest04" = "1" ]; } && echo ", 게스트 허용 설정 존재(${gshare:-AllowGuestAccess=1}) - 재활성 시 취약")"
elif [ "$IS_ROOT" -eq 1 ]; then
    result "PC-04|점검불가|파일 공유 서비스 상태 조회 불가: launchctl 명령 없음/조회 실패 (포트 445/548 닫힘)"
else
    result "PC-04|점검불가|파일 공유 서비스 상태 조회 불가: ${NEED_ROOT} (로컬 포트 445/548 은 닫혀 있으나 launchctl 시스템 도메인을 볼 수 없어 단정 불가)"
fi

# ── PC-05: 불필요 서비스 비활성화 ──────────────────────────────────
bad_svc=""; unk_svc=0
evd "PC-05" "launchctl print system/com.apple.screensharing"
evd "PC-05" "netstat -an -p tcp"
evd "PC-05" "ps -axo comm"
for entry in com.apple.screensharing:5900 com.apple.VNCServer: com.apple.tftpd:69 com.apple.bootpd: org.postfix.master:25 com.apple.ftp-proxy:; do
    svc=${entry%%:*}; port=${entry##*:}
    st=$(svc_state "$svc" "$port")
    evq "PC-05" "서비스 상태 (system 도메인 적재 여부 / 포트 ${port:-없음} LISTEN 여부; 사용자 에이전트 .agent 는 항상 로드되므로 근거 아님)" "$svc = $st"
    [ "$st" = "on" ] && bad_svc="${bad_svc} ${svc##com.apple.}"
    [ "$st" = "unk" ] && unk_svc=1
done
st=$(ard_state)
evq "PC-05" "원격 관리(ARD) 상태 (ARDAgent 프로세스 또는 포트 3283 LISTEN)" "ARD = $st"
[ "$st" = "on" ] && bad_svc="${bad_svc} 원격관리(ARD)"
[ "$st" = "unk" ] && unk_svc=1
if [ -n "$bad_svc" ]; then
    result "PC-05|취약|실행 중 불필요 서비스:${bad_svc}"
elif [ "$unk_svc" -eq 1 ]; then
    if [ "$IS_ROOT" -eq 1 ]; then
        result "PC-05|점검불가|불필요 서비스 적재 여부 조회 불가: launchctl 명령 없음/조회 실패 (root 실행)"
    else
        result "PC-05|점검불가|불필요 서비스 적재 여부 조회 불가: ${NEED_ROOT} (포트 리슨 확인된 서비스 없음)"
    fi
else
    result "PC-05|양호|불필요 서비스 미실행 (화면공유/원격관리/VNC/TFTP/BOOTP/FTP 등)"
fi

# ── PC-06: 백신 / Gatekeeper ──────────────────────────────────────
evd "PC-06" "spctl --status"
av_scan
evd "PC-06" "find $AV_DIRS -maxdepth 2 -name '*.app'"
evd "PC-06" "ps -axo comm"
evq "PC-06" "백신 판별 결과 (앱 이름·실행 파일 이름만으로 판별, 경로 제외 - /Applications/AhnLab/ASTx 는 안랩 세이프 트랜잭션(금융 보안 모듈)으로 백신 아님)" "앱=${AV_APPS:-없음}" "프로세스=${AV_PROCS:-없음}" "앱 패턴=${AV_APP_RE}" "프로세스 패턴=${AV_PROC_RE}"
gk_status=$(spctl --status 2>/dev/null)
if echo "$gk_status" | grep -qi "assessments enabled"; then
    if ! have find; then
        result "PC-06|점검불가|Gatekeeper 활성이나 find 명령이 없어 설치된 백신 앱을 조사할 수 없음"
    elif [ -n "$AV_APPS" ]; then
        result "PC-06|양호|Gatekeeper 활성 + 백신: ${AV_APPS}$([ -n "$AV_PROCS" ] && echo " (실행: ${AV_PROCS})" || echo " (실시간 감시 프로세스 미확인 - 백신 설정 확인)")"
    else
        result "PC-06|수동확인|Gatekeeper 활성, 백신 미탐지 (XProtect 내장 보호만 확인) — 백신 설치 및 실시간 감시 여부 확인"
    fi
elif [ -z "$gk_status" ]; then
    result "PC-06|점검불가|Gatekeeper 상태(spctl --status) 조회 실패"
else
    result "PC-06|취약|Gatekeeper 비활성 ($gk_status)"
fi

# ── PC-07: OS 보안 패치 (자동 업데이트 + 지원 종료·미적용 보안 릴리스) ──────────────────────────────
evd "PC-07" "defaults read /Library/Preferences/com.apple.SoftwareUpdate"
evd "PC-07" "defaults read '/Library/Managed Preferences/com.apple.SoftwareUpdate'"
evd "PC-07" "softwareupdate --schedule"
evd "PC-07" "sw_vers"
auto_check=$(defaults read "/Library/Managed Preferences/com.apple.SoftwareUpdate" AutomaticCheckEnabled 2>/dev/null)
[ -z "$auto_check" ] && auto_check=$(defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled 2>/dev/null)
auto_install=$(defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticallyInstallMacOSUpdates 2>/dev/null)
crit_install=$(defaults read /Library/Preferences/com.apple.SoftwareUpdate CriticalUpdateInstall 2>/dev/null)
sched=$(softwareupdate --schedule 2>&1)
# 자동 확인: 키가 있으면 키 값, 키가 없으면 macOS 기본값(켜짐) — softwareupdate --schedule 출력으로 대조
if [ "$auto_check" = "0" ]; then auto_on=0
elif [ "$auto_check" = "1" ]; then auto_on=1
elif echo "$sched" | grep -qiE 'turned off|check is off'; then auto_on=0
else auto_on=1; fi
mac_eos_check   # Apple 보안 릴리스 목록 조회 → 지원 종료(EoS)·미적용 보안 패치
evq "PC-07" "macOS 지원 종료·미적용 보안 릴리스 판정 원자료 (결과: ${EOS_RES})" "$EOS_EVD"
GRACE=${PATCH_GRACE_DAYS:-30}; case "$GRACE" in ''|*[!0-9]*) GRACE=30 ;; esac
pmiss=""; [ -n "$PATCH_LATEST" ] && pmiss="미적용 보안 릴리스 ${OS_VER} → ${PATCH_LATEST} (가장 오래된 미적용 배포 ${PATCH_DATE}, ${PATCH_AGE}일 경과)"
au="AutomaticCheckEnabled=${auto_check:-미설정(기본 1)}, AutoInstall=${auto_install:-미설정}, 긴급패치=${crit_install:-미설정(기본 1)}"
if [ "$EOS_RES" = "취약" ]; then
    result "PC-07|취약|${EOS_DESC}"
elif [ -n "$PATCH_LATEST" ] && [ "${PATCH_AGE:-0}" -gt "$GRACE" ] 2>/dev/null; then
    result "PC-07|취약|${pmiss} - ${GRACE}일 이상 보안 패치 미적용 (${au})"
elif ! have defaults; then
    result "PC-07|점검불가|defaults 명령이 없어 자동 업데이트 설정을 읽을 수 없음"
elif [ "$auto_on" != "1" ]; then
    result "PC-07|취약|자동 업데이트 확인 비활성 (${au}), OS=${OS_VER}"
elif [ "$EOS_RES" = "점검불가" ] || [ "$EOS_RES" = "수동확인" ]; then
    result "PC-07|${EOS_RES}|${EOS_DESC} (${au})"
else
    result "PC-07|양호|자동 업데이트 활성 (${au}), ${EOS_DESC}$([ -n "$pmiss" ] && echo ", ${pmiss}(유예 ${GRACE}일 이내)")"
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
evd "PC-10" "launchctl print system/com.openssh.sshd"
evd "PC-10" "launchctl print system/com.apple.screensharing"
evd "PC-10" "netstat -an -p tcp"
evd "PC-10" "ps -axo comm"
evd "PC-10" "ls -l /Library/PrivilegedHelperTools 2>/dev/null | grep -i chromoting; launchctl print system 2>/dev/null | grep -i chromoting"
evd "PC-10" "nc -z -w 1 127.0.0.1 22 && echo 'port 22 open' || echo 'port 22 closed'; nc -z -w 1 127.0.0.1 5900 && echo 'port 5900 open' || echo 'port 5900 closed'; nc -z -w 1 127.0.0.1 3283 && echo 'port 3283 open' || echo 'port 3283 closed'"
issues10=""; unk10=0; rl_err=""
sshst=$(svc_state com.openssh.sshd 22)
ssst=$(svc_state com.apple.screensharing 5900)
ardst=$(ard_state)
evq "PC-10" "서비스 상태 (system 도메인 적재 / 포트 LISTEN / ARDAgent 프로세스; 사용자 에이전트 .agent 는 항상 로드되므로 근거 아님)" "sshd=$sshst screensharing=$ssst ARD=$ardst"
if [ "$IS_ROOT" -eq 1 ]; then
    rl=$(systemsetup -getremotelogin 2>&1)
    if echo "$rl" | grep -qiE 'Remote Login:[[:space:]]*On'; then issues10="${issues10} SSH활성"
    elif echo "$rl" | grep -qiE 'Remote Login:[[:space:]]*Off'; then :
    elif [ "$sshst" = on ]; then issues10="${issues10} SSH활성(launchd/포트22)"
    else unk10=1; rl_err="systemsetup -getremotelogin 결과 판독 불가: $rl"; fi
else
    [ "$sshst" = on ] && issues10="${issues10} SSH활성(포트22 리슨/launchd)"
    [ "$sshst" = unk ] && unk10=1
fi
[ "$ssst" = on ] && issues10="${issues10} 화면공유활성"
[ "$ssst" = unk ] && unk10=1
[ "$ardst" = on ] && issues10="${issues10} 원격관리(ARD)활성"
[ "$ardst" = unk ] && unk10=1
rt10=$(remote_tools)
evq "PC-10" "3rd-party 원격 지원 프로그램 (프로세스 이름 / Chrome 원격 데스크톱 원격 액세스 표시 파일)" "${rt10:-없음}"
[ -n "$rt10" ] && issues10="${issues10} 원격지원프로그램(${rt10})"
if [ -n "$issues10" ]; then
    result "PC-10|취약|원격 접속 서비스 활성:${issues10}"
elif [ "$unk10" -eq 1 ]; then
    if [ "$IS_ROOT" -eq 1 ]; then
        result "PC-10|점검불가|원격 로그인(SSH)/화면공유 설정 조회 불가: ${rl_err:-launchctl 명령 없음/조회 실패} (터미널에 전체 디스크 접근 권한이 필요할 수 있음; 포트 22/5900 닫힘)"
    else
        result "PC-10|점검불가|원격 로그인(SSH)/화면공유 설정 조회 불가: ${NEED_ROOT} (systemsetup·launchctl 시스템 도메인 필요; 로컬 포트 22/5900 닫힘, ARD 프로세스 없음)"
    fi
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
sa_guest=$(echo "$sa_guest" | sed 's/^[0-9-]* [0-9:.]* sysadminctl\[[0-9:]*\] //')   # 시각·프로세스 접두 제거(원문은 증적에)
if ! have defaults; then
    result "PC-13|점검불가|defaults 명령이 없어 Guest 계정 설정을 읽을 수 없음"
elif [ "$guest_enabled" = "1" ] || [ "$guest_enabled" = "true" ] || echo "$sa_guest" | grep -qi 'enabled'; then
    result "PC-13|취약|Guest 계정 활성화됨 (GuestEnabled=${guest_enabled:-미설정}; ${sa_guest})"
else
    result "PC-13|양호|Guest 계정 비활성 (GuestEnabled=${guest_enabled:-미설정(기본 비활성)})"
fi

# ── PC-14: SIP(System Integrity Protection) ───────────────────────
evd "PC-14" "csrutil status"
sip_status=$(csrutil status 2>&1); sip_rc=$?
sip_dis=$(echo "$sip_status" | grep -iE ':[[:space:]]*disabled' | grep -viE 'status:' | sed 's/^[[:space:]]*//' | tr '\n' ',' | sed 's/,$//')
sip_head=$(echo "$sip_status" | awk 'NF{print; exit}')
if [ "$sip_rc" -eq 127 ] || [ -z "$sip_status" ] || echo "$sip_status" | grep -qiE 'command not found|No such file'; then
    result "PC-14|점검불가|csrutil status 조회 실패 (종료코드 ${sip_rc}): ${sip_head:-출력 없음}"
elif echo "$sip_status" | grep -qi 'custom configuration'; then
    result "PC-14|취약|SIP 일부 보호 해제(Custom Configuration): ${sip_head}${sip_dis:+ — 해제 항목: ${sip_dis}}"
elif echo "$sip_status" | grep -qiE 'status: enabled\.?$'; then
    result "PC-14|양호|SIP 활성: $sip_head"
elif echo "$sip_status" | grep -qiE 'status: (disabled|unknown)'; then
    result "PC-14|취약|SIP 비활성: ${sip_head}"
else
    result "PC-14|점검불가|csrutil status 출력을 해석하지 못함: ${sip_head}"
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
evd "PC-16" "profiles -P -o stdout"
pw16=$(pwpolicy getaccountpolicies 2>/dev/null); pw16_rc=$?
prof16=""; [ "$IS_ROOT" -eq 1 ] && prof16=$(profiles -P -o stdout 2>/dev/null)
max_fail=$(echo "$pw16" | tr -d '\n\t ' | grep -oE '<key>policyAttributeMaximumFailedAuthentications</key><integer>[0-9]+' | grep -oE '[0-9]+$' | awk 'NR==1')
[ -z "$max_fail" ] && max_fail=$(echo "$pw16" | grep -oE 'policyAttributeFailedAuthentications[[:space:]]*<[[:space:]]*[0-9]+' | grep -oE '[0-9]+$' | awk 'NR==1')
[ -z "$max_fail" ] && max_fail=$(echo "$prof16" | grep -iE 'maxFailedAttempts' | grep -oE '[0-9]+' | awk 'NR==1')
if ! echo "$pw16" | grep -q "policyAttribute" && [ -z "$max_fail" ]; then
    if [ "$IS_ROOT" -eq 1 ] && [ "$pw16_rc" -eq 0 ]; then
        evq "PC-16" "판정에 사용한 값" "pwpolicy 종료코드=${pw16_rc} 정책(policyAttribute) 없음, 구성 프로파일 maxFailedAttempts 없음"
        result "PC-16|취약|로그인 실패 잠금 임계값 미설정 (pwpolicy 계정 정책·구성 프로파일에 잠금 정책 없음)"
    elif [ "$IS_ROOT" -eq 1 ]; then
        result "PC-16|점검불가|로그인 실패 임계값 조회 실패: pwpolicy getaccountpolicies 종료코드 ${pw16_rc} - MDM/프로파일 수동 확인"
    else
        result "PC-16|점검불가|로그인 실패 임계값 조회 불가: ${NEED_ROOT}"
    fi
else
    evq "PC-16" "pwpolicy·구성 프로파일에서 추출한 로그인 실패 허용 횟수" "max_fail=${max_fail:-미설정}"
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
fv_status=$(fdesetup status 2>&1); fv_rc=$?
if [ "$fv_rc" -eq 127 ] || [ -z "$fv_status" ] || echo "$fv_status" | grep -qiE 'command not found|No such file'; then
    result "PC-18|점검불가|fdesetup status 조회 실패 (종료코드 ${fv_rc}): ${fv_status:-출력 없음}"
elif echo "$fv_status" | grep -qi 'Decryption in progress'; then
    result "PC-18|취약|FileVault 복호화 진행 중(해제되는 중): $fv_status"
elif echo "$fv_status" | grep -qi 'Encryption in progress'; then
    result "PC-18|수동확인|FileVault 암호화 진행 중(완료 전): $fv_status"
elif echo "$fv_status" | grep -qi 'FileVault is On'; then
    result "PC-18|양호|FileVault 활성: $fv_status"
else
    if echo "$fv_status" | grep -qi 'FileVault is Off'; then
        result "PC-18|취약|FileVault 비활성: ${fv_status}"
    else
        result "PC-18|점검불가|fdesetup status 출력을 해석하지 못함: ${fv_status}"
    fi
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
