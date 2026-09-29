#!/bin/bash
if [ -z "$BASH_VERSION" ]; then for _b in /bin/bash /usr/bin/bash /opt/freeware/bin/bash /usr/local/bin/bash /usr/contrib/bin/bash; do [ -x $_b ] && exec $_b "$0" "$@"; done; echo "bash 필요 (AIX: AIX Toolbox bash / HP-UX: Porting Centre bash 설치 후 재실행)"; exit 1; fi   # sh 로 실행 시 bash 로 재실행 (declare -A 등 bash 전용 문법)
unset LC_ALL; export LC_MESSAGES=C LC_TIME=C          # apt/lastlog 등 명령 출력·날짜를 영문 고정 (ko_KR 로케일 판정 차이 방지)
# ================================================================
# 서버(Unix/Linux) 보안 취약점 자동 점검 스크립트 — 전자금융기반시설
# ================================================================
#
# [용도]
#   전자금융기반시설 보안 취약점 평가기준 제2026-1호 [서버]
#   Windows Server는 check_server.ps1 사용.
#
# [대상 OS]
#   Linux (RHEL/CentOS/Rocky/Ubuntu/SLES/Amazon)
#   AIX 6.1~7.3 / HP-UX 11i / Solaris 10~11
#
# [사전 조건]
#   - root 권한 필요 (sudo bash 또는 root 로그인)
#
# [실행 방법]
#   bash check_server_srv.sh > /tmp/$(hostname)_srv.txt
#
# [산출물]
#   1) 표준출력: SRV-항목코드|결과|근거설명  (양호/취약/수동확인/N-A)
#   2) 증적 파일: /tmp/<호스트명>_srv_evidence.txt
#
# ================================================================

# ── OS 탐지 ──────────────────────────────────────────────────────
detect_os() {
    OS_FAMILY="LINUX"    # LINUX / AIX / SOLARIS / HPUX / BSD
    OS_DISTRO="UNKNOWN"  # RHEL / CENTOS / UBUNTU / DEBIAN / SLES / AMZN / ORACLE
    OS_MAJOR=0

    case "$(uname -s)" in
    MINGW*|MSYS*|CYGWIN*)
        OS_FAMILY="WINDOWS"; OS_DISTRO="GITBASH"
        OS_MAJOR=$(uname -s | grep -oE '[0-9]+' | head -1); return ;;
    AIX)
        OS_FAMILY="AIX"; OS_DISTRO="AIX"
        OS_MAJOR=$(uname -v); return ;;
    SunOS)
        OS_FAMILY="SOLARIS"; OS_DISTRO="SOLARIS"
        OS_MAJOR=$(uname -r | cut -d. -f2); return ;;
    "HP-UX")
        OS_FAMILY="HPUX"; OS_DISTRO="HPUX"
        OS_MAJOR=$(uname -r | cut -d. -f2); return ;;
    FreeBSD|OpenBSD|NetBSD)
        OS_FAMILY="BSD"; OS_DISTRO="$(uname -s)"
        OS_MAJOR=$(uname -r | cut -d. -f1); return ;;
    esac

    if [ -f /etc/os-release ]; then
        . /etc/os-release
        case "$ID" in
        rhel|centos|rocky|almalinux|ol) OS_DISTRO="RHEL"; OS_MAJOR="${VERSION_ID%%.*}" ;;
        ubuntu)  OS_DISTRO="UBUNTU"; OS_MAJOR="${VERSION_ID%%.*}" ;;
        debian)  OS_DISTRO="DEBIAN"; OS_MAJOR="${VERSION_ID}" ;;
        sles|suse) OS_DISTRO="SLES"; OS_MAJOR="${VERSION_ID%%.*}" ;;
        amzn)    OS_DISTRO="AMZN";  OS_MAJOR="${VERSION_ID}" ;;
        *)       case " $ID_LIKE " in   # ProLinux(ID=pl) 등 파생 배포판
                 *" rhel "*|*" centos "*|*" fedora "*) OS_DISTRO="RHEL" ;;
                 *" debian "*|*" ubuntu "*) OS_DISTRO="DEBIAN" ;;
                 *" suse "*) OS_DISTRO="SLES" ;;
                 *) OS_DISTRO="${ID:-UNKNOWN}" ;;
                 esac; OS_MAJOR="${VERSION_ID%%.*}" ;;
        esac
    elif [ -f /etc/redhat-release ]; then
        OS_DISTRO="RHEL"; OS_MAJOR=$(grep -oE '[0-9]+' /etc/redhat-release | head -1)
    elif [ -f /etc/debian_version ]; then
        OS_DISTRO="DEBIAN"; OS_MAJOR=$(cut -d. -f1 /etc/debian_version)
    fi
}

detect_os
case "$OS_FAMILY" in   # Solaris 기본 grep/awk 는 -E/-q/-o·-v 미지원, AIX·HP-UX 는 GNU 도구 경로 우선
SOLARIS) PATH="/usr/gnu/bin:/usr/xpg4/bin:/opt/csw/gnu:/opt/csw/bin:/usr/sfw/bin:$PATH" ;;
AIX)     PATH="/opt/freeware/bin:$PATH" ;;
HPUX)    PATH="/usr/local/bin:$PATH" ;;
esac; export PATH
HN=$(hostname 2>/dev/null || uname -n)
# ── 결과 사본 자동 저장: '> 파일' 리다이렉트를 빠뜨려도 판정 결과가 증적과 같은 위치에 남도록 표준출력을 복사 ──
_RESF="/tmp/${HN}_srv.txt"
if [ -z "$NO_RESULT_COPY" ] && ! [ /dev/fd/1 -ef "$_RESF" ] 2>/dev/null && ( : > "$_RESF" ) 2>/dev/null; then
    exec > >(tee "$_RESF"); _TEEPID=$!
else
    _RESF=""
fi

echo "# ============================================================"
echo "# 점검 대상: ${HN}"
echo "# OS: ${OS_FAMILY} / ${OS_DISTRO} ${OS_MAJOR}"
echo "# OS 상세: $( ( [ -r /etc/os-release ] && . /etc/os-release 2>/dev/null && echo "${PRETTY_NAME:-$NAME $VERSION_ID}" ) || ( command -v oslevel >/dev/null 2>&1 && echo "AIX $(oslevel -s 2>/dev/null)" ) || ( [ -r /etc/release ] && head -1 /etc/release | sed 's/^ *//' ) || uname -sr 2>/dev/null)"
echo "# 커널: $(uname -r 2>/dev/null)$( [ "$(uname -s 2>/dev/null)" = SunOS ] && echo " / $(uname -v 2>/dev/null)")"
echo "# 점검 기준: 전자금융기반시설 보안 취약점 평가기준 제2026-1호 [서버]"
echo "# 점검 일시: $(date '+%Y-%m-%d %H:%M:%S')"
if [ "$OS_DISTRO" = "RHEL" ]; then
    _id=$(. /etc/os-release 2>/dev/null; echo "$ID")
    [ "$_id" = "centos" ] && echo "# [경고] CentOS는 전체 버전 EOL - 취약 판정 대상"
fi
if [ "$OS_FAMILY" = "WINDOWS" ]; then
    echo "# [경고] Windows 환경(Git Bash)에서 실행됨 — Linux/Unix 전용 스크립트"
    echo "# [경고] Windows Server 점검은 check_server.ps1 사용"
fi
echo "# ============================================================"

# ── 결과 카운터 ──────────────────────────────────────────────────
_CP=0; _CF=0; _CM=0; _CN=0
_EVD="/tmp/${HN}_srv_evidence.txt"
# 증적 파일 쓰기 불가(다른 사용자 소유 기존 파일, /tmp 용량 부족 등) → 대체 경로 (쓰기 실패로 판정 중복 방지)
if ! ( : >> "$_EVD" ) 2>/dev/null; then
    _EVD=$(mktemp "${TMPDIR:-/tmp}/${HN}_evidence.XXXXXX" 2>/dev/null || echo "./${HN}_evidence_$$.txt")
    echo "# [경고] 기본 증적 파일에 쓸 수 없어 대체 경로 사용: $_EVD"
fi
_NONROOT=0; [ "$(id -u 2>/dev/null)" != "0" ] && { _NONROOT=1; echo "# [경고] root 권한 아님 — /etc/shadow·타 계정 홈 등 조회 불가 항목(SRV-022/074/096/122)은 수동확인 처리, root 로 재점검 권고"; }
echo "# ================================================================" > "$_EVD"
echo "# 증적 파일 (감사 추적용)" >> "$_EVD"
echo "# 대상: ${HN} / ${OS_FAMILY} ${OS_DISTRO} ${OS_MAJOR}" >> "$_EVD"
echo "# 생성: $(date '+%Y-%m-%d %H:%M:%S')" >> "$_EVD"
echo "# ================================================================" >> "$_EVD"

declare -A _INAME=(
    [SRV-001]='안전한 네트워크 모니터링 서비스 사용'
    [SRV-002]='패스워드 복잡성/최소 길이 설정'
    [SRV-003]='네트워크 모니터링 서비스 접근통제 설정 적절성'
    [SRV-004]='불필요한 SMTP 서비스 비활성화'
    [SRV-005]='SMTP 서비스의 expn/vrfy 명령어 실행 제한 여부'
    [SRV-006]='SMTP 서비스 로그 수준 설정 적절성'
    [SRV-007]='SMTP 서비스 보안 패치 적용 여부'
    [SRV-008]='SMTP 서비스의 DoS 방지 기능 설정 여부'
    [SRV-009]='SMTP 서비스 스팸 메일 릴레이 제한 설정 여부'
    [SRV-010]='SMTP 서비스의 메일 queue 처리 권한 설정 적절성'
    [SRV-011]='시스템 관리자 계정의 FTP 사용 제한 여부'
    [SRV-012]='.netrc 파일 내 중요 정보 미포함 여부'
    [SRV-013]='Anonymous 계정의 FTP 서비스 접속 제한 여부'
    [SRV-014]='NFS 접근통제 설정 적절성'
    [SRV-015]='불필요한 NFS 서비스 비활성화'
    [SRV-016]='불필요한 RPC 서비스 비활성화'
    [SRV-017]='관리자 그룹 구성원 관리'
    [SRV-018]='불필요한 하드디스크 기본 공유 비활성화'
    [SRV-019]='관리자 그룹 구성원 적절성'
    [SRV-020]='공유 기능에 대한 접근통제 설정 적절성'
    [SRV-021]='FTP 서비스 접근통제 설정 적절성'
    [SRV-022]='계정의 비밀번호 미설정, 빈 암호 사용 관리 여부'
    [SRV-023]='원격 터미널 서비스의 암호화 설정 적절성'
    [SRV-024]='취약한 Telnet 인증 방식 사용 제한 여부'
    [SRV-025]='hosts.equiv 또는 .rhosts 설정 제한 여부'
    [SRV-026]='root 계정 원격 접속 제한 여부'
    [SRV-027]='서비스 접근 IP 및 포트 제한 여부'
    [SRV-028]='원격 터미널 접속 타임아웃 설정 여부'
    [SRV-029]='SMB 세션 중단 관리 설정 여부'
    [SRV-030]='NFS 서비스 비활성화'
    [SRV-031]='계정 목록 및 네트워크 공유 이름 노출 방지 여부'
    [SRV-032]='automountd 서비스 비활성화'
    [SRV-033]='불필요한 RPC 서비스 비활성화'
    [SRV-034]='불필요한 서비스 비활성화'
    [SRV-035]='취약한 서비스 비활성화'
    [SRV-036]='Sendmail 서비스 비활성화'
    [SRV-037]='취약한 FTP 서비스 비활성화'
    [SRV-038]='웹서비스 디렉터리 리스팅'
    [SRV-039]='웹 프로세스 권한 제한'
    [SRV-040]='상위 디렉터리 접근 금지'
    [SRV-041]='웹서비스 불필요한 파일 제거'
    [SRV-042]='심볼릭 링크 사용 금지'
    [SRV-043]='파일 업로드/다운로드 제한'
    [SRV-044]='웹서비스 영역 분리'
    [SRV-045]='최신 보안패치 적용 여부'
    [SRV-046]='로그 정기 검토 및 보고'
    [SRV-047]='시스템 로깅 설정'
    [SRV-048]='su 사용 로그 설정'
    [SRV-049]='접속 기록 파일 권한 설정'
    [SRV-050]='로그인/로그아웃 기록 관리'
    [SRV-051]='su 사용자 제한'
    [SRV-052]='SMTP 서비스 비활성화'
    [SRV-053]='SMTP expn/vrfy 명령어 제한'
    [SRV-054]='SMTP 로그 수준 설정'
    [SRV-055]='SMTP 보안 패치 적용'
    [SRV-056]='SMTP DoS 방지 설정'
    [SRV-057]='SMTP 릴레이 제한'
    [SRV-058]='DNS 보안패치 적용'
    [SRV-059]='DNS 영역전송 제한'
    [SRV-060]='DNS Dynamic Update 비활성화'
    [SRV-061]='DNS 최신 버전 사용'
    [SRV-062]='DNS 서비스 정보 노출 방지 여부'
    [SRV-063]='DNS Recursive Query 제한 설정 여부'
    [SRV-064]='DNS 서비스 보안 패치 적용 여부'
    [SRV-065]='Cron 서비스 사용 권한 제한'
    [SRV-066]='DNS Zone Transfer 제한 설정 적절성'
    [SRV-067]='로그온 경고 메시지 설정'
    [SRV-068]='NFS 설정 파일 권한'
    [SRV-069]='비밀번호 관리정책 설정 적절성'
    [SRV-070]='취약한 패스워드 저장 방식 사용 제한 여부'
    [SRV-071]='웹서비스 디렉터리 인덱싱'
    [SRV-072]='기본 관리자 계정명(Administrator) 변경 여부'
    [SRV-073]='관리자 그룹에 불필요한 사용자 제거'
    [SRV-074]='불필요하거나 관리되지 않는 계정 제거'
    [SRV-075]='비밀번호 복잡도 설정'
    [SRV-076]='SNMP 접근통제 설정'
    [SRV-077]='SNMP Community String 복잡성'
    [SRV-078]='불필요한 Guest 계정 비활성화'
    [SRV-079]='익명 사용자에게 부적절한 권한(Everyone) 제거'
    [SRV-080]='일반 사용자의 프린터 드라이버 설치 제한 여부'
    [SRV-081]='Crontab 설정파일 권한 설정 적절성'
    [SRV-082]='시스템 주요 디렉터리 권한 설정 적절성'
    [SRV-083]='시스템 스타트업 스크립트 권한 설정 적절성'
    [SRV-084]='시스템 주요 파일 권한 설정 적절성'
    [SRV-085]='PATH 환경변수 설정'
    [SRV-086]='사용자 홈 디렉터리 소유자/권한'
    [SRV-087]='설치된 C 컴파일러의 권한 설정 적절성'
    [SRV-088]='Crontab 파일 권한'
    [SRV-089]='hosts.equiv/.rhosts 파일 존재'
    [SRV-090]='불필요한 원격 레지스트리 서비스 비활성화'
    [SRV-091]='불필요하게 SUID, SGID bit가 설정된 파일 제거'
    [SRV-092]='사용자 홈 디렉터리 경로 및 권한 설정 적절성'
    [SRV-093]='불필요한 world writable 파일 제거'
    [SRV-094]='Crontab 참조파일 권한 설정 적절성'
    [SRV-095]='존재하지 않는 소유자 및 그룹 권한을 가진 파일 또는 디렉터리 제거'
    [SRV-096]='사용자 환경파일의 소유자 또는 권한 설정 적절성'
    [SRV-097]='FTP 서비스 디렉터리 접근권한 설정 적절성'
    [SRV-098]='최소 필요 서비스만 유지'
    [SRV-099]='네트워크 접근제어 설정'
    [SRV-100]='시스템 계정 Shell 점검'
    [SRV-101]='불필요한 예약 작업 제거'
    [SRV-102]='세션 타임아웃 설정'
    [SRV-103]='LAN Manager 인증 수준 적절성'
    [SRV-104]='보안 채널 데이터 디지털 암호화 또는 서명 기능 설정 적절성'
    [SRV-105]='불필요한 시작프로그램 제거'
    [SRV-106]='root 외 UID 0 금지'
    [SRV-107]='패스워드 최소 길이'
    [SRV-108]='로그에 대한 접근통제 및 관리 적절성'
    [SRV-109]='시스템 주요 이벤트 로그 설정 적절성'
    [SRV-110]='소유자 없는 파일 점검'
    [SRV-111]='로그 관리(logrotate) 설정'
    [SRV-112]='Cron 서비스 로깅 설정 적절성'
    [SRV-113]='네트워크 접근통제 설정'
    [SRV-114]='xinetd 서비스 점검'
    [SRV-115]='로그의 정기적 검토 및 보고 수행 여부'
    [SRV-116]='“보안 감사를 수행할 수 없는 경우, 즉시 시스템 종료” 기능 비활성화'
    [SRV-117]='감사 로깅(auditd) 설정'
    [SRV-118]='주기적인 보안패치 및 벤더 권고사항 적용 여부'
    [SRV-119]='백신 프로그램 업데이트 적용 여부'
    [SRV-120]='보안 모듈(SELinux/AppArmor) 설정'
    [SRV-121]='root 계정의 PATH 환경변수 설정 적절성'
    [SRV-122]='umask 설정 적절성'
    [SRV-123]='최종 로그인 사용자 계정 노출 방지 여부'
    [SRV-124]='/etc/shadow 파일 권한'
    [SRV-125]='화면보호기 설정 적절성'
    [SRV-126]='자동 로그온 방지 설정 여부'
    [SRV-127]='로그인 실패 횟수에 따른 접속 제한 설정'
    [SRV-128]='NTFS 파일 시스템 사용 여부'
    [SRV-129]='백신 프로그램 설치 여부'
    [SRV-130]='불필요한 리스닝 서비스 점검'
    [SRV-131]='SU 명령 사용가능 그룹 제한 설정 적절성'
    [SRV-132]='NTP 시간 동기화 설정'
    [SRV-133]='Cron 서비스 사용 계정 제한 설정 적절성'
    [SRV-134]='스택 영역 실행 방지 설정 여부'
    [SRV-135]='TCP 보안 설정 여부'
    [SRV-136]='로그온 단계에서 "시스템 종료" 기능 비활성화'
    [SRV-137]='네트워크 서비스 접근 권한 적절성'
    [SRV-138]='백업 및 복구 권한 설정 적절성'
    [SRV-139]='시스템 자원 소유권 변경 권한 설정 적절성'
    [SRV-140]='이동식 미디어 포맷 및 꺼내기 허용 정책 설정 적절성'
    [SRV-141]='감사 로그 설정 파일 관리'
    [SRV-142]='중복 UID가 부여된 계정 제한 여부'
    [SRV-143]='불필요한 프로토콜 모듈 제거'
    [SRV-144]='/dev 경로에 불필요한 파일 제거'
    [SRV-145]='파일 무결성 점검 도구 설치'
    [SRV-146]='안티바이러스 설치 점검'
    [SRV-147]='불필요한 네트워크 모니터링 서비스 비활성화'
    [SRV-148]='부트로더 패스워드 설정'
    [SRV-149]='디스크 볼륨 암호화 적용 여부'
    [SRV-150]='로컬 로그온 허용 계정 제한 여부'
    [SRV-151]='익명 SID/이름 변환 설정 제한 여부'
    [SRV-152]='원격터미널 접속 가능한 사용자 그룹 제한 여부'
    [SRV-153]='시스템 하드닝 설정'
    [SRV-154]='커널 보안 파라미터 설정'
    [SRV-155]='방화벽 설정 점검'
    [SRV-156]='보안패치 주기 및 절차'
    [SRV-157]='백업 설정 점검'
    [SRV-158]='불필요한 Telnet 서비스 비활성화'
    [SRV-159]='서비스 배너 정보 노출 방지'
    [SRV-160]='패스워드 정책 설정'
    [SRV-161]='ftpusers 파일의 소유자 및 권한 설정 적절성'
    [SRV-162]='마운트 옵션 설정(nosuid/noexec)'
    [SRV-163]='시스템 사용 주의사항 출력'
    [SRV-164]='구성원이 존재하지 않는 GID 제거'
    [SRV-165]='불필요하게 Shell이 부여된 계정 제거'
    [SRV-166]='불필요한 숨김 파일 또는 디렉터리 제거'
    [SRV-167]='NFS/Samba 공유 설정'
    [SRV-168]='주요 설정파일 권한'
    [SRV-169]='.forward/.exrc/.netrc 파일 점검'
    [SRV-170]='SMTP 서비스 정보 노출 방지 여부'
    [SRV-171]='FTP 서비스 정보 노출 방지 여부'
    [SRV-172]='불필요한 시스템 자원 공유 제거'
    [SRV-173]='DNS 서비스 동적 업데이트 설정 적절성'
    [SRV-174]='불필요한 DNS 서비스 비활성화'
    [SRV-175]='시간 동기화를 위한 NTP 설정'
    [SRV-176]='비밀번호 저장 암호화 방식'
    [SRV-177]='sudo 명령어 접근 권한 설정 적절성'
    [SRV-179]='서비스 지원이 종료된(EoS) 시스템 및 장비 교체 여부'
)

# ── Windows 환경 조기 종료 ───────────────────────────────────────
if [ "$OS_FAMILY" = "WINDOWS" ]; then
    echo "# Windows 환경 — 전 항목 N-A 처리" >> "$_EVD"
    for _i in $(echo "$_GUIDE_SRV" | tr ' ' '\n' | sed -n 's/^SRV-//p'); do
        _CN=$((_CN+1))
        _code="SRV-${_i}"; _nm="${_INAME[SRV-${_i}]:-}"
        echo "${_code}|N-A|Windows 환경 — Linux/Unix 전용 항목"
        if [ -n "$_nm" ]; then
            printf '[판정] %s (%s)|N-A|Windows 환경 — Linux/Unix 전용 항목\n\n' "$_code" "$_nm" >> "$_EVD"
        else
            printf '[판정] %s|N-A|Windows 환경 — Linux/Unix 전용 항목\n\n' "$_code" >> "$_EVD"
        fi
    done
    _TOTAL=$((_CP + _CF + _CM + _CN))
    echo "# ================================================================"
    echo "# 점검 요약 — 전자금융기반시설 (SRV)"
    echo "#   총 점검 항목: ${_TOTAL}"
    echo "#   양호:         ${_CP}  (0%)"
    echo "#   취약:         ${_CF}  (0%)"
    echo "#   수동확인:     ${_CM}"
    echo "#   N-A:          ${_CN}"
    echo "# ================================================================"
    echo "# 점검 완료: $(date '+%Y-%m-%d %H:%M:%S')"
    echo "# 증적 파일: ${_EVD}"
    exit 0
fi
# ── 평가대상 매핑 (전자금융기반시설 평가기준 제2026-1호 [서버] '평가대상' 열 기준) ──
# 해당 OS가 평가대상이 아닌 항목은 판정을 N-A로 강제 (점검·증적 수집은 그대로 수행)
_NA_LINUX=" SRV-018 SRV-020 SRV-023 SRV-024 SRV-029 SRV-031 SRV-072 SRV-078 SRV-079 SRV-080 SRV-090 SRV-097 SRV-101 SRV-103 SRV-104 SRV-105 SRV-116 SRV-119 SRV-123 SRV-125 SRV-126 SRV-128 SRV-129 SRV-134 SRV-135 SRV-136 SRV-137 SRV-138 SRV-139 SRV-140 SRV-149 SRV-150 SRV-151 SRV-152 SRV-172 SRV-178 "
_NA_AIX=" SRV-018 SRV-020 SRV-023 SRV-024 SRV-029 SRV-031 SRV-072 SRV-078 SRV-079 SRV-080 SRV-090 SRV-097 SRV-101 SRV-103 SRV-104 SRV-105 SRV-116 SRV-119 SRV-123 SRV-125 SRV-126 SRV-128 SRV-129 SRV-134 SRV-135 SRV-136 SRV-137 SRV-138 SRV-139 SRV-140 SRV-149 SRV-150 SRV-151 SRV-152 SRV-172 SRV-178 "
_NA_SOLARIS=" SRV-018 SRV-020 SRV-023 SRV-024 SRV-029 SRV-031 SRV-072 SRV-078 SRV-079 SRV-080 SRV-090 SRV-097 SRV-101 SRV-103 SRV-104 SRV-105 SRV-116 SRV-119 SRV-123 SRV-125 SRV-126 SRV-128 SRV-129 SRV-136 SRV-137 SRV-138 SRV-139 SRV-140 SRV-149 SRV-150 SRV-151 SRV-152 SRV-172 SRV-178 "
_NA_HPUX=" SRV-018 SRV-020 SRV-023 SRV-024 SRV-029 SRV-031 SRV-072 SRV-078 SRV-079 SRV-080 SRV-090 SRV-097 SRV-101 SRV-103 SRV-104 SRV-105 SRV-116 SRV-119 SRV-123 SRV-125 SRV-126 SRV-128 SRV-129 SRV-134 SRV-135 SRV-136 SRV-137 SRV-138 SRV-139 SRV-140 SRV-149 SRV-150 SRV-151 SRV-152 SRV-172 SRV-178 "
_not_target() {
    local _lst
    case "$OS_FAMILY" in
        LINUX)   _lst="$_NA_LINUX" ;;
        AIX)     _lst="$_NA_AIX" ;;
        SOLARIS) _lst="$_NA_SOLARIS" ;;
        HPUX)    _lst="$_NA_HPUX" ;;
        *)       return 1 ;;
    esac
    case "$_lst" in *" $1 "*) return 0 ;; esac
    return 1
}
_GUIDE_SRV=" SRV-001 SRV-003 SRV-004 SRV-005 SRV-006 SRV-007 SRV-008 SRV-009 SRV-010 SRV-011 SRV-012 SRV-013 SRV-014 SRV-015 SRV-016 SRV-018 SRV-020 SRV-021 SRV-022 SRV-023 SRV-024 SRV-025 SRV-026 SRV-027 SRV-028 SRV-029 SRV-031 SRV-034 SRV-035 SRV-037 SRV-062 SRV-063 SRV-064 SRV-066 SRV-069 SRV-070 SRV-072 SRV-073 SRV-074 SRV-075 SRV-078 SRV-079 SRV-080 SRV-081 SRV-082 SRV-083 SRV-084 SRV-087 SRV-090 SRV-091 SRV-092 SRV-093 SRV-094 SRV-095 SRV-096 SRV-097 SRV-101 SRV-103 SRV-104 SRV-105 SRV-108 SRV-109 SRV-112 SRV-115 SRV-116 SRV-118 SRV-119 SRV-121 SRV-122 SRV-123 SRV-125 SRV-126 SRV-127 SRV-128 SRV-129 SRV-131 SRV-133 SRV-134 SRV-135 SRV-136 SRV-137 SRV-138 SRV-139 SRV-140 SRV-142 SRV-144 SRV-147 SRV-149 SRV-150 SRV-151 SRV-152 SRV-158 SRV-161 SRV-163 SRV-164 SRV-165 SRV-166 SRV-170 SRV-171 SRV-172 SRV-173 SRV-174 SRV-175 SRV-177 SRV-178 SRV-179 "   # 평가기준 제2026-1호 [서버] 평가항목 106개 — 그 외 SRV 코드는 참고 점검(증적만 기록, 결과·집계 제외)
result() {
    case "${1%%|*}" in SRV-*)
        case "$_GUIDE_SRV" in *" ${1%%|*} "*) ;; *)
            printf '[참고-평가기준 외] %s\n\n' "$1" >> "$_EVD"; return 0 ;; esac ;; esac
    if [ "$_NONROOT" = 1 ]; then
        case "${1%%|*}" in SRV-022|SRV-074|SRV-096|SRV-122)
            case "$1" in *"|양호|"*|*"|취약|"*)
                set -- "${1%%|*}|수동확인|root 권한 아님 - shadow·타 계정 파일 조회 불가로 판정 신뢰 불가, root 로 재점검 필요 (원 판정: ${1#*|})" ;; esac ;; esac
    fi
    local _code="${1%%|*}" _rest="${1#*|}"
    _code="${_code%% *}"
    if _not_target "$_code" && [ "${_rest%%|*}" != "N-A" ]; then
        printf '[평가대상 아님] %s 원 판정: %s
' "$_code" "$1" >> "$_EVD"
        set -- "${_code}|N-A|평가대상 아님 (${OS_FAMILY} 해당 없음 - 평가기준 평가대상 열)"
    fi
    echo "$1"
    case "$1" in
    *"|양호|"*)     _CP=$((_CP+1)) ;;
    *"|취약|"*)     _CF=$((_CF+1)) ;;
    *"|수동확인|"*) _CM=$((_CM+1)) ;;
    *"|N-A|"*)      _CN=$((_CN+1)) ;;
    esac
    local _code="${1%%|*}" _rest="${1#*|}"
    local _nm="${_INAME[$_code]:-}"
    if [ -n "$_nm" ]; then
        printf '[판정] %s (%s)|%s\n\n' "$_code" "$_nm" "$_rest" >> "$_EVD"
    else
        printf '[판정] %s\n\n' "$1" >> "$_EVD"
    fi
    return 0
}
evd() {
    local item="$1"; shift
    printf '[%s] %s $ %s\n' "$item" "$(date '+%H:%M:%S')" "$*" >> "$_EVD"
    eval "$@" >> "$_EVD" 2>&1
    printf '\n' >> "$_EVD"
}
_csv() { tr '\n' ',' | sed 's/,$//'; }
evd_file() {
    local item="$1" f="$2"
    if [ -f "$f" ] || [ -d "$f" ]; then
        printf '[%s] 파일: %s (존재)\n' "$item" "$f" >> "$_EVD"
    else
        printf '[%s] 파일: %s (미존재)\n' "$item" "$f" >> "$_EVD"
    fi
}

# 전체 파일시스템 탐색 시 네트워크/가상 파일시스템 제외 (NFS/CIFS/WSL 윈도우 드라이브 등)
_FP="( -fstype nfs -o -fstype nfs4 -o -fstype cifs -o -fstype smbfs -o -fstype 9p -o -fstype drvfs -o -fstype fuse.sshfs -o -fstype autofs -o -fstype proc -o -fstype sysfs ) -prune -o"
# ── 공통 함수 ────────────────────────────────────────────────────
get_perm() {
    local f="$1"; [ -e "$f" ] || [ -L "$f" ] || { echo ""; return; }
    if [ -L "$f" ]; then
        local rf; rf=$(readlink -f "$f" 2>/dev/null)
        [ -z "$rf" ] && rf=$(perl -MCwd -e 'print Cwd::abs_path($ARGV[0])' "$f" 2>/dev/null)
        [ -n "$rf" ] && [ -e "$rf" ] && f="$rf" || { echo ""; return; }
    fi
    case "$OS_FAMILY" in
    BSD)     stat -f "%Lp" "$f" 2>/dev/null ;;
    AIX|SOLARIS|HPUX) ls -lL "$f" 2>/dev/null | awk '{p=substr($1,2);r=0;for(i=1;i<=9;i++){c=substr(p,i,1);if(c!="-")r+=2^(9-i)};printf "%03o\n",r}' ;;
    *)       stat -c "%a" "$f" 2>/dev/null ;;
    esac
}
get_owner() {
    local f="$1"; [ -e "$f" ] || [ -L "$f" ] || { echo ""; return; }
    if [ -L "$f" ]; then
        local rf; rf=$(readlink -f "$f" 2>/dev/null)
        [ -z "$rf" ] && rf=$(perl -MCwd -e 'print Cwd::abs_path($ARGV[0])' "$f" 2>/dev/null)
        [ -n "$rf" ] && [ -e "$rf" ] && f="$rf" || { echo ""; return; }
    fi
    case "$OS_FAMILY" in
    BSD)     stat -f "%Su" "$f" 2>/dev/null ;;
    AIX|SOLARIS|HPUX) ls -lL "$f" 2>/dev/null | awk '{print $3}' ;;
    *)       stat -c "%U" "$f" 2>/dev/null ;;
    esac
}
is_running() {
    local svc="$1"
    command -v systemctl >/dev/null 2>&1 && systemctl is-active "$svc" 2>/dev/null | grep -q "^active" && return 0
    command -v service  >/dev/null 2>&1 && service "$svc" status 2>/dev/null | grep -qiE "running|started" && return 0
    command -v lssrc    >/dev/null 2>&1 && lssrc -s "$svc" 2>/dev/null | grep -qi "active" && return 0
    command -v svcs     >/dev/null 2>&1 && svcs -H "$svc" 2>/dev/null | grep -q "^online" && return 0
    ps -ef 2>/dev/null | grep -v grep | grep -qiw "$svc" && return 0
    command -v ps >/dev/null 2>&1 || { grep -qixF "$svc" /proc/[0-9]*/comm 2>/dev/null && return 0; }
    return 1
}
get_pam_files() {
    case "$OS_FAMILY" in
    AIX)     echo "/etc/security/user /etc/security/login.cfg" ;;
    SOLARIS) echo "/etc/pam.conf /etc/security/policy.conf /etc/default/login" ;;
    HPUX)    echo "/etc/pam.conf /etc/default/security" ;;
    *)
        case "$OS_DISTRO" in
        RHEL|CENTOS|ORACLE|AMZN)
            [ "${OS_MAJOR:-0}" -ge 8 ] 2>/dev/null && \
                echo "/etc/pam.d/system-auth /etc/pam.d/password-auth" || \
                echo "/etc/pam.d/system-auth /etc/pam.d/password-auth" ;;
        UBUNTU|DEBIAN) echo "/etc/pam.d/common-auth /etc/pam.d/common-password" ;;
        SLES)   echo "/etc/pam.d/common-auth /etc/pam.d/login" ;;
        *)
            for _pf in /etc/pam.d/system-auth /etc/pam.d/password-auth /etc/pam.d/common-auth /etc/pam.d/common-password; do
                [ -f "$_pf" ] && printf '%s ' "$_pf"
            done
            echo ;;
        esac ;;
    esac
}
pkg_installed() {
    local pkg="$1"
    case "$OS_FAMILY" in
    AIX)     lslpp -l "$pkg" >/dev/null 2>&1 ;;
    SOLARIS) pkginfo "$pkg" >/dev/null 2>&1 ;;
    HPUX)    swlist "$pkg" >/dev/null 2>&1 ;;
    *)
        case "$OS_DISTRO" in
        UBUNTU|DEBIAN) dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null | grep -q "install ok installed" ;;
        *)             rpm -q "$pkg" >/dev/null 2>&1 ;;
        esac ;;
    esac
}
pkg_update_available() {
    local pkg="$1"
    case "$OS_DISTRO" in
    UBUNTU|DEBIAN) command -v apt >/dev/null 2>&1 && apt list --upgradable "$pkg" 2>/dev/null | awk 'NR>1{print $1}' | grep -Eq "^${pkg}(/|$)" ;;
    *)  if command -v dnf >/dev/null 2>&1; then
            dnf -q check-update "$pkg" 2>/dev/null | grep -q "^$pkg"
        elif command -v yum >/dev/null 2>&1; then
            yum -q check-update "$pkg" 2>/dev/null | grep -q "^$pkg"
        else return 1; fi ;;
    esac
}
service_exists_any() {
    for svc in "$@"; do
        if command -v systemctl >/dev/null 2>&1; then
            systemctl list-unit-files --type=service 2>/dev/null | awk '{print $1}' | grep -qx "${svc}.service" && return 0
        fi
        [ -f "/etc/init.d/$svc" ] && return 0
    done
    return 1
}

# ================================================================
# SRV-001: 네트워크 모니터링 서비스 (SNMP 버전)
# ================================================================
# ── 6차 공통 헬퍼 (가이드 판단기준 대조) ──
_perm_over() {
    local p; p=$(printf '%03d' "${1: -3}" 2>/dev/null || echo "$1"); p="${p: -3}"
    [ -z "$p" ] && return 1
    (( (8#$p & ~8#$2 & 8#777) != 0 ))
}
_snmp_confs() {
    local f
    for f in /etc/snmp/snmpd.conf /etc/snmpd.conf /etc/snmpdv3.conf /etc/net-snmp/snmp/snmpd.conf /etc/sma/snmp/snmpd.conf /etc/SnmpAgent.d/snmpd.conf /etc/opt/snmp/snmpd.conf /etc/sfw/snmp/snmpd.conf; do
        [ -f "$f" ] && echo "$f"
    done
}
_named_conf() {
    local c
    for c in /etc/named.conf /etc/bind/named.conf; do
        [ -f "$c" ] || continue
        named-checkconf -p "$c" 2>/dev/null | tr '\n\t' '  ' | sed 's/"//g; s/;/;\n/g' && return
        cat "$c" /etc/bind/named.conf.options /etc/bind/named.conf.local 2>/dev/null | grep -vE '^\s*(//|#)'
        return
    done
}
# ── 8차 공통 헬퍼 (실무 스크립트·UNIX 실장비 결과 대조) ──
_TO=$(command -v timeout 2>/dev/null)
_to() { local s="$1"; shift; if [ -n "$_TO" ]; then "$_TO" "$s" "$@"; else "$@"; fi; }   # timeout 없는 AIX·HP-UX·Solaris 10 은 제한 없이 실행
_aix_default() { awk '/^default:/{f=1;next} /^[^ \t*#]/{f=0} f' /etc/security/user 2>/dev/null; }   # AIX default 스탠자 본문
_aix_attr() { awk -v s="$1" -v a="$2" '/^[^ \t*#][^ \t]*:[ \t]*$/{sub(/:.*/,"");st=$0;next} st==s && $0 ~ ("^[ \t]+" a "[ \t]*=") {sub(/^[^=]*=[ \t]*/,"");sub(/[ \t]+$/,"");print;exit}' "${3:-/etc/security/user}" 2>/dev/null; }
_inetd_on() {   # inetd(AIX·HP-UX·Solaris≤9) / SMF(Solaris 10+) / xinetd 로 기동되는 활성 서비스
    local s
    for s in "$@"; do
        [ -f /etc/inetd.conf ] && awk -v s="$s" '$0!~/^[ \t]*#/ && $1==s {print "inetd.conf:" s; exit}' /etc/inetd.conf 2>/dev/null
        [ "$OS_FAMILY" = "SOLARIS" ] && command -v inetadm >/dev/null 2>&1 && \
            inetadm 2>/dev/null | awk -v s="$s" '$1=="enabled" && $NF ~ ("^svc:/network/" s "([:/]|$)") {print "smf:" $NF}'
        [ -f "/etc/xinetd.d/$s" ] && grep -qiE '^[[:space:]]*disable[[:space:]]*=[[:space:]]*no' "/etc/xinetd.d/$s" 2>/dev/null && echo "xinetd:$s"
    done
}
_listen() { { ss -tln 2>/dev/null || netstat -an 2>/dev/null; } | awk -v p="$1" '/LISTEN/ {for(i=1;i<=NF;i++) if ($i ~ ("[.:]" p "$")) {print; exit}}'; }   # TCP LISTEN (Linux ':23' / UNIX '*.23')
_sshd_cfg() { local c; for c in /etc/ssh/sshd_config /opt/ssh/etc/sshd_config /usr/local/etc/sshd_config /etc/openssh/sshd_config; do [ -f "$c" ] && { echo "$c"; return; }; done; }
_sshd_bin() { local b; for b in $(command -v sshd 2>/dev/null) /usr/sbin/sshd /opt/ssh/sbin/sshd /usr/lib/ssh/sshd /usr/local/sbin/sshd; do [ -x "$b" ] && { echo "$b"; return; }; done; }
_snmp_run() { is_running snmpd && return 0; ps -ef 2>/dev/null | grep -v grep | grep -qE '[/ ](snmpd|snmpdm|snmpdv3ne|snmpdv3e)( |$)'; }   # HP-UX snmpdm, AIX snmpdv3 (cmsnmpd·dsm_sa_snmpd 제외)
_comm() { if [ "$OS_FAMILY" = HPUX ]; then UNIX95=1 ps -e -o comm= 2>/dev/null; else ps -e -o comm= 2>/dev/null; fi | sed 's#.*/##'; }
_ftp_running() { is_running vsftpd || is_running proftpd || is_running pure-ftpd || is_running in.ftpd || is_running ftpd || [ -n "$(_inetd_on ftp)" ] || [ -n "$(_listen 21)" ]; }

check_SRV001() {
    # 평가기준: v2 이용 시(v3 사용 가능 환경) 취약, v3 사용 시 보안레벨 AuthPriv — net-snmp 문법(rocommunity/rwcommunity/com2sec)
    local confs; confs=$(_snmp_confs)
    evd "SRV-001" "for f in $(echo $confs); do echo \"# \$f\"; grep -vE '^\s*(#|\$)' \$f | head -20; done"
    evd "SRV-001" "ps -ef 2>/dev/null | grep -iE '[s]nmp'; lssrc -s snmpd 2>/dev/null; ls -l /var/lib/net-snmp/snmpd.conf /var/lib/snmp/snmpd.conf 2>/dev/null; grep -ciE '^\s*(usmUser|createUser)' /var/lib/net-snmp/snmpd.conf /var/lib/snmp/snmpd.conf 2>/dev/null"
    if [ -z "$confs" ] && ! _snmp_run; then result "SRV-001|N-A|SNMP 미설치/미실행"; return; fi
    _snmp_run || { result "SRV-001|N-A|SNMP 설정 파일은 있으나 snmpd 미실행"; return; }
    local v2 v3 v3weak
    v2=$(cat $confs 2>/dev/null | grep -vE '^\s*#' | grep -iE '^\s*(rocommunity6?|rwcommunity6?|com2sec6?|community)\s|^\s*(get|set)-community-name\s*:' | head -3)
    v3=$(cat $confs 2>/dev/null | grep -vE '^\s*#' | grep -iE '^\s*(rouser|rwuser|createUser)\s|^\s*access\s.*\susm\s|^\s*USM_USER' | head -5)
    v3weak=$(cat $confs 2>/dev/null | grep -vE '^\s*#' | grep -iE '^\s*(rouser|rwuser)\s+\S+(\s+(noauth|auth)\b|\s*$)|^\s*access\s.*\susm\s+(noauth|auth)\b|^\s*VACM_ACCESS\s.*\b(noAuthNoPriv|AuthNoPriv)\b|^\s*USM_USER\s+(\S+\s+){5}(-|none)\b' | head -3)
    if [ -n "$v2" ]; then result "SRV-001|취약|SNMP v1/v2c 사용: $(echo "$v2" | head -1 | awk '{print $1}') (v3 사용 가능 환경에서 v2 이용)"
    elif [ -n "$v3weak" ]; then result "SRV-001|취약|SNMPv3 보안레벨 AuthPriv 미적용: $(echo "$v3weak" | head -1)"
    elif [ -n "$v3" ]; then result "SRV-001|양호|SNMPv3 AuthPriv(priv) 사용"
    else result "SRV-001|수동확인|snmpd 실행 중 - 버전·보안레벨 설정 수동 확인 ($(echo $confs))"; fi
}

# ================================================================
# SRV-003: SNMP 접근통제 (ACL)
# ================================================================
check_SRV003() {
    # 평가기준 판단방법: rocommunity/rwcommunity/com2sec 출발지(source) 제한, 'rocommunity public' 출발지 없음 = 통제 미흡
    local confs; confs=$(_snmp_confs)
    evd "SRV-003" "grep -hiE '^\s*(agentAddress|rocommunity|rwcommunity|com2sec|group|view|access|rouser|rwuser|createUser)' $(echo ${confs:-/dev/null}) 2>/dev/null"
    if [ -z "$confs" ] || ! _snmp_run; then result "SRV-003|N-A|SNMP 미실행"; return; fi
    local open
    open=$(cat $confs 2>/dev/null | grep -vE '^\s*#' | awk 'tolower($1)~/^r[ow]community6?$/ && ($3=="" || $3=="default" || $3=="0.0.0.0/0" || $3=="::/0"){print $1" "$2} tolower($1)~/^com2sec6?$/ && ($3=="default" || $3=="0.0.0.0/0"){print $1" "$2" "$3}' | head -3)
    # HP-UX get/set-community-name 에 IP: 미지정 = 출발지 무제한, AIX community 주소·마스크 0.0.0.0 = 전체 허용
    [ "$OS_FAMILY" = "HPUX" ] && open="${open}$(cat $confs 2>/dev/null | grep -vE '^\s*#' | grep -iE '^\s*(get|set)-community-name\s*:' | grep -viE '\bIP:' | awk '{print $1" "$2}' | head -2)"
    [ "$OS_FAMILY" = "AIX" ] && open="${open}$(cat $confs 2>/dev/null | grep -vE '^\s*#' | awk 'tolower($1)=="community" && (($3=="0.0.0.0"&&$4=="0.0.0.0") || ($5=="0.0.0.0"&&$6=="0.0.0.0")){print $1" "$2}' | head -2)"
    if [ -n "$open" ]; then result "SRV-003|취약|출발지 제한 없는 community: $(echo "$open" | awk '{print $1" "substr($2,1,2)"***"}' | tr '\n' ',' | sed 's/,$//')"
    elif cat $confs 2>/dev/null | grep -vE '^\s*#' | grep -qiE '^\s*(rocommunity|rwcommunity|com2sec|rouser|rwuser|(get|set)-community-name)'; then result "SRV-003|양호|SNMP 접근 출발지 지정 또는 v3 사용자 인증"
    else result "SRV-003|수동확인|SNMP 접근통제 설정 수동 확인 ($(echo $confs))"; fi
}

# ================================================================
# SRV-004: SMTP 서비스 비활성화
# ================================================================
check_SRV004() {
    evd "SRV-004" "ps -ef 2>/dev/null | grep -E 'sendmail|postfix|exim' | grep -v grep"
    evd "SRV-004" "ss -tlnp 2>/dev/null | grep ':25 ' || netstat -tlnp 2>/dev/null | grep ':25 '"
    is_running sendmail || is_running postfix || is_running exim || \
        netstat -tlnp 2>/dev/null | grep -q ":25 " || \
        ss -tlnp 2>/dev/null | grep -q ":25 " && \
        result "SRV-004|수동확인|SMTP 서비스 실행 중 (업무상 필요 여부 확인)" && return
    result "SRV-004|양호|SMTP 서비스 미실행"
}

# ================================================================
# SRV-011: 시스템 관리자 FTP 접속 제한
# ================================================================
check_SRV011() {
    evd "SRV-011" "cat /etc/ftpusers /etc/ftpd/ftpusers /etc/vsftpd/ftpusers /etc/vsftpd.ftpusers 2>/dev/null; grep -vE '^\s*#' /etc/inetd.conf 2>/dev/null | grep -w ftp; inetadm 2>/dev/null | grep -i ftp; lssrc -ls inetd 2>/dev/null | grep -i ftp"
    for f in /etc/ftpusers /etc/ftpd/ftpusers /etc/vsftpd/ftpusers /etc/vsftpd.ftpusers; do
        [ -f "$f" ] || continue
        if grep -q "^root" "$f" 2>/dev/null; then
            result "SRV-011|양호|FTP root 계정 제한 (${f})"
        else
            result "SRV-011|취약|FTP root 제한 미설정 (${f})"
        fi
        return
    done
    _ftp_running || { evd "SRV-011" "ps -ef 2>/dev/null | grep -E 'vsftpd|proftpd|ftpd' | grep -v grep"; result "SRV-011|N-A|FTP 서비스 미실행"; return; }
    result "SRV-011|취약|ftpusers 파일 없음 (root FTP 접속 제한 불가)"
}

# ================================================================
# SRV-013: Anonymous FTP 제한
# ================================================================
check_SRV013() {
    evd "SRV-013" "grep -i anonymous /etc/vsftpd/vsftpd.conf /etc/vsftpd.conf /etc/proftpd/proftpd.conf /etc/proftpd.conf 2>/dev/null; grep '^ftp:' /etc/passwd 2>/dev/null"
    # 평가기준: FTP 미사용 또는 Anonymous 비활성 → 양호
    _ftp_running || { result "SRV-013|양호|FTP 서비스 미사용"; return; }
    local f
    for f in /etc/vsftpd/vsftpd.conf /etc/vsftpd.conf; do
        [ -f "$f" ] || continue
        grep -qiE "^\s*anonymous_enable\s*=\s*YES" "$f" 2>/dev/null && { result "SRV-013|취약|Anonymous FTP 활성화 (${f})"; return; }
        grep -qiE "^\s*anonymous_enable\s*=" "$f" 2>/dev/null || { result "SRV-013|취약|anonymous_enable 미설정 (vsftpd 기본값 YES) (${f})"; return; }
        result "SRV-013|양호|Anonymous FTP 비활성화 (${f})"; return
    done
    for f in /etc/proftpd/proftpd.conf /etc/proftpd.conf; do
        [ -f "$f" ] || continue
        grep -vE '^\s*#' "$f" 2>/dev/null | grep -qi "<Anonymous" && { result "SRV-013|취약|proftpd <Anonymous> 블록 활성 (${f})"; return; }
        result "SRV-013|양호|proftpd Anonymous 미설정 (${f})"; return
    done
    grep -q "^ftp:" /etc/passwd 2>/dev/null && result "SRV-013|취약|ftpd 실행 중이며 ftp(anonymous) 계정 존재" || result "SRV-013|수동확인|FTP 실행 중 - Anonymous 설정 수동 확인"
}

# ================================================================
# SRV-014: NFS 접근통제
# ================================================================
check_SRV014() {
    evd "SRV-014" "ls -l /etc/exports /etc/dfs/dfstab 2>/dev/null; cat /etc/exports /etc/dfs/dfstab 2>/dev/null"
    local exports_file="/etc/exports"
    [ "$OS_FAMILY" = "SOLARIS" ] && exports_file="/etc/dfs/dfstab"
    [ "$OS_FAMILY" = "HPUX" ] && [ -z "$(grep -vE '^\s*(#|$)' /etc/exports 2>/dev/null)" ] && [ -f /etc/dfs/dfstab ] && exports_file="/etc/dfs/dfstab"   # HP-UX 11iv3 share 명령
    evd "SRV-014" "share 2>/dev/null; cat /etc/dfs/sharetab 2>/dev/null; exportfs 2>/dev/null"
    # 평가기준: NFS 비활성화 또는 적절한 접근통제 → 양호
    { [ -f "$exports_file" ] && [ -n "$(grep -vE '^\s*(#|$)' "$exports_file" 2>/dev/null)" ]; } || { result "SRV-014|양호|NFS 공유 미사용 (${exports_file} 설정 없음)"; return; }
    { is_running nfsd || is_running rpc.nfsd || is_running mountd || is_running rpc.mountd || { command -v systemctl >/dev/null 2>&1 && systemctl is-active nfs-server 2>/dev/null | grep -q '^active'; }; } || \
        { result "SRV-014|양호|NFS 서비스 비활성 (${exports_file} 설정은 존재 - 참고)"; return; }
    local bad="" p o
    if [ "$exports_file" = "/etc/dfs/dfstab" ]; then
        bad=$(grep -vE '^\s*(#|$)' "$exports_file" | grep -vE 'rw=|ro=|access=' | head -2)
    else
        bad=$(grep -vE '^\s*(#|$)' "$exports_file" | awk '{ if (NF<2) {print; next} for(i=2;i<=NF;i++){ h=$i; sub(/\(.*/,"",h); if (h=="" || h=="*" || h=="0.0.0.0/0") {print; break} } }' | head -2)
    fi
    p=$(get_perm "$exports_file"); o=$(get_owner "$exports_file")
    { [ "$o" != "root" ] || _perm_over "$p" 644; } && bad="${bad:+$bad / }${exports_file}(${o}:${p})"
    [ -n "$bad" ] && result "SRV-014|취약|NFS 접근통제 미흡: $(echo "$bad" | head -2 | tr '\n' ' ')" || result "SRV-014|양호|NFS 공유 호스트 지정·설정 파일 root 644 이하"
}

# ================================================================
# SRV-015: 불필요 NFS 비활성화
# ================================================================
check_SRV015() {
    evd "SRV-015" "ps -ef 2>/dev/null | grep -E 'nfsd|nfs-server' | grep -v grep"
    is_running nfs || is_running nfsd || is_running nfs-server || \
        is_running nfs-kernel-server && \
        result "SRV-015|수동확인|NFS 서비스 실행 중 (업무상 필요 여부 확인)" && return
    result "SRV-015|양호|NFS 서비스 미실행"
}

# ================================================================
# SRV-016: 불필요 RPC 비활성화
# ================================================================
check_SRV016() {
    # 평가기준 15종: rpc.cmsd, rpc.ttdbserverd, sadmind, rusersd, walld, sprayd, rstatd, rpc.nisd, rexd, rpc.pcnfsd, rpc.statd, rpc.ypupdated, rpc.rquotad, kcms_server, cachefsd (업무상 사용 시 예외)
    evd "SRV-016" "rpcinfo -p 2>/dev/null | head -30; ps -ef 2>/dev/null | grep -E 'rpc\.|sadmind|rusersd|walld|sprayd|rstatd|rexd|kcms|cachefsd' | grep -v grep"
    local s bad="" nfs=""
    for s in rpc.cmsd rpc.ttdbserverd sadmind rusersd rpc.rusersd walld rpc.rwalld sprayd rpc.sprayd rstatd rpc.rstatd rpc.nisd rexd rpc.rexd rpc.pcnfsd rpc.ypupdated kcms_server cachefsd; do
        is_running "$s" && bad="${bad} ${s}"
    done
    for s in rpc.statd rpc.rquotad; do is_running "$s" && nfs="${nfs} ${s}"; done
    local rp; rp=$(rpcinfo -p 2>/dev/null | awk '{print $NF}' | grep -E '^(cmsd|ttdbserverd|sadmind|rusersd|walld|sprayd|rstatd|nisd|rexd|pcnfsd|ypupdated)$' | sort -u | tr '\n' ' ')
    [ -n "$rp" ] && bad="${bad} [rpcinfo:${rp% }]"
    local inet; inet=$(grep -vE '^[[:space:]]*#' /etc/inetd.conf 2>/dev/null | grep -oE 'rpc\.(cmsd|ttdbserverd|rusersd|rwalld|sprayd|rstatd|rexd|pcnfsd|ypupdated)|sadmind|kcms_server|cachefsd' | sort -u | tr '\n' ' ')
    [ -n "$inet" ] && bad="${bad} [inetd.conf:${inet% }]"
    if [ "$OS_FAMILY" = "SOLARIS" ]; then
        inet=$(_inetd_on rpc/rstat rpc/rusers rpc/spray rpc/wall rpc/rex rpc/cde-calendar-manager rpc/cde-ttdbserver | sed -n 's/^smf://p' | tr '\n' ' ')
        [ -n "$inet" ] && bad="${bad} [${inet% }]"
    fi
    if [ -n "$bad" ]; then result "SRV-016|취약|불필요 RPC 서비스 활성:${bad}"
    elif [ -n "$nfs" ]; then result "SRV-016|수동확인|NFS 동반 RPC 서비스 실행:${nfs} - 업무상 사용 여부 확인"
    else result "SRV-016|양호|기준 RPC 서비스(cmsd·ttdbserverd·sadmind 등 15종) 미실행"; fi
}

# ================================================================
# SRV-022: 패스워드 미설정 계정 관리
# ================================================================
check_SRV022() {
    evd "SRV-022" "awk -F: '\$2==\"\"' /etc/shadow 2>/dev/null || awk -F: '\$2==\"\"' /etc/passwd 2>/dev/null"
    case "$OS_FAMILY" in
    AIX)   # AIX 패스워드 파일 = /etc/security/passwd (스탠자 password = 공란)
        no_pw=$(awk '/^[^ \t*#][^ \t]*:[ \t]*$/{sub(/:.*/,"");u=$0;next} /^[ \t]+password[ \t]*=/{v=$0;sub(/^[^=]*=[ \t]*/,"",v);sub(/[ \t]+$/,"",v); if(v=="") print u}' /etc/security/passwd 2>/dev/null | head -5)
        ;;
    HPUX|SOLARIS)
        no_pw=$( { [ -f /etc/shadow ] && awk -F: '$2 == "" {print $1}' /etc/shadow 2>/dev/null; logins -p 2>/dev/null | awk '{print $1"(logins -p)"}'; } | sort -u | head -5)
        ;;
    *)
        [ -f /etc/shadow ] && \
            no_pw=$(awk -F: '$2 == "" {print $1}' /etc/shadow 2>/dev/null | head -5) || \
            no_pw=$(awk -F: '$2 == "" {print $1}' /etc/passwd 2>/dev/null | head -5)
        ;;
    esac
    _pwe=$(awk -F: '$2=="" && $1!="" {print $1"(passwd 필드 공란)"}' /etc/passwd 2>/dev/null | head -5)
    [ -n "$_pwe" ] && no_pw="$(printf '%s\n%s' "$no_pw" "$_pwe" | grep -v '^$')"
    [ -n "$no_pw" ] && result "SRV-022|취약|비밀번호 미설정 계정: $(echo "$no_pw" | _csv)" || \
        result "SRV-022|양호|비밀번호 미설정 계정 없음"
}

# ================================================================
# SRV-025: hosts.equiv / .rhosts 설정 제한
# ================================================================
check_SRV025() {
    evd "SRV-025" "ls -la /etc/hosts.equiv /root/.rhosts /.rhosts 2>/dev/null"
    evd "SRV-025" "cat /etc/hosts.equiv /root/.rhosts 2>/dev/null"
    # 기준: 파일이 없거나 신뢰 호스트 목록만 있으면 양호, '+' 설정·불필요 계정/호스트가 있으면 취약
    local plus="" entries="" f
    for f in /etc/hosts.equiv /.rhosts $(awk -F: '$6!=""&&$6!="/"{print $6"/.rhosts"}' /etc/passwd 2>/dev/null | sort -u); do
        [ -f "$f" ] || continue
        grep -vE '^[[:space:]]*(#|$)' "$f" 2>/dev/null | grep -qE '(^|[[:space:]])\+' && plus="${plus} ${f}"
        [ -n "$(grep -vE '^[[:space:]]*(#|$)' "$f" 2>/dev/null)" ] && entries="${entries} ${f}($(grep -cvE '^[[:space:]]*(#|$)' "$f" 2>/dev/null)줄)"
    done
    if [ -n "$plus" ]; then result "SRV-025|취약|'+' 설정(모든 호스트/계정 신뢰) 존재:${plus}"
    elif [ -n "$entries" ]; then result "SRV-025|수동확인|신뢰 호스트 등록:${entries} - 불필요 계정/호스트 여부 확인"
    else result "SRV-025|양호|hosts.equiv/.rhosts 미존재 또는 설정 없음(주석만)"; fi
}

# ================================================================
# SRV-026: root 원격 접속 제한
# ================================================================
check_SRV026() {
    evd "SRV-026" "grep -i PermitRootLogin /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null; sshd -T 2>/dev/null | grep -i '^permitrootlogin'; ssh -V 2>&1; cat /etc/securetty 2>/dev/null | grep -E '^pts' | head -3"
    case "$OS_FAMILY" in
    AIX)
        # 평가기준(AIX): rlogin 사용 시 root rlogin=true, SSH 사용 시 PermitRootLogin yes → 하나라도 해당하면 취약
        val=$(awk '/^root:/{f=1;next} /^[^ \t*]/{f=0} f&&/rlogin/{sub(/.*=[ \t]*/,"");print;exit}' /etc/security/user 2>/dev/null)
        [ -z "$val" ] && val=$(awk '/^default:/{f=1;next} /^[^ \t*]/{f=0} f&&/rlogin/{sub(/.*=[ \t]*/,"");print;exit}' /etc/security/user 2>/dev/null)
        ssh_root=$(grep -iE "^\s*PermitRootLogin" "$(_sshd_cfg)" 2>/dev/null | awk '{print $2}' | head -1)
        if [ "${val:-true}" != "false" ]; then result "SRV-026|취약|AIX root rlogin=${val:-true(기본)}${ssh_root:+, SSH PermitRootLogin=${ssh_root}}"
        elif [ "${ssh_root,,}" = "yes" ]; then result "SRV-026|취약|AIX SSH PermitRootLogin=yes"
        else result "SRV-026|양호|AIX root rlogin=false, SSH PermitRootLogin=${ssh_root:-미설정(기본)}"; fi ;;
    SOLARIS)
        # 평가기준(Solaris): Telnet — /etc/default/login CONSOLE=/dev/console 없음/주석 이면 취약, SSH — PermitRootLogin yes 취약
        cons=$(grep -v "^#" /etc/default/login 2>/dev/null | grep "^CONSOLE")
        ssh_root=$(grep -iE "^\s*PermitRootLogin" "$(_sshd_cfg)" 2>/dev/null | awk '{print $2}' | head -1)
        if [ -z "$cons" ]; then result "SRV-026|취약|Solaris CONSOLE=/dev/console 미설정 (Telnet root 원격 접속 가능)${ssh_root:+, PermitRootLogin=${ssh_root}}"
        elif [ "${ssh_root,,}" = "yes" ]; then result "SRV-026|취약|Solaris SSH PermitRootLogin=yes"
        else result "SRV-026|양호|Solaris CONSOLE 제한, SSH PermitRootLogin=${ssh_root:-미설정}"; fi ;;
    HPUX)
        # 평가기준(HP-UX): Telnet 사용 시 /etc/securetty 없음·console 주석 → 취약, SSH PermitRootLogin yes → 취약
        local cf tel="" val sb; cf=$(_sshd_cfg); sb=$(_sshd_bin)
        evd "SRV-026" "grep -i PermitRootLogin $cf 2>/dev/null; cat /etc/securetty 2>/dev/null"
        [ -n "$sb" ] && val=$("$sb" -T 2>/dev/null | awk 'tolower($1)=="permitrootlogin"{print $2}')
        [ -z "$val" ] && val=$(grep -iE '^\s*PermitRootLogin' "$cf" 2>/dev/null | awk '{print $2}' | head -1)
        if is_running telnetd || [ -n "$(_inetd_on telnet; _listen 23)" ]; then
            grep -qE '^[[:space:]]*console[[:space:]]*$' /etc/securetty 2>/dev/null || tel="Telnet 사용 중 /etc/securetty console 미설정"
        fi
        if [ -n "$tel" ] || [ "${val,,}" = "yes" ]; then result "SRV-026|취약|HP-UX ${tel}${tel:+, }SSH PermitRootLogin=${val:-미확인} (${cf:-sshd_config 미발견})"
        elif [ -z "$val" ]; then result "SRV-026|수동확인|HP-UX PermitRootLogin 미설정·sshd -T 불가 (${cf:-sshd_config 미발견}) - 기본값 확인(HP-UX Secure Shell 구버전 기본 yes)"
        else result "SRV-026|양호|HP-UX PermitRootLogin=${val}, Telnet root 제한"; fi ;;
    *)
        # 평가기준: SSH는 PermitRootLogin yes 일 때만 취약, Telnet 사용 시 securetty 의 pts 허용 여부
        local src="sshd -T" val=""
        val=$(sshd -T 2>/dev/null | awk 'tolower($1)=="permitrootlogin"{print $2}' | tail -1)
        if [ -z "$val" ]; then
            src="설정파일"
            [ -d /etc/ssh/sshd_config.d ] && val=$(grep -rih "^\s*PermitRootLogin" /etc/ssh/sshd_config.d/ 2>/dev/null | awk '{print $2}' | head -1)
            [ -z "$val" ] && val=$(grep -i "^\s*PermitRootLogin" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' | head -1)
        fi
        local telnet_vuln=""
        if is_running telnetd || is_running in.telnetd || [ -n "$(_inetd_on telnet; _listen 23)" ]; then
            { [ ! -f /etc/securetty ] || grep -qE '^pts' /etc/securetty 2>/dev/null; } && telnet_vuln=" / Telnet 사용 중 securetty pts 허용"
        fi
        if [ -z "$val" ]; then
            local ov; ov=$( { ssh -V 2>&1; sshd -V 2>&1; rpm -q openssh-server 2>/dev/null; dpkg-query -W -f='OpenSSH_${Version}' openssh-server 2>/dev/null; } | grep -oE 'OpenSSH_[0-9]+\.[0-9]+|openssh-server-[0-9]+\.[0-9]+|OpenSSH_1:[0-9]+\.[0-9]+' | head -1 | grep -oE '[0-9]+\.[0-9]+$')
            if [ -n "$ov" ] && [ "${ov%%.*}" -ge 7 ] 2>/dev/null; then val="prohibit-password"; src="OpenSSH ${ov} 기본값"; fi
        fi
        case "${val,,}" in
        yes) result "SRV-026|취약|PermitRootLogin=yes (${src}) - root 원격 접속 허용${telnet_vuln}" ;;
        no|prohibit-password|without-password|forced-commands-only)
            [ -n "$telnet_vuln" ] && result "SRV-026|취약|PermitRootLogin=${val} (${src})${telnet_vuln}" \
                                  || result "SRV-026|양호|PermitRootLogin=${val} (${src})" ;;
        "") [ -n "$telnet_vuln" ] && result "SRV-026|취약|${telnet_vuln# / }" \
                                  || result "SRV-026|수동확인|PermitRootLogin 확인 불가 (sshd -T 실패, 설정 없음, OpenSSH 버전 미확인)" ;;
        *)  result "SRV-026|수동확인|PermitRootLogin=${val} (${src})" ;;
        esac ;;
    esac
}

# ================================================================
# SRV-027: 서비스 접근 IP/포트 제한 (TCP Wrapper / firewall)
# ================================================================
check_SRV027() {
    # 평가기준: 방화벽·tcp-wrapper·3rd-party 로 서비스 접근통제 — 규칙 유무로 판단, 없으면 상위 방화벽 등 확인(수동확인)
    evd "SRV-027" "grep -vE '^\s*(#|\$)' /etc/hosts.allow /etc/hosts.deny 2>/dev/null; grep -vE '^\s*(#|\$)' /var/adm/inetd.sec 2>/dev/null; ipfstat -io 2>/dev/null | head -20; inetadm -p 2>/dev/null | grep tcp_wrappers; lsfilt -a 2>/dev/null | head -20"
    evd "SRV-027" "firewall-cmd --list-all 2>/dev/null; ufw status numbered 2>/dev/null; iptables -S 2>/dev/null | head -40; nft list ruleset 2>/dev/null | head -40"
    local tw=0 fw="" n
    [ -n "$(grep -vE '^\s*(#|$)' /etc/hosts.allow /etc/hosts.deny 2>/dev/null)" ] && tw=1
    if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state 2>/dev/null | grep -q running; then
        n=$( { firewall-cmd --list-rich-rules 2>/dev/null; firewall-cmd --list-sources 2>/dev/null | tr ' ' '\n'; } | grep -c . ); fw="firewalld(zone=$(firewall-cmd --get-default-zone 2>/dev/null), rich/source ${n})"
    elif command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
        n=$(ufw status numbered 2>/dev/null | grep -c "^\["); [ "$n" -gt 0 ] && fw="ufw(${n} rules)"
    fi
    if [ -z "$fw" ]; then
        n=$(iptables -S 2>/dev/null | grep -c '^-A'); [ "${n:-0}" -gt 0 ] && fw="iptables(${n} rules)"
        [ -z "$fw" ] && { n=$(nft list ruleset 2>/dev/null | grep -cE '^\s+(ip|tcp|udp|iif|oif|meta|ct)\s'); [ "${n:-0}" -gt 0 ] && fw="nftables(${n} rules)"; }
        [ -z "$fw" ] && iptables -S 2>/dev/null | grep -qE '^-P INPUT (DROP|REJECT)' && fw="iptables(INPUT 기본 DROP)"
    fi
    if [ -n "$fw" ] || [ $tw -eq 1 ]; then result "SRV-027|양호|접근통제 규칙 존재 (tcp-wrapper=$([ $tw -eq 1 ] && echo 설정 || echo 없음), 방화벽=${fw:-없음})"
    else result "SRV-027|수동확인|호스트 방화벽·tcp-wrapper 규칙 없음 - 상위 방화벽·3rd-party 접근통제 여부 확인 (미통제 시 취약)"; fi
}

# ================================================================
# SRV-028: 원격 터미널 접속 타임아웃
# ================================================================
check_SRV028() {
    evd "SRV-028" "grep -rh 'TMOUT\\|tmout' /etc/profile /etc/bashrc /etc/bash.bashrc /etc/profile.d/ /root/.bashrc /root/.profile 2>/dev/null | grep -v '^#'"
    tmout=""
    for f in /etc/profile /etc/bashrc /etc/bash.bashrc /etc/environment \
              /root/.bashrc /root/.profile /etc/profile.d/*.sh; do
        [ -f "$f" ] || continue
        t=$(grep -h "TMOUT\|tmout" "$f" 2>/dev/null | grep -v "^\s*#" | grep -oE "[0-9]+" | head -1)
        [ -n "$t" ] && tmout=$t && break
    done
    case "$OS_FAMILY" in
    SOLARIS) [ -z "$tmout" ] && tmout=$(grep "^TIMEOUT" /etc/default/login 2>/dev/null | cut -d= -f2 | tr -d ' ') ;;
    AIX)     [ -z "$tmout" ] && tmout=$(grep "^TMOUT\|^tmout" /etc/profile /etc/environment 2>/dev/null | grep -oE "[0-9]+" | head -1) ;;
    esac
    # 평가기준: 900초(15분) 이하 양호 (내부 규정이 더 짧으면 그 기준 적용 - 수동 확인)
    if [ -z "$tmout" ] || [ "$tmout" = "0" ]; then
        result "SRV-028|취약|TMOUT 미설정 (세션 타임아웃 없음)"
    elif [ "$tmout" -le 900 ] 2>/dev/null; then
        result "SRV-028|양호|TMOUT=${tmout}초 (900초 이하, 내부 규정이 더 짧으면 그 기준으로 확인)"
    else
        result "SRV-028|취약|TMOUT=${tmout}초 (900초 초과)"
    fi
}

# ================================================================
# SRV-034: 불필요한 서비스 비활성화 (finger/chargen/daytime 등)
# ================================================================
check_SRV034() {
    # 평가기준(LINUX 등): 취약한 버전의 automountd 서비스가 불필요하게 활성화 / Solaris 는 dmi 서비스 추가
    evd "SRV-034" "ps -ef 2>/dev/null | grep -E 'autofs|automount|dmispd|snmpXdmid' | grep -v grep; grep -v '^#' /etc/inetd.conf 2>/dev/null | grep -i automount; systemctl is-active autofs 2>/dev/null; automount -V 2>/dev/null | head -1"
    local am="" dmi=""
    { is_running automount || is_running automountd || is_running autofs || grep -v '^#' /etc/inetd.conf 2>/dev/null | grep -qi automount || \
      { command -v systemctl >/dev/null 2>&1 && systemctl is-active autofs 2>/dev/null | grep -q '^active'; }; } && am="automount($(automount -V 2>/dev/null | head -1 | grep -oE '[0-9]+(\.[0-9]+)+' || echo 버전미확인))"
    [ "$OS_FAMILY" = "SOLARIS" ] && { is_running dmispd || is_running snmpXdmid; } && dmi="dmi(dmispd/snmpXdmid)"
    if [ -n "$dmi" ]; then result "SRV-034|취약|DMI 서비스 활성: ${dmi}${am:+ / $am}"
    elif [ -n "$am" ]; then result "SRV-034|수동확인|${am} 활성 - 업무상 필요 여부·취약 버전 여부 확인"
    else result "SRV-034|양호|automountd 서비스 비활성"; fi
}

# ================================================================
# SRV-035: 취약 서비스 비활성화 (telnet 등)
# ================================================================
check_SRV035() {
    # 평가기준: tftp·talk·ntalk / finger / rexec·rlogin·rsh / echo·discard·daytime·chargen / NIS·NIS+ (tftp 는 백업솔루션 필수 시 예외)
    evd "SRV-035" "grep -vE '^\s*#' /etc/inetd.conf 2>/dev/null | grep -E 'tftp|talk|finger|exec|login|shell|echo|discard|daytime|chargen'; ls /etc/xinetd.d 2>/dev/null; ps -ef 2>/dev/null | grep -E 'tftp|talk|finger|rexec|rlogin|rsh|ypserv|ypbind|yppasswdd|nisd' | grep -v grep"
    local found="" tftp="" s
    for s in talkd in.talkd ntalkd in.ntalkd fingerd in.fingerd rexecd in.rexecd rlogind in.rlogind rshd in.rshd ypserv ypbind yppasswdd rpc.nisd; do
        is_running "$s" && found="${found} ${s}"
    done
    { is_running tftpd || is_running in.tftpd || ss -uln 2>/dev/null | grep -q ':69 '; } && tftp="tftp"
    if command -v systemctl >/dev/null 2>&1; then
        for s in chargen daytime discard echo rsh rlogin rexec finger tftp talk ntalk; do
            systemctl is-active "${s}.socket" 2>/dev/null | grep -q "^active" && { [ "$s" = tftp ] && tftp="tftp" || found="${found} ${s}.socket"; }
        done
    fi
    local act; act=$(grep -vE '^\s*#' /etc/inetd.conf 2>/dev/null | awk '{print $1}' | grep -E '^(tftp|talk|ntalk|finger|exec|login|shell|echo|discard|daytime|chargen)$' | tr '\n' ' ')
    for s in $act; do [ "$s" = tftp ] && tftp="tftp" || found="${found} [inetd:${s}]"; done
    if [ "$OS_FAMILY" = "SOLARIS" ]; then
        for s in $(_inetd_on tftp talk finger login shell rexec echo discard daytime chargen | sed -n 's/^smf://p'); do
            case "$s" in */tftp/*|*/tftp:*) tftp="tftp" ;; *) found="${found} [smf:${s#svc:/network/}]" ;; esac
        done
        evd "SRV-035" "inetadm 2>/dev/null | grep -E 'tftp|talk|finger|login|shell|rexec|echo|discard|daytime|chargen'"
    fi
    if [ -d /etc/xinetd.d ]; then
        for s in /etc/xinetd.d/*; do
            [ -f "$s" ] || continue
            grep -qiE 'disable\s*=\s*no' "$s" 2>/dev/null || continue
            case "$(basename "$s")" in tftp*) tftp="tftp" ;; chargen*|daytime*|discard*|echo*|rsh|rlogin|rexec|finger|talk|ntalk) found="${found} [xinetd:$(basename "$s")]" ;; esac
        done
    fi
    if [ -n "$found" ]; then result "SRV-035|취약|취약 서비스 활성:${found}${tftp:+ / tftp}"
    elif [ -n "$tftp" ]; then result "SRV-035|수동확인|tftp 서비스 활성 - OS 백업솔루션 필수 사용 여부 확인 (불필요 시 취약)"
    else result "SRV-035|양호|tftp·talk·finger·r계열·echo/chargen 등·NIS 서비스 미실행"; fi
}

# ================================================================
# SRV-062: DNS 정보 노출 방지 (버전 노출)
# ================================================================
check_SRV062() {
    is_running named || { evd "SRV-062" "ps -ef 2>/dev/null | grep named | grep -v grep"; result "SRV-062|N-A|DNS 서비스 미실행"; return; }
    local nc; nc=$(_named_conf)
    evd "SRV-062" "echo '$(echo "$nc" | grep -iE 'version' | head -3)'"
    [ -z "$nc" ] && { result "SRV-062|수동확인|named.conf 위치 확인 필요"; return; }
    echo "$nc" | grep -qiE '(^|[[:space:]])version\s+("[^0-9"]*"|[^0-9;"]*)\s*;' && result "SRV-062|양호|DNS 버전 노출 차단 (version 문자열 대체)" || result "SRV-062|취약|DNS 버전 노출 차단 미설정 (version \"none\" 권고)"
}

# ================================================================
# SRV-066: DNS Zone Transfer 제한
# ================================================================
check_SRV066() {
    is_running named || { evd "SRV-066" "ps -ef 2>/dev/null | grep named | grep -v grep"; result "SRV-066|N-A|DNS 미실행"; return; }
    local nc; nc=$(_named_conf)
    evd "SRV-066" "echo '$(echo "$nc" | grep -iE 'allow-transfer' | head -5)'"
    [ -z "$nc" ] && { result "SRV-066|수동확인|named.conf 수동 확인"; return; }
    if echo "$nc" | grep -qiE 'allow-transfer\s*\{\s*any\s*;'; then result "SRV-066|취약|allow-transfer { any; } - 모든 호스트 Zone Transfer 허용"
    elif echo "$nc" | grep -qiE 'allow-transfer'; then result "SRV-066|양호|Zone Transfer 허용 대상 지정: $(echo "$nc" | grep -ioE 'allow-transfer\s*\{[^}]*\}' | head -1)"
    else result "SRV-066|취약|allow-transfer 미설정 (Zone Transfer 제한 없음)"; fi
}

# ================================================================
# SRV-063: DNS Recursive Query 제한 설정 여부
# ================================================================
check_SRV063() {
    is_running named || { evd "SRV-063" "ps -ef 2>/dev/null | grep named | grep -v grep"; result "SRV-063|양호|DNS 서비스 미실행"; return; }
    local nc; nc=$(_named_conf)
    evd "SRV-063" "echo '$(echo "$nc" | grep -iE 'recursion|allow-recursion|allow-query-cache' | head -5)'"
    [ -z "$nc" ] && { result "SRV-063|수동확인|named.conf 위치 확인 필요"; return; }
    # 평가기준: Recursive query 금지 또는 신뢰 호스트만 허용 → 양호 (BIND 9.4+ 기본 allow-recursion 은 localnets/localhost)
    if echo "$nc" | grep -qiE 'recursion\s+no\s*;'; then result "SRV-063|양호|recursion no"
    elif echo "$nc" | grep -qiE 'allow-recursion\s*\{\s*any\s*;'; then result "SRV-063|취약|allow-recursion { any; } - 모든 호스트 재귀 질의 허용"
    elif echo "$nc" | grep -qiE 'allow-recursion'; then result "SRV-063|양호|allow-recursion 신뢰 호스트 한정: $(echo "$nc" | grep -ioE 'allow-recursion\s*\{[^}]*\}' | head -1)"
    else result "SRV-063|수동확인|recursion 허용 대상 미지정 (BIND 기본 localnets·localhost) - 신뢰 호스트 한정 여부 확인"; fi
}

# ================================================================
# SRV-064: DNS 서비스 보안 패치 적용 여부
# ================================================================
check_SRV064() {
    is_running named || { evd "SRV-064" "ps -ef 2>/dev/null | grep named | grep -v grep"; result "SRV-064|양호|DNS 서비스 미실행"; return; }
    evd "SRV-064" "named -v 2>/dev/null; rpm -qa bind 2>/dev/null; dpkg -l bind9 2>/dev/null | tail -1"
    named_ver=$(named -v 2>/dev/null | grep -oE 'BIND [0-9][^ ]*' | head -1)
    if [ -n "$named_ver" ]; then
        result "SRV-064|수동확인|DNS 버전: ${named_ver} - 최신 보안 패치 적용 여부 수동 확인"
    else
        result "SRV-064|수동확인|DNS 서비스 실행 중 - 버전 및 보안 패치 수동 확인"
    fi
}

# ================================================================
# SRV-069: 비밀번호 관리정책 (최대 사용기간)
# ================================================================
_pw_policy() {
    # OS별 비밀번호 정책 (최소 길이 / 요구 문자 종류 수 / 출처) 출력: "<minlen> <classes> <label>"
    local ml=0 cls=0 who k
    case "$OS_FAMILY" in
    AIX)
        ml=$(_aix_default | grep -w "minlen" | grep -oE '[0-9]+' | head -1)
        cls=$(_aix_default | grep -wE "minalpha|minother|mindigit|minspecialchar" | grep -cE '= *[1-9]')
        who="AIX" ;;
    SOLARIS)
        # 평가기준 판단방법: MINALPHA 기본 2, MINNONALPHA(숫자+특수) 기본 1 — MINDIGIT·MINSPECIAL 과 함께 사용 불가
        local a u l d s n
        _sv() { sed -n "s/^$1=\([0-9]*\).*/\1/p" /etc/default/passwd 2>/dev/null | tail -1; }
        ml=$(_sv PASSLENGTH); ml=${ml:-6}
        a=$(_sv MINALPHA); u=$(_sv MINUPPER); l=$(_sv MINLOWER); d=$(_sv MINDIGIT); s=$(_sv MINSPECIAL); n=$(_sv MINNONALPHA)
        { [ "${a:-2}" -ge 1 ] || [ "${u:-0}" -ge 1 ] || [ "${l:-0}" -ge 1 ]; } 2>/dev/null && cls=1
        if [ -n "$d$s" ]; then [ "${d:-0}" -ge 1 ] 2>/dev/null && cls=$((cls+1)); [ "${s:-0}" -ge 1 ] 2>/dev/null && cls=$((cls+1))
        else [ "${n:-1}" -ge 1 ] 2>/dev/null && cls=$((cls+1)); fi
        who="Solaris" ;;
    HPUX)
        ml=$(grep -E "^\s*MIN_PASSWORD_LENGTH" /etc/default/security 2>/dev/null | cut -d= -f2 | tr -d ' ')
        for k in PASSWORD_MIN_LOWER_CASE_CHARS PASSWORD_MIN_UPPER_CASE_CHARS PASSWORD_MIN_DIGIT_CHARS PASSWORD_MIN_SPECIAL_CHARS; do
            grep -qE "^\s*${k}=[1-9]" /etc/default/security 2>/dev/null && cls=$((cls+1)); done
        who="HP-UX" ;;
    *)
        local pam_files f line="" conf="" c neg=0 mcl
        pam_files=$(get_pam_files)
        for f in $pam_files; do
            [ -f "$f" ] || continue
            line=$(grep -v "^\s*#" "$f" 2>/dev/null | grep -iE "pam_pwquality|pam_cracklib" | head -1)
            [ -n "$line" ] && break
        done
        [ -f /etc/security/pwquality.conf ] && conf=$(grep -vhE "^\s*(#|$)" /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf 2>/dev/null)
        if [ -z "$line" ] && [ -z "$conf" ]; then echo "0 0 모듈없음"; return; fi
        _pwv() { local x; x=$(echo "$line" | grep -oE "(^|\s)$1=-?[0-9]+" | tail -1 | cut -d= -f2)
                 [ -z "$x" ] && x=$(echo "$conf" | grep -E "^\s*$1\s*=" | tail -1 | grep -oE -- '-?[0-9]+'); echo "$x"; }
        ml=$(_pwv minlen); ml=${ml:-9}
        mcl=$(_pwv minclass); mcl=${mcl:-0}
        for c in dcredit ucredit lcredit ocredit; do [ "$(_pwv $c)" -lt 0 ] 2>/dev/null && neg=$((neg+1)); done
        [ "$neg" -gt "$mcl" ] && mcl=$neg
        cls=$mcl; who="pwquality" ;;
    esac
    echo "${ml:-0} ${cls:-0} ${who}"
}

_pw_policy_ok() {  # 평가기준 복잡도: 2종 10자 이상 또는 3종 8자 이상
    local ml="$1" cls="$2"
    { [ "$cls" -ge 3 ] && [ "$ml" -ge 8 ]; } 2>/dev/null || { [ "$cls" -ge 2 ] && [ "$ml" -ge 10 ]; } 2>/dev/null
}

check_SRV069() {
    # 평가기준: 비밀번호 관련 정책(2종 10자/3종 8자 복잡도 + 변경 기간 90일 이하)이 설정되어 있을 경우 양호
    evd "SRV-069" "grep -E '^PASS_MAX_DAYS|^MAXWEEKS|^maxage|PASSWORD_MAXDAYS|MIN_PASSWORD_LENGTH' /etc/login.defs /etc/default/passwd /etc/security/user /etc/default/security 2>/dev/null; grep -vE '^\s*(#|$)' /etc/security/pwquality.conf 2>/dev/null"
    local days="" src="" issues="" pol ml cls who
    case "$OS_FAMILY" in
    AIX)     local w; w=$(_aix_default | grep -w "maxage" | grep -oE '[0-9]+' | head -1)
             [ -n "$w" ] && days=$((w*7)); src="maxage=${w:-미설정}주" ;;
    SOLARIS) local w; w=$(grep "^MAXWEEKS" /etc/default/passwd 2>/dev/null | cut -d= -f2 | tr -d ' ')
             [ -n "$w" ] && days=$((w*7)); src="MAXWEEKS=${w:-미설정}주" ;;
    HPUX)    days=$(grep -E "^\s*PASSWORD_MAXDAYS" /etc/default/security 2>/dev/null | cut -d= -f2 | tr -d ' '); src="PASSWORD_MAXDAYS=${days:-미설정}" ;;
    *)       days=$(grep "^PASS_MAX_DAYS" /etc/login.defs 2>/dev/null | awk '{print $2}'); src="PASS_MAX_DAYS=${days:-미설정}" ;;
    esac
    if [ -z "$days" ] || [ "$days" = "0" ]; then issues="변경 기간 미설정(${src})"
    elif [ "$days" -gt 90 ] 2>/dev/null; then issues="변경 기간 ${days}일 초과(${src})"; fi
    pol=$(_pw_policy); ml=${pol%% *}; cls=$(echo "$pol" | awk '{print $2}'); who=$(echo "$pol" | awk '{print $3}')
    if [ "$who" = "모듈없음" ]; then issues="${issues:+$issues / }복잡도 모듈(pam_pwquality/pam_cracklib) 미설정"
    else _pw_policy_ok "$ml" "$cls" || issues="${issues:+$issues / }복잡도 정책 미달(${who}: 최소 ${ml}자, ${cls}종)"; fi
    if [ "$OS_FAMILY" = "LINUX" ] && [ -r /etc/shadow ]; then
        local _acc; _acc=$(awk -F: 'NR==FNR{if($7!~/(nologin|false|sync|shutdown|halt)$/)sh[$1]=1;next} ($1 in sh) && $2!~/^[!*]/ && ($5=="" || $5+0>90){print $1"("($5==""?"미설정":$5)")"}' /etc/passwd /etc/shadow 2>/dev/null | head -5 | tr '\n' ' ')
        [ -n "$_acc" ] && issues="${issues:+$issues / }기존 계정 최대 사용기간 90일 초과/미설정(chage): ${_acc}"
    fi
    if [ -n "$issues" ]; then result "SRV-069|취약|${issues} - 기준: 2종 10자/3종 8자 이상, 변경 기간 90일 이하"
    else result "SRV-069|양호|비밀번호 정책 설정 (${src}, ${who}: 최소 ${ml}자·${cls}종)"; fi
}

# ================================================================
# SRV-070: 취약한 패스워드 저장 방식
# ================================================================
check_SRV070() {
    evd "SRV-070" "awk -F: '{print \$1,substr(\$2,1,4)}' /etc/shadow 2>/dev/null | head -20; grep -E '^ENCRYPT_METHOD' /etc/login.defs 2>/dev/null; grep -E '^CRYPT_(DEFAULT|ALGORITHMS)' /etc/security/policy.conf /etc/default/security 2>/dev/null; grep -E '^[[:space:]]*pwd_algorithm' /etc/security/login.cfg 2>/dev/null; ls -ld /tcb/files/auth 2>/dev/null"
    local des="" alg weak
    case "$OS_FAMILY" in
    AIX)
        # 판단방법(AIX): login.cfg pwd_algorithm 이 112비트 이상 해시인지, /etc/security/passwd 해시 형식
        alg=$(_aix_attr usw pwd_algorithm /etc/security/login.cfg)
        des=$(awk '/^[^ \t*#][^ \t]*:[ \t]*$/{sub(/:.*/,"");u=$0;next} /^[ \t]+password[ \t]*=/{v=$0;sub(/^[^=]*=[ \t]*/,"",v);sub(/[ \t]+$/,"",v); if(v!="" && v!="*" && v!~/^\{/) print u}' /etc/security/passwd 2>/dev/null | head -5 | tr '\n' ' ')
        if [ -n "$des" ]; then result "SRV-070|취약|AIX crypt(DES) 해시 계정: ${des}(pwd_algorithm=${alg:-미설정=crypt})"
        elif [ -z "$alg" ] || [ "$alg" = "crypt" ]; then result "SRV-070|취약|AIX pwd_algorithm 미설정(crypt, 112비트 미만)"
        else result "SRV-070|양호|AIX pwd_algorithm=${alg}"; fi ;;
    HPUX)
        if [ -d /tcb/files/auth ] || [ -f /etc/shadow ]; then
            alg=$(grep -E '^[[:space:]]*CRYPT_DEFAULT' /etc/default/security 2>/dev/null | cut -d= -f2 | tr -d ' ')
            case "$alg" in __unix__|"") result "SRV-070|수동확인|HP-UX $( [ -d /tcb/files/auth ] && echo 'Trusted Mode' || echo shadow ) 사용, CRYPT_DEFAULT=${alg:-미설정} - 해시 강도 확인" ;;
                           *) result "SRV-070|양호|HP-UX shadow/Trusted Mode + CRYPT_DEFAULT=${alg}" ;; esac
        else result "SRV-070|취약|HP-UX shadow·Trusted Mode 미사용 (/etc/passwd 에 해시 저장)"; fi ;;
    *)
        if [ ! -f /etc/shadow ]; then
            result "SRV-070|취약|/etc/shadow 없음 (평문 패스워드 저장 가능)"
            return
        fi
        # DES(crypt 13자), MD5($1$) 는 취약 / SHA256($5$)·SHA512($6$)·bcrypt($2*)·yescrypt($y$) 양호
        des=$(awk -F: '$2!="" && $2!~/^(\$|\*|!|NP$|x$|LK)/ && length($2)==13 {print $1}' /etc/shadow 2>/dev/null | head -5 | tr '\n' ' ')
        weak=$(awk -F: '$2 ~ /^\$1\$/ {print $1}' /etc/shadow 2>/dev/null | head -5)
        if [ -n "$des" ]; then result "SRV-070|취약|DES(crypt) 해시 계정: ${des}$( [ "$OS_FAMILY" = SOLARIS ] && echo "(CRYPT_DEFAULT=$(sed -n 's/^CRYPT_DEFAULT=//p' /etc/security/policy.conf 2>/dev/null))")"
        elif [ -n "$weak" ]; then result "SRV-070|취약|MD5 해시 계정 존재: $(echo "$weak" | _csv)"
        else result "SRV-070|양호|shadow 사용, SHA256/SHA512 등 안전한 해시 (DES·MD5 없음)"; fi ;;
    esac
}

# ================================================================
# SRV-073: 관리자 그룹 불필요 사용자 제거
# ================================================================
check_SRV073() {
    # 평가기준: 관리자 그룹에 '불필요한' 계정 존재 여부 (인원 수 기준 없음) → 구성원 목록 증적 + 인터뷰
    evd "SRV-073" "grep -E '^(root|wheel|sudo|admin|system):' /etc/group 2>/dev/null"
    local grps="root wheel sudo admin"
    [ "$OS_FAMILY" = "BSD" ] && grps="wheel operator"
    [ "$OS_FAMILY" = "AIX" ] && grps="system security"
    local info="" members
    for grp in $grps; do
        members=$(grep "^${grp}:" /etc/group 2>/dev/null | cut -d: -f4)
        [ -n "$members" ] && info="${info} ${grp}:[${members}]"
    done
    if [ -z "$info" ]; then
        result "SRV-073|양호|관리자 그룹에 추가 구성원 없음"
    else
        result "SRV-073|수동확인|관리자 그룹 구성원:${info} - 불필요 계정 여부 확인"
    fi
}

# ================================================================
# SRV-074: 불필요/미관리 계정 제거
# ================================================================
check_SRV074() {
    # 평가기준: 로그인 가능한 계정별 분기(90일) 내 로그인 기록 + 비밀번호 변경 여부 (업무상 사용 여부 확인 필요)
    evd "SRV-074" "awk -F: '\$7 !~ /(nologin|false|sync|shutdown|halt)\$/ {print \$1,\$3,\$7}' /etc/passwd 2>/dev/null; lastlog 2>/dev/null | head -30"
    local today; today=$(( $(date +%s) / 86400 ))
    local vuln="" manual="" user sh pw lchg ll lsec now; now=$(date +%s)
    [ "$OS_FAMILY" = "AIX" ] && evd "SRV-074" "lsuser -a time_last_login lastupdate account_locked ALL 2>/dev/null"
    while IFS=: read -r user _ _ _ _ _ sh; do
        case "$sh" in *nologin|*false|*/sync|*/shutdown|*/halt|"") continue ;; esac
        pw=$(awk -F: -v u="$user" '$1==u{print $2}' /etc/shadow 2>/dev/null)
        case "$pw" in "!"*|"*"*) continue ;; esac   # 잠긴 계정(로그인 불가) 제외
        lchg=$(awk -F: -v u="$user" '$1==u{print $3}' /etc/shadow 2>/dev/null)
        local why=""
        case "$OS_FAMILY" in
        AIX)   # lsuser epoch: time_last_login(마지막 로그인), lastupdate(비밀번호 변경)
            [ "$(lsuser -a account_locked "$user" 2>/dev/null | sed -n 's/.*account_locked=//p')" = "true" ] && continue
            ll=$(lsuser -a time_last_login "$user" 2>/dev/null | sed -n 's/.*time_last_login=//p')
            lsec=$(lsuser -a lastupdate "$user" 2>/dev/null | sed -n 's/.*lastupdate=//p')
            if [ -z "$ll" ]; then why="로그인 기록 없음"
            elif [ $(( (now-ll)/86400 )) -gt 90 ] 2>/dev/null; then why="최근 로그인 $(( (now-ll)/86400 ))일 전"; fi
            [ -n "$lsec" ] && [ $(( (now-lsec)/86400 )) -gt 90 ] 2>/dev/null && why="${why:+$why, }비밀번호 변경 $(( (now-lsec)/86400 ))일 전"
            lchg="" ;;
        SOLARIS|HPUX)   # lastlog 없음 — last 출력은 연도 미표기라 로그인 일자는 증적으로 수동 확인
            manual="${manual} ${user}" ;;
        *)
            ll=$(lastlog -u "$user" 2>/dev/null | awk 'NR==2')
            [ -z "$ll" ] && command -v lastlog2 >/dev/null 2>&1 && ll=$(lastlog2 -u "$user" 2>/dev/null | awk 'NR==2')
            if [ -z "$ll" ] && ! command -v lastlog >/dev/null 2>&1 && ! command -v lastlog2 >/dev/null 2>&1; then manual="${manual} ${user}"
            elif [ -z "$ll" ] || echo "$ll" | grep -q "Never logged in"; then why="로그인 기록 없음"
            else
                lsec=$(date -d "$(echo "$ll" | awk '{for(i=NF-5;i<=NF;i++) printf $i" "}')" +%s 2>/dev/null)
                [ -n "$lsec" ] && [ $(( today - lsec/86400 )) -gt 90 ] && why="최근 로그인 $(( today - lsec/86400 ))일 전"
            fi ;;
        esac
        if [ -n "$lchg" ] && [ "$lchg" -gt 0 ] 2>/dev/null && [ $(( today - lchg )) -gt 90 ]; then why="${why:+$why, }비밀번호 변경 $(( today - lchg ))일 전"; fi
        [ -n "$why" ] && vuln="${vuln} ${user}(${why})"
    done < /etc/passwd
    [ -n "$manual" ] && evd "SRV-074" "for u in $(echo $manual); do last -1 \$u 2>/dev/null | head -1; done"
    if [ -n "$vuln" ]; then result "SRV-074|취약|분기 내 로그인/비밀번호 변경 없는 로그인 가능 계정:${vuln} - 업무상 사용 여부 확인"
    elif [ -n "$manual" ]; then result "SRV-074|수동확인|로그인 기록 자동 조회 불가 계정:${manual} - last 증적으로 90일 내 로그인 확인"
    else result "SRV-074|양호|로그인 가능 계정 모두 분기 내 로그인 및 비밀번호 변경"; fi
}

# ================================================================
# SRV-075: 비밀번호 복잡도
# ================================================================
check_SRV075() {
    # 평가기준: 모든 계정이 복잡도(2종 10자 / 3종 8자) 만족 — 판단방법: 빈 비밀번호 계정 확인 + 크랙
    evd "SRV-075" "grep -v '^#' /etc/security/pwquality.conf 2>/dev/null | grep -v '^$'"
    evd "SRV-075" "grep -i 'pam_pwquality\\|pam_cracklib' /etc/pam.d/system-auth /etc/pam.d/password-auth /etc/pam.d/common-password 2>/dev/null"
    local empty pol ml cls who
    empty=$(awk -F: '($2==""){print $1}' /etc/shadow 2>/dev/null | tr '\n' ' ')
    [ -n "$empty" ] && { result "SRV-075|취약|비밀번호 미설정 계정: ${empty}"; return; }
    pol=$(_pw_policy); ml=${pol%% *}; cls=$(echo "$pol" | awk '{print $2}'); who=$(echo "$pol" | awk '{print $3}')
    if [ "$who" = "모듈없음" ]; then result "SRV-075|취약|비밀번호 복잡도 모듈(pam_pwquality/pam_cracklib) 미설정"
    elif _pw_policy_ok "$ml" "$cls"; then
        result "SRV-075|수동확인|${who} 정책 기준 충족 (최소 ${ml}자, 문자 종류 ${cls}종 이상) - 기존 계정 비밀번호 복잡도 만족 여부(크랙) 확인"
    else
        result "SRV-075|취약|${who} 정책 기준 미달 (최소 ${ml}자, 문자 종류 ${cls}종 요구) - 기준: 2종 10자 이상 또는 3종 8자 이상"
    fi
}

_srv075_judge() {
    local who="$1" ml="$2" cls="$3"
    if { [ "$cls" -ge 3 ] && [ "$ml" -ge 8 ]; } 2>/dev/null || { [ "$cls" -ge 2 ] && [ "$ml" -ge 10 ]; } 2>/dev/null; then
        result "SRV-075|수동확인|${who} 정책 기준 충족 (최소 ${ml}자, 문자 종류 ${cls}종 이상) - 기존 계정 비밀번호 복잡도 만족 여부(크랙) 확인"
    else
        result "SRV-075|취약|${who} 정책 기준 미달 (최소 ${ml}자, 문자 종류 ${cls}종 요구) - 기준: 2종 10자 이상 또는 3종 8자 이상"
    fi
}

# ================================================================
# SRV-081: Crontab 설정파일 권한
# ================================================================
check_SRV081() {
    # 평가기준: crontab 명령 750 이하 / crontab 파일 others 읽기·쓰기 없음 / at·cron allow·deny 소유자 root·640 이하
    evd "SRV-081" "ls -alL /usr/bin/crontab /etc/cron.allow /etc/cron.deny /etc/at.allow /etc/at.deny 2>/dev/null; ls -alL /var/spool/cron/crontabs/ /var/spool/cron/ 2>/dev/null"
    local vuln="" p o f
    for f in /usr/bin/crontab /bin/crontab; do
        [ -f "$f" ] || continue
        p=$(get_perm "$f"); p=${p: -3}
        # 750 이하: others 권한 0, group 쓰기 없음
        { [ "${p:2:1}" != "0" ] || [ $(( ${p:1:1} & 2 )) -ne 0 ]; } 2>/dev/null && vuln="${vuln} ${f}(${p})"
        break
    done
    for d in /var/spool/cron/crontabs /var/spool/cron; do
        [ -d "$d" ] || continue
        for f in "$d"/*; do
            [ -f "$f" ] || continue
            p=$(get_perm "$f"); p=${p: -1}
            [ $(( p & 6 )) -ne 0 ] 2>/dev/null && vuln="${vuln} ${f}(others:${p})"
        done
        break
    done
    for f in /etc/cron.allow /etc/cron.deny /etc/at.allow /etc/at.deny /var/adm/cron/cron.allow /var/adm/cron/cron.deny /var/adm/cron/at.allow /var/adm/cron/at.deny /etc/cron.d/cron.allow /etc/cron.d/cron.deny /etc/cron.d/at.allow /etc/cron.d/at.deny; do
        [ -f "$f" ] || continue
        o=$(get_owner "$f"); p=$(get_perm "$f"); p=${p: -3}
        if [ "$o" != "root" ] || [ "${p:0:1}" -gt 6 ] || [ "${p:1:1}" -gt 4 ] || [ "${p:2:1}" != "0" ]; then vuln="${vuln} ${f}(${o}:${p})"; fi 2>/dev/null
    done
    [ -n "$vuln" ] && result "SRV-081|취약|cron 관련 파일 권한 과다:${vuln}" \
                   || result "SRV-081|양호|crontab 명령·crontab 파일·at/cron 접근제어 파일 권한 기준 충족"
}

# ================================================================
# SRV-084: 시스템 주요 파일 권한
# ================================================================
check_SRV084() {
    # 평가기준: passwd 644 / shadow 600 / hosts 644 / (x)inetd.conf 600 / syslog.conf 644 / services 644 / hosts.lpd 640, 소유자 root (AIX /etc/security/passwd 600)
    evd "SRV-084" "ls -la /etc/passwd /etc/shadow /etc/group /etc/hosts /etc/services /etc/rsyslog.conf /etc/syslog.conf /etc/inetd.conf /etc/xinetd.conf /etc/hosts.lpd /etc/security/passwd 2>/dev/null"
    local vuln="" f max
    for f in /etc/passwd:644 /etc/shadow:600 /etc/hosts:644 /etc/services:644 /etc/rsyslog.conf:644 /etc/syslog.conf:644 \
             /etc/inetd.conf:600 /etc/xinetd.conf:600 /etc/hosts.lpd:640 /etc/security/passwd:600; do
        max=${f##*:}; f=${f%:*}
        [ -f "$f" ] || continue
        [ "$(get_owner "$f")" != "root" ] && vuln="${vuln} ${f}(소유자=$(get_owner "$f"))"
        _perm_over "$(get_perm "$f")" "$max" && vuln="${vuln} ${f}($(get_perm "$f")>${max})"
    done
    if [ "$OS_FAMILY" = "HPUX" ] && [ -d /tcb/files/auth ]; then   # 평가기준(HP-UX): /tcb/files/auth/[a-z]/* 664, 소유자 root
        local tn=0
        for f in /tcb/files/auth/[a-z]/*; do
            [ -f "$f" ] || continue
            { [ "$(get_owner "$f")" != "root" ] || _perm_over "$(get_perm "$f")" 664; } && { tn=$((tn+1)); [ $tn -le 5 ] && vuln="${vuln} ${f}($(get_owner "$f"):$(get_perm "$f"))"; }
        done
        [ $tn -gt 5 ] && vuln="${vuln} …/tcb 외 $((tn-5))건"
    fi
    [ -n "$vuln" ] && result "SRV-084|취약|주요 파일 권한 기준 초과:${vuln}" || result "SRV-084|양호|주요 파일 소유자 root·권한 기준 이하"
}

# ================================================================
# SRV-091: SUID/SGID 파일 관리
# ================================================================
check_SRV091() {
    # 평가기준: 불필요하게 SUID·SGID 설정된 파일
    evd "SRV-091" "_to 30 find / \$_FP \( -perm -4000 -o -perm -2000 \) -type f -print 2>/dev/null | head -40"
    local dangerous="nmap perl python python3 php ruby bash sh find wget curl nc netcat awk vim gdb strace less more cp mv tar zip" bin bp found="" f nopkg=""
    for bin in $dangerous; do
        bp=$(command -v "$bin" 2>/dev/null); [ -z "$bp" ] && continue
        { [ -u "$bp" ] || [ -g "$bp" ]; } && found="${found} ${bp}"
    done
    if [ -n "$found" ]; then result "SRV-091|취약|위험 SUID/SGID 파일:${found}"; return; fi
    while IFS= read -r f; do
        # usrmerge 배포판은 패키지 DB 에 /bin·/sbin 경로로 등록되어 있어 두 경로 모두 조회
        { rpm -qf "$f" >/dev/null 2>&1 || dpkg -S "$f" >/dev/null 2>&1 || dpkg -S "${f#/usr}" >/dev/null 2>&1 || dpkg -S "$(readlink -f "$f")" >/dev/null 2>&1; } || nopkg="${nopkg} ${f}"
    done < <(_to 30 find / $_FP \( -perm -4000 -o -perm -2000 \) -type f -print 2>/dev/null | grep -vE '^/(proc|sys|var/lib/(docker|containers))' | head -200)
    { command -v rpm >/dev/null 2>&1 || command -v dpkg >/dev/null 2>&1; } || nopkg=""
    [ -n "$nopkg" ] && result "SRV-091|수동확인|패키지 외 SUID/SGID 파일:$(echo $nopkg | cut -c1-200) - 필요 여부 확인" || result "SRV-091|양호|위험 SUID/SGID 없음, 패키지 기본 파일만 존재"
}

# ================================================================
# SRV-092: 사용자 홈 디렉토리 경로/권한
# ================================================================
check_SRV092() {
    # 평가기준: 홈 디렉터리 소유자 불일치·계정간 중복 홈·others 쓰기
    evd "SRV-092" "awk -F: '\$3>=1000 || \$3>=500{print \$1,\$3,\$6}' /etc/passwd 2>/dev/null | head -30"
    local vuln="" min_uid dup user uid homedir
    min_uid=$(awk '/^UID_MIN/{print $2}' /etc/login.defs 2>/dev/null)
    [ -z "$min_uid" ] && case "$OS_FAMILY" in AIX) min_uid=200 ;; SOLARIS|HPUX) min_uid=100 ;; *) min_uid=500 ;; esac   # UNIX 일반 사용자 UID 대역
    dup=$(awk -F: -v m="$min_uid" '$3>=m && $6!="" && $6!="/"{print $6}' /etc/passwd 2>/dev/null | sort | uniq -d | tr '\n' ' ')
    [ -n "$dup" ] && vuln="${vuln} 중복 홈:${dup}"
    while IFS=: read -r user _ uid _ _ homedir _; do
        [ "${uid:-0}" -lt "$min_uid" ] 2>/dev/null && continue
        { [ "${uid:-0}" -ge 60000 ] || [ "${uid:-0}" -lt 0 ]; } 2>/dev/null && continue   # nobody·noaccess 등
        [ -z "$homedir" ] || [ "$homedir" = "/" ] || [ ! -d "$homedir" ] && continue
        [ "$(get_owner "$homedir")" != "$user" ] && vuln="${vuln} ${homedir}(소유자:$(get_owner "$homedir"))"
        local p; p=$(get_perm "$homedir"); [ $(( ${p: -1} & 2 )) -ne 0 ] && vuln="${vuln} ${homedir}(others 쓰기:${p})"
    done < /etc/passwd
    [ -n "$vuln" ] && result "SRV-092|취약|홈 디렉터리 이상:${vuln}" || result "SRV-092|양호|홈 디렉터리 소유자 일치·중복 없음·others 쓰기 없음"
}

# ================================================================
# SRV-093: world writable 파일
# ================================================================
check_SRV093() {
    evd "SRV-093" "_to 60 find / \$_FP -perm -0002 -type f ! -path '/proc/*' ! -path '/sys/*' ! -path '/dev/*' ! -path '/tmp/*' ! -path '/var/tmp/*' -print 2>/dev/null | head -20"
    local _ww _rc
    _ww=$(_to 60 find / $_FP -perm -0002 -type f ! -path "/proc/*" ! -path "/sys/*" \
          ! -path "/dev/*" ! -path "/tmp/*" ! -path "/var/tmp/*" -print 2>/dev/null); _rc=$?
    cnt=$(printf '%s' "$_ww" | grep -c .)
    # timeout(124) 이고 0건이면 검색 미완료 — 양호로 단정하지 않음
    if [ "$_rc" = "124" ] && [ "${cnt:-0}" -eq 0 ]; then result "SRV-093|수동확인|파일 검색 시간 초과(60초) - world writable 파일 수동 확인"; return; fi
    [ "${cnt:-0}" -gt 0 ] 2>/dev/null && \
        result "SRV-093|취약|world writable 파일 ${cnt}개 (tmp 제외)" || \
        result "SRV-093|양호|world writable 파일 없음"
}

# ================================================================
# SRV-108: 로그 접근통제 및 관리
# ================================================================
check_SRV108() {
    evd "SRV-108" "ls -la /var/log/messages /var/log/secure /var/log/auth.log /var/log/syslog /var/log/wtmp /var/log/lastlog 2>/dev/null"
    # 기준: 로그 파일을 소유자 이외 사용자가 수정 가능(그룹/others 쓰기)하면 취약 — 예외: wtmp·lastlog 664, btmp 660 (권한 변경 불가)
    vuln=""
    for logf in $(find /var/log /var/adm $( [ "$OS_FAMILY" = "AIX" ] && echo /etc/security ) -type f \( -perm -020 -o -perm -002 \) 2>/dev/null | head -200); do
        perm=$(get_perm "$logf")
        case "$(basename "$logf")" in
        wtmp*|lastlog*|btmp*) [ "$(( 0${perm: -1} & 2 ))" -eq 0 ] 2>/dev/null && continue ;;
        esac
        vuln="${vuln} ${logf}(${perm})"
    done
    [ -n "$vuln" ] && result "SRV-108|취약|소유자 외 쓰기 가능한 로그 파일:${vuln}" || \
        result "SRV-108|양호|로그 파일 소유자 외 쓰기 권한 없음 (wtmp·lastlog 664, btmp 660 기준 예외)"
}

# ================================================================
# SRV-109: 주요 이벤트 로그 설정
# ================================================================
check_SRV109() {
    evd "SRV-109" "grep -ihE '^auth|^authpriv|\*\.' /etc/rsyslog.conf /etc/rsyslog.d/*.conf /etc/syslog.conf 2>/dev/null | head -10; cat /etc/default/su 2>/dev/null | grep -E 'SULOG|SYSLOG'"
    case "$OS_FAMILY" in
    SOLARIS)
        # 평가기준(Solaris): auth.info 활성 + /etc/default/su SULOG=경로, SYSLOG=YES
        local a=0 s=0
        grep -vE '^\s*#' /etc/syslog.conf 2>/dev/null | grep -qE 'auth\.(info|debug|\*)|\*\.(info|debug)' && a=1
        grep -qE '^SULOG=' /etc/default/su 2>/dev/null && grep -qE '^SYSLOG=YES' /etc/default/su 2>/dev/null && s=1
        [ $a -eq 1 ] && [ $s -eq 1 ] && result "SRV-109|수동확인|auth.info·SULOG·SYSLOG=YES 설정 - 내부 로그 정책 부합 여부 확인" || result "SRV-109|취약|Solaris auth.info(${a})·/etc/default/su SULOG·SYSLOG=YES(${s}) 미충족" ;;
    AIX|HPUX)
        grep -vE '^\s*\*|^\s*#' /etc/syslog.conf 2>/dev/null | grep -qiE "^auth|\*\.(info|debug)" && \
            result "SRV-109|수동확인|syslog auth 설정 존재 - 내부 로그 기록 정책 부합 여부 확인" || result "SRV-109|취약|syslog auth 로그 미설정" ;;
    *)
        local f
        for f in /etc/rsyslog.conf /etc/rsyslog.d/*.conf /etc/syslog.conf; do
            [ -f "$f" ] || continue
            grep -qiE "^auth|^authpriv" "$f" 2>/dev/null && { result "SRV-109|양호|auth/authpriv 로그 설정됨 (${f}) - 내부 로그 정책 부합 여부는 참고 확인"; return; }
        done
        [ -f /etc/syslog-ng/syslog-ng.conf ] && grep -qi "auth\|authpriv" /etc/syslog-ng/syslog-ng.conf 2>/dev/null && { result "SRV-109|양호|syslog-ng auth 로그 설정됨"; return; }
        result "SRV-109|취약|auth/authpriv 로그 설정 없음" ;;
    esac
}

# ================================================================
# SRV-118: 보안패치 적용
# ================================================================
check_SRV118() {
    evd "SRV-118" "uname -r; oslevel -s 2>/dev/null; instfix -i 2>/dev/null | grep -E 'ML|SP' | tail -3; emgr -l 2>/dev/null | head; swlist -l bundle 2>/dev/null | grep -iE 'QPK|HPUX'; showrev -p 2>/dev/null | tail -5; pkg info entire 2>/dev/null | grep -iE 'version|branch'"
    evd "SRV-118" "rpm -qa --last 2>/dev/null | head -10 || dpkg -l 2>/dev/null | tail -10"
    case "$OS_FAMILY" in
    LINUX)
        # 저장소 조회 실패(폐쇄망·미등록)·미지원 패키지 관리자는 건수 0 으로 보지 않고 수동확인
        _upd_cnt=""; _upd_out=""; _upd_rc=0
        if command -v dnf >/dev/null 2>&1 || command -v yum >/dev/null 2>&1; then
            _pm=$(command -v dnf >/dev/null 2>&1 && echo dnf || echo yum)
            _upd_out=$(timeout 120 $_pm -q check-update 2>/dev/null); _upd_rc=$?
            # check-update: 100=업데이트 있음, 0=없음, 그 외(1 등)=저장소 오류
            case "$_upd_rc" in 100) _upd_cnt=$(echo "$_upd_out" | grep -cE "^[a-zA-Z0-9]") ;; 0) _upd_cnt=0 ;; esac
        elif command -v apt-get >/dev/null 2>&1; then
            # apt-get update 는 저장소 접근 실패(W: Failed to fetch)에도 0 을 반환 → 출력으로 실패 판별
            _upd_out=$(timeout 120 apt-get update 2>&1); _upd_rc=$?
            if [ "$_upd_rc" -eq 0 ] && ! echo "$_upd_out" | grep -qE "^Err:|Failed to fetch|Some index files failed|Temporary failure resolving"; then
                _upd_cnt=$(apt-get -s upgrade 2>/dev/null | grep -c "^Inst ")
            fi
        elif command -v zypper >/dev/null 2>&1; then
            _upd_out=$(timeout 120 zypper -q --non-interactive list-updates 2>/dev/null); _upd_rc=$?
            [ "$_upd_rc" -eq 0 ] && _upd_cnt=$(echo "$_upd_out" | grep -c "^v ")
        fi
        evd "SRV-118" "echo 'package manager rc=${_upd_rc} upgradable=${_upd_cnt:-조회 실패}'"
        if [ -z "$_upd_cnt" ]; then
            result "SRV-118|수동확인|패키지 저장소 조회 실패(폐쇄망·저장소 미등록 등) 또는 미지원 패키지 관리자 - 보안패치 적용 현황·검토 절차 수동 확인"
        elif [ "${_upd_cnt:-0}" -gt 0 ] 2>/dev/null; then
            result "SRV-118|취약|미적용 보안패치 ${_upd_cnt}건 (수동 확인 병행 권고)"
        elif [ "${_upd_cnt:-0}" -eq 0 ] 2>/dev/null; then
            result "SRV-118|양호|패키지 매니저 기준 미적용 업데이트 없음"
        else
            result "SRV-118|수동확인|보안패치 적용 현황 수동 확인 필요"
        fi ;;
    *)
        result "SRV-118|수동확인|보안패치 적용 현황 수동 확인 필요" ;;
    esac
}

# ================================================================
# SRV-121: root PATH 환경변수
# ================================================================
check_SRV121() {
    # 평가기준: PATH 에 '.', '::'(빈 항목) 또는 불필요한 임의 경로
    evd "SRV-121" "echo \$PATH; grep -rhE '^\s*(export\s+)?PATH=' /root/.bashrc /root/.bash_profile /root/.profile /etc/profile /etc/environment /etc/bashrc /etc/profile.d/*.sh 2>/dev/null"
    local bad="" v e
    while IFS= read -r v; do
        v=$(echo "$v" | sed -E 's/^\s*(export\s+)?PATH=//; s/["'"'"']//g')
        [ -z "$v" ] && continue
        case ":$v:" in *"::"*) bad="${bad} [빈 항목] ${v}"; continue ;; esac
        local IFS=':'; for e in $v; do
            case "$e" in .|./*) bad="${bad} [.] ${v}"; break ;; esac
        done; unset IFS
    done < <( { grep -rhE '^\s*(export\s+)?PATH=' /root/.bashrc /root/.bash_profile /root/.profile /etc/profile /etc/environment /etc/bashrc /etc/profile.d/*.sh 2>/dev/null; echo "PATH=$PATH"; } )
    [ -n "$bad" ] && result "SRV-121|취약|PATH 에 현재 디렉터리(.) 또는 빈 항목:$(echo "$bad" | cut -c1-200)" || result "SRV-121|양호|PATH 에 '.'·'::' 미포함"
}

# ================================================================
# SRV-122: umask 설정
# ================================================================
check_SRV122() {
    # 평가기준: 모든 계정·설정 파일 umask 가 022 이상(group·others 쓰기 금지)
    evd "SRV-122" "umask; grep -rhE '^\s*umask|^UMASK' /etc/profile /etc/bashrc /etc/login.defs /etc/profile.d/*.sh /root/.bashrc /root/.profile 2>/dev/null"
    local vals v bad=""
    local _homes; _homes=$(awk -F: '$7!~/(nologin|false)$/ && $6!="" && $6!="/"{print $6}' /etc/passwd 2>/dev/null | sort -u)
    vals=$( { grep -rhE '^\s*umask\s+[0-7]+|^\s*UMASK\s+[0-7]+' /etc/profile /etc/bashrc /etc/bash.bashrc /etc/login.defs /etc/profile.d/*.sh $(for h in $_homes; do echo "$h/.profile $h/.bashrc $h/.bash_profile $h/.kshrc $h/.cshrc"; done) 2>/dev/null | grep -oE '[0-7]{2,4}';
              [ "$OS_FAMILY" = "AIX" ] && awk '/^[^ \t*#][^ \t]*:[ \t]*$/{next} /^[ \t]+umask[ \t]*=/{v=$0;sub(/^[^=]*=[ \t]*/,"",v);print v}' /etc/security/user 2>/dev/null;
              [ "$OS_FAMILY" = "HPUX" ] && sed -n 's/^[[:space:]]*UMASK=\([0-7]*\).*/\1/p' /etc/default/security 2>/dev/null; } | sort -u)
    [ "$OS_FAMILY" = "AIX" ] && evd "SRV-122" "lsuser -a umask ALL 2>/dev/null"
    [ -z "$vals" ] && vals=$(umask 2>/dev/null)
    for v in $vals; do
        (( (8#$v & 8#022) == 8#022 )) || bad="${bad} ${v}"
    done
    [ -n "$bad" ] && result "SRV-122|취약|group/others 쓰기 허용 umask:${bad} (022 이상 필요, 조건부 설정 포함)" || result "SRV-122|양호|umask $(echo $vals) (022 이상)"
}

# ================================================================
# SRV-127: 로그인 실패 횟수 접속 제한
# ================================================================
check_SRV127() {
    # 평가기준: 계정 잠금 임계값 설정이 존재하면 양호 (횟수는 내부 규정 확인)
    evd "SRV-127" "grep -i 'pam_faillock\\|pam_tally' /etc/pam.d/system-auth /etc/pam.d/password-auth /etc/pam.d/common-auth 2>/dev/null"
    evd "SRV-127" "cat /etc/security/faillock.conf 2>/dev/null | grep -v '^#' | grep -v '^$'"
    local val="" label=""
    case "$OS_FAMILY" in
    AIX)     label="AIX loginretries";      val=$(_aix_attr default loginretries)
             evd "SRV-127" "lsuser -a loginretries ALL 2>/dev/null"
             local z; z=$(awk '/^[^ \t*#][^ \t]*:[ \t]*$/{sub(/:.*/,"");st=$0;next} st!="default" && st!="root" && /^[ \t]+loginretries[ \t]*=[ \t]*0[ \t]*$/{print st}' /etc/security/user 2>/dev/null | tr '\n' ' ')
             [ -n "$z" ] && [ "${val:-0}" -gt 0 ] 2>/dev/null && { result "SRV-127|취약|AIX loginretries=${val}(default)이나 계정별 0 재정의: ${z}"; return; } ;;
    SOLARIS) # 평가기준(SOL): policy.conf LOCK_AFTER_RETRIES=YES + /etc/default/login RETRIES 설정
             evd "SRV-127" "grep -E 'LOCK_AFTER_RETRIES' /etc/security/policy.conf 2>/dev/null; grep -E 'RETRIES' /etc/default/login 2>/dev/null"
             if grep -qE '^[[:space:]]*LOCK_AFTER_RETRIES=YES' /etc/security/policy.conf 2>/dev/null; then
                 val=$(sed -n 's/^[[:space:]]*RETRIES=\([0-9]*\).*/\1/p' /etc/default/login 2>/dev/null | tail -1)
                 label="Solaris LOCK_AFTER_RETRIES=YES, RETRIES"
             else label="Solaris LOCK_AFTER_RETRIES 미설정(≠YES)"; val=""; fi ;;
    HPUX)    # Trusted Mode: /tcb/files/auth/system/default u_maxtries#N / Non Trusted: AUTH_MAXTRIES (/etc/default/security, /var/adm/userdb/*)
             if [ -f /tcb/files/auth/system/default ]; then label="HP-UX u_maxtries(Trusted)"; val=$(grep -oE 'u_maxtries#[0-9]+' /tcb/files/auth/system/default 2>/dev/null | head -1 | cut -d'#' -f2)
             else label="HP-UX AUTH_MAXTRIES"; val=$(grep -hE "^\s*AUTH_MAXTRIES" /etc/default/security /var/adm/userdb/* 2>/dev/null | head -1 | cut -d= -f2 | tr -d ' '); fi ;;
    *)
        local pam_files f d found=0
        pam_files=$(get_pam_files)
        for f in $pam_files; do
            [ -f "$f" ] || continue
            if grep -v "^\s*#" "$f" 2>/dev/null | grep -qi "pam_faillock"; then
                label="pam_faillock"; found=1
                val=$(grep -v "^\s*#" "$f" | grep -i "pam_faillock" | grep -oE 'deny=[0-9]+' | cut -d= -f2 | head -1)
                break
            fi
        done
        if [ -f /etc/security/faillock.conf ]; then
            d=$(grep -v "^\s*#" /etc/security/faillock.conf 2>/dev/null | grep -E "^\s*deny\s*=" | grep -oE '[0-9]+' | head -1)
            [ -n "$d" ] && { val=$d; label="faillock.conf deny"; }
            [ $found -eq 1 ] && [ -z "$val" ] && { val=3; label="pam_faillock(기본 deny=3)"; }
        fi
        if [ $found -eq 0 ] && [ -z "$d" ]; then
            for f in $pam_files; do
                [ -f "$f" ] || continue
                if grep -v "^\s*#" "$f" 2>/dev/null | grep -qi "pam_tally"; then
                    label="pam_tally2"; val=$(grep -v "^\s*#" "$f" | grep -i "pam_tally" | grep -oE 'deny=[0-9]+' | cut -d= -f2 | head -1); break
                fi
            done
        fi ;;
    esac
    if [ -z "$val" ] || [ "$val" = "0" ]; then
        result "SRV-127|취약|계정 잠금 임계값 미설정${label:+ (${label})}"
    elif [ "$val" -le 5 ] 2>/dev/null; then
        result "SRV-127|양호|${label}=${val}회 설정"
    else
        result "SRV-127|양호|${label}=${val}회 설정 (5회 초과 - 내부 규정 기준 확인)"
    fi
}

# ================================================================
# SRV-131: su 명령어 그룹 제한
# ================================================================
check_SRV131() {
    evd "SRV-131" "grep -v '^#' /etc/pam.d/su 2>/dev/null; ls -l /bin/su /usr/bin/su 2>/dev/null; awk '/^(root|default):/,/^\$/' /etc/security/user 2>/dev/null | grep sugroups; grep -i SU_ROOT_GROUP /etc/default/security 2>/dev/null; grep -i su_group /etc/pam.conf 2>/dev/null"
    local su p
    su=$(ls /bin/su /usr/bin/su 2>/dev/null | head -1); p=$(get_perm "$su")
    case "$OS_FAMILY" in
    AIX)
        local g; g=$(awk '/^root:/{f=1;next} /^[^ \t*]/{f=0} f&&/sugroups/{sub(/.*=[ \t]*/,"");print;exit}' /etc/security/user 2>/dev/null)
        [ -z "$g" ] && g=$(awk '/^default:/{f=1;next} /^[^ \t*]/{f=0} f&&/sugroups/{sub(/.*=[ \t]*/,"");print;exit}' /etc/security/user 2>/dev/null)
        [ -n "$g" ] && [ "${g^^}" != "ALL" ] && result "SRV-131|양호|AIX sugroups=${g}" || result "SRV-131|취약|AIX sugroups=${g:-미설정} (ALL/미설정)" ;;
    HPUX)
        local g; g=$(grep -E '^\s*SU_ROOT_GROUP' /etc/default/security 2>/dev/null | cut -d= -f2 | tr -d ' ')
        [ -n "$g" ] && [ "${g^^}" != "ALL" ] && result "SRV-131|양호|HP-UX SU_ROOT_GROUP=${g}" || result "SRV-131|취약|HP-UX SU_ROOT_GROUP 미지정" ;;
    SOLARIS)
        if grep -vE '^\s*#' /etc/pam.conf 2>/dev/null | grep -q su_group; then result "SRV-131|양호|pam.conf su_group 설정"
        elif [ -n "$p" ] && [ $(( ${p: -1} & 1 )) -eq 0 ]; then result "SRV-131|양호|${su} others 실행 권한 없음 (${p}, 그룹=$(ls -l "$su" | awk '{print $4}'))"
        else result "SRV-131|취약|${su:-su} others 실행 가능 (${p:-미확인})"; fi ;;
    *)
        if grep -vE '^\s*#' /etc/pam.d/su 2>/dev/null | grep -qE '^\s*auth\s+(required|requisite)\s+\S*pam_wheel\.so'; then
            result "SRV-131|양호|su pam_wheel required 설정 (그룹=$(grep -vE '^\s*#' /etc/pam.d/su | grep -oE 'group=\S+' | cut -d= -f2 | head -1 | sed 's/^$/wheel/'))"
        elif [ -n "$p" ] && [ $(( ${p: -1} & 1 )) -eq 0 ]; then result "SRV-131|양호|${su} others 실행 권한 없음 (${p})"
        else result "SRV-131|취약|su pam_wheel(required) 미설정, ${su} others 실행 가능 (${p:-미확인})"; fi ;;
    esac
}

# ================================================================
# SRV-133: Cron 서비스 사용 계정 제한
# ================================================================
check_SRV133() {
    # 평가기준: allow/deny 내부에 계정 존재 또는 둘 다 없음(root만 사용) → 양호 / allow 없고 deny 비어 있음 → 취약
    local allow=/etc/cron.allow deny=/etc/cron.deny
    { [ "$OS_FAMILY" = "AIX" ] || [ "$OS_FAMILY" = "HPUX" ]; } && { allow=/var/adm/cron/cron.allow; deny=/var/adm/cron/cron.deny; }
    [ "$OS_FAMILY" = "SOLARIS" ] && { allow=/etc/cron.d/cron.allow; deny=/etc/cron.d/cron.deny; }
    evd "SRV-133" "ls -la $allow $deny 2>/dev/null; echo '[allow]'; cat $allow 2>/dev/null; echo '[deny]'; cat $deny 2>/dev/null"
    local a_cnt d_cnt
    a_cnt=$(grep -vcE '^\s*(#|$)' "$allow" 2>/dev/null); d_cnt=$(grep -vcE '^\s*(#|$)' "$deny" 2>/dev/null)
    if [ -f "$allow" ] && [ "${a_cnt:-0}" -gt 0 ]; then result "SRV-133|양호|${allow} 허용 계정 ${a_cnt}개 관리"
    elif [ ! -f "$allow" ] && [ ! -f "$deny" ]; then result "SRV-133|양호|cron.allow/cron.deny 모두 없음 (root만 cron 사용 가능)"
    elif [ ! -f "$allow" ] && [ "${d_cnt:-0}" -eq 0 ]; then result "SRV-133|취약|cron.allow 없고 cron.deny 비어 있음 (모든 계정 cron 사용 가능)"
    elif [ ! -f "$allow" ]; then result "SRV-133|양호|${deny} 거부 계정 ${d_cnt}개 관리"
    else result "SRV-133|수동확인|${allow} 존재하나 허용 계정 없음 (cron 사용 불가) - 의도 확인"; fi
}

# ================================================================
# SRV-142: 중복 UID 계정 제한
# ================================================================
check_SRV142() {
    evd "SRV-142" "awk -F: '{print \$3}' /etc/passwd 2>/dev/null | sort | uniq -d"
    dup=$(awk -F: '{print $3}' /etc/passwd 2>/dev/null | sort | uniq -d)
    [ -n "$dup" ] && result "SRV-142|취약|중복 UID 발견: $(echo "$dup" | head -5)" || \
        result "SRV-142|양호|중복 UID 없음"
}

# ================================================================
# SRV-144: /dev 불필요 파일
# ================================================================
check_SRV144() {
    # 평가기준: /dev 에 존재하지 않는 불필요 device(일반) 파일 (mqueue, shm 예외)
    evd "SRV-144" "find /dev \\( -path /dev/shm -o -path /dev/mqueue \\) -prune -o -type f -print 2>/dev/null | head -20"
    local fl; fl=$(find /dev \( -path /dev/shm -o -path /dev/mqueue \) -prune -o -type f -print 2>/dev/null | head -10)
    [ -n "$fl" ] && result "SRV-144|취약|/dev 내 일반 파일: $(echo "$fl" | tr '\n' ' ' | cut -c1-200)" || result "SRV-144|양호|/dev 불필요 일반 파일 없음 (shm·mqueue 제외)"
}

# ================================================================
# SRV-158: 불필요 Telnet 서비스 비활성화
# ================================================================
check_SRV158() {
    evd "SRV-158" "grep -vE '^\s*#' /etc/inetd.conf 2>/dev/null | grep -w telnet; inetadm 2>/dev/null | grep -i telnet; lssrc -ls inetd 2>/dev/null | grep -i telnet; ss -tln 2>/dev/null | grep ':23 '; netstat -an 2>/dev/null | grep -E '[.:]23[[:space:]].*LISTEN'"
    local on; on=$( { _inetd_on telnet; _listen 23 | awk '{print "LISTEN:23"}'; } | tr '\n' ' ')
    if is_running telnetd || is_running in.telnetd || [ -n "$on" ]; then result "SRV-158|취약|Telnet 서비스 활성 (${on:-telnetd 프로세스})"
    else result "SRV-158|양호|Telnet 서비스 미실행"; fi
}

# ================================================================
# SRV-161: ftpusers 파일의 소유자 및 권한 설정 적절성
# ================================================================
check_SRV161() {
    evd "SRV-161" "ls -la /etc/ftpusers /etc/ftpd/ftpusers /etc/vsftpd/ftpusers /etc/vsftpd/user_list /etc/vsftpd.ftpusers /etc/vsftpd.user_list 2>/dev/null"
    local f found="" bad="" p o
    for f in /etc/ftpusers /etc/ftpd/ftpusers /etc/vsftpd/ftpusers /etc/vsftpd/user_list /etc/vsftpd.ftpusers /etc/vsftpd.user_list; do
        [ -f "$f" ] || continue
        found="${found} ${f}"; p=$(get_perm "$f"); o=$(get_owner "$f")
        { [ "$o" != "root" ] || _perm_over "$p" 640; } && bad="${bad} ${f}(소유자:${o},권한:${p})"
    done
    if [ -z "$found" ]; then
        _ftp_running && result "SRV-161|취약|ftpusers 파일 없음 (FTP 실행 중)" || result "SRV-161|양호|FTP 서비스 미실행"
        return
    fi
    [ -n "$bad" ] && result "SRV-161|취약|ftpusers 소유자/권한 이상:${bad}" || result "SRV-161|양호|${found# } 소유자=root, 권한 640 이하"
}

# ================================================================
# SRV-163: 시스템 사용 주의사항 출력 (Banner)
# ================================================================
check_SRV163() {
    # 평가기준: 로그온 시 경고 메시지 미출력 또는 문구 내 시스템 버전 정보 노출 시 취약
    evd "SRV-163" "grep -iE '^\s*Banner' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null; for f in /etc/issue /etc/issue.net /etc/motd; do echo \"# \$f\"; head -5 \$f 2>/dev/null; done; grep -i herald /etc/security/login.cfg 2>/dev/null"
    local files="" f txt="" ver
    local sb; sb=$(sshd -T 2>/dev/null | awk 'tolower($1)=="banner"{print $2}')
    [ -z "$sb" ] && sb=$(grep -vE '^\s*#' $(_sshd_cfg) /etc/ssh/sshd_config.d/*.conf 2>/dev/null | grep -iE '^\S*:?\s*Banner' | awk '{print $NF}' | tail -1)
    [ -n "$sb" ] && [ "$sb" != "none" ] && [ -f "$sb" ] && files="$sb"
    for f in /etc/issue /etc/issue.net /etc/motd; do [ -s "$f" ] && files="${files} ${f}"; done
    [ "$OS_FAMILY" = "AIX" ] && txt=$(grep -vE '^\s*\*' /etc/security/login.cfg 2>/dev/null | grep -i 'herald' | head -1)
    for f in $files; do txt="${txt}"$'\n'"$(cat "$f" 2>/dev/null)"; done
    if [ -z "$(echo "$txt" | tr -d '[:space:]')" ]; then result "SRV-163|취약|로그온 경고 메시지(배너) 미설정"; return; fi
    ver=$(echo "$txt" | grep -oiE 'SunOS[^ ]*|Solaris [0-9.]+|AIX( Version)? [0-9.]+|HP-UX|HP Release [A-Z]?\.?[0-9.]+|Ubuntu [0-9.]+|CentOS[^[:cntrl:]]*[0-9]|Red Hat[^[:cntrl:]]*[0-9]|Rocky[^[:cntrl:]]*[0-9]|Debian[^[:cntrl:]]*[0-9]|\\r|\\v|Kernel [0-9]' | head -1)
    if [ -n "$ver" ]; then result "SRV-163|취약|배너에 시스템 버전 정보 노출 (${ver}) - $(echo $files)"
    elif echo "$txt" | grep -qiE 'authori[sz]ed|unauthori[sz]ed|warning|경고|허가|불법|monitor'; then result "SRV-163|양호|경고 문구 배너 설정 ($(echo $files))"
    else result "SRV-163|수동확인|배너 존재하나 경고 문구 미확인 ($(echo $files)) - 내용 확인"; fi
}

# ================================================================
# SRV-165: 불필요 Shell 계정 제거
# ================================================================
check_SRV165() {
    # 평가기준: 로그인이 필요하지 않은 계정(daemon·bin·sys·adm·listen·nobody·noaccess·diag·operator·games·gopher 등 시스템 계정)에 shell 부여 시 취약
    evd "SRV-165" "awk -F: '{printf \"%-15s UID=%-5s Shell=%s\\n\",\$1,\$3,\$7}' /etc/passwd"
    local min_uid bad="" user uid sh
    min_uid=$(awk '/^UID_MIN/{print $2}' /etc/login.defs 2>/dev/null)
    [ -z "$min_uid" ] && case "$OS_FAMILY" in AIX) min_uid=200 ;; SOLARIS|HPUX) min_uid=100 ;; *) min_uid=500 ;; esac   # UNIX 일반 사용자 UID 대역
    while IFS=: read -r user _ uid _ _ _ sh; do
        [ "$user" = "root" ] && continue
        if [ "$OS_FAMILY" = "LINUX" ]; then
            { [ "${uid:-0}" -lt "$min_uid" ] 2>/dev/null || echo "$user" | grep -qE '^(daemon|bin|sys|adm|listen|nobody|nobody4|noaccess|diag|operator|games|gopher)$'; } || continue
        else   # UNIX: 가이드 판단방법 계정 목록만 (일반 사용자 UID 체계가 OS 마다 다름)
            echo "$user" | grep -qE '^(daemon|bin|sys|adm|listen|nobody|nobody4|noaccess|diag|operator|games|gopher|uucp|lp|smmsp|nuucp)$' || continue
            [ -z "$sh" ] && sh="/bin/sh"   # Solaris 등 셸 필드 공란 = /bin/sh
        fi
        case "$sh" in */sync|*/shutdown|*/halt|*nologin|*false|"") continue ;; esac
        grep -qx "$sh" /etc/shells 2>/dev/null || case "$sh" in */bash|*/sh|*/ksh|*/csh|*/tcsh|*/zsh|*/dash) ;; *) continue ;; esac
        bad="${bad} ${user}(${sh})"
    done < /etc/passwd
    [ -n "$bad" ] && result "SRV-165|취약|로그인 불필요 시스템 계정에 shell 부여:${bad}" || result "SRV-165|양호|시스템 계정에 대화형 shell 미부여"
}

# ================================================================
# SRV-175: NTP 설정
# ================================================================
check_SRV175() {
    evd "SRV-175" "chronyc tracking 2>/dev/null || ntpq -p 2>/dev/null || timedatectl 2>/dev/null | grep -i synch"
    # chrony
    command -v chronyc >/dev/null 2>&1 && \
        chronyc tracking 2>/dev/null | grep -q "Reference ID" && \
        result "SRV-175|양호|chronyc NTP 동기화 활성" && return
    # ntpq
    command -v ntpq >/dev/null 2>&1 && \
        ntpq -p 2>/dev/null | grep -q "^\*" && \
        result "SRV-175|양호|ntpq 활성 피어 확인" && return
    # timedatectl
    command -v timedatectl >/dev/null 2>&1 && \
        timedatectl 2>/dev/null | grep -q "synchronized: yes" && \
        result "SRV-175|양호|timedatectl NTP 동기화 활성" && return
    # AIX
    [ "$OS_FAMILY" = "AIX" ] && grep -q "server" /etc/ntp.conf 2>/dev/null && \
        result "SRV-175|수동확인|AIX ntp.conf 서버 설정됨 (동기화 상태 확인)" && return
    result "SRV-175|취약|NTP 동기화 설정 미확인"
}

# ================================================================
# SRV-177: sudo 명령어 접근 권한 설정
# ================================================================
check_SRV177() {
    # 평가기준: sudo 접근 제한 — 불필요한 사용자가 sudo 권한을 가지는지 확인
    evd "SRV-177" "ls -l /etc/sudoers; grep -vE '^\s*(#|Defaults|\$)' /etc/sudoers /etc/sudoers.d/* 2>/dev/null"
    command -v sudo >/dev/null 2>&1 || [ -f /etc/sudoers ] || { result "SRV-177|양호|sudo 미설치"; return; }
    local rules all="" who="" np=""
    rules=$(grep -hvE '^\s*(#|Defaults|$)|^\s*(User|Runas|Host|Cmnd)_Alias|^\s*@include|^\s*#include' /etc/sudoers /etc/sudoers.d/* 2>/dev/null | grep -E '=')
    all=$(echo "$rules" | awk '$1=="ALL" || $1=="%users" || $1=="%everyone" || $1=="%staff"{print $1}' | sort -u | tr '\n' ' ')
    who=$(echo "$rules" | awk '$1!="root"{print $1}' | sort -u | tr '\n' ' ')
    np=$(echo "$rules" | grep -c 'NOPASSWD')
    if [ -n "$all" ]; then result "SRV-177|취약|모든(또는 일반 사용자 그룹) 사용자 sudo 허용: ${all}"
    elif [ -n "$who" ]; then result "SRV-177|수동확인|sudo 권한 보유: ${who}(NOPASSWD 규칙 ${np}건) - 불필요 사용자 여부 확인"
    else result "SRV-177|양호|root 외 sudo 권한 없음"; fi
}

# ================================================================
# SRV-179: EoS 시스템 장비 교체 (자동 판정)
# ================================================================
check_SRV179() {
    evd "SRV-179" "uname -srm; cat /etc/os-release 2>/dev/null | head -5; oslevel -s 2>/dev/null; swlist -l product 2>/dev/null | grep -E '^\s*HP-UX' | head -3; pkg info entire 2>/dev/null | grep -iE 'version|branch'; cat /etc/release 2>/dev/null | head -2"
    EOS_SCRIPT="$(dirname "$0")/eos_checker.py"
    [ ! -f "$EOS_SCRIPT" ] && {
        result "SRV-179|수동확인|eos_checker.py 없음 - 수동 확인 필요"
        return
    }

    product="" version=""
    case "$OS_FAMILY" in
    AIX)
        product="aix"; version="${OS_MAJOR}.$(uname -r)"
        ;;
    SOLARIS)
        product="solaris"
        version=$(uname -r | sed 's/5\.//')
        ;;
    HPUX)
        product="hp-ux"
        version=$(uname -r | sed 's/B\.//')
        ;;
    LINUX)
        case "$OS_DISTRO" in
        RHEL|CENTOS|ROCKY|ORACLE)
            case "$ID" in   # 파생 배포판은 각자의 수명 주기 (CentOS 8 은 2021-12-31 조기 종료, Stream 은 별도)
            centos)    product="centos"; version="$OS_MAJOR"; case "$NAME" in *Stream*) version="${OS_MAJOR}-stream" ;; esac ;;
            rocky)     product="rocky"; version="$OS_MAJOR" ;;
            almalinux) product="almalinux"; version="$OS_MAJOR" ;;
            rhel|"")   product="rhel"; version="$OS_MAJOR" ;;
            *) result "SRV-179|수동확인|${PRETTY_NAME:-$ID $VERSION_ID} (RHEL 계열 파생 배포판) EoS 수동 확인 - 벤더 Lifecycle 대조"; return ;;
            esac ;;
        UBUNTU)
            product="ubuntu"
            version=$(grep -oE '[0-9]+\.[0-9]+' /etc/os-release 2>/dev/null | head -1) ;;
        DEBIAN)
            product="debian"; version="$OS_MAJOR" ;;
        SLES)
            product="sles"; version="$OS_MAJOR" ;;
        AMZN)
            product="amazon-linux"; version="$OS_MAJOR" ;;
        *)
            result "SRV-179|수동확인|OS ${OS_DISTRO} ${OS_MAJOR} EoS 수동 확인"
            return ;;
        esac ;;
    *)
        result "SRV-179|수동확인|OS 종류 미탐지 - 수동 확인"
        return ;;
    esac

    _PY=$(command -v python3 2>/dev/null || { [ -x /usr/libexec/platform-python ] && echo /usr/libexec/platform-python; } || command -v python 2>/dev/null)
    if [ -z "$_PY" ]; then result "SRV-179|수동확인|python 미설치 - ${product} ${version} EoS 여부 수동 확인"; return; fi
    _eo=$("$_PY" "$EOS_SCRIPT" "$product" "$version" 2>/dev/null)   # 인터넷 연결 시 endoflife.date 조회, 아니면 내장 데이터
    eos_result=$(echo "$_eo" | grep "^결과:" | awk '{print $2}')
    eos_desc=$(echo "$_eo" | grep "^설명:" | cut -d: -f2- | sed "s/^ *//;s/ *$//")
    [ -z "$eos_result" ] && { result "SRV-179|수동확인|EoS 판정 실패 - 수동 확인"; return; }
    result "SRV-179|${eos_result}|${eos_desc}"
}

# ================================================================
# SRV-087: C 컴파일러 권한
# ================================================================
check_SRV087() {
    local _cc_list; _cc_list=$(for c in /usr/bin/gcc /usr/bin/cc /usr/bin/g++ /usr/local/bin/gcc /usr/vac/bin/xlc /usr/vac/bin/cc /opt/aCC/bin/aCC /opt/ansic/bin/cc /opt/SUNWspro/bin/cc /opt/developerstudio*/bin/cc /usr/sfw/bin/gcc $(command -v cc gcc 2>/dev/null); do echo "$c"; done | sort -u)   # /usr/ucb/cc 는 Studio 미설치 시 동작하지 않는 래퍼라 제외
    evd "SRV-087" "ls -laL $(echo $_cc_list) 2>/dev/null"
    _cc_vuln=""
    for cc in $_cc_list; do
        [ -x "$cc" ] || continue
        perm=$(get_perm "$cc")
        if echo "$perm" | grep -qE "[1357]$"; then
            _cc_vuln="${_cc_vuln} ${cc}(${perm})"
        fi
    done
    if [ -z "$_cc_vuln" ]; then
        _cc_found=0
        for cc in $_cc_list; do
            [ -x "$cc" ] && _cc_found=1 && break
        done
        [ $_cc_found -eq 0 ] && result "SRV-087|양호|C 컴파일러 미설치" || \
            result "SRV-087|양호|C 컴파일러 other 실행 권한 없음"
    else
        result "SRV-087|취약|C 컴파일러 other 실행 허용:${_cc_vuln}"
    fi
}

# ================================================================
# SMTP 공통 탐지 (SRV-005~010 공용)
# ================================================================
_smtp_type=""  # sendmail / postfix / exim / ""
_smtp_cf=""
_smtp_pids() { ps -ef 2>/dev/null | grep -v grep | grep -v defunct | grep -E "$1" | awk '{print $2}'; }
_in_container_only() {   # 모든 PID 가 '점검 스크립트와 다른' 컨테이너 cgroup 이면 참 (/proc 없는 UNIX 는 거짓 = 호스트 서비스)
    local p any=0 self; self=$(cat /proc/self/cgroup 2>/dev/null)
    for p in "$@"; do any=1; [ -r "/proc/$p/cgroup" ] || return 1
        grep -qE 'docker|containerd|kubepods|libpod' "/proc/$p/cgroup" 2>/dev/null || return 1
        [ "$(cat "/proc/$p/cgroup" 2>/dev/null)" = "$self" ] && return 1   # 스크립트와 같은 컨테이너 안의 MTA 는 대상 서비스
    done
    [ $any = 1 ]
}
_smtp_host() { local pids; pids=$(_smtp_pids "$1"); [ -n "$pids" ] || return 1; if _in_container_only $pids; then evd "SMTP" "echo '컨테이너 내부 MTA(${1}) - 호스트 판정 제외: '$(echo $pids)"; return 1; fi; return 0; }
_detect_smtp() {
    [ -n "$_smtp_type" ] && return
    if _smtp_host 'sendmail'; then
        _smtp_type="sendmail"
        for c in /etc/mail/sendmail.cf /etc/sendmail.cf /usr/lib/sendmail.cf; do
            [ -f "$c" ] && _smtp_cf="$c" && break
        done
    elif _smtp_host 'postfix|/master'; then
        _smtp_type="postfix"
        for c in /etc/postfix/main.cf /usr/local/etc/postfix/main.cf; do
            [ -f "$c" ] && _smtp_cf="$c" && break
        done
    elif _smtp_host 'exim'; then
        _smtp_type="exim"
        for c in /etc/exim4/exim4.conf /etc/exim/exim.conf; do
            [ -f "$c" ] && _smtp_cf="$c" && break
        done
    fi
}
_ver_lt() { [ "$1" != "$2" ] && [ "$(printf '%s\n%s\n' "$1" "$2" | sort -t. -k1,1n -k2,2n -k3,3n | head -1)" = "$1" ]; }
_smtp_running() {
    _detect_smtp
    [ -n "$_smtp_type" ] && return 0
    ss -tlnp 2>/dev/null | grep -q "[.:]25 " && return 0
    netstat -tlnp 2>/dev/null | grep -q ":25 " && return 0
    return 1
}

# ================================================================
# SRV-005: SMTP EXPN/VRFY 제한
# ================================================================
check_SRV005() {
    _smtp_running || { evd "SRV-005" "ps -ef 2>/dev/null | grep -E 'smtp|postfix|sendmail' | grep -v grep"; result "SRV-005|N-A|SMTP 서비스 미실행"; return; }
    _detect_smtp
    evd "SRV-005" "postconf disable_vrfy_command 2>/dev/null; grep -i PrivacyOptions $_smtp_cf 2>/dev/null"
    case "$_smtp_type" in
    postfix)
        local val=$(postconf -h disable_vrfy_command 2>/dev/null)
        [ "$val" = "yes" ] && result "SRV-005|양호|postfix disable_vrfy_command=yes" || \
            result "SRV-005|취약|postfix disable_vrfy_command=${val:-no}" ;;
    sendmail)
        # 평가기준: noexpn 과 novrfy 또는 goaway
        local po; po=$(grep -iE '^\s*O\s+PrivacyOptions' "$_smtp_cf" 2>/dev/null | tail -1)
        if echo "$po" | grep -qi "goaway" || { echo "$po" | grep -qi "noexpn" && echo "$po" | grep -qi "novrfy"; }; then
            result "SRV-005|양호|sendmail PrivacyOptions EXPN·VRFY 제한 (${po##*=})"
        else result "SRV-005|취약|sendmail PrivacyOptions noexpn·novrfy(또는 goaway) 미설정 (${po##*=})"; fi ;;
    *) result "SRV-005|수동확인|${_smtp_type:-SMTP} EXPN/VRFY 설정 수동 확인" ;;
    esac
}

# ================================================================
# SRV-006: SMTP 로그 수준
# ================================================================
check_SRV006() {
    _smtp_running || { evd "SRV-006" "ps -ef 2>/dev/null | grep -E 'smtp|postfix|sendmail' | grep -v grep"; result "SRV-006|N-A|SMTP 서비스 미실행"; return; }
    _detect_smtp
    evd "SRV-006" "postconf debug_peer_level syslog_facility 2>/dev/null; grep -i LogLevel $_smtp_cf 2>/dev/null"
    case "$_smtp_type" in
    postfix)
        # 평가기준: debug_peer_level 2 이상 (기본 2)
        local dl=$(postconf -h debug_peer_level 2>/dev/null)
        [ "${dl:-2}" -ge 2 ] 2>/dev/null && result "SRV-006|양호|postfix debug_peer_level=${dl:-2(기본)}" || result "SRV-006|취약|postfix debug_peer_level=${dl} (2 이상 필요)" ;;
    sendmail)
        # 평가기준: LogLevel 9 이상 (미설정 시 기본 9)
        local lv=$(grep -iE "^\s*O\s+LogLevel" "$_smtp_cf" 2>/dev/null | grep -oE '[0-9]+' | tail -1)
        [ "${lv:-9}" -ge 9 ] 2>/dev/null && result "SRV-006|양호|sendmail LogLevel=${lv:-9(기본)}" || result "SRV-006|취약|sendmail LogLevel=${lv} (9 이상 필요)" ;;
    *) result "SRV-006|수동확인|${_smtp_type:-SMTP} 로그 수준 수동 확인" ;;
    esac
}

# ================================================================
# SRV-007: SMTP 보안패치
# ================================================================
check_SRV007() {
    _smtp_running || { evd "SRV-007" "ps -ef 2>/dev/null | grep -E 'smtp|postfix|sendmail' | grep -v grep"; result "SRV-007|N-A|SMTP 서비스 미실행"; return; }
    _detect_smtp
    local ver=""
    case "$_smtp_type" in
    postfix) ver=$(postconf -h mail_version 2>/dev/null); evd "SRV-007" "postconf mail_version 2>/dev/null" ;;
    sendmail) ver=$(sendmail -d0.1 </dev/null 2>&1 | head -1 | grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)?' | head -1)
              [ -z "$ver" ] && ver=$(sed -n 's/^DZ\([0-9][0-9.]*\).*/\1/p' "$_smtp_cf" 2>/dev/null | head -1)
              evd "SRV-007" "sendmail -d0.1 </dev/null 2>&1 | head -1; grep '^DZ' $_smtp_cf 2>/dev/null" ;;
    exim) ver=$( { exim -bV 2>/dev/null || exim4 -bV 2>/dev/null; } | grep -oE 'version [0-9]+\.[0-9]+(\.[0-9]+)?' | head -1 | awk '{print $2}'); evd "SRV-007" "exim -bV 2>/dev/null | head -1; exim4 -bV 2>/dev/null | head -1" ;;
    esac
    # 평가기준 판단방법 최소 버전: Sendmail 8.14.9 / Postfix 2.5.13·2.6.10·2.7.4·2.8.3 / Exim 4.94.2 — 미만이면 알려진 취약점 미패치
    local min=""
    case "$_smtp_type" in
    sendmail) min="8.14.9" ;;
    exim) min="4.94.2" ;;
    postfix) case "$ver" in 2.5.*) min="2.5.13" ;; 2.6.*) min="2.6.10" ;; 2.7.*) min="2.7.4" ;; 2.8.*) min="2.8.3" ;; [01].*|2.[0-4].*) min="2.5.13" ;; esac ;;
    esac
    if [ -n "$ver" ] && [ -n "$min" ] && _ver_lt "$ver" "$min"; then result "SRV-007|취약|${_smtp_type} ${ver} - 평가기준 최소 버전 ${min} 미만 (보안 패치 미적용)"
    else result "SRV-007|수동확인|${_smtp_type} 버전=${ver:-미확인}${min:+ (평가기준 최소 ${min} 이상)} - 최신 버전·내부 패치 절차 확인"; fi
}

# ================================================================
# SRV-008: SMTP DoS 방지
# ================================================================
check_SRV008() {
    _smtp_running || { evd "SRV-008" "ps -ef 2>/dev/null | grep -E 'smtp|postfix|sendmail' | grep -v grep"; result "SRV-008|N-A|SMTP 서비스 미실행"; return; }
    _detect_smtp
    evd "SRV-008" "postconf message_size_limit header_size_limit default_process_limit local_destination_concurrency_limit smtpd_recipient_limit 2>/dev/null; grep -iE 'MaxDaemonChildren|ConnectionRateThrottle|MinFreeBlocks|MaxHeadersLength|MaxMessageSize' $_smtp_cf 2>/dev/null"
    case "$_smtp_type" in
    postfix)
        # 평가기준: 5개 파라미터는 기본값이 있어 미설정도 양호, 0(해제) 이면 취약
        local p z=""
        for p in message_size_limit header_size_limit default_process_limit local_destination_concurrency_limit smtpd_recipient_limit; do
            [ "$(postconf -h $p 2>/dev/null)" = "0" ] && z="${z} ${p}=0"
        done
        [ -n "$z" ] && result "SRV-008|취약|postfix 제한 해제(0):${z}" || result "SRV-008|양호|postfix DoS 제한 파라미터 기본값/설정값 유지 (0 해제 없음)" ;;
    sendmail)
        local p miss=""
        for p in MaxDaemonChildren ConnectionRateThrottle MinFreeBlocks MaxHeadersLength MaxMessageSize; do
            grep -qiE "^\s*O\s+${p}\s*=" "$_smtp_cf" 2>/dev/null || miss="${miss} ${p}"
        done
        [ -n "$miss" ] && result "SRV-008|취약|sendmail DoS 방지 파라미터 미설정:${miss}" || result "SRV-008|양호|sendmail DoS 방지 파라미터 5종 설정" ;;
    *) result "SRV-008|수동확인|${_smtp_type:-SMTP} DoS 방지 설정 수동 확인" ;;
    esac
}

# ================================================================
# SRV-009: SMTP 릴레이 제한
# ================================================================
check_SRV009() {
    _smtp_running || { evd "SRV-009" "ps -ef 2>/dev/null | grep -E 'smtp|postfix|sendmail' | grep -v grep"; result "SRV-009|N-A|SMTP 서비스 미실행"; return; }
    _detect_smtp
    evd "SRV-009" "postconf smtpd_relay_restrictions smtpd_recipient_restrictions mynetworks 2>/dev/null; grep -iE 'promiscuous_relay|relay_entire_domain|relay_local_from' $_smtp_cf /etc/mail/sendmail.mc 2>/dev/null; sendmail -d0.1 -bv root 2>/dev/null | head -1"
    case "$_smtp_type" in
    postfix)
        local mn=$(postconf -h mynetworks 2>/dev/null) rr=$(postconf -h smtpd_relay_restrictions 2>/dev/null)
        if echo "$mn $rr" | grep -qE '0\.0\.0\.0/0|static:all|\bpermit\s*(,|$)'; then result "SRV-009|취약|postfix 릴레이 전체 허용 (mynetworks=${mn})"
        else result "SRV-009|양호|postfix 릴레이 제한 (relay_restrictions=${rr:-기본 reject_unauth_destination})"; fi ;;
    sendmail)
        # 평가기준: 8.9 이상은 promiscuous_relay 비활성(기본)이면 양호, 8.9 미만은 access 파일 접근통제
        local ver; ver=$(sendmail -d0.1 -bv root 2>/dev/null | grep -oE 'Version [0-9]+\.[0-9]+' | awk '{print $2}' | head -1)
        [ -z "$ver" ] && ver=$(sed -n 's/^DZ\([0-9]*\.[0-9]*\).*/\1/p' "$_smtp_cf" 2>/dev/null | head -1)   # sendmail.cf 버전 매크로
        if grep -qiE 'promiscuous_relay|relay_entire_domain' "$_smtp_cf" /etc/mail/sendmail.mc 2>/dev/null; then result "SRV-009|취약|sendmail promiscuous_relay/relay_entire_domain 설정"
        elif [ -n "$ver" ] && { [ "${ver%%.*}" -gt 8 ] || { [ "${ver%%.*}" -eq 8 ] && [ "${ver#*.}" -ge 9 ]; }; } 2>/dev/null; then result "SRV-009|양호|sendmail ${ver} (8.9 이상 기본 릴레이 차단)"
        elif [ -f /etc/mail/access ]; then result "SRV-009|수동확인|sendmail ${ver:-버전 미확인} - /etc/mail/access 릴레이 접근통제 확인"
        else result "SRV-009|취약|sendmail ${ver:-버전 미확인} (8.9 미만 추정) - access 접근통제 파일 없음"; fi ;;
    *) result "SRV-009|수동확인|${_smtp_type:-SMTP} 릴레이 제한 수동 확인" ;;
    esac
}

# ================================================================
# SRV-010: SMTP 일반사용자 실행 방지
# ================================================================
check_SRV010() {
    _smtp_running || { evd "SRV-010" "ps -ef 2>/dev/null | grep -E 'smtp|postfix|sendmail' | grep -v grep"; result "SRV-010|N-A|SMTP 서비스 미실행"; return; }
    _detect_smtp
    evd "SRV-010" "ls -lL \$(postconf -h command_directory 2>/dev/null)/postsuper /usr/sbin/postsuper /usr/sbin/exim /usr/sbin/exim4 2>/dev/null; grep -i PrivacyOptions $_smtp_cf 2>/dev/null"
    case "$_smtp_type" in
    postfix)
        # 평가기준: postsuper 실행 파일 others 실행 권한 → 일반 사용자 queue 처리 가능
        local ps="$(postconf -h command_directory 2>/dev/null)/postsuper"; [ -f "$ps" ] || ps=/usr/sbin/postsuper
        if [ ! -f "$ps" ]; then result "SRV-010|수동확인|postsuper 실행 파일 확인 불가"
        else local p=$(get_perm "$ps"); [ $(( ${p: -1} & 1 )) -ne 0 ] && result "SRV-010|취약|${ps} others 실행 권한 (${p})" || result "SRV-010|양호|${ps} others 실행 권한 없음 (${p})"; fi ;;
    sendmail)
        grep -iE '^\s*O\s+PrivacyOptions' "$_smtp_cf" 2>/dev/null | grep -qi "restrictqrun" && \
            result "SRV-010|양호|sendmail PrivacyOptions restrictqrun 설정" || \
            result "SRV-010|취약|sendmail restrictqrun 미설정" ;;
    exim)
        local ex=$(command -v exim exim4 2>/dev/null | head -1); local p=$(get_perm "$ex")
        [ -n "$ex" ] && [ $(( ${p: -1} & 1 )) -ne 0 ] && result "SRV-010|취약|${ex} others 실행 권한 (${p})" || result "SRV-010|양호|exim others 실행 권한 없음 (${p:-미확인})" ;;
    *) result "SRV-010|수동확인|${_smtp_type:-SMTP} 일반사용자 실행 방지 수동 확인" ;;
    esac
}

# ================================================================
# SRV-012: .netrc 파일 점검
# ================================================================
check_SRV012() {
    # 평가기준: .netrc 내부에 아이디·패스워드 등 민감 정보 (전 계정 홈)
    local homes f found="" sens=""
    homes=$(awk -F: '$6!=""{print $6}' /etc/passwd 2>/dev/null | sort -u)
    for f in $(for h in $homes /root; do echo "${h%/}/.netrc"; done | sort -u); do
        [ -f "$f" ] || continue
        found="${found} ${f}"
        grep -qiE '\b(login|password)\b' "$f" 2>/dev/null && sens="${sens} ${f}"
    done
    evd "SRV-012" "echo '${found:- (없음)}'"
    if [ -n "$sens" ]; then result "SRV-012|취약|.netrc 에 계정·비밀번호 정보:${sens}"
    elif [ -n "$found" ]; then result "SRV-012|수동확인|.netrc 파일 존재(login/password 미발견):${found} - 내용 확인"
    else result "SRV-012|양호|.netrc 파일 미존재"; fi
}

# ================================================================
# SRV-021: FTP 접근통제
# ================================================================
check_SRV021() {
    _ftp_running || { evd "SRV-021" "ps -ef 2>/dev/null | grep -E 'vsftpd|proftpd|ftpd' | grep -v grep"; result "SRV-021|N-A|FTP 서비스 미실행"; return; }
    evd "SRV-021" "grep -iE 'tcp_wrappers|listen_address' /etc/vsftpd.conf /etc/vsftpd/vsftpd.conf 2>/dev/null; grep -iE 'vsftpd|ftp|ALL' /etc/hosts.allow /etc/hosts.deny 2>/dev/null; grep -iA3 '<Limit LOGIN>' /etc/proftpd/proftpd.conf /etc/proftpd.conf 2>/dev/null"
    # 평가기준: 특정 IP/호스트에서만 접속하도록 접근제어
    local conf tw hw
    conf=$(ls /etc/vsftpd.conf /etc/vsftpd/vsftpd.conf 2>/dev/null | head -1)
    if [ -n "$conf" ]; then
        tw=$(grep -iE "^\s*tcp_wrappers" "$conf" 2>/dev/null | tail -1 | cut -d= -f2 | tr -d ' ')
        hw=$(grep -vE '^\s*#' /etc/hosts.allow /etc/hosts.deny 2>/dev/null | grep -iE 'vsftpd|^\s*ALL\s*:' | head -2)
        [ "${tw^^}" = "YES" ] && [ -n "$hw" ] && { result "SRV-021|양호|vsftpd tcp_wrappers=YES + hosts.allow/deny 규칙"; return; }
    fi
    grep -vE '^\s*#' /etc/proftpd/proftpd.conf /etc/proftpd.conf 2>/dev/null | grep -iA3 "<Limit LOGIN>" | grep -qiE "Allow from|Deny from" && { result "SRV-021|양호|proftpd <Limit LOGIN> 접근 IP 제한"; return; }
    # 평가기준 판단방법(UNIX): AIX /etc/ftpaccess.ctl, HP-UX /etc/ftpd/ftphosts·ftpaccess, SOL /etc/ftpd/ftpaccess
    evd "SRV-021" "grep -vE '^\s*(#|\$)' /etc/ftpaccess.ctl /etc/ftpd/ftphosts 2>/dev/null; grep -iE '^\s*(allow|deny|class)' /etc/ftpd/ftpaccess 2>/dev/null"
    grep -qiE '^\s*(allow|deny)\s*:' /etc/ftpaccess.ctl 2>/dev/null && { result "SRV-021|양호|AIX /etc/ftpaccess.ctl allow/deny 설정"; return; }
    grep -qiE '^\s*(allow|deny)\s' /etc/ftpd/ftphosts 2>/dev/null && { result "SRV-021|양호|/etc/ftpd/ftphosts allow/deny 설정"; return; }
    result "SRV-021|수동확인|FTP 접근 IP 제한(tcp_wrappers 규칙·방화벽) 수동 확인 (vsftpd tcp_wrappers=${tw:-미설정})"
}

# ================================================================
# SRV-037: TFTP 서비스
# ================================================================
check_SRV037() {
    # 평가기준: FTP 서비스 활성 시 취약 (FTPS 등 통신 암호화 적용 시 양호)
    evd "SRV-037" "ps -ef 2>/dev/null | grep -E 'vsftpd|proftpd|pure-ftpd|ftpd' | grep -v grep; ss -tln 2>/dev/null | grep ':21 '; grep -iE '^\s*(ssl_enable|force_local_logins_ssl|force_local_data_ssl)' /etc/vsftpd.conf /etc/vsftpd/vsftpd.conf 2>/dev/null; grep -iE '^\s*TLS(Engine|Required)' /etc/proftpd/proftpd.conf /etc/proftpd/tls.conf 2>/dev/null"
    _ftp_running || { result "SRV-037|양호|FTP 서비스 비활성"; return; }
    local conf
    conf=$(ls /etc/vsftpd.conf /etc/vsftpd/vsftpd.conf 2>/dev/null | head -1)
    if [ -n "$conf" ] && is_running vsftpd; then
        if grep -qiE '^\s*ssl_enable\s*=\s*YES' "$conf" && ! grep -qiE '^\s*force_local_logins_ssl\s*=\s*NO' "$conf"; then result "SRV-037|양호|vsftpd FTPS(ssl_enable=YES) 적용"
        else result "SRV-037|취약|vsftpd 평문 FTP 서비스 활성 (ssl_enable 미설정 또는 SSL 로그인 강제 해제)"; fi
    elif is_running proftpd; then
        if grep -hiE '^\s*TLSEngine\s+on' /etc/proftpd/proftpd.conf /etc/proftpd/tls.conf 2>/dev/null | grep -q . && grep -hiE '^\s*TLSRequired\s+on' /etc/proftpd/proftpd.conf /etc/proftpd/tls.conf 2>/dev/null | grep -q .; then
            result "SRV-037|양호|proftpd TLSEngine on + TLSRequired on"
        else result "SRV-037|취약|proftpd 평문 FTP 허용 (TLSRequired 미설정)"; fi
    else result "SRV-037|취약|FTP 서비스 활성 (FTPS 적용 확인 불가 - 적용 시 수동 판정 변경)"; fi
}

# ================================================================
# SRV-082: 시스템 주요 디렉터리 권한
# ================================================================
check_SRV082() {
    # 평가기준: /usr /bin /sbin /etc /var 에 others 쓰기 권한이 있으면 취약
    evd "SRV-082" "ls -alLd /usr /bin /sbin /etc /var 2>/dev/null"
    local vuln="" d p
    for d in /usr /bin /sbin /etc /var; do
        [ -e "$d" ] || continue
        p=$(get_perm "$(readlink -f "$d" 2>/dev/null || echo "$d")"); p=${p: -1}
        [ $(( ${p:-0} & 2 )) -ne 0 ] 2>/dev/null && vuln="${vuln} ${d}(others 쓰기)"
    done
    [ -n "$vuln" ] && result "SRV-082|취약|시스템 주요 디렉터리 others 쓰기 권한:${vuln}" || \
        result "SRV-082|양호|시스템 주요 디렉터리(/usr /bin /sbin /etc /var) others 쓰기 권한 없음"
}

# ================================================================
# SRV-083: 시작 스크립트 권한
# ================================================================
check_SRV083() {
    # 평가기준: 시스템 스타트업 스크립트에 others 쓰기 권한 존재 시 취약 (소유자는 참고)
    evd "SRV-083" "ls -ld /etc/init.d /etc/rc.d /etc/rc.local 2>/dev/null; ls -la /etc/init.d/ /etc/systemd/system/*.service 2>/dev/null | head -20"
    local vuln="" f p
    while IFS= read -r f; do
        [ -f "$f" ] || continue
        p=$(get_perm "$f"); [ $(( ${p: -1} & 2 )) -ne 0 ] && vuln="${vuln} ${f}(${p}, 소유자=$(get_owner "$f"))"
    done < <( { for d in /etc/init.d /etc/rc.d/init.d /etc/rc.d/rc2.d /etc/rc.d/rc3.d /etc/rc2.d /etc/rc3.d /sbin/init.d /sbin/rc2.d /sbin/rc3.d; do [ -d "$d" ] && ls -1 "$d" 2>/dev/null | sed "s#^#$d/#"; done; ls /etc/rc.local /etc/systemd/system/*.service 2>/dev/null; } | sort -u | head -300)
    [ -n "$vuln" ] && result "SRV-083|취약|others 쓰기 가능 스타트업 스크립트:${vuln}" || result "SRV-083|양호|스타트업 스크립트 others 쓰기 권한 없음"
}

# ================================================================
# SRV-094: Crontab 참조 파일 권한
# ================================================================
check_SRV094() {
    # 평가기준: crontab 에서 실행하는 참조 파일에 others 쓰기 권한이 있으면 취약
    evd "SRV-094" "cat /etc/crontab /etc/cron.d/* /var/spool/cron/* /var/spool/cron/crontabs/* 2>/dev/null | grep -vE '^\s*(#|$)' | head -30"
    local vuln="" refs f p
    refs=$( { cat /etc/crontab /etc/cron.d/* 2>/dev/null | grep -vE '^\s*(#|$|[A-Z_]+=)' | awk '{for(i=7;i<=NF;i++) print $i}'
              cat /var/spool/cron/* /var/spool/cron/crontabs/* 2>/dev/null | grep -vE '^\s*(#|$|[A-Z_]+=)' | awk '{for(i=6;i<=NF;i++) print $i}'
              ls /etc/cron.hourly/* /etc/cron.daily/* /etc/cron.weekly/* /etc/cron.monthly/* 2>/dev/null
            } | grep -E '^/' | sort -u)
    for f in $refs; do
        [ -f "$f" ] || continue
        p=$(get_perm "$f"); p=${p: -1}
        [ $(( ${p:-0} & 2 )) -ne 0 ] 2>/dev/null && vuln="${vuln} ${f}"
    done
    local n; n=$(echo "$refs" | grep -c .)
    [ -n "$vuln" ] && result "SRV-094|취약|crontab 참조파일 others 쓰기 권한:${vuln}" || \
        result "SRV-094|양호|crontab 참조파일 ${n}개 others 쓰기 권한 없음"
}

# ================================================================
# SRV-095: 소유자/그룹 없는 파일
# ================================================================
check_SRV095() {
    evd "SRV-095" "_to 60 find / \$_FP \\( -nouser -o -nogroup \\) ! -path '/proc/*' ! -path '/sys/*' -print 2>/dev/null | head -10"
    local found="" _rc
    found=$(set -o pipefail; _to 60 find / $_FP \( -nouser -o -nogroup \) ! -path "/proc/*" ! -path "/sys/*" ! -path "/dev/*" ! -path "/run/*" ! -path "/var/lib/docker/*" ! -path "/var/lib/containers/*" -print 2>/dev/null | head -10); _rc=$?
    [ "$_rc" = "141" ] && _rc=0   # head 조기 종료(SIGPIPE)는 정상
    if [ -n "$found" ]; then
        result "SRV-095|취약|소유자/그룹 없는 파일 존재: $(echo "$found" | tr '\n' ',' | head -c 150)"
    elif [ "$_rc" = "124" ]; then
        result "SRV-095|수동확인|파일 검색 시간 초과(60초) - 소유자 없는 파일 수동 확인"
    else
        result "SRV-095|양호|소유자/그룹 없는 파일 없음"
    fi
}

# ================================================================
# SRV-096: 사용자 환경변수 파일 권한
# ================================================================
check_SRV096() {
    # 평가기준: 사용자 환경 파일에 others 권한(읽기/쓰기/실행)이 하나라도 있으면 취약
    evd "SRV-096" "for h in \$(awk -F: '\$7!~/(nologin|false)\$/{print \$6}' /etc/passwd | sort -u); do ls -l \$h/.profile \$h/.bashrc \$h/.bash_profile \$h/.kshrc \$h/.cshrc \$h/.login \$h/.*shrc 2>/dev/null; done | sort -u | head -40"
    local vuln="" user uid homedir sh df p o
    while IFS=: read -r user _ uid _ _ homedir sh; do
        case "$sh" in *nologin|*false) continue ;; esac
        [ -z "$homedir" ] || [ "$homedir" = "/" ] || [ ! -d "$homedir" ] && continue
        for df in "$homedir"/.profile "$homedir"/.login "$homedir"/.bash_profile "$homedir"/.bash_login "$homedir"/.*shrc; do
            [ -f "$df" ] || continue
            p=$(get_perm "$df"); o=$(get_owner "$df")
            [ "${p: -1}" != "0" ] && vuln="${vuln} ${df}(${p})"
            [ "$o" != "$user" ] && [ "$o" != "root" ] && vuln="${vuln} ${df}(소유자=${o})"
        done
    done < /etc/passwd
    [ -n "$vuln" ] && result "SRV-096|취약|사용자 환경파일 others 권한/소유자 이상:${vuln}" || \
        result "SRV-096|양호|사용자 환경파일 others 권한 없음"
}

# ================================================================
# SRV-112: Cron 로깅 설정
# ================================================================
check_SRV112() {
    evd "SRV-112" "grep -i cron /etc/rsyslog.conf /etc/rsyslog.d/*.conf /etc/syslog.conf 2>/dev/null | grep -v '^#'; grep CRONLOG /etc/default/cron 2>/dev/null"
    local found=0
    grep -rqiE "^\s*cron" /etc/rsyslog.conf /etc/rsyslog.d/*.conf /etc/syslog.conf 2>/dev/null && found=1
    [ "$OS_FAMILY" = "AIX" ] && grep -vE '^\s*(#|\*)' /etc/syslog.conf 2>/dev/null | grep -qi "cron" && found=1
    [ "$OS_FAMILY" = "SOLARIS" ] && grep -q '^CRONLOG=YES' /etc/default/cron 2>/dev/null && found=1
    [ $found -eq 1 ] && result "SRV-112|양호|cron 로그 기록 설정 (syslog 또는 CRONLOG=YES)" || \
        result "SRV-112|취약|cron 로그 기록 미설정"
}

# ================================================================
# SRV-115: 로그 검토/보고
# ================================================================
check_SRV115() {
    evd "SRV-115" "ls -la /var/log/messages /var/log/secure /var/log/auth.log /var/log/syslog 2>/dev/null | head -5"
    evd "SRV-115" "last -5 2>/dev/null"
    result "SRV-115|수동확인|로그 검토 수행 여부 수동 확인"
}

# ================================================================
# SRV-134: 스택 실행 방지
# ================================================================
check_SRV134() {
    case "$OS_FAMILY" in
    SOLARIS)
        evd "SRV-134" "grep noexec_user_stack /etc/system 2>/dev/null; sxadm status nxstack 2>/dev/null"
        if [ "${OS_MAJOR:-10}" -ge 11 ] 2>/dev/null && sxadm status nxstack 2>/dev/null | grep -qi "enabled"; then result "SRV-134|양호|Solaris 11 sxadm nxstack enabled"
        elif grep -qE '^\s*set\s+noexec_user_stack\s*=\s*1' /etc/system 2>/dev/null; then result "SRV-134|양호|/etc/system noexec_user_stack=1"
        else result "SRV-134|취약|스택 실행 방지 미설정 (noexec_user_stack / sxadm nxstack)"; fi ;;
    *)
        evd "SRV-134" "grep -o -m1 -w nx /proc/cpuinfo 2>/dev/null"
        if grep -q "nx" /proc/cpuinfo 2>/dev/null; then result "SRV-134|양호|CPU NX 비트 지원 (스택 실행 방지 활성)"
        else result "SRV-134|N-A|Linux 커널 기본 NX 보호 (확인 불필요)"; fi ;;
    esac
}

# ================================================================
# SRV-135: TCP 보안 설정
# ================================================================
check_SRV135() {
    case "$OS_FAMILY" in
    SOLARIS)
        # 평가기준(Solaris): TCP_STRONG_ISS=2 양호, 0/1 취약
        evd "SRV-135" "grep TCP_STRONG_ISS /etc/default/inetinit 2>/dev/null; ipadm show-prop -p _strong_iss tcp 2>/dev/null"
        local v; v=$(grep -E '^\s*TCP_STRONG_ISS' /etc/default/inetinit 2>/dev/null | cut -d= -f2 | tr -d ' ')
        [ -z "$v" ] && v=$(ipadm show-prop -p _strong_iss -co current tcp 2>/dev/null)
        case "$v" in 2) result "SRV-135|양호|TCP_STRONG_ISS=2" ;; 0|1) result "SRV-135|취약|TCP_STRONG_ISS=${v} (2 필요)" ;; *) result "SRV-135|수동확인|TCP_STRONG_ISS 확인 불가" ;; esac ;;
    *)
        evd "SRV-135" "sysctl net.ipv4.tcp_syncookies net.ipv4.conf.all.accept_redirects net.ipv4.conf.all.accept_source_route 2>/dev/null"
        result "SRV-135|N-A|평가대상 아님 (Solaris 전용 TCP_STRONG_ISS)" ;;
    esac
}

# ================================================================
# SRV-147: 네트워크 모니터링 서비스
# ================================================================
check_SRV147() {
    # 평가기준: 불필요한 네트워크 모니터링 서비스(SNMP 등)가 '실행 중'이면 취약 (판단방법: ps -ef | grep snmp)
    evd "SRV-147" "ps -ef 2>/dev/null | grep -E '[s]nmpd|[t]cpdump|[t]shark|[w]ireshark|[n]map' ; which tcpdump tshark wireshark nmap 2>/dev/null"
    local run_mon run_snmp inst=""
    run_snmp=$(_snmp_run && echo snmpd)
    run_mon=$(_comm | grep -xE 'tcpdump|tshark|wireshark|nmap|dumpcap' | sort -u | tr '\n' ' ')
    for t in tcpdump tshark wireshark nmap; do command -v $t >/dev/null 2>&1 && inst="${inst} ${t}"; done
    if [ -n "$run_mon" ]; then result "SRV-147|취약|네트워크 모니터링 도구 실행 중: ${run_mon}"
    elif [ -n "$run_snmp" ]; then result "SRV-147|수동확인|SNMP 서비스(snmpd) 실행 중 - 업무상 필요 여부 확인${inst:+ (설치된 도구:${inst})}"
    else result "SRV-147|양호|네트워크 모니터링 서비스 미실행${inst:+ (설치만 된 도구:${inst})}"; fi
}

# ================================================================
# SRV-164: GID 없는 계정
# ================================================================
check_SRV164() {
    # 평가기준: 구성원이 존재하지 않는 GID(보조 구성원도 없고 어떤 계정의 기본 그룹도 아닌 그룹) 존재 시 취약
    evd "SRV-164" "awk -F: '\$4==\"\"{print \$1\":\"\$3}' /etc/group 2>/dev/null | head -40; awk -F: '{print \$4}' /etc/passwd | sort -u | tr '\n' ' '"
    local umin; umin=$(awk '/^\s*GID_MIN/{print $2}' /etc/login.defs 2>/dev/null)
    [ -z "$umin" ] && case "$OS_FAMILY" in AIX) umin=200 ;; SOLARIS|HPUX) umin=100 ;; *) umin=1000 ;; esac   # UNIX 신규 그룹 GID 대역
    local pg; pg=" $(awk -F: '{print $4}' /etc/passwd 2>/dev/null | sort -u | tr '\n' ' ') "
    local empty_user="" empty_sys=0 g gid mem
    while IFS=: read -r g _ gid mem; do
        [ -z "$mem" ] || continue
        case "$pg" in *" $gid "*) continue ;; esac
        if [ "$gid" -ge "$umin" ] 2>/dev/null && [ "$gid" -lt 60000 ] 2>/dev/null; then empty_user="${empty_user} ${g}(${gid})"
        else empty_sys=$((empty_sys+1)); fi
    done < /etc/group
    if [ -n "$empty_user" ]; then result "SRV-164|취약|구성원 없는 그룹(GID ${umin} 이상):${empty_user} - 불필요 시 제거"
    else result "SRV-164|양호|신규 생성 GID(${umin} 이상) 중 구성원 없는 그룹 없음 (시스템 기본 그룹 ${empty_sys}개는 참고)"; fi
}

# ================================================================
# SRV-166: 숨김 파일/디렉터리
# ================================================================
check_SRV166() {
    evd "SRV-166" "find /home /root -maxdepth 2 -name '.*' ! -name '.bashrc' ! -name '.bash_profile' ! -name '.profile' ! -name '.bash_logout' ! -name '.ssh' ! -name '.bash_history' -type f 2>/dev/null | head -10"
    result "SRV-166|수동확인|불필요 숨김 파일 수동 확인"
}

# ================================================================
# SRV-170: SMTP 정보 노출
# ================================================================
check_SRV170() {
    _smtp_running || { evd "SRV-170" "ps -ef 2>/dev/null | grep -E 'smtp|postfix|sendmail' | grep -v grep"; result "SRV-170|N-A|SMTP 서비스 미실행"; return; }
    _detect_smtp
    evd "SRV-170" "postconf smtpd_banner 2>/dev/null; grep -i SmtpGreetingMessage $_smtp_cf 2>/dev/null; exim -bP smtp_banner 2>/dev/null"
    case "$_smtp_type" in
    postfix)
        local ban=$(postconf -h smtpd_banner 2>/dev/null)
        echo "$ban" | grep -qiE 'mail_version|version|[0-9]+\.[0-9]+' && result "SRV-170|취약|postfix 배너에 버전 정보 노출: ${ban}" || result "SRV-170|양호|SMTP 배너 버전 정보 노출 없음 (${ban})" ;;
    sendmail)
        # 평가기준: SmtpGreetingMessage 에 $v 포함 시 버전 노출 — 미설정 시 기본값('$j Sendmail $v/$Z; $b')도 노출
        local greet=$(grep -iE "^\s*O\s+SmtpGreetingMessage" "$_smtp_cf" 2>/dev/null | tail -1)
        if [ -z "$greet" ]; then result "SRV-170|취약|SmtpGreetingMessage 미설정 (기본 인사말에 버전 \$v 포함)"
        elif echo "$greet" | grep -qE '\$v|\$Z'; then result "SRV-170|취약|sendmail 배너에 버전(\$v/\$Z) 노출"
        else result "SRV-170|양호|sendmail 배너 버전 미노출"; fi ;;
    exim)
        exim -bP smtp_banner 2>/dev/null | grep -q 'version_number' && result "SRV-170|취약|exim smtp_banner 에 \$version_number 포함" || result "SRV-170|양호|exim 배너 버전 미노출" ;;
    *) result "SRV-170|수동확인|${_smtp_type:-SMTP} 배너 정보 수동 확인" ;;
    esac
}

# ================================================================
# SRV-171: FTP 배너 정보 노출
# ================================================================
check_SRV171() {
    _ftp_running || { evd "SRV-171" "ps -ef 2>/dev/null | grep -E 'vsftpd|proftpd|ftpd' | grep -v grep"; result "SRV-171|N-A|FTP 서비스 미실행"; return; }
    evd "SRV-171" "grep -iE 'ftpd_banner|banner_file|ServerIdent' /etc/vsftpd.conf /etc/vsftpd/vsftpd.conf /etc/proftpd/proftpd.conf /etc/proftpd.conf 2>/dev/null"
    local c b
    if is_running vsftpd; then
        c=$(ls /etc/vsftpd.conf /etc/vsftpd/vsftpd.conf 2>/dev/null | head -1)
        b=$(grep -iE '^\s*(ftpd_banner|banner_file)\s*=' "$c" 2>/dev/null | tail -1)
        if [ -z "$b" ]; then result "SRV-171|취약|vsftpd 배너 미설정 (기본 배너에 vsFTPd 버전 노출)"
        elif echo "$b" | grep -qiE 'vsftpd|[0-9]+\.[0-9]+\.[0-9]+'; then result "SRV-171|취약|vsftpd 배너에 서비스명·버전 노출: ${b}"
        else result "SRV-171|양호|vsftpd 배너 설정 (${b%%=*})"; fi
    elif is_running proftpd; then
        b=$(grep -hiE '^\s*ServerIdent' /etc/proftpd/proftpd.conf /etc/proftpd.conf 2>/dev/null | tail -1)
        if echo "$b" | grep -qiE 'ServerIdent\s+off|ServerIdent\s+on\s+"'; then result "SRV-171|양호|proftpd ${b}"
        else result "SRV-171|취약|proftpd ServerIdent 미설정 (기본 'ProFTPD x.y.z Server' 노출)"; fi
    elif [ -f /etc/ftpd/ftpaccess ]; then   # HP-UX·Solaris in.ftpd(wu-ftpd 계열) greeting
        b=$(grep -iE '^\s*greeting' /etc/ftpd/ftpaccess 2>/dev/null | awk '{print tolower($2)}' | tail -1)
        case "$b" in
        brief|terse|text) result "SRV-171|양호|ftpaccess greeting ${b} (버전 미노출)" ;;
        full) result "SRV-171|취약|ftpaccess greeting full (서비스명·버전 노출)" ;;
        *) result "SRV-171|수동확인|ftpaccess greeting 미설정 - 접속 배너 서비스명·버전 노출 확인" ;;
        esac
    else
        [ "$OS_FAMILY" = "AIX" ] && evd "SRV-171" "dspcat /usr/lib/nls/msg/\${LANG:-C}/ftpd.cat 2>/dev/null | grep -i 'ftp server' | head -3"
        result "SRV-171|수동확인|FTP 배너 서비스명·버전 노출 수동 확인"; fi
}

# ================================================================
# SRV-173: DNS 동적 업데이트
# ================================================================
check_SRV173() {
    is_running named || { evd "SRV-173" "ps -ef 2>/dev/null | grep named | grep -v grep"; result "SRV-173|N-A|DNS 서비스 미실행"; return; }
    local nc; nc=$(_named_conf)
    evd "SRV-173" "echo '$(echo "$nc" | grep -iE 'allow-update' | head -5)'"
    echo "$nc" | grep -qiE 'allow-update\s*\{\s*any\s*;' && result "SRV-173|취약|DNS allow-update any 설정됨" || result "SRV-173|양호|DNS 동적 업데이트 제한됨"
}

# ================================================================
# SRV-174: 불필요 DNS 서비스
# ================================================================
check_SRV174() {
    evd "SRV-174" "ps -ef 2>/dev/null | grep -E 'named|dnsmasq' | grep -v grep | head -5"
    # 평가기준: DNS 서비스가 실행 중이지 않거나 업무상 필요한 경우 양호
    if is_running named || is_running dnsmasq; then
        result "SRV-174|수동확인|DNS 서비스 실행 중 - 업무 필요성 확인"
    else
        result "SRV-174|양호|DNS 서비스 미실행"
    fi
}

# ================================================================
# SRV-176: 비밀번호 저장 암호화 방식
# ================================================================
check_SRV176() {
    evd "SRV-176" "grep -E '^ENCRYPT_METHOD|^MD5_CRYPT_ENAB' /etc/login.defs 2>/dev/null; awk -F: '\$2!~/^[!*]/{print \$1,substr(\$2,1,3)}' /etc/shadow 2>/dev/null | head -10"
    local algo=$(grep -E '^\s*ENCRYPT_METHOD' /etc/login.defs 2>/dev/null | awk '{print $2}' | tail -1)
    local weak=""
    while IFS=: read -r user hash rest; do
        [ -z "$hash" ] || echo "$hash" | grep -qE '^\$|^[!*]|^$' || continue
        case "$hash" in
            \$1\$*) weak="${weak} ${user}(MD5)" ;;
            \$2*) ;;
            \$5\$*) ;;
            \$6\$*) ;;
            \$y\$*) ;;
            '!'*|'*'|'') ;;
            *) weak="${weak} ${user}(DES/unknown)" ;;
        esac
    done < /etc/shadow 2>/dev/null
    if [ -n "$weak" ]; then
        result "SRV-176|취약|취약 해시 사용 계정:${weak} (기본 algo=${algo:-미설정})"
    elif [ -n "$algo" ]; then
        result "SRV-176|양호|비밀번호 암호화 방식=${algo}"
    else
        result "SRV-176|수동확인|ENCRYPT_METHOD 미설정 - shadow 해시 수동 확인"
    fi
}

# ================================================================
# 추가 SRV 항목 (전자금융기반시설 전체 179항목 커버)
# ================================================================

# SRV-002: 패스워드 복잡성
check_SRV002() {
    evd "SRV-002" "grep -E '^\s*(PASS_MIN_LEN|MINLEN)' /etc/login.defs 2>/dev/null; grep -v '^#' $(get_pam_files) 2>/dev/null | grep -iE 'pam_pwquality|pam_cracklib'; cat /etc/security/pwquality.conf 2>/dev/null | grep -v '^#' | grep -v '^\s*$'"
    local minlen="" dcredit="" ucredit="" lcredit="" ocredit=""
    for pf in $(get_pam_files); do
        [ -f "$pf" ] || continue
        local ml=$(grep -v '^#' "$pf" 2>/dev/null | grep -oE 'minlen=[0-9]+' | head -1 | cut -d= -f2)
        [ -n "$ml" ] && minlen=$ml
    done
    if [ -f /etc/security/pwquality.conf ]; then
        [ -z "$minlen" ] && minlen=$(grep -E '^\s*minlen' /etc/security/pwquality.conf 2>/dev/null | grep -oE '[0-9]+' | head -1)
        dcredit=$(grep -E '^\s*dcredit' /etc/security/pwquality.conf 2>/dev/null | grep -oE '[-0-9]+' | head -1)
        ucredit=$(grep -E '^\s*ucredit' /etc/security/pwquality.conf 2>/dev/null | grep -oE '[-0-9]+' | head -1)
        lcredit=$(grep -E '^\s*lcredit' /etc/security/pwquality.conf 2>/dev/null | grep -oE '[-0-9]+' | head -1)
        ocredit=$(grep -E '^\s*ocredit' /etc/security/pwquality.conf 2>/dev/null | grep -oE '[-0-9]+' | head -1)
    fi
    [ -z "$minlen" ] && minlen=$(grep -E '^\s*PASS_MIN_LEN' /etc/login.defs 2>/dev/null | awk '{print $2}' | tail -1)
    local has_complexity=0
    grep -v '^#' $(get_pam_files) 2>/dev/null | grep -qiE 'pam_pwquality|pam_cracklib' && has_complexity=1
    if [ "${minlen:-0}" -ge 8 ] 2>/dev/null && [ $has_complexity -eq 1 ]; then
        result "SRV-002|양호|패스워드 복잡성 설정됨 (minlen=${minlen}, dcredit=${dcredit:--1}, ucredit=${ucredit:--1}, lcredit=${lcredit:--1}, ocredit=${ocredit:--1})"
    elif [ "${minlen:-0}" -ge 8 ] 2>/dev/null; then
        result "SRV-002|취약|패스워드 길이=${minlen} 이나 복잡성 모듈(pam_pwquality/cracklib) 미적용"
    else
        result "SRV-002|취약|패스워드 최소 길이=${minlen:-미설정} (8자리 이상 + 복잡성 필요)"
    fi
}

# SRV-017: 관리자 그룹 최소 계정
check_SRV017() {
    evd "SRV-017" "grep -E '^(wheel|sudo|admin|root):' /etc/group 2>/dev/null"
    local info="" total=0
    for grp in wheel sudo admin root; do
        local members=$(grep "^${grp}:" /etc/group 2>/dev/null | cut -d: -f4)
        if [ -n "$members" ]; then
            local cnt=$(echo "$members" | tr ',' '\n' | grep -v '^$' | wc -l)
            total=$((total + cnt))
            info="${info} ${grp}:[${members}](${cnt}명)"
        fi
    done
    [ "$total" -le 5 ] 2>/dev/null && result "SRV-017|양호|관리자 그룹 멤버 ${total}명${info}" || \
        result "SRV-017|취약|관리자 그룹 멤버 과다 (${total}명)${info}"
}

# SRV-018: su 제한
check_SRV018() {
    evd "SRV-018" "cat /etc/pam.d/su 2>/dev/null | grep -v '^#'"
    if grep -v "^#" /etc/pam.d/su 2>/dev/null | grep -qi "pam_wheel"; then
        local wg=$(grep -v "^#" /etc/pam.d/su 2>/dev/null | grep -i "pam_wheel" | grep -oE 'group=\S+' | cut -d= -f2 | head -1)
        result "SRV-018|양호|su pam_wheel 제한 설정됨 (그룹=${wg:-wheel})"
    else
        result "SRV-018|취약|su pam_wheel 미설정 (root 외 su 제한 없음)"
    fi
}

# SRV-019: 불필요 관리자 그룹 구성원
check_SRV019() {
    evd "SRV-019" "grep -E '^(wheel|sudo|admin):' /etc/group 2>/dev/null; id root 2>/dev/null"
    local info=""
    for grp in wheel sudo admin; do
        local members=$(grep "^${grp}:" /etc/group 2>/dev/null | cut -d: -f4)
        [ -n "$members" ] && info="${info} ${grp}:[${members}]"
    done
    [ -n "$info" ] && result "SRV-019|수동확인|관리자 그룹 구성원 확인:${info}" || \
        result "SRV-019|양호|관리자 그룹 구성원 없음"
}

# SRV-020: GID 없는 계정
check_SRV020() {
    evd "SRV-020" "awk -F: '{print \$1,\$4}' /etc/passwd 2>/dev/null | head -20"
    local found=""
    while IFS=: read -r user _ _ gid _ _ _; do
        getent group "$gid" >/dev/null 2>&1 || found="${found} ${user}(GID=${gid})"
    done < /etc/passwd 2>/dev/null
    [ -n "$found" ] && result "SRV-020|취약|존재하지 않는 GID:${found}" || \
        result "SRV-020|양호|모든 계정 GID 유효"
}

# SRV-023: 서비스 접근 IP/Port 제한
check_SRV023() {
    evd "SRV-023" "cat /etc/hosts.allow 2>/dev/null | grep -v '^#' | grep -v '^\s*$'; echo '---'; cat /etc/hosts.deny 2>/dev/null | grep -v '^#' | grep -v '^\s*$'; echo '---'; iptables -L -n 2>/dev/null | head -20; firewall-cmd --list-all 2>/dev/null"
    local ctrl=0
    [ -f /etc/hosts.deny ] && grep -qv "^#" /etc/hosts.deny 2>/dev/null && grep -qiE "ALL.*ALL|sshd" /etc/hosts.deny 2>/dev/null && ctrl=1
    iptables -L -n 2>/dev/null | grep -qiE "ACCEPT|DROP|REJECT" && ctrl=1
    firewall-cmd --state 2>/dev/null | grep -q "running" && ctrl=1
    [ $ctrl -eq 1 ] && result "SRV-023|수동확인|접근통제 설정 존재 (위 현황의 규칙 적정성 확인)" || \
        result "SRV-023|취약|TCP Wrapper/방화벽 접근통제 미설정"
}

# SRV-024: 계정 잠금
check_SRV024() {
    evd "SRV-024" "grep -v '^#' $(get_pam_files) 2>/dev/null | grep -iE 'pam_tally2|pam_faillock|faillock'; cat /etc/security/faillock.conf 2>/dev/null | grep -v '^#' | grep -v '^\s*$'"
    local lock=0 deny=""
    for pf in $(get_pam_files) /etc/pam.d/system-auth /etc/pam.d/password-auth /etc/pam.d/common-auth; do
        [ -f "$pf" ] || continue
        grep -v "^#" "$pf" 2>/dev/null | grep -qiE "pam_tally2|pam_faillock" && lock=1
        local d=$(grep -v "^#" "$pf" 2>/dev/null | grep -oE 'deny=[0-9]+' | head -1 | cut -d= -f2)
        [ -n "$d" ] && deny=$d
    done
    [ -z "$deny" ] && [ -f /etc/security/faillock.conf ] && deny=$(grep -E '^\s*deny' /etc/security/faillock.conf 2>/dev/null | grep -oE '[0-9]+' | head -1)
    if [ $lock -eq 1 ] && [ "${deny:-0}" -gt 0 ] 2>/dev/null; then
        result "SRV-024|양호|계정 잠금 설정됨 (deny=${deny})"
    elif [ $lock -eq 1 ]; then
        result "SRV-024|수동확인|잠금 모듈 로드되나 deny 값 확인 필요"
    else
        result "SRV-024|취약|계정 잠금 미설정 (pam_tally2/faillock 없음)"
    fi
}

# SRV-029: 불필요 서비스 (echo/discard/daytime/chargen)
check_SRV029() {
    evd "SRV-029" "systemctl list-unit-files 2>/dev/null | grep -iE 'echo|discard|daytime|chargen'; ls /etc/xinetd.d/ 2>/dev/null | grep -iE 'echo|discard|daytime|chargen'"
    local found=""
    for svc in echo-dgram echo-stream discard-dgram discard-stream daytime-dgram daytime-stream chargen-dgram chargen-stream; do
        if [ -f "/etc/xinetd.d/$svc" ]; then
            grep -q "disable.*=.*no" "/etc/xinetd.d/$svc" 2>/dev/null && found="${found} ${svc}(xinetd)"
        fi
        systemctl is-active "${svc}.socket" 2>/dev/null | grep -q "^active" && found="${found} ${svc}(systemd)"
    done
    [ -n "$found" ] && result "SRV-029|취약|불필요 서비스 활성화:${found}" || \
        result "SRV-029|양호|echo/discard/daytime/chargen 비활성화"
}

# SRV-030: NFS 비활성화
check_SRV030() {
    evd "SRV-030" "systemctl is-active nfs-server nfs 2>/dev/null; ps -ef 2>/dev/null | grep -E 'nfsd|rpc.nfsd' | grep -v grep"
    if is_running nfs-server || is_running nfs || is_running nfsd; then
        result "SRV-030|수동확인|NFS 서비스 실행 중 (업무 필요 여부 확인)"
    else
        result "SRV-030|양호|NFS 서비스 미실행"
    fi
}

# SRV-031: NFS 접근통제
check_SRV031() {
    evd "SRV-031" "cat /etc/exports 2>/dev/null; showmount -e 2>/dev/null"
    if [ ! -f /etc/exports ]; then
        result "SRV-031|양호|/etc/exports 미존재 (NFS 미사용)"; return
    fi
    local wide=""
    grep -v "^#" /etc/exports 2>/dev/null | grep -qE "\*|0\.0\.0\.0" && wide="yes"
    [ -n "$wide" ] && result "SRV-031|취약|NFS 전체 공유 허용 (* 또는 0.0.0.0)" || \
        result "SRV-031|수동확인|NFS exports 설정 확인 (위 현황 참조)"
}

# SRV-032: automountd 비활성화
check_SRV032() {
    evd "SRV-032" "systemctl is-active autofs 2>/dev/null; ps -ef 2>/dev/null | grep automount | grep -v grep"
    if is_running autofs || is_running automountd; then
        result "SRV-032|취약|automountd/autofs 서비스 실행 중"
    else
        result "SRV-032|양호|automountd/autofs 비활성화"
    fi
}

# SRV-033: 불필요 RPC 서비스
check_SRV033() {
    evd "SRV-033" "rpcinfo -p 2>/dev/null | head -20; ps -ef 2>/dev/null | grep -E 'rpc\\.cmsd|rpc\\.ttdbserverd|sadmind|rstatd|rusersd|rwalld|sprayd' | grep -v grep"
    local found=""
    for svc in rpc.cmsd rpc.ttdbserverd sadmind rstatd rusersd rwalld sprayd; do
        ps -ef 2>/dev/null | grep -v grep | grep -qw "$svc" && found="${found} ${svc}"
    done
    [ -n "$found" ] && result "SRV-033|취약|불필요 RPC 서비스:${found}" || \
        result "SRV-033|양호|불필요 RPC 서비스 미실행"
}

# SRV-036: Sendmail 일반사용자 실행 방지
check_SRV036() {
    evd "SRV-036" "ls -la /usr/sbin/sendmail /usr/lib/sendmail 2>/dev/null; grep -i restrictqrun /etc/mail/sendmail.cf /etc/sendmail.cf 2>/dev/null"
    if ! is_running sendmail; then
        result "SRV-036|양호|Sendmail 미실행"; return
    fi
    local vuln=""
    for sm in /usr/sbin/sendmail /usr/lib/sendmail; do
        [ -e "$sm" ] || continue
        local perm=$(get_perm "$sm")
        local other_x=$((${perm:-0} % 10))
        [ $((other_x & 1)) -eq 1 ] 2>/dev/null && vuln="${vuln} ${sm}(${perm})"
    done
    local cf=""
    for c in /etc/mail/sendmail.cf /etc/sendmail.cf; do [ -f "$c" ] && cf="$c" && break; done
    [ -n "$cf" ] && ! grep -qi "restrictqrun" "$cf" 2>/dev/null && vuln="${vuln} [restrictqrun 미설정]"
    [ -n "$vuln" ] && result "SRV-036|취약|Sendmail 실행방지 미흡:${vuln}" || \
        result "SRV-036|양호|Sendmail 실행 권한 제한됨"
}

# SRV-038: 웹서비스 디렉터리 리스팅
check_SRV038() {
    evd "SRV-038" "grep -riE 'Options.*Indexes|autoindex' /etc/httpd/conf/ /etc/apache2/ /etc/nginx/ 2>/dev/null | grep -v '^#' | head -10"
    local web_running=0
    is_running httpd || is_running apache2 && web_running=1
    is_running nginx && web_running=1
    if [ $web_running -eq 0 ]; then
        result "SRV-038|N-A|웹서비스 미실행"; return
    fi
    local vuln=""
    for cf in /etc/httpd/conf/httpd.conf /etc/apache2/apache2.conf /etc/apache2/sites-enabled/*.conf; do
        [ -f "$cf" ] || continue
        grep -v "^#" "$cf" 2>/dev/null | grep -qi "Options.*Indexes" && vuln="${vuln} ${cf}"
    done
    for cf in /etc/nginx/nginx.conf /etc/nginx/conf.d/*.conf /etc/nginx/sites-enabled/*; do
        [ -f "$cf" ] || continue
        grep -v "^#" "$cf" 2>/dev/null | grep -qi "autoindex.*on" && vuln="${vuln} ${cf}"
    done
    [ -n "$vuln" ] && result "SRV-038|취약|디렉터리 리스팅 활성화:${vuln}" || \
        result "SRV-038|양호|디렉터리 리스팅 비활성화"
}

# SRV-039: 웹프로세스 권한
check_SRV039() {
    evd "SRV-039" "grep -iE '^\s*(User|Group)' /etc/httpd/conf/httpd.conf /etc/apache2/envvars /etc/apache2/apache2.conf 2>/dev/null | grep -v '^#'; ps aux 2>/dev/null | grep -E 'httpd|apache2|nginx' | head -5"
    local web_running=0
    is_running httpd || is_running apache2 || is_running nginx && web_running=1
    if [ $web_running -eq 0 ]; then
        result "SRV-039|N-A|웹서비스 미실행"; return
    fi
    local web_user=$(ps aux 2>/dev/null | grep -E 'httpd|apache2|nginx' | grep -v grep | grep -v root | awk '{print $1}' | sort -u | head -1)
    if [ "$web_user" = "root" ] || [ -z "$web_user" ]; then
        local cfg_user=$(grep -iE '^\s*User\s' /etc/httpd/conf/httpd.conf /etc/apache2/apache2.conf 2>/dev/null | grep -v '^#' | awk '{print $NF}' | tail -1)
        [ "$cfg_user" = "root" ] && result "SRV-039|취약|웹프로세스 root 권한 실행" || \
            result "SRV-039|수동확인|웹프로세스 실행 사용자 확인 필요 (${cfg_user:-미확인})"
    else
        result "SRV-039|양호|웹프로세스 사용자=${web_user}"
    fi
}

# SRV-040: 상위 디렉터리 접근 금지
check_SRV040() {
    evd "SRV-040" "grep -riE 'AllowOverride|<Directory' /etc/httpd/conf/httpd.conf /etc/apache2/apache2.conf 2>/dev/null | grep -v '^#' | head -10"
    is_running httpd || is_running apache2 || { result "SRV-040|N-A|Apache 미실행"; return; }
    local vuln=""
    for cf in /etc/httpd/conf/httpd.conf /etc/apache2/apache2.conf; do
        [ -f "$cf" ] || continue
        grep -v "^#" "$cf" 2>/dev/null | grep -qi "AllowOverride.*All" && vuln="${vuln} ${cf}"
    done
    [ -n "$vuln" ] && result "SRV-040|수동확인|AllowOverride All 설정 확인:${vuln}" || \
        result "SRV-040|양호|AllowOverride 제한됨"
}

# SRV-041: 웹서비스 불필요 파일 제거
check_SRV041() {
    evd "SRV-041" "ls -d /var/www/manual /usr/share/httpd/manual /etc/httpd/conf.d/manual.conf /var/www/html/index.html 2>/dev/null"
    is_running httpd || is_running apache2 || { result "SRV-041|N-A|Apache 미실행"; return; }
    local found=""
    for d in /var/www/manual /usr/share/httpd/manual /usr/share/doc/apache2; do
        [ -d "$d" ] && found="${found} ${d}"
    done
    [ -f /etc/httpd/conf.d/manual.conf ] && found="${found} manual.conf"
    [ -n "$found" ] && result "SRV-041|취약|불필요 파일/디렉터리 존재:${found}" || \
        result "SRV-041|양호|불필요 매뉴얼/샘플 파일 미존재"
}

# SRV-042: 심볼릭 링크 사용 금지
check_SRV042() {
    evd "SRV-042" "grep -riE 'Options.*FollowSymLinks' /etc/httpd/conf/httpd.conf /etc/apache2/apache2.conf 2>/dev/null | grep -v '^#'"
    is_running httpd || is_running apache2 || { result "SRV-042|N-A|Apache 미실행"; return; }
    local vuln=""
    for cf in /etc/httpd/conf/httpd.conf /etc/apache2/apache2.conf; do
        [ -f "$cf" ] || continue
        grep -v "^#" "$cf" 2>/dev/null | grep -qi "Options.*FollowSymLinks" && \
            ! grep -v "^#" "$cf" 2>/dev/null | grep -qi "Options.*-FollowSymLinks" && vuln="${vuln} ${cf}"
    done
    [ -n "$vuln" ] && result "SRV-042|취약|FollowSymLinks 허용:${vuln}" || \
        result "SRV-042|양호|FollowSymLinks 제한됨"
}

# SRV-043: 파일 업로드/다운로드 제한
check_SRV043() {
    evd "SRV-043" "grep -riE 'LimitRequestBody|client_max_body_size' /etc/httpd/conf/ /etc/apache2/ /etc/nginx/ 2>/dev/null | grep -v '^#' | head -5"
    is_running httpd || is_running apache2 || is_running nginx || { result "SRV-043|N-A|웹서비스 미실행"; return; }
    local found=""
    grep -riE 'LimitRequestBody' /etc/httpd/conf/ /etc/apache2/ 2>/dev/null | grep -v "^#" | head -1 | grep -q "LimitRequestBody" && found="Apache"
    grep -riE 'client_max_body_size' /etc/nginx/ 2>/dev/null | grep -v "^#" | head -1 | grep -q "client_max_body_size" && found="${found:+$found/}Nginx"
    [ -n "$found" ] && result "SRV-043|양호|업로드 제한 설정됨 (${found})" || \
        result "SRV-043|취약|파일 업로드 크기 제한 미설정"
}

# SRV-044: 웹서비스 영역 분리
check_SRV044() {
    evd "SRV-044" "grep -iE '^\s*DocumentRoot' /etc/httpd/conf/httpd.conf /etc/apache2/sites-enabled/*.conf 2>/dev/null | grep -v '^#'; grep -iE '^\s*root\s' /etc/nginx/sites-enabled/* /etc/nginx/conf.d/*.conf 2>/dev/null | grep -v '^#'"
    is_running httpd || is_running apache2 || is_running nginx || { result "SRV-044|N-A|웹서비스 미실행"; return; }
    local docroot=""
    docroot=$(grep -iE '^\s*DocumentRoot' /etc/httpd/conf/httpd.conf /etc/apache2/sites-enabled/*.conf 2>/dev/null | grep -v '^#' | awk '{print $NF}' | tr -d '"' | tail -1)
    [ -z "$docroot" ] && docroot=$(grep -iE '^\s*root\s' /etc/nginx/sites-enabled/* /etc/nginx/conf.d/*.conf 2>/dev/null | grep -v '^#' | awk '{print $NF}' | tr -d ';' | tail -1)
    if [ "$docroot" = "/" ]; then
        result "SRV-044|취약|DocumentRoot=/ (루트 디렉터리 설정)"
    elif [ -n "$docroot" ]; then
        result "SRV-044|양호|DocumentRoot=${docroot}"
    else
        result "SRV-044|수동확인|DocumentRoot 확인 필요"
    fi
}

# SRV-045: 보안패치
check_SRV045() {
    evd "SRV-045" "uname -r; rpm -qa --last 2>/dev/null | head -10; apt list --upgradable 2>/dev/null | head -10; yum updateinfo summary 2>/dev/null | head -10"
    result "SRV-045|수동확인|최신 보안패치 적용 여부 수동 확인 (위 현황 참조)"
}

# SRV-046: 로그 검토/보고
check_SRV046() {
    evd "SRV-046" "ls -lt /var/log/syslog /var/log/messages /var/log/secure /var/log/auth.log /var/log/cron 2>/dev/null | head -10; last -5 2>/dev/null"
    result "SRV-046|수동확인|로그 정기 검토/보고 수동 확인 (위 현황 참조)"
}

# SRV-047: 시스템 로깅 설정
check_SRV047() {
    evd "SRV-047" "grep -vE '^#|^\s*$' /etc/rsyslog.conf /etc/rsyslog.d/*.conf /etc/syslog.conf 2>/dev/null | head -20"
    local logging=0
    for f in /etc/rsyslog.conf /etc/rsyslog.d/*.conf /etc/syslog.conf; do
        [ -f "$f" ] || continue
        grep -qiE "^auth|^authpriv|^kern|^cron" "$f" 2>/dev/null && logging=1
    done
    [ $logging -eq 1 ] && result "SRV-047|양호|시스템 로깅 설정됨 (auth/kern/cron)" || \
        result "SRV-047|취약|시스템 로깅 미설정"
}

# SRV-048: su 사용 로그
check_SRV048() {
    evd "SRV-048" "ls -la /var/log/sulog /var/log/auth.log /var/log/secure 2>/dev/null; grep -i 'SULOG_FILE\|su.*session' /etc/login.defs /etc/rsyslog.conf /etc/pam.d/su 2>/dev/null | grep -v '^#'"
    if [ -f /var/log/auth.log ] || [ -f /var/log/secure ]; then
        result "SRV-048|양호|su 사용 로그 기록됨 (auth.log/secure)"
    elif [ -f /var/log/sulog ]; then
        result "SRV-048|양호|su 사용 로그 기록됨 (/var/log/sulog)"
    else
        result "SRV-048|취약|su 사용 로그 미설정"
    fi
}

# SRV-049: 접속기록 파일 보호
check_SRV049() {
    evd "SRV-049" "ls -la /var/log/wtmp /var/log/btmp /var/log/lastlog /var/run/utmp 2>/dev/null"
    local vuln=""
    for f in /var/log/wtmp /var/log/btmp /var/log/lastlog; do
        [ -f "$f" ] || continue
        local perm=$(get_perm "$f") owner=$(get_owner "$f")
        [ "$owner" != "root" ] && vuln="${vuln} ${f}(소유자=${owner})"
        [ "${perm:-777}" -gt 644 ] 2>/dev/null && vuln="${vuln} ${f}(${perm})"
    done
    if [ -f /var/log/btmp ]; then
        local bp=$(get_perm "/var/log/btmp")
        [ "${bp:-777}" -gt 600 ] 2>/dev/null && vuln="${vuln} btmp(${bp},600이하필요)"
    fi
    [ -n "$vuln" ] && result "SRV-049|취약|접속기록 파일 권한 이상:${vuln}" || \
        result "SRV-049|양호|접속기록 파일 권한 적절"
}

# SRV-050: 로그인/로그아웃 기록
check_SRV050() {
    evd "SRV-050" "last -5 2>/dev/null; lastlog 2>/dev/null | head -15; ls -la /var/log/wtmp /var/log/lastlog 2>/dev/null"
    if [ -f /var/log/wtmp ] && [ -f /var/log/lastlog ]; then
        result "SRV-050|양호|로그인/로그아웃 기록 파일 존재 (wtmp/lastlog)"
    else
        result "SRV-050|취약|로그인/로그아웃 기록 파일 미존재"
    fi
}

# SRV-051: su 사용자 제한 (wheel 그룹)
check_SRV051() {
    evd "SRV-051" "grep -v '^#' /etc/pam.d/su 2>/dev/null | grep pam_wheel; grep '^wheel:' /etc/group 2>/dev/null"
    if grep -v "^#" /etc/pam.d/su 2>/dev/null | grep -qi "pam_wheel"; then
        local members=$(grep "^wheel:" /etc/group 2>/dev/null | cut -d: -f4)
        result "SRV-051|양호|su pam_wheel 제한됨 (wheel 멤버: ${members:-없음})"
    else
        result "SRV-051|취약|su 사용자 제한 미설정 (pam_wheel 없음)"
    fi
}

# SRV-052: SMTP 비활성화
check_SRV052() {
    evd "SRV-052" "systemctl is-active postfix sendmail exim4 2>/dev/null; ss -tlnp 2>/dev/null | grep ':25 '"
    _smtp_running && result "SRV-052|수동확인|SMTP 서비스 실행 중 (업무 필요 여부 확인)" || \
        result "SRV-052|양호|SMTP 서비스 미실행"
}

# SRV-053: SMTP Banner 정보 제한
check_SRV053() {
    _smtp_running || { evd "SRV-053" "ps -ef 2>/dev/null | grep -E 'smtp|postfix|sendmail' | grep -v grep"; result "SRV-053|N-A|SMTP 미실행"; return; }
    _detect_smtp
    evd "SRV-053" "postconf smtp_banner smtpd_banner 2>/dev/null; grep -i SmtpGreetingMessage /etc/mail/sendmail.cf /etc/sendmail.cf 2>/dev/null"
    case "$_smtp_type" in
    postfix)
        local banner=$(postconf -h smtpd_banner 2>/dev/null)
        echo "$banner" | grep -qiE "postfix|version|MTA" && \
            result "SRV-053|취약|SMTP 배너 버전 노출 (${banner})" || \
            result "SRV-053|양호|SMTP 배너 커스터마이징됨" ;;
    sendmail)
        local banner=$(grep -i "SmtpGreetingMessage\|O SmtpGreetingMessage" "$_smtp_cf" 2>/dev/null | head -1)
        [ -n "$banner" ] && result "SRV-053|수동확인|sendmail 배너=${banner}" || \
            result "SRV-053|취약|sendmail 배너 기본값 사용" ;;
    *) result "SRV-053|수동확인|${_smtp_type:-SMTP} 배너 수동 확인" ;;
    esac
}

# SRV-054: SMTP Relay 제한
check_SRV054() {
    _smtp_running || { evd "SRV-054" "ps -ef 2>/dev/null | grep -E 'smtp|postfix|sendmail' | grep -v grep"; result "SRV-054|N-A|SMTP 미실행"; return; }
    _detect_smtp
    evd "SRV-054" "postconf mynetworks smtpd_relay_restrictions smtpd_recipient_restrictions 2>/dev/null; grep -i relay /etc/mail/access 2>/dev/null | head -5"
    case "$_smtp_type" in
    postfix)
        local rr=$(postconf -h smtpd_relay_restrictions 2>/dev/null)
        local mn=$(postconf -h mynetworks 2>/dev/null)
        result "SRV-054|수동확인|postfix relay_restrictions=${rr:-미설정}, mynetworks=${mn:-미설정}" ;;
    sendmail)
        [ -f /etc/mail/access ] && result "SRV-054|수동확인|sendmail /etc/mail/access 존재 (relay 설정 확인)" || \
            result "SRV-054|취약|sendmail relay 제한 미설정 (/etc/mail/access 없음)" ;;
    *) result "SRV-054|수동확인|${_smtp_type:-SMTP} relay 설정 수동 확인" ;;
    esac
}

# SRV-055: SMTP ACCESS 설정
check_SRV055() {
    _smtp_running || { evd "SRV-055" "ps -ef 2>/dev/null | grep -E 'smtp|postfix|sendmail' | grep -v grep"; result "SRV-055|N-A|SMTP 미실행"; return; }
    _detect_smtp
    evd "SRV-055" "cat /etc/mail/access 2>/dev/null | grep -v '^#' | head -10; postconf smtpd_client_restrictions smtpd_sender_restrictions 2>/dev/null"
    case "$_smtp_type" in
    postfix)
        local cr=$(postconf -h smtpd_client_restrictions 2>/dev/null)
        [ -n "$cr" ] && result "SRV-055|수동확인|postfix client_restrictions=${cr}" || \
            result "SRV-055|취약|postfix 발송 제한 미설정" ;;
    sendmail)
        [ -f /etc/mail/access ] && [ -s /etc/mail/access ] && \
            result "SRV-055|수동확인|sendmail /etc/mail/access 설정 확인" || \
            result "SRV-055|취약|sendmail access DB 미설정" ;;
    *) result "SRV-055|수동확인|${_smtp_type:-SMTP} ACCESS 설정 수동 확인" ;;
    esac
}

# SRV-056: SMTP VRFY/EXPN 비활성화
check_SRV056() {
    _smtp_running || { evd "SRV-056" "ps -ef 2>/dev/null | grep -E 'smtp|postfix|sendmail' | grep -v grep"; result "SRV-056|N-A|SMTP 미실행"; return; }
    _detect_smtp
    evd "SRV-056" "postconf disable_vrfy_command 2>/dev/null; grep -i PrivacyOptions $_smtp_cf 2>/dev/null"
    case "$_smtp_type" in
    postfix)
        local val=$(postconf -h disable_vrfy_command 2>/dev/null)
        [ "$val" = "yes" ] && result "SRV-056|양호|postfix disable_vrfy_command=yes" || \
            result "SRV-056|취약|postfix disable_vrfy_command=${val:-no}" ;;
    sendmail)
        [ -n "$_smtp_cf" ] && grep -qi "PrivacyOptions.*noexpn\|PrivacyOptions.*novrfy\|PrivacyOptions.*goaway" "$_smtp_cf" 2>/dev/null && \
            result "SRV-056|양호|sendmail EXPN/VRFY 제한됨" || \
            result "SRV-056|취약|sendmail EXPN/VRFY 미제한" ;;
    *) result "SRV-056|수동확인|${_smtp_type:-SMTP} VRFY/EXPN 수동 확인" ;;
    esac
}

# SRV-057: SMTP TLS/보안
check_SRV057() {
    _smtp_running || { evd "SRV-057" "ps -ef 2>/dev/null | grep -E 'smtp|postfix|sendmail' | grep -v grep"; result "SRV-057|N-A|SMTP 미실행"; return; }
    _detect_smtp
    evd "SRV-057" "postconf smtpd_use_tls smtpd_tls_cert_file smtpd_tls_security_level 2>/dev/null; grep -i 'STARTTLS\|AuthMechanisms\|CACert' $_smtp_cf 2>/dev/null | head -5"
    case "$_smtp_type" in
    postfix)
        local tls=$(postconf -h smtpd_tls_security_level 2>/dev/null)
        local use_tls=$(postconf -h smtpd_use_tls 2>/dev/null)
        if [ "$tls" = "encrypt" ] || [ "$tls" = "may" ] || [ "$use_tls" = "yes" ]; then
            result "SRV-057|양호|SMTP TLS 설정됨 (level=${tls:-legacy}, use_tls=${use_tls})"
        else
            result "SRV-057|취약|SMTP TLS 미설정 (tls_security_level=${tls:-미설정})"
        fi ;;
    *) result "SRV-057|수동확인|${_smtp_type:-SMTP} TLS/보안 설정 수동 확인" ;;
    esac
}

# SRV-058: DNS 보안패치
check_SRV058() {
    is_running named || { evd "SRV-058" "ps -ef 2>/dev/null | grep named | grep -v grep"; result "SRV-058|N-A|DNS 미실행"; return; }
    evd "SRV-058" "named -v 2>/dev/null; rpm -qa bind 2>/dev/null; dpkg -l bind9 2>/dev/null | tail -1"
    local ver=$(named -v 2>/dev/null | grep -oE 'BIND [0-9][^ ]*' | head -1)
    result "SRV-058|수동확인|DNS ${ver:-버전 미확인} - 보안 패치 적용 여부 확인"
}

# SRV-059: DNS 영역전송 제한
check_SRV059() {
    is_running named || { evd "SRV-059" "ps -ef 2>/dev/null | grep named | grep -v grep"; result "SRV-059|N-A|DNS 미실행"; return; }
    evd "SRV-059" "grep -i allow-transfer /etc/named.conf /etc/bind/named.conf 2>/dev/null"
    for conf in /etc/named.conf /etc/bind/named.conf; do
        [ -f "$conf" ] || continue
        grep -q "allow-transfer.*none" "$conf" 2>/dev/null && { result "SRV-059|양호|Zone Transfer 차단"; return; }
        grep -q "allow-transfer" "$conf" 2>/dev/null && { result "SRV-059|수동확인|allow-transfer 허용 대상 확인"; return; }
        result "SRV-059|취약|Zone Transfer 제한 미설정"; return
    done
    result "SRV-059|수동확인|named.conf 수동 확인"
}

# SRV-060: DNS Dynamic Update 비활성화
check_SRV060() {
    is_running named || { evd "SRV-060" "ps -ef 2>/dev/null | grep named | grep -v grep"; result "SRV-060|N-A|DNS 미실행"; return; }
    evd "SRV-060" "grep -i allow-update /etc/named.conf /etc/bind/named.conf 2>/dev/null"
    local vuln=0
    for conf in /etc/named.conf /etc/bind/named.conf; do
        [ -f "$conf" ] || continue
        grep -v "^[[:space:]]*//" "$conf" | grep -v "^#" | grep -i "allow-update" | grep -qi "any" && vuln=1
        grep -v "^[[:space:]]*//" "$conf" | grep -v "^#" | grep -i "allow-update" | grep -qi "none" && { result "SRV-060|양호|DNS 동적 업데이트 차단"; return; }
    done
    [ $vuln -eq 1 ] && result "SRV-060|취약|DNS 동적 업데이트 any 허용" || \
        result "SRV-060|수동확인|allow-update 설정 확인 필요"
}

# SRV-061: DNS 최신 버전
check_SRV061() {
    is_running named || { evd "SRV-061" "ps -ef 2>/dev/null | grep named | grep -v grep"; result "SRV-061|N-A|DNS 미실행"; return; }
    evd "SRV-061" "named -v 2>/dev/null"
    local ver=$(named -v 2>/dev/null | grep -oE 'BIND [0-9][^ ]*' | head -1)
    result "SRV-061|수동확인|DNS ${ver:-버전 미확인} - 최신 버전 사용 여부 확인"
}


# SRV-065
check_SRV065() {
    evd "SRV-065" "ls -la /etc/cron.allow /etc/cron.deny /etc/at.allow /etc/at.deny 2>/dev/null; cat /etc/cron.allow 2>/dev/null; cat /etc/cron.deny 2>/dev/null"
    if [ -f /etc/cron.allow ]; then
        local perm=$(get_perm "/etc/cron.allow") owner=$(get_owner "/etc/cron.allow")
        [ "$owner" = "root" ] && [ "${perm:-777}" -le 640 ] 2>/dev/null && \
            result "SRV-065|양호|cron.allow 존재 (소유자=${owner}, 권한=${perm})" || \
            result "SRV-065|취약|cron.allow 권한 이상 (소유자=${owner}, 권한=${perm})"
    elif [ -f /etc/cron.deny ]; then
        result "SRV-065|수동확인|cron.deny만 존재 (cron.allow 권장)"
    else
        result "SRV-065|취약|cron.allow/cron.deny 미존재 (모든 사용자 cron 사용 가능)"
    fi
}

# SRV-067
check_SRV067() {
    evd "SRV-067" "cat /etc/motd 2>/dev/null | head -5; cat /etc/issue 2>/dev/null | head -3; cat /etc/issue.net 2>/dev/null | head -3; grep -i Banner /etc/ssh/sshd_config 2>/dev/null | grep -v '^#'"
    local found=0
    for f in /etc/motd /etc/issue /etc/issue.net; do
        [ -f "$f" ] && [ -s "$f" ] && found=1
    done
    grep -v '^#' /etc/ssh/sshd_config 2>/dev/null | grep -qi "^Banner" && found=1
    [ $found -eq 1 ] && result "SRV-067|양호|로그온 경고 메시지 설정됨" || \
        result "SRV-067|취약|로그온 경고 메시지 미설정 (/etc/motd, /etc/issue, SSH Banner 없음)"
}

# SRV-068
check_SRV068() {
    evd "SRV-068" "ls -la /etc/exports 2>/dev/null; cat /etc/exports 2>/dev/null"
    if [ ! -f /etc/exports ]; then
        result "SRV-068|N-A|/etc/exports 미존재"; return
    fi
    local perm=$(get_perm "/etc/exports") owner=$(get_owner "/etc/exports")
    if [ "$owner" != "root" ]; then
        result "SRV-068|취약|/etc/exports 소유자=${owner} (root 필요)"
    elif [ "${perm:-777}" -gt 644 ] 2>/dev/null; then
        result "SRV-068|취약|/etc/exports 권한=${perm} (644 이하 필요)"
    else
        result "SRV-068|양호|/etc/exports 소유자=${owner}, 권한=${perm}"
    fi
}

# SRV-071
check_SRV071() {
    evd "SRV-071" "grep -riE 'Indexes|autoindex' /etc/httpd/conf/ /etc/apache2/ /etc/nginx/ 2>/dev/null | grep -v '^#' | head -10"
    if ! is_running httpd && ! is_running apache2 && ! is_running nginx; then
        result "SRV-071|N-A|웹서버 미실행"; return
    fi
    local vuln=""
    for cf in /etc/httpd/conf/httpd.conf /etc/apache2/apache2.conf /etc/apache2/sites-enabled/*.conf; do
        [ -f "$cf" ] || continue
        grep -v '^\s*#' "$cf" 2>/dev/null | grep -qi "Options.*Indexes" && vuln="${vuln} ${cf}"
    done
    for cf in /etc/nginx/nginx.conf /etc/nginx/conf.d/*.conf /etc/nginx/sites-enabled/*; do
        [ -f "$cf" ] || continue
        grep -v '^\s*#' "$cf" 2>/dev/null | grep -qi "autoindex.*on" && vuln="${vuln} ${cf}"
    done
    [ -n "$vuln" ] && result "SRV-071|취약|디렉터리 인덱싱 활성화:${vuln}" || \
        result "SRV-071|양호|디렉터리 인덱싱 비활성화"
}

# SRV-076
check_SRV076() {
    is_running snmpd || { evd "SRV-076" "ps -ef 2>/dev/null | grep snmpd | grep -v grep"; result "SRV-076|N-A|SNMP 미실행"; return; }
    evd "SRV-076" "grep -v '^#' /etc/snmp/snmpd.conf /etc/snmpd.conf 2>/dev/null | grep -iE 'com2sec|agentAddress|rocommunity|rwcommunity' | head -10"
    local acl=0
    for conf in /etc/snmpd.conf /etc/snmp/snmpd.conf; do
        [ -f "$conf" ] || continue
        grep -v '^#' "$conf" 2>/dev/null | grep -qiE 'com2sec.*[0-9]+\.[0-9]+|agentAddress.*udp:[0-9]' && acl=1
    done
    [ $acl -eq 1 ] && result "SRV-076|양호|SNMP 접근통제 설정됨 (IP 제한)" || \
        result "SRV-076|취약|SNMP 접근통제 미설정 (IP 제한 없음)"
}

# SRV-077
check_SRV077() {
    is_running snmpd || { evd "SRV-077" "ps -ef 2>/dev/null | grep snmpd | grep -v grep"; result "SRV-077|N-A|SNMP 미실행"; return; }
    evd "SRV-077" "grep -v '^#' /etc/snmp/snmpd.conf /etc/snmpd.conf 2>/dev/null | grep -iE 'community|rocommunity|rwcommunity' | head -10"
    local vuln=""
    for conf in /etc/snmpd.conf /etc/snmp/snmpd.conf; do
        [ -f "$conf" ] || continue
        grep -v '^#' "$conf" 2>/dev/null | grep -qiE '(rocommunity|rwcommunity|community).*(public|private)' && vuln="$conf"
    done
    [ -n "$vuln" ] && result "SRV-077|취약|기본 커뮤니티 스트링 사용 (public/private) - ${vuln}" || \
        result "SRV-077|양호|기본 커뮤니티 스트링 미사용"
}

# SRV-085
check_SRV085() {
    evd "SRV-085" "echo \$PATH; grep -iE 'PATH=|export PATH' /etc/profile /root/.bashrc /root/.bash_profile 2>/dev/null | grep -v '^#' | head -10"
    if echo "$PATH" | tr ':' '\n' | grep -qx '\.'; then
        result "SRV-085|취약|PATH에 현재 디렉토리(.) 포함"
    else
        result "SRV-085|양호|PATH에 현재 디렉토리(.) 미포함"
    fi
}

# SRV-086
check_SRV086() {
    evd "SRV-086" "awk -F: '\$3>=500 || \$3==0 {print \$1,\$3,\$6}' /etc/passwd 2>/dev/null | head -20"
    local vuln="" min_uid=500
    [ -f /etc/debian_version ] && min_uid=1000
    while IFS=: read -r user _ uid _ _ homedir _; do
        [ "${uid:-0}" -lt "$min_uid" ] 2>/dev/null && [ "$uid" != "0" ] && continue
        [ -z "$homedir" ] || [ "$homedir" = "/" ] && continue
        [ -d "$homedir" ] || continue
        local perm=$(get_perm "$homedir") owner=$(get_owner "$homedir")
        [ "$owner" != "$user" ] && vuln="${vuln} ${homedir}(소유자=${owner})"
        [ "${perm:-0}" -gt 755 ] 2>/dev/null && vuln="${vuln} ${homedir}(${perm})"
    done < /etc/passwd 2>/dev/null
    [ -n "$vuln" ] && result "SRV-086|취약|홈 디렉토리 이상:${vuln}" || \
        result "SRV-086|양호|홈 디렉토리 소유자 및 권한 적절 (755 이하)"
}

# SRV-088
check_SRV088() {
    evd "SRV-088" "ls -la /etc/crontab /var/spool/cron/ /var/spool/cron/crontabs/ 2>/dev/null"
    local vuln=""
    if [ -f /etc/crontab ]; then
        local perm=$(get_perm "/etc/crontab")
        [ "${perm:-777}" -gt 640 ] 2>/dev/null && vuln="${vuln} /etc/crontab(${perm})"
    fi
    for d in /var/spool/cron /var/spool/cron/crontabs; do
        [ -d "$d" ] || continue
        local dperm=$(get_perm "$d")
        [ "${dperm:-777}" -gt 750 ] 2>/dev/null && vuln="${vuln} ${d}(${dperm})"
    done
    [ -n "$vuln" ] && result "SRV-088|취약|crontab 권한 이상:${vuln}" || \
        result "SRV-088|양호|crontab 파일 권한 적절 (640 이하)"
}

# SRV-089
check_SRV089() {
    evd "SRV-089" "ls -la /etc/hosts.equiv 2>/dev/null; cat /etc/hosts.equiv 2>/dev/null; find /home /root -name '.rhosts' -ls 2>/dev/null | head -10"
    local vuln=""
    [ -f /etc/hosts.equiv ] && vuln="${vuln} /etc/hosts.equiv"
    local rhosts=$(find /home /root -name '.rhosts' 2>/dev/null | head -5)
    [ -n "$rhosts" ] && vuln="${vuln} ${rhosts}"
    [ -n "$vuln" ] && result "SRV-089|취약|hosts.equiv/.rhosts 파일 존재:${vuln}" || \
        result "SRV-089|양호|hosts.equiv/.rhosts 파일 미존재"
}

# SRV-097
check_SRV097() {
    evd "SRV-097" "systemctl list-unit-files --type=service --state=enabled 2>/dev/null | head -30; chkconfig --list 2>/dev/null | grep ':on' | head -20"
    local cnt=$(systemctl list-unit-files --type=service --state=enabled 2>/dev/null | grep -c "enabled")
    result "SRV-097|수동확인|활성화된 서비스 ${cnt:-미확인}개 (불필요 서비스 확인 필요)"
}

# SRV-098
check_SRV098() {
    evd "SRV-098" "systemctl list-unit-files --type=service --state=enabled 2>/dev/null | head -40"
    local cnt=$(systemctl list-unit-files --type=service --state=enabled 2>/dev/null | grep -c "enabled")
    result "SRV-098|수동확인|활성 서비스 ${cnt:-미확인}개 - 최소 필요 서비스만 유지 확인"
}

# SRV-099
check_SRV099() {
    evd "SRV-099" "iptables -L -n 2>/dev/null | head -20; firewall-cmd --list-all 2>/dev/null; ufw status 2>/dev/null"
    local fw=0
    iptables -L -n 2>/dev/null | grep -qv "^Chain\|^target\|^$" && fw=1
    systemctl is-active firewalld >/dev/null 2>&1 && fw=1
    ufw status 2>/dev/null | grep -qi "active" && fw=1
    [ $fw -eq 1 ] && result "SRV-099|양호|네트워크 접근제어 설정됨 (방화벽 활성)" || \
        result "SRV-099|취약|네트워크 접근제어 미설정 (방화벽 비활성 또는 규칙 없음)"
}

# SRV-100
check_SRV100() {
    evd "SRV-100" "awk -F: '{printf \"%-15s UID=%-5s Shell=%s\\n\",\$1,\$3,\$7}' /etc/passwd 2>/dev/null"
    result "SRV-100|수동확인|시스템 계정 Shell 현황 수동 확인 (위 현황 참조)"
}

# SRV-101
check_SRV101() {
    evd "SRV-101" "grep -i PermitRootLogin /etc/ssh/sshd_config 2>/dev/null | grep -v '^#'"
    local val=$(grep -v '^#' /etc/ssh/sshd_config 2>/dev/null | grep -i "PermitRootLogin" | awk '{print $2}' | tail -1)
    case "$val" in
        no|No|NO) result "SRV-101|양호|PermitRootLogin=no" ;;
        without-password|prohibit-password) result "SRV-101|양호|PermitRootLogin=${val} (키 인증만 허용)" ;;
        yes|Yes|YES) result "SRV-101|취약|PermitRootLogin=yes (root 원격접속 허용)" ;;
        "") result "SRV-101|취약|PermitRootLogin 미설정 (기본값 허용)" ;;
        *) result "SRV-101|수동확인|PermitRootLogin=${val}" ;;
    esac
}

# SRV-102
check_SRV102() {
    evd "SRV-102" "grep -rh TMOUT /etc/profile /etc/bashrc /root/.bashrc 2>/dev/null | grep -v '^#'; grep -i ClientAlive /etc/ssh/sshd_config 2>/dev/null | grep -v '^#'"
    local tmout=""
    for f in /etc/profile /etc/bashrc /etc/bash.bashrc /etc/environment /root/.bashrc /root/.profile; do
        [ -f "$f" ] || continue
        local t=$(grep -h 'TMOUT' "$f" 2>/dev/null | grep -v '^#' | grep -oE '[0-9]+' | head -1)
        [ -n "$t" ] && tmout=$t && break
    done
    local alive=$(grep -v '^#' /etc/ssh/sshd_config 2>/dev/null | grep -i "ClientAliveInterval" | awk '{print $2}' | tail -1)
    if [ -n "$tmout" ] && [ "$tmout" -le 600 ] 2>/dev/null; then
        result "SRV-102|양호|TMOUT=${tmout}초"
    elif [ -n "$alive" ] && [ "$alive" -le 600 ] 2>/dev/null && [ "$alive" -gt 0 ] 2>/dev/null; then
        result "SRV-102|양호|ClientAliveInterval=${alive}초"
    elif [ -n "$tmout" ]; then
        result "SRV-102|취약|TMOUT=${tmout}초 (600초 초과)"
    else
        result "SRV-102|취약|세션 타임아웃 미설정 (TMOUT/ClientAliveInterval 없음)"
    fi
}

# SRV-103
check_SRV103() {
    evd "SRV-103" "lastlog 2>/dev/null | head -30; awk -F: '\$7 !~ /nologin|false/ {print \$1,\$3,\$7}' /etc/passwd 2>/dev/null"
    local inactive=""
    while IFS= read -r line; do
        local user=$(echo "$line" | awk '{print $1}')
        [ -n "$user" ] && inactive="${inactive} ${user}"
    done < <(lastlog 2>/dev/null | awk 'NR>1 && /Never logged in/' | head -20)
    [ -n "$inactive" ] && result "SRV-103|수동확인|미로그인 계정:${inactive} (불필요 여부 검토)" || \
        result "SRV-103|수동확인|계정 목록 확인 (위 현황 참조)"
}

# SRV-104
check_SRV104() {
    evd "SRV-104" "grep -E '^wheel:|^sudo:|^admin:' /etc/group 2>/dev/null"
    local info="" total=0
    for grp in wheel sudo admin; do
        local members=$(grep "^${grp}:" /etc/group 2>/dev/null | cut -d: -f4)
        if [ -n "$members" ]; then
            local cnt=$(echo "$members" | tr ',' '\n' | grep -cv '^$')
            total=$((total + cnt))
            info="${info} ${grp}:[${members}](${cnt}명)"
        fi
    done
    [ "$total" -gt 5 ] 2>/dev/null && result "SRV-104|취약|관리자 그룹 멤버 과다(${total}명):${info}" || \
        result "SRV-104|양호|관리자 그룹 멤버(${total}명)${info}"
}

# SRV-105
check_SRV105() {
    evd "SRV-105" "grep -rh TMOUT /etc/profile /etc/bashrc 2>/dev/null | grep -v '^#'; grep -i ClientAliveCountMax /etc/ssh/sshd_config 2>/dev/null | grep -v '^#'"
    local tmout=""
    for f in /etc/profile /etc/bashrc /etc/bash.bashrc /root/.bashrc; do
        [ -f "$f" ] || continue
        local t=$(grep -h 'TMOUT' "$f" 2>/dev/null | grep -v '^#' | grep -oE '[0-9]+' | head -1)
        [ -n "$t" ] && tmout=$t && break
    done
    if [ -n "$tmout" ] && [ "$tmout" -le 600 ] 2>/dev/null; then
        result "SRV-105|양호|세션 종료 설정됨 (TMOUT=${tmout}초)"
    else
        result "SRV-105|취약|세션 종료 미설정 또는 600초 초과 (TMOUT=${tmout:-미설정})"
    fi
}

# SRV-106
check_SRV106() {
    evd "SRV-106" "awk -F: '\$3==0 {print \$1,\$3}' /etc/passwd 2>/dev/null"
    local found=$(awk -F: '$3==0 && $1!="root" {print $1}' /etc/passwd 2>/dev/null)
    [ -n "$found" ] && result "SRV-106|취약|root 외 UID 0 계정: $(echo "$found" | _csv)" || \
        result "SRV-106|양호|root 외 UID 0 계정 없음"
}

# SRV-107
check_SRV107() {
    evd "SRV-107" "grep -E '^PASS_MIN_LEN|^MINLEN' /etc/login.defs 2>/dev/null; grep -iE 'pam_pwquality|pam_cracklib' $(get_pam_files) 2>/dev/null | grep -v '^#'"
    local minlen=$(grep -E '^\s*PASS_MIN_LEN' /etc/login.defs 2>/dev/null | awk '{print $2}' | tail -1)
    local pam_ml=$(grep -v '^#' $(get_pam_files) 2>/dev/null | grep -oE 'minlen=[0-9]+' | head -1 | cut -d= -f2)
    local elen=${pam_ml:-${minlen:-0}}
    [ "${elen:-0}" -ge 8 ] 2>/dev/null && result "SRV-107|양호|패스워드 최소 길이=${elen}" || \
        result "SRV-107|취약|패스워드 최소 길이=${elen:-미설정} (8자리 이상 필요)"
}

# SRV-110
check_SRV110() {
    evd "SRV-110" "_to 60 find / \$_FP \( -nouser -o -nogroup \) -print 2>/dev/null | head -20"
    local found=$(_to 60 find / $_FP \( -nouser -o -nogroup \) -print 2>/dev/null | grep -vE '^/proc|^/sys|^/dev|^/run' | head -10)
    [ -n "$found" ] && result "SRV-110|취약|소유자 없는 파일 존재: $(echo "$found" | head -c 200)" || \
        result "SRV-110|양호|소유자 없는 파일 미존재"
}

# SRV-111
check_SRV111() {
    evd "SRV-111" "cat /etc/logrotate.conf 2>/dev/null | head -15; ls -la /etc/logrotate.d/ 2>/dev/null | head -10; du -sh /var/log 2>/dev/null"
    if [ -f /etc/logrotate.conf ]; then
        local rotate=$(grep -E '^\s*rotate ' /etc/logrotate.conf 2>/dev/null | awk '{print $2}')
        result "SRV-111|수동확인|logrotate 설정됨 (보관=${rotate:-미확인}주기) - 정책 적합성 확인"
    else
        result "SRV-111|취약|logrotate 미설정 (로그 관리 부재)"
    fi
}

# SRV-113
check_SRV113() {
    evd "SRV-113" "iptables -L -n --line-numbers 2>/dev/null | head -30; firewall-cmd --list-all 2>/dev/null; ufw status verbose 2>/dev/null"
    local fw=0
    iptables -L -n 2>/dev/null | grep -qvE '^Chain|^target|^$|ACCEPT.*anywhere.*anywhere' && fw=1
    systemctl is-active firewalld >/dev/null 2>&1 && fw=1
    ufw status 2>/dev/null | grep -qi "active" && fw=1
    [ $fw -eq 1 ] && result "SRV-113|양호|네트워크 접근통제 설정됨" || \
        result "SRV-113|취약|네트워크 접근통제 미설정 (방화벽 규칙 없음)"
}

# SRV-114
check_SRV114() {
    evd "SRV-114" "ls -la /etc/xinetd.d/ 2>/dev/null; grep -l 'disable.*no' /etc/xinetd.d/* 2>/dev/null"
    if [ ! -d /etc/xinetd.d ]; then
        result "SRV-114|양호|xinetd 미설치"; return
    fi
    local enabled=$(grep -l 'disable.*=.*no' /etc/xinetd.d/* 2>/dev/null | sed "s#.*/##")
    [ -n "$enabled" ] && result "SRV-114|수동확인|활성 xinetd 서비스: ${enabled} (필요 여부 확인)" || \
        result "SRV-114|양호|활성화된 xinetd 서비스 없음"
}

# SRV-116
check_SRV116() {
    evd "SRV-116" "systemctl is-active rsh.socket rlogin.socket rexec.socket 2>/dev/null; ps -ef 2>/dev/null | grep -E 'rshd|rlogind|rexecd|fingerd|in.fingerd' | grep -v grep"
    local vuln=""
    for svc in rsh rlogin rexec finger in.rshd in.rlogind in.rexecd in.fingerd; do
        is_running "$svc" && vuln="${vuln} ${svc}"
    done
    for sock in rsh.socket rlogin.socket rexec.socket; do
        systemctl is-active "$sock" >/dev/null 2>&1 && vuln="${vuln} ${sock}"
    done
    [ -n "$vuln" ] && result "SRV-116|취약|취약 서비스 실행 중:${vuln}" || \
        result "SRV-116|양호|rsh/rlogin/rexec/finger 서비스 미실행"
}

# SRV-117
check_SRV117() {
    evd "SRV-117" "auditctl -l 2>/dev/null | grep -iE 'useradd|userdel|passwd|groupadd|groupdel|shadow' | head -10; systemctl is-active auditd 2>/dev/null"
    if ! is_running auditd; then
        result "SRV-117|취약|auditd 미실행 (계정 감사 불가)"; return
    fi
    local rules=$(auditctl -l 2>/dev/null | grep -ciE 'useradd|userdel|passwd|groupadd|shadow')
    [ "${rules:-0}" -gt 0 ] 2>/dev/null && result "SRV-117|양호|계정 관련 감사 규칙 ${rules}개 설정됨" || \
        result "SRV-117|취약|계정 관련 감사 규칙 미설정 (useradd/userdel/passwd 추적 없음)"
}

# SRV-119
check_SRV119() {
    evd "SRV-119" "rpm -qa aide tripwire 2>/dev/null; dpkg -l aide tripwire 2>/dev/null | grep '^ii'; which aide tripwire ossec-control 2>/dev/null; aide --check 2>/dev/null | head -5"
    local tool=""
    command -v aide >/dev/null 2>&1 && tool="AIDE"
    command -v tripwire >/dev/null 2>&1 && tool="${tool} Tripwire"
    command -v ossec-control >/dev/null 2>&1 && tool="${tool} OSSEC"
    [ -n "$tool" ] && result "SRV-119|양호|파일 변경 감지 도구 설치됨 (${tool})" || \
        result "SRV-119|취약|파일 변경 감지 도구 미설치 (AIDE/Tripwire/OSSEC 없음)"
}

# SRV-120
check_SRV120() {
    evd "SRV-120" "getenforce 2>/dev/null; sestatus 2>/dev/null; aa-status 2>/dev/null | head -5; cat /etc/selinux/config 2>/dev/null | grep -v '^#'"
    local se=$(getenforce 2>/dev/null)
    local aa=$(aa-status 2>/dev/null | head -1)
    if [ "$se" = "Enforcing" ]; then
        result "SRV-120|양호|SELinux Enforcing 모드"
    elif [ "$se" = "Permissive" ]; then
        result "SRV-120|수동확인|SELinux Permissive 모드 (Enforcing 권장)"
    elif echo "$aa" | grep -qi "apparmor module is loaded"; then
        result "SRV-120|양호|AppArmor 활성화"
    else
        result "SRV-120|취약|SELinux/AppArmor 비활성 (보안 모듈 미적용)"
    fi
}

# SRV-123
check_SRV123() {
    evd "SRV-123" "grep -i Protocol /etc/ssh/sshd_config 2>/dev/null | grep -v '^#'; sshd -T 2>/dev/null | grep -i protocol"
    local proto=$(grep -v '^#' /etc/ssh/sshd_config 2>/dev/null | grep -i "^Protocol" | awk '{print $2}' | tail -1)
    if [ "$proto" = "1" ]; then
        result "SRV-123|취약|SSH Protocol 1 사용 (Protocol 2 필요)"
    elif [ "$proto" = "2" ] || [ -z "$proto" ]; then
        result "SRV-123|양호|SSH Protocol 2 사용 (${proto:-기본값})"
    else
        result "SRV-123|수동확인|SSH Protocol=${proto}"
    fi
}

# SRV-124
check_SRV124() {
    evd "SRV-124" "ls -la /etc/shadow 2>/dev/null; stat -c '%a %U' /etc/shadow 2>/dev/null"
    if [ ! -f /etc/shadow ]; then
        result "SRV-124|취약|/etc/shadow 미존재 (패스워드 파일 보호 불가)"; return
    fi
    local perm=$(get_perm "/etc/shadow") owner=$(get_owner "/etc/shadow")
    if [ "$owner" != "root" ]; then
        result "SRV-124|취약|/etc/shadow 소유자=${owner} (root 필요)"
    elif [ "${perm:-777}" -gt 640 ] 2>/dev/null; then
        result "SRV-124|취약|/etc/shadow 권한=${perm} (640 이하 필요)"
    else
        result "SRV-124|양호|/etc/shadow 소유자=${owner}, 권한=${perm}"
    fi
}

# SRV-126
check_SRV126() {
    evd "SRV-126" "grep -i MaxAuthTries /etc/ssh/sshd_config 2>/dev/null | grep -v '^#'"
    local val=$(grep -v '^#' /etc/ssh/sshd_config 2>/dev/null | grep -i "MaxAuthTries" | awk '{print $2}' | tail -1)
    if [ -z "$val" ]; then
        result "SRV-126|취약|MaxAuthTries 미설정 (기본값 6)"
    elif [ "$val" -le 5 ] 2>/dev/null; then
        result "SRV-126|양호|MaxAuthTries=${val}"
    else
        result "SRV-126|취약|MaxAuthTries=${val} (5 이하 권장)"
    fi
}

# SRV-128
check_SRV128() {
    evd "SRV-128" "ulimit -a 2>/dev/null; grep -v '^#' /etc/security/limits.conf 2>/dev/null | grep -v '^$' | head -15"
    local limits=$(grep -v '^#' /etc/security/limits.conf 2>/dev/null | grep -cv '^$')
    [ "${limits:-0}" -gt 0 ] 2>/dev/null && result "SRV-128|수동확인|limits.conf 설정 ${limits}줄 (적정성 확인)" || \
        result "SRV-128|수동확인|limits.conf 설정 없음 (기본값 사용 중)"
}

# SRV-129
check_SRV129() {
    evd "SRV-129" "ip link show 2>/dev/null | grep -i promisc; ifconfig -a 2>/dev/null | grep -i promisc"
    if ip link show 2>/dev/null | grep -qi "PROMISC"; then
        result "SRV-129|취약|Promiscuous 모드 인터페이스 발견"
    else
        result "SRV-129|양호|Promiscuous 모드 인터페이스 없음"
    fi
}

# SRV-130
check_SRV130() {
    evd "SRV-130" "ss -tlnp 2>/dev/null | head -30; netstat -tlnp 2>/dev/null | head -30"
    local cnt=$(ss -tlnp 2>/dev/null | grep -c "LISTEN")
    result "SRV-130|수동확인|리스닝 서비스 ${cnt:-미확인}개 (불필요 서비스 확인)"
}

# SRV-132
check_SRV132() {
    evd "SRV-132" "timedatectl 2>/dev/null; chronyc sources 2>/dev/null | head -5; ntpq -p 2>/dev/null | head -5; systemctl is-active chronyd ntpd 2>/dev/null"
    if command -v timedatectl >/dev/null 2>&1; then
        local sync=$(timedatectl 2>/dev/null | grep -ciE 'NTP sync.*yes|System clock sync.*yes')
        [ "${sync:-0}" -ge 1 ] && { result "SRV-132|양호|NTP 동기화 활성화"; return; }
    fi
    is_running chronyd && { result "SRV-132|양호|chrony 실행 중"; return; }
    is_running ntpd && { result "SRV-132|양호|ntpd 실행 중"; return; }
    result "SRV-132|취약|NTP 시간 동기화 미설정"
}

# SRV-136
check_SRV136() {
    evd "SRV-136" "systemctl is-active auditd 2>/dev/null; auditctl -l 2>/dev/null | head -20"
    if is_running auditd; then
        local rules=$(auditctl -l 2>/dev/null | wc -l)
        [ "${rules:-0}" -gt 0 ] 2>/dev/null && result "SRV-136|양호|auditd 활성, 규칙 ${rules}개" || \
            result "SRV-136|취약|auditd 실행 중이나 감사 규칙 없음"
    else
        result "SRV-136|취약|auditd 미실행 (감사 로그 미설정)"
    fi
}

# SRV-137
check_SRV137() {
    evd "SRV-137" "grep -E 'max_log_file|num_logs|log_file' /etc/audit/auditd.conf 2>/dev/null | grep -v '^#'; ls -la /etc/logrotate.d/audit* 2>/dev/null"
    if [ -f /etc/audit/auditd.conf ]; then
        local maxf=$(grep -i 'max_log_file ' /etc/audit/auditd.conf 2>/dev/null | grep -v '^#' | awk -F= '{print $2}' | tr -d ' ')
        local numl=$(grep -i 'num_logs' /etc/audit/auditd.conf 2>/dev/null | grep -v '^#' | awk -F= '{print $2}' | tr -d ' ')
        result "SRV-137|수동확인|auditd 로그 관리: max_log_file=${maxf:-미설정}MB, num_logs=${numl:-미설정}"
    else
        result "SRV-137|취약|auditd.conf 미존재 (감사 로그 백업 미설정)"
    fi
}

# SRV-138
check_SRV138() {
    evd "SRV-138" "ls -la /var/log/faillog /var/log/btmp /var/log/tallylog 2>/dev/null; faillog -u root 2>/dev/null; lastb 2>/dev/null | tail -5"
    local found=0
    for f in /var/log/faillog /var/log/btmp /var/log/tallylog; do
        [ -f "$f" ] && found=1
    done
    [ $found -eq 1 ] && result "SRV-138|양호|로그인 실패 기록 파일 존재" || \
        result "SRV-138|취약|로그인 실패 기록 파일 미존재 (faillog/btmp 없음)"
}

# SRV-139
check_SRV139() {
    evd "SRV-139" "auditctl -l 2>/dev/null | wc -l; auditctl -l 2>/dev/null | head -20"
    if ! is_running auditd; then
        result "SRV-139|취약|auditd 미실행"; return
    fi
    local rules=$(auditctl -l 2>/dev/null | wc -l)
    [ "${rules:-0}" -ge 5 ] 2>/dev/null && result "SRV-139|수동확인|감사 규칙 ${rules}개 (범위 적절성 확인)" || \
        result "SRV-139|취약|감사 규칙 부족 (${rules:-0}개)"
}

# SRV-140
check_SRV140() {
    evd "SRV-140" "ls -ld /var/log/audit/ 2>/dev/null; ls -la /var/log/audit/audit.log 2>/dev/null"
    if [ -d /var/log/audit ]; then
        local perm=$(get_perm "/var/log/audit") owner=$(get_owner "/var/log/audit")
        if [ "$owner" = "root" ] && [ "${perm:-777}" -le 750 ] 2>/dev/null; then
            result "SRV-140|양호|감사 로그 디렉터리 보호됨 (소유자=${owner}, 권한=${perm})"
        else
            result "SRV-140|취약|감사 로그 디렉터리 보호 미흡 (소유자=${owner}, 권한=${perm})"
        fi
    else
        result "SRV-140|취약|/var/log/audit 디렉터리 미존재"
    fi
}

# SRV-141
check_SRV141() {
    evd "SRV-141" "grep -iE 'max_log_file|max_log_file_action|space_left_action' /etc/audit/auditd.conf 2>/dev/null | grep -v '^#'; du -sh /var/log/audit/ 2>/dev/null"
    if [ -f /etc/audit/auditd.conf ]; then
        local maxf=$(grep -i 'max_log_file ' /etc/audit/auditd.conf 2>/dev/null | grep -v '^#' | awk -F= '{print $2}' | tr -d ' ')
        local action=$(grep -i 'max_log_file_action' /etc/audit/auditd.conf 2>/dev/null | grep -v '^#' | awk -F= '{print $2}' | tr -d ' ')
        result "SRV-141|수동확인|감사 로그 용량: max=${maxf:-미설정}MB, action=${action:-미설정}"
    else
        result "SRV-141|취약|auditd.conf 미존재"
    fi
}

# SRV-143
check_SRV143() {
    evd "SRV-143" "lsmod 2>/dev/null | grep -iE 'dccp|sctp|rds|tipc'; cat /etc/modprobe.d/*.conf 2>/dev/null | grep -iE 'dccp|sctp|rds|tipc'; sysctl net.ipv6.conf.all.disable_ipv6 2>/dev/null"
    local loaded=""
    for mod in dccp sctp rds tipc; do
        lsmod 2>/dev/null | grep -qi "$mod" && loaded="${loaded} ${mod}"
    done
    if [ -n "$loaded" ]; then
        result "SRV-143|취약|불필요 프로토콜 모듈 로드됨:${loaded}"
    else
        result "SRV-143|양호|불필요 프로토콜 모듈 미로드 (dccp/sctp/rds/tipc)"
    fi
}

# SRV-145
check_SRV145() {
    evd "SRV-145" "rpm -qa aide tripwire 2>/dev/null; dpkg -l aide tripwire 2>/dev/null | grep '^ii'; which aide tripwire 2>/dev/null; ls -la /var/lib/aide/aide.db* /var/lib/tripwire/*.twd 2>/dev/null"
    local tool=""
    command -v aide >/dev/null 2>&1 && tool="AIDE"
    command -v tripwire >/dev/null 2>&1 && tool="${tool} Tripwire"
    rpm -qa 2>/dev/null | grep -q "aide\|tripwire" && tool="${tool} (RPM)"
    [ -n "$tool" ] && result "SRV-145|양호|파일 무결성 점검 도구: ${tool}" || \
        result "SRV-145|취약|파일 무결성 점검 도구 미설치"
}

# SRV-146
check_SRV146() {
    evd "SRV-146" "rpm -qa clamav 2>/dev/null; dpkg -l clamav 2>/dev/null | grep '^ii'; which clamscan freshclam 2>/dev/null; systemctl is-active clamav-daemon 2>/dev/null"
    local av=""
    command -v clamscan >/dev/null 2>&1 && av="ClamAV"
    command -v sophos >/dev/null 2>&1 && av="${av} Sophos"
    is_running clamd && av="${av} (clamd 실행중)"
    [ -n "$av" ] && result "SRV-146|양호|안티바이러스 설치됨 (${av})" || \
        result "SRV-146|수동확인|안티바이러스 미설치 (ClamAV 등 미발견 - 별도 솔루션 확인)"
}

# SRV-148
check_SRV148() {
    evd "SRV-148" "grep -i password /boot/grub2/grub.cfg /boot/grub/grub.cfg 2>/dev/null | head -5; grep -i SINGLE /etc/sysconfig/init /etc/default/grub 2>/dev/null; cat /etc/securetty 2>/dev/null | head -5"
    local grub_pw=0
    for f in /boot/grub2/grub.cfg /boot/grub/grub.cfg /boot/efi/EFI/*/grub.cfg; do
        [ -f "$f" ] && grep -qi "password" "$f" 2>/dev/null && grub_pw=1
    done
    [ -f /boot/grub2/user.cfg ] && grep -qi "GRUB2_PASSWORD" /boot/grub2/user.cfg 2>/dev/null && grub_pw=1
    [ $grub_pw -eq 1 ] && result "SRV-148|양호|GRUB 패스워드 설정됨" || \
        result "SRV-148|취약|GRUB 패스워드 미설정 (부팅 보안 미흡)"
}

# SRV-149
check_SRV149() {
    evd "SRV-149" "useradd -D 2>/dev/null | grep INACTIVE; awk -F: '\$7!=\"\" && \$7 !~ /nologin|false/ {print \$1,\$7}' /etc/shadow 2>/dev/null | head -10"
    local inactive=$(useradd -D 2>/dev/null | grep "INACTIVE" | awk -F= '{print $2}')
    if [ "${inactive:-}" = "-1" ] || [ -z "$inactive" ]; then
        result "SRV-149|취약|INACTIVE 미설정 (비활성 계정 자동 잠금 없음)"
    elif [ "${inactive:-0}" -ge 0 ] 2>/dev/null; then
        result "SRV-149|양호|INACTIVE=${inactive}일 (비활성 계정 자동 잠금)"
    else
        result "SRV-149|수동확인|INACTIVE=${inactive} (설정 확인 필요)"
    fi
}

# SRV-150
check_SRV150() {
    evd "SRV-150" "awk -F: '{printf \"%-15s UID=%-5s Shell=%s\\n\",\$1,\$3,\$7}' /etc/passwd 2>/dev/null"
    result "SRV-150|수동확인|시스템 계정 Shell 현황 수동 확인 (위 현황 참조)"
}

# SRV-151
check_SRV151() {
    evd "SRV-151" "systemctl is-active usbguard 2>/dev/null; cat /etc/modprobe.d/*.conf 2>/dev/null | grep -i usb; lsmod 2>/dev/null | grep usb_storage"
    local restricted=0
    systemctl is-active usbguard >/dev/null 2>&1 && restricted=1
    grep -rqi 'install usb-storage /bin/true\|blacklist usb-storage' /etc/modprobe.d/ 2>/dev/null && restricted=1
    [ $restricted -eq 1 ] && result "SRV-151|양호|외부 매체 접근 제한 설정됨" || \
        result "SRV-151|수동확인|외부 매체 제한 미설정 (USB 차단 정책 확인)"
}

# SRV-152
check_SRV152() {
    evd "SRV-152" "which monit nagios zabbix_agentd ossec-control 2>/dev/null; systemctl is-active zabbix-agent nagios monit 2>/dev/null; ps -ef 2>/dev/null | grep -iE 'monit|nagios|zabbix|prometheus|node_exporter' | grep -v grep | head -5"
    local tools=""
    for t in monit nagios zabbix_agentd node_exporter prometheus; do
        is_running "$t" && tools="${tools} ${t}"
    done
    command -v monit >/dev/null 2>&1 && tools="${tools} monit(설치)"
    [ -n "$tools" ] && result "SRV-152|양호|모니터링 도구:${tools}" || \
        result "SRV-152|수동확인|프로세스 모니터링 도구 미발견 (별도 솔루션 확인)"
}

# SRV-153
check_SRV153() {
    evd "SRV-153" "sysctl net.ipv4.ip_forward net.ipv4.conf.all.accept_source_route net.ipv4.conf.all.accept_redirects net.ipv4.icmp_echo_ignore_broadcasts 2>/dev/null; rpm -qa --last 2>/dev/null | head -5"
    local vuln=""
    local fwd=$(sysctl -n net.ipv4.ip_forward 2>/dev/null)
    [ "$fwd" = "1" ] && vuln="${vuln} ip_forward=1"
    local srcrt=$(sysctl -n net.ipv4.conf.all.accept_source_route 2>/dev/null)
    [ "$srcrt" = "1" ] && vuln="${vuln} accept_source_route=1"
    [ -n "$vuln" ] && result "SRV-153|취약|하드닝 미흡:${vuln}" || \
        result "SRV-153|양호|시스템 하드닝 기본 설정 적절"
}

# SRV-154
check_SRV154() {
    evd "SRV-154" "sysctl net.ipv4.conf.all.accept_redirects net.ipv4.conf.all.send_redirects net.ipv4.conf.all.log_martians net.ipv4.conf.default.rp_filter net.ipv4.tcp_syncookies 2>/dev/null"
    local vuln=""
    local redir=$(sysctl -n net.ipv4.conf.all.accept_redirects 2>/dev/null)
    [ "$redir" = "1" ] && vuln="${vuln} accept_redirects=1"
    local sendr=$(sysctl -n net.ipv4.conf.all.send_redirects 2>/dev/null)
    [ "$sendr" = "1" ] && vuln="${vuln} send_redirects=1"
    local syncook=$(sysctl -n net.ipv4.tcp_syncookies 2>/dev/null)
    [ "$syncook" = "0" ] && vuln="${vuln} tcp_syncookies=0"
    [ -n "$vuln" ] && result "SRV-154|취약|커널 보안 파라미터 미흡:${vuln}" || \
        result "SRV-154|양호|커널 보안 파라미터 적절"
}

# SRV-155
check_SRV155() {
    evd "SRV-155" "systemctl is-active firewalld iptables ufw 2>/dev/null; iptables -L -n 2>/dev/null | head -15; ufw status 2>/dev/null"
    local fw=""
    systemctl is-active firewalld >/dev/null 2>&1 && fw="firewalld"
    systemctl is-active iptables >/dev/null 2>&1 && fw="${fw} iptables"
    ufw status 2>/dev/null | grep -qi "active" && fw="${fw} ufw"
    iptables -L -n 2>/dev/null | grep -qvE '^Chain|^target|^$' && [ -z "$fw" ] && fw="iptables(규칙존재)"
    [ -n "$fw" ] && result "SRV-155|양호|방화벽 활성:${fw}" || \
        result "SRV-155|취약|방화벽 비활성 (firewalld/iptables/ufw 모두 비활성)"
}

# SRV-156
check_SRV156() {
    evd "SRV-156" "rpm -qa --last 2>/dev/null | head -10; apt list --upgradable 2>/dev/null | head -10; yum updateinfo summary 2>/dev/null | head -5; stat -c '%y' /var/lib/rpm/Packages /var/lib/dpkg/status 2>/dev/null"
    local last_update=""
    if [ -f /var/lib/rpm/Packages ]; then
        last_update=$(stat -c '%y' /var/lib/rpm/Packages 2>/dev/null | cut -d' ' -f1)
    elif [ -f /var/lib/dpkg/status ]; then
        last_update=$(stat -c '%y' /var/lib/dpkg/status 2>/dev/null | cut -d' ' -f1)
    fi
    result "SRV-156|수동확인|마지막 패키지 변경: ${last_update:-미확인} (패치 주기/절차 확인)"
}

# SRV-157
check_SRV157() {
    evd "SRV-157" "crontab -l 2>/dev/null | grep -iE 'backup|rsync|tar|dump'; ls /etc/cron.d/ 2>/dev/null | grep -i backup; ls -la /etc/cron.daily/*backup* /etc/cron.weekly/*backup* 2>/dev/null"
    local bak=""
    crontab -l 2>/dev/null | grep -qiE 'backup|rsync|tar|dump' && bak="crontab"
    ls /etc/cron.d/ 2>/dev/null | grep -qi backup && bak="${bak} cron.d"
    ls /etc/cron.daily/*backup* /etc/cron.weekly/*backup* 2>/dev/null | grep -q . && bak="${bak} cron.daily/weekly"
    [ -n "$bak" ] && result "SRV-157|수동확인|백업 설정 발견: ${bak} (주기/범위 확인)" || \
        result "SRV-157|수동확인|백업 cron 미발견 (별도 백업 솔루션 확인)"
}

# SRV-159
check_SRV159() {
    evd "SRV-159" "grep -i Banner /etc/ssh/sshd_config 2>/dev/null | grep -v '^#'; grep -i ftpd_banner /etc/vsftpd/vsftpd.conf /etc/vsftpd.conf 2>/dev/null; postconf smtpd_banner 2>/dev/null"
    local checked=0 configured=0
    if grep -v '^#' /etc/ssh/sshd_config 2>/dev/null | grep -qi "^Banner"; then configured=$((configured+1)); fi
    checked=$((checked+1))
    if is_running vsftpd; then
        checked=$((checked+1))
        for cf in /etc/vsftpd/vsftpd.conf /etc/vsftpd.conf; do
            [ -f "$cf" ] && grep -qi "ftpd_banner" "$cf" 2>/dev/null && configured=$((configured+1))
        done
    fi
    [ $configured -ge 1 ] && result "SRV-159|양호|서비스 배너 설정됨 (${configured}개 서비스)" || \
        result "SRV-159|취약|서비스 배너 미설정 (버전 정보 노출 가능)"
}

# SRV-160
check_SRV160() {
    evd "SRV-160" "grep -E '^PASS_MAX_DAYS|^PASS_MIN_DAYS|^PASS_WARN_AGE|^PASS_MIN_LEN' /etc/login.defs 2>/dev/null"
    local max=$(grep -E '^\s*PASS_MAX_DAYS' /etc/login.defs 2>/dev/null | awk '{print $2}' | tail -1)
    local min=$(grep -E '^\s*PASS_MIN_DAYS' /etc/login.defs 2>/dev/null | awk '{print $2}' | tail -1)
    local warn=$(grep -E '^\s*PASS_WARN_AGE' /etc/login.defs 2>/dev/null | awk '{print $2}' | tail -1)
    local vuln=""
    [ "${max:-99999}" -gt 90 ] 2>/dev/null && vuln="${vuln} MAX_DAYS=${max:-미설정}"
    [ "${min:-0}" -lt 1 ] 2>/dev/null && vuln="${vuln} MIN_DAYS=${min:-0}"
    [ "${warn:-0}" -lt 7 ] 2>/dev/null && vuln="${vuln} WARN_AGE=${warn:-0}"
    [ -n "$vuln" ] && result "SRV-160|취약|패스워드 정책 미흡:${vuln}" || \
        result "SRV-160|양호|패스워드 정책 적절 (MAX=${max}, MIN=${min}, WARN=${warn})"
}

# SRV-162
check_SRV162() {
    evd "SRV-162" "grep -E '/tmp|/var/tmp|/home|/dev/shm' /etc/fstab 2>/dev/null; mount 2>/dev/null | grep -E '/tmp|/var/tmp|/dev/shm'"
    local vuln=""
    for mp in /tmp /var/tmp /dev/shm; do
        local opts=$(mount 2>/dev/null | grep " ${mp} " | awk '{print $NF}')
        if [ -n "$opts" ]; then
            echo "$opts" | grep -q "nosuid" || vuln="${vuln} ${mp}(nosuid 미설정)"
            if [ "$mp" = "/tmp" ] || [ "$mp" = "/var/tmp" ]; then
                echo "$opts" | grep -q "noexec" || vuln="${vuln} ${mp}(noexec 미설정)"
            fi
        fi
    done
    [ -n "$vuln" ] && result "SRV-162|취약|마운트 옵션 미흡:${vuln}" || \
        result "SRV-162|양호|마운트 옵션 적절 (nosuid/noexec 설정)"
}

# SRV-167
check_SRV167() {
    evd "SRV-167" "cat /etc/exports 2>/dev/null; grep -v '^#' /etc/samba/smb.conf 2>/dev/null | grep -iE 'path|share' | head -10; showmount -e localhost 2>/dev/null"
    local shares=""
    [ -f /etc/exports ] && [ -s /etc/exports ] && shares="NFS"
    grep -qi '\[.*\]' /etc/samba/smb.conf 2>/dev/null && shares="${shares} Samba"
    [ -n "$shares" ] && result "SRV-167|수동확인|공유 설정 존재: ${shares} (불필요 공유 확인)" || \
        result "SRV-167|양호|NFS/Samba 공유 미설정"
}

# SRV-168
check_SRV168() {
    evd "SRV-168" "ls -la /etc/passwd /etc/shadow /etc/group /etc/gshadow /etc/ssh/sshd_config /etc/login.defs 2>/dev/null"
    local vuln=""
    local -A expected=(["/etc/passwd"]=644 ["/etc/shadow"]=640 ["/etc/group"]=644 ["/etc/gshadow"]=640 ["/etc/ssh/sshd_config"]=600)
    for f in "${!expected[@]}"; do
        [ -f "$f" ] || continue
        local perm=$(get_perm "$f") owner=$(get_owner "$f")
        [ "$owner" != "root" ] && vuln="${vuln} ${f}(소유자=${owner})"
        [ "${perm:-777}" -gt "${expected[$f]}" ] 2>/dev/null && vuln="${vuln} ${f}(${perm})"
    done
    [ -n "$vuln" ] && result "SRV-168|취약|설정파일 권한 이상:${vuln}" || \
        result "SRV-168|양호|주요 설정파일 권한 적절"
}

# SRV-169
check_SRV169() {
    evd "SRV-169" "find /home /root -name '.forward' -o -name '.exrc' -o -name '.netrc' 2>/dev/null | head -10"
    local found=$(find /home /root -name '.forward' -o -name '.exrc' -o -name '.netrc' 2>/dev/null | head -10)
    [ -n "$found" ] && result "SRV-169|취약|불필요 사용자 환경파일 존재: $(echo "$found" | head -c 200)" || \
        result "SRV-169|양호|.forward/.exrc/.netrc 파일 미존재"
}

# SRV-172
check_SRV172() {
    evd "SRV-172" "cat /etc/issue 2>/dev/null; cat /etc/issue.net 2>/dev/null; uname -a 2>/dev/null"
    local vuln=0
    for f in /etc/issue /etc/issue.net; do
        [ -f "$f" ] || continue
        grep -qiE 'kernel|ubuntu|centos|red hat|debian|amazon|suse' "$f" 2>/dev/null && vuln=1
    done
    [ $vuln -eq 1 ] && result "SRV-172|취약|배너에 OS/커널 정보 노출 (/etc/issue)" || \
        result "SRV-172|양호|배너에 시스템 정보 미노출"
}

# ── 실행 (SRV-001 ~ SRV-179 전체) ───────────────────────────────
check_SRV001
check_SRV002
check_SRV003
check_SRV004
check_SRV005
check_SRV006
check_SRV007
check_SRV008
check_SRV009
check_SRV010
check_SRV011
check_SRV012
check_SRV013
check_SRV014
check_SRV015
check_SRV016
check_SRV017
check_SRV018
check_SRV019
check_SRV020
check_SRV021
check_SRV022
check_SRV023
check_SRV024
check_SRV025
check_SRV026
check_SRV027
check_SRV028
check_SRV029
check_SRV030
check_SRV031
check_SRV032
check_SRV033
check_SRV034
check_SRV035
check_SRV036
check_SRV037
check_SRV038
check_SRV039
check_SRV040
check_SRV041
check_SRV042
check_SRV043
check_SRV044
check_SRV045
check_SRV046
check_SRV047
check_SRV048
check_SRV049
check_SRV050
check_SRV051
check_SRV052
check_SRV053
check_SRV054
check_SRV055
check_SRV056
check_SRV057
check_SRV058
check_SRV059
check_SRV060
check_SRV061
check_SRV062
check_SRV063
check_SRV064
check_SRV065
check_SRV066
check_SRV067
check_SRV068
check_SRV069
check_SRV070
check_SRV071
evd "SRV-072" "uname -s"
result "SRV-072|N-A|Windows 전용 항목 (Linux/Unix 해당 없음)"
check_SRV073
check_SRV074
check_SRV075
check_SRV076
check_SRV077
evd "SRV-078" "uname -s"
result "SRV-078|N-A|Windows Guest 계정 (Linux/Unix 해당 없음)"
evd "SRV-079" "uname -s"
result "SRV-079|N-A|Windows Everyone 권한 (Linux/Unix 해당 없음)"
evd "SRV-080" "uname -s"
result "SRV-080|N-A|Windows 프린터 드라이버 (Linux/Unix 해당 없음)"
check_SRV081
check_SRV082
check_SRV083
check_SRV084
check_SRV085
check_SRV086
check_SRV087
check_SRV088
check_SRV089
evd "SRV-090" "uname -s"
result "SRV-090|N-A|Windows 원격 레지스트리 (Linux/Unix 해당 없음)"
check_SRV091
check_SRV092
check_SRV093
check_SRV094
check_SRV095
check_SRV096
check_SRV097
check_SRV098
check_SRV099
check_SRV100
check_SRV101
check_SRV102
check_SRV103
check_SRV104
check_SRV105
check_SRV106
check_SRV107
check_SRV108
check_SRV109
check_SRV110
check_SRV111
check_SRV112
check_SRV113
check_SRV114
check_SRV115
check_SRV116
check_SRV117
check_SRV118
check_SRV119
check_SRV120
check_SRV121
check_SRV122
check_SRV123
check_SRV124
evd "SRV-125" "uname -s"
result "SRV-125|N-A|Windows 화면 보호기 (Linux/Unix 해당 없음)"
check_SRV126
check_SRV127
check_SRV128
check_SRV129
check_SRV130
check_SRV131
check_SRV132
check_SRV133
check_SRV134
check_SRV135
check_SRV136
check_SRV137
check_SRV138
check_SRV139
check_SRV140
check_SRV141
check_SRV142
check_SRV143
check_SRV144
check_SRV145
check_SRV146
check_SRV147
check_SRV148
check_SRV149
check_SRV150
check_SRV151
check_SRV152
check_SRV153
check_SRV154
check_SRV155
check_SRV156
check_SRV157
check_SRV158
check_SRV159
check_SRV160
check_SRV161
check_SRV162
check_SRV163
check_SRV164
check_SRV165
check_SRV166
check_SRV167
check_SRV168
check_SRV169
check_SRV170
check_SRV171
check_SRV172
check_SRV173
check_SRV174
check_SRV175
check_SRV176
check_SRV177
evd "SRV-178" "uname -s"
result "SRV-178|N-A|Windows 개인 키 passphrase (Linux/Unix 해당 없음)"
check_SRV179

_TOTAL=$((_CP + _CF + _CM + _CN))
echo "# ================================================================"
echo "# 점검 요약 — 전자금융기반시설 (SRV)"
echo "#   총 점검 항목: ${_TOTAL}"
[ "$_TOTAL" -gt 0 ] 2>/dev/null && {
echo "#   양호:         ${_CP}  ($((_CP * 100 / _TOTAL))%)"
echo "#   취약:         ${_CF}  ($((_CF * 100 / _TOTAL))%)"
echo "#   수동확인:     ${_CM}"
echo "#   N-A:          ${_CN}"
}
echo "# ================================================================"
[ -n "$_RESF" ] && echo "# 결과 파일(자동 저장): ${_RESF}  ← 증적 파일과 함께 회수"
[ -n "$_TEEPID" ] && { exec >&- 2>/dev/null; wait "$_TEEPID" 2>/dev/null; sleep 1; }
exit 0
