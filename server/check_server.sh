#!/bin/bash
if [ -z "$BASH_VERSION" ]; then for _b in /bin/bash /usr/bin/bash /opt/freeware/bin/bash /usr/local/bin/bash /usr/contrib/bin/bash; do [ -x $_b ] && exec $_b "$0" "$@"; done; echo "bash 필요 (AIX: AIX Toolbox bash / HP-UX: Porting Centre bash 설치 후 재실행)"; exit 1; fi
# ================================================================
# 서버(Unix/Linux) 보안 취약점 점검 실행기
# ================================================================
#
# [용도]
#   기준을 골라 같은 폴더의 점검 스크립트를 실행한다. 점검 로직은 이 파일에 없다.
#     srv  → check_server_srv.sh  (전자금융기반시설 평가기준 제2026-1호 SRV)
#     u    → check_server_u.sh    (주요정보통신기반시설 상세가이드 2026 U-01~U-67)
#     all  → 둘 다 (전자금융 결과는 표준출력, 주요정보 결과는 /tmp/<호스트>_u.txt)
#   Windows Server는 run_server.bat 사용.
#
# [실행 방법]
#   sudo bash ./check_server.sh       > ./$(hostname)_server.txt   # 메뉴에서 선택 (메뉴는 stderr)
#   sudo bash ./check_server.sh srv   > ./$(hostname)_server.txt
#   sudo bash ./check_server.sh u     > ./$(hostname)_u.txt
#   sudo bash ./check_server.sh all   > ./$(hostname)_server.txt
#
# [산출물]
#   각 점검 스크립트가 표준출력(항목코드|결과|근거)과 증적 파일(/tmp/<호스트>_*_evidence.txt)을 만든다.
# ================================================================

_MODE="${1:-}"
if [ -z "$_MODE" ]; then
    { echo "점검 기준을 선택하세요:"
      echo "  1) 전자금융기반시설 (SRV-001~179)"
      echo "  2) 주요정보통신기반시설 2026 상세가이드 (U-01~U-67)"
      echo "  3) 전체 (전자금융 결과 + 주요정보 결과 파일 각각 생성)"
      printf "선택 [1/2/3]: "; } >&2   # '> 파일' 리다이렉트 시에도 화면에 표시
    read -r _sel
    case "$_sel" in
    1) _MODE="srv" ;;
    2) _MODE="u" ;;
    3) _MODE="all" ;;
    *) echo "잘못된 선택. 종료합니다." >&2; exit 1 ;;
    esac
fi
_MODE=$(echo "$_MODE" | tr '[:upper:]' '[:lower:]')
_SELF_DIR=$(cd "$(dirname "$0")" 2>/dev/null && pwd)
_need() { [ -f "$_SELF_DIR/$1" ] || { echo "# [오류] $1 가 같은 폴더에 없습니다 - server 폴더를 통째로 복사하세요" >&2; exit 1; }; }

case "$_MODE" in
srv) _need check_server_srv.sh; exec bash "$_SELF_DIR/check_server_srv.sh" ;;
u)   _need check_server_u.sh;   exec bash "$_SELF_DIR/check_server_u.sh" ;;
all)
    _need check_server_srv.sh; _need check_server_u.sh
    HN=$(hostname 2>/dev/null || uname -n)
    bash "$_SELF_DIR/check_server_srv.sh"
    # 주요정보 결과는 별도 파일 (umask 077: 결과·증적에 계정·설정 정보 포함)
    _UF="/tmp/${HN}_u.txt"
    [ -L "$_UF" ] && rm -f "$_UF"
    ( umask 077; NO_RESULT_COPY=1 bash "$_SELF_DIR/check_server_u.sh" > "$_UF" )
    echo "# 주요정보(U-01~U-67) 결과: ${_UF} / 증적: /tmp/${HN}_u_evidence.txt"
    ;;
*) echo "사용법: $0 {srv|u|all}" >&2; exit 1 ;;
esac
