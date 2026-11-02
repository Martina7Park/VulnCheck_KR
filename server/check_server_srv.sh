#!/bin/bash
# ================================================================
# 서버(Unix/Linux) 보안 취약점 자동 점검 — 전자금융기반시설 단독 실행용
# ================================================================
#
# [용도]
#   전자금융기반시설 보안 취약점 평가기준 제2026-1호 [서버] (SRV) 만 점검.
#   점검 로직은 check_server.sh 한 곳에서 관리하며, 이 파일은 'check_server.sh srv' 를 실행한다.
#   (예전에는 같은 점검 코드를 두 파일에 따로 두어 판정이 서로 달라지는 문제가 있었음)
#
# [실행 방법]  같은 폴더에 check_server.sh 필요 (server/ 폴더째 복사)
#   bash check_server_srv.sh > /tmp/$(hostname)_srv.txt
#
# [산출물]
#   1) 표준출력: SRV-항목코드|결과|근거설명  (양호/취약/수동확인/N-A)
#   2) 증적 파일: /tmp/<호스트명>_srv_evidence.txt
# ================================================================
_D=$(cd "$(dirname "$0")" 2>/dev/null && pwd)
if [ ! -f "$_D/check_server.sh" ]; then
    echo "# [오류] check_server.sh 가 같은 폴더(${_D})에 없습니다 - server/ 폴더를 통째로 복사하십시오" >&2
    exit 1
fi
SRV_FILE_TAG=srv exec bash "$_D/check_server.sh" srv
