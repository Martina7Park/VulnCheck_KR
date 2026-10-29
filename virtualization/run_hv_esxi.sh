#!/bin/sh
# ================================================================
# 여러 ESXi 호스트 일괄 점검 (점검자 PC — Linux / macOS)
# ================================================================
#   ESXi 마다 SSH 로 check_hv_esxi.sh 를 원격 실행하고, 결과+증적을 한 파일로 받습니다.
#   ESXi 에는 파일이 남지 않습니다.
#
# [사용]
#   sh run_hv_esxi.sh hosts.txt [계정]          (계정 기본값: root)
#   hosts.txt : 한 줄에 ESXi IP 또는 호스트명 하나 (# 이후는 주석)
#   HV_SSH_TEMP=1 sh run_hv_esxi.sh hosts.txt   SSH 를 점검 때문에 잠시 켠 경우 (HV-12 판정 참고)
#
# [결과]
#   ./hv_output/<ESXi 호스트명>_hv.txt  → converter/virtualization/output/ 에 복사
# ================================================================

HOSTS=${1:-hosts.txt}
USR=${2:-root}
DIR=$(cd "$(dirname "$0")" && pwd)
SCRIPT="$DIR/check_hv_esxi.sh"
OUT=./hv_output

[ -f "$HOSTS" ] || { echo "[ERROR] 호스트 목록 파일 없음: $HOSTS (한 줄에 ESXi IP/호스트명)"; exit 1; }
[ -f "$SCRIPT" ] || { echo "[ERROR] 점검 스크립트 없음: $SCRIPT"; exit 1; }
mkdir -p "$OUT"

ok=0; fail=0
# 목록 읽기는 fd 3 사용 (ssh 가 표준입력을 스크립트 본문으로 사용)
while IFS= read -r line <&3; do
    h=$(printf '%s' "$line" | sed 's/#.*//; s/^[[:space:]]*//; s/[[:space:]]*$//')
    [ -z "$h" ] && continue
    echo "[*] ${USR}@${h} 점검 중..."
    tmp="$OUT/.${h}_hv.tmp"
    if ssh -o ConnectTimeout=10 -o StrictHostKeyChecking=accept-new "${USR}@${h}" \
           "HV_INLINE=1 HV_SSH_TEMP=${HV_SSH_TEMP:-0} sh -s" < "$SCRIPT" > "$tmp" 2> "$tmp.err" \
       && grep -q '^HV-' "$tmp"; then
        name=$(sed -n 's/^# 점검 대상: *//p' "$tmp" | head -1)
        mv "$tmp" "$OUT/${name:-$h}_hv.txt"; rm -f "$tmp.err"
        echo "    → $OUT/${name:-$h}_hv.txt ($(grep -c '^HV-.*|취약|' "$OUT/${name:-$h}_hv.txt")건 취약)"
        ok=$((ok+1))
    else
        cat "$tmp.err" "$tmp" > "$OUT/${h}_hv_FAILED.log" 2>/dev/null; rm -f "$tmp" "$tmp.err"
        echo "    [실패] SSH 접속·실행 실패 - $OUT/${h}_hv_FAILED.log 확인 (SSH 서비스 시작·계정·방화벽)"
        fail=$((fail+1))
    fi
done 3< "$HOSTS"

echo "완료: 성공 ${ok}대 / 실패 ${fail}대 → $OUT/*_hv.txt 를 converter/virtualization/output/ 에 넣고 convert_v4.py 실행 (2. 주요정보 → 7. 가상화 장비)"
echo "점검이 끝난 ESXi 는 SSH 서비스를 다시 중지하십시오 (HV-12)."
