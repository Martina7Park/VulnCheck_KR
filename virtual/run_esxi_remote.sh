#!/bin/bash
# ================================================================
# 가상화(ESXi) 원격 일괄 점검 — 점검자 PC(Linux/macOS/Git Bash/WSL)에서 실행
# ================================================================
#
# 대상 ESXi 에 스크립트를 업로드하지 않고 SSH 로 check_esxi.sh 를 실행해
# 결과(<호스트>_esxi.txt)·증적(<호스트>_esxi_evidence.txt)을 바로 회수합니다.
#
# [사용법]
#   bash run_esxi_remote.sh hosts.txt [출력폴더]
#
#   hosts.txt — 한 줄에 대상 하나 ('#' 주석·빈 줄 무시, 계정 생략 시 root)
#       10.10.0.31
#       root@erpesxi02.erpsvt.local
#       admin@10.10.0.33
#   출력폴더 — 생략 시 ../converter/virtual/output (없으면 ./output)
#
# [사전 조건]
#   - 대상 ESXi 의 SSH 서비스 임시 활성화 (점검 후 반드시 비활성화 - HV-01)
#   - 호스트별로 SSH 비밀번호를 물어봅니다 (공개키 인증 시 생략)
# ================================================================

DIR=$(cd "$(dirname "$0")" && pwd)
SCRIPT="$DIR/check_esxi.sh"
LIST="$1"
if [ -z "$LIST" ] || [ ! -f "$LIST" ]; then
    echo "사용법: bash $0 hosts.txt [출력폴더]" >&2
    exit 1
fi
OUT="${2:-}"
if [ -z "$OUT" ]; then
    [ -d "$DIR/../converter/virtual/output" ] && OUT="$DIR/../converter/virtual/output" || OUT="$DIR/output"
fi
mkdir -p "$OUT" || exit 1

ok=0; ng=0
while read -r tgt _; do
    case "$tgt" in ''|\#*) continue ;; esac
    case "$tgt" in *@*) ;; *) tgt="root@$tgt" ;; esac
    echo "[점검] $tgt"
    tmp=$(mktemp "${TMPDIR:-/tmp}/esxi_remote.XXXXXX") || exit 1
    # -n 금지: 스크립트를 표준입력으로 넘김. 점검 결과에 비밀번호 프롬프트가 섞이지 않도록 stderr 는 터미널로
    if ssh -o ConnectTimeout=15 -o StrictHostKeyChecking=accept-new "$tgt" 'ESXI_EMIT_EVIDENCE=1 sh -s' < "$SCRIPT" > "$tmp" \
       && grep -q '^### ESXI-EVIDENCE-BEGIN ' "$tmp"; then
        hn=$(sed -n 's/^### ESXI-EVIDENCE-BEGIN //p' "$tmp" | head -1 | tr -d '\r' | tr -c 'A-Za-z0-9._\n-' '_')
        [ -z "$hn" ] && hn="${tgt#*@}"
        sed '/^### ESXI-EVIDENCE-BEGIN /,$d' "$tmp" > "$OUT/${hn}_esxi.txt"
        sed '1,/^### ESXI-EVIDENCE-BEGIN /d' "$tmp" > "$OUT/${hn}_esxi_evidence.txt"
        echo "  → $OUT/${hn}_esxi.txt ($(grep -c '^HV-' "$OUT/${hn}_esxi.txt")개 항목) / ${hn}_esxi_evidence.txt"
        ok=$((ok+1))
    else
        echo "  [실패] $tgt - SSH 접속·실행 실패 또는 ESXi 아님 (출력 일부: $(head -c 200 "$tmp" | tr '\n' ' '))" >&2
        ng=$((ng+1))
    fi
    rm -f "$tmp"
done < "$LIST"

echo "완료: 성공 ${ok}대 / 실패 ${ng}대 (출력 폴더: $OUT)"
echo "※ 점검이 끝난 ESXi 는 SSH 서비스를 다시 중지하세요."
[ "$ng" -eq 0 ]
