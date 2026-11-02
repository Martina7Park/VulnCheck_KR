#!/usr/bin/env python3
"""공통 점검 코드 동기화 — 원본 한 곳만 고치고 사본은 이 도구로 갱신한다.

  python tools/sync_common.py          # 사본 갱신
  python tools/sync_common.py --check  # 사본이 원본과 다르면 종료코드 1 (커밋 전 확인용)

원본 → 사본 (마커 사이 구간을 그대로 복사)
  server/check_server_srv.sh  SRV-COMMON, SRV-RUN  → webwas/check_webwas.sh
  server/check_server.ps1     SRV-COMMON           → webwas/check_webwas.ps1
"""
import os, re, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PAIRS = [
    ("server/check_server_srv.sh", "webwas/check_webwas.sh", ("SRV-COMMON", "SRV-RUN")),
    ("server/check_server.ps1", "webwas/check_webwas.ps1", ("SRV-COMMON",)),
]


def block(text, name, path):
    m = re.search(rf"^[^\n]*>>> {name}-BEGIN[^\n]*\n(.*?)^[^\n]*<<< {name}-END[^\n]*$", text, re.M | re.S)
    if not m:
        sys.exit(f"[오류] {path}: {name}-BEGIN/END 마커 없음")
    return m


def main():
    check = "--check" in sys.argv
    stale = []
    for src, dst, names in PAIRS:
        sp, dp = os.path.join(ROOT, src), os.path.join(ROOT, dst)
        with open(sp, encoding="utf-8", newline="") as f:
            s = f.read()
        with open(dp, encoding="utf-8", newline="") as f:
            d = f.read()
        new = d
        for n in names:
            body = block(s, n, src).group(1)
            m = block(new, n, dst)
            new = new[:m.start(1)] + body + new[m.end(1):]
        if new != d:
            stale.append(dst)
            if not check:
                with open(dp, "w", encoding="utf-8", newline="") as f:
                    f.write(new)
    if stale:
        print(("[불일치] " if check else "[갱신] ") + ", ".join(stale))
        sys.exit(1 if check else 0)
    print("[일치] 공통 코드 사본이 원본과 같습니다")


if __name__ == "__main__":
    main()
