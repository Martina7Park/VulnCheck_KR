#!/usr/bin/env python3
"""
점검 결과 diff / 추세 비교 도구

[사용법]
  1) 두 엑셀 비교 (이전 vs 현재):
     python compare_results.py diff  이전결과.xlsx  현재결과.xlsx

  2) 감사 로그 기반 추세 분석:
     python compare_results.py trend  logs/

  3) 특정 호스트만 비교:
     python compare_results.py diff  이전.xlsx  현재.xlsx  --host WEB-01

[입력]
  - diff: 컨버터가 만든 보고서(.xlsx). 호스트별 상세 시트의 '점검 항목'·'점검결과'·'현황 및 문제점' 열을 헤더로 찾아 읽음
    (표지·통계 시트는 제외). 수식 셀은 '검토·수정' 시트 값 → 숨김 원본 판정 열 순으로 대체
  - trend: logs/audit_*.json (대상 수가 달라도 비교되도록 취약률로 비교)
  - 판정값: 양호 / 취약 / N-A / 수동확인 / 점검불가

[출력]
  - 콘솔 요약
  - diff → compare_diff_YYYYMMDD_HHMMSS.xlsx
  - trend → compare_trend_YYYYMMDD_HHMMSS.xlsx
"""

import os, sys, datetime, json, glob, re

try:
    import openpyxl
    from openpyxl.styles import PatternFill, Font, Alignment, Border, Side
except ImportError:
    print("[ERROR] openpyxl 필요: pip install openpyxl")
    sys.exit(1)


RESULT_GOOD, RESULT_BAD, RESULT_NA, RESULT_MANUAL, RESULT_UNABLE = "양호", "취약", "N-A", "수동확인", "점검불가"
RESULTS = {RESULT_GOOD, RESULT_BAD, RESULT_NA, RESULT_MANUAL, RESULT_UNABLE}
FONT_NAME = "맑은 고딕"

# 색 체계: convert_v4.py 의 FILL_*·RESULT_FONT 와 같게 (취약 행 연빨강 FDECEA, 양호 네이비 굵게, N-A 회색, 수동확인 진회색)
# 점검불가는 컨버터 쪽 정의를 참고만 하여 노란 계열(주의)로 표시
FILL_HEADER = PatternFill(start_color="1F3864", end_color="1F3864", fill_type="solid")   # 네이비
FILL_BAD    = PatternFill(start_color="FDECEA", end_color="FDECEA", fill_type="solid")   # 연한 빨강
FILL_UNABLE = PatternFill(start_color="FFF2CC", end_color="FFF2CC", fill_type="solid")   # 연한 노랑
FILL_GOOD   = PatternFill(start_color="E2EFDA", end_color="E2EFDA", fill_type="solid")   # 연한 초록 (개선 표시 전용)
FILL_NEW_VULN = PatternFill(start_color="C0392B", end_color="C0392B", fill_type="solid")  # 신규 취약 시트 머리글
FILL_RESOLVED = PatternFill(start_color="1F3864", end_color="1F3864", fill_type="solid")  # 조치 완료 시트 머리글
FILL_UNVERIFIED = PatternFill(start_color="7F6000", end_color="7F6000", fill_type="solid")  # 확인불가 전환 시트 머리글

RESULT_FONT = {
    RESULT_GOOD:   Font(name=FONT_NAME, size=9, bold=True, color="1F3864"),
    RESULT_BAD:    Font(name=FONT_NAME, size=9, bold=True, color="C0392B"),
    RESULT_NA:     Font(name=FONT_NAME, size=9, color="999999"),
    RESULT_MANUAL: Font(name=FONT_NAME, size=9, color="333333"),
    RESULT_UNABLE: Font(name=FONT_NAME, size=9, bold=True, color="7F6000"),
}
RESULT_FILL = {RESULT_BAD: FILL_BAD, RESULT_UNABLE: FILL_UNABLE}

BD = Border(
    left=Side(style="thin", color="CCCCCC"),
    right=Side(style="thin", color="CCCCCC"),
    top=Side(style="thin", color="CCCCCC"),
    bottom=Side(style="thin", color="CCCCCC"),
)

_RESULT_ALIASES = {"N/A": RESULT_NA, "NA": RESULT_NA, "N-A": RESULT_NA, "해당없음": RESULT_NA}


def norm_result(v):
    """셀 값 → 표준 판정값 (공백 제거, N/A 표기 통일). 알 수 없는 값은 원문 유지"""
    s = re.sub(r"\s+", "", str(v or ""))
    return _RESULT_ALIASES.get(s.upper(), s)


def read_text(path):
    with open(path, "rb") as f:
        bom = f.read(2)
    encs = ("utf-16",) if bom in (b"\xff\xfe", b"\xfe\xff") else ()   # PowerShell 5.1 '>' 리다이렉트 = UTF-16LE
    for enc in encs + ("utf-8-sig", "utf-8", "cp949", "euc-kr", "latin-1"):
        try:
            with open(path, encoding=enc) as f:
                return f.read()
        except (UnicodeDecodeError, UnicodeError):
            continue
    return open(path, encoding="latin-1").read()


# ================================================================
# 엑셀 파싱: {(hostname, item_code): {"result": str, "reason": str, "sheet": str}}
#   컨버터 보고서 구조: 호스트(점검대상)별 상세 시트 — 헤더 행에 '점검 항목'(항목코드 열)·'점검결과'·'현황 및 문제점',
#   상단에 'Host Name' 라벨(값은 오른쪽 칸). 표지·개요·통계 등 다른 시트는 헤더가 없으므로 읽지 않는다.
#   점검결과·현황 칸이 '검토·수정' 시트를 참조하는 수식이면(캐시값 없음) 그 시트의 값을 따라가고,
#   그래도 없으면 숨김 원본 판정 열(점검결과 열 +4, 컨버터 S열 = 생성 시 판정)을 사용한다.
# ================================================================
_CODE_RE = re.compile(r"^[A-Z]{1,4}-\d{1,4}$")
_REF_RE = re.compile(r"^=\s*IF\(\s*(?:'((?:[^']|'')+)'|([^'!()]+))!\$?([A-Z]{1,3})\$?(\d+)\s*=\s*\"\"")
_STRICT_CODE_HDR = ("점검항목",)
_LOOSE_CODE_HDR = ("점검항목", "평가항목id", "항목id", "항목코드")
_LOOSE_RESULT_HDR = ("점검결과", "결과", "최종판정")


def _nk(v):
    return re.sub(r"\s+", "", str(v or "")).lower()


def _find_header(rows, code_hdrs, result_hdrs):
    """rows(list of tuple) 앞 60행에서 (헤더 행 idx, 항목코드 열, 결과 열, 사유 열) 탐색 (0-based). 없으면 None"""
    for ri, row in enumerate(rows[:60]):
        code_c = res_c = why_c = None
        for ci, v in enumerate(row):
            k = _nk(v)
            if not k:
                continue
            if code_c is None and k in code_hdrs:
                code_c = ci
            elif res_c is None and k in result_hdrs:
                res_c = ci
            elif why_c is None and (k.startswith("현황") or "근거" in k):
                why_c = ci
        if code_c is not None and res_c is not None:
            return ri, code_c, res_c, why_c
    return None


def _find_host(rows, upto, sheet_title):
    """헤더 위쪽의 'Host Name' 라벨 오른쪽 첫 값 → 호스트명. 없으면 시트명"""
    for row in rows[:upto]:
        for ci, v in enumerate(row):
            if _nk(v) in ("hostname", "호스트명", "호스트"):
                for w in row[ci + 1:]:
                    if w not in (None, "") and not str(w).startswith("="):
                        return str(w).strip()
    return sheet_title


def parse_result_excel(xlsx_path):
    wb_v = openpyxl.load_workbook(xlsx_path, read_only=True, data_only=True)    # 캐시된 계산값
    wb_f = openpyxl.load_workbook(xlsx_path, read_only=True, data_only=False)   # 수식 원문 (캐시값이 없을 때 참조 추적)
    try:
        grids_v, grids_f = {}, {}
        for name in wb_v.sheetnames:
            grids_v[name] = [tuple(r) for r in wb_v[name].iter_rows(values_only=True)]
            grids_f[name] = [tuple(r) for r in wb_f[name].iter_rows(values_only=True)]
    finally:
        wb_v.close()
        wb_f.close()

    def cell(grid, r, c):
        try:
            return grid[r][c]
        except IndexError:
            return None

    def follow(name, r, c):
        """(name,r,c) 셀의 표시값: 캐시값 → 참조 수식이면 대상 시트 값 → None"""
        v = cell(grids_v[name], r, c)
        if v not in (None, ""):
            return v
        f = cell(grids_f[name], r, c)
        if isinstance(f, str) and f.startswith("="):
            m = _REF_RE.match(f)
            if m:
                tgt = (m.group(1) or m.group(2)).replace("''", "'")
                if tgt in grids_v:
                    col = 0
                    for ch in m.group(3):
                        col = col * 26 + ord(ch) - 64
                    tv = cell(grids_v[tgt], int(m.group(4)) - 1, col - 1)
                    if tv not in (None, ""):
                        return tv
        return None

    def collect(code_hdrs, result_hdrs):
        data, seen_hosts = {}, set()
        for name, rows in grids_v.items():
            hdr = _find_header(rows, code_hdrs, result_hdrs)
            if not hdr:
                continue
            hr, cc, rc, wc = hdr
            host = _find_host(rows, hr, name)
            if host in seen_hosts:
                host = f"{host}({name})"
            seen_hosts.add(host)
            orig_c = rc + 4   # 숨김 원본 판정 열 (컨버터: O → S)
            for ri in range(hr + 1, len(rows)):
                code_v = cell(rows, ri, cc)
                if code_v is None:
                    continue
                code = str(code_v).strip().upper()
                if not _CODE_RE.match(code):
                    continue
                rv = norm_result(follow(name, ri, rc))
                if rv not in RESULTS:
                    ov = norm_result(cell(rows, ri, orig_c))
                    if ov in RESULTS:
                        rv = ov
                reason = ""
                if wc is not None:
                    w = follow(name, ri, wc)
                    reason = str(w).strip() if w not in (None, "") else ""
                data[(host, code)] = {"result": rv, "reason": reason, "sheet": name}
        return data

    data = collect(_STRICT_CODE_HDR, ("점검결과",))
    if not data:   # 컨버터 형식이 아니면 느슨한 헤더로 재시도
        data = collect(_LOOSE_CODE_HDR, _LOOSE_RESULT_HDR)
    if not data:
        print(f"  [WARN] 점검 항목/점검결과 헤더가 있는 시트를 찾을 수 없음: {xlsx_path}")
    return data


# ================================================================
# diff 모드: 이전 vs 현재 비교
# ================================================================
_DETERMINATE = (RESULT_GOOD, RESULT_BAD, RESULT_NA)


def classify_change(pr, cr):
    """(이전, 현재) 판정 → 변경 라벨 ('' = 변경 없음)
       악화: 취약이 아니던 것이 취약으로 / 개선: 취약 → 양호·N-A / 확인불가 전환: 확정 판정 → 수동확인·점검불가
       판정 확정: 수동확인·점검불가 → 양호·N-A / 그 외 변경"""
    if pr == cr:
        return ""
    if pr == "-":
        return "신규"
    if cr == "-":
        return "삭제"
    if cr == RESULT_BAD:
        return "악화"
    if pr == RESULT_BAD and cr in (RESULT_GOOD, RESULT_NA):
        return "개선"
    if pr in _DETERMINATE and cr in (RESULT_MANUAL, RESULT_UNABLE):
        return "확인불가 전환"
    if pr in (RESULT_MANUAL, RESULT_UNABLE) and cr in (RESULT_GOOD, RESULT_NA):
        return "판정 확정"
    return "변경"


def run_diff(prev_path, curr_path, host_filter=None):
    print(f"[비교] 이전: {os.path.basename(prev_path)}")
    print(f"[비교] 현재: {os.path.basename(curr_path)}")

    prev = parse_result_excel(prev_path)
    curr = parse_result_excel(curr_path)

    if host_filter:
        prev = {k: v for k, v in prev.items() if k[0] == host_filter or v.get("sheet") == host_filter}
        curr = {k: v for k, v in curr.items() if k[0] == host_filter or v.get("sheet") == host_filter}

    if not prev or not curr:
        print("[ERROR] 비교할 점검 결과를 읽지 못했습니다 (컨버터가 만든 호스트별 상세 시트가 있는 보고서인지, --host 값이 맞는지 확인)")
        return None

    all_keys = sorted(set(prev.keys()) | set(curr.keys()))
    prev_hosts = {k[0] for k in prev}
    curr_hosts = {k[0] for k in curr}

    new_vulns = []
    resolved = []
    unverified = []
    changed = []
    unchanged = []
    new_items = []
    removed_items = []

    for key in all_keys:
        hostname, code = key
        p = prev.get(key)
        c = curr.get(key)

        if p and not c:
            removed_items.append({"host": hostname, "code": code,
                                  "prev_result": p["result"], "prev_reason": p["reason"]})
            continue
        if not p and c:
            new_items.append({"host": hostname, "code": code,
                              "curr_result": c["result"], "curr_reason": c["reason"]})
            if c["result"] == RESULT_BAD:
                new_vulns.append({"host": hostname, "code": code,
                                  "reason": c["reason"]})
            continue

        pr = p["result"]
        cr = c["result"]
        label = classify_change(pr, cr)

        if not label:
            unchanged.append({"host": hostname, "code": code, "result": cr})
            continue
        entry = {"host": hostname, "code": code, "label": label,
                 "prev": pr, "curr": cr,
                 "prev_reason": p["reason"], "curr_reason": c["reason"]}
        changed.append(entry)
        if label == "악화":
            new_vulns.append({"host": hostname, "code": code, "reason": c["reason"]})
        elif label == "개선":
            resolved.append({"host": hostname, "code": code,
                             "new_result": cr, "reason": c["reason"]})
        elif label == "확인불가 전환":
            unverified.append({"host": hostname, "code": code, "prev": pr,
                               "new_result": cr, "reason": c["reason"]})

    # 콘솔 요약
    print(f"\n{'='*60}")
    print(f" 비교 결과 요약")
    print(f"{'='*60}")
    print(f"  전체 항목:       {len(all_keys):>5}건")
    print(f"  변경 없음:       {len(unchanged):>5}건")
    print(f"  결과 변경:       {len(changed):>5}건")
    print(f"  신규 취약:       {len(new_vulns):>5}건  ← 주의")
    print(f"  취약→조치완료:   {len(resolved):>5}건  ← 개선")
    print(f"  확인불가 전환:   {len(unverified):>5}건  ← 양호/취약이 수동확인·점검불가로 바뀜 (재점검 필요)")
    print(f"  신규 추가 항목:  {len(new_items):>5}건")
    print(f"  삭제된 항목:     {len(removed_items):>5}건")
    if prev_hosts - curr_hosts:
        print(f"  이전에만 있는 호스트: {', '.join(sorted(prev_hosts - curr_hosts))}")
    if curr_hosts - prev_hosts:
        print(f"  현재에만 있는 호스트: {', '.join(sorted(curr_hosts - prev_hosts))}")
    print(f"{'='*60}")

    if new_vulns:
        print(f"\n▼ 신규 취약 항목 ({len(new_vulns)}건):")
        for v in new_vulns:
            print(f"  [{v['host']}] {v['code']} — {v['reason'][:60]}")

    if resolved:
        print(f"\n▲ 조치 완료 항목 ({len(resolved)}건):")
        for v in resolved:
            print(f"  [{v['host']}] {v['code']} → {v['new_result']}")

    if unverified:
        print(f"\n? 확인불가 전환 항목 ({len(unverified)}건):")
        for v in unverified:
            print(f"  [{v['host']}] {v['code']} {v['prev']} → {v['new_result']} — {v['reason'][:50]}")

    # 엑셀 출력
    wb = openpyxl.Workbook()

    # 시트 1: 요약
    ws_sum = wb.active
    ws_sum.title = "비교 요약"
    _write_summary_sheet(ws_sum, prev_path, curr_path,
                         len(all_keys), len(unchanged), len(changed),
                         len(new_vulns), len(resolved),
                         len(new_items), len(removed_items), len(unverified))

    # 시트 2: 신규 취약
    if new_vulns:
        ws_nv = wb.create_sheet("신규 취약")
        _write_list_sheet(ws_nv, ["호스트", "항목코드", "근거"],
                          [[v["host"], v["code"], v["reason"]] for v in new_vulns],
                          FILL_NEW_VULN)

    # 시트 3: 조치 완료
    if resolved:
        ws_rv = wb.create_sheet("조치 완료")
        _write_list_sheet(ws_rv, ["호스트", "항목코드", "변경 후 결과", "근거"],
                          [[v["host"], v["code"], v["new_result"], v["reason"]] for v in resolved],
                          FILL_RESOLVED)

    # 시트 3-2: 확인불가 전환
    if unverified:
        ws_uv = wb.create_sheet("확인불가 전환")
        _write_list_sheet(ws_uv, ["호스트", "항목코드", "이전 결과", "현재 결과", "근거"],
                          [[v["host"], v["code"], v["prev"], v["new_result"], v["reason"]] for v in unverified],
                          FILL_UNVERIFIED)

    # 시트 4: 전체 변경
    if changed:
        ws_ch = wb.create_sheet("결과 변경")
        _write_list_sheet(ws_ch, ["호스트", "항목코드", "이전 결과", "현재 결과", "변경", "이전 근거", "현재 근거"],
                          [[e["host"], e["code"], e["prev"], e["curr"], e["label"],
                            e["prev_reason"], e["curr_reason"]] for e in changed])

    # 시트 5: 전체 diff (호스트×항목 매트릭스)
    ws_all = wb.create_sheet("전체 비교")
    _write_full_diff_sheet(ws_all, all_keys, prev, curr)

    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    out_dir = os.path.dirname(curr_path) or "."
    out_path = os.path.join(out_dir, f"compare_diff_{ts}.xlsx")
    wb.save(out_path)
    print(f"\n[완료] 비교 결과 저장: {out_path}")
    return out_path


def _apply_result_style(cell, val):
    """판정값 셀 서식 — 컨버터와 같은 글꼴·배경(취약 FDECEA)"""
    cell.font = RESULT_FONT.get(val, Font(name=FONT_NAME, size=9))
    if val in RESULT_FILL:
        cell.fill = RESULT_FILL[val]


def _write_summary_sheet(ws, prev_name, curr_name,
                         total, unchanged, chg, new_v, resolved, new_i, removed, unverified=0):
    ws.column_dimensions["A"].width = 20
    ws.column_dimensions["B"].width = 50

    rows = [
        ("비교 일시", datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
        ("이전 결과", os.path.basename(prev_name)),
        ("현재 결과", os.path.basename(curr_name)),
        ("", ""),
        ("전체 항목", total),
        ("변경 없음", unchanged),
        ("결과 변경", chg),
        ("신규 취약", new_v),
        ("취약→조치완료", resolved),
        ("확인불가 전환", unverified),
        ("신규 추가 항목", new_i),
        ("삭제된 항목", removed),
    ]
    for i, (label, val) in enumerate(rows, 1):
        ws.cell(i, 1, label).font = Font(name=FONT_NAME, size=10, bold=True)
        ws.cell(i, 2, val).font = Font(name=FONT_NAME, size=10)
        if label == "신규 취약" and val > 0:
            ws.cell(i, 2).fill = FILL_BAD
        if label == "확인불가 전환" and val > 0:
            ws.cell(i, 2).fill = FILL_UNABLE
        if label == "취약→조치완료" and val > 0:
            ws.cell(i, 2).fill = FILL_GOOD


def _write_list_sheet(ws, headers, rows, header_fill=None):
    for ci, h in enumerate(headers, 1):
        c = ws.cell(1, ci, h)
        c.font = Font(name=FONT_NAME, size=10, bold=True, color="FFFFFF")
        c.fill = header_fill or FILL_HEADER
        c.alignment = Alignment(horizontal="center", vertical="center")
        c.border = BD

    for ri, row in enumerate(rows, 2):
        for ci, val in enumerate(row, 1):
            c = ws.cell(ri, ci, val)
            c.font = Font(name=FONT_NAME, size=9)
            c.border = BD
            c.alignment = Alignment(vertical="center", wrap_text=True)
            if isinstance(val, str) and val in RESULTS:
                _apply_result_style(c, val)

    for ci in range(1, len(headers) + 1):
        ws.column_dimensions[openpyxl.utils.get_column_letter(ci)].width = max(15, len(headers[ci-1]) * 2 + 4)
    if len(headers) >= 3:
        ws.column_dimensions[openpyxl.utils.get_column_letter(len(headers))].width = 60
        if len(headers) >= 7:   # 결과 변경 시트: 이전·현재 근거 모두 넓게
            ws.column_dimensions[openpyxl.utils.get_column_letter(len(headers) - 1)].width = 60


def _write_full_diff_sheet(ws, all_keys, prev, curr):
    headers = ["호스트", "항목코드", "이전 결과", "현재 결과", "변경", "현재 근거"]
    for ci, h in enumerate(headers, 1):
        c = ws.cell(1, ci, h)
        c.font = Font(name=FONT_NAME, size=10, bold=True, color="FFFFFF")
        c.fill = FILL_HEADER
        c.alignment = Alignment(horizontal="center")
        c.border = BD

    ri = 2
    for key in sorted(all_keys):
        hostname, code = key
        p = prev.get(key, {})
        c_data = curr.get(key, {})
        pr = p.get("result", "-")
        cr = c_data.get("result", "-")
        change_label = classify_change(pr, cr)

        row_vals = [hostname, code, pr, cr, change_label, c_data.get("reason", "")]
        for ci, val in enumerate(row_vals, 1):
            cell = ws.cell(ri, ci, val)
            cell.font = Font(name=FONT_NAME, size=9)
            cell.border = BD
            if ci in (3, 4) and val in RESULTS:
                _apply_result_style(cell, val)
            if ci == 5:
                if val == "악화":
                    cell.fill = FILL_BAD
                    cell.font = Font(name=FONT_NAME, size=9, bold=True, color="C0392B")
                elif val == "개선":
                    cell.fill = FILL_GOOD
                    cell.font = Font(name=FONT_NAME, size=9, bold=True, color="1F3864")
                elif val == "확인불가 전환":
                    cell.fill = FILL_UNABLE
                    cell.font = Font(name=FONT_NAME, size=9, bold=True, color="7F6000")
        ri += 1

    ws.column_dimensions["A"].width = 18
    ws.column_dimensions["B"].width = 12
    ws.column_dimensions["C"].width = 12
    ws.column_dimensions["D"].width = 12
    ws.column_dimensions["E"].width = 14
    ws.column_dimensions["F"].width = 60
    ws.auto_filter.ref = f"A1:F{max(ri - 1, 1)}"


# ================================================================
# trend 모드: 감사 로그 기반 추세 분석 (대상 수가 달라도 비교되도록 비율 기준)
#   취약률 = 취약 / (전체 - N-A)   — N-A 는 평가 대상이 아니므로 분모에서 제외, 수동확인·점검불가는 분모에 포함
#   호스트당 취약 = 취약 / 대상 수
# ================================================================
_UNABLE_KEYS = ("unable", "unavailable", "uncheckable", "점검불가")   # 감사 로그의 점검불가 건수 키 (컨버터 구현에 따라)
RATE_EPS = 0.001   # 취약률 변화가 0.1%p 이내면 '유지'


def _unable_count(d):
    for k in _UNABLE_KEYS:
        if isinstance(d.get(k), int):
            return d[k]
    return 0


def _rate_dir(first, last):
    if first is None or last is None:
        return "-"
    delta = last - first
    return "악화" if delta > RATE_EPS else "개선" if delta < -RATE_EPS else "유지"


def run_trend(log_dir):
    print(f"[추세] 로그 폴더: {log_dir}")

    log_files = sorted(glob.glob(os.path.join(log_dir, "*.json")))
    if not log_files:
        print("[ERROR] JSON 로그 파일 없음")
        return

    entries = []
    for lf in log_files:
        try:
            text = read_text(lf)
            data = json.loads(text)
            if not isinstance(data, dict) or not isinstance(data.get("summary"), dict):
                print(f"  [WARN] 감사 로그 형식이 아님(건너뜀): {lf}")
                continue
            entries.append(data)
        except Exception as e:
            print(f"  [WARN] 로그 파싱 실패: {lf} — {e}")

    if not entries:
        print("[ERROR] 유효한 로그 없음")
        return

    entries.sort(key=lambda e: e.get("timestamp", ""))

    print(f"\n{'='*60}")
    print(f" 추세 분석 ({len(entries)}건 로그)")
    print(f"{'='*60}")
    print(f"  {'일시':<20} {'기준':<5} {'카테고리':<9} {'대상':>4} {'양호':>5} {'취약':>5} {'N-A':>5} {'수동':>5} {'불가':>5} {'취약률':>7} {'호스트당취약':>10}")
    print(f"  {'-'*20} {'-'*5} {'-'*9} {'-'*4} {'-'*5} {'-'*5} {'-'*5} {'-'*5} {'-'*5} {'-'*7} {'-'*10}")

    trend_data = []
    for e in entries:
        s = e.get("summary", {})
        ts = e.get("timestamp", "?")[:19]
        mode = e.get("mode_code", "?")
        cat = e.get("category", "?")
        tc = e.get("target_count", 0) or 0
        good = s.get("good", 0)
        bad = s.get("bad", 0)
        na = s.get("na", 0)
        mc = s.get("manual", 0)
        un = _unable_count(s)
        total = good + bad + na + mc + un
        base = total - na
        rate = bad / base if base > 0 else None
        per_host = bad / tc if tc > 0 else None

        rate_s = f"{rate*100:.1f}%" if rate is not None else "-"
        ph_s = f"{per_host:.1f}" if per_host is not None else "-"
        print(f"  {ts:<20} {mode:<5} {cat:<9} {tc:>4} {good:>5} {bad:>5} {na:>5} {mc:>5} {un:>5} {rate_s:>7} {ph_s:>10}")
        trend_data.append({
            "timestamp": ts, "mode": mode, "category": cat,
            "targets": tc, "good": good, "bad": bad, "na": na, "manual": mc, "unable": un,
            "total": total, "rate": rate, "per_host": per_host,
        })

    # 카테고리별 추세
    cats = {}
    for td in trend_data:
        key = f"{td['mode']}_{td['category']}"
        cats.setdefault(key, []).append(td)

    print(f"\n{'='*60}")
    print(f" 카테고리별 추세 변화 (취약률 기준)")
    print(f"{'='*60}")
    for key, items in cats.items():
        if len(items) < 2:
            continue
        first = items[0]
        last = items[-1]
        direction = _rate_dir(first["rate"], last["rate"])
        fr = f"{first['rate']*100:.1f}%" if first["rate"] is not None else "-"
        lr = f"{last['rate']*100:.1f}%" if last["rate"] is not None else "-"
        dl = f"{(last['rate'] - first['rate'])*100:+.1f}%p" if first["rate"] is not None and last["rate"] is not None else "-"
        note = f" (대상 수 {first['targets']}→{last['targets']}대, 비율로 비교)" if first["targets"] != last["targets"] else ""
        print(f"  {key}: 취약률 {fr} → {lr} ({direction}, Δ{dl}) / 취약 {first['bad']}건 → {last['bad']}건{note}")
        if last["unable"] > first["unable"]:
            print(f"    ※ 점검불가 {first['unable']}건 → {last['unable']}건: 취약률이 낮아졌어도 미점검 증가분은 확인 필요")

    # 엑셀 출력
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "추세 데이터"

    headers = ["일시", "기준", "카테고리", "대상 수", "양호", "취약", "N-A", "수동확인", "점검불가", "전체", "취약률", "호스트당 취약"]
    for ci, h in enumerate(headers, 1):
        c = ws.cell(1, ci, h)
        c.font = Font(name=FONT_NAME, size=10, bold=True, color="FFFFFF")
        c.fill = FILL_HEADER
        c.alignment = Alignment(horizontal="center")
        c.border = BD

    for ri, td in enumerate(trend_data, 2):
        vals = [td["timestamp"], td["mode"], td["category"], td["targets"],
                td["good"], td["bad"], td["na"], td["manual"], td["unable"], td["total"],
                td["rate"] if td["rate"] is not None else "-",
                round(td["per_host"], 2) if td["per_host"] is not None else "-"]
        for ci, val in enumerate(vals, 1):
            cell = ws.cell(ri, ci, val)
            cell.font = Font(name=FONT_NAME, size=9)
            cell.border = BD
            if ci == 6 and isinstance(val, int) and val > 0:
                cell.fill = FILL_BAD
            if ci == 9 and isinstance(val, int) and val > 0:
                cell.fill = FILL_UNABLE
            if ci == 11 and isinstance(val, float):
                cell.number_format = "0.0%"

    for ci, w in enumerate([22, 10, 12, 8, 8, 8, 8, 10, 10, 8, 10, 12], 1):
        ws.column_dimensions[openpyxl.utils.get_column_letter(ci)].width = w

    # 카테고리별 요약 시트
    if cats:
        ws2 = wb.create_sheet("카테고리 추세")
        headers2 = ["카테고리", "첫 점검일", "마지막 점검일", "점검 횟수", "첫 대상 수", "현재 대상 수",
                    "첫 취약률", "현재 취약률", "변화(%p)", "방향", "첫 취약", "현재 취약"]
        for ci, h in enumerate(headers2, 1):
            c = ws2.cell(1, ci, h)
            c.font = Font(name=FONT_NAME, size=10, bold=True, color="FFFFFF")
            c.fill = FILL_HEADER
            c.alignment = Alignment(horizontal="center")
            c.border = BD

        ri2 = 2
        for key, items in cats.items():
            first = items[0]
            last = items[-1]
            fr, lr = first["rate"], last["rate"]
            delta = round((lr - fr) * 100, 1) if fr is not None and lr is not None else "-"
            direction = _rate_dir(fr, lr)
            vals = [key, first["timestamp"], last["timestamp"], len(items),
                    first["targets"], last["targets"],
                    fr if fr is not None else "-", lr if lr is not None else "-", delta, direction,
                    first["bad"], last["bad"]]
            for ci, val in enumerate(vals, 1):
                cell = ws2.cell(ri2, ci, val)
                cell.font = Font(name=FONT_NAME, size=9)
                cell.border = BD
                if ci in (7, 8) and isinstance(val, float):
                    cell.number_format = "0.0%"
                if ci == 10:
                    if val == "악화":
                        cell.fill = FILL_BAD
                    elif val == "개선":
                        cell.fill = FILL_GOOD
            ri2 += 1

        for ci, w in enumerate([18, 22, 22, 10, 10, 12, 10, 10, 10, 8, 10, 10], 1):
            ws2.column_dimensions[openpyxl.utils.get_column_letter(ci)].width = w

    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    out_path = os.path.join(os.path.dirname(log_dir.rstrip("/\\")), f"compare_trend_{ts}.xlsx")
    wb.save(out_path)
    print(f"\n[완료] 추세 결과 저장: {out_path}")
    return out_path


# ================================================================
# CLI
# ================================================================
def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(0)

    cmd = sys.argv[1].lower()

    if cmd == "diff":
        if len(sys.argv) < 4:
            print("사용법: python compare_results.py diff <이전.xlsx> <현재.xlsx> [--host HOSTNAME]")
            sys.exit(1)
        prev_path = sys.argv[2]
        curr_path = sys.argv[3]
        host_filter = None
        if "--host" in sys.argv:
            idx = sys.argv.index("--host")
            if idx + 1 < len(sys.argv):
                host_filter = sys.argv[idx + 1]
        run_diff(prev_path, curr_path, host_filter)

    elif cmd == "trend":
        if len(sys.argv) < 3:
            print("사용법: python compare_results.py trend <logs_폴더>")
            sys.exit(1)
        log_dir = sys.argv[2]
        run_trend(log_dir)

    else:
        print(f"[ERROR] 알 수 없는 명령: {cmd}")
        print("  사용 가능: diff, trend")
        sys.exit(1)


if __name__ == "__main__":
    main()
