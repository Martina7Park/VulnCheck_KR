#!/usr/bin/env python3
"""점검 결과·증적 검사 — 항목마다 증적이 제대로 남았는지, 보고서에 그대로 들어갔는지 확인한다.

  python tools/check_evidence.py <결과.txt> [증적.txt] [--xlsx 상세보고서.xlsx] [--all]

증적 파일을 생략하면 결과 파일 이름으로 찾는다(<이름>_evidence.txt, 결과 헤더의 '# 증적 파일:').

검사 항목 (결과에 나온 항목코드마다)
  증적없음   증적에 그 항목의 명령 블록이 하나도 없음
  출력없음   명령 블록은 있으나 출력이 전부 비어 있음 (판정 근거 원자료 부족)
  빈인자     빈 변수로 만든 명령 (for x in ; / ls -l ; / /nonexistent 등)
  잘림       증적 명령이 head·cut·Select-Object -First 등으로 출력을 자름
  판정불일치 결과 줄과 증적 [판정] 줄의 결과값이 다름
  중복출력   결과에 같은 항목코드가 두 번 이상 나옴
  비밀노출   증적에 비밀번호·해시·SNMP community 원문으로 보이는 값
  보고서누락 (--xlsx) 증적 출력 줄이 보고서 어느 셀에도 없음

종료코드: 문제가 없으면 0, 있으면 1. --all 은 문제없는 항목도 표로 출력.
"""
import os, re, sys

CODE = r"[A-Z]{1,4}-\d{2,3}"
BLOCK = re.compile(rf"^\[({CODE})\] \d\d:\d\d:\d\d (?:\$ |PS> |SQL: )?(.*)$")
VERDICT = re.compile(rf"^\[판정\] ({CODE})(?: \([^)]*\))?\|([^|]*)\|")
OTHER_TAG = re.compile(r"^\[(?:판정|참고[^\]]*|평가대상 아님)\]")
RESULT = re.compile(rf"^({CODE})\|([^|]*)\|")

EMPTY_ARG = [
    (re.compile(r"\bfor \w+ in\s*;"), "for 목록이 빔"),
    (re.compile(r"\bls(?: -[a-zA-Z]+)*\s*(?:2>\S*\s*)?(?:;|\||$)"), "ls 대상 경로가 빔"),
    (re.compile(r"/nonexistent"), "대체 경로(/nonexistent) 사용"),
]


def grep_without_file(cmd):
    """파이프 첫 단계의 grep 이 패턴만 있고 파일 인자가 없는 경우 (빈 변수로 만든 명령 → 표준입력 대기)"""
    import shlex
    for seg in re.split(r";|&&|\|\||\$\(|`|\bdo\b|\bthen\b|\belse\b|\{", cmd):
        first = seg.split("|")[0].strip()
        if not first.startswith("grep "):
            continue
        try:
            toks = shlex.split(first)
        except ValueError:
            continue
        toks = [t for t in toks[1:] if not re.match(r"^\d?>|^<", t)]
        args, i = [], 0
        while i < len(toks):
            t = toks[i]
            if t in ("-e", "-f", "-m", "-A", "-B", "-C", "--include", "--exclude"):
                args.append(toks[i + 1] if i + 1 < len(toks) else ""); i += 2; continue
            if not t.startswith("-") or t == "-":
                args.append(t)
            i += 1
        if len(args) <= 1 and "-r" not in first and "-R" not in first:
            return True
    return False
TRUNC = re.compile(r"\|\s*head\s+-|\bhead -c\b|\bcut -c|Select-Object\s+-First|\|\s*tail\s+-\d")
SECRET = [
    (re.compile(r"\$(?:1|2[aby]?|5|6|y|gy|7)\$[^\s:*]{8,}"), "비밀번호 해시"),
    (re.compile(r"(?i)\b(?:ro|rw)community6?\s+(?!\S*\*)\S{3,}"), "SNMP community"),
    (re.compile(r"(?i)\bcom2sec\s+\S+\s+\S+\s+(?!\S*\*)\S{3,}"), "SNMP community"),
    (re.compile(r"(?i)\bsnmp-server community\s+(?!\S*\*)\S{3,}"), "SNMP community"),
    (re.compile(r"(?i)(?:password|passwd|pwd)\s*[=:]\s*(?![\"']?\*)[\"']?[^\s\"'*]{4,}"), "비밀번호 원문"),
    (re.compile(r"\b(?:mysql|mysqldump|mysqladmin|mariadb)\b[^|;]*\s-p(?!\*)\S{4,}"), "명령 인자 비밀번호"),   # mysql -pSECRET (iptables -p tcp 등과 구분)
    (re.compile(r"\bsqlcmd\b[^|;]*\s-P\s+(?!\*)\S{4,}"), "명령 인자 비밀번호"),
]


def read(path):
    with open(path, "rb") as f:
        raw = f.read()
    for enc in (("utf-16",) if raw[:2] in (b"\xff\xfe", b"\xfe\xff") else ()) + ("utf-8-sig", "cp949", "latin-1"):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue


def parse_results(text):
    res, dup = {}, set()
    for line in text.splitlines():
        m = RESULT.match(line.strip())
        if m:
            if m.group(1) in res:
                dup.add(m.group(1))
            res[m.group(1)] = m.group(2).strip()
    return res, dup


def parse_evidence(text):
    blocks, verdicts, cur = {}, {}, None
    for line in text.splitlines():
        m = BLOCK.match(line)
        if m:
            cur = {"cmd": m.group(2), "out": []}
            blocks.setdefault(m.group(1), []).append(cur)
            continue
        v = VERDICT.match(line)
        if v:
            verdicts[v.group(1)] = v.group(2).strip()
            cur = None
            continue
        if OTHER_TAG.match(line):
            cur = None
            continue
        if cur is not None:
            cur["out"].append(line)
    for bl in blocks.values():
        for b in bl:
            while b["out"] and not b["out"][-1].strip():
                b["out"].pop()
    return blocks, verdicts


def find_evidence(result_path, text):
    m = re.search(r"^# 증적 파일:\s*(\S+)", text, re.M)
    cands = [m.group(1)] if m else []
    base = os.path.splitext(result_path)[0]
    cands += [base + "_evidence.txt", os.path.join(os.path.dirname(result_path), os.path.basename(m.group(1)))] if m else [base + "_evidence.txt"]
    for c in cands:
        if c and os.path.isfile(c):
            return c
    return None


def xlsx_text(path):
    import openpyxl
    wb = openpyxl.load_workbook(path, read_only=True, data_only=True)
    parts = []
    for ws in wb.worksheets:
        for row in ws.iter_rows(values_only=True):
            parts.extend(str(v) for v in row if isinstance(v, str))
    wb.close()
    return "\n".join(parts)


def main(argv):
    args = [a for a in argv if not a.startswith("--")]
    show_all = "--all" in argv
    xlsx = argv[argv.index("--xlsx") + 1] if "--xlsx" in argv else None
    if xlsx in args:
        args.remove(xlsx)
    if not args:
        sys.exit(__doc__)
    rpath = args[0]
    rtext = read(rpath)
    epath = args[1] if len(args) > 1 else find_evidence(rpath, rtext)
    if not epath:
        sys.exit(f"[오류] 증적 파일을 찾지 못함 - 두 번째 인자로 지정: {rpath}")
    results, dups = parse_results(rtext)
    blocks, verdicts = parse_evidence(read(epath))
    report = xlsx_text(xlsx) if xlsx else None

    rows, bad = [], 0
    for code, res in results.items():
        issues = []
        bl = blocks.get(code, [])
        if not bl:
            issues.append("증적없음")
        elif all(not any(l.strip() for l in b["out"]) for b in bl) and res != "N-A":
            issues.append("출력없음")
        for b in bl:
            for pat, why in EMPTY_ARG:
                if pat.search(b["cmd"]):
                    issues.append(f"빈인자({why})")
                    break
            if grep_without_file(b["cmd"]):
                issues.append("빈인자(grep 파일 인자가 빔 - 표준입력 대기 가능)")
            if TRUNC.search(b["cmd"]):
                issues.append("잘림")
            for line in b["out"]:
                for pat, why in SECRET:
                    if pat.search(line):
                        issues.append(f"비밀노출({why})")
                        break
        if code in verdicts and verdicts[code] != res:
            issues.append(f"판정불일치(증적 {verdicts[code]})")
        if code in dups:
            issues.append("중복출력")
        if report is not None and bl:
            lines = [l.strip() for b in bl for l in b["out"] if len(l.strip()) >= 4]
            miss = [l for l in lines if l not in report]
            if miss:
                issues.append(f"보고서누락({len(miss)}/{len(lines)}줄)")
        issues = list(dict.fromkeys(issues))
        nout = sum(1 for b in bl for l in b["out"] if l.strip())
        if issues:
            bad += 1
        if issues or show_all:
            rows.append((code, res, len(bl), nout, ", ".join(issues) or "-"))

    print(f"결과: {rpath}\n증적: {epath}" + (f"\n보고서: {xlsx}" if xlsx else ""))
    print(f"항목 {len(results)}개 / 문제 있는 항목 {bad}개")
    if rows:
        print(f"\n{'항목':<9}{'결과':<7}{'블록':>4}{'출력줄':>6}  문제")
        for code, res, nb, no, iss in sorted(rows):
            print(f"{code:<9}{res:<7}{nb:>4}{no:>6}  {iss}")
    return 1 if bad else 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except BrokenPipeError:
        sys.exit(1)
