#!/usr/bin/env python3
# ================================================================
# 전자금융기반시설 / 주요정보통신기반시설
# 통합 취약점 점검 컨버터 v4.1
#
# 기준: 전자금융기반시설 보안 취약점 평가기준 제2026-1호
#       주요정보통신기반시설 기술적 취약점 분석 평가 방법 상세가이드
#
# [사용법]
#   python convert_v4.py
#   → 1. 평가 기반 선택  (1: 전자금융 / 2: 주요정보)
#   → 2. 점검 대상 선택  (1: 서버 / 2: 웹WAS / 3: DBMS / 4: 네트워크 / 5: 보안장비)
#
# [폴더 구조]
#   convert/
#   #── convert_v4.py
#   #── 전자금융기반시설_보안_취약점_평가기준_제2026-1호.xlsx  ← 기준 엑셀
#   #── server/
#   #   #── template.xlsx          ← 결과 기입할 엑셀 (기준 엑셀 복사본)
#   #   #── output/                ← check_server.sh 실행 결과 txt 파일
#   #       #── WEB-PROD-01.txt
#   #       #── DB-PROD-01.txt
#   #── webwas/
#   #   #── template.xlsx
#   #   #── output/
#   #── dbms/
#   #   #── template.xlsx
#   #   #── output/
#   #── network/
#       #── template.xlsx
#       #── config/                ← 네트워크 장비 config 파일 (기존 방식)
#
# [점검 스크립트 출력 형식]
#   항목코드|결과|근거설명
#   SRV-026|양호|PermitRootLogin no
#   SRV-069|취약|PASS_MAX_DAYS=99999 (90일 초과)
#   SRV-026|N-A|해당 없음 (Windows 전용)
#   SRV-xxx|수동확인|직접 확인 필요
# ================================================================

import os, re, sys, datetime, json, hashlib
import openpyxl
from openpyxl import load_workbook
from openpyxl.styles import PatternFill, Font, Alignment, Border, Side
from openpyxl.utils import get_column_letter
from openpyxl.formatting.rule import FormulaRule, CellIsRule
from openpyxl.worksheet.datavalidation import DataValidation
from openpyxl.chart import RadarChart, BarChart, Reference
from openpyxl.chart.label import DataLabelList
from openpyxl.chart.series import SeriesLabel


_XL_ILLEGAL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")   # 엑셀 셀에 쓸 수 없는 제어 문자 (레지스트리 값 등 증적에 섞임)


def read_text(path):
    """결과·증적 파일 읽기 (인코딩 자동 판별, 엑셀 불가 제어 문자 제거)"""
    for enc in ("utf-8-sig", "utf-8", "cp949", "euc-kr", "latin-1"):
        try:
            with open(path, encoding=enc) as f:
                return _XL_ILLEGAL.sub("", f.read())
        except (UnicodeDecodeError, UnicodeError):
            continue
    return _XL_ILLEGAL.sub("", open(path, encoding="latin-1").read())


# ================================================================
# 감사 로그 기록
# ================================================================
def _file_hash(path):
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()[:16]
    except Exception:
        return "N/A"


def write_audit_log(base_dir, mode, category, targets, output_path):
    """
    변환 실행 내역을 logs/ 폴더에 JSON으로 기록.
    targets: [{"name": str, "good": int, "bad": int, "na": int, "manual": int, "input_file": str}, ...]
    """
    log_dir = os.path.join(base_dir, "logs")
    os.makedirs(log_dir, exist_ok=True)

    ts = datetime.datetime.now()
    total_good = sum(t.get("good", 0) for t in targets)
    total_bad  = sum(t.get("bad", 0)  for t in targets)
    total_na   = sum(t.get("na", 0)   for t in targets)
    total_mc   = sum(t.get("manual", 0) for t in targets)
    total_all  = total_good + total_bad + total_na + total_mc

    entry = {
        "version":     VERSION,
        "timestamp":   ts.isoformat(timespec="seconds"),
        "mode":        "전자금융기반시설" if mode == "EF" else "주요정보통신기반시설",
        "mode_code":   mode,
        "category":    category,
        "target_count": len(targets),
        "targets":     targets,
        "summary": {
            "total":   total_all,
            "good":    total_good,
            "bad":     total_bad,
            "na":      total_na,
            "manual":  total_mc,
            "vuln_rate": f"{total_bad/total_all*100:.1f}%" if total_all else "0%",
        },
        "output_file": os.path.basename(output_path) if output_path else None,
        "output_hash": _file_hash(output_path) if output_path and os.path.exists(output_path) else None,
    }

    log_name = f"audit_{category}_{ts.strftime('%Y%m%d_%H%M%S')}.json"
    log_path = os.path.join(log_dir, log_name)
    with open(log_path, "w", encoding="utf-8") as f:
        json.dump(entry, f, ensure_ascii=False, indent=2)
    print(f"[LOG] 감사 로그 저장: {log_path}")
    return log_path


# ── 상수 ──────────────────────────────────────────────────────────
VERSION    = "4.1"
BASE_DATE  = "2026-01-01"   # 제2026-1호 기준일

# 결과값
RESULT_GOOD   = "양호"
RESULT_BAD    = "취약"
RESULT_NA     = "N-A"
RESULT_MANUAL = "수동확인"

# 기준 엑셀 시트명
SHEET_MAP = {
    "server":  "서버",
    "webwas":  "웹서버-WAS",
    "dbms":    "데이터베이스",
    "network": "네트워크 장비",
    "security":"정보보호시스템 장비",
    "pc":      None,   # PC는 기준 엑셀에 시트 없음 → 코드 내장 항목 사용
}

# PC 점검 항목 정의 (기준 엑셀에 없으므로 코드에서 관리)
PC_ITEMS = {
    "PC-01": {"name": "패스워드 설정",                "risk": "상",
              "fix": "모든 계정에 8자 이상의 영문·숫자·특수문자 조합 패스워드를 설정하십시오."},
    "PC-02": {"name": "패스워드 정책",                "risk": "상",
              "fix": "최소 길이 8자 이상, 최대 사용기간 90일 이하, 복잡성 요구사항 활성화, 계정 잠금 임계값 5회 이하로 설정하십시오."},
    "PC-03": {"name": "화면보호기/화면잠금",          "risk": "중",
              "fix": "화면보호기를 10분 이내로 설정하고, 재시작 시 패스워드 보호를 활성화하십시오."},
    "PC-04": {"name": "공유폴더 제거",                "risk": "상",
              "fix": "불필요한 공유폴더를 제거하고, 기본 관리 공유(ADMIN$, C$, D$ 등) 외 불필요한 공유를 비활성화하십시오."},
    "PC-05": {"name": "불필요 서비스 비활성화",       "risk": "중",
              "fix": "사용하지 않는 서비스(Telnet, FTP, Remote Desktop Services 등)를 중지하고 시작 유형을 '사용 안 함'으로 설정하십시오."},
    "PC-06": {"name": "백신 설치 및 실시간 감시",     "risk": "상",
              "fix": "백신 프로그램을 설치하고 실시간 감시 기능을 활성화하며, 최신 엔진으로 업데이트하십시오."},
    "PC-07": {"name": "OS 보안 패치",                 "risk": "상",
              "fix": "Windows Update를 통해 최신 보안 패치를 적용하고, 자동 업데이트를 활성화하십시오."},
    "PC-08": {"name": "방화벽 활성화",                "risk": "상",
              "fix": "Windows 방화벽 또는 개인 방화벽을 활성화하고, 인바운드/아웃바운드 규칙을 적절히 설정하십시오."},
    "PC-09": {"name": "이벤트 로그 관리",             "risk": "중",
              "fix": "보안 이벤트 로그 최대 크기를 10240KB 이상으로 설정하고, 로그 보존 정책을 구성하십시오."},
    "PC-10": {"name": "원격 데스크톱 제한",           "risk": "상",
              "fix": "사용하지 않는 원격 데스크톱(RDP)을 비활성화하거나, NLA(네트워크 수준 인증)를 활성화하십시오."},
    "PC-11": {"name": "자동실행(AutoRun) 비활성화",   "risk": "중",
              "fix": "모든 드라이브에 대해 자동 실행(AutoRun/AutoPlay) 기능을 비활성화하십시오. (NoDriveTypeAutoRun=0xFF)"},
    "PC-12": {"name": "이동매체(USB) 제한",           "risk": "중",
              "fix": "이동식 저장장치(USB)에 대한 접근 제어 정책을 설정하고, 불필요한 경우 사용을 차단하십시오."},
    "PC-13": {"name": "Guest 계정 비활성화",          "risk": "상",
              "fix": "Guest 계정을 비활성화하고, 불필요한 로컬 계정을 제거하십시오."},
    "PC-14": {"name": "UAC/SIP 활성화",               "risk": "상",
              "fix": "사용자 계정 컨트롤(UAC)을 '항상 알림' 또는 '기본' 수준 이상으로 설정하십시오. (EnableLUA=1)"},
    "PC-15": {"name": "브라우저 보안 설정",           "risk": "중",
              "fix": "브라우저 보안 수준을 '보통' 이상으로 설정하고, 팝업 차단 및 SmartScreen 필터를 활성화하십시오."},
    "PC-16": {"name": "로그인 실패 잠금 임계값",      "risk": "상",
              "fix": "계정 잠금 임계값을 5회 이하로 설정하고, 잠금 기간을 30분 이상으로 구성하십시오."},
    "PC-17": {"name": "감사 정책",                    "risk": "중",
              "fix": "로그온 이벤트, 계정 관리, 개체 액세스, 정책 변경 등의 감사 정책을 '성공/실패' 모두 감사하도록 설정하십시오."},
    "PC-18": {"name": "디스크 암호화",                "risk": "중",
              "fix": "BitLocker 또는 동등한 디스크 암호화 솔루션을 적용하여 시스템 드라이브를 암호화하십시오."},
}

# 기준 엑셀 컬럼 인덱스 (0-based)
COL_ID   = 1    # 평가항목ID
COL_NAME = 6    # 평가항목명
COL_RISK = 7    # 위험도
COL_DESC = 8    # 상세설명
COL_EF   = 9    # 평가기반(전자금융) - o이면 해당
COL_MI   = 10   # 평가기반(주요정보) - o이면 해당

# OS별 평가대상 컬럼 (서버/WAS 시트)
OS_COLS_SRV = {
    "AIX":    11,
    "HPUX":   12,
    "LINUX":  13,
    "SOL":    14,
    "WIN":    15,
}
# 웹서버-WAS 시트: 평가대상 열이 6개 더 있음(웹서비스/Apache/WebtoB/IIS/Tomcat/JEUS) → 판단기준 열 위치가 서버 시트와 다름
OS_COLS_WEB = {
    "AIX": 11, "HPUX": 12, "LINUX": 13, "SOL": 14, "WIN": 15,
    "WEBSVC": 16, "APACHE": 17, "WEBTOB": 18, "IIS": 19, "TOMCAT": 20, "JEUS": 21,
}
OS_CRITERIA_WEB = {
    "AIX":   (22, 23),
    "HPUX":  (24, 25),
    "LINUX": (26, 27),
    "SOL":   (28, 29),
    "WIN":   (30, 31),
}
# OS별 판단기준/방법 컬럼 (서버/WAS 시트)
OS_CRITERIA_SRV = {
    "AIX":   (16, 17),   # (기준 col, 방법 col)
    "HPUX":  (18, 19),
    "LINUX": (20, 21),
    "SOL":   (22, 23),
    "WIN":   (24, 25),
}

# DB 벤더별 평가대상 컬럼 (데이터베이스 시트)
DB_COLS = {
    "Oracle":   11,
    "RDS-Oracle":12,
    "MSSQL":    13,
    "RDS-MSSQL":14,
    "MySQL":    15,
    "RDS-MySQL":16,
    "Aurora-MySQL":17,
    "Azure-MySQL":18,
    "MariaDB":  19,
    "RDS-MariaDB":20,
    "PostgreSQL":21,
    "RDS-PgSQL":22,
    "Aurora-PgSQL":23,
    "Azure-PgSQL":24,
    "Tibero":   25,
}
DB_CRITERIA = {
    "Oracle":    (26, 27),
    "RDS-Oracle":(28, 29),
    "MSSQL":     (30, 31),
    "RDS-MSSQL": (32, 33),
    "MySQL":     (34, 35),
    "RDS-MySQL": (36, 37),
    "Aurora-MySQL":(38, 39),
    "Azure-MySQL": (40, 41),
    "MariaDB":   (42, 43),
    "RDS-MariaDB":(44, 45),
    "PostgreSQL":(46, 47),
    "RDS-PgSQL": (48, 49),
    "Aurora-PgSQL":(50, 51),
    "Azure-PgSQL":(52, 53),
    "Tibero":    (54, 55),
}

# 네트워크 장비 그룹 컬럼 (네트워크 장비 시트)
NET_COLS = {
    "SW":      11,
    "RTR":     12,
    "CISCO":   13,
    "A10":     14,
    "ALTEON":  15,
    "JUNIPER": 16,
}
NET_CRITERIA = {
    "GENERIC": (17, 18),
}
# 정보보호시스템 장비 시트: 평가대상 FW/VPN/IDS/IPS/DDoS/WAF(11~16), 판단기준/방법(17/18)
ISS_COLS = {"FW": 11, "VPN": 12, "IDS": 13, "IPS": 14, "DDOS": 15, "WAF": 16}
ISS_CRITERIA = {"GENERIC": (17, 18)}


# ================================================================
# 웹/WAS 항목 분류 체계 (WST 전용)
# ================================================================
WST_CLASSIFY = {
    "OS공통": {
        "WST-019","WST-022","WST-023","WST-024","WST-025","WST-028",
        "WST-029","WST-030","WST-049","WST-050","WST-052","WST-053",
        "WST-054","WST-058","WST-059","WST-060","WST-061","WST-062",
        "WST-064","WST-065","WST-066","WST-067","WST-068","WST-069",
        "WST-075","WST-076","WST-077","WST-078","WST-080","WST-082",
        "WST-083","WST-087","WST-090","WST-091","WST-099","WST-100",
        "WST-101","WST-107","WST-108","WST-109","WST-110","WST-111",
        "WST-112","WST-118","WST-119",
    },
    "네트워크서비스": {
        "WST-001","WST-002",                                                    # SNMP
        "WST-003","WST-004","WST-005","WST-006","WST-007","WST-008","WST-009",  # SMTP
        "WST-010","WST-011","WST-012","WST-018","WST-113","WST-114",            # FTP
        "WST-013","WST-014","WST-015",                                          # NFS/RPC
        "WST-045","WST-046","WST-047","WST-048","WST-116","WST-117",            # DNS
    },
    "Apache": {
        "WST-031","WST-033","WST-034","WST-035","WST-036","WST-037",
        "WST-038","WST-039","WST-044","WST-102","WST-121","WST-122",
        "WST-123","WST-124",
    },
    "Nginx": {
        "WST-031","WST-033","WST-034","WST-035","WST-036","WST-037",
        "WST-038","WST-039","WST-044","WST-102","WST-123","WST-124",
    },
    "WebtoB": {
        "WST-031","WST-033","WST-034","WST-035","WST-036","WST-037",
        "WST-038","WST-039","WST-044","WST-102","WST-124",
    },
    "IIS": {
        "WST-016","WST-017","WST-020","WST-021","WST-026","WST-027",
        "WST-031","WST-032","WST-033","WST-034","WST-035","WST-036",
        "WST-037","WST-038","WST-039","WST-040","WST-041","WST-042",
        "WST-043","WST-044","WST-051","WST-055","WST-056","WST-057",
        "WST-063","WST-070","WST-071","WST-072","WST-073","WST-074",
        "WST-079","WST-081","WST-084","WST-085","WST-086","WST-088",
        "WST-089","WST-094","WST-095","WST-096","WST-097","WST-098",
        "WST-102","WST-103","WST-104","WST-105","WST-106","WST-115",
        "WST-120","WST-121","WST-122","WST-123","WST-124",
    },
    "Tomcat":  {"WST-125","WST-126"},
    "JEUS":    {"WST-126"},
    "Solaris": {"WST-092","WST-093"},
}

# (섹션 레이블, 폰트색, 배경색)
WST_CATEGORY_STYLE = {
    "OS공통":        ("■ OS공통 점검 항목 (AIX / HP-UX / Linux / Solaris 공통)",      "1F3864", "BDD7EE"),
    "네트워크서비스": ("■ 네트워크 서비스 점검 항목 (SNMP / SMTP / FTP / NFS / DNS)",   "375623", "E2EFDA"),
    "Apache":        ("■ 웹서버 전용 점검 항목 (Apache)",                              "7B2D00", "FCE4D6"),
    "Nginx":         ("■ 웹서버 전용 점검 항목 (Nginx)",                               "7B2D00", "FCE4D6"),
    "WebtoB":        ("■ 웹서버 전용 점검 항목 (WebtoB)",                              "7B2D00", "FCE4D6"),
    "IIS":           ("■ 웹서버 전용 점검 항목 (IIS / Windows)",                       "7B2D00", "FCE4D6"),
    "Tomcat":        ("■ WAS 전용 점검 항목 (Tomcat)",                                "1A3A5C", "DAE8FC"),
    "JEUS":          ("■ WAS 전용 점검 항목 (JEUS)",                                  "1A3A5C", "DAE8FC"),
    "Solaris":       ("■ Solaris 전용 점검 항목",                                     "595959", "F2F2F2"),
}


# ================================================================
# 증적 파일 파싱
# ================================================================
def parse_evidence(evd_path):
    """
    *_evidence.txt 파일 파싱 — 항목별 상세 증적 추출
    반환: {"SRV-001": "실행 명령어 및 출력 결과 텍스트", ...}
    블록 시작: [CODE] HH:MM:SS $|PS> 명령 / [CODE] HH:MM:SS 설명 / [CODE] 파일: 경로
    블록 종료: [판정] / [참고-평가기준 외] / [평가대상 아님] / 다른 블록 시작
    REF-(평가기준 외 참고) 블록은 버림
    """
    if not os.path.exists(evd_path):
        return {}
    text = read_text(evd_path)
    evidence = {}
    state = {"code": None, "lines": []}

    def flush():
        c, ls = state["code"], state["lines"]
        if c and ls and not c.startswith("REF-"):
            block = "\n".join(ls)
            prev = evidence.get(c, "")
            evidence[c] = f"{prev}\n{block}" if prev else block
        state["code"], state["lines"] = None, []

    code_re = r'\[((?:REF-)?[A-Z]+-\d+|REF-\d+)\]'
    for line in text.splitlines():
        m = re.match(code_re + r'\s+\d{2}:\d{2}:\d{2}\s+(?:\$|PS>)\s+(.+)', line)
        if m:
            flush(); state["code"] = m.group(1); state["lines"] = [f"$ {m.group(2)}"]
            continue
        m = re.match(code_re + r'\s+파일:\s*(.+)', line)
        if m:
            flush(); state["code"] = m.group(1); state["lines"] = [f"파일: {m.group(2)}"]
            continue
        m = re.match(code_re + r'\s+\d{2}:\d{2}:\d{2}\s+(.+)', line)
        if m:
            flush(); state["code"] = m.group(1); state["lines"] = [f"# {m.group(2)}"]
            continue
        if re.match(r'^\[(판정|참고-평가기준 외|평가대상 아님)\]', line):
            flush()
            continue
        if state["code"] is not None:
            state["lines"].append(line)
    flush()

    for code in evidence:
        evidence[code] = evidence[code].strip()
    return evidence


def find_evidence_file(result_path):
    """결과 파일에 대응하는 증적 파일 탐색"""
    d = os.path.dirname(result_path)
    base = os.path.splitext(os.path.basename(result_path))[0]
    candidates = [
        os.path.join(d, f"{base}_evidence.txt"),
        os.path.join(d, f"{base}_srv_evidence.txt"),
        os.path.join(d, f"{base}_server_evidence.txt"),
        os.path.join(d, f"{base}_webwas_evidence.txt"),
        os.path.join(d, f"{base}_dbms_evidence.txt"),
        os.path.join(d, f"{base}_iss_evidence.txt"),
        os.path.join(d, f"{base}_pc_evidence.txt"),
    ]
    # PC 스크립트: 결과 PC_<호스트>.txt / PC_KISA_<호스트>.txt ↔ 증적 <호스트>_pc(_mac|_kisa)_evidence.txt
    pm = re.match(r"^PC_(KISA_)?(.+)$", base)
    if pm:
        h = pm.group(2)
        candidates += [os.path.join(d, f"{h}_pc_kisa_evidence.txt")] if pm.group(1) else \
                      [os.path.join(d, f"{h}_pc_evidence.txt"), os.path.join(d, f"{h}_pc_mac_evidence.txt")]
    for c in candidates:
        if os.path.exists(c):
            return c
    for f in os.listdir(d):
        if f.startswith(base) and "evidence" in f.lower() and f.endswith(".txt"):
            return os.path.join(d, f)
    # 보안장비 스크립트: 증적 파일명이 점검 대상 설정파일명 기준(<config>_iss_evidence.txt) → 결과 헤더 '# 파일:' 로 탐색
    try:
        head = "\n".join(read_text(result_path).splitlines()[:12])
        m = re.search(r"^#\s*파일\s*:\s*(\S+)", head, re.M)
        if m:
            c = os.path.join(d, f"{m.group(1)}_iss_evidence.txt")
            if os.path.exists(c):
                return c
    except Exception:
        pass
    return None


def _evidence_to_pipe_text(evd_text):
    """
    결과 파일 없이 증적 파일만 있을 때 → 증적 헤더 + [판정] 줄을 파이프 형식 결과 텍스트로 변환
    입력: # 대상: <호스트> / <OS>, # 생성: <일시>, [판정] SRV-001 (항목명)|N-A|사유
    출력: # 점검 대상: / # OS: / # 점검 일시: 헤더 + SRV-001|N-A|사유
    """
    head = "\n".join(evd_text.splitlines()[:8])
    out = []
    m = re.search(r"대상:\s*([^/\n]+?)\s*/\s*(.+)", head)
    if m:
        out += [f"# 점검 대상: {m.group(1).strip()}", f"# OS: {m.group(2).strip()}"]
    m = re.search(r"생성:\s*(.+)", head)
    if m:
        out.append(f"# 점검 일시: {m.group(1).strip()}")
    m = re.search(r"웹서버:\s*([^/\n]+?)\s*/\s*WAS:\s*(.+)", head)
    if m:
        out += [f"# 웹서버: {m.group(1).strip()}", f"# WAS: {m.group(2).strip()}"]
    for line in evd_text.splitlines():
        m = re.match(r"\[판정\]\s*([A-Z]+-\d+)(?:\s*\([^|]*\))?\s*\|(.*)", line)
        if m:
            out.append(f"{m.group(1)}|{m.group(2)}")
    return "\n".join(out)


def _fail_condition(std_text):
    """판단기준 텍스트에서 '취약' 조건 문장 추출 ('* 취약 - …' 또는 '… 경우 "취약"으로 판단' 형식)"""
    if not std_text:
        return ""
    m = re.search(r"(?:^|\n)\s*\*?\s*취약\s*[-:]?\s*(.+?)(?=\n\s*[*※]|\n\s*\(?예외|\Z)", std_text, re.S)
    if not m:
        m = re.search(r"(?:^|\s)\*\s*취약\s*[-:]\s*(.+?)(?=\s\*\s|\Z)", std_text, re.S)
    if m:
        return re.sub(r"\s+", " ", m.group(1)).strip().lstrip("-◦•·* ").strip()
    # '… 시 "취약"으로 판단' 형식: 모든 조건 수집, 앞의 '1) … 경우' 머리줄을 조건 맥락으로 붙임
    conds, ctx = [], ""
    for sent in re.split(r"\n", std_text):
        hm = re.match(r"\s*\d\)\s*(.+?)\s*$", sent)
        if hm and "판단" not in sent:
            ctx = hm.group(1)
            continue
        mm = re.search(r"(.+?)\s*[\"“”']?취약[\"“”']?\s*(?:으로|로)\s*판단", sent)
        if mm:
            cond = re.sub(r"\s+", " ", mm.group(1)).strip().lstrip("-◦•·* ").strip()
            conds.append(f"({ctx}) {cond}" if ctx else cond)
    if conds:
        return " / ".join(conds)
    # '- 조건' 목록만 있는 형식(양호 기준 없음) → 목록 자체가 취약 조건
    if "양호" not in std_text and re.match(r"\s*[-◦•·]\s*\S", std_text):
        body = std_text.split("※")[0]
        items = [x.strip() for x in re.split(r"\n\s*[-◦•·]\s*", "\n" + body) if x.strip()]
        return " / ".join(items)
    return ""


def _condense_evidence(evd_text, max_lines=8, width=60):
    """증적 원문 → 명령/출력 요약 (출력 없는 명령은 '(출력 없음)' 표기)"""
    out, pending_cmd = [], False
    for ln in evd_text.splitlines():
        if not ln.strip() or ln.startswith("[평가대상 아님]"):
            continue
        if ln.startswith(("$ ", "# ", "파일: ")):
            if pending_cmd:
                out.append("  (출력 없음)")
            out.append(ln[:width])
            pending_cmd = True
        else:
            out.append("  " + ln.strip()[:width])
            pending_cmd = False
    if pending_cmd:
        out.append("  (출력 없음)")
    if len(out) > max_lines:
        out = out[:max_lines] + ["  … (이하 생략, 증적 파일 참조)"]
    return "\n".join(out)


def _category_mismatch(res, criteria_items, fname):
    """결과 파일 항목코드가 현재 분야 평가기준과 전혀 겹치지 않으면 True (다른 분야 결과가 섞인 경우)"""
    if not res:
        print(f"[경고] {fname}: 판정 결과 줄(코드|결과|사유)이 없어 제외")
        return True
    hit = sum(1 for c in res if c in criteria_items)
    if hit == 0:
        pfx = sorted({c.split("-")[0] for c in res})
        exp = sorted({c.split("-")[0] for c in criteria_items})
        guide = any(c in KISA_GUIDE_ITEMS for c in res)
        why = ("주요정보(2026 상세가이드) 스크립트 결과 - 평가 기반 '2. 주요정보통신기반시설'에서 변환" if guide
               else "다른 분야 또는 다른 기준의 결과로 판단")
        print(f"[경고] {fname}: 항목코드({','.join(pfx)})가 이 분야 기준({','.join(exp)})과 불일치 → {why}하여 제외" if not guide
              else f"[경고] {fname}: 항목코드({','.join(pfx)})가 전자금융 기준({','.join(exp)})과 불일치 → {why} (제외)")
        return True
    if hit < len(res) * 0.3:
        print(f"[경고] {fname}: 기준과 일치하는 항목 {hit}/{len(res)}개뿐 — 분야 확인 필요")
    return False


def compose_status(res, evidence, criteria_items, sub_key=None):
    """현황 및 문제점 구성: [현황] 판정 사유 / [문제점] 평가기준 취약 조건 / [확인방법] / [증적] 요약"""
    evidence = evidence or {}
    out = {}
    for code, (rv, why) in res.items():
        item = criteria_items.get(code) or {}
        cb_all = item.get("criteria_by") or {}
        cb = cb_all.get(sub_key) or next((v for v in cb_all.values() if v.get("기준")), {})
        if rv == RESULT_NA:
            out[code] = (rv, why)
            continue
        parts = [f"[현황] {why}" if why else "[현황] -"]
        if rv == RESULT_BAD:
            cond = _fail_condition(cb.get("기준", ""))
            if cond:
                parts.append(f"[문제점] {'가이드 판단기준' if item.get('guide') else '평가기준'}상 '{cond}'에 해당하여 취약")
        elif rv == RESULT_MANUAL and item.get("guide"):
            parts.append("[판단기준]\n" + (cb.get("기준") or "").replace("* ", ""))
        elif rv == RESULT_MANUAL:
            ml = [l.rstrip() for l in (cb.get("방법") or "").splitlines() if l.strip()]
            if ml:
                if len(ml) > 6:
                    ml = ml[:6] + ["… (평가기준 판단방법 참조)"]
                parts.append("[확인방법]\n" + "\n".join(ml))
        evd = evidence.get(code, "")
        if evd:
            parts.append("[증적]\n" + _condense_evidence(evd))
        out[code] = (rv, "\n".join(parts) if len(parts) > 1 else (why or ""))
    return out


# ================================================================
# 파이프 출력 파싱
# ================================================================
def parse_pipe(text):
    """
    check_server.sh / check_webwas.sh / check_dbms.sh 출력 파싱
    형식: SRV-026|양호|PermitRootLogin no
    반환: {"SRV-026": ("양호", "PermitRootLogin no"), ...}
    """
    result = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith('#'): continue
        parts = line.split('|', 2)
        if len(parts) < 2: continue
        code_  = parts[0].strip().upper()
        res    = parts[1].strip()
        reason = parts[2].strip() if len(parts) > 2 else ""
        if re.match(r'[A-Z]+-\d+', code_):
            if code_ in result:
                # 같은 항목 중복 출력(구버전 스크립트 등) → 가장 나쁜 결과 우선, 사유 병합 (마지막 줄 우선으로 취약이 가려지는 문제 방지)
                rank = {RESULT_BAD: 4, RESULT_MANUAL: 3, RESULT_GOOD: 2, RESULT_NA: 1}
                pres, preason = result[code_]
                if res != pres:  # 세부 판정이 다르면 판정 표지 부착
                    if not preason.startswith("["):
                        preason = f"[{pres}] {preason}"
                    reason = f"[{res}] {reason}"
                if rank.get(res, 0) > rank.get(pres, 0):
                    result[code_] = (res, f"{reason} / {preason}")
                else:
                    result[code_] = (pres, f"{preason} / {reason}")
            else:
                result[code_] = (res, reason)
    return result


# ================================================================
# 웹/WAS 유형 탐지 및 분류 헬퍼
# ================================================================
def parse_webwas_type(text):
    """점검 결과 파일 헤더에서 웹서버/WAS 유형 자동 탐지"""
    web = "none"; was = "none"; os_fam = "linux"
    for line in text.splitlines()[:30]:
        s  = line.strip().lstrip("#").strip()
        kv = s.split(":", 1)
        if len(kv) < 2:
            continue
        key = kv[0].strip().lower()
        val = kv[1].strip().lower()
        if key in ("웹서버", "웹 서버"):
            if   "apache"  in val: web = "apache"
            elif "nginx"   in val: web = "nginx"
            elif "webtob"  in val: web = "webtob"
            elif "iis"     in val: web = "iis"
        elif key == "was":
            if   "tomcat"  in val: was = "tomcat"
            elif "jeus"    in val: was = "jeus"
        elif key == "os":
            if   "windows" in val: os_fam = "windows"
            elif "solaris" in val or "sunos" in val: os_fam = "solaris"
    if os_fam == "windows" and web == "none":
        web = "iis"
    return {"web": web, "was": was, "os": os_fam}


def get_item_category(code):
    """WST 항목코드의 분류 카테고리 반환"""
    for cat in ("Apache","Nginx","WebtoB","IIS","Tomcat","JEUS",
                "Solaris","OS공통","네트워크서비스"):
        if code.upper() in WST_CLASSIFY.get(cat, set()):
            return cat
    return "기타"


def get_webwas_categories(web_type, was_type, os_fam="linux"):
    """탐지된 웹서버/WAS 유형에 해당하는 카테고리 목록 반환 (출력 순서 포함)"""
    cats = ["OS공통", "네트워크서비스"]
    web_cat = {"apache":"Apache","nginx":"Nginx","webtob":"WebtoB","iis":"IIS"}
    was_cat = {"tomcat":"Tomcat","jeus":"JEUS"}
    if web_type in web_cat:
        cats.append(web_cat[web_type])
    if was_type in was_cat:
        cats.append(was_cat[was_type])
    if os_fam == "solaris":
        cats.append("Solaris")
    return cats


# ================================================================
# 네트워크 점검 로직 (기존 config 파싱 방식 유지)
# ================================================================
def any_m(lines, pattern):
    return any(re.search(pattern, l, re.I) for l in lines)

def fline(lines, pattern):
    for l in lines:
        if re.search(pattern, l, re.I): return l.strip()
    return None

def detect_net_vendor(text):
    # 자유 문구 줄(description·hostname·banner 등)의 단어로 오판하지 않도록 제외
    t = "\n".join(l for l in text.lower().splitlines()
                  if not re.match(r'\s*(description|hostname|sysname|banner|alias|name\s|set system host-name|snmp-server (location|contact))', l))
    if re.search(r'alteon|radware|^/c/sys|^/cfg/sys', t, re.M): return "ALTEON"
    if re.search(r'a10networks|vthunder|\bacos\b|^!version \S+.*build|^slb |^interface management\s*$', t, re.M): return "A10"
    if re.search(r'\bftos\b|dell networking|force10', t):     return "DELL"
    dl = sum(bool(re.search(p, t, re.M)) for p in (
        r'^\s*#.*\b(dgs|des|dxs|dws)-\d', r'^config (ports|terminal_line|safeguard_engine|traffic_control|snmp community)\b',
        r'^create account\b', r'^enable password encryption\b', r'^create vlan\b', r'^config ipif\b'))
    if dl >= 2: return "DLINK"
    if re.search(r'\bjunos\b|^set system |^set interfaces |^system \{|^interfaces \{|^version \S+;\s*$', t, re.M): return "JUNIPER"
    if re.search(r'^\s*sysname |^\s*snmp-agent |^\s*undo |^interface vlanif|^\s*local-user |\bvrp\b|\bcomware\b', t, re.M): return "HUAWEI"  # 가이드 벤더 그룹 미분류
    if re.search(r'^ltm |^sys global-settings|\bbig-?ip\b', t, re.M): return "BIGIP"
    if re.search(r'^add ns |^set ns |\bnetscaler\b', t, re.M): return "CITRIX"
    if re.search(r'\bbrocade\b|\bfastiron\b|\bnetiron\b', t): return "BROCADE"
    if re.search(r'\bpiolink\b|\bpas-k\b', t): return "PIOLINK"
    if re.search(r'^version \d|^line (vty|con)|^interface (gigabit|fastethernet|tengig|ethernet|port-channel|vlan|loopback)|^ip (route|access-list|http)|^snmp-server |^feature |\bios\b|nx-os|^asa version', t, re.M):
        return "CISCO"
    return "UNKNOWN"

def _l3_capable(lines):
    """라우팅 기능 사용 여부: ip routing / 라우팅 프로토콜 / 물리(비 SVI·관리) 인터페이스에 IP 주소 /
    IP 가 설정된 VLAN 인터페이스(SVI) 2개 이상 (VLAN 간 라우팅 — 관리용 SVI 1개만 있으면 L2)"""
    if any_m(lines, r'^\s*ip routing\b|^\s*router\s+(ospf|bgp|eigrp|rip|isis)\b|^\s*ipv6 unicast-routing|^\s*feature interface-vlan\b'):
        return True
    if any(re.match(r'\s*ip route\s+(?!0\.0\.0\.0\s+0\.0\.0\.0)(?!0\.0\.0\.0/0)\S', l, re.I) for l in lines):
        return True
    cur, sw = None, False
    svis = set()
    for l in lines:
        m = re.match(r'^interface\s+(\S+)', l, re.I)
        if m:
            cur, sw = m.group(1), False
            continue
        if cur is None:
            continue
        if re.match(r'^\S', l):
            cur = None; continue
        if re.search(r'^\s*switchport\b', l, re.I):
            sw = True
        if re.search(r'^\s*ip address\s+\d', l, re.I) and re.match(r'vlan', cur, re.I):
            svis.add(cur.lower())
            if len(svis) >= 2:
                return True
        if re.search(r'^\s*ip address\s+\d', l, re.I) and not sw and \
                not re.match(r'(vlan|mgmt|management|loopback|null|tunnel|bvi)', cur, re.I) and \
                not re.match(r'fastethernet0$', cur, re.I):
            return True
    return False


def detect_net_dtype(lines):
    """스위치/라우터 구분 — 스위치 포트가 있으면 SW(라우팅 사용 시 L3SW), 없으면 RTR"""
    if detect_net_vendor("\n".join(lines)) == "DLINK":   # D-Link 관리형 스위치 (DGS/DES/DXS)
        return "L3SW" if any_m(lines, r'^\s*create\s+iproute|^\s*enable\s+(ospf|rip|bgp)\b') else "SW"
    has_sw = any_m(lines, r'switchport|spanning-tree|^\s*vlan\s+\d+')
    if has_sw:
        return "L3SW" if _l3_capable(lines) else "SW"
    return "RTR"

def ok(s): return (RESULT_GOOD, s)
def ng(s): return (RESULT_BAD, s)
def na(s): return (RESULT_NA, s)

def get_vty_blocks(lines):
    blocks = []
    blk = None
    for l in lines:
        l = l.rstrip()
        if l.startswith('!') or (l.strip().startswith('!') and len(l.strip()) == 1):
            if blk is not None: blocks.append(blk); blk = None
            continue
        if re.match(r'\s*line vty', l, re.I):
            if blk is not None: blocks.append(blk)  # FIX: 기존 vty 블록 먼저 저장
            blk = [l.strip()]
        elif blk is not None:
            if re.match(r'\s*line |^\S', l):
                blocks.append(blk); blk = None
                if re.match(r'\s*line vty', l, re.I): blk = [l.strip()]
            else:
                blk.append(l.strip())
    if blk: blocks.append(blk)
    return blocks

def build_dlink_checks(lines, text):
    """
    D-Link 관리형 스위치 (DGS/DES/DXS 시리즈) 점검
    NET-001~NET-059 → {code: (결과, 현황문자열)}
    """
    def any_m(pat, flags=re.I):
        return any(re.search(pat, l, flags) for l in lines)
    def find_lines(pat, flags=re.I):
        return [l.strip() for l in lines if re.search(pat, l, flags)]
    def fline(pat, flags=re.I):
        for l in lines:
            if re.search(pat, l, flags): return l.strip()
        return None
    def ok(s):  return (RESULT_GOOD,   s)
    def ng(s):  return (RESULT_BAD,    s)
    def na(s):  return (RESULT_NA,     s)
    def mc(s):  return (RESULT_MANUAL, s)
    def fmt(actual, criteria, judge):
        return f"[실제값] {actual} [기준] {criteria} [판단] {judge}"

    results = {}

    # NET-001: 백업/복구
    results['NET-001'] = mc(fmt("D-Link config 백업", "설정 백업 절차 수립", "인터뷰 확인"))

    # NET-003: SNMP 버전
    snmp_enabled = any_m(r'enable\s+snmp')
    snmp_disabled = any_m(r'disable\s+snmp')
    snmp_comm = find_lines(r'config\s+snmp\s+community')
    snmp_v3 = any_m(r'config\s+snmp\s+engineID|snmpv3|config\s+snmpv3')

    if snmp_disabled and not snmp_enabled:
        results['NET-003'] = ok(fmt("SNMP 비활성화(disable snmp)", "SNMP 미사용 또는 v3 사용", "SNMP 비활성"))
        results['NET-004'] = na(fmt("SNMP 비활성", "해당 없음", "SNMP 미사용"))
        results['NET-005'] = na(fmt("SNMP 비활성", "해당 없음", "SNMP 미사용"))
        results['NET-006'] = na(fmt("SNMP 비활성", "해당 없음", "SNMP 미사용"))
    elif snmp_v3 and not snmp_comm:
        results['NET-003'] = ok(fmt("SNMPv3 사용", "SNMP v3 인증+암호화", "v3 적용"))
        results['NET-004'] = ok(fmt("SNMPv3 (community 없음)", "RW community 미사용", "양호"))
        results['NET-005'] = ok(fmt("SNMPv3", "v3 접근통제", "양호"))
        results['NET-006'] = mc(fmt("SNMPv3 접근 제한", "관리망 한정 SNMP", "수동 확인"))
    elif snmp_comm:
        pub_priv = [l for l in snmp_comm if re.search(r'"public"|"private"', l, re.I)]
        rw_comm = [l for l in snmp_comm if re.search(r'read_write', l, re.I)]
        if pub_priv:
            results['NET-003'] = ng(fmt(f"기본 community: {pub_priv[0][:80]}", "public/private 미사용", "기본 community 사용"))
        else:
            # 평가기준 복잡도: 2종 10자 이상 / 3종 8자 이상 (보고서 표기는 마스킹)
            weak_c = []
            for l in snmp_comm:
                m = re.search(r'community\s+"?([^"\s]+)"?', l, re.I)
                if not m: continue
                cs = m.group(1); cls = sum(bool(re.search(p, cs)) for p in (r'[A-Za-z]', r'\d', r'[^A-Za-z0-9]'))
                if not ((cls >= 2 and len(cs) >= 10) or (cls >= 3 and len(cs) >= 8)):
                    weak_c.append(f"{cs[:2]}{'*' * max(0, len(cs) - 2)}({len(cs)}자)")
            results['NET-003'] = ng(fmt(f"복잡도 미달 community: {', '.join(weak_c[:3])}", "2종 10자 / 3종 8자 이상", "community 복잡도 미달")) if weak_c else \
                mc(fmt(f"SNMPv1/v2c community {len(snmp_comm)}개 (복잡도 충족)", "SNMP v3 사용 가능한 환경에서 v2 이용 시 취약", "v3 사용 가능 환경인지 확인"))
        results['NET-004'] = ng(fmt(f"RW community: {rw_comm[0][:80]}", "RW 미사용", "RW 제거 필요")) if rw_comm else ok(fmt("RO community만 사용", "RW 미사용", "양호"))
        results['NET-005'] = mc(fmt("D-Link SNMP ACL", "접근 IP 제한", "trusted-host 설정 수동 확인"))
        results['NET-006'] = mc(fmt("SNMP 활성", "외부 인터페이스 차단", "수동 확인"))
    else:
        results['NET-003'] = ok(fmt("SNMP community 미설정", "SNMP 미사용 시 양호", "SNMP 미사용"))
        results['NET-004'] = na(fmt("SNMP 미사용", "해당 없음", "N-A"))
        results['NET-005'] = na(fmt("SNMP 미사용", "해당 없음", "N-A"))
        results['NET-006'] = na(fmt("SNMP 미사용", "해당 없음", "N-A"))

    # NET-007: 로컬 계정
    accounts = find_lines(r'create\s+account\s+\S+\s+\S+')
    if accounts:
        names = [re.search(r'create\s+account\s+\S+\s+(\S+)', a, re.I).group(1) for a in accounts if re.search(r'create\s+account\s+\S+\s+(\S+)', a, re.I)]
        results['NET-007'] = mc(fmt(f"로컬 계정 {len(names)}개: {', '.join(names[:5])}", "운영자 1인 1계정, 계정별 권한 적정", "1인 1계정·권한(admin) 적정성 인터뷰 확인"))
    else:
        results['NET-007'] = ng(fmt("create account 미발견", "Local 사용자 설정", "Local 사용자 미설정"))

    # NET-008: AAA
    radius = find_lines(r'config\s+radius|config\s+authentication')
    tacacs = find_lines(r'config\s+tacacs')
    if radius or tacacs:
        results['NET-008'] = ok(fmt(f"인증서버: {(radius+tacacs)[0][:60]}", "외부 인증(RADIUS/TACACS)", "인증서버 연동됨"))
    else:
        results['NET-008'] = mc(fmt("RADIUS/TACACS 설정 없음", "외부 인증서버 연동", "로컬 인증 사용 - 수동 확인"))

    # NET-009: 비밀번호 미설정
    pw_enc = any_m(r'enable\s+password[_\s]+encryption')
    results['NET-009'] = mc(fmt(f"password encryption={'활성' if pw_enc else '미설정'}", "모든 계정 비밀번호 설정", "수동 확인"))

    # NET-010: enable secret (D-Link는 admin 권한 체계 사용)
    results['NET-010'] = mc(fmt("D-Link admin/operator/user 권한 체계", "관리자 비밀번호 암호화", f"password encryption={'활성' if pw_enc else '미설정'}"))

    # NET-011: SSH v2
    # 평가기준: 사용자·관리자 비밀번호 암호화 여부 및 알고리즘 강도 (SSH 는 NET-015)
    ssh_enabled = any_m(r'enable\s+ssh')
    if pw_enc:
        results['NET-011'] = mc(fmt("enable password encryption 설정", "비밀번호 암호화 + 안전한 알고리즘", "암호화 적용 - 저장 알고리즘(펌웨어별) 보안강도 확인"))
    else:
        results['NET-011'] = ng(fmt("enable password encryption 미설정", "비밀번호 암호화 설정", "비밀번호 평문 저장"))

    # NET-014: 세션 타임아웃
    auto_logout = fline(r'config\s+terminal_line\s+\S+\s+auto_logout\s+\d+')
    if auto_logout:
        m = re.search(r'auto_logout\s+(\d+)', auto_logout, re.I)
        mins = int(m.group(1)) if m else 0
        if 0 < mins <= 15:
            results['NET-014'] = ok(fmt(f"auto_logout {mins}분", "15분 이하 타임아웃", f"{mins}분 설정"))
        elif mins == 0:
            results['NET-014'] = ng(fmt("auto_logout 0(무제한)", "15분 이하 설정", "타임아웃 미설정"))
        else:
            results['NET-014'] = ng(fmt(f"auto_logout {mins}분", "15분 이하", f"{mins}분 - 기준 초과"))
    else:
        results['NET-014'] = mc(fmt("auto_logout 설정 미발견", "세션 타임아웃 설정", "수동 확인"))

    # NET-015: Telnet 차단
    telnet_disabled = any_m(r'disable\s+telnet')
    telnet_enabled = any_m(r'enable\s+telnet')
    if telnet_disabled and not telnet_enabled:
        results['NET-015'] = ok(fmt("Telnet 비활성(disable telnet)", "Telnet 차단, SSH 전용", "Telnet 차단됨"))
    elif ssh_enabled and not telnet_enabled:
        results['NET-015'] = ok(fmt("SSH 활성, Telnet 미활성화", "SSH 전용", "Telnet 미사용"))
    elif telnet_enabled:
        results['NET-015'] = ng(fmt("Telnet 활성", "disable telnet + enable ssh", "평문 접속 허용"))
    else:
        results['NET-015'] = mc(fmt("Telnet 상태 확인 불가", "SSH 전용 사용", "수동 확인"))

    # NET-016: AUX (D-Link 스위치는 AUX 포트 없음)
    results['NET-016'] = na(fmt("D-Link 스위치 AUX 포트 없음", "AUX 비활성화", "해당 없음"))

    # NET-030: 불필요 서비스
    svc_en = []
    if any_m(r'enable\s+telnet'):   svc_en.append("Telnet")
    if any_m(r'enable\s+dhcp_relay|config\s+dhcp_relay'): svc_en.append("DHCP_Relay")
    if any_m(r'config\s+snmp\s+community.*public|config\s+snmp\s+community.*private'):
        svc_en.append("SNMP(기본community)")
    if any_m(r'enable\s+web\b|config\s+web\b'):  svc_en.append("Web관리")

    if svc_en:
        results['NET-030'] = ng(fmt(f"활성 불필요 서비스: {', '.join(svc_en)}", "불필요 서비스 비활성화", f"{len(svc_en)}개 비활성화 필요"))
    else:
        results['NET-030'] = ok(fmt("불필요 서비스 미발견", "주요 서비스 비활성화", "양호"))

    # NET-031: NTP/SNTP
    sntp = find_lines(r'config\s+sntp\s+primary|config\s+sntp\s+secondary|config\s+ntp')
    if sntp:
        results['NET-031'] = ok(fmt(f"SNTP: {sntp[0][:60]}", "시간 동기화 설정", "SNTP 설정됨"))
    else:
        results['NET-031'] = ng(fmt("SNTP 미설정", "config sntp primary [IP]", "시간 동기화 없음"))

    # NET-033: 로깅
    syslog_enabled = any_m(r'enable\s+syslog')
    syslog_host = find_lines(r'config\s+syslog\s+host\s+\d+\s+ipaddress')
    if syslog_enabled or syslog_host:
        results['NET-033'] = ok(fmt(f"syslog {'활성' if syslog_enabled else ''} {syslog_host[0][:60] if syslog_host else ''}", "로깅 활성화", "로깅 설정됨"))
    else:
        results['NET-033'] = ng(fmt("syslog 미설정", "enable syslog + config syslog host", "로깅 미설정"))

    # NET-034: 타임스탬프
    results['NET-034'] = mc(fmt("D-Link syslog 타임스탬프", "로그 시간 기록", "SNTP 설정 시 자동 포함 - 수동 확인"))

    # NET-035: 로그 버퍼
    results['NET-035'] = mc(fmt("D-Link 내장 로그 버퍼", "로그 버퍼 크기", "수동 확인"))

    # NET-036: 원격 로그서버
    if syslog_host:
        results['NET-036'] = ok(fmt(f"원격 syslog: {syslog_host[0][:60]}", "원격 로그서버 설정", "외부 전송 설정됨"))
    else:
        results['NET-036'] = ng(fmt("syslog host 미설정", "원격 syslog 서버 설정", "로그 외부 전송 없음"))

    # NET-037: 콘솔 로깅
    results['NET-037'] = mc(fmt("D-Link 콘솔 로그", "콘솔 로그 레벨", "수동 확인"))

    # NET-048: 보안패치
    results['NET-048'] = mc(fmt("D-Link 펌웨어 버전", "벤더 최신 펌웨어", "show switch 또는 show firmware 수동 확인"))

    # NET-050: 배너
    results['NET-050'] = mc(fmt("D-Link 로그인 배너", "무단 접근 경고 배너", "수동 확인"))

    # NET-051: TCP keepalive (D-Link N-A)
    results['NET-051'] = na(fmt("D-Link 스위치 TCP keepalive 해당 없음", "TCP keepalive", "L2/L3 스위치 N-A"))

    # NET-052: 미사용 인터페이스
    disabled_ports = find_lines(r'config\s+ports?\s+[\d,-]+\s+.*state\s+disable')
    all_ports = find_lines(r'config\s+ports?\s+[\d,-]+')
    if disabled_ports:
        results['NET-052'] = mc(fmt(f"비활성 포트 설정 {len(disabled_ports)}건 발견", "미사용 인터페이스 shutdown", "포트 상태 수동 확인"))
    else:
        results['NET-052'] = mc(fmt(f"config ports 설정 {len(all_ports)}건", "미사용 포트 비활성화", "전체 포트 상태 수동 확인"))

    # NET-054: 스위치 보안
    missing_54 = []; found_54 = []
    if any_m(r'config\s+port_security'):
        found_54.append("port_security")
    else:
        missing_54.append("port_security")
    if any_m(r'config\s+traffic_control|config\s+storm_control'):
        found_54.append("traffic_control/storm_control")
    else:
        missing_54.append("traffic_control")
    if any_m(r'config\s+loopback_detection'):
        found_54.append("loopback_detection")
    else:
        missing_54.append("loopback_detection")
    if any_m(r'config\s+filter\s+dhcp_server|config\s+dhcp_snooping'):
        found_54.append("dhcp_snooping/filter")
    if any_m(r'config\s+safeguard_engine'):
        found_54.append("safeguard_engine")
    if any_m(r'config\s+stp\s+.*fbpdu\s+enable|bpdu'):
        found_54.append("bpdu_protection")

    summary = f"설정: {', '.join(found_54) if found_54 else '없음'} | 미설정: {', '.join(missing_54) if missing_54 else '없음'}"
    # 평가기준: 포트 보안 미설정 시 취약 (traffic_control·loopback_detection 등은 참고)
    if "port_security" in found_54:
        results['NET-054'] = ok(fmt(summary, "스위치 포트 보안 설정", "포트 보안 설정됨"))
    else:
        results['NET-054'] = ng(fmt(summary, "스위치 포트 보안 설정", "포트 보안(port_security) 미설정"))

    # NET-056: 비밀번호 변경 주기
    results['NET-056'] = mc(fmt("비밀번호 변경 이력", "정기적 변경", "인터뷰 확인"))

    # NET-057: 취약 서비스
    # 평가기준 목록: CDP, LLDP, TFTP, Finger, identd, Smart Install (Telnet/HTTP 는 NET-015/030)
    weak = []
    if any_m(r'^\s*enable\s+lldp\b'): weak.append("LLDP")
    if weak:
        results['NET-057'] = ng(fmt(f"활성 취약 서비스: {', '.join(weak)}", "CDP/LLDP/TFTP/Finger/identd/Smart Install 비활성화", f"{len(weak)}개 비활성화 필요"))
    else:
        results['NET-057'] = ok(fmt("LLDP 등 기준 취약 서비스 미사용", "CDP/LLDP/TFTP/Finger/identd/Smart Install 비활성화", "양호"))

    # NET-058: 계정 잠금
    login_attempt = fline(r'config\s+admin\s+.*login_attempt|config\s+authentication.*attempt')
    if login_attempt:
        results['NET-058'] = ok(fmt(f"{login_attempt[:60]}", "로그인 실패 차단", "설정됨"))
    else:
        results['NET-058'] = mc(fmt("로그인 실패 차단 설정 미발견", "로그인 실패 횟수 제한", "수동 확인"))

    # NET-012: 비밀번호 복잡도 (D-Link는 자체 복잡도 정책 미지원)
    results['NET-012'] = mc(fmt("D-Link 자체 비밀번호 복잡도 정책 없음", "비밀번호 영문+숫자+특수 8자 이상", "운영 정책 수동 확인"))

    # NET-013: 접근 IP 제한 (D-Link trusted host / access_profile)
    trusted_host = find_lines(r'config\s+admin\s+.*trusted_host|config\s+trusted_host')
    access_prof = find_lines(r'config\s+access_profile')
    if trusted_host:
        results['NET-013'] = ok(fmt(f"trusted_host: {trusted_host[0][:60]}", "관리 접근 IP 제한", "접근 IP 제한 설정됨"))
    elif access_prof:
        results['NET-013'] = mc(fmt(f"access_profile {len(access_prof)}건", "관리 접근 IP 제한", "관리용 ACL 여부 수동 확인"))
    else:
        results['NET-013'] = ng(fmt("접근 IP 제한 설정 없음", "trusted_host 설정", "비인가 IP 접근 가능"))

    # NET-022: IP Source Routing (L2 스위치 해당 없음)
    if any_m(r'config\s+route\s+.*source|ip\s+source.?route'):
        results['NET-022'] = ng(fmt("source routing 관련 설정 발견", "IP source routing 차단", "source routing 비활성화 필요"))
    else:
        results['NET-022'] = na(fmt("D-Link L2/L3 스위치 source routing 해당 없음", "IP source routing 차단", "해당 없음"))

    # NET-026: Proxy ARP
    if any_m(r'proxy.?arp|ip\s+proxy'):
        results['NET-026'] = ng(fmt("Proxy ARP 관련 설정 발견", "Proxy ARP 비활성화", "비활성화 필요"))
    else:
        results['NET-026'] = na(fmt("D-Link 스위치 Proxy ARP 해당 없음", "Proxy ARP 비활성화", "해당 없음"))

    # NET-027: Directed Broadcast
    if any_m(r'directed.?broadcast'):
        results['NET-027'] = ng(fmt("directed broadcast 관련 설정 발견", "Directed Broadcast 차단", "비활성화 필요"))
    else:
        results['NET-027'] = na(fmt("D-Link 스위치 Directed Broadcast 해당 없음", "Directed Broadcast 차단", "해당 없음"))

    # NET-038~040: ACL 필터링
    acl_profile = find_lines(r'create\s+access_profile|config\s+access_profile')
    acl_rule = find_lines(r'config\s+access_rule')
    if acl_profile or acl_rule:
        acl_count = len(acl_profile) + len(acl_rule)
        results['NET-038'] = mc(fmt(f"access_profile/rule {acl_count}건", "표준 ACL 적용", "ACL 규칙 적정성 수동 확인"))
        results['NET-039'] = mc(fmt(f"access_profile/rule {acl_count}건", "확장 ACL 적용", "ACL 규칙 적정성 수동 확인"))
        results['NET-040'] = mc(fmt(f"access_profile/rule {acl_count}건", "VTY ACL 적용", "관리 접근용 ACL 수동 확인"))
    else:
        results['NET-038'] = ng(fmt("ACL(access_profile) 미설정", "표준 ACL 적용", "ACL 미설정"))
        results['NET-039'] = ng(fmt("ACL(access_profile) 미설정", "확장 ACL 적용", "ACL 미설정"))
        results['NET-040'] = mc(fmt("ACL 미설정 (trusted_host 대체 가능)", "VTY 접근제한", "수동 확인"))

    # NET-041: Multicast (IGMP snooping)
    igmp = any_m(r'config\s+igmp_snooping|enable\s+igmp_snooping')
    if igmp:
        results['NET-041'] = ok(fmt("IGMP snooping 설정됨", "멀티캐스트 제어", "IGMP snooping 적용"))
    else:
        results['NET-041'] = mc(fmt("IGMP snooping 미설정", "멀티캐스트 제어", "수동 확인"))

    # NET-042~046: ICMP 관련 (L2 스위치 해당 없음)
    results['NET-042'] = na(fmt("D-Link L2 스위치 ICMP 차단 해당 없음", "ICMP 차단", "해당 없음"))
    results['NET-043'] = na(fmt("D-Link L2 스위치 ICMP redirect 해당 없음", "ICMP Redirect 차단", "해당 없음"))
    results['NET-044'] = na(fmt("D-Link L2 스위치 ICMP unreachable 해당 없음", "ICMP Unreachable 차단", "해당 없음"))
    results['NET-045'] = na(fmt("D-Link L2 스위치 ICMP mask-reply 해당 없음", "ICMP Mask Reply 차단", "해당 없음"))
    results['NET-046'] = na(fmt("D-Link L2 스위치 ICMP Timestamp/Information 해당 없음", "ICMP Timestamp 차단", "해당 없음"))

    # NET-047: DDoS 방어 (safeguard_engine / dos_prevention)
    dos_prevention = any_m(r'config\s+dos_prevention|enable\s+dos_prevention')
    safeguard = any_m(r'config\s+safeguard_engine|enable\s+safeguard_engine')
    if dos_prevention or safeguard:
        found_dos = []
        if dos_prevention: found_dos.append("dos_prevention")
        if safeguard: found_dos.append("safeguard_engine")
        results['NET-047'] = ok(fmt(f"DDoS 방어: {', '.join(found_dos)}", "DDoS 방어 설정", "설정됨"))
    else:
        results['NET-047'] = ng(fmt("DoS prevention/safeguard 미설정", "config dos_prevention / safeguard_engine", "DDoS 방어 미설정"))

    # NET-049: 명령어 권한 수준
    admin_acc = find_lines(r'create\s+account\s+admin\b')
    oper_acc = find_lines(r'create\s+account\s+operator\b')
    user_acc = find_lines(r'create\s+account\s+user\b')
    priv_info = f"admin={len(admin_acc)}, operator={len(oper_acc)}, user={len(user_acc)}"
    if admin_acc and (oper_acc or user_acc):
        results['NET-049'] = ok(fmt(f"권한 분리: {priv_info}", "명령어 권한 수준 분리", "역할별 계정 설정됨"))
    else:
        results['NET-049'] = mc(fmt(f"계정: {priv_info}", "명령어 권한 수준 분리", "권한 분리 수동 확인"))

    # NET-059: EoS
    results['NET-059'] = mc(fmt("D-Link 장비 펌웨어/모델", "EoL/EoS 기준 지원 중인 장비 사용", "벤더 EoL 대조 수동 확인"))

    return results


def build_net_checks(lines, text):
    """
    다중 벤더 네트워크 장비 점검
    Cisco IOS/IOS-XE / ASA / Juniper JunOS / Alteon / Dell FTOS / D-Link
    NET-001~NET-059 → {code: (결과, 현황문자열)}
    """
    vendor = detect_net_vendor(text)

    if vendor == "DLINK":
        return build_dlink_checks(lines, text)

    dtype  = detect_net_dtype(lines)

    def any_m(pat, flags=re.I):
        return any(re.search(pat, l, flags) for l in lines)
    def find_lines(pat, flags=re.I):
        return [l.strip() for l in lines if re.search(pat, l, flags)]
    def fline(pat, flags=re.I):
        for l in lines:
            if re.search(pat, l, flags): return l.strip()
        return None
    def ok(s):  return (RESULT_GOOD,   s)
    def ng(s):  return (RESULT_BAD,    s)
    def na(s):  return (RESULT_NA,     s)
    def mc(s):  return (RESULT_MANUAL, s)

    def fmt(actual, criteria, judge):
        return f"[실제값] {actual} [기준] {criteria} [판단] {judge}"

    # ── 벤더별 인터페이스 목록 ──────────────────────────────────
    # interface Name + shutdown 여부
    def get_interfaces():
        ifaces = []
        cur_if = None
        for l in lines:
            m = re.match(r'\s*interface\s+(\S+)', l, re.I)
            if m:
                if cur_if: ifaces.append(cur_if)
                cur_if = {"name": m.group(1), "shutdown": False, "has_ip": False, "switchport": False}
            elif cur_if:
                if re.search(r'^\s*shutdown', l, re.I):  cur_if["shutdown"] = True
                if re.search(r'ip address', l, re.I):    cur_if["has_ip"] = True
                if re.search(r'switchport', l, re.I):    cur_if["switchport"] = True
                if re.match(r'^[a-z!]', l, re.I) and not l.startswith(' '):
                    ifaces.append(cur_if); cur_if = None
        if cur_if: ifaces.append(cur_if)
        return ifaces

    def acl_entries(name):
        """번호/이름 ACL 의 permit·deny 항목 목록 (정의 없으면 None)"""
        out, found, in_named = [], False, False
        for l in lines:
            s = l.strip()
            m = re.match(r'access-list\s+(\S+)\s+(permit|deny)\s+(.*)$', s, re.I)
            if m and m.group(1) == name:
                found = True; out.append((m.group(2).lower(), m.group(3))); continue
            m = re.match(r'ip access-list\s+(standard|extended)\s+(\S+)', s, re.I)
            if m:
                in_named = (m.group(2) == name); found = found or in_named; continue
            if in_named:
                if re.match(r'^\S', l):
                    in_named = False; continue
                m = re.match(r'(?:\d+\s+)?(permit|deny)\s+(.*)$', s, re.I)
                if m: out.append((m.group(1).lower(), m.group(2)))
        return out if found else None

    def acl_host_only(entries):
        """standard ACL permit 이 단일 IP(host x / x / x 0.0.0.0)만인지 → (bool, 문제 항목)"""
        wide = []
        for act, rest in entries:
            if act != "permit": continue
            r = rest.split()
            if not r: continue
            if r[0].lower() == "any" or (len(r) > 1 and r[0].lower() not in ("host",) and re.match(r'\d', r[0]) and r[1] not in ("0.0.0.0",) and re.match(r'\d+\.\d+\.\d+\.\d+$', r[1])):
                wide.append(f"permit {rest}")
            elif r[0].lower() in ("ip", "tcp", "udp", "icmp"):
                return None, [f"permit {rest}"]   # extended ACL — 단일 IP 여부 수동 확인
        return (not wide), wide

    ifaces = get_interfaces()
    has_sw_port  = any(i["switchport"] for i in ifaces)
    has_ip_intf  = any(i["has_ip"] for i in ifaces)
    # 순수 L2 스위치: switchport 있고 ip routing 없고 L3 인터페이스 없음
    is_pure_l2   = dtype == "SW"   # 관리 SVI IP 만 있는 스위치 포함
    # 라우터 전용 항목 체크 함수
    def rtr_only(code_str, actual, criteria, judge):
        if is_pure_l2:
            return na(fmt(f"L2 스위치 - {code_str} 해당 없음", criteria, "L2 스위치는 라우팅 항목 N-A"))
        return None

    results = {}

    # ──────────────────────────────────────────────────────────────
    # NET-001: 백업/복구 절차 수립
    # ──────────────────────────────────────────────────────────────
    results['NET-001'] = mc(fmt(
        "설정 백업 이력 및 NMS 구성",
        "장비 설정 정기 백업 절차 수립",
        "인터뷰 및 실사를 통해 백업 주기·보관 현황 확인 필요"
    ))

    # ──────────────────────────────────────────────────────────────
    # NET-003: SNMP 버전
    # ──────────────────────────────────────────────────────────────
    has_comm  = find_lines(r'snmp-server community\s+\S+|/c/cfg/sys/ssnmp')
    has_v3    = any_m(r'snmp-server.*version 3|snmp-server group.*v3|snmpv3')
    pub_priv  = find_lines(r'snmp-server community\s+(public|private)\b')
    v3_groups = find_lines(r'snmp-server group\s+\S+\s+v3\s+\S+')
    v3_weak   = [g for g in v3_groups if not re.search(r'\sv3\s+priv\b', g, re.I)]
    if v3_weak:
        results['NET-003'] = ng(fmt(f"SNMPv3 보안레벨 AuthPriv 미적용: {v3_weak[0]}", "SNMP v3 사용 시 보안레벨 AuthPriv(priv)",
                                    "SNMPv3 auth/noauth 그룹 존재 - priv 적용 필요"))
    elif has_v3 and not has_comm:
        results['NET-003'] = ok(fmt(
            f"SNMP v3 전용 사용 ({fline(r'snmp-server group.*v3')})",
            "SNMP v3 사용 시 보안레벨 AuthPriv",
            "SNMP v3 priv 적용됨"
        ))
    elif pub_priv:
        results['NET-003'] = ng(fmt(
            f"기본 community 사용: {pub_priv[0]}",
            "public/private community 미사용",
            "기본 community 사용 - 즉시 변경 필요"
        ))
    elif has_comm:
        # 평가기준 복잡도: 영문+숫자 10자 이상 또는 영문+숫자+특수문자 8자 이상 (암호화된 문자열은 판정 불가)
        weak_c, ok_c, unk = [], [], []
        for ln in has_comm:
            m = re.search(r'snmp-server community\s+(?:\d\s+)?(\S+)', ln, re.I)
            if not m:
                unk.append(ln.strip()); continue
            cs = m.group(1)
            if re.search(r'community\s+[0-9]\s+\S+', ln, re.I):
                unk.append(f"{cs[:4]}…(암호화)"); continue
            has_a, has_d = bool(re.search(r'[A-Za-z]', cs)), bool(re.search(r'\d', cs))
            has_s = bool(re.search(r'[^A-Za-z0-9]', cs))
            good = has_a and has_d and (len(cs) >= 10 or (has_s and len(cs) >= 8))
            masked = cs[:2] + "*" * max(0, len(cs) - 2)
            (ok_c if good else weak_c).append(f"{masked}({len(cs)}자)")
        if weak_c:
            results['NET-003'] = ng(fmt(f"복잡도 미달 community: {', '.join(weak_c[:3])}",
                                        "영문+숫자 10자 이상 또는 영문+숫자+특수 8자 이상 (v3 권고)", "community 복잡도 미달"))
        elif unk:
            results['NET-003'] = mc(fmt(f"community 확인 불가: {', '.join(unk[:3])}", "community 복잡도", "수동 확인"))
        else:
            results['NET-003'] = mc(fmt(f"v2c community 복잡도 충족: {', '.join(ok_c[:3])}",
                                        "SNMP v3 사용 가능한 환경에서 v2 이용 시 취약",
                                        "복잡도 충족 - SNMPv3 사용 가능 환경인지 확인 (가능하면 취약)"))
    else:
        results['NET-003'] = ok(fmt("SNMP 미사용 (snmp-server 설정 없음)", "SNMP 미사용 시 양호", "SNMP 미사용 확인됨"))

    # NET-004: SNMP community 권한
    rw_comm = find_lines(r'snmp-server community\s+\S+\s+RW')
    if rw_comm:
        results['NET-004'] = ng(fmt(
            f"RW community: {rw_comm[0]}",
            "SNMP RW(쓰기) community 미사용",
            f"RW community {len(rw_comm)}개 설정 - 제거 필요"
        ))
    elif has_v3 and not has_comm:
        results['NET-004'] = ok(fmt("SNMP v3 사용 (community 없음)", "RW community 미사용", "RW community 없음"))
    elif has_comm:
        results['NET-004'] = ok(fmt(
            f"RO community만 사용: {has_comm[0]}",
            "RW community 미사용",
            "RO community만 설정됨"
        ))
    else:
        results['NET-004'] = na(fmt("SNMP 미사용", "해당 없음", "SNMP 미사용"))

    # NET-005: SNMP ACL
    if has_comm or v3_groups:
        # 평가기준: ACL 미적용 또는 단일 IP 단위가 아니면(예: 10.10.10.0/25) 취약
        no_acl, acl_refs = [], []
        for ln in has_comm:
            m = re.search(r'snmp-server community\s+(?:\d\s+)?\S+(?:\s+view\s+\S+)?\s+(?:RO|RW)\s+(?:ipv6\s+\S+\s+)?(\S+)\s*$', ln, re.I)
            (acl_refs.append((ln, m.group(1))) if m else no_acl.append(ln))
        for g in v3_groups:
            m = re.search(r'\saccess\s+(?:ipv6\s+\S+\s+)?(\S+)', g, re.I)
            (acl_refs.append((g, m.group(1))) if m else no_acl.append(g))
        wide, unknown, okl = [], [], []
        for ln, acl in acl_refs:
            ent = acl_entries(acl)
            if ent is None:
                unknown.append(acl); continue
            good, w = acl_host_only(ent)
            if good is None: unknown.append(f"{acl}(extended)")
            else: (okl.append(acl) if good else wide.append(f"ACL {acl}: {w[0]}"))
        if no_acl:
            results['NET-005'] = ng(fmt(f"ACL 미적용: {no_acl[0]}", "SNMP ACL 을 단일 IP 단위로 적용", f"ACL 없는 SNMP 설정 {len(no_acl)}건"))
        elif wide:
            results['NET-005'] = ng(fmt("; ".join(wide[:3]), "SNMP ACL 을 단일 IP 단위로 적용 (예: 10.10.10.0/25 취약)", "대역·any 허용 ACL"))
        elif unknown:
            results['NET-005'] = mc(fmt(f"참조 ACL 정의 없음: {', '.join(unknown)}", "SNMP ACL 단일 IP", "ACL 정의·허용 IP 수동 확인"))
        else:
            results['NET-005'] = ok(fmt(f"단일 IP ACL 적용: {', '.join(okl)}", "SNMP ACL 단일 IP", "SNMP 접근 IP 단일 호스트로 제한됨 (불필요 IP 여부 확인)"))
    else:
        results['NET-005'] = na(fmt("SNMP 미사용", "해당 없음", "SNMP 미사용"))

    # NET-006: 외부 인터페이스 SNMP 차단
    vrf_only = any_m(r'snmp-server host.*vrf\s+\S+.*version 3') and not has_comm
    acl_deny_snmp = any_m(r'deny.*udp.*161|deny.*snmp')
    if vrf_only:
        results['NET-006'] = ok(fmt("VRF Mgmt 전용 SNMP v3 호스트 설정 (관리망 분리)", "관리망 한정 SNMP 허용", "외부 SNMP 접근 차단됨"))
    elif acl_deny_snmp:
        results['NET-006'] = ok(fmt("외부 SNMP 차단 ACL 적용됨", "외부 인터페이스 SNMP 차단 ACL", "외부 SNMP 차단 확인됨"))
    else:
        snmp_hosts = find_lines(r'snmp-server host\s+\S+')
        host_str = ", ".join(snmp_hosts[:3]) if snmp_hosts else "없음"
        results['NET-006'] = mc(fmt(
            f"SNMP 호스트: {host_str}",
            "외부 인터페이스 SNMP 차단 ACL 또는 관리망 분리",
            "외부 인터페이스 적용 여부 수동 확인"
        ))

    # ──────────────────────────────────────────────────────────────
    # NET-007: 로컬 사용자 계정 관리 (다시)
    # ──────────────────────────────────────────────────────────────
    if vendor == "JUNIPER":
        users = find_lines(r'set system login user\s+\S+')
    elif vendor == "ALTEON":
        users = find_lines(r'/c/sys/access/user|username\s+\S+')
    else:
        users = find_lines(r'^\s*username\s+\S+')

    if users:
        # 계정별 권한/타입 요약
        user_summary = []
        for u in users[:5]:
            name_m = re.search(r'username\s+(\S+)', u, re.I)
            priv_m = re.search(r'privilege\s+(\d+)', u, re.I)
            type_m = re.search(r'secret\s+(\d+)|password\s+(\d+)', u, re.I)
            if name_m:
                name = name_m.group(1)
                priv = f"priv{priv_m.group(1)}" if priv_m else ""
                stype = f"secret-type{type_m.group(1) or type_m.group(2)}" if type_m else ""
                user_summary.append(f"{name}({priv}{stype})")
        summary = ", ".join(user_summary) if user_summary else users[0][:60]
        results['NET-007'] = mc(fmt(
            f"로컬 계정 {len(users)}개: {summary}",
            "운영자 1인 1계정, 계정별 권한 적정(모니터링 계정에 관리자 권한 금지)",
            f"로컬 계정 {len(users)}개 - 1인 1계정·권한(privilege 15) 적정성 인터뷰 확인"
        ))
    else:
        results['NET-007'] = ng(fmt(
            "로컬 계정(username) 미발견",
            "Local 사용자 설정",
            "Local 사용자 미설정"
        ))

    # NET-008: AAA
    aaa_new = any_m(r'aaa new-model')
    tacacs  = find_lines(r'tacacs server\s+\S+|tacacs-server host\s+\S+')
    radius  = find_lines(r'radius server\s+\S+|radius-server host\s+\S+')
    if aaa_new and (tacacs or radius):
        srv = (tacacs + radius)[0]
        results['NET-008'] = ok(fmt(
            f"aaa new-model + {'TACACS' if tacacs else 'RADIUS'}: {srv}",
            "AAA + 외부 인증서버(TACACS/RADIUS)",
            "중앙 집중 인증 적용됨"
        ))
    elif aaa_new and any_m(r'^\s*aaa authentication login\s+\S+\s+(?!none\b)\S'):
        results['NET-008'] = ok(fmt(
            "aaa new-model + " + (fline(r'^\s*aaa authentication login') or "") + ", 외부 인증서버 없음",
            "AAA 인증 설정 또는 별도 인증서버",
            "AAA 인증 설정됨 (로컬 DB 인증)"
        ))
    elif aaa_new:
        results['NET-008'] = mc(fmt(
            "aaa new-model 만 설정 (aaa authentication login 미설정 - 기본 로컬 인증)",
            "AAA 인증 설정 또는 별도 인증서버",
            "AAA 인증 방식 수동 확인"
        ))
    else:
        results['NET-008'] = ng(fmt(
            "aaa new-model 미설정",
            "AAA 인증 체계 적용",
            "AAA 미사용 - 중앙 인증 미적용"
        ))

    # ──────────────────────────────────────────────────────────────
    # NET-009: 비밀번호 미설정 계정 (다시)
    # ──────────────────────────────────────────────────────────────
    # Cisco: username xxx (password/secret 없음), username xxx nopassword
    # ASA: username xxx nopassword
    # 패스워드 없는 패턴들
    no_pw_patterns = [
        r'username\s+\S+\s+nopassword',
        r'username\s+\S+\s+privilege\s+\d+\s*$',  # privilege만 있고 password 없음
        r'username\s+\S+\s*$',                      # username만 있음
    ]
    no_pw_lines = []
    for pat in no_pw_patterns:
        no_pw_lines += find_lines(pat)
    # 실제 secret/password 있는 줄 제외
    no_pw_lines = [l for l in no_pw_lines if not re.search(r'secret|password\s+\d?\s*\S{3,}', l, re.I)]

    all_user_lines = find_lines(r'^\s*username\s+')
    has_pw_lines   = [l for l in all_user_lines if re.search(r'secret|password', l, re.I)]
    # D-Link 등은 'username X password ..' 와 'username X privilege N' 을 별도 줄로 저장 → 다른 줄에 비밀번호가 있으면 제외
    pw_users = {m.group(1) for l in has_pw_lines for m in [re.match(r'\s*username\s+(\S+)', l, re.I)] if m}
    no_pw_lines = [l for l in no_pw_lines
                   if not (re.match(r'\s*username\s+(\S+)', l, re.I) and re.match(r'\s*username\s+(\S+)', l, re.I).group(1) in pw_users)]
    # D-Link DGS-3630: 라인에 인증 방식 미지정 + AAA default 목록 없음 → 로컬 계정 DB 로 로그인 인증 (CLI Reference R2.25 aaa authentication login)
    _brand, _model, _ = _net_brand(text)
    dlink_local_auth = _brand == "D-LINK" and "DGS-3630" in (_model or "").upper() and bool(pw_users)

    def line_blocks(kind):
        blks, cur = [], None
        for l in lines:
            if re.match(r'^line\s+' + kind, l, re.I):
                if cur: blks.append(cur)
                cur = [l.strip()]
            elif cur is not None:
                if re.match(r'^\S', l):
                    blks.append(cur); cur = None
                    if re.match(r'^line\s+' + kind, l, re.I): cur = [l.strip()]
                else:
                    cur.append(l.strip())
        if cur: blks.append(cur)
        return blks
    aaa_default = any_m(r'^\s*aaa new-model') and any_m(r'^\s*aaa authentication login default\s+(?!none\b)\S')
    line_nopw = []
    for kind in ("con", "aux", "vty"):
        for b in line_blocks(kind):
            s = " ".join(b)
            if re.search(r'transport input none|no exec\b', s, re.I): continue
            if not (re.search(r'\bpassword\s+\S|login local|login authentication', s, re.I) or aaa_default or dlink_local_auth):
                line_nopw.append(b[0])
    pw_vals = [re.search(r'(?:secret|password)\s+(?:\d\s+)?(\S+)\s*$', l, re.I) for l in find_lines(r'(secret|password)\s+(\d\s+)?\S+\s*$')]
    pw_vals = [m.group(1) for m in pw_vals if m]
    dup_pw = len(pw_vals) != len(set(pw_vals))
    if no_pw_lines or line_nopw:
        results['NET-009'] = ng(fmt(
            f"비밀번호 미설정: {', '.join((no_pw_lines + line_nopw)[:4])}",
            "계정·모드(enable/console/aux/vty)별 비밀번호 설정",
            f"비밀번호 미설정 {len(no_pw_lines) + len(line_nopw)}건"
        ))
    elif dup_pw:
        results['NET-009'] = ng(fmt("동일한 비밀번호(해시) 값이 여러 계정·모드에 사용됨", "계정·모드별 서로 다른 비밀번호", "중복 비밀번호 사용"))
    elif False:
        results['NET-009'] = ng(fmt(
            f"비밀번호 미설정 계정: {no_pw_lines[0][:80]}",
            "모든 계정 비밀번호 설정 필수",
            f"{len(no_pw_lines)}개 계정 비밀번호 없음 - 즉시 설정 필요"
        ))
    elif not all_user_lines:
        results['NET-009'] = mc(fmt(
            "로컬 계정 없음",
            "계정 존재 시 비밀번호 필수",
            "로컬 계정 없음 - AAA 사용 여부 확인"
        ))
    else:
        results['NET-009'] = mc(fmt(
            f"계정 {len(all_user_lines)}개·Line 모두 비밀번호(인증) 설정",
            "계정·모드별 비밀번호 설정 및 중복 사용 금지",
            "미설정 없음 - 해시 salt 로 중복 여부 판정 불가, 사용자·관리자 비밀번호 중복 인터뷰 확인"
        ))

    # NET-010: enable secret
    es = fline(r'enable secret')
    ep = fline(r'enable password')
    if not es and not ep:
        results['NET-010'] = ng(fmt("enable secret/password 미설정", "enable secret 설정 필수", "enable 접근 무인증 - 즉시 설정 필요"))
    elif ep and not es:
        results['NET-010'] = ng(fmt(f"{ep}", "enable password 대신 enable secret 사용", "enable password(평문/DES) 취약 - enable secret으로 교체 필요"))
    elif es:
        # 평가기준 NET-010: enable 비밀번호 암호화(enable secret) 여부만 판단 — 알고리즘 강도는 NET-011
        results['NET-010'] = ok(fmt(f"{es}", "enable secret 설정", "enable 비밀번호 암호화(enable secret) 설정됨"))

    # NET-011: 사용자·관리자 비밀번호 암호화 및 알고리즘 강도 (type 0=평문, 7=가역, 5=MD5, 4=취약 SHA256 → 취약 / 8·9 → 양호)
    weak, strong = [], []
    type_name = {0: "평문", 7: "type7(가역)", 5: "type5(MD5)", 4: "type4(취약 SHA256)", 8: "type8(PBKDF2)", 9: "type9(scrypt)"}
    for ln in find_lines(r'^\s*(username\s+\S+.*\s(secret|password)\s|enable\s+(secret|password)\s)'):
        m = re.search(r'\b(secret|password)\s+(\d)\s+\S', ln, re.I)
        kind = (m.group(1).lower() if m else re.search(r'\b(secret|password)\b', ln, re.I).group(1).lower())
        t = int(m.group(2)) if m else (5 if kind == "secret" else 0)
        who = re.sub(r'\s+(secret|password)\s+.*$', '', ln.strip(), flags=re.I)
        (strong if t in (8, 9) else weak).append(f"{who}: {type_name.get(t, f'type{t}')}")
    pw_enc = any_m(r'^\s*service password-encryption')
    if weak:
        results['NET-011'] = ng(fmt("; ".join(weak[:5]), "비밀번호 안전한 알고리즘(type 8/9) 암호화",
                                    f"평문 또는 보안강도 낮은 알고리즘 {len(weak)}건"
                                    + ("" if pw_enc else " / service password-encryption 미설정")))
    elif strong:
        results['NET-011'] = ok(fmt("; ".join(strong[:5]), "비밀번호 안전한 알고리즘(type 8/9) 암호화", "모든 비밀번호 type 8/9 적용"))
    elif vendor in ("JUNIPER", "ASA"):
        results['NET-011'] = mc(fmt(f"{vendor} 비밀번호 저장 방식", "안전한 암호 알고리즘", "비밀번호 해시 알고리즘 수동 확인"))
    else:
        results['NET-011'] = mc(fmt("로컬 비밀번호 설정 미발견 (AAA 서버 인증 등)", "안전한 암호 알고리즘", "인증 서버 측 비밀번호 저장 방식 수동 확인"))

    # NET-012: 비밀번호 복잡도
    minlen = fline(r'security passwords min-length\s+\d+')
    if minlen:
        n = re.search(r'\d+', minlen)
        nv = int(n.group()) if n else 0
        # 평가기준: 복잡성 준수·유추 가능 여부는 비밀번호 복호화(크랙)로 확인 → 설정만으로 양호 판정 불가
        results['NET-012'] = mc(fmt(f"{minlen}", "영문·숫자·특수문자 혼합 8자 이상", f"최소 {nv}자 정책 - 실제 비밀번호 복잡성(크랙) 확인 필요")) if nv >= 8 else ng(fmt(f"{minlen}", "8자 이상 필요", f"최소 {nv}자 - 8자 이상 설정 필요"))
    else:
        results['NET-012'] = mc(fmt("security passwords min-length 미설정", "비밀번호 복잡도 정책 적용", "복잡도 설정 수동 확인 (AAA 서버 정책 포함)"))

    # NET-013: VTY ACL
    vty_blocks = get_vty_blocks(lines)
    if not vty_blocks:
        results['NET-013'] = mc(fmt("VTY 설정 없음", "VTY 접근 ACL 적용", "VTY 미설정 - SSH 접근 경로 수동 확인"))
    else:
        acl_lines = []
        no_acl_vtys = []
        for blk in vty_blocks:
            blk_str = " ".join(blk)
            if re.search(r'transport input none', blk_str, re.I):
                continue
            acl_m = re.search(r'access-class\s+(\S+)\s+in', blk_str, re.I)
            if acl_m:
                acl_lines.append(f"{blk[0]}: access-class {acl_m.group(1)} in")
            else:
                no_acl_vtys.append(blk[0])
        if no_acl_vtys:
            results['NET-013'] = ng(fmt(
                f"ACL 미적용 VTY: {', '.join(no_acl_vtys)}",
                "모든 활성 VTY에 access-class [ACL] in 설정",
                f"VTY ACL 없음 - 모든 IP에서 원격 접근 가능"
            ))
        elif acl_lines:
            any_acl, unk_acl = [], []
            for al in acl_lines:
                nm = re.search(r'access-class\s+(\S+)', al).group(1)
                ent = acl_entries(nm)
                if ent is None: unk_acl.append(nm)
                elif any(a == "permit" and re.match(r'(ip\s+|tcp\s+)?any\b', r, re.I) for a, r in ent): any_acl.append(nm)
            if any_acl:
                results['NET-013'] = ng(fmt(f"VTY ACL 에 permit any: {', '.join(any_acl)}", "지정된 최소한의 IP 만 허용", "모든 IP 허용 ACL"))
            elif unk_acl:
                results['NET-013'] = mc(fmt(f"{'; '.join(acl_lines)} (ACL 정의 없음: {', '.join(unk_acl)})", "VTY ACL 최소 IP", "ACL 정의·허용 IP 수동 확인"))
            else:
                results['NET-013'] = ok(fmt(
                    f"{'; '.join(acl_lines)}",
                    "VTY에 접근 ACL 적용 (지정된 최소한의 IP)",
                    f"{len(acl_lines)}개 VTY 그룹 ACL 적용됨 - 허가 IP 적정성 확인"
                ))
        else:
            results['NET-013'] = ok(fmt("모든 VTY transport input none (접속 차단)", "VTY 접근 통제", "VTY 전체 차단됨"))

    # NET-014: 세션 타임아웃 — 평가기준 '모든 Line' (console·aux·vty)
    vty_blocks = line_blocks("con") + line_blocks("aux") + get_vty_blocks(lines)
    if not vty_blocks:
        results['NET-014'] = mc(fmt("VTY 없음", "세션 타임아웃 설정", "수동 확인"))
    else:
        timeout_issues = []; timeout_ok = []
        for blk in vty_blocks:
            blk_str = " ".join(blk)
            if re.search(r'transport input none', blk_str, re.I): continue
            mt = re.search(r'exec-timeout\s+(\d+)\s*(\d*)', blk_str, re.I)
            if mt:
                mins = int(mt.group(1)); secs = int(mt.group(2)) if mt.group(2) else 0
                total = mins*60+secs
                if total == 0:
                    timeout_issues.append(f"{blk[0]}: exec-timeout 0 0 (무제한)")
                elif total <= 900:
                    timeout_ok.append(f"{blk[0]}: exec-timeout {mins}분{secs}초")
                else:
                    timeout_issues.append(f"{blk[0]}: exec-timeout {total}초 ({total//60}분)")
            else:
                timeout_ok.append(f"{blk[0]}: exec-timeout 미설정(IOS 기본 10분)")
        if timeout_issues:
            results['NET-014'] = ng(fmt(
                f"타임아웃 미흡: {'; '.join(timeout_issues)}",
                "세션 타임아웃 15분(900초) 이하 (내부 규정이 더 짧으면 그 기준)",
                f"타임아웃 초과/미설정 VTY 존재"
            ))
        elif timeout_ok:
            results['NET-014'] = ok(fmt(
                f"{'; '.join(timeout_ok)}",
                "세션 타임아웃 15분 이하",
                f"모든 VTY 타임아웃 기준 충족"
            ))
        else:
            results['NET-014'] = ok(fmt("모든 VTY transport input none", "세션 타임아웃 설정", "VTY 차단됨"))

    # NET-015: Telnet 차단
    vty_blocks = get_vty_blocks(lines)
    if vendor in ("ALTEON",):
        ssh_on = any_m(r'^\s*sshd\s+(ena|on)\b')
        tnet_on = any_m(r'^\s*tnet\s+(ena|on)\b|telnet\s+(on|enable)')
        if tnet_on: results['NET-015'] = ng(fmt("Alteon tnet ena (Telnet 허용)", "암호화 프로토콜(SSH)만 허용", "Telnet 평문 접속 허용"))
        elif ssh_on: results['NET-015'] = ok(fmt("Alteon sshd ena, tnet 비활성", "SSH 전용", "SSH 전용 접속"))
        else: results['NET-015'] = mc(fmt("Alteon 원격 접속 설정 미확인", "SSH 전용", "원격 관리 프로토콜 수동 확인"))
    elif any_m(r'^feature \S') and not any_m(r'transport input'):   # NX-OS: VTY transport 명령 없음, Telnet 은 feature telnet 으로 활성
        results['NET-015'] = ng(fmt("feature telnet 활성", "SSH 전용 (no feature telnet)", "Telnet 평문 접속 허용")) if any_m(r'^feature telnet\b') \
            else ok(fmt(f"NX-OS feature telnet 미사용{' / feature ssh' if any_m(r'^feature ssh') else ''}", "SSH 전용", "Telnet 비활성 (NX-OS 기본)"))
    elif not vty_blocks:
        results['NET-015'] = mc(fmt("VTY 없음", "VTY transport input ssh", "수동 확인"))
    else:
        all_none = all(re.search(r'transport input none', " ".join(b), re.I) for b in vty_blocks)
        if all_none:
            results['NET-015'] = na(fmt("모든 VTY transport input none (접속 불가)", "Telnet 미허용", "VTY 전체 차단됨"))
        else:
            bad_vtys = []; good_vtys = []
            for blk in vty_blocks:
                blk_str = " ".join(blk)
                if re.search(r'transport input none', blk_str, re.I): continue
                _ti = re.search(r'transport input\s+([^;]*?)(?=\s+(?:transport|exec-timeout|login|password|access-class|privilege|logging|history|session|line)\b|$)', blk_str, re.I)
                if _ti and re.search(r'\b(telnet|all|rlogin)\b', _ti.group(1), re.I):
                    ti = next((l.strip() for l in blk if re.search(r'transport input', l, re.I)), None); bad_vtys.append(f"{blk[0]}: {ti or 'transport input 미설정'}")
                elif re.search(r'transport input ssh', blk_str, re.I):
                    good_vtys.append(blk[0])
                elif not re.search(r'transport input', blk_str, re.I):
                    bad_vtys.append(f"{blk[0]}: transport input 미설정 (기본=모두 허용)")
            if bad_vtys:
                results['NET-015'] = ng(fmt(f"Telnet 허용 VTY: {'; '.join(bad_vtys)}", "transport input ssh 전용", "Telnet 평문 허용 - 패스워드 노출 위험"))
            else:
                results['NET-015'] = ok(fmt(f"SSH 전용 VTY: {', '.join(good_vtys)}", "transport input ssh", "SSH 전용 설정됨"))

    # NET-016: AUX 포트 차단
    aux_lines = []
    in_aux = False
    for l in lines:
        if re.match(r'\s*line aux', l, re.I): in_aux = True; aux_lines = [l.strip()]
        elif in_aux:
            if re.match(r'^\S', l): in_aux = False
            else: aux_lines.append(l.strip())
    if not aux_lines:
        results['NET-016'] = na(fmt("AUX 포트 설정 없음", "AUX 포트 비활성화", "AUX 미설정 (차단으로 간주)"))
    else:
        aux_str = "; ".join(aux_lines[:4])
        if re.search(r'no exec|transport input none', " ".join(aux_lines), re.I):
            results['NET-016'] = ok(fmt(f"line aux: {aux_str}", "AUX 포트 no exec 또는 transport input none", "AUX 포트 차단됨"))
        else:
            results['NET-016'] = ng(fmt(f"line aux: {aux_str}", "transport input none 또는 no exec 설정", "AUX 포트 미차단 - 무인증 접근 가능"))

    # NET-022: source routing (라우터만 해당)
    if is_pure_l2:
        results['NET-022'] = na(fmt("L2 스위치", "라우터 해당 항목", "L2 스위치 N-A"))
    elif any_m(r'no ip source-route'):
        results['NET-022'] = ok(fmt("no ip source-route 설정됨", "no ip source-route 설정", "IP 소스라우팅 차단됨"))
    else:
        results['NET-022'] = ng(fmt("no ip source-route 미설정 (기본 활성)", "no ip source-route 명시 설정", "IP 소스라우팅 허용 - 경로 우회 공격 위험"))

    # NET-026: Proxy ARP
    no_proxy = find_lines(r'no ip proxy-arp')
    real_ip = [i for i in ifaces if i["has_ip"] and "Loopback" not in i["name"]]
    if not real_ip:
        results['NET-026'] = na(fmt("IP 라우팅 인터페이스 없음", "Proxy ARP 비활성화", "라우팅 없음"))
    elif len(no_proxy) >= len(real_ip):
        results['NET-026'] = ok(fmt(f"no ip proxy-arp: {len(no_proxy)}개 인터페이스", "모든 인터페이스 Proxy ARP 비활성", "Proxy ARP 전체 차단됨"))
    elif no_proxy:
        results['NET-026'] = ng(fmt(f"no ip proxy-arp {len(no_proxy)}개 / 전체 IP 인터페이스 {len(real_ip)}개", "no ip proxy-arp 설정 (인터페이스별)", f"{len(real_ip) - len(no_proxy)}개 인터페이스 Proxy ARP 허용"))
    else:
        results['NET-026'] = ng(fmt(f"no ip proxy-arp 미설정 (IP 인터페이스 {len(real_ip)}개)", "no ip proxy-arp 전체 설정", "Proxy ARP 허용 - ARP 스푸핑 위험"))

    # NET-027: Directed Broadcast (라우터만 해당)
    no_db = find_lines(r'no ip directed-broadcast')
    if is_pure_l2:
        results['NET-027'] = na(fmt("L2 스위치 - 라우팅 없음", "라우터 해당 항목", "L2 스위치 N-A"))
    elif find_lines(r'^\s*ip directed-broadcast'):
        _db_on = len(find_lines(r'^\s*ip directed-broadcast'))
        results['NET-027'] = ng(fmt(f"ip directed-broadcast 활성: {_db_on}개 인터페이스", "no ip directed-broadcast", "Directed Broadcast 허용 - Smurf 공격 취약"))
    elif no_db:
        results['NET-027'] = ok(fmt(f"no ip directed-broadcast: {len(no_db)}개 인터페이스", "no ip directed-broadcast 설정", "Directed Broadcast 차단됨"))
    else:
        # 평가기준: IOS 11 이하만 점검, IOS 12부터 기본 Disable
        _iv = re.search(r'^\s*version\s+(\d+)', text, re.M)
        if _iv and int(_iv.group(1)) >= 12:
            results['NET-027'] = ok(fmt(f"IOS {_iv.group(1)}.x - 기본 Disable (명시적 활성 설정 없음)", "IOS 12 이상 기본 차단", "Directed Broadcast 비활성(기본값)"))
        elif _iv:
            results['NET-027'] = ng(fmt(f"IOS {_iv.group(1)}.x, no ip directed-broadcast 미설정", "no ip directed-broadcast 설정", "Directed Broadcast 허용 - Smurf 공격 취약"))
        else:
            results['NET-027'] = mc(fmt("IOS 버전 미확인, no ip directed-broadcast 미설정", "IOS 11 이하 시 차단 설정", "IOS 버전 확인 필요"))

    # ──────────────────────────────────────────────────────────────
    # NET-030: 불필요 서비스 비활성화
    # 점검 기준 명시 항목:
    #   SNMP(v1/v2c), 웹(HTTP), TCP/UDP small servers, BOOTP, DHCP,
    #   Domain lookup, PAD, named, postfix, radvd 등
    svc_enabled = []
    svc_disabled = []
    svc_detail  = {}

    if vendor not in ("JUNIPER", "ALTEON"):
        # 1. TCP/UDP small servers
        for sname, pat in [
            ("tcp-small-servers", r"^\s*service tcp-small-server"),
            ("udp-small-servers", r"^\s*service udp-small-server"),
        ]:
            if any_m(pat):
                svc_enabled.append(sname); svc_detail[sname] = fline(pat) or sname
            else:
                svc_disabled.append(sname)

        # 2. SNMP (v1/v2c community 사용 = 불필요/위험 서비스)
        snmp_pub  = find_lines(r"snmp-server community\s+(public|private)")
        snmp_v12  = find_lines(r"snmp-server community\s+\S+")
        snmp_v3   = any_m(r"snmp-server.*version 3|snmp-server group.*v3")
        if snmp_pub:
            svc_enabled.append("SNMP(기본community)")
            svc_detail["SNMP(기본community)"] = snmp_pub[0]
        elif snmp_v12 and not snmp_v3:
            svc_enabled.append("SNMP(v1/v2c)")
            svc_detail["SNMP(v1/v2c)"] = snmp_v12[0]
        else:
            svc_disabled.append("SNMP(v3또는미사용)")

        # 3. 웹서비스 HTTP
        if any_m(r"^\s*ip http serve"):
            svc_enabled.append("HTTP서버")
            svc_detail["HTTP서버"] = fline(r"ip http server") or "ip http server"
        else:
            svc_disabled.append("HTTP서버")

        # HTTPS - ACL 없으면 취약
        if any_m(r"^\s*ip http secure-serve") and not any_m(r"ip http access-class"):
            svc_enabled.append("HTTPS서버(ACL없음)")
            svc_detail["HTTPS서버(ACL없음)"] = fline(r"ip http secure-server") or "ip http secure-server"

        # 4. BOOTP 서버
        if any_m(r"^\s*ip bootp serve"):
            svc_enabled.append("BOOTP서버")
            svc_detail["BOOTP서버"] = fline(r"ip bootp server") or "ip bootp server"
        else:
            svc_disabled.append("BOOTP서버")

        # 5. DHCP 서버
        if (any_m(r"^\s*service dhc") or any_m(r"ip dhcp pool")) and not any_m(r"no service dhcp"):
            svc_enabled.append("DHCP서버")
            svc_detail["DHCP서버"] = fline(r"ip dhcp pool") or "dhcp pool 설정됨"
        else:
            svc_disabled.append("DHCP서버")

        # 6. Domain lookup (기본 활성 - 명시 비활성화 없으면 취약)
        if not any_m(r"no ip domain.?lookup|no ip domain lookup"):
            svc_enabled.append("Domain-lookup")
            svc_detail["Domain-lookup"] = "no ip domain-lookup 미설정 (기본 활성화 상태)"
        else:
            l = fline(r"no ip domain.?lookup")
            svc_disabled.append(f"Domain-lookup(비활성:{l})")

        # 7. PAD
        if any_m(r"^\s*service pa"):
            svc_enabled.append("PAD")
            svc_detail["PAD"] = fline(r"service pad") or "service pad"
        else:
            svc_disabled.append("PAD")

        # 8. Finger
        if any_m(r"^\s*service finge|^\s*ip finge"):
            svc_enabled.append("Finger")
            svc_detail["Finger"] = fline(r"service finger|ip finger") or "finger"
        else:
            svc_disabled.append("Finger")


    elif vendor == "JUNIPER":
        for sname, pat in [
            ("Telnet",    r"set system services telnet"),
            ("HTTP",      r"set system services web-management htt"),
            ("FTP",       r"set system services ftp"),
            ("SNMP-v1v2", r"set snmp community"),
        ]:
            if any_m(pat):
                svc_enabled.append(sname); svc_detail[sname] = fline(pat) or sname
            else:
                svc_disabled.append(sname)

    elif vendor == "ALTEON":
        for sname, pat in [
            ("Telnet",    r"^\s*tnet\s+(ena|on)\b|telnet\s+(on|enable)"),
            ("SNMP-v1v2", r"^\s*(rcomm|wcomm)\s|snmp.*community"),
        ]:
            if any_m(pat):
                svc_enabled.append(sname); svc_detail[sname] = fline(pat) or sname
            else:
                svc_disabled.append(sname)

    if svc_enabled:
        detail_str = "; ".join(
            f"{k}: {svc_detail.get(k,'')[:35]}" for k in svc_enabled
        )[:200]
        results['NET-030'] = ng(fmt(
            f"활성 불필요 서비스 {len(svc_enabled)}개 - {detail_str}",
            "SNMP-v1v2/HTTP/TCP-UDP-small/BOOTP/DHCP/Domain-lookup/PAD/named/postfix/radvd 비활성화",
            f"비활성화 필요: {', '.join(svc_enabled)}"
        ))
    else:
        results['NET-030'] = ok(fmt(
            f"불필요 서비스 미발견 (비활성 확인: {', '.join(svc_disabled[:6])})",
            "주요 불필요 서비스 전체 비활성화",
            "기준 명시 서비스 비활성화 확인됨"
        ))

    # NET-031: NTP
    ntp_srv = find_lines(r'ntp server\s+\S+|/c/sys/ntp|set system ntp server')
    if ntp_srv:
        results['NET-031'] = ok(fmt(
            f"NTP 서버: {ntp_srv[0]}" + (f" 외 {len(ntp_srv)-1}개" if len(ntp_srv)>1 else ""),
            "NTP 서버 동기화 설정",
            f"NTP {len(ntp_srv)}개 서버 설정됨"
        ))
    else:
        results['NET-031'] = ng(fmt("NTP 서버 미설정", "ntp server [IP] 설정 필요", "시간 동기화 미설정 - 로그 시간 신뢰도 저하"))

    # ──────────────────────────────────────────────────────────────
    # 로깅 관련 (NET-033~037) 다시
    # ──────────────────────────────────────────────────────────────

    # NET-033: 로깅 활성화
    if vendor == "ASA":
        log_en = fline(r'logging enable')
        if log_en:
            log_trap = fline(r'logging trap\s+\S+')
            results['NET-033'] = ok(fmt(
                f"logging enable ({log_trap or ''})",
                "logging enable 설정",
                "ASA 로깅 활성화됨"
            ))
        else:
            results['NET-033'] = ng(fmt("logging enable 미설정", "logging enable 설정 필요", "ASA 로깅 비활성화됨"))
    elif vendor == "ALTEON":
        syslog = fline(r'/c/cfg/sys/syslog|syslog')
        results['NET-033'] = ok(fmt(f"Alteon syslog 설정: {syslog}", "syslog 활성화", "로깅 활성됨")) if syslog else ng(fmt("Alteon syslog 미설정", "syslog 설정 필요", "로깅 미설정"))
    elif vendor == "JUNIPER":
        jlog = fline(r'set system syslog')
        results['NET-033'] = ok(fmt(f"Junos syslog: {jlog}", "syslog 설정", "로깅 활성됨")) if jlog else ng(fmt("set system syslog 미설정", "syslog 설정 필요", "로깅 미설정"))
    else:
        log_lines = find_lines(r'^logging\s+')
        explicit_on = any_m(r'^\s*logging on\b')
        if explicit_on or log_lines:
            results['NET-033'] = ok(fmt(
                f"logging 설정: {log_lines[0] if log_lines else 'logging on'}",
                "logging on 또는 logging host 설정",
                f"로깅 활성화됨 ({len(log_lines)}개 logging 구문)"
            ))
        else:
            results['NET-033'] = ng(fmt("logging 설정 없음", "logging 활성화 필요", "로깅 미설정"))

    # NET-034: 로그 타임스탬프
    if vendor in ("ASA",):
        ts = fline(r'logging timestamp')
        results['NET-034'] = ok(fmt(f"{ts or 'logging timestamp 설정됨'}", "로그 타임스탬프 설정", "ASA 로그 시간 포함됨")) if ts else ng(fmt("logging timestamp 미설정", "logging timestamp 설정", "ASA 로그 시간 미포함"))
    elif vendor == "JUNIPER":
        results['NET-034'] = ok(fmt("Junos 기본 타임스탬프 포함", "로그 시간 기록", "Junos 로그 시간 기본 포함"))
    else:
        ts_log = fline(r'service timestamps log')
        ts_dbg = fline(r'service timestamps debug')
        if ts_log:
            results['NET-034'] = ok(fmt(
                f"{ts_log}" + (f" / {ts_dbg}" if ts_dbg else ""),
                "service timestamps log datetime msec 설정",
                "로그 타임스탬프 설정됨 - 정확한 시간 기록"
            ))
        else:
            results['NET-034'] = ng(fmt("service timestamps log 미설정", "service timestamps log datetime msec 설정 필요", "로그에 시간 미포함 - 사후 분석 어려움"))

    # NET-035: 로그 버퍼 크기
    if vendor == "ASA":
        buf_asa = fline(r'logging buffer-size\s+\d+')
        if buf_asa:
            sz = re.search(r'\d+', buf_asa)
            size = int(sz.group()) if sz else 0
            results['NET-035'] = ok(fmt(f"{buf_asa}", "logging buffer-size 설정", f"로깅 버퍼 {size}bytes 설정됨"))
        else:
            results['NET-035'] = ng(fmt("logging buffer-size 미설정", "logging buffer-size 16384 이상", "버퍼 미설정"))
    else:
        buf = fline(r'logging buffered\s+')
        if buf:
            m = re.search(r'logging buffered\s+(\d+)(?:\s+(\S+))?', buf, re.I)
            size  = int(m.group(1)) if m else 0
            level = m.group(2) if m and m.group(2) else "informational"
            # 평가기준: 버퍼 메모리 설정이 없을 경우만 취약 (크기 무관)
            results['NET-035'] = ok(fmt(
                f"{buf} (크기:{size or '기본'}, 레벨:{level})",
                "logging buffered 설정",
                f"로깅 버퍼 설정됨 ({size or '기본'} bytes, {level})"
            ))
        else:
            results['NET-035'] = ng(fmt("logging buffered 미설정", "logging buffered [크기] [레벨] 설정", "버퍼 로그 미설정 - 메모리 로그 없음"))

    # NET-036: 원격 로그서버
    if vendor == "ASA":
        log_hosts = find_lines(r'logging host\s+\S+\s+\S+')
    elif vendor == "ALTEON":
        log_hosts = find_lines(r'hst\d?\s+\d{1,3}\.\d{1,3}|syslog.*\d{1,3}\.\d{1,3}')
    elif vendor == "JUNIPER":
        log_hosts = find_lines(r'set system syslog host\s+\S+')
    else:
        log_hosts = find_lines(r'logging host\s+\S+')

    if log_hosts:
        hosts_str = "; ".join(log_hosts[:3])
        results['NET-036'] = ok(fmt(
            f"원격 로그서버 {len(log_hosts)}개: {hosts_str}",
            "원격 syslog 서버 설정 (SIEM 연동)",
            f"로그서버 {len(log_hosts)}개 설정됨 - 외부 전송 가능"
        ))
    else:
        results['NET-036'] = ng(fmt(
            "logging host/syslog 서버 미설정",
            "원격 syslog 서버 설정 필요",
            "로그 외부 전송 없음 - 장비 손상 시 로그 유실 위험"
        ))

    # NET-037: 콘솔 로깅 레벨
    if vendor == "ASA":
        cl = fline(r'logging console\s+\S+')
        results['NET-037'] = ok(fmt(f"{cl}", "logging console 레벨 설정", "ASA 콘솔 로그 설정됨")) if cl else mc(fmt("logging console 미설정", "적절한 레벨 설정", "콘솔 로그 레벨 수동 확인"))
    elif vendor == "JUNIPER":
        jcl = fline(r'set system syslog console')
        results['NET-037'] = ok(fmt(f"{jcl or 'Junos console syslog'}", "콘솔 로그 설정", "Junos 콘솔 로그 설정됨")) if jcl else mc(fmt("콘솔 로그 수동 확인", "syslog console 설정", "수동 확인"))
    else:
        # 평가기준 판단방법: 콘솔 로깅 사용 중지 또는 레벨 critical 이상 (emergencies/alerts/critical = 0~2)
        if any_m(r'^\s*no logging console\b'):
            results['NET-037'] = ok(fmt("no logging console", "콘솔 로깅 중지 또는 critical 이상", "콘솔 로깅 중지"))
        else:
            cl = fline(r'^\s*logging console\s+\S+')
            lv = re.search(r'logging console\s+(\S+)', cl, re.I).group(1).lower() if cl else "debugging(기본)"
            if lv in ("emergencies", "alerts", "critical", "0", "1", "2"):
                results['NET-037'] = ok(fmt(cl, "콘솔 로깅 중지 또는 critical 이상", f"콘솔 로그 레벨 {lv}"))
            else:
                results['NET-037'] = ng(fmt(cl or "logging console 미설정 (IOS 기본 debugging)", "콘솔 로깅 중지 또는 critical 이상",
                                            f"콘솔 로그 레벨 {lv} - 불필요한 콘솔 로깅"))

    # ──────────────────────────────────────────────────────────────
    # NET-038~040: ACL 필터 (다시 - 설정값 긁어오기)
    # ──────────────────────────────────────────────────────────────

    # NET-038~040: ACL/스푸핑 필터 (라우터만 해당)
    if is_pure_l2:
        for c in ('NET-038','NET-039','NET-040'):
            results[c] = na(fmt("L2 스위치 - WAN/라우팅 없음", "라우터 해당 항목", "L2 스위치 N-A"))
    else:
        # NET-038: 외부 인터페이스 ingress 필터
        # 외부 인터페이스에 적용된 ACL 탐지
        intf_acl_in  = find_lines(r'ip access-group\s+\S+\s+in')
        acl_defs     = find_lines(r'ip access-list\s+\S+\s+\S+|access-list\s+\d+')
        urpf         = find_lines(r'ip verify unicast source')
        if intf_acl_in or urpf:
            actual = "; ".join((intf_acl_in + urpf)[:3])
            results['NET-038'] = mc(fmt(
                f"Ingress ACL/uRPF: {actual}",
                "외부 인터페이스 ingress 필터 (bogon/RFC1918 차단 등)",
                f"ACL 설정 확인됨 ({len(intf_acl_in)}개 in) - 실제 룰 내용 및 외부 인터페이스 적용 수동 확인"
            ))
        else:
            results['NET-038'] = ng(fmt(
                f"ip access-group in 미설정 (ACL 정의: {len(acl_defs)}개)",
                "외부 인터페이스 ingress 패킷 필터 적용",
                "ingress ACL 미적용 - 위변조 패킷 유입 가능"
            ))

        # NET-039: 외부 인터페이스 egress 필터
        intf_acl_out = find_lines(r'ip access-group\s+\S+\s+out')
        if intf_acl_out:
            results['NET-039'] = mc(fmt(
                f"Egress ACL: {'; '.join(intf_acl_out[:2])}",
                "외부 인터페이스 egress 필터",
                "egress ACL 설정됨 - 룰 내용 수동 확인"
            ))
        else:
            results['NET-039'] = ng(fmt(
                "ip access-group out 미설정",
                "외부 인터페이스 egress 필터 적용",
                "egress ACL 미적용 - 내부 정보 유출 필터 없음"
            ))

        # NET-040: 스푸핑방지 필터 (다시)
        if urpf:
            results['NET-040'] = ok(fmt(
                f"uRPF 설정: {urpf[0]}",
                "ip verify unicast source reachable-via 설정 또는 bogon 차단 ACL",
                "uRPF(Unicast Reverse Path Forwarding) 스푸핑 방지 적용됨"
            ))
        else:
            # RFC1918 차단 ACL 탐지
            bogon_acl = find_lines(r'deny\s+ip\s+(10\.|172\.1[6-9]\.|172\.2[0-9]\.|172\.3[0-1]\.|192\.168\.)')
            if bogon_acl:
                results['NET-040'] = mc(fmt(
                    f"RFC1918 차단 ACL: {bogon_acl[0][:60]}",
                    "스푸핑 방지 (uRPF 또는 bogon ACL)",
                    "bogon 차단 ACL 설정됨 - 외부 인터페이스 적용 수동 확인"
                ))
            else:
                results['NET-040'] = ng(fmt(
                    f"uRPF 미설정, RFC1918 차단 ACL 미발견",
                    "ip verify unicast source 또는 bogon 차단 ACL 설정",
                    "스푸핑 방지 미설정 - IP 위조 패킷 허용 가능"
                ))

    # NET-041: 멀티캐스트 (라우터만 취약 - 스위치는 N-A)
    if is_pure_l2:
        results['NET-041'] = na(fmt("스위치 전용 장비 (L2)", "라우터 해당 항목", "L2 스위치 해당 없음"))
    else:
        mdeny = find_lines(r'deny\s+(ip\s+)?.*\b224\.0\.0\.0\s+(15\.255\.255\.255|0\.255\.255\.255)|deny\s+.*224\.0\.0\.0/4')
        if mdeny:
            results['NET-041'] = mc(fmt(f"멀티캐스트 차단 ACL: {mdeny[0][:60]}", "ACL 로 224.0.0.0 대역 유입 차단",
                                        "차단 ACL 존재 - 외부 인터페이스 적용 여부 확인"))
        else:
            results['NET-041'] = ng(fmt(f"224.0.0.0 차단 ACL 없음 ({fline(r'ip multicast-routing') or 'multicast-routing 미설정'})",
                                        "ACL 로 224.0.0.0 대역 유입 차단 (전용회선 연결 시 양호)",
                                        "멀티캐스트 차단 ACL 미설정 - 전용회선 연결이면 양호"))

    # ──────────────────────────────────────────────────────────────
    # NET-042: ICMP 차단 (라우터만 - 스위치는 N-A)
    # ──────────────────────────────────────────────────────────────
    if is_pure_l2:
        results['NET-042'] = na(fmt("L2 스위치 - ICMP 라우팅 해당 없음", "라우터 해당 항목", "L2 스위치 N-A"))
    else:
        icmp_deny = find_lines(r'deny\s+icmp')
        if icmp_deny:
            results['NET-042'] = mc(fmt(
                f"ICMP 차단 ACL: {icmp_deny[0][:60]}",
                "외부 ICMP 요청 차단 ACL 적용",
                "ICMP 차단 ACL 발견 - 외부 인터페이스 적용 여부 수동 확인"
            ))
        else:
            results['NET-042'] = ng(fmt(
                "ICMP 차단 ACL 없음",
                "외부 인터페이스 ICMP 제한 ACL",
                "ICMP 차단 미설정 - 네트워크 정보 노출 가능"
            ))

    # NET-043~046: ICMP (라우터만 해당)
    if is_pure_l2:
        for c in ('NET-043','NET-044','NET-045','NET-046'):
            results[c] = na(fmt("L2 스위치", "라우터 해당 항목", "L2 스위치 N-A"))
    else:
        # NET-043~046: ICMP 세부
        no_redir = find_lines(r'no ip redirects')
        no_unrch = find_lines(r'no ip unreachables')
        no_mask  = find_lines(r'no ip mask-reply')
        results['NET-043'] = ok(fmt(f"no ip redirects: {len(no_redir)}개 인터페이스", "no ip redirects 설정", "ICMP Redirect 차단됨")) if (no_redir or any_m(r'no ip redirects')) else ng(fmt("no ip redirects 미설정", "no ip redirects 인터페이스 적용", "ICMP Redirect 허용 - 라우팅 조작 가능"))
        _ipif = [i for i in ifaces if i["has_ip"] and not re.match(r'(loopback|null)', i["name"], re.I)]
        if no_unrch and len(no_unrch) >= len(_ipif):
            results['NET-044'] = ok(fmt(f"no ip unreachables: {len(no_unrch)}개 인터페이스", "인터페이스마다 no ip unreachables", "ICMP Unreachable 차단됨"))
        else:
            results['NET-044'] = ng(fmt(f"no ip unreachables {len(no_unrch)}개 / IP 인터페이스 {len(_ipif)}개", "인터페이스마다 no ip unreachables", "ICMP Unreachable 미차단 인터페이스 존재"))
        # 평가기준: 인터페이스에 ip mask-reply 설정이 '존재'할 때만 취약 (IOS 기본 비활성)
        mask_on = [l.strip() for l in find_lines(r'^\s*ip mask-reply')]
        results['NET-045'] = ng(fmt(f"ip mask-reply 설정: {len(mask_on)}개 인터페이스", "ip mask-reply 미설정", "Subnet Mask 정보 노출 가능")) if mask_on else ok(fmt("ip mask-reply 설정 없음 (IOS 기본 비활성)", "ip mask-reply 미설정", "ICMP Mask Reply 비활성"))
        results['NET-046'] = mc(fmt("ICMP Timestamp/Information ACL", "해당 유형 차단 ACL", "ACL 내용 수동 확인"))

    # NET-047: DDoS/CoPP
    if is_pure_l2:
        results['NET-047'] = na(fmt("L2 스위치", "라우터 해당 항목", "L2 스위치 N-A"))
    else:
        _ports = {"55", "77", "103", "135", "139", "445", "593", "137", "138"}
        _denied = set()
        for dl in find_lines(r'deny\s+(tcp|udp)\s+.*\beq\s+'):
            _denied.update(p for p in re.findall(r'\beq\s+(\d+)', dl) if p in _ports)
        _copp = fline(r'policy-map.*copp|ip tcp intercept')
        if _denied:
            results['NET-047'] = mc(fmt(f"권장 포트 차단 ACL {len(_denied)}/{len(_ports)}개: {', '.join(sorted(_denied, key=int))}",
                                        "ACL 로 DDoS 권장 포트(55,77,103,135,137~139,445,593) 차단",
                                        "차단 ACL 존재 - 외부 인터페이스 적용·누락 포트 확인"))
        else:
            results['NET-047'] = ng(fmt(f"DDoS 권장 포트 차단 ACL 없음{' (' + _copp[:40] + ')' if _copp else ''}",
                                        "ACL 로 DDoS 권장 포트 차단 (상단 DDoS 대응장비·전용회선이면 양호)",
                                        "포트 차단 ACL 미설정 - 상단 DDoS 대응장비·전용회선 여부 확인"))

    # NET-048: 보안패치
    results['NET-048'] = mc(fmt("장비 운영 IOS/펌웨어 버전 확인", "벤더 보안 권고 버전 사용", "version 명령으로 현재 버전 확인 후 벤더 EoL/패치 공지 대조"))

    # ──────────────────────────────────────────────────────────────
    # NET-049: 명령어 권한 제한 → 보류 (수동확인)
    # ──────────────────────────────────────────────────────────────
    priv_lines = find_lines(r'privilege\s+(exec|configure|interface)\s+level\s+\d+')
    view_lines = find_lines(r'parser view\s+\S+')
    role_lines = find_lines(r'username.*privilege\s+(1[0-4]|\d)\b')  # priv 1~14
    if priv_lines or view_lines:
        detail = (priv_lines + view_lines)[0]
        results['NET-049'] = mc(fmt(
            f"권한 설정: {detail}",
            "CLI 명령어 레벨별 접근 제한 (privilege level 또는 parser view)",
            f"권한 분리 설정 발견 ({len(priv_lines)}개 privilege, {len(view_lines)}개 view) - 실제 적용 범위 수동 확인"
        ))
    else:
        results['NET-049'] = mc(fmt(
            f"privilege/parser view 설정 없음 (계정 권한: {role_lines[0][:60] if role_lines else '미확인'})",
            "privilege level 또는 parser view로 명령어 권한 분리",
            "명령어 권한 분리 미설정 - 수동 확인 및 정책 검토 필요"
        ))

    # ──────────────────────────────────────────────────────────────
    # NET-050: 로그온 배너 (다시 - 내용 긁어오기)
    # ──────────────────────────────────────────────────────────────
    banner_content = []
    in_banner = False; banner_text_lines = []
    for l in lines:
        if re.match(r'\s*banner\s+(login|motd|exec|asdm)', l, re.I):
            in_banner = True
            banner_text_lines = [l.strip()]
        elif in_banner:
            if re.search(r'\^C|\^D|^\s*!', l):
                in_banner = False
                banner_content.append(" ".join(banner_text_lines[:3])[:100])
            else:
                banner_text_lines.append(l.strip())
    if in_banner and banner_text_lines:
        banner_content.append(" ".join(banner_text_lines[:3])[:100])

    if vendor == "JUNIPER":
        jbanner = fline(r'set system login message')
        if jbanner: banner_content.append(jbanner)

    if banner_content:
        bc = banner_content[0]
        # 경고 문구 포함 여부 확인
        has_warning = re.search(r'authorized|unauthorized|warning|법적|불법|경고|허가', bc, re.I)
        exposed = re.search(r'\b(IOS|NX-OS|JunOS|Version)\b|\d+\.\d+\(\d+\)', " ".join(banner_content), re.I)
        if exposed:
            results['NET-050'] = ng(fmt(f"배너 내용: \"{bc[:80]}\"", "경고 배너, 서비스명·버전 정보 미노출", f"배너에 버전 정보 노출 ({exposed.group(0)})"))
        elif has_warning:
            results['NET-050'] = ok(fmt(
                f"배너 내용: \"{bc[:80]}\"",
                "무단 접근 경고 문구 포함 배너",
                "경고 배너 설정됨 - 법적 보호 근거 확보"
            ))
        else:
            results['NET-050'] = mc(fmt(
                f"배너 존재하나 경고 문구 미포함: \"{bc[:60]}\"",
                "무단 접근 경고 문구 (authorized users only 등) 필요",
                "배너 있으나 경고 문구 없음 - 내용 보완 필요"
            ))
    else:
        results['NET-050'] = ng(fmt(
            "banner login/motd/exec 미설정",
            "무단 접근 경고 배너 설정",
            "배너 미설정 - 불법 접근 시 법적 효력 없음"
        ))

    # ──────────────────────────────────────────────────────────────
    # NET-051: TCP keepalive (다시 - 설정값 + 방향)
    # ──────────────────────────────────────────────────────────────
    ka_in  = any_m(r'service tcp-keepalives-in')
    ka_out = any_m(r'service tcp-keepalives-out')
    ka_gen = any_m(r'service tcp-keepalives\b')

    if ka_in and ka_out:
        results['NET-051'] = ok(fmt(
            "service tcp-keepalives-in + service tcp-keepalives-out 설정됨",
            "양방향 TCP keepalive 설정",
            "TCP keepalive 양방향 적용 - 유령 세션 방지"
        ))
    elif ka_gen:
        results['NET-051'] = ok(fmt(
            f"service tcp-keepalives 설정됨",
            "TCP keepalive 설정",
            "TCP keepalive 설정됨 (방향 구분 필요 시 in/out 분리 설정 권고)"
        ))
    elif ka_in or ka_out:
        direction = "in" if ka_in else "out"
        results['NET-051'] = mc(fmt(
            f"service tcp-keepalives-{direction}만 설정 (반대 방향 미설정)",
            "양방향(in+out) TCP keepalive 설정",
            f"{direction} 방향만 설정됨 - 나머지 방향 추가 설정 권고"
        ))
    else:
        results['NET-051'] = ng(fmt(
            "service tcp-keepalives 미설정",
            "service tcp-keepalives-in + tcp-keepalives-out 설정",
            "TCP keepalive 미설정 - 유령 세션 장기 유지 가능"
        ))

    # ──────────────────────────────────────────────────────────────
    # NET-052: 미사용 인터페이스 비활성화 (다시 - 실제 현황)
    # ──────────────────────────────────────────────────────────────
    active_no_desc = []
    shutdown_ifaces = []
    all_phy = [i for i in ifaces if not any(
        x in i["name"] for x in ["Loopback","Null","Tunnel","BVI","VLAN","Vlan","vlan","mgmt","Mgmt"]
    )]
    for i in all_phy:
        if i["shutdown"]:
            shutdown_ifaces.append(i["name"])
        elif not i["has_ip"] and not i["switchport"]:
            active_no_desc.append(i["name"])

    total   = len(all_phy)
    active  = total - len(shutdown_ifaces)
    shut    = len(shutdown_ifaces)

    if total == 0:
        results['NET-052'] = mc(fmt("물리 인터페이스 파싱 실패", "미사용 인터페이스 shutdown", "수동 확인"))
    elif active_no_desc:
        results['NET-052'] = mc(fmt(
            f"전체 {total}개 / shutdown {shut}개 / 활성 {active}개 "
            f"(IP/switchport 미설정 활성 포트: {', '.join(active_no_desc[:5])}{'...' if len(active_no_desc)>5 else ''})",
            "미사용 인터페이스 shutdown 처리",
            f"IP/L2 미설정 활성 포트 {len(active_no_desc)}개 - 미사용 여부 확인 후 shutdown 처리 필요"
        ))
    else:
        results['NET-052'] = mc(fmt(
            f"전체 {total}개 / 활성 {active}개(IP/L2 설정) / shutdown {shut}개",
            "sh int desc 에서 admin down 이 아닌 down 인터페이스 없음 (백업용 예외)",
            "설정만으로 링크 상태 확인 불가 - sh int desc/status 로 down 포트 확인"
        ))

    # ──────────────────────────────────────────────────────────────
    # NET-054: 스위치 보안 (다시 - 포괄적)
    # ──────────────────────────────────────────────────────────────
    if not has_sw_port:
        results['NET-054'] = na(fmt(
            f"스위치 포트 없음 ({dtype})",
            "스위치 포트 보안 설정 (L2 장비 해당)",
            f"라우터/L3 장비 - 스위치 보안 해당 없음"
        ))
    else:
        missing_54 = []; found_54 = []

        # port-security
        ps_global = any_m(r'switchport port-security')
        dhcp_snoop = any_m(r'ip dhcp snooping')
        dai = any_m(r'ip arp inspection')
        if ps_global: found_54.append("port-security")
        elif dhcp_snoop: found_54.append("dhcp-snooping")
        else: missing_54.append("port-security 또는 dhcp-snooping")

        # bpduguard
        bpdu_global = any_m(r'spanning-tree portfast bpduguard default|bpduguard default')
        bpdu_intf   = any_m(r'spanning-tree bpduguard enable|bpduguard enable')
        if bpdu_global: found_54.append("bpduguard(global)")
        elif bpdu_intf: found_54.append("bpduguard(interface)")
        else: missing_54.append("bpduguard")

        # storm-control
        sc_found = any_m(r'storm-control')
        if sc_found:
            sc_sample = fline(r'storm-control')
            found_54.append(f"storm-control({sc_sample[:30] if sc_sample else 'yes'})")
        else:
            missing_54.append("storm-control")

        # DAI (optional - 설정됐으면 bonus)
        if dai: found_54.append("DAI(dynamic-arp-inspection)")

        # 포트별 설정 수량
        ps_ports = len(find_lines(r'switchport port-security\s*$|switchport port-security maximum'))
        sc_ports = len(find_lines(r'storm-control broadcast|storm-control multicast'))

        sw_summary = f"설정됨: {', '.join(found_54)} | 미설정: {', '.join(missing_54)} | (port-security 포트:{ps_ports}개, storm-control 포트:{sc_ports}개)"
        _span = fline(r'^\s*monitor session')
        sw_summary += f" | span: {_span or '없음'}"
        if ps_global or dhcp_snoop or dai:
            results['NET-054'] = ok(fmt(sw_summary, "스위치 포트 보안 설정 (bpduguard·storm-control 은 참고)", "포트 보안 설정됨"))
        else:
            results['NET-054'] = ng(fmt(sw_summary, "스위치 포트 보안 설정", "포트 보안(port-security 등) 미설정"))

    # NET-056: 비밀번호 변경 주기
    results['NET-056'] = mc(fmt("비밀번호 변경 이력", "정기적 비밀번호 변경 수행", "변경 주기 및 최근 변경일 인터뷰 확인"))

    # ──────────────────────────────────────────────────────────────
    # NET-057: 취약 서비스 비활성화 (다시 - 더 포괄적)
    # ──────────────────────────────────────────────────────────────
    weak_en  = []
    weak_dis = []

    checks_57 = [   # 평가기준 목록: CDP, LLDP, TFTP, Finger, identd, Smart Install (그 외 서비스는 NET-030)
        (r'^\s*service finger\b|^\s*ip finger', "finger"),
        (r'^\s*lldp run\b',                     "LLDP"),
        (r'^\s*tftp-server\b',                  "TFTP"),
        (r'^\s*ip identd\b',                    "identd"),
        (r'^\s*vstack\b',                       "Smart Install(vstack)"),
    ]
    for pat, name in checks_57:
        if any_m(pat):
            weak_en.append(name)
        # 명시적 비활성화 확인
        no_pat = pat.replace(r'^\s*', r'^\s*no\s+')
        if any_m(no_pat):
            weak_dis.append(name)

    # CDP: IOS 기본 활성 → 'no cdp run' 없으면 구동 중으로 판단 (평가기준 취약 서비스 목록)
    if vendor == "CISCO":
        if any_m(r'^\s*no cdp run\b'):
            weak_dis.append("CDP")
        else:
            weak_en.append("CDP(기본 활성, no cdp run 미설정)")
    if any_m(r'^\s*no vstack\b'):
        weak_dis.append("Smart Install")
    # Juniper/Alteon 취약 서비스
    if vendor == "JUNIPER":
        if any_m(r'set protocols lldp'): weak_en.append("LLDP(Junos)")
        if any_m(r'set system services tftp|set system services finger'): weak_en.append("TFTP/Finger(Junos)")

    if weak_en:
        results['NET-057'] = ng(fmt(
            f"활성 취약 서비스: {', '.join(weak_en)}",
            "취약 서비스(CDP/LLDP/TFTP/Finger/identd/Smart Install 등) 비활성화",
            f"{len(weak_en)}개 취약 서비스 활성 - 비활성화 필요: {', '.join(weak_en)}"
        ))
    else:
        results['NET-057'] = ok(fmt(
            f"취약 서비스 미발견 (명시 비활성: {', '.join(weak_dis[:4]) if weak_dis else '없음'})",
            "취약 서비스(CDP/LLDP/TFTP/Finger/identd/Smart Install 등) 비활성화",
            "주요 취약 서비스 비활성화 확인됨"
        ))

    # NET-058: 계정 잠금
    _mf = fline(r'aaa local authentication attempts max-fail\s+\d+')
    _bf = fline(r'login block-for\s+\d+\s+attempts\s+\d+')
    _n  = int(re.search(r'max-fail\s+(\d+)', _mf).group(1)) if _mf else (int(re.search(r'attempts\s+(\d+)', _bf).group(1)) if _bf else None)
    lockout = _mf or _bf or fline(r'aaa.*lockout|security authentication failure rate')
    if _n is not None and _n <= 5:
        results['NET-058'] = ok(fmt(lockout, "계정 잠금 임계값 적절(5회 이하)", f"로그인 실패 {_n}회 잠금/차단"))
    elif _n is not None:
        results['NET-058'] = ng(fmt(lockout, "계정 잠금 임계값 적절(5회 이하)", f"임계값 {_n}회 - 과다"))
    elif lockout:
        results['NET-058'] = mc(fmt(lockout, "계정 잠금 임계값 적절", "지연/기타 방식 - 임계값 적정성 수동 확인"))
    else:
        results['NET-058'] = ng(fmt("login block-for / authentication failure rate 미설정", "로그인 실패 시 차단 설정", "무제한 로그인 시도 허용 - 무차별 공격 취약"))

    # 벤더 전용 파서가 없는 항목은 IOS 문법 기준으로 판정되므로, 비 Cisco 장비의 '취약'은 수동확인으로 전환
    _aware = {"JUNIPER": {"NET-007", "NET-011", "NET-030", "NET-031", "NET-033", "NET-034", "NET-036", "NET-037", "NET-050", "NET-057"},
              "ALTEON":  {"NET-007", "NET-015", "NET-030", "NET-031", "NET-033", "NET-036"}}
    if vendor == "JUNIPER" and not any_m(r'^set '):   # 계층형(show configuration) 형식은 set 기반 전용 파서 적용 불가
        _aware["JUNIPER"] = set()
    if vendor not in ("CISCO", "ASA"):
        for _c, _v in list(results.items()):
            if _v[0] in (RESULT_BAD, RESULT_GOOD, RESULT_NA) and _c not in _aware.get(vendor, set()):
                results[_c] = mc(f"{vendor} 설정 문법 자동 판정 미지원 - 수동 확인 (IOS 기준 참고: {_v[1][:120]})")

    # IOS 유사 문법 D-Link(DGS-3630 등): Cisco 기본값(미설정 = 활성) 가정 항목은 수동확인, CDP 는 미지원
    if _net_brand(text)[0] == "D-LINK":
        for _c in ("NET-022", "NET-026", "NET-034", "NET-043", "NET-044", "NET-051"):
            if results.get(_c, ("",))[0] == RESULT_BAD:
                results[_c] = mc(f"D-Link 장비 - Cisco 기본값 기준 판정 불가, 장비 기본값 확인 필요 (IOS 기준 참고: {results[_c][1][:120]})")
        if results.get('NET-057', ("",))[0] == RESULT_BAD:
            _m = re.search(r'활성 취약 서비스:\s*([^\[]+)', results['NET-057'][1])
            _w = re.sub(r'CDP\([^)]*\)|\bCDP\b', '', _m.group(1) if _m else '').strip(' ,')
            _w = re.sub(r',\s*,', ',', _w)
            results['NET-057'] = (ng(fmt(f"활성 취약 서비스: {_w}", "취약 서비스(CDP/LLDP/TFTP/Finger/identd/Smart Install 등) 비활성화",
                                         "취약 서비스 활성 - 비활성화 필요")) if _w else
                                  ok(fmt("CDP 미지원 장비(D-Link), 기타 기준 취약 서비스 미사용",
                                         "취약 서비스(CDP/LLDP/TFTP/Finger/identd/Smart Install 등) 비활성화", "양호")))

    # NET-059: EoS
    results['NET-059'] = mc(fmt(
        f"장비 벤더: {vendor}, 운영체제: config 상단 version 확인",
        "벤더 EoL/EoS 기준 지원 종료 이전 장비 사용",
        "벤더 EoL 페이지 대조 수동 확인 필요"
    ))

    return results


# ================================================================
# 점검 파일 헤더에서 대상 유형 탐지 (OS/DB/네트워크 세부 분기용)
# ================================================================
def _net_brand(text):
    """config 머리말(주석)의 제조사·모델·펌웨어 — 설정 문법이 IOS 계열이어도 실제 제조사 식별 (예: D-Link DGS-3630)"""
    head = "\n".join(l for l in text.splitlines()[:30] if l.lstrip().startswith(("!", "#")))
    m = re.search(r"\b((?:DGS|DES|DXS|DWS)-[\w-]+)", head, re.I)
    if m or re.search(r"d-link", head, re.I):
        fw = re.search(r"Firmware:\s*(?:Build\s*)?(\S+)", head, re.I)
        return "D-LINK", (m.group(1) if m else ""), (fw.group(1) if fw else "")
    return "", "", ""


def _cfg_blocks(lines, pat):
    """pat 으로 시작하는 설정 블록 → [(머리줄, [하위 설정 줄, ...])]"""
    out, cur = [], None
    for l in lines:
        if re.match(pat, l, re.I):
            cur = (l.strip(), [])
            out.append(cur)
            continue
        if cur is not None:
            if l[:1] in (" ", "\t") and l.strip():
                cur[1].append(l.strip())
                continue
            cur = None
    return out


def build_net_kisa_checks(lines, text):
    """
    주요정보(MI) 2026 상세가이드 N-xx 항목 직접 판정 (IOS 계열 문법 장비)
    - 평가기준 NET-030/NET-057 등이 여러 가이드 항목을 통합 점검 → 서비스별 분리 판정
    - 가이드 판단기준과 평가기준이 다른 항목(Session Timeout 10분·미설정 취약 등)은 가이드 기준으로 판정
    - 제조사(D-Link 등) 기본값 차이 반영, L3 인터페이스 보유 여부로 인터페이스 항목 적용
    """
    vendor = detect_net_vendor(text)
    if vendor not in ("CISCO", "ASA"):
        return {}
    brand, model, _ = _net_brand(text)
    dlink = brand == "D-LINK"
    dev = f"D-Link {model}".strip() if dlink else vendor
    # 제조사 문서로 기본값을 확인한 모델: DGS-3630 (CLI Reference Guide R2.25, D-Link)
    dgs3630 = dlink and "DGS-3630" in (model or "").upper()
    DGS_REF = "D-Link DGS-3630 CLI Reference Guide R2.25"

    def on(pat):
        return next((l.strip() for l in lines if re.match(pat, l, re.I)), "")

    def svc(code, name, pat):
        l = on(pat)
        return {code: (RESULT_BAD, f"{name} 활성: {l}") if l else (RESULT_GOOD, f"{name} 설정 없음 (비활성)")}

    r = {}
    ifs = _cfg_blocks(lines, r"^interface\s+\S+")
    l3_ifs = [h.split(None, 1)[1] for h, sub in ifs
              if any(re.match(r"ip address\s+\d", x, re.I) for x in sub)
              and not re.match(r"(?i)(mgmt|management|loopback|null)", h.split(None, 1)[1])]
    routing = bool(on(r"^\s*(ip routing|router\s+(ospf|bgp|eigrp|rip|isis))\b"))
    switch = bool(on(r"^\s*(vlan\s+\d|spanning-tree)")) or any(re.match(r"(?i)vlan", n) for n in l3_ifs) \
        or any("switchport" in x for _, sub in ifs for x in sub)
    is_l3 = routing or len(l3_ifs) >= 2
    dtype = ("L3 스위치" if is_l3 else "L2 스위치") if switch else "라우터"

    # ── 접근 관리 ──
    remote = _cfg_blocks(lines, r"^line\s+(vty|telnet|ssh)\b")
    rnames = ", ".join(h for h, _ in remote)
    if remote:
        acl = [x for _, sub in remote for x in sub if x.lower().startswith("access-class")] \
            or [on(r"^\s*(ip\s+)?(ssh|telnet)\s+.*access-class\b|^\s*ip\s+(ssh|telnet)\s+acl\b|.*trusted-host")]
        acl = [a for a in acl if a]
        r["N-06"] = ((RESULT_GOOD, f"원격 접속 접근 제한 설정: {acl[0]}") if acl
                     else (RESULT_BAD, f"원격 접속 라인({rnames})에 접근 제한 ACL(access-class) 미설정"))
        tos = []
        for h, sub in remote:
            m = next((re.match(r"exec-timeout\s+(\d+)(?:\s+(\d+))?", x, re.I) for x in sub
                      if re.match(r"exec-timeout\s+\d", x, re.I)), None)
            tos.append((h, None if m is None else int(m.group(1)) + int(m.group(2) or 0) / 60))
        unset = [h for h, t in tos if t is None]
        over = [f"{h}({t:g}분)" for h, t in tos if t is not None and (t == 0 or t > 10)]
        if unset or over:
            r["N-07"] = (RESULT_BAD, "Session Timeout " + " / ".join(
                x for x in ((f"미설정: {', '.join(unset)}" if unset else ""),
                            (f"10분 초과 또는 무제한: {', '.join(over)}" if over else "")) if x))
        else:
            r["N-07"] = (RESULT_GOOD, "Session Timeout 10분 이하: " + ", ".join(f"{h}({t:g}분)" for h, t in tos))
        telnet_off = bool(on(r"^\s*no\s+ip\s+telnet\s+server\b"))
        vty = [(h, sub) for h, sub in remote if h.lower().startswith("line vty")]
        ti = [x for _, sub in vty for x in sub if x.lower().startswith("transport input")]
        if vty and ti and all(re.fullmatch(r"(?i)transport input ssh", x) for x in ti) and len(ti) == len(vty):
            r["N-08"] = (RESULT_GOOD, "VTY 접속 프로토콜 SSH만 허용 (transport input ssh)")
        elif any(re.search(r"(?i)\b(telnet|all)\b", x) for x in ti):
            r["N-08"] = (RESULT_BAD, f"VTY 접속 시 평문 프로토콜 허용: {', '.join(ti)}")
        elif telnet_off:
            r["N-08"] = (RESULT_GOOD, "Telnet 서버 비활성(no ip telnet server) - SSH 접속만 사용")
        elif dlink:
            r["N-08"] = (RESULT_BAD, "Telnet 서버 비활성화 설정(no ip telnet server) 없음 - 평문 접속 허용")
        elif on(r"^\s*sdwan\b"):   # Catalyst SD-WAN IOS XE: VTY 기본 SSH 만 허용 (Cisco SD-WAN 명령 참조)
            r["N-08"] = (RESULT_GOOD, "SD-WAN IOS XE - VTY transport input 미설정 시 기본값 SSH 만 허용")
        else:
            unset = [h for h, sub in vty if not any(x.lower().startswith("transport input") for x in sub)]
            r["N-08"] = (RESULT_BAD, f"VTY transport input 미설정({', '.join(unset) or 'line vty'}) - Cisco IOS/IOS XE 기본값 transport input all(telnet 포함)로 평문 접속 허용")
    aux = _cfg_blocks(lines, r"^line\s+aux\b")
    if aux:
        sub = [x.lower() for _, s2 in aux for x in s2]
        r["N-09"] = ((RESULT_GOOD, "AUX 포트 사용 제한 (no exec / transport input none)")
                     if any(x in ("no exec", "transport input none") for x in sub)
                     else (RESULT_BAD, "AUX 포트 사용 제한 미설정 (no exec 또는 transport input none 필요)"))
    else:
        r["N-09"] = (RESULT_GOOD, "보조 입출력(AUX) 포트 설정 없음 - 미사용" + (" (AUX 포트 없는 장비)" if dlink else ""))

    # ── N-01 비밀번호 설정: 가이드 기준 = 기본 비밀번호 변경·비밀번호 설정 여부 (중복 사용은 가이드 기준 아님) ──
    #   제조사 초기값: Cisco IOS 기본 비밀번호 없음 / D-Link DGS-3630 사용자 계정 없음·enable 비밀번호 빈 값 (CLI Reference R2.25)
    users = [l.strip() for l in lines if re.match(r"^\s*username\s+\S+", l, re.I)]
    uname = lambda l: re.match(r"\s*username\s+(\S+)", l, re.I).group(1)
    pw_users = {uname(l) for l in users if re.search(r"\b(secret|password)\s+\S", l, re.I) and not re.search(r"\bnopassword\b", l, re.I)}
    nopw_users = sorted({uname(l) for l in users} - pw_users)
    weak_def = r"(cisco|admin|password|dlink|d-link|default|1234|12345|123456|manager|root|switch|router)"
    plain_def = sorted({uname(l) if l.lower().startswith("username") else l.split()[0]
                        for l in (x.strip() for x in lines)
                        if re.search(r"\b(password|secret)\s+(0\s+)?" + weak_def + r"\s*$", l, re.I)})
    aaa_login = on(r"^\s*aaa\s+authentication\s+login\s+default\s+(?!none\b)\S")
    line_noauth = []
    if not dlink:
        for h, sub in _cfg_blocks(lines, r"^line\s+(con|vty|aux)\b"):
            s1 = " ".join(sub).lower()
            if re.search(r"transport input none|no exec\b", s1):
                continue
            if not (re.search(r"\bpassword\s+\S|login local|login authentication", s1) or aaa_login):
                line_noauth.append(h)
    elif not (dgs3630 and pw_users):   # DGS-3630: 인증 방식 미지정 라인은 로컬 계정 DB 로 인증
        line_noauth = [h for h, _ in _cfg_blocks(lines, r"^line\s+\S+") if not users]
    bad01 = [x for x in ((f"비밀번호 없는 계정: {', '.join(nopw_users)}" if nopw_users else ""),
                         (f"기본값으로 추정되는 비밀번호 사용: {', '.join(plain_def)} (값 비공개)" if plain_def else ""),
                         (f"인증 없는 접속 라인: {', '.join(line_noauth)}" if line_noauth else "")) if x]
    if bad01:
        r["N-01"] = (RESULT_BAD, " / ".join(bad01))
    elif users or on(r"^\s*enable\s+(secret|password)\b") or aaa_login:
        r["N-01"] = (RESULT_GOOD, f"{dev}: 계정·접속 라인 비밀번호 설정 (제조사 기본값"
                     + (" - 사용자 계정 없음·enable 비밀번호 빈 값 - 에서 변경)" if dgs3630 else " - 비밀번호 없음 - 에서 변경)")
                     + (f", AAA 로그인 인증 사용: {aaa_login}" if aaa_login else ""))
    else:
        r["N-01"] = (RESULT_BAD, f"{dev}: 로컬 계정·enable 비밀번호·AAA 인증 모두 없음 - 제조사 기본 상태(비밀번호 미설정)")

    # ── N-02 비밀번호 복잡성: DGS-3630 은 복잡성 정책 기능 없음(CLI Reference R2.25) → 가이드: 기관 정책에 맞는 비밀번호 사용 여부
    #   평문 저장 비밀번호는 가이드 공통 복잡도(2종 10자 / 3종 8자)로 직접 판정 (값은 보고서에 쓰지 않음)
    if dgs3630 and not aaa_login:
        def _cx(pw):
            n = sum(bool(re.search(p, pw)) for p in (r"[A-Z]", r"[a-z]", r"\d", r"[^A-Za-z0-9]"))
            return (n >= 2 and len(pw) >= 10) or (n >= 3 and len(pw) >= 8)
        plain = [(uname(l), m.group(1)) for l in users
                 for m in [re.search(r"\bpassword\s+(?:0\s+)?(?![0-9]+\s)(\S+)\s*$", l, re.I)] if m]
        enc = [uname(l) for l in users if re.search(r"\bpassword\s+(7|15)\s+\S", l, re.I)]
        weak = sorted({u for u, pw in plain if not _cx(pw)})
        if weak:
            r["N-02"] = (RESULT_BAD, f"{dev}: 비밀번호 복잡성 정책 기능 없음({DGS_REF}) - 설정 비밀번호가 복잡도 기준(2종 10자/3종 8자) 미달: {', '.join(weak)} (값 비공개)")
        elif plain and not enc:
            r["N-02"] = (RESULT_GOOD, f"{dev}: 비밀번호 복잡성 정책 기능 없음({DGS_REF}) - 설정 비밀번호 복잡도 기준(2종 10자/3종 8자) 충족: {', '.join(sorted({u for u, _ in plain}))} (기관 정책 기준이 다르면 재확인)")

    # ── D-Link DGS-3630 기본값 반영 (CLI Reference R2.25): session-timeout 기본 3분 / logging on 기본 활성·버퍼 크기 인자 없음 ──
    if dgs3630:
        tos, bad07 = [], []
        for h, sub in _cfg_blocks(lines, r"^line\s+(console|telnet|ssh)\b"):
            m = next((re.match(r"session-timeout\s+(\d+)", x, re.I) for x in sub if re.match(r"session-timeout\s+\d+", x, re.I)), None)
            v = int(m.group(1)) if m else 3
            tos.append(f"{h}({v}분{'' if m else ', 기본값'})")
            if v == 0 or v > 10:
                bad07.append(f"{h}({'무제한' if v == 0 else f'{v}분'})")
        if tos:
            r["N-07"] = ((RESULT_BAD, f"{dev}: Session Timeout 10분 초과 또는 무제한: {', '.join(bad07)}") if bad07
                         else (RESULT_GOOD, f"{dev}: Session Timeout 10분 이하 - {', '.join(tos)} (session-timeout 기본 3분, {DGS_REF})"))
        r["N-13"] = (RESULT_MANUAL, f"{dev}: 로깅 버퍼 크기 설정 기능 없음(logging buffered 는 severity·write-delay 만, {DGS_REF}) - show logging 으로 버퍼 가득참 여부 확인")
        if on(r"^\s*no\s+logging\s+on\b"):
            r["N-14"] = (RESULT_BAD, f"{dev}: 시스템 로깅 비활성 (no logging on)")
        else:
            lg = on(r"^\s*logging\s+(buffered|server|console|monitor)\b")
            r["N-14"] = ((RESULT_GOOD, f"{dev}: 로깅 정책 설정: {lg}") if lg
                         else (RESULT_BAD, f"{dev}: 기본 로깅(logging on 기본 활성, 버퍼 warnings 이상)만 동작 - 로그 기록 정책에 따른 레벨·대상 설정 없음 ({DGS_REF})"))

    # ── 패치 관리: 제조사 공개 자료로 확인한 펌웨어 정보 (2026-09-29 조사) ──
    if dgs3630:
        fwm = re.search(r"Firmware:\s*Build\s*([\d.]+)", text)
        fw = fwm.group(1) if fwm else ""
        ver = lambda v: tuple(int(x) for x in re.findall(r"\d+", v)[:3])
        kb = ("최신 정식 펌웨어 2.25.018(2021-02-24), 이후 2.28.B003 은 베타(2022-12-06, CVE-2004-0230 TCP RST 대응·D-Link SAP10369)"
              " / H/W A1 은 D-Link 단종(EOL) 목록 등재(D-Link Korea End of Life Product List 2024-09-30)")
        bgp = on(r"^\s*router\s+bgp\b")
        if fw and ver(fw) < ver("2.25.018"):
            r["N-12"] = (RESULT_BAD, f"{dev}: 펌웨어 {fw} - 최신 정식 펌웨어 미적용 ({kb})")
        elif fw:
            r["N-12"] = (RESULT_MANUAL, f"{dev}: 펌웨어 {fw} = 최신 정식 버전, BGP {'사용 - 베타 2.28 적용 또는 BGP MD5 인증 확인' if bgp else '미사용 - CVE-2004-0230 영향 낮음'}"
                                        f" / H/W 버전 확인 필요(show version): A1 이면 단종 제품으로 보안 패치 중단 → 취약, A2 이면 양호 ({kb})")

    # ── 로그 관리 ──
    if dgs3630:
        sync = on(r"^\s*(sntp\s+server|ntp\s+server)\b")
        r["N-16"] = (RESULT_GOOD, f"{dev}: 시스템 로그에 날짜·시간 항상 기록 (별도 timestamp 명령 없음, {DGS_REF} show logging 출력 예)"
                                  + (f", 시간 동기화: {sync}" if sync else ", 시간 동기화(SNTP/NTP) 미설정 - N-15 참고"))
    elif dlink:
        r["N-16"] = (RESULT_MANUAL, f"{dev}: service timestamps 명령 미지원 - 로그 시간 정보 기록 여부 확인 (show logging)")

    # ── SNMP ──
    snmp = on(r"^\s*snmp-server\s+(community|user|host|group)\b")
    r["N-17"] = ((RESULT_MANUAL, f"SNMP 사용 중: {snmp} - 업무상 필요 여부 확인 (불필요 시 비활성화)")
                 if snmp else (RESULT_GOOD, "SNMP 미사용 (community/user/host 설정 없음)"))
    if not snmp:
        r["N-19"] = (RESULT_GOOD, "SNMP 미사용 - 가이드상 SNMP 비활성화 시 양호")
        r["N-20"] = (RESULT_GOOD, "SNMP 미사용 - RW 권한 커뮤니티 없음")

    # ── 기능 관리: 서비스 ──
    r.update(svc("N-21", "TFTP 서버", r"^\s*tftp-server\b"))
    if dtype != "라우터":   # 판단기준: 경계 라우터 또는 보안 장비에 적용 여부 → 이 장비 설정만으로 판정 불가
        r["N-22"] = (RESULT_MANUAL, f"{dtype}({dev}) - 판단기준상 경계 라우터 또는 보안 장비의 스푸핑 방지 필터링 적용 여부 확인 (적용 시 양호)")
        r["N-23"] = (RESULT_MANUAL, f"{dtype}({dev}) - 판단기준상 경계 라우터의 DDoS 방어 설정 또는 DDoS 대응 장비 사용 여부 확인 (사용 시 양호)")
    if dlink:
        r["N-25"] = (RESULT_MANUAL, f"{dev}: TCP Keepalive 설정 명령 없음" + (f" ({DGS_REF} 전체 확인)" if dgs3630 else "")
                                    + " - 유휴 세션 정리 동작은 제조사 확인 필요 (세션 타임아웃은 N-07)")
    else:
        ka = [x for x in ("in", "out") if on(rf"^\s*service tcp-keepalives-{x}\b")]
        r["N-25"] = ((RESULT_GOOD, "TCP Keepalive 설정 (service tcp-keepalives-in/out)") if len(ka) == 2
                     else (RESULT_BAD, "TCP Keepalive 미설정: service tcp-keepalives-" + "/".join(x for x in ("in", "out") if x not in ka)))
    r.update(svc("N-26", "Finger", r"^\s*(service finger|ip finger)\b"))
    http = on(r"^\s*ip http (server|secure-server)\b")
    hacl = on(r"^\s*ip http access-class\b")
    if http and hacl:
        r["N-27"] = (RESULT_GOOD, f"웹 서비스 활성({http}) - 접속 IP 제한 적용: {hacl}")
    elif http:
        r["N-27"] = (RESULT_BAD, f"웹 서비스 활성({http}) - 접속 IP 제한(ip http access-class) 미설정")
    else:
        r["N-27"] = (RESULT_GOOD, "웹 서비스(ip http server) 비활성")
    r.update(svc("N-28", "TCP/UDP small 서비스", r"^\s*service (tcp|udp)-small-servers?\b"))
    r.update(svc("N-29", "BOOTP 서버", r"^\s*ip bootp server\b"))
    if dlink:
        lldp = on(r"^\s*lldp run\b")
        r["N-30"] = ((RESULT_BAD, f"CDP 미지원 장비 - 유사 프로토콜 LLDP 활성: {lldp} (불필요 시 비활성화)") if lldp
                     else (RESULT_GOOD, f"CDP 미지원 장비({dev}), LLDP 활성 설정 없음"))
    else:
        nocdp = on(r"^\s*no cdp run\b")
        r["N-30"] = ((RESULT_GOOD, f"CDP 비활성: {nocdp}") if nocdp
                     else (RESULT_BAD, "CDP 기본 활성 (no cdp run 미설정)"))
    r.update(svc("N-35", "identd", r"^\s*ip identd\b"))
    nodl = on(r"^\s*no ip domain[- ]?lookup\b")
    if nodl:
        r["N-36"] = (RESULT_GOOD, f"Domain Lookup 비활성: {nodl}")
    elif dlink:
        dl = on(r"^\s*ip domain[- ]?lookup\b")
        r["N-36"] = ((RESULT_BAD, f"Domain Lookup 활성: {dl}") if dl
                     else (RESULT_GOOD, f"{dev}: ip domain lookup 설정 없음 - 기본값 비활성 ({DGS_REF})") if dgs3630
                     else (RESULT_MANUAL, f"{dev}: Domain Lookup 설정 없음 - 장비 기본값 확인 필요"))
    else:
        r["N-36"] = (RESULT_BAD, "Domain Lookup 기본 활성 (no ip domain-lookup 미설정)")
    r.update(svc("N-37", "PAD", r"^\s*service pad\b"))

    # ── 기능 관리: L3 인터페이스 ──
    if not l3_ifs:   # IP 가 설정된 인터페이스가 하나도 없음 → 해당 기능이 동작할 인터페이스 없음
        for code in ("N-31", "N-32", "N-33", "N-34", "N-38"):
            r[code] = (RESULT_GOOD, f"IP 가 설정된 인터페이스 없음({dtype}) - 해당 기능이 동작할 인터페이스 없음")
        return r   # 관리용 SVI 등 IP 인터페이스가 있으면 L2 스위치도 해당 인터페이스 기준으로 판정
    ifn = ", ".join(l3_ifs)
    l3sub = {h.split(None, 1)[1]: [x.lower() for x in sub] for h, sub in ifs if h.split(None, 1)[1] in l3_ifs}
    dbc = [n for n, sub in l3sub.items() if "ip directed-broadcast" in sub]
    r["N-31"] = ((RESULT_BAD, f"Directed Broadcast 허용 인터페이스: {', '.join(dbc)}") if dbc
                 else (RESULT_GOOD, f"L3 인터페이스({ifn})에 ip directed-broadcast 설정 없음 (기본 차단)"))
    if on(r"^\s*no ip source-route\b"):
        r["N-32"] = (RESULT_GOOD, "Source Routing 차단 (no ip source-route)")
    elif dlink:
        r["N-32"] = (RESULT_MANUAL, f"{dev}: Source Routing 차단 설정 명령 없음" + (f" ({DGS_REF} 전체 확인, DoS 방어 유형에도 없음)" if dgs3630 else "")
                                    + " - 소스 라우팅 패킷 처리 방식은 제조사 확인 필요")
    else:
        r["N-32"] = (RESULT_BAD, "Source Routing 기본 허용 (no ip source-route 미설정)")
    if dlink:
        pa = [n for n, sub in l3sub.items() if "ip proxy-arp" in sub or "ip local-proxy-arp" in sub]
        r["N-33"] = ((RESULT_BAD, f"Proxy ARP 활성 인터페이스: {', '.join(pa)}") if pa
                     else (RESULT_GOOD, f"{dev}: L3 인터페이스({ifn}) ip proxy-arp·ip local-proxy-arp 설정 없음 - 기본값 비활성 ({DGS_REF})") if dgs3630
                     else (RESULT_MANUAL, f"{dev}: L3 인터페이스({ifn}) Proxy ARP 설정 없음 - 장비 기본값 확인 필요"))
        un = [n for n, sub in l3sub.items() if "ip unreachables" in sub or "ip redirects" in sub]
        r["N-34"] = ((RESULT_BAD, f"ICMP unreachable/redirect 허용 인터페이스: {', '.join(un)}") if un
                     else (RESULT_MANUAL, f"{dev}: L3 인터페이스({ifn}) ICMP unreachable/redirect 차단 설정 명령 없음 ({DGS_REF} 전체 확인) - ICMP 오류 메시지 발송 여부는 제조사 확인 필요") if dgs3630
                     else (RESULT_MANUAL, f"{dev}: L3 인터페이스({ifn}) ICMP unreachable/redirect 설정 없음 - 장비 기본값 확인 필요"))
    else:
        pa = [n for n, sub in l3sub.items() if "no ip proxy-arp" not in sub]
        r["N-33"] = ((RESULT_BAD, f"Proxy ARP 기본 활성 (no ip proxy-arp 미설정): {', '.join(pa)}") if pa
                     else (RESULT_GOOD, "모든 L3 인터페이스 no ip proxy-arp 설정"))
        un = [n for n, sub in l3sub.items() if "no ip unreachables" not in sub or "no ip redirects" not in sub]
        r["N-34"] = ((RESULT_BAD, f"no ip unreachables / no ip redirects 미설정: {', '.join(un)}") if un
                     else (RESULT_GOOD, "모든 L3 인터페이스 ICMP unreachable/redirect 차단"))
    mr = [n for n, sub in l3sub.items() if "ip mask-reply" in sub]
    r["N-38"] = ((RESULT_BAD, f"mask-reply 허용 인터페이스: {', '.join(mr)}") if mr
                 else (RESULT_GOOD, f"L3 인터페이스({ifn})에 ip mask-reply 설정 없음 (기본 차단)"))
    return r


def detect_srv_os(text):
    """서버 파이프 출력 헤더 → OS_COLS_SRV 키 반환 (None = 탐지 실패)"""
    for line in text.splitlines()[:15]:
        s = line.strip().lstrip("#").strip()
        kv = s.split(":", 1)
        if len(kv) < 2: continue
        k = kv[0].strip().lower()
        v = kv[1].strip().upper()
        if k == "os":
            if "AIX"     in v: return "AIX"
            if "SOLARIS" in v or "SUNOS" in v: return "SOL"
            if "HPUX"    in v or "HP-UX" in v: return "HPUX"
            if "WINDOWS" in v or "WIN"   in v: return "WIN"
            return "LINUX"
    return None


def _infer_srv_os(res, evd_path=None):
    """OS 헤더가 없는 서버 결과 → 증적 헤더 또는 판정 사유 문구로 OS 추정 (None = 추정 불가)"""
    if evd_path and os.path.exists(evd_path):
        head = "\n".join(read_text(evd_path).splitlines()[:8])
        m = re.search(r"대상:\s*[^/\n]+/\s*(.+)", head)
        if m:
            got = detect_srv_os(f"# OS: {m.group(1)}")
            if got:
                return got
        if "PS>" in read_text(evd_path)[:4000]:
            return "WIN"
    blob = " ".join(w for _, w in res.values())
    win = len(re.findall(r"HKLM|레지스트리|Windows|RDP|NTFS|Get-|gpedit|로컬 보안 정책", blob, re.I))
    nix = len(re.findall(r"/etc/|pam|sshd|/var/|cron|umask|TMOUT|chmod|root", blob, re.I))
    if win >= 3 and win > nix * 2:
        return "WIN"
    if nix >= 3 and nix > win * 2:
        return "LINUX"
    return None


def detect_dbms_vendor(text):
    """DBMS 파이프 출력 헤더 → DB_COLS 키 반환 (None = 탐지 실패)"""
    head = [l for l in text.splitlines()[:25] if l.startswith("#")]
    if any(re.search(r"\d[\w.]*-mariadb|mariadb\s+\d|:\s*mariadb\b", l, re.I) for l in head):   # 버전 값이 MariaDB(예: 11.8.9-MariaDB) → MariaDB 기준 ('MySQL/MariaDB 버전' 머리말 문구는 제외)
        return "MariaDB"
    for line in text.splitlines()[:20]:
        s = line.strip().lstrip("#").strip()
        kv = s.split(":", 1)
        if len(kv) < 2: continue
        k = kv[0].strip().lower()
        v = kv[1].strip().lower()
        if k in ("dbms 종류", "dbms", "db", "db type", "db_type"):
            if "oracle"     in v: return "Oracle"
            if "mariadb"    in v: return "MariaDB"
            if "mysql"      in v: return "MySQL"
            if "mssql"      in v or "sql server" in v: return "MSSQL"
            if "postgresql" in v or "pgsql" in v: return "PostgreSQL"
            if "tibero"     in v: return "Tibero"
        elif k.startswith("sql server"):   # 구버전 check_dbms_mssql.ps1 결과: 'DBMS 종류' 없이 '# SQL Server 버전:' 만 출력
            return "MSSQL"
    return None


def detect_net_subtypes(text, lines):
    """네트워크 config → 적용되는 NET_COLS 키 목록 반환 (표시용)"""
    vendor = detect_net_vendor(text)
    dtype  = detect_net_dtype(lines)
    subs   = []
    if dtype in ("SW",  "L3SW"): subs.append("SW")
    if dtype in ("RTR", "L3SW"): subs.append("RTR")
    vendor_map = {"CISCO": "CISCO", "A10": "A10", "ALTEON": "ALTEON", "BIGIP": "ALTEON", "CITRIX": "ALTEON", "BROCADE": "ALTEON", "PIOLINK": "ALTEON", "JUNIPER": "JUNIPER"}
    if vendor in vendor_map:
        subs.append(vendor_map[vendor])
    return subs


def net_applicable(item, text, lines):
    """평가기준 '네트워크 장비' 평가대상: 장비 유형(스위치/라우터 열, L3 스위치는 둘 중 하나) 그리고
    벤더 그룹(A:CISCO / B:A10 / C:ALTEON 등 / D:JUNIPER 등) 열이 모두 'o' 여야 대상.
    그룹 미분류 벤더(D-Link·Dell 등)는 장비 유형 열만 적용."""
    ap = item.get("applies_to") or {}
    if not ap:
        return True
    dtype = detect_net_dtype(lines)
    dev = [t for t, d in (("SW", ("SW", "L3SW")), ("RTR", ("RTR", "L3SW"))) if dtype in d]
    dev_ok = any(ap.get(t) for t in dev)
    grp = {"CISCO": "CISCO", "A10": "A10", "ALTEON": "ALTEON", "BIGIP": "ALTEON", "CITRIX": "ALTEON", "BROCADE": "ALTEON", "PIOLINK": "ALTEON", "JUNIPER": "JUNIPER"}.get(detect_net_vendor(text))  # C그룹: BROCADE·ALTEON·NORTEL·BIGIP·CITRIX·PIOLINK
    return dev_ok and (grp is None or bool(ap.get(grp)))


def is_applicable(item, subtype):
    """criteria_items 항목이 주어진 subtype에 해당하는지 확인"""
    applies = item.get("applies_to", {})
    if not applies:
        return True  # 세부 컬럼 없는 시트 → 전체 적용
    return applies.get(subtype, False)


# ================================================================
# 주요정보통신기반시설 가이드 항목 매칭
# ================================================================
# 기준: 주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드 (한국인터넷진흥원, 2026)
#       — 2026판 PDF (873쪽, 작성 2025-12-23)
#       Unix U-01~U-67 / Windows W-01~W-64 / 웹 WEB-01~WEB-26 / 보안장비 S-01~S-23 / 네트워크 N-01~N-38 / PC PC-01~PC-18 / DBMS D-01~D-26
#       ※ 전자금융기반시설 평가기준(SRV/DBM/NET 등)과 항목코드·판단기준이 다름 — 이 표만 사용
# code: (중요도, 분류, 점검항목) — 주요정보(MI) 모드 보고서는 이 항목 체계로 출력
KISA_GUIDE_ITEMS = {
    # U — Unix 서버
    "U-01": ("상", "계정 관리", "root 계정 원격 접속 제한"),
    "U-02": ("상", "계정 관리", "비밀번호 관리정책 설정"),
    "U-03": ("상", "계정 관리", "계정 잠금 임계값 설정"),
    "U-04": ("상", "계정 관리", "비밀번호 파일 보호"),
    "U-05": ("상", "계정 관리", "root 이외의 UID가 '0' 금지"),
    "U-06": ("상", "계정 관리", "사용자 계정 su 기능 제한"),
    "U-07": ("하", "계정 관리", "불필요한 계정 제거"),
    "U-08": ("중", "계정 관리", "관리자 그룹에 최소한의 계정 포함"),
    "U-09": ("하", "계정 관리", "계정이 존재하지 않는 GID 금지"),
    "U-10": ("중", "계정 관리", "동일한 UID 금지"),
    "U-11": ("하", "계정 관리", "사용자 shell 점검"),
    "U-12": ("하", "계정 관리", "세션 종료 시간 설정"),
    "U-13": ("중", "계정 관리", "안전한 비밀번호 암호화 알고리즘 사용"),
    "U-14": ("상", "파일 및 디렉토리 관리", "root 홈, 패스 디렉터리 권한 및 패스 설정"),
    "U-15": ("상", "파일 및 디렉토리 관리", "파일 및 디렉터리 소유자 설정"),
    "U-16": ("상", "파일 및 디렉토리 관리", "/etc/passwd 파일 소유자 및 권한 설정"),
    "U-17": ("상", "파일 및 디렉토리 관리", "시스템 시작 스크립트 권한 설정"),
    "U-18": ("상", "파일 및 디렉토리 관리", "/etc/shadow 파일 소유자 및 권한 설정"),
    "U-19": ("상", "파일 및 디렉토리 관리", "/etc/hosts 파일 소유자 및 권한 설정"),
    "U-20": ("상", "파일 및 디렉토리 관리", "/etc/(x)inetd.conf 파일 소유자 및 권한 설정"),
    "U-21": ("상", "파일 및 디렉토리 관리", "/etc/(r)syslog.conf 파일 소유자 및 권한 설정"),
    "U-22": ("상", "파일 및 디렉토리 관리", "/etc/services 파일 소유자 및 권한 설정"),
    "U-23": ("상", "파일 및 디렉토리 관리", "SUID, SGID, Sticky bit 설정 파일 점검"),
    "U-24": ("상", "파일 및 디렉토리 관리", "사용자, 시스템 환경변수 파일 소유자 및 권한 설정"),
    "U-25": ("상", "파일 및 디렉토리 관리", "world writable 파일 점검"),
    "U-26": ("상", "파일 및 디렉토리 관리", "/dev에 존재하지 않는 device 파일 점검"),
    "U-27": ("상", "파일 및 디렉토리 관리", "$HOME/.rhosts, hosts.equiv 사용 금지"),
    "U-28": ("상", "파일 및 디렉토리 관리", "접속 IP 및 포트 제한"),
    "U-29": ("하", "파일 및 디렉토리 관리", "hosts.lpd 파일 소유자 및 권한 설정"),
    "U-30": ("중", "파일 및 디렉토리 관리", "UMASK 설정 관리"),
    "U-31": ("중", "파일 및 디렉토리 관리", "홈디렉토리 소유자 및 권한 설정"),
    "U-32": ("중", "파일 및 디렉토리 관리", "홈 디렉토리로 지정한 디렉토리의 존재 관리"),
    "U-33": ("하", "파일 및 디렉토리 관리", "숨겨진 파일 및 디렉토리 검색 및 제거"),
    "U-34": ("상", "서비스 관리", "Finger 서비스 비활성화"),
    "U-35": ("상", "서비스 관리", "공유 서비스에 대한 익명 접근 제한 설정"),
    "U-36": ("상", "서비스 관리", "r 계열 서비스 비활성화"),
    "U-37": ("상", "서비스 관리", "crontab 설정파일 권한 설정 미흡"),
    "U-38": ("상", "서비스 관리", "DoS 공격에 취약한 서비스 비활성화"),
    "U-39": ("상", "서비스 관리", "불필요한 NFS 서비스 비활성화"),
    "U-40": ("상", "서비스 관리", "NFS 접근 통제"),
    "U-41": ("상", "서비스 관리", "불필요한 automountd 제거"),
    "U-42": ("상", "서비스 관리", "불필요한 RPC 서비스 비활성화"),
    "U-43": ("상", "서비스 관리", "NIS, NIS+ 점검"),
    "U-44": ("상", "서비스 관리", "tftp, talk 서비스 비활성화"),
    "U-45": ("상", "서비스 관리", "메일 서비스 버전 점검"),
    "U-46": ("상", "서비스 관리", "일반 사용자의 메일 서비스 실행 방지"),
    "U-47": ("상", "서비스 관리", "스팸 메일 릴레이 제한"),
    "U-48": ("중", "서비스 관리", "expn, vrfy 명령어 제한"),
    "U-49": ("상", "서비스 관리", "DNS 보안 버전 패치"),
    "U-50": ("상", "서비스 관리", "DNS ZoneTransfer 설정"),
    "U-51": ("중", "서비스 관리", "DNS 서비스의 취약한 동적 업데이트 설정 금지"),
    "U-52": ("중", "서비스 관리", "Telnet 서비스 비활성화"),
    "U-53": ("하", "서비스 관리", "FTP 서비스 정보 노출 제한"),
    "U-54": ("중", "서비스 관리", "암호화되지 않는 FTP 서비스 비활성화"),
    "U-55": ("중", "서비스 관리", "FTP 계정 shell 제한"),
    "U-56": ("하", "서비스 관리", "FTP 서비스 접근 제어 설정"),
    "U-57": ("중", "서비스 관리", "Ftpusers 파일 설정"),
    "U-58": ("중", "서비스 관리", "불필요한 SNMP 서비스 구동 점검"),
    "U-59": ("상", "서비스 관리", "안전한 SNMP 버전 사용"),
    "U-60": ("중", "서비스 관리", "SNMP Community String 복잡성 설정"),
    "U-61": ("상", "서비스 관리", "SNMP Access Control 설정"),
    "U-62": ("하", "서비스 관리", "로그인 시 경고 메시지 설정"),
    "U-63": ("중", "서비스 관리", "sudo 명령어 접근 관리"),
    "U-64": ("상", "패치 관리", "주기적 보안 패치 및 벤더 권고사항 적용"),
    "U-65": ("중", "로그 관리", "NTP 및 시각 동기화 설정"),
    "U-66": ("중", "로그 관리", "정책에 따른 시스템 로깅 설정"),
    "U-67": ("중", "로그 관리", "로그 디렉터리 소유자 및 권한 설정"),
    # W — Windows 서버
    "W-01": ("상", "계정 관리", "Administrator 계정 이름 변경 등 보안성 강화"),
    "W-02": ("상", "계정 관리", "Guest 계정 비활성화"),
    "W-03": ("상", "계정 관리", "불필요한 계정 제거"),
    "W-04": ("상", "계정 관리", "계정 잠금 임계값 설정"),
    "W-05": ("상", "계정 관리", "해독 가능한 암호화를 사용하여 암호 저장 해제"),
    "W-06": ("상", "계정 관리", "관리자 그룹에 최소한의 사용자 포함"),
    "W-07": ("중", "계정 관리", "Everyone 사용 권한을 익명 사용자에 적용"),
    "W-08": ("중", "계정 관리", "계정 잠금 기간 설정"),
    "W-09": ("상", "계정 관리", "비밀번호 관리 정책 설정"),
    "W-10": ("중", "계정 관리", "마지막 사용자 이름 표시 안 함"),
    "W-11": ("중", "계정 관리", "로컬 로그온 허용"),
    "W-12": ("중", "계정 관리", "익명 SID/이름 변환 허용 해제"),
    "W-13": ("중", "계정 관리", "콘솔 로그온 시 로컬 계정에서 빈 암호 사용 제한"),
    "W-14": ("중", "계정 관리", "원격터미널 접속 가능한 사용자 그룹 제한"),
    "W-15": ("상", "서비스 관리", "사용자 개인키 사용 시 암호 입력"),
    "W-16": ("상", "서비스 관리", "공유 권한 및 사용자 그룹 설정"),
    "W-17": ("상", "서비스 관리", "하드디스크 기본 공유 제거"),
    "W-18": ("상", "서비스 관리", "불필요한 서비스 제거"),
    "W-19": ("상", "서비스 관리", "불필요한 IIS 서비스 구동 점검"),
    "W-20": ("상", "서비스 관리", "NetBIOS 바인딩 서비스 구동 점검"),
    "W-21": ("상", "서비스 관리", "암호화되지 않는 FTP 서비스 비활성화"),
    "W-22": ("상", "서비스 관리", "FTP 디렉토리 접근권한 설정"),
    "W-23": ("상", "서비스 관리", "공유 서비스에 대한 익명 접근 제한 설정"),
    "W-24": ("상", "서비스 관리", "FTP 접근 제어 설정"),
    "W-25": ("상", "서비스 관리", "DNS Zone Transfer 설정"),
    "W-26": ("상", "서비스 관리", "RDS(Remote Data Services)제거"),
    "W-27": ("상", "서비스 관리", "최신 Windows OS Build 버전 적용"),
    "W-28": ("중", "서비스 관리", "터미널 서비스 암호화 수준 설정"),
    "W-29": ("중", "서비스 관리", "불필요한 SNMP 서비스 구동 점검"),
    "W-30": ("중", "서비스 관리", "SNMP Community String 복잡성 설정"),
    "W-31": ("중", "서비스 관리", "SNMP Access Control 설정"),
    "W-32": ("중", "서비스 관리", "DNS 서비스 구동 점검"),
    "W-33": ("하", "서비스 관리", "HTTP/FTP/SMTP 배너 차단"),
    "W-34": ("중", "서비스 관리", "Telnet 서비스 비활성화"),
    "W-35": ("중", "서비스 관리", "불필요한 ODBC/OLE-DB 데이터 소스와 드라이브 제거"),
    "W-36": ("중", "서비스 관리", "원격터미널 접속 타임아웃 설정"),
    "W-37": ("중", "서비스 관리", "예약된 작업에 의심스러운 명령이 등록되어 있는지 점검"),
    "W-38": ("상", "패치 관리", "주기적 보안 패치 및 벤더 권고사항 적용"),
    "W-39": ("상", "패치 관리", "백신 프로그램 업데이트"),
    "W-40": ("중", "로그 관리", "정책에 따른 시스템 로깅 설정"),
    "W-41": ("중", "로그 관리", "NTP 및 시각 동기화 설정"),
    "W-42": ("하", "로그 관리", "이벤트 로그 관리 설정"),
    "W-43": ("중", "로그 관리", "이벤트 로그 파일 접근 통제 설정"),
    "W-44": ("상", "보안 관리", "원격으로 액세스할 수 있는 레지스트리 경로"),
    "W-45": ("상", "보안 관리", "백신 프로그램 설치"),
    "W-46": ("상", "보안 관리", "SAM 파일 접근 통제 설정"),
    "W-47": ("하", "보안 관리", "화면 보호기 설정"),
    "W-48": ("상", "보안 관리", "로그온하지 않고 시스템 종료 허용"),
    "W-49": ("상", "보안 관리", "원격 시스템에서 강제로 시스템 종료"),
    "W-50": ("상", "보안 관리", "보안 감사를 로그 할 수 없는 경우 즉시 시스템 종료"),
    "W-51": ("상", "보안 관리", "SAM 계정과 공유의 익명 열거 허용 안 함"),
    "W-52": ("상", "보안 관리", "Autologon 기능 제어"),
    "W-53": ("상", "보안 관리", "이동식 미디어 포맷 및 꺼내기 허용"),
    "W-54": ("중", "보안 관리", "Dos 공격 방어 레지스트리 설정"),
    "W-55": ("중", "보안 관리", "사용자가 프린터 드라이버를 설치할 수 없게 함"),
    "W-56": ("중", "보안 관리", "SMB 세션 중단 관리 설정"),
    "W-57": ("하", "보안 관리", "로그온 시 경고 메시지 설정"),
    "W-58": ("중", "보안 관리", "사용자별 홈 디렉터리 권한 설정"),
    "W-59": ("중", "보안 관리", "LAN Manager 인증 수준"),
    "W-60": ("중", "보안 관리", "보안 채널 데이터 디지털 암호화 또는 서명"),
    "W-61": ("중", "보안 관리", "파일 및 디렉토리 보호"),
    "W-62": ("중", "보안 관리", "시작 프로그램 목록 분석"),
    "W-63": ("중", "보안 관리", "도메인 컨트롤러-사용자의 시간 동기화"),
    "W-64": ("중", "보안 관리", "윈도우 방화벽 설정"),
    # WEB — 웹 서비스
    "WEB-01": ("상", "계정 관리", "Default 관리자 계정명 변경"),
    "WEB-02": ("상", "계정 관리", "취약한 비밀번호 사용 제한"),
    "WEB-03": ("상", "계정 관리", "비밀번호 파일 권한 관리"),
    "WEB-04": ("상", "서비스 관리", "웹 서비스 디렉터리 리스팅 방지 설정"),
    "WEB-05": ("상", "서비스 관리", "지정하지 않은 CGI/ISAPI 실행 제한"),
    "WEB-06": ("상", "서비스 관리", "웹 서비스 상위 디렉터리 접근 제한 설정"),
    "WEB-07": ("중", "서비스 관리", "웹 서비스 경로 내 불필요한 파일 제거"),
    "WEB-08": ("하", "서비스 관리", "웹 서비스 파일 업로드 및 다운로드 용량 제한"),
    "WEB-09": ("상", "서비스 관리", "웹 서비스 프로세스 권한 제한"),
    "WEB-10": ("상", "서비스 관리", "불필요한 프록시 설정 제한"),
    "WEB-11": ("중", "서비스 관리", "웹 서비스 경로 설정"),
    "WEB-12": ("중", "서비스 관리", "웹 서비스 링크 사용 금지"),
    "WEB-13": ("상", "서비스 관리", "웹 서비스 설정 파일 노출 제한"),
    "WEB-14": ("상", "서비스 관리", "웹 서비스 경로 내 파일의 접근 통제"),
    "WEB-15": ("상", "서비스 관리", "웹 서비스의 불필요한 스크립트 매핑 제거"),
    "WEB-16": ("중", "서비스 관리", "웹 서비스 헤더 정보 노출 제한"),
    "WEB-17": ("중", "서비스 관리", "웹 서비스 가상 디렉로리 삭제"),
    "WEB-18": ("상", "서비스 관리", "웹 서비스 WebDAV 비활성화"),
    "WEB-19": ("중", "보안 설정", "웹 서비스 SSI(Server Side Includes) 사용 제한"),
    "WEB-20": ("상", "보안 설정", "SSL/TLS 활성화"),
    "WEB-21": ("중", "보안 설정", "HTTP 리디렉션"),
    "WEB-22": ("하", "보안 설정", "에러 페이지 관리"),
    "WEB-23": ("중", "보안 설정", "LDAP 알고리즘 적절하게 구성"),
    "WEB-24": ("중", "보안 설정", "별도의 업로드 경로 사용 및 권한 설정"),
    "WEB-25": ("상", "패치 및 로그 관리", "주기적 보안 패치 및 벤더 권고사항 적용"),
    "WEB-26": ("중", "패치 및 로그 관리", "로그 디렉터리 및 파일 권한 설정"),
    # S — 보안장비
    "S-01": ("상", "계정 관리", "보안장비 Default 계정 변경"),
    "S-02": ("상", "계정 관리", "비밀번호 관리정책 설정"),
    "S-03": ("상", "계정 관리", "보안장비 계정별 권한 설정"),
    "S-04": ("상", "계정 관리", "보안장비 계정 관리"),
    "S-05": ("상", "계정 관리", "계정 잠금 임계값 설정"),
    "S-06": ("상", "접근 관리", "보안 장비 원격 관리 접근 통제"),
    "S-07": ("상", "접근 관리", "보안장비 보안 접속"),
    "S-08": ("상", "접근 관리", "세션 종료 시간 설정"),
    "S-09": ("상", "패치 관리", "주기적 보안 패치 및 벤더 권고사항 적용"),
    "S-10": ("중", "로그 관리", "보안장비 로그 설정"),
    "S-11": ("중", "로그 관리", "보안장비 로그 보관"),
    "S-12": ("중", "로그 관리", "보안장비 정책 백업 설정"),
    "S-13": ("중", "로그 관리", "원격 로그 서버 사용"),
    "S-14": ("중", "로그 관리", "NTP 및 시각 동기화 설정"),
    "S-15": ("상", "기능 관리", "정책 관리"),
    "S-16": ("상", "기능 관리", "NAT 설정"),
    "S-17": ("상", "기능 관리", "DMZ 설정"),
    "S-18": ("상", "기능 관리", "최소한의 서비스만 제공"),
    "S-19": ("상", "기능 관리", "이상징후 탐지 모니터링 수행"),
    "S-20": ("상", "기능 관리", "장비 사용량 검토"),
    "S-21": ("상", "기능 관리", "SNMP 서비스 확인"),
    "S-22": ("상", "기능 관리", "SNMP Community String 복잡성 설정"),
    "S-23": ("중", "기능 관리", "유해 트래픽 탐지/차단 정책 설정"),
    # N — 네트워크 장비
    "N-01": ("상", "계정 관리", "비밀번호 설정"),
    "N-02": ("상", "계정 관리", "비밀번호 복잡성 설정"),
    "N-03": ("상", "계정 관리", "암호화된 비밀번호 사용"),
    "N-04": ("상", "계정 관리", "계정 잠금 임계값 설정"),
    "N-05": ("중", "계정 관리", "사용자·명령어별 권한 설정"),
    "N-06": ("상", "접근 관리", "VTY 접근(ACL) 설정"),
    "N-07": ("상", "접근 관리", "Session Timeout 설정"),
    "N-08": ("중", "접근 관리", "VTY 접속 시 안전한 프로토콜 사용"),
    "N-09": ("중", "접근 관리", "불필요한 보조 입출력 포트 사용 금지"),
    "N-10": ("중", "접근 관리", "로그인 시 경고 메시지 설정"),
    "N-11": ("중", "접근 관리", "원격로그 서버 사용"),
    "N-12": ("상", "패치 관리", "주기적 보안 패치 및 벤더 권고사항 적용"),
    "N-13": ("중", "로그 관리", "로깅 버퍼 크기 설정"),
    "N-14": ("중", "로그 관리", "정책에 따른 로깅 설정"),
    "N-15": ("중", "로그 관리", "NTP 및 시각 동기화 설정"),
    "N-16": ("하", "로그 관리", "Timestamp 로그 설정"),
    "N-17": ("상", "기능 관리", "SNMP 서비스 확인"),
    "N-18": ("상", "기능 관리", "SNMP Community String 복잡성 설정"),
    "N-19": ("상", "기능 관리", "SNMP ACL 설정"),
    "N-20": ("상", "기능 관리", "SNMP Community 권한 설정"),
    "N-21": ("상", "기능 관리", "TFTP 서비스 차단"),
    "N-22": ("상", "기능 관리", "Spoofing 방지 필터링 적용"),
    "N-23": ("상", "기능 관리", "DDoS 공격 방어 설정 또는 DDoS 장비 사용"),
    "N-24": ("상", "기능 관리", "사용하지 않는 인터페이스 비활성화"),
    "N-25": ("중", "기능 관리", "TCP Keepalive 서비스 설정"),
    "N-26": ("중", "기능 관리", "Finger 서비스 차단"),
    "N-27": ("중", "기능 관리", "웹 서비스 차단"),
    "N-28": ("중", "기능 관리", "TCP/UDP small 서비스 차단"),
    "N-29": ("중", "기능 관리", "Bootp 서비스 차단"),
    "N-30": ("중", "기능 관리", "CDP 서비스 차단"),
    "N-31": ("중", "기능 관리", "Directed-broadcast 차단"),
    "N-32": ("중", "기능 관리", "Source Routing 차단"),
    "N-33": ("중", "기능 관리", "Proxy ARP 차단"),
    "N-34": ("중", "기능 관리", "ICMP unreachable, redirect 차단"),
    "N-35": ("중", "기능 관리", "identd 서비스 차단"),
    "N-36": ("중", "기능 관리", "Domain Lookup 차단"),
    "N-37": ("중", "기능 관리", "pad 차단"),
    "N-38": ("중", "기능 관리", "mask-reply 차단"),
    # PC — PC
    "PC-01": ("상", "계정 관리", "비밀번호의 주기적 변경"),
    "PC-02": ("상", "계정 관리", "비밀번호 관리정책 설정"),
    "PC-03": ("중", "계정 관리", "복구 콘솔에서 자동 로그온을 금지하도록 설정"),
    "PC-04": ("상", "서비스 관리", "공유 폴더 제거"),
    "PC-05": ("상", "서비스 관리", "항목의 불필요한 서비스 제거"),
    "PC-06": ("상", "서비스 관리", "비인가 상용 메신저 사용 금지"),
    "PC-07": ("중", "서비스 관리", "파일 시스템이 NTFS 포맷으로 설정"),
    "PC-08": ("중", "서비스 관리", "대상 시스템이 Windows 서버를 제외한 다른 OS로 멀티 부팅이 가능하지 않도록 설정"),
    "PC-09": ("하", "서비스 관리", "브라우저 종료 시 임시 인터넷 파일 폴더의 내용을 삭제하도록 설정"),
    "PC-10": ("상", "패치 관리", "주기적 보안 패치 및 벤더 권고사항 적용"),
    "PC-11": ("상", "패치 관리", "지원이 종료되지 않은 Windows OS Build 적용"),
    "PC-12": ("중", "보안 관리", "Windows 자동 로그인 점검"),
    "PC-13": ("상", "보안 관리", "바이러스 백신 프로그램 설치 및 주기적 업데이트"),
    "PC-14": ("상", "보안 관리", "바이러스 백신 프로그램에서 제공하는 실시간 감시 기능 활성화"),
    "PC-15": ("상", "보안 관리", "OS에서 제공하는 침입차단 기능 활성화"),
    "PC-16": ("상", "보안 관리", "화면보호기 대기 시간 설정 및 재시작 시 암호 보호 설정"),
    "PC-17": ("상", "보안 관리", "CD, DVD, USB 메모리 등과 같은 미디어의 자동 실행 방지 등 이동식 미디어에 대한 보안대책 수립"),
    "PC-18": ("중", "보안 관리", "원격 지원을 금지하도록 정책이 설정"),
    # D — DBMS
    "D-01": ("상", "계정 관리", "기본 계정의 비밀번호, 정책 등을 변경하여 사용"),
    "D-02": ("상", "계정 관리", "데이터베이스의 불필요 계정을 제거하거나, 잠금설정 후 사용"),
    "D-03": ("상", "계정 관리", "비밀번호 사용 기간 및 복잡도를 기관의 정책에 맞도록 설정"),
    "D-04": ("상", "계정 관리", "데이터베이스 관리자 권한을 꼭 필요한 계정 및 그룹에 대해서만 허용"),
    "D-05": ("중", "계정 관리", "비밀번호 재사용에 대한 제약 설정"),
    "D-06": ("중", "계정 관리", "DB 사용자 계정을 개별적으로 부여하여 사용"),
    "D-07": ("중", "계정 관리", "root 권한으로 서비스 구동 제한"),
    "D-08": ("상", "계정 관리", "안전한 암호화 알고리즘 사용"),
    "D-09": ("중", "계정 관리", "일정 횟수의 로그인 실패 시 이에 대한 잠금정책 설정"),
    "D-10": ("상", "접근 관리", "원격에서 DB 서버로의 접속 제한"),
    "D-11": ("상", "접근 관리", "DBA 이외의 인가되지 않은 사용자가 시스템 테이블에 접근할 수 없도록 설정"),
    "D-12": ("상", "접근 관리", "안전한 리스너 비밀번호 설정 및 사용"),
    "D-13": ("중", "접근 관리", "불필요한 ODBC/OLE-DB 데이터 소스와 드라이브를 제거하여 사용"),
    "D-14": ("중", "접근 관리", "데이터베이스의 주요 설정 파일, 비밀번호 파일 등과 같은 주요 파일들의 접근 권한이 적절하게 설정"),
    "D-15": ("하", "접근 관리", "관리자 이외의 사용자가 오라클 리스너의 접속을 통해 리스너 로그 및 trace 파일에 대한 변경 제한"),
    "D-16": ("하", "접근 관리", "Windows 인증 모드 사용"),
    "D-17": ("하", "옵션 관리", "Audit Table은 데이터베이스 관리자 계정으로 접근하도록 제한"),
    "D-18": ("상", "옵션 관리", "응용프로그램 또는 DBA 계정의 Role이 Public으로 설정되지 않도록 조정"),
    "D-19": ("상", "옵션 관리", "OS_ROLES, REMOTE_OS_AUTHENTICATION, REMOTE_OS_ROLES를 FALSE로 설정"),
    "D-20": ("하", "옵션 관리", "인가되지 않은 Object Owner의 제한"),
    "D-21": ("중", "옵션 관리", "인가되지 않은 GRANT OPTION 사용 제한"),
    "D-22": ("하", "옵션 관리", "데이터베이스의 자원 제한 기능을 TRUE로 설정"),
    "D-23": ("상", "옵션 관리", "xp_cmdshell 사용 제한"),
    "D-24": ("상", "옵션 관리", "Registry Procedure 권한 제한"),
    "D-25": ("상", "패치 관리", "주기적 보안 패치 및 벤더 권고 사항 적용"),
    "D-26": ("상", "패치 관리", "데이터베이스의 접근, 변경, 삭제 등의 감사 기록이 기관의 감사 기록 정책에 적합하도록 설정"),
}




# 가이드 판단기준·조치방법 (code: (양호, 취약, 조치방법)) — 주요정보(MI) 보고서의 판단기준/문제점/개선방안 문구
# 출처: 위 2026 상세가이드 항목별 '판단기준'·'조치방법' 원문
KISA_GUIDE_CRITERIA = {
    "U-01": ("원격터미널 서비스를 사용하지 않거나, 사용 시 root 직접 접속을 차단한 경우",
             "원격터미널 서비스 사용 시 root 직접 접속을 허용한 경우",
             "원격 접속 시 root 계정으로 접속할 수 없도록 파일 내용 설정"),
    "U-02": ("비밀번호 관리 정책이 설정된 경우",
             "비밀번호 관리 정책이 설정되지 않은 경우",
             "root 계정을 포함한 사용자 계정의 비밀번호를 영문, 숫자, 특수문자를 포함하여 최소 8자리 이상 및 최소 사용 기간 1일, 최대 사용 기간 90일, 최근 비밀번호 기억 4회 이상으로 설정"),
    "U-03": ("계정 잠금 임계값이 10회 이하의 값으로 설정된 경우",
             "계정 잠금 임계값이 설정되어 있지 않거나, 10회 이하의 값으로 설정되지 않은 경우",
             "계정 잠금 임계값을 10회 이하로 설정"),
    "U-04": ("쉐도우 비밀번호를 사용하거나, 비밀번호를 암호화하여 저장하는 경우",
             "쉐도우 비밀번호를 사용하지 않고, 비밀번호를 암호화하여 저장하지 않는 경우",
             "비밀번호 암호화 저장·관리 설정"),
    "U-05": ("root 계정과 동일한 UID를 갖는 계정이 존재하지 않는 경우",
             "root 계정과 동일한 UID를 갖는 계정이 존재하는 경우",
             "Ÿ UID가 0으로 설정된 계정을 0 이외의 중복되지 않은 UID로 변경 또는 불필요한 계정인 경우 제거하도록 설정 Ÿ (사용 중인 계정인 경우 명령어를 통한 조치가 적용되지 않을 수 있으므로 /etc/passwd 파일을 통해 변경)"),
    "U-06": ("su 명령어를 특정 그룹에 속한 사용자만 사용하도록 제한된 경우 ※ 일반 사용자 계정 없이 root 계정만 사용하는 경우 su 명령어 사용 제한 불필요",
             "su 명령어를 모든 사용자가 사용하도록 설정된 경우",
             "PAM 모듈 설정 또는 su 명령어 허용 그룹 생성 후 su 명령어 일반 사용자 권한 제거하도록 설정"),
    "U-07": ("불필요한 계정이 존재하지 않는 경우",
             "불필요한 계정이 존재하는 경우",
             "시스템에 존재하는 계정 확인 후 불필요한 계정 제거하도록 설정"),
    "U-08": ("관리자 그룹에 불필요한 계정이 등록되어 있지 않은 경우",
             "관리자 그룹에 불필요한 계정이 등록된 경우",
             "관리자 그룹에 등록된 계정 확인 후 불필요한 계정 제거하도록 설정"),
    "U-09": ("시스템 관리나 운용에 불필요한 그룹이 제거된 경우",
             "시스템 관리나 운용에 불필요한 그룹이 존재하는 경우",
             "불필요한 그룹이 존재하는 경우 관리자와 검토하여 제거하도록 설정 ※ /etc/group 파일과 /etc/passwd 파일을 비교하여 점검하기를 권고함"),
    "U-10": ("동일한 UID로 설정된 사용자 계정이 존재하지 않는 경우",
             "동일한 UID로 설정된 사용자 계정이 존재하는 경우",
             "동일한 UID를 가진 사용자 계정의 UID를 중복되지 않도록 변경하도록 설정"),
    "U-11": ("로그인이 필요하지 않은 계정에 /bin/false(/sbin/nologin) 쉘이 부여된 경우",
             "로그인이 필요하지 않은 계정에 /bin/false(/sbin/nologin) 쉘이 부여되지 않은 경우",
             "로그인이 필요하지 않은 계정에 대해 /bin/false(/sbin/nologin) 쉘 부여 설정"),
    "U-12": ("Session Timeout이 600초(10분) 이하로 설정된 경우",
             "Session Timeout이 600초(10분) 이하로 설정되지 않은 경우",
             "600초(10분) 동안 입력이 없는 경우 접속된 Session을 끊도록 설정"),
    "U-13": ("SHA-2 이상의 안전한 비밀번호 암호화 알고리즘을 사용하는 경우",
             "취약한 비밀번호 암호화 알고리즘을 사용하는 경우",
             "SHA-2 이상의 안전한 비밀번호 암호화 알고리즘 적용 설정"),
    "U-14": ("PATH 환경변수에 \".\" 이 맨 앞이나 중간에 포함되지 않은 경우",
             "PATH 환경변수에 \".\" 이 맨 앞이나 중간에 포함된 경우",
             "root 계정의 환경설정 파일(/.profile, /.bashrc 등)과 시스템 환경설정 파일(/etc/profile 등)에 설정된 PATH 환경변수에서 현재 디렉터리를 나타내는 \".\"을 PATH 환경변수의 마지막으로 이동하도록 설정 ※ /etc/profile 파일, root 계정, 일반 사용자 계정의 환경설정 파일을 순차적으로 검색하여 확인"),
    "U-15": ("소유자가 존재하지 않는 파일 및 디렉터리가 존재하지 않는 경우",
             "소유자가 존재하지 않는 파일 및 디렉터리가 존재하는 경우",
             "소유자가 존재하지 않는 파일 및 디렉터리 제거 또는 소유자 변경 설정"),
    "U-16": ("/etc/passwd 파일의 소유자가 root이고, 권한이 644 이하인 경우",
             "/etc/passwd 파일의 소유자가 root가 아니거나, 권한이 644 이하가 아닌 경우",
             "/etc/passwd 파일 소유자 및 권한 변경 설정"),
    "U-17": ("시스템 시작 스크립트 파일의 소유자가 root이고, 일반 사용자의 쓰기 권한이 제거된 경우",
             "시스템 시작 스크립트 파일의 소유자가 root가 아니거나, 일반 사용자의 쓰기 권한이 부여된 경우",
             "시스템 시작 스크립트 파일 소유자 및 권한 변경 설정"),
    "U-18": ("/etc/shadow 파일의 소유자가 root이고, 권한이 400 이하인 경우",
             "/etc/shadow 파일의 소유자가 root가 아니거나, 권한이 400 이하가 아닌 경우",
             "/etc/shadow 파일 소유자 및 권한 변경 설정"),
    "U-19": ("/etc/hosts 파일의 소유자가 root이고, 권한이 644 이하인 경우",
             "/etc/hosts 파일의 소유자가 root가 아니거나, 권한이 644 이하가 아닌 경우",
             "/etc/hosts 파일 소유자 및 권한 변경 설정"),
    "U-20": ("/etc/(x)inetd.conf 파일의 소유자가 root이고, 권한이 600 이하인 경우",
             "/etc/(x)inetd.conf 파일의 소유자가 root가 아니거나, 권한이 600 이하가 아닌 경우",
             "/etc/(x)inetd.conf 파일 소유자 및 권한 변경 설정"),
    "U-21": ("/etc/(r)syslog.conf 파일의 소유자가 root(또는 bin, sys)이고, 권한이 640 이하인 경우",
             "/etc/(r)syslog.conf 파일의 소유자가 root(또는 bin, sys)가 아니거나, 권한이 640 이하가 아닌 경우",
             "/etc/(r)syslog.conf 파일 소유자 및 권한 변경 설정"),
    "U-22": ("/etc/services 파일의 소유자가 root(또는 bin, sys)이고, 권한이 644 이하인 경우",
             "/etc/services 파일의 소유자가 root(또는 bin, sys)가 아니거나, 권한이 644 이하가 아닌 경우",
             "/etc/ services 파일 소유자 및 권한 변경 설정"),
    "U-23": ("주요 실행 파일의 권한에 SUID와 SGID에 대한 설정이 부여되어 있지 않은 경우",
             "주요 실행 파일의 권한에 SUID와 SGID에 대한 설정이 부여된 경우",
             "Ÿ 불필요한 SUID, SGID 권한 또는 해당 파일 제거하도록 설정 Ÿ 애플리케이션에서 생성한 파일이나 사용자가 임의로 생성한 파일 등 의심스럽거나 특이한 파일에 SUID 권한이 부여된 경우 제거하도록 설정"),
    "U-24": ("홈 디렉터리 환경변수 파일 소유자가 root 또는 해당 계정으로 지정되어 있고, 홈 디렉터리 환경변수 파일에 root 계정과 소유자만 쓰기 권한이 부여된 경우",
             "홈 디렉터리 환경변수 파일 소유자가 root 또는 해당 계정으로 지정되지 않거나, 홈 디렉터리 환경변수 파일에 root 계정과 소유자 외에 쓰기 권한이 부여된 경우",
             "환경변수 파일의 일반 사용자 쓰기 권한 제거하도록 설정"),
    "U-25": ("world writable 파일이 존재하지 않거나, 존재 시 설정 이유를 인지하고 있는 경우",
             "world writable 파일이 존재하나 설정 이유를 인지하지 못하고 있는 경우",
             "world writable 파일 존재 여부를 확인하고 불필요한 경우 제거하도록 설정"),
    "U-26": ("/dev 디렉터리에 대한 파일 점검 후 존재하지 않는 device 파일을 제거한 경우",
             "/dev 디렉터리에 대한 파일 미점검 또는 존재하지 않는 device 파일을 방치한 경우",
             "major, minor number를 가지지 않는 device 파일 제거하도록 설정"),
    "U-27": ("rlogin, rsh, rexec 서비스를 사용하지 않거나, 사용 시 아래와 같은 설정이 적용된 경우 1. /etc/hosts.equiv 및 $HOME/.rhosts 파일 소유자가 root 또는 해당 계정인 경우 2. /etc/hosts.equiv 및 $HOME/.rhosts 파일 권한이 600 이하인 경우 3. /etc/hosts.equiv 및 $HOME/.rhosts 파일 설정에 \"+\" 설정이 없는 경우",
             "rlogin, rsh, rexec 서비스를 사용하며 아래와 같은 설정이 적용되지 않은 경우 1. /etc/hosts.equiv 및 $HOME/.rhosts 파일 소유자가 root 또는 해당 계정이 아닌 경우 2. /etc/hosts.equiv 및 $HOME/.rhosts 파일 권한이 600을 초과한 경우 3. /etc/hosts.equiv 및 $HOME/.rhosts 파일 설정에 \"+\" 설정이 존재하는 경우",
             "/etc/hosts.equiv, $HOME/.rhosts 파일 소유자 및 권한 변경, 허용 호스트 및 계정 등록 설정"),
    "U-28": ("접속을 허용할 특정 호스트에 대한 IP주소 및 포트 제한을 설정한 경우",
             "접속을 허용할 특정 호스트에 대한 IP주소 및 포트 제한을 설정하지 않은 경우",
             "OS에 기본으로 제공하는 방화벽 애플리케이션이나 TCP Wrapper와 같은 호스트별 서비스 제한 애플리케이션을 사용하여 접근 허용 IP 등록 설정"),
    "U-29": ("/etc/hosts.lpd 파일이 존재하지 않거나, 불가피하게 사용 시 /etc/hosts.lpd 파일의 소유자가 root이고, 권한이 600 이하인 경우",
             "/etc/hosts.lpd 파일이 존재하며, 파일의 소유자가 root가 아니거나, 권한이 600 이하가 아닌 경우",
             "/etc/hosts.lpd 파일 제거 또는 /etc/hosts.lpd 파일 소유자 및 권한 변경 설정"),
    "U-30": ("UMASK 값이 022 이상으로 설정된 경우",
             "UMASK 값이 022 미만으로 설정된 경우",
             "설정 파일에 UMASK 값을 022로 설정"),
    "U-31": ("홈 디렉토리 소유자가 해당 계정이고, 타 사용자 쓰기 권한이 제거된 경우",
             "홈 디렉토리 소유자가 해당 계정이 아니거나, 타 사용자 쓰기 권한이 부여된 경우",
             "사용자별 홈 디렉토리 소유주를 해당 계정으로 변경하고, 타 사용자의 쓰기 권한 제거하도록 설정 (/etc/passwd 파일에서 홈 디렉토리 확인, 사용자 홈 디렉토리 외 개별적으로 만들어 사용하는 사용자 디렉토리 존재 여부 확인하여 점검)"),
    "U-32": ("홈 디렉토리가 존재하지 않는 계정이 발견되지 않는 경우",
             "홈 디렉토리가 존재하지 않는 계정이 발견된 경우",
             "홈 디렉토리가 존재하지 않는 계정에 홈 디렉토리 설정 또는 계정 제거하도록 설정"),
    "U-33": ("불필요하거나 의심스러운 숨겨진 파일 및 디렉토리를 제거한 경우",
             "불필요하거나 의심스러운 숨겨진 파일 및 디렉토리를 제거하지 않은 경우",
             "ls -al 명령어로 숨겨진 파일 존재 파악 후 불법적이거나 의심스러운 파일을 제거하도록 설정"),
    "U-34": ("Finger 서비스가 비활성화된 경우",
             "Finger 서비스가 활성화된 경우",
             "Finger 서비스 비활성화 설정"),
    "U-35": ("공유 서비스에 대해 익명 접근을 제한한 경우",
             "공유 서비스에 대해 익명 접근을 허용한 경우",
             "공유 서비스의 익명 접근 제한 설정"),
    "U-36": ("불필요한 r 계열 서비스가 비활성화된 경우",
             "불필요한 r 계열 서비스가 활성화된 경우",
             "불필요한 r 계열 서비스 중지 및 비활성화 설정 ※ NET Backup 등 특별한 용도로 사용하지 않는다면 shell(514), login(513), exec(512) 서비스 중 지 ※ rlogin, rsh, rexec 서비스는 backup, 클러스터링 등의 용도로 종종 사용되고 있으므로 해당 서비 스 사용 유무를 확인하여 미사용시 서비스 중지 ※ /etc/hosts.equiv 또는 $HOME/.rhosts 파일을 통해 해당 서비스 사용 여부 확인 (파일이 존재 하지 않거나 해당 파일 내에 설정이 없다면 사용하지 않는 것으로 간주)"),
    "U-37": ("crontab 및 at 명령어에 일반 사용자 실행 권한이 제거되어 있으며, cron 및 at 관련 파일 권한이 640 이하인 경우",
             "crontab 및 at 명령어에 일반 사용자 실행 권한이 부여되어 있으며, cron 및 at 관련 파일 권한이 640 이상인 경우",
             "crontab 및 at 명령어 파일 권한 750 이하, cron 및 at 관련 파일 소유자 및 파일 권한 640 이하 설정"),
    "U-38": ("DoS 공격에 취약한 서비스가 비활성화된 경우",
             "DoS 공격에 취약한 서비스가 활성화된 경우",
             "echo, discard, daytime, chargen, ntp, dns, snmp 등의 서비스 비활성화 설정"),
    "U-39": ("불필요한 NFS 서비스 관련 데몬이 비활성화된 경우",
             "불필요한 NFS 서비스 관련 데몬이 활성화된 경우",
             "NFS 서비스를 사용하지 않는 경우 서비스 중지 및 비활성화 설정 ※ 로컬 서버에 마운트 되어 있는 디렉터리 제거 및 공유 디렉터리 제거 후 서비스 중지 가능"),
    "U-40": ("접근 통제가 설정되어 있으며 NFS 설정 파일 접근 권한이 644 이하인 경우",
             "접근 통제가 설정되어 있지 않고 NFS 설정 파일 접근 권한이 644를 초과하는 경우",
             "Ÿ NFS 서비스를 사용하지 않는 경우 서비스 중지 및 비활성화 설정 Ÿ 불가피하게 사용 시 접근 통제 설정 및 NFS 설정 파일 접근 권한 644 설정"),
    "U-41": ("automountd 서비스가 비활성화된 경우",
             "automountd 서비스가 활성화된 경우",
             "automountd 서비스 비활성화 설정"),
    "U-42": ("불필요한 RPC 서비스가 비활성화된 경우",
             "불필요한 RPC 서비스가 활성화된 경우",
             "불필요한 RPC 서비스 중지 및 비활성화 설정"),
    "U-43": ("NIS 서비스가 비활성화되어 있거나, 불가피하게 사용 시 NIS+ 서비스를 사용하는 경우",
             "NIS 서비스가 활성화된 경우",
             "NIS 관련 서비스 비활성화 설정"),
    "U-44": ("tftp, talk, ntalk 서비스가 비활성화된 경우",
             "tftp, talk, ntalk 서비스가 활성화된 경우",
             "불필요한 tftp, talk, ntalk 서비스 비활성화 설정"),
    "U-45": ("메일 서비스 버전이 최신 버전인 경우",
             "메일 서비스 버전이 최신 버전이 아닌 경우",
             "Ÿ 메일 서비스를 사용하지 않는 경우 서비스 중지 및 비활성화 설정 Ÿ 메일 서비스 사용 시 패치 관리 정책을 수립하여 주기적으로 패치 적용 설정"),
    "U-46": ("일반 사용자의 메일 서비스 실행 방지가 설정된 경우",
             "일반 사용자의 메일 서비스 실행 방지가 설정되어 있지 않은 경우",
             "Ÿ 메일 서비스를 사용하지 않는 경우 서비스 중지 및 비활성화 설정 Ÿ 메일 서비스 사용 시 메일 서비스의 q 옵션 제한 설정"),
    "U-47": ("릴레이 제한이 설정된 경우",
             "릴레이 제한이 설정되어 있지 않은 경우",
             "Ÿ 메일 서비스를 사용하지 않는 경우 서비스 중지 및 비활성화 설정 Ÿ 메일 서비스 사용 시 릴레이 방지 설정 또는 릴레이 대상 접근 제어 설정"),
    "U-48": ("noexpn, novrfy 옵션이 설정된 경우",
             "noexpn, novrfy 옵션이 설정되어 있지 않은 경우",
             "Ÿ 메일 서비스를 사용하지 않는 경우 서비스 중지 및 비활성화 설정 Ÿ 메일 서비스 사용 시 메일 서비스 설정 파일에 noexpn, novrfy 또는 goaway 옵션 추가 설정"),
    "U-49": ("주기적으로 패치를 관리하는 경우",
             "주기적으로 패치를 관리하고 있지 않은 경우",
             "Ÿ DNS 서비스를 사용하지 않는 경우 서비스 중지 및 비활성화 설정 Ÿ DNS 서비스 사용 시 패치 관리 정책 수립 및 주기적으로 패치 적용 설정 ※ DNS 서비스의 경우 대부분의 버전에서 취약점이 보고되고 있으므로 OS 관리자, 서비스 개발자가 패치 적용에 따른 서비스 영향 정도를 정확히 파악하여 주기적인 패치 적용 정책 수리 후 적용"),
    "U-50": ("Zone Transfer를 허가된 사용자에게만 허용한 경우",
             "Zone Transfer를 모든 사용자에게 허용한 경우",
             "Ÿ DNS 서비스를 사용하지 않는 경우 서비스 중지 및 비활성화 설정 Ÿ DNS 서비스 사용 시 DNS Zone Transfer를 허가된 사용자에게만 전송 허용하도록 설정"),
    "U-51": ("DNS 서비스의 동적 업데이트 기능이 비활성화되었거나, 활성화 시 적절한 접근통제를 수행하고 있는 경우",
             "DNS 서비스의 동적 업데이트 기능이 활성화 중이며 적절한 접근통제를 수행하고 있지 않은 경우",
             "Ÿ DNS 서비스를 사용하지 않는 경우 서비스 중지 및 비활성화 설정 Ÿ DNS 서비스 사용 시 일반적으로 동적 업데이트 기능이 필요 없으나 확인 필요함"),
    "U-52": ("원격 접속 시 Telnet 프로토콜을 비활성화하고 있는 경우",
             "원격 접속 시 Telnet 프로토콜을 사용하는 경우",
             "Telnet, FTP 등 안전하지 않은 서비스 사용을 중지하고 SSH 설치 및 사용하도록 설정"),
    "U-53": ("FTP 접속 배너에 노출되는 정보가 없는 경우",
             "FTP 접속 배너에 노출되는 정보가 있는 경우",
             "Ÿ FTP 서비스를 사용하지 않는 경우 서비스 중지 및 비활성화 설정 Ÿ FTP 서비스 사용 시 FTP 설정 파일을 통해 접속 배너 설정 ※ 접속 배너에 서비스 이름이나 버전 정보를 노출하지 않는 것을 권고"),
    "U-54": ("암호화되지 않은 FTP 서비스가 비활성화된 경우",
             "암호화되지 않은 FTP 서비스가 활성화된 경우",
             "암호화되지 않은 FTP 서비스 중지 및 비활성화 설정"),
    "U-55": ("FTP 계정에 /bin/false(/sbin/nologin) 쉘이 부여된 경우",
             "FTP 계정에 /bin/false(/sbin/nologin) 쉘이 부여되어 있지 않은 경우",
             "Ÿ FTP 서비스를 사용하지 않는 경우 서비스 중지 및 비활성화 설정 Ÿ FTP 서비스 사용 시 FTP 계정에 /bin/false 쉘 부여 설정"),
    "U-56": ("특정 IP주소 또는 호스트에서만 FTP 서버에 접속할 수 있도록 접근 제어 설정을 적용한 경우",
             "FTP 서버에 접근 제어 설정을 적용하지 않은 경우",
             "Ÿ FTP 서비스를 사용하지 않는 경우 서비스 중지 및 비활성화 설정 Ÿ FTP 서비스 사용 시 접근 제어 설정"),
    "U-57": ("root 계정 접속을 차단한 경우",
             "root 계정 접속을 허용한 경우",
             "Ÿ FTP 서비스를 사용하지 않는 경우 서비스 중지 및 비활성화 설정 Ÿ FTP 서비스 사용 시 root 계정으로 직접 접속할 수 없도록 설정"),
    "U-58": ("SNMP 서비스를 사용하지 않는 경우",
             "SNMP 서비스를 사용하는 경우",
             "SNMP 서비스를 사용하지 않는 경우 서비스 중지 및 비활성화 설정"),
    "U-59": ("SNMP 서비스를 v3 이상으로 사용하는 경우",
             "SNMP 서비스를 v2 이하로 사용하는 경우",
             "Ÿ SNMP 서비스를 사용하지 않는 경우 서비스 중지 및 비활성화 설정 Ÿ SNMP 서비스 사용 시 SNMP 버전을 v3 이상으로 적용하도록 설정"),
    "U-60": ("SNMP Community String 기본값인 \"public\", \"private\"이 아닌 영문자, 숫자 포함 10자리 이상 또는 영문자, 숫자, 특수문자 포함 8자리 이상인 경우 ※ SNMP v3의 경우 별도 인증 기능을 사용하고, 해당 비밀번호가 복잡도를 만족하는 경우 양호",
             "아래의 내용 중 하나라도 해당되는 경우 1. SNMP Community String 기본값인 \"public\", \"private\"일 경우 2. 영문자, 숫자 포함 10자리 미만인 경우 3. 영문자, 숫자, 특수문자 포함 8자리 미만인 경우",
             "Ÿ SNMP 서비스를 사용하지 않는 경우 서비스 중지 및 비활성화 설정 Ÿ SNMP 서비스 사용 시 SNMP Community String 기본값인 \"public\", \"private\"이 아닌 영문자, 숫자 포함 10자리 이상 또는 영문자, 숫자, 특수문자 포함 8자리 이상으로 설정"),
    "U-61": ("SNMP 서비스에 접근 제어 설정이 되어 있는 경우",
             "SNMP 서비스에 접근 제어 설정이 되어 있지 않은 경우",
             "Ÿ SNMP 서비스를 사용하지 않는 경우 서비스 중지 및 비활성화 설정 Ÿ SNMP 서비스 사용 시 SNMP 접근 제어 설정하도록 설정"),
    "U-62": ("서버 및 Telnet, FTP, SMTP, DNS 서비스에 로그온 시 경고 메시지가 설정된 경우",
             "서버 및 Telnet, FTP, SMTP, DNS 서비스에 로그온 시 경고 메시지가 설정되어 있지 않은 경우",
             "Telnet, FTP, SMTP, DNS 서비스를 사용하는 경우 설정 파일을 통해 로그온 시 경고 메시지 설정"),
    "U-63": ("/etc/sudoers 파일 소유자가 root이고, 파일 권한이 640인 경우",
             "/etc/sudoers 파일 소유자가 root가 아니거나, 파일 권한이 640을 초과하는 경우",
             "/etc/sudoers 파일 소유자 및 권한 변경 설정"),
    "U-64": ("패치 적용 정책을 수립하여 주기적으로 패치 관리를 하고 있으며, 패치 관련 내용을 확인하고 적용하였을 경우",
             "패치 적용 정책을 수립하지 않고 주기적으로 패치 관리를 하지 않거나, 패치 관련 내용을 확인하지 않고 적용하지 않고 있는 경우",
             "OS 관리자, 서비스 개발자가 패치 적용에 따른 서비스 영향 정도를 파악하여 OS 관리자 및 벤더에서 적용하도록 설정 ※ OS 패치의 경우 지속해서 취약점이 발표되고 있으므로 O/S 관리자, 서비스 개발자가 패치 적용에 따른 서비스 영향 정도를 정확히 파악하여 주기적인 패치 적용 정책을 수립하여 적용해야 함"),
    "U-65": ("NTP 및 시각 동기화 설정이 기준에 따라 적용된 경우",
             "NTP 및 시각 동기화 설정이 기준에 따라 적용되어 있지 않은 경우",
             "NTP 설정 및 동기화 주기 설정"),
    "U-66": ("로그 기록 정책이 보안 정책에 따라 설정되어 수립되어 있으며, 로그를 남기고 있는 경우",
             "로그 기록 정책 미수립 또는 정책에 따라 설정되어 있지 않거나, 로그를 남기고 있지 않은 경우",
             "로그 기록 정책을 수립하고, 정책에 따라 (r)syslog.conf 파일을 설정"),
    "U-67": ("디렉터리 내 로그 파일의 소유자가 root이고, 권한이 644 이하인 경우",
             "디렉터리 내 로그 파일의 소유자가 root가 아니거나, 권한이 644를 초과하는 경우",
             "디렉터리 내 로그 파일 소유자 및 권한 변경 설정"),
    "W-01": ("Administrator 기본 계정 이름을 변경하거나 강화된 비밀번호를 적용한 경우",
             "Administrator 기본 계정 이름을 변경하지 않거나 단순 비밀번호를 적용한 경우",
             "Administrator 기본 계정 이름 변경 및 보안성이 있는 비밀번호 설정"),
    "W-02": ("Guest 계정이 비활성화되어 있는 경우",
             "Guest 계정이 활성화되어 있는 경우",
             "Guest 계정 비활성화"),
    "W-03": ("불필요한 계정이 존재하지 않는 경우",
             "불필요한 계정이 존재하는 경우",
             "현재 계정 현황 확인 후 불필요한 계정 삭제"),
    "W-04": ("계정 잠금 임계값이 5 이하의 값으로 설정된 경우",
             "계정 잠금 임계값이 5 초과의 값으로 설정된 경우",
             "계정 잠금 임계값을 5 이하의 값으로 설정"),
    "W-05": ("\"해독 가능한 암호화를 사용하여 암호 저장\" 정책이 \"사용 안 함\"으로 설정된 경우",
             "\"해독 가능한 암호화를 사용하여 암호 저장\" 정책이 \"사용\"으로 설정된 경우",
             "\"해독 가능한 암호화를 사용하여 암호 저장\"을 \"사용 안 함\"으로 설정"),
    "W-06": ("Administrators 그룹의 구성원을 1명 이하로 유지하거나, 불필요한 관리자 계정이 존재하지 않 는 경우",
             "Administrators 그룹에 불필요한 관리자 계정이 존재하는 경우",
             "Administrators 그룹에 포함된 불필요한 계정 제거"),
    "W-07": ("\"Everyone 사용 권한을 익명 사용자에게 적용\" 정책이 \"사용 안 함\"으로 되어 있는 경우",
             "\"Everyone 사용 권한을 익명 사용자에게 적용\" 정책이 \"사용\"으로 되어 있는 경우",
             "\"Everyone 사용 권한을 익명 사용자에게 적용\"정책을 \"사용 안 함\"으로 설정"),
    "W-08": ("\"계정 잠금 기간\" 및 \"계정 잠금 기간 원래대로 설정 기간\"이 60분 이상으로 설정된 경우",
             "\"계정 잠금 기간\" 및 \"잠금 기간 원래대로 설정 기간\"이 설정되지 않거나 60분 미만으로 설정된 경우",
             "\"계정 잠금 기간\" 및 \"잠금 기간 원래대로 설정 기간\" 60분 이상으로 설정"),
    "W-09": ("계정 비밀번호 관리 정책이 모두 적용된 경우",
             "계정 비밀번호 관리 정책이 모두 적용되어 있지 않은 경우",
             "비밀번호 복잡성, 최소 비밀번호 길이, 최대/최소 사용 기간을 기준에 맞게 설정"),
    "W-10": ("\"마지막 사용자 이름 표시 안 함\"이 \"사용\"으로 설정된 경우",
             "\"마지막 사용자 이름 표시 안 함\"이 \"사용 안 함\"으로 설정된 경우",
             "※ Windows NT: 마지막으로 로그온한 사용자 이름 표시 안 함 설정 ※ Windows 2000: 로그온 스크린에 마지막 사용자 이름 표시 안 함 사용 설정 ※ Windows 2003, 2008, 2012, 2016, 2019, 2022: 대화형 로그온: 마지막 사용자 이름 표시 안 함 사용 설정"),
    "W-11": ("로컬 로그온 허용 정책에 Administrators, IUSR_ 만 존재하는 경우",
             "로컬 로그온 허용 정책에 Administrators, IUSR_ 외 다른 계정 및 그룹이 존재하는 경우",
             "Administrators, IUSR_ 외 다른 계정 및 그룹의 로컬 로그온 제한"),
    "W-12": ("\"익명 SID/이름 변환 허용\" 정책이 \"사용 안 함\"으로 설정된 경우",
             "\"익명 SID/이름 변환 허용\" 정책이 \"사용\"으로 설정된 경우",
             "\"네트워크 액세스: 익명 SID/이름 변환 허용\" 정책 \"사용 안 함\" 설정"),
    "W-13": ("\"콘솔 로그온 시 로컬 계정에서 빈 암호 사용 제한\" 정책이 \"사용\"인 경우",
             "\"콘솔 로그온 시 로컬 계정에서 빈 암호 사용 제한\" 정책이 \"사용 안 함\"인 경우",
             "\"계정: 콘솔 로그온 시 로컬 계정에서 빈 암호 사용 제한\" 정책을 \"사용\"으로 설정"),
    "W-14": ("(관리자 계정을 제외한) 원격 접속이 가능한 계정을 생성하여 타 사용자의 원격 접속을 제한하고, 원격 접속 사용자 그룹에 불필요한 계정이 등록되어 있지 않은 경우",
             "(관리자 계정을 제외한) 원격 접속이 가능한 별도의 계정이 존재하지 않는 경우",
             "관리자 계정과 이외의 계정을 생성, 권한을 제한 사용 설정"),
    "W-15": ("사용자 개인 키를 사용할 때마다 암호 입력을 받는 경우",
             "사용자 개인 키를 사용할 때마다 암호 입력을 받지 않는 경우",
             "\"시스템 암호화: 컴퓨터에 저장된 사용자 키에 대해 강력한 키 보호 사용\" 정책을 \"키를 사용할 때마다 암호를 매 번 입력해야 함\"으로 적용"),
    "W-16": ("일반 공유 디렉터리가 없거나 공유 디렉터리 접근 권한에 Everyone 권한이 없는 경우",
             "일반 공유 디렉터리의 접근 권한에 Everyone 권한이 있는 경우",
             "공유 디렉터리 접근 권한에서 Everyone 권한 제거 후 필요한 계정 추가"),
    "W-17": ("레지스트리의 AutoShareServer (WinNT: AutoShareWks)가 0이며 기본 공유가 존재하지 않 는 경우",
             "레지스트리의 AutoShareServer (WinNT: AutoShareWks)가 1이거나 기본 공유가 존재하는 경우",
             "기본 공유 중지 후 레지스트리 값 설정(IPC$, 일반 공유 제외)"),
    "W-18": ("일반적으로 불필요한 서비스(아래 목록 참조)가 중지된 경우",
             "일반적으로 불필요한 서비스(아래 목록 참조)가 구동 중인 경우",
             "서비스 중지 후 \"사용 안 함\" 설정"),
    "W-19": ("IIS 서비스를 사용하지 않는 경우 또는 필요에 의해 IIS 서비스를 사용하는 경우",
             "IIS 서비스를 불필요하게 사용하는 경우",
             "IIS 서비스가 불필요한 경우 IIS 서비스 중지"),
    "W-20": ("TCP/IP와 NetBIOS 간의 바인딩이 제거되어 있는 경우",
             "TCP/IP와 NetBIOS 간의 바인딩이 제거되어 있지 않은 경우",
             "네트워크 제어판을 이용하여 TCP/IP와 NetBIOS 간의 바인딩(binding) 제거"),
    "W-21": ("FTP 서비스를 사용하지 않는 경우 또는 Secure FTP 서비스를 사용하는 경우",
             "암호화되지 않는 FTP 서비스를 사용하는 경우",
             "FTP 서비스가 필요하지 않다면 서비스 중지 또는 Secure FTP 응용 프로그램 사용"),
    "W-22": ("FTP 홈 디렉터리에 Everyone 권한이 없는 경우",
             "FTP 홈 디렉터리에 Everyone 권한이 있는 경우",
             "FTP 홈 디렉터리에서 Everyone 권한 삭제, 각 사용자에게 적절한 권한 부여"),
    "W-23": ("공유 서비스를 사용하지 않거나, 익명 인증 사용 안 함으로 설정된 경우",
             "공유 서비스를 사용하거나, 익명 인증 사용함으로 설정된 경우",
             "공유 서비스를 사용하지 않는 경우 서비스 중지, 사용할 경우 익명 인증 사용 안 함 설정 적용"),
    "W-24": ("특정 IP주소에서만 FTP 서버에 접속하도록 접근 제어 설정을 적용한 경우",
             "특정 IP주소에서만 FTP 서버에 접속하도록 접근 제어 설정을 적용하지 않는 경우 ※ 조치 시 마스터 속성과 모든 사이트에 적용함",
             "특정 IP주소에서만 FTP 서버에 접속하도록 접근 제어 설정"),
    "W-25": ("아래 기준에 해당하는 경우 1. DNS 서비스가 비활성화인 경우 2. 영역 전송 허용을 하지 않는 경우 3. 특정 서버로만 설정이 되어있는 경우",
             "위 3개 기준 중 하나라도 해당하지 않는 경우",
             "불필요 시 서비스 중지/사용 안 함 설정, 사용하는 경우 영역 전송을 특정 서버로 제한하거나 \"영역 전송 허용\"에 체크 해제"),
    "W-26": ("다음 중 한 가지라도 해당하는 경우 1. IIS를 사용하지 않는 경우 2. Windows 2008 이상 버전을 사용하는 경우 3. Windows 2000 서비스팩 4, Windows 2003 서비스팩 2 이상 설치된 경우 4. 기본 웹 사이트에 MSADC 가상 디렉터리가 존재하지 않는 경우 5. 해당 레지스트리 값이 존재하지 않는 경우",
             "양호 기준에 한 가지도 해당하지 않는 경우",
             "사용하지 않는 경우 IIS 서비스 중지/사용 안 함, 사용할 경우 레지스트리 키 값 제거 또는 관련 패치 적용"),
    "W-27": ("최신 Build가 설치되어 있으며 적용 절차 및 방법이 수립된 경우",
             "최신 Build가 설치되지 않거나, 적용 절차 및 방법이 수립되지 않은 경우",
             "설치에 따른 영향도 확인 후 최신 Build 설치(설치 후 시스템 재시작 필요)"),
    "W-28": ("원격 데스크톱 서비스를 사용하지 않거나 사용 시 암호화 수준을 \"클라이언트와 호환 가능(중간)\" 이상으로 설정한 경우",
             "원격 데스크톱 서비스를 사용하고 암호화 수준이 \"낮음\"으로 설정한 경우",
             "원격 데스크톱 서비스의 가동을 '중지' 및 '사용 안 함' 설정을 하거나, 부득이하게 사용할 경우 암호화 수준 설정 적용"),
    "W-29": ("SNMP 서비스를 사용하지 않는 경우 또는 Community String을 설정하여 SNMP 서비스를 사용하는 경우",
             "불필요하게 SNMP 서비스를 사용하는 경우",
             "불필요 시 서비스 중지/사용 안 함"),
    "W-30": ("SNMP 서비스를 사용하지 않거나 Community String이 public, private 이 아닌 경우",
             "SNMP 서비스를 사용하며, Community String이 public, private인 경우",
             "불필요 시 서비스 중지/사용 안 함, 사용 시 기본 Community String 변경"),
    "W-31": ("SNMP 서비스를 사용하지 않거나 특정 호스트로부터 SNMP 패킷 받아들이기가 설정된 경우",
             "모든 호스트로부터 SNMP 패킷 받아들이기가 설정된 경우",
             "불필요 시 서비스 중지/사용 안 함, 사용 시 SNMP 패킷 수령 호스트 지정"),
    "W-32": ("DNS 서비스를 사용하지 않거나 동적 업데이트 \"없음(아니오)\"으로 설정된 경우",
             "서비스를 사용하며 동적 업데이트가 설정된 경우",
             "DNS 서비스의 동적 업데이트 비활성화 설정"),
    "W-33": ("HTTP, FTP, SMTP 접속 시 배너 정보가 보이지 않는 경우",
             "HTTP, FTP, SMTP 접속 시 배너 정보가 보이는 경우",
             "사용하지 않는 경우 IIS 서비스 중지/사용 안 함, 사용 시 속성값 수정"),
    "W-34": ("Telnet 서비스가 구동되어 있지 않거나 인증 방법이 NTLM인 경우",
             "Telnet 서비스가 구동되어 있으며 인증 방법이 NTLM이 아닌 경우",
             "불필요 시 서비스 중지/사용 안 함 설정, 사용 시 인증 방법으로 NTLM만 사용"),
    "W-35": ("시스템 DSN 부분의 데이터 소스를 현재 사용하고 있는 경우",
             "시스템 DSN 부분의 데이터 소스를 현재 사용하고 있지 않은 경우",
             "사용하지 않는 불필요한 ODBC 데이터 소스 제거"),
    "W-36": ("원격 제어 시 Timeout 제어 설정을 30분 이하로 설정한 경우",
             "원격 제어 시 Timeout 제어 설정을 적용하지 않거나 30분 초과로 설정한 경우",
             "Timeout 제어 설정 적용"),
    "W-37": ("불필요한 명령어나 파일 등 주기적인 예약 작업의 존재 여부를 주기적으로 점검하고 제거한 경우",
             "불필요한 명령어나 파일 등 주기적인 예약 작업의 존재 여부를 주기적으로 점검하지 않거나, 불필 요한 작업을 제거하지 않은 경우",
             "예약 작업에 대한 주기적인 확인"),
    "W-38": ("패치 절차를 수립하여 주기적으로 패치를 확인 및 설치하는 경우",
             "패치 절차가 수립되어 있지 않거나 주기적으로 패치를 설치하지 않는 경우",
             "주기적인 보안 패치 확인 및 설치 적용"),
    "W-39": ("바이러스 백신 프로그램의 최신 엔진 업데이트가 설치되어 있거나, 망 격리 환경의 경우 백신 업데이트를 위한 절차 및 적용 방법이 수립된 경우",
             "바이러스 백신 프로그램의 최신 엔진 업데이트가 설치되어 있지 않거나, 망 격리 환경의 경우 백신 업데이트를 위한 절차 및 적용 방법이 수립되지 않은 경우",
             "백신 프로그램 환경설정 메뉴를 통해 DB 및 엔진의 최신 업데이트를 하도록 설정"),
    "W-40": ("감사 정책 권고 기준에 따라 감사 설정이 되어 있는 경우",
             "감사 정책 권고 기준에 따라 감사 설정이 되어 있지 않은 경우",
             "이벤트에 대한 감사 설정"),
    "W-41": ("NTP 및 시각 동기화를 설정한 경우",
             "NTP 및 시각 동기화를 설정하지 않은 경우",
             "NTP 및 시각 동기화 설정"),
    "W-42": ("최대 로그 크기 \"10,240KB 이상\"으로 설정, \"90일 이후 이벤트 덮어씀\"을 설정한 경우",
             "최대 로그 크기 \"10,240KB 미만\"으로 설정, 이벤트 덮어씀 기간이 \"90일 이하로 설정된 경우",
             "최대 로그 크기 \"10,204KB\", \"90일 이후 이벤트 덮어씀\" 설정"),
    "W-43": ("로그 디렉터리의 접근 권한에 Everyone 권한이 없는 경우",
             "로그 디렉터리의 접근 권한에 Everyone 권한이 있는 경우",
             "로그 디렉터리의 접근 권한에 Everyone 제거"),
    "W-44": ("Remote Registry Service가 중지된 경우",
             "Remote Registry Service가 사용 중인 경우",
             "불필요 시 서비스 중지 및 사용 안 함으로 설정"),
    "W-45": ("바이러스 백신 프로그램이 설치된 경우",
             "바이러스 백신 프로그램이 설치되어 있지 않은 경우",
             "백신 프로그램 설치"),
    "W-46": ("SAM 파일 접근 권한에 Administrator, System 그룹만 모든 권한으로 설정된 경우",
             "SAM 파일 접근 권한에 Administrator, System 그룹 외 다른 그룹에 권한이 설정된 경우",
             "SAM 파일 권한 확인 후 Administrator, System 그룹 외 다른 그룹에 설정된 권한 제거"),
    "W-47": ("화면 보호기를 설정하고 대기 시간이 10분 이하의 값으로 설정되어 있으며, 화면 보호기 해제를 위한 암호를 사용하는 경우",
             "화면 보호기가 설정되지 않았거나 암호를 사용하지 않거나, 화면 보호기 대기 시간이 10분을 초과한 값으로 설정된 경우",
             "화면 보호기 사용, 대기 시간 10분 이하, 해제를 위한 암호 사용"),
    "W-48": ("\"로그온하지 않고 시스템 종료 허용\"이 \"사용 안 함\"으로 설정된 경우",
             "\"로그온하지 않고 시스템 종료 허용\"이 \"사용\"으로 설정된 경우",
             "\"시스템 종료: 로그온하지 않고 시스템 종료\" 정책을 \"사용 안 함\" 설정"),
    "W-49": ("\"원격 시스템에서 강제로 시스템 종료\" 정책에 \"Administrators\"만 존재하는 경우",
             "\"원격 시스템에서 강제로 시스템 종료\" 정책에 \"Administrators\" 외 다른 계정 및 그룹이 존재하 는 경우",
             "\"원격 시스템에서 강제로 시스템 종료\" 정책에 \"Administrators\" 외 다른 계정 및 그룹 제거"),
    "W-50": ("\"보안 감사를 로그 할 수 없는 경우 즉시 시스템 종료\" 정책이 \"사용 안 함\"으로 되어있는 경우",
             "\"보안 감사를 로그 할 수 없는 경우 즉시 시스템 종료\" 정책이 \"사용\"으로 되어있는 경우",
             "\"보안 감사를 로그 할 수 없는 경우 즉시 시스템 종료\" 정책을 \"사용 안 함\"으로 설정"),
    "W-51": ("\"SAM 계정과 공유의 익명 열거 허용 안 함\"이 \"사용\"으로 설정된 경우",
             "\"SAM 계정과 공유의 익명 열거 허용 안 함\"이 \"사용 안 함\"으로 설정된 경우",
             "레지스트리 값 또는, 로컬 보안 정책 설정"),
    "W-52": ("AutoAdminLogon 값이 없거나 0으로 설정된 경우",
             "AutoAdminLogon 값이 1로 설정된 경우",
             "해당 레지스트리 값이 존재하는 경우 0으로 설정"),
    "W-53": ("\"이동식 미디어 포맷 및 꺼내기 허용\" 정책이 \"Administrators\"로 되어있는 경우",
             "\"이동식 미디어 포맷 및 꺼내기 허용\" 정책이 \"Administrators\"로 되어있지 않은 경우",
             "\"이동식 NTFS 미디어 꺼내기 허용\" 정책을 \"Administrators\"로 설정"),
    "W-54": ("아래 4가지 DoS 방어 레지스트리를 설정한 경우 Ÿ SynAttackProtect → 1이상 Ÿ EnableDeadGWDetect → 0 Ÿ KeepAliveTime → 300,000 Ÿ NoNameReleaseOnDemand → 1",
             "DoS 방어 레지스트리 값이 설정되어 있지 않은 경우",
             "레지스트리 값을 추가 또는 수정"),
    "W-55": ("\"사용자가 프린터 드라이버를 설치할 수 없게 함\" 정책이 \"사용\"인 경우",
             "\"사용자가 프린터 드라이버를 설치할 수 없게 함\" 정책이 \"사용 안 함\"인 경우",
             "\"사용자가 프린터 드라이버를 설치할 수 없게 함\" 정책을 \"사용\"으로 설정"),
    "W-56": ("\"로그온 시간이 만료되면 클라이언트 연결 끊기\" 정책을 \"사용\"으로, \"세션 연결을 중단하기 전에 필요한 유휴 시간\" 정책을 \"15분\" 이하로 설정한 경우",
             "\"로그온 시간이 만료되면 클라이언트 연결 끊기\" 정책이 \"사용 안 함\" 또는 \"세션 연결을 중단하기 전에 필요한 유휴 시간\" 정책이 \"15분\" 초과로 설정한 경우",
             "Ÿ \"로그인 시간이 만료되면 클라이언트 연결 끊기\" 정책 \"사용\" 설정 Ÿ \"세션 연결을 중단하기 전에 필요한 유휴 시간\" 정책 \"15분\" 이하로 설정"),
    "W-57": ("로그인 경고 메시지 제목 및 내용이 설정된 경우",
             "로그인 경고 메시지 제목 및 내용이 설정되어 있지 않은 경우",
             "로그인 메시지 제목 및 메시지 내용에 경고 문구 삽입"),
    "W-58": ("홈 디렉터리에 Everyone 권한이 없는 경우 (All Users, Default User 디렉터리 제외)",
             "홈 디렉터리에 Everyone 권한이 있는 경우",
             "Everyone 권한 제거"),
    "W-59": ("\"LAN Manager 인증 수준\" 정책에 \"NTLMv2 응답만 보냄\"이 설정되어 있는 경우",
             "\"LAN Manager 인증 수준\" 정책에 \"LM\" 및 \"NTLM\"인증이 설정되어 있는 경우",
             "- Windows 2000 : LAN Manager 인증 7수준 - > NTLMv2 응답만 보내기 - Windows 2003, 2008, 2012, 2016, 2019 : 네트워크 보안: LAN Manager 인증 수준 - > NTMLv2 응답만 보내기"),
    "W-60": ("아래 3가지 정책 모두 \"사용\"으로 되어있는 경우 Ÿ 도메인 구성원: 보안 채널 데이터를 디지털 암호화 또는 서명(항상) Ÿ 도메인 구성원: 보안 채널 데이터를 디지털 암호화(가능한 경우) Ÿ 도메인 구성원: 보안 채널 데이터 디지털 서명(가능한 경우)",
             "아래 3가지 정책 중 일부가 \"사용 안 함\"으로 되어있는 경우 Ÿ 도메인 구성원: 보안 채널 데이터를 디지털 암호화 또는 서명(항상) Ÿ 도메인 구성원: 보안 채널 데이터를 디지털 암호화(가능한 경우) Ÿ 도메인 구성원: 보안 채널 데이터 디지털 서명(가능한 경우)",
             "보안 채널 데이터를 디지털 암호화·서명 관련 3개 정책 → 사용"),
    "W-61": ("NTFS 파일 시스템을 사용하는 경우",
             "FAT 파일 시스템을 사용하는 경우",
             "FAT 파일 시스템을 사용 시 가능한 NTFS 파일 시스템 변환 설정"),
    "W-62": ("시작 프로그램 목록을 정기적으로 검사하고 불필요한 서비스를 비활성화한 경우",
             "시작 프로그램 목록을 정기적으로 검사하지 않고, 부팅 시 불필요한 서비스도 실행되고 있는 경우",
             "시작 프로그램 목록의 정기적인 검사 실시 및 불필요한 서비스 비활성화 설정"),
    "W-63": ("컴퓨터 시계 동기화 최대 허용 오차값이 5분 이하인 경우",
             "컴퓨터 시계 동기화 최대 허용 오차값이 5분 초과인 경우",
             "Kerberos 사용 시 컴퓨터 시계 동기화 최대 허용 오차값 5분 이하로 설정"),
    "W-64": ("Windows 방화벽 \"사용\"으로 설정된 경우",
             "Windows 방화벽 \"사용 안 함\"으로 설정된 경우",
             "Windows 방화벽 \"사용\"으로 설정"),
    "WEB-01": ("관리자 페이지를 사용하지 않거나, 계정명이 기본 계정명으로 설정되어 있지 않은 경우",
             "계정명이 기본 계정명으로 설정되어 있거나, 추측하기 쉬운 문자 조합으로 이루어진 계정명을 사용하는 경우",
             "기본 관리자 계정명을 추측하기 어려운 계정명으로 설정"),
    "WEB-02": ("관리자 비밀번호가 암호화되어 있거나, 유추하기 어려운 비밀번호로 설정된 경우",
             "관리자 비밀번호가 암호화되어 있지 않거나, 유추하기 쉬운 비밀번호로 설정된 경우",
             "복잡도 기준에 맞는 추측하기 어려운 비밀번호 설정"),
    "WEB-03": ("비밀번호 파일에 권한이 600 이하로 설정된 경우",
             "비밀번호 파일에 권한이 600 초과로 설정된 경우",
             "비밀번호 파일 권한 600 이하로 설정"),
    "WEB-04": ("디렉터리 리스팅이 설정되지 않은 경우",
             "디렉터리 리스팅이 설정된 경우",
             "디렉터리 리스팅 기능 차단 설정"),
    "WEB-05": ("CGI 스크립트를 사용하지 않거나 CGI 스크립트가 실행 가능한 디렉터리를 제한한 경우",
             "CGI 스크립트를 사용하고 CGI 스크립트가 실행 가능한 디렉터리를 제한하지 않은 경우",
             "CGI 스크립트를 정해진 디렉터리 내에서만 실행할 수 있도록 설정"),
    "WEB-06": ("상위 디렉터리 접근 기능을 제거한 경우",
             "상위 디렉터리 접근 기능을 제거하지 않은 경우",
             "상위 디렉터리 접근 기능 제거 설정"),
    "WEB-07": ("기본으로 생성되는 불필요한 파일 및 디렉터리가 존재하지 않을 경우",
             "기본으로 생성되는 불필요한 파일 및 디렉터리가 존재하는 경우",
             "불필요한 파일 및 디렉터리를 제거하도록 설정"),
    "WEB-08": ("파일 업로드 및 다운로드 용량을 제한한 경우",
             "파일 업로드 및 다운로드 용량을 제한하지 않은 경우",
             "파일 업로드 및 다운로드 용량을 허용 가능한 최소 범위로 제한하여 설정"),
    "WEB-09": ("웹 프로세스(웹 서비스)가 관리자 권한이 부여된 계정이 아닌 운영에 필요한 최소한의 권한을 가진 별도의 계정으로 구동되고 있는 경우",
             "웹 프로세스(웹 서비스)가 관리자 권한이 부여된 계정으로 구동되고 있는 경우",
             "웹 서비스 프로세스 구동 시 관리자 권한이 아닌 운영에 필요한 최소한의 권한을 가진 계정으로 구동 설정"),
    "WEB-10": ("불필요한 Proxy 설정을 제한한 경우",
             "불필요한 Proxy 설정을 제한하지 않은 경우",
             "불필요한 Proxy 설정 존재 여부 점검 및 제한 설정"),
    "WEB-11": ("웹 서버 경로를 기타 업무와 영역이 분리된 경로로 설정 및 불필요한 경로가 존재하지 않는 경우",
             "웹 서버 경로를 기타 업무와 영역이 분리되지 않은 경로로 설정하거나 불필요한 경로가 있는 경우",
             "웹 서버의 경로를 별도의 경로로 변경 및 불필요한 경로 제거 설정"),
    "WEB-12": ("심볼릭 링크, aliases, 바로가기 등의 링크 사용을 허용하지 않는 경우",
             "심볼릭 링크, aliases, 바로가기 등의 링크 사용을 허용하는 경우",
             "웹 서비스 링크 사용 제한 설정"),
    "WEB-13": ("일반 사용자의 DB 연결 파일에 대한 접근을 제한하고, 불필요한 스크립트 매핑이 제거된 경우",
             "일반 사용자의 DB 연결 파일에 대한 접근을 제한하지 않거나, 불필요한 스크립트 매핑이 제거되지 않은 경우",
             "DB 연결 파일에 대한 접근 권한 제한 또는 불필요한 스크립트 매핑 제거 등을 통한 웹 서비스 내 DB 연결 취약점 제거 설정"),
    "WEB-14": ("주요 설정 파일 및 디렉터리에 불필요한 접근 권한이 부여되지 않은 경우",
             "주요 설정 파일 및 디렉터리에 불필요한 접근 권한이 부여된 경우",
             "주요 설정 파일 및 디렉터리에 불필요한 접근 권한 제거 설정"),
    "WEB-15": ("불필요한 스크립트 매핑이 존재하지 않는 경우",
             "불필요한 스크립트 매핑이 존재하는 경우",
             "불필요한 스크립트 매핑 존재 여부 점검 및 제거 설정"),
    "WEB-16": ("HTTP 응답 헤더에서 웹 서버 정보가 노출되지 않는 경우",
             "HTTP 응답 헤더에서 웹 서버 정보가 노출되는 경우",
             "응답 헤더에 표시되는 정보를 최소한으로 제한하여 설정"),
    "WEB-17": ("불필요한 가상 디렉터리가 존재하지 않는 경우",
             "불필요한 가상 디렉터리가 존재하는 경우",
             "불필요한 가상 디렉터리 존재 여부 점검 및 삭제하도록 설정"),
    "WEB-18": ("WebDAV 서비스를 비활성화하고 있는 경우",
             "WebDAV 서비스를 활성화하고 있는 경우",
             "WebDAV 서비스 비활성화 설정"),
    "WEB-19": ("웹 서비스 SSI 사용 설정이 비활성화되어 있는 경우",
             "웹 서비스 SSI 사용 설정이 활성화되어 있는 경우",
             "웹 서비스 내 불필요한 SSI 사용 제한 설정"),
    "WEB-20": ("SSL/TLS 설정이 활성화되어 있는 경우",
             "SSL/TLS 설정이 비활성화되어 있는 경우",
             "웹 서비스 내 SSL/TLS 활성화 설정"),
    "WEB-21": ("HTTP 접근 시 HTTPS Redirection이 활성화된 경우",
             "HTTP 접근 시 HTTPS Redirection이 비활성화된 경우",
             "HTTP Redirection 활성화 설정"),
    "WEB-22": ("웹 서비스 에러 페이지가 별도로 지정된 경우",
             "웹 서비스 에러 페이지가 별도로 지정되지 않거나 에러 발생 시 중요 정보가 노출되는 경우",
             "필수 에러 코드에 대해 일원화된 에러 페이지 사용 및 에러 페이지 내 불필요 정보 노출 제한 설정"),
    "WEB-23": ("LDAP 연결 인증 시 안전한 비밀번호 다이제스트 알고리즘을 사용하는 경우",
             "LDAP 연결 인증 시 안전한 비밀번호 다이제스트 알고리즘을 사용하지 않는 경우",
             "LDAP 연결 인증 시 SHA-256 이상의 알고리즘을 사용하도록 설정"),
    "WEB-24": ("별도의 업로드 경로를 사용하고 일반 사용자의 접근 권한이 부여되지 않은 경우",
             "별도의 업로드 경로를 사용하지 않거나, 일반 사용자의 접근 권한이 부여된 경우",
             "기본 경로가 아닌 별도의 업로드 경로를 지정하고, 해당 경로에 대한 일반 사용자의 접근 권한을 제한하도록 설정"),
    "WEB-25": ("최신 보안 패치가 적용되어 있으며, 패치 적용 정책을 수립하여 주기적인 패치 관리를 하는 경우",
             "최신 보안 패치가 적용되어 있지 않거나 패치 적용 정책을 수립 및 주기적인 패치 관리를 하지 않는 경우",
             "패치 적용에 따른 서비스 영향 정도를 정확히 파악하여 주기적인 패치 적용 정책 수립 및 적용하도록 설정"),
    "WEB-26": ("로그 디렉터리 및 파일에 일반 사용자의 접근 권한이 없는 경우",
             "로그 디렉터리 및 파일에 일반 사용자의 접근 권한이 있는 경우",
             "로그 디렉터리 및 파일에 일반 사용자 접근 권한 제거 설정"),
    "S-01": ("장비에서 제공하고 있는 기본 계정을 변경하여 사용하는 경우 (기본 계정 변경이 불가능할 경우 기본 비밀번호 변경으로 보완 필요)",
             "장비에서 제공하고 있는 기본 계정을 변경할 수 있으나 변경하지 않고 사용하는 경우",
             "기본 계정 변경"),
    "S-02": ("비밀번호 관리 정책에 맞는 비밀번호가 사용된 경우",
             "비밀번호 관리 정책에 맞지 않는 비밀번호가 사용된 경우",
             "해당 기관의 비밀번호 관리 정책에 따라 적합하게 설정"),
    "S-03": ("사용자별 계정의 용도 파악 및 적절한 권한이 부여된 경우",
             "사용자별 계정의 용도 파악 및 적절한 권한이 부여되지 않은 경우",
             "사용자별 계정의 용도 파악 및 적절한 권한 부여"),
    "S-04": ("불필요한 계정을 제거하거나 관리된 경우",
             "불필요한 계정을 제거하지 않거나 관리되지 않은 경우",
             "불필요한 공용 계정 및 휴면계정 제거"),
    "S-05": ("로그인 실패 임계값을 5회 이하로 설정된 경우",
             "로그인 실패 임계값을 5회 이하로 설정되지 않은 경우",
             "로그인 실패 임계값을 5회 이하로 제한"),
    "S-06": ("원격 관리 시 관리자 IP 또는 특정 IP만 접근할 수 있도록 설정된 경우",
             "원격 관리 시 관리자 IP 또는 특정 IP만 접근할 수 있도록 설정되지 않은 경우",
             "원격 관리 시 관리자 및 특정 IP만 접근 허용"),
    "S-07": ("보안 장비 접속 시 암호화 통신을 하는 경우",
             "보안 장비 접속 시 암호화 통신을 하지 않는 경우",
             "보안 장비 접속 시, 가능하다면 SSL 등의 암호화 접속 활용"),
    "S-08": ("Session Timeout을 설정한 경우",
             "Session Timeout을 설정하지 않은 경우",
             "Session Timeout 시간을 설정"),
    "S-09": ("주기적 보안 패치 및 벤더 권고사항이 적용된 경우",
             "주기적 보안 패치 및 벤더 권고사항이 적용되지 않은 경우",
             "벤더사에서 주기적으로 제공하는 장비별 최신 취약점 정보를 파악 후 최신 패치 및 업그레이드를 수행"),
    "S-10": ("기관 정책에 따른 로그 설정된 경우",
             "기관 정책에 따른 로그 설정이 되지 않은 경우",
             "기관 정책에 따른 로깅 설정"),
    "S-11": ("정책에 따라 로그 보관 설정된 경우",
             "로그 보관 정책이 없고 관리되지 않은 경우",
             "보안 장비 로그를 정기적으로 분석 및 검토"),
    "S-12": ("보안 장비에 적용된 정책을 별도의 파일로 보관하고 있는 경우",
             "보안 장비에 적용된 정책을 별도의 파일로 보관하고 있지 않은 경우",
             "보안 장비에 적용된 정책을 별도의 파일로 보관"),
    "S-13": ("별도의 원격 로그 서버가 구축되어 있고, 원격 로그 서버에 저장될 로그가 기관 정책에 맞게 설정된 경우",
             "별도의 원격 로그 서버가 구축되어 있지 않거나, 원격 로그 서버에 저장될 로그가 기관 정책에 맞게 설정되지 않은 경우",
             "기관 정책에 맞게 원격 로그 서버에 저장될 로그 설정 후 보안 장비 로그 설정 메뉴에서 (r)syslog 설정 또는 주기적으로 별도 저장 매체에 백업((r)syslog 미지원일 경우)"),
    "S-14": ("NTP 및 시간 동기화 설정이 되어 있는 경우",
             "NTP 및 시간 동기화 설정이 되어 있지 않은 경우",
             "보안 장비 시간 설정에서 NTP 및 시간 동기화 설정 확인"),
    "S-15": ("정책에 대한 주기적인 검사로 미사용 및 중복된 정책을 확인하고 제거된 경우",
             "정책에 대한 주기적인 검사를 하지 않고 미사용 및 중복된 정책을 확인 및 제거되지 않은 경우",
             "정책에 대한 주기적인 검사로 미사용 및 중복된 정책을 확인하여 제거"),
    "S-16": ("외부 공개 필요성이 없는 서버, 단말기 등 정보시스템에 대해 NAT 설정을 적용한 경우",
             "외부 공개 필요성이 없는 서버, 단말기 등 정보시스템에 대해 NAT 설정을 적용하지 않은 경우",
             "외부 공개 필요성이 없는 정보시스템에 대해 공인 IP 지정 여부를 확인하여 사설 IP로 변경한 후 보안 장비에서 NAT 설정을 적용"),
    "S-17": ("DMZ를 구성하여 내부 네트워크를 보호하는 경우",
             "DMZ를 구성하지 않고 사설망에서 외부 공개 서비스를 제공하는 경우",
             "Ÿ DMZ를 구성하여 내부 네트워크와 외부 서비스 네트워크 분리 Ÿ 물리적(망 분리)으로 내부 네트워크와 외부 서비스 네트워크가 분리되어 있으면 해당 없음"),
    "S-18": ("All Deny 설정 및 보안 장비에 최소 서비스만 허용하는 경우",
             "All Deny 미설정 또는 보안 장비에 불필요한 서비스를 허용하는 경우",
             "보안 장비에 최소 서비스만 허용하도록 설정함"),
    "S-19": ("이상징후 탐지 모니터링을 수행하고 있는 경우",
             "이상징후 탐지 모니터링을 수행하고 있지 않은 경우",
             "이상징후 탐지 시 담당자/관리자가 즉시 확인할 수 있도록 모니터링 수행"),
    "S-20": ("보안 장비 가용성을 정기적으로 모니터링 및 검토할 경우",
             "보안 장비 가용성을 정기적으로 모니터링 및 검토하지 않을 경우",
             "장비 사용량을 정기적으로 모니터링"),
    "S-21": ("불필요한 SNMP 서비스를 사용하지 않을 경우",
             "불필요한 SNMP 서비스를 사용할 경우",
             "불필요한 경우 SNMP 서비스 중지"),
    "S-22": ("SNMP 서비스를 사용하지 않거나, 유추하기 어려운 Community String을 설정한 경우",
             "Community String을 기본값으로 사용하고 있거나, 유추하기 쉬운 Community String을 설정한 경우",
             "유추하기 어려운 Community String을 설정"),
    "S-23": ("유해 트래픽 탐지/차단 패턴이 적용된 경우",
             "유해 트래픽 탐지/차단 패턴이 적용되지 않은 경우",
             "유해 트래팍 탐지/차단 정책 설정"),
    "N-01": ("기본 비밀번호를 변경한 경우",
             "기본 비밀번호를 변경하지 않거나 비밀번호를 설정하지 않은 경우",
             "기본 비밀번호를 관리기관의 비밀번호 작성규칙을 준용하여 변경"),
    "N-02": ("기관 정책에 맞는 비밀번호 복잡성 정책을 설정하거나, 비밀번호 복잡성 설정 기능이 없는 장비는 기관 정책에 맞게 비밀번호를 사용하는 경우",
             "기관 정책에 맞지 않는 비밀번호를 설정하여 사용하는 경우",
             "관리기관의 비밀번호 작성규칙에 맞게 비밀번호 복잡성 정책 및 비밀번호 설정"),
    "N-03": ("비밀번호 암호화 설정을 적용한 경우",
             "비밀번호 암호화 설정을 적용하지 않은 경우",
             "비밀번호 암호화 설정 적용"),
    "N-04": ("로그인 실패 임계값이 5회 이하의 값으로 설정된 경우",
             "로그인 실패 임계값이 설정되어 있지 않거나, 5회 초과의 값으로 설정된 경우",
             "로그인 실패 임계값을 5회 이하로 설정"),
    "N-05": ("업무에 맞게 계정의 권한이 차등 부여된 경우",
             "업무에 맞게 계정의 권한이 차등 부여되지 않은 경우",
             "업무에 맞게 계정별 권한 차등(관리자 권한 최소화) 부여 ※ 한 명의 관리자가 네트워크 장비를 관리할 경우는 해당하지 않음"),
    "N-06": ("가상 터미널(VTY) 접근을 제한하는 ACL을 설정한 경우",
             "가상 터미널(VTY) 접근을 제한하는 ACL을 설정하지 않은 경우",
             "가상 터미널(VTY)에 특정 IP주소만 접근할 수 있도록 설정"),
    "N-07": ("Session Timeout 시간을 10분 이하로 설정한 경우",
             "Session Timeout 시간을 설정하지 않거나 10분 초과로 설정한 경우",
             "Session Timeout 설정 (10분 이하 권고)"),
    "N-08": ("장비 정책에 VTY 접근 시 암호화 프로토콜(ssh) 이용한 접근만 허용하고 있는 경우",
             "장비 정책에 VTY 접근 시 평문 프로토콜(telnet) 이용한 접근을 허용하고 있는 경우",
             "암호화 프로토콜만 VTY에 접근할 수 있도록 설정"),
    "N-09": ("불필요한 포트 및 인터페이스 사용을 제한한 경우",
             "불필요한 포트 및 인터페이스 사용을 제한하지 않은 경우",
             "불필요한 포트 및 인터페이스 사용 제한 또는 비활성화"),
    "N-10": ("로그온 시 접근에 대한 경고 메시지를 설정한 경우",
             "로그온 시 접근에 대한 경고 메시지를 설정하지 않거나 시스템 관련 정보가 노출되는 경우",
             "네트워크 장비 접속 시 경고 메시지 설정"),
    "N-11": ("별도의 로그 서버를 통해 로그를 관리하는 경우",
             "별도의 로그 서버가 없는 경우",
             "Syslog 등을 이용하여 로그 저장 설정"),
    "N-12": ("주기적으로 보안 패치 및 벤더 권고사항을 적용하는 경우",
             "주기적으로 보안 패치 및 벤더 권고사항을 적용하지 않는 경우",
             "장비별 제공하는 최신 취약점 정보를 파악 후 최신 패치 및 업그레이드를 수행"),
    "N-13": ("저장되는 로그 데이터보다 버퍼 용량이 큰 경우",
             "저장되는 로그 데이터보다 버퍼 용량이 작은 경우",
             "로그에 대한 정보를 확인하여 장비 성능을 고려한 최대 버퍼 크기를 설정"),
    "N-14": ("로그 기록 정책에 따라 로깅 설정이 되어 있는 경우",
             "로그 기록 정책 미수립 또는 로깅 설정이 미흡한 경우",
             "로그 기록 정책을 수립하고 정책에 따른 로깅 설정"),
    "N-15": ("NTP 서버를 통한 시스템 간 실시간 시간 동기화가 설정된 경우",
             "NTP 서버와 연동되어 있지 않아 시스템 간 실시간 시간 동기화 설정이 되어있지 않은 경우",
             "NTP 사용 시 신뢰할 수 있는 서버로 설정"),
    "N-16": ("timestamp 로그 설정이 되어 있는 경우",
             "timestamp 로그 설정이 되어 있지 않은 경우",
             "로그에 시간 정보가 기록될 수 있도록 timestamp 로그 설정"),
    "N-17": ("사용하지 않는 SNMP 서비스를 비활성화한 경우",
             "사용하지 않는 SNMP 서비스를 비활성화하지 않은 경우",
             "장비별 제공하는 최신 취약점 정보를 파악 후 최신 패치 및 업그레이드를 수행"),
    "N-18": ("SNMP 서비스를 비활성화하거나 SNMP Community String을 복잡성 기준(영어 대·소문자, 숫자, 특수문자 중 3종류 이상을 조합하여 8자리 이상)에 맞게 설정한 경우",
             "SNMP Community String을 기본 설정(public, private)으로 사용하고 있거나, 복잡성 기준에 맞지 않게 설정한 경우",
             "public, private 외 복잡성 기준에 맞는 Community String을 설정 ※ SNMP Community String 복잡성 기준 : 영어 대·소문자, 숫자, 특수문자 중 3종류 이상을 조합하여 8자리 이상으로 구성"),
    "N-19": ("SNMP 서비스를 비활성화하거나 SNMP 접근을 제한하는 ACL을 설정한 경우",
             "SNMP 접근을 제한하는 ACL을 설정하지 않은 경우",
             "SNMP 접근에 대한 ACL(Access List) 설정"),
    "N-20": ("SNMP 커뮤니티 권한이 읽기 전용(RO)인 경우",
             "SNMP 커뮤니티 권한이 불필요하게 읽기 쓰기(RW)인 경우",
             "SNMP Community String 권한 설정 (RW 권한 삭제 권고)"),
    "N-21": ("TFTP 서비스를 차단한 경우",
             "네트워크 장비의 TFTP 서비스를 차단하지 않은 경우",
             "네트워크 장비의 불필요한 TFTP 서비스를 비활성화 설정"),
    "N-22": ("경계 라우터 또는 보안 장비에 스푸핑 방지 필터링을 적용한 경우",
             "경계 라우터 또는 보안 장비에 스푸핑 방지 필터링을 적용하지 않은 경우",
             "경계 라우터 또는 보안 장비에서 스푸핑 방지 필터링 적용"),
    "N-23": ("경계 라우터에서 DDoS 공격 방어 설정을 하거나 DDoS 대응 장비를 사용하는 경우",
             "경계 라우터에서 DDoS 공격 방어 설정을 하지 않거나 DDoS 대응 장비를 사용하지 않는 경우",
             "DDoS 공격 방어 설정 점검"),
    "N-24": ("사용하지 않는 인터페이스가 비활성화된 경우",
             "사용하지 않는 인터페이스가 비활성화되지 않은 경우",
             "네트워크 장비에서 사용하지 않는 모든 인터페이스 비활성화 설정"),
    "N-25": ("TCP Keepalive 서비스를 설정한 경우",
             "TCP Keepalive 서비스를 설정하지 않은 경우",
             "네트워크 장비에서 TCP Keepalive 서비스를 사용하도록 설정"),
    "N-26": ("Finger 서비스를 차단하는 경우",
             "Finger 서비스를 차단하지 않는 경우",
             "장비별 Finger 서비스 제한 설정"),
    "N-27": ("불필요한 웹 서비스를 차단하거나 허용된 IP에서만 웹서비스 관리 페이지에 접속이 가능한 경우",
             "불필요한 웹 서비스를 차단하지 않은 경우",
             "HTTP 서비스 차단 또는 HTTP 서버를 관리하는 관리자 접속 IP 설정"),
    "N-28": ("TCP/UDP Small 서비스가 제한된 경우",
             "TCP/UDP Small 서비스가 제한되지 않은 경우",
             "TCP/UDP Small Service 제한 설정"),
    "N-29": ("BOOTP 서비스가 제한된 경우",
             "BOOTP 서비스가 제한되지 않은 경우",
             "장비별 BOOTP 서비스 제한 설정"),
    "N-30": ("CDP 서비스를 차단하는 경우",
             "CDP 서비스를 차단하지 않는 경우",
             "Ÿ 장비별 CDP 서비스 제한 설정 Ÿ CDP는 Cisco 전용 프로토콜이지만 일부 다른 벤더도 지원하며, CDP와 유사한 IEEE 표준인 LLDP(Link Layer Discovery Protocol, IEEE 802.1AB)도 불필요할 경우 비활성화"),
    "N-31": ("Directed Broadcasts를 차단하는 경우",
             "Directed Broadcasts를 차단하지 않는 경우",
             "장치별로 Directed Broadcasts 제한 설정"),
    "N-32": ("ip-source-route를 차단하는 경우",
             "ip-source-route를 차단하지 않는 경우",
             "각 인터페이스에서 ip-source-route 차단 설정"),
    "N-33": ("Proxy ARP를 차단하는 경우",
             "Proxy ARP를 차단하지 않는 경우",
             "각 인터페이스에서 Proxy ARP 비활성화 설정"),
    "N-34": ("ICMP unreachable, ICMP redirect를 차단하는 경우",
             "ICMP unreachable, ICMP redirect를 차단하지 않는 경우",
             "각 인터페이스에서 ICMP unreachables, ICMP redirects 비활성화"),
    "N-35": ("identd 서비스를 차단하는 경우",
             "identd 서비스를 차단하지 않는 경우",
             "idnetd 서비스 비활성화"),
    "N-36": ("Domain Lookup을 차단하는 경우",
             "Domain Lookup을 차단하지 않은 경우",
             "Domain Lookup 비활성화"),
    "N-37": ("PAD 서비스를 차단하는 경우",
             "PAD 서비스를 차단하지 않은 경우",
             "PAD 서비스 비활성화"),
    "N-38": ("mask-reply를 차단하는 경우",
             "mask-reply를 차단하지 않은 경우",
             "각 인터페이스에서 mask-reply 비활성화"),
    "PC-01": ("최대 암호 사용 기간이 \"90일\" 이하로 설정된 경우",
             "최대 암호 사용 기간이 \"제한 없음\"이거나 \"90일을\"을 초과하여 설정된 경우",
             "※ 최대 암호 사용 기간 \"90일\" 설정 ※ 최소 암호 사용 기간 \"1일\" 설정 ※ 최근 암호 기억 설정 (권장: 24개의 비밀번호 기억) ※ 사용자가 새 비밀번호를 변경하기 전에 이를 유지해야 하는 일수를 결정. 비밀번호 변경 후 편의성 때문에 기존 비밀번호로 다시 설정하는 경우가 많으므로 최소 사용 기간을 설정 ※ 이전 비밀번호를 다시 사용한다면 변경 주기가 의미가 없으므로 기존에 사용하던 비밀번호를 기억해서 사용하지 못하게 함"),
    "PC-02": ("복잡성을 만족하는 비밀번호 정책이 설정된 경우",
             "비밀번호를 사용하지 않거나, 추측하기 쉬운 문자조합으로 이루어진 짧은 자릿수의 비밀번호를 설정된 경우",
             "비밀번호 정책을 해당 기관의 보안 정책에 적합하게 설정"),
    "PC-03": ("복구 콘솔 자동 로그온 허용이 \"사용 안 함\"으로 설정된 경우",
             "복구 콘솔 자동 로그온 허용이 \"사용\"으로 설정된 경우",
             "복구 콘솔 자동 로그온 허용 \"사용 안 함\"으로 설정"),
    "PC-04": ("불필요한 공유 폴더가 존재하지 않거나 공유 폴더에 접근 권한 및 비밀번호가 설정된 경우",
             "불필요한 공유 폴더가 존재하거나 접근 권한 및 비밀번호 설정 없이 공유 폴더가 사용된 경우",
             "Ÿ 공유 폴더 불필요 시 삭제 Ÿ 공유 폴더 필요하면 적절한 접근 권한 부여 및 비밀번호 설정 Ÿ 조치 후 \"AutoShareWks\"값 변경으로 자동 공유 방지"),
    "PC-05": ("일반적으로 불필요한 서비스(아래 목록 참조)가 중지된 경우",
             "일반적으로 불필요한 서비스(아래 목록 참조)가 중지되지 않은 경우",
             "불필요한 서비스 중지 설정"),
    "PC-06": ("Windows Messenger가 실행 중지된 상태이거나 상용 메신저가 설치되지 않은 경우",
             "Windows Messenger가 실행 중이거나 상용 메신저가 설치된 경우",
             "\"Windows Messenger를 실행하지 않음\" 설정 및 상용 메신저 삭제"),
    "PC-07": ("모든 디스크 볼륨의 파일 시스템이 NTFS인 경우",
             "모든 디스크 볼륨의 파일 시스템이 FAT32인 경우",
             "모든 디스크 볼륨에 대해 파일 시스템 NTFS로 변경"),
    "PC-08": ("PC 내에 하나의 OS만 설치된 경우",
             "PC 내에 2개 이상의 OS가 설치된 경우",
             "하나의 OS만 설치하여 운영함"),
    "PC-09": ("\"브라우저를 닫을 때 임시 인터넷 파일 폴더 비우기\" 설정이 \"사용\"으로 설정된 경우",
             "\"브라우저를 닫을 때 임시 인터넷 파일 폴더 비우기\" 설정이 \"미사용\"으로 설정된 경우",
             "하나의 OS만 설치하여 운영함"),
    "PC-10": ("HOT FIX 설치 및 자동 업데이트 설정이 되어 있고 내부적으로 관리 절차를 수립하여 이행한 경우",
             "HOT FIX 설치되어 있지 않거나 내부적으로 관리 절차가 수립되지 않은 경우",
             "Windows Update 사이트에 접속하여 최신 패치 존재 여부 확인 및 패치 적용"),
    "PC-11": ("최신 빌드가 적용되어 있고 내부적으로 관리 절차를 수립하여 이행한 경우",
             "최신 빌드가 적용되어 있지 않거나 내부적으로 관리 절차가 수립되지 않은 경우",
             "Windows Update 사이트에 접속하여 최신 서비스팩 여부 확인 및 적용"),
    "PC-12": ("Windows 자동 로그인이 비활성화된 경우",
             "Windows 자동 로그인이 활성화된 경우",
             "Windows 자동 로그인 비활성화 설정"),
    "PC-13": ("백신이 설치되어 있고, 최신 업데이트가 적용된 경우",
             "백신이 설치되어 있지 않거나, 최신 업데이트가 적용되지 않은 경우",
             "바이러스 백신 설치 및 최신 업데이트 적용"),
    "PC-14": ("설치된 백신의 실시간 감시기능이 활성화된 경우",
             "백신이 설치되어 있지 않거나 실시간 감시기능이 비활성화된 경우",
             "바이러스 백신 실시간 감시 기능 설정"),
    "PC-15": ("Windows 방화벽 \"사용\"으로 설정된 경우 또는 유·무료 기타 방화벽을 사용한 경우",
             "Windows 방화벽 \"사용 안 함\"으로 설정된 경우 또는 유·무료 기타 방화벽을 사용하지 않은 경우",
             "Windows 방화벽 \"사용\"으로 설정 또는 유·무료 기타 방화벽을 사용"),
    "PC-16": ("화면보호기 설정(대기 시간 10분 이하) 및 비밀번호로 보호가 설정된 경우",
             "화면보호기 설정(대기 시간 10분 초과) 및 비밀번호로 보호가 설정되지 않은 경우",
             "화면보호기 설정 및 비밀번호 보호 설정"),
    "PC-17": ("미디어 사용 시 자동 실행되지 않고 내부적으로 관리 절차를 수립하여 이행된 경우",
             "미디어 사용 시 자동 실행되거나 내부적으로 관리 절차가 수립되지 않은 경우",
             "미디어 자동 실행 방지 설정"),
    "PC-18": ("원격 지원이 \"사용 안 함\"으로 설정된 경우",
             "원격 지원이 \"사용\"으로 설정된 경우",
             "원격 지원 서비스 비활성화"),
    "D-01": ("기본 계정의 초기 비밀번호를 변경하거나 잠금설정한 경우",
             "기본 계정의 초기 비밀번호 를 변경하지 않거나 잠금설정을 하지 않은 경우",
             "기본(관리자) 계정의 초기 비밀번호 및 권한 정책 변경"),
    "D-02": ("계정 정보를 확인하여 불필요한 계정이 없는 경우",
             "인가되지 않은 계정, 퇴직자 계정, 테스트 계정 등 불필요한 계정이 존재하는 경우",
             "계정별 용도를 파악한 후 불필요한 계정 삭제"),
    "D-03": ("기관 정책에 맞게 비밀번호 사용 기간 및 복잡도 설정이 적용된 경우",
             "기관 정책에 맞게 비밀번호 사용 기간 및 복잡도 설정이 적용되지 않은 경우",
             "기관 정책에 맞게 비밀번호 사용 기간 및 복잡도 정책 설정"),
    "D-04": ("관리자 권한이 필요한 계정 및 그룹에만 관리자 권한이 부여된 경우",
             "관리자 권한이 필요 없는 계정 및 그룹에 관리자 권한이 부여된 경우",
             "관리자 권한이 필요한 계정 및 그룹에만 관리자 권한 부여"),
    "D-05": ("비밀번호 재사용 제한 설정을 적용한 경우",
             "비밀번호 재사용 제한 설정을 적용하지 않은 경우",
             "PASSWORD_REUSE_TIME, PASSWORD_REUSE_MAX 파라미터 설정"),
    "D-06": ("사용자별 계정을 사용하고 있는 경우",
             "공용 계정을 사용하고 있는 경우",
             "사용자별 계정 생성 및 권한 부여"),
    "D-07": ("DBMS가 root 계정 또는 root 권한이 아닌 별도의 계정 및 권한으로 구동되고 있는 경우",
             "DBMS가 root 계정 또는 root 권한으로 구동되고 있는 경우",
             "DBMS 구동 계정 변경"),
    "D-08": ("해시 알고리즘 SHA-256 이상의 암호화 알고리즘을 사용하고 있는 경우",
             "해시 알고리즘 SHA-256 미만의 암호화 알고리즘을 사용하고 있는 경우",
             "SHA-256 이상의 암호화 알고리즘 적용"),
    "D-09": ("로그인 시도 횟수를 제한하는 값을 설정한 경우",
             "로그인 시도 횟수를 제한하는 값을 설정하지 않은 경우",
             "로그인 시도 횟수 제한 값 설정"),
    "D-10": ("DB 서버에 지정된 IP주소에서만 접근 가능하도록 제한한 경우",
             "DB 서버에 지정된 IP주소에서만 접근 가능하도록 제한하지 않은 경우",
             "DB 서버에 대해 지정된 IP주소에서만 접근 가능하도록 설정"),
    "D-11": ("시스템 테이블에 DBA만 접근 가능하도록 설정되어 있는 경우",
             "시스템 테이블에 DBA 외 일반 사용자 계정이 접근 가능하도록 설정되어 있는 경우",
             "시스템 테이블에 일반 사용자 계정이 접근할 수 없도록 설정"),
    "D-12": ("Listener의 비밀번호가 설정된 경우",
             "Listener의 비밀번호가 설정되어 있지 않은 경우",
             "Listener 비밀번호 설정"),
    "D-13": ("불필요한 ODBC/OLE-DB가 설치되지 않은 경우",
             "불필요한 ODBC/OLE-DB가 설치된 경우",
             "불필요한 ODBC/OLE-DB 제거"),
    "D-14": ("주요 설정 파일 및 디렉터리의 권한 설정 시 일반 사용자의 수정 권한을 제거한 경우",
             "주요 설정 파일 및 디렉터리의 권한 설정 시 일반 사용자의 수정 권한을 제거하지 않은 경우",
             "주요 설정 파일 및 디렉터리의 권한 설정 변경"),
    "D-15": ("Listener 관련 설정 파일에 대한 권한이 관리자로 설정되어 있으며, Listener로 파라미터를 변경할 수 없게 옵션이 설정된 경우",
             "Listener 관련 설정 파일에 대한 권한이 일반 사용자로 설정되어 있고, Listener로 파라미터를 변경할 수 없게 옵션이 설정되지 않은 경우",
             "주요 파일 및 로그 파일에 대한 권한을 관리자로 제한"),
    "D-16": ("Windows 인증 모드를 사용하고 sa 계정이 비활성화되어 있는 경우 sa 계정 활성화 시 강력한 암호 정책을 설정한 경우",
             "혼합 인증 모드를 사용하고, 활성화된 sa 계정에 대한 강력한 암호 정책 설정을 하지 않은 경우",
             "Windows 인증 모드 사용"),
    "D-17": ("Audit Table 접근 권한이 관리자 계정으로 설정한 경우",
             "Audit Table 접근 권한이 일반 계정으로 설정한 경우",
             "Audit Table 접근 권한을 관리자 계정으로 제한"),
    "D-18": ("DBA 계정의 Role이 Public으로 설정되지 않은 경우",
             "DBA 계정의 Role이 Public으로 설정된 경우",
             "DBA 계정의 Role 설정에서 Public 그룹 권한 취소"),
    "D-19": ("OS_ROLES, REMOTE_OS_AUTHENTICATION, REMOTE_OS_ROLES 설정이 FALSE로 설정된 경우",
             "OS_ROLES, REMOTE_OS_AUTHENTICATION, REMOTE_OS_ROLES 설정이 TRUE로 설정되지 않은 경우",
             "OS_ROLES, REMOTE_OS_AUTHENTICATION, REMOTE_OS_ROLES 설정을 FALSE로 변경"),
    "D-20": ("Object Owner가 SYS, SYSTEM, 관리자 계정 등으로 제한된 경우",
             "Object Owner가 일반 사용자에게도 존재하는 경우",
             "Object Owner를 SYS, SYSTEM, 관리자 계정으로 제한 설정"),
    "D-21": ("WITH_GRANT_OPTION이 ROLE에 의하여 설정된 경우",
             "WITH_GRANT_OPTION이 ROLE에 의하여 설정되지 않은 경우",
             "WITH_GRANT_OPTION이 ROLE에 의하여 설정되도록 변경"),
    "D-22": ("RESOURCE_LIMIT 설정이 TRUE로 되어있는 경우",
             "RESOURCE_LIMIT 설정이 FALSE로 되어있는 경우",
             "RESOURCE_LIMIT 설정을 TRUE로 설정 변경"),
    "D-23": ("xp_cmdshell이 비활성화 되어 있거나, 활성화 되어 있으면 다음의 조건을 모두 만족하는 경우 1. public의 실행(Execute) 권한이 부여되어 있지 않은 경우 2. 서비스 계정(애플리케이션 연동)에 sysadmin 권한이 부여되어 있지 않은 경우",
             "xp_cmdshell이 활성화 되어 있고, 양호의 조건을 만족하지 않는 경우",
             "xp_cmdshell 설정 값을 0 또는 False로 설정"),
    "D-24": ("제한이 필요한 시스템 확장 저장 프로시저들이 DBA 외 guest/public에게 부여되지 않은 경우",
             "제한이 필요한 시스템 확장 저장 프로시저들이 DBA 외 guest/public에게 부여된 경우",
             "guest/public에게 부여된 시스템 확장 저장 프로시저 권한 제거"),
    "D-25": ("보안 패치가 적용된 버전을 사용하는 경우",
             "보안 패치가 적용되지 않는 버전을 사용하는 경우",
             "보안 패치가 적용된 버전으로 업데이트"),
    "D-26": ("DBMS의 감사 로그 저장 정책이 수립되어 있으며, 정책 설정이 적용된 경우",
             "DBMS에 대한 감사 로그 저장을 하지 않거나, 정책 설정이 적용되지 않은 경우",
             "DBMS에 대한 감사 로그 저장 정책 수립, 적용"),
}

# 가이드 항목별 점검 대상(원문) — DBMS 제품별 대상 여부 판정에 사용
KISA_GUIDE_TARGET = {
    "D-01": "Oracle DB, MSSQL, MySQL, Altibase, Tibero, PostgreSQL, Cubrid 등",
    "D-02": "Oracle DB, MSSQL, MySQL, Altibase, Tibero, PostgreSQL, Cubrid 등",
    "D-03": "Oracle DB, MSSQL, MySQL, Altibase, Tibero, PostgreSQL 등",
    "D-04": "Oracle DB, MSSQL, MySQL, Altibase, Tibero, PostgreSQL, Cubrid 등",
    "D-05": "Oracle DB, Altibase, Tibero 등",
    "D-06": "Oracle DB, MSSQL, MySQL, Altibase, Tibero, PostgreSQL 등",
    "D-07": "Oracle DB, MySQL, Altibase, Cubrid 등",
    "D-08": "Oracle DB, MSSQL, MySQL, Tibero, PostgreSQL 등",
    "D-09": "Oracle DB, Altibase, Tibero 등",
    "D-10": "Windows OS, Oracle DB, MySQL, Altibase, Tibero, PostgreSQL 등",
    "D-11": "Oracle DB, MSSQL, MySQL, Altibase, Tibero, PostgreSQL 등",
    "D-12": "Oracle DB",
    "D-13": "Windows OS",
    "D-14": "Oracle DB, PostgreSQL, Cubrid 등",
    "D-15": "Oracle DB",
    "D-16": "MSSQL",
    "D-17": "Oracle DB, Altibase, Tibero 등",
    "D-18": "Oracle DB, Altibase, Tibero, Cubrid 등",
    "D-19": "Oracle DB",
    "D-20": "Oracle DB, Altibase, Tibero, PostgreSQL 등",
    "D-21": "Oracle DB, MySQL, Altibase, Tibero 등",
    "D-22": "Oracle DB",
    "D-23": "MSSQL",
    "D-24": "MSSQL",
    "D-25": "Oracle DB, MSSQL, MySQL, Altibase, Tibero, PostgreSQL, Cubrid 등",
    "D-26": "Oracle DB, MSSQL, Altibase, Tibero, PostgreSQL 등",
}


KISA_RISK_SCORE = {"상": 3, "중": 2, "하": 1}

KISA_FAMILY_LABEL = {"U": "Unix 서버", "W": "Windows 서버", "WEB": "웹 서비스", "D": "DBMS", "N": "네트워크 장비",
                     "S": "보안장비", "PC": "PC"}
KISA_FAMILY_SHORT = {"U": "Unix", "W": "Windows", "WEB": "WEB", "D": "DBMS", "N": "NET", "S": "SEC", "PC": "PC"}
KISA_CATEGORY_FAMILY = {"server": None, "webwas": "WEB", "dbms": "D", "network": "N", "security": "S"}

KISA_EF_SOURCES = {   # 2026 상세가이드 항목 → 판정 근거로 참조할 전자금융 스크립트 항목 (평가기준 엑셀 '과기정통부 고시 제2025-62호' 연계 열) — 판단기준은 가이드 기준
    "U-01": ['SRV-026', 'WST-023'],
    "U-02": ['SRV-069', 'WST-049'],
    "U-03": ['SRV-127', 'WST-087'],
    "U-04": ['SRV-070', 'WST-050'],
    "U-05": ['SRV-142', 'WST-099'],
    "U-06": ['SRV-131', 'WST-090'],
    "U-07": ['SRV-074', 'WST-053'],
    "U-08": ['SRV-073', 'WST-052'],
    "U-09": ['SRV-164', 'WST-110'],
    "U-10": ['SRV-142', 'WST-099'],
    "U-11": ['SRV-165', 'WST-111'],
    "U-12": ['SRV-028', 'WST-025'],
    "U-13": ['SRV-070', 'WST-050'],
    "U-14": ['SRV-121', 'WST-082'],
    "U-15": ['SRV-095', 'WST-068'],
    "U-16": ['SRV-084', 'WST-061'],
    "U-17": ['SRV-083', 'WST-060'],
    "U-18": ['SRV-084', 'WST-061'],
    "U-19": ['SRV-084', 'WST-061'],
    "U-20": ['SRV-084', 'WST-061'],
    "U-21": ['SRV-084', 'WST-061'],
    "U-22": ['SRV-084', 'WST-061'],
    "U-23": ['SRV-091', 'WST-064'],
    "U-24": ['SRV-096', 'WST-069'],
    "U-25": ['SRV-093', 'WST-066'],
    "U-26": ['SRV-144', 'WST-100'],
    "U-27": ['SRV-025', 'WST-022'],
    "U-28": ['SRV-027', 'WST-024'],
    "U-29": ['SRV-084', 'WST-061'],
    "U-30": ['SRV-122', 'WST-083'],
    "U-31": ['SRV-092', 'WST-065'],
    "U-32": ['SRV-092', 'WST-065'],
    "U-33": ['SRV-166', 'WST-112'],
    "U-34": ['SRV-035', 'WST-029'],
    "U-35": ['SRV-013', 'WST-012'],
    "U-36": ['SRV-035', 'WST-029'],
    "U-37": ['SRV-081', 'WST-058'],
    "U-38": ['SRV-004', 'SRV-035', 'WST-003', 'WST-029'],
    "U-39": ['SRV-015', 'WST-014'],
    "U-40": ['SRV-014', 'WST-013'],
    "U-41": ['SRV-034', 'WST-028'],
    "U-42": ['SRV-016', 'WST-015'],
    "U-43": ['SRV-035', 'WST-029'],
    "U-44": ['SRV-035', 'WST-029'],
    "U-45": ['SRV-007', 'WST-006'],
    "U-46": ['SRV-010', 'WST-009'],
    "U-47": ['SRV-009', 'WST-008'],
    "U-48": ['SRV-005', 'WST-004'],
    "U-49": ['SRV-064', 'WST-047'],
    "U-50": ['SRV-066', 'WST-048'],
    "U-51": ['SRV-173', 'WST-116'],
    "U-52": ['SRV-158', 'WST-107'],
    "U-53": ['SRV-171', 'WST-114'],
    "U-54": ['SRV-037', 'WST-030'],
    "U-55": ['SRV-165', 'WST-111'],
    "U-56": ['SRV-161', 'WST-108'],
    "U-57": ['SRV-011', 'WST-010'],
    "U-58": ['SRV-147', 'WST-101'],
    "U-59": ['SRV-001', 'WST-001'],
    "U-60": ['SRV-001', 'WST-001'],
    "U-61": ['SRV-003', 'WST-002'],
    "U-62": ['SRV-163', 'WST-109'],
    "U-63": ['SRV-177', 'WST-119'],
    "U-64": ['SRV-118', 'WST-080'],
    "U-65": ['SRV-175', 'WST-118'],
    "U-66": ['SRV-109', 'WST-076'],
    "U-67": ['SRV-108', 'WST-075'],
    "W-01": ['SRV-072', 'WST-051'],
    "W-02": ['SRV-078', 'WST-055'],
    "W-03": ['SRV-074', 'WST-053'],
    "W-04": ['SRV-127', 'WST-087'],
    "W-05": ['SRV-070', 'WST-050'],
    "W-06": ['SRV-073', 'WST-052'],
    "W-07": ['SRV-079', 'WST-056'],
    "W-08": ['SRV-127', 'WST-087'],
    "W-09": ['SRV-069', 'WST-049'],
    "W-10": ['SRV-123', 'WST-084'],
    "W-11": ['SRV-150', 'WST-104'],
    "W-12": ['SRV-151', 'WST-105'],
    "W-13": ['SRV-022', 'WST-019'],
    "W-14": ['SRV-152', 'WST-106'],
    "W-15": ['SRV-178', 'WST-120'],
    "W-16": ['SRV-020', 'WST-017'],
    "W-17": ['SRV-018', 'WST-016'],
    "W-18": ['SRV-034', 'WST-028'],
    "W-19": ['WST-039'],
    "W-20": ['SRV-034', 'WST-028'],
    "W-21": ['SRV-037', 'WST-030'],
    "W-22": ['SRV-097', 'WST-070'],
    "W-23": ['SRV-013', 'WST-012'],
    "W-24": ['SRV-021', 'WST-018'],
    "W-25": ['SRV-066', 'WST-048'],
    "W-26": ['SRV-034', 'WST-028'],
    "W-27": ['SRV-118', 'WST-080'],
    "W-28": ['SRV-023', 'WST-020'],
    "W-29": ['SRV-147', 'WST-101'],
    "W-30": ['SRV-001', 'WST-001'],
    "W-31": ['SRV-003', 'WST-002'],
    "W-32": ['SRV-173', 'WST-116'],
    "W-33": ['SRV-170', 'SRV-171', 'WST-102', 'WST-113', 'WST-114'],
    "W-34": ['SRV-158', 'WST-107'],
    "W-35": ['DBM-021'],
    "W-36": ['SRV-028', 'WST-025'],
    "W-37": ['SRV-101', 'WST-071'],
    "W-38": ['SRV-118', 'WST-080'],
    "W-39": ['SRV-119', 'WST-081'],
    "W-40": ['SRV-109', 'WST-076'],
    "W-41": ['SRV-175', 'WST-118'],
    "W-42": ['SRV-108', 'WST-075'],
    "W-43": ['SRV-108', 'WST-075'],
    "W-44": ['SRV-090', 'WST-063'],
    "W-45": ['SRV-129', 'WST-089'],
    "W-46": ['SRV-084', 'WST-061'],
    "W-47": ['SRV-125', 'WST-085'],
    "W-48": ['SRV-136', 'WST-094'],
    "W-49": ['SRV-136', 'WST-094'],
    "W-50": ['SRV-116', 'WST-079'],
    "W-51": ['SRV-031', 'WST-027'],
    "W-52": ['SRV-126', 'WST-086'],
    "W-53": ['SRV-140', 'WST-098'],
    "W-54": ['SRV-135', 'WST-093'],
    "W-55": ['SRV-080', 'WST-057'],
    "W-56": ['SRV-029', 'WST-026'],
    "W-57": ['SRV-163', 'WST-109'],
    "W-58": ['SRV-092', 'WST-065'],
    "W-59": ['SRV-103', 'WST-072'],
    "W-60": ['SRV-104', 'WST-073'],
    "W-61": ['SRV-128', 'WST-088'],
    "W-62": ['SRV-105', 'WST-074'],
    "W-63": ['SRV-175', 'WST-118'],
    "W-64": ['SRV-027', 'WST-024'],
    "WEB-01": ['WST-044'],
    "WEB-02": ['WST-044'],
    "WEB-03": ['WST-061'],
    "WEB-04": ['WST-031'],
    "WEB-05": ['WST-032'],
    "WEB-06": ['WST-033'],
    "WEB-07": ['WST-034'],
    "WEB-08": ['WST-035'],
    "WEB-09": ['WST-036'],
    "WEB-10": ['WST-121'],
    "WEB-11": ['WST-037'],
    "WEB-12": ['WST-038'],
    "WEB-13": ['WST-040'],
    "WEB-14": ['WST-041'],
    "WEB-15": ['WST-042'],
    "WEB-16": ['WST-102'],
    "WEB-17": ['WST-037'],
    "WEB-18": ['WST-028'],
    "WEB-19": ['WST-122'],
    "WEB-22": ['WST-123'],
    "WEB-23": ['WST-124'],
    "WEB-24": ['WST-125'],
    "WEB-25": ['WST-080'],
    "WEB-26": ['WST-075'],
    "D-01": ['DBM-001'],
    "D-02": ['DBM-003'],
    "D-03": ['DBM-007', 'DBM-008'],
    "D-04": ['DBM-004'],
    "D-05": ['DBM-019'],
    "D-06": ['DBM-020'],
    "D-07": ['DBM-034'],
    "D-08": ['DBM-005'],
    "D-09": ['DBM-006'],
    "D-10": ['DBM-013'],
    "D-11": ['DBM-017'],
    "D-12": ['DBM-012'],
    "D-13": ['DBM-021'],
    "D-14": ['DBM-022'],
    "D-15": ['DBM-012', 'DBM-022'],
    "D-16": ['DBM-031'],
    "D-17": ['DBM-030'],
    "D-18": ['DBM-015'],
    "D-19": ['DBM-014'],
    "D-20": ['DBM-028'],
    "D-21": ['DBM-024'],
    "D-22": ['DBM-029'],
    "D-23": ['DBM-035'],
    "D-24": ['DBM-036'],
    "D-25": ['DBM-016'],
    "D-26": ['DBM-011'],
    "N-01": ['NET-009'],
    "N-02": ['NET-012'],
    "N-03": ['NET-011'],
    "N-04": ['NET-058'],
    "N-05": ['NET-049'],
    "N-06": ['NET-013'],
    "N-07": ['NET-014'],
    "N-08": ['NET-015'],
    "N-09": ['NET-016'],
    "N-10": ['NET-050'],
    "N-11": ['NET-036'],
    "N-12": ['NET-048'],
    "N-13": ['NET-035'],
    "N-14": ['NET-033'],
    "N-15": ['NET-031'],
    "N-16": ['NET-034'],
    "N-17": ['NET-030'],
    "N-18": ['NET-003'],
    "N-19": ['NET-005'],
    "N-20": ['NET-004'],
    "N-21": ['NET-057'],
    "N-22": ['NET-040'],
    "N-23": ['NET-047'],
    "N-24": ['NET-052'],
    "N-25": ['NET-051'],
    "N-26": ['NET-057'],
    "N-27": ['NET-030'],
    "N-28": ['NET-030'],
    "N-29": ['NET-030'],
    "N-30": ['NET-057'],
    "N-31": ['NET-027'],
    "N-32": ['NET-022'],
    "N-33": ['NET-026'],
    "N-34": ['NET-043', 'NET-044'],
    "N-35": ['NET-057'],
    "N-36": ['NET-030'],
    "N-37": ['NET-030'],
    "N-38": ['NET-045'],
    "S-01": ['ISS-017'],
    "S-02": ['ISS-018'],
    "S-03": ['ISS-020'],
    "S-04": ['ISS-019'],
    "S-05": ['ISS-023'],
    "S-06": ['ISS-021'],
    "S-07": ['ISS-016'],
    "S-08": ['ISS-024'],
    "S-09": ['ISS-005'],
    "S-10": ['ISS-008', 'ISS-009', 'ISS-022'],
    "S-11": ['ISS-001'],
    "S-12": ['ISS-001'],
    "S-13": ['ISS-002'],
    "S-14": ['ISS-025'],
    "S-15": ['ISS-028', 'ISS-029', 'ISS-033', 'ISS-034', 'ISS-035', 'ISS-036', 'ISS-037', 'ISS-038', 'ISS-039', 'ISS-040'],
    "S-16": ['ISS-004'],
    "S-17": ['ISS-003'],
    "S-18": ['ISS-030', 'ISS-031', 'ISS-032', 'ISS-041'],
    "S-19": ['ISS-007'],
    "S-20": ['ISS-006'],
    "S-21": ['ISS-014'],
    "S-22": ['ISS-015'],
    "S-23": ['ISS-010', 'ISS-011', 'ISS-012', 'ISS-042'],
}

# 가이드 D 항목 점검 대상 문구 → 제품 키 (DB_COLS 키 기준, RDS/Aurora/Azure 는 원 제품으로 판단)
_KISA_DB_WORDS = {"Oracle": "ORACLE", "MSSQL": "MSSQL|MSSLQ", "MySQL": "MYSQL", "MariaDB": "MYSQL",
                  "PostgreSQL": "POSTGRE", "Tibero": "TIBERO"}


def _kisa_db_target(code, vendor):
    """DBMS 가이드 항목의 점검 대상에 해당 제품이 포함되는지 (None = 판단 불가 → 대상으로 간주)"""
    tgt = re.sub(r"[^\w, ]", "", KISA_GUIDE_TARGET.get(code, "")).upper()
    if not tgt or re.search(r"\bOS\b", tgt):
        return None
    base = re.sub(r"^(RDS|AURORA|AZURE)-", "", vendor or "", flags=re.I)
    base = {"PGSQL": "PostgreSQL"}.get(base.upper(), base)
    key = next((v for k, v in _KISA_DB_WORDS.items() if k.lower() == base.lower()), None)
    if not key:
        return None
    if base.upper() in _KISA_DB_EXTRA.get(code, ()):   # 대상 목록('…등')엔 없으나 가이드 점검 방법에 제품별 절차가 있는 항목
        return True
    return bool(re.search(key, tgt))


# 가이드 점검 대상 목록은 '… 등' 으로 끝나 전부를 열거하지 않음 → 점검 방법에 해당 제품 절차가 실린 항목은 대상으로 처리
_KISA_DB_EXTRA = {"D-14": ("MYSQL", "MARIADB")}   # D-14: MySQL my.cnf 600/640 절차


def _kisa_family(category, detected_sub):
    """카테고리·세부유형 → 가이드 항목군 (서버: WIN이면 W, 그 외 U)"""
    if category == "server":
        return "W" if detected_sub == "WIN" else "U"
    return KISA_CATEGORY_FAMILY.get(category)


def _kisa_criteria(family, criteria_items=None):
    """
    2026 상세가이드 항목군(family) 평가항목 구성
    - 항목명·중요도·판단기준·조치방법은 모두 가이드 원문(KISA_GUIDE_ITEMS/CRITERIA) 사용
    - sources: 가이드 전용 결과(U-xx 등)가 없을 때 판정 근거로 참조할 전자금융 스크립트 항목
    """
    criteria_items = criteria_items or {}
    items = {}
    for k, (risk, area, name) in KISA_GUIDE_ITEMS.items():
        if k.split("-")[0] != family:
            continue
        g_good, g_bad, g_fix = KISA_GUIDE_CRITERIA[k]
        items[k] = {
            "name":         name,
            "risk":         risk,
            "score":        KISA_RISK_SCORE.get(risk, 0),
            "guide":        True,
            "desc":         "",
            "control_area": area,
            "control_sub":  "",
            "applies_to":   {},
            "criteria_by":  {"GENERIC": {"기준": f"* 양호 : {g_good}\n* 취약 : {g_bad}", "방법": g_fix}},
            "sources":      [s for s in KISA_EF_SOURCES.get(k, []) if not criteria_items or s in criteria_items],
        }
    return items


# 연계 전자금융 항목 '취약'을 그대로 준용할 수 없는 항목 (가이드: 존재 시 설정 이유 인지 / 불필요 여부 판단)
_KISA_JUDGE_MANUAL = {"U-09", "U-25"}


# 가이드가 N/A(해당 없음)를 명시한 항목과 사유 (2026 상세가이드 원문)
_KISA_NA_EXPLICIT = {
    "U-35": r"공유 서비스|NFS|Samba|FTP",       # p70  공유 서비스 미사용 시 양호 또는 N/A
    "U-47": r"메일|SMTP|Sendmail|Postfix",      # p113 메일 서비스 미사용 시 양호 또는 N/A
    "U-48": r"메일|SMTP|Sendmail|Postfix",      # p116
    "S-17": r"망 ?분리|물리적",                  # p376 물리적 망분리 시 해당 없음
    "D-12": r"12c|1[89]c|2[1-9]c",               # p636 Oracle 12c R2 이후 Listener 비밀번호 미지원 → 해당사항 없음
}
_KISA_NA_OR_GOOD = {"U-35": "공유 서비스를", "U-47": "메일 서비스를", "U-48": "메일 서비스를"}   # 가이드 p70·p113·p116
_KISA_NA_TARGET_RE = re.compile(r"^(가이드 점검 대상|평가대상 아님|현재 유형|웹서버/WAS 미탐지|DBMS 미설치|Windows 환경 — Linux/Unix 전용)")


def _kisa_na_allowed(code, why):
    """가이드 기준상 N/A 가 허용되는 판정인지 (점검 대상 제품·OS 아님 / 가이드 명시 항목)"""
    why = why or ""
    if why.startswith("평가대상 아님") and code.split("-")[0] in ("U", "W"):
        return False
    if _KISA_NA_TARGET_RE.match(why) or "가이드 점검 대상(" in why:
        return True
    pat = _KISA_NA_EXPLICIT.get(code)
    return bool(pat and re.search(pat, why))


def _kisa_result(res, criteria_items, kisa_items, family):
    """
    판정 결과(res) → 가이드 항목 판정
    - 가이드 항목코드 결과(주요정보 전용 스크립트·가이드 기준 재판정) 우선
    - 없으면 연계 전자금융 항목 판정 준용 (여러 개: N-A 제외 가장 나쁜 판정, 취약 > 수동확인 > 양호)
    - 연계 항목도 없음: 수동확인
    """
    rank = {RESULT_BAD: 4, RESULT_MANUAL: 3, RESULT_GOOD: 2, RESULT_NA: 1}
    out = {}
    for k, it in kisa_items.items():
        if k in res:
            out[k] = res[k]
            continue
        srcs = [s for s in it["sources"] if s in res]
        if not srcs:
            out[k] = (RESULT_MANUAL, "점검 결과 없음 - 가이드 판단기준에 따라 수동 확인 필요")
            continue
        live = [s for s in srcs if res[s][0] != RESULT_NA]
        if not live:
            out[k] = (RESULT_NA, res[srcs[0]][1])
            continue
        rv = max((res[s][0] for s in live), key=lambda v: rank.get(v, 0))
        parts = [f"({res[s][0]}) {res[s][1]}" if len(live) > 1 else res[s][1] for s in live]
        shared = [c for c in KISA_GUIDE_ITEMS if c.split("-")[0] == family and c != k
                  and set(live) & set(KISA_EF_SOURCES.get(c, []))]
        notes = [f"※ 판정 근거: 점검 스크립트 {', '.join(live)} 결과 (가이드 판단기준 대비 확인 필요)"]
        if shared:
            notes.append(f"※ 같은 점검 결과를 {', '.join(shared)} 항목과 공유 - 항목별 세부 확인 필요")
        if rv == RESULT_BAD and k in _KISA_JUDGE_MANUAL:   # 가이드상 담당자 인지·필요성 판단 항목
            rv = RESULT_MANUAL
            notes.append(f"※ 가이드 판단기준: '{KISA_GUIDE_CRITERIA.get(k, ('',))[0]}' - 담당자 확인 후 판정")
        out[k] = (rv, "\n".join(parts + notes))
    # 가이드 N/A 기준: N/A 는 ① 가이드 '점검 대상'에 해당 제품·OS 가 없는 경우 ② 가이드가 명시한 항목만 허용
    #   그 외 N-A(서비스 미사용·파일 없음 등) → 양호(가이드 조치 방법상 미사용=중지·비활성화 상태) / 근거 불명 → 수동확인
    for k, (rv, why) in list(out.items()):
        if rv == RESULT_NA and k in _KISA_NA_OR_GOOD and re.search(r"미사용|미실행|미설치|미존재|없음", why or ""):
            # 가이드: '서비스를 사용하지 않는 경우 양호 또는 N/A' → 점검 스크립트(양호)와 판정 통일
            out[k] = (RESULT_GOOD, f"{why}\n※ 가이드 참고: {_KISA_NA_OR_GOOD[k]} 사용하지 않는 경우 양호 또는 N/A - 점검 스크립트 판정과 통일해 양호")
            continue
        if rv != RESULT_NA or _kisa_na_allowed(k, why):
            continue
        if re.match(r"평가대상 아님", why or ""):   # 전자금융 평가기준의 대상 구분 - 가이드 U·W 는 해당 OS 전체가 대상
            out[k] = (RESULT_MANUAL, f"{why}\n※ 전자금융 평가기준상 평가대상 외 항목이라 판정 근거 없음 - 가이드 판단기준으로 수동 확인")
            continue
        if re.search(r"미사용|미실행|미설치|미존재|없음|사용하지 않|비활성", why or ""):
            out[k] = (RESULT_GOOD, f"{why}\n※ 가이드 N/A 기준(점검 대상 제외·가이드 명시 항목)에 해당하지 않아 양호 - 점검 대상 서비스·파일 미사용/미존재")
        else:
            out[k] = (RESULT_MANUAL, f"{why}\n※ 가이드 N/A 기준(점검 대상 제외·가이드 명시 항목)에 해당하지 않음 - 가이드 판단기준으로 수동 확인")
    # 가이드 양호 기준에 '서비스 미사용'이 포함된 항목: 미사용(N-A) → 양호
    for k, (rv, why) in out.items():
        g = KISA_GUIDE_CRITERIA.get(k, ("",))[0]
        if (rv == RESULT_NA and not re.match(r"(가이드 점검 대상|평가대상 아님|현재 유형)", why or "")   # 대상 아님(N-A)은 유지
                and re.search(r"사용하지 않거나|미사용 또는|미사용이거나|비활성화 되어 있거나|비활성화되어 있거나|삭제되어 있거나|존재하지 않거나", g)
                and re.search(r"미실행|미사용|미설치|미구동|없음|비활성|사용하지 않", why or "")):
            out[k] = (RESULT_GOOD, f"{why}\n※ 가이드 판단기준: '{g}' - 서비스 미사용으로 양호")
    return out


def _kisa_groups(category, all_results, hosts_info, criteria_items, evidences=None):
    """
    주요정보(MI) 모드: 판정 결과 → 2026 상세가이드 항목 체계로 변환
    반환: [(구분 라벨, all_results, hosts_info, criteria_items), ...]  ※ 서버 Unix/Windows 혼재 시 항목군별 분리
    """
    fams = {}
    for host, (res, sub) in all_results.items():
        fams.setdefault(_kisa_family(category, sub), []).append(host)
    groups = []
    for fam, hosts in fams.items():
        items = _kisa_criteria(fam, criteria_items)
        g_res = {}
        legacy_n = 0
        for h in hosts:
            raw, sub = all_results[h]
            raw = dict(raw)
            ev = dict((evidences or {}).get(h) or {})
            direct = any(k in raw for k in items)
            if fam == "U" and not direct:   # 전자금융 스크립트 증적 → 가이드 기준 재판정
                for k, (rv, why, evd) in _kisa_unix_legacy(ev).items():
                    if k in items:
                        raw[k] = (rv, why + "\n※ 가이드 판단기준으로 판정 (전자금융 점검 스크립트 증적 기반)")
                        if evd:
                            ev[k] = evd
                        legacy_n += 1
            if fam == "W" and not direct:   # 전자금융 스크립트 증적 → 가이드 기준 재판정
                for k, (rv, why, evd) in _kisa_win_legacy(ev).items():
                    raw[k] = (rv, why + "\n※ 가이드 판단기준으로 판정 (전자금융 점검 스크립트 증적 기반)")
                    if evd:
                        ev[k] = evd
                    legacy_n += 1
            if fam == "D" and not direct:   # 전자금융 스크립트 증적 → 가이드 기준 재판정
                for k, (rv, why, evd) in _kisa_db_legacy(ev, sub).items():
                    raw[k] = (rv, why + "\n※ 가이드 판단기준으로 판정 (전자금융 점검 스크립트 증적 기반)")
                    if evd:
                        ev[k] = evd
                    legacy_n += 1
            if fam == "D":   # 가이드 점검 대상 제품 아님 → N-A
                for k in items:
                    if _kisa_db_target(k, sub) is False:
                        raw[k] = (RESULT_NA, f"가이드 점검 대상({re.sub(r'^[^A-Za-z가-힣]+', '', KISA_GUIDE_TARGET.get(k, ''))})에 {sub} 미포함")
            kres = _kisa_result(raw, criteria_items, items, fam)
            if evidences is not None:   # 현황 및 문제점: 가이드 판단기준으로 구성
                kev = {k: (ev.get(k) or "\n".join(ev[x] for x in it["sources"] if ev.get(x))) for k, it in items.items()}
                kres = compose_status(kres, kev, items, "GENERIC")
            g_res[h] = (kres, sub)
        g_hosts = [hi for hi in hosts_info if hi["hostname"] in g_res]
        print(f"[INFO] 주요정보통신기반시설 상세가이드(2026) 항목으로 변환: {KISA_FAMILY_LABEL[fam]} "
              f"{len(items)}개 항목 / 대상 {len(hosts)}대"
              + (f" / 전자금융 스크립트 증적 → 가이드 기준 재판정 {legacy_n}건" if legacy_n else ""))
        label = KISA_FAMILY_SHORT[fam] if len(fams) > 1 else ""
        groups.append((label, g_res, g_hosts, items))
    return groups


# ----------------------------------------------------------------
# 전자금융(SRV) 증적 → 주요정보통신기반시설 상세가이드(2026, U-01~U-67) 판정 재구성
# ----------------------------------------------------------------
# 주요정보 전용 스크립트(check_server_u.sh) 없이 전자금융 스크립트 증적만 있는 경우 사용.
# 가이드 판단기준이 평가기준과 다른 항목(임계값·대상 파일·통합 점검 항목)을
# 증적의 명령 출력으로 다시 판정한다. 판정 근거는 명령어 내용으로 찾으므로
# 항목코드 체계가 다른 구버전 스크립트(예: SRV-116=r 계열, SRV-147=tcpdump) 증적도 처리된다.
# 증적에서 근거를 찾지 못한 항목은 반환하지 않음 → 평가기준 연계 판정으로 대체.

_LS_RE = re.compile(r"^([-dlcbps])([rwxsStT-]{9})[.+@]?\s+\d+\s+(\S+)\s+(\S+)\s+.*?\s(\S+?)(?:\s+->\s+\S+)?\s*$")


def _ls_mode(bits):
    """ls 권한 문자열(rwxr-xr-x) → 8진 정수 (특수 비트 포함)"""
    v = 0
    for i, c in enumerate(bits):
        if c in "rwxsStT" and not (c in "ST"):
            v |= 1 << (8 - i)
    if bits[2] in "sS": v |= 0o4000
    if bits[5] in "sS": v |= 0o2000
    if bits[8] in "tT": v |= 0o1000
    return v


def _ev_cmds(evidence):
    """증적 dict → [(명령, 출력 줄 목록)] (항목코드 무관, 명령 단위)"""
    out = []
    for text in (evidence or {}).values():
        cur = None
        for ln in text.splitlines():
            if ln.startswith(("$ ", "# ")):   # 명령($) 또는 설명·SQL(#) 블록
                cur = (ln[2:], [])
                out.append(cur)
            elif cur is not None and ln.strip():
                cur[1].append(ln.rstrip())
    return out


class _UEv:
    """증적 명령 출력 검색 도우미"""

    def __init__(self, evidence):
        self.cmds = _ev_cmds(evidence)
        self.ls = {}
        for cmd, lines in self.cmds:
            for ln in lines:
                m = _LS_RE.match(ln)
                if m and m.group(5).startswith("/"):
                    self.ls[m.group(5)] = (m.group(1), _ls_mode(m.group(2)), m.group(3), m.group(4), ln.strip())

    def find(self, cmd_pat, out_pat=None):
        """명령이 cmd_pat 에 맞는 블록들 [(cmd, lines)] (out_pat 지정 시 출력에 해당 패턴이 있는 블록만)"""
        r = []
        for cmd, lines in self.cmds:
            if re.search(cmd_pat, cmd) and (out_pat is None or any(re.search(out_pat, l) for l in lines)):
                r.append((cmd, lines))
        return r

    def covered(self, path):
        """해당 경로를 대상으로 한 명령이 증적에 있는지"""
        return any(path in cmd for cmd, _ in self.cmds)

    @staticmethod
    def show(blocks, limit=12):
        out = []
        for cmd, lines in blocks:
            out.append(f"$ {cmd}")
            out += (lines[:limit] + (["  … (이하 생략)"] if len(lines) > limit else [])) if lines else ["  (출력 없음)"]
        return "\n".join(out)


def _u_accounts(ev):
    """/etc/passwd 계정 목록 {이름: (uid, shell, home)} — Shell 현황·홈 디렉터리 증적에서 수집"""
    acc = {}
    for cmd, lines in ev.find(r"/etc/passwd"):
        for l in lines:
            m = re.match(r"^(\S+)\s+UID=(\d+)\s+Shell=(\S*)", l)
            if m:
                acc.setdefault(m.group(1), [int(m.group(2)), m.group(3), ""])[1] = m.group(3)
                continue
            m = re.match(r"^(\S+):[^:]*:(\d+):\d+:[^:]*:([^:]*):(\S*)$", l)
            if m:
                acc[m.group(1)] = [int(m.group(2)), m.group(4), m.group(3)]
                continue
    for cmd, lines in ev.find(r"\$3>=500 \|\| \$3==0|\$3>=500\|\|\$3==0"):
        for l in lines:
            m = re.match(r"^(\S+)\s+(\d+)\s+(/\S*)$", l)
            if m:
                acc.setdefault(m.group(1), [int(m.group(2)), "", ""])[2] = m.group(3)
    return acc


_NOLOGIN = re.compile(r"(nologin|/false|/sync|/shutdown|/halt)$")


def _kisa_unix_legacy(evidence):
    """전자금융 서버 증적 → {U-xx(2026 상세가이드): (판정, 사유, 근거 증적)}"""
    ev = _UEv(evidence)
    if not ev.cmds:
        return {}
    r = {}
    acc = _u_accounts(ev)

    def put(code, rv, why, blocks):
        r[code] = (rv, why, _UEv.show(blocks) if blocks else "")

    def live(l):
        s = l.split(":", 1)[1] if re.match(r"^/\S+:", l) else l
        return None if s.lstrip().startswith("#") else s

    # ── U-02 비밀번호 관리정책 (영문·숫자·특수문자 8자 이상, 최소 1일, 최대 90일, 최근 4회 기억) ──
    pol, used = {}, []
    for pat in (r"PASS_MAX_DAYS|PASS_MIN_DAYS", r"pwquality|pam_cracklib|MINLEN|minlen", r"remember|pwhistory"):
        for cmd, lines in ev.find(pat):
            used.append((cmd, lines))
            for l in lines:
                t = live(l)
                if t is None:
                    continue
                for k, v in re.findall(r"\b(PASS_MAX_DAYS|PASS_MIN_DAYS|PASS_MIN_LEN)\s+(-?\d+)", t):
                    pol[k] = int(v)
                for k, v in re.findall(r"\b(minlen|dcredit|ucredit|lcredit|ocredit|minclass|remember)\s*=\s*(-?\d+)", t):
                    pol[k] = int(v)
    if "PASS_MAX_DAYS" in pol or "minlen" in pol or "PASS_MIN_LEN" in pol:
        bad, unk = [], []
        mx = pol.get("PASS_MAX_DAYS")
        if mx is None: unk.append("최대 사용기간")
        elif mx > 90 or mx <= 0: bad.append(f"최대 사용기간 {mx}일(90일 초과)")
        mn = pol.get("PASS_MIN_DAYS")
        if mn is None: unk.append("최소 사용기간")
        elif mn < 1: bad.append(f"최소 사용기간 {mn}일(1일 미만)")
        ln = pol.get("minlen", pol.get("PASS_MIN_LEN"))
        if ln is None: unk.append("최소 길이")
        elif ln < 8: bad.append(f"최소 길이 {ln}자(8자 미만)")
        cls = sum(1 for k in ("dcredit", "ocredit") if pol.get(k, 0) < 0) + (1 if pol.get("ucredit", 0) < 0 or pol.get("lcredit", 0) < 0 else 0)
        if not (pol.get("minclass", 0) >= 3 or cls >= 3):
            if any(k in pol for k in ("dcredit", "ucredit", "lcredit", "ocredit", "minclass")):
                bad.append("복잡성(영문·숫자·특수문자 조합) 미흡")
            else:
                unk.append("복잡성")
        rem = pol.get("remember")
        if rem is None: unk.append("최근 비밀번호 기억")
        elif rem < 4: bad.append(f"최근 비밀번호 기억 {rem}회(4회 미만)")
        cur = ", ".join(f"{k}={v}" for k, v in pol.items())
        if bad:
            put("U-02", RESULT_BAD, f"비밀번호 관리정책 미흡: {', '.join(bad)}" + (f" / 증적 미확인: {', '.join(unk)}" if unk else "") + f" (설정값: {cur})", used)
        elif unk:
            put("U-02", RESULT_MANUAL, f"수집된 정책 값은 기준 충족 ({cur}) - 증적 미확인 항목 확인 필요: {', '.join(unk)}", used)
        else:
            put("U-02", RESULT_GOOD, f"비밀번호 관리정책 설정 ({cur})", used)

    # ── U-03 계정 잠금 임계값 (10회 이하) ──
    blks = ev.find(r"pam_tally|pam_faillock|faillock")
    if blks:
        deny = []
        for cmd, lines in blks:
            for l in lines:
                t = live(l)
                if t is not None:
                    deny += [int(x) for x in re.findall(r"\bdeny\s*=\s*(\d+)", t)]
        if not deny:
            put("U-03", RESULT_BAD, "계정 잠금 임계값(deny) 미설정", blks)
        elif 0 < min(deny) <= 10:
            put("U-03", RESULT_GOOD, f"계정 잠금 임계값 deny={min(deny)} (10회 이하)", blks)
        else:
            put("U-03", RESULT_BAD, f"계정 잠금 임계값 deny={min(deny)} ({'잠금 없음' if min(deny) == 0 else '10회 초과'})", blks)

    # ── U-04 비밀번호 파일 보호 / U-13 암호화 알고리즘(SHA-2 이상) ──
    blks = ev.find(r"/etc/shadow", r"^\S+\s+(\$\w*\$?|\*|!+\S*|[A-Za-z0-9./]{2,})\s*$")
    hashes = {}
    for cmd, lines in blks:
        for l in lines:
            m = re.match(r"^(\S+)\s+(\S+)\s*$", l)
            if m and not m.group(1).startswith(("ENCRYPT_METHOD", "MD5_CRYPT")):
                hashes[m.group(1)] = m.group(2)
    enc = ev.find(r"ENCRYPT_METHOD")
    meth = ""
    for cmd, lines in enc:
        for l in lines:
            m = re.match(r"^\s*ENCRYPT_METHOD\s+(\S+)", l)
            if m: meth = m.group(1).upper()
    if hashes:
        put("U-04", RESULT_GOOD, f"쉐도우 비밀번호 사용 (/etc/shadow 에 해시 저장, 계정 {len(hashes)}개 확인)", blks)
        real = {u: h for u, h in hashes.items() if h.startswith("$") or re.match(r"^[A-Za-z0-9./]{13}$", h)}
        weak = [u for u, h in real.items() if not re.match(r"^\$(5|6|y|gy|7|2[aby]?)\$", h)]
        if weak:
            put("U-13", RESULT_BAD, f"SHA-2 미만 알고리즘 사용 계정: {', '.join(f'{u}({real[u][:3]})' for u in weak[:10])}", blks + enc)
        elif real:
            algs = sorted({real[u][:3] for u in real})
            put("U-13", RESULT_GOOD, f"비밀번호 해시 {', '.join(algs)} 사용 ($5$=SHA-256, $6$=SHA-512, $y$=yescrypt)"
                + (f", ENCRYPT_METHOD {meth}" if meth else ""), blks + enc)
        elif meth:
            put("U-13", RESULT_GOOD if meth in ("SHA256", "SHA512", "YESCRYPT") else RESULT_BAD,
                f"비밀번호 설정 계정 없음 - 기본 알고리즘 ENCRYPT_METHOD {meth}", enc)

    # ── 계정 목록 기반: U-05 UID 0 / U-11 사용자 shell / U-55 FTP 계정 shell ──
    if acc:
        src = ev.find(r"/etc/passwd", r"UID=\d+|^\S+:[^:]*:\d+:")
        uid0 = [u for u, (uid, _, _) in acc.items() if uid == 0 and u != "root"]
        put("U-05", RESULT_BAD if uid0 else RESULT_GOOD,
            f"root 외 UID 0 계정: {', '.join(uid0)}" if uid0 else "root 외 UID 0 계정 없음", src)
        sysacc = ("daemon", "bin", "sys", "adm", "listen", "nobody", "nobody4", "noaccess", "diag", "operator", "games", "gopher")
        shells = {u: s for u, (_, s, _) in acc.items() if s}
        if shells:
            bad = [f"{u}({shells[u]})" for u in sysacc if u in shells and not _NOLOGIN.search(shells[u])]
            other = [f"{u}({s})" for u, s in shells.items()
                     if u not in sysacc and u != "root" and 0 < acc[u][0] < 1000 and not _NOLOGIN.search(s)]
            note = f" / 참고: 그 외 UID 1000 미만 로그인 쉘 계정 {', '.join(other)} - 로그인 필요 여부 확인" if other else ""
            put("U-11", RESULT_BAD if bad else RESULT_GOOD,
                (f"로그인 불필요 계정에 쉘 부여: {', '.join(bad)}" if bad else
                 "로그인 불필요 계정(daemon·bin·sys·adm·listen·nobody·operator·games 등)에 nologin/false 부여") + note, src)
            if "ftp" in shells:
                put("U-55", RESULT_GOOD if _NOLOGIN.search(shells["ftp"]) else RESULT_BAD, f"ftp 계정 쉘: {shells['ftp']}", src)
            else:
                put("U-55", RESULT_GOOD, "ftp 계정 없음", src)

    # ── U-12 세션 종료 시간 (600초 이하) ──
    blks = ev.find(r"TMOUT|autologout")
    if blks:
        vals = []
        for cmd, lines in blks:
            for l in lines:
                t = live(l)
                if t is None:
                    continue
                vals += [int(x) for x in re.findall(r"\bTMOUT\s*=\s*(\d+)", t)]
                vals += [int(x) * 60 for x in re.findall(r"autologout\s*=\s*(\d+)", t)]
        vals = [v for v in vals if v > 0]
        if not vals:
            put("U-12", RESULT_BAD, "Session Timeout(TMOUT) 미설정", blks)
        elif min(vals) <= 600:
            put("U-12", RESULT_GOOD, f"TMOUT={min(vals)}초 (600초 이하)", blks)
        else:
            put("U-12", RESULT_BAD, f"TMOUT={min(vals)}초 (600초 초과)", blks)

    # ── 주요 파일 소유자·권한: U-16/18/19/20/21/22/29 (2026 가이드 기준값) ──
    def filechk(code, paths, maxmode, owners, absent_rv, absent_why):
        found = [(p, ev.ls[p]) for p in paths if p in ev.ls]
        blks = [b for b in ev.cmds if any(_LS_RE.match(ln) and ln.rstrip().endswith(" " + p) for ln in b[1] for p in paths)] \
            or [b for b in ev.cmds if any(re.search(re.escape(p) + r"(\s|$|\))", b[0]) for p in paths)]   # 권한 목록(ls) 블록 우선
        if not found:
            if absent_rv and any(ev.covered(p) for p in paths):
                put(code, absent_rv, absent_why, blks)
            return
        bad = []
        for p, (typ, mode, own, grp, _) in found:
            if typ == "l":
                continue
            if own not in owners:
                bad.append(f"{p} 소유자 {own}")
            if mode & ~maxmode & 0o7777:
                bad.append(f"{p} 권한 {mode:03o}")
        desc = ", ".join(f"{p}({own}, {mode:03o})" for p, (typ, mode, own, grp, _) in found)
        if bad:
            put(code, RESULT_BAD, f"{' / '.join(bad)} (기준: 소유자 {'/'.join(owners)}, {maxmode:03o} 이하)", blks)
        else:
            put(code, RESULT_GOOD, f"{desc} - 기준(소유자 {'/'.join(owners)}, {maxmode:03o} 이하) 충족", blks)

    filechk("U-16", ["/etc/passwd"], 0o644, ("root",), None, "")
    filechk("U-18", ["/etc/shadow"], 0o400, ("root",), None, "")
    filechk("U-19", ["/etc/hosts"], 0o644, ("root",), None, "")
    filechk("U-20", ["/etc/inetd.conf", "/etc/xinetd.conf"], 0o600, ("root",), RESULT_GOOD, "/etc/inetd.conf·/etc/xinetd.conf 파일 없음 (inetd/xinetd 미사용)")
    filechk("U-21", ["/etc/syslog.conf", "/etc/rsyslog.conf"], 0o640, ("root", "bin", "sys"), None, "")
    filechk("U-22", ["/etc/services"], 0o644, ("root", "bin", "sys"), None, "")
    filechk("U-29", ["/etc/hosts.lpd"], 0o600, ("root",), RESULT_GOOD, "/etc/hosts.lpd 파일 없음")
    if "U-29" not in r:
        put("U-29", RESULT_MANUAL, "증적 미수집 (/etc/hosts.lpd 존재 여부·권한 확인 필요: ls -l /etc/hosts.lpd)", [])

    # ── U-17 시스템 시작 스크립트 (소유자 root, 일반 사용자 쓰기 권한 없음) ──
    blks = ev.find(r"init\.d|rc\.d|rc\.local|systemd/system")
    if blks:
        bad = []
        for cmd, lines in blks:
            for l in lines:
                m = re.match(r"^([-d])([rwxsStT-]{9})[.+@]?\s+\d+\s+(\S+)\s+(\S+)\s+.*\s(\S+)$", l)
                if not m or m.group(5) in (".", ".."):
                    continue
                mode = _ls_mode(m.group(2))
                if m.group(3) != "root" or mode & 0o022:
                    bad.append(f"{m.group(5)}({m.group(3)}, {mode:03o})")
        put("U-17", RESULT_BAD if bad else RESULT_GOOD,
            f"소유자 root 아님 또는 그룹/기타 쓰기 권한: {', '.join(bad[:10])}" if bad else
            "시작 스크립트 소유자 root, 일반 사용자 쓰기 권한 없음 (증적 목록 기준)", blks)

    # ── U-24 환경변수 파일 (소유자 root/해당 계정, root·소유자 외 쓰기 권한 없음) ──
    envf = [(p, v) for p, v in ev.ls.items() if re.search(r"/\.(profile|kshrc|cshrc|bashrc|bash_profile|login|exrc|netrc|\w*shrc)$|^/etc/(profile|bashrc)$", p)]
    if envf:
        bad = []
        for p, (typ, mode, own, grp, _) in envf:
            if typ == "l":
                continue
            home_owner = next((u for u, (_, _, h) in acc.items() if h and h != "/" and p.startswith(h.rstrip("/") + "/")), None)
            if own != "root" and own != home_owner and not p.startswith(f"/home/{own}/"):
                bad.append(f"{p} 소유자 {own}")
            if mode & 0o022:
                bad.append(f"{p} 권한 {mode:03o}")
        put("U-24", RESULT_BAD if bad else RESULT_GOOD,
            f"환경변수 파일 기준 위반: {', '.join(bad[:10])}" if bad else
            f"환경변수 파일 {len(envf)}개 소유자·쓰기 권한 적절 (root·소유자만 쓰기)", ev.find(r"\.bashrc|\.profile"))

    # ── U-31 / U-32 홈 디렉터리 ──
    blks = ev.find(r"ls -ld", r"^\S+\s+/\S*\s+d[rwxsStT-]{9}")
    homes = {}
    for cmd, lines in blks:
        for l in lines:
            m = re.match(r"^(\S+)\s+(/\S*)\s+d([rwxsStT-]{9})[.+@]?\s+\d+\s+(\S+)\s+(\S+)", l)
            if m:
                homes[m.group(1)] = (m.group(2), _ls_mode(m.group(3)), m.group(4))
    if homes and acc:
        login = {u for u, (uid, sh, _) in acc.items() if sh and not _NOLOGIN.search(sh)}
        tgt = {u: v for u, v in homes.items() if u in login}
        bad = [f"{h}(소유자 {o})" for u, (h, m, o) in tgt.items() if o != u and u != "root"]
        bad += [f"{h}({m:03o})" for u, (h, m, o) in tgt.items() if m & 0o002]
        sysn = [h for u, (h, m, o) in homes.items() if u not in login and (o != u or m & 0o002)]
        note = f" / 참고: 로그인 불가 시스템 계정 홈 {', '.join(sysn[:6])} 은 소유자 불일치(서비스 디렉터리)" if sysn else ""
        if tgt:
            put("U-31", RESULT_BAD if bad else RESULT_GOOD,
                (f"홈 디렉터리 소유자 불일치/타 사용자 쓰기: {', '.join(bad)}" if bad else
                 f"로그인 계정 {len(tgt)}개 홈 디렉터리 소유자 일치, 타 사용자 쓰기 권한 없음") + note, blks)
        listed = {u for u, (uid, _, h) in acc.items() if uid >= 500 and h}
        if listed and any(re.search(r"\[ -d", c) for c, _ in blks):
            miss = [f"{u}({acc[u][2]})" for u in listed if u not in homes and u in login]
            put("U-32", RESULT_BAD if miss else RESULT_GOOD,
                f"홈 디렉터리가 존재하지 않는 계정: {', '.join(miss)}" if miss else
                "로그인 계정 홈 디렉터리 모두 존재 (UID 500 이상 계정 기준)", blks + ev.find(r"\$3>=500 \|\| \$3==0"))

    # ── 서비스: U-34 Finger / U-36 r 계열 / U-38 DoS / U-41 automountd ──
    def svc_chk(code, cmd_pat, hit_pat, name):
        blks = ev.find(cmd_pat)
        if not blks:
            return
        hits = []
        for cmd, lines in blks:
            for l in lines:
                if l.strip() == "active" or (re.search(hit_pat, l) and not re.search(r"\bgrep\b", l)
                                             and not l.strip().startswith("#")
                                             and not re.search(r"\b(disabled|masked|static|inactive|unknown)\b", l)):
                    hits.append(l.strip())
        put(code, RESULT_BAD if hits else RESULT_GOOD,
            f"{name} 활성: {' / '.join(hits[:5])}" if hits else f"{name} 비활성 (실행 중인 프로세스·활성 서비스 없음)", blks)

    svc_chk("U-34", r"finger", r"finger", "Finger 서비스")
    svc_chk("U-36", r"rsh|rlogin|rexec", r"\b(in\.)?(rshd|rlogind|rexecd)\b|^\s*(shell|login|exec)\s+stream|rsh\.socket|rlogin\.socket|rexec\.socket", "r 계열 서비스")
    svc_chk("U-38", r"chargen", r"\b(echo|discard|daytime|chargen)\b", "DoS 취약 서비스(echo·discard·daytime·chargen)")
    svc_chk("U-41", r"automount|autofs", r"automount", "automountd")

    # ── U-42 불필요 RPC / U-43 NIS (rpcinfo) ──
    rpc = ev.find(r"rpcinfo")
    if rpc:
        nis = [l.strip() for c, ls in rpc for l in ls if re.search(r"\byp(serv|bind|xfrd|passwd|update)\b|rpc\.nisd", l)]
        put("U-43", RESULT_BAD if nis else RESULT_GOOD,
            f"NIS 서비스 등록: {' / '.join(nis[:4])}" if nis else "RPC 등록 서비스에 NIS(ypserv/ypbind 등) 없음", rpc)
        rlist = r"\b(rpc\.cmsd|ttdbserverd|sadmind|rusersd|walld|sprayd|rstatd|rpc\.nisd|rexd|pcnfsd|status|rpc\.statd|ypupdated|rquotad|kcms_server|cachefsd)\b"
        hits = sorted({re.search(rlist, l).group(1) for c, ls in rpc for l in ls if re.search(rlist, l) and "grep" not in l})
        port = [l for c, ls in rpc for l in ls if "portmapper" in l]
        put("U-42", RESULT_BAD if hits else RESULT_GOOD,
            (f"불필요 RPC 서비스 활성: {', '.join(hits)}" + (" (status = rpc.statd)" if "status" in hits else "")) if hits else
            "가이드 대상 RPC 서비스(rpc.cmsd·ttdbserverd·sadmind·rusersd·walld·sprayd·rstatd·rpc.statd·rquotad 등) 미등록"
            + (" - rpcbind(portmapper) 는 동작 중(대상 목록 외)" if port else ""), rpc)

    # ── U-44 tftp·talk ──
    tf = ev.find(r":69 |tftp")
    xin = ev.find(r"xinetd\.d")
    if tf:
        hits = [l.strip() for c, ls in tf for l in ls if re.search(r":69\b|tftp|talk", l) and "grep" not in l and not l.strip().startswith("#")]
        hits += [l.strip() for c, ls in xin for l in ls if re.search(r"\b(tftp|talk|ntalk)\b", l)]
        put("U-44", RESULT_BAD if hits else RESULT_GOOD,
            f"tftp/talk 서비스 활성 또는 설정 존재: {' / '.join(hits[:5])}" if hits else
            "tftp(69/udp) 미사용, xinetd/inetd 에 tftp·talk·ntalk 활성 설정 없음", tf + xin)

    # ── U-37 crontab·at 명령어 750 이하, cron·at 관련 파일 640 이하 ──
    fs = [(p, v) for p, v in ev.ls.items() if re.search(r"^/etc/cron|^/var/spool/cron|^/etc/at\.(allow|deny)$|^/var/spool/at", p) and v[0] == "-"]
    if fs:
        bad = [f"{p}({own}, {mode:03o})" for p, (typ, mode, own, grp, _) in fs if own != "root" or mode & ~0o640 & 0o7777]
        cmd_ = [(p, v) for p, v in ev.ls.items() if re.search(r"/usr/bin/(crontab|at)$", p)]
        bad += [f"{p}({mode:04o}, 일반사용자 실행 가능)" for p, (typ, mode, own, grp, _) in cmd_ if mode & 0o001]
        put("U-37", RESULT_BAD if bad else RESULT_GOOD,
            f"cron·at 관련 기준 위반(파일 root·640 이하, 명령어 750 이하): {', '.join(bad[:8])}" if bad else
            "cron·at 관련 파일 root·640 이하" + ("" if cmd_ else " (crontab·at 명령어 권한 증적 없음 - 750 이하 확인 필요)"),
            ev.find(r"/etc/cron|/var/spool/cron|/etc/at\.|/var/spool/at"))

    # ── FTP: U-54 암호화되지 않은 FTP / U-56 FTP 접근 제어 ──
    ftp = ev.find(r"vsftpd|proftpd|ftpd")
    ftp_ps = [b for b in ftp if re.search(r"ps -|pgrep|systemctl", b[0])]
    if ftp_ps:
        run = [l.strip() for c, ls in ftp_ps for l in ls if re.search(r"vsftpd|proftpd|pure-ftpd|in\.ftpd|\bftpd\b", l) and "grep" not in l]
        if run:
            put("U-54", RESULT_BAD, f"암호화되지 않은 FTP 서비스 실행: {run[0][:80]} (FTPS 적용 시 예외 - 설정 확인)", ftp_ps)
            put("U-56", RESULT_MANUAL, "FTP 서비스 실행 중 - 특정 IP/호스트 접근 제어(tcp_wrappers, hosts.allow 등) 설정 확인 필요", ftp_ps)
        else:
            put("U-54", RESULT_GOOD, "FTP 서비스 미실행", ftp_ps)
            put("U-56", RESULT_NA, "FTP 서비스 미실행 - 접근 제어 점검 대상 없음", ftp_ps)

    # ── SNMP: U-58 ~ U-61 ──
    sn = ev.find(r"snmpd")
    sn_ps = [b for b in sn if re.search(r"ps -|pgrep|systemctl|lssrc|svcs", b[0])]
    if sn_ps:
        run = [l.strip() for c, ls in sn_ps for l in ls if re.search(r"snmpd", l) and "grep" not in l and l.strip() not in ("inactive", "unknown")]
        if run:
            put("U-58", RESULT_BAD, f"SNMP 서비스 사용 중: {run[0][:80]} (가이드: 사용 시 취약 - 업무상 필요 여부 확인)", sn_ps)
        else:
            put("U-58", RESULT_GOOD, "SNMP 서비스 미사용 (snmpd 미실행)", sn_ps)
            for c in ("U-59", "U-60", "U-61"):
                put(c, RESULT_NA, "SNMP 서비스 미사용 - 점검 대상 없음", sn_ps)

    # ── U-63 sudoers 소유자 root·권한 640 이하 ──
    su = ev.find(r"sudoers")
    if "/etc/sudoers" in ev.ls:
        typ, mode, own, grp, _ = ev.ls["/etc/sudoers"]
        ok_ = own == "root" and not (mode & ~0o640 & 0o7777)
        put("U-63", RESULT_GOOD if ok_ else RESULT_BAD, f"/etc/sudoers 소유자 {own}, 권한 {mode:03o} (기준: root, 640 이하)", su)
    elif su:
        nop = [l.split(":", 1)[0] for c, ls in su for l in ls if "NOPASSWD" in l]
        put("U-63", RESULT_MANUAL, "증적에 /etc/sudoers 소유자·권한 미수집 (ls -l /etc/sudoers 확인 필요)"
            + (f" / 참고: NOPASSWD 설정 파일 {', '.join(sorted(set(nop)))}" if nop else ""), su)

    # ── U-67 로그 파일 소유자 root·권한 644 이하 ──
    logs = [(p, v) for p, v in ev.ls.items() if p.startswith("/var/log/") and v[0] == "-"]
    if logs:
        bad = [f"{p}({own}, {mode:03o})" for p, (typ, mode, own, grp, _) in logs if own != "root" or mode & ~0o644 & 0o7777]
        put("U-67", RESULT_BAD if bad else RESULT_GOOD,
            f"로그 파일 기준 위반(소유자 root, 644 이하): {', '.join(bad[:8])}" if bad else
            f"로그 파일 {len(logs)}개 소유자 root, 권한 644 이하", ev.find(r"/var/log/"))
    return r


def _kisa_win_legacy(evidence):
    """전자금융 Windows 서버 증적 → {W-xx(2026 상세가이드): (판정, 사유, 근거 증적)} — 기준값이 평가기준과 다른 항목"""
    ev = _UEv(evidence)
    r = {}
    na_blk = ev.find(r"net accounts")

    def na_val(pat):
        for c, ls in na_blk:
            for l in ls:
                if re.search(pat, l, re.I):
                    v = l.split(":", 1)[-1].strip()
                    return v
        return None

    def num(v):
        m = re.search(r"-?\d+", v or "")
        return int(m.group()) if m else None

    # W-04 계정 잠금 임계값 5 이하
    th = na_val(r"Lockout threshold|잠금 임계값")
    if th is not None:
        n = num(th)
        if n and 0 < n <= 5:
            r["W-04"] = (RESULT_GOOD, f"계정 잠금 임계값 {n}회 (5회 이하)", _UEv.show(na_blk))
        else:
            r["W-04"] = (RESULT_BAD, f"계정 잠금 임계값 {th if not n else str(n) + '회'} (5회 이하 필요)", _UEv.show(na_blk))
        # W-08 잠금 기간·원래대로 설정 기간 60분 이상
        du, ow = num(na_val(r"Lockout duration|잠금 기간")), num(na_val(r"Lockout observation window|잠금 관찰 창"))
        if not n:
            r["W-08"] = (RESULT_BAD, "계정 잠금 임계값 미설정 - 잠금 기간 적용 안 됨", _UEv.show(na_blk))
        elif du is not None and ow is not None:
            r["W-08"] = ((RESULT_GOOD, f"계정 잠금 기간 {du}분, 원래대로 설정 기간 {ow}분 (60분 이상)") if du >= 60 and ow >= 60
                         else (RESULT_BAD, f"계정 잠금 기간 {du}분, 원래대로 설정 기간 {ow}분 (60분 이상 필요)")) + (_UEv.show(na_blk),)
    # W-09 비밀번호 관리 정책(복잡성·최소 길이 8·최대 90일·최소 1일)
    mx, mn, ln = num(na_val(r"Maximum password age|최대 암호 사용 기간")), num(na_val(r"Minimum password age|최소 암호 사용 기간")), num(na_val(r"Minimum password length|최소 암호 길이"))
    cpx = None
    for c, ls in ev.find(r"PasswordComplexity"):
        for l in ls:
            parts = [x.strip() for x in l.split("/")]
            if len(parts) == 3:
                cpx = parts[2] or None
    if mx is not None or ln is not None:
        bad = []
        if mx is None or mx <= 0 or mx > 90: bad.append(f"최대 사용 기간 {mx if mx and mx > 0 else '제한 없음'}{'일' if mx and mx > 0 else ''}")
        if mn is None or mn < 1: bad.append(f"최소 사용 기간 {mn}일")
        if ln is None or ln < 8: bad.append(f"최소 길이 {ln}자")
        if cpx == "0": bad.append("복잡성 사용 안 함")
        cur = f"최대 {mx}일, 최소 {mn}일, 최소 길이 {ln}자, 복잡성={cpx or '확인 불가'}"
        blocks = _UEv.show(na_blk + ev.find(r"PasswordComplexity"))
        if bad: r["W-09"] = (RESULT_BAD, f"비밀번호 관리 정책 미흡: {', '.join(bad)} ({cur})", blocks)
        elif cpx is None: r["W-09"] = (RESULT_MANUAL, f"{cur} - 복잡성 정책 확인 필요(관리자 권한)", blocks)
        else: r["W-09"] = (RESULT_GOOD, f"비밀번호 관리 정책 적용 ({cur})", blocks)
    # W-36 원격터미널 접속 타임아웃 30분 이하
    mi = [num(l.split(":", 1)[1]) for c, ls in ev.find(r"MaxIdleTime") for l in ls if re.match(r"^\s*MaxIdleTime\s*:", l)]
    mi = [x for x in mi if x]
    if ev.find(r"MaxIdleTime"):
        if mi and min(mi) <= 1800000:
            r["W-36"] = (RESULT_GOOD, f"원격 터미널 유휴 타임아웃 {min(mi) // 60000}분 (30분 이하)", _UEv.show(ev.find(r"MaxIdleTime")))
        else:
            r["W-36"] = (RESULT_BAD, f"원격 터미널 유휴 타임아웃 {'미설정' if not mi else str(min(mi) // 60000) + '분'} (30분 이하 필요)", _UEv.show(ev.find(r"MaxIdleTime")))
    # W-56 SMB 세션 중단: 로그온 시간 만료 시 연결 끊기 + 유휴 15분 이하
    sb = ev.find(r"EnableForcedLogOff")
    if sb:
        vals = {}
        for c, ls in sb:
            for l in ls:
                m = re.match(r"^\s*(EnableForcedLogoff|AutoDisconnect)\s*:\s*(-?\d+)", l, re.I)
                if m:
                    vals[m.group(1).lower()] = int(m.group(2))
        ef, ad = vals.get("enableforcedlogoff"), vals.get("autodisconnect", 15)
        ok_ = ef == 1 and 0 <= ad <= 15
        r["W-56"] = ((RESULT_GOOD if ok_ else RESULT_BAD),
                     f"로그온 시간 만료 시 연결 끊기={ef}, 유휴 시간 {ad}분{'(기본값)' if 'autodisconnect' not in vals else ''} (기준: 사용, 15분 이하)", _UEv.show(sb))
    return r


def _kisa_db_legacy(evidence, vendor):
    """전자금융 DBMS 증적 → {D-xx(2026 상세가이드): (판정, 사유, 근거 증적)} — 평가기준과 판단 대상이 다른 항목"""
    ev = _UEv(evidence)
    r = {}
    v = (vendor or "").lower()
    if "mysql" in v or "mariadb" in v:
        blks = ev.find(r"plugin FROM mysql\.user")
        plug = {}
        for c, ls in blks:
            for l in ls:
                m = re.match(r"^(\S+@\S*)\s+\((\S+)\)\s*$", l)
                if m:
                    plug[m.group(1)] = m.group(2)
        if plug:
            weak = [f"{u}({p})" for u, p in plug.items() if p in ("mysql_native_password", "mysql_old_password")]
            strong = sorted({p for p in plug.values() if p not in ("mysql_native_password", "mysql_old_password")})
            rv, why = ((RESULT_BAD, f"SHA-256 미만 비밀번호 해시 사용 계정(mysql_native_password=SHA-1): {', '.join(weak[:10])}")
                         if weak else (RESULT_GOOD, f"전 계정 인증 플러그인 {', '.join(strong)} (SHA-256 이상)"))
            r["D-08"] = (rv, why, _UEv.show(blks))
    elif "postgre" in v:
        blks = ev.find(r"password_encryption")
        enc = ""
        for c, ls in blks:
            for l in ls:
                m = re.search(r"\b(scram-sha-256|md5)\b", l, re.I)
                if m:
                    enc = m.group(1).lower()
        if enc:
            rv, why = ((RESULT_GOOD, "password_encryption=scram-sha-256 (SHA-256)") if enc == "scram-sha-256"
                         else (RESULT_BAD, "password_encryption=md5 (SHA-256 미만)"))
            r["D-08"] = (rv, why, _UEv.show(blks))
    return r


# ================================================================
# 기준 엑셀 로드 및 항목 목록 추출
# ================================================================
def load_criteria(excel_path, sheet_name, mode):
    """
    기준 엑셀에서 항목 목록 로드
    mode: "EF" (전자금융) or "MI" (주요정보)
    반환: {code: {name, risk, desc, control_area, control_sub, applies_to, criteria_by}}
      applies_to  : {"LINUX": True/False, ...}  ← OS/DB/장비 적용 대상 여부
      criteria_by : {"LINUX": {"기준": "...", "방법": "..."}, ...}  ← 세부 판단기준
    """
    wb = load_workbook(excel_path, read_only=True)
    ws = wb[sheet_name]
    items = {}
    col_filter = COL_EF if mode == "EF" else COL_MI

    # 시트별 세부 컬럼 매핑 선택
    if sheet_name == "서버":
        sub_cols  = OS_COLS_SRV
        crit_cols = OS_CRITERIA_SRV
    elif sheet_name == "웹서버-WAS":
        sub_cols  = OS_COLS_WEB
        crit_cols = OS_CRITERIA_WEB
    elif sheet_name == "데이터베이스":
        sub_cols  = DB_COLS
        crit_cols = DB_CRITERIA
    elif sheet_name == "네트워크 장비":
        sub_cols  = NET_COLS
        crit_cols = NET_CRITERIA
    elif sheet_name == "정보보호시스템 장비":
        sub_cols  = ISS_COLS
        crit_cols = ISS_CRITERIA
    else:
        sub_cols  = {}
        crit_cols = {}

    # 과기부 고시(주요정보통신기반시설) 연계 항목 열: [UNIX]/[WIN]/[WEB] 표기 시 해당 항목군만 인정
    hdr = next(ws.iter_rows(min_row=4, max_row=4, values_only=True), ())
    kisa_cols = []
    for ci, hv in enumerate(hdr):
        hs = str(hv or "")
        if "과학기술정보통신부고시" in hs:
            tag = "U" if "[UNIX]" in hs else "W" if "[WIN]" in hs else "WEB" if "[WEB]" in hs else ""
            kisa_cols.append((ci, tag))

    for row in ws.iter_rows(min_row=5, values_only=True):
        if not row or len(row) < 2: continue
        code = str(row[COL_ID]).strip() if row[COL_ID] else ""
        if not code or code == "None" or "-" not in code: continue

        # 평가 기반 필터 (EF/MI)
        if not row[col_filter]: continue

        name  = str(row[COL_NAME]).strip() if len(row) > COL_NAME and row[COL_NAME] else ""
        risk  = row[COL_RISK] if len(row) > COL_RISK and row[COL_RISK] else ""
        desc  = str(row[COL_DESC]) if len(row) > COL_DESC and row[COL_DESC] else ""
        control_area = str(row[3]).strip() if len(row) > 3 and row[3] else ""
        control_sub  = str(row[5]).strip() if len(row) > 5 and row[5] else ""

        # 세부 유형별 적용 대상 컬럼 로드 (OS/DB/장비 종류별 o 여부)
        applies_to = {}
        for sub_key, col_idx in sub_cols.items():
            applies_to[sub_key] = bool(len(row) > col_idx and row[col_idx])

        # 세부 유형별 판단기준/방법 컬럼 로드
        criteria_by = {}
        for sub_key, (c_std, c_met) in crit_cols.items():
            std = str(row[c_std]).replace("\\_", "_") if len(row) > c_std and row[c_std] else ""
            met = str(row[c_met]).replace("\\_", "_") if len(row) > c_met and row[c_met] else ""
            if std or met:
                criteria_by[sub_key] = {"기준": std, "방법": met}

        kisa = []
        for ci, tag in kisa_cols:
            if len(row) > ci and row[ci]:
                kisa += [k for k in re.findall(r"\b(?:U|W|WEB|D|N|S)-\d{2}\b", str(row[ci]))
                         if not tag or k.split("-")[0] == tag]

        items[code] = {
            "name":        name,
            "risk":        risk,
            "desc":        desc,
            "control_area": control_area,
            "control_sub":  control_sub,
            "applies_to":  applies_to,
            "criteria_by": criteria_by,
            "kisa":        list(dict.fromkeys(kisa)),
        }
    return items


# ================================================================
# 단색(네이비) 기조 보고서 스타일
# ================================================================
FONT_NAME = "맑은 고딕"
THIN_BORDER = Border(
    left=Side(style="thin", color="CCCCCC"),
    right=Side(style="thin", color="CCCCCC"),
    top=Side(style="thin", color="CCCCCC"),
    bottom=Side(style="thin", color="CCCCCC"),
)
FILL_HEADER    = PatternFill("solid", fgColor="1F3864")   # 네이비
FILL_SUBHEADER = PatternFill("solid", fgColor="2E4057")   # 다크 네이비
FILL_ODD       = PatternFill("solid", fgColor="FFFFFF")   # 흰색
FILL_EVEN      = PatternFill("solid", fgColor="F5F5F5")   # 연한 회색
FILL_VULN_ROW  = PatternFill("solid", fgColor="FDECEA")   # 연한 빨강
FILL_SUMMARY   = PatternFill("solid", fgColor="D6DCE4")   # 연한 네이비
FONT_HEADER    = Font(name=FONT_NAME, size=9, bold=True, color="FFFFFF")
FONT_TITLE     = Font(name=FONT_NAME, size=13, bold=True, color="FFFFFF")
FONT_DATA      = Font(name=FONT_NAME, size=9, color="333333")
FONT_GOOD      = Font(name=FONT_NAME, size=9, bold=True, color="1F3864")
FONT_BAD       = Font(name=FONT_NAME, size=9, bold=True, color="C0392B")
FONT_NA        = Font(name=FONT_NAME, size=9, color="999999")
FONT_MANUAL    = Font(name=FONT_NAME, size=9, color="333333")
FONT_RISK_HIGH = Font(name=FONT_NAME, size=9, bold=True, color="C0392B")
FONT_RISK_MID  = Font(name=FONT_NAME, size=9, color="333333")

RESULT_FONT = {
    RESULT_GOOD:   FONT_GOOD,
    RESULT_BAD:    FONT_BAD,
    RESULT_NA:     FONT_NA,
    RESULT_MANUAL: FONT_MANUAL,
}

FONT_SECTION = Font(name=FONT_NAME, size=12, bold=True, color="1F3864")
FONT_LABEL   = Font(name=FONT_NAME, size=10, bold=True, color="333333")
FONT_LABEL_W = Font(name=FONT_NAME, size=10, bold=True, color="FFFFFF")
FILL_LIGHT_BLUE = PatternFill("solid", fgColor="D6E4F0")

CAT_LABEL = {
    "server":"서버", "webwas":"웹/WAS", "dbms":"DBMS",
    "network":"네트워크 장비", "security":"보안장비", "pc":"PC(업무용 단말)",
}


# ================================================================
# 헤더 파싱 헬퍼
# ================================================================
def _parse_header_info(text):
    """결과 파일 헤더에서 호스트명, OS, 점검일시 등 추출"""
    info = {"hostname": "", "os": "", "date": "", "standard": ""}
    for line in text.splitlines()[:16]:
        if not line.lstrip("\ufeff \t").startswith("#"):   # 머리말(#) 줄만 - 판정 줄의 '점검 대상(…)' 문구 오인 방지
            continue
        s = line.strip().lstrip("\ufeff").lstrip("#").strip()
        if not s or s.startswith("=="): continue
        kv = s.split(":", 1)
        if len(kv) < 2: continue
        k = kv[0].strip()
        v = kv[1].strip()
        kl = k.lower()
        if "점검 대상" in k or "hostname" in kl:
            info["hostname"] = v
        elif kl == "os 상세":
            info["os_detail"] = v
        elif kl in ("커널", "kernel"):
            info["kernel"] = v
        elif kl == "os" or "운영체제" in k:
            info["os"] = v
        elif "점검 일시" in k or "date" in kl:
            info["date"] = v
        elif "점검 기준" in k:
            info["standard"] = v
        elif "dbms" in kl or "dbms 종류" in k:
            info["dbms"] = v
        elif "버전" in k and not info.get("version"):
            info["version"] = v
    if info.get("dbms") and info.get("version"):
        info["dbms"] = f"{info['dbms']} {info['version']}"
    if info.get("os_detail"):   # 점검대상 시트 O/S: 배포판 이름·버전 (+커널)
        info["os"] = info["os_detail"] + (f" (커널 {info['kernel']})" if info.get("kernel") else "")
    return info


# ================================================================
# 시트 생성 함수
# ================================================================
def _apply_border(ws, min_row, max_row, min_col, max_col):
    for r in range(min_row, max_row + 1):
        for c in range(min_col, max_col + 1):
            ws.cell(r, c).border = THIN_BORDER


def _risk_to_score(risk_val):
    """위험도 값을 점수로 변환"""
    try:
        v = float(risk_val)
        return v
    except (ValueError, TypeError):
        pass
    s = str(risk_val).strip()
    if s == "상": return 4.0
    if s == "중": return 3.0
    if s == "하": return 2.0
    return 0.0


def _item_score(item):
    """항목 위험도값: 가이드 항목(score 지정)은 상3/중2/하1, 그 외는 평가기준 위험도 점수"""
    if "score" in item:
        return float(item["score"])
    return _risk_to_score(item.get("risk", ""))


def _risk_grade(item):
    """항목 위험도 등급(상/중/하) 표시값"""
    r = str(item.get("risk", "")).strip()
    if r in ("상", "중", "하"):
        return r
    sc = _risk_to_score(r)
    return "상" if sc >= 4.0 else ("중" if sc >= 3.0 else ("하" if sc > 0 else r))


def _group_by_control_area(criteria_items):
    """항목을 control_sub(세부 통제분야)별로 그룹화. 반환: [(area_name, [code, ...])]"""
    groups = {}
    for code in sorted(criteria_items.keys()):
        item = criteria_items[code]
        sub = item.get("control_sub", "").strip()
        area = item.get("control_area", "").strip()
        label = sub if sub else (area if area else "기타")
        groups.setdefault(label, []).append(code)
    return list(groups.items())


def _cf_font(color, bold):
    return Font(color=color, bold=bold)


def _add_result_cf(ws, first, last):
    """점검결과(O열) 값 기준 조건부 서식 — 수동 변경(양호↔취약 등) 시 서식 즉시 반영"""
    if last < first:
        return
    # 뷰어별 첫 일치 규칙만 적용하는 경우(LibreOffice) 대비: O열 규칙을 먼저, 취약은 글꼴+배경 동시 지정
    o_rng = f"O{first}:O{last}"
    for val, fnt in RESULT_FONT.items():
        ws.conditional_formatting.add(
            o_rng, FormulaRule(formula=[f'$O{first}="{val}"'],
                               font=_cf_font(fnt.color, fnt.bold),
                               fill=FILL_VULN_ROW if val == RESULT_BAD else None))
    ws.conditional_formatting.add(
        f"C{first}:Q{last}",
        FormulaRule(formula=[f'$O{first}="{RESULT_BAD}"'], fill=FILL_VULN_ROW))


def _add_bad_count_cf(ws, rng):
    ws.conditional_formatting.add(
        rng, CellIsRule(operator="greaterThan", formula=["0"],
                        font=_cf_font(FONT_BAD.color, True)))


def _qsheet(name):
    return "'" + name.replace("'", "''") + "'"


_FIXED_SHEETS = {"표지", "개요", "개정이력", "점검대상", "보안수준 통계", "요약 통계", "취약점 목록", "취약점_계산", "검토·수정", "보안가이드"}
_SHEET_NAME_MAP = {}


def _init_sheet_names(hostnames):
    """호스트 시트명 사전 확정 — 금지문자 제거, 31자 제한, 중복 시 ~2,~3 접미사"""
    _SHEET_NAME_MAP.clear()
    used = {n.lower() for n in _FIXED_SHEETS}
    for h in hostnames:
        base = re.sub(r"[\[\]:*?/\\]", "_", str(h)).strip("'") or "host"
        name, i = base[:31], 1
        while name.lower() in used:
            i += 1
            sfx = f"~{i}"
            name = base[:31 - len(sfx)] + sfx
        used.add(name.lower())
        _SHEET_NAME_MAP[h] = name


def _host_sheet_name(hostname):
    return _SHEET_NAME_MAP.get(hostname) or hostname[:31]


def _sheet_link(hostname, cell="A1"):
    return f"#{_qsheet(_host_sheet_name(hostname))}!{cell}"


def _good_condition(std_text):
    """판단기준 텍스트에서 '양호' 조건 문장 추출"""
    if not std_text:
        return ""
    m = re.search(r"(?:^|\n|\s)\*?\s*양호\s*[-:]\s*(.+?)(?=\n\s*\*|\s\*\s*취약|\n\s*\(?예외|\Z)", std_text, re.S)
    if m:
        return re.sub(r"\s+", " ", m.group(1)).strip().lstrip("-◦•·* ").strip()
    for sent in std_text.split("\n"):
        mm = re.search(r"(.+?)\s*[\"“”']?양호[\"“”']?\s*(?:으로|로)\s*판단", sent)
        if mm:
            return re.sub(r"\s+", " ", mm.group(1)).strip()
    return ""



# ================================================================
# 주요정보: 명령어 수준 조치 가이드 (2026 상세가이드 '점검 및 조치 사례' → 대상 환경별)
# ================================================================
def _load_kisa_cases():
    """kisa26_cases.json (convert_v4.py 와 같은 폴더): {항목코드: [[환경 절 이름, 조치 절차 원문], ...]}"""
    p = os.path.join(os.path.dirname(os.path.abspath(__file__)), "kisa26_cases.json")
    try:
        with open(p, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


KISA_CASES = _load_kisa_cases()
# 가이드에 절차가 없는 환경의 제조사 문서 기반 조치 명령: {환경키: {항목코드: (출처, 명령 원문)}}
DGS = "D-Link DGS-3630 · CLI Reference Guide R2.25 기준"
MAC = "macOS 기본 명령 · 2026 상세가이드에 macOS 절차 없음"
KISA_VENDOR_CASES = {
    "DGS-3630": {
        "N-01": (DGS, "Switch# configure terminal\nSwitch(config)# username <관리자ID> privilege 15 password 0 <비밀번호>\nSwitch(config)# enable password <enable 비밀번호>\n※ 출고 시 사용자 계정 없음·enable 비밀번호 빈 값 - 계정·enable 비밀번호를 반드시 설정"),
        "N-02": (DGS, "※ 비밀번호 복잡성 정책 설정 기능 없음 - 기관 비밀번호 규칙(영문 대·소문자·숫자·특수문자 중 3종 이상 8자 이상)으로 재설정\nSwitch(config)# username <관리자ID> privilege 15 password 0 <복잡도 충족 비밀번호>"),
        "N-03": (DGS, "Switch(config)# service password-encryption\n※ 기본값 비활성 - 설정 후 running-config 에 비밀번호가 암호화되어 표시되는지 확인 (show running-config)"),
        "N-04": (DGS, "※ 로그인 실패 잠금 설정 명령 없음 (CLI Reference R2.25)\n대체 조치: 관리 접속 IP 제한(N-06 access-class) + RADIUS/TACACS+ 서버의 로그인 실패 잠금 정책 적용\nSwitch(config)# aaa new-model\nSwitch(config)# aaa authentication login default group <서버그룹> local"),
        "N-06": (DGS, "Switch(config)# ip access-list MGMT-ONLY\nSwitch(config-ip-acl)# permit <관리자 IP> 0.0.0.0\nSwitch(config-ip-acl)# exit\nSwitch(config)# line telnet\nSwitch(config-line)# access-class MGMT-ONLY\nSwitch(config-line)# exit\nSwitch(config)# line ssh\nSwitch(config-line)# access-class MGMT-ONLY"),
        "N-07": (DGS, "Switch(config)# line telnet\nSwitch(config-line)# session-timeout 10\nSwitch(config-line)# exit\nSwitch(config)# line ssh\nSwitch(config-line)# session-timeout 10\n※ 기본값 3분, 0 은 무제한(취약)"),
        "N-08": (DGS, "Switch(config)# no ip telnet server\nSwitch(config)# ip ssh server\n※ telnet 서버 기본 활성, SSH 서버 기본 비활성"),
        "N-10": (DGS, "Switch(config)# banner login #승인된 사용자만 접근할 수 있으며 모든 활동은 기록됩니다.#\n※ '#' 은 시작·끝 구분 문자"),
        "N-11": (DGS, "Switch(config)# logging server <SYSLOG 서버 IP> severity informational"),
        "N-13": (DGS, "※ 로깅 버퍼 크기 설정 인자 없음 (logging buffered 는 severity·write-delay 만 지정)\nSwitch# show logging   (버퍼 저장 메시지 수·가득참 여부 확인)\nSwitch(config)# logging server <SYSLOG 서버 IP>   (버퍼 부족 시 원격 로그로 보완)"),
        "N-14": (DGS, "Switch(config)# logging on\nSwitch(config)# logging buffered severity informational\nSwitch(config)# logging server <SYSLOG 서버 IP> severity informational\n※ 기본값: logging on 활성, 버퍼 severity warnings(4) - 기관 로그 정책에 맞게 레벨·대상 지정"),
        "N-15": (DGS, "Switch(config)# sntp enable\nSwitch(config)# sntp server <NTP 서버 IP>"),
        "N-17": (DGS, "Switch(config)# no snmp-server\n※ SNMP 에이전트 기본 비활성 - 불필요 시 비활성 유지"),
        "N-18": (DGS, "Switch(config)# no snmp-server community public\nSwitch(config)# no snmp-server community private\nSwitch(config)# snmp-server community <3종 8자 이상 문자열> ro access <관리자 ACL>\n※ 기본 커뮤니티 public(RO)·private(RW) 존재 - SNMP 사용 시 반드시 삭제"),
        "N-19": (DGS, "Switch(config)# ip access-list SNMP-MGR\nSwitch(config-ip-acl)# permit <NMS IP> 0.0.0.0\nSwitch(config-ip-acl)# exit\nSwitch(config)# snmp-server community <커뮤니티> ro access SNMP-MGR"),
        "N-20": (DGS, "Switch(config)# no snmp-server community private\nSwitch(config)# snmp-server community <커뮤니티> ro access <관리자 ACL>"),
        "N-27": (DGS, "Switch(config)# no ip http server\nSwitch(config)# ip http secure-server\n※ HTTP 서버 기본 활성, HTTPS 기본 비활성 - 웹 관리가 불필요하면 둘 다 비활성"),
        "N-36": (DGS, "Switch(config)# no ip domain lookup\n※ 기본값 비활성"),
    },
    "MACOS": {
        "PC-01": (MAC, "$ sudo pwpolicy -setglobalpolicy \"maxMinutesUntilChangePassword=129600\"   (90일)\n$ sudo pwpolicy -getaccountpolicies\n※ MDM 사용 시 구성 프로파일(Passcode 정책)로 적용"),
        "PC-02": (MAC, "$ sudo pwpolicy -setglobalpolicy \"minChars=8 requiresAlpha=1 requiresNumeric=1 requiresSymbol=1\"\n$ sudo pwpolicy -getaccountpolicies\n※ MDM 사용 시 구성 프로파일(Passcode 정책)로 적용"),
        "PC-04": (MAC, "$ sudo sysadminctl -smbGuestAccess off      (공유 폴더 게스트 접근 차단)\n$ sudo sharing -l                           (공유 목록 확인)\n$ sudo sharing -r \"<불필요한 공유 이름>\"     (불필요 공유 제거)\n또는 시스템 설정 > 일반 > 공유 > 파일 공유 끔"),
        "PC-05": (MAC, "$ sudo systemsetup -setremotelogin off      (원격 로그인 SSH 끔)\n시스템 설정 > 일반 > 공유 에서 사용하지 않는 공유 서비스(인터넷 공유·프린터 공유 등) 끔"),
        "PC-06": (MAC, "기관 비인가 메신저 앱을 '응용 프로그램' 폴더에서 삭제\n$ ls /Applications | grep -iE 'kakao|discord|telegram|line|whatsapp'"),
        "PC-07": (MAC, "$ diskutil list                              (내장 디스크 파일 시스템 확인)\n$ diskutil eraseVolume APFS <볼륨 이름> <디스크 식별자>   (FAT/exFAT 내장 볼륨 - 데이터 백업 후)"),
        "PC-09": (MAC, "Chrome: 구성 프로파일/관리 정책 ClearBrowsingDataOnExitList 에 cached_images_and_files 지정\nSafari: 해당 설정 없음 - 방문 기록·캐시 정기 삭제 정책으로 운영"),
        "PC-10": (MAC, "$ sudo softwareupdate --schedule on\n$ sudo defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled -bool true\n$ sudo defaults write /Library/Preferences/com.apple.SoftwareUpdate CriticalUpdateInstall -bool true\n$ softwareupdate -l                          (설치 대기 업데이트 확인)"),
        "PC-11": (MAC, "$ sw_vers                                    (현재 버전)\n$ softwareupdate --list-full-installers      (지원 버전 설치 파일 확인)\n※ Apple 보안 업데이트 대상인 최신 3개 주요 버전(2026-09 기준 macOS 15 이상)으로 업그레이드"),
        "PC-12": (MAC, "$ sudo defaults delete /Library/Preferences/com.apple.loginwindow autoLoginUser\n$ sudo rm -f /etc/kcpassword\n또는 시스템 설정 > 사용자 및 그룹 > 자동으로 로그인 '끔'"),
        "PC-13": (MAC, "기관 인가 백신 설치 후 엔진·패턴 자동 업데이트 설정\n$ sudo softwareupdate --background-critical   (XProtect 등 보안 데이터 즉시 갱신)"),
        "PC-14": (MAC, "기관 인가 백신의 실시간 감시(On-Access Scan) 활성화 - 백신 콘솔에서 설정"),
        "PC-15": (MAC, "$ sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on\n$ sudo /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate"),
        "PC-16": (MAC, "$ defaults -currentHost write com.apple.screensaver idleTime -int 600   (10분)\n$ sysadminctl -screenLock immediate -password -   (화면보호기·잠자기 후 즉시 암호 요구, macOS 13+)"),
        "PC-18": (MAC, "$ sudo launchctl disable system/com.apple.screensharing\n$ sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -deactivate -stop\n또는 시스템 설정 > 일반 > 공유 > 화면 공유·원격 관리 끔, TeamViewer·AnyDesk 등 원격 지원 프로그램 삭제"),
    },
}

# (대상 환경 문자열 정규식, 가이드 절 이름 정규식)
_KISA_ENV_RULES = [
    (r"\bLINUX\b|AMAZON LINUX|UBUNTU|CENTOS|RED ?HAT|RHEL|ROCKY|ORACLE LINUX|DEBIAN|SUSE|ALMALINUX", r"LINUX"),
    (r"\bAIX\b", r"\bAIX\b"), (r"HP-?UX", r"HP-UX"), (r"SOLARIS|SUNOS", r"SOLARIS"),
    (r"APACHE", r"^Apache"), (r"NGINX", r"^Nginx"), (r"TOMCAT", r"^Tomcat"), (r"JEUS", r"^JEUS"), (r"WEBTOB", r"^WebtoB"), (r"\bIIS\b", r"^IIS"),
    (r"MYSQL|MARIADB", r"^MySQL"), (r"POSTGRE|PGSQL", r"^PostgreSQL"), (r"\bORACLE\b(?! LINUX)", r"^Oracle DB"),
    (r"MSSQL|SQL ?SERVER", r"^MSSQL"), (r"TIBERO", r"^Tibero"), (r"ALTIBASE", r"^Altibase"), (r"CUBRID", r"^Cubrid"),
    (r"CISCO", r"^Cisco"), (r"JUNIPER|JUNOS", r"^Juniper"), (r"ALTEON|RADWARE", r"Alteon"), (r"PIOLINK", r"^Piolink"), (r"PASSPORT", r"^Passport"),
]


def _kisa_env(detected_sub, host_info):
    """대상 환경 문자열 (OS·제품 판별용)"""
    hi = host_info or {}
    return " ".join(str(x) for x in (detected_sub, hi.get("os"), hi.get("os_detail"), hi.get("web_info"), hi.get("dbms")) if x).upper()


def _kisa_vendor_key(env):
    if "D-LINK" in env and "DGS-3630" in env:
        return "DGS-3630"
    if "MACOS" in env or "MAC OS" in env or "DARWIN" in env:
        return "MACOS"
    return ""


def _kisa_cmd_sections(code, env, max_lines=30):
    """항목·대상 환경에 맞는 조치 절차 [(절 이름, 원문)] — 가이드 절 우선, 가이드에 없는 환경은 제조사 문서 기반"""
    vk = _kisa_vendor_key(env)
    if vk and code in KISA_VENDOR_CASES.get(vk, {}):
        src, txt = KISA_VENDOR_CASES[vk][code]
        return [(src, txt)]
    secs = KISA_CASES.get(code, [])
    fam = code.split("-")[0]
    pats = [lp for ep, lp in _KISA_ENV_RULES if re.search(ep, env)]
    if fam == "W" or (fam == "U" and "WIN" in env.split()):
        pats.append(r"Windows (NT|20)")
    if fam == "PC" and vk != "MACOS":
        pats.append(r"Windows 1[01]")
    picked = [(lab, txt) for lab, txt in secs if any(re.search(p, lab, re.I) for p in pats)]
    if fam == "W":   # Windows 절이 여러 판이면 최신(2012 이상) 우선
        new = [x for x in picked if re.search(r"20(1[2-9]|2\d)", x[0])]
        picked = new or picked
    if not picked:
        picked = [(lab, txt) for lab, txt in secs if lab == "공통"]
    out = []
    for lab, txt in picked:
        ls = txt.splitlines()
        if len(ls) > max_lines:
            ls = ls[:max_lines] + ["… (2026 상세가이드 원문 참조)"]
        out.append((lab, "\n".join(ls)))
    return out


def _kisa_cmd_block(code, env):
    """개선방안에 덧붙일 조치 명령 블록 (없으면 빈 문자열)"""
    secs = _kisa_cmd_sections(code, env)
    if not secs:
        return ""
    vk = _kisa_vendor_key(env)
    blocks = []
    for lab, txt in secs:
        src = lab if (vk and code in KISA_VENDOR_CASES.get(vk, {})) else f"{lab} · 2026 상세가이드"
        blocks.append(f"[조치 명령 예시 - {src}]\n{txt}")
    return "\n".join(blocks)


SECURITY_GUIDE_SHEET = "보안가이드"


def _create_security_guide_sheet(wb, all_results, hosts_info, criteria_items):
    """주요정보: 취약·수동확인 항목의 명령어 수준 조치 가이드 (중요도 순, 대상 환경별로 묶음)"""
    if not any((criteria_items.get(k) or {}).get("guide") for k in criteria_items):
        return
    if not KISA_CASES:   # 데이터 파일 누락 - 조용히 빠지지 않도록 경고
        print("[경고] kisa26_cases.json 없음 → '보안가이드' 시트·개선방안 조치 명령(2026 상세가이드 원문) 미생성")
        print(f"       convert_v4.py 와 같은 폴더({os.path.dirname(os.path.abspath(__file__))})에 kisa26_cases.json 을 두고 다시 변환하세요.")
        return
    hinfo = {h.get("hostname"): h for h in (hosts_info or [])}
    groups = {}
    for host, (res, sub) in all_results.items():
        env = _kisa_env(sub, hinfo.get(host, {}))
        for code, (rv, _why) in res.items():
            item = criteria_items.get(code) or {}
            if not item.get("guide") or rv not in (RESULT_BAD, RESULT_MANUAL):
                continue
            secs = _kisa_cmd_sections(code, env)
            key = (code, tuple(l for l, _ in secs))
            g = groups.setdefault(key, {"secs": secs, "hosts": []})
            g["hosts"].append(f"{host}({rv})")
    rank = {"상": 0, "중": 1, "하": 2}
    rows = sorted(groups.items(), key=lambda kv: (rank.get((criteria_items.get(kv[0][0]) or {}).get("risk", ""), 9), _code_sort_key(kv[0][0]) if "_code_sort_key" in globals() else kv[0][0]))
    ws = wb.create_sheet(SECURITY_GUIDE_SHEET)
    if REVIEW_SHEET in wb.sheetnames:   # 검토·수정 바로 뒤
        wb.move_sheet(SECURITY_GUIDE_SHEET, offset=wb.sheetnames.index(REVIEW_SHEET) + 1 - wb.sheetnames.index(SECURITY_GUIDE_SHEET))
    ws.sheet_view.showGridLines = False
    ws.cell(1, 1).value = "▣ 보안가이드 (명령어 수준 조치 방법)"
    ws.cell(1, 1).font = Font(name=FONT_NAME, size=14, bold=True)
    ws.cell(2, 1).value = ("보고서 생성 시점의 취약·수동확인 항목을 중요도 순(상→중→하)으로 정리했습니다. 조치 명령은 대상 환경(OS·제품)에 맞는 "
                           "2026 상세가이드 '점검 및 조치 사례' 원문이며, 가이드에 절차가 없는 제품은 제조사 문서 기반입니다. "
                           "적용 전 테스트 환경에서 서비스 영향을 확인하십시오. 중요도 '상' 항목을 우선 조치하십시오.")
    ws.cell(2, 1).font = Font(name=FONT_NAME, size=10, color="555555")
    ws.cell(2, 1).alignment = Alignment(wrap_text=True, vertical="top")
    ws.merge_cells(start_row=2, start_column=1, end_row=2, end_column=8)
    ws.row_dimensions[2].height = 42
    hdr = ["No", "중요도", "항목코드", "항목명", "대상(판정)", "대상 환경", "조치 목표 (가이드 양호 기준)", "조치 명령"]
    widths = [5, 7, 9, 26, 26, 16, 34, 80]
    for i, (h, w) in enumerate(zip(hdr, widths), 1):
        c = ws.cell(4, i); c.value = h; c.fill = FILL_HEADER; c.font = FONT_HEADER
        c.alignment = Alignment(horizontal="center", vertical="center", wrap_text=True)
        ws.column_dimensions[get_column_letter(i)].width = w
    r = 5
    for n, ((code, labs), g) in enumerate(rows, 1):
        item = criteria_items.get(code) or {}
        good = KISA_GUIDE_CRITERIA.get(code, ("",))[0]
        cmd = "\n\n".join(f"[{l}]\n{t}" for l, t in g["secs"]) or "가이드에 해당 환경의 조치 절차 없음 - 제조사 문서 참고"
        vals = [n, item.get("risk", ""), code, item.get("name", ""), ", ".join(g["hosts"]), " / ".join(labs) or "-", good, cmd]
        for i, v in enumerate(vals, 1):
            c = ws.cell(r, i); c.value = v
            c.font = Font(name=FONT_NAME, size=9, bold=(i == 3))
            c.alignment = Alignment(wrap_text=True, vertical="top", horizontal="center" if i in (1, 2, 3) else "left")
        risk = item.get("risk", "")
        if risk == "상":
            ws.cell(r, 2).font = Font(name=FONT_NAME, size=9, bold=True, color="C0392B")
        ws.row_dimensions[r].height = min(409, max(30, 12 * (cmd.count("\n") + 1)))
        r += 1
    _apply_border(ws, 4, max(4, r - 1), 1, 8)
    ws.freeze_panes = "A5"

def _fix_text_for(item, detected_sub):
    """개선방안: [조치 목표] 평가기준 양호 조건 + [조치 방법] 평가기준 판단방법 (없으면 기준 원문/내장 fix)"""
    cb_all = item.get("criteria_by", {}) or {}
    cb = cb_all.get(detected_sub) if detected_sub in cb_all else None
    if not cb or not cb.get("기준") or cb.get("기준", "").strip() in ("o", "-"):
        cb = next((v for v in cb_all.values()
                   if v.get("기준") and v["기준"].strip() not in ("o", "-")), None)
    if not cb:
        return item.get("fix", "")
    std = cb.get("기준", "")
    good = _good_condition(std)
    if not good:
        bad = _fail_condition(std)
        good = f"다음 상태에 해당하지 않도록 조치 — {bad}" if bad else ""
    parts = []
    if good:
        parts.append(f"[조치 목표] {good}")
    ml = [l.rstrip() for l in (cb.get("방법") or "").splitlines() if l.strip()]
    if ml:
        if len(ml) > 8:
            ml = ml[:8] + ["… (평가기준 판단방법 참조)"]
        parts.append("[조치 방법]\n" + "\n".join(ml))
    return "\n".join(parts) if parts else (std or item.get("fix", ""))


def _detail_layout(area_groups):
    """호스트 상세 시트 행 배치 사전계산 (통계 수식이 아래쪽 상세 영역을 참조하므로)"""
    stat_start = 13
    stat_total_row = stat_start + len(area_groups)
    detail_start = stat_total_row + 2
    hdr_row = detail_start + 2
    r = hdr_row + 1
    area_ranges = []
    for _, codes in area_groups:
        area_ranges.append((r, r + len(codes) - 1))
        r += len(codes)
    return {"stat_start": stat_start, "stat_total_row": stat_total_row,
            "detail_start": detail_start, "hdr_row": hdr_row,
            "first_data_row": hdr_row + 1, "last_data_row": r - 1,
            "area_ranges": area_ranges}


def _calc_host_stats(res, criteria_items, area_codes=None):
    """호스트 결과에 대한 통계 계산"""
    codes = area_codes if area_codes else list(criteria_items.keys())
    total_items = len(codes)
    good = bad = na_c = mc = 0
    total_score = 0.0
    vuln_score = 0.0
    for code in codes:
        rt = res.get(code)
        if rt is None:
            rt = (RESULT_MANUAL, "")
        result_val = rt[0]
        score = _item_score(criteria_items[code]) if code in criteria_items else 0.0
        if result_val == RESULT_GOOD:
            good += 1
            total_score += score
        elif result_val == RESULT_BAD:
            bad += 1
            total_score += score
            vuln_score += score
        elif result_val == RESULT_NA:
            na_c += 1
        else:
            mc += 1
            total_score += score
    checked = total_items - na_c
    sec_level = ((total_score - vuln_score) / total_score * 100) if total_score > 0 else 100.0
    return {
        "total": total_items, "checked": checked,
        "good": good, "bad": bad, "na": na_c, "manual": mc,
        "total_score": total_score, "vuln_score": vuln_score,
        "sec_level": sec_level,
    }


def _create_cover_sheet(wb, mode, category, hosts_info):
    """표지 시트 (레퍼런스 양식 매칭)"""
    ws = wb.active
    ws.title = "표지"
    ws.sheet_properties.tabColor = "1F3864"

    for col in range(1, 18):
        ws.column_dimensions[get_column_letter(col)].width = 5.56
    for rr in range(1, 53):
        ws.row_dimensions[rr].height = 13.5
    ws.row_dimensions[41].height = 17.25

    mode_str = "전자금융기반시설" if mode == "EF" else "주요정보통신기반시설"
    cat_str = CAT_LABEL.get(category, category)
    ctr = Alignment(horizontal="center", vertical="center", wrap_text=True)

    # "표 지" 라벨 (row 3, 우측 상단)
    ws.merge_cells("L3:O3")
    lbl = ws.cell(3, 12)
    lbl.value = "표  지"
    lbl.font = Font(name=FONT_NAME, size=14, bold=True, color="0000FF")
    lbl.alignment = ctr

    # 메인 타이틀 (row 12~22, 중앙 대형)
    ws.merge_cells("A12:Q22")
    tc = ws.cell(12, 1)
    tc.value = (f"{mode_str} 취약점 분석 및 평가\n\n"
                f"{cat_str} 취약점 진단\n상세 결과보고서")
    tc.font = Font(name=FONT_NAME, size=20, bold=True, color="1F3864")
    tc.alignment = ctr

    # 버전 표기 (row 25, 우측)
    ws.merge_cells("L25:P25")
    vc = ws.cell(25, 12)
    vc.value = "버전 : 1.0"
    vc.font = Font(name=FONT_NAME, size=11, bold=True)
    vc.alignment = Alignment(horizontal="right", vertical="center")

    # 날짜 (row 41, 중앙)
    dates = [h.get("date", "") for h in hosts_info if h.get("date")]
    if dates:
        d_min = min(dates)[:10]
        yr = d_min[:4]
        mo = d_min[5:7]
        date_display = f"{yr}.{mo}"
    else:
        date_display = datetime.datetime.now().strftime("%Y.%m")
    ws.merge_cells("A41:Q41")
    dc = ws.cell(41, 1)
    dc.value = date_display
    dc.font = Font(name=FONT_NAME, size=12, bold=True)
    dc.alignment = ctr

    # 수탁사 CI 영역 (row 44~45, 중앙 하단)
    ws.merge_cells("G44:K45")
    ci_cell = ws.cell(44, 7)
    ci_cell.value = "수탁사 CI"
    ci_cell.font = Font(name=FONT_NAME, size=18, bold=True, color="0000FF")
    ci_cell.alignment = ctr
    ci_bd = Border(
        left=Side("thin", color="999999"), right=Side("thin", color="999999"),
        top=Side("thin", color="999999"), bottom=Side("thin", color="999999"))
    for rr in (44, 45):
        for cc in range(7, 12):
            ws.cell(rr, cc).border = ci_bd

    # 외곽 테두리 (A1:Q52)
    outer_bd_tl = Border(top=Side("medium", color="1F3864"), left=Side("medium", color="1F3864"))
    outer_bd_tr = Border(top=Side("medium", color="1F3864"), right=Side("medium", color="1F3864"))
    outer_bd_bl = Border(bottom=Side("medium", color="1F3864"), left=Side("medium", color="1F3864"))
    outer_bd_br = Border(bottom=Side("medium", color="1F3864"), right=Side("medium", color="1F3864"))
    outer_bd_t  = Border(top=Side("medium", color="1F3864"))
    outer_bd_b  = Border(bottom=Side("medium", color="1F3864"))
    outer_bd_l  = Border(left=Side("medium", color="1F3864"))
    outer_bd_r  = Border(right=Side("medium", color="1F3864"))
    for c in range(2, 17):
        ws.cell(1, c).border = outer_bd_t
        ws.cell(52, c).border = outer_bd_b
    for r in range(2, 52):
        ws.cell(r, 1).border = outer_bd_l
        ws.cell(r, 17).border = outer_bd_r
    ws.cell(1, 1).border = outer_bd_tl
    ws.cell(1, 17).border = outer_bd_tr
    ws.cell(52, 1).border = outer_bd_bl
    ws.cell(52, 17).border = outer_bd_br

    ws.sheet_properties.pageSetUpPr = openpyxl.worksheet.properties.PageSetupProperties(fitToPage=True)
    ws.page_setup.fitToWidth = 1
    ws.page_setup.fitToHeight = 1
    ws.page_setup.orientation = "portrait"
    ws.print_area = "A1:Q52"


def _create_overview_sheet(wb, mode, category, hosts_info, criteria_items=None, example_host=None):
    """개요 시트 (레퍼런스 양식: 목적/평가정의/취약점 제거 방안)"""
    ws = wb.create_sheet("개요")
    ws.sheet_properties.tabColor = "1F3864"
    for c in range(1, 18):
        ws.column_dimensions[get_column_letter(c)].width = 13.0
    ws.column_dimensions["A"].width = 5.125

    mode_str = "전자금융기반시설" if mode == "EF" else "주요정보통신기반시설"
    cat_str = CAT_LABEL.get(category, category)
    ctr = Alignment(horizontal="center", vertical="center", wrap_text=True)
    left_wrap = Alignment(horizontal="left", vertical="center", wrap_text=True)

    r = 2
    ws.merge_cells(f"A{r}:Q{r}")
    c = ws.cell(r, 1)
    c.value = "1. 목적"
    c.font = FONT_SECTION
    c.alignment = Alignment(vertical="center")
    ws.row_dimensions[r].height = 26

    r = 4
    ws.merge_cells(f"B{r}:P{r}")
    if mode == "EF":
        basis = ("전자금융기반시설 보안 취약점 평가기준(제2026-1호)을 준용한 PC 자체 점검 항목(평가기준에 PC 분야 없음)"
                 if category == "pc" else "전자금융기반시설 보안 취약점 평가기준(제2026-1호)")
    else:   # 주요정보: 2026 상세가이드 (PC 도 가이드 PC-01~18)
        basis = "주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드(2026, 과기정통부 고시 제2025-62호)"
    ws.cell(r, 2).value = (
        f"본 보고서는 {basis}에 따라 {cat_str}"
        f"{'' if category in ('network', 'pc') else ' 시스템'}에 대해 "
        "기술적 취약점 점검을 실시하고, 발견된 취약점에 대한 위험도 분석 및 "
        "개선 방안을 제시하여 정보보호 수준을 향상하는 것을 목적으로 합니다."
    )
    ws.cell(r, 2).font = FONT_DATA
    ws.cell(r, 2).alignment = left_wrap
    ws.row_dimensions[r].height = 40

    r = 7
    ws.merge_cells(f"A{r}:Q{r}")
    ws.cell(r, 1).value = "2. 평가 정의"
    ws.cell(r, 1).font = FONT_SECTION
    ws.row_dimensions[r].height = 26

    sub_font = Font(name=FONT_NAME, size=10, bold=True, color="333333")
    eq_font = Font(name="Cambria Math", size=12, bold=False, color="1F3864")
    eq_lbl_font = Font(name=FONT_NAME, size=10, bold=True, color="1F3864")

    def _sub(row, text):
        ws.merge_cells(f"B{row}:P{row}")
        ws.cell(row, 2).value = text
        ws.cell(row, 2).font = sub_font
        ws.row_dimensions[row].height = 22

    def _line(row, text, font=FONT_DATA, height=18, indent=True):
        ws.merge_cells(f"C{row}:P{row}")
        ws.cell(row, 3).value = ("  " if indent else "") + text
        ws.cell(row, 3).font = font
        ws.cell(row, 3).alignment = Alignment(horizontal="left", vertical="center", wrap_text=True)
        ws.row_dimensions[row].height = height

    def _equation(row, label, expr, note=""):
        ws.merge_cells(f"C{row}:F{row}")
        ws.merge_cells(f"G{row}:L{row}")
        ws.merge_cells(f"M{row}:P{row}")
        for ci in range(3, 17):
            ws.cell(row, ci).fill = PatternFill("solid", fgColor="F2F6FB")
        ws.cell(row, 3).value = label
        ws.cell(row, 3).font = eq_lbl_font
        ws.cell(row, 3).alignment = ctr
        ws.cell(row, 7).value = expr
        ws.cell(row, 7).font = eq_font
        ws.cell(row, 7).alignment = ctr
        ws.cell(row, 13).value = note
        ws.cell(row, 13).font = Font(name=FONT_NAME, size=8, color="666666")
        ws.cell(row, 13).alignment = Alignment(horizontal="left", vertical="center", wrap_text=True)
        _apply_border(ws, row, row, 3, 16)
        ws.row_dimensions[row].height = 30

    # ── 2.1.1 점검항목 중요도 및 점수 (기준 엑셀 위험도값 실측) ──
    r = 9
    _sub(r, "2.1.1  점검항목의 중요도 및 점수 지정")
    grade_scores = {"상": set(), "중": set(), "하": set()}
    for it in (criteria_items or {}).values():
        sc = _item_score(it)
        if sc <= 0:
            continue
        grade_scores[_risk_grade(it)].add(sc)

    def _fmt_scores(v):
        return " / ".join(f"{x:g}점" for x in sorted(v, reverse=True)) if v else "-"

    r = 11
    score_headers = ["중요도", "위험도값(w)", "취약", "양호", "수동확인", "해당없음(N-A)"]
    col_spans = [(3, 4), (5, 6), (7, 9), (10, 11), (12, 14), (15, 16)]
    for (cs, ce), hdr in zip(col_spans, score_headers):
        ws.merge_cells(start_row=r, start_column=cs, end_row=r, end_column=ce)
        c = ws.cell(r, cs)
        c.value = hdr
        c.fill = FILL_SUBHEADER
        c.font = FONT_HEADER
        c.alignment = ctr
    _apply_border(ws, r, r, 3, 16)
    ws.row_dimensions[r].height = 20
    for i, grade in enumerate(("상", "중", "하")):
        dr = r + 1 + i
        vals = [grade, _fmt_scores(grade_scores[grade]),
                "w점 (A·B 모두 반영)", "0점 (A에만 반영)",
                "0점 (A에만 반영, 확인 후 재판정)", "산정 제외"]
        fill = FILL_ODD if i % 2 == 0 else FILL_EVEN
        for (cs, ce), v in zip(col_spans, vals):
            ws.merge_cells(start_row=dr, start_column=cs, end_row=dr, end_column=ce)
            c = ws.cell(dr, cs)
            c.value = v
            c.fill = fill
            c.font = FONT_DATA
            c.alignment = ctr
        _apply_border(ws, dr, dr, 3, 16)
        ws.row_dimensions[dr].height = 20
    r = r + 4
    _line(r, "※ 위험도값(w)은 주요정보통신기반시설 가이드 중요도 기준 적용 (상 = 3점, 중 = 2점, 하 = 1점)"
             if any("score" in it for it in (criteria_items or {}).values()) else
             "※ 위험도값(w)은 평가기준의 항목별 위험도 점수를 그대로 적용 (5·4점 = 상, 3점 = 중, 2·1점 = 하)",
          Font(name=FONT_NAME, size=8, color="666666"))

    # ── 2.1.2 기술적 취약점 점수 계산 ──
    r += 2
    _sub(r, "2.1.2  기술적 취약점 점수 계산")
    r += 1
    defs = [
        "• 모든 취약점이 식별되었을 경우의 점수 합(전체점수) : A  —  해당없음(N-A)을 제외한 점검 항목 위험도값의 합",
        "• 식별된 취약점들의 점수 합(취약점수) : B  —  '취약' 판정 항목 위험도값의 합",
        "• 자산의 수 : N,   자산별 보안수준 : Sₙ (n = 1, 2, …, N)",
    ]
    for d in defs:
        _line(r, d)
        r += 1
    r += 1
    _equation(r, "전체점수 · 취약점수", "A = Σᵢ∈P wᵢ ,   B = Σᵢ∈V wᵢ",
              "P : N-A 제외 점검 항목 집합\nV : 취약 판정 항목 집합 (V ⊆ P)")
    r += 1
    _equation(r, "자산별 보안수준", "Sₙ = (A − B) / A × 100",
              "A = 0 이면 100%\n소수점 첫째 자리 반올림")
    r += 1
    _equation(r, "전체 보안수준", "S = (1/N) · Σₙ₌₁ᴺ Sₙ",
              "자산별 보안수준의 단순 평균\n(자산 간 동일 가중)")
    r += 1
    _equation(r, "영역별 보안수준", "Sₐ = (1/N) · Σₙ₌₁ᴺ Sₙ,ₐ",
              "각 자산의 영역 a 보안수준 평균\n(Sₙ,ₐ = 영역 a 항목만으로 계산)")
    r += 2
    if example_host:
        q = _qsheet(_host_sheet_name(example_host))
        tr = 13 + len(_group_by_control_area(criteria_items))
        _line(r, "", Font(name=FONT_NAME, size=9, color="333333"))
        ws.cell(r, 3).value = (
            f'="  예) {example_host} : A = "&TEXT({q}!J{tr},"0.#")&", B = "&TEXT({q}!K{tr},"0.#")'
            f'&"  →  S = ("&TEXT({q}!J{tr},"0.#")&" − "&TEXT({q}!K{tr},"0.#")&") / "&TEXT({q}!J{tr},"0.#")'
            f'&" × 100 = "&TEXT({q}!L{tr},"0.0")&"%"')
        r += 1
    _line(r, "• 보안수준이 높을수록 식별된 취약점의 위험도 총량이 적은(안전한) 상태를 의미",
          Font(name=FONT_NAME, size=9, color="333333"))

    # ── 3. 취약점 제거 방안 ──
    r += 3
    ws.merge_cells(f"A{r}:Q{r}")
    ws.cell(r, 1).value = "3. 취약점 제거 방안"
    ws.cell(r, 1).font = FONT_SECTION
    ws.row_dimensions[r].height = 26

    r += 2
    ws.merge_cells(f"B{r}:P{r + 1}")
    ws.cell(r, 2).value = (
        "취약점이 발견된 항목에 대해서는 본 보고서의 '개선방안 및 보호대책'에 "
        "기술된 조치사항을 우선 적용하고, 긴급 조치가 필요한 항목(위험도 '상')은 "
        "즉시 보안 조치를 실시하여야 합니다.\n"
        "상세한 조치 방법은 각 호스트별 상세 점검 결과의 '개선방안' 항목을 참고하시기 바랍니다."
    )
    ws.cell(r, 2).font = FONT_DATA
    ws.cell(r, 2).alignment = left_wrap
    ws.row_dimensions[r].height = 30
    ws.row_dimensions[r + 1].height = 30

    ws.print_area = f"A1:Q{r + 2}"
    ws.page_setup.orientation = "portrait"
    ws.page_setup.fitToWidth = 1
    ws.page_setup.fitToHeight = 0
    ws.sheet_properties.pageSetUpPr.fitToPage = True


def _create_revision_sheet(wb):
    """개정이력 시트"""
    ws = wb.create_sheet("개정이력")
    ws.sheet_properties.tabColor = "1F3864"

    ws.merge_cells("A2:E2")
    ws.cell(2, 1).value = "▣ 개정 이력"
    ws.cell(2, 1).font = FONT_SECTION
    ws.row_dimensions[2].height = 22

    headers = ["개정번호", "개정일자", "개정내용", "작성자", "비고"]
    widths = [12, 15, 40, 15, 20]
    r = 4
    for ci, (hdr, w) in enumerate(zip(headers, widths), 1):
        c = ws.cell(r, ci)
        c.value = hdr
        c.fill = FILL_SUBHEADER
        c.font = FONT_HEADER
        c.alignment = Alignment(horizontal="center", vertical="center")
        ws.column_dimensions[get_column_letter(ci)].width = w
    _apply_border(ws, r, r, 1, 5)
    ws.row_dimensions[r].height = 22

    r = 5
    today = datetime.datetime.now().strftime("%Y-%m-%d")
    default_row = ["v0.1", today, "초안 작성", "", ""]
    for ci, v in enumerate(default_row, 1):
        c = ws.cell(r, ci)
        c.value = v
        c.font = FONT_DATA
        c.alignment = Alignment(horizontal="center", vertical="center")
    _apply_border(ws, r, r, 1, 5)

    for er in range(6, 10):
        for ci in range(1, 6):
            ws.cell(er, ci).font = FONT_DATA
        _apply_border(ws, er, er, 1, 5)


def _create_target_sheet(wb, hosts_info, all_results):
    """점검대상 시트 (호스트별 시트 하이퍼링크 포함). 반환: {hostname: target_row}"""
    ws = wb.create_sheet("점검대상")
    ws.sheet_properties.tabColor = "1F3864"

    ws.merge_cells("A2:F2")
    ws.cell(2, 1).value = "▣ 점검 대상"
    ws.cell(2, 1).font = FONT_SECTION
    ws.row_dimensions[2].height = 22

    headers = ["No", "HostName", "O/S", "IP", "용도", "비고"]
    widths = [6, 20, 25, 18, 18, 18]
    r = 4
    for ci, (hdr, w) in enumerate(zip(headers, widths), 1):
        c = ws.cell(r, ci)
        c.value = hdr
        c.fill = FILL_SUBHEADER
        c.font = FONT_HEADER
        c.alignment = Alignment(horizontal="center", vertical="center")
        ws.column_dimensions[get_column_letter(ci)].width = w
    _apply_border(ws, r, r, 1, 6)
    ws.row_dimensions[r].height = 22

    target_row_map = {}
    for i, hi in enumerate(hosts_info, 1):
        r = 4 + i
        hostname = hi.get("hostname", "")
        os_info = hi.get("os", "")
        if hi.get("web_info"):
            os_info = f"{os_info} / {hi['web_info']}" if os_info else hi["web_info"]
        if hi.get("dbms"):
            os_info = f"{os_info} / {hi['dbms']}" if os_info else hi["dbms"]
        ip = hi.get("ip", "")
        usage = hi.get("usage", "")

        target_row_map[hostname] = r

        ws.cell(r, 1).value = i
        hc = ws.cell(r, 2)
        hc.value = hostname
        try:
            hc.hyperlink = _sheet_link(hostname)
            hc.font = Font(name=FONT_NAME, size=9, color="0563C1", underline="single")
        except Exception:
            hc.font = FONT_DATA
        ws.cell(r, 3).value = os_info
        ws.cell(r, 4).value = ip
        ws.cell(r, 5).value = usage
        ws.cell(r, 6).value = ""

        fill = FILL_ODD if i % 2 else FILL_EVEN
        for ci in range(1, 7):
            c = ws.cell(r, ci)
            c.fill = fill
            if ci != 2:
                c.font = FONT_DATA
            c.alignment = Alignment(horizontal="center", vertical="center")
        ws.row_dimensions[r].height = 20
    _apply_border(ws, 5, 4 + len(hosts_info), 1, 6)
    ws.print_area = f"A1:F{4 + max(len(hosts_info), 1)}"
    ws.print_title_rows = "4:4"
    ws.page_setup.fitToWidth = 1
    ws.page_setup.fitToHeight = 0
    ws.sheet_properties.pageSetUpPr.fitToPage = True
    return target_row_map


def _create_security_stats_sheet(wb, all_results, criteria_items,
                                  hosts_info=None, category="server"):
    """보안수준 통계 시트 — 레퍼런스 양식 매칭 (2단 병합 헤더, 차트, 장비별 섹션)"""
    ws = wb.create_sheet("보안수준 통계")
    ws.sheet_properties.tabColor = "1F3864"

    ctr = Alignment(horizontal="center", vertical="center", wrap_text=True)
    lft = Alignment(horizontal="left", vertical="center", wrap_text=True)
    area_groups = _group_by_control_area(criteria_items)

    hdr_fill = FILL_SUBHEADER
    hdr_font = Font(name=FONT_NAME, size=10, bold=True, color="FFFFFF")
    data_font = Font(name=FONT_NAME, size=10, color="333333")
    data_bold = Font(name=FONT_NAME, size=10, bold=True, color="333333")
    sec_hdr_font = Font(name=FONT_NAME, size=12, bold=True, color="1F3864")
    sub_hdr_font = Font(name=FONT_NAME, size=10, bold=True, color="1F3864")

    col_widths = {"A": 12.5, "B": 13.0, "C": 9.5, "D": 13.0, "E": 13.0,
                  "F": 13.0, "G": 13.0, "H": 13.0, "I": 13.0, "J": 13.0,
                  "K": 13.0, "L": 9.0}
    for col_letter, w in col_widths.items():
        ws.column_dimensions[col_letter].width = w

    # ════════════════════════════════════════════════════════════════
    # Section 1: 영역별 보안수준
    # ════════════════════════════════════════════════════════════════
    ws.merge_cells("A1:K1")
    t1 = ws.cell(1, 1)
    t1.value = "■ 영역별/장비별 보안수준 통계"
    t1.font = Font(name=FONT_NAME, size=13, bold=True, color="1F3864")
    t1.alignment = lft
    ws.row_dimensions[1].height = 26

    ws.merge_cells("A2:K2")
    c2 = ws.cell(2, 1)
    c2.value = "1) 영역별 보안수준"
    c2.font = sec_hdr_font
    c2.alignment = lft
    ws.row_dimensions[2].height = 17.25

    ws.merge_cells("A3:K3")
    ws.row_dimensions[3].height = 4.5

    # 2단 헤더 — R4~R5 전체 셀에 fill/font/alignment 적용 후 merge
    for rr in (4, 5):
        for ci in range(1, 12):
            c = ws.cell(rr, ci)
            c.fill = hdr_fill
            c.font = hdr_font
            c.alignment = ctr

    ws.merge_cells("A4:B5")
    ws.cell(4, 1).value = "구분"

    ws.merge_cells("C4:H4")
    ws.cell(4, 3).value = "점검 결과"

    ws.merge_cells("I4:K4")
    ws.cell(4, 9).value = "점검 점수"

    sub_hdrs = {3: "전체항목", 4: "점검항목", 5: "양호", 6: "취약",
                7: "N-A", 8: "수동확인", 9: "전체점수", 10: "취약점수", 11: "보안수준"}
    for ci, txt in sub_hdrs.items():
        ws.cell(5, ci).value = txt
    ws.row_dimensions[5].height = 14.25
    _apply_border(ws, 4, 5, 1, 11)

    # 영역별 데이터 행 (R6~)
    area_data_start = 6
    r = 6
    host_refs = [_qsheet(_host_sheet_name(h)) for h in all_results.keys()]
    host_stat_total_row = 13 + len(area_groups)


    # 호스트 × 영역 참조 행렬(숨김 '통계_계산' 시트) → 영역별 합계/평균을 범위 함수로 계산
    #   (호스트별 셀을 + / 인수로 나열하면 약 210대 이상에서 Excel 수식 8,192자·인수 255개 한도 초과)
    mcol = {}
    MQ, mlast = None, 1
    if host_refs:
        mat = wb.create_sheet("통계_계산")
        mat.sheet_state = "hidden"
        MQ = _qsheet(mat.title)
        mat.cell(1, 1).value = "호스트명"
        for hi, hname in enumerate(all_results.keys()):
            mat.cell(2 + hi, 1).value = hname
        src_rows = [13 + ai for ai in range(len(area_groups))] + [host_stat_total_row]
        for bi, hrow in enumerate(src_rows):
            for k, hc in enumerate("DEFGHIJKL"):
                col = 2 + bi * 9 + k
                mcol[(hrow, hc)] = get_column_letter(col)
                mat.cell(1, col).value = f"{hc}{hrow}"
                for hi, q in enumerate(host_refs):
                    mat.cell(2 + hi, col).value = f"={q}!{hc}{hrow}"
        mlast = 1 + len(host_refs)

    def _host_avg(host_row):
        # 자산별 보안수준(Sn) 단순 평균 = (S1+…+SN)/N  (레퍼런스 산식)
        if not host_refs:
            return 100
        L = mcol[(host_row, "L")]
        return f"=ROUND(AVERAGE({MQ}!${L}$2:${L}${mlast}),1)"

    def _cross_sum(host_col, host_row):
        if not host_refs:
            return 0
        L = mcol[(host_row, host_col)]
        return f"=SUM({MQ}!${L}$2:${L}${mlast})"

    for ai, (area_name, codes) in enumerate(area_groups):

        fill = FILL_ODD if (r - area_data_start) % 2 == 0 else FILL_EVEN
        for ci in range(1, 12):
            c = ws.cell(r, ci)
            c.fill = fill
            c.font = data_font
            c.alignment = ctr
            c.border = THIN_BORDER
        ws.cell(r, 1).value = area_name
        ws.cell(r, 1).font = data_bold
        ws.cell(r, 2).font = data_bold

        # 보안수준통계 C..J ↔ 호스트 D..K (각 호스트 시트 동일 행 합산)
        vals = {ci: _cross_sum(get_column_letter(ci + 1), 13 + ai) for ci in range(3, 11)}
        vals[11] = _host_avg(13 + ai)
        for ci, v in vals.items():
            ws.cell(r, ci).value = v
            if ci == 11:
                ws.cell(r, ci).number_format = '0.0"%"'
                ws.cell(r, ci).font = data_bold
        ws.merge_cells(f"A{r}:B{r}")
        r += 1
    area_data_end = r - 1

    # "계" 합계 행
    tot_vals = {ci: f"=SUM({get_column_letter(ci)}{area_data_start}:{get_column_letter(ci)}{area_data_end})"
                for ci in range(3, 11)}
    tot_vals[11] = _host_avg(host_stat_total_row)
    for ci in range(1, 12):
        c = ws.cell(r, ci)
        c.fill = FILL_SUMMARY
        c.font = data_bold
        c.alignment = ctr
        c.border = THIN_BORDER
    ws.cell(r, 1).value = "계"
    for ci, v in tot_vals.items():
        ws.cell(r, ci).value = v
        if ci == 11:
            ws.cell(r, ci).number_format = '0.0"%"'
    ws.merge_cells(f"A{r}:B{r}")
    ws.cell(r, 2).border = THIN_BORDER
    ws.row_dimensions[r].height = 14.25
    totals_row = r
    r += 1

    # ════════════════════════════════════════════════════════════════
    # Section 2: 보안수준 그래프 — 레퍼런스 매칭 (전폭 바 차트 + 레이더)
    # ════════════════════════════════════════════════════════════════

    # 차트 데이터: 표 행 참조 수식 ("계" 행 포함, 레퍼런스 동일)
    chart_areas = []
    for cr in list(range(area_data_start, area_data_end + 1)) + [totals_row]:
        label = ws.cell(cr, 1).value
        chart_areas.append((label,
                            f"=IF(D{cr}=0,0,ROUND(E{cr}/D{cr}*100,1))",
                            f"=K{cr}", f"=E{cr}", f"=F{cr}"))

    if chart_areas:
        n = len(chart_areas)
        from openpyxl.chart.data_source import AxDataSource, StrRef as ChartStrRef

        # 차트 데이터를 시트 하단(행 200+)에 숨김 기록 — 장비별 표(차트 아래, 호스트 수만큼)와 겹치지 않게
        cdr = max(200, r + 40 + len(all_results))
        hide_font = Font(name=FONT_NAME, size=1, color="FFFFFF")
        col_hdrs = ["영역", "양호율(%)", "보안수준(%)", "양호", "취약"]
        for ci, h in enumerate(col_hdrs, 1):
            ws.cell(cdr, ci).value = h
            ws.cell(cdr, ci).font = hide_font
        ws.row_dimensions[cdr].height = 1

        for i, (area_name, good_pct, sec_pct, good_cnt, bad_cnt) in enumerate(chart_areas):
            dr = cdr + 1 + i
            ws.cell(dr, 1).value = area_name
            ws.cell(dr, 2).value = good_pct
            ws.cell(dr, 2).number_format = '0.0"%"'
            ws.cell(dr, 3).value = sec_pct
            ws.cell(dr, 3).number_format = '0.0"%"'
            ws.cell(dr, 4).value = good_cnt
            ws.cell(dr, 5).value = bad_cnt
            for ci in range(1, 6):
                ws.cell(dr, ci).font = hide_font
            ws.row_dimensions[dr].height = 1

        sn = ws.title
        cats_ref = Reference(ws, min_col=1, min_row=cdr + 1, max_row=cdr + n)
        str_cat = AxDataSource(strRef=ChartStrRef(f=f"'{sn}'!$A${cdr+1}:$A${cdr+n}"))

        # ── 1) BarChart: 영역별 보안수준(%) — 레퍼런스 메인 차트 ──
        group_label = CAT_LABEL.get(category, category)
        bar = BarChart()
        bar.type = "col"
        bar.grouping = "clustered"
        bar.title = f"{group_label} 보안수준"
        bar.style = 10
        bar.width = 11.3
        bar.height = 8.5

        sec_vals = Reference(ws, min_col=3, min_row=cdr, max_row=cdr + n)
        bar.add_data(sec_vals, titles_from_data=True)
        bar.set_categories(cats_ref)
        for _s in bar.series:
            _s.cat = str_cat

        if len(bar.series) >= 1:
            bar.series[0].graphicalProperties.solidFill = "1F3864"
            bar.series[0].dLbls = DataLabelList()
            bar.series[0].dLbls.showVal = True
            bar.series[0].dLbls.showCatName = False
            bar.series[0].dLbls.showSerName = False
            bar.series[0].dLbls.numFmt = '0.0"%"'

        bar.y_axis.scaling.min = 0
        bar.y_axis.scaling.max = 100
        bar.y_axis.numFmt = '0.0"%"'
        bar.y_axis.delete = False
        bar.x_axis.delete = False
        bar.x_axis.tickLblPos = "low"
        bar.legend = None

        # ── 2) RadarChart: 양호율(%) + 보안수준(%) ──
        n_areas = n - 1
        cats_ref_r = Reference(ws, min_col=1, min_row=cdr + 1, max_row=cdr + n_areas)
        str_cat_r = AxDataSource(strRef=ChartStrRef(f=f"'{sn}'!$A${cdr+1}:$A${cdr+n_areas}"))

        radar = RadarChart()
        radar.type = "filled"
        radar.title = "영역별 양호율 / 보안수준 비교"
        radar.style = 10
        radar.width = 17.7
        radar.height = 8.5

        sec_ref_r = Reference(ws, min_col=3, min_row=cdr, max_row=cdr + n_areas)
        good_ref_r = Reference(ws, min_col=2, min_row=cdr, max_row=cdr + n_areas)
        radar.add_data(sec_ref_r, titles_from_data=True)
        radar.add_data(good_ref_r, titles_from_data=True)
        radar.set_categories(cats_ref_r)
        for _s in radar.series:
            _s.cat = str_cat_r
        radar.x_axis.delete = False

        if len(radar.series) >= 1:
            radar.series[0].graphicalProperties.solidFill = "FFF0F0"
            radar.series[0].graphicalProperties.line.solidFill = "E06060"
            radar.series[0].graphicalProperties.line.width = 15000
            radar.series[0].dLbls = DataLabelList()
            radar.series[0].dLbls.showVal = True
            radar.series[0].dLbls.showCatName = False
            radar.series[0].dLbls.showSerName = False
            radar.series[0].dLbls.numFmt = '0.0"%"'
        if len(radar.series) >= 2:
            radar.series[1].graphicalProperties.solidFill = "C5D9F1"
            radar.series[1].graphicalProperties.line.solidFill = "1F3864"
            radar.series[1].graphicalProperties.line.width = 22000
            radar.series[1].dLbls = DataLabelList()
            radar.series[1].dLbls.showVal = True
            radar.series[1].dLbls.showCatName = False
            radar.series[1].dLbls.showSerName = False
            radar.series[1].dLbls.numFmt = '0.0"%"'

        radar.y_axis.scaling.min = 0
        radar.y_axis.scaling.max = 100
        radar.y_axis.numFmt = '0"%"'
        radar.legend.position = "b"

        r += 1
        ws.add_chart(bar, f"A{r}")

        from openpyxl.drawing.spreadsheet_drawing import OneCellAnchor, AnchorMarker as _AM
        from openpyxl.drawing.xdr import XDRPositiveSize2D as _Ext
        from openpyxl.utils.units import cm_to_EMU
        _col_off = int(41.25 * 12700)
        radar.anchor = OneCellAnchor(
            _from=_AM(col=4, colOff=_col_off, row=r - 1, rowOff=0),
            ext=_Ext(cx=cm_to_EMU(17.7), cy=cm_to_EMU(8.5)))
        ws._charts.append(radar)
        r += 14

    # ════════════════════════════════════════════════════════════════
    # Section 3: ▣ 장비별 보안수준
    # ════════════════════════════════════════════════════════════════
    r += 1
    ws.merge_cells(f"A{r}:K{r}")
    hb = ws.cell(r, 1)
    hb.value = "2) 장비별 보안수준"
    hb.font = sec_hdr_font
    hb.alignment = lft
    ws.row_dimensions[r].height = 17.25
    r += 1

    ws.merge_cells(f"A{r}:K{r}")
    ws.row_dimensions[r].height = 4.5
    r += 1

    # 2단 헤더 — Host명 (fill-before-merge)
    hdr_r1 = r
    hdr_r2 = r + 1
    for rr in (hdr_r1, hdr_r2):
        for ci in range(1, 12):
            c = ws.cell(rr, ci)
            c.fill = hdr_fill
            c.font = hdr_font
            c.alignment = ctr
            c.border = THIN_BORDER

    ws.merge_cells(f"A{hdr_r1}:B{hdr_r2}")
    ws.cell(hdr_r1, 1).value = "Host 명"

    ws.merge_cells(f"C{hdr_r1}:H{hdr_r1}")
    ws.cell(hdr_r1, 3).value = "점검 결과"

    ws.merge_cells(f"I{hdr_r1}:K{hdr_r1}")
    ws.cell(hdr_r1, 9).value = "점검 점수"

    for ci, txt in sub_hdrs.items():
        ws.cell(hdr_r2, ci).value = txt
    ws.row_dimensions[hdr_r2].height = 14.25
    r = hdr_r2 + 1

    # 장비별 데이터 행 — fill/border 먼저, merge 나중에
    group_label = CAT_LABEL.get(category, category).upper()
    host_list = list(all_results.keys())
    host_data_start = r
    host_count = len(host_list)

    for idx, hostname in enumerate(host_list):
        res, detected_sub = all_results[hostname]
        st = _calc_host_stats(res, criteria_items)
        hq = host_refs[idx]

        fill = FILL_ODD if idx % 2 == 0 else FILL_EVEN
        for ci in range(1, 12):
            c = ws.cell(r, ci)
            c.fill = fill
            c.font = data_font
            c.alignment = ctr
            c.border = THIN_BORDER

        ws.cell(r, 1).font = data_bold
        ws.cell(r, 2).value = hostname
        ws.cell(r, 2).font = data_bold

        vals = {ci: f"={hq}!{get_column_letter(ci + 1)}{host_stat_total_row}" for ci in range(3, 12)}
        for ci, v in vals.items():
            ws.cell(r, ci).value = v
            if ci == 11:
                ws.cell(r, ci).number_format = '0.0"%"'
                ws.cell(r, ci).font = data_bold
        r += 1
    host_data_end = r - 1
    _add_bad_count_cf(ws, f"F{area_data_start}:F{area_data_end + 1}")
    _add_bad_count_cf(ws, f"F{host_data_start}:F{host_data_end + 1}")

    if host_count > 1:
        ws.merge_cells(f"A{host_data_start}:A{host_data_end}")
    grp = ws.cell(host_data_start, 1)
    grp.value = group_label
    grp.font = data_bold
    grp.alignment = ctr

    # "계" 합계 행 — fill/border 먼저, merge 나중
    for ci in range(1, 12):
        c = ws.cell(r, ci)
        c.fill = FILL_SUMMARY
        c.font = data_bold
        c.alignment = ctr
        c.border = THIN_BORDER
    ws.cell(r, 1).value = "계"
    for ci in range(3, 11):
        L = get_column_letter(ci)
        ws.cell(r, ci).value = f"=SUM({L}{host_data_start}:{L}{host_data_end})"
    ws.cell(r, 11).value = f"=ROUND(AVERAGE(K{host_data_start}:K{host_data_end}),1)"
    ws.cell(r, 11).number_format = '0.0"%"'
    ws.merge_cells(f"A{r}:B{r}")
    ws.cell(r, 2).border = THIN_BORDER
    ws.row_dimensions[r].height = 14.25

    ws.merge_cells(f"A{r + 1}:K{r + 1}")
    ws.cell(r + 1, 1).value = (f'=IF(H{r}>0,"※ 수동확인 "&H{r}&"건 미판정 — 판정 확정 전까지 보안수준은 잠정치'
                               f' (수동확인 항목은 전체점수에만 반영)","")')
    ws.cell(r + 1, 1).font = Font(name=FONT_NAME, size=8, color="C0392B")
    ws.cell(r + 1, 1).alignment = Alignment(horizontal="left", vertical="center")
    # 인쇄: 표·차트 영역만(하단 숨김 차트 데이터 제외), 가로·폭 맞춤
    ws.print_area = f"A1:K{r + 1}"
    ws.page_setup.orientation = "landscape"
    ws.page_setup.fitToWidth = 1
    ws.page_setup.fitToHeight = 0
    ws.sheet_properties.pageSetUpPr.fitToPage = True


def _create_summary_stats_sheet(wb, all_results, criteria_items):
    """요약 통계 시트 (항목 × 호스트 매트릭스)"""
    ws = wb.create_sheet("요약 통계")
    ws.sheet_properties.tabColor = "1F3864"

    ctr = Alignment(horizontal="center", vertical="center", wrap_text=True)
    area_groups = _group_by_control_area(criteria_items)
    hostnames = list(all_results.keys())

    # 고정 열: 분류/항목코드/점검항목/위험도/위험도값/전체항목/점검항목/양호/취약/N-A/수동확인
    fixed_hdrs = ["분류", "항목코드", "점검항목", "위험도", "위험도값",
                  "전체", "점검", "양호", "취약", "N-A", "수동확인"]
    fixed_widths = [15, 12, 35, 7, 9, 7, 7, 7, 7, 7, 9]

    r = 2
    ws.merge_cells(f"A{r}:{get_column_letter(11 + len(hostnames))}{r}")
    ws.cell(r, 1).value = "▣ 요약 통계"
    ws.cell(r, 1).font = FONT_SECTION
    ws.row_dimensions[r].height = 22

    hdr_row = 4
    for ci, (hdr, w) in enumerate(zip(fixed_hdrs, fixed_widths), 1):
        c = ws.cell(hdr_row, ci)
        c.value = hdr
        c.fill = FILL_SUBHEADER
        c.font = FONT_HEADER
        c.alignment = ctr
        ws.column_dimensions[get_column_letter(ci)].width = w
    for hi, hname in enumerate(hostnames):
        ci = 12 + hi
        c = ws.cell(hdr_row, ci)
        c.value = hname
        c.hyperlink = _sheet_link(hname)
        c.fill = FILL_SUBHEADER
        c.font = FONT_HEADER
        c.alignment = ctr
        ws.column_dimensions[get_column_letter(ci)].width = 12
    if hostnames:
        ws.row_dimensions[hdr_row].height = 45 if max(len(h) for h in hostnames) > 12 else 22
    total_cols = 11 + len(hostnames)
    _apply_border(ws, hdr_row, hdr_row, 1, total_cols)

    # 호스트 시트 O열 참조 수식 → 호스트 시트 수정 시 즉시 반영
    host_first = _detail_layout(area_groups)["first_data_row"]
    host_refs = [_qsheet(_host_sheet_name(h)) for h in hostnames]
    last_col = get_column_letter(total_cols)
    data_row = hdr_row + 1
    idx = 0
    for area_name, codes in area_groups:
        for code in codes:
            item = criteria_items[code]
            risk = item.get("risk", "")
            score = _item_score(item)
            hrow = host_first + idx
            idx += 1
            r = data_row
            hr = f"$L{r}:${last_col}{r}"
            risk_disp = _risk_grade(item)
            vals = [area_name, code, item.get("name", ""), risk_disp, score,
                    len(hostnames), f"=F{r}-J{r}",
                    f'=COUNTIF({hr},"{RESULT_GOOD}")', f'=COUNTIF({hr},"{RESULT_BAD}")',
                    f'=COUNTIF({hr},"{RESULT_NA}")', f"=F{r}-H{r}-I{r}-J{r}"]
            fill = FILL_ODD if (data_row - hdr_row) % 2 else FILL_EVEN
            for ci, v in enumerate(vals, 1):
                c = ws.cell(data_row, ci)
                c.value = v
                c.fill = fill
                c.font = FONT_DATA
                c.alignment = ctr
            for hi, q in enumerate(host_refs):
                c = ws.cell(data_row, 12 + hi)
                c.value = f'=IF({q}!O{hrow}="","",{q}!O{hrow})'
                c.fill = fill
                c.font = FONT_DATA
                c.alignment = ctr

            _apply_border(ws, data_row, data_row, 1, total_cols)
            ws.row_dimensions[data_row].height = 18
            data_row += 1

    first, last = hdr_row + 1, data_row - 1
    if last >= first:
        h_rng = f"L{first}:{last_col}{last}"
        for val, fnt in RESULT_FONT.items():
            ws.conditional_formatting.add(
                h_rng, FormulaRule(formula=[f'L{first}="{val}"'],
                                   font=_cf_font(fnt.color, fnt.bold),
                                   fill=FILL_VULN_ROW if val == RESULT_BAD else None))
        ws.conditional_formatting.add(
            f"I{first}:I{last}",
            FormulaRule(formula=[f"$I{first}>0"], fill=FILL_VULN_ROW,
                        font=_cf_font(FONT_BAD.color, True)))
        ws.conditional_formatting.add(
            f"A{first}:K{last}",
            FormulaRule(formula=[f"$I{first}>0"], fill=FILL_VULN_ROW))
        ws.auto_filter.ref = f"A{hdr_row}:{last_col}{last}"
        ws.print_area = f"A1:{last_col}{last}"
    ws.freeze_panes = "L5"
    # 인쇄: 가로, 머리글 행·항목 열 반복 (호스트 10대 이하는 폭 맞춤)
    ws.print_title_rows = f"{hdr_row}:{hdr_row}"
    ws.print_title_cols = "A:C"
    ws.page_setup.orientation = "landscape"
    if len(hostnames) <= 10:
        ws.page_setup.fitToWidth = 1
        ws.page_setup.fitToHeight = 0
        ws.sheet_properties.pageSetUpPr.fitToPage = True


def _create_detail_sheet(wb, hostname, res, criteria_items, detected_sub, host_info,
                         target_row=None):
    """호스트별 상세 시트 (레퍼런스 양식: 17열 A-Q)"""
    sheet_name = _host_sheet_name(hostname)
    ws = wb.create_sheet(sheet_name)
    ws.sheet_properties.tabColor = "1F3864"

    ctr = Alignment(horizontal="center", vertical="center", wrap_text=True)

    # 열 너비 설정 (A-Q, 17열)
    col_widths = [6.75, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 43.5, 43.5]
    for i, w in enumerate(col_widths, 1):
        ws.column_dimensions[get_column_letter(i)].width = w

    # ── R2: 제목 ──
    ws.merge_cells("A2:O2")
    ws.cell(2, 1).value = "▣ 장비별 점검 상세 결과"
    ws.cell(2, 1).font = FONT_SECTION
    ws.cell(2, 1).alignment = Alignment(horizontal="left", vertical="center")
    ws.row_dimensions[2].height = 22

    # ── R4: 시스템 현황 ──
    ws.merge_cells("A4:O4")
    ws.cell(4, 1).value = "▣ 시스템 현황"
    ws.cell(4, 1).font = FONT_SECTION
    ws.row_dimensions[4].height = 22

    # R6: Host Name / OS
    os_val = host_info.get("os", detected_sub or "")
    if host_info.get("dbms"):
        os_val = f"{os_val} / {host_info['dbms']}" if os_val else host_info["dbms"]
    if host_info.get("web_info"):
        os_val = f"{os_val} / {host_info['web_info']}" if os_val else host_info["web_info"]

    ws.merge_cells("A6:B6"); ws.merge_cells("C6:F6")
    ws.merge_cells("G6:H6"); ws.merge_cells("I6:L6")
    ws.cell(6, 1).value = "Host Name"
    ws.cell(6, 1).fill = FILL_LIGHT_BLUE; ws.cell(6, 1).font = FONT_LABEL; ws.cell(6, 1).alignment = ctr
    ws.cell(6, 3).value = hostname
    ws.cell(6, 3).font = FONT_DATA; ws.cell(6, 3).alignment = ctr
    ws.cell(6, 7).value = "O/S"
    ws.cell(6, 7).fill = FILL_LIGHT_BLUE; ws.cell(6, 7).font = FONT_LABEL; ws.cell(6, 7).alignment = ctr
    ws.cell(6, 9).value = (f"=IF('점검대상'!C{target_row}=\"\",\"\",'점검대상'!C{target_row})"
                           if target_row else os_val)
    ws.cell(6, 9).font = FONT_DATA; ws.cell(6, 9).alignment = ctr
    _apply_border(ws, 6, 6, 1, 12)
    ws.row_dimensions[6].height = 18

    # R7: IP / 용도
    ws.merge_cells("A7:B7"); ws.merge_cells("C7:F7")
    ws.merge_cells("G7:H7"); ws.merge_cells("I7:L7")
    ws.cell(7, 1).value = "IP Address"
    ws.cell(7, 1).fill = FILL_LIGHT_BLUE; ws.cell(7, 1).font = FONT_LABEL; ws.cell(7, 1).alignment = ctr
    if target_row:
        ws.cell(7, 3).value = f"=IF('점검대상'!D{target_row}=\"\",\"\",'점검대상'!D{target_row})"
    else:
        ws.cell(7, 3).value = host_info.get("ip", "")
    ws.cell(7, 3).font = FONT_DATA; ws.cell(7, 3).alignment = ctr
    ws.cell(7, 7).value = "용도"
    ws.cell(7, 7).fill = FILL_LIGHT_BLUE; ws.cell(7, 7).font = FONT_LABEL; ws.cell(7, 7).alignment = ctr
    if target_row:
        ws.cell(7, 9).value = f"=IF('점검대상'!E{target_row}=\"\",\"\",'점검대상'!E{target_row})"
    else:
        ws.cell(7, 9).value = host_info.get("usage", "")
    ws.cell(7, 9).font = FONT_DATA; ws.cell(7, 9).alignment = ctr
    _apply_border(ws, 7, 7, 1, 12)
    ws.row_dimensions[7].height = 18

    # ── R9: 영역별 점검 결과 ──
    ws.merge_cells("A9:O9")
    ws.cell(9, 1).value = "▣ 영역별 점검 결과"
    ws.cell(9, 1).font = FONT_SECTION
    ws.row_dimensions[9].height = 22

    area_groups = _group_by_control_area(criteria_items)

    # 통계 헤더 (2행)
    ws.merge_cells("A11:C12"); ws.merge_cells("D11:I11"); ws.merge_cells("J11:L11")
    ws.cell(11, 1).value = "분류"
    ws.cell(11, 1).fill = FILL_SUBHEADER; ws.cell(11, 1).font = FONT_HEADER; ws.cell(11, 1).alignment = ctr
    ws.cell(11, 4).value = "항목 통계"
    ws.cell(11, 4).fill = FILL_SUBHEADER; ws.cell(11, 4).font = FONT_HEADER; ws.cell(11, 4).alignment = ctr
    ws.cell(11, 10).value = "점검 점수"
    ws.cell(11, 10).fill = FILL_SUBHEADER; ws.cell(11, 10).font = FONT_HEADER; ws.cell(11, 10).alignment = ctr

    stat_sub_hdrs = ["전체", "점검", "양호", "취약", "N-A", "수동확인", "전체점수", "취약점수", "보안수준"]
    for ci, hdr in enumerate(stat_sub_hdrs, 4):
        c = ws.cell(12, ci)
        c.value = hdr
        c.fill = FILL_SUBHEADER; c.font = FONT_HEADER; c.alignment = ctr
    _apply_border(ws, 11, 12, 1, 12)

    # 영역별 데이터 행 (수식: 상세 영역 O/M열 참조 → 점검결과 수동 변경 시 즉시 반영)
    layout = _detail_layout(area_groups)
    stat_row = layout["stat_start"]
    stat_data_start = stat_row
    for (area_name, codes), (s, e) in zip(area_groups, layout["area_ranges"]):
        st = _calc_host_stats(res, criteria_items, codes)
        ws.merge_cells(f"A{stat_row}:C{stat_row}")
        ws.cell(stat_row, 1).value = area_name
        ws.cell(stat_row, 1).font = FONT_DATA; ws.cell(stat_row, 1).alignment = ctr

        O = f"$O${s}:$O${e}"
        M = f"$M${s}:$M${e}"
        rr = stat_row
        stat_vals = [
            f"=ROWS({O})",
            f"=D{rr}-H{rr}",
            f'=COUNTIF({O},"{RESULT_GOOD}")',
            f'=COUNTIF({O},"{RESULT_BAD}")',
            f'=COUNTIF({O},"{RESULT_NA}")',
            f"=D{rr}-F{rr}-G{rr}-H{rr}",
            f'=SUMPRODUCT(({O}<>"{RESULT_NA}")*{M})',
            f'=SUMPRODUCT(({O}="{RESULT_BAD}")*{M})',
            f"=IF(J{rr}=0,100,ROUND((J{rr}-K{rr})/J{rr}*100,1))",
        ]
        for ci, v in enumerate(stat_vals, 4):
            c = ws.cell(stat_row, ci)
            c.value = v
            c.font = FONT_DATA; c.alignment = ctr
            if ci == 12:
                c.number_format = '0.0"%"'
        _apply_border(ws, stat_row, stat_row, 1, 12)
        stat_row += 1
    stat_data_end = stat_row - 1

    # 전체 합계
    ws.merge_cells(f"A{stat_row}:C{stat_row}")
    ws.cell(stat_row, 1).value = "전체 보안 수준"
    ws.cell(stat_row, 1).fill = FILL_SUMMARY
    ws.cell(stat_row, 1).font = Font(name=FONT_NAME, size=9, bold=True, color="333333")
    ws.cell(stat_row, 1).alignment = ctr
    tr = stat_row
    tot_vals = [f"=SUM({get_column_letter(ci)}{stat_data_start}:{get_column_letter(ci)}{stat_data_end})"
                for ci in range(4, 12)]
    tot_vals.append(f"=IF(J{tr}=0,100,ROUND((J{tr}-K{tr})/J{tr}*100,1))")
    for ci, v in enumerate(tot_vals, 4):
        c = ws.cell(stat_row, ci)
        c.value = v
        c.fill = FILL_SUMMARY
        c.font = Font(name=FONT_NAME, size=9, bold=True, color="333333")
        c.alignment = ctr
        if ci == 12:
            c.number_format = '0.0"%"'
    _apply_border(ws, stat_row, stat_row, 1, 12)
    ws.merge_cells(f"A{stat_row + 1}:L{stat_row + 1}")
    ws.cell(stat_row + 1, 1).value = (f'=IF(I{tr}>0,"※ 수동확인 "&I{tr}&"건 미판정 — 판정 확정 전까지 보안수준은 잠정치","")')
    ws.cell(stat_row + 1, 1).font = Font(name=FONT_NAME, size=8, color="C0392B")
    ws.cell(stat_row + 1, 1).alignment = Alignment(horizontal="left", vertical="center")

    # ── 호스트 RadarChart (영역별 보안수준) ──
    if stat_data_end >= stat_data_start and len(area_groups) >= 2:
        cats_ref = Reference(ws, min_col=1, min_row=stat_data_start, max_row=stat_data_end)
        from openpyxl.chart.data_source import AxDataSource, StrRef as ChartStrRef
        host_sn = ws.title
        host_str_cat = AxDataSource(strRef=ChartStrRef(f=f"'{host_sn}'!$A${stat_data_start}:$A${stat_data_end}"))
        radar = RadarChart()
        radar.type = "filled"
        from openpyxl.chart.title import Title
        from openpyxl.chart.text import Text, RichText
        from openpyxl.chart.layout import Layout, ManualLayout
        from openpyxl.drawing.text import (Paragraph, ParagraphProperties,
                                           CharacterProperties, RegularTextRun)

        def _rich(sz, bold=False):
            cp = CharacterProperties(sz=sz, b=bold)
            return RichText(p=[Paragraph(pPr=ParagraphProperties(defRPr=cp), endParaRPr=cp)])

        # 제목 한 줄(10pt) + 플롯 영역 수동 배치 → 꼭짓점 라벨과 제목/값 라벨 겹침 방지
        t_cp = CharacterProperties(sz=1000, b=True)
        radar.title = Title(tx=Text(rich=RichText(p=[Paragraph(
            pPr=ParagraphProperties(defRPr=t_cp),
            r=[RegularTextRun(rPr=t_cp, t=f"{hostname} 영역별 보안수준")])])), overlay=False)
        radar.plot_area.layout = Layout(manualLayout=ManualLayout(
            layoutTarget="inner", xMode="edge", yMode="edge", x=0.28, y=0.24, w=0.44, h=0.62))
        radar.x_axis.txPr = _rich(800)
        radar.style = 10
        radar.width = 9.5
        radar.height = 6.4
        sec_ref = Reference(ws, min_col=12, min_row=stat_data_start - 1, max_row=stat_data_end)
        radar.add_data(sec_ref, titles_from_data=True)
        radar.set_categories(cats_ref)
        for _s in radar.series:
            _s.cat = host_str_cat
        radar.x_axis.delete = False
        if len(radar.series) >= 1:
            radar.series[0].graphicalProperties.solidFill = "D6E4F0"
            radar.series[0].graphicalProperties.line.solidFill = "1F3864"
            radar.series[0].graphicalProperties.line.width = 20000
            radar.series[0].dLbls = DataLabelList()
            radar.series[0].dLbls.showVal = True
            radar.series[0].dLbls.showCatName = False
            radar.series[0].dLbls.showSerName = False
            radar.series[0].dLbls.numFmt = '0.0"%"'
            radar.series[0].dLbls.txPr = _rich(800, True)
        radar.y_axis.scaling.min = 0
        radar.y_axis.scaling.max = 100
        radar.y_axis.numFmt = '0"%"'
        radar.y_axis.delete = True
        radar.series[0].dLbls.showLegendKey = False
        radar.legend = None
        from openpyxl.drawing.spreadsheet_drawing import OneCellAnchor, AnchorMarker as _AM
        from openpyxl.drawing.xdr import XDRPositiveSize2D as _Ext
        from openpyxl.utils.units import cm_to_EMU
        radar.anchor = OneCellAnchor(
            _from=_AM(col=12, colOff=146050, row=5, rowOff=107950),
            ext=_Ext(cx=cm_to_EMU(9.5), cy=cm_to_EMU(6.4)))
        ws._charts.append(radar)

    # ── 상세 점검 현황 ──
    detail_start = layout["detail_start"]
    ws.merge_cells(f"A{detail_start}:O{detail_start}")
    ws.cell(detail_start, 1).value = "▣ 상세 점검 현황"
    ws.cell(detail_start, 1).font = FONT_SECTION
    ws.row_dimensions[detail_start].height = 22

    ws.merge_cells(f"P{detail_start}:Q{detail_start}")
    ws.cell(detail_start, 16).value = "(양호, 취약, N-A, 수동확인)"
    ws.cell(detail_start, 16).font = Font(name=FONT_NAME, size=8, color="666666")
    ws.cell(detail_start, 16).alignment = Alignment(horizontal="right", vertical="center")

    # 상세 헤더 (17열)
    hdr_row = layout["hdr_row"]
    ws.merge_cells(f"A{hdr_row}:B{hdr_row}")
    ws.cell(hdr_row, 1).value = "구분"
    ws.cell(hdr_row, 1).fill = FILL_SUBHEADER; ws.cell(hdr_row, 1).font = FONT_HEADER; ws.cell(hdr_row, 1).alignment = ctr

    ws.merge_cells(f"C{hdr_row}:K{hdr_row}")
    ws.cell(hdr_row, 3).value = "점검 항목"
    ws.cell(hdr_row, 3).fill = FILL_SUBHEADER; ws.cell(hdr_row, 3).font = FONT_HEADER; ws.cell(hdr_row, 3).alignment = ctr

    detail_col_hdrs = {12: "위험도", 13: "위험도\n값", 14: "점검\n결과 값", 15: "점검\n결과", 16: "현황 및 문제점", 17: "개선방안\n및 보호대책"}
    for ci, hdr in detail_col_hdrs.items():
        c = ws.cell(hdr_row, ci)
        c.value = hdr
        c.fill = FILL_SUBHEADER; c.font = FONT_HEADER; c.alignment = ctr
    _apply_border(ws, hdr_row, hdr_row, 1, 17)
    ws.row_dimensions[hdr_row].height = 28

    # 상세 데이터 행
    data_row = hdr_row + 1
    for area_name, codes in area_groups:
        area_start_row = data_row
        for code in codes:
            item = criteria_items[code]
            rt = res.get(code, (RESULT_MANUAL, ""))
            result_val, reason = rt

            risk = item.get("risk", "")
            score = _item_score(item)

            # 조치방안
            fix_text = _fix_text_for(item, detected_sub)
            if item.get("guide") and result_val in (RESULT_BAD, RESULT_MANUAL):   # 주요정보: 대상 환경별 조치 명령
                cmd = _kisa_cmd_block(code, _kisa_env(detected_sub, host_info))
                if cmd:
                    fix_text = f"{fix_text}\n{cmd}" if fix_text else cmd

            row_fill = FILL_ODD if (data_row - hdr_row) % 2 else FILL_EVEN

            # C: 항목코드
            ws.cell(data_row, 3).value = code
            ws.cell(data_row, 3).font = Font(name=FONT_NAME, size=10, bold=True)
            ws.cell(data_row, 3).alignment = ctr

            # D-K: 항목명 (merge D:K)
            ws.merge_cells(f"D{data_row}:K{data_row}")
            ws.cell(data_row, 4).value = item.get("name", "")
            ws.cell(data_row, 4).font = FONT_DATA
            ws.cell(data_row, 4).alignment = Alignment(horizontal="left", vertical="center", wrap_text=True)

            # L: 위험도
            risk_display = risk
            try:
                rv = float(risk)
                if rv >= 4.0: risk_display = "상"
                elif rv >= 3.0: risk_display = "중"
                else: risk_display = "하"
            except (ValueError, TypeError):
                pass
            ws.cell(data_row, 12).value = risk_display
            ws.cell(data_row, 12).font = Font(name=FONT_NAME, size=10, bold=True) if risk_display == "상" else FONT_DATA
            ws.cell(data_row, 12).alignment = ctr

            # M: 위험도값
            ws.cell(data_row, 13).value = score
            ws.cell(data_row, 13).font = FONT_DATA; ws.cell(data_row, 13).alignment = ctr

            # N: 점검결과값
            ws.cell(data_row, 14).value = (
                f'=IF(OR(O{data_row}="{RESULT_NA}",O{data_row}="{RESULT_MANUAL}"),"-",'
                f'IF(O{data_row}="{RESULT_BAD}",M{data_row},0))')
            ws.cell(data_row, 14).font = FONT_DATA; ws.cell(data_row, 14).alignment = ctr

            # O: 점검결과 (S: 생성 시 판정 — 수동 변경 추적용, 숨김·통계 미참조)
            ws.cell(data_row, 19).value = result_val
            ws.cell(data_row, 15).value = result_val
            ws.cell(data_row, 15).font = RESULT_FONT.get(result_val, FONT_DATA)
            ws.cell(data_row, 15).alignment = ctr

            # P: 현황 및 문제점
            ws.cell(data_row, 16).value = reason
            ws.cell(data_row, 16).font = FONT_DATA
            ws.cell(data_row, 16).alignment = Alignment(horizontal="left", vertical="center", wrap_text=True)

            # Q: 개선방안
            # Q: 취약일 때만 표시 (원문은 숨김 R열) → 양호↔취약 변경 시 자동 표시/해제
            ws.cell(data_row, 18).value = fix_text
            ws.cell(data_row, 17).value = f'=IF(O{data_row}="{RESULT_BAD}",R{data_row},"")' if fix_text else ""
            ws.cell(data_row, 17).font = FONT_DATA
            ws.cell(data_row, 17).alignment = Alignment(horizontal="left", vertical="center", wrap_text=True)

            # 행 전체 배경
            for ci in range(1, 18):
                ws.cell(data_row, ci).fill = row_fill

            _apply_border(ws, data_row, data_row, 1, 17)
            est = sum(len(l) // 36 + 1 for l in str(reason or "").split("\n"))
            if result_val == RESULT_BAD and fix_text:
                est = max(est, sum(len(l) // 36 + 1 for l in fix_text.split("\n")))
            ws.row_dimensions[data_row].height = max(16, min(400, est * 13))
            data_row += 1

        # 구분 열 세로 병합 (A:B)
        if data_row > area_start_row:
            if data_row - area_start_row > 1:
                ws.merge_cells(f"A{area_start_row}:B{data_row - 1}")
            else:
                ws.merge_cells(f"A{area_start_row}:B{area_start_row}")
            ws.cell(area_start_row, 1).value = area_name
            ws.cell(area_start_row, 1).font = FONT_DATA
            ws.cell(area_start_row, 1).alignment = ctr

    assert data_row - 1 == layout["last_data_row"]
    first, last = layout["first_data_row"], data_row - 1
    # 판정을 수동 변경한 행: 현황 및 문제점(P) 주황 배경 → 문구 검토 유도 (LibreOffice 는 첫 일치 규칙만 적용하므로 먼저 등록)
    ws.conditional_formatting.add(
        f"P{first}:P{last}",
        FormulaRule(formula=[f'AND($S{first}<>"",$O{first}<>$S{first})'],
                    fill=PatternFill("solid", start_color="FCE4D6", end_color="FCE4D6")))
    # 양호/취약/N-A/수동확인 외 값(공란·붙여넣기 오입력) 노란 배경
    ws.conditional_formatting.add(
        f"O{first}:O{last}",
        FormulaRule(formula=[f'AND($O{first}<>"{RESULT_GOOD}",$O{first}<>"{RESULT_BAD}",'
                             f'$O{first}<>"{RESULT_NA}",$O{first}<>"{RESULT_MANUAL}")'],
                    fill=PatternFill("solid", start_color="FFFF00", end_color="FFFF00")))
    _add_result_cf(ws, first, last)
    ws.column_dimensions["S"].hidden = True
    O_rng, S_rng = f"$O${first}:$O${last}", f"$S${first}:$S${last}"
    _tr = layout["stat_total_row"]
    ws.cell(_tr + 1, 1).value = (
        f'=IF(I{_tr}>0,"※ 수동확인 "&I{_tr}&"건 미판정 — 판정 확정 전까지 보안수준은 잠정치'
        f'"&IF(ROWS({O_rng})-COUNTIF({O_rng},"{RESULT_GOOD}")-COUNTIF({O_rng},"{RESULT_BAD}")'
        f'-COUNTIF({O_rng},"{RESULT_NA}")-COUNTIF({O_rng},"{RESULT_MANUAL}")>0," (미입력·오입력 "&'
        f'(ROWS({O_rng})-COUNTIF({O_rng},"{RESULT_GOOD}")-COUNTIF({O_rng},"{RESULT_BAD}")'
        f'-COUNTIF({O_rng},"{RESULT_NA}")-COUNTIF({O_rng},"{RESULT_MANUAL}"))&"건 포함)",""),"")'
        f'&IF(SUMPRODUCT(--({O_rng}<>{S_rng}))>0,"  ※ 판정 변경 "&SUMPRODUCT(--({O_rng}<>{S_rng}))'
        f'&"건 — 현황 및 문제점 문구 검토 (주황 표시)","")')
    dv = DataValidation(type="list", allow_blank=False, showErrorMessage=True,
                        formula1=f'"{RESULT_GOOD},{RESULT_BAD},{RESULT_NA},{RESULT_MANUAL}"',
                        errorTitle="점검결과 입력 오류",
                        error="양호 / 취약 / N-A / 수동확인 중에서 선택하세요.")
    dv.add(f"O{first}:O{last}")
    ws.add_data_validation(dv)
    ws.column_dimensions["R"].hidden = True
    ws.print_area = f"A1:Q{last}"
    ws.print_title_rows = f"{hdr_row}:{hdr_row}"
    ws.page_setup.orientation = "landscape"
    ws.page_setup.fitToWidth = 1
    ws.page_setup.fitToHeight = 0
    ws.sheet_properties.pageSetUpPr.fitToPage = True
    _add_bad_count_cf(ws, f"G{stat_data_start}:G{layout['stat_total_row']}")
    ws.auto_filter.ref = f"A{hdr_row}:Q{data_row - 1}"
    ws.freeze_panes = f"A{hdr_row + 1}"


def _create_vuln_list_sheet(wb, all_results, criteria_items):
    """취약점 목록 시트 — 호스트 시트 점검결과 변경 즉시 목록 자동 갱신 (FILTER 미사용, Excel 2010+).
    숨김 '취약점_계산' 시트에서 취약 항목에 순번(1,2,3..)을 매기고, 목록은 k번째 항목을 INDEX/MATCH로 조회."""
    ws = wb.create_sheet("취약점 목록")
    calc = wb.create_sheet("취약점_계산")
    calc.sheet_state = "hidden"
    ws.sheet_properties.tabColor = "C0392B"
    ctr = Alignment(horizontal="center", vertical="center", wrap_text=True)
    lft = Alignment(horizontal="left", vertical="center", wrap_text=True)
    CQ = _qsheet(calc.title)

    # ── 계산 시트: 전 호스트 × 전 항목 ──
    for ci, h in enumerate(["호스트명", "링크", "항목코드", "항목명", "위험도",
                            "점검결과", "취약순번", "현황", "개선방안"], 1):
        calc.cell(1, ci).value = h
    area_groups = _group_by_control_area(criteria_items)
    host_first = _detail_layout(area_groups)["first_data_row"]
    cr = 2
    for hostname in all_results:
        q = _qsheet(_host_sheet_name(hostname))
        idx = 0
        for _, codes in area_groups:
            for code in codes:
                hrow = host_first + idx
                idx += 1
                item = criteria_items[code]
                sc = _item_score(item)
                risk_disp = _risk_grade(item)
                calc.cell(cr, 1).value = hostname
                calc.cell(cr, 2).value = _sheet_link(hostname, f"C{hrow}")
                calc.cell(cr, 3).value = code
                calc.cell(cr, 4).value = item.get("name", "")
                calc.cell(cr, 5).value = risk_disp
                calc.cell(cr, 6).value = f'=IF({q}!O{hrow}="","",{q}!O{hrow})'
                calc.cell(cr, 7).value = f'=IF(F{cr}="{RESULT_BAD}",COUNTIF($F$2:F{cr},"{RESULT_BAD}"),"")'
                calc.cell(cr, 8).value = f'=IF({q}!P{hrow}="","",{q}!P{hrow})'
                calc.cell(cr, 9).value = f'=IF({q}!Q{hrow}="","",{q}!Q{hrow})'
                cr += 1
    calc_last = max(cr - 1, 2)
    n_rows = cr - 2

    # ── 목록 시트 ──
    ws.merge_cells("A2:E2")
    ws.cell(2, 1).value = "▣ 취약점 목록"
    ws.cell(2, 1).font = FONT_SECTION
    ws.row_dimensions[2].height = 22
    ws.merge_cells("F2:H2")
    ws.cell(2, 6).value = f'="총 "&COUNTIF({CQ}!$F$2:$F${calc_last},"{RESULT_BAD}")&"건 (호스트 시트 점검결과 변경 시 자동 반영)"'
    ws.cell(2, 6).font = Font(name=FONT_NAME, size=9, bold=True, color="C0392B")
    ws.cell(2, 6).alignment = Alignment(horizontal="right", vertical="center")

    headers = ["No", "호스트명", "항목코드", "항목명", "위험도", "점검결과",
               "현황 및 문제점", "개선방안 및 보호대책"]
    widths = [6, 20, 11, 40, 8, 9, 50, 50]
    hdr_row = 4
    for ci, (h, w) in enumerate(zip(headers, widths), 1):
        c = ws.cell(hdr_row, ci)
        c.value = h
        c.fill = FILL_SUBHEADER; c.font = FONT_HEADER; c.alignment = ctr
        ws.column_dimensions[get_column_letter(ci)].width = w
    _apply_border(ws, hdr_row, hdr_row, 1, 8)
    ws.row_dimensions[hdr_row].height = 22
    ws.column_dimensions["J"].hidden = True

    link_font = Font(name=FONT_NAME, size=9, color="0563C1", underline="single")
    first = hdr_row + 1
    last = hdr_row + max(n_rows, 1)
    for k in range(1, max(n_rows, 1) + 1):
        r = hdr_row + k
        ws.cell(r, 10).value = f"=IFERROR(MATCH({k},{CQ}!$G$2:$G${calc_last},0)+1,\"\")"

        def ix(col):
            return f"INDEX({CQ}!${col}$1:${col}${calc_last},$J{r})"
        vals = [f'=IF($J{r}="","",{k})',
                f'=IF($J{r}="","",HYPERLINK({ix("B")},{ix("A")}))',
                f'=IF($J{r}="","",{ix("C")})',
                f'=IF($J{r}="","",{ix("D")})',
                f'=IF($J{r}="","",{ix("E")})',
                f'=IF($J{r}="","",{ix("F")})',
                f'=IF($J{r}="","",{ix("H")})',
                f'=IF($J{r}="","",{ix("I")})']
        for ci, v in enumerate(vals, 1):
            c = ws.cell(r, ci)
            c.value = v
            c.font = link_font if ci == 2 else FONT_DATA
            c.alignment = lft if ci in (4, 7, 8) else ctr

    thin = Side(style="thin", color="BFBFBF")
    ws.conditional_formatting.add(
        f"F{first}:F{last}",
        FormulaRule(formula=[f'$J{first}<>""'], font=_cf_font(FONT_BAD.color, True),
                    border=Border(left=thin, right=thin, top=thin, bottom=thin)))
    ws.conditional_formatting.add(
        f"E{first}:E{last}",
        FormulaRule(formula=[f'AND($J{first}<>"",$E{first}="상")'],
                    font=_cf_font(FONT_RISK_HIGH.color, True),
                    border=Border(left=thin, right=thin, top=thin, bottom=thin)))
    ws.conditional_formatting.add(
        f"A{first}:H{last}",
        FormulaRule(formula=[f'$J{first}<>""'],
                    border=Border(left=thin, right=thin, top=thin, bottom=thin)))
    ws.freeze_panes = f"A{first}"
    # 빈 목록 행(생성 시점 취약 건수 초과분) 숨김 → 인쇄 빈 페이지 방지. 취약 추가 시 자동필터 재적용으로 표시
    n_bad = sum(1 for h in all_results
                for code in criteria_items
                if (all_results[h][0].get(code) or ("", ""))[0] == RESULT_BAD)
    for k in range(n_bad + 1, max(n_rows, 1) + 1):
        ws.row_dimensions[hdr_row + k].hidden = True
    # (필터 조건 '비어 있지 않음' 은 LibreOffice 저장 시 손상되어 미사용 — 행 숨김만 적용)
    ws.auto_filter.ref = f"A{hdr_row}:H{last}"
    ws.merge_cells("A3:H3")
    # 표시 행(SUBTOTAL 103 은 숨김 행 제외)보다 취약 건수가 많으면 재적용 안내
    ws.cell(3, 1).value = (f'=IF(COUNTIF({CQ}!$F$2:$F${calc_last},"{RESULT_BAD}")>SUBTOTAL(103,$C${first}:$C${last}),'
                           f'"※ 취약 항목이 추가되어 목록 일부가 숨겨져 있음 — 전체 선택 후 행 숨기기 취소","")')
    ws.cell(3, 1).font = Font(name=FONT_NAME, size=9, bold=True, color="C0392B")
    # 인쇄: 가로·폭 맞춤·제목행 반복, 숨김 계산열(J) 제외
    ws.print_area = f"A1:H{last}"
    ws.print_title_rows = f"{hdr_row}:{hdr_row}"
    ws.page_setup.orientation = "landscape"
    ws.page_setup.fitToWidth = 1
    ws.page_setup.fitToHeight = 0
    ws.sheet_properties.pageSetUpPr.fitToPage = True


REVIEW_SHEET = "검토·수정"


def _create_review_sheet(wb, all_results, criteria_items):
    """검토·수정 시트 — 생성 시점 취약·수동확인 항목을 한곳에 모아 최종 판정·현황을 수정
    - 이 시트의 '최종 판정'·'현황 및 문제점'이 호스트 시트 점검결과(O)·현황(P)의 원본이 됨(호스트 시트는 수식으로 참조)
      → 수정 즉시 호스트 시트·영역별 통계·보안수준 통계·요약 통계·취약점 목록에 반영
    - 양호·N-A 로 생성된 항목은 기존처럼 호스트 시트에서 직접 수정 (취약으로 바꾸면 취약점 목록에 자동 추가)"""
    ws = wb.create_sheet(REVIEW_SHEET)
    # 시트 순서: … 요약 통계 → 취약점 목록 → 검토·수정 → 호스트(점검대상)별 시트
    if "요약 통계" in wb.sheetnames:
        pos = wb.sheetnames.index("요약 통계") + 1
        for name in ("취약점 목록", REVIEW_SHEET):
            if name in wb.sheetnames:
                wb.move_sheet(name, offset=pos - wb.sheetnames.index(name))
                pos += 1
    ws.sheet_properties.tabColor = "E67E22"
    ctr = Alignment(horizontal="center", vertical="center", wrap_text=True)
    lft = Alignment(horizontal="left", vertical="top", wrap_text=True)
    RQ = _qsheet(ws.title)
    area_groups = _group_by_control_area(criteria_items)
    host_first = _detail_layout(area_groups)["first_data_row"]

    rows = []   # (hostname, hrow, code, 원 판정, 사유)
    for hostname, (res, _) in all_results.items():
        idx = 0
        for _, codes in area_groups:
            for code in codes:
                hrow = host_first + idx
                idx += 1
                rv, why = res.get(code) or ("", "")
                if rv in (RESULT_BAD, RESULT_MANUAL):
                    rows.append((hostname, hrow, code, rv, why or ""))

    ws.merge_cells("A2:G2")
    ws.cell(2, 1).value = "▣ 검토·수정 (취약·수동확인 항목)"
    ws.cell(2, 1).font = FONT_SECTION
    ws.row_dimensions[2].height = 22
    ws.merge_cells("A3:K3")
    ws.cell(3, 1).value = ("최종 판정(G)·현황 및 문제점(I)을 여기서 수정하면 호스트 시트·통계·취약점 목록에 바로 반영됩니다. "
                           "이 시트에 있는 항목은 호스트 시트의 점검결과·현황 칸이 이 시트를 참조하므로 여기서만 수정하십시오.")
    ws.cell(3, 1).font = Font(name=FONT_NAME, size=9, color="7F6000")
    ws.cell(3, 1).alignment = Alignment(horizontal="left", vertical="center", wrap_text=True)
    ws.row_dimensions[3].height = 30
    hdr = 5
    ws.merge_cells("H2:K2")
    last = hdr + max(len(rows), 1)
    G_rng, F_rng = f"$G${hdr + 1}:$G${last}", f"$F${hdr + 1}:$F${last}"
    ws.cell(2, 8).value = (f'="대상 {len(rows)}건 / 현재 취약 "&COUNTIF({G_rng},"{RESULT_BAD}")&" · 수동확인 "&COUNTIF({G_rng},"{RESULT_MANUAL}")'
                           f'&" · 양호 "&COUNTIF({G_rng},"{RESULT_GOOD}")&" · N-A "&COUNTIF({G_rng},"{RESULT_NA}")'
                           f'&" (판정 변경 "&SUMPRODUCT(--({G_rng}<>{F_rng}))&"건)"')
    ws.cell(2, 8).font = Font(name=FONT_NAME, size=9, bold=True, color="C0392B")
    ws.cell(2, 8).alignment = Alignment(horizontal="right", vertical="center")

    headers = ["No", "호스트명", "항목코드", "항목명", "위험도", "스크립트 판정", "최종 판정",
               "변경", "현황 및 문제점 (수정 가능)", "개선방안 및 보호대책", "검토 의견"]
    widths = [6, 20, 10, 32, 7, 10, 10, 6, 60, 50, 30]
    for ci, (h, w) in enumerate(zip(headers, widths), 1):
        c = ws.cell(hdr, ci)
        c.value = h
        c.fill = FILL_SUBHEADER; c.font = FONT_HEADER; c.alignment = ctr
        ws.column_dimensions[get_column_letter(ci)].width = w
    for ci in (7, 9, 11):   # 입력 칸 머리글 강조
        ws.cell(hdr, ci).fill = PatternFill("solid", fgColor="C55A11")
    _apply_border(ws, hdr, hdr, 1, 11)
    ws.row_dimensions[hdr].height = 22

    link_font = Font(name=FONT_NAME, size=9, color="0563C1", underline="single")
    edit_fill = PatternFill("solid", fgColor="FFF2CC")
    linked_fill = PatternFill("solid", fgColor="EAF1FB")
    thin = Side(style="thin", color="BFBFBF")
    brd = Border(left=thin, right=thin, top=thin, bottom=thin)
    for k, (hostname, hrow, code, rv, why) in enumerate(rows, 1):
        r = hdr + k
        item = criteria_items[code]
        hq = _qsheet(_host_sheet_name(hostname))
        vals = [k, f'=HYPERLINK("{_sheet_link(hostname, f"C{hrow}").replace(chr(34), chr(34) * 2)}","{hostname.replace(chr(34), "")}")', code,
                item.get("name", ""), _risk_grade(item), rv, rv, f'=IF(G{r}<>F{r},"변경","")', why,
                f'=IF({hq}!R{hrow}="","",{hq}!R{hrow})', ""]
        for ci, v in enumerate(vals, 1):
            c = ws.cell(r, ci)
            c.value = v
            c.font = link_font if ci == 2 else (RESULT_FONT.get(rv, FONT_DATA) if ci in (6, 7) else FONT_DATA)
            c.alignment = lft if ci in (4, 9, 10, 11) else ctr
            c.border = brd
            if ci in (7, 9, 11):
                c.fill = edit_fill
        # 호스트 시트: 점검결과(O)·현황(P)을 이 시트 참조로 전환 (옅은 파랑 = 검토·수정 시트 연결 칸)
        hws = wb[_host_sheet_name(hostname)]
        hws.cell(hrow, 15).value = f'=IF({RQ}!G{r}="","",{RQ}!G{r})'
        hws.cell(hrow, 16).value = f'=IF({RQ}!I{r}="","",{RQ}!I{r})'
        hws.cell(hrow, 15).fill = linked_fill
        hws.cell(hrow, 16).fill = linked_fill
    first = hdr + 1
    if rows:
        dv = DataValidation(type="list", allow_blank=False, showErrorMessage=True,
                            formula1=f'"{RESULT_GOOD},{RESULT_BAD},{RESULT_NA},{RESULT_MANUAL}"',
                            errorTitle="최종 판정 입력 오류", error="양호 / 취약 / N-A / 수동확인 중에서 선택하세요.")
        dv.add(f"G{first}:G{last}")
        ws.add_data_validation(dv)
        for val, font in ((RESULT_BAD, FONT_BAD), (RESULT_GOOD, FONT_GOOD), (RESULT_NA, FONT_NA), (RESULT_MANUAL, FONT_MANUAL)):
            ws.conditional_formatting.add(f"G{first}:G{last}", FormulaRule(formula=[f'$G{first}="{val}"'], font=_cf_font(font.color, font.bold)))
        ws.conditional_formatting.add(f"A{first}:K{last}", FormulaRule(formula=[f'$G{first}<>$F{first}'],
                                      fill=PatternFill("solid", fgColor="FCE4D6", bgColor="FCE4D6")))
        ws.auto_filter.ref = f"A{hdr}:K{last}"
    ws.freeze_panes = f"C{first}"
    ws.print_area = f"A1:K{last}"
    ws.print_title_rows = f"{hdr}:{hdr}"
    ws.page_setup.orientation = "landscape"
    ws.page_setup.fitToWidth = 1
    ws.page_setup.fitToHeight = 0
    ws.sheet_properties.pageSetUpPr.fitToPage = True


# ================================================================
# EoS 현황 (서버·웹/WAS·DBMS·네트워크) — 대상별 OS·버전·커널·제품 버전 수집 → EoS 판정 → .txt
# ================================================================
_EOS_CATS = {"server": "서버", "webwas": "웹서버/WAS", "dbms": "DBMS", "network": "네트워크 장비"}
_OSID_MAP = {"amzn": "amazon-linux", "rhel": "rhel", "centos": "centos", "rocky": "rocky-linux", "almalinux": "almalinux",
             "ol": "oracle-linux", "ubuntu": "ubuntu", "debian": "debian", "sles": "sles", "sled": "sles"}


def _eos_os_from(text, evd):
    """→ (제품키, 버전, 표시명)"""
    blob = text + "\n" + evd
    osid = re.search(r'(?m)^ID="?([\w.-]+)"?\s*$', evd)
    vid = re.search(r'(?m)^VERSION_ID="?([\w.]+)"?\s*$', evd)
    pretty = re.search(r'(?m)^#\s*OS 상세:\s*(.+)$', text) or re.search(r'(?m)^PRETTY_NAME="?([^"\n]+)"?', evd)
    name = pretty.group(1).strip() if pretty else ""
    if osid and vid and osid.group(1) in _OSID_MAP:
        prod = _OSID_MAP[osid.group(1)]
        nm = re.search(r'(?m)^NAME="?([^"\n]+)"?', evd)
        return prod, vid.group(1), name or f"{nm.group(1).strip() if nm else osid.group(1)} {vid.group(1)}"
    low = (name or "").lower()
    for key, prod in (("amazon linux", "amazon-linux"), ("red hat", "rhel"), ("centos stream", "centos-stream"), ("centos", "centos"),
                      ("rocky", "rocky-linux"), ("almalinux", "almalinux"), ("oracle linux", "oracle-linux"), ("ubuntu", "ubuntu"),
                      ("debian", "debian"), ("suse", "sles")):
        if key in low:
            m = re.search(r"(\d+(?:\.\d+)?)", name)
            return prod, (m.group(1) if m else ""), name
    if low.startswith("aix"):
        m = re.search(r"(\d)(\d)00-(\d\d)", name)   # oslevel -s 7200-05-...
        return "aix", (f"{m.group(1)}.{m.group(2)}.{int(m.group(3))}" if m else ""), name
    m = re.search(r"(?mi)^#\s*(?:OS|대상):\s*(.+)$", blob)
    hdr = m.group(1) if m else ""
    w = re.search(r"Windows Server\s*(2008 R2|2012 R2|2003|2008|2012|2016|2019|2022|2025)", blob, re.I)
    if w:
        return "windows-server", w.group(1).replace(" ", "").lower(), f"Windows Server {w.group(1)}"
    for pat, prod in ((r"AMZN\s+([\d.]+)", "amazon-linux"), (r"(?:RHEL|REDHAT)\s+(\d+)", "rhel"), (r"UBUNTU\s+([\d.]+)", "ubuntu"),
                      (r"DEBIAN\s+(\d+)", "debian"), (r"SLES\s+(\d+)", "sles"), (r"CENTOS\s+(\d+)", "centos"),
                      (r"SOLARIS\s+(\d+)", "solaris"), (r"AIX\s+(\d+(?:\.\d+)?)", "aix"), (r"HPUX\s+([\d.]+)", "hp-ux")):
        m = re.search(pat, hdr, re.I)
        if m:
            return prod, m.group(1), (name or hdr.split("/")[-1].strip())
    return "", "", name or hdr


def _eos_kernel_from(text, evd):
    m = re.search(r"(?m)^#\s*커널:\s*(\S+)", text)
    if m:
        return m.group(1)
    m = re.search(r"(?m)^Linux\s+(\d+\.\d+\.\d+[-\w.]*)", evd) or re.search(r"(?m)^(\d+\.\d+\.\d+-[\w.]+(?:x86_64|aarch64|amd64|generic|aws|el\d[\w.]*))\s*$", evd)
    if m:
        return m.group(1)
    b = re.search(r"\(Build (\d+)", text)
    return f"Build {b.group(1)}" if b else ""


def _eos_products_from(category, text, evd, hinfo):
    """→ [(구분, 제품키, 버전)]"""
    blob = text + "\n" + evd
    out = []
    if category == "webwas":
        m = re.search(r"Apache/(\d+\.\d+\.\d+)", blob)
        if m: out.append(("웹서버", "apache", m.group(1)))
        m = re.search(r"nginx/(\d+\.\d+\.\d+)", blob)
        if m: out.append(("웹서버", "nginx", m.group(1)))
        m = re.search(r"Apache Tomcat(?:/| Version )(\d+\.\d+\.\d+)", blob)
        if m: out.append(("WAS", "tomcat", m.group(1)))
        m = re.search(r"JEUS\s*(?:Version\s*)?(\d+)", blob, re.I)
        if m: out.append(("WAS", "jeus", m.group(1)))
        m = re.search(r"WebtoB\s*(\d+)", blob, re.I)
        if m: out.append(("웹서버", "webtob", m.group(1)))
        m = re.search(r"Microsoft-IIS/(\d+\.\d+)", blob)
        if m: out.append(("웹서버", "iis", m.group(1)))
    elif category == "dbms":
        m = re.search(r"(?m)MySQL/MariaDB 버전:\s*(\d+\.\d+\.\d+)(-MariaDB)?", blob, re.I)
        if m: out.append(("DBMS", "mariadb" if m.group(2) else "mysql", m.group(1)))
        m = re.search(r"PostgreSQL(?: 버전:)?\s+(\d+(?:\.\d+)?)", blob)
        if m: out.append(("DBMS", "postgresql", m.group(1)))
        m = re.search(r"Oracle Database (\d+[a-z]*)[^\n]*?(?:Release|Version) (\d+\.\d+)", blob)
        if m: out.append(("DBMS", "oracle", m.group(2)))
        m = re.search(r"SQL Server(?: 버전:)?\s*(?:Microsoft SQL Server\s*)?(20\d\d|\d+\.\d+)", blob)
        if m: out.append(("DBMS", "mssql", m.group(1)))
        m = re.search(r"Tibero\s*(\d+)", blob, re.I)
        if m: out.append(("DBMS", "tibero", m.group(1)))
    elif category == "network":
        osd = hinfo.get("os", "")
        v = re.search(r"(\d+\.\d+(?:\.\d+)?)", osd)
        vendor = detect_net_vendor(text)
        if "IOS XE" in text or "IOS-XE" in text or (vendor == "CISCO" and v and v.group(1).split(".")[0] in ("16", "17", "26")):
            out.append(("네트워크 OS", "cisco-ios-xe", v.group(1) if v else ""))
        elif vendor == "CISCO" and "D-LINK" not in osd:
            out.append(("네트워크 OS", "cisco-ios", v.group(1) if v else ""))
        elif vendor == "ASA":
            out.append(("네트워크 OS", "cisco-asa", v.group(1) if v else ""))
        elif vendor == "JUNIPER":
            out.append(("네트워크 OS", "junos", v.group(1) if v else ""))
        else:
            out.append(("네트워크 OS", osd or vendor or "미확인", v.group(1) if v else ""))
    return out


def _eos_scan_category(category, base_dir):
    """분야별 결과(없으면 증적)·config 파일 → [(호스트, OS표시, 커널, [(구분, 제품, 버전, 판정, 종료일, 설명)])]"""
    mod = None
    try:
        import importlib.util
        path = os.path.join(base_dir, "eos_checker.py")
        if not os.path.exists(path):
            path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "eos_checker.py")
        spec = importlib.util.spec_from_file_location("eos_checker", path)
        mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
    except Exception:
        mod = None
    d = os.path.join(base_dir, category, "config" if category == "network" else "output")
    if not os.path.isdir(d):
        return [], mod
    files = sorted(f for f in os.listdir(d) if f.endswith(".txt"))
    res_files = [f for f in files if "evidence" not in f.lower()] if category != "network" else files
    use_evd_only = category != "network" and not res_files
    targets = files if use_evd_only else res_files
    rows = []
    for f in targets:
        path = os.path.join(d, f)
        text = read_text(path)
        evd = ""
        if category != "network":
            ep = path if use_evd_only else find_evidence_file(path)
            evd = read_text(ep) if ep and os.path.exists(ep) else ""
        if use_evd_only:
            text = _evidence_to_pipe_text(text) + "\n" + "\n".join(text.splitlines()[:8])
        hinfo = _parse_header_info(text)
        host = hinfo.get("hostname") or re.sub(r"(_(srv|server|u|webwas|dbms))?(_evidence)?$", "", os.path.splitext(f)[0])
        comps = []
        if category == "network":
            lines = text.splitlines()
            brand, model, fw = _net_brand(text)
            mv = re.search(r"^\s*(?:version|JUNOS|Software Version)\s+(\S+)", text, re.M | re.I)
            hinfo["os"] = " ".join(x for x in ((brand or detect_net_vendor(text)), model, (mv.group(1) if mv else fw)) if x)
            hn = re.search(r"^\s*hostname\s+(\S+)", text, re.M)
            host = hn.group(1) if hn else os.path.splitext(f)[0]
            os_disp, kern = hinfo["os"], ""
        else:
            prod, ver, os_disp = _eos_os_from(text, evd)
            kern = _eos_kernel_from(text, evd)
            if prod:
                comps.append(("OS", prod, ver))
            else:
                comps.append(("OS", os_disp or "미확인", ""))
        comps += _eos_products_from(category, text, evd, hinfo)
        judged = []
        for kind, prod, ver in comps:
            if mod and ver:
                r, e, desc = mod.check_eos(prod, ver, os.environ.get("EOS_OFFLINE") != "1")
            else:
                r, e, desc = RESULT_MANUAL, None, f"{prod} {ver or ''} 버전 미확인 - 벤더 지원 정책 수동 확인".strip()
            judged.append((kind, prod, ver, r, e, desc))
        if kern and kern[:1].isdigit() and mod:
            kr, ke, kd = mod.kernel_status(kern, os.environ.get("EOS_OFFLINE") != "1")
            judged.append(("커널(참고)", "linux", kern, "참고", ke, kd + " - 배포판 커널은 배포판 지원 정책을 따르므로 판정에 미반영"))
        rows.append((host, os_disp, kern, judged))
    return rows, mod


def write_eos_inventory(base_dir, categories=None, out_dir=None):
    """EoS 현황 .txt 생성 → 경로 반환 (categories 미지정 시 서버·웹/WAS·DBMS·네트워크 전체)"""
    categories = categories or list(_EOS_CATS)
    now = datetime.datetime.now()
    lines, summary = [], []
    mod = None
    for cat in categories:
        rows, m = _eos_scan_category(cat, base_dir)
        mod = mod or m
        if not rows:
            continue
        bad = [r for r in rows if any(j[3] == RESULT_BAD for j in r[3])]
        near = [r for r in rows if r not in bad and any(j[3] == RESULT_MANUAL and "임박" in j[5] for j in r[3])]
        unk = [r for r in rows if r not in bad and r not in near and any(j[3] == RESULT_MANUAL for j in r[3])]
        summary.append(f"  {_EOS_CATS[cat]:<10} 전체 {len(rows):>3}대 / EoS(지원 종료) {len(bad):>3}대 / 종료 임박(90일 이내) {len(near):>3}대 / 확인 필요 {len(unk):>3}대")
        # 제품·버전별 집계
        agg = {}
        for host, osd, kern, judged in rows:
            for kind, prod, ver, r, e, desc in judged:
                if r == "참고":
                    continue
                key = (kind, prod, ".".join(re.findall(r"\d+", ver)[:2]) if ver else "?", r, e or "")
                agg.setdefault(key, []).append(host)
        lines += ["", "=" * 100, f"[{_EOS_CATS[cat]}] 대상 {len(rows)}대 — EoS {len(bad)}대, 임박 {len(near)}대, 확인 필요 {len(unk)}대", "=" * 100,
                  "", "■ 제품·버전별 집계", f"  {'구분':<10}{'제품':<16}{'버전':<10}{'판정':<8}{'종료일':<12}대수"]
        for (kind, prod, ver, r, e), hosts in sorted(agg.items(), key=lambda x: ({"취약": 0, "수동확인": 1, "양호": 2}.get(x[0][3], 3), x[0][1], x[0][2])):
            lines.append(f"  {kind:<10}{prod:<16}{ver:<10}{r:<8}{e:<12}{len(hosts)}대")
        lines += ["", "■ 대상별 상세", f"  {'호스트':<48}{'OS':<28}{'커널':<36}판정"]
        for host, osd, kern, judged in rows:
            worst = next((x for x in (RESULT_BAD, RESULT_MANUAL, RESULT_GOOD) if any(j[3] == x for j in judged)), "-")
            lines.append(f"  {host[:47]:<48}{osd[:27]:<28}{kern[:35]:<36}{worst}")
            for kind, prod, ver, r, e, desc in judged:
                lines.append(f"      - [{kind}] {r}: {desc}")
    src = "인터넷 연결 시 endoflife.date 온라인 조회, 미연결 시 내장 데이터" if os.environ.get("EOS_OFFLINE") != "1" else "내장 데이터만 사용(EOS_OFFLINE=1)"
    head = ["EoS(지원 종료) 현황 보고", "=" * 100,
            f"작성 일시   : {now:%Y-%m-%d %H:%M:%S}",
            f"판정 기준일 : {getattr(mod, 'CHECK_DATE', now.date())} (내장 데이터 수집일 {getattr(mod, 'DATA_DATE', '-')})",
            f"조회 방식   : {src}",
            "판정 기준   : 제조사 지원 종료일(eol) 경과 = 취약(EoS), 90일 이내 = 임박(수동확인), 버전 미확인·미등재 = 확인 필요",
            "", "■ 요약"] + (summary or ["  대상 파일 없음 (server/webwas/dbms 의 output, network 의 config 폴더 확인)"])
    out_dir = out_dir or base_dir
    name = "EoS_현황_" + ("전체" if len(categories) > 1 else _EOS_CATS[categories[0]].replace("/", "")) + f"_{now:%Y%m%d_%H%M%S}.txt"
    path = os.path.join(out_dir, name)
    with open(path, "w", encoding="utf-8-sig", newline="\r\n") as fp:
        fp.write("\n".join(head + lines) + "\n")
    print("\n".join(["", "[EoS 현황]"] + (summary or ["  대상 없음"]) + [f"  → 저장: {path}"]))
    return path


# ================================================================
# 메인 변환 함수
# ================================================================


def auto_create_template(cat_dir, criteria_excel, sheet_name, mode="EF"):
    """기준 엑셀에서 결과 기입용 template.xlsx 자동 생성"""
    try:
        from openpyxl import Workbook, load_workbook
        from openpyxl.styles import PatternFill, Font, Alignment, Border, Side
        
        src_wb = load_workbook(criteria_excel, read_only=True)
        if sheet_name not in src_wb.sheetnames:
            print(f"[ERROR] 기준 엑셀에 [{sheet_name}] 시트 없음")
            return None
        ws_src = src_wb[sheet_name]

        col_filter = 9 if mode == "EF" else 10  # COL_EF=9, COL_MI=10
        items = []
        for row in ws_src.iter_rows(min_row=5, values_only=True):
            if not row or len(row) < 2: continue
            code = str(row[1]).strip() if row[1] else ""
            if not code or code == "None" or "-" not in code: continue
            if not (len(row) > col_filter and row[col_filter]): continue  # EF/MI 필터
            name  = str(row[6])[:60]  if len(row) > 6  and row[6]  else ""
            risk  = str(row[7])       if len(row) > 7  and row[7]  else ""
            ef    = "o"               if len(row) > 9  and row[9]  else ""
            mi    = "o"               if len(row) > 10 and row[10] else ""
            items.append((code, name, risk, ef, mi))

        wb  = Workbook()
        ws  = wb.active
        ws.title = f"{sheet_name} 점검결과"
        ws.freeze_panes = "A6"

        H1 = PatternFill("solid", fgColor="1F3864")
        H2 = PatternFill("solid", fgColor="2E75B6")
        bd = Border(
            left=Side(style="thin", color="BBBBBB"),
            right=Side(style="thin", color="BBBBBB"),
            top=Side(style="thin", color="BBBBBB"),
            bottom=Side(style="thin", color="BBBBBB"),
        )
        def fnt(bold=False, color="000000", size=9):
            return Font(name="맑은 고딕", size=size, bold=bold, color=color)
        ctr = Alignment(horizontal="center", vertical="center", wrap_text=True)
        lft = Alignment(horizontal="left",   vertical="center", wrap_text=True)

        # 제목
        ws.merge_cells("A1:N1")
        mode_label = "전자금융기반시설" if mode == "EF" else "주요정보통신기반시설"
        ws["A1"].value = f"{mode_label} 보안 취약점 평가 결과 [{sheet_name}]"
        ws["A1"].font  = Font(name="맑은 고딕", size=13, bold=True, color="FFFFFF")
        ws["A1"].fill  = H1
        ws["A1"].alignment = ctr
        ws.row_dimensions[1].height = 28

        # 정보행
        ws["B2"] = "점검 기관:"; ws["C2"] = ""
        ws["E2"] = "점검 일자:"; ws["F2"] = datetime.datetime.now().strftime("%Y-%m-%d")
        ws["H2"] = "점검자:";    ws["I2"] = ""
        for addr in ["B2","C2","E2","F2","H2","I2"]:
            ws[addr].font = fnt(size=9)
        ws.row_dimensions[2].height = 16

        # 요약 수식
        stat_row   = 3
        res_col    = "M"
        last_data  = 5 + len(items)
        stats = [
            ("C3:D3", "양호",   "양호",   "C6EFCE", "006100"),
            ("E3:F3", "취약",   "취약",   "FFC7CE", "9C0006"),
            ("G3:H3", "N-A",    "N-A",    "EEEEEE", "595959"),
            ("I3:J3", "수동확인","수동확인","FFEB9C","9C5700"),
        ]
        ws.merge_cells("A3:B3"); ws["A3"].value = "점검 결과 요약"
        ws["A3"].font = Font(name="맑은 고딕", size=10, bold=True, color="FFFFFF")
        ws["A3"].fill = H2; ws["A3"].alignment = ctr
        ws.merge_cells("A4:B4")

        for merge, label, val, bg, fg in stats:
            ws.merge_cells(merge)
            start = merge.split(":")[0]
            ws[start].value = label
            ws[start].font  = Font(name="맑은 고딕", size=10, bold=True, color=fg)
            ws[start].fill  = PatternFill("solid", fgColor=bg)
            ws[start].alignment = ctr

            cnt_addr = start[0] + "4"
            ws.merge_cells(f"{start[0]}4:{merge.split(':')[1][0]}4")
            ws[cnt_addr].value = f'=COUNTIF({res_col}6:{res_col}{last_data},"{val}")'
            ws[cnt_addr].font  = Font(name="맑은 고딕", size=11, bold=True, color=fg)
            ws[cnt_addr].fill  = PatternFill("solid", fgColor=bg)
            ws[cnt_addr].alignment = ctr

        ws.row_dimensions[3].height = 20
        ws.row_dimensions[4].height = 22

        # 헤더
        headers = [
            ("A",4,"No."),("B",14,"평가항목ID"),("C",50,"평가항목명"),
            ("D",8,"위험도"),("E",8,"전자금융"),("F",8,"주요정보"),
            ("G",12,"대상 서버 IP"),("H",12,"대상 서버 IP"),
            ("I",12,"대상 서버 IP"),("J",12,"대상 서버 IP"),
            ("K",12,"대상 서버 IP"),
            ("L",12,"점검 IP"),
            ("M",10,"점검결과"),
            ("N",60,"현황 (자동기입)"),
            ("O",50,"해결방안"),
        ]
        for col, width, hdr in headers:
            c = ws[f"{col}5"]
            c.value = hdr; c.fill = H2; c.border = bd
            c.font  = Font(name="맑은 고딕", size=9, bold=True, color="FFFFFF")
            c.alignment = ctr
            ws.column_dimensions[col].width = width
        ws.row_dimensions[5].height = 20

        # 데이터
        even = PatternFill("solid", fgColor="EEF3FA")
        odd  = PatternFill("solid", fgColor="FFFFFF")
        for idx, (code, name, risk, ef, mi) in enumerate(items):
            row = idx + 6
            fill = even if idx % 2 == 0 else odd
            def sc(col, val, align=ctr, bold=False, clr="000000"):
                c = ws[f"{col}{row}"]
                c.value = val; c.fill = fill; c.border = bd
                c.font  = Font(name="맑은 고딕", size=9, bold=bold, color=clr)
                c.alignment = align
            sc("A", idx+1)
            sc("B", code, bold=True, clr="1F3864")
            sc("C", name, align=lft)
            # 위험도 색상
            try: rv = float(risk) if risk else 0
            except: rv = 0
            rc = ws[f"D{row}"]
            rc.value = risk; rc.border = bd; rc.alignment = ctr
            if rv >= 4.0:
                rc.fill = PatternFill("solid", fgColor="FFC7CE")
                rc.font = Font(name="맑은 고딕", size=9, bold=True, color="9C0006")
            elif rv >= 3.0:
                rc.fill = PatternFill("solid", fgColor="FFEB9C")
                rc.font = Font(name="맑은 고딕", size=9, bold=True, color="9C5700")
            else:
                rc.fill = fill
                rc.font = Font(name="맑은 고딕", size=9)
            sc("E", ef); sc("F", mi)
            for col in list("GHIJKL"): sc(col, "")
            sc("M", ""); sc("N", "", align=lft)
            ws.row_dimensions[row].height = 16

        tmpl_path = os.path.join(cat_dir, "template.xlsx")
        wb.save(tmpl_path)
        print(f"[INFO] template.xlsx 자동 생성 완료 ({len(items)}개 항목)")
        return tmpl_path
    except Exception as e:
        print(f"[ERROR] 템플릿 자동 생성 실패: {e}")
        return None

def run_webwas_convert(mode, base_dir, criteria_excel):
    """
    웹/WAS 전용 컨버터 – 유형별 자동 분류
    - 점검 결과 파일 헤더에서 웹서버(Apache/Nginx/WebtoB/IIS) 및
      WAS(Tomcat/JEUS) 유형을 자동 탐지
    - 탐지된 유형에 해당하지 않는 항목은 N-A 처리
    - 표지 / 점검 개요 / 총괄 요약 / 호스트별 상세 시트 생성
    """
    cat_dir   = os.path.join(base_dir, "webwas")
    input_dir = os.path.join(cat_dir, "output")

    if not os.path.exists(input_dir):
        print(f"[ERROR] 입력 폴더 없음: {input_dir}"); return

    input_files = sorted(f for f in os.listdir(input_dir)
                         if f.endswith(".txt") and "evidence" not in f.lower())
    # 결과 파일이 없으면 증적 파일(*_webwas_evidence.txt)의 [판정] 줄로 결과 복원
    evidence_only = False
    if not input_files:
        input_files = sorted(f for f in os.listdir(input_dir) if f.endswith(".txt") and "evidence" in f.lower())
        evidence_only = bool(input_files)
        if evidence_only:
            print(f"[안내] 결과 파일 없음 → 증적 파일 {len(input_files)}개의 [판정] 줄로 결과 복원")
    if not input_files:
        print(f"[ERROR] {input_dir}에 .txt 파일 없음"); return

    print(f"[INFO] 기준 엑셀 로드: 웹서버-WAS")
    criteria_items = load_criteria(criteria_excel, SHEET_MAP["webwas"], "EF" if mode == "MI" else mode)   # MI: 가이드 항목 판정 근거 자료로 전 항목 사용
    print(f"[INFO] 평가항목 {len(criteria_items)}개 로드 ({'전자금융' if mode=='EF' else '주요정보'} 기준)")

    all_results = {}
    evidences   = {}
    hosts_info  = []

    for fname in input_files:
        pure = os.path.splitext(fname)[0]
        text = read_text(os.path.join(input_dir, fname))
        if evidence_only:
            text = _evidence_to_pipe_text(text)
            pure = re.sub(r"(_webwas)?_evidence$", "", pure, flags=re.I)

        hinfo = _parse_header_info(text)
        evidence = {}
        if not hinfo["hostname"]:
            hinfo["hostname"] = pure

        res = parse_pipe(text)
        if _category_mismatch(res, criteria_items, fname):
            continue
        evd_path = os.path.join(input_dir, fname) if evidence_only else find_evidence_file(os.path.join(input_dir, fname))
        if evd_path:
            evidence = parse_evidence(evd_path)
            print(f"[INFO] {fname} → 증적 파일 병합: {os.path.basename(evd_path)} ({len(evidence)}건)")

        ti   = parse_webwas_type(text)
        cats = get_webwas_categories(ti["web"], ti["was"], ti["os"])
        applicable = set()
        for cat in cats:
            applicable |= WST_CLASSIFY.get(cat, set())

        web_disp = ti["web"].upper() if ti["web"] != "none" else "미탐지"
        was_disp = ti["was"].upper() if ti["was"] != "none" else "미탐지"
        hinfo["web_info"] = " / ".join(x for x in (web_disp, was_disp) if x != "미탐지")

        for code in criteria_items:
            if code not in res:
                if code.upper() in applicable:
                    res[code] = (RESULT_MANUAL, "스크립트 미점검 항목 (수동 확인 필요)")
                else:
                    res[code] = (RESULT_NA, f"현재 유형({web_disp}/{was_disp})에 해당 없는 항목")

        res = run_eos_check("webwas", res, text, base_dir)

        detected_sub = detect_srv_os(text)
        if detected_sub:
            forced = 0
            for code, (rv, why) in list(res.items()):
                item = criteria_items.get(code)
                if item and rv != RESULT_NA and not is_applicable(item, detected_sub):
                    res[code] = (RESULT_NA, f"평가대상 아님 ({detected_sub} 해당 없음 - 평가기준 평가대상 열)")
                    forced += 1
            if forced:
                print(f"[INFO] {fname} → 평가대상 아닌 항목 {forced}건 N-A 보정")
        if mode == "MI":   # 가이드 항목 변환 후 현황 구성
            evidences[hinfo["hostname"]] = evidence
        else:
            res = compose_status(res, evidence, criteria_items, detected_sub)
        _h = hinfo["hostname"]
        if _h in all_results:   # 같은 호스트 결과 파일이 여럿(전자금융 + 주요정보 전용 스크립트 등) → 판정·증적 병합, 대상 1대 (파일 순서 무관)
            _old_res, _old_sub = all_results[_h]
            res = {**_old_res, **res}
            detected_sub = detected_sub or _old_sub
            if _h in evidences:
                evidences[_h] = {**evidences[_h], **(evidence or {})}
            for _hi in hosts_info:
                if _hi.get("hostname") == _h:
                    for _k, _v in hinfo.items():
                        if _v and not _hi.get(_k):
                            _hi[_k] = _v
            print(f"[INFO] {fname}: 같은 호스트({_h})의 다른 결과 파일과 병합")
            all_results[_h] = (res, detected_sub)
            continue
        all_results[_h] = (res, detected_sub)
        hosts_info.append(hinfo)

        total = sum(1 for k in res if k in criteria_items)
        bad   = sum(1 for k, v in res.items() if k in criteria_items and v[0] == RESULT_BAD)
        good  = sum(1 for k, v in res.items() if k in criteria_items and v[0] == RESULT_GOOD)
        print(f"[INFO] {fname} → 웹서버={web_disp}, WAS={was_disp}, 양호 {good} / 취약 {bad}")

    if not all_results:
        _no_results_stop(mode, "webwas")
        return
    # 주요정보(MI): 2026 상세가이드 웹 서비스(WEB-xx) 항목 체계로 변환
    if mode == "MI" and all_results:
        _, all_results, hosts_info, criteria_items = _kisa_groups("webwas", all_results, hosts_info, criteria_items, evidences)[0]

    wb = openpyxl.Workbook()
    print(f"[INFO] 보고서 생성 중...")

    _create_cover_sheet(wb, mode, "webwas", hosts_info)
    _create_overview_sheet(wb, mode, "webwas", hosts_info, criteria_items,
                           next(iter(all_results), None))
    _create_revision_sheet(wb)
    _init_sheet_names(list(all_results.keys()))
    target_row_map = _create_target_sheet(wb, hosts_info, all_results)
    _create_security_stats_sheet(wb, all_results, criteria_items, hosts_info, "webwas")
    _create_summary_stats_sheet(wb, all_results, criteria_items)

    for hostname, (res, detected_sub) in all_results.items():
        hi = next((h for h in hosts_info if h["hostname"] == hostname), {})
        _create_detail_sheet(wb, hostname, res, criteria_items, detected_sub, hi,
                             target_row_map.get(hostname))
        filled = sum(1 for code in criteria_items if code in res)
        print(f"[INFO] {hostname}: {filled}개 항목 기입 완료")

    _create_vuln_list_sheet(wb, all_results, criteria_items)
    _create_review_sheet(wb, all_results, criteria_items)
    _create_security_guide_sheet(wb, all_results, hosts_info, criteria_items)

    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    mode_str  = "전자금융" if mode == "EF" else "주요정보"
    out_path  = os.path.join(cat_dir, f"상세보고서_{mode_str}_웹WAS_{timestamp}.xlsx")
    wb.save(out_path)
    total_bad = sum(sum(1 for v in res.values() if v[0] == RESULT_BAD)
                    for res, _ in all_results.values())
    print(f"\n[완료] 상세보고서 저장: {out_path}")
    print(f"  시트 구성: 표지 / 개요 / 개정이력 / 점검대상 / 보안수준 통계 / 요약 통계 / 호스트 상세 {len(all_results)}개")
    print(f"  총 점검 대상: {len(all_results)}대 / 전체 취약: {total_bad}건")

    audit_targets = []
    for hostname, (res, detected_sub) in all_results.items():
        filtered = {code: res.get(code, (RESULT_MANUAL, "")) for code in criteria_items}
        good = sum(1 for v in filtered.values() if v[0] == RESULT_GOOD)
        bad  = sum(1 for v in filtered.values() if v[0] == RESULT_BAD)
        na_c = sum(1 for v in filtered.values() if v[0] == RESULT_NA)
        mc   = sum(1 for v in filtered.values() if v[0] == RESULT_MANUAL)
        hi = next((h for h in hosts_info if h["hostname"] == hostname), {})
        audit_targets.append({
            "name": hostname, "subtype": detected_sub,
            "web_info": hi.get("web_info", ""),
            "good": good, "bad": bad, "na": na_c, "manual": mc,
            "input_file": f"{hostname}.txt",
        })
    write_audit_log(base_dir, mode, "webwas", audit_targets, out_path)
    try:
        write_eos_inventory(base_dir, ["webwas"], cat_dir)
    except Exception as e:
        print(f"[경고] EoS 현황 생성 실패: {e}")


def _load_eos_checker(base_dir):
    """eos_checker.py를 직접 import하여 check_eos 함수 반환"""
    eos_path = os.path.join(base_dir, "eos_checker.py")
    if not os.path.exists(eos_path):
        return None
    import importlib.util
    spec = importlib.util.spec_from_file_location("eos_checker", eos_path)
    mod  = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.check_eos


def parse_version_info(text):
    """
    점검 결과 파일 헤더에서 제품+버전 쌍 추출.
    반환: [(product, version), ...]
    """
    found = []
    for line in text.splitlines()[:40]:
        s = line.strip().lstrip("#").strip()
        kv = s.split(":", 1)
        if len(kv) < 2:
            continue
        key = kv[0].strip().lower()
        val = kv[1].strip()

        if key in ("os", "운영체제", "os종류"):
            v = val.lower()
            if "red hat" in v or "rhel" in v:
                m = re.search(r'(\d+\.?\d*)', val)
                if m: found.append(("rhel", m.group(1)))
            elif "centos" in v:
                m = re.search(r'(\d+\.?\d*)', val)
                if m: found.append(("centos", m.group(1)))
            elif "ubuntu" in v:
                m = re.search(r'(\d+\.\d+)', val)
                if m: found.append(("ubuntu", m.group(1)))
            elif "rocky" in v:
                m = re.search(r'(\d+\.?\d*)', val)
                if m: found.append(("rocky", m.group(1)))
            elif "debian" in v:
                m = re.search(r'(\d+)', val)
                if m: found.append(("debian", m.group(1)))
            elif "sles" in v or "suse" in v:
                m = re.search(r'(\d+)', val)
                if m: found.append(("sles", m.group(1)))
            elif "amazon" in v:
                m = re.search(r'(\d+|2023)', val)
                if m: found.append(("amazon-linux", m.group(1)))
            elif "aix" in v:
                m = re.search(r'(\d+\.\d+)', val)
                if m: found.append(("aix", m.group(1)))
            elif "solaris" in v or "sunos" in v:
                m = re.search(r'(\d+\.?\d*)', val)
                if m: found.append(("solaris", m.group(1)))
            elif "hp-ux" in v or "hpux" in v:
                m = re.search(r'(11i\s*v\d+|\d+)', val, re.I)
                if m: found.append(("hp-ux", m.group(1).lower()))
            elif "windows" in v:
                m = re.search(r'(2008r?2?|2012r?2?|2016|2019|2022|2025)', val, re.I)
                if m: found.append(("windows-server", m.group(1).lower()))

        elif key in ("웹서버", "웹 서버"):
            v = val.lower()
            if "apache" in v:
                m = re.search(r'(\d+\.\d+)', val)
                if m: found.append(("apache", m.group(1)))
            elif "nginx" in v:
                m = re.search(r'(\d+\.\d+)', val)
                if m: found.append(("nginx", m.group(1)))

        elif key == "was":
            v = val.lower()
            if "tomcat" in v:
                m = re.search(r'(\d+\.?\d*)', val)
                if m: found.append(("tomcat", m.group(1)))
            elif "jeus" in v:
                m = re.search(r'(\d+)', val)
                if m: found.append(("jeus", m.group(1)))
            elif "webtob" in v:
                m = re.search(r'(\d+)', val)
                if m: found.append(("webtob", m.group(1)))

        elif key in ("dbms 종류", "dbms", "db", "db type", "db_type", "dbms종류"):
            v = val.lower()
            if "oracle" in v:
                m = re.search(r'(\d+[cg]?)', val, re.I)
                if m: found.append(("oracle", m.group(1).lower()))
            elif "mysql" in v:
                m = re.search(r'(\d+\.\d+)', val)
                if m: found.append(("mysql", m.group(1)))
            elif "mariadb" in v:
                m = re.search(r'(\d+\.\d+)', val)
                if m: found.append(("mariadb", m.group(1)))
            elif "mssql" in v or "sql server" in v:
                m = re.search(r'(20\d{2})', val)
                if m: found.append(("mssql", m.group(1)))
            elif "postgresql" in v or "pgsql" in v:
                m = re.search(r'(\d+)', val)
                if m: found.append(("postgresql", m.group(1)))
            elif "tibero" in v:
                m = re.search(r'(\d+)', val)
                if m: found.append(("tibero", m.group(1)))

        elif key in ("os version", "os 버전", "os버전", "kernel"):
            m = re.search(r'(\d+\.?\d*\.?\d*)', val)
            if m and not found:
                found.append(("unknown", m.group(1)))

    return found


EOS_ITEM_CODES = {
    "server":  "SRV-179",
    "webwas":  "WST-126",
    "dbms":    "DBM-025",
    "network": "NET-059",
}

def run_eos_check(category, res, text, base_dir):
    """
    EoS 항목 자동 판정 (eos_checker.py 직접 import).
    text: 원본 점검 결과 파일 텍스트 (헤더에서 버전 추출용)
    """
    check_eos = _load_eos_checker(base_dir)
    if not check_eos:
        return res

    eos_code = EOS_ITEM_CODES.get(category)
    if not eos_code:
        return res

    versions = parse_version_info(text)
    if not versions:
        return res

    eos_results = []
    for product, version in versions:
        if product == "unknown":
            continue
        try:
            result, eol_date, desc = check_eos(product, version, use_api=False)
            eos_results.append((product, version, result, eol_date, desc))
        except Exception:
            pass

    if not eos_results:
        return res

    worst = RESULT_GOOD
    descs = []
    for product, version, result, eol_date, desc in eos_results:
        descs.append(desc)
        if result == RESULT_BAD:
            worst = RESULT_BAD
        elif result == RESULT_MANUAL and worst != RESULT_BAD:
            worst = RESULT_MANUAL

    combined = " / ".join(descs)
    if eos_code in res:
        old_result, old_reason = res[eos_code]
        if old_result == RESULT_MANUAL:
            res[eos_code] = (worst, combined)
    else:
        res[eos_code] = (worst, combined)

    return res

def _pc_items_as_criteria():
    """PC_ITEMS를 criteria_items 호환 형식으로 변환"""
    risk_map = {"상": "4.0", "중": "3.0", "하": "2.0"}
    items = {}
    for code, item in PC_ITEMS.items():
        items[code] = {
            "name":         item["name"],
            "risk":         risk_map.get(item.get("risk", ""), item.get("risk", "")),
            "desc":         "",
            "control_area": "PC보안",
            "control_sub":  "",
            "applies_to":   {},
            "criteria_by":  {},
            "fix":          item.get("fix", ""),
        }
    return items


def run_pc_convert(mode, base_dir):
    """PC 점검 결과 변환 (기준 엑셀 없이 코드 내장 항목 사용)"""
    cat_dir   = os.path.join(base_dir, "pc")
    input_dir = os.path.join(cat_dir, "output")

    if not os.path.exists(input_dir):
        print(f"[ERROR] PC 점검 결과 폴더 없음: {input_dir}")
        return

    input_files = sorted(f for f in os.listdir(input_dir)
                         if f.endswith(".txt") and "evidence" not in f.lower())
    if not input_files:
        print(f"[ERROR] {input_dir}에 .txt 파일 없음")
        return

    if mode == "MI":   # 주요정보: 2026 상세가이드 PC-01~PC-19 (check_pc_kisa.ps1 결과)
        criteria_items = _kisa_criteria("PC")
        print(f"[INFO] 주요정보통신기반시설 상세가이드(2026) PC 항목 {len(criteria_items)}개 로드")
    else:
        criteria_items = _pc_items_as_criteria()
        print(f"[INFO] PC 내장 항목 {len(criteria_items)}개 로드")

    all_results = {}
    hosts_info  = []

    for fname in input_files:
        path = os.path.join(input_dir, fname)
        pure = os.path.splitext(fname)[0]
        text = read_text(path)

        hinfo = _parse_header_info(text)
        evidence = {}
        if not hinfo["hostname"]:
            hinfo["hostname"] = pure
        if not hinfo.get("os"):
            hinfo["os"] = "Windows"

        res = parse_pipe(text)
        kisa_file = "상세가이드(2026)" in "\n".join(text.splitlines()[:15])   # check_pc_kisa.ps1 / check_pc_mac_kisa.sh 결과 머리말
        if (mode == "MI") != kisa_file:   # PC 항목코드가 같아도 기준(항목 의미)이 다름 → 섞지 않음
            print(f"[경고] {fname}: " + ("전자금융용 check_pc.ps1/check_pc_mac.sh 결과 - 주요정보 변환에는 check_pc_kisa.ps1/check_pc_mac_kisa.sh 결과 필요 → 제외"
                                        if mode == "MI" else "주요정보용 check_pc_kisa.ps1/check_pc_mac_kisa.sh 결과 - 전자금융 변환 대상 아님 → 제외"))
            continue
        if _category_mismatch(res, criteria_items, fname):
            continue
        evd_path = find_evidence_file(path)
        if evd_path:
            evidence = parse_evidence(evd_path)
            print(f"[INFO] {fname} → 증적 파일 병합: {os.path.basename(evd_path)} ({len(evidence)}건)")
        for code in criteria_items:
            if code not in res:
                res[code] = (RESULT_MANUAL, "스크립트 미점검 항목 (수동 확인 필요)")

        res = compose_status(res, evidence, criteria_items, None)
        all_results[hinfo["hostname"]] = (res, "PC")
        hosts_info.append(hinfo)

        bad  = sum(1 for v in res.values() if v[0] == RESULT_BAD)
        good = sum(1 for v in res.values() if v[0] == RESULT_GOOD)
        print(f"[INFO] {fname} → 총 {len(res)}개 / 양호 {good} / 취약 {bad}")

    if not all_results:
        _no_results_stop(mode, "pc")
        return
    wb = openpyxl.Workbook()
    print(f"[INFO] 보고서 생성 중...")

    _create_cover_sheet(wb, mode, "pc", hosts_info)
    _create_overview_sheet(wb, mode, "pc", hosts_info, criteria_items,
                           next(iter(all_results), None))
    _create_revision_sheet(wb)
    _init_sheet_names(list(all_results.keys()))
    target_row_map = _create_target_sheet(wb, hosts_info, all_results)
    _create_security_stats_sheet(wb, all_results, criteria_items, hosts_info, "pc")
    _create_summary_stats_sheet(wb, all_results, criteria_items)

    for hostname, (res, detected_sub) in all_results.items():
        hi = next((h for h in hosts_info if h["hostname"] == hostname), {})
        _create_detail_sheet(wb, hostname, res, criteria_items, detected_sub, hi,
                             target_row_map.get(hostname))
        print(f"[INFO] {hostname}: {len(criteria_items)}개 항목 기입 완료")

    _create_vuln_list_sheet(wb, all_results, criteria_items)
    _create_review_sheet(wb, all_results, criteria_items)
    _create_security_guide_sheet(wb, all_results, hosts_info, criteria_items)

    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    mode_str  = "전자금융" if mode == "EF" else "주요정보"
    out_path  = os.path.join(cat_dir, f"상세보고서_{mode_str}_PC_{timestamp}.xlsx")
    wb.save(out_path)
    total_bad = sum(sum(1 for v in res.values() if v[0] == RESULT_BAD)
                    for res, _ in all_results.values())
    print(f"\n[완료] 상세보고서 저장: {out_path}")
    print(f"  시트 구성: 표지 / 개요 / 개정이력 / 점검대상 / 보안수준 통계 / 요약 통계 / 호스트 상세 {len(all_results)}개")
    print(f"  총 점검 대상: {len(all_results)}대 / 전체 취약: {total_bad}건")

    audit_targets = []
    for hostname, (res, detected_sub) in all_results.items():
        filtered = {code: res.get(code, (RESULT_MANUAL, "")) for code in criteria_items}
        good = sum(1 for v in filtered.values() if v[0] == RESULT_GOOD)
        bad  = sum(1 for v in filtered.values() if v[0] == RESULT_BAD)
        na_c = sum(1 for v in filtered.values() if v[0] == RESULT_NA)
        mc   = sum(1 for v in filtered.values() if v[0] == RESULT_MANUAL)
        audit_targets.append({
            "name": hostname, "good": good, "bad": bad, "na": na_c, "manual": mc,
            "input_file": f"{hostname}.txt",
        })
    write_audit_log(base_dir, mode, "pc", audit_targets, out_path)


def _no_results_stop(mode, category):
    """변환할 결과가 하나도 없을 때(반대 기준 결과만 있음 등) 보고서 생성 대신 안내 후 중단"""
    other = "2. 주요정보통신기반시설" if mode == "EF" else "1. 전자금융기반시설"
    print(f"[ERROR] {CAT_LABEL.get(category, category)}: {'전자금융' if mode == 'EF' else '주요정보'} 기준으로 변환할 결과 파일이 없습니다 - 보고서를 만들지 않습니다.")
    print(f"        위에 '제외' 경고가 있으면 다른 기준용 스크립트 결과입니다. 평가 기반을 '{other}'(으)로 선택하거나, 해당 기준 스크립트로 다시 수집하세요.")


def run_convert(mode, category, base_dir, criteria_excel):
    """
    mode: "EF" or "MI"
    category: "server", "webwas", "dbms", "network", "security", "pc"
    base_dir: convert/ 루트 폴더
    criteria_excel: 기준 엑셀 경로
    """
    # 웹/WAS는 유형별 자동 분류 전용 함수로 처리
    if category == "webwas":
        run_webwas_convert(mode, base_dir, criteria_excel)
        return

    # PC는 기준 엑셀 없이 코드 내장 항목으로 처리
    if category == "pc":
        run_pc_convert(mode, base_dir)
        return

    cat_dir    = os.path.join(base_dir, category)
    sheet_name = SHEET_MAP.get(category, "")

    if not os.path.exists(cat_dir):
        print(f"[ERROR] 폴더 없음: {cat_dir}")
        return

    # 입력 파일 폴더
    if category == "network":
        input_dir = os.path.join(cat_dir, "config")
        input_mode = "config"
    else:
        input_dir = os.path.join(cat_dir, "output")
        input_mode = "pipe"

    if not os.path.exists(input_dir):
        print(f"[ERROR] 입력 폴더 없음: {input_dir}")
        return

    input_files = [f for f in os.listdir(input_dir)
                   if f.endswith(".txt") and "evidence" not in f.lower()]
    # 결과 파일이 없으면 증적 파일(*_evidence.txt)의 [판정] 줄로 결과 복원
    evidence_only = False
    if not input_files and input_mode == "pipe":
        input_files = [f for f in os.listdir(input_dir)
                       if f.endswith(".txt") and "evidence" in f.lower()]
        if input_files:
            evidence_only = True
            print(f"[안내] 결과 파일 없음 → 증적 파일 {len(input_files)}개의 [판정] 줄로 결과 복원")
    if not input_files:
        print(f"[ERROR] {input_dir}에 .txt 파일 없음")
        return

    # 기준 엑셀에서 항목 목록 로드
    kisa_mode   = mode == "MI" and category in KISA_CATEGORY_FAMILY
    if kisa_mode:
        # 주요정보: 판정 기준은 2026 상세가이드. 전자금융 점검 스크립트 결과는 가이드 항목 판정 근거 자료로만 사용
        criteria_items = load_criteria(criteria_excel, sheet_name, "EF")
        print("[INFO] 판정 기준: 주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드(2026)")
        print(f"[INFO] 전자금융 점검 스크립트 결과가 있으면 판정 근거 자료로 사용 ({len(criteria_items)}개 항목 코드 인식)")
    else:
        print(f"[INFO] 기준 엑셀 로드: {sheet_name}")
        criteria_items = load_criteria(criteria_excel, sheet_name, mode)
        print(f"[INFO] 평가항목 {len(criteria_items)}개 로드 완료 ({'전자금융' if mode=='EF' else '주요정보'} 기준)")
    known_codes = dict(criteria_items, **{k: {} for k in KISA_GUIDE_ITEMS}) if kisa_mode else criteria_items

    # 각 입력 파일 파싱
    all_results = {}
    evidences   = {}
    hosts_info  = []
    for fname in sorted(input_files):
        path  = os.path.join(input_dir, fname)
        pure  = os.path.splitext(fname)[0]
        text  = read_text(path)
        if evidence_only:
            text = _evidence_to_pipe_text(text)
            pure = re.sub(r"(_(srv|server|u|w|kisa|webwas|dbms|iss|pc))?_evidence$", "", pure, flags=re.I)
        lines = text.splitlines()

        hinfo = _parse_header_info(text)
        evidence = {}
        if not hinfo["hostname"]:
            hinfo["hostname"] = pure

        if input_mode == "pipe":
            res = parse_pipe(text)
            if _category_mismatch(res, known_codes, fname):
                continue
            if not kisa_mode and any(k in KISA_GUIDE_ITEMS for k in res) and not any(k in criteria_items for k in res):
                continue
            evd_path = path if evidence_only else find_evidence_file(path)
            if evd_path:
                evidence = parse_evidence(evd_path)
                print(f"[INFO] {fname} → 증적 파일 병합: {os.path.basename(evd_path)} ({len(evidence)}건)")
            if category == "server":
                sub_key = detect_srv_os(text)
                if not sub_key:
                    sub_key = _infer_srv_os(res, evd_path)
                    print(f"[경고] {fname}: 결과 헤더에 OS 정보 없음 → "
                          + (f"{sub_key}로 추정하여 평가대상 보정" if sub_key else "OS 추정 불가, 평가대상 보정 생략 (원본 확인 필요)"))
                    if sub_key and not hinfo.get("os"):
                        hinfo["os"] = f"{sub_key} (추정)"
            elif category == "dbms":
                sub_key = detect_dbms_vendor(text)
            elif category == "security":
                mdev = re.search(r"^#\s*장비유형\s*:\s*(\S+)", text, re.M)
                dev = mdev.group(1).upper().replace("-", "") if mdev else ""
                sub_key = dev if dev in ISS_COLS else None
                mven = re.search(r"^#\s*벤더\s*:\s*(.+)$", text, re.M)
                if not hinfo.get("os"):
                    hinfo["os"] = " / ".join(x for x in ((mven.group(1).strip() if mven else ""), dev) if x)
            else:
                sub_key = None
            # 스크립트가 평가대상 아닌 항목에 판정을 낸 경우(구버전 스크립트 결과 포함) → N-A 보정
            if sub_key:
                forced = 0
                for code, (rv, why) in list(res.items()):
                    item = criteria_items.get(code)
                    if item and rv != RESULT_NA and not is_applicable(item, sub_key):
                        res[code] = (RESULT_NA, f"평가대상 아님 ({sub_key} 해당 없음 - 평가기준 평가대상 열)")
                        forced += 1
                if forced:
                    print(f"[INFO] {fname} → 평가대상 아닌 항목 {forced}건 N-A 보정")
                # 역방향: 평가대상인데 스크립트가 '전용 항목/해당 없음'으로 N-A 처리 → 수동확인
                revived = 0
                for code, (rv, why) in list(res.items()):
                    item = criteria_items.get(code)
                    if (item and rv == RESULT_NA and is_applicable(item, sub_key)
                            and re.search(r"전용 항목|해당 ?없음", why or "")
                            and not why.startswith("평가대상 아님")):
                        res[code] = (RESULT_MANUAL,
                                     f"평가기준상 {sub_key} 평가대상이나 스크립트 미점검 (스크립트 사유: {why}) - 수동 확인 필요")
                        revived += 1
                if revived:
                    print(f"[INFO] {fname} → 평가대상인데 N-A 처리된 항목 {revived}건 수동확인 전환")
            for code in criteria_items:
                if code in res: continue
                item = criteria_items[code]
                if sub_key and not is_applicable(item, sub_key):
                    res[code] = (RESULT_NA, f"현재 유형({sub_key})에 해당 없는 항목")
                else:
                    res[code] = (RESULT_MANUAL, "스크립트 미점검 항목 (수동 확인 필요)")
        else:  # network config
            vendor = detect_net_vendor(text)
            res    = build_net_checks(lines, text)
            sub_key = None
            # 판정된 항목도 평가대상(장비 유형·벤더 그룹) 아니면 N-A
            for code in list(res):
                item = criteria_items.get(code)
                if item and res[code][0] != RESULT_NA and not net_applicable(item, text, lines):
                    res[code] = (RESULT_NA, f"평가대상 아님 (장비 유형 {detect_net_dtype(lines)}·벤더 {vendor} 해당 없음 - 평가기준 평가대상 열)")
            if mode == "MI":   # 가이드 항목 직접 판정 (통합 점검 항목 분리)
                res.update(build_net_kisa_checks(lines, text))
            if not hinfo.get("os"):
                mv = re.search(r"^\s*(?:version|JUNOS|Software Version)\s+(\S+)", text, re.M | re.I)
                hn = re.search(r"^\s*hostname\s+(\S+)", text, re.M)
                if hn and hinfo["hostname"] == pure:
                    hinfo["hostname"] = hn.group(1)
                brand, model, fw = _net_brand(text)
                ver = mv.group(1) if mv else fw
                hinfo["os"] = " ".join(x for x in ((brand or vendor), model, ver) if x)
            net_subs = detect_net_subtypes(text, lines)
            for code in criteria_items:
                if code in res: continue
                item = criteria_items[code]
                applicable = net_applicable(item, text, lines)
                if not applicable:
                    res[code] = (RESULT_NA, f"장비 유형({', '.join(net_subs) or vendor})에 해당 없음")
                else:
                    res[code] = (RESULT_MANUAL, "config에서 자동 판단 불가 (수동 확인)")
            print(f"[INFO] {fname} → 벤더: {vendor}, 취약: {sum(1 for v in res.values() if v[0]==RESULT_BAD)}건")

        res = run_eos_check(category, res, text, base_dir)

        detected_sub = sub_key if input_mode == "pipe" else "GENERIC"
        if kisa_mode:   # 가이드 항목 변환 후 현황 구성
            evidences[hinfo["hostname"]] = evidence
        else:
            res = compose_status(res, evidence, criteria_items, detected_sub)
        _h = hinfo["hostname"]
        if _h in all_results:   # 같은 호스트 결과 파일이 여럿(전자금융 + 주요정보 전용 스크립트 등) → 판정·증적 병합, 대상 1대 (파일 순서 무관)
            _old_res, _old_sub = all_results[_h]
            res = {**_old_res, **res}
            detected_sub = detected_sub or _old_sub
            if _h in evidences:
                evidences[_h] = {**evidences[_h], **(evidence or {})}
            for _hi in hosts_info:
                if _hi.get("hostname") == _h:
                    for _k, _v in hinfo.items():
                        if _v and not _hi.get(_k):
                            _hi[_k] = _v
            print(f"[INFO] {fname}: 같은 호스트({_h})의 다른 결과 파일과 병합")
            all_results[_h] = (res, detected_sub)
            continue
        all_results[_h] = (res, detected_sub)
        hosts_info.append(hinfo)
        total = sum(1 for k in res if k in criteria_items)
        bad   = sum(1 for k, v in res.items() if k in criteria_items and v[0] == RESULT_BAD)
        good  = sum(1 for k, v in res.items() if k in criteria_items and v[0] == RESULT_GOOD)
        print(f"[INFO] {fname} → 총 {total}개 / 양호 {good} / 취약 {bad}")

    if not all_results:
        _no_results_stop(mode, category)
        return
    # 주요정보(MI): 가이드 항목 체계로 변환 (서버 Unix/Windows 혼재 시 보고서 분리)
    if mode == "MI" and category in KISA_CATEGORY_FAMILY:
        groups = _kisa_groups(category, all_results, hosts_info, criteria_items, evidences)
    else:
        groups = [("", all_results, hosts_info, criteria_items)]
    for label, g_results, g_hosts, g_items in groups:
        _write_report(mode, category, cat_dir, base_dir, g_results, g_hosts, g_items, label)
    if category in _EOS_CATS:   # 서버·DBMS·네트워크: 대상별 OS·버전·커널·제품 EoS 현황 .txt
        try:
            write_eos_inventory(base_dir, [category], cat_dir)
        except Exception as e:
            print(f"[경고] EoS 현황 생성 실패: {e}")


def _write_report(mode, category, cat_dir, base_dir, all_results, hosts_info, criteria_items, label=""):
    """상세보고서 워크북 생성·저장 + 감사 로그 (label: 파일명 구분자, 예: Unix/Windows)"""
    # 새 워크북 생성 (템플릿 불필요)
    wb = openpyxl.Workbook()
    print(f"[INFO] 보고서 생성 중...")

    _create_cover_sheet(wb, mode, category, hosts_info)
    _create_overview_sheet(wb, mode, category, hosts_info, criteria_items,
                           next(iter(all_results), None))
    _create_revision_sheet(wb)
    _init_sheet_names(list(all_results.keys()))
    target_row_map = _create_target_sheet(wb, hosts_info, all_results)
    _create_security_stats_sheet(wb, all_results, criteria_items, hosts_info, category)
    _create_summary_stats_sheet(wb, all_results, criteria_items)

    for hostname, (res, detected_sub) in all_results.items():
        hi = next((h for h in hosts_info if h["hostname"] == hostname), {})
        _create_detail_sheet(wb, hostname, res, criteria_items, detected_sub, hi,
                             target_row_map.get(hostname))
        filled = sum(1 for code in criteria_items if code in res)
        print(f"[INFO] {hostname}: {filled}개 항목 기입 완료")

    # 저장
    _create_vuln_list_sheet(wb, all_results, criteria_items)
    _create_review_sheet(wb, all_results, criteria_items)
    _create_security_guide_sheet(wb, all_results, hosts_info, criteria_items)

    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    mode_str  = "전자금융" if mode == "EF" else "주요정보"
    cat_str   = CAT_LABEL.get(category, category)
    out_name  = f"상세보고서_{mode_str}_{cat_str}{'_' + label if label else ''}_{timestamp}.xlsx"
    out_path  = os.path.join(cat_dir, out_name)
    wb.save(out_path)
    total_bad = sum(sum(1 for v in res.values() if v[0] == RESULT_BAD)
                    for res, _ in all_results.values())
    print(f"\n[완료] 상세보고서 저장: {out_path}")
    print(f"  시트 구성: 표지 / 개요 / 개정이력 / 점검대상 / 보안수준 통계 / 요약 통계 / 호스트 상세 {len(all_results)}개")
    print(f"  총 점검 대상: {len(all_results)}대 / 전체 취약: {total_bad}건")

    audit_targets = []
    for hostname, (res, detected_sub) in all_results.items():
        filtered = {code: res.get(code, (RESULT_MANUAL, "")) for code in criteria_items}
        good = sum(1 for v in filtered.values() if v[0] == RESULT_GOOD)
        bad  = sum(1 for v in filtered.values() if v[0] == RESULT_BAD)
        na_c = sum(1 for v in filtered.values() if v[0] == RESULT_NA)
        mc   = sum(1 for v in filtered.values() if v[0] == RESULT_MANUAL)
        audit_targets.append({
            "name": hostname, "subtype": detected_sub,
            "good": good, "bad": bad, "na": na_c, "manual": mc,
            "input_file": f"{hostname}.txt",
        })
    write_audit_log(base_dir, mode, category, audit_targets, out_path)


# ================================================================
# CLI 메뉴
# ================================================================
def main():
    print("=" * 60)
    print("  전자금융기반시설 / 주요정보통신기반시설")
    print("  취약점 점검 통합 컨버터 v" + VERSION)
    print("=" * 60)

    # ── 기준 엑셀 위치 ─────────────────────────────────────────
    base_dir = os.path.dirname(os.path.abspath(__file__))
    
    # 기준 엑셀 탐색
    criteria_candidates = [
        os.path.join(base_dir, "전자금융기반시설_보안_취약점_평가기준_제2026-1호.xlsx"),
        os.path.join(base_dir, "criteria.xlsx"),
    ]
    criteria_candidates += [os.path.join(base_dir, f) for f in os.listdir(base_dir)
                             if "취약점" in f and "평가기준" in f and f.endswith(".xlsx")]
    criteria_excel = next((p for p in criteria_candidates if os.path.exists(p)), None)

    if not criteria_excel:
        print("[ERROR] 기준 엑셀 파일을 찾을 수 없습니다.")
        print("  → 이 스크립트와 같은 폴더에 '전자금융기반시설_보안_취약점_평가기준_제2026-1호.xlsx' 를 넣어주세요.")
        sys.exit(1)

    print(f"\n[기준 엑셀] {os.path.basename(criteria_excel)}")

    # ── 1단계: 평가 기반 선택 ─────────────────────────────────
    print("\n[1단계] 평가 기반 선택")
    print("  1. 전자금융기반시설 (전자금융감독규정 준거)")
    print("  2. 주요정보통신기반시설 (과학기술정보통신부 고시 준거)")
    while True:
        sel = input("  선택 (1/2): ").strip()
        if sel == "1":  mode = "EF"; mode_name = "전자금융기반시설"; break
        if sel == "2":  mode = "MI"; mode_name = "주요정보통신기반시설"; break
        print("  1 또는 2를 입력하세요.")

    # ── 2단계: 점검 대상 선택 ─────────────────────────────────
    print(f"\n[2단계] 점검 대상 선택 ({mode_name})")
    if mode == "MI":   # 2026 상세가이드 항목코드
        codes = ["U-01~67 / W-01~64", "WEB-01~26", "D-01~26", "N-01~38", "S-01~23", "PC-01~18"]
    else:
        codes = ["SRV-xxx", "WST-xxx", "DBM-xxx", "NET-xxx", "ISS-xxx", "PC-xx"]
    print(f"  1. 서버           ({codes[0]}: Linux/Unix/Windows - AIX, HP-UX, LINUX, Solaris, Windows)")
    print(f"  2. 웹서버/WAS     ({codes[1]}: Apache, Nginx, WebtoB, Tomcat, JEUS, IIS)")
    print(f"  3. 데이터베이스   ({codes[2]}: Oracle, MSSQL, MySQL, MariaDB, PostgreSQL, Tibero)")
    print(f"  4. 네트워크 장비  ({codes[3]}: Cisco, A10, Alteon, Juniper, D-Link)")
    print(f"  5. 보안장비       ({codes[4]}: FW, VPN, IDS, IPS, DDoS, WAF)")
    print(f"  6. PC(업무용단말) ({codes[5]}: Windows 10/11, macOS)")
    print("  7. EoS 현황       (서버·웹/WAS·DBMS·네트워크 OS·버전·커널 → 지원 종료 대수 .txt)")
    while True:
        sel = input("  선택 (1~7): ").strip()
        if sel == "7":
            write_eos_inventory(base_dir)
            return
        if sel == "1": category = "server";   cat_name = "서버"; break
        if sel == "2": category = "webwas";   cat_name = "웹서버/WAS"; break
        if sel == "3": category = "dbms";     cat_name = "데이터베이스"; break
        if sel == "4": category = "network";  cat_name = "네트워크 장비"; break
        if sel == "5": category = "security"; cat_name = "보안장비"; break
        if sel == "6": category = "pc";       cat_name = "PC(업무용 단말)"; break
        print("  1~7 중 하나를 입력하세요.")

    print(f"\n[실행] {mode_name} / {cat_name} 점검 컨버팅 시작")
    sub = "config" if category == "network" else "output"
    print(f"  입력 폴더: {os.path.join(base_dir, category, sub)}")
    print("-" * 60)

    run_convert(mode, category, base_dir, criteria_excel)


if __name__ == "__main__":
    main()
