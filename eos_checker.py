#!/usr/bin/env python3
# ================================================================
# EoS (End of Support) 자동 판정 모듈 v1.0
# 기준일: 2026-06-24
#
# [사용법]
#   python eos_checker.py oracle 19c
#   python eos_checker.py mysql 8.0
#   python eos_checker.py rhel 7
#   python eos_checker.py "cisco-ios-xe" 17.9
#
# [반환]
#   (결과, EoS일자, 설명)
#   결과: 양호 / 취약 / 수동확인
# ================================================================

import re, sys, datetime, json
try:
    from urllib.request import urlopen, Request
    from urllib.error import URLError
    HAS_URLLIB = True
except ImportError:
    HAS_URLLIB = False

CHECK_DATE = datetime.date(2026, 6, 24)   # 점검 기준일
RESULT_GOOD   = "양호"
RESULT_BAD    = "취약"
RESULT_MANUAL = "수동확인"

# ================================================================
# 하드코딩 EoS 데이터베이스 (2026-06-24 기준)
# 형식: { 제품명(소문자): { 버전_prefix: EoS_date 또는 None(현역) } }
# EoS_date = "YYYY-MM-DD" | "YYYY-MM" | "YYYY"
# None = 현역 (Active)
# ================================================================
EOS_DB = {

    # ── OS: Linux ─────────────────────────────────────────────────
    "rhel": {
        "6":  "2020-11-30",
        "7":  "2024-06-30",   # ✗ EoS
        "8":  None,           # Active until 2029-05-31
        "9":  None,           # Active until 2032-05-31
        "10": None,
    },
    "centos": {
        "6":  "2020-11-30",
        "7":  "2024-06-30",   # ✗ EoS
        "8":  "2021-12-31",   # ✗ EoS (CentOS 8 조기 종료)
        "8-stream": None,
        "9-stream": None,
    },
    "rocky": {
        "8":  None,   # Active until 2029
        "9":  None,   # Active until 2032
    },
    "almalinux": {
        "8":  None,
        "9":  None,
    },
    "ubuntu": {
        "16.04": "2021-04-30",
        "18.04": "2023-04-30",   # ✗ EoS (ESM은 별도)
        "20.04": "2025-04-30",   # ✗ EoS (ESM은 별도)
        "22.04": None,            # Active until 2027-04-30
        "24.04": None,            # Active until 2029-04-30
        "24.10": "2025-07-12",
        "25.04": None,
    },
    "debian": {
        "9":  "2022-06-30",
        "10": "2024-06-30",   # ✗ EoS
        "11": "2026-08-31",   # Active (barely)
        "12": None,            # Active until 2028-06-30
        "13": None,
    },
    "sles": {
        "12": "2024-10-31",   # ✗ EoS
        "15": None,            # Active until 2031
    },
    "amazon-linux": {
        "1":  "2023-12-31",   # ✗ EoS
        "2":  "2025-06-30",   # ✗ EoS
        "2023": None,          # Active
    },

    # ── OS: Unix ──────────────────────────────────────────────────
    "aix": {
        "6.1": "2017-04-30",
        "7.1": "2023-04-30",   # ✗ EoS
        "7.2": "2025-04-30",   # ✗ EoS
        "7.3": None,            # Active
    },
    "solaris": {
        "10": "2021-01-26",   # ✗ EoS
        "11.4": None,          # Active
        "11": None,
    },
    "hp-ux": {
        "11i v1": "2012-12-31",
        "11i v2": "2015-06-30",
        "11i v3": "2025-12-31",   # ✗ EoS (2025-12-31 지남)
    },

    # ── OS: Windows Server ────────────────────────────────────────
    "windows-server": {
        "2003":   "2015-07-14",
        "2008":   "2020-01-14",
        "2008r2": "2020-01-14",   # ✗ EoS
        "2012":   "2023-10-10",   # ✗ EoS
        "2012r2": "2023-10-10",   # ✗ EoS
        "2016":   None,            # Active until 2027-01-12
        "2019":   None,            # Active until 2029-01-09
        "2022":   None,            # Active until 2031-10-14
    },

    # ── DBMS: Oracle ──────────────────────────────────────────────
    "oracle": {
        "10g": "2010-07-13",
        "10":  "2010-07-13",
        "11g": "2020-12-31",
        "11":  "2020-12-31",
        "12c": "2022-07-31",
        "12":  "2022-07-31",
        "18c": "2021-06-30",
        "18":  "2021-06-30",
        "19c": None,              # Active (Premier 2024-12, Extended 2027-12)
        "19":  None,
        "21c": "2024-04-30",   # ✗ EoS (Short Term)
        "21":  "2024-04-30",
        "23c": None,              # Active
        "23":  None,
    },

    # ── DBMS: MySQL ───────────────────────────────────────────────
    "mysql": {
        "5.0": "2012-01-09",
        "5.1": "2013-12-31",
        "5.5": "2018-12-31",
        "5.6": "2021-02-28",   # ✗ EoS
        "5.7": "2023-10-31",   # ✗ EoS
        "8.0": "2026-04-30",   # ✗ EoS (2026-04 지남)
        "8.4": None,            # Active (LTS until 2032)
        "9.0": "2025-01-31",
        "9.1": None,
    },

    # ── DBMS: MariaDB ─────────────────────────────────────────────
    "mariadb": {
        "10.4": "2024-06-18",   # ✗ EoS
        "10.5": "2025-06-24",   # ✗ EoS
        "10.6": "2026-07-06",   # ⚠ EoS 임박 (2주 후)
        "10.11": None,           # Active LTS until 2028
        "11.4": None,            # Active LTS
        "11.7": None,
        "11.8": None,
    },

    # ── DBMS: PostgreSQL ──────────────────────────────────────────
    "postgresql": {
        "10": "2022-11-10",
        "11": "2023-11-09",   # ✗ EoS
        "12": "2024-11-14",   # ✗ EoS
        "13": "2025-11-13",   # ✗ EoS
        "14": None,            # Active until 2026-11-12
        "15": None,            # Active until 2027-11-11
        "16": None,            # Active until 2028-11-09
        "17": None,            # Active until 2029-11-08
    },

    # ── DBMS: MSSQL ───────────────────────────────────────────────
    "mssql": {
        "2008":   "2019-07-09",
        "2008r2": "2019-07-09",
        "2012":   "2022-07-12",   # ✗ EoS
        "2014":   "2024-07-09",   # ✗ EoS
        "2016":   "2026-07-14",   # ⚠ EoS 임박 (3주 후)
        "2017":   None,            # Active until 2027-10-12
        "2019":   None,            # Active until 2030-01-08
        "2022":   None,            # Active until 2033-01-11
    },
    "sqlserver": {  # alias
        "2012": "2022-07-12",
        "2014": "2024-07-09",
        "2016": "2026-07-14",
        "2017": None,
        "2019": None,
        "2022": None,
    },

    # ── Web Server: Apache ────────────────────────────────────────
    "apache": {
        "2.2": "2017-12-31",   # ✗ EoS
        "2.4": None,            # Active
    },
    "httpd": {  # alias
        "2.2": "2017-12-31",
        "2.4": None,
    },

    # ── Web Server: Nginx ─────────────────────────────────────────
    "nginx": {
        "1.14": "2020-04-14",
        "1.16": "2021-05-25",
        "1.18": "2022-05-24",
        "1.20": "2023-05-23",
        "1.22": "2024-08-13",
        "1.24": None,            # Active (stable)
        "1.26": None,            # Active (stable)
        "1.27": None,            # Active (mainline)
    },

    # ── WAS: Tomcat ───────────────────────────────────────────────
    "tomcat": {
        "6":  "2016-12-31",
        "7":  "2021-03-31",
        "8.0": "2018-06-30",
        "8.5": "2024-03-31",   # ✗ EoS
        "9":  None,             # Active until 2026-12-31 (check)
        "9.0": None,
        "10": None,
        "10.1": None,           # Active
        "11": None,
        "11.0": None,           # Active
    },

    # ── WAS: JEUS ─────────────────────────────────────────────────
    "jeus": {
        "5":  "2016-12-31",   # ✗ EoS
        "6":  "2019-12-31",   # ✗ EoS
        "7":  "2022-12-31",   # ✗ EoS
        "8":  None,            # Active (TmaxSoft 정책 따름)
    },

    # ── WAS: WebtoB ───────────────────────────────────────────────
    "webtob": {
        "3": "2016-12-31",
        "4": "2019-12-31",
        "5": None,             # Active
    },

    # ── Network: Cisco IOS-XE ─────────────────────────────────────
    "cisco-ios-xe": {
        "16.6":  "2022-08-31",
        "16.9":  "2023-02-28",
        "16.12": "2023-08-31",
        "17.3":  "2024-08-31",
        "17.6":  "2026-03-31",   # ✗ EoS
        "17.9":  "2025-08-31",   # ✗ EoS
        "17.10": "2026-07-31",   # ⚠ EoS 임박 (1개월 후)
        "17.12": None,            # Active (until ~2027-03)
        "17.15": None,            # Active (until ~2028-03)
        "17.17": "2026-03-31",   # ✗ EoS
        "17.18": None,            # Active (현재 권장)
    },

    # ── Network: Cisco IOS (Classic) ──────────────────────────────
    "cisco-ios": {
        "12.0": "2015-01-12",
        "12.1": "2015-01-12",
        "12.2": "2016-04-29",
        "12.3": "2015-08-31",
        "12.4": "2018-06-29",
        "15.0": "2019-07-31",
        "15.1": "2022-08-31",
        "15.2": "2023-03-31",
        "15.4": "2022-10-31",
        "15.5": "2023-06-30",
        "15.6": "2023-04-29",
        "15.7": None,             # check - may still be active
        "15.8": None,
        "15.9": None,
    },

    # ── Network: Cisco ASA ────────────────────────────────────────
    "cisco-asa": {
        "9.8":  "2022-09-30",
        "9.12": "2024-03-31",
        "9.14": "2024-09-30",
        "9.16": None,
        "9.18": None,
        "9.20": None,
    },

    # ── Network: Juniper Junos ────────────────────────────────────
    "junos": {
        "18": "2023-10-31",
        "20": "2024-10-31",
        "21": "2025-10-31",   # ✗ EoS
        "22": None,
        "23": None,
        "24": None,
    },
}

# ================================================================
# endoflife.date API 조회 (인터넷 연결 시)
# ================================================================
EOLDATE_PRODUCTS = {
    "rhel":        "rhel",
    "centos":      "centos",
    "ubuntu":      "ubuntu",
    "debian":      "debian",
    "oracle":      "oracle-database",
    "mysql":       "mysql",
    "mariadb":     "mariadb",
    "postgresql":  "postgresql",
    "mssql":       "mssqlserver",
    "sqlserver":   "mssqlserver",
    "apache":      "apache",
    "nginx":       "nginx",
    "tomcat":      "tomcat",
    "cisco-ios-xe":"cisco-ios-xe",
}

def query_eoldate_api(product: str, version: str) -> tuple:
    """endoflife.date API 조회"""
    if not HAS_URLLIB:
        return None, None
    slug = EOLDATE_PRODUCTS.get(product.lower())
    if not slug:
        return None, None
    url = f"https://endoflife.date/api/{slug}/{version}.json"
    try:
        req = Request(url, headers={"Accept": "application/json", "User-Agent": "eos-checker/1.0"})
        resp = urlopen(req, timeout=3)
        data = json.loads(resp.read().decode())
        eol  = data.get("eol") or data.get("endOfLife")
        if eol is False:  # eol=false means still active
            return True, None   # (is_active, eol_date)
        elif isinstance(eol, str):
            return False, eol   # (is_active, eol_date)
    except Exception:
        pass
    return None, None


# ================================================================
# 버전 정규화 및 매칭
# ================================================================
def normalize_version(v: str) -> str:
    """버전 문자열 정규화"""
    if not v:
        return ""
    v = v.strip().lower()
    # 11g r2 → 11g, 12c r1 → 12c
    v = re.sub(r'\s+r[12]$', '', v)
    # IOS-XE 17.12.06 → 17.12
    m = re.match(r'^(\d+\.\d+)', v)
    if m:
        return m.group(1)
    return v

def get_version_prefix(version: str) -> list:
    """버전에서 매칭 가능한 prefix 목록 반환 (긴 것 우선)"""
    v = normalize_version(version)
    prefixes = []
    # 정규화 버전 그대로
    prefixes.append(v)
    # 주 버전만 (major)
    m = re.match(r'^(\d+)', v)
    if m:
        prefixes.append(m.group(1))
    # major.minor
    m = re.match(r'^(\d+\.\d+)', v)
    if m and m.group(1) != v:
        prefixes.append(m.group(1))
    return prefixes

def check_eos(product: str, version: str, use_api: bool = True) -> tuple:
    """
    EoS 판정
    반환: (결과, EoS_일자_또는_None, 설명)
    """
    product_lower = product.lower().strip()
    version_lower = version.lower().strip()

    # 1. API 조회 시도
    if use_api:
        try:
            is_active, eol_date = query_eoldate_api(product_lower, normalize_version(version_lower))
            if is_active is True:
                return RESULT_GOOD, None, f"{product} {version} 지원 기간 내 (endoflife.date 확인)"
            elif is_active is False and eol_date:
                try:
                    eol = datetime.date.fromisoformat(eol_date)
                    if eol < CHECK_DATE:
                        days = (CHECK_DATE - eol).days
                        return RESULT_BAD, eol_date, f"{product} {version} EoS {days}일 경과 ({eol_date})"
                    else:
                        days = (eol - CHECK_DATE).days
                        return RESULT_GOOD, eol_date, f"{product} {version} EoS {days}일 남음 ({eol_date})"
                except ValueError:
                    pass
        except Exception:
            pass

    # 2. 하드코딩 DB 조회
    db_entry = None
    for key in EOS_DB:
        if product_lower in key or key in product_lower:
            db_entry = EOS_DB[key]
            break

    if db_entry is None:
        return RESULT_MANUAL, None, f"{product} {version} EoS 정보 없음 - 벤더 사이트 수동 확인"

    # 버전 매칭 (긴 prefix 우선)
    prefixes = get_version_prefix(version_lower)
    eol_str = None
    matched_key = None

    for pfx in prefixes:
        # 직접 매칭
        if pfx in db_entry:
            eol_str  = db_entry[pfx]
            matched_key = pfx
            break
        # 부분 매칭 (major.minor prefix)
        for k in sorted(db_entry.keys(), key=len, reverse=True):
            if pfx.startswith(k) or k.startswith(pfx):
                eol_str  = db_entry[k]
                matched_key = k
                break
        if matched_key:
            break

    if matched_key is None:
        return RESULT_MANUAL, None, f"{product} {version} 버전 정보 DB 없음 - 수동 확인"

    # eol_str = None → 현역
    if eol_str is None:
        return RESULT_GOOD, None, f"{product} {version} 지원 기간 내 (하드코딩 DB)"

    # EoS 날짜 파싱
    for fmt in ("%Y-%m-%d", "%Y-%m", "%Y"):
        try:
            if fmt == "%Y-%m":
                eol = datetime.date.fromisoformat(eol_str + "-01")
            elif fmt == "%Y":
                eol = datetime.date.fromisoformat(eol_str + "-01-01")
            else:
                eol = datetime.date.fromisoformat(eol_str)
            break
        except ValueError:
            eol = None

    if eol is None:
        return RESULT_MANUAL, eol_str, f"{product} {version} EoS 날짜 파싱 실패: {eol_str}"

    if eol < CHECK_DATE:
        days = (CHECK_DATE - eol).days
        if days <= 180:
            return RESULT_BAD, eol_str, f"{product} {version} EoS {days}일 경과 ({eol_str}) ⚠ 최근 종료"
        else:
            return RESULT_BAD, eol_str, f"{product} {version} EoS 종료 ({eol_str}, {days//365}년 {days%365//30}개월 경과)"
    else:
        days = (eol - CHECK_DATE).days
        if days <= 90:
            return RESULT_MANUAL, eol_str, f"{product} {version} EoS {days}일 남음 ({eol_str}) ⚠ 임박"
        else:
            return RESULT_GOOD, eol_str, f"{product} {version} 지원 기간 내 (EoS: {eol_str})"


# ================================================================
# 시스템 자동 탐지 헬퍼 (bash 스크립트에서 호출용)
# ================================================================
def detect_and_check(product: str, version: str) -> str:
    """결과를 파이프 포맷으로 반환"""
    result, eol_date, desc = check_eos(product, version)
    return f"{result}|{desc}"


# ================================================================
# 일괄 점검 (운영 시스템 전체 검사용)
# ================================================================
def batch_check(items: list) -> list:
    """
    items: [(product, version, item_code), ...]
    반환: [(item_code, result, eol_date, desc), ...]
    """
    results = []
    for product, version, code in items:
        result, eol_date, desc = check_eos(product, version)
        results.append((code, result, eol_date, desc))
    return results


# ================================================================
# CLI
# ================================================================
if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("사용법: python eos_checker.py <제품> <버전>")
        print("예시:")
        print("  python eos_checker.py oracle 19c")
        print("  python eos_checker.py mysql 8.0")
        print("  python eos_checker.py rhel 7")
        print("  python eos_checker.py ubuntu 20.04")
        print("  python eos_checker.py cisco-ios-xe 17.9")
        print("  python eos_checker.py mssql 2016")
        print("  python eos_checker.py tomcat 8.5")
        print()
        # 전체 현황 출력
        print("=" * 65)
        print(f"  EoS 전체 현황 ({CHECK_DATE} 기준)")
        print("=" * 65)
        all_items = []
        for prod, versions in EOS_DB.items():
            for ver, eol in sorted(versions.items()):
                if eol:
                    try:
                        d = datetime.date.fromisoformat(eol + ("-01" if len(eol)==7 else "") + ("-01" if len(eol)==4 else ""))
                        if d >= datetime.date(2020, 1, 1):
                            all_items.append((prod, ver, eol, d))
                    except: pass
        all_items.sort(key=lambda x: x[3], reverse=True)
        for prod, ver, eol, d in all_items[:30]:
            passed = d < CHECK_DATE
            flag = "✗ EoS" if passed else ("⚠ 임박" if (d - CHECK_DATE).days <= 90 else "  예정")
            print(f"  {flag}  {prod:20} {ver:12} → {eol}")
        sys.exit(0)

    product = sys.argv[1]
    version = sys.argv[2]
    use_api = "--no-api" not in sys.argv

    result, eol_date, desc = check_eos(product, version, use_api)

    print(f"제품:   {product} {version}")
    print(f"결과:   {result}")
    print(f"EoS:    {eol_date or 'N/A'}")
    print(f"설명:   {desc}")
