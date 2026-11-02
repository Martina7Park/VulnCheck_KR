#!/usr/bin/env python3
# ================================================================
# CVE / 보안패치 자동 확인 모듈 v1.1
# 기준: NVD API v2 + 내장 수기 CVE 데이터 (2026-06-24)
#
# [사용법]
#   python check_patch.py oracle 19.0.0.0    # Oracle 패치 확인
#   python check_patch.py rhel 8             # OS 패치 확인
#   python check_patch.py tomcat 9.0.87      # WAS 패치 확인
#
# [출력]
#   (결과, CVE_수, 설명)
#
# [네트워크 없을 때]
#   하드코딩된 주요 CVE 데이터 사용 (Critical만, 전체 버전 구성요소 비교)
#   CVE 가 발견되지 않아도 '양호'로 판정하지 않고 '확인된 CVE 없음(데이터 기준일 표시)' + 수동확인으로 반환
# ================================================================

import re, sys, json, datetime
try:
    from urllib.request import urlopen, Request
    from urllib.parse import urlencode, quote
    from urllib.error import URLError
    HAS_URLLIB = True
except ImportError:
    HAS_URLLIB = False

CHECK_DATE = datetime.date.today()          # 판정 기준일 (실행일)
DATA_DATE  = datetime.date(2026, 6, 24)     # 내장 CVE 데이터 기준일 (학습 지식 기반 수기 데이터)
RESULT_GOOD   = "양호"
RESULT_BAD    = "취약"
RESULT_MANUAL = "수동확인"
RESULT_UNABLE = "점검불가"   # NVD 조회 실패 등 점검 자체를 수행하지 못한 경우

# ================================================================
# 주요 Critical CVE 하드코딩 (CVSS 9.0 이상 위주) — 패치 미적용 시 자동 탐지용
#   ※ 수기 데이터(학습 지식 기준)이며 '(확인 필요)' 표시는 벤더 공지로 영향 버전을 재확인할 것
#   버전 키 형식 (숫자 구성요소를 튜플로 비교 — 문자열 접두 비교 아님):
#     "A.B.C"      해당 버전 계열(접두 구성요소 일치)  예) "5.7" = 5.7.x 전체, "2.4.49" = 2.4.49 만
#     "A.B.C..X.Y.Z"  A.B.C 이상 X.Y.Z 이하 (양 끝 포함)  예) "9.0.0..9.0.85"
#   여러 키가 동시에 해당하면 CVE 를 합산한다. 영향 없음([])인 버전은 항목을 두지 않는다(조회 결과 없음 = 미해당).
# ================================================================
CRITICAL_CVES = {
    # Oracle Database (확인 필요: RU 단위로 영향이 갈리므로 19.0/12 계열 전체를 '미패치 의심'으로 표시)
    "oracle": {
        "19.0": ["CVE-2021-2351", "CVE-2022-21500", "CVE-2023-21965"],
        "12":    ["CVE-2021-2351", "CVE-2020-14750", "CVE-2019-2725"],
    },
    # MySQL (확인 필요: 8.0.35 이하 / 5.7 계열)
    "mysql": {
        "8.0.0..8.0.35": ["CVE-2024-20960", "CVE-2024-20961"],
        "5.7":           ["CVE-2024-20960", "CVE-2023-22005", "CVE-2023-22006"],
    },
    # MSSQL (연도 버전 — 최신 CU 미적용 시 해당, 확인 필요)
    "mssql": {
        "2017": ["CVE-2024-37341"],
        "2016": ["CVE-2024-37341", "CVE-2024-20701"],
    },
    # Tomcat (확인 필요: 9.0.x 는 9.0.85 이하 / 8.5.x 는 8.5.98 이하 / 10.1.x 는 10.1.18 이하가 CVE-2024-24549 영향)
    "tomcat": {
        "8.5.0..8.5.98":   ["CVE-2024-24549"],
        "9.0.0..9.0.85":   ["CVE-2024-24549"],
        "10.1.0..10.1.18": ["CVE-2024-24549"],
        "8.5.0..8.5.95":   ["CVE-2023-46589"],
        "9.0.0..9.0.82":   ["CVE-2023-46589"],
        "10.1.0..10.1.15": ["CVE-2023-46589"],
        "8.5.7..8.5.63":   ["CVE-2024-21733"],
        "9.0.0..9.0.43":   ["CVE-2024-21733"],
    },
    # Apache HTTP (2.4.49 경로 순회/RCE, 2.4.50 불완전 수정)
    "apache": {
        "2.4.49": ["CVE-2021-41773", "CVE-2021-42013"],
        "2.4.50": ["CVE-2021-42013"],
    },
    # nginx (확인 필요: CVE-2024-7347 은 mp4 모듈 사용 시 1.5.13~1.27.0 영향이나 기존 데이터 범위 유지)
    "nginx": {
        "1.22": ["CVE-2024-7347"],
    },
    # Linux
    "rhel": {
        "7": ["CVE-2024-1086", "CVE-2023-44487"],
    },
    # Cisco IOS-XE (확인 필요: CVE-2023-20198 은 웹 UI 활성 시 해당, 고정 릴리스 이전 버전)
    "cisco-ios-xe": {
        "17.9":  ["CVE-2023-20198", "CVE-2023-20273"],
        "17.6":  ["CVE-2023-20198", "CVE-2023-20273", "CVE-2022-20812"],
        "17.3":  ["CVE-2023-20198", "CVE-2022-20812", "CVE-2021-1435"],
        "16":    ["CVE-2023-20198", "CVE-2022-20812", "CVE-2021-1435", "CVE-2020-3209"],
    },
}

# 입력 제품명 별칭 → CRITICAL_CVES / NVD_KEYWORDS 키
PRODUCT_ALIASES = {
    "redhat": "rhel", "red hat": "rhel", "red-hat": "rhel",
    "httpd": "apache", "apache-http-server": "apache",
    "sqlserver": "mssql", "mssqlserver": "mssql", "sql-server": "mssql",
    "oracle-database": "oracle", "ios-xe": "cisco-ios-xe", "postgres": "postgresql",
}

# NVD API 제품명 매핑
NVD_KEYWORDS = {
    "oracle":       "oracle database",
    "mysql":        "mysql",
    "mariadb":      "mariadb",
    "postgresql":   "postgresql",
    "mssql":        "sql server",
    "sqlserver":    "sql server",
    "apache":       "apache http server",
    "nginx":        "nginx",
    "tomcat":       "apache tomcat",
    "rhel":         "red hat enterprise linux",
    "ubuntu":       "ubuntu",
    "centos":       "centos",
    "cisco-ios-xe": "cisco ios xe",
    "cisco-asa":    "cisco adaptive security appliance",
}

_BIG = 10 ** 9
LAST_NVD_ERROR = ""   # 마지막 NVD 조회 실패 사유 (점검불가 근거용)


def _canon_product(product):
    """제품명 → 내장 DB 키 (별칭 정규화 후 정확 일치, 없으면 단어 경계 포함 검사). 미등재면 None"""
    p = re.sub(r"\s+", " ", (product or "").lower().strip())
    p = PRODUCT_ALIASES.get(p, p)
    if p in CRITICAL_CVES:
        return p
    for k in CRITICAL_CVES:
        if re.search(r"(?<![a-z0-9])" + re.escape(k) + r"(?![a-z0-9])", p):
            return k
    return None


def _ver_tuple(s):
    """'8.0.32-log' → (8, 0, 32) / '2016 SP3' → (2016,) / 숫자로 시작하지 않으면 ()"""
    m = re.match(r"\s*v?(\d+(?:\.\d+)*)", str(s or "").lower())
    return tuple(int(x) for x in m.group(1).split(".")) if m else ()


def _pad(t, n, fill):
    return tuple(t) + (fill,) * (n - len(t))


def _match_spec(spec, v):
    """버전 키 spec 과 입력 버전 튜플 v 비교 → 'full'(확실히 해당) / 'partial'(패치 수준이 모자라 해당 가능성) / None"""
    if not v:
        return None
    if ".." in spec:
        lo_s, hi_s = spec.split("..", 1)
        lo, hi = _ver_tuple(lo_s), _ver_tuple(hi_s)
        n = max(len(lo), len(hi), len(v))
        v_low, v_high = _pad(v, n, 0), _pad(v, n, _BIG)
        lo_p, hi_p = _pad(lo, n, 0), _pad(hi, n, _BIG)   # hi 는 '그 계열 끝까지' 포함
        if lo_p <= v_low and v_high <= hi_p:
            return "full"
        if v_low <= hi_p and v_high >= lo_p:
            return "partial"
        return None
    fam = _ver_tuple(spec)
    if len(v) >= len(fam):
        return "full" if v[:len(fam)] == fam else None
    return "partial" if fam[:len(v)] == v else None


def lookup_local(product, version):
    """내장 CVE DB 조회 → (확실히 해당 CVE 목록, 해당 가능성 CVE 목록) ; 제품 미등재면 (None, None)"""
    key = _canon_product(product)
    if not key:
        return None, None
    v = _ver_tuple(version)
    full, part = [], []
    for spec, cves in CRITICAL_CVES[key].items():
        hit = _match_spec(spec, v)
        target = full if hit == "full" else part if hit == "partial" else None
        if target is not None:
            target.extend(c for c in cves if c not in target)
    part = [c for c in part if c not in full]
    return full, part


def query_nvd_api(product: str, version: str) -> tuple:
    """NVD API v2로 CVE 조회 (Critical 만, 최대 5건 표시).
    날짜 조건 없음: NVD 의 pubStartDate/pubEndDate 는 한 번에 최대 120일 범위라 '최근 1년'을 한 번에 조회할 수 없고,
    제품·버전 키워드 검색 특성상 과거 CVE 도 포함된다 → 결과는 참고용(수동 확인 대상)이다.
    반환: (CVE ID 목록 | None[조회 실패], 전체 건수). 실패 사유는 LAST_NVD_ERROR."""
    global LAST_NVD_ERROR
    LAST_NVD_ERROR = ""
    if not HAS_URLLIB:
        LAST_NVD_ERROR = "urllib 사용 불가"
        return None, 0

    keyword = NVD_KEYWORDS.get(product.lower(), product)
    query = urlencode({"keywordSearch": f"{keyword} {version}".strip(),
                       "cvssV3Severity": "CRITICAL", "resultsPerPage": 5}, quote_via=quote)
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?{query}"
    try:
        req = Request(url, headers={"Accept": "application/json", "User-Agent": "eos-checker/1.0"})
        with urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode())
        total = data.get("totalResults", 0)
        cves  = [v.get("cve", {}).get("id", "") for v in data.get("vulnerabilities", [])]
        return cves, total
    except Exception as e:
        LAST_NVD_ERROR = f"{type(e).__name__}: {e}"[:120]
        return None, 0


def _fmt_cves(cves, n=5):
    return ", ".join(cves[:n]) + (f" 외 {len(cves) - n}건" if len(cves) > n else "")


def check_patch(product: str, version: str, use_api: bool = True) -> tuple:
    """
    보안패치 확인
    반환: (결과, CVE_수, 설명)   결과: 취약 / 수동확인 / 점검불가  (CVE 미발견을 '양호'로 단정하지 않음)
    """
    product_lower = product.lower().strip()
    version_lower = version.lower().strip()
    tag = f"{product} {version}".strip()

    # 1. 하드코딩 CVE DB 조회 (전체 버전 튜플 비교)
    full, part = lookup_local(product_lower, version_lower)
    if full:
        extra = f" (패치 수준에 따라 추가 가능: {_fmt_cves(part, 3)})" if part else ""
        return RESULT_BAD, len(full), f"Critical CVE 미패치 의심: {_fmt_cves(full)}{extra} [내장 데이터 {DATA_DATE}]"
    if part:
        return RESULT_MANUAL, len(part), (f"{tag}: 패치 수준(전체 버전)을 알 수 없어 판정 불가 - 해당 가능 CVE {_fmt_cves(part)} "
                                          f"(정확한 버전 확인 필요) [내장 데이터 {DATA_DATE}]")

    # 2. NVD API 조회
    nvd_note = ""
    if use_api:
        cves, total = query_nvd_api(product_lower, version_lower)
        if cves is not None:
            if total > 0:
                return RESULT_MANUAL, total, f"Critical CVE {total}건 발견 - 패치 적용 여부 수동 확인: {_fmt_cves(cves, 3)} [NVD 조회 {CHECK_DATE}]"
            return (RESULT_MANUAL, 0,
                    f"확인된 CVE 없음 ({tag}, NVD 조회 {CHECK_DATE} / 내장 데이터 {DATA_DATE} 기준) - "
                    f"키워드 검색 한계가 있어 양호로 단정할 수 없음, 벤더 보안 공지로 패치 적용 여부 확인")
        nvd_note = f" (NVD 조회 실패: {LAST_NVD_ERROR})"
        if _canon_product(product_lower) is None:
            return RESULT_UNABLE, 0, f"{tag} 보안패치 점검 불가 - 내장 데이터에 없는 제품이며 NVD 조회에 실패함{nvd_note}"

    if _canon_product(product_lower) is not None and not _ver_tuple(version_lower):
        return RESULT_MANUAL, 0, f"{tag} 버전을 해석할 수 없어 내장 CVE 데이터와 비교하지 못함 - 수동 확인 필요"
    online = "NVD 조회 생략(--no-api)" if not use_api else nvd_note.strip(" ()")
    return RESULT_MANUAL, 0, (f"{tag} 보안패치 적용 현황 수동 확인 필요 - 내장 데이터({DATA_DATE})에서 해당 CVE 없음, {online}")


# ================================================================
# 서버/OS 실행 버전 자동 추출 헬퍼
# ================================================================
def extract_version_from_uname(uname_output: str) -> tuple:
    """uname -a 출력에서 OS 종류/버전 추출"""
    u = uname_output.lower()
    if "red hat" in u or "rhel" in u:
        m = re.search(r'el(\d+)', u)
        return "rhel", m.group(1) if m else "unknown"
    if "ubuntu" in u:
        m = re.search(r'ubuntu\s*(\d+\.\d+)', u)
        return "ubuntu", m.group(1) if m else "unknown"
    if "centos" in u:
        m = re.search(r'el(\d+)', u)
        return "centos", m.group(1) if m else "unknown"
    if "aix" in u:
        m = re.search(r'aix\s*(\d+)', u)
        return "aix", m.group(1) if m else "unknown"
    if "sunos" in u:
        m = re.search(r'(\d+\.\d+)', u)
        return "solaris", m.group(1) if m else "unknown"
    return "unknown", "unknown"


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("사용법: python check_patch.py <제품> <버전>")
        print("예시:")
        print("  python check_patch.py mysql 8.0")
        print("  python check_patch.py rhel 7")
        print("  python check_patch.py cisco-ios-xe 17.9")
        sys.exit(0)

    product = sys.argv[1]
    version = sys.argv[2]
    use_api = "--no-api" not in sys.argv

    result, cnt, desc = check_patch(product, version, use_api)
    print(f"제품:   {product} {version}")
    print(f"결과:   {result}")
    print(f"CVE수:  {cnt}")
    print(f"설명:   {desc}")
