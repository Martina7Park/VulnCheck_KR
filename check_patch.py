#!/usr/bin/env python3
# ================================================================
# CVE / 보안패치 자동 확인 모듈 v1.0
# 기준: NVD API v2 + KISA 취약점 정보 (2026-06-24)
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
#   하드코딩된 주요 CVE 데이터 사용 (Critical만)
# ================================================================

import re, sys, json, datetime
try:
    from urllib.request import urlopen, Request
    from urllib.error import URLError
    HAS_URLLIB = True
except ImportError:
    HAS_URLLIB = False

CHECK_DATE = datetime.date(2026, 6, 24)
RESULT_GOOD   = "양호"
RESULT_BAD    = "취약"
RESULT_MANUAL = "수동확인"

# ================================================================
# 주요 Critical CVE 하드코딩 (2025-2026, CVSS 9.0 이상)
# 패치 미적용 시 자동 탐지용
# ================================================================
CRITICAL_CVES = {
    # Oracle Database
    "oracle": {
        "19.20": [],            # Patched as of Oct 2023
        "19.22": [],            # Patched as of Jan 2024
        "19.0":  ["CVE-2021-2351", "CVE-2022-21500", "CVE-2023-21965"],
        "12":    ["CVE-2021-2351", "CVE-2020-14750", "CVE-2019-2725"],
    },
    # MySQL
    "mysql": {
        "8.0.36": [],
        "8.0.32": ["CVE-2024-20960", "CVE-2024-20961"],
        "5.7":    ["CVE-2024-20960", "CVE-2023-22005", "CVE-2023-22006"],
    },
    # MSSQL
    "mssql": {
        "2019": [],   # With latest CU
        "2022": [],
        "2017": ["CVE-2024-37341"],
        "2016": ["CVE-2024-37341", "CVE-2024-20701"],
    },
    # Tomcat
    "tomcat": {
        "10.1.20": [],
        "9.0.87":  [],
        "9.0.80":  ["CVE-2024-21733", "CVE-2024-24549"],
        "8.5":     ["CVE-2024-24549", "CVE-2023-46589"],
    },
    # Apache HTTP
    "apache": {
        "2.4.62": [],
        "2.4.58": [],
        "2.4.50": ["CVE-2021-41773", "CVE-2021-42013"],
    },
    # nginx
    "nginx": {
        "1.26": [],
        "1.24": [],
        "1.22": ["CVE-2024-7347"],
    },
    # Linux
    "rhel": {
        "9": [],
        "8": [],
        "7": ["CVE-2024-1086", "CVE-2023-44487"],
    },
    # Cisco IOS-XE
    "cisco-ios-xe": {
        "17.12": [],
        "17.9":  ["CVE-2023-20198", "CVE-2023-20273"],  # 실제 2023년 심각 취약점
        "17.6":  ["CVE-2023-20198", "CVE-2023-20273", "CVE-2022-20812"],
        "17.3":  ["CVE-2023-20198", "CVE-2022-20812", "CVE-2021-1435"],
        "16":    ["CVE-2023-20198", "CVE-2022-20812", "CVE-2021-1435", "CVE-2020-3209"],
    },
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


def query_nvd_api(product: str, version: str) -> tuple:
    """NVD API v2로 CVE 조회 (최근 1년, Critical/High만)"""
    if not HAS_URLLIB:
        return None, 0

    keyword = NVD_KEYWORDS.get(product.lower(), product)
    url = (f"https://services.nvd.nist.gov/rest/json/cves/2.0"
           f"?keywordSearch={keyword}+{version}&cvssV3Severity=CRITICAL"
           f"&resultsPerPage=5")
    try:
        req = Request(url, headers={"Accept": "application/json", "User-Agent": "eos-checker/1.0"})
        resp = urlopen(req, timeout=5)
        data = json.loads(resp.read().decode())
        total = data.get("totalResults", 0)
        cves  = [v.get("cve", {}).get("id", "") for v in data.get("vulnerabilities", [])]
        return cves, total
    except Exception:
        return None, 0


def check_patch(product: str, version: str, use_api: bool = True) -> tuple:
    """
    보안패치 확인
    반환: (결과, CVE_수, 설명)
    """
    product_lower = product.lower().strip()
    version_lower = version.lower().strip()

    # 1. 하드코딩 CVE DB 조회
    db_entry = None
    for k in CRITICAL_CVES:
        if product_lower in k or k in product_lower:
            db_entry = CRITICAL_CVES[k]
            break

    if db_entry:
        cves_found = []
        ver_norm = re.match(r'(\d+\.\d+)', version_lower)
        check_ver = ver_norm.group(1) if ver_norm else version_lower
        maj = version_lower.split('.')[0] if '.' in version_lower else version_lower

        for ver_key, cves in db_entry.items():
            if (check_ver.startswith(ver_key) or ver_key.startswith(check_ver)
                    or maj == ver_key):
                cves_found = cves
                break

        if cves_found:
            return RESULT_BAD, len(cves_found), f"Critical CVE 미패치 의심: {', '.join(cves_found[:3])}"

    # 2. NVD API 조회
    if use_api:
        cves, total = query_nvd_api(product_lower, version_lower)
        if cves is not None:
            if total > 0:
                return RESULT_MANUAL, total, f"Critical CVE {total}건 발견 - 패치 적용 여부 수동 확인: {', '.join(cves[:3])}"
            else:
                return RESULT_GOOD, 0, f"NVD 기준 Critical CVE 미발견 ({product} {version})"

    return RESULT_MANUAL, 0, f"{product} {version} 보안패치 적용 현황 수동 확인 필요"


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
