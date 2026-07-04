#!/usr/bin/env python3
# ================================================================
# 전자금융기반시설 / 주요정보통신기반시설
# 통합 취약점 점검 컨버터 v4.0
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

import os, re, sys, datetime
import openpyxl
from openpyxl import load_workbook
from openpyxl.styles import PatternFill, Font, Alignment, Border, Side
from openpyxl.utils import get_column_letter

# ── 상수 ──────────────────────────────────────────────────────────
VERSION    = "4.0"
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
    t = text.lower()
    if re.search(r'alteon|radware|/c/sys|/cfg/sys', t): return "ALTEON"
    if re.search(r'a10networks|vthunder|acos', t):      return "A10"
    if re.search(r'ftos|dell networking|force10', t):   return "DELL"
    if re.search(r'junos|set system|set interfaces', t):return "JUNIPER"
    return "CISCO"

def detect_net_dtype(lines):
    """스위치/라우터 구분"""
    has_sw = any_m(lines, r'switchport|spanning-tree|vlan\s+\d+')
    has_rt = any_m(lines, r'ip routing|router (ospf|bgp|eigrp)|interface.*GigabitEthernet')
    if has_sw and not has_rt: return "SW"
    if has_rt and not has_sw: return "RTR"
    return "L3SW"

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

def build_net_checks(lines, text):
    """
    다중 벤더 네트워크 장비 점검
    Cisco IOS/IOS-XE / ASA / Juniper JunOS / Alteon / Dell FTOS
    NET-001~NET-059 → {code: (결과, 현황문자열)}
    """
    vendor = detect_net_vendor(text)
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

    ifaces = get_interfaces()
    has_sw_port  = any(i["switchport"] for i in ifaces)
    has_ip_intf  = any(i["has_ip"] for i in ifaces)
    # 순수 L2 스위치: switchport 있고 ip routing 없고 L3 인터페이스 없음
    is_pure_l2   = has_sw_port and not has_ip_intf and not any_m(r"^ip routing")
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
    if has_v3 and not has_comm:
        results['NET-003'] = ok(fmt(
            f"SNMP v3 전용 사용 ({fline(r'snmp-server group.*v3')})",
            "SNMP v3 인증+암호화 또는 SNMP 미사용",
            "SNMP v3 priv/auth 적용됨"
        ))
    elif pub_priv:
        results['NET-003'] = ng(fmt(
            f"기본 community 사용: {pub_priv[0]}",
            "public/private community 미사용",
            "기본 community 사용 - 즉시 변경 필요"
        ))
    elif has_comm:
        sample = has_comm[0]
        results['NET-003'] = mc(fmt(
            f"SNMPv1/v2c community 사용: {sample}",
            "SNMP v3으로 전환 권고",
            "community 문자열 강도 및 ACL 적용 수동 확인"
        ))
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
    if has_v3 and not has_comm:
        results['NET-005'] = ok(fmt("SNMP v3 priv/auth (ACL 불필요)", "v3 priv 또는 community ACL", "v3 접근통제 적용됨"))
    elif has_comm:
        comm_with_acl = find_lines(r'snmp-server community\s+\S+\s+(RO|RW)\s+\d+|snmp-server community.*access')
        comm_no_acl   = find_lines(r'snmp-server community\s+\S+\s+(RO|RW)\s*$')
        if comm_no_acl:
            results['NET-005'] = ng(fmt(
                f"ACL 미적용 community: {comm_no_acl[0]}",
                "모든 community에 ACL 적용",
                f"ACL 없는 community {len(comm_no_acl)}개 - 특정 IP만 허용하도록 ACL 설정 필요"
            ))
        elif comm_with_acl:
            results['NET-005'] = ok(fmt(
                f"community ACL 적용: {comm_with_acl[0]}",
                "community에 ACL 적용",
                "SNMP 접근 IP 제한됨"
            ))
        else:
            results['NET-005'] = mc(fmt("community ACL 설정 불명", "ACL 적용 여부 확인", "수동 확인 필요"))
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
        results['NET-007'] = ok(fmt(
            f"로컬 계정 {len(users)}개: {summary}",
            "최소 1개 이상 로컬 계정 설정 (AAA 장애 시 대체)",
            f"로컬 계정 {len(users)}개 설정됨 - 계정 적정성 수동 확인"
        ))
    else:
        results['NET-007'] = mc(fmt(
            "로컬 계정(username) 미발견",
            "AAA 장애 대비 로컬 계정 설정",
            "AAA 장애 시 접근 불가 위험 - 로컬 계정 추가 권고"
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
    elif aaa_new:
        results['NET-008'] = ng(fmt(
            "aaa new-model 설정, 외부 인증서버 미설정",
            "TACACS 또는 RADIUS 서버 연동",
            "AAA 활성화됐으나 외부 서버 없음 - 로컬 인증만 사용"
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

    if no_pw_lines:
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
        results['NET-009'] = ok(fmt(
            f"모든 로컬 계정 비밀번호 설정: {has_pw_lines[0][:60] if has_pw_lines else '확인됨'}",
            "모든 계정 비밀번호 설정",
            f"비밀번호 미설정 계정 없음 ({len(all_user_lines)}개 계정)"
        ))

    # NET-010: enable secret
    es = fline(r'enable secret')
    ep = fline(r'enable password')
    if not es and not ep:
        results['NET-010'] = ng(fmt("enable secret/password 미설정", "enable secret 설정 필수", "enable 접근 무인증 - 즉시 설정 필요"))
    elif ep and not es:
        results['NET-010'] = ng(fmt(f"{ep}", "enable password 대신 enable secret 사용", "enable password(평문/DES) 취약 - enable secret으로 교체 필요"))
    elif es:
        m = re.search(r'enable secret\s+(\d+)', es, re.I)
        t = int(m.group(1)) if m else -1
        if t in (8, 9):
            results['NET-010'] = ok(fmt(f"{es}", f"type {t} (PBKDF2/scrypt 강력 암호화)", f"enable secret type {t} - 강력한 해시 적용됨"))
        elif t == 5:
            results['NET-010'] = ng(fmt(f"{es}", "type 8/9 사용 권고 (MD5=type5 취약)", "MD5 해시(type5) - 레인보우테이블 취약, type9로 교체 필요"))
        elif t == 4:
            results['NET-010'] = ng(fmt(f"{es}", "type 8/9 사용 권고 (type4=SHA256 취약)", "type4 사용 - PBKDF2/scrypt(type8/9)로 교체 권고"))
        else:
            results['NET-010'] = ok(fmt(f"{es}", "enable secret 설정됨", "enable secret 설정됨 - 타입 확인 권고"))

    # NET-011: SSH v2
    ssh_ver = fline(r'ip ssh version\s+\d+|ssh version\s+\d+')
    if ssh_ver and re.search(r'version\s+2', ssh_ver, re.I):
        ssh_algo = find_lines(r'ip ssh server algorithm')
        algo_str = f", 알고리즘: {ssh_algo[0]}" if ssh_algo else ""
        results['NET-011'] = ok(fmt(f"{ssh_ver}{algo_str}", "SSH v2 전용 사용", "SSHv2 전용 설정됨"))
    elif ssh_ver and re.search(r'version\s+1', ssh_ver, re.I):
        results['NET-011'] = ng(fmt(f"{ssh_ver}", "ip ssh version 2 설정 필요", "SSHv1 사용 중 - 취약한 암호화"))
    elif vendor == "ASA" and any_m(r'ssh\s+\d{1,3}\.\d{1,3}'):
        results['NET-011'] = ok(fmt("ASA SSH 설정됨 (ASA는 기본 SSHv2)", "SSH 암호화 통신", "ASA SSH 활성 - SSHv2 기본 사용"))
    elif vendor == "JUNIPER" and any_m(r'ssh.*v2|set system services ssh'):
        results['NET-011'] = ok(fmt(fline(r'set system services ssh') or "Junos SSH", "SSH v2", "Junos SSH v2 사용"))
    else:
        results['NET-011'] = ng(fmt("ip ssh version 2 미설정 (SSHv1 포함 허용)", "ip ssh version 2 명시 설정", "SSHv1 허용 가능 - 설정 추가 필요"))

    # NET-012: 비밀번호 복잡도
    minlen = fline(r'security passwords min-length\s+\d+')
    if minlen:
        n = re.search(r'\d+', minlen)
        nv = int(n.group()) if n else 0
        results['NET-012'] = ok(fmt(f"{minlen}", "최소 길이 8자 이상", f"최소 {nv}자 설정됨")) if nv >= 8 else ng(fmt(f"{minlen}", "8자 이상 필요", f"최소 {nv}자 - 8자 이상 설정 필요"))
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
            results['NET-013'] = ok(fmt(
                f"{'; '.join(acl_lines)}",
                "VTY에 접근 ACL 적용",
                f"{len(acl_lines)}개 VTY 그룹 ACL 적용됨"
            ))
        else:
            results['NET-013'] = ok(fmt("모든 VTY transport input none (접속 차단)", "VTY 접근 통제", "VTY 전체 차단됨"))

    # NET-014: 세션 타임아웃
    vty_blocks = get_vty_blocks(lines)
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
                elif total <= 600:
                    timeout_ok.append(f"{blk[0]}: exec-timeout {mins}분{secs}초")
                else:
                    timeout_issues.append(f"{blk[0]}: exec-timeout {total}초 ({total//60}분)")
            else:
                timeout_issues.append(f"{blk[0]}: exec-timeout 미설정")
        if timeout_issues:
            results['NET-014'] = ng(fmt(
                f"타임아웃 미흡: {'; '.join(timeout_issues)}",
                "세션 타임아웃 10분(600초) 이하",
                f"타임아웃 초과/미설정 VTY 존재"
            ))
        elif timeout_ok:
            results['NET-014'] = ok(fmt(
                f"{'; '.join(timeout_ok)}",
                "세션 타임아웃 10분 이하",
                f"모든 VTY 타임아웃 기준 충족"
            ))
        else:
            results['NET-014'] = ok(fmt("모든 VTY transport input none", "세션 타임아웃 설정", "VTY 차단됨"))

    # NET-015: Telnet 차단
    vty_blocks = get_vty_blocks(lines)
    if vendor in ("ALTEON",):
        ssh_on = any_m(r'sshd\s+on|/c/sys/access/sshd.*on')
        results['NET-015'] = ok(fmt("Alteon sshd on", "SSH 전용", "SSH 전용 접속")) if ssh_on else ng(fmt("Alteon SSH 미활성", "SSH 전용 사용", "Telnet 허용 가능"))
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
                if re.search(r'transport input\s+(telnet|all)', blk_str, re.I):
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
        results['NET-026'] = mc(fmt(f"no ip proxy-arp {len(no_proxy)}개 / 전체 IP 인터페이스 {len(real_ip)}개", "모든 인터페이스 적용", "일부만 적용 - 나머지 수동 확인"))
    else:
        results['NET-026'] = ng(fmt(f"no ip proxy-arp 미설정 (IP 인터페이스 {len(real_ip)}개)", "no ip proxy-arp 전체 설정", "Proxy ARP 허용 - ARP 스푸핑 위험"))

    # NET-027: Directed Broadcast (라우터만 해당)
    no_db = find_lines(r'no ip directed-broadcast')
    if is_pure_l2:
        results['NET-027'] = na(fmt("L2 스위치 - 라우팅 없음", "라우터 해당 항목", "L2 스위치 N-A"))
    elif no_db:
        results['NET-027'] = ok(fmt(f"no ip directed-broadcast: {len(no_db)}개 인터페이스", "no ip directed-broadcast 설정", "Directed Broadcast 차단됨"))
    else:
        results['NET-027'] = ng(fmt("no ip directed-broadcast 미설정", "no ip directed-broadcast 설정", "Directed Broadcast 허용 - Smurf 공격 취약"))

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

        # 9. Linux 계열 데몬 (config에 흔적 있는 경우)
        for sname, pat in [
            ("named",   "rnamebin"),
            ("postfix", "rpostfi"),
            ("radvd",   "rradv"),
            ("dhcpd",   "rdhcp"),
        ]:
            if any_m(pat):
                svc_enabled.append(sname)
                svc_detail[sname] = fline(pat) or sname

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
            ("Telnet",    r"telnet\s+on|/c/cfg/sys/access/telnet.*on"),
            ("SNMP-v1v2", r"snmp.*community"),
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
            results['NET-035'] = ok(fmt(f"{buf_asa}", "버퍼 16384 이상", f"버퍼 {size}bytes 설정됨")) if size >= 16384 else ng(fmt(f"{buf_asa}", "16384 이상 권고", f"버퍼 {size}bytes - 증가 권고"))
        else:
            results['NET-035'] = ng(fmt("logging buffer-size 미설정", "logging buffer-size 16384 이상", "버퍼 미설정"))
    else:
        buf = fline(r'logging buffered\s+')
        if buf:
            m = re.search(r'logging buffered\s+(\d+)(?:\s+(\S+))?', buf, re.I)
            size  = int(m.group(1)) if m else 0
            level = m.group(2) if m and m.group(2) else "informational"
            if size >= 16384:
                results['NET-035'] = ok(fmt(
                    f"{buf} (크기:{size}, 레벨:{level})",
                    "logging buffered 16384 이상 + 적절한 레벨",
                    f"버퍼 {size}bytes({size//1024}KB) {level} 레벨 설정됨"
                ))
            else:
                results['NET-035'] = ng(fmt(
                    f"{buf} (크기:{size})",
                    "logging buffered 16384 이상 권고",
                    f"버퍼 {size}bytes - 16384 이상으로 증가 필요"
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
        cl = fline(r'logging console\s*\S*')
        if cl:
            level = re.search(r'logging console\s+(\S+)', cl, re.I)
            lv = level.group(1) if level else "informational"
            # debugging 은 과도한 레벨
            if lv == "debugging":
                results['NET-037'] = mc(fmt(f"{cl}", "informational 이하 권고", f"레벨 {lv} - 과도한 로깅 발생 가능, 레벨 조정 검토"))
            else:
                results['NET-037'] = ok(fmt(f"{cl}", "콘솔 로그 레벨 설정", f"콘솔 로그 레벨: {lv}"))
        else:
            results['NET-037'] = ng(fmt("logging console 미설정 (기본: debugging)", "logging console informational 설정", "콘솔 기본 debugging 레벨 - informational으로 제한 설정 필요"))

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
    if has_sw_port and not has_ip_intf:
        results['NET-041'] = na(fmt("스위치 전용 장비 (L2)", "라우터 해당 항목", "L2 스위치 해당 없음"))
    else:
        mc_routing = fline(r'ip multicast-routing')
        mc_intf    = find_lines(r'ip pim\s+(sparse|dense|passive)')
        if mc_routing or mc_intf:
            results['NET-041'] = mc(fmt(
                f"{mc_routing or ''} {'; '.join(mc_intf[:2])}",
                "불필요 멀티캐스트 비활성화",
                "멀티캐스트 활성 - 업무상 필요 여부 확인"
            ))
        else:
            results['NET-041'] = ok(fmt("ip multicast-routing 미설정", "불필요 멀티캐스트 비활성화", "멀티캐스트 미사용 확인됨"))

    # ──────────────────────────────────────────────────────────────
    # NET-042: ICMP 차단 (라우터만 - 스위치는 N-A)
    # ──────────────────────────────────────────────────────────────
    if has_sw_port and not has_ip_intf:
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
        results['NET-044'] = ok(fmt(f"no ip unreachables: {len(no_unrch)}개 인터페이스", "no ip unreachables 설정", "ICMP Unreachable 차단됨")) if (no_unrch or any_m(r'no ip unreachables')) else ng(fmt("no ip unreachables 미설정", "no ip unreachables 인터페이스 적용", "ICMP Unreachable 허용 - 네트워크 구조 노출"))
        results['NET-045'] = ok(fmt(f"no ip mask-reply: {len(no_mask)}개 인터페이스", "no ip mask-reply 설정", "ICMP Mask Reply 차단됨")) if (no_mask or any_m(r'no ip mask-reply')) else ng(fmt("no ip mask-reply 미설정", "no ip mask-reply 설정", "Subnet Mask 정보 노출 가능"))
        results['NET-046'] = mc(fmt("ICMP Timestamp/Information ACL", "해당 유형 차단 ACL", "ACL 내용 수동 확인"))

    # NET-047: DDoS/CoPP
    copp = find_lines(r'policy-map.*copp|class-map.*copp|ip tcp intercept|ip inspect')
    results['NET-047'] = ok(fmt(f"DoS방어: {copp[0][:60]}", "CoPP/DoS 방어 정책", "CoPP 또는 TCP Intercept 설정됨")) if copp else mc(fmt("CoPP/TCP-Intercept 미발견", "CoPP 정책 또는 IP Inspect 설정", "DDoS 방어 정책 수동 확인"))

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
        if has_warning:
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
        results['NET-052'] = ok(fmt(
            f"전체 {total}개 / 활성 {active}개(IP/L2 설정) / shutdown {shut}개",
            "미사용 인터페이스 shutdown",
            f"모든 활성 인터페이스 IP 또는 L2 설정 확인됨"
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
        if missing_54:
            results['NET-054'] = ng(fmt(
                sw_summary,
                "port-security + bpduguard + storm-control 전체 설정",
                f"스위치 보안 {len(missing_54)}개 항목 미설정 - {', '.join(missing_54)} 설정 필요"
            ))
        else:
            results['NET-054'] = ok(fmt(
                sw_summary,
                "port-security + bpduguard + storm-control 설정",
                f"스위치 보안 전체 설정됨"
            ))

    # NET-056: 비밀번호 변경 주기
    results['NET-056'] = mc(fmt("비밀번호 변경 이력", "정기적 비밀번호 변경 수행", "변경 주기 및 최근 변경일 인터뷰 확인"))

    # ──────────────────────────────────────────────────────────────
    # NET-057: 취약 서비스 비활성화 (다시 - 더 포괄적)
    # ──────────────────────────────────────────────────────────────
    weak_en  = []
    weak_dis = []

    checks_57 = [
        (r'^\s*service tcp-small-servers\b',   "tcp-small-servers"),
        (r'^\s*service udp-small-servers\b',   "udp-small-servers"),
        (r'^\s*service finger\b|^\s*ip finger', "finger"),
        (r'^\s*service pad\b',                  "PAD"),
        (r'^\s*ip bootp server\b',              "BOOTP"),
        (r'^\s*ip dns server\b',                "DNS서버"),
        (r'^\s*ip http server\b',               "HTTP"),
    ]
    for pat, name in checks_57:
        if any_m(pat):
            weak_en.append(name)
        # 명시적 비활성화 확인
        no_pat = pat.replace(r'^\s*', r'^\s*no\s+')
        if any_m(no_pat):
            weak_dis.append(name)

    # Juniper/Alteon 취약 서비스
    if vendor == "JUNIPER":
        if any_m(r'set system services telnet'): weak_en.append("Telnet(Junos)")
        if any_m(r'set system services ftp'):    weak_en.append("FTP(Junos)")
    if vendor == "ALTEON":
        if any_m(r'telnet\s+on|telnet\s+enable'): weak_en.append("Telnet(Alteon)")

    if weak_en:
        results['NET-057'] = ng(fmt(
            f"활성 취약 서비스: {', '.join(weak_en)}",
            "tcp-small-servers/udp-small-servers/finger/PAD/BOOTP/HTTP 서버 비활성화",
            f"{len(weak_en)}개 취약 서비스 활성 - 비활성화 필요: {', '.join(weak_en)}"
        ))
    else:
        results['NET-057'] = ok(fmt(
            f"취약 서비스 미발견 (명시 비활성: {', '.join(weak_dis[:4]) if weak_dis else '없음'})",
            "취약 서비스(tcp/udp-small/finger/PAD 등) 비활성화",
            "주요 취약 서비스 비활성화 확인됨"
        ))

    # NET-058: 계정 잠금
    lockout = fline(r'aaa.*lockout|login block-for\s+\d+|security authentication failure rate')
    if lockout:
        results['NET-058'] = ok(fmt(f"{lockout}", "로그인 실패 횟수 제한 설정", "계정 잠금 설정됨"))
    else:
        results['NET-058'] = ng(fmt("login block-for / authentication failure rate 미설정", "로그인 실패 시 차단 설정", "무제한 로그인 시도 허용 - 무차별 공격 취약"))

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


def detect_dbms_vendor(text):
    """DBMS 파이프 출력 헤더 → DB_COLS 키 반환 (None = 탐지 실패)"""
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
    return None


def detect_net_subtypes(text, lines):
    """네트워크 config → 적용되는 NET_COLS 키 목록 반환"""
    vendor = detect_net_vendor(text)
    dtype  = detect_net_dtype(lines)
    subs   = []
    if dtype in ("SW",  "L3SW"): subs.append("SW")
    if dtype in ("RTR", "L3SW"): subs.append("RTR")
    vendor_map = {"CISCO": "CISCO", "A10": "A10", "ALTEON": "ALTEON", "JUNIPER": "JUNIPER"}
    if vendor in vendor_map:
        subs.append(vendor_map[vendor])
    return subs


def is_applicable(item, subtype):
    """criteria_items 항목이 주어진 subtype에 해당하는지 확인"""
    applies = item.get("applies_to", {})
    if not applies:
        return True  # 세부 컬럼 없는 시트 → 전체 적용
    return applies.get(subtype, False)


# ================================================================
# 기준 엑셀 로드 및 항목 목록 추출
# ================================================================
def load_criteria(excel_path, sheet_name, mode):
    """
    기준 엑셀에서 항목 목록 로드
    mode: "EF" (전자금융) or "MI" (주요정보)
    반환: {code: {name, risk, desc, applies_to, criteria_by}}
      applies_to  : {"LINUX": True/False, ...}  ← OS/DB/장비 적용 대상 여부
      criteria_by : {"LINUX": {"기준": "...", "방법": "..."}, ...}  ← 세부 판단기준
    """
    wb = load_workbook(excel_path, read_only=True)
    ws = wb[sheet_name]
    items = {}
    col_filter = COL_EF if mode == "EF" else COL_MI

    # 시트별 세부 컬럼 매핑 선택
    if sheet_name in ("서버", "웹서버-WAS"):
        sub_cols  = OS_COLS_SRV
        crit_cols = OS_CRITERIA_SRV
    elif sheet_name == "데이터베이스":
        sub_cols  = DB_COLS
        crit_cols = DB_CRITERIA
    elif sheet_name == "네트워크 장비":
        sub_cols  = NET_COLS
        crit_cols = {}
    else:
        sub_cols  = {}
        crit_cols = {}

    for row in ws.iter_rows(min_row=5, values_only=True):
        if not row or len(row) < 2: continue
        code = str(row[COL_ID]).strip() if row[COL_ID] else ""
        if not code or code == "None" or "-" not in code: continue

        # 평가 기반 필터 (EF/MI)
        if not row[col_filter]: continue

        name  = str(row[COL_NAME]).strip() if len(row) > COL_NAME and row[COL_NAME] else ""
        risk  = row[COL_RISK] if len(row) > COL_RISK and row[COL_RISK] else ""
        desc  = str(row[COL_DESC])[:200] if len(row) > COL_DESC and row[COL_DESC] else ""

        # 세부 유형별 적용 대상 컬럼 로드 (OS/DB/장비 종류별 o 여부)
        applies_to = {}
        for sub_key, col_idx in sub_cols.items():
            applies_to[sub_key] = bool(len(row) > col_idx and row[col_idx])

        # 세부 유형별 판단기준/방법 컬럼 로드
        criteria_by = {}
        for sub_key, (c_std, c_met) in crit_cols.items():
            std = str(row[c_std])[:300] if len(row) > c_std and row[c_std] else ""
            met = str(row[c_met])[:300] if len(row) > c_met and row[c_met] else ""
            if std or met:
                criteria_by[sub_key] = {"기준": std, "방법": met}

        items[code] = {
            "name":        name,
            "risk":        risk,
            "desc":        desc,
            "applies_to":  applies_to,
            "criteria_by": criteria_by,
        }
    return items


# ================================================================
# 엑셀 결과 기입
# ================================================================
FILL = {
    RESULT_GOOD:   PatternFill("solid", fgColor="C6EFCE"),
    RESULT_BAD:    PatternFill("solid", fgColor="FFC7CE"),
    RESULT_NA:     PatternFill("solid", fgColor="EEEEEE"),
    RESULT_MANUAL: PatternFill("solid", fgColor="FFEB9C"),
}
FONT_COLOR = {
    RESULT_GOOD:   "006100",
    RESULT_BAD:    "9C0006",
    RESULT_NA:     "595959",
    RESULT_MANUAL: "9C5700",
}
FONT_NAME = "맑은 고딕"

def write_result(ws, row, col_result, col_reason, col_criteria,
                 result_val, reason, criteria_text=""):
    cell_r = ws.cell(row=row, column=col_result)
    cell_r.value = result_val
    cell_r.fill  = FILL.get(result_val, FILL[RESULT_MANUAL])
    cell_r.font  = Font(name=FONT_NAME, size=9, bold=True,
                        color=FONT_COLOR.get(result_val, "000000"))
    cell_r.alignment = Alignment(horizontal="center", vertical="center")

    if col_reason:
        cell_d = ws.cell(row=row, column=col_reason)
        existing = cell_d.value or ""
        new_val  = f"{existing}\n■ 현황\n{reason}" if existing else f"■ 현황\n{reason}"
        cell_d.value = new_val
        cell_d.alignment = Alignment(wrap_text=True, vertical="top")

    if col_criteria and criteria_text:
        ws.cell(row=row, column=col_criteria).value = criteria_text


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
    - 탐지된 유형에 해당하는 항목만 섹션별로 구분하여 기입
    - 서버별 개별 시트 + 전체 요약 시트 생성
    """
    cat_dir   = os.path.join(base_dir, "webwas")
    input_dir = os.path.join(cat_dir, "output")

    if not os.path.exists(input_dir):
        print(f"[ERROR] 입력 폴더 없음: {input_dir}"); return

    input_files = sorted(f for f in os.listdir(input_dir) if f.endswith(".txt"))
    if not input_files:
        print(f"[ERROR] {input_dir}에 .txt 파일 없음"); return

    print(f"[INFO] 기준 엑셀 로드: 웹서버-WAS")
    criteria_items = load_criteria(criteria_excel, SHEET_MAP["webwas"], mode)
    print(f"[INFO] 평가항목 {len(criteria_items)}개 로드 ({'전자금융' if mode=='EF' else '주요정보'} 기준)")

    # ── 스타일 공통 정의 ──────────────────────────────────────────
    BD  = Border(
        left=Side(style="thin", color="CCCCCC"), right=Side(style="thin", color="CCCCCC"),
        top=Side(style="thin", color="CCCCCC"),  bottom=Side(style="thin", color="CCCCCC"),
    )
    CTR = Alignment(horizontal="center", vertical="center", wrap_text=True)
    LFT = Alignment(horizontal="left",   vertical="center", wrap_text=True)
    H1F = PatternFill("solid", fgColor="1F3864")
    H2F = PatternFill("solid", fgColor="2E75B6")
    EVF = PatternFill("solid", fgColor="EEF3FA")
    ODF = PatternFill("solid", fgColor="FFFFFF")
    FN  = "맑은 고딕"

    wb = openpyxl.Workbook()
    wb.remove(wb.active)

    mode_label   = "전자금융기반시설" if mode == "EF" else "주요정보통신기반시설"
    summary_rows = []

    for fname in input_files:
        pure = os.path.splitext(fname)[0]
        text = open(os.path.join(input_dir, fname), encoding="utf-8", errors="ignore").read()

        res = parse_pipe(text)
        for code in criteria_items:
            if code not in res:
                res[code] = (RESULT_MANUAL, "스크립트 출력에 없음 (수동 확인)")

        ti   = parse_webwas_type(text)
        cats = get_webwas_categories(ti["web"], ti["was"], ti["os"])

        applicable = set()
        for cat in cats:
            applicable |= WST_CLASSIFY.get(cat, set())

        cnt = {RESULT_GOOD: 0, RESULT_BAD: 0, RESULT_NA: 0, RESULT_MANUAL: 0}
        for code in criteria_items:
            if code.upper() not in applicable: continue
            rv, _ = res.get(code, (RESULT_MANUAL, ""))
            if rv in cnt: cnt[rv] += 1

        web_disp = ti["web"].upper() if ti["web"] != "none" else "미탐지"
        was_disp = ti["was"].upper() if ti["was"] != "none" else "미탐지"

        summary_rows.append((
            pure, web_disp, was_disp,
            cnt[RESULT_GOOD], cnt[RESULT_BAD], cnt[RESULT_NA], cnt[RESULT_MANUAL]
        ))

        # ── 서버별 시트 생성 ──────────────────────────────────────
        ws = wb.create_sheet(title=pure[:31])
        ws.freeze_panes = "A9"

        # 제목
        ws.merge_cells("A1:H1")
        c = ws["A1"]
        c.value = f"{mode_label} 보안 취약점 평가 결과 [웹서버-WAS]"
        c.font = Font(name=FN, size=13, bold=True, color="FFFFFF")
        c.fill = H1F; c.alignment = CTR
        ws.row_dimensions[1].height = 28

        # 서버 정보
        for addr, val, bold in [
            ("A2","점검 대상:", True), ("B2", pure, False),
            ("D2","웹서버:",    True), ("E2", web_disp, False),
            ("F2","WAS:",       True), ("G2", was_disp, False),
        ]:
            ws[addr].value = val
            ws[addr].font  = Font(name=FN, size=9, bold=bold)
        ws.row_dimensions[2].height = 15

        ws.merge_cells("A3:H3")
        ws["A3"].value = (
            f"평가 기준: {'전자금융기반시설' if mode=='EF' else '주요정보통신기반시설'}"
            f"  |  점검일: {datetime.datetime.now().strftime('%Y-%m-%d')}"
        )
        ws["A3"].font = Font(name=FN, size=8, color="595959")
        ws.row_dimensions[3].height = 14

        # 결과 요약 (행 4~7)
        ws.merge_cells("A4:B7")
        ws["A4"].value = "결과\n요약"
        ws["A4"].font  = Font(name=FN, size=10, bold=True, color="FFFFFF")
        ws["A4"].fill  = H2F; ws["A4"].alignment = CTR; ws["A4"].border = BD

        for mr_l, mr_c, lbl, rk, bg, fg in [
            ("C4:D4","C5:D5","양호",    RESULT_GOOD,   "C6EFCE","006100"),
            ("E4:F4","E5:F5","취약",    RESULT_BAD,    "FFC7CE","9C0006"),
            ("G4:H4","G5:H5","N-A",     RESULT_NA,     "EEEEEE","595959"),
            ("C6:D6","C7:D7","수동확인", RESULT_MANUAL, "FFEB9C","9C5700"),
        ]:
            ws.merge_cells(mr_l); ws.merge_cells(mr_c)
            sl = mr_l.split(":")[0]; cl = mr_c.split(":")[0]
            ws[sl].value = lbl
            ws[sl].font  = Font(name=FN, size=9, bold=True, color=fg)
            ws[sl].fill  = PatternFill("solid", fgColor=bg)
            ws[sl].alignment = CTR; ws[sl].border = BD
            ws[cl].value = cnt[rk]
            ws[cl].font  = Font(name=FN, size=14, bold=True, color=fg)
            ws[cl].fill  = PatternFill("solid", fgColor=bg)
            ws[cl].alignment = CTR; ws[cl].border = BD
        for r in range(4, 8):
            ws.row_dimensions[r].height = 18

        # 컬럼 너비 및 헤더행
        col_cfg = [
            ("A",5,"No."),("B",14,"평가항목 ID"),("C",44,"평가항목명"),
            ("D",8,"위험도"),("E",18,"분류"),("F",12,"점검결과"),
            ("G",70,"현황 (자동기입)"),("H",20,"비고"),
        ]
        for col_l, w, hdr in col_cfg:
            ws.column_dimensions[col_l].width = w
            c = ws[f"{col_l}8"]
            c.value = hdr; c.fill = H2F; c.border = BD
            c.font  = Font(name=FN, size=9, bold=True, color="FFFFFF")
            c.alignment = CTR
        ws.row_dimensions[8].height = 20

        # ── 카테고리별 섹션 기입 ──────────────────────────────────
        cur = 9; no = 1

        for cat in cats:
            cat_codes = sorted(
                [cd for cd in criteria_items
                 if cd.upper() in WST_CLASSIFY.get(cat, set())],
                key=lambda x: int(re.search(r'\d+', x).group())
            )
            if not cat_codes:
                continue

            # 섹션 헤더 행
            lbl_text, lbl_fc, lbl_bg = WST_CATEGORY_STYLE[cat]
            ws.merge_cells(f"A{cur}:H{cur}")
            sh = ws.cell(cur, 1)
            sh.value = lbl_text
            sh.fill  = PatternFill("solid", fgColor=lbl_bg)
            sh.font  = Font(name=FN, size=9, bold=True, color=lbl_fc)
            sh.alignment = LFT; sh.border = BD
            ws.row_dimensions[cur].height = 17
            cur += 1

            # 항목 행
            for code in cat_codes:
                item = criteria_items[code]
                rv, reason = res.get(code, (RESULT_MANUAL, ""))
                rfill = EVF if no % 2 == 0 else ODF

                # No.
                c = ws.cell(cur, 1)
                c.value = no; c.fill = rfill; c.border = BD
                c.font = Font(name=FN, size=9); c.alignment = CTR

                # 항목 ID
                c = ws.cell(cur, 2)
                c.value = code; c.fill = rfill; c.border = BD
                c.font = Font(name=FN, size=9, bold=True, color="1F3864")
                c.alignment = CTR

                # 항목명
                c = ws.cell(cur, 3)
                c.value = item.get("name",""); c.fill = rfill; c.border = BD
                c.font = Font(name=FN, size=9); c.alignment = LFT

                # 위험도 (색상 구분)
                risk = item.get("risk","")
                try: rv_f = float(risk) if risk else 0
                except: rv_f = 0
                c = ws.cell(cur, 4)
                c.value = risk; c.border = BD; c.alignment = CTR
                if rv_f >= 4.0:
                    c.fill = PatternFill("solid", fgColor="FFC7CE")
                    c.font = Font(name=FN, size=9, bold=True, color="9C0006")
                elif rv_f >= 3.0:
                    c.fill = PatternFill("solid", fgColor="FFEB9C")
                    c.font = Font(name=FN, size=9, bold=True, color="9C5700")
                else:
                    c.fill = rfill; c.font = Font(name=FN, size=9)

                # 분류
                c = ws.cell(cur, 5)
                c.value = cat; c.fill = rfill; c.border = BD
                c.font = Font(name=FN, size=9, color="595959"); c.alignment = CTR

                # 점검결과
                c = ws.cell(cur, 6)
                c.value = rv
                c.fill  = FILL.get(rv, FILL[RESULT_MANUAL])
                c.font  = Font(name=FN, size=9, bold=True,
                               color=FONT_COLOR.get(rv, "000000"))
                c.alignment = CTR; c.border = BD

                # 현황
                c = ws.cell(cur, 7)
                c.value = reason; c.fill = rfill; c.border = BD
                c.font = Font(name=FN, size=9); c.alignment = LFT

                # 비고
                c = ws.cell(cur, 8)
                c.value = ""; c.fill = rfill; c.border = BD

                ws.row_dimensions[cur].height = 16
                cur += 1; no += 1

        print(f"[INFO] {pure}: 웹서버={ti['web']}, WAS={ti['was']}, {no-1}개 항목 기입")

    # ── 전체 요약 시트 ────────────────────────────────────────────
    ws = wb.create_sheet(title="전체 요약", index=0)

    ws.merge_cells("A1:J1")
    c = ws["A1"]
    c.value = f"{mode_label} 보안 취약점 평가 - 웹/WAS 점검 전체 요약"
    c.font = Font(name=FN, size=13, bold=True, color="FFFFFF")
    c.fill = H1F; c.alignment = CTR
    ws.row_dimensions[1].height = 28

    sum_hdrs = ["No.","호스트명","웹서버 유형","WAS 유형",
                "양호","취약","N-A","수동확인","합계","취약률(%)"]
    col_w    = [5, 30, 15, 12, 8, 8, 8, 10, 8, 10]
    for ci, (h, w) in enumerate(zip(sum_hdrs, col_w), 1):
        c = ws.cell(2, ci)
        c.value = h; c.fill = H2F; c.border = BD
        c.font = Font(name=FN, size=9, bold=True, color="FFFFFF")
        c.alignment = CTR
        ws.column_dimensions[get_column_letter(ci)].width = w
    ws.row_dimensions[2].height = 20

    for idx, (host, web, was_, good, bad, na, manual) in enumerate(summary_rows):
        r   = idx + 3
        tot = good + bad + na + manual
        rate = f"{bad/tot*100:.1f}%" if tot else "-"
        rfill = EVF if idx % 2 == 0 else ODF
        for ci, val in enumerate([idx+1, host, web, was_, good, bad, na, manual, tot, rate], 1):
            c = ws.cell(r, ci)
            c.value = val; c.fill = rfill; c.border = BD
            c.font = Font(name=FN, size=9); c.alignment = CTR
        if bad > 0:
            c2 = ws.cell(r, 6)
            c2.font = Font(name=FN, size=9, bold=True, color="9C0006")
            c2.fill = PatternFill("solid", fgColor="FFC7CE")
        ws.row_dimensions[r].height = 16

    # ── 저장 ─────────────────────────────────────────────────────
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    mode_str  = "전자금융" if mode == "EF" else "주요정보"
    out_path  = os.path.join(cat_dir, f"점검결과_{mode_str}_웹WAS_{timestamp}.xlsx")
    wb.save(out_path)
    print(f"\n[완료] 웹/WAS 분류 결과 저장: {out_path}")
    print(f"  총 점검 서버: {len(summary_rows)}개")


def run_eos_check(category, res, base_dir):
    """EoS 항목 자동 판정 (eos_checker.py 연동)"""
    import subprocess, os
    eos_script = os.path.join(base_dir, "eos_checker.py")
    if not os.path.exists(eos_script):
        return res

    EOS_CODES = {
        "server":  "SRV-179",
        "webwas":  "WST-126",
        "dbms":    "DBM-025",
        "network": "NET-059",
    }
    code = EOS_CODES.get(category)
    if not code:
        return res

    # 파이프 출력에서 버전/제품 정보 추출
    for item_code, (result, reason) in res.items():
        if result == RESULT_MANUAL and "EoS" in reason:
            # 버전 정보가 있으면 자동 판정 시도
            ver_m = re.search(r'(\d+\.\d+\.?\d*)', reason)
            if ver_m:
                # 제품 추정 후 판정
                prod = ""
                if "Oracle" in reason or "oracle" in reason: prod = "oracle"
                elif "MySQL" in reason or "mysql" in reason: prod = "mysql"
                elif "MSSQL" in reason or "SQL Server" in reason: prod = "mssql"
                elif "rhel" in reason.lower() or "Red Hat" in reason: prod = "rhel"
                if prod:
                    try:
                        r = subprocess.run(
                            ["python3", eos_script, prod, ver_m.group(1), "--no-api"],
                            capture_output=True, text=True, timeout=5)
                        lines = r.stdout.splitlines()
                        eos_result = next((l.split("결과:")[-1].strip() for l in lines if "결과:" in l), None)
                        eos_desc   = next((l.split("설명:")[-1].strip() for l in lines if "설명:" in l), None)
                        if eos_result:
                            res[item_code] = (eos_result, eos_desc or reason)
                    except Exception:
                        pass
    return res

def run_convert(mode, category, base_dir, criteria_excel):
    """
    mode: "EF" or "MI"
    category: "server", "webwas", "dbms", "network", "security"
    base_dir: convert/ 루트 폴더
    criteria_excel: 기준 엑셀 경로
    """
    # 웹/WAS는 유형별 자동 분류 전용 함수로 처리
    if category == "webwas":
        run_webwas_convert(mode, base_dir, criteria_excel)
        return

    cat_dir    = os.path.join(base_dir, category)
    sheet_name = SHEET_MAP.get(category, "")

    if not os.path.exists(cat_dir):
        print(f"[ERROR] 폴더 없음: {cat_dir}")
        return

    # 결과 엑셀 템플릿 찾기 (없으면 기준 엑셀로 자동 생성)
    xlsx_files = [f for f in os.listdir(cat_dir) if f.endswith(".xlsx") and not f.startswith("~$")]
    if not xlsx_files:
        print(f"[INFO] template.xlsx 없음 → 기준 엑셀로 자동 생성 중...")
        tmpl_path = auto_create_template(cat_dir, criteria_excel, sheet_name, mode)
        if not tmpl_path:
            print(f"[ERROR] 템플릿 자동 생성 실패")
            return
    else:
        tmpl_path = os.path.join(cat_dir, xlsx_files[0])

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

    input_files = [f for f in os.listdir(input_dir) if f.endswith(".txt")]
    if not input_files:
        print(f"[ERROR] {input_dir}에 .txt 파일 없음")
        return

    # 기준 엑셀에서 항목 목록 로드
    print(f"[INFO] 기준 엑셀 로드: {sheet_name}")
    criteria_items = load_criteria(criteria_excel, sheet_name, mode)
    print(f"[INFO] 평가항목 {len(criteria_items)}개 로드 완료 ({'전자금융' if mode=='EF' else '주요정보'} 기준)")

    # 각 입력 파일 파싱
    all_results = {}
    for fname in input_files:
        path  = os.path.join(input_dir, fname)
        pure  = os.path.splitext(fname)[0]
        text  = open(path, encoding="utf-8", errors="ignore").read()
        lines = text.splitlines()

        if input_mode == "pipe":
            res = parse_pipe(text)
            # OS/DB 유형 탐지 (세부 항목 N-A 판정용)
            if category == "server":
                sub_key = detect_srv_os(text)
            elif category == "dbms":
                sub_key = detect_dbms_vendor(text)
            else:
                sub_key = None
            # 파이프에 없는 항목: 해당 OS/DB 미적용 → N-A, 적용 대상 → 수동확인
            for code in criteria_items:
                if code in res: continue
                item = criteria_items[code]
                if sub_key and not is_applicable(item, sub_key):
                    res[code] = (RESULT_NA, f"현재 유형({sub_key})에 해당 없는 항목")
                else:
                    res[code] = (RESULT_MANUAL, "스크립트 출력에 없음 (수동 확인)")
        else:  # network config
            vendor = detect_net_vendor(text)
            res    = build_net_checks(lines, text)
            # criteria_items에 있지만 config 파싱에서 생성되지 않은 항목 처리
            net_subs = detect_net_subtypes(text, lines)
            for code in criteria_items:
                if code in res: continue
                item = criteria_items[code]
                if net_subs and item.get("applies_to"):
                    applicable = any(is_applicable(item, s) for s in net_subs)
                else:
                    applicable = True
                if not applicable:
                    res[code] = (RESULT_NA, f"장비 유형({', '.join(net_subs) or vendor})에 해당 없음")
                else:
                    res[code] = (RESULT_MANUAL, "config에서 자동 판단 불가 (수동 확인)")
            print(f"[INFO] {fname} → 벤더: {vendor}, 취약: {sum(1 for v in res.values() if v[0]==RESULT_BAD)}건")

        all_results[pure] = res
        total = len(res)
        bad   = sum(1 for v in res.values() if v[0] == RESULT_BAD)
        good  = sum(1 for v in res.values() if v[0] == RESULT_GOOD)
        print(f"[INFO] {fname} → 총 {total}개 / 양호 {good} / 취약 {bad}")

    # 엑셀 기입
    print(f"[INFO] 엑셀 기입 시작: {tmpl_path}")
    wb  = load_workbook(tmpl_path)
    ws  = wb.active

    # 행 → (hostname, code) 매핑 구축
    # 템플릿 엑셀 구조에 따라 컬럼 위치 조정
    # 기본: B열=항목ID, D열=Hostname
    # 결과 기입 컬럼: 점검관이 설정하는 컬럼 (L열=결과, M열=현황)
    # 실제 기준 엑셀과 별첨 엑셀 구조가 다를 수 있으므로 유연하게 처리

    # 헤더 행 탐색
    header_row = None
    id_col = None; result_col = None; reason_col = None; host_col = None

    for row_idx in range(1, min(20, ws.max_row+1)):
        for col_idx in range(1, ws.max_column+1):
            v = ws.cell(row_idx, col_idx).value
            if not v: continue
            sv = str(v).strip().lower()
            if "평가항목id" in sv or "항목id" in sv or "항목코드" in sv:
                header_row = row_idx; id_col = col_idx
            if "점검결과" in sv or "결과" in sv and result_col is None:
                result_col = col_idx
            if "현황" in sv or "근거" in sv and reason_col is None:
                reason_col = col_idx
            if "hostname" in sv or "서버명" in sv or "장비명" in sv or "ip" in sv.lower():
                host_col = col_idx

    if not header_row:
        # 기준 엑셀 자체를 쓰는 경우 (별도 결과컬럼 없음)
        # 새 컬럼 추가
        header_row = 4
        id_col     = 2   # B열
        result_col = ws.max_column + 1
        reason_col = result_col + 1
        # 결과/현황 헤더 추가
        ws.cell(header_row, result_col).value = "점검결과"
        ws.cell(header_row, reason_col).value = "점검 현황"

    data_start = (header_row or 4) + 1

    # 1. 기존 가이드라인 행 데이터 캐싱 (항목코드를 키로 저장)
    criteria_rows = {}
    for row_idx in range(data_start, ws.max_row + 1):
        code_val = ws.cell(row_idx, id_col).value if id_col else None
        if code_val:
            code = str(code_val).strip().upper()
            if code in criteria_items:
                criteria_rows[code] = [ws.cell(row_idx, col).value for col in range(1, ws.max_column + 1)]

    # 2. 템플릿에 있던 기존 빈 데이터 행들은 삭제 (아래로 새로 append하기 위함)
    if ws.max_row >= data_start:
        ws.delete_rows(data_start, ws.max_row - data_start + 1)

    # 3. 장비별 x 항목별로 행을 새로 생성하여 추가
    for hostname, res in all_results.items():
        filled = 0
        for code in criteria_items:
            if code not in criteria_rows: continue
            rt = res.get(code)
            if rt is None: continue
            
            result_val, reason = rt
            row_data = list(criteria_rows[code])
            
            if host_col and host_col <= len(row_data):
                row_data[host_col - 1] = hostname
            if result_col and result_col <= len(row_data):
                row_data[result_col - 1] = result_val
            if reason_col and reason:
                row_data[reason_col - 1] = f"[{hostname}] {reason}"

            ws.append(row_data)
            curr_row = ws.max_row
            
            if result_col:
                c = ws.cell(curr_row, result_col)
                c.fill  = FILL.get(result_val, FILL[RESULT_MANUAL])
                c.font  = Font(name=FONT_NAME, size=9, bold=True, color=FONT_COLOR.get(result_val, "000000"))
                c.alignment = Alignment(horizontal="center", vertical="center")
            if reason_col:
                c2 = ws.cell(curr_row, reason_col)
                c2.font = Font(name=FONT_NAME, size=9)
                c2.alignment = Alignment(vertical="center", wrap_text=True)
                
            filled += 1

        print(f"[INFO] {hostname}: {filled}개 항목 기입 완료")

    # 저장
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    mode_str  = "전자금융" if mode == "EF" else "주요정보"
    cat_str   = {"server":"서버","webwas":"웹WAS","dbms":"DBMS","network":"네트워크","security":"보안장비"}[category]
    out_name  = f"점검결과_{mode_str}_{cat_str}_{timestamp}.xlsx"
    out_path  = os.path.join(cat_dir, out_name)
    wb.save(out_path)
    print(f"\n[완료] 결과 저장: {out_path}")
    print(f"  총 점검 서버/장비: {len(all_results)}개")


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
    print("  1. 서버           (SRV-xxx: Linux/Unix/Windows - AIX, HP-UX, LINUX, Solaris, Windows)")
    print("  2. 웹서버/WAS     (WST-xxx: Apache, WebtoB, Tomcat, JEUS, IIS)")
    print("  3. 데이터베이스   (DBM-xxx: Oracle, MSSQL, MySQL, MariaDB, PostgreSQL, Tibero)")
    print("  4. 네트워크 장비  (NET-xxx: Cisco, A10, Alteon, Juniper)")
    print("  5. 보안장비       (ISS-xxx: FW, VPN, IDS, IPS, DDoS, WAF)")
    while True:
        sel = input("  선택 (1~5): ").strip()
        if sel == "1": category = "server";   cat_name = "서버"; break
        if sel == "2": category = "webwas";   cat_name = "웹서버/WAS"; break
        if sel == "3": category = "dbms";     cat_name = "데이터베이스"; break
        if sel == "4": category = "network";  cat_name = "네트워크 장비"; break
        if sel == "5": category = "security"; cat_name = "보안장비"; break
        print("  1~5 중 하나를 입력하세요.")

    print(f"\n[실행] {mode_name} / {cat_name} 점검 컨버팅 시작")
    print(f"  입력 폴더: {os.path.join(base_dir, category, 'output' if category != 'network' else 'config')}")
    print("-" * 60)

    run_convert(mode, category, base_dir, criteria_excel)


if __name__ == "__main__":
    main()
