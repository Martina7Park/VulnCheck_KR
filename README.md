# 전자금융기반시설 / 주요정보통신기반시설 취약점 점검 컨버터 v4.0

점검 스크립트 실행 결과(.txt)를 기준 엑셀에 자동으로 기입하는 변환 도구입니다.

---

## 지원 평가 기준

- 전자금융기반시설 보안 취약점 평가기준 (제2026-1호)
- 주요정보통신기반시설 기술적 취약점 분석 평가 방법 상세가이드

---

## 지원 점검 대상

| 구분 | 항목코드 | 지원 유형 |
|------|----------|-----------|
| 서버 | SRV-xxx | Linux (RHEL/Ubuntu/Debian), AIX, HP-UX, Solaris, Windows |
| 웹서버/WAS | WST-xxx | Apache, Nginx, WebtoB, IIS / Tomcat, JEUS |
| 데이터베이스 | DBM-xxx | Oracle, MSSQL, MySQL, MariaDB, PostgreSQL, Tibero |
| 네트워크 장비 | NET-xxx | Cisco IOS/IOS-XE, A10, Alteon, Juniper |
| 보안장비 | ISS-xxx | 방화벽, VPN, IDS/IPS, DDoS, WAF |

---

## 사전 요구사항

Python 3.8 이상 및 openpyxl 라이브러리가 필요합니다.

```
pip install openpyxl
```

---

## 폴더 구조

```
컨버터/
├── convert_v4.py                          # 메인 컨버터 (이 파일 실행)
├── check_server.sh                        # 서버 점검 스크립트 (Linux/Unix)
├── check_server.ps1                       # 서버 점검 스크립트 (Windows PowerShell)
├── check_webwas.sh                        # 웹서버/WAS 점검 스크립트
├── check_dbms.sh                          # DBMS 점검 스크립트 (Linux)
├── check_dbms_mssql.ps1                   # DBMS 점검 스크립트 (MSSQL/Windows)
├── check_patch.py                         # 패치 현황 점검 보조 스크립트
├── eos_checker.py                         # EoS(지원 종료) 자동 판정 모듈
├── 전자금융기반시설_보안_취약점_평가기준(제2026-1호).xlsx  # 기준 엑셀 (필수)
│
├── server/
│   ├── server_template.xlsx               # 결과 기입용 템플릿
│   └── output/                            # 점검 결과 txt 파일 위치
│       └── WEB-PROD-01.txt
│
├── webwas/
│   ├── webwas_template.xlsx               # 결과 기입용 템플릿
│   └── output/                            # 점검 결과 txt 파일 위치
│       └── WAS-PROD-01.txt
│
├── dbms/
│   ├── dbms_template.xlsx
│   └── output/
│       └── DB-ORA-01.txt
│
└── network/
    ├── network_template.xlsx
    └── config/                            # 네트워크 장비 config 파일 위치
        └── ISR4461-CORE-01.txt
```

---

## 사용 방법

### 1단계: 점검 스크립트 실행

점검 대상 서버에서 해당 스크립트를 실행하고 결과를 output/ 폴더에 저장합니다.

**서버 (Linux/Unix)**
```bash
bash check_server.sh > /tmp/$(hostname)_server.txt
```

**웹서버/WAS (Linux)**
```bash
bash check_webwas.sh > /tmp/$(hostname)_webwas.txt
```

**DBMS (Linux)**
```bash
bash check_dbms.sh > /tmp/$(hostname)_dbms.txt
```

**서버/DBMS (Windows PowerShell)**
```powershell
powershell -ExecutionPolicy Bypass -File check_server.ps1 > C:\Temp\hostname_server.txt
powershell -ExecutionPolicy Bypass -File check_dbms_mssql.ps1 > C:\Temp\hostname_dbms.txt
```

결과 파일(.txt)을 해당 카테고리의 `output/` 폴더 또는 `config/` 폴더에 복사합니다.

### 2단계: 컨버터 실행

```bash
python convert_v4.py
```

실행하면 순서대로 선택합니다.

```
[1단계] 평가 기준 선택
  1. 전자금융기반시설
  2. 주요정보통신기반시설

[2단계] 점검 대상 선택
  1. 서버
  2. 웹서버/WAS
  3. 데이터베이스
  4. 네트워크 장비
  5. 보안장비
```

### 3단계: 결과 확인

변환 완료 후 해당 카테고리 폴더에 Excel 파일이 생성됩니다.

```
webwas/점검결과_전자금융_웹WAS_20260630_143022.xlsx
```

---

## 점검 결과 파일 형식

스크립트 출력은 파이프(|) 구분 형식을 사용합니다.

```
항목코드|결과|근거설명
WST-023|양호|PermitRootLogin no
WST-031|취약|디렉토리 리스팅 활성화: Options Indexes (httpd.conf)
WST-044|수동확인|웹서버/WAS 기본 계정 변경 여부 수동 확인
WST-013|N-A|NFS 미사용
```

결과값: `양호` / `취약` / `수동확인` / `N-A`

---

## 웹서버/WAS 자동 분류 기능

`check_webwas.sh` 실행 결과에는 점검 시 탐지된 웹서버 및 WAS 유형이 헤더에 기록됩니다.

```
# 웹서버: apache (Apache/2.4.57)
# WAS: tomcat (Tomcat 9.0.87)
```

컨버터는 이 정보를 읽어 해당 서버에 실제 적용 가능한 항목만 자동으로 추출하고,
아래 분류에 따라 섹션별로 구분하여 Excel에 기입합니다.

| 분류 | 내용 |
|------|------|
| OS 공통 | 운영체제 공통 보안 항목 (계정/파일권한/로그 등) |
| 네트워크서비스 | SNMP, SMTP, FTP, NFS/RPC, DNS |
| Apache | Apache 웹서버 전용 항목 |
| Nginx | Nginx 웹서버 전용 항목 |
| WebtoB | WebtoB 웹서버 전용 항목 |
| IIS | IIS 웹서버 (Windows) 전용 항목 |
| Tomcat | Tomcat WAS 전용 항목 |
| JEUS | JEUS WAS 전용 항목 |
| Solaris | Solaris OS 전용 항목 |

Excel 출력은 서버별 개별 시트 + 전체 요약 시트로 구성됩니다.

---

## 네트워크 장비 config 파일

네트워크 장비는 `check_*` 스크립트 대신 장비 config 파일을 직접 사용합니다.
`network/config/` 폴더에 장비명.txt 형태로 저장하면 벤더(Cisco/Juniper/Alteon/A10)를
자동으로 탐지하여 분석합니다.

---

## EoS(지원 종료) 자동 판정

`eos_checker.py` 모듈이 있으면 서버/웹서버/DBMS의 버전별 EoS 여부를 자동으로 판정합니다.
버전 정보가 점검 결과에 포함되어 있을 경우 `양호` 또는 `취약`으로 자동 기입됩니다.

---

## 유의 사항

- 기준 엑셀 파일(`전자금융기반시설_보안_취약점_평가기준(제2026-1호).xlsx`)이 같은 폴더에 있어야 합니다.
- template.xlsx가 없으면 기준 엑셀을 기반으로 자동 생성합니다.
- 네트워크 대상 외 모든 카테고리는 `output/` 폴더의 `.txt` 파일을 입력으로 사용합니다.
- Windows에서는 Python 3 설치 후 명령 프롬프트(cmd) 또는 PowerShell에서 실행합니다.
