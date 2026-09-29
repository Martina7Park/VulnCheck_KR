# 전자금융기반시설 / 주요정보통신기반시설 취약점 점검 컨버터 v4.1

대상 시스템에서 점검 스크립트를 실행해 결과(.txt)를 만들고, 점검자 PC에서 `convert_v4.py` 로 상세보고서 엑셀을 생성하는 도구입니다.

> 실행 방법·환경변수·트러블슈팅 등 상세 내용은 [`사용설명서_v4.md`](사용설명서_v4.md) 를 참고하세요.

---

## 지원 평가 기준

| 기준 | 항목코드 | 비고 |
|------|----------|------|
| 전자금융기반시설 보안 취약점 평가기준 (제2026-1호) | SRV / WST / DBM / NET / ISS / PC | 컨버터 1단계에서 `1` 선택 |
| 주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드 (2026, 과기정통부 고시 제2025-62호) | U / W / WEB / D / N / S / PC | 컨버터 1단계에서 `2` 선택 |

두 기준은 **항목코드가 겹쳐도 의미가 다릅니다**(예: PC-01). 스크립트 실행 시 고른 기준과 컨버터에서 고른 기준을 맞추십시오. 기준이 섞인 결과는 컨버터가 걸러냅니다.

---

## 점검 스크립트

### 서버

| 대상 | 스크립트 | 전자금융 | 주요정보 (2026 가이드) |
|------|----------|----------|------------------------|
| Linux / AIX / HP-UX / Solaris | `check_server.sh` (메뉴·인자 `srv` / `u` / `all`) | `check_server.sh srv` 또는 단독 `check_server_srv.sh` → SRV-xxx | `check_server_u.sh` → U-01~67 |
| Windows Server 2008 R2~2025 | `run_server.bat` 또는 `check_server.ps1 -Mode srv\|w\|all` | `check_server.ps1` → SRV-xxx | `check_server_w.ps1` → W-01~64 |

`check_server.sh` / `check_server.ps1` 에서 주요정보를 고르면 `check_server_u.sh` / `check_server_w.ps1` 을 실행합니다. `all` 을 고르면 전자금융 결과(`<호스트>_server.txt`)와 별도로 주요정보 결과 파일이 만들어집니다 (Linux: `/tmp/<호스트>_u.txt`, Windows: 스크립트 폴더 `<호스트>_w.txt`).

### 웹서버/WAS · DBMS

한 스크립트가 두 기준을 모두 판정합니다. 인자(`ef` / `mi` / `all`)로 기준을 고르고, 인자가 없으면 메뉴가 나옵니다. 자동 실행(터미널이 아닐 때)이면 `all` 로 실행됩니다.

| 대상 | 스크립트 | 전자금융 | 주요정보 |
|------|----------|----------|----------|
| Apache / Nginx / WebtoB / Tomcat / JEUS (Linux·Unix) | `check_webwas.sh [ef\|mi\|all]` | WST-xxx | WEB-01~26 |
| IIS / Apache / Nginx / Tomcat / JEUS (Windows) | `run_webwas.bat` 또는 `check_webwas.ps1 -Mode ef\|mi\|all` | WST-xxx | WEB-01~26 |
| Oracle / MySQL / MariaDB / PostgreSQL / Tibero / MSSQL(Linux) | `check_dbms.sh [ef\|mi\|all]` (`DBMS_TYPE`, 접속 정보는 환경변수) | DBM-xxx | D-01~26 (MySQL·MariaDB·PostgreSQL 직접 판정) |
| MSSQL (Windows) | `run_dbms_mssql.bat` 또는 `check_dbms_mssql.ps1 -Mode ef\|mi\|all` | DBM-xxx | D-01~26 |

Oracle·Tibero 는 전자금융 DBM 결과를 컨버터의 주요정보 모드가 가이드 D 항목으로 변환합니다.

### PC (업무용 단말)

| 대상 | 전자금융 (자체 점검 항목) | 주요정보 |
|------|--------------------------|----------|
| Windows 10/11 | `run_pc.bat` / `check_pc.ps1` | `run_pc_kisa.bat` / `check_pc_kisa.ps1` |
| macOS 12 이상 | `check_pc_mac.sh` | `check_pc_mac_kisa.sh` |
| iOS / iPadOS | `check_pc_ios.md` (수동 체크리스트) | — |

전자금융 평가기준에는 PC 분야가 없어 PC-01~18 은 평가기준을 준용한 자체 점검 항목입니다. 주요정보 쪽은 2026 가이드 PC-01~18 입니다.

### 네트워크 장비 · 보안장비

| 대상 | 방법 | 전자금융 | 주요정보 |
|------|------|----------|----------|
| 네트워크 장비 (Cisco IOS/IOS-XE/ASA, Juniper, Alteon, A10, Dell FTOS, D-Link) | 장비 config 를 `network/config/` 에 저장 → 컨버터가 직접 파싱 ([`README_network.txt`](README_network.txt)) | NET-xxx | N-01~38 |
| 보안장비 (FortiGate, Palo Alto, 일반 / FW·VPN·IDS·IPS·DDoS·WAF) | `bash check_security.sh <config.txt> [vendor] [device_type]` (점검자 PC에서 실행) | ISS-001~043 | S-01~23 (컨버터 변환) |

---

## 보조 도구

| 파일 | 설명 |
|------|------|
| `convert_v4.py` | 메인 컨버터 (결과 .txt → 상세보고서 .xlsx) |
| `kisa26_cases.json` | 2026 가이드 '점검 및 조치 사례' 원문. 주요정보 보고서의 **보안가이드** 시트와 개선방안의 조치 명령에 쓰입니다. `convert_v4.py` 와 같은 폴더에 두어야 합니다. |
| `eos_checker.py` | OS·웹서버/WAS·DBMS·네트워크 OS 버전의 EoS(지원 종료) 판정. endoflife.date 온라인 조회를 먼저 하고, 안 되면 내장 데이터(기준일 2026-09-28)를 씁니다. `EOS_OFFLINE=1` 이면 오프라인 강제. 단독 실행: `python eos_checker.py mysql 8.0` |
| `compare_results.py` | 이전·현재 보고서 비교(`diff`), 감사 로그 기반 추세 분석(`trend`) |
| `check_patch.py` | 제품·버전별 CVE/보안 패치 확인 (단독 실행: `python check_patch.py tomcat 9.0.87`) |
| `install_prereq.bat` / `install_prereq.ps1` | 점검자 PC(Windows)에 Python + openpyxl 설치. 이미 있으면 건너뜁니다. |

---

## 사전 요구사항

- **대상 시스템:** Linux/Unix 는 bash + root 권한, Windows 는 PowerShell + 관리자 권한
- **점검자 PC:** Python 3.8 이상, openpyxl

```
pip install openpyxl
```

Windows 점검자 PC는 `install_prereq.bat` 을 더블클릭해도 됩니다.

---

## 폴더 구조 (점검자 PC)

```
컨버터/
├── convert_v4.py
├── kisa26_cases.json                  # 주요정보 보안가이드 시트용
├── eos_checker.py                     # EoS 판정 (없으면 EoS 자동 판정 생략)
├── compare_results.py
├── 전자금융기반시설_보안_취약점_평가기준(제2026-1호).xlsx   # 기준 엑셀 (필수)
│
├── server/output/        ← *_server.txt, *_u.txt, *_w.txt (+ *_evidence.txt)
├── webwas/output/        ← *_webwas.txt
├── dbms/output/          ← *_oracle.txt, *_mysql.txt, *_mssql.txt ...
├── network/config/       ← 네트워크 장비 config (여기만 config/)
├── security/output/      ← check_security.sh 결과
├── pc/output/            ← PC_*.txt, PC_KISA_*.txt
└── logs/                 ← 감사 로그 (자동 생성)
```

기준 엑셀은 파일명에 `취약점`·`평가기준` 이 들어간 `.xlsx` 면 인식합니다. 카테고리별 `template.xlsx` 가 없으면 기준 엑셀로 자동 생성합니다.

증적 파일(`*_evidence.txt`)을 결과 파일과 같은 폴더에 넣으면, 컨버터가 보고서의 근거 설명에 사용합니다.

---

## 사용 방법

### 1단계: 점검 스크립트 실행 (대상 시스템)

```bash
# Linux/Unix 서버 — 메뉴에서 기준 선택 (또는 인자 srv / u / all)
sudo bash ./check_server.sh > ./$(hostname)_server.txt

# 웹서버/WAS, DBMS — 인자 ef / mi / all
sudo bash ./check_webwas.sh all > ./$(hostname)_webwas.txt
sudo DBMS_TYPE=mysql bash ./check_dbms.sh all > ./$(hostname)_mysql.txt

# macOS PC
bash ./check_pc_mac.sh > ~/Desktop/$(hostname)_pc.txt              # 전자금융
sudo bash ./check_pc_mac_kisa.sh > ~/Desktop/PC_KISA_$(hostname -s).txt   # 주요정보
```

Windows 는 `run_server.bat` / `run_webwas.bat` / `run_dbms_mssql.bat` / `run_pc.bat` / `run_pc_kisa.bat` 을 관리자 권한으로 실행하면 결과가 스크립트 폴더에 저장됩니다.

`.sh` 스크립트는 `> 파일` 을 빠뜨려도 `/tmp/<호스트>_*.txt` 에 결과 사본을 남깁니다. **결과 파일과 증적 파일(`*_evidence.txt`)을 함께 회수**하십시오.

DBMS 접속 정보(환경변수), RDS/Aurora, 보안장비 config 추출 명령 등은 [`사용설명서_v4.md`](사용설명서_v4.md) 를 참고하세요.

### 2단계: 컨버터 실행 (점검자 PC)

결과 파일을 카테고리별 `output/` (네트워크는 `config/`) 폴더에 넣고 실행합니다.

```bash
python convert_v4.py
```

```
[1단계] 평가 기반 선택
  1. 전자금융기반시설
  2. 주요정보통신기반시설

[2단계] 점검 대상 선택
  1. 서버
  2. 웹서버/WAS
  3. 데이터베이스
  4. 네트워크 장비
  5. 보안장비
  6. PC(업무용 단말)
  7. EoS 현황
```

전자금융 스크립트 결과만 있어도 주요정보(2) 모드로 변환할 수 있습니다. 이때 판단기준이 다른 항목은 증적을 가이드 기준으로 다시 판정합니다.

### 3단계: 결과 확인

카테고리 폴더에 상세보고서가 생성됩니다.

```
webwas/상세보고서_전자금융기반시설_웹WAS_20260929_143022.xlsx
```

| 산출물 | 설명 |
|--------|------|
| 상세보고서 `.xlsx` | 표지·개요·통계·호스트별 상세 시트 |
| └ **검토·수정** 시트 | 취약·수동확인 항목 모음. 여기서 최종 판정·현황을 고치면 호스트 시트와 통계에 반영됩니다. |
| └ **보안가이드** 시트 (주요정보) | 취약·수동확인 항목의 대상 환경별 조치 명령 (가이드 원문) |
| `EoS_현황_<분야>_<일시>.txt` | 제품·버전별 EoS 대수와 호스트 목록 (메뉴 7 은 전체 분야 통합) |
| `logs/audit_*.json` | 변환 실행 이력 (`compare_results.py trend` 입력) |

### 결과 비교

```bash
python compare_results.py diff  이전결과.xlsx  현재결과.xlsx  [--host WEB-01]
python compare_results.py trend logs/
```

---

## 점검 결과 파일 형식

스크립트 출력은 파이프(|) 구분 형식입니다.

```
항목코드|결과|근거설명
SRV-069|취약|PASS_MAX_DAYS=99999 (90일 초과)
U-01|양호|PermitRootLogin no
WEB-04|취약|디렉토리 리스팅 활성화: Options Indexes (httpd.conf)
D-12|N-A|Oracle 12c R2 이후 해당 없음
```

결과값: `양호` / `취약` / `수동확인` / `N-A`

`#` 으로 시작하는 머리말(OS, 커널, 웹서버/WAS·DBMS 종류와 버전, 점검 기준)은 컨버터가 대상 분류와 EoS 판정에 사용합니다.

```
# 웹서버: apache (Apache/2.4.57)
# WAS: tomcat (Tomcat 9.0.87)
```

결과 파일은 UTF-8, CP949, UTF-16(PowerShell 5.1 `>` 리다이렉트) 모두 읽을 수 있습니다.

---

## 유의 사항

- 기준 엑셀(`전자금융기반시설_보안_취약점_평가기준(제2026-1호).xlsx`)이 `convert_v4.py` 와 같은 폴더에 있어야 합니다. 기준 엑셀과 결과 파일(`*.xlsx`, `*.txt`)은 저장소에 포함되지 않습니다(`.gitignore`).
- 전자금융용과 주요정보용 결과를 같은 `output/` 폴더에 섞어 두어도 컨버터가 선택한 기준의 코드만 사용합니다. 선택한 기준의 결과가 없으면 보고서를 만들지 않고 안내합니다.
- 점검 후 대상 시스템에서 스크립트·결과·증적 파일을 삭제하고, DB 비밀번호 환경변수를 `unset` 하십시오.
- 네트워크 장비 config 와 증적 파일에는 계정·설정 정보가 들어 있으므로 암호화해서 전달하십시오.
