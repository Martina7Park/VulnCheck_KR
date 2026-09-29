# 전자금융기반시설 / 주요정보통신기반시설 취약점 점검 도구 v4.1

대상 시스템에서 점검 스크립트를 실행해 결과(.txt)를 모으고, 점검자 PC에서 컨버터로 상세보고서 엑셀을 만드는 도구입니다.

- **지원 기준**
  - 전자금융기반시설 보안 취약점 평가기준 (제2026-1호) — SRV / WST / DBM / NET / ISS / PC
  - 주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드 (2026) — U / W / WEB / D / N / S / PC
- **상세 사용법:** [사용설명서.md](사용설명서.md)

---

## 폴더 구성

```
├── README.md
├── 사용설명서.md               실행 방법·환경변수·트러블슈팅
│
├── scripts/                   ▶ 대상 시스템에서 실행 (폴더째 복사)
│   ├── linux/                 Linux·AIX·HP-UX·Solaris — 서버 / 웹·WAS / DBMS
│   ├── windows/               Windows Server — 서버 / IIS·웹·WAS / MSSQL (run_*.bat)
│   ├── pc/                    업무용 PC — Windows / macOS / iOS 체크리스트
│   ├── security/              보안장비 config 점검 (점검자 PC에서 실행)
│   └── network/               네트워크 장비 config 추출 안내
│
└── converter/                 ▶ 점검자 PC에서 실행 (작업 폴더)
    ├── convert_v4.py          결과 → 상세보고서 엑셀
    ├── eos_checker.py         EoS(지원 종료) 판정
    ├── kisa26_cases.json      2026 가이드 조치 사례 (보안가이드 시트)
    ├── compare_results.py     이전·현재 결과 비교 / 추세
    ├── check_patch.py         CVE·패치 확인 (단독 실행)
    └── install_prereq.bat     Python + openpyxl 설치 (Windows)
```

---

## 어떤 스크립트를 쓰나

| 대상 | 폴더 | 실행 | 기준 선택 |
|------|------|------|-----------|
| 서버 (Linux/Unix) | `scripts/linux` | `sudo bash check_server.sh` | 메뉴 또는 인자 `srv` / `u` / `all` |
| 서버 (Windows) | `scripts/windows` | `run_server.bat` (관리자) | 메뉴 1 전자금융 / 2 주요정보 / 3 둘 다 |
| 웹서버/WAS (Linux/Unix) | `scripts/linux` | `sudo bash check_webwas.sh` | 인자 `ef` / `mi` / `all` |
| 웹서버/WAS (Windows·IIS) | `scripts/windows` | `run_webwas.bat` (관리자) | 메뉴 |
| DBMS (Oracle·MySQL·MariaDB·PostgreSQL·Tibero) | `scripts/linux` | `DBMS_TYPE=mysql bash check_dbms.sh` | 인자 `ef` / `mi` / `all` |
| DBMS (MSSQL) | `scripts/windows` | `run_dbms_mssql.bat` (관리자) | 메뉴 |
| PC (Windows 10/11) | `scripts/pc` | 전자금융 `run_pc.bat` / 주요정보 `run_pc_kisa.bat` | 파일로 구분 |
| PC (macOS) | `scripts/pc` | 전자금융 `check_pc_mac.sh` / 주요정보 `check_pc_mac_kisa.sh` | 파일로 구분 |
| PC (iOS/iPadOS) | `scripts/pc` | `check_pc_ios.md` 수동 체크리스트 | — |
| 보안장비 (FortiGate·Palo Alto 등) | `scripts/security` | `bash check_security.sh <config.txt> [vendor] [type]` | 컨버터에서 선택 |
| 네트워크 장비 (Cisco·Juniper·Alteon·A10·Dell·D-Link) | `scripts/network` | 스크립트 없음 — config 추출만 | 컨버터에서 선택 |

두 기준은 항목코드가 겹쳐도 뜻이 다릅니다(예: PC-01). 스크립트에서 고른 기준과 컨버터에서 고른 기준을 맞추십시오. `all` 로 실행한 결과는 컨버터가 선택한 기준의 코드만 골라 씁니다.

---

## 빠른 시작

### 1. 대상 시스템에서 점검

```bash
cd scripts/linux
sudo bash ./check_server.sh > ./$(hostname)_server.txt
```

결과 파일과 **증적 파일(`*_evidence.txt`)을 함께 회수**합니다. Windows는 `run_*.bat` 을 관리자 권한으로 실행하면 결과가 같은 폴더에 저장됩니다.

### 2. 점검자 PC에서 변환

```bash
pip install openpyxl          # 최초 1회 (Windows: converter/install_prereq.bat)
cd converter
python convert_v4.py
```

`converter/` 에 기준 엑셀(`전자금융기반시설_보안_취약점_평가기준(제2026-1호).xlsx`)을 두고, 회수한 결과를 분야별 폴더에 넣습니다.

```
converter/
├── server/output/     webwas/output/     dbms/output/
├── security/output/   pc/output/
└── network/config/    ← 네트워크 장비 config
```

메뉴에서 **평가 기준(전자금융 / 주요정보)** 과 **점검 대상(서버·웹WAS·DBMS·네트워크·보안장비·PC·EoS 현황)** 을 고르면 분야 폴더에 `상세보고서_<기준>_<분야>_<일시>.xlsx` 가 생성됩니다.

- **검토·수정** 시트: 취약·수동확인 항목을 고치면 통계까지 반영
- **보안가이드** 시트 (주요정보): 대상 환경별 조치 명령
- `EoS_현황_*.txt`, `logs/audit_*.json` (변환 이력) 함께 생성

### 3. 이전 점검과 비교 (선택)

```bash
python compare_results.py diff  이전결과.xlsx  현재결과.xlsx
python compare_results.py trend logs/
```

---

## 결과 파일 형식

```
항목코드|결과|근거설명
SRV-069|취약|PASS_MAX_DAYS=99999 (90일 초과)
U-01|양호|PermitRootLogin no
```

결과값: `양호` / `취약` / `수동확인` / `N-A` — `#` 로 시작하는 머리말(OS·제품 버전·점검 기준)은 컨버터가 대상 분류와 EoS 판정에 씁니다.

---

## 유의 사항

- 기준 엑셀·결과 파일(`*.xlsx`, `*.txt`)은 저장소에 올리지 않습니다 (`.gitignore`).
- 점검 후 대상 시스템에서 스크립트·결과·증적을 삭제하고, DB 비밀번호 환경변수를 지우십시오.
- 장비 config·증적 파일에는 계정·설정 정보가 있으므로 암호화해서 전달하십시오.
