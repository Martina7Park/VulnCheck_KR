# 전자금융기반시설 / 주요정보통신기반시설 취약점 점검 도구 v4.1

대상 시스템에서 점검 스크립트를 실행해 결과(.txt)를 모으고, 점검자 PC에서 컨버터로 상세보고서 엑셀을 만드는 도구입니다.

- **지원 기준:** 전자금융기반시설 평가기준(제2026-1호) / 주요정보통신기반시설 상세가이드(2026)
- **상세 사용법:** [사용설명서.md](사용설명서.md)

---

## 폴더 안내

| 폴더 | 무엇에 쓰나 | 어디서 실행 | 실행할 파일 |
|------|-------------|-------------|-------------|
| [`server/`](server) | 서버 점검 (Linux·Unix / Windows Server) | 대상 서버 | `check_server.sh` / `run_server.bat` |
| [`webwas/`](webwas) | 웹서버·WAS 점검 (Apache·Nginx·WebtoB·Tomcat·JEUS·IIS) | 대상 서버 | `check_webwas.sh` / `run_webwas.bat` |
| [`dbms/`](dbms) | DBMS 점검 (Oracle·MySQL·MariaDB·PostgreSQL·Tibero·MSSQL) | DB 서버 | `check_dbms.sh` / `run_dbms_mssql.bat` |
| [`network/`](network) | 네트워크 장비 — 스크립트 없음, config 추출 안내 | 장비 콘솔 | — |
| [`security/`](security) | 보안장비 config 점검 (FortiGate·Palo Alto 등) | 점검자 PC | `check_security.sh` |
| [`pc/`](pc) | 업무용 PC 점검 (Windows·macOS·iOS) | 사용자 PC | `run_pc.bat` / `run_pc_kisa.bat` / `check_pc_mac*.sh` |
| [`converter/`](converter) | 결과 → 상세보고서 엑셀 변환, EoS 판정, 결과 비교 | 점검자 PC | `convert_v4.py` |

각 폴더를 열면 파일별 용도가 README 로 정리되어 있습니다. `.sh` 는 Linux/Unix·macOS, `.bat`·`.ps1` 은 Windows 용이며, Windows 는 `run_*.bat` 만 실행하면 됩니다.

---

## 작업 흐름

```
① 대상 시스템            ② 결과 회수                     ③ 점검자 PC
server/ webwas/ dbms/  →  결과 .txt + 증적 _evidence.txt  →  converter/<분야>/output/ 에 넣고
pc/ 스크립트 실행          (네트워크·보안장비는 config)        python convert_v4.py
                                                            → 상세보고서_<기준>_<분야>_<일시>.xlsx
```

```bash
# ① 예: Linux 서버
cd server
sudo bash ./check_server.sh > ./$(hostname)_server.txt     # 메뉴에서 전자금융 / 주요정보 / 둘 다 선택

# ③ 점검자 PC
cd converter
pip install openpyxl          # 최초 1회 (Windows: install_prereq.bat)
python convert_v4.py
```

두 기준은 항목코드가 겹쳐도 뜻이 다릅니다(예: PC-01). 스크립트에서 고른 기준과 컨버터에서 고른 기준을 맞추십시오.

---

## 유의 사항

- 기준 엑셀·결과 파일(`*.xlsx`, `*.txt`)은 저장소에 올리지 않습니다 (`.gitignore`).
- 점검 후 대상 시스템에서 스크립트·결과·증적을 삭제하고, DB 비밀번호 환경변수를 지우십시오.
- 장비 config·증적 파일에는 계정·설정 정보가 있으므로 암호화해서 전달하십시오.
