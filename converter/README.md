# 컨버터 (점검자 PC)

회수한 점검 결과를 상세보고서 엑셀로 만듭니다. **이 폴더가 작업 폴더**입니다.

| 파일 | 용도 |
|------|------|
| `convert_v4.py` | **메인 — 이것 실행.** 결과 txt → 상세보고서 xlsx |
| `eos_checker.py` | EoS(지원 종료) 판정 — 컨버터가 자동 사용 |
| `kisa26_cases.json` | 2026 가이드 조치 사례 원문 — 주요정보 보고서의 보안가이드 시트 |
| `compare_results.py` | 이전·현재 보고서 비교 (`diff`) / 추세 (`trend`) |
| `check_patch.py` | 제품·버전별 CVE·패치 확인 (단독 실행) |
| `install_prereq.bat` / `.ps1` | Windows 에 Python + openpyxl 설치 |

```bash
pip install openpyxl          # 최초 1회 (Windows: install_prereq.bat)
python convert_v4.py          # 기준(전자금융/주요정보) → 대상(서버·웹WAS·DBMS·네트워크·보안장비·PC) 선택
```

이 폴더에 기준 엑셀(`전자금융기반시설_보안_취약점_평가기준(제2026-1호).xlsx`)을 두고, 결과를 아래 폴더에 넣습니다 (없으면 만드세요).

```
server/output/   webwas/output/   dbms/output/   security/output/   pc/output/   network/config/
```
