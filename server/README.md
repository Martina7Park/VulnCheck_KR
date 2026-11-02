# 서버 점검

대상 서버에서 실행합니다. **이 폴더를 통째로 복사**하세요 (스크립트끼리 서로 호출합니다).

| 파일 | OS | 기준 | 용도 |
|------|----|------|------|
| `check_server.sh` | Linux / AIX / HP-UX / Solaris | 전자금융 · 주요정보 | **이것만 실행하면 됨** — 메뉴·인자로 기준 선택 (`srv` / `u` / `all`) 후 아래 스크립트 실행 |
| `check_server_srv.sh` | Linux / Unix | 전자금융 SRV | `check_server.sh` 가 호출 (단독 실행도 가능). SRV 공통 점검 코드의 원본 — 수정 후 `python tools/sync_common.py` 로 웹/WAS 사본 갱신 |
| `check_server_u.sh` | Linux / Unix | 주요정보 U-01~67 | `check_server.sh` 가 호출 (단독 실행도 가능) |
| `run_server.bat` | Windows Server 2008 R2~2025 | 전자금융 · 주요정보 | **이것만 실행하면 됨** — 관리자 권한, 메뉴에서 기준 선택 |
| `check_server.ps1` | Windows Server | 전자금융 SRV | `run_server.bat` 가 호출 (SRV 공통 점검 코드의 원본 — 웹/WAS 사본은 `tools/sync_common.py` 로 갱신) |
| `check_server_w.ps1` | Windows Server | 주요정보 W-01~64 | `run_server.bat` 가 호출 |

```bash
sudo bash ./check_server.sh > ./$(hostname)_server.txt     # Linux/Unix
```

결과(`*_server.txt`·`*_srv.txt`, `*_u.txt`, `*_w.txt`)와 증적(`*_evidence.txt`)을 회수해 `converter/server/output/` 에 넣습니다. Windows 는 결과·증적을 스크립트 폴더에 UTF-8 로 직접 저장합니다.

판정값은 양호 / 취약 / 수동확인 / **점검불가** / N-A 입니다. root(관리자)가 아니면 읽을 수 없는 항목이 점검불가로 나오므로 root(관리자)로 실행하세요. 결과 헤더에 IP·실행 계정·클라우드(보안그룹 ID) 정보가 들어갑니다.
