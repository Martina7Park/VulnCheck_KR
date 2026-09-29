# 서버 점검

대상 서버에서 실행합니다. **이 폴더를 통째로 복사**하세요 (스크립트끼리 서로 호출합니다).

| 파일 | OS | 기준 | 용도 |
|------|----|------|------|
| `check_server.sh` | Linux / AIX / HP-UX / Solaris | 전자금융 · 주요정보 | **이것만 실행하면 됨** — 메뉴에서 기준 선택 (`srv` / `u` / `all`) |
| `check_server_u.sh` | Linux / Unix | 주요정보 U-01~67 | `check_server.sh` 가 호출 (단독 실행도 가능) |
| `check_server_srv.sh` | Linux / Unix | 전자금융 SRV | 전자금융 단독 실행용 |
| `run_server.bat` | Windows Server 2008 R2~2025 | 전자금융 · 주요정보 | **이것만 실행하면 됨** — 관리자 권한, 메뉴에서 기준 선택 |
| `check_server.ps1` | Windows Server | 전자금융 SRV | `run_server.bat` 가 호출 |
| `check_server_w.ps1` | Windows Server | 주요정보 W-01~64 | `run_server.bat` 가 호출 |

```bash
sudo bash ./check_server.sh > ./$(hostname)_server.txt     # Linux/Unix
```

결과(`*_server.txt`, `*_u.txt`, `*_w.txt`)와 증적(`*_evidence.txt`)을 회수해 `converter/server/output/` 에 넣습니다.
