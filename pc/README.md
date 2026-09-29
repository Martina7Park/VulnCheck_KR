# PC(업무용 단말) 점검

사용자 PC에서 실행합니다. **기준마다 파일이 다릅니다** — 항목코드(PC-01~18)는 같아도 뜻이 다르므로 섞지 마세요.

| OS | 전자금융 | 주요정보 (2026 가이드) |
|----|----------|------------------------|
| Windows 10/11 | `run_pc.bat` (→ `check_pc.ps1`) | `run_pc_kisa.bat` (→ `check_pc_kisa.ps1`) |
| macOS | `check_pc_mac.sh` | `check_pc_mac_kisa.sh` |
| iOS / iPadOS | `check_pc_ios.md` 수동 체크리스트 | — |

Windows 는 `.bat` 을 더블클릭하면 결과가 같은 폴더에 저장됩니다. 결과를 `converter/pc/output/` 에 넣습니다.
