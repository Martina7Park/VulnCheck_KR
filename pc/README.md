# PC(단말) 점검

사용자 PC에서 실행하는 점검 스크립트입니다. **기준이 다른 두 스크립트를 섞어 쓰면 안 됩니다** — 항목코드(PC-01~18)는 같지만 항목의 의미가 다릅니다.

| OS | 전자금융 기준 (자체 점검 PC-01~18) | 주요정보 기준 (2026 상세가이드 PC-01~18) |
|----|----------|------------------------|
| Windows 10/11 | `run_pc.bat` (→ `check_pc.ps1`) | `run_pc_kisa.bat` (→ `check_pc_kisa.ps1`) |
| macOS | `check_pc_mac.sh` | `check_pc_mac_kisa.sh` |
| iOS / iPadOS | `check_pc_ios.md` 수동 체크리스트 (PC-01~18, 전자금융 기준) | — |

## 실행 방법과 권한

- **Windows**: `.bat` 을 더블클릭하면 관리자 권한 상승(UAC)을 요청하고, 결과를 **UTF-8** 로 저장합니다(영문 로캘 Windows 에서도 한글이 깨지지 않음). 상승을 거부하면 비관리자로 계속 진행하며, 관리자 권한이 필요한 항목(보안 정책·감사 정책·BitLocker·bcdedit·공유 ACL 등)은 `점검불가` 로 출력됩니다. PowerShell 2.0 이상에서 동작하며 cmdlet 이 없으면 WMI·net 명령으로 대체합니다.
- **macOS**: `sudo bash check_pc_mac.sh` 처럼 root 로 실행하세요. 비root 로 실행하면 시스템 데몬(launchctl)·원격 로그인(systemsetup)·암호 정책(pwpolicy)·공유 목록을 볼 수 없어 해당 항목이 `점검불가` 가 됩니다. sudo 로 실행해도 화면 잠금·Safari 같은 사용자 설정은 `SUDO_USER`(없으면 콘솔 로그인 사용자) 기준으로 읽습니다.
- 결과 형식은 `PC-코드|결과|근거` 이며 결과 값은 양호 / 취약 / 수동확인 / 점검불가 / N-A 입니다. 점검 자체를 못 한 경우(권한·명령 없음·조회 실패)는 `점검불가` + 구체적 사유, 자료는 모았지만 사람이 판단해야 하면 `수동확인` 입니다.
- 결과 맨 앞 `#` 헤더에 `# IP`, `# 실행 계정`, `# 클라우드`(IMDS 2초 타임아웃: AWS/Azure/GCP/없음/미확인)가 기록됩니다.
- 판정에 쓴 원자료는 증적 파일(`<호스트명>_pc_evidence.txt` / `_pc_kisa_evidence.txt` / `_pc_mac_evidence.txt`)에 자르지 않고 남습니다 (2000줄 초과분만 생략 표시).

결과 파일(`PC_<호스트명>.txt` / `PC_KISA_<호스트명>.txt`)과 증적 파일을 함께 `converter/pc/output/` 에 넣습니다.
