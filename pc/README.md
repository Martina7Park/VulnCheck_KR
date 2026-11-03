# PC(단말) 점검

사용자 PC에서 실행하는 점검 스크립트입니다. **기준이 다른 두 스크립트를 섞어 쓰면 안 됩니다** — 항목코드(PC-01~18)는 같지만 항목의 의미가 다릅니다.

| OS | 전자금융 기준 (자체 점검 PC-01~18) | 주요정보 기준 (2026 상세가이드 PC-01~18) |
|----|----------|------------------------|
| Windows 10/11 | `run_pc.bat` (→ `check_pc.ps1`) | `run_pc_kisa.bat` (→ `check_pc_kisa.ps1`) |
| macOS | `check_pc_mac.sh` | `check_pc_mac_kisa.sh` |
| iOS / iPadOS | `check_pc_ios.md` 수동 체크리스트 (PC-01~18, 전자금융 기준) | — |

## 실행 방법과 권한

- **Windows**: `.bat` 을 더블클릭하면 관리자 권한 상승(UAC)을 요청하고, 결과를 **UTF-8** 로 저장합니다(영문 로캘 Windows 에서도 한글이 깨지지 않음). 상승을 거부하면 비관리자로 계속 진행하며, 관리자 권한이 필요한 항목(보안 정책·감사 정책·BitLocker·bcdedit·공유 ACL 등)은 `점검불가` 로 출력됩니다. PowerShell 2.0 이상에서 동작하며 cmdlet 이 없으면 WMI·net 명령으로 대체합니다.
- **macOS**: `sudo bash check_pc_mac.sh` 처럼 root 로 실행하세요. 비root 로 실행하면 시스템 데몬(launchctl)·원격 로그인(systemsetup)·암호 정책(pwpolicy)·공유 목록을 볼 수 없어 해당 항목이 `점검불가` 가 됩니다. (root 로 조회했는데 암호 정책·로그인 실패 잠금 정책이 하나도 없으면 `점검불가` 가 아니라 `취약` 입니다.) sudo 로 실행해도 화면 잠금·Safari 같은 사용자 설정은 `SUDO_USER`(없으면 콘솔 로그인 사용자) 기준으로 읽습니다.
- **macOS 지원 종료·패치 판정**: 전자금융 PC-07 / 주요정보 PC-10·PC-11 은 Apple 보안 릴리스 목록(`support.apple.com/en-us/100100`)을 `curl` 로 조회합니다. 최신 주요 버전 최초 출시 이후에도 CVE 포함 보안 업데이트를 받은 주요 버전만 '지원 중'으로 보고(Apple 은 지원 종료일을 공지하지 않음), 같은 주요 버전의 더 새 보안 릴리스가 `PATCH_GRACE_DAYS`(기본 30)일을 넘게 미적용이면 취약입니다. 조회 원자료(macOS 행과 해석 결과)는 증적에 전부 남습니다. 인터넷이 안 되거나 `curl` 이 없거나 페이지 형식이 바뀌어 해석에 실패하면 연도 기반 **추정**으로 판정하고 근거에 '추정'이라고 표시합니다(`MAC_EOS_OFFLINE=1` 이면 조회를 생략). 
- **macOS 서비스 활성 판정**: `launchctl list` 에 보이는 `com.apple.screensharing.agent`·`com.apple.RemoteDesktop.agent` 는 서비스를 꺼도 모든 사용자 세션에 항상 로드되는 보조 에이전트라 근거로 쓰지 않습니다. 화면공유·파일공유·SSH 는 `launchctl print system/<서비스>` 로드 여부 또는 포트 LISTEN(`netstat -an -p tcp`: 5900·445·548·22), 원격 관리는 `ARDAgent` 프로세스·포트 3283 으로 판정합니다. 비root 에서 system 도메인을 볼 수 없고 포트도 닫혀 있으면 `점검불가` 입니다. 공유 폴더가 정의돼 있어도 SMB/AFP 서비스가 꺼져 있으면 양호이며, 게스트 허용 설정이 남아 있으면 근거에 '재활성 시 취약'이 표시됩니다.
- **macOS 백신 판별**: 앱 이름·실행 파일 이름(경로 제외)으로만 판별합니다. `/Applications/AhnLab/ASTx`(안랩 세이프 트랜잭션, 금융 보안 모듈)는 백신이 아닙니다.
- **Windows 비밀번호 판정**: `PasswordRequired=False` 는 '빈 비밀번호 허용 플래그'일 뿐이라 단독으로 취약 처리하지 않습니다. 마지막 암호 설정일(`PasswordLastSet`)이 없으면 취약, 있으면 `수동확인`(플래그만 해제), Microsoft 계정은 Microsoft 가 비밀번호를 관리하는 계정으로 표기합니다(PS 2.0 경로는 `net user` 의 날짜로 확인, 못 읽으면 수동확인). 주요정보 PC-07(NTFS)은 USB·외장 디스크(WMI 연관 조회로 판별)의 FAT/exFAT 를 판정에서 제외하고 근거에 표시합니다.
- 결과 형식은 `PC-코드|결과|근거` 이며 결과 값은 양호 / 취약 / 수동확인 / 점검불가 / N-A 입니다. 점검 자체를 못 한 경우(권한·명령 없음·조회 실패)는 `점검불가` + 구체적 사유, 자료는 모았지만 사람이 판단해야 하면 `수동확인` 입니다.
- 결과 맨 앞 `#` 헤더에 `# IP`, `# 실행 계정`, `# 클라우드`(IMDS 2초 타임아웃: AWS/Azure/GCP/없음/미확인)가 기록됩니다.
- 판정에 쓴 원자료는 증적 파일(`<호스트명>_pc_evidence.txt` / `_pc_kisa_evidence.txt` / `_pc_mac_evidence.txt`)에 자르지 않고 남습니다 (2000줄 초과분만 생략 표시).

결과 파일(`PC_<호스트명>.txt` / `PC_KISA_<호스트명>.txt`)과 증적 파일을 함께 `converter/pc/output/` 에 넣습니다.
