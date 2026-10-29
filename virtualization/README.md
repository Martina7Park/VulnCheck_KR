# 가상화 장비 점검 (VMware ESXi)

주요정보통신기반시설 상세가이드(2026) **11장 가상화 장비 HV-01~25** 기준으로 ESXi 호스트를 점검합니다.
ESXi 기본 셸(busybox sh)에서 그대로 실행되며, bash 등 추가 설치가 필요 없습니다.

| 파일 | 실행 위치 | 용도 |
|------|-----------|------|
| `check_hv_esxi.sh` | ESXi (SSH) | 점검 스크립트 — 결과 `HV-xx\|결과\|근거` + 증적 |
| `run_hv_esxi.sh` | 점검자 PC (Linux/macOS) | 호스트 목록의 ESXi 를 SSH 로 차례로 점검 (ESXi 에 파일 남지 않음) |
| `run_hv_esxi.bat` | 점검자 PC (Windows 10+, OpenSSH 클라이언트) | 위와 같음 |

```bash
# 한 대: 점검자 PC 에서 바로 실행 (결과+증적이 한 파일)
ssh root@<ESXi IP> 'HV_INLINE=1 sh -s' < check_hv_esxi.sh > <ESXi호스트명>_hv.txt

# 여러 대: hosts.txt 에 한 줄씩 ESXi IP/호스트명
sh run_hv_esxi.sh hosts.txt          # Windows: run_hv_esxi.bat hosts.txt
```

- 점검 전 ESXi 에서 SSH 서비스를 시작하고(호스트 > 관리 > 서비스 > TSM-SSH), 점검이 끝나면 다시 중지하십시오. SSH 를 점검 때문에 잠시 켰다면 `HV_SSH_TEMP=1`(bat 은 메뉴 1)로 실행하면 HV-12 를 양호로 판정하고 중지 안내를 남깁니다.
- 결과 `*_hv.txt` 를 `converter/virtualization/output/` 에 넣고 `convert_v4.py` → **2. 주요정보** → **7. 가상화 장비** 를 선택합니다. 가상화는 주요정보 기준 전용이며, 기준 엑셀이 없어도 변환됩니다.
- 가상 머신 설정(HV-18~21)은 등록된 VM 의 `.vmx` 를, 가상 스위치(HV-22~24)는 표준 스위치·포트 그룹과 분산 스위치 포트 정책(`net-dvs`)을 확인합니다. 분산 스위치 정책을 읽지 못하면 vCenter 에서 확인하도록 수동확인으로 남깁니다.
- vCenter·XenServer·KVM·Nutanix 는 이 스크립트 대상이 아닙니다 (가이드 절차로 수동 점검).
