# 가상화(하이퍼바이저) 점검

VMware ESXi 호스트에서 실행합니다. 전자금융 평가기준·주요정보 2026 상세가이드에 가상화 항목이 없어서, **VMware vSphere 보안 구성 가이드·CIS ESXi 벤치마크 기반 자체 항목 ESX-01~30** 으로 점검합니다. 두 기준 모두 같은 항목을 씁니다.

| 파일 | 대상 | 용도 |
|------|------|------|
| `check_esxi.sh` | ESXi 6.5 / 6.7 / 7.0 / 8.0 / 9.0 | **이것 실행** — ESXi Shell(busybox sh) 호환, 조회 명령만 사용 |

```bash
# 1) Host Client [관리]→[서비스]에서 TSM-SSH 를 임시로 시작한 뒤 데이터스토어에 복사
scp check_esxi.sh root@<ESXi>:/vmfs/volumes/datastore1/
# 2) 실행 → 스크립트 폴더에 <호스트>_esxi.txt + <호스트>_esxi_evidence.txt 자동 저장
ssh root@<ESXi> 'sh /vmfs/volumes/datastore1/check_esxi.sh'
# 3) 두 파일 회수 → 호스트에서 스크립트·결과 삭제, SSH 다시 중지
```

결과와 증적을 `converter/hypervisor/output/` 에 넣고 컨버터 메뉴 **7. 가상화**를 고릅니다.

- **잠금 모드(Lockdown)** 호스트: 예외 사용자(Exception Users) 계정으로 실행하거나 점검하는 동안만 해제합니다.
- **vCenter Server(VCSA)** 는 이 스크립트로 점검하지 않습니다. Photon OS 이므로 `server/check_server.sh` 로 점검합니다.
- 저장 위치를 바꾸려면 `OUT_DIR=/vmfs/volumes/datastore1/check sh check_esxi.sh` 처럼 실행합니다.

| 분야 | 항목 |
|------|------|
| 계정 관리 | ESX-01 불필요 계정 · 02 비밀번호 복잡성 · 03 최대 사용 기간 · 04 재사용 제한 · 05 계정 잠금 · 06 AD 'ESX Admins' 자동 권한(CVE-2024-37085) |
| 서비스 관리 | ESX-07 SSH · 08 ESXi Shell · 09 SLP(ESXiArgs) · 10 SNMP · 11 MOB · 12 CIM |
| 접근 통제 | ESX-13 방화벽·접근 IP 제한 · 14 잠금 모드 · 15 세션 타임아웃 · 16 경고 메시지 · 17 TLS · 18 관리망 분리 · 19 vSwitch 보안 정책 · 20 iSCSI CHAP |
| 로그 관리 | ESX-21 원격 Syslog · 22 로그 영구 저장 · 23 NTP |
| 패치 관리 | ESX-24 지원 종료(EoS) 버전 · 25 최신 보안 패치 |
| 가상화 보안 | ESX-26 VIB 허용 수준 · 27 execInstalledOnly · 28 VM 콘솔 복사·붙여넣기 · 29 메모리 페이지 공유 · 30 dvFilter |

기관 기준표에 가상화 항목이 따로 있으면 `converter/convert_v4.py` 의 `HV_ITEMS`(항목명·판단기준·조치 방법)와 이 스크립트의 판정 수치를 그 기준에 맞춰 바꾸십시오.
