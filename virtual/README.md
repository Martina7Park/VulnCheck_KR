# 가상화 (VMware ESXi) 점검

ESXi 호스트에서 실행합니다. ESXi Shell(BusyBox ash)에는 bash가 없으므로 이 스크립트는 POSIX `sh` 문법으로만 작성되어 있습니다.

| 파일 | 실행 위치 | 용도 |
|------|-----------|------|
| `check_esxi.sh` | ESXi Shell / SSH | **ESXi 점검 스크립트**: HV-01~34, ESXi 6.5 / 6.7 / 7.0 / 8.0 |
| `run_esxi_remote.sh` | 점검자 PC (Linux·macOS·Git Bash·WSL) | 여러 대를 SSH로 한 번에 점검하고 결과·증적을 회수 |

점검 항목은 VMware vSphere 보안 구성 가이드(SCG 7/8)와 CIS ESXi 벤치마크의 호스트 설정을 서버 평가항목 분류에 맞춰 정리한 자체 항목입니다. 전자금융과 주요정보 두 기준에 공통으로 씁니다.

| 분류 | 항목 |
|------|------|
| 계정 관리 | HV-01 SSH 비활성화 · 02 ESXi Shell 비활성화 · 03 패스워드 복잡성 · 04 최대 사용 기간 · 05 재사용 제한 · 06 잠금 임계값 · 07 잠금 해제 시간 · 08 로컬 계정·권한 · 09 SSH 공개키 · 10 잠금 모드 · 11 AD 'ESX Admins'(CVE-2024-37085) |
| 서비스 관리 | 12 세션 타임아웃 · 13 SSH 보안 설정 · 14 MOB · 15 SLP(ESXiArgs) · 16 CIM · 17 SNMP · 18 방화벽·접근 IP · 19 TLS · 20 인증서 · 21 경고 배너 · 22 NTP |
| 로그 관리 | 23 원격 로그 서버 · 24 로그 영구 저장 · 25 감사 기록 |
| 패치 관리 | 26 보안 패치·EoS · 27 VIB 수용 수준 · 28 execInstalledOnly |
| 가상화 보안 | 29 가상 스위치 보안 정책 · 30 관리·vMotion 분리 · 31 iSCSI CHAP · 32 VM(VMX) 보안 설정 · 33 TPS 솔팅 · 34 BPDU 차단 |

## 실행

점검 전에 SSH를 임시로 켭니다(Host Client: 관리 > 서비스 > TSM-SSH 시작). 점검이 끝나면 다시 끕니다.

```bash
# 1) 여러 대: 점검자 PC 에서 (hosts.txt 에 한 줄에 하나씩: 10.10.0.31 / root@erpesxi02.erpsvt.local)
bash ./run_esxi_remote.sh hosts.txt          # 결과·증적 → ../converter/virtual/output/

# 2) 한 대, 업로드 없이: 점검자 PC 에서
ssh root@<ESXi> 'sh -s' < check_esxi.sh > <호스트>_esxi.txt
scp root@<ESXi>:/tmp/<호스트>_esxi_evidence.txt .

# 3) ESXi 에 올려서 실행 (결과 /tmp/<호스트>_esxi.txt 자동 저장)
sh ./check_esxi.sh
```

- ESXi 8은 기본으로 `execInstalledOnly`가 켜져 있어 `./check_esxi.sh`처럼 직접 실행하면 막힙니다. **반드시 `sh`로 실행**하십시오.
- 결과 `<호스트>_esxi.txt`와 증적 `<호스트>_esxi_evidence.txt`를 `converter/virtual/output/`에 넣고, 컨버터에서 **7. 가상화**를 고릅니다.
- vCenter Server Appliance는 대상이 아닙니다. Photon OS이므로 OS 점검은 `server/check_server.sh`로 하고, vCenter 설정은 수동으로 점검합니다.
- 분산 스위치(vDS) 포트그룹 보안 정책은 호스트에서 볼 수 없어 HV-29를 수동확인으로 둡니다. vCenter에서 확인하십시오.
- 점검이 끝나면 ESXi의 `/tmp/<호스트>_esxi*.txt`를 지웁니다. `run_esxi_remote.sh`는 증적을 회수한 뒤 대상의 증적 파일을 자동으로 지웁니다.
