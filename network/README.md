# 네트워크 장비 점검

**스크립트가 없습니다.** 장비 config 를 텍스트로 추출해 전달하면 컨버터가 직접 분석합니다.

| 장비 | config 추출 명령 |
|------|------------------|
| Cisco IOS / IOS-XE / NX-OS / ASA | `show running-config` (ASA·NX-OS 는 전용 판정) |
| Juniper JunOS | `show configuration \| display set` |
| D-Link | `show config current_config` / `show running-config` (또는 웹 콘솔에서 백업) — 고유 CLI(`create snmp community`, `create trusted_host` 등)와 IOS 계열 CLI 모두 지원 |
| Alteon / A10 | `show running-config` |
| Dell FTOS | `show running-config` |

추출한 파일을 `<장비명>.txt` 로 저장해 `converter/network/config/` 에 넣습니다. 결과 항목: 전자금융 NET-xxx / 주요정보 N-01~38
