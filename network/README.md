# 네트워크 장비 점검

**스크립트가 없습니다.** 장비 config 를 텍스트로 추출해 전달하면 컨버터가 직접 분석합니다.

| 장비 | config 추출 명령 | 판정 수준 |
|------|------------------|-----------|
| Cisco IOS / IOS-XE / NX-OS | `show running-config` | 자동 판정 (NX-OS 는 NX-OS 기본값 기준) |
| Cisco ASA | `show running-config` | 자동 판정 (ASA 문법 항목) + 나머지 수동확인 |
| Juniper Junos | `show configuration \| display set` (계층형 `show configuration` 도 가능) | 주요 항목 자동 판정 + 나머지 수동확인 |
| D-Link (IOS 유사 문법·네이티브 CLI) | `show running-config` / `show config current_config` (또는 웹 콘솔 백업) | 자동 판정 |
| Alteon | `/cfg/dump` | 주요 항목 자동 판정 + 나머지 수동확인 |
| A10 / Dell / Huawei 등 | `show running-config` / `display current-configuration` | 제조사 식별만 - 대부분 수동확인 |
| FRRouting(FRR)·Quagga 라우팅 데몬 | `vtysh -c "show running-config"` | 제조사 식별만 - 수동확인 (장비 보안 설정은 호스트 OS 점검 `server/` 대상) |

추출한 파일을 `<장비명>.txt` (또는 `.cfg` · `.conf` · `.log`) 로 저장해 `converter/network/config/` 에 넣습니다. 주요정보(2026 상세가이드) 변환은 전자금융 기준 엑셀이 없어도 실행됩니다 (전자금융 변환은 기준 엑셀 필요). 결과 항목: 전자금융 NET-xxx / 주요정보 N-01~38. 호스트명·OS 버전은 config 에서 읽습니다 (`hostname`, `set system host-name`, `sysname` 등).

- IOS 유사 문법 D-Link(DGS-3630)는 config 머리말로 제조사를 식별해 제조사 기본값으로 판정합니다 — Telnet·HTTP 서버 기본 활성, SSH 서버·Domain Lookup·Proxy ARP 기본 비활성, 로깅(버퍼 포함) 기본 활성, 라인 session-timeout 기본 3분. running-config 에는 기본값과 다른 설정만 나오므로 `no ip http server` 가 없으면 웹 서버가 켜진 것으로 봅니다.
- 비밀번호 값을 가리고 제출하면(`password 0` 뒤 값 없음) 비밀번호 설정·복잡성 항목은 수동확인으로 나옵니다.
- Cisco NX-OS 는 NX-OS 기본값으로 판정합니다 — enable 모드·`aaa new-model`·`tcp-keepalives` 명령 없음, Proxy ARP·Directed Broadcast 기본 비활성, 로그 타임스탬프 기본 기록, 콘솔 로깅 기본 critical, Telnet 기본 비활성.
- Cisco ASA 는 관리 접속 허용 호스트(`ssh`·`telnet`·`http <망> <마스크> <인터페이스>`), `ssh/console timeout`, `enable`·계정 비밀번호 저장 방식(encrypted=MD5 기반 / pbkdf2), `aaa authentication ... console`, `logging` 설정, `ip verify reverse-path` 로 판정하고, IOS 라우터 전용 명령 항목은 수동확인입니다.
- 외부 인터페이스 필터링 항목(NET-038~042·047, 주요정보 N-22·23)은 인터페이스·정적 경로에 공인 IP 가 없고 BGP 도 쓰지 않는 내부 장비면 수동확인입니다 (상단 경계 장비에서 확인). L2 스위치(라우팅 미사용)는 Proxy ARP·Source Routing 을 판정하지 않습니다.
- 주요정보 변환 시 전자금융 통합 항목(NET-030 불필요 서비스, NET-057 취약 서비스)의 '취약'은 실제 활성 서비스에 해당하는 가이드 항목에만 반영합니다 (예: SNMP 만 사용 중이면 웹·BOOTP·PAD 항목은 취약이 아님).
