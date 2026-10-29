# 네트워크 장비 점검

**스크립트가 없습니다.** 장비 config 를 텍스트로 추출해 전달하면 컨버터가 직접 분석합니다.

| 장비 | config 추출 명령 |
|------|------------------|
| Cisco IOS / IOS-XE / NX-OS | `show running-config` |
| Juniper JunOS | `show configuration \| display set` |
| D-Link | `show running-config` (또는 웹 콘솔에서 백업) |
| Alteon / A10 | `show running-config` |
| Dell FTOS | `show running-config` |

추출한 파일을 `<장비명>.txt` 로 저장해 `converter/network/config/` 에 넣습니다. 결과 항목: 전자금융 NET-xxx / 주요정보 N-01~38

- IOS 유사 문법 D-Link(DGS-3630)는 config 머리말로 제조사를 식별해 제조사 기본값으로 판정합니다 — Telnet·HTTP 서버 기본 활성, SSH 서버·Domain Lookup·Proxy ARP 기본 비활성, 로깅(버퍼 포함) 기본 활성, 라인 session-timeout 기본 3분. running-config 에는 기본값과 다른 설정만 나오므로 `no ip http server` 가 없으면 웹 서버가 켜진 것으로 봅니다.
- 비밀번호 값을 가리고 제출하면(`password 0` 뒤 값 없음) 비밀번호 설정·복잡성 항목은 수동확인으로 나옵니다.
- Cisco NX-OS 는 NX-OS 기본값으로 판정합니다 — enable 모드·`aaa new-model`·`tcp-keepalives` 명령 없음, Proxy ARP·Directed Broadcast 기본 비활성, 로그 타임스탬프 기본 기록, 콘솔 로깅 기본 critical, Telnet 기본 비활성.
- 외부 인터페이스 필터링 항목(NET-038~042·047, 주요정보 N-22·23)은 인터페이스·정적 경로에 공인 IP 가 없고 BGP 도 쓰지 않는 내부 장비면 수동확인입니다 (상단 경계 장비에서 확인). L2 스위치(라우팅 미사용)는 Proxy ARP·Source Routing 을 판정하지 않습니다.
