# 네트워크 장비 점검

**스크립트가 없습니다.** 장비 config 를 텍스트로 추출해 전달하면 컨버터가 직접 분석합니다.

| 장비 | config 추출 명령 | 컨버터 판정 방식 |
|------|------------------|------------------|
| Cisco IOS / IOS-XE | `show running-config` | IOS 문법 전체 판정 (vty·line·interface 단위) |
| Cisco ASA | `show running-config` | ASA 고유 문법 판정 (`ssh/telnet/http <IP> <마스크> <if>`, `snmp-server host`, `sysopt noproxyarp`, `aaa authentication … console`, `logging enable`) |
| Cisco NX-OS | `show running-config` | NX-OS 고유 문법 판정 (`feature telnet`, `snmp-server community … group <role>`, `snmp-server user`, `logging server`, `line vty` 의 `access-class`) |
| Juniper JunOS | `show configuration \| display set` (계층형 `show configuration` 도 가능) | set 형식으로 정규화 후 판정 (`set snmp community … authorization`, `set system services`, `set system login`, lo0 필터) |
| D-Link (DGS/DES 고유 CLI) | `show config current_config` 또는 웹 콘솔 백업 | `create snmp community … read_only/read_write`, `create trusted_host`, `create syslog host`, `enable/disable password encryption·telnet·web·ssh`, `config serial_port … auto_logout`, `config sntp` 등 |
| D-Link (DGS-3630 등 IOS 유사 CLI) | `show running-config` | IOS 유사 문법 + `line telnet/ssh/console` `session-timeout`, `ip telnet server` |
| Alteon | `/cfg/dump` 또는 `show running-config` | `/c/sys/access`(tnet·sshd·snmp), `/c/sys/ssnmp`(rcomm·wcomm·snmpv3), `/c/sys/ntp`, `/c/sys/syslog` |
| A10 (ACOS) | `show running-config` | `snmp-server SNMPv1-v2c … community read\|read-write`, `enable-management service`, `terminal idle-timeout`, `logging host`, `ntp server` |
| Dell FTOS | `show running-config` | IOS 유사 문법 중 SNMP·계정·vty·로깅·NTP·배너·LLDP 항목 판정 |

추출한 파일을 `<장비명>.txt` 로 저장해 `converter/network/config/` 에 넣습니다. 결과 항목: 전자금융 NET-xxx / 주요정보 N-01~38

## 판정 규칙 요약

- **SNMP 쓰기 권한**은 벤더별로 모두 취약(NET-004 / N-20)으로 판정합니다: IOS·Dell `RW`/`rw`, `view … RW`, v3 `group … write`, NX-OS `group network-admin`·`rw`, Juniper `authorization read-write`, D-Link `read_write`·`write_view`, Alteon `wcomm`·`snmp w`, A10 `community read-write`. ASA 의 SNMP 는 읽기 전용이라 쓰기 권한이 있을 수 없습니다.
- 보고서에는 **community 는 앞 2자만**, 비밀번호·해시·TACACS/RADIUS key·SNMPv3 키는 `***` 로 마스킹해 출력합니다.
- 주석(`!`)과 부정형(`no …`)은 구분합니다. 설정이 없을 때는 장비·OS 버전별 기본값이 다른 항목(예: IOS `ip bootp server`, `service pad`)을 임의로 가정하지 않고 수동확인으로 둡니다.
- 벤더 문법으로 판정할 수 없는 항목은 다른 벤더 명령을 근거에 넣지 않고 `수동확인` 으로 표시합니다.
- 벤더 자동 분류: 위 표의 구문으로 장비를 식별합니다. 식별할 수 없으면 `UNKNOWN`/기타로 분류되어 대부분 수동확인이 됩니다.
