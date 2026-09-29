# 보안장비 점검

장비에서 config 를 추출한 뒤 **점검자 PC에서** 실행합니다. 결과 항목: 전자금융 ISS-001~043 (주요정보 S-01~23 은 컨버터가 변환)

| 파일 | 용도 |
|------|------|
| `check_security.sh` | FortiGate / Palo Alto / 일반 장비 config 점검 — 장비 유형 FW·VPN·IDS·IPS·DDoS·WAF |

```bash
# FortiGate: show full-configuration  /  Palo Alto: show config running  → txt 로 저장
bash check_security.sh fw01_config.txt fortigate FW > security_fw01.txt
```

결과를 `converter/security/output/` 에 넣습니다.
