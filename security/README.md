# 보안장비 점검

장비에서 config 를 추출한 뒤 **점검자 PC에서** 실행합니다. 결과 항목: 전자금융 ISS-001~043 (주요정보 S-01~23 은 컨버터가 변환)

| 파일 | 용도 |
|------|------|
| `check_security.sh` | FortiGate / Palo Alto(XML·set 형식) / 일반 장비 config 점검 — 장비 유형 FW·VPN·IDS·IPS·DDoS·WAF |

```bash
# FortiGate: show full-configuration  /  Palo Alto: show config running (XML) 또는 set cli config-output-format set; show (set 형식) → txt 로 저장
bash check_security.sh fw01_config.txt fortigate FW > security_fw01.txt
```

- 벤더 인자는 대소문자를 구분하지 않으며(`Fortigate`, `PaloAlto` 가능) 생략하면 config 구문으로 자동 탐지합니다.
- 결과 맨 앞 `# IP` 는 config 에 적힌 장비 관리 IP 입니다.
- **증적 파일은 결과 파일과 같은 폴더에 `<결과파일명>_iss_evidence.txt` 로 저장**됩니다 (`> security_fw01.txt` 이면 `security_fw01_iss_evidence.txt`). 컨버터가 이 이름으로 자동 병합합니다. 결과를 파일로 리다이렉트하지 않으면 `/tmp/<config명>_iss.txt` 와 `/tmp/<config명>_iss_evidence.txt` 가 만들어지며, 4번째 인자로 결과 파일 경로를 줄 수도 있습니다.
- config 에 해당 섹션이 없어(부분 config) 판단할 수 없는 항목은 `점검불가` 로 출력됩니다. 전체 설정(`show full-configuration` 등)으로 다시 추출하세요.
- 증적의 비밀번호 해시는 알고리즘 접두만, SNMP community 는 앞 2자+`***` 로 마스킹됩니다.

결과와 증적 파일을 `converter/security/output/` 에 함께 넣습니다.
