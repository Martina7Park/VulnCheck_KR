네트워크 장비 점검 안내
========================

네트워크 장비(Cisco, Juniper, D-Link, Alteon, A10, Dell FTOS 등)는
장비 콘솔에서 show running-config 등으로 config를 추출한 후
텍스트 파일(.txt)로 저장하여 전달합니다.

별도 스크립트 실행은 필요 없습니다.

[config 추출 명령어 예시]
  Cisco IOS/IOS-XE : show running-config
  Cisco NX-OS      : show running-config
  Juniper JunOS    : show configuration | display set
  D-Link           : show running-config (또는 웹 콘솔에서 백업)
  Alteon/A10        : show running-config

추출한 config 파일은 점검자에게 전달하면
convert_v4.py (네트워크 카테고리)로 자동 파싱됩니다.
