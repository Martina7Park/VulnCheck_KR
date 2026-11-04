# CHANGELOG

## 2026-11-04 — macOS PC: 비root 서비스 판정·원격 지원 프로그램 탐지 보완

- `pc/check_pc_mac.sh`, `pc/check_pc_mac_kisa.sh`: 비root 에서도 `launchctl print system/<라벨>` 로 system 도메인 적재 여부를 읽을 수 있음(macOS 26.6 실기 확인) → `SYSVIS` 로 확인되면 '미적재 + 포트 닫힘 = 비활성'으로 판정
  - sudo 없이 실행 시 '점검불가'였던 전금 PC-04·PC-05·PC-10, 주요정보 PC-04·PC-05·PC-18 이 실제 상태로 판정됨
  - 주요정보 PC-05(비root): 원격 로그인·원격 Apple 이벤트·TFTP/FTP/Telnet/BOOTP 를 launchd 적재·포트로 확인. 인터넷 공유는 데몬(com.apple.NetworkSharing)이 꺼져 있어도 항상 적재되므로 NAT 설정·프로세스로 판정
- 원격 지원 프로그램 탐지(주요정보 PC-18, 전금 PC-10): Chrome 원격 데스크톱 호스트(`remoting_me2me_host`, `me2me_enabled` 표시 파일) 미탐지 수정, RustDesk·Splashtop·ScreenConnect·LogMeIn·GoToAssist·RealVNC 추가
- 주요정보 PC-16: 판정 문구에 섞이던 `sysadminctl` 로그 머리(날짜·PID) 제거
- 검증: macOS 26.6.2 비root 실행 — 주요정보 점검불가 3→0, 전금 4→1(Safari 전체 디스크 접근 필요 PC-15만 남음), `tools/check_evidence.py` 문제 항목 0

## 2026-11-03 — DBMS 접속 계정·비밀번호 실행 중 입력

- `dbms/check_dbms.sh`: 터미널 실행 시 점검 기준 선택 뒤 `[DBMS] DB 접속 계정` → `비밀번호(숨김)` 를 묻는 `_ask_cred` 추가 (Oracle·MySQL/MariaDB·PostgreSQL·Tibero·MSSQL)
  - 계정 Enter = 기본 계정(root·postgres·tibero·sa·system) 또는 OS 인증. Oracle 로컬은 계정 Enter 시 `/ as sysdba` 로 비밀번호 질문 생략
  - 환경변수로 지정한 계정·비밀번호는 묻지 않음. 터미널이 아니면(자동 실행) 묻지 않음 — 기존 동작 유지
  - Oracle 로컬에서 `sys` + 비밀번호로 접속할 때 `as sysdba` 붙임 (ORA-28009 방지)
  - 앞에서 이미 물었으면 Tibero·MSSQL·Oracle 원격의 기존 비밀번호 질문은 중복으로 묻지 않음 (MySQL·PostgreSQL·Oracle OS 인증 실패 시 재질문은 유지)
- `dbms/check_dbms_mssql.ps1`: 콘솔 실행 시 계정·비밀번호 입력. 계정 Enter = Windows 인증 → 실패 시 sa 비밀번호, 계정 입력 시 SQL 인증
- `dbms/run_dbms_mssql.bat`, `dbms/README.md`, `사용설명서.md`: 안내 문구 갱신 (비밀번호를 명령줄·환경변수에 적는 예시 제거)
- 검증: MariaDB 11(root/별도 계정·특수문자 비밀번호/틀린 비밀번호/비대화형), PostgreSQL 16(TCP·peer), MSSQL 2022 Linux — 57/57/31 항목, 결과·증적에 비밀번호 원문 없음
