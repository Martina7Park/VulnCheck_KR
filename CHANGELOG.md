# CHANGELOG

## 2026-11-03 — DBMS 접속 계정·비밀번호 실행 중 입력

- `dbms/check_dbms.sh`: 터미널 실행 시 점검 기준 선택 뒤 `[DBMS] DB 접속 계정` → `비밀번호(숨김)` 를 묻는 `_ask_cred` 추가 (Oracle·MySQL/MariaDB·PostgreSQL·Tibero·MSSQL)
  - 계정 Enter = 기본 계정(root·postgres·tibero·sa·system) 또는 OS 인증. Oracle 로컬은 계정 Enter 시 `/ as sysdba` 로 비밀번호 질문 생략
  - 환경변수로 지정한 계정·비밀번호는 묻지 않음. 터미널이 아니면(자동 실행) 묻지 않음 — 기존 동작 유지
  - Oracle 로컬에서 `sys` + 비밀번호로 접속할 때 `as sysdba` 붙임 (ORA-28009 방지)
  - 앞에서 이미 물었으면 Tibero·MSSQL·Oracle 원격의 기존 비밀번호 질문은 중복으로 묻지 않음 (MySQL·PostgreSQL·Oracle OS 인증 실패 시 재질문은 유지)
- `dbms/check_dbms_mssql.ps1`: 콘솔 실행 시 계정·비밀번호 입력. 계정 Enter = Windows 인증 → 실패 시 sa 비밀번호, 계정 입력 시 SQL 인증
- `dbms/run_dbms_mssql.bat`, `dbms/README.md`, `사용설명서.md`: 안내 문구 갱신 (비밀번호를 명령줄·환경변수에 적는 예시 제거)
- 검증: MariaDB 11(root/별도 계정·특수문자 비밀번호/틀린 비밀번호/비대화형), PostgreSQL 16(TCP·peer), MSSQL 2022 Linux — 57/57/31 항목, 결과·증적에 비밀번호 원문 없음
