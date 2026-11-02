# DBMS 점검

DB 서버(또는 DB 에 접속할 수 있는 bastion·클라이언트 PC)에서 실행합니다. 접속 정보는 환경변수로 넘깁니다 ([사용설명서](../사용설명서.md) 참고).

| 파일 | OS | 대상 DBMS | 용도 |
|------|----|-----------|------|
| `check_dbms.sh` | Linux / Unix | Oracle, MySQL, MariaDB, PostgreSQL, Tibero, MSSQL(Linux), 관리형(RDS·Aurora·Azure) | **Linux/Unix 는 이것 실행** — 인자 `ef` / `mi` / `all` |
| `run_dbms_mssql.bat` | Windows | MSSQL 2014~2022, RDS for SQL Server, Azure SQL | **Windows MSSQL 은 이것 실행** (로컬 점검은 관리자 권한) |
| `check_dbms_mssql.ps1` | Windows | MSSQL | `run_dbms_mssql.bat` 가 호출 (PowerShell 2.0 이상, `-Mode ef\|mi\|all`, `-OutFile`) |

```bash
DBMS_TYPE=mysql bash ./check_dbms.sh all
```

결과·증적 파일은 `/tmp` (Windows 는 스크립트 폴더) 에 **DBMS 종류와 대상 식별자를 넣은 이름**으로 자동 저장되므로 같은 bastion 에서 여러 DB 를 점검해도 덮어쓰지 않습니다. `converter/dbms/output/` 에 두 파일을 함께 넣습니다.

| 구분 | 결과 파일 | 증적 파일 |
|------|-----------|-----------|
| Linux/Unix | `/tmp/<실행호스트>_<dbms>_<대상>_dbms.txt` | `/tmp/<실행호스트>_<dbms>_<대상>_dbms_evidence.txt` |
| Windows | `<스크립트 폴더>\<호스트>_mssql_<대상>_dbms.txt` (UTF-8 BOM) | `…_dbms_evidence.txt` |

`<대상>` 은 로컬이면 `local`, 원격·관리형이면 `호스트_포트[_서비스명]` (영숫자·점·하이픈만).

## 관리형 DB(RDS·Aurora·Azure) · 원격 실행

접속 대상이 **로컬이 아니거나 관리형**이면 로컬 파일·프로세스·umask·방화벽 항목을 실행 호스트 기준으로 판정하지 않습니다.

| 환경 | OS 의존 항목 (설정 파일 권한, 구동 계정·umask, 로컬 방화벽, tip/listener/sqlnet 파일 등) | DB 안에서 조회되는 항목 |
|------|------|------|
| 관리형 (RDS·Aurora·Azure) | `N-A(관리형 DB - 운영체제 접근 불가, 파라미터 그룹·콘솔 설정으로 확인)` | 관리형 전용 통제를 조회해 판정: MySQL `require_secure_transport`·`server_audit_logging`, PostgreSQL `rds.force_ssl`·`ssl`·`pgaudit`, Oracle 통합 감사·세션 암호화 어댑터, MSSQL 세션 `encrypt_option` 등. `rdsadmin`·`rdsrepladmin`·`rds_superuser`·`rdsa` 같은 예약 계정은 계정 점검에서 제외하고 근거에 표시 |
| 설치형이지만 원격 접속 | `점검불가` (대상 서버에서 직접 실행 필요) | 그대로 판정 |

관리형 판별: `DBMS_ENV=rds|aurora|azure` 환경변수, 또는 접속 호스트가 `*.rds.amazonaws.com`·`*.cluster-*`·`*.database.windows.net`·`*.database.azure.com` 이면 자동 탐지 (설치형으로 강제하려면 `DBMS_ENV=onprem`).
SSH 터널(`127.0.0.1:포트`)로 원격 DB 에 붙으면 로컬로 보이므로 `DBMS_REMOTE=1` 을 지정하세요.

```bash
# RDS MySQL (bastion 에서 실행)
DBMS_ENV=rds DBMS_TYPE=mysql MYSQL_HOST=mydb.xxxx.ap-northeast-2.rds.amazonaws.com MYSQL_USER=admin bash ./check_dbms.sh all
# Aurora PostgreSQL
DBMS_TYPE=pgsql PGSQL_HOST=mydb.cluster-xxxx.ap-northeast-2.rds.amazonaws.com PGSQL_USER=postgres PGPASSWORD=... bash ./check_dbms.sh all
# RDS Oracle
DBMS_TYPE=oracle ORACLE_HOST=mydb.xxxx.rds.amazonaws.com ORACLE_SERVICE=ORCL ORACLE_USER=admin ORACLE_PASS=... bash ./check_dbms.sh all
# RDS/Azure SQL (Linux bastion)
DBMS_TYPE=mssql MSSQL_SERVER=mydb.xxxx.database.windows.net MSSQL_USER=admin MSSQL_PASS=... bash ./check_dbms.sh all
```
```bat
rem Windows 클라이언트 PC 에서 RDS for SQL Server 점검
set MSSQL_SERVER=mydb.xxxx.rds.amazonaws.com,1433
set MSSQL_USER=admin
run_dbms_mssql.bat
```

## 결과 헤더

결과 맨 앞 `#` 헤더에 점검 대상(원격이면 `host:port/서비스명`, 로컬이면 호스트명), 실행 호스트, IP, 실행 계정, 클라우드, `DBMS 환경`(설치형 / 관리형 (RDS-MySQL 등)), DBMS 종류, DB 버전이 들어갑니다.

## 판정값 · 증적

판정은 `양호` / `취약` / `수동확인` / `점검불가` / `N-A` 입니다. 쿼리 오류(ORA-/ERROR/TBR-/권한 부족/접속 끊김)는 값으로 쓰지 않고 해당 항목을 `점검불가` 로 내며, 오류 원문은 증적에 남습니다 ("0건" 과 "조회 실패" 를 구분).
증적에는 실행한 SQL 전문, 열 이름, 결과 행 전체(잘림 없음), 오류 원문이 기록됩니다.

비밀번호는 명령 인자로 넘기지 않습니다 (sqlplus·tbsql 은 표준입력, mysql 은 600 임시 옵션 파일, psql 은 `PGPASSWORD`, sqlcmd 는 `SQLCMDPASSWORD`).
