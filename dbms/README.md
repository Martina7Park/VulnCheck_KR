# DBMS 점검

DB 서버에서 실행합니다. 접속 정보는 환경변수로 넘깁니다 ([사용설명서](../사용설명서.md) 참고).

| 파일 | OS | 대상 DBMS | 용도 |
|------|----|-----------|------|
| `check_dbms.sh` | Linux / Unix | Oracle, MySQL, MariaDB, PostgreSQL, Tibero, MSSQL(Linux) | **Linux/Unix 는 이것 실행** — 인자 `ef` / `mi` / `all` |
| `run_dbms_mssql.bat` | Windows | MSSQL 2014~2022 | **Windows MSSQL 은 이것 실행** (관리자 권한) |
| `check_dbms_mssql.ps1` | Windows | MSSQL | `run_dbms_mssql.bat` 가 호출 |

```bash
DBMS_TYPE=mysql bash ./check_dbms.sh all > ./$(hostname)_mysql.txt
```

결과와 증적을 `converter/dbms/output/` 에 넣습니다.
