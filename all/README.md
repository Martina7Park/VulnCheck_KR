# 통합 자동 점검 (파일 하나로 서버 전체 점검)

서버에 **파일 하나만** 올려 실행하면 OS·웹서버/WAS·DBMS 를 자동으로 찾아 해당하는 점검을 모두 돌리고, 결과를 **압축 파일 하나**로 만듭니다.
"이 서버는 웹/WAS니까 웹 스크립트, DB니까 DB 스크립트"를 고를 필요가 없습니다.

| 파일 | 대상 | 실행 |
|------|------|------|
| `check_all.sh` | Linux / AIX / HP-UX / Solaris | `sudo bash check_all.sh` |
| `check_all.bat` | Windows Server | 우클릭 → **관리자 권한으로 실행** |

실행하면 기준(1 전자금융 / 2 주요정보 / 3 둘 다)만 고르면 됩니다. Linux 는 인자로 바로 지정할 수도 있습니다: `sudo bash check_all.sh all`

## 자동으로 하는 일

| 구분 | Linux / Unix | Windows |
|------|--------------|---------|
| 서버 | 항상 점검 (전자금융 SRV · 주요정보 U) | 항상 점검 (전자금융 SRV · 주요정보 W) |
| 웹서버/WAS | Apache · Nginx · WebtoB · Tomcat · JEUS 가 실행 중이거나 설치돼 있으면 점검 | IIS · Apache · Nginx · Tomcat · JEUS 가 있으면 점검 |
| DBMS | 실행 중인 Oracle · MySQL/MariaDB · PostgreSQL · Tibero · MSSQL 을 **모두** 찾아 각각 점검 | 실행 중인 MSSQL 점검 (Windows 인증 먼저 시도) |
| 없으면 | 해당 분야는 건너뜀 | 〃 |

DB 접속은 각 스크립트와 같습니다. Oracle 은 OS 인증, PostgreSQL 은 peer 인증, MySQL 은 소켓 인증을 먼저 시도하고, 안 되면 실행 중에 비밀번호를 물어봅니다. 미리 환경변수(`MYSQL_PASS` 등)로 넘겨도 됩니다 ([사용설명서](../사용설명서.md)).

## 결과

```
<호스트>_vulncheck_<일시>.tar.gz   (Windows: .zip)   ← 이 파일 하나만 회수
 ├── server/output/   <호스트>_server.txt, <호스트>_u.txt (또는 _w.txt) + 증적
 ├── webwas/output/   <호스트>_webwas.txt + 증적          (웹/WAS 가 있을 때)
 ├── dbms/output/     <호스트>_mysql.txt, <호스트>_pgsql.txt … + 증적  (DB 가 있을 때)
 └── summary.txt      탐지 결과·분야별 양호/취약 건수
```

점검자 PC에서는 **`converter/` 폴더 안에서 압축을 풀면** 분야별 `output/` 에 바로 들어갑니다. 그다음 `python convert_v4.py` 를 분야별로 실행하면 됩니다.

```bash
cd converter
tar -xzf WEB-PROD-01_vulncheck_20260929_101245.tar.gz     # Windows 10 이상도 tar 명령 있음
```

## 선택 옵션 (Linux)

| 환경변수 | 설명 |
|----------|------|
| `OUT_DIR=/경로` | 결과 저장 위치 (기본: 현재 폴더) |
| `WEBWAS=no` / `WEBWAS=yes` | 웹서버/WAS 점검 강제 생략 / 강제 실행 |
| `DBMS_TYPES="oracle mysql"` | 점검할 DBMS 직접 지정 (프로세스가 안 보이는 원격 DB 등) |

Windows 는 `WEBWAS`, `MSSQL_SERVER` / `MSSQL_USER` / `MSSQL_PASS` / `MSSQL_WINAUTH` 를 쓸 수 있습니다.

## 알아둘 점

- Windows 의 Oracle · MySQL · PostgreSQL 은 점검 스크립트가 없어서, 탐지되면 summary 에 "수동 점검"으로 표시만 합니다.
- MSSQL 은 기본 인스턴스 기준입니다. 이름 있는 인스턴스는 `MSSQL_SERVER=호스트\인스턴스` 로 지정하세요.
- 네트워크 장비·보안장비·PC 는 이 파일 대상이 아닙니다 (각 폴더 참고).

## 관리자용: 파일 다시 만들기

`check_all.sh` / `check_all.bat` 은 `server/` · `webwas/` · `dbms/` 스크립트를 합쳐 **자동 생성**한 파일입니다. 점검 스크립트를 고친 뒤에는 꼭 다시 만드세요.

```bash
python all/build.py           # 다시 생성
python all/build.py --check   # 최신인지 확인
```

통합 실행 로직은 `all/src/runner.sh`, `all/src/runner.ps1` 에 있습니다.
