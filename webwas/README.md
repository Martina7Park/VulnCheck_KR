# 웹서버 / WAS 점검

대상 서버에서 실행합니다. 두 기준을 한 번에 점검할 수 있습니다 (`ef` 전자금융 WST / `mi` 주요정보 WEB-01~26 / `all` 둘 다).

| 파일 | OS | 대상 제품 | 용도 |
|------|----|-----------|------|
| `check_webwas.sh` | Linux / Unix | Apache, Nginx, WebtoB, Tomcat, JEUS | **Linux/Unix 는 이것 실행** |
| `run_webwas.bat` | Windows | IIS, Apache, Nginx, Tomcat, JEUS | **Windows 는 이것 실행** (관리자 권한) |
| `check_webwas.ps1` | Windows | 〃 | `run_webwas.bat` 가 호출 |

```bash
sudo bash ./check_webwas.sh all > ./$(hostname)_webwas.txt
```

**탐지 순서:** 실행 중인 프로세스(실제 바이너리·설정 경로)를 먼저 찾고, 없으면 기본 설치 경로를 찾습니다. 그래서 소스로 설치한 Apache·Nginx(`/usr/local`·`/app`·`/sw`)와 sudo 환경에서 PATH에 없는 WebtoB·JEUS도 찾습니다. 탐지 결과는 결과 머리말 `# 설정 경로:`에 표시됩니다.

**같은 서버에 Tomcat 인스턴스나 웹서버가 여러 개일 때:** 결과 머리말 `# [안내]`에 나머지 대상이 나옵니다. 대상을 지정해 각각 한 번씩 더 실행하십시오. 결과 파일과 점검 대상명에 인스턴스명이 붙어 따로 집계됩니다.

```bash
sudo env TOMCAT_HOME=/app/tomcat2 bash ./check_webwas.sh all > ./$(hostname)_tomcat2_webwas.txt
sudo env NGINX_CONF=/usr/local/nginx/conf/nginx.conf bash ./check_webwas.sh all > ./$(hostname)_nginx_webwas.txt
```
(`export` 후 `sudo` 로 실행하면 환경변수가 넘어가지 않으므로 `sudo env 변수=값 bash …` 형태로 지정. 지정 가능: `APACHE_CONF` `NGINX_CONF` `TOMCAT_HOME` `JEUS_HOME` `WEBTOBDIR`)

결과와 증적을 `converter/webwas/output/` 에 넣습니다.
