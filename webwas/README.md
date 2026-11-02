# 웹서버 / WAS 점검

대상 서버에서 실행합니다. 두 기준을 한 번에 점검할 수 있습니다 (`ef` 전자금융 WST / `mi` 주요정보 WEB-01~26 / `all` 둘 다).

| 파일 | OS | 대상 제품 | 용도 |
|------|----|-----------|------|
| `check_webwas.sh` | Linux / Unix | Apache, Nginx, WebtoB, Tomcat, JEUS | **Linux/Unix 는 이것 실행** |
| `run_webwas.bat` | Windows | IIS, Apache, Nginx, Tomcat, JEUS | **Windows 는 이것 실행** (관리자 권한 권장) |
| `check_webwas.ps1` | Windows | 〃 | `run_webwas.bat` 가 호출 |

```bash
sudo bash ./check_webwas.sh all > ./$(hostname)_webwas.txt
```

결과와 증적을 `converter/webwas/output/` 에 넣습니다.

## 점검 방식

- **여러 제품·여러 인스턴스를 모두 점검**합니다. Apache+Nginx 동시 설치, Tomcat 의 모든 인스턴스(`-Dcatalina.base`, 알려진 설치 경로), Tomcat+JEUS 동시 설치를 각각 판정하고 근거에 `[제품/인스턴스 경로]` 로 대상별 결과를 남깁니다. Windows 의 IIS 는 사이트뿐 아니라 하위 응용 프로그램·가상 디렉터리의 `web.config` 까지 해석합니다.
- **판정값 `점검불가`**: 제품은 탐지됐지만 설정 파일을 못 찾았거나 읽을 권한이 없을 때(비root·비관리자), 명령·모듈이 없거나 조회에 실패했을 때는 양호가 아니라 `점검불가` 로 나오며 근거에 사유가 적힙니다. 비root 실행은 일부 항목이 점검불가가 되므로 root(관리자)로 실행하세요.
- **실제 HTTP 응답 수집**: 설정에 구성된 포트 중 리슨 중인 로컬 HTTP/HTTPS 포트에 3초 타임아웃으로 `GET /`, 존재하지 않는 경로, `TRACE /` 를 요청해(curl → 없으면 wget, Windows 는 .NET WebRequest) 상태코드·`Server`·`Location` 헤더를 증적에 남기고 설정 판정과 함께 근거에 반영합니다(WEB-04/16/20/21/22, WST-031/102/123 등). 예: 설정 파일에는 리디렉션이 없어도 실제 응답이 `301 https://` 이면 양호(LB/프록시 처리로 판단), `Server` 헤더에 버전이 보이면 취약. 기본 가상호스트(127.0.0.1) 기준이므로 이름 기반 가상호스트는 증적 확인이 필요합니다.
- 탐지 경로를 직접 지정하려면 환경변수 `APACHE_CONF`, `NGINX_CONF`, `CATALINA_BASE`/`CATALINA_HOME`/`CATALINA_BASES`(공백 구분 다중), `JEUS_HOME`, `WEBTOBDIR`(Windows 는 `TOMCAT_HOME`, `IIS_APPHOST` 도) 를 설정합니다.
- Windows 에서 Apache·Nginx·Tomcat 은 listing/서버 정보/SSI/프록시/에러 페이지/업로드 용량/WebDAV/SSL·리디렉션/관리 계정 등 주요 항목을 자동 판정하고, 자동 판정을 지원하지 않는 항목은 `수동확인`(증적의 설정 파일 참조)으로 나옵니다. JEUS 는 일부 항목만 자동입니다.
- 결과 헤더에 `# IP:`, `# 실행 계정:`, `# 클라우드:`(AWS/Azure/GCP 메타데이터) 가 추가됩니다. Windows 는 결과 파일(`<호스트명>_webwas.txt`)과 증적 파일을 스크립트가 UTF-8(BOM)으로 직접 저장하므로 cmd `>` 리다이렉트가 필요 없습니다.
