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

결과와 증적을 `converter/webwas/output/` 에 넣습니다.
