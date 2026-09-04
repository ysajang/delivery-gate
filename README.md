# delivery-gate

납품 전 자동 보안 게이트. 고객에게 산출물을 넘기기 직전 로컬(WSL)에서 한 번 실행한다.

## 설치

    ./install.sh

gitleaks 최신 바이너리를 `bin/`에 내려받고 semgrep을 설치한다.

## 사용

    ./gate.sh /경로/고객리포

윈도우 디스크의 프로젝트는 `/mnt/c/...` 경로로 부른다. `/mnt/c` 경유는 느리므로
큰 리포는 WSL 내부에 클론해서 돌리는 편이 낫다.

## 게이트 구성

| 게이트 | 내용 | 도구 |
|---|---|---|
| G1 | 시크릿 (작업트리 + 커밋이력) | gitleaks `dir`, `git` |
| G2 | 취약 패턴, ERROR 등급만 | semgrep `p/default` + `p/owasp-top-ten` + 스택별 |
| G3 | 취약 의존성 | npm audit / composer audit / dotnet list package |

하나라도 걸리면 exit 1. 결과는 `reports/<리포명>-<타임스탬프>/`에 남는다.

## 한계

자동 게이트 통과는 "안전"이 아니라 "명백한 것은 없음"이다.
인가·IDOR·비즈니스 로직 결함은 앱마다 정답이 달라 룰로 표현되지 않으므로
`manual-checks.md`를 반드시 함께 수행한다.

`--config auto`는 쓰지 않는다. semgrep 레지스트리에 프로젝트 URL로 로그인되는
동작이 있어 고객 코드에 부적절하다.

## 검증 상태

- 실행 확인: gitleaks v8.30.1 `dir`/`git`, semgrep v1.176.0 다중 `--config` + `--error`,
  시크릿 심은 리포 FAIL 판정, 깨끗한 리포 PASS 판정, `install.sh` 전체 실행
- 미검증: composer / dotnet 분기(문서 기준 작성), WSL 실환경
