# delivery-gate

납품 전 자동 보안 게이트. 고객에게 산출물을 넘기기 직전 로컬(WSL)에서 한 번 실행한다.

## 설치

    ./install.sh

gitleaks 최신 바이너리를 `bin/`에 내려받고 semgrep을 설치한다.

## 사용

    ./gate.sh ~/projects_wsl/<프로젝트명>

프로젝트는 `~/projects_wsl` 아래에 둔다. 윈도우 디스크(`/mnt/c/...`)에 있는 것도
스캔은 되지만 파일 I/O가 느려 오래 걸리므로 `~/projects_wsl`로 옮겨 돌린다.

## 게이트 구성

| 게이트 | 내용 | 도구 |
|---|---|---|
| G1 | 시크릿 (작업트리 + 커밋이력) | gitleaks `dir`, `git` |
| G2 | 취약 패턴, ERROR 등급만 | semgrep `p/default` + `p/owasp-top-ten` + 스택별 |
| G3 | 취약 의존성 (프로덕션만 차단) | npm audit / composer audit / dotnet list package |

하나라도 걸리면 exit 1. 결과는 `reports/<리포명>-<타임스탬프>/`에 남는다.

G2는 자동생성·빌드 산출물(`generated` `node_modules` `.next` `dist` `build` `vendor`
`test-results` 압축 JS 락파일)을 제외한다. 볼 것이 없으면서 파싱 경고만 만들기 때문.

semgrep이 파일을 파싱하지 못하면 그 구간은 룰이 돌지 않은 것이므로 요약에 `WARN`으로
표시한다. `WARN`은 exit 코드를 바꾸지 않지만 커버리지 구멍이므로 무시하지 않는다.

G3는 `--omit=dev` 결과만 차단 기준으로 삼는다. 린터·코드젠 같은 빌드 도구의
ReDoS/DoS 로 납품을 막으면 노이즈가 커져 게이트 전체가 무시되기 때문이다.
dev 쪽 건수는 `WARN`으로만 표시한다.

건수는 패키지가 아니라 고유 취약점(advisory) 단위로 센다. npm audit 은 의존성
경로상의 패키지를 세므로 취약한 리프 하나가 상위 패키지 수만큼 부풀려진다
(예: `turbo-stream` 하나가 `@remix-run/*` 5건으로 계상).

수정본이 없는 high 취약점은 차단하지 않고 `WARN` 으로 기록만 한다. 손쓸 수 없는
항목으로 납품을 영구히 막으면 게이트를 우회하게 되기 때문이다. 대신 납품 문서의
"점검하지 않은 범위"에 그 목록을 적는다. critical 은 수정본이 없어도 차단한다.

## 한계

자동 게이트 통과는 "안전"이 아니라 "명백한 것은 없음"이다.
인가·IDOR·비즈니스 로직 결함은 앱마다 정답이 달라 룰로 표현되지 않으므로
`manual-checks.md`를 반드시 함께 수행한다.

`--config auto`는 쓰지 않는다. semgrep 레지스트리에 프로젝트 URL로 로그인되는
동작이 있어 고객 코드에 부적절하다.

## 검증 상태

- 실행 확인: gitleaks v8.30.1 `dir`/`git`, semgrep v1.176.0 다중 `--config` + `--error`,
  시크릿 심은 리포 FAIL 판정, 깨끗한 리포 PASS 판정, `install.sh` 전체 실행
- 실측: Next.js + Prisma 리포(파일 172개)에 실행 -> 38초, 오탐 0건.
  API 라우트 30개에 semgrep ERROR 지적이 0으로 나왔다. 안전하다는 뜻이 아니라
  인가 결함을 SAST가 원래 못 잡는다는 실측이다 -> `manual-checks.md`가 필수인 근거
- 미검증: composer / dotnet 분기(문서 기준 작성), WSL 실환경
