# 개발 기준

## 구성

- `gate.sh` 게이트 본체 (bash)
- `lib/` 게이트가 호출하는 판정 스크립트 (python3 표준 라이브러리만 사용)
- `rules/gitleaks.toml` G1 룰 (gitleaks 기본 룰 + 추가 룰)
- `tests/` 회귀 테스트
- `install.sh` 외부 도구 설치 (WSL/Ubuntu 기준)
- `manual-checks.md` 스캐너가 못 잡는 수동 확인 목록
- `skills/delivery-gate/SKILL.md` 게이트 운용 절차

## 실행

    ./install.sh
    ./gate.sh <대상경로>

## 검증

- 셸 문법: `bash -n gate.sh install.sh`
- 판정 스크립트: `python3 -m py_compile lib/*.py`
- G1 룰: `./tests/test_g1_rules.sh` (gitleaks 필요)
- G3 composer·dotnet 분기: `./tests/test_g3_fallbacks.sh` (실제 composer·dotnet 이 PATH 에 없어야 한다. 스텁으로 흉내 냄)

## 원칙

- 판정 불가(도구 없음, 실행 실패, 출력 해석 실패)는 PASS 로 세지 않는다
- 차단은 FAIL, 기록만 할 것은 WARN, 돌지 않은 것은 SKIP 으로 구분한다
- 새 판정 로직은 실패 사례 입력으로 먼저 확인한 뒤 넣는다

## 건드리지 말 것

- `reports/` `bin/` 은 커밋하지 않는다 (`.gitignore` 유지). 리포트에는 고객 코드 경로와 취약점 위치가 들어 있다
- semgrep `--config auto` 는 쓰지 않는다 (레지스트리에 프로젝트 정보가 전송되는 동작)
- 테스트 입력에 실제 형태의 시크릿 문자열을 파일로 커밋하지 않는다 (호스팅 쪽 비밀값 차단에 걸리고 그 자체가 노출이다)

## 미확인

- WSL 실환경 전체 실행
- composer / dotnet 분기 실제 도구 실행
