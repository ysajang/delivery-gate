#!/usr/bin/env bash
# 납품 전 자동 게이트 - 시크릿 / SAST / 취약 의존성
# 사용법: ./gate.sh [대상경로]   (기본값: 현재 디렉터리)
set -uo pipefail

TARGET_RAW="${1:-.}"
if [ ! -d "$TARGET_RAW" ]; then
  printf '\033[31m대상 경로가 없습니다: %s\033[0m\n' "$TARGET_RAW" >&2
  printf '사용법: ./gate.sh ~/projects_wsl/<프로젝트명>\n' >&2
  exit 2
fi
TARGET="$(cd "$TARGET_RAW" && pwd)"
if [ -z "$TARGET" ]; then
  printf '\033[31m대상 경로를 확정하지 못했습니다: %s\033[0m\n' "$TARGET_RAW" >&2
  exit 2
fi
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN="$HERE/bin"
STAMP="$(date +%Y%m%d-%H%M%S)"
OUT="$HERE/reports/$(basename "$TARGET")-$STAMP"
mkdir -p "$OUT"
export PATH="$BIN:$PATH"

FAIL=0
declare -a RESULT

log()  { printf '\n\033[1m== %s\033[0m\n' "$1"; }
pass() { RESULT+=("PASS  $1"); printf '\033[32mPASS\033[0m  %s\n' "$1"; }
fail() { RESULT+=("FAIL  $1"); FAIL=1; printf '\033[31mFAIL\033[0m  %s\n' "$1"; }
skip() { RESULT+=("SKIP  $1"); printf '\033[33mSKIP\033[0m  %s\n' "$1"; }
warn() { RESULT+=("WARN  $1"); printf '\033[33mWARN\033[0m  %s\n' "$1"; }

# ---------- G1: 시크릿 ----------
log "G1 시크릿 스캔 (gitleaks 기본 룰 + rules/gitleaks.toml)"
GL_CONF="$HERE/rules/gitleaks.toml"
if [ ! -f "$GL_CONF" ]; then
  fail "G1 룰 파일 없음 ($GL_CONF) -> git pull 로 복구"
elif command -v gitleaks >/dev/null 2>&1; then
  gitleaks dir "$TARGET" --config "$GL_CONF" --no-banner --redact \
    --report-format json --report-path "$OUT/secrets-worktree.json" >/dev/null 2>&1
  [ $? -eq 0 ] && pass "G1a 작업트리 시크릿 없음" || fail "G1a 작업트리 시크릿 발견 -> $OUT/secrets-worktree.json"

  if [ -d "$TARGET/.git" ]; then
    gitleaks git "$TARGET" --config "$GL_CONF" --no-banner --redact \
      --report-format json --report-path "$OUT/secrets-history.json" >/dev/null 2>&1
    [ $? -eq 0 ] && pass "G1b 커밋이력 시크릿 없음" || fail "G1b 커밋이력 시크릿 발견 -> $OUT/secrets-history.json"
  else
    skip "G1b .git 없음 -> 이력 스캔 생략"
  fi
else
  fail "G1 gitleaks 미설치 -> install.sh 실행"
fi

# ---------- G2: SAST ----------
log "G2 취약 패턴 스캔 (semgrep, ERROR 등급만)"
if command -v semgrep >/dev/null 2>&1; then
  CONF=(--config p/default --config p/owasp-top-ten)
  [ -f "$TARGET/package.json" ]        && CONF+=(--config p/javascript --config p/typescript)
  [ -f "$TARGET/composer.json" ]       && CONF+=(--config p/php)
  ls "$TARGET"/*.csproj  >/dev/null 2>&1 && CONF+=(--config p/csharp)
  ls "$TARGET"/**/*.csproj >/dev/null 2>&1 && CONF+=(--config p/csharp)
  [ -f "$TARGET/nginx.conf" ]          && CONF+=(--config p/nginx)

  EXC=(--exclude generated --exclude node_modules --exclude .next --exclude dist
       --exclude build --exclude vendor --exclude test-results --exclude "*.min.js"
       --exclude "*.bundle.js" --exclude "*.lock" --exclude package-lock.json)

  semgrep scan "${CONF[@]}" "${EXC[@]}" --severity ERROR --error --metrics=off --quiet \
    --json --output "$OUT/sast.json" "$TARGET" >/dev/null 2>&1
  SG=$?
  case $SG in
    0) pass "G2 ERROR 등급 지적 없음" ;;
    1) fail "G2 ERROR 등급 지적 있음 -> $OUT/sast.json" ;;
    *) fail "G2 semgrep 실행 실패 (네트워크/룰셋 확인)" ;;
  esac

  # 파싱 실패 = 룰이 안 돈 구간 -> 커버리지 구멍이므로 표면화
  if [ -s "$OUT/sast.json" ]; then
    PARSE=$(python3 - "$OUT/sast.json" <<'PY'
import json,sys,os
d=json.load(open(sys.argv[1]))
files=set()
for e in d.get("errors",[]):
    p=e.get("path")
    if p: files.add(os.path.basename(p))
scanned=len(d.get("paths",{}).get("scanned",[]))
print(f"{len(files)}|{scanned}|{','.join(sorted(files)[:5])}")
PY
)
    P_CNT="${PARSE%%|*}"; REST="${PARSE#*|}"; P_SCAN="${REST%%|*}"; P_FILES="${REST#*|}"
    if [ "${P_CNT:-0}" -gt 0 ] 2>/dev/null; then
      warn "G2 파싱 실패 ${P_CNT}개 파일 -> 해당 구간은 룰 미적용 (${P_FILES})"
    fi
    [ -n "${P_SCAN:-}" ] && echo "     스캔 파일 ${P_SCAN}개"
  fi
else
  fail "G2 semgrep 미설치 -> install.sh 실행"
fi

# ---------- G3: 의존성 ----------
log "G3 취약 의존성"
DEP_RAN=0
if [ -f "$TARGET/package.json" ]; then
  DEP_RAN=1
  if [ -f "$TARGET/package-lock.json" ] || [ -f "$TARGET/npm-shrinkwrap.json" ]; then
    # 차단 기준은 프로덕션 의존성만 -> dev 도구의 ReDoS/DoS 로 납품을 막지 않는다
    ( cd "$TARGET" && npm audit --omit=dev --json > "$OUT/dep-npm-prod.json" 2>"$OUT/dep-npm.err" )
    ( cd "$TARGET" && npm audit --json > "$OUT/dep-npm-all.json" 2>>"$OUT/dep-npm.err" )

    SUM_PROD="$(python3 "$HERE/lib/npm_audit.py" "$OUT/dep-npm-prod.json")"
    SUM_ALL="$(python3 "$HERE/lib/npm_audit.py" "$OUT/dep-npm-all.json")"
    IFS='|' read -r P_FIXABLE P_NOFIX P_TOTAL P_NOFIXPKG <<< "$SUM_PROD"
    IFS='|' read -r A_FIXABLE A_NOFIX A_TOTAL _ <<< "$SUM_ALL"

    if [ "${P_FIXABLE:--1}" -lt 0 ] 2>/dev/null; then
      # 판정 불가를 통과로 세지 않는다 -> 의존성 점검을 못 한 채 납품되는 것을 막는다
      fail "G3 npm audit 판정 불가 (${P_NOFIXPKG:-원인불명}) -> $OUT/dep-npm.err 확인"
    elif [ "$P_FIXABLE" -gt 0 ]; then
      fail "G3 프로덕션 취약점 ${P_FIXABLE}건 (수정 가능) -> $OUT/dep-npm-prod.json"
    else
      pass "G3 프로덕션 수정 가능한 high/critical 없음"
    fi

    # 수정본이 없는 high 는 마스터가 손쓸 수 없으므로 차단하지 않고 기록만 한다
    # (critical NOFIX 는 npm_audit.py 가 차단 대상으로 분류한다)
    if [ "${P_NOFIX:-0}" -gt 0 ] 2>/dev/null; then
      warn "G3 프로덕션 수정본 없는 취약점 ${P_NOFIX}건 -> 납품 문서에 기록 필요 (${P_NOFIXPKG})"
    fi

    if [ "${A_TOTAL:-0}" -gt "${P_TOTAL:-0}" ] 2>/dev/null; then
      warn "G3 dev 전용 취약점 $(( A_TOTAL - P_TOTAL ))건 (차단 대상 아님) -> $OUT/dep-npm-all.json"
    fi
  else
    skip "G3 npm 락파일 없음 -> npm install 후 재실행"
  fi
fi
if [ -f "$TARGET/composer.json" ]; then
  DEP_RAN=1
  if ! command -v composer >/dev/null 2>&1; then
    fail "G3 composer 미설치 -> 의존성 판정 불가"
  else
    # 종료코드 1 은 취약·abandoned·설치 누락을 함께 뜻한다 -> 어느 쪽이든 차단하고 리포트로 구분
    ( cd "$TARGET" && composer audit --no-dev --format=json > "$OUT/dep-composer.json" 2>"$OUT/dep-composer.err" )
    [ $? -eq 0 ] && pass "G3 composer 문제 없음" \
      || fail "G3 composer 취약·abandoned 또는 판정 불가 -> $OUT/dep-composer.json, dep-composer.err"
  fi
fi
# ls 로 여러 glob 을 한 번에 검사하면 하나만 없어도 실패한다 -> glob 마다 따로 확인
has_glob() { compgen -G "$1" >/dev/null 2>&1; }
if has_glob "$TARGET/*.sln" || has_glob "$TARGET/*.csproj"; then
  DEP_RAN=1
  if ! command -v dotnet >/dev/null 2>&1; then
    fail "G3 dotnet 미설치 -> 의존성 판정 불가"
  else
    ( cd "$TARGET" && dotnet list package --vulnerable --include-transitive > "$OUT/dep-dotnet.txt" 2>&1 )
    DN=$?
    # 통과는 "취약 없음" 문구를 확인했을 때만. 일부 프로젝트가 에러로 빠져도 나머지는
    # "no vulnerable packages" 를 찍으므로 error 줄이 하나라도 있으면 판정 불가로 본다
    if grep -qi "has the following vulnerable packages" "$OUT/dep-dotnet.txt"; then
      fail "G3 dotnet 취약 패키지 -> $OUT/dep-dotnet.txt"
    elif [ $DN -ne 0 ] || grep -qiE "^[[:space:]]*error" "$OUT/dep-dotnet.txt" \
         || ! grep -qi "has no vulnerable packages" "$OUT/dep-dotnet.txt"; then
      fail "G3 dotnet 판정 불가 (종료코드 $DN) -> $OUT/dep-dotnet.txt"
    else
      pass "G3 dotnet 취약 패키지 없음"
    fi
  fi
fi
[ $DEP_RAN -eq 0 ] && skip "G3 인식 가능한 매니페스트 없음"

# ---------- 요약 ----------
log "요약"
printf '%s\n' "${RESULT[@]}" | tee "$OUT/summary.txt"
echo "리포트: $OUT"
if [ $FAIL -eq 1 ]; then
  printf '\n\033[31m납품 불가 - 위 FAIL 항목을 먼저 해결하십시오\033[0m\n'
else
  printf '\n\033[32m자동 게이트 통과 - 다음은 manual-checks.md 수동 확인\033[0m\n'
fi
echo "주의: 인가·IDOR·비즈니스 로직 결함은 이 게이트가 잡지 못합니다 -> manual-checks.md"
exit $FAIL
