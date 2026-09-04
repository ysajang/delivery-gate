#!/usr/bin/env bash
# 납품 전 자동 게이트 - 시크릿 / SAST / 취약 의존성
# 사용법: ./gate.sh [대상경로]   (기본값: 현재 디렉터리)
set -uo pipefail

TARGET="$(cd "${1:-.}" && pwd)"
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
log "G1 시크릿 스캔 (gitleaks)"
if command -v gitleaks >/dev/null 2>&1; then
  gitleaks dir "$TARGET" --no-banner --redact \
    --report-format json --report-path "$OUT/secrets-worktree.json" >/dev/null 2>&1
  [ $? -eq 0 ] && pass "G1a 작업트리 시크릿 없음" || fail "G1a 작업트리 시크릿 발견 -> $OUT/secrets-worktree.json"

  if [ -d "$TARGET/.git" ]; then
    gitleaks git "$TARGET" --no-banner --redact \
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
    ( cd "$TARGET" && npm audit --audit-level=high --json > "$OUT/dep-npm.json" 2>"$OUT/dep-npm.err" )
    if python3 -c "import json,sys;d=json.load(open('$OUT/dep-npm.json'));v=d.get('metadata',{}).get('vulnerabilities',{});sys.exit(1 if (v.get('high',0)+v.get('critical',0))>0 else 0)" 2>/dev/null; then
      pass "G3 npm high/critical 없음"
    elif [ -s "$OUT/dep-npm.json" ]; then
      fail "G3 npm high/critical 취약점 -> $OUT/dep-npm.json"
    else
      skip "G3 npm audit 실행 실패 -> $OUT/dep-npm.err 확인"
    fi
  else
    skip "G3 npm 락파일 없음 -> npm install 후 재실행"
  fi
fi
if [ -f "$TARGET/composer.json" ] && command -v composer >/dev/null 2>&1; then
  DEP_RAN=1
  ( cd "$TARGET" && composer audit --format=json > "$OUT/dep-composer.json" 2>/dev/null )
  [ $? -eq 0 ] && pass "G3 composer 취약점 없음" || fail "G3 composer 취약점 -> $OUT/dep-composer.json"
fi
if ls "$TARGET"/*.sln "$TARGET"/*.csproj >/dev/null 2>&1 && command -v dotnet >/dev/null 2>&1; then
  DEP_RAN=1
  ( cd "$TARGET" && dotnet list package --vulnerable --include-transitive > "$OUT/dep-dotnet.txt" 2>&1 )
  if grep -qi "has the following vulnerable packages" "$OUT/dep-dotnet.txt"; then
    fail "G3 dotnet 취약 패키지 -> $OUT/dep-dotnet.txt"
  else
    pass "G3 dotnet 취약 패키지 없음"
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
