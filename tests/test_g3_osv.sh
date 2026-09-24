#!/usr/bin/env bash
# G3 Gradle·Python 분기 통합 테스트 (osv-scanner 와 네트워크 필요)
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export PATH="$HERE/bin:$PATH"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
BAD=0
g3() {  # $1 프로젝트 경로 [$2 PATH 앞에 붙일 경로] -> G3 줄만
  PATH="${2:+$2:}$PATH" "$HERE/gate.sh" "$1" 2>&1 | sed 's/\x1b\[[0-9;]*m//g' | grep -E '^(PASS|FAIL|SKIP|WARN)  G3' | sort -u
}
expect() {  # $1 이름 $2 출력 $3 정규식
  if printf '%s\n' "$2" | grep -Eq "$3"; then echo "PASS $1"; else echo "FAIL $1 -> 기대 $3 / 실제: $2"; BAD=1; fi
}

mkdir -p "$T/py" "$T/py-clean" "$T/gr-nolock/app" "$T/gr-lock/app" "$T/none"
printf 'requests==2.19.0\n' > "$T/py/requirements.txt"
: > "$T/py-clean/requirements.txt"
echo 'plugins { id("com.android.application") }' > "$T/gr-nolock/app/build.gradle.kts"
echo 'include(":app")' > "$T/gr-nolock/settings.gradle.kts"
cp "$T/gr-nolock/settings.gradle.kts" "$T/gr-lock/"
cp "$T/gr-nolock/app/build.gradle.kts" "$T/gr-lock/app/"
printf '# lock\ncom.squareup.okhttp3:okhttp:3.12.0=releaseRuntimeClasspath\nempty=\n' > "$T/gr-lock/app/gradle.lockfile"

if command -v osv-scanner >/dev/null 2>&1; then
  expect "python 취약 의존성 차단"    "$(g3 "$T/py")"        '^FAIL  G3 python·gradle 취약점 [0-9]+건'
  expect "빈 requirements 는 판정 불가" "$(g3 "$T/py-clean")"  '^FAIL  G3 osv-scanner 패키지 0개'
  expect "gradle 락파일 없으면 SKIP"   "$(g3 "$T/gr-nolock")" '^SKIP  G3 gradle 락파일 없음'
  expect "gradle 락파일 있으면 스캔"    "$(g3 "$T/gr-lock")"   '^FAIL  G3 python·gradle 취약점 [0-9]+건'
else
  echo "SKIP osv-scanner 없음 -> 스캔 케이스 생략"
fi
# 미설치: osv-scanner 를 찾지 못하게 PATH 를 시스템 기본 경로로 좁힌다
SB="$T/stubs"; mkdir -p "$SB"; ln -s "$(command -v gitleaks)" "$SB/gitleaks" 2>/dev/null
out="$(PATH="$SB:/usr/bin:/bin" "$HERE/gate.sh" "$T/py" 2>&1 | sed 's/\x1b\[[0-9;]*m//g' | grep -E '^(PASS|FAIL|SKIP|WARN)  G3' | sort -u)"
[ -x "$HERE/bin/osv-scanner" ] && out="(bin/osv-scanner 가 있어 미설치 케이스 생략)"
expect "osv-scanner 미설치는 FAIL" "$out" '^FAIL  G3 osv-scanner 미설치|생략'
expect "대상 스택 없으면 G3 미실행" "$(g3 "$T/none")" '^SKIP  G3 인식 가능한 매니페스트 없음'
exit $BAD
