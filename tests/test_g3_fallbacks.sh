#!/usr/bin/env bash
# G3 composer / dotnet 분기 회귀 테스트
# 실제 도구 대신 스텁을 PATH 앞에 두고 출력·종료코드를 흉내 낸다
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
BAD=0

# $1 이름 $2 스택(dotnet|composer) $3 스텁 본문(없으면 미설치) $4 기대 줄 정규식
case_run() {
  local name="$1" stack="$2" stub="$3" want="$4"
  local proj="$T/$name" sb="$T/$name-stub"
  mkdir -p "$proj" "$sb"
  if [ "$stack" = dotnet ]; then echo '<Project Sdk="Microsoft.NET.Sdk"></Project>' > "$proj/app.csproj"
  else echo '{"require":{}}' > "$proj/composer.json"; fi
  if [ -n "$stub" ]; then
    printf '#!/usr/bin/env bash\n%s\n' "$stub" > "$sb/$stack"; chmod +x "$sb/$stack"
  fi
  local out
  out="$(PATH="$sb:$PATH" "$HERE/gate.sh" "$proj" 2>&1 | sed 's/\x1b\[[0-9;]*m//g' | grep -E '^(PASS|FAIL|SKIP|WARN)  G3' | sort -u)"
  if printf '%s\n' "$out" | grep -Eq "$want"; then
    echo "PASS $name"
  else
    echo "FAIL $name -> 기대: $want / 실제: $out"; BAD=1
  fi
}

if command -v dotnet >/dev/null 2>&1 || command -v composer >/dev/null 2>&1; then
  echo "실제 dotnet/composer 가 PATH 에 있어 미설치 케이스를 재현할 수 없음"; exit 2
fi

NOVULN='echo "The given project \`App\` has no vulnerable packages given the current sources."'
case_run dotnet-missing    dotnet   ""                                       '^FAIL  G3 dotnet .*미설치'
case_run dotnet-exit1      dotnet   'echo "error: restore failed"; exit 1'   '^FAIL  G3 dotnet .*판정 불가'
case_run dotnet-partial    dotnet   "$NOVULN"'; echo "error: The imported project was not found."' '^FAIL  G3 dotnet .*판정 불가'
case_run dotnet-vuln       dotnet   'echo "Project \`App\` has the following vulnerable packages"' '^FAIL  G3 dotnet 취약 패키지'
case_run dotnet-clean      dotnet   "$NOVULN"                                '^PASS  G3 dotnet'
case_run dotnet-noproject  dotnet   'echo "Could not find a MSBuild project file"' '^FAIL  G3 dotnet .*판정 불가'
case_run composer-missing  composer ""                                       '^FAIL  G3 composer .*미설치'
case_run composer-exit1    composer 'echo "{}"; exit 1'                      '^FAIL  G3 composer'
case_run composer-clean    composer 'echo "{\"advisories\":[]}"'            '^PASS  G3 composer'
exit $BAD
