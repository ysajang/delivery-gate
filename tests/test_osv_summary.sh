#!/usr/bin/env bash
# lib/osv_summary.py 판정 회귀 테스트 (네트워크·osv-scanner 불필요)
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
BAD=0
check() {  # $1 이름 $2 입력파일 $3 기대 출력(차단|기록|전체)
  local got; got="$(python3 "$HERE/lib/osv_summary.py" "$2" | cut -d'|' -f1-3)"
  if [ "$got" = "$3" ]; then echo "PASS $1"; else echo "FAIL $1 -> 기대 $3 / 실제 $got"; BAD=1; fi
}
pkg() {  # $1 생태계 $2 이름 $3 그룹 JSON 배열
  printf '{"package":{"name":"%s","version":"1.0","ecosystem":"%s"},"vulnerabilities":[],"groups":%s}' "$2" "$1" "$3"
}
res() { printf '{"results":[{"source":{"path":"x","type":"lockfile"},"packages":[%s]}]}' "$1" > "$2"; }

res "$(pkg PyPI requests '[{"ids":["A"],"aliases":["A"],"max_severity":"8.7"},{"ids":["B"],"aliases":["B"],"max_severity":"5.3"}]')" "$T/py.json"
check "high 1건 차단 medium 1건 기록" "$T/py.json" "1|1|2"

res "$(pkg Maven okhttp '[{"ids":["C"],"aliases":["C"],"max_severity":""}]')" "$T/unk.json"
check "등급 미기재는 차단 쪽" "$T/unk.json" "1|0|1"

res "$(pkg npm lodash '[{"ids":["D"],"aliases":["D"],"max_severity":"9.8"}]')" "$T/npm.json"
check "npm 은 npm audit 담당이라 제외" "$T/npm.json" "0|0|0"

res "$(pkg PyPI a '[{"ids":["E"],"aliases":["E"],"max_severity":"7.5"}]'),$(pkg PyPI b '[{"ids":["E2"],"aliases":["E"],"max_severity":"7.5"}]')" "$T/dup.json"
check "같은 별칭 취약점은 1건" "$T/dup.json" "1|0|1"

echo '{"results":[]}' > "$T/empty.json"
check "결과 비어 있음" "$T/empty.json" "0|0|0"

echo 'not json' > "$T/bad.json"
check "읽기 실패는 판정 불가" "$T/bad.json" "-1|0|0"

echo '{"foo":1}' > "$T/schema.json"
check "스키마 불일치는 판정 불가" "$T/schema.json" "-1|0|0"
exit $BAD
