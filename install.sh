#!/usr/bin/env bash
# gitleaks + semgrep 설치 (WSL/Ubuntu 기준)
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
mkdir -p "$HERE/bin"

TAG="$(curl -sIL -o /dev/null -w '%{url_effective}' https://github.com/gitleaks/gitleaks/releases/latest | sed 's#.*/tag/##')"
VER="${TAG#v}"
echo "gitleaks $TAG 설치"
curl -sL "https://github.com/gitleaks/gitleaks/releases/download/${TAG}/gitleaks_${VER}_linux_x64.tar.gz" -o /tmp/gl.tar.gz
tar xzf /tmp/gl.tar.gz -C "$HERE/bin" gitleaks
chmod +x "$HERE/bin/gitleaks"
"$HERE/bin/gitleaks" version

# --- semgrep ---
find_semgrep() {
  command -v semgrep 2>/dev/null && return 0
  local cands=("$HOME/.local/bin/semgrep" "/usr/local/bin/semgrep")
  local ub; ub="$(python3 -m site --user-base 2>/dev/null || true)"
  [ -n "$ub" ] && cands+=("$ub/bin/semgrep")
  local c
  for c in "${cands[@]}"; do
    [ -x "$c" ] && { echo "$c"; return 0; }
  done
  return 1
}

SG="$(find_semgrep || true)"
if [ -z "$SG" ]; then
  echo "semgrep 설치"
  if command -v pipx >/dev/null 2>&1; then
    pipx install semgrep >/dev/null
  else
    pip3 install --user --break-system-packages -q semgrep \
      || pip install --user --break-system-packages -q semgrep \
      || { echo "semgrep 설치 실패 -> sudo apt install pipx && pipx install semgrep 후 재실행"; exit 1; }
  fi
  SG="$(find_semgrep || true)"
fi

if [ -z "$SG" ]; then
  echo "semgrep 실행파일을 찾지 못했습니다 -> 아래 결과를 알려주십시오"
  echo "  python3 -m site --user-base ; ls -la \"$HOME/.local/bin\" | grep -i semgrep"
  exit 1
fi

# semgrep 본체는 실행 시 pysemgrep 을 PATH 에서 찾아 exec 한다 -> 짝을 같이 링크한다
SGDIR="$(dirname "$(readlink -f "$SG")")"
PYSG=""
for c in "$SGDIR/pysemgrep" "$HOME/.local/bin/pysemgrep" "/usr/local/bin/pysemgrep" \
         "$(python3 -m site --user-base 2>/dev/null)/bin/pysemgrep"; do
  [ -x "$c" ] && { PYSG="$c"; break; }
done

if [ -z "$PYSG" ]; then
  echo "pysemgrep 을 찾지 못했습니다 -> semgrep 설치가 불완전합니다. 재설치합니다"
  pip3 install --user --break-system-packages -q --force-reinstall semgrep \
    || { echo "재설치 실패 -> sudo apt install pipx && pipx install semgrep 후 재실행"; exit 1; }
  for c in "$HOME/.local/bin/pysemgrep" "$(python3 -m site --user-base 2>/dev/null)/bin/pysemgrep"; do
    [ -x "$c" ] && { PYSG="$c"; break; }
  done
  SG="$(find_semgrep || true)"
fi

ln -sf "$SG" "$HERE/bin/semgrep"
[ -n "$PYSG" ] && ln -sf "$PYSG" "$HERE/bin/pysemgrep"

PATH="$HERE/bin:$PATH" semgrep --version || {
  echo "semgrep 실행 검증 실패 -> 아래 결과를 알려주십시오"
  echo "  ls -la \"$HERE/bin\" ; ls -la \"$HOME/.local/bin\" | grep -i semgrep"
  exit 1
}
echo "설치 완료 -> ./gate.sh <대상경로>"
