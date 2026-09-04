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

ln -sf "$SG" "$HERE/bin/semgrep"
"$HERE/bin/semgrep" --version
echo "설치 완료 -> ./gate.sh <대상경로>"
