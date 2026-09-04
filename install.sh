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

if ! command -v semgrep >/dev/null 2>&1; then
  echo "semgrep 설치"
  pip install --break-system-packages -q semgrep || pip3 install --break-system-packages -q semgrep
fi
semgrep --version
echo "설치 완료 -> ./gate.sh <대상경로>"
