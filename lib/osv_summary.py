#!/usr/bin/env python3
"""osv-scanner --format json 결과를 게이트 판정용으로 요약한다.

npm 은 npm audit 이 따로 판정하므로 여기서는 Maven(Gradle)·PyPI 만 센다.
건수는 osv-scanner 의 groups(별칭으로 묶인 고유 취약점) 단위다.

차단: CVSS 7.0 이상, 또는 등급 미기재(판정 불가를 통과로 세지 않는다)
기록: 7.0 미만

출력 (한 줄, | 구분):
  차단수 | 기록수 | 전체수 | 차단 패키지 목록(쉼표)
읽기 실패·스키마 불일치 시 -1 로 시작하는 줄 -> 호출 측에서 통과로 세지 않는다.
"""
import json
import sys

ECOSYSTEMS = ("Maven", "PyPI")
BLOCK_SCORE = 7.0


def severity(group):
    """max_severity 문자열 -> float, 없거나 숫자가 아니면 None"""
    try:
        return float(group.get("max_severity") or "")
    except ValueError:
        return None


def main():
    if len(sys.argv) < 2:
        print("-1|0|0|인자없음")
        return 2
    try:
        with open(sys.argv[1], encoding="utf-8") as fh:
            data = json.load(fh)
    except Exception:
        print("-1|0|0|읽기실패")
        return 2
    if not isinstance(data, dict) or "results" not in data:
        print("-1|0|0|스키마불일치")
        return 2

    block, warn, block_pkgs = set(), set(), set()
    for result in data.get("results") or []:
        for pkg in result.get("packages") or []:
            info = pkg.get("package") or {}
            if info.get("ecosystem") not in ECOSYSTEMS:
                continue
            for group in pkg.get("groups") or []:
                key = tuple(sorted(group.get("aliases") or group.get("ids") or []))
                score = severity(group)
                if score is None or score >= BLOCK_SCORE:
                    block.add(key)
                    block_pkgs.add("%s@%s" % (info.get("name"), info.get("version")))
                else:
                    warn.add(key)
    warn -= block
    print("%d|%d|%d|%s" % (len(block), len(warn), len(block | warn),
                           ",".join(sorted(block_pkgs)[:8])))
    return 0


if __name__ == "__main__":
    sys.exit(main())
