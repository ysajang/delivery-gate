#!/usr/bin/env python3
"""npm audit --json 결과를 게이트 판정용으로 요약한다.

npm audit 은 취약점이 아니라 의존성 경로상의 패키지를 센다.
하나의 취약한 리프가 상위 패키지 수만큼 부풀려지므로 고유 취약점(advisory)
단위로 다시 센다.

출력 (한 줄, | 구분):
  차단대상수 | NOFIX수 | 고유취약점수 | NOFIX패키지목록(쉼표)
읽기 실패 시 -1 로 시작하는 줄.
"""
import json
import sys

BLOCKING = ("high", "critical")


def advisories(pkg):
    """via 항목 중 high/critical advisory 만 추출 -> (source, title)

    via 에는 해당 패키지의 모든 등급 advisory 가 들어오므로 등급으로 거른다.
    """
    out = set()
    for v in pkg.get("via", []):
        if isinstance(v, dict) and v.get("severity") in BLOCKING:
            out.add((v.get("source"), v.get("title")))
    return out


def main():
    try:
        with open(sys.argv[1], encoding="utf-8") as fh:
            data = json.load(fh)
    except Exception:
        print("-1|0|0|")
        return

    vulns = data.get("vulnerabilities", {})
    fixable, nofix = set(), set()
    nofix_pkgs = []

    for name, pkg in vulns.items():
        if pkg.get("severity") not in BLOCKING:
            continue
        adv = advisories(pkg)
        # 이 패키지 자체에 advisory 가 없으면 상위 전파분 -> 뿌리에서 이미 계산됨
        if not adv:
            continue
        if pkg.get("fixAvailable") is False and pkg.get("severity") != "critical":
            nofix |= adv
            nofix_pkgs.append(name)
        else:
            fixable |= adv

    print("%d|%d|%d|%s" % (
        len(fixable),
        len(nofix),
        len(fixable | nofix),
        ",".join(sorted(nofix_pkgs)[:8]),
    ))


if __name__ == "__main__":
    main()
