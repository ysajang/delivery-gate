#!/usr/bin/env python3
"""npm audit --json 결과를 게이트 판정용으로 요약한다.

npm audit 은 취약점이 아니라 의존성 경로상의 패키지를 센다.
하나의 취약한 리프가 상위 패키지 수만큼 부풀려지므로 고유 취약점(advisory)
단위로 다시 센다.

출력 (한 줄, | 구분):
  차단대상수 | NOFIX수 | 고유취약점수 | NOFIX패키지목록(쉼표)
판정 불가(스키마 불일치·읽기 실패) 시 -1 로 시작하는 줄 -> 호출 측에서 통과로
세지 않는다.
"""
import json
import sys

BLOCKING = ("high", "critical")
SUPPORTED_REPORT_VERSION = 2


def advisories(pkg):
    """via 항목 중 high/critical advisory 만 추출 -> (source, title)

    via 에는 전이 경로상의 패키지 이름(문자열)과 실제 advisory(객체)가 섞여
    들어오고, 객체에는 해당 패키지의 모든 등급 advisory 가 포함된다.
    """
    out = set()
    for v in pkg.get("via", []):
        if isinstance(v, dict) and v.get("severity") in BLOCKING:
            out.add((v.get("source"), v.get("title")))
    return out


def classify(pkg):
    """fixAvailable 의 세 형태를 게이트 판정용으로 나눈다.

    True  -> npm audit fix 로 해결됨                  : 차단
    dict  -> 다른 패키지를 특정 버전으로 갈아야 함     : 차단 (조치 가능하므로)
    False -> 수정본 없음                              : 기록만
    없음  -> 판정 불가 -> 차단 쪽으로 보수적으로 처리
    """
    fix = pkg.get("fixAvailable", "MISSING")
    if fix is False:
        return "nofix"
    return "block"


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

    # 스키마 가드: npm 6 형식(advisories 키)이나 미지원 버전이 들어오면
    # 빈 결과가 나오므로 통과로 읽히지 않게 판정 불가로 끊는다.
    ver = data.get("auditReportVersion")
    if ver != SUPPORTED_REPORT_VERSION or "vulnerabilities" not in data:
        print("-1|0|0|스키마불일치(auditReportVersion=%s)" % ver)
        return 2

    vulns = data["vulnerabilities"]
    blocking, nofix = set(), set()
    nofix_pkgs = []

    for name, pkg in vulns.items():
        if pkg.get("severity") not in BLOCKING:
            continue
        adv = advisories(pkg)
        # advisory 가 없으면 상위 전파분 -> 뿌리에서 이미 계산됨
        if not adv:
            continue
        # critical 은 수정본이 없어도 차단한다
        if classify(pkg) == "nofix" and pkg.get("severity") != "critical":
            nofix |= adv
            nofix_pkgs.append(name)
        else:
            blocking |= adv

    print("%d|%d|%d|%s" % (
        len(blocking),
        len(nofix),
        len(blocking | nofix),
        ",".join(sorted(nofix_pkgs)[:8]),
    ))
    return 0


if __name__ == "__main__":
    sys.exit(main())
