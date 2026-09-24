#!/usr/bin/env bash
# G1 커스텀 시크릿 룰 회귀 테스트
# 시크릿 형태 문자열은 실행 시점에 조립한다 -> 리포에 실제 형태의 키가 커밋되지 않게
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export PATH="$HERE/bin:$PATH"
command -v gitleaks >/dev/null 2>&1 || { echo "gitleaks 없음 -> install.sh 먼저"; exit 2; }

T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
rnd() { python3 -c "import secrets,string,sys;a=sys.argv[2];print(''.join(secrets.choice(a) for _ in range(int(sys.argv[1]))))" "$1" "$2"; }
ALNUM='abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
URLB64="${ALNUM}_-"
HEX='0123456789abcdef'

FCM="AAAA$(rnd 7 "$URLB64"):APA91b$(rnd 134 "$URLB64")"
NSEC="$(rnd 10 "$ALNUM")"
KKEY="$(rnd 32 "$HEX")"

mkdir -p "$T/pos" "$T/neg"
# 양성: 실제로 발견된 노출 형태를 그대로 재현
printf 'object C {\n  const val SERVER_KEY = "%s"\n}\n' "$FCM" > "$T/pos/FcmClient.kt"
printf '<resources>\n  <string name="cloud_messaging_key">%s</string>\n</resources>\n' "$FCM" > "$T/pos/fcm_strings.xml"
printf '.addHeader(\n    "X-Naver-Client-Secret",\n    "%s"\n).build()\n' "$NSEC" > "$T/pos/NaverInterceptor.kt"
printf 'object Constants {\n  const val client_secret = "%s"\n}\n' "$NSEC" > "$T/pos/NaverConstants.kt"
printf '<resources>\n  <string name="social_login_info_naver_client_secret">%s</string>\n</resources>\n' "$NSEC" > "$T/pos/naver_strings.xml"
printf '<resources>\n  <string name="kakao_key">%s</string>\n</resources>\n' "$KKEY" > "$T/pos/kakao_strings.xml"
printf 'val h = "KakaoAK %s"\n' "$KKEY" > "$T/pos/KakaoHeader.kt"

# 음성: 비밀값이 아니거나 이미 분리된 형태
printf '//  buildConfigField "String", "NAVER_CLIENT_SECRET", properties['"'"'naver_client_secret'"'"']\n' > "$T/neg/build.gradle"
printf 'object C {\n  const val client_secret = ""\n  const val client_secret2 = BuildConfig.NAVER_SECRET\n}\n' > "$T/neg/Empty.kt"
printf '<meta-data android:name="com.kakao.sdk.AppKey" android:value="%s"/>\n' "$KKEY" > "$T/neg/AndroidManifest.xml"
printf '"X-Naver-Client-Secret: ${Constants.client_secret}"\n' > "$T/neg/Uses.kt"
# 카카오 네이티브 앱 키는 앱에 들어가는 값 (리소스에 둔 형태)
printf '<resources>\n  <string name="kakao_app_key" >%s</string>\n  <string name="kakao_native_app_key">%s</string>\n</resources>\n' "$KKEY" "$KKEY" > "$T/neg/native_strings.xml"

gitleaks dir "$T" --config "$HERE/rules/gitleaks.toml" --no-banner --redact \
  --report-format json --report-path "$T/r.json" >/dev/null 2>&1

python3 - "$T/r.json" <<'PY'
import json, sys, os
hits = {(os.path.basename(f["File"]), f["RuleID"]) for f in json.load(open(sys.argv[1]))}
expect = [
    ("FcmClient.kt", "fcm-legacy-server-key"),
    ("fcm_strings.xml", "fcm-legacy-server-key"),
    ("NaverInterceptor.kt", "client-secret-literal"),
    ("NaverConstants.kt", "client-secret-literal"),
    ("naver_strings.xml", "client-secret-literal"),
    ("kakao_strings.xml", "kakao-rest-api-key"),
    ("KakaoHeader.kt", "kakao-rest-api-key"),
]
custom = {"fcm-legacy-server-key", "client-secret-literal", "kakao-rest-api-key"}
neg = {"build.gradle", "Empty.kt", "AndroidManifest.xml", "Uses.kt", "native_strings.xml"}
bad = 0
for e in expect:
    ok = e in hits
    bad += not ok
    print(("PASS" if ok else "FAIL"), "탐지", *e)
for f, r in sorted(hits):
    if f in neg and r in custom:
        bad += 1
        print("FAIL", "오탐", f, r)
print("오탐 없음" if not any(f in neg and r in custom for f, r in hits) else "")
sys.exit(1 if bad else 0)
PY
