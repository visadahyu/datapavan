#!/usr/bin/env bash
# Builds W8 part 2a's proxy fixture with the SDK's build tools only, like scripts/workload-app/build.sh. Output:
# build/proxy-fixture/proxy-fixture.apk under the repository root, signed with a throwaway key, and the same app under
# three more package names, proxy-fixture-telegram.apk, -whatsapp.apk and -signal.apk, each an app of its own that
# the network part's debug builds add to that messenger's clients (scripts/verify-proxies.sh); and
# proxy-fixture-outside.apk, the app the proxy record's measurements leave out of the tunnel
# (scripts/measure-proxy-settings.sh); and proxy-fixture-target37.apk, the same app targeting API 37, for what Android
# 17 does to an app that targets it and follows a proxy on the local network without the local network grant (the
# proxy record's unit S2, M5). The others target API 35.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
SDK="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-$HOME/Android/sdk}}"
TOOLS="$SDK/build-tools/37.0.0"
PLATFORM="$SDK/platforms/android-37.0/android.jar"
OUT="$ROOT/build/proxy-fixture"

rm -rf "$OUT" && mkdir -p "$OUT/classes" "$OUT/dex"
javac --release 17 -cp "$PLATFORM" -d "$OUT/classes" $(find "$HERE/src" -name '*.java')
"$TOOLS/d8" --min-api 29 --lib "$PLATFORM" --output "$OUT/dex" $(find "$OUT/classes" -name '*.class')
# A throwaway key: the fixture is never distributed.
keytool -genkeypair -keystore "$OUT/fixture.keystore" -storepass fixture -keypass fixture \
    -alias fixture -keyalg EC -validity 1 -dname "CN=Datapavan proxy fixture" >/dev/null 2>&1
for role in "" telegram whatsapp signal outside target37; do
    name="proxy-fixture${role:+-$role}"
    target=35
    [ "$role" != target37 ] || target=37
    rename=()
    [ -z "$role" ] || rename=(--rename-manifest-package "org.visadahyu.datapavan.proxyfixture.$role")
    "$TOOLS/aapt2" link -I "$PLATFORM" --manifest "$HERE/AndroidManifest.xml" "${rename[@]}" \
        --min-sdk-version 29 --target-sdk-version "$target" --version-code 1 --version-name test -o "$OUT/unsigned.apk"
    (cd "$OUT/dex" && zip -q "$OUT/unsigned.apk" classes.dex)
    "$TOOLS/zipalign" -f 4 "$OUT/unsigned.apk" "$OUT/aligned.apk"
    "$TOOLS/apksigner" sign 2>/dev/null --ks "$OUT/fixture.keystore" --ks-pass pass:fixture --out "$OUT/$name.apk" "$OUT/aligned.apk"
    rm -f "$OUT/unsigned.apk" "$OUT/aligned.apk"
done
echo "$OUT/proxy-fixture.apk"
