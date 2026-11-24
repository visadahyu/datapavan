#!/usr/bin/env bash
# Builds the proxy record's test-only device owner (scripts/measure-proxy-settings.sh) with the SDK's build tools
# only, like scripts/proxy-fixture/build.sh. Output: build/proxy-owner/proxy-owner.apk under the repository root,
# signed with a throwaway key; testOnly, so it installs only with `adb install -t`.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
SDK="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-$HOME/Android/sdk}}"
TOOLS="$SDK/build-tools/37.0.0"
PLATFORM="$SDK/platforms/android-37.0/android.jar"
OUT="$ROOT/build/proxy-owner"

rm -rf "$OUT" && mkdir -p "$OUT/classes" "$OUT/dex"
javac --release 17 -cp "$PLATFORM" -d "$OUT/classes" $(find "$HERE/src" -name '*.java')
"$TOOLS/d8" --min-api 29 --lib "$PLATFORM" --output "$OUT/dex" $(find "$OUT/classes" -name '*.class')
"$TOOLS/aapt2" compile --dir "$HERE/res" -o "$OUT/res.zip"
"$TOOLS/aapt2" link -I "$PLATFORM" --manifest "$HERE/AndroidManifest.xml" \
    --min-sdk-version 29 --target-sdk-version 35 --version-code 1 --version-name test -o "$OUT/unsigned.apk" "$OUT/res.zip"
(cd "$OUT/dex" && zip -q "$OUT/unsigned.apk" classes.dex)
"$TOOLS/zipalign" -f 4 "$OUT/unsigned.apk" "$OUT/aligned.apk"
# A throwaway key: the owner is never distributed.
keytool -genkeypair -keystore "$OUT/owner.keystore" -storepass fixture -keypass fixture \
    -alias owner -keyalg EC -validity 1 -dname "CN=Datapavan proxy owner" >/dev/null 2>&1
"$TOOLS/apksigner" sign 2>/dev/null --ks "$OUT/owner.keystore" --ks-pass pass:fixture --out "$OUT/proxy-owner.apk" "$OUT/aligned.apk"
rm -f "$OUT/unsigned.apk" "$OUT/aligned.apk"
echo "$OUT/proxy-owner.apk"
