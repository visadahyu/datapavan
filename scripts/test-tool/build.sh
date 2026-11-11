#!/usr/bin/env bash
# Builds W6's test tool APK with the SDK's build tools only, like scripts/fixture-app/build.sh.
# Output: build/test-tool/test-tool.apk under the repository root, signed with a throwaway key.
# It targets API 33, so that its foreground service needs no declared type.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
SDK="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-$HOME/Android/sdk}}"
TOOLS="$SDK/build-tools/37.0.0"
PLATFORM="$SDK/platforms/android-37.0/android.jar"
OUT="$ROOT/build/test-tool"

rm -rf "$OUT" && mkdir -p "$OUT/classes" "$OUT/dex"
javac --release 17 -cp "$PLATFORM" -d "$OUT/classes" $(find "$HERE/src" -name '*.java')
"$TOOLS/d8" --min-api 29 --lib "$PLATFORM" --output "$OUT/dex" $(find "$OUT/classes" -name '*.class')
"$TOOLS/aapt2" link -I "$PLATFORM" --manifest "$HERE/AndroidManifest.xml" \
    --min-sdk-version 29 --target-sdk-version 33 --version-code 1 --version-name test -o "$OUT/unsigned.apk"
(cd "$OUT/dex" && zip -q "$OUT/unsigned.apk" classes.dex)
"$TOOLS/zipalign" -f 4 "$OUT/unsigned.apk" "$OUT/aligned.apk"
# A throwaway key: the test tool is never distributed.
keytool -genkeypair -keystore "$OUT/tool.keystore" -storepass testtool -keypass testtool \
    -alias tool -keyalg EC -validity 1 -dname "CN=Datapavan test tool" >/dev/null 2>&1
"$TOOLS/apksigner" sign 2>/dev/null --ks "$OUT/tool.keystore" --ks-pass pass:testtool --out "$OUT/test-tool.apk" "$OUT/aligned.apk"
echo "$OUT/test-tool.apk"
