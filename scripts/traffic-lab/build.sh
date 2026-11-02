#!/usr/bin/env bash
# Builds the traffic lab APK with the SDK's build tools only, like scripts/fixture-app/build.sh.
# Output: build/traffic-lab/traffic-lab.apk under the repository root.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
SDK="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-$HOME/Android/sdk}}"
TOOLS="$SDK/build-tools/37.0.0"
PLATFORM="$SDK/platforms/android-37.0/android.jar"
OUT="$ROOT/build/traffic-lab"

rm -rf "$OUT" && mkdir -p "$OUT/classes" "$OUT/dex"
javac --release 17 -cp "$PLATFORM" -d "$OUT/classes" $(find "$HERE/src" -name '*.java')
"$TOOLS/d8" --min-api 29 --lib "$PLATFORM" --output "$OUT/dex" $(find "$OUT/classes" -name '*.class')
"$TOOLS/aapt2" link -I "$PLATFORM" --manifest "$HERE/AndroidManifest.xml" \
    --min-sdk-version 29 --target-sdk-version 35 --version-code 1 --version-name lab -o "$OUT/unsigned.apk"
(cd "$OUT/dex" && zip -q "$OUT/unsigned.apk" classes.dex)
"$TOOLS/zipalign" -f 4 "$OUT/unsigned.apk" "$OUT/aligned.apk"
# A throwaway key: the lab tool is never distributed.
keytool -genkeypair -keystore "$OUT/lab.keystore" -storepass trafficlab -keypass trafficlab \
    -alias lab -keyalg EC -validity 1 -dname "CN=Datapavan traffic lab" >/dev/null 2>&1
"$TOOLS/apksigner" sign 2>/dev/null --ks "$OUT/lab.keystore" --ks-pass pass:trafficlab --out "$OUT/traffic-lab.apk" "$OUT/aligned.apk"
echo "$OUT/traffic-lab.apk"
