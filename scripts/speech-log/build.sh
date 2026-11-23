#!/usr/bin/env bash
# Builds the TalkBack walk's speech log APK with the SDK's build tools only, like scripts/test-tool/build.sh.
# Output: build/speech-log/speech-log.apk under the repository root, signed with a throwaway key.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
SDK="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-$HOME/Android/sdk}}"
TOOLS="$SDK/build-tools/37.0.0"
PLATFORM="$SDK/platforms/android-37.0/android.jar"
OUT="$ROOT/build/speech-log"

rm -rf "$OUT" && mkdir -p "$OUT/classes" "$OUT/dex"
javac --release 17 -cp "$PLATFORM" -d "$OUT/classes" $(find "$HERE/src" -name '*.java')
"$TOOLS/d8" --min-api 33 --lib "$PLATFORM" --output "$OUT/dex" $(find "$OUT/classes" -name '*.class')
"$TOOLS/aapt2" compile --dir "$HERE/res" -o "$OUT/res.zip"
"$TOOLS/aapt2" link -I "$PLATFORM" --manifest "$HERE/AndroidManifest.xml" \
    --min-sdk-version 33 --target-sdk-version 33 --version-code 1 --version-name test -o "$OUT/unsigned.apk" "$OUT/res.zip"
(cd "$OUT/dex" && zip -q "$OUT/unsigned.apk" classes.dex)
"$TOOLS/zipalign" -f 4 "$OUT/unsigned.apk" "$OUT/aligned.apk"
# A throwaway key: the speech log is never distributed.
keytool -genkeypair -keystore "$OUT/log.keystore" -storepass speechlog -keypass speechlog \
    -alias log -keyalg EC -validity 1 -dname "CN=Datapavan speech log" >/dev/null 2>&1
"$TOOLS/apksigner" sign 2>/dev/null --ks "$OUT/log.keystore" --ks-pass pass:speechlog --out "$OUT/speech-log.apk" "$OUT/aligned.apk"
echo "$OUT/speech-log.apk"
