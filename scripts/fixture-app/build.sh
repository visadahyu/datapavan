#!/usr/bin/env bash
# Builds the test fixture APK with the SDK's build tools only (javac, d8, aapt2, apksigner): no
# Gradle and no dependencies. Output: build/fixture/fixture.apk under the repository root.
#
#   scripts/fixture-app/build.sh [package]
#
# With a package name, the same app is built under that name into build/fixture-<package>/, for
# example to pose as a known app signed by someone else (ADR 0018).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
SDK="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-$HOME/Android/sdk}}"
TOOLS="$SDK/build-tools/37.0.0"
PLATFORM="$SDK/platforms/android-37.0/android.jar"
OUT="$ROOT/build/fixture${1:+-$1}"

rm -rf "$OUT" && mkdir -p "$OUT/classes" "$OUT/dex"
javac --release 17 -cp "$PLATFORM" -d "$OUT/classes" $(find "$HERE/src" -name '*.java')
"$TOOLS/d8" --min-api 29 --lib "$PLATFORM" --output "$OUT/dex" $(find "$OUT/classes" -name '*.class')
"$TOOLS/aapt2" compile --dir "$HERE/res" -o "$OUT/res.zip"
"$TOOLS/aapt2" link -I "$PLATFORM" --manifest "$HERE/AndroidManifest.xml" \
    --min-sdk-version 29 --target-sdk-version 35 --version-code 1 --version-name fixture \
    ${1:+--rename-manifest-package "$1"} -o "$OUT/unsigned.apk" "$OUT/res.zip"
(cd "$OUT/dex" && zip -q "$OUT/unsigned.apk" classes.dex)
"$TOOLS/zipalign" -f 4 "$OUT/unsigned.apk" "$OUT/aligned.apk"
# A throwaway key: the fixture is never distributed.
keytool -genkeypair -keystore "$OUT/fixture.keystore" -storepass fixture -keypass fixture \
    -alias fixture -keyalg EC -validity 1 -dname "CN=Datapavan test fixture" >/dev/null 2>&1
"$TOOLS/apksigner" sign 2>/dev/null --ks "$OUT/fixture.keystore" --ks-pass pass:fixture --out "$OUT/fixture.apk" "$OUT/aligned.apk"
echo "$OUT/fixture.apk"
