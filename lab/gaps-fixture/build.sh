#!/usr/bin/env bash
# Builds the lab's gaps fixture (ADR 0048, decision 5) with the SDK's build tools only, as
# scripts/fixture-app/build.sh does, signed with a throwaway key made for each build. Output:
# build/gaps-fixture/gaps-fixture.apk under the repository root.
#
#   lab/gaps-fixture/build.sh [--lab-phone]
#
# Without --lab-phone the fixture stops on anything but an emulator before it reads anything. With it, the
# build goes to build/gaps-fixture-lab-phone/ and runs on a lab phone too, after the maintainer confirms
# the device on its screen; each phone and each session needs the maintainer's consent.
#
# The build fails if the manifest, or the APK it makes, names the INTERNET permission: the fixture never
# uploads anything. scripts/check.sh checks the same.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
SDK="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-$HOME/Android/sdk}}"
TOOLS="$SDK/build-tools/37.0.0"
PLATFORM="$SDK/platforms/android-37.0/android.jar"
NAME=gaps-fixture
case "${1:-}" in
    "") ;;
    --lab-phone) NAME=gaps-fixture-lab-phone ;;
    *) echo "usage: $0 [--lab-phone]" >&2; exit 2 ;;
esac
OUT="$ROOT/build/$NAME"

if grep -q 'android.permission.INTERNET' "$HERE/AndroidManifest.xml"; then
    echo "lab/gaps-fixture/AndroidManifest.xml names the INTERNET permission; the fixture must not hold it" >&2
    exit 1
fi
rm -rf "$OUT" && mkdir -p "$OUT/src" "$OUT/classes" "$OUT/dex"
cp -r "$HERE/src/." "$OUT/src/"
if [ "$NAME" = gaps-fixture-lab-phone ]; then
    sed -i 's/static final boolean LAB_PHONE = false;/static final boolean LAB_PHONE = true;/' \
        "$OUT/src/org/visadahyu/lab/gapsfixture/FixtureFlags.java"
    grep -q 'LAB_PHONE = true' "$OUT/src/org/visadahyu/lab/gapsfixture/FixtureFlags.java"
fi
javac --release 17 -XDsuppressNotes -cp "$PLATFORM" -d "$OUT/classes" $(find "$OUT/src" -name '*.java')
"$TOOLS/d8" --min-api 29 --lib "$PLATFORM" --output "$OUT/dex" $(find "$OUT/classes" -name '*.class')
"$TOOLS/aapt2" link -I "$PLATFORM" --manifest "$HERE/AndroidManifest.xml" \
    --min-sdk-version 29 --target-sdk-version 37 --version-code 1 --version-name lab -o "$OUT/unsigned.apk"
if "$TOOLS/aapt2" dump permissions "$OUT/unsigned.apk" | grep -q 'android.permission.INTERNET'; then
    echo "the fixture's APK holds the INTERNET permission" >&2
    exit 1
fi
(cd "$OUT/dex" && zip -q "$OUT/unsigned.apk" classes.dex)
"$TOOLS/zipalign" -f 4 "$OUT/unsigned.apk" "$OUT/aligned.apk"
# A throwaway key: the fixture is never distributed, and no build of it is published (ADR 0048, decision 1).
keytool -genkeypair -keystore "$OUT/lab.keystore" -storepass gapslab -keypass gapslab \
    -alias lab -keyalg EC -validity 1 -dname "CN=Datapavan lab gaps fixture" >/dev/null 2>&1
"$TOOLS/apksigner" sign 2>/dev/null --ks "$OUT/lab.keystore" --ks-pass pass:gapslab --out "$OUT/$NAME.apk" "$OUT/aligned.apk"
rm -f "$OUT/lab.keystore"
echo "$OUT/$NAME.apk"
