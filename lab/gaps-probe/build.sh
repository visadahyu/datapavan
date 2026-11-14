#!/usr/bin/env bash
# Builds the lab's gaps probe (ADR 0048) with the SDK's build tools only (javac, d8, aapt2, apksigner), as
# scripts/fixture-app/build.sh does: no Gradle, platform APIs only, and a throwaway key made for each build.
# Output: build/gaps-probe/gaps-probe.apk under the repository root.
#
#   lab/gaps-probe/build.sh [--peer]
#
# --peer builds the same code as a second app, org.visadahyu.lab.gapsprobe.peer, into build/gaps-probe-peer/:
# the loopback behaviour needs two apps that may open sockets, and the fixture may not (ADR 0048, decision 5).
# It targets API 37, so that the newest version's limits for apps apply to it.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
SDK="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-$HOME/Android/sdk}}"
TOOLS="$SDK/build-tools/37.0.0"
PLATFORM="$SDK/platforms/android-37.0/android.jar"
NAME=gaps-probe
case "${1:-}" in
    "") ;;
    --peer) NAME=gaps-probe-peer ;;
    *) echo "usage: $0 [--peer]" >&2; exit 2 ;;
esac
OUT="$ROOT/build/$NAME"

rm -rf "$OUT" && mkdir -p "$OUT/classes" "$OUT/dex"
if [ "$NAME" = gaps-probe-peer ]; then
    sed 's/android:label="Gaps probe (lab)"/android:label="Gaps probe peer (lab)"/' "$HERE/AndroidManifest.xml" >"$OUT/AndroidManifest.xml"
    RENAME=(--rename-manifest-package org.visadahyu.lab.gapsprobe.peer)
else
    cp "$HERE/AndroidManifest.xml" "$OUT/AndroidManifest.xml"
    RENAME=()
fi
javac --release 17 -XDsuppressNotes -cp "$PLATFORM" -d "$OUT/classes" $(find "$HERE/src" -name '*.java')
"$TOOLS/d8" --min-api 29 --lib "$PLATFORM" --output "$OUT/dex" $(find "$OUT/classes" -name '*.class')
"$TOOLS/aapt2" link -I "$PLATFORM" --manifest "$OUT/AndroidManifest.xml" \
    --min-sdk-version 29 --target-sdk-version 37 --version-code 1 --version-name lab \
    "${RENAME[@]}" -o "$OUT/unsigned.apk"
(cd "$OUT/dex" && zip -q "$OUT/unsigned.apk" classes.dex)
"$TOOLS/zipalign" -f 4 "$OUT/unsigned.apk" "$OUT/aligned.apk"
# A throwaway key: the probe is never distributed, and no build of it is published (ADR 0048, decision 1).
keytool -genkeypair -keystore "$OUT/lab.keystore" -storepass gapslab -keypass gapslab \
    -alias lab -keyalg EC -validity 1 -dname "CN=Datapavan lab gaps probe" >/dev/null 2>&1
"$TOOLS/apksigner" sign 2>/dev/null --ks "$OUT/lab.keystore" --ks-pass pass:gapslab --out "$OUT/$NAME.apk" "$OUT/aligned.apk"
rm -f "$OUT/lab.keystore"
echo "$OUT/$NAME.apk"
