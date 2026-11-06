#!/usr/bin/env bash
# Checks that a commit builds into the same release APK twice (docs/RELEASE.md, ADR 0024 point 6). It
# clones the commit into two fresh directories with different paths, builds the unsigned release APK
# in each with no build cache, and fails unless the two files are identical. On a difference it lists
# the entries that differ; diffoscope, where installed, shows how. F-Droid compares in the same way,
# so a difference here would keep it from publishing the project's signed APK.
#
# Needs what the normal build needs (ANDROID_HOME, the NDK, the pinned Rust toolchain). Takes two full
# builds.
#
#   scripts/reproducible.sh [commit, default HEAD] [file to keep the APK in, if the builds agree]
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMMIT="$(git -C "$ROOT" rev-parse "${1:-HEAD}")"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

build() {
    local dir="$WORK/$1/datapavan"
    git clone -q --no-local "$ROOT" "$dir"
    git -C "$dir" checkout -q "$COMMIT"
    # Where the SDK is, if this checkout says so rather than ANDROID_HOME.
    [ ! -f "$ROOT/android/local.properties" ] || cp "$ROOT/android/local.properties" "$dir/android/"
    (cd "$dir/android" && ./gradlew -q --no-daemon --no-build-cache --no-configuration-cache :app:assembleRelease)
    cp "$dir/android/app/build/outputs/apk/release/app-release-unsigned.apk" "$WORK/$1.apk"
}

echo "== Building $COMMIT twice"
build first
build second-with-a-longer-path

a=$(sha256sum "$WORK/first.apk" | cut -d' ' -f1)
b=$(sha256sum "$WORK/second-with-a-longer-path.apk" | cut -d' ' -f1)
if [ "$a" = "$b" ]; then
    echo "== reproducible: both builds are $a"
    [ -z "${2:-}" ] || cp "$WORK/first.apk" "$2"
    exit 0
fi

echo "NOT REPRODUCIBLE: $a and $b" >&2
mkdir -p "$WORK/x" "$WORK/y"
(cd "$WORK/x" && unzip -q "$WORK/first.apk")
(cd "$WORK/y" && unzip -q "$WORK/second-with-a-longer-path.apk")
diff -rq "$WORK/x" "$WORK/y" >&2 || true
if command -v diffoscope >/dev/null; then
    diffoscope --text - "$WORK/first.apk" "$WORK/second-with-a-longer-path.apk" | head -200 >&2 || true
fi
exit 1
