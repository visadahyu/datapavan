#!/usr/bin/env bash
# Checks that a commit builds into the same release APKs twice (docs/RELEASE.md, ADR 0024 point 6):
# the audit app's and Watch's (ADR 0029). It clones the commit into two fresh directories with different
# paths and builds the unsigned release APKs in each with no build cache, both apps in one Gradle run in
# the first and each app in a run of its own in the second, as F-Droid builds each app on its own. It
# fails unless each app's two files are identical. On a difference it lists the entries that differ;
# diffoscope, where installed, shows how. F-Droid compares in the same way, so a difference here would
# keep it from publishing the project's signed APKs.
#
# Needs what the normal build needs (ANDROID_HOME, the NDK, the pinned Rust toolchain). Builds each
# app twice.
#
#   scripts/reproducible.sh [commit, default HEAD] [file to keep the audit app's APK in] [file to keep Watch's APK in]
#
# The files are kept only if every pair of builds agrees.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMMIT="$(git -C "$ROOT" rev-parse "${1:-HEAD}")"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# Builds the release APKs into $WORK/<name>-app.apk and $WORK/<name>-watch.apk; "together" builds both
# apps in one Gradle run, "apart" each in a run of its own.
build() {
    local name=$1 how=$2
    local dir="$WORK/$name/datapavan"
    git clone -q --no-local "$ROOT" "$dir"
    git -C "$dir" checkout -q "$COMMIT"
    # Where the SDK is, if this checkout says so rather than ANDROID_HOME.
    [ ! -f "$ROOT/android/local.properties" ] || cp "$ROOT/android/local.properties" "$dir/android/"
    local gradle=(./gradlew -q --no-daemon --no-build-cache --no-configuration-cache)
    if [ "$how" = together ]; then
        (cd "$dir/android" && "${gradle[@]}" :app:assembleRelease :watch:assembleRelease)
    else
        (cd "$dir/android" && "${gradle[@]}" :app:assembleRelease)
        (cd "$dir/android" && "${gradle[@]}" :watch:assembleRelease)
    fi
    cp "$dir/android/app/build/outputs/apk/release/app-release-unsigned.apk" "$WORK/$name-app.apk"
    cp "$dir/android/watch/build/outputs/apk/release/watch-release-unsigned.apk" "$WORK/$name-watch.apk"
}

# Compares the two builds of one app ($1: app or watch); shows how they differ when they do.
compare() {
    local first="$WORK/first-$1.apk" second="$WORK/second-with-a-longer-path-$1.apk"
    local a b
    a=$(sha256sum "$first" | cut -d' ' -f1)
    b=$(sha256sum "$second" | cut -d' ' -f1)
    if [ "$a" = "$b" ]; then
        echo "== $1: reproducible, both builds are $a"
        return 0
    fi
    echo "NOT REPRODUCIBLE ($1): $a and $b" >&2
    rm -rf "$WORK/x" "$WORK/y"
    mkdir -p "$WORK/x" "$WORK/y"
    (cd "$WORK/x" && unzip -q "$first")
    (cd "$WORK/y" && unzip -q "$second")
    diff -rq "$WORK/x" "$WORK/y" >&2 || true
    if command -v diffoscope >/dev/null; then
        diffoscope --text - "$first" "$second" | head -200 >&2 || true
    fi
    return 1
}

echo "== Building $COMMIT twice"
build first together
build second-with-a-longer-path apart

ok=0
compare app || ok=1
compare watch || ok=1
[ "$ok" = 0 ] || exit 1
[ -z "${2:-}" ] || cp "$WORK/first-app.apk" "$2"
[ -z "${3:-}" ] || cp "$WORK/first-watch.apk" "$3"
