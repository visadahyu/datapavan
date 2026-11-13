#!/usr/bin/env bash
# Checks that a commit builds into the same release APKs twice (docs/RELEASE.md, ADR 0024 point 6): those
# of Datapavan Basic and Datapavan Advanced (ADR 0045). It clones the commit into two fresh directories
# with different paths and builds the unsigned release APKs in each with no build cache, each edition in
# a Gradle run of its own, as F-Droid builds each on its own: Basic first in the first directory, and
# Advanced first in the second, so that nothing one edition leaves behind can change the other. It fails
# unless each edition's two files are identical. On a difference it lists the entries that differ;
# diffoscope, where installed, shows how. F-Droid compares in the same way, so a difference here would
# keep it from publishing the project's signed APKs.
#
# Needs what the normal build needs (ANDROID_HOME, the NDK, the pinned Rust toolchain). Builds each
# edition twice.
#
#   scripts/reproducible.sh [commit, default HEAD] [file to keep Basic's APK in] [file to keep Advanced's APK in]
#
# The files are kept only if every pair of builds agrees.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMMIT="$(git -C "$ROOT" rev-parse "${1:-HEAD}")"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# Builds the release APKs into $WORK/<name>-basic.apk and $WORK/<name>-advanced.apk, in the order given
# after the name.
build() {
    local name=$1
    shift
    local dir="$WORK/$name/datapavan"
    git clone -q --no-local "$ROOT" "$dir"
    git -C "$dir" checkout -q "$COMMIT"
    # Where the SDK is, if this checkout says so rather than ANDROID_HOME.
    [ ! -f "$ROOT/android/local.properties" ] || cp "$ROOT/android/local.properties" "$dir/android/"
    local gradle=(./gradlew -q --no-daemon --no-build-cache --no-configuration-cache)
    for edition in "$@"; do
        local own=()
        # Advanced keeps a task history of its own (android/app/build.gradle.kts).
        [ "$edition" = basic ] || own=(--project-cache-dir .gradle-advanced)
        (cd "$dir/android" && "${gradle[@]}" -Pdatapavan.edition="$edition" "${own[@]}" :app:assembleRelease)
    done
    cp "$dir/android/app/build/outputs/apk/release/app-release-unsigned.apk" "$WORK/$name-basic.apk"
    cp "$dir/android/app/build-advanced/outputs/apk/release/app-release-unsigned.apk" "$WORK/$name-advanced.apk"
}

# Compares the two builds of one edition ($1: basic or advanced); shows how they differ when they do.
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
build first basic advanced
build second-with-a-longer-path advanced basic

ok=0
compare basic || ok=1
compare advanced || ok=1
[ "$ok" = 0 ] || exit 1
[ -z "${2:-}" ] || cp "$WORK/first-basic.apk" "$2"
[ -z "${3:-}" ] || cp "$WORK/first-advanced.apk" "$3"
