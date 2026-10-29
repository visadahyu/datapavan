#!/usr/bin/env bash
# Compares the classes that Datapavan's DEX parser finds with what the SDK's dexdump finds, for every
# DEX file in the given APKs. Use it on real apps after changing core/engine/src/dex.rs, for example
# on APKs pulled from a test phone with `adb shell pm path` and `adb pull`. Needs the Android SDK
# build tools (dexdump) and unzip.
#
#   scripts/compare-dex.sh app.apk [more.apk ...]
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SDK="${ANDROID_HOME:-$HOME/Android/Sdk}"
DEXDUMP="$SDK/build-tools/37.0.0/dexdump"
[ -x "$DEXDUMP" ] || { echo "dexdump not found at $DEXDUMP; set ANDROID_HOME" >&2; exit 2; }

cargo build --quiet --release --locked --manifest-path "$ROOT/core/Cargo.toml" --example dex_classes
PARSER="$ROOT/core/target/release/examples/dex_classes"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
files=0 classes=0 differences=0
for apk in "$@"; do
    rm -rf "$work/dex" && mkdir -p "$work/dex"
    unzip -q -o "$apk" 'classes*.dex' -d "$work/dex" 2>/dev/null || true
    for dex in "$work"/dex/classes*.dex; do
        [ -f "$dex" ] || continue
        files=$((files + 1))
        "$DEXDUMP" "$dex" 2>/dev/null | sed -n "s/^  Class descriptor  : 'L\(.*\);'$/\1/p" | tr / . >"$work/expected"
        if ! "$PARSER" "$dex" >"$work/actual" 2>"$work/error"; then
            echo "$(basename "$apk") $(basename "$dex"): $(cat "$work/error")"
            differences=$((differences + 1))
            continue
        fi
        classes=$((classes + $(wc -l <"$work/actual")))
        if ! cmp -s "$work/expected" "$work/actual"; then
            echo "$(basename "$apk") $(basename "$dex"): differs from dexdump"
            diff "$work/expected" "$work/actual" | head -5
            differences=$((differences + 1))
        fi
    done
done
echo "== $files DEX files, $classes classes, $differences differences"
[ "$differences" -eq 0 ]
