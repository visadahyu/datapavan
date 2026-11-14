#!/usr/bin/env bash
# End-to-end check of data pack imports (ADR 0017) on an emulator or phone. It makes packs from the
# debug APK's own payload with the test key, which debug builds trust, puts them in Downloads, and
# imports them through the system file picker: a damaged pack must be refused, a newer one used,
# the same one again refused as not newer, and the imported pack must still be in use after a
# restart. The newer pack carries an old date, so the overview must warn that the data is old, and
# the data sources screen must show the fingerprint that sha256sum gives. The packs and the imported
# data are removed afterwards.
#
# Checked on emulators. On a Galaxy A40 (Android 11), a file pushed over adb stays "pending" in the
# media store, so the file picker greys it out and the check cannot pick it; a file saved by a browser
# or a messenger is not affected.
#
# Run scripts/smoke.sh first, which installs the debug APK.
#
#   scripts/verify-datapack.sh [path/to/app-debug.apk]
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APK="${1:-$ROOT/android/app/build/outputs/apk/debug/app-debug.apk}"
PKG=org.visadahyu.datapavan
DOWNLOADS=/sdcard/Download
# shellcheck source=scripts/adb-ui.sh
. "$ROOT/scripts/adb-ui.sh"

WORK=$(mktemp -d)
cleanup() {
    adb shell rm -f "$DOWNLOADS/datapavan-test-*.pack" >/dev/null 2>&1 || true
    adb shell run-as "$PKG" rm -rf no_backup/datapack >/dev/null 2>&1 || true
    adb shell rm -f "$DUMP" >/dev/null 2>&1 || true
    rm -rf "$WORK"
}
trap cleanup EXIT

fail() {
    echo "VERIFY FAILED: $*" >&2
    local out="$ROOT/build/screenshots"
    mkdir -p "$out"
    adb exec-out screencap -p >"$out/verify-datapack-failure.png" 2>/dev/null || true
    if adb shell uiautomator dump "$DUMP" >&2; then
        adb shell cat "$DUMP" >"$out/verify-datapack-failure.xml"
        echo "On screen:" >&2
        grep -o 'text="[^"]\+"' "$out/verify-datapack-failure.xml" | head -40 >&2 || true
    fi
    exit 1
}

expect() {
    scroll_to "$1" || fail "expected \"$1\" on screen"
    echo "ok: $1"
}

# The overview lists every app with a finding before its last line, so on a phone in daily use the
# data sources button can be many screens down.
open_data_sources() {
    tap_id settings || fail "no settings button"
    within 10 gone_id settings || fail "the settings did not open within 10 s"
    for _ in 1 2 3 4 5; do
        tap_text "Data sources" && break
    done
    within 10 screen_has "Datapavan compares your apps" || fail "the data sources screen did not open within 10 s"
}

# Imports $1 from Downloads through the system file picker. The picker opens where it was last used,
# so it may already show Downloads. Every dataset adds its licence above the button, so it can be
# further down than one call of tap_text scrolls.
import_pack() {
    local tapped=""
    for _ in 1 2 3; do
        tap_text "Import a data pack" && tapped=1 && break
    done
    [ -n "$tapped" ] || fail "no import button"
    for _ in $(seq 1 10); do
        screen_has "Recent" || screen_has "Downloads" || screen_has "$1" && break
        sleep 1
    done
    if ! screen_has "$1"; then
        tap_desc "Show roots" || fail "the file picker has no list of places"
        within 10 screen_has "Downloads" || fail "the file picker's list of places showed no Downloads within 10 s"
        tap_text "Downloads" || fail "the file picker shows no Downloads"
        within 10 screen_has "$1" || echo "  the file picker did not show $1 within 10 s of opening Downloads"
    fi
    tap_text "$1" || fail "the file picker does not show $1"
    sleep 2
}

echo "== Data pack import verification on Android $(adb shell getprop ro.build.version.release | tr -d '\r')"

unzip -p "$APK" assets/data/bundled.payload >"$WORK/payload"
sequence=$(sed -n 's/^sequence \([0-9]*\)$/\1/p' "$WORK/payload" | head -1)
[ -n "$sequence" ] || fail "the APK has no data pack payload"
newer=$((sequence + 1))
"$ROOT/scripts/datapack-test.py" "$WORK/payload" "$WORK/datapavan-test-damaged.pack" --sequence "$((sequence + 2))" --corrupt
"$ROOT/scripts/datapack-test.py" "$WORK/payload" "$WORK/datapavan-test-newer.pack" --sequence "$newer" --date 2025-01-01
fingerprint=$(tail -n +3 "$WORK/datapavan-test-newer.pack" | sha256sum | cut -c1-64)
adb shell run-as "$PKG" rm -rf no_backup/datapack >/dev/null 2>&1 || true
for pack in "$WORK"/*.pack; do
    adb push "$pack" "$DOWNLOADS/" >/dev/null
done

start_audit || fail "the audit overview did not appear"
open_data_sources
expect "Data pack $sequence of "

import_pack datapavan-test-damaged.pack
expect "The signature does not match"
import_pack datapavan-test-newer.pack
expect "Data pack $newer is now in use."
import_pack datapavan-test-newer.pack
expect "This pack is not newer than the one in use."

# The imported pack is checked again and used after a restart, and its data is old.
start_audit || fail "the audit overview did not appear after a restart"
scroll_to_top
expect "This data is from "
open_data_sources
expect "Data pack $newer of "
screen_has "Data pack $newer of .*, imported\\." || fail "the imported pack is not in use after a restart"
expect "$fingerprint"

echo "== data pack verification passed"
