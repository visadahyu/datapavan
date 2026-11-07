#!/usr/bin/env bash
# Runs a really signed release on an emulator (docs/RELEASE.md, "Every release", step 6): the smoke
# test and the shortcut check, then the app must know itself genuine, show the data pack the notes name,
# refuse a damaged copy of that pack and refuse the pack again as not newer. Run
# scripts/verify-signed.py on the same directory first, which checks the files from the published keys.
#
# Only for emulators: it uninstalls Datapavan before and after. Use CI's image (dp-api35-ci): on the
# Android 11 emulator the file picker would not pick a file that adb put in Downloads.
#
#   scripts/verify-signed-release.sh DIRECTORY
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT=${1:?usage: scripts/verify-signed-release.sh DIRECTORY}
PKG=org.visadahyu.datapavan
DOWNLOADS=/sdcard/Download
# shellcheck source=scripts/adb-ui.sh
. "$ROOT/scripts/adb-ui.sh"

fail() {
    echo "VERIFY FAILED: $*" >&2
    if adb shell uiautomator dump "$DUMP" >/dev/null 2>&1; then
        adb shell cat "$DUMP" | grep -o 'text="[^"]\+"' | head -24 >&2 || true
    fi
    exit 1
}
expect() { scroll_to "$1" || { scroll_to_top; scroll_to "$1"; } || fail "expected \"$1\""; echo "ok: $1"; }
field() { sed -n "s/^$1: //p" "$OUT/notes.txt"; }

is_emulator || fail "not an emulator: this script uninstalls Datapavan"
apk="$OUT/$(field APK)"
pack_name=$(field "Data pack")
pack="$OUT/$pack_name"
sequence=$(printf '%s\n' "$pack_name" | sed -n 's/^datapavan-data-\([0-9]*\)\.pack$/\1/p')
[ -f "$apk" ] && [ -f "$pack" ] && [ -n "$sequence" ] || fail "the notes in $OUT name no APK or data pack that is there"

adb uninstall "$PKG" >/dev/null 2>&1 || true
"$ROOT/scripts/smoke.sh" "$apk"
"$ROOT/scripts/verify-shortcuts.sh" | tail -1
start_audit || fail "no overview"
tap_id settings || fail "no settings button"
sleep 1
tap_text "Is this copy genuine?" || fail "no own-copy entry"
sleep 1
expect "It matches Datapavan"
adb shell input keyevent KEYCODE_BACK
sleep 1
for _ in 1 2 3 4 5; do tap_text "Data sources" && break; done
sleep 1
screen_has "Datapavan compares your apps" || fail "data sources did not open"
expect "Data pack $sequence of "
expect "$(tail -n +3 "$pack" | sha256sum | cut -d' ' -f1)"
scroll_to_top

damaged=$(mktemp)
trap 'rm -f "$damaged"' EXIT
python3 -I - "$pack" "$damaged" <<'PY'
import pathlib, sys
data = bytearray(pathlib.Path(sys.argv[1]).read_bytes())
data[-100] ^= 1
pathlib.Path(sys.argv[2]).write_bytes(data)
PY
adb push "$pack" "$DOWNLOADS/$pack_name" >/dev/null
adb push "$damaged" "$DOWNLOADS/datapavan-damaged.pack" >/dev/null

import_pack() {
    local tapped=""
    for _ in 1 2 3; do tap_text "Import a data pack" && tapped=1 && break; done
    [ -n "$tapped" ] || fail "no import button"
    for _ in $(seq 1 10); do
        if screen_has "Recent" || screen_has "Downloads" || screen_has "$1"; then break; fi
        sleep 1
    done
    if ! screen_has "$1"; then
        tap_desc "Show roots" || fail "no list of places"
        sleep 1
        tap_text "Downloads" || fail "no Downloads"
        sleep 2
    fi
    tap_text "$1" || fail "the picker does not show $1"
    sleep 2
}
import_pack datapavan-damaged.pack
expect "The signature does not match"
import_pack "$pack_name"
expect "This pack is not newer than the one in use."
adb shell rm -f "$DOWNLOADS/$pack_name" "$DOWNLOADS/datapavan-damaged.pack"
if adb shell dumpsys package "$PKG" | grep -q "android.permission.INTERNET"; then
    fail "the release holds the INTERNET permission"
fi
adb uninstall "$PKG" >/dev/null
echo "== the signed release passed on the emulator"
