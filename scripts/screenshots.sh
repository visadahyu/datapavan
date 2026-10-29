#!/usr/bin/env bash
# Screenshots of the audit overview in every UI language and in the pseudo-locales (accented and
# right-to-left), each with an accessibility check of the screen (scripts/a11y-check.py). CI keeps
# the screenshots as a build artifact, so layout changes in every language can be reviewed.
#
# Needs Android 13 or newer for app-specific languages, and python3 for the check. Run
# scripts/smoke.sh first, which installs the debug APK.
#
#   scripts/screenshots.sh [output directory, default build/screenshots]
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${1:-$ROOT/build/screenshots}"
PKG=org.visadahyu.datapavan
# shellcheck source=scripts/adb-ui.sh
. "$ROOT/scripts/adb-ui.sh"

if [ "$(adb shell getprop ro.build.version.sdk | tr -d '\r')" -lt 33 ]; then
    echo "skip: app-specific languages need Android 13 or newer"
    exit 0
fi

mkdir -p "$OUT"
density=$(adb shell wm density | tr -d '\r' | sed -n 's/.*: \([0-9]*\)$/\1/p' | tail -1)
min_px=$((48 * density / 160))
failed=0
trap 'adb shell cmd locale set-app-locales "$PKG" --locales en >/dev/null 2>&1 || true; adb shell rm -f "$DUMP" >/dev/null 2>&1 || true' EXIT

echo "== Screenshots and accessibility check on Android $(adb shell getprop ro.build.version.release | tr -d '\r')"
adb shell input keyevent KEYCODE_WAKEUP
adb shell wm dismiss-keyguard >/dev/null 2>&1 || true
for locale in en fr de fa en-XA ar-XB; do
    adb shell cmd locale set-app-locales "$PKG" --locales "$locale"
    adb shell am force-stop "$PKG"
    adb shell am start -n "$PKG/.MainActivity" >/dev/null
    if ! wait_for_overview; then
        echo "SCREENSHOTS FAILED: the overview did not appear in $locale" >&2
        exit 1
    fi
    # The top of the overview, then one screen further down, where the app list starts.
    for part in 1 2; do
        if [ "$part" = 2 ]; then
            swipe_up
            adb shell uiautomator dump "$DUMP" >/dev/null
        fi
        adb exec-out screencap -p >"$OUT/overview-$locale-$part.png"
        adb shell cat "$DUMP" >"$OUT/overview-$locale-$part.xml"
        python3 -I "$ROOT/scripts/a11y-check.py" "$OUT/overview-$locale-$part.xml" "$min_px" || failed=1
    done
    echo "ok: $locale"
done

[ "$failed" -eq 0 ] || { echo "SCREENSHOTS FAILED: accessibility problems above" >&2; exit 1; }
echo "== screenshots in ${OUT#"$ROOT/"}, accessibility check passed"
