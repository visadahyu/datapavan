#!/usr/bin/env bash
# Smoke test on a connected device or emulator: installs the debug APK, starts the app, and checks
# that the audit overview appears, that the tracker scan of every app finishes, that the app holds
# no INTERNET permission, and that it did not crash. It needs nothing but adb, so it adds no test dependencies. CI runs it on an emulator; run
# it locally against a phone with USB debugging (set ANDROID_SERIAL if several are connected).
#
#   scripts/smoke.sh [path/to/app-debug.apk]
#
# INSTALL_ABI=armeabi-v7a installs the app as a 32-bit program, as on phones whose Android is 32-bit.
# CI's emulator cannot run 32-bit ARM code; a phone with a 64-bit Android that still runs 32-bit apps
# can, and so can the Android 11 (API 30) emulator, which translates ARM code.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APK="${1:-$ROOT/android/app/build/outputs/apk/debug/app-debug.apk}"
PKG=org.visadahyu.datapavan
# shellcheck source=scripts/adb-ui.sh
. "$ROOT/scripts/adb-ui.sh"

fail() {
    echo "SMOKE FAILED: $*" >&2
    adb logcat -d -b crash 2>/dev/null | tail -40 >&2 || true
    # What was on screen, in the log and as a file that CI keeps with the screenshots.
    mkdir -p "$ROOT/build/screenshots"
    adb exec-out screencap -p >"$ROOT/build/screenshots/smoke-failure.png" 2>/dev/null || true
    if adb shell uiautomator dump "$DUMP" >/dev/null 2>&1; then
        echo "On screen:" >&2
        adb shell cat "$DUMP" | grep -o 'text="[^"]\+"' | head -40 >&2 || true
    fi
    exit 1
}

echo "== Smoke test on $(adb shell getprop ro.product.model | tr -d '\r'), Android $(adb shell getprop ro.build.version.release | tr -d '\r')"
adb wait-for-device
adb install -r ${INSTALL_ABI:+--abi "$INSTALL_ABI"} "$APK" >/dev/null
if [ -n "${INSTALL_ABI:-}" ]; then
    abi=$(adb shell dumpsys package "$PKG" | tr -d '\r' | sed -n 's/.*primaryCpuAbi=\([^ ]*\).*/\1/p' | head -1)
    [ "$abi" = "$INSTALL_ABI" ] || fail "installed as $abi, not $INSTALL_ABI"
    echo "ok: installed as $abi"
fi
adb logcat -c
start_audit || fail "the audit overview did not appear within 60 seconds"
scroll_to "Your plan" || fail "the summary has no plan"
echo "ok: summary shown"
wait_for_tracker_scan || fail "the tracker scan did not finish within 5 minutes"
echo "ok: tracker scan finished"

if adb shell dumpsys package "$PKG" | grep -q "android.permission.INTERNET"; then
    fail "the installed app holds the INTERNET permission"
fi
echo "ok: no INTERNET permission"

adb shell pidof "$PKG" >/dev/null || fail "the app is no longer running"
if adb logcat -d -b crash 2>/dev/null | grep -q "$PKG"; then
    fail "the app crashed"
fi
echo "ok: no crash"

adb shell rm -f "$DUMP"
echo "== smoke test passed"
