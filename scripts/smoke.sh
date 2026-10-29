#!/usr/bin/env bash
# Smoke test on a connected device or emulator: installs the debug APK, starts the app, and checks
# that the audit overview appears, that the app holds no INTERNET permission, and that it did not
# crash. It needs nothing but adb, so it adds no test dependencies. CI runs it on an emulator; run
# it locally against a phone with USB debugging (set ANDROID_SERIAL if several are connected).
#
#   scripts/smoke.sh [path/to/app-debug.apk]
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APK="${1:-$ROOT/android/app/build/outputs/apk/debug/app-debug.apk}"
PKG=org.visadahyu.datapavan
# shellcheck source=scripts/adb-ui.sh
. "$ROOT/scripts/adb-ui.sh"

fail() {
    echo "SMOKE FAILED: $*" >&2
    adb logcat -d -b crash 2>/dev/null | tail -40 >&2 || true
    exit 1
}

echo "== Smoke test on $(adb shell getprop ro.product.model | tr -d '\r'), Android $(adb shell getprop ro.build.version.release | tr -d '\r')"
adb wait-for-device
adb install -r "$APK" >/dev/null
adb logcat -c
start_audit || fail "the audit overview did not appear within 60 seconds"
scroll_to "Apps checked:" || fail "the app summary is missing"
echo "ok: audit overview shown"

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
