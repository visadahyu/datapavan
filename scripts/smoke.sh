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
DUMP=/sdcard/datapavan-smoke.xml

fail() {
    echo "SMOKE FAILED: $*" >&2
    adb logcat -d -b crash 2>/dev/null | tail -40 >&2 || true
    exit 1
}

screen_has() {
    adb shell uiautomator dump "$DUMP" >/dev/null 2>&1 || return 1
    adb shell cat "$DUMP" 2>/dev/null | grep -q "text=\"$1"
}

echo "== Smoke test on $(adb shell getprop ro.product.model | tr -d '\r'), Android $(adb shell getprop ro.build.version.release | tr -d '\r')"
adb wait-for-device
# Emulators start without a secure lock screen; a phone must already be unlocked.
adb shell input keyevent KEYCODE_WAKEUP
adb shell wm dismiss-keyguard >/dev/null 2>&1 || true
adb install -r "$APK" >/dev/null
# English UI for the text checks; app-specific locales exist from Android 13.
adb shell cmd locale set-app-locales "$PKG" --locales en >/dev/null 2>&1 || true
adb logcat -c
adb shell am force-stop "$PKG"
adb shell am start -n "$PKG/.MainActivity" >/dev/null

for _ in $(seq 1 60); do
    screen_has "This phone" && break
    sleep 1
done
screen_has "This phone" || fail "the audit overview did not appear within 60 seconds"
screen_has "Apps checked:" || fail "the app summary is missing"
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
