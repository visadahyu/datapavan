#!/usr/bin/env bash
# Smoke test on a connected device or emulator: installs the debug APK, starts the app, and checks
# that the audit overview appears, that the tracker scan of every app finishes, that About says where
# newer versions are, that the app holds no INTERNET permission, and that it did not crash. It needs nothing but adb, so it adds no test dependencies. CI runs it on an emulator; run
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

# The app cannot learn of a newer version, so About says where newer versions are (Release.kt). The
# settings button scrolls away with the summary's top.
scroll_to_top
tap_id settings || fail "no settings button"
sleep 1
tap_text "About" || fail "settings have no About"
sleep 1
scroll_to "Newer versions" || fail "About does not say where newer versions are"
screen_has "datapavan.org" || fail "About does not show the website's address"
echo "ok: About says where newer versions are"
adb shell input keyevent KEYCODE_BACK
adb shell input keyevent KEYCODE_BACK

# Every screen is protected (ADR 0040): Android lists the app's window as secure; the settings allow
# screenshots, and leaving the screen protects it again at once, without waiting for the minute.
window_secure "$PKG" || fail "the app's window is not protected from screenshots"
if [ "$(adb shell getprop ro.build.version.sdk | tr -d '\r')" -ge 31 ]; then
    window_hides_overlays "$PKG" || fail "Android does not hide other apps' overlays over the app's window"
fi
scroll_to_top
tap_id settings || fail "no settings button"
sleep 1
tap_text "Allow screenshots for one minute" || fail "the settings have no button to allow screenshots"
sleep 1
! window_secure "$PKG" || fail "the app's window stayed protected after screenshots were allowed"
screen_has "Block screenshots now" || fail "the settings do not offer to block screenshots again"
adb shell input keyevent KEYCODE_HOME
for _ in 1 2 3 4 5; do window_secure "$PKG" && break; sleep 1; done
adb shell am start -W -n "$PKG/.MainActivity" >/dev/null
sleep 1
window_secure "$PKG" || fail "the app's window was not protected again after it left the screen"
echo "ok: the screen is protected, screenshots can be allowed, and leaving the screen protects it again"
adb shell input keyevent KEYCODE_BACK

adb shell pidof "$PKG" >/dev/null || fail "the app is no longer running"
if adb logcat -d -b crash 2>/dev/null | grep -q "$PKG"; then
    fail "the app crashed"
fi
echo "ok: no crash"

adb shell rm -f "$DUMP"
echo "== smoke test passed"
