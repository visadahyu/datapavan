#!/usr/bin/env bash
# End-to-end check of the audit's findings (milestone M2) on an emulator. A test fixture app (see
# scripts/fixture-app) is installed and given risky access over adb, and, where adb can become root,
# the device gets a user-installed certificate authority. Datapavan must then report each of them,
# and the USB debugging that every emulator has on. Last, the fixture is installed again under the
# package name of Exclave, whose official keys data/app-signers records completely (ADR 0018), and it
# must be reported as a modified copy. Everything is undone afterwards.
#
# Wireless debugging cannot be checked here: Android switches it straight back off without a Wi-Fi
# network that allows it. The unit tests cover that rule.
#
# Only for emulators: it changes device settings. Run scripts/smoke.sh first, which installs the
# debug APK.
#
#   scripts/verify-audit.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FIXTURE=org.visadahyu.datapavan.fixture
IMPOSTOR=com.github.dyhkwong.sagernet
# shellcheck source=scripts/adb-ui.sh
. "$ROOT/scripts/adb-ui.sh"

if [ "$(adb shell getprop ro.kernel.qemu | tr -d '\r')" != "1" ] && [ "$(adb shell getprop ro.boot.qemu | tr -d '\r')" != "1" ]; then
    echo "verify-audit.sh changes device settings and runs on emulators only" >&2
    exit 2
fi

CA_FILE=""
ROOTED=""
cleanup() {
    adb shell settings delete secure enabled_accessibility_services >/dev/null 2>&1 || true
    adb uninstall "$FIXTURE" >/dev/null 2>&1 || true
    adb uninstall "$IMPOSTOR" >/dev/null 2>&1 || true
    if [ -n "$CA_FILE" ]; then
        adb shell rm -f "/data/misc/user/0/cacerts-added/$CA_FILE" >/dev/null 2>&1 || true
    fi
    if [ -n "$ROOTED" ]; then
        adb unroot >/dev/null 2>&1 || true
        adb wait-for-device
    fi
    adb shell rm -f "$DUMP" >/dev/null 2>&1 || true
}
trap cleanup EXIT

fail() {
    echo "VERIFY FAILED: $*" >&2
    # What was on screen, in the log and as files that CI keeps with the screenshots.
    local out="$ROOT/build/screenshots"
    mkdir -p "$out"
    adb exec-out screencap -p >"$out/verify-failure.png" 2>/dev/null || true
    echo "Accessibility setting: $(adb shell settings get secure enabled_accessibility_services | tr -d '\r')" >&2
    adb shell dumpsys accessibility 2>/dev/null | grep -i -E 'fixture|enabled services|bound services|crashed' | head -10 >&2 || true
    if adb shell uiautomator dump "$DUMP" >&2; then
        adb shell cat "$DUMP" >"$out/verify-failure.xml"
        echo "On screen:" >&2
        grep -o 'text="[^"]\+"' "$out/verify-failure.xml" | head -40 >&2 || true
    fi
    exit 1
}

# Looks below the current position first, then once more from the top: on a tall screen an item can
# already be above the place where the previous one was found.
expect() {
    scroll_to "$1" || { scroll_to_top; scroll_to "$1"; } || fail "expected \"$1\" on screen"
    echo "ok: $1"
}

# Enables the fixture's accessibility service. While Android is still processing the fresh install,
# it can write its own list of enabled services back over the setting and drop the fixture (seen on
# CI's slower emulator). So the setting is written until Android reports the service as enabled in
# two checks two seconds apart.
enable_fixture_accessibility() {
    local streak=0
    for _ in $(seq 1 20); do
        if adb shell dumpsys accessibility | grep -q "Enabled services:{.*$FIXTURE/"; then
            streak=$((streak + 1))
            [ "$streak" -ge 2 ] && return 0
        else
            streak=0
            adb shell settings put secure enabled_accessibility_services "$FIXTURE/$FIXTURE.FixtureAccessibilityService"
            adb shell settings put secure accessibility_enabled 1
        fi
        sleep 2
    done
    return 1
}

echo "== Audit verification on Android $(adb shell getprop ro.build.version.release | tr -d '\r')"

# The fixture: a VPN app with an enabled accessibility service, microphone, camera and location,
# allowed to install apps, installed over adb rather than from a store, and with classes that match
# a tracker signature (Sentry) and a traffic-sharing SDK (Pawns, data/sdks).
fixture_apk=$("$ROOT/scripts/fixture-app/build.sh" | tail -1)
# Each build signs with a new throwaway key, so a fixture left behind would block the install.
adb uninstall "$FIXTURE" >/dev/null 2>&1 || true
adb install -r -g "$fixture_apk" >/dev/null
adb shell appops set "$FIXTURE" REQUEST_INSTALL_PACKAGES allow

# A user-installed certificate authority needs root to place; Google APIs emulator images allow it.
adb root >/dev/null 2>&1 || true
adb wait-for-device
if [ "$(adb shell id -u | tr -d '\r')" = "0" ]; then
    ROOTED=1
    work=$(mktemp -d)
    openssl req -x509 -newkey rsa:2048 -nodes -keyout "$work/ca.key" -out "$work/ca.pem" \
        -subj "/CN=Datapavan verification CA" -days 1 2>/dev/null
    CA_FILE="$(openssl x509 -subject_hash_old -in "$work/ca.pem" -noout).0"
    openssl x509 -in "$work/ca.pem" -outform DER -out "$work/$CA_FILE"
    adb shell mkdir -p /data/misc/user/0/cacerts-added
    adb push "$work/$CA_FILE" /data/misc/user/0/cacerts-added/ >/dev/null 2>&1
    adb shell "chown -R system:system /data/misc/user/0/cacerts-added; chmod 644 /data/misc/user/0/cacerts-added/*; restorecon -R /data/misc/user/0/cacerts-added" >/dev/null 2>&1
    rm -rf "$work"
else
    echo "skip: adb cannot become root here, so no certificate authority is installed"
fi

enable_fixture_accessibility || fail "Android does not keep the fixture's accessibility service enabled"

start_audit || fail "the audit overview did not appear"
expect "USB debugging is on"
[ -z "$CA_FILE" ] || expect "Extra certificate authority installed"
expect "No hardware check available"
wait_for_tracker_scan || fail "the tracker scan did not finish"

tap_text "Datapavan test fixture" || fail "the fixture app is not listed"
sleep 1
# The fixture's own page, not another app's: its name above the findings heading.
screen_has "What we found" && screen_has "Datapavan test fixture" || fail "the fixture's page did not open"
scroll_to_top
expect "VPN app that can control the phone"
expect "Can install other apps"
expect "Microphone, camera or location"
expect "Not from a known app store"
expect "Contains trackers"
expect "Sentry (crash reporting)"
# Above the tracker list: the finding card, then the SDK section.
scroll_to_top
expect "Can share your internet connection"
expect "Pawns SDK by IPRoyal"

# A known app signed by someone else.
impostor_apk=$("$ROOT/scripts/fixture-app/build.sh" "$IMPOSTOR" | tail -1)
adb uninstall "$FIXTURE" >/dev/null 2>&1 || true
adb uninstall "$IMPOSTOR" >/dev/null 2>&1 || true
adb install -r "$impostor_apk" >/dev/null
start_audit || fail "the audit overview did not appear with the impostor installed"
tap_text "Datapavan test fixture" || fail "the impostor is not listed"
sleep 1
scroll_to_top
expect "Modified copy"
expect "This copy of Exclave is not signed by its developer."

echo "== audit verification passed"
