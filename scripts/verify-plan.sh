#!/usr/bin/env bash
# End-to-end check of the remediation plan (ADR 0026) on an emulator, with a debug build of Datapavan
# installed. The test fixture (scripts/fixture-app), a VPN app with an enabled accessibility service,
# must be the plan's first card. Its care step comes before the screens; when the accessibility
# service is turned off while Settings is open, the card, the session's summary and the journal must
# say so, with what to turn back on. Turned on again, the change must show as come back. At the
# medium level the fixture's other reasons and USB debugging join; both are kept as they are, and the
# next session must then have nothing to do. Last, the journal is deleted. Everything is undone
# afterwards. The check three days after a session needs a clock that moves; the unit tests cover it.
#
# Only for emulators: it changes device settings.
#
#   scripts/verify-plan.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FIXTURE=org.visadahyu.datapavan.fixture
DATAPAVAN=org.visadahyu.datapavan
# The app shows names inside Unicode isolates (ui/Bidi.kt), so the expected texts carry them too.
NAME=$'\u2068'"Datapavan test fixture"$'\u2069'
# shellcheck source=scripts/adb-ui.sh
. "$ROOT/scripts/adb-ui.sh"

if [ "$(adb shell getprop ro.kernel.qemu | tr -d '\r')" != "1" ] && [ "$(adb shell getprop ro.boot.qemu | tr -d '\r')" != "1" ]; then
    echo "verify-plan.sh changes device settings and runs on emulators only" >&2
    exit 2
fi

cleanup() {
    adb shell appops set "$DATAPAVAN" GET_USAGE_STATS default >/dev/null 2>&1 || true
    adb shell settings delete secure enabled_accessibility_services >/dev/null 2>&1 || true
    adb uninstall "$FIXTURE" >/dev/null 2>&1 || true
    adb shell run-as "$DATAPAVAN" rm -f files/journal.txt >/dev/null 2>&1 || true
    adb shell rm -f "$DUMP" >/dev/null 2>&1 || true
}
trap cleanup EXIT

fail() {
    echo "VERIFY FAILED: $*" >&2
    local out="$ROOT/build/screenshots"
    mkdir -p "$out"
    adb exec-out screencap -p >"$out/verify-plan-failure.png" 2>/dev/null || true
    if adb shell uiautomator dump "$DUMP" >/dev/null 2>&1; then
        adb shell cat "$DUMP" >"$out/verify-plan-failure.xml"
        echo "On screen:" >&2
        grep -o 'text="[^"]\+"' "$out/verify-plan-failure.xml" | head -40 >&2 || true
    fi
    exit 1
}

expect() {
    scroll_to "$1" || { scroll_to_top; scroll_to "$1"; } || fail "expected \"$1\" on screen"
    echo "ok: $1"
}

tap() {
    tap_text "$1" || { scroll_to_top; tap_text "$1"; } || fail "nothing to tap called \"$1\""
    sleep 1
}

# As in verify-audit.sh: Android can drop a freshly installed service from the setting, so it is
# written until two checks two seconds apart see it enabled.
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

echo "== Plan verification on Android $(adb shell getprop ro.build.version.release | tr -d '\r')"

fixture_apk=$("$ROOT/scripts/fixture-app/build.sh" | tail -1)
adb uninstall "$FIXTURE" >/dev/null 2>&1 || true
adb install -r -g "$fixture_apk" >/dev/null
adb shell appops set "$FIXTURE" REQUEST_INSTALL_PACKAGES allow
adb shell appops set "$DATAPAVAN" GET_USAGE_STATS allow
adb shell run-as "$DATAPAVAN" rm -f files/journal.txt >/dev/null 2>&1 || true
enable_fixture_accessibility || fail "Android does not keep the fixture's accessibility service enabled"

start_audit || fail "the audit overview did not appear"
wait_for_tracker_scan || fail "the tracker scan did not finish"
scroll_to_top
expect "Your plan"
expect "First: $NAME can read the screen or act for you"

# Light: the fixture's control access is the only card; the care step comes first.
tap "Open the plan"
expect "Light"
expect "· $NAME can read the screen or act for you"
tap "Start"
expect "1 of 1"
expect "If someone else may have installed this app"
tap "I understand, continue"
tap "Accessibility"
# Settings is open; the service goes off as if the user had switched it there.
adb shell settings delete secure enabled_accessibility_services
adb shell settings put secure accessibility_enabled 0
sleep 2
adb shell input keyevent KEYCODE_BACK
expect "Changed: Accessibility service removed"
tap "Finish"
expect "$NAME: Accessibility service removed"
expect "Everything is in the journal"
tap "Done"

# The overview runs the audit again; the journal holds the change and how to undo it.
wait_for_overview || fail "the overview did not come back"
scroll_to_top
tap "Journal"
expect "Changed: Accessibility service removed"
expect "To undo, turn back on: Accessibility service"
adb shell input keyevent KEYCODE_BACK

# Turned on again: the change has come back.
enable_fixture_accessibility || fail "the accessibility service did not come back on"
start_audit || fail "the audit overview did not appear after the service came back"
wait_for_tracker_scan || fail "the tracker scan did not finish after the service came back"
scroll_to_top
expect "Something you changed through the plan has come back"
tap "Journal"
expect "Has come back since: Accessibility service removed"
adb shell input keyevent KEYCODE_BACK

# Medium: the fixture's other reasons join its card, and USB debugging is a card of its own.
scroll_to_top
tap "Open the plan"
tap "Medium"
expect "· USB debugging is on"
tap "Start"
expect "1 of 2"
expect "Also: Can install apps, Traffic-sharing SDK"
tap "Keep as it is"
expect "2 of 2"
expect "USB debugging is on"
tap "Keep as it is"
expect "Kept as they are: $NAME, This phone"
tap "Done"

# Kept as they were, so the next session at the same level has nothing to do.
wait_for_overview || fail "the overview did not come back after the medium session"
scroll_to_top
expect "Nothing to do at this level now."
tap "Open the plan"
expect "Nothing to do at this level."
adb shell input keyevent KEYCODE_BACK

scroll_to_top
tap "Journal"
tap "Delete the journal"
# The question also starts with "Delete", so the list is scrolled to its end, where the button is.
swipe_up
tap "Delete"
expect "Nothing yet."

echo "PASS: the plan handed off, recorded, noticed a change coming back, kept items, and deleted its journal"
