#!/usr/bin/env bash
# The stage for the store and website images: a phone-sized emulator, the test fixture holding risky
# access, and the lab app with real traffic counted by Android. The screens then show real findings
# about apps of our own, and name no one else's app (ADR 0015).
#
# Only for emulators: it changes device settings. Then run scripts/smoke.sh and scripts/store-images.sh.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FIXTURE=org.visadahyu.datapavan.fixture
LAB=org.visadahyu.datapavan.trafficlab

if [ "$(adb shell getprop ro.kernel.qemu | tr -d '\r')" != "1" ] && [ "$(adb shell getprop ro.boot.qemu | tr -d '\r')" != "1" ]; then
    echo "store-scene.sh changes device settings and runs on emulators only" >&2
    exit 2
fi

adb shell wm size 1080x2400
adb shell wm density 420

"$ROOT/scripts/fixture-app/build.sh" >/dev/null
adb install -r -g "$ROOT/build/fixture/fixture.apk" >/dev/null
adb shell appops set "$FIXTURE" REQUEST_INSTALL_PACKAGES allow
adb shell settings put secure enabled_accessibility_services "$FIXTURE/$FIXTURE.FixtureAccessibilityService"
adb shell settings put secure accessibility_enabled 1

"$ROOT/scripts/traffic-lab/build.sh" >/dev/null
adb install -r "$ROOT/build/traffic-lab/traffic-lab.apk" >/dev/null

# Real bytes for Android to count: some with the app on screen, most without.
LOG="$(mktemp)"
python3 -I "$ROOT/scripts/traffic-lab/server.py" "$LOG" &
SERVER=$!
trap 'kill "$SERVER" 2>/dev/null || true; rm -f "$LOG"' EXIT
sleep 1
adb shell am start -W -n "$LAB/.TransferActivity" --el down 90000000 --el up 12000000 >/dev/null
sleep 25
adb shell am force-stop "$LAB"
adb shell am broadcast -n "$LAB/.TransferReceiver" --el down 30000000 --el up 40000000 >/dev/null
sleep 25
echo "server saw $(wc -l <"$LOG") transfers"
echo "== scene ready"
