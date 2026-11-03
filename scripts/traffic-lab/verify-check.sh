#!/usr/bin/env bash
# End-to-end check of the guided check (ADR 0025) on an emulator, with a debug build of Datapavan
# installed: Datapavan reads the traffic lab app's counts, the lab app downloads 5,000,000 bytes from
# server.py on this computer while Datapavan is in the background, and Datapavan reads again when it
# comes back. The result must show the download, a share of sent bytes and no note that the count
# was not up to date. Emulators only: it gives Datapavan usage access over adb.
#
#   scripts/traffic-lab/verify-check.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=scripts/adb-ui.sh
. "$ROOT/scripts/adb-ui.sh"

DATAPAVAN=org.visadahyu.datapavan
LAB=org.visadahyu.datapavan.trafficlab
BYTES=5000000

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

[ "$(adb shell getprop ro.kernel.qemu | tr -d '\r')" = 1 ] || fail "verify-check.sh changes device settings and runs on emulators only"

log=$(mktemp)
python3 "$ROOT/scripts/traffic-lab/server.py" "$log" &
server=$!
# Leaves the emulator as it was: no lab app, and usage access back to its default.
cleanup() {
    kill "$server" 2>/dev/null || true
    rm -f "$log" "$log.result"
    adb shell rm -f "$DUMP" >/dev/null 2>&1 || true
    adb uninstall "$LAB" >/dev/null 2>&1 || true
    adb shell appops set "$DATAPAVAN" GET_USAGE_STATS default >/dev/null 2>&1 || true
}
trap cleanup EXIT

# Each build of the lab app has a new key, so an older one is removed first.
adb uninstall "$LAB" >/dev/null 2>&1 || true
adb install "$("$ROOT/scripts/traffic-lab/build.sh" 2>/dev/null | tail -1)" >/dev/null
adb shell appops set "$DATAPAVAN" GET_USAGE_STATS allow

start_audit || fail "the audit overview did not appear"
open_tab apps || fail "no apps destination"
tap_id filter-all || fail "no filter for all apps"
sleep 1
tap_text "Datapavan traffic lab" || fail "the lab app is not listed"
sleep 1
open_sections
tap_text "Check one activity" || fail "the app's page offers no guided check"
tap_text "Download a file" || fail "no activity to choose"
tap_text "Start" || fail "no start button"

# Datapavan waits until 15 seconds after its last query, then reads and asks for the activity.
for _ in $(seq 1 40); do
    screen_has "Do the activity in" && break
    sleep 1
done
screen_has "Do the activity in" || fail "the first reading did not come"

adb shell am start -W -n "$LAB/.TransferActivity" --el down "$BYTES" >/dev/null
for _ in $(seq 1 60); do
    grep -q " down $BYTES " "$log" && break
    sleep 1
done
grep -q " down $BYTES " "$log" || fail "the lab app did not download"

# The lab app closes itself and Datapavan comes back: the second reading follows.
for _ in $(seq 1 60); do
    screen_has "Check 1: Download a file" && break
    sleep 1
done
screen_has "Check 1: Download a file" || fail "no result"
adb shell cat "$DUMP" | grep -o 'text="[^"]*"' | sed 's/^text="//; s/"$//' | perl -CS -pe 's/[\x{2066}-\x{2069}]//g' |
    grep -E "received|Sent:|Time between|up to date" | tee /dev/stderr >"$log.result"

# 5,000,000 bytes and their headers are 4.77 to 5.00 MB in the emulator's steps of 1,024.
received=$(sed -n 's/^\(Wi-Fi\|Mobile data\): \([0-9.]*\) MB received.*/\2/p' "$log.result" | head -1)
[ -n "$received" ] || fail "no received bytes in the result"
awk -v r="$received" 'BEGIN { exit !(r >= 4.77 && r <= 5.0) }' || fail "received $received MB, not about $BYTES bytes"
grep -q "^Sent: " "$log.result" || fail "no share of sent bytes"
if grep -q "up to date" "$log.result"; then fail "Android's count was not up to date"; fi

echo "PASS: the guided check counted the lab app's download of $BYTES bytes ($received MB)"
