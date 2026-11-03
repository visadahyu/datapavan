#!/usr/bin/env bash
# The keyboard spike (docs/spikes/2026-11-keyboard-counting.md): does Android count a keyboard's
# traffic as foreground while it is on screen? The lab app's keyboard (LabKeyboard) downloads
# 3,000,000 bytes from server.py while shown and 7,000,000 bytes 20 seconds after it is hidden; the
# script shows it in the contact editor, hides it, and prints the lab app's counts by state (1
# background, 2 foreground), read twice 20 seconds apart so that the second is up to date. Emulators
# only; it sets the keyboard and puts the default one back afterwards.
#
#   scripts/traffic-lab/keyboard.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=scripts/adb-ui.sh
. "$ROOT/scripts/adb-ui.sh"
LAB=org.visadahyu.datapavan.trafficlab

[ "$(adb shell getprop ro.kernel.qemu | tr -d '\r')" = 1 ] || { echo "emulators only" >&2; exit 2; }

log=$(mktemp)
python3 "$ROOT/scripts/traffic-lab/server.py" "$log" &
server=$!
cleanup() {
    kill "$server" 2>/dev/null || true
    rm -f "$log"
    adb shell ime reset >/dev/null 2>&1 || true
    adb uninstall "$LAB" >/dev/null 2>&1 || true
    adb shell rm -f "$DUMP" >/dev/null 2>&1 || true
}
trap cleanup EXIT

adb uninstall "$LAB" >/dev/null 2>&1 || true
adb install "$("$ROOT/scripts/traffic-lab/build.sh" 2>/dev/null | tail -1)" >/dev/null
adb shell appops set "$LAB" GET_USAGE_STATS allow
# Android can take a moment to see a keyboard that was just installed.
for _ in $(seq 1 20); do adb shell ime list -a -s | tr -d '\r' | grep -q "^$LAB/.LabKeyboard$" && break; sleep 1; done
adb shell ime enable "$LAB/.LabKeyboard" >/dev/null
adb shell ime set "$LAB/.LabKeyboard" >/dev/null
t0=$(date +%s%3N)

# Settings' search opens with its field focused and the keyboard shown, as a new task so that an
# earlier one cannot be brought back without it. Where the keyboard stays hidden, its field is tapped.
adb shell input keyevent KEYCODE_HOME
adb shell am start -f 0x10008000 -a com.android.settings.action.SETTINGS_SEARCH >/dev/null
for _ in $(seq 1 10); do grep -q " down 3000000 " "$log" && break; sleep 1; done
if ! grep -q " down 3000000 " "$log" && adb shell uiautomator dump "$DUMP" >/dev/null 2>&1; then
    bounds=$(adb shell cat "$DUMP" | grep -o 'class="android.widget.EditText"[^>]*bounds="[^"]*"' | head -1 | grep -o 'bounds="[^"]*"' | grep -o '[0-9]\+' | tr '\n' ' ')
    # shellcheck disable=SC2086
    [ -z "$bounds" ] || { set -- $bounds; adb shell input tap $((($1 + $3) / 2)) $((($2 + $4) / 2)); }
fi
for _ in $(seq 1 30); do grep -q " down 3000000 " "$log" && break; sleep 1; done
grep -q " down 3000000 " "$log" || { echo "the keyboard did not download while shown" >&2; exit 1; }
sleep 3
adb shell input keyevent KEYCODE_BACK
for _ in $(seq 1 60); do grep -q " down 7000000 " "$log" && break; sleep 1; done
grep -q " down 7000000 " "$log" || { echo "the keyboard did not download after it was hidden" >&2; exit 1; }
sleep 5
adb shell input keyevent KEYCODE_HOME

# The same aligned period as the guided check (ADR 0025), read twice so the second is up to date.
day=86400000
start=$(( (t0 - day) / 7200000 * 7200000 ))
end=$(( $(date +%s%3N) + 2 * day ))
read_counts() { adb shell am broadcast -n "$LAB/.ReadReceiver" --ela starts "$start" --ela ends "$end" 2>/dev/null | tr -d '\r'; }
read_counts >/dev/null
sleep 20
out=$(read_counts)
uid=$(echo "$out" | sed -n 's/.*me \([0-9]*\).*/\1/p' | head -1)
echo "== Android $(adb shell getprop ro.build.version.release | tr -d '\r'): the lab keyboard's counts (state 1 background, 2 foreground)"
echo "$out" | grep -E "^q 0 (wifi|mobile) $uid " | awk '{ printf "%s state %s: %d bytes received, %d sent\n", $3, $5, $6, $7 }'
