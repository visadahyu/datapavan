#!/usr/bin/env bash
# The measurement of docs/spikes/2026-11-feed-left-of-home.md (ADR 0046, decision 5): on a Google Play emulator
# image, does the Google app's traffic while the user scrolls the feed left of the home screen count as in use?
# Runs on the emulator ANDROID_SERIAL names, after scripts/verify-activity.sh installed Advanced's debug build;
# prints what Watch's debug dump says of the Google app while the feed shows. Emulators only: it grants usage
# access and starts a VPN, and takes them back at the end.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
PKG=org.visadahyu.datapavan.advanced
GOOGLE=com.google.android.googlequicksearchbox
. "$ROOT/scripts/adb-ui.sh"
is_emulator || { echo "emulator only" >&2; exit 2; }
dumpw() { adb shell dumpsys activity service "$PKG/org.visadahyu.datapavan.watch.WatchVpnService" "$@" | tr -d '\r' | sed 's/^ *//'; }
adb shell pm path "$GOOGLE" >/dev/null 2>&1 || { echo "feed: no Google app on this image"; exit 0; }
allow_vpn "$PKG"
adb shell appops set "$PKG" GET_USAGE_STATS allow
adb shell svc power stayon true
adb shell input keyevent KEYCODE_WAKEUP
adb shell wm dismiss-keyguard >/dev/null 2>&1 || true
adb shell am start -W -n "$PKG/org.visadahyu.datapavan.watch.MainActivity" --ez start true >/dev/null
sleep 8
GUID=$(adb shell cmd package list packages -U "$GOOGLE" | tr -d '\r' | sed -n "s/^package:$GOOGLE uid:\([0-9]*\)$/\1/p")
echo "feed: Google app uid $GUID, version $(adb shell dumpsys package "$GOOGLE" | tr -d '\r' | sed -n 's/^ *versionName=//p' | sed -n 1p)"
echo "feed: home $(adb shell cmd package resolve-activity -c android.intent.category.HOME -a android.intent.action.MAIN | tr -d '\r' | sed -n 's/^ *packageName=//p' | sed -n 1p)"
adb shell input keyevent KEYCODE_HOME
sleep 5
size=$(adb shell wm size | tr -d '\r' | sed -n 's/.*: \([0-9]*\)x\([0-9]*\)$/\1 \2/p' | tail -1); w=${size% *}; h=${size#* }
adb shell input swipe 20 $((h / 2)) $((w * 9 / 10)) $((h / 2)) 400
sleep 4
echo "feed: focus $(adb shell dumpsys window | tr -d '\r' | grep -m1 'mCurrentFocus' | sed 's/^ *//')"
dump_screen && adb shell cat "$DUMP" | grep -o 'package="[^"]*"' | sort | uniq -c | sed 's/^/feed: dump /'
for _ in $(seq 1 12); do
    adb shell input swipe $((w / 2)) $((h * 3 / 4)) $((w / 2)) $((h / 4)) 300
    sleep 5
done
sleep 3
dumpw activity-read | grep -E '^activity-(read|states)'
echo "feed: $(grep "^activity-app $GUID " <<<"$(dumpw)" || echo "no line for the Google app")"
adb shell input keyevent KEYCODE_HOME
adb shell svc power stayon false
adb shell appops set "$PKG" GET_USAGE_STATS default
