#!/usr/bin/env bash
# End-to-end check of the live counters behind the network part's view "Now" (W5, ADR 0046, decision 6, items 1 and 6;
# item 5 is in verify-chain.sh, which has the tool), on an emulator only: it installs three copies of the
# workload app (scripts/workload-app), grants usage access and keeps the screen on with adb, and puts both
# back at the end. It starts the test server (scripts/network-lab/server.py) on ports of this computer found
# free (scripts/host-ports.sh), starts the network part's tunnel, and checks, from the network part's debug dump, which
# prints no destination:
#
# - item 1: one app sends in the background, on a long connection it opened while on screen and on a timer,
#   while another app is on screen sending: the first's bytes in the background are within 5 % of what it
#   logged it sent after the grace, its bytes before in use; the app on screen is in use; a third app's
#   foreground service sends with its notification, within 5 % of what it logged, after its own grace, and,
#   from Android 13, in the background once the app's notifications are refused;
# - the log's records of the first app's connection carry both states, cut where it left the screen;
# - item 6: without usage access, the dump says so, and a flow's bytes have no state.
#
# W5's third part reads the same from the screen too, from uiautomator dumps of the view "Now"
# (scripts/now-screen.py): item 1 for each of the three apps, item 6 with its reason; and it checks the
# window while the screen was off (the screen turned off over adb while the app sends, then on), the app's
# history from the log with its states, the audit's page of an app opening "Now" for that app, and item 4 for
# what this part adds: no notification of Advanced names an app or a destination of the run.
#
# Before the first unlock after a restart, item 6's other half, needs a phone restarted with a screen lock,
# which an emulator check cannot unlock again on its own: the engine's and the tracker's tests cover it.
#
#   scripts/verify-activity.sh [path/to/Datapavan-Advanced-debug.apk]
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APK="${1:-$ROOT/android/app/build-advanced/outputs/apk/debug/app-debug.apk}"
PKG=org.visadahyu.datapavan.advanced
NETWORK_SCREEN=org.visadahyu.datapavan.network.MainActivity
# The workload app under three package names, three apps: on screen, in the background, with a service.
SCREEN_APP=org.visadahyu.datapavan.workload
BACKGROUND_APP=org.visadahyu.datapavan.workload.b
NOTICE_APP=org.visadahyu.datapavan.workload.c
WORK=org.visadahyu.datapavan.workload.WorkActivity
SHELL_UID=2000
# shellcheck source=scripts/adb-ui.sh
. "$ROOT/scripts/adb-ui.sh"

is_emulator || {
    echo "verify-activity.sh runs on an emulator only: it installs apps and changes usage access" >&2
    exit 2
}
HOST=10.0.2.2
# shellcheck source=scripts/host-ports.sh
. "$ROOT/scripts/host-ports.sh"

SERVER=""
SCREENS=$(mktemp -d)
# Its dumps of the screens, which a failure keeps (adb-ui.sh's keep_evidence).
CHECK_DUMPS=$SCREENS
# The screen's rotation as found, put back at the end: the history's check turns the screen.
ROTATION=$(adb shell settings get system accelerometer_rotation | tr -d '\r')
cleanup() {
    rm -rf "$SCREENS"
    adb shell settings put system user_rotation 0 >/dev/null 2>&1 || true
    adb shell settings put system accelerometer_rotation "${ROTATION:-0}" >/dev/null 2>&1 || true
    adb shell appops set "$PKG" GET_USAGE_STATS default >/dev/null 2>&1 || true
    adb shell svc power stayon false >/dev/null 2>&1 || true
    for app in "$SCREEN_APP" "$BACKGROUND_APP" "$NOTICE_APP"; do adb uninstall "$app" >/dev/null 2>&1 || true; done
    adb shell am force-stop "$PKG" >/dev/null 2>&1 || true
    [ -z "$SERVER" ] || kill "$SERVER" 2>/dev/null || true
}
check_evidence_on cleanup
# It reads the connection log of the device's day: that day must not end while it runs.
check_day_guard
host_server || exit 1

fail() {
    check_failed "$*"
    echo "ACTIVITY CHECK FAILED: $*" >&2
    adb logcat -d -b crash 2>/dev/null | tail -40 >&2 || true
    exit 1
}

# The network part's own account, with debug commands (NetworkVpnService.debugActivity).
network_dump() {
    adb shell dumpsys activity service "$PKG/org.visadahyu.datapavan.network.NetworkVpnService" "$@" | tr -d '\r' | sed 's/^ *//'
}

uid_of() { adb shell cmd package list packages -U "$1" | tr -d '\r' | sed -n "s/^package:$1 uid:\([0-9]*\)$/\1/p"; }

# The view "Now" for the app $1 alone, read from the screen (adb-ui.sh's network_now).
now_screen() { network_now "$PKG" "$1" "$SCREENS/now.xml"; }

# From now-screen.py's output $1: bytes sent (field 3) or received (4) in the state $2, or 0.
screen_bytes() { awk -v state="$2" -v field="${3:-3}" '$1 == "bytes" && $2 == state { print $field; found = 1 } END { if (!found) print 0 }' <<<"$1"; }

vpn_up() {
    local uid vpns
    uid=$(uid_of "$PKG")
    vpns=$(adb shell dumpsys connectivity | tr -d '\r' | grep -E 'ni\{(VPN |\[type: VPN)' || true)
    [ -n "$uid" ] || return 1
    grep -q "OwnerUid: $uid " <<<"$vpns" && return 0
    # Android 10 names no VPN's owner there: a VPN connected, and the network part's own account that its tunnel runs.
    [ "$(adb shell getprop ro.build.version.sdk | tr -d '\r')" -lt 30 ] && grep -q 'state: CONNECTED/CONNECTED' <<<"$vpns" &&
        grep -qx 'running true' <<<"$(network_dump)"
}

workload_log() { adb logcat -d -s DatapavanWorkload | tr -d '\r' | sed -n 's/.*DatapavanWorkload: //p'; }

# The number a workload app logged after "$1 $2 ", or nothing yet.
logged() { workload_log | sed -n "s/^$1 $2 \([0-9]*\).*/\1/p" | tail -1; }

# The live view now: one app's line ("activity-app UID ..."), or nothing. The dump is read whole before grep
# reads it: under pipefail, a grep that stops reading early fails the pipe.
app_line() { grep "^activity-app $1 " <<<"$(network_dump)" || true; }

# From an app's line: bytes up (2) or down (3) in window $2 (10m, 1h, screen) and column $3 (0 no state, 1 in
# use, 2 with its notification, 3 in the background, 4 not told yet).
bytes_of() {
    python3 -I -c '
import sys
line, window, column, way = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4])
fields = dict(f.split("=", 1) for f in line.split() if "=" in f)
print(fields[window].split(",")[column].split("/")[way])' "$1" "$2" "$3" "$4"
}
up() { bytes_of "$1" "$2" "$3" 0; }

# Whether $1 is within 5 % of $2, which must not be 0.
within_5() {
    python3 -I -c 'import sys; a, b = int(sys.argv[1]), int(sys.argv[2]); sys.exit(0 if b > 0 and abs(a - b) <= 0.05 * b else 1)' "$1" "$2"
}

echo "== The live view's counters, end to end, on $(adb shell getprop ro.product.model | tr -d '\r'), Android $(adb shell getprop ro.build.version.release | tr -d '\r')"
adb wait-for-device
adb install -r "$APK" >/dev/null
allow_vpn "$PKG" || fail "Android did not take the VPN consent for $PKG"
[ "$(adb shell getprop ro.build.version.sdk | tr -d '\r')" -lt 37 ] || adb shell pm grant "$PKG" android.permission.ACCESS_LOCAL_NETWORK
# Usage access, as the user grants it in Settings (ADR 0022).
adb shell appops set "$PKG" GET_USAGE_STATS allow
"$ROOT/scripts/workload-app/build.sh" >/dev/null
for app in "$SCREEN_APP" "$BACKGROUND_APP" "$NOTICE_APP"; do adb uninstall "$app" >/dev/null 2>&1 || true; done
adb install "$ROOT/build/workload-app/workload-app.apk" >/dev/null
adb install "$ROOT/build/workload-app/workload-app-b.apk" >/dev/null
adb install "$ROOT/build/workload-app/workload-app-c.apk" >/dev/null
SCREEN_UID=$(uid_of "$SCREEN_APP")
BACKGROUND_UID=$(uid_of "$BACKGROUND_APP")
NOTICE_UID=$(uid_of "$NOTICE_APP")
[ -n "$SCREEN_UID" ] && [ -n "$BACKGROUND_UID" ] && [ -n "$NOTICE_UID" ] || fail "the workload apps did not install"
adb shell pm grant "$NOTICE_APP" android.permission.POST_NOTIFICATIONS >/dev/null 2>&1 || true
# The screen stays on: the app on screen must be in use for the whole check.
adb shell svc power stayon true
adb shell input keyevent KEYCODE_WAKEUP
adb shell wm dismiss-keyguard >/dev/null 2>&1 || true
adb shell am force-stop "$PKG"
adb shell am start -W -n "$PKG/$NETWORK_SCREEN" --ez start true >/dev/null
for _ in $(seq 1 20); do vpn_up && break; sleep 1; done
vpn_up || fail "the network part's tunnel did not come up"
echo "ok: the tunnel is up, with usage access"
# The table of trackers "Now" marks with (ADR 0046, decision 2 (d)): the εxodus network signatures of the data
# pack the audit verifies, read in the network process by the network part's own library, one alternative outside the
# subset refused; and a test's own name, not traffic of the run, found as the two trackers whose signatures name it.
trackers=$(network_dump activity-tracker x.doubleclick.net 443)
read -r _ with_signature alternatives refused <<<"$(grep '^activity-trackers ' <<<"$trackers")"
[ "${alternatives:-0}" -gt 600 ] && [ "${refused:-}" = 1 ] ||
    fail "the table of trackers is not read from the data pack: $(grep '^activity-tracker' <<<"$trackers" | tr '\n' ';')"
grep -q '^activity-tracker Google DoubleClick,Google AdMob$' <<<"$trackers" ||
    fail "the trackers of a name are not found: $(grep '^activity-tracker ' <<<"$trackers")"
echo "ok: \"Now\" reads $alternatives network signatures of $with_signature trackers from the data pack, $refused refused, and finds a name's"
# The log keeps what the engine writes, for its records' states below.
grep -q '^log-retention 30 set$' <<<"$(network_dump log-retention 30)" || fail "retention could not be set to 30 days"

adb logcat -c
# A foreground service, which sends 35 s after its screen leaves, for 20 s.
adb shell am start -W -n "$NOTICE_APP/$WORK" --es service "$HOST:$((PORT + 1)),20,400" >/dev/null
sleep 2
# A long connection opened on screen, then 35 s after the screen leaves, 30 s of sending in the background.
adb shell am start -W -n "$BACKGROUND_APP/$WORK" --es background "$HOST:$PORT,30,2000" >/dev/null
sleep 5
# Another app on screen meanwhile, sending each second.
adb shell am start -n "$SCREEN_APP/$WORK" --es stay 80 --es udp-every "$HOST:$((PORT + 1))" >/dev/null
sent() { [ -n "$(logged "$BACKGROUND_APP" background-sent)" ] && [ -n "$(logged "$NOTICE_APP" service-sent)" ] && [ -n "$(logged "$SCREEN_APP" stay-sent)" ]; }
within 150 sent || fail "the workload apps did not all log what they sent: $(workload_log | tr '\n' ';')"
background_sent=$(logged "$BACKGROUND_APP" background-sent)
on_screen_sent=$(workload_log | sed -n "s/^$BACKGROUND_APP background-sent [0-9]* on-screen-sent \([0-9]*\)$/\1/p" | tail -1)
notice_sent=$(logged "$NOTICE_APP" service-sent)
screen_sent=$(logged "$SCREEN_APP" stay-sent)
echo "  sent: in the background $background_sent bytes (before, on screen, $on_screen_sent), from the service $notice_sent, on screen $screen_sent"
# The states told up to two seconds ago: past the last bytes.
sleep 4
grep -q '^activity-read true$' <<<"$(network_dump activity-read)" || fail "the tracker did not read the states"
grep -q '^activity-states states ' <<<"$(network_dump)" || fail "the dump does not say the states are known: $(grep '^activity-states' <<<"$(network_dump)")"

background=$(app_line "$BACKGROUND_UID")
notice=$(app_line "$NOTICE_UID")
screen=$(app_line "$SCREEN_UID")
[ -n "$background" ] && [ -n "$notice" ] && [ -n "$screen" ] || fail "an app is missing from the live view: $(network_dump | grep '^activity-app' | tr '\n' ';')"
echo "  $background"
echo "  $notice"
echo "  $screen"
within_5 "$(up "$background" 10m 3)" "$background_sent" ||
    fail "the app in the background has $(up "$background" 10m 3) bytes up in the background, not within 5 % of the $background_sent it sent"
[ "$(up "$background" 10m 1)" -ge "$on_screen_sent" ] ||
    fail "the app in the background has $(up "$background" 10m 1) bytes up in use, fewer than the $on_screen_sent it sent on screen"
[ "$(up "$background" 10m 4)" = 0 ] || fail "the app in the background still has bytes not told: $background"
echo "ok: an app's bytes sent in the background, on a connection opened on screen and on a timer, are in the background within 5 %"
within_5 "$(up "$screen" 10m 1)" "$screen_sent" ||
    fail "the app on screen has $(up "$screen" 10m 1) bytes up in use, not within 5 % of the $screen_sent it sent"
[ "$(up "$screen" 10m 3)" = 0 ] && [ "$(up "$screen" 10m 2)" = 0 ] || fail "the app on screen has bytes not in use: $screen"
echo "ok: the app on screen is in use"
within_5 "$(up "$notice" 10m 2)" "$notice_sent" ||
    fail "the foreground service's app has $(up "$notice" 10m 2) bytes up with its notification, not within 5 % of the $notice_sent it sent"
[ "$(up "$notice" 10m 3)" = 0 ] || fail "the foreground service's app has bytes in the background: $notice"
echo "ok: a foreground service's bytes are with its notification"
# The same from the screen: "Now" names each app with its state and its bytes (W5's third part).
background_screen=$(now_screen "$BACKGROUND_APP")
grep -qx 'now in the background' <<<"$background_screen" ||
    fail "\"Now\" does not show the app in the background now: $(tr '\n' ';' <<<"$background_screen" | cut -c1-800)"
within_5 "$(screen_bytes "$background_screen" background)" "$background_sent" ||
    fail "\"Now\" shows $(screen_bytes "$background_screen" background) bytes sent in the background, not within 5 % of the $background_sent sent"
[ "$(screen_bytes "$background_screen" in-use)" -ge "$on_screen_sent" ] || fail "\"Now\" shows fewer bytes in use than the $on_screen_sent sent on screen"
screen_screen=$(now_screen "$SCREEN_APP")
within_5 "$(screen_bytes "$screen_screen" in-use)" "$screen_sent" ||
    fail "\"Now\" shows $(screen_bytes "$screen_screen" in-use) bytes sent in use by the app on screen, not within 5 % of the $screen_sent sent"
[ "$(screen_bytes "$screen_screen" background)" = 0 ] || fail "\"Now\" shows the app on screen in the background"
notice_screen=$(now_screen "$NOTICE_APP")
within_5 "$(screen_bytes "$notice_screen" notification)" "$notice_sent" ||
    fail "\"Now\" shows $(screen_bytes "$notice_screen" notification) bytes with its notification, not within 5 % of the $notice_sent sent"
echo "ok: on the screen, \"Now\" shows the app in the background within 5 %, the app on screen in use, the service with its notification"
# From Android 13 an app's notifications are off until the user allows them, and its foreground service then
# shows no notification: the same service, its notifications refused, is in the background (ADR 0046).
if [ "$(adb shell getprop ro.build.version.sdk | tr -d '\r')" -ge 33 ]; then
    adb shell pm revoke "$NOTICE_APP" android.permission.POST_NOTIFICATIONS >/dev/null 2>&1 || true
    with_notification=$(up "$notice" 10m 2)
    adb logcat -c
    adb shell am start -W -n "$NOTICE_APP/$WORK" --es service "$HOST:$((PORT + 1)),20,400" >/dev/null
    silent_sent() { [ -n "$(logged "$NOTICE_APP" service-sent)" ]; }
    within 120 silent_sent || fail "the service of the app whose notifications are off did not log what it sent"
    silent=$(logged "$NOTICE_APP" service-sent)
    sleep 4
    grep -q '^activity-read true$' <<<"$(network_dump activity-read)" || fail "the tracker did not read the states"
    notice=$(app_line "$NOTICE_UID")
    echo "  $notice"
    within_5 "$(up "$notice" 10m 3)" "$silent" ||
        fail "the service of the app whose notifications are off has $(up "$notice" 10m 3) bytes up in the background, not within 5 % of the $silent it sent"
    [ "$(up "$notice" 10m 2)" = "$with_notification" ] ||
        fail "the service of an app whose notifications are off added bytes with its notification: $notice"
    echo "ok: a foreground service of an app whose notifications are off is in the background"
fi
# How late the usage events came into Android's record; a reading leaves them 2 seconds (ADR 0046).
echo "  $(grep '^activity-late ' <<<"$(network_dump)")"
grep -q " now=in-use " <<<"$screen" || fail "the app on screen is not in use now: $screen"

# The log's records of the long connection: in use, then in the background, cut where it left the screen.
grep -q '^log-flushed$' <<<"$(network_dump log-flush)" || fail "the log did not take the engine's records"
records=$(network_dump log-today | sed -n "s/^log-record tcp $BACKGROUND_UID ${HOST//./\\.}:$PORT //p")
grep -q " state=in-use " <<<"$records" && grep -q " state=background " <<<"$records" ||
    fail "the log's records of the connection opened on screen do not carry both states: $(tr '\n' ';' <<<"$records")"
echo "ok: the log's records of the connection carry its app's state, in use and then in the background"

# Whether the window of "Now" named $1 is the one chosen: its row, or a node around its text, selected.
window_chosen() {
    dump_screen || return 1
    adb shell cat "$DUMP" >"$SCREENS/window.xml" 2>/dev/null || return 1
    python3 -I -c '
import sys, xml.etree.ElementTree as ET
root = ET.parse(sys.argv[1]).getroot()
parents = {child: parent for parent in root.iter() for child in parent}
for node in root.iter("node"):
    if node.get("text") == sys.argv[2]:
        while node is not None:
            if "true" in (node.get("selected"), node.get("checked")):
                sys.exit(0)
            node = parents.get(node)
sys.exit(1)' "$SCREENS/window.xml" "$1"
}

# The app's history, from the log (retention 30 days): a tap on its row in "Now" opens it, and it holds the
# run's segments of the connection with their states, in use and in the background, and their destination.
# "Now" is on the window of an hour first: the history, a rotation over it, and the way back keep that window
# (review c1 of W5's third part, screens, M2: they reset it to 10 minutes and sorted the rows anew).
now_screen "$BACKGROUND_APP" >/dev/null
tap_text "The last hour" || fail "no window of an hour in \"Now\""
within 10 window_chosen "The last hour" || fail "the window of an hour is not chosen"
tap_holding "$BACKGROUND_APP" || fail "no row of the app to tap in \"Now\""
within 15 screen_has "History of" || fail "the app's history did not open"
scroll_to "State: in the background" || fail "the history holds no segment in the background"
adb shell cat "$DUMP" >"$SCREENS/history.xml"
grep -q '^place 10\.0\.2\.2$' <<<"$(python3 -I "$ROOT/scripts/now-screen.py" "$SCREENS/history.xml" -)" ||
    fail "the history does not name the run's destination"
scroll_to "State: in use" || fail "the history holds no segment in use"
echo "ok: the app's history holds the run's segments of its connection, in use and in the background, with their destination"
adb shell settings put system accelerometer_rotation 0
adb shell settings put system user_rotation 1
sleep 3
within 15 screen_has "History of" || fail "a rotation closed the app's history"
adb shell settings put system user_rotation 0
sleep 3
within 15 screen_has "History of" || fail "a rotation back closed the app's history"
adb shell input keyevent KEYCODE_BACK
within 10 window_chosen "The last hour" || fail "back from the history, \"Now\" lost the window chosen"
echo "ok: the history stays open over a rotation, and \"Now\" keeps its window after it"
# Back on the network screen, its screenshot setting acts on its own window, after "Now" closed (review c1, m1). The
# network screen is known by its activity resumed with the focus: a protected window alone is "Now"'s too (run 3 of
# the network shard on the size pass, 2026-11-27, found no screenshot setting here).
back_to "$PKG/$NETWORK_SCREEN" || fail "back from \"Now\", the network screen did not return"
within 10 window_secure "$PKG" || fail "the network screen is not protected from screenshots after \"Now\" closed"
tap_text "Allow screenshots for one minute" || fail "no screenshot setting on the network screen"
within 10 window_unprotected "$PKG" || fail "allowing screenshots left the network screen protected after \"Now\" closed"
tap_text "Block screenshots now" >/dev/null 2>&1 || true
echo "ok: the network screen allows screenshots on its own window after \"Now\" closed"

# The window while the screen was off (the open list's fourth item): the screen turns off soon after the app
# leaves it, the app sends in the background meanwhile, and the screen comes on again. The window holds those
# bytes, in the background, and "Now" says how many apps sent how much while it was off.
adb logcat -c
adb shell am start -W -n "$BACKGROUND_APP/$WORK" --es background "$HOST:$PORT,20,1500" >/dev/null
sleep 8
adb shell svc power stayon false
adb shell input keyevent KEYCODE_SLEEP
off_sent() { [ -n "$(logged "$BACKGROUND_APP" background-sent)" ]; }
within 150 off_sent || fail "the app did not log what it sent while the screen was off"
sent_off=$(logged "$BACKGROUND_APP" background-sent)
sleep 3
adb shell input keyevent KEYCODE_WAKEUP
adb shell wm dismiss-keyguard >/dev/null 2>&1 || true
adb shell svc power stayon true
sleep 4
grep -q '^activity-read true$' <<<"$(network_dump activity-read)" || fail "the tracker did not read after the screen came on"
read -r _ off_from off_until <<<"$(grep '^activity-off ' <<<"$(network_dump)")"
[ "${off_from:-0}" -gt 0 ] && [ "${off_until:-0}" -gt "$off_from" ] || fail "no window while the screen was off: $(grep '^activity-off' <<<"$(network_dump)")"
background=$(app_line "$BACKGROUND_UID")
echo "  screen off for $(( (off_until - off_from) / 1000 )) s; $background"
within_5 "$(up "$background" off 3)" "$sent_off" ||
    fail "the window while the screen was off holds $(up "$background" off 3) bytes in the background, not within 5 % of the $sent_off sent"
[ "$(up "$background" off 1)" = 0 ] || fail "the window while the screen was off holds bytes in use: $background"
off_screen=$(now_screen "$BACKGROUND_APP")
read -r _ off_apps off_bytes <<<"$(grep '^off ' <<<"$off_screen")"
# The line holds what the dump holds, and no more: the apps but the tool that sent in the background while
# the screen was off, and their bytes sent (review c1 of W5's third part, screens, m6: checked from below only).
read -r dump_apps dump_bytes <<<"$(network_dump | python3 -I -c '
import sys
apps = total = 0
for line in sys.stdin:
    fields = dict(f.split("=", 1) for f in line.split() if "=" in f)
    if line.startswith("activity-app ") and fields.get("tool") == "0":
        sent = int(fields["off"].split(",")[3].split("/")[0])
        apps += sent > 0
        total += sent
print(apps, total)')"
[ "${off_apps:-0}" = "$dump_apps" ] && within_5 "${off_bytes:-0}" "$dump_bytes" && [ "${off_bytes:-0}" -ge $((sent_off * 95 / 100)) ] ||
    fail "\"Now\" does not say what apps sent while the screen was off: $(grep '^off' <<<"$off_screen")"
echo "ok: the window while the screen was off holds the app's bytes in the background, and \"Now\" says so"

# The audit's page of an app opens "Now" for that app alone (ADR 0046, decision 2 (d); Advanced only).
# The audit's screen in the package's main process; the network process, and its tunnel, run on. On CI the emulator
# stopped answering adb here three times on 2026-11-19, about 30 s after the audit started its scan beside the network
# part and the workload apps (docs/ci-flakes.md): every adb call of this step waits for the device when it drops off,
# says what it was doing (memory, crashes, kills), and is made once more.
adb_again shell am start -n "$PKG/org.visadahyu.datapavan.MainActivity" >/dev/null ||
    fail "the audit could not be started, or the emulator stopped answering adb; see the lines above"
within 60 has_id nav-summary || fail "the audit did not start"
open_tab apps || fail "no list of apps in the audit"
within 60 has_id app-row || fail "no app in the audit's list"
# The list shows apps with findings first: its last filter, "All", is found along the row of filters, and its
# search finds the workload apps among the emulator's own.
# The bounds of the first element whose text is $1 and a count, as "All 243", in a new dump.
counted_bounds() {
    local screen
    dump_screen || return 1
    screen=$(adb shell cat "$DUMP") || return 1
    grep -o "text=\"$1 [0-9]*\"[^>]*bounds=\"[^\"]*\"" <<<"$screen" | sed -n 1p | grep -o 'bounds="[^"]*"' | grep -o '[0-9]\+' | tr '\n' ' '
}
read -r _ chips_top _ chips_bottom <<<"$(counted_bounds "With findings" || true)"
[ -n "${chips_bottom:-}" ] || fail "no filters over the audit's list"
all=""
for _ in 1 2 3 4 5; do
    all=$(counted_bounds All || true)
    [ -z "$all" ] || break
    adb_again shell input swipe 900 $(( (chips_top + chips_bottom) / 2 )) 150 $(( (chips_top + chips_bottom) / 2 )) 300 ||
        fail "the emulator stopped answering adb in the audit's list; see the lines above"
    sleep 1
done
[ -n "$all" ] || fail "no filter for all apps"
set -- $all
adb_again shell input tap $(( ($1 + $3) / 2 )) $(( ($2 + $4) / 2 )) || fail "the emulator stopped answering adb in the audit's list"
sleep 1
tap_text "Search apps" || fail "no search in the audit's list"
adb_again shell input text workload || fail "the emulator stopped answering adb in the audit's search"
sleep 2
# The keyboard, if it shows, goes, so that the list and then the page are read whole.
if grep -q 'mInputShown=true' <<<"$(adb shell dumpsys input_method | tr -d '\r')"; then adb shell input keyevent KEYCODE_BACK; sleep 1; fi
tap_text "Datapavan workload" || fail "the workload app is not in the audit's list"
within 10 screen_has "Back" || fail "the app's page did not open"
page=$(adb shell cat "$DUMP" | LC_ALL=C sed 's/\xe2\x81[\xa6-\xa9]//g' | grep -o 'org\.visadahyu\.datapavan\.workload[.bc]*' | sed -n 1p) || page=""
[ -n "$page" ] || fail "the app's page does not name its package"
tap_text "Network" || fail "no network section on the app's page"
tap_text "See what this app sends now" || fail "the app's page does not offer \"Now\""
within 15 screen_has "Showing one app." || fail "\"Now\" did not open for one app"
adb_again shell cat "$DUMP" >"$SCREENS/one.xml" || fail "the emulator stopped answering adb on \"Now\" for one app"
grep -qx row <<<"$(python3 -I "$ROOT/scripts/now-screen.py" "$SCREENS/one.xml" "$page")" || fail "\"Now\" opened from the app's page does not show $page"
# And no other app: the other workload apps sent in this run too (review c1, screens, m6).
for other in "$SCREEN_APP" "$BACKGROUND_APP" "$NOTICE_APP"; do
    [ "$other" = "$page" ] && continue
    grep -qx no-row <<<"$(python3 -I "$ROOT/scripts/now-screen.py" "$SCREENS/one.xml" "$other")" ||
        fail "\"Now\" opened for $page shows $other too"
done
echo "ok: the audit's page of $page opens \"Now\" for that app"
adb shell am start -W -n "$PKG/$NETWORK_SCREEN" --activity-clear-top >/dev/null

# Item 6: without usage access, the dump says so, and the shell's flow has no state.
adb shell appops set "$PKG" GET_USAGE_STATS deny
answer=$(timeout 15 adb shell "printf 'GET /ping HTTP/1.0\r\n\r\n' | nc -w 5 $HOST $PORT" | tr -d '\r' || true)
grep -q '^pong$' <<<"$answer" || fail "no answer over TCP from the test server"
sleep 4
grep -q '^activity-read true$' <<<"$(network_dump activity-read)" || fail "the tracker did not read without usage access"
grep -q '^activity-states no-access ' <<<"$(network_dump)" || fail "the dump does not say usage access is missing: $(grep '^activity-states' <<<"$(network_dump)")"
shell=$(app_line "$SHELL_UID")
echo "  $shell"
grep -q " now=none-no-access " <<<"$shell" || fail "the shell's state now is not 'none, no usage access': $shell"
[ "$(up "$shell" 10m 0)" -gt 0 ] || fail "the shell's flow has no bytes without a state: $shell"
for column in 1 2 3; do
    [ "$(up "$shell" 10m "$column")" = 0 ] || fail "the shell's flow has bytes in a state without usage access: $shell"
done
echo "ok: without usage access, the dump says so, and a flow's bytes have no state"
shell_screen=$(now_screen com.android.shell)
grep -qx 'now no state' <<<"$shell_screen" || fail "\"Now\" does not show the shell with no state: $(tr '\n' ';' <<<"$shell_screen" | cut -c1-800)"
grep -qx 'why Datapavan had no usage access.' <<<"$shell_screen" || fail "\"Now\" does not say why the shell's bytes have no state"
grep -q 'Allow usage access' <<<"$(grep '^texts ' <<<"$shell_screen")" || fail "\"Now\" does not offer usage access without it"
[ "$(screen_bytes "$shell_screen" none)" -gt 0 ] || fail "\"Now\" shows no bytes in no state for the shell"
echo "ok: on the screen, without usage access, the app's row has no state and says why"

# Item 4, for what this part adds: no notification of Advanced names an app or a destination of the run
# (dumpsys notification, against every package and destination of the run). The network part posts none yet; W9's
# summary will be held to the same.
notifications=$(adb shell dumpsys notification --noredact | tr -d '\r' | python3 -I -c '
import sys
pkg = sys.argv[1]
block, own = [], []
for line in sys.stdin:
    if "NotificationRecord(" in line:
        if block and f"pkg={pkg} " in block[0]:
            own.extend(block)
        block = []
    block.append(line)
if block and f"pkg={pkg} " in block[0]:
    own.extend(block)
print("".join(own))' "$PKG")
for name in "$SCREEN_APP" "$BACKGROUND_APP" "$NOTICE_APP" com.android.shell "Datapavan workload" "$HOST"; do
    ! grep -qF "$name" <<<"$notifications" || fail "a notification of $PKG names $name"
done
echo "ok: no notification of $PKG names an app or a destination of the run"
echo "== The live view's counters passed"
