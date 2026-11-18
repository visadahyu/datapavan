#!/usr/bin/env bash
# End-to-end check of the live counters behind Watch's view "Now" (W5, ADR 0046, decision 6, items 1 and 6;
# item 5 is in verify-chain.sh, which has the tool), on an emulator only: it installs three copies of the
# workload app (scripts/workload-app), grants usage access and keeps the screen on with adb, and puts both
# back at the end. It starts the test server (scripts/watch-lab/server.py) on ports of this computer found
# free (scripts/host-ports.sh), starts Watch's tunnel, and checks, from Watch's debug dump, which prints no
# destination:
#
# - item 1: one app sends in the background, on a long connection it opened while on screen and on a timer,
#   while another app is on screen sending: the first's bytes in the background are within 5 % of what it
#   logged it sent after the grace, its bytes before in use; the app on screen is in use; a third app's
#   foreground service sends with its notification, within 5 % of what it logged, after its own grace, and,
#   from Android 13, in the background once the app's notifications are refused;
# - the log's records of the first app's connection carry both states, cut where it left the screen;
# - item 6: without usage access, the dump says so, and a flow's bytes have no state.
#
# Before the first unlock after a restart, item 6's other half, needs a phone restarted with a screen lock,
# which an emulator check cannot unlock again on its own: the engine's and the tracker's tests cover it.
#
#   scripts/verify-activity.sh [path/to/Datapavan-Advanced-debug.apk]
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APK="${1:-$ROOT/android/app/build-advanced/outputs/apk/debug/app-debug.apk}"
PKG=org.visadahyu.datapavan.advanced
WATCH_SCREEN=org.visadahyu.datapavan.watch.MainActivity
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
cleanup() {
    adb shell appops set "$PKG" GET_USAGE_STATS default >/dev/null 2>&1 || true
    adb shell svc power stayon false >/dev/null 2>&1 || true
    for app in "$SCREEN_APP" "$BACKGROUND_APP" "$NOTICE_APP"; do adb uninstall "$app" >/dev/null 2>&1 || true; done
    adb shell am force-stop "$PKG" >/dev/null 2>&1 || true
    [ -z "$SERVER" ] || kill "$SERVER" 2>/dev/null || true
}
trap cleanup EXIT
host_server || exit 1

fail() {
    echo "ACTIVITY CHECK FAILED: $*" >&2
    adb logcat -d -b crash 2>/dev/null | tail -40 >&2 || true
    exit 1
}

# Watch's own account, with debug commands (WatchVpnService.debugActivity).
watch_dump() {
    adb shell dumpsys activity service "$PKG/org.visadahyu.datapavan.watch.WatchVpnService" "$@" | tr -d '\r' | sed 's/^ *//'
}

uid_of() { adb shell cmd package list packages -U "$1" | tr -d '\r' | sed -n "s/^package:$1 uid:\([0-9]*\)$/\1/p"; }

vpn_up() {
    local uid vpns
    uid=$(uid_of "$PKG")
    vpns=$(adb shell dumpsys connectivity | tr -d '\r' | grep -E 'ni\{(VPN |\[type: VPN)' || true)
    [ -n "$uid" ] && grep -q "OwnerUid: $uid " <<<"$vpns"
}

workload_log() { adb logcat -d -s DatapavanWorkload | tr -d '\r' | sed -n 's/.*DatapavanWorkload: //p'; }

# The number a workload app logged after "$1 $2 ", or nothing yet.
logged() { workload_log | sed -n "s/^$1 $2 \([0-9]*\).*/\1/p" | tail -1; }

# The live view now: one app's line ("activity-app UID ..."), or nothing. The dump is read whole before grep
# reads it: under pipefail, a grep that stops reading early fails the pipe.
app_line() { grep "^activity-app $1 " <<<"$(watch_dump)" || true; }

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
adb shell am start -W -n "$PKG/$WATCH_SCREEN" --ez start true >/dev/null
for _ in $(seq 1 20); do vpn_up && break; sleep 1; done
vpn_up || fail "Watch's tunnel did not come up"
echo "ok: the tunnel is up, with usage access"
# The log keeps what the engine writes, for its records' states below.
grep -q '^log-retention 30 set$' <<<"$(watch_dump log-retention 30)" || fail "retention could not be set to 30 days"

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
grep -q '^activity-read true$' <<<"$(watch_dump activity-read)" || fail "the tracker did not read the states"
grep -q '^activity-states states ' <<<"$(watch_dump)" || fail "the dump does not say the states are known: $(grep '^activity-states' <<<"$(watch_dump)")"

background=$(app_line "$BACKGROUND_UID")
notice=$(app_line "$NOTICE_UID")
screen=$(app_line "$SCREEN_UID")
[ -n "$background" ] && [ -n "$notice" ] && [ -n "$screen" ] || fail "an app is missing from the live view: $(watch_dump | grep '^activity-app' | tr '\n' ';')"
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
    grep -q '^activity-read true$' <<<"$(watch_dump activity-read)" || fail "the tracker did not read the states"
    notice=$(app_line "$NOTICE_UID")
    echo "  $notice"
    within_5 "$(up "$notice" 10m 3)" "$silent" ||
        fail "the service of the app whose notifications are off has $(up "$notice" 10m 3) bytes up in the background, not within 5 % of the $silent it sent"
    [ "$(up "$notice" 10m 2)" = "$with_notification" ] ||
        fail "the service of an app whose notifications are off added bytes with its notification: $notice"
    echo "ok: a foreground service of an app whose notifications are off is in the background"
fi
# How late the usage events came into Android's record; a reading leaves them 2 seconds (ADR 0046).
echo "  $(grep '^activity-late ' <<<"$(watch_dump)")"
grep -q " now=in-use " <<<"$screen" || fail "the app on screen is not in use now: $screen"

# The log's records of the long connection: in use, then in the background, cut where it left the screen.
grep -q '^log-flushed$' <<<"$(watch_dump log-flush)" || fail "the log did not take the engine's records"
records=$(watch_dump log-today | sed -n "s/^log-record tcp $BACKGROUND_UID ${HOST//./\\.}:$PORT //p")
grep -q " state=in-use " <<<"$records" && grep -q " state=background " <<<"$records" ||
    fail "the log's records of the connection opened on screen do not carry both states: $(tr '\n' ';' <<<"$records")"
echo "ok: the log's records of the connection carry its app's state, in use and then in the background"

# Item 6: without usage access, the dump says so, and the shell's flow has no state.
adb shell appops set "$PKG" GET_USAGE_STATS deny
answer=$(timeout 15 adb shell "printf 'GET /ping HTTP/1.0\r\n\r\n' | nc -w 5 $HOST $PORT" | tr -d '\r' || true)
grep -q '^pong$' <<<"$answer" || fail "no answer over TCP from the test server"
sleep 4
grep -q '^activity-read true$' <<<"$(watch_dump activity-read)" || fail "the tracker did not read without usage access"
grep -q '^activity-states no-access ' <<<"$(watch_dump)" || fail "the dump does not say usage access is missing: $(grep '^activity-states' <<<"$(watch_dump)")"
shell=$(app_line "$SHELL_UID")
echo "  $shell"
grep -q " now=none-no-access " <<<"$shell" || fail "the shell's state now is not 'none, no usage access': $shell"
[ "$(up "$shell" 10m 0)" -gt 0 ] || fail "the shell's flow has no bytes without a state: $shell"
for column in 1 2 3; do
    [ "$(up "$shell" 10m "$column")" = 0 ] || fail "the shell's flow has bytes in a state without usage access: $shell"
done
echo "ok: without usage access, the dump says so, and a flow's bytes have no state"
echo "== The live view's counters passed"
