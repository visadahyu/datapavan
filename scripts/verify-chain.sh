#!/usr/bin/env bash
# W6's end-to-end check of chaining (docs/DESIGN.md, 13.2; docs/VPN.md; ADR 0038), on an emulator.
# The test tool (scripts/test-tool) runs a SOCKS5 proxy with a password on the phone's loopback, as a
# circumvention tool does in proxy mode. Watch must find it by itself: its package, its port, that
# Android names it as the port's owner, and that it wants a password. With adb's shell (UID 2000)
# chained through it, TCP reaches the test server on this computer by address and by a name only the
# tool can resolve (the shell gets a stand-in address for it), UDP goes through the tool's relay, the
# tool's own connections go directly and are counted under the tool, and a wrong password is refused.
# Then the tool stops: the shell's connections fail, and a sentinel on this computer, outside Android,
# sees none of them reach it directly, while it does see a control's direct connection. Last, the user's
# own path on the chain screen: Watch offers its password, which is set in the tool; one installed app
# (scripts/workload-app) is picked and the chain turned on; that app's lookup and TCP go through the
# tool under its own UID, its UDP goes nowhere until the user allows UDP on the screen and then through
# the tool, and adb's shell, not picked, goes directly. The screen says what the tool's proxy lets other
# apps do, without a password and then with one (ADR 0041, decision 5). Then the tool stops with the chain
# on: the screen says the apps wait, its switch still turns the chain off, and the picked app then goes
# directly. With UDP allowed, the picked app also sends STUN requests from one socket to two names on one
# port at once, and both answers must reach it (ADR 0044, unit 9b). Last, that app is left out of the
# tunnel on the screen (ADR 0041): Watch sets its tunnel up again, the app reaches the server and Watch
# no longer sees it; taken back, Watch sees it again. Nothing
# is left running: the tunnel, the tool and the server stop at the end, and the tool is uninstalled.
#
#   scripts/verify-chain.sh [path/to/Datapavan-Advanced-debug.apk]
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APK="${1:-$ROOT/android/app/build-advanced/outputs/apk/debug/app-debug.apk}"
PKG=org.visadahyu.datapavan.advanced
# Watch's screen in Datapavan Advanced (ADR 0045); debug builds export it for these checks.
WATCH_SCREEN=org.visadahyu.datapavan.watch.MainActivity
TOOL=org.visadahyu.datapavan.testtool
WORKLOAD=org.visadahyu.datapavan.workload
TOOL_PORT=10870
# The test tool's STUN server for unit 9b's step, at 127.0.0.1 and 127.0.0.2 on the phone.
STUN_PORT=10871
SHELL_UID=2000
# shellcheck source=scripts/adb-ui.sh
. "$ROOT/scripts/adb-ui.sh"

is_emulator || { echo "verify-chain.sh runs on an emulator only" >&2; exit 2; }
HOST=10.0.2.2
# The test server, started on ports of this computer found free and held until the check ends
# (scripts/host-ports.sh): WATCH_TEST_PORT, or a base picked from 8790 up.
# shellcheck source=scripts/host-ports.sh
. "$ROOT/scripts/host-ports.sh"
PASSWORD="$(python3 -I -c 'import secrets;print(secrets.token_urlsafe(15))')"
WORK="$(mktemp -d)"
SERVER=""

cleanup() {
    adb shell am force-stop "$PKG" >/dev/null 2>&1 || true
    adb shell am force-stop "$TOOL" >/dev/null 2>&1 || true
    adb uninstall "$TOOL" >/dev/null 2>&1 || true
    adb uninstall "$WORKLOAD" >/dev/null 2>&1 || true
    [ -z "$SERVER" ] || kill "$SERVER" 2>/dev/null || true
    rm -rf "$WORK"
}
trap cleanup EXIT
host_server --sentinel "$WORK/sentinel.log" || exit 1

dump() { adb shell dumpsys activity service "$PKG/org.visadahyu.datapavan.watch.WatchVpnService" "$@" | tr -d '\r'; }
# When the engine's counters began, then its counter at place $1, counting from 1, as Watch's dump prints
# them, from one dump: two reads with another beginning span an engine Watch started afresh, whose
# counters began again at 0 (unit 9b, fix round 2).
counter_since() { dump | awk -v n="$1" '/^ *counters-since /{since=$2} /^ *counters /{sub(/^ *counters /, ""); split($0, c, " ")} END{print since, c[n]}'; }
flows() { dump | sed -n 's/^ *flow //p'; }
tool_log() { adb logcat -d -s DatapavanTestTool | tr -d '\r' | sed -n 's/.*DatapavanTestTool: //p'; }
workload_log() { adb logcat -d -s DatapavanWorkload | tr -d '\r' | sed -n 's/.*DatapavanWorkload: //p'; }
# Runs a shell command on the device, killing it after $1 seconds: nc -u waits for more answers.
device() {
    local seconds=$1
    shift
    timeout "$seconds" adb shell "$@" 2>&1 | tr -d '\r' || true
}
ping_from_shell() { device 10 "printf 'GET /ping HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n' | toybox nc -w 6 $1 $PORT"; }

fail() {
    echo "CHAIN CHECK FAILED: $*" >&2
    if dump_screen 2>/dev/null; then
        echo "On the screen:" >&2
        adb shell cat "$DUMP" 2>/dev/null | grep -o 'text="[^"]\+"' | head -20 >&2 || true
    fi
    echo "The tool's requests:" >&2
    tool_log | tail -20 >&2 || true
    echo "The flows of the shell and the tool:" >&2
    flows | grep -E " ($SHELL_UID|${TOOL_UID:-x}) " | tail -20 >&2 || true
    echo "Watch's searches for the tool (debug log):" >&2
    search_log | tail -20 >&2 || true
    adb logcat -d -b crash 2>/dev/null | tail -30 >&2 || true
    exit 1
}

# The steps of Watch's searches for the tool, which a debug build logs (Tools.search).
search_log() { adb logcat -d -s WatchChain | tr -d '\r' | sed -n 's/.*WatchChain: //p'; }

vpn_up() {
    local uid vpns
    uid=$(adb shell cmd package list packages -U "$PKG" | tr -d '\r' | sed -n "s/^package:$PKG uid:\([0-9]*\)$/\1/p")
    vpns=$(adb shell dumpsys connectivity | tr -d '\r')
    [ -n "$uid" ] && grep -qE "OwnerUid: $uid " <<<"$vpns"
}

"$ROOT/scripts/test-tool/build.sh" >/dev/null
"$ROOT/scripts/workload-app/build.sh" >/dev/null
adb install -r "$APK" >/dev/null
# A fresh start: the chain's settings of an earlier run would change what the screen offers.
adb shell pm clear "$PKG" >/dev/null
adb uninstall "$WORKLOAD" >/dev/null 2>&1 || true
adb install "$ROOT/build/workload-app/workload-app.apk" >/dev/null
WORKLOAD_UID=$(adb shell cmd package list packages -U "$WORKLOAD" | tr -d '\r' | sed -n "s/^package:$WORKLOAD uid:\([0-9]*\)$/\1/p")
[ -n "$WORKLOAD_UID" ] || fail "the workload app did not install"
adb uninstall "$TOOL" >/dev/null 2>&1 || true
adb install "$ROOT/build/test-tool/test-tool.apk" >/dev/null
TOOL_UID=$(adb shell cmd package list packages -U "$TOOL" | tr -d '\r' | sed -n "s/^package:$TOOL uid:\([0-9]*\)$/\1/p")
[ -n "$TOOL_UID" ] || fail "the test tool did not install"

adb logcat -c
adb shell am start-foreground-service -n "$TOOL/.ToolService" --ei port "$TOOL_PORT" \
    --es user watch --es password "$PASSWORD" --es map "watch.test=$HOST" >/dev/null
for _ in $(seq 1 10); do tool_log | grep -q "^listening" && break; sleep 1; done
tool_log | grep -q "^listening $TOOL_PORT" || fail "the test tool does not listen"

allow_vpn "$PKG" || fail "Android did not take the VPN consent for $PKG"
[ "$(adb shell getprop ro.build.version.sdk | tr -d '\r')" -lt 37 ] || adb shell pm grant "$PKG" android.permission.ACCESS_LOCAL_NETWORK
adb shell am force-stop "$PKG"
adb shell am start -W -n "$PKG/$WATCH_SCREEN" --ez start true >/dev/null
for _ in $(seq 1 20); do vpn_up && break; sleep 1; done
vpn_up || fail "Watch's tunnel did not come up"
echo "ok: the tunnel is up for every app"

expected="tool answering $TOOL 127.0.0.1:$TOOL_PORT uid $TOOL_UID password yes owner yes"
for attempt in 1 2 3 4 5; do
    found=$(dump find-tool | grep -E '^ *tool ' | sed 's/^ *//')
    [ "$found" = "$expected" ] && break
    echo "  search $attempt: $found" >&2
    sleep 2
done
[ "$found" = "$expected" ] || fail "Watch did not find the tool as expected: $found"
echo "ok: Watch found the tool, its port, its owner and that it wants a password"

chained=$(dump chain 127.0.0.1 "$TOOL_PORT" "$TOOL_UID" udp "$SHELL_UID" watch "$PASSWORD")
grep -q "chain on" <<<"$chained" || fail "the chain did not turn on; Watch's dump said: ${chained:-nothing}"

answer=$(ping_from_shell "$HOST")
grep -q pong <<<"$answer" || fail "TCP by address through the tool: no answer ($answer)"
log=$(tool_log)
grep -q "^connect $HOST $PORT$" <<<"$log" || fail "the tool was not asked for $HOST:$PORT"
list=$(flows)
grep -qE "^tcp [^ ]+ $HOST:$PORT $SHELL_UID opened" <<<"$list" || fail "the shell's flow is not listed"
grep -qE "^tcp [^ ]+ $HOST:$PORT $TOOL_UID opened" <<<"$list" || fail "the tool's own connection is not counted under the tool"
echo "ok: TCP by address through the tool; the tool's own connection went directly, counted under it"

answer=$(ping_from_shell watch.test)
grep -q pong <<<"$answer" || fail "TCP by name through the tool: no answer ($answer)"
grep -q "^connect watch.test $PORT$" <<<"$(tool_log)" || fail "the tool was not given the name"
grep -qE "^tcp [^ ]+ 198\.1[89]\.[0-9]+\.[0-9]+:$PORT $SHELL_UID opened dns .* watch\.test$" <<<"$(flows)" ||
    fail "the shell did not connect to a stand-in named watch.test"
echo "ok: the shell's lookup got a stand-in, and its name went to the tool"

echo=$(device 5 "echo chained-udp | toybox nc -u -w 2 watch.test $((PORT + 1))")
grep -q chained-udp <<<"$echo" || fail "UDP through the tool's relay: no echo ($echo)"
grep -q "^associate$" <<<"$(tool_log)" || fail "the tool was not asked for a UDP relay"
echo "ok: UDP through the tool's relay, by name"

chained=$(dump chain 127.0.0.1 "$TOOL_PORT" "$TOOL_UID" udp "$SHELL_UID" watch wrong-password)
grep -q "chain on" <<<"$chained" || fail "the chain with a wrong password did not turn on; Watch's dump said: ${chained:-nothing}"
grep -q pong <<<"$(ping_from_shell "$HOST")" && fail "a wrong password was let through"
grep -q "^password refused$" <<<"$(tool_log)" || fail "the tool did not see the wrong password"
echo "ok: a wrong password is refused, and nothing goes directly instead"

# Watch never logs SOCKS credentials (DESIGN.md, 13.2): neither password is in Android's log or in
# Watch's account of itself. (The passwords reached Watch only through the debug dump's command line.)
seen=$( (adb logcat -d -b main -b system -b crash; dump) 2>/dev/null | tr -d '\r')
grep -qF "$PASSWORD" <<<"$seen" && fail "the tool's password is in Android's log or Watch's dump"
grep -qF "wrong-password" <<<"$seen" && fail "a password Watch was given is in Android's log or Watch's dump"
echo "ok: no password in Android's log or in Watch's dump"

# The tool stops. A sentinel on this computer, outside Android, notes every TCP connection and UDP
# datagram that reaches its port: the emulator's own capture does not see what goes over its Wi-Fi.
# A control from Watch's own UID, which goes directly, shows that the sentinel sees what leaves.
chained=$(dump chain 127.0.0.1 "$TOOL_PORT" "$TOOL_UID" udp "$SHELL_UID" watch "$PASSWORD")
grep -q "chain on" <<<"$chained" || fail "the chain did not turn on again; Watch's dump said: ${chained:-nothing}"
adb shell am force-stop "$TOOL"
SENTINEL_PORT=$((PORT + 3))
# The test server's sentinel, held since the check began, writes a line for each connection and datagram;
# only those after this mark count.
SENTINEL_MARK=$(wc -l <"$WORK/sentinel.log")
sentinel_since() { tail -n +$((SENTINEL_MARK + 1)) "$WORK/sentinel.log"; }
sleep 1
grep -q pong <<<"$(ping_from_shell "$HOST")" && fail "with the tool stopped, the shell still reached the server"
device 6 "toybox nc -w 2 $HOST $SENTINEL_PORT </dev/null" >/dev/null
device 5 "echo stopped-udp | toybox nc -u -w 2 $HOST $SENTINEL_PORT" >/dev/null
sleep 1
[ -z "$(sentinel_since)" ] || fail "with the tool stopped, the shell reached this computer directly: $(sentinel_since | tr '\n' ' ')"
device 6 "run-as $PKG toybox nc -w 2 $HOST $SENTINEL_PORT </dev/null" >/dev/null
sleep 1
grep -q '^tcp$' <<<"$(sentinel_since)" || fail "the sentinel did not see the control's direct connection: the check proves nothing"
echo "ok: with the tool stopped, the shell's TCP and UDP failed, and a sentinel on this computer saw none of them, only the control's direct connection"

unchained=$(dump unchain)
grep -q "chain off" <<<"$unchained" || fail "the chain did not turn off; Watch's dump said: ${unchained:-nothing}"

# The user's own path, on the chain screen in English. The tool starts without a password; Watch finds it
# and offers its own user name and password, which go into the tool as a user would set them.
adb shell cmd locale set-app-locales "$PKG" --locales en-US >/dev/null 2>&1 || true
listening=$(tool_log | grep -c "^listening")
adb shell am start-foreground-service -n "$TOOL/.ToolService" --ei port "$TOOL_PORT" --es map "watch.test=$HOST" >/dev/null
for _ in $(seq 1 10); do [ "$(tool_log | grep -c "^listening")" -gt "$listening" ] && break; sleep 1; done
# Back to Watch as a user comes back to it, which makes it look for the tool again.
adb shell input keyevent KEYCODE_HOME
sleep 1
adb shell am start -W -n "$PKG/$WATCH_SCREEN" >/dev/null
SWITCH="Send apps through Datapavan test tool"
# A search that missed the listening tool is a defect of Watch's, which a user sees as "not answering"
# (docs/ci-flakes.md, "Defects found by flakes"): the check looks once more, so that the rest of the screen
# is still checked, but every second look is a warning on the run and a line in its summary.
searched_again() {
    echo "::warning title=Watch's tool search::$1"
    [ -z "${GITHUB_STEP_SUMMARY:-}" ] || echo "- verify-chain.sh: $1 (a known defect, docs/ci-flakes.md)" >>"$GITHUB_STEP_SUMMARY"
    search_log | grep '^screen: ' | tail -3 | sed 's/^/    /' >&2 || true
}
# Waits for the chain screen's search to offer the tool. The search, and the first password after a fresh
# start (a new Keystore key), take a few seconds: they are waited for before scrolling, or the scroll moves
# the section off the screen before it is drawn. A search that missed the tool leaves "Look again" on the
# screen, which a user would tap; then it is tapped. The search runs again each time the screen comes back
# to the front, and it once missed the tool there, after the screen had first found it (CI, 2026-11-14:
# "ConnectException", then the tool found again a moment later), which took the user name and password off
# the screen.
search_offers_tool() {
    scroll_to_top
    within 30 screen_has "$SWITCH" && return 0
    screen_has "Look again" || return 1
    searched_again "the chain screen's search missed the listening tool; looking again"
    adb shell cat "$DUMP" 2>/dev/null | grep -o 'text="[^"]\+"' | sed -n '5,9p' | sed 's/^/    screen: /' >&2 || true
    echo "    the service's search now: $(dump find-tool | grep -E '^ *tool ' | sed 's/^ *//')" >&2
    tap_text "Look again" || true
    scroll_to_top
    within 30 screen_has "$SWITCH"
}
# The screen in front again, as a user brings it back: its search runs again.
reopen_screen() {
    adb shell input keyevent KEYCODE_HOME
    sleep 1
    adb shell am start -W -n "$PKG/$WATCH_SCREEN" >/dev/null
}
# True once the screen shows the text $1 from the tool's section, after at most one more search.
screen_says() {
    local try
    for try in 1 2; do
        search_offers_tool || true
        scroll_to "$1" && return 0
        [ "$try" = 2 ] && break
        searched_again "the chain screen did not say \"$1\"; bringing it back to search once more"
        reopen_screen
    done
    return 1
}
screen_says "$SWITCH" || fail "the chain screen did not offer the test tool"
# The tool's proxy answered without asking for a password: the screen says what that lets other apps
# do (ADR 0041, decision 5). The test tool can take a password, so the screen does not say it has none.
screen_says "The proxy of Datapavan test tool asks for no password, so any app on this phone can use it." ||
    fail "the chain screen did not say that any app on the phone can use the tool's open proxy"
screen_has "Datapavan test tool has no setting for a password" && fail "the chain screen said the test tool takes no password"
echo "ok: the screen says that any app can use the tool's proxy while it asks for no password"
# The user name sits just above the password, and either can be at the screen's edge: each is read from
# a dump taken once it is on the screen. A text not found leaves its value empty, for the check below,
# instead of ending the script without a word under pipefail (CI, 2026-11-12).
read_shown() {
    scroll_to "$1" || return 0
    dump_screen || true
    { adb shell cat "$DUMP" | tr -d '\r' | grep -o "text=\"$1[^\"]*\"" | sed "s/^text=\"$1//; s/\"\$//" | head -1; } || true
}
# The user name and password show while the screen's last search found the tool: if they are missing, the
# search is run once more, as a user would by leaving the screen and coming back. What the screen must
# offer is unchanged.
for try in 1 2; do
    user=$(read_shown "User name: ")
    password=$(read_shown "Password: ")
    [ -n "$user" ] && [ -n "$password" ] && break
    [ "$try" = 2 ] && break
    searched_again "the chain screen showed no user name and password; bringing it back to search once more"
    reopen_screen
    search_offers_tool || true
done
[ -n "$user" ] && [ -n "$password" ] || fail "the chain screen offered no user name and password for the tool"
listening=$(tool_log | grep -c "^listening")
stun_listening=$(tool_log | grep -cE "^stun 127\.0\.0\.[12] $STUN_PORT$" || true)
adb shell am force-stop "$TOOL"
adb shell am start-foreground-service -n "$TOOL/.ToolService" --ei port "$TOOL_PORT" \
    --es user "$user" --es password "$password" --ei stun "$STUN_PORT" \
    --es map "watch.test=$HOST,stun-a.test=127.0.0.1,stun-b.test=127.0.0.2" >/dev/null
for _ in $(seq 1 10); do [ "$(tool_log | grep -c "^listening")" -gt "$listening" ] && break; sleep 1; done
# The STUN server for unit 9b's step starts with the tool here, the only start that asks for it. Its two
# lines are read now, not at the step near the end of the run, by when logcat's ring may have turned past
# them (unit 9b, fix round 2), and counted from before this start, so that lines of an earlier run cannot
# stand in for them.
stun_lines() { tool_log | grep -cE "^stun 127\.0\.0\.[12] $STUN_PORT$" || true; }
for _ in $(seq 1 10); do [ "$(stun_lines)" -ge $((stun_listening + 2)) ] && break; sleep 1; done
[ "$(stun_lines)" -ge $((stun_listening + 2)) ] ||
    fail "the test tool's STUN server does not listen at 127.0.0.1 and 127.0.0.2: $(tool_log | grep '^stun' | tail -4 | tr '\n' ' ')"
# The state of the row showing exactly the text $1 in the last dump: "chosen", "not chosen" or "absent".
# The row is the element with that text, or the nearest one around it that can be checked or selected.
row_state() {
    adb shell cat "$DUMP" | python3 -I -c '
import sys, xml.etree.ElementTree as ET
text = sys.argv[1]
root = ET.fromstring(sys.stdin.read())
parents = {child: parent for parent in root.iter() for child in parent}
state = "absent"
for node in root.iter("node"):
    if node.get("text") != text:
        continue
    state = "not chosen"
    while node is not None:
        if node.get("checked") == "true" or node.get("selected") == "true":
            print("chosen")
            sys.exit(0)
        if node.get("checkable") == "true":
            break
        node = parents.get(node)
print(state)' "$1"
}
# True when the row showing $1 is on the screen and chosen.
marked() {
    dump_screen || return 1
    [ "$(row_state "$1")" = chosen ]
}
# Taps the row showing $1 until it shows as chosen, and leaves it chosen if it already was. Each try
# looks for the row from the top of the screen, since scroll_to only looks further down and a tapped row
# may move up as the list around it changes. A tap can be lost while the screen moves (CI, 2026-11-13:
# the choice of apps stayed on every app, and the shell, not picked, went through the tool).
choose() {
    local try
    for try in 1 2 3; do
        scroll_to_top
        scroll_to "$1" || { echo "    \"$1\" not found on try $try" >&2; continue; }
        marked "$1" && return 0
        tap_text "$1" || { echo "    \"$1\" could not be tapped on try $try" >&2; continue; }
        for _ in 1 2 3; do
            sleep 1
            marked "$1" && return 0
        done
        echo "    \"$1\" was $(row_state "$1") after the tap of try $try" >&2
    done
    return 1
}
# The password is below the choice of apps, and scroll_to only looks further down: back to the top first.
scroll_to_top
choose "Only the apps I choose" || fail "the chain screen did not take the choice of apps"
# The other choice is then not marked: this also shows that marked tells the two apart.
marked "Every app" && fail "the chain screen shows both choices of apps as chosen"
# The list of apps loads in the background.
for _ in $(seq 1 15); do screen_has "Datapavan workload" && break; sleep 1; done
choose "Datapavan workload" || fail "the workload app could not be chosen"
# The list of apps pushed the switch up, off the screen.
scroll_to_top
choose "$SWITCH" || fail "the chain's switch did not turn on"
scroll_to_top
scroll_to "Only the apps I choose" && marked "Only the apps I choose" || fail "the choice of apps changed when the chain turned on"
scroll_to_top
sleep 2
through=$(tool_log | grep -c "^connect watch.test $PORT$")
associations=$(tool_log | grep -c "^associate$" || true)
# Runs the workload app once with the extras given, and prints its log lines of that run.
work() {
    local runs
    runs=$(workload_log | grep -c "^done$" || true)
    adb shell am start -W -n "$WORKLOAD/.WorkActivity" "$@" >/dev/null
    for _ in $(seq 1 "${WORK_WAIT:-30}"); do [ "$(workload_log | grep -c "^done$")" -gt "$runs" ] && break; sleep 1; done
    workload_log | awk -v runs="$runs" '$0 == "done" { done++; next } done == runs'
}
log=$(work --es name watch.test --es tcp "watch.test:$PORT" --es udp "watch.test:$((PORT + 1))")
grep -qE "^resolved watch\.test 198\.1[89]\." <<<"$log" || fail "the workload app's lookup got no stand-in: $log"
grep -q "^tcp watch.test:$PORT pong$" <<<"$log" || fail "the workload app's TCP did not get through: $log"
# TCP only until the user allows UDP (ADR 0041, decision 5): the echo server on this computer would
# answer a datagram that went through the tool or directly, so no echo means it went nowhere.
grep -q "^udp watch.test:$((PORT + 1)) echo$" <<<"$log" && fail "the workload app's UDP got through before the user allowed it"
[ "$(tool_log | grep -c "^associate$")" = "$associations" ] || fail "the tool was asked for a UDP relay before the user allowed it"
[ "$(tool_log | grep -c "^connect watch.test $PORT$")" -gt "$through" ] || fail "the workload app's TCP did not go through the tool"
grep -qE "^tcp [^ ]+ 198\.1[89]\.[0-9]+\.[0-9]+:$PORT $WORKLOAD_UID opened" <<<"$(flows)" ||
    fail "the workload app's flow is not listed under its own UID"
through=$(tool_log | grep -c "^connect $HOST $PORT$")
grep -q pong <<<"$(ping_from_shell "$HOST")" || fail "adb's shell, not picked, did not reach the server"
[ "$(tool_log | grep -c "^connect $HOST $PORT$")" = "$through" ] || fail "adb's shell, not picked, went through the tool"
echo "ok: on the chain screen: Watch's password set in the tool, one picked app's lookup and TCP through the tool, its UDP nowhere until allowed, the shell directly"

# The live view "Now" (ADR 0046, decision 6, item 5): with "Log where these apps connect" off, it keeps no
# destination of the picked app, only its bytes, marked as through the tool; it marks the tool; and it keeps
# the destinations of the shell, which goes directly. Watch's debug dump prints counts, no destination.
grep -q 'activity-read true' <<<"$(dump activity-read)" || fail "the tracker of the apps' states did not read"
activity_line() { grep "^activity-app $1 " <<<"$(dump | sed 's/^ *//')" || true; }
chained=$(activity_line "$WORKLOAD_UID")
grep -q " through-tool=1 places=0 " <<<"$chained" || fail "the live view keeps a destination of the picked app: $chained"
grep -q " tool=1 " <<<"$(activity_line "$TOOL_UID")" || fail "the live view does not mark the tool: $(activity_line "$TOOL_UID")"
grep -qE " places=[1-9]" <<<"$(activity_line 2000)" || fail "the live view keeps no destination of the shell: $(activity_line 2000)"
echo "ok: the live view keeps no destination of the picked app while its destinations are not logged, and marks the tool"
# The same from the screen (W5's third part): "Now" shows the picked app's bytes as sent through the tool, and
# no place it reached.
screens=$(mktemp -d)
chained_screen=$(watch_now "$PKG" "$WORKLOAD" "$screens/now.xml")
rm -rf "$screens"
adb shell input keyevent KEYCODE_BACK
grep -qx through-tool <<<"$chained_screen" || fail "\"Now\" does not show the picked app as sent through the tool: $(tr '\n' ';' <<<"$chained_screen" | cut -c1-800)"
! grep -q '^place ' <<<"$chained_screen" || fail "\"Now\" names a place the picked app reached: $(grep '^place ' <<<"$chained_screen")"
echo "ok: on the screen, \"Now\" shows the picked app through the tool, with no place it reached"

# Back on the screen, which looks for the tool again: its proxy now asks for a password. The user then
# allows UDP, and the picked app's datagrams go through the tool's relay.
adb shell am start -W -n "$PKG/$WATCH_SCREEN" >/dev/null
UDP_SWITCH="Send UDP through Datapavan test tool too"
screen_says "The proxy of Datapavan test tool asks for a password, so other apps on this phone cannot use it." ||
    fail "the chain screen did not say that the tool's proxy now asks for a password"
tap_text "$UDP_SWITCH" || fail "the chain screen has no switch for UDP"
sleep 2
log=$(work --es udp "watch.test:$((PORT + 1))")
grep -q "^udp watch.test:$((PORT + 1)) echo$" <<<"$log" || fail "the workload app's UDP did not get through once allowed: $log"
[ "$(tool_log | grep -c "^associate$")" -gt "$associations" ] || fail "the tool was not asked for a UDP relay once UDP was allowed"
echo "ok: the screen says the proxy asks for a password; with UDP allowed, the picked app's UDP goes through the tool"

# Two names on one port, asked at once from one socket (ADR 0044, unit 9b). The tool resolves them to
# 127.0.0.1 and 127.0.0.2, where its STUN server answers on the same port, so the app's two stand-ins
# both wait on that port when the answers come back through the relay, each from an address the app
# never saw. Before unit 9b both were dropped, as either name's; now each reaches the app from its own
# stand-in, told by its transaction ID. The workload app resolves both names before it sends, and sends
# the two requests back to back, so that the first answer finds both stand-ins waiting: the 48th counter,
# the answers told by an identifier where the address alone could not tell, must grow by one at least
# (the second answer may find the first stand-in bound already). The emulator's first run of this step
# resolved the second name between the two sends, and passed with the counter at 0, as unit 9 would
# have: it showed nothing of unit 9b. The app sends each request again until it is answered, with its
# transaction ID, as RFC 8489 6.2.1 has a client do, for up to 39.5 s (fix round 2). The counter is read
# with when the engine's counters began: an engine Watch started afresh between the two reads counted from
# 0 again, which says nothing of this step either way, so the step runs once more, and a second such
# start fails the run as that, never as a pass or as unit 9b's failure.
for attempt in 1 2; do
    before=$(counter_since 48)
    log=$(WORK_WAIT=45 work --es stun "stun-a.test,stun-b.test:$STUN_PORT")
    after=$(counter_since 48)
    [ "${before%% *}" = "${after%% *}" ] && break
    [ "$attempt" = 2 ] &&
        fail "Watch's engine started afresh during the STUN step, twice (counters since ${before%% *}, then ${after%% *}): whether unit 9b told the answers apart cannot be read"
    restarted="Watch's engine started afresh during the STUN step (counters since ${before%% *}, then ${after%% *}); the step runs once more"
    echo "::warning title=Watch's engine::$restarted"
    [ -z "${GITHUB_STEP_SUMMARY:-}" ] || echo "- verify-chain.sh: $restarted" >>"$GITHUB_STEP_SUMMARY"
done
grep -qE "^stun stun-a\.test,stun-b\.test:$STUN_PORT both after [0-9]+ sendings$" <<<"$log" ||
    fail "two STUN requests to two names on one port, from one socket: not both answered: $log; $(tool_log | grep '^stun' | tail -4 | tr '\n' ' ')"
identified=${before#* }
told=${after#* }
[ "$told" -gt "$identified" ] ||
    fail "both STUN answers came, but none was told by its transaction ID (48th counter $identified, then $told, the engine's counters since ${after%% *}): the step did not reach unit 9b"
echo "ok: two STUN names asked at once on one port through the tool, each answered from its own stand-in, told by their IDs ($identified, then $told; $(sed -n 's/.* both after \([0-9]*\) sendings$/\1/p' <<<"$log") sendings)"

# The screen looked for the tool again when the workload app left it. A search that says a listening
# tool does not answer is W6's open finding (CI, 2026-11-12): not a failure yet, but its steps are shown.
WAITING="Datapavan test tool does not answer"
if screen_has "$WAITING"; then
    echo "  note: the chain screen's search says the test tool does not answer" >&2
    echo "    the tool's process: $(adb shell pidof "$TOOL" | tr -d '\r' || true)" >&2
    search_log | tail -12 | sed 's/^/    search: /' >&2 || true
fi

# The tool stops while the chain is on: the screen says the apps wait, and its switch still turns the
# chain off, after which the picked app goes directly.
adb shell am force-stop "$TOOL"
adb shell input keyevent KEYCODE_HOME
sleep 1
adb shell am start -W -n "$PKG/$WATCH_SCREEN" >/dev/null
for _ in $(seq 1 30); do screen_has "$WAITING" && break; sleep 1; done
screen_has "$WAITING" || fail "with the tool stopped and the chain on, the screen did not say that the tool does not answer"
scroll_to_top
tap_text "$SWITCH" || fail "with the tool stopped, the chain's switch was not on the screen to turn it off"
sleep 2
direct=$(workload_log | grep -c "^tcp $HOST:$PORT pong$" || true)
adb shell am start -W -n "$WORKLOAD/.WorkActivity" --es tcp "$HOST:$PORT" >/dev/null
for _ in $(seq 1 20); do [ "$(workload_log | grep -c "^tcp $HOST:$PORT pong$" || true)" -gt "$direct" ] && break; sleep 1; done
[ "$(workload_log | grep -c "^tcp $HOST:$PORT pong$" || true)" -gt "$direct" ] ||
    fail "after the chain was turned off with the tool stopped, the picked app did not reach the server: $(workload_log | tail -3 | tr '\n' ' ')"
echo "ok: with the tool stopped, the screen says the apps wait, and its switch turns the chain off; the picked app then goes directly"

# An app left out of the tunnel (ADR 0041), chosen on the screen as a user would: Watch sets its tunnel up
# again, the app still reaches the server, and Watch sees no new traffic of it. Taken back, Watch sees it
# again. Whichever way the setup went, a new engine (the apps left out changed, so Android brings up a new VPN
# network, ADR 0044, unit 12b) or the running one keeping its flows, only a flow that was not there before
# counts, by its protocol, the app's end and the destination, so that a UDP socket reused toward another
# destination counts too.
workload_flows_now() { flows | grep " $WORKLOAD_UID " || true; }
# The workload's flows now that were not among $1.
new_workload_flows() {
    local now
    now=$(workload_flows_now)
    awk 'NR == FNR { seen[$1 " " $2 " " $3] = 1; next } NF && !(($1 " " $2 " " $3) in seen)' <(printf '%s\n' "$1") <(printf '%s\n' "$now")
}
workload_reaches() {
    local before
    before=$(workload_log | grep -c "^tcp $HOST:$PORT pong$" || true)
    adb shell am start -W -n "$WORKLOAD/.WorkActivity" --es tcp "$HOST:$PORT" >/dev/null
    for _ in $(seq 1 20); do [ "$(workload_log | grep -c "^tcp $HOST:$PORT pong$" || true)" -gt "$before" ] && return 0; sleep 1; done
    return 1
}
adb shell am start -W -n "$PKG/$WATCH_SCREEN" >/dev/null
seen=$(workload_flows_now)
tap_text "Choose apps to leave out" || fail "the screen has no button to leave apps out"
tap_text "Datapavan workload" || fail "the workload app is not in the list of apps to leave out"
sleep 2
for _ in $(seq 1 20); do vpn_up && break; sleep 1; done
vpn_up || fail "Watch's tunnel did not come back after an app was left out"
scroll_to_top
scroll_to "1 app is left out." || fail "the screen does not say that one app is left out"
workload_reaches || fail "the app left out did not reach the server"
fresh=$(new_workload_flows "$seen")
[ -z "$fresh" ] || fail "Watch still saw the left-out app's traffic: $(head -3 <<<"$fresh" | tr '\n' ';')"
echo "ok: an app left out on the screen reaches the server without Watch seeing it"
seen=$(workload_flows_now)
tap_text "Datapavan workload" || fail "the workload app could not be taken back"
sleep 2
for _ in $(seq 1 20); do vpn_up && break; sleep 1; done
vpn_up || fail "Watch's tunnel did not come back after the app was taken back"
scroll_to_top
scroll_to "No app is left out." || fail "the screen does not say that no app is left out"
workload_reaches || fail "the app taken back did not reach the server"
for _ in $(seq 1 10); do [ -n "$(new_workload_flows "$seen")" ] && break; sleep 1; done
[ -n "$(new_workload_flows "$seen")" ] || fail "Watch did not see the app's traffic after it was taken back"
echo "ok: taken back, the app passes through Watch again"
echo "== chain check passed"
