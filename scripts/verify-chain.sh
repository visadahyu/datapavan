#!/usr/bin/env bash
# W6's end-to-end check of chaining (docs/DESIGN.md, 13.2; docs/VPN.md; ADR 0038), on an emulator.
# The test tool (scripts/test-tool) runs a SOCKS5 proxy with a password on the phone's loopback, as a
# circumvention tool does in proxy mode. The network part must find it by itself: its package, its port, that
# Android names it as the port's owner, and that it wants a password. With adb's shell (UID 2000)
# chained through it, TCP reaches the test server on this computer by address and by a name only the
# tool can resolve (the shell gets a stand-in address for it), UDP goes through the tool's relay, the
# tool's own connections go directly and are counted under the tool, and a wrong password is refused.
# Then the tool stops: the shell's connections fail, and a sentinel on this computer, outside Android,
# sees none of them reach it directly, while it does see a control's direct connection. Last, the user's
# own path on the chain screen: the network part offers its password, which is set in the tool; one installed app
# (scripts/workload-app) is picked and the chain turned on; that app's lookup and TCP go through the
# tool under its own UID, its UDP goes nowhere until the user allows UDP on the screen and then through
# the tool, and adb's shell, not picked, goes directly. The screen says what the tool's proxy lets other
# apps do, without a password and then with one (ADR 0041, decision 5). Then the tool stops with the chain
# on: the screen says the apps wait, its switch still turns the chain off, and the picked app then goes
# directly. With UDP allowed, the picked app also sends STUN requests from one socket to two names on one
# port at once, and both answers must reach it (ADR 0044, unit 9b). Last, that app is left out of the
# tunnel on the screen (ADR 0041): the network part sets its tunnel up again, the app reaches the server and the network
# part no longer sees it; taken back, the network part sees it again. On the way, the chain section links the test
# tool's guide (W8, part 3b), which quotes the label read from the installed tool's own resources. On the way too, the
# tool's own row (the proxy record's unit D, R10, as the maintainer decided on 2026-11-25, option (c)): with "Log where
# apps connect ..." off, every connection of the tool shows in "Now" there only, for its window, its own connection to a
# server of its own and those it makes directly for the picked app alike, and the log keeps none of their addresses;
# the tool's own choice logs its own connection with its address and never the one it made for the picked app's
# request by address, while one by a name only the tool resolves, which nothing ties to what the chain asked, is logged
# as its own, as the choice's words say; with the switch on, both are logged. Then the same with the chain turned off on
# its screen, the test tool counted as a tool by debug builds' rule alone. Nothing
# is left running: the tunnel, the tool and the server stop at the end, and the tool is uninstalled.
#
#   scripts/verify-chain.sh [path/to/Datapavan-Advanced-debug.apk]
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APK="${1:-$ROOT/android/app/build-advanced/outputs/apk/debug/app-debug.apk}"
PKG=org.visadahyu.datapavan.advanced
# The network screen in Datapavan Advanced (ADR 0045); debug builds export it for these checks.
NETWORK_SCREEN=org.visadahyu.datapavan.network.MainActivity
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
# (scripts/host-ports.sh): NETWORK_TEST_PORT, or a base picked from 8790 up.
# shellcheck source=scripts/host-ports.sh
. "$ROOT/scripts/host-ports.sh"
PASSWORD="$(python3 -I -c 'import secrets;print(secrets.token_urlsafe(15))')"
WORK="$(mktemp -d)"
# The screens' dumps, apart from WORK and its password: a failure keeps them (adb-ui.sh's keep_evidence).
SCREENS=$(mktemp -d)
CHECK_DUMPS=$SCREENS
SERVER=""

cleanup() {
    # The switch and the tool's choice back off, whatever step failed (review D-rest m9): the next run starts from a
    # cleared app all the same.
    if [ -n "${TOOL_UID:-}" ]; then
        dump log-destinations off >/dev/null 2>&1 || true
        dump tool-log "$TOOL" off >/dev/null 2>&1 || true
    fi
    adb shell am force-stop "$PKG" >/dev/null 2>&1 || true
    adb shell am force-stop "$TOOL" >/dev/null 2>&1 || true
    adb uninstall "$TOOL" >/dev/null 2>&1 || true
    adb uninstall "$WORKLOAD" >/dev/null 2>&1 || true
    [ -z "$SERVER" ] || kill "$SERVER" 2>/dev/null || true
    rm -rf "$WORK" "$SCREENS"
}
check_evidence_on cleanup
host_server --sentinel "$WORK/sentinel.log" --tool || exit 1
# The tool's own server, which answers a line (unit D, D9), and the port of the request by a name only the tool resolves.
OWN_PORT=$((PORT + 4))
RESIDUAL_PORT=$((PORT + 5))

dump() { adb shell dumpsys activity service "$PKG/org.visadahyu.datapavan.network.NetworkVpnService" "$@" | tr -d '\r'; }
# When the engine's counters began, then its counter at place $1, counting from 1, as the network part's dump prints
# them, from one dump: two reads with another beginning span an engine the network part started afresh, whose
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
    check_failed "$*"
    echo "CHAIN CHECK FAILED: $*" >&2
    if dump_screen 2>/dev/null; then
        echo "On the screen:" >&2
        adb shell cat "$DUMP" 2>/dev/null | grep -o 'text="[^"]\+"' | head -20 >&2 || true
    fi
    echo "The tool's requests:" >&2
    tool_log | tail -20 >&2 || true
    echo "The flows of the shell and the tool:" >&2
    flows | grep -E " ($SHELL_UID|${TOOL_UID:-x}) " | tail -20 >&2 || true
    echo "the network part's searches for the tool (debug log):" >&2
    search_log | tail -20 >&2 || true
    adb logcat -d -b crash 2>/dev/null | tail -30 >&2 || true
    exit 1
}

# The steps of the network part's searches for the tool, which a debug build logs (Tools.search).
search_log() { adb logcat -d -s NetworkChain | tr -d '\r' | sed -n 's/.*NetworkChain: //p'; }

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
    --es user datapavan --es password "$PASSWORD" --es map "network.test=$HOST" >/dev/null
for _ in $(seq 1 10); do tool_log | grep -q "^listening" && break; sleep 1; done
tool_log | grep -q "^listening $TOOL_PORT" || fail "the test tool does not listen"

allow_vpn "$PKG" || fail "Android did not take the VPN consent for $PKG"
[ "$(adb shell getprop ro.build.version.sdk | tr -d '\r')" -lt 37 ] || adb shell pm grant "$PKG" android.permission.ACCESS_LOCAL_NETWORK
adb shell am force-stop "$PKG"
adb shell am start -W -n "$PKG/$NETWORK_SCREEN" --ez start true >/dev/null
for _ in $(seq 1 20); do vpn_up && break; sleep 1; done
vpn_up || fail "the network part's tunnel did not come up"
echo "ok: the tunnel is up for every app"

expected="tool answering $TOOL 127.0.0.1:$TOOL_PORT uid $TOOL_UID password yes owner yes"
for attempt in 1 2 3 4 5; do
    found=$(dump find-tool | grep -E '^ *tool ' | sed 's/^ *//')
    [ "$found" = "$expected" ] && break
    echo "  search $attempt: $found" >&2
    sleep 2
done
[ "$found" = "$expected" ] || fail "the network part did not find the tool as expected: $found"
echo "ok: the network part found the tool, its port, its owner and that it wants a password"

chained=$(dump chain 127.0.0.1 "$TOOL_PORT" "$TOOL_UID" udp "$SHELL_UID" datapavan "$PASSWORD")
grep -q "chain on" <<<"$chained" || fail "the chain did not turn on; the network part's dump said: ${chained:-nothing}"

answer=$(ping_from_shell "$HOST")
grep -q pong <<<"$answer" || fail "TCP by address through the tool: no answer ($answer)"
log=$(tool_log)
grep -q "^connect $HOST $PORT$" <<<"$log" || fail "the tool was not asked for $HOST:$PORT"
list=$(flows)
grep -qE "^tcp [^ ]+ $HOST:$PORT $SHELL_UID opened" <<<"$list" || fail "the shell's flow is not listed"
grep -qE "^tcp [^ ]+ $HOST:$PORT $TOOL_UID opened" <<<"$list" || fail "the tool's own connection is not counted under the tool"
echo "ok: TCP by address through the tool; the tool's own connection went directly, counted under it"

answer=$(ping_from_shell network.test)
grep -q pong <<<"$answer" || fail "TCP by name through the tool: no answer ($answer)"
grep -q "^connect network.test $PORT$" <<<"$(tool_log)" || fail "the tool was not given the name"
grep -qE "^tcp [^ ]+ 198\.1[89]\.[0-9]+\.[0-9]+:$PORT $SHELL_UID opened dns .* network\.test$" <<<"$(flows)" ||
    fail "the shell did not connect to a stand-in named network.test"
echo "ok: the shell's lookup got a stand-in, and its name went to the tool"

echo=$(device 5 "echo chained-udp | toybox nc -u -w 2 network.test $((PORT + 1))")
grep -q chained-udp <<<"$echo" || fail "UDP through the tool's relay: no echo ($echo)"
grep -q "^associate$" <<<"$(tool_log)" || fail "the tool was not asked for a UDP relay"
echo "ok: UDP through the tool's relay, by name"

chained=$(dump chain 127.0.0.1 "$TOOL_PORT" "$TOOL_UID" udp "$SHELL_UID" datapavan wrong-password)
grep -q "chain on" <<<"$chained" || fail "the chain with a wrong password did not turn on; the network part's dump said: ${chained:-nothing}"
grep -q pong <<<"$(ping_from_shell "$HOST")" && fail "a wrong password was let through"
grep -q "^password refused$" <<<"$(tool_log)" || fail "the tool did not see the wrong password"
echo "ok: a wrong password is refused, and nothing goes directly instead"

# The network part never logs SOCKS credentials (DESIGN.md, 13.2): neither password is in Android's log or in
# the network part's account of itself. (The passwords reached the network part only through the debug dump's command
# line.)
seen=$( (adb logcat -d -b main -b system -b crash; dump) 2>/dev/null | tr -d '\r')
grep -qF "$PASSWORD" <<<"$seen" && fail "the tool's password is in Android's log or the network part's dump"
grep -qF "wrong-password" <<<"$seen" && fail "a password the network part was given is in Android's log or the network part's dump"
echo "ok: no password in Android's log or in the network part's dump"

# The tool stops. A sentinel on this computer, outside Android, notes every TCP connection and UDP
# datagram that reaches its port: the emulator's own capture does not see what goes over its Wi-Fi.
# A control from the network part's own UID, which goes directly, shows that the sentinel sees what leaves.
chained=$(dump chain 127.0.0.1 "$TOOL_PORT" "$TOOL_UID" udp "$SHELL_UID" datapavan "$PASSWORD")
grep -q "chain on" <<<"$chained" || fail "the chain did not turn on again; the network part's dump said: ${chained:-nothing}"
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
grep -q "chain off" <<<"$unchained" || fail "the chain did not turn off; the network part's dump said: ${unchained:-nothing}"

# The user's own path, on the chain screen in English. The tool starts without a password; the network part finds it
# and offers its own user name and password, which go into the tool as a user would set them.
adb shell cmd locale set-app-locales "$PKG" --locales en-US >/dev/null 2>&1 || true
listening=$(tool_log | grep -c "^listening")
adb shell am start-foreground-service -n "$TOOL/.ToolService" --ei port "$TOOL_PORT" --es map "network.test=$HOST" >/dev/null
for _ in $(seq 1 10); do [ "$(tool_log | grep -c "^listening")" -gt "$listening" ] && break; sleep 1; done
# Back to the network part as a user comes back to it, which makes it look for the tool again.
adb shell input keyevent KEYCODE_HOME
sleep 1
adb shell am start -W -n "$PKG/$NETWORK_SCREEN" >/dev/null
SWITCH="Send apps through Datapavan test tool"
# A search that missed the listening tool is a defect of the network part's, which a user sees as "not answering"
# (docs/ci-flakes.md, "Defects found by flakes"): the check looks once more, so that the rest of the screen
# is still checked, but every second look is a warning on the run and a line in its summary.
searched_again() {
    echo "::warning title=the network part's tool search::$1"
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
    adb shell am start -W -n "$PKG/$NETWORK_SCREEN" >/dev/null
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
# W8, part 3b: the chain section links the guide of each tool of the table installed here, the test tool's among
# them (src/debug/assets/test-guides.tsv). The guide quotes the tool's label as the tool's own resources have it
# (scripts/test-tool/res), not as the data records it: the network part read it from the installed tool by its name.
GUIDE_LINK="Datapavan test tool in proxy mode"
# Read whole, then searched: under pipefail, a grep -q that stops reading early would fail the pipe.
guide_says() {
    local screen
    dump_screen || return 1
    screen=$(adb shell cat "$DUMP" 2>/dev/null) || return 1
    grep -qF "$1" <<<"$screen"
}
tap_text "$GUIDE_LINK" || fail "the chain section did not link the test tool's guide"
# The guide is longer than a screen: what it says further down is read after scrolling to it.
guide_scrolls_to() {
    for _ in 1 2 3 4 5 6; do
        guide_says "$1" && return 0
        guide_says "Recorded switch of the test tool" && return 1
        swipe_up
    done
    guide_says "$1"
}
within 10 guide_says "Proxy switch of the test tool" || fail "the test tool's guide did not quote the label read from the tool"
guide_says "Recorded switch of the test tool" && fail "the test tool's guide quoted the recorded label, not the tool's own"
guide_scrolls_to "are read from" || fail "the test tool's guide did not say its labels were read from the tool"
guide_says "Recorded switch of the test tool" && fail "the test tool's guide quoted the recorded label further down"
adb shell input keyevent KEYCODE_BACK
# Back in the chain section, which the guides' heading tells from the guide, the link can sit below the screen: the
# lines under the switch grew with unit D's, and the section keeps its place. So both are scrolled to.
within 10 scroll_to "How the tools on this phone run beside Datapavan:" || fail "Back from the guide did not return to the chain section"
scroll_to "$GUIDE_LINK" || fail "the chain section no longer links the test tool's guide after Back"
# The links are below the user name and password, which the next step reads scrolling down from the top.
scroll_to_top
echo "ok: the chain section links the installed tool's guide, which quotes the label read from the tool's own resources"
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
    --es map "network.test=$HOST,stun-a.test=127.0.0.1,stun-b.test=127.0.0.2" >/dev/null
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
through=$(tool_log | grep -c "^connect network.test $PORT$")
associations=$(tool_log | grep -c "^associate$" || true)
# Runs the workload app once with the extras given, and prints its log lines of that run.
work() {
    local runs
    runs=$(workload_log | grep -c "^done$" || true)
    adb shell am start -W -n "$WORKLOAD/.WorkActivity" "$@" >/dev/null
    for _ in $(seq 1 "${WORK_WAIT:-30}"); do [ "$(workload_log | grep -c "^done$")" -gt "$runs" ] && break; sleep 1; done
    workload_log | awk -v runs="$runs" '$0 == "done" { done++; next } done == runs'
}
log=$(work --es name network.test --es tcp "network.test:$PORT" --es udp "network.test:$((PORT + 1))")
grep -qE "^resolved network\.test 198\.1[89]\." <<<"$log" || fail "the workload app's lookup got no stand-in: $log"
grep -q "^tcp network.test:$PORT pong$" <<<"$log" || fail "the workload app's TCP did not get through: $log"
# TCP only until the user allows UDP (ADR 0041, decision 5): the echo server on this computer would
# answer a datagram that went through the tool or directly, so no echo means it went nowhere.
grep -q "^udp network.test:$((PORT + 1)) echo$" <<<"$log" && fail "the workload app's UDP got through before the user allowed it"
[ "$(tool_log | grep -c "^associate$")" = "$associations" ] || fail "the tool was asked for a UDP relay before the user allowed it"
[ "$(tool_log | grep -c "^connect network.test $PORT$")" -gt "$through" ] || fail "the workload app's TCP did not go through the tool"
grep -qE "^tcp [^ ]+ 198\.1[89]\.[0-9]+\.[0-9]+:$PORT $WORKLOAD_UID opened" <<<"$(flows)" ||
    fail "the workload app's flow is not listed under its own UID"
through=$(tool_log | grep -c "^connect $HOST $PORT$")
grep -q pong <<<"$(ping_from_shell "$HOST")" || fail "adb's shell, not picked, did not reach the server"
[ "$(tool_log | grep -c "^connect $HOST $PORT$")" = "$through" ] || fail "adb's shell, not picked, went through the tool"
echo "ok: on the chain screen: the network part's password set in the tool, one picked app's lookup and TCP through the tool, its UDP nowhere until allowed, the shell directly"

# The live view "Now" (ADR 0046, decision 6, item 5), with the tool's own row (the proxy record's unit D, R10, option (c)
# of 2026-11-25). With "Log where apps connect ..." off, it keeps no destination of the picked app, only its bytes, marked
# as through the tool; it marks the tool; and it keeps the destinations of the shell, which goes directly. Every
# connection of the tool shows under the tool's row, there only, for its window: its own connection to its server
# (D9), and those it makes directly for the picked app, by address and by a name only the tool resolves, each at a port of
# its own (audit-D M5). The log keeps no address of any of them. "Now" keys a place with no name by its address alone
# (`same_place`), so the three are one place at the test server's address, showing one of their ports: the live view
# is counted per address, and the ports are told apart by the debug engine's flows and by the log's records.
grep -q "log-retention 1 set" <<<"$(dump log-retention 1)" || fail "the log's retention was not set"
# Opens the tool's own connection to its server, or closes it, and waits for its line.
open_own() {
    local before
    before=$(tool_log | grep -c "^own $HOST $OWN_PORT open$" || true)
    adb shell am start-foreground-service -n "$TOOL/.ToolService" --es own "$HOST:$OWN_PORT" >/dev/null
    for _ in $(seq 1 15); do [ "$(tool_log | grep -c "^own $HOST $OWN_PORT open$" || true)" -gt "$before" ] && return 0; sleep 1; done
    return 1
}
close_own() {
    local before
    before=$(tool_log | grep -c "^own closed$" || true)
    adb shell am start-foreground-service -n "$TOOL/.ToolService" --ez stop-own true >/dev/null
    for _ in $(seq 1 10); do [ "$(tool_log | grep -c "^own closed$" || true)" -gt "$before" ] && return 0; sleep 1; done
    return 1
}
# The picked app asks the tool for $1 (HOST:PORT), and the tool is asked for it: by address, or by name.
ask_through_tool() {
    local asked log
    asked=$(tool_log | grep -c "^connect ${1%:*} ${1##*:}$" || true)
    log=$(work --es tcp "$1")
    grep -q "^tcp $1 pong$" <<<"$log" || fail "the picked app's request for $1 did not get through the tool: $log"
    [ "$(tool_log | grep -c "^connect ${1%:*} ${1##*:}$" || true)" -gt "$asked" ] || fail "the tool was not asked for $1"
}
open_own || fail "the test tool did not open its own connection: $(tool_log | grep '^own' | tail -3 | tr '\n' ' ')"
ask_through_tool "$HOST:$PORT"
ask_through_tool "network.test:$RESIDUAL_PORT"
grep -q 'activity-read true' <<<"$(dump activity-read)" || fail "the tracker of the apps' states did not read"
activity_line() { grep "^activity-app $1 " <<<"$(dump | sed 's/^ *//')" || true; }
# A tool's own places as the dump gives them, one a line (audit-D M5): ADDRESS:PORT, `v` for shown there only or `-`,
# and the name; the places at the address $2 in the lines $1, whatever port they show; the debug engine's flows of the
# tool to the address and port $1, by their app end, which tell the ports apart; and whether it keeps one there now that
# was not among the ends $2 (it keeps 512 flows, the oldest out first, so a count could stand still).
tool_places() { dump | sed 's/^ *//' | awk -v uid="$TOOL_UID" '$1 == "activity-place" && $2 == uid { print $3, $4, $6 }'; }
places_at() { awk -v at="$2" '{ address = $1; sub(/:[0-9]+$/, "", address) } address == at' <<<"$1"; }
tool_flows_to() { flows | awk -v at="$1" -v uid="$TOOL_UID" '$1 == "tcp" && $3 == at && $4 == uid && $5 == "opened" { print $2 }'; }
new_tool_flow_to() { [ -n "$(awk 'NR == FNR { seen[$1] = 1; next } NF && !($1 in seen)' <(printf '%s\n' "$2") <(tool_flows_to "$1"))" ]; }
chained=$(activity_line "$WORKLOAD_UID")
grep -q " through-tool=1 places=0 " <<<"$chained" || fail "the live view keeps a destination of the picked app: $chained"
grep -q " tool=1 through-tool=0 " <<<"$(activity_line "$TOOL_UID")" || fail "the live view does not mark the tool: $(activity_line "$TOOL_UID")"
grep -qE " places=[1-9]" <<<"$(activity_line 2000)" || fail "the live view keeps no destination of the shell: $(activity_line 2000)"
for at in "$HOST:$PORT" "$HOST:$OWN_PORT" "$HOST:$RESIDUAL_PORT"; do
    [ -n "$(tool_flows_to "$at")" ] || fail "the debug engine kept no flow of the tool to $at: its own connections are not counted under it"
done
places=$(tool_places)
at_host=$(places_at "$places" "$HOST")
[ -n "$at_host" ] || fail "the live view does not show where the tool connected: $(tr '\n' ';' <<<"$places")"
[ -z "$(awk '$2 != "v"' <<<"$at_host")" ] ||
    fail "a place of the tool is not shown there only, for its window, while the switch is off: $(tr '\n' ';' <<<"$places")"
[ -z "$(awk '$3 == "network.test"' <<<"$places")" ] || fail "the tool's place holds the name only the tool resolved: $(tr '\n' ';' <<<"$places")"
echo "ok: the live view keeps no destination of the picked app, marks the tool, and shows the tool's connections there only, for their window"
# The same from the screen (W5's third part): "Now" shows the picked app's bytes as sent through the tool, and no place
# it reached; and the tool's own row its place, the address the tool connected to, there only, for its window, never
# the name only the tool resolved. The run's names and addresses are looked for in every text of the picked app's screen
# too, so that a place read as something else still fails the check (review c1 of W5's third part, screens, M1).
# The tool's row in "Now", read on until a place of it shows: network_now stops at the row's bytes, and a tool's card
# (unit D's lines on its places and its choice) holds its places below the screen. Up to three more half screens, read
# with what was read before, as network_now reads its second dump.
tool_now() {
    local read i dumps=("$1")
    read=$(network_now "$PKG" "$TOOL" "$1")
    for i in 1 2 3; do
        grep -q '^place ' <<<"$read" && break
        swipe_up
        dump_screen || continue
        adb shell cat "$DUMP" >"$1.$i" 2>/dev/null || continue
        dumps+=("$1.$i")
        read=$(python3 -I "$ROOT/scripts/now-screen.py" "${dumps[@]}" "$TOOL") || continue
    done
    printf '%s\n' "$read"
}
chained_screen=$(network_now "$PKG" "$WORKLOAD" "$SCREENS/now.xml")
tool_screen=$(tool_now "$SCREENS/tool.xml")
grep -qx through-tool <<<"$chained_screen" || fail "\"Now\" does not show the picked app as sent through the tool: $(tr '\n' ';' <<<"$chained_screen" | cut -c1-800)"
! grep -q '^place ' <<<"$chained_screen" || fail "\"Now\" names a place of the picked app: $(grep '^place ' <<<"$chained_screen")"
for name in network.test "$HOST"; do
    ! grep -qF "$name" <<<"$(grep '^texts ' <<<"$chained_screen")" || fail "\"Now\" shows $name on the picked app's row while it is not logged"
done
grep -qx tool <<<"$tool_screen" || fail "\"Now\" does not show the tool's row as the tool's: $(tr '\n' ';' <<<"$tool_screen" | cut -c1-800)"
grep -qx "place $HOST" <<<"$tool_screen" || fail "\"Now\" does not show where the tool connected: $(tr '\n' ';' <<<"$tool_screen" | cut -c1-800)"
grep -qx tool-live-only <<<"$tool_screen" ||
    fail "\"Now\" does not say that the tool's places are shown there only, for their window: $(tr '\n' ';' <<<"$tool_screen" | cut -c1-800)"
! grep -qF network.test <<<"$(grep '^texts ' <<<"$tool_screen")" || fail "\"Now\" shows on the tool's row the name only the tool resolved"
echo "ok: on the screen, \"Now\" shows the picked app through the tool with no place it reached, and the tool's place there only, for its window"
# The log keeps the tool's connections and the picked app's, with no address of either while the switch is off.
dump log-flush >/dev/null
tool_records() { dump log-today | sed -n "s/^ *log-record tcp $TOOL_UID //p"; }
stripped_records() { grep -cE '^[0.:]+ ' <<<"$1" || true; }
records=$(tool_records)
[ "$(stripped_records "$records")" -ge 3 ] || fail "the log holds no record of each of the tool's three connections: the check proves nothing"
! grep -qF "$HOST:" <<<"$records" || fail "with the switch off, the log holds where the tool connected: $(grep -F "$HOST:" <<<"$records" | head -3 | tr '\n' ';')"
picked=$(dump log-today | sed -n "s/^ *log-record tcp $WORKLOAD_UID //p")
[ -n "$picked" ] || fail "the log holds no record of the picked app: the check proves nothing"
! grep -qE "$HOST:|network\.test" <<<"$picked" || fail "with the switch off, the log holds where the picked app connected"
echo "ok: with the switch off, the log keeps the tool's connections and the picked app's, with no address of either"

# The tool's own choice, "Log where TOOL connects for itself" (D7), the switch off, turned on on the tool's row in "Now" as
# a user does, through its link's and its confirmation's tags (review D-rest m9): from then on, the tool's own connection
# is logged with its address, and the one it makes for the picked app's request by address is not (what the chain asked
# the tool for). The request by a name only the tool resolves, sent with no hello Datapavan can read, cannot be tied to
# it, and is logged as the tool's own: the choice's confirmation says Datapavan cannot always tell them apart. "Now" then
# shows the tool's place in full.
# Taps the element tagged $1 ("Now" and the confirmation give their tags as resource ids), scrolling down to it, and
# moved up first from the gesture bar when it lies there.
tap_tag() {
    local bounds height left top right bottom try
    for _ in $(seq 1 10); do
        has_id "$1" && break
        swipe_up
    done
    height=$(adb shell wm size | tr -d '\r' | sed -n 's/.*x\([0-9]*\)$/\1/p' | tail -1)
    for try in 1 2; do
        has_id "$1" || return 1
        bounds=$(adb shell cat "$DUMP" | tr -d '\r' |
            sed -n "s/.*resource-id=\"$1\"[^>]*bounds=\"\[\([0-9]*\),\([0-9]*\)\]\[\([0-9]*\),\([0-9]*\)\]\".*/\1 \2 \3 \4/p" | sed -n 1p)
        [ -n "$bounds" ] || return 1
        read -r left top right bottom <<<"$bounds"
        if [ "$try" = 1 ] && [ "$bottom" -gt $((height * 7 / 8)) ]; then
            swipe_up
            continue
        fi
        adb shell input tap $(( (left + right) / 2 )) $(( (top + bottom) / 2 ))
        return 0
    done
    return 1
}
tool_handed() { grep -qE "^proxy-logged-tools (.* )?$TOOL_UID( |$)" <<<"$(dump | sed 's/^ *//')"; }
tool_not_handed() { grep -qE "^proxy-logged-tools -$" <<<"$(dump | sed 's/^ *//')"; }
# The tool's row from its top, as network_now left it.
scroll_to_top
tap_tag tool-log-link || fail "the tool's place in \"Now\" offers no link to log where the tool connects for itself"
within 10 has_id tool-log-yes || fail "the link did not ask for its confirmation"
tap_tag tool-log-yes || fail "the confirmation's yes could not be tapped"
# Back only once the confirmation has gone, or it closes the dialog and leaves "Now" in front of the network screen,
# which a later step then cannot bring back; and "Now" is checked gone.
now_gone() {
    local screen
    dump_screen || return 1
    screen=$(adb shell cat "$DUMP" 2>/dev/null) || return 1
    ! grep -qF 'text="Pause updates"' <<<"$screen"
}
within 10 gone_id tool-log-yes || fail "the confirmation did not close after its yes"
adb shell input keyevent KEYCODE_BACK
within 10 now_gone || fail "Back did not leave \"Now\" after the tool was chosen on its row"
within 10 tool_handed || fail "the hand-over did not give the engine the tool chosen on the screen: $(dump | sed 's/^ *//' | grep '^proxy-logged-tools')"
no_window() { [ -z "$(awk '$2 == "v"' <<<"$(tool_places)")" ]; }
within 10 no_window || fail "with the tool chosen, \"Now\" still shows its places only for their window: $(tool_places | tr '\n' ';')"
close_own || fail "the test tool did not close its own connection"
open_own || fail "the test tool did not open its own connection again"
dump log-flush >/dev/null
records=$(tool_records)
grep -qF "$HOST:$OWN_PORT " <<<"$records" || fail "with the tool chosen, the log does not hold the tool's own connection with its address"
# The request by address: the tool's flow there is born (the debug engine keeps it), and its record is kept with no
# address, where the choice keeps the own connection's: the positive control of the check that follows (n7).
flows_before=$(tool_flows_to "$HOST:$PORT")
stripped=$(stripped_records "$records")
ask_through_tool "$HOST:$PORT"
dump log-flush >/dev/null
records=$(tool_records)
new_tool_flow_to "$HOST:$PORT" "$flows_before" || fail "the debug engine kept no new flow of the tool to $HOST:$PORT"
[ "$(stripped_records "$records")" -gt "$stripped" ] || fail "with the tool chosen, the log holds no record of the tool's flow for the picked app's request by address"
! grep -qF "$HOST:$PORT " <<<"$records" ||
    fail "with the tool chosen, the log holds where the tool connected for the picked app's request by address: $(grep -F "$HOST:$PORT " <<<"$records" | head -2 | tr '\n' ';')"
ask_through_tool "network.test:$RESIDUAL_PORT"
dump log-flush >/dev/null
grep -qF "$HOST:$RESIDUAL_PORT " <<<"$(tool_records)" ||
    fail "the request by a name only the tool resolves is not logged as the tool's own, as the choice's words say it may be"
echo "ok: with the tool chosen on its row, its own connection is logged with its address, the one for the picked app's request by address is not, and the request by a name only the tool resolves is logged as its own"
# The switch on, the choice off and no longer handed (n7): the tool's connections are logged with their addresses, the
# one for the picked app too.
grep -q "tool-log $TOOL off" <<<"$(dump tool-log "$TOOL" off)" || fail "the tool's own choice was not turned off"
within 10 tool_not_handed || fail "the hand-over still gives the engine the tool chosen: $(dump | sed 's/^ *//' | grep '^proxy-logged-tools')"
grep -q "log-destinations on" <<<"$(dump log-destinations on)" || fail "the switch \"Log where apps connect ...\" was not turned on"
sleep 2
close_own || fail "the test tool did not close its own connection"
dump log-flush >/dev/null
own_logged=$(grep -cF "$HOST:$OWN_PORT " <<<"$(tool_records)" || true)
open_own || fail "the test tool did not open its own connection again"
ask_through_tool "$HOST:$PORT"
dump log-flush >/dev/null
records=$(tool_records)
[ "$(grep -cF "$HOST:$OWN_PORT " <<<"$records" || true)" -gt "$own_logged" ] || fail "with the switch on, the log does not hold the tool's own connection with its address"
grep -qF "$HOST:$PORT " <<<"$records" || fail "with the switch on, the log does not hold where the tool connected for the picked app"
grep -q "log-destinations off" <<<"$(dump log-destinations off)" || fail "the switch \"Log where apps connect ...\" was not turned off again"
echo "ok: with the switch on, the tool's connections are logged with their addresses"

# Back on the screen, which looks for the tool again: its proxy now asks for a password. The user then
# allows UDP, and the picked app's datagrams go through the tool's relay.
adb shell am start -W -n "$PKG/$NETWORK_SCREEN" >/dev/null
UDP_SWITCH="Send UDP through Datapavan test tool too"
screen_says "The proxy of Datapavan test tool asks for a password, so other apps on this phone cannot use it." ||
    fail "the chain screen did not say that the tool's proxy now asks for a password"
tap_text "$UDP_SWITCH" || fail "the chain screen has no switch for UDP"
sleep 2
log=$(work --es udp "network.test:$((PORT + 1))")
grep -q "^udp network.test:$((PORT + 1)) echo$" <<<"$log" || fail "the workload app's UDP did not get through once allowed: $log"
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
# with when the engine's counters began: an engine the network part started afresh between the two reads counted from
# 0 again, which says nothing of this step either way, so the step runs once more, and a second such
# start fails the run as that, never as a pass or as unit 9b's failure.
for attempt in 1 2; do
    before=$(counter_since 48)
    log=$(WORK_WAIT=45 work --es stun "stun-a.test,stun-b.test:$STUN_PORT")
    after=$(counter_since 48)
    [ "${before%% *}" = "${after%% *}" ] && break
    [ "$attempt" = 2 ] &&
        fail "the network part's engine started afresh during the STUN step, twice (counters since ${before%% *}, then ${after%% *}): whether unit 9b told the answers apart cannot be read"
    restarted="the network part's engine started afresh during the STUN step (counters since ${before%% *}, then ${after%% *}); the step runs once more"
    echo "::warning title=the network part's engine::$restarted"
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
adb shell am start -W -n "$PKG/$NETWORK_SCREEN" >/dev/null
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

# The tool's own row while it is not chained (the proxy record's unit D, R10; audit-D m14): the chain turned off through
# its settings, as the screen just did, and the tools read again with no chain's tool, the test tool still counts as a
# tool, by debug builds' rule alone (its package under this project's own prefix). Its own connection shows in "Now"
# there only, for its window; the log keeps no address of it; with the switch on, it does.
chain_off_read() { grep -qE "^proxy-tools read=[0-9]+ chosen=- (.* )?$TOOL_UID( |$)" <<<"$(dump | sed 's/^ *//')"; }
within 30 chain_off_read ||
    fail "the tools were not read again with the chain off, or the test tool is no tool by the debug rule: $(dump | sed 's/^ *//' | grep '^proxy-tools')"
dump log-flush >/dev/null
records=$(tool_records)
own_logged=$(grep -cF "$HOST:$OWN_PORT " <<<"$records" || true)
stripped=$(stripped_records "$records")
flows_before=$(tool_flows_to "$HOST:$OWN_PORT")
open_own || fail "the test tool, not chained, did not open its own connection"
new_tool_flow_to "$HOST:$OWN_PORT" "$flows_before" || fail "the debug engine kept no new flow of the tool, not chained, to $HOST:$OWN_PORT"
# Its place, at the test server's address, shown there only: a tool not chained that the debug rule did not count, or
# whose window the engine did not keep, would show it in full.
own_shown_only() {
    local at
    at=$(places_at "$(tool_places)" "$HOST")
    [ -n "$at" ] && [ -z "$(awk '$2 != "v"' <<<"$at")" ]
}
within 10 own_shown_only || fail "the tool's own connection, not chained, is not shown there only, for its window: $(tool_places | tr '\n' ';')"
grep -q " tool=0 through-tool=0 " <<<"$(activity_line "$TOOL_UID")" || fail "the live view marks the tool as chained: $(activity_line "$TOOL_UID")"
tool_screen=$(tool_now "$SCREENS/tool-unchained.xml")
adb shell input keyevent KEYCODE_BACK
for line in tool-unchained tool-live-only "place $HOST"; do
    grep -qx "$line" <<<"$tool_screen" || fail "\"Now\" does not show the tool, not chained, as such ($line): $(tr '\n' ';' <<<"$tool_screen" | cut -c1-800)"
done
! grep -qx tool <<<"$tool_screen" || fail "\"Now\" shows the tool, not chained, as the chain's"
# Its window after it ends is the engine's tests' to prove (tests 1, 4 and 5): the place it shares with the tool's
# earlier connections to that address stays for theirs too, so no check here could fail for its own.
close_own || fail "the test tool did not close its own connection"
dump log-flush >/dev/null
records=$(tool_records)
[ "$(grep -cF "$HOST:$OWN_PORT " <<<"$records" || true)" -eq "$own_logged" ] ||
    fail "with the switch off, the log holds where the tool, not chained, connected for itself"
[ "$(stripped_records "$records")" -gt "$stripped" ] || fail "the log holds no new record of the tool's own connection: the check proves nothing"
grep -q "log-destinations on" <<<"$(dump log-destinations on)" || fail "the switch \"Log where apps connect ...\" was not turned on"
sleep 2
open_own || fail "the test tool, not chained, did not open its own connection again"
close_own || fail "the test tool did not close its own connection"
dump log-flush >/dev/null
[ "$(grep -cF "$HOST:$OWN_PORT " <<<"$(tool_records)" || true)" -gt "$own_logged" ] ||
    fail "with the switch on, the log does not hold where the tool, not chained, connected for itself"
grep -q "log-destinations off" <<<"$(dump log-destinations off)" || fail "the switch \"Log where apps connect ...\" was not turned off again"
adb shell am force-stop "$TOOL"
echo "ok: the tool, not chained, counted by its package alone in a debug build: its own connection shown there only, for its window, and logged with its address only with the switch on"

# An app left out of the tunnel (ADR 0041), chosen on the screen as a user would: the network part sets its tunnel up
# again, the app still reaches the server, and the network part sees no new traffic of it. Taken back, the network part
# sees it again. Whichever way the setup went, a new engine (the apps left out changed, so Android brings up a new VPN
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
adb shell am start -W -n "$PKG/$NETWORK_SCREEN" >/dev/null
seen=$(workload_flows_now)
tap_text "Choose apps to leave out" || fail "the screen has no button to leave apps out"
tap_text "Datapavan workload" || fail "the workload app is not in the list of apps to leave out"
sleep 2
for _ in $(seq 1 20); do vpn_up && break; sleep 1; done
vpn_up || fail "the network part's tunnel did not come back after an app was left out"
scroll_to_top
scroll_to "1 app is left out." || fail "the screen does not say that one app is left out"
workload_reaches || fail "the app left out did not reach the server"
fresh=$(new_workload_flows "$seen")
[ -z "$fresh" ] || fail "the network part still saw the left-out app's traffic: $(head -3 <<<"$fresh" | tr '\n' ';')"
echo "ok: an app left out on the screen reaches the server without the network part seeing it"
seen=$(workload_flows_now)
tap_text "Datapavan workload" || fail "the workload app could not be taken back"
sleep 2
for _ in $(seq 1 20); do vpn_up && break; sleep 1; done
vpn_up || fail "the network part's tunnel did not come back after the app was taken back"
scroll_to_top
scroll_to "No app is left out." || fail "the screen does not say that no app is left out"
workload_reaches || fail "the app taken back did not reach the server"
for _ in $(seq 1 10); do [ -n "$(new_workload_flows "$seen")" ] && break; sleep 1; done
[ -n "$(new_workload_flows "$seen")" ] || fail "the network part did not see the app's traffic after it was taken back"
echo "ok: taken back, the app passes through the network part again"
echo "== chain check passed"
