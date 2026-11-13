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
# directly. Last, that app is left out of the tunnel on the screen (ADR 0041): Watch sets its tunnel up
# again, the app reaches the server and Watch no longer sees it; taken back, Watch sees it again. Nothing
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
SHELL_UID=2000
# shellcheck source=scripts/adb-ui.sh
. "$ROOT/scripts/adb-ui.sh"

is_emulator || { echo "verify-chain.sh runs on an emulator only" >&2; exit 2; }
HOST=10.0.2.2
PORT=${WATCH_TEST_PORT:-8790}
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

dump() { adb shell dumpsys activity service "$PKG/org.visadahyu.datapavan.watch.WatchVpnService" "$@" | tr -d '\r'; }
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

python3 -I "$ROOT/scripts/watch-lab/server.py" "$PORT" &
SERVER=$!
adb logcat -c
adb shell am start-foreground-service -n "$TOOL/.ToolService" --ei port "$TOOL_PORT" \
    --es user watch --es password "$PASSWORD" --es map "watch.test=$HOST" >/dev/null
for _ in $(seq 1 10); do tool_log | grep -q "^listening" && break; sleep 1; done
tool_log | grep -q "^listening $TOOL_PORT" || fail "the test tool does not listen"

adb shell appops set "$PKG" ACTIVATE_VPN allow
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

dump chain 127.0.0.1 "$TOOL_PORT" "$TOOL_UID" udp "$SHELL_UID" watch "$PASSWORD" | grep -q "chain on" ||
    fail "the chain did not turn on"

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

dump chain 127.0.0.1 "$TOOL_PORT" "$TOOL_UID" udp "$SHELL_UID" watch wrong-password | grep -q "chain on" ||
    fail "the chain with a wrong password did not turn on"
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
dump chain 127.0.0.1 "$TOOL_PORT" "$TOOL_UID" udp "$SHELL_UID" watch "$PASSWORD" | grep -q "chain on" ||
    fail "the chain did not turn on again"
adb shell am force-stop "$TOOL"
SENTINEL_PORT=$((PORT + 3))
python3 -I - "$SENTINEL_PORT" >"$WORK/sentinel.log" <<'PY' &
# Prints "tcp" for each connection and "udp" for each datagram that reaches the port, at once.
import selectors, socket, sys
port = int(sys.argv[1])
tcp = socket.create_server(("0.0.0.0", port))
udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udp.bind(("0.0.0.0", port))
watch = selectors.DefaultSelector()
watch.register(tcp, selectors.EVENT_READ, "tcp")
watch.register(udp, selectors.EVENT_READ, "udp")
while True:
    for key, _ in watch.select():
        if key.data == "tcp":
            key.fileobj.accept()[0].close()
        else:
            key.fileobj.recvfrom(65535)
        print(key.data, flush=True)
PY
SENTINEL=$!
sleep 1
grep -q pong <<<"$(ping_from_shell "$HOST")" && fail "with the tool stopped, the shell still reached the server"
device 6 "toybox nc -w 2 $HOST $SENTINEL_PORT </dev/null" >/dev/null
device 5 "echo stopped-udp | toybox nc -u -w 2 $HOST $SENTINEL_PORT" >/dev/null
sleep 1
[ ! -s "$WORK/sentinel.log" ] || { kill "$SENTINEL"; fail "with the tool stopped, the shell reached this computer directly: $(tr '\n' ' ' <"$WORK/sentinel.log")"; }
device 6 "run-as $PKG toybox nc -w 2 $HOST $SENTINEL_PORT </dev/null" >/dev/null
sleep 1
kill "$SENTINEL"
grep -q '^tcp$' "$WORK/sentinel.log" || fail "the sentinel did not see the control's direct connection: the check proves nothing"
echo "ok: with the tool stopped, the shell's TCP and UDP failed, and a sentinel on this computer saw none of them, only the control's direct connection"

dump unchain | grep -q "chain off" || fail "the chain did not turn off"

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
# The search, and the first password after a fresh start (a new Keystore key), take a few seconds: wait
# for them before scrolling, or the scroll moves the section off the screen before it is drawn.
for _ in $(seq 1 30); do screen_has "$SWITCH" && break; sleep 1; done
# A search that missed the tool leaves "Look again" on the screen, which a user would tap.
if ! screen_has "$SWITCH" && screen_has "Look again"; then
    echo "  the chain screen's search missed the tool: looking again" >&2
    adb shell cat "$DUMP" 2>/dev/null | grep -o 'text="[^"]\+"' | sed -n '5,9p' | sed 's/^/    screen: /' >&2 || true
    echo "    the service's search now: $(dump find-tool | grep -E '^ *tool ' | sed 's/^ *//')" >&2
    tap_text "Look again" || true
    for _ in $(seq 1 30); do screen_has "$SWITCH" && break; sleep 1; done
fi
scroll_to "$SWITCH" || fail "the chain screen did not offer the test tool"
# The tool's proxy answered without asking for a password: the screen says what that lets other apps
# do (ADR 0041, decision 5). The test tool can take a password, so the screen does not say it has none.
scroll_to "The proxy of Datapavan test tool asks for no password, so any app on this phone can use it." ||
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
user=$(read_shown "User name: ")
password=$(read_shown "Password: ")
[ -n "$user" ] && [ -n "$password" ] || fail "the chain screen offered no user name and password for the tool"
listening=$(tool_log | grep -c "^listening")
adb shell am force-stop "$TOOL"
adb shell am start-foreground-service -n "$TOOL/.ToolService" --ei port "$TOOL_PORT" \
    --es user "$user" --es password "$password" --es map "watch.test=$HOST" >/dev/null
for _ in $(seq 1 10); do [ "$(tool_log | grep -c "^listening")" -gt "$listening" ] && break; sleep 1; done
# The password is below the choice of apps, and scroll_to only looks further down: back to the top first.
scroll_to_top
tap_text "Only the apps I choose" || fail "no choice of apps on the chain screen"
# The list of apps loads in the background.
for _ in $(seq 1 15); do screen_has "Datapavan workload" && break; sleep 1; done
tap_text "Datapavan workload" || fail "the workload app is not among the apps to choose"
# The list of apps pushed the switch up, off the screen.
scroll_to_top
tap_text "$SWITCH" || fail "the chain's switch is not on the screen"
sleep 2
through=$(tool_log | grep -c "^connect watch.test $PORT$")
associations=$(tool_log | grep -c "^associate$" || true)
# Runs the workload app once with the extras given, and prints its log lines of that run.
work() {
    local runs
    runs=$(workload_log | grep -c "^done$" || true)
    adb shell am start -W -n "$WORKLOAD/.WorkActivity" "$@" >/dev/null
    for _ in $(seq 1 30); do [ "$(workload_log | grep -c "^done$")" -gt "$runs" ] && break; sleep 1; done
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

# Back on the screen, which looks for the tool again: its proxy now asks for a password. The user then
# allows UDP, and the picked app's datagrams go through the tool's relay.
adb shell am start -W -n "$PKG/$WATCH_SCREEN" >/dev/null
UDP_SWITCH="Send UDP through Datapavan test tool too"
for _ in $(seq 1 30); do screen_has "$SWITCH" && break; sleep 1; done
scroll_to "The proxy of Datapavan test tool asks for a password, so other apps on this phone cannot use it." ||
    fail "the chain screen did not say that the tool's proxy now asks for a password"
tap_text "$UDP_SWITCH" || fail "the chain screen has no switch for UDP"
sleep 2
log=$(work --es udp "watch.test:$((PORT + 1))")
grep -q "^udp watch.test:$((PORT + 1)) echo$" <<<"$log" || fail "the workload app's UDP did not get through once allowed: $log"
[ "$(tool_log | grep -c "^associate$")" -gt "$associations" ] || fail "the tool was not asked for a UDP relay once UDP was allowed"
echo "ok: the screen says the proxy asks for a password; with UDP allowed, the picked app's UDP goes through the tool"

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
# again, the app still reaches the server, and Watch no longer sees its traffic. Taken back, Watch sees it
# again.
workload_flows() { flows | grep -c " $WORKLOAD_UID " || true; }
workload_reaches() {
    local before
    before=$(workload_log | grep -c "^tcp $HOST:$PORT pong$" || true)
    adb shell am start -W -n "$WORKLOAD/.WorkActivity" --es tcp "$HOST:$PORT" >/dev/null
    for _ in $(seq 1 20); do [ "$(workload_log | grep -c "^tcp $HOST:$PORT pong$" || true)" -gt "$before" ] && return 0; sleep 1; done
    return 1
}
adb shell am start -W -n "$PKG/$WATCH_SCREEN" >/dev/null
tap_text "Choose apps to leave out" || fail "the screen has no button to leave apps out"
tap_text "Datapavan workload" || fail "the workload app is not in the list of apps to leave out"
sleep 2
for _ in $(seq 1 20); do vpn_up && break; sleep 1; done
vpn_up || fail "Watch's tunnel did not come back after an app was left out"
scroll_to_top
scroll_to "1 app is left out." || fail "the screen does not say that one app is left out"
workload_reaches || fail "the app left out did not reach the server"
[ "$(workload_flows)" = 0 ] || fail "Watch still saw the left-out app's traffic: $(flows | grep " $WORKLOAD_UID " | head -3 | tr '\n' ';')"
echo "ok: an app left out on the screen reaches the server without Watch seeing it"
tap_text "Datapavan workload" || fail "the workload app could not be taken back"
sleep 2
for _ in $(seq 1 20); do vpn_up && break; sleep 1; done
vpn_up || fail "Watch's tunnel did not come back after the app was taken back"
scroll_to_top
scroll_to "No app is left out." || fail "the screen does not say that no app is left out"
workload_reaches || fail "the app taken back did not reach the server"
for _ in $(seq 1 10); do [ "$(workload_flows)" -gt 0 ] && break; sleep 1; done
[ "$(workload_flows)" -gt 0 ] || fail "Watch did not see the app's traffic after it was taken back"
echo "ok: taken back, the app passes through Watch again"
echo "== chain check passed"
