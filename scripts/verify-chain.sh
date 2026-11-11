#!/usr/bin/env bash
# W6's end-to-end check of chaining (docs/DESIGN.md, 13.2; docs/VPN.md; ADR 0038), on an emulator.
# The test tool (scripts/test-tool) runs a SOCKS5 proxy with a password on the phone's loopback, as a
# circumvention tool does in proxy mode. Watch must find it by itself: its package, its port, that
# Android names it as the port's owner, and that it wants a password. With adb's shell (UID 2000)
# chained through it, TCP reaches the test server on this computer by address and by a name only the
# tool can resolve (the shell gets a stand-in address for it), UDP goes through the tool's relay, the
# tool's own connections go directly and are counted under the tool, and a wrong password is refused.
# Then the tool stops: the shell's connections fail, and a sentinel on this computer, outside Android,
# sees none of them reach it directly, while it does see a control's direct connection. Nothing is left running: the tunnel, the tool and the
# server stop at the end, and the tool is uninstalled.
#
#   scripts/verify-chain.sh [path/to/watch-debug.apk]
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APK="${1:-$ROOT/android/watch/build/outputs/apk/debug/watch-debug.apk}"
PKG=org.visadahyu.datapavan.watch
TOOL=org.visadahyu.datapavan.testtool
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
    [ -z "$SERVER" ] || kill "$SERVER" 2>/dev/null || true
    rm -rf "$WORK"
}
trap cleanup EXIT

dump() { adb shell dumpsys activity service "$PKG/.WatchVpnService" "$@" | tr -d '\r'; }
flows() { dump | sed -n 's/^ *flow //p'; }
tool_log() { adb logcat -d -s DatapavanTestTool | tr -d '\r' | sed -n 's/.*DatapavanTestTool: //p'; }
# Runs a shell command on the device, killing it after $1 seconds: nc -u waits for more answers.
device() {
    local seconds=$1
    shift
    timeout "$seconds" adb shell "$@" 2>&1 | tr -d '\r' || true
}
ping_from_shell() { device 10 "printf 'GET /ping HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n' | toybox nc -w 6 $1 $PORT"; }

fail() {
    echo "CHAIN CHECK FAILED: $*" >&2
    echo "The tool's requests:" >&2
    tool_log | tail -20 >&2 || true
    echo "The flows of the shell and the tool:" >&2
    flows | grep -E " ($SHELL_UID|${TOOL_UID:-x}) " | tail -20 >&2 || true
    adb logcat -d -b crash 2>/dev/null | tail -30 >&2 || true
    exit 1
}

vpn_up() {
    local uid vpns
    uid=$(adb shell cmd package list packages -U "$PKG" | tr -d '\r' | sed -n "s/^package:$PKG uid:\([0-9]*\)$/\1/p")
    vpns=$(adb shell dumpsys connectivity | tr -d '\r')
    [ -n "$uid" ] && grep -qE "OwnerUid: $uid " <<<"$vpns"
}

"$ROOT/scripts/test-tool/build.sh" >/dev/null
adb install -r "$APK" >/dev/null
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
adb shell am start -W -n "$PKG/.MainActivity" --ez start true >/dev/null
for _ in $(seq 1 20); do vpn_up && break; sleep 1; done
vpn_up || fail "Watch's tunnel did not come up"
echo "ok: the tunnel is up for every app"

found=$(dump find-tool | grep -E '^ *tool ' | sed 's/^ *//')
[ "$found" = "tool answering $TOOL 127.0.0.1:$TOOL_PORT uid $TOOL_UID password yes owner yes" ] ||
    fail "Watch did not find the tool as expected: $found"
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
echo "== chain check passed"
