#!/usr/bin/env bash
# End-to-end check of Watch's packet engine, milestones W2 and W3 (docs/DESIGN.md, 13.2), on an
# emulator or a phone: starts the test server (scripts/watch-lab/server.py) on this computer, starts
# Watch's tunnel for every app through its debug entry, and plays the app with adb's own shell (UID 2000) and its nc.
# Through Watch it checks that TCP and UDP reach the server and come back; that a connection closed at
# once, a refused one and an unreachable one each get their owner named; that the app sees the refusal
# as "refused" and an unreachable IPv6 address as "no route", as without a VPN; that names resolve
# through the tunnel's DNS, and flows are named after a DNS answer or a TLS server name (W3); and that
# all of it still works after the network beneath switches from Wi-Fi to mobile data. Nothing is left
# running: the tunnel and the server stop at the end.
#
# The emulator reaches this computer at 10.0.2.2. On a phone, set WATCH_TEST_HOST to the computer's
# address on the same Wi-Fi; the network switch is then skipped, since it would cut the phone off.
#
#   scripts/verify-watch.sh [path/to/watch-debug.apk]
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APK="${1:-$ROOT/android/watch/build/outputs/apk/debug/watch-debug.apk}"
PKG=org.visadahyu.datapavan.watch
SHELL_UID=2000
# shellcheck source=scripts/adb-ui.sh
. "$ROOT/scripts/adb-ui.sh"

if is_emulator; then HOST=${WATCH_TEST_HOST:-10.0.2.2}; else HOST=${WATCH_TEST_HOST:?set WATCH_TEST_HOST to this computer's address on the phone's Wi-Fi}; fi
PORT=${WATCH_TEST_PORT:-8790}

SERVER=""
# A TLS ClientHello for watch.test, which the test server answers as bad HTTP; only its name counts.
HELLO_ON_DEVICE=/data/local/tmp/watch-hello.bin
cleanup() {
    adb shell rm -f "$HELLO_ON_DEVICE" >/dev/null 2>&1 || true
    adb shell am force-stop "$PKG" >/dev/null 2>&1 || true
    if is_emulator; then adb shell svc wifi enable >/dev/null 2>&1 || true; fi
    [ -z "$SERVER" ] || kill "$SERVER" 2>/dev/null || true
}
trap cleanup EXIT

fail() {
    echo "WATCH CHECK FAILED: $*" >&2
    adb logcat -d -b crash 2>/dev/null | tail -40 >&2 || true
    # On a phone the flows name other apps' destinations, which stay on the phone: counters only.
    local filter=.
    is_emulator || filter='^(running|counters)'
    echo "Watch's own account:" >&2
    adb shell dumpsys activity service "$PKG/.WatchVpnService" 2>/dev/null | tr -d '\r' | sed -n 's/^ *//p' | grep -E "$filter" | tail -40 >&2 || true
    exit 1
}

# The flows the engine kept, one per line: protocol app destination uid outcome named-by name.
flows() {
    adb shell dumpsys activity service "$PKG/.WatchVpnService" | tr -d '\r' | sed -n 's/^ *flow //p'
}

# Whether a flow of the shell matches: protocol, destination and outcome.
has_flow() {
    flows | grep -qE "^$1 [^ ]+ $(sed 's/[.[]/\\&/g; s/]/\\]/g' <<<"$2") $SHELL_UID $3 "
}

# Whether a flow of the shell, by protocol $1 to any address on port $2, is named $3 by $4 (W3).
has_named_flow() {
    flows | grep -qE "^$1 [^ ]+ [^ ]+:$2 $SHELL_UID opened $4 ${3//./\\.}\$"
}

vpn_up() {
    local uid
    uid=$(adb shell cmd package list packages -U "$PKG" | tr -d '\r' | sed -n "s/^package:$PKG uid:\([0-9]*\)$/\1/p")
    adb shell dumpsys connectivity | tr -d '\r' | grep -E 'ni\{(VPN |\[type: VPN)' | grep -q "OwnerUid: $uid "
}

# Runs a shell command on the device, killing it after $1 seconds: nc -u waits for more answers.
device() {
    local seconds=$1
    shift
    timeout "$seconds" adb shell "$@" 2>&1 | tr -d '\r' || true
}

# TCP, a connection closed at once, a refused one, UDP and DNS, each checked by what the app saw and
# by the flow the engine recorded with the shell's UID.
traffic() {
    local round=$1 answer
    answer=$(device 15 "printf 'GET /ping HTTP/1.0\r\n\r\n' | nc -w 5 $HOST $PORT")
    grep -q '^pong$' <<<"$answer" || fail "$round: no answer over TCP from the test server"
    has_flow tcp "$HOST:$PORT" opened || fail "$round: no TCP flow of the shell to the server"
    echo "ok: $round: TCP through Watch, owner named"

    device 10 "nc -w 2 $HOST $PORT </dev/null" >/dev/null
    [ "$(flows | grep -cE "^tcp [^ ]+ ${HOST//./\\.}:$PORT $SHELL_UID opened ")" -ge 2 ] ||
        fail "$round: a connection closed at once has no owner"
    echo "ok: $round: a connection closed at once, owner named"

    # Nothing listens on TCP at the UDP echo's port, so the server's computer refuses it (a firewall
    # that lets the test through, as on a phone's Wi-Fi, lets both ports through).
    answer=$(device 15 "nc -w 5 $HOST $((PORT + 1)) </dev/null")
    grep -qi 'refused' <<<"$answer" || fail "$round: a refused connection looked like this to the app: $answer"
    has_flow tcp "$HOST:$((PORT + 1))" refused || fail "$round: no refused flow of the shell"
    echo "ok: $round: a refused connection, refused for the app"

    answer=$(device 8 "echo watch-$round | nc -u -w 3 $HOST $((PORT + 1))")
    grep -q "^watch-$round\$" <<<"$answer" || fail "$round: no UDP echo"
    has_flow udp "$HOST:$((PORT + 1))" opened || fail "$round: no UDP flow of the shell"
    echo "ok: $round: UDP through Watch, owner named"

    # ping resolves the name first, through the tunnel's DNS; its ICMP itself is not forwarded yet.
    answer=$(device 15 "ping -c 1 -W 2 example.com")
    grep -q 'PING example.com (' <<<"$answer" || fail "$round: example.com did not resolve: $answer"
    flows | grep -qE "^udp [^ ]+ (10\.215\.173\.3|\[fd7a:6470:7761::3\]):53 $SHELL_UID opened " ||
        fail "$round: no DNS flow of the shell to the tunnel's DNS address"
    echo "ok: $round: names resolve through the tunnel"

    # W3: a flow to an address from a DNS answer is named after the name the app asked for (UDP opens
    # at once, whether or not the address answers), and a TLS connection after its server name.
    device 6 "echo watch | nc -u -w 1 example.com 9" >/dev/null
    has_named_flow udp 9 example.com dns || fail "$round: a flow to example.com was not named after its DNS answer"
    echo "ok: $round: a flow named from its DNS answer"
    device 10 "nc -w 2 $HOST $PORT < $HELLO_ON_DEVICE" >/dev/null
    has_named_flow tcp "$PORT" watch.test tls || fail "$round: a TLS connection was not named after its server name"
    echo "ok: $round: a flow named from its TLS server name"

    # A flow to an address no DNS answer gave is named after its network's organisation, when this
    # build carries the table (data/dbip-asn/update.py; a clean checkout has none, ADR 0036).
    if adb shell dumpsys activity service "$PKG/.WatchVpnService" | grep -q 'organisations 20'; then
        device 6 "echo watch | nc -u -w 1 8.8.8.8 9" >/dev/null
        has_named_flow udp 9 'Google LLC' org || fail "$round: a flow to 8.8.8.8 was not named after Google's network"
        echo "ok: $round: a flow named from the organisation table"
    else
        echo "skipped: $round: this build has no organisation table"
    fi
}

echo "== Watch's engine, end to end, on $(adb shell getprop ro.product.model | tr -d '\r'), Android $(adb shell getprop ro.build.version.release | tr -d '\r')"
adb wait-for-device
python3 -I "$ROOT/scripts/watch-lab/server.py" "$PORT" &
SERVER=$!
adb install -r "$APK" >/dev/null
hello=$(mktemp)
python3 -I - "$hello" <<'PY'
import struct, sys
name = b"watch.test"
body = b"\x03\x03" + bytes(32) + b"\x00\x00\x02\x13\x01\x01\x00"
extension = struct.pack("!HHHBH", 0, len(name) + 5, len(name) + 3, 0, len(name)) + name
body += struct.pack("!H", len(extension)) + extension
handshake = b"\x01\x00" + struct.pack("!H", len(body)) + body
open(sys.argv[1], "wb").write(b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake)
PY
adb push "$hello" "$HELLO_ON_DEVICE" >/dev/null 2>&1
rm -f "$hello"
is_emulator && adb shell appops set "$PKG" ACTIVATE_VPN allow
# Android 17: the server is on the local network, which Watch reaches for every app (ADR 0034).
[ "$(adb shell getprop ro.build.version.sdk | tr -d '\r')" -lt 37 ] || adb shell pm grant "$PKG" android.permission.ACCESS_LOCAL_NETWORK
adb shell am force-stop "$PKG"
adb logcat -c
adb shell am start -W -n "$PKG/.MainActivity" --ez start true >/dev/null
for _ in $(seq 1 20); do vpn_up && break; sleep 1; done
vpn_up || fail "Watch's tunnel did not come up (on a phone, allow the VPN request on its screen first)"
echo "ok: the tunnel is up for every app"

traffic first

answer=$(device 15 "nc -6 -w 5 2001:db8::1 80 </dev/null")
grep -qiE 'no route|unreachable' <<<"$answer" || fail "an unreachable IPv6 address looked like this to the app: $answer"
has_flow tcp "[2001:db8::1]:80" unreachable || fail "no unreachable flow of the shell"
echo "ok: an unreachable IPv6 address gets the app an ICMPv6 error"

if is_emulator; then
    # The emulator has Wi-Fi and mobile data: switching Wi-Fi off moves the tunnel to mobile data.
    adb shell svc wifi disable
    sleep 8
    vpn_up || fail "the tunnel went down when the network beneath switched"
    traffic "after a network switch"
    adb shell svc wifi enable
else
    echo "skipped: the network switch, on a phone"
fi

if flows | awk -v host="$HOST" 'index($3, host) && $4 == "-"' | grep -q .; then
    fail "a flow to the test server has no owner"
fi
if adb logcat -d -b crash 2>/dev/null | grep -q "$PKG"; then
    fail "Watch crashed"
fi
echo "ok: no crash"
echo "== Watch's engine passed"
