#!/usr/bin/env bash
# End-to-end check of Watch's packet engine, milestones W2 and W3 (docs/DESIGN.md, 13.2), on an
# emulator or a phone: starts the test server (scripts/watch-lab/server.py) on this computer, starts
# Watch's tunnel for every app through its debug entry, and plays the app with adb's own shell (UID 2000) and its nc.
# Through Watch it checks that TCP and UDP reach the server and come back; that a connection closed at
# once, a refused one and an unreachable one each get their owner named; that the app sees the refusal
# as "refused" and an unreachable IPv6 address as "no route", as without a VPN; that names resolve
# through the tunnel's DNS, and flows are named after a DNS answer, a TLS server name or a QUIC one,
# with the ECH a hello offers noted, an app's own DNS is recognised, and strict Private DNS is
# detected (W3); and that
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
# The emulator's Private DNS setting before the test changed it, restored at the end.
DNS_MODE=""
DNS_HOST=""
restore_private_dns() {
    [ -n "$DNS_MODE" ] || return 0
    for key in mode specifier; do
        value=$DNS_MODE
        [ "$key" = mode ] || value=$DNS_HOST
        if [ "$value" = null ]; then
            adb shell settings delete global "private_dns_$key" >/dev/null 2>&1 || true
        else
            adb shell settings put global "private_dns_$key" "$value" >/dev/null 2>&1 || true
        fi
    done
    DNS_MODE=""
}
# A TLS ClientHello for watch.test, which the test server answers as bad HTTP; only its name counts.
HELLO_ON_DEVICE=/data/local/tmp/watch-hello.bin
# A QUIC ClientHello for watch.test offering ECH, in two Initial datagrams, its CRYPTO frames out of
# order as Chrome sends them; the UDP echo sends them back, and only the name counts.
QUIC_ON_DEVICE=/data/local/tmp/watch-quic
# An app's own DNS (ADR 0029): a plain query for example.org, and a TLS hello for dns.google.
DNS_ON_DEVICE=/data/local/tmp/watch-dns.bin
DOH_ON_DEVICE=/data/local/tmp/watch-doh.bin
cleanup() {
    adb shell rm -f "$HELLO_ON_DEVICE" "$QUIC_ON_DEVICE-1.bin" "$QUIC_ON_DEVICE-2.bin" "$DNS_ON_DEVICE" "$DOH_ON_DEVICE" >/dev/null 2>&1 || true
    adb shell am force-stop "$PKG" >/dev/null 2>&1 || true
    if is_emulator; then
        adb shell svc wifi enable >/dev/null 2>&1 || true
        restore_private_dns
    fi
    [ -z "$SERVER" ] || kill "$SERVER" 2>/dev/null || true
}
trap cleanup EXIT

fail() {
    echo "WATCH CHECK FAILED: $*" >&2
    adb logcat -d -b crash 2>/dev/null | tail -40 >&2 || true
    # A process Android ended leaves no crash: how Watch's last ones ended, with no destination.
    echo "How Watch's process last ended:" >&2
    adb shell dumpsys activity exit-info "$PKG" 2>/dev/null | tr -d '\r' | grep -E 'timestamp=|reason=' | head -6 >&2 || true
    # On a phone the flows name other apps' destinations, which stay on the phone: counters only.
    local filter=.
    is_emulator || filter='^(running|counters)'
    echo "Watch's own account:" >&2
    adb shell dumpsys activity service "$PKG/.WatchVpnService" 2>/dev/null | tr -d '\r' | sed -n 's/^ *//p' | grep -E "$filter" | tail -40 >&2 || true
    exit 1
}

# The flows the engine kept, one per line: protocol app destination uid outcome named-by ech dns network
# name.
flows() {
    adb shell dumpsys activity service "$PKG/.WatchVpnService" | tr -d '\r' | sed -n 's/^ *flow //p'
}

# Whether a flow of the shell matches: protocol, destination and outcome.
has_flow() {
    flows | grep -qE "^$1 [^ ]+ $(sed 's/[.[]/\\&/g; s/]/\\]/g' <<<"$2") $SHELL_UID $3 "
}

# Whether a flow of the shell, by protocol $1 to any address on port $2, is named $3 by $4 (W3), with
# the ECH column $5 (any if not given).
has_named_flow() {
    flows | grep -qE "^$1 [^ ]+ [^ ]+:$2 $SHELL_UID opened $4 ${5:-[^ ]+} [^ ]+ [^ ]+ ${3//./\\.}\$"
}

# What Watch says of Private DNS on its network: plain, network, or strict and the provider (debug).
private_dns() {
    adb shell dumpsys activity service "$PKG/.WatchVpnService" | tr -d '\r' | sed -n 's/^ *private-dns //p'
}

wait_private_dns() {
    for _ in $(seq 1 "${2:-20}"); do
        [ "$(private_dns)" = "$1" ] && return 0
        sleep 1
    done
    return 1
}

# What Android itself says of Private DNS on each network, for a failure: whether Watch or Android lags.
android_private_dns() {
    adb shell dumpsys connectivity | tr -d '\r' |
        grep -oE 'NetworkAgentInfo\{network\{[0-9]+\}|InterfaceName: [a-z0-9]+|UsePrivateDns: [a-z]+|PrivateDnsServerName: [^ ]+' |
        paste -sd' '
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
    has_named_flow tcp "$PORT" watch.test tls - || fail "$round: a TLS connection was not named after its server name"
    echo "ok: $round: a flow named from its TLS server name"
    device 10 "(cat $QUIC_ON_DEVICE-1.bin; sleep 1; cat $QUIC_ON_DEVICE-2.bin) | nc -u -w 2 $HOST $((PORT + 1))" >/dev/null
    has_named_flow udp "$((PORT + 1))" watch.test quic ech ||
        fail "$round: a QUIC connection was not named after its server name, with ECH offered; its flows: $(flows | grep -E ":$((PORT + 1)) ")"
    echo "ok: $round: a flow named from its QUIC server name, put together from two datagrams"

    # An app's own DNS, past Watch's resolver (ADR 0029): plain DNS to Google's public resolver, and a
    # TLS hello for its DNS-over-HTTPS name. Neither needs an answer to be recognised. nc quits 3 s after
    # its input ends (-q), so that od sees the end of the answer.
    answer=$(device 10 "nc -u -q 3 8.8.8.8 53 < $DNS_ON_DEVICE | od -An -tx1")
    flows | grep -qE "^udp [^ ]+ 8\.8\.8\.8:53 $SHELL_UID [a-z]+ [^ ]+ [^ ]+ plain:google " ||
        fail "$round: plain DNS to 8.8.8.8 was not recognised as the app's own"
    echo "ok: $round: an app's own plain DNS, to a known resolver"
    # The answer of a resolver the app asked itself names that app's next flow, and only its flows. Where
    # a network filters public resolvers, an emulator's own DNS server, asked directly instead of through
    # Watch's, answers instead.
    if [ -z "$answer" ] && is_emulator; then
        answer=$(device 10 "nc -u -q 3 10.0.2.3 53 < $DNS_ON_DEVICE | od -An -tx1")
    fi
    own=$(python3 -I - "$answer" 2>/dev/null <<'PY'
import sys
data = bytes.fromhex(sys.argv[1].replace(" ", "").replace("\n", ""))
at = 12
while data[at]:
    at += 1 + data[at]
at += 5
for _ in range(int.from_bytes(data[6:8], "big")):
    at += 2 if data[at] >= 0xC0 else 1 + data[at]
    kind, length = int.from_bytes(data[at:at + 2], "big"), int.from_bytes(data[at + 8:at + 10], "big")
    if kind == 1 and length == 4:
        print(".".join(str(b) for b in data[at + 10:at + 14]))
        break
    at += 10 + length
PY
    ) || own=""
    if [ -n "$own" ]; then
        device 6 "echo watch | nc -u -w 1 $own 7" >/dev/null
        has_named_flow udp 7 example.org dns || fail "$round: the app's own DNS answer did not name its next flow"
        echo "ok: $round: the answer of the app's own resolver names its next flow"
    else
        echo "skipped: $round: no answer from a resolver the app asked itself"
    fi
    device 10 "nc -w 3 8.8.8.8 443 < $DOH_ON_DEVICE" >/dev/null
    flows | grep -qE "^tcp [^ ]+ 8\.8\.8\.8:443 $SHELL_UID [a-z]+ [^ ]+ [^ ]+ encrypted:google " ||
        fail "$round: a TLS hello for dns.google was not recognised as encrypted DNS"
    echo "ok: $round: an app's own encrypted DNS, to a known resolver"

    # A flow to an address no DNS answer gave is named after its network's organisation, when this
    # build carries the table (data/dbip-asn/update.py; a clean checkout has none, ADR 0036).
    if adb shell dumpsys activity service "$PKG/.WatchVpnService" | grep -q 'organisations 20'; then
        # One of Google's name servers' addresses: apps rarely look its name up, and a name from DNS
        # would come first (Android or an app may look up dns.google, which names 8.8.8.8).
        device 6 "echo watch | nc -u -w 1 216.239.32.10 9" >/dev/null
        has_named_flow udp 9 'Google LLC' org || fail "$round: a flow to 216.239.32.10 was not named after Google's network"
        flows | grep -qE "^udp [^ ]+ 216\.239\.32\.10:9 $SHELL_UID opened org [^ ]+ [^ ]+ as15169:hosting Google LLC$" ||
            fail "$round: Google's network was not marked as one that hosts other companies' servers"
        echo "ok: $round: a flow named from the organisation table"
        # The owners' table names the company people know, not the registry's "Facebook, Inc.".
        device 6 "echo watch | nc -u -w 1 157.240.1.35 9" >/dev/null
        flows | grep -qE "^udp [^ ]+ 157\.240\.1\.35:9 $SHELL_UID opened org [^ ]+ [^ ]+ as32934:own Meta Platforms, Inc\.$" ||
            fail "$round: a flow to Meta's network was not named after Meta"
        echo "ok: $round: a network named after the company that owns it"
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
# The QUIC Initial packets are protected with Python's HMAC and OpenSSL's AES, apart from Watch's own
# code (RFC 9001 5): the keys from the connection ID, AES-CTR with GCM's counter, a zero tag (Watch
# does not check it), then the header protection.
python3 -I - "$hello" <<'PY'
import hashlib, hmac, struct, subprocess, sys

def expand_label(secret, label, length):
    label = b"tls13 " + label
    info = struct.pack("!HB", length, len(label)) + label + b"\x00\x01"
    return hmac.new(secret, info, hashlib.sha256).digest()[:length]

def aes(key, data, mode, iv=b""):
    command = ["openssl", "enc", "-aes-128-" + mode, "-K", key.hex(), "-nopad"]
    command += ["-iv", iv.hex()] if iv else []
    return subprocess.run(command, input=data, capture_output=True, check=True).stdout

cid = bytes.fromhex("5761746368517569")
salt = bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")
secret = expand_label(hmac.new(salt, cid, hashlib.sha256).digest(), b"client in", 32)
key, iv, hp = (expand_label(secret, b"quic " + l, n) for l, n in ((b"key", 16), (b"iv", 12), (b"hp", 16)))

def initial(pn, frames, size):
    header = b"\xc3" + struct.pack("!IB", 1, len(cid)) + cid + b"\x00\x00"
    length = max(size - len(header) - 22, len(frames))
    header += struct.pack("!H", 0x4000 | (length + 20))
    at = len(header)
    header += struct.pack("!I", pn)
    nonce = bytes(a ^ b for a, b in zip(iv, struct.pack("!IQ", 0, pn)))
    packet = bytearray(header + aes(key, frames.ljust(length, b"\x00"), "ctr", nonce + b"\x00\x00\x00\x02"))
    packet += bytes(16)
    mask = aes(hp, bytes(packet[at + 4:at + 20]), "ecb")
    packet[0] ^= mask[0] & 0x0F
    for i in range(4):
        packet[at + i] ^= mask[1 + i]
    return bytes(packet)

def crypto(offset, data):
    return b"\x06" + struct.pack("!HH", 0x4000 | offset, 0x4000 | len(data)) + data

name = b"watch.test"
extensions = struct.pack("!HHHBH", 0, len(name) + 5, len(name) + 3, 0, len(name)) + name
extensions += bytes([0xFE, 0x0D, 0, 12, 0, 0, 1, 0, 1, 7, 0, 0, 0, 2, 1, 2])
extensions += struct.pack("!HH", 21, 1400) + bytes(1400)
body = b"\x03\x03" + bytes(32) + b"\x00\x00\x02\x13\x01\x01\x00" + struct.pack("!H", len(extensions)) + extensions
hello = b"\x01\x00" + struct.pack("!H", len(body)) + body
first = crypto(40, hello[40:700]) + b"\x01" + crypto(0, hello[:40])
second = crypto(700, hello[700:])
for n, packet in ((1, initial(0, first, 1250)), (2, initial(1, second, 1250))):
    open(f"{sys.argv[1]}-{n}.bin", "wb").write(packet)
PY
for n in 1 2; do adb push "$hello-$n.bin" "$QUIC_ON_DEVICE-$n.bin" >/dev/null 2>&1; done
python3 -I - "$hello" <<'PY'
import struct, sys
query = struct.pack("!HHHHHH", 0x5741, 0x0100, 1, 0, 0, 0) + b"\x07example\x03org\x00" + struct.pack("!HH", 1, 1)
open(sys.argv[1] + "-dns.bin", "wb").write(query)
name = b"dns.google"
body = b"\x03\x03" + bytes(32) + b"\x00\x00\x02\x13\x01\x01\x00"
extension = struct.pack("!HHHBH", 0, len(name) + 5, len(name) + 3, 0, len(name)) + name
body += struct.pack("!H", len(extension)) + extension
handshake = b"\x01\x00" + struct.pack("!H", len(body)) + body
open(sys.argv[1] + "-doh.bin", "wb").write(b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake)
PY
adb push "$hello-dns.bin" "$DNS_ON_DEVICE" >/dev/null 2>&1
adb push "$hello-doh.bin" "$DOH_ON_DEVICE" >/dev/null 2>&1
rm -f "$hello" "$hello-1.bin" "$hello-2.bin" "$hello-dns.bin" "$hello-doh.bin"
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

# Strict Private DNS sends every app's lookups past Watch's resolver; Watch says so on its screen. Only
# on an emulator: a phone's settings are its owner's. Android needs no answer from the provider to
# report the setting, and the setting is restored at once. It runs last: Android then looks up
# dns.google through Watch, which names 8.8.8.8 after it from then on.
if is_emulator; then
    wait_private_dns plain || fail "Watch reads Private DNS as '$(private_dns)', not plain, before the test"
    DNS_MODE=$(adb shell settings get global private_dns_mode | tr -d '\r')
    DNS_HOST=$(adb shell settings get global private_dns_specifier | tr -d '\r')
    adb shell settings put global private_dns_specifier dns.google
    adb shell settings put global private_dns_mode hostname
    wait_private_dns "strict dns.google" || fail "strict Private DNS was not detected: '$(private_dns)'"
    restore_private_dns
    # Once, right after the network switch, Watch still read strict mode 20 s after the restore; three
    # tries could not repeat it. This waits longer, and a failure shows whether Android itself still
    # reports the provider.
    wait_private_dns plain 60 ||
        fail "Watch still reads Private DNS as '$(private_dns)' once it was restored; Android says: $(android_private_dns)"
    echo "ok: strict Private DNS is detected, and its end"
else
    echo "skipped: Private DNS, on a phone"
fi

if flows | awk -v host="$HOST" 'index($3, host) && $4 == "-"' | grep -q .; then
    fail "a flow to the test server has no owner"
fi
if adb logcat -d -b crash 2>/dev/null | grep -q "$PKG"; then
    fail "Watch crashed"
fi
echo "ok: no crash"
echo "== Watch's engine passed"
