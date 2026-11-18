#!/usr/bin/env bash
# End-to-end check of Watch's packet engine, milestones W2 and W3 (docs/DESIGN.md, 13.2), on an
# emulator or a phone: starts the test server (scripts/watch-lab/server.py) on this computer, starts
# Watch's tunnel for every app through its debug entry, and plays the app with adb's own shell (UID 2000) and its nc.
# Through Watch it checks that TCP and UDP reach the server and come back; that a connection closed at
# once, a refused one and an unreachable one each get their owner named; that the app sees the refusal
# as "refused" and an unreachable IPv6 address as "no route", as without a VPN; that names resolve
# through the tunnel's DNS, and flows are named after a DNS answer, a TLS server name or a QUIC one,
# with the ECH a hello offers noted, an app's own DNS is recognised, and strict Private DNS is
# detected (W3); that a connection straight to Watch's own listener is closed and counted; that a
# connection kept open goes on when the tunnel is set up again with the same addresses and apps; and that
# all of it still works after the network beneath switches from Wi-Fi to mobile data. Nothing is left
# running: the tunnel and the server stop at the end.
#
# The emulator reaches this computer at 10.0.2.2. On a phone, set WATCH_TEST_HOST to the computer's
# address on the same Wi-Fi; the network switch is then skipped, since it would cut the phone off.
#
#   scripts/verify-watch.sh [path/to/Datapavan-Advanced-debug.apk]
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APK="${1:-$ROOT/android/app/build-advanced/outputs/apk/debug/app-debug.apk}"
PKG=org.visadahyu.datapavan.advanced
# Watch's screen in Datapavan Advanced (ADR 0045); debug builds export it for these checks.
WATCH_SCREEN=org.visadahyu.datapavan.watch.MainActivity
SHELL_UID=2000
# shellcheck source=scripts/adb-ui.sh
. "$ROOT/scripts/adb-ui.sh"

if is_emulator; then HOST=${WATCH_TEST_HOST:-10.0.2.2}; else HOST=${WATCH_TEST_HOST:?set WATCH_TEST_HOST to this computer's address on the phone's Wi-Fi}; fi
PORT=${WATCH_TEST_PORT:-8790}

SERVER=""
# The emulator's Private DNS setting before the test changed it, restored at the end.
DNS_MODE=""
DNS_HOST=""
# Writes the global setting $1 back to $2, as "settings get" read it: "null" deletes it.
put_setting() {
    if [ "$2" = null ]; then
        adb shell settings delete global "$1" >/dev/null 2>&1 || true
    else
        adb shell settings put global "$1" "$2" >/dev/null 2>&1 || true
    fi
}
restore_private_dns() {
    [ -n "$DNS_MODE" ] || return 0
    put_setting private_dns_mode "$DNS_MODE"
    put_setting private_dns_specifier "$DNS_HOST"
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
# A connection kept open across the tunnel set up again (ADR 0044, unit 12b): nc writes its answers to a
# file on the device, and its second request waits until a marker file is there.
KEPT_GO=/data/local/tmp/watch-kept-go
KEPT_OUT=/data/local/tmp/watch-kept-out
# The adb shell on this computer that holds that connection, while it is open.
KEPT=""
# The emulator's setting to keep mobile data up while Wi-Fi is on, before the test changed it.
DATA_ALWAYS_ON=""
# Set while airplane mode is on to restart the emulator's radios, so that a failure then turns it off.
AIRPLANE=""

cleanup() {
    [ -z "$KEPT" ] || kill "$KEPT" 2>/dev/null || true
    adb shell rm -f "$HELLO_ON_DEVICE" "$QUIC_ON_DEVICE-1.bin" "$QUIC_ON_DEVICE-2.bin" "$DNS_ON_DEVICE" "$DOH_ON_DEVICE" \
        "$KEPT_GO" "$KEPT_OUT" >/dev/null 2>&1 || true
    adb shell am force-stop "$PKG" >/dev/null 2>&1 || true
    if is_emulator; then
        [ -z "$AIRPLANE" ] || adb shell cmd connectivity airplane-mode disable >/dev/null 2>&1 || true
        adb shell svc wifi enable >/dev/null 2>&1 || true
        case "$DATA_ALWAYS_ON" in
            "") ;;
            null) adb shell settings delete global mobile_data_always_on >/dev/null 2>&1 || true ;;
            *) adb shell settings put global mobile_data_always_on "$DATA_ALWAYS_ON" >/dev/null 2>&1 || true ;;
        esac
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
    # On a phone the flows name other apps' destinations, which stay on the phone: counters only. On an
    # emulator, every flow of the shell (the test's own), then the last of the others.
    local account
    account=$(adb shell dumpsys activity service "$PKG/org.visadahyu.datapavan.watch.WatchVpnService" 2>/dev/null | tr -d '\r' | sed -n 's/^ *//p' || true)
    echo "Watch's own account:" >&2
    grep -E '^(running|counters|mtu|setups)' <<<"$account" >&2 || true
    # Watch's own log: how each setup went, and its warnings. It names no destination.
    echo "Watch's log:" >&2
    adb logcat -d -s Watch:I 2>/dev/null | tr -d '\r' | tail -15 >&2 || true
    if is_emulator; then
        echo "The shell's flows:" >&2
        grep -E "^flow [a-z]+ [^ ]+ [^ ]+ $SHELL_UID " <<<"$account" >&2 || echo "  none" >&2
        echo "The last of the others:" >&2
        grep -E '^flow ' <<<"$account" | grep -vE "^flow [a-z]+ [^ ]+ [^ ]+ $SHELL_UID " | tail -20 >&2 || true
        echo "Android's networks:" >&2
        adb shell dumpsys connectivity 2>/dev/null | tr -d '\r' | grep -E 'Active default network|^ *NetworkAgentInfo\{' | cut -c1-160 | head -6 >&2 || true
    fi
    exit 1
}

# The flows the engine kept, one per line: protocol app destination uid outcome named-by ech dns network
# dns-name name (dns-name: the DNS answer's name where it differs from the connection's own, else -).
flows() {
    adb shell dumpsys activity service "$PKG/org.visadahyu.datapavan.watch.WatchVpnService" | tr -d '\r' | sed -n 's/^ *flow //p'
}

# Whether a flow matching the pattern is listed, read again for up to 5 s: a flow is listed once Android
# has named its app, which on CI after a network switch took a few seconds. The list is read whole, then
# searched: under pipefail, a grep -q that stops reading early fails the pipe, so a flow that was there
# could look missing.
# The tunnel's addresses that Watch chose (ADR 0041), from its dump: "<set> <tun4> <dns4> <tun6> <dns6>".
# adb reads nothing from stdin here: called inside a pipeline, it would swallow the pipe's input.
addresses_line() { adb shell dumpsys activity service "$PKG/org.visadahyu.datapavan.watch.WatchVpnService" </dev/null | tr -d '\r' | sed -n 's/^ *addresses //p'; }
tunnel_address() { addresses_line | awk '{print $2}'; }
# The tunnel's DNS server, IPv4 or IPv6 as the flows list them, as an extended regular expression.
tunnel_dns_pattern() { addresses_line | awk '{gsub(/\./, "\\.", $3); print $3 "|\\[" $5 "\\]"}'; }

flow_listed() {
    local list
    for _ in 1 2 3 4 5; do
        list=$(flows)
        grep -qE "$1" <<<"$list" && return 0
        sleep 1
    done
    return 1
}

# Whether a flow of the shell matches: protocol, destination and outcome.
has_flow() {
    flow_listed "^$1 [^ ]+ $(sed 's/[.[]/\\&/g; s/]/\\]/g' <<<"$2") $SHELL_UID $3 "
}

# Whether a flow of the shell, by protocol $1 to any address on port $2, is named $3 by $4 (W3), with
# the ECH column $5 (any if not given).
has_named_flow() {
    flow_listed "^$1 [^ ]+ [^ ]+:$2 $SHELL_UID opened $4 ${5:-[^ ]+} [^ ]+ [^ ]+ [^ ]+ ${3//./\\.}\$"
}

# What Watch says of Private DNS on its network: plain, network, or strict and the provider (debug).
private_dns() {
    adb shell dumpsys activity service "$PKG/org.visadahyu.datapavan.watch.WatchVpnService" | tr -d '\r' | sed -n 's/^ *private-dns //p'
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
    local vpns
    vpns=$(adb shell dumpsys connectivity | tr -d '\r' | grep -E 'ni\{(VPN |\[type: VPN)' || true)
    [ -n "$uid" ] && grep -q "OwnerUid: $uid " <<<"$vpns"
}

# True when Watch says its tunnel runs with the address set $1 (common or spare) and Android lists its
# VPN. Watch names the new set as it starts setting the tunnel up again, before its engine runs: the set
# alone does not say that the tunnel carries traffic.
tunnel_on() {
    local dump
    dump=$(adb shell dumpsys activity service "$PKG/org.visadahyu.datapavan.watch.WatchVpnService" </dev/null | tr -d '\r')
    grep -q '^ *running true$' <<<"$dump" && grep -q "^ *addresses $1 " <<<"$dump" && vpn_up
}

# Waits up to $1 seconds until the tunnel records a flow of the shell from its present address: each try
# sends a datagram to a documentation address (192.0.2.1, RFC 5737), which no network routes and no check
# below looks at. Right after the tunnel was set up again, a connection once passed with no flow recorded
# at all, and the first check failed on it (CI, 2026-11-14); the checks start once the engine records.
tunnel_records() {
    local deadline=$((SECONDS + $1)) from
    from=$(tunnel_address)
    while :; do
        device 4 "echo watch-ready | nc -u -w 1 192.0.2.1 9" >/dev/null
        grep -qE "^udp ${from//./\\.}:[0-9]+ 192\.0\.2\.1:9 $SHELL_UID " <<<"$(flows)" && return 0
        [ "$SECONDS" -lt "$deadline" ] || return 1
        sleep 1
    done
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
    flow_listed "^udp [^ ]+ ($(tunnel_dns_pattern)):53 $SHELL_UID opened " ||
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
    flow_listed "^udp [^ ]+ 8\.8\.8\.8:53 $SHELL_UID [a-z]+ [^ ]+ [^ ]+ plain:google " ||
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
    flow_listed "^tcp [^ ]+ 8\.8\.8\.8:443 $SHELL_UID [a-z]+ [^ ]+ [^ ]+ encrypted:google " ||
        fail "$round: a TLS hello for dns.google was not recognised as encrypted DNS"
    echo "ok: $round: an app's own encrypted DNS, to a known resolver"

    # A flow to an address no DNS answer gave is named after its network's organisation, when this
    # build carries the table (data/dbip-asn/update.py; a clean checkout has none, ADR 0036).
    if adb shell dumpsys activity service "$PKG/org.visadahyu.datapavan.watch.WatchVpnService" | grep -q 'organisations 20'; then
        # One of Google's name servers' addresses: apps rarely look its name up, and a name from DNS
        # would come first (Android or an app may look up dns.google, which names 8.8.8.8).
        device 6 "echo watch | nc -u -w 1 216.239.32.10 9" >/dev/null
        has_named_flow udp 9 'Google LLC' org || fail "$round: a flow to 216.239.32.10 was not named after Google's network"
        flow_listed "^udp [^ ]+ 216\.239\.32\.10:9 $SHELL_UID opened org [^ ]+ [^ ]+ as15169:hosting - Google LLC$" ||
            fail "$round: Google's network was not marked as one that hosts other companies' servers"
        echo "ok: $round: a flow named from the organisation table"
        # The owners' table names the company people know, not the registry's "Facebook, Inc.".
        device 6 "echo watch | nc -u -w 1 157.240.1.35 9" >/dev/null
        flow_listed "^udp [^ ]+ 157\.240\.1\.35:9 $SHELL_UID opened org [^ ]+ [^ ]+ as32934:own - Meta Platforms, Inc\.$" ||
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
# code (RFC 9001 5): the keys from the connection ID, AES-CTR with GCM's counter, GCM's tag over the
# header and the payload (Watch reads a hello only from a packet whose tag checks, ADR 0044, unit 9b),
# then the header protection. OpenSSL's command line has no GCM, so GHASH is written out here from
# NIST SP 800-38D, checked against its test cases 2 and 4 before any packet is built.
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

def gmul(x, y):
    # Multiplication in GCM's field, its blocks read with the first bit the highest (SP 800-38D 6.3).
    z = 0
    for i in range(127, -1, -1):
        if (x >> i) & 1:
            z ^= y
        y = (y >> 1) ^ (0xE1 << 120) if y & 1 else y >> 1
    return z

def gcm_tag(key, nonce, aad, ciphertext):
    def blocks(data):
        data += bytes(-len(data) % 16)
        return [int.from_bytes(data[i:i + 16], "big") for i in range(0, len(data), 16)]
    h = int.from_bytes(aes(key, bytes(16), "ecb"), "big")
    s = 0
    for block in blocks(aad) + blocks(ciphertext) + [(len(aad) * 8) << 64 | len(ciphertext) * 8]:
        s = gmul(s ^ block, h)
    j0 = int.from_bytes(aes(key, nonce + b"\x00\x00\x00\x01", "ecb"), "big")
    return (j0 ^ s).to_bytes(16, "big")

# SP 800-38D's test cases 2 and 4 (the GCM specification's own), so a fault here fails here.
zero = aes(bytes(16), bytes(16), "ctr", bytes(12) + b"\x00\x00\x00\x02")
assert gcm_tag(bytes(16), bytes(12), b"", zero).hex() == "ab6e47d42cec13bdf53a67b21257bddf"
k4, n4 = bytes.fromhex("feffe9928665731c6d6a8f9467308308"), bytes.fromhex("cafebabefacedbaddecaf888")
c4 = bytes.fromhex(
    "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e"
    "21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091")
a4 = bytes.fromhex("feedfacedeadbeeffeedfacedeadbeefabaddad2")
assert gcm_tag(k4, n4, a4, c4).hex() == "5bc94fbc3221a5db94fae95ae7121a47"

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
    payload = aes(key, frames.ljust(length, b"\x00"), "ctr", nonce + b"\x00\x00\x00\x02")
    packet = bytearray(header + payload + gcm_tag(key, nonce, header, payload))
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
if is_emulator; then allow_vpn "$PKG" || fail "Android did not take the VPN consent for $PKG"; fi
# Android 17: the server is on the local network, which Watch reaches for every app (ADR 0034).
[ "$(adb shell getprop ro.build.version.sdk | tr -d '\r')" -lt 37 ] || adb shell pm grant "$PKG" android.permission.ACCESS_LOCAL_NETWORK
adb shell am force-stop "$PKG"
if is_emulator; then
    # The emulator has Wi-Fi and mobile data, and the network switch near the end moves the tunnel from one
    # to the other. Read whole: under pipefail, a grep -q that stops reading early fails the pipe.
    default_network() {
        adb shell dumpsys connectivity | tr -d '\r' | sed -n 's/^Active default network: //p'
    }
    networks() {
        adb shell dumpsys connectivity | tr -d '\r' |
            sed -n 's/^ *NetworkAgentInfo{network{\([0-9]*\)}.*ni{\([^ ]*\) \([A-Z]*\).*/\1 \2 \3/p' | paste -sd ';'
    }
    # Whether the network type $1 is connected, in the list $2 or in Android's list now.
    up() {
        grep -qE "(^|;)[0-9]+ $1[^ ;]* CONNECTED" <<<"${2:-$(networks)}"
    }
    # Waits up to $1 seconds for mobile data, and for Wi-Fi too when $2 is "wifi".
    wait_up() {
        for _ in $(seq 1 $(($1 / 2))); do
            up MOBILE && { [ "${2:-}" != wifi ] || up WIFI; } && return 0
            sleep 2
        done
        up MOBILE && { [ "${2:-}" != wifi ] || up WIFI; }
    }
    # Waits up to $1 seconds until mobile data and Wi-Fi are both up and Android's list of networks has
    # stayed the same over four reads two seconds apart. After airplane mode the radios came back and then
    # replaced their networks once more while Watch ran (CI, 2026-11-14); Watch starts over networks that
    # have stopped changing.
    wait_settled() {
        local deadline=$((SECONDS + $1)) last="" now steady=0
        while :; do
            now=$(networks)
            if up MOBILE "$now" && up WIFI "$now" && [ "$now" = "$last" ]; then
                steady=$((steady + 1))
                [ "$steady" -ge 3 ] && return 0
            else
                steady=0
            fi
            last=$now
            [ "$SECONDS" -lt "$deadline" ] || return 1
            sleep 2
        done
    }
    # Mobile data stays up beside Wi-Fi, as on most phones, so that the switch has a network to go to: on
    # CI, mobile data brought up only after Wi-Fi went off was not there 40 s later ("Active default
    # network: none"). It is brought up here, before Watch starts, where restarting the radios touches no
    # tunnel: on CI it was sometimes not up at all minutes later (2026-11-11, twice, and 2026-11-12, twice:
    # Wi-Fi only), and turning data off and on did not always bring it.
    DATA_ALWAYS_ON=$(adb shell settings get global mobile_data_always_on | tr -d '\r')
    adb shell settings put global mobile_data_always_on 1
    if ! wait_up 60; then
        echo "  no mobile data after 60 s ($(networks)): turning it off and on"
        adb shell svc data disable
        sleep 2
        adb shell svc data enable
    fi
    if ! wait_up 60; then
        echo "  still no mobile data ($(networks)): restarting the radios with airplane mode"
        AIRPLANE=1
        adb shell cmd connectivity airplane-mode enable
        sleep 5
        adb shell cmd connectivity airplane-mode disable
        AIRPLANE=""
    fi
    wait_up 90 wifi ||
        fail "the emulator did not have both Wi-Fi and mobile data before Watch started ($(networks)), even after airplane mode, so the network switch would have nowhere to go; this is the emulator, not Watch"
    wait_settled 60 ||
        fail "the emulator's networks kept changing for 60 s before Watch started ($(networks)); this is the emulator, not Watch"
    echo "  networks before Watch starts: $(networks)"
fi
# The device's network or the test server may not be ready yet: on CI the first check below once found
# no answer (2026-11-11). Wait until the device reaches the server without Watch, so that a failure below
# is Watch's.
direct() {
    grep -q '^pong$' <<<"$(device 8 "printf 'GET /ping HTTP/1.0\r\n\r\n' | nc -w 3 $HOST $PORT")"
}
for _ in $(seq 1 30); do
    direct && break
    sleep 2
done
direct || fail "the device does not reach the test server at $HOST:$PORT even without Watch"
adb logcat -c
adb shell am start -W -n "$PKG/$WATCH_SCREEN" --ez start true >/dev/null
for _ in $(seq 1 20); do vpn_up && break; sleep 1; done
vpn_up || fail "Watch's tunnel did not come up (on a phone, allow the VPN request on its screen first)"
echo "ok: the tunnel is up for every app"
# The tunnel's addresses are the common ones (ADR 0041): the emulator's network, 10.0.2.0/24, does not
# use them.
case "$(addresses_line)" in
    "common 10.1.10.1 10.1.10.3 "*) echo "ok: the tunnel has the addresses common to other firewalls" ;;
    *) fail "the tunnel's addresses are not the common ones: $(addresses_line)" ;;
esac
# A network that uses the common addresses gets the spare ones (ADR 0041). The emulator's network cannot
# be made to clash, so a debug command takes the same path: the tunnel is set up again, traffic passes
# with the spare addresses, and it comes back to the common ones.
adb shell dumpsys activity service "$PKG/org.visadahyu.datapavan.watch.WatchVpnService" addresses-force spare </dev/null | grep -q '^ *addresses-forced spare' ||
    fail "the debug command to force the spare addresses failed"
within 20 tunnel_on spare || fail "the tunnel did not run with the spare addresses within 20 s: $(addresses_line)"
case "$(addresses_line)" in
    "spare 10.215.173.1 10.215.173.3 "*) ;;
    *) fail "the tunnel did not take the spare addresses: $(addresses_line)" ;;
esac
tunnel_records 30 || fail "with the spare addresses, the tunnel recorded no flow of the shell within 30 s"
answer=$(timeout 15 adb shell "printf 'GET /ping HTTP/1.0\r\n\r\n' | nc -w 5 $HOST $PORT" | tr -d '\r' || true)
grep -q '^pong$' <<<"$answer" || fail "no answer over TCP with the spare addresses"
adb shell dumpsys activity service "$PKG/org.visadahyu.datapavan.watch.WatchVpnService" addresses-force auto </dev/null >/dev/null
within 20 tunnel_on common || fail "the tunnel did not run with the common addresses again within 20 s: $(addresses_line)"
tunnel_records 30 || fail "back on the common addresses, the tunnel recorded no flow of the shell within 30 s"
echo "ok: with a clashing network the tunnel takes the spare addresses, traffic passes, and it comes back"

traffic first

answer=$(device 15 "nc -6 -w 5 2001:db8::1 80 </dev/null")
grep -qiE 'no route|unreachable' <<<"$answer" || fail "an unreachable IPv6 address looked like this to the app: $answer"
has_flow tcp "[2001:db8::1]:80" unreachable || fail "no unreachable flow of the shell"
echo "ok: an unreachable IPv6 address gets the app an ICMPv6 error"

# Ping through the tunnel (ADR 0044, decision 5): the shell's ping uses an unprivileged ICMP socket, and the
# engine carries each echo request through one of its own, protected. The 34th counter counts requests carried,
# the 35th replies, the 37th requests dropped because Android gave Watch no ICMP socket. A reply needs the
# network beneath to carry ICMP, which a CI runner may not, so it is reported, not required.
echo_counters() {
    adb shell dumpsys activity service "$PKG/org.visadahyu.datapavan.watch.WatchVpnService" | tr -d '\r' | sed -n 's/^ *counters //p' | awk '{print $34, $35, $37}'
}
read -r carried0 replies0 unsupported0 <<<"$(echo_counters)"
device 12 "ping -c 2 -W 3 1.1.1.1" >/dev/null 2>&1 || true
read -r carried1 replies1 unsupported1 <<<"$(echo_counters)"
if [ "${unsupported1:-0}" != "${unsupported0:-0}" ]; then
    if is_emulator; then fail "Android gave Watch no ICMP socket on the emulator: ping was dropped"; fi
    echo "skipped: ping, as this phone gives Watch no ICMP socket (dropped and counted)"
else
    [ "${carried1:-0}" -gt "${carried0:-0}" ] || fail "the shell's ping was not carried: $carried0, then $carried1"
    if [ "${replies1:-0}" -gt "${replies0:-0}" ]; then
        echo "ok: ping passes the tunnel through Watch's own ICMP socket, and its replies came back"
    else
        echo "ok: ping passes the tunnel through Watch's own ICMP socket (no reply: the network beneath carries no ICMP here)"
    fi
fi

# A traceroute's first hop through Watch (ADR 0044, unit 11b). Watch is not a hop: the shell's ping with a time to live
# of 1 leaves the phone with 1, and the first router's "time to live exceeded" reaches the shell from that router, as
# without Watch. It must come from an address other than 1.1.1.1, and the 42nd counter, the "time exceeded" Watch passed
# on, must grow: before, every error from the path was dropped, and Watch's request left with its own 64. ping prints the
# sender on the error's line, as "From 10.0.2.2: icmp_seq=1 Time to live exceeded" or with a name before the address in
# brackets; the last address on that line is the sender. On a phone, a reply from 1.1.1.1 ("bytes from") fails: no path
# reaches it in one hop, so the request left with a time to live other than the app's (the second review of unit 11b
# found the check passed so). The emulator's NAT answers ICMP itself, a TTL-1 ping included, so there it is reported, as
# is a network that sends no "time exceeded". Each output is read whole before it is parsed.
exceeded_counter() {
    adb shell dumpsys activity service "$PKG/org.visadahyu.datapavan.watch.WatchVpnService" | tr -d '\r' | sed -n 's/^ *counters //p' | awk '{print $42}'
}
if [ "${unsupported1:-0}" != "${unsupported0:-0}" ]; then
    echo "skipped: a ping with a time to live of 1, as this phone gives Watch no ICMP socket"
else
    exceeded0=$(exceeded_counter)
    traced=$(device 12 "ping -c 1 -t 1 -W 3 1.1.1.1")
    exceeded1=$(exceeded_counter)
    said=$(head -n 4 <<<"$traced" | paste -sd ' ' | cut -c1-300)
    exceeded_line=$(grep -i -m1 'exceeded' <<<"$traced" || true)
    if [ -n "$exceeded_line" ]; then
        router=$(grep -oE '([0-9]{1,3}[.]){3}[0-9]{1,3}' <<<"$exceeded_line" | tail -n 1 || true)
        [ -n "$router" ] && [ "$router" != 1.1.1.1 ] ||
            fail "a ping with a time to live of 1 was told its time ran out by ${router:-no address}, not by a router on the path: $exceeded_line"
        [ "${exceeded1:-0}" -gt "${exceeded0:-0}" ] ||
            fail "a ping with a time to live of 1 was told its time ran out by $router, but Watch counted no \"time exceeded\" passed on (${exceeded0:-?}, then ${exceeded1:-?}): the error did not come through Watch"
        echo "ok: a ping with a time to live of 1 is told its time ran out by the first router, $router, as without Watch (counted: $exceeded0, then $exceeded1)"
    elif grep -q 'bytes from' <<<"$traced"; then
        if is_emulator; then
            echo "reported: the emulator's NAT answers a ping with a time to live of 1 itself, so no router's \"time exceeded\" can be seen here (counted: ${exceeded0:-?}, then ${exceeded1:-?}); the shell's ping said: $said"
        else
            fail "a ping with a time to live of 1 got a reply from 1.1.1.1, which no path reaches in one hop: Watch sent it with another time to live than the shell's, or this network answers pings itself; the shell's ping said: $said"
        fi
    else
        echo "not seen: this network sends no \"time to live exceeded\" for a time to live of 1 (counted: ${exceeded0:-?}, then ${exceeded1:-?}); the shell's ping said: $said"
    fi
fi

# The tunnel's MTU follows the network beneath (ADR 0044, decision 5 as amended): Watch reads the first hop's MTU of each IP
# version from the kernel and gives the tunnel the smaller, within 1,280 and 1,500; its dump says what it chose and what it
# read. The interface that holds the tunnel's address must carry that MTU. On the emulator both networks are 1,500. Each
# output is read whole before it is parsed: under pipefail, a reader that stops early would fail the pipe.
mtu_line=$(adb shell dumpsys activity service "$PKG/org.visadahyu.datapavan.watch.WatchVpnService" </dev/null | tr -d '\r' | sed -n 's/^ *mtu //p')
read -r chosen _ first4 first6 <<<"$mtu_line"
links=$(adb shell ip -o -4 addr show </dev/null | tr -d '\r')
interface=$(awk -v address="$(tunnel_address)" '$4 ~ ("^" address "/") && !found { print $2; found = 1 }' <<<"$links")
[ -n "$interface" ] || fail "no interface holds the tunnel's address $(tunnel_address)"
# Android 15's shell may neither read /sys/class/net nor ask the kernel for links ("ip link": "Permission
# denied"), so the MTU is read where it may: from ip where that works, else from Android's own record of the
# VPN network in dumpsys connectivity, whose link properties carry the MTU the tunnel was built with.
link_mtu=$( { adb shell ip -o link show dev "$interface" </dev/null 2>/dev/null || true; } | tr -d '\r' | sed -n 's/.* mtu \([0-9]*\) .*/\1/p')
if [ -z "$link_mtu" ]; then
    connectivity=$(adb shell dumpsys connectivity </dev/null | tr -d '\r')
    vpn_line=$(grep -m1 "InterfaceName: $interface " <<<"$connectivity" || true)
    link_mtu=$(sed -n 's/.* MTU: \([0-9]*\).*/\1/p' <<<"$vpn_line")
fi
if is_emulator && [ "$chosen" != 1500 ]; then
    fail "on the emulator, whose networks are 1,500, Watch chose a tunnel MTU of $chosen (first hop: IPv4 $first4, IPv6 $first6)"
fi
if [ -z "$link_mtu" ]; then
    echo "skipped: the MTU of the tunnel's interface $interface, which this shell can read neither with ip nor from dumpsys (Watch chose $chosen; first hop: IPv4 $first4, IPv6 $first6)"
    echo "  the VPN network's record: ${vpn_line:-none}" | cut -c1-400
else
    [ "$link_mtu" = "$chosen" ] || fail "the tunnel's interface $interface carries an MTU of $link_mtu, not the ${chosen:-none} Watch chose (first hop: IPv4 $first4, IPv6 $first6)"
    echo "ok: the tunnel's MTU is $chosen, the first hop's (IPv4 $first4, IPv6 $first6)"
fi

# A tunnel set up again with the same addresses and apps, as for a new MTU, keeps its VPN network on Android and is
# handed to the running engine, which keeps its flows (ADR 0044, unit 12b). A connection to the test server is opened
# through Watch and kept open: one nc sends an HTTP request, waits until a marker file is there (at most 60 s),
# then, only if it is there, sends a second on the same connection, kept alive, and writes the answers to a file.
# Android 15's shell may not make a FIFO in /data/local/tmp, so the requests come from one shell's output. A debug
# command sets the tunnel up again with nothing changed: Android makes a new interface, and the old one goes once
# the engine has closed it. Then the marker lets the second request go: it must be answered on the same nc
# connection, and the tunnel keep the MTU Watch chose (the first-hop values beside it may change with a measure).
# Each output is read whole before it is parsed.
#
# Android's netd destroys every TCP socket on an address it believes was removed. The old interface's reset removes
# the tunnel's address there while the new interface holds it, and netd's count of the interfaces that hold it can
# race (the Android 15 emulator, 2026-11-16: "Destroyed 5 sockets on 10.1.10.1" right after the new tunnel was
# established): the kept connection's sockets go then, the shell's own among them, and no VPN could keep it. Watch's
# engine lost its listener with them, and refused every connection after, until it bound its listener anew (ADR 0044,
# unit 12b). So when the kept connection carries no second answer, a new connection through Watch must pass right
# after, and Android's log tells a destroy by netd, which is reported and passes, from a stall, which fails. A destroy
# passes only if the running engine took the tunnel, as Watch's dump counts ("setups kept N"): a new engine, the
# fallback when a swap fails, ends the connections itself, which a destroy by netd must not hide.
KEPT_REQUEST='GET /ping HTTP/1.1\r\nHost: watch\r\n\r\n'
kept_ask() { device 5 "touch $KEPT_GO" >/dev/null; }
# Waits up to 10 s until the kept connection has had $1 answers.
kept_answered() {
    local answers
    for _ in $(seq 1 10); do
        answers=$(device 5 "grep -o pong $KEPT_OUT | wc -l")
        [ "${answers// /}" = "$1" ] && return 0
        sleep 1
    done
    return 1
}
# A new connection through Watch, as the first traffic check makes one: whether it is answered.
new_connection_passes() {
    local answer
    answer=$(device 15 "printf 'GET /ping HTTP/1.0\r\n\r\n' | nc -w 5 $HOST $PORT")
    grep -q '^pong$' <<<"$answer"
}
# netd's lines in Android's log since the device's time $1, in seconds since the epoch, that say it destroyed sockets
# on the address $2, as "Destroyed 5 sockets on 10.1.10.1", joined by "; ". The address's dots match only dots, and
# the address must end there, so that 10.1.10.1 does not match 10.1.10.10. The log is read whole, then searched.
netd_destroyed() {
    local log pattern
    log=$(adb logcat -d -T "$1.000" </dev/null 2>/dev/null | tr -d '\r' || true)
    pattern="Destroyed [0-9]+ sockets on ${2//./\\.}([^0-9.]|\$)"
    grep -oE "$pattern.*" <<<"$log" | head -3 | paste -sd ';' - | sed 's/;/; /g' || true
}
# Watch's count of setups, "kept N anew M": those the running engine took, and those a new engine took.
setups_line() {
    adb shell dumpsys activity service "$PKG/org.visadahyu.datapavan.watch.WatchVpnService" </dev/null | tr -d '\r' | sed -n 's/^ *setups //p'
}
# The interfaces that hold the tunnel's IPv4 address, one a line.
tunnel_interfaces() {
    local links
    links=$(adb shell ip -o -4 addr show </dev/null | tr -d '\r')
    awk -v address="$(tunnel_address)" '$4 ~ ("^" address "/") { print $2 }' <<<"$links"
}
device 5 "rm -f $KEPT_GO $KEPT_OUT" >/dev/null
adb shell "(printf '$KEPT_REQUEST'; i=0; while [ ! -e $KEPT_GO ] && [ \$i -lt 300 ]; do sleep 0.2; i=\$((i + 1)); done; [ -e $KEPT_GO ] && printf '$KEPT_REQUEST'; sleep 5) | nc $HOST $PORT > $KEPT_OUT" </dev/null >/dev/null 2>&1 &
KEPT=$!
# The device waits 60 s at most for the marker (300 times 0.2 s), from about now.
kept_since=$SECONDS
kept_answered 1 || fail "a connection kept open through Watch got no answer to its first request; the device has: $(device 5 "ls -l $KEPT_OUT; head -c 300 $KEPT_OUT; ps -A -o PID,NAME | grep -E ' (nc|sleep)\$'" | tr '\n' ' ')"
# Android's log is read from here on, by the device's own clock, and Watch's count of setups.
setup_since=$(adb shell date +%s </dev/null | tr -d '\r')
setups_before=$(setups_line)
adb shell dumpsys activity service "$PKG/org.visadahyu.datapavan.watch.WatchVpnService" setup-again </dev/null | grep -q '^ *setup-again' ||
    fail "the debug command to set the tunnel up again failed"
moved=""
for _ in $(seq 1 20); do
    now=$(tunnel_interfaces)
    if [ -n "$now" ] && ! grep -qx "$interface" <<<"$now"; then
        moved=$(head -n 1 <<<"$now")
        break
    fi
    sleep 1
done
[ -n "$moved" ] || fail "the tunnel was not set up again within 20 s, or its old interface $interface stayed: $(tunnel_interfaces | paste -sd ' ')"
# Still one answer: the second request goes only once the marker is there, never when the device's wait ends.
kept_answered 1 || fail "the connection kept open through Watch had other than one answer before its second request: $(device 5 "grep -o pong $KEPT_OUT | wc -l")"
asked=$((SECONDS - kept_since))
kept_ask
# What netd destroyed on the tunnel's address, when the kept connection ended with it.
kept_destroyed=""
if ! kept_answered 2; then
    [ "$asked" -lt 60 ] ||
        fail "the kept connection's second request was never sent: the marker came $asked s after the connection opened, after the device's 60 s wait for it had ended, as the steps before took that long; this says nothing of the swap"
    kept_destroyed=$(netd_destroyed "$setup_since" "$(tunnel_address)")
    new_connection_passes ||
        fail "the connection kept open through Watch carried no answer after the tunnel was set up again with the same addresses (interface $interface, then $moved), and a new connection through Watch right after got none either: the engine did not take it (netd's destroys on the tunnel's address: ${kept_destroyed:-none})"
    [ -n "$kept_destroyed" ] ||
        fail "the connection kept open through Watch carried no answer after the tunnel was set up again with the same addresses (interface $interface, then $moved; the marker came after $asked s, within the device's 60 s wait for it), and netd destroyed no socket on the tunnel's address: a stall (a new connection through Watch passed)"
    read -r _ kept0 _ anew0 <<<"$setups_before"
    setups_after=$(setups_line)
    read -r _ kept1 _ anew1 <<<"$setups_after"
    [ -n "$kept0" ] && [ "${kept1:-}" = "$((kept0 + 1))" ] && [ "${anew1:-}" = "$anew0" ] ||
        fail "netd destroyed the sockets on the tunnel's address ($kept_destroyed), but the running engine did not take the tunnel set up again: Watch's setups went from '$setups_before' to '$setups_after', so the kept connection may have ended with a new engine"
    note="netd destroyed the sockets on the tunnel's address when the tunnel was set up again with the same addresses ($kept_destroyed): the connection kept open through Watch ended with them, as Android ends it; a new connection through Watch passed right after"
    echo "::warning title=netd destroyed the tunnel's sockets::$note"
    [ -z "${GITHUB_STEP_SUMMARY:-}" ] || echo "- verify-watch.sh: $note (ADR 0044, unit 12b)" >>"$GITHUB_STEP_SUMMARY"
fi
mtu_after=$(adb shell dumpsys activity service "$PKG/org.visadahyu.datapavan.watch.WatchVpnService" </dev/null | tr -d '\r' | sed -n 's/^ *mtu //p')
read -r chosen_after _ <<<"$mtu_after"
[ "$chosen_after" = "$chosen" ] || fail "the tunnel's MTU changed when it was set up again with nothing changed: $chosen, then $chosen_after ($mtu_after)"
kill "$KEPT" 2>/dev/null || true
wait "$KEPT" 2>/dev/null || true
KEPT=""
device 5 "rm -f $KEPT_GO $KEPT_OUT" >/dev/null
interface=$moved
if [ -n "$kept_destroyed" ]; then
    echo "ok: set up again with the same addresses (interface $interface now), the tunnel kept its MTU; netd destroyed the kept connection's sockets ($kept_destroyed), and a new connection through Watch passed right after"
else
    echo "ok: set up again with the same addresses (interface $interface now), the tunnel kept a connection open through Watch, both ways, and its MTU"
fi

# Fragments (ADR 0044, decision 5 as amended): a ping of 2,000 bytes of data is a 2,028-byte request, which the
# shell's kernel cuts into fragments at the tunnel's MTU of 1,500, and the engine puts together again before it
# looks at what the request is: the 39th counter counts the datagrams it rebuilt. On an emulator it must rise; a
# phone's shell may not send such a ping, so there it is reported. The reply is larger than the tunnel's MTU too,
# and is written whole; a CI runner's network may carry no ICMP, so it is reported, not required.
rebuilt_counters() {
    adb shell dumpsys activity service "$PKG/org.visadahyu.datapavan.watch.WatchVpnService" | tr -d '\r' | sed -n 's/^ *counters //p' | awk '{print $39, $35}'
}
read -r rebuilt0 replies0 <<<"$(rebuilt_counters)"
device 12 "ping -c 2 -s 2000 -W 3 1.1.1.1" >/dev/null 2>&1 || true
read -r rebuilt1 replies1 <<<"$(rebuilt_counters)"
if [ "${rebuilt1:-0}" -gt "${rebuilt0:-0}" ]; then
    if [ "${replies1:-0}" -gt "${replies0:-0}" ]; then
        echo "ok: a ping larger than the tunnel's MTU is put together from its fragments, and its replies came back"
    else
        echo "ok: a ping larger than the tunnel's MTU is put together from its fragments (no reply: the network beneath carries no ICMP here)"
    fi
elif is_emulator; then
    fail "the shell's fragmented ping was not put together: $rebuilt0, then $rebuilt1"
else
    echo "not seen: this phone's shell sent no fragmented ping, or the engine did not put it together ($rebuilt0, then $rebuilt1)"
fi

# Watch's listener is on the tunnel's own address, which any app can reach directly, from a port it
# picks. A connection that does not come from the address the engine rewrites the apps' connections to
# come from is closed at once and counted (the 19th counter): it never takes another app's waiting
# upstream connection. The listener's port is in /proc/net/tcp: listening (0A), Watch's UID, on the
# tunnel's IPv4 address, which the kernel prints as hex in reverse byte order.
strangers() {
    adb shell dumpsys activity service "$PKG/org.visadahyu.datapavan.watch.WatchVpnService" | tr -d '\r' | sed -n 's/^ *counters //p' | awk '{print $19}'
}
watch_uid=$(adb shell cmd package list packages -U "$PKG" | tr -d '\r' | sed -n "s/^package:$PKG uid:\([0-9]*\)$/\1/p")
listener_hex=$(python3 -I -c 'import sys; print("".join(f"{int(b):02X}" for b in reversed(sys.argv[1].split("."))))' "$(tunnel_address)")
listener=$(adb shell cat /proc/net/tcp 2>/dev/null | tr -d '\r' | python3 -I -c '
import sys
for line in sys.stdin:
    f = line.split()
    if len(f) > 7 and f[3] == "0A" and f[7] == sys.argv[1] and f[1].startswith(sys.argv[2] + ":"):
        print(int(f[1].split(":")[1], 16))
        break' "$watch_uid" "$listener_hex")
if [ -n "$listener" ]; then
    before=$(strangers)
    answer=$(device 8 "echo hello | nc -w 5 $(tunnel_address) $listener")
    [ -z "$answer" ] || fail "a connection straight to Watch's listener got an answer: $answer"
    after=$(strangers)
    [ "$after" = $((before + 1)) ] || fail "a connection straight to Watch's listener was not counted: $before, then $after"
    echo "ok: a connection straight to Watch's listener is closed at once and counted"
elif is_emulator; then
    fail "Watch's listener is not in /proc/net/tcp"
else
    echo "skipped: the listener check, as this phone does not show /proc/net/tcp"
fi

if is_emulator; then
    # Switching Wi-Fi off moves the tunnel to mobile data, which came up before Watch started. If it went
    # down since, turning it off and on once more.
    if ! wait_up 30; then
        echo "  no mobile data before the switch ($(networks)): turning it off and on"
        adb shell svc data disable
        sleep 2
        adb shell svc data enable
    fi
    wait_up 60 || fail "the emulator's mobile data went down after Watch started ($(networks)), so the switch has nowhere to go"
    before=$(default_network)
    wifi=$(sed -n 's/\(^\|.*;\)\([0-9]*\) WIFI[^ ;]* CONNECTED.*/\2/p' <<<"$(networks)")
    echo "  networks before the switch: $(networks); default $before"
    # Android may already use mobile data as the default while Wi-Fi is up (CI, 2026-11-12, twice): then
    # Wi-Fi going off moves nothing, and the default must simply be a network other than Wi-Fi.
    [ "$before" = "$wifi" ] || echo "  the default was not Wi-Fi before the switch"
    adb shell svc wifi disable
    # Right after, Android may still name Wi-Fi as the default: wait for another one.
    for _ in $(seq 1 30); do
        now=$(default_network)
        [[ "$now" =~ ^[0-9]+$ && "$now" != "$wifi" ]] && break
        sleep 2
    done
    echo "  networks after the switch: $(networks); default $(default_network)"
    now=$(default_network)
    [[ "$now" =~ ^[0-9]+$ && "$now" != "$wifi" ]] ||
        fail "Android had no network but Wi-Fi 60 s after Wi-Fi went off, so nothing could pass, with Watch or without"
    sleep 3
    vpn_up || fail "the tunnel went down when the network beneath switched"
    # As without a VPN, a connection during the switch may fail (ADR 0012); the next ones must pass.
    for _ in $(seq 1 15); do
        timeout 8 adb shell "printf 'GET /ping HTTP/1.0\r\n\r\n' | nc -w 5 $HOST $PORT" 2>/dev/null | tr -d '\r' | grep -q '^pong$' && break
        sleep 2
    done
    sleep 2
    traffic "after a network switch"
    adb shell svc wifi enable
    # Wi-Fi comes back beneath the tunnel. The Private DNS check below once ran while it did, and Android
    # kept the provider on the tunnel's network after the restore (CI, 2026-11-14): it waits until Wi-Fi
    # is up again and the networks have settled.
    wait_settled 90 || fail "Wi-Fi did not come back, or the networks did not settle, within 90 s ($(networks)); this is the emulator, not Watch"
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
    mode=$DNS_MODE
    host=$DNS_HOST
    restore_private_dns
    # Right after the network switch, Watch has twice still read strict mode long after the restore (once
    # 20 s, and on CI on 2026-11-14 a minute, while Android itself still named the provider on the
    # tunnel's network): Watch reads what Android says. If after 20 s Android itself still names the
    # provider, the specifier is written once more and restored, which makes Android read the setting
    # again; the mode stays restored throughout. If Android no longer names it and Watch still reads strict
    # mode, that is Watch's failure, and nothing is written again.
    if ! wait_private_dns plain 20; then
        said=$(android_private_dns)
        grep -q 'PrivateDnsServerName: dns\.google' <<<"$said" ||
            fail "Watch still reads Private DNS as '$(private_dns)' 20 s after the restore, while Android no longer names the provider: $said"
        echo "  Watch reads Private DNS as '$(private_dns)' 20 s after the restore, and Android still names the provider: $said; writing the setting again"
        DNS_MODE=$mode
        DNS_HOST=$host
        adb shell settings put global private_dns_specifier restore.invalid
        sleep 1
        restore_private_dns
        wait_private_dns plain 60 ||
            fail "Watch still reads Private DNS as '$(private_dns)' once it was restored, also after the setting was written again; Android says: $(android_private_dns)"
    fi
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
