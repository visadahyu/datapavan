#!/usr/bin/env bash
# W7's emulator check (part 1, ADR 0035): Watch's WireGuard tunnels on a real Android, against the lab's two
# peers of the Linux kernel's WireGuard on this computer (Compose project datapavan-wglab, their ports
# published on this computer's loopback alone, which the emulator reaches as 10.0.2.2). Through the debug
# dump's way in, a configuration is set from a file in Watch's private storage and the workload app
# (scripts/workload-app) is routed through it: its lookup of a name only the peer's DNS server knows, its TCP
# and its UDP reach the peer, which sees them come from the configuration's address; adb's shell, routed
# too, reaches it over IPv6 inside the tunnel. Another app goes directly: the shell, before it is routed,
# reaches this computer's test server. A second configuration routes the shell to the second peer at the
# same time. A TCP connection through the tunnel is kept across a network switch. Then the peers stop: the
# routed app waits, the tunnel says its server does not answer, and a sentinel on this computer sees nothing
# of the routed app arrive directly, while it sees a control's direct connection.
#
# CI's runner joins in W7's part 3. Where no lab peer can start (no Docker, or no wireguard module), the
# check is skipped with a line that says so, and passes: it then proves nothing, and the run says it.
#
#   scripts/verify-wireguard.sh [path/to/Datapavan-Advanced-debug.apk]
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APK="${1:-$ROOT/android/app/build-advanced/outputs/apk/debug/app-debug.apk}"
PKG=org.visadahyu.datapavan.advanced
WATCH_SCREEN=org.visadahyu.datapavan.watch.MainActivity
WORKLOAD=org.visadahyu.datapavan.workload
SHELL_UID=2000
# shellcheck source=scripts/adb-ui.sh
. "$ROOT/scripts/adb-ui.sh"

is_emulator || { echo "verify-wireguard.sh runs on an emulator only" >&2; exit 2; }
HOST=10.0.2.2
# shellcheck source=scripts/host-ports.sh
. "$ROOT/scripts/host-ports.sh"
PEER_DIR="$ROOT/spikes/wireguard-core/peer"
compose=(docker compose -f "$PEER_DIR/compose.yaml" -f "$PEER_DIR/compose.publish.yaml")
WORK="$(mktemp -d)"
SERVER=""
DATA_ALWAYS_ON=""

cleanup() {
    adb shell am force-stop "$PKG" >/dev/null 2>&1 || true
    adb uninstall "$WORKLOAD" >/dev/null 2>&1 || true
    adb shell svc wifi enable >/dev/null 2>&1 || true
    [ -z "$DATA_ALWAYS_ON" ] || adb shell settings put global mobile_data_always_on "$DATA_ALWAYS_ON" >/dev/null 2>&1 || true
    [ -z "$SERVER" ] || kill "$SERVER" 2>/dev/null || true
    "${compose[@]}" stop >/dev/null 2>&1 || true
    rm -rf "$WORK"
}
trap cleanup EXIT

dump() { adb shell dumpsys activity service "$PKG/org.visadahyu.datapavan.watch.WatchVpnService" "$@" | tr -d '\r'; }
workload_log() { adb logcat -d -s DatapavanWorkload | tr -d '\r' | sed -n 's/.*DatapavanWorkload: //p'; }
device() {
    local seconds=$1
    shift
    timeout "$seconds" adb shell "$@" 2>&1 | tr -d '\r' || true
}
seen() { "${compose[@]}" exec -T "$1" cat /run/wglab/seen 2>/dev/null || true; }
fail() {
    echo "WIREGUARD CHECK FAILED: $*" >&2
    echo "Watch's tunnels:" >&2
    dump | grep -E '^ *tunnel ' >&2 || true
    echo "The workload's lines:" >&2
    workload_log | tail -20 >&2 || true
    echo "What the peers saw:" >&2
    seen peer | tail -10 >&2
    seen peer2 | tail -10 >&2
    adb logcat -d -b crash 2>/dev/null | tail -30 >&2 || true
    exit 1
}
vpn_up() {
    local uid
    uid=$(adb shell cmd package list packages -U "$PKG" | tr -d '\r' | sed -n "s/^package:$PKG uid:\([0-9]*\)$/\1/p")
    [ -n "$uid" ] && grep -qE "OwnerUid: $uid " <<<"$(adb shell dumpsys connectivity | tr -d '\r')"
}
# The workload app, in its own process, with the extras given, until it logs "done".
workload() {
    adb logcat -c
    adb shell am start -W -n "$WORKLOAD/.WorkActivity" "$@" >/dev/null
    for _ in $(seq 1 30); do
        workload_log | grep -qx done && return 0
        sleep 1
    done
}
# Writes the configuration $2 into Watch's private storage as $1, and sets it as the tunnel $3.
set_tunnel() {
    adb shell run-as "$PKG" sh -c "'mkdir -p files && cat > files/$1'" <<<"$2"
    local answer
    answer=$(dump tunnel-add "$3" "$1" | grep -E '^ *tunnel-(set|refused) ' | sed 's/^ *//')
    adb shell run-as "$PKG" rm -f "files/$1"
    [ "$answer" = "tunnel-set $3" ] || fail "the configuration was not set: $answer"
}
config() {
    # $1 key, $2 IPv4, $3 IPv6, $4 port on this computer, $5 the peer's public key
    printf '[Interface]\nPrivateKey = %s\nAddress = %s/32, %s/128\nDNS = 10.77.0.1\n\n[Peer]\nPublicKey = %s\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = %s:%s\n' \
        "$1" "$2" "$3" "$5" "$HOST" "$4"
}
free_udp() {
    python3 -I -c 'import socket,sys
for p in range(int(sys.argv[1]), int(sys.argv[1]) + 200):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.bind(("127.0.0.1", p)); print(p); break
    except OSError: pass
    finally: s.close()' "$1"
}

# The lab's peers, their ports published on this computer's loopback; without them the check is skipped.
export WGLAB_PORT WGLAB_PORT2
WGLAB_PORT=$(free_udp 51820)
WGLAB_PORT2=$(free_udp $((WGLAB_PORT + 1)))
if ! settings=$("$ROOT/scripts/wglab.sh" --peers 2>"$WORK/peers.err"); then
    echo "SKIPPED verify-wireguard.sh: no WireGuard lab peer could start here ($(tail -1 "$WORK/peers.err")); nothing of W7 was checked on the emulator"
    exit 0
fi
# Split at the first `=` alone: a key's base64 ends in one, which `read` with IFS='=' would drop.
while IFS= read -r line; do
    [[ $line == WGLAB_*=* ]] && export "${line%%=*}=${line#*=}"
done <<<"$settings"
echo "ok: the lab's two kernel WireGuard peers answer on this computer's loopback, ports $WGLAB_PORT and $WGLAB_PORT2"

host_server --sentinel "$WORK/sentinel.log" || exit 1
"$ROOT/scripts/workload-app/build.sh" >/dev/null
adb install -r "$APK" >/dev/null
adb shell pm clear "$PKG" >/dev/null
adb uninstall "$WORKLOAD" >/dev/null 2>&1 || true
adb install "$ROOT/build/workload-app/workload-app.apk" >/dev/null
WORKLOAD_UID=$(adb shell cmd package list packages -U "$WORKLOAD" | tr -d '\r' | sed -n "s/^package:$WORKLOAD uid:\([0-9]*\)$/\1/p")
[ -n "$WORKLOAD_UID" ] || fail "the workload app did not install"
# Mobile data beside Wi-Fi, as verify-watch.sh has it, so that the switch below has a network to go to.
DATA_ALWAYS_ON=$(adb shell settings get global mobile_data_always_on | tr -d '\r')
adb shell settings put global mobile_data_always_on 1
allow_vpn "$PKG" || fail "Android did not take the VPN consent for $PKG"
[ "$(adb shell getprop ro.build.version.sdk | tr -d '\r')" -lt 37 ] || adb shell pm grant "$PKG" android.permission.ACCESS_LOCAL_NETWORK
adb shell am force-stop "$PKG"
adb shell am start -W -n "$PKG/$WATCH_SCREEN" --ez start true >/dev/null
for _ in $(seq 1 20); do vpn_up && break; sleep 1; done
vpn_up || fail "Watch's tunnel did not come up"

# Another app goes directly: the shell, routed nowhere yet, reaches this computer's test server.
direct=$(device 10 "printf 'GET /ping HTTP/1.0\r\n\r\n' | toybox nc -w 6 $HOST $PORT")
grep -q pong <<<"$direct" || fail "the shell did not reach this computer directly: $direct"
echo "ok: an app not routed goes directly"

set_tunnel wg1.conf "$(config "$WGLAB_PLAIN" 10.77.0.2 fd77::2 "$WGLAB_PORT" "$WGLAB_PEER_PUBLIC")" 1
dump tunnel-route "$WORKLOAD_UID" 1 | grep -q "tunnel-routed $WORKLOAD_UID 1" || fail "the workload app was not routed"
workload --es name lab.test --es tcp 10.77.0.1:80 --es udp 10.77.0.1:7
lines=$(workload_log)
grep -qx "resolved lab.test 10.77.0.1" <<<"$lines" || fail "the lookup did not go to the peer's DNS server"
grep -qx "tcp 10.77.0.1:80 pong" <<<"$lines" || fail "TCP did not reach the peer"
grep -qx "udp 10.77.0.1:7 echo" <<<"$lines" || fail "UDP did not reach the peer"
peer_saw=$(seen peer)
for what in dns http udp-echo; do
    grep -qE "^$what 10\.77\.0\.2 " <<<"$peer_saw" || fail "the peer saw no $what from the configuration's address 10.77.0.2"
done
echo "ok: the routed app's lookup, TCP and UDP reached the peer, which saw them from 10.77.0.2"

dump tunnel-route "$SHELL_UID" 1 | grep -q "tunnel-routed $SHELL_UID 1" || fail "the shell was not routed"
six=$(device 12 "printf 'GET /ping HTTP/1.0\r\n\r\n' | toybox nc -w 8 fd77::1 80")
if grep -q "pong datapavan wglab peer wglab-peer1 fd77::2" <<<"$six"; then
    echo "ok: IPv6 inside the tunnel, from the configuration's fd77::2"
else
    fail "IPv6 through the tunnel did not reach the peer as fd77::2: $six"
fi

set_tunnel wg2.conf "$(config "$WGLAB_SECOND" 10.77.0.4 fd77::4 "$WGLAB_PORT2" "$WGLAB_PEER2_PUBLIC")" 2
dump tunnel-route "$SHELL_UID" 2 >/dev/null
second=$(device 10 "echo who | toybox nc -u -w 3 10.77.0.1 8")
grep -q "^10.77.0.4 [0-9]* wglab-peer2" <<<"$second" || fail "the shell did not reach the second peer as 10.77.0.4: $second"
workload --es udp 10.77.0.1:7
workload_log | grep -qx "udp 10.77.0.1:7 echo" || fail "the workload app lost its tunnel beside the second"
echo "ok: two configurations at once, the workload app through the first peer and the shell through the second"

# A connection through the tunnel across a network switch: Wi-Fi off while it is open, mobile data beneath.
device 40 "(echo one; sleep 15; echo two; sleep 2) | toybox nc -w 25 10.77.0.1 9000" >"$WORK/kept" &
held=$!
sleep 4
adb shell svc wifi disable
sleep 8
adb shell svc wifi enable
wait "$held" || true
if grep -qx two "$WORK/kept"; then
    echo "ok: the routed connection was kept across the network switch"
else
    fail "the routed connection did not outlive the network switch: $(tr '\n' ' ' <"$WORK/kept")"
fi

# The peers stop: the routed apps wait, and nothing of theirs reaches this computer directly.
"${compose[@]}" stop >/dev/null 2>&1
SENTINEL_MARK=$(wc -l <"$WORK/sentinel.log")
workload --es tcp "$HOST:$((PORT + 3))" --es udp "$HOST:$((PORT + 3))"
device 10 "echo sentinel | toybox nc -w 4 $HOST $((PORT + 3))" >/dev/null
# The state's fields after the number: handshake, received, error, not-answering, plain-dns, connected, flows.
state=""
for _ in $(seq 1 25); do
    state=$(dump | sed -n 's/^ *tunnel 1 //p')
    [ "$(awk '{print $4}' <<<"$state")" = 1 ] && break
    sleep 1
done
[ "$(awk '{print $4}' <<<"$state")" = 1 ] || fail "the first tunnel does not say its server does not answer: $state"
[ -z "$(tail -n +$((SENTINEL_MARK + 1)) "$WORK/sentinel.log")" ] || fail "with the peers stopped, a routed app reached this computer directly"
dump tunnel-route "$SHELL_UID" 0 >/dev/null
device 10 "echo control | toybox nc -w 4 $HOST $((PORT + 3))" >/dev/null
grep -q '^tcp$' <<<"$(tail -n +$((SENTINEL_MARK + 1)) "$WORK/sentinel.log")" ||
    fail "the sentinel did not see the control's direct connection: the step proves nothing"
echo "ok: with the peers stopped, the routed apps waited and nothing of theirs left directly; the tunnel says it does not answer"

dump tunnel-remove 1 >/dev/null
dump tunnel-remove 2 >/dev/null
echo "== WireGuard upstream checked on the emulator"
