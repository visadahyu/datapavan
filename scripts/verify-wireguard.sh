#!/usr/bin/env bash
# W7's emulator check (part 1, ADR 0035): Watch's WireGuard tunnels on a real Android, against the lab's two
# peers of the Linux kernel's WireGuard on this computer (Compose project datapavan-wglab, their ports
# published on this computer's loopback alone, which the emulator reaches as 10.0.2.2). Through the debug
# dump's way in, a configuration is set from a file in Watch's private storage and the workload app
# (scripts/workload-app) is routed through it: its lookup of a name only the peer's DNS server knows, its TCP
# and its UDP reach the peer, which sees them come from the configuration's address, and the apps it names
# reach Watch's side. An app not routed still goes directly. adb's shell, routed too, reaches the peer over
# IPv6 inside the tunnel, TCP and UDP. A second configuration routes the shell to the second peer at the same
# time, the workload app still through the first. The network beneath switches from Wi-Fi to mobile data while
# only the peer has more to send: it reaches the shell only where Watch told it the tunnel's new address. Then
# the peers stop answering: the routed apps' packets and lookups go on well past the tunnel saying so, and none
# leaves directly (a sentinel on this computer sees nothing, and Watch has no direct flow of theirs); the peers
# come back, and the app's traffic goes through again. A tunnel whose configuration is removed keeps its apps
# waiting. Nothing Watch shows or logs names a key or the endpoint.
#
# Only where no lab peer can start here at all (no Docker, Docker not answering, or no wireguard module) is the
# check skipped, with a line that says so, and it passes: it then proves nothing, and the run says it. With
# WGLAB_REQUIRED=1, which CI sets (W7, part 3a), that fails too, with its reason. Any other failure of the lab fails
# the check; the peers' logs then go to build/wglab/.
#
#   scripts/verify-wireguard.sh [path/to/Datapavan-Advanced-debug.apk]
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APK="${1:-$ROOT/android/app/build-advanced/outputs/apk/debug/app-debug.apk}"
PKG=org.visadahyu.datapavan.advanced
NETWORK_SCREEN=org.visadahyu.datapavan.network.MainActivity
WORKLOAD=org.visadahyu.datapavan.workload
SHELL_UID=2000
# shellcheck source=scripts/adb-ui.sh
. "$ROOT/scripts/adb-ui.sh"

is_emulator || { echo "verify-wireguard.sh runs on an emulator only" >&2; exit 2; }
HOST=10.0.2.2
# shellcheck source=scripts/host-ports.sh
. "$ROOT/scripts/host-ports.sh"
# shellcheck source=scripts/emulator-networks.sh
. "$ROOT/scripts/emulator-networks.sh"
PEER_DIR="$ROOT/spikes/wireguard-core/peer"
compose=(docker compose -f "$PEER_DIR/compose.yaml" -f "$PEER_DIR/compose.publish.yaml")
WORK="$(mktemp -d)"
SERVER=""
DATA_ALWAYS_ON=""

cleanup() {
    local status=$?
    adb shell run-as "$PKG" rm -f files/wg1.conf files/wg2.conf >/dev/null 2>&1 || true
    adb shell am force-stop "$PKG" >/dev/null 2>&1 || true
    adb uninstall "$WORKLOAD" >/dev/null 2>&1 || true
    adb shell svc wifi enable >/dev/null 2>&1 || true
    case "$DATA_ALWAYS_ON" in
        "") ;;
        null) adb shell settings delete global mobile_data_always_on >/dev/null 2>&1 || true ;;
        *) adb shell settings put global mobile_data_always_on "$DATA_ALWAYS_ON" >/dev/null 2>&1 || true ;;
    esac
    [ -z "$SERVER" ] || kill "$SERVER" 2>/dev/null || true
    # The peers' logs, which CI keeps when a check fails (W7, part 3a).
    if [ "$status" != 0 ]; then
        mkdir -p "$ROOT/build/wglab"
        "${compose[@]}" logs --no-color --timestamps >"$ROOT/build/wglab/peers-$(basename "$0" .sh).log" 2>&1 || true
    fi
    "${compose[@]}" stop >/dev/null 2>&1 || true
    rm -rf "$WORK"
}
trap cleanup EXIT

dump() { adb shell dumpsys activity service "$PKG/org.visadahyu.datapavan.network.NetworkVpnService" "$@" | tr -d '\r'; }
workload_log() { adb logcat -d -s DatapavanWorkload | tr -d '\r' | sed -n 's/.*DatapavanWorkload: //p'; }
device() {
    local seconds=$1
    shift
    timeout "$seconds" adb shell "$@" 2>&1 | tr -d '\r' || true
}
in_peer() { local service=$1; shift; "${compose[@]}" exec -T "$service" "$@"; }
seen() { in_peer "$1" cat /run/wglab/seen 2>/dev/null || true; }
# A tunnel's state: `handshake received error not-answering plain-dns connected flows configured resolutions`.
state_of() { sed -n "s/^ *tunnel $1 //p" <<<"$(dump)"; }
# How many of the kept flows of the app $1 went the way $2 (`direct`, `tunnel:N`).
flows_of() {
    local count
    count=$(awk -v uid="$1" -v route="$2" '$1 == "flow-route" && $2 == uid && $3 == route { print $4 }' <<<"$(dump)")
    echo "${count:-0}"
}
fail() {
    echo "WIREGUARD CHECK FAILED: $*" >&2
    echo "Watch's tunnels and flows' routes:" >&2
    grep -E '^ *(tunnel|flow-route) ' <<<"$(dump)" >&2 || true
    echo "The workload's lines:" >&2
    workload_log | tail -20 >&2 || true
    echo "What the peers saw:" >&2
    seen peer | tail -10 >&2
    seen peer2 | tail -10 >&2
    echo "Networks: $(networks); default $(default_network)" >&2
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
        grep -qx done <<<"$(workload_log)" && return 0
        sleep 1
    done
}
# Writes the configuration $2 into Watch's private storage as $1, sets it as the tunnel $3, and removes the
# file whatever the answer; the dump's lines are kept in $WORK/set.
set_tunnel() {
    adb shell run-as "$PKG" sh -c "'mkdir -p files && cat > files/$1'" <<<"$2"
    dump tunnel-add "$3" "$1" >"$WORK/set" || true
    adb shell run-as "$PKG" rm -f "files/$1"
    local answer
    answer=$(grep -E '^ *tunnel-(set|refused) ' "$WORK/set" | sed 's/^ *//' || true)
    [ "$answer" = "tunnel-set $3" ] || fail "the configuration was not set: ${answer:-no answer}"
}
route() {
    grep -q "tunnel-routed $1 $2" <<<"$(dump tunnel-route "$1" "$2")" || fail "the app $1 was not routed to $2"
}
config() {
    # $1 key, $2 IPv4, $3 IPv6, $4 port on this computer, $5 the peer's public key, $6 more [Interface] lines
    printf '[Interface]\nPrivateKey = %s\nAddress = %s/32, %s/128\nDNS = 10.77.0.1\n%s\n[Peer]\nPublicKey = %s\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = %s:%s\n' \
        "$1" "$2" "$3" "${6:-}" "$5" "$HOST" "$4"
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
sentinel_since() { tail -n +$((SENTINEL_MARK + 1)) "$WORK/sentinel.log"; }

# The lab's peers, their ports published on this computer's loopback. Skipped only where none can start here.
why_not=""
if ! command -v docker >/dev/null 2>&1; then
    why_not="no Docker"
elif ! docker info >/dev/null 2>&1; then
    why_not="Docker does not answer"
elif [ ! -d /sys/module/wireguard ]; then
    why_not="the wireguard module is not loaded"
fi
if [ -n "$why_not" ]; then
    # On CI the switch is on (WGLAB_REQUIRED=1, W7's part 3a): there a skip would pass without checking, so it fails.
    if [ "${WGLAB_REQUIRED:-}" = 1 ]; then
        echo "WIREGUARD CHECK FAILED: WGLAB_REQUIRED=1, and no WireGuard lab peer can start here ($why_not; Linux $(uname -r))" >&2
        exit 1
    fi
    echo "SKIPPED verify-wireguard.sh: no WireGuard lab peer can start here ($why_not); nothing of W7 was checked on the emulator"
    [ -z "${GITHUB_ACTIONS:-}" ] || echo "::notice title=W7's emulator check skipped::$why_not: nothing of W7 was checked on the emulator"
    exit 0
fi
export WGLAB_PORT WGLAB_PORT2
WGLAB_PORT=$(free_udp 51820)
WGLAB_PORT2=$(free_udp $((WGLAB_PORT + 1)))
settings=$("$ROOT/scripts/wglab.sh" --peers 2>"$WORK/peers.err") ||
    { cat "$WORK/peers.err" >&2; echo "WIREGUARD CHECK FAILED: the lab's peers did not start, though Docker and the wireguard module are here" >&2; exit 1; }
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
if ! wait_up 60; then
    echo "  no mobile data after 60 s ($(networks)): turning it off and on"
    adb shell svc data disable
    sleep 2
    adb shell svc data enable
fi
if ! wait_up 90 wifi; then
    wifi_again 90
    if ! wait_up 90 wifi; then
        mobile_again || true
        wait_up 60 wifi || { wifi_again 60; wait_up 60 wifi; } ||
            fail "the emulator did not have both Wi-Fi and mobile data ($(networks); $(wifi_state)), even after airplane mode, the modem registered again and a new boot; this is the emulator, not Watch"
    fi
fi
wait_settled 60 || fail "the emulator's networks kept changing for 60 s ($(networks)); this is the emulator, not Watch"
allow_vpn "$PKG" || fail "Android did not take the VPN consent for $PKG"
[ "$(adb shell getprop ro.build.version.sdk | tr -d '\r')" -lt 37 ] || adb shell pm grant "$PKG" android.permission.ACCESS_LOCAL_NETWORK
adb shell am force-stop "$PKG"
adb shell am start -W -n "$PKG/$NETWORK_SCREEN" --ez start true >/dev/null
for _ in $(seq 1 20); do vpn_up && break; sleep 1; done
vpn_up || fail "Watch's tunnel did not come up"

# The first configuration names the workload app as its own (IncludedApplications): Watch's side reads it, for
# part 2's import to offer, and the engine routes by Watch's own choice alone.
set_tunnel wg1.conf "$(config "$WGLAB_PLAIN" 10.77.0.2 fd77::2 "$WGLAB_PORT" "$WGLAB_PEER_PUBLIC" "IncludedApplications = $WORKLOAD")" 1
grep -q "tunnel-apps 1 only $WORKLOAD" "$WORK/set" || fail "the configuration's apps did not reach Watch's side: $(tr '\n' ' ' <"$WORK/set")"
route "$WORKLOAD_UID" 1
workload --es name lab.test --es tcp 10.77.0.1:80 --es udp 10.77.0.1:7
lines=$(workload_log)
grep -qx "resolved lab.test 10.77.0.1" <<<"$lines" || fail "the lookup did not go to the peer's DNS server"
grep -qx "tcp 10.77.0.1:80 pong" <<<"$lines" || fail "TCP did not reach the peer"
grep -qx "udp 10.77.0.1:7 echo" <<<"$lines" || fail "UDP did not reach the peer"
peer_saw=$(seen peer)
for what in dns http udp-echo; do
    grep -qE "^$what 10\.77\.0\.2 " <<<"$peer_saw" || fail "the peer saw no $what from the configuration's address 10.77.0.2"
done
[ "$(flows_of "$WORKLOAD_UID" direct)" = 0 ] || fail "the routed app has flows that went directly"
echo "ok: the routed app's lookup, TCP and UDP reached the peer, which saw them from 10.77.0.2; the configuration's apps reached Watch's side"

# Another app goes directly beside it: the shell, routed nowhere, reaches this computer's test server.
direct=$(device 10 "printf 'GET /ping HTTP/1.0\r\n\r\n' | toybox nc -w 6 $HOST $PORT")
grep -q pong <<<"$direct" || fail "the shell did not reach this computer directly: $direct"
[ "$(flows_of "$SHELL_UID" direct)" -gt 0 ] || fail "Watch has no direct flow of the shell"
echo "ok: an app not routed goes directly beside the routed one"

route "$SHELL_UID" 1
six=$(device 12 "printf 'GET /ping HTTP/1.0\r\n\r\n' | toybox nc -w 8 fd77::1 80")
grep -q "pong datapavan wglab peer wglab-peer1 fd77::2" <<<"$six" || fail "IPv6 TCP through the tunnel did not reach the peer as fd77::2: $six"
six_udp=$(device 10 "echo who | toybox nc -u -w 3 fd77::1 8")
grep -q "^fd77::2 [0-9]* wglab-peer1" <<<"$six_udp" || fail "IPv6 UDP through the tunnel did not reach the peer as fd77::2: $six_udp"
echo "ok: IPv6 inside the tunnel, TCP and UDP, from the configuration's fd77::2"

set_tunnel wg2.conf "$(config "$WGLAB_SECOND" 10.77.0.4 fd77::4 "$WGLAB_PORT2" "$WGLAB_PEER2_PUBLIC")" 2
route "$SHELL_UID" 2
second=$(device 10 "echo who | toybox nc -u -w 3 10.77.0.1 8")
grep -q "^10.77.0.4 [0-9]* wglab-peer2" <<<"$second" || fail "the shell did not reach the second peer as 10.77.0.4: $second"
echoes() { grep -c "^udp-echo $1 " <<<"$(seen "$2")" || true; }
first_before=$(echoes 10.77.0.2 peer)
second_before=$(echoes 10.77.0.2 peer2)
workload --es udp 10.77.0.1:7
grep -qx "udp 10.77.0.1:7 echo" <<<"$(workload_log)" || fail "the workload app lost its tunnel beside the second"
[ "$(echoes 10.77.0.2 peer)" -gt "$first_before" ] || fail "the workload app's echo did not reach the first peer"
[ "$(echoes 10.77.0.2 peer2)" = "$second_before" ] || fail "the workload app's echo went to the second peer"
echo "ok: two configurations at once, the workload app through the first peer and the shell through the second"

# The network beneath switches while only the peer has more to send. The shell asks the second peer's ticker
# once; it answers at once, then, after 30 s of silence, ten times and "end". The shell sends nothing more, and
# its tunnel nothing after the keepalive WireGuard owes ten seconds after the first answer; the switch comes 15 s
# in, inside the silence. The peer's last answers reach the shell only where Watch tells it the tunnel's new
# address: a new socket on the new network, and a packet from it.
wait_up 30 wifi || fail "not both Wi-Fi and mobile data before the switch ($(networks)), so the switch has nowhere to go"
# Wi-Fi goes off where it is the default; Android may already use mobile data as the default while Wi-Fi is up
# (verify-watch.sh, CI, 2026-11-12), and then mobile data goes off, which moves the default to Wi-Fi.
from=$(default_network)
wifi=$(sed -n 's/\(^\|.*;\)\([0-9]*\) WIFI[^ ;]* CONNECTED.*/\2/p' <<<"$(networks)")
radio=data
[ "$from" != "$wifi" ] || radio=wifi
device 60 "(echo start; sleep 50) | toybox nc -u -w 55 10.77.0.1 9002" >"$WORK/ticks" &
held=$!
started=$SECONDS
sleep 15
adb shell svc "$radio" disable
moved=""
for _ in $(seq 1 30); do
    now=$(default_network)
    if [[ "$now" =~ ^[0-9]+$ && "$now" != "$from" ]]; then
        moved=$((SECONDS - started))
        break
    fi
    sleep 1
done
[ -n "$moved" ] || fail "Android had no other default network 30 s after $radio went off ($(networks))"
[ "$moved" -le 28 ] || fail "the default network moved only ${moved} s in, after the silence: the step proves nothing; this is the emulator, not Watch"
wait "$held" || true
adb shell svc "$radio" enable
if grep -qx end "$WORK/ticks" && grep -qx "tick 1" "$WORK/ticks"; then
    echo "ok: across the network switch ($radio off, the default moved ${moved} s in), the peer's last answers reached the routed app"
else
    fail "the peer's answers after the network switch did not reach the routed app: $(tr '\n' ' ' <"$WORK/ticks")"
fi
if ! wait_settled 90; then
    wifi_again 90
    wait_settled 90 || fail "Wi-Fi did not come back, or the networks did not settle ($(networks); $(wifi_state)); this is the emulator, not Watch"
fi

# The peers stop answering: their WireGuard leaves its port, keeping its keys and clients. The routed apps go on
# sending, TCP, UDP and lookups of names never asked before, well past the first tunnel saying it does not
# answer; nothing of theirs leaves directly: the sentinel on this computer sees nothing, and Watch has no direct
# flow of theirs. Then the peers come back, and the workload app's traffic goes through again.
SENTINEL_MARK=$(wc -l <"$WORK/sentinel.log")
shell_direct=$(flows_of "$SHELL_UID" direct)
tunnelled=$(flows_of "$WORKLOAD_UID" tunnel:1)
for service in peer peer2; do in_peer "$service" wg set wg0 listen-port 51899; done
attempt() {
    workload --es name "gone-$1.lab.test" --es tcp "$HOST:$((PORT + 3))" --es udp "$HOST:$((PORT + 3))"
    device 8 "echo sentinel | toybox nc -w 4 $HOST $((PORT + 3))" >/dev/null
    device 6 "echo sentinel | toybox nc -u -w 2 $HOST $((PORT + 3))" >/dev/null
}
attempt 1
state=""
for _ in $(seq 1 25); do
    state=$(state_of 1)
    [ "$(awk '{print $4}' <<<"$state")" = 1 ] && break
    sleep 1
done
[ "$(awk '{print $4}' <<<"$state")" = 1 ] || fail "the first tunnel does not say its server does not answer: $state"
said=$SECONDS
for round in 2 3 4; do
    attempt "$round"
    sleep 3
done
[ $((SECONDS - said)) -ge 15 ] || sleep $((15 - (SECONDS - said)))
[ -z "$(sentinel_since)" ] || fail "with the peers not answering, a routed app reached this computer directly: $(sentinel_since | tr '\n' ' ')"
[ "$(flows_of "$WORKLOAD_UID" direct)" = 0 ] || fail "with the peers not answering, the workload app has flows that went directly"
# The kept flows are the latest 512: old ones may leave the list, never new direct ones come.
[ "$(flows_of "$SHELL_UID" direct)" -le "$shell_direct" ] || fail "with the peers not answering, the shell has new flows that went directly"
[ "$(flows_of "$WORKLOAD_UID" tunnel:1)" -gt "$tunnelled" ] || fail "the workload app's attempts did not reach its tunnel"
if grep -q "^resolved gone-" <<<"$(workload_log)"; then fail "a lookup was answered while the peers did not answer"; fi
[ "$(awk '{print $4}' <<<"$(state_of 1)")" = 1 ] || fail "the first tunnel stopped saying its server does not answer"
echo "ok: with the peers not answering, the routed apps' packets and lookups waited, past the tunnel saying so, and nothing of theirs left directly"
for service in peer peer2; do in_peer "$service" wg set wg0 listen-port 51820; done
back=""
for _ in $(seq 1 6); do
    workload --es tcp 10.77.0.1:80
    if grep -qx "tcp 10.77.0.1:80 pong" <<<"$(workload_log)"; then back=1; break; fi
    sleep 2
done
[ -n "$back" ] || fail "the peers came back, and the workload app's TCP still did not reach them"
[ "$(awk '{print $4}' <<<"$(state_of 1)")" = 0 ] || fail "the peers came back, and the first tunnel still says its server does not answer"
echo "ok: the peers came back, and the workload app's traffic went through its tunnel again"

# A tunnel whose configuration is removed keeps the apps routed to it waiting: Watch shows it as routed and not
# configured, and the workload app's traffic does not leave directly.
grep -q "tunnel-removed 1" <<<"$(dump tunnel-remove 1)" || fail "the first tunnel was not removed"
state=$(state_of 1)
[ "$(awk '{print $8}' <<<"$state")" = 0 ] || fail "a removed tunnel with its apps still routed is not shown as waiting for its configuration: $state"
SENTINEL_MARK=$(wc -l <"$WORK/sentinel.log")
workload --es tcp "$HOST:$((PORT + 3))" --es udp "$HOST:$((PORT + 3))"
sleep 3
[ -z "$(sentinel_since)" ] || fail "with its tunnel removed, the routed app reached this computer directly"
[ "$(flows_of "$WORKLOAD_UID" direct)" = 0 ] || fail "with its tunnel removed, the workload app has flows that went directly"
# The control: the shell, routed nowhere now, reaches the sentinel, which so sees what leaves directly.
route "$SHELL_UID" 0
device 10 "echo control | toybox nc -w 4 $HOST $((PORT + 3))" >/dev/null
grep -q '^tcp$' <<<"$(sentinel_since)" || fail "the sentinel did not see the control's direct connection: the steps above prove nothing"
echo "ok: with its configuration removed, the routed app waited and nothing of it left directly; the control's direct connection reached the sentinel"

# Nothing Watch shows or logs names a key or the endpoint.
shown="$(dump)
$(adb logcat -d | tr -d '\r')"
for secret in "$WGLAB_PLAIN" "$WGLAB_SECOND" "$HOST:$WGLAB_PORT" "$HOST:$WGLAB_PORT2"; do
    ! grep -qF -- "$secret" <<<"$shown" || fail "Watch's dump or the device's log shows a key or the endpoint"
done
echo "ok: neither Watch's dump nor the device's log names a key or the endpoint"

dump tunnel-remove 2 >/dev/null
echo "== WireGuard upstream checked on the emulator"
