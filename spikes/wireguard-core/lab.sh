#!/usr/bin/env bash
# W7's interoperation lab (ADR 0035): GotaTun's Tunn (lab/, the client) against the Linux kernel's WireGuard,
# the reference implementation, in a container of its own Compose project, datapavan-wglab (peer/). It builds
# the client and the peer's image, starts the peer, gives it three clients with keys from the peer's own
# `wg genkey`, runs the client's scenarios, checks what the peer saw (`wg show`), and stops the project at the
# end, also on failure (stop, not down: nothing restarts it).
#
#   spikes/wireguard-core/lab.sh [--quick]
#
# --quick leaves out the rekey after REKEY_AFTER_TIME, which waits two minutes. The peer's address on the
# project's network is written as PEER. Needs Docker with Compose, the wireguard module loaded on the host (a
# container cannot load it) and the pinned Rust toolchain. Prints PASS or FAIL per check; fails if any failed.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
QUICK=""
if [ "${1:-}" = --quick ]; then
    QUICK=1
    shift
fi
compose=(docker compose -f "$HERE/peer/compose.yaml")
in_peer() { "${compose[@]}" exec -T peer "$@"; }
trap '"${compose[@]}" stop >/dev/null 2>&1 || true' EXIT

[ -d /sys/module/wireguard ] || { echo "the wireguard module is not loaded on this host (modprobe wireguard)" >&2; exit 1; }
(cd "$HERE" && cargo build -q --release --locked -p wg-lab)
client="$HERE/target/release/wg-lab"
"${compose[@]}" up -d --build --quiet-pull >/dev/null 2>&1 || "${compose[@]}" up -d --build

# Ready once its services have bound their addresses in the tunnel (peer/services.py writes the mark; the
# logs would not do, as they keep the lines of earlier starts).
for _ in $(seq 30); do
    in_peer test -e /run/wglab/ready 2>/dev/null && break
    sleep 1
done
server_public=$(in_peer wg show wg0 public-key 2>/dev/null) || true
in_peer test -e /run/wglab/ready 2>/dev/null && [ -n "$server_public" ] ||
    { "${compose[@]}" logs peer >&2; echo "the peer did not come up" >&2; exit 1; }
address=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$("${compose[@]}" ps -q peer)")
echo "== peer: kernel WireGuard in datapavan-wglab, $(in_peer sh -c 'grep -E "^(wireguard-tools-wg|iproute2|python3)-[0-9]" /etc/wglab-packages | tr "\n" " "')"

# A client: its private key from the peer's wg, its public key, and its entry on the peer.
#   new_client NAME V4 V6 [PSK on the peer] [the peer's PersistentKeepalive for it]
declare -A private public
new_client() {
    private[$1]=$(in_peer wg genkey)
    public[$1]=$(in_peer wg pubkey <<<"${private[$1]}")
    local set=(wg set wg0 peer "${public[$1]}" allowed-ips "$2/32,$3/128")
    [ -z "${5:-}" ] || set+=(persistent-keepalive "$5")
    if [ -n "${4:-}" ]; then
        in_peer "${set[@]}" preshared-key /dev/stdin <<<"$4"
    else
        in_peer "${set[@]}"
    fi
}
peer_field() { in_peer wg show wg0 "$1" | awk -v k="${public[$2]}" '$1 == k { print $2 }'; }

psk=$(in_peer wg genpsk)
wrong=$(in_peer wg genpsk)
new_client plain 10.77.0.2 fd77::2
new_client psk 10.77.0.3 fd77::3 "$psk" 3
new_client wrong 10.77.0.4 fd77::4 "$psk"

failed=0
out=$(mktemp)
trap 'rm -f "$out"; "${compose[@]}" stop >/dev/null 2>&1 || true' EXIT
run() {
    local name=$1
    shift
    echo "== client $name: $*"
    local status=0
    WG_PRIVATE="${private[$name]}" WG_PEER_PUBLIC="$server_public" "$client" --peer "$address:51820" "$@" >"$out" || status=$?
    sed "s/$address/PEER/g" "$out"
    [ "$status" = 0 ] || failed=1
}

extra=()
[ -z "$QUICK" ] || extra=(--skip-rekey)
run plain --v4 10.77.0.2 --v6 fd77::2 --scenario full --keepalive 5 "${extra[@]}"
port=$(awk '$1 == "local-port" { print $2 }' "$out")
endpoint=$(peer_field endpoints plain)
handshake=$(peer_field latest-handshakes plain)
transfer=$(in_peer wg show wg0 transfer | awk -v k="${public[plain]}" '$1 == k { print $2 " received, " $3 " sent" }')
if [ "${endpoint##*:}" = "$port" ]; then
    echo "PASS peer-endpoint-follows-roaming: the peer has the client at port $port, the client's last local port"
else
    echo "FAIL peer-endpoint-follows-roaming: the peer has the client at port ${endpoint##*:}, the client's last port is $port"
    failed=1
fi
now=$(date +%s)
echo "note: the peer's last handshake with this client $((now - handshake)) s ago; transfer ${transfer} (bytes, the peer's view)"

WG_PSK="$psk" run psk --v4 10.77.0.3 --v6 fd77::3 --scenario psk
WG_PSK="$wrong" run wrong --v4 10.77.0.4 --v6 fd77::4 --scenario wrong-psk
handshake=$(peer_field latest-handshakes wrong)
if [ "$handshake" = 0 ]; then
    echo "PASS peer-wrong-psk-no-session: the peer has no completed handshake with the client of the wrong key"
else
    echo "FAIL peer-wrong-psk-no-session: the peer records a handshake at $handshake"
    failed=1
fi

"${compose[@]}" stop >/dev/null 2>&1
echo "== datapavan-wglab stopped"
[ "$failed" = 0 ] && echo "== all lab checks passed" || { echo "== some lab checks FAILED" >&2; exit 1; }
