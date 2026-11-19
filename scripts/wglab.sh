#!/usr/bin/env bash
# W7's interoperation lab through the engine itself (ADR 0035, "Tests without a provider"): Watch's engine, with
# its WireGuard tunnels, against two peers of the Linux kernel's WireGuard, the reference implementation, in the
# Compose project datapavan-wglab (spikes/wireguard-core/peer). It starts the peers, gives them the lab's clients
# with keys from the peers' own `wg genkey` (one with a preshared key), runs core/net/tests/wglab.rs, ignored by
# default, with them, checks what the peers saw (`wg show`: a completed handshake with each client, and the
# preshared key on the peer's side where the client has one, and none where it has none), and stops the project
# at the end, also on failure (stop, not down: nothing restarts it).
#
#   scripts/wglab.sh            the lab
#   scripts/wglab.sh --peers    only start the peers and print their settings, for scripts/verify-wireguard.sh
#                               (with compose.publish.yaml: their ports on the host's loopback); it stops nothing
#
# Needs Docker with Compose and the wireguard module loaded on the host (a container cannot load it). Run by
# scripts/check.sh wglab.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PEER_DIR="$ROOT/spikes/wireguard-core/peer"
compose=(docker compose -f "$PEER_DIR/compose.yaml")
MODE="${1:-lab}"
if [ "$MODE" = --peers ]; then
    compose+=(-f "$PEER_DIR/compose.publish.yaml")
fi
in_peer() { local service=$1; shift; "${compose[@]}" exec -T "$service" "$@"; }

[ -d /sys/module/wireguard ] || { echo "the wireguard module is not loaded on this host (modprobe wireguard)" >&2; exit 1; }
if [ "$MODE" != --peers ]; then
    trap '"${compose[@]}" stop >/dev/null 2>&1 || true' EXIT
fi
"${compose[@]}" up -d --build --quiet-pull >/dev/null 2>&1 || "${compose[@]}" up -d --build
for service in peer peer2; do
    for _ in $(seq 30); do
        in_peer "$service" test -e /run/wglab/ready 2>/dev/null && break
        sleep 1
    done
    in_peer "$service" test -e /run/wglab/ready || { "${compose[@]}" logs "$service" >&2; echo "$service did not come up" >&2; exit 1; }
done
address_of() { docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$("${compose[@]}" ps -q "$1")"; }

# A client: its private key from the peer's wg, and its entry on the peer.
#   client SERVICE V4 V6 [PSK]
client() {
    local service=$1 v4=$2 v6=$3 psk=${4:-} private public
    private=$(in_peer "$service" wg genkey)
    public=$(in_peer "$service" wg pubkey <<<"$private")
    if [ -n "$psk" ]; then
        in_peer "$service" wg set wg0 peer "$public" allowed-ips "$v4/32,$v6/128" preshared-key /dev/stdin <<<"$psk"
    else
        in_peer "$service" wg set wg0 peer "$public" allowed-ips "$v4/32,$v6/128"
    fi
    printf '%s %s\n' "$private" "$public"
}

psk=$(in_peer peer wg genpsk)
read -r plain_private plain_public < <(client peer 10.77.0.2 fd77::2)
read -r psk_private psk_public < <(client peer 10.77.0.3 fd77::3 "$psk")
read -r second_private second_public < <(client peer2 10.77.0.4 fd77::4)

export WGLAB_PEER="$(address_of peer):51820" WGLAB_PEER2="$(address_of peer2):51820"
export WGLAB_PEER_PUBLIC="$(in_peer peer wg show wg0 public-key)" WGLAB_PEER2_PUBLIC="$(in_peer peer2 wg show wg0 public-key)"
export WGLAB_PLAIN="$plain_private" WGLAB_PSK_KEY="$psk_private" WGLAB_PSK="$psk" WGLAB_SECOND="$second_private"

if [ "$MODE" = --peers ]; then
    # For the emulator check: the settings, one per line, KEY=value; the keys are the lab's own, made now.
    env | grep '^WGLAB_' | sort
    exit 0
fi

echo "== peers: kernel WireGuard in datapavan-wglab, $(in_peer peer sh -c 'grep -E "^wireguard-tools-wg-[0-9]" /etc/wglab-packages')"
(cd "$ROOT/core" && cargo test -p datapavan-net --test wglab --locked -- --ignored --test-threads 1 --nocapture)

# What the peers saw: a completed handshake with each client of the lab.
failed=0
handshake_of() { in_peer "$1" wg show wg0 latest-handshakes | awk -v k="$2" '$1 == k { print $2 }'; }
for check in "peer $plain_public plain" "peer $psk_public preshared-key" "peer2 $second_public second-tunnel"; do
    read -r service key name <<<"$check"
    if [ "$(handshake_of "$service" "$key")" -gt 0 ]; then
        echo "PASS peer-saw-handshake-$name: $service has a completed handshake with the engine's client"
    else
        echo "FAIL peer-saw-handshake-$name: $service has none"
        failed=1
    fi
done
# The preshared key is on the peer's side too: a client that left it out would then make no session, so the
# preshared-key test above shows the engine uses it.
psk_of() { in_peer peer wg show wg0 preshared-keys | awk -v k="$1" '$1 == k { print $2 }'; }
if [ "$(psk_of "$psk_public")" = "$psk" ] && [ "$(psk_of "$plain_public")" = "(none)" ]; then
    echo "PASS peer-holds-preshared-key: the peer has the lab's preshared key for that client, and none for the plain one"
else
    echo "FAIL peer-holds-preshared-key: the peer's preshared keys are not the lab's"
    failed=1
fi
"${compose[@]}" stop >/dev/null 2>&1
echo "== datapavan-wglab stopped"
[ "$failed" = 0 ] && echo "== all WireGuard lab checks passed" || { echo "== some WireGuard lab checks FAILED" >&2; exit 1; }
