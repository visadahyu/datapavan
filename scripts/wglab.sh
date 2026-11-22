#!/usr/bin/env bash
# W7's interoperation lab through the engine itself (ADR 0035, "Tests without a provider"): the network part's engine,
# with its WireGuard tunnels, against peers of both reference implementations in the Compose project datapavan-wglab
# (spikes/wireguard-core/peer): two of the Linux kernel's WireGuard and, since W7's part 3a, two of wireguard-go, a
# second code base by WireGuard's authors. It starts the peers, gives them the lab's clients with keys from the
# peers' own `wg genkey`, and runs core/net/tests/wglab.rs, ignored by default, against each implementation in
# turn; checks that cargo ran every test it lists, so that a run that tested nothing cannot pass; checks what the
# peers saw (`wg show`: a completed handshake with each client, and the preshared key on the peer's side where the
# client has one, and none where it has none); and stops the project at the end, also on failure (stop, not down:
# nothing restarts it). The kernel's version and wireguard-go's are written first; on failure the peers' logs go
# to build/wglab/peers.log.
#
#   scripts/wglab.sh            the lab
#   scripts/wglab.sh --peers    only start the kernel's two peers and print their settings, for the emulator checks
#                               (scripts/verify-wireguard.sh, verify-wireguard-import.sh; with compose.publish.yaml:
#                               their ports on the host's loopback); it stops nothing
#
#   WGLAB_LONG=1       also the checks that take minutes, which CI's weekly run carries: a rekey 120 s after the
#                      first handshake, keepalives on time both ways, and a cookie reply under a flood of initiations,
#                      through the engine, against both implementations at once (about three minutes more). The
#                      kernel's flood counts for every kernel WireGuard interface of the machine (the kernel keeps one
#                      measure of load for all), so for its seconds a handshake of the machine's own WireGuard, if it
#                      has one, takes a cookie's round trip, about five seconds more.
#   WGLAB_NO_BUILD=1   the peers' image is built already (CI builds it with its cache): start it as it is
#
# Needs Docker with Compose, the wireguard module loaded on the host (a container cannot load it) and, for
# wireguard-go, /dev/net/tun; without them it fails, saying which. Run by scripts/check.sh wglab.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PEER_DIR="$ROOT/spikes/wireguard-core/peer"
compose=(docker compose -f "$PEER_DIR/compose.yaml")
MODE="${1:-lab}"
services=(peer peer2 gopeer gopeer2)
if [ "$MODE" = --peers ]; then
    compose+=(-f "$PEER_DIR/compose.publish.yaml")
    services=(peer peer2)
fi
in_peer() { local service=$1; shift; "${compose[@]}" exec -T "$service" "$@"; }

missing=""
if ! command -v docker >/dev/null 2>&1; then
    missing="no Docker"
elif ! docker info >/dev/null 2>&1; then
    missing="Docker does not answer"
elif [ ! -d /sys/module/wireguard ]; then
    missing="the wireguard module is not loaded on this host (modprobe wireguard; Linux $(uname -r))"
elif [ "$MODE" != --peers ] && [ ! -c /dev/net/tun ]; then
    missing="no /dev/net/tun on this host for wireguard-go (modprobe tun)"
fi
[ -z "$missing" ] || { echo "$missing" >&2; exit 1; }

WORK="$(mktemp -d)"
finish() {
    local status=$?
    if [ "$status" != 0 ]; then
        mkdir -p "$ROOT/build/wglab"
        "${compose[@]}" logs --no-color --timestamps >"$ROOT/build/wglab/peers.log" 2>&1 || true
        echo "the peers' logs: build/wglab/peers.log" >&2
    fi
    [ "$MODE" = --peers ] || "${compose[@]}" stop >/dev/null 2>&1 || true
    rm -rf "$WORK"
}
trap finish EXIT
if [ "${WGLAB_NO_BUILD:-}" = 1 ]; then
    "${compose[@]}" up -d --no-build --pull never "${services[@]}"
else
    "${compose[@]}" up -d --build --quiet-pull "${services[@]}" >/dev/null 2>&1 || "${compose[@]}" up -d --build "${services[@]}"
fi
for service in "${services[@]}"; do
    for _ in $(seq 30); do
        in_peer "$service" test -e /run/wglab/ready 2>/dev/null && break
        sleep 1
    done
    in_peer "$service" test -e /run/wglab/ready || { "${compose[@]}" logs "$service" >&2; echo "$service did not come up" >&2; exit 1; }
done
container_of() { "${compose[@]}" ps -q "$1"; }
address_of() { docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$(container_of "$1")"; }
address6_of() { docker inspect -f '{{range .NetworkSettings.Networks}}{{.GlobalIPv6Address}}{{end}}' "$(container_of "$1")"; }

# A client: its private key from the peer's wg, and its entry on the peer, with the peer's own keepalive for it
# where KEEPALIVE says.
#   client SERVICE V4 V6 [PSK] [KEEPALIVE]
client() {
    local service=$1 v4=$2 v6=$3 psk=${4:-} keepalive=${5:-} private public
    private=$(in_peer "$service" wg genkey)
    public=$(in_peer "$service" wg pubkey <<<"$private")
    local set=(wg set wg0 peer "$public" allowed-ips "$v4/32,$v6/128")
    [ -z "$keepalive" ] || set+=(persistent-keepalive "$keepalive")
    if [ -n "$psk" ]; then
        in_peer "$service" "${set[@]}" preshared-key /dev/stdin <<<"$psk"
    else
        in_peer "$service" "${set[@]}"
    fi
    printf '%s %s\n' "$private" "$public"
}

if [ "$MODE" = --peers ]; then
    # For the emulator checks: the settings, one per line, KEY=value; the keys are the lab's own, made now.
    read -r plain_private _ < <(client peer 10.77.0.2 fd77::2)
    read -r second_private _ < <(client peer2 10.77.0.4 fd77::4)
    printf '%s\n' "WGLAB_PEER=$(address_of peer):51820" "WGLAB_PEER2=$(address_of peer2):51820" \
        "WGLAB_PEER_PUBLIC=$(in_peer peer wg show wg0 public-key)" "WGLAB_PEER2_PUBLIC=$(in_peer peer2 wg show wg0 public-key)" \
        "WGLAB_PLAIN=$plain_private" "WGLAB_SECOND=$second_private" | sort
    exit 0
fi

versions="the kernel's WireGuard on Linux $(uname -r) (module $(cat /sys/module/wireguard/version)); $(in_peer gopeer cat /etc/wglab-wireguard-go); the peers' $(in_peer peer sh -c 'grep "^wireguard-tools " /etc/wglab-packages')"
echo "== references: $versions"
[ -z "${GITHUB_STEP_SUMMARY:-}" ] || echo "WireGuard lab against $versions" >>"$GITHUB_STEP_SUMMARY"

failed=0
# Runs the lab's tests that the filter arguments select, tagged TAG in their lines, and fails unless cargo ran every
# test it lists for them, none ignored.
#   run_lab TAG FILTER...
run_lab() {
    local tag=$1 listed result passed ignored
    shift
    listed=$(cd "$ROOT/core" && cargo test -q -p datapavan-net --test wglab --locked -- --include-ignored --list "$@" | grep -c ': test$' || true)
    (cd "$ROOT/core" && cargo test -p datapavan-net --test wglab --locked -- --include-ignored --test-threads 1 --nocapture "$@") 2>&1 |
        sed -u "s/\(^\|\.\.\. \)PASS /\1PASS [$tag] /" | tee "$WORK/cargo-$tag.txt" || failed=1
    result=$(grep -E '^test result: ' "$WORK/cargo-$tag.txt" | tail -1 || true)
    passed=$(sed -n 's/.* \([0-9]*\) passed;.*/\1/p' <<<"$result")
    ignored=$(sed -n 's/.* \([0-9]*\) ignored;.*/\1/p' <<<"$result")
    if [ "$listed" -gt 0 ] && [ "${passed:-0}" = "$listed" ] && [ "${ignored:-}" = 0 ]; then
        echo "PASS [$tag] cargo-ran-the-lab: all $listed of the lab's tests ran and passed, none ignored"
    else
        echo "FAIL [$tag] cargo-ran-the-lab: cargo lists $listed tests and says: ${result:-nothing}"
        failed=1
    fi
}

# The lab against one implementation, its peers ONE and TWO.
#   implementation NAME ONE TWO
implementation() {
    local name=$1 one=$2 two=$3 psk plain_public psk_public second_public
    psk=$(in_peer "$one" wg genpsk)
    read -r WGLAB_PLAIN plain_public < <(client "$one" 10.77.0.2 fd77::2)
    read -r WGLAB_PSK_KEY psk_public < <(client "$one" 10.77.0.3 fd77::3 "$psk")
    read -r WGLAB_SECOND second_public < <(client "$two" 10.77.0.4 fd77::4)
    read -r WGLAB_SIX WGLAB_SIX_PUBLIC < <(client "$one" 10.77.0.5 fd77::5)
    # The negative check's clients: one holding the lab's preshared key, which the engine is given another for, and
    # one the engine is given the second peer's public key for.
    read -r WGLAB_WRONG_PSK_KEY WGLAB_WRONG_PSK_PUBLIC < <(client "$one" 10.77.0.6 fd77::6 "$psk")
    read -r WGLAB_WRONG_PEER_KEY WGLAB_WRONG_PEER_PUBLIC < <(client "$one" 10.77.0.7 fd77::7)
    WGLAB_WRONG_PSK=$(in_peer "$one" wg genpsk)
    export WGLAB_IMPL="$name" WGLAB_PSK="$psk" WGLAB_WRONG_PSK WGLAB_PLAIN WGLAB_PSK_KEY WGLAB_SECOND WGLAB_SIX WGLAB_SIX_PUBLIC WGLAB_WRONG_PSK_KEY WGLAB_WRONG_PSK_PUBLIC \
        WGLAB_WRONG_PEER_KEY WGLAB_WRONG_PEER_PUBLIC
    export WGLAB_PEER="$(address_of "$one"):51820" WGLAB_PEER2="$(address_of "$two"):51820" \
        WGLAB_PEER6="[$(address6_of "$one")]:51820"
    export WGLAB_PEER_PUBLIC="$(in_peer "$one" wg show wg0 public-key)" WGLAB_PEER2_PUBLIC="$(in_peer "$two" wg show wg0 public-key)"
    export WGLAB_PEER_HOST="$(in_peer "$one" hostname)" WGLAB_PEER2_HOST="$(in_peer "$two" hostname)" \
        WGLAB_PEER_CONTAINER="$(container_of "$one")"
    echo "== the lab against $name: $one and $two"
    run_lab "$name" --skip long_

    # What the peers saw: a completed handshake with each client of the lab.
    handshake_of() { in_peer "$1" wg show wg0 latest-handshakes | awk -v k="$2" '$1 == k { print $2 }'; }
    for check in "$one $plain_public plain" "$one $psk_public preshared-key" "$two $second_public second-tunnel"; do
        read -r service key what <<<"$check"
        if [ "$(handshake_of "$service" "$key")" -gt 0 ]; then
            echo "PASS [$name] peer-saw-handshake-$what: $service has a completed handshake with the engine's client"
        else
            echo "FAIL [$name] peer-saw-handshake-$what: $service has none"
            failed=1
        fi
    done
    # The preshared key is on the peer's side too: a client that left it out would then make no session, so the
    # preshared-key test above shows the engine uses it.
    psk_of() { in_peer "$one" wg show wg0 preshared-keys | awk -v k="$1" '$1 == k { print $2 }'; }
    if [ "$(psk_of "$psk_public")" = "$psk" ] && [ "$(psk_of "$plain_public")" = "(none)" ]; then
        echo "PASS [$name] peer-holds-preshared-key: the peer has the lab's preshared key for that client, and none for the plain one"
    else
        echo "FAIL [$name] peer-holds-preshared-key: the peer's preshared keys are not the lab's"
        failed=1
    fi
}

implementation kernel peer peer2
implementation go gopeer gopeer2

if [ "${WGLAB_LONG:-}" = 1 ]; then
    # The long checks' clients on each implementation's first peer, as WGLAB_<KERNEL|GO>_<name>; the one for the
    # peer's own keepalives with the peer's keepalive every 3 s; the flood's key is known to no peer.
    for pair in "KERNEL peer" "GO gopeer"; do
        read -r prefix service <<<"$pair"
        export "WGLAB_${prefix}_PEER=$(address_of "$service"):51820" "WGLAB_${prefix}_PUBLIC=$(in_peer "$service" wg show wg0 public-key)" \
            "WGLAB_${prefix}_CONTAINER=$(container_of "$service")" "WGLAB_${prefix}_FLOOD=$(in_peer "$service" wg genkey)"
        n=$([ "$prefix" = KERNEL ] && echo 0 || echo 1)
        read -r key public < <(client "$service" "10.77.0.$((8 + n))" "fd77::$((8 + n))")
        export "WGLAB_${prefix}_REKEY=$key" "WGLAB_${prefix}_REKEY_PUBLIC=$public"
        read -r key public < <(client "$service" "10.77.0.$((10 + 2 * n))" "fd77::$((10 + 2 * n))")
        export "WGLAB_${prefix}_KEEPALIVE=$key" "WGLAB_${prefix}_KEEPALIVE_PUBLIC=$public"
        read -r key _ < <(client "$service" "10.77.0.$((11 + 2 * n))" "fd77::$((11 + 2 * n))" "" 3)
        export "WGLAB_${prefix}_PEER_KEEPALIVE=$key"
        read -r key _ < <(client "$service" 10.77.0.14 fd77::14)
        export "WGLAB_${prefix}_COOKIE=$key"
    done
    echo "== the long checks against both: peer and gopeer"
    started=$SECONDS
    run_lab long long_
    echo "== the long checks took $((SECONDS - started)) s"
fi

"${compose[@]}" stop >/dev/null 2>&1
echo "== datapavan-wglab stopped"
[ "$failed" = 0 ] && echo "== all WireGuard lab checks passed" || { echo "== some WireGuard lab checks FAILED" >&2; exit 1; }
