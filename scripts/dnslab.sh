#!/usr/bin/env bash
# W8's DNS lab (scripts/dnslab): every way the network part may send an app's DNS, in the Compose project
# datapavan-dnslab, for the emulator checks and the engine's tests. Each way answers probe.dnslab.test with its own
# address, so that a check can tell which one answered:
#   ODoH target of odoh-rs (DNSCrypt's doh-proxy), through the relay   10.53.1.1
#   ODoH target of odoh-server-go, through the relay                   10.53.2.2
#   plain DoH (doh-proxy)                                              10.53.3.3
#   DoT (nginx's stream TLS)                                           10.53.4.4
#   the network's plain resolver (UDP and TCP 53, and DoT on 853)      10.53.5.5   (printer.home.arpa 192.168.1.50)
#   a forged answer of the censor (inject)                             10.53.6.6
# and name-N.dnslab.test answers 10.53.0.(N mod 256) everywhere. Every server is reached through the censor, whose
# fronts listen on the host's loopback alone (an emulator reaches 127.0.0.1 as 10.0.2.2); the network's resolver
# also on 10.153.53.1:53 and :853 (this computer's address on the lab's own bridge, which only the lab's containers share), for an emulator started with `-dns-server 10.153.53.1`. The lab's CA
# (scripts/dnslab/certs, test keys, public on purpose) signs every server's certificate.
#
#   scripts/dnslab.sh up                  builds and starts the lab, waits until every way answers, sets every
#                                         front to pass and the portal open, and prints the fronts, NAME=host:port
#                                         (the base port: DNSLAB_PORT, else the running lab's, else the first
#                                         free of 18440, 18450, ...;
#                                         the resolver's address: DNSLAB_RESOLVER_ADDR, else 10.153.53.1, this computer's address on the lab's bridge)
#   scripts/dnslab.sh fronts              prints the fronts of the running lab
#   scripts/dnslab.sh data DIR            writes the lab's datasets into DIR in the formats of data/odoh and
#                                         data/dns-presets, as the emulator sees the fronts (10.0.2.2): relays.tsv,
#                                         targets.tsv (with each target's configs fetched now), pairs.tsv,
#                                         presets.tsv, and the CA as ca.pem (DNSLAB_PINS=1: with the servers' pins)
#   scripts/dnslab.sh censor FRONT MODE [NAME]
#                                         FRONT: relay target-a target-b doh dot portal resolver resolver-dot;
#                                         MODE: pass, drop, reset, reset-sni NAME, block (dot, resolver-dot),
#                                         inject (resolver) (scripts/dnslab/py/censor.py says what each does)
#   scripts/dnslab.sh rotate              restarts target-a (odoh-rs), which makes a new key at each start, and waits
#                                         until it serves configs other than before (the key rotation's check)
#   scripts/dnslab.sh portal open|captive
#   scripts/dnslab.sh counts              what the censor saw, per front
#   scripts/dnslab.sh log SERVICE         a backend's query log (target-a, target-b, doh, dot, resolver), or any
#                                         service's output (relay, portal, censor, ...)
#   scripts/dnslab.sh selftest            checks every way and every censor mode from this computer with clients
#                                         independent of the app (curl, dig, scripts/dnslab/dnsclient.py and
#                                         odoh_probe.py), starting the lab if it is not running; it leaves every
#                                         front on pass and the portal open, and the lab running
#   scripts/dnslab.sh stop                stops the project (stop, not down: nothing restarts it)
#
#   DNSLAB_RELAY=caddy                    Datapavan's own relay as its server runs it (ADR 0055: Debian 13's Caddy
#                                         with server/'s files and the lab's pairs, scripts/relaylab/dnslab.Caddyfile)
#                                         behind the relay's front in odoh-server-go's place, at /odoh/proxy; for up,
#                                         data and selftest, and for scripts/verify-dns.sh, which passes it on
#
# Needs Docker with Compose, curl, dig, and Python's cryptography package (python3-cryptography) for the ODoH
# client. Only the project datapavan-dnslab is touched.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LAB="$ROOT/scripts/dnslab"
CA="$LAB/certs/ca.pem"
NETWORK=datapavan-dnslab_lab
EMULATOR_HOST=10.0.2.2
RESOLVER_ADDR="${DNSLAB_RESOLVER_ADDR:-10.153.53.1}"
export DNSLAB_RESOLVER_ADDR="$RESOLVER_ADDR"
compose=(docker compose -f "$LAB/compose.yaml" -f "$LAB/compose.publish.yaml")
# The fronts, in the censor's order from the base port.
FRONTS=(relay target-a target-b doh dot portal resolver resolver-dot)
# shellcheck source=scripts/host-ports.sh
. "$ROOT/scripts/host-ports.sh"

say() { echo "$*" >&2; }
# The relay behind the relay's front, and its path.
case "${DNSLAB_RELAY:-odoh-server-go}" in
    caddy) RELAY_SERVICE=caddy-relay RELAY_PATH=/odoh/proxy compose+=(--profile caddy) ;;
    odoh-server-go) RELAY_SERVICE=relay RELAY_PATH=/proxy ;;
    *) say "!! DNSLAB_RELAY is caddy or odoh-server-go, not $DNSLAB_RELAY"; exit 2 ;;
esac
client() { python3 -I "$LAB/dnsclient.py" "$@"; }
odoh() { python3 -I "$LAB/odoh_probe.py" "$@"; }
ctl() { "${compose[@]}" exec -T censor ctl "$@"; }
portal_ctl() { "${compose[@]}" exec -T portal ctl "$@"; }

censor_running() {
    local id
    id=$("${compose[@]}" ps -q --status running censor 2>/dev/null || true)
    [ -n "$id" ] && ctl ready >/dev/null 2>&1
}

# The base port of the running censor, when it runs on the host's loopback (compose.publish.yaml).
running_base() { ctl fronts | awk '$1 == "relay" && $3 ~ /^127\.0\.0\.1:/ { n = split($3, a, ":"); print a[n] }'; }

port_of() {
    local name=$1 i
    for i in "${!FRONTS[@]}"; do
        [ "${FRONTS[$i]}" = "$name" ] && { echo $((BASE + i)); return; }
    done
    return 1
}

# What holds port $1 on the resolver's address (or on every address), TCP or UDP; nothing when free. Ports under
# 1024 cannot be bound to test them without privileges, so ss is asked.
resolver_port_holder() {
    local port=$1
    ss -Hlntu "sport = :$port" 2>/dev/null | awk -v addr="$RESOLVER_ADDR" '{
        n = split($5, a, ":"); host = substr($5, 1, length($5) - length(a[n]) - 1)
        if (host == addr || host == "0.0.0.0" || host == "*" || host == "[::]" || host == "[::ffff:" addr "]")
            print $1 " " $5
    }'
}

choose_base() {
    local first=18440 tries=21 base i holder
    if [ -n "${DNSLAB_PORT:-}" ]; then
        first=$DNSLAB_PORT tries=1
    fi
    for ((base = first; base < first + 10 * tries; base += 10)); do
        holder=""
        for i in "${!FRONTS[@]}"; do
            holder=$(host_port_holder $((base + i)))
            [ -z "$holder" ] || break
        done
        if [ -z "$holder" ]; then
            echo "$base"
            return 0
        fi
        if [ -n "${DNSLAB_PORT:-}" ]; then
            say "!! a port of the lab's fronts from DNSLAB_PORT=$base is held: $holder; free it or set another DNSLAB_PORT"
            return 1
        fi
        say "== a port from $base is held ($holder), trying the next base"
    done
    say "!! no free ports for the lab's fronts from $first to $((first + 10 * tries - 1))"
    return 1
}

print_fronts() {
    local i
    for i in "${!FRONTS[@]}"; do
        case "${FRONTS[$i]}" in
            resolver | resolver-dot) ;;
            *) echo "${FRONTS[$i]}=127.0.0.1:$((BASE + i))" ;;
        esac
    done
    echo "resolver=$RESOLVER_ADDR:53"
    echo "resolver-dot=$RESOLVER_ADDR:853"
    echo "resolver-alt=127.0.0.1:$(port_of resolver)"
    echo "resolver-dot-alt=127.0.0.1:$(port_of resolver-dot)"
}

# DoH with curl: POST, application/dns-message. doh_query PORT HOST NAME [dnsclient query options]
doh_query() {
    local port=$1 host=$2 name=$3 work
    shift 3
    work=$(mktemp -d)
    client build "$name" "$@" >"$work/query"
    if curl -sS --max-time 5 --cacert "$CA" --resolve "$host:$port:127.0.0.1" \
        -H 'content-type: application/dns-message' -H 'accept: application/dns-message' \
        --data-binary @"$work/query" -o "$work/answer" "https://$host:$port/dns-query" 2>"$work/error"; then
        client parse "$work/answer"
    else
        echo "failed curl: $(tr '\n' ' ' <"$work/error")"
    fi
    rm -rf "$work"
}

# DoH with curl: GET, ?dns= (base64url). doh_get PORT HOST NAME
doh_get() {
    local port=$1 host=$2 name=$3 work encoded
    work=$(mktemp -d)
    encoded=$(client build "$name" | python3 -I -c 'import base64, sys
print(base64.urlsafe_b64encode(sys.stdin.buffer.read()).decode().rstrip("="))')
    if curl -sS --max-time 5 --cacert "$CA" --resolve "$host:$port:127.0.0.1" -H 'accept: application/dns-message' \
        -o "$work/answer" "https://$host:$port/dns-query?dns=$encoded" 2>"$work/error"; then
        client parse "$work/answer"
    else
        echo "failed curl: $(tr '\n' ' ' <"$work/error")"
    fi
    rm -rf "$work"
}

odoh_query() {
    local target=$1
    odoh query --ca "$CA" --relay-connect "127.0.0.1:$(port_of relay)" --relay relay.dnslab.test --relay-path "$RELAY_PATH" \
        --target "$target.dnslab.test" --configs-connect "127.0.0.1:$(port_of "$target")" "${@:2}"
}

# Every way, once; quiet. The fronts must be on pass.
ready_once() {
    doh_query "$(port_of doh)" doh.dnslab.test probe.dnslab.test | grep 'a=10.53.3.3 ' >/dev/null &&
        odoh_query target-a | grep 'a=10.53.1.1$' >/dev/null &&
        odoh_query target-b | grep 'a=10.53.2.2$' >/dev/null &&
        client dot 127.0.0.1 "$(port_of dot)" probe.dnslab.test --sni dot.dnslab.test --ca "$CA" | grep 'a=10.53.4.4 ' >/dev/null &&
        client udp "$RESOLVER_ADDR" 53 probe.dnslab.test | grep 'a=10.53.5.5 ' >/dev/null &&
        client dot "$RESOLVER_ADDR" 853 probe.dnslab.test --sni resolver.dnslab.test --ca "$CA" | grep 'a=10.53.5.5 ' >/dev/null &&
        [ "$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 "http://127.0.0.1:$(port_of portal)/generate_204")" = 204 ]
}

up() {
    local service address id
    if censor_running && [ -n "$(running_base)" ]; then
        BASE=$(running_base)
        if [ -n "${DNSLAB_PORT:-}" ] && [ "$DNSLAB_PORT" != "$BASE" ]; then
            say "== the lab runs with its fronts from $BASE; moving them to DNSLAB_PORT=$DNSLAB_PORT"
            "${compose[@]}" stop censor >/dev/null 2>&1
            BASE=$(choose_base)
        fi
    else
        BASE=$(choose_base)
        for address in 53 853; do
            local holder
            holder=$(resolver_port_holder "$address")
            if [ -n "$holder" ]; then
                say "!! port $address on $RESOLVER_ADDR, the network resolver's, is held: $holder." \
                    "Stop that program, or set DNSLAB_RESOLVER_ADDR to another loopback address (127.0.0.3)"
                return 1
            fi
        done
    fi
    export DNSLAB_PORT=$BASE
    say "== starting datapavan-dnslab (fronts from 127.0.0.1:$BASE, the network's resolver on $RESOLVER_ADDR)"
    "${compose[@]}" up -d --build --quiet-pull >/dev/null 2>&1 || "${compose[@]}" up -d --build >&2
    for _ in $(seq 60); do
        censor_running && break
        sleep 0.5
    done
    censor_running || { "${compose[@]}" logs censor >&2; say "!! the censor did not come up"; return 1; }
    # doh-proxy and nginx look their backend up once, at their start: one that started before its backend (a
    # backend recreated or restarted since) is restarted, so that it reaches the backend's address of now.
    local server backend
    for service in "target-a ns-target-a" "doh ns-doh" "dot ns-dot" "resolver-dot resolver"; do
        read -r server backend <<<"$service"
        if [ "$(started_at "$server")" -lt "$(started_at "$backend")" ]; then
            say "== $server started before its backend $backend: restarting it"
            "${compose[@]}" restart "$server" >/dev/null 2>&1
        fi
    done
    # On the host's network the censor cannot resolve the servers' names: it gets their addresses; the relay's
    # front, those of the relay DNSLAB_RELAY names.
    local container
    for service in relay target-a target-b doh dot portal resolver resolver-dot; do
        container=$service
        [ "$service" != relay ] || container=$RELAY_SERVICE
        id=$("${compose[@]}" ps -q "$container")
        address=$(docker inspect -f "{{(index .NetworkSettings.Networks \"$NETWORK\").IPAddress}}" "$id")
        ctl upstream "$service" "$address" >/dev/null
    done
    for service in "${FRONTS[@]}"; do ctl set "$service" pass >/dev/null; done
    portal_ctl open >/dev/null
    for _ in $(seq 90); do
        ready_once 2>/dev/null && break
        sleep 1
    done
    if ! ready_once; then
        "${compose[@]}" ps >&2
        say "!! not every way of the lab answers"
        return 1
    fi
    say "== every way of the lab answers (the relay: $RELAY_SERVICE, $RELAY_PATH)"
    print_fronts
}

# When a service's container started, in nanoseconds since 1970.
started_at() { date -d "$(docker inspect -f '{{.State.StartedAt}}' "$("${compose[@]}" ps -q "$1")")" +%s%N; }

need_running() {
    censor_running && BASE=$(running_base) && [ -n "$BASE" ] ||
        { say "!! the lab is not running on this computer's loopback: scripts/dnslab.sh up"; exit 1; }
}

pin_of() {
    if [ "${DNSLAB_PINS:-}" = 1 ]; then
        echo "sha256/$(openssl x509 -in "$LAB/certs/$1.pem" -pubkey -noout | openssl pkey -pubin -outform der |
            openssl dgst -sha256 -binary | openssl base64 -A)"
    else
        echo "-"
    fi
}

data() {
    local dir=$1 configs_a configs_b
    need_running
    mkdir -p "$dir"
    configs_a=$(odoh configs --ca "$CA" --connect "127.0.0.1:$(port_of target-a)" --host target-a.dnslab.test)
    configs_b=$(odoh configs --ca "$CA" --connect "127.0.0.1:$(port_of target-b)" --host target-b.dnslab.test)
    for configs in "$configs_a" "$configs_b"; do
        [[ "$configs" =~ ^[0-9a-f]+$ ]] || { say "!! a target's configs could not be fetched: $configs"; exit 1; }
    done
    local h=$EMULATOR_HOST
    {
        echo "# SPDX-License-Identifier: CC0-1.0"
        echo "# The DNS lab's Oblivious DoH relay (scripts/dnslab.sh data, $(date -u +%F)), as the emulator reaches it."
        echo "# Test only: every operator, person, seat and AS below is invented (XA to XE are user-assigned country codes, AS64496 to AS64511 documentation numbers)."
        echo "# Columns: id, url, ipv4, ipv6, operator, person, jurisdictions, hosting, cdn, pins, note. '-' means none."
        local relay_note="the lab's relay (odoh-server-go); reaches the targets by their names inside the lab"
        [ "$RELAY_SERVICE" = relay ] ||
            relay_note="Datapavan's own relay as its server runs it (Debian 13's Caddy with server/'s files); reaches the targets by their names inside the lab"
        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' lab-relay \
            "https://relay.dnslab.test:$(port_of relay)$RELAY_PATH" "$h" - "DNS lab relay operator XA" \
            "DNS lab relay person XA" XA AS64501 AS64504 "$(pin_of relay)" "$relay_note"
    } >"$dir/relays.tsv"
    {
        echo "# SPDX-License-Identifier: CC0-1.0"
        echo "# The DNS lab's Oblivious DoH targets (scripts/dnslab.sh data, $(date -u +%F)), as the emulator reaches them; configs fetched now."
        echo "# Test only: every operator, person, seat and AS below is invented (XA to XE are user-assigned country codes, AS64496 to AS64511 documentation numbers)."
        echo "# Columns: id, host, path, ipv4, ipv6, operator, person, jurisdictions, hosting, cdn, filtering, doh, doh-ipv4,"
        echo "#   doh-ipv6, pins, configs, note. '-' means none."
        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' lab-target-a \
            target-a.dnslab.test /dns-query "$h" - "DNS lab target operator XB" "DNS lab target person XB" XB \
            AS64502 AS64505 no "https://target-a.dnslab.test:$(port_of target-a)/dns-query" "$h" - \
            "$(pin_of target-a)" "$configs_a" \
            "the lab's target of odoh-rs (doh-proxy 0.11.1), probe.dnslab.test 10.53.1.1; the relay reaches it at port 443 inside the lab, the emulator at the doh URL's port; a new key at each start"
        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' lab-target-b \
            target-b.dnslab.test /dns-query "$h" - "DNS lab target operator XC" "DNS lab target person XC" XC \
            AS64503 AS64506 no "https://target-b.dnslab.test:$(port_of target-b)/dns-query" "$h" - \
            "$(pin_of target-b)" "$configs_b" \
            "the lab's target of odoh-server-go, probe.dnslab.test 10.53.2.2; the relay reaches it at port 443 inside the lab, the emulator at the doh URL's port; a fixed test key"
    } >"$dir/targets.tsv"
    {
        echo "# SPDX-License-Identifier: CC0-1.0"
        echo "# The DNS lab's pairs (scripts/dnslab.sh data): the relay with each target, odoh-rs's first."
        echo "# Columns: relay (an id of relays.tsv), target (an id of targets.tsv)."
        printf 'lab-relay\tlab-target-a\nlab-relay\tlab-target-b\n'
    } >"$dir/pairs.tsv"
    {
        echo "# SPDX-License-Identifier: CC0-1.0"
        echo "# The DNS lab's DoH and DoT servers as presets (scripts/dnslab.sh data, $(date -u +%F)), as the emulator reaches them."
        echo "# Test only: operators and seats invented; the lab logs every query, for its checks."
        echo "# Columns: id, name, operator, country, protocol, endpoint, ipv4, ipv6, logging, audit, filtering, policy, pins,"
        echo "#   note, service, logs, blocks, audited. '-' means none."
        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' lab-doh "DNS lab DoH" \
            "DNS lab DoH operator XD" XD doh "https://doh.dnslab.test:$(port_of doh)/dns-query" "$h" - \
            "logs every query (test lab)" - none https://dnslab.test/privacy "$(pin_of doh)" \
            "the lab's plain DoH (doh-proxy 0.11.1), probe.dnslab.test 10.53.3.3" standard day none no
        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' lab-dot "DNS lab DoT" \
            "DNS lab DoT operator XE" XE dot "dot.dnslab.test:$(port_of dot)" "$h" - \
            "logs every query (test lab)" - none https://dnslab.test/privacy "$(pin_of dot)" \
            "the lab's DoT (nginx's stream TLS before the lab's responder), probe.dnslab.test 10.53.4.4" standard day none no
    } >"$dir/presets.tsv"
    cp "$CA" "$dir/ca.pem"
    say "== the lab's datasets written in $dir (fronts from $EMULATOR_HOST:$BASE)"
}

log_of() {
    local service=$1
    case "$service" in
        target-a | target-b | doh | dot) service="ns-$service" ;;
        resolver-dot) service=resolver ;;
    esac
    "${compose[@]}" logs --no-log-prefix --no-color "$service"
}

# The selftest: PASS or FAIL per line.
FAILED=0
check() {
    local name=$1 want=$2 got=$3 matched
    if matched=$(grep -m1 -E -- "$want" <<<"$got"); then
        echo "PASS $name: $matched"
    else
        echo "FAIL $name: wanted /$want/, got: $(tr '\n' ' ' <<<"$got")"
        FAILED=1
    fi
}

restore() {
    local front
    for front in "${FRONTS[@]}"; do ctl set "$front" pass >/dev/null 2>&1 || true; done
    portal_ctl open >/dev/null 2>&1 || true
}

selftest() {
    local out first second n mark configs_a
    up >/dev/null
    trap restore EXIT
    ctl reset-counts >/dev/null
    local relay target_a target_b doh dot portal
    relay=$(port_of relay) target_a=$(port_of target-a) target_b=$(port_of target-b) doh=$(port_of doh)
    dot=$(port_of dot) portal=$(port_of portal)
    echo "== ways, through the fronts on pass (fronts from 127.0.0.1:$BASE, the network's resolver on $RESOLVER_ADDR)"
    check doh-post "^answer rcode=NOERROR a=10\.53\.3\.3 " "$(doh_query "$doh" doh.dnslab.test probe.dnslab.test)"
    n=$((RANDOM * 7 + 1000))
    out=$(doh_query "$doh" doh.dnslab.test "name-$n.dnslab.test" --pad)
    check doh-padded "^answer rcode=NOERROR a=10\.53\.0\.$((n % 256)) .*padding=yes" "$out"
    check doh-backend-saw-padding "name=name-$n\.dnslab\.test type=A ecs=no padding=yes" "$(log_of doh | grep "name-$n\." || true)"
    check doh-get "^answer rcode=NOERROR a=10\.53\.3\.3 " "$(doh_get "$doh" doh.dnslab.test probe.dnslab.test)"
    check target-a-plain-doh "^answer rcode=NOERROR a=10\.53\.1\.1 " "$(doh_query "$target_a" target-a.dnslab.test probe.dnslab.test)"
    check target-b-plain-doh "^answer rcode=NOERROR a=10\.53\.2\.2 " "$(doh_query "$target_b" target-b.dnslab.test probe.dnslab.test)"
    # ObliviousDoHConfigs: a length, then version 0x0001, a length, and X25519 (0x0020), HKDF-SHA256, AES-128-GCM.
    configs_a=$(odoh configs --ca "$CA" --connect "127.0.0.1:$target_a" --host target-a.dnslab.test || true)
    check target-a-configs "^[0-9a-f]{4}0001[0-9a-f]{4}002000010001" "$configs_a"
    check target-b-configs "^[0-9a-f]{4}0001[0-9a-f]{4}002000010001" "$(odoh configs --ca "$CA" --connect "127.0.0.1:$target_b" --host target-b.dnslab.test)"
    check odoh-relay-target-a "^answer rcode=NOERROR a=10\.53\.1\.1$" "$(odoh_query target-a)"
    check odoh-relay-target-b "^answer rcode=NOERROR a=10\.53\.2\.2$" "$(odoh_query target-b)"
    check dot "^answer rcode=NOERROR a=10\.53\.4\.4 " "$(client dot 127.0.0.1 "$dot" probe.dnslab.test --sni dot.dnslab.test --ca "$CA")"
    out=$(client dot 127.0.0.1 "$dot" probe.dnslab.test --sni dot.dnslab.test --ca "$CA" --pad || true)
    check dot-padded-468 "length=(468|936) padding=yes" "$out"
    check resolver-udp "^10\.53\.5\.5$" "$(dig +short +tries=1 +time=3 @"$RESOLVER_ADDR" probe.dnslab.test A)"
    check resolver-tcp "^10\.53\.5\.5$" "$(dig +short +tcp +tries=1 +time=3 @"$RESOLVER_ADDR" probe.dnslab.test A)"
    check resolver-printer "^192\.168\.1\.50$" "$(dig +short +tries=1 +time=3 @"$RESOLVER_ADDR" printer.home.arpa A)"
    check resolver-name-n "^10\.53\.0\.44$" "$(dig +short +tries=1 +time=3 @"$RESOLVER_ADDR" name-300.dnslab.test A)"
    check resolver-aaaa-nodata "status: NOERROR.*ANSWER: 0," "$(dig +tries=1 +time=3 @"$RESOLVER_ADDR" probe.dnslab.test AAAA | grep -E 'status|ANSWER:' | tr '\n' ' ')"
    check resolver-nxdomain "status: NXDOMAIN" "$(dig +tries=1 +time=3 @"$RESOLVER_ADDR" nothing.example A | grep status)"
    check resolver-udp-padded-468 "length=468 padding=yes" "$(client udp "$RESOLVER_ADDR" 53 probe.dnslab.test --pad)"
    check resolver-tcp-padded-468 "length=468 padding=yes" "$(client tcp "$RESOLVER_ADDR" 53 probe.dnslab.test --pad)"
    check resolver-unpadded "length=[0-9]+ padding=no" "$(client udp "$RESOLVER_ADDR" 53 probe.dnslab.test)"
    n=$((RANDOM * 7 + 1000))
    client udp "$RESOLVER_ADDR" 53 "name-$n.dnslab.test" --ecs >/dev/null || true
    check resolver-logs-ecs "name=name-$n\.dnslab\.test type=A ecs=yes padding=no" "$(log_of resolver | grep "name-$n\." || true)"
    check resolver-alt-port "^10\.53\.5\.5$" "$(dig +short +tries=1 +time=3 -p "$(port_of resolver)" @127.0.0.1 probe.dnslab.test A)"
    check resolver-dot-by-name "^answer rcode=NOERROR a=10\.53\.5\.5 " "$(client dot "$RESOLVER_ADDR" 853 probe.dnslab.test --sni resolver.dnslab.test --ca "$CA")"
    check resolver-dot-by-address "^answer rcode=NOERROR a=10\.53\.5\.5 " "$(client dot "$RESOLVER_ADDR" 853 probe.dnslab.test --sni "$RESOLVER_ADDR" --ca "$CA")"
    check portal-open "^204$" "$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 "http://127.0.0.1:$portal/generate_204")"

    echo "== censor modes, one at a time"
    ctl set doh drop >/dev/null
    check drop-doh-syn "^failed connect-timeout$" "$(client tls 127.0.0.1 "$doh" --sni doh.dnslab.test --ca "$CA" --timeout 3)"
    check drop-doh-curl "failed curl: .*(timed out|Timeout)" "$(doh_query "$doh" doh.dnslab.test probe.dnslab.test)"
    check drop-other-front-passes "^answer rcode=NOERROR a=10\.53\.4\.4 " "$(client dot 127.0.0.1 "$dot" probe.dnslab.test --sni dot.dnslab.test --ca "$CA")"
    check drop-counted "^doh .* dropped=[1-9]" "$(ctl counts)"
    ctl set doh pass >/dev/null
    check pass-after-drop "^answer rcode=NOERROR a=10\.53\.3\.3 " "$(doh_query "$doh" doh.dnslab.test probe.dnslab.test)"
    ctl set resolver drop >/dev/null
    check drop-resolver-udp "^failed timeout$" "$(client udp "$RESOLVER_ADDR" 53 probe.dnslab.test --timeout 3)"
    check drop-resolver-dig "timed out" "$(dig +tries=1 +time=2 @"$RESOLVER_ADDR" probe.dnslab.test A 2>&1 || true)"
    check drop-resolver-counted "^resolver .* dropped=[1-9]" "$(ctl counts)"
    ctl set resolver pass >/dev/null
    ctl set target-a reset >/dev/null
    check reset-target-a "^failed reset$" "$(client tls 127.0.0.1 "$target_a" --sni target-a.dnslab.test --ca "$CA")"
    check reset-target-a-plain-doh "failed curl: .*(reset|Recv failure)" "$(doh_query "$target_a" target-a.dnslab.test probe.dnslab.test)"
    # The relay reaches the target inside the lab, past the censor: with configs at hand, ODoH still answers.
    check reset-target-a-relay-path-passes "^answer rcode=NOERROR a=10\.53\.1\.1$" "$(odoh_query target-a --configs "$configs_a")"
    check reset-counted "^target-a .* resets=[1-9]" "$(ctl counts)"
    ctl set target-a pass >/dev/null
    # An open connection is reset at its next segment once its front resets.
    mark=$(mktemp -u)
    out=$(mktemp)
    client dot 127.0.0.1 "$dot" probe.dnslab.test --sni dot.dnslab.test --ca "$CA" --again-after "$mark" >"$out" &
    for _ in $(seq 50); do [ -s "$out" ] && break; sleep 0.1; done
    ctl set dot reset >/dev/null
    touch "$mark"
    wait $! || true
    check open-connection-answered "^answer rcode=NOERROR a=10\.53\.4\.4 " "$(sed -n 1p "$out")"
    check open-connection-reset "^failed reset$" "$(sed -n 2p "$out")"
    rm -f "$mark" "$out"
    ctl set dot pass >/dev/null
    # An open connection goes silent once its front drops.
    mark=$(mktemp -u)
    out=$(mktemp)
    client dot 127.0.0.1 "$dot" probe.dnslab.test --sni dot.dnslab.test --ca "$CA" --timeout 3 --again-after "$mark" >"$out" &
    for _ in $(seq 50); do [ -s "$out" ] && break; sleep 0.1; done
    ctl set dot drop >/dev/null
    touch "$mark"
    wait $! || true
    check open-connection-answered-before-drop "^answer rcode=NOERROR a=10\.53\.4\.4 " "$(sed -n 1p "$out")"
    check open-connection-silent "^failed timeout$" "$(sed -n 2p "$out")"
    check held-counted "^dot .* held=[1-9]" "$(ctl counts)"
    rm -f "$mark" "$out"
    ctl set dot pass >/dev/null
    ctl set relay reset-sni relay.dnslab.test >/dev/null
    check reset-sni-named "^failed reset$" "$(odoh_query target-b)"
    # Past the censor, the server's own handshake: odoh-server-go's completes for any name; Datapavan's Caddy relay
    # holds no certificate for another name and ends it with an alert of its own, which is no reset.
    if [ "$RELAY_SERVICE" = relay ]; then want='^handshake ok'; else want='^failed SSLError:.*ALERT_INTERNAL_ERROR'; fi
    check reset-sni-other-name-passes "$want" "$(client tls 127.0.0.1 "$relay" --sni other.dnslab.test)"
    check reset-sni-other-front-passes "^answer rcode=NOERROR a=10\.53\.3\.3 " "$(doh_query "$doh" doh.dnslab.test probe.dnslab.test)"
    ctl set relay pass >/dev/null
    check pass-after-reset-sni "^answer rcode=NOERROR a=10\.53\.2\.2$" "$(odoh_query target-b)"
    ctl set dot block >/dev/null
    check block-dot "^failed connect-timeout$" "$(client dot 127.0.0.1 "$dot" probe.dnslab.test --sni dot.dnslab.test --ca "$CA" --timeout 3)"
    ctl set dot pass >/dev/null
    ctl set resolver-dot block >/dev/null
    check block-resolver-dot "^failed connect-timeout$" "$(client dot "$RESOLVER_ADDR" 853 probe.dnslab.test --sni resolver.dnslab.test --ca "$CA" --timeout 3)"
    check block-leaves-plain-dns "^10\.53\.5\.5$" "$(dig +short +tries=1 +time=3 @"$RESOLVER_ADDR" probe.dnslab.test A)"
    ctl set resolver-dot pass >/dev/null
    ctl set resolver inject >/dev/null
    out=$(client udp "$RESOLVER_ADDR" 53 probe.dnslab.test --answers 2 || true)
    first=$(sed -n 1p <<<"$out") second=$(sed -n 2p <<<"$out")
    check inject-forged-first "^answer rcode=NOERROR a=10\.53\.6\.6 " "$first"
    check inject-real-second "^answer rcode=NOERROR a=10\.53\.5\.5 " "$second"
    check inject-dig-takes-forged "^10\.53\.6\.6$" "$(dig +short +tries=1 +time=3 @"$RESOLVER_ADDR" probe.dnslab.test A)"
    check inject-tcp-passes "^10\.53\.5\.5$" "$(dig +short +tcp +tries=1 +time=3 @"$RESOLVER_ADDR" probe.dnslab.test A)"
    check inject-counted "^resolver .* injected=[1-9]" "$(ctl counts)"
    ctl set resolver pass >/dev/null
    check pass-after-inject "^10\.53\.5\.5$" "$(dig +short +tries=1 +time=3 @"$RESOLVER_ADDR" probe.dnslab.test A)"

    echo "== the captive portal"
    portal_ctl captive >/dev/null
    check portal-captive "^302 http://127\.0\.0\.1:$portal/login$" "$(curl -s -o /dev/null -w '%{http_code} %{redirect_url}' --max-time 3 "http://127.0.0.1:$portal/generate_204")"
    check portal-login-page "^200$" "$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 "http://127.0.0.1:$portal/login")"
    portal_ctl open >/dev/null
    check portal-open-again "^204$" "$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 "http://127.0.0.1:$portal/generate_204")"

    restore
    trap - EXIT
    echo "== what the censor saw"
    ctl counts
    check left-on-pass "^$" "$(ctl modes | grep -v ' pass$' || true)"
    check portal-left-open "^portal open$" "$(portal_ctl state)"
    if [ "$FAILED" = 0 ]; then
        echo "== all DNS lab checks passed"
    else
        echo "== some DNS lab checks FAILED" >&2
        return 1
    fi
}

# Restarts target-a, whose key is new at each start, and waits until it serves other configs (W8's fix round, review
# S-M1: the emulator check's key rotation).
rotate() {
    need_running
    local before after
    before=$(odoh configs --ca "$CA" --connect "127.0.0.1:$(port_of target-a)" --host target-a.dnslab.test)
    "${compose[@]}" restart target-a >/dev/null 2>&1
    for _ in $(seq 1 30); do
        after=$(odoh configs --ca "$CA" --connect "127.0.0.1:$(port_of target-a)" --host target-a.dnslab.test 2>/dev/null || true)
        if [[ "$after" =~ ^[0-9a-f]+$ ]] && [ "$after" != "$before" ]; then
            say "== target-a serves a new key"
            return
        fi
        sleep 1
    done
    say "!! target-a did not come back with a new key"
    exit 1
}

case "${1:-}" in
    up) up ;;
    rotate) rotate ;;
    fronts) need_running; print_fronts ;;
    data) [ -n "${2:-}" ] || { say "usage: $0 data DIR"; exit 2; }; data "$2" ;;
    censor)
        [ -n "${3:-}" ] || { say "usage: $0 censor FRONT MODE [NAME]"; exit 2; }
        ctl set "${@:2}"
        ;;
    portal)
        case "${2:-}" in open | captive) portal_ctl "$2" ;; *) say "usage: $0 portal open|captive"; exit 2 ;; esac
        ;;
    counts) ctl counts ;;
    log) [ -n "${2:-}" ] || { say "usage: $0 log SERVICE"; exit 2; }; log_of "$2" ;;
    selftest) selftest ;;
    # Every service, the profile's too, whichever relay ran.
    stop) "${compose[@]}" --profile caddy stop ;;
    *) sed -n '2,/^set -euo/p' "$0" | sed '$d' >&2; exit 2 ;;
esac
