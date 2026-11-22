#!/usr/bin/env bash
# The ports of this computer that an emulator check's test server takes (scripts/network-lab/server.py),
# found free and then held for the whole check. Another program on one of them, even on 127.0.0.1 alone,
# which the emulator reaches as 10.0.2.2, answers in the server's place: a check that wants a connection
# refused, or an echo, then fails as if the network part were at fault (2026-11-18: a program on 127.0.0.1:8791 made
# verify-network.sh's "refused" step read an empty answer).
#
#   . scripts/host-ports.sh; host_server [--sentinel FILE]
#       starts the test server on free ports and holds them until the check ends: TCP PORT (HTTP), UDP
#       PORT+1 (echo), TCP PORT+1 bound without listening (refused, as the checks want, and taken from any
#       other program), and with --sentinel TCP and UDP PORT+3 (verify-chain.sh's sentinel, which writes to
#       FILE). It sets PORT and SERVER (the server's pid, for the check's cleanup to stop). The base is
#       NETWORK_TEST_PORT if it is set, else the first of 8790, 8800, ... 8990 the server can hold; with
#       HOST_PORTS_FIXED=1, as for a phone, whose computer's firewall was opened for 8790 and 8791, it is
#       8790 and is never moved. A port held at a base that may not move stops the check at once, naming
#       the port and, where ss can tell, the program that holds it.
#   scripts/host-ports.sh --self-test
#       checks that logic against throwaway listeners and the real server on ports from 20000 up, with no
#       emulator.

HOST_PORTS_SERVER="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/network-lab/server.py"

# What holds port $1 of this computer, TCP or UDP, on any address: "tcp 127.0.0.1:8791 by python3 (pid
# 4321)", or nothing when it is free. Whether it is free is asked of the kernel by binding the port as the
# test server does (TCP with SO_REUSEADDR, as ThreadingHTTPServer, so that connections closing from an
# earlier run do not count; UDP without it, so that a holder that set it counts too); ss names the holder
# where it may see it.
host_port_holder() {
    local port=$1 held proto
    held=$(python3 -I - "$port" <<'PY'
import socket, sys
port = int(sys.argv[1])
for kind, name in ((socket.SOCK_STREAM, "tcp"), (socket.SOCK_DGRAM, "udp")):
    s = socket.socket(socket.AF_INET, kind)
    if kind == socket.SOCK_STREAM:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind(("0.0.0.0", port))
        if kind == socket.SOCK_STREAM:
            s.listen(1)
    except OSError:
        print(name)
        break
    finally:
        s.close()
PY
    ) || held="unknown"
    [ -n "$held" ] || return 0
    for proto in $held; do
        local line
        line=$(ss -H -ln${proto:0:1}p "sport = :$port" 2>/dev/null | head -1 || true)
        if [ -n "$line" ]; then
            awk -v proto="$proto" '{
                who = "a program ss may not name (run as its user or root to see it)"
                if (match($0, /users:\(\("[^"]+",pid=[0-9]+/)) {
                    split(substr($0, RSTART + 9, RLENGTH - 9), part, "\",pid=")
                    who = part[1] " (pid " part[2] ")"
                }
                print proto " " $4 " by " who
            }' <<<"$line"
        else
            echo "$proto port $port by a program ss does not list"
        fi
    done
}

# Starts the test server on free ports and holds them (see the top).
host_server() {
    local sentinel=() offsets=(0 1) first=${HOST_PORTS_FIRST:-8790} tries=${HOST_PORTS_TRIES:-21} fixed=""
    local base offset holder out
    if [ "${1:-}" = --sentinel ]; then
        sentinel=(--sentinel "$2")
        offsets+=(3)
    fi
    if [ -n "${NETWORK_TEST_PORT:-}" ]; then
        first=$NETWORK_TEST_PORT tries=1
        fixed="NETWORK_TEST_PORT=$NETWORK_TEST_PORT names it: set it to another base, or leave it unset to have one picked"
    elif [ -n "${HOST_PORTS_FIXED:-}" ]; then
        tries=1
        fixed="the phone reaches this computer through its firewall, opened for $first and $((first + 1)): free them, or open others and set NETWORK_TEST_PORT to their base"
    fi
    out=$(mktemp)
    for ((base = first; base < first + 10 * tries; base += 10)); do
        holder=""
        for offset in "${offsets[@]}"; do
            holder=$(host_port_holder $((base + offset)))
            [ -z "$holder" ] || break
        done
        if [ -z "$holder" ]; then
            : >"$out"
            python3 -I "$HOST_PORTS_SERVER" "$base" "${sentinel[@]}" >"$out" 2>&1 &
            SERVER=$!
            for _ in $(seq 1 100); do
                grep -q "^ready $base$" "$out" && break
                kill -0 "$SERVER" 2>/dev/null || break
                sleep 0.1
            done
            if grep -q "^ready $base$" "$out"; then
                rm -f "$out"
                PORT=$base
                [ "$base" = "$first" ] || echo "== the test server holds ports from $base: one from $first on was held" >&2
                return 0
            fi
            # Taken by another program in the moment since it was found free, or the server failed.
            kill "$SERVER" 2>/dev/null || true
            wait "$SERVER" 2>/dev/null || true
            SERVER=""
            holder="the server could not hold them: $(tr '\n' ' ' <"$out")"
        fi
        if [ -n "$fixed" ]; then
            rm -f "$out"
            echo "!! a port of this computer from $base, which the check's test server needs, is held: $holder." \
                "Stop that program; $fixed." >&2
            return 1
        fi
        echo "== a port from $base is held, trying the next base: $holder" >&2
    done
    rm -f "$out"
    echo "!! no free ports for the check's test server from $first to $((first + 10 * tries - 1)); the last held: $holder" >&2
    return 1
}

# The self-test: throwaway listeners hold ports, which host_port_holder must name and host_server pass by,
# or stop at; and the server, once ready, holds every port it should, the refused one refused.
host_ports_self_test() {
    local failures=0 base out holders=() pid mark
    unset NETWORK_TEST_PORT HOST_PORTS_FIXED
    fail_test() {
        echo "self-test: $*" >&2
        failures=$((failures + 1))
    }
    # Holds a port in the background: tcp or udp, the address, the port, and whether with SO_REUSEADDR.
    hold() {
        exec {fd}< <(python3 -I -c '
import socket, sys, time
kind = socket.SOCK_STREAM if sys.argv[1] == "tcp" else socket.SOCK_DGRAM
s = socket.socket(socket.AF_INET, kind)
if sys.argv[4] == "reuse":
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((sys.argv[2], int(sys.argv[3])))
if kind == socket.SOCK_STREAM:
    s.listen(1)
print("held", flush=True)
time.sleep(60)' "$1" "$2" "$3" "$4")
        holders+=("$!")
        read -r _ <&"$fd"
    }
    release() {
        for pid in "${holders[@]}"; do kill "$pid" 2>/dev/null || true; done
        holders=()
        sleep 0.2
    }
    # A free base well away from the checks' own, and below the kernel's range of ports for outgoing
    # connections (32768 up), found by starting the real server there.
    mark=$(mktemp -u)
    HOST_PORTS_FIRST=$((20000 + RANDOM % 10000)) HOST_PORTS_TRIES=50 host_server --sentinel "$mark" 2>/dev/null ||
        { echo "self-test: the server started nowhere" >&2; return 1; }
    base=$PORT
    # The sentinel's file is there once the server is ready, for verify-chain.sh to count its lines at once.
    [ -f "$mark" ] || fail_test "the sentinel's file is not there once the server is ready"
    # The server holds its ports: HTTP answers, the next port is refused and held, the echo echoes, and the
    # sentinel's are held.
    python3 -I - "$base" <<'PY' || fail_test "the server does not hold its ports as it should"
import socket, sys, urllib.request
base = int(sys.argv[1])
assert urllib.request.urlopen(f"http://127.0.0.1:{base}/ping", timeout=5).read() == b"pong"
try:
    socket.create_connection(("127.0.0.1", base + 1), timeout=5)
    raise SystemExit("connected to the refused port")
except ConnectionRefusedError:
    pass
other = socket.socket()
try:
    other.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    other.bind(("127.0.0.1", base + 1))
    other.listen(1)
    raise SystemExit("another program could listen on the refused port")
except OSError:
    pass
u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
u.settimeout(5)
u.sendto(b"echo", ("127.0.0.1", base + 1))
assert u.recvfrom(64)[0] == b"echo"
for kind in (socket.SOCK_STREAM, socket.SOCK_DGRAM):
    s = socket.socket(socket.AF_INET, kind)
    try:
        s.bind(("127.0.0.1", base + 3))
        raise SystemExit("the sentinel's port is not held")
    except OSError:
        pass
socket.create_connection(("127.0.0.1", base + 3), timeout=5).close()
PY
    for _ in $(seq 1 50); do grep -qx tcp "$mark" 2>/dev/null && break; sleep 0.1; done
    grep -qx tcp "$mark" 2>/dev/null || fail_test "the sentinel did not write a connection to its file"
    rm -f "$mark"
    kill "$SERVER" 2>/dev/null || true
    wait "$SERVER" 2>/dev/null || true
    sleep 0.2
    # Holders the check must name: TCP on 127.0.0.1 alone, as on 2026-11-18; TCP on another address than
    # 127.0.0.1; UDP that set SO_REUSEADDR, beside which the server's echo could not bind.
    hold tcp 127.0.0.1 $((base + 1)) plain
    out=$(host_port_holder $((base + 1)))
    grep -q "^tcp 127.0.0.1:$((base + 1)) by python3" <<<"$out" || fail_test "a TCP holder on 127.0.0.1 not named: '$out'"
    release
    hold tcp 127.0.0.2 $((base + 1)) plain
    [ -n "$(host_port_holder $((base + 1)))" ] || fail_test "a TCP holder on 127.0.0.2 passed"
    release
    hold udp 127.0.0.1 $((base + 1)) reuse
    [ -n "$(host_port_holder $((base + 1)))" ] || fail_test "a UDP holder with SO_REUSEADDR passed"
    release
    # A held base: passed by when the base may move, a stop naming the port and its program when it may not.
    hold tcp 127.0.0.1 $((base + 1)) plain
    # Run in a subshell, which stops a server it started itself and says so.
    out=$({ NETWORK_TEST_PORT=$base host_server && kill "$SERVER" && echo "taken"; } 2>&1 || true)
    if grep -q '^taken$' <<<"$out"; then
        fail_test "NETWORK_TEST_PORT's held base was taken"
    elif ! grep -q "$((base + 1)) by python3" <<<"$out" || ! grep -q "NETWORK_TEST_PORT=$base" <<<"$out"; then
        fail_test "the stop names neither the port, its program nor NETWORK_TEST_PORT: $out"
    fi
    out=$({ HOST_PORTS_FIXED=1 HOST_PORTS_FIRST=$base host_server && kill "$SERVER" && echo "taken"; } 2>&1 || true)
    if grep -q '^taken$' <<<"$out"; then
        fail_test "a phone's held base was moved"
    elif ! grep -q "firewall" <<<"$out" || ! grep -q "NETWORK_TEST_PORT" <<<"$out"; then
        fail_test "a phone's stop does not say how to go on: $out"
    fi
    if HOST_PORTS_FIRST=$base HOST_PORTS_TRIES=50 host_server 2>/dev/null && [ "$PORT" != "$base" ]; then
        kill "$SERVER" 2>/dev/null || true
        wait "$SERVER" 2>/dev/null || true
    else
        fail_test "no other base taken past a held port (PORT $PORT)"
    fi
    release
    if [ "$failures" -eq 0 ]; then
        echo "host ports: held ports are named, passed by or stop a check; the server holds its own, the refused one refused"
    else
        echo "host ports: self-test failed" >&2
    fi
    [ "$failures" -eq 0 ]
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
    set -euo pipefail
    case "${1:-}" in
        --self-test) host_ports_self_test ;;
        *) echo "usage: . $0 and host_server [--sentinel FILE], or $0 --self-test" >&2; exit 2 ;;
    esac
fi
