#!/usr/bin/env bash
# The ports of this computer that an emulator check's test servers take (scripts/watch-lab/server.py and the
# checks' own listeners), found free before the check starts. Another program on one of them, even on
# 127.0.0.1 alone, which the emulator reaches as 10.0.2.2, answers in the server's place: a check that wants
# a connection refused, or an echo, then fails as if Watch were at fault (2026-11-18: a program on
# 127.0.0.1:8791 made verify-watch.sh's "refused" step read an empty answer).
#
#   . scripts/host-ports.sh; host_ports 0 1 3
#       sets PORT so that PORT, PORT+1 and PORT+3 are free for TCP and UDP on every address: WATCH_TEST_PORT
#       if it is set, else the first of 8790, 8800, ... 8990 at which they all are. With WATCH_TEST_PORT
#       set and a port of it held, or none of those free, it stops the check at once, naming the port and,
#       where ss can tell, the program that holds it.
#   scripts/host-ports.sh --self-test
#       checks that logic against throwaway listeners on this computer, with no emulator.

# What holds port $1 of this computer, TCP or UDP, on any address: "tcp 127.0.0.1:8791 by python3 (pid
# 4321)", or nothing when it is free. Whether it is free is asked of the kernel by binding the port as the
# test servers do (TCP with SO_REUSEADDR, as ThreadingHTTPServer, so that connections closing from an
# earlier run do not count; UDP without it); ss names the holder where it may see it.
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

# Sets PORT to a base at which every port PORT+offset, for each offset given, is free (see the top).
host_ports() {
    local base offset holder first=${HOST_PORTS_FIRST:-8790} tries=${HOST_PORTS_TRIES:-21}
    if [ -n "${WATCH_TEST_PORT:-}" ]; then
        for offset in "$@"; do
            holder=$(host_port_holder $((WATCH_TEST_PORT + offset)))
            if [ -n "$holder" ]; then
                echo "!! port $((WATCH_TEST_PORT + offset)) of this computer, which the check's test servers need" \
                    "(WATCH_TEST_PORT=$WATCH_TEST_PORT + $offset), is held: $holder. Stop that program, or set" \
                    "WATCH_TEST_PORT to another base, or leave it unset to have one picked." >&2
                return 1
            fi
        done
        PORT=$WATCH_TEST_PORT
        return 0
    fi
    for ((base = first; base < first + 10 * tries; base += 10)); do
        holder=""
        for offset in "$@"; do
            holder=$(host_port_holder $((base + offset)))
            [ -z "$holder" ] || break
        done
        if [ -z "$holder" ]; then
            PORT=$base
            [ "$base" = "$first" ] || echo "== the test servers take ports from $base: one from $first on was held" >&2
            return 0
        fi
        echo "== port held, trying the next base: $holder" >&2
    done
    echo "!! no free ports for the check's test servers from $first to $((first + 10 * tries - 1)); the last held: $holder" >&2
    return 1
}

# The self-test: throwaway listeners hold ports, and host_ports must name them, or pass them by.
host_ports_self_test() {
    local failures=0 base held_pid udp_pid out
    unset WATCH_TEST_PORT
    # A base well away from the checks' own, so that a check running beside this test is not disturbed,
    # and below the kernel's range of ports for outgoing connections (32768 up).
    HOST_PORTS_FIRST=$((20000 + RANDOM % 10000)) HOST_PORTS_TRIES=50 host_ports 0 1 3 || return 1
    base=$PORT
    hold() { python3 -I -c '
import socket, sys, time
kind = socket.SOCK_STREAM if sys.argv[1] == "tcp" else socket.SOCK_DGRAM
s = socket.socket(socket.AF_INET, kind)
s.bind(("127.0.0.1", int(sys.argv[2])))
if kind == socket.SOCK_STREAM:
    s.listen(1)
print("held", flush=True)
time.sleep(60)' "$1" "$2"; }
    exec 3< <(hold tcp $((base + 1)))
    held_pid=$!
    read -r _ <&3
    # WATCH_TEST_PORT given, its +1 held on 127.0.0.1 alone, as on 2026-11-18: stop, naming it.
    if out=$(WATCH_TEST_PORT=$base host_ports 0 1 2>&1); then
        echo "self-test: a held port $((base + 1)) passed" >&2
        failures=$((failures + 1))
    elif ! grep -q "port $((base + 1)) " <<<"$out" || ! grep -q "python3" <<<"$out"; then
        echo "self-test: the message names neither the port nor its program: $out" >&2
        failures=$((failures + 1))
    fi
    # No WATCH_TEST_PORT: another base, all free.
    if ! HOST_PORTS_FIRST=$base HOST_PORTS_TRIES=50 host_ports 0 1 2>/dev/null || [ "$PORT" = "$base" ]; then
        echo "self-test: no other base picked past the held port (PORT $PORT)" >&2
        failures=$((failures + 1))
    fi
    kill "$held_pid" 2>/dev/null || true
    exec 3<&-
    # A UDP port held is held too.
    exec 4< <(hold udp $((base + 3)))
    udp_pid=$!
    read -r _ <&4
    if WATCH_TEST_PORT=$base host_ports 0 1 3 2>/dev/null; then
        echo "self-test: a held UDP port $((base + 3)) passed" >&2
        failures=$((failures + 1))
    fi
    kill "$udp_pid" 2>/dev/null || true
    exec 4<&-
    # Free again, the given base is taken as it is.
    sleep 0.2
    if ! WATCH_TEST_PORT=$base host_ports 0 1 3 2>/dev/null || [ "$PORT" != "$base" ]; then
        echo "self-test: free ports $base were refused" >&2
        failures=$((failures + 1))
    fi
    if [ "$failures" -eq 0 ]; then
        echo "host ports: a port held, TCP or UDP, stops a check or is passed by"
    else
        echo "host ports: self-test failed" >&2
    fi
    [ "$failures" -eq 0 ]
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
    set -euo pipefail
    case "${1:-}" in
        --self-test) host_ports_self_test ;;
        *) echo "usage: . $0 and host_ports OFFSETS..., or $0 --self-test" >&2; exit 2 ;;
    esac
fi
