#!/usr/bin/env bash
# W8 part 2a's proxy lab (ADR 0052): an app's own proxies in the Compose project datapavan-proxylab
# (scripts/proxylab/compose.yaml), on a network with no way out, published on the host's loopback alone. Each run
# makes a synthetic user, password and MTProto secret of its own: never a real one.
#
#   scripts/proxylab.sh            the lab's own check from the host (scripts/proxylab/check.py): each proxy takes
#                                  the fixture's handshakes and carries them to the lab's target, a wrong password is
#                                  refused, mtg accepts a fake-TLS hello made with the lab's secret and refuses
#                                  another; then the project stops (stop, not down: nothing restarts it)
#   scripts/proxylab.sh --serve    only start it, and print its settings, one KEY=value a line, for the emulator check
#                                  (scripts/verify-proxies.sh), which stops it when it is done
#
#   PROXYLAB_NO_BUILD=1   the image is built already (CI builds it with its cache): start it as it is
#
# Ports: the first of 18080, 18090, ... 18190 where six in a row are free (PROXYLAB_PORT to choose).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LAB="$ROOT/scripts/proxylab"
compose=(docker compose -f "$LAB/compose.yaml")
MODE="${1:-check}"

missing=""
if ! command -v docker >/dev/null 2>&1; then
    missing="no Docker"
elif ! docker info >/dev/null 2>&1; then
    missing="Docker does not answer"
fi
[ -z "$missing" ] || { echo "$missing" >&2; exit 1; }

# Six free ports in a row on the host, from $PROXYLAB_PORT or the first base that has them.
free_base() {
    python3 -I - "${PROXYLAB_PORT:-}" <<'PY'
import socket, sys
def free(port):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind(("127.0.0.1", port))
        return True
    except OSError:
        return False
    finally:
        s.close()
bases = [int(sys.argv[1])] if sys.argv[1] else range(18080, 18200, 10)
for base in bases:
    if all(free(base + i) for i in range(6)):
        print(base)
        break
else:
    sys.exit("no six free ports in a row from %s" % sys.argv[1] if sys.argv[1] else "no six free ports from 18080")
PY
}

base=$(free_base)
export PROXYLAB_PORT=$base PROXYLAB_PORT_HTTP=$((base + 1)) PROXYLAB_PORT_OPEN=$((base + 2)) \
    PROXYLAB_PORT_MTG=$((base + 3)) PROXYLAB_PORT_ECHO=$((base + 4)) PROXYLAB_PORT_TLS=$((base + 5))
# The user name is random too, so that a check can look for it (the fix round's R-m7): "lab" is in too many strings.
PROXYLAB_USER="user-$(python3 -I -c 'import secrets; print(secrets.token_hex(8))')"
PROXYLAB_PASSWORD="lab-$(python3 -I -c 'import secrets; print(secrets.token_hex(12))')"
# ee, a 16-byte key, and the cover name in hex: a fake-TLS secret for a name of the lab's own.
PROXYLAB_MTG_SECRET="ee$(python3 -I -c 'import secrets; print(secrets.token_hex(16) + "cover.proxylab.test".encode().hex())')"
export PROXYLAB_USER PROXYLAB_PASSWORD PROXYLAB_MTG_SECRET

finish() {
    local status=$?
    if [ "$status" != 0 ]; then
        mkdir -p "$ROOT/build/proxylab"
        "${compose[@]}" logs --no-color --timestamps >"$ROOT/build/proxylab/lab.log" 2>&1 || true
        echo "the lab's logs: build/proxylab/lab.log" >&2
    fi
    if [ "$MODE" != --serve ] || [ "$status" != 0 ]; then
        "${compose[@]}" stop >/dev/null 2>&1 || true
    fi
}
trap finish EXIT
if [ "${PROXYLAB_NO_BUILD:-}" = 1 ]; then
    "${compose[@]}" up -d --no-build --pull never >/dev/null
else
    "${compose[@]}" up -d --build --quiet-pull >/dev/null 2>&1 || "${compose[@]}" up -d --build
fi
for _ in $(seq 30); do
    "${compose[@]}" exec -T front test -e /tmp/ready 2>/dev/null && break
    sleep 1
done
"${compose[@]}" exec -T front test -e /tmp/ready || { echo "the lab's front did not come up" >&2; exit 1; }
# The lab's own network has no way out: nothing the lab carries can reach the internet.
[ "$(docker network inspect datapavan-proxylab_lab --format '{{.Internal}}')" = true ] ||
    { echo "the lab's network is not internal" >&2; exit 1; }
# The proxies take a moment after their containers start.
for _ in $(seq 30); do
    python3 -I -c "import socket,sys; [socket.create_connection(('127.0.0.1', p), 1).close() for p in sys.argv[1:]]" \
        "$PROXYLAB_PORT" "$PROXYLAB_PORT_HTTP" "$PROXYLAB_PORT_OPEN" "$PROXYLAB_PORT_MTG" 2>/dev/null && break
    sleep 1
done

if [ "$MODE" = --serve ]; then
    printf '%s\n' "PROXYLAB_PORT=$PROXYLAB_PORT" "PROXYLAB_PORT_HTTP=$PROXYLAB_PORT_HTTP" "PROXYLAB_PORT_OPEN=$PROXYLAB_PORT_OPEN" \
        "PROXYLAB_PORT_MTG=$PROXYLAB_PORT_MTG" "PROXYLAB_PORT_ECHO=$PROXYLAB_PORT_ECHO" "PROXYLAB_PORT_TLS=$PROXYLAB_PORT_TLS" \
        "PROXYLAB_USER=$PROXYLAB_USER" "PROXYLAB_PASSWORD=$PROXYLAB_PASSWORD" "PROXYLAB_MTG_SECRET=$PROXYLAB_MTG_SECRET"
    exit 0
fi

versions="$("${compose[@]}" exec -T target cat /etc/proxylab-mtg); $("${compose[@]}" exec -T target sh -c 'grep -E "^(microsocks|tinyproxy|socat|python3) " /etc/proxylab-packages | tr "\n" " "')"
echo "== proxy lab: $versions"
python3 -I "$LAB/check.py" 127.0.0.1 "$PROXYLAB_PORT" "$PROXYLAB_PORT_HTTP" "$PROXYLAB_PORT_OPEN" "$PROXYLAB_PORT_MTG" \
    "$PROXYLAB_USER" "$PROXYLAB_PASSWORD" "$PROXYLAB_MTG_SECRET"
echo "== the proxy lab checked"
