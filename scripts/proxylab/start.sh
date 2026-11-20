#!/bin/sh
# What each service of the proxy lab runs (compose.yaml), by its first argument. Credentials and the MTProto
# secret come from the environment, made fresh by scripts/proxylab.sh for each run: synthetic, never a real one.
set -eu
case "${1:-}" in
    socks)
        # microsocks: SOCKS5 with RFC 1929's user name and password.
        exec microsocks -i 0.0.0.0 -p 1080 -u "$PROXYLAB_USER" -P "$PROXYLAB_PASSWORD"
        ;;
    http-auth | http-open)
        conf=/tmp/tinyproxy.conf
        {
            echo "Port 8888"
            echo "Listen 0.0.0.0"
            echo "Timeout 30"
            echo "MaxClients 32"
            echo "LogLevel Warning"
            echo "Allow 0.0.0.0/0"
            echo "ConnectPort 443"
            echo "DisableViaHeader Yes"
            [ "$1" = http-open ] || echo "BasicAuth $PROXYLAB_USER $PROXYLAB_PASSWORD"
        } >"$conf"
        exec tinyproxy -d -c "$conf"
        ;;
    mtg)
        # Fake TLS for the cover name in the secret; DNS over HTTPS pointed at nothing, and the lab's network has no
        # way out: mtg reaches no Telegram data centre and no cover site.
        exec mtg simple-run -n 127.0.0.1 -t 5s 0.0.0.0:3128 "$PROXYLAB_MTG_SECRET"
        ;;
    target)
        exec python3 -I /opt/proxylab/target.py
        ;;
    front)
        # Each "PORT=HOST:PORT" of PROXYLAB_FRONT: a fixed forward from the host's side to one service of the lab, in
        # this shell, which waits for them all.
        for forward in $(echo "$PROXYLAB_FRONT" | tr ',' ' '); do
            socat "TCP-LISTEN:${forward%%=*},fork,reuseaddr" "TCP:${forward#*=}" &
        done
        touch /tmp/ready
        wait
        ;;
    *)
        echo "unknown service: ${1:-}" >&2
        exit 2
        ;;
esac
