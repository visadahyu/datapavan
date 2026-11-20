#!/bin/sh
# Brings up wg0 with the reference implementation WGLAB_IMPL names: `kernel` (the default), the Linux kernel's
# WireGuard, whose module must be loaded on the host (a container cannot load it), or `go`, wireguard-go on the
# container's TUN device. A new private key on every start, listening on 51820. The peer's addresses in the tunnel
# are 10.77.0.1 and fd77::1; 10.77.1.1 and fd77:1::1 are where the reflector answers from, outside the client's
# AllowedIPs. scripts/wglab.sh adds the clients with `wg set`, which reaches either implementation.
set -eu
mkdir -p /run/wglab
# The container's files outlive a stop: a ready mark from the last start must not count.
rm -f /run/wglab/ready /run/wglab/seen
case "${WGLAB_IMPL:-kernel}" in
    kernel)
        if ! ip link add wg0 type wireguard; then
            echo "no kernel WireGuard here: load the wireguard module on the host (modprobe wireguard)" >&2
            exit 1
        fi
        ;;
    go)
        # The control socket of the last start outlives a stop, as the files above do, and would answer nothing.
        rm -f /var/run/wireguard/wg0.sock
        # In the foreground, as a child of this shell and then of services.py: it ends with the container.
        wireguard-go -f wg0 &
        for _ in $(seq 50); do
            [ -S /var/run/wireguard/wg0.sock ] && break
            sleep 0.1
        done
        if [ ! -S /var/run/wireguard/wg0.sock ]; then
            echo "wireguard-go did not open its control socket (is /dev/net/tun given to the container?)" >&2
            exit 1
        fi
        ;;
    *)
        echo "WGLAB_IMPL is ${WGLAB_IMPL}: kernel or go" >&2
        exit 1
        ;;
esac
umask 077
wg genkey >/run/wglab/private
wg set wg0 listen-port 51820 private-key /run/wglab/private
ip address add 10.77.0.1/24 dev wg0
ip address add 10.77.1.1/32 dev wg0
ip -6 address add fd77::1/64 dev wg0 nodad
ip -6 address add fd77:1::1/128 dev wg0 nodad
ip link set wg0 mtu 1420 up
echo "wglab peer ready: ${WGLAB_IMPL:-kernel}"
exec python3 -I /opt/wglab/services.py
