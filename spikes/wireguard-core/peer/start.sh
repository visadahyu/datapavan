#!/bin/sh
# Brings up wg0 with the kernel's WireGuard (the module must be loaded on the host: a container cannot load
# it), a new private key on every start, listening on 51820. The peer's addresses in the tunnel are
# 10.77.0.1 and fd77::1; 10.77.1.1 and fd77:1::1 are where the reflector answers from, outside the client's
# AllowedIPs. lab.sh adds the clients with `wg set`.
set -eu
if ! ip link add wg0 type wireguard; then
    echo "no kernel WireGuard here: load the wireguard module on the host (modprobe wireguard)" >&2
    exit 1
fi
mkdir -p /run/wglab
# The container's files outlive a stop: a ready mark from the last start must not count.
rm -f /run/wglab/ready /run/wglab/seen
umask 077
wg genkey >/run/wglab/private
wg set wg0 listen-port 51820 private-key /run/wglab/private
ip address add 10.77.0.1/24 dev wg0
ip address add 10.77.1.1/32 dev wg0
ip -6 address add fd77::1/64 dev wg0 nodad
ip -6 address add fd77:1::1/128 dev wg0 nodad
ip link set wg0 mtu 1420 up
echo "wglab peer ready"
exec python3 -I /opt/wglab/services.py
