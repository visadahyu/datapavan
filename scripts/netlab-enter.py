#!/usr/bin/env python3
# The engine's network lab (ADR 0044, decision 6): inside a fresh user and network namespace, made by
# `unshare --user --map-root-user --net`, builds the network the engine sees on Android and runs one
# test with the tunnel as its standard input.
#
# - tun0 holds the tunnel's common addresses (10.1.10.1/32), as Watch's tunnel does; the fake peer
#   (10.1.10.2) and the tunnel's DNS address (10.1.10.3) are routed into it.
# - The "internet" is 198.51.100.9 on the loopback (a documentation address, RFC 5737).
# - Test apps bind 10.1.10.1, and a rule sends what they send into tun0, as Android sends an app's
#   traffic into the VPN. The engine's own sockets are unbound and take the ordinary routes, as
#   protected sockets do on Android. The rule comes before the local table, so that an app's packets to
#   an address of the namespace still pass through the tunnel; only packets from the tunnel's address
#   to itself stay local.
# - Packets the engine writes come from addresses that are local in the namespace, so reverse-path
#   filtering is off and tun0 accepts local sources.
# - Only GID 0 exists in the namespace, so it may open ICMP sockets.
#
#   netlab-enter.py -- PROGRAM [ARGUMENTS...]
#
# Everything here is undone when the namespace ends with the test. It changes nothing outside it.
import fcntl
import os
import struct
import subprocess
import sys

TUNSETIFF = 0x400454CA
IFF_TUN = 0x0001
IFF_NO_PI = 0x1000

TUN4 = "10.1.10.1"
FAKE4 = "10.1.10.2"
DNS4 = "10.1.10.3"
SERVER4 = "198.51.100.9"
APPS_TABLE = "100"


def ip(*arguments):
    subprocess.run(["ip", *arguments], check=True)


def sysctl(name, value):
    with open("/proc/sys/" + name.replace(".", "/"), "w") as setting:
        setting.write(value)


def tun(name):
    fd = os.open("/dev/net/tun", os.O_RDWR)
    fcntl.ioctl(fd, TUNSETIFF, struct.pack("16sH", name.encode(), IFF_TUN | IFF_NO_PI))
    return fd


def main():
    if len(sys.argv) < 3 or sys.argv[1] != "--":
        sys.exit("usage: netlab-enter.py -- PROGRAM [ARGUMENTS...]")
    program = sys.argv[2:]

    ip("link", "set", "lo", "up")
    ip("addr", "add", SERVER4 + "/32", "dev", "lo")

    tunnel = tun("tun0")
    ip("link", "set", "tun0", "mtu", "1500", "up")
    ip("addr", "add", TUN4 + "/32", "dev", "tun0")
    for address in (FAKE4, DNS4):
        ip("route", "add", address + "/32", "dev", "tun0")
    ip("route", "add", "default", "dev", "tun0", "table", APPS_TABLE)
    # Between the tunnel's own address and itself, packets stay local, as on Android: an app that
    # connects to the engine's listener directly, and the listener's answers to it, use the loopback.
    ip("rule", "add", "pref", "50", "from", TUN4, "to", TUN4, "lookup", "local")
    ip("rule", "add", "pref", "100", "from", TUN4, "lookup", APPS_TABLE)
    ip("rule", "add", "pref", "200", "lookup", "local")
    ip("rule", "del", "pref", "0")

    sysctl("net.ipv4.conf.all.rp_filter", "0")
    sysctl("net.ipv4.conf.tun0.rp_filter", "0")
    sysctl("net.ipv4.conf.tun0.accept_local", "1")
    sysctl("net.ipv4.ping_group_range", "0 0")

    os.dup2(tunnel, 0)
    os.close(tunnel)
    os.set_blocking(0, False)
    os.execv(program[0], program)


if __name__ == "__main__":
    main()
