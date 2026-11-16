#!/usr/bin/env python3
# The engine's network lab (ADR 0044, decision 6): inside a fresh user and network namespace, made by
# `unshare --user --map-root-user --net`, builds the network the engine sees on Android and runs one
# test with the tunnel as its standard input.
#
# - tun0 holds the tunnel's common addresses (10.1.10.1/32), as Watch's tunnel does; the fake peer
#   (10.1.10.2) and the tunnel's DNS address (10.1.10.3) are routed into it.
# - The "internet" is 198.51.100.9 on the loopback (a documentation address, RFC 5737), and
#   198.51.100.10 beside it: a second server, or a stranger to the apps, for the UDP mapping's tests.
# - Test apps bind 10.1.10.1, and a rule sends what they send into tun0, as Android sends an app's
#   traffic into the VPN. The engine's own sockets are unbound and take the ordinary routes, as
#   protected sockets do on Android. The rule comes before the local table, so that an app's packets to
#   an address of the namespace still pass through the tunnel; only packets from the tunnel's address
#   to itself stay local.
# - Packets the engine writes come from addresses that are local in the namespace, so reverse-path
#   filtering is off and tun0 accepts local sources.
# - Only GID 0 exists in the namespace, so it may open ICMP sockets. With NETLAB_PING_GROUPS=none the
#   namespace keeps its default range instead, which allows no group, as a kernel that refuses such
#   sockets: Linux takes no empty range from a user namespace that maps one group.
# - 203.0.113.0/24 (RFC 5737) is routed into tun1, which no one reads: a server there never answers,
#   as one behind a firewall that drops packets.
# - Through IPv6 the same, where the machine has IPv6: tun0 holds the tunnel's common IPv6 address
#   (a /128), and the "internet" is 2001:db8::9 (RFC 3849) on the loopback. Where it has none, the lab
#   says so, sets NETLAB_IPV6=absent for the test, and goes on with IPv4: the IPv6 tests then fail.
# - A narrow network (ADR 0044, decision 5 as amended): a server at 198.51.100.20 and 2001:db8:1::20 on
#   "far", one end of a veth pair whose other end, "near", is in the same namespace. What the
#   namespace itself sends there takes table 101, whose routes go out of "near", a link of 1,280 bytes,
#   from the "internet" addresses; packets from the apps still go into tun0 first, by the rule before
#   it, and packets that come in on "far" are delivered there, by the local table after it. So the
#   engine's sockets meet a first hop of 1,280 (IP_MTU says so, also for IPv6), their datagrams leave
#   "near" as fragments, and the server gets them whole; and an app of the namespace's own addresses
#   meets that network as an app meets its link without Watch. A permanent neighbour entry spares the
#   neighbour discovery; "far" takes packets from addresses of the namespace's own.
#
# - A tunnel set up again (ADR 0044, unit 12b): a test that hands the running engine a new tunnel needs a
#   second tun device whose descriptor it owns, as Android makes a new interface for each tunnel it
#   establishes. Rust makes a tun device only with unsafe ioctls, and a descriptor inherited by its number
#   becomes an owned one only with unsafe code too, so the test opens /dev/net/tun itself and runs this
#   script inside the namespace with that file as its standard input: --tunnel names the device (TUNSETIFF
#   acts on the open file, which the test shares), makes it non-blocking and brings it up as tun0 is.
#   --move then does what Android's in-place update of a VPN network does (AOSP's Vpn.establish): the
#   tunnel's addresses and the routes into it go to the new device, then the old one's addresses go and
#   it goes down, as Android resets the old interface.
#
#   netlab-enter.py -- PROGRAM [ARGUMENTS...]
#   netlab-enter.py --tunnel NAME      (inside the namespace, the new file at standard input)
#   netlab-enter.py --move FROM TO     (inside the namespace)
#
# Everything here is undone when the namespace ends with the test. It changes nothing outside it.
import fcntl
import json
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
OTHER4 = "198.51.100.10"
SILENT4 = "203.0.113.0/24"
TUN6 = "fd00:1:fd00:1:fd00:1:fd00:1"
FAKE6 = "fd00:1:fd00:1:fd00:1:fd00:2"
DNS6 = "fd00:1:fd00:1:fd00:1:fd00:3"
SERVER6 = "2001:db8::9"
APPS_TABLE = "100"
NARROW4 = "198.51.100.20"
NARROW6 = "2001:db8:1::20"
NARROW_TABLE = "101"
NARROW_MTU = "1280"


def ip(*arguments):
    subprocess.run(["ip", *arguments], check=True)


def sysctl(name, value):
    with open("/proc/sys/" + name.replace(".", "/"), "w") as setting:
        setting.write(value)


# The tunnel's IPv6 side, built as its IPv4 side is. The addresses skip duplicate address detection,
# which would hold them back for a moment.
def ipv6():
    ip("-6", "addr", "add", SERVER6 + "/128", "dev", "lo")
    ip("-6", "addr", "add", TUN6 + "/128", "dev", "tun0", "nodad")
    for address in (FAKE6, DNS6):
        ip("-6", "route", "add", address + "/128", "dev", "tun0")
    ip("-6", "route", "add", "default", "dev", "tun0", "table", APPS_TABLE)
    ip("-6", "rule", "add", "pref", "50", "from", TUN6, "to", TUN6, "lookup", "local")
    ip("-6", "rule", "add", "pref", "100", "from", TUN6, "lookup", APPS_TABLE)
    ip("-6", "rule", "add", "pref", "200", "lookup", "local")
    ip("-6", "rule", "del", "pref", "0")


# The narrow network's IPv4 side; its IPv6 side follows in ipv6_narrow, where the machine has IPv6.
def narrow():
    ip("link", "add", "near", "type", "veth", "peer", "name", "far")
    # The link's own MTU too, not only its route's: a socket that takes the link's MTU (probe,
    # interface, omit) then meets the same narrow network as one that takes the path's.
    ip("link", "set", "near", "mtu", NARROW_MTU)
    for side in ("near", "far"):
        ip("link", "set", side, "up")
    ip("addr", "add", NARROW4 + "/32", "dev", "far")
    ip("neigh", "add", NARROW4, "lladdr", far_address(), "dev", "near", "nud", "permanent")
    ip("route", "add", NARROW4 + "/32", "dev", "near", "mtu", NARROW_MTU, "src", SERVER4,
       "table", NARROW_TABLE)
    ip("rule", "add", "pref", "150", "iif", "lo", "to", NARROW4, "lookup", NARROW_TABLE)
    sysctl("net.ipv4.conf.far.rp_filter", "0")
    sysctl("net.ipv4.conf.far.accept_local", "1")


def ipv6_narrow():
    ip("-6", "addr", "add", NARROW6 + "/128", "dev", "far", "nodad")
    ip("-6", "neigh", "add", NARROW6, "lladdr", far_address(), "dev", "near", "nud", "permanent")
    ip("-6", "route", "add", NARROW6 + "/128", "dev", "near", "mtu", NARROW_MTU, "src", SERVER6,
       "table", NARROW_TABLE)
    ip("-6", "rule", "add", "pref", "150", "iif", "lo", "to", NARROW6, "lookup", NARROW_TABLE)


# /sys in the namespace is the host's, so the veth's address is read from ip itself.
def far_address():
    shown = subprocess.run(["ip", "-j", "link", "show", "far"], check=True, capture_output=True,
                           text=True)
    return json.loads(shown.stdout)[0]["address"]


def tun(name):
    fd = os.open("/dev/net/tun", os.O_RDWR)
    name_tun(fd, name)
    return fd


def name_tun(fd, name):
    fcntl.ioctl(fd, TUNSETIFF, struct.pack("16sH", name.encode(), IFF_TUN | IFF_NO_PI))


# The tun device NAME on the file at standard input, which the test opened and keeps: up, non-blocking,
# and taking local sources, as tun0 does. Its addresses and routes come with --move.
def second_tunnel(name):
    name_tun(0, name)
    os.set_blocking(0, False)
    ip("link", "set", name, "mtu", "1500", "up")
    sysctl(f"net.ipv4.conf.{name}.rp_filter", "0")
    sysctl(f"net.ipv4.conf.{name}.accept_local", "1")


# Android's in-place update of the VPN network, from the tunnel on OLD to the one on NEW: the new
# interface gets the tunnel's addresses, the network's routes move to it, and only then is the old one
# reset, its addresses gone and the interface down. IPv6 moves too where the lab has it.
def move(old, new):
    ipv6_here = os.environ.get("NETLAB_IPV6") != "absent"
    ip("addr", "add", TUN4 + "/32", "dev", new)
    for address in (FAKE4, DNS4):
        ip("route", "replace", address + "/32", "dev", new)
    ip("route", "replace", "default", "dev", new, "table", APPS_TABLE)
    if ipv6_here:
        ip("-6", "addr", "add", TUN6 + "/128", "dev", new, "nodad")
        for address in (FAKE6, DNS6):
            ip("-6", "route", "replace", address + "/128", "dev", new)
        ip("-6", "route", "replace", "default", "dev", new, "table", APPS_TABLE)
    ip("addr", "del", TUN4 + "/32", "dev", old)
    if ipv6_here:
        ip("-6", "addr", "del", TUN6 + "/128", "dev", old)
    ip("link", "set", old, "down")


def main():
    if len(sys.argv) == 3 and sys.argv[1] == "--tunnel":
        return second_tunnel(sys.argv[2])
    if len(sys.argv) == 4 and sys.argv[1] == "--move":
        return move(sys.argv[2], sys.argv[3])
    if len(sys.argv) < 3 or sys.argv[1] != "--":
        sys.exit("usage: netlab-enter.py -- PROGRAM [ARGUMENTS...] | --tunnel NAME | --move FROM TO")
    program = sys.argv[2:]

    ip("link", "set", "lo", "up")
    ip("addr", "add", SERVER4 + "/32", "dev", "lo")
    ip("addr", "add", OTHER4 + "/32", "dev", "lo")

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
    narrow()
    try:
        ipv6()
        ipv6_narrow()
    except (subprocess.CalledProcessError, OSError) as error:
        print(f"netlab: no IPv6 here ({error}); the IPv6 tests will fail", file=sys.stderr)
        os.environ["NETLAB_IPV6"] = "absent"

    # Its descriptor stays open in the test, unread, for as long as the namespace lives.
    silent = tun("tun1")
    os.set_inheritable(silent, True)
    ip("link", "set", "tun1", "up")
    ip("route", "add", SILENT4, "dev", "tun1")

    sysctl("net.ipv4.conf.all.rp_filter", "0")
    sysctl("net.ipv4.conf.tun0.rp_filter", "0")
    sysctl("net.ipv4.conf.tun0.accept_local", "1")
    if os.environ.get("NETLAB_PING_GROUPS") != "none":
        sysctl("net.ipv4.ping_group_range", "0 0")

    os.dup2(tunnel, 0)
    os.close(tunnel)
    os.set_blocking(0, False)
    os.execv(program[0], program)


if __name__ == "__main__":
    main()
