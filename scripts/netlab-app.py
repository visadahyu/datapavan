#!/usr/bin/env python3
# An app of the engine's network lab (core/net/tests/netlab.rs, ADR 0044, the proposal for decision 5): sends
# datagrams of SIZE bytes from SOURCE to an echo server at SERVER:PORT through a UDP socket of each path
# MTU discovery mode, unconnected and connected, two from each socket, and says for each what became of
# it, one line for each socket:
#
#   want connected: echoed 1472; echoed 1472
#   do unconnected: refused EMSGSIZE; refused EMSGSIZE
#
# What can become of a datagram: refused by the app's own kernel as it is sent, echoed whole (or
# garbled), lost (no echo within two seconds), or an error on the read that waits for the echo, as a
# connected default socket gets after an ICMP "fragmentation needed" or "packet too big".
#
# The modes are Linux's (IP_MTU_DISCOVER and IPV6_MTU_DISCOVER: dont, want, do, probe, interface,
# omit), and for IPv6 also a default socket with IPV6_DONTFRAG. nix, which the tests use, sets none of
# them on Linux, and the engine's workspace forbids unsafe code; Python's socket module takes the
# option numbers of <linux/in.h> and <linux/in6.h>.
#
#   netlab-app.py SOURCE SERVER PORT SIZE
import errno
import socket
import sys

IP_MTU_DISCOVER = 10
IPV6_MTU_DISCOVER = 23
IPV6_DONTFRAG = 62
MODES = {"dont": 0, "want": 1, "do": 2, "probe": 3, "interface": 4, "omit": 5}
WAIT = 2.0


def name(error):
    return errno.errorcode.get(error.errno, str(error.errno))


# What became of one datagram of `payload`, sent on `app`.
def outcome(app, payload, server, connected):
    try:
        if connected:
            app.send(payload)
        else:
            app.sendto(payload, server)
    except OSError as error:
        return "refused " + name(error)
    try:
        echo = app.recv(65535)
    except socket.timeout:
        return "lost"
    except OSError as error:
        return "recv " + name(error)
    return ("echoed %d" if echo == payload else "garbled %d") % len(echo)


def main():
    if len(sys.argv) != 5:
        sys.exit("usage: netlab-app.py SOURCE SERVER PORT SIZE")
    source, host, port, size = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4])
    v6 = ":" in host
    family, level, option = ((socket.AF_INET6, socket.IPPROTO_IPV6, IPV6_MTU_DISCOVER) if v6
                             else (socket.AF_INET, socket.IPPROTO_IP, IP_MTU_DISCOVER))
    settings = [(mode, (level, option, value)) for mode, value in MODES.items()]
    if v6:
        settings.append(("dontfrag", (socket.IPPROTO_IPV6, IPV6_DONTFRAG, 1)))
    server = (host, port)
    for mode, setting in settings:
        for connected in (False, True):
            app = socket.socket(family, socket.SOCK_DGRAM)
            app.bind((source, 0))
            app.setsockopt(*setting)
            app.settimeout(WAIT)
            if connected:
                app.connect(server)
            # Each datagram's bytes are its own, so that an echo of the other shows.
            results = [outcome(app, bytes([n]) * size, server, connected) for n in (1, 2)]
            print("%s %s: %s" % (mode, "connected" if connected else "unconnected", "; ".join(results)))
            app.close()


if __name__ == "__main__":
    main()
