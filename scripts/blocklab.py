#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""W8 part 3a's blocking lab (scripts/verify-blocking.sh, ADR 0053): what stands for the internet while the
emulator's fixture reaches a tracker's names, on this computer's loopback alone, which the emulator reaches as
10.0.2.2. It is the witness of what left the phone through the network part:

- a DNS server, which the network part's debug builds ask as the network's resolver (`dns-network-resolver`), and which
  knows three names under home.arpa: tracker.blocklab.home.arpa (the debug builds' blocked row),
  cloaked.blocklab.home.arpa (a CNAME to it, as CNAME cloaking does) and plain.blocklab.home.arpa (a control no row
  names), each A 10.0.2.2; AAAA and other types have no data, other names do not exist;
- a TCP echo server and a UDP echo server.

Every question, connection accepted, byte received and datagram is written to the event log, one line each:
`dns NAME TYPE`, `tcp-open ID`, `tcp-bytes ID N`, `tcp-close ID`, `udp N`. The check reads it to assert that a
blocked flow's lookup never came, that a blocked hello's connection carried no byte, and that a blocked QUIC hello
sent no datagram. Nothing here reaches beyond this computer.

    scripts/blocklab.py EVENT_LOG     prints "BLOCKLAB dns=P tcp=P udp=P" once it listens, then serves until killed
"""

import socketserver
import struct
import sys
import threading

NAMES = {
    "tracker.blocklab.home.arpa": None,
    "cloaked.blocklab.home.arpa": "tracker.blocklab.home.arpa",
    "plain.blocklab.home.arpa": None,
}
ADDRESS = bytes([10, 0, 2, 2])
LOCK = threading.Lock()


def log(line):
    with LOCK:
        with open(sys.argv[1], "a", encoding="utf-8") as out:
            out.write(line + "\n")


def read_name(message, at):
    labels = []
    while True:
        length = message[at]
        if length == 0:
            return ".".join(labels), at + 1
        labels.append(message[at + 1:at + 1 + length].decode("ascii", "replace"))
        at += 1 + length


def wire(name):
    out = b""
    for label in name.split("."):
        out += bytes([len(label)]) + label.encode("ascii")
    return out + b"\x00"


def answer(query):
    ident, flags, qd = struct.unpack("!HHH", query[:6])
    if qd != 1:
        return None
    name, at = read_name(query, 12)
    kind, _ = struct.unpack("!HH", query[at:at + 4])
    question = query[12:at + 4]
    lower = name.lower().rstrip(".")
    log(f"dns {lower} {kind}")
    records = b""
    count = 0
    rcode = 0
    if lower not in NAMES:
        rcode = 3
    else:
        owner = 0xC00C
        target = NAMES[lower]
        if target is not None:
            data = wire(target)
            records += struct.pack("!HHHIH", owner, 5, 1, 300, len(data)) + data
            count += 1
            # The A record's owner is the CNAME's target, which starts after the header, the question and the
            # CNAME record's fixed fields.
            owner = 0xC000 | (12 + len(question) + 12)
        if kind == 1:
            records += struct.pack("!HHHIH", owner, 1, 1, 300, 4) + ADDRESS
            count += 1
    header = struct.pack("!HHHHHH", ident, 0x8180 | (flags & 0x0100) | rcode, 1, count, 0, 0)
    return header + question + records


class Dns(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        reply = answer(data)
        if reply:
            sock.sendto(reply, self.client_address)


class Udp(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        log(f"udp {len(data)}")
        sock.sendto(data, self.client_address)


class Tcp(socketserver.BaseRequestHandler):
    serial = 0

    def handle(self):
        with LOCK:
            Tcp.serial += 1
            ident = Tcp.serial
        log(f"tcp-open {ident}")
        self.request.settimeout(10)
        try:
            while True:
                data = self.request.recv(65536)
                if not data:
                    break
                log(f"tcp-bytes {ident} {len(data)}")
                self.request.sendall(data)
        except OSError:
            pass
        log(f"tcp-close {ident}")


class ThreadedUdp(socketserver.ThreadingMixIn, socketserver.UDPServer):
    daemon_threads = True


class ThreadedTcp(socketserver.ThreadingMixIn, socketserver.TCPServer):
    daemon_threads = True
    allow_reuse_address = True


def main():
    if len(sys.argv) != 2:
        print(__doc__, file=sys.stderr)
        sys.exit(2)
    open(sys.argv[1], "w", encoding="utf-8").close()
    servers = [ThreadedUdp(("127.0.0.1", 0), Dns), ThreadedTcp(("127.0.0.1", 0), Tcp), ThreadedUdp(("127.0.0.1", 0), Udp)]
    for server in servers:
        threading.Thread(target=server.serve_forever, daemon=True).start()
    ports = [s.server_address[1] for s in servers]
    print(f"BLOCKLAB dns={ports[0]} tcp={ports[1]} udp={ports[2]}", flush=True)
    threading.Event().wait()


if __name__ == "__main__":
    main()
