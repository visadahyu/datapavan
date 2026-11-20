# SPDX-License-Identifier: Apache-2.0
"""A backend DNS responder of the DNS lab (scripts/dnslab, W8), one per way, each with its own answer, so that a
check can tell which way answered. On UDP and TCP port 53:

- probe.dnslab.test A: the address given with --probe (10.53.1.1 for the ODoH target of odoh-rs, 10.53.2.2 for
  odoh-server-go's, 10.53.3.3 for the plain DoH server, 10.53.4.4 for the DoT server, 10.53.5.5 for the
  network's resolver: docs in scripts/dnslab.sh);
- name-N.dnslab.test A (any decimal N): 10.53.0.(N mod 256), for latency runs without caches;
- each --extra NAME=ADDRESS (the network's resolver: printer.home.arpa=192.168.1.50), and its zone;
- every other type of those names: no data (NOERROR, the zone's SOA in the authority section); every other name:
  NXDOMAIN. TTL 0 everywhere, so that no cache keeps an answer between two steps of a check.

EDNS(0): an OPT is echoed when the query has one (payload 1232, the DO bit copied, BADVERS for a version above
0); when the query carries a padding option (RFC 7830, code 12), the answer is padded to a multiple of 468 bytes
(RFC 8467, block-length padding). A client subnet option (code 8) is never echoed. One line per query on stdout:
the way's name, the transport, the name, the type, whether the query had a client subnet option or padding, its
length and the answer. Python's standard library only; nothing it receives is kept."""

import argparse
import ipaddress
import socket
import struct
import sys
import threading

TYPES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 41: "OPT",
         43: "DS", 46: "RRSIG", 48: "DNSKEY", 64: "SVCB", 65: "HTTPS", 255: "ANY"}
RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED", 16: "BADVERS"}
PADDING_BLOCK = 468
EDNS_PAYLOAD = 1232
TCP_IDLE = 30


class Query:
    """A parsed query: what the answer needs and what the log says."""

    def __init__(self, data):
        if len(data) < 12:
            raise ValueError("short")
        self.id, self.flags, qd, an, ns, ar = struct.unpack(">HHHHHH", data[:12])
        if self.flags & 0x8000:
            raise ValueError("a response")
        self.opcode = (self.flags >> 11) & 0xF
        self.qd = qd
        self.edns = None  # (payload, version, do) when there is an OPT
        self.ecs = False
        self.padding = False
        self.name = ""
        self.qtype = 0
        self.qclass = 0
        self.question = b""
        if qd != 1:
            return
        pos, labels = 12, []
        while True:
            if pos >= len(data):
                raise ValueError("cut name")
            length = data[pos]
            if length == 0:
                pos += 1
                break
            if length & 0xC0:
                raise ValueError("compressed question")
            labels.append(data[pos + 1:pos + 1 + length].decode("ascii", "replace"))
            pos += 1 + length
        if pos + 4 > len(data):
            raise ValueError("cut question")
        self.qtype, self.qclass = struct.unpack(">HH", data[pos:pos + 4])
        self.question = data[12:pos + 4]
        self.name = ".".join(labels).lower()
        pos += 4
        for index in range(an + ns + ar):
            pos = skip_name(data, pos)
            if pos + 10 > len(data):
                raise ValueError("cut record")
            rtype, rclass, ttl, rdlen = struct.unpack(">HHIH", data[pos:pos + 10])
            rdata = data[pos + 10:pos + 10 + rdlen]
            pos += 10 + rdlen
            if index >= an + ns and rtype == 41:
                self.edns = (rclass, (ttl >> 16) & 0xFF, bool(ttl & 0x8000))
                opt = 0
                while opt + 4 <= len(rdata):
                    code, olen = struct.unpack(">HH", rdata[opt:opt + 4])
                    self.ecs |= code == 8
                    self.padding |= code == 12
                    opt += 4 + olen


def skip_name(data, pos):
    while True:
        if pos >= len(data):
            raise ValueError("cut name")
        length = data[pos]
        if length == 0:
            return pos + 1
        if length & 0xC0 == 0xC0:
            return pos + 2
        pos += 1 + length


def encode_name(name):
    return b"".join(bytes([len(label)]) + label.encode() for label in name.split(".") if label) + b"\0"


class Zone:
    def __init__(self, probe, extras):
        self.records = {"probe.dnslab.test": probe}
        self.records.update(extras)
        self.zones = sorted({"dnslab.test"} | {".".join(name.split(".")[-2:]) for name in extras},
                            key=len, reverse=True)

    def zone_of(self, name):
        for zone in self.zones:
            if name == zone or name.endswith("." + zone):
                return zone
        return None

    def address(self, name):
        if name in self.records:
            return self.records[name]
        first, _, rest = name.partition(".")
        if rest == "dnslab.test" and first.startswith("name-") and first[5:].isdigit():
            return f"10.53.0.{int(first[5:]) % 256}"
        return None

    def exists(self, name):
        return self.address(name) is not None or name in self.zones


def soa(zone):
    rdata = encode_name("ns." + zone) + encode_name("hostmaster." + zone) + struct.pack(">IIIII", 1, 3600, 600,
                                                                                       86400, 0)
    return encode_name(zone) + struct.pack(">HHIH", 6, 1, 0, len(rdata)) + rdata


def answer(query, zone, limit):
    """The answer's bytes and a word for the log."""
    rcode, answers, authority, said = 0, [], [], "-"
    if query.qd != 1:
        rcode = 1
    elif query.opcode != 0:
        rcode = 4
    elif query.edns and query.edns[1] > 0:
        rcode = 16
    elif query.qclass != 1:
        rcode = 5
    else:
        address = zone.address(query.name)
        if address and query.qtype in (1, 255):
            answers.append(b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 0, 4) + socket.inet_aton(address))
            said = address
        elif query.qtype == 6 and query.name in zone.zones:
            answers.append(soa(query.name)[len(encode_name(query.name)):])
            answers[-1] = b"\xc0\x0c" + answers[-1]
            said = "SOA"
        elif zone.exists(query.name):
            said = "nodata"
        else:
            rcode, said = 3, "nxdomain"
        if not answers and zone.zone_of(query.name):
            authority.append(soa(zone.zone_of(query.name)))
    flags = 0x8000 | (query.flags & 0x7900) | 0x0080 | (rcode & 0xF)
    question = query.question if query.qd == 1 else b""

    def build(answers, authority, extra_flags=0):
        body = question + b"".join(answers) + b"".join(authority)
        records = b""
        if query.edns is not None:
            ttl = ((rcode >> 4) << 24) | (0x8000 if query.edns[2] else 0)
            options = b""
            base = 12 + len(body) + 11
            if query.padding:
                pad = (PADDING_BLOCK - (base + 4) % PADDING_BLOCK) % PADDING_BLOCK
                options = struct.pack(">HH", 12, pad) + b"\0" * pad
            records = b"\0" + struct.pack(">HHIH", 41, EDNS_PAYLOAD, ttl, len(options)) + options
        header = struct.pack(">HHHHHH", query.id, flags | extra_flags, 1 if question else 0, len(answers),
                             len(authority), 1 if records else 0)
        return header + body + records

    data = build(answers, authority)
    if limit and len(data) > limit:
        data = build([], [], 0x0200)
        said += ",truncated"
    return data, f"{RCODES.get(rcode, rcode)} {said}"


def log(service, proto, query, size, said):
    kind = TYPES.get(query.qtype, f"TYPE{query.qtype}")
    print(f"query service={service} proto={proto} name={query.name or '-'} type={kind} "
          f"ecs={'yes' if query.ecs else 'no'} padding={'yes' if query.padding else 'no'} length={size} "
          f"answer={said.replace(' ', ':')}", flush=True)


def handle(data, service, proto, zone, limit_of):
    try:
        query = Query(data)
    except (ValueError, struct.error, UnicodeError):
        if len(data) >= 12 and not data[2] & 0x80:
            print(f"query service={service} proto={proto} malformed length={len(data)}", flush=True)
            return data[:2] + struct.pack(">HHHHH", 0x8081, 0, 0, 0, 0)
        return None
    reply, said = answer(query, zone, limit_of(query))
    log(service, proto, query, len(data), said)
    return reply


def serve_udp(sock, service, zone):
    def limit(query):
        return 512 if query.edns is None else max(512, min(query.edns[0], EDNS_PAYLOAD))
    while True:
        data, sender = sock.recvfrom(65535)
        reply = handle(data, service, "udp", zone, limit)
        if reply:
            sock.sendto(reply, sender)


def serve_tcp_connection(connection, service, zone):
    with connection:
        connection.settimeout(TCP_IDLE)
        stream = connection.makefile("rb")
        try:
            while True:
                head = stream.read(2)
                if len(head) < 2:
                    return
                data = stream.read(struct.unpack(">H", head)[0])
                reply = handle(data, service, "tcp", zone, lambda query: 0)
                if reply is None:
                    return
                connection.sendall(struct.pack(">H", len(reply)) + reply)
        except OSError:
            return


def serve_tcp(server, service, zone):
    while True:
        connection, _ = server.accept()
        threading.Thread(target=serve_tcp_connection, args=(connection, service, zone), daemon=True).start()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--name", required=True, help="the way's name, for the log")
    parser.add_argument("--probe", required=True, help="probe.dnslab.test's address from this way")
    parser.add_argument("--extra", action="append", default=[], help="NAME=ADDRESS, answered too")
    parser.add_argument("--port", type=int, default=53)
    args = parser.parse_args()
    ipaddress.IPv4Address(args.probe)
    extras = {}
    for item in args.extra:
        name, _, address = item.partition("=")
        ipaddress.IPv4Address(address)
        extras[name.lower().rstrip(".")] = address
    zone = Zone(args.probe, extras)
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.bind(("0.0.0.0", args.port))
    tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    tcp.bind(("0.0.0.0", args.port))
    tcp.listen(64)
    threads = [threading.Thread(target=serve_udp, args=(udp, args.name, zone), daemon=True),
               threading.Thread(target=serve_tcp, args=(tcp, args.name, zone), daemon=True)]
    for thread in threads:
        thread.start()
    print(f"ready service={args.name} probe={args.probe} port={args.port}", flush=True)
    for thread in threads:
        thread.join()


if __name__ == "__main__":
    sys.exit(main())
