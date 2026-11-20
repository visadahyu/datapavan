# SPDX-License-Identifier: Apache-2.0
"""The DNS lab's own DNS client (scripts/dnslab.sh), independent of the app: plain DNS on UDP and TCP, DoT, a
bare TLS handshake, and the bytes of a query and its answer for curl's DoH. Python's standard library only; run
with python3 -I.

  dnsclient.py udp ADDR PORT NAME [--answers K]      the first K answers within the timeout (an injector's
                                                     forged answer and the real one)
  dnsclient.py tcp ADDR PORT NAME [--again-after FILE]
  dnsclient.py dot ADDR PORT NAME --sni NAME --ca CA [--again-after FILE]
                                                     with --again-after, asks again on the same connection once
                                                     FILE exists
  dnsclient.py tls ADDR PORT --sni NAME [--ca CA]    a TLS handshake alone (without --ca, no verification)
  dnsclient.py build NAME > query.bin                a query, for curl --data-binary
  dnsclient.py parse answer.bin                      an answer, read
Every query command takes --type A|AAAA|..., --pad (an EDNS padding option, RFC 7830, as RFC 8467's clients
pad: to a multiple of 128 bytes), --ecs (a client subnet option, 192.0.2.0/24), --no-edns and --timeout S.

One line per answer: `answer rcode=NOERROR a=10.53.3.3 length=468 padding=yes`, or for a failure one of
`failed connect-timeout|timeout|reset|eof|refused|certificate|...` and exit code 1."""

import argparse
import os
import socket
import ssl
import struct
import sys
import time

TYPES = {"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "PTR": 12, "MX": 15, "TXT": 16, "AAAA": 28, "SRV": 33,
         "SVCB": 64, "HTTPS": 65, "ANY": 255}
RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED", 16: "BADVERS"}


class Failed(Exception):
    pass


def query(args, qid=None):
    qid = int(time.monotonic_ns() & 0xFFFF) if qid is None else qid
    qtype = TYPES.get(args.type.upper()) or int(args.type)
    question = b"".join(bytes([len(p)]) + p.encode() for p in args.name.split(".") if p) + b"\0" + \
        struct.pack(">HH", qtype, 1)
    header = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0 if args.no_edns else 1)
    if args.no_edns:
        return header + question
    options = b""
    if args.ecs:
        options += struct.pack(">HHHBB", 8, 7, 1, 24, 0) + bytes([192, 0, 2])
    if args.pad:
        base = len(header) + len(question) + 11 + len(options) + 4
        pad = (-base) % 128
        options += struct.pack(">HH", 12, pad) + b"\0" * pad
    return header + question + b"\0" + struct.pack(">HHIH", 41, 1232, 0, len(options)) + options


def read(message):
    """rcode, A addresses, and whether the answer carries a padding option."""
    rcode = message[3] & 0xF
    qd, an, ns, ar = struct.unpack(">HHHH", message[4:12])
    pos = 12

    def skip(pos):
        while True:
            length = message[pos]
            if length == 0:
                return pos + 1
            if length & 0xC0 == 0xC0:
                return pos + 2
            pos += 1 + length
    for _ in range(qd):
        pos = skip(pos) + 4
    addresses, padding = [], False
    for index in range(an + ns + ar):
        pos = skip(pos)
        rtype, rclass, ttl, rdlen = struct.unpack(">HHIH", message[pos:pos + 10])
        rdata = message[pos + 10:pos + 10 + rdlen]
        if index < an and rtype == 1 and rdlen == 4:
            addresses.append(socket.inet_ntoa(rdata))
        if rtype == 41:
            rcode |= (ttl >> 24) << 4
            opt = 0
            while opt + 4 <= len(rdata):
                code, olen = struct.unpack(">HH", rdata[opt:opt + 4])
                padding |= code == 12
                opt += 4 + olen
        pos += 10 + rdlen
    return rcode, addresses, padding


def line(message):
    rcode, addresses, padding = read(message)
    return (f"answer rcode={RCODES.get(rcode, rcode)} a={','.join(addresses) or '-'} length={len(message)} "
            f"padding={'yes' if padding else 'no'}")


def failure(error):
    if isinstance(error, ConnectionResetError):
        return "reset"
    if isinstance(error, ConnectionRefusedError):
        return "refused"
    if isinstance(error, ssl.SSLCertVerificationError):
        return "certificate"
    if isinstance(error, (ssl.SSLEOFError, ssl.SSLZeroReturnError, ConnectionAbortedError, BrokenPipeError)):
        return "eof"
    if isinstance(error, (socket.timeout, TimeoutError)):
        return "timeout"
    if isinstance(error, ssl.SSLError) and "EOF" in str(error):
        return "eof"
    return f"{type(error).__name__}:{error}".replace(" ", "_")


def connect(args):
    try:
        return socket.create_connection((args.addr, args.port), timeout=args.timeout)
    except (socket.timeout, TimeoutError):
        raise Failed("connect-timeout")


def exchange_stream(sock, data):
    sock.sendall(struct.pack(">H", len(data)) + data)
    head = b""
    while len(head) < 2:
        more = sock.recv(2 - len(head))
        if not more:
            raise Failed("eof")
        head += more
    size, body = struct.unpack(">H", head)[0], b""
    while len(body) < size:
        more = sock.recv(size - len(body))
        if not more:
            raise Failed("eof")
        body += more
    return body


def tls(args, sock):
    if args.ca:
        context = ssl.create_default_context(cafile=args.ca)
    else:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    return context.wrap_socket(sock, server_hostname=args.sni)


def run(args):
    if args.command == "build":
        sys.stdout.buffer.write(query(args))
        return 0
    if args.command == "parse":
        with open(args.file, "rb") as file:
            data = file.read()
        if len(data) < 12:
            raise Failed(f"not-an-answer:{len(data)}-bytes")
        print(line(data))
        return 0
    if args.command == "udp":
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(args.timeout)
        sock.sendto(query(args), (args.addr, args.port))
        got = 0
        deadline = time.monotonic() + args.timeout
        while got < args.answers:
            sock.settimeout(max(0.01, deadline - time.monotonic()))
            try:
                data, _ = sock.recvfrom(65535)
            except (socket.timeout, TimeoutError):
                if got:
                    return 0
                raise Failed("timeout")
            print(line(data), flush=True)
            got += 1
        return 0
    sock = connect(args)
    sock.settimeout(args.timeout)
    if args.command != "tcp":
        sock = tls(args, sock)
    if args.command == "tls":
        certificate = sock.getpeercert(binary_form=True)
        print(f"handshake ok version={sock.version()} certificate-bytes={len(certificate or b'')}")
        sock.close()
        return 0
    print(line(exchange_stream(sock, query(args))), flush=True)
    if args.again_after:
        # The same connection again, once FILE exists: what an open connection meets after a change.
        deadline = time.monotonic() + 30
        while not os.path.exists(args.again_after) and time.monotonic() < deadline:
            time.sleep(0.05)
        print(line(exchange_stream(sock, query(args))), flush=True)
    return 0


def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("udp", "tcp", "dot", "tls", "build", "parse"):
        p = sub.add_parser(name)
        if name in ("udp", "tcp", "dot", "tls"):
            p.add_argument("addr")
            p.add_argument("port", type=int)
        if name == "parse":
            p.add_argument("file")
            continue
        if name != "tls":
            p.add_argument("name")
            p.add_argument("--type", default="A")
            p.add_argument("--pad", action="store_true")
            p.add_argument("--ecs", action="store_true")
            p.add_argument("--no-edns", action="store_true")
        p.add_argument("--timeout", type=float, default=4)
        if name == "udp":
            p.add_argument("--answers", type=int, default=1)
        if name in ("tcp", "dot"):
            p.add_argument("--again-after", metavar="FILE")
        if name in ("dot", "tls"):
            p.add_argument("--sni", required=True)
            p.add_argument("--ca", required=name == "dot")
    args = parser.parse_args()
    try:
        return run(args)
    except Failed as error:
        print(f"failed {error}")
    except (OSError, ValueError, struct.error, IndexError) as error:
        print(f"failed {failure(error)}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
