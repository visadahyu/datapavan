# SPDX-License-Identifier: Apache-2.0
"""The DNS lab's censor (scripts/dnslab, W8): the one way to every server of the lab, a front per server, each
with a mode a check sets. Python's standard library only; nothing it relays is kept.

Fronts (the server behind each, on the lab's network, and the front's port from the base DNSLAB_PORT):
  relay +0, target-a +1, target-b +2, doh +3, dot +4 (DoT), portal +5 (HTTP), resolver +6 (the network's
  resolver, UDP and TCP; also on DNSLAB_RESOLVER_ADDR port 53), resolver-dot +7 (its DoT; also on
  DNSLAB_RESOLVER_ADDR port 853). Every front listens on DNSLAB_BIND.

Modes, per front:
  pass        relays both ways;
  drop        no answer at all: a new TCP connection's SYN goes unanswered (the front's listener is held full,
              so that the kernel drops the SYNs, which it counts), a connection already open goes silent both
              ways until the front passes again, and a UDP datagram is dropped: the client times out;
  reset       a TCP reset once the client's first data (a TLS ClientHello) arrives; a connection already open
              is reset at its next segment; UDP datagrams are dropped;
  reset-sni NAME
              the same, only for connections whose ClientHello names NAME; the others pass;
  block       the DoT fronts (dot, resolver-dot) only: port 853 blocked, by drop;
  inject      the network resolver's front only: each UDP query for an A record gets a forged answer
              (10.53.6.6, TTL 0) at once, then the query goes on to the resolver and its real answer follows,
              as an on-path injector does; TCP passes.

  python3 -I censor.py serve                    the censor itself
  python3 -I censor.py ctl set FRONT MODE [NAME] | modes | counts | reset-counts | fronts | ready
                                                | upstream FRONT ADDRESS
                                                talks to it over its control socket (in its container).

Counts per front: connections (TCP connections accepted), datagrams (UDP datagrams received), resets (TCP
connections it reset), dropped (TCP SYNs the kernel dropped at the held listener, retransmissions included, and
UDP datagrams it dropped), held (open connections it silenced), injected (forged answers sent).

Upstreams are reached by the services' names on the lab's network; on the host's network (compose.publish.yaml)
those names do not resolve, and scripts/dnslab.sh gives each front its server's address with `upstream`."""

import os
import selectors
import socket
import struct
import sys
import threading
import time

CONTROL = "/run/dnslab-censor.sock"
FORGED = "10.53.6.6"
HELD_FULL_BACKLOG = 0
BACKLOG = 128
UDP_IDLE = 60

# name, protocols, offset from the base port, upstream service, upstream port, port on the resolver's address
FRONTS = [
    ("relay", ("tcp",), 0, "relay", 443, None),
    ("target-a", ("tcp",), 1, "target-a", 443, None),
    ("target-b", ("tcp",), 2, "target-b", 443, None),
    ("doh", ("tcp",), 3, "doh", 443, None),
    ("dot", ("tcp",), 4, "dot", 853, None),
    ("portal", ("tcp",), 5, "portal", 80, None),
    ("resolver", ("udp", "tcp"), 6, "resolver", 53, 53),
    ("resolver-dot", ("tcp",), 7, "resolver-dot", 853, 853),
]
DOT_FRONTS = {"dot", "resolver-dot"}
COUNTS = ("connections", "datagrams", "resets", "dropped", "held", "injected")


def say(*words):
    print(*words, flush=True)


class Front:
    def __init__(self, name, protocols, upstream, upstream_port):
        self.name = name
        self.protocols = protocols
        self.upstream = upstream
        self.upstream_port = upstream_port
        self.mode = "pass"
        self.sni = None
        self.lock = threading.Lock()
        self.counts = dict.fromkeys(COUNTS, 0)
        self.listeners = []

    def count(self, what, n=1):
        with self.lock:
            self.counts[what] += n

    def silent(self):
        return self.mode in ("drop", "block")

    def resets(self, sni):
        return self.mode == "reset" or (self.mode == "reset-sni" and sni is not None and sni == self.sni)

    def address(self):
        return (self.upstream, self.upstream_port)


def linger_reset(sock):
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
    except OSError:
        pass
    sock.close()


def client_hello_sni(data):
    """The server name of a TLS ClientHello in its first record, lower case, or None."""
    try:
        if len(data) < 9 or data[0] != 22 or data[5] != 1:
            return None
        hello = data[9:5 + int.from_bytes(data[3:5], "big")]
        pos = 34
        pos += 1 + hello[pos]
        pos += 2 + int.from_bytes(hello[pos:pos + 2], "big")
        pos += 1 + hello[pos]
        end = min(len(hello), pos + 2 + int.from_bytes(hello[pos:pos + 2], "big"))
        pos += 2
        while pos + 4 <= end:
            kind, length = int.from_bytes(hello[pos:pos + 2], "big"), int.from_bytes(hello[pos + 2:pos + 4], "big")
            pos += 4
            if kind == 0:
                names, at = hello[pos:pos + length], 2
                while at + 3 <= len(names):
                    size = int.from_bytes(names[at + 1:at + 3], "big")
                    if names[at] == 0:
                        return names[at + 3:at + 3 + size].decode("ascii", "replace").lower().rstrip(".")
                    at += 3 + size
                return None
            pos += length
    except IndexError:
        return None
    return None


def first_data(client):
    """The client's first data: a whole TLS record when it starts one (the ClientHello), else what came."""
    client.settimeout(30)
    data = client.recv(65536)
    if data[:1] == b"\x16" and len(data) >= 5:
        want = 5 + int.from_bytes(data[3:5], "big")
        deadline = time.monotonic() + 3
        while len(data) < want and len(data) < 65536 and time.monotonic() < deadline:
            client.settimeout(max(0.05, deadline - time.monotonic()))
            try:
                more = client.recv(65536)
            except socket.timeout:
                break
            if not more:
                break
            data += more
    client.settimeout(None)
    return data


class Connection:
    def __init__(self, front, client):
        self.front = front
        self.client = client
        self.upstream = None
        self.sni = None
        self.lock = threading.Lock()
        self.closed = False
        self.ends = 0
        self.held = False

    def reset(self, why, counted=True):
        with self.lock:
            if self.closed:
                return
            self.closed = True
        if counted:
            self.front.count("resets")
        say(f"reset front={self.front.name} sni={self.sni or '-'} {why}")
        linger_reset(self.client)
        if self.upstream:
            linger_reset(self.upstream)

    def close(self):
        with self.lock:
            if self.closed:
                return
            self.closed = True
        for sock in (self.client, self.upstream):
            if sock:
                try:
                    sock.close()
                except OSError:
                    pass

    def end(self):
        with self.lock:
            self.ends += 1
            done = self.ends == 2
        if done:
            self.close()

    def hold(self):
        """Waits while the front is silent; False when the connection closed meanwhile."""
        while self.front.silent():
            if not self.held:
                self.held = True
                self.front.count("held")
            if self.closed:
                return False
            time.sleep(0.05)
        return not self.closed

    def pump(self, source, sink):
        while True:
            try:
                data = source.recv(65536)
            except OSError:
                break
            if not data:
                try:
                    sink.shutdown(socket.SHUT_WR)
                except OSError:
                    pass
                break
            if not self.hold():
                return
            if self.front.resets(self.sni):
                self.reset("on an open connection")
                return
            try:
                sink.sendall(data)
            except OSError:
                break
        self.end()

    def run(self):
        front = self.front
        try:
            data = first_data(self.client)
        except OSError:
            self.close()
            return
        if not data:
            self.close()
            return
        self.sni = client_hello_sni(data)
        if not self.hold():
            return
        if front.resets(self.sni):
            self.reset("at the first data")
            return
        try:
            self.upstream = socket.create_connection(front.address(), timeout=5)
            self.upstream.settimeout(None)
            self.upstream.sendall(data)
        except OSError as error:
            say(f"upstream front={front.name} {front.address()} failed: {error}")
            self.reset("the server did not answer", counted=False)
            return
        threading.Thread(target=self.pump, args=(self.upstream, self.client), daemon=True).start()
        self.pump(self.client, self.upstream)


class TcpListener:
    def __init__(self, front, address, port):
        self.front = front
        self.address = address
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((address, port))
        self.sock.listen(BACKLOG)
        self.sock.setblocking(False)
        self.fillers = []
        self.lock = threading.Lock()
        self.full = False
        self.drops_base = self.drops()

    def drops(self):
        """The SYNs the kernel dropped at this listener (SO_MEMINFO's drops)."""
        try:
            return struct.unpack("9I", self.sock.getsockopt(socket.SOL_SOCKET, 55, 36))[8]
        except OSError:
            return 0

    def fill(self):
        """Holds the listener full: backlog 0 and one connection of its own waiting, so new SYNs are dropped."""
        self.sock.listen(HELD_FULL_BACKLOG)
        filler = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        filler.setblocking(False)
        try:
            filler.connect(("127.0.0.1" if self.address == "0.0.0.0" else self.address, self.port))
        except BlockingIOError:
            pass
        # Waits for it to be queued (at once on the loopback), so that the next SYN finds the listener full.
        waiting = selectors.DefaultSelector()
        waiting.register(filler, selectors.EVENT_WRITE)
        waiting.select(timeout=1)
        waiting.close()
        self.fillers.append(filler)

    def release(self):
        self.sock.listen(BACKLOG)
        own = set()
        for filler in self.fillers:
            try:
                own.add(filler.getsockname())
            except OSError:
                pass
        while True:
            try:
                connection, peer = self.sock.accept()
            except (BlockingIOError, InterruptedError):
                break
            if peer in own:
                connection.close()
            else:
                self.accepted(connection)
        for filler in self.fillers:
            filler.close()
        self.fillers = []

    def apply(self):
        """Fills or releases the listener for the front's mode; the control command calls it, so that the mode
        holds for every SYN once `ctl set` has answered."""
        with self.lock:
            if self.front.silent() and not self.full:
                self.fill()
                self.full = True
            elif not self.front.silent() and self.full:
                self.release()
                self.full = False

    def accepted(self, connection):
        connection.setblocking(True)
        self.front.count("connections")
        threading.Thread(target=Connection(self.front, connection).run, daemon=True).start()

    def run(self):
        selector = selectors.DefaultSelector()
        selector.register(self.sock, selectors.EVENT_READ)
        while True:
            if self.full:
                time.sleep(0.1)
                continue
            if not selector.select(timeout=0.2):
                continue
            with self.lock:
                if self.full:
                    continue
                try:
                    connection, _ = self.sock.accept()
                except (BlockingIOError, InterruptedError):
                    continue
            self.accepted(connection)


class UdpListener:
    def __init__(self, front, address, port):
        self.front = front
        self.address = address
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((address, port))
        self.peers = {}
        self.lock = threading.Lock()

    def upstream_for(self, client):
        with self.lock:
            entry = self.peers.get(client)
            if entry:
                entry[1] = time.monotonic()
                return entry[0]
            upstream = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            upstream.connect(self.front.address())
            self.peers[client] = [upstream, time.monotonic()]
        threading.Thread(target=self.answers, args=(client, upstream), daemon=True).start()
        return upstream

    def forget(self):
        """Drops every client's way to the upstream, for a new upstream address."""
        with self.lock:
            entries, self.peers = list(self.peers.values()), {}
        for upstream, _ in entries:
            try:
                upstream.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

    def answers(self, client, upstream):
        upstream.settimeout(5)
        while True:
            try:
                data = upstream.recv(65535)
            except socket.timeout:
                with self.lock:
                    entry = self.peers.get(client)
                    if entry is None or entry[0] is not upstream or time.monotonic() - entry[1] > UDP_IDLE:
                        if entry is not None and entry[0] is upstream:
                            del self.peers[client]
                        upstream.close()
                        return
                continue
            except OSError:
                data = b""
            if not data:
                with self.lock:
                    if self.peers.get(client, [None])[0] is upstream:
                        del self.peers[client]
                upstream.close()
                return
            if self.front.mode in ("drop", "block", "reset", "reset-sni"):
                continue
            self.sock.sendto(data, client)

    def run(self):
        while True:
            data, client = self.sock.recvfrom(65535)
            front = self.front
            front.count("datagrams")
            if front.mode in ("drop", "block", "reset", "reset-sni"):
                front.count("dropped")
                continue
            if front.mode == "inject":
                forged = forge(data)
                if forged:
                    self.sock.sendto(forged, client)
                    front.count("injected")
            try:
                self.upstream_for(client).send(data)
            except OSError as error:
                say(f"upstream front={front.name} {front.address()} failed: {error}")


def forge(query):
    """A forged answer to an A query: 10.53.6.6, no EDNS, as injectors send; None for anything else."""
    try:
        if len(query) < 17 or query[2] & 0x80 or struct.unpack(">H", query[4:6])[0] != 1:
            return None
        pos = 12
        while query[pos]:
            if query[pos] & 0xC0:
                return None
            pos += 1 + query[pos]
        pos += 1
        qtype, qclass = struct.unpack(">HH", query[pos:pos + 4])
    except (IndexError, struct.error):
        return None
    if qtype != 1 or qclass != 1:
        return None
    flags = 0x8180 | (struct.unpack(">H", query[2:4])[0] & 0x0100)
    return (query[:2] + struct.pack(">HHHHH", flags, 1, 1, 0, 0) + query[12:pos + 4] +
            b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 0, 4) + socket.inet_aton(FORGED))


class Censor:
    def __init__(self):
        bind = os.environ.get("DNSLAB_BIND", "0.0.0.0")
        base = int(os.environ.get("DNSLAB_PORT", "10440"))
        resolver = os.environ.get("DNSLAB_RESOLVER_ADDR", "0.0.0.0")
        self.base = base
        self.fronts = {}
        self.listeners = []
        for name, protocols, offset, upstream, upstream_port, resolver_port in FRONTS:
            front = Front(name, protocols, upstream, upstream_port)
            self.fronts[name] = front
            places = [(bind, base + offset)]
            if resolver_port and resolver != "off":
                places.insert(0, (resolver, resolver_port))
            for address, port in places:
                for protocol in protocols:
                    kind = TcpListener if protocol == "tcp" else UdpListener
                    listener = kind(front, address, port)
                    front.listeners.append((protocol, address, port, listener))
                    self.listeners.append(listener)

    def command(self, words):
        if not words:
            return "error: no command"
        verb, args = words[0], words[1:]
        if verb == "ready":
            return "ready"
        if verb == "set":
            if len(args) < 2 or args[0] not in self.fronts:
                return f"error: set FRONT MODE [NAME]; fronts: {' '.join(self.fronts)}"
            front, mode = self.fronts[args[0]], args[1]
            if mode == "reset-sni":
                if len(args) != 3:
                    return "error: reset-sni needs a NAME"
            elif len(args) != 2:
                return f"error: {mode} takes no NAME"
            if mode not in ("pass", "drop", "reset", "reset-sni", "block", "inject"):
                return f"error: unknown mode {mode}"
            if mode == "block" and front.name not in DOT_FRONTS:
                return f"error: block is for the DoT fronts ({' '.join(sorted(DOT_FRONTS))})"
            if mode == "inject" and "udp" not in front.protocols:
                return "error: inject is for the network resolver's front (resolver)"
            front.sni = args[2].lower().rstrip(".") if mode == "reset-sni" else None
            front.mode = mode
            for protocol, _, _, listener in front.listeners:
                if protocol == "tcp":
                    listener.apply()
            say(f"mode front={front.name} {mode}{' ' + front.sni if front.sni else ''}")
            return f"ok {front.name} {mode}{' ' + front.sni if front.sni else ''}"
        if verb == "modes":
            return "\n".join(f"{f.name} {f.mode}{' ' + f.sni if f.sni else ''}" for f in self.fronts.values())
        if verb == "counts":
            lines = []
            for front in self.fronts.values():
                with front.lock:
                    counts = dict(front.counts)
                counts["dropped"] += sum(max(0, listener.drops() - listener.drops_base)
                                         for protocol, _, _, listener in front.listeners if protocol == "tcp")
                lines.append(front.name + " " + " ".join(f"{k}={counts[k]}" for k in COUNTS) +
                             f" mode={front.mode}{':' + front.sni if front.sni else ''}")
            return "\n".join(lines)
        if verb == "reset-counts":
            for front in self.fronts.values():
                with front.lock:
                    front.counts = dict.fromkeys(COUNTS, 0)
                for protocol, _, _, listener in front.listeners:
                    if protocol == "tcp":
                        listener.drops_base = listener.drops()
            return "ok counts reset"
        if verb == "fronts":
            return "\n".join(f"{f.name} {protocol} {address}:{port}" for f in self.fronts.values()
                             for protocol, address, port, _ in f.listeners)
        if verb == "upstream":
            if len(args) != 2 or args[0] not in self.fronts:
                return "error: upstream FRONT ADDRESS"
            front = self.fronts[args[0]]
            front.upstream = args[1]
            for protocol, _, _, listener in front.listeners:
                if protocol == "udp":
                    listener.forget()
            return f"ok {args[0]} upstream {args[1]}"
        if verb == "upstreams":
            return "\n".join(f"{f.name} {f.upstream}:{f.upstream_port}" for f in self.fronts.values())
        return f"error: unknown command {verb}"

    def control(self):
        try:
            os.unlink(CONTROL)
        except FileNotFoundError:
            pass
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(CONTROL)
        os.chmod(CONTROL, 0o600)
        server.listen(8)
        while True:
            connection, _ = server.accept()
            with connection:
                try:
                    line = connection.makefile("r").readline()
                    connection.sendall((self.command(line.split()) + "\n").encode())
                except OSError:
                    pass

    def serve(self):
        for listener in self.listeners:
            threading.Thread(target=listener.run, daemon=True).start()
        threading.Thread(target=self.control, daemon=True).start()
        for name, front in self.fronts.items():
            for protocol, address, port, _ in front.listeners:
                say(f"front {name} {protocol} {address}:{port} -> {front.upstream}:{front.upstream_port}")
        say("censor ready")
        while True:
            time.sleep(3600)


def ctl(words):
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        client.connect(CONTROL)
    except OSError as error:
        print(f"the censor does not answer: {error}", file=sys.stderr)
        return 1
    client.sendall((" ".join(words) + "\n").encode())
    answer = client.makefile("r").read()
    sys.stdout.write(answer)
    return 1 if answer.startswith("error") else 0


def main():
    if sys.argv[1:2] == ["serve"]:
        Censor().serve()
    elif sys.argv[1:2] == ["ctl"]:
        return ctl(sys.argv[2:])
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
