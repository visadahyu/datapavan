#!/usr/bin/env python3
# The test server for Watch's end-to-end check (scripts/verify-network.sh), from the packet-engine
# spike: GET /bytes/N sends N bytes, POST /sink reads and drops the body, GET /ping answers four bytes.
# UDP on the next port echoes every datagram. The emulator reaches it at 10.0.2.2, a phone on the
# same Wi-Fi at the computer's address. Nothing it receives is kept.
#
# It holds every port the checks use for as long as it runs, so that no other program can take one
# after the checks found it free (review 4 of W5's first part, minor 2): TCP on the next port too, bound
# without listening, so that a connection there is refused, as the checks want, and no other program can
# listen there; and with --sentinel, TCP and UDP three ports on, where each connection and datagram is
# written as "tcp" or "udp" to FILE, for verify-chain.sh. Once every port is bound it prints "ready PORT";
# a port it cannot bind ends it at once, with the error.
#
#   python3 -I scripts/network-lab/server.py [port, default 8790] [--sentinel FILE]
import selectors
import socket
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

CHUNK = bytes(64 * 1024)


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    # Headers and body go out in separate writes; with Nagle on, the client's delayed ACK adds about
    # 40 ms to every kept-alive answer, which would hide the engines' own latency.
    disable_nagle_algorithm = True

    def log_message(self, *args):
        pass

    def do_GET(self):
        if self.path == "/ping":
            self._answer(b"pong")
        elif self.path.startswith("/bytes/"):
            try:
                size = int(self.path[len("/bytes/"):])
            except ValueError:
                return self.send_error(400)
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(size))
            self.end_headers()
            left = size
            while left > 0:
                part = CHUNK if left >= len(CHUNK) else CHUNK[:left]
                self.wfile.write(part)
                left -= len(part)
        else:
            self.send_error(404)

    def do_POST(self):
        if self.path != "/sink":
            return self.send_error(404)
        left = int(self.headers.get("Content-Length", "0"))
        while left > 0:
            got = self.rfile.read(min(left, 1 << 20))
            if not got:
                break
            left -= len(got)
        self._answer(b"ok")

    def _answer(self, body):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        if self.headers.get("Connection", "").lower() == "close":
            self.send_header("Connection", "close")
            self.close_connection = True
        self.end_headers()
        self.wfile.write(body)


def echo_udp(sock):
    while True:
        data, peer = sock.recvfrom(65535)
        sock.sendto(data, peer)


def sentinel(tcp, udp, out):
    """Writes "tcp" for each connection and "udp" for each datagram that reaches the sentinel's port."""
    selector = selectors.DefaultSelector()
    selector.register(tcp, selectors.EVENT_READ, "tcp")
    selector.register(udp, selectors.EVENT_READ, "udp")
    while True:
        for key, _ in selector.select():
            if key.data == "tcp":
                key.fileobj.accept()[0].close()
            else:
                key.fileobj.recvfrom(65535)
            print(key.data, file=out, flush=True)


def main(args):
    sentinel_log = None
    if "--sentinel" in args:
        at = args.index("--sentinel")
        sentinel_log = args[at + 1]
        del args[at:at + 2]
    port = int(args[0]) if args else 8790
    try:
        ThreadingHTTPServer.daemon_threads = True
        http = ThreadingHTTPServer(("0.0.0.0", port), Handler)
        echo = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        echo.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 << 20)
        echo.bind(("0.0.0.0", port + 1))
        # Bound and not listening: refused, and held from any other program that would listen.
        refused = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        refused.bind(("0.0.0.0", port + 1))
        if sentinel_log is not None:
            guard_tcp = socket.create_server(("0.0.0.0", port + 3))
            guard_udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            guard_udp.bind(("0.0.0.0", port + 3))
            # Made before "ready", so that the check can mark it at once.
            guard_log = open(sentinel_log, "a", encoding="utf-8")
    except OSError as error:
        print(f"the test server could not hold its ports from {port}: {error}", file=sys.stderr, flush=True)
        return 1
    threading.Thread(target=echo_udp, args=(echo,), daemon=True).start()
    if sentinel_log is not None:
        threading.Thread(target=sentinel, args=(guard_tcp, guard_udp, guard_log), daemon=True).start()
    print(f"ready {port}", flush=True)
    try:
        http.serve_forever()
    finally:
        refused.close()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
