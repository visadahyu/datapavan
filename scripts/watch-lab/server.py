#!/usr/bin/env python3
# The test server for Watch's end-to-end check (scripts/verify-watch.sh), from the packet-engine
# spike: GET /bytes/N sends N bytes, POST /sink reads and drops the body, GET /ping answers four bytes.
# UDP on the next port echoes every datagram. The emulator reaches it at 10.0.2.2, a phone on the
# same Wi-Fi at the computer's address. Nothing it receives is kept.
#
#   python3 -I scripts/watch-lab/server.py [port, default 8790]
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


def echo_udp(port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 << 20)
    sock.bind(("0.0.0.0", port))
    while True:
        data, peer = sock.recvfrom(65535)
        sock.sendto(data, peer)


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8790
    threading.Thread(target=echo_udp, args=(port + 1,), daemon=True).start()
    ThreadingHTTPServer.daemon_threads = True
    ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()
