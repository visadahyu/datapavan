#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# The lab's server for lab/run.sh (ADR 0048): the only destination of the gaps probe's traffic, which the
# emulator reaches at 10.0.2.2, its name for this computer's loopback. It listens on loopback only, so that
# no other device on the network can reach it and land in a run's log. HTTP on 8792 and 8793 (the second
# origin of the webview behaviour) answers a few fixed paths with fixed bodies; UDP on 8796 takes datagrams
# and answers none. Each request is one line of the log file it is given: the time, the protocol, the port,
# the path or the datagram's size, and the client's User-Agent. Nothing a client sends is kept beyond that.
#
#   python3 -I lab/server.py LOG
import socket
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HTTP_PORTS = (8792, 8793)
UDP_PORT = 8796
SECOND = "http://10.0.2.2:8793"
GIF = bytes.fromhex("47494638396101000100800000000000ffffff21f90401000000002c00000000010001000002024401003b")
ANSWERS = {
    "/gaps/download": (bytes(4096), "application/octet-stream"),
    "/gaps/tab": (b"<!doctype html><title>gaps tab</title><p>gaps lab tab</p>", "text/html"),
    "/gaps/page": (
        ('<!doctype html><title>gaps page</title><p>gaps lab page</p>'
         f'<img src="{SECOND}/gaps/image">'
         f'<script>fetch("{SECOND}/gaps/fetch", {{mode: "no-cors"}})</script>').encode(),
        "text/html",
    ),
    "/gaps/image": (GIF, "image/gif"),
    "/gaps/fetch": (b"ok", "text/plain"),
    "/ping": (b"pong", "text/plain"),
}
LOCK = threading.Lock()


def log(out, *fields):
    with LOCK:
        out.write(" ".join([f"{time.time():.3f}"] + [str(f) for f in fields]) + "\n")
        out.flush()


def handler(out):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.0"

        def log_message(self, *args):
            pass

        def do_GET(self):
            agent = (self.headers.get("User-Agent") or "-").replace(" ", "_")
            log(out, "http", self.server.server_address[1], self.path, agent)
            body, kind = ANSWERS.get(self.path, (None, None))
            if body is None:
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header("Content-Type", kind)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

    return Handler


def udp(out):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", UDP_PORT))
    while True:
        data, _ = sock.recvfrom(65535)
        log(out, "udp", UDP_PORT, len(data), "-")


if __name__ == "__main__":
    out = open(sys.argv[1], "a", encoding="utf-8")
    ThreadingHTTPServer.daemon_threads = True
    ThreadingHTTPServer.allow_reuse_address = True
    # short-lived opens 100 connections in ten seconds: a backlog of 5, the default, drops SYNs on a busy host.
    ThreadingHTTPServer.request_queue_size = 256
    servers = [ThreadingHTTPServer(("127.0.0.1", port), handler(out)) for port in HTTP_PORTS]
    for server in servers[1:]:
        threading.Thread(target=server.serve_forever, daemon=True).start()
    threading.Thread(target=udp, args=(out,), daemon=True).start()
    log(out, "ready", *HTTP_PORTS, UDP_PORT, "-")
    servers[0].serve_forever()
