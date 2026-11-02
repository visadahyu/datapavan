#!/usr/bin/env python3
"""Plain HTTP server for the traffic lab, on the computer at 127.0.0.1:8765 (10.0.2.2 in the emulator).

  GET /down/N      N bytes of incompressible data
  POST /up         reads the body and counts it
  GET /page/K/N    an HTML page with K images of N bytes each, for a browser

Every finished transfer is written to the log file given as the only argument, one line each:
WALL_TIME_S down|up BYTES PATH.
"""
import os
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = 8765
BLOCK = os.urandom(64 * 1024)
LOG = open(sys.argv[1], "a", buffering=1)


def log(kind, size, path):
    LOG.write(f"{time.time():.3f} {kind} {size} {path}\n")


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        parts = self.path.split("?")[0].strip("/").split("/")
        if parts[0] == "down" and len(parts) == 2 and parts[1].isdigit():
            self.send_body(int(parts[1]), "application/octet-stream")
        elif parts[0] == "page" and len(parts) == 3 and parts[1].isdigit() and parts[2].isdigit():
            images = "".join(f'<img src="/img/{parts[2]}/{i}">' for i in range(int(parts[1])))
            page = f"<!doctype html><title>Traffic lab</title>{images}".encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(page)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(page)
            log("down", len(page), self.path)
        elif parts[0] == "img" and len(parts) == 3 and parts[1].isdigit():
            self.send_body(int(parts[1]), "image/png")
        else:
            self.send_error(404)

    def do_POST(self):
        left = int(self.headers.get("Content-Length", "0"))
        size = left
        while left > 0:
            chunk = self.rfile.read(min(left, 64 * 1024))
            if not chunk:
                break
            left -= len(chunk)
        self.send_response(200 if left == 0 else 400)
        self.send_header("Content-Length", "0")
        self.end_headers()
        log("up", size - left, self.path)

    def send_body(self, size, kind):
        self.send_response(200)
        self.send_header("Content-Type", kind)
        self.send_header("Content-Length", str(size))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        left = size
        while left > 0:
            n = min(left, len(BLOCK))
            self.wfile.write(BLOCK[:n])
            left -= n
        log("down", size, self.path)


if __name__ == "__main__":
    ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
