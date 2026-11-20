# SPDX-License-Identifier: Apache-2.0
"""The proxy lab's target (scripts/proxylab): what the lab's proxies carry the fixture to, on the lab's own network.

Port 80 answers any HTTP request with 204 and closes; ports 443 and 5222 echo whatever comes until the client
closes: a TLS hello sent through a proxy's tunnel comes back as it went, which tells the fixture its bytes passed.
Python's standard library alone.
"""
import socket
import socketserver
import threading


class Echo(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(30)
        try:
            while True:
                data = self.request.recv(65536)
                if not data:
                    return
                self.request.sendall(data)
        except OSError:
            return


class NoContent(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(30)
        seen = b""
        try:
            while b"\r\n\r\n" not in seen and len(seen) < 65536:
                data = self.request.recv(4096)
                if not data:
                    return
                seen += data
            self.request.sendall(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
        except OSError:
            return


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
    address_family = socket.AF_INET


def main():
    servers = [Server(("0.0.0.0", 80), NoContent), Server(("0.0.0.0", 443), Echo), Server(("0.0.0.0", 5222), Echo)]
    for server in servers[1:]:
        threading.Thread(target=server.serve_forever, daemon=True).start()
    servers[0].serve_forever()


if __name__ == "__main__":
    main()
