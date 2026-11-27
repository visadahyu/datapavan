# SPDX-License-Identifier: Apache-2.0
"""The proxy lab's target (scripts/proxylab): what the lab's proxies carry the fixture to, on the lab's own network.

Port 80 speaks HTTP/1.1 with keep-alive (the proxy record's forwarder): it answers every request with 204, as the
emulator's fixture expects, and its answer's fields say what the target got: X-Lab-Line the request line, X-Lab-Host
the Host field ("-" for none), X-Lab-Fields the field names in the order they came, X-Lab-Body the body's length and
SHA-256 (read by Content-Length, or chunked by hand). It closes after a request that asks so. Each request is also
kept, and port 8081 answers GET /seen with them, one a line (the request line, a tab, the Host field), from the host's
side only (scripts/proxylab/check.py), so that a request a proxy read out of another's body shows.

Ports 443 and 5222 echo whatever comes until the client closes: a TLS hello sent through a proxy's tunnel comes back
as it went, which tells the fixture its bytes passed. Python's standard library alone.
"""
import hashlib
import socket
import socketserver
import threading

MAX_HEAD = 65536
SEEN = []
SEEN_LOCK = threading.Lock()


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


class Reader:
    """Bytes of one connection, read as they are needed."""

    def __init__(self, sock):
        self.sock = sock
        self.data = b""

    def more(self):
        chunk = self.sock.recv(65536)
        if not chunk:
            raise EOFError
        self.data += chunk

    def until(self, mark, limit):
        while mark not in self.data:
            if len(self.data) > limit:
                raise ValueError("too long")
            self.more()
        line, self.data = self.data.split(mark, 1)
        return line

    def exactly(self, n):
        while len(self.data) < n:
            self.more()
        out, self.data = self.data[:n], self.data[n:]
        return out


def body_of(reader, fields):
    """The request's body by its framing: chunked (RFC 9112, 7.1, read by hand), Content-Length, or none."""
    coding = [v.strip().lower() for k, v in fields if k.lower() == "transfer-encoding"]
    if coding and coding[-1].split(",")[-1].strip() == "chunked":
        body = b""
        while True:
            size = int(reader.until(b"\r\n", 1024).split(b";")[0].strip(), 16)
            if size == 0:
                while reader.until(b"\r\n", MAX_HEAD):
                    pass
                return body
            body += reader.exactly(size)
            reader.exactly(2)
    lengths = [v.strip() for k, v in fields if k.lower() == "content-length"]
    return reader.exactly(int(lengths[0])) if lengths else b""


class Http(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(30)
        reader = Reader(self.request)
        try:
            while True:
                head = reader.until(b"\r\n\r\n", MAX_HEAD).decode("latin-1")
                line, *rest = head.split("\r\n")
                fields = [tuple(f.split(":", 1)) for f in rest if ":" in f]
                fields = [(k, v.strip()) for k, v in fields]
                host = next((v for k, v in fields if k.lower() == "host"), "-")
                with SEEN_LOCK:
                    SEEN.append(f"{line}\t{host}")
                if any(k.lower() == "expect" and v.lower() == "100-continue" for k, v in fields):
                    self.request.sendall(b"HTTP/1.1 100 Continue\r\n\r\n")
                body = body_of(reader, fields)
                tokens = [t.strip().lower() for k, v in fields if k.lower() == "connection" for t in v.split(",")]
                close = "close" in tokens or (line.endswith("HTTP/1.0") and "keep-alive" not in tokens)
                answer = (
                    "HTTP/1.1 204 No Content\r\n"
                    f"X-Lab-Line: {line}\r\n"
                    f"X-Lab-Host: {host}\r\n"
                    f"X-Lab-Fields: {','.join(k for k, _ in fields)}\r\n"
                    f"X-Lab-Body: {len(body)} {hashlib.sha256(body).hexdigest()}\r\n"
                    + ("Connection: close\r\n" if close else "")
                    + "\r\n"
                )
                self.request.sendall(answer.encode("latin-1"))
                if close:
                    return
        except (OSError, EOFError, ValueError):
            return


class Seen(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(10)
        try:
            Reader(self.request).until(b"\r\n\r\n", MAX_HEAD)
            with SEEN_LOCK:
                body = "".join(s + "\n" for s in SEEN).encode("latin-1")
            self.request.sendall(
                b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nConnection: close\r\nContent-Length: "
                + str(len(body)).encode()
                + b"\r\n\r\n"
                + body
            )
        except (OSError, EOFError, ValueError):
            return


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
    address_family = socket.AF_INET


def main():
    servers = [
        Server(("0.0.0.0", 80), Http),
        Server(("0.0.0.0", 8081), Seen),
        Server(("0.0.0.0", 443), Echo),
        Server(("0.0.0.0", 5222), Echo),
    ]
    for server in servers[1:]:
        threading.Thread(target=server.serve_forever, daemon=True).start()
    servers[0].serve_forever()


if __name__ == "__main__":
    main()
