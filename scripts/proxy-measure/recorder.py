# SPDX-License-Identifier: Apache-2.0
"""The proxy record's recorder (scripts/measure-proxy-settings.sh): what reaches a proxy that Android's settings name.

On this computer's loopback alone, which an emulator reaches as 10.0.2.2, three ports from the first argument:

- BASE, an HTTP proxy: a plain request in absolute form gets 204 (200 and a page for a path ending in /webview, so
  that a WebView finishes); a CONNECT gets "200 Connection established", then a TLS handshake with the self-signed
  certificate given (the third and fourth arguments), which the app refuses. A refused certificate is a failure the
  app's HTTP stack does not retry another way, where a closed tunnel made Android's OkHttp try again directly (the
  plan's audit, 2026-11-24); the server name the app asked for is logged as a line of its own;
- BASE + 1 serves /proxy.pac: PROXY 10.0.2.2:BASE for every host but 10.0.2.2, which goes DIRECT;
- BASE + 2, a direct target: 204 for anything (200 and a page for /webview).

Each request is one line of the log (the second argument), tab-separated: milliseconds since 1970, the port's role,
the request line, the Host header and the User-Agent. Nothing else of a request is kept, no credential header. Python's
standard library alone; it runs until it is stopped.

With a fifth argument `tunnel`, for the resolver unit's run on a network that requires its proxy (R-PLAN.md, "After
the audit"): a CONNECT to an address, as the network part's resolver sends one (by the data pack's address, never a
name), is carried to that address on port 443 from this computer, both ways, and logged as `proxy-tunnel`; a CONNECT
to a name is answered as above. Nothing of what crosses the tunnel is read or kept.
"""
import ipaddress
import socket
import socketserver
import ssl
import sys
import threading
import time

PAGE = b"<!doctype html><title>recorded</title>recorded"


def pac(base):
    return (
        "function FindProxyForURL(url, host) {\n"
        '  if (host == "10.0.2.2") return "DIRECT";\n'
        f'  return "PROXY 10.0.2.2:{base}";\n'
        "}\n"
    ).encode("ascii")


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
    address_family = socket.AF_INET


def main():
    base, path, cert, key = int(sys.argv[1]), sys.argv[2], sys.argv[3], sys.argv[4]
    tunnels = len(sys.argv) > 5 and sys.argv[5] == "tunnel"
    log = open(path, "a", buffering=1, encoding="utf-8")
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(cert, key)
    names = threading.local()

    def asked(sock, name, context):
        names.value = name or "-"

    tls.sni_callback = asked
    lock = threading.Lock()
    script = pac(base)

    def record(role, head):
        lines = head.split("\r\n")
        headers = {}
        for line in lines[1:]:
            name, _, value = line.partition(":")
            headers[name.strip().lower()] = value.strip()
        fields = [str(int(time.time() * 1000)), role, lines[0], headers.get("host", "-"), headers.get("user-agent", "-")]
        # A tab or a line break in what an app sent would split the line: they become spaces.
        with lock:
            log.write("\t".join(" ".join(f.split()) for f in fields) + "\n")

    def reply(sock, status, body=b"", kind="text/html"):
        head = f"HTTP/1.1 {status}\r\nConnection: close\r\nContent-Length: {len(body)}\r\n"
        if body:
            head += f"Content-Type: {kind}\r\n"
        sock.sendall(head.encode("ascii") + b"\r\n" + body)

    def handler(role):
        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                self.request.settimeout(15)
                seen = b""
                try:
                    while b"\r\n\r\n" not in seen and len(seen) < 65536:
                        data = self.request.recv(4096)
                        if not data:
                            break
                        seen += data
                except OSError:
                    pass
                head = seen.split(b"\r\n\r\n", 1)[0].decode("latin-1")
                if not head:
                    record(role, "(nothing)")
                    return
                record(role, head)
                target = head.split(" ")[1] if head.count(" ") >= 2 else ""
                try:
                    if role == "proxy" and head.startswith("CONNECT ") and tunnels and tunnel_to(target):
                        carry(self.request, tunnel_to(target), seen.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in seen else b"")
                    elif role == "proxy" and head.startswith("CONNECT "):
                        self.request.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
                        names.value = "-"
                        try:
                            tls.wrap_socket(self.request, server_side=True).close()
                            outcome = "accepted"
                        except (ssl.SSLError, OSError) as e:
                            outcome = type(e).__name__
                        record("proxy-tls", f"TLS {outcome} server-name {names.value}")
                    elif role == "pac":
                        if target.endswith("/proxy.pac"):
                            reply(self.request, "200 OK", script, "application/x-ns-proxy-autoconfig")
                        else:
                            reply(self.request, "404 Not Found")
                    elif target.endswith("/webview"):
                        reply(self.request, "200 OK", PAGE)
                    else:
                        reply(self.request, "204 No Content")
                except OSError:
                    pass

        return Handler

    def tunnel_to(authority):
        """The address and port of a CONNECT to an address on port 443, or None for a name or another port."""
        host, _, port = authority.rpartition(":")
        try:
            address = ipaddress.ip_address(host.strip("[]"))
        except ValueError:
            return None
        return (str(address), 443) if port == "443" and address.is_global else None

    def carry(client, where, early):
        try:
            upstream = socket.create_connection(where, timeout=10)
        except OSError as e:
            record("proxy-tunnel", f"TUNNEL {where[0]}:{where[1]} {type(e).__name__}")
            reply(client, "502 Bad Gateway")
            return
        record("proxy-tunnel", f"TUNNEL {where[0]}:{where[1]} open")
        client.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
        if early:
            upstream.sendall(early)
        client.settimeout(None)
        upstream.settimeout(None)

        def pipe(a, b):
            try:
                while True:
                    data = a.recv(16384)
                    if not data:
                        break
                    b.sendall(data)
            except OSError:
                pass
            for s in (a, b):
                try:
                    s.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

        other = threading.Thread(target=pipe, args=(upstream, client), daemon=True)
        other.start()
        pipe(client, upstream)
        other.join(30)
        upstream.close()

    servers = [
        Server(("127.0.0.1", base), handler("proxy")),
        Server(("127.0.0.1", base + 1), handler("pac")),
        Server(("127.0.0.1", base + 2), handler("direct")),
    ]
    for server in servers[1:]:
        threading.Thread(target=server.serve_forever, daemon=True).start()
    print("ready", flush=True)
    servers[0].serve_forever()


if __name__ == "__main__":
    main()
