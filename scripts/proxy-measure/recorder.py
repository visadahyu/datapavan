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
the request line, the Host header and the User-Agent; for a plain request to the proxy (absolute form, the proxy
record's forwarder), a sixth field, its field names in their order, comma-separated, never their values. Nothing else
of a request is kept, no credential header. Python's
standard library alone; it runs until it is stopped.

With a fifth argument `tunnel`, for the resolver unit's run on a network that requires its proxy (R-PLAN.md, "After
the audit"): a CONNECT to a public address on port 443 or 80, as the network part's resolver sends one (by the data
pack's address, never a name) and the engine sends a direct app's (the unit S2), is carried to that address from this
computer, both ways, and logged as `proxy-tunnel`, once when it opens and once when it closes, with the bytes each way;
a CONNECT to a name is answered as above. Nothing of what crosses the tunnel is read or kept but its length.

For the unit S2's rows (S2-PLAN.md, section 8, M8), two more modes, each in place of `tunnel`:
- `names-only`: a CONNECT to one of the addresses listed after the mode's word gets 403, as a proxy that takes names
  alone; with no address listed, every address does. A CONNECT to a public name on port 443 or 80 is carried to that
  name, looked up on this computer. Other addresses are carried as in `tunnel`, so that the resolver still answers;
- `password`: a CONNECT to one of the addresses listed (every one, with none listed) gets 407 with
  `Proxy-Authenticate: Basic`, as a proxy that asks for a password; others as in `tunnel`.
For the forwarder's rows (F-PLAN.md, section 9, "The emulator"), one more:
- `connect-443`: a CONNECT to any port but 443 gets 403, as squid's default (`http_access deny CONNECT !SSL_ports`),
  logged as `proxy-refused`; a CONNECT to 443 is carried as in `names-only`, so that the resolver still answers. A plain
  request in absolute form is answered as above, and its field names are logged.
The mode is the fifth argument, or, with a sixth, the first line of that file, read anew at each request, so that a
run changes it between its parts: the mode's word, then its addresses comma-separated.
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
    start_mode = sys.argv[5] if len(sys.argv) > 5 else ""
    mode_file = sys.argv[6] if len(sys.argv) > 6 else None

    def mode():
        """The mode's word and the addresses it names, from the mode file where one is given and holds a line."""
        line = start_mode
        if mode_file:
            try:
                with open(mode_file, encoding="ascii") as f:
                    line = f.readline().strip() or start_mode
            except OSError:
                pass
        word, _, listed = line.partition(" ")
        return word, {a for a in listed.replace(",", " ").split() if a}
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
        if role == "proxy" and lines[0].split(" ")[1:2] and lines[0].split(" ")[1].startswith("http://"):
            # A plain request in absolute form: its field names, never their values (F-PLAN.md, section 9).
            fields.append(",".join(line.partition(":")[0].strip() for line in lines[1:] if ":" in line) or "-")
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
                early = seen.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in seen else b""
                word, listed = mode()
                tunnels = word in ("tunnel", "names-only", "password", "connect-443")
                try:
                    if role == "proxy" and head.startswith("CONNECT ") and word == "connect-443" and not target.endswith(":443"):
                        record("proxy-refused", f"REFUSED {target} 403 {word}")
                        self.request.sendall(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                    elif role == "proxy" and head.startswith("CONNECT ") and word in ("names-only", "password") and refused(target, listed):
                        status = "403 Forbidden" if word == "names-only" else "407 Proxy Authentication Required"
                        record("proxy-refused", f"REFUSED {target} {status.split(' ')[0]} {word}")
                        extra = "Proxy-Authenticate: Basic realm=\"recorder\"\r\n" if word == "password" else ""
                        self.request.sendall(f"HTTP/1.1 {status}\r\n{extra}Content-Length: 0\r\nConnection: close\r\n\r\n".encode("ascii"))
                    elif role == "proxy" and head.startswith("CONNECT ") and tunnels and tunnel_to(target):
                        carry(self.request, tunnel_to(target), early)
                    elif role == "proxy" and head.startswith("CONNECT ") and word in ("names-only", "connect-443") and named(target):
                        carry(self.request, named(target), early)
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
        """The address and port of a CONNECT to a public address on port 443 or 80, or None for a name or another."""
        host, _, port = authority.rpartition(":")
        try:
            address = ipaddress.ip_address(host.strip("[]"))
        except ValueError:
            return None
        return (str(address), int(port)) if port in ("443", "80") and address.is_global else None

    def named(authority):
        """The name and port of a CONNECT to a name on port 443 or 80 that this computer resolves to public addresses
        alone, or None."""
        host, _, port = authority.rpartition(":")
        if port not in ("443", "80") or not host or host.startswith("["):
            return None
        try:
            ipaddress.ip_address(host)
            return None
        except ValueError:
            pass
        try:
            found = {info[4][0] for info in socket.getaddrinfo(host, int(port), socket.AF_INET, socket.SOCK_STREAM)}
        except OSError:
            return None
        return (host, int(port)) if found and all(ipaddress.ip_address(a).is_global for a in found) else None

    def refused(authority, listed):
        """Whether the mode refuses a CONNECT to this authority: an address it lists, or any address with none listed."""
        host, _, _ = authority.rpartition(":")
        try:
            address = ipaddress.ip_address(host.strip("[]"))
        except ValueError:
            return False
        return not listed or str(address) in listed

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
        # The bytes each way, counted and never kept: from the app (up) and to it (down).
        carried = {"up": len(early), "down": 0}

        def pipe(a, b, way):
            try:
                while True:
                    data = a.recv(16384)
                    if not data:
                        break
                    carried[way] += len(data)
                    b.sendall(data)
            except OSError:
                pass
            for s in (a, b):
                try:
                    s.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

        other = threading.Thread(target=pipe, args=(upstream, client, "down"), daemon=True)
        other.start()
        pipe(client, upstream, "up")
        other.join(30)
        upstream.close()
        record("proxy-tunnel", f"TUNNEL {where[0]}:{where[1]} closed up={carried['up']} down={carried['down']}")

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
