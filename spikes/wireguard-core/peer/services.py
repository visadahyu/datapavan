"""What answers behind the lab peer's WireGuard interface (W7's spike, ADR 0035; W7's own tests since part 1), on
its IPv4 and IPv6 address in the tunnel: a UDP echo on port 7; on port 8, an answer that names the address and
port the datagram came from, as this peer saw it; a reflector on port 9, which sends each datagram back from an
address outside the client's AllowedIPs for the peer (10.77.1.1, fd77:1::1), for the client to drop; DNS on port
53, which answers every A question with 10.77.0.1 and every AAAA with fd77::1; and HTTP on port 80, whose answer
names the client's address and this peer's host name. ICMP echo is the kernel's own. Python's standard library
only."""

import http.server
import socket
import threading

ADDRESSES = {socket.AF_INET: "10.77.0.1", socket.AF_INET6: "fd77::1"}
OUTSIDE = {socket.AF_INET: "10.77.1.1", socket.AF_INET6: "fd77:1::1"}


def bound(family, address, port):
    sock = socket.socket(family, socket.SOCK_DGRAM)
    if family == socket.AF_INET6:
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    sock.bind((address, port))
    return sock


def udp(sock, out):
    while True:
        data, sender = sock.recvfrom(65535)
        out.sendto(data, sender)


def whoami(sock):
    while True:
        _, sender = sock.recvfrom(65535)
        sock.sendto(f"{sender[0]} {sender[1]} {socket.gethostname()}\n".encode(), sender)


def dns(sock):
    """A, AAAA: one answer each, 300 s; anything else: no data. One question, as stub resolvers ask."""
    while True:
        query, sender = sock.recvfrom(512)
        if len(query) < 17 or query[2] & 0x80:
            continue
        end = 12
        while end < len(query) and query[end] != 0:
            end += query[end] + 1
        if end + 5 > len(query):
            continue
        question = query[12:end + 5]
        kind = int.from_bytes(query[end + 1:end + 3], "big")
        data = {1: socket.inet_pton(socket.AF_INET, ADDRESSES[socket.AF_INET]),
                28: socket.inet_pton(socket.AF_INET6, ADDRESSES[socket.AF_INET6])}.get(kind)
        header = query[:2] + b"\x81\x80\x00\x01" + (b"\x00\x01" if data else b"\x00\x00") + b"\x00\x00\x00\x00"
        answer = b""
        if data:
            answer = b"\xc0\x0c" + kind.to_bytes(2, "big") + b"\x00\x01" + (300).to_bytes(4, "big") + len(data).to_bytes(2, "big") + data
        sock.sendto(header + question + answer, sender)


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = f"datapavan wglab peer {socket.gethostname()} {self.client_address[0]}\n".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class Server6(http.server.ThreadingHTTPServer):
    address_family = socket.AF_INET6


def main():
    # Every socket is bound before the file that says so is written (lab.sh waits for it).
    threads = []
    for family in ADDRESSES:
        echo = bound(family, ADDRESSES[family], 7)
        reflector = bound(family, ADDRESSES[family], 9)
        threads.append(threading.Thread(target=udp, args=(echo, echo), daemon=True))
        threads.append(threading.Thread(target=whoami, args=(bound(family, ADDRESSES[family], 8),), daemon=True))
        threads.append(threading.Thread(target=dns, args=(bound(family, ADDRESSES[family], 53),), daemon=True))
        threads.append(threading.Thread(target=udp, args=(reflector, bound(family, OUTSIDE[family], 9)), daemon=True))
    servers = [http.server.ThreadingHTTPServer((ADDRESSES[socket.AF_INET], 80), Handler),
               Server6((ADDRESSES[socket.AF_INET6], 80), Handler)]
    threads += [threading.Thread(target=s.serve_forever, daemon=True) for s in servers]
    for thread in threads:
        thread.start()
    with open("/run/wglab/ready", "w") as ready:
        ready.write("ready\n")
    print("wglab services ready", flush=True)
    for thread in threads:
        thread.join()


main()
