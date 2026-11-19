"""What answers behind the lab peer's WireGuard interface (W7's spike, ADR 0035), on its IPv4 and IPv6
address in the tunnel: a UDP echo on port 7; a reflector on port 9, which sends each datagram back from an
address outside the client's AllowedIPs for the peer (10.77.1.1, fd77:1::1), for the client to drop; and
HTTP on port 80. ICMP echo is the kernel's own. Python's standard library only."""

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


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"datapavan wglab peer\n"
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
