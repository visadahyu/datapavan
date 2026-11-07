#!/usr/bin/env python3
# A minimal SOCKS5 proxy for the spike's chaining check (RESTRICTED-REGIONS.md): no authentication,
# CONNECT only, as a circumvention tool in proxy mode offers it. It prints one line per connection so
# the check can see that the engine's traffic went through it. Nothing is kept.
#
# It listens on the computer's loopback only, so nothing on the network can use it; the emulator
# reaches the computer's loopback as 10.0.2.2.
#
#   python3 -I tools/socks5.py [port, default 1080]
import socket
import struct
import sys
import threading


def pipe(src, dst):
    try:
        while True:
            data = src.recv(65536)
            if not data:
                break
            dst.sendall(data)
    except OSError:
        pass
    finally:
        try:
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            pass


def read(sock, n):
    data = b""
    while len(data) < n:
        part = sock.recv(n - len(data))
        if not part:
            raise ConnectionError("closed")
        data += part
    return data


def handle(client, peer):
    try:
        version, methods = read(client, 2)
        read(client, methods)
        if version != 5:
            return
        client.sendall(b"\x05\x00")
        version, command, _, kind = read(client, 4)
        if kind == 1:
            host = socket.inet_ntop(socket.AF_INET, read(client, 4))
        elif kind == 4:
            host = socket.inet_ntop(socket.AF_INET6, read(client, 16))
        elif kind == 3:
            host = read(client, read(client, 1)[0]).decode()
        else:
            return
        (port,) = struct.unpack("!H", read(client, 2))
        # 10.0.2.2 is the emulator's name for this computer's loopback, which the proxy reaches directly.
        if host == "10.0.2.2":
            host = "127.0.0.1"
        if command != 1:
            client.sendall(b"\x05\x07\x00\x01" + bytes(6))
            return
        try:
            upstream = socket.create_connection((host, port), timeout=10)
        except OSError:
            client.sendall(b"\x05\x05\x00\x01" + bytes(6))
            return
        client.sendall(b"\x05\x00\x00\x01" + bytes(6))
        print(f"CONNECT {host}:{port} from {peer[0]}", flush=True)
        threading.Thread(target=pipe, args=(upstream, client), daemon=True).start()
        pipe(client, upstream)
    except (OSError, ConnectionError, ValueError):
        pass
    finally:
        client.close()


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 1080
    server = socket.create_server(("127.0.0.1", port))
    while True:
        conn, addr = server.accept()
        threading.Thread(target=handle, args=(conn, addr), daemon=True).start()
