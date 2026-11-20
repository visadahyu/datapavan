# SPDX-License-Identifier: Apache-2.0
"""The speed budget's measure for the names of direct apps (W8, part 1; ADR 0039): warm p50 and p95 of each way
Watch's encrypted resolver uses, against plain DNS to this network's resolver, from this computer on the same
network, with clients independent of the app. Each way keeps one connection, as Watch does, and asks a fixed list
of public names once each after a first query that opens the connection; the names are the same for every way.
Endpoints and their addresses come from the data pack's tables (data/odoh, data/dns-presets); no name of a server
is looked up. Nothing is sent but the public names below, and no way is asked more than len(NAMES) + 1 times.

    python3 -I scripts/dns-latency.py [--resolver ADDRESS] [--pairs] [--presets]
"""

import argparse
import http.client
import os
import socket
import ssl
import statistics
import struct
import sys
import time

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "dnslab"))
import odoh_probe  # noqa: E402  (the lab's independent ODoH client)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
NAMES = [
    "wikipedia.org", "example.com", "ietf.org", "mozilla.org", "debian.org", "kernel.org", "python.org", "gnu.org",
    "apache.org", "openstreetmap.org", "archive.org", "w3.org", "rust-lang.org", "fsf.org", "eff.org", "torproject.org",
    "signal.org", "f-droid.org", "codeberg.org", "gitlab.com", "github.com", "bbc.co.uk", "dw.com", "reuters.com",
    "un.org", "who.int", "europa.eu", "nasa.gov", "cern.ch", "nature.com",
]


def rows(path):
    with open(os.path.join(ROOT, path)) as f:
        return [line.rstrip("\n").split("\t") for line in f if line.strip() and not line.startswith("#")]


def query(name, qtype=1, pad=True):
    message = struct.pack(">HHHHHH", 0, 0x0100, 1, 0, 0, 1)
    message += b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\0" + struct.pack(">HH", qtype, 1)
    opt = b"\0" + struct.pack(">HHIH", 41, 1232, 0, 0)
    if pad:
        length = len(message) + len(opt) + 4
        padding = (128 - length % 128) % 128
        opt = b"\0" + struct.pack(">HHIH", 41, 1232, 0, 4 + padding) + struct.pack(">HH", 12, padding) + b"\0" * padding
    return message + opt


def timed(ask):
    times = []
    ask(NAMES[0])
    for name in NAMES:
        start = time.monotonic()
        ask(name)
        times.append((time.monotonic() - start) * 1000)
    times.sort()
    return statistics.median(times), times[min(len(times) - 1, int(len(times) * 0.95))]


def plain(resolver):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(3)

    def ask(name):
        q = bytearray(query(name, pad=False))
        q[0:2] = os.urandom(2)
        sock.sendto(bytes(q), (resolver, 53))
        while True:
            data, _ = sock.recvfrom(4096)
            if data[:2] == bytes(q[:2]):
                return data

    return ask


def https(url_host, address, path, body_type, make_body):
    context = ssl.create_default_context()
    connection = {"c": None}

    def connect():
        raw = socket.create_connection((address, 443), timeout=5)
        tls = context.wrap_socket(raw, server_hostname=url_host)
        c = http.client.HTTPSConnection(url_host, timeout=5, context=context)
        c.sock = tls
        connection["c"] = c

    def ask(name):
        if connection["c"] is None:
            connect()
        body, opener = make_body(name)
        c = connection["c"]
        c.request("POST", path, body=body, headers={"Content-Type": body_type, "Accept": body_type})
        response = c.getresponse()
        data = response.read()
        if response.status != 200:
            raise RuntimeError(f"HTTP {response.status}")
        return opener(data)

    return ask


def dot(host, address):
    context = ssl.create_default_context()
    tls = context.wrap_socket(socket.create_connection((address, 853), timeout=5), server_hostname=host)

    def ask(name):
        q = query(name)
        tls.sendall(struct.pack(">H", len(q)) + q)
        length = struct.unpack(">H", tls.recv(2))[0]
        data = b""
        while len(data) < length:
            data += tls.recv(length - len(data))
        return data

    return ask


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--resolver", help="this network's resolver (default: the first nameserver of /etc/resolv.conf)")
    args = parser.parse_args()
    resolver = args.resolver
    if not resolver:
        with open("/etc/resolv.conf") as f:
            resolver = next(line.split()[1] for line in f if line.startswith("nameserver"))
    results = [("plain DNS to this network's resolver", timed(plain(resolver)))]
    relays = {r[0]: r for r in rows("data/odoh/relays.tsv")}
    targets = {t[0]: t for t in rows("data/odoh/targets.tsv")}
    for relay_id, target_id in rows("data/odoh/pairs.tsv"):
        relay, target = relays[relay_id], targets[target_id]
        relay_host = relay[1].split("/")[2]
        relay_path = "/" + relay[1].split("/", 3)[3] if relay[1].count("/") > 2 else "/"
        configs = odoh_probe.parse_configs(bytes.fromhex(target[15]))
        if not configs:
            continue
        contents, pk = configs[0]
        path = f"{relay_path}?targethost={target[1]}&targetpath={target[2]}"

        def sealed(name, contents=contents, pk=pk):
            body, plain_text, exporter = odoh_probe.build(contents, pk, query(name))
            return body, lambda data: odoh_probe.open_response(data, plain_text, exporter)

        ask = https(relay_host, relay[2].split(",")[0], path, "application/oblivious-dns-message", sealed)
        try:
            results.append((f"ODoH {relay_id} -> {target_id}", timed(ask)))
        except Exception as e:  # noqa: BLE001  (a way that fails is reported, not fatal)
            results.append((f"ODoH {relay_id} -> {target_id}", f"failed: {type(e).__name__}"))
        if target[11] != "-":
            doh_host = target[11].split("/")[2]
            ask = https(doh_host, target[12].split(",")[0], "/" + target[11].split("/", 3)[3],
                        "application/dns-message", lambda name: (query(name), lambda data: data))
            try:
                results.append((f"DoH to {target_id}'s operator", timed(ask)))
            except Exception as e:  # noqa: BLE001
                results.append((f"DoH to {target_id}'s operator", f"failed: {type(e).__name__}"))
    for preset in rows("data/dns-presets/presets.tsv"):
        if preset[0] not in ("quad9-unsecured-doh", "quad9-unsecured-dot", "cloudflare-dot"):
            continue
        address = preset[6].split(",")[0]
        try:
            if preset[4] == "doh":
                host = preset[5].split("/")[2]
                ask = https(host, address, "/" + preset[5].split("/", 3)[3], "application/dns-message",
                            lambda name: (query(name), lambda data: data))
            else:
                ask = dot(preset[5], address)
            results.append((f"preset {preset[0]}", timed(ask)))
        except Exception as e:  # noqa: BLE001
            results.append((f"preset {preset[0]}", f"failed: {type(e).__name__}"))
    for name, result in results:
        if isinstance(result, tuple):
            print(f"{name}: warm p50 {result[0]:.0f} ms, p95 {result[1]:.0f} ms")
        else:
            print(f"{name}: {result}")


if __name__ == "__main__":
    main()
