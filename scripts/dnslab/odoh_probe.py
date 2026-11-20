# SPDX-License-Identifier: Apache-2.0
"""A minimal Oblivious DoH client (RFC 9230: HPKE X25519, HKDF-SHA256, AES-128-GCM) for the DNS lab's selftest
(scripts/dnslab.sh), independent of the app: adapted from the W8 research probe (the maintainer's
research/2026-11-w8/tools/odoh_probe.py) to the lab's CA and to fronts reached by address with the server's name
for TLS. Needs Python's `cryptography` package (python3-cryptography); run with python3 -I.

  odoh_probe.py configs --ca CA --connect ADDR:PORT --host NAME
      prints the target's ObliviousDoHConfigs (GET /.well-known/odohconfigs) as lower-case hex
  odoh_probe.py query --ca CA --relay-connect ADDR:PORT --relay NAME [--relay-path /proxy]
                      --target NAME [--target-path /dns-query] (--configs HEX | --configs-connect ADDR:PORT)
                      [--name probe.dnslab.test] [--timeout S]
      sends one ODoH query through the relay to the target and prints the decrypted answer:
      `answer rcode=NOERROR a=10.53.1.1`; a failure prints `failed reset|timeout|eof|http-NNN|...` and exits 1."""

import argparse
import hashlib
import hmac
import http.client
import socket
import ssl
import struct
import sys
import urllib.parse

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def extract(salt, ikm):
    return hmac.new(salt or b"\0" * 32, ikm, hashlib.sha256).digest()


def expand(prk, info, length):
    out, t, i = b"", b"", 1
    while len(out) < length:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        out += t
        i += 1
    return out[:length]


RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}
KEM, KDF, AEAD = 0x0020, 0x0001, 0x0001
SUITE_KEM = b"KEM" + struct.pack(">H", KEM)
SUITE = b"HPKE" + struct.pack(">HHH", KEM, KDF, AEAD)


def lext(suite, salt, label, ikm):
    return extract(salt, b"HPKE-v1" + suite + label + ikm)


def lexp(suite, prk, label, info, length):
    return expand(prk, struct.pack(">H", length) + b"HPKE-v1" + suite + label + info, length)


def setup_base_s(pk_r, info):
    sk_e = X25519PrivateKey.generate()
    pk_e = sk_e.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    dh = sk_e.exchange(X25519PublicKey.from_public_bytes(pk_r))
    eae = lext(SUITE_KEM, b"", b"eae_prk", dh)
    ss = lexp(SUITE_KEM, eae, b"shared_secret", pk_e + pk_r, 32)
    psk_id_hash = lext(SUITE, b"", b"psk_id_hash", b"")
    info_hash = lext(SUITE, b"", b"info_hash", info)
    ctx = b"\x00" + psk_id_hash + info_hash
    secret = lext(SUITE, ss, b"secret", b"")
    return pk_e, lexp(SUITE, secret, b"key", ctx, 16), lexp(SUITE, secret, b"base_nonce", ctx, 12), \
        lexp(SUITE, secret, b"exp", ctx, 32)


def lp(data):
    return struct.pack(">H", len(data)) + data


def parse_configs(blob):
    i, out = 2, []
    while i < len(blob):
        version, length = struct.unpack(">HH", blob[i:i + 4])
        contents = blob[i + 4:i + 4 + length]
        kem, kdf, aead, pk_len = struct.unpack(">HHHH", contents[:8])
        if version == 1 and (kem, kdf, aead) == (KEM, KDF, AEAD):
            out.append((contents, contents[8:8 + pk_len]))
        i += 4 + length
    return out


def dns_query(name, qtype=1):
    header = struct.pack(">HHHHHH", 0, 0x0100, 1, 0, 0, 1)
    question = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\0" + struct.pack(">HH", qtype, 1)
    return header + question + b"\0" + struct.pack(">HHIH", 41, 1232, 0, 0)


def build(config_contents, pk, message):
    key_id = expand(extract(b"", config_contents), b"odoh key id", 32)
    pad = b"\0" * ((-len(message) - 4) % 128)
    plain = lp(message) + lp(pad)
    enc, key, nonce, exporter = setup_base_s(pk, b"odoh query")
    aad = b"\x01" + lp(key_id)
    return b"\x01" + lp(key_id) + lp(enc + AESGCM(key).encrypt(nonce, plain, aad)), plain, exporter


def open_response(body, plain, exporter):
    if body[0] != 2:
        raise ValueError("not an ODoH response")
    nonce_len = struct.unpack(">H", body[1:3])[0]
    nonce_r = body[3:3 + nonce_len]
    ct_len = struct.unpack(">H", body[3 + nonce_len:5 + nonce_len])[0]
    ct = body[5 + nonce_len:5 + nonce_len + ct_len]
    secret = lexp(SUITE, exporter, b"sec", b"odoh response", 16)
    prk = extract(plain + lp(nonce_r), secret)
    key, nonce = expand(prk, b"odoh key", 16), expand(prk, b"odoh nonce", 12)
    pt = AESGCM(key).decrypt(nonce, ct, b"\x02" + lp(nonce_r))
    return pt[2:2 + struct.unpack(">H", pt[:2])[0]]


def answers(message):
    """The rcode and the A addresses of a DNS answer."""
    rcode = message[3] & 0xF
    qd, an = struct.unpack(">HH", message[4:8])
    pos = 12

    def skip(pos):
        while True:
            length = message[pos]
            if length == 0:
                return pos + 1
            if length & 0xC0 == 0xC0:
                return pos + 2
            pos += 1 + length
    for _ in range(qd):
        pos = skip(pos) + 4
    addresses = []
    for _ in range(an):
        pos = skip(pos)
        rtype, _, _, rdlen = struct.unpack(">HHIH", message[pos:pos + 10])
        if rtype == 1 and rdlen == 4:
            addresses.append(socket.inet_ntoa(message[pos + 10:pos + 14]))
        pos += 10 + rdlen
    return rcode, addresses


class Front(http.client.HTTPSConnection):
    """HTTPS to a server by its name (SNI, certificate, Host) at the front's address."""

    def __init__(self, name, connect, context, timeout):
        address, _, port = connect.rpartition(":")
        super().__init__(name, int(port), context=context, timeout=timeout)
        self.front = (address, int(port))
        self.context = context

    def connect(self):
        sock = socket.create_connection(self.front, timeout=self.timeout)
        self.sock = self.context.wrap_socket(sock, server_hostname=self.host)


def fetch_configs(args, context, connect, host):
    connection = Front(host, connect, context, args.timeout)
    connection.request("GET", "/.well-known/odohconfigs")
    response = connection.getresponse()
    body = response.read()
    connection.close()
    if response.status != 200:
        raise RuntimeError(f"http-{response.status}")
    return body


def failure(error):
    if isinstance(error, ConnectionResetError):
        return "reset"
    if isinstance(error, (socket.timeout, TimeoutError)):
        return "timeout"
    if isinstance(error, (ssl.SSLEOFError, ssl.SSLZeroReturnError, http.client.RemoteDisconnected,
                          ConnectionAbortedError, BrokenPipeError)):
        return "eof"
    if isinstance(error, ssl.SSLCertVerificationError):
        return "certificate"
    return f"{type(error).__name__}:{error}".replace(" ", "_")


def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    configs = sub.add_parser("configs")
    query = sub.add_parser("query")
    for p in (configs, query):
        p.add_argument("--ca", required=True)
        p.add_argument("--timeout", type=float, default=5)
    configs.add_argument("--connect", required=True)
    configs.add_argument("--host", required=True)
    query.add_argument("--relay-connect", required=True)
    query.add_argument("--relay", required=True)
    query.add_argument("--relay-path", default="/proxy")
    query.add_argument("--target", required=True)
    query.add_argument("--target-path", default="/dns-query")
    query.add_argument("--configs")
    query.add_argument("--configs-connect")
    query.add_argument("--name", default="probe.dnslab.test")
    args = parser.parse_args()
    context = ssl.create_default_context(cafile=args.ca)
    try:
        if args.command == "configs":
            print(fetch_configs(args, context, args.connect, args.host).hex())
            return 0
        blob = bytes.fromhex(args.configs) if args.configs else \
            fetch_configs(args, context, args.configs_connect, args.target)
        usable = parse_configs(blob)
        if not usable:
            print("failed no-usable-config")
            return 1
        contents, pk = usable[0]
        message, plain, exporter = build(contents, pk, dns_query(args.name))
        relay = Front(args.relay, args.relay_connect, context, args.timeout)
        path = args.relay_path + "?" + urllib.parse.urlencode({"targethost": args.target,
                                                               "targetpath": args.target_path})
        relay.request("POST", path, body=message, headers={"Content-Type": "application/oblivious-dns-message",
                                                           "Accept": "application/oblivious-dns-message"})
        response = relay.getresponse()
        body = response.read()
        relay.close()
        if response.status != 200:
            print(f"failed http-{response.status}")
            return 1
        rcode, addresses = answers(open_response(body, plain, exporter))
        print(f"answer rcode={RCODES.get(rcode, rcode)} a={','.join(addresses) or '-'}")
        return 0
    except Exception as error:  # every failure is a result here, named for the check
        print(f"failed {failure(error)}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
