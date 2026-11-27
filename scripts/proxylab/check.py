# SPDX-License-Identifier: Apache-2.0
"""The proxy lab's own check, from the host (scripts/proxylab.sh): each proxy takes the handshake the emulator's
fixture speaks (scripts/proxy-fixture), with the lab's synthetic credentials, and carries it to the lab's target;
a wrong password is refused; mtg accepts a fake-TLS hello made with the lab's secret and refuses one made with
another. Each step prints PASS or FAIL and its name; the run fails on any FAIL.

The network's own proxy (the proxy record's unit S2): tinyproxy, a real proxy, gets the engine's own CONNECT, the
bytes connect::request writes, from core/net/testdata/connect-requests.tsv, which connect.rs's unit test holds to
them. Without a password it opens one by name and one by address, the target's address on the lab's network in
place of the table's documentation address, and carries a hello; it refuses one to port 80 with 403, by the lab's
ConnectPort 443 (start.sh: tinyproxy's own default, its ConnectPort lines commented out, allows every port); and
with a password it answers 407, which the engine takes for a proxy that wants one.

Plain HTTP in absolute form (the proxy record's forwarder, used where the network's proxy refuses a CONNECT to that
port): squid and tinyproxy, each as Debian ships it but for the lab's network allowed, and the lab's two tinyproxies,
get requests in absolute form, and the target's answer says what each proxy sent it (target.py's X-Lab fields). The
rows pin what these versions do, as measured on 2026-11-28: squid refuses a CONNECT to port 80 (the forwarder's
premise) and plain requests to ports outside its Safe_ports; it keeps the client's connection, answers a pipelined
pair in order, makes the origin's Host from the URL (lower case, no trailing dot, no :80) and sends no Upgrade.
tinyproxy carries a CONNECT to any port as shipped, keeps the Host as the client wrote it but for :80, sends no
Upgrade, and serves one request a connection: it closes after the first answer and drops a pipelined second. Neither
reads a request out of the body of an Expect request it refused early (the forwarder's audit, m6), by the target's
own record of what it got.

    python3 -I check.py HOST PORT_SOCKS PORT_HTTP PORT_OPEN PORT_MTG USER PASSWORD MTG_SECRET TARGET_ADDRESS \
        PORT_SQUID PORT_DEBIAN PORT_SEEN
"""
import base64
import hashlib
import hmac
import os
import socket
import struct
import sys
import time

INNER = "inner.proxylab.test"
COVER_PREFIX = "ee"
# The engine's own requests, byte for byte (the proxy record's unit S2).
REQUESTS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "core", "net", "testdata",
                        "connect-requests.tsv")
# The table's address row, whose address the check replaces with the target's on the lab's network.
TABLE_ADDRESS = "198.51.100.9"


def client_hello(name, session=b"\x00" * 32, random=b"\x07" * 32):
    """A small TLS 1.3 ClientHello record for name, as the fixture builds it."""
    server_name = name.encode()
    sni = struct.pack(">HBH", len(server_name) + 3, 0, len(server_name)) + server_name
    extensions = struct.pack(">HH", 0, len(sni)) + sni
    extensions += struct.pack(">HHB", 43, 3, 2) + b"\x03\x04"  # supported_versions: TLS 1.3
    body = b"\x03\x03" + random + bytes([len(session)]) + session
    body += struct.pack(">H", 2) + b"\x13\x01" + b"\x01\x00"
    body += struct.pack(">H", len(extensions)) + extensions
    handshake = b"\x01" + struct.pack(">I", len(body))[1:] + body
    return b"\x16\x03\x01" + struct.pack(">H", len(handshake)) + handshake


def fake_tls_hello(secret_hex):
    """A fake-TLS hello for the MTProto secret ee + key + cover name: the random is HMAC-SHA256(key, the record with
    a zero random), its last four bytes XORed with the time (TDLib's TlsInit.cpp; mtg's client_side.go)."""
    secret = bytes.fromhex(secret_hex[2:])
    key, cover = secret[:16], secret[16:].decode()
    record = bytearray(client_hello(cover, session=os.urandom(32), random=b"\x00" * 32))
    digest = bytearray(hmac.new(key, bytes(record), hashlib.sha256).digest())
    stamp = struct.pack("<I", int(time.time()))
    for i in range(4):
        digest[28 + i] ^= stamp[i]
    record[11:43] = digest
    return bytes(record)


def connect(host, port):
    s = socket.create_connection((host, port), timeout=10)
    s.settimeout(10)
    return s


def read_exactly(s, n):
    data = b""
    while len(data) < n:
        chunk = s.recv(n - len(data))
        if not chunk:
            break
        data += chunk
    return data


def socks5(host, port, user, password):
    s = connect(host, port)
    s.sendall(b"\x05\x01\x02")
    if read_exactly(s, 2) != b"\x05\x02":
        return None
    s.sendall(bytes([1, len(user)]) + user.encode() + bytes([len(password)]) + password.encode())
    if read_exactly(s, 2) != b"\x01\x00":
        return None
    s.sendall(b"\x05\x01\x00\x03" + bytes([len(INNER)]) + INNER.encode() + struct.pack(">H", 443))
    reply = read_exactly(s, 4)
    if reply[:2] != b"\x05\x00":
        return None
    read_exactly(s, {1: 6, 4: 18}.get(reply[3], 0) or 1 + read_exactly(s, 1)[0] + 2)
    return s


def http_connect(host, port, user=None, password=None):
    s = connect(host, port)
    auth = ""
    if user is not None:
        auth = "Proxy-Authorization: Basic " + base64.b64encode(f"{user}:{password}".encode()).decode() + "\r\n"
    s.sendall(f"CONNECT {INNER}:443 HTTP/1.1\r\nHost: {INNER}:443\r\n{auth}\r\n".encode())
    head = b""
    while b"\r\n\r\n" not in head:
        chunk = s.recv(1)
        if not chunk:
            break
        head += chunk
    return s if head.startswith(b"HTTP/1.") and b" 200 " in head.split(b"\r\n")[0] else None


def engine_request(target):
    """The request the engine's connect::request writes for target, as the shared table holds it."""
    with open(REQUESTS, encoding="utf-8") as table:
        for line in table:
            if line.startswith("#") or not line.strip():
                continue
            name, request = line.rstrip("\n").split("\t")
            if name == target:
                return request.replace("\\r", "\r").replace("\\n", "\n").encode()
    raise SystemExit(f"no request for {target} in {REQUESTS}")


def engine_connect(host, port, request):
    """Sends request as it is, and reads the answer's head to its blank line and no further, as the engine does: the
    socket and the status code, None for no HTTP answer."""
    s = connect(host, port)
    s.sendall(request)
    head = b""
    while not head.endswith(b"\r\n\r\n") and not head.endswith(b"\n\n") and len(head) < 8192:
        chunk = s.recv(1)
        if not chunk:
            break
        head += chunk
    line = head.split(b"\n")[0]
    code = int(line[9:12]) if line[:7] == b"HTTP/1." and line[9:12].isdigit() else None
    return s, code


def exchange(host, port, data, quiet=1.5):
    """Sends data as it is and reads until the proxy closes or stays quiet for `quiet` seconds: the answers, each its
    status code and its fields (names in lower case), in order, and whether the proxy closed."""
    s = connect(host, port)
    s.sendall(data)
    s.settimeout(quiet)
    got, closed = b"", False
    while len(got) < 1 << 20:
        try:
            chunk = s.recv(65536)
        except socket.timeout:
            break
        if not chunk:
            closed = True
            break
        got += chunk
    s.close()
    answers = []
    while b"\r\n\r\n" in got:
        head, got = got.split(b"\r\n\r\n", 1)
        line, *rest = head.decode("latin-1").split("\r\n")
        code = int(line[9:12]) if line[:7] == "HTTP/1." and line[9:12].isdigit() else None
        fields = dict((k.strip().lower(), v.strip()) for k, v in (f.split(":", 1) for f in rest if ":" in f))
        length = 0 if code is None or code < 200 or code in (204, 304) else int(fields.get("content-length", len(got)))
        got = got[length:]
        answers.append((code, fields))
    return answers, closed


def plain(path, host=INNER, method="GET", fields="", body=b""):
    """A request in absolute form, as the forwarder writes one: the URL's authority and Host from host."""
    length = f"Content-Length: {len(body)}\r\n" if body and "Transfer-Encoding" not in fields else ""
    return f"{method} http://{host}{path} HTTP/1.1\r\nHost: {host}\r\n{fields}{length}\r\n".encode() + body


def lab(answer):
    """What the target says it got, from one answer's X-Lab fields: the request line, Host, field names, body."""
    code, fields = answer
    return code, fields.get("x-lab-line"), fields.get("x-lab-host"), fields.get("x-lab-fields", "").split(","), \
        fields.get("x-lab-body")


def seen(host, port):
    """Every request the target got so far, by its own record (target.py's port 8081)."""
    answers = connect(host, port)
    answers.sendall(b"GET /seen HTTP/1.1\r\nHost: target\r\n\r\n")
    got = b""
    while True:
        chunk = answers.recv(65536)
        if not chunk:
            break
        got += chunk
    return got.split(b"\r\n\r\n", 1)[1].decode("latin-1")


def said(got):
    """The first answer's request line and Host, as the target says it got them, for a row's name."""
    return got[0][1:3] if got else "no answer"


def body_of(data):
    return f"{len(data)} {hashlib.sha256(data).hexdigest()}"


def http_get(host, port, user=None, password=None):
    s = connect(host, port)
    auth = ""
    if user is not None:
        auth = "Proxy-Authorization: Basic " + base64.b64encode(f"{user}:{password}".encode()).decode() + "\r\n"
    s.sendall(f"GET http://{INNER}/lab HTTP/1.1\r\nHost: {INNER}\r\n{auth}Connection: close\r\n\r\n".encode())
    answer = s.recv(4096)
    s.close()
    return answer.split(b"\r\n")[0]


def main(argv):
    host, socks_port, http_port, open_port, mtg_port, user, password, secret, target, squid_port, debian_port, \
        seen_port = argv
    socks_port, http_port, open_port, mtg_port, squid_port, debian_port, seen_port = map(
        int, (socks_port, http_port, open_port, mtg_port, squid_port, debian_port, seen_port))
    failed = 0

    def check(name, ok):
        nonlocal failed
        print(("PASS " if ok else "FAIL ") + name, flush=True)
        failed += 0 if ok else 1

    hello = client_hello(INNER)
    s = socks5(host, socks_port, user, password)
    check("socks5-with-password-carries-a-hello", s is not None and (s.sendall(hello) or read_exactly(s, len(hello))) == hello)
    check("socks5-refuses-a-wrong-password", socks5(host, socks_port, user, password + "x") is None)
    s = http_connect(host, http_port, user, password)
    check("connect-with-basic-carries-a-hello", s is not None and (s.sendall(hello) or read_exactly(s, len(hello))) == hello)
    check("connect-refuses-a-wrong-password", http_connect(host, http_port, user, password + "x") is None)
    check("plain-request-through-the-proxy", http_get(host, http_port, user, password).startswith(b"HTTP/1.") and b"204" in http_get(host, http_port, user, password))
    check("open-proxy-plain-request", b"204" in http_get(host, open_port))
    s = connect(host, mtg_port)
    s.sendall(fake_tls_hello(secret))
    answer = read_exactly(s, 6)
    check("mtg-accepts-the-fake-tls-hello", answer[:3] == b"\x16\x03\x03")
    other = secret[:2] + ("00" * 16) + secret[34:]
    s = connect(host, mtg_port)
    s.sendall(fake_tls_hello(other))
    try:
        refused = read_exactly(s, 3) != b"\x16\x03\x03"
    except OSError:
        refused = True
    check("mtg-refuses-another-secret", refused)

    def carries(s, code):
        return code == 200 and (s.sendall(hello) or read_exactly(s, len(hello))) == hello

    s, code = engine_connect(host, open_port, engine_request(INNER + ":443"))
    check("tinyproxy-opens-the-engines-connect-by-name", carries(s, code))
    by_address = engine_request(TABLE_ADDRESS + ":443").replace(TABLE_ADDRESS.encode(), target.encode())
    s, code = engine_connect(host, open_port, by_address)
    check("tinyproxy-opens-the-engines-connect-by-address", carries(s, code))
    _, code = engine_connect(host, open_port, engine_request(INNER + ":80"))
    check(f"tinyproxy-refuses-the-engines-connect-to-port-80-by-connectport-443 (answered {code})", code == 403)
    _, code = engine_connect(host, http_port, engine_request(INNER + ":443"))
    check(f"tinyproxy-with-a-password-answers-407-to-the-engines-connect (answered {code})", code == 407)

    # Plain HTTP in absolute form (the proxy record's forwarder).
    _, code = engine_connect(host, squid_port, engine_request(INNER + ":80"))
    check(f"squid-refuses-the-engines-connect-to-port-80 (answered {code})", code == 403)
    s, code = engine_connect(host, squid_port, engine_request(INNER + ":443"))
    check("squid-opens-the-engines-connect-to-port-443", carries(s, code))
    _, code = engine_connect(host, debian_port, engine_request(INNER + ":80"))
    check(f"shipped-tinyproxy-opens-the-engines-connect-to-port-80 (answered {code})", code == 200)

    proxies = (("squid", squid_port), ("shipped-tinyproxy", debian_port), ("tinyproxy-connectport-443", open_port))
    hello_body = b"hello"
    for name, port in proxies:
        answers, _ = exchange(host, port, plain("/fwd?q=1", fields="User-Agent: lab\r\nAccept: */*\r\n"))
        got = [lab(a) for a in answers]
        check(f"{name}-forwards-a-request-in-origin-form ({said(got)})",
              len(got) == 1 and got[0][:3] == (204, "GET /fwd?q=1 HTTP/1.1", INNER) and "User-Agent" in got[0][3])
        answers, _ = exchange(host, port, plain("/post", method="POST", body=hello_body))
        got = [lab(a) for a in answers]
        check(f"{name}-forwards-a-body-whole", len(got) == 1 and got[0][1] == "POST /post HTTP/1.1"
              and got[0][4] == body_of(hello_body))
        chunked = plain("/chunked", method="POST", fields="Transfer-Encoding: chunked\r\n",
                        body=b"5\r\nhello\r\n0\r\n\r\n")
        answers, _ = exchange(host, port, chunked)
        got = [lab(a) for a in answers]
        check(f"{name}-forwards-a-chunked-body-whole", len(got) == 1 and got[0][4] == body_of(hello_body))
        upgrade = ("Connection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\n"
                   "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n")
        answers, _ = exchange(host, port, plain("/ws", fields=upgrade))
        got = [lab(a) for a in answers]
        check(f"{name}-sends-the-origin-no-upgrade-from-a-request-in-absolute-form ({said(got)})",
              len(got) == 1 and got[0][0] == 204 and "Upgrade" not in got[0][3])
        answers, _ = exchange(host, port, plain("/uir", fields="Upgrade-Insecure-Requests: 1\r\n"))
        got = [lab(a) for a in answers]
        check(f"{name}-forwards-upgrade-insecure-requests", len(got) == 1 and "Upgrade-Insecure-Requests" in got[0][3])
        answers, _ = exchange(host, port, f"OPTIONS http://{INNER} HTTP/1.1\r\nHost: {INNER}\r\n\r\n".encode())
        got = [lab(a) for a in answers]
        check(f"{name}-sends-an-options-request-with-no-path-as-options-slash ({said(got)})",
              len(got) == 1 and got[0][1] == "OPTIONS / HTTP/1.1")
        # The Host the origin gets (the forwarder's audit, m4 and m5): squid makes it from the URL; tinyproxy keeps the
        # client's, but for :80; both read :080 as port 80.
        for written, squid_host, tinyproxy_host in (
            ("INNER.ProxyLab.TEST", INNER, "INNER.ProxyLab.TEST"),
            (INNER + ".", INNER, INNER + "."),
            (INNER + ":80", INNER, INNER),
            (INNER + ":080", INNER, INNER),
        ):
            answers, _ = exchange(host, port, plain("/host", host=written))
            got = [lab(a) for a in answers]
            wanted = squid_host if name == "squid" else tinyproxy_host
            check(f"{name}-sends-the-origin-host-{wanted}-for-{written}", len(got) == 1 and got[0][2] == wanted)
        # A pipelined pair, and a second request after the first answer.
        pair = plain("/pair-1") + plain("/pair-2", method="POST", body=hello_body)
        answers, closed = exchange(host, port, pair)
        got = [lab(a) for a in answers]
        if name == "squid":
            check("squid-answers-a-pipelined-pair-in-order", [g[1] for g in got] == ["GET /pair-1 HTTP/1.1",
                  "POST /pair-2 HTTP/1.1"] and got[1][4] == body_of(hello_body) and not closed)
        else:
            check(f"{name}-answers-one-request-a-connection-and-closes ({[g[1] for g in got]}, closed {closed})",
                  [g[1] for g in got] == ["GET /pair-1 HTTP/1.1"] and closed)
        # An Expect request the proxy refuses early, whose body is a whole request (the forwarder's audit, m6): the
        # target must never get that request.
        for expect, port_written in (("100-continue", 81), ("x-lab", 80)):
            nonce = os.urandom(6).hex()
            inner = plain(f"/smuggled-{nonce}")
            answers, _ = exchange(host, port, plain("/expect", host=f"{INNER}:{port_written}", method="POST",
                                                    fields=f"Expect: {expect}\r\n", body=inner))
            codes = [a[0] for a in answers]
            check(f"{name}-reads-no-request-out-of-the-body-of-an-expect-{expect}-to-port-{port_written} "
                  f"(answered {codes})", f"smuggled-{nonce}" not in seen(host, seen_port))
    for written in (INNER + ":81", INNER + ":25"):
        answers, _ = exchange(host, squid_port, plain("/safe-ports", host=written))
        codes = [a[0] for a in answers]
        check(f"squid-refuses-a-request-to-{written}-by-safe-ports (answered {codes})", codes == [403])
    answers, _ = exchange(host, http_port, plain("/auth"))
    codes = [a[0] for a in answers]
    check(f"tinyproxy-with-a-password-answers-407-to-a-request-in-absolute-form (answered {codes})", codes == [407])
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
