# SPDX-License-Identifier: Apache-2.0
"""Fetches Telegram's published address ranges again for Watch's inference of MTProto proxies (ADR 0052).

    python3 -I data/messengers/update.py
    python3 -I data/messengers/update.py --self-test    (no fetch: the bounds below)

It reads https://core.telegram.org/resources/cidr.txt, checks that every line is one network in CIDR
form and nothing else, and compares it with telegram-cidr.txt beside this script. It records each fetch
in SOURCE: when, the file's SHA-256 and Last-Modified header, the count of ranges, and the ranges added
and removed since the last fetch. A fetch that adds or removes a range changes nothing until a person
runs it again with DATAPAVAN_ACCEPT_CHANGE=1, having read the change; then telegram-cidr.txt is replaced
byte for byte, so that its SHA-256 stays the fetched file's.

clients.tsv and names.tsv are the project's own lists (CC0), kept by hand with a source for each row.
core/net/src/messengers.rs reads all three; they ship compiled into Watch's engine and in the data pack.
"""
import datetime
import hashlib
import ipaddress
import os
import pathlib
import sys
import urllib.request

URL = "https://core.telegram.org/resources/cidr.txt"
HERE = pathlib.Path(__file__).resolve().parent
KEPT = HERE / "telegram-cidr.txt"
SOURCE = HERE / "SOURCE"
# The most bytes a fetch reads: the file is 14 lines today. A longer one fails the run, never cut short.
MAX_BYTES = 65536
# The widest range taken: a network wider than a /16 (IPv4) or a /29 (IPv6) is no data centre's, and 0.0.0.0/0 or
# ::/0 would call every address Telegram's (the fix round's S-n2).
SHORTEST = {4: 16, 6: 29}
# The most ranges one fetch may add: more is a change to read by hand, not to take.
MAX_ADDED = 32


def ranges(data: bytes) -> list:
    """The networks of a fetched file, in its order; any other line fails the run."""
    networks = []
    for number, line in enumerate(data.decode("ascii").splitlines(), 1):
        if not line:
            continue
        network = ipaddress.ip_network(line, strict=True)
        if str(network) != line:
            raise SystemExit(f"line {number} is not one network in its canonical form: {line!r}")
        if not network.is_global:
            raise SystemExit(f"line {number} is not a public network: {line}")
        if network.prefixlen < SHORTEST[network.version]:
            raise SystemExit(f"line {number} is wider than a /{SHORTEST[network.version]}: {line}")
        networks.append(line)
    if not networks:
        raise SystemExit("the file holds no network")
    return networks


def main() -> None:
    request = urllib.request.Request(URL, headers={"User-Agent": "datapavan-data-update"})
    with urllib.request.urlopen(request, timeout=30) as response:
        data = response.read(MAX_BYTES + 1)
        modified = response.headers.get("Last-Modified", "-")
    if len(data) > MAX_BYTES:
        raise SystemExit(f"the file is longer than {MAX_BYTES} bytes: not read, rather than cut short")
    new = ranges(data)
    old = ranges(KEPT.read_bytes()) if KEPT.exists() else []
    added = [r for r in new if r not in old]
    removed = [r for r in old if r not in new]
    if len(added) > MAX_ADDED:
        raise SystemExit(f"{len(added)} ranges added, more than {MAX_ADDED}: read the file by hand")
    changed = KEPT.exists() and (added or removed)
    if changed and os.environ.get("DATAPAVAN_ACCEPT_CHANGE") != "1":
        print("Telegram's ranges changed; read the change, then run again with DATAPAVAN_ACCEPT_CHANGE=1:")
        for r in added:
            print(f"  added   {r}")
        for r in removed:
            print(f"  removed {r}")
        sys.exit(1)
    now = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    v4 = sum(1 for r in new if ipaddress.ip_network(r).version == 4)
    previous = SOURCE.read_text().split("\n# fetches\n", 1)[1] if SOURCE.exists() and "\n# fetches\n" in SOURCE.read_text() else ""
    fetch = (
        f"- {now} sha256 {hashlib.sha256(data).hexdigest()} last-modified {modified!r} ranges {len(new)} "
        f"added {','.join(added) or '-'} removed {','.join(removed) or '-'}\n"
    )
    if KEPT.exists() and not changed and data != KEPT.read_bytes():
        fetch += "  (the same ranges in other bytes: telegram-cidr.txt kept as it was)\n"
    elif not KEPT.exists() or changed:
        KEPT.write_bytes(data)
    head = SOURCE.read_text().split("\n# fetches\n", 1)[0] if SOURCE.exists() else ""
    if not head:
        raise SystemExit("SOURCE has no head to keep")
    head = "\n".join(
        line if not line.startswith("ranges:") else f"ranges: {len(new)} ({v4} IPv4, {len(new) - v4} IPv6)"
        for line in head.splitlines()
    )
    SOURCE.write_text(f"{head}\n# fetches\n{previous}{fetch}")
    print(f"{len(new)} ranges, {len(added)} added, {len(removed)} removed")


def self_test() -> None:
    """The bounds, without a fetch (scripts/check.sh data runs it): too wide a range fails, the kept file passes."""
    for wide in (b"0.0.0.0/0\n", b"::/0\n", b"91.108.0.0/15\n", b"2001:b20::/28\n"):
        try:
            ranges(wide)
        except SystemExit:
            continue
        raise SystemExit(f"self-test: {wide!r} was taken")
    ranges(b"91.108.0.0/16\n2001:b28::/32\n")
    ranges(KEPT.read_bytes())
    print("update.py self-test passed")


if __name__ == "__main__":
    if sys.argv[1:] == ["--self-test"]:
        self_test()
    else:
        main()
