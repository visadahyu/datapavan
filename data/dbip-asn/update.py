# SPDX-License-Identifier: Apache-2.0
"""Builds Watch's table from IP address to network and organisation (ADR 0036) from DB-IP's IP to ASN
Lite, the month's release.

    python3 -I data/dbip-asn/update.py [release month, default the current one, as 2026-11]

It writes asn.bin and SOURCE next to itself. It fails when DB-IP's download page no longer states the
licence, so that a person reads a change before the data changes (ADR 0015, decision 9); when a line of
the file is not exactly what the format says; and when the counts move by more than a tenth from the
last table, until a person runs it again with DATAPAVAN_ACCEPT_CHANGE=1.

What it keeps: ranges of public addresses (both ends global by Python's `ipaddress`) announced by
public AS numbers, with neighbouring ranges of the same AS merged, and one name per AS, the one that
covers the most addresses. Private, reserved and documentation addresses and AS numbers are dropped:
Watch names local addresses itself, and nobody owns the others.

asn.bin, little-endian, the same bytes for the same input:

    magic "DPASN\\0\\0\\1", release month (8 bytes, "2026-11" and a zero), the source file's SHA-256 (32)
    v4 count, v6 count, AS count, names length (u32 each)
    v4 ranges: start (u32), end (u32), AS index (u32), sorted by start
    v6 ranges: start (u128), end (u128), AS index (u32), sorted by start
    ASes: number (u32), name offset (u32), name length (u32), sorted by number
    names: UTF-8, one after another

core/net/src/organisations.rs reads it.
"""
import csv
import datetime
import gzip
import hashlib
import html
import io
import ipaddress
import os
import pathlib
import re
import struct
import sys
import tempfile
import urllib.request

PAGE_URL = "https://db-ip.com/db/download/ip-to-asn-lite"
FILE_URL = "https://download.db-ip.com/free/dbip-asn-lite-{month}.csv.gz"
LICENCE_STATEMENT = (
    "The free IP to ASN Lite database by DB-IP is licensed under a Creative Commons Attribution 4.0 "
    "International License."
)
HERE = pathlib.Path(__file__).resolve().parent
MAGIC = b"DPASN\0\0\1"
# The longest organisation name kept; longer ones are cut at a character boundary.
MAX_NAME = 120
# How far the counts may move from the last table before a person has to confirm.
MAX_CHANGE = 0.10


def fetch(url: str) -> bytes:
    # A generic client name: the data is public, and nothing about the person running this is sent.
    request = urllib.request.Request(url, headers={"User-Agent": "datapavan-data-update"})
    with urllib.request.urlopen(request, timeout=120) as response:
        return response.read()


def public_as(number: int) -> bool:
    """Not 0, AS_TRANS, documentation, private or reserved (RFC 5398, 6996, 7300, IANA's registry)."""
    return (
        0 < number < 64496 and number != 23456
        or 131072 <= number < 4200000000
    )


def main() -> None:
    month = sys.argv[1] if len(sys.argv) > 1 else datetime.date.today().strftime("%Y-%m")
    if not re.fullmatch(r"20[0-9]{2}-(0[1-9]|1[0-2])", month):
        sys.exit(f"not a release month: {month}")

    page = html.unescape(re.sub(r"<[^>]+>", " ", fetch(PAGE_URL).decode("utf-8", "replace")))
    page = re.sub(r"\s+([.,])", r"\1", re.sub(r"\s+", " ", page))
    if LICENCE_STATEMENT not in page:
        sys.exit("DB-IP's download page no longer states the licence; read it and update data/dbip-asn/LICENSE")

    url = FILE_URL.format(month=month)
    raw = fetch(url)
    digest = hashlib.sha256(raw).hexdigest()
    text = gzip.decompress(raw).decode("utf-8")

    v4, v6 = [], []
    names_by_as: dict[int, dict[str, int]] = {}
    lines = 0
    for row in csv.reader(io.StringIO(text, newline="")):
        lines += 1
        if len(row) != 4:
            sys.exit(f"line {lines}: {len(row)} fields, not 4")
        first, last, number, name = row
        try:
            start, end, number = ipaddress.ip_address(first), ipaddress.ip_address(last), int(number)
        except ValueError as error:
            sys.exit(f"line {lines}: {error}")
        if start.version != end.version or int(start) > int(end) or not 0 <= number <= 0xFFFFFFFF:
            sys.exit(f"line {lines}: not a range of one version with an AS number: {row}")
        if any(ord(c) < 32 or ord(c) == 127 for c in name):
            sys.exit(f"line {lines}: a control character in the name")
        if not (start.is_global and end.is_global and public_as(number)):
            continue
        name = " ".join(name.split())[:MAX_NAME]
        size = int(end) - int(start) + 1
        counts = names_by_as.setdefault(number, {})
        counts[name] = counts.get(name, 0) + size
        (v4 if start.version == 4 else v6).append((int(start), int(end), number))

    def merged(ranges):
        ranges.sort()
        out = []
        for start, end, number in ranges:
            if out and start <= out[-1][1]:
                sys.exit(f"overlapping ranges at {start}")
            if out and out[-1][2] == number and out[-1][1] + 1 == start:
                out[-1] = (out[-1][0], end, number)
            else:
                out.append((start, end, number))
        return out

    v4, v6 = merged(v4), merged(v6)
    numbers = sorted({n for _, _, n in v4} | {n for _, _, n in v6})
    index = {n: i for i, n in enumerate(numbers)}
    # The name covering the most addresses; among equals, the first in sort order.
    names = [min(names_by_as[n].items(), key=lambda item: (-item[1], item[0]))[0] for n in numbers]

    previous = HERE / "SOURCE"
    if previous.exists() and os.environ.get("DATAPAVAN_ACCEPT_CHANGE") != "1":
        old = dict(line.split(": ", 1) for line in previous.read_text().splitlines() if ": " in line)
        for key, new in (("v4-ranges", len(v4)), ("v6-ranges", len(v6)), ("as-numbers", len(numbers))):
            if key in old and abs(new - int(old[key])) > MAX_CHANGE * int(old[key]):
                sys.exit(f"{key} moved from {old[key]} to {new}; check, then run with DATAPAVAN_ACCEPT_CHANGE=1")

    name_bytes = bytearray()
    as_table = bytearray()
    for number, name in zip(numbers, names):
        encoded = name.encode("utf-8")
        as_table += struct.pack("<III", number, len(name_bytes), len(encoded))
        name_bytes += encoded
    out = io.BytesIO()
    out.write(MAGIC)
    out.write(month.encode("ascii") + b"\0")
    out.write(bytes.fromhex(digest))
    out.write(struct.pack("<IIII", len(v4), len(v6), len(numbers), len(name_bytes)))
    for start, end, number in v4:
        out.write(struct.pack("<III", start, end, index[number]))
    for start, end, number in v6:
        out.write(start.to_bytes(16, "little") + end.to_bytes(16, "little") + struct.pack("<I", index[number]))
    out.write(as_table)
    out.write(name_bytes)
    table = out.getvalue()

    (HERE / "asn.bin").write_bytes(table)
    retrieved = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    (HERE / "SOURCE").write_text(
        "# SPDX-License-Identifier: CC0-1.0\n"
        f"retrieved: {retrieved}\n"
        f"release: {month}\n"
        f"file: {url}\n"
        f"file-sha256: {digest}\n"
        f"licence-statement: {PAGE_URL}\n"
        f"lines: {lines}\n"
        f"v4-ranges: {len(v4)}\n"
        f"v6-ranges: {len(v6)}\n"
        f"as-numbers: {len(numbers)}\n"
        f"table-bytes: {len(table)}\n"
        f"table-sha256: {hashlib.sha256(table).hexdigest()}\n"
    )
    print(f"{lines} lines; {len(v4)} IPv4 and {len(v6)} IPv6 ranges, {len(numbers)} AS numbers; {len(table)} bytes")


if __name__ == "__main__":
    main()
