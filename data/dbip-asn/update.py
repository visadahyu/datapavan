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

asn.bin, little-endian, in blocks that are each compressed on their own (raw deflate), so that a
lookup reads and inflates one block of a few kilobytes and the table stays about 2.7 MB:

    magic "DPASN\0\0\2", release month (8 bytes, "2026-11" and a zero), the source file's SHA-256 (32)
    v4 blocks, v6 blocks, AS blocks, AS count (u32 each)
    v4 index: per block, its first address (u32), offset and length of its data (u32 each)
    v6 index: per block, its first address (u128), offset and length (u32 each)
    AS index: per block, offset and length (u32 each)
    the blocks' data, offsets counted from its start

A block of addresses holds up to 512 entries, each the start of a range (a varint, the difference from
the entry before, the block's first counting from the block's first address) and its AS index (a
varint; 16777215 for a gap that no range covers). An entry holds until the next one starts. A block of
ASes holds 256 ASes in index order, each its number (a varint, the difference from the one before, the
block's first from 0), the length of its name (a varint) and the name in UTF-8.

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
import zlib

PAGE_URL = "https://db-ip.com/db/download/ip-to-asn-lite"
FILE_URL = "https://download.db-ip.com/free/dbip-asn-lite-{month}.csv.gz"
LICENCE_STATEMENT = (
    "The free IP to ASN Lite database by DB-IP is licensed under a Creative Commons Attribution 4.0 "
    "International License."
)
HERE = pathlib.Path(__file__).resolve().parent
MAGIC = b"DPASN\0\0\2"
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


GAP = 0xFFFFFF
RANGES_PER_BLOCK = 512
ASES_PER_BLOCK = 256


def varint(n: int) -> bytes:
    out = bytearray()
    while True:
        low, n = n & 0x7F, n >> 7
        out.append(low | (0x80 if n else 0))
        if not n:
            return bytes(out)


def deflate(data: bytes) -> bytes:
    compressor = zlib.compressobj(9, zlib.DEFLATED, -15, 9)
    return compressor.compress(data) + compressor.flush()


def write_table(month, digest, v4, v6, ases, index) -> bytes:
    """The table in the layout of the module's docstring."""
    def entries(ranges):
        out = []
        for i, (start, end, number) in enumerate(ranges):
            out.append((start, index[number]))
            if i + 1 == len(ranges) or ranges[i + 1][0] > end + 1:
                out.append((end + 1, GAP))
        return out

    data = bytearray()
    indexes = []
    for family, width in ((entries(v4), 4), (entries(v6), 16)):
        rows = bytearray()
        for i in range(0, len(family), RANGES_PER_BLOCK):
            block = family[i:i + RANGES_PER_BLOCK]
            raw = bytearray()
            previous = block[0][0]
            for start, as_index in block:
                raw += varint(start - previous) + varint(as_index)
                previous = start
            packed = deflate(bytes(raw))
            # An entry past the end of the address space (a gap after the last range) is left out.
            first = block[0][0]
            if first >= 1 << (8 * width):
                continue
            rows += first.to_bytes(width, "little") + struct.pack("<II", len(data), len(packed))
            data += packed
        indexes.append(rows)
    as_rows = bytearray()
    for i in range(0, len(ases), ASES_PER_BLOCK):
        raw = bytearray()
        previous = 0
        for number, name in ases[i:i + ASES_PER_BLOCK]:
            raw += varint(number - previous) + varint(len(name)) + name
            previous = number
        packed = deflate(bytes(raw))
        as_rows += struct.pack("<II", len(data), len(packed))
        data += packed
    v4_blocks, v6_blocks = len(indexes[0]) // 12, len(indexes[1]) // 24
    header = MAGIC + month.encode("ascii") + b"\0" + bytes.fromhex(digest)
    header += struct.pack("<IIII", v4_blocks, v6_blocks, len(as_rows) // 8, len(ases))
    return header + bytes(indexes[0]) + bytes(indexes[1]) + bytes(as_rows) + bytes(data)


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

    table = write_table(month, digest, v4, v6, [(n, names[i].encode("utf-8")) for i, n in enumerate(numbers)], index)
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
