#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Sums up an emulator's capture for a gaps run (lab/run.sh, ADR 0048): the packets, the connections (SYNs) and
# datagrams to the lab's server, the packets that hold the probe's payloads, and each distinct name under
# .gaps.example that a DNS packet holds, so that a row can tell which of the probe's lookups left the virtual
# phone. It prints nothing else of the capture, which stays on the machine that ran it.
#
#   python3 -I lab/capture-summary.py CAPTURE.pcap > capture.txt
import struct
import sys
from collections import Counter

SUFFIX = b"\x04gaps\x07example\x00"


def main(path):
    data = open(path, "rb").read()
    endian = "<" if data[:4] == b"\xd4\xc3\xb2\xa1" else ">"
    link = struct.unpack(endian + "I", data[20:24])[0]
    at, packets, to = 24, 0, Counter()
    patterns = {"gaps-loopback": b"gaps-loopback", "gaps-short-lived": b"gaps-short-lived", "gaps.example": SUFFIX}
    hits = Counter()
    names = set()
    while at + 16 <= len(data):
        caplen = struct.unpack(endian + "I", data[at + 8:at + 12])[0]
        frame = data[at + 16:at + 16 + caplen]
        at += 16 + caplen
        packets += 1
        for name, pattern in patterns.items():
            if pattern in frame:
                hits[name] += 1
        # The label before ".gaps.example": its length byte, then that many printable bytes.
        start = frame.find(SUFFIX)
        while start > 0:
            for length in range(1, min(63, start - 1) + 1):
                label = frame[start - length:start]
                if frame[start - length - 1] == length and all(48 <= b <= 57 or 97 <= b <= 122 or b == 45 for b in label):
                    names.add(label.decode() + ".gaps.example")
                    break
            start = frame.find(SUFFIX, start + 1)
        ip = frame[14:] if link == 1 and frame[12:14] in (b"\x08\x00", b"\x86\xdd") else b""
        if not (ip[:1] and ip[0] >> 4 == 4 and len(ip) >= 24):
            continue
        proto, header, dst = ip[9], (ip[0] & 15) * 4, ".".join(str(b) for b in ip[16:20])
        l4 = ip[header:]
        if proto in (6, 17) and len(l4) >= 4:
            port = struct.unpack("!H", l4[2:4])[0]
            if dst == "10.0.2.2" and port in (8792, 8793, 8796):
                if proto == 17:
                    to[("udp", f"{dst}:{port}")] += 1
                elif len(l4) >= 14 and l4[13] & 0x12 == 0x02:
                    to[("tcp-syn", f"{dst}:{port}")] += 1
    print(f"packets {packets}")
    for (kind, where), n in sorted(to.items()):
        print(f"to {kind} {where} {n}")
    for name in patterns:
        print(f"pattern {name} {hits[name]}")
    for name in sorted(names):
        print(f"query {name}")


if __name__ == "__main__":
    main(sys.argv[1])
