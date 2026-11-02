#!/usr/bin/env python3
"""Adds up IP bytes in a packet capture (classic pcap), the way Android counts them: the IP packet's
own length, headers included, never the frame's. Reads Ethernet captures (the emulator's -tcpdump:
mobile data) and 802.11 radiotap captures (netsimd --pcap: Wi-Fi).

  capture.py FILE [--from WALL_S] [--to WALL_S] [--port PORT]

The direction comes from the frame: on Ethernet, the emulator's network card is the guest; on Wi-Fi,
frames to the access point are sent and frames from it received. Packets to a multicast or broadcast
address are counted apart. Prints one JSON object: bytes and packets each way, and the largest packet
seen (more than the MTU means the capture holds segmentation-offloaded packets).
"""
import argparse
import ipaddress
import json
import struct
import sys
from collections import Counter, defaultdict

ETHERNET, IEEE802_11, RADIOTAP = 1, 105, 127
LLC_SNAP = bytes.fromhex("aaaa03000000")
GUEST_MAC = bytes.fromhex("525400123456")  # the emulator's eth0
BROADCAST = ipaddress.ip_address("255.255.255.255")


def packets(path):
    with open(path, "rb") as f:
        head = f.read(24)
        magic = struct.unpack("<I", head[:4])[0]
        if magic in (0xA1B2C3D4, 0xA1B23C4D):
            order = "<"
        else:
            order = ">"
            magic = struct.unpack(">I", head[:4])[0]
        scale = 1e-9 if magic == 0xA1B23C4D else 1e-6
        link = struct.unpack(order + "I", head[20:24])[0]
        if link not in (ETHERNET, IEEE802_11, RADIOTAP):
            sys.exit(f"link type {link} is neither Ethernet nor 802.11")
        while True:
            record = f.read(16)
            if len(record) < 16:
                return
            sec, frac, size, _ = struct.unpack(order + "IIII", record)
            yield sec + frac * scale, link, f.read(size)


def clock_shift(path, port, finished):
    """Seconds to add to the file's timestamps to get the computer's wall-clock time. The emulator's
    -tcpdump writes local time as if it were UTC, and its clock runs a few seconds apart; netsimd
    writes UTC. The shift is found by matching the ends of bursts of packets on [port] with the times
    at which the server [finished] each transfer."""
    ends, last = [], None
    for when, link, frame in packets(path):
        fact = ip(link, frame)
        if fact is None or port not in (fact[3], fact[4]):
            continue
        if last is None or when - last > 1:
            ends.append(when)
        ends[-1] = last = when
    if not ends or not finished:
        return 0.0
    # The time zone: the quarter of an hour that most pairs of a log time and a burst agree on.
    coarse = Counter(round((t - e) / 900) * 900 for t in finished for e in ends).most_common(1)[0][0]
    gaps = sorted(g for g in (min((t - coarse - e for t in finished), key=abs) for e in ends) if abs(g) < 30)
    return coarse + gaps[len(gaps) // 2]


def payload(link, frame):
    """The direction ("tx", "rx" or None), the EtherType and the offset of the network header, or None
    for frames without one."""
    if link == ETHERNET:
        kind, at = struct.unpack("!H", frame[12:14])[0], 14
        if kind == 0x8100:
            kind, at = struct.unpack("!H", frame[16:18])[0], 18
        way = "tx" if frame[6:12] == GUEST_MAC else "rx" if frame[0:6] == GUEST_MAC else None
        return way, kind, at
    start = struct.unpack("<H", frame[2:4])[0] if link == RADIOTAP else 0
    control, flags = frame[start], frame[start + 1]
    if (control >> 2) & 3 != 2 or flags & 0x40:
        return None  # not a data frame, or encrypted
    at = start + 24 + (6 if flags & 3 == 3 else 0)
    if (control >> 4) & 0x8:
        at += 2 + (4 if flags & 0x80 else 0)  # QoS control, and HT control when ordered
    if frame[at:at + 6] != LLC_SNAP:
        return None
    way = {1: "tx", 2: "rx"}.get(flags & 3)
    return way, struct.unpack("!H", frame[at + 6:at + 8])[0], at + 8


def ip(link, frame):
    """(direction, destination, IP length, source port, destination port) or None."""
    found = payload(link, frame)
    if found is None:
        return None
    way, kind, at = found
    if kind == 0x0800 and len(frame) >= at + 20:
        header = (frame[at] & 0x0F) * 4
        length, proto = struct.unpack("!H", frame[at + 2:at + 4])[0], frame[at + 9]
        dst = frame[at + 16:at + 20]
        ports = frame[at + header:at + header + 4]
    elif kind == 0x86DD and len(frame) >= at + 40:
        length, proto = struct.unpack("!H", frame[at + 4:at + 6])[0] + 40, frame[at + 6]
        dst = frame[at + 24:at + 40]
        ports = frame[at + 40:at + 44]
    else:
        return None
    sport, dport = struct.unpack("!HH", ports) if proto in (6, 17) and len(ports) == 4 else (0, 0)
    return way, ipaddress.ip_address(dst), length, sport, dport


def summarise(path, windows, shift=0.0):
    """Totals for each window (start, end, port or None) of wall-clock time, in one pass over the file;
    [shift] is added to the file's timestamps (see clock_shift)."""
    totals = [defaultdict(int) for _ in windows]
    for when, link, frame in packets(path):
        when += shift
        hits = [i for i, (start, end, _) in enumerate(windows) if start <= when <= end]
        if not hits:
            continue
        fact = ip(link, frame)
        if fact is None or fact[0] is None:
            continue
        way, dst, length, sport, dport = fact
        if dst.is_multicast or dst == BROADCAST:
            way = "group_" + way
        for i in hits:
            port = windows[i][2]
            if port and port not in (sport, dport):
                continue
            total = totals[i]
            total[way] += length
            total[way + "_packets"] += 1
            total["largest"] = max(total["largest"], length)
    keys = ("rx", "tx", "rx_packets", "tx_packets", "largest")
    return [{**{k: t[k] for k in keys}, **{k: v for k, v in t.items() if k.startswith("group")}} for t in totals]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("file")
    parser.add_argument("--from", dest="start", type=float, default=0)
    parser.add_argument("--to", dest="end", type=float, default=float("inf"))
    parser.add_argument("--port", type=int)
    args = parser.parse_args()
    print(json.dumps(summarise(args.file, [(args.start, args.end, args.port)])[0]))


if __name__ == "__main__":
    main()
