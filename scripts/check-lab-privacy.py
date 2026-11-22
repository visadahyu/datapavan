#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Fails if a published gaps run could tell where the computer that ran it is (ADR 0048).

    scripts/check-lab-privacy.py [docs/platform-gaps]
    scripts/check-lab-privacy.py --self-test

An emulator reaches the Internet through its computer's network, and the image's own components talk to
servers near it: their addresses and names would name the network's provider and region. So in the runs'
files and the results' measured values:
- every flow (runs/*/flows-*.txt) goes to the lab's own addresses or is the placeholder "other:<port>", with
  names only under .example or another name reserved for testing (lab/redact-flows.awk): its DNS name, the
  tenth field since W5's first part, and its name, the rest of the line, each one name with no space (a flow
  written before has its name tenth and nothing after);
- no IPv4 address lies outside 10/8, 127/8 and the documentation ranges, and no IPv6 address is global.
The images' identity (image.txt, and each run's rows.csv) holds versions, not addresses, and is left out of
the address scan.
"""
import csv
import ipaddress
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
OURS = re.compile(r"^(10\.0\.2\.\d+|10\.1\.10\.\d+|10\.215\.173\.\d+|127\.\d+\.\d+\.\d+|\[::1\]|\[fd00:1:fd00:1:fd00:1:fd00:[0-9a-f]+\])$")
RESERVED = re.compile(r"^(-|[^ ]*(^|\.)(example|test|invalid|localhost)|[^ ]*(^|\.)example\.(com|net|org))$")
# A dotted quad after "/" is a version (a User-Agent's "Chrome/145.0.0.0"), not an address.
IPV4 = re.compile(r"(?<![\w./])(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?![\w.])")
IPV6 = re.compile(r"(?<![\w:])([0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{0,4}){2,7})(?![\w:])")
ALLOWED4 = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "127.0.0.0/8", "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]


def shown(path):
    """`path` as a problem names it: from the repository, or in full outside it, as in the self-test."""
    return path.relative_to(ROOT) if path.is_relative_to(ROOT) else path


def host(address):
    return address[:address.index("]") + 1] if address.startswith("[") else address.rsplit(":", 1)[0]


def addresses(text):
    found = []
    for match in IPV4.finditer(text):
        try:
            address = ipaddress.ip_address(match.group(1))
        except ValueError:
            continue
        if not any(address in network for network in ALLOWED4):
            found.append(str(address))
    for match in IPV6.finditer(text):
        try:
            address = ipaddress.ip_address(match.group(1).split("%")[0])
        except ValueError:
            continue
        if address in ipaddress.ip_network("2000::/3"):
            found.append(str(address))
    return found


def main(base):
    problems = []
    for path in sorted(base.glob("runs/*/flows-*.txt")):
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            fields = line.split(" ")
            if len(fields) < 4:
                continue
            dns_name = fields[9] if len(fields) > 9 else "-"
            name = " ".join(fields[10:]) or "-"
            destination_ours = OURS.match(host(fields[2])) or re.fullmatch(r"other:(\d+|-)", fields[2])
            names_reserved = RESERVED.match(dns_name) and RESERVED.match(name)
            if not destination_ours or not (fields[1] == "-" or OURS.match(host(fields[1]))) or not names_reserved:
                problems.append(f"{shown(path)}:{number}: a flow that is not the lab's: {line}")
    for path in sorted(base.glob("runs/**/*")):
        # image.txt and rows.csv hold the emulator's version, dotted like an address; rows.csv's measured
        # values are checked in results.csv below.
        if not path.is_file() or path.name in ("image.txt", "rows.csv") or path.suffix == ".png":
            continue
        for found in addresses(path.read_text(encoding="utf-8", errors="replace")):
            problems.append(f"{shown(path)}: holds the address {found}")
    results = base / "results.csv"
    if results.exists():
        for row in csv.DictReader(results.open(encoding="utf-8")):
            for found in addresses(row["measured"]):
                problems.append(f"{shown(results)}: a row of {row['behaviour']} holds the address {found}")
    for problem in problems:
        print(problem, file=sys.stderr)
    return 1 if problems else 0


def self_test():
    """The redaction and this check read the dump's flows as the network part writes them since W5's first part, with a
    DNS name before the name: a flow to the lab whose name is reserved and whose DNS name is not leaked through both
    while they read the two as one name (review 1 of W5's first part, names, finding 3)."""
    import subprocess
    import tempfile
    leaking = "tcp 10.1.10.1:40000 10.0.2.2:443 2000 opened tls - - - realsite.com probe.gaps.example"
    kept = "udp 10.1.10.1:40001 10.0.2.2:53 2000 opened dns - plain - - probe.gaps.example"
    written_before = "tcp 10.1.10.1:40002 10.0.2.2:443 2000 opened tls - - - probe.gaps.example"
    elsewhere = "tcp 10.1.10.1:40003 93.184.216.34:443 2000 opened tls - - - - www.example.com"
    failures = []
    redacted = subprocess.run(
        ["awk", "-f", str(ROOT / "lab" / "redact-flows.awk")],
        input="\n".join([leaking, kept, elsewhere]) + "\n", capture_output=True, text=True, check=True,
    ).stdout.splitlines()
    expected = [
        "tcp 10.1.10.1:40000 10.0.2.2:443 2000 opened tls - - - - probe.gaps.example",
        kept,
        "tcp - other:443 2000 - - - - - - -",
    ]
    if redacted != expected:
        failures.append(f"the redaction gave {redacted}")
    with tempfile.TemporaryDirectory() as base:
        runs = pathlib.Path(base) / "runs" / "run"
        runs.mkdir(parents=True)
        (runs / "flows-leaking.txt").write_text(leaking + "\n", encoding="utf-8")
        if main_quiet(pathlib.Path(base)) == 0:
            failures.append("a flow with a DNS name of the network passed the check")
        (runs / "flows-leaking.txt").write_text("\n".join(redacted + [written_before]) + "\n", encoding="utf-8")
        if main_quiet(pathlib.Path(base)) != 0:
            failures.append("the redacted flows, and one written before W5, failed the check")
    for failure in failures:
        print(failure, file=sys.stderr)
    print("lab privacy: the redaction and the check read the DNS name apart" if not failures else "self-test failed")
    return 1 if failures else 0


def main_quiet(base):
    """main(base), its problems not printed, whose paths it reports relative to the repository."""
    import contextlib
    import io
    with contextlib.redirect_stderr(io.StringIO()):
        return main(base)


if __name__ == "__main__":
    if sys.argv[1:] == ["--self-test"]:
        sys.exit(self_test())
    sys.exit(main(pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "docs" / "platform-gaps"))
