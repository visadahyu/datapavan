#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Writes, as PEM, the certificate chain of the last hardware check that a debug build logged (ADR 0040).

    adb logcat -d -s DatapavanAttestationLab:I | scripts/attestation-chain-from-logcat.py > chain.pem

Debug builds log each check as a summary line, each certificate as base64 DER in parts, and "end"
(android/app/src/debug/.../audit/AttestationLab.kt). The summary goes to stderr. Fails unless a whole check
was logged.
"""
import base64
import re
import sys
import textwrap

TAG = "DatapavanAttestationLab"
PART = re.compile(r"certificate (\d+)/(\d+) part (\d+)/(\d+) ([A-Za-z0-9+/=]+)$")


def main():
    checks, current = [], None
    for raw in sys.stdin:
        if TAG not in raw:
            continue
        # "... I DatapavanAttestationLab: message" (threadtime) or "I/DatapavanAttestationLab( 123): message" (brief).
        rest = raw.split(TAG, 1)[1].rstrip("\r\n")
        message = rest.split(": ", 1)[1] if ": " in rest else rest.strip()
        if message.startswith("check "):
            current = {"summary": message, "parts": {}}
        elif message == "end" and current is not None:
            checks.append(current)
            current = None
        elif current is not None:
            match = PART.search(message)
            if match:
                index, count, part, parts, text = match.groups()
                current["parts"].setdefault((int(index), int(count)), {})[int(part)] = (int(parts), text)
    if not checks:
        sys.exit("no whole hardware check in the log")
    last = checks[-1]
    print(last["summary"], file=sys.stderr)
    for (index, count), parts in sorted(last["parts"].items()):
        total = next(iter(parts.values()))[0]
        if sorted(parts) != list(range(1, total + 1)):
            sys.exit(f"certificate {index}/{count} is incomplete")
        der = base64.b64decode("".join(parts[p][1] for p in sorted(parts)))
        body = "\n".join(textwrap.wrap(base64.b64encode(der).decode("ascii"), 64))
        print(f"-----BEGIN CERTIFICATE-----\n{body}\n-----END CERTIFICATE-----")


if __name__ == "__main__":
    main()
