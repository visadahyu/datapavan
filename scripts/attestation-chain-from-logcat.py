#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Writes, as PEM, the certificate chain of the last hardware check that a debug build logged (ADR 0040).

    adb shell run-as org.visadahyu.datapavan touch files/attestation-lab    # turn the record on
    (run the audit)
    adb logcat -d -s DatapavanAttestationLab:I | scripts/attestation-chain-from-logcat.py > chain.pem
    adb shell run-as org.visadahyu.datapavan rm files/attestation-lab       # and off again

Debug builds log each check, while the lab has turned the record on, as a summary line, each certificate as
base64 DER in parts, and "end" (android/app/src/debug/.../audit/AttestationLab.kt). The summary goes to
stderr. Fails unless a whole check was logged: every certificate that the summary counts, each with all its
parts, and nothing else. A certificate chain carries more than its verdict (ADR 0040, "The lab record"):
publish one only from a lab device and a build signed with a throwaway key.
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
    counted = re.search(r" certificates=(\d+)$", last["summary"])
    if not counted:
        sys.exit("the summary does not count the certificates")
    count = int(counted.group(1))
    # Every certificate the summary counts, each numbered of that count, and no other.
    if sorted(last["parts"]) != [(index, count) for index in range(1, count + 1)]:
        seen = ", ".join(f"{index}/{of}" for index, of in sorted(last["parts"])) or "none"
        sys.exit(f"the summary counts {count} certificates, the log holds {seen}")
    pems = []
    for (index, _), parts in sorted(last["parts"].items()):
        totals = {total for total, _ in parts.values()}
        if len(totals) != 1 or sorted(parts) != list(range(1, totals.pop() + 1)):
            sys.exit(f"certificate {index}/{count} is incomplete")
        der = base64.b64decode("".join(parts[p][1] for p in sorted(parts)), validate=True)
        body = "\n".join(textwrap.wrap(base64.b64encode(der).decode("ascii"), 64))
        pems.append(f"-----BEGIN CERTIFICATE-----\n{body}\n-----END CERTIFICATE-----")
    print("\n".join(pems))


if __name__ == "__main__":
    main()
