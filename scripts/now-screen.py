#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Reads Watch's view "Now", or an app's history, from one uiautomator dump, for the emulator checks
(scripts/verify-activity.sh, verify-chain.sh; ADR 0046, decision 6): what the screen says of one app,
found by its package name, which each row shows under the app's label.

    python3 -I scripts/now-screen.py DUMP.xml [DUMP.xml...] PACKAGE

PACKAGE `-` reads the whole screen as one row, as for an app's history. Several dumps, as of a screen and
then of it scrolled, are read as one, in order.

Prints, one a line: `row` or `no-row`; `now STATE` (its words); for each state with traffic,
`bytes STATE SENT RECEIVED` in bytes (STATE one of background, notification, in-use, none, not-yet); `why
TEXT` for each reason bytes have no state; `through-tool` and `tool` where the row says so; `place NAME` for
each destination shown; `state STATE` for each entry of a history; `off APPS BYTES` for the line on the
window while the screen was off; and `texts` with every text of the screen, joined by ` | `. Sizes are read
as Android writes them in English (SI units: 1 kB = 1,000 bytes); the isolates around them are dropped.
"""
import re
import sys
import xml.etree.ElementTree as ET

UNITS = {"B": 1, "kB": 1_000, "MB": 1_000_000, "GB": 1_000_000_000}
SIZE = r"([0-9][0-9.,]*) (B|kB|MB|GB)"
STATES = {
    "while you were not using it": "background",
    "while its notification could show": "notification",
    "while you were using it": "in-use",
    "with no state": "none",
    "state not known yet": "not-yet",
}
ISOLATES = dict.fromkeys(map(ord, "⁦⁧⁨⁩"))


def size(number, unit):
    return round(float(number.replace(",", "")) * UNITS[unit])


def texts(path):
    root = ET.parse(path).getroot()
    found = []
    for node in root.iter("node"):
        for attribute in ("text", "content-desc"):
            value = (node.get(attribute) or "").translate(ISOLATES)
            if value:
                found.append(value)
    return found


def main(paths, package):
    every = [text for path in paths for text in texts(path)]
    text = "\n".join(every)
    out = []
    off = re.search(r"While the screen was off \(([^)]*)\), (\d+) apps? you were not using sent " + SIZE, text)
    if off:
        out.append(f"off {off.group(2)} {size(off.group(3), off.group(4))}")
    elif "no app you were not using sent data" in text:
        out.append("off 0 0")
    # "-": the whole screen, as an app's history, which names the app in its title. Of a screen read twice, the
    # second time scrolled, the row is read from the last dump that names the app.
    start = 0 if package == "-" else text.rfind(package)
    if start < 0:
        out.append("no-row")
    else:
        out.append("row")
        # The row runs to the next app's row, which begins with its label, or to the section after the rows.
        rest = text[start + len(package):]
        ends = [m.start() for m in re.finditer(r"\n[a-z][a-z0-9_]*(\.[a-z0-9_]+)+\n|What this view cannot see", rest)]
        row = text[start: start + len(package) + (ends[0] if ends else len(rest))]
        now = re.search(r"Now: ([a-z ]+)", row)
        if now:
            out.append(f"now {now.group(1).strip()}")
        for match in re.finditer(r"Sent " + SIZE + r" and received " + SIZE + r",? ([a-z ]+[a-z])", row):
            for words, state in STATES.items():
                if match.group(5).startswith(words):
                    out.append(f"bytes {state} {size(match.group(1), match.group(2))} {size(match.group(3), match.group(4))}")
        for match in re.finditer(r"with no state\. ([^\n,]*\.)", row):
            out.append(f"why {match.group(1)}")
        if "Sent through your circumvention tool" in row:
            out.append("through-tool")
        if "Your circumvention tool." in row:
            out.append("tool")
        for match in re.finditer(
            r"(?:\n|, )([^\n,]+)(?:\n|, )(name the connection sent|name from a DNS answer|owner of the network|no name known)", "\n" + row
        ):
            out.append(f"place {match.group(1)}")
        for match in re.finditer(r"State: ([a-z ]+)", row):
            out.append(f"state {match.group(1).strip()}")
    out.append("texts " + " | ".join(every))
    print("\n".join(out))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:-1], sys.argv[-1]))
