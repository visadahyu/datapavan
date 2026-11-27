#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Reads the network part's view "Now", or an app's history, from one uiautomator dump, for the emulator checks
(scripts/verify-activity.sh, verify-chain.sh; ADR 0046, decision 6): what the screen says of one app,
found by its package name, which each row shows under the app's label.

    python3 -I scripts/now-screen.py DUMP.xml [DUMP.xml...] PACKAGE

PACKAGE `-` reads the whole screen as one row, as for an app's history. Several dumps, as of a screen and
then of it scrolled, are read as one, in order.

Prints, one a line: `row` or `no-row`; `now STATE` (its words); for each state with traffic,
`bytes STATE SENT RECEIVED` in bytes (STATE one of background, notification, in-use, none, not-yet); `why
TEXT` for each reason bytes have no state; `through-tool`, `tool` (the chain's tool), `tool-unchained` (another tool),
`tool-left-out` (some of a tool's connections no longer shown) and `tool-live-only` (a tool's place shown there only,
for its window; the proxy record's unit D) where the row says so; `place NAME` for
each destination shown; `more-places TEXT` where the row shows only its first places and offers the rest behind a
button, TEXT the button's words; `state STATE` for each entry of a history; `off APPS BYTES` for the line on the
window while the screen was off; and `texts` with every text of the screen, joined by ` | `. Sizes are read
as Android writes them in English (SI units: 1 kB = 1,000 bytes); the isolates around them are dropped.
"""
import os
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


# Where a destination's name came from: the line under each destination's own.
NAMED = ("name the connection sent", "name from a DNS answer", "owner of the network", "no name known")


def row_end(lines, first, whole):
    """Where the row that holds lines[first] ends: before the next app's label, the line before the line
    before the next "Now: ...", since each row is its label, its package line and its state now; or at the
    section after the rows. A destination's name, however much it looks like a package, ends nothing (review
    c1 of W5's third part, screens, M1: a row ended at `network.test`, so a chained app's place went unseen)."""
    for i in range(first + 1, len(lines)):
        if lines[i].startswith("What this view cannot see"):
            return i
        # The row's own state line is the one after its package line; a later one is the next row's.
        if not whole and lines[i].startswith("Now: ") and i - 2 > first:
            return i - 2
    return len(lines)


def self_test():
    """The reader against dumps it must read, among them a row whose destination looks like a package."""
    import tempfile

    def dump(texts):
        nodes = "".join(f'<node text="{t}" content-desc="" bounds="[0,0][1,1]"/>' for t in texts)
        folder = tempfile.mkdtemp()
        path = os.path.join(folder, "dump.xml")
        with open(path, "w", encoding="utf-8") as f:
            f.write(f"<hierarchy>{nodes}</hierarchy>")
        return path

    def read(paths, package):
        import contextlib
        import io

        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            main(paths, package)
        return [line for line in out.getvalue().splitlines() if not line.startswith("texts ")]

    chained = ["Now", "Workload", "org.example.w", "Now: in use", "Sent 22 B and received 142 B while you were using it.",
               "Sent through your circumvention tool. Where it connected is not shown, because x is off."]
    # A chained app's row that shows a place named like a package: the check of item 5 must see it.
    shown = read([dump(chained + ["network.test", "name the connection sent", "Sent 1 B, received 2 B"])], "org.example.w")
    assert "place network.test" in shown, shown
    assert "through-tool" in shown and "bytes in-use 22 142" in shown, shown
    # The same row with no place: none read.
    assert not any(line.startswith("place ") for line in read([dump(chained)], "org.example.w"))
    # A row of more places than it shows first: its button is read with its words, so that the reader can tap it (CI run
    # 46052462725: the test server's address was the tool's sixth place, behind "Show 1 more place"); none without it.
    more = read([dump(chained + ["example.org", "name from a DNS answer", "Show 1 more place", "What this view cannot see"])],
                "org.example.w")
    assert "more-places Show 1 more place" in more and "open" not in more, more
    assert "more-places Show 3 more places" in read([dump(chained + ["Show 3 more places"])], "org.example.w")
    assert not any(line.startswith("more-places ") for line in shown), shown
    # A tool's row (the proxy record's unit D): another tool's, with a place shown there only, and connections no
    # longer shown; the chain's tool says only that it is.
    tool = ["Tool", "org.example.t", "Now: in the background", "A circumvention tool. Datapavan does not send apps through it.",
            "Some of its connections are not shown here. While x is off, Now shows where a circumvention tool connects.",
            "10.0.2.2", "no name known", "Sent 1 B, received 2 B",
            "Tool connected here, for itself or for an app that uses it. Now shows this while the connection is open."]
    read_tool = read([dump(tool)], "org.example.t")
    for line in ("tool-unchained", "tool-left-out", "tool-live-only", "place 10.0.2.2"):
        assert line in read_tool, read_tool
    assert "tool" not in read_tool, read_tool
    chained_tool = read([dump(["Tool", "org.example.t", "Now: in use", "Your circumvention tool. Its traffic includes x."])], "org.example.t")
    assert "tool" in chained_tool and "tool-unchained" not in chained_tool and "tool-live-only" not in chained_tool, chained_tool
    # Two rows: the first's places are its own, the second's not among them.
    two = chained + ["example.org", "name from a DNS answer", "Maps", "org.example.maps", "Now: in the background",
                     "maps.example", "name the connection sent", "What this view cannot see"]
    first = read([dump(two)], "org.example.w")
    assert "place example.org" in first and "place maps.example" not in first, first
    second = read([dump(two)], "org.example.maps")
    assert "place maps.example" in second and "now in the background" in second, second
    # A package whose name begins another's: each row is its own (the workload apps are w, w.b and w.c).
    prefix = chained + ["B", "org.example.w.b", "Now: in the background", "Sent 3 B and received 4 B while you were not using it."]
    assert "now in use" in read([dump(prefix)], "org.example.w"), read([dump(prefix)], "org.example.w")
    assert "now in the background" in read([dump(prefix)], "org.example.w.b")
    assert "no-row" in read([dump(chained)], "org.example")
    # Two dumps of one list scrolled half a page: the lines both show are read once, so the row's bytes are one line.
    upper = ["Now", "Showing one app."] + chained[1:5]
    lower = chained[3:] + ["What this view cannot see"]
    once = read([dump(upper), dump(lower)], "org.example.w")
    assert [line for line in once if line.startswith("bytes ")] == ["bytes in-use 22 142"], once
    assert "through-tool" in once and "open" not in once, once
    # A row that runs to the end of the texts read is open, as it may go on below the screen; one the next row or the
    # section after the rows ends is not.
    assert "open" in read([dump(chained)], "org.example.w"), read([dump(chained)], "org.example.w")
    assert "open" not in first and "open" not in read([dump(prefix)], "org.example.w")
    print("now-screen.py: self-test passed")
    return 0


def joined(dumps):
    """The texts of dumps of one list scrolled down between them, in order: of each dump after the first, what it
    repeats of the one before (the longest run that ends the one and begins the other) is read once, so that no line of
    a row that both show counts twice (unit D's activity check: a row's bytes read twice summed as two numbers)."""
    every = []
    for found in dumps:
        overlap = next((k for k in range(min(len(every), len(found)), 0, -1) if every[-k:] == found[:k]), 0)
        every += found[overlap:]
    return every


def main(paths, package):
    every = joined([texts(path) for path in paths])
    text = "\n".join(every)
    out = []
    off = re.search(r"While the screen was off \(([^)]*)\), (\d+) apps? you were not using sent " + SIZE, text)
    if off:
        out.append(f"off {off.group(2)} {size(off.group(3), off.group(4))}")
    elif "no app you were not using sent data" in text:
        out.append("off 0 0")
    # "-": the whole screen, as an app's history, which names the app in its title. Of a screen read twice, the
    # second time scrolled, the row is read from the last dump that names the app.
    lines = every
    if package == "-":
        first = 0
    else:
        # The package as a whole name: org.example.w is not in org.example.w.b's row.
        named = re.compile(r"(?<![\w.])" + re.escape(package) + r"(?!\w|\.\w)")
        at = [i for i, line in enumerate(lines) if named.search(line)]
        first = at[-1] if at else -1
    if first < 0:
        out.append("no-row")
    else:
        out.append("row")
        end = row_end(lines, first, package == "-")
        # A row that runs to the last text read may go on below the screen's edge: the reader then reads further.
        if end == len(lines):
            out.append("open")
        row = "\n".join(lines[first:end])
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
        if "A circumvention tool. Datapavan does not send apps through it." in row:
            out.append("tool-unchained")
        if "Some of its connections are not shown here." in row:
            out.append("tool-left-out")
        if "connected here, for itself or for an app that uses it." in row:
            out.append("tool-live-only")
        for match in re.finditer(r"(?:\n|, )([^\n,]+)(?:\n|, )(" + "|".join(NAMED) + ")", "\n" + row):
            out.append(f"place {match.group(1)}")
        # A row of more places than it shows first ends them with a button for the rest (NowScreen's FIRST_PLACES).
        for match in re.finditer(r"^(Show [0-9]+ more places?)$", row, re.MULTILINE):
            out.append(f"more-places {match.group(1)}")
        for match in re.finditer(r"State: ([a-z ]+)", row):
            out.append(f"state {match.group(1).strip()}")
    out.append("texts " + " | ".join(every))
    print("\n".join(out))
    return 0


if __name__ == "__main__":
    if sys.argv[1:] == ["--self-test"]:
        sys.exit(self_test())
    sys.exit(main(sys.argv[1:-1], sys.argv[-1]))
