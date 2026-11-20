# SPDX-License-Identifier: Apache-2.0
"""Writes the ICANN section of the public suffix list (publicsuffix.org) for Watch's resolver (W8, part 1, fix
round, review S-C1): a network's search domain that is a public suffix (`com`, `co.uk`) is never the network's
own, and Watch ignores it.

    python3 -I data/public-suffix/update.py PATH-TO-public_suffix_list.dat [version of the copy]

It writes icann.dat and SOURCE next to itself. It takes the list from a copy on disk (Debian's `publicsuffix`
package keeps one at /usr/share/publicsuffix/public_suffix_list.dat), never from the network, and fails when the
list's licence notice, its first three lines, is no longer the one recorded here (ADR 0015, decision 9), when the
ICANN section's markers are missing, or when the count of rules moves by more than a tenth from the last file,
until a person runs it again with DATAPAVAN_ACCEPT_CHANGE=1.

icann.dat: a header of comment lines (`//`), then one rule per line as the list writes it (`co.uk`, a wildcard
`*.ck`, an exception `!www.ck`), lower case, every label that is not ASCII written as its A-label (`xn--` and
Punycode, RFC 3492), as a search domain arrives from DHCP. The private section (companies' own suffixes, such as
`github.io`) is left out: the brief asked for the ICANN section, the suffixes of the domain registries.
"""

import hashlib
import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
# The list's licence notice as read on 2026-11-20: its first three lines, the MPL-2.0 header.
NOTICE_SHA256 = "775e2d3cd4efb1ac4d64b6d65e799ccaea47aec4f73c68bf6b4f2e093e6d1b2d"


def a_label(label: str) -> str:
    """The label as DNS carries it: an A-label when it is not ASCII."""
    if label.isascii():
        return label
    return "xn--" + label.encode("punycode").decode("ascii")


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__, file=sys.stderr)
        return 2
    source = Path(sys.argv[1])
    version = sys.argv[2] if len(sys.argv) > 2 else "unknown"
    raw = source.read_bytes()
    text = raw.decode("utf-8")
    lines = text.splitlines()
    notice = "\n".join(lines[:3]).encode("utf-8")
    notice_sha = hashlib.sha256(notice).hexdigest()
    if notice_sha != NOTICE_SHA256 and os.environ.get("DATAPAVAN_ACCEPT_CHANGE") != "1":
        print(f"the list's licence notice changed (sha256 {notice_sha}): read it, then update NOTICE_SHA256",
              file=sys.stderr)
        return 1
    try:
        start = lines.index("// ===BEGIN ICANN DOMAINS===")
        end = lines.index("// ===END ICANN DOMAINS===")
    except ValueError:
        print("the ICANN section's markers are missing", file=sys.stderr)
        return 1
    rules = []
    for line in lines[start + 1:end]:
        rule = line.strip().split()[0] if line.strip() else ""
        if not rule or rule.startswith("//"):
            continue
        exception = rule.startswith("!")
        labels = [a_label(label) for label in rule.removeprefix("!").lower().split(".")]
        rules.append(("!" if exception else "") + ".".join(labels))
    target = HERE / "icann.dat"
    if target.exists() and os.environ.get("DATAPAVAN_ACCEPT_CHANGE") != "1":
        before = sum(1 for line in target.read_text().splitlines() if line and not line.startswith("//"))
        if before and abs(len(rules) - before) > before // 10:
            print(f"{before} rules before, {len(rules)} now: run again with DATAPAVAN_ACCEPT_CHANGE=1",
                  file=sys.stderr)
            return 1
    header = [
        "// SPDX-License-Identifier: MPL-2.0",
        "// The ICANN section of the public suffix list (https://publicsuffix.org), Mozilla Public License 2.0",
        "// (LICENSE). Written by update.py beside this file, from the list's copy that SOURCE names: lower case,",
        "// every label not in ASCII as its A-label. One rule per line, as the list writes it.",
    ]
    target.write_text("\n".join(header + rules) + "\n")
    written = target.read_bytes()
    (HERE / "SOURCE").write_text(
        "\n".join([
            "# SPDX-License-Identifier: CC0-1.0",
            "list: https://publicsuffix.org/list/public_suffix_list.dat, read from a copy on disk",
            f"copy: {version}",
            f"file-sha256: {hashlib.sha256(raw).hexdigest()}",
            "licence-statement: the list's first three lines, the MPL-2.0 notice",
            f"licence-sha256: {notice_sha}",
            "section: ICANN (between // ===BEGIN ICANN DOMAINS=== and // ===END ICANN DOMAINS===)",
            f"rules: {len(rules)}",
            f"icann.dat-sha256: {hashlib.sha256(written).hexdigest()}",
        ]) + "\n"
    )
    print(f"{len(rules)} rules written to {target}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
