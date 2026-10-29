# SPDX-License-Identifier: Apache-2.0
"""Accessibility check of one uiautomator dump of Datapavan's screen.

Every clickable element must have a label that a screen reader can announce (its own text or content
description, or one of its children's), and must be at least the minimum touch size in both
directions. Elements cut off by the edge of a scrolling list are skipped: the dump measures only their
visible part and leaves out the children that are off screen, label included.

    python3 -I scripts/a11y-check.py DUMP.xml MIN_SIZE_PX
"""
import re
import sys
import xml.etree.ElementTree as ET

PACKAGE = "org.visadahyu.datapavan"


def bounds(node):
    return tuple(int(v) for v in re.findall(r"\d+", node.get("bounds", "")))


def main() -> int:
    path, min_px = sys.argv[1], int(sys.argv[2])
    root = ET.parse(path).getroot()
    parents = {child: parent for parent in root.iter() for child in parent}
    problems = []
    for node in root.iter("node"):
        if node.get("clickable") != "true" or node.get("package") != PACKAGE:
            continue
        box = bounds(node)
        clipped = False
        ancestor = parents.get(node)
        while ancestor is not None:
            if ancestor.get("scrollable") == "true":
                outer = bounds(ancestor)
                clipped = box[1] <= outer[1] or box[3] >= outer[3]
                break
            ancestor = parents.get(ancestor)
        if clipped:
            continue
        label = next((n.get("text") or n.get("content-desc") for n in node.iter() if n.get("text") or n.get("content-desc")), "")
        if not label:
            problems.append(f"clickable element without a label at {node.get('bounds')}")
        if box[2] - box[0] < min_px or box[3] - box[1] < min_px:
            problems.append(f"touch target smaller than 48 dp at {node.get('bounds')}: {label[:40]!r}")
    for problem in problems:
        print(f"{path}: {problem}", file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
