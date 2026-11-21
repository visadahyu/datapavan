# SPDX-License-Identifier: CC0-1.0
"""How much of the trackers εxodus finds most often hosts.tsv and waiting.tsv cover.

Usage: python3 -I coverage.py TRACKERS_PAGE
TRACKERS_PAGE is a saved copy of εxodus's tracker list, https://reports.exodus-privacy.eu.org/en/trackers/ (each
tracker with "found in N applications"); it is ODbL and is not kept in this repository.

A row joins a tracker when an alternative of the tracker's code signature (data/exodus/trackers.tsv, column 5) is a
prefix of the row's classes, or the classes a prefix of it; a code row also joins the trackers its condition's
prefixes join. A waiting row joins the tracker its exodus column names. A tracker counts as covered (1) when a host row
joins it and no waiting row does, partly (0.5) when both do, waiting (0) otherwise.
"""
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))


def rows(path):
    with open(path, encoding="utf-8") as f:
        return [line.rstrip("\n").split("\t") for line in f if line.strip() and not line.startswith("#")]


def main(page):
    trackers = {}
    for f in rows(os.path.join(HERE, "..", "exodus", "trackers.tsv")):
        alts = [a.replace("\\.", ".") for a in f[4].split("|")] if len(f) > 4 and f[4] else []
        trackers[f[0]] = (f[1], alts)
    with open(page, encoding="utf-8") as f:
        found = re.findall(r'href="/en/trackers/(\d+)/">\s*(.*?)&nbsp;.*?found in (\d+) applications', f.read(), re.S)
    apps = {i: int(n) for i, _, n in found}

    def join(prefix):
        return {i for i, (_, alts) in trackers.items() if any(a.startswith(prefix) or prefix.startswith(a) for a in alts)}

    hosted, unjoined = set(), []
    for f in rows(os.path.join(HERE, "hosts.tsv")):
        prefixes = [f[2]] + (re.split(r"[ |]", f[4].replace("block-with ", "").replace("keep-with ", "")) if f[3] == "code" else [])
        ids = set().union(*(join(p) for p in prefixes if p))
        hosted |= ids
        if not join(f[2]):
            unjoined.append(f[0])
    names = {name: i for i, (name, _) in trackers.items()}
    waiting = {names[f[2]] for f in rows(os.path.join(HERE, "waiting.tsv"))}

    def score(i):
        return 1.0 if i in hosted and i not in waiting else 0.5 if i in hosted else 0.0

    ranked = sorted(apps, key=lambda i: -apps[i])
    top = ranked[:50]
    full = sum(1 for i in top if score(i) == 1.0)
    part = sum(1 for i in top if score(i) == 0.5)
    print(f"top 50 by apps: {full} covered, {part} partly, {50 - full - part} waiting")
    for label, ids in (("top 50", top), ("all trackers", ranked)):
        total = sum(apps[i] for i in ids)
        print(f"weighted by apps, {label}: {100 * sum(apps[i] * score(i) for i in ids) / total:.1f}%")
    print(f"host rows joined to no εxodus tracker: {len(unjoined)} ({', '.join(unjoined)})")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    main(sys.argv[1])
