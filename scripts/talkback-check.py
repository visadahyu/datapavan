#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Reads the record of scripts/talkback-walk.sh and says what fails (docs/ACCESSIBILITY.md).

    python3 -I scripts/talkback-check.py RECORD_DIR

Each file LOCALE-SCREEN.txt holds the walk of one screen: "Speech" lines (what TalkBack handed the speech engine, with
the language and voice it asked for, and the walk's gestures) and "Tree" lines (the screen's accessibility tree, one
node per line: depth|class|role|heading|text {locales}|description {locales}|state|pane|checked|selected|live|clickable|id).

What fails:
- an item TalkBack calls unlabelled;
- in Persian and Arabic, a text of the app in that script whose node carries no locale of its language (its voice
  would be the phone's), and an utterance of that script asked for in another language although the app's text is
  marked;
- a screen with no heading;
- a screen reached by a click with nothing said on arriving;
- the same utterance said three times or more with no gesture between (a live region that chatters).
"""
import re
import sys
from pathlib import Path

SCRIPT = re.compile(r"[؀-ۿ]")
CODES = {"fa": ("fa", "fas"), "ar": ("ar", "ara")}
# Screens opened by a click, where TalkBack should say something on arriving.
# Not "now-paused": its confirmation is a line shown only while the VPN runs, and the walk runs with the VPN off.
CLICKED = re.compile(r"^(apps|phone|network|settings.*|review|app|check)$")
# TalkBack's own hint, "Double-tap to <action>", carries the app's name for the action (an onClickLabel), which Compose
# takes as plain text: in the phone's language (a known gap in docs/ACCESSIBILITY.md), not counted.
HINT = re.compile(r"^(Double-tap|Double-tap and hold) to ")


def read(path):
    speech, tree = [], []
    for line in path.read_text(encoding="utf-8").splitlines():
        kind, _, rest = line.partition("\t")
        (speech if kind == "Speech" else tree).append(rest)
    return speech, tree


def check(path):
    locale, _, screen = path.stem.partition("-")
    speech, tree = read(path)
    problems = []
    said = [s for s in speech if "\t" in s]
    if any("nlabel" in s.lower() for s in said):
        problems.append("TalkBack calls an item unlabelled")
    nodes = [t.split("|") for t in tree if t.count("|") >= 12]
    if not any(n[3] == "heading" for n in nodes):
        problems.append("no heading")
    if locale in CODES:
        own = CODES[locale]
        for n in nodes:
            for field in (n[4], n[5]):
                text = re.sub(r"\s*\{[^}]*\}", "", field)
                locales = re.findall(r"\{([^}]*)\}", field)
                # Text of the app's own script, outside isolates, with no locale of its language.
                bare = re.sub(r"[⁦-⁨][^⁩]*⁩", "", text)
                if SCRIPT.search(bare) and not any(l.split("-")[0] in own for l in ",".join(locales).split(",") if l):
                    problems.append(f"text without its language: {text[:50]!r}")
        # A pane's or a window's title is a plain string, which no locale can mark: said in the phone's language (a
        # known gap), and not counted here.
        titles = {n[7] for n in nodes if n[7]} | {t.split(" ", 1)[1] for t in tree if t.startswith("window ")}
        wrong = [s for s in said if SCRIPT.search(s.split("\t", 1)[1]) and s.split("-")[0] not in own
                 and s.split("\t", 1)[1] not in titles and not HINT.match(s.split("\t", 1)[1])]
        if wrong:
            problems.append(f"{len(wrong)} utterances of {locale} text asked for in another language, e.g. {wrong[0][:60]!r}")
    if CLICKED.match(screen):
        arrival = []
        for s in speech:
            if s.startswith("gesture next"):
                break
            if "\t" in s:
                arrival.append(s)
        if not arrival:
            problems.append("nothing said on arriving")
    run, last = 0, None
    for s in speech:
        if s.startswith("gesture"):
            run, last = 0, None
            continue
        if "\t" not in s:
            continue
        run = run + 1 if s == last else 1
        last = s
        if run == 3:
            problems.append(f"said three times without a gesture: {s[:60]!r}")
    return problems


def main():
    record = Path(sys.argv[1])
    files = sorted(p for p in record.glob("*-*.txt") if p.stem != "about")
    failed = 0
    for path in files:
        problems = check(path)
        failed += bool(problems)
        print(f"{'ok ' if not problems else 'FAIL'} {path.stem}" + "".join(f"\n     {p}" for p in dict.fromkeys(problems)))
    print(f"talkback walk: {len(files)} screens, {failed} with problems")
    return 1 if failed or not files else 0


if __name__ == "__main__":
    sys.exit(main())
