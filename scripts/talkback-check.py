#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Reads the record of scripts/talkback-walk.sh and says what fails (docs/ACCESSIBILITY.md).

    python3 -I scripts/talkback-check.py RECORD_DIR

Each file LOCALE-SCREEN.txt holds the walk of one screen: "Speech" lines (what TalkBack handed the speech engine, with
the language and voice it asked for, and the walk's gestures) and "Tree" lines (the screen's accessibility tree, one
node per line: depth|class|role|heading|text {locales}|description {locales}|state|pane|checked|selected|live|clickable|id).

What fails:
- a walk that ran to its cap without coming round to its first item (the record is cut off);
- an item TalkBack calls unlabelled;
- in Persian and Arabic, a text of the app in that script whose node carries no locale of its language (its voice
  would be the phone's);
- in every language, an utterance in Arabic, Cyrillic or Chinese script asked for in a language that is not
  written in it (a language's own name read in another's voice, say), apart from screens' names and TalkBack's
  action hints, which Android takes as plain text;
- a screen with no heading;
- a screen reached by a click whose name was not said on arriving: its pane's name, or the tab that was selected;
- the same sentence said twice with no gesture between (a live region that chatters).
"""
import re
import sys
from pathlib import Path

SCRIPT = re.compile(r"[\u0600-\u06FF]")
# A script, and the speech languages (ISO 639-2, as the speech engine is asked) written in it.
SCRIPTS = ((re.compile(r"[\u0600-\u06FF]"), ("fas", "ara")), (re.compile(r"[\u0400-\u04FF]"), ("rus",)),
           (re.compile(r"[\u4E00-\u9FFF]"), ("zho", "chi")))
CODES = {"fa": ("fa", "fas"), "ar": ("ar", "ara")}
# Screens opened by a click, where TalkBack should say something on arriving.
# Not "now-paused": its confirmation is a line shown only while the VPN runs, and the walk runs with the VPN off.
CLICKED = re.compile(r"^(apps|phone|network|settings.*|review|app|check)$")
# TalkBack's own hint, "Double-tap to <action>", carries the app's name for the action (an onClickLabel), which Compose
# takes as plain text: in the phone's language (a known gap in docs/ACCESSIBILITY.md), not counted.
HINT = re.compile(r"^(Double-tap|Double-tap and hold) to ")
# Known gaps, each in docs/ACCESSIBILITY.md, reported apart rather than failed:
# - the licences are a list of some hundred parts alike, walked for its first steps only;
PARTIAL = {"settings-licences"}
# - TalkBack 17 reads a choice row in the app's language, though each language's name in the language list carries
#   its own (the walk of 2026-11-23).
LANGUAGE_NAMES = {"\u2068" + n + "\u2069" for n in ("English", "Français", "Deutsch", "Español", "Русский", "简体中文", "العربية", "فارسی")}


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
    ends = [s.split(" ", 2)[2] for s in speech if s.startswith("gesture end ")]
    if ends and ends[-1] == "cap" and screen not in PARTIAL:
        problems.append("the walk ran to its cap without coming round: the record is cut off")
    titles = {n[7] for n in nodes if n[7]} | {t.split(" ", 1)[1] for t in tree if t.startswith("window ")}
    for s in said:
        asked, text = s.split("-")[0], s.split("\t", 1)[1]
        if text in titles or HINT.match(text) or text in LANGUAGE_NAMES:
            continue
        for script, languages in SCRIPTS:
            if script.search(text) and asked not in languages:
                problems.append(f"said in the wrong voice ({asked}): {text[:50]!r}")
                break
    if not any(n[3] == "heading" for n in nodes):
        problems.append("no heading")
    if locale in CODES:
        own = CODES[locale]
        for n in nodes:
            for field in (n[4], n[5]):
                text = re.sub(r"\s*\{[^}]*\}", "", field)
                locales = re.findall(r"\{([^}]*)\}", field)
                # Text of the app's own script, outside isolates, with no locale of its language.
                bare = re.sub(r"[\u2066-\u2068][^\u2069]*\u2069", "", text)
                if SCRIPT.search(bare) and not any(l.split("-")[0] in own for l in ",".join(locales).split(",") if l):
                    problems.append(f"text without its language: {text[:50]!r}")
    if CLICKED.match(screen):
        arrival = []
        for s in speech:
            if s.startswith("gesture next"):
                break
            if "\t" in s:
                arrival.append(s)
        # The screen's name: its pane's, or the words of the tab that is now selected (its own or its children's).
        names = {n[7] for n in nodes if n[7]}
        for i, n in enumerate(nodes):
            if n[9] != "selected":
                continue
            depth = int(n[0])
            for m in [n] + [m for m in nodes[i + 1:i + 6] if int(m[0]) > depth]:
                if m[4]:
                    names.add(re.sub(r"\s*\{[^}]*\}", "", m[4]))
        if not any(name and any(name in a.split("\t", 1)[1] for a in arrival) for name in names):
            problems.append(f"its name was not said on arriving (said: {' / '.join(a.split(chr(9), 1)[1] for a in arrival)[:80]!r})")
    # After the first swipe (arriving, TalkBack may say a window's name and then focus it), within one step.
    block, walking = [], False
    for s in speech:
        if s.startswith("gesture"):
            walking = walking or s.startswith("gesture next")
            block = []
            continue
        if "\t" not in s or not walking:
            continue
        text = s.split("\t", 1)[1]
        # TalkBack's own words ("Button", "Double-tap to activate") may come twice in one step; a sentence of the app
        # may not.
        if len(text) >= 12 and not HINT.match(text) and text in block:
            problems.append(f"said twice without a gesture: {text[:60]!r}")
        block.append(text)
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
