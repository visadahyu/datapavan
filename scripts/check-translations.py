#!/usr/bin/env python3
"""Checks what a translation can break without anyone reading it (ADR 0030): every string of English
exists in every language, with the same placeholders, tags and isolation marks; plurals have the forms
their language needs; store texts fit their limits; the website's texts have the shape of English's.

    scripts/check-translations.py [language ...]

It says nothing about whether a translation is good. That takes a person who speaks the language.
"""
import json
import re
import sys
import xml.etree.ElementTree as ET
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RES = ROOT / "android/app/src/main/res"
META = ROOT / "fastlane/metadata/android"
SITE = ROOT / "site/data/text"

# language: (resource directory, store directory, website file, plural forms from CLDR)
LANGUAGES = {
    "fr": ("values-fr", "fr-FR", "fr", {"one", "many", "other"}),
    "de": ("values-de", "de-DE", "de", {"one", "other"}),
    "fa": ("values-fa", "fa-IR", "fa", {"one", "other"}),
    "ru": ("values-ru", "ru-RU", "ru", {"one", "few", "many", "other"}),
    "zh": ("values-zh-rCN", "zh-CN", "zh", {"other"}),
    "es": ("values-es", "es-ES", "es", {"one", "many", "other"}),
    "ar": ("values-ar", "ar", "ar", {"zero", "one", "two", "few", "many", "other"}),
}
LIMITS = {"title.txt": 30, "short_description.txt": 80, "full_description.txt": 4000}
# Each versionCode's store changelog, as F-Droid and Google Play limit it.
CHANGELOG_LIMIT = 500
PLACEHOLDER = re.compile(r"%(?:\d+\$)?[-#+0,(]*\d*(?:\.\d+)?[a-zA-Z]")
MARKS = "⁦⁧⁨⁩‪‫‬‭‮‎‏"


def text_of(node):
    return "".join(node.itertext())


def raw_of(node):
    return ET.tostring(node, encoding="unicode", method="xml")


def fingerprint(node):
    """What must survive translation: placeholders, inline tags, line breaks and directional marks."""
    text = text_of(node)
    tags = Counter(child.tag for child in node.iter() if child is not node)
    return Counter(PLACEHOLDER.findall(text)), tags, Counter(c for c in text if c in MARKS), text.count("\\n")


def read_resources(path):
    root = ET.parse(path).getroot()
    strings = {n.get("name"): n for n in root.findall("string") if n.get("translatable") != "false"}
    plurals = {n.get("name"): {i.get("quantity"): i for i in n.findall("item")} for n in root.findall("plurals")}
    return strings, plurals


def check_resources(code, directory, forms, problems):
    path = RES / directory / "strings.xml"
    if not path.exists():
        problems.append(f"{code}: {path.relative_to(ROOT)} is missing")
        return
    base_strings, base_plurals = read_resources(RES / "values/strings.xml")
    try:
        strings, plurals = read_resources(path)
    except ET.ParseError as error:
        problems.append(f"{code}: not well-formed: {error}")
        return
    for name in sorted(set(base_strings) - set(strings)):
        problems.append(f"{code}: missing string {name}")
    for name in sorted(set(strings) - set(base_strings)):
        problems.append(f"{code}: string not in English: {name}")
    for name in sorted(set(base_strings) & set(strings)):
        a, b = fingerprint(base_strings[name]), fingerprint(strings[name])
        if a[0] != b[0]:
            problems.append(f"{code}: {name}: placeholders {dict(b[0])}, English has {dict(a[0])}")
        if a[1] != b[1]:
            problems.append(f"{code}: {name}: tags {dict(b[1])}, English has {dict(a[1])}")
        if a[2] != b[2]:
            problems.append(f"{code}: {name}: directional marks differ from English")
        if a[3] != b[3]:
            problems.append(f"{code}: {name}: line breaks differ from English")
        value = text_of(strings[name])
        if re.search(r"(?<!\\)['\"]", value) and not (value.startswith('"') and value.endswith('"')):
            problems.append(f"{code}: {name}: unescaped quote or apostrophe")
        if not value.strip():
            problems.append(f"{code}: {name}: empty")
    for name in sorted(set(base_plurals) - set(plurals)):
        problems.append(f"{code}: missing plural {name}")
    for name in sorted(set(base_plurals) & set(plurals)):
        if set(plurals[name]) != forms:
            problems.append(f"{code}: {name}: plural forms {sorted(plurals[name])}, needs {sorted(forms)}")
        wanted = {p for item in base_plurals[name].values() for p in PLACEHOLDER.findall(text_of(item))}
        for quantity, item in plurals[name].items():
            found = set(PLACEHOLDER.findall(text_of(item)))
            # A form for exactly one number may leave its number out, as "one" often does; nothing else may.
            if found - wanted or (quantity not in ("zero", "one", "two") and found != wanted):
                problems.append(f"{code}: {name} ({quantity}): placeholders {sorted(found)}, English has {sorted(wanted)}")


def check_store(code, directory, problems):
    files = dict(LIMITS)
    for changelog in sorted((META / "en-US" / "changelogs").glob("*.txt")):
        files[f"changelogs/{changelog.name}"] = CHANGELOG_LIMIT
    for file, limit in files.items():
        path = META / directory / file
        if not path.exists():
            problems.append(f"{code}: {path.relative_to(ROOT)} is missing")
        elif len(path.read_text(encoding="utf-8").strip()) > limit:
            problems.append(f"{code}: {file} is over {limit} characters")


def same_shape(a, b, where, problems, code):
    if isinstance(a, dict):
        if not isinstance(b, dict) or set(a) != set(b):
            problems.append(f"{code}: site {where}: keys differ")
            return
        for key in a:
            same_shape(a[key], b[key], f"{where}.{key}", problems, code)
    elif isinstance(a, list):
        if not isinstance(b, list) or len(a) != len(b):
            problems.append(f"{code}: site {where}: list length differs")
            return
        for i, (x, y) in enumerate(zip(a, b)):
            same_shape(x, y, f"{where}[{i}]", problems, code)
    elif isinstance(a, bool):
        if a != b:
            problems.append(f"{code}: site {where}: flag changed")
    elif not isinstance(b, str):
        problems.append(f"{code}: site {where}: not text")


def check_site(code, stem, problems):
    path = SITE / f"{stem}.json"
    if not path.exists():
        problems.append(f"{code}: {path.relative_to(ROOT)} is missing")
        return
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except ValueError as error:
        problems.append(f"{code}: {path.name}: {error}")
        return
    base = json.loads((SITE / "en.json").read_text(encoding="utf-8"))
    same_shape(base, data, "", problems, code)
    if data.get("lang") != stem:
        problems.append(f"{code}: site lang is {data.get('lang')}")
    # The anchors are links on the page, so they stay as they are.
    if [n[0] for n in data.get("nav", [])] != [n[0] for n in base["nav"]]:
        problems.append(f"{code}: site nav anchors changed")


def main():
    wanted = sys.argv[1:] or list(LANGUAGES)
    problems = []
    for code in wanted:
        directory, store, stem, forms = LANGUAGES[code]
        check_resources(code, directory, forms, problems)
        check_store(code, store, problems)
        check_site(code, stem, problems)
    for problem in problems:
        print(problem)
    print(f"translations: {len(wanted)} languages, {len(problems)} problems")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
