#!/usr/bin/env python3
# Keeps the English strings plain (DESIGN.md, "Plain language"): every string or plural of at least
# twelve words must reach a Flesch-Kincaid grade of 10 or lower, the level that plain-language guides
# such as the US Federal Plain Language Guidelines aim below. The translations follow the English.
# Licence notices, which must name the licence, are exempt.
#
#   scripts/plain-language.py [strings.xml]
import re
import sys
import xml.etree.ElementTree as ET

MAX_GRADE = 10.0
MIN_WORDS = 12
EXEMPT = {"trackers_source"}


def syllables(word):
    word = re.sub(r"[^a-z]", "", word.lower())
    if len(word) <= 3:
        return 1
    word = re.sub(r"(?:[^laeiouy]es|ed|[^laeiouy]e)$", "", word)
    word = re.sub(r"^y", "", word)
    return max(1, len(re.findall(r"[aeiouy]{1,2}", word)))


def grade(text):
    words = re.findall(r"[A-Za-z][A-Za-z'-]*", text)
    sentences = max(1, len(re.findall(r"[.!?;:](\s|$)", text)))
    return len(words), 0.39 * len(words) / sentences + 11.8 * sum(map(syllables, words)) / max(1, len(words)) - 15.59


def main(path):
    failed = []
    for element in ET.parse(path).getroot():
        name = element.get("name")
        if name in EXEMPT:
            continue
        if element.tag == "plurals":
            texts = ["".join(item.itertext()) for item in element if item.get("quantity") == "other"]
        else:
            texts = ["".join(element.itertext())]
        for text in texts:
            # Placeholders read as one short word.
            words, level = grade(re.sub(r"%\d\$[sd]", "it", text).replace("\\'", "'"))
            if words >= MIN_WORDS and level > MAX_GRADE:
                failed.append(f"{name}: grade {level:.1f}: {text}")
    for line in failed:
        print(line, file=sys.stderr)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "android/app/src/main/res/values/strings.xml"))
