#!/usr/bin/env python3
"""Android's own labels, read from the phone (ADR 0054).

Checks data/android-labels/labels.tsv, the places each label Datapavan quotes is read from on a phone, and holds
the fallback strings (android_label_* in both modules' strings.xml, in all eight languages) to AOSP's own text at the
release most phones run (FALLBACK_API), with a second string for a later release where the text changes after it.
AOSP's texts are recorded in scripts/testdata/android-labels-aosp.tsv, which --fetch writes from AOSP's own files.

  scripts/android-labels.py                 the data check (scripts/check.sh data runs it)
  scripts/android-labels.py --fetch DIR     AOSP's strings at the tags into DIR, from android.googlesource.com with
                                            ?format=TEXT, then the recorded texts written from them (lab work)
  scripts/android-labels.py --against DIR   the check, then the recorded texts and every row's name against AOSP's
                                            files in DIR (lab work: CI keeps no copy)
  scripts/android-labels.py --self-test     the check's own test, on broken copies of the data
  scripts/android-labels.py --expected API  the recorded texts at one release, as "KEY LANG TEXT" lines, for
                                            scripts/verify-labels.sh
  scripts/android-labels.py --write-fallbacks MODULE KEY...
                                            writes the fallback strings of the keys into the module's (app or network)
                                            eight strings.xml from the recorded texts, replacing its earlier ones: the
                                            way to move the fallbacks when FALLBACK_API moves

What it holds the data to:
- every row has its eight columns; a maker's row names the device its label was seen on; an aosp row names the
  repository and the tags it was read at, which match its Android versions;
- the recorded texts cover every key at every Android version its rows cover, in all eight languages;
- every android_label_KEY string names a key of the data and equals AOSP's text at FALLBACK_API in each language
  after Android's unquoting and the app's cleaning; android_label_KEY_apiN equals it at N and later, and exists
  exactly where the text of some language changes after FALLBACK_API;
- the website's static mentions of a label (m8) equal the English fallback.
"""
import base64
import json
import re
import sys
import tempfile
import time
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data/android-labels/labels.tsv"
RECORDED = ROOT / "scripts/testdata/android-labels-aosp.tsv"
MODULES = [ROOT / "android/app/src/main/res", ROOT / "android/network/src/main/res"]
SITE = ROOT / "site/data/text/en.json"

# The last tag of each release in range, by API level (minSdk 29 to compileSdk 37).
TAGS = [
    (29, "android-10.0.0_r47"),
    (30, "android-11.0.0_r48"),
    (31, "android-12.0.0_r34"),
    (32, "android-12.1.0_r27"),
    (33, "android-13.0.0_r84"),
    (34, "android-14.0.0_r75"),
    (35, "android-15.0.0_r36"),
    (36, "android-16.0.0_r4"),
    (37, "android-17.0.0_r1"),
]
API_OF = {tag: api for api, tag in TAGS}
FIRST_API, LAST_API = TAGS[0][0], TAGS[-1][0]
# The release most phones run on 2026-11-22 (ADR 0054): the fallback strings are its text.
FALLBACK_API = 35
# Datapavan's languages and AOSP's folders for them: neutral Spanish is values-es, Simplified Chinese values-zh-rCN,
# and English AOSP's values/, which is American (m3, m4).
LANGS = {"en": "values", "fa": "values-fa", "ar": "values-ar", "fr": "values-fr", "de": "values-de", "es": "values-es",
         "ru": "values-ru", "zh": "values-zh-rCN"}
MODULE_DIRS = {"en": "values", "fa": "values-fa", "ar": "values-ar", "fr": "values-fr", "de": "values-de", "es": "values-es",
               "ru": "values-ru", "zh": "values-zh-rCN"}
HOST = "https://android.googlesource.com"


def repository(name, tag):
    """The project and resource folder of an AOSP repository at a tag, as SOURCE names them."""
    if name == "settings":
        return "platform/packages/apps/Settings", "res"
    if name == "settingslib":
        return "platform/frameworks/base", "packages/SettingsLib/res"
    if name == "permissioncontroller":
        if API_OF[tag] <= 30:
            return "platform/packages/apps/PackageInstaller", "res"
        return "platform/packages/modules/Permission", "PermissionController/res"
    raise ValueError(name)


COLUMNS = ["key", "maker", "api", "package", "type", "name", "verified", "source"]
KEY = re.compile(r"^[a-z][a-z0-9_]*$")
MAKER = re.compile(r"^(aosp|[a-z0-9][a-z0-9 _-]*)$")
API = re.compile(r"^(\d+)-(\d*)$")
PACKAGE = re.compile(r"^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$")
# The packages an aosp row may read, by its repository: SettingsLib's strings are merged into Settings' package, and the
# permission controller is Google's on phones with its services, AOSP's on others. As SystemLabels.AOSP_PACKAGES.
PACKAGES_OF = {
    "settings": {"com.android.settings"},
    "settingslib": {"com.android.settings"},
    "permissioncontroller": {"com.google.android.permissioncontroller", "com.android.permissioncontroller"},
}
NAME = re.compile(r"^[a-z][a-z0-9_]*$")
SOURCE = re.compile(r"^(aosp:(settings|settingslib|permissioncontroller)@(android-[0-9.]+_r\d+)\.\.(android-[0-9.]+_r\d+)|device)$")
VARIANT = re.compile(r"^android_label_([a-z0-9_]+?)(?:_api(\d+))?$")
# As OtherAppResources.clean: no direction characters, soft hyphen or zero-width space; a control character turns into
# a space; one line. Only ASCII whitespace collapses, as Java's \s, so a no-break space (French, before a colon) stays.
MARKS = set("\u200e\u200f\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069\u061c\u00ad\u200b")


def clean(text):
    flat = "".join(" " if ord(c) < 0x20 or 0x7f <= ord(c) < 0xa0 else c for c in text if c not in MARKS)
    return re.sub(r"[ \t\n\x0b\f\r]+", " ", flat).strip(" \t\n\x0b\f\r")


def unquote(raw):
    """A string resource's text as Android gives it: quotes and escapes undone, whitespace collapsed outside quotes."""
    out = []
    quoted = False
    i = 0
    while i < len(raw):
        c = raw[i]
        if c == "\\" and i + 1 < len(raw):
            n = raw[i + 1]
            if n == "u" and re.match(r"[0-9a-fA-F]{4}", raw[i + 2:i + 6]):
                out.append(chr(int(raw[i + 2:i + 6], 16)))
                i += 6
                continue
            out.append({"n": "\n", "t": "\t"}.get(n, n))
            i += 2
            continue
        if c == '"':
            quoted = not quoted
            i += 1
            continue
        # As aapt2: only ASCII whitespace collapses; a no-break space is kept.
        if c in " \t\n\r\f\v" and not quoted:
            if not out or out[-1] != " ":
                out.append(" ")
            i += 1
            continue
        out.append(c)
        i += 1
    return "".join(out).strip()


def resource_strings(path):
    """name -> text of a strings.xml, the default product's where a string has several."""
    out = {}
    for element in ET.parse(path).getroot():
        if element.tag != "string":
            continue
        name = element.get("name")
        product = element.get("product")
        if product not in (None, "default") and name in out:
            continue
        if product not in (None, "default") and name not in out:
            out[name] = (product, unquote("".join(element.itertext())))
            continue
        out[name] = (product, unquote("".join(element.itertext())))
    return {name: text for name, (_, text) in out.items()}


def table(path):
    return [line.split("\t") for line in path.read_text(encoding="utf-8").splitlines() if line and not line.startswith("#")]


def api_range(text):
    m = API.match(text)
    low = int(m.group(1))
    high = int(m.group(2)) if m.group(2) else LAST_API
    return max(low, FIRST_API), min(high, LAST_API)


def check_rows(rows, problems):
    out = []
    for n, cells in enumerate(rows, 1):
        where = f"labels.tsv row {n}"
        if len(cells) != len(COLUMNS):
            problems.append(f"{where}: {len(cells)} columns, not {len(COLUMNS)}")
            continue
        row = dict(zip(COLUMNS, cells))
        for column, pattern in [("key", KEY), ("maker", MAKER), ("api", API), ("package", PACKAGE), ("name", NAME), ("source", SOURCE)]:
            if not pattern.match(row[column]):
                problems.append(f"{where}: {column} '{row[column]}' is not well-formed")
        if row["type"] != "string":
            problems.append(f"{where}: type '{row['type']}' is not string")
        if not API.match(row["api"]) or not SOURCE.match(row["source"]):
            continue
        low, high = api_range(row["api"])
        if low > high:
            problems.append(f"{where}: api {row['api']} holds no release from {FIRST_API} to {LAST_API}")
        if row["maker"] != "aosp" and (row["verified"] == "-" or not row["verified"].strip()):
            problems.append(f"{where}: a maker's row names the device its label was seen on (verified)")
        if row["maker"] == "aosp" and not row["source"].startswith("aosp:"):
            problems.append(f"{where}: an aosp row's source is the AOSP repository and its tags")
        m = SOURCE.match(row["source"])
        if m.group(1).startswith("aosp:") and row["package"] not in PACKAGES_OF[m.group(2)]:
            problems.append(f"{where}: package {row['package']} is not where {m.group(2)}'s strings are ({', '.join(sorted(PACKAGES_OF[m.group(2)]))})")
        if m.group(1).startswith("aosp:"):
            first, last = m.group(3), m.group(4)
            if first not in API_OF or last not in API_OF:
                problems.append(f"{where}: source tags {first}..{last} are not the tags read (TAGS)")
            elif (API_OF[first], API_OF[last]) != (low, high):
                problems.append(f"{where}: source tags {first}..{last} are not its Android versions {row['api']}")
            row["repository"] = m.group(2)
        out.append(row)
    return out


def read_recorded(path, problems):
    """(key, api, lang) -> (name, text) of the recorded AOSP texts."""
    recorded = {}
    for n, cells in enumerate(table(path), 1):
        if len(cells) != 5 or not cells[1].isdigit() or cells[2] not in LANGS:
            problems.append(f"{path.name} row {n} is not KEY API LANG NAME TEXT")
            continue
        recorded[(cells[0], int(cells[1]), cells[2])] = (cells[3], cells[4])
    return recorded


def covered(rows, key):
    """The Android versions the aosp rows of key cover."""
    apis = set()
    for row in rows:
        if row["key"] == key and row["maker"] == "aosp":
            low, high = api_range(row["api"])
            apis.update(range(low, high + 1))
    return apis


def fallback_strings(module):
    """lang -> {name: text} of a module's android_label_* strings, after Android's unquoting and cleaning."""
    out = {}
    for lang, folder in MODULE_DIRS.items():
        path = module / folder / "strings.xml"
        if not path.exists():
            continue
        strings = resource_strings(path)
        out[lang] = {name: clean(text) for name, text in strings.items() if name.startswith("android_label_")}
    return out


def check_fallbacks(rows, recorded, modules, problems, site=SITE):
    keys = {row["key"] for row in rows}
    english = {}
    for module in modules:
        label = module.parent.parent.parent.name
        by_lang = fallback_strings(module)
        names = set(by_lang.get("en", {}))
        for name in sorted(names):
            m = VARIANT.match(name)
            key, variant = m.group(1), m.group(2)
            if key not in keys:
                problems.append(f"{label}: {name} names no key of labels.tsv")
                continue
            if key not in recorded_keys(recorded):
                continue
            api = int(variant) if variant else FALLBACK_API
            if variant and api <= FALLBACK_API:
                problems.append(f"{label}: {name} is for a release before the fallback's ({FALLBACK_API})")
            for lang in LANGS:
                text = by_lang.get(lang, {}).get(name)
                aosp = recorded.get((key, api, lang))
                if text is None or aosp is None:
                    problems.append(f"{label}: {name} ({lang}): {'missing' if text is None else 'no AOSP text recorded at API ' + str(api)}")
                    continue
                if text != aosp[1]:
                    problems.append(f"{label}: {name} ({lang}) is '{text}', AOSP's at API {api} is '{aosp[1]}' ({aosp[0]})")
            if not variant:
                english[key] = by_lang.get("en", {}).get(name)
        # Each key a module falls back for has a string from each release after the fallback's where some language's
        # text changes, and none elsewhere.
        for key in sorted({VARIANT.match(n).group(1) for n in names} & keys):
            if key not in recorded_keys(recorded):
                continue
            wanted = set()
            previous = {lang: recorded.get((key, FALLBACK_API, lang), ("", ""))[1] for lang in LANGS}
            for api in range(FALLBACK_API + 1, LAST_API + 1):
                now = {lang: recorded.get((key, api, lang), ("", ""))[1] for lang in LANGS}
                if now != previous:
                    wanted.add(api)
                previous = now
            have = {int(VARIANT.match(n).group(2)) for n in names if VARIANT.match(n).group(1) == key and VARIANT.match(n).group(2)}
            for api in sorted(wanted - have):
                problems.append(f"{label}: android_label_{key} changes at API {api}: android_label_{key}_api{api} is missing")
            for api in sorted(have - wanted):
                problems.append(f"{label}: android_label_{key}_api{api} is not needed: no language's text changes at API {api}")
    # The website cannot read the phone, so its mentions of a label are the English fallback (m8).
    if site.exists():
        text = site.read_text(encoding="utf-8")
        for key, phrase in SITE_LABELS.items():
            if phrase not in text:
                problems.append(f"{site.name}: no longer mentions '{phrase}': update SITE_LABELS")
            elif english.get(key) not in (None, phrase):
                problems.append(f"{site.name}: '{phrase}' is not the English fallback of {key}, '{english.get(key)}'")


def recorded_keys(recorded):
    return {key for key, _, _ in recorded}


# The website's static mentions of Android's labels (site/data/text/en.json), by key.
SITE_LABELS = {"usage_access": "Usage access", "usb_debugging": "USB debugging"}


def check_recorded(rows, recorded, problems):
    for key in sorted({row["key"] for row in rows}):
        for api in sorted(covered(rows, key)):
            for lang in LANGS:
                if (key, api, lang) not in recorded:
                    problems.append(f"{RECORDED.name}: no AOSP text for {key} at API {api} in {lang}")
    for key, api, lang in sorted(recorded):
        if api not in covered(rows, key):
            problems.append(f"{RECORDED.name}: {key} at API {api} ({lang}) is covered by no aosp row")
    # Each key's first aosp row at a release reads the name AOSP's text was recorded under, so that a misspelt name
    # fails here and not only against AOSP's files.
    for (key, api, lang), (name, _) in sorted(recorded.items()):
        if lang != "en":
            continue
        first = next((row for row in rows if row["key"] == key and row["maker"] == "aosp" and api_range(row["api"])[0] <= api <= api_range(row["api"])[1]), None)
        if first is not None and first["name"] != name:
            problems.append(f"{RECORDED.name}: {key} at API {api} was recorded under {name}, but its first aosp row reads {first['name']}")


def check(rows_path=DATA, recorded_path=RECORDED, modules=MODULES, site=SITE):
    problems = []
    rows = check_rows(table(rows_path), problems)
    recorded = read_recorded(recorded_path, problems) if recorded_path.exists() else {}
    if not recorded_path.exists():
        problems.append(f"{recorded_path.name} is missing: run --fetch")
    check_recorded(rows, recorded, problems)
    check_fallbacks(rows, recorded, modules, problems, site)
    return rows, recorded, problems


def cache_path(directory, repo, tag, lang):
    return Path(directory) / repo / tag / LANGS[lang] / "strings.xml"


def wanted_files(rows):
    files = set()
    for row in rows:
        if row["maker"] != "aosp" or "repository" not in row:
            continue
        low, high = api_range(row["api"])
        for api, tag in TAGS:
            if low <= api <= high:
                for lang in LANGS:
                    files.add((row["repository"], tag, lang))
    return sorted(files)


# The most a fetched file may hold, base64 included: Settings' largest strings.xml is about 1.5 MB.
MAX_FETCH = 8 << 20


def fetch(directory, rows):
    for repo, tag, lang in wanted_files(rows):
        target = cache_path(directory, repo, tag, lang)
        if target.exists():
            continue
        project, res = repository(repo, tag)
        url = f"{HOST}/{project}/+/refs/tags/{tag}/{res}/{LANGS[lang]}/strings.xml?format=TEXT"
        target.parent.mkdir(parents=True, exist_ok=True)
        for attempt in range(4):
            try:
                with urllib.request.urlopen(url, timeout=60) as response:
                    body = response.read(MAX_FETCH + 1)
                if len(body) > MAX_FETCH:
                    raise SystemExit(f"{url} is larger than {MAX_FETCH} bytes")
                target.write_bytes(base64.b64decode(body, validate=True))
                break
            except urllib.error.HTTPError as error:
                # Every repository read has all eight languages at every tag: a missing file is a wrong path.
                if error.code == 404:
                    raise SystemExit(f"{url} is not there (404)")
                time.sleep(5 * (attempt + 1))
            except (urllib.error.URLError, TimeoutError):
                time.sleep(5 * (attempt + 1))
        else:
            raise SystemExit(f"could not fetch {url}")
        print(f"fetched {repo} {tag} {lang}", file=sys.stderr)
        time.sleep(0.3)


def derive(directory, rows, problems):
    """The recorded texts, from AOSP's files in directory: for each key and release, the first aosp row whose name
    the release has answers, in each language, or in English where AOSP has no text in that language, as a phone does."""
    cache = {}

    def strings(repo, tag, lang):
        if (repo, tag, lang) not in cache:
            path = cache_path(directory, repo, tag, lang)
            cache[(repo, tag, lang)] = resource_strings(path) if path.exists() else {}
        return cache[(repo, tag, lang)]

    recorded = {}
    for key in sorted({row["key"] for row in rows}):
        for api, tag in TAGS:
            for row in rows:
                if row["key"] != key or row["maker"] != "aosp" or "repository" not in row:
                    continue
                low, high = api_range(row["api"])
                if not low <= api <= high:
                    continue
                base = strings(row["repository"], tag, "en")
                if row["name"] not in base:
                    problems.append(f"{key}: {row['name']} is not in {row['repository']} at {tag}")
                    continue
                for lang in LANGS:
                    text = strings(row["repository"], tag, lang).get(row["name"], base[row["name"]])
                    recorded[(key, api, lang)] = (row["name"], clean(text))
                break
    return recorded


def write_recorded(path, recorded):
    lines = [
        "# SPDX-License-Identifier: Apache-2.0",
        "# The Android Open Source Project's text of each label of data/android-labels/labels.tsv, at the last tag of each",
        "# release (scripts/android-labels.py TAGS), in Datapavan's eight languages, after Android's unquoting and the app's",
        "# cleaning; English where AOSP has no text in a language, as a phone shows it. Written by",
        "# scripts/android-labels.py --fetch from AOSP's own files. Columns: key, API level, language, resource name, text.",
    ]
    for (key, api, lang), (name, text) in sorted(recorded.items(), key=lambda kv: (kv[0][0], kv[0][1], list(LANGS).index(kv[0][2]))):
        lines.append("\t".join([key, str(api), lang, name, text]))
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def android_escape(text):
    """A text as a string resource holds it: XML's escapes and Android's."""
    out = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\\", "\\\\")
    out = out.replace("'", "\\'").replace('"', '\\"')
    return "\\" + out if out[:1] in ("@", "?") else out


REPOSITORY_NAMES = {"settings": "Settings'", "settingslib": "SettingsLib's", "permissioncontroller": "the permission controller's"}


def write_fallbacks(module_name, keys, rows, recorded, modules=None):
    """The android_label_* block of each of the module's strings.xml, written from the recorded texts: the block before
    it, its heading comment included, goes first, so that writing twice gives the same file."""
    module = (modules or {"app": MODULES[0], "network": MODULES[1]})[module_name]
    names = {}
    for key in keys:
        if key not in recorded_keys(recorded):
            raise SystemExit(f"no recorded text for {key}")
        apis = [FALLBACK_API]
        previous = None
        for api in range(FALLBACK_API, LAST_API + 1):
            now = [recorded[(key, api, lang)][1] for lang in LANGS]
            if previous is not None and now != previous:
                apis.append(api)
            previous = now
        names[key] = apis
    for lang, folder in MODULE_DIRS.items():
        path = module / folder / "strings.xml"
        lines = path.read_text(encoding="utf-8").split("\n")
        kept = []
        in_heading = False
        for line in lines:
            if line.strip().startswith("<!-- Android's own labels (ADR 0054)"):
                in_heading = "-->" not in line
                continue
            if in_heading:
                in_heading = "-->" not in line
                continue
            if "<string name=\"android_label_" in line or line.strip().startswith("<!-- Android's own label"):
                continue
            kept.append(line)
        end = max(i for i, line in enumerate(kept) if line.strip() == "</resources>")
        block = []
        if lang == "en":
            block.append("    <!-- Android's own labels (ADR 0054): AOSP's text at the release most phones run, each copied in every language")
            block.append("         from AOSP's own translation, never translated, for where the phone gives none. scripts/android-labels.py holds")
            block.append("         them to AOSP; an _apiN string is the text from Android's API level N on. -->")
        for key in keys:
            for api in names[key]:
                name = f"android_label_{key}" + ("" if api == FALLBACK_API else f"_api{api}")
                resource, text = recorded[(key, api, lang)]
                tag = dict(TAGS)[api]
                repo = next(r["repository"] for r in rows if r["key"] == key and r["maker"] == "aosp" and r["name"] == resource)
                block.append(f"    <!-- Android's own label: {REPOSITORY_NAMES[repo]} {resource} at {tag}. -->")
                block.append(f"    <string name=\"{name}\">{android_escape(text)}</string>")
        kept[end:end] = block
        path.write_text("\n".join(kept), encoding="utf-8")


def self_test():
    """Broken copies of the data, each of which must fail the check with the problem it is about."""
    rows_text = DATA.read_text(encoding="utf-8")
    recorded_text = RECORDED.read_text(encoding="utf-8")
    _, _, base = check()
    if base:
        print("self-test: the data itself fails the check:", *base, sep="\n  ")
        return 1
    cases = []
    first_aosp = next(line for line in rows_text.splitlines() if line and not line.startswith("#"))
    lockdown = next(line for line in rows_text.splitlines() if "\tvpn_menu_lockdown\t" in line)
    controller = next(line for line in rows_text.splitlines() if "\tauto_revoke_label\t" in line)
    cases.append(("a maker's row with no device", rows_text + first_aosp.replace("\taosp\t", "\tsamsung\t", 1) + "\n", recorded_text,
                  "names the device"))
    cases.append(("an api range its tags do not match", rows_text.replace(first_aosp, first_aosp.replace("\t29-\t", "\t30-\t", 1)), recorded_text,
                  "are not its Android versions"))
    cases.append(("a missing column", rows_text.replace(first_aosp, first_aosp.rsplit("\t", 1)[0]), recorded_text, "columns, not 8"))
    cases.append(("a source that is no AOSP repository", rows_text.replace(first_aosp, first_aosp.replace("aosp:settings@", "aosp:launcher@")),
                  recorded_text, "source 'aosp:launcher@"))
    cases.append(("a misspelt resource name", rows_text.replace(first_aosp, first_aosp.replace("\tusage_access\t-", "\tusage_acces\t-")),
                  recorded_text, "its first aosp row reads usage_acces"))
    cases.append(("a misspelt name in a row of a later release", rows_text.replace(lockdown, lockdown.replace("vpn_menu_lockdown", "vpn_lockdown_typo")),
                  recorded_text, "its first aosp row reads vpn_lockdown_typo"))
    cases.append(("a package where the repository's strings are not", rows_text.replace(controller, controller.replace("\tcom.google.android.permissioncontroller\t", "\tcom.android.settings\t")),
                  recorded_text, "is not where permissioncontroller's strings are"))
    recorded_lines = [line for line in recorded_text.splitlines() if line and not line.startswith("#")]
    at_fallback = next(line for line in recorded_lines if line.split("\t")[1] == str(FALLBACK_API) and line.split("\t")[2] == "de")
    cases.append(("a fallback that is not AOSP's text", rows_text, recorded_text.replace(at_fallback, at_fallback.rsplit("\t", 1)[0] + "\tSomething else"),
                  "AOSP's at API 35 is 'Something else'"))
    cases.append(("a release with no recorded text", rows_text, recorded_text.replace(recorded_lines[0] + "\n", ""), "no AOSP text for"))
    later = next(line for line in recorded_lines if line.split("\t")[1] == str(LAST_API) and line.split("\t")[2] == "fr")
    cases.append(("a change after the fallback's release with no string for it", rows_text, recorded_text.replace(later, later.rsplit("\t", 1)[0] + "\tUn autre nom"),
                  "is missing"))
    failed = []
    with tempfile.TemporaryDirectory() as work:
        for what, rows_copy, recorded_copy, wanted in cases:
            rows_path = Path(work) / "labels.tsv"
            recorded_path = Path(work) / "recorded.tsv"
            rows_path.write_text(rows_copy, encoding="utf-8")
            recorded_path.write_text(recorded_copy, encoding="utf-8")
            _, _, problems = check(rows_path, recorded_path)
            if not any(wanted in problem for problem in problems):
                failed.append(f"{what}: wanted '{wanted}', got {problems[:3]}")
        # The writer of the fallbacks, twice over a copy of the app's files: the second run changes nothing.
        copy = Path(work) / "res"
        for folder in MODULE_DIRS.values():
            (copy / folder).mkdir(parents=True)
            (copy / folder / "strings.xml").write_bytes((MODULES[0] / folder / "strings.xml").read_bytes())
        problems = []
        rows = check_rows(table(DATA), problems)
        recorded = read_recorded(RECORDED, problems)
        keys = [VARIANT.match(n).group(1) for n in fallback_strings(MODULES[0])["en"] if not VARIANT.match(n).group(2)]
        write_fallbacks("app", keys, rows, recorded, {"app": copy})
        once = {f: (copy / f / "strings.xml").read_bytes() for f in MODULE_DIRS.values()}
        write_fallbacks("app", keys, rows, recorded, {"app": copy})
        if any((copy / f / "strings.xml").read_bytes() != once[f] for f in MODULE_DIRS.values()):
            failed.append("the fallbacks' writer changes a file it has written")
        if once["values"] != (MODULES[0] / "values" / "strings.xml").read_bytes():
            failed.append("the fallbacks' writer does not give the app's strings.xml as it is")
    for what in failed:
        print(f"self-test: not caught: {what}")
    print(f"android labels self-test: {len(cases) - len([f for f in failed if ':' in f and 'writer' not in f])} of {len(cases)} broken copies caught"
          f", and the writer {'is not' if any('writer' in f for f in failed) else 'is'} idempotent")
    return 1 if failed else 0


def main(argv):
    if argv[1:] == ["--self-test"]:
        return self_test()
    if len(argv) == 3 and argv[1] == "--expected":
        problems = []
        api = int(argv[2])
        for (key, at, lang), (name, text) in sorted(read_recorded(RECORDED, problems).items()):
            if at == api:
                print(f"{key}\t{lang}\t{text}")
        return 1 if problems else 0
    if len(argv) >= 4 and argv[1] == "--write-fallbacks":
        problems = []
        rows = check_rows(table(DATA), problems)
        write_fallbacks(argv[2], argv[3:], rows, read_recorded(RECORDED, problems))
        if problems:
            print(*problems, sep="\n")
            return 1
    if len(argv) == 3 and argv[1] == "--fetch":
        problems = []
        rows = check_rows(table(DATA), problems)
        if problems:
            print(*problems, sep="\n")
            return 1
        fetch(argv[2], rows)
        recorded = derive(argv[2], rows, problems)
        if problems:
            print(*problems, sep="\n")
            return 1
        write_recorded(RECORDED, recorded)
        print(f"wrote {RECORDED.relative_to(ROOT)}: {len(recorded)} texts")
    rows, recorded, problems = check()
    if len(argv) == 3 and argv[1] == "--against":
        derived = derive(argv[2], rows, problems)
        for item in sorted(set(derived) | set(recorded)):
            if derived.get(item) != recorded.get(item):
                problems.append(f"{RECORDED.name}: {item} is {recorded.get(item)}, AOSP's files say {derived.get(item)}")
    elif len(argv) > 1 and argv[1] not in ("--fetch", "--write-fallbacks"):
        print(__doc__)
        return 2
    for problem in problems:
        print(problem)
    keys = {row["key"] for row in rows}
    print(f"android labels: {len(rows)} rows, {len(keys)} keys, {len(recorded)} recorded texts, {len(problems)} problems")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
