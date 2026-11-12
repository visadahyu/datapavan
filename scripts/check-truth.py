#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Checks that the public documents say what the code and the record say (ADR 0039, docs/RELEASE.md).

    scripts/check-truth.py

A privacy tool's trust rests on saying only what is true, and on 2026-11-12 eleven public statements
were found that the code or the record contradicted: each had been true, or planned, when written. This
script checks the statements that a machine can read against their single source:

- releases: the git tags, against the changelog, the security policy, the README, the channels and
  release documents, the app's version and build date, and the website's download button;
- decisions: the ADR files, against the index in docs/decisions/README.md and DESIGN.md's table;
- dated status lines: the roadmap's and DESIGN.md's dates, against the newest decision and release;
- build facts: the minimum Android version and the UI languages, against the Gradle files and the
  translated resources;
- datasets: the counts in each data/*/SOURCE, the README's count of known signing keys and the
  changelog's size of the table of tools, against the rows of the data files;
- milestones: the README's status, against the roadmap's table.

Statements a machine cannot read (mirrors, backups, what a screen shows) are checked by a reviewer at
each release (docs/RELEASE.md). Part of scripts/check.sh; scripts/check-truth-test.py checks that each
check catches what it is for. It needs the release tags: in CI, check out with tags.
"""
import datetime
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent

# Android's version for each API level the project uses (ADR 0003).
ANDROID = {29: "10", 30: "11", 31: "12", 32: "12L", 33: "13", 34: "14", 35: "15", 36: "16", 37: "17"}

# The language names CONTRIBUTING.md uses, and their resource folders (values-<qualifier>).
LANGUAGES = {
    "English": "", "French": "fr", "German": "de", "Spanish": "es", "Russian": "ru",
    "Simplified Chinese": "zh-rCN", "Arabic": "ar", "Persian": "fa",
}

# Documents whose status line names the current release and the date it was published.
RELEASE_STATUS = ["README.md", "SECURITY.md", "docs/CHANNELS.md", "docs/RELEASE.md"]

# Each dataset's SOURCE gives counts; each count is the number of rows in one file.
DATASET_COUNTS = {
    "data/app-signers": {"apps": "apps.tsv", "certificates": "signers.tsv"},
    "data/tools": {"apps": "tools.tsv", "evidence": "sources.tsv"},
}

DATE = r"\d{4}-\d{2}-\d{2}"


def version(text):
    return tuple(int(part) for part in text.split("."))


def rows(text):
    return [line for line in text.splitlines() if line.strip() and not line.startswith("#")]


def sentence_after(text, start):
    """The text from `start` to the end of its sentence (a full stop before a space or a line's end)."""
    end = re.compile(r"\.(\s|$)").search(text, start)
    return text[start:end.start() if end else len(text)]


def check_releases(tags, changelog, status_docs, gradle_app, hugo):
    """tags: {"0.1.2": date published}. status_docs: {path: text}."""
    problems = []
    if not tags:
        return ["no release tags (v1.2.3) found: fetch the tags (git fetch --tags)"]
    latest = max(tags, key=version)
    published = tags[latest]

    headings = dict(re.findall(rf"^## \[(\d+\.\d+\.\d+)\] - ({DATE})$", changelog, re.M))
    if "## [Unreleased]" not in changelog:
        problems.append("CHANGELOG.md has no [Unreleased] section")
    for tag, date in sorted(tags.items(), key=lambda item: version(item[0])):
        if tag not in headings:
            problems.append(f"CHANGELOG.md has no section for the release {tag}")
            continue
        # The changelog's date is the one built into the app (RELEASE_DATE, scripts/prepare-signing.sh). It
        # may be the day planned for the release, one day from its publication (0.1.2, docs/RELEASE.md).
        apart = abs((datetime.date.fromisoformat(headings[tag]) - date).days)
        if apart > 1:
            problems.append(f"CHANGELOG.md dates {tag} {headings[tag]}, but it was published on {date}")
    for heading in headings:
        if heading not in tags:
            problems.append(f"CHANGELOG.md has a section for {heading}, which no tag v{heading} published")

    for path, text in status_docs.items():
        mention = re.search(rf"(?<![\d.])v?{re.escape(latest)}(?![\d.]*\d)", text)
        if not mention:
            problems.append(f"{path} does not name the current release, {latest}")
            continue
        date = re.search(DATE, sentence_after(text, mention.end()))
        if date and date.group() != published.isoformat():
            problems.append(f"{path} says {latest} came out on {date.group()}; it was published on {published}")

    app = re.search(r'versionName = "([\d.]+)"', gradle_app)
    if not app:
        problems.append("android/app/build.gradle.kts has no versionName")
    else:
        name = app.group(1)
        if version(name) < version(latest):
            problems.append(f"the app's versionName {name} is older than the release {latest}")
        built = re.search(rf'"RELEASE_DATE", "\\"({DATE})\\""', gradle_app)
        if name in headings and (not built or built.group(1) != headings[name]):
            problems.append(f"the app's RELEASE_DATE is not CHANGELOG.md's date for {name}, {headings[name]}")

    button = re.search(r'^release_tag = "v([\d.]+)"$', hugo, re.M)
    if not button or button.group(1) != latest:
        problems.append(f"site/hugo.toml's download button is not the current release, v{latest}")
    apk = re.search(r'^release_apk = "(.*)"$', hugo, re.M)
    if not apk or latest not in apk.group(1):
        problems.append(f"site/hugo.toml's release_apk is not {latest}'s APK")
    return problems


def first_word(text):
    return text.split()[0].rstrip(",;") if text.split() else ""


def adr_files(directory):
    """{number: (file name, status line, newest date in its status and date lines)} from docs/decisions."""
    found = {}
    for path in sorted(directory.glob("[0-9][0-9][0-9][0-9]-*.md")):
        text = path.read_text(encoding="utf-8")
        status = re.search(r"^- Status: (.+)$", text, re.M)
        dated = re.findall(DATE, " ".join(re.findall(r"^- (?:Status|Date): .+$", text, re.M)))
        found[path.name[:4]] = (path.name, status.group(1) if status else "", max(dated, default=""))
    return found


def check_decisions(files, index, design):
    """files: adr_files(). index and design: the texts of docs/decisions/README.md and DESIGN.md."""
    problems = []
    row = re.compile(r"^\| \[(\d{4})\]\(([^)]+)\) \| (.+?) \| (.+?) \|$", re.M)
    tables = {}
    for path, text, prefix in (("docs/decisions/README.md", index, ""), ("docs/DESIGN.md", design, "decisions/")):
        listed = {}
        for number, link, title, status in row.findall(text):
            if number in listed:
                problems.append(f"{path} lists ADR {number} twice")
            listed[number] = (link, title, status)
        tables[path] = listed
        for number, (name, status_line, _) in files.items():
            if number not in listed:
                problems.append(f"{path} does not list ADR {number} ({name})")
                continue
            link, _, status = listed[number]
            if link != prefix + name:
                problems.append(f"{path} links ADR {number} to {link}, not {prefix + name}")
            # The first word is the status (Accepted, Proposed, Superseded); the rest may be shortened.
            if not status_line or first_word(status) != first_word(status_line):
                problems.append(f"{path} gives ADR {number} the status \"{status}\"; the ADR says \"{status_line}\"")
            superseded = re.search(r"\b(\d{4})\b", status_line) if status_line.startswith("Superseded") else None
            if superseded and superseded.group(1) not in status:
                problems.append(f"{path} does not say that ADR {superseded.group(1)} superseded ADR {number}")
        for number in listed:
            if number not in files:
                problems.append(f"{path} lists ADR {number}, which has no file")
    # DESIGN.md's table repeats the index, so that the two cannot drift apart.
    index_rows = {n: (t, s) for n, (_, t, s) in tables["docs/decisions/README.md"].items()}
    design_rows = {n: (t, s) for n, (_, t, s) in tables["docs/DESIGN.md"].items()}
    for number in sorted(set(index_rows) & set(design_rows)):
        if index_rows[number] != design_rows[number]:
            problems.append(f"docs/DESIGN.md's row for ADR {number} differs from docs/decisions/README.md's")
    return problems


def check_status_dates(roadmap, design, newest_decision, latest_release):
    """The roadmap's and DESIGN.md's dates are no older than the newest decision and release."""
    problems = []
    newest = max(newest_decision, latest_release)
    stands = re.search(rf"^Where it stands on ({DATE})", roadmap, re.M)
    if not stands:
        problems.append("ROADMAP.md has no \"Where it stands on <date>\" line")
    elif stands.group(1) < newest:
        problems.append(f"ROADMAP.md's status is of {stands.group(1)}, older than the newest decision or release ({newest})")
    revised = re.search(rf"revised ({DATE})", design)
    if not revised:
        problems.append("docs/DESIGN.md's header has no \"revised <date>\"")
    elif revised.group(1) < newest_decision:
        problems.append(f"docs/DESIGN.md was revised on {revised.group(1)}, before the newest decision ({newest_decision})")
    return problems


def check_build(readme, adr_0003, contributing, gradles, languages):
    """gradles: {path: text}. languages: {app: set of values-<qualifier> folder qualifiers}."""
    problems = []
    levels = {}
    for path, text in gradles.items():
        level = re.search(r"minSdk = (\d+)", text)
        if not level:
            problems.append(f"{path} has no minSdk")
        else:
            levels[path] = int(level.group(1))
    if len(set(levels.values())) > 1:
        problems.append(f"the apps' minSdk differ: {levels}")
    if levels:
        level = min(levels.values())
        android = ANDROID.get(level, f"API {level}")
        # The sentence may wrap inside the README's quoted status block.
        said = re.search(r"Android (\S+) or\s+(?:>\s*)?newer", readme)
        if not said or said.group(1) != android:
            problems.append(f"README.md does not say \"Android {android} or newer\" (minSdk {level})")
        title = re.search(r"Minimum Android version (\S+) \(API (\d+)\)", adr_0003)
        if not title or (title.group(1), int(title.group(2))) != (android, level):
            problems.append(f"ADR 0003's title does not say Android {android} (API {level})")

    listed = re.search(r"The UI ships in (.+?)\.\s", contributing, re.S)
    if not listed:
        return problems + ["CONTRIBUTING.md has no \"The UI ships in …\" sentence"]
    names = [n.strip() for n in re.split(r",|\band\b", " ".join(listed.group(1).split())) if n.strip()]
    unknown = [n for n in names if n not in LANGUAGES]
    if unknown:
        problems.append(f"check-truth.py does not know the language {', '.join(unknown)}: add it to LANGUAGES")
    said = {LANGUAGES[n] for n in names if n in LANGUAGES}
    for app, folders in languages.items():
        if folders != said:
            extra = sorted(folders - said)
            missing = sorted(said - folders)
            problems.append(f"CONTRIBUTING.md's languages are not {app}'s: in the app only {extra}, named only {missing}")
    return problems


def check_datasets(sources, readme, changelog):
    """sources: {dataset: (SOURCE text, {count name: rows in its file})}."""
    problems = []
    for dataset, (source, counted) in sources.items():
        for name, actual in counted.items():
            said = re.search(rf"^{name}: (\d+)$", source, re.M)
            if not said:
                problems.append(f"{dataset}/SOURCE does not give \"{name}\"")
            elif int(said.group(1)) != actual:
                problems.append(f"{dataset}/SOURCE says {name}: {said.group(1)}, but the file has {actual} rows")
    apps = sources.get("data/app-signers", (None, {}))[1].get("apps")
    said = re.search(r"official signing certificates of (\d+) apps", readme)
    if apps is not None and (not said or int(said.group(1)) != apps):
        problems.append(f"README.md does not say that the official signing certificates of {apps} apps are known")
    # The changelog's entry for the table of tools gives its size.
    tools = sources.get("data/tools", (None, {}))[1].get("apps")
    said = re.search(r"table of tools \(`data/tools/`\).*?It holds (\d+) apps", changelog, re.S)
    if tools is not None and said and int(said.group(1)) != tools:
        problems.append(f"CHANGELOG.md says the table of tools holds {said.group(1)} apps; data/tools has {tools}")
    return problems


def check_milestones(readme, roadmap):
    """The README's milestone status against the roadmap's table (✅ done, 🔄 in progress)."""
    problems = []
    table = dict(re.findall(r"^\| (M\d+) \|.*\| *(✅|🔄|⏳) *\|$", roadmap, re.M))
    # The README's status is a quoted block: "> Status: …", continued on lines that start with ">".
    lines = readme.splitlines()
    start = next((i for i, line in enumerate(lines) if line.startswith("> Status:")), None)
    if start is None:
        return ["README.md has no \"> Status:\" block"]
    block = []
    for line in lines[start:]:
        if not line.startswith(">"):
            break
        block.append(line.lstrip(">"))
    status = " ".join(" ".join(block).split())
    complete = re.search(r"Milestones (.+?) are complete", status)
    done = set(re.findall(r"\bM\d+\b", complete.group(1))) if complete else set()
    going = set(re.findall(r"\b(M\d+)\b[^.]*?\bis in progress", status))
    for milestone, mark in table.items():
        if mark == "✅" and milestone not in done:
            problems.append(f"ROADMAP.md marks {milestone} done; README.md's status does not say so")
        if mark == "🔄" and milestone not in going:
            problems.append(f"ROADMAP.md marks {milestone} in progress; README.md's status does not say so")
    for milestone in done:
        if table.get(milestone) != "✅":
            problems.append(f"README.md says {milestone} is complete; ROADMAP.md marks it {table.get(milestone, 'nowhere')}")
    return problems


def release_tags():
    out = subprocess.run(
        ["git", "-C", str(ROOT), "for-each-ref", "--format=%(refname:short) %(creatordate:iso-strict)", "refs/tags/v*"],
        check=True, capture_output=True, text=True,
    ).stdout
    tags = {}
    for line in out.splitlines():
        name, when = line.split(" ", 1)
        if re.fullmatch(r"v\d+\.\d+\.\d+", name):
            moment = datetime.datetime.fromisoformat(when).astimezone(datetime.timezone.utc)
            tags[name[1:]] = moment.date()
    return tags


def read(path):
    return (ROOT / path).read_text(encoding="utf-8")


def language_folders(app):
    folders = set()
    for path in (ROOT / app / "src/main/res").glob("values*"):
        qualifier = path.name[len("values"):].lstrip("-")
        # Not a language: night mode, API levels, screen sizes.
        if qualifier and re.fullmatch(r"night|v\d+|[swh]\d+dp|land|port", qualifier):
            continue
        folders.add(qualifier)
    return folders


def main():
    tags = release_tags()
    decisions = adr_files(ROOT / "docs/decisions")
    newest_decision = max((date for _, _, date in decisions.values()), default="")
    latest_release = max(tags.values()).isoformat() if tags else ""
    checks = {
        "releases": check_releases(
            tags, read("CHANGELOG.md"), {p: read(p) for p in RELEASE_STATUS},
            read("android/app/build.gradle.kts"), read("site/hugo.toml"),
        ),
        "decisions": check_decisions(decisions, read("docs/decisions/README.md"), read("docs/DESIGN.md")),
        "dated status lines": check_status_dates(read("ROADMAP.md"), read("docs/DESIGN.md"), newest_decision, latest_release),
        "build facts": check_build(
            read("README.md"), read("docs/decisions/" + decisions["0003"][0]),
            read("CONTRIBUTING.md"),
            {p: read(p) for p in ("android/app/build.gradle.kts", "android/watch/build.gradle.kts")},
            {app: language_folders(f"android/{app}") for app in ("app", "watch")},
        ),
        "datasets": check_datasets(
            {d: (read(f"{d}/SOURCE"), {n: len(rows(read(f"{d}/{f}"))) for n, f in c.items()}) for d, c in DATASET_COUNTS.items()},
            read("README.md"), read("CHANGELOG.md"),
        ),
        "milestones": check_milestones(read("README.md"), read("ROADMAP.md")),
    }
    problems = [problem for found in checks.values() for problem in found]
    for problem in problems:
        print(problem)
    print(f"truth: {len(checks)} kinds of statement checked, {len(problems)} problems")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
