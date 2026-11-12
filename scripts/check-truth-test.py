#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Checks that scripts/check-truth.py catches what each of its checks is for.

    scripts/check-truth-test.py

Each check is run on the repository's own files, which must pass, and then on a copy with one false
statement planted, which must fail. A check that never fails would let a false statement through unseen.
Part of scripts/check.sh.
"""
import datetime
import importlib.util
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
sys.dont_write_bytecode = True  # no __pycache__ in scripts/
spec =importlib.util.spec_from_file_location("check_truth", HERE / "check-truth.py")
truth = importlib.util.module_from_spec(spec)
spec.loader.exec_module(truth)
read = truth.read

failures = []


def expect(name, problems, caught):
    """caught: whether the check must report a problem."""
    if bool(problems) != caught:
        failures.append(f"{name}: expected {'a problem' if caught else 'none'}, got {problems or 'none'}")


def swap(text, old, new):
    assert old in text, f"the fixture lost {old!r}"
    return text.replace(old, new, 1)


# Releases.
tags = truth.release_tags()
latest = max(tags, key=truth.version)
published = tags[latest].isoformat()
changelog = read("CHANGELOG.md")
status = {p: read(p) for p in truth.RELEASE_STATUS}
gradle = read("android/app/build.gradle.kts")
hugo = read("site/hugo.toml")
expect("releases as they are", truth.check_releases(tags, changelog, status, gradle, hugo), False)
expect("no tags", truth.check_releases({}, changelog, status, gradle, hugo), True)
wrong_day = (tags[latest] - datetime.timedelta(days=3)).isoformat()
expect("a status line with the wrong date",
       truth.check_releases(tags, changelog, {**status, "SECURITY.md": swap(status["SECURITY.md"], published, wrong_day)}, gradle, hugo), True)
expect("a status line that names an older release",
       truth.check_releases(tags, changelog, {**status, "README.md": status["README.md"].replace(latest, "0.0.9")}, gradle, hugo), True)
expect("a release missing from the changelog",
       truth.check_releases(tags, swap(changelog, f"## [{latest}]", "## [9.9.9]"), status, gradle, hugo), True)
heading = next(line for line in changelog.splitlines() if line.startswith(f"## [{latest}] - "))
built = heading.rsplit(" ", 1)[1]
far = (tags[latest] - datetime.timedelta(days=6)).isoformat()
expect("a changelog date far from the tag (the app built with the same date)",
       truth.check_releases(tags, swap(changelog, heading, f"## [{latest}] - {far}"), status,
                            swap(gradle, f'\\"{built}\\"', f'\\"{far}\\"'), hugo), True)
expect("an app built with another date than the changelog's",
       truth.check_releases(tags, changelog, status, swap(gradle, f'\\"{built}\\"', f'\\"{published}\\"') if built != published
                            else swap(gradle, f'\\"{built}\\"', '\\"2000-01-01\\"'), hugo), True)
expect("an app older than the release", truth.check_releases(tags, changelog, status, swap(gradle, f'versionName = "{latest}"', 'versionName = "0.0.1"'), hugo), True)
expect("a download button on an older release", truth.check_releases(tags, changelog, status, gradle, swap(hugo, f'release_tag = "v{latest}"', 'release_tag = "v0.0.1"')), True)

# Decisions.
decisions = truth.adr_files(truth.ROOT / "docs/decisions")
index = read("docs/decisions/README.md")
design = read("docs/DESIGN.md")
expect("decisions as they are", truth.check_decisions(decisions, index, design), False)
row = next(line for line in index.splitlines() if line.startswith("| [0043]"))
expect("an ADR missing from the index", truth.check_decisions(decisions, swap(index, row + "\n", ""), design), True)
expect("a status the ADR does not have",
       truth.check_decisions(decisions, swap(index, row, row.replace("| Accepted |", "| Proposed |")), design), True)
expect("DESIGN.md's table drifting from the index",
       truth.check_decisions(decisions, index, swap(design, "| Apache-2.0 licence |", "| Apache licence |")), True)
expect("an index row for an ADR with no file",
       truth.check_decisions(decisions, index + "| [0999](0999-none.md) | Nothing | Accepted |\n", design), True)

# Dated status lines.
roadmap = read("ROADMAP.md")
newest = max(date for _, _, date in decisions.values())
expect("status dates as they are", truth.check_status_dates(roadmap, design, newest, published), False)
expect("a roadmap status older than the newest decision",
       truth.check_status_dates(roadmap, design, "2099-01-01", published), True)

# Build facts.
readme = read("README.md")
adr_0003 = read("docs/decisions/" + decisions["0003"][0])
contributing = read("CONTRIBUTING.md")
gradles = {p: read(p) for p in ("android/app/build.gradle.kts", "android/watch/build.gradle.kts")}
languages = {app: truth.language_folders(f"android/{app}") for app in ("app", "watch")}
expect("build facts as they are", truth.check_build(readme, adr_0003, contributing, gradles, languages), False)
expect("the README naming another Android version",
       truth.check_build(swap(readme, "Android 10 or", "Android 11 or"), adr_0003, contributing, gradles, languages), True)
expect("a language the apps have and CONTRIBUTING.md does not name",
       truth.check_build(readme, adr_0003, contributing, gradles, {**languages, "app": languages["app"] | {"tr"}}), True)
expect("a language CONTRIBUTING.md names that the apps lack",
       truth.check_build(readme, adr_0003, contributing, gradles, {**languages, "watch": languages["watch"] - {"fa"}}), True)

# Datasets.
sources = {d: (read(f"{d}/SOURCE"), {n: len(truth.rows(read(f"{d}/{f}"))) for n, f in c.items()})
           for d, c in truth.DATASET_COUNTS.items()}
changelog_now = read("CHANGELOG.md")
expect("datasets as they are", truth.check_datasets(sources, readme, changelog_now), False)
signers_source, signers_counts = sources["data/app-signers"]
expect("a SOURCE count one off",
       truth.check_datasets({**sources, "data/app-signers": (signers_source, {**signers_counts, "apps": signers_counts["apps"] + 1})}, readme, changelog_now), True)
expect("the README's count of known apps one off",
       truth.check_datasets(sources, readme.replace(f"certificates of {signers_counts['apps']} apps", f"certificates of {signers_counts['apps'] - 1} apps"), changelog_now), True)
tools_count = sources["data/tools"][1]["apps"]
expect("the changelog's size of the table of tools one off",
       truth.check_datasets(sources, readme, swap(changelog_now, f"It holds {tools_count} apps", f"It holds {tools_count - 7} apps")), True)

# Milestones.
expect("milestones as they are", truth.check_milestones(readme, roadmap), False)
in_progress = next(line for line in roadmap.splitlines() if line.startswith("| M") and line.rstrip().endswith("🔄 |"))
expect("a milestone done in the roadmap but in progress in the README",
       truth.check_milestones(readme, swap(roadmap, in_progress, in_progress[: in_progress.rindex("🔄")] + "✅ |")), True)

for failure in failures:
    print(failure)
print(f"check-truth-test: {len(failures)} failures")
sys.exit(1 if failures else 0)
