#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Fails if a release build holds anything of the lab (ADR 0048, decision 1).

    scripts/check-lab-classes.py --android DIR --lab DIR --lab-classes DIR --dexdump PATH [EXPECTED ...]
    scripts/check-lab-classes.py --self-test --lab DIR

Release builds are shrunk and renamed by R8, so a lab class called from product code ships under a short
name: the class names in a dex prove nothing alone. So, for every release APK and bundle under DIR's build
outputs (any flavour, any path with "release" in it), and every archive or dex inside one, found by its magic
bytes wherever it sits and whatever its name:
- an APK or bundle without a dex fails, and so does a dex that the SDK's dexdump cannot read;
- no class is under org.visadahyu.lab., or has the name of a class compiled from lab/ (nested ones as
  Outer$Inner);
- no dex, manifest or resource table holds a string of the lab's: the distinctive string literals of its
  sources (those that name "gaps"), each lab app's label, and its package;
- each dex that R8 made names its mapping by the "pg-map-id" of its marker, and a release mapping.txt with
  that pg_map_id must exist; that mapping, R8's record of the original names, inlined frames included, must
  name no lab class.
Each EXPECTED file must exist, so that a build that made nothing cannot pass; up-to-date outputs are fine,
since each dex is paired with its own mapping. Finding no release output at all fails too.

--self-test checks that the lab strings cover every lab app's label and package.
"""
import argparse
import io
import json
import pathlib
import re
import subprocess
import sys
import tempfile
import zipfile

ZIP = b"PK\x03\x04"
DEX = b"dex\n"
problems = []


def lab_strings(lab):
    """The strings only the lab's code and apps hold, derived from lab/: every string literal of its Java
    sources that names "gaps" (case aside) and has at least eight characters, cut at line breaks, each app's
    label (manifests and build scripts) and package, and the lab's package."""
    found = {"org.visadahyu.lab", "org/visadahyu/lab"}
    for path in pathlib.Path(lab).rglob("*.java"):
        for literal in re.findall(r'"((?:[^"\\\n]|\\.)*)"', path.read_text(encoding="utf-8")):
            for part in literal.split("\\n"):
                if re.search("gaps", part, re.IGNORECASE) and len(part) >= 8 and "\\" not in part:
                    found.add(part)
    for path in list(pathlib.Path(lab).rglob("AndroidManifest.xml")) + list(pathlib.Path(lab).rglob("*.sh")):
        text = path.read_text(encoding="utf-8")
        found.update(re.findall(r'android:label="([^"]+)"', text))
        found.update(re.findall(r'package="([^"]+)"', text))
        found.update(re.findall(r"--rename-manifest-package\s+([\w.]+)", text))
    return sorted(found, key=len, reverse=True)


def lab_names(classes):
    """The lab's classes as simple names (Outer and Outer$Inner), anonymous and synthetic ones left out."""
    names = set()
    for path in pathlib.Path(classes).rglob("*.class"):
        name = path.stem
        if any(part == "" or part.isdigit() or "Lambda" in part or "lambda" in part for part in name.split("$")):
            continue
        names.add(name)
    return names


def strings_in(where, data, strings, kind):
    # Binary XML and resource tables hold strings in UTF-16: read without zero bytes too.
    plain = data.replace(b"\0", b"") if kind != "dex" else data
    for string in strings:
        encoded = string.encode("utf-8")
        if encoded in data or encoded in plain:
            problems.append(f"{where}: holds the lab's string \"{string}\"")


def check_dex(where, data, context):
    with tempfile.NamedTemporaryFile(suffix=".dex") as tmp:
        tmp.write(data)
        tmp.flush()
        result = subprocess.run([context["dexdump"], "-h", tmp.name], capture_output=True, text=True)
    classes = re.findall(r"Class descriptor\s*:\s*'L([^;]*);'", result.stdout)
    if result.returncode != 0 or not classes:
        problems.append(f"{where}: dexdump cannot read this dex: {(result.stderr or result.stdout).strip()[:200]}")
        return 0
    for descriptor in classes:
        if descriptor.startswith("org/visadahyu/lab/"):
            problems.append(f"{where}: holds the class {descriptor.replace('/', '.')}")
        elif descriptor.rsplit("/", 1)[-1] in context["names"]:
            problems.append(f"{where}: holds a class named like the lab's: {descriptor.replace('/', '.')}")
    strings_in(where, data, context["strings"], "dex")
    # The marker R8 writes into each dex it makes, with the id of its mapping.
    for marker in re.findall(rb"~~R8(\{[^}]*\})", data):
        try:
            map_id = json.loads(marker).get("pg-map-id")
        except ValueError:
            continue
        if map_id:
            context["map_ids"].setdefault(map_id, []).append(where)
    return len(classes)


def check_archive(where, data, context, depth=0):
    """Checks one archive and every archive and dex inside it; returns the classes counted and the dex files."""
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as error:
        problems.append(f"{where}: not a readable archive: {error}")
        return 0, 0
    count = dexes = 0
    for entry in archive.namelist():
        inner = f"{where}!{entry}"
        content = archive.read(entry)
        if content.startswith(DEX):
            count += check_dex(inner, content, context)
            dexes += 1
        elif content.startswith(ZIP):
            if depth >= 4:
                problems.append(f"{inner}: archives nested too deep to check")
            else:
                inner_count, _ = check_archive(inner, content, context, depth + 1)
                count += inner_count
        elif entry.endswith("AndroidManifest.xml") or entry.endswith("resources.arsc") or entry.endswith("resources.pb"):
            strings_in(inner, content, context["strings"], "resources")
    return count, dexes


def check_mapping(path, names):
    """The mapping's id, after checking that no class line or inlined frame names a lab class."""
    map_id = None
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if line.startswith("# pg_map_id:"):
            map_id = line.split(":", 1)[1].strip()
            continue
        if not line or line.startswith("#"):
            continue
        if not line[0].isspace():
            original = line.split(" -> ", 1)[0]
            if original.startswith("org.visadahyu.lab.") or original.rsplit(".", 1)[-1] in names:
                problems.append(f"{path}: the build compiled the lab class {original} (R8: {line.strip()})")
            continue
        # A member line, or a frame inlined from another class: "1:3:void some.Class.method():10:10 -> a".
        for owner in re.findall(r"([\w$]+(?:\.[\w$]+)+)\.[\w$<>]+\(", line):
            if owner.startswith("org.visadahyu.lab.") or owner.rsplit(".", 1)[-1] in names:
                problems.append(f"{path}: code of the lab class {owner} was inlined (R8: {line.strip()})")
        if "org.visadahyu.lab." in line and not re.search(r"([\w$]+(?:\.[\w$]+)+)\.[\w$<>]+\(", line):
            problems.append(f"{path}: a member names a lab type (R8: {line.strip()})")
    return map_id


def self_test(lab):
    strings = lab_strings(lab)
    failures = []
    for manifest in pathlib.Path(lab).rglob("AndroidManifest.xml"):
        text = manifest.read_text(encoding="utf-8")
        for value in re.findall(r'package="([^"]+)"', text) + re.findall(r'android:label="([^"]+)"', text):
            if value not in strings:
                failures.append(f"{manifest}: {value} is not among the lab strings")
    for script in pathlib.Path(lab).rglob("build.sh"):
        for value in re.findall(r"--rename-manifest-package\s+([\w.]+)", script.read_text(encoding="utf-8")):
            if value not in strings:
                failures.append(f"{script}: {value} is not among the lab strings")
    if not any(s.startswith("Gaps") and s.endswith("(lab)") for s in strings) or len(strings) < 8:
        failures.append(f"too few lab strings: {strings}")
    for failure in failures:
        print(failure, file=sys.stderr)
    print(f"lab strings: {len(strings)}, every lab app's label and package among them" if not failures else "self-test failed")
    return 1 if failures else 0


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--lab", required=True)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--android")
    parser.add_argument("--lab-classes")
    parser.add_argument("--dexdump")
    parser.add_argument("expected", nargs="*")
    args = parser.parse_args()
    if args.self_test:
        return self_test(args.lab)
    names = lab_names(args.lab_classes)
    if not names:
        print("no class compiled from lab/", file=sys.stderr)
        return 1
    context = {"names": names, "strings": lab_strings(args.lab), "dexdump": args.dexdump, "map_ids": {}}
    android = pathlib.Path(args.android)
    outputs = sorted(p for p in android.rglob("*")
                     if p.is_file() and "/outputs/" in p.as_posix() and "release" in p.as_posix().lower()
                     and p.suffix.lower() in (".apk", ".aab", ".apks"))
    mapping_files = sorted(p for p in android.rglob("mapping.txt")
                           if "/outputs/" in p.as_posix() and "release" in p.as_posix().lower())
    if not outputs:
        problems.append(f"no release APK or bundle under {android}: build them first")
    for expected in args.expected:
        if not pathlib.Path(expected).is_file():
            problems.append(f"{expected}: missing, so the build did not make it")
    for path in outputs:
        before = len(problems)
        count, dexes = check_archive(str(path), path.read_bytes(), context)
        if dexes == 0:
            problems.append(f"{path}: holds no dex")
        if len(problems) == before:
            print(f"  {path}: {count} classes in {dexes} dex, none of the lab's, and none of its strings")
    mappings = {}
    for path in mapping_files:
        before = len(problems)
        map_id = check_mapping(path, names)
        if map_id:
            mappings[map_id] = path
        if len(problems) == before:
            print(f"  {path}: pg_map_id {(map_id or '-')[:12]}, names no lab class")
    for map_id, places in sorted(context["map_ids"].items()):
        if map_id not in mappings:
            problems.append(f"{places[0]}: R8 made this dex with pg-map-id {map_id}, and no release mapping.txt has it")
        else:
            print(f"  {len(places)} dex paired with {mappings[map_id]} by pg-map-id {map_id[:12]}")
    for problem in problems:
        print(problem, file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
