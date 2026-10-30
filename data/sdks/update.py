#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Reads the SDK identifiers of sources.tsv in the artefacts the vendors publish and writes signatures.tsv.

    data/sdks/update.py [--cache DIR]

Each identifier is looked for in its artefact: an AAR or JAR from the vendor's own repository. The
artefact is only read, never run, and its SHA-256 is recorded (ADR 0019). An identifier gets:
  grade 1  when it survives code shrinking in apps that embed the SDK: a manifest component, or a
           class that the artefact's own keep rules preserve;
  grade 4  when it was read but shrinking may rename it, or when no artefact is public yet.
Only grades 1 to 3 reach the phone. An identifier that its artefact does not contain is a problem a
person has to look at, and makes the script fail.
"""
import argparse
import datetime
import hashlib
import io
import pathlib
import re
import sys
import urllib.request
import xml.etree.ElementTree as ElementTree
import zipfile

HERE = pathlib.Path(__file__).resolve().parent
ANDROID = "{http://schemas.android.com/apk/res/android}"


class Problem(Exception):
    """Something about one source that a person has to look at."""


def fetch(url, cache, keep):
    path = cache / re.sub(r"[^A-Za-z0-9._-]", "_", url)
    if not (keep and path.exists()):
        request = urllib.request.Request(url, headers={"User-Agent": "datapavan-sdks"})
        with urllib.request.urlopen(request, timeout=120) as response:
            path.write_bytes(response.read())
    return path


def resolve(artefact, cache):
    """The URL and file of an artefact: a URL, or the newest release of maven:<repository>|<group>:<artifact>."""
    if not artefact.startswith("maven:"):
        return artefact, fetch(artefact, cache, keep=True)
    repository, coordinates = artefact[len("maven:"):].split("|")
    group, artifact = coordinates.split(":")
    base = f"{repository}/{group.replace('.', '/')}/{artifact}"
    metadata = ElementTree.fromstring(fetch(f"{base}/maven-metadata.xml", cache, keep=False).read_bytes())
    version = metadata.findtext("versioning/release") or metadata.findtext("versioning/latest")
    if not version:
        raise Problem(f"{base}: no release in maven-metadata.xml")
    for extension in ("aar", "jar"):
        url = f"{base}/{version}/{artifact}-{version}.{extension}"
        try:
            return url, fetch(url, cache, keep=True)
        except OSError:
            continue
    raise Problem(f"{base}/{version}: no AAR or JAR")


def class_names(jar):
    with zipfile.ZipFile(io.BytesIO(jar)) as archive:
        return {name[:-len(".class")].replace("/", ".") for name in archive.namelist()
                if name.endswith(".class") and "$" not in name}


def contents(path):
    """Classes, manifest components, native libraries and keep rules of an AAR or JAR."""
    classes, components, libraries, keep = set(), set(), set(), []
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        if path.suffix == ".jar" or "classes.jar" not in names:
            classes |= class_names(path.read_bytes())
        for name in names:
            if name == "classes.jar" or (name.startswith("libs/") and name.endswith(".jar")):
                classes |= class_names(archive.read(name))
            elif re.fullmatch(r"jni/[^/]+/[^/]+\.so", name):
                libraries.add(name.rsplit("/", 1)[1])
            elif name == "proguard.txt" or name.startswith("META-INF/proguard/"):
                keep += re.findall(r"^-keep\S*\s+(?:public\s+)?(?:class|interface|enum)\s+([\w.*$]+)",
                                   archive.read(name).decode("utf-8", "replace"), re.M)
        if "AndroidManifest.xml" in names:
            manifest = ElementTree.fromstring(archive.read("AndroidManifest.xml"))
            package = manifest.get("package", "")
            for element in manifest.iter():
                name = element.get(f"{ANDROID}name")
                if element.tag in ("activity", "service", "receiver", "provider") and name:
                    components.add(package + name if name.startswith(".") else name)
    patterns = [re.compile(re.escape(p).replace(r"\*\*", ".*").replace(r"\*", r"[^.]*") + "$") for p in keep]
    return classes, components, libraries, patterns


def check(match_type, value, found):
    """Whether the artefact contains the identifier, and whether it survives shrinking in host apps."""
    classes, components, libraries, keep = found
    kept = lambda name: any(p.match(name) for p in keep)
    if match_type == "manifest-component":
        return value in components, True
    if match_type == "class":
        return value in classes, value in components or kept(value)
    if match_type == "class-prefix":
        matching = [c for c in classes if c.startswith(value)]
        return bool(matching), any(c in components or kept(c) for c in matching)
    if match_type == "native-lib":
        return value in libraries, True
    raise Problem(f"unknown match type {match_type}")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--cache", type=pathlib.Path, default=pathlib.Path.home() / ".cache/datapavan/sdks")
    args = parser.parse_args()
    args.cache.mkdir(parents=True, exist_ok=True)

    def rows(name):
        return [line.split("\t") for line in (HERE / name).read_text().splitlines() if line and not line.startswith("#")]

    sdks = {row[0] for row in rows("sdks.tsv")}
    artefacts = {}
    problems = []
    out = []
    today = datetime.date.today().isoformat()
    for sdk, artefact, match_type, value, specificity, attribution, source in rows("sources.tsv"):
        if sdk not in sdks:
            problems.append(f"{sdk} is in sources.tsv but not in sdks.tsv")
        grade, url, digest = 4, "", ""
        try:
            if artefact != "-":
                if artefact not in artefacts:
                    url, path = resolve(artefact, args.cache)
                    artefacts[artefact] = (url, hashlib.sha256(path.read_bytes()).hexdigest(), contents(path))
                url, digest, found = artefacts[artefact]
                present, survives = check(match_type, value, found)
                if not present:
                    raise Problem(f"{url} does not contain {match_type} {value}")
                grade = 1 if survives else 4
        except (Problem, OSError, ValueError, zipfile.BadZipFile, ElementTree.ParseError) as error:
            problems.append(f"{sdk} {value}: {error}")
            continue
        out.append([sdk, match_type, value, specificity, str(grade), attribution, source, url, digest, today])
        print(f"{sdk}: {match_type} {value}: grade {grade}{' from ' + url if url else ''}")

    header = [
        "# SPDX-License-Identifier: CC0-1.0",
        "# SDK identifiers and their evidence (ADR 0019), written by update.py. Only grades 1 to 3 reach the phone.",
        "# Columns: sdk, match type, identifier, specificity, grade, attributed by, source, artefact read,",
        "# its SHA-256, checked.",
    ]
    (HERE / "signatures.tsv").write_text("\n".join(header + ["\t".join(r) for r in out]) + "\n")
    shipped = [r for r in out if int(r[4]) <= 3]
    (HERE / "SOURCE").write_text("\n".join([
        "# SPDX-License-Identifier: CC0-1.0",
        f"retrieved: {today}",
        f"sdks: {len(sdks)}",
        f"identifiers: {len(out)}",
        f"shipped-identifiers: {len(shipped)} for {len({r[0] for r in shipped})} SDKs",
        "method: data/sdks/update.py, from the artefacts in sources.tsv",
    ]) + "\n")
    print(f"wrote {len(out)} identifiers; {len(shipped)} ship")
    if problems:
        print("\n".join(["Problems to look at:"] + problems), file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
