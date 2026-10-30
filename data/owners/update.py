#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Reads which company publishes which app from the sources in publisher-sources.tsv, writes
publishers.tsv, and checks the hand-reviewed entities.tsv and sdk-operators.tsv (ADR 0020).

    data/owners/update.py [--cache DIR] [--cache-only]

An app is identified by its package name and the SHA-256 of its signing certificate, never by its name
or package prefix alone. Sources:
  asset-links  a company's own Digital Asset Links file (/.well-known/assetlinks.json); every Android
               app it names is the company's, and the file's SHA-256 is recorded. Companies of one group
               may name each other's apps; companies of different groups naming one app is a problem;
  sdk-needs    the certificates of a service's genuine packages in data/sdk-needs, which come from the
               company's own client library.
Both are grade 1. Files are only read. With --cache-only, a file not in the cache is skipped. A
reference to an unknown company, or a source that names no app, is a problem a person has to look at,
and makes the script fail.
"""
import argparse
import datetime
import hashlib
import json
import pathlib
import re
import sys
import urllib.request

HERE = pathlib.Path(__file__).resolve().parent
NEEDS = HERE.parent / "sdk-needs"
FINGERPRINT = re.compile(r"(?:[0-9A-Fa-f]{2}:){31}[0-9A-Fa-f]{2}")


def rows(path):
    return [line.split("\t") for line in path.read_text().splitlines() if line and not line.startswith("#")]


def fetch(url, cache, cache_only):
    path = cache / re.sub(r"[^A-Za-z0-9._-]", "_", url)
    if cache_only:
        return path if path.exists() else None
    request = urllib.request.Request(url, headers={"User-Agent": "datapavan-owners"})
    with urllib.request.urlopen(request, timeout=60) as response:
        path.write_bytes(response.read())
    return path


def asset_links(path):
    """(package, certificate SHA-256) of every Android app that an assetlinks.json file names."""
    found = set()
    for statement in json.loads(path.read_text()):
        target = statement.get("target", {}) if isinstance(statement, dict) else {}
        if target.get("namespace") != "android_app" or not target.get("package_name"):
            continue
        for fingerprint in target.get("sha256_cert_fingerprints", []):
            if FINGERPRINT.fullmatch(fingerprint):
                found.add((target["package_name"], fingerprint.replace(":", "").lower()))
    return found


def group(entities, entity):
    """The company at the top of entity's group today: up through parents that hold it wholly or by
    majority, while that control lasts."""
    seen = set()
    while entity not in seen:
        seen.add(entity)
        row = entities[entity]
        if row[3] == "-" or row[4] not in ("whole", "majority") or row[6]:
            return entity
        entity = row[3]
    return entity


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--cache", type=pathlib.Path, default=pathlib.Path.home() / ".cache/datapavan/owners")
    parser.add_argument("--cache-only", action="store_true", help="read only files already in the cache")
    args = parser.parse_args()
    args.cache.mkdir(parents=True, exist_ok=True)

    problems = []
    # A missing or extra column shifts every later one, so the counts are checked first.
    for name, columns in (("entities.tsv", 9), ("sdk-operators.tsv", 10)):
        problems += [f"{name}: {row[0]} has {len(row)} columns, not {columns}" for row in rows(HERE / name) if len(row) != columns]
    entities = {row[0]: row for row in rows(HERE / "entities.tsv")}
    for entity, row in entities.items():
        if row[3] != "-" and (row[3] not in entities or row[4] not in ("whole", "majority", "joint", "minority")):
            problems.append(f"{entity}: unknown parent {row[3]} or control {row[4]}")
    for row in rows(HERE / "sdk-operators.tsv"):
        if row[3] not in entities:
            problems.append(f"{row[0]}: unknown entity {row[3]}")

    services = {row[0]: row[2].split(",") for row in rows(NEEDS / "services.tsv")}
    service_signers = {}
    for row in rows(NEEDS / "signers.tsv"):
        service_signers.setdefault(row[0], []).append((row[1], row[3], row[4]))

    today = datetime.date.today().isoformat()
    # (package, certificate) -> {entity: set of (source, its SHA-256)}
    found = {}
    for entity, method, location in rows(HERE / "publisher-sources.tsv"):
        if entity not in entities:
            problems.append(f"{location}: unknown entity {entity}")
            continue
        if method == "asset-links":
            try:
                path = fetch(location, args.cache, args.cache_only)
            except OSError as error:
                problems.append(f"{location}: {error}")
                continue
            if path is None:
                print(f"{entity}: {location} not read yet")
                continue
            try:
                apps = asset_links(path)
            except (ValueError, AttributeError) as error:
                problems.append(f"{location}: {error}")
                continue
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            for app in apps:
                found.setdefault(app, {}).setdefault(entity, set()).add((location, digest))
        elif method == "sdk-needs":
            if location not in services or location not in service_signers:
                problems.append(f"{entity}: no certificates for service {location} in data/sdk-needs")
                continue
            apps = {(package, certificate) for package in services[location] for certificate, _, _ in service_signers[location]}
            for (package, certificate) in apps:
                for _, urls, digests in service_signers[location]:
                    found.setdefault((package, certificate), {}).setdefault(entity, set()).add((urls, digests))
        else:
            problems.append(f"{location}: unknown method {method}")
            continue
        if not apps:
            problems.append(f"{location}: names no Android app")
        print(f"{entity}: {len(apps)} apps from {location}")

    lines = [
        "# SPDX-License-Identifier: CC0-1.0",
        "# Which company publishes which app (ADR 0020), written by update.py. Columns: package, SHA-256 of",
        "# its signing certificate, entity, grade, sources and their SHA-256 (separated by spaces, in the same",
        "# order), checked.",
    ]
    for (package, certificate), owners in sorted(found.items()):
        # Companies of one group often name each other's apps; companies of different groups must not.
        if len({group(entities, entity) for entity in owners}) > 1:
            problems.append(f"{package} {certificate}: named by companies of different groups {sorted(owners)}")
        for entity, read in sorted(owners.items()):
            lines.append("\t".join([package, certificate, entity, "1", " ".join(s for s, _ in sorted(read)),
                                    " ".join(d for _, d in sorted(read)), today]))
    (HERE / "publishers.tsv").write_text("\n".join(lines) + "\n")
    (HERE / "SOURCE").write_text("\n".join([
        "# SPDX-License-Identifier: CC0-1.0",
        f"retrieved: {today}",
        f"entities: {len(entities)}",
        f"sdk-operators: {len(rows(HERE / 'sdk-operators.tsv'))}",
        f"publisher-certificates: {len(found)}",
        "method: data/owners/update.py, from publisher-sources.tsv; entities.tsv and sdk-operators.tsv by hand",
    ]) + "\n")
    print(f"wrote {len(found)} app certificates")
    if problems:
        print("\n".join(["Problems to look at:"] + problems), file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
