#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Reads the SDK capabilities of sources.tsv and the service certificates of signer-sources.tsv in the
vendors' own artefacts, and writes capabilities.tsv and signers.tsv (ADR 0021).

    data/sdk-needs/update.py [--cache DIR] [--cache-only]

Each artefact is an AAR or JAR from the vendor's own repository. It is only read, never run, and its
SHA-256 is recorded. A capability gets
  grade 1  when its class is read in the vendor's artefact;
  grade 4  when the artefact is not read yet (--cache-only and not in the cache).
Only grades 1 to 3 reach the phone. A certificate is read from the X.509 certificates that the vendor's
own client library embeds to check the service; certificates with AOSP's test-key subject are left out.
A class or certificate that its artefact does not contain is a problem a person has to look at, and
makes the script fail.
"""
import argparse
import datetime
import hashlib
import io
import pathlib
import re
import struct
import sys
import urllib.request
import xml.etree.ElementTree as ElementTree
import zipfile

HERE = pathlib.Path(__file__).resolve().parent
# AOSP's test keys carry this address; a package signed with one proves nothing about its maker.
TEST_KEY_MARK = b"android@android.com"


class Problem(Exception):
    """Something about one source that a person has to look at."""


def rows(name):
    return [line.split("\t") for line in (HERE / name).read_text().splitlines() if line and not line.startswith("#")]


def fetch(url, cache, keep, cache_only):
    path = cache / re.sub(r"[^A-Za-z0-9._-]", "_", url)
    if keep and path.exists():
        return path
    if cache_only:
        return None
    request = urllib.request.Request(url, headers={"User-Agent": "datapavan-sdk-needs"})
    with urllib.request.urlopen(request, timeout=120) as response:
        path.write_bytes(response.read())
    return path


def resolve(artefact, cache, cache_only):
    """The URL and file of maven:<repository>|<group>:<artifact>[:<version>]; no file if not read yet."""
    if not artefact.startswith("maven:"):
        raise Problem(f"unknown artefact {artefact}")
    repository, coordinates = artefact[len("maven:"):].split("|")
    group, artifact, *version = coordinates.split(":")
    base = f"{repository}/{group.replace('.', '/')}/{artifact}"
    if not version:
        metadata = fetch(f"{base}/maven-metadata.xml", cache, keep=False, cache_only=cache_only)
        if metadata is None:
            return base, None
        root = ElementTree.fromstring(metadata.read_bytes())
        version = [root.findtext("versioning/release") or root.findtext("versioning/latest")]
        if not version[0]:
            raise Problem(f"{base}: no release in maven-metadata.xml")
    for extension in ("aar", "jar"):
        url = f"{base}/{version[0]}/{artifact}-{version[0]}.{extension}"
        try:
            path = fetch(url, cache, keep=True, cache_only=cache_only)
        except OSError:
            continue
        if path is not None:
            return url, path
    if cache_only:
        return base, None
    raise Problem(f"{base}/{version[0]}: no AAR or JAR")


def class_files(path):
    """Name and bytes of each class file of an AAR (its classes.jar and libs/*.jar) or JAR."""
    def from_jar(data):
        with zipfile.ZipFile(io.BytesIO(data)) as jar:
            for name in jar.namelist():
                if name.endswith(".class"):
                    yield name[:-len(".class")].replace("/", "."), jar.read(name)
    data = path.read_bytes()
    if path.suffix == ".jar":
        yield from from_jar(data)
        return
    with zipfile.ZipFile(path) as aar:
        for name in aar.namelist():
            if name == "classes.jar" or (name.startswith("libs/") and name.endswith(".jar")):
                yield from from_jar(aar.read(name))


def utf8_constants(data):
    """The CONSTANT_Utf8 entries of a class file, each decoded to its UTF-16 code units."""
    if data[:4] != b"\xca\xfe\xba\xbe":
        return
    count = struct.unpack(">H", data[8:10])[0]
    at, index = 10, 1
    sizes = {3: 4, 4: 4, 5: 8, 6: 8, 7: 2, 8: 2, 9: 4, 10: 4, 11: 4, 12: 4, 15: 3, 16: 2, 17: 4, 18: 4, 19: 2, 20: 2}
    while index < count:
        tag = data[at]
        if tag == 1:
            length = struct.unpack(">H", data[at + 1:at + 3])[0]
            raw, units, i = data[at + 3:at + 3 + length], [], 0
            while i < len(raw):
                byte = raw[i]
                if byte < 0x80:
                    units.append(byte)
                    i += 1
                elif byte & 0xe0 == 0xc0:
                    units.append(((byte & 0x1f) << 6) | (raw[i + 1] & 0x3f))
                    i += 2
                else:
                    units.append(((byte & 0x0f) << 12) | ((raw[i + 1] & 0x3f) << 6) | (raw[i + 2] & 0x3f))
                    i += 3
            yield units
            at += 3 + length
        elif tag in sizes:
            at += 1 + sizes[tag]
            index += 1 if tag in (5, 6) else 0
        else:
            raise Problem(f"unknown constant tag {tag}")
        index += 1


def embedded_certificates(path):
    """SHA-256 of each X.509 certificate a library embeds as a byte string, without AOSP test keys."""
    found = set()
    for _, data in class_files(path):
        for units in utf8_constants(data):
            if len(units) < 300 or any(unit > 0xff for unit in units) or units[:2] != [0x30, 0x82]:
                continue
            blob = bytes(units)
            certificate = blob[:struct.unpack(">H", blob[2:4])[0] + 4]
            if TEST_KEY_MARK not in certificate:
                found.add(hashlib.sha256(certificate).hexdigest())
    return found


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--cache", type=pathlib.Path, default=pathlib.Path.home() / ".cache/datapavan/sdk-needs")
    parser.add_argument("--cache-only", action="store_true", help="read only artefacts already in the cache")
    args = parser.parse_args()
    args.cache.mkdir(parents=True, exist_ok=True)

    services = {row[0] for row in rows("services.tsv")}
    today = datetime.date.today().isoformat()
    problems, capabilities, signers, artefacts = [], [], [], {}

    def read(artefact):
        if artefact not in artefacts:
            url, path = resolve(artefact, args.cache, args.cache_only)
            artefacts[artefact] = (url, path, hashlib.sha256(path.read_bytes()).hexdigest() if path else "")
        return artefacts[artefact]

    for capability, needs, artefact, identifier, evidence in rows("sources.tsv"):
        if not set(needs.split(",")) <= services:
            problems.append(f"{capability}: unknown service in {needs}")
        try:
            url, path, digest = read(artefact)
            grade = 4
            if path is not None:
                if identifier not in {name for name, _ in class_files(path)}:
                    raise Problem(f"{url} does not contain class {identifier}")
                grade = 1
        except (Problem, OSError, ValueError, zipfile.BadZipFile, ElementTree.ParseError) as error:
            problems.append(f"{capability}: {error}")
            continue
        capabilities.append([capability, needs, "class", identifier, str(grade), evidence, url if path else "", digest, today])
        print(f"{capability}: {identifier}: grade {grade}{' from ' + url if path else ' (artefact not read yet)'}")

    for service, artefact, method in rows("signer-sources.tsv"):
        if service not in services or method != "embedded-certificates":
            problems.append(f"{service}: unknown service or method {method}")
            continue
        try:
            url, path, digest = read(artefact)
            if path is None:
                print(f"{service}: artefact not read yet")
                continue
            certificates = embedded_certificates(path)
            if not certificates:
                raise Problem(f"{url} embeds no certificate")
        except (Problem, OSError, ValueError, zipfile.BadZipFile, ElementTree.ParseError) as error:
            problems.append(f"{service}: {error}")
            continue
        for certificate in sorted(certificates):
            signers.append([service, certificate, "1", url, digest, today])
        print(f"{service}: {len(certificates)} certificates from {url}")

    (HERE / "capabilities.tsv").write_text("\n".join([
        "# SPDX-License-Identifier: CC0-1.0",
        "# SDK capabilities that need a system service (ADR 0021), written by update.py. Only grades 1 to 3",
        "# reach the phone. Columns: capability, services it needs (all), match type, identifier, grade,",
        "# where the vendor states the dependency, artefact read, its SHA-256, checked.",
    ] + ["\t".join(row) for row in capabilities]) + "\n")
    (HERE / "signers.tsv").write_text("\n".join([
        "# SPDX-License-Identifier: CC0-1.0",
        "# Certificates of the genuine packages of each service (ADR 0021), written by update.py from the",
        "# vendor's own client library. Columns: service, certificate SHA-256, grade, artefact read, its",
        "# SHA-256, checked.",
    ] + ["\t".join(row) for row in signers]) + "\n")
    shipped = [row for row in capabilities if int(row[4]) <= 3]
    (HERE / "SOURCE").write_text("\n".join([
        "# SPDX-License-Identifier: CC0-1.0",
        f"retrieved: {today}",
        f"capabilities: {len(capabilities)}",
        f"shipped-capabilities: {len(shipped)}",
        f"certificates: {len(signers)} for {len({row[0] for row in signers})} services",
        "method: data/sdk-needs/update.py, from the artefacts in sources.tsv and signer-sources.tsv",
    ]) + "\n")
    print(f"wrote {len(capabilities)} capabilities ({len(shipped)} ship) and {len(signers)} certificates")
    if problems:
        print("\n".join(["Problems to look at:"] + problems), file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
