#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Collects the official signing certificates of the apps in sources.tsv and writes signers.tsv (ADR 0018).

    data/app-signers/update.py [--cache DIR] [--cache-only]
    data/app-signers/update.py --read-play DIR --api LEVEL


Needs network access, apksigner and aapt2 from the Android SDK's build-tools, and a JDK's jarsigner and
keytool. Downloaded APKs and indexes are untrusted: they are only read, by apksigner, aapt2 and the JDK,
never run. They are kept in the cache folder (default ~/.cache/datapavan/app-signers). With
--cache-only, nothing is downloaded: every file must already be in the cache, for example when one new
channel was fetched by hand with the maintainer's approval.

Evidence, from strongest (ADR 0018):
  1  a fingerprint the developer publishes;
  2  F-Droid's AllowedAPKSigningKeys, or a repository index whose signature matches the repository's
     published key;
  3  IzzyOnDroid's index (it checks the author's key), or an APK whose OpenPGP signature verifies
     with the key whose fingerprint the developer publishes;
  4  APKs of official channels that agree across two channels;
  5  a single reading.
Every APK is read with apksigner across Android 10 to 17, so that every signer some phone sees is
recorded, with its lineage. Google Play copies cannot be downloaded: from-play.sh installs them on a
test device and copies their APKs, and --read-play records what they carry in play.tsv, which every
run then reads as the Play channel. Copies read on devices with two Android levels count as two
fetches. A conflict, such as a published fingerprint that no APK carries, is printed
and makes the script fail, so that a person looks at it before the data is committed.
"""
import argparse
import datetime
import hashlib
import json
import os
import pathlib
import re
import subprocess
import sys
import urllib.request
import zipfile

HERE = pathlib.Path(__file__).resolve().parent
MIN_SDK, MAX_SDK = 29, 37

# Repositories whose index update.py reads, with the SHA-256 of the key that signs it and where the
# repository publishes that key.
REPOS = {
    "fdroid": ("https://f-droid.org/repo",
               "43238d512c1e5eb2d6569f4a3afbf5523418b82e0a3ed1552770abb9a9c9ccab", 2,
               "https://f-droid.org/docs/Release_Channels_and_Signing_Keys/"),
    "guardian": ("https://guardianproject.info/fdroid/repo",
                 "b7c2eefd8dac7806af67dfcd92eb18126bc08312a7f2d6f3862e46013c7a6135", 2,
                 "https://guardianproject.info/signing-keys/"),
    "izzy": ("https://apt.izzysoft.de/fdroid/repo",
             "3bf0d6abfeae2f401707b6d966be743bf0eee49c2561b9ba39073711f628937a", 3,
             "https://apt.izzysoft.de/fdroid/"),
    "flclash": ("https://chen08209.github.io/FlClash-fdroid-repo/repo",
                "789d6d32668712ef7672f9e58deeb15fbd6dceec5ae7a4371ea72f2aae8a12fd", 2,
                "https://github.com/chen08209/FlClash"),
}


class Problem(Exception):
    """Something about one source that a person has to look at."""


def fail(message):
    raise Problem(message)


def tool(name):
    """An Android SDK build tool from the newest build-tools folder."""
    sdk = os.environ.get("ANDROID_HOME") or os.environ.get("ANDROID_SDK_ROOT")
    if not sdk:
        fail("set ANDROID_HOME")
    versions = sorted(pathlib.Path(sdk, "build-tools").iterdir(), key=lambda p: [int(x) for x in re.findall(r"\d+", p.name)])
    return str(versions[-1] / name)


def fingerprint(text):
    """A SHA-256 fingerprint in any common notation, as 64 lowercase hex digits."""
    digits = re.sub(r"[^0-9a-fA-F]", "", text).lower()
    if len(digits) != 64:
        fail(f"not a SHA-256 fingerprint: {text}")
    return digits


# Set by --cache-only: read files from the cache and download nothing.
OFFLINE = False


def fetch(url, cache, name=None, keep=False):
    """Downloads url into the cache. Only files whose name carries a version are kept between runs."""
    path = cache / (name or re.sub(r"[^A-Za-z0-9._-]", "_", url))
    if OFFLINE:
        if not path.exists():
            raise Problem(f"{url} is not in the cache")
        return path
    if not (keep and path.exists()):
        request = urllib.request.Request(url, headers={"User-Agent": "datapavan-app-signers"})
        with urllib.request.urlopen(request, timeout=120) as response, open(str(path) + ".part", "wb") as out:
            while chunk := response.read(1 << 20):
                out.write(chunk)
        os.replace(str(path) + ".part", path)
    return path


def run(*command):
    result = subprocess.run(command, capture_output=True, text=True)
    return result.returncode, result.stdout + result.stderr


def github_asset(repository, pattern, cache):
    """The URL and file of the newest release asset of owner/repo whose name matches pattern."""
    release = json.loads(fetch(f"https://api.github.com/repos/{repository}/releases/latest", cache).read_text())
    assets = [a for a in release.get("assets", []) if re.search(pattern, a["name"])]
    if len(assets) != 1:
        fail(f"{repository} {release.get('tag_name')}: {len(assets)} assets match {pattern}")
    url = assets[0]["browser_download_url"]
    return url, fetch(url, cache, f"{repository.replace('/', '_')}_{assets[0]['name']}", keep=True)


def page_asset(page, pattern, cache):
    """The URL and file of the newest download on a listing page whose name matches pattern."""
    names = sorted(set(re.findall(pattern, fetch(page, cache).read_text(errors="replace"))))
    if not names:
        fail(f"{page}: nothing matches {pattern}")
    url = page.rstrip("/") + "/" + names[-1]
    return url, fetch(url, cache, names[-1], keep=True)


def verify_openpgp(url, path, spec, cache):
    """Checks the APK's detached OpenPGP signature against the developer's published key.

    spec: the signature file's suffix, the key's URL, the key's fingerprint as the developer
    publishes it, and where it is published."""
    suffix, key_url, expected, _ = spec.split()
    expected = re.sub(r"[^0-9A-Fa-f]", "", expected).upper()
    signature = fetch(url + suffix, cache)
    key = fetch(key_url, cache)
    home = cache / "gnupg"
    home.mkdir(mode=0o700, exist_ok=True)
    run("gpg", "--homedir", str(home), "--batch", "--quiet", "--import", str(key))
    code, output = run("gpg", "--homedir", str(home), "--batch", "--status-fd", "1", "--verify", str(signature), str(path))
    valid = re.search(r"^\[GNUPG:\] VALIDSIG .* ([0-9A-F]{40,64})$", output, re.M)
    if code != 0 or not valid or valid.group(1) != expected:
        fail(f"{url}: the OpenPGP signature does not verify with key {expected}:\n{output[-600:]}")


def apk_certificates(path):
    """Package name, and each signing certificate with whether it is a debug certificate."""
    code, badging = run(tool("aapt2"), "dump", "packagename", str(path))
    if code != 0:
        fail(f"{path.name}: aapt2 cannot read it: {badging.strip()}")
    package = badging.strip().splitlines()[-1].strip()
    code, output = run(tool("apksigner"), "verify", "--print-certs", "--verbose",
                       "--min-sdk-version", str(MIN_SDK), "--max-sdk-version", str(MAX_SDK), str(path))
    if code != 0:
        fail(f"{path.name}: apksigner does not verify it:\n{output}")
    certificates = {}
    # A source stamp is Google Play's mark on APKs that went through Play, not a signing key.
    signers = [line for line in output.splitlines() if not line.startswith("Source Stamp")]
    for block in re.split(r"(?=^\S*Signer[^\n]*certificate DN:)", "\n".join(signers), flags=re.M):
        digest = re.search(r"certificate SHA-256 digest: ([0-9a-f]{64})", block)
        if digest:
            certificates[digest.group(1)] = "CN=Android Debug" in block
    from_play = "Source Stamp Signer: certificate DN:" in output and "O=Google Inc." in output
    schemes = re.findall(r"^Verified using (v[\d.]+) scheme \([^)]*\): true", output, flags=re.M)
    # Earlier keys from a rotation lineage identify genuine copies too.
    code, lineage = run(tool("apksigner"), "lineage", "--in", str(path), "--print-certs")
    if code == 0:
        for digest in re.findall(r"SHA-256 digest: ([0-9a-f]{64})", lineage):
            certificates.setdefault(digest, False)
    if not certificates:
        fail(f"{path.name}: no signer found")
    return package, certificates, from_play, schemes


def version_code(path):
    code, badging = run(tool("aapt2"), "dump", "badging", str(path))
    found = re.search(r"versionCode='(\d+)'", badging)
    if code != 0 or not found:
        fail(f"{path.name}: aapt2 cannot read its version")
    return found.group(1)


PLAY_HEADER = [
    "# SPDX-License-Identifier: CC0-1.0",
    "# Signing certificates of Google Play copies (ADR 0018), read by update.py --read-play from APKs that",
    "# from-play.sh installed from Play on a test device. Columns: package, Android API level of the device,",
    "# version code, SHA-256 of the base APK, certificates (SHA-256, \":debug\" for a debug certificate),",
    "# Play's source stamp (yes/no), signature schemes that verify, checked.",
]


def read_play(folder, api):
    """Records the certificates of the Play APKs in folder, read on a device with API level api, in play.tsv."""
    apps = {line.split("\t")[0] for line in (HERE / "apps.tsv").read_text().splitlines()
            if line and not line.startswith("#")}
    path = HERE / "play.tsv"
    rows = {}
    if path.exists():
        for line in path.read_text().splitlines():
            if line and not line.startswith("#"):
                columns = line.split("\t")
                rows[(columns[0], columns[1])] = columns
    today = datetime.date.today().isoformat()
    for apk in sorted(folder.glob("*.apk")):
        package, certificates, from_play, schemes = apk_certificates(apk)
        if package not in apps:
            fail(f"{apk.name}: {package} is not in apps.tsv")
        digest = hashlib.sha256(apk.read_bytes()).hexdigest()
        # The same APK read again keeps the date it was first read; only a new copy is dated today.
        before = rows.get((package, str(api)))
        rows[(package, str(api))] = [
            package, str(api), version_code(apk), digest,
            ",".join(d + (":debug" if debug else "") for d, debug in certificates.items()),
            "yes" if from_play else "no", ",".join(schemes), before[7] if before and before[3] == digest else today,
        ]
        print(f"{package} on API {api}: {', '.join(certificates)} ({', '.join(schemes)})")
    path.write_text("\n".join(PLAY_HEADER + ["\t".join(r) for _, r in sorted(rows.items())]) + "\n")
    print(f"play.tsv: {len(rows)} readings")


def repository_index(repo, cache):
    """The packages of a repository's index-v1, after checking the index's signature."""
    base, key, _, _ = REPOS[repo]
    jar = fetch(f"{base}/index-v1.jar", cache, f"{repo}-index-v1.jar")
    code, output = run("keytool", "-printcert", "-jarfile", str(jar))
    signers = {fingerprint(m) for m in re.findall(r"SHA256: ([0-9A-F:]{95})", output)}
    if code != 0 or signers != {key}:
        fail(f"{repo}: index-v1.jar is not signed by the published key {key}:\n{output[:600]}")
    # F-Droid-style repositories still sign their index with SHA-1, which the JDK refuses by default.
    # It is allowed for this check only; the signer must still be the repository's published key.
    policy = cache / "allow-sha1-jar.security"
    policy.write_text("jdk.jar.disabledAlgorithms=MD2, MD5, RSA keySize < 1024, DSA keySize < 1024\n")
    code, output = run("jarsigner", f"-J-Djava.security.properties={policy}", "-verify", "-strict", str(jar))
    if "jar verified" not in output:
        fail(f"{repo}: jarsigner does not verify index-v1.jar:\n{output[:600]}")
    with zipfile.ZipFile(jar) as archive:
        return json.loads(archive.read("index-v1.json"))["packages"]


def allowed_keys(url, cache):
    text = fetch(url, cache).read_text()
    block = re.search(r"^AllowedAPKSigningKeys:(.*(?:\n\s+-.*)*)", text, re.M)
    if not block:
        fail(f"{url}: no AllowedAPKSigningKeys")
    return [fingerprint(k) for k in re.findall(r"[0-9a-fA-F]{64}", block.group(1))]


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--cache", type=pathlib.Path, default=pathlib.Path.home() / ".cache/datapavan/app-signers")
    parser.add_argument("--read-play", type=pathlib.Path, metavar="DIR", help="record the Play APKs in DIR in play.tsv")
    parser.add_argument("--api", type=int, help="the API level of the device the Play APKs come from")
    parser.add_argument("--cache-only", action="store_true", help="read only files already in the cache")
    args = parser.parse_args()
    global OFFLINE
    OFFLINE = args.cache_only
    if args.read_play:
        if not args.api:
            parser.error("--read-play needs --api")
        try:
            read_play(args.read_play, args.api)
        except Problem as error:
            sys.exit(f"Problem: {error}")
        return
    args.cache.mkdir(parents=True, exist_ok=True)

    sources = [line.split("\t") for line in (HERE / "sources.tsv").read_text().splitlines()
               if line and not line.startswith("#")]
    apps = {line.split("\t")[0] for line in (HERE / "apps.tsv").read_text().splitlines()
            if line and not line.startswith("#")}
    indexes = {}
    # (package, sha256) -> evidence: grade, channels, controllers, sources, readings, debug
    found = {}
    problems = []

    def record(package, digest, grade, channel, controller, source, reading=None, debug=False):
        entry = found.setdefault((package, digest), {
            "grades": set(), "channels": set(), "controllers": set(), "sources": set(), "readings": set(), "debug": False})
        entry["grades"].add(grade)
        entry["channels"].add(channel)
        entry["controllers"].add(controller)
        entry["sources"].add(source)
        entry["debug"] |= debug
        if reading:
            entry["readings"].add(reading)

    def collect(package, channel, controller, method, location, value, openpgp):
        if method == "published":
            record(package, fingerprint(value), 1, channel, controller, location)
        elif method == "fdroid-allowed":
            for digest in allowed_keys(location, args.cache):
                record(package, digest, 2, channel, controller, location)
        elif method == "index":
            if value not in indexes:
                indexes[value] = repository_index(value, args.cache)
            versions = indexes[value].get(package)
            if not versions:
                fail(f"not in the {value} index")
            for digest in {v["signer"] for v in versions if v.get("signer")}:
                record(package, digest, REPOS[value][2], channel, controller, f"{REPOS[value][0]}/index-v1.jar")
        elif method == "apk":
            if location.startswith("github:"):
                url, path = github_asset(location[len("github:"):], value, args.cache)
            elif location.startswith("page:"):
                url, path = page_asset(location[len("page:"):], value, args.cache)
            else:
                url, path = location, fetch(location, args.cache)
            grade = 5
            if openpgp:
                verify_openpgp(url, path, openpgp, args.cache)
                grade = 3
            actual, certificates, from_play, _ = apk_certificates(path)
            if actual != package:
                fail(f"{url}: the APK is {actual}")
            for digest, debug in certificates.items():
                # An APK exported from Google Play carries Play's stamp and, usually, a key Google holds.
                record(package, digest, grade, channel, "google" if from_play else controller, url, reading=channel, debug=debug)
                if openpgp:
                    found[(package, digest)]["sources"].add(openpgp.split()[3])
                if from_play:
                    found[(package, digest)]["channels"].add("play")
            print(f"read {package} from {url}: {', '.join(certificates)}{' (exported from Google Play)' if from_play else ''}")
        else:
            fail(f"unknown method {method}")

    for row in sources:
        package, channel, controller, method, location, value = row[:6]
        if package not in apps:
            problems.append(f"{package} is in sources.tsv but not in apps.tsv")
        try:
            collect(package, channel, controller, method, location, value, row[6] if len(row) > 6 else "")
        except (Problem, OSError, ValueError, KeyError) as error:
            problems.append(f"{package} ({method} {location}): {error}")

    # Google Play copies, read on test devices. Play's source stamp marks Play App Signing, so Google holds
    # the key; without it the developer signed the APK it uploaded.
    play = HERE / "play.tsv"
    play_rows = [line for line in (play.read_text().splitlines() if play.exists() else [])
                 if line and not line.startswith("#")]
    for line in play_rows:
        package, api, _, _, certificates, stamp = line.split("\t")[:6]
        if package not in apps:
            problems.append(f"{package} is in play.tsv but not in apps.tsv")
            continue
        for certificate in certificates.split(","):
            digest, _, debug = certificate.partition(":")
            record(package, digest, 5, "play", "google" if stamp == "yes" else "developer",
                   f"https://play.google.com/store/apps/details?id={package}", reading=f"play@{api}", debug=debug == "debug")

    # Grade 4: the same certificate read from APKs of two channels, or of Play on two Android levels.
    for entry in found.values():
        if len(entry["readings"]) >= 2:
            entry["grades"].add(4)

    # A developer statement that no APK of the same channel carries needs a person's look.
    for (package, digest), entry in found.items():
        if 1 in entry["grades"]:
            read = {d for (p, d), e in found.items() if p == package and e["readings"] & entry["channels"]}
            if read and digest not in read:
                problems.append(f"{package}: the published key {digest} is on none of the APKs read")

    today = datetime.date.today().isoformat()
    # Offline, nothing was checked again: a certificate already recorded keeps the date it was checked.
    checked = {}
    if OFFLINE and (HERE / "signers.tsv").exists():
        for line in (HERE / "signers.tsv").read_text().splitlines():
            if line and not line.startswith("#"):
                columns = line.split("\t")
                checked[(columns[0], columns[1])] = columns[6]
    lines = [
        "# SPDX-License-Identifier: CC0-1.0",
        "# Official signing certificates of VPN, proxy and circumvention apps, and of Datapavan itself (ADR 0018,",
        "# ADR 0024), written by update.py.",
        "# Columns: package, SHA-256 of the signing certificate, grade (1 strongest to 5), whose key, channels,",
        "# debug (yes: an Android debug certificate), checked, sources.",
    ]
    for (package, digest), entry in sorted(found.items()):
        lines.append("\t".join([
            package, digest, str(min(entry["grades"])), ",".join(sorted(entry["controllers"])),
            ",".join(sorted(entry["channels"])), "yes" if entry["debug"] else "no", checked.get((package, digest), today),
            " ".join(sorted(entry["sources"])),
        ]))
    (HERE / "signers.tsv").write_text("\n".join(lines) + "\n")
    grades = [min(e["grades"]) for e in found.values()]
    (HERE / "SOURCE").write_text("\n".join([
        "# SPDX-License-Identifier: CC0-1.0",
        f"retrieved: {today}",
        f"apps: {len(apps)}",
        f"packages-with-certificates: {len({p for p, _ in found})}",
        f"certificates: {len(found)}",
        f"play-readings: {len(play_rows)}",
        "by-grade: " + ", ".join(f"{g}: {grades.count(g)}" for g in range(1, 6)),
        "method: data/app-signers/update.py, from the sources in sources.tsv and the Play readings in play.tsv",
    ]) + "\n")
    print(f"wrote {len(found)} certificates for {len({p for p, _ in found})} packages")
    if problems:
        print("\n".join(["Problems to look at:"] + problems), file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
