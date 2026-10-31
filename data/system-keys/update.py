#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Writes keys.tsv: the SHA-256 of every system signing key that cannot be trusted (ADR 0023).

    data/system-keys/update.py [--cache DIR] [--cache-only]

Public test keys and development keys are read from the certificate files that sources.tsv names,
which googlesource serves as base64; the SHA-256 of each certificate's DER encoding is what Android and
apksigner print. The leaked platform certificates come from leaked.tsv, copied by hand from Google's
list. Files are only read, and each one's SHA-256 is recorded. With --cache-only, a file not in the
cache is skipped. A file that is not one X.509 certificate, or a fingerprint that is not 64 hex digits,
is a problem a person has to look at, and makes the script fail.
"""
import argparse
import base64
import datetime
import hashlib
import pathlib
import re
import subprocess
import sys
import urllib.request

HERE = pathlib.Path(__file__).resolve().parent
SHA256 = re.compile(r"[0-9a-f]{64}")
PEM = re.compile(rb"-----BEGIN CERTIFICATE-----\s*(.+?)\s*-----END CERTIFICATE-----", re.S)


def rows(path):
    return [line.split("\t") for line in path.read_text().splitlines() if line and not line.startswith("#")]


def fetch(url, cache, cache_only):
    path = cache / re.sub(r"[^A-Za-z0-9._-]", "_", url)
    if cache_only:
        return path if path.exists() else None
    request = urllib.request.Request(url, headers={"User-Agent": "datapavan-system-keys"})
    with urllib.request.urlopen(request, timeout=60) as response:
        path.write_bytes(response.read())
    return path


def certificate(data, kind):
    """The DER encoding of the one certificate in a PEM or DER file."""
    if kind == "pem":
        found = PEM.findall(data)
        if len(found) != 1:
            raise ValueError(f"{len(found)} certificates in the PEM file")
        data = base64.b64decode(b"".join(found[0].split()))
    if data[:1] != b"\x30":
        raise ValueError("not a DER structure")
    return data


def subject(der):
    """The certificate's subject as openssl prints it, for people reading keys.tsv."""
    out = subprocess.run(["openssl", "x509", "-inform", "DER", "-noout", "-subject", "-nameopt", "RFC2253"],
                         input=der, capture_output=True, check=True).stdout.decode()
    return out.strip().removeprefix("subject=")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--cache", type=pathlib.Path, default=pathlib.Path.home() / ".cache/datapavan/system-keys")
    parser.add_argument("--cache-only", action="store_true", help="read only files already in the cache")
    args = parser.parse_args()
    args.cache.mkdir(parents=True, exist_ok=True)

    today = datetime.date.today().isoformat()
    problems = []
    lines = [
        "# SPDX-License-Identifier: CC0-1.0",
        "# System signing keys that cannot be trusted (ADR 0023), written by update.py. Columns: SHA-256 of",
        "# the certificate, kind (aosp-test, google-dev or leaked), name, subject, source, the source's",
        "# SHA-256 (of the downloaded file; empty for a web page), date read.",
    ]
    for kind, name, form, url in rows(HERE / "sources.tsv"):
        try:
            path = fetch(url, args.cache, args.cache_only)
        except OSError as error:
            problems.append(f"{url}: {error}")
            continue
        if path is None:
            print(f"{kind} {name}: not read yet")
            continue
        try:
            data = base64.b64decode(path.read_bytes(), validate=False)
            der = certificate(data, form)
            lines.append("\t".join([hashlib.sha256(der).hexdigest(), kind, name, subject(der), url,
                                    hashlib.sha256(data).hexdigest(), today]))
        except (ValueError, subprocess.CalledProcessError) as error:
            problems.append(f"{url}: {error}")
    for number, (cert, _sample, source, _published, read) in enumerate(rows(HERE / "leaked.tsv"), start=1):
        if not SHA256.fullmatch(cert):
            problems.append(f"leaked.tsv row {number}: {cert} is not a SHA-256")
            continue
        lines.append("\t".join([cert, "leaked", f"apvi-{number}", "", source, "", read]))
    fingerprints = [line.split("\t")[0] for line in lines if not line.startswith("#")]
    if len(set(fingerprints)) != len(fingerprints):
        problems.append("a fingerprint appears twice")
    (HERE / "keys.tsv").write_text("\n".join(lines) + "\n")
    (HERE / "SOURCE").write_text("\n".join([
        "# SPDX-License-Identifier: CC0-1.0",
        f"retrieved: {today}",
        f"keys: {len(fingerprints)}",
        "method: data/system-keys/update.py, from sources.tsv (AOSP and CTS certificate files) and leaked.tsv (by hand)",
    ]) + "\n")
    print(f"wrote {len(fingerprints)} keys")
    if problems:
        print("\n".join(["Problems to look at:"] + problems), file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
