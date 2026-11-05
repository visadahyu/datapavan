#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Checks that every place that publishes Datapavan's keys matches the files in keys/ (ADR 0024).

    scripts/check-keys.py

People compare these fingerprints to tell a genuine copy from a fake, and the app's self-check reads
the same value from data/app-signers. A typing mistake in any of them would make a genuine copy look
fake, so each one is compared with the certificate itself. Part of scripts/check.sh.
"""
import base64
import hashlib
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
PACKAGE = "org.visadahyu.datapavan"
RECIPE = "docs/fdroid/org.visadahyu.datapavan.yml"

problems = []


def text(path):
    return (ROOT / path).read_text(encoding="utf-8")


def rows(path):
    return [line.split("\t") for line in text(path).splitlines() if line and not line.startswith("#")]


def public_key(path):
    """The second line of a signify public key file, which is the key itself."""
    lines = text(path).splitlines()
    if len(lines) != 2 or not lines[0].endswith("public key"):
        problems.append(f"{path} is not a signify public key file")
        return ""
    return lines[1]


def main():
    pem = re.search(r"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----", text("keys/datapavan-release.pem"), re.S)
    if not pem:
        sys.exit("keys/datapavan-release.pem holds no certificate")
    digest = hashlib.sha256(base64.b64decode(pem.group(1))).hexdigest()
    pairs = ":".join(digest[i:i + 2] for i in range(0, 64, 2)).upper()

    # People read the fingerprint in these, in one line or in several.
    for path in ("README.md", "keys/README.md", "docs/RELEASE.md", "docs/site/index.html"):
        if pairs not in re.sub(r"\s|<br>", "", text(path)):
            problems.append(f"{path} does not show the certificate's fingerprint {pairs}")

    if f"AllowedAPKSigningKeys: {digest}\n" not in text(RECIPE):
        problems.append(f"{RECIPE}: AllowedAPKSigningKeys is not {digest}")

    published = [r for r in rows("data/app-signers/sources.tsv") if r[0] == PACKAGE]
    if [(r[2], r[3], r[5].replace(":", "").lower()) for r in published] != [("developer", "published", digest)]:
        problems.append(f"data/app-signers/sources.tsv needs one published developer row for {PACKAGE} with {digest}")
    signers = [r for r in rows("data/app-signers/signers.tsv") if r[0] == PACKAGE]
    if [(r[1], r[2], r[3], r[5]) for r in signers] != [(digest, "1", "developer", "no")]:
        problems.append(f"data/app-signers/signers.tsv needs one grade 1 developer row for {PACKAGE} with {digest}")
    if [r[2] for r in rows("data/app-signers/apps.tsv") if r[0] == PACKAGE] != ["yes"]:
        problems.append(f"data/app-signers/apps.tsv needs {PACKAGE} with a closed key set")

    data_key = public_key("keys/datapavan-data-1.pub")
    notes_key = public_key("keys/datapavan-notes-1.pub")
    if f"key {data_key}\n" not in text("data/PACK"):
        problems.append(f"data/PACK does not name the data-signing key {data_key}")
    for path in ("README.md", "keys/README.md"):
        for name, key in (("data-signing", data_key), ("release notes", notes_key)):
            if key not in text(path):
                problems.append(f"{path} does not show the {name} key {key}")

    if problems:
        sys.exit("\n".join(problems))
    print(f"keys: every published copy matches keys/ ({pairs})")


main()
