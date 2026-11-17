#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Converts Google's key attestation test chains (android/keyattestation, testdata/) into the TSV that
attestation.rs's tests read: each leaf certificate's KeyDescription extension, exactly as
X509Certificate.getExtensionValue returns it, with the values Google's reference library decodes from
it (the .json beside each .pem).

    core/engine/testdata/keyattestation/convert.py > core/engine/testdata/keyattestation/vectors.tsv

It reads the files in this directory, whose SHA-256 sums SOURCE records. The certificate is walked here
with a few lines of DER, not with attestation.rs's parser, so that the two do not share a reading.
"""
import base64
import json
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
# 1.3.6.1.4.1.11129.2.1.17, as its DER OBJECT IDENTIFIER element.
KEY_DESCRIPTION_OID = bytes.fromhex("060a2b06010401d679020111")


def element(data, at):
    """The (tag, start of content, end) of the DER element at `at`."""
    tag = data[at]
    length = data[at + 1]
    start = at + 2
    if length & 0x80:
        count = length & 0x7F
        length = int.from_bytes(data[start:start + count], "big")
        start += count
    return tag, start, start + length


def children(data, start, end):
    while start < end:
        tag, content, after = element(data, start)
        yield tag, start, content, after
        start = after


def extension(certificate):
    """The KeyDescription extension's OCTET STRING element, tag and length included."""
    _, content, end = element(certificate, 0)
    _, tbs, tbs_end = element(certificate, content)
    for tag, _, inner, after in children(certificate, tbs, tbs_end):
        if tag != 0xA3:  # [3] extensions
            continue
        _, sequence, sequence_end = element(certificate, inner)
        for _, _, fields, fields_end in children(certificate, sequence, sequence_end):
            parts = list(children(certificate, fields, fields_end))
            if certificate[parts[0][1]:parts[0][3]] == KEY_DESCRIPTION_OID:
                _, at, _, value_end = parts[-1]
                return certificate[at:value_end]
    raise SystemExit("no KeyDescription extension")


def leaf(pem_path):
    text = pem_path.read_text()
    body = text.split("-----BEGIN CERTIFICATE-----")[1].split("-----END CERTIFICATE-----")[0]
    return base64.b64decode("".join(body.split()))


def hex64(value):
    return base64.b64decode(value).hex() if value is not None else "-"


def plain(value):
    if value is None:
        return "-"
    return str(value).lower() if isinstance(value, bool) else str(value)


def list_columns(authorizations):
    root = authorizations.get("rootOfTrust")
    columns = [
        plain(root["deviceLocked"]) if root else "-",
        root["verifiedBootState"] if root else "-",
        hex64(root.get("verifiedBootKey")) if root else "-",
        hex64(root.get("verifiedBootHash")) if root else "-",
    ]
    for name in ("osVersion", "osPatchLevel", "vendorPatchLevel", "bootPatchLevel"):
        columns.append(plain(authorizations.get(name)))
    return columns


def main():
    print("# SPDX-License-Identifier: Apache-2.0")
    print("# SPDX-FileCopyrightText: Google LLC (android/keyattestation, testdata/); converted by convert.py")
    print("# path, extension (hex), then from the .json, '-' where absent or where there is no .json:")
    print("# attestationVersion, attestationSecurityLevel, keyMintSecurityLevel, attestationChallenge (hex),")
    print("# then for softwareEnforced and for hardwareEnforced: deviceLocked, verifiedBootState,")
    print("# verifiedBootKey (hex), verifiedBootHash (hex), osVersion, osPatchLevel, vendorPatchLevel,")
    print("# bootPatchLevel")
    for pem in sorted(HERE.glob("*/**/*.pem")):
        relative = pem.relative_to(HERE).as_posix()
        row = [relative, extension(leaf(pem)).hex()]
        expected = pem.with_suffix(".json")
        if expected.exists():
            description = json.loads(expected.read_text())
            row += [
                description["attestationVersion"],
                description["attestationSecurityLevel"],
                description["keyMintSecurityLevel"],
                hex64(description["attestationChallenge"]),
            ]
            row += list_columns(description.get("softwareEnforced", {}))
            row += list_columns(description.get("hardwareEnforced", {}))
        else:
            row += ["-"] * 20
        print("\t".join(row))


if __name__ == "__main__":
    sys.exit(main())
