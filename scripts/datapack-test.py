#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Signs a data pack payload with the test key in scripts/testdata, for tests only.

Debug builds trust the test key and release builds never do (docs/DATA-PACKS.md). The pack is in the
embedded-signature format of signify, and Ed25519 signatures are deterministic, so OpenSSL makes the
same bytes as `signify -S -e` would; CI has OpenSSL but not signify.

    scripts/datapack-test.py PAYLOAD PACK [--sequence N] [--date YYYY-MM-DD] [--corrupt]

--sequence replaces the payload's sequence number, so that a test can make a pack newer than the
app's own, and --date its date, for example to make the data look old. --corrupt changes the last
byte after signing, so that the signature no longer matches.
"""
import argparse
import base64
import pathlib
import re
import subprocess
import sys
import tempfile

TESTDATA = pathlib.Path(__file__).resolve().parent / "testdata"
# PKCS#8 wrapping of a raw Ed25519 seed (RFC 8410).
PKCS8_ED25519 = bytes.fromhex("302e020100300506032b657004220420")


def secret_key():
    """Key number and seed from the signify secret key, which has no passphrase."""
    raw = base64.b64decode((TESTDATA / "datapack-test.sec").read_text().splitlines()[1])
    # pkalg, kdfalg, kdfrounds, salt, checksum, keynum, then the 64-byte secret key.
    if raw[:4] != b"EdBK" or int.from_bytes(raw[4:8], "big") != 0:
        sys.exit("the test key must be a signify key without a passphrase")
    return raw[32:40], raw[40:72]


def sign(message, seed):
    with tempfile.TemporaryDirectory() as work:
        key = pathlib.Path(work, "key.der")
        key.write_bytes(PKCS8_ED25519 + seed)
        data = pathlib.Path(work, "message")
        data.write_bytes(message)
        return subprocess.run(
            ["openssl", "pkeyutl", "-sign", "-rawin", "-keyform", "DER", "-inkey", key, "-in", data],
            check=True, capture_output=True,
        ).stdout


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("payload", type=pathlib.Path)
    parser.add_argument("pack", type=pathlib.Path)
    parser.add_argument("--sequence", type=int)
    parser.add_argument("--date")
    parser.add_argument("--corrupt", action="store_true")
    args = parser.parse_args()

    payload = args.payload.read_bytes()
    header, end, rest = payload.partition(b"\nend\n")
    if not end:
        sys.exit(f"{args.payload}: not a data pack payload")
    for field, value in (("sequence", args.sequence), ("date", args.date)):
        if value is not None:
            header, count = re.subn(rb"^%s .*$" % field.encode(), b"%s %s" % (field.encode(), str(value).encode()),
                                    header, count=1, flags=re.M)
            if count != 1:
                sys.exit(f"{args.payload}: no {field} line")
    payload = header + end + rest
    number, seed = secret_key()
    signature = sign(payload, seed)
    pack = b"untrusted comment: verify with datapack-test.pub\n"
    pack += base64.b64encode(b"Ed" + number + signature) + b"\n" + payload
    if args.corrupt:
        pack = pack[:-1] + bytes([pack[-1] ^ 1])
    args.pack.write_bytes(pack)


if __name__ == "__main__":
    main()
