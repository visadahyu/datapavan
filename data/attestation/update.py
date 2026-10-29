# SPDX-License-Identifier: Apache-2.0
"""Refreshes Google's key attestation trust anchors and the attestation revocation list.

Run from anywhere with `python3 -I data/attestation/update.py`; it needs `openssl` on PATH and
writes google-roots.pem, revoked-serials.txt and SOURCE next to itself. It fails if the
documentation page no longer states its licence, so that a licence change is read by a person
before the data changes (ADR 0015, decision 9).
"""
import datetime
import hashlib
import html
import json
import pathlib
import re
import subprocess
import sys
import urllib.request

PAGE_URL = "https://developer.android.com/privacy-and-security/security-key-attestation?hl=en"
STATUS_URL = "https://android.googleapis.com/attestation/status"
LICENCE_STATEMENT = "Content and code samples on this page are subject to the licenses described in the Content License"
HERE = pathlib.Path(__file__).resolve().parent
PEM = re.compile(r"-----BEGIN CERTIFICATE-----[A-Za-z0-9+/=\s]+?-----END CERTIFICATE-----")


def fetch(url: str) -> bytes:
    with urllib.request.urlopen(url, timeout=60) as response:
        return response.read()


def openssl(pem: str, *args: str) -> bytes:
    return subprocess.run(["openssl", *args], input=pem.encode(), capture_output=True, check=True).stdout


def anchors(page: str) -> list[str]:
    """One certificate per distinct root key: the one that stays valid longest."""
    best: dict[str, tuple[datetime.datetime, str]] = {}
    for block in PEM.findall(page):
        pem = re.sub(r"\s+", "\n", block.replace("-----BEGIN CERTIFICATE-----", "").replace("-----END CERTIFICATE-----", "").strip())
        pem = "-----BEGIN CERTIFICATE-----\n" + pem + "\n-----END CERTIFICATE-----\n"
        key = openssl(openssl(pem, "x509", "-pubkey", "-noout").decode(), "pkey", "-pubin", "-outform", "DER")
        end = openssl(pem, "x509", "-noout", "-enddate").decode().strip().removeprefix("notAfter=")
        not_after = datetime.datetime.strptime(end, "%b %d %H:%M:%S %Y %Z")
        fingerprint = hashlib.sha256(key).hexdigest()
        if fingerprint not in best or best[fingerprint][0] < not_after:
            best[fingerprint] = (not_after, pem)
    return [best[k][1] for k in sorted(best)]


def revoked(status: bytes) -> list[str]:
    entries = json.loads(status)["entries"]
    serials = []
    for serial, entry in entries.items():
        if not re.fullmatch(r"[a-f1-9][a-f0-9]*", serial) or entry.get("status") not in ("REVOKED", "SUSPENDED"):
            sys.exit(f"unexpected entry in the status list: {serial}")
        serials.append(serial)
    return sorted(serials)


def main() -> None:
    page_bytes = fetch(PAGE_URL)
    status_bytes = fetch(STATUS_URL)
    page = html.unescape(page_bytes.decode("utf-8"))
    if LICENCE_STATEMENT not in re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", page)):
        sys.exit("the documentation page no longer states its licence; read it and update data/attestation/LICENSE")
    roots = anchors(page)
    if len(roots) != 2:
        sys.exit(f"expected 2 root keys on the page, found {len(roots)}; read the page before updating")
    serials = revoked(status_bytes)

    (HERE / "google-roots.pem").write_text("".join(roots))
    (HERE / "revoked-serials.txt").write_text(
        "# SPDX-License-Identifier: LicenseRef-NoLicenceStated\n"
        "# Serial numbers, in lowercase hex, of attestation certificates that Google has revoked.\n"
        + "".join(s + "\n" for s in serials)
    )
    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    (HERE / "SOURCE").write_text(
        "# SPDX-License-Identifier: CC0-1.0\n"
        f"retrieved: {now}\n"
        f"page: {PAGE_URL}\n"
        f"page-sha256: {hashlib.sha256(page_bytes).hexdigest()}\n"
        f"page-licence-statement: {LICENCE_STATEMENT}\n"
        f"status-list: {STATUS_URL}\n"
        f"status-list-sha256: {hashlib.sha256(status_bytes).hexdigest()}\n"
        f"root-keys: {len(roots)}\n"
        f"revoked-serials: {len(serials)}\n"
    )
    print(f"{len(roots)} root keys, {len(serials)} revoked serials")


if __name__ == "__main__":
    main()
