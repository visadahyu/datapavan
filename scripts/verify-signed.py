"""Checks a release's signed files on the main system, from the published keys only (docs/RELEASE.md,
"Every release", step 6). It needs no secret and trusts nothing that came back from the offline system
except through a signature or a hash that the notes name.

    python3 -I scripts/verify-signed.py DIRECTORY [COMMIT]

DIRECTORY holds what the offline step wrote: notes.txt and notes.txt.sig, and the signed APK and data
pack that the notes name. COMMIT, by default HEAD, is the release commit. Needs openssl and apksigner
(the newest build-tools under ANDROID_HOME), not signify, which the main system lacks: signify's
signatures are Ed25519, which openssl checks.
"""

import base64
import hashlib
import os
import pathlib
import re
import subprocess
import sys
import tempfile
import zipfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
KEYS = ROOT / "keys"
# The DER prefix of an Ed25519 public key (RFC 8410), followed by its 32 bytes.
ED25519_DER_PREFIX = bytes.fromhex("302a300506032b6570032100")


def fail(message):
    print(f"VERIFY FAILED: {message}", file=sys.stderr)
    sys.exit(1)


def ok(message):
    print(f"ok: {message}")


def signify_verify(signed, purpose):
    """Checks a file in signify's embedded format (`signify -S -e`) and returns the signed bytes. The
    key is the one in keys/ whose key number the signature names, and it must be a key for `purpose`
    ("notes" or "data"), so that a data key cannot vouch for release notes or the other way round."""
    lines = signed.read_bytes().split(b"\n", 2)
    if len(lines) < 3 or not lines[0].startswith(b"untrusted comment: "):
        fail(f"{signed.name} is not in signify's embedded format")
    signature = base64.b64decode(lines[1], validate=True)
    if len(signature) != 74 or signature[:2] != b"Ed":
        fail(f"{signed.name} has no Ed25519 signature")
    matches = []
    for pub in sorted(KEYS.glob("*.pub")):
        key = base64.b64decode(pub.read_text().splitlines()[1], validate=True)
        if len(key) == 42 and key[:2] == b"Ed" and key[2:10] == signature[2:10]:
            matches.append((pub, key))
    if len(matches) != 1:
        fail(f"{signed.name}: {len(matches)} keys in keys/ have its key number")
    pub, key = matches[0]
    if not pub.name.startswith(f"datapavan-{purpose}-"):
        fail(f"{signed.name} is signed with {pub.name}, which is not a {purpose} key")
    with tempfile.TemporaryDirectory() as tmp:
        tmp = pathlib.Path(tmp)
        (tmp / "pub.der").write_bytes(ED25519_DER_PREFIX + key[10:])
        (tmp / "message").write_bytes(lines[2])
        (tmp / "signature").write_bytes(signature[10:])
        result = subprocess.run(
            ["openssl", "pkeyutl", "-verify", "-rawin", "-pubin", "-keyform", "DER",
             "-inkey", tmp / "pub.der", "-in", tmp / "message", "-sigfile", tmp / "signature"],
            capture_output=True, text=True, check=False,
        )
    if result.returncode != 0:
        fail(f"{signed.name}: the signature does not match ({(result.stdout + result.stderr).strip()})")
    ok(f"{signed.name} is signed with keys/{pub.name}")
    return lines[2]


def apksigner():
    home = os.environ.get("ANDROID_HOME") or os.environ.get("ANDROID_SDK_ROOT") or str(pathlib.Path.home() / "Android/sdk")
    tools = sorted((pathlib.Path(home) / "build-tools").glob("*/apksigner"), key=lambda p: [int(n) for n in re.findall(r"\d+", p.parent.name)])
    if not tools:
        fail(f"no apksigner under {home}/build-tools")
    return str(tools[-1])


def main():
    if len(sys.argv) not in (2, 3):
        fail("usage: python3 -I scripts/verify-signed.py DIRECTORY [COMMIT]")
    out = pathlib.Path(sys.argv[1])
    commit = subprocess.run(["git", "-C", ROOT, "rev-parse", sys.argv[2] if len(sys.argv) == 3 else "HEAD"],
                            capture_output=True, text=True, check=True).stdout.strip()

    notes = signify_verify(out / "notes.txt.sig", "notes")
    if notes != (out / "notes.txt").read_bytes():
        fail("the signed notes differ from notes.txt")
    ok("notes.txt is what was signed")
    text = notes.decode()
    if "@@" in text:
        fail("the notes still hold a placeholder")

    def field(name):
        found = re.findall(rf"^{re.escape(name)}: (.+)$", text, re.M)
        if len(found) != 1:
            fail(f"the notes have {len(found)} lines for {name}")
        return found[0]

    if field("Commit") != commit:
        fail(f"the notes name commit {field('Commit')}, not {commit}")
    ok(f"the notes name the release commit {commit[:12]}")

    gradle = subprocess.run(["git", "-C", ROOT, "show", f"{commit}:android/app/build.gradle.kts"],
                            capture_output=True, text=True, check=True).stdout
    version = re.search(r'^\s*versionName = "(.+)"$', gradle, re.M).group(1)
    if text.splitlines()[0] != f"Datapavan {version}":
        fail(f"the notes begin \"{text.splitlines()[0]}\", not \"Datapavan {version}\"")
    ok(f"the notes are for version {version}, the commit's")

    apk = out / field("APK")
    if apk.name != f"datapavan-{version}.apk" or not apk.is_file():
        fail(f"no signed APK {apk.name} for version {version}")
    if hashlib.sha256(apk.read_bytes()).hexdigest() != field("APK SHA-256"):
        fail(f"{apk.name}'s SHA-256 is not the one in the notes")
    ok(f"{apk.name}'s SHA-256 is the one in the notes")

    # apksigner checks every scheme's signature over the whole file; --min-sdk-version 24 makes it
    # report v2 too, which it otherwise skips for minSdk 29 (docs/RELEASE.md, step 4).
    verified = subprocess.run([apksigner(), "verify", "--verbose", "--print-certs", "--min-sdk-version", "24", apk],
                              capture_output=True, text=True, check=False)
    if verified.returncode != 0:
        fail(f"apksigner rejects {apk.name}: {verified.stdout}{verified.stderr}")
    report = verified.stdout
    for scheme in ("v2", "v3"):
        if not re.search(rf"^Verified using {scheme} scheme \(APK Signature Scheme {scheme}\): true$", report, re.M):
            fail(f"{apk.name} is not signed with scheme {scheme}")
    if re.search(r"^Number of signers: (\d+)$", report, re.M).group(1) != "1":
        fail(f"{apk.name} has more than one signer")
    # With --verbose each scheme's signer has its lines ("V3.0 Signer: certificate SHA-256 digest: ...").
    certificates = set(re.findall(r"^[^\n]*Signer[^\n:]*: certificate SHA-256 digest: ([0-9a-f]{64})$", report, re.M))
    if len(certificates) != 1:
        fail(f"{apk.name} names {len(certificates)} signing certificates")
    certificate = certificates.pop()
    ok(f"{apk.name} is signed with v2 and v3 by one certificate")
    if field("Signing certificate SHA-256").replace(":", "").lower() != certificate:
        fail("the notes name another certificate than the APK's")
    pem = subprocess.run(["openssl", "x509", "-in", KEYS / "datapavan-release.pem", "-noout", "-fingerprint", "-sha256"],
                         capture_output=True, text=True, check=True).stdout
    if pem.split("=", 1)[1].strip().replace(":", "").lower() != certificate:
        fail("the APK's certificate is not keys/datapavan-release.pem")
    ok("the APK's certificate is keys/datapavan-release.pem, as the notes say")

    pack = out / field("Data pack")
    payload = signify_verify(pack, "data")
    if hashlib.sha256(payload).hexdigest() != field("Data pack fingerprint"):
        fail(f"{pack.name}'s fingerprint is not the one in the notes")
    ok(f"{pack.name}'s fingerprint is the one in the notes")
    with zipfile.ZipFile(apk) as zipped:
        if zipped.read("assets/data/bundled.payload") != payload:
            fail(f"{pack.name} holds other data than the APK carries")
    ok(f"{pack.name} holds the data the APK carries")

    sums = out / "SHA256SUMS"
    if sums.is_file():
        for line in sums.read_text().splitlines():
            digest, name = line.split(maxsplit=1)
            name = name.lstrip("*")
            if (out / name).is_file() and hashlib.sha256((out / name).read_bytes()).hexdigest() != digest:
                fail(f"SHA256SUMS: {name} differs")
        ok("SHA256SUMS agrees with the files it names that are here")
    print(f"== the signed files of {version} check out")


if __name__ == "__main__":
    main()
