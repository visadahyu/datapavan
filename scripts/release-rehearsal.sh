#!/usr/bin/env bash
# A dry run of docs/RELEASE.md's "Every release" steps with throwaway keys, made in a temporary
# directory and deleted at the end: it builds the release APK, signs it with a fresh RSA 4096 key as
# apksigner does on the offline system, checks the certificate, the signature schemes, the version and
# the permissions, writes the release notes and signs them in signify's embedded format (with
# OpenSSL, which makes the same bytes, as scripts/datapack-test.py does), and checks them.
#
# With --install and an emulator attached, it also installs the signed release build in place of the
# debug build and runs the smoke test and the shortcut check on it, since only the release build is
# shrunk by R8; afterwards the debug build is installed again. Nothing this script makes may be
# published: its keys exist only for the run, and the real ones are made offline (ACTION 26).
#
#   scripts/release-rehearsal.sh [--install]
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PKG=org.visadahyu.datapavan
SDK=$(sed -n 's/^sdk.dir=//p' "$ROOT/android/local.properties" 2>/dev/null || true)
SDK=${ANDROID_HOME:-${SDK:-$HOME/Android/Sdk}}
TOOLS="$SDK/build-tools/$(ls "$SDK/build-tools" | sort -V | tail -1)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

fail() { echo "REHEARSAL FAILED: $*" >&2; exit 1; }

gradle="$ROOT/android/app/build.gradle.kts"
version=$(sed -n 's/^ *versionName = "\(.*\)"$/\1/p' "$gradle")
code=$(sed -n 's/^ *versionCode = \([0-9]*\)$/\1/p' "$gradle")
echo "== Rehearsal of the release of $version (versionCode $code)"

# 1. The unsigned release APK, as RELEASE.md's checks build it.
(cd "$ROOT/android" && ./gradlew --quiet :app:assembleRelease)
unsigned="$ROOT/android/app/build/outputs/apk/release/app-release-unsigned.apk"
[ -f "$unsigned" ] || fail "no unsigned release APK"

# 2. A throwaway key with the parameters of RELEASE.md: RSA 4096, 50 years.
pass=$(openssl rand -hex 24)
keytool -genkeypair -keystore "$WORK/rehearsal.p12" -storetype PKCS12 -alias datapavan -keyalg RSA \
    -keysize 4096 -validity 18250 -dname "CN=Datapavan rehearsal, O=Visadahyu" \
    -storepass "$pass" -keypass "$pass" >/dev/null 2>&1
expected=$(keytool -list -v -keystore "$WORK/rehearsal.p12" -alias datapavan -storepass "$pass" |
    sed -n 's/^.*SHA256: *//p' | tr -d ':' | tr 'A-F' 'a-f')
[ ${#expected} = 64 ] || fail "keytool printed no SHA-256 fingerprint"

# 3. Signing as on the offline system, then the checks the maintainer reads.
signed="$WORK/datapavan-$version.apk"
# The schemes are named, not left to apksigner: for minSdk 29 it would sign with v3 alone, which tools
# that read only v2 cannot check, and it would write a v4 file that no channel publishes.
"$TOOLS/apksigner" sign --ks "$WORK/rehearsal.p12" --ks-key-alias datapavan --ks-pass "pass:$pass" \
    --v1-signing-enabled false --v2-signing-enabled true --v3-signing-enabled true --v4-signing-enabled false \
    --out "$signed" "$unsigned" 2>/dev/null
# apksigner reports only the schemes that the APK's minSdk needs; --min-sdk-version 24 makes it
# check v2 as well.
certs=$("$TOOLS/apksigner" verify --verbose --print-certs --min-sdk-version 24 "$signed" 2>/dev/null)
grep -q '^Verifies$' <<<"$certs" || fail "apksigner does not verify the signed APK"
for scheme in v2 v3; do
    grep -q "^Verified using $scheme scheme.*: true$" <<<"$certs" || fail "not signed with scheme $scheme"
done
printed=$(sed -n 's/^.*Signer.*certificate SHA-256 digest: //p' <<<"$certs" | sort -u)
[ "$printed" = "$expected" ] || fail "apksigner shows $printed, keytool $expected"
echo "ok: signed with schemes v2 and v3; the certificate's SHA-256 is the key's"
[ ! -e "$signed.idsig" ] || fail "apksigner wrote a v4 signature file"

badging=$("$TOOLS/aapt2" dump badging "$signed")
grep -q "versionCode='$code' versionName='$version'" <<<"$badging" || fail "the APK's version is not $version ($code)"
grep -q "application-debuggable" <<<"$badging" && fail "the release APK is debuggable"
"$TOOLS/aapt2" dump permissions "$signed" | grep -q 'android.permission.INTERNET' && fail "the release APK asks for INTERNET"
echo "ok: version $version ($code), not debuggable, no INTERNET permission"

# 4. Release notes, signed in signify's embedded format with a throwaway Ed25519 key.
apk_sha=$(sha256sum "$signed" | cut -d' ' -f1)
cat >"$WORK/notes.txt" <<NOTES
Datapavan $version (rehearsal, not a release)

APK: datapavan-$version.apk
APK SHA-256: $apk_sha
Signing certificate SHA-256: $expected

Genuine Datapavan v0.1 has no internet access and never asks for it.
NOTES
# The same bytes as signify -G and signify -S -e: a key number, the raw Ed25519 public key, and a
# signature over the whole message, which follows the signature line. The check after it is the one a
# user or channel operator makes with signify -V -e: the key numbers match and the signature verifies.
python3 -I - "$WORK" <<'PY' || fail "the signed notes do not verify"
import base64, os, pathlib, subprocess, sys
work = pathlib.Path(sys.argv[1])
def openssl(*args):
    return subprocess.run(["openssl", *map(str, args)], check=True, capture_output=True).stdout
openssl("genpkey", "-algorithm", "ed25519", "-outform", "DER", "-out", work / "notes.der")
public = openssl("pkey", "-inform", "DER", "-in", work / "notes.der", "-pubout", "-outform", "DER")[-32:]
number = os.urandom(8)
work.joinpath("notes.pub").write_text("untrusted comment: Datapavan release notes rehearsal key\n"
                                      + base64.b64encode(b"Ed" + number + public).decode() + "\n")
notes = work.joinpath("notes.txt").read_bytes()
signature = openssl("pkeyutl", "-sign", "-rawin", "-keyform", "DER", "-inkey", work / "notes.der", "-in", work / "notes.txt")
work.joinpath("notes.txt.sig").write_bytes(b"untrusted comment: verify with notes.pub\n"
                                           + base64.b64encode(b"Ed" + number + signature) + b"\n" + notes)
# Verification, from the published files only.
pub = base64.b64decode(work.joinpath("notes.pub").read_text().splitlines()[1])
lines = work.joinpath("notes.txt.sig").read_bytes().split(b"\n", 2)
sig = base64.b64decode(lines[1])
assert pub[:2] == sig[:2] == b"Ed" and pub[2:10] == sig[2:10], "key numbers differ"
work.joinpath("pub.der").write_bytes(bytes.fromhex("302a300506032b6570032100") + pub[10:42])
work.joinpath("msg").write_bytes(lines[2])
work.joinpath("sig.bin").write_bytes(sig[10:])
openssl("pkeyutl", "-verify", "-rawin", "-pubin", "-keyform", "DER", "-inkey", work / "pub.der",
        "-in", work / "msg", "-sigfile", work / "sig.bin")
assert lines[2] == notes
PY
echo "ok: release notes signed and verified"

# 5. Optionally, the signed release build on an emulator.
if [ "${1:-}" = --install ]; then
    if [ "$(adb shell getprop ro.kernel.qemu | tr -d '\r')" != "1" ] && [ "$(adb shell getprop ro.boot.qemu | tr -d '\r')" != "1" ]; then
        fail "--install replaces the installed Datapavan and runs on emulators only"
    fi
    adb uninstall "$PKG" >/dev/null 2>&1 || true
    "$ROOT/scripts/smoke.sh" "$signed"
    "$ROOT/scripts/verify-shortcuts.sh"
    adb uninstall "$PKG" >/dev/null
    adb install "$ROOT/android/app/build/outputs/apk/debug/app-debug.apk" >/dev/null
    echo "ok: the signed release build runs; the debug build is installed again"
fi
echo "PASS: the release steps work with throwaway keys; nothing from this run may be published"
