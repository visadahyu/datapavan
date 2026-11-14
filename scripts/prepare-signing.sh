#!/usr/bin/env bash
# Gathers what a release of one edition carries to the offline system (docs/RELEASE.md, "Every release"),
# from a clean commit that is on origin/main: the unsigned APK once two builds of it agree
# (scripts/reproducible.sh), the data pack's payload, the notes to sign, and SHA256SUMS of them all. It
# needs no key and signs nothing. The notes keep @@APK_SHA256@@ and @@FINGERPRINT@@ for the offline step to
# fill in, since the signed APK's hash exists only there.
#
# The files carry the edition (ADR 0045; the maintainer, 2026-11-14): datapavan-basic-<version>.apk and
# datapavan-advanced-<version>.apk, from the release after 0.1.2, whose published datapavan-0.1.2.apk keeps
# its name. Basic and Advanced share one version line, so Advanced is prepared only at Basic's version.
#
#   scripts/prepare-signing.sh DIRECTORY [EDITION]    a directory that is missing or empty; basic (the
#                                                     default) or advanced
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT=${1:?usage: scripts/prepare-signing.sh DIRECTORY [basic|advanced]}
EDITION=${2:-basic}

fail() { echo "PREPARE FAILED: $*" >&2; exit 1; }

case $EDITION in
    basic) NAME="Datapavan Basic" ;;
    advanced) NAME="Datapavan Advanced" ;;
    *) fail "the edition is basic or advanced, not \"$EDITION\"" ;;
esac

[ -z "$(git -C "$ROOT" status --porcelain)" ] || fail "the working tree is not clean"
commit=$(git -C "$ROOT" rev-parse HEAD)
git -C "$ROOT" merge-base --is-ancestor "$commit" origin/main || fail "$commit is not on origin/main"

gradle="$ROOT/android/app/build.gradle.kts"
version=$(sed -n 's/^ *versionName = "\(.*\)"$/\1/p' "$gradle")
code=$(sed -n 's/^ *versionCode = \([0-9]*\)$/\1/p' "$gradle")
if [ "$EDITION" = advanced ]; then
    # Advanced's version is on a line of its own (app/build.gradle.kts), and must be Basic's.
    advanced_version=$(sed -n 's/^ *if (advanced) { versionCode = [0-9]*; versionName = "\(.*\)" }$/\1/p' "$gradle")
    code=$(sed -n 's/^ *if (advanced) { versionCode = \([0-9]*\); versionName = ".*" }$/\1/p' "$gradle")
    [ -n "$code" ] || fail "android/app/build.gradle.kts has no line with Advanced's version"
    [ "$advanced_version" = "$version" ] ||
        fail "Advanced's versionName is \"$advanced_version\", Basic's \"$version\": the two share one version line"
fi
case $version in
    "" | *-*) fail "\"$version\" is not a release's version" ;;
esac
# The app shows this date and counts its age from it (Release.kt), so it must be the changelog's.
date=$(sed -n 's/^ *buildConfigField("String", "RELEASE_DATE", "\\"\([0-9-]*\)\\"")$/\1/p' "$gradle")
grep -qxF "## [$version] - $date" "$ROOT/CHANGELOG.md" || fail "CHANGELOG.md has no \"## [$version] - $date\" for RELEASE_DATE \"$date\""
# Advanced's store texts have no place in fastlane/ yet (ADR 0045: F-Droid gets a recipe per edition).
[ "$EDITION" = basic ] || fail "Advanced's store changelog has no place in fastlane/ yet; decide it before its first release"
changes="$ROOT/fastlane/metadata/android/en-US/changelogs/$code.txt"
[ -f "$changes" ] || fail "no store changelog for versionCode $code"
sequence=$(sed -n 's/^sequence //p' "$ROOT/data/PACK")
[ -n "$sequence" ] || fail "data/PACK has no sequence"

mkdir -p "$OUT"
[ -z "$(ls -A "$OUT")" ] || fail "$OUT is not empty"

apk="datapavan-$EDITION-$version"
# reproducible.sh builds both editions and keeps Basic's APK in its second argument, Advanced's in its third.
if [ "$EDITION" = basic ]; then
    "$ROOT/scripts/reproducible.sh" "$commit" "$OUT/$apk-unsigned.apk"
else
    "$ROOT/scripts/reproducible.sh" "$commit" "" "$OUT/$apk-unsigned.apk"
fi
[ -f "$OUT/$apk-unsigned.apk" ] || fail "no unsigned APK"

(cd "$ROOT/android" && ./gradlew --quiet :app:dataPayload)
cp "$ROOT/android/app/build/datapack/data/bundled.payload" "$OUT/datapavan-data-$sequence.payload"
pack_fingerprint=$(sha256sum "$OUT/datapavan-data-$sequence.payload" | cut -d' ' -f1)

cat >"$OUT/notes.txt" <<NOTES
$NAME $version

Commit: $commit
APK: $apk.apk
APK SHA-256: @@APK_SHA256@@
Signing certificate SHA-256: @@FINGERPRINT@@
Data pack: datapavan-data-$sequence.pack
Data pack fingerprint: $pack_fingerprint

$(cat "$changes")

Genuine Datapavan Basic never has internet access. Genuine Datapavan Advanced uses it only for your own
apps' traffic and the servers you choose, and never asks for your camera, microphone, location, contacts,
messages or call log. No Datapavan app ever asks you for money.
NOTES

(cd "$OUT" && sha256sum -- * >SHA256SUMS)
echo "== ready to sign, from $commit:"
(cd "$OUT" && ls -l)
