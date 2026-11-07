#!/usr/bin/env bash
# Gathers what a release carries to the offline system (docs/RELEASE.md, "Every release"), from a clean
# commit that is on origin/main: the unsigned APK once two builds of it agree (scripts/reproducible.sh),
# the data pack's payload, the notes to sign, and SHA256SUMS of them all. It needs no key and signs
# nothing. The notes keep @@APK_SHA256@@ and @@FINGERPRINT@@ for the offline step to fill in, since the
# signed APK's hash exists only there.
#
#   scripts/prepare-signing.sh DIRECTORY    a directory that is missing or empty
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT=${1:?usage: scripts/prepare-signing.sh DIRECTORY}

fail() { echo "PREPARE FAILED: $*" >&2; exit 1; }

[ -z "$(git -C "$ROOT" status --porcelain)" ] || fail "the working tree is not clean"
commit=$(git -C "$ROOT" rev-parse HEAD)
git -C "$ROOT" merge-base --is-ancestor "$commit" origin/main || fail "$commit is not on origin/main"

gradle="$ROOT/android/app/build.gradle.kts"
version=$(sed -n 's/^ *versionName = "\(.*\)"$/\1/p' "$gradle")
code=$(sed -n 's/^ *versionCode = \([0-9]*\)$/\1/p' "$gradle")
case $version in
    "" | *-*) fail "\"$version\" is not a release's version" ;;
esac
# The app shows this date and counts its age from it (Release.kt), so it must be the changelog's.
date=$(sed -n 's/^ *buildConfigField("String", "RELEASE_DATE", "\\"\([0-9-]*\)\\"")$/\1/p' "$gradle")
grep -qxF "## [$version] - $date" "$ROOT/CHANGELOG.md" || fail "CHANGELOG.md has no \"## [$version] - $date\" for RELEASE_DATE \"$date\""
changes="$ROOT/fastlane/metadata/android/en-US/changelogs/$code.txt"
[ -f "$changes" ] || fail "no store changelog for versionCode $code"
sequence=$(sed -n 's/^sequence //p' "$ROOT/data/PACK")
[ -n "$sequence" ] || fail "data/PACK has no sequence"

mkdir -p "$OUT"
[ -z "$(ls -A "$OUT")" ] || fail "$OUT is not empty"

"$ROOT/scripts/reproducible.sh" "$commit" "$OUT/datapavan-$version-unsigned.apk"
[ -f "$OUT/datapavan-$version-unsigned.apk" ] || fail "no unsigned APK"

(cd "$ROOT/android" && ./gradlew --quiet :app:dataPayload)
cp "$ROOT/android/app/build/datapack/data/bundled.payload" "$OUT/datapavan-data-$sequence.payload"
pack_fingerprint=$(sha256sum "$OUT/datapavan-data-$sequence.payload" | cut -d' ' -f1)

cat >"$OUT/notes.txt" <<NOTES
Datapavan $version

Commit: $commit
APK: datapavan-$version.apk
APK SHA-256: @@APK_SHA256@@
Signing certificate SHA-256: @@FINGERPRINT@@
Data pack: datapavan-data-$sequence.pack
Data pack fingerprint: $pack_fingerprint

$(cat "$changes")

Genuine Datapavan has no internet access and never asks for it.
NOTES

(cd "$OUT" && sha256sum -- * >SHA256SUMS)
echo "== ready to sign, from $commit:"
(cd "$OUT" && ls -l)
