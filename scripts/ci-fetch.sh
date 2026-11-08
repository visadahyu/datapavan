#!/usr/bin/env bash
# Fetches the pinned Gradle distribution and Hugo with the workflow's token (GH_TOKEN), for CI.
# Both are published on GitHub, and GitHub at times times out anonymous downloads (2026-11-08): with a
# token CI does not stop. Each file is still checked against the SHA-256 pinned in the repository, and
# put where the Gradle wrapper and scripts/build-site.sh look first, so neither downloads it again.
# Anything already there (from the CI cache) is left alone. Locally there is no need to run this.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
: "${GH_TOKEN:?GH_TOKEN must be set}"

# The Gradle distribution, in the folder the wrapper derives from distributionUrl (PathAssembler:
# the zip's name, then the URL's MD5 in base 36). With the zip there, the wrapper checks its
# distributionSha256Sum, unpacks it and downloads nothing.
props="$ROOT/android/gradle/wrapper/gradle-wrapper.properties"
url=$(sed -n 's/^distributionUrl=//p' "$props" | sed 's/\\:/:/g')
sum=$(sed -n 's/^distributionSha256Sum=//p' "$props")
zip=${url##*/}
version=$(sed -n 's/^gradle-\(.*\)-bin\.zip$/\1/p' <<<"$zip")
[ -n "$version" ] && [ -n "$sum" ] || { echo "cannot read $props" >&2; exit 1; }
hash=$(python3 -I -c '
import hashlib, sys
n = int(hashlib.md5(sys.argv[1].encode()).hexdigest(), 16)
digits, out = "0123456789abcdefghijklmnopqrstuvwxyz", ""
while n:
    n, r = divmod(n, 36)
    out = digits[r] + out
print(out)' "$url")
dist="${GRADLE_USER_HOME:-$HOME/.gradle}/wrapper/dists/${zip%.zip}/$hash"
if [ -f "$dist/$zip.ok" ] || [ -f "$dist/$zip" ]; then
    echo "Gradle $version: already there"
else
    mkdir -p "$dist"
    gh release download "v$version" -R gradle/gradle-distributions -p "$zip" -O "$dist/$zip.part"
    echo "$sum  $dist/$zip.part" | sha256sum -c --quiet -
    mv "$dist/$zip.part" "$dist/$zip"
    echo "Gradle $version: fetched and checked"
fi

# Hugo, where scripts/build-site.sh keeps it; its version and hash are pinned there.
hugo_version=$(sed -n 's/^VERSION=//p' "$ROOT/scripts/build-site.sh")
hugo_sum=$(sed -n 's/^SHA256=//p' "$ROOT/scripts/build-site.sh")
tools="$ROOT/build/tools/hugo-$hugo_version"
if [ -x "$tools/hugo" ]; then
    echo "Hugo $hugo_version: already there"
else
    mkdir -p "$tools"
    gh release download "v$hugo_version" -R gohugoio/hugo -p "hugo_${hugo_version}_linux-amd64.tar.gz" -O "$tools/hugo.tar.gz"
    echo "$hugo_sum  $tools/hugo.tar.gz" | sha256sum -c --quiet -
    tar -xzf "$tools/hugo.tar.gz" -C "$tools" hugo
    rm "$tools/hugo.tar.gz"
    echo "Hugo $hugo_version: fetched and checked"
fi
