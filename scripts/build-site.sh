#!/usr/bin/env bash
# Builds datapavan.org from site/ into docs/site with a pinned Hugo, which it fetches and verifies by hash.
# Nothing else is needed, and nothing but plain files comes out.
#
#   scripts/build-site.sh           write docs/site
#   scripts/build-site.sh --check   fail if docs/site differs from what site/ gives
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION=0.169.0
SHA256=2d2f0bfe357d8cb4cec02f6bb28a3bff34978c8dda44b618029c5eb9d66765a7
TOOLS="$ROOT/build/tools/hugo-$VERSION"
HUGO="$TOOLS/hugo"

if [ ! -x "$HUGO" ]; then
    mkdir -p "$TOOLS"
    curl -fsSL -o "$TOOLS/hugo.tar.gz" "https://github.com/gohugoio/hugo/releases/download/v$VERSION/hugo_${VERSION}_linux-amd64.tar.gz"
    echo "$SHA256  $TOOLS/hugo.tar.gz" | sha256sum -c --logLevel error -
    tar -xzf "$TOOLS/hugo.tar.gz" -C "$TOOLS" hugo
    rm "$TOOLS/hugo.tar.gz"
fi

# The privacy policy has one source, PRIVACY.md at the repository's root.
{
    printf -- '---\ntitle: Privacy policy\n---\n'
    sed -E '1d; s#\]\(([^):]+)\)#](https://github.com/visadahyu/datapavan/blob/main/\1)#g' "$ROOT/PRIVACY.md"
} >"$ROOT/site/content/privacy/index.en.md"

if [ "${1:-}" = --check ]; then
    OUT="$(mktemp -d)"
    trap 'rm -rf "$OUT"' EXIT
    "$HUGO" --source "$ROOT/site" --destination "$OUT" --logLevel error
    diff -r "$OUT" "$ROOT/docs/site"
    python3 -I "$ROOT/scripts/check-site.py" "$OUT"
else
    "$HUGO" --source "$ROOT/site" --destination "$ROOT/docs/site" --cleanDestinationDir --logLevel error
    python3 -I "$ROOT/scripts/check-site.py"
fi
