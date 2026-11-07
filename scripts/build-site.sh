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
    echo "$SHA256  $TOOLS/hugo.tar.gz" | sha256sum -c --quiet -
    tar -xzf "$TOOLS/hugo.tar.gz" -C "$TOOLS" hugo
    rm "$TOOLS/hugo.tar.gz"
fi

# The privacy policy has one source, PRIVACY.md at the repository's root.
mkdir -p "$ROOT/site/content/privacy"
{
    printf -- '---\ntitle: Privacy policy\n---\n'
    sed -E '1d; s#\]\(([^):]+)\)#](https://github.com/visadahyu/datapavan/blob/main/\1)#g' "$ROOT/PRIVACY.md"
} >"$ROOT/site/content/privacy/index.en.md"

# The current release's store changelog in each language, for the download section: fastlane/ holds it,
# translated and reviewed like the app (ADR 0030).
code=$(sed -n 's/^release_code = \([0-9]*\)$/\1/p' "$ROOT/site/hugo.toml")
[ -n "$code" ] || { echo "site/hugo.toml has no release_code" >&2; exit 1; }
python3 -I - "$ROOT" "$code" <<'PY'
import json, pathlib, sys
root, code = pathlib.Path(sys.argv[1]), sys.argv[2]
stores = {"en": "en-US", "fr": "fr-FR", "de": "de-DE", "es": "es-ES", "ru": "ru-RU", "zh": "zh-CN", "ar": "ar", "fa": "fa-IR"}
changes = {
    language: (root / "fastlane/metadata/android" / store / "changelogs" / f"{code}.txt").read_text(encoding="utf-8").strip()
    for language, store in stores.items()
}
(root / "site/data/changes.json").write_text(json.dumps(changes, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
PY

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
