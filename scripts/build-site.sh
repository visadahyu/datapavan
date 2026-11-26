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
    curl -fsSL --retry 5 --retry-all-errors --retry-delay 10 -o "$TOOLS/hugo.tar.gz" "https://github.com/gohugoio/hugo/releases/download/v$VERSION/hugo_${VERSION}_linux-amd64.tar.gz"
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

# The accessibility statement has one source too, docs/ACCESSIBILITY.md, in English. Its links are resolved from docs/: an
# anchor stays, a link to a file of the repository becomes its address on GitHub (check-site.py checks that the file
# exists). Every other language gets a short page in its own words, from site/data/text, that says what Datapavan aims
# for and how to tell us, and links the full statement (the accessibility unit, part 2).
python3 -I - "$ROOT" <<'PY'
import json, os, pathlib, re, sys
root = pathlib.Path(sys.argv[1])
out = root / "site/content/accessibility"
out.mkdir(parents=True, exist_ok=True)
text = (root / "docs/ACCESSIBILITY.md").read_text(encoding="utf-8").split("\n", 1)[1]
def resolve(match):
    label, target = match.group(1), match.group(2)
    if re.match(r"[a-z]+:|#", target):
        return match.group(0)
    path, _, anchor = target.partition("#")
    full = os.path.normpath(os.path.join("docs", path))
    return f"[{label}](https://github.com/visadahyu/datapavan/blob/main/{full}{'#' + anchor if anchor else ''})"
text = re.sub(r"\[([^\]]+)\]\(([^)\s]+)\)", resolve, text)
words = json.loads((root / "site/data/text/en.json").read_text(encoding="utf-8"))
(out / "index.en.md").write_text(f'---\ntitle: "{words["a11y_title"]}"\n---\n{text}', encoding="utf-8")
for lang in ("fr", "de", "es", "ru", "zh", "ar", "fa"):
    w = json.loads((root / f"site/data/text/{lang}.json").read_text(encoding="utf-8"))
    title = w["a11y_title"].replace('"', '\\"')
    # The link to the full statement, in English, is the page layout's (site/layouts/page.html).
    body = f'{w["a11y_aim"]}\n\n{w["a11y_tell"]}\n'
    (out / f"index.{lang}.md").write_text(f'---\ntitle: "{title}"\n---\n\n{body}', encoding="utf-8")
PY

# The site's map, one page per language (site/layouts/map.html), so that every page can be found a second way beside the
# navigation and the footer (WCAG 2.4.5). Its title is the footer's word for it.
python3 -I - "$ROOT" <<'PY'
import json, pathlib, sys
root = pathlib.Path(sys.argv[1])
out = root / "site/content/map"
out.mkdir(parents=True, exist_ok=True)
for lang in ("en", "fr", "de", "es", "ru", "zh", "ar", "fa"):
    title = json.loads((root / f"site/data/text/{lang}.json").read_text(encoding="utf-8"))["foot_map"].replace('"', '\\"')
    (out / f"index.{lang}.md").write_text(f'---\ntitle: "{title}"\nlayout: map\n---\n', encoding="utf-8")
PY

# The per-tool guides for proxy mode (W8, part 3b), one page per tool: written from data/tools/guide*.tsv and the
# network part's English strings by scripts/guides.py, which checks the data first, so that the site says what the
# network part says.
python3 -I "$ROOT/scripts/guides.py" --site "$ROOT/site/content/guides" >/dev/null

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

# Hugo also writes a sitemap per language. The one at the root (site/layouts/sitemapindex.xml) lists every page of
# every language, and English's own would sit under /en/, where a sitemap may not list the root's pages. llms.txt
# is the same: the root one lists the other languages. So is the page for a missing address: the server answers every
# one with the root's (site/layouts/404.html), which links every language.
prune() {
    rm -f "$1"/*/sitemap.xml "$1"/*/llms.txt "$1"/*/404.html
    rmdir "$1/en"
}

# The sitemap's lastmod comes from site/data/lastmod.json, the hash of each page's <main> and the date it last
# changed (scripts/lastmod.py). A build updates it from what it built and builds again, so that the sitemap carries the
# new dates; the check only reads it, so that it gives the same site on any day.
if [ "${1:-}" = --check ]; then
    OUT="$(mktemp -d)"
    trap 'rm -rf "$OUT"' EXIT
    "$HUGO" --source "$ROOT/site" --destination "$OUT" --logLevel error
    prune "$OUT"
    python3 -I "$ROOT/scripts/lastmod.py" --check "$OUT"
    diff -r "$OUT" "$ROOT/docs/site"
    python3 -I "$ROOT/scripts/check-site.py" "$OUT"
else
    "$HUGO" --source "$ROOT/site" --destination "$ROOT/docs/site" --cleanDestinationDir --logLevel error
    prune "$ROOT/docs/site"
    python3 -I "$ROOT/scripts/lastmod.py" "$ROOT/docs/site"
    "$HUGO" --source "$ROOT/site" --destination "$ROOT/docs/site" --cleanDestinationDir --logLevel error
    prune "$ROOT/docs/site"
    python3 -I "$ROOT/scripts/lastmod.py" --check "$ROOT/docs/site"
    python3 -I "$ROOT/scripts/check-site.py"
fi
