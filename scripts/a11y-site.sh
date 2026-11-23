#!/usr/bin/env bash
# The site's local accessibility audit (site/README.md, "Accessibility"): axe-core and the keyboard, reflow and text
# spacing checks of scripts/a11y-site/run.mjs over every page of the built site, in the system's Chrome. Local only;
# CI keeps the rules that need no browser in scripts/check-site.py.
#
# The two packages and their dependencies are pinned in scripts/a11y-site/package-lock.json (integrity hashes) and
# installed into build/a11y-site/tool with their install scripts off; nothing downloads a browser.
#
#   scripts/a11y-site.sh [site directory, default docs/site]
# Needs node and npm, and Chrome (CHROME names another binary).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SITE="$(cd "${1:-$ROOT/docs/site}" && pwd)"
TOOL="$ROOT/build/a11y-site/tool"
mkdir -p "$TOOL"
cp "$ROOT/scripts/a11y-site/package.json" "$ROOT/scripts/a11y-site/package-lock.json" "$ROOT/scripts/a11y-site/run.mjs" "$TOOL/"
(cd "$TOOL" && npm ci --ignore-scripts --no-audit --no-fund --loglevel=error)
node "$TOOL/run.mjs" "$SITE" "$ROOT/build/a11y-site"
