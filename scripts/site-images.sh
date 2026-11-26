#!/usr/bin/env bash
# The website's icons and its link-preview card, from the mark in site/static/favicon.svg (site/README.md, "Search
# engines"). Search engines show a raster favicon, not an SVG one (Google: square, a multiple of 48 px; ICO and PNG
# among the formats), phones a touch icon, and link previews a 1200 x 630 picture.
#
#   scripts/site-images.sh    writes into site/static:
#     favicon-192.png         the mark, 192 px
#     favicon.ico             16, 32 and 48 px
#     apple-touch-icon.png    180 px, the mark's square without its rounded corners, which the phone draws itself
#     images/card.png         1200 x 630: the mark and the name, in the site's own font and colours, with no sentence
#                             in any language, so that one card serves all eight
#
# It needs ImageMagick (magick) and Chrome, which draws the card with the site's own font. The files are kept in Git,
# like scripts/store-images.sh's, so the build needs neither.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STATIC="$ROOT/site/static"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
# No time chunks, so that the same mark gives the same files.
PNG=(-depth 8 -strip -define png:exclude-chunks=date,time)

magick -background none -density 600 "$STATIC/favicon.svg" -resize 192x192 "${PNG[@]}" "$STATIC/favicon-192.png"
for size in 16 32 48; do
    magick -background none -density 600 "$STATIC/favicon.svg" -resize "${size}x${size}" "${PNG[@]}" "$WORK/icon-$size.png"
done
magick "$WORK/icon-16.png" "$WORK/icon-32.png" "$WORK/icon-48.png" "$STATIC/favicon.ico"
sed 's/ rx="52"//' "$STATIC/favicon.svg" >"$WORK/square.svg"
magick -background none -density 600 "$WORK/square.svg" -resize 180x180 "${PNG[@]}" "$STATIC/apple-touch-icon.png"
echo "ok: icons"

# The card: the header's brand at a large size, the mark beside the name, on the page's paper (site/assets/style.css,
# the light scheme). Chrome draws it from a page that loads the site's own Archivo.
mark="$(sed -n '/<svg/,$p' "$STATIC/favicon.svg" | tr -d '\n')"
cat >"$WORK/card.html" <<HTML
<!doctype html>
<meta charset="utf-8">
<style>
@font-face{font-family:"Archivo";src:url("file://$STATIC/fonts/archivo-latin-wdth-normal.woff2") format("woff2");font-weight:100 900;font-stretch:62% 125%}
html,body{margin:0;width:1200px;height:630px;overflow:hidden;background:#FBF7F0}
body{display:flex;align-items:center;justify-content:center;gap:48px;border-bottom:24px solid #1F4E8C;box-sizing:border-box}
svg{width:220px;height:220px;flex:none}
p{margin:0 0 10px;font:800 150px/1 "Archivo";font-stretch:88%;color:#1F4E8C;letter-spacing:-.01em}
</style>
$mark
<p>Datapavan</p>
HTML
google-chrome --headless=new --disable-gpu --hide-scrollbars --no-first-run --user-data-dir="$WORK/chrome" \
    --force-device-scale-factor=1 --window-size=1200,630 --virtual-time-budget=5000 \
    --screenshot="$WORK/card.png" "file://$WORK/card.html" >/dev/null 2>&1
magick "$WORK/card.png" -crop 1200x630+0+0 +repage -colors 64 "${PNG[@]}" "$STATIC/images/card.png"
size=$(stat -c %s "$STATIC/images/card.png")
[ "$size" -lt 300000 ] || { echo "images/card.png is $size bytes, over 300 KB" >&2; exit 1; }
echo "ok: card, $size bytes"
