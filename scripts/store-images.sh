#!/usr/bin/env bash
# The store images in fastlane/metadata/android, which F-Droid, IzzyOnDroid and Google Play read: the
# 512 px icon, drawn from the launcher icon's own layers, and six phone screenshots in each UI
# language (the summary, the apps, an app's page, the plan, network use and the phone), taken by
# scripts/screenshots.sh in SystemUI's demo mode, so the status bar shows nothing of the device, and
# with usage access allowed for the run, so that network use has numbers. Both are undone afterwards.
#
# Only for emulators: it changes device settings. Run scripts/smoke.sh first, which installs the debug
# APK, on a phone-sized screen (the pixel_7 profile, or `wm size 1080x2400; wm density 420`).
#
#   scripts/store-images.sh            icon and screenshots
#   scripts/store-images.sh icon       the icon only, no device needed
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PKG=org.visadahyu.datapavan
META="$ROOT/fastlane/metadata/android"
RES="$ROOT/android/app/src/main/res"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# The icon: the adaptive icon's background colour and foreground path on a full square, as stores
# want it; they round the corners themselves.
python3 -I - "$RES" "$WORK/icon.svg" <<'EOF'
import re, sys, xml.etree.ElementTree as ET
res, out = sys.argv[1], sys.argv[2]
A = "{http://schemas.android.com/apk/res/android}"
colors = {c.get("name"): c.text.strip() for f in ("values/colors.xml", "values/ic_launcher_background.xml")
          for c in ET.parse(f"{res}/{f}").getroot().iter("color")}
def color(value):
    while value.startswith("@color/"):
        value = colors[value[len("@color/"):]]
    return value
background = color(colors["ic_launcher_background"])
vector = ET.parse(f"{res}/drawable/ic_launcher_foreground.xml").getroot()
paths = "".join(f'<path fill="{color(p.get(A + "fillColor"))}" d="{p.get(A + "pathData")}"/>' for p in vector.iter("path"))
width, height = vector.get(A + "viewportWidth"), vector.get(A + "viewportHeight")
open(out, "w").write(f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}">'
                     f'<rect width="{width}" height="{height}" fill="{background}"/>{paths}</svg>')
EOF
mkdir -p "$META/en-US/images"
magick -background none -density 1200 "$WORK/icon.svg" -resize 512x512 -depth 8 -strip "$META/en-US/images/icon.png"
echo "ok: icon"
[ "${1:-}" = icon ] && exit 0

if [ "$(adb shell getprop ro.kernel.qemu | tr -d '\r')" != "1" ] && [ "$(adb shell getprop ro.boot.qemu | tr -d '\r')" != "1" ]; then
    echo "store-images.sh changes device settings and runs on emulators only" >&2
    exit 2
fi

demo() { adb shell am broadcast -a com.android.systemui.demo -e command "$@" >/dev/null; }
cleanup() {
    demo exit || true
    adb shell settings put global sysui_demo_allowed 0 >/dev/null 2>&1 || true
    adb shell appops set "$PKG" GET_USAGE_STATS default >/dev/null 2>&1 || true
    rm -rf "$WORK"
}
trap cleanup EXIT

adb shell settings put global sysui_demo_allowed 1
demo enter
demo clock -e hhmm 1200
demo battery -e level 100 -e plugged false
demo network -e wifi show -e level 4 -e fully true
demo network -e mobile hide
demo notifications -e visible false
adb shell appops set "$PKG" GET_USAGE_STATS allow

"$ROOT/scripts/screenshots.sh" "$WORK/shots"

for pair in en:en-US fr:fr-FR de:de-DE fa:fa-IR; do
    locale=${pair%%:*}
    dir="$META/${pair#*:}/images/phoneScreenshots"
    rm -rf "$dir"
    mkdir -p "$dir"
    n=1
    for screen in summary apps app plan network phone; do
        magick "$WORK/shots/$screen-$locale-light.png" -depth 8 -strip "$dir/$n.png"
        n=$((n + 1))
    done
    echo "ok: ${pair#*:}"
done
echo "== store images in ${META#"$ROOT/"}"
