#!/usr/bin/env bash
# Screenshots of every destination, the settings, an app's page (ADR 0027) and the plan (ADR 0026),
# opened by its launcher shortcut, in every UI language
# and in the pseudo-locales (accented and right-to-left), and in dark mode in English and Persian,
# each with an accessibility check of the screen (scripts/a11y-check.py). CI keeps the screenshots as
# a build artifact, so layout changes in every language can be reviewed.
#
# Needs Android 13 or newer for app-specific languages, and python3 for the check. Run
# scripts/smoke.sh first, which installs the debug APK.
#
#   scripts/screenshots.sh [output directory, default build/screenshots]
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${1:-$ROOT/build/screenshots}"
PKG=org.visadahyu.datapavan
# shellcheck source=scripts/adb-ui.sh
. "$ROOT/scripts/adb-ui.sh"

if [ "$(adb shell getprop ro.build.version.sdk | tr -d '\r')" -lt 33 ]; then
    echo "skip: app-specific languages need Android 13 or newer"
    exit 0
fi

mkdir -p "$OUT"
density=$(adb shell wm density | tr -d '\r' | sed -n 's/.*: \([0-9]*\)$/\1/p' | tail -1)
min_px=$((48 * density / 160))
failed=0
trap 'adb shell cmd uimode night no >/dev/null 2>&1 || true; adb shell cmd locale set-app-locales "$PKG" --locales en >/dev/null 2>&1 || true; adb shell rm -f "$DUMP" >/dev/null 2>&1 || true' EXIT

# One screen: its picture, its UI dump and the accessibility check of the dump.
capture() {
    local dumped=""
    sleep 1
    # uiautomator gives up while the screen is still moving, so it gets three tries.
    for _ in 1 2 3; do
        if dump_screen; then
            dumped=1
            break
        fi
        sleep 1
    done
    if [ -z "$dumped" ]; then
        echo "SCREENSHOTS FAILED: no UI dump of $1 in $locale ($mode)" >&2
        exit 1
    fi
    adb exec-out screencap -p >"$OUT/$1-$locale-$mode.png"
    adb shell cat "$DUMP" >"$OUT/$1-$locale-$mode.xml"
    python3 -I "$ROOT/scripts/a11y-check.py" "$OUT/$1-$locale-$mode.xml" "$min_px" || passed=""
}

echo "== Screenshots and accessibility check on Android $(adb shell getprop ro.build.version.release | tr -d '\r')"
adb shell input keyevent KEYCODE_WAKEUP
adb shell wm dismiss-keyguard >/dev/null 2>&1 || true
# Every destination, the settings, an app's page and the plan: light in every language and both
# pseudo-locales, dark in English and Persian.
for mode in light dark; do
    if [ "$mode" = dark ]; then locales="en fa"; adb shell cmd uimode night yes >/dev/null; else locales="en fr de es ru zh-CN ar fa en-XA ar-XB"; adb shell cmd uimode night no >/dev/null; fi
    for locale in $locales; do
        adb shell cmd locale set-app-locales "$PKG" --locales "$locale"
        adb shell am force-stop "$PKG"
        adb shell am start -n "$PKG/.MainActivity" >/dev/null
        if ! wait_for_overview; then
            echo "SCREENSHOTS FAILED: the summary did not appear in $locale ($mode)" >&2
            exit 1
        fi
        passed=1
        capture summary
        for tab in apps phone network; do
            open_tab "$tab" || { echo "SCREENSHOTS FAILED: no $tab destination in $locale" >&2; exit 1; }
            capture "$tab"
        done
        tap_id settings || { echo "SCREENSHOTS FAILED: no settings button in $locale" >&2; exit 1; }
        capture settings
        adb shell input keyevent KEYCODE_BACK
        open_tab apps
        tap_id app-row || { echo "SCREENSHOTS FAILED: no app in the list in $locale" >&2; exit 1; }
        capture app
        # The plan, opened as its launcher shortcut opens it (xml/shortcuts.xml).
        adb shell am start -W -a org.visadahyu.datapavan.action.OPEN_PLAN -f 0x1000c000 -n "$PKG/.MainActivity" >/dev/null
        for _ in $(seq 1 60); do has_id plan && break; sleep 1; done
        has_id plan || { echo "SCREENSHOTS FAILED: the plan did not open in $locale" >&2; exit 1; }
        capture plan
        if [ -n "$passed" ]; then echo "ok: $locale ($mode)"; else echo "problems: $locale ($mode)"; failed=1; fi
    done
done

[ "$failed" -eq 0 ] || { echo "SCREENSHOTS FAILED: accessibility problems above" >&2; exit 1; }
echo "== screenshots in ${OUT#"$ROOT/"}, accessibility check passed"
