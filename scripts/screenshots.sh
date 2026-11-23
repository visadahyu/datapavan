#!/usr/bin/env bash
# Screenshots of every destination, the settings, an app's page (ADR 0027) and the plan (ADR 0026),
# opened by its launcher shortcut, in every UI language
# and in the pseudo-locales (accented and right-to-left), and in dark mode in English and Persian,
# each with an accessibility check of the screen (scripts/a11y-check.py: labels, touch size, and the contrast of every
# text and icon on the frame the picture is made from). Then, in LARGE_LOCALES (default English and Persian), the
# same screens at Android's largest text and display size with bold text, where every text must grow (WCAG 1.4.4);
# and in KEYS_LOCALES (default the same), a keyboard walk of the summary and the settings, where Tab must reach every
# button in reading order (2.1.1, 2.4.3). CI keeps the screenshots as a build artifact, so layout changes in every
# language can be reviewed (docs/ACCESSIBILITY.md).
#
# Needs Android 13 or newer for app-specific languages, and python3 for the check. Run
# scripts/smoke.sh first, which installs the debug APK.
#
# With --now, Datapavan Advanced's view "Now" and an app's history (ADR 0046, W5's third part) instead, from
# Advanced's debug APK, installed first: with the tunnel up, a request of adb's shell to a test server on this
# computer, and usage access granted, in every UI language and both pseudo-locales, and in dark mode in
# English and Persian, as the audit's screens; NOW_LOCALES may name fewer.
#
#   scripts/screenshots.sh [--now] [output directory, default build/screenshots]
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NOW=""
if [ "${1:-}" = --now ]; then NOW=1; shift; fi
OUT="${1:-$ROOT/build/screenshots}"
PKG=org.visadahyu.datapavan
[ -z "$NOW" ] || PKG=org.visadahyu.datapavan.advanced
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
# Android's largest display size, as Settings computes it (DisplayDensityUtils): 1.5 times the default, but no
# denser than leaves the screen 320 dp wide. The default and the size are the ones in force (CI's emulator is given a
# phone's 1080 x 2400 at 420 dpi over its own), and the density in force comes back at the end.
density_set=$(adb shell wm density | tr -d '\r' | sed -n 's/^Override density: \([0-9]*\)$/\1/p')
size=$(adb shell wm size | tr -d '\r' | sed -n 's/^\(Physical\|Override\) size: \([0-9]*\)x\([0-9]*\)$/\2 \3/p' | tail -1)
narrow=$(printf '%s\n' $size | sort -n | head -1)
density_largest=$((density * 3 / 2 < narrow * 160 / 320 ? density * 3 / 2 : narrow * 160 / 320))
# Every setting a pass changes, back as it was.
restore() {
    adb shell cmd uimode night no >/dev/null 2>&1 || true
    adb shell cmd locale set-app-locales "$PKG" --locales en >/dev/null 2>&1 || true
    adb shell settings put system font_scale 1.0 >/dev/null 2>&1 || true
    adb shell settings put secure font_weight_adjustment 0 >/dev/null 2>&1 || true
    if [ -n "$density_set" ]; then adb shell wm density "$density_set" >/dev/null 2>&1 || true
    else adb shell wm density reset >/dev/null 2>&1 || true; fi
    adb shell rm -f "$DUMP" /sdcard/datapavan-frame.raw >/dev/null 2>&1 || true
}
trap restore EXIT

# The app protects every screen from screenshots (ADR 0040); a debug build started with
# screenshots_for_tests keeps it off, so that these pictures are not black.
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
    # One raw frame, just after the dump: the check measures its contrast and writes the picture from it.
    adb exec-out screencap >"$OUT/$1-$locale-$mode.raw"
    adb shell cat "$DUMP" >"$OUT/$1-$locale-$mode.xml"
    python3 -I "$ROOT/scripts/a11y-check.py" "$OUT/$1-$locale-$mode.xml" "$min_px" "$PKG" \
        --frame "$OUT/$1-$locale-$mode.raw" --png "$OUT/$1-$locale-$mode.png" || passed=""
    rm -f "$OUT/$1-$locale-$mode.raw"
    # At the largest text, each text must have grown from its height at the default (the light pass's dump).
    if [ "$mode" = large ]; then
        python3 -I "$ROOT/scripts/a11y-check.py" grew "$PKG" "$OUT/$1-$locale-light.xml" "$OUT/$1-$locale-large.xml" || passed=""
    fi
}

# Whether the network part's own account says its tunnel runs (--now).
network_running() {
    grep -qx 'running true' <<<"$(adb shell dumpsys activity service "$PKG/org.visadahyu.datapavan.network.NetworkVpnService" | tr -d '\r' | sed 's/^ *//')"
}

# Whether the network part counts traffic of adb's shell, after one more request to the test server (--now).
shell_counted() {
    adb shell "printf 'GET /ping HTTP/1.0\r\n\r\n' | nc -w 5 $HOST $PORT" >/dev/null 2>&1 || true
    sleep 2
    grep -q '^activity-app 2000 ' <<<"$(adb shell dumpsys activity service "$PKG/org.visadahyu.datapavan.network.NetworkVpnService" | tr -d '\r' | sed 's/^ *//')"
}

# Advanced's "Now" and an app's history (--now): the network part's tunnel up for adb's shell, which asks a test server
# on this computer for a page, so that "Now" has a row to show and to open.
now_screens() {
    local network=org.visadahyu.datapavan.network.MainActivity
    is_emulator || { echo "SCREENSHOTS FAILED: --now runs on an emulator only: it grants usage access and starts a VPN" >&2; exit 1; }
    HOST=10.0.2.2
    # shellcheck source=scripts/host-ports.sh
    . "$ROOT/scripts/host-ports.sh"
    host_server || exit 1
    trap 'adb shell dumpsys activity service "$PKG/org.visadahyu.datapavan.network.NetworkVpnService" log-retention 0 >/dev/null 2>&1 || true; adb shell appops set "$PKG" GET_USAGE_STATS default >/dev/null 2>&1 || true; kill "$SERVER" 2>/dev/null || true; restore' EXIT
    allow_vpn "$PKG" || { echo "SCREENSHOTS FAILED: no VPN consent for $PKG" >&2; exit 1; }
    adb shell appops set "$PKG" GET_USAGE_STATS allow
    for mode in light dark; do
        if [ "$mode" = dark ]; then locales="${NOW_DARK_LOCALES:-en fa}"; adb shell cmd uimode night yes >/dev/null; else locales="${NOW_LOCALES:-en fr de es ru zh-CN ar fa en-XA ar-XB}"; adb shell cmd uimode night no >/dev/null; fi
        for locale in $locales; do
            adb shell cmd locale set-app-locales "$PKG" --locales "$locale"
            adb shell am force-stop "$PKG"
            adb shell am start -W -n "$PKG/$network" --ez start true >/dev/null
            within 20 network_running || { echo "SCREENSHOTS FAILED: the network part's tunnel did not come up in $locale" >&2; exit 1; }
            # The log kept for a week, so that the history shows the shell's entries and the days' buttons, not
            # only the line of a log that keeps nothing (review c1 of W5's third part, screens, nit 13).
            grep -q '^log-retention 7 set$' <<<"$(adb shell dumpsys activity service "$PKG/org.visadahyu.datapavan.network.NetworkVpnService" log-retention 7 | tr -d '\r' | sed 's/^ *//')" ||
                { echo "SCREENSHOTS FAILED: the log's retention could not be set in $locale" >&2; exit 1; }
            # The request again until the network part counts it: just after the tunnel starts, Android may not route it
            # yet.
            within 30 shell_counted || { echo "SCREENSHOTS FAILED: the network part did not count the shell's request in $locale" >&2; exit 1; }
            # The shell's records written now, so that its history shows them, not "nothing kept yet".
            grep -q '^log-flushed$' <<<"$(adb shell dumpsys activity service "$PKG/org.visadahyu.datapavan.network.NetworkVpnService" log-flush | tr -d '\r' | sed 's/^ *//')" ||
                { echo "SCREENSHOTS FAILED: the log's records were not written in $locale" >&2; exit 1; }
            # "Now" for the shell alone, whose row is the first below the view's top.
            adb shell am start -n "$PKG/$network" --activity-clear-top --ez now true --es now_package com.android.shell \
                --ez screenshots_for_tests true >/dev/null
            passed=1
            sleep 3
            capture now
            for _ in 1 2 3 4; do screen_has_holding com.android.shell && break; swipe_up; done
            screen_has_holding com.android.shell || { echo "SCREENSHOTS FAILED: no row in \"Now\" in $locale" >&2; exit 1; }
            capture now-row
            tap_holding com.android.shell || { echo "SCREENSHOTS FAILED: no row to open in $locale" >&2; exit 1; }
            sleep 2
            capture history
            adb shell input keyevent KEYCODE_BACK
            if [ -n "$passed" ]; then echo "ok: now $locale ($mode)"; else echo "problems: now $locale ($mode)"; failed=1; fi
        done
    done
    [ "$failed" -eq 0 ] || { echo "SCREENSHOTS FAILED: accessibility problems above" >&2; exit 1; }
    echo "== screenshots of \"Now\" in ${OUT#"$ROOT/"}, accessibility check passed"
    exit 0
}

echo "== Screenshots and accessibility check on Android $(adb shell getprop ro.build.version.release | tr -d '\r')"
adb shell input keyevent KEYCODE_WAKEUP
adb shell wm dismiss-keyguard >/dev/null 2>&1 || true
[ -z "$NOW" ] || now_screens
# Every destination, the settings, an app's page and the plan: light in every language and both
# pseudo-locales, dark in English and Persian.
for mode in light dark large; do
    case $mode in
        dark) locales="en fa"; adb shell cmd uimode night yes >/dev/null ;;
        large)
            locales="${LARGE_LOCALES:-en fa}"
            adb shell cmd uimode night no >/dev/null
            adb shell settings put system font_scale 2.0
            adb shell settings put secure font_weight_adjustment 300
            adb shell wm density "$density_largest"
            min_px=$((48 * density_largest / 160)) ;;
        *) locales="en fr de es ru zh-CN ar fa en-XA ar-XB"; adb shell cmd uimode night no >/dev/null ;;
    esac
    for locale in $locales; do
        adb shell cmd locale set-app-locales "$PKG" --locales "$locale"
        adb shell am force-stop "$PKG"
        adb shell am start -n "$PKG/.MainActivity" --ez screenshots_for_tests true >/dev/null
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
        # Each picture is taken once its screen has replaced the one before.
        within 10 gone_id settings || { echo "SCREENSHOTS FAILED: the settings did not open in $locale" >&2; exit 1; }
        capture settings
        adb shell input keyevent KEYCODE_BACK
        open_tab apps
        # On a fresh emulator the list fills only once the first scan ends: wait for a row (CI, 2026-11-14,
        # docs/ci-flakes.md), then open it.
        within 60 has_id app-row || { echo "SCREENSHOTS FAILED: no app in the list in $locale after 60 s" >&2; exit 1; }
        tap_id app-row || { echo "SCREENSHOTS FAILED: no app in the list in $locale" >&2; exit 1; }
        within 10 gone_id app-row || { echo "SCREENSHOTS FAILED: the app's page did not open in $locale" >&2; exit 1; }
        capture app
        # The plan, opened as its launcher shortcut opens it (xml/shortcuts.xml).
        adb shell am start -W -a org.visadahyu.datapavan.action.OPEN_PLAN -f 0x1000c000 -n "$PKG/.MainActivity" --ez screenshots_for_tests true >/dev/null
        for _ in $(seq 1 60); do has_id plan && break; sleep 1; done
        has_id plan || { echo "SCREENSHOTS FAILED: the plan did not open in $locale" >&2; exit 1; }
        capture plan
        if [ -n "$passed" ]; then echo "ok: $locale ($mode)"; else echo "problems: $locale ($mode)"; failed=1; fi
    done
done

restore
min_px=$((48 * density / 160))

# The keyboard: from the top of a screen, Tab after Tab, a dump after each, until the focus has gone round.
key_walk() {
    local name=$1 rtl=0 steps=() i
    case $locale in ar | fa | ar-XB) rtl=1 ;; esac
    dump_screen || { echo "SCREENSHOTS FAILED: no UI dump of $name before the keyboard walk in $locale" >&2; exit 1; }
    adb shell cat "$DUMP" >"$OUT/keys-$name-$locale-0.xml"
    for i in $(seq 1 "${KEYS_MAX:-24}"); do
        adb shell input keyevent KEYCODE_TAB
        dump_screen || continue
        adb shell cat "$DUMP" >"$OUT/keys-$name-$locale-$i.xml"
        steps+=("$OUT/keys-$name-$locale-$i.xml")
    done
    python3 -I "$ROOT/scripts/a11y-check.py" keys "$PKG" "$rtl" "$OUT/keys-$name-$locale-0.xml" "${steps[@]}" || passed=""
}
for locale in ${KEYS_LOCALES:-en fa}; do
    adb shell cmd locale set-app-locales "$PKG" --locales "$locale"
    adb shell am force-stop "$PKG"
    adb shell am start -n "$PKG/.MainActivity" --ez screenshots_for_tests true >/dev/null
    wait_for_overview || { echo "SCREENSHOTS FAILED: the summary did not appear in $locale (keys)" >&2; exit 1; }
    passed=1
    key_walk summary
    tap_id settings || { echo "SCREENSHOTS FAILED: no settings button in $locale (keys)" >&2; exit 1; }
    within 10 gone_id settings || { echo "SCREENSHOTS FAILED: the settings did not open in $locale (keys)" >&2; exit 1; }
    key_walk settings
    if [ -n "$passed" ]; then echo "ok: keys $locale"; else echo "problems: keys $locale"; failed=1; fi
done

[ "$failed" -eq 0 ] || { echo "SCREENSHOTS FAILED: accessibility problems above" >&2; exit 1; }
echo "== screenshots in ${OUT#"$ROOT/"}, accessibility check passed"
