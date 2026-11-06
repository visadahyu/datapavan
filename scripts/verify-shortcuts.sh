#!/usr/bin/env bash
# End-to-end check of the launcher shortcuts (android/app/src/main/res/xml/shortcuts.xml), with a
# debug build of Datapavan installed. Android must list the three shortcuts with their English labels,
# and each one, started with the very intent and flags that Android hands the launcher, must open its
# screen: the plan without the navigation bar, the apps and network use with their tab selected. Back
# from the plan must lead to the summary. It changes nothing on the device apart from the app's own
# language, which start_audit sets to English as every other script does.
#
#   scripts/verify-shortcuts.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PKG=org.visadahyu.datapavan
# shellcheck source=scripts/adb-ui.sh
. "$ROOT/scripts/adb-ui.sh"

trap 'adb shell rm -f "$DUMP" >/dev/null 2>&1 || true' EXIT

fail() {
    echo "VERIFY FAILED: $*" >&2
    local out="$ROOT/build/screenshots"
    mkdir -p "$out"
    adb exec-out screencap -p >"$out/verify-shortcuts-failure.png" 2>/dev/null || true
    if adb shell uiautomator dump "$DUMP" >/dev/null 2>&1; then
        adb shell cat "$DUMP" >"$out/verify-shortcuts-failure.xml"
        echo "On screen:" >&2
        grep -o 'text="[^"]\+"' "$out/verify-shortcuts-failure.xml" | head -40 >&2 || true
    fi
    exit 1
}

# Waits up to a minute for $@ to succeed: the audit loads before any screen shows.
wait_until() {
    for _ in $(seq 1 60); do
        "$@" && return 0
        sleep 1
    done
    return 1
}

start_audit || fail "Datapavan did not start"

# Android parses the shortcuts when the app is installed; the dump shows what a launcher receives.
listed=$(adb shell dumpsys shortcut | tr -d '\r' | awk -v pkg="$PKG" '/Package: /{mine = ($2 == pkg)} mine')
[ -n "$listed" ] || fail "Android lists no shortcuts for $PKG"
# User builds of Android, as on phones, hide each shortcut's id, labels and intent in the dump
# (emulator images show them). There the shortcuts are told apart by their label resources and
# started with the actions of shortcuts.xml and the flags Android gives every static shortcut.
hidden=false
grep -q 'ShortcutInfo {id=\*\*\*,' <<<"$listed" && hidden=true
XML="$ROOT/android/app/src/main/res/xml/shortcuts.xml"
STATIC_FLAGS=0x1000c000 # FLAG_ACTIVITY_NEW_TASK | FLAG_ACTIVITY_CLEAR_TASK | FLAG_ACTIVITY_TASK_ON_HOME

check_label() {
    grep -A6 "ShortcutInfo {id=$1," <<<"$listed" | grep -q "$2=$3, " || fail "shortcut $1: $2 is not \"$3\""
}

open_shortcut() {
    local intent action flags
    if $hidden; then
        action=$(grep -A8 "android:shortcutId=\"$1\"" "$XML" | sed -n 's/.*android:action="\([^"]*\)".*/\1/p' | head -1)
        flags=$STATIC_FLAGS
    else
        intent=$(grep -A14 "ShortcutInfo {id=$1," <<<"$listed" | grep -m1 'intents=\[Intent {') || fail "shortcut $1 is not listed"
        action=$(sed -n 's/.*act=\([^ ]*\).*/\1/p' <<<"$intent")
        flags=$(sed -n 's/.*flg=\(0x[0-9a-f]*\).*/\1/p' <<<"$intent")
        grep -q "cmp=$PKG/.MainActivity" <<<"$intent" || fail "shortcut $1 does not start MainActivity: $intent"
    fi
    [ -n "$action" ] && [ -n "$flags" ] || fail "shortcut $1 has no action or flags"
    adb shell am start -W -a "$action" -f "$flags" -n "$PKG/.MainActivity" >/dev/null
}

if $hidden; then
    for label in shortcut_plan nav_apps nav_network; do
        grep -q "shortLabel=\*\*\*, resId=[0-9]*\[$label\]" <<<"$listed" || fail "no shortcut is labelled with $label"
    done
    [ "$(grep -c 'activity=ComponentInfo{'"$PKG/$PKG.MainActivity"'}' <<<"$listed")" = 3 ] || fail "not three shortcuts start MainActivity"
    echo "ok: Android lists the three shortcuts (this build hides their labels; ShortcutsTest checks them)"
else
    check_label plan shortLabel Plan
    check_label plan longLabel "Your plan"
    check_label apps shortLabel Apps
    check_label network shortLabel Network
    check_label network longLabel "Network use"
    echo "ok: Android lists the three shortcuts"
fi

open_shortcut apps
wait_until selected_id nav-apps || fail "the apps shortcut did not open the apps"
echo "ok: the apps shortcut opens the apps"

open_shortcut network
wait_until selected_id nav-network || fail "the network shortcut did not open network use"
echo "ok: the network shortcut opens network use"

open_shortcut plan
wait_until has_id plan || fail "the plan shortcut did not open the plan"
has_id nav-summary && fail "the plan shows the navigation bar"
echo "ok: the plan shortcut opens the plan"
adb shell input keyevent KEYCODE_BACK
wait_until selected_id nav-summary || fail "back from the plan did not lead to the summary"
echo "ok: back from the plan leads to the summary"

echo "PASS: every launcher shortcut opens its screen"
