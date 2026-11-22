#!/usr/bin/env bash
# Android's own labels, read from the phone (ADR 0054), on an emulator with Datapavan Basic's debug build installed,
# and Advanced's where its APK is built.
#
# 1. Basic's debug dump (MainActivity, labels-read) reads every label of the data pack's rows in Datapavan's eight
#    languages, with no language change on the emulator, and each must be read from the phone and be AOSP's text at
#    the emulator's own release (scripts/android-labels.py --expected), unless KNOWN below names why it differs.
# 2. The discovery command (labels-find) finds usage access's resource by its English text and prints it in the
#    other languages.
# 3. The screens, from Android 13, which sets an app's own language: with the phone in English and Datapavan in
#    Persian, the phone's finding of USB debugging names its page as the phone does, Datapavan's Persian beside it;
#    with the phone in Persian (set by the locale manager's shell command on Android 17, else by the emulator's Custom
#    Locale app, else, on a userdebug image, by the property Android starts with and a restart of its framework) and
#    Datapavan in English, the plan's card for USB debugging quotes the switch and the page in Persian,
#    each in its own direction, English beside them; and
#    in Advanced, the names' section quotes Android's always-on switch both ways.
#
# Only for emulators: it changes the phone's language, and sets it back to English (United States) at the end.
#
#   scripts/verify-labels.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PKG=org.visadahyu.datapavan
ADVANCED=org.visadahyu.datapavan.advanced
ADVANCED_APK="$ROOT/android/app/build-advanced/outputs/apk/debug/app-debug.apk"
# shellcheck source=scripts/adb-ui.sh
. "$ROOT/scripts/adb-ui.sh"

LRI=$'⁦'
RLI=$'⁧'
PDI=$'⁩'
# Where an emulator's image shows another text than AOSP's at the last tag of its release, by tabs: the key, the
# language, the API level, the text it shows, and why. Translations are revised within a release: Android 15's Google
# APIs image (revision 9, build AE3A.240806.043 of August 2024, the local dp-api35-ci's) shows android-15.0.0_r1's
# text for these three, which r10 and r20 revised (read from android.googlesource.com on 2026-11-22). An image with
# the last tag's text passes too. Android 11's (dp-api30, RSR1.240422.006) shows 11.0.0_r20's Arabic accessibility. The
# phone's own text is what Datapavan reads either way; the fallback stays the last tag's.
KNOWN=$(printf '%s\t%s\t%s\t%s\t%s\n' \
    accessibility zh 35 '无障碍' "android-15.0.0_r1's text, revised in r10" \
    developer_options fa 35 'گزینه‌های برنامه‌نویسان' "android-15.0.0_r1's text, revised in r10" \
    notification_access zh 35 '阅读、回复和控制通知' "android-15.0.0_r1's text, revised by r20" \
    accessibility ar 30 'إمكانية الوصول' "android-11.0.0_r1's to r20's text, revised by r35")

if ! is_emulator; then
    echo "verify-labels.sh changes the phone's language and runs on emulators only" >&2
    exit 2
fi
API=$(adb shell getprop ro.build.version.sdk | tr -d '\r')
PHONE_CHANGED=""
INSTALLED_ADVANCED=""

cleanup() {
    if [ -n "$PHONE_CHANGED" ]; then set_phone_locale en-US >/dev/null 2>&1 || true; fi
    adb shell cmd locale set-app-locales "$PKG" --locales en >/dev/null 2>&1 || true
    [ -z "$INSTALLED_ADVANCED" ] || adb uninstall "$ADVANCED" >/dev/null 2>&1 || true
    adb shell rm -f "$DUMP" >/dev/null 2>&1 || true
}
trap cleanup EXIT

fail() {
    echo "VERIFY FAILED: $*" >&2
    local out="$ROOT/build/screenshots"
    mkdir -p "$out"
    adb exec-out screencap -p >"$out/verify-labels-failure.png" 2>/dev/null || true
    if adb shell uiautomator dump "$DUMP" >/dev/null 2>&1; then
        adb shell cat "$DUMP" >"$out/verify-labels-failure.xml"
        echo "On screen:" >&2
        grep -o 'text="[^"]\+"' "$out/verify-labels-failure.xml" | head -40 >&2 || true
    fi
    exit 1
}

# Whether Android has the locale manager's shell command for the phone's language (Android 17). Read whole: under
# pipefail, a grep -q that stops reading early fails the pipe.
device_locale_command() {
    local help
    help=$(adb shell cmd locale help 2>/dev/null || true)
    grep -q 'set-device-locale' <<<"$help"
}

# The phone's own language, as Settings would set it: through the locale manager's shell command where Android has
# one (Android 17), else through the emulator's Custom Locale app; then waits until Android holds it.
set_phone_locale() {
    if device_locale_command; then
        adb shell cmd locale set-device-locale "$1" >/dev/null
        for _ in $(seq 1 20); do
            [ "$(adb shell cmd locale get-device-locale | tr -d '\r')" = "$1" ] && return 0
            sleep 1
        done
        return 1
    fi
    if custom_locale_app; then
        adb shell am broadcast -a com.android.intent.action.SET_LOCALE --es com.android.intent.extra.LOCALE "$1" \
            com.android.customlocale2 >/dev/null
        for _ in $(seq 1 20); do
            [ "$(adb shell getprop persist.sys.locale | tr -d '\r')" = "$1" ] && return 0
            sleep 1
        done
        return 1
    fi
    # Android 15's Google APIs image has neither: on its userdebug build, the property Android starts with, and a
    # restart of Android's framework, which ends every app (as Settings' own change does not). The old framework can
    # still answer for a moment after the restart is asked for, and an app's language set then is lost when the new one
    # loads the stored ones (CI, 2026-11-22): so this waits for a new system_server that has finished booting and holds
    # the language.
    [ "$(adb shell getprop ro.build.type | tr -d '\r')" != user ] || return 1
    adb root >/dev/null
    timeout 60 adb wait-for-device
    local before now config
    before=$(adb shell pidof system_server | tr -d '\r')
    adb shell setprop sys.boot_completed 0
    adb shell setprop persist.sys.locale "$1"
    adb shell setprop ctl.restart zygote
    for _ in $(seq 1 120); do
        now=$(adb shell pidof system_server 2>/dev/null | tr -d '\r') || now=""
        if [ -n "$now" ] && [ "$now" != "$before" ] && [ "$(adb shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" = 1 ]; then
            break
        fi
        sleep 2
    done
    [ -n "$now" ] && [ "$now" != "$before" ] || return 1
    # The new framework's configuration names the language as fa-rIR.
    for _ in $(seq 1 30); do
        config=$(adb shell am get-config 2>/dev/null | tr -d '\r') || config=""
        grep -q -- "-${1%-*}-r${1#*-}-" <<<"$config" && break
        sleep 1
    done
    grep -q -- "-${1%-*}-r${1#*-}-" <<<"$config" || return 1
    adb shell input keyevent KEYCODE_WAKEUP
    adb shell wm dismiss-keyguard >/dev/null 2>&1 || true
    [ "$(adb shell getprop persist.sys.locale | tr -d '\r')" = "$1" ]
}

# Datapavan's own language ($2) for the package $1, set and seen to hold for three seconds: a language set while
# Android's framework still loads the stored ones can be lost (CI, 2026-11-22), and the screens would then be checked
# in another language than the one this script means.
set_app_language() {
    local said
    for _ in 1 2 3 4 5; do
        adb shell cmd locale set-app-locales "$1" --locales "$2" >/dev/null
        sleep 3
        said=$(adb shell cmd locale get-app-locales "$1" | tr -d '\r')
        [[ "$said" == *"are [$2]"* ]] && return 0
        sleep 2
    done
    fail "Datapavan's language for $1 did not stay $2: Android says '$said'"
}

# Whether the emulator's Custom Locale app is there. Read whole, as above.
custom_locale_app() {
    local packages
    packages=$(adb shell pm list packages com.android.customlocale2 2>/dev/null | tr -d '\r')
    grep -q customlocale2 <<<"$packages"
}

# Whether the screen's dump holds the text $1 anywhere in an element's text. A text with a double quote in it is
# written in single quotes from Android 16, and with &quot; before; an apostrophe as &apos; or as it is.
screen_contains() {
    local screen
    dump_screen || return 1
    screen=$(adb shell cat "$DUMP" 2>/dev/null) || return 1
    screen=${screen//&quot;/\"}
    screen=${screen//&apos;/\'}
    grep -qF -- "$1" <<<"$screen"
}

# AOSP's text of a label at this release, in a language.
expected() { awk -F'\t' -v key="$1" -v lang="$2" '$1 == key && $2 == lang { print $3; exit }' <<<"$EXPECTED"; }

echo "== Android's own labels on Android $(adb shell getprop ro.build.version.release | tr -d '\r') (API $API)"
EXPECTED=$(python3 -I "$ROOT/scripts/android-labels.py" --expected "$API")
[ -n "$EXPECTED" ] || fail "no AOSP text recorded for API $API (scripts/testdata/android-labels-aosp.tsv)"

# A fresh start: no data pack imported, as an import of a test pack could hold other rows.
adb shell pm clear "$PKG" >/dev/null
adb shell am start -W -n "$PKG/.MainActivity" >/dev/null
read_dump=""
for _ in $(seq 1 10); do
    read_dump=$(adb shell dumpsys activity "$PKG/.MainActivity" labels-read </dev/null | tr -d '\r')
    grep -qx 'labels-read done' <<<"$read_dump" && break
    sleep 1
done
grep -qx 'labels-read done' <<<"$read_dump" || fail "the debug dump did not read the labels: $(tail -3 <<<"$read_dump")"
grep -m1 '^labels-read maker' <<<"$read_dump"

compared=0
known_count=0
differ=()
while IFS=$'\t' read -r key lang text; do
    line=$(grep -m1 "^label $key $lang " <<<"$read_dump" || true)
    [ -n "$line" ] || { differ+=("$key $lang: not in the dump"); continue; }
    source=$(cut -d' ' -f4 <<<"$line")
    got=$(cut -d' ' -f6- <<<"$line")
    compared=$((compared + 1))
    if [ "$source" != phone ] || [ "$got" != "$text" ]; then
        known=$(awk -F'\t' -v key="$key" -v lang="$lang" -v api="$API" -v got="$got" \
            '$1 == key && $2 == lang && $3 == api && $4 == got { print $5 }' <<<"$KNOWN")
        if [ "$source" = phone ] && [ -n "$known" ]; then
            known_count=$((known_count + 1))
            echo "  known: $key $lang: '$got', AOSP's at the release's last tag '$text': $known"
        else
            differ+=("$key $lang: $source '$got', AOSP's at API $API is '$text'")
        fi
    fi
done <<<"$EXPECTED"
if [ ${#differ[@]} -gt 0 ]; then
    printf '  %s\n' "${differ[@]}" >&2
    fail "${#differ[@]} of $compared labels are not AOSP's text at API $API"
fi
echo "ok: all $compared labels read from the phone in eight languages are AOSP's text at API $API, $known_count of them an earlier tag's, as known"

usage_en=$(expected usage_access en)
usage_fa=$(expected usage_access fa)
found=$(adb shell dumpsys activity "$PKG/.MainActivity" labels-find en "'$usage_en'" </dev/null | tr -d '\r')
grep -qx 'found string/usage_access' <<<"$found" || fail "labels-find did not find usage_access by '$usage_en': $(tail -3 <<<"$found")"
grep -qxF "  fa $usage_fa" <<<"$found" || fail "labels-find did not print usage_access in Persian: $(grep -A9 'found string/usage_access' <<<"$found")"
refused=$(adb shell dumpsys activity "$PKG/.MainActivity" labels-find en --package "$PKG" Datapavan </dev/null | tr -d '\r')
grep -q "^labels-find refused $PKG: not a system app" <<<"$refused" || fail "labels-find read an app that is not a system app: $refused"
echo "ok: labels-find finds a label's name by its text, prints it in eight languages, and reads system apps only"

if [ "$API" -lt 33 ]; then
    echo "skipped: the screens, as Android $API sets no app's own language"
    echo "== Android's own labels checked on the emulator"
    exit 0
fi
device_locale_command || custom_locale_app || [ "$(adb shell getprop ro.build.type | tr -d '\r')" != user ] ||
    fail "this image can set no phone language: no locale manager's set-device-locale, no Custom Locale app, and a user build"

# The labels as this phone gave them above, which the screens must quote.
phone_label() { grep -m1 "^label $1 $2 phone " <<<"$read_dump" | cut -d' ' -f6-; }
dev_en=$(phone_label developer_options en)
dev_fa=$(phone_label developer_options fa)
usb_en=$(phone_label usb_debugging en)
usb_fa=$(phone_label usb_debugging fa)
always_en=$(phone_label always_on_vpn en)
always_fa=$(phone_label always_on_vpn fa)

# The phone in English, Datapavan in Persian: the finding's button is the phone's label, Persian beside it.
set_app_language "$PKG" fa
adb shell am force-stop "$PKG"
adb shell am start -W -n "$PKG/.MainActivity" >/dev/null
# The network tab's usage access card keeps Datapavan's name for the access and gives the phone's own (the maintainer,
# 2026-11-22): the page's and its switch's names, the phone's first.
usage_fa=$(phone_label usage_access fa)
usage_en=$(phone_label usage_access en)
permit_en=$(phone_label permit_usage_access en)
permit_fa=$(phone_label permit_usage_access fa)
line="This phone's settings call it “$LRI$usage_en$PDI ($RLI$usage_fa$PDI)”, with the switch “$LRI$permit_en$PDI ($RLI$permit_fa$PDI)”."
open_tab network || fail "the network tab did not open"
for _ in $(seq 1 30); do screen_contains "$line" && break; sleep 1; done
screen_contains "$line" || { scroll_to "This phone's settings call it" >/dev/null || true; screen_contains "$line"; } ||
    fail "the usage access card does not say '$line'"
echo "ok: phone in English, Datapavan in Persian: the usage access card says '$line'"
open_tab phone || fail "the phone's tab did not open"
button="$LRI$dev_en$PDI ($RLI$dev_fa$PDI)"
scroll_to "$button" || fail "the finding of USB debugging has no button '$button'"
echo "ok: phone in English, Datapavan in Persian: the button reads '$button'"

# The phone in Persian, Datapavan in English: the plan's card quotes the switch and its page in Persian, right to
# left inside the English sentence, English beside each.
PHONE_CHANGED=1
set_phone_locale fa-IR || fail "the phone's language did not change to Persian"
set_app_language "$PKG" en
adb shell am force-stop "$PKG"
adb shell am start -W -a org.visadahyu.datapavan.action.OPEN_PLAN -n "$PKG/.MainActivity" >/dev/null
tap_text "Medium" || fail "the plan's level Medium is not on screen (Datapavan's language: $(adb shell cmd locale get-app-locales "$PKG" | tr -d '\r'))"
tap_text "Start" || fail "the plan has nothing to start at Medium"
card="turn off the “$RLI$usb_fa$PDI ($LRI$usb_en$PDI)” switch on the “$RLI$dev_fa$PDI ($LRI$dev_en$PDI)” page."
for _ in 1 2 3 4 5 6; do
    screen_contains "$card" && break
    tap_text "Next" || break
done
screen_contains "$card" || fail "no card of the plan says '$card'"
echo "ok: phone in Persian, Datapavan in English: the plan's card says '$card'"

# Advanced's network monitoring, both ways: its names' section quotes Android's always-on switch.
if [ -f "$ADVANCED_APK" ]; then
    adb shell pm list packages "$ADVANCED" | grep -q "package:$ADVANCED\$" || INSTALLED_ADVANCED=1
    adb install -r "$ADVANCED_APK" >/dev/null
    # Whether the names' section's limits quote $1, the screen opened afresh in the language $2. The sentence holds
    # quotes, which the dump may write in other quotes, so the line above it, as that language's file has it, leads
    # there.
    watch_says() {
        local above
        above=$(sed -n 's/.*<string name="dns_local_names">\([^<]*\)<.*/\1/p' "$ROOT/android/network/src/main/res/$2/strings.xml" | sed "s/\\\\'/'/g")
        adb shell am force-stop "$ADVANCED"
        adb shell am start -W -n "$ADVANCED/org.visadahyu.datapavan.watch.MainActivity" >/dev/null
        scroll_to "${above:0:24}" || fail "the names' section is not on screen ('${above:0:24}')"
        for _ in 1 2 3; do
            screen_contains "$1" && return 0
            swipe_up
        done
        return 1
    }
    set_app_language "$ADVANCED" en
    quoted="\"$RLI$always_fa$PDI ($LRI$always_en$PDI)\" switch"
    watch_says "$quoted" values || fail "with the phone in Persian, the names' section does not quote $quoted"
    echo "ok: phone in Persian, Advanced in English: the names' section quotes $quoted"
    set_phone_locale en-US || fail "the phone's language did not change back to English"
    set_app_language "$ADVANCED" fa
    quoted="\"$LRI$always_en$PDI ($RLI$always_fa$PDI)\" switch"
    watch_says "$quoted" values-fa || fail "with Advanced in Persian, the names' section does not quote $quoted"
    echo "ok: phone in English, Advanced in Persian: the names' section quotes $quoted"
    adb shell cmd locale set-app-locales "$ADVANCED" --locales en
else
    echo "skipped: Advanced's screens, as its debug APK is not built"
fi

set_phone_locale en-US || fail "the phone's language did not change back to English"
PHONE_CHANGED=""
echo "== Android's own labels checked on the emulator"
