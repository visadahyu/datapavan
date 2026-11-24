#!/usr/bin/env bash
# The TalkBack walk (docs/ACCESSIBILITY.md): what Google's screen reader says on each of Datapavan Advanced's screens,
# arriving and then item after item, with each screen's accessibility tree, in each language of WALK_LOCALES (default
# English, Persian and Arabic). Local only: TalkBack ships only in Google Play system images (the dp-api37-16k AVD), and
# CI's image has none. scripts/talkback-check.py reads the record.
#
# The project's own scripts/speech-log (emulators only, never shipped) makes it work:
# - a speech engine that speaks nothing and writes each utterance TalkBack hands it, with the language and voice
#   TalkBack asks for, to logcat;
# - an accessibility service that performs TalkBack's swipes through Android's gesture dispatch (which passes through
#   touch exploration as a finger would; "adb shell input" does not), clicks elements by test tag while TalkBack stays
#   on, so that what it says on arriving at a screen is heard, and writes the screen's node tree.
# TalkBack stays on for the whole walk: no uiautomator dump is made, since a dump unbinds every accessibility service.
#
#   scripts/talkback-walk.sh [output directory, default build/talkback]
#
# Needs ANDROID_SERIAL set to an emulator with TalkBack, Advanced's debug APK and build/speech-log/speech-log.apk
# (scripts/speech-log/build.sh). Every setting it changes is put back at the end.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${1:-$ROOT/build/talkback}"
PKG=org.visadahyu.datapavan.advanced
NETWORK=org.visadahyu.datapavan.network.MainActivity
# Advanced holds Basic's classes, so its audit's activity is named in full.
AUDIT=org.visadahyu.datapavan.MainActivity
TALKBACK=com.google.android.marvin.talkback/com.google.android.marvin.talkback.TalkBackService
GESTURES=org.visadahyu.datapavan.speechlog/org.visadahyu.datapavan.speechlog.GestureService
ACTION=org.visadahyu.datapavan.speechlog.GESTURE
# The app whose guided check is walked: TalkBack itself, an accessibility service on every phone that has it.
CHECKED=com.google.android.marvin.talkback
APK="$ROOT/android/app/build-advanced/outputs/apk/debug/app-debug.apk"
LOG_APK="$ROOT/build/speech-log/speech-log.apk"
# shellcheck source=scripts/adb-ui.sh
. "$ROOT/scripts/adb-ui.sh"

fail() { echo "TALKBACK WALK FAILED: $*" >&2; exit 1; }
[ -n "${ANDROID_SERIAL:-}" ] || fail "set ANDROID_SERIAL to the emulator to walk"
is_emulator || fail "emulators only: it replaces the speech engine and turns on accessibility services"
adb shell pm path com.google.android.marvin.talkback | grep -q . || fail "no TalkBack on this image (Google Play images have it)"
[ -f "$APK" ] && [ -f "$LOG_APK" ] || fail "build Advanced's debug APK and scripts/speech-log first"

old_tts=$(adb shell settings get secure tts_default_synth | tr -d '\r')
old_services=$(adb shell settings get secure enabled_accessibility_services | tr -d '\r')
old_enabled=$(adb shell settings get secure accessibility_enabled | tr -d '\r')
# The settings as they were: an emulator may carry accessibility services of its own.
put_back() {
    if [ "$2" = null ]; then adb shell settings delete secure "$1" >/dev/null 2>&1 || true
    else adb shell settings put secure "$1" "$2" >/dev/null 2>&1 || true; fi
}
restore() {
    put_back enabled_accessibility_services "$old_services"
    put_back accessibility_enabled "$old_enabled"
    put_back tts_default_synth "$old_tts"
    adb shell cmd locale set-app-locales "$PKG" --locales en >/dev/null 2>&1 || true
}
trap restore EXIT

adb install -r -g "$APK" >/dev/null
# The speech log is signed with a key made at each build: an older copy is removed first.
adb uninstall org.visadahyu.datapavan.speechlog >/dev/null 2>&1 || true
adb install "$LOG_APK" >/dev/null
adb shell settings put secure tts_default_synth org.visadahyu.datapavan.speechlog
adb shell settings delete global datapavan_speechlog_without >/dev/null 2>&1 || true
# A walk of a long screen writes thousands of lines; the default log buffer would drop the first.
adb logcat -G 16M >/dev/null 2>&1 || true
# On Android 13 and later, TalkBack's suite asks once for leave to notify, in a dialog over the screen being walked; the
# emulator gives it beforehand, so that nothing is tapped.
adb shell pm grant com.google.android.marvin.talkback android.permission.POST_NOTIFICATIONS 2>/dev/null || true
mkdir -p "$OUT"
talkback=$(adb shell dumpsys package com.google.android.marvin.talkback | tr -d '\r' | sed -n 's/^ *versionName=//p' | head -1)
echo "TalkBack $talkback, default settings; Android $(adb shell getprop ro.build.version.release | tr -d '\r')" >"$OUT/about.txt"

tell() { adb shell am broadcast -a "$ACTION" --es do "$@" >/dev/null; }
spoken() { adb logcat -d -s DatapavanSpeech:I | grep -c $'\t' || true; }
# What TalkBack said since the last gesture: the utterances after the last "gesture" line.
said_last() { adb logcat -d -s DatapavanSpeech:I | tr -d '\r' | sed -n 's/^.* DatapavanSpeech: //p' | awk '/^gesture /{block=""; next} /^load /{next} {block=block $0 "|"} END{print block}'; }

talkback_on() {
    adb shell settings put secure enabled_accessibility_services "$TALKBACK:$GESTURES"
    adb shell settings put secure accessibility_enabled 1
    for _ in $(seq 1 20); do
        adb logcat -d -s DatapavanSpeech:I | grep -q 'gestures ready' && break
        sleep 1
    done
    sleep 4
}

# A click by test tag, with TalkBack on; fails the walk if the element is not there.
click() {
    local answer="" try
    # The service may scroll a list to reach the element: it answers when it has clicked, or found nothing. A miss is
    # tried again once, a few seconds later, as the screen may still be changing.
    for try in 1 2; do
        tell click --es id "$1"
        for _ in $(seq 1 20); do
            answer=$(adb logcat -d -s DatapavanSpeech:I | grep -o "gesture click $1 \(done\|missing\)" | tail -1 || true)
            [ -z "$answer" ] || break
            sleep 1
        done
        [ "$answer" != "gesture click $1 done" ] || break
        adb logcat -c
        sleep 4
    done
    [ "$answer" = "gesture click $1 done" ] || fail "no element $1 to click in $locale"
    sleep 2
}

# The screen on display: what TalkBack said on arriving (since the record began), the tree, then a swipe to the next
# item at a time, until TalkBack comes round to items it said before, two swipes bring nothing new within 9 s each,
# or WALK_MAX swipes (default 80). The record of the screen begins with the step that led to it: call begin before.
begin() { adb logcat -c; }
walk() {
    local name=$1 before after quiet=0 i now key reason=cap
    local -a blocks=()
    local -A seen=()
    sleep 2
    tell tree
    sleep 2
    for i in $(seq 1 "${WALK_MAX:-80}"); do
        before=$(spoken)
        tell next
        sleep 1.5
        after=$(spoken)
        # A long item, a licence read whole, keeps TalkBack busy past the wait, and it goes on to the next item some
        # seconds later (seen on the data sources page, 2026-11-24): a swipe is quiet only if nothing comes within 9 s.
        for _ in 1 2 3 4 5 6; do
            [ "$after" = "$before" ] || break
            sleep 1.25
            after=$(spoken)
        done
        if [ "$after" = "$before" ]; then quiet=$((quiet + 1)); else quiet=0; fi
        if [ "$quiet" -ge 2 ]; then reason=quiet; break; fi
        now=$(said_last)
        blocks+=("$now")
        # TalkBack goes on from the last item to the first: three steps in a row that were said before, in the same
        # order, mean it has come round (one repeated item alone may be two items with the same words).
        if [ "${#blocks[@]}" -ge 3 ]; then
            key="${blocks[-3]}"$'\x1f'"${blocks[-2]}"$'\x1f'"${blocks[-1]}"
            if [ -n "${seen[$key]:-}" ]; then reason=wrap; break; fi
            seen[$key]=1
        fi
    done
    tell end --es id "$reason"
    sleep 1
    adb logcat -d -s DatapavanSpeech:I DatapavanTree:I | tr -d '\r' | sed -n 's/^.* Datapavan\(Speech\|Tree\): /\1\t/p' |
        grep -v $'^Speech\tgestures ready$' >"$OUT/$locale-$name.txt"
    # A walk whose swipes never ran, that TalkBack never spoke in, or whose tree is missing, is no record.
    grep -q $'^Speech\tgesture next done$' "$OUT/$locale-$name.txt" || fail "no swipe was performed on $name in $locale"
    grep -qP '^Speech\t[^\t]+\t' "$OUT/$locale-$name.txt" || fail "TalkBack said nothing on $name in $locale"
    grep -q $'^Tree\tend$' "$OUT/$locale-$name.txt" || fail "no tree of $name in $locale"
    echo "walked: $name in $locale"
}

start_activity() { adb shell am start -W -n "$PKG/$1" "${@:2}" >/dev/null; }

talkback_on
for locale in ${WALK_LOCALES:-en fa ar}; do
    adb shell cmd locale set-app-locales "$PKG" --locales "$locale"
    adb shell am force-stop "$PKG"
    begin; start_activity "$AUDIT"; sleep 6; walk summary
    for tab in apps phone network; do begin; click "nav-$tab"; walk "$tab"; done
    begin; click settings; walk settings
    # The settings' pages, the strict review, the guided check and the journal are opened directly (debug builds'
    # screen_for_tests): TalkBack keeps its focus in a list, so a list cannot be scrolled to the way in.
    for page in data_sources own_copy privacy licences about; do
        adb shell am force-stop "$PKG"
        begin; start_activity "$AUDIT" --es screen_for_tests "settings:$page"; sleep 4; walk "settings-$page"
    done
    for screen in review journal "check:$CHECKED"; do
        adb shell am force-stop "$PKG"
        begin; start_activity "$AUDIT" --es screen_for_tests "$screen"; sleep 4; walk "${screen%%:*}"
    done
    adb shell am force-stop "$PKG"
    begin; start_activity "$AUDIT"; sleep 6
    begin; click nav-apps
    begin; click app-row; walk app
    begin; adb shell am start -W -a org.visadahyu.datapavan.action.OPEN_PLAN -f 0x1000c000 -n "$PKG/$AUDIT" >/dev/null; walk plan
    adb shell am force-stop "$PKG"
    begin; start_activity "$NETWORK"; walk network-screen
    begin; start_activity "$NETWORK" --activity-clear-top --ez now true; walk now
    # Opened again, so that the pause is at the top: the walk scrolled "Now" down.
    adb shell am force-stop "$PKG"
    start_activity "$NETWORK" --activity-clear-top --ez now true; sleep 4
    begin; click now-pause; walk now-paused
done

# What a reader of the record looks for first.
python3 -I "$ROOT/scripts/talkback-check.py" "$OUT" | tee "$OUT/summary.txt"
