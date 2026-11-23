#!/usr/bin/env bash
# The TalkBack walk (docs/ACCESSIBILITY.md): what Google's screen reader says on each of Datapavan Advanced's screens,
# item after item, in each language of WALK_LOCALES (default English, Persian and Arabic), written to a record that
# people read. Local only: TalkBack ships only in Google Play system images (the dp-api37-16k AVD), and CI's image has
# none.
#
# Two pieces of the project's own, from scripts/speech-log (emulators only, never shipped), make it work:
# - a speech engine that speaks nothing and writes each utterance TalkBack hands it, with the language TalkBack asks
#   for, to logcat;
# - an accessibility service that performs TalkBack's swipe to the next item through Android's gesture dispatch, which
#   passes through TalkBack's touch exploration as a finger would. "adb shell input" does not: it goes past TalkBack.
# A uiautomator dump unbinds every accessibility service while it runs, so each screen is reached with TalkBack off,
# then TalkBack is turned on and the screen walked from the item it focuses first, until a swipe brings nothing new.
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
TALKBACK=com.google.android.marvin.talkback/com.google.android.marvin.talkback.TalkBackService
GESTURES=org.visadahyu.datapavan.speechlog/org.visadahyu.datapavan.speechlog.GestureService
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
restore() {
    adb shell settings delete secure enabled_accessibility_services >/dev/null 2>&1 || true
    adb shell settings put secure accessibility_enabled 0 >/dev/null 2>&1 || true
    if [ "$old_tts" = null ]; then adb shell settings delete secure tts_default_synth >/dev/null 2>&1 || true
    else adb shell settings put secure tts_default_synth "$old_tts" >/dev/null 2>&1 || true; fi
    adb shell cmd locale set-app-locales "$PKG" --locales en >/dev/null 2>&1 || true
}
trap restore EXIT

adb install -r -g "$APK" >/dev/null
adb install -r "$LOG_APK" >/dev/null
adb shell settings put secure tts_default_synth org.visadahyu.datapavan.speechlog
mkdir -p "$OUT"
talkback=$(adb shell dumpsys package com.google.android.marvin.talkback | tr -d '\r' | sed -n 's/^ *versionName=//p' | head -1)
echo "TalkBack $talkback, default settings; Android $(adb shell getprop ro.build.version.release | tr -d '\r')" >"$OUT/about.txt"

spoken() { adb logcat -d -s DatapavanSpeech:I | grep -c $'\t' || true; }

talkback_on() {
    adb logcat -c
    adb shell settings put secure enabled_accessibility_services "$TALKBACK:$GESTURES"
    adb shell settings put secure accessibility_enabled 1
    for _ in $(seq 1 20); do
        adb logcat -d -s DatapavanSpeech:I | grep -q 'gestures ready' && break
        sleep 1
    done
    # TalkBack reads the window's title and focuses its first item.
    sleep 4
}

talkback_off() {
    adb shell settings delete secure enabled_accessibility_services
    adb shell settings put secure accessibility_enabled 0
    sleep 2
}

# The screen on display, walked: a swipe to the next item at a time, until two swipes in a row bring nothing new or
# WALK_MAX swipes (default 80) were made.
walk() {
    local name=$1 before after quiet=0 i
    talkback_on
    for i in $(seq 1 "${WALK_MAX:-80}"); do
        before=$(spoken)
        adb shell am broadcast -a org.visadahyu.datapavan.speechlog.GESTURE --es do next >/dev/null
        sleep 1.5
        after=$(spoken)
        if [ "$after" = "$before" ]; then quiet=$((quiet + 1)); else quiet=0; fi
        [ "$quiet" -lt 2 ] || break
    done
    adb logcat -d -s DatapavanSpeech:I | tr -d '\r' | sed -n 's/^.* DatapavanSpeech: //p' | grep -v '^gestures ready$' >"$OUT/$locale-$name.txt"
    talkback_off
    echo "walked: $name in $locale ($(grep -c $'\t' "$OUT/$locale-$name.txt" || true) utterances)"
}

start_app() {
    adb shell am force-stop "$PKG"
    adb shell am start -W -n "$PKG/.MainActivity" "$@" >/dev/null
}

for locale in ${WALK_LOCALES:-en fa ar}; do
    adb shell cmd locale set-app-locales "$PKG" --locales "$locale"
    start_app
    wait_for_overview || fail "the summary did not appear in $locale"
    walk summary
    for tab in apps phone network; do
        open_tab "$tab" || fail "no $tab destination in $locale"
        walk "$tab"
    done
    tap_id settings || fail "no settings button in $locale"
    within 10 gone_id settings || fail "the settings did not open in $locale"
    walk settings
    start_app
    wait_for_overview || fail "the summary did not come back in $locale"
    open_tab apps || fail "no apps destination in $locale"
    within 60 has_id app-row || fail "no app in the list in $locale"
    tap_id app-row || fail "no app to open in $locale"
    within 10 gone_id app-row || fail "the app's page did not open in $locale"
    walk app
    adb shell am start -W -a org.visadahyu.datapavan.action.OPEN_PLAN -f 0x1000c000 -n "$PKG/.MainActivity" >/dev/null
    within 60 has_id plan || fail "the plan did not open in $locale"
    walk plan
    adb shell am force-stop "$PKG"
    adb shell am start -W -n "$PKG/$NETWORK" >/dev/null
    sleep 3
    walk network-screen
    adb shell am start -W -n "$PKG/$NETWORK" --activity-clear-top --ez now true >/dev/null
    sleep 3
    walk now
done

# What a reader of the record looks for first: items TalkBack could only call unlabelled, and Persian or Arabic text
# handed to the speech engine as another language's.
{
    echo "== $(cat "$OUT/about.txt")"
    grep -il 'unlabel' "$OUT"/*.txt | sed 's#^.*/#unlabelled items in #' || true
    for f in "$OUT"/fa-*.txt "$OUT"/ar-*.txt; do
        [ -f "$f" ] || continue
        n=$(grep -P '^(?!fas|per|ara)[a-z]{3}-[A-Z]*\t.*[\x{0600}-\x{06FF}]' "$f" | grep -c . || true)
        [ "$n" = 0 ] || echo "${f##*/}: $n utterances of Persian or Arabic text asked for in another language"
    done
} | tee "$OUT/summary.txt"
