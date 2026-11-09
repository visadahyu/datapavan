#!/usr/bin/env bash
# Smoke test of Datapavan Watch, milestone W1 (docs/DESIGN.md, 13.2), on a connected device or
# emulator: installs the debug APK, opens Watch in every UI language and two pseudo-locales, and checks
# that its text is translated and laid out right to left where the language is; then turns the tunnel
# on and off from Watch's screen and checks that Android lists Watch's VPN only while it is on, with
# Watch alone inside it, and that Watch did not crash. It needs nothing but adb.
#
# On an emulator the VPN consent is given through appops. On a phone, the person holding it taps
# Android's consent dialog the first time; the script waits three minutes for that.
#
#   scripts/smoke-watch.sh [path/to/watch-debug.apk]
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APK="${1:-$ROOT/android/watch/build/outputs/apk/debug/watch-debug.apk}"
PKG=org.visadahyu.datapavan.watch
RES="$ROOT/android/watch/src/main/res"
# shellcheck source=scripts/adb-ui.sh
. "$ROOT/scripts/adb-ui.sh"

fail() {
    echo "WATCH SMOKE FAILED: $*" >&2
    adb logcat -d -b crash 2>/dev/null | tail -40 >&2 || true
    mkdir -p "$ROOT/build/screenshots"
    adb exec-out screencap -p >"$ROOT/build/screenshots/smoke-watch-failure.png" 2>/dev/null || true
    if adb shell uiautomator dump "$DUMP" >/dev/null 2>&1; then
        echo "On screen:" >&2
        adb shell cat "$DUMP" | grep -o 'text="[^"]\+"' | head -20 >&2 || true
    fi
    exit 1
}

# The string $2 of the resource directory $1, as Android shows it (the XML's escapes undone).
string() {
    sed -n "s/.*<string name=\"$2\">\(.*\)<\/string>.*/\1/p" "$RES/$1/strings.xml" | sed "s/\\\\'/'/g"
}

# Opens Watch afresh in the language $1 (a BCP 47 tag, or "" for the phone's own).
open_in() {
    adb shell am force-stop "$PKG"
    adb shell cmd locale set-app-locales "$PKG" --locales "$1" >/dev/null
    adb shell am start -W -n "$PKG/.MainActivity" >/dev/null
}

# Waits up to $2 seconds for text starting with $1.
wait_for() {
    local i
    for i in $(seq 1 "$2"); do
        screen_has "$1" && return 0
        sleep 1
    done
    return 1
}

# The VPN network Android lists, if it is Watch's: one line, empty when there is none. Android 12 and
# later write "ni{VPN CONNECTED ...", Android 10 and 11 "ni{[type: VPN[] ..."; both name the owner.
vpn_line() {
    adb shell dumpsys connectivity | tr -d '\r' | grep -E 'ni\{(VPN |\[type: VPN)' | grep "OwnerUid: $uid " | head -1 || true
}

# The apps inside the tunnel, as Android's routing rules send them to it: the UID ranges of the rules
# that look up the tunnel's own table (the one with its default route), other than root's, one per
# line. Other tables have rules for other apps, such as per-app network preferences. Watch's UID can
# come with its SDK sandbox's (Android 13 and later: 10000 more), and each user of the phone (a work
# profile, a private space) adds both again in that user, with the same last five digits.
tunnel_uids() {
    local table
    table=$(adb shell ip route show table all | tr -d '\r' | sed -n 's/^default dev tun[0-9]* table \([0-9a-z_]*\) .*/\1/p' | head -1)
    [ -n "$table" ] || return 0
    adb shell ip rule | tr -d '\r' | grep -E "lookup $table( |\$)" | grep -o 'uidrange [0-9]*-[0-9]*' |
        cut -d' ' -f2 | grep -v '^0-0$' | sort -u || true
}

echo "== Watch smoke test on $(adb shell getprop ro.product.model | tr -d '\r'), Android $(adb shell getprop ro.build.version.release | tr -d '\r')"
adb wait-for-device
adb install -r "$APK" >/dev/null
# Exactly Watch's package: the listing also matches names that start with it, such as the spike's.
uid=$(adb shell cmd package list packages -U "$PKG" | tr -d '\r' | sed -n "s/^package:$PKG uid:\([0-9]*\)$/\1/p")
[ -n "$uid" ] || fail "Watch is not installed"
adb logcat -c

# Every language, by the tagline in its resource directory. Per-app languages need Android 13.
width=$(adb shell wm size | tr -d '\r' | sed -n 's/.*: \([0-9]*\)x.*/\1/p' | tail -1)
if [ "$(adb shell getprop ro.build.version.sdk | tr -d '\r')" -ge 33 ]; then
    for pair in en:values fr:values-fr de:values-de es:values-es ru:values-ru zh-CN:values-zh-rCN ar:values-ar fa:values-fa; do
        tag=${pair%%:*}
        tagline=$(string "${pair#*:}" tagline)
        open_in "$tag"
        wait_for "$tagline" 15 || fail "Watch in $tag does not show its tagline"
        # Right to left: the heading ends at the right edge, not the left.
        set -- $(text_bounds "Datapavan Watch")
        case $tag in
            ar | fa) [ "$3" -gt $((width * 3 / 4)) ] || fail "Watch in $tag is not laid out right to left" ;;
            *) [ "$1" -lt $((width / 4)) ] || fail "Watch in $tag is not laid out left to right" ;;
        esac
        echo "ok: $tag"
    done
    # The pseudo-locales of debug builds: accented English, and English mirrored right to left.
    open_in en-XA
    wait_for "\\[Šéé" 15 || fail "Watch in en-XA does not show the pseudo-locale's text"
    echo "ok: en-XA"
    open_in ar-XB
    wait_for "Datapavan Watch" 15 || fail "Watch in ar-XB does not open"
    set -- $(text_bounds "Datapavan Watch")
    [ "$3" -gt $((width * 3 / 4)) ] || fail "Watch in ar-XB is not laid out right to left"
    echo "ok: ar-XB"
    adb shell cmd locale set-app-locales "$PKG" --locales "" >/dev/null
    open_in ""
else
    echo "skipped: per-app languages need Android 13"
    adb shell am start -W -n "$PKG/.MainActivity" >/dev/null
fi

# The tunnel, in English from here on.
if [ "$(adb shell getprop ro.build.version.sdk | tr -d '\r')" -ge 33 ]; then open_in en; fi
wait_for "$(string values status_off)" 15 || fail "Watch does not say it is off"
[ -z "$(vpn_line)" ] || fail "Android lists Watch's VPN before it was turned on"
is_emulator && adb shell appops set "$PKG" ACTIVATE_VPN allow
tap_now "$(string values turn_on)" || fail "no button to turn Watch on"
if ! wait_for "$(string values status_on)" 5; then
    echo "Waiting three minutes for the VPN request to be allowed on the phone's screen"
    wait_for "$(string values status_on)" 180 || fail "Watch did not say it is on"
fi
line=$(vpn_line)
[ -n "$line" ] || fail "Android lists no VPN of Watch's while Watch says it is on"
ranges=$(tunnel_uids)
[ -n "$ranges" ] || fail "Android's routing rules send no app into the tunnel"
for range in $ranges; do
    first=${range%-*}
    last=${range#*-}
    app=$((first % 100000))
    [ "$first" = "$last" ] && { [ "$app" = "$uid" ] || [ "$app" = $((uid + 10000)) ]; } ||
        fail "the tunnel holds more than Watch itself: $(echo $ranges)"
done
echo "ok: the tunnel is up, with Watch alone inside it"

tap_now "$(string values turn_off)" || fail "no button to turn Watch off"
wait_for "$(string values status_off)" 10 || fail "Watch did not say it is off"
for _ in 1 2 3 4 5; do
    [ -z "$(vpn_line)" ] && break
    sleep 1
done
[ -z "$(vpn_line)" ] || fail "Android still lists Watch's VPN after it was turned off"
echo "ok: the tunnel is down"

adb shell pidof "$PKG" >/dev/null || fail "Watch is no longer running"
if adb logcat -d -b crash 2>/dev/null | grep -q "$PKG"; then
    fail "Watch crashed"
fi
echo "ok: no crash"
echo "== Watch smoke test passed"
