#!/usr/bin/env bash
# Smoke test of the network part's service in Datapavan Advanced (milestones W1 and W2, docs/DESIGN.md, 13.2) on a
# connected device or emulator: installs the debug APK, opens the network part in every UI language and two
# pseudo-locales, and checks that its text is translated and laid out right to left where the language is; then turns
# the tunnel on and off from the network screen and checks that Android lists the network part's VPN only while it is
# on, with every app inside it, the network part itself and adb's shell among them, and that the network part did not
# crash. It needs nothing but adb. scripts/verify-network.sh checks the traffic through it.
#
# On an emulator the VPN consent is given through appops. On a phone, the person holding it taps
# Android's consent dialog the first time; the script waits three minutes for that.
#
#   scripts/smoke-network.sh [path/to/Datapavan-Advanced-debug.apk]
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APK="${1:-$ROOT/android/app/build-advanced/outputs/apk/debug/app-debug.apk}"
PKG=org.visadahyu.datapavan.advanced
# The network screen in Datapavan Advanced (ADR 0045); debug builds export it for these checks.
NETWORK_SCREEN=org.visadahyu.datapavan.network.MainActivity
RES="$ROOT/android/network/src/main/res"
# shellcheck source=scripts/adb-ui.sh
. "$ROOT/scripts/adb-ui.sh"

fail() {
    echo "NETWORK SMOKE FAILED: $*" >&2
    adb logcat -d -b crash 2>/dev/null | tail -40 >&2 || true
    mkdir -p "$ROOT/build/screenshots"
    adb exec-out screencap -p >"$ROOT/build/screenshots/smoke-network-failure.png" 2>/dev/null || true
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

# The screen's title, "Network", in the folder $1's language.
title() {
    string "$1" network_title
}

# The bounds of the first element whose text contains $1, for a pseudo-locale that wraps every text in marks.
bounds_containing() {
    adb shell cat "$DUMP" | grep -o "text=\"[^\"]*$1[^\"]*\"[^>]*bounds=\"[^\"]*\"" | head -1 | grep -o 'bounds="[^"]*"' |
        grep -o '[0-9]\+' | tr '\n' ' '
}

# Opens the network part afresh in the language $1 (a BCP 47 tag, or "" for the phone's own).
open_in() {
    adb shell am force-stop "$PKG"
    adb shell cmd locale set-app-locales "$PKG" --locales "$1" >/dev/null
    adb shell am start -W -n "$PKG/$NETWORK_SCREEN" >/dev/null
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

# The VPN network Android lists, if it is the network part's: one line, empty when there is none. Android 12 and
# later write "ni{VPN CONNECTED ...", Android 10 and 11 "ni{[type: VPN[] ..."; both name the owner.
vpn_line() {
    adb shell dumpsys connectivity | tr -d '\r' | grep -E 'ni\{(VPN |\[type: VPN)' | grep "OwnerUid: $uid " | head -1 || true
}

# The apps inside the tunnel, as Android's routing rules send them to it: the UID ranges of the rules
# that look up the tunnel's own table (the one with its default route), other than root's, one per
# line. Other tables have rules for other apps, such as per-app network preferences.
tunnel_uids() {
    local table
    table=$(adb shell ip route show table all | tr -d '\r' | sed -n 's/^default dev tun[0-9]* table \([0-9a-z_]*\) .*/\1/p' | head -1)
    [ -n "$table" ] || return 0
    adb shell ip rule | tr -d '\r' | grep -E "lookup $table( |\$)" | grep -o 'uidrange [0-9]*-[0-9]*' |
        cut -d' ' -f2 | grep -v '^0-0$' | sort -u || true
}

echo "== The network part's smoke test on $(adb shell getprop ro.product.model | tr -d '\r'), Android $(adb shell getprop ro.build.version.release | tr -d '\r')"
adb wait-for-device
adb install -r "$APK" >/dev/null
# Exactly the network part's package: the listing also matches names that start with it, such as the spike's.
uid=$(adb shell cmd package list packages -U "$PKG" | tr -d '\r' | sed -n "s/^package:$PKG uid:\([0-9]*\)$/\1/p")
[ -n "$uid" ] || fail "the network part is not installed"
adb logcat -c

# Every language, by the tagline in its resource directory, and the title's side. Per-app languages need Android 13.
width=$(adb shell wm size | tr -d '\r' | sed -n 's/.*: \([0-9]*\)x.*/\1/p' | tail -1)
if [ "$(adb shell getprop ro.build.version.sdk | tr -d '\r')" -ge 33 ]; then
    for pair in en:values fr:values-fr de:values-de es:values-es ru:values-ru zh-CN:values-zh-rCN ar:values-ar fa:values-fa; do
        tag=${pair%%:*}
        tagline=$(string "${pair#*:}" network_tagline)
        [ -n "$tagline" ] || fail "no network_tagline in ${pair#*:}"
        open_in "$tag"
        wait_for "$tagline" 15 || fail "the network part in $tag does not show its tagline"
        # Right to left: the heading ends at the right edge, not the left.
        set -- $(text_bounds "$(title "${pair#*:}")")
        [ $# -eq 4 ] || fail "the network part in $tag shows no title \"$(title "${pair#*:}")\""
        case $tag in
            ar | fa) [ "$3" -gt $((width * 3 / 4)) ] || fail "the network part in $tag is not laid out right to left" ;;
            *) [ "$1" -lt $((width / 4)) ] || fail "the network part in $tag is not laid out left to right" ;;
        esac
        echo "ok: $tag"
    done
    # The pseudo-locales of debug builds: accented English, and English mirrored right to left.
    open_in en-XA
    wait_for "\\[Šéé" 15 || fail "the network part in en-XA does not show the pseudo-locale's text"
    echo "ok: en-XA"
    open_in ar-XB
    # The title, pseudo-localized, is the first sign that the screen is open.
    for _ in $(seq 1 15); do
        dump_screen && set -- $(bounds_containing "$(title values)") && [ $# -eq 4 ] && break
        set --
        sleep 1
    done
    [ $# -eq 4 ] || fail "the network part in ar-XB shows no title"
    [ "$3" -gt $((width * 3 / 4)) ] || fail "the network part in ar-XB is not laid out right to left"
    echo "ok: ar-XB"
    adb shell cmd locale set-app-locales "$PKG" --locales "" >/dev/null
    open_in ""
else
    echo "skipped: per-app languages need Android 13"
    adb shell am start -W -n "$PKG/$NETWORK_SCREEN" >/dev/null
fi

# The tunnel, in English from here on.
if [ "$(adb shell getprop ro.build.version.sdk | tr -d '\r')" -ge 33 ]; then open_in en; fi
wait_for "$(string values status_off)" 15 || fail "the network part does not say it is off"
[ -z "$(vpn_line)" ] || fail "Android lists the network part's VPN before it was turned on"
if is_emulator; then allow_vpn "$PKG" || fail "Android did not take the VPN consent for $PKG"; fi
tap_now "$(string values turn_on)" || fail "no button to turn the network part on"
if ! wait_for "$(string values status_on)" 5; then
    echo "Waiting three minutes for the VPN request to be allowed on the phone's screen"
    wait_for "$(string values status_on)" 180 || fail "the network part did not say it is on"
fi
line=$(vpn_line)
[ -n "$line" ] || fail "Android lists no VPN of the network part's while the network part says it is on"
ranges=$(tunnel_uids)
[ -n "$ranges" ] || fail "Android's routing rules send no app into the tunnel"
# Whether a range of $ranges holds the UID $1.
inside() {
    local range
    for range in $ranges; do
        [ "${range%-*}" -le "$1" ] && [ "$1" -le "${range#*-}" ] && return 0
    done
    return 1
}
inside "$uid" || fail "the network part is not inside its own tunnel, which its engine needs: $(echo $ranges)"
inside 2000 || fail "adb's shell, an app like any other, is not inside the tunnel: $(echo $ranges)"
echo "ok: the tunnel is up, with every app inside it"

tap_now "$(string values turn_off)" || fail "no button to turn the network part off"
wait_for "$(string values status_off)" 10 || fail "the network part did not say it is off"
for _ in 1 2 3 4 5; do
    [ -z "$(vpn_line)" ] && break
    sleep 1
done
[ -z "$(vpn_line)" ] || fail "Android still lists the network part's VPN after it was turned off"
echo "ok: the tunnel is down"

# Every screen is protected (ADR 0040): Android lists the network part's window as secure; the setting allows
# screenshots, and leaving the screen protects it again at once, without waiting for the minute.
window_secure "$PKG" || fail "the network part's window is not protected from screenshots: $(window_attrs "$PKG" | tr -s ' ' | head -4 | tr '\n' ' ')"
if [ "$(adb shell getprop ro.build.version.sdk | tr -d '\r')" -ge 31 ]; then
    window_hides_overlays "$PKG" || fail "Android does not hide other apps' overlays over the network part's window"
fi
tap_text "$(string values screenshots_allow)" || fail "no button to allow screenshots"
within 10 window_unprotected "$PKG" || fail "the network part's window stayed protected 10 s after screenshots were allowed"
within 10 screen_has "$(string values screenshots_block)" || fail "the network part does not offer to block screenshots again"
adb shell input keyevent KEYCODE_HOME
for _ in 1 2 3 4 5; do window_secure "$PKG" && break; sleep 1; done
adb shell am start -W -n "$PKG/$NETWORK_SCREEN" >/dev/null
# Read once its window is listed again: from then on it must be protected, with no wait.
within 10 window_listed "$PKG" || fail "the network part's window was not listed 10 s after it came back"
window_secure "$PKG" || fail "the network part's window was not protected again after it left the screen"
echo "ok: the screen is protected, screenshots can be allowed, and leaving the screen protects it again"

adb shell pidof "$PKG:network" >/dev/null || fail "the network part is no longer running"
if adb logcat -d -b crash 2>/dev/null | grep -q "$PKG"; then
    fail "the network part crashed"
fi
echo "ok: no crash"
echo "== The network part's smoke test passed"
