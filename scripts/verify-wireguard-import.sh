#!/usr/bin/env bash
# W7's second emulator check (part 2, ADR 0035): the way in a user has, against the lab's two peers of the Linux
# kernel's WireGuard (Compose project datapavan-wglab, as scripts/verify-wireguard.sh has them). A configuration is
# imported through Android's own documents screen and another from a picture of its QR code through the photo
# picker, each confirmed on Watch's screen, which proposes the app the first names; the workload app goes through
# the first, is moved to the second through "Each app's way" and back, and reaches each peer from that
# configuration's address. The first confirmation survives the screen made anew for a rotation, a dark-mode switch
# and a larger font, with the name typed into it. Watch's process is killed and started again: the tunnels come back
# from the store. The workload app is installed again, so that it has a new UID, and still goes through its
# configuration, never directly. No file of Watch's holds a key or a configuration's text in plain form, which a
# search that finds the store's own word proves it can see. The camera path: the phone's own camera takes a photo
# for Watch with the virtual scene's wall showing the second configuration's QR code, which Watch reads in the
# decoder's isolated process; the scene's picture is small and seen at an angle, so either the confirmation shows,
# and is cancelled, or Watch says it found no code; the photo is deleted either way and leaves no copy in
# MediaStore. Where the emulator has no camera, the cancel path alone is checked, and the run says so. ADR 0047's
# profile, turned on through the debug builds' dump, puts the configurations under key B: Watch started again on a
# locked phone holds the app and asks for the unlock in one notification, and the tunnel comes back at the unlock. A
# configuration removed with its apps waiting holds the app: nothing of it leaves directly. Then the measure ADR
# 0035 asks of setUnlockedDeviceRequired: a key that needs an unlocked phone does not open while the phone is
# locked, Watch's own key does, and the time each takes. With the package receiver off, the app installed again is
# asked of Watch at its first packet and goes through its configuration. Last, key A deleted: Watch holds every app
# with one notification until the user lets them go on its screen.
#
# Skipped, with a line that says so, only where no lab peer can start (no Docker, Docker not answering, or no
# wireguard module), as verify-wireguard.sh is, and failed then too with WGLAB_REQUIRED=1, which CI sets (W7, part
# 3a).
#
#   scripts/verify-wireguard-import.sh [path/to/Datapavan-Advanced-debug.apk]
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APK="${1:-$ROOT/android/app/build-advanced/outputs/apk/debug/app-debug.apk}"
PKG=org.visadahyu.datapavan.advanced
WATCH_SCREEN=org.visadahyu.datapavan.watch.MainActivity
WORKLOAD=org.visadahyu.datapavan.workload
CAMERA_SHUTTER=com.android.camera2:id/shutter_button
CAMERA_DONE=com.android.camera2:id/done_button
# shellcheck source=scripts/adb-ui.sh
. "$ROOT/scripts/adb-ui.sh"

is_emulator || { echo "verify-wireguard-import.sh runs on an emulator only" >&2; exit 2; }
HOST=10.0.2.2
# shellcheck source=scripts/host-ports.sh
. "$ROOT/scripts/host-ports.sh"
PEER_DIR="$ROOT/spikes/wireguard-core/peer"
compose=(docker compose -f "$PEER_DIR/compose.yaml" -f "$PEER_DIR/compose.publish.yaml")
WORK="$(mktemp -d)"
SERVER=""
PIN=""

cleanup() {
    local status=$?
    [ -z "$PIN" ] || adb shell locksettings clear --old "$PIN" >/dev/null 2>&1 || true
    adb shell "rm -f /sdcard/Download/wg-import-one.conf /sdcard/Pictures/wg-import-two-*.png" >/dev/null 2>&1 || true
    adb shell "content delete --uri content://media/external/file --where \"_display_name LIKE 'wg-import-%'\"" >/dev/null 2>&1 || true
    adb emu virtualscene-image wall >/dev/null 2>&1 || true
    # Watch's data goes with the run: a route left waiting for a removed configuration would hold the workload app,
    # which the checks after this one install again, as it holds any app the user left so.
    adb shell pm clear "$PKG" >/dev/null 2>&1 || true
    adb uninstall "$WORKLOAD" >/dev/null 2>&1 || true
    [ -z "$SERVER" ] || kill "$SERVER" 2>/dev/null || true
    # The peers' logs, which CI keeps when a check fails (W7, part 3a).
    if [ "$status" != 0 ]; then
        mkdir -p "$ROOT/build/wglab"
        "${compose[@]}" logs --no-color --timestamps >"$ROOT/build/wglab/peers-$(basename "$0" .sh).log" 2>&1 || true
    fi
    "${compose[@]}" stop >/dev/null 2>&1 || true
    rm -rf "$WORK"
}
trap cleanup EXIT

dump() { adb shell dumpsys activity service "$PKG/org.visadahyu.datapavan.watch.WatchVpnService" "$@" | tr -d '\r'; }
workload_log() { adb logcat -d -s DatapavanWorkload | tr -d '\r' | sed -n 's/.*DatapavanWorkload: //p'; }
device() {
    local seconds=$1
    shift
    timeout "$seconds" adb shell "$@" 2>&1 | tr -d '\r' || true
}
in_peer() { local service=$1; shift; "${compose[@]}" exec -T "$service" "$@"; }
seen() { in_peer "$1" cat /run/wglab/seen 2>/dev/null || true; }
state_of() { sed -n "s/^ *tunnel $1 //p" <<<"$(dump)"; }
store_line() { grep -E "^ *tunnel-(slot|waiting) $1 " <<<"$(dump tunnel-store)" | sed 's/^ *//' || true; }
flows_of() {
    local count
    count=$(awk -v uid="$1" -v route="$2" '$1 == "flow-route" && $2 == uid && $3 == route { print $4 }' <<<"$(dump)")
    echo "${count:-0}"
}
# What the screen shows, the isolates around names and addresses dropped.
screen_text() { dump_screen >/dev/null 2>&1 || true; adb shell cat "$DUMP" 2>/dev/null | LC_ALL=C sed 's/\xe2\x81[\xa6-\xa9]//g'; }
fail() {
    echo "WIREGUARD IMPORT CHECK FAILED: $*" >&2
    echo "Watch's store, tunnels and flows' routes:" >&2
    grep -E '^ *(tunnel|flow-route)' <<<"$(dump tunnel-store)" >&2 || true
    echo "On screen:" >&2
    screen_text | grep -o 'text="[^"]\+"' | head -30 >&2 || true
    workload_log | tail -10 >&2 || true
    echo "The peers' clients (keys cut short):" >&2
    for service in peer peer2; do
        in_peer "$service" wg show wg0 dump 2>/dev/null | tail -n +2 | awk -v s="$service" '{print s, substr($1, 1, 8), $3, $4, $5, $6, $7}' >&2 || true
    done
    adb logcat -d -b crash 2>/dev/null | tail -30 >&2 || true
    exit 1
}
vpn_up() {
    local uid
    uid=$(adb shell cmd package list packages -U "$PKG" | tr -d '\r' | sed -n "s/^package:$PKG uid:\([0-9]*\)$/\1/p")
    [ -n "$uid" ] && grep -qE "OwnerUid: $uid " <<<"$(adb shell dumpsys connectivity | tr -d '\r')"
}
workload() {
    adb logcat -c
    adb shell am start -W -n "$WORKLOAD/.WorkActivity" "$@" >/dev/null
    for _ in $(seq 1 30); do
        grep -qx done <<<"$(workload_log)" && return 0
        sleep 1
    done
}
watch_screen() {
    adb shell input keyevent KEYCODE_WAKEUP
    adb shell am start -W -n "$PKG/$WATCH_SCREEN" --activity-clear-top >/dev/null
    sleep 1
    scroll_to_top
}
# Scrolls Watch's screen until the element whose resource-id is $1 shows, and taps it.
tap_tag() {
    for _ in $(seq 1 10); do
        has_id "$1" && { tap_dumped_id "$1"; return 0; }
        swipe_up
    done
    return 1
}
# Taps the first element whose content description starts with $1.
tap_desc_prefix() {
    local bounds
    dump_screen || return 1
    bounds=$(adb shell cat "$DUMP" | grep -o "content-desc=\"$1[^\"]*\"[^>]*bounds=\"[^\"]*\"" | head -1 | grep -o 'bounds="[^"]*"' | grep -o '[0-9]\+' | tr '\n' ' ')
    [ -n "$bounds" ] || return 1
    set -- $bounds
    adb shell input tap $(( ($1 + $3) / 2 )) $(( ($2 + $4) / 2 ))
}
# Whether the element whose resource-id is $1 is ticked.
ticked() { grep -o "<node[^>]*resource-id=\"$1\"[^>]*>" <<<"$(screen_text)" | grep -q 'checked="true"'; }
config() {
    # $1 key, $2 IPv4, $3 IPv6, $4 port on this computer, $5 the peer's public key, $6 more [Interface] lines
    printf '[Interface]\nPrivateKey = %s\nAddress = %s/32, %s/128\nDNS = 10.77.0.1\n%s\n[Peer]\nPublicKey = %s\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = %s:%s\n' \
        "$1" "$2" "$3" "${6:-}" "$5" "$HOST" "$4"
}
free_udp() {
    python3 -I -c 'import socket,sys
for p in range(int(sys.argv[1]), int(sys.argv[1]) + 200):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.bind(("127.0.0.1", p)); print(p); break
    except OSError: pass
    finally: s.close()' "$1"
}
sentinel_since() { tail -n +$((SENTINEL_MARK + 1)) "$WORK/sentinel.log"; }
# Whether the store's line for slot $1 matches the pattern $2; whether the engine's state of tunnel $1 has $3 at field $2.
store_has() { grep -qE "$2" <<<"$(store_line "$1")"; }
state_field() { [ "$(awk -v f="$2" '{print $f}' <<<"$(state_of "$1")")" = "$3" ]; }
capture_left() { adb shell run-as "$PKG" ls cache/qr-capture 2>/dev/null | tr -d '\r' || true; }
no_capture() { [ -z "$(capture_left)" ]; }
vpn_down() { ! vpn_up; }
confirmation_or_refusal() { screen_has "No QR code could be read" || has_id tunnel-confirm; }
images() { adb shell content query --uri content://media/external/images/media --projection _id 2>/dev/null | tr -d '\r' | grep -c '^Row' || true; }
# The confirmation's Save, once its screen shows.
# The confirmation's last button, Cancel, once on screen: Save, above it, is then clear of the navigation bar, under
# which an element at the screen's bottom edge lies, and which takes a tap there.
confirmation_end() {
    for _ in $(seq 1 15); do has_id tunnel-cancel && return 0; swipe_up; done
    return 1
}
save_confirmation() {
    within 20 has_id tunnel-confirm || fail "the confirmation did not show"
    confirmation_end && has_id tunnel-save || fail "the confirmation has no Save"
    tap_dumped_id tunnel-save
    within 10 gone_id tunnel-confirm || fail "the confirmation stayed after Save"
}

why_not=""
if ! command -v docker >/dev/null 2>&1; then
    why_not="no Docker"
elif ! docker info >/dev/null 2>&1; then
    why_not="Docker does not answer"
elif [ ! -d /sys/module/wireguard ]; then
    why_not="the wireguard module is not loaded"
fi
if [ -n "$why_not" ]; then
    # On CI the switch is on (WGLAB_REQUIRED=1, W7's part 3a): there a skip would pass without checking, so it fails.
    if [ "${WGLAB_REQUIRED:-}" = 1 ]; then
        echo "WIREGUARD CHECK FAILED: WGLAB_REQUIRED=1, and no WireGuard lab peer can start here ($why_not; Linux $(uname -r))" >&2
        exit 1
    fi
    echo "SKIPPED verify-wireguard-import.sh: no WireGuard lab peer can start here ($why_not); nothing of W7's import was checked on the emulator"
    [ -z "${GITHUB_ACTIONS:-}" ] || echo "::notice title=W7's import check skipped::$why_not: nothing of W7's import was checked on the emulator"
    exit 0
fi
# The QR code's picture is drawn with the ZXing jar the app is built with, from Gradle's cache, checked against the
# verification metadata's SHA-256: nothing is downloaded for it.
zxing_sum=$(grep -A2 '<artifact name="core-3.5.4.jar">' "$ROOT/android/gradle/verification-metadata.xml" | sed -n 's/.*sha256 value="\([0-9a-f]*\)".*/\1/p')
ZXING=""
for jar in $(find "${GRADLE_USER_HOME:-$HOME/.gradle}/caches/modules-2/files-2.1/com.google.zxing/core/3.5.4" -name core-3.5.4.jar 2>/dev/null); do
    [ "$(sha256sum "$jar" | cut -d' ' -f1)" = "$zxing_sum" ] && ZXING=$jar
done
[ -n "$ZXING" ] || { echo "WIREGUARD IMPORT CHECK FAILED: ZXing's jar is not in Gradle's cache with its recorded hash; build the app first" >&2; exit 1; }

export WGLAB_PORT WGLAB_PORT2
WGLAB_PORT=$(free_udp 51820)
WGLAB_PORT2=$(free_udp $((WGLAB_PORT + 1)))
settings=$("$ROOT/scripts/wglab.sh" --peers 2>"$WORK/peers.err") ||
    { cat "$WORK/peers.err" >&2; echo "WIREGUARD IMPORT CHECK FAILED: the lab's peers did not start" >&2; exit 1; }
while IFS= read -r line; do
    [[ $line == WGLAB_*=* ]] && export "${line%%=*}=${line#*=}"
done <<<"$settings"
echo "ok: the lab's two kernel WireGuard peers answer on this computer's loopback, ports $WGLAB_PORT and $WGLAB_PORT2"

host_server --sentinel "$WORK/sentinel.log" || exit 1
"$ROOT/scripts/workload-app/build.sh" >/dev/null
adb install -r "$APK" >/dev/null
adb shell pm clear "$PKG" >/dev/null
adb uninstall "$WORKLOAD" >/dev/null 2>&1 || true
adb install "$ROOT/build/workload-app/workload-app.apk" >/dev/null
WORKLOAD_UID=$(adb shell cmd package list packages -U "$WORKLOAD" | tr -d '\r' | sed -n "s/^package:$WORKLOAD uid:\([0-9]*\)$/\1/p")
[ -n "$WORKLOAD_UID" ] || fail "the workload app did not install"
allow_vpn "$PKG" || fail "Android did not take the VPN consent for $PKG"
[ "$(adb shell getprop ro.build.version.sdk | tr -d '\r')" -lt 37 ] || adb shell pm grant "$PKG" android.permission.ACCESS_LOCAL_NETWORK
adb shell cmd locale set-app-locales "$PKG" --locales en >/dev/null 2>&1 || true
adb shell am force-stop "$PKG"
adb shell am start -W -n "$PKG/$WATCH_SCREEN" --ez start true >/dev/null
within 20 vpn_up || fail "Watch's tunnel did not come up"

# 1. A file, through Android's documents screen: the confirmation says what it does and proposes the app it names.
config "$WGLAB_PLAIN" 10.77.0.2 fd77::2 "$WGLAB_PORT" "$WGLAB_PEER_PUBLIC" "IncludedApplications = $WORKLOAD" >"$WORK/wg-import-one.conf"
adb push "$WORK/wg-import-one.conf" /sdcard/Download/wg-import-one.conf >/dev/null
adb shell am broadcast -a android.intent.action.MEDIA_SCANNER_SCAN_FILE -d file:///sdcard/Download/wg-import-one.conf >/dev/null
rm -f "$WORK/wg-import-one.conf"
watch_screen
tap_tag tunnel-add-file || fail "Watch's screen has no way to add a file"
within 20 screen_has "wg-import-one.conf" || fail "the documents screen does not show the configuration's file"
tap_text "wg-import-one.conf" || fail "the configuration's file could not be picked"
within 20 has_id tunnel-confirm || fail "no confirmation after the file was picked"
shown=$(screen_text)
grep -q "Server: $HOST, port $WGLAB_PORT\." <<<"$shown" || fail "the confirmation does not name the server"
grep -q "10.77.0.2/32, fd77::2/128" <<<"$shown" || fail "the confirmation does not name the addresses"
grep -q 'text="wg-import-one"' <<<"$shown" || fail "the configuration's name is not the file's"
! grep -qF "$WGLAB_PLAIN" <<<"$shown" || fail "the confirmation shows the private key"
for _ in $(seq 1 8); do has_id "tunnel-app-$WORKLOAD" && break; swipe_up; done
ticked "tunnel-app-$WORKLOAD" || fail "the app the file names is not proposed"
screen_has "Its way now: Directly" || fail "the proposed app's way now is not shown"
# The confirmation survives the screen made anew (review M1 of the fix round): a name typed into it, then a rotation,
# dark mode and a larger font, each of which makes Watch's screen anew; the confirmation, the name and the tick stay.
scroll_to_top
tap_tag tunnel-name || fail "the confirmation has no name field"
adb shell input keyevent KEYCODE_MOVE_END
adb shell input text "-kept"
# The keyboard goes, Back only while it shows: Back without it cancels the confirmation. A screen made anew gives the
# name its focus, and the keyboard, back; a swipe over it would type.
keyboard_away() {
    grep -q "mInputShown=true" <<<"$(adb shell dumpsys input_method | tr -d '\r')" || return 0
    adb shell input keyevent KEYCODE_BACK
    sleep 1
}
keyboard_away
within 5 screen_has 'wg-import-one-kept' || fail "the name typed into the confirmation does not show"
# The confirmation and its name; with "ticked", the proposed app's tick too, which takes scrolling, and swipe_up's
# lengths are the portrait screen's, so not in landscape.
recreated() {
    within 20 has_id tunnel-confirm || return 1
    keyboard_away
    screen_has 'wg-import-one-kept' || return 1
    [ "${1:-}" = ticked ] || return 0
    for _ in $(seq 1 8); do has_id "tunnel-app-$WORKLOAD" && break; swipe_up; done
    ticked "tunnel-app-$WORKLOAD"
}
rotation=$(adb shell settings get system user_rotation | tr -d '\r')
auto_rotation=$(adb shell settings get system accelerometer_rotation | tr -d '\r')
font=$(adb shell settings get system font_scale | tr -d '\r')
night=$(adb shell cmd uimode night | tr -d '\r' | sed -n 's/^Night mode: //p')
restore_display() {
    adb shell settings put system user_rotation "${rotation/null/0}" >/dev/null 2>&1 || true
    adb shell settings put system accelerometer_rotation "${auto_rotation/null/0}" >/dev/null 2>&1 || true
    adb shell settings put system font_scale "${font/null/1.0}" >/dev/null 2>&1 || true
    adb shell cmd uimode night "${night:-no}" >/dev/null 2>&1 || true
}
adb shell settings put system accelerometer_rotation 0
adb shell settings put system user_rotation 1
sleep 2
recreated || { restore_display; fail "the confirmation or its name did not survive a rotation to landscape"; }
adb shell settings put system user_rotation 0
sleep 2
recreated ticked || { restore_display; fail "the confirmation, its name or its tick did not survive a rotation back"; }
adb shell cmd uimode night yes >/dev/null
sleep 2
recreated ticked || { restore_display; fail "the confirmation, its name or its tick did not survive dark mode"; }
adb shell settings put system font_scale 1.3
sleep 2
recreated ticked || { restore_display; fail "the confirmation, its name or its tick did not survive a larger font"; }
restore_display
sleep 2
recreated ticked || fail "the confirmation did not survive the display put back"
echo "ok: the confirmation, the name typed into it and its tick survived a rotation, dark mode and a larger font"
save_confirmation
within 15 store_has 1 "^tunnel-slot 1 default - name known set routes 1$" ||
    fail "the first configuration is not kept and set with its app: $(store_line 1)"
workload --es name lab.test --es tcp 10.77.0.1:80 --es udp 10.77.0.1:7
lines=$(workload_log)
grep -qx "resolved lab.test 10.77.0.1" <<<"$lines" || fail "the lookup did not go to the peer's DNS server"
grep -qx "tcp 10.77.0.1:80 pong" <<<"$lines" || fail "TCP did not reach the peer"
grep -qx "udp 10.77.0.1:7 echo" <<<"$lines" || fail "UDP did not reach the peer"
grep -qE "^http 10\.77\.0\.2 " <<<"$(seen peer)" || fail "the peer saw nothing from the configuration's address 10.77.0.2"
[ "$(flows_of "$WORKLOAD_UID" direct)" = 0 ] || fail "the routed app has flows that went directly"
echo "ok: a file picked on the documents screen, confirmed with the app it named, and that app's traffic through it to the peer"

# 2. A picture of a QR code, through the photo picker, in the decoder's isolated process.
# An MTU of this run's own, which the confirmation shows, tells this run's picture from any other the picker holds.
MTU=$((1300 + RANDOM % 150))
config "$WGLAB_SECOND" 10.77.0.4 fd77::4 "$WGLAB_PORT2" "$WGLAB_PEER2_PUBLIC" "MTU = $MTU" >"$WORK/two.conf"
# A name of this run's own: the picker keeps what it read of a path, also after the file there was replaced.
PICTURE=wg-import-two-$RANDOM.png
java -cp "$ZXING" "$ROOT/scripts/qr-picture/QrPicture.java" "$WORK/two.conf" "$WORK/$PICTURE" 6
rm -f "$WORK/two.conf"
adb push "$WORK/$PICTURE" "/sdcard/Pictures/$PICTURE" >/dev/null
adb shell am broadcast -a android.intent.action.MEDIA_SCANNER_SCAN_FILE -d "file:///sdcard/Pictures/$PICTURE" >/dev/null
adb logcat -c
watch_screen
tap_tag tunnel-add-picture || fail "Watch's screen has no way to choose a picture"
# The picker names each picture by when it was taken, which for a pushed file is its time: this run's is the one
# taken at its file's time, whatever else the picker holds.
taken=$(adb shell stat -c %Y "/sdcard/Pictures/$PICTURE" | tr -d '\r')
zone=$(adb shell getprop persist.sys.timezone | tr -d '\r')
at=$(TZ="${zone:-UTC}" date -d "@$taken" +%-I:%M:%S)
within 20 tap_desc_prefix "Photo taken on [^\"]*$at" || fail "the photo picker shows no picture taken at $at"
within 30 has_id tunnel-confirm || fail "no confirmation after the picture was picked"
shown=$(screen_text)
grep -q "10.77.0.4/32, fd77::4/128" <<<"$shown" && grep -q "Server: $HOST, port $WGLAB_PORT2\." <<<"$shown" &&
    grep -q "Largest packet inside it: $MTU bytes\." <<<"$shown" ||
    fail "the picture's configuration is not this run's: the picker gave another picture"
grep -qE "Start proc [0-9]+:$PKG:qr.*/u[0-9]+i[0-9]+ for service" <<<"$(adb logcat -d | tr -d '\r')" ||
    fail "the QR decoder did not run in an isolated process"
save_confirmation
within 15 store_has 2 "^tunnel-slot 2 other - name known set routes 0$" ||
    fail "the second configuration is not kept and set: $(store_line 2)"
echo "ok: a picture of a QR code, read in an isolated process, confirmed and set"

# Each app's way: the workload app moves to the second configuration and back.
# The list and the app's choices stay open across visits of the screen, as the user left them.
route_to() {
    watch_screen
    tap_tag "route-choice-$WORKLOAD-$1" && return 0
    watch_screen
    if ! tap_tag "route-$WORKLOAD"; then
        watch_screen
        tap_tag routes-open || fail "no list of each app's way"
        tap_tag "route-$WORKLOAD" || fail "the workload app is not in the list of ways"
    fi
    tap_tag "route-choice-$WORKLOAD-$1" || fail "no way $1 for the workload app"
}
second_before=$(grep -c "^udp-echo 10.77.0.4 " <<<"$(seen peer2)" || true)
first_before=$(grep -c "^udp-echo 10.77.0.2 " <<<"$(seen peer)" || true)
route_to tunnel-2
within 10 store_has 2 "routes 1$" || fail "the app's way did not move to the second configuration"
# The second tunnel's first handshake starts with this datagram; a lost initiation is sent again after five seconds
# (REKEY_TIMEOUT), past the workload's wait, so the datagram is sent up to three times, and the run says how many.
tries=0
for tries in 1 2 3; do
    workload --es udp 10.77.0.1:7
    grep -qx "udp 10.77.0.1:7 echo" <<<"$(workload_log)" && break
    sleep 3
done
grep -qx "udp 10.77.0.1:7 echo" <<<"$(workload_log)" || fail "UDP did not pass through the second configuration"
[ "$tries" = 1 ] || echo "note: the second configuration's first handshake answered at the workload's try $tries"
[ "$(grep -c "^udp-echo 10.77.0.4 " <<<"$(seen peer2)" || true)" -gt "$second_before" ] || fail "the second peer saw no echo from 10.77.0.4"
[ "$(grep -c "^udp-echo 10.77.0.2 " <<<"$(seen peer)" || true)" = "$first_before" ] || fail "the first peer still saw the app"
route_to tunnel-1
within 10 store_has 1 "routes 1$" || fail "the app's way did not move back to the first configuration"
echo "ok: the app moved to the second configuration under Each app's way, reached the second peer from 10.77.0.4, and moved back"

# 3. Watch's process killed and started again: the tunnels come back from the store, and the app through its own.
pid=$(adb shell pidof "$PKG:watch" | tr -d '\r')
[ -n "$pid" ] || fail "no process of Watch's"
adb shell run-as "$PKG" kill -9 "$pid" || fail "Watch's process could not be killed"
within 20 vpn_down || fail "Watch's VPN stayed up with its process killed"
adb shell am start -S -W -n "$PKG/$WATCH_SCREEN" --ez start true >/dev/null
within 20 vpn_up || fail "Watch's tunnel did not come up again"
within 10 store_has 1 " set routes 1$" && within 10 store_has 2 " set " ||
    fail "the configurations did not come back from the store: $(store_line 1); $(store_line 2)"
workload --es tcp 10.77.0.1:80
grep -qx "tcp 10.77.0.1:80 pong" <<<"$(workload_log)" || fail "after the restart the app's TCP did not reach the peer"
echo "ok: Watch's process killed and started again, the configurations came back from the store and the app went through again"

# 3b. The workload app installed again (review M1 of the fix round): Android gives it a new UID, and Watch, which routes
# by UID, hands the engine its route again when the app comes, so that it goes through its configuration, never its
# other way.
adb uninstall "$WORKLOAD" >/dev/null
adb install "$ROOT/build/workload-app/workload-app.apk" >/dev/null
again=$(adb shell cmd package list packages -U "$WORKLOAD" | tr -d '\r' | sed -n "s/^package:$WORKLOAD uid:\([0-9]*\)$/\1/p")
[ -n "$again" ] || fail "the workload app did not install again"
[ "$again" != "$WORKLOAD_UID" ] || fail "Android gave the workload app its old UID $again again: this step proves nothing"
engine_route() { grep -qE "^ *tunnel-engine-route $1 $2$" <<<"$(dump tunnel-store)"; }
within 10 engine_route "$again" 1 ||
    fail "the engine has no route for the app's new UID $again: $(grep tunnel-engine-route <<<"$(dump tunnel-store)" | tr '\n' ' ')"
! engine_route "$WORKLOAD_UID" 1 || fail "the engine still routes the app's old UID $WORKLOAD_UID"
WORKLOAD_UID=$again
peer_before=$(grep -c "^http 10\.77\.0\.2 " <<<"$(seen peer)" || true)
workload --es tcp 10.77.0.1:80
grep -qx "tcp 10.77.0.1:80 pong" <<<"$(workload_log)" || fail "installed again, the app's TCP did not reach the peer"
[ "$(grep -c "^http 10\.77\.0\.2 " <<<"$(seen peer)" || true)" -gt "$peer_before" ] || fail "installed again, the peer saw nothing from 10.77.0.2"
[ "$(flows_of "$WORKLOAD_UID" direct)" = 0 ] || fail "installed again, the app has flows that went directly"
echo "ok: the workload app installed again had a new UID ($WORKLOAD_UID), which Watch routed at once, and went through its configuration to the peer"

# 3c. The same with the package receiver off (the maintainer's word of 2026-11-20): no hand-over names the new UID,
# and the engine, at the app's first packet, asks Watch where it goes and holds the flow until Watch answers its
# configuration; nothing of it goes on a default way meanwhile.
grep -qE "^ *packages-follow off$" <<<"$(dump packages-follow off)" || fail "the package receiver could not be turned off"
adb uninstall "$WORKLOAD" >/dev/null
adb install "$ROOT/build/workload-app/workload-app.apk" >/dev/null
asked=$(adb shell cmd package list packages -U "$WORKLOAD" | tr -d '\r' | sed -n "s/^package:$WORKLOAD uid:\([0-9]*\)$/\1/p")
[ -n "$asked" ] && [ "$asked" != "$WORKLOAD_UID" ] || fail "the workload app did not get a new UID: $asked"
sleep 2
! engine_route "$asked" 1 || fail "with the receiver off the engine was handed the new UID's route: this step proves nothing"
peer_before=$(grep -c "^http 10\.77\.0\.2 " <<<"$(seen peer)" || true)
workload --es tcp 10.77.0.1:80
grep -qx "tcp 10.77.0.1:80 pong" <<<"$(workload_log)" || fail "with the receiver off, the app installed again did not reach the peer"
[ "$(grep -c "^http 10\.77\.0\.2 " <<<"$(seen peer)" || true)" -gt "$peer_before" ] || fail "with the receiver off, the peer saw nothing from 10.77.0.2"
[ "$(flows_of "$asked" direct)" = 0 ] || fail "with the receiver off, the app installed again had flows that went directly"
grep -qE "^ *tunnel-asked $asked tunnel:1$" <<<"$(dump tunnel-store)" || fail "the engine did not ask Watch where the new UID goes"
! engine_route "$asked" 1 || fail "the engine was handed the new UID's route meanwhile: this step proves nothing"
grep -qE "^ *packages-follow on$" <<<"$(dump packages-follow on)" || fail "the package receiver could not be turned on again"
WORKLOAD_UID=$asked
echo "ok: with the receiver off, the app installed again (UID $WORKLOAD_UID) was asked of Watch at its first packet and went through its configuration, none of it directly"

# 4. No file of Watch's holds a key or a configuration's text in plain form, nor, in the store, an app it routes: the
# state is wrapped under key A. The search must first find a file of its own among Watch's (review m4 of the fix
# round): a search that cannot read Watch's files finds nothing either.
adb shell run-as "$PKG" sh -c "'mkdir -p no_backup/tunnels-control && echo datapavan-search-control > no_backup/tunnels-control/file'"
control=$(adb shell run-as "$PKG" sh -c "'grep -rlF -- datapavan-search-control . 2>/dev/null'" | tr -d '\r' || true)
adb shell run-as "$PKG" rm -r no_backup/tunnels-control
grep -q "no_backup/tunnels-control/file" <<<"$control" || fail "the search for keys cannot see a file it put among Watch's: it would prove nothing"
for plain in "$WORKLOAD" "route " "order "; do
    found=$(adb shell run-as "$PKG" sh -c "'grep -rlF -- \"$plain\" no_backup/tunnels 2>/dev/null'" | tr -d '\r' || true)
    [ -z "$found" ] || fail "the store holds what decides a route in plain form ($plain): $found"
done
for secret in "$WGLAB_PLAIN" "$WGLAB_SECOND" "PrivateKey" "Endpoint = $HOST"; do
    found=$(adb shell run-as "$PKG" sh -c "'grep -rlF -- \"$secret\" . 2>/dev/null'" | tr -d '\r' || true)
    [ -z "$found" ] || fail "Watch's files hold a key or a configuration in plain form: $found"
done
no_capture || fail "a photo is left in Watch's cache: $(capture_left)"
shown_log="$(dump tunnel-store)
$(adb logcat -d | tr -d '\r')"
for secret in "$WGLAB_PLAIN" "$WGLAB_SECOND" "$HOST:$WGLAB_PORT" "$HOST:$WGLAB_PORT2"; do
    ! grep -qF -- "$secret" <<<"$shown_log" || fail "Watch's dump or the device's log shows a key or the endpoint"
done
echo "ok: no file of Watch's, its dump or the device's log holds a key or a configuration's text"

# 5. The camera path: the phone's own camera writes the photo to Watch's file, which is read in the isolated decoder and
# deleted, with no copy in MediaStore. The scene's wall shows the second configuration's QR code, small and at an
# angle, so Watch either shows its confirmation, which is cancelled, or says no code could be read; with no camera,
# the cancel deletes the file.
before=$(images)
adb emu virtualscene-image wall "$WORK/$PICTURE" >/dev/null 2>&1 || true
watch_screen
tap_tag tunnel-add-camera || fail "Watch's screen has no way to take a photo"
if within 15 has_id "$CAMERA_SHUTTER"; then
    tap_dumped_id "$CAMERA_SHUTTER"
    within 15 has_id "$CAMERA_DONE" || fail "the camera did not offer its photo"
    [ -n "$(capture_left)" ] || fail "no file of Watch's waits for the camera's photo"
    tap_dumped_id "$CAMERA_DONE"
    within 30 confirmation_or_refusal || fail "Watch did not read the camera's photo"
    if has_id tunnel-confirm; then
        # Cancel at the screen's bottom edge would lie under the navigation bar: one swipe more lifts it.
        confirmation_end && swipe_up && has_id tunnel-cancel && tap_dumped_id tunnel-cancel
    fi
    echo "ok: the phone's camera wrote the photo to Watch's own file, which was read in the isolated decoder"
else
    echo "SKIPPED the camera's photo: this emulator has no camera (CI's and the shards' run with -camera-back none); the cancel path alone is checked"
    adb shell input keyevent KEYCODE_BACK
    sleep 2
    # The camera app, with no camera, stops; Android hands Watch its answer when Watch's screen is in front again
    # (an emulator of Android 15 showed the launcher instead), and only then is the photo's file deleted.
    watch_screen
fi
within 10 no_capture || fail "the camera's photo was not deleted: $(capture_left)"
[ "$(images)" = "$before" ] || fail "the camera left a copy in MediaStore ($before images before, $(images) after)"
echo "ok: the photo was deleted, and MediaStore holds no copy ($before images before and after)"

# 5b. ADR 0047's profile, the maintainer's decision of 2026-11-20 (ADR 0035): the configurations go under key B, which
# opens only on an unlocked phone, and what decides the routes stays under key A. Watch started again on a locked
# phone holds the routed app, which sends nothing directly, and one notification, naming no configuration, asks for
# the unlock; at the unlock the tunnel comes back and the notification goes. W9 wires the profile's switch; the
# debug builds' dump turns it on and off here.
[ "$(adb shell getprop ro.build.version.sdk | tr -d '\r')" -lt 33 ] || adb shell pm grant "$PKG" android.permission.POST_NOTIFICATIONS
moved=$(sed -n 's/^ *tunnel-profile on moved //p' <<<"$(dump tunnel-profile on)")
[ "$moved" = "2 unmoved 0" ] || fail "the profile did not move both configurations under key B: ${moved:-nothing said}"
keys=$(grep -E '^ *tunnel-key-of ' <<<"$(dump tunnel-store)" | sed 's/^ *//' | tr '\n' ' ')
[ "$keys" = "tunnel-key-of 1 b tunnel-key-of 2 b " ] || fail "the configurations are not under key B: $keys"
PIN=4927
adb shell locksettings set-pin "$PIN" >/dev/null
adb shell input keyevent KEYCODE_SLEEP
sleep 3
pid=$(adb shell pidof "$PKG:watch" | tr -d '\r')
[ -n "$pid" ] || fail "no process of Watch's"
adb shell run-as "$PKG" kill -9 "$pid" || fail "Watch's process could not be killed"
within 20 vpn_down || fail "Watch's VPN stayed up with its process killed"
adb shell am start -S -W -n "$PKG/$WATCH_SCREEN" --ez start true >/dev/null
within 20 vpn_up || fail "Watch's tunnel did not come up on the locked phone"
within 10 store_has 1 "name locked unset routes 1$" ||
    fail "on the locked phone the first configuration is not held unset with its app: $(store_line 1)"
within 10 state_field 1 8 0 || fail "the engine does not hold the app for the configuration it cannot open: $(state_of 1)"
notice() { sed -n 's/^ *tunnel-profile on notice //p' <<<"$(dump tunnel-store)"; }
notice_is() { [ "$(notice)" = "$1" ]; }
within 10 notice_is shown || fail "no notification asks for the unlock: $(notice)"
record=$(adb shell dumpsys notification --noredact | tr -d '\r' | grep -A30 "NotificationRecord.*pkg=$PKG.*id=7201" || true)
grep -qF "Unlock your phone to connect again" <<<"$record" || fail "the notification does not say to unlock"
for word in wg-import "WireGuard" "$HOST" 10.77.0; do
    ! grep -qF -- "$word" <<<"$record" || fail "the notification names a configuration or a server ($word)"
done
SENTINEL_MARK=$(wc -l <"$WORK/sentinel.log")
direct_before=$(flows_of "$WORKLOAD_UID" direct)
workload --es tcp "$HOST:$((PORT + 3))" --es udp "$HOST:$((PORT + 3))"
sleep 3
[ -z "$(sentinel_since)" ] || fail "on the locked phone the app whose configuration waits reached this computer directly"
[ "$(flows_of "$WORKLOAD_UID" direct)" = "$direct_before" ] || fail "on the locked phone the waiting app has flows that went directly"
grep -qx done <<<"$(workload_log)" || fail "the workload app did not run on the locked phone: the step above proves nothing"
adb shell input keyevent KEYCODE_WAKEUP
adb shell wm dismiss-keyguard >/dev/null 2>&1 || true
sleep 1
adb shell input text "$PIN"
adb shell input keyevent KEYCODE_ENTER
within 20 store_has 1 "name known set routes 1$" || fail "after the unlock the first configuration was not set: $(store_line 1)"
within 10 notice_is none || fail "the notification stayed after the unlock: $(notice)"
workload --es tcp 10.77.0.1:80
grep -qx "tcp 10.77.0.1:80 pong" <<<"$(workload_log)" || fail "after the unlock the app's TCP did not reach the peer"
moved=$(sed -n 's/^ *tunnel-profile off moved //p' <<<"$(dump tunnel-profile off)")
[ "$moved" = "2 unmoved 0" ] || fail "the profile turned off did not move both configurations back under key A: ${moved:-nothing said}"
adb shell locksettings clear --old "$PIN" >/dev/null && PIN=""
echo "ok: under key B, Watch started again on the locked phone held the app, which sent nothing directly, and asked for the unlock in one notification naming no configuration; at the unlock the tunnel came back and the notification went"

# 6. A configuration removed with its apps waiting holds the app: nothing of it leaves directly.
watch_screen
tap_tag tunnel-remove-1 || fail "no way to remove the first configuration"
within 10 has_id tunnel-remove-wait || fail "the removal does not ask what its apps do"
tap_dumped_id tunnel-remove-wait
tap_id tunnel-remove-confirm || fail "the removal could not be confirmed"
within 10 store_has 1 "^tunnel-waiting 1 routes 1$" || fail "the removed configuration's app does not wait: $(store_line 1)"
within 10 state_field 1 8 0 || fail "the engine does not hold the app for the removed configuration: $(state_of 1)"
SENTINEL_MARK=$(wc -l <"$WORK/sentinel.log")
direct_before=$(flows_of "$WORKLOAD_UID" direct)
workload --es tcp "$HOST:$((PORT + 3))" --es udp "$HOST:$((PORT + 3))"
sleep 3
[ -z "$(sentinel_since)" ] || fail "with its configuration removed, the waiting app reached this computer directly"
[ "$(flows_of "$WORKLOAD_UID" direct)" = "$direct_before" ] || fail "with its configuration removed, the app has flows that went directly"
device 10 "echo control | toybox nc -w 4 $HOST $((PORT + 3))" >/dev/null
grep -q '^tcp$' <<<"$(sentinel_since)" || fail "the sentinel did not see the control's direct connection: the step above proves nothing"
echo "ok: removed with its apps waiting, the configuration's app sent nothing out directly; the control's direct connection reached the sentinel"

# 7. The measure of setUnlockedDeviceRequired (ADR 0035, W7, part 2): a key that needs an unlocked phone, and Watch's.
probe() { sed -n "s/^ *tunnel-key-probe //p" <<<"$(dump tunnel-key-probe "$1")"; }
made=$(probe make)
opened=$(sed -n 's/^ *tunnel-opened 2 //p' <<<"$(dump tunnel-key-time)")
PIN=4927
adb shell locksettings set-pin "$PIN" >/dev/null
adb shell input keyevent KEYCODE_SLEEP
sleep 3
locked=$(probe open)
own_locked=$(sed -n 's/^ *tunnel-opened 2 //p' <<<"$(dump tunnel-key-time)")
adb shell input keyevent KEYCODE_WAKEUP
adb shell wm dismiss-keyguard >/dev/null 2>&1 || true
sleep 1
adb shell input text "$PIN"
adb shell input keyevent KEYCODE_ENTER
sleep 2
unlocked=$(probe open)
probe clear >/dev/null
adb shell locksettings clear --old "$PIN" >/dev/null && PIN=""
echo "measure: a key that needs an unlocked phone: $made; locked: $locked; unlocked again: $unlocked"
echo "measure: Watch's own key opens a configuration in ${opened:-?} ms unlocked, ${own_locked:-?} ms locked"
[[ $locked == "open locked "* ]] || fail "a key that needs an unlocked phone opened while it was locked: $locked"
[[ $unlocked == "open ok "* ]] || fail "a key that needs an unlocked phone did not open once it was unlocked: $unlocked"
[ -n "$own_locked" ] || fail "Watch's own key did not open a configuration while the phone was locked"

# 8. Key A lost for good (the maintainer's word of 2026-11-20), deleted through the debug dump as a Keystore reset
# would: the marker says the store held routes (step 6 left the app waiting), so Watch started again holds every app,
# sends nothing directly, and shows one notification, naming no configuration, that opens its screen; there the
# user lets the apps go their way, which forgets the store, and the app goes directly again.
grep -qE "^ *tunnel-key-deleted a$" <<<"$(dump tunnel-key-delete a)" || fail "key A could not be deleted"
pid=$(adb shell pidof "$PKG:watch" | tr -d '\r')
[ -n "$pid" ] || fail "no process of Watch's"
adb shell run-as "$PKG" kill -9 "$pid" || fail "Watch's process could not be killed"
within 20 vpn_down || fail "Watch's VPN stayed up with its process killed"
adb shell am start -S -W -n "$PKG/$WATCH_SCREEN" --ez start true >/dev/null
within 20 vpn_up || fail "Watch's tunnel did not come up with key A gone"
lost_state() { grep -qE "^ *tunnel-state lost$" <<<"$(dump tunnel-store)"; }
lost_notice() { [ "$(sed -n 's/^ *tunnel-lost notice //p' <<<"$(dump tunnel-store)")" = "$1" ]; }
within 10 lost_state || fail "with key A gone the store's state is not lost: $(dump tunnel-store | grep -E 'tunnel-(state|slot)' | tr '\n' ' ')"
within 10 lost_notice shown || fail "no notification says Watch holds the apps"
record=$(adb shell dumpsys notification --noredact | tr -d '\r' | grep -A30 "NotificationRecord.*pkg=$PKG.*id=7202" || true)
grep -qF "Watch is holding your apps" <<<"$record" || fail "the notification does not say Watch holds the apps"
for word in wg-import "WireGuard" "$HOST" 10.77.0; do
    ! grep -qF -- "$word" <<<"$record" || fail "the notification names a configuration or a server ($word)"
done
SENTINEL_MARK=$(wc -l <"$WORK/sentinel.log")
direct_before=$(flows_of "$WORKLOAD_UID" direct)
workload --es tcp "$HOST:$((PORT + 3))" --es udp "$HOST:$((PORT + 3))"
sleep 3
[ -z "$(sentinel_since)" ] || fail "with key A gone, an app reached this computer directly"
[ "$(flows_of "$WORKLOAD_UID" direct)" = "$direct_before" ] || fail "with key A gone, the app has flows that went directly"
grep -qx done <<<"$(workload_log)" || fail "the workload app did not run: the step above proves nothing"
watch_screen
tap_tag tunnel-lost-let-go || fail "Watch's screen does not offer to let the apps go their way"
within 10 lost_notice none || fail "the notification stayed after the choice"
lost_state && fail "the store was not forgotten after the choice"
SENTINEL_MARK=$(wc -l <"$WORK/sentinel.log")
workload --es tcp "$HOST:$((PORT + 3))"
sentinel_saw_tcp() { grep -q '^tcp$' <<<"$(sentinel_since)"; }
within 10 sentinel_saw_tcp || fail "after the choice the app did not go its way: nothing reached the sentinel directly"
echo "ok: with key A gone and the marker present, Watch held every app with one notification naming no configuration; let go on its screen, the app went its way"

echo "== WireGuard import checked on the emulator"
