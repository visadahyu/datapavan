#!/usr/bin/env bash
# W7's second emulator check (part 2, ADR 0035): the way in a user has, against the lab's two peers of the Linux
# kernel's WireGuard (Compose project datapavan-wglab, as scripts/verify-wireguard.sh has them). A configuration is
# imported through Android's own documents screen and another from a picture of its QR code through the photo
# picker, each confirmed on Watch's screen, which proposes the app the first names; the workload app goes through
# the first, is moved to the second through "Each app's way" and back, and reaches each peer from that
# configuration's address. Watch's process is killed and started again: the tunnels come back from the store. No
# file of Watch's holds a key or a configuration's text in plain form. The camera path: the phone's own camera takes
# a photo for Watch (the emulator's scene holds no QR code), which is read in the decoder's isolated process,
# refused, deleted, and leaves no copy in MediaStore; where the emulator has no camera, the cancel path alone is
# checked, and the run says so. A configuration removed with its apps waiting holds the app: nothing of it leaves
# directly. Last, the measure ADR 0035 asks of setUnlockedDeviceRequired: a key that needs an unlocked phone does
# not open while the phone is locked, Watch's own key does, and the time each takes.
#
# Skipped, with a line that says so, only where no lab peer can start (no Docker, Docker not answering, or no
# wireguard module), as verify-wireguard.sh is; CI's runner joins in W7's part 3.
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
    [ -z "$PIN" ] || adb shell locksettings clear --old "$PIN" >/dev/null 2>&1 || true
    adb shell "rm -f /sdcard/Download/wg-import-one.conf /sdcard/Pictures/wg-import-two-*.png" >/dev/null 2>&1 || true
    adb shell "content delete --uri content://media/external/file --where \"_display_name LIKE 'wg-import-%'\"" >/dev/null 2>&1 || true
    adb emu virtualscene-image wall >/dev/null 2>&1 || true
    adb shell am force-stop "$PKG" >/dev/null 2>&1 || true
    adb uninstall "$WORKLOAD" >/dev/null 2>&1 || true
    [ -z "$SERVER" ] || kill "$SERVER" 2>/dev/null || true
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
save_confirmation() {
    within 20 has_id tunnel-confirm || fail "the confirmation did not show"
    tap_tag tunnel-save || fail "the confirmation has no Save"
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

# 4. No file of Watch's holds a key or a configuration's text in plain form.
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

# 5. The camera path: the phone's own camera writes the photo to Watch's file, which is read, refused (the emulator's
# scene holds no QR code) and deleted, with no copy in MediaStore; with no camera, the cancel deletes it.
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
    has_id tunnel-confirm && tap_tag tunnel-cancel
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

echo "== WireGuard import checked on the emulator"
