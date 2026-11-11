#!/usr/bin/env bash
# Runs Watch's release build, as users get it, on an emulator: R8 has shrunk and renamed its code, and
# its Rust library is optimised. The other checks run the debug build, which has test entries; this one
# has none, so it turns Watch on from its screen. It checks that traffic passes the tunnel (a TCP request
# and a UDP echo to the test server), that Android names each flow's app, that the log gets records (the
# three calls the Rust library makes into Watch's code, which R8 renamed until 2026-11-10), and that
# Watch's memory stays within its budget, with its screen open and with the service alone.
#
# The release APK is signed here with a key made for this run and thrown away, never the project's.
# Emulator only: it uninstalls Watch, with its log, before and after.
#
#   scripts/verify-watch-release.sh [path/to/watch-release-unsigned.apk]
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
UNSIGNED="${1:-$ROOT/android/watch/build/outputs/apk/release/watch-release-unsigned.apk}"
PKG=org.visadahyu.datapavan.watch
HOST=10.0.2.2
PORT=${WATCH_TEST_PORT:-8790}
# Watch's memory budget, PSS in MB: about twice what it used on the Android 15 emulator on 2026-11-10
# (23 MB, with the screen open and with the service alone).
BUDGET_MB=${WATCH_MEMORY_BUDGET_MB:-48}
# shellcheck source=scripts/adb-ui.sh
. "$ROOT/scripts/adb-ui.sh"

is_emulator || {
    echo "verify-watch-release.sh runs on an emulator only: it uninstalls Watch and its log" >&2
    exit 2
}

WORK=$(mktemp -d)
SERVER=""
cleanup() {
    adb uninstall "$PKG" >/dev/null 2>&1 || true
    [ -z "$SERVER" ] || kill "$SERVER" 2>/dev/null || true
    rm -rf "$WORK"
}
trap cleanup EXIT

fail() {
    echo "RELEASE CHECK FAILED: $*" >&2
    adb logcat -d -b crash 2>/dev/null | tail -40 >&2 || true
    echo "How Watch's process last ended:" >&2
    adb shell dumpsys activity exit-info "$PKG" 2>/dev/null | tr -d '\r' | grep -E 'timestamp=|reason=' | head -6 >&2 || true
    echo "Watch's own account:" >&2
    adb shell dumpsys activity service "$PKG/.WatchVpnService" 2>/dev/null | tr -d '\r' | sed -n 's/^ *//p' | tail -10 >&2 || true
    exit 1
}

vpn_up() {
    local uid
    uid=$(adb shell cmd package list packages -U "$PKG" | tr -d '\r' | sed -n "s/^package:$PKG uid:\([0-9]*\)$/\1/p")
    local vpns
    vpns=$(adb shell dumpsys connectivity | tr -d '\r' | grep -E 'ni\{(VPN |\[type: VPN)' || true)
    [ -n "$uid" ] && grep -q "OwnerUid: $uid " <<<"$vpns"
}

# Watch's counters (Counters::snapshot in core/net/src/engine.rs), and its log's status line.
counters() {
    adb shell dumpsys activity service "$PKG/.WatchVpnService" | tr -d '\r' | sed -n 's/^ *counters //p'
}
log_line() {
    adb shell dumpsys activity service "$PKG/.WatchVpnService" | tr -d '\r' | sed -n 's/^ *log retention //p'
}

# Watch's memory, PSS in KB.
pss() {
    adb shell dumpsys meminfo "$PKG" | tr -d '\r' | sed -n 's/^ *TOTAL PSS: *\([0-9]*\).*/\1/p' | head -1
}

echo "== Watch's release build, on $(adb shell getprop ro.product.model | tr -d '\r'), Android $(adb shell getprop ro.build.version.release | tr -d '\r')"
[ -f "$UNSIGNED" ] || fail "no release APK at $UNSIGNED (./gradlew :watch:assembleRelease)"
tools=$(find "${ANDROID_HOME:-$ANDROID_SDK_ROOT}/build-tools" -maxdepth 1 -mindepth 1 -type d | sort -V | tail -1)
keytool -genkeypair -keystore "$WORK/throwaway.jks" -storepass throwaway -keypass throwaway -alias throwaway \
    -keyalg RSA -keysize 2048 -validity 1 -dname "CN=Watch release check" >/dev/null 2>&1
"$tools/zipalign" -f -p 16 "$UNSIGNED" "$WORK/aligned.apk"
"$tools/apksigner" sign --ks "$WORK/throwaway.jks" --ks-pass pass:throwaway --out "$WORK/watch-release.apk" "$WORK/aligned.apk" 2>/dev/null

python3 -I "$ROOT/scripts/watch-lab/server.py" "$PORT" &
SERVER=$!
adb uninstall "$PKG" >/dev/null 2>&1 || true
adb install "$WORK/watch-release.apk" >/dev/null
adb shell appops set "$PKG" ACTIVATE_VPN allow
[ "$(adb shell getprop ro.build.version.sdk | tr -d '\r')" -lt 37 ] || adb shell pm grant "$PKG" android.permission.ACCESS_LOCAL_NETWORK
# The button is found by its English text: Android 13 and later set Watch's language alone.
adb shell cmd locale set-app-locales "$PKG" --locales en-US >/dev/null 2>&1 || true
adb shell input keyevent KEYCODE_WAKEUP
adb shell wm dismiss-keyguard
# On CI the tap once did not start the tunnel, with no crash and the service never started (2026-11-11):
# a second tap, if the first did nothing.
for attempt in 1 2; do
    adb shell am start -W -n "$PKG/.MainActivity" >/dev/null
    sleep 2
    if ! tap_text "Turn on"; then
        [ "$attempt" = 2 ] || fail "no \"Turn on\" button on Watch's screen"
    fi
    for _ in $(seq 1 20); do vpn_up && break; sleep 1; done
    vpn_up && break
    [ "$attempt" = 2 ] || echo "  the tunnel was not up 20 s after \"Turn on\": once more"
done
vpn_up || fail "Watch's tunnel did not come up"
echo "ok: the release build's tunnel is up, turned on from its screen"

answer=$(timeout 15 adb shell "printf 'GET /ping HTTP/1.0\r\n\r\n' | nc -w 5 $HOST $PORT" | tr -d '\r' || true)
grep -q '^pong$' <<<"$answer" || fail "no answer over TCP through the release build"
answer=$(timeout 8 adb shell "echo watch-release | nc -u -q 2 $HOST $((PORT + 1))" | tr -d '\r' || true)
grep -q '^watch-release$' <<<"$answer" || fail "no UDP echo through the release build"
echo "ok: TCP and UDP pass the release build's tunnel"

# Flows whose app Android did not name: a few may be the system's own (one of eight on CI); the release
# build of 2026-11-09, whose engine could not ask, named none of 242.
read -r tcp udp _ _ unknown _ <<<"$(counters)"
[ $((unknown * 2)) -le $((tcp + udp)) ] || fail "Android named no app for $unknown of $((tcp + udp)) flows"
echo "ok: Android names the app of the release build's flows ($unknown of $((tcp + udp)) without one)"

# The engine hands the log its records about 30 s after a flow ends.
records=0
for _ in $(seq 1 30); do
    records=$(log_line | sed -n 's/.* records \([0-9]*\) .*/\1/p')
    [ "${records:-0}" -gt 0 ] && break
    sleep 3
done
[ "${records:-0}" -gt 0 ] || fail "the release build's log got no records: $(log_line)"
echo "ok: the release build's log gets records ($records)"

open_kb=$(pss)
adb shell input keyevent KEYCODE_BACK
sleep 15
alone_kb=$(pss)
echo "  memory: $((open_kb / 1024)) MB with the screen open, $((alone_kb / 1024)) MB with the service alone (budget $BUDGET_MB MB)"
[ "$open_kb" -le $((BUDGET_MB * 1024)) ] && [ "$alone_kb" -le $((BUDGET_MB * 1024)) ] ||
    fail "Watch's memory is over its budget of $BUDGET_MB MB"
echo "ok: Watch's memory is within its budget"

if adb logcat -d -b crash 2>/dev/null | grep -q "$PKG"; then
    fail "Watch crashed"
fi
echo "ok: no crash"
echo "== Watch's release build passed"
