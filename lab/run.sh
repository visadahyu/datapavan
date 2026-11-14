#!/usr/bin/env bash
# Runs one behaviour of the lab's probe of Android's platform gaps (ADR 0048) on a fresh emulator, and
# writes its raw output and the row it gives. One command per row:
#
#   lab/run.sh <behaviour> <api> [--trials N] [--parts LIST] [--cores LIST] [--out DIR]
#
#   behaviour  vpn-seen, appops-closed, proc-net, loopback, indicators, carried-by-system, short-lived
#              or webview (ADR 0048, decision 2)
#   api        29, 30, 31, 34, 35, 36 or 37: the system image of that version named below. An image that is
#              not installed is named and the run stops: this script downloads nothing.
#   --trials   trials of a timing behaviour (short-lived, the resolver's part of carried-by-system);
#              at least 100, the default
#   --parts    carried-by-system only: some of its parts, comma-separated: download, tab, push, resolver
#              (default all; push is not run, and its row says why)
#   --cores    the host's threads the emulator is pinned to with taskset (default 16-23)
#   --out      where the raw output goes (default docs/platform-gaps/runs/<date>-<behaviour>-api<api>)
#
# It creates an AVD of its own (under build/gaps-avd, apart from any other), boots it with -no-snapshot
# -wipe-data -tcpdump, installs the probe, the fixture and Watch's Advanced debug build where the behaviour
# needs them, runs the steps, records the image's identity, what else ran on the machine, and the capture's
# SHA-256, then stops the emulator and deletes the AVD, also when a step fails. Every adb command names the
# emulator's serial: a phone plugged into the machine is never touched.
#
# The machine's rule (ADR 0048, decision 7): at most three emulators at once, on at most 12 of its threads,
# with at least 14 GB of memory left free; a timing behaviour runs alone. The script refuses to start
# otherwise.
#
# The row is printed and written to <out>/rows.csv. It reaches docs/platform-gaps/results.csv only once
# someone has checked it under ADR 0048, decision 4: a result that differs from its public source, or a
# behaviour no public source states, is a possible new finding, and stays out of the repository.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SDK="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-$HOME/Android/sdk}}"
ADB="$SDK/platform-tools/adb"
EMULATOR="$SDK/emulator/emulator"
AVDMANAGER="$SDK/cmdline-tools/latest/bin/avdmanager"
WATCH_APK="${WATCH_APK:-$ROOT/android/app/build-advanced/outputs/apk/debug/app-debug.apk}"
WATCH=org.visadahyu.datapavan.advanced
WATCH_SCREEN=org.visadahyu.datapavan.watch.MainActivity
WATCH_SERVICE=$WATCH/org.visadahyu.datapavan.watch.WatchVpnService
PROBE=org.visadahyu.lab.gapsprobe
PEER=org.visadahyu.lab.gapsprobe.peer
FIXTURE=org.visadahyu.lab.gapsfixture
RAM_MB=4096

usage() {
    sed -n '4,13p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//' >&2
    exit 2
}

[ $# -ge 2 ] || usage
BEHAVIOUR=$1
API=$2
shift 2
TRIALS=100
PARTS=download,tab,push,resolver
CORES=16-23
OUT=""
while [ $# -gt 0 ]; do
    case $1 in
        --trials) TRIALS=$2; shift 2 ;;
        --parts) PARTS=$2; shift 2 ;;
        --cores) CORES=$2; shift 2 ;;
        --out) OUT=$2; shift 2 ;;
        *) usage ;;
    esac
done
case $BEHAVIOUR in
    vpn-seen | appops-closed | proc-net | loopback | indicators | carried-by-system | short-lived | webview) ;;
    *) usage ;;
esac
case $BEHAVIOUR:$PARTS in
    short-lived:* | carried-by-system:*resolver*)
        TIMING=yes
        [ "$TRIALS" -ge 100 ] || { echo "a timing behaviour needs at least 100 trials (ADR 0048, decision 2)" >&2; exit 2; } ;;
    *) TIMING=no ;;
esac
# The stock emulator images: Google APIs, x86_64. Android 17's image is the one with Google Play and 16 KB
# pages, the only one of that version on this machine.
case $API in
    29) IMAGE="system-images;android-29;google_apis;x86_64"; ANDROID=10 ;;
    30) IMAGE="system-images;android-30;google_apis;x86_64"; ANDROID=11 ;;
    31) IMAGE="system-images;android-31;google_apis;x86_64"; ANDROID=12 ;;
    34) IMAGE="system-images;android-34;google_apis;x86_64"; ANDROID=14 ;;
    35) IMAGE="system-images;android-35;google_apis;x86_64"; ANDROID=15 ;;
    36) IMAGE="system-images;android-36;google_apis;x86_64"; ANDROID=16 ;;
    37) IMAGE="system-images;android-37.0;google_apis_playstore_ps16k;x86_64"; ANDROID=17 ;;
    *) usage ;;
esac
IMAGE_DIR="$SDK/${IMAGE//;//}"
if [ ! -f "$IMAGE_DIR/source.properties" ]; then
    echo "$IMAGE is not installed. It needs the maintainer's word: sdkmanager \"$IMAGE\"" >&2
    exit 2
fi
case $BEHAVIOUR in
    vpn-seen | loopback | carried-by-system | short-lived | webview)
        [ -f "$WATCH_APK" ] || {
            echo "no Watch debug build at $WATCH_APK; build it with:" >&2
            echo "  cd android && ./gradlew -Pdatapavan.edition=advanced --project-cache-dir .gradle-advanced :app:assembleDebug" >&2
            exit 2
        } ;;
esac
DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ)
OUT=${OUT:-$ROOT/docs/platform-gaps/runs/$(date -u +%Y%m%dT%H%M%SZ)-$BEHAVIOUR-api$API}
mkdir -p "$OUT"
OUT=$(cd "$OUT" && pwd)
# The capture and the emulator's own log stay on this machine, under build/: the capture holds the emulator's
# own traffic to Google's services too, and the log this machine's paths. The capture's SHA-256 is recorded.
KEEP="$ROOT/build/gaps-runs/$(basename "$OUT")"
mkdir -p "$KEEP"

# The machine's rule, before anything starts.
threads_in() {
    python3 -I -c 'import sys
n = 0
for part in sys.argv[1].split(","):
    a, _, b = part.partition("-")
    n += int(b or a) - int(a) + 1
print(n)' "$1"
}
others=$(pgrep -f '^[^ ]*qemu-system' || true)
threads=$(threads_in "$CORES")
used=0
for pid in $others; do
    list=$(sed -n 's/^Cpus_allowed_list:\s*//p' "/proc/$pid/status" 2>/dev/null || true)
    [ -z "$list" ] || used=$((used + $(threads_in "$list")))
done
running=$(wc -w <<<"$others")
free_mb=$(awk '/MemAvailable/ {print int($2 / 1024)}' /proc/meminfo)
[ "$running" -lt 3 ] || { echo "three emulators already run; the machine's rule allows three at once" >&2; exit 2; }
[ $((used + threads)) -le 12 ] || { echo "the emulators would use $((used + threads)) of the machine's threads; at most 12" >&2; exit 2; }
[ $((free_mb - RAM_MB)) -ge 14336 ] || { echo "only $free_mb MB of memory available; 14 GB must stay free beside the emulator's $RAM_MB MB" >&2; exit 2; }
[ "$TIMING" = no ] || [ "$running" -eq 0 ] || { echo "a timing behaviour runs alone, and $running emulator(s) run" >&2; exit 2; }
case $BEHAVIOUR in
    carried-by-system | short-lived | webview)
        ! grep -qE "[:.](8792|8793)\s" <<<"$(ss -ltn)" && ! grep -qE "[:.]8796\s" <<<"$(ss -lun)" ||
            { echo "the lab's server's ports (8792, 8793, 8796) are in use: another run uses them" >&2; exit 2; } ;;
esac

# Whether this run's emulator is the only one: checked at the start, after boot, around each timing step and
# at the end, and recorded for every run; a timing run that is not alone stops (ADR 0048, decision 7).
ALONE=$([ "$running" -eq 0 ] && echo yes || echo no)
check_alone() {
    local others
    others=$(pgrep -af '^[^ ]*qemu-system' | grep -vc -- "-avd $AVD " || true)
    [ "${others:-0}" -eq 0 ] && return 0
    ALONE=no
    [ "$TIMING" = no ] || { echo "another emulator runs ($1), and a timing run must run alone: run it again" >&2; exit 1; }
}

# What ran beside the emulator: the load, the memory, the emulators, and the processes that used at least
# 10 % of a thread, by kind (build tools by name; anything else, such as the desktop's own apps, as "other").
beside() {
    local busy
    busy=$(top -b -n 2 -d 1 -w 512 | awk '/^top -/ {block++; next}
        block == 2 && $1 ~ /^[0-9]+$/ && $9 + 0 >= 10 {
            name = $12
            if (name !~ /^(java|python3?|cargo|rustc|gradle|qemu-system.*|emulator|node|clang.*|ld|kotlin.*|adb|top)$/) name = "other"
            sum[name] += $9
        }
        END { for (n in sum) printf "%s:%d%%,", n, sum[n] }' | sed 's/,$//')
    echo "beside_$1 load=$(cut -d' ' -f1-3 /proc/loadavg | tr ' ' ,) mem_available_mb=$(awk '/MemAvailable/ {print int($2 / 1024)}' /proc/meminfo) emulators=$(pgrep -c -f '^[^ ]*qemu-system' || true) busy=${busy:--}"
}

# The port of a console no emulator and no other program uses: the emulator's serial follows from it.
# A run claims its port with a directory, so that two runs started together do not take the same one.
export ANDROID_AVD_HOME="$ROOT/build/gaps-avd"
mkdir -p "$ANDROID_AVD_HOME"
PORT=""
devices=$("$ADB" devices)
listening=$(ss -ltn)
for p in $(seq 5600 2 5680); do
    if ! grep -q "^emulator-$p\b" <<<"$devices" && ! grep -qE "[:.]($p|$((p + 1)))\s" <<<"$listening" &&
        mkdir "$ANDROID_AVD_HOME/port-$p" 2>/dev/null; then
        PORT=$p
        break
    fi
done
[ -n "$PORT" ] || { echo "no free emulator port between 5600 and 5680" >&2; exit 2; }
SERIAL=emulator-$PORT
export ANDROID_SERIAL=$SERIAL
export PATH="$SDK/platform-tools:$PATH"
AVD=gaps-$BEHAVIOUR-api${API%%.*}-$$
EMU_PID=""
SERVER_PID=""
LOGCAT_PID=""
# Set once the device behind the serial has shown it is this run's emulator; before that, the cleanup sends
# nothing to the serial and stops the emulator by its process alone.
IDENTIFIED=""
# Every adb command names this emulator's serial.
a() { "$ADB" -s "$SERIAL" "$@"; }

stop_emulator() {
    [ -n "$EMU_PID" ] || return 0
    [ -z "$IDENTIFIED" ] || a emu kill >/dev/null 2>&1 || true
    for _ in $(seq 1 30); do kill -0 "$EMU_PID" 2>/dev/null || break; sleep 1; done
    kill "$EMU_PID" 2>/dev/null || true
    sleep 2
    kill -9 "$EMU_PID" 2>/dev/null || true
    EMU_PID=""
}
cleanup() {
    set +e
    [ -z "$IDENTIFIED" ] || a shell settings delete global hidden_api_policy >/dev/null 2>&1
    [ -z "$SERVER_PID" ] || kill "$SERVER_PID" 2>/dev/null
    [ -z "$LOGCAT_PID" ] || kill "$LOGCAT_PID" 2>/dev/null
    # Watch's flows before redaction, left by a step that stopped half-way.
    rm -f "$OUT/probe.raw" "$OUT"/flows-*.tmp "$OUT"/flows-*.before
    stop_emulator
    "$AVDMANAGER" delete avd -n "$AVD" >/dev/null 2>&1
    rm -rf "$ANDROID_AVD_HOME/$AVD.avd" "$ANDROID_AVD_HOME/$AVD.ini" "$HOME/.android/modem-nv-ram-$PORT"
    rmdir "$ANDROID_AVD_HOME/port-$PORT" 2>/dev/null
}
trap cleanup EXIT

echo "== $BEHAVIOUR on Android $ANDROID ($IMAGE), emulator $SERIAL (AVD $AVD), cores $CORES, raw output in $OUT"
{
    echo "behaviour $BEHAVIOUR"
    echo "android $ANDROID"
    echo "api $API"
    echo "date $DATE"
    commit=$(git -C "$ROOT" rev-parse --short=12 HEAD)
    [ -z "$(git -C "$ROOT" status --porcelain -- lab)" ] || commit="$commit-dirty"
    echo "probe_commit $commit"
    echo "trials $([ "$TIMING" = yes ] && echo "$TRIALS" || echo 1)"
    [ "$BEHAVIOUR" != carried-by-system ] || echo "parts $PARTS"
    echo "serial $SERIAL"
    echo "cores $CORES"
    echo "run runs/$(basename "$OUT")"
    beside before
} >"$OUT/run.txt"

# The lab's apps, built now with a throwaway key each, and copied for this run: another run may build them
# again meanwhile, one build at a time.
mkdir -p "$KEEP/apks"
(
    flock 9
    cp "$("$ROOT/lab/gaps-probe/build.sh" | tail -1)" "$KEEP/apks/gaps-probe.apk"
    cp "$("$ROOT/lab/gaps-probe/build.sh" --peer | tail -1)" "$KEEP/apks/gaps-probe-peer.apk"
    cp "$("$ROOT/lab/gaps-fixture/build.sh" | tail -1)" "$KEEP/apks/gaps-fixture.apk"
) 9>"$ROOT/build/gaps-build.lock"
PROBE_APK=$KEEP/apks/gaps-probe.apk
PEER_APK=$KEEP/apks/gaps-probe-peer.apk
FIXTURE_APK=$KEEP/apks/gaps-fixture.apk

echo no | "$AVDMANAGER" create avd -n "$AVD" -k "$IMAGE" -d pixel_7 >/dev/null
sed -i -e "s/^hw.ramSize=.*/hw.ramSize=$RAM_MB/" -e 's/^hw.cpu.ncore=.*/hw.cpu.ncore=4/' "$ANDROID_AVD_HOME/$AVD.avd/config.ini"
# In UTC: the emulator's clock shows in screenshots, and the project keeps the local time zone out of all it
# publishes.
taskset -c "$CORES" "$EMULATOR" -avd "$AVD" -port "$PORT" -no-snapshot -wipe-data -timezone Etc/UTC -tcpdump "$KEEP/capture.pcap" \
    -no-window -gpu swiftshader_indirect -no-boot-anim -camera-back none -camera-front none >"$KEEP/emulator.log" 2>&1 &
EMU_PID=$!
booted=no
for _ in $(seq 1 150); do
    if [ "$(a shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" = 1 ]; then booted=yes; break; fi
    kill -0 "$EMU_PID" 2>/dev/null || break
    sleep 2
done
[ "$booted" = yes ] || { echo "the emulator did not boot; see $KEEP/emulator.log" >&2; exit 1; }
# The device behind the serial is the emulator this run started, and an emulator.
[ "$(a emu avd name 2>/dev/null | head -1 | tr -d '\r')" = "$AVD" ] || { echo "$SERIAL is not this run's emulator" >&2; exit 1; }
[ "$(a shell getprop ro.boot.qemu | tr -d '\r')" = 1 ] || [ "$(a shell getprop ro.kernel.qemu | tr -d '\r')" = 1 ] ||
    { echo "$SERIAL does not say it is an emulator" >&2; exit 1; }
IDENTIFIED=yes
check_alone "after boot"
timezone=$(a shell getprop persist.sys.timezone | tr -d '\r')
case $timezone in
    Etc/UTC | UTC | GMT | Etc/GMT) ;;
    *) echo "the emulator's time zone is '$timezone', not UTC: its screenshots would show the local time" >&2; exit 1 ;;
esac
SDK_INT=$(a shell getprop ro.build.version.sdk | tr -d '\r')
# The emulator's capture sees its cellular network only, not its Wi-Fi: Wi-Fi goes off, so that everything
# the virtual phone sends crosses the capture. Right after boot Android may still turn Wi-Fi on, so it is
# turned off until it has stayed off, with mobile data up, for three readings in a row; the run fails at
# the end if Wi-Fi came back meanwhile.
wifi_off() {
    local readings=0 wifi networks
    for _ in $(seq 1 45); do
        a shell svc wifi disable >/dev/null 2>&1 || true
        sleep 2
        wifi=$(a shell dumpsys wifi | tr -d '\r')
        networks=$(a shell dumpsys connectivity | tr -d '\r')
        if grep -q '^Wi-Fi is disabled' <<<"$wifi" && ! grep -qE 'NetworkAgentInfo\{.*WIFI.*CONNECTED' <<<"$networks" &&
            grep -qE 'NetworkAgentInfo\{.*(MOBILE|CELLULAR).*CONNECTED' <<<"$networks"; then
            readings=$((readings + 1))
            [ "$readings" -lt 3 ] || return 0
        else
            readings=0
        fi
    done
    return 1
}
wifi_off || { echo "Wi-Fi did not stay off, or mobile data did not come up: the capture would miss traffic" >&2; exit 1; }
a shell settings put global window_animation_scale 0
a shell settings put global transition_animation_scale 0
a shell settings put global animator_duration_scale 0
a shell input keyevent KEYCODE_WAKEUP
a shell wm dismiss-keyguard >/dev/null 2>&1 || true

# The image's identity (ADR 0048, decision 2). The SDK keeps no archive once an image is installed, and its
# repository lists each archive's SHA-1 only: that SHA-1, from the SDK manager's cache, and the SHA-256 of
# the installed image's files stand for the archive's SHA-256.
{
    echo "image $IMAGE"
    revision=$(sed -n 's/^Pkg.Revision=//p' "$IMAGE_DIR/source.properties")
    echo "image_revision $revision"
    echo "archive_sha1 $(python3 -I - "$IMAGE" "$revision" "$HOME/.android/cache" <<'PY'
import glob, os, sys, xml.etree.ElementTree as ET
path, revision, cache = sys.argv[1:4]
for name in sorted(glob.glob(os.path.join(cache, "sdkbin-*sys-img2*"))):
    try:
        root = ET.parse(name).getroot()
    except ET.ParseError:
        continue
    for package in root.iter("remotePackage"):
        rev = package.find("revision")
        if package.get("path") == path and rev is not None and ".".join(x.text for x in rev) == revision:
            for checksum in package.iter("checksum"):
                print(checksum.text)
                sys.exit(0)
print("not-in-sdk-cache")
PY
)"
    echo "image_files_sha256 $( (cd "$IMAGE_DIR" && find . -type f -print0 | sort -z | xargs -0 sha256sum) | sha256sum | cut -d' ' -f1)"
    echo "fingerprint $(a shell getprop ro.build.fingerprint | tr -d '\r')"
    echo "security_patch $(a shell getprop ro.build.version.security_patch | tr -d '\r')"
    play=$(a shell dumpsys package com.google.android.modulemetadata | tr -d '\r' | sed -n 's/^ *versionName=\([0-9]\{4\}-[0-9]\{2\}\).*/\1/p' | head -1)
    echo "play_update ${play:-none}"
    resolver=$(a shell pm list packages --apex-only --show-versioncode 2>/dev/null | tr -d '\r' |
        sed -n 's/^package:\(com\.[a-z.]*resolv\) versionCode:\([0-9]*\)$/\1@\2/p' | head -1)
    echo "resolver ${resolver:-none}"
    echo "emulator $("$EMULATOR" -version 2>/dev/null | sed -n 's/^Android emulator version \([^ ]*\).*/\1/p' | head -1)"
} >"$OUT/image.txt"

# The lab's server, for the behaviours that send to it; its ports are fixed in the probe, so one run at a
# time uses it.
case $BEHAVIOUR in
    carried-by-system | short-lived | webview)
        python3 -I "$ROOT/lab/server.py" "$OUT/server.log" &
        SERVER_PID=$!
        for _ in $(seq 1 10); do grep -q ready "$OUT/server.log" 2>/dev/null && break; sleep 0.5; done
        grep -q ready "$OUT/server.log" || { echo "the lab's server did not start" >&2; exit 1; } ;;
esac

# The probe's and the fixture's lines, streamed from logcat for the whole run into probe.raw: nothing is
# cleared, so no line falls between a read and a clear. collect writes probe.log from it.
a logcat -c
a logcat -v raw -s GapsProbe:I GapsFixture:I >"$OUT/probe.raw" 2>/dev/null &
LOGCAT_PID=$!
collect() {
    tr -d '\r' <"$OUT/probe.raw" | grep -v '^--------- ' >"$OUT/probe.log" || true
}
# Waits up to $2 seconds for a line of the probe or the fixture that holds $1.
wait_line() {
    for _ in $(seq 1 "$2"); do
        grep -qF -- "$1" "$OUT/probe.raw" && return 0
        sleep 1
    done
    collect
    echo "no line '$1' after $2 s" >&2
    return 1
}
install() { a install --no-incremental -r "$1" >/dev/null; }
# Starts the probe ($1: its package, the probe's or the peer's) for behaviour $2 and step $3, in a task of
# its own: a running task would only be brought to the front.
probe() {
    local app=$1 behaviour=$2 step=$3
    shift 3
    a shell am start -W -f 0x10008000 -n "$app/org.visadahyu.lab.gapsprobe.GapsProbe" \
        --es behaviour "$behaviour" --es step "$step" "$@" >/dev/null
}
# Starts the fixture with the reads $1 and confirms its screen, as the maintainer would on a lab phone.
fixture() {
    a shell am start -W -f 0x10008000 -n "$FIXTURE/org.visadahyu.lab.gapsfixture.GapsFixture" --es reads "$1" >/dev/null
    wait_line "fixture waiting confirm" 30
    (. "$ROOT/scripts/adb-ui.sh" && tap_text Confirm) || { echo "the fixture's Confirm button was not found" >&2; return 1; }
}
lan_permission() {
    [ "$SDK_INT" -lt 37 ] || a shell pm grant "$1" android.permission.ACCESS_LOCAL_NETWORK
}
# Watch's VPN is up: a connected VPN network whose owner is Watch's UID (Android 11 names no package in its
# line, later versions do). Android 10 prints no owner at all: there, a connected VPN while Watch says its
# tunnel runs; the emulator has no other VPN app. Read whole, then searched: under pipefail, a grep -q that
# stops reading early fails the pipe.
vpn_up() {
    local uid vpn
    uid=$(a shell cmd package list packages -U "$WATCH" | tr -d '\r' | sed -n "s/^package:$WATCH uid:\([0-9]*\)$/\1/p")
    vpn=$(grep -E 'ni\{(VPN |\[type: VPN)' <<<"$(a shell dumpsys connectivity | tr -d '\r')" || true)
    [ -n "$uid" ] && grep -q CONNECTED <<<"$vpn" || return 1
    if grep -q "OwnerUid:" <<<"$vpn"; then
        grep -qE "OwnerUid: $uid( |$)" <<<"$vpn"
    else
        grep -q '^ *running true' <<<"$(a shell dumpsys activity service "$WATCH_SERVICE" | tr -d '\r')"
    fi
}
watch_start() {
    # The emulator allows Watch's VPN without the consent dialog, as verify-watch.sh does. Right after an
    # install the setting can be lost (AppOps does not know the UID yet), so it is set until it reads back.
    local mode
    for _ in $(seq 1 15); do
        a shell appops set "$WATCH" ACTIVATE_VPN allow
        mode=$(a shell appops get "$WATCH" ACTIVATE_VPN | tr -d '\r')
        grep -q 'allow' <<<"$mode" && break
        sleep 2
    done
    lan_permission "$WATCH"
    # Right after boot the first start can be lost: it is sent again, up to three times.
    local try
    for try in 1 2 3; do
        a shell am start -W -n "$WATCH/$WATCH_SCREEN" --ez start true >/dev/null
        for _ in $(seq 1 20); do vpn_up && return 0; sleep 1; done
        a shell am force-stop "$WATCH"
    done
    a exec-out screencap -p >"$KEEP/watch-not-up.png" 2>/dev/null || true
    a logcat -d >"$KEEP/watch-not-up.log" 2>/dev/null || true
    echo "Watch's tunnel did not come up (screen and logcat in $KEEP)" >&2
    return 1
}
# Watch's flows (debug builds keep the latest 512), into flows-$1.txt, each through lab/redact-flows.awk: a
# flow to anything but the lab's own addresses keeps its count, port and UID only.
flows() {
    a shell dumpsys activity service "$WATCH_SERVICE" | tr -d '\r' | sed -n 's/^ *flow //p' |
        awk -f "$ROOT/lab/redact-flows.awk" >"$OUT/flows-$1.txt"
}
# Starts the probe's step and reads Watch's flows every few seconds until the line $2 shows (at most $3
# seconds): a step of many flows could push its first ones out of the 512 Watch keeps. flows-$1.txt gets the
# flows of the step's window only, those listed before it left out. The probe's arguments follow $3.
flows_during() {
    local label=$1 line=$2 seconds=$3
    shift 3
    a shell dumpsys activity service "$WATCH_SERVICE" | tr -d '\r' | sed -n 's/^ *flow //p' | sort -u >"$OUT/flows-$label.before"
    check_alone "before $label"
    probe "$@"
    set -- "$label" "$line" "$seconds"
    : >"$OUT/flows-$1.tmp"
    for _ in $(seq 1 $(($3 / 3))); do
        a shell dumpsys activity service "$WATCH_SERVICE" | tr -d '\r' | sed -n 's/^ *flow //p' >>"$OUT/flows-$1.tmp"
        grep -qF -- "$2" "$OUT/probe.raw" && break
        sleep 3
    done
    sleep 3
    a shell dumpsys activity service "$WATCH_SERVICE" | tr -d '\r' | sed -n 's/^ *flow //p' >>"$OUT/flows-$1.tmp"
    sort -u "$OUT/flows-$1.tmp" | comm -23 - "$OUT/flows-$1.before" | awk -f "$ROOT/lab/redact-flows.awk" >"$OUT/flows-$1.txt"
    rm -f "$OUT/flows-$1.tmp" "$OUT/flows-$1.before"
    grep -qF -- "$2" "$OUT/probe.raw" || { collect; echo "no line '$2' after $3 s" >&2; return 1; }
    check_alone "after $1"
}

vpn_seen() {
    install "$PROBE_APK"
    install "$WATCH_APK"
    probe "$PROBE" vpn-seen none
    wait_line "vpn-seen none done" 30
    watch_start
    probe "$PROBE" vpn-seen inside
    wait_line "vpn-seen inside done" 30
    # Left out as the user leaves an app out on Watch's screen (ADR 0041): Watch's own list of apps, which
    # it reads when its tunnel starts. Debug builds let adb write into the app's files.
    a shell am force-stop "$WATCH"
    a shell "run-as $WATCH sh -c 'mkdir -p shared_prefs && cat > shared_prefs/left_out.xml'" <<EOF
<?xml version='1.0' encoding='utf-8' standalone='yes' ?>
<map>
    <set name="apps">
        <string>$PROBE</string>
    </set>
</map>
EOF
    watch_start
    probe "$PROBE" vpn-seen left-out
    wait_line "vpn-seen left-out done" 30
}

appops_closed() {
    install "$PROBE_APK"
    install "$FIXTURE_APK"
    a shell pm grant "$FIXTURE" android.permission.RECORD_AUDIO
    probe "$PROBE" appops-closed watch
    wait_line "appops-closed watch ready" 30
    fixture mic
    wait_line "fixture done" 30
    sleep 3
    # The control: the probe's own microphone, which its watcher must report.
    a shell pm grant "$PROBE" android.permission.RECORD_AUDIO
    probe "$PROBE" appops-closed self-mic
    wait_line "appops-closed self-mic done" 30
    wait_line "appops-closed watch end" 60
    # The history, as installed, then with the emulator's setting that opens hidden APIs to apps, then with
    # GET_APP_OPS_STATS granted over adb (DESIGN's advanced mode), then with both. Each in a new process.
    local step
    for step in history-default history-hidden-open history-granted history-granted-hidden-open; do
        case $step in
            *hidden-open) a shell settings put global hidden_api_policy 1 ;;
            *) a shell settings delete global hidden_api_policy >/dev/null ;;
        esac
        [ "$step" != history-granted ] || a shell pm grant "$PROBE" android.permission.GET_APP_OPS_STATS
        a shell am force-stop "$PROBE"
        probe "$PROBE" appops-closed "$step"
        wait_line "appops-closed $step done" 30
    done
    a shell settings delete global hidden_api_policy >/dev/null
}

proc_net() {
    install "$PROBE_APK"
    probe "$PROBE" proc-net once
    wait_line "proc-net once done" 30
}

loopback() {
    install "$PROBE_APK"
    install "$PEER_APK"
    install "$FIXTURE_APK"
    install "$WATCH_APK"
    watch_start
    flows before
    probe "$PROBE" loopback listen
    wait_line "loopback listen ready" 30
    probe "$PEER" loopback connect
    wait_line "loopback connect done" 40
    wait_line "loopback listen done" 40
    fixture socket
    wait_line "fixture done" 30
    sleep 2
    flows after
}

# Text of the screen as "title: summary" pairs, from the XML dumps given (one per scroll).
screen_pairs() {
    python3 -I - "$@" <<'PY'
import re, sys, html
seen = []
for name in sys.argv[1:]:
    texts = [html.unescape(t) for t in re.findall(r'text="([^"]*)"', open(name, encoding="utf-8").read()) if t]
    i = 0
    while i < len(texts):
        pair = texts[i]
        if i + 1 < len(texts) and re.match(r"(Used by|Not used|Accessed|Allowed|No apps)", texts[i + 1]):
            pair += ": " + texts[i + 1]
            i += 1
        if pair not in seen:
            seen.append(pair)
        i += 1
print("\n".join(p.replace("\n", " ") for p in seen))
PY
}
dump_to() {
    a shell uiautomator dump /sdcard/gaps-ui.xml >/dev/null 2>&1 || true
    a shell cat /sdcard/gaps-ui.xml >"$1" 2>/dev/null || : >"$1"
}

indicators() {
    install "$PROBE_APK"
    install "$FIXTURE_APK"
    # The synthetic data (ADR 0048, decision 5): a contact under a lab account with a made-up name, a call
    # and an SMS through the emulator's console, an image in shared storage; the probe puts the clip.
    a shell content insert --uri content://com.android.contacts/raw_contacts \
        --bind account_type:s:org.visadahyu.lab --bind account_name:s:lab
    local raw
    raw=$(a shell content query --uri content://com.android.contacts/raw_contacts --projection _id | tr -d '\r' | sed -n 's/.*_id=\([0-9]*\).*/\1/p' | tail -1)
    a shell content insert --uri content://com.android.contacts/data --bind "raw_contact_id:i:$raw" \
        --bind mimetype:s:vnd.android.cursor.item/name --bind data1:s:GapsLabContact
    a emu gsm call 5550100 >/dev/null
    sleep 3
    a emu gsm cancel 5550100 >/dev/null
    for _ in 1 2 3; do
        a emu sms send 5550101 gaps-lab-message >/dev/null
        sleep 8
        grep -q '_id=' <<<"$(a shell content query --uri content://sms/inbox --projection _id)" && break
    done
    python3 -I -c 'import struct, sys, zlib
def chunk(kind, data):
    return struct.pack("!I", len(data)) + kind + data + struct.pack("!I", zlib.crc32(kind + data) & 0xFFFFFFFF)
sys.stdout.buffer.write(b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack("!IIBBBBB", 1, 1, 8, 2, 0, 0, 0))
    + chunk(b"IDAT", zlib.compress(b"\x00\x80\x80\x80")) + chunk(b"IEND", b""))' >"$OUT/gaps-lab.png"
    a push "$OUT/gaps-lab.png" /sdcard/Pictures/gaps-lab.png >/dev/null 2>&1
    rm -f "$OUT/gaps-lab.png"
    # The media store learns of the image by a scan: the volume's (Android 11 and later) or the file's (Android
    # 10, where the volume's call does nothing); both are asked, until the image is listed.
    for _ in 1 2 3 4 5; do
        a shell content call --method scan_volume --uri content://media --arg external_primary >/dev/null 2>&1 || true
        a shell am broadcast -a android.intent.action.MEDIA_SCANNER_SCAN_FILE -d file:///sdcard/Pictures/gaps-lab.png >/dev/null 2>&1 || true
        sleep 3
        grep -q '_id=' <<<"$(a shell content query --uri content://media/external/images/media --projection _id)" && break
    done
    {
        echo "seeded contacts $(a shell content query --uri content://com.android.contacts/contacts --projection _id | grep -c '_id=' || true)"
        echo "seeded calllog $(a shell content query --uri content://call_log/calls --projection _id | grep -c '_id=' || true)"
        echo "seeded sms $(a shell content query --uri content://sms/inbox --projection _id | grep -c '_id=' || true)"
        echo "seeded media $(a shell content query --uri content://media/external/images/media --projection _id | grep -c '_id=' || true)"
    } >"$OUT/observed.txt"
    local permission
    for permission in READ_CONTACTS READ_CALL_LOG READ_SMS RECORD_AUDIO; do
        a shell pm grant "$FIXTURE" "android.permission.$permission"
    done
    if [ "$SDK_INT" -ge 33 ]; then
        a shell pm grant "$FIXTURE" android.permission.READ_MEDIA_IMAGES
    else
        a shell pm grant "$FIXTURE" android.permission.READ_EXTERNAL_STORAGE
    fi
    a shell input keyevent KEYCODE_HOME
    probe "$PROBE" indicators clip
    wait_line "indicators clip done" 30
    # Android's toasts, read every fifth of a second from before the fixture starts: a short toast lasts two
    # seconds, and on Android 14 the slower readings below missed one that a screenshot showed.
    (
        for _ in $(seq 1 60); do
            a shell dumpsys notification </dev/null | tr -d '\r' |
                sed -n 's/.*TextToastRecord{[^}]*text=\(.*\) duration=.*/toast \1/p' >>"$OUT/toasts.tmp"
            sleep 0.2
        done
    ) &
    local toasts=$!
    fixture contacts,calllog,sms,media,clipboard,mic
    # While the fixture reads and records: what the status bar offers to accessibility (the privacy chip),
    # SystemUI's own list of privacy items, and screenshots.
    mkdir -p "$OUT/screens"
    local i
    for i in $(seq 1 10); do
        if a shell uiautomator dump --windows /sdcard/gaps-ui.xml >/dev/null 2>&1; then
            a shell cat /sdcard/gaps-ui.xml | tr -d '\r' | grep -o 'content-desc="[^"]*\(icrophone\|amera\|ocation\)[^"]*"' |
                sed 's/^content-desc=/chip /' >>"$OUT/observed.tmp" || true
        fi
        a shell dumpsys activity service com.android.systemui 2>/dev/null | tr -d '\r' |
            sed -n 's/^ *PrivacyItem(privacyType=\([A-Z_]*\), application=PrivacyApplication(packageName=\([^,]*\),.*/privacy-item \1 \2/p' >>"$OUT/observed.tmp" || true
        [ "$i" -gt 4 ] || a exec-out screencap -p >"$OUT/screens/during-$i.png"
        sleep 0.5
    done
    wait_line "fixture done" 30
    wait "$toasts"
    sort -u "$OUT/observed.tmp" "$OUT/toasts.tmp" >>"$OUT/observed.txt"
    rm -f "$OUT/observed.tmp" "$OUT/toasts.tmp"
    # Notifications that came while the fixture read: their apps and channels only.
    a shell dumpsys notification --noredact | tr -d '\r' |
        sed -n 's/^ *NotificationRecord([^:]*: pkg=\([^ ]*\) .*channel=\([^ ]*\) .*/notification \1 \2/p' | sort -u >>"$OUT/observed.txt"
    # The privacy dashboard (Android 12 and later), and what it lists beyond location, camera and microphone.
    if [ "$SDK_INT" -ge 31 ]; then
        a shell am start -W -a android.intent.action.REVIEW_PERMISSION_USAGE >/dev/null
        sleep 3
        dump_to "$OUT/dashboard-1.xml"
        a exec-out screencap -p >"$OUT/screens/dashboard.png"
        if (. "$ROOT/scripts/adb-ui.sh" && tap_text "See other permissions"); then
            sleep 2
            for i in 2 3 4 5 6; do
                dump_to "$OUT/dashboard-$i.xml"
                (. "$ROOT/scripts/adb-ui.sh" && swipe_up)
            done
        fi
        screen_pairs "$OUT"/dashboard-*.xml | sed 's/^/dashboard /' >>"$OUT/observed.txt"
        rm -f "$OUT"/dashboard-*.xml
    else
        echo "dashboard none (Android $ANDROID has no privacy dashboard)" >>"$OUT/observed.txt"
    fi
}

carried_by_system() {
    install "$PROBE_APK"
    install "$WATCH_APK"
    lan_permission "$PROBE"
    watch_start
    case ,$PARTS, in *,download,*) ;; *) carried_tab_and_resolver; return ;; esac
    flows download-before
    probe "$PROBE" carried-by-system download
    wait_line "carried-by-system download done" 90
    sleep 3
    flows download-after
    carried_tab_and_resolver
}

carried_tab_and_resolver() {
    case ,$PARTS, in *,tab,*) ;; *) carried_resolver; return ;; esac
    # The Custom Tab: the image's browser loads the page, unless it first shows a screen of its own.
    flows tab-before
    probe "$PROBE" carried-by-system tab
    wait_line "carried-by-system tab done" 30
    sleep 10
    flows tab-after
    # The activity on screen: topResumedActivity from Android 12, mResumedActivity before.
    echo "tab-screen $(a shell dumpsys activity activities | tr -d '\r' |
        sed -n 's/.*\(topResumedActivity=\|mResumedActivity: \)ActivityRecord{[^ ]* [^ ]* \([^ ]*\) .*/\2/p' | head -1)" >>"$OUT/observed.txt"
    a exec-out screencap -p >"$OUT/tab.png"
    a shell input keyevent KEYCODE_HOME
    carried_resolver
}

carried_resolver() {
    case ,$PARTS, in *,resolver,*) ;; *) return 0 ;; esac
    # The resolver, by Private DNS mode: off, automatic (Android's default) and strict with a provider.
    local mode
    for mode in off opportunistic hostname; do
        if [ "$mode" = hostname ]; then a shell settings put global private_dns_specifier dns.google; fi
        a shell settings put global private_dns_mode "$mode"
        sleep 10
        echo "private-dns $mode watch=$(a shell dumpsys activity service "$WATCH_SERVICE" | tr -d '\r' | sed -n 's/^ *private-dns //p' | tr ' ' _)" >>"$OUT/observed.txt"
        flows_during "resolve-$mode" "carried-by-system resolve-$mode done" $((TRIALS * 6 + 120)) \
            "$PROBE" carried-by-system "resolve-$mode" --ei trials "$TRIALS"
    done
    a shell settings delete global private_dns_specifier >/dev/null
    a shell settings delete global private_dns_mode >/dev/null
}

short_lived() {
    install "$PROBE_APK"
    install "$WATCH_APK"
    lan_permission "$PROBE"
    watch_start
    local step
    for step in udp-closed udp-open tcp-closed tcp-open; do
        flows_during "$step" "short-lived $step done" $((TRIALS / 5 + 120)) "$PROBE" short-lived "$step" --ei trials "$TRIALS"
    done
}

webview() {
    install "$PROBE_APK"
    install "$WATCH_APK"
    lan_permission "$PROBE"
    watch_start
    flows before
    probe "$PROBE" webview page
    wait_line "webview page loaded" 60
    sleep 5
    flows after
}

"${BEHAVIOUR//-/_}"
a shell cmd package list packages -U | tr -d '\r' | sort >"$OUT/uids.txt"
if ! grep -q '^Wi-Fi is disabled' <<<"$(a shell dumpsys wifi | tr -d '\r')"; then
    echo "Wi-Fi came back on during the run, so the capture missed traffic; run it again" >&2
    exit 1
fi
sleep 1
collect
kill "$LOGCAT_PID" 2>/dev/null || true
LOGCAT_PID=""
rm -f "$OUT/probe.raw"
beside after >>"$OUT/run.txt"
check_alone "at the end"
echo "alone $ALONE" >>"$OUT/run.txt"
[ -z "$SERVER_PID" ] || kill "$SERVER_PID" 2>/dev/null || true
SERVER_PID=""
stop_emulator

# The capture is the ground truth where traffic matters: what left the virtual phone, whoever sent it.
python3 -I "$ROOT/lab/capture-summary.py" "$KEEP/capture.pcap" >"$OUT/capture.txt"
echo "capture_sha256 $(sha256sum "$KEEP/capture.pcap" | cut -d' ' -f1)" >>"$OUT/run.txt"

(
    flock 9
    "$ROOT/lab/gaps-tools/build.sh" >/dev/null
    java -cp "$ROOT/build/gaps-tools/classes" org.visadahyu.lab.gapstools.GapsRows row "$OUT" >"$OUT/rows.csv"
) 9>"$ROOT/build/gaps-build.lock"
cat "$OUT/rows.csv"
echo "== done: $OUT (the capture and the emulator's log: $KEEP); the emulator $SERIAL is stopped and its AVD deleted"
