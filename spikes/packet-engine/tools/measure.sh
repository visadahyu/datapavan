#!/usr/bin/env bash
# (`am start` without -W: on Android 11 it waits forever for an activity that finishes at once.)
# One measuring round of the packet-engine spike (../README.md) on the device that ANDROID_SERIAL
# names: starts an engine (or none, for the baseline), runs the workload against tools/server.py,
# and prints one line per measurement plus the engine's memory, CPU time and counters.
#
#   ANDROID_SERIAL=emulator-5556 HOST=10.0.2.2:8790 tools/measure.sh userspace|system|gvisor|none [rounds]
set -uo pipefail
: "${ANDROID_SERIAL:?set ANDROID_SERIAL: this script never guesses the device}"
ENGINE=${1:?engine: userspace, system, gvisor or none}
ROUNDS=${2:-3}
HOST=${HOST:-10.0.2.2:8790}
WATCH=org.visadahyu.datapavan.watch.spike
LOAD=org.visadahyu.datapavan.watch.load
DOWNLOAD_BYTES=${DOWNLOAD_BYTES:-50000000}
UPLOAD_BYTES=${UPLOAD_BYTES:-20000000}

wait_for() { # wait_for PATTERN SECONDS: waits for a logcat line of the spike's apps since this round began
    local pattern=$1 deadline=$((SECONDS + $2)) line
    while [ "$SECONDS" -lt "$deadline" ]; do
        line=$(adb logcat -d -T "$SINCE" -s WatchSpike:I WatchLoad:I | grep -F -- "$pattern" | tail -1)
        if [ -n "$line" ]; then echo "$line"; return 0; fi
        sleep 1
    done
    return 1
}

load() { # load TAG OP URL [extra am args...]: one workload run, prints its result
    local tag=$1 op=$2 url=$3
    shift 3
    adb shell am start -n "$LOAD/.LoadActivity" --es op "$op" --es url "$url" --es tag "$tag" "$@" >/dev/null
    wait_for "tag=$tag " 300 | sed 's/.*SPIKE_RESULT //' || echo "tag=$tag op=$op error=timeout"
}

cpu_ticks() { # utime+stime of the watch app, in clock ticks
    local pid
    pid=$(adb shell pidof "$WATCH" | tr -d '\r')
    [ -n "$pid" ] || { echo 0; return; }
    adb shell cat "/proc/$pid/stat" | tr -d '\r' | awk '{print $14 + $15}'
}

# Only the spike's own lines are read, from this time on; the phone's log is left as it is.
SINCE="$(adb shell date +%s | tr -d '\r').000"  # seconds since the epoch: no space for adb to split
if [ "$ENGINE" != none ]; then
    adb shell am start -n "$WATCH/.MainActivity" --es action start --es engine "$ENGINE" >/dev/null
    wait_for "SPIKE_STARTED engine=$ENGINE" 20 | sed 's/.*SPIKE_STARTED/started/' || { echo "engine $ENGINE did not start"; adb logcat -d -s WatchSpike | tail -5; exit 1; }
fi
before=$(cpu_ticks)
run=$(date +%s)
for r in $(seq 1 "$ROUNDS"); do
    load "$run-d$r" download "http://$HOST/bytes/$DOWNLOAD_BYTES" --ei n 1
    load "$run-u$r" upload "http://$HOST/sink" --el bytes "$UPLOAD_BYTES" --ei n 1
    load "$run-p$r" parallel "http://$HOST/bytes/$((DOWNLOAD_BYTES / 4))" --ei parallel 4 --ei n 1
    load "$run-c$r" connect "http://$HOST/ping" --ei n 100
    load "$run-r$r" rtt "http://$HOST/ping" --ei n 100
done
after=$(cpu_ticks)
echo "cpu_ticks=$((after - before)) engine=$ENGINE"
adb shell dumpsys meminfo "$WATCH" | tr -d '\r' | grep -E 'TOTAL PSS|TOTAL RSS|^ *TOTAL' | head -2 | sed 's/^ */meminfo: /'
if [ "$ENGINE" != none ]; then
    adb shell am start -n "$WATCH/.MainActivity" --es action stop >/dev/null
    wait_for "SPIKE_STOPPED" 20 | sed 's/.*SPIKE_STOPPED/stats:/'
fi
