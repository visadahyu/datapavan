#!/usr/bin/env bash
# W2's CPU check (docs/DESIGN.md, 13.2): the packet-engine spike's measuring round
# (spikes/packet-engine/tools/measure.sh), run through Watch itself, so that Watch's engine CPU for the
# spike's workload can be set against the spike's system engine. Watch's tunnel carries only the
# spike's workload app (org.visadahyu.datapavan.watch.load, installed from the spike), which loads the
# test server (scripts/watch-lab/server.py). Prints one line per measurement, then Watch's CPU time in
# clock ticks, its memory and its counters. Only the workload's own log lines are read.
#
#   ANDROID_SERIAL=... HOST=192.168.1.20:8790 scripts/watch-lab/measure.sh [rounds, default 3]
set -uo pipefail
: "${ANDROID_SERIAL:?set ANDROID_SERIAL: this script never guesses the device}"
ROUNDS=${1:-3}
HOST=${HOST:-10.0.2.2:8790}
WATCH=org.visadahyu.datapavan.advanced
LOAD=org.visadahyu.datapavan.watch.load
DOWNLOAD_BYTES=${DOWNLOAD_BYTES:-50000000}
UPLOAD_BYTES=${UPLOAD_BYTES:-20000000}

wait_for() { # wait_for PATTERN SECONDS: waits for a workload log line since this round began
    local pattern=$1 deadline=$((SECONDS + $2)) line
    while [ "$SECONDS" -lt "$deadline" ]; do
        line=$(adb logcat -d -T "$SINCE" -s WatchLoad:I | grep -F -- "$pattern" | tail -1)
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

cpu_ticks() { # utime+stime of Watch, in clock ticks
    local pid
    pid=$(adb shell pidof "$WATCH:watch" | tr -d '\r')
    [ -n "$pid" ] || { echo 0; return; }
    adb shell cat "/proc/$pid/stat" | tr -d '\r' | awk '{print $14 + $15}'
}

adb shell pm path "$LOAD" >/dev/null || { echo "the spike's workload app is not installed (spikes/packet-engine/README.md)"; exit 1; }
SINCE="$(adb shell date +%s | tr -d '\r').000"
adb shell am force-stop "$WATCH"
adb shell am start -n "$WATCH/org.visadahyu.datapavan.watch.MainActivity" --ez start true --es only_apps "$LOAD" >/dev/null
sleep 3
adb shell dumpsys activity service "$WATCH/org.visadahyu.datapavan.watch.WatchVpnService" | tr -d '\r' | grep -q 'running true' || { echo "Watch's tunnel did not start"; exit 1; }
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
echo "cpu_ticks=$((after - before)) engine=watch"
adb shell dumpsys meminfo "$WATCH:watch" | tr -d '\r' | grep -E 'TOTAL PSS|TOTAL RSS|^ *TOTAL' | head -2 | sed 's/^ */meminfo: /'
adb shell dumpsys activity service "$WATCH/org.visadahyu.datapavan.watch.WatchVpnService" | tr -d '\r' | grep -E '^ *counters' | sed 's/^ *//'
adb shell am force-stop "$WATCH"
