#!/usr/bin/env bash
# The UDP round of the spike: QUIC-sized datagrams both ways through one engine (or none), and the
# engine's CPU time for them. Most of the bytes of Meta's apps travel over QUIC (ADR 0029).
#
#   ANDROID_SERIAL=emulator-5556 HOST=10.0.2.2:8790 tools/measure-udp.sh userspace|system|gvisor|none [rounds] [datagrams]
set -uo pipefail
: "${ANDROID_SERIAL:?set ANDROID_SERIAL: this script never guesses the device}"
ENGINE=${1:?engine: userspace, system, gvisor or none}
ROUNDS=${2:-3}
COUNT=${3:-20000}
HOST=${HOST:-10.0.2.2:8790}
WATCH=org.visadahyu.datapavan.watch.spike
LOAD=org.visadahyu.datapavan.watch.load
SINCE="$(adb shell date +%s | tr -d '\r').000"

wait_for() {
    local pattern=$1 deadline=$((SECONDS + $2)) line
    while [ "$SECONDS" -lt "$deadline" ]; do
        line=$(adb logcat -d -T "$SINCE" -s WatchSpike:I WatchLoad:I | grep -F -- "$pattern" | tail -1)
        if [ -n "$line" ]; then echo "$line"; return 0; fi
        sleep 1
    done
    return 1
}

cpu_ticks() {
    local pid
    pid=$(adb shell pidof "$WATCH" | tr -d '\r')
    [ -n "$pid" ] || { echo 0; return; }
    adb shell cat "/proc/$pid/stat" | tr -d '\r' | awk '{print $14 + $15}'
}

if [ "$ENGINE" != none ]; then
    adb shell am start -n "$WATCH/.MainActivity" --es action start --es engine "$ENGINE" >/dev/null
    wait_for "SPIKE_STARTED engine=$ENGINE" 20 >/dev/null || { echo "engine $ENGINE did not start"; exit 1; }
fi
before=$(cpu_ticks)
run=$(date +%s)
for r in $(seq 1 "$ROUNDS"); do
    adb shell am start -n "$LOAD/.LoadActivity" --es op udp --es url "http://$HOST/ping" --ei n "$COUNT" --es tag "$run-q$r" >/dev/null
    wait_for "tag=$run-q$r " 300 | sed 's/.*SPIKE_RESULT //' || echo "tag=$run-q$r error=timeout"
done
after=$(cpu_ticks)
echo "cpu_ticks=$((after - before)) engine=$ENGINE datagrams=$((ROUNDS * COUNT))"
if [ "$ENGINE" != none ]; then
    adb shell am start -n "$WATCH/.MainActivity" --es action stop >/dev/null
    wait_for "SPIKE_STOPPED" 20 | sed 's/.*SPIKE_STOPPED/stats:/'
fi
