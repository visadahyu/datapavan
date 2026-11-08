#!/usr/bin/env bash
# The loopback owner test: can the VPN app learn which app owns a local proxy port?
# Usage, from spikes/packet-engine/: ANDROID_SERIAL=<serial> [EMU=1] bash tools/loopback-test.sh android
# Prints only the spike's own lines (loopback addresses, the test apps' UIDs), nothing else of the phone.
set -u
cd "$1"
W=org.visadahyu.datapavan.watch.spike
L=org.visadahyu.datapavan.watch.load
adb install -r watch/build/outputs/apk/debug/watch-debug.apk >/dev/null && adb install -r load/build/outputs/apk/debug/load-debug.apk >/dev/null || { echo "install failed"; exit 1; }
[ "${EMU:-0}" = 1 ] && adb shell appops set $W ACTIVATE_VPN allow
echo "uids: $(adb shell cmd package list packages -U $W | tr -d '\r') $(adb shell cmd package list packages -U $L | grep -v '\.load\.' | tr -d '\r')"
watch() { adb shell am start -n $W/.MainActivity "$@" >/dev/null 2>&1; }
run_case() { # name, port, bind
  local t0; t0=$(adb shell date +%s | tr -d '\r')
  adb shell am start -n $L/.LoadActivity --es op listen --ei port "$2" --es bind "$3" --ei n 8 >/dev/null 2>&1
  sleep 2
  watch --es action loopback --ei port "$2"
  sleep 3
  echo "== $1 (port $2, bind $3)"
  adb logcat -d -T "$t0.0" -s WatchSpike WatchLoad 2>/dev/null | grep -E "SPIKE_(LOOPBACK|LISTENING|ERROR)" | sed -E 's/^.* (SPIKE_)/\1/'
  sleep 6
}
watch --es action stop; sleep 2
run_case "no VPN running" 18801 v4
watch --es action start --es engine system --es allow $L --ez quiet true; sleep 3
run_case "tool inside the tunnel" 18802 v4
run_case "tool inside, bound to 0.0.0.0" 18803 any4
run_case "tool inside, bound to ::" 18804 any6
watch --es action start --es engine system --es allow org.visadahyu.datapavan --ez quiet true; sleep 3
run_case "tool outside the tunnel" 18805 v4
watch --es action stop; sleep 2
echo "vpn after: $(adb shell dumpsys connectivity | grep -c -i 'VPN.*CONNECTED')"
