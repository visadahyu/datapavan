#!/usr/bin/env bash
# One round of the enterprise-channels spike on the device that ANDROID_SERIAL names: an emulator with
# no accounts, started with -read-only so that nothing it does is kept. From spikes/enterprise-channels/:
#   ANDROID_SERIAL=emulator-5554 bash tools/run.sh android
# Makes the controller the device owner, tests the three channels, then removes it again.
# (`am start` without -W: on Android 11 it waits forever for an activity that finishes at once.)
set -u
cd "$1"
C=org.visadahyu.datapavan.enterprise.controller
P=org.visadahyu.datapavan.enterprise.probe
L=org.visadahyu.datapavan.watch.load
echo "android $(adb shell getprop ro.build.version.release | tr -d '\r'), $(adb shell getprop ro.product.manufacturer | tr -d '\r')"
adb install -r -t controller/build/outputs/apk/debug/controller-debug.apk >/dev/null && adb install -r probe/build/outputs/apk/debug/probe-debug.apk >/dev/null || { echo "install failed"; exit 1; }
adb shell dpm set-device-owner $C/.Admin 2>&1 | tail -1
control() { adb shell am start -n $C/.ControlActivity "$@" >/dev/null 2>&1; sleep 2; }
probe() { adb shell am start -n $P/.ProbeActivity "$@" >/dev/null 2>&1; sleep 3; }
since=$(adb shell date +%s | tr -d '\r')
show() { adb logcat -d -T "$since.0" -s EntSpike WatchLoad 2>/dev/null | grep -E "SPIKE_" | sed -E 's/^.*(SPIKE_)/\1/'; since=$(adb shell date +%s | tr -d '\r'); }

echo "== 1. the probe has no INTERNET permission"; probe --es action whoami; show
echo "== 2. managed configuration in"; control --es action config --es pkg $P --es level strict --es allowed_vpn ch.protonvpn.android; probe --es action config; show
echo "== 3. a verdict out (setStates, then setStatesImmediate)"; probe --es action report; sleep 5; probe --es action report --ez immediate true; sleep 5; show
echo "== 4. limits: key 100 and 101, message 1000 and 1001, data 1000 and 1001"
probe --es action report --ez immediate true --ei keylen 100 --ei msglen 1000 --ei datalen 1000; sleep 3
probe --es action report --ez immediate true --ei keylen 101; probe --es action report --ez immediate true --ei msglen 1001; probe --es action report --ez immediate true --ei datalen 1001; sleep 3; show
echo "== 5. many states at once (50)"; probe --es action report --ez immediate true --ei count 50; sleep 5; show | sed -E "s/key=verdictk?[0-9]+/key=verdictN/" | sort | uniq -c | sort -rn | head -4
echo "== 6. network logging delegated to the probe"
control --es action delegate --es pkg $P; probe --es action whoami; probe --es action logging --ez on true; show
adb shell am start -n $L/.LoadActivity --es op connect --es url "https://example.com:443/" --ei n 3 >/dev/null 2>&1; sleep 15
adb shell dpm force-network-logs 2>&1 | tail -1; sleep 10; show
echo "== cleanup"; probe --es action logging --ez on false; control --es action logging --ez on false; show
adb shell dpm remove-active-admin $C/.Admin 2>&1 | tail -1
adb uninstall $P >/dev/null; adb uninstall $C >/dev/null
echo "device owner left: $(adb shell dpm list-owners 2>/dev/null | tr -d '\r' | tail -1)"
