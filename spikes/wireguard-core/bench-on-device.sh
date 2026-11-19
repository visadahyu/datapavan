#!/usr/bin/env bash
# Runs W7's spike benchmark (bench/: Tunn's encapsulation, then the peer's decapsulation, per packet) on one
# Android device over adb (ADR 0035, question 2).
#
#   ANDROID_SERIAL=<serial> spikes/wireguard-core/bench-on-device.sh [rounds, default 3]
#
# It builds wg-bench with cargo-ndk, release profile as the engine ships, with `ring` and with `aws-lc-rs`,
# for the device's own ABI and, where the device also runs 32-bit ARM code, for armeabi-v7a too. It copies
# the binaries to /data/local/tmp/datapavan-wg-bench, runs each on the device's fastest core and on its
# slowest (by cpuinfo_max_freq), one run at a time, each pinned to its core, for packets of 1280 and 1420
# bytes, and removes the directory at the end, also on failure. Nothing is installed and no setting
# changes. It refuses to run while the phone is in a call. One tab-separated line per run on stdout: the
# device, its Android release, the ABI, then wg-bench's columns (see bench/src/main.rs).
set -euo pipefail

: "${ANDROID_SERIAL:?set ANDROID_SERIAL to the device to run on}"
export ANDROID_SERIAL
ROUNDS=${1:-3}
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SDK="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-$HOME/Android/sdk}}"
export ANDROID_NDK_HOME="$SDK/ndk/30.0.16248370"
DIR=/data/local/tmp/datapavan-wg-bench

device() { adb shell "$@" </dev/null | tr -d '\r'; }

[ "$(adb get-state 2>/dev/null)" = device ] || { echo "no device $ANDROID_SERIAL" >&2; exit 1; }
calls=$(device dumpsys telephony.registry 2>/dev/null || true)
if grep -E 'mCallState=[12]' >/dev/null <<<"$calls"; then
    echo "the device is in a call: not now" >&2
    exit 1
fi
model=$(device getprop ro.product.model)
release=$(device getprop ro.build.version.release)
primary=$(device getprop ro.product.cpu.abi)
abis=("$primary")
if [ "$primary" = arm64-v8a ] && grep armeabi-v7a >/dev/null <<<"$(device getprop ro.product.cpu.abilist)"; then
    abis+=(armeabi-v7a)
fi

# The fastest and the slowest core, by their highest frequency; one core if all are alike.
freqs=$(device 'for c in /sys/devices/system/cpu/cpu[0-9]*; do echo "${c##*cpu} $(cat $c/cpufreq/cpuinfo_max_freq 2>/dev/null || echo 0)"; done')
fast=$(sort -k2,2nr -k1,1n <<<"$freqs" | awk 'NR == 1 { print $1 }')
slow=$(sort -k2,2n -k1,1n <<<"$freqs" | awk 'NR == 1 { print $1 }')
cores=("$fast")
[ "$(awk -v c="$fast" '$1 == c { print $2 }' <<<"$freqs")" = "$(awk -v c="$slow" '$1 == c { print $2 }' <<<"$freqs")" ] || cores+=("$slow")
echo "# $model, Android $release, ABIs ${abis[*]}, cores ${cores[*]} (max kHz: $(tr '\n' ' ' <<<"$freqs"))" >&2

declare -A triple=([arm64-v8a]=aarch64-linux-android [armeabi-v7a]=armv7-linux-androideabi [x86_64]=x86_64-linux-android)
trap 'adb shell rm -rf "$DIR" </dev/null >/dev/null 2>&1 || true' EXIT
device rm -rf "$DIR"
device mkdir -p "$DIR"
for abi in "${abis[@]}"; do
    for backend in ring aws-lc; do
        (cd "$HERE" && cargo ndk -t "$abi" --platform 29 build -q --release --locked -p wg-bench --features "$backend" \
            --target-dir "$HERE/target/bench-$backend") >&2
        adb push -q "$HERE/target/bench-$backend/${triple[$abi]}/release/wg-bench" "$DIR/wg-bench-$abi-$backend" </dev/null >&2
        device chmod 755 "$DIR/wg-bench-$abi-$backend"
    done
done

printf 'device\tandroid\tabi\tround\tbackend\tarch\tcore\tsize\tencap_ns\tdecap_ns\tboth_ns\tms_per_MB\tcpu_over_wall\tpackets\n'
for round in $(seq "$ROUNDS"); do
    for abi in "${abis[@]}"; do
        for backend in ring aws-lc; do
            for core in "${cores[@]}"; do
                device "$DIR/wg-bench-$abi-$backend" --cpu "$core" --seconds 3 | awk -v d="$model" -v r="$release" -v a="$abi" -v n="$round" \
                    'NR > 1 { print d "\t" r "\t" a "\t" n "\t" $0 }'
            done
        done
    done
done
