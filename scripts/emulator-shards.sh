#!/usr/bin/env bash
# Runs CI's emulator shards (scripts/emulator-shard.sh) on local emulators before a push, up to three at
# once, within this machine's caps: each emulator gets four threads of its own (two cores and their
# siblings) through taskset, at most twelve threads together, and one more starts only while at least
# 14 GB of memory would stay free beside it. Each emulator is a read-only instance of one AVD, so it
# boots clean and keeps nothing; it is named by its serial, every check runs with ANDROID_SERIAL set to
# it, and only emulators this script started are touched. Everything it started is stopped at the end,
# also on failure or Ctrl-C.
#
#   scripts/emulator-shards.sh [--alone] [--avd NAME] [shard...]
#
# With no shard named, every shard runs. --alone runs them one after another, for timing-sensitive work
# on a busy machine (the watch shard holds the chain and release checks). The AVD defaults to CI's image,
# dp-api35-ci, which is brought to CI's phone size (1080 x 2400 at 420 dpi) with animations off, as CI's
# runner does. Build the APKs first:
#
#   (cd android && ./gradlew assembleDebug && ./gradlew -Pdatapavan.edition=advanced \
#       --project-cache-dir .gradle-advanced :app:assembleDebug :app:assembleRelease)
#
# Each shard's output goes to build/emulator-shards/<shard>.log; the script fails if any shard failed.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SDK="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-$HOME/Android/sdk}}"
EMULATOR="$SDK/emulator/emulator"
AVD=dp-api35-ci
ALONE=""
MAX_EMULATORS=3
THREADS_EACH=4
FREE_FLOOR_KB=$((14 * 1024 * 1024))
# What one emulator with a 2 GB guest takes of the host's memory, about.
EMULATOR_KB=$((5 * 1024 * 1024))
FIRST_PORT=5600
OUT="$ROOT/build/emulator-shards"

shards=()
while [ $# -gt 0 ]; do
    case $1 in
        --alone) ALONE=1 ;;
        --avd) AVD=$2; shift ;;
        -h | --help) awk 'NR > 1 && /^#/ { sub(/^# ?/, ""); print; next } NR > 1 { exit }' "$0"; exit 0 ;;
        -*) echo "unknown option $1" >&2; exit 2 ;;
        *) shards+=("$1") ;;
    esac
    shift
done
known=$("$ROOT/scripts/emulator-shard.sh" list)
[ ${#shards[@]} -gt 0 ] || mapfile -t shards <<<"$known"
for shard in "${shards[@]}"; do
    grep -qx "$shard" <<<"$known" || { echo "no shard named $shard; the shards are: $(echo $known)" >&2; exit 2; }
done
for apk in android/app/build/outputs/apk/debug/app-debug.apk android/app/build-advanced/outputs/apk/debug/app-debug.apk \
    android/app/build-advanced/outputs/apk/release/app-release-unsigned.apk; do
    [ -f "$ROOT/$apk" ] || { echo "no $apk: build the APKs first (see $0 --help)" >&2; exit 2; }
done
[ -x "$EMULATOR" ] || { echo "no emulator at $EMULATOR" >&2; exit 2; }
"$EMULATOR" -list-avds | grep -qx "$AVD" || { echo "no AVD named $AVD" >&2; exit 2; }

# Sets of four threads, two cores and their SMT siblings, from the last cores down, so that the first
# cores stay with whatever else runs here. A machine without SMT gets four cores per set.
cpu_sets() {
    local seen="" cpu siblings set="" count=0
    for cpu in $(ls -d /sys/devices/system/cpu/cpu[0-9]* | sed 's/.*cpu//' | sort -rn); do
        siblings=$(cat "/sys/devices/system/cpu/cpu$cpu/topology/thread_siblings_list" 2>/dev/null) || continue
        case " $seen " in *" $siblings "*) continue ;; esac
        seen="$seen $siblings"
        set="${set:+$set,}$siblings"
        count=$((count + $(tr ',-' '\n\n' <<<"$siblings" | grep -c .)))
        # "a-b" lists two threads as a range.
        if [ "$count" -ge "$THREADS_EACH" ]; then
            echo "$set"
            set=""
            count=0
        fi
    done
}
mapfile -t CPU_SETS < <(cpu_sets | head -n "$MAX_EMULATORS")
[ ${#CPU_SETS[@]} -gt 0 ] || { echo "could not read the CPU topology" >&2; exit 2; }

mem_available_kb() { sed -n 's/^MemAvailable: *\([0-9]*\) kB$/\1/p' /proc/meminfo; }

# Slot i: its CPU set, its console port and serial, the emulator's PID and the shard running there.
declare -a SLOT_PID SLOT_SHARD SLOT_RUN
STARTED_PIDS=()

stop_slot() {
    local i=$1 serial=emulator-$((FIRST_PORT + 2 * $1)) pid=${SLOT_PID[$1]:-}
    [ -n "$pid" ] || return 0
    adb -s "$serial" emu kill >/dev/null 2>&1 || true
    for _ in $(seq 1 30); do kill -0 "$pid" 2>/dev/null || break; sleep 1; done
    kill "$pid" 2>/dev/null || true
    SLOT_PID[$i]=""
}

cleanup() {
    local i pid
    # A shard runs in a process group of its own, with its checks and their test servers.
    for pid in ${SLOT_RUN[@]+"${SLOT_RUN[@]}"}; do [ -z "$pid" ] || kill -TERM -- "-$pid" 2>/dev/null || true; done
    for i in "${!CPU_SETS[@]}"; do stop_slot "$i"; done
    # Anything this script started that is still there, by its own PID only.
    for pid in ${STARTED_PIDS[@]+"${STARTED_PIDS[@]}"}; do kill "$pid" 2>/dev/null || true; done
}
trap cleanup EXIT
trap 'exit 130' INT TERM

# Boots a fresh emulator in slot $1, pinned to its CPU set; fails if the port is taken or it does not boot.
boot_slot() {
    local i=$1 port=$((FIRST_PORT + 2 * $1)) serial pid
    serial=emulator-$port
    if adb devices | grep -q "^$serial[[:space:]]" || ss -ltn 2>/dev/null | grep -qE "[:.]($port|$((port + 1)))[[:space:]]"; then
        echo "port $port is in use, by an emulator this script did not start: not touching it" >&2
        return 1
    fi
    taskset -c "${CPU_SETS[$i]}" "$EMULATOR" -avd "$AVD" -read-only -port "$port" -no-window -gpu swiftshader_indirect \
        -noaudio -no-boot-anim -camera-back none -no-snapshot -no-metrics >"$OUT/emulator-$port.log" 2>&1 &
    pid=$!
    SLOT_PID[$i]=$pid
    STARTED_PIDS+=("$pid")
    timeout 300 adb -s "$serial" wait-for-device || return 1
    for _ in $(seq 1 150); do
        [ "$(adb -s "$serial" shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" = 1 ] && break
        sleep 2
    done
    [ "$(adb -s "$serial" shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" = 1 ] || return 1
    # As CI's runner leaves its emulator: a phone's size (the pixel_7 profile) and no animations.
    adb -s "$serial" shell wm size 1080x2400
    adb -s "$serial" shell wm density 420
    for setting in window_animation_scale transition_animation_scale animator_duration_scale; do
        adb -s "$serial" shell settings put global "$setting" 0.0
    done
    adb -s "$serial" shell input keyevent KEYCODE_WAKEUP
    adb -s "$serial" shell wm dismiss-keyguard >/dev/null 2>&1 || true
}

mkdir -p "$OUT"
pending=("${shards[@]}")
failed=()
passed=()
slots=${#CPU_SETS[@]}
[ -z "$ALONE" ] || slots=1

# Starts the next pending shard in a free slot, if the memory floor allows another emulator.
start_next() {
    local i=$1 shard=${pending[0]} beside="" j
    if [ "$(mem_available_kb)" -lt $((FREE_FLOOR_KB + EMULATOR_KB)) ]; then
        return 1
    fi
    pending=("${pending[@]:1}")
    for j in "${!SLOT_SHARD[@]}"; do [ -z "${SLOT_SHARD[$j]}" ] || beside="$beside ${SLOT_SHARD[$j]}"; done
    echo "== $shard: booting emulator-$((FIRST_PORT + 2 * i)) on CPUs ${CPU_SETS[$i]}${beside:+, beside$beside}"
    if ! boot_slot "$i"; then
        echo "!! $shard: the emulator did not boot (see $OUT/emulator-$((FIRST_PORT + 2 * i)).log)" >&2
        stop_slot "$i"
        failed+=("$shard")
        return 0
    fi
    SLOT_SHARD[$i]=$shard
    ANDROID_SERIAL=emulator-$((FIRST_PORT + 2 * i)) setsid "$ROOT/scripts/emulator-shard.sh" "$shard" >"$OUT/$shard.log" 2>&1 &
    SLOT_RUN[$i]=$!
    STARTED_PIDS+=("${SLOT_RUN[$i]}")
}

for i in $(seq 0 $((slots - 1))); do SLOT_SHARD[$i]=""; SLOT_RUN[$i]=""; SLOT_PID[$i]=""; done
while :; do
    for i in $(seq 0 $((slots - 1))); do
        # A finished shard frees its slot and its emulator.
        if [ -n "${SLOT_RUN[$i]}" ] && ! kill -0 "${SLOT_RUN[$i]}" 2>/dev/null; then
            if wait "${SLOT_RUN[$i]}"; then
                echo "ok: ${SLOT_SHARD[$i]} (log: ${OUT#"$ROOT/"}/${SLOT_SHARD[$i]}.log)"
                passed+=("${SLOT_SHARD[$i]}")
            else
                echo "FAILED: ${SLOT_SHARD[$i]}; its log ends:" >&2
                tail -15 "$OUT/${SLOT_SHARD[$i]}.log" | sed 's/^/    /' >&2
                failed+=("${SLOT_SHARD[$i]}")
            fi
            SLOT_RUN[$i]=""
            SLOT_SHARD[$i]=""
            stop_slot "$i"
        fi
        if [ -z "${SLOT_RUN[$i]}" ] && [ ${#pending[@]} -gt 0 ]; then
            start_next "$i" || true
        fi
    done
    busy=""
    for i in $(seq 0 $((slots - 1))); do [ -z "${SLOT_RUN[$i]}" ] || busy=1; done
    [ -n "$busy" ] || [ ${#pending[@]} -gt 0 ] || break
    if [ -z "$busy" ] && [ ${#pending[@]} -gt 0 ] && [ "$(mem_available_kb)" -lt $((FREE_FLOOR_KB + EMULATOR_KB)) ]; then
        echo "!! less than $(((FREE_FLOOR_KB + EMULATOR_KB) / 1024 / 1024)) GB of memory available, and nothing running: not starting ${pending[*]}" >&2
        failed+=("${pending[@]}")
        break
    fi
    sleep 5
done

echo "== passed: ${passed[*]:-none}; failed: ${failed[*]:-none}"
[ ${#failed[@]} -eq 0 ]
