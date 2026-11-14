#!/usr/bin/env bash
# The emulator checks in shards, each for an emulator of its own: CI runs one job per shard, and
# scripts/emulator-shards.sh runs them on local emulators side by side. Which check is in which shard is
# written only here. Each shard starts on a freshly booted emulator and installs what it tests; within a
# shard the checks run in this order, each resetting what it changed, as they did in one job before
# 2026-11-14.
#
#   scripts/emulator-shard.sh list       the shards, one per line
#   scripts/emulator-shard.sh check      only says whether the device in ANDROID_SERIAL may run a shard,
#                                        reading two of its properties and nothing else
#   scripts/emulator-shard.sh <shard>    runs the shard's checks on the device in ANDROID_SERIAL
#
# A shard installs apps, changes settings, sets a PIN and taps: it runs only on an emulator, named by its
# serial (ANDROID_SERIAL=emulator-NNNN) and saying so itself, never on a phone or on "the only device adb
# sees", since a phone may be attached beside the emulators.
#
# The APKs come from the build (scripts/check.sh android, or CI's build job): Basic's and Advanced's debug
# builds and Advanced's unsigned release build, at Gradle's output paths.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SHARDS="watch audit screens"

# The checks of shard $1, in order.
checks_of() {
    case $1 in
        # Watch in Datapavan Advanced: its smoke test, its engine end to end, its chaining through a test
        # tool, its connection log, and its release build as users get it.
        watch) echo smoke-watch.sh verify-watch.sh verify-chain.sh verify-log.sh verify-watch-release.sh ;;
        # Basic: its smoke test, which installs it, then the audit with its fixture, the remediation plan,
        # the launcher shortcuts and the data pack import.
        audit) echo smoke.sh verify-audit.sh verify-plan.sh verify-shortcuts.sh verify-datapack.sh ;;
        # Basic's screens in every language with the accessibility check.
        screens) echo screenshots.sh ;;
        *) return 1 ;;
    esac
}

# Whether ANDROID_SERIAL names an emulator, by its serial and by what the device says of itself. Only
# getprop is run on the device.
emulator_guard() {
    local serial=${ANDROID_SERIAL:-} qemu kernel
    if [ -z "$serial" ]; then
        echo "refused: ANDROID_SERIAL is not set; a shard runs only on an emulator named by its serial" >&2
        return 1
    fi
    qemu=$(adb -s "$serial" shell getprop ro.boot.qemu </dev/null 2>/dev/null | tr -d '\r') || qemu=""
    kernel=$(adb -s "$serial" shell getprop ro.kernel.qemu </dev/null 2>/dev/null | tr -d '\r') || kernel=""
    case $serial in
        emulator-[0-9]*) ;;
        *)
            echo "refused: $serial is not an emulator's serial (ro.boot.qemu '${qemu}', ro.kernel.qemu '${kernel}')" >&2
            return 1
            ;;
    esac
    if [ "$qemu" != 1 ] && [ "$kernel" != 1 ]; then
        echo "refused: $serial does not say it is an emulator (ro.boot.qemu '${qemu}', ro.kernel.qemu '${kernel}')" >&2
        return 1
    fi
    echo "ok: $serial is an emulator"
}

case "${1:-}" in
    list) tr ' ' '\n' <<<"$SHARDS" ;;
    check) emulator_guard ;;
    "") echo "usage: $0 list | $0 <shard>" >&2; exit 2 ;;
    *)
        shard=$1
        checks=$(checks_of "$shard") || { echo "no shard named $shard; the shards are: $SHARDS" >&2; exit 2; }
        emulator_guard >/dev/null || exit 2
        echo "== Emulator shard $shard on $ANDROID_SERIAL: $checks"
        for check in $checks; do
            case $check in
                screenshots.sh)
                    # The screenshots shard has Basic to itself: installed fresh here, as smoke.sh does in
                    # the audit shard.
                    adb install -r "$ROOT/android/app/build/outputs/apk/debug/app-debug.apk" >/dev/null
                    "$ROOT/scripts/screenshots.sh" "$ROOT/build/screenshots"
                    ;;
                *) "$ROOT/scripts/$check" ;;
            esac
        done
        echo "== Emulator shard $shard passed"
        ;;
esac
