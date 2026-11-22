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
SHARDS="network audit screens dns proxies blocking wireguard"

# The checks of shard $1, in order.
checks_of() {
    case $1 in
        # Watch in Datapavan Advanced: its smoke test, its engine end to end, its chaining through a test
        # tool, the live counters by the apps' states, its connection log, and its release build as users get it.
        network) echo smoke-network.sh verify-network.sh verify-chain.sh verify-activity.sh verify-log.sh verify-network-release.sh ;;
        # Basic: its smoke test, which installs it, then the audit with its fixture, the remediation plan,
        # the launcher shortcuts, the data pack import, and Android's own labels with the screens that quote them
        # (ADR 0054), which also installs Advanced for its names' section; each skip there fails the shard where
        # LABELS_REQUIRED=1, as on CI.
        audit) echo smoke.sh verify-audit.sh verify-plan.sh verify-shortcuts.sh verify-datapack.sh verify-labels.sh ;;
        # Basic's screens in every language with the accessibility check.
        screens) echo screenshots.sh ;;
        # Watch's WireGuard upstream against the lab's peers of the kernel's WireGuard, and the import of its
        # configurations through Android's own documents screen, photo picker and camera (W7; a shard of their own
        # since part 3a, which CI runs where the WireGuard code or its checks changed, and every week): each skipped,
        # and saying so, where no peer can start, unless WGLAB_REQUIRED=1, as on CI.
        wireguard) echo verify-wireguard.sh verify-wireguard-import.sh ;;
        # Watch's encrypted resolver for direct apps' names against the DNS lab (W8, part 1; a shard of its own
        # since the fix round, review R-M4): Watch asks the lab's resolver as the network's through a debug
        # command, so any emulator serves; skipped, and saying so, where Docker does not run, unless
        # DNSLAB_REQUIRED=1, as on CI.
        dns) echo verify-dns.sh ;;
        # Apps' built-in proxies named (W8, part 2a, ADR 0052): the project's proxy fixture through the proxy lab's
        # SOCKS5, HTTP and MTProto proxies on this computer, skipped, and saying so, where Docker cannot start the lab,
        # unless PROXYLAB_REQUIRED=1, as on CI.
        proxies) echo verify-proxies.sh ;;
        # Tracker blocking and its undo (W8, part 3a, ADR 0053): the project's blocking fixture against the blocking lab
        # on this computer (scripts/blocklab.py, Python's standard library alone), skipped, and saying so, where it cannot
        # start, unless BLOCKING_REQUIRED=1, as on CI.
        blocking) echo verify-blocking.sh ;;
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
                verify-wireguard.sh | verify-wireguard-import.sh)
                    # A check that ends without its last line has not checked everything (W7, part 3a): with the
                    # switch on, that fails the shard, whatever the check's own status said.
                    log=$(mktemp)
                    "$ROOT/scripts/$check" | tee "$log"
                    last=$(tail -n 1 "$log")
                    rm -f "$log"
                    if [ "${WGLAB_REQUIRED:-}" = 1 ] && ! grep -qx '== WireGuard .* checked on the emulator' <<<"$last"; then
                        echo "$check ended without its last line, with WGLAB_REQUIRED=1: '$last'" >&2
                        exit 1
                    fi
                    ;;
                verify-dns.sh)
                    # As the WireGuard checks: with DNSLAB_REQUIRED=1, only the check's last line passes the shard.
                    log=$(mktemp)
                    "$ROOT/scripts/$check" | tee "$log"
                    last=$(tail -n 1 "$log")
                    rm -f "$log"
                    if [ "${DNSLAB_REQUIRED:-}" = 1 ] && [ "$last" != "== the DNS check passed" ]; then
                        echo "$check ended without its last line, with DNSLAB_REQUIRED=1: '$last'" >&2
                        exit 1
                    fi
                    ;;
                verify-proxies.sh)
                    # As the WireGuard checks: with the switch on, a check that ends without its last line fails the shard.
                    log=$(mktemp)
                    "$ROOT/scripts/$check" | tee "$log"
                    last=$(tail -n 1 "$log")
                    rm -f "$log"
                    if [ "${PROXYLAB_REQUIRED:-}" = 1 ] && [ "$last" != "== Apps' built-in proxies checked on the emulator" ]; then
                        echo "$check ended without its last line, with PROXYLAB_REQUIRED=1: '$last'" >&2
                        exit 1
                    fi
                    ;;
                verify-labels.sh)
                    # With the switch on, the labels check must reach its last line and skip nothing (ADR 0054).
                    log=$(mktemp)
                    "$ROOT/scripts/$check" | tee "$log"
                    last=$(tail -n 1 "$log")
                    skipped=$(grep -c '^skipped:' "$log" || true)
                    rm -f "$log"
                    if [ "${LABELS_REQUIRED:-}" = 1 ] && { [ "$last" != "== Android's own labels checked on the emulator" ] || [ "$skipped" != 0 ]; }; then
                        echo "$check skipped $skipped steps or ended without its last line, with LABELS_REQUIRED=1: '$last'" >&2
                        exit 1
                    fi
                    ;;
                verify-blocking.sh)
                    # As the WireGuard checks: with the switch on, a check that ends without its last line fails the shard.
                    log=$(mktemp)
                    "$ROOT/scripts/$check" | tee "$log"
                    last=$(tail -n 1 "$log")
                    rm -f "$log"
                    if [ "${BLOCKING_REQUIRED:-}" = 1 ] && [ "$last" != "== the blocking check passed" ]; then
                        echo "$check ended without its last line, with BLOCKING_REQUIRED=1: '$last'" >&2
                        exit 1
                    fi
                    ;;
                *) "$ROOT/scripts/$check" ;;
            esac
        done
        echo "== Emulator shard $shard passed"
        ;;
esac
