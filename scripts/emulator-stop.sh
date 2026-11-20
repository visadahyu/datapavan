#!/usr/bin/env bash
# Stops CI's emulator once its shard passed, within a bound (docs/ci-flakes.md, 2026-11-19): `adb emu kill`, then up
# to 60 s for the emulator's virtual machine to end, then SIGKILL to it, with a warning on the run. In the W7 spike's
# run the emulator runner's own `emu kill` was answered and the emulator never ended, which held the screens shard
# to its time limit although every check had passed. On CI only, where the job's one emulator is this one: it
# refuses to run anywhere else.
#
#   scripts/emulator-stop.sh emulator-5554
set -euo pipefail

serial=${1:?usage: $0 emulator-NNNN}
[ "${GITHUB_ACTIONS:-}" = true ] || { echo "refused: this stops CI's emulator only" >&2; exit 2; }
running() { pgrep '^qemu-system' >/dev/null; }
adb -s "$serial" emu kill >/dev/null 2>&1 || true
for _ in $(seq 60); do
    running || { echo "the emulator stopped"; exit 0; }
    sleep 1
done
echo "::warning title=The emulator did not stop::60 s after emu kill $serial still ran; it was killed (docs/ci-flakes.md, 2026-11-19)"
pkill -KILL '^qemu-system' || true
