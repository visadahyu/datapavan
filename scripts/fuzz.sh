#!/usr/bin/env bash
# Runs every fuzz target in core/fuzz for a while. CI runs it on every change. Debug assertions and
# overflow checks are on (cargo fuzz's default), with AddressSanitizer.
#
# Needs the pinned nightly toolchain and cargo-fuzz:
#   rustup toolchain install nightly-2026-10-01 --profile minimal
#   cargo install cargo-fuzz --version 0.13.2 --locked
#
#   scripts/fuzz.sh [seconds in all, default 240]
#
# The time is shared evenly among the targets, so that a new target does not make a run outlast the
# time limit of its CI job.
#
# Inputs that find a bug are saved in core/fuzz/artifacts/<target>/; seeds live in
# core/fuzz/seeds/<target>/, and the growing corpus in core/fuzz/corpus/<target>/ (not committed).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NIGHTLY=nightly-2026-10-01
TOTAL_SECONDS="${1:-240}"

cd "$ROOT/core"
# Fails if fuzz/Cargo.lock would change, as --locked does for the other builds.
cargo +"$NIGHTLY" metadata --locked --format-version 1 --manifest-path fuzz/Cargo.toml >/dev/null

targets=$(cargo +"$NIGHTLY" fuzz list)
SECONDS_PER_TARGET=$((TOTAL_SECONDS / $(wc -w <<<"$targets")))
# libFuzzer reads -max_total_time=0 as no limit.
if ((SECONDS_PER_TARGET < 1)); then
    echo "fuzz.sh: $TOTAL_SECONDS s is less than a second for each target" >&2
    exit 1
fi

for target in $targets; do
    echo "== Fuzzing $target for $SECONDS_PER_TARGET s"
    mkdir -p "fuzz/corpus/$target"
    cargo +"$NIGHTLY" fuzz run "$target" "fuzz/corpus/$target" "fuzz/seeds/$target" -- \
        -max_total_time="$SECONDS_PER_TARGET" -max_len=4096 -timeout=10 -print_final_stats=1
done

echo "== fuzzing found nothing"
