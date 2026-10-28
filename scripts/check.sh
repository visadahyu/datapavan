#!/usr/bin/env bash
# Runs every quality gate. CI calls this script; run it locally before pushing.
#
#   scripts/check.sh          all gates
#   scripts/check.sh rust     Rust gates only
#   scripts/check.sh android  Android gates only (builds the Rust library as part of it)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WHAT="${1:-all}"

rust_gates() {
    echo "== Rust: format, lint, test, dependency policy"
    cd "$ROOT/core"
    cargo fmt --all --check
    cargo clippy --workspace --all-targets --locked -- -D warnings
    cargo test --workspace --locked
    cargo deny --locked check
}

android_gates() {
    echo "== Android: lint, unit tests, debug and release builds (includes the permission guard)"
    cd "$ROOT/android"
    ./gradlew --no-daemon --stacktrace lintDebug testDebugUnitTest assembleDebug assembleRelease
}

case "$WHAT" in
    rust) rust_gates ;;
    android) android_gates ;;
    all) rust_gates; android_gates ;;
    *) echo "usage: $0 [all|rust|android]" >&2; exit 2 ;;
esac

echo "== all requested gates passed"
