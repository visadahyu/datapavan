#!/usr/bin/env bash
# Runs every quality gate. CI calls this script; run it locally before pushing.
#
#   scripts/check.sh          all gates
#   scripts/check.sh rust     Rust gates only
#   scripts/check.sh android  Android gates only (builds the Rust library as part of it)
#   scripts/check.sh data     bundled datasets only
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WHAT="${1:-all}"

data_gates() {
    echo "== Data: licence and source of every bundled dataset (ADR 0015)"
    local failed=0 dir file
    for dir in "$ROOT"/data/*/; do
        for file in LICENSE SOURCE; do
            if ! grep -q 'SPDX-License-Identifier:' "$dir$file" 2>/dev/null; then
                echo "${dir#"$ROOT/"}$file is missing or has no SPDX-License-Identifier" >&2
                failed=1
            fi
        done
        # Every other file names its licence in its first lines or in a REUSE sidecar file.
        for file in "$dir"*; do
            case "$file" in */LICENSE | */SOURCE | *.license) continue ;; esac
            if ! head -n 5 "$file" | grep -q 'SPDX-License-Identifier:' && [ ! -f "$file.license" ]; then
                echo "${file#"$ROOT/"} names no licence" >&2
                failed=1
            fi
        done
    done
    # The data pack's header (docs/DATA-PACKS.md); the Gradle build checks its values.
    if ! grep -q 'SPDX-License-Identifier:' "$ROOT/data/PACK" 2>/dev/null ||
        ! grep -qE '^sequence [1-9][0-9]*$' "$ROOT/data/PACK" || ! grep -qE '^date [0-9]{4}-[0-9]{2}-[0-9]{2}$' "$ROOT/data/PACK"; then
        echo "data/PACK is missing, or lacks its licence, sequence or date" >&2
        failed=1
    fi
    # Every published copy of the project's keys (ADR 0024).
    python3 -I "$ROOT/scripts/check-keys.py" || failed=1
    # What a translation can break without anyone reading it (ADR 0030).
    python3 -I "$ROOT/scripts/check-translations.py" || failed=1
    # The website in docs/site is what site/ builds, and it keeps the site's rules.
    "$ROOT/scripts/build-site.sh" --check || failed=1
    [ "$failed" -eq 0 ]
}

rust_gates() {
    echo "== Rust: format, lint, test, dependency policy"
    cd "$ROOT/core"
    cargo fmt --all --check
    cargo clippy --workspace --all-targets --locked -- -D warnings
    for target in aarch64-linux-android armv7-linux-androideabi x86_64-linux-android; do
        cargo clippy --workspace --all-targets --locked --target "$target" -- -D warnings
    done
    cargo test --workspace --locked
    # Needs network access to fetch the RustSec advisory database.
    cargo deny --locked check
}

android_gates() {
    echo "== Android: plain English strings (scripts/plain-language.py)"
    python3 -I "$ROOT/scripts/plain-language.py" "$ROOT/android/app/src/main/res/values/strings.xml"
    echo "== Android: lint, unit tests, APK and bundle builds, permission guard, native-library check"
    cd "$ROOT/android"
    ./gradlew --no-daemon --stacktrace \
        lintDebug lintRelease testDebugUnitTest \
        assembleDebug assembleRelease bundleRelease \
        verifyApkDebug verifyApkRelease
}

case "$WHAT" in
    rust) rust_gates ;;
    android) android_gates ;;
    data) data_gates ;;
    all) data_gates; rust_gates; android_gates ;;
    *) echo "usage: $0 [all|rust|android|data]" >&2; exit 2 ;;
esac

echo "== all requested gates passed"
