#!/usr/bin/env bash
# Runs every quality gate. CI calls this script; run it locally before pushing.
#
#   scripts/check.sh          all gates
#   scripts/check.sh rust     Rust gates only
#   scripts/check.sh android  Android gates only (builds the Rust library as part of it)
#   scripts/check.sh data     bundled datasets, published keys, the documents' truth, translations and
#                             the website: no build, so CI runs it on every push, documents only included
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
    # What the public documents say, against the code and the record (ADR 0039), and the check's own test.
    python3 -I "$ROOT/scripts/check-truth.py" || failed=1
    python3 -I "$ROOT/scripts/check-truth-test.py" || failed=1
    # What a translation can break without anyone reading it (ADR 0030).
    python3 -I "$ROOT/scripts/check-translations.py" || failed=1
    # The website in docs/site is what site/ builds, and it keeps the site's rules.
    "$ROOT/scripts/build-site.sh" --check || failed=1
    [ "$failed" -eq 0 ]
}

# The engine in its network lab (core/net/tests/netlab.rs, ADR 0044): a real tun device in an
# unprivileged user and network namespace. A machine that cannot make one fails here, with the reason,
# rather than passing without the tests; NETLAB=skip runs the other gates and says plainly that these
# did not run.
netlab_gate() {
    echo "== Rust: the engine in its network lab"
    if [ "${NETLAB:-}" = skip ]; then
        echo "!! NETLAB=skip: the network lab tests were NOT RUN" >&2
        return 0
    fi
    local probe
    if ! probe=$(unshare --user --map-root-user --net sh -c 'ip link set lo up && ip tuntap add mode tun dev probe0' 2>&1); then
        echo "no network lab here (a user namespace with a tun device): $probe" >&2
        echo "set NETLAB=skip to run the other gates without it" >&2
        return 1
    fi
    cargo test -p datapavan-net --test netlab --locked -- --ignored
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
    # The fuzz crate has a lockfile of its own, which a new dependency of the engine must reach too
    # (CI's fuzz run, 2026-11-12: nix came in and only the workspace's lockfile had it).
    (cd "$ROOT/core/fuzz" && cargo metadata --locked --format-version 1 >/dev/null)
    # Basic's native code (core/jni) holds no network crate (ADR 0045, decision 9): Android keeps an app
    # without INTERNET off the network, and this keeps the code from even trying. Read whole: under
    # pipefail, a grep that stops reading early fails the pipe.
    echo "== Rust: Basic's native library holds no network crate"
    local crates network
    crates=$(cargo tree --locked -p datapavan-jni -e normal --prefix none --target all | sed 's/ .*//' | sort -u)
    network=$(grep -xE 'datapavan-net|socket2|mio|tokio|nix|hyper|h2|reqwest|ureq|rustls|native-tls|openssl|quinn|smoltcp' <<<"$crates" || true)
    [ -z "$network" ] || { echo "Basic's native library depends on network crates: $network" >&2; exit 1; }
    netlab_gate
    # Needs network access to fetch the RustSec advisory database.
    cargo deny --locked check
}

android_gates() {
    echo "== Android: plain English strings (scripts/plain-language.py)"
    python3 -I "$ROOT/scripts/plain-language.py" "$ROOT/android/app/src/main/res/values/strings.xml"
    python3 -I "$ROOT/scripts/plain-language.py" "$ROOT/android/watch/src/main/res/values/strings.xml"
    echo "== Android: Watch's colours are the audit app's (watch/.../ui/Theme.kt)"
    diff <(grep -o 'Color(0x[0-9A-F]*)' "$ROOT/android/app/src/main/java/org/visadahyu/datapavan/ui/Theme.kt") \
        <(grep -o 'Color(0x[0-9A-F]*)' "$ROOT/android/watch/src/main/java/org/visadahyu/datapavan/watch/ui/Theme.kt")
    echo "== Android: lint, unit tests, APK and bundle builds of Basic, its allowlist, native-library check"
    cd "$ROOT/android"
    ./gradlew --no-daemon --stacktrace \
        lintDebug lintRelease testDebugUnitTest \
        assembleDebug assembleRelease bundleRelease \
        verifyApkDebug verifyApkRelease
    # Advanced builds in android/app/build-advanced; lint covers Watch's library through the app.
    echo "== Android: lint, APK and bundle builds of Advanced, its allowlist, native-library check (ADR 0045)"
    ./gradlew --no-daemon --stacktrace -Pdatapavan.edition=advanced \
        :app:lintDebug :app:lintRelease :app:testDebugUnitTest \
        :app:assembleDebug :app:assembleRelease :app:bundleRelease \
        :app:verifyApkDebug :app:verifyApkRelease
}

case "$WHAT" in
    rust) rust_gates ;;
    android) android_gates ;;
    data) data_gates ;;
    all) data_gates; rust_gates; android_gates ;;
    *) echo "usage: $0 [all|rust|android|data]" >&2; exit 2 ;;
esac

echo "== all requested gates passed"
