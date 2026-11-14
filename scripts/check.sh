#!/usr/bin/env bash
# Runs every quality gate. CI calls this script; run it locally before pushing.
#
#   scripts/check.sh          all gates
#   scripts/check.sh rust     Rust gates only
#   scripts/check.sh android  Android gates only (builds the Rust library as part of it)
#   scripts/check.sh data     bundled datasets, published keys, the documents' truth, translations and
#                             the website: no build, so CI runs it on every push, documents only included
#   scripts/check.sh lab      the lab's gaps probe and fixture (ADR 0048): their build with the SDK's build
#                             tools, the fixture's missing INTERNET permission, the tools' unit tests, the
#                             README's tables against results.csv, and the published runs' privacy; seconds,
#                             so CI runs it on every push too
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

# The lab's probe of Android's platform gaps (ADR 0048, decision 7): both apps built with the SDK's build tools
# alone, the fixture without the INTERNET permission (decision 5), the JVM tests of the tools that turn a run
# into rows, and the README's tables, which only the tools write, against results.csv.
lab_gates() {
    echo "== Lab: the gaps probe, its peer and the fixture build with the SDK's tools alone"
    "$ROOT/lab/gaps-probe/build.sh" >/dev/null
    "$ROOT/lab/gaps-probe/build.sh" --peer >/dev/null
    "$ROOT/lab/gaps-fixture/build.sh" >/dev/null
    echo "== Lab: the fixture holds no INTERNET permission (ADR 0048, decision 5)"
    fixture_no_internet
    echo "== Lab: the gaps tools' unit tests, and the README's tables against results.csv"
    "$ROOT/lab/gaps-tools/build.sh"
    java -cp "$ROOT/build/gaps-tools/classes" org.visadahyu.lab.gapstools.GapsTable check \
        "$ROOT/docs/platform-gaps/results.csv" "$ROOT/docs/platform-gaps/README.md"
    echo "== Lab: no published run holds an address or a name of the network that ran it"
    python3 -I "$ROOT/scripts/check-lab-privacy.py"
    echo "== Lab: the release check's lab strings cover every lab app"
    python3 -I "$ROOT/scripts/check-lab-classes.py" --self-test --lab "$ROOT/lab"
}

# The fixture's manifest, and the APK its build made, name no INTERNET permission. Its build script refuses the
# same; this check holds even if the script is changed. Read whole: under pipefail, a grep -q that stops
# reading early fails the pipe.
fixture_no_internet() {
    local manifest permissions
    manifest=$(cat "$ROOT/lab/gaps-fixture/AndroidManifest.xml")
    permissions=$("${ANDROID_HOME:-${ANDROID_SDK_ROOT:-$HOME/Android/sdk}}/build-tools/37.0.0/aapt2" dump permissions \
        "$ROOT/build/gaps-fixture/gaps-fixture.apk")
    if grep -q 'android.permission.INTERNET' <<<"$manifest$permissions"; then
        echo "the lab's fixture names the INTERNET permission (ADR 0048, decision 5)" >&2
        return 1
    fi
}

# No release build holds anything of the lab (ADR 0048, decision 1): scripts/check-lab-classes.py reads every
# release APK and bundle under $1's build outputs, every archive and dex inside them, and every release
# mapping.txt, R8's record of the original names, paired with each dex by its pg-map-id, against the classes
# compiled from lab/ and the strings of its sources. Each further argument is a release file the build must
# have made.
lab_class_check() {
    local android=${1:-$ROOT/android} sdk work status=0
    shift $(($# < 1 ? 0 : 1))
    sdk="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-$HOME/Android/sdk}}"
    work=$(mktemp -d)
    javac --release 17 -XDsuppressNotes -nowarn -cp "$sdk/platforms/android-37.0/android.jar" \
        -d "$work/classes" $(find "$ROOT/lab" -name '*.java') >/dev/null
    python3 -I "$ROOT/scripts/check-lab-classes.py" --android "$android" --lab "$ROOT/lab" --lab-classes "$work/classes" \
        --dexdump "$sdk/build-tools/37.0.0/dexdump" "$@" || status=$?
    rm -rf "$work"
    return "$status"
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
    # Advanced builds in android/app/build-advanced, with a task history of its own; lint covers Watch's
    # library through the app.
    echo "== Android: lint, APK and bundle builds of Advanced, its allowlist, native-library check (ADR 0045)"
    ./gradlew --no-daemon --stacktrace -Pdatapavan.edition=advanced --project-cache-dir .gradle-advanced \
        :app:lintDebug :app:lintRelease :app:testDebugUnitTest \
        :app:assembleDebug :app:assembleRelease :app:bundleRelease \
        :app:verifyApkDebug :app:verifyApkRelease
    echo "== Android: no release APK or bundle holds a class or a package of the lab (ADR 0048)"
    local out
    out="$ROOT/android/app"
    lab_class_check "$ROOT/android" \
        "$out/build/outputs/apk/release/app-release-unsigned.apk" "$out/build/outputs/bundle/release/app-release.aab" \
        "$out/build/outputs/mapping/release/mapping.txt" \
        "$out/build-advanced/outputs/apk/release/app-release-unsigned.apk" "$out/build-advanced/outputs/bundle/release/app-release.aab" \
        "$out/build-advanced/outputs/mapping/release/mapping.txt"
}

case "$WHAT" in
    rust) rust_gates ;;
    android) android_gates ;;
    data) data_gates ;;
    lab) lab_gates ;;
    all) data_gates; lab_gates; rust_gates; android_gates ;;
    *) echo "usage: $0 [all|rust|android|data|lab]" >&2; exit 2 ;;
esac

echo "== all requested gates passed"
