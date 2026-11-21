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
#   scripts/check.sh wglab    W7's interoperation lab: the engine's WireGuard tunnels against peers of both
#                             reference implementations, the Linux kernel's WireGuard and wireguard-go, in the
#                             Compose project datapavan-wglab (scripts/wglab.sh); needs Docker, the wireguard module
#                             and /dev/net/tun; about a minute, stopped at the end; WGLAB_LONG=1 adds the checks that
#                             take minutes
#   scripts/check.sh advanced-debug
#                             Advanced's debug APK alone, for the wireguard emulator shard of CI's weekly run
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
    # The per-tool guides for proxy mode against the table of tools and Watch's strings (W8, part 3b), and the check's
    # own test; build-site.sh below writes their pages from the same data.
    python3 -I "$ROOT/scripts/guides.py" || failed=1
    python3 -I "$ROOT/scripts/guides.py" --self-test || failed=1
    # Telegram's ranges' fetcher refuses too wide a range (ADR 0052, fix round).
    python3 -I "$ROOT/data/messengers/update.py" --self-test || failed=1
    # What a translation can break without anyone reading it (ADR 0030).
    python3 -I "$ROOT/scripts/check-translations.py" || failed=1
    # The emulator checks read "Now" from the screen with now-screen.py, which must see a row's places.
    python3 -I "$ROOT/scripts/now-screen.py" --self-test || failed=1
    # The speed budget's verdict for direct apps' names (ADR 0039), on made-up numbers: the measure itself needs the
    # public operators and runs before each release (docs/RELEASE.md).
    python3 -I "$ROOT/scripts/dns-latency.py" --self-test || failed=1
    # The emulator checks find the ports of this computer their test servers take free before they start.
    "$ROOT/scripts/host-ports.sh" --self-test || failed=1
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
    python3 -I "$ROOT/scripts/check-lab-privacy.py" --self-test
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
    # For Android through cargo-ndk, as Gradle builds the library: since W7, GotaTun's aws-lc-sys compiles C
    # for the target, which needs the NDK's clang (ADR 0035). The NDK is the version the app builds with.
    local ndk
    ndk=$(sed -n 's/^ *ndkVersion = "\(.*\)"/\1/p' "$ROOT/android/app/build.gradle.kts")
    export ANDROID_NDK_HOME="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-$HOME/Android/sdk}}/ndk/$ndk"
    for abi in arm64-v8a armeabi-v7a x86_64; do
        cargo ndk -t "$abi" --platform 29 clippy --workspace --all-targets --locked -- -D warnings
    done
    cargo test --workspace --locked
    # The fuzz crate has a lockfile of its own, which a new dependency of the engine must reach too
    # (CI's fuzz run, 2026-11-12: nix came in and only the workspace's lockfile had it).
    (cd "$ROOT/core/fuzz" && cargo metadata --locked --format-version 1 >/dev/null)
    # And its targets must still build against the engine's API, which only CI's fuzz run used to find
    # (W5's first part, 2026-11-18: the DNS cache came to take the time since start). On stable Rust a
    # check is enough; the sanitizers and cargo-fuzz stay in CI.
    echo "== Rust: the fuzz targets build against the engine"
    (cd "$ROOT/core/fuzz" && cargo check --locked --bins --quiet)
    # Basic's native code (core/jni) holds no network crate (ADR 0045, decision 9): Android keeps an app
    # without INTERNET off the network, and this keeps the code from even trying. Read whole: under
    # pipefail, a grep that stops reading early fails the pipe.
    echo "== Rust: Basic's native library holds no network crate"
    local crates network
    crates=$(cargo tree --locked -p datapavan-jni -e normal --prefix none --target all | sed 's/ .*//' | sort -u)
    network=$(grep -xE 'datapavan-net|socket2|mio|tokio|nix|hyper|h2|reqwest|ureq|rustls|native-tls|openssl|quinn|smoltcp' <<<"$crates" || true)
    [ -z "$network" ] || { echo "Basic's native library depends on network crates: $network" >&2; exit 1; }
    netlab_gate
    # The licence texts of the native libraries' crates, which the APKs carry (W7's fix round, review M4): what
    # core/Cargo.lock gives, and no crate without one.
    echo "== Rust: licences/ holds the texts of every crate inside the native libraries (scripts/licences.py)"
    python3 -I "$ROOT/scripts/licences.py" --check
    # Needs network access to fetch the RustSec advisory database.
    cargo deny --locked check
}

# Fails when the library $2 in the APK $1 is missing for one of the app's ABIs or larger than $3 bytes in it.
native_budget() {
    local apk=$1 lib=$2 budget=$3 abi size listing
    listing=$(unzip -l "$apk")
    for abi in arm64-v8a armeabi-v7a x86_64; do
        size=$(awk -v path="lib/$abi/$lib" '$4 == path {print $1}' <<<"$listing")
        [ -n "$size" ] || { echo "$apk has no lib/$abi/$lib" >&2; exit 1; }
        echo "  $abi: $size bytes"
        [ "$size" -le "$budget" ] || { echo "lib/$abi/$lib is $size bytes, over its budget of $budget" >&2; exit 1; }
    done
}

# Fails when the APK $1 does not carry, under assets/licences/, each of the files $2... as the repository has
# them (NOTICE, W7's fix round, review M4).
licence_texts() {
    local apk=$1 file
    shift
    for file in "$@"; do
        cmp -s <(unzip -p "$apk" "assets/licences/$(basename "$file")") "$ROOT/$file" ||
            { echo "$apk does not carry $file as assets/licences/$(basename "$file")" >&2; exit 1; }
    done
    echo "  $(basename "$apk"): $*"
}

android_gates() {
    echo "== Android: plain English strings (scripts/plain-language.py)"
    python3 -I "$ROOT/scripts/plain-language.py" "$ROOT/android/app/src/main/res/values/strings.xml"
    python3 -I "$ROOT/scripts/plain-language.py" "$ROOT/android/watch/src/main/res/values/strings.xml"
    # Strings in English only until ADR 0030's translation and review moves them into strings.xml.
    for pending in "$ROOT"/android/*/src/main/res/values/strings_untranslated.xml; do
        [ ! -f "$pending" ] || python3 -I "$ROOT/scripts/plain-language.py" "$pending"
    done
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
    # Watch's native library, as Advanced's release APK ships it (stripped), stays within its budget per ABI:
    # 2 MB, set by the maintainer on 2026-11-19 after W7's spike measured 1.22 to 1.59 MB today and about 1.35 to
    # 1.80 with WireGuard's core (ADR 0035, question 3; VPN.md). Nothing held the earlier target of 1 MB, and the
    # library grew past it unnoticed.
    echo "== Android: Watch's native library within 2 MB per ABI (ADR 0035)"
    native_budget "$out/build-advanced/outputs/apk/release/app-release-unsigned.apk" libdatapavan_watch.so 2097152
    # The table of the Java and Kotlin libraries comes along, held by the build to each variant's classpath
    # (checkJvmComponents): the licence screen reads its list from these files (W7, part 2).
    echo "== Android: the release APKs carry NOTICE, their native libraries' licence texts and their libraries' table (licences/)"
    licence_texts "$out/build/outputs/apk/release/app-release-unsigned.apk" NOTICE LICENSE licences/native-core.txt \
        licences/jvm-components.tsv
    licence_texts "$out/build-advanced/outputs/apk/release/app-release-unsigned.apk" NOTICE LICENSE \
        licences/native-core.txt licences/native-watch.txt licences/MPL-2.0.txt licences/gotatun-BSD-3-Clause.txt \
        licences/jvm-components.tsv
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
    wglab)
        echo "== Rust: the engine's WireGuard against the kernel's and wireguard-go (scripts/wglab.sh)"
        "$ROOT/scripts/wglab.sh"
        ;;
    advanced-debug)
        echo "== Android: Advanced's debug APK"
        cd "$ROOT/android"
        ./gradlew --no-daemon --stacktrace -Pdatapavan.edition=advanced --project-cache-dir .gradle-advanced \
            :app:assembleDebug
        ;;
    all) data_gates; lab_gates; rust_gates; android_gates ;;
    *) echo "usage: $0 [all|rust|android|data|lab|wglab|advanced-debug]" >&2; exit 2 ;;
esac

echo "== all requested gates passed"
