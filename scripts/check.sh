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
#   scripts/check.sh resolve  Gradle's plugins and dependencies of both editions, resolved and fetched, nothing built,
#                             tried up to three times, 60 s then 180 s apart, saying what the repositories answer after
#                             each failed try: CI's build job runs it before its gates
#   scripts/check.sh prepush  right before a push, three things CI's run fetches from outside that can move while the
#                             repository stands still: cargo-deny at CI's version, its advisory database and crates.io's
#                             yanked list fetched afresh; every lab image's install steps, the installs simulated
#                             (scripts/lab-pins.py, Docker); Gradle's plugins and dependencies of both editions, asked of
#                             the repositories again. No build, no emulator, a minute or two; each part is reported, and
#                             the check fails if any did. LABPINS=skip leaves out the lab images and says so
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
    # The screens' accessibility check measures what it is for: contrast as ATF does, the raw capture, large text and
    # the keyboard walk, on made-up screens (docs/ACCESSIBILITY.md).
    python3 -I "$ROOT/scripts/a11y-check-test.py" || failed=1
    # The per-tool guides for proxy mode against the table of tools and the network part's strings (W8, part 3b), and
    # the check's own test; build-site.sh below writes their pages from the same data.
    python3 -I "$ROOT/scripts/guides.py" || failed=1
    python3 -I "$ROOT/scripts/guides.py" --self-test || failed=1
    # Android's own labels (ADR 0054): the rows of data/android-labels and every android_label_* fallback, in eight
    # languages, against AOSP's text as scripts/testdata/android-labels-aosp.tsv records it, and the check's own test.
    python3 -I "$ROOT/scripts/android-labels.py" || failed=1
    python3 -I "$ROOT/scripts/android-labels.py" --self-test || failed=1
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
    # The pre-push check of the lab images' packages reads every Dockerfile: one it cannot read fails here, in CI,
    # rather than going unchecked before a push (check.sh prepush).
    python3 -I "$ROOT/scripts/lab-pins.py" --self-test || failed=1
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

# Fails unless the network part's library $2 in the release APK $1 keeps its unwind tables as the size pass left them
# (ADR 0053): x86_64's is linked without their index (core/network-jni/build.rs), so a crash's tombstone finds the
# tables through the section headers alone, and nothing may strip those; arm64-v8a's keeps the index. $3 is the NDK.
unwind_tables() {
    local apk=$1 lib=$2 readelf="$3/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-readelf" work sections segments
    work=$(mktemp -d)
    unzip -p "$apk" "lib/x86_64/$lib" >"$work/x86_64.so"
    unzip -p "$apk" "lib/arm64-v8a/$lib" >"$work/arm64-v8a.so"
    sections=$("$readelf" -SW "$work/x86_64.so")
    segments=$("$readelf" -lW "$work/x86_64.so")
    grep -qE ' \.eh_frame +PROGBITS' <<<"$sections" || { echo "lib/x86_64/$lib has no .eh_frame section" >&2; exit 1; }
    ! grep -q GNU_EH_FRAME <<<"$segments" || { echo "lib/x86_64/$lib has its unwind index again" >&2; exit 1; }
    segments=$("$readelf" -lW "$work/arm64-v8a.so")
    grep -q GNU_EH_FRAME <<<"$segments" || { echo "lib/arm64-v8a/$lib has lost its unwind index" >&2; exit 1; }
    rm -rf "$work"
    echo "  x86_64: .eh_frame, read through the section headers, no index; arm64-v8a: .eh_frame with its index"
}

# Fails when a native library of the APK $1, $2 on each ABI, names crates.io's sources by their directory: both
# native tasks remap it to /c (the cold paths' third pass, ADR 0053), and a cargo that named the directory otherwise
# would bring back about 5.6 KB per ABI unseen. Read from a file, not a pipe that grep could close early.
registry_paths() {
    local apk=$1 lib=$2 abi work
    work=$(mktemp -d)
    for abi in arm64-v8a armeabi-v7a x86_64; do
        unzip -p "$apk" "lib/$abi/$lib" >"$work/lib.so" 2>/dev/null || true
        [ -s "$work/lib.so" ] || { echo "$apk has no lib/$abi/$lib" >&2; exit 1; }
        ! grep -qaF /cargo/registry/src/index.crates.io- "$work/lib.so" ||
            { echo "lib/$abi/$lib names crates.io's sources by their directory: the remap to /c is lost" >&2; exit 1; }
    done
    rm -rf "$work"
    echo "  $(basename "$apk"): $lib, crates.io's sources as /c on every ABI"
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
    python3 -I "$ROOT/scripts/plain-language.py" "$ROOT/android/network/src/main/res/values/strings.xml"
    # Strings in English only until ADR 0030's translation and review moves them into strings.xml.
    for pending in "$ROOT"/android/*/src/main/res/values/strings_untranslated.xml; do
        [ ! -f "$pending" ] || python3 -I "$ROOT/scripts/plain-language.py" "$pending"
    done
    echo "== Android: the network part's colours are the audit app's (network/.../ui/Theme.kt)"
    diff <(grep -o 'Color(0x[0-9A-F]*)' "$ROOT/android/app/src/main/java/org/visadahyu/datapavan/ui/Theme.kt") \
        <(grep -o 'Color(0x[0-9A-F]*)' "$ROOT/android/network/src/main/java/org/visadahyu/datapavan/network/ui/Theme.kt")
    echo "== Android: lint, unit tests, APK and bundle builds of Basic, its allowlist, native-library check"
    cd "$ROOT/android"
    ./gradlew --no-daemon --stacktrace \
        lintDebug lintRelease testDebugUnitTest \
        assembleDebug assembleRelease bundleRelease \
        verifyApkDebug verifyApkRelease
    # Advanced builds in android/app/build-advanced, with a task history of its own; lint covers the network part's
    # library through the app.
    echo "== Android: lint, APK and bundle builds of Advanced, its allowlist, native-library check (ADR 0045)"
    ./gradlew --no-daemon --stacktrace -Pdatapavan.edition=advanced --project-cache-dir .gradle-advanced \
        :app:lintDebug :app:lintRelease :app:testDebugUnitTest \
        :app:assembleDebug :app:assembleRelease :app:bundleRelease \
        :app:verifyApkDebug :app:verifyApkRelease
    echo "== Android: no release APK or bundle holds a class or a package of the lab (ADR 0048)"
    local out
    out="$ROOT/android/app"
    # The network part's native library, as Advanced's release APK ships it (stripped), stays within its budget per ABI:
    # 2 MB, set by the maintainer on 2026-11-19 after W7's spike measured 1.22 to 1.59 MB today and about 1.35 to
    # 1.80 with WireGuard's core (ADR 0035, question 3; VPN.md). Nothing held the earlier target of 1 MB, and the
    # library grew past it unnoticed.
    echo "== Android: the network part's native library within 2 MB per ABI (ADR 0035)"
    native_budget "$out/build-advanced/outputs/apk/release/app-release-unsigned.apk" libdatapavan_network.so 2097152
    echo "== Android: the network part's unwind tables, for tombstones (ADR 0053, the size pass)"
    unwind_tables "$out/build-advanced/outputs/apk/release/app-release-unsigned.apk" libdatapavan_network.so \
        "${ANDROID_HOME:-${ANDROID_SDK_ROOT:-$HOME/Android/sdk}}/ndk/$(sed -n 's/^ *ndkVersion = "\(.*\)"/\1/p' "$ROOT/android/app/build.gradle.kts")"
    echo "== Android: both native libraries name crates.io's sources by the short remap (ADR 0053, the third pass)"
    registry_paths "$out/build-advanced/outputs/apk/release/app-release-unsigned.apk" libdatapavan_network.so
    registry_paths "$out/build/outputs/apk/release/app-release-unsigned.apk" libdatapavan.so
    # The table of the Java and Kotlin libraries comes along, held by the build to each variant's classpath
    # (checkJvmComponents): the licence screen reads its list from these files (W7, part 2).
    echo "== Android: the release APKs carry NOTICE, their native libraries' licence texts and their libraries' table (licences/)"
    licence_texts "$out/build/outputs/apk/release/app-release-unsigned.apk" NOTICE LICENSE licences/native-core.txt \
        licences/jvm-components.tsv
    licence_texts "$out/build-advanced/outputs/apk/release/app-release-unsigned.apk" NOTICE LICENSE \
        licences/native-core.txt licences/native-network.txt licences/MPL-2.0.txt licences/gotatun-BSD-3-Clause.txt \
        licences/jvm-components.tsv
    lab_class_check "$ROOT/android" \
        "$out/build/outputs/apk/release/app-release-unsigned.apk" "$out/build/outputs/bundle/release/app-release.aab" \
        "$out/build/outputs/mapping/release/mapping.txt" \
        "$out/build-advanced/outputs/apk/release/app-release-unsigned.apk" "$out/build-advanced/outputs/bundle/release/app-release.aab" \
        "$out/build-advanced/outputs/mapping/release/mapping.txt"
}

# Gradle's plugins and the external modules of every configuration Gradle can resolve, of both editions, resolved and
# fetched where missing, with nothing built (scripts/prepush-resolve.init.gradle.kts). Its arguments go to both runs.
# The libraries read no edition, so Advanced's run resolves only the app, whose graph takes the network part.
gradle_resolve() {
    local init="$ROOT/scripts/prepush-resolve.init.gradle.kts"
    (cd "$ROOT/android" &&
        ./gradlew --no-daemon --quiet --no-configuration-cache --init-script "$init" "$@" prepushResolve &&
        ./gradlew --no-daemon --quiet --no-configuration-cache --init-script "$init" "$@" \
            -Pdatapavan.edition=advanced --project-cache-dir .gradle-advanced :app:prepushResolve)
}

# What each repository answers now for the modules that the failed resolution in the file $1 names: Gradle reports a
# plugin's marker as "not found" whatever the repository answered, at every log level, so the run asks the two itself
# (a HEAD of each module's POM: an HTTP status, the address that gave it, the time).
repository_answers() {
    local coordinates coordinate group artifact version base url
    coordinates=$(grep -oE "(plugin artifact '|Could not (find|resolve) )[A-Za-z0-9_.-]+:[A-Za-z0-9_.-]+:[A-Za-z0-9_.+-]+" "$1" |
        grep -oE "[A-Za-z0-9_.-]+:[A-Za-z0-9_.-]+:[A-Za-z0-9_.+-]+$" | sed 's/\.$//' | sort -u | head -n 5 || true)
    for coordinate in $coordinates; do
        IFS=: read -r group artifact version <<<"$coordinate"
        for base in https://dl.google.com/dl/android/maven2 https://repo.maven.apache.org/maven2; do
            url="$base/${group//.//}/$artifact/$version/$artifact-$version.pom"
            echo "  $url: $(curl -sS -o /dev/null -I --max-time 20 -w '%{http_code} from %{remote_ip} in %{time_total} s' "$url" 2>&1 || true)" >&2
        done
    done
}

# CI's build job, before its gates: what they resolve, fetched first and tried up to three times, so that a
# repository's blip during the run (the Compose plugin's marker, docs/ci-flakes.md) is retried where it happens, with a
# warning on the run, rather than failing a gate. Three tries 30 s apart did not ride out the marker's fourth failure,
# so the waits are 60 s, then 180 s. The second try asks again only for what is missing, since an error answer is not
# kept and a refresh would ask again for every module, which a rate limit would only make worse; the third asks the
# repositories again for everything, since Gradle keeps a 404 as "missing". After each failed try the run says what the
# repositories answer for the modules it names (repository_answers). In the weekly run of main it also fills the cache
# entry that main saves with every module of both editions.
resolve_gate() {
    echo "== Android: Gradle's plugins and dependencies of both editions, resolved before the gates"
    local try wait log
    log=$(mktemp)
    for try in 1 2 3; do
        if [ "$try" -lt 3 ]; then
            gradle_resolve >"$log" 2>&1 && break
        else
            gradle_resolve --refresh-dependencies >"$log" 2>&1 && break
        fi
        cat "$log" >&2
        echo "What the repositories answer now:" >&2
        repository_answers "$log"
        if [ "$try" -eq 3 ]; then
            rm -f "$log"
            echo "Gradle's plugins and dependencies did not resolve in three tries" >&2
            return 1
        fi
        wait=$((try == 1 ? 60 : 180))
        echo "${GITHUB_ACTIONS:+::warning::}Gradle's plugins and dependencies did not resolve (try $try of 3): again in $wait s" >&2
        sleep "$wait"
    done
    cat "$log"
    rm -f "$log"
}

# Right before a push, three things CI's run will fetch from outside that can move while nothing in the repository
# changes. What each part finds: a new RustSec advisory or a yanked crate (cargo-deny, CI's failure of 2026-11-24); a lab
# pin the image's sources do not hold, before CI meets it (Alpine dropped one that day; the labs now read fixed Debian
# snapshots, so this finds a pin edited wrong, or the snapshot service down); a plugin or a library the repositories do
# not give now. A blip of a repository during CI's own run is beyond it: resolve_gate retries Gradle's in CI. Left out,
# most fixed by a checksum or a digest and so able to blip but not to drift: lint's Play SDK Index, which CI's lint reads;
# AAPT2's binary; what the lab images' build stages fetch (odoh-server-go's git clone at a commit, which can drift if its
# history is rewritten, the crates and Go modules) and their base images; the Android SDK's packages, Gradle's
# distribution, the Rust toolchain and the emulator's system image.
prepush_gates() {
    local failed=0
    # CI's own command at CI's own version, its warnings of crates in two versions left to CI's log: the advisory
    # database's format moves, and two versions of cargo-deny can read it differently.
    echo "== Pre-push: cargo-deny as CI runs it, its advisory database and crates.io's yanked list fetched afresh"
    local want have
    want=$(sed -n 's/^ *CARGO_DENY_VERSION: "\(.*\)"$/\1/p' "$ROOT/.github/workflows/ci.yml")
    have=$(cargo deny --version 2>/dev/null || true)
    have=${have#cargo-deny }
    if [ -z "$want" ] || [ "$have" != "$want" ]; then
        echo "cargo-deny is ${have:-missing} here and ${want:-not named} in CI (ci.yml's CARGO_DENY_VERSION):" \
            "cargo install cargo-deny --version $want --locked" >&2
        failed=1
    else
        (cd "$ROOT/core" && cargo deny --log-level error --locked check) || failed=1
    fi
    echo "== Pre-push: every lab image's install steps, run as written with the installs simulated (scripts/lab-pins.py)"
    if [ "${LABPINS:-}" = skip ]; then
        echo "!! LABPINS=skip: the lab images' packages were NOT CHECKED" >&2
    else
        python3 -I "$ROOT/scripts/lab-pins.py" || failed=1
    fi
    # Asked of the repositories again, never answered from the cache alone, which would pass here whatever they hold.
    echo "== Pre-push: Gradle's plugins and dependencies, Basic and Advanced, asked of the repositories again"
    gradle_resolve --refresh-dependencies || failed=1
    [ "$failed" -eq 0 ]
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
    resolve) resolve_gate ;;
    prepush) prepush_gates ;;
    all) data_gates; lab_gates; rust_gates; android_gates ;;
    *) echo "usage: $0 [all|rust|android|data|lab|wglab|advanced-debug|resolve|prepush]" >&2; exit 2 ;;
esac

echo "== all requested gates passed"
