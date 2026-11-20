#!/usr/bin/env bash
# What CI must run for a commit: the rule, written once, that ci.yml's scope job applies (ADR 0043).
#
# Every changed path needs one of three things:
#   none      the repository checks only (scripts/check.sh data), which run on every push anyway;
#   build     also the build and its gates (scripts/check.sh rust and android);
#   emulator  also the emulator checks (scripts/emulator-shard.sh), which need the build's APKs.
# Beside these, the WireGuard checks (W7, part 3a, ADR 0035): the cargo lab against both reference implementations
# (scripts/check.sh wglab, in the build job) and the emulator's wireguard shard. They run where a path they read
# differs from the nearest earlier commit whose run passed them both: a run in which the build and the wireguard
# shard passed, which happens only where the scope said they were needed, since the shard runs only then. The
# other shards prove the emulator checks without it. main moves by fast-forward only, so a weekly run carries them
# whatever changed (ci.yml's schedule), which also catches the runner's kernel moving without a commit.
#
# A commit is compared with the nearest earlier commit whose tree passed that work in CI, not with the
# push before it: a pushed commit whose run failed or was cancelled proves nothing, and a change after it
# is compared with what last passed. A commit needs the build unless its tree differs from a tree that
# passed the build only in paths that need none; it needs the emulator checks unless its tree differs
# from a tree that passed them only in paths that need no emulator. Paths are compared without rename
# detection, so a file moved out of the app counts as removed from it. Anything this rule does not name
# needs everything, and so does a change to the rule or to CI itself. A tree that holds a symbolic link or
# a submodule needs everything too: a path the rule lets off could then be read under another name.
#
#   scripts/ci-scope.sh tier <path>...   each path's tier
#   scripts/ci-scope.sh test             the rule against its table of paths, and the choice of the
#                                        earlier pass against a small repository built for the test
#   scripts/ci-scope.sh decide           in the scope job: writes build=, emulator=, wireguard=, shards= (the
#                                        emulator job's matrix, as JSON), weekly=false and the commits reused
#                                        to $GITHUB_OUTPUT (or prints them)
#   scripts/ci-scope.sh weekly           the same for the weekly run: the WireGuard checks alone
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# The tier of one path.
tier() {
    case $1 in
        # CI's definition and this rule: everything.
        .github/* | scripts/ci-scope.sh) echo emulator ;;
        # What the build and the emulator checks read: the apps, the engine, the toolchain, the scripts and
        # their test tools. A document among them can be bundled or compiled (a crate's README in its
        # documentation tests), so it counts as code here.
        android/* | core/* | scripts/* | rust-toolchain.toml) echo emulator ;;
        data/*) data_tier "$1" ;;
        # The lab's tools build with the SDK and have gates in the build; no emulator check runs them.
        lab/*) echo build ;;
        # Documents, brand files and the website, which the repository checks read and nothing else does.
        docs/* | brand/* | site/* | *.md) echo none ;;
        *) echo emulator ;;
    esac
}

# data/: both editions bundle every file of every dataset but the scripts that make them and hidden files
# (BundledDataTask in android/app/build.gradle.kts), and the data pack's header from data/PACK. The audit's
# pack leaves out data/dbip-asn and data/resolvers, of which Watch's build reads only asn.bin and
# resolvers.tsv (android/watch/build.gradle.kts); files at data/'s top other than PACK are not bundled.
data_tier() {
    local rest=${1#data/} name=${1##*/}
    case $rest in
        PACK | dbip-asn/asn.bin | resolvers/resolvers.tsv) echo emulator; return ;;
        dbip-asn/* | resolvers/*) echo build; return ;;
        */*) ;;
        *) echo build; return ;;
    esac
    case $name in
        *.py | *.sh | .*) echo build ;;
        *) echo emulator ;;
    esac
}

rank() { case $1 in none) echo 0 ;; build) echo 1 ;; *) echo 2 ;; esac; }

# Whether the WireGuard checks read path $1: the engine and its bridge with their build, the apps (Watch's screens and
# store run inside Advanced, which the app module builds with Basic's code), the lab's peers, the checks and what
# they share, and CI and this rule. Basic's native library, the fuzz targets, the lab's probe, the datasets and the
# documents they do not read.
wireguard_path() {
    case $1 in
        .github/* | scripts/ci-scope.sh | scripts/check.sh | scripts/emulator-shard.sh | scripts/emulator-stop.sh) return 0 ;;
        core/net/* | core/engine/* | core/watch-jni/* | core/Cargo.toml | core/Cargo.lock | rust-toolchain.toml) return 0 ;;
        android/* | spikes/wireguard-core/peer/*) return 0 ;;
        scripts/wglab.sh | scripts/verify-wireguard.sh | scripts/verify-wireguard-import.sh | scripts/workload-app/*) return 0 ;;
        scripts/adb-ui.sh | scripts/host-ports.sh | scripts/emulator-networks.sh) return 0 ;;
        *) return 1 ;;
    esac
}

# Whether a path the WireGuard checks read differs between the trees of commits $1 and $2, in repository $3.
diff_wireguard() {
    local path
    while IFS= read -r path; do
        [ -n "$path" ] || continue
        if wireguard_path "$path"; then
            echo true
            return
        fi
    done < <(git -C "$3" diff --no-renames --name-only "$1" "$2" --)
    echo false
}

# The emulator job's matrix, as JSON: every shard but wireguard where the emulator checks are needed ($1), and
# wireguard where the WireGuard checks are ($2).
shards_json() {
    local shard list=()
    for shard in $("$ROOT/scripts/emulator-shard.sh" list); do
        if { [ "$shard" = wireguard ] && [ "$2" = true ]; } || { [ "$shard" != wireguard ] && [ "$1" = true ]; }; then
            list+=("\"$shard\"")
        fi
    done
    local IFS=,
    echo "[${list[*]}]"
}

# The highest tier among the paths that differ between the trees of commits $1 and $2, in repository $3.
diff_tier() {
    local path highest=none t
    while IFS= read -r path; do
        [ -n "$path" ] || continue
        t=$(tier "$path")
        [ "$(rank "$t")" -le "$(rank "$highest")" ] || highest=$t
        [ "$highest" != emulator ] || break
    done < <(git -C "$3" diff --no-renames --name-only "$1" "$2" --)
    echo "$highest"
}

# The CI jobs that prove a tree, as "<job name> <conclusion>" lines on stdin, give what they proved, as words:
# build, or emulator (which includes the build), and wireguard. The emulator checks count only if every shard but
# wireguard passed; the WireGuard checks if the build and the wireguard shard did, which ran only where the build
# ran the cargo lab. Runs before 2026-11-14 had one job, "checks", which built and ran the emulator checks together,
# and runs before W7's part 3a no WireGuard checks.
proved() {
    local jobs shard all=1 words=""
    jobs=$(cat)
    if grep -qx 'checks success' <<<"$jobs"; then
        echo emulator
        return
    fi
    for shard in $("$ROOT/scripts/emulator-shard.sh" list); do
        [ "$shard" != wireguard ] || continue
        grep -qx "emulator $shard success" <<<"$jobs" || all=""
    done
    if [ -n "$all" ] && grep -qx 'build success' <<<"$jobs"; then
        words=emulator
    elif grep -qx 'build success' <<<"$jobs"; then
        words=build
    fi
    if grep -qx 'build success' <<<"$jobs" && grep -qx 'emulator wireguard success' <<<"$jobs"; then
        words="$words wireguard"
    fi
    echo $words
}

# The jobs of the completed push runs of commit $1, as "<job name> <conclusion>" lines, one run after
# another. Pull requests are left out: their runs test a merge, not the commit. In the test, a file stands
# in for the API.
jobs_of() {
    if [ -n "${CI_SCOPE_JOBS:-}" ]; then
        sed -n "s/^$1 //p" "$CI_SCOPE_JOBS"
        return
    fi
    local run
    for run in $(grep "^$1 " <<<"$RUNS" | cut -d' ' -f2); do
        gh api "repos/$GITHUB_REPOSITORY/actions/runs/$run/jobs?per_page=100" --jq '.jobs[] | "\(.name) \(.conclusion)"'
        echo "--"
    done
}

# Prints "build=<bool>", "emulator=<bool>", "wireguard=<bool>", "shards=<JSON>", "build-base=<commit or none>",
# "emulator-base=<...>" and "wireguard-base=<...>" for commit $1 in repository $2, from the proofs jobs_of finds
# among its ancestors, nearest first.
decide_for() {
    local head=$1 repo=$2 commit word block line build_base="" emulator_base="" wireguard_base="" examined=0 build emulator
    local wireguard links b e w
    while IFS= read -r commit; do
        [ -n "$build_base" ] && [ -n "$emulator_base" ] && [ -n "$wireguard_base" ] && break
        # Only commits CI ran on are asked about, and only so many, to keep to the API's budget.
        if [ -z "${CI_SCOPE_JOBS:-}" ] && ! grep -q "^$commit " <<<"$RUNS"; then continue; fi
        examined=$((examined + 1))
        [ "$examined" -le 25 ] || break
        # Each run's jobs, up to a line "--", are judged apart: two half-runs of one commit do not make a
        # whole one.
        b=""
        e=""
        w=""
        block=""
        while IFS= read -r line; do
            if [ "$line" != "--" ]; then
                block+="$line"$'\n'
                continue
            fi
            for word in $(proved <<<"$block"); do
                case $word in
                    emulator) e=1; b=1 ;;
                    build) b=1 ;;
                    wireguard) w=1 ;;
                esac
            done
            block=""
        done < <(jobs_of "$commit"; echo "--")
        [ -z "$b" ] || build_base=${build_base:-$commit}
        [ -z "$e" ] || emulator_base=${emulator_base:-$commit}
        [ -z "$w" ] || wireguard_base=${wireguard_base:-$commit}
    done < <(git -C "$repo" rev-list --max-count=300 "$head")
    build=true
    emulator=true
    wireguard=true
    links=$(git -C "$repo" ls-tree -r "$head" | awk '$1 == "120000" || $1 == "160000" { print $4 }')
    if [ -n "$links" ]; then
        echo "a symbolic link or a submodule, so everything runs: $(echo $links)" >&2
        emulator_base=""
        build_base=""
        wireguard_base=""
    fi
    if [ -n "$emulator_base" ] && [ "$(diff_tier "$emulator_base" "$head" "$repo")" != emulator ]; then emulator=false; fi
    if [ -n "$build_base" ] && [ "$(diff_tier "$build_base" "$head" "$repo")" = none ]; then build=false; fi
    if [ -n "$wireguard_base" ] && [ "$(diff_wireguard "$wireguard_base" "$head" "$repo")" = false ]; then wireguard=false; fi
    # The emulator checks run on the build's APKs; the WireGuard checks on them and in the build job.
    [ "$emulator" = false ] || build=true
    [ "$wireguard" = false ] || build=true
    echo "build=$build"
    echo "emulator=$emulator"
    echo "wireguard=$wireguard"
    echo "shards=$(shards_json "$emulator" "$wireguard")"
    echo "build-base=${build_base:-none}"
    echo "emulator-base=${emulator_base:-none}"
    echo "wireguard-base=${wireguard_base:-none}"
}

run_tests() {
    local failed=0 expected path got
    while read -r expected path; do
        [ -n "$expected" ] || continue
        got=$(tier "$path")
        if [ "$got" != "$expected" ]; then
            echo "tier of $path: $got, expected $expected" >&2
            failed=1
        fi
    done <<'TABLE'
none     README.md
none     CHANGELOG.md
none     keys/README.md
none     docs/RELEASE.md
none     docs/decisions/0043-release-integrity-and-repository-controls.md
none     docs/platform-gaps/results.csv
none     docs/site/index.html
none     brand/logo.svg
none     site/content/_index.en.md
none     site/hugo.toml
none     spikes/notes.md
build    lab/gaps/probe/src/Probe.java
build    data/CORRECTIONS.md
build    data/exodus/update.py
build    data/app-signers/from-play.sh
build    data/owners/.gitkeep
build    data/dbip-asn/LICENSE
build    data/dbip-asn/update.py
build    data/resolvers/sources.tsv
build    data/resolvers/LICENSE
emulator data/PACK
emulator data/exodus/trackers.tsv
emulator data/exodus/LICENSE
emulator data/attestation/google-roots.pem.license
emulator data/dbip-asn/asn.bin
emulator data/resolvers/resolvers.tsv
emulator data/owners/README.md
emulator data/owners/.hidden/table.tsv
emulator data/tools/tools.tsv
emulator android/app/src/main/java/org/visadahyu/datapavan/MainActivity.kt
emulator android/app/src/main/res/values-fa/strings.xml
emulator android/watch/README.md
emulator android/gradle/libs.versions.toml
emulator core/net/src/engine.rs
emulator core/README.md
emulator core/Cargo.lock
emulator rust-toolchain.toml
emulator scripts/verify-watch.sh
emulator scripts/adb-ui.sh
emulator scripts/emulator-shard.sh
emulator scripts/test-tool/src/Tool.java
emulator scripts/testdata/README.md
emulator scripts/check.sh
emulator scripts/ci-scope.sh
emulator .github/workflows/ci.yml
emulator .github/workflows/fuzz.yml
emulator keys/datapavan-data-1.pub
emulator fastlane/metadata/android/en-US/changelogs/3.txt
emulator LICENSE
emulator a-new-directory/file
TABLE
    [ "$failed" = 0 ] && echo "ok: every path in the table has its tier"

    # Which paths the WireGuard checks read.
    local wanted said
    while read -r wanted path; do
        [ -n "$wanted" ] || continue
        if wireguard_path "$path"; then said=yes; else said=no; fi
        if [ "$said" != "$wanted" ]; then
            echo "the WireGuard checks read $path: $said, expected $wanted" >&2
            failed=1
        fi
    done <<'TABLE'
yes core/net/src/engine/tunnels.rs
yes core/net/tests/wglab.rs
yes core/engine/src/lib.rs
yes core/watch-jni/src/lib.rs
yes core/Cargo.lock
yes rust-toolchain.toml
yes android/watch/src/main/java/org/visadahyu/datapavan/watch/TunnelStore.kt
yes android/app/build.gradle.kts
yes spikes/wireguard-core/peer/Dockerfile
yes scripts/wglab.sh
yes scripts/verify-wireguard.sh
yes scripts/verify-wireguard-import.sh
yes scripts/workload-app/src/Work.java
yes scripts/adb-ui.sh
yes scripts/check.sh
yes scripts/ci-scope.sh
yes scripts/emulator-shard.sh
yes .github/workflows/ci.yml
no  core/jni/src/lib.rs
no  core/fuzz/fuzz_targets/dns.rs
no  core/deny.toml
no  scripts/verify-audit.sh
no  scripts/screenshots.sh
no  lab/gaps/probe/src/Probe.java
no  data/exodus/trackers.tsv
no  spikes/wireguard-core/lab/src/main.rs
no  docs/decisions/0035-wireguard-upstream.md
no  README.md
TABLE
    [ "$failed" = 0 ] && echo "ok: every path in the WireGuard table is read or not as it says"

    # ci.yml's matrix is the shards this rule chose, from scripts/emulator-shard.sh's list, which the proofs read.
    local listed
    listed=$("$ROOT/scripts/emulator-shard.sh" list)
    if grep -qx ' *shard: \${{ fromJSON(needs.scope.outputs.shards) }}' "$ROOT/.github/workflows/ci.yml" &&
        [ "$(shards_json true true)" = "[$(sed 's/.*/"&"/' <<<"$listed" | paste -sd,)]" ]; then
        echo "ok: ci.yml's matrix runs the shards this rule chooses from scripts/emulator-shard.sh's list"
    else
        echo "ci.yml's matrix is not the rule's shards, or they are not scripts/emulator-shard.sh's list ($(echo $listed))" >&2
        failed=1
    fi

    # The choice of an earlier pass, in a repository made for the test. Each case names the commit to
    # decide, and what must come out.
    local work
    work=$(mktemp -d)
    trap "rm -rf '$work'" EXIT
    git -C "$work" -c init.defaultBranch=main init -q
    commit() { # message, then path=content pairs; prints the new commit
        local message=$1 pair
        shift
        for pair in "$@"; do
            mkdir -p "$work/$(dirname "${pair%%=*}")"
            if [ "${pair#*=}" = "-" ]; then git -C "$work" rm -q "${pair%%=*}"; else printf '%s\n' "${pair#*=}" >"$work/${pair%%=*}"; fi
        done
        git -C "$work" add -A
        git -C "$work" -c user.name=test -c user.email=test@test -c commit.gpgsign=false commit -q -m "$message"
        git -C "$work" rev-parse HEAD
    }
    local full app docs lab moved again failing fixed legacy legacy_docs build_only none_proved half unproved symlink submodule
    full=$(commit "a full pass" android/app/Main.kt=1 docs/a.md=1 lab/x=1 data/exodus/trackers.tsv=1)
    docs=$(commit "documents" docs/a.md=2 README.md=2 site/hugo.toml=2)
    lab=$(commit "the lab and unbundled data" lab/x=2 data/exodus/update.py=2)
    app=$(commit "the app" android/app/Main.kt=2)
    again=$(commit "documents after an app change" docs/a.md=3)
    git -C "$work" checkout -q "$full"
    moved=$(commit "a move out of the app" android/app/Main.kt=- docs/Main.kt=1)
    git -C "$work" checkout -q "$full"
    failing=$(commit "an app change whose emulator checks failed" android/app/Main.kt=3)
    fixed=$(commit "documents after it" docs/a.md=4)
    git -C "$work" checkout -q "$full"
    build_only=$(commit "data whose build passed" data/exodus/update.py=5)
    none_proved=$(commit "documents after it" README.md=5)
    git -C "$work" checkout -q "$full"
    ln -s ../android/app/Main.kt "$work/docs/link.kt"
    symlink=$(commit "a documents' link into the app" docs/b.md=1)
    git -C "$work" checkout -q "$full"
    printf '1\n' >"$work/docs/c.md"
    git -C "$work" add -A
    git -C "$work" update-index --add --cacheinfo "160000,$full,docs/module"
    git -C "$work" -c user.name=test -c user.email=test@test -c commit.gpgsign=false commit -q -m "a submodule among the documents"
    submodule=$(git -C "$work" rev-parse HEAD)
    git -C "$work" rm -q --cached docs/module
    git -C "$work" checkout -q "$full"
    half=$(commit "an app change passed in two halves" android/app/Main.kt=6)
    git -C "$work" checkout -q "$full"
    local wg_only not_wg wg_failed wg_failed_docs
    wg_only=$(commit "the lab's peers" spikes/wireguard-core/peer/Dockerfile=2)
    git -C "$work" checkout -q "$full"
    not_wg=$(commit "Basic's native library" core/jni/src/lib.rs=2)
    git -C "$work" checkout -q "$full"
    wg_failed=$(commit "an engine change whose WireGuard shard failed" core/net/src/tunnels.rs=2)
    wg_failed_docs=$(commit "documents after it" docs/a.md=5)
    git -C "$work" checkout -q --orphan unproved
    unproved=$(commit "documents on a history CI never passed" docs/a.md=7)
    git -C "$work" checkout -q --orphan legacy
    legacy=$(commit "a run of the workflow before the shards" android/app/Main.kt=9)
    legacy_docs=$(commit "documents" docs/a.md=9)
    {
        echo "$full build success"
        for shard in $listed; do echo "$full emulator $shard success"; done
        echo "$full repository success"
        echo "$failing build success"
        for shard in $listed; do echo "$failing emulator $shard $([ "$shard" = watch ] && echo failure || echo success)"; done
        echo "$build_only build success"
        for shard in $listed; do echo "$build_only emulator $shard skipped"; done
        echo "$legacy checks success"
        # Two runs of one commit, each missing a shard the other passed.
        echo "$half build success"
        for shard in $listed; do echo "$half emulator $shard $([ "$shard" = watch ] && echo success || echo failure)"; done
        echo "$half --"
        echo "$half build success"
        for shard in $listed; do echo "$half emulator $shard $([ "$shard" = watch ] && echo failure || echo success)"; done
        echo "$wg_failed build success"
        for shard in $listed; do echo "$wg_failed emulator $shard $([ "$shard" = wireguard ] && echo failure || echo success)"; done
    } >"$work/jobs"
    local case_head expected_out out
    while read -r case_head expected_out; do
        [ -n "$case_head" ] || continue
        out=$(CI_SCOPE_JOBS="$work/jobs" decide_for "${!case_head}" "$work" | grep -E '^(build|emulator|wireguard|shards)=' | paste -sd' ')
        if [ "$out" = "$expected_out" ]; then
            echo "ok: $case_head: $out"
        else
            echo "$case_head: $out, expected $expected_out" >&2
            failed=1
        fi
    done <<'CASES'
full           build=false emulator=false wireguard=false shards=[]
docs           build=false emulator=false wireguard=false shards=[]
lab            build=true emulator=false wireguard=false shards=[]
app            build=true emulator=true wireguard=true shards=["watch","audit","screens","wireguard"]
again          build=true emulator=true wireguard=true shards=["watch","audit","screens","wireguard"]
moved          build=true emulator=true wireguard=true shards=["watch","audit","screens","wireguard"]
failing        build=true emulator=true wireguard=false shards=["watch","audit","screens"]
fixed          build=true emulator=true wireguard=false shards=["watch","audit","screens"]
build_only     build=false emulator=false wireguard=false shards=[]
none_proved    build=false emulator=false wireguard=false shards=[]
half           build=true emulator=true wireguard=false shards=["watch","audit","screens"]
symlink        build=true emulator=true wireguard=true shards=["watch","audit","screens","wireguard"]
submodule      build=true emulator=true wireguard=true shards=["watch","audit","screens","wireguard"]
unproved       build=true emulator=true wireguard=true shards=["watch","audit","screens","wireguard"]
legacy         build=true emulator=false wireguard=true shards=["wireguard"]
legacy_docs    build=true emulator=false wireguard=true shards=["wireguard"]
wg_only        build=true emulator=true wireguard=true shards=["watch","audit","screens","wireguard"]
not_wg         build=true emulator=true wireguard=false shards=["watch","audit","screens"]
wg_failed      build=true emulator=false wireguard=true shards=["wireguard"]
wg_failed_docs build=true emulator=false wireguard=true shards=["wireguard"]
CASES
    [ "$failed" = 0 ] || { echo "ci-scope.sh: the rule's tests failed" >&2; return 1; }
    echo "== the scope rule's tests passed"
}

case "${1:-}" in
    tier)
        shift
        for path in "$@"; do echo "$(tier "$path") $path"; done
        ;;
    test) run_tests ;;
    decide)
        : "${GITHUB_REPOSITORY:?}" "${GITHUB_SHA:?}"
        # The newest completed push runs of this workflow, as "<commit> <run>" lines.
        RUNS=$(gh api "repos/$GITHUB_REPOSITORY/actions/workflows/ci.yml/runs?event=push&status=completed&per_page=100" \
            --jq '.workflow_runs[] | "\(.head_sha) \(.id)"')
        result="$(decide_for "$GITHUB_SHA" "$ROOT")
weekly=false"
        echo "$result"
        [ -z "${GITHUB_OUTPUT:-}" ] || echo "$result" >>"$GITHUB_OUTPUT"
        ;;
    weekly)
        # The weekly run, and one started by hand: the WireGuard checks alone, with their long ones, whatever
        # changed; the build job builds what the wireguard shard installs.
        result="build=true
emulator=false
wireguard=true
shards=$(shards_json false true)
weekly=true"
        echo "$result"
        [ -z "${GITHUB_OUTPUT:-}" ] || echo "$result" >>"$GITHUB_OUTPUT"
        ;;
    *) echo "usage: $0 tier <path>... | test | decide | weekly" >&2; exit 2 ;;
esac
