#!/usr/bin/env bash
# What CI must run for a commit: the rule, written once, that ci.yml's scope job applies (ADR 0043).
#
# Every changed path needs one of three things:
#   none      the repository checks only (scripts/check.sh data), which run on every push anyway;
#   build     also the build and its gates (scripts/check.sh rust and android);
#   emulator  also the emulator checks (scripts/emulator-shard.sh), which need the build's APKs.
#
# A commit is compared with the nearest earlier commit whose tree passed that work in CI, not with the
# push before it: a pushed commit whose run failed or was cancelled proves nothing, and a change after it
# is compared with what last passed. A commit needs the build unless its tree differs from a tree that
# passed the build only in paths that need none; it needs the emulator checks unless its tree differs
# from a tree that passed them only in paths that need no emulator. Paths are compared without rename
# detection, so a file moved out of the app counts as removed from it. Anything this rule does not name
# needs everything, and so does a change to the rule or to CI itself.
#
#   scripts/ci-scope.sh tier <path>...   each path's tier
#   scripts/ci-scope.sh test             the rule against its table of paths, and the choice of the
#                                        earlier pass against a small repository built for the test
#   scripts/ci-scope.sh decide           in the scope job: writes build=, emulator= and the commits
#                                        reused to $GITHUB_OUTPUT (or prints them)
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

# The CI jobs that prove a tree, as "<job name> <conclusion>" lines on stdin, give what they proved: build,
# emulator (which includes the build), or nothing. The emulator checks count only if every shard passed.
# Runs before 2026-11-14 had one job, "checks", which built and ran the emulator checks together.
proved() {
    local jobs shard all=1
    jobs=$(cat)
    if grep -qx 'checks success' <<<"$jobs"; then
        echo emulator
        return
    fi
    for shard in $("$ROOT/scripts/emulator-shard.sh" list); do
        grep -qx "emulator $shard success" <<<"$jobs" || all=""
    done
    if [ -n "$all" ] && grep -qx 'build success' <<<"$jobs"; then
        echo emulator
    elif grep -qx 'build success' <<<"$jobs"; then
        echo build
    fi
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

# Prints "build=<bool>", "emulator=<bool>", "build-base=<commit or none>" and "emulator-base=<...>" for
# commit $1 in repository $2, from the proofs jobs_of finds among its ancestors, nearest first.
decide_for() {
    local head=$1 repo=$2 commit proof block line build_base="" emulator_base="" examined=0 build emulator
    while IFS= read -r commit; do
        [ -n "$build_base" ] && [ -n "$emulator_base" ] && break
        # Only commits CI ran on are asked about, and only so many, to keep to the API's budget.
        if [ -z "${CI_SCOPE_JOBS:-}" ] && ! grep -q "^$commit " <<<"$RUNS"; then continue; fi
        examined=$((examined + 1))
        [ "$examined" -le 25 ] || break
        # Each run's jobs, up to a line "--", are judged apart: two half-runs of one commit do not make a
        # whole one.
        proof=""
        block=""
        while IFS= read -r line; do
            if [ "$line" != "--" ]; then
                block+="$line"$'\n'
                continue
            fi
            case $(proved <<<"$block") in
                emulator) proof=emulator ;;
                build) [ "$proof" = emulator ] || proof=build ;;
            esac
            block=""
        done < <(jobs_of "$commit"; echo "--")
        case $proof in
            emulator) build_base=${build_base:-$commit}; emulator_base=${emulator_base:-$commit} ;;
            build) build_base=${build_base:-$commit} ;;
        esac
    done < <(git -C "$repo" rev-list --max-count=300 "$head")
    build=true
    emulator=true
    if [ -n "$emulator_base" ] && [ "$(diff_tier "$emulator_base" "$head" "$repo")" != emulator ]; then emulator=false; fi
    if [ -n "$build_base" ] && [ "$(diff_tier "$build_base" "$head" "$repo")" = none ]; then build=false; fi
    # The emulator checks run on the build's APKs.
    [ "$emulator" = false ] || build=true
    echo "build=$build"
    echo "emulator=$emulator"
    echo "build-base=${build_base:-none}"
    echo "emulator-base=${emulator_base:-none}"
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

    # The shards ci.yml's matrix runs are the shards scripts/emulator-shard.sh lists, which the proofs read.
    local matrix listed
    matrix=$(sed -n 's/^ *shard: \[\(.*\)\]$/\1/p' "$ROOT/.github/workflows/ci.yml" | tr -d ' ' | tr ',' '\n')
    listed=$("$ROOT/scripts/emulator-shard.sh" list)
    if [ "$matrix" = "$listed" ]; then
        echo "ok: ci.yml's matrix runs the shards scripts/emulator-shard.sh lists"
    else
        echo "ci.yml's matrix ($(echo $matrix)) is not scripts/emulator-shard.sh's list ($(echo $listed))" >&2
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
    local full app docs lab moved again failing fixed legacy legacy_docs build_only none_proved half unproved
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
    half=$(commit "an app change passed in two halves" android/app/Main.kt=6)
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
    } >"$work/jobs"
    local case_head expected_out out
    while read -r case_head expected_out; do
        [ -n "$case_head" ] || continue
        out=$(CI_SCOPE_JOBS="$work/jobs" decide_for "${!case_head}" "$work" | grep -E '^(build|emulator)=' | paste -sd' ')
        if [ "$out" = "$expected_out" ]; then
            echo "ok: $case_head: $out"
        else
            echo "$case_head: $out, expected $expected_out" >&2
            failed=1
        fi
    done <<'CASES'
full         build=false emulator=false
docs         build=false emulator=false
lab          build=true emulator=false
app          build=true emulator=true
again        build=true emulator=true
moved        build=true emulator=true
failing      build=true emulator=true
fixed        build=true emulator=true
build_only   build=false emulator=false
none_proved  build=false emulator=false
half         build=true emulator=true
unproved     build=true emulator=true
legacy       build=false emulator=false
legacy_docs  build=false emulator=false
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
        result=$(decide_for "$GITHUB_SHA" "$ROOT")
        echo "$result"
        [ -z "${GITHUB_OUTPUT:-}" ] || echo "$result" >>"$GITHUB_OUTPUT"
        ;;
    *) echo "usage: $0 tier <path>... | test | decide" >&2; exit 2 ;;
esac
