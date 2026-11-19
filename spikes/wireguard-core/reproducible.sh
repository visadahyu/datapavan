#!/usr/bin/env bash
# Builds each of size.sh's variants twice from one commit and compares the libraries byte for byte (W7's
# spike, ADR 0035), by scripts/reproducible.sh's method: two fresh clones of the commit at paths of different
# lengths, each with its own target directories and no build cache, the second building the variants in the
# reverse order. On a difference it shows how the two files differ. It also counts, in every library, the
# strings that name a path of this machine (the home directory, the clones, the temporary directory).
#
#   spikes/wireguard-core/reproducible.sh [commit, default HEAD] [variant...]
#
# Prints both builds' size.sh lines, then one line per variant and ABI; fails unless every pair agrees.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
COMMIT="$(git -C "$ROOT" rev-parse "${1:-HEAD}")"
shift $(($# > 0 ? 1 : 0))
variants=("$@")
[ ${#variants[@]} -gt 0 ] || variants=(today baseline ring aws-lc)
reversed=()
for ((i = ${#variants[@]} - 1; i >= 0; i--)); do reversed+=("${variants[i]}"); done
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
STRIP_DIR="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-$HOME/Android/sdk}}/ndk/30.0.16248370/toolchains/llvm/prebuilt/linux-x86_64/bin"

build() {
    local name=$1
    shift
    local dir="$WORK/$name/datapavan"
    git clone -q --no-local "$ROOT" "$dir"
    git -C "$dir" checkout -q "$COMMIT"
    "$dir/spikes/wireguard-core/size.sh" "$WORK/$name/out" "$dir" "$@" >"$WORK/$name.tsv"
    sed "s/^/$name\t/" "$WORK/$name.tsv"
}

echo "== Building $COMMIT twice: ${variants[*]}"
build first "${variants[@]}"
build second-with-a-longer-path "${reversed[@]}"

ok=0
for variant in "${variants[@]}"; do
    for abi in arm64-v8a armeabi-v7a x86_64; do
        a="$WORK/first/out/$variant/$abi/libdatapavan_watch.stripped.so"
        b="$WORK/second-with-a-longer-path/out/$variant/$abi/libdatapavan_watch.stripped.so"
        leaks=$(strings "$a" | grep -c -E "$HOME|$WORK|/tmp/" || true)
        if cmp -s "$a" "$b"; then
            echo "== $variant $abi: reproducible, $(stat -c %s "$a") bytes, $(sha256sum "$a" | cut -c1-16), $leaks strings naming this machine's paths"
        else
            ok=1
            echo "NOT REPRODUCIBLE: $variant $abi ($(stat -c %s "$a") and $(stat -c %s "$b") bytes)" >&2
            diff <("$STRIP_DIR/llvm-readelf" -S -W "$a") <("$STRIP_DIR/llvm-readelf" -S -W "$b") >&2 || true
            cmp -l "$a" "$b" | head -20 >&2 || true
            diff <(strings "$a") <(strings "$b") | head -40 >&2 || true
        fi
    done
done
exit "$ok"
