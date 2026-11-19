#!/usr/bin/env bash
# Size per ABI of Watch's native library (W7's spike, ADR 0035, question 3). Four variants:
#
#   today     core/watch-jni, as the app builds it now;
#   baseline  the spike's copy (size/): core/watch-jni's own source, unchanged, without WireGuard;
#   ring      the same with GotaTun 0.10.3 on `ring`, linked in and called;
#   aws-lc    the same with GotaTun 0.10.3 on `aws-lc-rs`.
#
# Each is built as android/watch/build.gradle.kts builds the library: cargo-ndk for the three shipped ABIs
# at API 29, `build --locked --release`, none of the inherited flags that could change the output, and the
# same remapped paths; then stripped as the APK's packaging strips native libraries (the NDK's llvm-strip
# --strip-unneeded).
#
#   spikes/wireguard-core/size.sh OUT_DIR [ROOT] [variant...]
#
# ROOT is the checkout to build in (default: the one this script is in), so that scripts/reproducible.sh's
# method can build a commit in two fresh clones. Writes OUT_DIR/<variant>/<abi>/libdatapavan_watch.so (as
# built) and .stripped.so, and prints one line per library: variant, ABI, bytes as built, bytes stripped,
# and the stripped file's sha256.
set -euo pipefail

OUT="$(mkdir -p "$1" && cd "$1" && pwd)"
ROOT="$(cd "${2:-$(dirname "${BASH_SOURCE[0]}")/../..}" && pwd)"
shift $(($# < 2 ? $# : 2))
variants=("$@")
[ ${#variants[@]} -gt 0 ] || variants=(today baseline ring aws-lc)

SDK="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-$HOME/Android/sdk}}"
NDK="$SDK/ndk/30.0.16248370"
CARGO_HOME="${CARGO_HOME:-$HOME/.cargo}"
STRIP="$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-strip"
ABIS=(arm64-v8a armeabi-v7a x86_64)

# The Gradle task's environment: its dropped variables, the NDK, and the remapped paths.
for name in RUSTFLAGS CARGO_BUILD_RUSTFLAGS CARGO_ENCODED_RUSTFLAGS CARGO_TARGET_DIR CARGO_BUILD_TARGET_DIR; do
    unset "$name"
done
while read -r name; do unset "$name"; done < <(env | sed -n 's/^\(CARGO_PROFILE_[A-Za-z0-9_]*\)=.*/\1/p')
export ANDROID_NDK_HOME="$NDK"
CARGO_ENCODED_RUSTFLAGS="--remap-path-prefix=$CARGO_HOME/registry/src=/cargo/registry/src"$'\x1f'"--remap-path-prefix=$ROOT=/datapavan"
export CARGO_ENCODED_RUSTFLAGS

for variant in "${variants[@]}"; do
    case $variant in
        today) dir="$ROOT/core"; args=(-p datapavan-watch-jni) ;;
        baseline) dir="$ROOT/spikes/wireguard-core"; args=(-p wg-size) ;;
        ring) dir="$ROOT/spikes/wireguard-core"; args=(-p wg-size --features ring) ;;
        aws-lc) dir="$ROOT/spikes/wireguard-core"; args=(-p wg-size --features aws-lc) ;;
        *) echo "unknown variant $variant" >&2; exit 2 ;;
    esac
    rm -rf "${OUT:?}/$variant"
    abi_args=()
    for abi in "${ABIS[@]}"; do abi_args+=(-t "$abi"); done
    (cd "$dir" && cargo ndk "${abi_args[@]}" --platform 29 -o "$OUT/$variant" build --locked --release -q "${args[@]}") >&2
    for abi in "${ABIS[@]}"; do
        lib="$OUT/$variant/$abi/libdatapavan_watch.so"
        "$STRIP" --strip-unneeded -o "${lib%.so}.stripped.so" "$lib"
        printf '%s\t%s\t%s\t%s\t%s\n' "$variant" "$abi" "$(stat -c %s "$lib")" "$(stat -c %s "${lib%.so}.stripped.so")" \
            "$(sha256sum "${lib%.so}.stripped.so" | cut -d' ' -f1)"
    done
done
