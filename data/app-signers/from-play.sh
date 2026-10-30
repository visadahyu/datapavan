#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Reads the signing certificates of the Google Play copies of the apps in apps.tsv (ADR 0018).
#
#   ANDROID_SERIAL=<device> data/app-signers/from-play.sh [package...]
#
# Needs a test device or emulator with Google Play, on which someone has signed in to Play by hand. For
# each package it opens the Play listing, taps Install, copies the installed base APK into the cache
# (~/.cache/datapavan/app-signers/play/api<level>/) and uninstalls the app again. The app is never
# opened. update.py --read-play then records what the APKs carry in play.tsv. A package that Play does
# not offer on this device (not listed, not in this country, or not for this Android version) is
# reported and skipped. Apps that were installed before are copied and left installed.
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=scripts/adb-ui.sh
. "$HERE/../../scripts/adb-ui.sh"
: "${ANDROID_SERIAL:?set ANDROID_SERIAL to the test device}"

api=$(adb shell getprop ro.build.version.sdk | tr -d '\r')
cache="${CACHE:-$HOME/.cache/datapavan/app-signers}/play/api$api"
mkdir -p "$cache"
if [ $# -gt 0 ]; then
    packages=("$@")
else
    mapfile -t packages < <(grep -v '^#' "$HERE/apps.tsv" | cut -f1)
fi

read=()
skipped=()
for package in "${packages[@]}"; do
    ours=no
    if ! installed "$package"; then
        if ! install_from_play "$package"; then
            skipped+=("$package")
            echo "$package: Play does not offer it here"
            continue
        fi
        ours=yes
    fi
    installer=$(adb shell dumpsys package "$package" | sed -n 's/.*installerPackageName=\([^ ]*\).*/\1/p' | head -1 | tr -d '\r')
    if [ "$installer" != com.android.vending ]; then
        skipped+=("$package")
        echo "$package: installed by ${installer:-adb}, not by Play"
        continue
    fi
    base=$(adb shell pm path "$package" | sed -n 's/^package://p' | tr -d '\r' | grep '/base\.apk$')
    adb pull "$base" "$cache/$package.apk" >/dev/null 2>&1
    read+=("$package")
    echo "$package: copied"
    [ $ours = yes ] && adb uninstall "$package" >/dev/null
done

echo "copied ${#read[@]}, skipped ${#skipped[@]}: ${skipped[*]:-none}"
[ ${#read[@]} -eq 0 ] || "$HERE/update.py" --read-play "$cache" --api "$api"
