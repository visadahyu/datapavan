#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Compares the tracker scan with εxodus reports for the same app versions: M3's definition of done
# (docs/spikes/2026-10-m3-exodus-comparison.md).
#
#   ANDROID_SERIAL=<device> scripts/compare-exodus.sh package...
#
# Needs a test device or emulator with Google Play, on which someone has signed in by hand. For each
# package it reads the app's latest report on reports.exodus-privacy.eu.org and installs the app from
# Play. When the installed version code is the report's, it scans the DEX files of every installed APK
# (base and splits) with the engine and prints one line: the trackers in the report, how many the scan
# found embedded or only referenced, the ones it missed, and the ones it found besides. Apps it
# installed are uninstalled again; none is opened.
set -uo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
# shellcheck source=scripts/adb-ui.sh
. "$ROOT/scripts/adb-ui.sh"
: "${ANDROID_SERIAL:?set ANDROID_SERIAL to the test device}"

cargo build -q --release --example scan_trackers --manifest-path "$ROOT/core/engine/Cargo.toml" || exit 1
scan="$ROOT/core/target/release/examples/scan_trackers"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# The version code and tracker ids of the latest εxodus report of $1, as "code id id ...".
report() {
    python3 -I - "$1" <<'EOF'
import re, sys, urllib.request
url = f"https://reports.exodus-privacy.eu.org/en/reports/{sys.argv[1]}/latest/"
request = urllib.request.Request(url, headers={"User-Agent": "datapavan-compare-exodus"})
try:
    page = urllib.request.urlopen(request, timeout=60).read().decode()
except OSError:
    sys.exit(1)
code = re.search(r"Version code:</b> <samp>(\d+)</samp>", page)
if not code:
    sys.exit(1)
print(code.group(1), *sorted({int(i) for i in re.findall(r'href="/en/trackers/(\d+)/"', page)}))
EOF
}

for package in "$@"; do
    if ! wanted=$(report "$package"); then
        echo "$package: no εxodus report"
        continue
    fi
    read -r want_code trackers <<< "$wanted"
    ours=no
    if ! installed "$package"; then
        if ! install_from_play "$package"; then
            echo "$package: Play does not offer it here"
            continue
        fi
        ours=yes
    fi
    code=$(adb shell dumpsys package "$package" | sed -n 's/.*versionCode=\([0-9]*\).*/\1/p' | head -1)
    if [ "$code" != "$want_code" ]; then
        echo "$package: other version (installed $code, report $want_code)"
    else
        dir="$work/$package"
        mkdir -p "$dir"
        n=0
        for apk in $(adb shell pm path "$package" | sed -n 's/^package://p' | tr -d '\r'); do
            n=$((n + 1))
            adb pull "$apk" "$dir/$n.apk" >/dev/null 2>&1
            mkdir -p "$dir/$n"
            unzip -q -o "$dir/$n.apk" 'classes*.dex' -d "$dir/$n" 2>/dev/null
        done
        find "$dir" -name 'classes*.dex' -print0 | sort -z |
            xargs -0 "$scan" "$ROOT/data/exodus/trackers.tsv" > "$dir/found.tsv"
        python3 -I - "$package" "$code" "$dir/found.tsv" "$n" $trackers <<'EOF'
import sys
package, code, found, apks, *report = sys.argv[1:]
report = {int(t) for t in report}
rows = [line.split("\t") for line in open(found).read().splitlines() if line]
embedded = {int(r[1]) for r in rows if r[0] == "embedded"}
referenced = {int(r[1]) for r in rows if r[0] == "referenced"} - embedded
print(f"{package} {code}: report {len(report)}, embedded {len(report & embedded)}, "
      f"referenced only {len(report & referenced)}, missed {sorted(report - embedded - referenced)}, "
      f"besides: embedded {sorted(embedded - report)}, referenced {sorted(referenced - report)}; {apks} APKs")
EOF
    fi
    [ $ours = no ] || adb uninstall "$package" >/dev/null
done
