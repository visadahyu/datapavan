#!/usr/bin/env bash
# Compares Datapavan's network use per app with the system's data-usage screen (milestone M4,
# ADR 0022). Settings looks different on every vendor, so it is opened by hand first: the per-app
# list of one network type (mobile or Wi-Fi) for one usage cycle. The script reads the largest rows
# of that list, opens each app's page in Datapavan (a debug build, with usage access) and reads the
# same network type there.
#
# Datapavan counts 30 days back from the moment it reads. Settings' cycles differ: a billing month
# for mobile data, and on many phones four weeks for Wi-Fi. Debug builds therefore take the period's
# length in days and, for a cycle that has ended, its end as Unix milliseconds.
#
# Settings steps by 1,024 in AOSP and by 1,000 on Samsung phones (ui/DataSize.kt); the script reads
# Settings' sizes with the same step, or with STEP if set.
#
# On a personal phone, set PRIVATE=1: app names and amounts are then never printed, only each row's
# rank and difference.
#
#   scripts/compare-usage.sh mobile|wifi [ROWS] [DAYS] [CYCLE_END_MS]
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/adb-ui.sh
. "$ROOT/scripts/adb-ui.sh"

case "${1:-}" in
    mobile) LINE="Mobile data" ;;
    wifi) LINE="Wi-Fi" ;;
    *) echo "usage: $0 mobile|wifi [ROWS] [DAYS] [CYCLE_END_MS]" >&2; exit 2 ;;
esac
ROWS="${2:-10}"
DAYS="${3:-30}"
UNTIL="${4:-}"
PKG=org.visadahyu.datapavan
SIZE='^[0-9.,]+ (B|byte|kB|KB|MB|GB)$'
# The screen dumps name the phone's apps: none is left on it.
trap 'adb shell rm -f "$DUMP" >/dev/null 2>&1 || true' EXIT

texts() {
    adb shell uiautomator dump "$DUMP" >/dev/null 2>&1
    adb shell cat "$DUMP" </dev/null | grep -o 'text="[^"]*"' | sed 's/^text="//; s/"$//; s/&amp;/\&/g' | grep -v '^$' || true
}

if [ -z "${STEP:-}" ]; then
    STEP=1024
    [ "$(adb shell getprop ro.product.manufacturer | tr -d '\r' | tr '[:upper:]' '[:lower:]')" != samsung ] || STEP=1000
fi

# Datapavan wraps names and sizes in Unicode bidi isolates (ui/Bidi.kt); comparisons ignore them.
ISOLATES='[\x{2066}-\x{2069}]'
plain() { perl -CS -pe "s/$ISOLATES//g"; }

# Bytes of a size as Settings writes it.
bytes() {
    awk -v s="$1" -v k="$STEP" 'BEGIN { split(s, p, " "); gsub(",", "", p[1]); m = 1
        if (p[2] == "kB" || p[2] == "KB") m = k; else if (p[2] == "MB") m = k^2; else if (p[2] == "GB") m = k^3
        printf "%.0f", p[1] * m }'
}

# The open Settings list: "name<TAB>size" for each row whose next text is a size, largest first.
settings_rows() {
    local name shown
    for _ in 1 2 3 4 5 6; do
        texts | awk -v size="$SIZE" 'prev != "" && $0 ~ size { print prev "\t" $0 } { prev = $0 }'
        swipe_up
    done | awk -F '\t' '!seen[$1]++' | while IFS=$'\t' read -r name shown; do
        printf '%s\t%s\t%s\n' "$(bytes "$shown")" "$name" "$shown"
    done | sort -t $'\t' -k1,1nr | cut -f2-
}

start_datapavan() {
    adb shell am force-stop "$PKG"
    adb shell cmd locale set-app-locales "$PKG" --locales en >/dev/null 2>&1 || true
    local extras=(--ei usage_days "$DAYS")
    [ -z "$UNTIL" ] || extras+=(--el usage_until "$UNTIL")
    adb shell am start -n "$PKG/.MainActivity" "${extras[@]}" >/dev/null
    for _ in $(seq 1 60); do
        has_id nav-summary && return 0
        sleep 1
    done
    return 1
}

# Opens an app's page: from the network destination's list ("Name: size", or "Name (+2): size" for a
# shared user ID), else from the list of all apps (ADR 0027).
open_app() {
    local row previous=""
    for list in network all; do
        if [ "$list" = network ]; then
            open_tab network || return 1
        else
            open_tab apps || return 1
            tap_id filter-all || return 1
            sleep 1
        fi
        scroll_to_top
        for _ in $(seq 1 80); do
            if [ "$list" = network ]; then
                row=$(texts | perl -CSA -ne 'BEGIN { $n = shift } $p = $_; $p =~ s/'"$ISOLATES"'//g; if (index($p, $n) == 0 && substr($p, length $n) =~ /^( \(\+\d+\))?: /) { print; exit }' "$1")
                row=${row%$'\n'}
            else
                row=$(texts | awk -v n="$1" '$0 == n { print; exit }')
            fi
            if [ -n "$row" ]; then
                # The screen dump writes "&" as "&amp;".
                row=${row//&/&amp;}
                # A row at the very bottom lies under the navigation bar, which takes the tap.
                local bounds height
                bounds=$(text_bounds "$row")
                height=$(adb shell wm size | tr -d '\r' | sed -n 's/.*x\([0-9]*\)$/\1/p' | tail -1)
                if [ -n "$bounds" ] && [ "$(echo "$bounds" | awk '{ print $4 }')" -gt $((height * 4 / 5)) ]; then
                    adb shell input swipe 500 $((height * 3 / 5)) 500 $((height * 2 / 5)) 300
                    sleep 1
                fi
                tap_text "$row"
                return
            fi
            [ "$list" = network ] && screen_has "Not opened for a long time" && break
            # The end of the list: a swipe that changes nothing.
            local now
            now=$(texts | md5sum)
            [ "$now" = "$previous" ] && break
            previous=$now
            swipe_up
        done
    done
    return 1
}

# The app page's line for this network type, as "size" ("0" when the app used none).
datapavan_size() {
    open_sections
    scroll_to "Network use" >/dev/null || return 1
    for _ in 1 2 3 4; do
        local line
        line=$(texts | plain | grep -m1 -E "^$LINE [0-9]" || true)
        [ -n "$line" ] && { echo "$line" | sed -E "s/^$LINE ([^:]+):.*/\1/"; return; }
        texts | grep -q -E '^(Last opened|Not opened since|No network use)' && { echo 0; return; }
        swipe_up
    done
    return 1
}

echo "== Reading the open Settings list" >&2
mapfile -t rows < <(settings_rows | head -n "$ROWS")
[ "${#rows[@]}" -gt 0 ] || { echo "no rows with sizes on screen: open Settings' per-app list first" >&2; exit 1; }

worst=0
rank=0
for row in "${rows[@]}"; do
    rank=$((rank + 1))
    name=${row%%$'\t'*}
    shown=${row#*$'\t'}
    start_datapavan || { echo "Datapavan's overview did not appear" >&2; exit 1; }
    if ! open_app "$name" || ! ours=$(datapavan_size); then
        if [ -n "${PRIVATE:-}" ]; then echo "$rank	not found"; else echo "$name	$shown	not found"; fi
        continue
    fi
    a=$(bytes "$shown")
    b=$( [ "$ours" = 0 ] && echo 0 || bytes "$ours")
    diff=$(awk -v a="$a" -v b="$b" 'BEGIN { printf "%.2f", (a == 0 ? 0 : (b - a) * 100 / a) }')
    worst=$(awk -v w="$worst" -v d="$diff" 'BEGIN { d = d < 0 ? -d : d; print (d > w ? d : w) }')
    if [ -n "${PRIVATE:-}" ]; then echo "$rank	$diff %"; else echo "$name	$shown	$ours	$diff %"; fi
done
echo "== largest difference: $worst %"
