#!/usr/bin/env bash
# W6's DNS spike (docs/spikes/2026-11-shared-dns-cache.md), on an emulator with Watch's debug build
# installed. Android's resolver keeps one cache for all the apps of a network: does an answer one app got
# through Watch's DNS address reach another app without a lookup, and does an answer whose time to live
# Watch set to 0 stay out of that cache? Two apps look the same names up: adb's shell (UID 2000) and
# Watch's own UID through run-as, both inside Watch's tunnel. Each lookup that reaches Watch is a UDP
# flow to its DNS address with the app's UID as owner; a lookup answered from the cache is none.
#
#   ANDROID_SERIAL=emulator-5554 scripts/watch-lab/dns-cache.sh
#
# Prints one line per case: how many lookups of each app reached Watch. The names are example.com,
# .org and .net (RFC 2606) and random names under example.com, which do not exist.
set -euo pipefail

: "${ANDROID_SERIAL:?set ANDROID_SERIAL to the emulator, never a phone}"
case "$ANDROID_SERIAL" in emulator-*) ;; *) echo "only on an emulator" >&2; exit 2 ;; esac
export ANDROID_SERIAL
PKG=org.visadahyu.datapavan.advanced
# Watch's screen in Datapavan Advanced (ADR 0045); debug builds export it for these checks.
WATCH_SCREEN=org.visadahyu.datapavan.watch.MainActivity
SHELL_UID=2000

cleanup() { adb shell am force-stop "$PKG" >/dev/null 2>&1 || true; }
trap cleanup EXIT

dump() { adb shell dumpsys activity service "$PKG/org.visadahyu.datapavan.watch.WatchVpnService" "$@" | tr -d '\r'; }
# The lookups of one UID that reached Watch: its UDP flows to either of the tunnel's DNS addresses,
# IPv4 or IPv6. The list is read whole, then counted.
lookups() {
    local flows
    flows=$(dump)
    # The tunnel's DNS server, as Watch's dump gives it (ADR 0041).
    local dns
    dns=$(sed -n 's/^ *addresses [a-z]* [^ ]* \([^ ]*\) [^ ]* \([^ ]*\)$/\1|\\[\2\\]/p' <<<"$flows" | sed 's/\./\\./g')
    grep -cE "^ *flow udp [^ ]* ($dns):53 $1 " <<<"$flows" || true
}
from_shell() { adb shell ping -c 1 -W 1 "$1" >/dev/null 2>&1 || true; }
from_watch() { adb shell run-as "$PKG" ping -c 1 -W 1 "$1" >/dev/null 2>&1 || true; }

WATCH_UID=$(adb shell cmd package list packages -U "$PKG" | tr -d '\r' | sed -n "s/^package:$PKG uid:\([0-9]*\)$/\1/p")
[ -n "$WATCH_UID" ] || { echo "Watch's debug build is not installed" >&2; exit 1; }
SDK=$(adb shell getprop ro.build.version.sdk | tr -d '\r')
RESOLV=$(adb shell pm list packages --apex-only --show-versioncode 2>/dev/null | tr -d '\r' | sed -n 's/^package:com\.\(google\.\)\{0,1\}android\.resolv versionCode:/&/p' | sed 's/^package://; s/ versionCode:/ /')

adb shell appops set "$PKG" ACTIVATE_VPN allow
adb shell am force-stop "$PKG"
# A new tunnel is a new network, with a cache of its own: names looked up before do not count.
adb shell am start -W -n "$PKG/$WATCH_SCREEN" --ez start true >/dev/null
for _ in $(seq 1 20); do
    vpns=$(adb shell dumpsys connectivity | tr -d '\r')
    grep -qE "OwnerUid: $WATCH_UID " <<<"$vpns" && break
    sleep 1
done
sleep 2
echo "android sdk $SDK, resolver module ${RESOLV:-none}, watch uid $WATCH_UID"

# One case: the shell looks the name up, then Watch's UID, then the shell again.
case_of() {
    local label=$1 name=$2
    local s0 w0 s1 w1 s2
    s0=$(lookups $SHELL_UID); w0=$(lookups "$WATCH_UID")
    from_shell "$name"; s1=$(lookups $SHELL_UID)
    from_watch "$name"; w1=$(lookups "$WATCH_UID")
    from_shell "$name"; s2=$(lookups $SHELL_UID)
    echo "$label: shell first $((s1 - s0)), other app $((w1 - w0)), shell again $((s2 - s1))"
}

echo "dns-uncached off: $(dump dns-uncached off | grep -c 'dns-uncached off')"
case_of "normal ttl, an answer" example.com
case_of "normal ttl, no such name" "spike-$RANDOM-$RANDOM.example.com"
echo "dns-uncached on: $(dump dns-uncached on | grep -c 'dns-uncached on')"
case_of "ttl 0, an answer" example.org
case_of "ttl 0, no such name" "spike-$RANDOM-$RANDOM.example.com"
dump dns-uncached off >/dev/null
case_of "normal ttl again, an answer" example.net
