#!/usr/bin/env bash
# W8, part 1's emulator check (ADR 0042, "How it is built"): Watch's encrypted resolver for the names of apps that go
# directly, on a real Android, against the DNS lab (scripts/dnslab.sh, Compose project datapavan-dnslab). Each of the
# lab's servers answers probe.dnslab.test with an address of its own, and each logs the names it was asked, so the
# check reads which way answered from what the app was given and from the servers' logs, and that nothing reached
# the network's resolver from the network resolver's own log (what reached it, as a capture would show it).
#
# Watch asks the lab's resolver as the network's (W8's fix round, review R-M4): a debug build's command points its
# exchanges with the network's resolver at the lab's resolver front, so that any emulator works, CI's included. An
# emulator started with `-dns-server 10.153.53.1` (the lab's bridge on this computer; the emulator ignores a
# loopback address there) also sends Android's own lookups to the lab, and the check then says so. With
# DNSLAB_REQUIRED=1 (CI's dns shard) the check fails where it would otherwise skip. The check:
#   0. "Notify me" without Android's leave to notify (Android 13 and later): the screen asks, the user refuses, the
#      switch stays off and the screen says why (review R-M3);
#   1. a direct app's name goes by Oblivious DoH through the lab's relay to the first target, and the network's
#      resolver never sees it; Watch's own process looks up no name at all; nor when the tunnel is set up again;
#   2. Android's opportunistic DNS over TLS to Watch's address is refused, at least once, and its lookups come on
#      port 53;
#   3. the user's preset (DoH, then DoT) and the user's own DoH resolver answer;
#   4. strict, with every encrypted way down (the censor drops them): the app gets no address, nothing reaches the
#      network's resolver, Watch's state says so, and a local name (printer.home.arpa) still resolves;
#   5. outside strict, the same: the network's resolver answers, the state says fallback, the notification shows;
#      the ways come back, and once their back-off ends the names go by ODoH again;
#   6. the censor's methods one by one: a reset on the relay's server name holds ODoH for six minutes and the next
#      way answers; port 853 blocked fails the DoT preset over to the next way, and with "only this resolver" to
#      nothing at all; an injected answer reaches a name that goes encrypted never, and the app only through the
#      fallback;
#   7. behind a captive portal no failure counts. Android's own validation reaches the engine where the emulator
#      reaches the internet; "not validated" is set by a debug command, since no emulator here sits behind a real
#      portal (the lab's portal container serves its selftest);
#   8. a WireGuard endpoint's name goes the encrypted way;
#   9. a network's search domains (review S-C1): `com` is refused; a name under the network's own domain goes the
#      encrypted way first and to the network's resolver only when the internet does not know it;
#  10. a target's key rotated (review S-M1): its pair is held, the other carries the names, the key is fetched
#      later at the target's own addresses, and the pair answers again.
#
#   scripts/verify-dns.sh [path/to/Datapavan-Advanced-debug.apk]
#
#   DNSLAB_RELAY=caddy     the lab's relay is Datapavan's own as its server runs it (ADR 0055: Debian 13's Caddy with
#                          server/'s files, scripts/dnslab.sh says how), at /odoh/proxy
#   DNSLAB_ONLY=odoh       the ODoH steps alone: the setup, 1, 1b, 2 and 10 (the key's rotation, whose 401 comes back
#                          through the relay); not 3b, the speed budget, which is timing-sensitive and runs whole on
#                          CI's dns shard
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APK="${1:-$ROOT/android/app/build-advanced/outputs/apk/debug/app-debug.apk}"
PKG=org.visadahyu.datapavan.advanced
NETWORK_SCREEN=org.visadahyu.datapavan.network.MainActivity
WORKLOAD=org.visadahyu.datapavan.workload
LAB="$ROOT/scripts/dnslab.sh"
# shellcheck source=scripts/adb-ui.sh
. "$ROOT/scripts/adb-ui.sh"

ONLY="${DNSLAB_ONLY:-}"
case $ONLY in "" | odoh) ;; *) echo "DNSLAB_ONLY is odoh or unset, not $ONLY" >&2; exit 2 ;; esac
# Whether a step outside the ODoH steps runs.
all_steps() { [ -z "$ONLY" ]; }
[ -n "${ANDROID_SERIAL:-}" ] || { echo "set ANDROID_SERIAL to the emulator's serial" >&2; exit 2; }
is_emulator || { echo "verify-dns.sh runs on an emulator only" >&2; exit 2; }
WORK="$(mktemp -d)"
PRIVATE_MODE=""

# Every front of the censor back on pass.
all_pass() {
    local front
    for front in relay target-a target-b doh dot resolver resolver-dot; do "$LAB" censor "$front" pass >/dev/null 2>&1 || true; done
}

cleanup() {
    all_pass
    "$LAB" portal open >/dev/null 2>&1 || true
    [ -z "$PRIVATE_MODE" ] || adb shell settings put global private_dns_mode "$PRIVATE_MODE" >/dev/null 2>&1 || true
    adb shell run-as "$PKG" rm -rf files/dnslab files/wg-dns.conf >/dev/null 2>&1 || true
    adb shell am force-stop "$PKG" >/dev/null 2>&1 || true
    adb uninstall "$WORKLOAD" >/dev/null 2>&1 || true
    "$LAB" stop >/dev/null 2>&1 || true
    rm -rf "$WORK"
}
trap cleanup EXIT

dump() { adb shell dumpsys activity service "$PKG/org.visadahyu.datapavan.network.NetworkVpnService" "$@" | tr -d '\r'; }
way() { sed -n 's/^ *dns-way //p' <<<"$(dump)"; }
held() { sed -n 's/^ *dns-held //p' <<<"$(dump)"; }
workload_log() { adb logcat -d -s DatapavanWorkload | tr -d '\r' | sed -n 's/.*DatapavanWorkload: //p'; }
# Looks $1 up in the workload app, through Android's resolver; prints the address, or "failed".
lookup() {
    # A new process each time: Android's libcore keeps an answer for two seconds in the app's own memory.
    adb shell am force-stop "$WORKLOAD"
    adb logcat -c
    adb shell am start -W -n "$WORKLOAD/.WorkActivity" --es name "$1" >/dev/null
    for _ in $(seq 1 30); do
        grep -qx done <<<"$(workload_log)" && break
        sleep 1
    done
    local line
    line=$(grep -E "^(resolved|resolve) $1 " <<<"$(workload_log)" | tail -1)
    case $line in
        "resolved $1 "*) echo "${line##* }" ;;
        *) echo failed ;;
    esac
}
# Whether the lab's server $1 was asked the name $2 since the mark $3 (a count of its log's lines).
asked() { tail -n +$(($3 + 1)) <<<"$("$LAB" log "$1" 2>/dev/null | tr -d '\000')" | grep -q "$2"; }
mark() { "$LAB" log "$1" 2>/dev/null | tr -d '\000' | wc -l; }
# Both lab targets' marks, and whether either was asked $1 since: the order of the pairs is learned per network and
# the hedge asks the second after 400 ms, so which target a name reaches is a race, not a property (CI run
# 44906315436). Only a step that leaves one pair (the key's rotation) names its target.
target_marks() { echo "$(mark target-a) $(mark target-b)"; }
asked_target() {
    local a b
    read -r a b <<<"$2"
    asked target-a "$1" "$a" || asked target-b "$1" "$b"
}
fail() {
    echo "DNS CHECK FAILED: $*" >&2
    echo "Watch's DNS state:" >&2
    grep -E '^ *dns-' <<<"$(dump)" >&2 || true
    echo "The censor's counts:" >&2
    "$LAB" counts >&2 || true
    adb logcat -d -b crash 2>/dev/null | tail -30 >&2 || true
    exit 1
}
vpn_up() {
    local uid
    uid=$(adb shell cmd package list packages -U "$PKG" | tr -d '\r' | sed -n "s/^package:$PKG uid:\([0-9]*\)$/\1/p")
    [ -n "$uid" ] && grep -qE "OwnerUid: $uid " <<<"$(adb shell dumpsys connectivity | tr -d '\r')"
}
expect() {
    # $1 what, $2 got, $3 wanted
    [ "$2" = "$3" ] || fail "$1: got '$2', wanted '$3'"
    echo "ok: $1 ($2)"
}
# A fresh name each time, so that no cache answers.
n=0
fresh() { n=$((n + 1)); echo "name-$n-$RANDOM.dnslab.test"; }

# Skipped, and saying so, only where the lab cannot run here at all: the check then proves nothing, and its line
# says it. With DNSLAB_REQUIRED=1, as on CI's dns shard, that is a failure.
skip() {
    if [ "${DNSLAB_REQUIRED:-}" = 1 ]; then
        echo "DNS CHECK FAILED: it would skip, with DNSLAB_REQUIRED=1: $1" >&2
        exit 1
    fi
    echo "SKIPPED verify-dns.sh: $1; nothing of W8's part 1 was checked on the emulator"
    [ -z "${GITHUB_ACTIONS:-}" ] || echo "::notice title=W8's emulator check skipped::$1"
    exit 0
}
# Taps the first element whose text starts with $1 (a text with an apostrophe, which the dump may escape).
tap_starting() {
    dump_screen || return 1
    local bounds
    bounds=$(adb shell cat "$DUMP" | grep -o "text=\"$1[^\"]*\"[^>]*bounds=\"[^\"]*\"" | head -1 | grep -o 'bounds="[^"]*"' | grep -o '[0-9]\+' | tr '\n' ' ')
    [ -n "$bounds" ] || return 1
    set -- $bounds
    adb shell input tap $(( ($1 + $3) / 2 )) $(( ($2 + $4) / 2 ))
}
command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1 || skip "no Docker answers here"

# The lab, its fronts and its datasets as the emulator sees them.
"$LAB" up >"$WORK/fronts" || fail "the DNS lab did not start"
. <(sed -n 's/^\([a-z-]*\)=\(.*\)$/FRONT_\1=\2/p' "$WORK/fronts" | tr '-' '_')
"$LAB" data "$WORK/data" >/dev/null || fail "the lab's datasets were not written"
echo "ok: the DNS lab runs; fronts $(tr '\n' ' ' <"$WORK/fronts")"

"$ROOT/scripts/workload-app/build.sh" >/dev/null
adb install -r "$APK" >/dev/null
adb shell pm clear "$PKG" >/dev/null
adb uninstall "$WORKLOAD" >/dev/null 2>&1 || true
adb install "$ROOT/build/workload-app/workload-app.apk" >/dev/null

# Before Watch: whether the emulator's own resolver is the lab's too (started with -dns-server 10.153.53.1). Then
# a lookup that slipped past Watch would show in the lab's log as well; otherwise only Watch's own exchanges do.
if [ "$(lookup printer.home.arpa)" = 192.168.1.50 ]; then
    echo "ok: the emulator's own resolver is the lab's too: a lookup past Watch would show in its log"
else
    echo "ok: the emulator's own resolver is not the lab's; Watch is pointed at the lab's resolver below"
fi

# The lab's tables and root in Watch's files, in place of the pack's (debug builds only).
adb push "$WORK/data/." /data/local/tmp/dnslab >/dev/null
adb shell run-as "$PKG" sh -c "'mkdir -p files/dnslab && cp /data/local/tmp/dnslab/* files/dnslab/'"
adb shell rm -rf /data/local/tmp/dnslab
allow_vpn "$PKG" || fail "Android did not take the VPN consent for $PKG"
[ "$(adb shell getprop ro.build.version.sdk | tr -d '\r')" -lt 37 ] || adb shell pm grant "$PKG" android.permission.ACCESS_LOCAL_NETWORK
adb shell am start -W -n "$PKG/$NETWORK_SCREEN" --ez start true >/dev/null
for _ in $(seq 1 20); do vpn_up && break; sleep 1; done
vpn_up || fail "Watch's tunnel did not come up"
applied=$(sed -n 's/^ *dns-applied //p' <<<"$(dump dns-apply)")
expect "Watch read the lab's tables (relays targets pairs presets)" "$applied" "1 2 2 2"
# The network's resolver is the lab's from here on, through its censor's front on this computer's loopback, as the
# emulator reaches it (10.0.2.2).
set_resolver=$(sed -n 's/^ *dns-network-resolver-set //p' <<<"$(dump dns-network-resolver "10.0.2.2:${FRONT_resolver_alt##*:}")")
expect "Watch asks the lab's resolver as the network's" "$set_resolver" "/10.0.2.2:${FRONT_resolver_alt##*:}"
# The precheck, once the lab is up: a failure, never a skip.
expect "a local name through Watch reaches the lab's resolver" "$(lookup printer.home.arpa)" 192.168.1.50
# Android's own check of the network: where the emulator reaches the internet, its "validated" reaches the engine
# by the real path; where it cannot (its own resolver is the lab's), the engine is told so.
validated=""
for _ in $(seq 1 20); do
    grep -q "dns-validated 1" <<<"$(dump)" && { validated=android; break; }
    sleep 1
done
if [ -n "$validated" ]; then
    echo "ok: Android's own validation of the network reached the engine"
else
    dump dns-validated on >/dev/null
    echo "ok: Android cannot validate the network here (its resolver knows only the lab's names): the engine is told it is"
fi

# 0. "Notify me" without Android's leave to notify (Android 13 and later): the switch asks; refused, it stays off
# and the screen says why (review R-M3). Then the leave, as W9's onboarding will ask it.
if all_steps && [ "$(adb shell getprop ro.build.version.sdk | tr -d '\r')" -ge 33 ]; then
    adb shell pm revoke "$PKG" android.permission.POST_NOTIFICATIONS >/dev/null 2>&1 || true
    adb shell am start -W -n "$PKG/$NETWORK_SCREEN" >/dev/null
    scroll_to "Notify me while names go to the network" || fail "the screen has no \"Notify me\" switch"
    tap_starting "Notify me while names go to the network" || fail "the \"Notify me\" switch could not be tapped"
    denied=""
    for _ in $(seq 1 10); do
        tap_id "com.android.permissioncontroller:id/permission_deny_button" && { denied=yes; break; }
        sleep 1
    done
    [ -n "$denied" ] || fail "turning \"Notify me\" on did not ask for Android's leave to notify"
    sleep 1
    scroll_to "Android does not let Watch show notifications" || fail "refused, the screen does not say why"
    grep -q "dns-notify off" <<<"$(dump)" || fail "refused, \"Notify me\" did not stay off"
    echo "ok: refused Android's leave to notify, \"Notify me\" stayed off and the screen said why"
    adb shell pm grant "$PKG" android.permission.POST_NOTIFICATIONS
fi

# 1. ODoH by default; nothing to the network's resolver; no lookup of Watch's own.
resolver_mark=$(mark resolver)
# Which pair answers first depends on time: the second pair is asked after the hedge's 400 ms, and on CI's slower
# emulator it can answer first (run 44796928789). Either is ODoH through the lab's relay; the order itself is held by
# the ladder's unit tests and by step 8, which holds a pair. What this step proves is that the name goes by ODoH and
# nothing reaches the network's resolver.
probe=$(lookup probe.dnslab.test)
case "$probe" in
    10.53.1.1) target=target-a ;;
    10.53.2.2) target=target-b ;;
    *) fail "a direct app's name goes by ODoH to a lab target: got '$probe', wanted 10.53.1.1 or 10.53.2.2" ;;
esac
echo "ok: a direct app's name goes by ODoH ($target answered)"
expect "Watch's way" "$(way)" "odoh lab-relay lab-$target"
name=$(fresh)
target_mark=$(mark "$target")
lookup "$name" >/dev/null
asked "$target" "$name" "$target_mark" || fail "the target of Watch's way ($target) was not asked $name"
asked resolver "$name" "$resolver_mark" && fail "the network's resolver saw $name"
asked resolver "probe.dnslab.test" "$resolver_mark" && fail "the network's resolver saw probe.dnslab.test"
asked resolver "dnslab.test" "$resolver_mark" && fail "the network's resolver saw a name of the lab's servers: Watch looked one up"
echo "ok: the network's resolver saw none of these names, nor any of the lab's servers"

# 1b. The tunnel set up again (ADR 0044, unit 12b): the engine that takes it has the resolver before its first
# packet, so no lookup slips to the network's resolver meanwhile.
resolver_mark=$(mark resolver)
dump setup-again >/dev/null
names=""
for _ in 1 2 3; do
    name=$(fresh)
    names="$names $name"
    lookup "$name" >/dev/null
done
for name in $names; do
    asked resolver "$name" "$resolver_mark" && fail "after the tunnel was set up again, the network's resolver saw $name"
done
echo "ok: the tunnel set up again, and the network's resolver saw none of the lookups around it"

# 2. Android's opportunistic DNS over TLS: port 853 at Watch's address refused, lookups on port 53.
PRIVATE_MODE=$(adb shell settings get global private_dns_mode | tr -d '\r')
adb shell settings put global private_dns_mode opportunistic
sleep 3
# Either lab pair, as in step 1: the second pair is asked after the hedge's 400 ms, and on CI's slower emulator its
# target can answer first (CI run 44906315436); the property is that the name goes by ODoH, not which pair won.
probe=$(lookup probe.dnslab.test)
case "$probe" in
    10.53.1.1 | 10.53.2.2) ;;
    *) fail "with Private DNS on automatic, a name did not go by ODoH to a lab target: got '$probe', wanted 10.53.1.1 or 10.53.2.2" ;;
esac
[[ "$(way)" == odoh* ]] || fail "with Private DNS on automatic, Watch's way is not ODoH: $(way)"
echo "ok: with Private DNS on automatic, names still go by ODoH ($probe)"
# Watch's DNS addresses, of the set the tunnel took (ADR 0041): Android may try either family.
read -r dns4 dns6 < <(sed -n 's/^ *addresses [^ ]* [^ ]* \([^ ]*\) [^ ]* \([^ ]*\)$/\1 \2/p' <<<"$(dump)")
refused=0
for _ in $(seq 1 30); do
    refused=$(grep -cE "^ *flow tcp [^ ]+ (${dns4//./\\.}|\[$dns6\]):853 [0-9]+ refused" <<<"$(dump)" || true)
    [ "$refused" -ge 1 ] && break
    sleep 1
done
if [ "$refused" -lt 1 ]; then
    grep -E '^ *(addresses|flow tcp .*:853 )' <<<"$(dump)" >&2 || true
    fail "Android's DNS over TLS to Watch's addresses ($dns4, $dns6) at port 853 was never seen refused"
fi
echo "ok: flows to Watch's address at port 853 refused: $refused"
adb shell settings put global private_dns_mode "${PRIVATE_MODE/null/off}"
PRIVATE_MODE=""

# Steps 3 to 7 are not ODoH's (DNSLAB_ONLY=odoh leaves them out); they keep their indentation.
if all_steps; then
# 3. The user's preset (DoH, then DoT) and own resolver.
dump dns-choice preset lab-doh >/dev/null
expect "the DoH preset answers" "$(lookup probe.dnslab.test)" 10.53.3.3
dump dns-choice preset lab-dot >/dev/null
expect "the DoT preset answers" "$(lookup probe.dnslab.test)" 10.53.4.4
dump dns-choice doh "https://doh.dnslab.test:${FRONT_doh##*:}/dns-query" 10.0.2.2 >/dev/null
expect "the user's own DoH resolver answers" "$(lookup probe.dnslab.test)" 10.53.3.3
dump dns-choice odoh >/dev/null

# 3b. The speed budget (ADR 0039, "The speed budget of direct apps' names"): Watch's own cost of each way in the lab,
# where every server is a few milliseconds away, written as ADR 0039 writes the budget on real networks: against plain
# DNS timed in the same step. The engine times each exchange it hands over and answers, per carry (latency CARRY COUNT
# P50 P95, in ms). Each way's lookups go one for one with fresh local names under home.arpa, which only the network's
# resolver answers (the lab's with NXDOMAIN, which the engine times as an answer), so that a stall of the emulator,
# which holds every process on it, falls on both carries alike; the durations are cleared before each way, so that
# only its own exchanges count; and each way gets BUDGET_LOOKUPS lookups, so that its p95 is not its largest few
# (CI's runs 44899858955, 44905337897, 44910873200 and 44910928225, docs/ci-flakes.md). The bounds: each way's p50
# at most 100 ms above plain DNS's, its p95 at most 250 ms above plain DNS's, and plain DNS's own p50 through Watch
# at most 100 ms, so that a slowness common to every carry still fails. No retry. The CPU time Watch's process spends
# per lookup is read from its /proc/PID/stat (ticks of 10 ms).
BUDGET_LOOKUPS=100
BUDGET_P50_ABOVE_MS=100
BUDGET_P95_ABOVE_MS=250
BUDGET_PLAIN_P50_MS=100
watch_pid=$(adb shell pidof "$PKG:network" | tr -d '\r')
[ -n "$watch_pid" ] || watch_pid=$(adb shell pidof "$PKG" | tr -d '\r')
cpu() { adb shell cat "/proc/$watch_pid/stat" | tr -d '\r' | awk '{print $14 + $15}'; }
# Looks the names $1 (by commas) up in the workload app, in order, in one process (fresh names: no cache answers);
# prints how many of them it logged an answer or a failure for.
lookups() {
    adb shell am force-stop "$WORKLOAD"
    adb logcat -c
    adb shell am start -W -n "$WORKLOAD/.WorkActivity" --es names "$1" >/dev/null
    for _ in $(seq 1 180); do
        grep -qx done <<<"$(workload_log)" && break
        sleep 1
    done
    grep -cE '^(resolved|resolve) ' <<<"$(workload_log)" || true
}
# The figures of carry $1 in the dump $2: COUNT P50 P95.
latency_of() { sed -n "s/^ *dns-latency $1 \([0-9]*\) \([0-9]*\) \([0-9]*\)$/\1 \2 \3/p" <<<"$2"; }
# A token of this run: the names below are new to every cache, the emulator's own across runs included.
stamp=$RANDOM
k=0
for choice in "odoh" "preset lab-doh" "preset lab-dot"; do
    k=$((k + 1))
    case $choice in
        odoh) carry=odoh ;;
        "preset lab-doh") carry=doh ;;
        *) carry=dot ;;
    esac
    # shellcheck disable=SC2086 # the choice's words are the dump's arguments
    dump dns-choice $choice >/dev/null
    # Warm, as the budget on real networks is: the way's first exchange opens its connection, which Watch then keeps.
    lookups "name-${stamp}${k}0000.dnslab.test,warm-$stamp-$k.home.arpa" >/dev/null
    # name-N.dnslab.test answers 10.53.0.(N mod 256) on every way; a local name the lab's resolver does not hold
    # gets NXDOMAIN.
    names=""
    for i in $(seq 1 "$BUDGET_LOOKUPS"); do
        names="$names,name-${stamp}${k}$(printf %04d "$i").dnslab.test,plain-$stamp-$k-$i.home.arpa"
    done
    dump dns-times-clear >/dev/null
    before=$(cpu)
    logged=$(lookups "${names#,}")
    after=$(cpu)
    [ "$logged" -eq $((2 * BUDGET_LOOKUPS)) ] ||
        fail "$choice: the workload app logged $logged of its $((2 * BUDGET_LOOKUPS)) lookups within 180 s"
    answered=$(grep -c "^resolved name-${stamp}${k}[0-9]*\.dnslab\.test 10\.53\.0\." <<<"$(workload_log)" || true)
    [ "$answered" -eq "$BUDGET_LOOKUPS" ] || fail "$choice: $answered of the $BUDGET_LOOKUPS names of the way got their address"
    status=$(dump)
    read -r count p50 p95 < <(latency_of "$carry" "$status") || true
    read -r plain_count plain_p50 plain_p95 < <(latency_of network "$status") || true
    figures="$carry p50 ${p50:-?} ms, p95 ${p95:-?} ms (${count:-0} exchanges); plain DNS in the same step p50 ${plain_p50:-?} ms, p95 ${plain_p95:-?} ms (${plain_count:-0} exchanges)"
    [ "${count:-0}" -ge "$BUDGET_LOOKUPS" ] || fail "too few $carry exchanges timed in the lab: $figures"
    [ "${plain_count:-0}" -ge "$BUDGET_LOOKUPS" ] || fail "too few exchanges of plain DNS timed beside $carry in the lab: $figures"
    [ "$plain_p50" -le "$BUDGET_PLAIN_P50_MS" ] && [ "$p50" -le $((plain_p50 + BUDGET_P50_ABOVE_MS)) ] &&
        [ "$p95" -le $((plain_p95 + BUDGET_P95_ABOVE_MS)) ] ||
        fail "$carry in the lab over the budget of ADR 0039 (the way's p50 at most $BUDGET_P50_ABOVE_MS ms above plain DNS's, its p95 at most $BUDGET_P95_ABOVE_MS ms above, plain DNS's p50 at most $BUDGET_PLAIN_P50_MS ms): $figures"
    echo "ok: $carry in the lab, within the budget (ADR 0039): $figures; Watch's CPU per lookup $(( (after - before) * 10 / (2 * BUDGET_LOOKUPS) )) ms ($((2 * BUDGET_LOOKUPS)) lookups, half of them local)"
done
dump dns-choice odoh >/dev/null

# 4. Strict, every encrypted way down.
dump dns-strict on >/dev/null
for front in relay target-a target-b doh; do "$LAB" censor "$front" drop >/dev/null; done
"$LAB" censor dot block >/dev/null
resolver_mark=$(mark resolver)
name=$(fresh)
expect "strict, every way down: the app gets no address" "$(lookup "$name")" failed
asked resolver "$name" "$resolver_mark" && fail "strict: the network's resolver saw $name"
[[ "$(way)" == failing* ]] || fail "strict: the state does not say failing: $(way)"
echo "ok: strict sent nothing to the network's resolver, and Watch's state says $(way)"
expect "strict: a local name still goes to the network's resolver" "$(lookup printer.home.arpa)" 192.168.1.50

# 5. Outside strict: the fallback, its notification, and its end.
dump dns-strict off dns-notify on >/dev/null
name=$(fresh)
resolver_mark=$(mark resolver)
lookup "$name" >/dev/null
asked resolver "$name" "$resolver_mark" || fail "outside strict the network's resolver was not asked $name"
[[ "$(way)" == fallback* ]] || fail "the state does not say fallback: $(way)"
sleep 1
grep -q "id=7203" <<<"$(adb shell dumpsys notification --noredact | tr -d '\r')" || fail "the fallback's notification is not shown"
echo "ok: outside strict the network's resolver answered, the state says $(way), and the notification shows"
all_pass
# Target A's operator's own DoH answers as target A does: the way, not the address, says ODoH is back.
climbed=""
for _ in $(seq 1 40); do
    lookup "$(fresh)" >/dev/null
    if [[ "$(way)" == odoh* ]]; then climbed=yes; break; fi
    sleep 3
done
[ -n "$climbed" ] || fail "the names did not climb back to ODoH once the ways answered"
[[ "$(way)" == "odoh lab-relay lab-target-"[ab] ]] || fail "Watch's way once the ways came back is not ODoH through a lab pair: $(way)"
echo "ok: Watch's way once the ways came back ($(way))"
sleep 1
grep -q "id=7203" <<<"$(adb shell dumpsys notification --noredact | tr -d '\r')" && fail "the notification stayed after the fallback ended"
echo "ok: the fallback ended and its notification went"

# 6. The censor's methods one by one.
# Step 5's drops held the rungs below ODoH for their back-off (up to ladder::BACKOFF_MOST, a minute), and ODoH
# answering again does not end those holds: a rung below is tried only while the ones above are held. The reset
# below asks that the next rung answers, so it starts once nothing is held; Watch falling back to the network
# while every encrypted way is held is right (CI's run 44877347782 met it on a slower emulator).
released=""
for _ in $(seq 1 45); do
    if [ "$(held)" = 0 ]; then released=yes; break; fi
    sleep 2
done
[ -n "$released" ] || fail "the holds of step 5 did not end within 90 s: held $(held)"
"$LAB" censor relay reset-sni relay.dnslab.test >/dev/null
name=$(fresh)
lookup "$name" >/dev/null
[[ "$(way)" == doh-target* || "$(way)" == preset* ]] || fail "a reset on the relay's name did not move to the next way: $(way)"
echo "ok: a reset on the relay's server name: the next way answers ($(way)); held $(held)"
"$LAB" censor relay pass >/dev/null
expect "ODoH stays held after a reset, though the relay answers again" "$(lookup probe.dnslab.test)" "$(lookup probe.dnslab.test)"
[[ "$(way)" != odoh* ]] || fail "ODoH was not held after the reset"
echo "ok: ODoH held after the reset ($(way))"
dump dns-choice preset lab-dot >/dev/null
"$LAB" censor dot block >/dev/null
name=$(fresh)
lookup "$name" >/dev/null
[[ "$(way)" != choice ]] || fail "port 853 blocked: the DoT preset still answered"
echo "ok: port 853 blocked: the next way answers ($(way))"
# "Only this resolver" (review R-M1): nothing else is asked, the network's resolver included.
dump dns-only on >/dev/null
targets=$(target_marks)
resolver_mark=$(mark resolver)
name=$(fresh)
expect "port 853 blocked, only this resolver: the app gets no address" "$(lookup "$name")" failed
asked_target "$name" "$targets" && fail "only this resolver: a target was asked $name"
asked resolver "$name" "$resolver_mark" && fail "only this resolver: the network's resolver saw $name"
echo "ok: only this resolver: nothing else was asked ($(way))"
dump dns-only off >/dev/null
"$LAB" censor dot pass >/dev/null
dump dns-choice odoh >/dev/null
# An injected answer: never for a name that goes encrypted; for a local name, which only the network's resolver
# answers, and for any name once the fallback sends it there.
"$LAB" censor resolver inject >/dev/null
# ODoH is still held from the reset above: whichever encrypted way answers, its own address, never the forged one.
encrypted=$(lookup probe.dnslab.test)
case $encrypted in
    10.53.1.1 | 10.53.2.2 | 10.53.3.3 | 10.53.4.4) echo "ok: an injected answer never reaches a name that goes encrypted ($encrypted, $(way))" ;;
    *) fail "with the network's resolver forging answers, a name that goes encrypted got '$encrypted'" ;;
esac
expect "an injected answer reaches a local name, which only the network's resolver answers" "$(lookup printer.home.arpa)" 10.53.6.6
for front in relay target-a target-b doh; do "$LAB" censor "$front" drop >/dev/null; done
"$LAB" censor dot block >/dev/null
expect "outside strict, every way down: the injected answer reaches the app through the fallback" "$(lookup "$(fresh)")" 10.53.6.6
all_pass
"$LAB" censor resolver pass >/dev/null
dump dns-choice odoh >/dev/null

# 7. Behind a captive portal no failure counts: told the network is not validated, as Android says behind one (a
# debug command: no emulator here sits behind a real portal).
dump dns-validated off >/dev/null
sleep 1
grep -q "dns-validated 0" <<<"$(dump)" || fail "the engine was not told the network is not validated"
# The holds of the steps before stay (a change of setting keeps them, review R-m1): no new one may come, and those
# there only end.
before=$(held)
for front in relay target-a target-b doh dot; do "$LAB" censor "$front" reset >/dev/null; done
lookup "$(fresh)" >/dev/null
[ "$(held)" -le "$before" ] || fail "behind a captive portal, failures held ways: $(held) held, $before before"
echo "ok: behind a captive portal, failures held nothing new ($(held) held, $before before)"
all_pass
dump dns-validated on >/dev/null
fi

# What the resolver learned (its holds) stays across a change of strict or of the choice (review R-m1), but not of
# the pairs, whose steps are others then: a step that needs the ways fresh changes the pairs and back.
fresh_resolver() {
    dump dns-pairs "'lab-relay>lab-target-b'" >/dev/null
    dump dns-pairs default >/dev/null
    [ "$(held)" = 0 ] || fail "a change of pairs did not start the ways afresh: $(held) held"
}

# Steps 8 and 9 are not ODoH's either.
if all_steps; then
# 8. A WireGuard endpoint's name goes the encrypted way.
fresh_resolver
targets=$(target_marks)
resolver_mark=$(mark resolver)
key=$(python3 -I -c 'import base64,os; print(base64.b64encode(os.urandom(32)).decode())')
peer=$(python3 -I -c 'import base64,os; print(base64.b64encode(os.urandom(32)).decode())')
printf '[Interface]\nPrivateKey = %s\nAddress = 10.77.9.2/32\nDNS = 10.77.9.1\n[Peer]\nPublicKey = %s\nAllowedIPs = 0.0.0.0/0\nEndpoint = probe.dnslab.test:51820\n' "$key" "$peer" |
    adb shell run-as "$PKG" sh -c "'cat > files/wg-dns.conf'"
dump tunnel-add 9 wg-dns.conf >/dev/null
adb shell run-as "$PKG" rm -f files/wg-dns.conf
uid=$(adb shell cmd package list packages -U "$WORKLOAD" | tr -d '\r' | sed -n "s/^package:$WORKLOAD uid:\([0-9]*\)$/\1/p")
dump tunnel-route "$uid" 9 >/dev/null
adb shell am start -W -n "$WORKLOAD/.WorkActivity" --es udp 10.77.9.1:7 >/dev/null
for _ in $(seq 1 15); do
    asked_target probe.dnslab.test "$targets" && break
    sleep 1
done
asked_target probe.dnslab.test "$targets" || fail "the endpoint's name did not go by ODoH"
asked resolver probe.dnslab.test "$resolver_mark" && fail "the endpoint's name reached the network's resolver"
state=$(sed -n 's/^ *tunnel 9 //p' <<<"$(dump)")
echo "ok: the WireGuard endpoint's name went by ODoH, not to the network's resolver (tunnel state: $state)"
dump tunnel-remove 9 >/dev/null
# The workload app back on its own way: a removed configuration's apps wait for it otherwise.
dump tunnel-route "$uid" 0 >/dev/null

fresh_resolver
# 9. A network's search domains (review S-C1): a public suffix is refused; under the network's own domain, the
# encrypted way first, the network's resolver only for a name the internet does not know.
search=$(sed -n 's/^ *dns-search-set //p' <<<"$(dump dns-search "com,office.example")")
expect "the search domains Watch keeps of com and office.example" "$search" office.example
for _ in $(seq 1 10); do grep -q "dns-search office.example" <<<"$(dump)" && break; sleep 1; done
grep -q "dns-search office.example" <<<"$(dump)" || fail "the engine does not show the network's domain in use"
targets=$(target_marks)
resolver_mark=$(mark resolver)
expect "a name only the network knows, under its own domain" "$(lookup nas.office.example)" 192.168.1.60
asked_target nas.office.example "$targets" || fail "nas.office.example did not go the encrypted way first"
asked resolver nas.office.example "$resolver_mark" || fail "nas.office.example did not reach the network's resolver"
leak="leak-$RANDOM.example.com"
expect "a name under com, which the network set as its domain" "$(lookup "$leak")" failed
asked resolver "$leak" "$resolver_mark" && fail "a name under com reached the network's resolver"
echo "ok: com refused as a search domain; office.example's name reached the network only after the internet did not know it"
dump dns-search "" >/dev/null
fi

fresh_resolver
# 10. A target's key rotated (review S-M1, S-C2): the pair that meets the 401 is held, the other carries the names;
# the key is fetched minutes later in the product, a second or two here, at the target's own addresses; then the
# pair answers again.
dump dns-refresh 1 2 >/dev/null
"$LAB" rotate >/dev/null || fail "the lab's target-a did not rotate its key"
target_b_mark=$(mark target-b)
name=$(fresh)
lookup "$name" >/dev/null
asked target-b "$name" "$target_b_mark" || fail "after target-a's new key, the other pair did not carry $name"
[ "$(held)" -ge 1 ] || fail "target-a's pair was not held after its 401"
echo "ok: target-a's key rotated: the other pair carried the name ($(way)), held $(held)"
# The fetch, a second or two later: the hold ends once the new key is in.
released=""
for _ in $(seq 1 20); do
    sleep 1
    [ "$(held)" = 0 ] && { released=yes; break; }
done
dump dns-refresh off >/dev/null
[ -n "$released" ] || fail "target-a's pair stayed held: its new key was not fetched"
# The first pair alone, its key kept across the change: it answers with the new key.
dump dns-pairs "'lab-relay>lab-target-a'" >/dev/null
target_mark=$(mark target-a)
name=$(fresh)
lookup "$name" >/dev/null
asked target-a "$name" "$target_mark" || fail "target-a's pair did not answer again after its new key"
expect "the way after target-a's new key" "$(way)" "odoh lab-relay lab-target-a"
dump dns-pairs default >/dev/null
echo "ok: target-a's new key was fetched apart from the lookup, and its pair answers again"

if all_steps; then
    echo "== the DNS check passed"
else
    echo "== the DNS check's ODoH steps passed (1, 1b, 2, 10), through the relay $(sed -n 's/^lab-relay\t\([^\t]*\)\t.*/\1/p' "$WORK/data/relays.tsv")"
fi
