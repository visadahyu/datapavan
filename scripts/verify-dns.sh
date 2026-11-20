#!/usr/bin/env bash
# W8, part 1's emulator check (ADR 0042, "How it is built"): Watch's encrypted resolver for the names of apps that go
# directly, on a real Android, against the DNS lab (scripts/dnslab.sh, Compose project datapavan-dnslab). Each of the
# lab's servers answers probe.dnslab.test with an address of its own, and each logs the names it was asked, so the
# check reads which way answered from what the app was given and from the servers' logs, and that nothing reached
# the network's resolver from the network resolver's own log (what reached it, as a capture would show it).
#
# The emulator must use the lab's resolver as its network's: start it with `-dns-server 10.153.53.1` (the lab's bridge on this computer; the emulator ignores a loopback
# address there). The check:
#   1. a direct app's name goes by Oblivious DoH through the lab's relay to the first target, and the network's
#      resolver never sees it; Watch's own process looks up no name at all;
#   2. Android's opportunistic DNS over TLS to Watch's address is refused, and its lookups come on port 53;
#   3. the user's preset (DoH, then DoT) and the user's own DoH resolver answer;
#   4. strict, with every encrypted way down (the censor drops them): the app gets no address, nothing reaches the
#      network's resolver, Watch's state says so, and a local name (printer.home.arpa) still resolves;
#   5. outside strict, the same: the network's resolver answers, the state says fallback, the notification shows;
#      the ways come back, and once their back-off ends the names go by ODoH again;
#   6. the censor's methods one by one: a reset on the relay's server name holds ODoH for six minutes and the next
#      way answers; port 853 blocked fails the DoT preset over to the next way; an injected answer reaches the app
#      only through the fallback;
#   7. behind a captive portal no failure counts (the engine told so: the lab's resolver knows only the lab's
#      names, so Android's own check of the network cannot pass on the emulator);
#   8. a WireGuard endpoint's name goes the encrypted way.
#
#   scripts/verify-dns.sh [path/to/Datapavan-Advanced-debug.apk]
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APK="${1:-$ROOT/android/app/build-advanced/outputs/apk/debug/app-debug.apk}"
PKG=org.visadahyu.datapavan.advanced
WATCH_SCREEN=org.visadahyu.datapavan.watch.MainActivity
WORKLOAD=org.visadahyu.datapavan.workload
LAB="$ROOT/scripts/dnslab.sh"
# shellcheck source=scripts/adb-ui.sh
. "$ROOT/scripts/adb-ui.sh"

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

dump() { adb shell dumpsys activity service "$PKG/org.visadahyu.datapavan.watch.WatchVpnService" "$@" | tr -d '\r'; }
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

# Before Watch: the emulator's network resolver must be the lab's.
expect "the emulator's network resolver is the lab's (printer.home.arpa before Watch)" "$(lookup printer.home.arpa)" 192.168.1.50

# The lab's tables and root in Watch's files, in place of the pack's (debug builds only).
adb push "$WORK/data/." /data/local/tmp/dnslab >/dev/null
adb shell run-as "$PKG" sh -c "'mkdir -p files/dnslab && cp /data/local/tmp/dnslab/* files/dnslab/'"
adb shell rm -rf /data/local/tmp/dnslab
allow_vpn "$PKG" || fail "Android did not take the VPN consent for $PKG"
[ "$(adb shell getprop ro.build.version.sdk | tr -d '\r')" -lt 37 ] || adb shell pm grant "$PKG" android.permission.ACCESS_LOCAL_NETWORK
# The fallback's notification needs the user's leave from Android 13 on, which W9's onboarding asks.
[ "$(adb shell getprop ro.build.version.sdk | tr -d '\r')" -lt 33 ] || adb shell pm grant "$PKG" android.permission.POST_NOTIFICATIONS
adb shell am start -W -n "$PKG/$WATCH_SCREEN" --ez start true >/dev/null
for _ in $(seq 1 20); do vpn_up && break; sleep 1; done
vpn_up || fail "Watch's tunnel did not come up"
# The lab's resolver knows only the lab's names, so Android's own check of the network can never pass here: the
# engine is told the network is validated, as it would be on a real network, and step 7 tells it otherwise.
dump dns-validated on >/dev/null
applied=$(sed -n 's/^ *dns-applied //p' <<<"$(dump dns-apply)")
expect "Watch read the lab's tables (relays targets pairs presets)" "$applied" "1 2 2 2"

# 1. ODoH by default; nothing to the network's resolver; no lookup of Watch's own.
resolver_mark=$(mark resolver)
expect "a direct app's name goes by ODoH to the first target" "$(lookup probe.dnslab.test)" 10.53.1.1
expect "Watch's way" "$(way)" "odoh lab-relay lab-target-a"
name=$(fresh)
target_mark=$(mark target-a)
lookup "$name" >/dev/null
asked target-a "$name" "$target_mark" || fail "the first target was not asked $name"
asked resolver "$name" "$resolver_mark" && fail "the network's resolver saw $name"
asked resolver "probe.dnslab.test" "$resolver_mark" && fail "the network's resolver saw probe.dnslab.test"
asked resolver "dnslab.test" "$resolver_mark" && fail "the network's resolver saw a name of the lab's servers: Watch looked one up"
echo "ok: the network's resolver saw none of these names, nor any of the lab's servers"

# 2. Android's opportunistic DNS over TLS: port 853 at Watch's address refused, lookups on port 53.
PRIVATE_MODE=$(adb shell settings get global private_dns_mode | tr -d '\r')
adb shell settings put global private_dns_mode opportunistic
sleep 3
expect "with Private DNS on automatic, names still go by ODoH" "$(lookup probe.dnslab.test)" 10.53.1.1
refused=$(grep -cE "^ *flow tcp [^ ]+ 10\.1\.10\.3:853 [0-9]+ refused" <<<"$(dump)" || true)
echo "ok: flows to Watch's address at port 853 refused: $refused"
adb shell settings put global private_dns_mode "${PRIVATE_MODE/null/off}"
PRIVATE_MODE=""

# 3. The user's preset (DoH, then DoT) and own resolver.
dump dns-choice preset lab-doh >/dev/null
expect "the DoH preset answers" "$(lookup probe.dnslab.test)" 10.53.3.3
dump dns-choice preset lab-dot >/dev/null
expect "the DoT preset answers" "$(lookup probe.dnslab.test)" 10.53.4.4
dump dns-choice doh "https://doh.dnslab.test:${FRONT_doh##*:}/dns-query" 10.0.2.2 >/dev/null
expect "the user's own DoH resolver answers" "$(lookup probe.dnslab.test)" 10.53.3.3
dump dns-choice odoh >/dev/null

# 3b. The speed budget (ADR 0039): Watch's own cost of each way in the lab, where every server is a few
# milliseconds away. The engine times each exchange it hands over and answers (latency WAY COUNT P50 P95, in ms);
# the CPU time Watch's process spends per lookup is read from its /proc/PID/stat (ticks of 10 ms).
watch_pid=$(adb shell pidof "$PKG:watch" | tr -d '\r')
[ -n "$watch_pid" ] || watch_pid=$(adb shell pidof "$PKG" | tr -d '\r')
cpu() { adb shell cat "/proc/$watch_pid/stat" | tr -d '\r' | awk '{print $14 + $15}'; }
for choice in "odoh" "preset lab-doh" "preset lab-dot"; do
    # shellcheck disable=SC2086 # the choice's words are the dump's arguments
    dump dns-choice $choice >/dev/null
    before=$(cpu)
    for _ in $(seq 1 20); do lookup "$(fresh)" >/dev/null; done
    after=$(cpu)
    echo "ok: $choice: Watch's CPU per lookup $(( (after - before) * 10 / 20 )) ms (20 lookups)"
done
dump dns-choice odoh >/dev/null
grep -E '^ *dns-latency ' <<<"$(dump)" | sed 's/^ */  /'
for carry in odoh doh dot; do
    read -r count p50 p95 < <(sed -n "s/^ *dns-latency $carry \([0-9]*\) \([0-9]*\) \([0-9]*\)$/\1 \2 \3/p" <<<"$(dump)")
    [ "${count:-0}" -ge 15 ] || fail "too few $carry exchanges timed: ${count:-0}"
    [ "$p50" -le "${DNS_BUDGET_LAB_P50_MS:-100}" ] && [ "$p95" -le "${DNS_BUDGET_LAB_P95_MS:-400}" ] ||
        fail "$carry in the lab: p50 $p50 ms, p95 $p95 ms, over the budget of ${DNS_BUDGET_LAB_P50_MS:-100} and ${DNS_BUDGET_LAB_P95_MS:-400} ms (ADR 0039)"
    echo "ok: $carry in the lab: p50 $p50 ms, p95 $p95 ms, within the budget (ADR 0039)"
done

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
expect "Watch's way once the ways came back" "$(way)" "odoh lab-relay lab-target-a"
sleep 1
grep -q "id=7203" <<<"$(adb shell dumpsys notification --noredact | tr -d '\r')" && fail "the notification stayed after the fallback ended"
echo "ok: the fallback ended and its notification went"

# 6. The censor's methods one by one.
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
"$LAB" censor dot pass >/dev/null
dump dns-choice odoh >/dev/null
"$LAB" censor resolver inject >/dev/null
expect "an injected answer reaches a local name, which only the network's resolver answers" "$(lookup printer.home.arpa)" 10.53.6.6
"$LAB" censor resolver pass >/dev/null

# 7. Behind a captive portal no failure counts: told the network is not validated, as Android says behind one.
dump dns-validated off >/dev/null
sleep 1
grep -q "dns-validated 0" <<<"$(dump)" || fail "the engine was not told the network is not validated"
for front in relay target-a target-b doh dot; do "$LAB" censor "$front" reset >/dev/null; done
lookup "$(fresh)" >/dev/null
expect "behind a captive portal, failures held nothing" "$(held)" 0
all_pass
dump dns-validated on >/dev/null

# 8. A WireGuard endpoint's name goes the encrypted way.
target_mark=$(mark target-a)
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
    asked target-a probe.dnslab.test "$target_mark" && break
    sleep 1
done
asked target-a probe.dnslab.test "$target_mark" || fail "the endpoint's name did not go by ODoH"
asked resolver probe.dnslab.test "$resolver_mark" && fail "the endpoint's name reached the network's resolver"
state=$(sed -n 's/^ *tunnel 9 //p' <<<"$(dump)")
echo "ok: the WireGuard endpoint's name went by ODoH, not to the network's resolver (tunnel state: $state)"
dump tunnel-remove 9 >/dev/null

echo "== the DNS check passed"
