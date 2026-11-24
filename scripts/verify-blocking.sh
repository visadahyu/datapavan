#!/usr/bin/env bash
# W8 part 3a's emulator check (ADR 0053): tracker blocking and its undo on a real Android, through Android's own
# resolver and TCP stack, against the blocking lab on this computer (scripts/blocklab.py, on its loopback alone, which
# the emulator reaches as 10.0.2.2). The project's own fixture (scripts/blocking-fixture), installed as two apps, A and
# B, and as a browser, looks up and reaches the lab's names under home.arpa, which only the network part's debug builds
# block (a row of their own, never a real tracker's). The network part asks the lab's DNS server as the network's
# resolver (its debug command `dns-network-resolver`); local names go there in every setting. The lab is the witness of
# what left: it logs every question, connection, byte and datagram. The check:
#   1. a blocked lookup gets no address, and the lab is never asked; two apps, one name, within a second: the blocked
#      one gets none and the allowed one the lab's address, and the blocked one still gets none after (Android's one
#      cache per network carried nothing);
#   2. a TLS hello in two segments, a plain HTTP request and a QUIC hello in two datagrams, each to the lab's address
#      with the blocked name: the TCP connection reaches the lab (its handshake always does) but carries no byte, and
#      the QUIC flow sends no datagram and gets "port unreachable"; the allowed app's go through, echoed;
#   3. a name whose CNAME leads to the blocked one is blocked;
#   4. the undo, timed and by taps on the screen: "Allow trackers in this app" in "Now" lets B's next lookup through
#      within seconds, and "Block trackers again" stops it again;
#   5. the pause on the network screen lifts every block, "Block again now" ends it;
#   6. the browser is left out by default and said so, and blocked once included;
#   7. no notification names an app or a name of the run.
# Where the lab cannot start here (no python3), the check is skipped, with a line that says so; with BLOCKING_REQUIRED=1,
# which CI sets, that fails.
#
#   scripts/verify-blocking.sh [path/to/Datapavan-Advanced-debug.apk]
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APK="${1:-$ROOT/android/app/build-advanced/outputs/apk/debug/app-debug.apk}"
PKG=org.visadahyu.datapavan.advanced
NETWORK_SCREEN=org.visadahyu.datapavan.network.MainActivity
FIXTURE=org.visadahyu.datapavan.blockfixture
A=$FIXTURE.a
B=$FIXTURE.b
BROWSER=$FIXTURE.browser
HOST=10.0.2.2
TRACKER=tracker.blocklab.home.arpa
CLOAKED=cloaked.blocklab.home.arpa
PLAIN=plain.blocklab.home.arpa
# shellcheck source=scripts/adb-ui.sh
. "$ROOT/scripts/adb-ui.sh"

[ -n "${ANDROID_SERIAL:-}" ] || { echo "set ANDROID_SERIAL to the emulator's serial" >&2; exit 2; }
is_emulator || { echo "verify-blocking.sh runs on an emulator only" >&2; exit 2; }
WORK="$(mktemp -d)"
LAB=""

cleanup() {
    local status=$?
    adb shell am force-stop "$PKG" >/dev/null 2>&1 || true
    for app in "$A" "$B" "$BROWSER"; do adb uninstall "$app" >/dev/null 2>&1 || true; done
    if [ -n "$LAB" ]; then kill "$LAB" 2>/dev/null || true; fi
    if [ "$status" != 0 ] && [ -f "$WORK/events.log" ]; then
        mkdir -p "$ROOT/build/blocklab"
        cp "$WORK/events.log" "$ROOT/build/blocklab/events-verify-blocking.log" || true
    fi
    rm -rf "$WORK"
}
trap cleanup EXIT

dump() { adb shell dumpsys activity service "$PKG/org.visadahyu.datapavan.network.NetworkVpnService" "$@" | tr -d '\r'; }
fixture_log() { adb logcat -d -s DatapavanBlockingFixture | tr -d '\r' | sed -n 's/.*DatapavanBlockingFixture: //p'; }
fail() {
    echo "BLOCKING CHECK FAILED: $*" >&2
    echo "the network part's blocking:" >&2
    dump | grep -E '^ *(blocking|blocked)' >&2 || true
    echo "The lab's last events:" >&2
    tail -20 "$WORK/events.log" >&2 || true
    echo "The fixture's lines:" >&2
    fixture_log | tail -20 >&2 || true
    adb logcat -d -b crash 2>/dev/null | tail -30 >&2 || true
    exit 1
}
ok() { echo "ok: $*"; }
vpn_up() {
    local uid
    uid=$(adb shell cmd package list packages -U "$PKG" | tr -d '\r' | sed -n "s/^package:$PKG uid:\([0-9]*\)$/\1/p")
    [ -n "$uid" ] && grep -qE "OwnerUid: $uid " <<<"$(adb shell dumpsys connectivity | tr -d '\r')"
}
uid_of() { adb shell cmd package list packages -U "$1" | tr -d '\r' | sed -n "s/^package:$1 uid:\([0-9]*\)$/\1/p"; }

# Starts the fixture $1 afresh with the action $2 and the extras after: a new process each time, so that no
# answer its own runtime keeps (Android's keeps one about 2 s, a failed one too) stands for a new lookup.
start_fixture() {
    local package=$1 action=$2
    shift 2
    adb shell am force-stop "$package"
    adb shell am start -n "$package/$FIXTURE.BlockActivity" --es action "$action" "$@" >/dev/null
}
result_of() {
    local action=$1 line=""
    for _ in $(seq 1 30); do
        line=$(fixture_log | grep -E "^$action " | tail -1 || true)
        [ -n "$line" ] && break
        sleep 0.5
    done
    printf '%s\n' "${line#"$action "}"
}
run_fixture() {
    adb logcat -c
    start_fixture "$@"
    result_of "$2"
}
lookup() { run_fixture "$1" lookup --es name "$2"; }
# How many lines of the lab's events match the pattern $1.
events() { grep -cE "$1" "$WORK/events.log" || true; }

# The lab. Skipped only where it cannot start here at all.
if ! command -v python3 >/dev/null 2>&1; then
    if [ "${BLOCKING_REQUIRED:-}" = 1 ]; then
        echo "BLOCKING CHECK FAILED: BLOCKING_REQUIRED=1, and the blocking lab cannot start here (no python3)" >&2
        exit 1
    fi
    echo "SKIPPED verify-blocking.sh: the blocking lab cannot start here (no python3); nothing of W8 part 3a was checked on the emulator"
    exit 0
fi
python3 -I "$ROOT/scripts/blocklab.py" "$WORK/events.log" >"$WORK/lab.out" 2>"$WORK/lab.err" &
LAB=$!
for _ in $(seq 1 20); do grep -q '^BLOCKLAB ' "$WORK/lab.out" && break; sleep 0.25; done
read -r DNS_PORT TCP_PORT UDP_PORT < <(sed -n 's/^BLOCKLAB dns=\([0-9]*\) tcp=\([0-9]*\) udp=\([0-9]*\)$/\1 \2 \3/p' "$WORK/lab.out")
[ -n "${UDP_PORT:-}" ] || { cat "$WORK/lab.err" >&2; fail "the blocking lab did not start"; }
ok "the blocking lab answers on this computer's loopback: DNS $DNS_PORT, TCP $TCP_PORT, UDP $UDP_PORT"
{ read -r QUIC_FIRST; read -r QUIC_SECOND; } <"$ROOT/scripts/blocking-fixture/quic-hello.hex"

"$ROOT/scripts/blocking-fixture/build.sh" >/dev/null
adb install -r "$APK" >/dev/null
adb shell pm clear "$PKG" >/dev/null
for role in a b browser; do
    adb uninstall "$FIXTURE.$role" >/dev/null 2>&1 || true
    adb install "$ROOT/build/blocking-fixture/blocking-fixture-$role.apk" >/dev/null
done
A_UID=$(uid_of "$A")
B_UID=$(uid_of "$B")
[ -n "$A_UID" ] && [ -n "$B_UID" ] && [ -n "$(uid_of "$BROWSER")" ] || fail "the fixtures did not install"
allow_vpn "$PKG" || fail "Android did not take the VPN consent for $PKG"
[ "$(adb shell getprop ro.build.version.sdk | tr -d '\r')" -lt 37 ] || adb shell pm grant "$PKG" android.permission.ACCESS_LOCAL_NETWORK
adb shell am start -W -n "$PKG/$NETWORK_SCREEN" --ez start true >/dev/null
for _ in $(seq 1 20); do vpn_up && break; sleep 1; done
vpn_up || fail "the network part's tunnel did not come up"
set_resolver=$(sed -n 's/^ *dns-network-resolver-set //p' <<<"$(dump dns-network-resolver "$HOST:$DNS_PORT")")
[ "$set_resolver" = "/$HOST:$DNS_PORT" ] || fail "the network part did not take the lab as the network's resolver: '$set_resolver'"
# The precheck, blocking off: a failure, never a skip.
# Only the control name: an answer for the blocked name now would wait in Android's cache for its time to live,
# which no app can flush, and stand for the lookups after blocking is on (an accepted limit, ADR 0053).
[ "$(lookup "$A" "$PLAIN")" = "ok $HOST" ] || fail "the lab's control name did not resolve through the network part"
ok "with blocking off, the lab's names resolve through the network part"

# Blocking on, by its switch on the network screen; the browser is said to be left out.
adb shell am start -W -n "$PKG/$NETWORK_SCREEN" --activity-clear-top >/dev/null
tap_text "Block trackers" || fail "the network screen has no switch \"Block trackers\""
state=""
for _ in $(seq 1 10); do
    state=$(dump | sed -n 's/^ *blocking \(on\|off\) .*/\1/p' | head -1)
    [ "$state" = on ] && break
    sleep 1
done
[ "$state" = on ] || fail "the switch did not turn blocking on"
# "blocking on" comes from the settings at once; the browsers and the covered apps come from the facts the handover
# publishes after the engine has the table, a moment later (CI, run 45033044776, attempt 1: the browser line was read
# before it). Wait for the handover, then read once, so that "not published yet" stays apart from "published without
# the browser". The blocked lookup below needs the same handover.
handed_over() { grep -qE '^ *blocking on .* covered [1-9][0-9]*$' <<<"$(dump)"; }
within 10 handed_over || fail "the network part did not publish what blocking covers within 10 s of blocking on: $(dump | grep -E '^ *blocking ' | head -1)"
line=$(dump | grep -E '^ *blocking on ' | head -1)
grep -qE 'table [1-9][0-9]* ' <<<"$line" || fail "the network part holds no graded table: $line"
grep -qE "^ *blocking-browser $BROWSER\$" <<<"$(dump)" || fail "the fixture's browser is not told as a browser"
scroll_to "Browsers are not blocked" || fail "the screen does not say that browsers are left out"
ok "blocking is on ($line), and the browser is left out and said so"

# 1. A blocked lookup: no address, and the lab never asked.
asked=$(events "^dns $TRACKER ")
[ "$(lookup "$A" "$TRACKER")" = none ] || fail "A's lookup of the blocked name got an address"
[ "$(lookup "$B" "$TRACKER")" = none ] || fail "B's lookup of the blocked name got an address"
[ "$(events "^dns $TRACKER ")" = "$asked" ] || fail "the lab was asked the blocked name"
grep -qE "^ *blocked $A_UID $TRACKER [1-9]" <<<"$(dump)" || fail "the network part counted no blocked lookup of A"
ok "a blocked name gets no address, and nothing leaves the phone for it"

# 4. The undo, timed: one tap on B's row in "Now", which its bytes to the lab's control name put there.
[[ $(run_fixture "$B" hello --es name "$PLAIN" --es host "$HOST" --es port "$TCP_PORT") == ok\ * ]] ||
    fail "B's hello to the control name did not go through"
network_now "$PKG" "$B" "$WORK/now.xml" >/dev/null
tap_text "Allow trackers in this app" || fail "B's row in \"Now\" has no \"Allow trackers in this app\""
tapped=$SECONDS
through=""
for _ in $(seq 1 20); do
    [ "$(lookup "$B" "$TRACKER")" = "ok $HOST" ] && { through=$((SECONDS - tapped)); break; }
done
[ -n "$through" ] || fail "B's lookup did not get through after the allow"
grep -qE "^ *blocking-allowed $B " <<<"$(dump)" || fail "the network part does not hold B's allowance"
ok "one tap allowed B: its lookup went through ${through} s after the tap"

# 1 (cont.). Two apps, one name, within a second: each gets its own answer, and A still none after.
adb logcat -c
start_fixture "$A" lookup --es name "$TRACKER"
start_fixture "$B" lookup --es name "$TRACKER"
for _ in $(seq 1 30); do [ "$(fixture_log | grep -c '^done$')" -ge 2 ] && break; sleep 0.5; done
results=$(fixture_log | grep '^lookup ' | sort)
[ "$(grep -c '^lookup none$' <<<"$results")" = 1 ] && [ "$(grep -c "^lookup ok $HOST\$" <<<"$results")" = 1 ] ||
    fail "two apps, one name, within a second: '$results'"
[ "$(lookup "$A" "$TRACKER")" = none ] || fail "A got B's answer after it: Android's cache carried it"
ok "two apps, one name, within a second: the blocked one got none, the allowed one the address"

# 2. The connections, by the blocked name at the lab's address.
opened=$(events '^tcp-open ')
bytes=$(events '^tcp-bytes ')
hello=$(run_fixture "$A" hello --es name "$TRACKER" --es host "$HOST" --es port "$TCP_PORT")
case $hello in reset | closed) ;; *) fail "A's blocked hello in two segments: '$hello'" ;; esac
http=$(run_fixture "$A" http --es name "$TRACKER" --es host "$HOST" --es port "$TCP_PORT")
case $http in reset | closed) ;; *) fail "A's blocked plain request: '$http'" ;; esac
sleep 1
[ "$(events '^tcp-open ')" -ge $((opened + 2)) ] || fail "the lab saw no connection (the handshake does reach it)"
[ "$(events '^tcp-bytes ')" = "$bytes" ] || fail "a byte of a blocked connection reached the lab"
datagrams=$(events '^udp ')
quic=$(run_fixture "$A" quic --es host "$HOST" --es port "$UDP_PORT" --es first "$QUIC_FIRST" --es second "$QUIC_SECOND")
[ "$quic" = unreachable ] || fail "A's blocked QUIC hello in two datagrams: '$quic'"
[ "$(events '^udp ')" = "$datagrams" ] || fail "a datagram of a blocked QUIC flow reached the lab"
ok "a hello in two segments, a plain request and a QUIC hello in two datagrams: no byte, no datagram reached the lab"
hello=$(run_fixture "$B" hello --es name "$TRACKER" --es host "$HOST" --es port "$TCP_PORT")
[[ $hello == ok\ * ]] || fail "B's allowed hello: '$hello'"
quic=$(run_fixture "$B" quic --es host "$HOST" --es port "$UDP_PORT" --es first "$QUIC_FIRST" --es second "$QUIC_SECOND")
[[ $quic == ok\ * ]] || fail "B's allowed QUIC hello: '$quic'"
ok "the allowed app's hello and QUIC hello went through, echoed"

# 3. CNAME cloaking.
[ "$(lookup "$A" "$CLOAKED")" = none ] || fail "A's lookup of a name whose CNAME leads to the blocked one got an address"
[ "$(lookup "$B" "$CLOAKED")" = "ok $HOST" ] || fail "B's lookup of the cloaked name did not resolve"
ok "a name whose CNAME chain leads to the blocked name is blocked"

# 4 (cont.). One tap blocks B again.
network_now "$PKG" "$B" "$WORK/now.xml" >/dev/null
tap_text "Block trackers again" || fail "B's row in \"Now\" has no \"Block trackers again\""
tapped=$SECONDS
stopped=""
for _ in $(seq 1 20); do
    [ "$(lookup "$B" "$TRACKER")" = none ] && { stopped=$((SECONDS - tapped)); break; }
done
[ -n "$stopped" ] || fail "B's lookup still got through after \"Block trackers again\""
ok "one tap blocked B again: its lookup got none ${stopped} s after the tap"

# 5. The pause, which names no app.
adb shell am start -W -n "$PKG/$NETWORK_SCREEN" --activity-clear-top >/dev/null
tap_text "Pause blocking for 10 minutes" || fail "the network screen has no \"Pause blocking for 10 minutes\""
paused=""
for _ in $(seq 1 20); do [ "$(lookup "$A" "$TRACKER")" = "ok $HOST" ] && { paused=yes; break; }; done
[ -n "$paused" ] || fail "the pause did not lift A's block"
adb shell am start -W -n "$PKG/$NETWORK_SCREEN" --activity-clear-top >/dev/null
tap_text "Block again now" || fail "the network screen has no \"Block again now\" while paused"
again=""
for _ in $(seq 1 20); do [ "$(lookup "$A" "$TRACKER")" = none ] && { again=yes; break; }; done
[ -n "$again" ] || fail "\"Block again now\" did not end the pause"
ok "the pause lifted every block, and \"Block again now\" ended it"

# 6. The browser: left out by default, blocked once included.
[ "$(lookup "$BROWSER" "$TRACKER")" = "ok $HOST" ] || fail "the browser was blocked though browsers are left out"
adb shell am start -W -n "$PKG/$NETWORK_SCREEN" --activity-clear-top >/dev/null
tap_text "Also block in browsers" || fail "the network screen has no \"Also block in browsers\""
included=""
for _ in $(seq 1 20); do [ "$(lookup "$BROWSER" "$TRACKER")" = none ] && { included=yes; break; }; done
[ -n "$included" ] || fail "the browser was not blocked once included"
ok "the browser is left out by default, and blocked once included"

# 7. Nothing outside the app names an app or a name of the run.
notifications=$(adb shell dumpsys notification --noredact 2>/dev/null | tr -d '\r' | grep -iE "tickerText|android.text|android.title" || true)
for leak in "$TRACKER" "$CLOAKED" blocklab "$A" "$B" "$BROWSER" "blocking fixture"; do
    ! grep -qiF "$leak" <<<"$notifications" || fail "a notification names '$leak'"
done
ok "no notification names an app or a name of the run"
echo "== the blocking check passed"
