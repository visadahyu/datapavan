#!/usr/bin/env bash
# End-to-end check of Watch's connection log, milestone W4 (docs/DESIGN.md 13.2, ADR 0037), on an
# emulator only: it sets a screen-lock PIN and locks the screen, which a phone's owner would not want.
# It starts the test server (scripts/watch-lab/server.py), carries a TCP and a UDP flow of adb's shell
# (UID 2000) through Watch, has the engine hand over its records at once (a debug command), and checks:
# that the log holds both flows with their bytes; that the database files hold no destination in the
# clear; that Watch's log output names no destination; that an earlier day cannot be opened while the
# phone is locked and can once it is unlocked; that the wipe leaves no file and no key; that over a
# scripted session the shell's bytes in the log are within 5 % of Android's own count (M4's bar), both
# counted as IP packets on the tunnel; that expiry does not wait for traffic (a day past retention is
# never read, and leaves the file when Watch starts again; a shorter retention deletes at once; "none"
# leaves no file and no key); and then runs the log's model test (LogModel, debug builds) inside Watch.
#
#   scripts/verify-log.sh [path/to/watch-debug.apk]
#
# LOG_MODEL_SEED repeats a model run that failed (each run draws a seed and prints it); LOG_MODEL_STEPS
# sets its length (300).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APK="${1:-$ROOT/android/watch/build/outputs/apk/debug/watch-debug.apk}"
PKG=org.visadahyu.datapavan.watch
SHELL_UID=2000
PIN=4826
# shellcheck source=scripts/adb-ui.sh
. "$ROOT/scripts/adb-ui.sh"

is_emulator || {
    echo "verify-log.sh runs on an emulator only: it sets a PIN and locks the screen" >&2
    exit 2
}
HOST=10.0.2.2
PORT=${WATCH_TEST_PORT:-8790}

SERVER=""
PIN_SET=""
cleanup() {
    [ -z "$PIN_SET" ] || adb shell locksettings clear --old "$PIN" >/dev/null 2>&1 || true
    adb shell cmd locale set-app-locales "$PKG" --locales "" >/dev/null 2>&1 || true
    adb shell am force-stop "$PKG" >/dev/null 2>&1 || true
    [ -z "$SERVER" ] || kill "$SERVER" 2>/dev/null || true
}
trap cleanup EXIT

fail() {
    echo "LOG CHECK FAILED: $*" >&2
    adb logcat -d -b crash 2>/dev/null | tail -40 >&2 || true
    # A process Android ended leaves no crash: how Watch's last ones ended, with no destination.
    echo "How Watch's process last ended:" >&2
    adb shell dumpsys activity exit-info "$PKG" 2>/dev/null | tr -d '\r' | grep -E 'timestamp=|reason=' | head -6 >&2 || true
    exit 1
}

# Watch's own account, with debug commands (WatchVpnService.debugLog).
watch_dump() {
    adb shell dumpsys activity service "$PKG/.WatchVpnService" "$@" | tr -d '\r' | sed 's/^ *//'
}

log_line() {
    watch_dump | sed -n 's/^log retention //p'
}

# The days of the log's rows ("records") or key rows ("keys") as the file holds them, one per line,
# read before anything runs expiry.
raw_days() {
    watch_dump log-raw | sed -n 's/^log-raw //p' | python3 -I -c '
import sys
fields = sys.stdin.read().split()
table = fields[fields.index(sys.argv[1]) + 1] if sys.argv[1] in fields else "-"
print("\n".join(day.split(":")[0] for day in table.split(",") if day != "-"))' "$1"
}

# What Watch's screen says of the log's earlier days now: the sentence after "Watch keeps a record of
# each connection", or "none". The screen is in English for the test (set below).
lock_sentence() {
    adb shell input keyevent KEYCODE_WAKEUP
    scroll_to "Watch keeps a record of each connection" >/dev/null || true
    swipe_up
    dump_screen >/dev/null
    adb shell cat "$DUMP" | grep -o 'text="[^"]*"' | sed 's/^text="//; s/"$//' |
        grep -E '^(Records of earlier days|This phone has no screen lock|This phone did not let Watch)' | head -1 | grep . || echo none
}

start_watch() {
    adb shell am start -W -n "$PKG/.MainActivity" --ez start true >/dev/null
    for _ in $(seq 1 20); do vpn_up && break; sleep 1; done
    vpn_up || fail "Watch's tunnel did not come up"
}

vpn_up() {
    local uid
    uid=$(adb shell cmd package list packages -U "$PKG" | tr -d '\r' | sed -n "s/^package:$PKG uid:\([0-9]*\)$/\1/p")
    local vpns
    vpns=$(adb shell dumpsys connectivity | tr -d '\r' | grep -E 'ni\{(VPN |\[type: VPN)' || true)
    [ -n "$uid" ] && grep -q "OwnerUid: $uid " <<<"$vpns"
}

# Android's own count of the shell's traffic through the VPN, as "up down": the entries of the VPN's
# network for UID 2000 (printed "type=17" from Android 12, "type=VPN" before), every bucket, all tags
# together (tag 0x0). Android 11 also repeats that traffic under the network beneath; those entries are
# left out.
android_bytes() {
    adb shell dumpsys netstats --poll >/dev/null
    adb shell dumpsys netstats --uid | tr -d '\r' | python3 -I -c '
import re, sys
uid, up, down, on = sys.argv[1], 0, 0, False
for line in sys.stdin:
    if "ident=" in line:
        on = re.search(r"type=(17|VPN)\b", line) is not None and f" uid={uid} " in line and "tag=0x0" in line
    elif on and (m := re.search(r" rb=(\d+) .* tb=(\d+)", line)):
        down, up = down + int(m.group(1)), up + int(m.group(2))
print(up, down)' "$SHELL_UID"
}

# The log's count of the same, as "up down": every record of the shell today, as the tunnel carried it.
log_bytes() {
    watch_dump log-flush >/dev/null
    watch_dump log-today | sed -n 's/^log-record //p' | python3 -I -c '
import re, sys
uid, up, down = sys.argv[1], 0, 0
for line in sys.stdin:
    fields = line.split()
    m = re.search(r" wire=(\d+)/(\d+)", line)
    if m and len(fields) > 1 and fields[1] == uid:
        up, down = up + int(m.group(1)), down + int(m.group(2))
print(up, down)' "$SHELL_UID"
}

# The phone's local day, as days since 1970, as Watch counts it.
local_day() {
    python3 -I -c 'import sys; s, z = int(sys.argv[1]), sys.argv[2]; o = (1 if z[0] == "+" else -1) * (int(z[1:3]) * 3600 + int(z[3:5]) * 60); print((s + o) // 86400)' \
        "$(adb shell date +%s | tr -d '\r')" "$(adb shell date +%z | tr -d '\r')"
}

echo "== Watch's connection log, end to end, on $(adb shell getprop ro.product.model | tr -d '\r'), Android $(adb shell getprop ro.build.version.release | tr -d '\r')"
adb wait-for-device
python3 -I "$ROOT/scripts/watch-lab/server.py" "$PORT" &
SERVER=$!
adb install -r "$APK" >/dev/null
# As a new install: the log's default is then what a new user gets (ADR 0040).
adb shell pm clear "$PKG" >/dev/null
adb shell appops set "$PKG" ACTIVATE_VPN allow
[ "$(adb shell getprop ro.build.version.sdk | tr -d '\r')" -lt 37 ] || adb shell pm grant "$PKG" android.permission.ACCESS_LOCAL_NETWORK
adb shell am force-stop "$PKG"
# The screen checks read English. Android 13 and later can set Watch's language alone; before, the
# phone's own language must be English, or the screen checks are skipped.
english=""
if adb shell cmd locale set-app-locales "$PKG" --locales en-US >/dev/null 2>&1; then
    english=1
else
    case "$(adb shell getprop persist.sys.locale | tr -d '\r')$(adb shell getprop ro.product.locale | tr -d '\r')" in en*) english=1 ;; esac
fi
adb logcat -c
adb shell am start -W -n "$PKG/.MainActivity" --ez start true >/dev/null
for _ in $(seq 1 20); do vpn_up && break; sleep 1; done
vpn_up || fail "Watch's tunnel did not come up"
echo "ok: the tunnel is up"
# Watch's debug commands need its service running; the test starts from an empty log.
watch_dump log-wipe | grep -q '^log-wiped true$' || fail "the log could not be wiped before the test"
# The log keeps nothing until the user chooses (ADR 0040). The checks below keep 30 days.
log_line | grep -qE '^0 days ' || fail "a new install's log keeps records: $(log_line)"
watch_dump log-retention 30 | grep -q '^log-retention 30 set$' || fail "retention could not be set to 30 days"
# The screen reads the retention when it opens: it opens afresh, as after the user chose 30 days there.
adb shell am start -W -n "$PKG/.MainActivity" -f 0x10008000 >/dev/null
echo "ok: a new install's log keeps nothing until the user chooses"

request='GET /ping HTTP/1.0\r\n\r\n'
answer=$(timeout 15 adb shell "printf '$request' | nc -w 5 $HOST $PORT" | tr -d '\r' || true)
grep -q '^pong$' <<<"$answer" || fail "no answer over TCP from the test server"
answer=$(timeout 8 adb shell "echo watch-log | nc -u -w 3 $HOST $((PORT + 1))" | tr -d '\r' || true)
grep -q '^watch-log$' <<<"$answer" || fail "no UDP echo"

# The TCP flow has ended, but its rewriting stays for half a minute, for what Android's stack still
# sends, and the UDP flow stays open for a minute: the log gets each one's segment so far.
watch_dump log-flush | grep -q '^log-flushed$' || fail "the log did not take the engine's records"
today=$(watch_dump log-today | sed -n 's/^log-record //p')
grep -qE "^tcp $SHELL_UID $HOST:$PORT up=22 down=[1-9][0-9]* (continues|ended) " <<<"$today" ||
    fail "the log has no TCP flow of the shell with its 22 bytes up: $(grep -c . <<<"$today") records"
# A network change, as on a freshly started emulator, ends UDP flows: then the segment is the whole flow.
grep -qE "^udp $SHELL_UID $HOST:$((PORT + 1)) up=10 down=10 (continues|ended) " <<<"$today" ||
    fail "the log has no segment of the shell's UDP flow with 10 bytes each way; the shell's records: $(grep "^[a-z]* $SHELL_UID " <<<"$today" | tr '\n' ';')"
echo "ok: the log holds the shell's TCP flow and its UDP flow so far, with their bytes"

# The screen says of earlier days only what holds: this emulator has no screen lock, so they can be
# opened at any time, and the screen does not say "only while the phone is unlocked".
if [ -n "$english" ]; then
    adb shell wm dismiss-keyguard
    said=$(lock_sentence)
    case "$said" in "This phone has no screen lock"*) ;; *) fail "with no screen lock, the screen said: $said" ;; esac
    echo "ok: with no screen lock, the screen says that earlier days can be opened at any time"
else
    echo "skipped: the screen checks, as the phone's language is not English"
fi

# A flow open when the tunnel stops still reaches the log: the engine hands over its last records.
timeout 20 adb shell "sleep 8 | nc -w 10 $HOST $PORT" >/dev/null 2>&1 &
talking=$!
sleep 3
adb shell am start -W -n "$PKG/.MainActivity" --ez stop true >/dev/null
for _ in $(seq 1 20); do vpn_up || break; sleep 1; done
wait "$talking" 2>/dev/null || true
adb shell am start -W -n "$PKG/.MainActivity" --ez start true >/dev/null
for _ in $(seq 1 20); do vpn_up && break; sleep 1; done
vpn_up || fail "Watch's tunnel did not come up again"
watch_dump log-today | grep -qE "^log-record tcp $SHELL_UID $HOST:$PORT up=0 down=0 ended " ||
    fail "a flow open when the tunnel stopped did not reach the log"
echo "ok: a flow open when the tunnel stops reaches the log"

# Over a scripted session, the log's bytes for the shell match Android's own count within 5 %: downloads,
# an upload, small UDP flows, and names looked up (no ping: Watch does not carry ICMP yet).
read -r android_up0 android_down0 <<<"$(android_bytes)"
read -r log_up0 log_down0 <<<"$(log_bytes)"
for _ in 1 2 3; do
    timeout 60 adb shell "printf 'GET /bytes/2000000 HTTP/1.0\r\n\r\n' | nc -w 10 $HOST $PORT > /dev/null" || true
done
timeout 60 adb shell "(printf 'POST /sink HTTP/1.0\r\nContent-Length: 1000000\r\n\r\n'; head -c 1000000 /dev/zero) | nc -w 10 $HOST $PORT > /dev/null" || true
for i in 1 2 3 4 5; do
    timeout 10 adb shell "echo watch-$i | nc -u -q 1 $HOST $((PORT + 1))" >/dev/null || true
done
for name in example.com example.org example.net; do
    timeout 10 adb shell "echo watch | nc -u -q 1 $name 9" >/dev/null 2>&1 || true
done
sleep 2
read -r android_up1 android_down1 <<<"$(android_bytes)"
read -r log_up1 log_down1 <<<"$(log_bytes)"
python3 -I - "$((android_up1 - android_up0))" "$((android_down1 - android_down0))" \
    "$((log_up1 - log_up0))" "$((log_down1 - log_down0))" <<'PY' || fail "the log's bytes are not within 5 % of Android's count"
import sys
android_up, android_down, log_up, log_down = map(int, sys.argv[1:])
ok = True
for way, android, log in (("up", android_up, log_up), ("down", android_down, log_down)):
    off = abs(log - android) / android if android else 1.0
    print(f"  {way}: Android {android} bytes, the log {log} bytes, {off * 100:.2f} % apart")
    ok = ok and android > 0 and off <= 0.05
sys.exit(0 if ok else 1)
PY
echo "ok: over a scripted session the log's bytes are within 5 % of Android's own count"
# Each download's packets on the tunnel hold at least its payload: none of them was counted after the
# flow's last segment was written (as before 2026-11-10, when a download lost up to a quarter).
watch_dump log-flush >/dev/null
watch_dump log-today | sed -n 's/^log-record //p' | python3 -I -c '
import collections, re, sys
down, wire = collections.Counter(), collections.Counter()
for line in sys.stdin:
    fields = line.split()
    flow = re.search(r" flow=(\d+)", line)
    if fields[:3] == ["tcp", sys.argv[1], sys.argv[2]] and flow:
        down[flow.group(1)] += int(re.search(r" down=(\d+)", line).group(1))
        wire[flow.group(1)] += int(re.search(r" wire=\d+/(\d+)", line).group(1))
short = [f"flow {f}: {wire[f]} on the tunnel for {down[f]} received" for f in down if down[f] >= 1_000_000 and wire[f] < down[f]]
if short:
    print("\n".join(short))
sys.exit(1 if short or len([f for f in down if down[f] >= 1_000_000]) < 3 else 0)' "$SHELL_UID" "$HOST:$PORT" ||
    fail "a download's packets on the tunnel are fewer than its payload"
echo "ok: each download's packets on the tunnel hold its whole payload"

# The database and its journal, read as Watch itself could, hold no destination in the clear.
files=$(mktemp -d)
for file in log.db log.db-journal log.db-wal; do
    adb exec-out run-as "$PKG" cat "databases/$file" >"$files/$file" 2>/dev/null || true
done
[ -s "$files/log.db" ] || fail "no log database"
if grep -aqE "10\.0\.2\.2|watch\.test|example\.(com|org)|8\.8\.8\.8" "$files"/*; then
    fail "a destination is in the log's files in the clear"
fi
# As bytes too (bash cannot hold the zero byte, so Python looks).
if python3 -I -c 'import sys; sys.exit(0 if any(bytes([10, 0, 2, 2]) in open(f, "rb").read() for f in sys.argv[1:]) else 1)' "$files"/*; then
    fail "the test server's address is in the log's files as bytes"
fi
rm -rf "$files"
echo "ok: the log's files hold no destination in the clear"

uid=$(adb shell cmd package list packages -U "$PKG" | tr -d '\r' | sed -n "s/^package:$PKG uid:\([0-9]*\)$/\1/p")
if adb logcat -d --uid="$uid" 2>/dev/null | grep -qE "10\.0\.2\.2|watch\.test|example\.(com|org)|8\.8\.8\.8"; then
    fail "a destination reached logcat"
fi
echo "ok: no destination in Watch's logcat"

# An earlier day opens only on an unlocked phone. Only today's day key stays in memory.
earlier=$(($(local_day) - 3))
watch_dump log-test-day "$earlier" | grep -q "^log-test-day $earlier written$" || fail "no test record for an earlier day"
watch_dump log-day "$earlier" | grep -q "^log-day $earlier open 1$" || fail "the earlier day did not open on an unlocked phone"
adb shell locksettings set-pin "$PIN" >/dev/null
PIN_SET=1
adb shell input keyevent KEYCODE_SLEEP
sleep 3
result=$(watch_dump log-day "$earlier" | sed -n "s/^log-day $earlier //p")
[ "$result" = locked ] || fail "the earlier day was '$result' while the phone was locked"
adb shell input keyevent KEYCODE_WAKEUP
adb shell wm dismiss-keyguard
sleep 1
adb shell input text "$PIN"
adb shell input keyevent KEYCODE_ENTER
sleep 2
result=$(watch_dump log-day "$earlier" | sed -n "s/^log-day $earlier //p")
[ "$result" = "open 1" ] || fail "the earlier day was '$result' once the phone was unlocked"
# Watch's screen, back in front after the unlock, reads the screen lock again.
if [ -n "$english" ]; then
    said=$(lock_sentence)
    case "$said" in "Records of earlier days can be opened only while the phone is unlocked."*) ;; *) fail "with a PIN, the screen said: $said" ;; esac
    echo "ok: with a PIN, the screen says that earlier days open only while the phone is unlocked"
fi
adb shell locksettings clear --old "$PIN" >/dev/null
PIN_SET=""
echo "ok: an earlier day is locked with the phone, and opens once it is unlocked"

watch_dump log-wipe | grep -q '^log-wiped true$' || fail "the wipe did not finish"
left=$(adb shell run-as "$PKG" ls databases 2>/dev/null | tr -d '\r' | grep -E '^log\.db' || true)
[ -z "$left" ] || fail "the wipe left files: $left"
log_line | grep -qE ' records 0 key-rows 0 key false ' || fail "the wipe left records or the key: $(log_line)"
echo "ok: the wipe leaves no file and no key"

# Expiry does not wait for traffic (ADR 0037). A record put back past retention (30
# days) is never read, and leaves the file, with its key row, when Watch's process starts again.
now=$(local_day)
past=$((now - 40))
watch_dump log-put-day "$past" | grep -q "^log-put-day $past written$" || fail "no record put back for day $past"
raw_days records | grep -qx "$past" && raw_days keys | grep -qx "$past" || fail "the record put back for day $past is not in the file"
result=$(watch_dump log-day "$past" | sed -n "s/^log-day $past //p")
[ "$result" = "open 0" ] || fail "day $past, past retention, gave '$result'"
raw_days records | grep -qx "$past" || fail "reading day $past deleted it: the read alone must not be what keeps it out"
adb shell am force-stop "$PKG"
start_watch
! raw_days records | grep -qx "$past" && ! raw_days keys | grep -qx "$past" || fail "day $past, past retention, is still in the file after Watch started again"
echo "ok: a day past retention is never read, and leaves the file when Watch starts again"

# A shorter retention deletes at once what it no longer keeps; "none" leaves no file and no key.
earlier=$((now - 3))
for day in "$earlier" "$now"; do
    watch_dump log-test-day "$day" | grep -q "^log-test-day $day written$" || fail "no test record for day $day"
done
watch_dump log-retention 1 | grep -q '^log-retention 1 set$' || fail "retention could not be set to 1 day"
days=$(raw_days records; raw_days keys)
grep -qx "$now" <<<"$days" || fail "retention 1 deleted today's records"
! grep -qvx "$now" <<<"$days" || fail "retention 1 left earlier days in the file: $(sort -u <<<"$days" | tr '\n' ' ')"
watch_dump log-retention 0 | grep -q '^log-retention 0 set$' || fail "retention could not be set to none"
left=$(adb shell run-as "$PKG" ls databases 2>/dev/null | tr -d '\r' | grep -E '^log\.db' || true)
[ -z "$left" ] || fail "retention none left files: $left"
log_line | grep -qE '^0 days 0 records 0 key-rows 0 key false ' || fail "retention none left records or the key: $(log_line)"
watch_dump log-retention 30 | grep -q '^log-retention 30 set$' || fail "retention could not be set back to 30 days"
echo "ok: a shorter retention deletes at once, and none leaves no file and no key"

# The log's model test (LogModel): random sequences of writes, reads, clock and time-zone changes,
# restarts, locking, retention changes, wipes, the expiry job, a full database and a failing Keystore,
# each checked against a model of what the log must and must not give back.
seed=${LOG_MODEL_SEED:-$(od -An -N4 -tu4 /dev/urandom | tr -d ' ')}
steps=${LOG_MODEL_STEPS:-300}
watch_dump log-model "$seed" "$steps" | grep -q "^log-model started seed $seed steps $steps$" || fail "the model test did not start"
result=""
for _ in $(seq 1 360); do
    result=$(watch_dump log-model-result | grep '^log-model ' || true)
    case "$result" in "log-model running"*) sleep 5 ;; *) break ;; esac
done
echo "  $result"
grep -q '^log-model passed ' <<<"$result" || fail "the log's model test did not pass (repeat it with LOG_MODEL_SEED=$seed)"
echo "ok: the log's model test passed $steps steps"

if adb logcat -d -b crash 2>/dev/null | grep -q "$PKG"; then
    fail "Watch crashed"
fi
echo "ok: no crash"
echo "== Watch's connection log passed"
