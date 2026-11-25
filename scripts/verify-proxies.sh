#!/usr/bin/env bash
# W8 part 2a's emulator check (ADR 0052): apps' built-in proxies named on a real Android, against the proxy lab on this
# computer (Compose project datapavan-proxylab, published on this computer's loopback alone, which the emulator
# reaches as 10.0.2.2; its own network has no way out). The project's own proxy fixture (scripts/proxy-fixture) speaks
# SOCKS5 with a password, an HTTP CONNECT with Basic credentials, a plain request to an HTTP proxy and one through
# Android's proxy setting; under three more package names, which the network part's debug builds add to the clients of
# Telegram, WhatsApp and Signal (never a real app's), it sends Telegram's obfuscated start and a fake-TLS hello to mtg,
# WhatsApp's clear header, and TLS hellos with Signal's names. Each kind must be named as ADR 0052 says: the declared
# ones by the destination asked for, read from the connection once the proxy's reply confirmed them, a plain request
# keeping its own name, Android's setting told apart; the inferred ones with the cover name naming nothing, the
# fake-TLS one only once the network part saw the app's lookups; Signal's own fronting and captcha names are not a
# proxy. "Now" and the log hold the same while the switch "Log where apps connect through your tool, WireGuard or a
# proxy" is on. With it off, "Now" holds the proxy's address, its first hop, and nothing the app asked it for, and the
# log only its kind; the window that ends a first hop in "Now" ten minutes after its connection is the engine's tests'
# to check, never a wait here. That switch is on the network screen, though the phone has no tool and no tunnel. The
# user's choice for one app (the proxy record's unit C) never covers the lab's local address; on an emulator that `adb
# root` takes, a rule of its own `nat` table sends the network part's connections to a TEST-NET address to the lab, and
# there the chosen app's proxy is named and logged with the switch off, until the choice is turned off; an update keeps
# the choice and a reinstall ends it. No password or user name reaches the network part's dump, the log, the device's
# log or its crash buffer.
#
# The false positives that need a maker's own network (a Telegram CDN data centre beside its ranges, WhatsApp's link
# previews and backups beside Meta's networks) are checked in the engine's network lab (core/net/tests/netlab.rs) and
# its tests: an emulator here must not reach them.
#
# Only where the lab cannot start here at all (no Docker, or Docker not answering) is the check skipped, with a line
# that says so; with PROXYLAB_REQUIRED=1, which CI sets, that fails. Any other failure of the lab fails the check; its
# logs then go to build/proxylab/.
#
#   scripts/verify-proxies.sh [path/to/Datapavan-Advanced-debug.apk]
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APK="${1:-$ROOT/android/app/build-advanced/outputs/apk/debug/app-debug.apk}"
PKG=org.visadahyu.datapavan.advanced
NETWORK_SCREEN=org.visadahyu.datapavan.network.MainActivity
FIXTURE=org.visadahyu.datapavan.proxyfixture
# shellcheck source=scripts/adb-ui.sh
. "$ROOT/scripts/adb-ui.sh"

is_emulator || { echo "verify-proxies.sh runs on an emulator only" >&2; exit 2; }
HOST=10.0.2.2
compose=(docker compose -f "$ROOT/scripts/proxylab/compose.yaml")
WORK="$(mktemp -d)"
PROXY_SET=""
# Unit C's part: whether this check rooted the emulator, and the nat rule it set there.
ROOTED=""
DNAT_SET=""
DNAT_RULE=""

cleanup() {
    local status=$?
    if [ -n "$DNAT_SET" ]; then adb shell "iptables -w -t nat -D OUTPUT $DNAT_RULE" >/dev/null 2>&1 || true; fi
    if [ -n "$ROOTED" ]; then
        adb unroot >/dev/null 2>&1 || true
        timeout 60 adb wait-for-device >/dev/null 2>&1 || true
    fi
    if [ -n "$PROXY_SET" ]; then
        adb shell settings put global http_proxy :0 >/dev/null 2>&1 || true
        adb shell settings delete global http_proxy >/dev/null 2>&1 || true
    fi
    adb shell am force-stop "$PKG" >/dev/null 2>&1 || true
    for role in "" .telegram .whatsapp .signal; do adb uninstall "$FIXTURE$role" >/dev/null 2>&1 || true; done
    if [ "$status" != 0 ]; then
        mkdir -p "$ROOT/build/proxylab"
        "${compose[@]}" logs --no-color --timestamps >"$ROOT/build/proxylab/lab-verify-proxies.log" 2>&1 || true
    fi
    "${compose[@]}" stop >/dev/null 2>&1 || true
    rm -rf "$WORK"
}
trap cleanup EXIT

dump() { adb shell dumpsys activity service "$PKG/org.visadahyu.datapavan.network.NetworkVpnService" "$@" | tr -d '\r'; }
fixture_log() { adb logcat -d -s DatapavanProxyFixture | tr -d '\r' | sed -n 's/.*DatapavanProxyFixture: //p'; }
proxies() { dump | sed -n 's/^ *flow-proxy //p'; }
fail() {
    echo "PROXIES CHECK FAILED: $*" >&2
    echo "the network part's proxied flows:" >&2
    proxies >&2 || true
    echo "the network part's flows to the lab:" >&2
    dump | sed -n 's/^ *flow //p' | grep -F "$HOST:" >&2 || true
    echo "The fixture's lines:" >&2
    fixture_log | tail -20 >&2 || true
    adb logcat -d -b crash 2>/dev/null | tail -30 >&2 || true
    exit 1
}
vpn_up() {
    local uid
    uid=$(adb shell cmd package list packages -U "$PKG" | tr -d '\r' | sed -n "s/^package:$PKG uid:\([0-9]*\)$/\1/p")
    [ -n "$uid" ] && grep -qE "OwnerUid: $uid " <<<"$(adb shell dumpsys connectivity | tr -d '\r')"
}
uid_of() { adb shell cmd package list packages -U "$1" | tr -d '\r' | sed -n "s/^package:$1 uid:\([0-9]*\)$/\1/p"; }
# The fixture under package $1, with the extras given, until it logs "done"; its line for the action $2 must be
# "$2 ok $3".
fixture() {
    local package=$1 action=$2 expected=$3
    shift 3
    adb logcat -c
    adb shell am start -W -n "$package/$FIXTURE.ProxyActivity" --es action "$action" "$@" >/dev/null
    for _ in $(seq 1 30); do
        grep -qx done <<<"$(fixture_log)" && break
        sleep 1
    done
    local line
    line=$(fixture_log | grep -E "^$action (ok|failed)" | tail -1 || true)
    [ "$line" = "$action ok $expected" ] || fail "the fixture's $action through the lab: ${line:-no answer}"
}
# The proxied flow of the app $1 to the lab's port $2 whose fields after the UID match the pattern $3 (`kind how
# flags asked proxy-name cover name`), within 10 s.
proxied() {
    local uid=$1 port=$2 pattern=$3
    for _ in $(seq 1 10); do
        grep -qE "^tcp [^ ]+ ${HOST//./\\.}:$port $uid $pattern\$" <<<"$(proxies)" && return 0
        sleep 1
    done
    fail "no proxied flow of $uid to $HOST:$port as '$pattern'"
}

# The lab, its ports published on this computer's loopback. Skipped only where it cannot start here at all.
why_not=""
if ! command -v docker >/dev/null 2>&1; then
    why_not="no Docker"
elif ! docker info >/dev/null 2>&1; then
    why_not="Docker does not answer"
fi
if [ -n "$why_not" ]; then
    if [ "${PROXYLAB_REQUIRED:-}" = 1 ]; then
        echo "PROXIES CHECK FAILED: PROXYLAB_REQUIRED=1, and the proxy lab cannot start here ($why_not)" >&2
        exit 1
    fi
    echo "SKIPPED verify-proxies.sh: the proxy lab cannot start here ($why_not); nothing of W8 part 2a was checked on the emulator"
    [ -z "${GITHUB_ACTIONS:-}" ] || echo "::notice title=W8 part 2a's emulator check skipped::$why_not: nothing was checked on the emulator"
    exit 0
fi
settings=$("$ROOT/scripts/proxylab.sh" --serve 2>"$WORK/lab.err") ||
    { cat "$WORK/lab.err" >&2; echo "PROXIES CHECK FAILED: the proxy lab did not start, though Docker is here" >&2; exit 1; }
while IFS= read -r line; do
    [[ $line == PROXYLAB_*=* ]] && export "${line%%=*}=${line#*=}"
done <<<"$settings"
echo "ok: the proxy lab answers on this computer's loopback, ports $PROXYLAB_PORT to $PROXYLAB_PORT_TLS"

"$ROOT/scripts/proxy-fixture/build.sh" >/dev/null
adb install -r "$APK" >/dev/null
adb shell pm clear "$PKG" >/dev/null
for role in "" -telegram -whatsapp -signal; do
    adb uninstall "$FIXTURE${role/-/.}" >/dev/null 2>&1 || true
    adb install "$ROOT/build/proxy-fixture/proxy-fixture$role.apk" >/dev/null
done
APP_UID=$(uid_of "$FIXTURE")
TELEGRAM_UID=$(uid_of "$FIXTURE.telegram")
WHATSAPP_UID=$(uid_of "$FIXTURE.whatsapp")
SIGNAL_UID=$(uid_of "$FIXTURE.signal")
[ -n "$APP_UID" ] && [ -n "$TELEGRAM_UID" ] && [ -n "$WHATSAPP_UID" ] && [ -n "$SIGNAL_UID" ] || fail "the fixtures did not install"
allow_vpn "$PKG" || fail "Android did not take the VPN consent for $PKG"
[ "$(adb shell getprop ro.build.version.sdk | tr -d '\r')" -lt 37 ] || adb shell pm grant "$PKG" android.permission.ACCESS_LOCAL_NETWORK
adb shell am force-stop "$PKG"
adb shell am start -W -n "$PKG/$NETWORK_SCREEN" --ez start true >/dev/null
for _ in $(seq 1 20); do vpn_up && break; sleep 1; done
vpn_up || fail "the network part's tunnel did not come up"

# The debug builds' way in: the fixtures as the three messengers' clients, and never a real app's package.
grep -q "messenger-client refused" <<<"$(dump messenger-client telegram org.telegram.messenger)" ||
    fail "the dump took a real app's package as a messenger's client"
for family in telegram whatsapp signal; do
    grep -q "messenger-client $family $FIXTURE.$family" <<<"$(dump messenger-client "$family" "$FIXTURE.$family")" ||
        fail "the fixture was not added to $family's clients"
done
grep -q "log-destinations on" <<<"$(dump log-destinations on)" || fail "the switch \"Log where apps connect ...\" was not turned on"
grep -q "log-retention 1 set" <<<"$(dump log-retention 1)" || fail "the log's retention was not set"
# The "local" fact (the proxy record's unit B): the engine was handed the network beneath's on-link prefix that holds
# the lab's address, whichever network that is here (the emulator's Wi-Fi or its radio), so the lab's proxies below are
# local (the flag n) by that prefix, not only by the rule for private addresses.
on_link=$(dump | sed -n 's/^ *proxy-on-link //p') || fail "the network part's dump could not be read"
echo "   the network beneath, as the engine holds it: ${on_link:-nothing}"
grep -qE "(^| )10\.0\.2\.[0-9]+/24( |$)" <<<"$on_link" ||
    fail "the engine was not handed the network beneath's prefix of $HOST: ${on_link:-nothing}"
sleep 1
lab=(--es host "$HOST" --es user "$PROXYLAB_USER" --es password "$PROXYLAB_PASSWORD")

# Declared: each named by the destination asked for, a password unencrypted said, none of them Android's setting.
fixture "$FIXTURE" socks5 echoed "${lab[@]}" --es port "$PROXYLAB_PORT"
proxied "$APP_UID" "$PROXYLAB_PORT" "socks5 read pn inner\.proxylab\.test:443 - - inner\.proxylab\.test"
fixture "$FIXTURE" connect echoed "${lab[@]}" --es port "$PROXYLAB_PORT_HTTP"
proxied "$APP_UID" "$PROXYLAB_PORT_HTTP" "connect read pn inner\.proxylab\.test:443 - - inner\.proxylab\.test"
fixture "$FIXTURE" forward 204 "${lab[@]}" --es port "$PROXYLAB_PORT_HTTP"
# A plain request cannot be confirmed by its reply: its flow keeps its own name, and says what it asked for.
proxied "$APP_UID" "$PROXYLAB_PORT_HTTP" "forward read pn inner\.proxylab\.test:80 - - [^i].*"
echo "ok: SOCKS5 with a password and CONNECT with Basic named by the destination asked for once the proxy confirmed it, a plain request keeping its own name"

# Android's proxy setting, told apart from an app's own.
PROXY_SET=1
adb shell settings put global http_proxy "$HOST:$PROXYLAB_PORT_OPEN"
sleep 2
fixture "$FIXTURE" setting 204
proxied "$APP_UID" "$PROXYLAB_PORT_OPEN" "forward read sn inner\.proxylab\.test:80 - - [^i].*"
# "Now"'s line of Android's own setting (the proxy record's unit B): the whole phone's proxy, read once the tunnel is
# the network part's default network, never the Wi-Fi network's as the whole phone's (review B-rest 1).
context_global() { grep -q "proxy-context global=${HOST//./\\.}:$PROXYLAB_PORT_OPEN " <<<"$(dump)"; }
within 10 context_global || fail "\"Now\" does not hold the whole phone's proxy: $(dump | sed -n 's/^ *proxy-context //p')"
adb shell settings put global http_proxy :0
adb shell settings delete global http_proxy >/dev/null 2>&1 || true
PROXY_SET=""
context_none() { grep -q "proxy-context global=- network=- " <<<"$(dump)"; }
within 10 context_none || fail "\"Now\" still holds a proxy setting once none is set: $(dump | sed -n 's/^ *proxy-context //p')"
echo "ok: Android's proxy setting told apart from an app's own"

# Inferred: Telegram's obfuscated start and fake-TLS hello to mtg, WhatsApp's clear header, Signal's proxy by its name.
fixture "$FIXTURE.telegram" obfuscated sent --es host "$HOST" --es port "$PROXYLAB_PORT_MTG"
proxied "$TELEGRAM_UID" "$PROXYLAB_PORT_MTG" "mtproto inferred on - - - .*"
# A hello no answer tied is evidence only where the network part sees the app's lookups: the fixture looks a name up
# first.
fixture "$FIXTURE.telegram" lookup asked --es name lookup.proxylab.test
fixture "$FIXTURE.telegram" faketls accepted --es host "$HOST" --es port "$PROXYLAB_PORT_MTG" --es secret "$PROXYLAB_MTG_SECRET"
proxied "$TELEGRAM_UID" "$PROXYLAB_PORT_MTG" "mtproto inferred on - - cover\.proxylab\.test .*"
if grep -E "^tcp [^ ]+ ${HOST//./\\.}:$PROXYLAB_PORT_MTG $TELEGRAM_UID " <<<"$(dump | sed -n 's/^ *flow //p')" | grep -q "cover\.proxylab\.test"; then
    fail "the fake-TLS cover named Telegram's flow"
fi
fixture "$FIXTURE.whatsapp" whatsapp echoed --es host "$HOST" --es port "$PROXYLAB_PORT_ECHO"
proxied "$WHATSAPP_UID" "$PROXYLAB_PORT_ECHO" "whatsapp inferred on - - - .*"
fixture "$FIXTURE.signal" hello echoed --es host "$HOST" --es port "$PROXYLAB_PORT_TLS" --es name signal-proxy.proxylab.test
proxied "$SIGNAL_UID" "$PROXYLAB_PORT_TLS" "signal inferred n - - - signal-proxy\.proxylab\.test"
echo "ok: Telegram's MTProto proxy (obfuscated and fake TLS, the cover naming nothing), WhatsApp's and Signal's inferred"

# The switch the rows point to is on the network screen, though this phone has no circumvention tool and no WireGuard
# configuration: an app's own proxy was seen (the fix round's R-M4).
adb shell am start -W -n "$PKG/$NETWORK_SCREEN" >/dev/null
sleep 2
scroll_to "Log where apps connect through your tool, WireGuard or a proxy" ||
    fail "the switch is not on the network screen, with no tool, no tunnel and a Telegram proxy seen"
adb shell input keyevent KEYCODE_HOME
echo "ok: the switch is on the network screen with no tool and no tunnel, a Telegram proxy seen"

# Signal's own fronting and its captcha are no proxy, though it made no direct connection to Signal; and its fronting
# counts as reaching Signal directly (a set proxy turns it off), so the proxy's name above is taken back.
for name in www.google.com js.hcaptcha.com; do
    fixture "$FIXTURE.signal" hello echoed --es host "$HOST" --es port "$PROXYLAB_PORT_TLS" --es name "$name"
done
sleep 1
flows=$(dump | sed -n 's/^ *flow //p')
for name in www.google.com js.hcaptcha.com; do
    grep -qE "^tcp [^ ]+ ${HOST//./\\.}:$PROXYLAB_PORT_TLS $SIGNAL_UID .* ${name//./\\.}\$" <<<"$flows" ||
        fail "Signal's flow named $name is not among the network part's flows"
    ! grep -qE "^tcp [^ ]+ [^ ]+ $SIGNAL_UID .* ${name//./\\.}\$" <<<"$(proxies)" || fail "Signal's flow named $name was named a proxy"
done
! grep -qE "^tcp [^ ]+ [^ ]+ $SIGNAL_UID signal inferred " <<<"$(proxies)" ||
    fail "Signal's fronting did not take its proxy's name back"
echo "ok: Signal's own fronting and its captcha are not named a proxy, and its fronting takes the proxy's name back"

# "Now" and the log hold the same: the destination asked for and the proxy's kind.
now=$(dump | sed -n 's/^ *activity-proxy //p') || fail "the network part's dump could not be read"
grep -qE "^$APP_UID socks5:read:pn:inner\.proxylab\.test@443:- ${HOST//./\\.}:$PROXYLAB_PORT named-by=1 inner\.proxylab\.test 10m=[0-9]+/[0-9]+$" <<<"$now" ||
    fail "\"Now\" does not hold the SOCKS5 proxy as named: $now"
grep -qE "^$TELEGRAM_UID mtproto:inferred:on:-:- " <<<"$now" || fail "\"Now\" does not hold Telegram's proxy: $now"
dump log-flush >/dev/null
log=$(dump log-today | sed -n 's/^ *log-record //p')
grep -qE "^tcp $APP_UID ${HOST//./\\.}:$PROXYLAB_PORT .* inner\.proxylab\.test .*proxy=socks5:read:pn:inner\.proxylab\.test@443:-$" <<<"$log" ||
    fail "the log does not hold the SOCKS5 proxy as named"
echo "ok: \"Now\" and the log hold the proxies as named"

# The switch off. At once, "Now" holds nothing an app asked its proxy for (R6); the first hops stay for their window.
grep -q "log-destinations off" <<<"$(dump log-destinations off)" || fail "the switch \"Log where apps connect ...\" was not turned off"
proxies_now() { dump | sed -n 's/^ *activity-proxy //p'; }
none_asked_now() { ! grep -q "inner\.proxylab\.test" <<<"$(proxies_now)"; }
within 5 none_asked_now || fail "with the switch off, \"Now\" still holds where an app asked its proxy to go: $(proxies_now)"
# The flows of the part before reached the same first hops, which stay in "Now" for their ten minutes, so the flows
# opened now are told apart by the bytes they add there (audit-A 1), and in the log by when their records start.
# The flag `v`: shown there only, for its window, as the switch is off.
SOCKS_HOP="^$APP_UID socks5:read:pnv:-:- ${HOST//./\\.}:$PROXYLAB_PORT named-by=4 - 10m="
TELEGRAM_HOP="^$TELEGRAM_UID mtproto:inferred:onv:-:- ${HOST//./\\.}:$PROXYLAB_PORT_MTG "
# The bytes up and down in the last 10 minutes of the "Now" lines that match the pattern $1, all together. One awk,
# no grep: under pipefail a grep that finds nothing would end the script (the pattern goes by the environment, which
# awk reads without turning its backslashes into escapes).
ten_minutes() {
    proxies_now | PATTERN="$1" awk '$0 ~ ENVIRON["PATTERN"] {
        for (i = 1; i <= NF; i++) if ($i ~ /^10m=/) { split(substr($i, 5), b, "/"); sum += b[1] + b[2] }
    } END { print sum + 0 }'
}
# Each failing step says so: under set -e an assignment from a failed command would end the check with no word of its
# own (review A, rest, note 7).
socks_before=$(ten_minutes "$SOCKS_HOP") || fail "the network part's dump could not be read"
telegram_before=$(ten_minutes "$TELEGRAM_HOP") || fail "the network part's dump could not be read"
# As verify-network.sh reads the phone's time: toybox's date has whole seconds.
phone_time=$(adb shell date +%s </dev/null | tr -d '\r') || fail "the phone's time could not be read"
[[ $phone_time =~ ^[0-9]+$ ]] || fail "the phone's time could not be read: ${phone_time:-nothing}"
off_since=$((phone_time * 1000))
fixture "$FIXTURE" socks5 echoed "${lab[@]}" --es port "$PROXYLAB_PORT"
fixture "$FIXTURE.telegram" obfuscated sent --es host "$HOST" --es port "$PROXYLAB_PORT_MTG"
# "Now" counts both flows once the network part has read their first bytes and inferred Telegram's proxy (CI, run
# 45157535067, attempt 2: read one second after the fixture, before it had). So wait for the two first hops' bytes to
# grow; only then are the log's checks about records that exist.
socks_now() { [ "$(ten_minutes "$SOCKS_HOP")" -gt "$socks_before" ]; }
telegram_now() { [ "$(ten_minutes "$TELEGRAM_HOP")" -gt "$telegram_before" ]; }
within 15 socks_now ||
    fail "with the switch off, \"Now\" did not show the SOCKS5 proxy's first hop for the new flow within 15 s: $(proxies_now)"
within 15 telegram_now ||
    fail "with the switch off, \"Now\" did not show Telegram's proxy's first hop for the new flow within 15 s: $(proxies_now)"
none_asked_now || fail "with the switch off, \"Now\" holds where an app asked its proxy to go: $(proxies_now)"
# C1 through the whole app: the newest kept flow of the fixture to the SOCKS5 proxy is named neither by what it asked
# for nor by the hello inside.
newest=$(proxies | awk -v port="$HOST:$PROXYLAB_PORT" -v uid="$APP_UID" '$1 == "tcp" && $3 == port && $4 == uid { line = $0 } END { print line }') ||
    fail "the network part's kept flows could not be read"
[[ $newest =~ \ socks5\ read\ pn\ -\ -\ -\ -$ ]] ||
    fail "with the switch off, the request or the inner hello named the SOCKS5 flow: ${newest:-none}"
dump log-flush >/dev/null
log=$(dump log-today | sed -n 's/^ *log-record //p')
grep -qE "^tcp $APP_UID 0\.0\.0\.0:0 .* - .*proxy=socks5:read:pln:-:-$" <<<"$log" ||
    fail "with the switch off, the log does not hold the SOCKS5 proxy's kind alone"
# No record of the fixture's SOCKS5 proxy with its first hop starts after the switch went off, a second's margin
# allowed for the phone's whole seconds.
kept=$(SINCE="$off_since" APP="$APP_UID" awk '$1 == "tcp" && $2 == ENVIRON["APP"] && /proxy=socks5:read:pn:/ {
    for (i = 1; i <= NF; i++) if ($i ~ /^at=/) { split(substr($i, 4), t, "-"); if (t[1] + 1000 >= ENVIRON["SINCE"] + 0) print t[1] }
}' <<<"$log")
[ -z "$kept" ] || fail "with the switch off, the log got a record of the SOCKS5 proxy with its first hop (at=${kept%%$'\n'*})"
# An inferred proxy's records wait ten minutes, its window of take-back, before the log gets them (ADR 0052, the fix
# round's F2): none of Telegram's is in the log yet, though the flush wrote everything else. Every TCP flow of the
# Telegram fixture in this check went to its MTProto proxy, so none may be there at all, marked or not: a record
# written before the flow was named would carry it unmarked.
! grep -qE "^tcp $TELEGRAM_UID .*proxy=mtproto" <<<"$log" ||
    fail "the log got a record of Telegram's inferred proxy within its window of take-back"
! grep -qE "^tcp $TELEGRAM_UID " <<<"$log" ||
    fail "the log got a record of a Telegram flow to its inferred proxy, unmarked, within the window of take-back: $(grep -E "^tcp $TELEGRAM_UID " <<<"$log" | head -2)"
echo "ok: with the switch off, \"Now\" shows the proxies' first hops and nothing asked, the log keeps their kind alone, and an inferred one's records wait for their window"

# R7 (the proxy record's unit B): with the switch off, a plain request to Android's setting is left out of the record as
# a confirmed proxy's, and "Now" shows its first hop in full for its window. The part with the switch on reached the
# same first hop minutes before, so the new flow is told apart by the bytes it adds there, and in the log by when its
# records start (audit-B 11).
SETTING_HOP="^$APP_UID forward:read:snv:-:- ${HOST//./\\.}:$PROXYLAB_PORT_OPEN "
setting_before=$(ten_minutes "$SETTING_HOP") || fail "the network part's dump could not be read"
PROXY_SET=1
adb shell settings put global http_proxy "$HOST:$PROXYLAB_PORT_OPEN"
sleep 2
phone_time=$(adb shell date +%s </dev/null | tr -d '\r') || fail "the phone's time could not be read"
[[ $phone_time =~ ^[0-9]+$ ]] || fail "the phone's time could not be read: ${phone_time:-nothing}"
setting_since=$((phone_time * 1000))
fixture "$FIXTURE" setting 204
setting_now() { [ "$(ten_minutes "$SETTING_HOP")" -gt "$setting_before" ]; }
within 15 setting_now ||
    fail "with the switch off, \"Now\" did not show the first hop of the plain request to Android's setting within 15 s: $(proxies_now)"
adb shell settings put global http_proxy :0
adb shell settings delete global http_proxy >/dev/null 2>&1 || true
PROXY_SET=""
dump log-flush >/dev/null
log=$(dump log-today | sed -n 's/^ *log-record //p')
grep -qE "^tcp $APP_UID 0\.0\.0\.0:0 .*proxy=forward:read:sln:-:-$" <<<"$log" ||
    fail "with the switch off, the log does not hold the plain request to Android's setting left out"
kept=$(SINCE="$setting_since" APP="$APP_UID" awk '$1 == "tcp" && $2 == ENVIRON["APP"] && /proxy=forward:read:sn:/ {
    for (i = 1; i <= NF; i++) if ($i ~ /^at=/) { split(substr($i, 4), t, "-"); if (t[1] + 1000 >= ENVIRON["SINCE"] + 0) print t[1] }
}' <<<"$log")
[ -z "$kept" ] || fail "with the switch off, the log got a record of the plain request to Android's setting with its address (at=${kept%%$'\n'*})"
echo "ok: with the switch off, a plain request to Android's setting is shown in full in \"Now\" for its window and left out of the log"

# The proxy record's unit C (ADR 0052, decision 8, R3): the user's choice for one app, "Log where APP connects through a
# proxy", made through the debug builds' dump as the screens make it (every package of the app's UID, each with its first
# install time), with the switch still off. Its first hop must not be local for the choice to cover it, and the lab is
# reached at 10.0.2.2, which is: so on an emulator that `adb root` takes, a rule of the emulator's own `nat` table sends
# the network part's own connections to a TEST-NET address (RFC 5737) to the lab, and the engine sees a first hop that
# no prefix makes local, from end to end: the store, the hand-over, the JNI, the engine, "Now" and the log. Only the
# network part's sockets match the rule, by their UID; the fixture's packets reach the tunnel with the TEST-NET address
# still on them. An image whose build refuses root (a `user` build, as the Play Store's) runs only the steps that need
# none, and says so; with PROXYLAB_REQUIRED=1, which CI sets on its rootable image, a refused root fails, and so does a
# missing `nat` table anywhere. The ten-minute window is the engine's tests' to check, never a wait here.
CHOICE_ADDRESS=203.0.113.80
logged_uids() { dump | sed -n 's/^ *proxy-logged //p'; }
names_uid() { [[ " $(logged_uids) " == *" $1 "* ]]; }
names_none() { [ "$(logged_uids)" = - ]; }
# The phone's time in milliseconds, in whole seconds, as above.
phone_ms() {
    local now
    now=$(adb shell date +%s </dev/null | tr -d '\r') || return 1
    [[ $now =~ ^[0-9]+$ ]] || return 1
    echo $((now * 1000))
}
# Whether the log's records $1 hold one of the fixture's that matches the pattern $2 and starts at or after $3 (ms), a
# second's margin allowed for the phone's whole seconds.
record_since() {
    SINCE="$3" APP="$APP_UID" PATTERN="$2" awk '$1 == "tcp" && $2 == ENVIRON["APP"] && $0 ~ ENVIRON["PATTERN"] {
        for (i = 1; i <= NF; i++) if ($i ~ /^at=/) { split(substr($i, 4), t, "-"); if (t[1] + 1000 >= ENVIRON["SINCE"] + 0) found = 1 }
    } END { exit !found }' <<<"$1"
}
# The newest kept flow of the fixture to $1:$2, as `flow-proxy` writes it.
newest_flow() {
    proxies | awk -v to="$1:$2" -v uid="$APP_UID" '$1 == "tcp" && $3 == to && $4 == uid { line = $0 } END { print line }'
}

grep -q "proxy-log refused" <<<"$(dump proxy-log org.telegram.messenger on)" || fail "the dump took a real app's package for the choice"
grep -q "proxy-log $FIXTURE on" <<<"$(dump proxy-log "$FIXTURE" on)" || fail "the dump did not make the choice for the fixture"
within 5 names_uid "$APP_UID" || fail "the network part did not hand the fixture's UID $APP_UID as chosen: $(logged_uids)"
# The SDK Runtime's UID the engine's rule gives the fixture's (app_of), against Android's own answer, public from API 35.
sdk=$(adb shell getprop ro.build.version.sdk | tr -d '\r')
if [ "$sdk" -ge 35 ]; then
    sandbox=$(dump | sed -n "s/^ *proxy-sandbox $APP_UID //p")
    [ "$sandbox" = $((APP_UID + 10000)) ] ||
        fail "Android gives the fixture's SDK Runtime the UID ${sandbox:-none}, not $((APP_UID + 10000)), which the engine's rule follows"
    echo "ok: the fixture chosen through the dump, handed by its UID, and Android's SDK Runtime UID for it ($sandbox) is the engine's rule's"
else
    echo "ok: the fixture chosen through the dump and handed by its UID; below API 35 ($sdk) Android has no call to compare the SDK Runtime's rule with"
fi

# 1. At the lab's own address, which is local: the choice never covers a local proxy.
socks_before=$(ten_minutes "$SOCKS_HOP") || fail "the network part's dump could not be read"
chosen_since=$(phone_ms) || fail "the phone's time could not be read"
fixture "$FIXTURE" socks5 echoed "${lab[@]}" --es port "$PROXYLAB_PORT"
within 15 socks_now ||
    fail "with the fixture chosen, \"Now\" did not show the local SOCKS5 proxy's first hop for its window alone within 15 s: $(proxies_now)"
none_asked_now || fail "the choice covered a proxy on the local network in \"Now\": $(proxies_now)"
newest=$(newest_flow "$HOST" "$PROXYLAB_PORT") || fail "the network part's kept flows could not be read"
[[ $newest =~ \ socks5\ read\ pn\ -\ -\ -\ -$ ]] || fail "the choice named a flow to a local proxy: ${newest:-none}"
dump log-flush >/dev/null
log=$(dump log-today | sed -n 's/^ *log-record //p')
record_since "$log" "^tcp [0-9]+ 0\\.0\\.0\\.0:0 .*proxy=socks5:read:pln:-:-$" "$chosen_since" ||
    fail "with the fixture chosen, the log does not hold its local SOCKS5 proxy's kind alone"
! record_since "$log" "proxy=socks5:read:pn:" "$chosen_since" || fail "the choice logged a local proxy's first hop"
echo "ok: the choice for one app never covers a proxy on the local network, live or in the log"

# 2. Root, and the rule that sends the network part's own connections to $CHOICE_ADDRESS to the lab.
build_type=$(adb shell getprop ro.build.type | tr -d '\r')
if [ "$build_type" != user ]; then
    adb root >/dev/null 2>&1 || true
    timeout 60 adb wait-for-device || true
    for _ in $(seq 1 10); do
        [ "$(adb shell id -u 2>/dev/null | tr -d '\r')" = 0 ] && ROOTED=1 && break
        sleep 1
    done
fi
if [ -n "$ROOTED" ]; then
    ADV_UID=$(uid_of "$PKG")
    [ -n "$ADV_UID" ] || fail "the network part's UID could not be read"
    DNAT_RULE="-m owner --uid-owner $ADV_UID -d $CHOICE_ADDRESS -p tcp --dport $PROXYLAB_PORT -j DNAT --to-destination $HOST:$PROXYLAB_PORT"
    adb shell "iptables -w -t nat -I OUTPUT 1 $DNAT_RULE" ||
        fail "the emulator's nat table took no rule: the choice cannot be checked at an address that is not local here"
    DNAT_SET=1
    echo "ok: rooted ($build_type build), the network part's own connections to $CHOICE_ADDRESS:$PROXYLAB_PORT go to the lab"

    # 3. Through the lab at an address that is not local: the chosen app's proxy is named by its destination, live and
    # in the log, with the switch off.
    choice_lab=(--es host "$CHOICE_ADDRESS" --es user "$PROXYLAB_USER" --es password "$PROXYLAB_PASSWORD")
    covered_since=$(phone_ms) || fail "the phone's time could not be read"
    fixture "$FIXTURE" socks5 echoed "${choice_lab[@]}" --es port "$PROXYLAB_PORT"
    covered() {
        [[ $(newest_flow "$CHOICE_ADDRESS" "$PROXYLAB_PORT") =~ \ socks5\ read\ p\ inner\.proxylab\.test:443\ -\ -\ inner\.proxylab\.test$ ]]
    }
    within 10 covered ||
        fail "the chosen app's flow through $CHOICE_ADDRESS was not named by its destination: $(newest_flow "$CHOICE_ADDRESS" "$PROXYLAB_PORT")"
    CHOICE_PLACE="^$APP_UID socks5:read:p:inner\\.proxylab\\.test@443:- ${CHOICE_ADDRESS//./\\.}:$PROXYLAB_PORT named-by=1 inner\\.proxylab\\.test 10m="
    place_full() { grep -qE "$CHOICE_PLACE" <<<"$(proxies_now)"; }
    within 10 place_full || fail "\"Now\" does not show the chosen app's proxy in full, with where it asked to go: $(proxies_now)"
    dump log-flush >/dev/null
    log=$(dump log-today | sed -n 's/^ *log-record //p')
    record_since "$log" "^tcp [0-9]+ ${CHOICE_ADDRESS//./\\.}:$PROXYLAB_PORT .* inner\\.proxylab\\.test .*proxy=socks5:read:p:inner\\.proxylab\\.test@443:-$" \
        "$covered_since" || fail "the log does not hold the chosen app's proxy and where it asked to go"
    echo "ok: with the switch off, the chosen app's own proxy at an address that is not local is named by its destination, in \"Now\" and in the log"
else
    if [ "${PROXYLAB_REQUIRED:-}" = 1 ]; then
        fail "PROXYLAB_REQUIRED=1, and this $build_type build refuses adb root: the choice cannot be checked at an address that is not local"
    fi
    echo "NOT RUN: the choice's steps at an address that is not local (2, 3 and 5's check of what is stripped) need adb root, which this $build_type build refuses"
fi

# 4. An update keeps the first install time, and so the choice.
adb install -r "$ROOT/build/proxy-fixture/proxy-fixture.apk" >/dev/null
[ "$(uid_of "$FIXTURE")" = "$APP_UID" ] || fail "the fixture's update gave it another UID"
sleep 3
names_uid "$APP_UID" || fail "an update of the fixture ended its choice: $(logged_uids)"
echo "ok: an update of the chosen app keeps its choice"

# 5. Turned off: at once, nothing the chosen app asked its proxy for stays in "Now" (R6), and its next flow is left out.
grep -q "proxy-log $FIXTURE off" <<<"$(dump proxy-log "$FIXTURE" off)" || fail "the dump did not end the choice for the fixture"
within 5 names_none || fail "the network part still hands the fixture as chosen: $(logged_uids)"
if [ -n "$ROOTED" ]; then
    within 5 none_asked_now || fail "with the choice off, \"Now\" still holds where the fixture asked its proxy to go: $(proxies_now)"
    CHOICE_HOP="^$APP_UID socks5:read:pv:-:- ${CHOICE_ADDRESS//./\\.}:$PROXYLAB_PORT "
    hop_before=$(ten_minutes "$CHOICE_HOP") || fail "the network part's dump could not be read"
    off_since=$(phone_ms) || fail "the phone's time could not be read"
    fixture "$FIXTURE" socks5 echoed "${choice_lab[@]}" --es port "$PROXYLAB_PORT"
    hop_now() { [ "$(ten_minutes "$CHOICE_HOP")" -gt "$hop_before" ]; }
    within 15 hop_now || fail "with the choice off, \"Now\" did not show the proxy's first hop alone for its window: $(proxies_now)"
    none_asked_now || fail "with the choice off, \"Now\" holds where the fixture asked its proxy to go: $(proxies_now)"
    dump log-flush >/dev/null
    log=$(dump log-today | sed -n 's/^ *log-record //p')
    record_since "$log" "^tcp [0-9]+ 0\\.0\\.0\\.0:0 .*proxy=socks5:read:pl:-:-$" "$off_since" ||
        fail "with the choice off, the log does not hold the proxy's kind alone"
    ! record_since "$log" "proxy=socks5:read:p:" "$off_since" || fail "with the choice off, the log got the proxy's first hop"
    # The rule and root go now, so that the rest of the check runs as it always did.
    adb shell "iptables -w -t nat -D OUTPUT $DNAT_RULE" || fail "the emulator's nat rule could not be deleted"
    DNAT_SET=""
    adb unroot >/dev/null 2>&1 || true
    timeout 60 adb wait-for-device || true
    ROOTED=""
    echo "ok: the choice turned off strips at once what the app's proxy asked for, and its next flow is left out of the log"
else
    echo "ok: the choice turned off is no longer handed"
fi

# 6. A reinstall ends it: the package removed and installed again while the network part does not follow the apps, so
# that only its first install time tells, at the next hand-over.
grep -q "proxy-log $FIXTURE on" <<<"$(dump proxy-log "$FIXTURE" on)" || fail "the dump did not make the choice for the fixture again"
within 5 names_uid "$APP_UID" || fail "the network part did not hand the fixture as chosen again: $(logged_uids)"
grep -qE "^ *packages-follow off$" <<<"$(dump packages-follow off)" || fail "the package receiver could not be turned off"
adb uninstall "$FIXTURE" >/dev/null
adb install "$ROOT/build/proxy-fixture/proxy-fixture.apk" >/dev/null
APP_UID=$(uid_of "$FIXTURE")
[ -n "$APP_UID" ] || fail "the fixture did not install again"
grep -qE "^ *packages-follow on$" <<<"$(dump packages-follow on)" || fail "the package receiver could not be turned on again"
# The switch set as it is: every route and the proxies handed again.
grep -q "log-destinations off" <<<"$(dump log-destinations off)" || fail "the switch could not be set again"
within 10 names_none || fail "the choice outlived the fixture's reinstall: proxy-logged $(logged_uids)"
echo "ok: a reinstall of the chosen app ends its choice, by its first install time"

# No password anywhere the network part writes or Android logs.
shown="$(dump)
$(dump log-today)
$(adb logcat -d | tr -d '\r')
$(adb logcat -d -b crash 2>/dev/null | tr -d '\r')"
! grep -qF -- "$PROXYLAB_PASSWORD" <<<"$shown" || fail "the network part's dump, its log or the device's log shows the proxy's password"
! grep -qF -- "$PROXYLAB_USER" <<<"$shown" || fail "the network part's dump, its log or the device's log shows the proxy's user name"
! grep -qF -- "$(printf '%s' "$PROXYLAB_USER:$PROXYLAB_PASSWORD" | base64 -w0)" <<<"$shown" || fail "a Basic credential shows"
! grep -qF -- "${PROXYLAB_MTG_SECRET:2:32}" <<<"$shown" || fail "the MTProto secret's key shows"
echo "ok: no password, user name, Basic credential or MTProto key in the network part's dump, its log, the device's log or its crash buffer"

dump log-destinations on >/dev/null
dump messenger-clear >/dev/null
echo "== Apps' built-in proxies checked on the emulator"
