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
# proxy. "Now" and the log hold the same, and with the switch "Log where apps connect through your tool, WireGuard or a
# proxy" off only the kind; that switch is on the network screen, though the phone has no tool and no tunnel. No
# password or user name reaches the network part's dump, the log, the device's log or its crash buffer.
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

cleanup() {
    local status=$?
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
sleep 1
lab=(--es host "$HOST" --es user "$PROXYLAB_USER" --es password "$PROXYLAB_PASSWORD")

# Declared: each named by the destination asked for, a password unencrypted said, none of them Android's setting.
fixture "$FIXTURE" socks5 echoed "${lab[@]}" --es port "$PROXYLAB_PORT"
proxied "$APP_UID" "$PROXYLAB_PORT" "socks5 read p inner\.proxylab\.test:443 - - inner\.proxylab\.test"
fixture "$FIXTURE" connect echoed "${lab[@]}" --es port "$PROXYLAB_PORT_HTTP"
proxied "$APP_UID" "$PROXYLAB_PORT_HTTP" "connect read p inner\.proxylab\.test:443 - - inner\.proxylab\.test"
fixture "$FIXTURE" forward 204 "${lab[@]}" --es port "$PROXYLAB_PORT_HTTP"
# A plain request cannot be confirmed by its reply: its flow keeps its own name, and says what it asked for.
proxied "$APP_UID" "$PROXYLAB_PORT_HTTP" "forward read p inner\.proxylab\.test:80 - - [^i].*"
echo "ok: SOCKS5 with a password and CONNECT with Basic named by the destination asked for once the proxy confirmed it, a plain request keeping its own name"

# Android's proxy setting, told apart from an app's own.
PROXY_SET=1
adb shell settings put global http_proxy "$HOST:$PROXYLAB_PORT_OPEN"
sleep 2
fixture "$FIXTURE" setting 204
proxied "$APP_UID" "$PROXYLAB_PORT_OPEN" "forward read s inner\.proxylab\.test:80 - - [^i].*"
adb shell settings put global http_proxy :0
adb shell settings delete global http_proxy >/dev/null 2>&1 || true
PROXY_SET=""
echo "ok: Android's proxy setting told apart from an app's own"

# Inferred: Telegram's obfuscated start and fake-TLS hello to mtg, WhatsApp's clear header, Signal's proxy by its name.
fixture "$FIXTURE.telegram" obfuscated sent --es host "$HOST" --es port "$PROXYLAB_PORT_MTG"
proxied "$TELEGRAM_UID" "$PROXYLAB_PORT_MTG" "mtproto inferred o - - - .*"
# A hello no answer tied is evidence only where the network part sees the app's lookups: the fixture looks a name up
# first.
fixture "$FIXTURE.telegram" lookup asked --es name lookup.proxylab.test
fixture "$FIXTURE.telegram" faketls accepted --es host "$HOST" --es port "$PROXYLAB_PORT_MTG" --es secret "$PROXYLAB_MTG_SECRET"
proxied "$TELEGRAM_UID" "$PROXYLAB_PORT_MTG" "mtproto inferred o - - cover\.proxylab\.test .*"
if grep -E "^tcp [^ ]+ ${HOST//./\\.}:$PROXYLAB_PORT_MTG $TELEGRAM_UID " <<<"$(dump | sed -n 's/^ *flow //p')" | grep -q "cover\.proxylab\.test"; then
    fail "the fake-TLS cover named Telegram's flow"
fi
fixture "$FIXTURE.whatsapp" whatsapp echoed --es host "$HOST" --es port "$PROXYLAB_PORT_ECHO"
proxied "$WHATSAPP_UID" "$PROXYLAB_PORT_ECHO" "whatsapp inferred o - - - .*"
fixture "$FIXTURE.signal" hello echoed --es host "$HOST" --es port "$PROXYLAB_PORT_TLS" --es name signal-proxy.proxylab.test
proxied "$SIGNAL_UID" "$PROXYLAB_PORT_TLS" "signal inferred - - - - signal-proxy\.proxylab\.test"
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
now=$(dump | sed -n 's/^ *activity-proxy //p')
grep -qE "^$APP_UID socks5:read:p:inner\.proxylab\.test@443:- ${HOST//./\\.}:$PROXYLAB_PORT named-by=1 inner\.proxylab\.test$" <<<"$now" ||
    fail "\"Now\" does not hold the SOCKS5 proxy as named: $now"
grep -qE "^$TELEGRAM_UID mtproto:inferred:o:-:- " <<<"$now" || fail "\"Now\" does not hold Telegram's proxy: $now"
dump log-flush >/dev/null
log=$(dump log-today | sed -n 's/^ *log-record //p')
grep -qE "^tcp $APP_UID ${HOST//./\\.}:$PROXYLAB_PORT .* inner\.proxylab\.test .*proxy=socks5:read:p:inner\.proxylab\.test@443:-$" <<<"$log" ||
    fail "the log does not hold the SOCKS5 proxy as named"
echo "ok: \"Now\" and the log hold the proxies as named"

# The switch off: the next proxied flows keep their kind alone, in "Now" and in the log, marked as left out.
grep -q "log-destinations off" <<<"$(dump log-destinations off)" || fail "the switch \"Log where apps connect ...\" was not turned off"
sleep 1
fixture "$FIXTURE" socks5 echoed "${lab[@]}" --es port "$PROXYLAB_PORT"
fixture "$FIXTURE.telegram" obfuscated sent --es host "$HOST" --es port "$PROXYLAB_PORT_MTG"
sleep 1
dump log-flush >/dev/null
log=$(dump log-today | sed -n 's/^ *log-record //p')
grep -qE "^tcp $APP_UID 0\.0\.0\.0:0 .* - .*proxy=socks5:read:pl:-:-$" <<<"$log" ||
    fail "with the switch off, the log does not hold the SOCKS5 proxy's kind alone"
# An inferred proxy's records wait ten minutes, its window of take-back, before the log gets them (ADR 0052, the fix
# round's F2): none of Telegram's is in the log yet, though the flush wrote everything else.
! grep -qE "^tcp $TELEGRAM_UID .*proxy=mtproto" <<<"$log" ||
    fail "the log got a record of Telegram's inferred proxy within its window of take-back"
now=$(dump | sed -n 's/^ *activity-proxy //p')
grep -qE "^$APP_UID socks5:read:pl:-:- 0\.0\.0\.0:0 " <<<"$now" || fail "with the switch off, \"Now\" does not hold the kind alone: $now"
grep -qE "^$TELEGRAM_UID mtproto:inferred:ol:-:- 0\.0\.0\.0:0 " <<<"$now" ||
    fail "with the switch off, \"Now\" does not hold Telegram's proxy's kind alone: $now"
echo "ok: with the switch off, the log and \"Now\" keep the proxy's kind alone, and an inferred one's records wait for their window"

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
