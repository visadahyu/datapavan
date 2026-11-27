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
# the choice and a reinstall ends it. On such an emulator too, the network's own proxy (the proxy record's unit S2): the
# project's device owner sets the Wi-Fi network's proxy to the proxy record's recorder, the emulator's iptables reject
# every other way out, and a fresh app's request to a public name must answer through it, by the engine's CONNECT to its
# address; the on-link target gets none; and with the network's proxy at a name that never resolves and the switch "Send
# apps through this proxy" on, the request fails with no flow opened, and answers directly once the switch is off. No
# password or user name reaches the network part's dump, the log, the
# device's log or its crash buffer.
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
# Unit C's part: whether this check rooted the emulator, whether it asked to (so that a root that took too long to show
# is undone all the same; review C-rest 10), and the nat rule it set there.
ROOTED=""
UNROOT=""
DNAT_SET=""
DNAT_RULE=""
# The network's own proxy's row (the proxy record's unit S2): the recorder it started, the device owner, mobile data
# off, the Wi-Fi network's proxy and the egress rules it set, and whether it rooted the emulator, each undone at the
# row's end or by the cleanup.
OWNER=org.visadahyu.datapavan.proxyowner
RECORDER=""
OWNER_SET=""
DATA_OFF=""
WIFI_PROXY_SET=""
EGRESS_SET=""
BENEATH_ROOTED=""
# The switch "Send apps through this proxy" turned on through the debug dump, for the switch's hold (S2's review, m2).
THROUGH_SET=""

# Clears Android's global proxy, and clears it again until Android itself holds none. The two writes in a row, ":0"
# and then the setting's deletion, sometimes leave Android's own copy (global_http_proxy_host and _port) set, and "Now"
# then rightly still shows the proxy Android reports: 3 of 40 rounds on an emulator held to one core, as on CI run
# 45847704354. Cleared up to three times; whether it went, for the caller.
global_proxy_gone() {
    local host
    host=$(adb shell settings get global global_http_proxy_host 2>/dev/null | tr -d '\r')
    [ "$host" = null ] || [ -z "$host" ]
}
clear_global_proxy() {
    local _
    for _ in 1 2 3; do
        adb shell settings put global http_proxy :0 >/dev/null 2>&1 || true
        adb shell settings delete global http_proxy >/dev/null 2>&1 || true
        within 5 global_proxy_gone && return 0
    done
    return 1
}

# The network's own proxy's row: the device owner's action $1 with the extras after it, its line.
owner_do() {
    local line
    adb logcat -c
    adb shell am start -W -n "$OWNER/$OWNER.OwnerActivity" --es action "$1" "${@:2}" >/dev/null
    for _ in $(seq 1 30); do
        adb logcat -d -s DatapavanProxyOwner | tr -d '\r' | grep -q 'DatapavanProxyOwner: done$' && break
        sleep 1
    done
    line=$(adb logcat -d -s DatapavanProxyOwner | tr -d '\r' | sed -n "s/.*DatapavanProxyOwner: \($1 \(ok\|failed\) .*\)/\1/p" | tail -1)
    echo "${line:-$1 no-answer}"
}
wifi_connected() { adb shell cmd wifi status | tr -d '\r' | grep -q 'Wifi is connected to "AndroidWifi"'; }
wifi_enabled() {
    local status
    status=$(adb shell cmd wifi status 2>/dev/null | tr -d '\r') || return 1
    grep -qx 'Wifi is enabled' <<<"$status"
}
# Wi-Fi's own state, as scripts/emulator-networks.sh names it.
wifi_state() {
    adb shell cmd wifi status 2>/dev/null | tr -d '\r' | grep -E '^Wifi is (enabled|disabled|connected|not connected)' |
        paste -sd ';' || true
}
wifi_default() {
    local dc default
    dc=$(adb shell dumpsys connectivity | tr -d '\r')
    default=$(sed -n 's/^Active default network: //p' <<<"$dc" | head -1)
    [ -n "$default" ] && grep -qE "network\{$default\} +handle\{[0-9]+\} +ni\{WIFI" <<<"$dc"
}
# The saved network's state for auto-join as Android's Wi-Fi service dumps it: NETWORK_SELECTION_ENABLED, or its status
# and why it is disabled (as NETWORK_SELECTION_TEMPORARY_DISABLED NETWORK_SELECTION_DISABLED_NO_INTERNET_TEMPORARY).
wifi_selection() {
    local dumped
    dumped=$(adb shell dumpsys wifi 2>/dev/null | tr -d '\r') || true
    sed -n '/Configured networks Begin/,/Configured networks End/{
        s/^ *\(NetworkSelectionStatus\|mNetworkSelectionDisableReason\) \(.*\)/\2/p
    }' <<<"$dumped" | paste -sd ' ' || true
}
# Wi-Fi off and on, so that the saved network's proxy reaches its link (scripts/measure-proxy-settings.sh), then told to
# join the emulator's own network by name, as a user's tap does, not left to Android's auto-join: behind the recorder,
# whose certificate fails Android's HTTPS probe, Android disables the saved network for auto-join (the row's note
# says how), and on CI run 46052462725 Wi-Fi came back on, scanned twice in 60 s and joined nothing, as on 2026-11-19
# (scripts/emulator-networks.sh). The join enables the network and keeps its proxy, which the shell's configuration
# leaves unassigned. Once, and the network's state is named where it fails.
wifi_again() {
    adb shell svc wifi disable
    sleep 2
    adb shell svc wifi enable
    within 20 wifi_enabled || return 1
    adb shell cmd wifi connect-network AndroidWifi open >/dev/null 2>&1 || true
    within 60 wifi_connected && within 30 wifi_default
}
# Every connection out of the emulator rejected but on the loopback, into the VPN's interface and to the recorder's
# proxy, first in OUTPUT; "-D" takes them out.
beneath_egress() {
    local op=$1
    if [ "$op" = -I ]; then
        adb shell iptables -w -I OUTPUT 1 -j REJECT && adb shell ip6tables -w -I OUTPUT 1 -j REJECT &&
            adb shell iptables -w -I OUTPUT 1 -d "$HOST" -p tcp --dport "$BENEATH_PORT" -j ACCEPT &&
            for table in iptables ip6tables; do
                adb shell "$table" -w -I OUTPUT 1 -o tun+ -j ACCEPT && adb shell "$table" -w -I OUTPUT 1 -o lo -j ACCEPT || return 1
            done
    else
        adb shell iptables -w -D OUTPUT -d "$HOST" -p tcp --dport "$BENEATH_PORT" -j ACCEPT
        for table in iptables ip6tables; do
            adb shell "$table" -w -D OUTPUT -o lo -j ACCEPT
            adb shell "$table" -w -D OUTPUT -o tun+ -j ACCEPT
            adb shell "$table" -w -D OUTPUT -j REJECT
        done
    fi
}
# The row undone, whatever of it was set, in the reverse order; at its end and by the cleanup.
beneath_undo() {
    # The switch first, while the settle still has the key it was set for.
    [ -z "$THROUGH_SET" ] || dump proxy-through off >/dev/null 2>&1 || true
    THROUGH_SET=""
    [ -z "$EGRESS_SET" ] || beneath_egress -D >/dev/null 2>&1 || true
    EGRESS_SET=""
    if [ -n "$WIFI_PROXY_SET" ]; then
        owner_do wifi-none >/dev/null 2>&1 || true
        wifi_again >/dev/null 2>&1 || true
        WIFI_PROXY_SET=""
    fi
    if [ -n "$OWNER_SET" ]; then
        adb shell dpm remove-active-admin "$OWNER/.OwnerReceiver" >/dev/null 2>&1 || true
        adb uninstall "$OWNER" >/dev/null 2>&1 || true
        OWNER_SET=""
    fi
    if [ -n "$DATA_OFF" ]; then adb shell svc data enable >/dev/null 2>&1 || true; DATA_OFF=""; fi
    if [ -n "$RECORDER" ]; then kill "$RECORDER" 2>/dev/null || true; wait "$RECORDER" 2>/dev/null || true; RECORDER=""; fi
    if [ -n "$BENEATH_ROOTED" ]; then
        adb unroot >/dev/null 2>&1 || true
        timeout 60 adb wait-for-device >/dev/null 2>&1 || true
        BENEATH_ROOTED=""
    fi
}

cleanup() {
    local status=$?
    beneath_undo
    if [ -n "$DNAT_SET" ]; then adb shell "iptables -w -t nat -D OUTPUT $DNAT_RULE" >/dev/null 2>&1 || true; fi
    if [ -n "$UNROOT" ]; then
        adb unroot >/dev/null 2>&1 || true
        timeout 60 adb wait-for-device >/dev/null 2>&1 || true
    fi
    if [ -n "$PROXY_SET" ]; then clear_global_proxy || true; fi
    adb shell am force-stop "$PKG" >/dev/null 2>&1 || true
    for role in "" .telegram .whatsapp .signal; do adb uninstall "$FIXTURE$role" >/dev/null 2>&1 || true; done
    if [ "$status" != 0 ]; then
        mkdir -p "$ROOT/build/proxylab"
        "${compose[@]}" logs --no-color --timestamps >"$ROOT/build/proxylab/lab-verify-proxies.log" 2>&1 || true
    fi
    "${compose[@]}" stop >/dev/null 2>&1 || true
    rm -rf "$WORK"
}
check_evidence_on cleanup
# It reads the connection log of the device's day: that day must not end while it runs.
check_day_guard

dump() { adb shell dumpsys activity service "$PKG/org.visadahyu.datapavan.network.NetworkVpnService" "$@" | tr -d '\r'; }
fixture_log() { adb logcat -d -s DatapavanProxyFixture | tr -d '\r' | sed -n 's/.*DatapavanProxyFixture: //p'; }
proxies() { dump | sed -n 's/^ *flow-proxy //p'; }
fail() {
    check_failed "$*"
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
echo "ok: the proxy lab answers on this computer's loopback, ports $PROXYLAB_PORT to $PROXYLAB_PORT_SEEN"

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
clear_global_proxy || fail "Android kept its global proxy after it was cleared three times"
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
clear_global_proxy || fail "Android kept its global proxy after it was cleared three times"
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
# The hand-overs of the proxies so far; those the change of the package $1 ran; and why the choice for the package $1
# ended without the user, as the debug builds' dump writes them (review C-rest 6 and 11).
handed_count() { dump | sed -n 's/^ *proxy-handed //p'; }
package_handed() { dump | awk -v p="$1" '$1 == "packages-handed" && $2 == p { n = $3 } END { print n + 0 }'; }
ended_why() { dump | awk -v p="$1" '$1 == "proxy-ended" && $2 == p { print $3 }'; }
# Whether the change of the package $1 ran a hand-over since there were $2.
package_handed_since() { [ "$(package_handed "$1")" -gt "$2" ]; }
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
    UNROOT=1
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

# 4. An update keeps the first install time, and so the choice: read after the hand-over the update's own broadcast
# runs, never the one before it (review C-rest 6).
updates=$(package_handed "$FIXTURE")
adb install -r "$ROOT/build/proxy-fixture/proxy-fixture.apk" >/dev/null
[ "$(uid_of "$FIXTURE")" = "$APP_UID" ] || fail "the fixture's update gave it another UID"
within 15 package_handed_since "$FIXTURE" "$updates" || fail "the network part ran no hand-over for the fixture's update within 15 s"
names_uid "$APP_UID" || fail "an update of the fixture ended its choice: $(logged_uids)"
echo "ok: an update of the chosen app keeps its choice, read after the hand-over that followed it"

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
    UNROOT=""
    echo "ok: the choice turned off strips at once what the app's proxy asked for, and its next flow is left out of the log"
else
    echo "ok: the choice turned off is no longer handed"
fi

# 6. A reinstall ends it, and says so (review C-rest 1). First one the network part follows, as a phone's always is:
# the removal's hand-over finds the package gone, and the install's finds it back.
grep -q "proxy-log $FIXTURE on" <<<"$(dump proxy-log "$FIXTURE" on)" || fail "the dump did not make the choice for the fixture again"
within 5 names_uid "$APP_UID" || fail "the network part did not hand the fixture as chosen again: $(logged_uids)"
removals=$(package_handed "$FIXTURE")
adb uninstall "$FIXTURE" >/dev/null
within 15 package_handed_since "$FIXTURE" "$removals" || fail "the network part ran no hand-over for the fixture's removal within 15 s"
names_none || fail "the choice outlived the fixture's removal: proxy-logged $(logged_uids)"
[ "$(ended_why "$FIXTURE")" = removed ] || fail "the fixture's removal was kept as '$(ended_why "$FIXTURE")', not removed"
installs=$(package_handed "$FIXTURE")
adb install "$ROOT/build/proxy-fixture/proxy-fixture.apk" >/dev/null
APP_UID=$(uid_of "$FIXTURE")
[ -n "$APP_UID" ] || fail "the fixture did not install again"
within 15 package_handed_since "$FIXTURE" "$installs" || fail "the network part ran no hand-over for the fixture's install within 15 s"
names_none || fail "the choice came back with the fixture's new install: proxy-logged $(logged_uids)"
[ "$(ended_why "$FIXTURE")" = installed-again ] ||
    fail "the fixture installed again after a removal the network part saw says '$(ended_why "$FIXTURE")', not installed again"
echo "ok: a reinstall the network part follows ends the choice, and its rows say it was installed again"

# Then one it does not follow, the package receiver off, so that only the first install time tells, at the next
# hand-over: with none between the removal and the install, or the removal would tell (review C-rest 11). A hand-over
# between them (a network callback, a reading of the tools) is tried again, at most three times.
grep -qE "^ *packages-follow off$" <<<"$(dump packages-follow off)" || fail "the package receiver could not be turned off"
quiet=""
for _ in 1 2 3; do
    grep -q "proxy-log $FIXTURE on" <<<"$(dump proxy-log "$FIXTURE" on)" || fail "the dump did not make the choice for the fixture again"
    within 5 names_uid "$APP_UID" || fail "the network part did not hand the fixture as chosen again: $(logged_uids)"
    before=$(handed_count)
    adb uninstall "$FIXTURE" >/dev/null
    adb install "$ROOT/build/proxy-fixture/proxy-fixture.apk" >/dev/null
    APP_UID=$(uid_of "$FIXTURE")
    [ -n "$APP_UID" ] || fail "the fixture did not install again"
    [ "$(handed_count)" = "$before" ] && quiet=1 && break
done
[ -n "$quiet" ] || fail "three times a hand-over came between the fixture's removal and its install: the first install time's rule is not checked"
grep -qE "^ *packages-follow on$" <<<"$(dump packages-follow on)" || fail "the package receiver could not be turned on again"
# The switch set as it is: every route and the proxies handed again.
grep -q "log-destinations off" <<<"$(dump log-destinations off)" || fail "the switch could not be set again"
within 10 names_none || fail "the choice outlived the fixture's reinstall: proxy-logged $(logged_uids)"
[ "$(ended_why "$FIXTURE")" = installed-again ] ||
    fail "the fixture installed again, seen by its first install time alone, says '$(ended_why "$FIXTURE")', not installed again"
echo "ok: a reinstall of the chosen app ends its choice by its first install time alone, and says so"

# 7. The network's own proxy (the proxy record's unit S2; S2-PLAN.md, section 8, and its audit's M4): on an emulator
# that `adb root` takes, the project's test-only device owner (scripts/proxy-owner) sets the Wi-Fi network's own proxy
# to the recorder (scripts/proxy-measure/recorder.py, its tunnel mode, on this computer's loopback), mobile data off so
# that Wi-Fi is the network beneath, and the emulator's iptables reject every connection out but to the recorder. A
# fresh fixture's request to a public name (example.com, RFC 2606) must answer through it: the engine counts its flow
# under `network-proxy`, and the recorder carried a CONNECT to that flow's address with no User-Agent. The recorder's
# own address, 10.0.2.2, is on-link and rightly never reached through the proxy: the direct target there gets no
# CONNECT. Where root or the device owner is refused, the row says so and is not run; with PROXYLAB_REQUIRED=1, which CI
# sets, that fails. Its evidence is the recorder's log, the network part's dump and the device's log, kept on a failure.
# The row needs this computer's internet (S2's review, m6): the recorder carries the fixture's request to example.com,
# and the resolver's lookup to the first ODoH pair's relay (data/odoh). A preflight connects to both from here first;
# where either cannot be reached, the row is skipped and says so, as the runner's outage, not the engine's, whatever
# PROXYLAB_REQUIRED says.
# Then the switch's hold (S2's review, m2), on the same Wi-Fi network with its way out open again: its proxy at a name
# that never resolves (proxy.invalid, RFC 6761), and the switch "Send apps through this proxy" turned on for it through
# the debug dump (`proxy-through`, since "Now" draws the switch only once the engine has an address). The engine holds a
# direct app's new flow, its SYN unanswered, and fails it as an unreachable network where no proxy came within 3 s: a
# fresh fixture's request to example.com must fail, the engine must keep a flow of it failed as unreachable and none
# opened, none through the proxy, and its counter 80 (the flows the hold kept waiting) must rise. With the switch off
# again, the engine has no setting, and the same request must answer directly, by a flow opened.
not_run() {
    [ "${PROXYLAB_REQUIRED:-}" != 1 ] || fail "PROXYLAB_REQUIRED=1, and the network's own proxy's row cannot run: $1"
    echo "NOT RUN: the network's own proxy's row: $1"
}
# The preflight: prints what this computer cannot reach on port 443, nothing where it reaches both.
runner_reach() {
    local relay addresses
    relay=$(awk -F'\t' '!/^#/ && NF >= 2 { print $1; exit }' "$ROOT/data/odoh/pairs.tsv")
    addresses=$(awk -F'\t' -v id="$relay" '!/^#/ && $1 == id { print $3 ($4 == "-" ? "" : "," $4) }' "$ROOT/data/odoh/relays.tsv")
    python3 -I - example.com "${addresses%%,*}" <<'PY'
import socket, sys
for host in sys.argv[1:]:
    try:
        socket.create_connection((host or "(no relay address)", 443), timeout=5).close()
    except OSError as e:
        print(f"{host or 'the first relay'}:443 ({e.__class__.__name__})")
PY
}
beneath_row() {
    local line base flows dest unreachable selection
    unreachable=$(runner_reach | paste -sd ' ')
    if [ -n "$unreachable" ]; then
        echo "SKIPPED: the network's own proxy's row: this computer cannot reach $unreachable, the runner's outage, not the engine's"
        return 0
    fi
    adb root >/dev/null 2>&1 || true
    timeout 60 adb wait-for-device || true
    for _ in $(seq 1 10); do
        [ "$(adb shell id -u 2>/dev/null | tr -d '\r')" = 0 ] && BENEATH_ROOTED=1 && break
        sleep 1
    done
    [ -n "$BENEATH_ROOTED" ] || { BENEATH_ROOTED=1; not_run "this $(adb shell getprop ro.build.type | tr -d '\r') build refuses adb root"; return 0; }
    # Three free ports in a row on this computer's loopback, from 18300, for the recorder's proxy, PAC and direct target.
    base=$(python3 -I - <<'PY'
import socket, sys
def free(port):
    s = socket.socket()
    try:
        s.bind(("127.0.0.1", port))
        return True
    except OSError:
        return False
    finally:
        s.close()
for base in range(18300, 18400, 10):
    if all(free(base + i) for i in range(3)):
        print(base)
        break
else:
    sys.exit("no three free ports in a row from 18300")
PY
) || fail "no free ports for the recorder"
    BENEATH_PORT=$base
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 1 -subj "/CN=inner.proxylab.test" \
        -keyout "$WORK/recorder-key.pem" -out "$WORK/recorder-cert.pem" >/dev/null 2>&1 || fail "no certificate for the recorder"
    : >"$WORK/recorder.tsv"
    python3 -I "$ROOT/scripts/proxy-measure/recorder.py" "$base" "$WORK/recorder.tsv" "$WORK/recorder-cert.pem" \
        "$WORK/recorder-key.pem" tunnel >"$WORK/recorder.out" 2>&1 &
    RECORDER=$!
    recorder_ready() { grep -qx ready "$WORK/recorder.out" 2>/dev/null; }
    within 10 recorder_ready || fail "the recorder did not start: $(cat "$WORK/recorder.out")"
    "$ROOT/scripts/proxy-owner/build.sh" >/dev/null 2>&1 || fail "the device owner could not be built"
    adb shell dpm remove-active-admin "$OWNER/.OwnerReceiver" >/dev/null 2>&1 || true
    adb uninstall "$OWNER" >/dev/null 2>&1 || true
    adb install -t "$ROOT/build/proxy-owner/proxy-owner.apk" >/dev/null || fail "the device owner did not install"
    OWNER_SET=1
    if ! adb shell dpm set-device-owner "$OWNER/.OwnerReceiver" >/dev/null 2>&1; then
        not_run "Android refused the project's device owner (an account on the emulator, or not a fresh one)"
        return 0
    fi
    adb shell pm grant "$OWNER" android.permission.ACCESS_FINE_LOCATION
    adb shell cmd location set-location-enabled true >/dev/null 2>&1 || true
    adb shell svc data disable
    DATA_OFF=1
    within 30 wifi_default || fail "Wi-Fi is not the default network with mobile data off"
    line=$(owner_do wifi-proxy --es host "$HOST" --es port "$base")
    [[ $line == "wifi-proxy ok "* ]] || fail "the device owner did not set the Wi-Fi network's proxy: $line"
    WIFI_PROXY_SET=1
    wifi_again ||
        fail "Wi-Fi did not come back as the default network after its proxy was set ($(wifi_state); the saved network: $(wifi_selection))"
    beneath_held() { grep -qE "^ *beneath-proxy ${HOST//./\\.}:$base network " <<<"$(dump beneath-proxy)"; }
    within 20 beneath_held || fail "the engine was not handed the Wi-Fi network's proxy: $(dump beneath-proxy | grep 'beneath-proxy' || echo none)"
    beneath_egress -I || fail "the emulator's iptables took no rule"
    EGRESS_SET=1
    echo "ok: the Wi-Fi network's own proxy is the recorder at $HOST:$base, the engine holds it, and every other way out is rejected"

    routes_before=$(dump | sed -n "s/^ *flow-route $APP_UID network-proxy //p")
    adb shell am force-stop "$FIXTURE"
    fixture "$FIXTURE" get 200 --es url "https://example.com/"
    through() { [ "$(dump | sed -n "s/^ *flow-route $APP_UID network-proxy //p")" -gt "${routes_before:-0}" ] 2>/dev/null; }
    within 10 through || fail "the engine counts no flow of the fixture through the network's proxy: $(dump | grep 'flow-route' || echo none)"
    # Its flows opened to port 443 since the fixture's lab steps, whose destinations were addresses on the lab's network.
    flows=$(dump | sed -n 's/^ *flow //p' | awk -v uid="$APP_UID" -v lab="$HOST:" '$1 == "tcp" && $4 == uid && $5 == "opened" && $3 ~ /:443$/ && index($3, lab) != 1 { print $3 }' | sort -u)
    [ -n "$flows" ] || fail "the engine kept no opened flow of the fixture to a public address on port 443"
    for dest in $flows; do
        awk -F'\t' -v d="$dest" '$2 == "proxy" && $3 == "CONNECT " d " HTTP/1.1" && $5 == "-" { found = 1 } END { exit !found }' "$WORK/recorder.tsv" &&
            awk -F'\t' -v d="$dest" '$2 == "proxy-tunnel" && $3 == "TUNNEL " d " open" { found = 1 } END { exit !found }' "$WORK/recorder.tsv" &&
            break
        dest=""
    done
    [ -n "$dest" ] || fail "the recorder carried no CONNECT with no User-Agent to the fixture's flow ($flows): $(cut -f2,3 "$WORK/recorder.tsv" | tail -8 | tr '\n' ';')"
    echo "ok: on a network that requires its proxy, a fresh app reaches example.com through it: CONNECT $dest with no User-Agent, the engine's route network-proxy"

    adb shell am force-stop "$FIXTURE"
    adb logcat -c
    adb shell am start -W -n "$FIXTURE/$FIXTURE.ProxyActivity" --es action get --es url "http://$HOST:$((base + 2))/direct" >/dev/null
    for _ in $(seq 1 30); do
        grep -qx done <<<"$(fixture_log)" && break
        sleep 1
    done
    line=$(fixture_log | grep -E '^get (ok|failed)' | tail -1 || true)
    [[ $line == "get failed "* ]] || fail "the on-link direct target answered on a network that rejects it: ${line:-no answer}"
    ! grep -qF "CONNECT $HOST:$((base + 2)) " "$WORK/recorder.tsv" || fail "the engine sent the on-link direct target through the proxy"
    echo "ok: the on-link direct target $HOST:$((base + 2)) is never sent through the proxy ($line)"

    beneath_egress -D || fail "the emulator's iptables rules could not be taken out"
    EGRESS_SET=""
    # Behind the recorder, Android's HTTP probe answered and its HTTPS probe failed on the recorder's certificate, and
    # Android disabled the network for auto-join (DISABLED_NO_INTERNET_TEMPORARY on this computer's runs): said here,
    # before wifi_again joins it by name.
    selection=$(wifi_selection)
    [ "$selection" = NETWORK_SELECTION_ENABLED ] ||
        echo "  note: before the proxy at proxy.invalid, Android held the saved network as ${selection:-(not dumped)} for auto-join"
    line=$(owner_do wifi-proxy --es host proxy.invalid --es port "$base")
    [[ $line == "wifi-proxy ok "* ]] || fail "the device owner did not set the Wi-Fi network's proxy to proxy.invalid: $line"
    wifi_again ||
        fail "Wi-Fi did not come back as the default network after its proxy was set to proxy.invalid ($(wifi_state); the saved network: $(wifi_selection))"
    beneath_unresolved() { grep -qE '^ *beneath-proxy none unresolved ' <<<"$(dump beneath-proxy)"; }
    within 30 beneath_unresolved || fail "the engine's setting is not proxy.invalid's, unresolved: $(dump beneath-proxy | grep 'beneath-proxy' || echo none)"
    line=$(dump proxy-through on | sed -n 's/^ *\(proxy-through .*\)/\1/p')
    [ "$line" = "proxy-through on" ] || fail "the dump did not turn the switch on: ${line:-no answer}"
    THROUGH_SET=1
    beneath_hold() { grep -qE '^ *beneath-proxy hold .* always=1 ' <<<"$(dump beneath-proxy)"; }
    within 20 beneath_hold || fail "the engine was not handed the switch's hold: $(dump beneath-proxy | grep 'beneath-proxy' || echo none)"
    held_count() { dump | sed -n 's/^ *counters //p' | head -1 | awk '{ print $81 }'; }
    routes_through() { dump | sed -n "s/^ *flow-route $APP_UID network-proxy //p"; }
    # The fixture's TCP flows kept, by the app's end and the destination, and its new ones' outcomes since $1.
    fixture_flows() { dump | sed -n 's/^ *flow //p' | awk -v uid="$APP_UID" '$1 == "tcp" && $4 == uid { print $2, $3, $5 }'; }
    outcomes_since() { awk 'NR == FNR { seen[$1 " " $2] = 1; next } !seen[$1 " " $2] { print $3 }' <(printf '%s\n' "$1") <(fixture_flows) | sort | uniq -c | awk '{ printf "%s=%d ", $2, $1 }'; }
    fetch() {
        adb shell am force-stop "$FIXTURE"
        adb logcat -c
        adb shell am start -W -n "$FIXTURE/$FIXTURE.ProxyActivity" --es action get --es url "https://example.com/" >/dev/null
        for _ in $(seq 1 30); do
            grep -qx done <<<"$(fixture_log)" && break
            sleep 1
        done
        fixture_log | grep -E '^get (ok|failed)' | tail -1 || true
    }
    local held routes new_routes before outcomes
    held=$(held_count)
    routes=$(routes_through)
    before=$(fixture_flows)
    line=$(fetch)
    sleep 1
    outcomes=$(outcomes_since "$before")
    [[ $line == "get failed "* ]] || fail "with the switch on and no proxy to be had, the fixture's request answered: ${line:-no answer}"
    [[ $outcomes == *unreachable=* && $outcomes != *opened=* ]] || fail "the engine's flows of the fixture with the switch's hold: ${outcomes:-none}"
    # Only the routes kept since the fetch: the engine keeps its latest 512 flows, so an older proxied flow of the
    # fixture may have left the list meanwhile (the shards of 2026-11-27, beside an app's 490 unreachable flows).
    new_routes=$(comm -13 <(sort <<<"$routes") <(routes_through | sort))
    [ -z "$new_routes" ] || fail "a flow of the fixture went through the network's proxy, which has no address: $new_routes"
    [ "$(held_count)" -gt "${held:-0}" ] 2>/dev/null || fail "the engine's counter of the flows the hold kept waiting did not rise: $held -> $(held_count)"
    echo "ok: with the switch on and the network's proxy at proxy.invalid, the request fails ($line), its flows ${outcomes% }, none opened, the hold's counter $held -> $(held_count)"

    line=$(dump proxy-through off | sed -n 's/^ *\(proxy-through .*\)/\1/p')
    [ "$line" = "proxy-through off" ] || fail "the dump did not turn the switch off: ${line:-no answer}"
    THROUGH_SET=""
    beneath_none() { grep -qE '^ *beneath-proxy none ' <<<"$(dump beneath-proxy)"; }
    within 20 beneath_none || fail "the engine kept a setting with the switch off: $(dump beneath-proxy | grep 'beneath-proxy' || echo none)"
    held=$(held_count)
    before=$(fixture_flows)
    line=$(fetch)
    sleep 1
    outcomes=$(outcomes_since "$before")
    [ "$line" = "get ok 200" ] || fail "with the switch off, the fixture's request did not answer directly: ${line:-no answer}"
    [[ $outcomes == *opened=* ]] || fail "the engine kept no opened flow of the fixture with the switch off: ${outcomes:-none}"
    [ "$(held_count)" = "$held" ] || fail "the hold kept a flow waiting with the switch off: $held -> $(held_count)"
    echo "ok: with the switch off, the same request answers directly ($line), its flows ${outcomes% }"
    beneath_undo
}
beneath_row

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
