#!/usr/bin/env bash
# The proxy record's measurements 7.1 and 7.2, part one (the middle-way study's section 7, the brief's audit finding
# 20): what Android's own proxy settings do to an ordinary app, with Datapavan Advanced's VPN off and on, on an
# emulator. A measurement, not a check: it stops only when a step could not be made, and writes what it saw.
#
# The settings, each made without the Settings screens and taken away again: none; the Wi-Fi network's own proxy (a
# host and port) and its own PAC, set by the project's test-only device owner (scripts/proxy-owner) through the saved
# network, with Wi-Fi turned off and on so that the network's link takes it; the global proxy by
# `settings put global http_proxy`; the global proxy and a global PAC by the device owner's
# setRecommendedGlobalProxy. The proxy, the PAC file and a direct target are the recorder's (scripts/proxy-measure/
# recorder.py) on this computer's loopback, which the emulator reaches as 10.0.2.2; it logs each request line, its Host,
# its User-Agent, and the server name of a TLS hello through a CONNECT.
#
# For each setting the project's proxy fixture (scripts/proxy-fixture) says what Android tells it (`read`, once in a
# process that was running when the setting changed, then afresh), fetches with HttpURLConnection over http and https
# and from an address target that only a direct connection reaches as itself (`get`), sends a plain request by a socket
# of its own to the proxy the system properties name (`property`), loads a page in a WebView (`webview`), and sends a
# plain request to the recorder's proxy of its own choosing (`forward`, to see whether the engine calls that address
# Android's setting). Each action but the first starts a fresh process. With the VPN on, the network part's dump says
# which UID each flow came from and how the engine named it, and a second copy of the fixture, left out of the tunnel
# (ADR 0041), shows what an app outside it gets. A proxy was used only where the recorder logged the request at its
# proxy port and, with the VPN on, the engine shows the flow there: an exception alone says nothing, since Android's
# HTTP stack tries a direct connection after a proxy that failed (the plan's audit, 2026-11-24).
#
# Four passes (PASSES="1 2 3 4" to choose): the VPN off; the Wi-Fi network's proxy and PAC set first and the VPN
# started after them; the VPN on while each setting changes; and a process of the fixture that started before the VPN,
# with the Wi-Fi network's own setting, used again once the VPN is up. Mobile data is off for the run, so that Wi-Fi is
# the default network and the VPN's. A fifth, PASSES=5, on an emulator that `adb root` takes (a google_apis image), is
# a network that requires its proxy: with the Wi-Fi network's proxy set and the VPN on, the emulator's iptables reject
# every connection out but to the recorder's proxy, so that the network part's resolver answers only through it.
#
# The resolver unit (the strategy repository's research/2026-11-proxy-record/R-PLAN.md, "After the audit", M8): with
# the VPN on, each setting's part ends with what the network part's resolver did in it, as positive evidence, never as
# an absence: the proxy it follows and why (the dump's `dns-proxy`), the exchanges that answered by each way since the
# part began (`dns-latency`, cleared at its start), and the recorder's CONNECTs to an address on port 443, by
# User-Agent. The resolver sends those by the data pack's address with no User-Agent; the recorder carries them to that
# address from this computer (its `tunnel` mode), so that no hold of the resolver's comes from the proxy's path, and
# answers every CONNECT to a name as before.
#
# Emulators only, named by ANDROID_SERIAL=emulator-N (a phone may be attached beside them): the device owner needs a
# freshly booted emulator with no account, best a read-only instance. Everything it set is taken away at the end: the
# proxies, the device owner, mobile data back on, the fixtures; the recorder and the log reader stop.
#
#   ANDROID_SERIAL=emulator-5620 [PASSES="1 2 3 4"] scripts/measure-proxy-settings.sh [Datapavan-Advanced-debug.apk]
#
# Output in build/proxy-measure/: api<SDK>.txt (api<SDK>-passes-<N...>.txt for a choice of passes), the recorder's
# log beside it (-recorder.tsv) and the device's log for the whole run (-logcat.txt).
set -euo pipefail
export LC_ALL=C

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APK="${1:-$ROOT/android/app/build-advanced/outputs/apk/debug/app-debug.apk}"
PKG=org.visadahyu.datapavan.advanced
NETWORK_SCREEN=org.visadahyu.datapavan.network.MainActivity
FIXTURE=org.visadahyu.datapavan.proxyfixture
OUTSIDE=$FIXTURE.outside
OWNER=org.visadahyu.datapavan.proxyowner
HOST=10.0.2.2
INNER=inner.proxylab.test
# shellcheck source=scripts/adb-ui.sh
. "$ROOT/scripts/adb-ui.sh"

[[ ${ANDROID_SERIAL:-} == emulator-* ]] || { echo "name the emulator: ANDROID_SERIAL=emulator-N" >&2; exit 2; }
is_emulator || { echo "measure-proxy-settings.sh runs on an emulator only" >&2; exit 2; }
[ -f "$APK" ] || { echo "no $APK: build Datapavan Advanced's debug APK first" >&2; exit 2; }
SDK_INT=$(adb shell getprop ro.build.version.sdk | tr -d '\r')
OUT="$ROOT/build/proxy-measure"
mkdir -p "$OUT/tls"
RUN="api$SDK_INT${PASSES:+-passes-${PASSES// /}}"
REPORT="$OUT/$RUN.txt"
RECORDS="$OUT/$RUN-recorder.tsv"
STREAM="$OUT/$RUN-logcat.txt"
: >"$REPORT"
: >"$RECORDS"
say() { printf '%s\n' "$*" | tee -a "$REPORT"; }

# Three free ports in a row on this computer's loopback, from 18300.
BASE=$(python3 -I - <<'PY'
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
)
PROXY_PORT=$BASE
PAC_URL="http://$HOST:$((BASE + 1))/proxy.pac"
DIRECT_URL="http://$HOST:$((BASE + 2))/direct"
# A self-signed certificate for the recorder's TLS after a CONNECT, which the fixture refuses: made for this run.
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 1 -subj "/CN=$INNER" \
    -keyout "$OUT/tls/key.pem" -out "$OUT/tls/cert.pem" >/dev/null 2>&1
python3 -I "$ROOT/scripts/proxy-measure/recorder.py" "$BASE" "$RECORDS" "$OUT/tls/cert.pem" "$OUT/tls/key.pem" tunnel \
    >"$OUT/recorder.out" 2>&1 &
RECORDER=$!
for _ in $(seq 20); do grep -qx ready "$OUT/recorder.out" 2>/dev/null && break; sleep 0.5; done
grep -qx ready "$OUT/recorder.out" || { echo "the recorder did not start" >&2; kill "$RECORDER"; exit 1; }
# The device's whole log as it comes, which a clear of its buffer does not cut short.
adb logcat -c
adb logcat -v threadtime >"$STREAM" 2>/dev/null &
STREAMER=$!

OWNER_SET=""
DATA_OFF=""
EGRESS_SET=""
# Pass 5's rules: every connection out of the emulator rejected but those on the loopback, into the VPN's interface and
# to the recorder's proxy. Inserted first in OUTPUT, ahead of Android's own chains, and taken out again.
egress_rules() {
    local op=$1
    adb shell iptables "$op" OUTPUT -o lo -j ACCEPT
    adb shell iptables "$op" OUTPUT -o tun+ -j ACCEPT
    adb shell iptables "$op" OUTPUT -d "$HOST" -p tcp --dport "$PROXY_PORT" -j ACCEPT
    adb shell iptables "$op" OUTPUT -j REJECT
    adb shell ip6tables "$op" OUTPUT -o lo -j ACCEPT
    adb shell ip6tables "$op" OUTPUT -o tun+ -j ACCEPT
    adb shell ip6tables "$op" OUTPUT -j REJECT
}
egress_only_proxy() {
    # Inserted in reverse, each at the head, so that they run in the order above.
    adb shell iptables -I OUTPUT 1 -j REJECT
    adb shell iptables -I OUTPUT 1 -d "$HOST" -p tcp --dport "$PROXY_PORT" -j ACCEPT
    adb shell iptables -I OUTPUT 1 -o tun+ -j ACCEPT
    adb shell iptables -I OUTPUT 1 -o lo -j ACCEPT
    adb shell ip6tables -I OUTPUT 1 -j REJECT
    adb shell ip6tables -I OUTPUT 1 -o tun+ -j ACCEPT
    adb shell ip6tables -I OUTPUT 1 -o lo -j ACCEPT
    EGRESS_SET=1
}
egress_back() {
    egress_rules -D >/dev/null 2>&1
    EGRESS_SET=""
}
cleanup() {
    local status=$?
    set +e
    [ -z "$EGRESS_SET" ] || egress_back
    adb shell settings delete global http_proxy >/dev/null 2>&1
    if [ -n "$OWNER_SET" ]; then
        owner global-none >/dev/null 2>&1
        owner wifi-none >/dev/null 2>&1
        wifi_again >/dev/null 2>&1
        adb shell dpm remove-active-admin "$OWNER/.OwnerReceiver" >/dev/null 2>&1
    fi
    [ -z "$DATA_OFF" ] || adb shell svc data enable >/dev/null 2>&1
    adb shell am force-stop "$PKG" >/dev/null 2>&1
    for app in "$FIXTURE" "$OUTSIDE" "$OWNER"; do adb uninstall "$app" >/dev/null 2>&1; done
    kill "$RECORDER" "$STREAMER" 2>/dev/null
    wait "$RECORDER" "$STREAMER" 2>/dev/null
    [ "$status" = 0 ] || echo "the measurement stopped early; what it saw is in $REPORT" >&2
}
trap cleanup EXIT

# The lines an app of ours logged under tag $1 since the log was cleared.
lines_of() { adb logcat -d -s "$1" | tr -d '\r' | sed -n "s/.*$1: //p"; }
# Starts app $1's activity $2 with the action $3 and the extras after it, and waits for "done" under tag $4; prints
# the action's line.
run_app() {
    local package=$1 activity=$2 action=$3 tag=$4
    shift 4
    adb logcat -c
    adb shell am start -W -n "$package/$activity" --es action "$action" "$@" >/dev/null
    for _ in $(seq 1 60); do
        grep -qx done <<<"$(lines_of "$tag")" && break
        sleep 0.5
    done
    local line
    line=$(lines_of "$tag" | grep -E "^$action (ok|failed)" | tail -1 || true)
    echo "${line:-$action no-answer}"
}
owner() { run_app "$OWNER" "$OWNER.OwnerActivity" "$1" DatapavanProxyOwner "${@:2}"; }
# The fixture under package $1 (fresh: its process stopped first, unless $2 is "live"), action $3, extras after it.
fixture_as() {
    local package=$1 fresh=$2 action=$3
    shift 3
    [ "$fresh" = live ] || adb shell am force-stop "$package"
    run_app "$package" "$FIXTURE.ProxyActivity" "$action" DatapavanProxyFixture "$@"
}

# The networks as ConnectivityService holds them: the default, each network's kind, the VPN's underlying networks and
# UID ranges, and the Wi-Fi link's own proxy.
network_state() {
    local dc kinds
    dc=$(adb shell dumpsys connectivity | tr -d '\r')
    kinds=$(grep -oE 'NetworkAgentInfo\{network\{[0-9]+\} +handle\{[0-9]+\} +ni\{[A-Z_]+' <<<"$dc" |
        sed -E 's/.*network\{([0-9]+)\}.*ni\{([A-Z_]+)$/\1:\2/' | sort -u | tr '\n' ' ' || true)
    printf 'default=%s networks=%s' "$(sed -n 's/^Active default network: //p' <<<"$dc" | head -1)" "$kinds"
    printf 'vpn=%s ' "$(grep -m1 -E '^ *NetworkAgentInfo\{.*InterfaceName: tun0 ' <<<"$dc" |
        grep -oE 'UnderlyingNetworks: \[[^]]*\]|Uids: <[^>]*>' | tr '\n' ' ')"
    printf 'wifi-link-proxy=%s\n' "$(wifi_link_proxy "$dc")"
}
# The Wi-Fi network's link's own proxy as ConnectivityService holds it, from the dump $1: each network is one line
# (a bounded repetition across these long lines took grep half a minute, dp-api35-ci, 2026-11-24).
wifi_link_proxy() {
    grep -m1 -E '^ *NetworkAgentInfo\{.*InterfaceName: wlan0 ' <<<"$1" | grep -oE 'HttpProxy: \[[^]]*\]( [0-9]+)?' |
        head -1 | sed 's/^HttpProxy: //' || true
}
# The framework's PAC pieces now: the handler's process and the ports it listens on (from /proc/net/tcp, by its UID),
# and whether the PAC processor's service is bound.
pac_state() {
    local ports="" line port
    while read -r line; do
        port=${line#*:}
        ports="$ports $((16#$port))"
    done < <(adb shell cat /proc/net/tcp /proc/net/tcp6 | tr -d '\r' | awk -v uid="$HANDLER_UID" '$4 == "0A" && $8 == uid { print $2 }')
    printf 'handler-pid=%s handler-listens=%s pacprocessor-bound=%s\n' \
        "$(adb shell pidof com.android.proxyhandler | tr -d '\r')" "${ports# }" \
        "$(adb shell dumpsys activity services com.android.pacprocessor | tr -d '\r' | grep -c 'ServiceRecord{' || true)"
}

dump() { adb shell dumpsys activity service "$PKG/org.visadahyu.datapavan.network.NetworkVpnService" "$@" | tr -d '\r'; }
uid_of() { adb shell cmd package list packages -U "$1" | tr -d '\r' | sed -n "s/^package:$1 uid:\([0-9]*\)$/\1/p"; }
vpn_up() {
    local uid
    uid=$(uid_of "$PKG")
    [ -n "$uid" ] && grep -qE "OwnerUid: $uid " <<<"$(adb shell dumpsys connectivity | tr -d '\r')"
}
vpn_down() { ! vpn_up; }
wifi_connected() { adb shell cmd wifi status | tr -d '\r' | grep -q 'Wifi is connected to "AndroidWifi"'; }
wifi_default() {
    local dc default
    dc=$(adb shell dumpsys connectivity | tr -d '\r')
    default=$(sed -n 's/^Active default network: //p' <<<"$dc" | head -1)
    [ -n "$default" ] && grep -qE "network\{$default\} +handle\{[0-9]+\} +ni\{WIFI" <<<"$dc"
}
# Wi-Fi off and on, so that the saved network's proxy reaches its link (a change alone left the link as it was,
# dp-api35-ci, 2026-11-24), and back on the network as the default.
wifi_again() {
    adb shell svc wifi disable
    sleep 2
    adb shell svc wifi enable
    within 60 wifi_connected || return 1
    within 30 wifi_default || return 1
    sleep 3
}

VPN=off
flows_now() { if [ "$VPN" = on ]; then dump | sed -n 's/^ *flow //p' | sort -u; fi; }
proxies_now() { if [ "$VPN" = on ]; then dump | sed -n 's/^ *flow-proxy //p' | sort -u; fi; }
FLOWS_BEFORE=""
PROXIES_BEFORE=""
RECORDS_BEFORE=0
STREAM_BEFORE=0
mark() {
    FLOWS_BEFORE=$(flows_now)
    PROXIES_BEFORE=$(proxies_now)
    RECORDS_BEFORE=$(wc -l <"$RECORDS")
    STREAM_BEFORE=$(wc -l <"$STREAM")
}
# What arrived since the mark: the recorder's lines; Android's own lines about a PAC, its handler, proxies and local
# network access; and with the VPN on, the network part's new flows of the UIDs that matter here or to the recorder's
# ports, and its new proxied flows (keyed by protocol, the app's address and the destination).
since_mark() {
    kill -0 "$RECORDER" 2>/dev/null || { echo "the recorder stopped" >&2; exit 1; }
    tail -n +"$((RECORDS_BEFORE + 1))" "$RECORDS" |
        awk -F'\t' '{ printf "    recorder: %s %s | host %s | ua %s\n", $2, $3, $4, substr($5, 1, 100) }'
    tail -n +"$((STREAM_BEFORE + 1))" "$STREAM" | tr -d '\r' |
        grep -E 'PacProxy|PacManager|PacService|PacNative|ProxyServer|ProxyService|ProxySelector|pacprocessor|proxyhandler|Error resolving PAC|LOCAL_NETWORK|LocalNetwork|local network|avc: .*(pac|proxy)' |
        grep -vE 'DatapavanProxy|am_|ActivityManager: (Start|Force|Killing)|ActivityTaskManager' | cut -c1-220 | tail -12 | sed 's/^/    android: /' || true
    [ "$VPN" = on ] || return 0
    local uids="$FIXTURE_UID|$OUTSIDE_UID|$HANDLER_UID|$PAC_UID|1000|0"
    awk 'NR == FNR { seen[$1 " " $2 " " $3] = 1; next } !seen[$1 " " $2 " " $3]' <(printf '%s\n' "$FLOWS_BEFORE") <(flows_now) |
        grep -E "^[a-z]+ [^ ]+ (${HOST//./\\.}:($BASE|$((BASE + 1))|$((BASE + 2))) [^ ]+|[^ ]+ ($uids)) " | sed 's/^/    flow: /' || true
    awk 'NR == FNR { seen[$1 " " $2 " " $3] = 1; next } !seen[$1 " " $2 " " $3]' <(printf '%s\n' "$PROXIES_BEFORE") <(proxies_now) |
        sed 's/^/    flow-proxy: /' || true
}
step() {
    local what=$1
    shift
    mark
    say "  $what: $("$@")"
    sleep 2
    since_mark | tee -a "$REPORT"
}

say "== Measurements 7.1 and 7.2 (part one) on $(adb shell getprop ro.product.model | tr -d '\r'), Android $(adb shell getprop ro.build.version.release | tr -d '\r') (API $SDK_INT), build $(adb shell getprop ro.build.fingerprint | tr -d '\r')"
say "   recorder on this computer's loopback: proxy $HOST:$PROXY_PORT, PAC $PAC_URL, direct target $DIRECT_URL"

"$ROOT/scripts/proxy-fixture/build.sh" >/dev/null
"$ROOT/scripts/proxy-owner/build.sh" >/dev/null 2>&1
adb install -r "$APK" >/dev/null
adb shell pm clear "$PKG" >/dev/null
for app in "$FIXTURE" "$OUTSIDE"; do adb uninstall "$app" >/dev/null 2>&1 || true; done
adb install "$ROOT/build/proxy-fixture/proxy-fixture.apk" >/dev/null
adb install "$ROOT/build/proxy-fixture/proxy-fixture-outside.apk" >/dev/null
# The second copy left out of the tunnel, as the network screen's choice stores it (ADR 0041), before the network part
# first starts.
printf '%s\n' "<?xml version='1.0' encoding='utf-8' standalone='yes' ?>" '<map>' '    <set name="apps">' \
    "        <string>$OUTSIDE</string>" '    </set>' '</map>' >"$OUT/left_out.xml"
adb shell "run-as $PKG sh -c 'mkdir -p shared_prefs && cat > shared_prefs/left_out.xml'" <"$OUT/left_out.xml"
grep -q "$OUTSIDE" <<<"$(adb shell run-as "$PKG" cat shared_prefs/left_out.xml | tr -d '\r')" ||
    { echo "the left-out app was not stored" >&2; exit 1; }
adb shell dpm remove-active-admin "$OWNER/.OwnerReceiver" >/dev/null 2>&1 || true
adb uninstall "$OWNER" >/dev/null 2>&1 || true
adb install -t "$ROOT/build/proxy-owner/proxy-owner.apk" >/dev/null
adb shell dpm set-device-owner "$OWNER/.OwnerReceiver" >/dev/null ||
    { echo "Android refused the device owner (an account, or not a fresh emulator?)" >&2; exit 1; }
OWNER_SET=1
adb shell pm grant "$OWNER" android.permission.ACCESS_FINE_LOCATION
adb shell cmd location set-location-enabled true >/dev/null 2>&1 || true
[ "$SDK_INT" -lt 37 ] || adb shell pm grant "$PKG" android.permission.ACCESS_LOCAL_NETWORK
adb shell svc data disable
DATA_OFF=1
within 30 wifi_default || { echo "Wi-Fi is not the default network with mobile data off" >&2; exit 1; }
FIXTURE_UID=$(uid_of "$FIXTURE")
OUTSIDE_UID=$(uid_of "$OUTSIDE")
HANDLER_UID=$(uid_of com.android.proxyhandler)
PAC_UID=$(uid_of com.android.pacprocessor)
say "   UIDs: fixture $FIXTURE_UID, the copy left out $OUTSIDE_UID, com.android.proxyhandler ${HANDLER_UID:-none}, com.android.pacprocessor ${PAC_UID:-none}, system 1000, Datapavan Advanced $(uid_of "$PKG"), owner $(uid_of "$OWNER")"
say "   targets: proxyhandler $(adb shell dumpsys package com.android.proxyhandler | tr -d '\r' | grep -m1 -oE 'targetSdk=[0-9]+'), its local network permission: $(adb shell dumpsys package com.android.proxyhandler | tr -d '\r' | grep -m1 -oE 'android.permission.ACCESS_LOCAL_NETWORK[^,]*' || echo none listed)"
say "   WebView: $(adb shell dumpsys webviewupdate | tr -d '\r' | grep -m1 -E 'Current WebView package' | sed 's/^ *//')"
say "   owner: $(owner state)"
say "   Private DNS: $(adb shell settings get global private_dns_mode | tr -d '\r'), mobile data off"

set_setting() {
    case $1 in
        none) echo "nothing set" ;;
        wifi-proxy)
            owner wifi-proxy --es host "$HOST" --es port "$PROXY_PORT"
            wifi_again
            ;;
        wifi-pac)
            owner wifi-pac --es url "$PAC_URL"
            wifi_again
            ;;
        global-setting)
            adb shell settings put global http_proxy "$HOST:$PROXY_PORT"
            echo "settings put global http_proxy $HOST:$PROXY_PORT"
            ;;
        global-owner) owner global-proxy --es host "$HOST" --es port "$PROXY_PORT" ;;
        global-pac) owner global-pac --es url "$PAC_URL" ;;
    esac
}
clear_setting() {
    case $1 in
        none) ;;
        wifi-proxy | wifi-pac)
            owner wifi-none >/dev/null
            wifi_again
            ;;
        global-setting)
            adb shell settings put global http_proxy :0
            adb shell settings delete global http_proxy >/dev/null
            ;;
        global-owner | global-pac) owner global-none >/dev/null ;;
    esac
    sleep 2
}
vpn_start() {
    allow_vpn "$PKG" || { echo "Android did not take the VPN consent for $PKG" >&2; exit 1; }
    adb shell am force-stop "$PKG"
    adb shell am start -W -n "$PKG/$NETWORK_SCREEN" --ez start true >/dev/null
    within 30 vpn_up || { echo "the network part's tunnel did not come up" >&2; exit 1; }
    adb shell input keyevent KEYCODE_HOME
    VPN=on
    sleep 3
}
vpn_stop() {
    adb shell am force-stop "$PKG"
    within 20 vpn_down || { echo "the network part's tunnel did not go down" >&2; exit 1; }
    VPN=off
    sleep 2
}

# One setting measured: $1 the setting, $2 "set" to set it now (and take it away after), or "preset" where it was set
# before the VPN started.
measure() {
    local setting=$1 how=$2
    say ""
    say "-- VPN $VPN, setting $setting ($how)"
    local row_records
    row_records=$(wc -l <"$RECORDS")
    [ "$VPN" != on ] || dump dns-times-clear >/dev/null
    if [ "$how" = set ]; then
        # A process of the fixture that runs while the setting changes.
        fixture_as "$FIXTURE" fresh read >/dev/null
        mark
        say "  set: $(set_setting "$setting")"
        # A PAC file is fetched once it is set: up to 20 s for the recorder to see it.
        if [[ $setting == *pac ]]; then
            for _ in $(seq 1 20); do
                tail -n +"$((RECORDS_BEFORE + 1))" "$RECORDS" | grep -q $'\tpac\t' && break
                sleep 1
            done
        fi
        sleep 3
        since_mark | tee -a "$REPORT"
    fi
    say "  networks: $(network_state)"
    say "  PAC pieces: $(pac_state)"
    say "  owner: $(owner state)"
    [ "$how" != set ] || step "read (a process running across the change)" fixture_as "$FIXTURE" live read
    step read fixture_as "$FIXTURE" fresh read
    step "get http" fixture_as "$FIXTURE" fresh get --es url "http://$INNER/get"
    step "get https" fixture_as "$FIXTURE" fresh get --es url "https://$INNER/get"
    step "get the direct target" fixture_as "$FIXTURE" fresh get --es url "$DIRECT_URL"
    step property fixture_as "$FIXTURE" fresh property --es url "http://$INNER/property"
    step "property, the direct target" fixture_as "$FIXTURE" fresh property --es url "$DIRECT_URL"
    step webview fixture_as "$FIXTURE" fresh webview --es url "http://$INNER/webview"
    step "forward to the recorder's proxy, the app's own choice" fixture_as "$FIXTURE" fresh forward --es host "$HOST" --es port "$PROXY_PORT"
    if [ "$VPN" = on ] && [[ $setting == wifi-* || $setting == none ]]; then
        step "left out: read" fixture_as "$OUTSIDE" fresh read
        step "left out: get http" fixture_as "$OUTSIDE" fresh get --es url "http://$INNER/get"
        step "left out: get the direct target" fixture_as "$OUTSIDE" fresh get --es url "$DIRECT_URL"
        step "left out: property" fixture_as "$OUTSIDE" fresh property --es url "http://$INNER/property"
        step "left out: webview" fixture_as "$OUTSIDE" fresh webview --es url "http://$INNER/webview"
    fi
    say "  PAC pieces after: $(pac_state)"
    if [ "$VPN" = on ]; then
        # A name no cache holds, so that the part has at least one exchange of the resolver's own: the fixture's names
        # are cached from the part before, and through a global proxy apps look no name up at all.
        step "a lookup of a name no cache holds" fixture_as "$FIXTURE" fresh lookup --es name "r$(date +%s%N).example.com"
        resolver_evidence "$row_records"
    fi
    [ "$how" != set ] || clear_setting "$setting"
}

# What the network part's resolver did in a setting's part, since the recorder's line $1: the proxy it follows and why,
# the way it is on, the exchanges that answered by each way, and the recorder's CONNECTs to an address on port 443, the
# resolver's form, with no User-Agent and with one.
resolver_evidence() {
    local from=$1 state
    state=$(dump dns-proxy)
    say "  resolver: proxy $(sed -n 's/^ *dns-proxy //p' <<<"$state" | head -1); way $(sed -n 's/^ *dns-way //p' <<<"$state" | head -1)"
    say "  resolver's answers by way: $(sed -n 's/^ *dns-latency \([^ ]*\) \([0-9]*\) .*/\1=\2/p' <<<"$state" | tr '\n' ' ')"
    say "  resolver's CONNECTs by address: $(tail -n +"$((from + 1))" "$RECORDS" | awk -F'\t' '
        $2 == "proxy" && $3 ~ /^CONNECT (\[[0-9a-fA-F:.]+\]|[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+):443 HTTP/ { if ($5 == "-") bare++; else named++ }
        $2 == "proxy-tunnel" && $3 ~ / open$/ { open++ }
        END { printf "%d with no User-Agent, %d with one, %d tunnels opened", bare, named, open }')"
}

SETTINGS="none wifi-proxy wifi-pac global-setting global-owner global-pac"
for pass in ${PASSES:-1 2 3 4}; do
    case $pass in
        1)
            say ""
            say "== pass 1: the VPN off"
            for setting in $SETTINGS; do measure "$setting" set; done
            ;;
        2)
            say ""
            say "== pass 2: the Wi-Fi network's own setting made first, then the VPN started"
            for setting in wifi-proxy wifi-pac; do
                say ""
                say "  set before the VPN: $(set_setting "$setting")"
                vpn_start
                measure "$setting" preset
                vpn_stop
                clear_setting "$setting"
            done
            ;;
        3)
            say ""
            say "== pass 3: the VPN on while each setting changes"
            vpn_start
            for setting in $SETTINGS; do measure "$setting" set; done
            vpn_stop
            ;;
        5)
            say ""
            say "== pass 5: a network that requires its proxy: the Wi-Fi network's own proxy set, the VPN on, every connection out rejected but to the proxy"
            adb root >/dev/null 2>&1 || true
            adb wait-for-device
            [ "$(adb shell id -u | tr -d '\r')" = 0 ] || { echo "pass 5 needs an emulator that adb root takes" >&2; exit 2; }
            say "  set before the VPN: $(set_setting wifi-proxy)"
            vpn_start
            egress_only_proxy
            say "  egress: only to $HOST:$PROXY_PORT, the loopback and the VPN's interface"
            measure wifi-proxy preset
            egress_back
            vpn_stop
            clear_setting wifi-proxy
            ;;
        4)
            # Android tells a process its proxy when it starts and on a change of the proxy setting, by the UID's
            # network then; the VPN starting is no such change. So a process that started before the VPN, with the
            # Wi-Fi network's own setting, may keep using it inside the tunnel.
            say ""
            say "== pass 4: a process of the fixture that started before the VPN, the Wi-Fi network's own setting made first"
            for setting in wifi-proxy wifi-pac; do
                say ""
                say "-- setting $setting, made with the VPN off: $(set_setting "$setting")"
                step "read, the VPN off (starts the process)" fixture_as "$FIXTURE" fresh read
                say "  the fixture's process: $(adb shell pidof "$FIXTURE" | tr -d '\r')"
                vpn_start
                say "  networks: $(network_state)"
                step "read, the same process, the VPN on" fixture_as "$FIXTURE" live read
                step "get http, the same process" fixture_as "$FIXTURE" live get --es url "http://$INNER/get"
                step "get https, the same process" fixture_as "$FIXTURE" live get --es url "https://$INNER/get"
                step "get the direct target, the same process" fixture_as "$FIXTURE" live get --es url "$DIRECT_URL"
                step "webview, the same process" fixture_as "$FIXTURE" live webview --es url "http://$INNER/webview"
                say "  the fixture's process: $(adb shell pidof "$FIXTURE" | tr -d '\r')"
                step "read, a fresh process" fixture_as "$FIXTURE" fresh read
                step "get http, a fresh process" fixture_as "$FIXTURE" fresh get --es url "http://$INNER/get"
                vpn_stop
                clear_setting "$setting"
            done
            ;;
    esac
done
say ""
say "== done; the recorder's own log: $RECORDS; the device's log: $STREAM"
