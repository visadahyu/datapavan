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
# every connection out but to the recorder's proxy, so that the network part's resolver answers only through it. A
# sixth, PASSES=6, on the same kind of emulator, is that network with the global proxy alone: no proxy of the Wi-Fi
# network's own, the global proxy set by `settings put global http_proxy` before the VPN starts, so that the resolver
# answers only through the global proxy, its second way where the network has none (the maintainer's decision of
# 2026-11-25, R-PLAN.md). Pass 3's global rows show the same choice made again on a change of the global proxy. A
# seventh, PASSES=7, on the same kind of emulator, is an open network with the global proxy alone and one server down:
# the first ODoH pair's relay's addresses (data/odoh) refused at the connection, every other connection out allowed, so
# that the resolver, which takes the global proxy only once direct connections to two servers failed with none made
# since (the global proxy's review, M1), sends it nothing.
#
# The resolver unit (the strategy repository's research/2026-11-proxy-record/R-PLAN.md, "After the audit", M8): with
# the VPN on, each setting's part ends with what the network part's resolver did in it, as positive evidence, never as
# an absence: the proxy it follows, `network` or `global`, or why none (the dump's `dns-proxy`), the exchanges that
# answered by each way since the part began (`dns-latency`, cleared at its start), and the recorder's CONNECTs to an
# address on port 443, by User-Agent. The resolver sends those by the data pack's address with no User-Agent; the recorder carries them to that
# address from this computer (its `tunnel` mode), so that no hold of the resolver's comes from the proxy's path, and
# answers every CONNECT to a name as before.
#
# The engine's way through the network's own proxy (the strategy repository's research/2026-11-proxy-record/S2-PLAN.md,
# section 8, and its audit's M4 and M8): each part also gets public targets, which the engine may carry through the
# proxy, where the recorder's address 10.0.2.2 is on-link and rightly never is: example.com (RFC 2606) over https and
# http by name, and over http by the address the fixture's lookup gave, each timed; with the VPN on, each part says the
# dump's `beneath-proxy` line, the network beneath's prefixes (`proxy-on-link`), what "Now" holds of Android's settings
# (`proxy-context`) and, at its end, "Now"'s own lines about a proxy, read off the screen; and each step the routes the
# engine's kept flows took by app (`flow-route`, `network-proxy` the way through the proxy). The recorder carries a
# CONNECT to a public address on port 443 or 80 (its `tunnel` mode), counting the bytes each way. Pass 5 with
# PASS5_DROP=1 drops what it otherwise rejects, for the cost of the direct share before the proxy, timed over three
# servers and again once the proxy came first. Pass 3 ends with a Wi-Fi proxy and the global setting together, and on
# Android 17 and later with the local network grant revoked (`local-no-grant`). PASSES=8, on an emulator that `adb
# root` takes, is pass 5's network with the unit's rows: the recorder refusing the target's address with 407 (a
# password) and with 403 (names only), an exclusion list naming a target, tracker blocking with a blocked lookup and a
# blocked hello through the proxy, a chained app (with CHAIN_SOCKS=host:port:user:password, a SOCKS5 proxy as the
# chain's tool, the proxy lab's), and the proxy removed while the VPN runs. On Android 17 and later, each part also has
# a copy of the fixture that targets API 37 (M5) fetch the public target and the direct target. SETTINGS names the
# settings that passes 1 and 3 go through; MEASURE_NAME, a word, starts the output's names, so that two runs (a build
# before and one after) can go side by side.
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
TARGET37=$FIXTURE.target37
# The public targets (RFC 2606's names), which only the engine's way through the proxy reaches on pass 5's network:
# three servers at addresses of their own, for the order the engine learns.
PUBLIC=example.com
PUBLIC_MORE="example.net example.org"
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
mkdir -p "$OUT"
RUN="${MEASURE_NAME:+$MEASURE_NAME-}api$SDK_INT${PASSES:+-passes-${PASSES// /}}${PASS5_DROP:+-drop}"
REPORT="$OUT/$RUN.txt"
RECORDS="$OUT/$RUN-recorder.tsv"
STREAM="$OUT/$RUN-logcat.txt"
# The recorder's mode for the part, read at each request: its word and the addresses it names.
MODE_FILE="$OUT/$RUN-mode"
: >"$REPORT"
: >"$RECORDS"
echo tunnel >"$MODE_FILE"
recorder_mode() { printf '%s\n' "$*" >"$MODE_FILE"; }
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
TLS="$OUT/$RUN-tls"
mkdir -p "$TLS"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 1 -subj "/CN=$INNER" \
    -keyout "$TLS/key.pem" -out "$TLS/cert.pem" >/dev/null 2>&1
python3 -I "$ROOT/scripts/proxy-measure/recorder.py" "$BASE" "$RECORDS" "$TLS/cert.pem" "$TLS/key.pem" tunnel "$MODE_FILE" \
    >"$OUT/$RUN-recorder.out" 2>&1 &
RECORDER=$!
for _ in $(seq 20); do grep -qx ready "$OUT/$RUN-recorder.out" 2>/dev/null && break; sleep 0.5; done
grep -qx ready "$OUT/$RUN-recorder.out" || { echo "the recorder did not start" >&2; kill "$RECORDER"; exit 1; }
# The device's whole log as it comes, which a clear of its buffer does not cut short.
adb logcat -c
adb logcat -v threadtime >"$STREAM" 2>/dev/null &
STREAMER=$!

OWNER_SET=""
DATA_OFF=""
EGRESS_SET=""
DOWN=""
CHAINED=""
BLOCKING_ON=""
# Pass 5's rules: every connection out of the emulator rejected (dropped, with PASS5_DROP=1) but those on the loopback,
# into the VPN's interface, to the recorder's proxy and to the ports of EGRESS_ALSO on this computer (pass 8's chain).
# Inserted first in OUTPUT, ahead of Android's own chains, and taken out again.
EGRESS_END=REJECT
[ -z "${PASS5_DROP:-}" ] || EGRESS_END=DROP
EGRESS_ALSO=""
egress_rules() {
    local op=$1 port
    adb shell iptables "$op" OUTPUT -o lo -j ACCEPT
    adb shell iptables "$op" OUTPUT -o tun+ -j ACCEPT
    for port in "$PROXY_PORT" $EGRESS_ALSO; do adb shell iptables "$op" OUTPUT -d "$HOST" -p tcp --dport "$port" -j ACCEPT; done
    adb shell iptables "$op" OUTPUT -j "$EGRESS_END"
    adb shell ip6tables "$op" OUTPUT -o lo -j ACCEPT
    adb shell ip6tables "$op" OUTPUT -o tun+ -j ACCEPT
    adb shell ip6tables "$op" OUTPUT -j "$EGRESS_END"
}
egress_only_proxy() {
    local port
    # Inserted in reverse, each at the head, so that they run in the order above.
    adb shell iptables -I OUTPUT 1 -j "$EGRESS_END"
    for port in $EGRESS_ALSO "$PROXY_PORT"; do adb shell iptables -I OUTPUT 1 -d "$HOST" -p tcp --dport "$port" -j ACCEPT; done
    adb shell iptables -I OUTPUT 1 -o tun+ -j ACCEPT
    adb shell iptables -I OUTPUT 1 -o lo -j ACCEPT
    adb shell ip6tables -I OUTPUT 1 -j "$EGRESS_END"
    adb shell ip6tables -I OUTPUT 1 -o tun+ -j ACCEPT
    adb shell ip6tables -I OUTPUT 1 -o lo -j ACCEPT
    EGRESS_SET=1
}
egress_back() {
    egress_rules -D >/dev/null 2>&1
    EGRESS_SET=""
}
# Pass 7's server down: each of the first ODoH pair's relay's addresses, as data/odoh gives them, refused at the
# connection by a TCP reset; "-D" takes the rules out again.
DOWN_ADDRESSES=""
down_rules() {
    local op=$1 address
    for address in ${DOWN_ADDRESSES//,/ }; do
        if [[ $address == *:* ]]; then
            adb shell ip6tables "$op" OUTPUT -d "$address" -p tcp -j REJECT --reject-with tcp-reset
        else
            adb shell iptables "$op" OUTPUT -d "$address" -p tcp -j REJECT --reject-with tcp-reset
        fi
    done
}
DOWN_RELAY=""
# Not in a subshell: what it sets is what server_back and the clean-up take out.
server_down() {
    DOWN_RELAY=$(awk -F'\t' '!/^#/ && NF >= 2 { print $1; exit }' "$ROOT/data/odoh/pairs.tsv")
    DOWN_ADDRESSES=$(awk -F'\t' -v id="$DOWN_RELAY" '!/^#/ && $1 == id { print $3 ($4 == "-" ? "" : "," $4) }' "$ROOT/data/odoh/relays.tsv")
    [ -n "$DOWN_ADDRESSES" ] || { echo "no addresses for the relay $DOWN_RELAY in data/odoh" >&2; exit 1; }
    DOWN=1
    down_rules -I
}
server_back() {
    down_rules -D >/dev/null 2>&1
    DOWN=""
}
# Android's global proxy taken away whole (the global proxy's review, m5): Android reads `http_proxy` only when it is
# not empty, so `:0` first, which clears the proxy it holds, whoever set it; then every setting it keeps one in.
clear_global_proxy() {
    local key
    adb shell settings put global http_proxy :0
    for key in http_proxy global_http_proxy_host global_http_proxy_port global_http_proxy_exclusion_list global_http_proxy_pac; do
        adb shell settings delete global "$key" >/dev/null
    done
}
cleanup() {
    local status=$?
    set +e
    [ -z "$EGRESS_SET" ] || egress_back
    [ -z "$DOWN" ] || server_back
    clear_global_proxy >/dev/null 2>&1
    if [ -n "$OWNER_SET" ]; then
        owner global-none >/dev/null 2>&1
        owner wifi-none >/dev/null 2>&1
        wifi_again >/dev/null 2>&1
        adb shell dpm remove-active-admin "$OWNER/.OwnerReceiver" >/dev/null 2>&1
    fi
    [ -z "$DATA_OFF" ] || adb shell svc data enable >/dev/null 2>&1
    [ -z "$CHAINED" ] || dump unchain >/dev/null 2>&1
    [ -z "$BLOCKING_ON" ] || blocking_switch off >/dev/null 2>&1
    adb shell am force-stop "$PKG" >/dev/null 2>&1
    [ "$SDK_INT" -lt 37 ] || adb shell pm grant "$PKG" android.permission.ACCESS_LOCAL_NETWORK >/dev/null 2>&1
    for app in "$FIXTURE" "$OUTSIDE" "$TARGET37" "$OWNER"; do adb uninstall "$app" >/dev/null 2>&1; done
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
# The network part's whole dump, once a step, with the VPN on; nothing with it off.
state_now() { if [ "$VPN" = on ]; then dump; fi; }
flows_of() { sed -n 's/^ *flow //p' <<<"$1" | sort -u; }
proxies_of() { sed -n 's/^ *flow-proxy //p' <<<"$1" | sort -u; }
routes_of() { sed -n 's/^ *flow-route //p' <<<"$1"; }
FLOWS_BEFORE=""
PROXIES_BEFORE=""
ROUTES_BEFORE=""
RECORDS_BEFORE=0
STREAM_BEFORE=0
mark() {
    local state
    state=$(state_now)
    FLOWS_BEFORE=$(flows_of "$state")
    PROXIES_BEFORE=$(proxies_of "$state")
    ROUTES_BEFORE=$(routes_of "$state")
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
    local uids="$FIXTURE_UID|$OUTSIDE_UID|${TARGET37_UID:-$FIXTURE_UID}|$HANDLER_UID|$PAC_UID|1000|0" state
    state=$(state_now)
    awk 'NR == FNR { seen[$1 " " $2 " " $3] = 1; next } !seen[$1 " " $2 " " $3]' <(printf '%s\n' "$FLOWS_BEFORE") <(flows_of "$state") |
        grep -E "^[a-z]+ [^ ]+ (${HOST//./\\.}:($BASE|$((BASE + 1))|$((BASE + 2))) [^ ]+|[^ ]+ ($uids)) " | sed 's/^/    flow: /' || true
    awk 'NR == FNR { seen[$1 " " $2 " " $3] = 1; next } !seen[$1 " " $2 " " $3]' <(printf '%s\n' "$PROXIES_BEFORE") <(proxies_of "$state") |
        sed 's/^/    flow-proxy: /' || true
    # The ways the engine's kept flows went, by app, where a count of the fixtures' grew: `network-proxy` is the network's
    # own proxy (the unit S2).
    awk -v uids="^($FIXTURE_UID|$OUTSIDE_UID|${TARGET37_UID:-$FIXTURE_UID})$" 'NR == FNR { had[$1 " " $2] = $3; next }
        $1 ~ uids && $3 + 0 > had[$1 " " $2] + 0 { printf "    flow-route: %s %s %d -> %d\n", $1, $2, had[$1 " " $2], $3 }' \
        <(printf '%s\n' "$ROUTES_BEFORE") <(routes_of "$state") || true
}
step() {
    local what=$1
    shift
    mark
    say "  $what: $("$@")"
    sleep 2
    since_mark | tee -a "$REPORT"
}

# The engine's way through the network's own proxy (the unit S2), with the VPN on: the dump's `beneath-proxy` line
# (none from a build before the unit), the network beneath's prefixes as the engine has them, and what "Now" holds of
# Android's settings.
beneath_state() {
    local state line
    state=$(dump beneath-proxy)
    line=$(sed -n 's/^ *beneath-proxy //p' <<<"$state" | head -1)
    printf 'beneath-proxy %s; on-link %s; %s\n' "${line:-(no such line: a build before the unit)}" \
        "$(sed -n 's/^ *proxy-on-link //p' <<<"$state" | head -1)" "$(grep -m1 -oE 'proxy-context .*' <<<"$state" || echo 'proxy-context (none)')"
}
# "Now"'s own lines about a proxy or the local network, off the screen, one a line: the screen opened on "Now", read
# from the top and half a page down, and left at home again.
now_lines() {
    local dump_file="$OUT/$RUN-now.xml" texts=""
    adb shell am start -n "$PKG/$NETWORK_SCREEN" --activity-clear-top --ez now true >/dev/null
    sleep 3
    if dump_screen && adb shell cat "$DUMP" >"$dump_file" 2>/dev/null; then
        texts=$(python3 -I "$ROOT/scripts/now-screen.py" "$dump_file" - | sed -n 's/^texts //p')
        swipe_up
        if dump_screen && adb shell cat "$DUMP" >"$dump_file.more" 2>/dev/null; then
            texts="$texts | $(python3 -I "$ROOT/scripts/now-screen.py" "$dump_file.more" - | sed -n 's/^texts //p')"
        fi
    fi
    adb shell input keyevent KEYCODE_HOME
    # The fixture's own label and package name are no line about a proxy.
    awk 'BEGIN { RS = " [|] " } { gsub(/\n/, " "); gsub(/^ +| +$/, "") } /[Pp]roxy|local network/ && !/proxyfixture|proxy fixture/ && !seen[$0]++ { print "    now: " $0 }' <<<"$texts" || true
}
# Tracker blocking turned on or off by its switch on the network screen ("Block trackers"), as verify-blocking.sh does,
# until the dump says so.
blocking_now() { dump | sed -n 's/^ *blocking \(on\|off\) .*/\1/p' | head -1; }
blocking_switch() {
    local want=$1
    if [ "$(blocking_now)" != "$want" ]; then
        adb shell am start -W -n "$PKG/$NETWORK_SCREEN" --activity-clear-top >/dev/null
        tap_text "Block trackers" >/dev/null || { echo "no switch \"Block trackers\""; return 1; }
        for _ in $(seq 1 15); do
            [ "$(blocking_now)" = "$want" ] && break
            sleep 1
        done
        adb shell input keyevent KEYCODE_HOME
    fi
    if [ "$want" = on ]; then BLOCKING_ON=1; else BLOCKING_ON=""; fi
    echo "blocking $(blocking_now)"
}
# The fixture's lookup of the name $1, inside the tunnel when it is up: the addresses, comma-separated, or nothing.
addresses_of() { fixture_as "$FIXTURE" fresh resolve --es name "$1" | sed -n 's/^resolve ok //p'; }
# The first IPv4 address of a comma-separated list.
first_v4() { tr ',' '\n' <<<"$1" | grep -m1 -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' || true; }
# The public target's steps, each timed: by name over https and http, and over http by the address the lookup gave; on
# Android 17 and later, the copy that targets API 37 to the public name and to the direct target.
public_steps() {
    local address
    address=$(first_v4 "$(addresses_of "$PUBLIC")")
    say "  the public target: $PUBLIC at ${address:-no address}"
    step "get the public name, https" fixture_as "$FIXTURE" fresh timed --es url "https://$PUBLIC/"
    step "get the public name, http" fixture_as "$FIXTURE" fresh timed --es url "http://$PUBLIC/"
    [ -z "$address" ] || step "get the public address, http" fixture_as "$FIXTURE" fresh timed --es url "http://$address/"
    if [ -n "$TARGET37_UID" ]; then
        step "target 37: get the public name, https" fixture_as "$TARGET37" fresh timed --es url "https://$PUBLIC/"
        step "target 37: get the direct target" fixture_as "$TARGET37" fresh timed --es url "$DIRECT_URL"
    fi
}

say "== Measurements 7.1 and 7.2 (part one) on $(adb shell getprop ro.product.model | tr -d '\r'), Android $(adb shell getprop ro.build.version.release | tr -d '\r') (API $SDK_INT), build $(adb shell getprop ro.build.fingerprint | tr -d '\r')"
say "   recorder on this computer's loopback: proxy $HOST:$PROXY_PORT, PAC $PAC_URL, direct target $DIRECT_URL"

# FIXTURES_BUILT=1 where they are built already: a second run beside a first must not remove them while it installs.
if [ -z "${FIXTURES_BUILT:-}" ]; then
    "$ROOT/scripts/proxy-fixture/build.sh" >/dev/null
    "$ROOT/scripts/proxy-owner/build.sh" >/dev/null 2>&1
fi
adb install -r "$APK" >/dev/null
adb shell pm clear "$PKG" >/dev/null
for app in "$FIXTURE" "$OUTSIDE" "$TARGET37"; do adb uninstall "$app" >/dev/null 2>&1 || true; done
adb install "$ROOT/build/proxy-fixture/proxy-fixture.apk" >/dev/null
adb install "$ROOT/build/proxy-fixture/proxy-fixture-outside.apk" >/dev/null
[ "$SDK_INT" -lt 37 ] || adb install "$ROOT/build/proxy-fixture/proxy-fixture-target37.apk" >/dev/null
# The second copy left out of the tunnel, as the network screen's choice stores it (ADR 0041), before the network part
# first starts.
printf '%s\n' "<?xml version='1.0' encoding='utf-8' standalone='yes' ?>" '<map>' '    <set name="apps">' \
    "        <string>$OUTSIDE</string>" '    </set>' '</map>' >"$OUT/$RUN-left_out.xml"
adb shell "run-as $PKG sh -c 'mkdir -p shared_prefs && cat > shared_prefs/left_out.xml'" <"$OUT/$RUN-left_out.xml"
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
TARGET37_UID=""
[ "$SDK_INT" -lt 37 ] || TARGET37_UID=$(uid_of "$TARGET37")
HANDLER_UID=$(uid_of com.android.proxyhandler)
PAC_UID=$(uid_of com.android.pacprocessor)
say "   UIDs: fixture $FIXTURE_UID, the copy left out $OUTSIDE_UID, the copy that targets API 37 ${TARGET37_UID:-none}, com.android.proxyhandler ${HANDLER_UID:-none}, com.android.pacprocessor ${PAC_UID:-none}, system 1000, Datapavan Advanced $(uid_of "$PKG"), owner $(uid_of "$OWNER")"
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
        # The unit S2's: the Wi-Fi network's proxy with an exclusion list naming a public target, and the Wi-Fi
        # network's proxy with the global setting beside it.
        wifi-excluding)
            owner wifi-proxy --es host "$HOST" --es port "$PROXY_PORT" --es exclusions "$EXCLUDED"
            wifi_again
            ;;
        wifi-and-global) echo "$(set_setting wifi-proxy); $(set_setting global-setting)" ;;
    esac
}
clear_setting() {
    case $1 in
        none) ;;
        wifi-proxy | wifi-pac | wifi-excluding)
            owner wifi-none >/dev/null
            wifi_again
            ;;
        global-setting) clear_global_proxy ;;
        global-owner | global-pac) owner global-none >/dev/null ;;
        wifi-and-global)
            clear_setting global-setting
            clear_setting wifi-proxy
            ;;
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
    [ "$VPN" != on ] || say "  engine: $(beneath_state)"
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
    public_steps
    say "  PAC pieces after: $(pac_state)"
    if [ "$VPN" = on ]; then
        say "  engine at the part's end: $(beneath_state)"
        now_lines | tee -a "$REPORT"
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

# The switch "Send apps through this proxy" under "Now"'s line about the network's proxy, a control of its own beside
# its words (its test tag), tapped once "Now" shows it.
through_switch() {
    adb shell am start -n "$PKG/$NETWORK_SCREEN" --activity-clear-top --ez now true >/dev/null
    sleep 3
    scroll_to "Send apps through this proxy" >/dev/null 2>&1 || return 1
    tap_id now-network-proxy-through || return 1
    sleep 3
}
# The unit S2's part on an open network: the Wi-Fi network's proxy set with the VPN on, and the user's switch "Send apps
# through this proxy" turned on in "Now", so that apps go through it though a direct connection works; then off again.
switch_part() {
    say ""
    say "-- VPN $VPN, setting wifi-proxy with the switch \"Send apps through this proxy\" (set)"
    mark
    say "  set: $(set_setting wifi-proxy)"
    sleep 3
    since_mark | tee -a "$REPORT"
    say "  engine: $(beneath_state)"
    if through_switch; then
        sleep 3
        adb shell input keyevent KEYCODE_HOME
        say "  the switch tapped on: $(beneath_state)"
        now_lines | tee -a "$REPORT"
        step "get the public name, https, the switch on" fixture_as "$FIXTURE" fresh timed --es url "https://$PUBLIC/"
        step "get the public name, http, the switch on" fixture_as "$FIXTURE" fresh timed --es url "http://$PUBLIC/"
        step "get the direct target, the switch on" fixture_as "$FIXTURE" fresh timed --es url "$DIRECT_URL"
        through_switch || say "  the switch could not be tapped off"
        adb shell input keyevent KEYCODE_HOME
        say "  the switch tapped off: $(beneath_state)"
        step "get the public name, https, the switch off" fixture_as "$FIXTURE" fresh timed --es url "https://$PUBLIC/"
    else
        adb shell input keyevent KEYCODE_HOME
        say "  \"Now\" shows no switch \"Send apps through this proxy\""
        now_lines | tee -a "$REPORT"
    fi
    clear_setting wifi-proxy
}

# Pass 5's order: each public server's first connection timed, then the first two again; the dump's line after each
# says whether the proxy came first by then (three servers that failed directly and opened through it, with no direct
# success between). With PASS5_DROP=1 each direct try waits out its share before the proxy. Then a WebView loads the
# public name (the audit's m8).
order_part() {
    local name
    say ""
    say "-- the engine's order on this network ($EGRESS_END for the rest): three servers, then the first two again"
    say "  engine: $(beneath_state)"
    for name in $PUBLIC $PUBLIC_MORE $PUBLIC ${PUBLIC_MORE%% *}; do
        step "timed https://$name/" fixture_as "$FIXTURE" fresh timed --es url "https://$name/"
        say "    engine: $(beneath_state | cut -d';' -f1)"
    done
    step "webview, the public name" fixture_as "$FIXTURE" fresh webview --es url "https://$PUBLIC/"
    say "  engine at the part's end: $(beneath_state)"
    now_lines | tee -a "$REPORT"
}

# Pass 8's rows (the unit S2's, M8), on pass 5's network, each with the recorder's lines and the engine's routes.
rows_s2() {
    local com net org com4 tunnels
    say ""
    say "-- the targets, looked up through the tunnel"
    com=$(addresses_of "$PUBLIC")
    net=$(addresses_of example.net)
    org=$(addresses_of "$EXCLUDED")
    com4=$(first_v4 "$com")
    say "  $PUBLIC $com; example.net $net; $EXCLUDED $org"
    say "  engine: $(beneath_state)"
    step "control: get https://$PUBLIC/" fixture_as "$FIXTURE" fresh timed --es url "https://$PUBLIC/"

    say ""
    say "-- a proxy that asks for a password: the recorder answers 407 for example.net's addresses"
    recorder_mode password "$net"
    step "get https://example.net/, 407" fixture_as "$FIXTURE" fresh timed --es url "https://example.net/"
    say "  engine: $(beneath_state)"
    now_lines | tee -a "$REPORT"
    recorder_mode tunnel

    say ""
    say "-- an exclusion list naming $EXCLUDED"
    mark
    say "  set: $(set_setting wifi-excluding)"
    since_mark | tee -a "$REPORT"
    say "  owner: $(owner state)"
    say "  engine: $(beneath_state)"
    step "get https://$EXCLUDED/, excluded" fixture_as "$FIXTURE" fresh timed --es url "https://$EXCLUDED/"
    step "get https://$PUBLIC/, not excluded" fixture_as "$FIXTURE" fresh timed --es url "https://$PUBLIC/"
    mark
    say "  set: $(set_setting wifi-proxy)"
    since_mark | tee -a "$REPORT"

    say ""
    say "-- tracker blocking on: a blocked name, and a hello for it to $PUBLIC's address through the proxy"
    say "  $(blocking_switch on)"
    step "get https://tracker.blocklab.home.arpa/, blocked" fixture_as "$FIXTURE" fresh timed --es url "https://tracker.blocklab.home.arpa/"
    if [ -n "$com4" ]; then
        tunnels=$(wc -l <"$RECORDS")
        step "a TLS hello for tracker.blocklab.home.arpa to $com4:443" fixture_as "$FIXTURE" fresh hello --es name tracker.blocklab.home.arpa --es host "$com4" --es port 443
        sleep 3
        say "  the tunnels it opened, as they closed: $(tail -n +"$((tunnels + 1))" "$RECORDS" | awk -F'\t' '$2 == "proxy-tunnel" && $3 ~ / closed / { printf "%s; ", $3 }')"
    fi
    say "  $(blocking_switch off)"

    if [ -n "${CHAIN_HOST:-}" ]; then
        say ""
        say "-- a chained app: the fixture chained through the SOCKS5 proxy at $CHAIN_HOST:$CHAIN_PORT as the tool (its UID stands in as the copy left out's)"
        say "  $(dump chain "$CHAIN_HOST" "$CHAIN_PORT" "$OUTSIDE_UID" no-udp "$FIXTURE_UID" "$CHAIN_USER" "$CHAIN_PASSWORD" | grep -m1 -oE 'chain (on|off)')"
        CHAINED=1
        step "chained: get https://$PUBLIC/" fixture_as "$FIXTURE" fresh timed --es url "https://$PUBLIC/"
        step "chained: get http://$com4/" fixture_as "$FIXTURE" fresh timed --es url "http://$com4/"
        say "  $(dump unchain | grep -m1 -oE 'chain (on|off)')"
        CHAINED=""
    fi

    say ""
    say "-- a proxy that takes names alone: the recorder answers 403 for $PUBLIC's addresses"
    recorder_mode names-only "$com"
    step "get https://$PUBLIC/, 403 by address" fixture_as "$FIXTURE" fresh timed --es url "https://$PUBLIC/"
    say "  engine: $(beneath_state)"
    step "get http://$PUBLIC/, names first" fixture_as "$FIXTURE" fresh timed --es url "http://$PUBLIC/"
    recorder_mode tunnel

    say ""
    say "-- the proxy removed while the VPN runs"
    mark
    clear_setting wifi-proxy
    say "  cleared: $(owner state)"
    since_mark | tee -a "$REPORT"
    say "  engine: $(beneath_state)"
    step "get https://$PUBLIC/, no proxy" fixture_as "$FIXTURE" fresh timed --es url "https://$PUBLIC/"
    step "get http://$com4/, no proxy" fixture_as "$FIXTURE" fresh timed --es url "http://$com4/"
    now_lines | tee -a "$REPORT"
}

SETTINGS="${SETTINGS:-none wifi-proxy wifi-pac global-setting global-owner global-pac}"
EXCLUDED=example.org
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
            # The unit S2's parts: the Wi-Fi network's proxy and the global setting together; the user's switch "Send
            # apps through this proxy"; and on Android 17 and later the local network grant revoked.
            measure wifi-and-global set
            switch_part
            if [ "$SDK_INT" -ge 37 ]; then
                say ""
                # Android ends an app's processes when one of its permissions is revoked: the VPN starts again without it.
                adb shell pm revoke "$PKG" android.permission.ACCESS_LOCAL_NETWORK
                say "  the local network grant revoked: $(adb shell dumpsys package "$PKG" | tr -d '\r' | grep -m1 -oE 'android.permission.ACCESS_LOCAL_NETWORK: granted=[a-z]+' || echo 'not listed')"
                within 20 vpn_down || true
                vpn_start
                measure wifi-proxy set
                adb shell pm grant "$PKG" android.permission.ACCESS_LOCAL_NETWORK
                say "  the grant given back: $(adb shell dumpsys package "$PKG" | tr -d '\r' | grep -m1 -oE 'android.permission.ACCESS_LOCAL_NETWORK: granted=[a-z]+' || echo 'not listed')"
            fi
            vpn_stop
            ;;
        8)
            say ""
            say "== pass 8: the unit S2's rows on a network that requires its proxy: the Wi-Fi network's own proxy set, the VPN on, every connection out refused ($EGRESS_END) but to the proxy"
            adb root >/dev/null 2>&1 || true
            adb wait-for-device
            [ "$(adb shell id -u | tr -d '\r')" = 0 ] || { echo "pass 8 needs an emulator that adb root takes" >&2; exit 2; }
            if [ -n "${CHAIN_SOCKS:-}" ]; then
                IFS=: read -r CHAIN_HOST CHAIN_PORT CHAIN_USER CHAIN_PASSWORD <<<"$CHAIN_SOCKS"
                [ "$CHAIN_HOST" = "$HOST" ] || { echo "CHAIN_SOCKS must be on $HOST, this computer" >&2; exit 2; }
                EGRESS_ALSO=$CHAIN_PORT
            fi
            say "  set before the VPN: $(set_setting wifi-proxy)"
            vpn_start
            egress_only_proxy
            say "  egress: only to $HOST:$PROXY_PORT${EGRESS_ALSO:+ and $HOST:$EGRESS_ALSO (the tool of the chain)}, the loopback and the VPN's interface"
            rows_s2
            egress_back
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
            say "  egress: only to $HOST:$PROXY_PORT, the loopback and the VPN's interface ($EGRESS_END for the rest)"
            measure wifi-proxy preset
            order_part
            egress_back
            vpn_stop
            clear_setting wifi-proxy
            ;;
        6)
            say ""
            say "== pass 6: a network that requires its proxy, with the global proxy alone: no proxy of the Wi-Fi network's own, the global proxy set, the VPN on, every connection out rejected but to the proxy"
            adb root >/dev/null 2>&1 || true
            adb wait-for-device
            [ "$(adb shell id -u | tr -d '\r')" = 0 ] || { echo "pass 6 needs an emulator that adb root takes" >&2; exit 2; }
            say "  set before the VPN: $(set_setting global-setting)"
            vpn_start
            egress_only_proxy
            say "  egress: only to $HOST:$PROXY_PORT, the loopback and the VPN's interface"
            measure global-setting preset
            egress_back
            vpn_stop
            clear_setting global-setting
            ;;
        7)
            say ""
            say "== pass 7: an open network with the global proxy alone and one server down: the first ODoH pair's relay refused at the connection, every other connection out allowed"
            adb root >/dev/null 2>&1 || true
            adb wait-for-device
            [ "$(adb shell id -u | tr -d '\r')" = 0 ] || { echo "pass 7 needs an emulator that adb root takes" >&2; exit 2; }
            say "  set before the VPN: $(set_setting global-setting)"
            vpn_start
            server_down
            say "  down: the relay $DOWN_RELAY at $DOWN_ADDRESSES, refused at the connection"
            measure global-setting preset
            server_back
            vpn_stop
            clear_setting global-setting
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
