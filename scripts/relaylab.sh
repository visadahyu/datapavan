#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# The test of Datapavan's ODoH relay as Caddy configuration (server/, ADR 0055), in the Compose project
# datapavan-relaylab (scripts/relaylab): Debian 13's Caddy 2.6.2, the server's, with server/log.caddy,
# server/odoh-relay.caddy and server/odoh-pairs.caddy and `local_certs` (Caddy's `tls internal` for every site),
# and two stand-ins for the targets under their own names (odoh.cloudflare-dns.com over HTTP/2,
# odoh.crypto.sx over HTTP/1.1 alone), which record every request they get. It sends each request over HTTP/1.1
# and HTTP/2 from a client address of its own (127.0.0.9, inside the relay's container) and asserts every rule of
# server/README.md from what came back and from what the stand-ins got:
#   - an allowed POST is forwarded with its body, the target's Host, ODoH's Content-Type and Accept, and no other
#     header (none of the client's, none Caddy adds); the target's status and body come back with ODoH's type and
#     none of the target's headers (its cookie, Server, CORS, Clear-Site-Data, reporting, Location, ...);
#   - the target's path is taken plain or with each "/" as "%2F", as RFC 9230's URI template writes it; any other
#     method, type or size, any query that is not exactly one allowed target (another host, a duplicated or encoded
#     targethost, an extra parameter, another order or path, another encoding) gets a 4xx, and no stand-in is
#     contacted;
#   - with a stand-in down, the relay fails, and nothing Caddy logs carries the client's address, nor does a failed
#     TLS handshake or the mail site's failing proxy, nor a client that resets the connection mid-response (Go's
#     error text, which names both ends) or mid-body; a slow body reaches no target; no access log is on; a control
#     without server/log.caddy shows the address there;
#   - with RELAYLAB_SERVER, odoh-relay.sh leaves the Caddyfile and Caddy as it found them when a restart fails or a
#     target does not answer through the relay, installs, changes nothing on a second run, and removes (--remove).
#
#   scripts/relaylab.sh                  the test, with a Caddyfile of its own around server/'s files
#   RELAYLAB_SERVER=DIR scripts/relaylab.sh
#                                        the same on the server's own Caddyfile, rebuilt from DIR/site.sh and
#                                        DIR/mail-proxy.sh (the strategy repository's server/), with DIR/odoh-relay.sh
#                                        run on it in the container, twice, as the maintainer runs it on the server;
#                                        its copies of server/'s files must equal them
#
# Needs Docker with Compose, openssl and python3. Only the project datapavan-relaylab is touched; it is stopped at
# the end (stop, not down). Prints PASS or FAIL per line, and "== all relay lab checks passed" last.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LAB="$ROOT/scripts/relaylab"
SERVER="$ROOT/server"
STRATEGY="${RELAYLAB_SERVER:-}"
WORK="$(mktemp -d)"
# RELAYLAB_KEEP=1: leave the project running and its folder in place at the end, to look at them.
KEEP="${RELAYLAB_KEEP:-}"
export RELAYLAB_WORK="$WORK"
compose=(docker compose -f "$LAB/compose.yaml")
RELAY=datapavan-relaylab
CLIENT=127.0.0.9
# A client address of the kind the headers below claim: it must reach neither a target nor the log.
CLAIMED=198.51.100.77
ODOH=application/oblivious-dns-message
CF="targethost=odoh.cloudflare-dns.com&targetpath=/dns-query"
SX="targethost=odoh.crypto.sx&targetpath=/dns-query"

say() { echo "$*" >&2; }
cleanup() {
    if [ -n "$KEEP" ]; then
        say "== kept: the project datapavan-relaylab runs, with its folder $WORK"
        return
    fi
    "${compose[@]}" stop >/dev/null 2>&1 || true
    rm -rf "$WORK"
}
trap cleanup EXIT

FAILED=0
pass() { echo "PASS $*"; }
fail() { echo "FAIL $*"; FAILED=1; }

# The test CA and the stand-ins' certificates, for this run only.
certs() {
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 -sha256 \
        -subj "/CN=Datapavan relay lab test CA (this run only)" -keyout "$WORK/ca.key" -out "$WORK/ca.pem" \
        -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign" 2>/dev/null
    local id host
    for id in cloudflare:odoh.cloudflare-dns.com crypto-sx:odoh.crypto.sx; do
        host=${id#*:} id=${id%%:*}
        openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj "/CN=$host" \
            -keyout "$WORK/$id.key" -out "$WORK/$id.csr" 2>/dev/null
        printf 'subjectAltName=DNS:%s\nextendedKeyUsage=serverAuth\n' "$host" >"$WORK/$id.ext"
        openssl x509 -req -in "$WORK/$id.csr" -CA "$WORK/ca.pem" -CAkey "$WORK/ca.key" -CAcreateserial -days 2 \
            -sha256 -extfile "$WORK/$id.ext" -out "$WORK/$id.pem" 2>/dev/null
    done
    chmod 644 "$WORK"/*.key
}

# The Caddyfile: server/'s three files around a site like datapavan.org's (static files) and one like
# mail.datapavan.org's (a proxy to a local service, absent here, so that it fails).
own_caddyfile() {
    {
        printf '{\n\tadmin off\n\tlocal_certs\n\tservers {\n\t\tprotocols h1 h2\n\t}\n'
        cat "$SERVER/log.caddy"
        printf '}\n\n'
        cat "$SERVER/odoh-relay.caddy"
        echo
        cat "$SERVER/odoh-pairs.caddy"
        cat <<'CADDY'

datapavan.org {
	import odoh_relay
	root * /srv/datapavan/site
	file_server
}

mail.datapavan.org {
	reverse_proxy 127.0.0.1:8080
}
CADDY
    } >"$WORK/Caddyfile"
}

# The server's Caddyfile as site.sh writes it, with mail-proxy.sh's block inserted as it inserts it, and
# `local_certs` added after `admin off`: no certificate authority is reachable here.
server_caddyfile() {
    local block
    sed -n "/^cat > \/etc\/caddy\/Caddyfile <<'CADDY'$/,/^CADDY$/p" "$STRATEGY/site.sh" | sed '1d;$d' >"$WORK/site"
    block=$(sed -n "/^    block=\$(cat <<'CADDY'$/,/^CADDY$/p" "$STRATEGY/mail-proxy.sh" | sed '1d;$d')
    [ -s "$WORK/site" ] && [ -n "$block" ] || { say "!! site.sh or mail-proxy.sh no longer reads as this test expects"; exit 1; }
    awk -v block="$block" '/^# Any other name that still points here gets nothing\./ { print block; print "" } { print }' \
        "$WORK/site" | sed 's/^\tadmin off$/&\n\tlocal_certs/' >"$WORK/Caddyfile"
}

# In the relay's container.
in_relay() { docker exec -i "$RELAY" "$@"; }

# req NAME PROTO EXTRA_CURL_ARGS... : one request from the client's address; sets STATUS, BODY and HEADERS (the
# response's header lines, lower case).
req() {
    local proto=$1
    shift
    local out
    out=$(in_relay curl -sS --max-time 15 "--$proto" --interface "$CLIENT" \
        --cacert /var/lib/caddy/caddy/pki/authorities/local/root.crt --resolve datapavan.org:443:127.0.0.1 \
        --resolve mail.datapavan.org:443:127.0.0.1 -D /tmp/headers -o /tmp/body -w '%{http_code}' "$@" 2>&1) || true
    STATUS=$out
    BODY=$(in_relay cat /tmp/body 2>/dev/null || true)
    HEADERS=$(in_relay cat /tmp/headers 2>/dev/null | tr -d '\r' | tr 'A-Z' 'a-z' || true)
}

# The client's headers that must never reach a target.
CLIENT_HEADERS=(
    -H "X-Forwarded-For: $CLAIMED" -H "X-Forwarded-Proto: http" -H "X-Forwarded-Host: elsewhere.example"
    -H "Forwarded: for=$CLAIMED;proto=https" -H "X-Real-IP: $CLAIMED" -H "Via: 1.1 client-proxy"
    -H "User-Agent: relaylab-client/1" -H "Accept-Language: fa-IR" -H "Cookie: session=client-cookie"
    -H "Referer: https://referer.example/" -H "Origin: https://origin.example" -H "X-Client-Own: something"
    -H "Accept: */*"
)

# A body of N random bytes in the container, /tmp/q; prints its SHA-256.
body() { in_relay sh -c "head -c $1 /dev/urandom >/tmp/q && sha256sum /tmp/q | cut -d' ' -f1"; }

# The stand-ins' records: JSON lines in their output.
records() { "${compose[@]}" logs --no-log-prefix --no-color "$1" 2>/dev/null | grep '^{' || true; }
count() { records "$1" | wc -l; }
counts() { echo "$(count cloudflare) $(count crypto-sx)"; }

# A forwarded request: the target got exactly one request since the mark, and it is as the rules say.
# forwarded LABEL TARGET HOST MARK SHA
forwarded() {
    local label=$1 target=$2 host=$3 mark=$4 sha=$5 verdict
    verdict=$(records "$target" | tail -n +$((mark + 1)) | python3 -I -c '
import json, sys
host, sha, odoh = sys.argv[1], sys.argv[2], sys.argv[3]
rows = [json.loads(line) for line in sys.stdin if line.strip()]
if len(rows) != 1:
    sys.exit("%d requests reached the target, not 1" % len(rows))
r = rows[0]
headers = {k.lower(): v for k, v in r["headers"].items()}
problems = []
if r["method"] != "POST":
    problems.append("method " + r["method"])
if r["uri"] != "/dns-query":
    problems.append("uri " + r["uri"])
if r["host"] != host:
    problems.append("host " + r["host"])
if r["body_sha256"] != sha:
    problems.append("another body")
for name in ("content-type", "accept"):
    if headers.get(name) != [odoh]:
        problems.append("%s %s" % (name, headers.get(name)))
extra = sorted(set(headers) - {"content-type", "accept", "content-length"})
if extra:
    problems.append("headers beyond the three: " + ", ".join("%s: %s" % (k, headers[k]) for k in extra))
if problems:
    sys.exit("; ".join(problems))
print("%s %s %s%s, headers: %s" % (r["proto"], r["method"], r["host"], r["uri"], ", ".join(sorted(headers))))
' "$host" "$sha" "$ODOH" 2>&1) && pass "$label: the target got $verdict" || fail "$label: $verdict"
}

# The target's headers, which must never come back under datapavan.org's origin.
TARGET_HEADERS='set-cookie|set-cookie2|server|x-relaylab-target|clear-site-data|access-control-[a-z-]+|nel|report-to|location|link|refresh|content-disposition|cross-origin-resource-policy|cache-control'

# A response as the client sees it: the status wanted, ODoH's type, none of the target's headers.
answered() {
    local label=$1 want=$2 body_want=${3:-}
    [ "$STATUS" = "$want" ] || { fail "$label: status $STATUS, wanted $want (body: ${BODY:0:120})"; return; }
    if [ -n "$body_want" ] && [ "$BODY" != "$body_want" ]; then
        fail "$label: body '${BODY:0:120}', wanted '$body_want'"
        return
    fi
    if grep -qE "^($TARGET_HEADERS):" <<<"$HEADERS"; then
        fail "$label: the response carries $(grep -E "^($TARGET_HEADERS):" <<<"$HEADERS" | tr '\n' ' ')"
        return
    fi
    if ! grep -qx "content-type: $ODOH" <<<"$HEADERS"; then
        fail "$label: the response's type is not ODoH's: $(grep '^content-type:' <<<"$HEADERS" || echo none)"
        return
    fi
    pass "$label: $STATUS, the target's body, ODoH's type, none of the target's headers"
}

# A refusal: a 4xx (the one wanted) and no target contacted.
refused() {
    local label=$1 want=$2 before=$3 after
    after=$(counts)
    if [ "$STATUS" != "$want" ]; then
        fail "$label: status $STATUS, wanted $want"
    elif [ "$after" != "$before" ]; then
        fail "$label: a target was contacted (requests before: $before, after: $after)"
    else
        pass "$label: $STATUS, no target contacted"
    fi
}

log_lines() { in_relay cat /var/log/caddy.log | wc -l; }
# Whether Caddy's log since line $1 carries an address of the client's or its claimed one.
log_since() { in_relay cat /var/log/caddy.log | tail -n +$(($1 + 1)); }
# Whether the Caddyfile in the container turns any access log on: its adapted JSON names "logs" once, the global
# log's, and no server's (review m6).
no_access_log() {
    local n
    n=$(in_relay sh -c 'caddy adapt --adapter caddyfile --config /etc/caddy/Caddyfile 2>/dev/null' | grep -o '"logs":' | wc -l)
    [ "$n" = 1 ] && pass "$1: no server logs its requests (the adapted configuration names \"logs\" once, the global log's)" ||
        fail "$1: the adapted configuration names \"logs\" $n times: an access log is on, or the global log is gone"
}

# A client that asks a target, through the relay over HTTP/1.1, for a large answer, reads 100 kB of it and closes,
# which resets the connection with unread data: Caddy's proxy then logs Go's error text, which names the client's
# address and port (review M1). The abort races the request's end: Caddy logs either that text or "context
# canceled", so it is tried until it logs a write error, at most ten times; sets ABORT_MARK.
abort_mid_response() {
    local proto=${1:-http1.1}
    for _ in 1 2 3 4 5 6 7 8 9 10; do
        ABORT_MARK=$(log_lines)
        in_relay sh -c "printf big-8000000 >/tmp/big; curl -s --$proto --interface $CLIENT \
            --cacert /var/lib/caddy/caddy/pki/authorities/local/root.crt --resolve datapavan.org:443:127.0.0.1 \
            -X POST 'https://datapavan.org/odoh/proxy?$CF' -H 'Content-Type: $ODOH' --data-binary @/tmp/big |
            head -c 100000 >/dev/null; true"
        sleep 1
        log_since "$ABORT_MARK" | grep -q 'incomplete response","error":"write ' && return 0
    done
    return 1
}

no_address() {
    local label=$1 mark=$2 lines found
    lines=$(log_since "$mark")
    found=$(grep -nE "$CLIENT|$CLAIMED|remote_ip|remote_port|remote_addr|client-cookie|relaylab-client" <<<"$lines" || true)
    if [ -n "$found" ]; then
        fail "$label: Caddy's log carries the client: $(head -c 400 <<<"$found")"
    else
        pass "$label: $(grep -c . <<<"$lines" || true) log lines since, none with the client's address"
    fi
}

# ---- the setup
command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1 || { say "!! no Docker answers here"; exit 1; }
certs
if [ -n "$STRATEGY" ]; then
    server_caddyfile
    say "== the server's Caddyfile rebuilt from $STRATEGY/site.sh and mail-proxy.sh"
else
    own_caddyfile
fi
"${compose[@]}" up -d --build --force-recreate --quiet-pull >/dev/null 2>&1 || "${compose[@]}" up -d --build --force-recreate >&2
ready=""
for _ in $(seq 1 60); do
    if in_relay test -s /var/lib/caddy/caddy/pki/authorities/local/root.crt 2>/dev/null &&
        in_relay curl -s -o /dev/null --max-time 2 -k --resolve datapavan.org:443:127.0.0.1 https://datapavan.org/ 2>/dev/null; then
        ready=yes
        break
    fi
    sleep 0.5
done
[ -n "$ready" ] || { in_relay cat /var/log/caddy.log >&2 || true; say "!! Caddy did not come up"; exit 1; }
in_relay sh -c 'mkdir -p /srv/datapavan/site && echo "the site" >/srv/datapavan/site/index.html'
version=$(in_relay caddy version)
case $version in
    2.6.2 | v2.6.2*) pass "Debian's Caddy runs: $version ($(in_relay dpkg-query -W -f='${Version}' caddy))" ;;
    *) fail "the Caddy here is $version, not the server's 2.6.2" ;;
esac

if [ -n "$STRATEGY" ]; then
    echo "== odoh-relay.sh, as on the server"
    # Its copies of server/'s files are server/'s files.
    for part in LOG:log.caddy RELAY:odoh-relay.caddy PAIRS:odoh-pairs.caddy; do
        if diff <(sed -n "/<<'${part%%:*}'$/,/^${part%%:*}$/p" "$STRATEGY/odoh-relay.sh" | sed '1d;$d') \
            "$SERVER/${part#*:}" >/dev/null; then
            pass "odoh-relay.sh carries server/${part#*:} as it is"
        else
            fail "odoh-relay.sh's copy of server/${part#*:} differs from it"
        fi
    done
    in_relay sh -c 'cat >/tmp/odoh-relay.sh' <"$STRATEGY/odoh-relay.sh"
    # Caddy's internal root, trusted as the server's real chain is, so that the script's checks from the server work.
    in_relay sh -c 'cp /var/lib/caddy/caddy/pki/authorities/local/root.crt /usr/local/share/ca-certificates/caddy-local.crt && update-ca-certificates >/dev/null 2>&1'
    sum() { in_relay sha256sum /etc/caddy/Caddyfile | cut -d' ' -f1; }
    site_code() { req http1.1 https://datapavan.org/; echo "$STATUS"; }
    original=$(sum)
    # A step after the write fails: the server is left as the script found it (review M2).
    # rolled_back LABEL OUTPUT EXIT
    rolled_back() {
        local label=$1 out=$2 code=$3 state
        state=$(in_relay systemctl is-active caddy || true)
        if [ "$code" = 0 ]; then
            fail "$label: the script succeeded: $(tail -3 <<<"$out" | tr '\n' ' ')"
        elif [ "$(sum)" != "$original" ]; then
            fail "$label: the new Caddyfile stayed: $(tail -8 <<<"$out" | tr '\n' ' ')"
        elif [ "$state" != active ] || [ "$(site_code)" != 200 ]; then
            fail "$label: Caddy is $state, the website answers $(site_code): $(tail -8 <<<"$out" | tr '\n' ' ')"
        elif in_relay test -e /etc/caddy/Caddyfile.before-odoh-relay; then
            fail "$label: its backup stayed behind"
        elif ! grep -q '^the Caddyfile before it is back' <<<"$out"; then
            fail "$label: the script did not say what it did: $(tail -6 <<<"$out" | tr '\n' ' ')"
        else
            pass "$label: rolled back, Caddy active and the website at 200: $(grep -E '^(!!|the Caddyfile before|Caddy )' <<<"$out" | tr '\n' ' ' | cut -c1-400)"
        fi
    }
    in_relay touch /run/relaylab-fail-restart
    code=0; out=$(in_relay bash /tmp/odoh-relay.sh 2>&1) || code=$?
    rolled_back "odoh-relay.sh with Caddy's restart failing" "$out" "$code"
    in_relay rm -f /run/relaylab-fail-restart
    "${compose[@]}" stop crypto-sx >/dev/null 2>&1
    code=0; out=$(in_relay bash /tmp/odoh-relay.sh 2>&1) || code=$?
    rolled_back "odoh-relay.sh with a target not answering through the relay" "$out" "$code"
    "${compose[@]}" start crypto-sx >/dev/null 2>&1
    sleep 2
    for run in first second; do
        before=$(sum)
        if out=$(in_relay bash /tmp/odoh-relay.sh 2>&1) && tail -1 <<<"$out" | grep -qx RELAY_DONE; then
            pass "odoh-relay.sh, its $run run: $(grep -E '^(ok|==)' <<<"$out" | tr '\n' ' ' | cut -c1-700)"
        else
            fail "odoh-relay.sh, its $run run: $(tail -25 <<<"$out" | tr '\n' ' ')"
        fi
        after=$(sum)
        if [ "$run" = second ]; then
            [ "$before" = "$after" ] && pass "its second run left the Caddyfile as it was" ||
                fail "its second run changed the Caddyfile"
        fi
    done
    installed=$(sum)
    no_access_log "after odoh-relay.sh"
    # --remove takes every part out, to the byte; then it goes back in for the checks below.
    if out=$(in_relay bash /tmp/odoh-relay.sh --remove 2>&1) && tail -1 <<<"$out" | grep -qx RELAY_REMOVED &&
        [ "$(sum)" = "$original" ]; then
        pass "odoh-relay.sh --remove: the Caddyfile as it was before, to the byte: $(grep -E '^ok' <<<"$out" | tr '\n' ' ' | cut -c1-300)"
    else
        fail "odoh-relay.sh --remove: $(tail -8 <<<"$out" | tr '\n' ' ')"
    fi
    out=$(in_relay bash /tmp/odoh-relay.sh 2>&1) || true
    tail -1 <<<"$out" | grep -qx RELAY_DONE && [ "$(sum)" = "$installed" ] &&
        pass "odoh-relay.sh after --remove: the same Caddyfile again" || fail "odoh-relay.sh after --remove: $(tail -6 <<<"$out" | tr '\n' ' ')"
    in_relay test -f /etc/caddy/Caddyfile.before-odoh-relay && pass "the Caddyfile before it is kept as Caddyfile.before-odoh-relay" ||
        fail "no backup of the Caddyfile"
    [ "$(in_relay grep -c '^	import odoh_relay$' /etc/caddy/Caddyfile)" = 1 ] &&
        [ "$(in_relay grep -c '^(odoh_relay) {$' /etc/caddy/Caddyfile)" = 1 ] &&
        [ "$(in_relay grep -c 'request delete' /etc/caddy/Caddyfile)" = 1 ] &&
        pass "each part is in the Caddyfile once" || fail "a part is missing or twice in the Caddyfile"
    req http1.1 https://datapavan.org/
    [ "$STATUS" = 200 ] && pass "the website still answers: $STATUS" || fail "the website answers $STATUS"
    req http1.1 --resolve www.datapavan.org:443:127.0.0.1 https://www.datapavan.org/x
    [ "$STATUS" = 301 ] && grep -qx 'location: https://datapavan.org/x' <<<"$HEADERS" &&
        pass "its redirects still answer: $STATUS to https://datapavan.org/x" || fail "www.datapavan.org answers $STATUS"
fi

[ -n "$STRATEGY" ] || no_access_log "the test's Caddyfile"

# ---- the rules, over each protocol
for proto in http1.1 http2; do
    echo "== $proto"
    curl_proto=$proto
    for pair in "cloudflare odoh.cloudflare-dns.com $CF" "crypto-sx odoh.crypto.sx $SX"; do
        read -r target host query <<<"$pair"
        sha=$(body 317)
        mark=$(count "$target")
        req "$curl_proto" -X POST "https://datapavan.org/odoh/proxy?$query" -H "Content-Type: $ODOH" \
            "${CLIENT_HEADERS[@]}" --data-binary @/tmp/q
        answered "$proto, to $target: the response" 200 "answer of $target to $sha"
        forwarded "$proto, to $target" "$target" "$host" "$mark" "$sha"
    done
    # The path as RFC 9230's URI template writes it, "/" as "%2F".
    sha=$(body 64)
    mark=$(count cloudflare)
    req "$curl_proto" -X POST "https://datapavan.org/odoh/proxy?targethost=odoh.cloudflare-dns.com&targetpath=%2Fdns-query" \
        -H "Content-Type: $ODOH" --data-binary @/tmp/q
    answered "$proto, the path written %2Fdns-query" 200 "answer of cloudflare to $sha"
    forwarded "$proto, the path written %2Fdns-query" cloudflare odoh.cloudflare-dns.com "$mark" "$sha"
    # The target's own status comes back.
    in_relay sh -c 'printf status-401 >/tmp/q'
    req "$curl_proto" -X POST "https://datapavan.org/odoh/proxy?$CF" -H "Content-Type: $ODOH" --data-binary @/tmp/q
    answered "$proto, the target's 401" 401
    # The largest message RFC 9230 allows is forwarded.
    sha=$(body 65604)
    mark=$(count crypto-sx)
    req "$curl_proto" -X POST "https://datapavan.org/odoh/proxy?$SX" -H "Content-Type: $ODOH" --data-binary @/tmp/q
    answered "$proto, a body of 65,604 bytes" 200 "answer of crypto-sx to $sha"
    forwarded "$proto, a body of 65,604 bytes" crypto-sx odoh.crypto.sx "$mark" "$sha"

    body 100 >/dev/null
    b=$(counts); req "$curl_proto" "https://datapavan.org/odoh/proxy?$CF" -H "Content-Type: $ODOH"
    refused "$proto, GET" 405 "$b"
    b=$(counts); req "$curl_proto" -X PUT "https://datapavan.org/odoh/proxy?$CF" -H "Content-Type: $ODOH" --data-binary @/tmp/q
    refused "$proto, PUT" 405 "$b"
    b=$(counts); req "$curl_proto" -X OPTIONS "https://datapavan.org/odoh/proxy?$CF"
    refused "$proto, OPTIONS" 405 "$b"
    b=$(counts); req "$curl_proto" -X POST "https://datapavan.org/odoh/proxy?$CF" -H "Content-Type: application/dns-message" --data-binary @/tmp/q
    refused "$proto, plain DoH's type" 415 "$b"
    b=$(counts); req "$curl_proto" -X POST "https://datapavan.org/odoh/proxy?$CF" -H "Content-Type: $ODOH; charset=utf-8" --data-binary @/tmp/q
    refused "$proto, ODoH's type with a parameter" 415 "$b"
    b=$(counts); req "$curl_proto" -X POST "https://datapavan.org/odoh/proxy?$CF" -H "Content-Type:" --data-binary @/tmp/q
    refused "$proto, no type" 415 "$b"
    body 65605 >/dev/null
    b=$(counts); req "$curl_proto" -X POST "https://datapavan.org/odoh/proxy?$CF" -H "Content-Type: $ODOH" --data-binary @/tmp/q
    refused "$proto, a body of 65,605 bytes" 413 "$b"
    b=$(counts); req "$curl_proto" -X POST "https://datapavan.org/odoh/proxy?$CF" -H "Content-Type: $ODOH" --data-binary ''
    refused "$proto, an empty body" 413 "$b"
    body 100 >/dev/null
    if [ "$proto" = http1.1 ]; then
        b=$(counts); req "$curl_proto" -X POST "https://datapavan.org/odoh/proxy?$CF" -H "Content-Type: $ODOH" \
            -H "Transfer-Encoding: chunked" --data-binary @/tmp/q
        refused "$proto, a chunked body without a length" 413 "$b"
    fi
    for query in \
        "targethost=fra01.dnscry.pt&targetpath=/dns-query" \
        "targethost=example.com&targetpath=/" \
        "targethost=odoh.cloudflare-dns.com&targethost=odoh.crypto.sx&targetpath=/dns-query" \
        "targethost=odoh.cloudflare-dns.com&targetpath=/dns-query&targethost=example.com" \
        "targethost=odoh%2Ecloudflare-dns.com&targetpath=/dns-query" \
        "targethost=%6fdoh.cloudflare-dns.com&targetpath=/dns-query" \
        "targethost=odoh.cloudflare-dns.com&targetpath=%2fdns-query" \
        "targethost=odoh.cloudflare-dns.com&targetpath=%2F%64ns-query" \
        "targethost=odoh.cloudflare-dns.com&targetpath=/dns%2Dquery" \
        "targethost=ODOH.CLOUDFLARE-DNS.COM&targetpath=/dns-query" \
        "targethost=odoh.cloudflare-dns.com.&targetpath=/dns-query" \
        "targethost=odoh.cloudflare-dns.com:8443&targetpath=/dns-query" \
        "targethost=odoh.cloudflare-dns.com&targetpath=/dns-query&targetport=8443" \
        "targethost=odoh.cloudflare-dns.com&targetpath=/dns-query&x=1" \
        "targethost=odoh.cloudflare-dns.com&targetpath=/dns-query&" \
        "targetpath=/dns-query&targethost=odoh.cloudflare-dns.com" \
        "targethost=odoh.cloudflare-dns.com&targetpath=/other" \
        "targethost=odoh.cloudflare-dns.com&targetpath=/dns-query/../admin" \
        "targethost=odoh.cloudflare-dns.com" \
        "targethost=odoh.crypto.sx&targetpath=/dns-query?dns=x" \
        ""; do
        b=$(counts)
        req "$curl_proto" -X POST "https://datapavan.org/odoh/proxy?$query" -H "Content-Type: $ODOH" --data-binary @/tmp/q
        refused "$proto, the query '$query'" 403 "$b"
    done
    for path in /odoh/proxy/ /odoh/proxy/x /odoh/ /odoh/proxyx "/odoh/proxy%2F"; do
        b=$(counts)
        req "$curl_proto" -X POST "https://datapavan.org$path?$CF" -H "Content-Type: $ODOH" --data-binary @/tmp/q
        refused "$proto, the path $path" 404 "$b"
    done
done

# ---- aborts and slow bodies (review M1, m1)
echo "== aborts and slow bodies"
mark=$(log_lines)
if abort_mid_response http1.1; then
    lines=$(log_since "$ABORT_MARK")
    grep -q '"error":"write tcp ADDR->ADDR' <<<"$lines" &&
        pass "an HTTP/1.1 client resetting mid-response: Caddy logs the abort with both ends as ADDR" ||
        fail "an HTTP/1.1 client resetting mid-response: the abort's error is not masked: $(grep 'incomplete' <<<"$lines" | head -c 400)"
else
    fail "an HTTP/1.1 client resetting mid-response: Caddy never logged the abort's write error in ten tries, so the check proves nothing"
fi
# Over HTTP/2 the abort is a stream's cancel, logged without an address; run for the log's check below.
abort_mid_response http2 >/dev/null || true
for proto in http1.1 http2; do
    # Five clients that send a body of 1,000 bytes at 100 bytes a second and give up after 3 s, and one that sends
    # it whole in about 2.5 s: only that one reaches a target, once (buffer_requests).
    b=$(counts)
    in_relay sh -c "head -c 1000 /dev/urandom >/tmp/slow
        for i in 1 2 3 4 5; do
            curl -s --$proto --interface $CLIENT --limit-rate 100 --max-time 3 -o /dev/null \
                --cacert /var/lib/caddy/caddy/pki/authorities/local/root.crt --resolve datapavan.org:443:127.0.0.1 \
                -X POST 'https://datapavan.org/odoh/proxy?$SX' -H 'Content-Type: $ODOH' --data-binary @/tmp/slow &
        done
        wait; true"
    STATUS=499
    refused "$proto, five slow bodies given up mid-way" 499 "$b"
    sha=$(in_relay sh -c "sha256sum /tmp/slow | cut -d' ' -f1")
    in_relay cp /tmp/slow /tmp/q
    mark_sx=$(count crypto-sx)
    req "$proto" --limit-rate 400 -X POST "https://datapavan.org/odoh/proxy?$SX" -H "Content-Type: $ODOH" --data-binary @/tmp/q
    answered "$proto, a slow body sent whole" 200 "answer of crypto-sx to $sha"
    forwarded "$proto, a slow body sent whole" crypto-sx odoh.crypto.sx "$mark_sx" "$sha"
done
no_address "aborts mid-response and mid-body" "$mark"

# ---- the log: a target down, a failed handshake, the mail site's proxy failing
echo "== Caddy's log"
mark=$(log_lines)
"${compose[@]}" stop crypto-sx >/dev/null 2>&1
body 100 >/dev/null
req http2 -X POST "https://datapavan.org/odoh/proxy?$SX" -H "Content-Type: $ODOH" "${CLIENT_HEADERS[@]}" --data-binary @/tmp/q
[[ "$STATUS" == 50[234] ]] && pass "a target down: the relay fails ($STATUS)" || fail "a target down: status $STATUS, wanted 502, 503 or 504"
req http1.1 -X POST "https://datapavan.org/odoh/proxy?$SX" -H "Content-Type: $ODOH" "${CLIENT_HEADERS[@]}" --data-binary @/tmp/q
req http1.1 https://mail.datapavan.org/ "${CLIENT_HEADERS[@]}"
[[ "$STATUS" == 50[234] ]] && pass "the mail site's service absent: its proxy fails ($STATUS)" || fail "the mail site: status $STATUS"
# Plain HTTP to the TLS port, and a hello with no name: TLS handshake errors.
in_relay sh -c "curl -s --max-time 3 --interface $CLIENT http://127.0.0.1:443/ >/dev/null; true"
in_relay sh -c "echo | timeout 3 openssl s_client -connect 127.0.0.1:443 -bind $CLIENT:0 -noservername >/dev/null 2>&1; true"
sleep 1
lines=$(log_since "$mark")
grep -q '"logger":"http.log.error"' <<<"$lines" && pass "the failures are in Caddy's error log: $(grep -c '"logger":"http.log.error"' <<<"$lines") lines" ||
    fail "the failures were not logged, so the log's check below proves nothing: $(head -c 600 <<<"$lines")"
no_address "a target down, the mail proxy failing, failed handshakes" "$mark"
no_address "the whole log of this run" 0
"${compose[@]}" start crypto-sx >/dev/null 2>&1
for _ in $(seq 1 20); do
    sha=$(body 50)
    req http1.1 -X POST "https://datapavan.org/odoh/proxy?$SX" -H "Content-Type: $ODOH" --data-binary @/tmp/q
    [ "$STATUS" = 200 ] && break
    sleep 0.5
done
answered "the target back: the relay forwards again" 200 "answer of crypto-sx to $sha"

# ---- the control: without the log's filter, the same failure writes the client's address
echo "== the control, without server/log.caddy's filter"
in_relay sh -c "cp /etc/caddy/Caddyfile /tmp/Caddyfile.kept && sed -i '/^\tlog {\$/,/^\t}\$/d' /etc/caddy/Caddyfile"
if in_relay grep -q 'request delete' /etc/caddy/Caddyfile; then
    fail "the control could not take the log's filter out"
else
    in_relay systemctl restart caddy
    "${compose[@]}" stop crypto-sx >/dev/null 2>&1
    mark=$(log_lines)
    req http1.1 -X POST "https://datapavan.org/odoh/proxy?$SX" -H "Content-Type: $ODOH" "${CLIENT_HEADERS[@]}" --data-binary @/tmp/q
    sleep 1
    log_since "$mark" | grep -q "\"remote_ip\":\"$CLIENT\"" && pass "the control: without the filter, Caddy's error log names $CLIENT, so the check above can see it" ||
        fail "the control: even without the filter no address was logged, so the check above proves nothing"
    "${compose[@]}" start crypto-sx >/dev/null 2>&1
    sleep 2
    if abort_mid_response http1.1 && log_since "$ABORT_MARK" | grep -q "\"error\":\"[^\"]*$CLIENT:[0-9]"; then
        pass "the control: without the filter, an abort mid-response logs $CLIENT and its port in the error's text"
    else
        fail "the control: without the filter, the abort's error did not name $CLIENT, so its check proves nothing"
    fi
    in_relay sh -c "cp /tmp/Caddyfile.kept /etc/caddy/Caddyfile"
    in_relay systemctl restart caddy
    "${compose[@]}" start crypto-sx >/dev/null 2>&1
fi

if [ "$FAILED" = 0 ]; then
    echo "== all relay lab checks passed"
else
    echo "== some relay lab checks FAILED" >&2
    exit 1
fi
