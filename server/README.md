# Datapavan's ODoH relay, as Caddy configuration

The project's own Oblivious DoH relay ([ADR 0055](../docs/decisions/0055-an-odoh-relay-of-the-projects-own.md),
proposed), on the server that serves datapavan.org. It is configuration for the Caddy that already serves the
website, not a program of its own: no new program, no DNS record and no firewall change. It answers one path,
`https://datapavan.org/odoh/proxy`.

## What it does

An app that uses Oblivious DoH seals its DNS question to a target with the target's key, and sends it to a
relay with the target's name. The relay passes the sealed question on and the sealed answer back. It sees the
phone's address but cannot read the question; the target reads the question but sees only the relay's address.
This relay passes questions only to targets that other operators run.

## The files

- `log.caddy`: lines for the Caddyfile's global options. Caddy then writes no client's address in any log line,
  for every site on the server, not only the relay.
- `odoh-relay.caddy`: two snippets for the Caddyfile's top level. The datapavan.org site imports `odoh_relay`.
- `odoh-pairs.caddy`: the targets the relay forwards to.

The maintainer installs them with `server/odoh-relay.sh` in the strategy repository, which carries copies of these
files. `scripts/relaylab.sh` tests them, and checks those copies against them.

## The rules

**What it forwards:** a `POST` to `/odoh/proxy` that meets all of these:

- **Type:** `Content-Type` is exactly `application/oblivious-dns-message`.
- **Size:** `Content-Length` is between 1 and 65,604 bytes. That is the largest message RFC 9230 allows: one
  byte of type, a key id of at most 64 bytes and a sealed message of at most 65,535 bytes, each with a two-byte
  length.
- **Query:** the whole query is exactly `targethost=HOST&targetpath=PATH` for one of the targets in
  `odoh-pairs.caddy`.
  - PATH may be plain (`/dns-query`, as Datapavan's app writes it) or with `/` written as `%2F` (as RFC 9230's
    URI template expands it).
  - Nothing else matches: no other host, no duplicated or encoded `targethost`, no extra parameter, no other
    order, path or encoding.

**What it refuses:** anything else gets a 4xx and contacts nothing:

- another method: 405;
- another type: 415;
- another size, or a body without a length: 413;
- another query: 403;
- another path: the website's own 404.

**The forwarded request:**

- **What it carries:** the body; `Content-Type` and `Accept` of ODoH; the target's `Host`; the body's length.
- **What it drops:** every header of the client's, and those Caddy's proxy adds by itself:
  - `X-Forwarded-*`, `Forwarded`, `X-Real-IP`, `Via`;
  - `User-Agent` (Go's own as well), `Accept-Language`, `Cookie`, `Referer`, `Origin`.

**The response:** the target's status and body come back, without its cookies and without any `Server` header.

**Logging:** there is no access log. Caddy's error log would carry the client's request, its address included,
when a target is down. `log.caddy` deletes those fields for every site, and the relay writes no address.

Go's own messages at the debug level name an address in their text. Caddy's log level therefore stays at its
default, info.

## Choices that need a word

- **The targets:** the relay is in Germany (AS197540, netcup). Under the pair rule in `core/net/src/catalogue.rs`
  it pairs with:
  - Cloudflare's target (US, CR);
  - crypto.sx's target (FR, US).

  It does not pair with dnscry.pt's targets, which are in Germany. A target is added here only once
  `data/odoh/targets.tsv` holds it and the rule allows the pair.
- **No count per address:** the relay keeps no state about anyone. Abuse is limited by what it forwards: two
  targets, one path, ODoH's type and size. A kernel rate limit per source address in `nftables` is a later option,
  and it would need the maintainer's word.
- **Caddy 2.6.2's limits, written around:**
  - A lone `*` in a header deletion crashes the request. `request_header -**` deletes every header instead.
  - In the proxy's own header list, deletions run after settings. The client's headers are therefore deleted
    before the proxy starts.
  - The test fails if either changes.

## The test

`scripts/relaylab.sh` runs Debian 13's own Caddy package, the server's version, with these files and Caddy's
`tls internal`. Two stand-ins answer under the targets' names over TLS and record what they receive. The test
asserts every rule above over HTTP/1.1 and HTTP/2. With a target down, it reads Caddy's log for any address. A
control run without `log.caddy` shows that the check would catch one.

`scripts/dnslab.sh` with `DNSLAB_RELAY=caddy` puts the same relay into the DNS lab. Advanced's network monitoring
then reaches the lab's targets through it on an emulator (`scripts/verify-dns.sh`, `DNSLAB_ONLY=odoh` for the
ODoH steps alone).
