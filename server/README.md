# Datapavan's ODoH relay, as Caddy configuration

The project's own Oblivious DoH relay ([ADR 0055](../docs/decisions/0055-an-odoh-relay-of-the-projects-own.md),
proposed), on the server that serves datapavan.org. It is configuration for the Caddy that already serves the
website, not a program of its own: no new program, no DNS record and no firewall change. It answers one path,
`https://datapavan.org/odoh/proxy`, and what Caddy's path matcher takes as equal to it (case, doubled or dotted
slashes and percent-escapes are normalised first, so `/ODOH/PROXY` or `/odoh//proxy` reach it too; the target and
its path stay fixed whatever the spelling).

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
files. It puts the Caddyfile as it found it back, and Caddy on it, when any step after its write fails, and takes
the relay out with `--remove`. `scripts/relaylab.sh` tests them, and checks those copies against them.

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

- **When:** only once the whole body is in (`buffer_requests`): a slow client holds no request open at a target.
- **What it carries:** the body; `Content-Type` and `Accept` of ODoH; the target's `Host`; the body's length. The
  names of any trailers a client declares go too, never their values: `request_header` does not reach trailers.
- **What it drops:** every header of the client's, and those Caddy's proxy adds by itself:
  - `X-Forwarded-*`, `Forwarded`, `X-Real-IP`, `Via`;
  - `User-Agent` (Go's own as well), `Accept-Language`, `Cookie`, `Referer`, `Origin`.

**The response:** the target's status and body come back with ODoH's `Content-Type`, and none of the target's
headers: no cookie, `Server`, CORS, `Clear-Site-Data`, reporting, `Location` or anything else it writes is served
under datapavan.org's origin.

**Logging:** there is no access log; `odoh-relay.sh` and the test fail when any site turns one on. What Caddy's log
lines carry, and what `log.caddy` does to it, for every site:

- `request` (every `http.log.error` line): the client's address, port, headers and URI. Deleted.
- `remote_ip`, `remote_port` (debug lines): deleted.
- `error` (the proxy's lines): Go's network error text, which names both ends of a connection, for example when a
  client resets mid-response over HTTP/1.1. Every address in it, with its port, becomes `ADDR`; the upstream's too.
- `msg`: cannot be filtered in Caddy 2.6.2. In `http.log.error` it is the handler's error, which here names only an
  upstream (a target, or the mail proxy's local service). Go's own messages, which name the client in their text
  (a TLS handshake error, a panic), come at the debug level only. Caddy's log level therefore stays at its default,
  info.

Outside Caddy, the firewall's input chain logs the source of dropped packets, five a minute. A relay client that
tried QUIC on UDP port 443 would be logged; none tries today, since Caddy offers no HTTP/3, the site has no HTTPS
record, and Datapavan's app does not use QUIC.

## Choices that need a word

- **The targets:** the relay is in Germany (AS197540, netcup). Under the pair rule in `core/net/src/catalogue.rs`
  it pairs with:
  - Cloudflare's target (US, CR);
  - crypto.sx's target (FR, US).

  It does not pair with dnscry.pt's targets, which are in Germany. A target is added here only once
  `data/odoh/targets.tsv` holds it and the rule allows the pair.
- **No count per address:** the relay keeps no state about anyone. Abuse is limited by what it forwards: two
  targets, one path, ODoH's type and size, and only whole bodies. A slow client holds a connection to Caddy, as it
  could to the website, but no request at a target; Caddy 2.6.2 sets no read timeout, so how many such connections
  it holds is bounded by the server's memory, shared with the website and the mail proxy. Both targets sit on
  Cloudflare's network (AS13335): one rate limit or bot decision there fails both of the relay's pairs at once. A
  kernel rate limit per source address in `nftables` is a later option, and it would need the maintainer's word.
- **Caddy 2.6.2's limits, written around:**
  - A lone `*` in a header deletion crashes the request. `-**` deletes every header instead.
  - In the proxy's own header lists, deletions run after settings. The client's headers are therefore deleted
    before the proxy starts (`request_header -**`), and ODoH's type is set on the response by a deferred `header`,
    after the proxy deleted every header of the target's (`header_down -**`).
  - Its request buffering ignores read errors; the length check before it keeps a short body from being forwarded.
  - A rewrite that ends in `?` re-expands the placeholders it holds (CVE-2026-77281, not fixed in Debian 13): the
    relay's rewrite holds a literal path alone, and must stay so.
  - The test fails if any of these changes.

## The test

`scripts/relaylab.sh` runs Debian 13's own Caddy package, the server's version, with these files and Caddy's
`tls internal`. Two stand-ins answer under the targets' names over TLS, with every header above, and record what
they receive. The test asserts every rule above over HTTP/1.1 and HTTP/2. It reads Caddy's log for any address with
a target down, with clients that reset mid-response and mid-body, and with failed handshakes. A control run
without `log.caddy` shows that the checks would catch one.

CI runs it on the `dns` shard with a Caddyfile of its own around these files. Its server mode
(`RELAYLAB_SERVER`) rebuilds the server's Caddyfile from the strategy repository's scripts and runs
`odoh-relay.sh` on it, its failures included; that repository is private, so this mode runs on the maintainer's
computer only.

`scripts/dnslab.sh` with `DNSLAB_RELAY=caddy` puts the same relay into the DNS lab. Advanced's network monitoring
then reaches the lab's targets through it on an emulator (`scripts/verify-dns.sh`, `DNSLAB_ONLY=odoh` for the
ODoH steps alone).
