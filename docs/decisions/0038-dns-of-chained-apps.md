# 0038. DNS of chained apps: stand-in addresses, names to the tool

- Status: Accepted (by the maintainer on 2026-11-11, with Quad9 as the resolver of open question 1)
- Date: 2026-11-11

## Context

In W6 the user picks apps whose traffic Watch sends through the local SOCKS5 proxy of the user's
circumvention tool ([DESIGN.md §13.2](../DESIGN.md#132-v020-watch-the-connection-log-next-to-circumvention-tools),
[VPN.md](../VPN.md)). VPN.md already says that such apps never use the network's resolver: the network
would see every name they look up, and in a filtered network it answers some names falsely. This record
decides how their lookups are answered instead.

What is known:

- **Android names the app behind each lookup.** Its resolver sends each app's query to Watch's DNS address
  on a socket owned by that app, on Android 11, 15 and 17
  ([spike](../spikes/2026-11-shared-dns-cache.md)). So Watch can answer each app by its route.
- **Android shares one cache among all the apps of the tunnel,** answers and negative answers alike, and
  keeps no answer whose time to live is 0 (same spike). Whatever Watch answers one app, it can keep out of
  another app's reach.
- **Every proxy tool of the table takes names.** Of the 20 rows of `data/tools/tools.tsv` with a proxy
  mode, 18 accept a host name in a SOCKS5 request (address type 3) by a primary source, and the other two
  (Karing, MahsaNG) by inference; the tool resolves the name at its far end. Tor (Orbot, InviZible)
  carries no UDP at all, so a DNS query cannot go through it as a datagram.
- **The tools do the same in their own VPN mode.** sing-box and Clash answer lookups with stand-in
  addresses from 198.18.0.0/15 ("fake IP") and send the name onward when the app connects
  [sing-box docs; Clash Meta docs]; sing-box's example also gives IPv6 stand-ins from 2001:2::/48, and it
  can keep its map in a file across restarts (`store_fakeip`) [sing-box docs]. Tor maps names to
  addresses in 127.192.0.0/10 for the same purpose (`AutomapHostsOnResolve`, `VirtualAddrNetworkIPv4`)
  [Tor manual], and has a SOCKS command of its own, `RESOLVE` [Tor's SOCKS extensions], which no other
  tool offers.
- **Browsers sort addresses into spaces.** Local Network Access, which Chrome ships, puts 198.18.0.0/15
  in the *loopback* space, `fc00::/7` (unique local addresses, Watch's own prefix among them) in the
  *local* space, and every address it does not list, 2001:2::/48 included, in the *public* space
  [WICG Local Network Access]. The space of a connection is taken from the address it was made to; a page
  whose address is more public than the address of a request it makes needs the user's permission for
  that request. Stand-ins that fall into two spaces would therefore make some requests of an ordinary
  site look like requests into the user's own network.
- **HTTPS records** (RFC 9460) carry the keys of Encrypted Client Hello (ECH), which hide the server name
  from whoever carries the connection, and may carry address hints (`ipv4hint`, `ipv6hint`).

Options:

1. **Stand-in addresses, names to the tool.** For a chained app, Watch answers A questions itself, with
   an address from a reserved range that it maps to the name. When the app connects to that address,
   Watch asks the tool for the name (`CONNECT` or a UDP datagram with address type 3); the tool resolves
   it where its traffic leaves. A name reaches the tool only when the app connects to it.
2. **Every query through the tool to a resolver.** Watch sends the app's query as DNS over TCP through
   `CONNECT`, or as a datagram where the tool carries UDP, to a public resolver. Real addresses, but the
   resolver learns every name, and the answer suits the resolver's location rather than the tool's exit.
3. **Tor's `RESOLVE`** for Tor, and option 2 for the others: two paths to keep, for one tool family.
4. **Stand-ins for every app,** chained or not, as sing-box does when it routes some apps directly inside
   its own tunnel. Android's shared cache would then do no harm, but direct apps would see stand-ins too
   and depend on Watch's map for every connection: Watch would no longer only observe them (§5, v0.2).
5. **The network's resolver,** as for direct apps. Ruled out by VPN.md.

## Decision

Option 1, from W6 on, with these rules:

- **IPv4 stand-ins only.** Stand-ins come from 198.18.0.0/15 (RFC 2544, set aside for benchmarks and not
  routed on the internet), the range the tools themselves use, routed into the tunnel already. A chained
  app's AAAA question gets an empty answer ("no data"), so that every stand-in it meets is in the same
  space of Local Network Access and an ordinary site never looks like the user's own network. The tool
  chooses IPv4 or IPv6 at its exit by itself, since it is given the name, so nothing is lost: on an
  IPv6-only network the app still connects to an IPv4 stand-in inside the tunnel, and the tool reaches
  its server over IPv6.
- **The map.** Each name gets one stand-in, the same for as long as the name is used, so that connections
  in parallel agree. When the range is full, the stand-in used least recently goes to the new name.
- **The map is not kept across a restart** of Watch, unlike sing-box's `store_fakeip`: it is a list of
  the names the user opened through the tool, which is evidence in a phone search (§8). It lives in
  memory only and is never logged. A connection to a stand-in the map does not hold gets a reset (TCP) or
  an ICMP error (UDP), so the app looks the name up again.
- **Times to live.** While any app is chained, every answer of Watch's DNS address reaches the apps with
  a time to live of 0, so that no stand-in reaches a direct app through Android's shared cache and no
  answer of the network's resolver reaches a chained app. Watch keeps a cache of its own for each route,
  which honours the real time to live, so that no resolver sees more queries than before.
- **Connections.** A chained app's connection to a stand-in goes to the tool with the name; to any other
  address (a hard-coded one, or one from the app's own DNS) with that address. Both go through the tool or
  not at all (VPN.md).
- **Other record types through the tool** (HTTPS and SVCB, TXT, MX, SRV and the rest), already in W6: Watch
  sends the app's question as DNS over TCP (RFC 7766) through the tool's `CONNECT` to a public resolver,
  Quad9's service without blocking (`quad9-unsecured` in `data/resolvers`) until the user chooses one,
  and passes the answer on with a time to live of 0. From an HTTPS or SVCB answer it removes the address
  hints, so that every connection goes to a stand-in in one space, and keeps the ECH keys, so that ECH
  works through the tool as without it. Through the tool, the resolver sees the tool's exit, not the
  user's address. W8 adds the user's own DoH or DoT resolver, reached through the tool the same way.
  If the resolver cannot be reached through the tool (a Tor exit that refuses port 53, for example),
  these questions get an empty answer, and the app falls back to A.
- **Reverse lookups** of a stand-in are answered from the map, with the name.
- **Unchanged:** direct apps and the tool itself use the network's resolver (or the one the user chose
  in W8); an app's own DNS goes through the tool like any of its traffic.

## Consequences

- **Against the field.** The core, stand-ins and names to the tool, is the field's standard practice
  (sing-box, Clash, Tor), not an invention. Beyond it: direct apps in the same tunnel keep their real
  answers, which the field's tools do not do inside one tunnel; the choice was measured on Android rather
  than assumed; stand-ins stay in one Local Network Access space; and the map is never written down.
- No query of a chained app reaches the network beneath. A and AAAA questions never leave the phone; the
  other types reach the chosen resolver only through the tool.
- The tool resolves at its exit, so content networks answer for that place, as in the tool's own VPN mode.
- ECH keeps working for chained apps, so the tool's operator does not see the server names that ECH hides.
- Chained apps see addresses in 198.18.0.0/15 and no IPv6 addresses. An app that checks the address it
  connects to (rare) may refuse it; W6's lab run looks for this among the ten apps of W3.
- Answers with a time to live of 0 bring every lookup of every app to Watch while a chain is on; Watch's
  caches answer them. Questions of other types wait for a round trip through the tool. W6's lab run
  measures the delay; W9's battery runs measure the cost.
- **Strict Private DNS:** Android then sends lookups over TLS to the user's server, past Watch's DNS
  address. Watch can neither answer nor route them, and whose they are is not known (ADR 0035, question 6).
  W6 tells the user that a chain needs Private DNS off or on "automatic", as onboarding does (W9).

## What the lab measures before W6 is done

1. Chrome on the emulators and the A40, chained: an ordinary site with resources on other hosts loads with
   no Local Network Access prompt and no blocked request; then the same with IPv6 stand-ins in Watch's
   prefix and in 2001:2::/48, to confirm that one space is what matters.
2. ECH through the tool: a site that offers ECH (Cloudflare's test page) reports that ECH was used.
3. The ten apps of W3, chained: which work, which refuse a stand-in.
4. Strict Private DNS: whose socket carries Android's TLS lookups, and whether a chain should refuse to
   start in that mode rather than warn. *Measured on 2026-11-11 ([lab](../spikes/2026-11-chain-lab.md)): Android's
   resolver (UID 1051) asks the provider itself, so the lookups go directly, encrypted; the app's connections still
   go through the tool by address. Watch warns and does not refuse.*
5. The delay of other record types through each tool of W6 (v2rayNG, NekoBox, Hiddify, Orbot), and
   whether Tor's exits carry DNS over TCP to the resolver. *Measured through the test tool on 2026-11-11 (same
   notes): about half a second for each question, until Watch kept the tool route's answers as this record says;
   now the first costs that and the next about 10 ms. Through Tor: not measured yet.*

## Open questions

1. **The resolver for other record types in W6,** until the user chooses one in W8: proposed, Quad9 (a
   Swiss foundation that does not log addresses), its service without blocking (`quad9-unsecured` in
   `data/resolvers`, 9.9.9.10 and 149.112.112.10), so that Watch filters nothing by default; the
   alternative was to ask the user when the chain is set up, with no answer for those types until then.
   *Decided by the maintainer on 2026-11-11: Quad9 without blocking.*
2. **Ranges taken by the network.** 198.18.0.0/15 is not routed on the internet, but a lab or a carrier
   may use it inside its network. Seen nowhere so far; the lab run and W4's runs on the A40 show it.
3. **How long a name keeps its stand-in** once no flow uses it: the least recently used goes first; the
   size of the range (131,072 addresses) makes reuse within an app's own cache time unlikely.

## Sources

- sing-box, "FakeIP" (`inet4_range` 198.18.0.0/15 and `inet6_range` 2001:2::/48 in the example), https://sing-box.sagernet.org/configuration/dns/fakeip/, retrieved 2026-11-11.
- sing-box, "Cache File" (`store_fakeip`), https://sing-box.sagernet.org/configuration/experimental/cache-file/, retrieved 2026-11-11.
- Clash Meta (mihomo), DNS settings: `fake-ip-range: 198.18.0.1/16` in the example, https://wiki.metacubex.one/en/config/dns/, retrieved 2026-11-11.
- The Tor manual, `VirtualAddrNetworkIPv4` (127.192.0.0/10 by default) and `AutomapHostsOnResolve`, https://2019.www.torproject.org/docs/tor-manual.html.en, retrieved 2026-11-11.
- Tor's SOCKS extensions (`RESOLVE`, command F0), https://spec.torproject.org/socks-extensions.html.
- WICG, "Local Network Access", the table of non-public address blocks (198.18.0.0/15 loopback, `fc00::/7` local), https://wicg.github.io/local-network-access/, retrieved 2026-11-11.
- RFC 9460 (SVCB and HTTPS records; `ech`, `ipv4hint`, `ipv6hint`); RFC 7766 (DNS over TCP).
- RFC 2544, appendix C.2.2 (198.18.0.0/15 for benchmarks); RFC 6890 lists it as not globally reachable.
- RFC 1928, section 5 (address type 3, a domain name for the proxy to resolve).
