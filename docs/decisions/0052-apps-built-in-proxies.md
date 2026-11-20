# 0052. Apps' built-in proxies named: read from the connection, or inferred with substitution

- Status: Proposed (built on `watch-w8b`, W8 part 2a, 2026-11-20; awaits the maintainer's word)
- Date: 2026-11-20
- Decided by: drafted by the builder of W8 part 2a with AI help, under the session's grant (go on by the roadmap at
  the S-tier bar), from a brief audited once before the build; the maintainer accepts or changes it.
- Builds on: ADR [0025](0025-guided-check-and-traffic-facts.md) (decisions 4 and 5: facts, never alarms; the words),
  [0036](0036-ip-to-organisation-dataset.md) (decision 4: an address's organisation hosts, it does not run),
  [0037](0037-connection-log-storage.md), [0038](0038-dns-of-chained-apps.md),
  [0046](0046-live-activity.md) (decision 3: the tool's own row; "Log where these apps connect"),
  [0047](0047-profile-for-phones-that-may-be-searched.md) and [0015](0015-dataset-licences.md).

## Context

DESIGN.md's W8 row: "Apps' built-in proxies are named, with their operator when it is not the app's maker, Telegram's
MTProto and SOCKS5 proxies first." Many apps carry a proxy setting of their own: browsers, games, download managers,
and above all messengers in restricted regions (Telegram's MTProto and SOCKS5 proxies, WhatsApp's since January
2023, Signal's since 2021). Watch sees every app's packets and already names each flow by its app, its TLS or QUIC
server name, the DNS answer for its address and the address's organisation. A flow through an app's own proxy is
then named after the proxy, and where the proxy is reached by its address alone, after the proxy's hosting company:
the user learns nothing of where the app really went, nor that it used a proxy.

What the field does (research of 2026-11-20, in the private strategy repository): nDPI, and PCAPdroid on top of it,
label SOCKS and HTTP `CONNECT`, but name neither the destination asked for nor the proxy's place; nDPI's Telegram
label is an address match, so a flow to an MTProto proxy gets none; no tool found says "this app uses a proxy of its
own, here, for this destination". No peer-reviewed method for MTProto proxies exists; the material is implementers'
documentation. The brief's audit (one round, 2026-11-20) found that inferences resting on one feature misname
Telegram's CDN data centres, WhatsApp's link previews and backups, and Signal's own fronting, and asked for
substitution; that "the operator" is not what the data gives; and that an app's own proxy is circumvention, as
chaining is, and must follow the same switch.

## Decision

1. **Proxies the app's own bytes declare are read from the connection.** The first bytes an app sends on a TCP flow
   that went directly are read for SOCKS5 (RFC 1928, with RFC 1929's user name and password), SOCKS4 and 4a, an
   HTTP `CONNECT`, and a plain HTTP request sent to a proxy (its target in absolute form), within 4,096 bytes
   (`core/net/src/proxies.rs`, fuzzed). The flow is named by the destination the app asked the proxy for, a source
   of names after the hello's and before a DNS answer's (which names the proxy's address, not the destination); after
   a SOCKS or `CONNECT` handshake the inner TLS hello is read too, and names the flow as any hello does. Of a plain
   request only the authority is taken, never its path or query. The screens word it "Asked the SOCKS5 proxy at
   ADDRESS for DESTINATION. Read from the connection."
2. **Never kept, logged, shown or held past the parse:** RFC 1929's user name and password, SOCKS4's user ID, a
   `Proxy-Authorization` header's value, a URL's user information. The parser skips them by their lengths and
   delimiters and copies nothing of them; the bytes they passed through, the sniff buffer (its capacity set once, so
   that it never moves) and the relay's own buffer, are zeroed when dropped. The one fact said is that a password for
   this proxy crossed the network unencrypted (RFC 1929's, or HTTP's `Basic`), never the password. Tests prove that
   none of them reaches a flow, the log, the live view, the debug dump, logcat or the crash buffer; the fuzz seeds are
   synthetic.
3. **Skipped:** the user's circumvention tool's own flows, and the apps Watch chains through it or sends through a
   WireGuard tunnel: what they carry is the tool's (ADR 0046, decision 3), and a tool whose upstream is plain SOCKS5
   or HTTP would otherwise show every chained destination under its row.
4. **Android's proxy setting** (the global one, and each network's), which every app that follows it shares, is told
   apart from an app's own: Watch hands the engine its hosts and ports at each start and change, and a declared proxy
   at one of them says "This is the proxy in Android's settings, which other apps can use too." A proxy given by a PAC
   file is found by Android on the phone's own loopback, which never enters the tunnel: not seen.
5. **Messengers' proxies are inferred, each with substitution,** and worded "Through a KIND at ADDRESS. Inferred from
   where and how it connects. What it reaches from there is encrypted." The clients are their makers' own packages
   (`data/messengers/clients.tsv`). A proxy is named only while, in the same window (the live view's ten minutes, or
   while one is open), the app made no direct connection to its maker's own network; a direct connection that opens
   later takes the name back from its open flows.
   - **Telegram's MTProto:** a flow to an address outside Telegram's published ranges (`data/messengers`, its
     `cidr.txt` byte for byte, each fetch recorded with its date, SHA-256 and the ranges added and removed) whose
     first 64 bytes pass the obfuscated transport's rules (the excluded prefixes and bytes 4 to 8, not a length; and
     random-looking: 3 to 5 bits set a byte on average), or whose TLS hello's server name no DNS answer Watch passed tied
     to this address (fake TLS). Any TCP flow of the app to its ranges, even one refused, is a direct connection: with
     a proxy set, Telegram makes none. A CDN data centre reached while the app goes directly is therefore no proxy.
   - **The cover name never names the flow.** For Telegram's and WhatsApp's clients, a hello whose name no DNS answer
     Watch passed tied to an address outside the maker's network does not rename the flow, whatever substitution says:
     "Telegram → google.com" never appears. The name is kept as the cover it is ("Its connection sent the name NAME to
     look like that site"), with, where the owners' tables name both, the company behind the name and the network's: the
     owner test supports, never decides (mtg advises a cover hosted with the proxy's own provider).
   - **WhatsApp's proxy:** WhatsApp's clear header (`W` `A` and two bytes, or `E` `D` `0` `1` with its routing data,
     as whatsmeow and Baileys write it) to an address outside Meta's networks, on any port (5222 and 80 by default; the
     client lets the user set others), or a TLS hello whose name no DNS answer tied to such an address (the proxy's 443
     and its media ports, 587 and 7777, which carry `*.whatsapp.net` names). Meta's networks are AS32934 and AS63293,
     which Meta's peering page names, through the organisation table, or a DNS name of WhatsApp's; an address of the
     user's own network is no company's. Without the organisation table nothing is inferred elsewhere. A link preview
     or a backup reaches a name a DNS answer tied to its address: not a candidate, and substitution besides.
   - **Signal's proxy:** decided by names. A TLS hello of a Signal client whose name is not Signal's own
     (`signal.org`, `signalcaptchas.org`), not one of Signal's fronts (the names its source sends to reach Signal
     through Google's and Fastly's networks), and not a third party it reaches itself (Stripe, hCaptcha). Signal's
     fronting is its own circumvention and is not shown as a proxy. Signal has no network of its own, so nothing is said
     of its maker's network.
6. **Who runs it is never said.** "An address in the network of ORGANISATION. Who runs it is not known." or "On your
   local network. Who runs it is not known." Where Watch can tell that the network is not the app maker's, it says so:
   for Telegram (outside its ranges) and WhatsApp (outside Meta's networks) always; for a declared proxy only where the
   owners' tables name both the network's company group and the app's (ADR 0020) and they differ. Never "the
   operator".
7. **The confidence, in words:** "Read from the connection" for a declared proxy; "Inferred from where and how it
   connects" for a messenger's. What Watch never knows is said, in "What this view cannot see": who runs a proxy, where
   an inferred proxy sends the traffic on, and whether the user or the app chose it.
8. **An app's own proxy is circumvention, as chaining is.** The proxy's address and the destination asked for follow
   "Log where these apps connect" in the log and in "Now": while it is off (the default), a proxied flow keeps only
   its kind and the facts that name nothing (Android's setting, a password unencrypted, outside the maker's network),
   at an address of zeros; turning it off strips the open flows, the segments that wait for their states and the live
   view at once, and the place a flow's first bytes were counted under goes when the request names it. Under ADR 0047's
   profile, as for chained apps, nothing of it is recorded or shown; the substitution's state is a few instants per
   messenger, in memory. Nothing reaches a summary, the widget or the tile (ADR 0046, decision 3).
9. **The records.** The log's records are version 5 and the live view's snapshot version 4, each with a proxy block
   after the route (`log::push_proxy`): the kind, the flags, the destination asked for, the proxy's own name, its
   network's organisation and the cover; six counters are appended (declared, with a password, inferred, substituted,
   taken back, covers kept out). Watch's Kotlin side reads version 5 and still reads 1 to 4.

## Consequences

- Watch says, for the first time in the field as far as the research found, where an app went through its own
  proxy and where that proxy is, for the declared kinds with no guess at all.
- **Accepted limits**, each with its reason:
  - Proxies inside TLS or QUIC (HTTPS proxies, Signal's own inner TLS, QUIC-based proxies): their request is encrypted.
    Signal's and WhatsApp's are inferred instead; others are not seen as proxies.
  - Apps pointed at a proxy on the phone itself (Orbot's SOCKS port, a PAC proxy): loopback never enters the tunnel, so
    their traffic shows as the proxy app's, as chaining's tool.
  - Only the first request on a connection is read: a plain HTTP proxy's later requests on a kept-alive connection to
    other hosts are counted under the first.
  - An inferred proxy's destination beyond it is encrypted: Watch shows the proxy, not where it leads.
  - A WhatsApp proxy given by a name that Android's resolver answered, reached over TLS on 443, sends a name a DNS
    answer tied to its address: it looks like a link preview, and is not named (the same proxy on 5222 or 80 is).
  - Substitution reads ten minutes: a user who turns a proxy on within ten minutes of a direct connection sees it named
    only after them; one who turns it off sees it taken back at the first direct connection.
  - Forks of the three clients are not recognised until a row of `clients.tsv` names them; the list travels in the
    signed data pack.
  - The false positives that need a maker's own network (a Telegram CDN data centre beside its ranges, WhatsApp's link
    previews and backups) are checked in the engine's tests and its network lab, not on the emulator, which must reach
    no outside server.
- **Checks:** unit tests for each parser and rule, fuzzing of the parser (`fuzz_targets/proxies.rs`, synthetic seeds),
  two network-lab tests through the whole engine on Linux's TCP stack (an address of Telegram's ranges on the lab's own
  loopback), the proxy lab (`scripts/proxylab.sh`: microsocks, tinyproxy, mtg built from v2.3.0 at a pinned commit, on
  a network with no way out), and the emulator's `proxies` shard (`scripts/verify-proxies.sh`), which CI runs and in
  which a skip fails: the project's own fixture under package names of its own, which only debug builds add to a
  messenger's clients.
- **Size:** Watch's native library grows by 45,520 bytes on arm64-v8a, 32,832 on armeabi-v7a and 49,232 on x86_64
  (built alike from `main` and from this part: 1,707,608, 1,465,644 and 1,981,256 bytes before; 1,753,128, 1,498,476
  and 2,030,488 after); in Advanced's release APK it is 1,751,840, 1,497,192 and 2,029,136 bytes, under the 2 MiB gate
  of each ABI. With part 1's 153 KB on x86_64 the two together pass the gate there, until part 1's fix round's savings
  land: the gate stands, and the merge waits for them.
- **Frontier research, open:** Telegram's fake-TLS hello across versions, told from the device without a JA4 database;
  encapsulated handshakes seen from the device (Xue et al., USENIX Security 2024) for Signal and WhatsApp; and how
  people read "read from the connection" against "inferred", with real users.

## How it is built (W8, part 2a)

- `core/net/src/proxies.rs` (the parsers), `messengers.rs` (the data), `engine/proxied.rs` (the rules, substitution,
  the sniff and its zeroing), `engine/tcp.rs` (the relay reads through the sniff), `log.rs` and `snapshot.rs` (the
  formats); `core/watch-jni` (`nativeProxies`, `nativeMessengerClients`, `nativeFlowProxies`).
- Watch: `WatchVpnService.applyProxies` (the messengers' UIDs, Android's proxy setting, again at package and proxy
  changes), `activity/ProxyFacts.kt` (what a row says, a pure function), the screens "Now" and the history, the
  strings in `strings_untranslated.xml` until ADR 0030's translation, held to ADR 0025's words by a test.
- Data: `data/messengers` (CC0 for the project's lists; Telegram's `cidr.txt` states no licence, ADR 0015's record).
