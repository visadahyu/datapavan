# 0052. Apps' built-in proxies named: read from the connection, or inferred with substitution

- Status: Proposed (built on `watch-w8b`, W8 part 2a, 2026-11-20; its fix round on `watch-w8b-fix`, 2026-11-21;
  awaits the maintainer's word)
- Date: 2026-11-20, fix round 2026-11-21
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
2023, Signal's since 2021). Advanced sees every app's packets and already names each flow by its app, its TLS or QUIC
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
   that went directly are read for SOCKS5 (RFC 1928, with RFC 1929's user name and password), SOCKS4 and 4a, an HTTP
   `CONNECT`, and a plain HTTP request sent to a proxy (its target in absolute form), within 4,096 bytes
   (`core/net/src/proxies.rs`, fuzzed). **The app declares the proxy, not Datapavan** (decision F1): a request alone
   is only what the app wrote, so a SOCKS or `CONNECT` request names its flow only once the server's first bytes
   confirm the handshake (`proxies::confirmed`: SOCKS5's choice of the method the app then used, RFC 1929's success
   where it was used, then `05 00 00`; SOCKS4's `00 5a`; an `HTTP/1.x 2xx` status line for `CONNECT`). Until then, and
   for good when the server refuses, never answers or answers in another protocol, the flow keeps its own address,
   names and trackers' marks, and a hello read after the request names it as its own. Confirmed, the flow is named by
   the destination the app asked the proxy for, a source of names after the hello's and before a DNS answer's (which
   names the proxy's address, not the destination), by the address asked for where no answer names it, never by the
   proxy's; the inner TLS hello is read too, and names the flow as any hello does. A plain request in absolute form
   cannot be confirmed so, since origin servers accept that form too (RFC 9112, 3.2.2): its flow keeps its own address
   and names whatever the switch says, and its row says what the request asked for, never that the server is a proxy.
   Of a plain request only the authority is taken, never its path or query, and a target with an `@` after its
   authority is refused. SOCKS5 needs a plausible method list (one to ten, each IANA assigned, none twice, the method
   used among them) and SOCKS4 a printable user ID: 0 of 2,000,000 random 600-byte starts parse as a request (36
   without these two rules). The screens word it "Asked the SOCKS5 proxy at ADDRESS for DESTINATION. Read from the
   connection."
2. **Never kept, logged, shown or held past the parse:** RFC 1929's user name and password, SOCKS4's user ID, a
   `Proxy-Authorization` header's value, a URL's user information. The parser skips them by their lengths and
   delimiters and copies nothing of them; the bytes they passed through in the relay, the sniff buffer (its capacity
   set once, so that it never moves) and the relay's own buffer, are zeroed when dropped, and a hello's buffer is
   started only for a stream whose first byte is TLS's `0x16`, so no other first bytes are copied (S-m6).
   The packet path before the relay is not zeroed: the tunnel's packet buffer, the fragment reassembler and a held TCP
   Fast Open SYN's payload (an accepted limit below). The one fact said is that a password for
   this proxy crossed the network unencrypted (RFC 1929's, or HTTP's `Basic`), never the password. Tests prove that
   none of them reaches a flow, the log, the live view, the debug dump, logcat or the crash buffer; the fuzz seeds are
   synthetic.
3. **Skipped:** the user's circumvention tool's own flows, and the apps Advanced chains through it or sends through a
   WireGuard tunnel: what they carry is the tool's (ADR 0046, decision 3), and a tool whose upstream is plain SOCKS5
   or HTTP would otherwise show every chained destination under its row.
4. **Android's proxy setting** (the global one, and each network's), which every app that follows it shares, is told
   apart from an app's own: the network part hands the engine its hosts and ports at each start and change, and a
   declared proxy at one of them says "This is the proxy in Android's settings, which other apps can use too." A proxy
   given by a PAC file is found by Android on the phone's own loopback, which never enters the tunnel: not seen.
5. **Messengers' proxies are inferred, each with substitution,** and worded "Through a KIND at ADDRESS. Inferred from
   where and how it connects.", followed by a sentence that where it goes from there is encrypted and cannot be seen.
   The clients are their makers' own packages (`data/messengers/clients.tsv`). A proxy is named only while, in the
   same window (the live view's ten minutes in time since the phone started, sleep included, or while one is open),
   the app made no TCP connection to its maker's own network. A direct connection within ten minutes after a naming
   takes the name back (F2): the flow becomes what it would have been, its name, address and place in "Now",
   un-hidden, the hello kept as a cover naming it, the segments that wait for their states rewritten; the log's
   records of an inferred flow are held back for those ten minutes (at most 1,024 at once) and rewritten on a
   take-back, so that no record says what the engine took back. The instants of the direct connections cross to the
   next engine at a hand-over, so a CDN flow opened right after it is not named.
   - **Telegram's MTProto:** a flow to an address outside Telegram's published ranges (`data/messengers`, its
     `cidr.txt` byte for byte, each fetch recorded with its date, SHA-256 and the ranges added and removed) whose
     first 64 bytes pass the obfuscated transport's rules (the excluded prefixes and bytes 4 to 8, not a length; and
     random-looking: 3 to 5 bits set a byte on average, 16 to 48 of the 64 bytes with the high bit set, and not UTF-8
     text: a random header misses that 2.4 times in 100,000, measured 26 in 1,000,000), or whose TLS hello's server
     name is untied to this address (fake TLS, below). Any TCP flow of the app to its ranges, even one refused, is a
     direct connection; a call's UDP to a relay is not one (an accepted limit below). A CDN data centre reached while
     the app goes directly is therefore no proxy.
   - **When a hello is untied** (F3): no answer the engine passed and still holds gave the name this address (an
     address keeps up to eight names given before its last, each until its own answer ends), and the app, or Android's
     resolver for it, did not look the name up through the tunnel within the names' lifetime: mtg's cover is never
     looked up. The rule counts only where the engine sees the app's lookups: Private DNS not strict on the tunnel's
     network, and a lookup of the app through the tunnel in the window. Otherwise an untied hello is no evidence, and
     only the byte rules and substitution decide. A hello that is no cover, and one while substitution holds, names
     its flow as any does.
   - **The cover name never names the flow.** For Telegram's and WhatsApp's clients, a hello whose name no DNS answer
     the engine passed tied to an address outside the maker's network, while the rule above counts and the flow is
     named the proxy, does not rename the flow: "Telegram → google.com" never appears under its proxy. The name is
     kept as the cover it is ("Its connection sent the name NAME.", followed by a sentence that no DNS answer passed
     through the tunnel gave that name this address), with, where the owners' tables name both, the company behind the
     name and the network's: the owner test supports, never decides (mtg advises a cover hosted with the proxy's own
     provider).
   - **WhatsApp's proxy:** WhatsApp's clear header (`W` `A` and two bytes, or `E` `D` `0` `1` with its routing data,
     as whatsmeow and Baileys write it) to an address outside Meta's networks, on any port (5222 and 80 by default; the
     client lets the user set others), or a TLS hello whose name no DNS answer tied to such an address (the proxy's 443
     and its media ports, 587 and 7777, which carry `*.whatsapp.net` names). Meta's networks are AS32934 and AS63293,
     which Meta's peering page names, through the organisation table, or a DNS name of WhatsApp's; an address of the
     user's own network is no company's. Without the organisation table nothing is inferred elsewhere. A link preview
     or a backup reaches a name a DNS answer tied to its address: not a candidate, and substitution besides.
   - **Signal's proxy:** decided by names. A TLS hello of a Signal client whose name is not Signal's own
     (`signal.org`, `signalcaptchas.org`), not one of Signal's fronts (the names its source sends to reach Signal
     through Google's and Fastly's networks), and not a third party it reaches itself (Stripe, hCaptcha, its donations'
     `signaldonations.org` and PayPal, `debuglogs.org`, MobileCoin's hosts), nor a name it reaches within ten minutes
     after such a third party: its web view opens the payment's pages from there, a card issuer's 3-D Secure page among
     them, whose names no list can hold (F7). Signal's fronting is its own circumvention and counts as a
     direct connection to Signal: a set proxy turns it off (`SignalServiceNetworkAccess.kt`, `getConfiguration`, at
     the pinned commit `aa38b25`), so a front seen means no proxy. Signal has no network of its own, so nothing is said
     of its maker's network.
6. **Who runs it is never said.** "An address in the network of ORGANISATION. Who runs it is not known." or "On your
   local network. Who runs it is not known." Where Datapavan can tell that the network is not the app maker's, it says
   so: for Telegram (outside its ranges) and WhatsApp (outside Meta's networks) always, the network unknown or the row
   left out included; for a declared proxy only where the owners' tables name both the network's company group and the
   app's (ADR 0020) and they differ. Never "the operator".
7. **The confidence, in words,** shown whether or not the switch is on (F5): "Read from the connection" for a declared
   proxy; "Inferred from where and how it connects" for a messenger's. What Datapavan never knows is said, in "What
   this view cannot see": who runs a proxy, where an inferred proxy sends the traffic on, and whether the user or the
   app chose it.
8. **An app's own proxy is circumvention, as chaining is.** The proxy's address and the destination asked for follow
   the one switch, "Log where apps connect through your tool, WireGuard or a proxy" (W6's switch, F6), in the log and
   in "Now": while it is off (the default), a confirmed or inferred proxy's flow keeps only its kind, the facts that
   name nothing (Android's setting, a password unencrypted, outside the maker's network) and its trackers' marks, at
   an address of zeros; turning it off strips the open flows, the segments that wait for their states and the live
   view at once, and the place a flow's first bytes were counted under goes when the request names it. The trackers'
   marks are matched in the engine on every name the flow carried before anything was stripped (its address's DNS
   name, the outer hello's, the destination asked for, an inner hello's) and kept by εxodus id alone, which names a
   tracker's company, never an address or a name (F1). The switch is drawn wherever anything is left out for it, and
   every left-out row links to it. That under ADR 0047's profile nothing of it is recorded or shown is W9's work, a
   must in DESIGN.md's W9 row: no engine path reads the profile yet. A release's dump writes the six proxy counters as
   `-`. The substitution's state is a few instants and name hashes per messenger, in memory. Nothing reaches a
   summary, the widget or the tile (ADR 0046, decision 3).
9. **The records.** The log's records are version 5 and the live view's snapshot version 4, each with a proxy block
   after the route (`log::push_proxy`): the kind, the flags (bit 4: the flow left out), the destination asked for, the
   proxy's own name, its network's organisation, the cover and the trackers' ids (at most eight); six counters are
   appended (declared, with a password, inferred, substituted, taken back, covers kept out). The network part's Kotlin
   side reads version 5 and still reads 1 to 4.

## Consequences

- Advanced says, for the first time in the field as far as the research found, where an app went through its own
  proxy and where that proxy is, for the declared kinds with no guess at all.
- **Accepted limits**, each with its reason:
  - Proxies inside TLS or QUIC (HTTPS proxies, Signal's own inner TLS, QUIC-based proxies): their request is encrypted.
    Signal's and WhatsApp's are inferred instead; others are not seen as proxies.
  - Apps pointed at a proxy on the phone itself (Orbot's SOCKS port, a PAC proxy): loopback never enters the tunnel, so
    their traffic shows as the proxy app's, as chaining's tool.
  - Only the first request on a connection is read: a plain HTTP proxy's later requests on a kept-alive connection to
    other hosts are counted under the first.
  - An inferred proxy's destination beyond it is encrypted: Advanced shows the proxy, not where it leads.
  - A WhatsApp proxy given by a name that Android's resolver answered, reached over TLS on 443, sends a name a DNS
    answer tied to its address: it looks like a link preview, and is not named (the same proxy on 5222 or 80 is).
  - Substitution reads ten minutes: a user who turns a proxy on within ten minutes of a direct connection sees it named
    only after them; one who turns it off sees it taken back at the first direct connection.
  - Forks of the three clients are not recognised until a row of `clients.tsv` names them. The list, as Telegram's
    ranges and the names, is compiled into the engine and kept out of the data pack, as the resolvers are (the network
    part's data alone): an update of any of them needs an app release (S-n4).
  - **An app that runs a proxy-shaped server of its own** (F1): a server that answers a SOCKS or `CONNECT`
    request as a proxy does confirms it, so the app can leave its destination out while the switch is off. Its bytes,
    its states and its trackers' marks stay; turning the switch on shows the rest. The app, not Datapavan, declares a
    flow proxied.
  - **A hello's tie needs the app's lookups** (F3): under strict Private DNS, or for an app whose lookups do not pass
    through the tunnel (its own DNS over HTTPS), a fake-TLS proxy is not inferred from its hello; Telegram's obfuscated
    start and WhatsApp's header still are.
  - **A Telegram fake-TLS proxy whose cover resolves to it** (S-m4): the engine passed that answer, so the name is
    tied and the flow is named by it with no proxy, as for WhatsApp's below. The open research is Telegram's hello
    template.
  - **Substitution counts TCP connections alone** (R-m5): with "use proxy for calls" off, Telegram's calls reach its
    relays over UDP directly while its chats go through the proxy; those datagrams do not cancel the proxy's naming,
    which is right for the chats. That Telegram makes no TCP connection to its ranges while a proxy is set is read
    from its behaviour, not from its documentation: where it did, its proxy would not be named (a false negative).
  - **The take-back's window** (F2): ten minutes after a naming; a direct connection later, as when the user turns the
    proxy off, takes nothing back, as the proxy was real until then. Past 1,024 held-back records, the oldest is
    written as it is.
  - **Signal's window after a third party** (F7): ten minutes; a 3-D Secure challenge longer than that, or a page
    Signal opens without a listed host before it, is named its proxy while Signal goes through one.
  - **The packet path is not zeroed** (S-m6): the tunnel's packet buffer, the fragment reassembler and a held Fast Open
    SYN carry a credential's bytes before the relay; zeroing them would cost every packet a write.
  - The false positives that need a maker's own network (a Telegram CDN data centre beside its ranges, WhatsApp's link
    previews and backups) are checked in the engine's tests and its network lab, not on the emulator, which must reach
    no outside server.
- **Checks:** unit tests for each parser and rule, fuzzing of the parser (`fuzz_targets/proxies.rs`, synthetic seeds),
  two network-lab tests through the whole engine on Linux's TCP stack (an address of Telegram's ranges on the lab's own
  loopback), the proxy lab (`scripts/proxylab.sh`: microsocks, tinyproxy, mtg built from v2.3.0 at a pinned commit, on
  a network with no way out), and the emulator's `proxies` shard (`scripts/verify-proxies.sh`), which CI runs and in
  which a skip fails: the project's own fixture under package names of its own, which only debug builds add to a
  messenger's clients.
- **Size:** the network part's native library grew by 45,520 bytes on arm64-v8a, 32,832 on armeabi-v7a and 49,232 on
  x86_64 in part 2a (built alike from `main` and from it before part 1: 1,707,608, 1,465,644 and 1,981,256 bytes
  before; 1,753,128, 1,498,476 and 2,030,488 after). After the fix round, rebased onto `main` with part 1 (whose fix
  round measured 1,695,200, 1,256,752 and 1,933,072 bytes, stripped, inside `core`), the library in Advanced's release
  APK 1,772,296 bytes on arm64-v8a, 1,312,792 on armeabi-v7a and 2,017,976 on x86_64, under the 2 MiB gate (2,097,152
  bytes) of each ABI, which is unchanged: x86_64 79,176 bytes under it. Against part 1's figures, built otherwise,
  this part with its fix round adds about 77, 56 and 85 KB.
- **Frontier research, open:** Telegram's fake-TLS hello across versions, told from the device without a JA4 database;
  encapsulated handshakes seen from the device (Xue et al., USENIX Security 2024) for Signal and WhatsApp; and how
  people read "read from the connection" against "inferred", with real users.

## How it is built (W8, part 2a)

- `core/net/src/proxies.rs` (the parsers), `messengers.rs` (the data), `engine/proxied.rs` (the rules, substitution,
  the sniff and its zeroing), `engine/tcp.rs` (the relay reads through the sniff), `log.rs` and `snapshot.rs` (the
  formats); `core/network-jni` (`nativeProxies`, `nativeMessengerClients`, `nativeFlowProxies`).
- The network part (`android/network`): `NetworkVpnService.applyProxies` (the messengers' UIDs, Android's proxy
  setting, again at package and proxy changes), `activity/ProxyFacts.kt` (what a row says, a pure function), the
  screens "Now" and the history, the strings in `strings_untranslated.xml` until ADR 0030's translation, held to
  ADR 0025's words by a test.
- Data: `data/messengers` (CC0 for the project's lists; Telegram's `cidr.txt` states no licence, ADR 0015's record).

## Fix round (2026-11-21)

One review round ran with two independent reviewers (security and engine; screens, words and checks), read only, on
`5885669..da15d69`. The decisions below were taken by **the coordinator, under the maintainer's word of 2026-11-21**,
for the maintainer to confirm when this ADR is accepted; the builder of the fix round wrote them in, each with its
reason.

- **F1. The reply confirms, the app declares** (security M1). A request of about 40 bytes, ignored by an SDK's own
  server, turned any flow into `0.0.0.0:0` with no name and stripped its trackers' marks. Reason: only the server's
  answer shows that a proxy took the request; a plain request cannot be confirmed so, so its flow is never hidden for
  it. The marks are taken in the engine from every name the flow carries before anything is stripped, and kept as the
  company only while the switch is off, so that what a proxy hides never hides a tracker. The residual limit is stated
  above: an app that runs a proxy-shaped server of its own.
- **F2. A take-back is complete** (security M2, screens m1). Reason: a name taken back that stayed hidden made the
  history say "Sent through your circumvention tool" of a flow that was not. Of the two ways the brief allowed, the
  records of an inferred flow are held back for the window of take-back and rewritten on one, rather than a correction
  record the readers apply: it changes no format, reader or day file, and keeps the log's bounds (at most 1,024
  records held, ten minutes each). The history now tells a flow left out for a proxy, by its recorded kind, from one
  sent through the tool, by its recorded route.
- **F3. "Tied" is tested from the name's side** (security M3, screens M1). Reason: one name per address made a
  re-pointed shared address (Telegram's `www.youtube.com` and `i.ytimg.com`; WhatsApp's backup on `www.googleapis.com`
  and `oauth2.googleapis.com`) a cover, on every hello of a user on a real MTProxy. Where the engine cannot see the
  app's lookups the rule is no evidence at all, rather than a guess.
- **F4. The cover line states facts only** (screens M2): ADR 0025 decision 4 bans words that imply intent; the word
  test also refuses "look like", "disguise", "pretend", "fake" and "hide".
- **F5. Confidence words always, "own" dropped** (screens M3): with the switch off, an inferred proxy was stated as a
  fact, and Android's setting was called the app's "own".
- **F6. The switch the screen points to is always there** (screens M4), one switch as the maintainer settled for the
  tool's row (ADR 0046): reworded to cover apps' own proxies, drawn in the tool's section, the WireGuard section, or on
  its own once an app's own proxy is seen since the engine started, and linked from every left-out row.
- **F7. Signal's own connections and its third parties** (screens M5, security m3): fronting counts as direct (a set
  proxy turns it off, verified at the pinned commit), the third parties are read from that commit (and PayPal's
  approval host from PayPal's own API specification, as Signal gets the URL from its server), and the 3-D Secure pages,
  which open in Signal's own web view (`Stripe3DSDialogFragment`, `PayPalConfirmationDialogFragment`), fall in the
  window after a third party.
- **Open, for the maintainer.** One alternative was weighed and left open: for an app that is not a messenger and does
  not use Android's setting or a proxy on the local network, its own proxy's connection could show as any flow's
  does, with only the destination asked for following the switch. That would close F1's residual limit, but departs
  from the maintainer's rule of 2026-11-19 for the tool's own row (ADR 0046): the servers follow the switch.

The minors and nits, as done: SOCKS4's printable user ID and SOCKS5's plausible methods (security m1); obfuscated2's
high-bit bound and text rule (m2); the fake-TLS cover that resolves to its proxy, an accepted limit (m4); the profile's
promise made W9's must, and the six counters gated on a debuggable build (m5, screens m4); the zeroing claim corrected
and the hello buffer started on `0x16` alone (m6); a destination asked for by address names its flow (screens m2); the
maker fact where the network is unknown (screens m3); Telegram's UDP calls stated as a limit and tested (screens m5);
PRIVACY.md and its page (screens m6); a random SOCKS user name searched for on the emulator (screens m7); the hand
mutants recorded below (screens m8); an `@` after the authority refused (n1); `update.py`'s bounds (n2); substitution
on the time since the phone started (n3); the client list's place corrected above (n4); the snapshot's comment (n5);
the credit for Signal's fronting given to names, and the history's address parsed once (screens' nits).

**Checks of the fix round.** Each fix has a test that fails when the fix is reverted (the hand mutants below are those
reverts and more). The engine's unit tests, the network lab's proxy tests (four, a hand-over among them), the network
part's JVM tests (`ProxyRowTest`, `LogSwitchTest`, `HistoryTest`, `ProxyFactsTest`, `TrackerMarksTest`), the proxy lab
and the emulator's `proxies` shard.

**Hand mutants**, in cargo-mutants' manner, on the code as it is after the fix round (part 2a's first 27 were not
recorded one by one, so they were run again in this set rather than recovered):
66 in all, 63 killed and 3 argued equivalent.
- *The parsers* (`proxies.rs`, 18): SOCKS5's list of more than ten methods (equivalent: more than ten methods, each 0 to
  9, none twice, cannot be, and the rule of none twice refuses them), a method outside 0 to 9, one offered twice, the
  method used not offered; SOCKS4's user ID of any bytes; the reply's method, RFC 1929's refusal, SOCKS4's refusal,
  `CONNECT`'s `407`, a plain request confirmed; an `@` after the authority; the high bit's bound, the text rule, the
  bits' average, an excluded prefix, bytes 4 to 8 zero; an empty password said to cross; a scheme not `Basic`.
- *The rules* (`proxied.rs`, `names.rs`, `naming.rs`, `logbook.rs`, `now.rs`, `log.rs`, 33): a request named before
  its reply; too few bytes taken as a confirmation (equivalent: `confirmed` reads at most 12 bytes, so it never
  answers "not yet" at 16); a plain request left out whole, its place dropped from "Now", hidden when the switch turns
  off; no trackers' marks on a confirmed proxy, none from an inner hello, none from the destination asked for; an
  address asked for naming nothing; a take-back leaving the flow hidden, its place's proxy, the segments that wait,
  the records held back; nothing held back; a take-back past its window; the instants not carried, an open direct
  connection not handed as now; strict Private DNS ignored, no lookup needed, a looked-up name not tied, only the last
  name of an address tied; a hello lost under substitution; Signal's fronting not direct, no window after a third
  party; a stream not read for proxies copied (equivalent: the hello buffer is dropped before any byte when the stream
  does not start with `0x16`, which the copy counter shows), an inner stream not TLS copied, a hello buffer started on
  any byte; the left-out bit and the trackers not written; the setting's port, a proxy on the local network, the
  substitution's window, a cover not kept as one.
- *The network part's Kotlin side* (15, all killed by its JVM tests): `ProxyFacts` (kept read from the address, a
  plain request called an HTTP proxy, the maker said where the companies agree, a cover of the network's own company,
  the dump's counters in a release), `proxyRow`'s branches (the confidence line, Android's setting, the password while
  left out, a plain request's link, the maker where the network is unknown, the cover line), `LogSwitch` (the switch
  alone), `History` (a direct segment said through the tool), `TrackerMarks.byId` (the name's column) and `LogRecord`
  (the left-out bit).
Twelve survived the first run, one did not build and two did not apply as written: tests were added for each that was
not equivalent (the parsers' plausible methods with 0 offered, the bits' average alone, an empty password, a five-letter
scheme; the destination asked for alone marking a proxy, the held segments of a take-back, an open direct connection a
minute later at a hand-over, a request alone in a read before its inner stream, a plain request's place placed in "Now"
before the switch turns off), and each was run again and killed, as were the other three, written anew.
