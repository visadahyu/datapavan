# 0053. Tracker blocking: hosts graded by what they do, the same in every app, refused before a byte leaves, undone in one tap

- Status: Proposed (built on `watch-w8c`, W8 part 3a, 2026-11-21; awaits the maintainer's word). The decisions
  marked *(coordinator)* were taken by the coordinator of W8 from the audit of the first brief, and are for the
  maintainer to confirm when this record is accepted.
- Date: 2026-11-21
- Decided by: drafted by the builder of W8 part 3a with AI help, under the session's grant (go on by the roadmap at
  the S-tier bar), from a brief audited once before the build; the maintainer accepts or changes it.
- Builds on: ADR [0020](0020-same-company-trackers.md) (decision 1: a fact, never a discount), whose reasons it extends
  to blocking; [0025](0025-guided-check-and-traffic-facts.md) (decision 4: the words);
  [0036](0036-ip-to-organisation-dataset.md) (an address's organisation hosts, it does not run);
  [0038](0038-dns-of-chained-apps.md); [0046](0046-live-activity.md); [0047](0047-profile-for-phones-that-may-be-searched.md);
  [0015](0015-dataset-licences.md) (the new dataset).
- Amends: ADR 0046, decision 4 ("Trackers are named only from the εxodus network signatures"), as decision 1 (e)
  says; ADR 0047's table of what is kept, by one row (decision 8).

## Context

DESIGN.md's W8 row: "Tracker blocking stays off until the user turns it on, and is undone in one tap." Advanced already
names every app's flows by app, server name, DNS answer and the address's organisation, and marks tracker
destinations from the εxodus network signatures (ADR 0046).

What the field does (research of 2026-11-20 in the private strategy repository, `tracker_blocking.md`):
- **DuckDuckGo App Tracking Protection**, the leading design without root, reads each flow's name from DNS, HTTP or
  the TLS server name, matches it to a list of tracking companies, exempts an app whose owner is the tracker's owner,
  keeps per-app exceptions for known breakage, and leaves out browsers and apps that do not work through a VPN. The
  undo is a per-app switch in a list of apps. TrackerControl made the same design its default ("Minimal") in 2026.
- **NetGuard** blocks by address; addresses that many names share cannot be told apart. **Pi-hole's** operators
  report that "no data" is taken more quietly than "no such name", and its default is the null address.
- **No product documents a timed allowance**, and no usability study of an undo, or of "this app may break", was
  found. No independent study of App Tracking Protection's, TrackerControl's or RethinkDNS's breakage was found.

The first brief's audit (one round, 2026-11-21) found what makes a plain port of that design fall short:
- **εxodus's signatures were made to detect, not to block.** `\.facebook\.com` is the signature of Facebook Login,
  Share and Places as well as Ads; 172 of εxodus's 432 trackers have no network signature at all; and Firebase
  Analytics, in about 58 % of apps, sends to `app-measurement.com`, which its signature omits.
- **Android keeps one DNS cache per network, keyed by the question and not by the app** (`res_cache.cpp`): a negative
  answer kept for a few seconds carries one app's block to another, and an allowed app's answer back.
- **The engine wrote a connection's first bytes upstream before it read their name**, and sent a QUIC flow's
  datagrams as they came, so half of a two-datagram hello left before its name was known.
- **The app's own company.** DuckDuckGo's exemption, made against breakage, passes Google's tracking in Google's
  apps. ADR 0020 forbids ownership to excuse a tracker; its decision governs the scan's findings, written before
  blocking, but its reasons carry over.

## Decision

### 1. What is blocked: hosts graded by what they do (`data/blocking/`)

(a) **Datapavan's own table**, CC0, in the signed data pack: `hosts.tsv`, one row per host, keyed by the host and the
SDK's Maven coordinate, never by an εxodus id *(coordinator)*. Each row holds the SDK's Java package prefix, its grade
(`block`, `keep` or `code`), the condition of a `code` grade, the host's function in one line, the kind of its
evidence (the SDK's documentation, its open code at a pinned commit or tag where the host is a constant, Tweasel's
CC0 tracker wiki endpoint by endpoint, or the vendor's own list of hosts to allow through a firewall), the source and
the date, as `data/sdks` records its evidence. Hosts are never taken from the εxodus signatures. **Why:** a host's
function, not its domain, decides whether blocking it breaks the app; a row says what the host does and how that is
known, and can be disputed through `data/CORRECTIONS.md`.

(b) **Grades.** `block`: the host serves only tracking, analytics, attribution, advertising, or crash and performance
reports. `keep`: it also serves the app itself (sign-in, a database, storage, push, the settings the app needs, a
deep link the app routes on, a request to erase the user's data). `code`: it serves both, and the app's own code
decides *(coordinator)*: `graph.facebook.com`, where App Events and Login both post, is `block` in an app whose εxodus
code signatures (the audit's scan) show the analytics or ads SDK but not Login, Share or Places, and `keep`
otherwise, an app never scanned included. **Why:** that is function, not owner, and the one evidence on the phone of
what the app uses the host for.

(c) **Exceptions** (`exceptions.tsv`: package and signing certificate, host, reason, source) keep a `block` or `code`
row for an SDK vendor's own app whose own function uses the host *(coordinator)*: Facebook's apps and Meta Ads Manager
read Facebook's own Graph API. Matched by package and certificate, never by package or company alone (ADR 0020,
decision 4). **Why:** the host is that app's own service, as a sign-in host is another app's.

(d) **Matching** on label boundaries *(coordinator)*: a row's host names itself and every name under it, never a name
that merely contains it, unlike εxodus's `re.search`; where rows nest, the narrowest names the name, so that a `keep`
row under a `block` one keeps what it names. Names compare without regard to ASCII case. Rows never name a broad
shared parent (`googleapis.com`, `google.com`, `facebook.com`, `amazonaws.com`, `cloudfront.net`), which a test holds.

(e) **ADR 0046's decision 4 is amended** *(coordinator)*: εxodus names the tracker, and its hosts come from εxodus's
signature or from the graded table with a primary source. A row joins its εxodus tracker at run time by its package
prefix against the εxodus code signatures (one is a prefix of the other): a collective database (ODbL 4.5a), not a
derivative, and the table holds no εxodus data. **Why:** without it, Advanced could neither block nor mark
`app-measurement.com`.

(f) **Other lists are leads only** *(coordinator)*: DuckDuckGo's tracker lists and privacy configuration (CC BY-NC-SA
4.0 by its own README, not Apache-2.0 as the research note had it), Disconnect's and EasyPrivacy's (share-alike). The
table's builder opened none of them: every row was read in a lane-1 primary source.

(g) **Hosts known only from closed SDK binaries wait for lane 2** (ADR 0051): reading them needs decompiling tracker
SDK samples. They are listed in `waiting.tsv`, and the analysis machine's brief is in the maintainer's private notes
(`lane-2/briefs/2026-11-21-w8c-closed-sdk-hosts.md`). Nothing was guessed.

(h) **Coverage, weighted by εxodus's prevalence** *(coordinator)*: `data/blocking/coverage.py` weighs each tracker by
the number of apps εxodus finds it in. The 50 commonest trackers are to get every host they send to that a source
names; a tracker counts as covered when all of them are graded and it waits for nothing. The first table's figures
are in "How it is built".

### 2. No discount: the same rows in every app

A `block` row is blocked in every app blocking covers, the tracker's own company's included; a `keep` row is blocked in
none *(coordinator)*. The decision rests on the host's function and the app's own code, never on who owns the app:
nothing in the engine or in what Kotlin hands it reads an app's or a tracker's owner. ADR 0046 2 (d) takes the
tracker's mark from a destination of the app's own company; that rule keeps governing the εxodus marks, and never a
row of this table: a blocked flow is always shown with its row. **Why** (ADR 0020's reasons, extended): the law counts
another company of a group as a third party, the Digital Markets Act forbids combining data across a gatekeeper's
services without consent, and a familiar brand reassures people who would not be reassured otherwise. DuckDuckGo's
exemption exists against breakage; code-dependent grades and evidenced exceptions remove that need without excusing
anything. Test: an app the owners table gives to Google reaching an AdMob host is blocked.

### 3. DNS

(a) **Where the decision sits** *(coordinator)*: before part 1's cache and its stale window, for every record type,
HTTPS and SVCB included, on every way the engine answers an app's lookup: the encrypted resolver, the network's
resolver, a chained app's stand-ins and other questions, DNS over TCP to the tunnel's DNS address, a
WireGuard-tunnelled app's lookups, and the engine's cache of the network's answers. A question a row blocks for the
app is answered at once and asks no one.

(b) **The answer**: "no data" with an SOA in the authority section, its time to live 0 and its `MINIMUM` 0
*(coordinator)*. Never the null address, which sends the app to the phone's own loopback, outside the tunnel, where
the tools listen; never "no such name", which Pi-hole's operators report clients retry harder.

(c) **Android's cache**: while blocking is on, every positive answer for a name a row grades `block` or `code` reaches
every app with a time to live of 0 too *(coordinator)*, so that no app's answer reaches another's lookup, and an undo
or a block is not delayed by a cached answer.

(d) **CNAME chains**: each name of an answer's chain is matched, which closes CNAME cloaking, for apps whose names
the engine resolves.

(e) **Limits, stated**: chained apps' names are resolved by the user's tool (ADR 0038), so only the question's name is
matched, never a chain; strict Private DNS and apps' own encrypted DNS take the DNS path away, leaving the connection
path.

### 4. Connections: no byte of a blocked flow's payload goes upstream

(a) **Hold for the hello** *(coordinator)*: the app's direction is held while its start reads as an unfinished TLS
hello or plain HTTP request head, at most 16 KiB and 1 s, and a QUIC flow's datagrams while their Initial packets read
as an unfinished `ClientHello`, at most four datagrams and 1 s: a post-quantum hello spans two segments or two
datagrams. Protocols in which the server speaks first send nothing first and never wait. The name is read from the
hello, from plain HTTP's `Host`, or, for a chained app, from its stand-in's name before the SOCKS request goes to the
tool, and decided before anything is written upstream or to the tool. A hold that runs out sends what it held, unread.

(b) **Blocking by address** *(coordinator)*: only through the ask-first path, so that Android names the app before
anything leaves, and only for an address that an answer the engine passed, still held, tied to blocked names alone, and
never inside a network that the organisation table does not name as a company's own: a CDN, a cloud or a host sells
room to others (ADR 0036). Google's networks host Google Cloud, so a Google tracker is never blocked by its address.

(c) **The upstream connect is not deferred.** The audit allowed it only for 443 flows to addresses tied to no name,
with a timer, "if at all". **Accepted limit, with its reason:** deferring the connect costs correctness, not speed:
the app's stack would see a handshake the server never made, Happy Eyeballs (RFC 8305) would race a connection that
is not there, and a refused or unreachable server would look open. So the TCP handshake of a flow later refused by
its hello reaches the tracker's server: the phone's address and the time reach it, never a byte of payload.

(d) **The refusal**: TCP gets a reset, at once, never a timeout; QUIC gets ICMP "port unreachable", as ADR 0038
refuses QUIC elsewhere, so that Cronet falls back to TCP at once, where the hello is read again.

(e) **Re-blocking resets open flows** *(coordinator)*: a flow whose name a row names is decided again at each of its
later bytes, either way, so that a block set again, or an hour that ran out, resets it at its next byte (HTTP/2
pools many requests on one connection).

(f) **WireGuard-tunnelled apps** are blocked where the engine has their names, at their lookups to the tunnel's DNS
address. Their connections run end to end inside the tunnel (ADR 0035), so their hellos are not held. **Accepted
limit.**

(g) **Coalescing**: a tracker request coalesced onto a `keep` connection (HTTP/2's connection reuse) is not seen.
**Accepted limit**, frontier research.

(h) **Through the network's own proxy** (the proxy record's unit S2, [ADR 0052](0052-apps-built-in-proxies.md),
decision 11): blocking decides before the proxy has anything of the app's. A name blocked at its lookup is answered
empty, and no connection follows; a flow blocked by its address is refused before any upstream, the proxy's included;
a flow blocked by its hello or its plain request is held as (a) says, so the proxy gets the `CONNECT` by address and
then an empty tunnel, which is what (c) gives the server on a direct route, a connection and no payload; and a request
by name never carries a name blocking refuses for the app. Checked in the network lab (a blocked hello reaches neither
the proxy, which read the `CONNECT` and nothing after, nor the server, and the app gets a reset) and on the emulator
(the tunnel closed with 0 bytes each way, the flow blocked by its hello under the route through the network's proxy).

### 5. What is never blocked, or not by default

(a) **Browsers** are left out by default, and the screen says so; the user may include them *(coordinator)*. A browser
is an app that resolves a browsable `https` intent to a host no app claims, counting only intent filters with no
authority, so that App Links apps do not count. **Why:** a browser opens any website, whose third parties are the
site's, not the browser's.

(b) **Not covered by this part**, and the screen says so: apps that came with the phone, UID 1000 and Google Play
services. Flows Android names no app for, and Datapavan's own, are never blocked.

(c) **The user's tool** (ADR 0046, decision 3): its connections are never blocked by their hello, since a cover name
may be any popular host, and a wrong block cuts circumvention. An option, off by default, blocks the tool's own SDK
lookups by DNS alone *(coordinator)*, because Advanced protects data from the tools too.

### 6. The undo

(a) **On the app's row**, in "Now" and in its history: one tap, "Allow trackers in this app", for an hour, and one tap
"Block trackers again" ends it sooner *(coordinator)*. Expiry is checked at each decision, on the time since the
phone started, with no alarm. An hour, not a plain allow: an app allowed for good stays unprotected after the breakage
it was allowed for is over, and no product documents a timed allowance, so this is new in the field; the words are
tested with real users (decision 10).

(b) **Per row**: under the app, each row it reached has its own allow, until blocked again, or one per company where
one εxodus signature names several of its trackers.

(c) **A global pause**: ten minutes, naming no app, on the network screen *(coordinator)*. Breakage shows inside the
broken app, and no notification may name it (ADR 0046). **The tile** that would carry it is W9's and does not exist
yet: the pause joins it there. Ten minutes, not an hour: it lifts every app's blocks at once.

(d) **Late sends**: where an allow is offered, the screen says that apps may send what they held back once allowed.

(e) **How fast**: within seconds, not "at once": apps keep a failed lookup for a moment (Android's runtime about two
seconds), and the screen says so.

### 7. Words (ADR 0025, decision 4)

Lookups answered empty are counted apart from connections refused. A tracker is named as ADR 0046 names it, with its
company only where the owners' table gives one: a form with no company for the many that have none, and the row's
host where no εxodus tracker joins it. The word "grade" never appears on a screen. A `keep` row the app reached is told
as a fact ("Not blocked: this host also serves the app itself."). Nothing new reaches a summary or the widget; the tile
will carry only the pause.

### 8. What is kept

(a) **The log**: a blocked flow is a flow with a blocked state (the log's version 6: outcome 4, and the SDK of the row
that blocked it).

(b) **Chained apps**: their rows follow "Log where apps connect through your tool, WireGuard or a proxy": while it is
off, the row's SDK, which names a tracker and its company, is kept, and the host is not. A circumvention tool's own
rows follow R10 (ADR 0046, decision 3, the tool's own row; the proxy record's unit D, answering its brief's
question 13): the SDK always; the host with the switch, with the user's choice for that tool, or where the trackers'
signatures name it, since a tool's connection to a tracker is kept in full.

(c) **The profile** (ADR 0047): allowances are kept behind Advanced's lock and wiped by a wipe, as the apps left out
of the tunnel are (a new row of ADR 0047's table). Nothing of blocking is recorded under it: its counts are in memory
and cleared with the live view, and the log does not run. This joins W9's must in DESIGN.md.

### 9. Checks

Unit tests for each of the above, fuzzing of the table's reader and the `Host` reader against a plain search, hand
mutants recorded below, and the emulator's `blocking` shard (`scripts/verify-blocking.sh`), which CI runs and where a
skip fails: the project's own fixture under two packages and as a browser, a debug-only row for the lab's names on
debuggable builds only, and the lab as the witness that no payload byte, and for DNS and QUIC blocks no connection
and no datagram, reached it. The native library stays within its 2 MiB gate per ABI.

### 10. What only real apps can show, waiting for the maintainer

Sessions of ordinary apps on the A40 with blocking on: breakage, each traced to a row; the error of code-dependent
grades; SDKs' retries, and what they send after an allow; whether Firebase uploads under Play services' UID; the
shares of ECH and of apps' own encrypted DNS; and battery. The grades are only as good as their sources until then.
The words of the allow and the pause are checked with real users under ADR 0046's decision 11.

## Consequences

- Advanced blocks trackers by what each host does, the same in every app, and refuses a flow before any byte of its
  payload leaves; as far as the research found, no tool without root states its grades with their sources, holds a
  hello until its name is read, keeps Android's cache from carrying one app's answer to another, or offers a timed
  undo.
- **Accepted limits**, each with its reason above: the TCP handshake reaches a server later refused by its hello
  (4 c); WireGuard-tunnelled apps by their lookups alone (4 f); coalescing (4 g); chained apps' CNAME chains, strict
  Private DNS and apps' own encrypted DNS (3 e); browsers, preinstalled apps, UID 1000 and Play services by default
  (5); an app's own proxy's inner hello is not held (ADR 0052 reads it after the handshake); hosts that wait for
  lane 2 (1 g); the first flows after the network part starts, before the setting is handed over; and, at the moment
  blocking is turned on, the answers Android's cache already holds for blocked names, which keep their addresses for
  their time to live (no app can flush that cache; found on the emulator): their connections are still refused by
  their hello, and every answer after is kept for no time.
- The table needs keeping: SDKs change their hosts. It is re-checked at least every six months, as the other datasets
  are, and at each update of the lane-2 brief's results.
- Frontier research: grades that depend on code signatures and their error on real apps; data sent late, after an
  allow; tracker requests coalesced onto a `keep` connection; the words of the pause and the allow with real users.

## How it is built (W8, part 3a)

- **The table** (`data/blocking`, built by a research pass of its own on 2026-11-21): 94 rows, 82 `block`, 11 `keep` and
  one `code` (`graph.facebook.com`), across 33 SDK coordinates; evidence 57 from code at a pinned commit or tag, 26 from
  Tweasel's endpoint pages, 11 from vendors' firewall pages; 8 exceptions (Facebook, Facebook Lite and Meta Ads
  Manager, each certificate from Facebook's asset-links file as `data/owners/publishers.tsv` records it); 34 rows wait
  (23 trackers with no host from any lane-1 source, 11 partly covered). εxodus's server refused connections from the
  build machine that day, so prevalence was read from its tracker list as the Internet Archive kept it on 2026-11-13
  (SHA-256 in `SOURCE`), cross-checked against the statistics page of 2026-11-17. `coverage.py` gives: of the 50
  commonest trackers, 17 covered, 10 partly and 23 waiting; **59.7 % covered weighted by prevalence over those 50, and
  55.3 % over all trackers**. Most of the gap is advertising SDKs whose code is closed (AppLovin, AppsFlyer's hosts beyond
  its apex, Pangle, InMobi, Mintegral's ad hosts, Google AdMob's beyond `googleads.g.doubleclick.net`): the lane-2 brief
  names them. Judgement calls, each in its row: Branch's API hosts `keep` (their answers carry the deep links apps route
  on); Adjust's GDPR hosts `keep` (they carry the user's request to erase the device's data); OneSignal's API `keep`
  (push registration); Firebase installations and Remote Config `keep`.
- **The engine** (`core/net`): the table's reader and the `Host` reader in `blocking.rs` (`Table::parse`, `find` on
  label boundaries, `http_host`); the blocked answer in `answers.rs` (`blocked`) and the chain's names in `dns.rs`
  (`chain`); the decision, the tallies, the ties of addresses and the gates in `engine/blocks.rs` (`Blocks::blocks`
  the one rule; `Shared::lookup_blocked`, `answer_blocked`, `tie`, `address_verdict`, `blocked_flow`; `Gate::feed`,
  `QuicGate`), called from every DNS way (`resolver::answer` before its cache, `lookups::answer`, `Loop::udp`'s open
  and opening flows, `relayed` on the network's answers, the cache of direct answers, DNS over TCP by the app's UID,
  `tunnels.rs` for a tunnelled app), from `tcp::upstream`'s ask-first path (`blocked_before`: a stand-in's name, a
  tied address), from `tcp::relay` (the gate on the app's side, the row decided again on both sides), and from
  `udp.rs` (`gated` on both ways a datagram leaves for a peer, the refusal as ICMP "port unreachable" in
  `count_sent`). The setting comes whole through `network-jni` (`nativeBlockingTable`, `nativeBlocking`,
  `nativeBlocked`), which turns the allowances' times left into deadlines on the time since the phone started, and is
  carried to the engines to come with the chain. Four counters are appended: lookups answered empty, connections
  refused, of them by address, and starts held. The log's version 6 adds the outcome 4 and the row's SDK.
- **The network part's Kotlin side** (`android/network`, `blocking/`): `BlockingSettings` (the store, timed at each
  decision, a clock set back pulled in, `wipe()` for W9), `Coverage` (covered UIDs; browsers by
  `https://example.invalid/` with filters of no host; Datapavan itself, Play services, UIDs below 10000 and the tool
  left out), `Grades` and `TrackerCode` (the code grade from the audit's scan cache, joined to εxodus by prefix;
  exceptions by package and current or past certificate), `Handover` and `BlockingHandover` (the setting's text,
  handed at start, on each change, on an app's install or removal, and when the pack or the scan changes), the debug
  builds' lab row (`src/debug`, an empty one in `src/release`), and the screens (`ui/BlockingSection.kt`,
  `ui/BlockingLines.kt`, "Now"'s row, the history's rows). The link to the log's switch opens the network screen above
  "Now" without clearing it, and Back returns to the same row or history (`ui/LogSwitch.kt`).
- **Choices made in the build**: the per-app allow lasts an hour (one constant), the global pause ten minutes; a per-row
  allow lasts until blocked again; "Block trackers again" ends the app's hour and leaves its per-row allows; a shared
  UID is covered only where every package that holds it was installed by the user; a `code` row is kept for an app
  updated since its scan, and, under the profile, where there is no scan file.
- **Checks.** The engine's unit tests grew by 20 (the table, the `Host` reader, the blocked answer, the chain, the
  decision in every app and for the tool, allowances and the pause at a decision, two apps and one name, CNAME
  cloaking, the address tie outside clouds, the gate, a hello in two segments through the relay, a plain request, a
  protocol in which the server speaks first, a QUIC hello in two datagrams, a chained app's question and stand-in, the
  log's version 6), and the network part's Kotlin tests by 35 (the store and its expiry, coverage, the browser filter,
  the code grade and the exceptions, the setting's text, the words against ADR 0025's list, the log's reader, the link
  to the switch). The fuzz target `blocking` checks the table's reader whole or nothing, the matcher against a plain
  search of every row, and the `Host` reader: 4,293,071 runs in 121 s, nothing found. **Hand mutants** (2026-11-21),
  each a rule undone in the engine with the tests run: 16 of 16 killed: covered apps only, the tool by DNS alone, an
  allowance's expiry, the pause's end, the SOA's `MINIMUM` 0, every name of a CNAME chain, a time to live of 0 for
  answers that may be blocked, the hold of an unfinished hello, the relay's refusal, the hold of an unfinished QUIC
  hello, never by address in a cloud, label boundaries, a chained app's question, a stand-in's name before the tool, a
  block set again at the next byte, and the log's outcome code.
- **The emulator check** (`scripts/verify-blocking.sh`, the `blocking` shard), on the Android 15 emulator
  (`dp-api35-ci`), alone, 2026-11-21: passed. The blocked name got no address and the lab was never asked; one tap on
  B's row in "Now" let its lookup through within 1 s, and one tap blocked it again within 1 s; two apps, one name,
  within a second, each got its own answer, and the blocked one none after; a TLS hello in two segments and a plain
  request reached the lab's port with their handshake and no byte, and a QUIC hello in two datagrams sent no datagram
  and got "port unreachable", while the allowed app's were echoed; the CNAME to the blocked name was blocked; the pause
  lifted every block and "Block again now" ended it; the fixture's browser, and Chrome, were told as browsers, left out,
  and blocked once included; no notification named an app or a name of the run. Its first run found the limit of
  Android's cache at the moment blocking is turned on (Consequences); the check does not look the blocked name up
  before. The `dns` shard (`scripts/verify-dns.sh`) passed on the same emulator, alone, with the latency budget
  (ODoH p50 5 ms, p95 70 ms in the lab).
- **Size.** The network part's native library in Advanced's release APK (`scripts/check.sh android`, 2026-11-21):
  1,828,008 bytes on arm64-v8a, 1,351,480 on armeabi-v7a and 2,082,200 on x86_64, under the 2 MiB gate (2,097,152
  bytes); against `main` after part 2a's fix round (1,772,296, 1,312,792 and 2,017,976), blocking adds 55,712, 38,688
  and 64,224 bytes. **x86_64 has 14,952 bytes left**: the next unit that grows the engine needs a size pass first, or
  the maintainer's word on the gate (ADR 0035, question 3).
- **The size pass** (2026-11-24, before the next units grow the engine; build settings only, the engine's code
  untouched). At `fb15505` the library was 1,828,328 bytes on arm64-v8a, 1,351,800 on armeabi-v7a and 2,082,648 on
  x86_64, 14,504 under the gate (448 bytes fewer than above, from the units merged since). *Method:* each variant built
  as Gradle builds it (cargo-ndk, the same flags and environment, platform 29) and stripped as AGP strips it
  (`llvm-strip --strip-unneeded`), which gives the gate's figures to the byte, on all three ABIs; where the bytes are,
  from the sections (`llvm-readelf -S`) and from each function's size by crate in an unstripped build (`llvm-nm -S
  --size-sort`). On x86_64 the code is 1,681,866 bytes (the engine 564 KB, `core` 157 KB, tokio 154 KB, hashbrown 113
  KB, `alloc` 106 KB, `std` 104 KB, the JNI functions with the engine inlined into them 84 KB, aws-lc 71 KB, `std`'s
  backtrace symbolizer 67 KB, `jni` 67 KB), the unwind tables 159,312 bytes and their index 24,652. *The speed:* the
  engine's own measures in release builds on the development machine, pinned to four threads, each setting alternated
  with the other six times (`per_packet_cost`, a count, the live view, an answer among 4,000 peers), and the W2 CPU
  check (`scripts/network-lab/measure.sh`) on the Android 15 emulator with release Rust
  (`-Pdatapavan.rustRelease=true`), before and after in turn, five times each. Beside them ran another project's
  database work and, for a minute or two, the engine's tests, clippy and a Gradle build in other checkouts. The netlab
  tests and the `dns` shard build the engine in Cargo's dev profile, which none of the kept settings touch: they are
  functional gates here, and passed (the netlab's 66 tests; the `dns` shard on the Android 15 emulator, its lab's ODoH
  p50 9 ms and p95 48 ms, with Gradle builds of other checkouts beside it for part of the run), as did the network
  shard's check of the release build (`scripts/verify-network-release.sh`) on the emulator, with the folding below too:
  three times in turn with the build before it, the service alone at 45 to 46 MB of its 48 MB budget after and 45 MB
  before. Two earlier runs of the folded build, right after the CPU check and beside a Gradle build, read 48 MB and
  failed that budget, which has little room on this emulator.
  **Kept: x86_64's release library is linked without `.eh_frame_hdr`** (`core/network-jni/build.rs`), the sorted index
  of its unwind tables (24,652 bytes; leaving it out saves 24,848). The code is the same, 404,415 instructions before
  and after in the same order, 24,768 bytes lower, a whole number of 64-byte lines, so its speed should not move, and it
  did not: the engine's CPU per MB moved in the CPU check was 23.5 ms before and 23.6 after (medians; the before runs
  spread from 23.5 to 23.9, and one at 18.8), downloads at 96 and 89 Mbit/s, uploads at 93 and 92, four parallel
  downloads at 99 and 100, and the p50 of a connection and of a round trip 2.2 and 2.1 ms, 0.75 and 0.83 ms. The tables
  themselves stay, and Android's unwinder reads them without the index: `debuggerd -b` on the running engine, on the
  emulator, unwound the engine's thread through its six frames in the library to the thread's start, with the index and
  without, each frame at the same place 24,768 bytes lower; `scripts/check.sh android` now fails if x86_64's library
  loses its `.eh_frame` or arm64's its index. Only release builds: nothing in them unwinds its own stack, since a panic
  aborts, while a debug build turns a panic into a Java exception (the `jni` crate's `catch_unwind`), through the
  unwinder linked into the library, which looks for the tables through the index.
  **Kept too, on x86_64's release library: lld folds identical functions into one copy (`--icf=all`)**, the maintainer's
  word of 2026-11-24 after the options below: 11,024 bytes more. `--icf=safe` folds nothing here, since no object of the
  link, Rust's or aws-lc's, carries an address-significance table. Only code is folded, never data: lld keeps every data
  section unique for an object without that table, so distinct statics keep distinct addresses (`bytes` compares its
  vtables with its statics' addresses), and `.rodata` and `.data.rel.ro` keep their sizes. The functions that stay are
  the same instructions at other addresses, measured: in the CPU check, five times each in turn, the engine's CPU per MB
  moved was 23.44 ms before and after (medians; 23.3 to 23.8 before, 22.8 to 24.0 after), downloads at 95 and 97 Mbit/s,
  uploads at 91 and 92, four parallel downloads at 99 and 100, with another project's database work beside them; and
  `debuggerd -b` unwound the engine's thread as before. *The risk:* two functions with the same machine code share one
  address, so C code that compared function addresses would take them for one. Rust does not promise functions distinct
  addresses. Of aws-lc, lld folds today an empty AEAD cleanup (with an empty function of the NDK's `crtbegin`), two
  copies of jitterentropy's `jent_zfree`, and `CRYPTO_STATIC_MUTEX_lock_write` with `CRYPTO_MUTEX_lock_write`: aws-lc
  never takes their addresses, but the cleanup's, which it compares with NULL alone. An upgrade of aws-lc or GotaTun can
  bring a new fold, so its review (ADR 0035) links once with `-Wl,--print-icf-sections` and reads every fold from an
  object that is not Rust's. In a tombstone a folded function would show under the name of the copy that stays; the
  stripped library names only its 39 exported functions, and no two of them share an address.
  **The library: 1,828,328 bytes on arm64-v8a, 1,351,800 on armeabi-v7a and 2,046,776 on x86_64; x86_64 has 50,376 bytes
  left**, 35,872 more than at `fb15505`; arm64 and armv7 keep the index and fold nothing, with 268,824 and 745,352 bytes
  left. **Advanced's APK no longer carries GotaTun's own cdylib** either: GotaTun declares one, cargo-ndk copied it
  beside the engine, and nothing loaded it (324,064 bytes on x86_64, 304,968 on arm64-v8a and 11,808 on armeabi-v7a,
  about 640 KB of the APK). Both cargo-ndk tasks keep only their crate's library now, and the APK check fails on any
  native library an edition does not name; the release bundle, built from the same libraries, holds the same ones (read
  by hand, not by the check). GotaTun's cdylib is still built on every build and thrown away: Cargo cannot change a
  dependency's crate type.
  **Considered and rejected:** x86_64's release library without its unwind tables (`.eh_frame` discarded by a linker
  script), measured before the folding: 159,368 bytes more and 198,720 left, with no speed cost expected, since the code
  is the same (not measured); the maintainer kept the tables (2026-11-24): CI's release checks run on x86_64, and a
  crash's frames there are the only evidence.
  **Rejected for their speed** (bytes saved on arm64 / armv7 / x86_64): opt-level `z` for the whole library, 227,800 /
  181,620 / 168,832 (medians of `s` against `z`: a count 13.35 → 15.7 ns, an answer among 4,000 peers 171.5 → 284.5 ns,
  the live view 1.02 → 1.76 ms, and the engine's CPU for a datagram sent directly 4.80 → 5.00 µs at 1,280 bytes and 4.58
  → 4.93 µs at 100, through WireGuard 4.68 → 4.85 µs at 1,280 and 4.65 → 4.53 µs at 100, within the noise of a measure
  in 10 ms ticks); LLVM's machine outliner (`-C llvm-args=-enable-machine-outliner=always`), 69,504 / 70,640 / 38,528
  (medians, six rounds each, on a quiet machine: an answer among 4,000 peers 169 → 273 ns, the live view 0.99 → 1.435
  ms, a count 13.3 → 13.7 ns, a datagram sent directly 4.65 → 4.88 µs at 1,280 bytes and 4.53 → 4.75 µs at 100).
  **Rejected, since they grow the library:** `z` for the dependencies alone, by 48,488 / 42,500 / 57,208 bytes, and for
  all of them but the packet path's (tokio, GotaTun, `bytes`, aws-lc), by 12,728 / 2,888 / 18,352. **Rejected, since
  they save little or nothing where room is needed:** `z` for the bridge alone, the link's root, 1,664 / 7,460 / 1,280,
  since each function keeps its own crate's level through the link-time optimisation; lld's `-O2`, 0 / 64 / 64; `-C
  force-unwind-tables=no`, 50,736 / 4,864 / 0, since rustc drops the functions' `uwtable` but LLVM's x86-64 backend
  writes the tables all the same (tried on a small crate), and on arm64 and armv7 it would take away the frames the
  maintainer kept on x86_64. **Not applied:** `--icf=all` on arm64 and armv7, 12,976 / 6,272, and the index left out on
  arm64, 24,976: they have room.
  **Proposals for later** (code or a dependency's settings, not this pass's): curve25519-dalek's precomputed table of
  the base point, 30,720 bytes on every ABI, which GotaTun turns on through `x25519-dalek`'s default features and Cargo
  cannot turn off from here; without it an X25519 public key from a secret takes 22 µs instead of 13.7 on the
  development machine, through curve25519-dalek's AVX2 backend (once per WireGuard handshake and once per ODoH query,
  for HPKE's key pair), a Diffie-Hellman 40 µs either way; ARM phones take the slower serial path, for which the crate
  gives the table about four times the speed (not measured here); it needs GotaTun to depend on `x25519-dalek` without
  default features, a reviewed step (ADR 0035). For the engine's builder, after the cold paths' two passes below:
  hashbrown's maps instantiated per type (113 KB on x86_64), on the packet path, where each change needs a speed
  measure of its own; tokio's code for each relaying task's type (a kept connection's, an echo's, a tunnel's, about 2 KB
  each on x86_64), which a boxed task type would share at one indirect call more per poll; and `std`'s backtrace
  symbolizer (67 KB), which only a nightly `build-std` drops. Boxing the largest futures of the cold paths
  (`udp::open_udp`'s, 42 KB, and `Engine::start_with`'s, 29 KB) only moves their bytes (the first pass). What the two
  passes took is gone: of `std`'s `RandomState::new` inlined, 620 bytes are left on x86_64, all in tokio's and
  GotaTun's own code and in `keys` itself, and the `jni` crate's entry code is one copy per return type. No free setting
  is left for x86_64: what remains is code and GotaTun's table. Not measured: arm64 and armv7 on a phone, which the
  settings pass did not touch; the two cold-path passes below change their code, and the second grows arm64-v8a's
  library by 512 bytes of unwind entries for its JNI entry (stated there).
- **The cold paths** (2026-11-25, the maintainer's route that day over a review of the gate: room for the proxy record's
  next units, from code that runs once per engine start, per flow opened or question to Android, with no change of
  behaviour and none on the packet path; build settings untouched). *Where the bytes were,* by the size pass's method,
  plus each function's bytes laid on the source functions inlined into it (an x86_64 build with line tables, every
  instruction through `llvm-symbolizer --inlining`): `udp::open_udp`'s future (41,742 bytes) and `Engine::start_with`
  (30,432) are big, but almost none of their code is there twice, so boxing their inner futures only moves it
  (`Box::pin` of `open_udp`'s two arms put 27,889 of its bytes in the boxed future's poll and saved 604). What can go is
  code instantiated once per type: tokio's code for a task, about 2 KB on x86_64 for each type of future spawned; the
  blocking pool's, about 1.2 KB for each type of closure; and `std`'s `RandomState::new`, inlined at each map made,
  about 100 bytes each time, 39 times in `Engine::start_with` and 15 KB across the library. **Kept, one commit each**
  (bytes on arm64-v8a / armeabi-v7a / x86_64, from Gradle's own build and AGP's strip):
  - one boxed task type for the engine's tasks that relay no stream of traffic (W8's, moved out of the resolver,
    `engine::Task`), and one blocking task type for the calls to Android (`engine::on_pool`): 3,296 / 1,888 / 3,168;
  - those tasks spawned through it: opening a UDP destination's way, the questions to Android about an app socket, a
    tunnelled flow or an app the network part did not name, a chained app's lookup, the logger, a TCP connection's
    opening and the listener's accept loop: 24,072 / 14,504 / 22,536;
  - three inner futures of the UDP open path boxed (`open_mapped`, `mapping_for`, a stand-in's own association;
    `open_lookups`' box made the library larger, and is left out): 1,664 / 640 / 2,496;
  - a new map's hasher keys made out of line (`crate::keys`, `map`, `set`) where the engine starts, hands over and opens
    a flow, and in the settings the network part sends: each map still calls `RandomState::new` once, in the same order,
    and keeps its type: 8,064 / 5,856 / 8,704.

  **The library: 1,810,296 bytes on arm64-v8a, 1,342,336 on armeabi-v7a and 2,032,136 on x86_64; x86_64 has 65,016 bytes
  left** (28,112 before: 36,904 more), arm64 286,856 and armv7 754,816. *Left as they were,* since they run per packet,
  per answer or in a relay task: every relaying task's type (a mapping's, a stand-in's own association's, a flow of
  lookups' answers, a kept connection's, a tunnel's, an echo's, the TCP relay, `Loop::send`'s retry), and the maps of a
  mapping's sources, the ordered sets and the names' FIFOs (about 1.5 KB of `RandomState::new` on x86_64). *What it
  costs:* each boxed task one allocation more and one indirect call per poll (tokio boxes a future over 16 KB itself);
  each call to Android two allocations more (the job's box and the slot for its answer), one indirect call and two
  uncontended locks; each boxed inner future one allocation; each map made one call. Counted per event, at most: a UDP
  destination opened directly seven allocations more (its task, two inner futures, and its two calls to Android: whose
  socket it is, and the protection of its own), a TCP connection five (its task and its two calls), and a DNS query,
  which is an event of its own since Android's resolver sends each from a new port, five for a direct app's (its flow's
  opening and its two calls), four for a chained app's (its opening, its question to Android and its lookup's task),
  three where the encrypted resolver answers (its opening and its question); each beside its calls to Android over
  Binder, tens to hundreds of microseconds on a phone. No measure covers the chained path. *The machine code of the
  packet path,* compared function by function before and after on unstripped x86_64 and arm64-v8a builds, addresses,
  jump targets and page offsets set aside: the polls of every relaying task are the same, and so are `Loop::handle`,
  `Loop::send`, `relayed_receive`, `mapped_receive`, `try_send_to`, `tunnels::forward`, `Tun::send` and `Counts::count`.
  What differs: `Loop::forward` in three call targets alone, in the branches that spawn a UDP destination's opening, a
  tunnelled flow's question and a TCP connection's opening; `Loop::answered_here` where it spawns a chained or resolved
  lookup's task, and drops its join handle itself; `run`'s start (the maps of its tables, the logger's spawn), and in
  its loop the registers and one stack slot, now at offset 0; `echo::carry`'s poll in the branch that protects a new
  ping socket; `toward_peer` on x86_64 in one call to a folded copy of the same code and one `mov` fewer, and on arm64
  in the order of its blocks after `try_send_to`, one taken branch moved, within two instructions on each path; and on
  arm64 `Shared::learn`'s four page loads, which the linker relaxed. *The speed,* before (`main` with the measure below)
  and after in turn, beside another project's database and build containers: the engine's own release measures, pinned
  to four threads, eight rounds each at a load of 5 to 10 (medians): a count 12.95 ns both, a mark 169 and 168 ns, the
  live view 0.98 and 0.97 ms, an answer among 4,000 peers 164.5 ns both, the engine's CPU for a datagram through
  WireGuard 4.90 and 4.85 µs at 1,280 bytes and 4.50 and 4.48 at 100, sent directly 4.85 and 4.90 at 1,280 and 4.85 and
  4.65 at 100 (10 ms ticks; eight rounds earlier at a load of 13 gave the same within their spread). The W2 CPU check on
  the Android 15 emulator with release Rust, fifteen times each in turn, in three sets of five whose throughput moved
  with the other project's load (about 90 Mbit/s at loads of 10 to 51, about 300 at 20 to 28): the engine's CPU per MB
  moved 24.1 and 23.9 ms, 23.8 and 24.6, and 12.0 and 11.9 (medians of each set); downloads, uploads, four parallel
  downloads, and the p50 of a connection and of a round trip differed between the builds by less than between runs of
  one build, in every set (a rank test's |z| under 1.4, the signs mixed). *The time to open a UDP flow,* a new measure
  (`opening_a_udp_flow`, `core/net/tests/wireguard.rs`): one datagram from each of 400 new ports, each waited for at the
  far end; medians of eight rounds on the development machine at a load of 5 to 10, from the send to the arrival and
  then the engine thread's CPU per open: directly 45.2 and 44.0 µs, 39.5 and 38.7; a lookup to the network part's DNS
  address 38.9 and 38.3, 33.5 and 33.6; through WireGuard 22.8 and 22.2, 18.1 and 17.5. Built for Android and run on the
  emulator, forty rounds each, the engine thread's CPU per open: directly 36.2 and 36.3 µs, a lookup 49.5 and 51.8,
  through WireGuard 18.3 and 17.9, each difference inside a 95% interval that holds no change (the widest from −2.0 to
  +4.6 µs), the measure's resolution there. The cost the change adds, a few hundred nanoseconds at most, is below both.
  Not measured: arm64 and armv7 on a phone, whose code changed only as above. **Next, if more room is needed:**
  hashbrown's code, 112 KB in 169 functions of its own and 109 KB inlined into others, one instantiation per key and
  value type, on the packet path; the backtrace symbolizer and GotaTun's table, above. The `jni` crate's code in each
  JNI function and the maps this pass left went in the second pass, below.
- **The cold paths, second pass** (2026-11-26, the same route: room for S2 of the proxy record, which plans for 20 KB
  and stops with 8 KiB left). *Where the bytes were,* by the first pass's method: `std`'s `RandomState::new` still
  inlined in 18 of the engine's functions, 4,525 bytes on x86_64 (a build with line tables), and the `jni` crate's entry
  code copied into each of the 41 JNI functions. **Kept, one commit each** (stripped bytes of unstripped builds,
  `ndkbuild.sh` then `llvm-strip --strip-unneeded`, on x86_64; on the three ABIs for the last two):
  - the hasher keys out of line in the names' tables (`names::Fifo`), the count of ended flows by app (`Counts::end`),
    the live view's two maps and a kept connection's questions: −768;
  - the JNI bridge's three maps through the engine's own maker, `datapavan_net::map` and `set`, now public: −384;
  - `Names::insert`'s set of the names an address was given again replaced by a scan of the entries kept, at most nine,
    with the same result in the same order (a unit test compares the two on 2,400 lists): −144;
  - a measure of the down path, `per_datagram_cost_of_the_down_path` (`core/net/tests/wireguard.rs`): a far end sends a
    direct app's mapping 100,000 datagrams of each size, 32 at a time, and the measure reads the engine thread's CPU per
    datagram relayed to the app, which nothing measured;
  - a mapping's sources, fingerprints and known addresses, the ordered sets and the sweep's set, which the first pass
    left derived so that the relay task `udp::mapped` kept its poll (its M2), now with that M2's condition met, the
    measure above before and after: −3,264, and item 1 in all −4,560 / −3,984 / −2,112 on x86_64 / arm64-v8a /
    armeabi-v7a; what is left of `RandomState::new` inlined is 620 bytes in five functions, tokio's, GotaTun's and
    `keys` itself;
  - a check of the JNI error path, which no check reached (`jni-errors`, a debug command the network shard runs): for
    each return type an input can make fail, a call with a null throws a `RuntimeException` whose message starts
    "Rust error:", and the next call works; Int, ByteArray and LongArray have no input that fails, the default value
    returned with the exception is dropped by Java and cannot be read, and the panic path, caught in debug builds alone,
    has no input that reaches it; and it runs against the debug profile's Rust library, which the network shard
    installs, so the release profile's `entry` (fat LTO, `--icf=all` on x86_64, `panic = "abort"`) is exercised on
    its success paths by the release build's checks (`verify-network-release.sh`) and on its error path by none;
  - one entry per return type for every JNI function (`entry`, seven types, the body a closure behind one indirect
    call), with the same error policy: −4,352 on x86_64 and −1,344 on armeabi-v7a, and **+512 on arm64-v8a**, where
    `.text` shrinks by 1,600 bytes but the 38 closures and six entries made functions of their own bring their unwind
    entries and their index's (`.eh_frame` +1,816, `.eh_frame_hdr` +328), which no shape avoids; kept by the plan's rule
    per ABI (an item is dropped if it grows x86_64 or armeabi-v7a, or arm64-v8a by more than 1 KiB).

  **The library, from Gradle's own build and AGP's strip: 2,064,648 bytes on x86_64, 1,844,664 on arm64-v8a and
  1,368,784 on armeabi-v7a; x86_64 has 32,504 bytes left** (23,400 before: 9,104 more), arm64 3,280 bytes smaller and
  armv7 3,520. *The machine code of the packet path,* compared function by function against `d9b44fb7` on unstripped
  x86_64 and arm64-v8a builds with the size pass's tool, its list refreshed: six names were gone since the first pass,
  each inlined into a function the list holds (`Loop::udp` into `Loop::forward`, `read_mapped` into `mapped_receive`,
  `Tun::recv` and `try_recv` into `run`'s loop, `tcp::relay` into the accept task's poll, `send_to_app` on the packet
  path into the polls of `mapped`, `own_relayed` and `echo::carry`), and five functions that run per answer or per new
  source were added (`Scope::beside_or`, `label_taken` and `into_peer`, `Sources::add`, `Names::insert`'s merge). Of 105
  on x86_64 and 107 on arm64, all are the same but eight on each: `udp::mapped`'s poll, where LLVM now inlines
  `Core::poll` (2,451 instructions on x86_64) into `raw::poll` (69 before, 2,217 after; 70 and 2,071 on arm64), the same
  body but for the calls to `keys` where its maps are made, register choices and spills; `kept::run`'s poll only in the
  branch that makes its map (the inlined keys become one call, and their thread-local set-up goes); `Shared::learn`, the
  three `Scope` functions and `Sources::add`, where the inlined keys become a call and elsewhere the registers, spills
  and the order of blocks change, and on x86_64 a few comparisons take a spilled operand from memory instead of a
  register or the other way; and `Names::insert`'s merge, by its scan. Every relay's other poll, `Loop::forward`,
  `handle`, `send`, `toward_peer`, `relayed_receive`, `mapped_receive`, `try_send_to`, `tunnels::forward`, `Tun::send`
  and `Counts::count` are the same. Across the whole library, besides those: the 41 JNI functions, now a call to their
  entry; item 1's other functions (`Engine::activity`, `Counts::end`, the `Default`s of `Sources` and `Names`, a
  hashbrown insert into a set of `u64`); on x86_64 `route_of_app` (556 → 554 instructions), a `get_region`, two
  formatting shims, `decode_error_kind` and `thread_local_destructor`; on arm64 a `get_region`, `std`'s set-up of the
  keys' thread-local, which now takes `hashmap_random_keys` inline (84 → 219 instructions, once per thread), and eight
  functions only by a page offset or the linker's relaxation of a page load; the rest by addresses alone. *The speed,*
  since those differences reach beyond the branch that makes a map, before (`d9b44fb7` with the measure above), before
  the mapping's sources and after, in turn, the engine thread's CPU (medians, before and after): on the development
  machine, pinned to four threads, eight rounds at a load of 19 to 35 from another project, a datagram on the down path
  4.33 and 4.34 µs at 1,280 bytes and 4.21 and 4.15 at 100, sent directly 5.35 and 5.28 and 5.25 and 5.20, through
  WireGuard 6.63 and 6.83 and 6.28 and 6.30 (10 ms ticks), opening a UDP flow directly 41.25 and 42.15 µs, a lookup
  34.65 and 33.95, through WireGuard 18.9 and 19.0; on the Android 15 emulator, built for Android, twenty rounds, the
  down path 2.82 and 2.85 µs and 2.60 and 2.65, sent directly 4.05 and 4.00 and 3.90 and 3.88, through WireGuard 4.58
  and 4.65 and 3.55 and 3.50, opening directly 34.05 and 34.3 µs, a lookup 49.15 and 50.45, through WireGuard 18.45 and
  18.2. The plan's rule, "after runs within the before runs' spread", is read on the medians with a rank test: read on
  every single run it would drop an unchanged build about three times in four (all eight of eight runs from one
  distribution land inside the other eight's range with probability 8·7/(16·15), about 0.23), and here 2 of 8 single
  runs per size on the host and 1 of 20 on the emulator fell just outside, on both sides. Each median after sits within
  the before runs' spread, a rank test's |z| under 1.6 each; the mapping's sources
  alone, against the build before them, |z| under 0.7 on the down path. The engine's own release measures, 24 rounds
  each in turn: a count 13.4 ns both, a mark 178 and 176 ns, the live view 1.02 ms both, an answer among 4,000 peers 175
  and 176.5 ns, 16,384 stand-ins bound to one address added in 4.97 and 4.92 ms and removed in 2.37 and 2.40, beside one
  label added in 18.2 and 18.4 ms and removed in 5.56 and 5.62; and, in a measure written for this pass and not kept,
  learning a DNS answer for an address already held 665 and 464 ns in every app's table, by the scan, and 314 and 305 in
  apps' own. Not measured: arm64 and armv7 on a phone.
