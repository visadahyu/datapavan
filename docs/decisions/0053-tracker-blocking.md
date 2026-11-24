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
off, the row's SDK, which names a tracker and its company, is kept, and the host is not.

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
  default features, a reviewed step (ADR 0035). For the engine's builder: hashbrown's maps instantiated per type (113 KB
  on x86_64), the largest futures (`udp::open_udp`'s 42 KB, `Engine::start_with`'s 29 KB), and `std`'s backtrace
  symbolizer (67 KB), which only a nightly `build-std` drops. No free setting is left for x86_64: what remains is code
  and GotaTun's table. Not measured: arm64 and armv7 on a phone, which this pass did not touch; nothing kept changes
  their code.
