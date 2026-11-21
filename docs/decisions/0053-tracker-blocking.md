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

DESIGN.md's W8 row: "Tracker blocking stays off until the user turns it on, and is undone in one tap." Watch already
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
derivative, and the table holds no εxodus data. **Why:** without it, Watch could neither block nor mark
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
HTTPS and SVCB included, on every way Watch answers an app's lookup: the encrypted resolver, the network's resolver,
a chained app's stand-ins and other questions, DNS over TCP to Watch's address, a WireGuard-tunnelled app's lookups,
and Watch's cache of the network's answers. A question a row blocks for the app is answered at once and asks no one.

(b) **The answer**: "no data" with an SOA in the authority section, its time to live 0 and its `MINIMUM` 0
*(coordinator)*. Never the null address, which sends the app to the phone's own loopback, outside the tunnel, where
the tools listen; never "no such name", which Pi-hole's operators report clients retry harder.

(c) **Android's cache**: while blocking is on, every positive answer for a name a row grades `block` or `code` reaches
every app with a time to live of 0 too *(coordinator)*, so that no app's answer reaches another's lookup, and an undo
or a block is not delayed by a cached answer.

(d) **CNAME chains**: each name of an answer's chain is matched, which closes CNAME cloaking, for apps whose names
Watch resolves.

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
anything leaves, and only for an address that an answer Watch passed, still held, tied to blocked names alone, and
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

(f) **WireGuard-tunnelled apps** are blocked where Watch has their names, at their lookups to Watch's address. Their
connections run end to end inside the tunnel (ADR 0035), so their hellos are not held. **Accepted limit.**

(g) **Coalescing**: a tracker request coalesced onto a `keep` connection (HTTP/2's connection reuse) is not seen.
**Accepted limit**, frontier research.

### 5. What is never blocked, or not by default

(a) **Browsers** are left out by default, and the screen says so; the user may include them *(coordinator)*. A browser
is an app that resolves a browsable `https` intent to a host no app claims, counting only intent filters with no
authority, so that App Links apps do not count. **Why:** a browser opens any website, whose third parties are the
site's, not the browser's.

(b) **Not covered by this part**, and the screen says so: apps that came with the phone, UID 1000 and Google Play
services. Flows Android names no app for, and Watch's own, are never blocked.

(c) **The user's tool** (ADR 0046, decision 3): its connections are never blocked by their hello, since a cover name
may be any popular host, and a wrong block cuts circumvention. An option, off by default, blocks the tool's own SDK
lookups by DNS alone *(coordinator)*, because Watch protects data from the tools too.

### 6. The undo

(a) **On the app's row**, in "Now" and in its history: one tap, "Allow trackers in this app", for an hour, and one tap
"Block trackers again" ends it sooner *(coordinator)*. Expiry is checked at each decision, on the time since the
phone started, with no alarm. An hour, not a plain allow: an app allowed for good stays unprotected after the breakage
it was allowed for is over, and no product documents a timed allowance, so this is new in the field; the words are
tested with real users (decision 10).

(b) **Per row**: under the app, each row it reached has its own allow, until blocked again, or one per company where
one εxodus signature names several of its trackers.

(c) **A global pause**: ten minutes, naming no app, on Watch's main screen *(coordinator)*. Breakage shows inside the
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

(b) **Chained apps**: their rows follow "Log where these apps connect": while it is off, the row's SDK, which names a
tracker and its company, is kept, and the host is not.

(c) **The profile** (ADR 0047): allowances are kept behind Watch's lock and wiped by a wipe, as the apps left out of the
tunnel are (a new row of ADR 0047's table). Nothing of blocking is recorded under it: its counts are in memory and
cleared with the live view, and the log does not run. This joins W9's must in DESIGN.md.

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

- Watch blocks trackers by what each host does, the same in every app, and refuses a flow before any byte of its
  payload leaves; as far as the research found, no tool without root states its grades with their sources, holds a
  hello until its name is read, keeps Android's cache from carrying one app's answer to another, or offers a timed
  undo.
- **Accepted limits**, each with its reason above: the TCP handshake reaches a server later refused by its hello
  (4 c); WireGuard-tunnelled apps by their lookups alone (4 f); coalescing (4 g); chained apps' CNAME chains, strict
  Private DNS and apps' own encrypted DNS (3 e); browsers, preinstalled apps, UID 1000 and Play services by default
  (5); an app's own proxy's inner hello is not held (ADR 0052 reads it after the handshake); hosts that wait for
  lane 2 (1 g); the first flows after Watch starts, before the setting is handed over; and, at the moment blocking
  is turned on, the answers Android's cache already holds for blocked names, which keep their addresses for their
  time to live (no app can flush that cache; found on the emulator): their connections are still refused by their
  hello, and every answer after is kept for no time.
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
- **The engine** (`core/net`): the table's reader and the `Host` reader in `blocking.rs` (`Table::parse`, `find` on label
  boundaries, `http_host`); the blocked answer in `answers.rs` (`blocked`) and the chain's names in `dns.rs` (`chain`);
  the decision, the tallies, the ties of addresses and the gates in `engine/blocks.rs` (`Blocks::blocks` the one rule;
  `Shared::lookup_blocked`, `answer_blocked`, `tie`, `address_verdict`, `blocked_flow`; `Gate::feed`, `QuicGate`), called
  from every DNS way (`resolver::answer` before its cache, `lookups::answer`, `Loop::udp`'s open and opening flows,
  `relayed` on the network's answers, the cache of direct answers, DNS over TCP by the app's UID, `tunnels.rs` for a
  tunnelled app), from `tcp::upstream`'s ask-first path (`blocked_before`: a stand-in's name, a tied address), from
  `tcp::relay` (the gate on the app's side, the row decided again on both sides), and from `udp.rs` (`gated` on both
  ways a datagram leaves for a peer, the refusal as ICMP "port unreachable" in `count_sent`). The setting comes whole
  through `watch-jni` (`nativeBlockingTable`, `nativeBlocking`, `nativeBlocked`), which turns the allowances' times left
  into deadlines on the time since the phone started, and is carried to the engines to come with the chain. Four
  counters are appended: lookups answered empty, connections refused, of them by address, and starts held. The log's
  version 6 adds the outcome 4 and the row's SDK.
- **Watch's Kotlin side** (`android/watch`, `blocking/`): `BlockingSettings` (the store, timed at each decision, a
  clock set back pulled in, `wipe()` for W9), `Coverage` (covered UIDs; browsers by `https://example.invalid/` with
  filters of no host; Watch, Play services, UIDs below 10000 and the tool left out), `Grades` and `TrackerCode` (the
  code grade from the audit's scan cache, joined to εxodus by prefix; exceptions by package and current or past
  certificate), `Handover` and `BlockingHandover` (the setting's text, handed at start, on each change, on an app's
  install or removal, and when the pack or the scan changes), the debug builds' lab row (`src/debug`, an empty one in
  `src/release`), and the screens (`ui/BlockingSection.kt`, `ui/BlockingLines.kt`, "Now"'s row, the history's rows).
  The link to the log's switch opens Watch's screen above "Now" without clearing it, and Back returns to the same row
  or history (`ui/LogSwitch.kt`).
- **Choices made in the build**: the per-app allow lasts an hour (one constant), the global pause ten minutes; a per-row
  allow lasts until blocked again; "Block trackers again" ends the app's hour and leaves its per-row allows; a shared
  UID is covered only where every package that holds it was installed by the user; a `code` row is kept for an app
  updated since its scan, and, under the profile, where there is no scan file.
