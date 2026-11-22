# 0042. DNS of apps that go directly: Oblivious DoH, several jurisdictions

- Status: Accepted (by the maintainer on 2026-11-12), with open questions
- Date: 2026-11-12

## Context

Apps that Advanced sends through the user's tool have their names resolved by the tool
([ADR 0038](0038-dns-of-chained-apps.md)). Every other app goes directly. For those, the network part's resolver
answers inside the tunnel and asks upstream. Asked as plain DNS from a protected socket to the network's resolver
([VPN.md](../VPN.md), DESIGN.md §13.2, W3), the network sees every name a direct app looks up, unless the user set
Private DNS. W8 adds a DoH or DoT resolver of the user's choice and a strict setting that never falls back to the
network.

Encrypting the questions to one resolver hides them from the network, but hands all of them, with the user's
address, to that resolver's operator. Oblivious DoH (ODoH, RFC 9230) splits the two:
- **A relay** sees the user's address but not the question.
- **A target** sees the question but not the address.

In filtered networks, though, DoH and its relays are often blocked, and a resolver that cannot be reached
leaves every direct app without names.

## Decision

1. **ODoH is the default** upstream for the names of apps that go directly (built in W8, part 1). No single
   server sees both who asks and what.
2. **Several jurisdictions.** Relays and targets are chosen from more than one operator and jurisdiction, and the
   user can see and change them.
3. **The network's resolver is a fallback only,** outside the strict setting. Advanced uses it only when no
   encrypted path answers, and says so on the network screen while it does. With the strict setting, it is never
   used.
4. **The user's own choice stays.** A DoH or DoT resolver of the user's choice, and the strict setting, stay beside
   ODoH (points 6 and 7 below).

## Open questions

- **Which relays and targets.** Answered by W8's part 1: the datasets and the defaults below, with sh2o out. A
  relay of the project's own, paired only with other operators' targets, adds a jurisdiction; running both halves
  would be collusion by design. The maintainer chose a relay of the project's own on 2026-11-21:
  [ADR 0055](0055-an-odoh-relay-of-the-projects-own.md) (proposed).
- **Fallbacks in filtered networks.** How names keep working where DoH and ODoH are blocked, without falling back
  silently to a resolver the censor controls: the ladder, its holds and strict below. Still open at the frontier,
  and left for later with reasons: DNS over QUIC and DoH3 (no hook for the socket or the resolver in Android's
  HttpEngine), SNI left out and a ClientHello split on retry, per endpoint (no dataset field for them yet), and
  ODoH's reachability in filtered networks, never measured.
- **The cost.** ODoH adds a hop to each uncached name. Its latency is measured against Advanced's speed budget in
  ADR 0039.

## How it is built (W8, part 1)

Decided before the build in its brief and audited once (strategy repository, `research/2026-11-w8/`), revisable by
the maintainer; built on `watch-w8a` on 2026-11-20. Each point as built:

1. **TLS is the platform's, not the engine's.** DoH, ODoH's HTTP and DoT run in Kotlin in `:network`
   (`dns/Exchanger.kt`, `dns/DotClient.kt`) on Android's own TLS (Conscrypt, BoringSSL), whose ClientHello is every
   Android app's: OkHttp 5.5.1, pinned, with HTTP/2; no `User-Agent`, no `Accept-Encoding` (compression would undo
   the padding), no cookies, no cache, no redirects; its `Dns` answers only with the data pack's addresses, so no
   server's name is ever looked up; certificates checked against Android's own roots only (`AndroidCAStore`'s
   `system:` aliases, never a user's or an administrator's, `dns/SystemTrust.kt`), plus each endpoint's pins where
   the dataset gives them; DoT checks the server's name in the handshake; one client, connection pool and TLS
   session cache per network beneath, idle connections closed after 60 s and opened again on demand; Conscrypt sends
   no early data. Every socket is protected from the tunnel and bound to the network beneath, or goes through the
   user's tool (`dns/ToolSocket.kt`, SOCKS5 with its password, the destination by address). The engine hands each
   exchange over (`Platform::exchange`, which returns at once: every step of it, Android's roots, the TLS
   context and the client included, runs on the exchanger's own threads, and is built ahead when the service
   starts and the network changes) and awaits its reply (`Engine::exchanges`), so the packet loop never waits. Each
   exchange carries its own addresses and pins; a socket to the user's tool on the LAN is protected like any other. What the platform does not give, written as it stands: Conscrypt is a Mainline module
   from Android 10, but whether a given image keeps it updated is not verified (the Android 15 emulator image used
   here carries `com.google.android.conscrypt` 350820300, its factory version); the root store is updated apart from
   the system only from Android 14; ECH comes only from Android 17, for apps that target API 37; no source shows
   post-quantum key exchange by default.
2. **The engine keeps** the DNS parsing (its own: `hygiene.rs`, `dns.rs`), the caches (`dnscache.rs`, with RFC
   8767's stale answers), the policy (`ladder.rs`, `engine/resolver.rs`) and ODoH: its framing
   (`odoh.rs`) and its HPKE (`hpke.rs`, RFC 9180 base mode, the one suite) are the engine's own code, over crates the
   library already carries for WireGuard and QUIC: `x25519-dalek` 2, RustCrypto's `hkdf` and `aes-gcm`. The size
   gate is 2,097,152 bytes per ABI; the measures, inside `core`, stripped, are under "The fix round" below. **x86_64,
   the emulators' ABI, stays over it; arm64 and armv7, the phones' ABIs, are within it with 270 and 550 KB to
   spare.** The gate is the maintainer's to keep or to except for x86_64.
3. **Data, signed, in the pack:** `data/odoh` (relays, targets with their bootstrap keys, the default pairs) and
   `data/dns-presets` (the user's choices, each with its card), CC0, every value with its source. `data/resolvers`
   stays a detection list. Either changes without a release; closed services are left out.
4. **ODoH pairs** (`catalogue.rs`): refused on a shared operator, person, jurisdiction, or hosting or CDN network,
   read from the fields; an entry whose person, jurisdictions or hosting the dataset does not know never pairs.
   Defaults, verified again on 2026-11-20: Numa's relay (DE, RO; AS24940) to Cloudflare's target (US, CR; AS13335),
   then crypto.sx's relay on Fastly (FR, US; AS54113) to dnscry.pt's fra01 (DE; AS44486). sh2o is out while its
   operator is unknown. The second pair is asked 400 ms after the first, unless the first failed sooner: above
   the first pair's warm p95 on the internet (171 ms, ADR 0039) and its first query on a cold connection (about
   250 to 300 ms), so the second is asked only when the first is slower than a new connection would be; each
   attempt is sealed afresh. Only unfiltered targets pair. The user sees the pairs on the network screen
   and changes them among those the rule allows.
5. **Target keys.** No target publishes `odohconfig` in a DNS HTTPS record (checked through two resolvers on
   2026-11-20: Cloudflare's record has none, crypto.sx's has ECH only, dnscry.pt's nodes have no HTTPS record). A
   401 holds the pair that met it (6 hours, or until a new key comes) and the other pair carries the names; the
   key is fetched apart from the lookup, a random 2 to 10 minutes later, at most once per target per network every
   4 hours (review S-C2). The engine asks first for the target's HTTPS record of presets whose
   operator runs no target in the pairs, through the user's tool while it is on, and takes it only when two agree;
   failing that it fetches `/.well-known/odohconfigs` from the target at its own addresses (review S-M1), through
   the tool while it is on, else, **last and as an accepted limit**, directly over the network beneath, which shows
   the phone's address to the target minutes apart from any question, once per key, and gives no assurance that
   every user holds the same key. A key equal to the one held keeps the pair held: a target cannot call for the
   fetch with a 401 to a key it holds. The pack's copy bootstraps.
   Rotation measured during the build, every 30 minutes: dnscry.pt fra01's key, the second default pair's, changed
   between 15:39 and 16:09 UTC, held at least since 13:44; Cloudflare's did not change from 13:44 to 16:09 UTC, and
   it serves it with `no-store` and a `Last-Modified` of that day's 00:00 UTC, so a daily key is likely. Keys
   therefore change faster than packs can follow, and the fetch after a 401 is the usual way a key arrives, not a
   rare one: the pack's copy only saves the first fetch while it is still current. A key feed that every user
   holds alike, accepted when two paths agree, is frontier work (the IETF's consistency drafts expired in 2024).
6. **The order, by privacy** (`ladder.rs`): the user's own resolver, a rung of its own; ODoH, first or next after
   the user's resolver failed (review R-M1); then, while the user's tool is on, ODoH through the tool; then DoH to
   the targets' own operators; then the presets that filter nothing; the network's resolver last, never in strict.
   With "only this resolver" the user's resolver is the only step and the network's resolver is never asked for a
   name of the internet either. The engine learns only within a rung (the step that answered last is tried first there)
   and climbs back as soon as a higher step's hold ends. Holds: 5 s after a timeout, a refusal or an error,
   doubling to 60 s; 360 s after a reset once the TLS hello was out or a certificate that does not check; 6 hours
   after a 401, until the key's fetch (point 5); none while Android says the network is not validated (a captive
   portal); all cleared, with everything learned and the answers kept, on a change of network, but kept when only
   strict, "only" or the choice changed (review R-m1). Nothing of it is stored or keyed by a network's name.
7. **Strict:** with no encrypted way answering, "server failure" at once, and the screen says why. Local names
   (single labels, `home.arpa`, `ipv4only.arpa`, `resolver.arpa`, `localhost`, `local`, the zones of RFC 6303 and
   RFC 7793) go to the network's resolver in either setting, and the screen says so. A name under one of the
   network's search domains goes the encrypted way first, and to the network's resolver only when that way answers
   NXDOMAIN, in strict too; a search domain of one label or a public suffix is ignored (review S-C1, "The fix
   round"). The screen also says what strict cannot cover: Android's own connectivity checks, apps' own encrypted
   DNS, the apps left out of the tunnel, and the moments the network part restarts or is stopped without Always-on.
8. **Hygiene** (`hygiene.rs`): ID 0 (RFC 8484); every EDNS option the app sent dropped (client subnet and cookies
   among them); EDNS(0) padding to 128-byte blocks (RFC 8467), which asks the resolver to pad its answer (RFC 7830);
   the answer made the app's again (its ID and question, a bare OPT record or none, cut to a truncated answer past
   what it takes over UDP, so that it asks again over TCP); answers kept for their time to live and served stale
   for up to a day, with a time to live of 30 s, while a fresh one is asked (RFC 8767); no DNSSEC validation on
   the phone (the resolvers validate; a stub would need DNSKEY and DS chains for each name, more round trips through
   a relay, and a validator, a code class with a long 2026 record of proof bypasses); both address families towards
   the resolvers where the dataset gives them; ADR 0038's per-route caches kept.
9. **The two leaks closed.** Once the resolver is set, every port of the tunnel's DNS address but 53 is refused, TCP
   with a reset and UDP with an ICMP error, so Android's opportunistic DNS over TLS asks on port 53 (seen on the
   emulator: Private DNS on "automatic", the flow to port 853 refused, the names still by ODoH); DNS over TCP at port
   53 goes to the engine's own listener and the same ways (`connect_lookups`); a chained app's other record types go
   the encrypted ways through the tool, never to Quad9 in plain DNS (`lookups.rs`).
10. **W7's endpoint names** go the encrypted way (`resolver::endpoint`), not to Android's resolver; outside strict
    the network's resolver answers when nothing else does, and the tunnel's state says plain; in strict nothing does.
11. **The screen** (`ui/DnsSection.kt`) says which way names go now (the relay's and target's operators and
    countries), by what failed when the user's resolver does not answer, the fallback while it lasts, and, if the user
    turns it on and Android lets Datapavan notify, a notification while it lasts (the network part has no tile until
    W9); when Android's strict Private DNS takes the names past the tunnel, that note alone; the choice, one row per
    service with its card in translated words and what happens if it fails; "only this resolver"; the network's own
    domains in use. Nothing of the names is kept or logged: the state names ways, never lookups.
12. **Speed:** ADR 0039's budget, measured on 2026-11-20 (below there).

Checks: the unit tests (the ladder, the pair rule, the hygiene, the catalogue against the shipped tables, the
resolver with a fake Kotlin side: ODoH, hedging, a 401's key, strict, local names, the fallback and its end, TCP,
the tool, endpoint names, the captive portal); HPKE against RFC 9180's A.1.1 vectors, both sides; ODoH against an
implementation of its own in Python, to the byte (`core/net/testdata/odoh/oracle.py`, since RFC 9230 has no
vectors), and against `odoh-rs` both ways; the engine through its tunnel (`core/net/tests/resolver.rs`); the transport on the JVM against the lab's
certificates (DoT, pins, a user's root refused, a certificate for another name refused, the tool's SOCKS5); three
new fuzz targets (`odoh`, `hygiene`, `catalogue`: 4.5, 12.2 and 3.8 million runs, no finding); 31 hand mutants
on the new rules, all killed (six by tests added for them); the DNS lab (`scripts/dnslab.sh`) and the emulator
check (`scripts/verify-dns.sh`), passed on the Android 15 emulator.

**Limits, as they stand:** Android sends its connectivity checks, and DNS of apps excluded from the tunnel, past
Advanced; apps that send DNS themselves (to 8.8.8.8, or their own DoH) are named, not redirected; while the network
part's process (`:network`) is killed or the tunnel is set up anew, Android may resolve outside the tunnel unless
Always-on with "Block connections without VPN" is set (Mullvad, 2024: its getaddrinfo path), which onboarding
recommends; an injected answer reaches whatever the network's resolver answers (local names, and the fallback outside
strict); the target key's fetch above; ODoH does not hide the connection that follows a lookup (its address, and its
server name without ECH); one person curates the public ODoH list and runs a relay and a target; Android's own
validation of the network could not be exercised in the lab (its resolver knows only the lab's names), so the emulator
check tells the engine "not validated", while "validated" reaches it by Android's own path where the emulator reaches
the internet.

### The fix round (W8, part 1, 2026-11-20)

One review round (`research/2026-11-w8/review-w8a-security.md`, `review-w8a-screens.md` in the strategy repository)
and its fix brief, whose decisions the coordinator took under the session's grant. Each fix has a test that fails
when the fix is taken back, checked by taking each back by hand: 23 in the engine, 14 on the Kotlin side (two tests
were tightened after it), and the notification's permission on the emulator. What was decided, and why:

- **A network's search domains (S-C1).** DHCP's option 15 is the network's to set, so it cannot decide that a name of
  the internet is local: a hostile Wi-Fi with the domain `com` had every `*.com` name in plain DNS, strict included.
  Now only the special-use zones and single labels go to the network's resolver unasked. A name under a search domain
  goes the encrypted way first and to the network's resolver only on NXDOMAIN (a name the internet does not know is
  the network's own), in strict too, and that NXDOMAIN is never served from the cache. A search domain of one label is
  refused by the engine; one that is a public suffix by the network part's Kotlin side, from the ICANN section of the
  public suffix list in the signed pack (`data/public-suffix`, MPL-2.0, ADR 0015), and none at all without that list.
  The status and the screen show the domains in use; they go when the network changes, before the next one's arrive.
  **What the rule gets wrong:** a split-horizon name, one the internet knows with another answer than the network's (a
  company's intranet under its public domain), gets the internet's answer; the network then learns nothing, which is
  the side to err on. Asking the network first for names under its domain, as Android does, would hand every such name
  to a network that chose the domain; a list of domains the user confirms would serve split horizon, and is left for a
  later unit.
- **A 401 apart from the lookup (S-C2), and the targets' own addresses (S-M1).** Point 5 above. The 401 holds that
  pair, the other carries the names; the fetch waits a random 2 to 10 minutes and runs once per target per network
  every 4 hours; records are asked only of operators that run no target in the pairs, through the tool when it is
  on; the direct fetch is the last way; an unchanged key keeps the pair held, so a target cannot tie a chosen query
  to the phone's address with a 401. The targets' address columns are read, and the test double refuses an
  address-less fetch.
- **The user's own resolver (R-M1, S-m3).** It is tested with one query (`example.com`) before it is saved, and the
  screen shows how long it took or what failed; a resolver that does not answer is not saved. When it fails later,
  the screen says so first ("Your resolver does not answer…"), and ODoH carries the names next, then the rest of the
  order. "Only this resolver" asks nothing else, the network's resolver included; the card says what happens if the
  resolver fails. A preset is saved without a test: it comes from the signed pack, and a failure on one network is
  the network's.
- **Words, not the dataset's English (R-M2).** A row is the operator and a translated service name (blocks harmful
  sites, unfiltered, standard), one row per service with its two protocols inside (n3); the card's logging,
  filtering and audit are enumerated columns of `presets.tsv`, each with its source, which the screen turns into
  translated sentences; countries come from `Locale`; the policy link is on the card (n1). The table keeps its
  sourced sentences for the record. The engine does not carry the presets' words.
- **The notification's permission (R-M3).** Turning "Notify me" on asks for Android's leave on Android 13 and later;
  refused, the switch stays off and the screen says why; the emulator check runs that case before it grants.
- **CI (R-M4).** The emulator check has a shard of its own, `dns`, with the lab started before the emulator, and
  `DNSLAB_REQUIRED=1`, which turns a skip, or a check that ends without its last line, into a failure. A debug command
  points the network part's exchanges with the network's resolver at the lab's resolver, so CI's emulators need no
  special start; the precheck after that fails rather than skips. The default path is tested on the JVM: DoH and ODoH
  over OkHttp against OkHttp's own test server with the lab's certificate, over HTTP/2 (the unit tests run OkHttp's
  JVM build of the same version): the request on the wire, a 401, a body over the limit, the pins.
- **The speed budget (R-M5).** `scripts/dns-latency.py` compares against ADR 0039's budget and exits non-zero on a
  breach or a failed default pair; RELEASE.md calls it; in the lab each way's p95 is held at most 250 ms above plain
  DNS's timed in the same step (ADR 0039's section on the speed budget says why).
- **The minors and nits.** A random ID towards the network's resolver (S-m1); the tool's socket protected when the
  tool is not on the loopback (S-m2); "unfiltered only" held in the engine, and a URL's path held to RFC 3986's
  unreserved characters, so no path adds a parameter to the relay's URL (S-m4, and the screen checks a URL as the
  engine reads it, n2); nothing of an exchange on the engine's thread (S-m5); one reply per network exchange, pins
  and addresses per exchange, both record ways asked, a stale answer renewed once at a time (the nits); "Notify me"
  does not reset the resolver, and strict or the choice keep the holds (R-m1); the texts on the connection log,
  the strict limits, "operators" for who runs the relays and targets, the hedge, the key's daily fetch (R-m2 to
  R-m4); the strict Private DNS note alone (R-m5); a selectable custom row, the refusal tied to its field and read
  out, left-to-right fields with a URL keyboard, Persian digits read as ASCII, relay and target in words, and a
  live region that reads the way's kind, not each hedge (R-m6); check steps that can fail (R-m7: at least one flow
  refused at port 853, the injected answer through the fallback asserted, Android's own validation reaching the
  engine where the emulator reaches the internet).
- **The size gate.** The brief asked first for HPKE over aws-lc-rs's primitives, one audited provider: measured, it
  brought aws-lc's X25519, HMAC and AES-GCM into a library that links only its ChaCha20-Poly1305 for WireGuard, and
  grew by 757,320 bytes on arm64, 494,580 on armv7 and 986,888 on x86_64. HPKE was therefore written over
  `x25519-dalek`, `hkdf` and `aes-gcm`, which the library already holds, held to RFC 9180's vectors both ways, the
  Python oracle, `odoh-rs` (now in tests only) and the fuzz target. Measured, stripped, against the gate of 2,097,152
  bytes (arm64 / armv7 / x86_64): before the round 1,836,584 / 1,557,176 / 2,136,152; with the own HPKE 1,817,416 /
  1,539,760 / 2,106,376; with the round's other fixes 1,821,304 / 1,542,192 / 2,109,944; with the presets' words and
  the bridge's texts moved to Kotlin, no cost in speed, 1,819,448 / 1,540,784 / 2,106,872. In Advanced's release APK,
  as `scripts/check.sh android` reads the gate, after the rebase on main: 1,817,800 / 1,539,280 / 2,105,352, x86_64
  8,200 bytes over the gate. Then, at the coordinator's second step: building the DNS path's crypto crates (aes-gcm,
  aes, ghash, polyval, hkdf, sha2 and their traits) with opt-level `z` left x86_64 unchanged and made arm64 864 bytes
  larger, and was taken back; building `ed25519-compact`, which checks a data pack's signature when the pack is read
  and never runs per packet, with its `opt_size` feature (its field arithmetic called rather than inlined; one
  function alone was 133 KB on x86_64) gave **1,695,200 / 1,256,752 / 1,933,072**, x86_64 164,080 bytes under the
  gate, with the gate unchanged. Its cost, on this computer: a signature's check 33 → about 44 µs, and the SHA-512
  over a signed pack about 3.5 times slower (3 MB: 4 → 14 ms; the bundled payload is 0.65 MB). Lookups do not touch
  it: the network part's CPU per lookup on the emulator stayed 19, 17 and 13 ms (ODoH, DoH, DoT, 60 lookups each,
  before and after), the lab's ODoH p50 and p95 10 and 51 ms before, 4 and 49 ms after, and ODoH's seal and open 55.6
  µs and 1.50 µs before, 55.6 to 56.9 µs and 1.50 µs after.

**Release gate for the maintainer:** each volunteer operator whose endpoint is a default (Numa, crypto.sx,
dnscry.pt) is asked before a release ships it; Cloudflare's ODoH page states no logging policy of its own.

## Consequences

- **VPN.md's default.** VPN.md's DNS row and DESIGN.md's W3 and W8 rows point here. The network's resolver is not
  the default for direct apps; it is decision 3's fallback.
- **ADR 0034's requirement narrows.** Upstream queries to the network's resolver through `DnsResolver` matter
  only for the fallback.
- **The engine needs HPKE for ODoH, and no TLS client:** the platform's TLS carries DoH, ODoH and DoT from the
  network part's Kotlin side (point 1). The engine's new parsers (ODoH's messages, the hygiene, the datasets) are
  fuzzed, and they, `odoh-rs` and `hpke`, which no one has paid to audit, fall within the outside review (ADR 0039).
