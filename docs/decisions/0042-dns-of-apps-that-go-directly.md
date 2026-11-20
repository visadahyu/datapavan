# 0042. DNS of apps that go directly: Oblivious DoH, several jurisdictions

- Status: Accepted (by the maintainer on 2026-11-12), with open questions; part 1 of W8 built on 2026-11-20 (below)
- Date: 2026-11-12

## Context

Apps that Watch sends through the user's tool have their names resolved by the tool
([ADR 0038](0038-dns-of-chained-apps.md)). Every other app goes directly. For those, Watch's resolver answers
inside the tunnel and asks upstream, today as plain DNS from a protected socket to the network's resolver
([VPN.md](../VPN.md), DESIGN.md §13.2, W3). So by default the network sees every name a direct app looks up,
unless the user set Private DNS. The plan for W8 adds a DoH or DoT resolver of the user's choice and a strict
setting that never falls back to the network.

Encrypting the questions to one resolver hides them from the network, but hands all of them, with the user's
address, to that resolver's operator. Oblivious DoH (ODoH, RFC 9230) splits the two:
- **A relay** sees the user's address but not the question.
- **A target** sees the question but not the address.

In filtered networks, though, DoH and its relays are often blocked, and a resolver that cannot be reached
leaves every direct app without names.

## Decision

1. **ODoH is the default** upstream for the names of apps that go directly, once W8 is built. No single server
   sees both who asks and what.
2. **Several jurisdictions.** Relays and targets are chosen from more than one operator and jurisdiction, and the
   user can see and change them.
3. **The network's resolver is a fallback only,** outside the strict setting. Watch uses it only when no
   encrypted path answers, and says so on its screen while it does. With the strict setting, it is never used.
4. **The user's own choice stays.** A DoH or DoT resolver of the user's choice, and the strict setting, remain as
   W8 planned.

## Open questions

Answered by part 1 (2026-11-20), as far as it goes: **which relays and targets**, the datasets and the defaults
above, with sh2o out; whether the project runs or sponsors a relay stays the maintainer's (a project relay paired
only with other operators' targets adds a jurisdiction; running both halves would be collusion by design).
**Fallbacks in filtered networks**: the ladder, its holds and strict above; still open at the frontier, and left
for later with reasons: DNS over QUIC and DoH3 (no hook for the socket or the resolver in Android's HttpEngine),
SNI left out and a ClientHello split on retry, per endpoint (no dataset field for them yet), and ODoH's reachability
in filtered networks, never measured. **The cost**: measured, ADR 0039.

- **Which relays and targets.** Few public ODoH relays exist. Their operators and terms, and whether the
  project should run or sponsor one, are read before W8.
- **Fallbacks in filtered networks.** How Watch keeps names working where DoH and ODoH are blocked, without
  falling back silently to a resolver the censor controls, is research at the frontier.
- **The cost.** ODoH adds a hop to each uncached name. Its latency is measured against Watch's speed budget
  (ADR 0039).

## How it is built (W8, part 1)

Decided before the build in its brief and audited once (strategy repository, `research/2026-11-w8/`), revisable by
the maintainer; built on `watch-w8a` on 2026-11-20. Each point as built:

1. **TLS is the platform's, not the engine's.** DoH, ODoH's HTTP and DoT run in Kotlin in `:watch`
   (`dns/Exchanger.kt`, `dns/DotClient.kt`) on Android's own TLS (Conscrypt, BoringSSL), whose ClientHello is every
   Android app's: OkHttp 5.5.1, pinned, with HTTP/2; no `User-Agent`, no `Accept-Encoding` (compression would undo
   the padding), no cookies, no cache, no redirects; its `Dns` answers only with the data pack's addresses, so no
   server's name is ever looked up; certificates checked against Android's own roots only (`AndroidCAStore`'s
   `system:` aliases, never a user's or an administrator's, `dns/SystemTrust.kt`), plus each endpoint's pins where
   the dataset gives them; DoT checks the server's name in the handshake; one client, connection pool and TLS
   session cache per network beneath, idle connections closed after 60 s and opened again on demand; Conscrypt sends
   no early data. Every socket is protected from the tunnel and bound to the network beneath, or goes through the
   user's tool (`dns/ToolSocket.kt`, SOCKS5 with its password, the destination by address). The engine hands each
   exchange over (`Platform::exchange`, which returns at once) and awaits its reply (`Engine::exchanges`), so the
   packet loop never waits. What the platform does not give, written as it stands: Conscrypt is a Mainline module
   from Android 10, but whether a given image keeps it updated is not verified (the Android 15 emulator image used
   here carries `com.google.android.conscrypt` 350820300, its factory version); the root store is updated apart from
   the system only from Android 14; ECH comes only from Android 17, for apps that target API 37; no source shows
   post-quantum key exchange by default.
2. **The engine keeps** the DNS parsing (its own: `hygiene.rs`, `dns.rs`), the caches (`dnscache.rs`, with RFC
   8767's stale answers), the policy (`ladder.rs`, `engine/resolver.rs`) and ODoH's HPKE (`odoh.rs`: Cloudflare's
   `odoh-rs` 1.0.5 on rozbb's `hpke` 0.14.1, pinned). Measured inside `core`, stripped: arm64 1,836,584 bytes
   (+127,832 over W7), armv7 1,557,176 (+91,440), x86_64 2,136,152 (+152,976), against the 2,097,152-byte gate.
   ODoH's crypto alone is +29,440 / +24,864 / +40,840; the rest is the resolver's own code. Savings that cost no
   speed were taken (the resolver's tasks boxed into one type, its small tables as lists, no generic sort: about
   20 KB on x86_64); opt-level `z` for the cold crates made x86_64 larger, not smaller. **x86_64 stays 39,000 bytes
   over the gate; arm64 and armv7, the phones' ABIs, are within it.** Stopped there for the maintainer, as the brief
   asks, without raising the gate: an own HPKE (base mode, export, one suite) over `x25519-dalek` 2, `hkdf` and
   `aes-gcm`, already in the tree, would save about the 40 KB ODoH's crypto costs, which only just reaches the gate;
   or a written exception for x86_64, the emulators' ABI (and ChromeOS's on Intel).
3. **Data, signed, in the pack:** `data/odoh` (relays, targets with their bootstrap keys, the default pairs) and
   `data/dns-presets` (the user's choices, each with its card), CC0, every value with its source. `data/resolvers`
   stays a detection list. Either changes without a release; closed services are left out.
4. **ODoH pairs** (`catalogue.rs`): refused on a shared operator, person, jurisdiction, or hosting or CDN network,
   read from the fields; an entry whose person, jurisdictions or hosting the dataset does not know never pairs.
   Defaults, verified again on 2026-11-20: Numa's relay (DE, RO; AS24940) to Cloudflare's target (US, CR; AS13335),
   then crypto.sx's relay on Fastly (FR, US; AS54113) to dnscry.pt's fra01 (DE; AS44486). sh2o is out while its
   operator is unknown. The second pair is asked 400 ms after the first, unless the first failed sooner: about
   three times the warm p95 of the first pair in the lab and twice its cold first query on the internet (below);
   each attempt is sealed afresh. Only unfiltered targets pair. The user sees the pairs on Watch's screen and
   changes them among those the rule allows.
5. **Target keys.** No target publishes `odohconfig` in a DNS HTTPS record (checked through two resolvers on
   2026-11-20: Cloudflare's record has none, crypto.sx's has ECH only, dnscry.pt's nodes have no HTTPS record). The
   engine still asks for it first, after a 401, through two ways of different operators, and takes it only when
   both agree; failing that it fetches `/.well-known/odohconfigs` from the target, through the user's tool while it
   is on, else directly over the network beneath: **an accepted limit**, which shows the phone's address to the
   target once per key, and gives no assurance that every user holds the same key. The pack's copy bootstraps.
   Rotation measured during the build: Cloudflare's and fra01's configurations did not change between 13:44 and
   15:39 UTC; Cloudflare serves its with `no-store` and a `Last-Modified` of that day's 00:00 UTC, so a daily
   rotation is likely and is not yet shown.
6. **The order, by privacy** (`ladder.rs`): the user's own resolver, else ODoH; then, while the user's tool is on,
   ODoH through the tool; then DoH to the targets' own operators; then the presets that filter nothing; the
   network's resolver last, never in strict. Watch learns only within a rung (the step that answered last is
   tried first there) and climbs back as soon as a higher step's hold ends. Holds: 5 s after a timeout, a refusal
   or an error, doubling to 60 s; 360 s after a reset once the TLS hello was out or a certificate that does not
   check; none after a 401 (the key is fetched again); none while Android says the network is not validated (a
   captive portal); all cleared, with everything learned and the answers kept, on a change of network. Nothing of
   it is stored or keyed by a network's name.
7. **Strict:** with no encrypted way answering, "server failure" at once, and the screen says why. Local names
   (single labels, the network's search domains, `home.arpa`, `ipv4only.arpa`, `resolver.arpa`, `localhost`,
   `local`, the zones of RFC 6303 and RFC 7793) go to the network's resolver in either setting, and the screen says
   so; it also says what strict cannot cover: Android's own connectivity checks and apps' own encrypted DNS.
8. **Hygiene** (`hygiene.rs`): ID 0 (RFC 8484); every EDNS option the app sent dropped (client subnet and cookies
   among them); EDNS(0) padding to 128-byte blocks (RFC 8467), which asks the resolver to pad its answer (RFC 7830);
   the answer made the app's again (its ID and question, a bare OPT record or none, cut to a truncated answer past
   what it takes over UDP, so that it asks again over TCP); answers kept for their time to live and served stale
   for up to a day, with a time to live of 30 s, while a fresh one is asked (RFC 8767); no DNSSEC validation on
   the phone (the resolvers validate; a stub would need DNSKEY and DS chains for each name, more round trips through
   a relay, and a validator, a code class with a long 2026 record of proof bypasses); both address families towards
   the resolvers where the dataset gives them; ADR 0038's per-route caches kept.
9. **The two leaks closed.** Once the resolver is set, every port of Watch's DNS address but 53 is refused, TCP with
   a reset and UDP with an ICMP error, so Android's opportunistic DNS over TLS asks on port 53 (seen on the emulator:
   Private DNS on "automatic", the flow to port 853 refused, the names still by ODoH); DNS over TCP at port 53 goes
   to the engine's own listener and the same ways (`connect_lookups`); a chained app's other record types go the
   encrypted ways through the tool, never to Quad9 in plain DNS (`lookups.rs`).
10. **W7's endpoint names** go the encrypted way (`resolver::endpoint`), not to Android's resolver; outside strict
    the network's resolver answers when nothing else does, and the tunnel's state says plain; in strict nothing does.
11. **The screen** (`ui/DnsSection.kt`) says which way names go now (the relay's and target's operators and
    countries), the fallback while it lasts, and, if the user turns it on, a notification while it lasts (Watch has
    no tile until W9); when Android's strict Private DNS takes the names past Watch; the choice, with each preset's
    card. Nothing of the names is kept or logged: the state names ways, never lookups.
12. **Speed:** ADR 0039's budget, measured on 2026-11-20 (below there).

Checks: the unit tests (the ladder, the pair rule, the hygiene, the catalogue against the shipped tables, the
resolver with a fake Kotlin side: ODoH, hedging, a 401's key, strict, local names, the fallback and its end, TCP,
the tool, endpoint names, the captive portal); HPKE against RFC 9180's A.1.1 vectors, both sides; ODoH against an
implementation of its own in Python, to the byte (`core/net/testdata/odoh/oracle.py`, since RFC 9230 has no
vectors); the engine through its tunnel (`core/net/tests/resolver.rs`); the transport on the JVM against the lab's
certificates (DoT, pins, a user's root refused, a certificate for another name refused, the tool's SOCKS5); three
new fuzz targets (`odoh`, `hygiene`, `catalogue`: 4.5, 12.2 and 3.8 million runs, no finding); 31 hand mutants
on the new rules, all killed (six by tests added for them); the DNS lab (`scripts/dnslab.sh`) and the emulator
check (`scripts/verify-dns.sh`), passed on the Android 15 emulator.

**Limits, as they stand:** Android sends its connectivity checks, and DNS of apps excluded from the tunnel, past
Watch; apps that send DNS themselves (to 8.8.8.8, or their own DoH) are named, not redirected; while Watch's process
is killed or the tunnel is set up anew, Android may resolve outside the tunnel unless Always-on with "Block
connections without VPN" is set (Mullvad, 2024: its getaddrinfo path), which onboarding recommends; an injected
answer reaches whatever the network's resolver answers (local names, and the fallback outside strict); the target
key's fetch above; ODoH does not hide the connection that follows a lookup (its address, and its server name
without ECH); one person curates the public ODoH list and runs a relay and a target; Android's own validation of
the network could not be exercised in the lab (its resolver knows only the lab's names), so the emulator check
tells the engine the network's state, while the unit tests hold the rule.

**Release gate for the maintainer:** each volunteer operator whose endpoint is a default (Numa, crypto.sx,
dnscry.pt) is asked before a release ships it; Cloudflare's ODoH page states no logging policy of its own.

## Consequences

- **VPN.md's default changes.** VPN.md's DNS row and DESIGN.md's W3 and W8 rows now point here. The network's
  resolver stops being the default for direct apps once W8 lands. Until then, the screen says that direct apps'
  names go to the network's resolver.
- **ADR 0034's requirement narrows.** Upstream queries to the network's resolver through `DnsResolver` matter
  only for the fallback.
- **The engine needs HPKE for ODoH, and no TLS client** (corrected by W8's part 1: the platform's TLS carries DoH,
  ODoH and DoT from Watch's Kotlin side). The engine's new parsers (ODoH's messages, the hygiene, the datasets) are
  fuzzed, and they, `odoh-rs` and `hpke`, which no one has paid to audit, fall within the outside review (ADR 0039).
