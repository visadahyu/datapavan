# 0035. WireGuard upstream: GotaTun's protocol core in the engine, raw packets forwarded

- Status: Accepted (by the maintainer on 2026-11-09)
- Date: 2026-11-09

## Context

Milestone W7 ([DESIGN.md §13.2](../DESIGN.md#132-v020-watch-the-connection-log-next-to-circumvention-tools))
lets a provider's WireGuard configuration (Proton VPN's free plan, Mullvad and others), imported from a
file or a QR code, become Watch's upstream for the apps the user picks. Android allows one VPN at a
time, so one VPN then does both jobs. The "Before W1" list asks for this ADR: a Rust implementation
inside the engine (BoringTun and its maintained forks) against Go's wireguard-go, decided by licence,
upkeep and audit history.

The limits come from earlier decisions:

- **ADR 0006:** no `unsafe` in `datapavan-engine`. Dependencies may hold `unsafe`, but it must stay
  small and reviewed.
- **ADR 0012:** the system stack in Rust, one engine thread, no Go toolchain in the reproducible build.
  Each app's SYN is held until Android has named the app.
- **`core/deny.toml`:** only Apache-2.0, MIT and Unicode-3.0 pass today. Adding a licence is a
  deliberate, reviewed decision.
- **VPN.md:** the engine adds at most 1 MB per ABI (arm64, armv7, x86_64; minSdk 29), at most 3 % of a
  day's battery, no inbound path, and apps sent through an upstream wait when it is down. They never
  go directly.

Two things must be chosen: the **protocol core** (handshake, keys, timers, encryption) and how the
engine **forwards** the chosen apps' packets to it.

## Options for the protocol core

What was found on 2026-11-09 (sources at the end):

| Implementation | Licence | Upkeep in 2026 | Audit | On Android in production |
|---|---|---|---|---|
| Cloudflare BoringTun | BSD-3-Clause | 0.7.0 (January), 0.7.1 (May); last commit 2026-06-15 | none published found | Cloudflare's 1.1.1.1 app, per its README (current use unverified) |
| Mullvad GotaTun | MPL-2.0 (code before 2026-03-05: BSD-3-Clause) | 23 releases since 2025-11-06, 0.10.2 on 2026-10-20; commits to 2026-11-07 | Assured Security Consultants, 2026-01-19 to 2026-02-15 | Mullvad VPN since app 2025.10 (end of November 2025) |
| NordSecurity NepTUN | BSD-3-Clause | git tags only, v3.0.6 on 2026-10-06; commits to 2026-10-21 | none of NepTUN itself found | NordVPN's apps through libtelio (Android unverified) |
| Firezone's BoringTun fork, now **sanstun** | Apache-2.0, with BoringTun's BSD-3-Clause notice | fork archived; sanstun started 2026-10-02, 0.1.0 on 2026-10-30, commits to 2026-11-07 | none ("has not received a formal security audit") | Firezone's clients: the fork until 2026-10-20, sanstun since (released versions unverified) |
| Defguard's BoringTun fork | BSD-3-Clause | `defguard_boringtun` 0.7.1 on 2026-10-27 | none found | Defguard's clients (unverified) |
| wireguard-go | MIT | last snapshot tag 0.0.20250522; fixes on 2026-05-22, 2026-10-06, 2026-10-24 | none published found (unverified) | WireGuard's own app, Proton VPN (its own fork of WireGuard's Android library), Rethink, Mullvad until November 2025 |
| Kernel WireGuard | GPL-2.0 | | | only with root |

### Cloudflare BoringTun

- **API.** `noise::Tunn` takes a packet and returns a datagram for the network, or the reverse:
  `encapsulate`, `decapsulate`, `update_timers`, into caller buffers. With default features (no
  `device`) there is no TUN device, no socket and no thread. The caller drives the timers; BoringTun's
  own device ticks every 250 ms, and there is no call that says when the next timer is due.
- **Unsafe.** None in the protocol core except one call for the boot-time clock. The device, FFI and
  JNI modules hold the rest and are not compiled with default features.
- **Crypto.** `ring` for ChaCha20-Poly1305, `x25519-dalek` 2, RustCrypto `blake2`, `hmac` and
  `chacha20poly1305` (XChaCha for cookies).
- **Known issues.** No 16-byte padding of data messages (a `TODO` in `noise/session.rs`); a nonce
  counter that could wrap on 32-bit targets (armv7) under a long rekey time was fixed only in 0.7.1;
  the README still warns that the project "is currently undergoing a restructuring". Upkeep is slow
  but alive.

### Mullvad GotaTun

- **History.** A BoringTun fork. Mullvad replaced wireguard-go with it on Android in app 2025.10, after
  "more than 85%" of the crashes reported from Google Play came from wireguard-go. Mullvad reports the
  user-perceived crash rate fell from 0.40 % to 0.01 %. Mullvad's Android build lists aarch64, armv7,
  i686 and x86_64 among its Rust targets, so GotaTun runs on armv7 too (inferred from
  `android/scripts/generate-sboms.sh`). GotaTun's README tests only the arm64 and x86_64 Android
  libraries. F-Droid builds Mullvad's app, GotaTun included, from source with NDK r27d.
- **Audit.** Assured audited the whole implementation except the CLI, the DAITA code and the external
  dependencies. Findings: two low (session indices from an LFSR, no padding), nine notes, one good. The
  low ones were fixed in 0.3.0, the roaming note in 0.4.0. Open notes: keys are not specially protected
  in memory (3.5), and `ring` is a one-person project (3.9).
- **API.** `noise::Tunn` with `handle_outgoing_packet`, `handle_incoming_packet`, `update_timers` and
  `get_queued_packets`; packets are `gotatun-packet` types. The `device`, `tun`, `socket` and `daita`
  features are optional. `tokio` is a hard dependency even without them. While a handshake runs, Tunn
  queues up to 256 packets. Its own device calls the timers every 250 ms; it has no next-deadline call.
  *Spike, 2026-11-19 ([spike](../spikes/2026-11-wireguard-core.md)): the API is the same in 0.10.3;
  the packet types are GotaTun's own `packet` module, not a separate crate; without the device the caller
  also passes every datagram through `RateLimiter::verify_packet` (the MAC check) and checks AllowedIPs
  after decryption.*
- **Unsafe.** None in the protocol core (its clock module forbids `unsafe`); one site in
  `gotatun-packet`'s buffer pool; two in the optional socket module. *Spike, 2026-11-19: 17 sites in the
  0.10.3 package, 1 compiled without the optional features (`packet/pool.rs`, in GotaTun itself); the 58 new
  crates that reach the library hold 2,446.*
- **Crypto.** `aws-lc-rs` by default since 0.6.0 (2026-04-30), `ring` with
  `default-features = false, features = ["ring"]`. Mullvad measured RustCrypto's `chacha20poly1305` at
  "roughly a 50% drop in tunnel throughput", and `aws-lc-rs` equal to `ring`. Mullvad's app uses
  `aws-lc-rs`.
- **Cost.** About 29 direct dependencies (counted from its manifest), and ten 0.x minor versions in a
  year, each allowed to break the API.

### NordSecurity NepTUN

A BoringTun fork, used by Nord's GPL-3.0 libtelio, which Nord calls "the backbone of all our NordVPN
applications". Same `Tunn` shape and crypto as BoringTun, still without padding. It is not on
crates.io: Watch would need a git dependency, which `deny.toml` forbids today (`unknown-git =
"deny"`). A Cure53 audit of NordVPN's meshnet (December 2024) covered libtelio; whether NepTUN was in
scope is unverified.

### Firezone's fork, now sanstun

Firezone archived its BoringTun fork and on 2026-10-20 replaced it in its client library with
**sanstun**, a redesign by the same people. It is fully "sans-IO": time and random seeds come from the
caller, it keeps no internal buffers, and it tells the caller when its next timer is due
(`poll_timeout`, `handle_timeout`). It has no `unsafe` at all (about 4,600 lines), pads data messages,
randomises session indices, and needs 9 direct dependencies (`ring`, `x25519-dalek` 3, RustCrypto
`blake2`, `chacha20`, `hmac`, `subtle`, `zeroize`, `rand`, `tracing`). Firezone's own changes are
Apache-2.0 since 2026-10-30; the 0.1.0 crate on crates.io still declares BSD-3-Clause. Against it: five
weeks old, a breaking change already after 0.1.0, one company, no audit, and the caller must route by
AllowedIPs and queue packets during a handshake itself.

### Other Rust forks

Defguard's fork adds dependency updates and Swift bindings, nothing an Android engine needs. EasyTier's
fork stopped in August 2024. The WireGuard project's own Rust implementation, `wireguard-rs`, has had no
commit since January 2021. `onetun` (MIT) is not an implementation: it puts `smoltcp` on top of
BoringTun.

### wireguard-go

The reference userspace implementation, by WireGuard's author, MIT. The official Android app builds it
with Go 1.24.3, which its Makefile downloads and patches (`goruntime-boottime-over-monotonic.diff`, so
that Go's timers count deep sleep), into `libwg-go.so` through cgo. The official APK 1.0.20260315 is
16.9 MB as one APK (its contents were not opened); the per-ABI size of the Go library was not
measured here. The spike's gVisor library was 5.4 MB per ABI. The device owns a TUN device and its
goroutines; packet in and packet out needs a custom `tun.Device`, as `tun/netstack` does, behind a
Rust-to-C-to-Go call per batch. That brings back everything ADR 0012 kept out: the second toolchain,
a second runtime and garbage collector in the VPN process, and a split hot path. No public audit was
found.

### Kernel WireGuard and an implementation of our own

Android's generic kernels carry WireGuard, but creating and configuring the interface needs
`CAP_NET_ADMIN`. The official app uses it only through a root shell (`WgQuickBackend` checks
`/sys/module/wireguard` and runs `wg` as root). A normal app has only `VpnService`, so this is not
available, and it would take the packets out of the engine anyway. Writing our own is not an option:
the forks show how easy the details are to get wrong (index randomness, padding, roaming, the nonce
counter on 32-bit targets, a handshake race wireguard-go fixed on 2026-10-06).

### What every Rust option brings

- **Licences.** `x25519-dalek`, `curve25519-dalek` and `subtle` are BSD-3-Clause, and `ring` is
  "Apache-2.0 AND ISC". So every Rust option adds BSD-3-Clause and ISC to `deny.toml`. BoringTun,
  NepTUN and GotaTun also add BSD-2-Clause (`ip_network`, `ip_network_table`). GotaTun adds MPL-2.0;
  `aws-lc-rs` would add nothing beyond these (its terms are ISC, Apache-2.0, MIT and BSD-3-Clause).
  All are compatible with Apache-2.0. MPL-2.0 is file-level copyleft: Watch stays Apache-2.0, but
  changes to GotaTun's own files would have to be published under MPL-2.0, and a binary must say
  where its source is. wireguard-go is MIT, and Go's standard library BSD-3-Clause.
- **Build.** `ring` compiles C and pre-generated assembly with the NDK's clang, which `cargo-ndk`
  supplies; no Perl, CMake or Go. `aws-lc-rs` compiles the much larger AWS-LC with a C compiler only
  (CMake "never required" outside FIPS). Both put C objects into the reproducible build, so
  `scripts/reproducible.sh` must cover them. RustCrypto alone would be pure Rust, but none of the
  candidates offers it for the data path.
- **Size.** No candidate publishes a library size. The spike below measures it. *Spike, 2026-11-19:
  GotaTun adds 149 KB to Watch's stripped library on arm64 with `ring` (123 KB on armv7, 191 KB on x86_64),
  and 170 KB with `aws-lc-rs`.*
- **Clock.** WireGuard's timers must count deep sleep, or a phone that wakes uses a session the server
  has already dropped. BoringTun, NepTUN and GotaTun read `CLOCK_BOOTTIME` themselves. sanstun takes
  the time from the caller, and Rust's `Instant` uses `CLOCK_MONOTONIC`, which does not reliably count
  suspend, so Watch would have to supply boot time.

## Options for the forwarding

1. **End each connection in Watch and dial again through a TCP stack inside the tunnel.** This is the
   usual way: Rethink, the closest product (a firewall with per-app WireGuard on Android), runs
   wireguard-go with a second gVisor netstack; sing-box dials through a userspace stack inside its
   WireGuard endpoint (Xray and mihomo likewise, unverified here); `onetun` uses `smoltcp` on
   BoringTun. Each tunnelled connection would cross two TCP stacks, and Watch would need a userspace
   TCP stack, which ADR 0012 rejected (`ipstack`).
2. **Give the TUN the configuration's address,** as WireGuard's own app does: packets then need no
   change. But Watch's tunnel carries every app and the system stack's listener and fake peer. Android
   picks one source address for all apps on an interface, and a new configuration would mean a new
   TUN, breaking every app's connections.
3. **Forward the chosen apps' raw IP packets into the session, swapping the address.** The app's own
   TCP then runs end to end with the server. Address swaps with checksum updates are basic NAT
   (RFC 3022, RFC 1624), which the system stack already does.

## Decision

**The protocol core is GotaTun's `noise::Tunn`,** pinned to an exact version, with
`default-features = false, features = ["ring"]`: no device, TUN, socket or DAITA code. It is the only
audited Rust implementation, in production on Android at Mullvad since November 2025, and the most
actively kept. It sits behind a small trait in `datapavan-engine`, so that sanstun or BoringTun can
replace it in one module. The configuration (`wg-quick` format) is parsed in the engine and fuzzed
like every parser.

**The forwarding is option 3.** For an app the user chose:

- **The held SYN decides.** The engine holds the first SYN (or the first UDP datagram) as now and asks
  Android for the owner. A chosen app's flow is marked "tunnel". There is no upstream connect; the
  source is swapped from the TUN address to the configuration's address, the IP and TCP or UDP
  checksums are updated incrementally, and the packet goes to `Tunn`. Ports are not changed: the kernel
  already gives each socket on the TUN address its own port, and the configuration's address belongs to
  this phone alone. The flow table keeps the decision, the counters and the firewall state.
- **Back from the tunnel.** A decrypted packet passes only if its source is inside the peer's
  AllowedIPs and it belongs to a flow a local app started; everything else is dropped (VPN.md, "No
  inbound path"). The destination is swapped back and the packet written to the TUN. ICMP errors get
  their inner header swapped too, as a NAT does (RFC 5508). A refused or unreachable server looks so
  to the app, because the answer is the server's own.
- **DNS.** Android's resolver sends each query on a socket it hands to the asking app's UID (`fchown`
  in AOSP's `resolv_tag_socket`), so the owner lookup should name the app; to confirm on devices. A
  chosen app's query to Watch's DNS address is redirected to the configuration's DNS server through the
  tunnel, TCP queries too, and its answer is read for the log on the way back. Its names never reach
  the network's resolver. A configuration without a DNS line is an open question below.
- **IPv6.** With an IPv6 address in the configuration, the same swap. Without one, a chosen app's IPv6
  gets an ICMPv6 "unreachable" (W2 already plans these), so it falls back to IPv4 inside the tunnel.
  Never directly.
- **MTU.** While a WireGuard upstream is set, the TUN's MTU is the configuration's MTU, or 1280 as in
  WireGuard's own app. Direct apps then send smaller segments on the local leg only; W7 measures the
  CPU this costs on the A40. If it is too much: keep the MTU, clamp the MSS in a tunnelled SYN, and
  answer oversized packets with "fragmentation needed" or "packet too big", as routers do.
- **Timers and keepalive.** The engine calls the timers from its one event loop, about once a second,
  only while a session exists or a handshake runs; an idle tunnel costs no timer (GotaTun rounds its
  timers to the second). `PersistentKeepalive` is used only if the configuration sets it, since each
  keepalive wakes the radio. *Spike, 2026-11-19: GotaTun does not round them, and it stamps every event
  with the time of the last `update_timers` call, which alone expires sessions; so the engine also calls it
  before a packet that comes after a pause of a second or more. Against the kernel's WireGuard the
  one-second tick kept `PersistentKeepalive` within 0.1 s and rekeyed 120.7 s after the first handshake.*
- **A dropped tunnel.** No code path leads from a chosen app's flow to a direct socket. While the
  provider does not answer, packets wait in Tunn's bounded queue or are lost on the way; the apps see
  timeouts and Watch says the provider does not answer. If Watch itself crashes under "Block
  connections without VPN", Android blocks everything (ADR 0006).
- **Roaming.** The tunnel's UDP socket is protected, like every upstream socket. On a network change
  (W2's callback) Watch re-creates it if needed and at once sends a keepalive, or a new handshake if
  the session is old, so the server learns the new address. The server's address stays the configured
  one, as wireguard-go does on Android (`DisableSomeRoamingForBrokenMobileSemantics`). The chosen
  apps' connections can survive a switch between Wi-Fi and mobile, because their address inside the
  tunnel does not change; direct apps' do not (spike).
- **Flows without an owner** follow the stricter path: through the tunnel while any app is chosen.
  To confirm with the maintainer (open questions).

**Before building W7,** a short spike on the A40 and the emulators: size per ABI with `ring` and with
`aws-lc-rs`, CPU per megabyte through the tunnel against W2's engine alone, both builds reproducible,
and a Proton VPN free configuration carrying TCP, UDP, IPv6 and DNS.

**How this stands against the field.** The protocol core is today's best choice in Rust: the one a
large provider moved its Android app to, and the only one audited. The forwarding is better than what
Android firewalls do today (a second TCP stack inside the tunnel), and costs less CPU. Each part is
standard: a WireGuard core fed packet by packet (BoringTun's design), NAT with incremental checksums,
MSS clamping, ICMP for path MTU, a protected endpoint socket, a fixed server address and boot-time
timers on Android (WireGuard's own app). New is the combination: per-app routing decided in the engine
at the held SYN, and DNS routed per app by the owner of the resolver's socket, beside the system stack
in one tunnel. No research is needed; the spike is.

## Consequences

- **`deny.toml` gains BSD-3-Clause, BSD-2-Clause, ISC and MPL-2.0** (accepted with this ADR), in the
  commit that brings GotaTun in (W7), not before, so that nothing else slips in under them; the
  comment "only permissive" changes for MPL-2.0. The licence screen and NOTICE list them. Changes to
  GotaTun's files, if ever needed, are published upstream or under MPL-2.0.
- **No Go.** The reproducible build gains C objects from `ring` only, through the NDK's clang. *Spike,
  2026-11-19: with GotaTun inside `core`'s workspace, two clean builds at different paths give identical
  libraries for all three ABIs, with `ring` and with `aws-lc-rs`, and no path of the machine in them.*
- **About 29 more direct crates,** some shared with the engine (`tokio`). Each GotaTun upgrade is a
  reviewed step, often a breaking one. *Spike, 2026-11-19: 29 on Android; Watch's library goes from 54
  crates to 120, 8 of the new ones build-time macros; `tokio` gains no feature; the lock gains a second
  generation of RustCrypto's traits.*
- **The engine sees segments, not a byte stream,** for tunnelled TCP. Naming a flow by its TLS server
  name (W3) needs a small, bounded reassembly of the first segments, since a ClientHello with
  post-quantum key shares is larger than one segment.
- **The log.** Tunnelled flows are counted per app. Proposed: their destinations are recorded only if
  the user turns that on, as for flows chained through a tool (VPN.md), since a log of them is evidence
  in a phone search.
- **Accounting.** Android sees the tunnel's datagrams as Watch's traffic. ADR 0022's open check of how
  Android counts traffic that passes a VPN covers this too.
- **Keys.** The private key is wrapped with a Keystore key at rest (W7), unwrapped only to build the
  session, and zeroed after; `x25519-dalek` zeroes its secret on drop. In memory it has no further
  protection, as Assured noted for GotaTun and as wireguard-go has none.
- **Plain WireGuard is easy to recognise on the wire.** On networks that block it, W7 does not help;
  chaining through the user's tool (W6) stays the way there.
- **Fallback.** sanstun if GotaTun's licence or churn becomes a problem, once sanstun has an audit;
  BoringTun after that. The trait keeps the switch to one module.

## Open questions

1. **MPL-2.0 or no audit?** Is MPL-2.0 acceptable for Watch and the organisational edition (ADR 0033)?
   If not, sanstun (Apache-2.0, unaudited, five weeks old) is the next choice.
2. **`ring` or `aws-lc-rs`?** Proposed `ring` (smaller, fewer licences); Mullvad's app uses `aws-lc-rs`.
   The spike's size and CPU decide. *Spike, 2026-11-19 ([spike](../spikes/2026-11-wireguard-core.md)):
   `ring`, unless the A40's run shows `aws-lc-rs` 10 % faster or more on ARM. On x86_64 the two are equal
   within 2 % (both ways about 0.85 ms per MB on the development machine, 1.45 on the emulator); `ring` is
   21 KB smaller on arm64; both builds are reproducible and need the same four licences. The A40's run
   (the coordinator, 2026-11-19): equal within 1 % in 64-bit code on both core classes (11 to 19 ms per MB),
   `aws-lc-rs` 7 to 11 % faster in 32-bit code; the line sits on the threshold, so the maintainer decides.*
3. **Size:** does the engine stay under 1 MB per ABI with WireGuard in it? Unverified. *Spike,
   2026-11-19: no, and it is over already: Watch's library is 1.38 MB on arm64 today (1.22 on armv7, 1.59
   on x86_64), and 1.53 MB with GotaTun on `ring` (1.34, 1.78). The spike proposes a measured budget with a
   gate instead of the 1 MB target.*
4. **Android's DNS cache is shared** by all apps of one VPN network. A direct app's answer from the
   network's resolver can be served from the cache to a chosen app, and so can a censored one. Not a
   leak of the chosen app's question, but a wrong answer is possible. One idea: answers from the
   network's resolver get TTL 0 while any app is tunnelled or chained. Unverified that Android then
   does not cache them. Shared with W6. *Answered on 2026-11-11 on the emulators with Android 11, 15
   and 17 ([spike](../spikes/2026-11-shared-dns-cache.md)): the cache is shared, and an answer or a
   negative answer with TTL 0 is not kept. Every answer gets TTL 0 while any app is chained or
   tunnelled, and Watch keeps a cache of its own per route. The A40 and Android 10 to 16 are still to
   run.*
5. **Is the owner of the resolver's query socket the app** on Android 10 to 17 and on other vendors?
   The AOSP source says so; to check on the A40 and the emulators. Shared with W3 and W6. *Yes on the
   emulators with Android 11, 15 and 17 (same spike); the A40 and Android 10 to 16 are still to run.*
6. **Strict Private DNS:** Android then sends queries over one DNS-over-TLS connection per network, not
   per app (inference, unverified). Chosen apps' names would then go to the user's Private DNS server,
   encrypted, not to the provider's. The UI should say so.
7. **Flows without an owner, and ICMP echo** (Android names no owner for ICMP): through the tunnel, or
   refused?
8. **LAN access** for chosen apps (printers, a NAS): with AllowedIPs `0.0.0.0/0` they fail. Offer
   "local network directly", as WireGuard's app offers "Exclude private IPs"?
9. **Which configurations W7 accepts:** one interface and one peer only? A hostname endpoint (resolved
   how, before the tunnel)? AllowedIPs narrower than everything (then the rest is refused, never sent
   directly)? No DNS line (then the user's DoH or DoT resolver through the tunnel)?
10. **QR import** needs `CAMERA` (Watch's permissions ADR) or decoding a QR code from a picked image,
    which needs no permission. The decoder parses hostile input.
11. **Proton's free configuration:** does it carry an IPv6 address and `PersistentKeepalive`? Not
    verified; the W7 test from outside shows it.
12. **Timers:** is a one-second tick while a session lives cheap enough, or should GotaTun get a
    next-deadline call (Firezone added one to its fork before sanstun)? Measured in W9's battery runs.
13. **IPv6-only mobile networks** with 464XLAT: an IPv4 endpoint through Android's CLAT from a
    protected socket. To test.
14. **Obfuscated variants** (AmneziaWG, a wireguard-go fork): later, if users' networks need them.

## Settled with the maintainer (2026-11-19)

Before W7 was built, the maintainer took these answers to the open questions, after a check of each against the
field's best:

- **Question 1:** MPL-2.0 stands, as accepted with this ADR; GotaTun it is.
- **Question 2:** decided by the spike below (size, CPU, reproducible builds); `ring` unless the spike shows
  otherwise. *Decided after the spike (the maintainer, 2026-11-19): **`aws-lc-rs`**, GotaTun's default and what
  Mullvad ships. Equal to `ring` in 64-bit code on the A40, 7 to 11 % faster in 32-bit code, kept by a team where
  `ring` is mainly one person's (the audit's note 3.9), for 21 KB more on arm64 and a larger C library in the
  reproducible build.*
- **Question 3, decided after the spike (the maintainer, 2026-11-19):** Watch's native library stays within **2 MB
  per ABI**, as Advanced's release APK ships it, held by a gate in `scripts/check.sh android`; VPN.md's earlier
  target of 1 MB, which nothing held, was passed before WireGuard (1.38 MB on arm64).
- **Question 7:** flows Android names no owner for, and ICMP echo, go through the tunnel while any app is chosen;
  never directly.
- **Question 8:** a switch "Local network directly" for the chosen apps (printers, a NAS: private, link-local and
  unique-local ranges), off by default, as Mullvad's local network sharing and WireGuard's "Exclude private IPs".
- **Question 9:** one interface and one peer; `PresharedKey` supported where the provider gives one (WireGuard's
  only defence against a future quantum computer recording today's handshakes). An endpoint given as a host name is
  resolved before the tunnel through a protected socket over encrypted DNS where Watch has it, and the user is told
  when only plain DNS could resolve it (the network would learn which provider the user chose); most providers'
  files, Proton's among them, give an address. AllowedIPs narrower than everything: the rest is refused, never sent
  directly. A configuration with no `DNS` line is refused in W7 with a plain message: its names would otherwise have
  nowhere private to go; W8, which brings the user's own encrypted resolver, routes them through the tunnel to it
  instead.
- **Question 10:** a QR code is read from a photo the system camera takes for Watch (`ACTION_IMAGE_CAPTURE`, which
  needs no camera permission of Watch's own) or from a picked image, decoded with ZXing's core library
  (Apache-2.0); Watch never holds `CAMERA`.
- **Question 11 and the check from outside:** with a Proton VPN free configuration that the maintainer imports on
  the A40 personally; no agent sees or moves its private key.
- **Tests without a provider:** a WireGuard peer of the reference implementation (the Linux kernel's or
  wireguard-go) in a container on the development machine and on CI, so that every run tests interoperation with
  WireGuard itself, not GotaTun with GotaTun.

- **Routes, decided before W7 was built (the maintainer, 2026-11-19):** each app has one route: directly,
  through the user's tool (W6), or through one WireGuard configuration; the tool's chain and WireGuard run at once,
  for different apps, as RethinkDNS allows. **Several configurations** are kept and run at once, each app assigned
  to one of them (the official WireGuard app keeps several but runs one; RethinkDNS runs several per app). The
  destinations of apps sent through WireGuard are logged only under the switch that governs chained apps' ("Log where
  these apps connect"), off by default, since a log of them is evidence in a phone search. **Routing by
  destination** (a domain or a network directly, the rest through a tunnel, as sing-box's and Clash's rules do) is
  left out of W7 for a unit of its own after W8, with its own ADR: it is a rule engine with privacy questions of
  its own (IP-to-country data, its interplay with W8's resolver), and the users who most need it reach it today
  through their own tool's rules over W6's chain.

**Frontier research is not needed:** every part is established; the spike and the interoperation tests answer
what is open.

## How it is built (W7, part 1, 2026-11-19)

Part 1 builds the engine's side and the JNI bridge, with a debug-build way in; part 2 brings the import, the
key's storage and the screens; part 3 the CI peer, the A40's measurements and the check from outside with a
provider. What was chosen where the decision left room, and why:

- **Where.** `core/net/src/wireguard/`: `config.rs` (the parser), `core.rs` (the trait `Core` and GotaTun behind
  it, the only file that names GotaTun), `swap.rs` (the swaps, the back path's reader, the MSS clamp);
  `core/net/src/engine/tunnels.rs` (the table of tunnels, the routes' tunnel side, forwarding both ways, each
  tunnel's task). GotaTun is `=0.10.3` with `default-features = false, features = ["aws-lc-rs"]`; its 89 crates
  in the lock are those the spike measured, version for version. `core/deny.toml` gained BSD-3-Clause,
  BSD-2-Clause, ISC and MPL-2.0; `NOTICE` lists GotaTun, where its source is, and the new licences. `cargo deny`
  passes. The licence texts of every crate inside the native libraries are in `licences/` (`native-core.txt`,
  `native-watch.txt`, written by `scripts/licences.py` from each package's own texts, which `scripts/check.sh
  rust` holds current and which fails on a crate with none); GotaTun's package carries none, so
  `licences/MPL-2.0.txt` (Debian's copy of the licence) and `licences/gotatun-BSD-3-Clause.txt` (the SPDX text
  with the Cloudflare notice its source files carry) stand for them. Every APK carries `NOTICE`, `LICENSE` and
  its libraries' texts under `assets/licences/`, which `scripts/check.sh android` checks in both release APKs. Since `aws-lc-sys` compiles C for the target, `scripts/check.sh rust` runs the Android clippy
  through cargo-ndk.
- **Size.** Watch's stripped library in Advanced's release APK: 1,644,296 bytes on arm64, 1,417,888 on armv7,
  1,909,432 on x86_64, within the 2 MB gate (2,097,152), which `scripts/check.sh android` holds. Against the
  spike's measure of the engine without WireGuard (1,384,656, 1,220,364, 1,590,136 at `f1127f3`): +259,640,
  +197,524 and +319,296 bytes, GotaTun's 170 KB and W7's own code and tables. After the fix round: 1,678,872, 1,442,344 and
  1,949,640 bytes (+34,576, +24,456, +40,208: the resolver's callback, the fragments put together, the
  application lists).
- **The configuration.** One `[Interface]` and one `[Peer]`, keys and sections in any case, `#` comments, a
  UTF-8 BOM, CRLF. Refused with a reason the screens can show (`Refusal`: a code, a line, a key, never a value):
  several peers or interfaces, an unknown section, `PostUp` and every other key it does not carry (among them
  `Table` and `SaveConfig`), a key twice, a value it cannot read, two addresses of one version, a search domain in
  `DNS`, no `DNS` (W7, question 9), both of WireGuard's app's application lists at once, and, new
  here, **no DNS server the tunnel reaches**: one of a version the configuration has an address of and inside
  the peer's `AllowedIPs`, since its answers must pass the back path's filter. `MTU` 576 to 1,500, at least
  1,280 with an IPv6 address; none gives 1,280. Keys are canonical base64 of 32 bytes, the all-zero key
  refused; they are `Secret`s, zeroed on drop (`zeroize`), never in `Debug`, a refusal, the dump or a log
  line; compared in constant time, and GotaTun's copies of them zeroed too. `ListenPort` and `FwMark` are read
  and ignored, and WireGuard's app's `IncludedApplications` or `ExcludedApplications` kept, at most 512 package
  names, for part 2's import to offer (the maintainer's answer 2, below). An endpoint must be a unicast address,
  not an IPv6 link-local one; the loopback is allowed, since local relays (wstunnel, udp2raw) listen there. At most
  16 KiB of text, 256 networks in `AllowedIPs`, 8 DNS servers. Fuzzed (`core/fuzz`, target `wireguard`, 7 seeds:
  12.4 million runs without a fault after the one fault it found, a shift past a whole prefix, fixed; it checks
  that neither key shows in `Debug` as bytes or base64 and that no refusal's text holds a run a key could be);
  the back path's reader and the MSS clamp too (target `wireguard_back`, 9 seeds: what is read lies inside the
  packet, swaps read back, a clamped MSS is within its bound with its checksum still right).
- **Routes.** `Route` gains `Tunnel(n)`, decided where W6 decides it, after Android named the app: the held SYN
  (`tcp::upstream`, which now waits for the owner whenever any app goes through a tunnel) and the first
  datagram (`udp::open_mapped`, `udp::open_lookups`). An app with a tunnel goes through it whatever the chain
  says, since each app has one route; a flow of no app, and every echo, take the default tunnel, the first
  configuration set, while any app goes through any; a stand-in address is refused. A route to a tunnel whose
  configuration is not set, or was removed, stays: its apps' flows are refused, never sent directly, and the
  state shows the tunnel as routed and not configured, until the configuration comes or Watch routes them
  elsewhere (the reviews' first finding). While any app goes
  through a tunnel, a SYN that finds no listener of the system stack is routed first, since tunnelled
  connections need none.
- **Forwarding and the way back.** Ports are kept. A packet from the tunnel passes only if its source is in
  the peer's `AllowedIPs`, its destination is the configuration's own address, and it belongs to a flow a
  local app started, by protocol, the far end's address and port, and the app's port: the same filter for
  TCP and UDP, endpoint-dependent, narrower than the direct path's address-dependent filtering of ADR 0044,
  since the provider's NAT already decides what comes in and Watch adds no inbound path. Errors are matched
  by the packet they quote, their quote swapped as RFC 5508 asks (the quoted transport checksum updated where
  the quote holds it, the error's own made anew). A destination the tunnel cannot carry (outside
  `AllowedIPs`, or IPv6 without an IPv6 address) gets "administratively prohibited", which Linux's TCP takes as
  a hard error at once (EHOSTUNREACH, EACCES in IPv6), so Happy Eyeballs falls back to IPv4 without waiting.
- **DNS.** A tunnelled app's lookups to Watch's DNS address go to the configuration's DNS server: over UDP
  rebuilt datagram by datagram, so that a query to Watch's IPv6 address reaches an IPv4 server; over TCP by a
  second swap, of the same version only. Answers are learned for every app's flows, as Android's resolver's
  are, kept in a cache of the tunnel's own, and reach the app with a time to live of 0; while any app goes
  through a tunnel every answer of Watch's DNS address does (question 4). An answer over TCP is learned when
  one segment holds it whole, and is not rebuilt, as on the direct and chained paths. Fragments from the tunnel
  are put together (16 datagrams, 256 KiB, 5 s per tunnel) before the filter reads them.
- **MTU: the second way.** The tunnel keeps the TUN's MTU, the first hop's, which direct apps keep using whole;
  a tunnelled SYN's MSS and the server's SYN-ACK's are clamped to the configuration's MTU, and a packet larger
  than it that may not be fragmented gets "fragmentation needed" or "packet too big" from its destination, as
  a router answers; one the engine put together from the app's own fragments passes whole. Why: several
  tunnels with different MTUs cannot share one TUN MTU without the smallest bounding every app, direct ones
  included; each configuration added or removed would set the tunnel up again; and the clamp and the error
  are what routers do. Shown in the lab, through the engine against the kernel's WireGuard
  (`the_mtu_holds_on_the_path_to_the_kernel_peer`): with a configuration's MTU of 1,280, an app's SYN with an MSS of
  1,460 reaches the peer's kernel as 1,240 in IPv4 and 1,220 in IPv6 (what the peer's socket reads as
  `TCP_MAXSEG`), the SYN-ACK reaches the app clamped alike, a datagram of 1,280 bytes that may not be fragmented
  passes whole to the peer and back, and one of 1,281 gets the app "fragmentation needed" or "packet too big"
  with 1,280 from its destination. Not shown: an Android app's own socket learning the path MTU from that error,
  nor the CPU a TUN at 1,280 would have cost direct apps on the A40, which the first way rested on. QUIC, most of
  the web's UDP, finds its path's MTU itself (RFC 9000, 14.3, and DPLPMTUD, RFC 8899), sending probes it lets
  be lost, so it needs no error from Watch (the maintainer's answer 1).
- **The core's demands** (the spike's list), each with a test: every datagram through the rate limiter first
  (in `GotaTun::receive`), `AllowedIPs` after decryption, an `MtuWatcher` of the configuration's MTU for
  padding, the queue drained after a handshake, and the timers. Each tunnel's task ticks once a second only
  while a session or a handshake lives or `PersistentKeepalive` is set, and runs the timers before a packet
  either way after a pause of a second or more; an idle tunnel waits on its socket alone. A tunnel with
  keepalives starts at once when an app is routed to it, as the reference implementations start such a peer.
- **A tunnel that does not answer.** No path leads from a tunnelled flow to a direct socket. Packets wait in
  the core's queue of 256 or are lost, counted; the state says "does not answer" once a second initiation goes
  out with the first unanswered, about five seconds after the first (`REKEY_TIMEOUT`; a routine rekey's one
  initiation does not), and gives the handshake's age, the last packet received, and the last error (of the
  socket, the endpoint's name, or the core, as a word). The timers' pause is measured on `CLOCK_BOOTTIME`, so a
  phone that slept runs them before its next packet.
- **Roaming and the endpoint.** Each tunnel has its own protected, connected UDP socket. On a network change it
  is made anew and the server is told at once: a keepalive while the session is younger than two minutes, else
  a handshake; the server's address stays the configured one. A host name is resolved before the tunnel by
  Android's own resolver on the network beneath (`Network.getAllByName`, from Kotlin on a thread of its own, at
  most 10 s), which uses the user's Private DNS where it is on: encrypted where Android says Private DNS is
  active on that network (strict, or "automatic" with a server that offers DNS over TLS), plain otherwise, and
  the state says which (the maintainer's answer 4, below). Only where Android has no network to ask does the
  engine ask the network's resolver itself, in plain DNS through a protected socket, and says so. An IPv4 address
  first, never a loopback or multicast one. It is resolved again after four unanswered initiations, at most once
  a minute; a name that does not resolve, or a socket that cannot be made, is tried again after a pause that
  doubles from 5 s to a minute, its apps' packets waiting meanwhile, never asking again per packet (the engine
  reviewer's second finding); the state counts the resolutions.
- **Local network directly**, per configuration, off by default: a tunnelled app's RFC 1918, link-local,
  unique-local and multicast destinations go directly, but not the configuration's own networks, its DNS
  servers (Proton's 10.2.0.1 beside 10.2.0.2/32), Watch's addresses, or a private range the configuration's
  `AllowedIPs` names as narrowly as the local range or more (a company's 10.0.0.0/8 through its tunnel; an
  `AllowedIPs` of everything does not count). Its destinations stay out of the log as the app's others do,
  while "Log where these apps connect" is off, as the live view hides that app's places.
- **The log and Now.** `Flow` gains its route (`Via`): the log's record goes to version 4, a segment's route
  after its state; the snapshot to version 3, each destination's route and each app's tunnel. A tunnelled
  flow's destination is kept only under "Log where these apps connect", as a chained one's; the tunnel's own
  server is reached by Watch's protected socket and is no app's flow. The Kotlin readers and fixtures follow;
  a segment of a version before 4 reads as of no known route. "Now"'s screen does not read the route yet: part
  2 gives it its line. Nine counters are appended (52 to 60). The tunnels' table is taken only after the log's
  live flows or alone, and the log is told nothing under it (the engine reviewer's third finding: the two were
  taken in opposite orders, and the engine could freeze); a new SYN on the ends of a closed connection ends the
  old flow's record.
- **The bridge.** `nativeTunnelSet(id, text, localNetwork)` (the text zeroed once parsed; a refusal returned as
  text), `nativeTunnelParse(text)` (the refusal, or the configuration's application lists, for part 2's import),
  `nativeTunnelRemove` (the configuration only: its routes stay, and its apps wait), `nativeTunnelRoutes(uids,
  tunnels, logDestinations)`, `nativeTunnelStates` (with whether each tunnel is configured, and how many times
  its name was resolved); kept beside the chain for the engines to come, forgotten when the tunnel stops. The
  engine calls `WatchVpnService.resolveEndpoint(name)` back, kept from R8 and checked in the APK like the other
  callbacks. Debug builds' dump: `tunnel-add ID FILE [local]` from Watch's files directory (with a `tunnel-apps`
  line for each app the file names), `tunnel-route UID ID`, `tunnel-remove ID`, a `tunnel` line per state, with
  no key, address or endpoint, and a `flow-route UID ROUTE COUNT` line for each app and way its kept flows went;
  a release build's dump answers none of them, which `scripts/verify-watch-release.sh` checks.
- **Bounds.** 8,192 tunnelled TCP and UDP flows in all, and as many echo identifiers; 8 datagrams waiting for a
  tunnel's socket; the core's queue of 256 per tunnel; a closed TCP flow kept `close_linger` (30 s), a silent
  one 2 h 4 min (RFC 5382); a UDP flow `udp_idle` (120 s); an echo 30 s; the per-tunnel DNS cache as Watch's
  others (`dnscache::CAPACITY`); a resolution 3 s per kind.
- **Measured.** Tests: the parser (every refusal), the swaps and checksums against etherparse's recomputation,
  the quote of an error, the MSS clamp, the back path's filter, routes and the default tunnel, the timers'
  rule, the DNS redirect, in units and in `core/net/tests/wireguard.rs` through the whole engine against
  GotaTun's own core as the server. Interoperation through the engine, `scripts/check.sh wglab`
  (`scripts/wglab.sh`, a new mode beside `lab`, which is the gaps probe's), against two peers of the kernel's
  WireGuard: TCP, UDP, ICMP (the reply from the peer itself) and DNS on IPv4 and IPv6, answers from outside
  `AllowedIPs` dropped, a `PresharedKey` that the peer holds too, two tunnels at once to two peers, the MTU's
  clamp and errors, each peer seeing the handshake (19 checks since the fix round,
  [results](../../spikes/wireguard-core/results-2026-11-20-lab-engine-fix.txt); 13 before,
  [results](../../spikes/wireguard-core/results-2026-11-19-lab-engine.txt)). On the emulator,
  `scripts/verify-wireguard.sh` in the watch shard, on CI's image (Android 15): the workload app's lookup, TCP
  and UDP through the first peer from 10.77.0.2, the apps its configuration names read on Watch's side, another
  app directly beside it, IPv6 TCP and UDP inside the tunnel from fd77::2, a second configuration to the second
  peer at once with the first app's echoes counted at the first peer, a network switch while only the peer has
  more to send, the peers not answering while the routed apps send TCP, UDP and lookups of new names for 15 s
  past the tunnel saying so (nothing at a sentinel, no direct flow of theirs in Watch's list) and then answering
  again, a removed configuration holding its apps, and no key or endpoint in the dump or the device's log. Run
  with the socket's remaking reverted, and again with only the keepalive after it reverted, the switch step
  fails: the peer's answers after the switch never arrive; run with an app sent directly while its tunnel does
  not answer, the stopped-peers step fails at the sentinel. The watch shard's first run found that a route
  changed from Watch's thread ended the app's open flows there, reading the log's clock off the engine's thread,
  which a debug build refuses with a panic; they are now ended on the engine's thread, and a test holds it. Per
  packet, the engine's CPU for a UDP datagram from an app (`per_packet_cost`, release build, each far end
  counting what it read: all 200,000 of each run): through a tunnel 4.4 µs at 1,280 bytes and 4.1 µs at 100 on
  the development machine, directly 4.45 and 4.35 µs. Encryption is a small part of either; the system calls
  are most of it. The figures given before the fix round (directly 7.0 and 6.9 µs here, 5.3 and 5.1 on the
  emulator, a tunnel cheaper than the direct path) measured the direct path against a reader that had stopped,
  so the engine handled a "port unreachable" for each packet; they are withdrawn, and the emulator's and the
  A40's come in part 3.
- **Accepted limits.** A new engine (a tunnel set up with other addresses) begins new sessions: the cores are
  not handed over, only the setting. The quote of an error is read without IPv6 extension headers, which Watch's
  own packets into the tunnel never carry. An echo request the engine put together from the app's fragments,
  larger than the tunnel's MTU, gets "fragmentation needed" where TCP and UDP put together pass whole, so a
  `ping -s 2000` through a tunnel fails where a router would fragment it. A UDP datagram put together from the
  app's fragments that opens a tunnelled flow waits on the direct path's side while Android names its app, and
  loses the mark of having been put together there: in IPv6, one larger than the configuration's MTU then gets
  "packet too big" once, where the next, on the open flow, passes whole (found in the fix round; the direct
  path's waiting datagrams would need to carry the mark). Under Private DNS's "automatic" mode
  Android may ask in plain DNS when the server's DNS over TLS fails, after saying it is active, so an endpoint's
  name the state calls encrypted may have gone out plain then; strict mode never does. A thread asking
  Android's resolver past its 10 s ends when Android answers, its answer unread. A cookie reply under load, an
  IPv6 outer address and wireguard-go as the peer are not in the lab (the spike's list).

**The maintainer's answers (2026-11-19, after the reviews of part 1), and how they are built:**

1. **The MTU's second way stands**, as above; QUIC finds its path's MTU itself, and the ADR says so.
2. **`ListenPort` and `FwMark` are read and ignored**, so that a file exported from WireGuard's app imports;
   `IncludedApplications` and `ExcludedApplications` are kept by the parser (not both at once) and handed over by
   the bridge (`nativeTunnelParse`) for part 2's import to fill the choice of apps with and show for the user to
   confirm; the engine routes by Watch's own choice alone.
3. **An app's tunnel wins over the chain's "every app but the tool"**: the app's own route is the more specific
   choice. The alternative, the chain winning, would send through the tool an app the user put in a tunnel by
   name. Its cost: an app in a tunnel leaves the tool's cover, which part 2's screens show beside the chain's.
4. **An endpoint's name is resolved over encrypted DNS where Android has it**: by Android's own resolver on the
   network beneath, which uses the user's Private DNS, not by Watch's own DNS over TLS to the Private DNS server.
   Why: it encrypts exactly where the user's setting does, with Android's own validation of the server and its
   fallback rules; it needs no TLS client in the engine before W8; and it asks on the network beneath, never
   through a tunnel that is not up. Plain DNS only where Android has none (no network beneath to ask), through
   a protected socket, and the state says so. **W8 takes endpoint resolution over** with the user's own
   encrypted resolver.
5. **A tunnelled UDP flow asks Android again after a pause** (`udp_reask`, 1 s), as the direct path does: the
   datagrams that come meanwhile wait (at most `udp_waiting`, 32), and a flow Android now names for another app
   or route ends, its datagram going the new app's way.

## Fix round of part 1 (2026-11-19)

Two independent reviews of part 1 (the engine; the bridge, the checks and the documents) found eight majors
between them; each is fixed with a test or check that fails when the fix is reverted:

- **A route to a tunnel that is not set** sent the app directly; now it is kept and refused (above, "Routes").
  `an_app_routed_to_a_tunnel_not_set_waits_and_never_goes_directly`, the units' route tests, and on the emulator
  the last step of `scripts/verify-wireguard.sh`.
- **An endpoint name that does not resolve** was asked again per packet; now with a doubling pause
  (`a_name_that_does_not_resolve_is_not_asked_again_per_packet`).
- **The tunnels' table and the log's live flows** were taken in opposite orders; now the log is told after the
  table's lock (`forwarding_tells_the_log_nothing_under_the_tables_lock`, which froze on the old order).
- **The "peers stopped" step** sent nothing after the tunnel said it does not answer; now the routed apps send
  TCP, UDP and lookups of new names for 15 s past it, a sentinel and Watch's own flow list must show nothing
  direct, and the peers come back for the app's traffic to pass again. Run with an app sent directly while its
  tunnel does not answer, it fails.
- **The network-switch step** passed without a switch, and with roaming reverted; now the default network moves
  off Wi-Fi (or off mobile data where that was the default) while only the peer has more to send, after a
  silence in which nothing of the client's is owed, so that the peer's last answers reach the app only where
  Watch remade its socket and sent from it at once. Run with each half of `roamed` reverted, it fails.
- **Licences:** the texts are now in the repository and in every APK, held by the gates (above, "Where").
- **The MTU's evidence** is now the lab's, through the engine (above).

Minors fixed with tests: fragments from the tunnel put together; "Local network directly" leaving a private
`AllowedIPs` to the tunnel; a new SYN on a closed connection's ends ending the old record; the timers' pause on
`CLOCK_BOOTTIME`; `resolve` reading AAAA after an unreadable A answer; tests for the hand mutants that
survived (R1, a mapping of an app newly routed; the answers at a time to live of 0, cached and direct; the
endpoint's name; the second flow on the same way back refused; an error's quote; a datagram put together passing
whole, now in IPv6 too, where M5 had survived the IPv4 case, and kept so while it waits for Android to be asked
again; a ping to a stand-in; the roam's handshake on an old session). Fixed without a test of their own: the
keys' constant-time comparison and zeroed copies, and an idle tunnel's task ended when its configuration goes.
Of 40 hand mutants (the engine reviewer's 30 and ten of the fix round's rules), the crate's tests kill all but
six: M24 (the handover's tunnels, which `watch-jni`'s test kills), M32 and M34 (the engine's own plain query
and the name asked again after a minute of failed handshakes, which would need port 53 or minutes), M35 and M36
(a SYN on a closed connection's ends, through the whole engine; the record's end is tested in the table), and
the removed tunnel's idle task. The fuzz targets assert what they say (8.9 and 24.5 million runs from their
seeds, 90 s each, without a fault). The emulator check skips only without Docker, an answering Docker or the
wireguard module, and fails otherwise; reads every dump whole; counts the peer's echoes for the two tunnels; adds IPv6 UDP; waits for the networks to
settle after the switch; checks that no key or endpoint shows in the dump or the device's log; and removes the
key's file whatever happens. The release build's dump is checked to answer no debug command. The lab checks the
ping's source and the peer's preshared key. `per_packet_cost` measured the direct path against a reader that had
stopped, so the engine handled "port unreachable" for every packet: its readers now read throughout, it counts
what arrived and asserts that nothing was dropped.

**Left for later, written down:** the back path's filter (`tunnels::back`) has no fuzz target of its own (it
needs a table with flows, inside the crate); an AAAA lookup and a configuration without IPv6 on the emulator (its
ICMPv6 "administratively prohibited") are units and lab checks only; Android's Private DNS in strict mode makes
its DNS over TLS connections itself, and whether Android names Watch's tunnelled apps or the resolver as their
owner, which decides whether their names reach the provider through the tunnel, is for part 3's check on the A40.

**Release gate.** No release ships W7 before part 2 shows the licences on a screen of Advanced (the APK carries
them already, and `NOTICE` says where GotaTun's source is, as MPL-2.0 section 3.2 asks), and before
`licences/gotatun-BSD-3-Clause.txt` is compared with `LICENSE-CLOUDFLARE` at GotaTun's tag 0.10.3, which could
not be downloaded here. *Closed in part 2 (2026-11-20), both halves: below, "The licence screen" and "Cloudflare's
text".*

## How it is built (W7, part 2, 2026-11-20)

Part 2 gives the user the way in: the import from a file and a QR code, the configurations kept wrapped, each
app's route, the states, and the licence screen. What was chosen where the decisions left room, and why:

- **Where.** `android/watch/.../tunnel/`: `TunnelStore.kt` and `Wrap.kt` (the store and its key), `Import.kt` (the
  confirmation's model), `Routes.kt` (each app's route), `TunnelStates.kt`, `Refusals.kt`; `tunnel/qr/` (the
  decoder, its isolated service, Watch's client and the camera's file); `ui/Tunnels.kt` (the sections and the
  confirmation). In Rust, `Config::describe` and `carries_everything` (`config.rs`), `MAX_TUNNELS`
  (`engine/tunnels.rs`) and `nativeTunnelOrder` (`watch-jni`).
- **The store.** Each configuration in a slot of its own, numbered from 1, a number never given again while an app
  is routed to it. Its text and its name are wrapped apart, so that showing a name never opens a key: AES-256-GCM
  under a non-exportable `AndroidKeyStore` key (`KeystoreWrap`), generated in StrongBox where the phone takes it,
  else wherever its Keystore keeps keys (the screen says which: StrongBox, the secure area, or software, as on the
  emulator); the Keystore draws each wrap's 96-bit IV itself (randomised encryption, so no IV can be reused by
  Watch's mistake); a label, the record's version, the slot's number and the part are the associated data, so that
  a wrap moved to another slot or part does not open. The files are in `noBackupFilesDir/tunnels`, which Android
  leaves out of cloud backup, and which the application's `data_extraction_rules.xml` and `backup_rules.xml`, the
  same for both editions, exclude with every other domain from cloud backup and device-to-device transfer. Beside
  the wraps, in plain text, what Watch must read without a key: the slots in order, the default first, "Local
  network directly", the next number, and each app's slot by package name. Why plain: a configuration whose wrap
  cannot be opened must still hold its apps, so the routes cannot sit behind the key; the chain's apps are kept so
  already (ADR 0047's table). Each write replaces a file whole. The text never becomes a `String` in Watch's
  process: bytes from the file or the decoder to the confirmation, to the store and to `nativeTunnelSet`, each array
  zeroed after use; the JNI's copy is zeroed by Rust (`zeroize`). A wrap that cannot be opened reads as lost (the
  key gone, the wrap damaged) or locked (a key that needs an unlocked phone, on a locked one): the screen says so,
  and its apps stay routed to it and wait.
- **`setUnlockedDeviceRequired`: measured, and not set.** The measure (`scripts/verify-wireguard-import.sh`,
  step 7, Android 15 emulator): a key made as Watch's but with the flag (`tunnel-key-probe`) opened at once while the phone
  was unlocked; with a PIN set and the screen off, it did not open (the Keystore threw `InvalidKeyException`, read as
  locked by the keyguard's state), and it opened again after the PIN; Watch's own key opened a configuration in under
  a millisecond, locked and unlocked. The emulator's Keystore is software; the A40's, a trusted environment, is part
  3's to time. What the flag would protect: the configurations of a phone searched
  after its first unlock, locked, with Watch not running, against someone who can run code as Watch on it (ADR
  0047's extraction); from Android 12 the Keystore enforces it by a key it drops at each lock. What it would not:
  a phone searched unlocked, ADR 0047's commonest case, where the searcher demands the code; nor a phone where
  Watch runs, which is how Watch is meant to run (always on), since the engine then holds the keys in memory, as
  every WireGuard client does. What it would cost: Watch started again while the phone is locked, after an update
  installed at night, a crash, or Android ending its process, could not open its configurations, and its tunnelled
  apps would wait, sending nothing, until the next unlock (Watch would set them then; the code for it is in place,
  `waitForUnlock`). The field keeps WireGuard keys in plain files (WireGuard's app, Mullvad's); Watch's wrap under
  a hardware key is already beyond it. The narrow case against a cost that every user meets after every update at
  night decides it: not set, for the maintainer to confirm. The alternative kept open: set it under ADR 0047's
  profile for phones that may be searched, where the user has said a locked phone's search matters more; the key
  would then be made anew and every configuration wrapped again at the profile's switch.
- **From a file.** `ACTION_OPEN_DOCUMENT` for any type (providers name `.conf` files variously), so no storage
  permission; at most 16 KiB read (the parser's own bound), a longer file refused as too long; the name from the
  document's display name, `.conf` dropped. The parser is the engine's (Rust, fuzzed), in Watch's process: it is
  memory-safe and holds no state, where the picture's decoders are not.
- **From a QR code.** The phone's own camera through `ACTION_IMAGE_CAPTURE` with `EXTRA_OUTPUT` to one file in
  Watch's cache, through its FileProvider, granted for writing alone through the intent's ClipData and revoked once
  the camera answers; on Android 10 the intent names the preinstalled camera, found among the apps that answer it
  by their system flag (from Android 11 Android itself sends it to a preinstalled camera alone). Watch never holds
  `CAMERA`: Advanced's build refuses it by name, and Basic's by its allowlist. The photo is deleted once read, when
  the read fails or throws, when the camera is cancelled or answers nothing (`Capture.finish`, tested on every
  path), and a photo left by a crash at Watch's next start, of the screen or the service. Or a picture picked in the
  photo picker (`PickVisualMedia`, which falls back to the documents screen where there is no picker), with the line
  that the picture holds the configuration's private key and the user may want to delete it. The decoder is ZXing's
  core 3.5.4 (Apache-2.0, no dependencies, from Maven Central, in the verification metadata), in `QrService`, an
  isolated process of its own (`:qr`) with no permissions, no network and none of Watch's files, which the build
  holds isolated and unexported as it holds the audit's parsers. It takes the picture as a read-only descriptor, reads
  it with Android's `ImageDecoder` in one pass (a file or a pipe), refuses one larger than 16,384 pixels a side from
  its header, brings any other down by a power of two to at most 2,048 a side as it decodes, tries a dark code on
  light, then light on dark (a screen in dark mode), then the other binarizer, and returns at most 2,953 bytes, a QR
  code's largest in byte mode, which a configuration with small letters always takes; the whole read has 10 s, after
  which the answer is "too slow" and the process ends. Android ends an isolated process once Watch unbinds it
  ("isolated not needed", seen on the emulator), and the service ends its own as well; ZXing holds the text as a
  `String` there alone.
- **The confirmation**, before anything is saved, shows what the configuration does and never a key, from
  `nativeTunnelParse`, which now answers `Config::describe`: the server and its port (and, for a name, that the
  network may see it unless Private DNS is on), the addresses (and, without IPv6, that IPv6 is refused and the apps
  use IPv4), the DNS servers, whether `AllowedIPs` carry everything or only the networks named, the others refused,
  never sent directly (`carries_everything` adds the networks up, so `0.0.0.0/1, 128.0.0.0/1` is everything), the
  preshared key, the keepalive and the MTU. The name is editable: the file's, else "WireGuard N", the first number
  free. `IncludedApplications` and `ExcludedApplications` become a proposed choice of apps, ticked for the user to
  confirm or change, never applied silently: those installed of the first; every app the user can choose but those
  of the second; never Watch itself or an app left out of Watch; the apps named and not installed are listed. A
  configuration on its way is held by Watch's process alone, never in a saved state, which Android copies out of the
  process, and zeroed when saved or cancelled. Each refusal is said in plain words with its line and key
  (`Refusals`); a test reads the codes from `Refusal::code` and the bridge, and fails for a code without words or
  with another code's.
- **Several configurations.** Add, replace (its apps and switches kept), rename (the name's wrap alone), remove,
  "Local network directly" (off by default) and the default, which is the first in order: the engine takes the order
  from `nativeTunnelOrder`, each tunnel keeping its core and session. Removal asks what its apps do, wait or go their
  other way, with neither chosen beforehand, so that nothing goes directly unasked. **At most eight**
  (`MAX_TUNNELS`, held in the engine, the bridge's `too-many` and the store, and a test holds the two numbers
  equal): each tunnel holds a core with its queue of 256 packets, a socket, 256 KiB of fragments and a read buffer,
  about 700 KiB at worst, so eight stay within a tenth of Watch's 48 MB budget; a user needs a few.
- **Each app's route** is chosen in one place, "Each app's way": directly, through the tool, or through one
  configuration; an app routed to a removed configuration waits, and an app left out of Watch goes through none.
  An app with a tunnel is shown so in the chain's choice, where it cannot be ticked, and the chain for every app
  says how many go through a configuration instead (the maintainer's answer 3). Choosing a route takes the app out
  of its other way. "Directly" is not offered while the chain takes every app, which only leaving the app out of
  Watch overrides. The service hands the configurations and the routes to the engine at every start, after the chain
  and before the tunnel is established, and at once when the screen changes them (`ACTION_APPLY_TUNNELS`); each
  configuration's text is opened only to be set and zeroed, and one already set is not opened again. Routes go by
  UID; packages that share one share a route, the first by name deciding. The debug hook stays for part 1's check;
  its routes and the store's replace each other, as both call `nativeTunnelRoutes`.
- **Each configuration's state**, from `nativeTunnelStates` once a second while Watch's screen is in front, not at
  all otherwise: the last handshake's age, not connected yet, no answer (its apps wait, nothing goes directly), the
  endpoint's name resolved over plain DNS only, not ready in Watch (its apps wait), and a wrap that cannot be opened.
- **"Now" and the history** name the configuration an app and each destination went through, and say "a WireGuard
  configuration since removed" for a number the store no longer holds; the names are read from the store off the
  main thread, once each.
- **The licence screen** lists, in each edition, every part its APK carries: the native crates, read at run time
  from the `- NAME VERSION: LICENCE` lines of `assets/licences/native-*.txt`, the files `scripts/licences.py` writes
  from `core/Cargo.lock` and `scripts/check.sh` holds current, so a crate added later is on the screen without
  anyone editing a list; and the Java and Kotlin libraries from `licences/jvm-components.tsv`, which the build holds
  to each variant's runtime classpath (`checkJvmComponents`, failing for a module no row covers and for a row that
  covers none; made to fail once each way). Each opens its full text (NOTICE, with where GotaTun's source is;
  LICENSE; the native texts; in Advanced MPL-2.0 and GotaTun's BSD text). Basic's list follows the same mechanism.
- **Cloudflare's text.** `licences/gotatun-BSD-3-Clause.txt` now holds `LICENSE-CLOUDFLARE` byte for byte, as
  GotaTun's repository holds it at tag v0.10.3 (commit `c541472b40ec489ba7bdfd048512e89e556c7a3c`, SHA-256
  `6dbef24708bad8c727bd80cca58ba8aa1637cdcb2cc6e9a31ea49235717e9391`), compared on 2026-11-20 with the SPDX text the
  file held: the same 224 words in the same order, only the line breaks differed. A unit test pins its hash.
- **Screens.** In Watch's activity, whose window is protected (ADR 0040); the confirmation is part of it, and the
  removal's dialog inherits the protection. Headings are marked for TalkBack and changing lines are live regions;
  rows are the controls, buttons stand in a column that wraps at a large font, and nothing has a fixed height;
  names, hosts, addresses and package names are isolated (checked on the emulator in the mirrored pseudo-locale, ar-XB, at a font size of 200 %: the
  card, its switch and its text laid out right to left, a configuration's name kept in its own order). The strings are in English only, in
  `strings_untranslated.xml` of `:watch` and of `:app`, held to the plain-language gate.
- **Measured.** Tests: 36 new JVM tests in `:watch` (the store 11, the confirmation 8, the decoder and the photo 7, the
  routes 4, the refusals 3, the states 2, the history 1), 8 in `:app` for the licence list, and 4 in Rust (the
  description, "everything", the bound and the order); `:watch` has 145 in all. Hand mutants: 53 by hand in cargo-mutants' manner on the new rules (the store 14, the routes' model 9, the photo's
  deletion 4, the decoder's bounds 5, the refusals' mapping and the confirmation 10, the Rust description, bound and
  order 11), all viable: 50 killed, 3 equivalent (removing a slot's "Local network directly" at removal, the names'
  cache, and the default's guard against a slot not kept, each undone by the state's reading, which keeps only slots
  whose text exists); the first run's 7 survivors got the tests that kill them, among them the bridge's bound tested
  past eight and a tall picture. The parser's fuzz target, after `describe`: 8.4 million
  runs in 120 s without a fault, checking that the description holds no key and that "everything" allows sample
  addresses. Sizes: each edition's release APK, unsigned and without the organisation table (not committed), from
  `208aacd` to part 2: Basic 4,973,754 to 4,993,070 bytes (+19,316, the licence screen), Advanced 11,164,928 to
  11,364,724 (+199,796: its code 2,611,788 to 2,779,536, ZXing's reader, the store, the screens and the licence
  screen, and the table of libraries); Watch's native library 1,686,432, 1,450,296 and 1,958,224 bytes on arm64,
  armv7 and x86_64 (+7,560, +7,952, +8,584 for the description and the order), within the 2 MB gate. Pictures through
  the decoder's isolated process on the emulator (`qr-decode`): a code read in 251 ms; random bytes, a cut PNG, a
  damaged one, a bare JPEG header and an empty file refused as no picture in about 100 ms; a PNG whose header claims
  100,000 pixels a side, and one 20,000 wide, refused from their headers; a white picture of 6,000 by 6,000 brought
  down and read as no code in 294 ms; no crash. On the emulator, `scripts/verify-wireguard-import.sh` in the watch shard: on the Android 15 image (dp-api35-ci), every step passed on an emulator with
  the virtual scene's camera (its photo read and refused, deleted, MediaStore unchanged) and on one without a camera,
  as the shards and CI run (the cancel path). The watch shard (`scripts/emulator-shards.sh --alone watch`) passed
  smoke, verify-watch, verify-chain and part 1's verify-wireguard with part 2's service and screens; its first run
  of the import check found that a camera app that stops, with no camera, hands Watch its answer only when Watch's
  screen is in front again, so the photo's empty file waited for that; the check now brings the screen back first,
  and a photo left by a process that died is deleted at the next start. The import check's first runs also met the
  photo picker giving a picture read before from the same path; each run's picture has a name and an MTU of its own.
  Run before the activity check, it left the workload app routed to the configuration it removed with its apps
  waiting, and the activity check's copy of that app then waited, as such a route is meant to hold it; the check now
  clears Watch's data when it ends.
- **Accepted limits.** The Keystore's cipher, the binder's parcel that carries the decoded text from the isolated
  process, and Compose's text field for the name keep copies Watch cannot zero; the text is never a `String` in
  Watch's process, but it is one inside the decoder's, which ends after each picture. A picture picked in the photo
  picker stays in the user's gallery; Watch says so but cannot delete it. On the emulator the camera's scene holds
  no QR code, so the camera's photo is read and refused there, not decoded; a decoded photo of the phone's own camera
  is part 3's, on the A40. Routes go by UID, so packages that share a UID share a route. The confirmation's server line, the dump's `tunnel-store` and the states never print a key; the
  endpoint is shown on the confirmation alone. A file or picture larger than its bound is refused, never cut.

## Sources

Read on 2026-11-09 unless marked otherwise.

- Repository: [VPN.md](../VPN.md), [DESIGN.md §13.2](../DESIGN.md#132-v020-watch-the-connection-log-next-to-circumvention-tools),
  [ADR 0006](0006-rust-engine-unsafe-forbidden.md), [ADR 0008](0008-gradle-dependency-verification.md),
  [ADR 0012](0012-packet-engine.md), [packet-engine spike](../spikes/2026-11-packet-engine.md),
  `core/deny.toml`, `core/Cargo.toml`, `core/engine/Cargo.toml`,
  `spikes/packet-engine/rust/engine/src/system.rs`.
- BoringTun: https://github.com/cloudflare/boringtun (README, CHANGELOG, `boringtun/Cargo.toml`,
  `src/noise`, `src/device/mod.rs`, commit log), read 2026-11-09;
  https://crates.io/crates/boringtun, read 2026-11-09.
- GotaTun: https://github.com/mullvad/gotatun (README, CHANGELOG, `Cargo.toml` files, `src/noise`,
  `src/device/mod.rs`, commit log), read 2026-11-09; https://crates.io/crates/gotatun, read 2026-11-09.
- GotaTun audit: https://github.com/mullvad/gotatun/blob/main/audits/2026-02-17-Assured.md, read
  2026-11-09. The full report it links,
  https://www.assured.se/publications/Assured_Mullvad_GotaTun_Code_Review_2026.pdf, was not read.
- Mullvad: https://mullvad.net/en/blog/announcing-gotatun-the-future-of-wireguard-at-mullvad-vpn, read
  2026-11-09; https://github.com/mullvad/mullvadvpn-app (`Cargo.toml`,
  `android/scripts/generate-sboms.sh`), read 2026-11-09;
  https://gitlab.com/fdroid/fdroiddata/-/raw/master/metadata/net.mullvad.mullvadvpn.yml, read
  2026-11-09.
- NepTUN: https://github.com/NordSecurity/NepTUN (README, `neptun/Cargo.toml`, tags, commit log), read
  2026-11-09; https://github.com/NordSecurity/libtelio (`Cargo.toml`), read 2026-11-09;
  https://www.bleepingcomputer.com/news/linux/nordvpn-open-sources-its-linux-vpn-client-and-libraries/,
  read 2026-11-09. The Cure53 meshnet audit of December 2024 was seen only in a search summary
  (unverified).
- Firezone: https://github.com/firezone/boringtun (README, `noise/timers.rs`, archived), read
  2026-11-09; https://github.com/firezone/sanstun (README, NOTICE.txt, CHANGELOG, `Cargo.toml`, `src`),
  read 2026-11-09; https://crates.io/crates/sanstun, read 2026-11-09;
  https://github.com/firezone/firezone/pull/15728 and https://github.com/firezone/firezone/pull/16086
  (commit messages via the GitHub API), read 2026-11-09.
- Other forks: https://github.com/defGuard/boringtun, https://crates.io/crates/defguard_boringtun,
  https://crates.io/crates/boringtun-easytier, https://git.zx2c4.com/wireguard-rs/log/,
  https://github.com/aramperes/onetun (`Cargo.toml`), all read 2026-11-09.
- wireguard-go: https://git.zx2c4.com/wireguard-go (`device/mobilequirks.go`, commit log), read
  2026-11-09.
- WireGuard for Android: https://git.zx2c4.com/wireguard-android (`GoBackend.java`,
  `WgQuickBackend.java`, `tunnel/tools/libwg-go/Makefile`, `api-android.go`, `go.mod`), read
  2026-11-09; https://download.wireguard.com/android-client/ (size of
  `com.wireguard.android-1.0.20260315.apk` from its HTTP header), read 2026-11-09.
- Proton VPN: https://github.com/ProtonVPN/android-app (`gradle/libs.versions.toml`) and
  https://github.com/ProtonVPN/wireguard-android (`tunnel/tools/libwg-go/go.mod`), read 2026-11-09.
- Rethink: https://github.com/celzero/rethink-app and https://github.com/celzero/firestack
  (`go.mod`, `intra/ipn/wgproxy.go`), read 2026-11-09.
- sing-box: https://sing-box.sagernet.org/configuration/endpoint/wireguard/ and
  https://github.com/SagerNet/sing-box/tree/main/transport/wireguard (`device_stack.go`), read
  2026-11-09.
- Android's resolver:
  https://android.googlesource.com/platform/packages/modules/DnsResolver/+/refs/heads/main/resolv_private.h
  and `res_send.cpp` in the same directory, read 2026-11-09.
- Rust's clock: https://doc.rust-lang.org/std/time/struct.Instant.html, read 2026-11-09.
- Crypto crates: https://aws.github.io/aws-lc-rs/requirements/index.html,
  https://github.com/briansmith/ring (README, commit log), and the crates.io pages of `ring`,
  `aws-lc-rs`, `aws-lc-sys`, `x25519-dalek`, `curve25519-dalek`, `subtle`, `ip_network`,
  `ip_network_table` and `chacha20poly1305`, all read 2026-11-09.
- WireGuard's formal verification: https://www.wireguard.com/formal-verification/, read 2026-11-09.
- Cited from knowledge, not re-read on 2026-11-09: RFC 1624 (incremental checksum update), RFC 3022
  (basic NAT), RFC 5508 (NAT behaviour for ICMP).
