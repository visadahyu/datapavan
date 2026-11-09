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
- **Unsafe.** None in the protocol core (its clock module forbids `unsafe`); one site in
  `gotatun-packet`'s buffer pool; two in the optional socket module.
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
- **Size.** No candidate publishes a library size. The spike below measures it.
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
  keepalive wakes the radio.
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
- **No Go.** The reproducible build gains C objects from `ring` only, through the NDK's clang.
- **About 29 more direct crates,** some shared with the engine (`tokio`). Each GotaTun upgrade is a
  reviewed step, often a breaking one.
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
   The spike's size and CPU decide.
3. **Size:** does the engine stay under 1 MB per ABI with WireGuard in it? Unverified.
4. **Android's DNS cache is shared** by all apps of one VPN network. A direct app's answer from the
   network's resolver can be served from the cache to a chosen app, and so can a censored one. Not a
   leak of the chosen app's question, but a wrong answer is possible. One idea: answers from the
   network's resolver get TTL 0 while any app is tunnelled or chained. Unverified that Android then
   does not cache them. Shared with W6.
5. **Is the owner of the resolver's query socket the app** on Android 10 to 17 and on other vendors?
   The AOSP source says so; to check on the A40 and the emulators. Shared with W3 and W6.
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
