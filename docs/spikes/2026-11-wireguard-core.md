# GotaTun's protocol core beside Watch's engine (before W7)

A spike of 2026-11-19, asked for by [ADR 0035](../decisions/0035-wireguard-upstream.md) ("Before building W7"), on
its questions 2 (`ring` or `aws-lc-rs`) and 3 (the size budget), and on the interoperation tests its settled section
asks for. Code: [`spikes/wireguard-core/`](../../spikes/wireguard-core/), outside `core`'s workspace with a lock file of
its own; nothing went into `core/net` or the app. Everything below is GotaTun 0.10.3, pinned exactly, with
`default-features = false` and one crypto feature; Rust 1.99.1, NDK 30.0.16248370, cargo-ndk 4.1.2; `core` as of
`f1127f3`.

## Method

- **Size.** [`size.sh`](../../spikes/wireguard-core/size.sh) builds Watch's library as
  `android/watch/build.gradle.kts` does (cargo-ndk, API 29, `build --locked --release`, the Gradle task's environment
  and remapped paths, `core`'s release profile) and strips it as the APK's packaging does (`llvm-strip
  --strip-unneeded`). Variants: `today` (`core/watch-jni`); `baseline`, the spike's crate `size/`, which includes
  `core/watch-jni/src/lib.rs` unchanged; `ring` and `aws-lc`, the same with one more export that runs a session
  between two `Tunn`s (handshake with a preshared key, the queued first packet, a data packet each way, the timers,
  the counters), so nothing W7 calls is dropped as dead code; and `ring-in-core`, `aws-lc-in-core`, the same crate
  built as a member of a copy of `core`'s workspace, the shape W7 will have. `today` as measured is byte for byte the
  `libdatapavan_watch.so` in Advanced's release APK built from the same `core`, for all three ABIs: the method
  measures what ships.
- **Reproducible.** [`reproducible.sh`](../../spikes/wireguard-core/reproducible.sh), the method of
  `scripts/reproducible.sh`: two fresh clones of the commit at paths of different lengths, each with its own target
  directories, the second building the variants in reverse order; the stripped libraries compared byte for byte,
  and searched for strings that name this machine's paths.
- **CPU.** [`bench/`](../../spikes/wireguard-core/bench/src/main.rs), built with `core`'s release profile, pins its
  thread to one core and runs batches of 256 packets through an established session: the phone's
  `handle_outgoing_packet` (with the TUN's MTU, 1420, so data is padded as W7 will send it), then the server's
  `RateLimiter::verify_packet` and `handle_incoming_packet`, as a datagram from the socket goes. Building the input
  packets is outside the time. 3 s per size after 0.5 s of warm-up; the thread's CPU time over the wall time
  shows whether the core was its own. MB is 10^6 bytes of IP packets.
  [`bench-on-device.sh`](../../spikes/wireguard-core/bench-on-device.sh) runs it over adb from `/data/local/tmp` on
  a device's fastest and slowest cores.
- **Interoperation.** [`lab.sh`](../../spikes/wireguard-core/lab.sh): the Linux kernel's WireGuard (the reference
  implementation; the module is loaded on the host) in a container of its own Compose project, `datapavan-wglab`,
  from the official `alpine:3.24` image pinned by digest with Alpine's own `wireguard-tools-wg` 1.0.20260223,
  `iproute2` and `python3`, `NET_ADMIN` only, nothing published on the host. Behind its interface: the kernel's ICMP
  echo, a UDP echo, a reflector that answers from an address outside the client's AllowedIPs, and an HTTP server, on
  IPv4 and IPv6. The client, [`lab/`](../../spikes/wireguard-core/lab/src/main.rs), drives `Tunn` over one UDP
  socket with hand-built IP packets (no TCP stack) as W7's engine would: the timers once a second, every datagram
  through the `RateLimiter` first, answers only from the configured server address, AllowedIPs checked by the
  caller. Keys come from the peer's own `wg genkey`. `lab.sh --quick` leaves out the two-minute rekey wait, for CI.
- **Licences and `unsafe`.** `cargo deny --locked --offline check` in the spike with its own
  [`deny.toml`](../../spikes/wireguard-core/deny.toml): `core/deny.toml` plus BSD-3-Clause, BSD-2-Clause, ISC and
  MPL-2.0, the advisory database as fetched on 2026-11-19 (commit `7133866`). `unsafe` sites counted per crate by
  [`unsafe-count.py`](../../spikes/wireguard-core/unsafe-count.py), a lexical count after comments and strings are
  removed.
- **API.** GotaTun 0.10.3's source read, and diffed against 0.10.2 (both from crates.io).

## 1. Size per ABI

Stripped `libdatapavan_watch.so`, bytes:

| | arm64-v8a | armeabi-v7a | x86_64 |
|---|---|---|---|
| Today (`core/watch-jni`) | 1,384,656 | 1,220,364 | 1,590,136 |
| With GotaTun on `ring` | 1,533,936 | 1,343,124 | 1,781,544 |
| With GotaTun on `aws-lc-rs` | 1,555,096 | 1,351,152 | 1,804,296 |
| `ring`, added | +149,280 (+10.8 %) | +122,760 (+10.1 %) | +191,408 (+12.0 %) |
| `aws-lc-rs`, added | +170,440 (+12.3 %) | +130,788 (+10.7 %) | +214,160 (+13.5 %) |
| VPN.md's 1 MB, today's excess | +384,656 | +220,364 | +590,136 |
| VPN.md's 1 MB, excess with `ring` | +533,936 | +343,124 | +781,544 |

The GotaTun rows are the in-`core` builds; the spike's own layout gives the same within 1 KB (section 2). In MiB
the `ring` library is 1.46, 1.28 and 1.70.

- **The 1 MB target is already passed today,** by 0.38 MB on arm64, before any WireGuard. The packet-engine spike
  measured 0.96 MB on arm64 for both Rust engines together (2026-11-07); the engine has grown since.
- **Compressed** (gzip -9, near what a download costs): today 733 KB on arm64, with `ring` 826 KB (+93 KB), with
  `aws-lc-rs` 835 KB (+102 KB).
- **`opt-level = "z"`** instead of `"s"` would take about 250 KB off on arm64: 1,129,680 bytes today, 1,283,184
  with `ring`, still above 1 MB. Its cost in speed was not measured.
- **`tokio`** comes in with `sync`, `rt`, `time`, `macros` and `io-util` (its `net` only with the `device`
  feature), all of which the engine already enables: it adds nothing. `nix` gains `fs` and `user`.
- **Crates.** GotaTun has 29 direct dependencies on Android (28 and the crypto crate), as ADR 0035 counted. Watch's
  library goes from 54 crates to 120 with `ring` (66 new, 8 of them procedural macros that run in the build only) and
  to 121 with `aws-lc-rs` (`aws-lc-rs`, `aws-lc-sys` and `untrusted` 0.7 instead of `ring` and `untrusted` 0.9). The
  lock gains a second generation of RustCrypto's traits beside the engine's (`digest` 0.10, `cipher` 0.4, `aead` 0.5,
  `hmac` 0.12, `universal-hash` 0.5, `block-buffer`, `crypto-common`, `inout`), two versions each of `rand_core` (0.6,
  0.9) and `getrandom` (0.2, 0.3), and `thiserror` 1: `cargo deny` warns of 14 duplicated crates against 1 in `core`.
  GotaTun keeps RustCrypto's `chacha20poly1305` for XChaCha20 in cookie replies only, and `blake2`, `hmac` and
  `x25519-dalek` for the handshake.

## 2. Reproducible

Two clean builds from commit `ade03d8`, in fresh clones at paths of different lengths:

- **`today`, `ring-in-core` and `aws-lc-in-core`: byte-identical for all three ABIs,** and identical again to a third
  build under another path (the in-`core` variants) and to the APK (`today`). No library holds a string naming a
  path of this machine. The C objects need nothing more: AWS-LC's build already maps its file names to `/aws-lc/...`,
  and `ring`'s C leaves no file name in the library.
- **The spike's own `baseline`, `ring` and `aws-lc` differ between the clones** (by 0 to 448 bytes in size, always in
  content). The cause is the spike's layout, not GotaTun or the C code: outside `core`'s workspace, Cargo hashes the
  absolute path of a path dependency into its metadata (`datapavan_net` hashed to `ae04fb31` in one clone and
  `27c0ef7f` in another, while `tokio`'s hash was the same in both), and the hash reaches the symbol names and, through
  LTO, the code's layout. Inside `core`'s workspace, as W7 will build it, the hash is relative and the build is
  reproducible, as the in-`core` variants show.

`ring` and `aws-lc-rs` build with the NDK's clang: no CMake or bindgen is installed here, and `aws-lc-sys` used its
pregenerated bindings (its own for `aarch64-linux-android`, its universal ones for the other two ABIs).

## 3. CPU per megabyte

Nanoseconds per packet, the median of three runs of 3 s each; "both" is the phone's encapsulation and the server's
decapsulation of the same packet ([runs](../../spikes/wireguard-core/results-2026-11-19-bench.tsv)):

| | Size | `ring`: encap / decap / both | ms per MB | `aws-lc-rs`: both | ms per MB |
|---|---|---|---|---|---|
| Development machine (Ryzen 9 7900X, one core) | 1280 | 532 / 561 / 1,093 | 0.85 | 1,112 | 0.87 |
| | 1420 | 598 / 567 / 1,165 | 0.82 | 1,176 | 0.83 |
| Emulator (Android 11, x86_64) | 1280 | 921 / 927 / 1,851 | 1.45 | 1,849 | 1.44 |
| | 1420 | 1,037 / 1,039 / 2,085 | 1.47 | 2,100 | 1.48 |

The thread's CPU time equalled the wall time in every run (each core was its own). The two backends are equal within
2 % on x86_64, `ring` slightly ahead at 1280 bytes on the development machine and level on the emulator.

**Against the engine:** a tunnelled byte is encapsulated (going up) or decapsulated (coming down), not both, so it
costs about half a "both": 0.42 ms per MB on the development machine and 0.73 ms on the emulator. The engine alone
cost 6.9 ms of CPU per MB of QUIC-sized UDP and 9.7 ms per MB of TCP on the development machine's Android 17 emulator
(the packet-engine spike, 2026-11-07, its process's CPU for whole transfers), so GotaTun adds roughly 7 to 11 % there,
before the address swap and the extra copy W7 adds. Per packet it is about 40 times one of the engine's per-packet
counts (12.5 to 13.2 ns on this machine, ADR 0046 part 2; 9 to 12 ns for ADR 0044's identifier reading). On the Galaxy
A40 the engine cost 111 ms per MB of TCP (40 s for 360 MB).

**On the Galaxy A40** (Samsung SM-A405FN, Android 11; the coordinator ran `bench-on-device.sh` on 2026-11-19, the
phone not in a call; core 6 is a Cortex-A73 at 1.77 GHz, core 0 a Cortex-A53 at 1.59 GHz; three rounds, which
agreed within 1 %; [results](../../spikes/wireguard-core/results-2026-11-19-bench-a40.tsv)), ms per MB for
encapsulation plus the peer's decapsulation, round 2:

| ABI, core | 1280 B, `ring` | 1280 B, `aws-lc-rs` | 1420 B, `ring` | 1420 B, `aws-lc-rs` |
|---|---|---|---|---|
| arm64-v8a, A73 | 12.75 | 12.85 | 11.11 | 11.21 |
| arm64-v8a, A53 | 18.60 | 18.82 | 15.92 | 16.06 |
| armeabi-v7a, A73 | 15.09 | 13.92 | 13.12 | 11.79 |
| armeabi-v7a, A53 | 24.71 | 23.08 | 20.72 | 18.52 |

In 64-bit code the two are equal within 1 %. In 32-bit code `aws-lc-rs` takes 7 to 11 % less time. A tunnelled byte
costs about half a row: 6 to 9 ms per MB on the A40's cores in 64-bit code, about 5 to 8 % on top of the engine's
111 ms per MB of TCP there.

## 4. Interoperation with WireGuard itself

All 21 checks passed against the kernel's WireGuard
([results](../../spikes/wireguard-core/results-2026-11-19-lab-kernel.txt)):

- **Handshake:** one initiation; the first packet (an ICMP echo) waited in `Tunn`'s queue, went out from
  `get_queued_packets` once the response came, and was answered 0.44 ms after it was first sent, handshake included.
- **Data both ways:** ICMP echo and UDP echo on IPv4 and IPv6; a TCP SYN to port 80 on each version answered by a
  SYN-ACK that acknowledges our ISN + 1, then a request and the server's `HTTP/1.0 200 OK`, then a reset.
- **`PresharedKey`:** a second client with one: handshake and echo on both versions. A third client whose key
  differs from the peer's: three initiations, each response refused by `Tunn` (`InvalidAeadTag`), no session, and the
  peer records no handshake with it.
- **Rekey:** the second handshake 120.7 s after the first, started by `update_timers` on the one-second tick once
  the session was 120 s old and data had been sent; 11 of 11 echoes answered across it, and the new session carried
  both versions.
- **`PersistentKeepalive`** of 5 s: 3 keepalives in 12 s of silence, 5.1 s apart (the one-second tick rounds up).
  The other way, the peer's own keepalives every 3 s: 2 received in 8 s.
- **Roaming:** a new socket on another local port; the next echoes on both versions were answered at the new port,
  and `wg show` has the client's endpoint at it.
- **AllowedIPs:** the reflector's answers from 10.77.1.1 and fd77:1::1, outside this client's AllowedIPs for the
  peer, were decrypted by `Tunn` and dropped by the caller's check, one per version; none passed.

Not covered: a cookie reply under load (the kernel sends one only when its handshake queue is long), an IPv6 outer
address, a provider's server.

## 5. Licences and `unsafe`

- **`cargo deny`:** advisories, bans, licences and sources pass for the spike's crates with the four licences added,
  and no other is needed: `gotatun` MPL-2.0; `x25519-dalek`, `curve25519-dalek` and `subtle` BSD-3-Clause;
  `ip_network` and `ip_network_table` BSD-2-Clause; `ring` "Apache-2.0 AND ISC"; `untrusted` ISC; `aws-lc-rs` "ISC
  AND (Apache-2.0 OR ISC)"; `aws-lc-sys` ISC, Apache-2.0, MIT and BSD-3-Clause, with MIT-0 only as an alternative.
  No advisory matched. Only the 14 duplicate warnings above.
- **`unsafe` in GotaTun:** 17 sites in the package, 1 compiled with these features: `packet/pool.rs`, a
  `BytesMut::set_len` in `PacketBufPool`, which W7 need not use. The other 16 are in `device/uapi` (Windows, 9) and
  the `socket` feature's UDP code (7). The protocol core (`noise/`) has none, and its clock module forbids it.
- **In the 58 new crates that end in the library** (with `ring`): 2,446 sites; 18 crates have none, 6 of them forbid
  it at their root. The most: `zerocopy` 490 (GotaTun's packet casts), `lock_api` 297 and `parking_lot_core` 139
  with `parking_lot` 86 (GotaTun's mutexes), `ring` 228, `ppv-lite86` 168 (SIMD for `rand_chacha`, GotaTun's
  `StdRng`), `futures-util` 136, `getrandom` 0.3 92 and 0.2 56, `smallvec` 80, `generic-array` 78, `eyre` 78,
  `futures-task` 64, `constant_time_eq` 54, `poly1305` 50, `once_cell` 47, `curve25519-dalek` 35. The counts take in
  code for other targets and features, so they bound what is compiled.
- **C and assembly:** `ring`'s package has 137 C and assembly files (188,000 lines, most of them pregenerated
  assembly for every target); `aws-lc-sys`'s has 1,882 (1.6 million lines), and its Rust side is FFI bindings, one
  generated file per target (11,285 sites in all, about 840 each). Of either, the library links only what
  ChaCha20-Poly1305 needs: about 150 KB with `ring` against 170 KB with `aws-lc-rs`, the Rust included.

## 6. The API as of 0.10.3

From 0.10.2 to 0.10.3 the API did not change. Two changes: the TAI64N handshake timestamp's base is now the
kernel's (2^62 + 10 instead of 2^62 + 37, so stamps are 27 s earlier than 0.10.2's; a client moving from 0.10.2
may see its first handshakes ignored for up to 27 s), and `portable-atomic` for targets without 64-bit atomics (none
of Watch's). What `Tunn` asks of its caller:

- **Construction:** `Tunn::new(static_private, peer_public, preshared_key, persistent_keepalive, IndexTable,
  Arc<RateLimiter>)`. The caller makes the `IndexTable` (session indices from an OS-seeded `StdRng`) and the
  `RateLimiter`, and keeps the limiter: **every incoming datagram must pass `RateLimiter::verify_packet(from,
  packet)` first**, which parses it into a `WgKind` and checks a handshake's MAC1 (and MAC2 under load). Without the
  device nothing else does.
- **Out:** `handle_outgoing_packet(packet, Some(&mut MtuWatcher))` returns a data datagram, or a handshake
  initiation while the packet waits in a queue of 256 (later packets are dropped silently); it pads to 16 bytes only
  when given an `MtuWatcher` (`MtuWatcher::new(mtu)`). It allocates one buffer per packet.
- **In:** `handle_incoming_packet(WgKind)` returns a datagram to send (a handshake response, or the keepalive that
  confirms our handshake, after which `get_queued_packets(&mut mtu)` must be drained), a decrypted packet, or an
  error. A decrypted packet still holds its padding until `try_into_ipvx` cuts it to the IP length. **AllowedIPs are
  not checked**: the caller must, as the lab's client does. The datagram's source address is not used: the endpoint
  and roaming are the caller's.
- **Timers and the clock:** `update_timers()` returns at most one datagram (a handshake retry, a rekey, a keepalive)
  or `ConnectionExpired`. The clock is `CLOCK_BOOTTIME` (`nix::clock_gettime`), so deep sleep counts. But **every
  event is stamped with the time of the last `update_timers` call**, which alone reads the clock and alone expires
  sessions (after 180 s) and the connection (after 540 s). GotaTun's own device calls it every 250 ms forever. ADR
  0035's "an idle tunnel costs no timer" therefore needs one rule in W7: call `update_timers` before handling a
  packet that comes after a pause of a second or more, not only on the tick, or a session the server has dropped is
  used once more. The timers are not rounded to the second, whatever the comment in `update_timers` says; there is
  still no next-deadline call. The handshake's TAI64N stamp is the wall clock read when the `Tunn` is made plus boot
  time since: keep one `Tunn` across network changes; one made again after the clock was set back is ignored by the
  server until the clock passes its last stamp.
- **Randomness:** the OS's (`getrandom`) for ephemeral keys and the rate limiter's secrets; `StdRng` seeded from it
  for indices and timer jitter (`new_with_rng` takes another).
- **Panics:** a few `expect`s on paths that cannot fail and `clock_gettime(...).unwrap()`; with `panic = "abort"`
  any of them ends the VPN process, which fails closed (ADR 0006).

What ADR 0035 assumed and the code says otherwise: packets are GotaTun's own `gotatun::packet` module in 0.10.2 and
0.10.3, not a separate `gotatun-packet` crate, and its one `unsafe` site is in GotaTun itself; the timers are not
rounded to the second. Everything else it says of GotaTun holds: no TUN, socket or thread without the features,
`tokio` required, the 256-packet queue, boot time, the 250 ms device tick, no next-deadline call.

## Recommendation for question 2: `ring` or `aws-lc-rs`

**The builder's recommendation was `ring`,** as ADR 0035 proposed, unless the A40's run showed `aws-lc-rs` clearly
faster on ARM (10 % or more on either core class). The A40's run: equal in 64-bit code, `aws-lc-rs` 7 to 11 % faster
in 32-bit code (above), so the line sits on the threshold, and the choice is the maintainer's (ADR 0035, question
2). What weighs:

- CPU: equal within 2 % on x86_64.
- Size: `ring` is smaller by 21 KB on arm64, 8 KB on armv7 and 23 KB on x86_64.
- Build: both reproducible with the NDK's clang; `ring`'s package carries 137 C and assembly files,
  `aws-lc-sys`'s 1,882, and both link only ChaCha20-Poly1305.
- Licences: the same four; `aws-lc-sys` adds MIT-0 only as an alternative.
- Against `ring`: it is mainly one person's project (Assured's note 3.9), and `aws-lc-rs` is GotaTun's default and
  what Mullvad ships, so `ring` is the less exercised configuration of GotaTun in production. GotaTun's `crypto`
  module is a re-export of one AEAD API that both crates offer, and the lab ran on `ring` against the kernel, so the
  risk is small.

Best in class? For the protocol core, yes, as ADR 0035 found. For this choice the field has no single standard:
Mullvad took `aws-lc-rs` on Android, Cloudflare's and Firezone's cores use `ring`.

## Recommendation for question 3: the size budget

VPN.md's "at most 1 MB per ABI" was a target set before the engine was built, and the engine has passed it without
WireGuard: 1.38 MB on arm64 today. GotaTun adds 0.15 MB there, about 11 %. No change to GotaTun's use brings the library
back under 1 MB: `opt-level = "z"` comes closest at 1.28 MB with `ring`, at a cost in speed not measured.

Proposed: VPN.md's target becomes a measured budget for Watch's library per ABI, set where W7 lands with some room
for W8 to W10 (for example 2 MB per ABI as stripped in the APK, against 1.53, 1.34 and 1.78 MB with `ring`), and a
gate in the release build that fails above it, so that each later increase is seen in the commit that makes it and
decided there. Against the field this stays small: the packet-engine spike measured Go's gVisor library at 5.4 MB per
ABI on its own, and WireGuard's own app carries the Go runtime as well (its library was not measured). The gate is
what the field mostly lacks; the number itself is the maintainer's call.

## What W7's brief must take from this

- **The dependency:** `gotatun = { version = "=0.10.3", default-features = false, features = ["ring"] }` (or the
  backend question 2 settles), in `core/net` inside `core`'s workspace. `core/deny.toml` gains the four licences in
  that commit, and the multiple-versions warnings grow from 1 to 14; the lock gains the crates of section 1.
- **The caller's duties,** each with a test: every datagram through `RateLimiter::verify_packet` before `Tunn`, a
  cookie reply sent back; after a decrypted packet, the AllowedIPs check and the flow check (VPN.md, "No inbound
  path"); `get_queued_packets` drained after a handshake response; `MtuWatcher::new(mtu)` passed so data is padded;
  `update_timers` on the one-second tick while a session or handshake lives (and while idle too when the configuration
  sets `PersistentKeepalive`), and also before handling a packet after a pause of a second or more; one `Tunn` per
  configuration kept across network changes; datagrams accepted only from the configured endpoint; the 256-packet
  queue and its silent drops counted.
- **The interoperation lab moves into W7's tests:** `spikes/wireguard-core/peer` and `lab.sh --quick` (about a minute)
  in CI, driven by the engine's own WireGuard code rather than the spike's client. GitHub's runners must have the
  `wireguard` module loaded (`sudo modprobe wireguard`; not tried here); W7's emulator checks reach the peer
  through the host, so the Compose file needs a published UDP port for them, and roaming then passes Docker's
  NAT.
- **Reproducible builds:** GotaTun lives inside `core`'s workspace, as `ring-in-core` did; a path dependency outside
  the workspace makes the library depend on the checkout's path.
- **Size:** the budget question 3 settles, and a gate that fails a build above it.
- **CPU on phones:** W7's own measurement of the whole path (TUN, address swap, `Tunn`, socket) on the A40, as ADR
  0035 asks for the MTU; the A40's run of `bench-on-device.sh` measured `Tunn` alone (above).

## Still open

- **Not covered by the lab:** a cookie reply under load, an IPv6 outer address, wireguard-go as the peer (for runners
  without the kernel module), a provider's server (question 11, the maintainer's Proton configuration on the A40).
- **`opt-level = "z"`:** saves about 250 KB on arm64 (the other ABIs not measured); what it costs the engine and
  GotaTun in speed is unmeasured.
- **The one-second tick's battery cost** (question 12), in W9's battery runs.

## Sources

- GotaTun 0.10.3 and 0.10.2 from crates.io (`src/noise`, `src/packet`, `src/tun/mod.rs`, `src/sleepyinstant`,
  `src/device/mod.rs`, `Cargo.toml`), read 2026-11-19.
- The licences of the new crates from their `Cargo.toml` on crates.io, read 2026-11-19.
- RustSec's advisory database, commit `7133866` of 2026-11-19, through `cargo deny`.
- Repository: [ADR 0035](../decisions/0035-wireguard-upstream.md), [VPN.md](../VPN.md),
  [ADR 0044](../decisions/0044-udp-mapping-and-budgets.md), [ADR 0046](../decisions/0046-live-activity.md),
  [packet-engine spike](2026-11-packet-engine.md), `core/deny.toml`, `scripts/reproducible.sh`,
  `android/watch/build.gradle.kts`.
