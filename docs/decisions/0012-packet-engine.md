# 0012. Packet engine for the local VPN

- Status: Accepted (by the maintainer on 2026-11-07)
- Date: 2026-10-28, decided from the spike on 2026-11-07

## Context

The local VPN of Datapavan Watch (v0.2, ADR 0029) must carry every app's packets from the tunnel to
their real destinations. It must also know which app each flow belongs to, show a refused or
unreachable server as such, cost little battery, add under 1 MB per ABI (VPN.md), and run beside
circumvention tools through a local SOCKS5 proxy (RESTRICTED-REGIONS.md). The candidates were a Rust
userspace stack (`smoltcp` or `ipstack`) and Go's gVisor netstack.

The spike ([findings](../spikes/2026-11-packet-engine.md), code in `spikes/packet-engine/`) measured
three engines behind one surface, on the Android 17 and 15 emulators and on a Galaxy A40 with Android
11:

1. `ipstack`, a userspace stack in Rust;
2. a third approach, the "system" stack of sing-box and mihomo: packets are rewritten so that
   Android's own kernel TCP terminates them, in about 500 lines of safe Rust;
3. gVisor in Go, through gomobile.

## Decision

**The system stack, in Rust.** Each new TCP connection's first SYN is held until Android has named
the app (`getConnectionOwnerUid`) and the real server has accepted, or the app gets a reset. Watch
runs inside its own tunnel and protects its upstream sockets, which this design requires. UDP is
relayed in Rust, one socket per flow.

Why, from the spike:

- **CPU, the best stand-in for battery.** On the A40 it needed 40 s of CPU for the workload, `ipstack`
  63 s and gVisor 139 s. For QUIC-sized UDP on the emulator it needed 1.0 s, against 1.3 s and 2.6 s.
- **Attribution and honest failures.** With the SYN held it found the app of every flow on the A40
  and showed a closed port as refused, as gVisor did. `ipstack` lost the owner of half the short
  connections and showed a closed port as open.
- **Size and memory.** The library is 0.96 MB for arm64 with both Rust engines in it; gVisor's is
  5.4 MB per ABI. The watch app's memory: 46 MB, against 60 MB with gVisor.
- **Robustness.** On Android 11, 15 and 17 it carried TCP and UDP without loss. Across a Wi-Fi
  switch the tunnel stayed up: the transfer in flight broke, as it does without a VPN, and the next
  one ran. IPv6 entered the tunnel and failed fast without an IPv6 network. It chained through a
  SOCKS5 proxy at about 210 Mbit/s on the emulator. After an engine restart, an app's kept-alive
  connection got a reset and reconnected in a second.
- **One language.** The engine and its parsers stay in the memory-safe Rust engine (ADR 0006). There
  is no second toolchain in the reproducible build and no split between Go and Rust.

gVisor stays the fallback if the system stack fails on phones the spike did not reach. `ipstack` is
not used: it blocks in its TCP stream's Drop and needs a multi-threaded runtime, against VPN.md's
single engine thread.

## Consequences

- **VPN.md changes in three places.** Watch is inside its own tunnel and protects its sockets,
  instead of being excluded. Onboarding asks for `ACCESS_LOCAL_NETWORK` on Android 17, which Watch
  needs to pass on any app's traffic to private addresses. The engine answers a segment of an
  unknown connection with a reset.
- **Not yet measured:**
  - Android 10 and 12 to 14;
  - vendors other than Samsung, whose kernels and netd rules this design leans on (policy routing,
    `tcp_fwmark_accept`): device reports and the lab cover them;
  - the battery cost of a whole day, against VPN.md's 3 % target: measured on Watch itself, not on
    the spike, since an idle VPN's cost is in its timers and wakeups.
- **Still to build for chaining:** SOCKS5 UDP ASSOCIATE, so that QUIC and calls can go through a proxy
  too; the spike chained TCP only.
- **Accepted:** the maintainer chose the system stack on 2026-11-07, after the spike.
