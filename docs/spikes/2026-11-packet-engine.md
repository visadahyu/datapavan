# Spike: the packet engine for Datapavan Watch (ADR 0012)

Status: **in progress.** Started 2026-11-07. The emulator round is done; the round on the Galaxy A40,
which decides, is not. Code: [spikes/packet-engine/](../../spikes/packet-engine/README.md).

## Question

Which engine should carry every app's packets in Datapavan Watch, the separate VPN app of v0.2
([ADR 0029](../decisions/0029-network-access-for-v0.2.md), [VPN.md](../VPN.md))? ADR 0012 named two
candidates. The spike measures three, because the fastest Android clients today also use a third
approach:

1. **Rust, userspace stack:** `ipstack` 1.0.1 on tokio terminates each connection in userspace.
2. **Rust, the system's own stack:** packets are rewritten so that Android's kernel TCP terminates
   them, as the "system" stack of sing-box and mihomo does. The rewriting (addresses, ports, RFC 1624
   checksum updates) is about 400 lines of safe Rust written for the spike.
3. **Go, gVisor netstack** (`gvisor.dev/gvisor` at `v0.0.0-20261107083731-df6600af9f2c`, Go 1.27.3,
   bound with gomobile): the approach of existing Android firewalls.

All three sit behind one Kotlin surface (start on the tunnel's descriptor, stop, counters) and make
the same upcall per new flow, `ConnectivityManager.getConnectionOwnerUid`, so that each pays for
finding the app.

## Method

- **Apps.** `watch` holds the `VpnService` and the engines; `load` is the workload. The tunnel takes
  only the workload app (`addAllowedApplication`), so no other app's traffic passes it.
- **Workload** against `tools/server.py` on the development computer, per round:
  - one 50 MB download;
  - one 20 MB upload;
  - four parallel downloads, 50 MB in all;
  - 100 fresh TCP connections (time to connect);
  - 100 requests on one kept-alive connection (round trip).
- **Runs.** Three rounds per engine, and the baseline without a VPN before and after.
- **Also read:** the engine process's CPU time (`/proc/pid/stat`), its memory (`dumpsys meminfo`), the
  native library's size per ABI, and the engines' own counters.
- **Emulator round:** Android 17 (API 37, x86_64, 16 KB pages), 2026-11-07, with nothing else running.
  Its virtual network caps every path at about 300 Mbit/s, the baseline's too. So it compares
  correctness, CPU, memory and size, not speed.

## Results on the emulator

Medians of three rounds; the baseline of six.

| | Baseline | Rust userspace | Rust system | Go gVisor |
|---|---|---|---|---|
| Download, Mbit/s | 292 | 313 | 294 | 290 |
| Upload, Mbit/s | 240 | 241 | 240 | 236 |
| 4 parallel, Mbit/s | 307 | 308 | 295 | 292 |
| Connect, p50 ms | 0.42 | 0.27 | 0.35 | 0.66 |
| Kept-alive round trip, p50 ms | 0.40 | 0.42 | 0.38 | 0.44 |
| Engine CPU for the three rounds, s | | 3.6 | 3.5 | 6.7 |
| Watch app memory (PSS), MB | | 37 | 38 | 53 |
| Native library, arm64-v8a | | 0.96 MB, both Rust engines together | | 5.4 MB |
| Native library, armeabi-v7a | | 0.63 MB | | 5.4 MB |
| Flows whose app was not found | | 218 of 305 | 250 of 305 | 1 of 305 |

The first download after gVisor started failed once to connect; the other 44 transfers of all
engines went through.

**The system engine with the SYN held** until Android has named the app and the real server has
accepted (three rounds, the same day):

| | Download | Upload | 4 parallel | Connect p50 | Round trip p50 | CPU | App not found |
|---|---|---|---|---|---|---|---|
| Rust system, SYN held | 292 Mbit/s | 238 | 296 | 0.62 ms | 0.39 ms | 3.4 s | 1 of 305 |

**A refused connection** (a closed port on the test server, three tries each):

| Engine | What the app saw |
|---|---|
| Without a VPN | "Connection refused" |
| Rust system, SYN held | "Connection refused" |
| Go gVisor | "Connection refused" |
| Rust userspace (`ipstack`) | a connection that opened, in 0.24 ms, to a server that does not listen |

## Findings so far

1. **Throughput is not where they differ on the emulator.** Every engine reached the emulator's own
   cap. The A40 has to show whether one falls behind on a real radio.
2. **gVisor costs about twice the CPU** of either Rust engine for the same bytes, and 15 MB more
   memory. CPU time is the best stand-in for battery until the 8-hour runs. Its library is 5.4 MB per
   ABI against VPN.md's target of under 1 MB. That would also triple the APK people pass on by hand.
3. **At first only gVisor found the app of short connections.** It finishes the handshake with the app only
   after the real server accepted, so the app's socket still exists when Android is asked. The Rust
   engines answer the handshake at once. By the time they ask, a connect-and-close test has already
   closed its socket, and Android knows no owner. This decides a lot for a tool whose point is "which
   app": the Rust system engine can do the same by holding the app's SYN until the lookup and the
   upstream connect are done. `ipstack` cannot without changing it.
4. **The same holds for honest failures.** With an early handshake, an app sees a refused server as a
   connection that opens and then breaks. gVisor and the system engine with the SYN held show it as
   refused, as without a VPN; `ipstack` did not (table above).
5. **`ipstack` blocks in its TCP stream's Drop** (`block_in_place` and `block_on`). It needs tokio's
   multi-threaded runtime, against VPN.md's single engine thread. On a current-thread runtime it hung
   the engine when it stopped, with connections still open. Its README calls it "unstable, under
   development".
6. **The system stack works only with Watch inside its own tunnel.** Android routes the answers of the
   engine's listener back through the tunnel only for UIDs inside the VPN, by policy routing. So Watch
   adds itself to the tunnel and calls `VpnService.protect` on each upstream socket, one more upcall
   per flow. VPN.md's "Datapavan itself is excluded from the tunnel" does not hold for this engine.
7. **Android 17 asks for `ACCESS_LOCAL_NETWORK`** before an app that targets it reaches a private
   address. Watch's own upstream sockets are such an app's, so Watch needs it for every app's LAN
   traffic (printers, TVs, a NAS), and the permission and its explanation belong in its onboarding.
8. **The tunnel descriptor:** `Builder.setBlocking(false)` is needed. The engines read until "would
   block", and the Rust side also sets `O_NONBLOCK` itself.

## Leaning, before the A40

- **The Rust system stack is the leading candidate.** It is small, efficient and safe Rust. The
  kernel's own TCP does the hard part, with Android's tuned congestion control. With the SYN held it
  attributes and fails as honestly as gVisor. It still has to pass two things:
  - Android 10 to 16 and other vendors, since it leans on policy routing and `tcp_fwmark_accept`;
  - the A40's numbers.
- **gVisor is the fallback** if the system stack fails on real phones. It is proven and correct, but
  it carries a cost in size, CPU and memory, a second toolchain in the reproducible build, and
  parsers split between Go and Rust.
- **`ipstack` is out** unless it is forked, for findings 3 and 5.

## Still to do

1. The A40 round over Wi-Fi to `tools/server.py`, with the VPN consent tapped on the phone:
   - throughput, latency, CPU, memory;
   - Wi-Fi switched off and on during a transfer;
   - IPv6;
   - 8 hours of a scripted workload per engine and without a VPN, unplugged, read from batterystats
     and the battery level.
2. Chaining through a local SOCKS5 proxy (RESTRICTED-REGIONS.md), at least as a check that each engine
   can.
3. The choice, recorded in ADR 0012.
