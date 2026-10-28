# Local VPN design (v0.2 "Watch", v0.3 "Guard")

> Status: **design draft.** The packet engine is chosen after a two-week spike (decision D3).

## What "VPN" means here

Datapavan uses Android's `VpnService` only to see and filter traffic on the device. It is a
**firewall**, not a tunnel:

- No Datapavan server exists, and no traffic is sent to us.
- Traffic leaves the phone towards its real destination, so the user's IP address does not change.
- All analysis happens on the device, in the Rust engine.

## Data path

```
 app ──packets──▶ TUN interface ──fd──▶ Rust engine ──protected socket──▶ real destination
                  (VpnService)          │
                                        ├─ flow table (5-tuple → app UID, domain, counters)
                                        ├─ DNS resolver and IP→hostname cache
                                        ├─ TLS SNI / QUIC Initial parser
                                        ├─ rule engine (allow / block / log)
                                        └─ statistics → encrypted local store
```

1. **Tunnel.** `VpnService.Builder` creates a TUN interface. Routes cover all of IPv4 and IPv6, DNS points to a virtual address inside the tunnel, and Datapavan itself is excluded from the tunnel.
2. **Hand-off.** The TUN file descriptor is passed to the Rust engine over JNI. From then on Kotlin only controls the lifecycle; all packet handling is in Rust.
3. **Which app?** For every new TCP or UDP flow, the engine asks `ConnectivityManager.getConnectionOwnerUid()` (Android 10+, available only to the active VPN app). The answer is cached for the lifetime of the flow.
4. **Which destination?** In order of preference:
   1. the DNS answers we served (IP → hostname cache);
   2. the TLS ClientHello SNI of the connection;
   3. the QUIC Initial SNI (harder, later);
   4. an offline IP → ASN/organisation database.
   When none applies, the UI says "unknown" plainly.
5. **Decision.** The rule engine returns allow, block or log-only.
6. **Forwarding.** A userspace TCP/IP stack terminates each connection locally and opens a real, `protect()`-ed socket to the destination, then relays bytes. UDP flows go through a NAT table with idle timeouts.
7. **Recording.** Per-flow statistics go to app-private, encrypted SQLite (key in the Android Keystore), with 30-day default retention.

## Policies

| Topic | Policy |
|---|---|
| DNS | Our resolver answers inside the tunnel and resolves upstream through a protected socket: the network's resolver by default, or a DoH/DoT resolver the user chooses. Blocked tracker domains get an empty answer. If the chosen upstream fails, we fall back to the network's resolver: **Datapavan must never break the user's connectivity**. |
| QUIC | Optional "block QUIC" setting (UDP 443). Apps then fall back to TCP + TLS, where the SNI is visible. Off by default in v0.2, so we observe without interfering. |
| Fail mode | Onboarding recommends Android's *Always-on VPN* with *Block connections without VPN*. If the engine dies, traffic stops instead of silently bypassing. |
| Private DNS | If Android Private DNS is in strict mode, hostnames are hidden from us. Onboarding detects this and explains the trade-off. |
| Network changes | Wi-Fi ↔ mobile switches re-bind upstream sockets without dropping the tunnel. |
| IPv6 | First-class. Never leak IPv6 around the tunnel. |

## Coexistence with other VPNs

Android allows **one active VPN at a time**. This matters most where people depend on circumvention
tools. Datapavan therefore supports **chaining**: its upstream sockets can go through a local SOCKS5
proxy offered by another app (for example v2rayNG, NekoBox, Orbot or Psiphon in proxy mode). The user
keeps both their circumvention tool and Datapavan. Datapavan does **not** implement circumvention
itself. Later, an optional upstream WireGuard connection can serve users of commercial VPN providers.

## Engineering constraints

- **Battery:** one engine thread, event-driven, no busy loops, batched reads. Target: ≤ 3 % extra battery per day, measured on the Galaxy A40.
- **Memory safety:** every parser (IP, TCP, UDP, DNS, TLS, QUIC) lives in `datapavan-engine`, where `unsafe` is forbidden, and is fuzzed with `cargo fuzz`.
- **Size:** the engine adds well under 1 MB per ABI.
- **Samsung and other OEM battery managers:** a health check in the app, plus per-vendor onboarding guides.

## Spike plan (two weeks)

Build a minimal forwarder twice, with the same JNI surface:

1. a Rust userspace stack (`smoltcp` or `ipstack`);
2. Go's gVisor netstack (the approach of existing Android firewalls).

Measure both on the A40: throughput, latency, battery drain over 8 hours of mixed use, memory, binary
size, and robustness when the network changes. Record the choice as an ADR.

## Licence hygiene

Several existing Android firewalls (NetGuard, TrackerControl) are GPL-licensed. We study their ideas
and publications, but we do not copy their code into this Apache-2.0 project.
