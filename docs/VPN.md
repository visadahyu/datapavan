# Local VPN design (v0.2 "Watch", v0.3 "Guard")

> Status: **design draft.** The packet engine is chosen after a two-week spike ([ADR 0012](decisions/0012-packet-engine.md)).

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
3. **Which app?** For every new TCP or UDP flow, the engine asks `ConnectivityManager.getConnectionOwnerUid()` (Android 10+, available only to the active VPN app). That is a Java API, so the engine makes one JNI upcall per new flow; the answer is cached for the lifetime of the flow.
4. **Which destination?** In order of preference:
   1. the DNS answers we served (IP → hostname cache);
   2. the TLS ClientHello SNI of the connection;
   3. the QUIC Initial SNI (harder, later);
   4. an offline IP → ASN/organisation database.
   When none applies, the UI says "unknown" plainly.
5. **Decision.** The rule engine returns allow, block or log-only.
6. **Forwarding.** A userspace TCP/IP stack terminates each connection locally and opens a real, `protect()`-ed socket to the destination, then relays bytes. UDP flows go through a NAT table with idle timeouts.
7. **Recording.** Per-flow statistics go to app-private, encrypted SQLite (key in the Android Keystore). Retention is the user's choice: none, 1 day, 7 days or 30 days, with a one-tap wipe. Flows chained through a circumvention proxy are counted but their destinations are **not** recorded by default, because a log of them is evidence in a phone search.

## Policies

| Topic | Policy |
|---|---|
| DNS | Our resolver answers inside the tunnel and resolves upstream through a protected socket: the network's resolver by default, or a DoH/DoT resolver the user chooses. Blocked tracker domains get an empty answer. If the chosen upstream fails, the default is to fall back to the network's resolver and show a visible warning. In censored networks that fallback would hand every query to the censor, so a **strict DNS** setting never falls back (recommended in restricted regions). |
| QUIC | Optional "block QUIC" setting (UDP 443). Apps then fall back to TCP + TLS, where the SNI is visible. Off by default in v0.2, so we observe without interfering. |
| Connectivity and fail mode | Datapavan never breaks connectivity through its own policy decisions. The one deliberate exception is an engine crash under Android's *Always-on VPN* with *Block connections without VPN*: traffic then stops until Android restarts the service, instead of silently bypassing the firewall (fail-closed, see [ADR 0006](decisions/0006-rust-engine-unsafe-forbidden.md)). Onboarding recommends this mode. |
| Private DNS | If Android Private DNS is in strict mode, hostnames are hidden from us. Onboarding detects this and explains the trade-off. |
| Network changes | Wi-Fi ↔ mobile switches re-bind upstream sockets without dropping the tunnel. |
| IPv6 | First-class. Never leak IPv6 around the tunnel. |
| Encrypted content | Never decrypted: Datapavan installs no certificate authority and does not intercept TLS. Apps that bypass our resolver (their own encrypted DNS, hard-coded IPs) are flagged, and the TLS ClientHello fingerprint identifies the client library behind a connection. |

## Behaviour analysis

- **Accounting cross-check.** Android counts each app's traffic itself (`NetworkStatsManager`). The engine compares that with the bytes it saw for the same app; a surplus on Android's side is traffic that bypassed the tunnel, and the UI says so.
- **Traffic shape.** Content stays encrypted, but shape does not: a steady, low-rate upstream of small packets at regular intervals looks like compressed audio, and large upstream bursts look like photo or video uploads. The engine learns each app's normal shape on the device during v0.2 (upload-to-download ratio, upload rates, on screen and in the background) and reports deviations as observations. A deviation that coincides with microphone use in the sensor log gets a higher priority. All of this stays on the device.
- **A learned baseline only detects change.** If an app leaks with every request from the first day, the leak becomes its "normal". Three more layers cover that case:
  1. **Destination split.** Upload bytes are split by destination category (content, analytics, advertising) using our resolver, the server names and the tracker lists. This needs no baseline. It fails only when an app sends everything over one channel.
  2. **Lab reference.** The project measures apps on its own lab phones, where decrypting its own test traffic is legitimate research, and compares each action with a privacy-respecting equivalent (for example the web version of the same service in a privacy browser). The results ship as a signed reference list, like the tracker lists, and as public reports. Legal advice comes first.
  3. **Declared against observed.** Google Play shows a data-safety label that each developer fills in and nobody checks. Datapavan compares the label with what it observes; every contradiction is a documented finding. Google's terms do not allow collecting or redistributing the labels automatically (ADR 0015). So for now the app links to each listing, and the lab cites the labels of the apps it measures by hand. In-app comparison waits for researcher access under DSA Article 40(12) or for Google's permission.

## Coexistence with other VPNs

Android allows **one active VPN at a time**. This matters most where people depend on circumvention
tools. Datapavan therefore supports **chaining**: its upstream sockets can go through a local SOCKS5
proxy offered by another app (for example v2rayNG, NekoBox, Orbot or Psiphon in proxy mode). The user
keeps both their circumvention tool and Datapavan. Datapavan does **not** implement circumvention
itself. Later, an optional upstream WireGuard connection can serve users of commercial VPN providers.

Chaining also contains an untrusted tool (see [RESTRICTED-REGIONS.md](RESTRICTED-REGIONS.md)):

- **No inbound path.** SOCKS5 `CONNECT` only carries connections the phone opens, so the phone gets no address in the VPN provider's network. The engine accepts packets only for flows a local app started, UDP replies included, and drops everything else. SOCKS5 `BIND` is never used.
- **The tool's own traffic is visible.** In proxy mode the tool is an ordinary app inside Datapavan's tunnel. Its own connections, to its servers and anywhere else, are attributed to it like any other app's. They are forwarded directly, never back into the proxy, which also prevents loops.
- **Proxy-like behaviour is flagged** (v0.2) and can be blocked (v0.3): many distinct destinations in a short time, sustained upload, or activity while the screen is off. Thresholds come from measurements, and a flag says what was seen instead of accusing the app. Detection counts destinations in memory, so it does not need the destination log that is off by default for chained flows.
- **Per-app choice.** The user decides which apps go through the tool. Everything else goes directly or is blocked.
- **Proxy mode, step by step.** Onboarding has a guide per popular tool, in every UI language, for running it in proxy mode instead of VPN mode.

## Engineering constraints

- **Battery:** one engine thread, event-driven, no busy loops, batched reads. Target: ≤ 3 % extra battery per day, measured on the Galaxy A40.
- **Memory safety:** if the Rust stack is chosen (ADR 0012), every parser (IP, TCP, UDP, DNS, TLS, QUIC) lives in `datapavan-engine`, where `unsafe` is forbidden, and is fuzzed with `cargo fuzz`. With gVisor, the Go stack handles IP and TCP, and the higher-level parsers (DNS, TLS, QUIC) stay in Rust.
- **Size:** target: the engine adds less than 1 MB per ABI. To be measured in the spike; the M1 bridge alone is about 340 KB on arm64, mostly the Rust standard library.
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
