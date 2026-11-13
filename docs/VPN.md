# Local VPN design (v0.2 "Watch", v0.3 "Guard")

> Status: **design draft.** The packet engine is chosen: the system stack in Rust, accepted on 2026-11-07 ([ADR 0012](decisions/0012-packet-engine.md), [findings](spikes/2026-11-packet-engine.md)). The milestones of the first release, 0.2.0, are in [DESIGN.md §13.2](DESIGN.md#132-v020-watch-the-connection-log-next-to-circumvention-tools).

## What "VPN" means here

Watch, the part of Datapavan planned for v0.2, is an app of its own beside the audit app ([ADR 0029](decisions/0029-network-access-for-v0.2.md)). It uses Android's `VpnService` only to see and filter traffic on the device. It is a
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

1. **Tunnel.** `VpnService.Builder` creates a TUN interface. Routes cover all of IPv4 and IPv6, and DNS points to a virtual address inside the tunnel. Watch itself is inside its own tunnel and calls `protect()` on each upstream socket: the system stack needs this, because Android routes the answers of the engine's listener back through the tunnel only for apps inside it ([spike](spikes/2026-11-packet-engine.md), finding 6).
2. **Hand-off.** The TUN file descriptor is passed to the Rust engine over JNI. From then on Kotlin only controls the lifecycle; all packet handling is in Rust.
3. **Which app?** For every new TCP or UDP flow, the engine asks `ConnectivityManager.getConnectionOwnerUid()` (Android 10+, available only to the active VPN app). That is a Java API, so the engine makes one JNI upcall per new flow; the answer is cached for the lifetime of the flow.
4. **Which destination?** In order of preference:
   1. the DNS answers we served (IP → hostname cache);
   2. the TLS ClientHello SNI of the connection;
   3. the QUIC Initial SNI (harder, later);
   4. an offline IP → ASN/organisation database.
   When none applies, the UI says "unknown" plainly.
5. **Decision.** The rule engine returns allow, block or log-only.
6. **Forwarding.** Android's own TCP stack, reached through rewritten addresses, terminates each connection locally ([ADR 0012](decisions/0012-packet-engine.md)). The app's SYN is held until the owner lookup and the real, `protect()`-ed connection to the destination are done, then bytes are relayed. UDP leaves through one mapping per app socket, whatever the destination: one protected socket, or for an app chained through the user's tool one SOCKS5 `UDP ASSOCIATE`, each datagram with a header that names its destination. Answers come in only from addresses that app sent to; through the tool, the header of each answer says where it came from (endpoint-independent mapping with address-dependent filtering, [ADR 0044](decisions/0044-udp-mapping-and-budgets.md)). A mapping silent both ways for two minutes ends, and so does one that the chain, set again, sends another way. Each destination is still its own flow in the log, and a new flow's first datagrams wait in it, in order, while its owner is found and its socket opened off the event loop.
7. **Recording.** Per-flow statistics go to app-private, encrypted SQLite (key in the Android Keystore). Retention is the user's choice at onboarding: none, 1 day, 7 days or 30 days, with no default and none kept until the user chooses ([ADR 0040](decisions/0040-own-safety-in-an-untrusted-environment.md)), and a one-tap wipe. Flows chained through a circumvention proxy are counted but their destinations are **not** recorded by default, because a log of them is evidence in a phone search.

## Policies

| Topic | Policy |
|---|---|
| DNS | Our resolver answers inside the tunnel and resolves upstream through a protected socket. For apps that go directly the default is Oblivious DoH, with relays and targets in several jurisdictions, and the network's resolver only as a fallback outside the strict setting ([ADR 0042](decisions/0042-dns-of-apps-that-go-directly.md)); until W8 is built, it is the network's resolver. The user can choose a DoH/DoT resolver instead. Blocked tracker domains get an empty answer. If the chosen upstream fails, the default is to fall back to the network's resolver and show a visible warning. In censored networks that fallback would hand every query to the censor, so a **strict DNS** setting never falls back (recommended in restricted regions). Apps chained through a circumvention tool never use the network's resolver: their names go to the tool (SOCKS5 with the domain name, or DNS through the proxy), or the network would see every name they look up. |
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
tools. Watch therefore supports **chaining**: its upstream sockets can go through a local SOCKS5
proxy offered by another app in its proxy-only mode (for example v2rayNG, NekoBox, Hiddify or Orbot).
The user keeps both their circumvention tool and Watch. Some tools have no proxy mode and run only as
a VPN: WireGuard's own app, Outline, Psiphon and Lantern's released app. For providers that hand out
a WireGuard configuration (Proton VPN, also on its free plan, Mullvad and others), Watch carries it
as its own upstream (0.2.0). Datapavan does **not** implement circumvention itself.

Chaining also contains an untrusted tool (see [RESTRICTED-REGIONS.md](RESTRICTED-REGIONS.md)):

- **No inbound path.** SOCKS5 `CONNECT` only carries connections the phone opens, so the phone gets no address in the VPN provider's network. The engine accepts packets only from addresses a local app sent to, UDP replies included, and drops everything else. Through the tool's UDP relay, each answer's SOCKS5 header names where it came from: one from an address the app did not send to is dropped and counted, and a stand-in's name, which the tool resolved, is bound to the first answer from the port the app asked ([ADR 0044](decisions/0044-udp-mapping-and-budgets.md), decision 2). SOCKS5 `BIND` is never used.
- **The tool's own traffic is visible.** In proxy mode the tool is an ordinary app inside Watch's tunnel. Its own connections, to its servers and anywhere else, are attributed to it like any other app's. They are forwarded directly, never back into the proxy, which also prevents loops. Watch never excludes the tool from its tunnel: Android names a connection's owner to a VPN only for the apps that VPN covers.
- **Which app is behind the port.** Watch connects to the proxy port and asks Android who owns the other end of that loopback connection. On 2026-11-08 this gave the listening app's UID on a Samsung phone with Android 11 and on Android 17's emulator, for a port bound to 127.0.0.1, 0.0.0.0 or `::` alike, and nothing for an app outside the tunnel ([spike](spikes/2026-11-packet-engine.md)). A port number alone is only a hint: several tools share 10808, 9050 or 2080.
- **Watch must not become the leak.** When the tool stops, the apps sent through it wait and Watch says so; they never go directly, which would show the network every destination from the user's own address. UDP of a chained app goes through the proxy, once the user allows it, or not at all. Checks that the chain works use the address Android itself checks connectivity with, never a Datapavan host, so the tool's operator learns nothing about the user.
- **The proxy port is a door.** Many tools leave their local proxy open with no password, so any app on the phone, even one kept out of the tunnel, can use it to reach the tool's servers and learn their address. Watch's screen says whether the tool's proxy asked it for a password, and what an open one lets other apps do. It offers a generated password where the tool supports one, opens no unauthenticated port of its own, and never writes SOCKS credentials to its log. A password does not cover UDP: no tool is known to keep other apps off its UDP relay, so the chosen apps' UDP goes through the tool only once the user turns that on, and otherwise goes nowhere ([ADR 0041](decisions/0041-watch-visibility-and-coexistence.md), decision 5).
- **Proxy-like behaviour is flagged** (v0.2) and can be blocked (v0.3): many distinct destinations in a short time, sustained upload, or activity while the screen is off. Thresholds come from measurements, and a flag says what was seen instead of accusing the app. Detection counts destinations in memory, so it does not need the destination log that is off by default for chained flows.
- **Per-app choice.** The user decides which apps go through the tool. Everything else goes directly or is blocked.
- **Proxy mode, step by step.** Onboarding has a guide per popular tool, in every UI language, for running it in proxy mode instead of VPN mode.

## Engineering constraints

- **Battery:** one engine thread, event-driven, no busy loops, batched reads. Target: ≤ 3 % extra battery per day, measured on the Galaxy A40.
- **Memory safety:** if the Rust stack is chosen (ADR 0012), every parser (IP, TCP, UDP, DNS, TLS, QUIC) lives in `datapavan-engine`, where `unsafe` is forbidden, and is fuzzed with `cargo fuzz`. With gVisor, the Go stack handles IP and TCP, and the higher-level parsers (DNS, TLS, QUIC) stay in Rust.
- **Size:** target: the engine adds less than 1 MB per ABI. To be measured in the spike; the M1 bridge alone is about 340 KB on arm64, mostly the Rust standard library.
- **Samsung and other OEM battery managers:** a health check in the app, plus per-vendor onboarding guides.

## The spike

Done in November 2026: three engines measured on emulators and the Galaxy A40, with an idle night on
all of the A40's apps. Findings in [spikes/2026-11-packet-engine.md](spikes/2026-11-packet-engine.md),
the choice in [ADR 0012](decisions/0012-packet-engine.md).

## Licence hygiene

Several existing Android firewalls (NetGuard, TrackerControl) are GPL-licensed. We study their ideas
and publications, but we do not copy their code into this Apache-2.0 project.
