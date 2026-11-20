# Local VPN design (v0.2 network monitoring, v0.3 "Guard", in Datapavan Advanced)

> Status: **design draft.** The packet engine is chosen: the system stack in Rust, accepted on 2026-11-07 ([ADR 0012](decisions/0012-packet-engine.md), [findings](spikes/2026-11-packet-engine.md)). The milestones of the first release, Datapavan Advanced 0.2.0, are in [DESIGN.md §13.2](DESIGN.md#132-v020-datapavan-advanced-the-connection-log-next-to-circumvention-tools).

## What "VPN" means here

Watch, the part of Datapavan planned for v0.2, is a service of Datapavan Advanced, not an app of its own ([ADR 0045](decisions/0045-three-editions-of-one-app.md), in place of [ADR 0029](decisions/0029-network-access-for-v0.2.md)); Datapavan Basic never has it. It uses Android's `VpnService` only to see and filter traffic on the device. It is a
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
   When none applies, the UI says "unknown" plainly. (Amended 2026-11-18, in W5's first part: the connection's own
   server name, TLS or QUIC, now comes first, then the DNS answer, whose name is kept beside it where the two
   differ, then the organisation. A DNS answer is tied to a flow by its address alone, and either name can be
   wrong. [ADR 0044](decisions/0044-udp-mapping-and-budgets.md), decision 4.)
5. **Decision.** The rule engine returns allow, block or log-only.
6. **Forwarding.** Android's own TCP stack, reached through rewritten addresses, terminates each connection locally ([ADR 0012](decisions/0012-packet-engine.md)). The app's SYN is held until the owner lookup and the real, `protect()`-ed connection to the destination are done, then bytes are relayed. UDP leaves through one mapping per app socket, whatever the destination: one protected socket, or for an app chained through the user's tool one SOCKS5 `UDP ASSOCIATE`, each datagram with a header that names its destination. Answers come in only from addresses that app sent to; through the tool, the header of each answer says where it came from (endpoint-independent mapping with address-dependent filtering, [ADR 0044](decisions/0044-udp-mapping-and-budgets.md)). A mapping silent both ways for two minutes ends, and so does one that the chain, set again, sends another way. Each destination is still its own flow in the log, and a new flow's first datagrams wait in it, in order, while its owner is found and its socket opened off the event loop.
7. **Recording.** Per-flow statistics go to app-private, encrypted SQLite (key in the Android Keystore). Retention is the user's choice at onboarding: none, 1 day, 7 days or 30 days, with no default and none kept until the user chooses ([ADR 0040](decisions/0040-own-safety-in-an-untrusted-environment.md)), and a one-tap wipe. Flows chained through a circumvention proxy are counted but their destinations are **not** recorded by default, because a log of them is evidence in a phone search.

## Policies

| Topic | Policy |
|---|---|
| DNS | Our resolver answers inside the tunnel. For apps that go directly the default is Oblivious DoH (RFC 9230): each query is sealed in the engine to a target's key and sent through a relay of another operator, jurisdiction and network, so that neither sees both who asks and what ([ADR 0042](decisions/0042-dns-of-apps-that-go-directly.md), built in W8's part 1). The user can choose a DoH or DoT resolver instead: a preset with its card, or their own. When the first way does not answer, the next in the order of privacy does: ODoH through the user's tool while it is on, DoH to the targets' own operators, the presets that filter nothing; the network's resolver last, only outside the **strict** setting, and Watch's screen says so while it lasts (a notification too, if the user turns it on). In strict a name no encrypted way answers gets "server failure" at once (recommended in restricted regions, where that fallback would hand every query to the censor). Local names (the network's search domains, `home.arpa`, the private reverse zones) go to the network's resolver in either setting. DoH, ODoH's HTTP and DoT run on Android's own TLS from Watch's Kotlin side, from sockets Watch protects and binds to the network beneath; servers are reached at the data pack's addresses, never looked up; queries carry no client subnet and are padded to 128-byte blocks. Port 853 at Watch's DNS address is refused, so Android's opportunistic DNS over TLS asks Watch on port 53; DNS over TCP to Watch goes the same ways. Blocked tracker domains get an empty answer (W8, part 3). Apps chained through a circumvention tool never use the network's resolver: their A and AAAA lookups get stand-ins whose names go to the tool, and their other questions go the encrypted ways through the tool. |
| QUIC | Optional "block QUIC" setting (UDP 443). Apps then fall back to TCP + TLS, where the SNI is visible. Off by default in v0.2, so we observe without interfering. |
| Connectivity and fail mode | Datapavan never breaks connectivity through its own policy decisions. The one deliberate exception is an engine crash under Android's *Always-on VPN* with *Block connections without VPN*: traffic then stops until Android restarts the service, instead of silently bypassing the firewall (fail-closed, see [ADR 0006](decisions/0006-rust-engine-unsafe-forbidden.md)). Onboarding recommends this mode. |
| Private DNS | If Android Private DNS is in strict mode, Android sends every app's lookups encrypted to that provider, past Watch's resolver: Watch's choice of resolver then does not apply, and its screen says so. On "automatic", Android's DNS over TLS to Watch's address is refused and its lookups come to Watch on port 53, which then sends them its encrypted ways; Watch's fallback to the network's resolver goes through Android's own resolver on the network beneath, encrypted where that network's resolver speaks DNS over TLS. Onboarding explains the trade-off (W9). |
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
as its own upstream (0.2.0, W7, [ADR 0035](decisions/0035-wireguard-upstream.md)). Each app has one route:
directly, through the user's tool, or through one WireGuard configuration; several configurations run at
once, and the tool's chain beside them, for different apps. Datapavan does **not** implement circumvention
itself.

Chaining also contains an untrusted tool (see [RESTRICTED-REGIONS.md](RESTRICTED-REGIONS.md)):

- **No inbound path.** SOCKS5 `CONNECT` only carries connections the phone opens, so the phone gets no address in the VPN provider's network. The engine accepts packets only from addresses a local app sent to, UDP replies included, and drops everything else. Through the tool's UDP relay, each answer's SOCKS5 header names where it came from: one from an address the app did not send to is dropped and counted, and a stand-in's name, which the tool resolved, is bound to the first answer from the port the app asked that carries what the app's own datagram asked it to carry, where the protocol carries it: a DNS query's ID and question, a STUN transaction ID, a QUIC connection ID or the Initial keys that derive from it, an NTP request's timestamp ([ADR 0044](decisions/0044-udp-mapping-and-budgets.md), decision 2 and unit 9b). Several stand-ins on one port each take their own answer by it, and an identifier the app also sent another destination there moves no answer away from where that destination answers. A stand-in whose protocol carries none is bound to the first answer from its port, and when it would wait beside another on that port, or carries the same identifier as another, it gets a `UDP ASSOCIATE` of its own, which its datagrams always leave by, since nothing else could tell their answers apart; a stranger who learns where the tool's relay sends from can still answer such a stand-in first, as none of the relays read for this filters by sender. Where a relay labels an answer with a name, as Xray and sing-box do for every answer from the address their first destination resolved to, a label is read as the address it stands for, by the rules an address is read by. What comes under it is the first name's destination on that port while one lives there, and then the stand-in first bound beside it there by its identifier; the first name gets it again once the app sends to it again. An answer that carries another stand-in's identifier goes to that one, waiting or bound beside on its port. For five seconds after a stand-in without identifiers began to wait on the port, the label's answers are dropped, as for an address a stand-in was bound to, since the tool may have resolved that name there too; spared are those that carry an identifier the holder was sent, among them QUIC packets to its client's source ID where that has 4 bytes or more (Chromium's and Cronet's is empty, and their answers are dropped while it lasts). As the address behind a label is unknown, an answer under it that names in the clear what the app sent (a STUN, DNS or NTP identifier) goes to the label's holder if the holder was sent it, else to the one destination that was, or to no one where several were; a QUIC answer, which names what it answers only under keys, goes by its keys among the stand-ins that wait on its port or are bound beside on it, else by the label. A relay elsewhere than on the phone or at the proxy's own address is refused. SOCKS5 `BIND` is never used.
- **The tool's own traffic is visible.** In proxy mode the tool is an ordinary app inside Watch's tunnel. Its own connections, to its servers and anywhere else, are attributed to it like any other app's. They are forwarded directly, never back into the proxy, which also prevents loops. Watch never excludes the tool from its tunnel: Android names a connection's owner to a VPN only for the apps that VPN covers.
- **Which app is behind the port.** Watch connects to the proxy port and asks Android who owns the other end of that loopback connection. On 2026-11-08 this gave the listening app's UID on a Samsung phone with Android 11 and on Android 17's emulator, for a port bound to 127.0.0.1, 0.0.0.0 or `::` alike, and nothing for an app outside the tunnel ([spike](spikes/2026-11-packet-engine.md)). A port number alone is only a hint: several tools share 10808, 9050 or 2080.
- **Watch must not become the leak.** When the tool stops, or a WireGuard server stops answering, the apps sent through it wait and Watch says so; they never go directly, which would show the network every destination from the user's own address. UDP of a chained app goes through the proxy, once the user allows it, or not at all. Checks that the chain works use the address Android itself checks connectivity with, never a Datapavan host, so the tool's operator learns nothing about the user.
- **The proxy port is a door.** Many tools leave their local proxy open with no password, so any app on the phone, even one kept out of the tunnel, can use it to reach the tool's servers and learn their address. Watch's screen says whether the tool's proxy asked it for a password, and what an open one lets other apps do. It offers a generated password where the tool supports one, opens no unauthenticated port of its own, and never writes SOCKS credentials to its log. A password does not cover UDP: no tool is known to keep other apps off its UDP relay, so the chosen apps' UDP goes through the tool only once the user turns that on, and otherwise goes nowhere ([ADR 0041](decisions/0041-watch-visibility-and-coexistence.md), decision 5).
- **Proxy-like behaviour is flagged** (v0.2) and can be blocked (v0.3): many distinct destinations in a short time, sustained upload, or activity while the screen is off. Thresholds come from measurements, and a flag says what was seen instead of accusing the app. Detection counts destinations in memory, so it does not need the destination log that is off by default for chained flows.
- **Per-app choice.** The user decides which apps go through the tool, and which through which WireGuard
  configuration. Everything else goes directly or is blocked.
- **WireGuard upstreams** (W7, ADR 0035). A chosen app's own IP packets go into the WireGuard session with the
  configuration's address as their source, their checksums updated, so its TCP runs end to end with the
  server; no second TCP stack, no upstream socket of Watch's for it. Back from the tunnel a packet passes only
  from inside the peer's `AllowedIPs`, to the configuration's address, on a flow a local app started; anything
  else is dropped and counted, so a tunnel opens no inbound path either. ICMP errors are passed on with their
  quote swapped back. The chosen app's lookups to Watch's DNS address go to the configuration's DNS server
  through the tunnel; its names never reach the network's resolver. A destination the tunnel cannot carry,
  outside a narrower `AllowedIPs`, or IPv6 when the configuration has no IPv6 address, is refused at once;
  "Local network directly", per configuration and off by default, lets the chosen apps reach a printer or a
  NAS. Flows Android names no app for, and every app's ping, go through the default configuration, the one the
  user chose, while any app goes through one; Watch's screen says so whenever a configuration exists, and while the
  default cannot be opened they are refused, never sent through another configuration. While a tunnel's server does not answer, or its configuration is not set, its apps wait and
  Watch says so; they never go directly. On a network switch the tunnel's own protected socket is made anew and
  the server told at once, so the chosen apps' connections go on. A server given by name is looked up by
  Watch's own encrypted resolver (ODoH by default, W8's part 1); only outside the strict setting, when no
  encrypted way answers, does the network's resolver, and then Watch says the network could learn which provider
  the user chose. The tunnel keeps the TUN's MTU: a tunnelled SYN's MSS is clamped to the
  configuration's MTU, and a larger packet gets "fragmentation needed" or "packet too big", as from a router.
  Their destinations are logged only under "Log where these apps connect", as chained apps' are.
- **The way in** (W7, part 2, ADR 0035). A configuration comes from a file (Android's documents screen, no storage
  permission) or a QR code: a photo the phone's own camera takes for Watch, which never holds `CAMERA`, or a
  picture picked in the photo picker, read with ZXing's core in an isolated process with no permissions. Before
  anything is saved, Watch shows what it does and never a key: the server, the addresses, the DNS server, whether
  only some destinations go through it, whether it has a preshared key; the apps it names become a proposed choice
  to confirm, never applied silently. Watch keeps at most eight, each wrapped with AES-256-GCM under an Android
  Keystore key, in StrongBox where the phone has one; the text is opened only to be handed to the engine, and
  zeroed. Each app's way, directly, through the tool or through one configuration, is set in one place on Watch's
  screen; removing a configuration asks whether its apps wait or go their other way, never directly unasked.
- **Proxy mode, step by step.** Onboarding has a guide per popular tool, in every UI language, for running it in proxy mode instead of VPN mode.

## Engineering constraints

- **Battery:** one engine thread, event-driven, no busy loops, batched reads. Target: ≤ 3 % extra battery per day, measured on the Galaxy A40.
- **Memory safety:** if the Rust stack is chosen (ADR 0012), every parser (IP, TCP, UDP, DNS, TLS, QUIC) lives in `datapavan-engine`, where `unsafe` is forbidden, and is fuzzed with `cargo fuzz`. With gVisor, the Go stack handles IP and TCP, and the higher-level parsers (DNS, TLS, QUIC) stay in Rust.
- **Size:** Watch's native library, stripped as Advanced's release APK ships it, stays within 2 MB per ABI, held by a gate in `scripts/check.sh android` (the maintainer, 2026-11-19, after W7's spike: [ADR 0035](decisions/0035-wireguard-upstream.md), question 3). The earlier target, less than 1 MB, was set before the engine was built; nothing held it, and the library grew to 1.38 MB on arm64 (1.22 on armv7, 1.59 on x86_64) before WireGuard. WireGuard's core adds about 0.13 to 0.21 MB.
- **Samsung and other OEM battery managers:** a health check in the app, plus per-vendor onboarding guides.
- **Interoperation:** Watch's WireGuard is checked through its own engine against both reference implementations,
  the Linux kernel's WireGuard and wireguard-go, never against its own core alone: `scripts/check.sh wglab` and the
  emulator's `wireguard` shard, on CI where the WireGuard code or its checks change and every week, the weekly run
  with a rekey, keepalives and a cookie reply under load; on CI a check that cannot find its peer fails
  ([ADR 0035](decisions/0035-wireguard-upstream.md), "How it is built (W7, part 3a)").

## The spike

Done in November 2026: three engines measured on emulators and the Galaxy A40, with an idle night on
all of the A40's apps. Findings in [spikes/2026-11-packet-engine.md](spikes/2026-11-packet-engine.md),
the choice in [ADR 0012](decisions/0012-packet-engine.md).

## Licence hygiene

Several existing Android firewalls (NetGuard, TrackerControl) are GPL-licensed. We study their ideas
and publications, but we do not copy their code into this Apache-2.0 project.
