# Local VPN design (v0.2 and v0.3 "Guard", in Datapavan Advanced)

> Status: **design draft.** The packet engine is chosen: the system stack in Rust, accepted on 2026-11-07 ([ADR 0012](decisions/0012-packet-engine.md), [findings](spikes/2026-11-packet-engine.md)). The milestones of the first release, Datapavan Advanced 0.2.0, are in [DESIGN.md §13.2](DESIGN.md#132-v020-datapavan-advanced-the-connection-log-next-to-circumvention-tools).

## What "VPN" means here

The local VPN, planned for v0.2, is the network part of Datapavan Advanced ([ADR 0045](decisions/0045-three-editions-of-one-app.md)); Datapavan Basic never has it. It uses Android's `VpnService` only to see and filter traffic on the device. It is a
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

1. **Tunnel.** `VpnService.Builder` creates a TUN interface. Routes cover all of IPv4 and IPv6, and DNS points to a virtual address inside the tunnel. Datapavan Advanced itself is inside its own tunnel and calls `protect()` on each upstream socket: the system stack needs this, because Android routes the answers of the engine's listener back through the tunnel only for apps inside it ([spike](spikes/2026-11-packet-engine.md), finding 6).
2. **Hand-off.** The TUN file descriptor is passed to the Rust engine over JNI. From then on Kotlin only controls the lifecycle; all packet handling is in Rust.
3. **Which app?** For every new TCP or UDP flow, the engine asks `ConnectivityManager.getConnectionOwnerUid()` (Android 10+, available only to the active VPN app). That is a Java API, so the engine makes one JNI upcall per new flow; the answer is cached for the lifetime of the flow.
4. **Which destination?** In order of preference:
   1. the server name the connection itself sent: the TLS ClientHello SNI, or the QUIC Initial's;
   2. for a flow through a proxy the app set itself, SOCKS or HTTP, the destination the app asked the proxy for,
      read from its first bytes ([ADR 0052](decisions/0052-apps-built-in-proxies.md));
   3. the DNS answers we served (IP → hostname cache), whose name is kept beside the connection's own where the two
      differ; for a flow through an app's own proxy it names the proxy;
   4. an offline IP → ASN/organisation database.
   When none applies, the UI says "unknown" plainly. A DNS answer is tied to a flow by its address alone, and either
   name can be wrong ([ADR 0044](decisions/0044-udp-mapping-and-budgets.md), decision 4).
5. **Decision.** The rule engine returns allow, block or log-only.
6. **Forwarding.** Android's own TCP stack, reached through rewritten addresses, terminates each connection locally ([ADR 0012](decisions/0012-packet-engine.md)). The app's SYN is held until the owner lookup and the real, `protect()`-ed connection to the destination are done, then bytes are relayed. UDP leaves through one mapping per app socket, whatever the destination: one protected socket, or for an app chained through the user's tool one SOCKS5 `UDP ASSOCIATE`, each datagram with a header that names its destination. Answers come in only from addresses that app sent to; through the tool, the header of each answer says where it came from (endpoint-independent mapping with address-dependent filtering, [ADR 0044](decisions/0044-udp-mapping-and-budgets.md)). A mapping silent both ways for two minutes ends, and so does one that the chain, set again, sends another way. Each destination is still its own flow in the log, and a new flow's first datagrams wait in it, in order, while its owner is found and its socket opened off the event loop.
7. **Recording.** Per-flow statistics go to app-private, encrypted SQLite (key in the Android Keystore). Retention is the user's choice at onboarding: none, 1 day, 7 days or 30 days, with no default and none kept until the user chooses ([ADR 0040](decisions/0040-own-safety-in-an-untrusted-environment.md)), and a one-tap wipe. Flows chained through a circumvention proxy are counted but their destinations are **not** recorded by default, because a log of them is evidence in a phone search.

## Policies

| Topic | Policy |
|---|---|
| DNS | Our resolver answers inside the tunnel. For apps that go directly the default is Oblivious DoH (RFC 9230): each query is sealed in the engine to a target's key and sent through a relay of another operator, jurisdiction and network, so that neither sees both who asks and what ([ADR 0042](decisions/0042-dns-of-apps-that-go-directly.md), built in W8's part 1). The user can choose a DoH or DoT resolver instead: a preset with its card, or their own. When the first way does not answer, the next in the order of privacy does: ODoH through the user's tool while it is on, DoH to the targets' own operators, the presets that filter nothing; the network's resolver last, only outside the **strict** setting, and the network screen says so while it lasts (a notification too, if the user turns it on). In strict a name no encrypted way answers gets "server failure" at once (recommended in restricted regions, where that fallback would hand every query to the censor). Local names (`home.arpa`, the private reverse zones, single labels) go to the network's resolver in either setting; a name under the network's own search domain goes there only when the encrypted way says the internet does not know it, and a search domain that is a public suffix is ignored. With the user's own resolver chosen, ODoH comes next when it fails, unless the user chose "only this resolver". DoH, ODoH's HTTP and DoT run on Android's own TLS from the network part's Kotlin side, from sockets it protects and binds to the network beneath; servers are reached at the data pack's addresses, never looked up; directly first, and only when they cannot be reached directly, by address, through the network's own proxy, or where the network has none, through a proxy set for the whole phone, and that one only once direct connections to two servers failed at the connection itself with none made since, so that its operator learns of the resolver only where the network lets nothing through directly; never through a PAC file or a proxy on the phone itself ([ADR 0042](decisions/0042-dns-of-apps-that-go-directly.md), "Android's proxy"); queries carry no client subnet and are padded to 128-byte blocks. Port 853 at Datapavan's DNS address is refused, so Android's opportunistic DNS over TLS asks Datapavan on port 53; DNS over TCP to Datapavan goes the same ways. Tracker blocking (W8, part 3a, [ADR 0053](decisions/0053-tracker-blocking.md), off until the user turns it on) decides first, before the cache, for every record type: a name a row of Datapavan's graded table blocks for the app gets "no data" with an SOA kept for no time, and asks no one; every answer for a name a row may block reaches every app with a time to live of 0, since Android keeps one cache per network for all apps; each name of a CNAME chain is matched. Apps chained through a circumvention tool never use the network's resolver: their A and AAAA lookups get stand-ins whose names go to the tool, and their other questions go the encrypted ways through the tool. |
| QUIC | Optional "block QUIC" setting (UDP 443). Apps then fall back to TCP + TLS, where the SNI is visible. Off by default in v0.2, so we observe without interfering. |
| Connectivity and fail mode | Datapavan never breaks connectivity through its own policy decisions. The one deliberate exception is an engine crash under Android's *Always-on VPN* with *Block connections without VPN*: traffic then stops until Android restarts the service, instead of silently bypassing the firewall (fail-closed, see [ADR 0006](decisions/0006-rust-engine-unsafe-forbidden.md)). Onboarding recommends this mode. |
| Private DNS | If Android Private DNS is in strict mode, Android sends every app's lookups encrypted to that provider, past Datapavan's resolver: Datapavan's choice of resolver then does not apply, and the network screen says so. On "automatic", Android's DNS over TLS to Datapavan's address is refused and its lookups come to Datapavan on port 53, which then sends them its encrypted ways; Datapavan's fallback to the network's resolver goes through Android's own resolver on the network beneath, encrypted where that network's resolver speaks DNS over TLS. Onboarding explains the trade-off (W9). |
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
tools. Datapavan Advanced therefore supports **chaining**: its upstream sockets can go through a local SOCKS5
proxy offered by another app in its proxy-only mode (for example v2rayNG, NekoBox, Hiddify or Orbot).
The user keeps both their circumvention tool and Datapavan Advanced. Some tools have no proxy mode and run only as
a VPN: WireGuard's own app, Outline, Psiphon and Lantern's released app. For providers that hand out
a WireGuard configuration (Proton VPN, also on its free plan, Mullvad and others), Advanced carries it
as its own upstream (0.2.0, W7, [ADR 0035](decisions/0035-wireguard-upstream.md)). Each app has one route:
directly, through the user's tool, or through one WireGuard configuration; several configurations run at
once, and the tool's chain beside them, for different apps. Datapavan does **not** implement circumvention
itself.

Chaining also contains an untrusted tool (see [RESTRICTED-REGIONS.md](RESTRICTED-REGIONS.md)):

- **No inbound path.** SOCKS5 `CONNECT` only carries connections the phone opens, so the phone gets no address in the VPN provider's network. The engine accepts packets only from addresses a local app sent to, UDP replies included, and drops everything else. Through the tool's UDP relay, each answer's SOCKS5 header names where it came from: one from an address the app did not send to is dropped and counted, and a stand-in's name, which the tool resolved, is bound to the first answer from the port the app asked that carries what the app's own datagram asked it to carry, where the protocol carries it: a DNS query's ID and question, a STUN transaction ID, a QUIC connection ID or the Initial keys that derive from it, an NTP request's timestamp ([ADR 0044](decisions/0044-udp-mapping-and-budgets.md), decision 2 and unit 9b). Several stand-ins on one port each take their own answer by it, and an identifier the app also sent another destination there moves no answer away from where that destination answers. A stand-in whose protocol carries none is bound to the first answer from its port, and when it would wait beside another on that port, or carries the same identifier as another, it gets a `UDP ASSOCIATE` of its own, which its datagrams always leave by, since nothing else could tell their answers apart; a stranger who learns where the tool's relay sends from can still answer such a stand-in first, as none of the relays read for this filters by sender. Where a relay labels an answer with a name, as Xray and sing-box do for every answer from the address their first destination resolved to, a label is read as the address it stands for, by the rules an address is read by. What comes under it is the first name's destination on that port while one lives there, and then the stand-in first bound beside it there by its identifier; the first name gets it again once the app sends to it again. An answer that carries another stand-in's identifier goes to that one, waiting or bound beside on its port. For five seconds after a stand-in without identifiers began to wait on the port, the label's answers are dropped, as for an address a stand-in was bound to, since the tool may have resolved that name there too; spared are those that carry an identifier the holder was sent, among them QUIC packets to its client's source ID where that has 4 bytes or more (Chromium's and Cronet's is empty, and their answers are dropped while it lasts). As the address behind a label is unknown, an answer under it that names in the clear what the app sent (a STUN, DNS or NTP identifier) goes to the label's holder if the holder was sent it, else to the one destination that was, or to no one where several were; a QUIC answer, which names what it answers only under keys, goes by its keys among the stand-ins that wait on its port or are bound beside on it, else by the label. A relay elsewhere than on the phone or at the proxy's own address is refused. SOCKS5 `BIND` is never used.
- **The tool's own traffic is visible.** In proxy mode the tool is an ordinary app inside Advanced's tunnel. Its own connections, to its servers and anywhere else, are attributed to it like any other app's. Any tool's own connections show in "Now" in full while each is open and for ten minutes after it ends, and are logged with their addresses only with "Log where apps connect through your tool, WireGuard or a proxy" on, or once you choose to log that tool's own connections (ADR 0046, decision 3). For the tool you chain through, what it sends directly for the chained apps by its own rules shows under its row too; under that choice, the connections Advanced ties to what it asked the tool for in the ten seconds before are not logged, and those it cannot tie are logged as the tool's own. They are forwarded directly, never back into the proxy, which also prevents loops. Advanced never excludes the tool from its tunnel: Android names a connection's owner to a VPN only for the apps that VPN covers.
- **Which app is behind the port.** Advanced connects to the proxy port and asks Android who owns the other end of that loopback connection. On 2026-11-08 this gave the listening app's UID on a Samsung phone with Android 11 and on Android 17's emulator, for a port bound to 127.0.0.1, 0.0.0.0 or `::` alike, and nothing for an app outside the tunnel ([spike](spikes/2026-11-packet-engine.md)). A port number alone is only a hint: several tools share 10808, 9050 or 2080.
- **Advanced must not become the leak.** When the tool stops, or a WireGuard server stops answering, the apps sent through it wait and Datapavan says so; they never go directly, which would show the network every destination from the user's own address. UDP of a chained app goes through the proxy, once the user allows it, or not at all. Checks that the chain works use the address Android itself checks connectivity with, never a Datapavan host, so the tool's operator learns nothing about the user.
- **The proxy port is a door.** Many tools leave their local proxy open with no password, so any app on the phone, even one kept out of the tunnel, can use it to reach the tool's servers and learn their address. The network screen says whether the tool's proxy asked it for a password, and what an open one lets other apps do. It offers a generated password where the tool supports one, opens no unauthenticated port of its own, and never writes SOCKS credentials to its log. A password does not cover UDP: no tool is known to keep other apps off its UDP relay, so the chosen apps' UDP goes through the tool only once the user turns that on, and otherwise goes nowhere ([ADR 0041](decisions/0041-visibility-and-coexistence.md), decision 5).
- **Apps' own proxies are named** (W8, part 2a, [ADR 0052](decisions/0052-apps-built-in-proxies.md)). A SOCKS5, SOCKS4
  or HTTP proxy an app set itself is read from the connection's first bytes: the flow is named by the destination the
  app asked for, once the proxy's reply confirmed the handshake, the proxy's place beside it ("an address in the
  network of X; who runs it is not known", or "on your local network"), with whether it is Android's proxy setting,
  shared by the apps that follow it, and whether a password crossed unencrypted; the password itself is never kept,
  and the bytes it passed through in the relay are zeroed. A request the server does not confirm names nothing, and a
  plain request in absolute form, which origin servers take too, keeps its flow's own address and names. Telegram's
  MTProto, WhatsApp's and Signal's proxies are inferred from where and how the app connects, each only while the app
  reaches its maker's own network by no TCP connection (substitution, on the time since the phone started), and a
  direct connection within ten minutes takes a name back whole, in the log too; a hello counts as a fake-TLS cover
  only where no answer Datapavan holds gave its name the address, the app did not look the name up through Datapavan,
  and Datapavan sees the app's lookups at all (Private DNS not strict), and a cover never names the flow. Signal's fronting
  counts as going directly, and what its web view opens after a payment's host is not its proxy. The tool's own flows
  and the apps chained or tunnelled through it are not read: they carry the tool's traffic. An app's own proxy's first
  hop (its address, name and network, and a messenger's cover name) is shown in "Now" while the connection is open and
  for ten minutes after it ends, whatever the switch (ADR 0052, decision 8). It is logged, with the destination asked
  for, only under the one switch "Log where apps connect through your tool, WireGuard or a proxy", or for an app the
  user chose on its row or its page, "Log where APP connects through a proxy" (the proxy record's unit C, R3), which
  the engine decides per flow and does not apply to a flow it reads as through Android's setting or a local proxy, nor
  to a tool's or Android's PAC proxy (a PAC file's proxies, and the setting given by name, can escape that reading:
  ADR 0052's limits for the choice);
  otherwise the log keeps its kind, the facts that name nothing and its trackers' marks, matched on its names before
  they were left out, and the destination is not shown either. The choice is kept by package and first install time,
  never by UID, so a reinstall or a package that joins the app's UID ends it. The switch is on the network screen wherever a row points to it. Proxies inside
  TLS or QUIC, and those on the phone itself, whose loopback never enters the tunnel, are not seen, but for Android's
  PAC proxy, whose connections for other apps, left-out apps included, come into the tunnel under its own name and
  say so.
- **The facts of an app's own proxy** (the proxy record's unit B, ADR 0052 decisions 4 and 9), kept whatever the switch:
  whether it is Android's own setting, matched by its address or a name Android's resolver gave it and never by an
  app's own resolver's answer; whether it is on the user's own network, decided once by the network beneath's on-link
  prefixes and kept in the log's version 7; and, on a messenger's record the engine took back or never named for
  substitution, that Datapavan could not tell. A plain request to Android's setting is left out of the record as a
  confirmed proxy's, and shown in "Now" for its window. A circumvention tool's own proxy rows say so, the tool known by
  its signing key, never its package name. "Now" says which of Android's own proxy settings is set, the whole phone's
  first.
- **An app's own SOCKS5 relay** (the proxy record's unit U, ADR 0052): once an app's own SOCKS5 server confirms its
  `UDP ASSOCIATE`, and while that control connection is open, the app's UDP that goes directly to that same server at
  the port its reply names, or comes in from that server, is the app's own proxy's, with its first hop: shown in "Now"
  for its window, and logged under the switch alone, as for its TCP. The tie is at the server whose own bytes
  confirmed, never at an address the reply names: a reply naming another address ties nothing there, and that address
  stays in the log, as before. On a flow the app began, the first datagram's SOCKS5 header gives the trackers' marks
  and, with the switch on, where the app asked to go; a fragment or a header that does not parse gives none, later
  datagrams on the flow are not read, and no hello names the flow, only marks it. At most 16 associations for each
  app and 256 in all are tied at once; an association ends with its connection, and none crosses a restart of the
  tunnel.
- **Proxy-like behaviour is flagged** (v0.2) and can be blocked (v0.3): many distinct destinations in a short time, sustained upload, or activity while the screen is off. Thresholds come from measurements, and a flag says what was seen instead of accusing the app. Detection counts destinations in memory, so it does not need the destination log that is off by default for chained flows.
- **Per-app choice.** The user decides which apps go through the tool, and which through which WireGuard
  configuration. Everything else goes directly or is blocked.
- **WireGuard upstreams** (W7, ADR 0035). A chosen app's own IP packets go into the WireGuard session with the
  configuration's address as their source, their checksums updated, so its TCP runs end to end with the
  server; no second TCP stack, no upstream socket of Advanced's for it. Back from the tunnel a packet passes only
  from inside the peer's `AllowedIPs`, to the configuration's address, on a flow a local app started; anything
  else is dropped and counted, so a tunnel opens no inbound path either. ICMP errors are passed on with their
  quote swapped back. The chosen app's lookups to Datapavan's DNS address go to the configuration's DNS server
  through the tunnel; its names never reach the network's resolver. A destination the tunnel cannot carry,
  outside a narrower `AllowedIPs`, or IPv6 when the configuration has no IPv6 address, is refused at once;
  "Local network directly", per configuration and off by default, lets the chosen apps reach a printer or a
  NAS. Flows Android names no app for, and every app's ping, go through the default configuration, the one the
  user chose, while any app goes through one; the network screen says so whenever a configuration exists, and while the
  default cannot be opened they are refused, never sent through another configuration. While a tunnel's server does not answer, or its configuration is not set, its apps wait and
  Datapavan says so; they never go directly. On a network switch the tunnel's own protected socket is made anew and
  the server told at once, so the chosen apps' connections go on. A server given by name is looked up by
  Datapavan's own encrypted resolver (ODoH by default, W8's part 1); only outside the strict setting, when no
  encrypted way answers, does the network's resolver, and then Datapavan says the network could learn which provider
  the user chose. The tunnel keeps the TUN's MTU: a tunnelled SYN's MSS is clamped to the
  configuration's MTU, and a larger packet gets "fragmentation needed" or "packet too big", as from a router.
  Their destinations are logged only under "Log where these apps connect", as chained apps' are.
- **The way in** (W7, part 2, ADR 0035). A configuration comes from a file (Android's documents screen, no storage
  permission) or a QR code: a photo the phone's own camera takes for Advanced, which never holds `CAMERA`, or a
  picture picked in the photo picker, read with ZXing's core in an isolated process with no permissions. Before
  anything is saved, Datapavan shows what it does and never a key: the server, the addresses, the DNS server, whether
  only some destinations go through it, whether it has a preshared key; the apps it names become a proposed choice
  to confirm, never applied silently. Advanced keeps at most eight, each wrapped with AES-256-GCM under an Android
  Keystore key, in StrongBox where the phone has one; the text is opened only to be handed to the engine, and
  zeroed. Each app's way, directly, through the tool or through one configuration, is set in one place on the network
  screen; removing a configuration asks whether its apps wait or go their other way, never directly unasked.
- **Tracker blocking** (W8, part 3a, [ADR 0053](decisions/0053-tracker-blocking.md)), off until the user turns it on.
  Only hosts of Datapavan's own graded table (`data/blocking`) are blocked, each graded by what it does (only
  tracking: blocked; also the app's own sign-in, storage or push: kept; both, as `graph.facebook.com`: decided by the
  app's own code), the same in every app, the tracker's own company's included. A blocked lookup gets "no data"; a
  connection's first bytes are held while they read as an unfinished TLS or QUIC hello or HTTP request head, and a
  blocked one is reset (QUIC: "port unreachable") before any byte of its payload leaves, to the server or the user's
  tool; an address is blocked by itself only when an answer Datapavan passed tied it to blocked names alone, outside any
  CDN or cloud. Browsers are left out unless the user includes them; preinstalled apps, Android itself and Play
  services are not covered; the user's tool's connections are never blocked, its own tracker lookups only by an
  option. One tap in "Now" allows an app's trackers for an hour, one tap blocks them again, and a ten-minute pause
  lifts every block; it works within seconds, since apps keep a failed lookup for a moment.
- **Proxy mode, step by step** (W8, part 3b; [ADR 0041](decisions/0041-visibility-and-coexistence.md), "How the
  per-tool guides are built"). Every tool of the table has a page (`data/tools/guides.tsv`): the steps to run it in its
  proxy mode, read from its source at a release tag with a line of code for every step and label; or, for a tool that
  runs only as a VPN, that Advanced cannot run beside it, with W7's import where its provider issues WireGuard files; or
  that its steps wait until it is tried with Advanced, where its code is closed or its source does not settle them. A page says
  where the switch is, the listener and its port, whether a password can be set, what the tool asks for, what Datapavan
  does next and how to go back. Where the tool's profile sets its listener (Clash Meta for Android, sing-box), the page
  has the user set a port it names, 7890 and 2080, and Advanced's finder greets that port: no port is typed into Datapavan.
  The tool's labels are quoted from the installed tool itself, by their resource names, in its language, the phone's
  or Datapavan's; a label it keeps elsewhere is the data's. Android hides a VPN's owner, so the chain section links the
  guide of every installed tool of the table; the website has the same text under `docs/site/guides/`, and onboarding
  (W9) links them. They never link to a download and never recommend a tool. The order follows the maintainer's tool
  usage matrix, then the table; tools other than the four tried on 2026-11-11 wait for a device check.

## Engineering constraints

- **Battery:** one engine thread, event-driven, no busy loops, batched reads. Target: ≤ 3 % extra battery per day, measured on the Galaxy A40.
- **Memory safety:** with the Rust stack of ADR 0012, every parser (IP, TCP, UDP, DNS, TLS, QUIC) lives in the packet engine's crate, `datapavan-net`, where `unsafe` is forbidden, and is fuzzed with `cargo fuzz`.
- **Size:** the network part's native library (`libdatapavan_network.so`), stripped as Advanced's release APK ships it, stays within 2 MB per ABI, held by a gate in `scripts/check.sh android` (the maintainer, 2026-11-19, after W7's spike: [ADR 0035](decisions/0035-wireguard-upstream.md), question 3). Before WireGuard the library was 1.38 MB on arm64 (1.22 on armv7, 1.59 on x86_64); WireGuard's core adds about 0.13 to 0.21 MB.
- **Samsung and other OEM battery managers:** a health check in the app, plus per-vendor onboarding guides.
- **Interoperation:** Advanced's WireGuard is checked through its own engine against both reference implementations,
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
