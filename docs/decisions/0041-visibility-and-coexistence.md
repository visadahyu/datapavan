# 0041. What other apps see of Datapavan Advanced, and working beside every app

- Status: Accepted (by the maintainer on 2026-11-12)
- Date: 2026-11-12
- See also: [ADR 0048](0048-lab-probe-of-android-gaps.md), which builds decision 2's probe app and runs it;
  [ADR 0054](0054-android-labels-read-from-the-phone.md), which reads Android's own labels the way point 6 of "How the
  per-tool guides are built" reads a tool's, from the shared module.

## Context

Advanced's network part is a local VPN. It changes no address and sends nothing to a server of its own, but Android
tells every app that a VPN runs. Any app can see this:
- `TRANSPORT_VPN` on its network, under a normal permission;
- the tunnel's interface in the list of interfaces;
- the tunnel's addresses.

Apps may report this to their servers, and some refuse to run while a VPN is on, banking and state-linked apps among
them. For a user who runs Advanced's VPN without any circumvention tool, the VPN itself becomes the signal. That is at
odds with the first principle of [RESTRICTED-REGIONS.md](../RESTRICTED-REGIONS.md#principles): "No feature that could
identify a user to authorities."

Advanced also chains apps through the user's circumvention tool (W6, ADR 0038). In proxy mode the tool listens on
the phone's loopback, where any app can find its port. Through a tool that takes no password, any app can send
traffic. Even with a password, some tools' UDP relays accept datagrams from any app.

And the tunnel carries every app's traffic. When an app fails inside it and cannot be left out, the user's only
way out is to turn the tunnel off.

## Decision

1. **Say it plainly.** Advanced's onboarding and its network screen say that other apps can see that a VPN runs,
   that some report it, and that some refuse to work while it is on. They say what Datapavan does about it, and what
   it cannot do.
2. **Leave an app out.** From 0.2.0 the user can leave any app out of the tunnel. Advanced says honestly what this
   hides and what it does not: the app's own network is then not a VPN, but the tunnel's interface may still
   show in the list of interfaces. The lab measures what an excluded app sees, with a probe app of the project's
   own, run on the maintainer's machine on the Android versions of ADR 0048; CI builds and unit-tests the probe.
3. **Addresses that do not single Advanced out.** The tunnel uses addresses common to many VPN apps, not fixed
   values of Datapavan's own.
4. **The local network on Android 17, by each app's own grant.** Advanced forwards an app's traffic to the local
   network only if that UID holds the local-network permission itself, and records refusals. This holds for apps
   it cannot name too, whose UID is checked the same way. It is the requirement ADR 0034 puts on the engine.
5. **Tools without a password, and open UDP relays.** Advanced chains through a tool whose proxy takes no
   password, and says that any app on the phone can use that port; it gives the steps to set a password in that
   tool. Where a tool's UDP relay accepts datagrams from other apps, Advanced chains TCP only by default and says
   why. The lasting fix is in the tools: the project asks their makers to require the password on the relay too.
6. **A compatibility matrix kept current.** It is published and maintained continuously, not as a one-off list:
   - **Automated runs:** a set of devices runs the apps, inside the tunnel, outside it, chained, and with
     blocking.
   - **Reports from users:** a user can report an app that fails in Advanced's tunnel, and the report carries no
     personal data.
   - **Which apps:** they are chosen by public reach in each region, banks, payment, government, messaging and
     transport first.
   - **Inside Advanced:** when an app fails in the tunnel, Advanced offers to leave it out.
7. **The lab tests apps that refuse a VPN.** Named apps are tested on real phones one by one, each test agreed
   first, and the results are published with evidence (ADR 0015).

### How decision 3 is built (2026-11-12)

**The principle: an open project, a quiet phone.** The maintainer asked whether a security tool should hide itself or be
plainly seen. The project is open about what it is: its code, its name, its signing key, and what it tells its own user;
Android also always shows that the VPN is Datapavan Advanced's. What the phone does not do is tell every other app,
unasked, which tool its user chose. The tunnel's address is such a message: any app reads it without a permission, and
an address of Datapavan's own would mark its user as a Datapavan Advanced user, and through the chain a likely user of a
circumvention tool. So Advanced takes addresses that other apps of its own kind use. It does not take the addresses of a
different kind of app: it does not pass itself off as something it is not.

**The addresses.** The tunnel addresses of 32 apps were read from their own source at a tag or commit. Three
groups share them:
- 172.19.0.1 and fdfe:dcba:9876::1 belong to proxy and circumvention clients: Shadowsocks, NekoBox, Exclave,
  Clash Meta, Hiddify and others, with a /30 or /28 that Android 17 would count as local network.
- 10.1.10.1/32 and fd00:1:fd00:1:fd00:1:fd00:1/128 belong to privacy firewalls: NetGuard, TrackerControl and
  InviZible Pro.
- 10.111.222.1/24 belongs to Intra, Outline and RethinkDNS.

Advanced takes the firewalls' pair. It has exactly the /32 and /128 that the network part needs, and an app that
reads it finds a local firewall, which Advanced is. The engine and the service hold the same two sets (`Addresses`
in core/net/src/engine.rs, `TunnelAddresses` in the network part), and a unit test fails if they drift apart.

**A network that uses them itself.** Comcast Business gateways answer at 10.1.10.1, and a tunnel that took the
router's address would cut the phone off from its router and resolver. Before it sets up the tunnel, the network
part reads every network beneath it: their addresses with their prefixes, their gateways and their DNS servers. If
one of them uses an address of the common set, the network part takes a rarer set of its own (10.215.173.1 and
fd7a:6470:7761::1, shared only with PCAPdroid's IPv4 address). When a network changes to clash, or stops
clashing, the network part sets the tunnel up again with the other set.

**What still differs.** The tunnel's DNS server (10.1.10.3) and its MTU (1500, where NetGuard uses 10000) are
Datapavan's own. An app that can list installed packages can still see that Advanced is installed. Hiding that a VPN
runs is not possible on stock Android. The probe app of decision 2 is to measure what an app outside the tunnel still
sees. This decision narrows what the address alone says; it does not make Advanced invisible.

### How decision 5 is built (2026-11-12)

**What the network part already knows.** It finds the user's tool with a SOCKS5 greeting that offers no password (ADR
0038). The proxy's answer says whether it wants one. The table of tools says whether the tool can take a password
at all, and whether it carries UDP.

**A proxy that asks no password.** Advanced still chains through it, since refusing would leave the user without the
network part. The network screen says, in the error colour, that any app on the phone can use the proxy, learn that the
user runs this tool and the address of its server, and send its own traffic through it. For a tool that has no password
setting, Advanced says so, and that the proxy stays open while the tool runs in proxy mode. For a tool that takes one,
Advanced shows the user name and password it made, and where tools keep that setting: the settings of their local proxy,
often named inbound, SOCKS or local port. Steps for each tool, with evidence, belong in the table of tools.

**A proxy that asks a password.** Advanced says that other apps cannot use it, and that they can still see that it is
there: any SOCKS5 server answers a greeting.

**UDP: TCP only by default.** No tool is known to tie its UDP relay to the app that opened it, and stock Android has no
loopback firewall by app. While a relay carries the network part's datagrams, other apps on the phone may send through
it too, even where the tool's proxy asks a password. A 2026 test found that the UDP of some Xray and sing-box clients
works with no password at all ([Habr](https://habr.com/en/articles/1020080)). So for every tool, the chosen apps' UDP
goes through the tool only once the user turns that on, under a switch that says why it is off and what is lost: calls
and some games in the chained apps. Web pages still load: names go through the tool over TCP (ADR 0038), and browsers
fall back from QUIC to TCP. Off, a chained app's UDP goes nowhere, never directly. For a tool that carries no UDP, the
screen keeps saying so, with no switch.

**Not yet.** Which tools' relays take datagrams from other apps, or with no password, is lab work: a check per
tool, recorded in the table of tools with its evidence. A tool whose relay is shown to refuse other apps can then
default to UDP on. The network part does not probe the relay itself: a probe from it cannot tell a relay that refuses
another app from one that refuses the probe's destination.
### How the per-tool guides are built (2026-11-21)

W8, part 3b: the guides that decision 5's "steps for each tool" and VPN.md's "Proxy mode, step by step" ask for. The
decisions are the coordinator's (BRIEF-part-3b, after one audit of the first brief), with their reasons.

1. **Every tool of the table has a page.** Each package of `data/tools/tools.tsv` with a VPN or proxy mode is on one
   of 49 pages (`data/tools/guides.tsv`), and no other package is:
   - **21 with steps,** for tools whose proxy mode the source settles;
   - **4 for WireGuard:** Proton VPN, Mullvad and Windscribe run only as a VPN, and their websites issue WireGuard
     files, which Advanced carries itself (W7). WireGuard's own app joins them, although the brief named providers only:
     the file or QR code the user gave it is a standard configuration. AmneziaWG and Amnezia VPN do not, since
     AmneziaWG is not WireGuard's protocol ([ADR 0035](0035-wireguard-upstream.md), point 14);
   - **10 for tools that run only as a VPN.** They hold Android's one VPN slot, so Advanced's tunnel cannot run beside
     them; the page says so, and that Datapavan's check of the apps works without the tunnel;
   - **14 waiting:** the tools whose values end in `?`, and those whose code is closed or partly closed, which their
     source cannot settle: MahsaNG, V2Box, Npv Tunnel, NetMod, Karing, v2RayTun, Psiphon's Google Play build, Happ,
     Defyx, HTTP Injector, 1.1.1.1 + WARP, AM TUNNEL LITE, OpenVPN Connect and Surfboard. NetMod names a Proxy
     Tethering: its page says that whether it gives a proxy Advanced can use is not known yet, never that it has none.
2. **The order.** Among the tools with a proxy mode, the maintainer's private tool usage matrix (global, read
   2026-11-21) puts v2rayNG (both flavours), Clash Meta for Android, FlClash, Hiddify, NekoBox and Orbot first; the
   rest follow `tools.tsv`, then the tools without a proxy mode. No country and no figure of the matrix is public.
3. **Read from source, at a release tag, line by line.** Each guide is read at the release tag of a recorded version,
   the newest stable one unless the 2026-11-11 run tried another. Every step, label, listener and password setting links
   to the line that shows it, at that commit (`guide-steps.tsv`, `guide-labels.tsv`). v2rayNG 2.3.15, NekoBox 1.4.2,
   Orbot 17.9.7-BETA-1 and Hiddify 5.5.5 are read at the versions the [real tools' run](../spikes/2026-11-real-tools.md)
   tried, so they count as tried with the network part. Every other tool waits for a device check, under the 2026-11-11
   method (the developer's own release, its signer checked), until the maintainer gives the word for it; none is
   installed or run here. Where a newer release than the commit `tools.tsv` read exists, the guide is read at it, and
   the data check holds its listener and password to the table's row: none differed. Two proxy labels of the table were
   wrong at the very commits it read, and are corrected with their evidence: WG Tunnel calls its mode "Local proxy",
   under "App mode", and Oblivion 8 shows "SOCKS5 only" under "Routing mode" ("Proxy only mode" is in its strings, on no
   screen).
4. **What a guide says.** Where the switch is, with the tool's labels; the listener and its port; whether a user name
   and password can be set, and where; what the tool asks for in that mode, from its code (notifications; the alarms
   permission, Orbot; a battery exemption; Android 17's local network permission, which Advanced does not need for a
   proxy on the phone; a VPN's consent even in proxy mode, MDV-HN Edition, which turns Advanced's tunnel off once); what
   Advanced does next; how to go back; and the facts a user of that tool needs (ByeByeDPI sends nothing to a server, so
   the apps it carries reach their destinations from the user's own address; DNSTT.XYZ opens a SOCKS5 proxy only with
   its SSH tunnel type; a work profile shifts the SagerNet family's ports; some of ZedSecure's engines still start a
   VPN). The sentences are the network part's strings, plain by the gate and free of ADR 0025's words (decision 4); they
   never recommend a tool and never point to a download.
5. **A profile's listener: the guide names the port, and the finder greets it.** Clash Meta for Android and sing-box
   take their listener from the user's profile, so the finder had no port to greet (`ToolTable.kt`). The other way, the
   user typing the port into Advanced, was weighed and not taken. The user changes the tool anyway, by turning off
   "Route System Traffic" or by writing a profile without a `tun` inbound, and the port is one more field in the same
   place. Clash Meta's Override, which applies to every profile and wins over it, sets "Mixed Port" to 7890, the port
   many profiles use. sing-box's profile gets a `mixed` inbound on 127.0.0.1, port 2080, the SagerNet family's default,
   since its documentation names none. So Advanced still finds every tool with no port typed (W6's measure), has no
   field to mistype, and a port is still the tool's only when Android names the tool its owner. The cost: until the user
   sets the named port, a profile with another one is not found; the page says to set it even then. GuidesTest checks
   it.
6. **The labels are data, read at run time.** A tool speaks the phone's language, or one chosen in the tool, which
   Android tells no other app (LocaleManager answers only the app itself, its installer and the keyboard). So Advanced
   reads each label from the installed tool by the resource name the data records: its resources opened without its code
   (`createPackageContext` with no flags, a configuration for the locales asked, a lookup by name). Nothing is
   decompiled, and none of the tool's code runs. The label comes in the phone's languages, which from Android 13 come
   from LocaleManager, and also in Datapavan's own where that differs, the best sign of a language the user chose; a
   tool's language counts as present only where its words differ from its default ones. The shared module reads them
   (`OtherAppResources`, `PhoneLocales`), as it reads Android's own labels
   ([ADR 0054](0054-android-labels-read-from-the-phone.md)). A label that is not an Android resource (Flutter's i18n
   files: Hiddify, FlClash, Oblivion; words written in code: DNSTT.XYZ, SlipNet, WhiteDNS, some of MDV-HN's and
   MasterDnsVPN-GG's), or that the installed version no longer has, is the data's, in the first of those languages its
   source has, else in English. A label is cut to one line of at most 80 characters with no direction overrides, and
   isolated in the sentence. Labels are not strings for ADR 0030's translators; the sentences are.
7. **Package visibility costs nothing new.** Advanced holds `QUERY_ALL_PACKAGES` for the audit
   ([ADR 0014](0014-v0.1-permissions.md)), and the network part's own launcher query
   ([ADR 0034](0034-network-permissions.md)) reaches any tool a user can open. Either lets Advanced open a tool's
   resources.
8. **Where they show.**
   - **On the network screen.** Android hides a VPN's owner from other apps (`FoundTool.ownerConfirmed`), so Advanced
     cannot tell which tool runs as the VPN now. The chain section links the guide of every tool of the table installed
     here, whatever its search found.
   - **On the website.** The same text, one page per tool under `docs/site/guides/`: `scripts/guides.py` writes the
     pages from the same data and the network part's English strings, and a JVM test holds the screen's blocks to the
     built pages. The labels link to their lines of code and the version to the tag; nothing links to a release, a store
     or a file to install, and no page ranks one tool above another.
   - **In onboarding.** W9 opens the same screen (`GuideActivity.intent`) from the same links.
9. **Checks.** The data check (`scripts/guides.py` in `scripts/check.sh data`): every page, step, label, resource,
   listener and password setting has its source line and matches `tools.tsv`, and its self-test catches 19 broken
   copies; `--against` the sources' clones found all 532 lines on 2026-11-21. The site's link check; the
   plain-language gate; GuidesTest and ToolLabelsTest on the JVM: the chain section's links, the named ports and the
   finder, the words, and labels read from the project's test tool's resources in two languages. The emulator check
   (`scripts/verify-chain.sh`): the chain section links the test tool's guide, which quotes the label from the
   installed test tool's resources, not the one the data records.

**Limits.** A language chosen inside a tool cannot be read: where it is neither the phone's nor Datapavan's, the
quoted labels are in another language than the tool shows, and the places the steps name (a menu, a tab, a gear)
still lead. A tool installed from Google Play in language splits holds only the phone's languages, and Android gives
its default words for any other: Datapavan's language is added beside the phone's only where the tool's resources have
it. A label written in code or in Flutter's files is what the source had at the recorded version, and a newer
version may say otherwise. The website is in English until the translations unit, with parts 1, 2a and 3a's strings
(ADR 0030); a translated page will quote each tool's labels in its language from the tool's own files. Every tool but
the four the run tried waits for the maintainer's word for a device check.

## Consequences

- **0.2.0 grows.** Exclusion, the notice, the local-network rule and the matrix are release gates (ADR 0039).
- **Exclusion weakens coverage.** An app left out is not in the log. Advanced says this on the app's page, and
  the log shows the gap.
- **Hiding Advanced's VPN completely is not possible** on stock Android without root. What can be reduced, and by how
  much, is research at the frontier. The probe app gives it numbers.
- **Some fixes depend on others.** The relay's password and the tools' defaults are their makers' to change.
