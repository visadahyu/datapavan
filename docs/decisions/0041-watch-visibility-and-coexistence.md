# 0041. What other apps see of Watch, and working beside every app

- Status: Accepted (by the maintainer on 2026-11-12)
- Date: 2026-11-12

## Context

Watch is a local VPN. It changes no address and sends nothing to a server of its own, but Android tells every
app that a VPN runs. Any app can see this:
- `TRANSPORT_VPN` on its network, under a normal permission;
- the tunnel's interface in the list of interfaces;
- the tunnel's addresses.

Apps may report this to their servers, and some refuse to run while a VPN is on, banking and state-linked apps
among them. For a user who runs Watch without any circumvention tool, Watch itself becomes the signal. That is
at odds with the first principle of [RESTRICTED-REGIONS.md](../RESTRICTED-REGIONS.md#principles): "No feature
that could identify a user to authorities."

Watch also chains apps through the user's circumvention tool (W6, ADR 0038). In proxy mode the tool listens on
the phone's loopback, where any app can find its port. Through a tool that takes no password, any app can send
traffic. Even with a password, some tools' UDP relays accept datagrams from any app.

And Watch carries every app's traffic. When an app fails inside the tunnel, the user's only way out today is to
turn Watch off.

## Decision

1. **Say it plainly.** Watch's onboarding and its screen say that other apps can see that a VPN runs, that some
   report it, and that some refuse to work while it is on. They say what Watch does about it, and what it cannot
   do.
2. **Leave an app out.** From 0.2.0 the user can leave any app out of the tunnel. Watch says honestly what this
   hides and what it does not: the app's own network is then not a VPN, but the tunnel's interface may still
   show in the list of interfaces. The lab measures what an excluded app sees, with a probe app of the project's
   own, on every Android version in CI.
3. **Addresses that do not single Watch out.** The tunnel uses addresses common to many VPN apps, not fixed
   values of Watch's own.
4. **The local network on Android 17, by each app's own grant.** Watch forwards an app's traffic to the local
   network only if that UID holds the local-network permission itself, and records refusals. This holds for apps
   Watch cannot name too, whose UID is checked the same way. It closes ADR 0034's unbuilt requirement.
5. **Tools without a password, and open UDP relays.** Watch chains through a tool whose proxy takes no
   password, and says that any app on the phone can use that port; it gives the steps to set a password in that
   tool. Where a tool's UDP relay accepts datagrams from other apps, Watch chains TCP only by default and says
   why. The lasting fix is in the tools: the project asks their makers to require the password on the relay too.
6. **A compatibility matrix kept current.** It is published and maintained continuously, not as a one-off list:
   - **Automated runs:** a set of devices runs the apps, inside the tunnel, outside it, chained, and with
     blocking.
   - **Reports from users:** a user can report an app that fails with Watch, and the report carries no personal
     data.
   - **Which apps:** they are chosen by public reach in each region, banks, payment, government, messaging and
     transport first.
   - **Inside Watch:** when an app fails with Watch, Watch offers to leave it out.
7. **The lab tests apps that refuse a VPN.** Named apps are tested on real phones one by one, each test agreed
   first, and the results are published with evidence (ADR 0015).

### How decision 3 is built (2026-11-12)

**The principle: an open project, a quiet phone.** The maintainer asked whether a security tool should hide
itself or be plainly seen. The project is open about what it is: its code, its name, its signing key, and what it
tells its own user; Android also always shows that the VPN is Watch's. What the phone does not do is tell every
other app, unasked, which tool its user chose. The tunnel's address is such a message: any app reads it without a
permission, and an address of Watch's own would mark its user as a Watch user, and through the chain a likely user
of a circumvention tool. So Watch takes addresses that other apps of its own kind use. It does not take the
addresses of a different kind of app: it does not pass itself off as something it is not.

**The addresses.** The tunnel addresses of 32 apps were read from their own source at a tag or commit. Three
groups share them:
- 172.19.0.1 and fdfe:dcba:9876::1 belong to proxy and circumvention clients: Shadowsocks, NekoBox, Exclave,
  Clash Meta, Hiddify and others, with a /30 or /28 that Android 17 would count as local network.
- 10.1.10.1/32 and fd00:1:fd00:1:fd00:1:fd00:1/128 belong to privacy firewalls: NetGuard, TrackerControl and
  InviZible Pro.
- 10.111.222.1/24 belongs to Intra, Outline and RethinkDNS.

Watch takes the firewalls' pair. It has exactly the /32 and /128 that Watch needs, and an app that reads it finds
a local firewall, which Watch is. The engine and the service hold the same two sets (`Addresses` in
core/net/src/engine.rs, `TunnelAddresses` in Watch), and a unit test fails if they drift apart.

**A network that uses them itself.** Comcast Business gateways answer at 10.1.10.1, and a tunnel that took the
router's address would cut the phone off from its router and resolver. Before it sets up the tunnel, Watch reads
every network beneath it: their addresses with their prefixes, their gateways and their DNS servers. If one of
them uses an address of the common set, Watch takes its earlier, rarer addresses (10.215.173.1 and
fd7a:6470:7761::1, shared only with PCAPdroid's IPv4 address). When a network changes to clash, or stops
clashing, Watch sets the tunnel up again with the other set.

**What still differs.** The tunnel's DNS server (10.1.10.3) and its MTU (1500, where NetGuard uses 10000) are
Watch's own. An app that can list installed packages can still see that Watch is installed. Hiding that a VPN runs
is not possible on stock Android. The probe app of decision 2 is to measure what an app outside the tunnel still
sees. This decision narrows what the address alone says; it does not make Watch invisible.

### How decision 5 is built (2026-11-12)

**What Watch already knows.** Watch finds the user's tool with a SOCKS5 greeting that offers no password (ADR
0038). The proxy's answer says whether it wants one. The table of tools says whether the tool can take a password
at all, and whether it carries UDP.

**A proxy that asks no password.** Watch still chains through it, since refusing would leave the user without
Watch. Its screen says, in the error colour, that any app on the phone can use the proxy, learn that the user runs
this tool and the address of its server, and send its own traffic through it. For a tool that has no password
setting, Watch says so, and that the proxy stays open while the tool runs in proxy mode. For a tool that takes
one, Watch shows the user name and password it made, and where tools keep that setting: the settings of their
local proxy, often named inbound, SOCKS or local port. Steps for each tool, with evidence, belong in the table of
tools.

**A proxy that asks a password.** Watch says that other apps cannot use it, and that they can still see that it is
there: any SOCKS5 server answers a greeting.

**UDP: TCP only by default.** No tool is known to tie its UDP relay to the app that opened it, and stock Android
has no loopback firewall by app. While a relay carries Watch's datagrams, other apps on the phone may send through
it too, even where the tool's proxy asks a password. A 2026 test found that the UDP of some Xray and sing-box
clients works with no password at all ([Habr](https://habr.com/en/articles/1020080)). So for every tool, the
chosen apps' UDP goes through the tool only once the user turns that on, under a switch that says why it is off
and what is lost: calls and some games in the chained apps. Web pages still load: names go through the tool over
TCP (ADR 0038), and browsers fall back from QUIC to TCP. Off, a chained app's UDP goes nowhere, never directly.
For a tool that carries no UDP, the screen keeps saying so, with no switch.

**Not yet.** Which tools' relays take datagrams from other apps, or with no password, is lab work: a check per
tool, recorded in the table of tools with its evidence. A tool whose relay is shown to refuse other apps can then
default to UDP on. Watch does not probe the relay itself: a probe from Watch cannot tell a relay that refuses
another app from one that refuses the probe's destination.
## Consequences

- **0.2.0 grows.** Exclusion, the notice, the local-network rule and the matrix are release gates (ADR 0039).
- **Exclusion weakens coverage.** An app left out is not in the log. Watch says this on the app's page, and
  the log shows the gap.
- **Hiding Watch completely is not possible** on stock Android without root. What can be reduced, and by how
  much, is research at the frontier. The probe app gives it numbers.
- **Some fixes depend on others.** The relay's password and the tools' defaults are their makers' to change.
