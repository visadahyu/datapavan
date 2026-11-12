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

## Consequences

- **0.2.0 grows.** Exclusion, the notice, the local-network rule and the matrix are release gates (ADR 0039).
- **Exclusion weakens coverage.** An app left out is not in the log. Watch says this on the app's page, and
  the log shows the gap.
- **Hiding Watch completely is not possible** on stock Android without root. What can be reduced, and by how
  much, is research at the frontier. The probe app gives it numbers.
- **Some fixes depend on others.** The relay's password and the tools' defaults are their makers' to change.
