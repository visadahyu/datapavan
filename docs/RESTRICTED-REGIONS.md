# Working in restricted regions

Datapavan must work for people in countries with heavy internet censorship or surveillance, such as
China, Iran and Russia. This document describes how.

## Why the core already works

- **v0.1 cannot open network connections.** Nothing to block, nothing to filter.
- **The VPN is local.** It needs no server and sends nothing to us, so it works in filtered networks and even offline.
- **No dependency on Google Play Services.** Phones sold in China usually ship without them.

## Challenges and answers

| Challenge | Answer |
|---|---|
| **One VPN at a time.** Users depend on circumvention VPNs | Chaining through a local SOCKS5 proxy from the user's circumvention tool (see [VPN.md](VPN.md)). We never build circumvention ourselves |
| **Tools that run only as a VPN**, with no proxy mode: some commercial VPNs, and some tools handed out by the authorities that filter the network | Watch must work beside every tool the user has, as far as Android allows. Where a provider offers a WireGuard configuration, Watch carries it as its own upstream, so one VPN does both (0.2.0). Otherwise the tool keeps the VPN, and the audit app still audits it without a tunnel: its official signing certificate (ADR 0018), its permissions and special access, the trackers and traffic-sharing SDKs in its code (ADR 0019), and its own data use from Android's counters. The app says plainly which of these a tool allows |
| **Most people do not know which kind of tool they have**, and should not have to | Watch finds out by itself (0.2.0). It carries the same signed list of tools and certificates as the audit app (ADR 0018) and a signed table of each tool's modes, ports, password options and UDP support, so it sees which tools are installed and whether one is genuine. Android tells it that another VPN is active but not whose, so it works that out from the installed tools. It probes only the known ports, with a SOCKS5 greeting, and then asks Android which app owns the port: a port number alone is only a hint, since several tools share one. It picks the way that works, chaining, WireGuard upstream or the audit alone. The user is asked only for what Android or the tool reserves to them, one step at a time, in plain words: the tap that allows a VPN; switching the tool to proxy mode first, since a new VPN stops the old one and the tool's proxy with it; turning off another VPN's "always-on", which keeps Watch from starting (Watch opens that screen); and fetching a provider's WireGuard file, which providers give only after a login on their website |
| **Proxies built into apps**: Telegram's MTProto and SOCKS5 proxies, and the proxy settings of WhatsApp and Signal | These connect from inside the app, so they pass through Watch like any other connection. The log names the app and the proxy's address, and says when the proxy is run by someone other than the app's maker: such an operator sees the user's address and when they use the app, not their messages. A SOCKS5 password in an app's proxy settings travels in clear and is never written to the log (0.2.0) |
| **Tools handed out to watch their users**, by a government or its contractors | Treated as untrusted, like every tool: chained where possible, so that their own traffic is attributed to them, and always audited. Findings that name a tool follow ADR 0015's evidence rules |
| **Phone seizure or inspection** at borders and checkpoints | Destinations of chained flows are not recorded by default. Retention is selectable, including none, with a one-tap wipe. The VPN-free modes keep no network log at all. No list of the user's tools and no history of checks is kept, and no notification names a VPN or a tool: someone who opens the phone should learn no more than the installed apps already tell |
| **Distribution.** Play is absent or restricted; F-Droid or GitHub may be blocked | APKs on several independent mirrors, with reproducible builds, so that F-Droid can ship the developer-signed APK and anyone can rebuild it. The website's download section also links the same file on GitHub, since one network let the page through while the download did nothing (2026-11-07), and says that a copy passed on by hand is fine once its key matches |
| **Fake or trojanised copies** circulating in messenger channels | Verify every APK with an **external** tool (`apksigner`, AppVerifier, or F-Droid's own checks) against the signing-certificate fingerprint published in the repository and on the website. The app's own display of a fingerprint proves nothing, because a modified copy can show any text. Instructions are given in every UI language |
| **Updating tracker lists** when our servers are unreachable | Lists ship inside the app. Updates are signed (Ed25519) and never roll back to older versions, so they are valid from any mirror, a file sent over a messenger, or a USB stick. The signature makes an update genuine, not the way it travelled |
| **Update requests reveal Datapavan use** to network observers | Updates are optional. Lists can be imported as files instead |
| **Poisoned DNS, blocked DoH** | A **strict DNS** setting never falls back to the network's resolver, because that fallback would hand every query to the censor. It is recommended in restricted regions. The UI separates "blocked by Datapavan" from "network failure" |
| **Legal risk to the user.** VPN use or sale is legally restricted in several countries. Android shows a VPN key icon even for a local VPN | The VPN-free modes (the v0.1 audit) stay fully useful on their own. The docs explain the risk honestly, and we make no claims about evading surveillance |
| **Google developer verification.** Since 2026-09-30, certified Android devices in four countries install apps from participating stores only from verified developers. Direct installs are not checked yet; this goes global in 2027 | Datapavan's developer identity is registered with Google, so normal installs keep working. Installs over ADB are exempt |
| **OEM battery managers** (Xiaomi, Oppo, Vivo and others) | Per-vendor onboarding guides and an in-app health check |
| **Huawei HarmonyOS NEXT** no longer runs Android apps natively | Not supported |
| **Sanctions** | The free, open-source app is distributed as-is. Paid editions and payments involving sanctioned jurisdictions require legal review before any sale |
| **Languages** | Persian ships at launch; Russian and Chinese are added through the normal translation workflow |

## Untrusted VPN apps

Where most people need a circumvention tool, the tool itself is often the biggest risk on the phone.
Free VPN apps, and modified copies of well-known tools shared in messenger channels, put both the user
and the networks they connect to at risk.

| Threat | What happens | Answer | From |
|---|---|---|---|
| **Remote control and data theft** | A VPN app also holds accessibility, overlay, device-admin or notification access, and reads messages and login codes | The audit flags every VPN app that holds such access, with a direct path to revoke it or uninstall the app | v0.1 (M2) |
| **Trojanised copies** | A modified copy of a known tool, signed by someone else, carries spyware | Installed circumvention tools are checked against their official signing certificates, from a signed list | v0.1 (M3) |
| **The phone as an attack proxy** | A hidden SDK turns the phone into an exit node for other people's traffic: fraud, password guessing and attacks that are traced back to the owner | Known proxy and remote-access SDKs are part of the scanner's signatures. In chained mode, every flow is attributed to its app, including the tool's own connections, and proxy-like behaviour is flagged and can be blocked | v0.1 (M3), v0.2, v0.3 |
| **Inbound access from the VPN network** | A full-tunnel VPN gives the phone an address inside the provider's network, where the operator or other customers can reach it | In chained mode the tool runs as a local SOCKS5 proxy, which only carries connections the phone opens. The phone has no address in the provider's network, and Datapavan drops every packet that does not belong to a flow a local app started | v0.2 |
| **Interception of encrypted traffic** | The VPN asks the user to install its own certificate authority, which lets it read HTTPS | The audit lists user-installed certificate authorities and explains what each one allows | v0.1 (M2) |
| **Debugging left on** | Setup guides for some tools tell users to enable USB or wireless debugging | The audit flags enabled debugging | v0.1 (M2) |

**The principle:** the circumvention tool becomes a pipe, not the owner of the phone's network.
Watch stays the device's VPN, decides which apps may use the pipe, and sees what goes into it (see
[VPN.md](VPN.md)). Watch must not become a leak itself: chained apps never fall back to a direct
connection, their names never go to the network's resolver, and checks of the chain never contact a
Datapavan host.

**Limits:**

- If the tool runs in VPN mode instead of proxy mode, only the VPN-free checks apply. Per-tool guides show how to switch to proxy mode, which most popular tools offer. Some have none: WireGuard's own app, Outline, Psiphon and Lantern's released app run only as a VPN.
- A copy signed with an unknown key is reported as modified only when every official key of that tool is known. For most circumvention tools some channel's key is still missing, so such a copy is shown as unconfirmed, not as fake (ADR 0018). Tools that publish their keys' fingerprints close this gap; we ask their developers to.
- Advice never stops at "remove this tool": a user who loses their only tool may turn to a worse one. The advice is to install a trusted tool first, then remove the doubtful one.
- Datapavan cannot clean a phone that is already compromised. It finds the risk, checks device integrity through hardware attestation, and guides removal, including through Android's safe mode. Stage 2 starts from a factory reset and prevents reinfection.
- It sees metadata, never the content of encrypted traffic.
- For organisations, stage 2 enforces the same protection: only approved, signature-verified tools; no user-installed certificate authorities; no debugging; always-on VPN with Datapavan in front of the tool.

How each limit is covered in later stages is in [DESIGN.md](DESIGN.md), section 2.

**Open question,** to be decided in a separate ADR after legal advice: embedding an open-source tunnelling
core (for example Xray-core, MPL-2.0) so that users can bring their own server configuration. It would
remove the one-VPN-at-a-time limit, but it contradicts the rule that we do not build circumvention,
carries legal and sanctions risk, and starts a cat-and-mouse game with censors.

## Principles

1. **Never endanger the user.** No feature that could identify a user to authorities. No telemetry, ever. No log that becomes evidence by default. No claims we cannot keep.
2. **Never break connectivity by our own choice.** A privacy tool that cuts people off gets uninstalled, and leaves them worse off. The only exceptions are ones the user turns on: strict DNS, fail-closed lockdown, and apps sent through a circumvention tool, which wait while the tool is down instead of going out directly.
3. **Trust the signature, not the channel.** Everything we ship (apps, lists, updates) can be verified independently of where it came from.
