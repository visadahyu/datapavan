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
| **Phone seizure or inspection** at borders and checkpoints | Destinations of chained flows are not recorded by default. Retention is selectable, including none, with a one-tap wipe. The VPN-free modes keep no network log at all |
| **Distribution.** Play is absent or restricted; F-Droid or GitHub may be blocked | APKs on several independent mirrors, with reproducible builds, so that F-Droid can ship the developer-signed APK and anyone can rebuild it |
| **Fake or trojanised copies** circulating in messenger channels | Verify every APK with an **external** tool (`apksigner`, AppVerifier, or F-Droid's own checks) against the signing-certificate fingerprint published in the repository and on the website. The app's own display of a fingerprint proves nothing, because a modified copy can show any text. Instructions are given in every UI language |
| **Updating tracker lists** when our servers are unreachable | Lists ship inside the app. Updates are signed (Ed25519) and never roll back to older versions, so they are valid from any mirror, a file sent over a messenger, or a USB stick. The signature makes an update genuine, not the way it travelled |
| **Update requests reveal Datapavan use** to network observers | Updates are optional. Lists can be imported as files instead |
| **Poisoned DNS, blocked DoH** | A **strict DNS** setting never falls back to the network's resolver, because that fallback would hand every query to the censor. It is recommended in restricted regions. The UI separates "blocked by Datapavan" from "network failure" |
| **Legal risk to the user.** VPN use or sale is legally restricted in several countries. Android shows a VPN key icon even for a local VPN | The VPN-free modes (the v0.1 audit) stay fully useful on their own. The docs explain the risk honestly, and we make no claims about evading surveillance |
| **Google developer verification.** Since 2026-09-30, certified Android devices in four countries install apps only from verified developers; this goes global in 2027 | Datapavan's developer identity will be registered with Google before the first release, so normal installs keep working. Installs over ADB are exempt |
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
Datapavan stays the device's VPN, decides which apps may use the pipe, and sees what goes into it (see
[VPN.md](VPN.md)).

**Limits:**

- If the tool runs in VPN mode instead of proxy mode, only the VPN-free checks apply.
- Datapavan cannot clean a phone that is already compromised. It finds the risk and guides its removal.
- It sees metadata, never the content of encrypted traffic.
- For organisations, stage 2 enforces the same protection: only approved, signature-verified tools; no user-installed certificate authorities; no debugging; always-on VPN with Datapavan in front of the tool.

## Principles

1. **Never endanger the user.** No feature that could identify a user to authorities. No telemetry, ever. No log that becomes evidence by default. No claims we cannot keep.
2. **Never break connectivity by our own choice.** A privacy tool that cuts people off gets uninstalled, and leaves them worse off. The only exceptions are ones the user turns on: strict DNS, and fail-closed lockdown.
3. **Trust the signature, not the channel.** Everything we ship (apps, lists, updates) can be verified independently of where it came from.
