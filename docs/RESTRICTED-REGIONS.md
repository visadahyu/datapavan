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

## Principles

1. **Never endanger the user.** No feature that could identify a user to authorities. No telemetry, ever. No log that becomes evidence by default. No claims we cannot keep.
2. **Never break connectivity by our own choice.** A privacy tool that cuts people off gets uninstalled, and leaves them worse off. The only exceptions are ones the user turns on: strict DNS, and fail-closed lockdown.
3. **Trust the signature, not the channel.** Everything we ship (apps, lists, updates) can be verified independently of where it came from.
