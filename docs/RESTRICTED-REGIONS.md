# Working in restricted regions

Datapavan must work for people in countries with heavy internet censorship or surveillance, such as
China, Iran and Russia. This document describes how.

## Why the core already works

- **v0.1 has no network access at all.** Nothing to block, nothing to filter.
- **The VPN is local.** It needs no server and sends nothing to us, so it works in filtered networks and even offline.
- **No dependency on Google Play Services.** Phones sold in China usually ship without them.

## Challenges and answers

| Challenge | Answer |
|---|---|
| **One VPN at a time.** Users depend on circumvention VPNs | Chaining through a local SOCKS5 proxy from the user's circumvention tool (see [VPN.md](VPN.md)). We never build circumvention ourselves |
| **Distribution.** Play is absent or restricted; F-Droid, GitHub or Codeberg may be blocked | APKs on several independent mirrors. Reproducible builds and a published signing-certificate fingerprint, so a copy from any source (even a messenger channel) can be verified. The app shows its own signing fingerprint |
| **Fake or trojanised copies** circulating in messenger channels | The same signature verification, explained in simple steps in every UI language |
| **Updating tracker lists** when our servers are unreachable | Lists ship inside the app. Updates are signed (Ed25519), so they are valid from any mirror, a file sent over a messenger, or a USB stick. The signature makes an update genuine, not the way it travelled |
| **Poisoned DNS, blocked DoH** | Fall back to the network's resolver; never break connectivity. The UI separates "blocked by Datapavan" from "network failure" |
| **Legal risk to the user.** VPN use or sale is legally restricted in several countries. Android shows a VPN key icon even for a local VPN | The VPN-free modes (the v0.1 audit) stay fully useful on their own. The docs explain the risk honestly, and we make no claims about evading surveillance |
| **OEM battery managers** (Xiaomi, Oppo, Vivo and others) | Per-vendor onboarding guides and an in-app health check |
| **Huawei HarmonyOS NEXT** no longer runs Android apps | Not supported |
| **Sanctions** | The free, open-source app is distributed as-is. Paid editions and payments involving sanctioned jurisdictions require legal review before any sale |
| **Languages** | Persian ships at launch; Russian and Chinese are added through the normal translation workflow |

## Principles

1. **Never endanger the user.** No feature that could identify a user to authorities. No telemetry, ever. No claims we cannot keep.
2. **Never break connectivity.** A privacy tool that cuts people off gets uninstalled, and leaves them worse off.
3. **Trust the signature, not the channel.** Everything we ship (apps, lists, updates) can be verified independently of where it came from.
