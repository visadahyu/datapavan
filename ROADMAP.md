# Roadmap

Datapavan grows in three stages. Each stage stands on its own and makes the next one possible.
Technical details for stage 1 are in [docs/DESIGN.md](docs/DESIGN.md).

| Stage | What | Who it serves | Control over the phone |
|---|---|---|---|
| 1 | Layer app for stock Android, no root | Individuals | What a normal app may do |
| 2 | Enterprise flavour in Device Owner mode | Organisations | Fleet policies, system apps disabled, VPN enforced |
| 3 | Hardened Android-based OS on partner hardware | Governments, high-security users | The whole software stack |

Status legend: ✅ done · 🔄 in progress · ⏳ planned.

---

## Stage 1: the layer app

### v0.1 "Audit": no VPN, no INTERNET permission

The app cannot open a network connection. That is the strongest trust signal we can give.

| Milestone | Content | Status |
|---|---|---|
| M1 | Skeleton: Android app, Rust core, JNI bridge, i18n and RTL, quality gates, CI, brand | ✅ |
| M2 | App inventory and permission audit, including special access (accessibility, notification listener, device admin, overlay, usage access, VPN, install unknown apps, battery-optimisation exemptions) | ⏳ |
| M3 | Tracker SDK scanner: a DEX parser in the Rust engine, matched against a tracker-signature database | ⏳ |
| M4 | Network usage per app, from `NetworkStatsManager` | ⏳ |
| M5 | Plain-language UI, brand theme, first release on Codeberg, submission to F-Droid | ⏳ |

### v0.2 "Watch": local VPN, observe only

A **local** VPN: no server is involved and the user's IP address does not change. Before this version
starts, a two-week spike picks the packet engine (Rust netstack or Go gVisor). Design: [docs/VPN.md](docs/VPN.md).

- A connection log per app: domain, IP, organisation, bytes, time, foreground or background.
- Chaining through a local SOCKS5 proxy, so Datapavan can run next to circumvention tools (see
  [docs/RESTRICTED-REGIONS.md](docs/RESTRICTED-REGIONS.md)).

### v0.3 "Guard": blocking

- Network access per app (Wi-Fi, mobile, background), and tracker-domain blocking with per-app exceptions.
- Safe defaults, one-tap undo, and a "this app broke" path.

### v0.4 "Report"

- A weekly plain-language report, exportable as PDF or JSON.
- A GDPR Article 15 helper: for each company whose trackers were observed, a ready-to-send data-access request.

---

## Stage 2: organisations

- **Device Owner flavour.** Disables system apps, enforces always-on VPN in lockdown mode, controls installs and permissions on stock devices, with no root and no bootloader unlocking.
- **Work-profile isolation.** Puts high-tracking apps (for example Meta's) in a separate profile that cannot see the rest of the phone. Possible without a factory reset.
- **AI-data guard.** Watches apps and system AI services that can read the screen, notifications or keyboard input.
- **Compliance reporting** for the GDPR and comparable laws (for example the UK GDPR, Switzerland's FADP, Brazil's LGPD and Turkey's KVKK).

## Stage 3: our own OS

- A hardened, Android-based OS on partner hardware, where the stage 1 and 2 layers become part of the system.
- The same Rust engine runs as a system service.
- Requires hardware that lets the bootloader be relocked with our own keys, so this stage depends on partnerships with device makers.
- A certification programme lets device makers have their devices reviewed and carry the "compatible and secure" label.

---

## Work outside the code

| Track | Status |
|---|---|
| Name and brand (see [docs/NAMES.md](docs/NAMES.md), [brand/](brand/README.md)) | ✅ |
| Foundation charter (see [docs/FOUNDATION.md](docs/FOUNDATION.md)) | 🔄 principles written; legal entity planned |
| Domains and EU trademark registration | ⏳ |
| Security contact with an OpenPGP key | ⏳ blocks going public |
| CI on Codeberg (Woodpecker); for now CI runs on the GitHub mirror | ⏳ |
| Make the repository public | ⏳ before v0.1 is released |
| F-Droid submission | ⏳ with v0.1 |
