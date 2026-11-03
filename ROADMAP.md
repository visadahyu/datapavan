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
| M2 | App inventory and permission audit, including special access (accessibility, notification listener, device admin, overlay, usage access, VPN, install unknown apps, battery-optimisation exemptions), plus risk checks for VPN users: VPN apps with remote-control access, user-installed certificate authorities, enabled debugging; device integrity from hardware key attestation. Preinstalled system apps from data-collecting companies (for example Meta's services that device makers ship), with their state and a guide to disable or remove them reversibly. Apps that hold microphone, camera or location access, with a link to the system's privacy dashboard | ✅ |
| M3 | Tracker SDK scanner: a DEX parser in the Rust engine, matched against a tracker-signature database and Datapavan's own list of traffic-sharing, remote-support and screen-recording SDKs ([ADR 0019](docs/decisions/0019-traffic-sharing-remote-support-sdks.md)); installed VPN, proxy and circumvention apps checked against their developers' official signing certificates, Google Play copies included ([ADR 0018](docs/decisions/0018-app-signing-certificates.md)); datasets shipped as signed data packs that the user can also import as files, without network access ([DATA-PACKS.md](docs/DATA-PACKS.md)); each entry that names a company records its evidence, with a public way to dispute it (ADR 0015). Done on 2026-10-30: the scan finds every tracker of the εxodus reports for 22 apps of the same version ([spike](docs/spikes/2026-10-m3-exodus-comparison.md)), and a re-signed copy of a known app is reported as modified | ✅ |
| M4 | Network usage per app, from `NetworkStatsManager`; unused apps from usage access, for the remediation plan ([ADR 0022](docs/decisions/0022-network-use-and-unused-apps.md)). Done on 2026-10-31: every app's size matched Settings on an Android 17 emulator, and the A40's ten largest Wi-Fi rows within 0.07 % ([spike](docs/spikes/2026-10-m4-network-use.md)) | ✅ |
| M5 | Plain-language UI, brand theme (built on 2026-11-03, contrast checked by `ThemeTest`), first release on GitHub, submission to F-Droid. The data-signing key, made offline before the release ([docs/DATA-PACKS.md](docs/DATA-PACKS.md#keys)). Defences against fake copies of Datapavan, with fingerprints published in at least two places before the release ([ADR 0024](docs/decisions/0024-fake-copies-of-datapavan.md)); the in-app self-check and the sentence to teach were built on 2026-11-03, and Datapavan's own row in `data/app-signers` follows once the release key exists. The remediation plan ([docs/REMEDIATION.md](docs/REMEDIATION.md)): three levels, a short queue of actions ordered by impact, each confirmed in one tap, a journal with undo, and a safety floor that no level can lower. The guided check of one activity in an app, and two facts about traffic that need no comparison ([ADR 0025](docs/decisions/0025-guided-check-and-traffic-facts.md), [spike](docs/spikes/2026-11-guided-check.md)): built on 2026-11-02 and checked end to end on the emulator (`scripts/traffic-lab/verify-check.sh`). The remediation plan's part for v0.1 ([ADR 0026](docs/decisions/0026-remediation-plan-v0.1.md)): built on 2026-11-03 and checked end to end on Android 11, 15 and 17 emulators (`scripts/verify-plan.sh`, also in CI) | ⏳ |

The data behind M3 keeps growing next to the later milestones:

- SDKs known only from research (IPIDEA's, PROXYLIB and others) join the list once samples are read
  offline; Bright SDK, Massive, Honeygain and Repocket once an official app or artefact is read.
- Keys of Google Play copies for older Android versions, from Play emulators with Android 11 to 13.
- A second official channel for keys read only once, and the first hybrid (v3.2) signatures.
- An informational note for apps that use the name or icon of a listed app (ADR 0018, decision 8).
- Apps named in reports on networks that relay traffic, matched by package and certificate
  (ADR 0019).
- Trackers from the app's own company group ([ADR 0020](docs/decisions/0020-same-company-trackers.md)):
  the rule and the first owners are done; more owners and publishers follow, among them the makers'
  own keys from their Digital Asset Links files.
- The phone maker's software and system keys that cannot be trusted
  ([ADR 0023](docs/decisions/0023-maker-software-and-system-keys.md)): the system key is read on the
  phone and checked against AOSP's public test keys, Google's development keys and the platform keys
  Google listed as leaked in 2022; further leaks join `data/system-keys` as they are published.
- Tracker capabilities that need a service the phone lacks
  ([ADR 0021](docs/decisions/0021-service-dependent-capabilities.md)): the service check and seven
  capabilities are done; more follow as their vendors' artefacts are read, and the check still needs
  a device matrix. The scan's lower memory and parallelism by memory are done.

Checks left from M4 (ADR 0022):

- How Android counts traffic through a VPN service and through a local proxy app.
- Whether Android 13 to 16 also lock usage access for apps installed from a file.
- The units of other vendors' data-usage screens, Android 10, and mobile data on a Samsung phone.

### v0.2 "Watch": local VPN, observe only

A **local** VPN: no server is involved and the user's IP address does not change. Before this version
starts, a two-week spike picks the packet engine (Rust netstack or Go gVisor). Design: [docs/VPN.md](docs/VPN.md).

- A connection log per app: domain, IP, organisation, bytes, time, foreground or background.
- Chaining through a local SOCKS5 proxy, so Datapavan can run next to circumvention tools (see
  [docs/RESTRICTED-REGIONS.md](docs/RESTRICTED-REGIONS.md)). The tool becomes a pipe, not the owner of
  the phone's network: no inbound access from the VPN provider's network, and proxy-like behaviour,
  including the tool's own, is flagged. Per-tool guides for proxy mode.
- Apps that bypass Datapavan's resolver are flagged; TLS fingerprints identify the client library.
- A sensor activity log: when the microphone recorded or the camera was on, and whether the screen was off, with an alert for use while the screen is off. Android hides which app records, so the app is inferred from what was on screen and which services ran. A feasibility spike comes first.
- Apps that keep their own always-on connection instead of the system push service are flagged.
- An optional advanced mode, granted once over USB, reads Android's own history of microphone and camera use and names the app exactly.
- Cross-checks report contradictions: our sensor log against Android's record, and Android's per-app data accounting against what the VPN saw.
- Unusual behaviour: each app's normal traffic shape is learned on the device, and deviations are reported, for example a steady audio-like upload or large uploads while the user only scrolled. Because a learned baseline only detects change, uploads are also split by destination (content, analytics, advertising) and compared with lab reference measurements. Ranges for kinds of app come from the project's lab ([docs/LAB.md](docs/LAB.md)): measured on its own phones, published with every run, and compared with a user's guided check, which can be repeated and reported; they get their own ADR first (ADR 0025, point 5).

### v0.3 "Guard": blocking

- Network access per app (Wi-Fi, mobile, background), and tracker-domain blocking with per-app exceptions.
- Blocking of proxy-like behaviour flagged in v0.2.
- "Notifications yes, hidden uploads no": per app, network access only while the app is on screen. Push notifications still arrive through the system's push service. Some messengers then fetch the message text themselves, so their notifications may arrive without text or late; the choice is per app.
- Safe defaults, one-tap undo, and a "this app broke" path.

### v0.4 "Report"

- A weekly plain-language report, exportable as PDF or JSON.
- A GDPR Article 15 helper: for each company whose trackers were observed, a ready-to-send data-access request.
- Declared against observed: each app's data-safety label on Google Play compared with what Datapavan saw. The labels come from the lab, cited by hand, until researcher access under DSA Article 40(12) or Google's permission allows more (ADR 0015).

---

## Stage 2: organisations

- **Device Owner flavour.** Disables system apps, enforces always-on VPN in lockdown mode, controls installs and permissions on stock devices, with no root and no bootloader unlocking.
- **Circumvention policy** for organisations in filtered networks: only approved, signature-verified tools; no user-installed certificate authorities; no debugging; Datapavan always in front of the tool.
- **Work-profile isolation.** Puts high-tracking apps (for example Meta's) in a separate profile that cannot see the rest of the phone, and pauses the whole profile when those apps are not in use. Possible without a factory reset.
- **Enforced permissions.** Microphone, camera and location stay denied for every app outside an allow-list, and new requests are denied automatically: the strict sensor mode that stage 1 can only guide.
- **AI-data guard.** Watches apps and system AI services that can read the screen, notifications or keyboard input.
- **Compliance reporting** for the GDPR and comparable laws (for example the UK GDPR, Switzerland's FADP, Brazil's LGPD and Turkey's KVKK).

## Stage 3: our own OS

- A hardened, Android-based OS on partner hardware, where the stage 1 and 2 layers become part of the system.
- The same Rust engine runs as a system service. It sees which app uses which sensor, live, and can ask the user before each use.
- Partner hardware should offer sensor kill switches, or an indicator light wired to the sensor's power, so that software cannot hide sensor use.
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
| Hosting: GitHub as the only home (ADR 0013); a self-hosted EU forge reconsidered once the domain exists | ✅ |
| Make the repository public | ⏳ before v0.1 is released |
| F-Droid submission | ⏳ with v0.1 |
| Measurement lab: reference measurements on the project's own phones, public reports, and evidence for data-protection authorities and civil-society organisations (legal advice first) | ⏳ from v0.2 |
