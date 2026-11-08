# Datapavan — Design Document

| | |
|---|---|
| Version | 0.2 (draft, revised 2026-10-29) |
| Date | 2026-10-28 |
| Scope | Stage 1: the layer app for stock Android, with no root |
| Status | The whole design, much of it not built yet. The [README](../README.md) says what exists today |
| Maintainer (planned) | Visadahyu Foundation |

Items marked **TBV** (to be verified) still need checking against a primary source before we rely on them.

---

## 1. Purpose

Datapavan shows and controls what data each app on an Android phone sends, and to whom. It works on the
device, without root and without any cloud service.

**Target outcome:** no data leaves the device except what the user knowingly gives to a service. The user
can see what left, where it went, and when.

## 2. What we can and cannot protect

An app on a stock phone has hard limits. We state them openly, because overclaiming would destroy trust.

| Datapavan **can** | Datapavan **cannot** |
|---|---|
| Show which apps contain tracking SDKs | See or stop what the user types or posts *inside* a service (e.g. an Instagram post) |
| Show which domains and companies each app contacts, and how much data it sends | Read the content of encrypted traffic |
| Block tracker domains for every app | Remove or modify the maker's system apps (that needs ADB or stage 2) |
| Cut network access per app (Wi-Fi / mobile / background) | Control firmware, the modem or the bootloader (stage 3) |
| Flag apps that hold high-risk permissions or special access | Guarantee that every system component goes through the VPN |
| Flag VPN apps that could control the phone, and modified copies of known circumvention tools | Clean a phone that is already compromised |
| Show when the microphone or camera was used, including with the screen off, and which app used it: exactly with an optional one-time grant over USB, otherwise inferred | Watch every app's sensor use live: Android hides other apps' activity from apps, which protects users from spying apps; stage 3 does it natively |

Each limit is a reason for the next stage. Where each one is addressed:

| Limit in stage 1 | Stage 1 | Stage 2 (Device Owner) | Stage 3 (own OS) |
|---|---|---|---|
| A phone that is already compromised | Finds the risk and guides removal: revoke device-admin or accessibility access first, and use Android's safe mode for apps that resist. A hardware-attested check of the bootloader and verified-boot state, verified against Google's attestation roots and revocation list; stronger when made from a second phone, because a compromised system can tamper with a check on itself | Provisioning starts from a factory reset; policies then allow only approved accessibility services and keyboards, and forbid unknown sources, debugging and user-installed certificate authorities | Verified boot with our own keys on trusted hardware |
| Content of encrypted traffic | **Never decrypted, by design.** Intercepting TLS would make Datapavan the threat it warns about. Instead: apps that bypass our resolver (their own encrypted DNS, hard-coded IPs) are flagged, client libraries are recognised by their TLS fingerprint, and volume and timing are used. Encrypted Client Hello will hide more server names over time, which shifts the weight to DNS and the IP-to-organisation data | Same | Same |
| A circumvention tool running in VPN mode | Per-tool guides, in every UI language, for switching to proxy mode. The VPN-free checks still apply: genuine signature, risky access, hidden SDKs | Proxy mode enforced by policy | Per-app routing in the system |
| System traffic that bypasses the VPN | Onboarding recommends *Always-on VPN* with *Block connections without VPN* | Lockdown enforced | Full control of the network stack |
| Which app is using the microphone or camera | Inferred from the foreground app; exact history with an optional one-time grant over USB | Same | Live, per-use consent in the system; partner hardware with sensor kill switches or an indicator light wired to the sensor's power |
| Firmware, modem and bootloader | Not possible | Not possible | Partner hardware with a bootloader relockable with our keys |

## 3. Principles (non-negotiable)

1. **Local-first.** All analysis happens on the device. No Datapavan server ever receives user data.
2. **Zero telemetry.** No data leaves the phone unless the user sends it ([ADR 0016](decisions/0016-no-user-data.md)). No analytics or crash-reporting SDKs. Crash reports stay local and are shared only by explicit user action.
3. **No Google Play Services dependency.** The app must work on de-Googled devices.
4. **Least privilege.** Each feature asks only for the permission it needs, and explains why before asking.
5. **Plain language.** Every finding has a short, non-technical explanation. Every English string of twelve words or more reaches a Flesch-Kincaid grade of 10 or lower, which `scripts/plain-language.py` checks in `scripts/check.sh`; the median is about 6. Licence notices, which must name the licence, are exempt.
6. **Hands off other apps.** No patching, injection or repackaging of third-party apps. We work only at the system and network level.
7. **Verifiable.** Open source, reproducible builds, signed releases, pinned dependencies.
8. **Clean revenue.** We follow the foundation charter: no ads, no data sales, and no money from parties whose data collection we restrict.

## 4. Users and test devices

- **Stage 1 users:** individual Android users on Android 10 (API 29) or newer.
- **Later:** organisations (stage 2, Device Owner mode).

| Device | Role | Android |
|---|---|---|
| Emulator (KVM, x86_64) | Daily development loop; Play images for real-world apps | 11 (API 30), and 17 (API 37) with 16 KB pages |
| Samsung Galaxy A40 | Lab device: old, low-end, resettable. **Keep the bootloader locked** (unlocking permanently trips Knox, and stage 2 tests need Knox) | 11 |
| Samsung Galaxy A56 | Real-world validation on a maintainer's personal phone, from later milestones (ADR 0011). Stable builds only; never unlocked | 15/16 |
| More vendors (needed) | Datapavan targets every Android vendor, and both phones above are Samsung. The lab needs at least a Pixel (Android's reference behaviour), a Xiaomi or Redmi phone and a low-cost Tecno or Infinix phone; the remediation evidence is kept per vendor, model and build | Various |

## 5. Roadmap for stage 1

Each release can ship on its own and is useful by itself.

### v0.1 "Audit": no VPN, **no INTERNET permission**

Shipping without network permission at all is a strong trust signal: the app *cannot* open a network connection.

- **App inventory:** all installed apps (user and system), installer source, and first-install and last-update dates.
- **Permission audit:** granted dangerous permissions, plus special access: accessibility, device admin, notification listener, usage access, VPN, overlay, install unknown apps, and battery-optimisation exemptions.
- **Risk checks for VPN users:** VPN apps that also hold remote-control access (accessibility, overlay, device admin, notification listener), user-installed certificate authorities, and enabled USB or wireless debugging (see [RESTRICTED-REGIONS.md](RESTRICTED-REGIONS.md)).
- **Device integrity:** bootloader lock and verified-boot state from hardware key attestation, with the certificate chain checked against Google's attestation root keys and revocation list (a chain to another root, a broken chain or a revoked key is reported), with guided removal of risky apps (including Android's safe mode).
- **Preinstalled data collectors:** system apps from data-collecting companies that the device maker ships (for example Meta's app manager and services on Samsung phones), with their state, their traffic (from M4) and a guide to disable them or remove them reversibly for the user.
- **The phone maker's software and its system key** (ADR 0023): the key that signs the package `android` is read on the phone, and each app's page says, as separate facts, whether the app is signed with it (the maker shipped or approved it with system rights, which does not mean the maker wrote it), whether it runs as the system user, and whether it came with the system image, as a later update or as a later install. A system key that is one of AOSP's public test keys, or one of the platform keys Google listed in 2022 as having signed malware, is a phone-wide finding (`data/system-keys`); so is Google's development key, as a note. An app signed with such a key that was installed later, or updated, from anywhere but Google Play, the maker's own store or the phone's own setup is a high finding; from those, a note. Nothing is called safe or unneeded, and nothing of the maker's is offered for removal by default.
- **Sensor access:** apps that hold microphone, camera or location access, especially where the app's purpose does not need it; a link to the system's privacy dashboard (Android 12+), which shows when each app used them; and advice to prefer one-time grants.
- **Strict sensor mode (guided):** Android does not let one app change another app's permissions, so stage 1 walks the user through every app with microphone, camera or location access, opens each app's permission page, recommends *Ask every time* or *Don't allow*, and warns when an app gains the access again. Voice assistants' wake-word listening ("Hey Google", Bixby) is named, with the setting that turns it off. Stage 2 enforces the same policy without the user's clicks.
- **Tracker SDK detection:** scan each app's DEX class names on the device, in the base APK and every split, against a bundled tracker-signature database, and, in the same pass, against Datapavan's own list of traffic-sharing (proxy), remote-support and screen-recording SDKs (`data/sdks`, ADR 0019), whose findings state what was found, what the code does when it is on and what could not be checked, never intent or consent. Trackers whose code the app contains are shown apart from those it only refers to. The first scan reads every app's code (about 90 seconds for 436 apps on the A40); results are cached per app version and signature data. DEX files that an APK stores uncompressed, most of them, are mapped from the APK as Android itself does, so only the pages the parser needs are read; compressed ones are read into memory, and those over 48 MB are reported as unreadable instead. Each class name is matched once, without building lists of names, and the number of apps scanned at once follows the phone's memory. Where an SDK capability needs a system service that the phone lacks in the current profile, such as Google Play services for reading Google's advertising ID, the app's page says so for that capability only, with the time of the check (ADR 0021); Google Play services, the Play Store and HMS Core are each judged genuine, a substitute such as microG, or absent. Installed VPN, proxy and circumvention apps are also checked against their developers' official signing certificates (`data/app-signers`, ADR 0018): a copy is called modified only on positive evidence (every official key known and the data fresh, or a debug key the developer never uses), a key not known yet is shown as a fact with its fingerprint, and a genuine build disguised under another name keeps its disguise behind a tap. Datasets ship as signed data packs ([DATA-PACKS.md](DATA-PACKS.md), ADR 0017): the APK carries the current one, and a newer pack can be imported through the system file picker, without network access. The signature (Ed25519, in signify's format) is checked before anything is read, and a pack is never replaced by an older one. A *Data sources* screen shows each dataset's date and licence notice and the pack's fingerprint, and the overview warns when the data is more than six months old. Every entry that names a company records its evidence and can be disputed publicly (ADR 0015).
- **Network usage per app** (ADR 0022): bytes received and sent, for mobile data (all SIMs together) and Wi-Fi, with the part Android counted as background, over the last 30 or 7 days, read from `NetworkStatsManager`. It needs the *Usage access* special permission, which the app explains and asks for but never requires. Only totals for the period are read, never which app was opened when, and nothing is kept. Android counts per user ID, so apps that share one are shown together and never split; traffic routed through a local proxy app counts under that app; tethering, removed apps and the system get lines of their own. Sizes use the step of the phone's own data-usage screen, so that the two can be compared: 1,024 in AOSP, 1,000 on Samsung phones, measured per vendor. The overview lists the apps that used the most.
- **Apps not opened for a long time** (ADR 0022): the last time each app was visible or ran a foreground service, from `UsageStatsManager`. Apps not opened for 90 days that still hold a sensitive permission, special access, VPN permission or background data use are listed for the remediation plan, with a link to Android's own page of unused apps; "not opened" is stated as a fact, and apps that work without being opened, such as keyboards and VPNs, say that it means little.
- **The guided check** (ADR 0025): on an app's page, the user names one activity, Datapavan reads the app's counts, opens the app, and reads again when the user returns, at least 15 seconds later and with no query in between, checking against the phone's live totals that Android's count is up to date. It shows received and sent bytes per minute and the background share; for activities that only receive, sent bytes as a share of received ones next to what acknowledgements and requests alone take (about 0.5 to 3 %). Two facts need no comparison: an app installed and never opened that used data, and background sending by keyboards, live wallpapers and home screens. Nothing is an alert, nothing is kept, and no string judges an app.
- **Plain-language card per app:** what it can access, what trackers it carries, how much it sends, and what the user can do about it, at the top of the app's page (ADR 0027).
- **Structure** ([ADR 0027](decisions/0027-app-structure-and-settings.md)): four destinations in a navigation bar (summary, apps, phone, network); the app list with search, filters and orders; sections on an app's page that open and close; settings for appearance and language on every supported Android version, and the pages about the app itself.
- **Remediation plan:** findings become a short queue of actions ordered by how much risk each removes, at a light, medium or strict level, each previewed and confirmed in one tap, recorded in a journal and reversible. A safety floor protects the phone's core functions at every level. In v0.1 an action opens the right system screen; the Device Owner edition applies the same plan by itself. Design: [REMEDIATION.md](REMEDIATION.md). v0.1's part ([ADR 0026](decisions/0026-remediation-plan-v0.1.md)): items from the phone's debugging and certificate authorities, apps with access that can control the phone, doubtful copies, apps that install apps or contain a traffic-sharing SDK, apps not opened for 90 days that still hold something, and, at the strict level only, preinstalled apps; in three classes by what the action removes, then trackers' purpose, time not opened and name, with no score; sessions of five cards; a care step before control access and before preinstalled apps; a safety floor computed on the phone (default apps, keyboards, screen readers, device owners and preinstalled admins, the installer and permission controller) plus `data/remediation/floor.tsv` by function; and a journal that reads each item again when the user comes back, records what actually changed, says what has come back since, offers undo through the same screen and asks once, three days later, whether everything still works.

### v0.2 "Watch": local VPN, observe only

- Connection log per app: destination domain, IP, organisation (from an offline IP-to-ASN database), bytes, time, and foreground/background state.
- A timeline answering "who did this app talk to?", with tracker destinations flagged.
- Chained mode closes inbound access from the VPN provider's network and flags proxy-like behaviour, including the circumvention tool's own connections (see [VPN.md](VPN.md)).
- Apps that bypass Datapavan's resolver (their own encrypted DNS, hard-coded IPs) are flagged; TLS fingerprints identify the client library behind a connection.
- **Sensor activity log:** recording sessions of the microphone (`AudioManager` recording callbacks) and camera availability changes, with time and screen state, and an alert when either is used while the screen is off. Android redacts the recording app's identity for other apps, so it is inferred from the foreground app and running services, and the UI says so. A feasibility spike comes first.
- **Advanced mode (optional):** `GET_APP_OPS_STATS` and `DUMP` are development permissions, so the user can grant them once over USB (`adb shell pm grant`). Datapavan then reads Android's own per-app history of microphone and camera use, the record behind the privacy indicator and dashboard, and the audio and camera services' logs, and names the app exactly, including wake-word listening by voice assistants. A guide turns USB debugging on for the grant and off again, and the app checks that it is off. This needs its own ADR before it ships.
- **Cross-checks:** Datapavan reports contradictions between two independent records. Sensors: its own log against Android's app-op history (advanced mode). Network: Android's per-app accounting (`NetworkStatsManager`) against the bytes the VPN saw; a surplus on Android's side is traffic that went around the VPN. Both records come from the same operating system, so a compromised system can falsify both; only hardware can be fully independent (stage 3).
- **Unusual behaviour:** during the observation period, the engine learns each app's normal traffic shape on this device: upload-to-download ratio and upload rates, on screen and in the background. Deviations are reported as observations, never as accusations. Encrypted traffic still has a shape: compressed audio is a steady, low-rate upstream of small packets at regular intervals; photo and video uploads are large upstream bursts; media-upload servers often have recognisable names. A deviation that coincides with microphone use in the sensor log is reported with higher priority. A spike on the A40 with labelled activities (a voice message, a photo post, plain scrolling) measures how reliable this is before it ships. A baseline learned on the device only detects change, so destination categories, lab reference measurements and the developer's declared data-safety label cover leaks that are present from the first day (see [VPN.md](VPN.md)).
- Apps that keep their own always-on connection instead of the system push service are flagged.
- Nothing is blocked yet. This lets us check accuracy and battery cost before we take control.

### v0.3 "Guard": blocking

- Network access per app on or off, separately for Wi-Fi, mobile and background.
- Tracker-domain blocking: global, with per-app exceptions.
- Safe defaults, one-tap undo, and a "this app broke" path that guides the user to the rule responsible.
- **"Notifications yes, hidden uploads no":** per app, network access only while the app is on screen. Push notifications arrive through the system's push service, which holds one connection for all apps and wakes an app briefly; in that window the app cannot use the microphone or camera, and with this rule it cannot upload either. Messengers that fetch the message text themselves may show notifications without text, or late, so the rule is chosen per app.

### v0.4 "Report"

- A weekly plain-language report, exportable as PDF or JSON.
- **GDPR helper:** for each company whose trackers were observed, draft a GDPR Article 15 data-access request that the user can send. Each observation is a concrete, defensible reason to ask "what do you hold about me?"

### Later (stage 2 preview; full plan in [ROADMAP.md](../ROADMAP.md))

- **Enterprise flavour in Device Owner mode:** disable system apps, enforce always-on VPN, and apply policies at fleet scale.
- **Work-profile isolation helper:** put Meta and other high-tracking apps in a separate profile without a factory reset, and pause the profile when they are not in use.
- **Enforced permissions:** microphone, camera and location stay denied for chosen apps.
- **AI-data guard:** watch apps and system AI services that can read the screen, notifications or keyboard input.

## 6. Architecture

```
+-------------------------------- Android app (Kotlin) --------------------------------+
|  UI (Jetpack Compose) · onboarding & permissions · reports · rules editor             |
|---------------------------------------------------------------------------------------|
|  Audit module            : PackageManager, DEX scanner, NetworkStatsManager           |
|  VPN host (VpnService)   : tunnel lifecycle, socket protect(), owner-UID lookup       |
|  Local store             : SQLite, encrypted; key held in Android Keystore            |
|------------------------------  JNI (jni crate, no JNA)  ------------------------------|
|  Rust core  (libdatapavan)                                                            |
|   packet parser · flow table · DNS & TLS-SNI extraction · rule engine · statistics    |
|   TCP/UDP forwarder through Android's own TCP stack (ADR 0012)                        |
+---------------------------------------------------------------------------------------+
```

The picture shows the parts, not the packages. Since [ADR 0029](decisions/0029-network-access-for-v0.2.md)
the VPN host and the forwarder live in Watch, a separate app with `INTERNET`, and the audit app reads
Watch's log through a one-way interface and never holds `INTERNET` itself.

### 6.1 Why a Rust core

- **Memory safety where it matters most.** The core parses untrusted bytes from every app and every server. A parser bug in C or C++ here becomes a security hole on the user's phone.
- **One engine for all three stages.** The same library runs inside the VpnService app (stage 1), the Device Owner flavour (stage 2), and later as a system daemon in our own hardened OS (stage 3). Platform code stays thin.
- **Plan B:** the Go gVisor netstack approach used by existing open-source Android firewalls. The spike of November 2026 chose the Rust system stack and kept gVisor as the fallback (ADR 0012).

### 6.2 Attributing traffic to apps

- **Which app?** On Android 10+, the active VPN app may call `ConnectivityManager.getConnectionOwnerUid()` for each new TCP/UDP flow. This is a Java API, so the Rust engine makes one JNI upcall per new flow and caches the answer for the flow's lifetime. The returned UID maps to a package.
- **Which destination?**
  1. DNS answers seen inside the tunnel fill an IP → hostname cache.
  2. The TLS ClientHello SNI of each new connection gives the hostname directly.
  3. QUIC Initial packets carry SNI too, but parsing them is harder (later).
  4. If no hostname is known, an offline IP-to-ASN lookup gives at least the organisation.
- **Shrinking visibility:** Encrypted Client Hello (ECH), apps with their own DNS-over-HTTPS, and Android Private DNS all hide hostnames. Step 4 is the fallback, and the UI must show plainly when a destination is "unknown".

### 6.3 DNS handling

The VPN advertises its own DNS address inside the tunnel. The core answers queries and resolves them
upstream through a protected socket, either via the network's resolver or a user-chosen DoH/DoT resolver.
Blocked tracker domains get an empty answer. If the user has Android Private DNS on, onboarding must
detect it and explain the trade-off.

### 6.4 Storage and retention

- App-private SQLite, encrypted. The key lives in the Android Keystore.
- Default retention is 30 days, adjustable by the user, with "delete everything now" one tap away.
- Nothing is ever written to shared storage, except exports the user starts.

## 7. Platform constraints and risks

| Risk | Effect | Mitigation |
|---|---|---|
| Android allows only one active VPN | Users with a commercial VPN cannot run both | Explain in onboarding; later, chain to an upstream WireGuard server |
| Private DNS, in-app DoH, ECH | Hostnames hidden | IP → ASN fallback; honest "unknown" in the UI |
| Some system traffic may bypass the VPN | Incomplete view | Say so in the UI; stage 2/3 close the gap |
| Samsung battery management kills background services | VPN stops silently | Onboarding: exempt from battery optimisation, enable Always-on VPN, show a health check |
| Battery and CPU overhead | Users uninstall | Target ≤ 3 % extra battery per day (measure on the A40); keep the hot path in Rust |
| Google Play policy: VPN apps may not manipulate ads; `QUERY_ALL_PACKAGES` is restricted | Play rejection | Ship via F-Droid, our own site and Obtainium first; consider an "Audit-only" Play flavour later |
| Google developer verification (since 2026-09-30 for participating stores in four countries; direct installs are not checked yet; global in 2027) | Apps from unverified developers cannot be installed on certified devices; registering requires sharing the developer's identity with Google | Register the maintainer's identity before v0.1; transfer to the foundation later |
| Copyright status of AI-assisted code is uncertain | Weaker licence enforcement and ownership proof | Decisions made and approved by the maintainer; all agent output reviewed before commit; AI assistance disclosed (`Assisted-by:` trailers, README); agent session logs kept privately, never committed |

## 8. Threat model (initial)

**Assets:** connection metadata, app inventory, rules, and exported reports.

| Adversary | Example | Mitigation |
|---|---|---|
| Tracking app on the same device | Tries to read Datapavan's logs | No exported components except the launcher (plus AndroidX's ProfileInstallReceiver, guarded by the system-only DUMP permission); encrypted app-private storage |
| Malicious app abusing Datapavan | Sends intents to change rules | Rules change only through our own UI; all IPC is internal |
| Network attacker | Tampers with blocklist updates or data packs | Updates are optional and signed (Ed25519, signify's format, ADR 0017); keys pinned in the app, rotated through a chain of signed packs, and revoked by app updates; the signature is checked before parsing, and older packs are refused |
| Supply-chain attacker | Compromises a dependency or our build | Pinned dependencies with SHA-256 verification, exclusive repository content, cargo-deny advisories in CI, reproducible builds, signed releases |
| Device seizure or inspection | A phone check at a border or checkpoint; the connection log becomes evidence | No destination logging for flows chained through a circumvention proxy (default); selectable retention, including none; one-tap wipe |
| State network observer | Sees that a device runs Datapavan (for example through list-update requests) | List updates are optional and can be imported as files; no other network traffic of our own |
| Malformed or hostile input | Packets, DEX files of other apps, attestation certificates or data packs crash or exploit a parser | Rust; fuzzing of all parsers (`cargo fuzz`, also in CI); the forwarder fails closed |

Beyond its own assets, Datapavan protects the user from untrusted VPN apps: remote control, modified
copies of known tools, hidden proxy SDKs, inbound access from the VPN network, and interception through
user-installed certificate authorities. See [RESTRICTED-REGIONS.md](RESTRICTED-REGIONS.md).

## 9. Data sources

The enterprise flavour will be commercial, so every dataset must allow commercial use. Licences were
checked against each source on 2026-10-29; the details and obligations are in
[ADR 0015](decisions/0015-dataset-licences.md).

| Need | Source | Licence and use |
|---|---|---|
| Attestation trust anchors and revoked keys | Google's root certificates (Android Developers documentation) and attestation revocation list | Roots: Apache-2.0, as the documentation states. Revocation list: no licence stated; facts published for verifiers; bundled since M2's hardening, released only if the legal review agrees |
| Tracker SDK signatures | εxodus tracker database | ODbL 1.0; bundled in `data/exodus` as a derivative database, with the ODbL notice in the app |
| Tracker domains | EasyPrivacy; εxodus network signatures | EasyPrivacy under CC BY-SA 3.0 or later (v0.2). HaGeZi (GPL-3.0) only after its upstream sources are checked. **Excluded as non-commercial:** Disconnect and DuckDuckGo Tracker Radar (both CC BY-NC-SA 4.0) |
| IP → ASN / organisation | IPtoASN; DB-IP Lite as fallback | PDDL 1.0; CC BY 4.0 with attribution (v0.2) |
| Official signing certificates of VPN, proxy and circumvention apps | Fingerprints the developers publish, F-Droid's reviewed metadata, signed repository indexes, and APKs from official channels, read by `data/app-signers/update.py` | Our list, CC0 1.0, in the signed data pack; each certificate records its source, date and evidence grade (ADR 0018) |
| Traffic-sharing (proxy), remote-support and screen-recording SDK identifiers | The vendors' own published SDKs, read by `data/sdks/update.py`; SDKs known only from platform or security research once Datapavan has read them in samples (εxodus has none) | Our list, CC0 1.0, in the signed data pack; each identifier records its artefact's SHA-256, evidence grade and date, and only grades 1 to 3 ship (ADR 0019) |
| Reference traffic measurements | The project's own lab phones | Our data; published with the reports |
| Declared data-safety labels | Google Play listings | Not collected automatically (Play terms and robots.txt). The app links to the listing; the lab cites labels by hand; at scale, DSA Article 40(12) or Google's permission |
| TLS client fingerprints | JA3 and JA4, computed by our own code | BSD-3-Clause (v0.2). **Excluded:** JA4+ (FoxIO License, no commercial use without an OEM licence) |

## 10. Tech stack

- **Android:** Kotlin, Jetpack Compose (the only UI dependency), minSdk 29, compileSdk and targetSdk 37, Gradle version catalog, no Google Play Services. Application ID `org.visadahyu.datapavan` (permanent). ABIs: `arm64-v8a` (phones), `armeabi-v7a` (phones whose Android is 32-bit, common among low-cost models) and `x86_64` (emulator).
- **Core:** Rust pinned in `rust-toolchain.toml`, built with `cargo-ndk` and NDK r30. Libraries are 16 KB page-aligned, which devices with 16 KB memory pages (supported since Android 15) need and Google Play requires. Two crates: `datapavan-engine` (all logic; `unsafe` forbidden by the compiler) and `datapavan-jni` (the only place `unsafe` is allowed; one small function per export).
- **Bridge:** direct JNI through the `jni` crate. We chose it over UniFFI because UniFFI's Kotlin bindings depend on JNA (about 1.5 MB, and reflection-based), while our JNI surface stays tiny: a version call today, and start/stop/query for the engine later. Netstack candidates to evaluate in the spike: `smoltcp`, `ipstack`.
- **Supply chain:** Google's artifact groups may come only from Google's repository and everything else only from Maven Central (`exclusiveContent`); Gradle dependency verification (SHA-256 of every artifact, generated from an empty Gradle home); the Gradle distribution is pinned by checksum and the wrapper jar is validated in CI; native libraries are built with remapped paths and a controlled cargo environment; `Cargo.lock` is committed and every build uses `--locked`; `cargo deny` checks licences, sources and advisories.
- **Quality gates:** `scripts/check.sh` runs everything that CI runs. That covers rustfmt; Clippy (pedantic, warnings as errors) for the host and both Android targets; Rust tests; cargo-deny; Android Lint for debug and release (warnings as errors); unit tests; APK and bundle builds; the forbidden-permission guard, wired into the manifest pipeline so no build path can skip it; and a check that every APK carries the Rust library with its JNI export.
- **CI:** GitHub Actions (actions pinned by commit SHA), calling the same `scripts/check.sh` as local builds, then, on an Android 15 emulator, `scripts/smoke.sh` (the audit overview appears, the app holds no INTERNET permission, and it does not crash) and `scripts/verify-audit.sh`, which installs a test fixture app built from `scripts/fixture-app` with the SDK's tools only, gives it and the device risky access over adb (an enabled accessibility service on a VPN app, the right to install apps, sensors, a user-installed certificate authority) and checks that the audit reports each one; and `scripts/verify-datapack.sh`, which imports test packs through the system file picker (a damaged one, a newer one, the same one again) and checks that the imported pack is still used after a restart. Both need only adb, so they add no test dependencies; the smoke test also runs against a phone. Then `scripts/screenshots.sh` takes screenshots of the overview in every UI language and both pseudo-locales, kept as a build artifact, and checks each screen's accessibility (every tappable element has a label for screen readers and is at least 48 dp). A separate workflow fuzzes every Rust parser (`scripts/fuzz.sh`, cargo fuzz on a pinned nightly): for eight minutes in all when a working branch changes the engine, and for forty minutes every week on `main`, shared evenly among the targets, with a corpus that grows from run to run. CI skips pushes that change only documentation, and a fast-forward of `main` to a commit that already passed on its working branch.
- **Quality:** Kotlin and Rust unit tests, parser fuzzing, the emulator smoke test, and a manual test matrix on the A40 and A56.
- **Release:** reproducible builds (`scripts/reproducible.sh` builds a commit twice from fresh clones in different directories and compares the APKs), F-Droid store texts in `fastlane/`, and APKs signed offline ([RELEASE.md](RELEASE.md)).
- **JDK:** Gradle runs on JDK 21, pinned through Gradle's daemon JVM criteria.

## 11. Internationalisation

Adding a language must be a mechanical step: add translations, with no code changes. Right-to-left (RTL)
support is built in from the first commit, because retrofitting it later touches every screen.

**Launch languages** (ADR 0030): English (source), French, German, Spanish, Russian, Simplified Chinese,
Arabic and Persian. Persian is the RTL reference language, reviewed by a native speaker. The others are reviewed
by independent AI models, and corrections from native speakers are welcome.

**Rules for code**
- All user-visible text lives in string resources. Lint fails on hard-coded text in XML; Compose text literals are caught in review (a custom Lint rule may follow).
- Plurals and variables use ICU/Android plurals, never string concatenation. Arabic, for example, has six plural forms.
- Layout uses start/end, never left/right. Directional icons are auto-mirrored. Logos and brand marks are not.
- **Bidi isolation for technical tokens.** Datapavan constantly shows domains, IP addresses, package names and byte counts inside translated sentences. Every such left-to-right token is wrapped in a Unicode left-to-right isolate (LRI … PDI, via `isolateLtr()`) so that it cannot scramble an RTL sentence.
- IP addresses, domains and package names are tokens, not numbers. They are never localised, and keep Latin digits in every locale.
- Numbers, dates and byte sizes use the locale's formatters.
- Layouts must survive about 30–40 % text growth (German is typically the longest).

**Testing**
- Debug builds enable the Android pseudo-locales `en-XA` (accented, longer text) and `ar-XB` (RTL). This tests layout before any translation exists.
- CI takes screenshots of the audit overview in every language, `en-XA` and `ar-XB`, with an accessibility check of each screen (`scripts/screenshots.sh`; app-specific languages need Android 13, so it runs on the Android 15 emulator).

**Language selection:** per-app language through the system setting on Android 13+, generated by
`locales_config`, plus an in-app picker on older versions.

**Translation workflow:** a Weblate instance (e.g. Hosted Weblate's free plan for libre projects), with English as the source. Machine
translation (e.g. DeepL) may only appear as a suggestion, marked "needs review". Each language keeps a
short glossary of key terms (tracker, permission, background, and so on), so the plain-language promise
holds in every language.

## 12. Repository layout

```
datapavan/
  README.md, ROADMAP.md, CHANGELOG.md, SECURITY.md, PRIVACY.md, CONTRIBUTING.md, CODE_OF_CONDUCT.md
  docs/
    DESIGN.md          this document
    VPN.md             local VPN design (v0.2, v0.3)
    REMEDIATION.md     the remediation plan: levels, actions, safety floor, evidence
    DATA-PACKS.md      signed data packs: format, checks, keys, publishing
    RESTRICTED-REGIONS.md
    FOUNDATION.md      foundation charter principles
    NAMES.md           history and meaning of the names
    decisions/         architecture decision records (ADRs)
    spikes/            feasibility spikes and their findings
  android/             Android app (Kotlin); Gradle project root
  core/                Rust workspace: engine/ (no unsafe) and jni/ (bridge); fuzz/ (cargo fuzz targets, nightly, not in the workspace)
  brand/               logo SVGs and brand guide
  scripts/check.sh     all quality gates; CI calls it
  scripts/smoke.sh     smoke test on an emulator or phone over adb; CI calls it
  scripts/verify-audit.sh   end-to-end check of the audit's findings on an emulator; CI calls it
  scripts/verify-datapack.sh   end-to-end check of data pack imports through the file picker; CI calls it
  scripts/datapack-test.py  signs test packs with the public test key in scripts/testdata (debug builds only)
  scripts/fixture-app/ test app with risky access, built without Gradle, for verify-audit.sh
  scripts/screenshots.sh    screenshots in every language with an accessibility check (a11y-check.py); CI calls it
  scripts/fuzz.sh      runs every fuzz target; CI calls it
  scripts/compare-dex.sh    compares the DEX parser with the SDK's dexdump on real APKs
  scripts/compare-exodus.sh compares the tracker scan with εxodus reports for the same app versions
  data/                bundled dataset snapshots, each with LICENSE, SOURCE and its converter (ADR 0015): attestation/ (Google's attestation roots and revocation list), exodus/ (tracker signatures), app-signers/ (official signing certificates of VPN, proxy and circumvention apps), sdks/ (traffic-sharing, remote-support and screen-recording SDKs), sdk-needs/ (SDK capabilities that need a system service, and the certificates of those services), owners/ (who runs SDK services, who controls which company, who publishes which app), system-keys/ (system signing keys that cannot be trusted: AOSP's public test keys, Google's development keys and the platform keys Google listed as leaked); CORRECTIONS.md says how to dispute an entry; PACK holds the data pack's sequence, date and keys
```

## 13. Milestones

### 13.1 v0.1 "Audit"

| # | Milestone | Done when |
|---|---|---|
| M1 | Skeleton | Android app and Rust core build together; CI green; app opens on the emulator and the A40 (A56 testing deferred, ADR 0011); string resources, RTL support and pseudo-locales in place from the start; brand marks and app icon |
| M2 | App inventory and permission audit | Matches what system Settings shows, checked on the A40 and the emulator; the VPN risk checks fire for a test app that holds remote-control access, a user-installed certificate authority, and enabled debugging; the integrity check reports the A40's locked bootloader and verified boot; the preinstalled Meta system apps on the A40 are listed with their state |
| M3 | Tracker SDK scanner | For 20 popular apps whose installed version has a published εxodus report, every tracker in the report is found (embedded or referenced), and every other difference is explained (APK splits, see the [comparison spike](spikes/2026-10-m3-exodus-comparison.md)); a re-signed copy of a known circumvention tool is reported as not genuine |
| M4 | Network usage per app | Byte counts within 5 % of the Settings data-usage screen |
| M5 | Plain-language UI and first release | v0.1 published on GitHub in eight languages, and submitted to F-Droid; manifest has **no INTERNET permission**; build is reproducible |

### 13.2 v0.2.0 "Watch": the connection log

v0.2 comes in three releases ([ROADMAP.md](../ROADMAP.md)). This plan covers the first: Watch, the
separate app of [ADR 0029](decisions/0029-network-access-for-v0.2.md), with its packet engine and a
connection log per app that the audit app reads. 0.2.1 (next to circumvention tools) and 0.2.2
(behaviour) get their own tables once 0.2.0 is out. The milestones are named W1 to W6, so that they
are not confused with v0.1's M1 to M5, which the ADRs cite.

**Before W1:**

- **The battery baseline:** the Galaxy A40 for a night and a day without a VPN, to compare with the
  idle night under the spike's engine ([spike](spikes/2026-11-packet-engine.md), "Left for Watch
  itself"). W6's battery target is measured against it.
- **Watch's permissions,** in an ADR of their own, as ADR 0014 did for v0.1: each permission, why, and
  what fails without it, read for every Android version from 10 to 17. Watch needs `INTERNET` and, on
  Android 17, `ACCESS_LOCAL_NETWORK` (spike, finding 7). Proposed: Watch records the app's UID only,
  and the audit app, which already holds package visibility and usage access (ADR 0014), turns UIDs
  into apps and flow times into foreground or background. Watch then needs neither, and knows the
  least it can.
- **The IP-to-organisation dataset,** under ADR 0015: candidates (among them iptoasn.com's table, DB-IP's
  IP to ASN Lite, and tables built from RIPE RIS or RouteViews data) are compared for licence,
  coverage and freshness before one is chosen. It ships like the other datasets, with LICENSE, SOURCE
  and a converter, and is updated through data packs (ADR 0017).

| # | Milestone | Done when |
|---|---|---|
| W1 | Watch's skeleton | A second Gradle module, `:watch`, package `org.visadahyu.datapavan.watch`, signed with the same key. Both APKs come from one build, CI is green, and each is reproducible on its own. The build fails if the audit app gains `INTERNET`, as now, or if Watch's manifest holds anything outside its permissions ADR. Watch opens on the emulator and the A40 with strings in all eight languages, RTL and pseudo-locales from the start, and an icon from the brand marks. Its tunnel starts and stops. |
| W2 | The packet engine in the product | The system-stack forwarder moves from the spike into `core/`, with `unsafe` forbidden (ADR 0006) and every parser fuzzed in CI. It holds each app's SYN until the owner lookup and the protected upstream connection are done; UDP goes through a NAT table with idle timeouts; a segment of an unknown connection gets a reset; unreachable destinations get ICMP and ICMPv6 answers; a network switch re-binds the upstream sockets without dropping the tunnel. An end-to-end test in CI, grown from the spike's workload app, carries TCP and UDP through Watch and finds the owner of every flow, connect-and-close and refused connections included. It passes on emulators with Android 10 and 12 to 17 and on the A40, and IPv6 is checked end to end on a network that has it. The engine adds at most 1 MB per ABI ([VPN.md](VPN.md)). |
| W3 | A name for every flow | Watch's resolver answers inside the tunnel and asks the network's resolver through a protected socket. Watch never lowers what the phone had: where Android spoke DNS over TLS to the network's resolver (Private DNS on "automatic"), Watch's upstream does too, and strict Private DNS is detected and explained. Each flow is named, in this order, from the DNS answers Watch served, the TLS server name, the QUIC Initial server name, or the organisation in the offline dataset, and otherwise shown as "unknown". Apps' own encrypted DNS to known resolvers, and plain DNS sent past the network's resolver, are recognised and named (ADR 0029). On the emulator, a fixture app's flows are named by each of the four routes. A scripted session of ten popular apps on an emulator with test accounts, run once under Watch and once under PCAPdroid, the usual tool for logging connections without root, leaves no larger share of flows unnamed under Watch than under PCAPdroid. |
| W4 | The connection log | Each flow is stored with the app's UID, the name and where it came from, IP and port, protocol, organisation, bytes each way, and start and end time. The store is app-private, encrypted SQLite, its key in the Android Keystore. Retention is none, 1, 7 or 30 days (30 by default, §6.4), with a one-tap wipe. Tests show that the database cannot be read without the key, that no destination reaches logcat, and that the wipe leaves nothing behind. Over a scripted emulator session, each app's bytes in the log are within 5 % of Android's own count for that app, the bar of M4, once ADR 0022's open check says how Android counts traffic that passes a VPN. |
| W5 | The audit app reads the log | Watch offers the log through a read-only, versioned interface that only an app signed with the same key may use, and takes nothing from the audit app (ADR 0029). The audit app names the apps behind the UIDs, where a flow older than the app that now holds its UID belongs to "an app since removed", and marks each flow foreground or background from usage access when it has it. Each app's page answers "who did this app talk to?" as a timeline, with tracker destinations flagged from the εxodus network signatures. Tests: an app signed with another key gets nothing; the audit app works unchanged without Watch; where the log would answer a question, the audit app offers Watch with the same fingerprint check as for itself. The new screens pass the accessibility check in all eight languages (`scripts/screenshots.sh`). |
| W6 | Onboarding and the 0.2.0 release | Onboarding covers the VPN consent, Android 17's local-network permission, strict Private DNS, the always-on VPN with "block connections without VPN" ([VPN.md](VPN.md)), and battery managers, Samsung's first, with guides for other vendors. A Quick Settings tile turns Watch on and off. A day of ordinary use on the A40 costs at most 3 % extra battery against the baseline. The sentence of ADR 0029 is taught in the self-check, the store texts, RELEASE.md and the website. Store texts and changelog are translated and reviewed in eight languages (ADR 0030); both apps are in `data/app-signers` with their fingerprints; a review against the threat model (§8) covers what Watch adds. 0.2.0 is published on GitHub with both APKs, on the website and through Obtainium. F-Droid follows [CHANNELS.md](CHANNELS.md); Google Play gets only the audit app for now (ADR 0029, ADR 0031). |

The order is W1, W2, then W3 and W4 side by side, then W5 and W6. Tests on the A40 use the workload
and fixture apps and the battery measurement; sessions with popular apps run on emulators with test
accounts, so that no one's personal data enters a test log. Phones from other vendors are still
missing: until one is found, W2's device test covers Samsung and the emulators only, and the release
notes say so.

**Not in 0.2.0:** chaining through a circumvention tool's proxy, a WireGuard upstream, a DNS resolver
of the user's choice with the strict DNS setting, per-tool guides, proxy-like behaviour flagged, and
tracker blocking that the user turns on (0.2.1); the sensor log, the cross-checks, learned traffic
shapes and apps that keep their own push connection (0.2.2); TLS fingerprints of client libraries
(later in v0.2).

## 14. Decisions

Each decision is recorded in full, with context and consequences, as an ADR in
[decisions/](decisions/README.md). This table is the summary.

| ADR | Decision | Status |
|---|---|---|
| [0001](decisions/0001-apache-2-licence.md) | Apache-2.0 licence | Accepted |
| [0002](decisions/0002-codeberg-with-github-mirror.md) | Codeberg as home, GitHub as read-only mirror | Superseded by 0013 |
| [0003](decisions/0003-minimum-android-10.md) | Minimum Android 10 (API 29) | Accepted |
| [0004](decisions/0004-ui-languages-and-rtl.md) | Languages at launch, changed by ADR 0030; RTL from the first commit | Accepted |
| [0005](decisions/0005-english-documentation.md) | Documentation in English only | Accepted |
| [0006](decisions/0006-rust-engine-unsafe-forbidden.md) | Rust engine with `unsafe` forbidden; separate JNI crate | Accepted |
| [0007](decisions/0007-direct-jni-over-uniffi.md) | Direct JNI instead of UniFFI | Accepted |
| [0008](decisions/0008-gradle-dependency-verification.md) | Gradle dependency verification from an empty Gradle home | Accepted |
| [0009](decisions/0009-no-automatic-jdk-download.md) | Gradle daemon pinned to JDK 21, no automatic JDK download | Accepted |
| [0010](decisions/0010-cuneiform-brand-marks.md) | Old Persian cuneiform signs as brand marks | Accepted |
| [0011](decisions/0011-m1-test-devices.md) | M1 tested on emulators and the Galaxy A40 | Accepted |
| [0012](decisions/0012-packet-engine.md) | Packet engine for the local VPN: Android's own TCP stack through rewritten addresses, in Rust | Accepted |
| [0013](decisions/0013-github-as-home.md) | GitHub as the only home; Codeberg dropped | Accepted |
| [0014](decisions/0014-v0.1-permissions.md) | Permissions for v0.1 "Audit" | Accepted |
| [0015](decisions/0015-dataset-licences.md) | Licences of bundled datasets | Accepted |
| [0016](decisions/0016-no-user-data.md) | No data from users; learning happens in the lab | Accepted |
| [0017](decisions/0017-data-pack-format.md) | Data packs in signify's format, checked with ed25519-compact | Accepted |
| [0018](decisions/0018-app-signing-certificates.md) | Official signing certificates of VPN, proxy and circumvention apps | Accepted |
| [0019](decisions/0019-traffic-sharing-remote-support-sdks.md) | Traffic-sharing, remote-support and screen-recording SDKs | Accepted |

## 15. Names

- **Datapavan:** Old Persian *dāta* "law" + *pāvan* "protector" (as in *xšaçapāvan*, "protector of the realm"; the Median form of that title, *\*xšaθrapāvan-*, gave Greek *satrápēs* and English *satrap*). The compound is coined from two attested elements: "protector of the law" in Old Persian, and "data protector" when read in English.
- **Visadahyu:** "of all nations", from Xerxes' inscription on the Gate of All Nations at Persepolis (XPa: *duvarθim visadahyum*).
