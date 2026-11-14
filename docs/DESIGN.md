# Datapavan — Design Document

| | |
|---|---|
| Version | 0.2 (draft, revised 2026-11-14: three editions, ADR 0045; what apps sent while not in use, shown live, ADR 0046, proposed; a profile for phones that may be searched, ADR 0047, proposed; a lab probe of where stock Android leaves privacy tools blind or exposed, ADR 0048, proposed; the editions' names and one version line, the maintainer, 2026-11-14; a signing key for each edition, ready to rotate, backed up in shares, ADR 0049, proposed; mobile operators and SIM cards, ADR 0050, proposed) |
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
| Samsung Galaxy A56 | Real-world validation on a maintainer's personal phone, from later milestones (ADR 0011). Stable builds only; never unlocked | 17 |
| More vendors (needed) | Datapavan targets every Android vendor, and both phones above are Samsung. The lab needs at least a Pixel (Android's reference behaviour), a Xiaomi or Redmi phone and a low-cost Tecno or Infinix phone; the remediation evidence is kept per vendor, model and build | Various |

## 5. Roadmap for stage 1

Each release can ship on its own and is useful by itself. v0.1 is Datapavan Basic, released as Datapavan Basic
0.1.2. v0.2's network monitoring, v0.3's blocking and v0.4's reports land in Datapavan Advanced, and what of them
needs no network comes to Basic as well ([ADR 0045](decisions/0045-three-editions-of-one-app.md)). The two editions
share one version line: Datapavan Advanced 0.2.0, its first release, is built from the same commit as Datapavan
Basic 0.2.0 (the maintainer, 2026-11-14).

### v0.1 "Audit", Datapavan Basic: no VPN, **no INTERNET permission**

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

### v0.2, network monitoring, in Datapavan Advanced: local VPN, observe only

- Connection log per app: destination domain, IP, organisation (from an offline IP-to-ASN database), bytes, time, and foreground/background state.
- A timeline answering "who did this app talk to?", with tracker destinations flagged.
- Chained mode closes inbound access from the VPN provider's network and flags proxy-like behaviour, including the circumvention tool's own connections (see [VPN.md](VPN.md)).
- Apps that bypass Datapavan's resolver (their own encrypted DNS, hard-coded IPs) are flagged; TLS fingerprints identify the client library behind a connection.
- **Sensor activity log:** recording sessions of the microphone (`AudioManager` recording callbacks) and camera availability changes, with time and screen state, and an alert when either is used while the screen is off. Android redacts the recording app's identity for other apps, so it is inferred from the foreground app and running services, and the UI says so. A feasibility spike comes first.
- **Advanced mode (optional):** `GET_APP_OPS_STATS` and `DUMP` are development permissions, so the user can grant them once over USB (`adb shell pm grant`). Granting `GET_APP_OPS_STATS` does not open Android's per-app history of microphone and camera use, the record behind the privacy indicator and dashboard: on the Android 11, 15 and 17 emulators, `getHistoricalOps` gave an app holding it an empty answer for other apps' history ([platform gaps](platform-gaps/README.md), `appops-closed`, 2026-11-14). AOSP's `AppOpsService` answers that history only to the system, an instrumented caller, the permission controller or a holder of `GET_HISTORICAL_APP_OPS_STATS`. How advanced mode reads which app used the microphone or the camera, from that history or from the audio and camera services' logs through `DUMP` (not measured yet), is open until a design decides; the aim stays to name the app exactly, including wake-word listening by voice assistants. A guide turns USB debugging on for the grant and off again, and the app checks that it is off. This needs its own ADR before it ships.
- **Cross-checks:** Datapavan reports contradictions between two independent records. Sensors: its own log against Android's app-op history (advanced mode). Network: Android's per-app accounting (`NetworkStatsManager`) against the bytes the VPN saw; a surplus on Android's side is traffic that went around the VPN. Both records come from the same operating system, so a compromised system can falsify both; only hardware can be fully independent (stage 3).
- **Unusual behaviour:** during the observation period, the engine learns each app's normal traffic shape on this device: upload-to-download ratio and upload rates, on screen and in the background. Deviations are reported as observations, never as accusations. Encrypted traffic still has a shape: compressed audio is a steady, low-rate upstream of small packets at regular intervals; photo and video uploads are large upstream bursts; media-upload servers often have recognisable names. A deviation that coincides with microphone use in the sensor log is reported with higher priority. A spike on the A40 with labelled activities (a voice message, a photo post, plain scrolling) measures how reliable this is before it ships. A baseline learned on the device only detects change, so destination categories, lab reference measurements and the developer's declared data-safety label cover leaks that are present from the first day (see [VPN.md](VPN.md)).
- Apps that keep their own always-on connection instead of the system push service are flagged.
- Nothing is blocked by default. Blocking of tracker domains comes in 0.2.0 only when the user turns it on, undone in one tap, and fuller blocking waits for v0.3 ([ROADMAP.md](../ROADMAP.md)). This lets us check accuracy and battery cost before we take control.

### v0.3 "Guard", in Datapavan Advanced: blocking

- Network access per app on or off, separately for Wi-Fi, mobile and background.
- Tracker-domain blocking: global, with per-app exceptions.
- Safe defaults, one-tap undo, and a "this app broke" path that guides the user to the rule responsible.
- **"Notifications yes, hidden uploads no":** per app, network access only while the app is on screen. Push notifications arrive through the system's push service, which holds one connection for all apps and wakes an app briefly; in that window the app cannot use the microphone or camera, and with this rule it cannot upload either. Messengers that fetch the message text themselves may show notifications without text, or late, so the rule is chosen per app.

### v0.4 "Report", in Datapavan Advanced

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

The picture shows the parts, not the packages. Since [ADR 0045](decisions/0045-three-editions-of-one-app.md)
the VPN host and the forwarder live in the `:watch` library, which only Datapavan Advanced includes: Advanced
holds `INTERNET` and reads its own log, and Datapavan Basic never holds `INTERNET`.

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

- App-private SQLite whose records are sealed one by one under a key for their day; the keys live in the Android Keystore ([ADR 0037](decisions/0037-connection-log-storage.md)).
- No default retention: the user chooses at onboarding between none, 1, 7 and 30 days, and until onboarding exists the log keeps none ([ADR 0040](decisions/0040-own-safety-in-an-untrusted-environment.md)). "Delete everything now" is one tap away.
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
| App on the same device that probes loopback | Finds the circumvention tool's local proxy to learn that the user runs one, or uses a proxy with no password to learn the server's address and send traffic through it ([ADR 0041](decisions/0041-watch-visibility-and-coexistence.md), decision 5) | Watch says on its screen what the tool's proxy lets other apps do, and offers a password where the tool takes one; the chained apps' UDP goes through the tool only once the user turns it on, since no tool is known to keep other apps off its UDP relay. Traffic between apps over loopback never enters the tunnel, so Watch does not see it |
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
| IP → ASN / organisation | DB-IP Lite, checked against IPtoASN, which is the fallback ([ADR 0036](decisions/0036-ip-to-organisation-dataset.md)); our own CC0 map from AS numbers to companies in `data/owners` | CC BY 4.0 with attribution; PDDL 1.0 (v0.2) |
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

<a id="132-v020-watch-the-connection-log-next-to-circumvention-tools"></a>

### 13.2 v0.2.0, Datapavan Advanced: the connection log, next to circumvention tools

v0.2 comes in two releases ([ROADMAP.md](../ROADMAP.md)). This plan covers the first: Datapavan
Advanced 0.2.0, with the Watch service and its packet engine (planned as a separate app in
[ADR 0029](decisions/0029-network-access-for-v0.2.md), a library of Advanced since ADR 0045), a connection log per
app that the audit reads, and the ways Advanced works beside the user's VPN or circumvention tool ([RESTRICTED-REGIONS.md](RESTRICTED-REGIONS.md)). 0.2.1 (behaviour) gets its own
table once 0.2.0 is out. The milestones are named W1 to W9, so that they are not confused with v0.1's
M1 to M5, which the ADRs cite.

**Before W1:**

- **Watch's permissions,** in an ADR of their own, as ADR 0014 did for v0.1: each permission, why, and
  what fails without it, read for every Android version from 10 to 17. Watch needs `INTERNET` and, on
  Android 17, `ACCESS_LOCAL_NETWORK` (spike, finding 7). Proposed: the log records the app's UID only,
  and the audit app, which already holds package visibility and usage access (ADR 0014), turns UIDs
  into apps and flow times into foreground or background. Watch's own screens name only the user's
  tool and the apps the user picks for the chain; the ADR settles whether `<queries>` entries are
  enough for that or Watch needs package visibility, since a `<queries>` entry once missed a VPN app
  (spike, "Who owns a local proxy port").
- **The IP-to-organisation dataset,** under ADR 0015: candidates (among them iptoasn.com's table, DB-IP's
  IP to ASN Lite, and tables built from RIPE RIS or RouteViews data) are compared for licence,
  coverage and freshness before one is chosen. It ships like the other datasets, with LICENSE, SOURCE
  and a converter, and is updated through data packs (ADR 0017).
- **The table of tools:** each known tool's modes, default ports, password options and UDP support,
  signed and shipped beside `data/app-signers` (RESTRICTED-REGIONS.md), from the research of November
  2026 and the tools' own sources.
- **WireGuard,** in an ADR: an implementation in Rust inside the engine (Cloudflare's BoringTun and
  its maintained forks are the candidates) against Go's wireguard-go, which would bring back the Go
  toolchain ADR 0012 kept out. Licence, upkeep and audit history decide.

Status of the items before W1, 2026-11-09: Watch's permissions in [ADR 0034](decisions/0034-watch-permissions.md),
WireGuard in [ADR 0035](decisions/0035-wireguard-upstream.md) and the dataset in
[ADR 0036](decisions/0036-ip-to-organisation-dataset.md), all three accepted by the maintainer on
2026-11-09; the table of tools in `data/tools/` ([notes](spikes/2026-11-table-of-tools.md)). Before W6,
one question needs a closer look: Android keeps one DNS cache for all apps of a VPN network, so an app
sent through the tool or WireGuard may be given an answer the network's resolver gave another app,
possibly a censored one (ADR 0035, open question 4). A spike on 2026-11-11 settled it on the emulators
with Android 11, 15 and 17 ([notes](spikes/2026-11-shared-dns-cache.md)): the cache is shared, for
answers and negative answers alike; Android names the app that asked as the owner of each lookup; and an
answer whose time to live Watch sets to 0 is not kept. While any app is chained, Watch therefore gives
the apps every answer with a time to live of 0, answers each lookup from the app's own route, and keeps
a cache of its own per route.

Status of W1 and W2, 2026-11-09, on the branches `watch-w1` and `watch-w2`. W1 is built: its CI run
passed. W2 is built and passes `scripts/smoke-watch.sh` and `scripts/verify-watch.sh` on the emulators
with Android 11, 15 and 17 and on the A40 (Android 11), where the engine's CPU for the spike's workload
was 37.8 and 38.8 s against the spike's 42.4 and 41.4 s, back to back (`scripts/watch-lab/measure.sh`).
The release library is 533 KB on arm64. Still open for W2: the emulators with Android 10, 12, 13, 14
and 16, and IPv6 end to end on a network that has it (this one has none). Known for W4: the byte
counters count a connection only when it ends cleanly, and Watch's memory (96 MB PSS with its screen,
against the spike's 29 MB) needs a look.

W3, on `watch-w3`, 2026-11-09: flows are named from the DNS answers Watch passes on (the name the app
asked for, through CNAME chains), from the TLS server name of the app's first bytes, and last from the
organisation table of [ADR 0036](decisions/0036-ip-to-organisation-dataset.md), 2.71 MB in compressed
blocks, read in place; each name says where it came from. Decided on 2026-11-09: when Private DNS is on
"automatic" and the network's resolver speaks DNS over TLS, Android's queries pass through Watch still
encrypted, so their names come from TLS or QUIC; W8 brings a TLS client into the engine anyway (the user's
DoH or DoT resolver), and with it Watch answers Android's DNS over TLS itself and keeps both the
encryption upstream and the names, within 0.2.0. `scripts/verify-watch.sh` checks all three. Decided
later that day: the QUIC server name is read in versions 1 and 2 from a `ClientHello` put together
across packets and out-of-order CRYPTO frames (Chrome's post-quantum `ClientHello` spans two packets,
and Chrome scatters its frames on purpose), checked against the RFCs' sample packets; a name that is
only a provider's public name under Encrypted Client Hello is never shown as the destination; the
monthly table goes in a data repository of its own (ADR 0036); and the ten-app comparison is measured
against a record independent of both tools (row W3). The apps come from the Play Store on an emulator
image with Play, signed in by the maintainer with an account kept for tests; such images have no root,
so the same APKs are installed on an image with root for the owner check.

The QUIC server name is built the same evening. Watch reads versions 1 and 2, puts the `ClientHello`
together by offset across up to eight datagrams, and does not check the AEAD tag, since anyone can
compute the Initial keys; the keys and payloads match RFC 9001's and RFC 9369's samples, and
`scripts/verify-watch.sh` sends a two-datagram `ClientHello` with its frames out of order, protected
with Python's HMAC and OpenSSL's AES rather than Watch's code. The DNS answers' HTTPS records give the
public names of ECH configurations, and a hello that offers ECH under one of them leaves the flow's name
as it was and marks it hidden; a hello that offers ECH under any other name names the flow and is
marked as offering ECH, since a real ECH and GREASE cannot be told apart when the app looked its names
up past Watch (ADR 0036 records that limit). Two crates came in for it, `aes` and `sha2` from RustCrypto (MIT or Apache-2.0),
about 27 KB per ABI. Counters without destinations, readable on any phone, count the names read from
TLS and QUIC, the QUIC flows whose name could not be read, and the hellos that offered ECH or hid the
name. On the Android 17 emulator, Chrome opening Google over QUIC gave six QUIC names and no QUIC flow
left unread, every hello offering ECH as Chrome's GREASE does.

Private DNS, the same evening. On the Android 17 emulator, Android applies strict Private DNS to Watch's
network as to any other: the resolver (UID 1051) sends every app's lookups to the provider over DNS over
TLS, through the tunnel but past Watch's resolver, and Watch names those connections only by the
provider. Watch reads the setting from its own network's link properties and, while it is on, says on
its screen what this hides and what it still names; it does not ask the user to turn Private DNS off,
since that would show the lookups to the network as well (W9's onboarding guides the choice). The note
also covers "automatic" on a network whose DNS server encrypts, which the emulator cannot show: its
network's server has no DNS over TLS. The four strings were translated into the seven languages with
Android's own names for the setting, read from the emulator's Settings app, and reviewed by two other
models; one finding was settled. `scripts/verify-watch.sh` turns strict mode on and off on the emulator
and checks that Watch reads both.

An app's own DNS, the same evening (ADR 0029). A flow is marked as the app's own DNS when it is plain
DNS on port 53 to another server than Watch's, DNS over TLS or QUIC on port 853, or DNS over HTTPS on
port 443 to a known resolver's address or host name (from DNS, TLS or QUIC). The known resolvers are a
new CC0 table, `data/resolvers`, every host and address from its operator's own page, compiled into the
engine and kept out of the audit app: 60 services of 18 operators, from Google, Cloudflare and Quad9
to Alibaba, Tencent's DNSPod, Yandex and Shecan, each checked again by two other models; Mullvad's was
left out, since its page says it closed on 2026-11-02. The answers an app gets from a resolver of its
own name that app's later flows, and only that app's: the app chose that resolver and must not rename
other apps' connections through it. ECH public names come only from Android's resolver. Two counters
without destinations count the app's own plain and encrypted DNS.

Networks named after their companies, the same evening (ADR 0036, decision 4). `data/owners/asns.tsv`
maps 39 AS numbers to 17 companies of `entities.tsv`, which grew by eleven, each AS from its registry's
RDAP record and linked to its company by the company's own page or the record's contacts; one model
compiled it, two others checked it alone. A network is marked as hosting other companies' servers
unless a page of the company names it as its own: only Meta's two and Netflix's main AS are marked as
their own, and Watch names the others "a server on <company>'s network". Twitter's three AS numbers
were left out: only one contact's e-mail address linked them to X Corp. A flow named by its network
now carries the AS number and that mark, and shows Meta Platforms, Inc., not the registry's "Facebook,
Inc.". Still to build: the ten-app comparison. One run of
`scripts/verify-watch.sh` saw Watch still read strict Private DNS 20 s after the setting was restored,
right after a network switch; three tries could not repeat it, so the check now waits 60 s and, if it
fails, prints what Android itself reports for each network.

W4, on `watch-w4`, 2026-11-09: the connection log as [ADR 0037](decisions/0037-connection-log-storage.md)
decides. The engine counts each flow's bytes as they pass and hands the log a record when a flow ends,
a segment of every open flow at each quarter hour, each app's lookups to Watch's own DNS address, and
what is open when the tunnel stops; Watch seals each record under its day's key in SQLite. The screen
offers retention of none, 1, 7 or 30 days and deletes the log in one tap, in eight languages, reviewed
by two models and settled by a third. `scripts/verify-log.sh` passes on the Android 17 emulator: flows
with their bytes, no destination in the files or in Watch's logcat, an earlier day shut while the screen
is locked and open once it is unlocked, and a wipe that leaves no file and no key. How Android counts
traffic through a VPN, the open check of ADR 0022: it keeps each app's traffic on the VPN's network
under that network, with its own entry per app (type 17, transport VPN, in `dumpsys netstats`), counted
as IP packets on the tunnel, headers included, while the log counts what the apps sent and received.
So the engine now also counts each flow's IP packets as the tunnel carries them, and each app's lookups
to Watch's DNS address with their answers. Over a scripted session (6 MB down, 1 MB up, small UDP
flows, lookups) the shell's bytes in the log and Android's own count were 0.02 % and 0.00 % apart on
Android 15, 0.03 % and 0.00 % on Android 17, and 0.03 % and 0.00 % on Android 11, against M4's 5 %;
`scripts/verify-log.sh` checks it, and passes in full on all three. Android 11 prints that network as
"type=VPN" and also repeats the same traffic under the network beneath, so summing every network counts
it twice. An open check for ADR 0022 and W5: the audit app asks Android for Wi-Fi and mobile traffic
only, so with Watch on, an app's traffic may be missing from those totals from Android 12, and present
before; the audit app must say so or read the VPN's network too. Still to do in W4: the log on the A40
(verify-log.sh sets a PIN, so it runs on emulators only) and on an Android 10 emulator, whose system
image is not on this computer; Watch's memory (96 MB PSS with its screen).

W4, 2026-11-10: expiry no longer waits for traffic. It ran only when a record was written or retention
changed, so a log kept for 7 days by someone who then turned Watch off kept its old days in the file for as
long as Watch stayed off. Now it also runs when Watch's process starts, when the tunnel starts, when the
screen opens, before every read and count, and from a job about every six hours, and a day past retention is
never read back or written, even before expiry has run. Android limits the job: it decides when the job
runs, and the job does not survive a restart of the phone, since that would need the permission to start at
boot, which ADR 0034 does not give Watch; the next start of Watch's process then expires the log. Three more
defects of the same store are fixed. A batch that failed after its day key was made left that key's number
in memory without its row, so the rest of the day failed to write. A failure on the log's thread could end
Watch's process, and the tunnel with it; each one is now counted, without any destination. And yesterday's
key stayed in memory until the next write, not only until midnight. A model-based test (`LogModel`, debug
builds) runs inside Watch on the emulator, against Android's own SQLite and the Keystore. It draws random
sequences of writes, reads, the clock moving on and back, time zones, restarts, locking, changes of
retention, wipes, the expiry job, a full or failing database and a failing Keystore, and after each step
checks what must and must not be read back; `scripts/verify-log.sh` runs 300 steps of it, with a fresh seed
that it prints. On the code as it is, 50 seeds of 1500 steps each pass on Android 15; with each of the four
defects above put back in turn, it fails for 20, 18, 20 and 20 of 20 seeds. It also found a fifth defect:
with retention none and a failing Keystore, a read answered "cannot be opened" instead of "nothing". While
checking this, verify-log.sh's byte comparison failed on Android 15 (8.9 % apart). The engine wrote a TCP
flow's last segment as soon as its relay ended, but Android's stack still sends what it holds for the app
through the tunnel in the 30 s the rewriting stays, and those packets were counted after that segment: 10 of
20 downloads of 2 MB lost 5 to 26 % of their packets in the log. The last segment is now written when the
rewriting goes, and ends at the flow's last packet. All 20 downloads then carry 1.037 times their payload on
the tunnel, and over the scripted session the log and Android's count match to the byte. The 0.03 % of the
day before came from runs in which that loss did not happen; verify-log.sh now checks each download on its
own. Both scripts pass in full on Android 11, 15 and 17; the log and Android's count were 0.05 % and 0.01 %
apart on Android 11, and equal to the byte on 15 and 17. On the first run after a fresh boot of the Android
17 emulator, verify-watch.sh once found Watch's engine started over, with no crash logged; two runs after it
passed, and both scripts now print how Watch's process last ended when they fail.

The engine, the same day: its listener, on the tunnel's own address, took any connection that reached it and
matched it to a waiting upstream connection by the source port alone. Any app can reach that address
directly and pick its port, so one that hit the next fake port in the few milliseconds before the real
connection arrived would have taken another app's connection, with its bytes in the log under that app; once
Watch blocks or routes by app (W6 to W8), it would have been a way around the rule. Now the listener takes
only a connection from the fake address the engine rewrites the apps' connections to come from, which no app
can bind; anything else is closed at once and counted (a 19th counter). Fake ports are drawn at random
instead of in order, and a freed port waits 60 s before it is handed out again, so that a new SYN does not
meet the old connection in Android's TIME_WAIT. A connection whose rewriting was forgotten before Android
handed it over now ends its flow in the log at once. A unit test plays both connections on the loopback, and
`scripts/verify-watch.sh` connects the shell straight to the listener, found in `/proc/net/tcp`, and sees it
closed and counted. Both scripts pass in full with it on Android 11, 15 and 17.
Watch's screen, the same day, says of earlier days only what holds on the phone. It said always that they
open only while the phone is unlocked, which is false on a phone with no screen lock, and on one that
refused a key tied to the lock. Now it says that once the log's key pair exists, tied to the lock, on a
phone with a screen lock; on a phone with none, that they can be opened at any time and would open only
while it is unlocked with one; where the phone refused, that they can be opened at any time; before the key
pair exists, nothing; and with retention none, only that Watch keeps no record. The screen lock is read each
time the screen opens; adding one later also shuts records already kept, which verify-log.sh shows on
Android 11, 15 and 17. "Screen lock" is Android's own term in each language, from the Settings app of the
Android 17 emulator. The three new sentences were translated into seven languages, reviewed alone by two
models and settled by a third. `scripts/verify-log.sh` reads the screen: without a PIN it must not say "only
while the phone is unlocked", and with one it must.
Watch's memory, the same day. The 96 MB of W2 was the debug build with its screen: its code is not shrunk,
its Rust library not optimised, and it runs under the JIT. On the Android 15 emulator the debug build used
69 to 70 MB PSS, and the release build 23 MB, with its screen open and with the service alone (24 and 22 MB
on Android 17, 30 and 28 MB on Android 11); the emulator draws in software, so a phone adds its screen's
buffers while the screen is open. After 500 TCP connections through the release build, with 510 records in
the log, its native heap had not grown (8.7 MB before, 5.1 MB after). Measuring the release build found that
it did not work at all: R8 had renamed the three methods the Rust library calls back by name (to protect a
socket, to ask a flow's app, to hand the log its records), so no connection passed, no flow had its app, and
the log stayed empty. Every check until then ran the debug build, and none ran the release build.
`proguard-rules.pro` now keeps them, the build fails if the APK's code lacks any of them (verifyApkRelease),
and `scripts/verify-watch-release.sh`, in CI, signs the release build with a key made for the run, turns
Watch on from its screen, and checks traffic, each flow's app, the log and a memory budget of 48 MB; it
passes on Android 11, 15 and 17. Still to do: the release build's memory on the A40, with a real screen.

Before W6, 2026-11-10, after W3 and W4 were merged into `main`: each new UDP flow, so each lookup, was
opened inside the engine's packet loop, which waited for Android to name the flow's app and for the
protected socket, about 3 ms in the day and 11 ms in deep idle by the spike's numbers; meanwhile no packet
of any app moved. A new UDP flow is now opened in a task of its own, as TCP's are: its first datagrams wait
in its entry of the table, at most 32, and leave in the order the app sent them once the socket is there, so
the app is still known before the first one leaves, as the rules of W6 to W8 need. A test plays two flows
through a fake tunnel while Android takes 600 ms to name one: the other flow's answer comes back at once,
and the slow flow's two datagrams then leave in order. Before the change the same test failed, the answer of
the other flow coming only after the slow flow's. verify-watch.sh, verify-log.sh and verify-watch-release.sh
pass with it on Android 11, 15 and 17.
The same day: the engine forgot a TCP connection after 600 s without a packet, open or not, while its relay
lived on, so the next line from the server was dropped and the app's own was answered with a reset. Apps
keep push connections open with heartbeats many minutes apart, and RFC 5382 asks a NAT to keep an
established connection at least 2 h 4 min. Seen on the A40 on 2026-11-09: a line after 684 silent seconds
never arrived. Now a connection that Android's stack handed to the relay is forgotten only by the relay,
when the connection ends; the sweep keeps to those never handed over. Since Android's stack answers the
app's own keepalives inside the phone, the upstream socket has the kernel's keepalive on, so that a server
gone without a word still ends the connection (after about 2 h 11 min by Linux's defaults). The same run on
the Android 15 emulator after the change: the line after 690 silent seconds arrived, the app's own line
reached the server, and the server held nothing unacknowledged. Unit tests check that a relayed connection
outlives three hours of silence while one never relayed is forgotten.
Also before W6: `core/net/src/engine.rs`, 2,285 lines, is split by moves only into `engine.rs` (the public
types, `Engine`, `Config`, `Platform`, `Counters`, the packet loop and the tests) and five modules beside
it: `naming` (what names a flow), `logbook` (each flow's bytes, the segments and the logger), `tcp` and
`udp` (the two paths), and `upstream` (the engine's own connections, the one place W6 and W7 extend). A
line-by-line comparison of the code before and after finds only imports, visibility within the engine and
line wrapping changed.
The end-to-end check after a network switch failed on CI in four runs of five that day, and the reasons lay
in the check, not in the engine. CI's emulator has Wi-Fi as its default network and brought mobile data up
only once Wi-Fi was gone, at times not within 40 s, so Android had no network ("Active default network:
none") and nothing could pass, with Watch or without; the emulators on this computer had no Wi-Fi at all, so
their switch had changed nothing. And seven checks ran `flows | grep -qE` under `pipefail`: a `grep -q` that
found its line early stopped reading, the command before it failed on SIGPIPE, and a flow in the list looked
missing. `scripts/verify-watch.sh` now keeps mobile data up beside Wi-Fi during the switch, as most phones
do, waits for Android to have another default network, prints Android's networks before and after, and reads
lists whole before searching them, again for a few seconds while Android names a flow's app. On this
computer's Android 15 emulator with Wi-Fi as its default, the switch now really happens, and the check
passes in full.

W6, on `watch-w6`, 2026-11-11, after the maintainer kept 0.2.0's whole scope (W5 to W9). First the DNS
spike above: the apps' shared cache is kept out of the way with answers whose time to live is 0. Then the
SOCKS5 client, `core/net/src/socks5.rs` (RFC 1928, with RFC 1929's password): `CONNECT` to an address or a
name, which the tool then resolves, and `UDP ASSOCIATE` with its datagrams; `BIND` has no command at all.
Watch offers the password method only when it has credentials, so a tool that takes no password still
answers, and a password never shows in a `Debug` output. The parsers take any bytes and are fuzzed (target
`socks5`); `core/net/tests/socks5.rs` runs the client against a small proxy in the same process, whose
bytes are written by hand from the RFCs, for an address, a name, the password asked for, refused or not
offered, the proxy's failures, something that is not a proxy, and a UDP relay, announced or as 0.0.0.0.
The engine does not use it yet: routing by app comes next. How chained apps' lookups are answered is
[ADR 0038](decisions/0038-dns-of-chained-apps.md), accepted the same day: stand-in addresses from
198.18.0.0/15 for A questions, the name sent to the tool, no stand-in for AAAA, other record types through
the tool to Quad9 without blocking, ECH kept.

W6's routing by app, the same day, in the engine (`core/net/src/engine/chain.rs`, `lookups.rs`, `udp.rs`,
`tcp.rs`): `Engine::chain` turns a chain on with the tool's proxy, its password, its UID and the chained
apps (or every app but the tool), and off. While it is on, a flow's route waits for Android to name its app,
so that a chained app's connection never starts directly. Chained apps' TCP goes through `CONNECT`, their
UDP through a `UDP ASSOCIATE` whose connection stays open for the flow, by the name behind a stand-in
(`core/net/src/standins.rs`) or by address; a tool without UDP sends their UDP nowhere. Their lookups are
answered by Watch (`core/net/src/answers.rs`): a stand-in for A, no data for AAAA, the name for a reverse
lookup of a stand-in, and any other question from Quad9 through the tool, rebuilt without address hints.
The tool's own traffic and the other apps' go directly; a flow whose app Android cannot name goes nowhere,
since it could be either. A stopped tool gets the app an ICMP error, and nothing leaves directly. Chained
flows reach the log with their app and bytes but no destination, unless the user asks for them. Every
answer has a time to live of 0 while a chain is on, and direct apps' repeated lookups are answered from
Watch's own cache (`core/net/src/dnscache.rs`), so the network's resolver is asked no more often than
before. `core/net/tests/chain.rs` runs the whole engine on a pair of datagram sockets with an in-process
proxy for UDP and lookups; TCP through the tool needs Android's stack and is checked on the emulator
(W6's CI test, next). Not yet: Watch's screens and the finding of the tool (Kotlin), and the lab's
measurements of ADR 0038.

W6's side in Watch, the same day (`android/watch/.../chain/`, `ui/ChainSection.kt`). The build copies the table
of tools into Watch's assets, and Watch declares the one launcher `<queries>` entry of ADR 0034. Watch looks
for the installed tools of the table that have a proxy mode, greets only their known SOCKS5 ports (also
shifted by the Android user's number), and asks Android who owns each answering port; a port another app
holds is not the tool's. Its screen says which tool it found and on which port, or that none is installed,
or that the tools installed have their proxy off; it has the switch that sends every app, or the apps the
user picks, through the tool; a user name and a password Watch made for the tool's proxy, kept encrypted
under a Keystore key and copied as sensitive, so that other apps on the phone cannot use the proxy; notes
when the tool carries no UDP or strict Private DNS sends lookups past Watch; and the switch for chained
destinations in the log, off by default. With the chain on and the tool silent, it says the apps wait and
nothing of theirs goes out directly. The service hands the chain to the engine before any traffic, from the
proxy where the tool last answered, then looks again in the background. The 18 strings are in eight
languages, with Android's own terms from the Settings app, reviewed under ADR 0030's process. Checked by
hand on the Android 15 emulator with `scripts/watch-lab/socks5.py` on this computer standing in for the
tool: TCP by address and by stand-in name, UDP through the relay, and a stopped proxy.

W6's check in CI, the same day: `scripts/verify-chain.sh` with a test tool on the phone (`scripts/test-tool`,
a SOCKS5 proxy with a password on the loopback, in a foreground service), which debug builds of Watch know
from `src/debug/assets/tools-test.tsv`. Watch must find it by itself, with Android naming it as the port's
owner and the password it wants; with adb's shell chained through it, TCP reaches the test server by address
and by a name only the tool resolves, through a stand-in, UDP goes through its relay, the tool's own
connections go directly under its own UID, and a wrong password is refused. Then the tool stops: the shell's
TCP and UDP fail, and a sentinel on the computer, outside Android, sees none of them, while it does see a
control connection from Watch's own UID, which goes directly. The emulator's own capture (`network capture`
in its console) was the first idea, but it does not see what goes over the emulator's Wi-Fi. Passes on the
emulators with Android 11, 15 and 17. Two faults the test found: Android's loopback address of choice is
`::1`, so a tool listening "on the loopback" in Java may not be on 127.0.0.1 where the table says; and a
proxy that refuses Watch's greeting closes the connection before Android can name its owner, so the owner is
now asked as soon as the connection is made.

W6's real tools, the same day, on the emulator with Android 15 ([notes](spikes/2026-11-real-tools.md)): v2rayNG
2.3.15, NekoBox 1.4.2 and Orbot 17.9.7, each from its developer's release and signed with the key in
`data/app-signers`, in proxy mode. Watch found each by itself, with Android naming it as the owner of its port, and
the chain was turned on from Watch's screen with no port typed; TCP went through each, UDP through v2rayNG and
NekoBox and nowhere with Orbot, which carries none; a lookup through Orbot got a stand-in and Tor resolved the name.
The log kept the chained flows without destination. Found on the way: v2rayNG's sniffing and its direct route for
private addresses, and NekoBox dropping an answer after the app's half-close. Hiddify 5.5.5 did not start its
core on the emulator, before Watch was involved. On the A40 (Android 11), with only the test apps inside the
tunnel, Watch found the test tool, Orbot, v2rayNG and NekoBox, each with its owner confirmed, and the shell
reached Android's own check address through each by a stand-in name, and Quad9 over UDP through v2rayNG and
NekoBox. NekoBox's own lookups went to Alibaba's public DNS over HTTPS, shown under its UID. ADR 0038's lab, the same day
([notes](spikes/2026-11-chain-lab.md)): a stand-in answers in about 10 ms; other questions through the tool took
half a second each until the tool's route got the cache the ADR promises (now about 10 ms after the first), and
a new name costs about 60 to 90 ms now that Watch keeps a connection to each resolver open through the tool.
Questions share it without waiting for earlier answers, each under an ID of the connection's own, and each
answer is matched by ID and by the question it repeats (RFC 7766). It closes after 10 s with no question, when
the resolver or the tool ends it, or when the chain changes. So the resolver can tie together chained apps'
questions within those seconds, as it already could by the tool's exit address. Also in the lab:
strict Private DNS sends chained apps' lookups to the provider directly, encrypted, while their traffic still goes
through the tool; Chrome loaded a page with resources from other hosts through the tool with no Local Network
Access prompt; the HTTPS record a chained app gets keeps its ECH key. On the emulators with Android 11 and 17,
v2rayNG, NekoBox and Orbot were each found and chained as on the A40. On Android 17, v2rayNG asked for
`ACCESS_LOCAL_NETWORK`; it was refused, and the chain still worked, since a proxy on loopback does not need it.
Android named no owner of NekoBox's port once, at the first search after the tunnel started, and named NekoBox at
every later search. Hiddify 5.5.5 was found and chained on Android 17, also with its password, which takes the user
`hiddify`, and on the A40. On the x86_64 emulators with Android 11 and 15, the emulator itself stopped at Hiddify's
first connection. So each of the four tools has been found and chained without a port typed, on the A40 and on an
emulator. Still to come: ECH in a browser that offers it, and the ten apps of W3. W6's "done when", clause
by clause: [acceptance](spikes/2026-11-w6-acceptance.md). W6 was accepted by the maintainer on 2026-11-11 and
merged into `main`.

Gate 2 of 0.2.0, the review's findings 18 to 21 (D25), began on 2026-11-12 with the small parts:
- **Counters, appended after the nineteen before them:**
  - IP fragments, now counted apart from the other skipped packets;
  - hellos read on flows a DNS answer had named, and of those, how many named another server. A day on the phone
    tells how much finding 20 matters before the log carries both names.
- **The lock:** `nativeStop` and `nativeStart` take the engine out of its lock before joining its thread.
- **Protect:** `protect()` hands Kotlin an owned duplicate of the socket's descriptor, so a caller that times out
  cannot leave a number the kernel gives to another socket.

The engine's limits moved into `Config` (`Limits`), so tests can drive time in seconds. ADR 0044 was accepted the
same day.

The engine's network lab, the same day (`core/net/tests/netlab.rs`, `scripts/netlab-enter.py`). Each test re-runs
itself inside an unprivileged user and network namespace, where a real tun0 holds the tunnel's common addresses.
Test apps bind the tunnel's address and a routing rule sends them into tun0, while the engine's own sockets take
the ordinary routes, as protected sockets do. So Linux's own TCP stack terminates connections at the engine's
listener as Android's does, in an ordinary `cargo test`, without an emulator. The first tests:
- TCP and UDP pass;
- a stranger at the listener is turned away and counted (finding 15);
- a relayed connection silent past the sweep's limit still gets its late answer (finding 16).

`scripts/check.sh rust` runs them, and fails with the reason where no namespace can be made. `NETLAB=skip` says
plainly that they did not run. CI lifts Ubuntu's AppArmor restriction on such namespaces for its runner.

Resets, the same day (finding 21). A relayed connection whose one direction fails, as when the server or the app
resets it, now ends both sides with a reset, and is counted. Before, the app got a clean close, and could not tell
a cut-off answer from a finished one. A clean close still closes with a FIN, direction by direction. Three lab tests
cover it: the server's reset, the app's reset, and a clean close.

The waiting cap, the same day (finding 18, first step). At most so many TCP connections wait for their servers at
once, for every app together: an eighth of what the process may open after a reserve for Watch, at most 4,096 (112
for a process limited to 1,024 files). A SYN beyond the cap is dropped, as by a full queue, and counted. Its port is
freed at once, as is the port of a connection that failed, since neither reached Android's stack. A lab test sends
six connections to a server that never answers, with a cap of four: two are dropped while four wait, all fail, and
another app's connection then opens at once.

Two names in the log wait for the phone's counters to say how often the names differ (ADR 0044, decision 4).

The mapping, the same day (findings 18 and 19), built by a fresh agent from a written brief and reviewed before it
was committed.
- **The direct path:** an app's UDP socket now leaves through one protected, unconnected socket, whatever the
  destination. Each destination is a peer with its own flow, name, bytes and QUIC reading. Answers come in only
  from addresses the app sent to; another port of such an address becomes a peer of its own.
- **Lifetime:** a mapping ends after two minutes with no datagram either way.
- **ICMP errors:** they come back through `IP_RECVERR`, read with nix's safe functions.
- **Lookups:** a lookup to the tunnel's DNS address ends with its last answer.
- **Memory:** one 64 KiB buffer per engine thread replaces one per flow.
- **Found on the way:** tokio wakes a reader only for readable data, not for an error. So the connected sockets'
  "port unreachable" fired only when a later datagram came. Both kinds of socket now also wake on errors.
- **Tests:** six lab tests cover it:
  - a STUN-like check that two servers see the same port;
  - the filter;
  - ICMP "refused";
  - a 4,000-byte answer;
  - a lookup that ends;
  - a mapping kept open by sending alone.

  Each was made to fail by breaking the code it guards.

The chain's mappings, 2026-11-13 (finding 19, ADR 0044 decision 2), built by a fresh agent from a written brief.
A chained app's UDP socket now sends to every destination over one `UDP ASSOCIATE`, each datagram with a header
naming its destination. Each answer goes to the destination its header names, with the direct path's filter;
before, anything the tool's relay sent reached the app as if from the flow's destination. A stand-in is bound to the
first answer from the port the app asked. A mapping now also ends when the chain is set again and sends its app
another way. W6's done-when changes its wording to match. An independent review the same day found five faults, fixed
before the merge: a second name at a bound address answered as the first; any sender on the port could take a
waiting stand-in; forged headers could grow a mapping without end; a datagram sent just as the chain took its app
could leave directly; and a relay elsewhere than on the phone was used. A second review found five more, also
fixed: one name asked on two ports got no answer on the second; a newly chained app's lookups could still reach the
network's resolver; a port Android handed to a chained app could leave the old app's direct way, and an unnamed
app's way was guessed; a flow that came in from a port 53 could teach Watch names; and a relay at the phone's own
Wi-Fi address was refused. A third found the lookups to the tunnel's DNS address still kept a port's old app,
directly or through the chain, and a reused port was logged under its old app without a chain; Android is now asked
again for both, with or without a chain, and an app it cannot name is never guessed. A fourth found that a flow
that came in by name could be taken as a stand-in, that one unanswered name could cut a bound one for minutes,
that a pause cost one question to Android for each destination, and that a repeated answer could end a flow of
lookups early; each is fixed. A fifth found that a datagram to a new destination, or a lookup, could take the
answer to a question about its socket asked before it came, which could name the port's previous app; only a
destination the socket already knows shares a question now. It also found that a reply to a flow shown as a
stand-in went to the tool by address, not by the stand-in's name, and that a stand-in answered by name kept its
queries; both are fixed, and the tests it found racy or too lenient now fail when what they guard changes. A
sixth found that datagrams held behind another, or joining a question, could take an answer asked well before
they came, and that a slow answer widened the window by its own latency; an answer now holds only for what came
less than `udp_reask` after it was asked. It also found that a lookup's answer naming a new app left the old
app's mapping in place, that a port that came in counted as a destination the app knew, that an app answering
every sender lifted the cap of 64, and that a live stand-in whose name left the map became unreachable at its
next pause; each is fixed. A seventh found that an answer naming the new app was forgotten when no way of the
socket was open yet, so that a way opened afterwards on the old app's older answer; the table now keeps the
newest answer about each socket, for as long as it has a way, and opens no way on an older one that names
another app. It also found that each answer scanned the whole table, that the windows were tested from one
side only, and that a live stand-in's way could pass to another app; each is fixed. An eighth found that the
seventh's fix sent an old app's datagrams under the new app's answer, since it took an answer to hold for what
came before its question; a chained app's datagrams could so leave directly. The decision whose a datagram is
now lives in one function every path asks: answers less than `udp_reask` from a datagram that disagree drop it,
and a model drives that rule through 10,000 random schedules of handovers. It also found that an answer still
looked at every flow of lookups of its socket, a lookup flow's window that no test pinned, and a destination
that took on another app's tool failure; each is fixed. A ninth found that only the first datagram waiting for a
way asked Android, so that a retry behind a slow handshake was dropped as ambiguous: each datagram now asks as it
comes and keeps whose it was taken for, and drops are counted as ambiguous or late apart. It also found that what
only comes in to a mapping kept the old app's way without asking, that the model checked no liveness and left
out the chain, failing ways and the record's end, and that a peer's way was looked up before the cap of 64;
each is fixed, and the stream's window and the cost of lookups are stated. A tenth found nothing critical or
major: a waiting datagram taken for one app as it came could leave under another that an answer near it named,
where the rule's own principle says a handover fell near it; it is now dropped as ambiguous. Four paths it found
untested and two window edges are now pinned, and the model also walks every schedule within small bounds. An
eleventh, of that fix only, found no fault in safety, and one in the counter's words, now corrected. How it is
built: [ADR 0044](decisions/0044-udp-mapping-and-budgets.md), "How it is built".

Shares for each app, 2026-11-14 (finding 18, ADR 0044 decision 3), built by a fresh agent from a written brief.
Each app may now hold a quarter of what the engine allows, at least 32 connections waiting for their servers and 64
UDP ways, and the apps Android cannot name share one share: one app that sends to tens of thousands of ports, or to
addresses that never answer, uses up its own share, and four must do so before any other app is touched, or fewer
where a floor lifts a share above a quarter of its cap, as at a limit of 1,024 files, and for TCP two and a half
there, where Android answers late and connections already on their way lift an app up to twice its share. A UDP way
holds its place for as long as it holds a socket: a mapping until it ends, a lookup to the tunnel's DNS address
until its answer. At the cap or an app's share, a mapping ends to make room: an answered lookup first, as an app's
own resolver leaves one behind each query; then the app's own least recently active mapping quiet for five seconds;
then any app's. A mapping with traffic in the last five seconds never ends so, and a call is never cut; if none may
end, the new way's datagrams are dropped, as by a full queue. Each refusal and each mapping ended is counted, with
no destination. Whose a datagram is stays decided by the one rule: a way refused fails at once, and a mapping ended
to make room asks Android again at its app's next datagram; the model drives both. An independent review found no
fault in UDP and one in TCP: a connection dropped for its app's share once its SYN had left the phone was never
logged. Android is now asked first wherever the share could refuse a connection, and one begun beside Android is
never dropped. How it is built: [ADR 0044](decisions/0044-udp-mapping-and-budgets.md), "How it is built".

Still to come: ICMP echo and the network's MTU.

| # | Milestone | Done when |
|---|---|---|
| W1 | Watch's skeleton | A second Gradle module, `:watch`, package `org.visadahyu.datapavan.watch`, signed with the same key. Both APKs come from one build, CI is green, and each is reproducible on its own. The build fails if the audit app gains `INTERNET`, as now, or if Watch's manifest holds anything outside its permissions ADR. Watch opens on the emulator and the A40 with strings in all eight languages, RTL and pseudo-locales from the start, and an icon from the brand marks. Its tunnel starts and stops. Since ADR 0045, `:watch` is a library that only Datapavan Advanced includes; Advanced is built from `:app` with `-Pdatapavan.edition=advanced`, and the package `org.visadahyu.datapavan.watch` is dropped before its first release. |
| W2 | The packet engine in the product | The system-stack forwarder moves from the spike into `core/`, with `unsafe` forbidden (ADR 0006) and every parser fuzzed in CI. It holds each app's SYN until the owner lookup and the protected upstream connection are done; UDP goes through a NAT table with idle timeouts; a segment of an unknown connection gets a reset; unreachable destinations get ICMP and ICMPv6 answers; a network switch re-binds the upstream sockets without dropping the tunnel. An end-to-end test in CI, grown from the spike's workload app, carries TCP and UDP through Watch and finds the owner of every flow, connect-and-close and refused connections included. It passes on emulators with Android 10 and 12 to 17 and on the A40, and IPv6 is checked end to end on a network that has it. The engine adds at most 1 MB per ABI ([VPN.md](VPN.md)). On the A40, its CPU time for the spike's download stays at or below the spike's system engine, so that a regression shows while the work goes on, not at the battery test. |
| W3 | A name for every flow | Watch's resolver answers inside the tunnel and asks the network's resolver through a protected socket. Watch never lowers what the phone had: where Android spoke DNS over TLS to the network's resolver (Private DNS on "automatic"), Watch's upstream does too, and strict Private DNS is detected and explained. Each flow is named, in this order, from the DNS answers Watch served, the TLS server name, the QUIC Initial server name (QUIC versions 1 and 2, the `ClientHello` put together from several packets and from CRYPTO frames out of order), or the organisation in the offline dataset, and otherwise shown as "unknown". A server name that is only a provider's public name under Encrypted Client Hello is never shown as the destination when Watch saw that name in an ECH configuration of a DNS answer: Watch says the real name is hidden. When the app looked its names up elsewhere, a real ECH and Chrome's GREASE look the same by design, and the name is shown with a note that ECH was offered. Apps' own encrypted DNS to known resolvers, and plain DNS sent past the network's resolver, are recognised and named (ADR 0029). On the emulator, a fixture app's flows are named by each of the four routes. A scripted session of ten popular apps on an emulator, from their first start without signing in, runs three times under Watch and three times under PCAPdroid, the usual tool for logging connections without root. Both are measured against a record independent of either: the emulator's own capture of what leaves it, for destinations and names, and, on an image with root, the kernel's owner of each socket, since both tools ask Android the same question for owners. Watch names at least as large a share of flows correctly as PCAPdroid, and gives every flow the owner the kernel recorded. Sessions after signing in follow once test accounts exist. |
| W4 | The connection log | Each flow is stored with the app's UID, the name and where it came from, IP and port, protocol, organisation, bytes each way, and start and end time. Flows chained through a tool are counted, but their destinations are recorded only if the user turns that on ([VPN.md](VPN.md)). The store is app-private SQLite whose records are sealed one by one under a key for their day, held in the Android Keystore ([ADR 0037](decisions/0037-connection-log-storage.md)). Retention is none, 1, 7 or 30 days (no default: chosen at onboarding, none until then; §6.4 and ADR 0040), with a one-tap wipe. Tests show that the database cannot be read without the key, that no destination reaches logcat, and that the wipe leaves nothing behind. Over a scripted emulator session, each app's bytes in the log are within 5 % of Android's own count for that app, the bar of M4, once ADR 0022's open check says how Android counts traffic that passes a VPN. |
| W5 | The audit app reads the log | Watch offers the log through a read-only, versioned interface that only an app signed with the same key may use, and takes nothing from the audit app (ADR 0029). The audit app names the apps behind the UIDs, where a flow older than the app that now holds its UID belongs to "an app since removed", and marks each flow foreground or background from usage access when it has it. Each app's page answers "who did this app talk to?" as a timeline, with tracker destinations flagged from the εxodus network signatures. Tests: an app signed with another key gets nothing; the audit app works unchanged without Watch; where the log would answer a question, the audit app offers Watch with the same fingerprint check as for itself. The new screens pass the accessibility check in all eight languages (`scripts/screenshots.sh`). Dropped by ADR 0045: Advanced reads its own log. How the gate is met in Advanced, with a live view of what apps sent while the user was not using them, is proposed in [ADR 0046](decisions/0046-live-activity.md). |
| W6 | Chaining through the tool's proxy | Watch finds the user's tool by itself: the installed tools from the signed list and table, a SOCKS5 greeting on their known ports only, and the port's owner asked from Android. Chained apps' TCP goes through SOCKS5 `CONNECT` and their UDP through `UDP ASSOCIATE`, or not at all; their DNS goes to the tool, never to the network. When the tool stops, chained apps wait and Watch says so; nothing goes out directly. The tool's own traffic is forwarded directly and attributed to it; nothing comes in from an address a local app did not send to, or, for a name the tool resolves, from any but the first address that answers at the port the app asked (on port 53, only an answer to the app's own query), and `BIND` is never used. Watch offers a generated password where the tool supports one, opens no port of its own, and never logs SOCKS credentials. The user chooses which apps go through the tool. In CI, a test proxy with `UDP ASSOCIATE` and a password carries a workload app's TCP, UDP and DNS; with the proxy stopped, a capture on the emulator's host shows no packet of a chained app leaving directly; checks that the chain works use only the address Android itself checks connectivity with. On the A40 and the emulators, v2rayNG, NekoBox, Hiddify and Orbot in proxy mode are each found and chained without the user typing a port. |
| W7 | A WireGuard upstream | A provider's WireGuard configuration, from a file or a QR code, becomes Watch's upstream for the apps the user picks, so one VPN does both. Its private key is encrypted with a Keystore key and never logged. With a Proton VPN free configuration, every chosen app's traffic leaves through the tunnel, IPv4, IPv6 and DNS, as a check from outside shows; a dropped tunnel holds the chosen apps back instead of sending them directly; the extra battery and CPU against W2's engine alone are measured on the A40. |
| W8 | DNS of the user's choice, flags and guides | Oblivious DoH by default for apps that go directly, with relays and targets in several jurisdictions, and the network's resolver only as a fallback outside the strict setting ([ADR 0042](decisions/0042-dns-of-apps-that-go-directly.md)). A DoH or DoT resolver of the user's choice, and a strict setting that never falls back to the network's resolver (VPN.md; recommended in restricted regions). Apps' built-in proxies are named, with their operator when it is not the app's maker, Telegram's MTProto and SOCKS5 proxies first. Proxy-like behaviour (many destinations in a short time, sustained upload, activity with the screen off) is flagged as what was seen, with thresholds from a lab run recorded in `docs/spikes/`, counted in memory so that chained destinations stay unrecorded. Tracker blocking stays off until the user turns it on, and is undone in one tap. Per-tool guides for proxy mode. Tests: strict DNS sends nothing to the network's resolver while the chosen one is down; a fixture app with a Telegram-style proxy setting is named; every flag on W3's ten-app session is explained in the lab notes; blocking and its undo work. The guides are translated and reviewed in eight languages (ADR 0030). |
| W9 | Onboarding and the 0.2.0 release | Onboarding covers the VPN consent, Android 17's local-network permission, strict Private DNS, the always-on VPN with "block connections without VPN" ([VPN.md](VPN.md)), the kind of tool Watch found and the next step for it, and battery managers, Samsung's first, with guides for other vendors. A Quick Settings tile turns Watch on and off. Battery is tested on the Galaxy A56 with the signed release candidate (ADR 0011 allows only stable builds on it), in windows of six to seven hours of ordinary use at similar times of day: one without Watch or any VPN, one with Watch alone, one with Watch carrying a Proton VPN free configuration, and one with Proton VPN's own app alone. Each window is read over adb from Android's battery statistics: Watch's own share, and the total drain per hour with the screen on and off, scaled to 24 hours. Only Watch's line and the totals are read; no other app's name is recorded. Watch alone costs at most 3 % of a day's battery over the window without a VPN, and Watch with Proton's configuration at most 3 % over Proton's own app. If the candidate passes, the same APK is published. The sentence of ADR 0029 is taught in the self-check, the store texts, RELEASE.md and the website. Store texts and changelog are translated and reviewed in eight languages (ADR 0030); both apps are in `data/app-signers` with their fingerprints; a review against the threat model (§8) covers what Watch adds. 0.2.0 is published on GitHub with both APKs, on the website and through Obtainium. F-Droid follows [CHANNELS.md](CHANNELS.md); Google Play gets only the audit app for now (ADR 0029, ADR 0031). |

Besides each milestone's "done when", Datapavan Advanced 0.2.0 passes the release gates of [ADR 0039](decisions/0039-release-gates.md), among them what other apps see of Watch and the compatibility matrix ([ADR 0041](decisions/0041-watch-visibility-and-coexistence.md)) and Watch's own safety ([ADR 0040](decisions/0040-own-safety-in-an-untrusted-environment.md)). Before an independent review, a build of Datapavan Advanced goes only to identified testers.

The order: W1 and W2 first. W3, W4 and W6 then run side by side, since each needs only the engine;
W5 follows W4, W7 follows W6, and W8 follows W3 and W6. W9 comes last. Tests on the A40 use the
workload and fixture apps, the circumvention tools and the engine's CPU checks; the battery test runs
on the A56 with the release candidate (W9); sessions with popular
apps run on emulators with test accounts, so that no one's personal data enters a test log. Phones
from other vendors are still missing: until one is found, the device tests cover Samsung and the
emulators only, and the release notes say so.

**Not in 0.2.0:** the sensor log, the cross-checks, learned traffic shapes and apps that keep their own
push connection (0.2.1, after their feasibility spikes); TLS fingerprints of client libraries (later
in v0.2); fuller blocking (v0.3).

## 14. Decisions

Each decision is recorded in full, with context and consequences, as an ADR in
[decisions/](decisions/README.md). This table is the summary.

| ADR | Decision | Status |
|---|---|---|
| [0001](decisions/0001-apache-2-licence.md) | Apache-2.0 licence | Accepted |
| [0002](decisions/0002-codeberg-with-github-mirror.md) | Codeberg as home, GitHub as read-only mirror | Superseded by 0013 |
| [0003](decisions/0003-minimum-android-10.md) | Minimum Android version 10 (API 29) | Accepted |
| [0004](decisions/0004-ui-languages-and-rtl.md) | Languages at launch, changed by ADR 0030; RTL from the first commit | Accepted |
| [0005](decisions/0005-english-documentation.md) | Documentation in English only | Accepted |
| [0006](decisions/0006-rust-engine-unsafe-forbidden.md) | Rust engine with `unsafe` forbidden; separate JNI crate | Accepted |
| [0007](decisions/0007-direct-jni-over-uniffi.md) | Direct JNI instead of UniFFI | Accepted |
| [0008](decisions/0008-gradle-dependency-verification.md) | Gradle dependency verification, generated from an empty Gradle home | Accepted |
| [0009](decisions/0009-no-automatic-jdk-download.md) | Gradle daemon pinned to JDK 21, no automatic JDK download | Accepted |
| [0010](decisions/0010-cuneiform-brand-marks.md) | Old Persian cuneiform signs as brand marks | Accepted |
| [0011](decisions/0011-m1-test-devices.md) | M1 tested on emulators and the Galaxy A40 only | Accepted |
| [0012](decisions/0012-packet-engine.md) | Packet engine for the local VPN: Android's own TCP stack through rewritten addresses, in Rust | Accepted |
| [0013](decisions/0013-github-as-home.md) | GitHub as the only home; Codeberg dropped | Accepted |
| [0014](decisions/0014-v0.1-permissions.md) | Permissions for v0.1 "Audit" | Accepted |
| [0015](decisions/0015-dataset-licences.md) | Licences of bundled datasets | Accepted |
| [0016](decisions/0016-no-user-data.md) | No data from users; learning happens in the lab | Accepted |
| [0017](decisions/0017-data-pack-format.md) | Data packs in signify's format, checked with ed25519-compact | Accepted |
| [0018](decisions/0018-app-signing-certificates.md) | Official signing certificates of VPN, proxy and circumvention apps | Accepted |
| [0019](decisions/0019-traffic-sharing-remote-support-sdks.md) | Traffic-sharing, remote-support and screen-recording SDKs | Accepted |
| [0020](decisions/0020-same-company-trackers.md) | Trackers from the app's own company group | Accepted |
| [0021](decisions/0021-service-dependent-capabilities.md) | Tracker capabilities that need a service the phone lacks | Accepted |
| [0022](decisions/0022-network-use-and-unused-apps.md) | Network use per app and apps not opened, from Android's own records | Accepted |
| [0023](decisions/0023-maker-software-and-system-keys.md) | The phone maker's software and leaked system keys | Accepted |
| [0024](decisions/0024-fake-copies-of-datapavan.md) | Fake copies of Datapavan | Accepted |
| [0025](decisions/0025-guided-check-and-traffic-facts.md) | The guided check of one activity, and two traffic facts that need no comparison | Accepted |
| [0026](decisions/0026-remediation-plan-v0.1.md) | The remediation plan's part for v0.1 | Accepted |
| [0027](decisions/0027-app-structure-and-settings.md) | The app's structure and settings | Accepted |
| 0028 | This number was not used | – |
| [0029](decisions/0029-network-access-for-v0.2.md) | v0.2's VPN in a separate app, Datapavan Watch, so that Datapavan never holds INTERNET | Superseded by 0045 |
| [0030](decisions/0030-more-languages-reviewed-by-independent-models.md) | Spanish, Russian, Chinese and Arabic at launch, reviewed by independent models | Accepted |
| [0031](decisions/0031-datapavan-lite-on-google-play.md) | Datapavan Lite on Google Play: its own name, package and key | Accepted, being built |
| [0032](decisions/0032-expert-tool-for-preinstalled-apps.md) | An expert tool of Datapavan's own for preinstalled apps | Proposed |
| [0033](decisions/0033-organisational-edition-beside-a-suite.md) | The organisational edition beside a device-management suite | Accepted, not built yet |
| [0034](decisions/0034-watch-permissions.md) | Permissions for Watch: five, one only on Android 10 and 11 and one only on 17, and the build's allowlist | Accepted |
| [0035](decisions/0035-wireguard-upstream.md) | WireGuard upstream: GotaTun's protocol core in the engine, raw packets forwarded | Accepted |
| [0036](decisions/0036-ip-to-organisation-dataset.md) | The IP-to-organisation dataset: DB-IP Lite, checked against iptoasn | Accepted |
| [0037](decisions/0037-connection-log-storage.md) | The connection log: records sealed one by one, a key for each day, readable only on an unlocked phone | Accepted |
| [0038](decisions/0038-dns-of-chained-apps.md) | DNS of chained apps: stand-in addresses, names to the tool | Accepted |
| [0039](decisions/0039-release-gates.md) | Release gates, a preview for identified testers, and what 1.0 means | Accepted |
| [0040](decisions/0040-own-safety-in-an-untrusted-environment.md) | Datapavan's own safety in an untrusted environment | Accepted |
| [0041](decisions/0041-watch-visibility-and-coexistence.md) | What other apps see of Watch, and working beside every app | Accepted |
| [0042](decisions/0042-dns-of-apps-that-go-directly.md) | DNS of apps that go directly: Oblivious DoH, several jurisdictions | Accepted, with open questions |
| [0043](decisions/0043-release-integrity-and-repository-controls.md) | Release integrity, repository controls and continuous fuzzing | Accepted |
| [0044](decisions/0044-udp-mapping-and-budgets.md) | UDP mapping, budgets for each app, and the engine's smaller gaps | Accepted |
| [0045](decisions/0045-three-editions-of-one-app.md) | Three editions of one app: Basic, Advanced and Enterprise | Accepted |
| [0046](decisions/0046-live-activity.md) | What apps sent while the user was not using them, shown live | Proposed |
| [0047](decisions/0047-profile-for-phones-that-may-be-searched.md) | A profile for phones that may be searched: nothing of use kept | Proposed |
| [0048](decisions/0048-lab-probe-of-android-gaps.md) | A lab probe of where stock Android leaves privacy tools blind or exposed | Proposed |
| [0049](decisions/0049-signing-keys-of-the-editions.md) | A signing key for each edition, ready to rotate, backed up in shares | Proposed |
| [0050](decisions/0050-operators-and-sim-cards.md) | Mobile operators and SIM cards: what the phone installed, what the SIM can do, what to tell users | Proposed |

## 15. Names

- **Datapavan:** Old Persian *dāta* "law" + *pāvan* "protector" (as in *xšaçapāvan*, "protector of the realm"; the Median form of that title, *\*xšaθrapāvan-*, gave Greek *satrápēs* and English *satrap*). The compound is coined from two attested elements: "protector of the law" in Old Persian, and "data protector" when read in English.
- **Visadahyu:** "of all nations", from Xerxes' inscription on the Gate of All Nations at Persepolis (XPa: *duvarθim visadahyum*).
