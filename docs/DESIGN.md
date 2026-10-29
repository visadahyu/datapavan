# Datapavan — Design Document

| | |
|---|---|
| Version | 0.2 (draft, revised 2026-10-29) |
| Date | 2026-10-28 |
| Scope | Stage 1: the layer app for stock Android, with no root |
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

## 3. Principles (non-negotiable)

1. **Local-first.** All analysis happens on the device. No Datapavan server ever receives user data.
2. **Zero telemetry.** No analytics or crash-reporting SDKs. Crash reports stay local and are shared only by explicit user action.
3. **No Google Play Services dependency.** The app must work on de-Googled devices.
4. **Least privilege.** Each feature asks only for the permission it needs, and explains why before asking.
5. **Plain language.** Every finding has a short, non-technical explanation.
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

## 5. Roadmap for stage 1

Each release can ship on its own and is useful by itself.

### v0.1 "Audit": no VPN, **no INTERNET permission**

Shipping without network permission at all is a strong trust signal: the app *cannot* open a network connection.

- **App inventory:** all installed apps (user and system), installer source, and first-install and last-update dates.
- **Permission audit:** granted dangerous permissions, plus special access: accessibility, device admin, notification listener, usage access, VPN, overlay, install unknown apps, and battery-optimisation exemptions.
- **Tracker SDK detection:** scan each app's DEX class names on the device against a bundled tracker-signature database.
- **Network usage per app:** bytes up and down, split by foreground/background and Wi-Fi/mobile, read from `NetworkStatsManager` (needs the *Usage access* special permission).
- **Plain-language card per app:** what it can access, what trackers it carries, how much it sends, and what the user can do about it.

### v0.2 "Watch": local VPN, observe only

- Connection log per app: destination domain, IP, organisation (from an offline IP-to-ASN database), bytes, time, and foreground/background state.
- A timeline answering "who did this app talk to?", with tracker destinations flagged.
- Nothing is blocked yet. This lets us check accuracy and battery cost before we take control.

### v0.3 "Guard": blocking

- Network access per app on or off, separately for Wi-Fi, mobile and background.
- Tracker-domain blocking: global, with per-app exceptions.
- Safe defaults, one-tap undo, and a "this app broke" path that guides the user to the rule responsible.

### v0.4 "Report"

- A weekly plain-language report, exportable as PDF or JSON.
- **GDPR helper:** for each company whose trackers were observed, draft a GDPR Article 15 data-access request that the user can send. Each observation is a concrete, defensible reason to ask "what do you hold about me?"

### Later (stage 2 preview; full plan in [ROADMAP.md](../ROADMAP.md))

- **Enterprise flavour in Device Owner mode:** disable system apps, enforce always-on VPN, and apply policies at fleet scale.
- **Work-profile isolation helper:** put Meta and other high-tracking apps in a separate profile without a factory reset.
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
|   userspace TCP/UDP forwarder (netstack)                                              |
+---------------------------------------------------------------------------------------+
```

### 6.1 Why a Rust core

- **Memory safety where it matters most.** The core parses untrusted bytes from every app and every server. A parser bug in C or C++ here becomes a security hole on the user's phone.
- **One engine for all three stages.** The same library runs inside the VpnService app (stage 1), the Device Owner flavour (stage 2), and later as a system daemon in our own hardened OS (stage 3). Platform code stays thin.
- **Plan B:** the Go gVisor netstack approach used by existing open-source Android firewalls. We decide after a two-week spike (ADR 0012).

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
| Google developer verification (in force since 2026-09-30 in four countries; global in 2027) | Apps from unverified developers cannot be installed on certified devices; registering requires sharing the developer's identity with Google | Register the maintainer's identity before v0.1; transfer to the foundation later |
| Copyright status of AI-assisted code is uncertain | Weaker licence enforcement and ownership proof | Decisions made and approved by the maintainer; all agent output reviewed before commit; AI assistance disclosed (`Assisted-by:` trailers, README); agent session logs kept privately, never committed |

## 8. Threat model (initial)

**Assets:** connection metadata, app inventory, rules, and exported reports.

| Adversary | Example | Mitigation |
|---|---|---|
| Tracking app on the same device | Tries to read Datapavan's logs | No exported components except the launcher (plus AndroidX's ProfileInstallReceiver, guarded by the system-only DUMP permission); encrypted app-private storage |
| Malicious app abusing Datapavan | Sends intents to change rules | Rules change only through our own UI; all IPC is internal |
| Network attacker | Tampers with blocklist updates | Updates are optional and signed (Ed25519/minisign); pinned public key in the app |
| Supply-chain attacker | Compromises a dependency or our build | Pinned dependencies with SHA-256 verification, exclusive repository content, cargo-deny advisories in CI, reproducible builds, signed releases |
| Device seizure or inspection | A phone check at a border or checkpoint; the connection log becomes evidence | No destination logging for flows chained through a circumvention proxy (default); selectable retention, including none; one-tap wipe |
| State network observer | Sees that a device runs Datapavan (for example through list-update requests) | List updates are optional and can be imported as files; no other network traffic of our own |
| Malformed or hostile packets | Crash or exploit the parser | Rust; fuzzing of all parsers (`cargo fuzz`); the forwarder fails closed |

## 9. Data sources (licences TBV)

The enterprise flavour will be commercial, so every dataset must allow commercial use.

| Need | Candidates | Note |
|---|---|---|
| Tracker SDK signatures | εxodus Privacy tracker database | Licence TBV |
| Tracker domains | EasyPrivacy, HaGeZi, Disconnect | Licences TBV. **Avoid non-commercial licences**, e.g. DuckDuckGo Tracker Radar (CC BY-NC-SA, TBV) |
| IP → ASN / organisation | iptoasn.com, DB-IP Lite | Licences TBV |

## 10. Tech stack

- **Android:** Kotlin, Jetpack Compose (the only UI dependency), minSdk 29, compileSdk and targetSdk 37, Gradle version catalog, no Google Play Services. Application ID `org.visadahyu.datapavan` (permanent). ABIs: `arm64-v8a` (phones) and `x86_64` (emulator).
- **Core:** Rust pinned in `rust-toolchain.toml`, built with `cargo-ndk` and NDK r30. Libraries are 16 KB page-aligned, which devices with 16 KB memory pages (supported since Android 15) need and Google Play requires. Two crates: `datapavan-engine` (all logic; `unsafe` forbidden by the compiler) and `datapavan-jni` (the only place `unsafe` is allowed; one small function per export).
- **Bridge:** direct JNI through the `jni` crate. We chose it over UniFFI because UniFFI's Kotlin bindings depend on JNA (about 1.5 MB, and reflection-based), while our JNI surface stays tiny: a version call today, and start/stop/query for the engine later. Netstack candidates to evaluate in the spike: `smoltcp`, `ipstack`.
- **Supply chain:** Google's artifact groups may come only from Google's repository and everything else only from Maven Central (`exclusiveContent`); Gradle dependency verification (SHA-256 of every artifact, generated from an empty Gradle home); the Gradle distribution is pinned by checksum and the wrapper jar is validated in CI; native libraries are built with remapped paths and a controlled cargo environment; `Cargo.lock` is committed and every build uses `--locked`; `cargo deny` checks licences, sources and advisories.
- **Quality gates:** `scripts/check.sh` runs everything that CI runs. That covers rustfmt; Clippy (pedantic, warnings as errors) for the host and both Android targets; Rust tests; cargo-deny; Android Lint for debug and release (warnings as errors); unit tests; APK and bundle builds; the forbidden-permission guard, wired into the manifest pipeline so no build path can skip it; and a check that every APK carries the Rust library with its JNI export.
- **CI:** GitHub Actions (actions pinned by commit SHA), calling the same `scripts/check.sh` as local builds.
- **Quality:** Kotlin and Rust unit tests, parser fuzzing, instrumented tests on the emulator, and a manual test matrix on the A40 and A56.
- **Release:** reproducible builds, F-Droid metadata, signed APKs.
- **JDK:** Gradle runs on JDK 21, pinned through Gradle's daemon JVM criteria.

## 11. Internationalisation

Adding a language must be a mechanical step: add translations, with no code changes. Right-to-left (RTL)
support is built in from the first commit, because retrofitting it later touches every screen.

**Launch languages:** English (source), French, German and Persian. Persian is the RTL reference
language, reviewed by a native speaker. Arabic comes in the first wave after launch, once
native reviewers are found.

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
- CI takes screenshots of key screens in English, `en-XA`, `ar-XB` and Persian.

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
    RESTRICTED-REGIONS.md
    FOUNDATION.md      foundation charter principles
    NAMES.md           history and meaning of the names
    decisions/         architecture decision records (ADRs)
  android/             Android app (Kotlin); Gradle project root
  core/                Rust workspace: engine/ (no unsafe) and jni/ (bridge)
  brand/               logo SVGs and brand guide
  scripts/check.sh     all quality gates; CI calls it
  data/                (from M3) bundled dataset snapshots + their LICENSE files
```

## 13. Milestones for v0.1 "Audit"

| # | Milestone | Done when |
|---|---|---|
| M1 | Skeleton | Android app and Rust core build together; CI green; app opens on the emulator and the A40 (A56 testing deferred, ADR 0011); string resources, RTL support and pseudo-locales in place from the start; brand marks and app icon |
| M2 | App inventory and permission audit | Matches what system Settings shows, checked on the A40 and the emulator |
| M3 | Tracker SDK scanner | Results for 20 popular apps agree with published εxodus reports |
| M4 | Network usage per app | Byte counts within 5 % of the Settings data-usage screen |
| M5 | Plain-language UI and first release | v0.1 published on GitHub in English, French, German and Persian, and submitted to F-Droid; manifest has **no INTERNET permission**; build is reproducible |

## 14. Decisions

Each decision is recorded in full, with context and consequences, as an ADR in
[decisions/](decisions/README.md). This table is the summary.

| ADR | Decision | Status |
|---|---|---|
| [0001](decisions/0001-apache-2-licence.md) | Apache-2.0 licence | Accepted |
| [0002](decisions/0002-codeberg-with-github-mirror.md) | Codeberg as home, GitHub as read-only mirror | Superseded by 0013 |
| [0003](decisions/0003-minimum-android-10.md) | Minimum Android 10 (API 29) | Accepted |
| [0004](decisions/0004-ui-languages-and-rtl.md) | English, French, German and Persian at launch; RTL from the first commit | Accepted |
| [0005](decisions/0005-english-documentation.md) | Documentation in English only | Accepted |
| [0006](decisions/0006-rust-engine-unsafe-forbidden.md) | Rust engine with `unsafe` forbidden; separate JNI crate | Accepted |
| [0007](decisions/0007-direct-jni-over-uniffi.md) | Direct JNI instead of UniFFI | Accepted |
| [0008](decisions/0008-gradle-dependency-verification.md) | Gradle dependency verification from an empty Gradle home | Accepted |
| [0009](decisions/0009-no-automatic-jdk-download.md) | Gradle daemon pinned to JDK 21, no automatic JDK download | Accepted |
| [0010](decisions/0010-cuneiform-brand-marks.md) | Old Persian cuneiform signs as brand marks | Accepted |
| [0011](decisions/0011-m1-test-devices.md) | M1 tested on emulators and the Galaxy A40 | Accepted |
| [0012](decisions/0012-packet-engine.md) | Packet engine for the local VPN | Proposed (spike pending) |
| [0013](decisions/0013-github-as-home.md) | GitHub as the only home; Codeberg dropped | Accepted |

## 15. Names

- **Datapavan:** Old Persian *dāta* "law" + *pāvan* "protector" (as in *xšaçapāvan*, "protector of the realm"; the Median form of that title, *\*xšaθrapāvan-*, gave Greek *satrápēs* and English *satrap*). The compound is coined from two attested elements: "protector of the law" in Old Persian, and "data protector" when read in English.
- **Visadahyu:** "of all nations", from Xerxes' inscription on the Gate of All Nations at Persepolis (XPa: *duvarθim visadahyum*).
