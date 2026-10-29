# Datapavan

**Datapavan shows what the apps on your Android phone can reach and what they send, and to whom, and
helps you stop it.** Everything runs on the device. It needs no root and no cloud service, and version
0.1 does not even have permission to use the internet.

> Status: **pre-alpha.** Milestones M1 (the build skeleton) and M2 (the app and permission audit) are
> complete; nothing has been released yet. See the [roadmap](ROADMAP.md).

## Why

Most people cannot see what their phone does with their data. Tracking SDKs sit inside thousands of apps.
Apps keep talking to third parties in the background, and system components send data to the phone maker
and to the platform owner. Where the internet is filtered, people also install VPN apps from unknown
sources, and such an app sees all of their traffic. Datapavan makes all of this visible and lets the user
control it.

The goal: **no data leaves the device except what the user knowingly gives to a service. The user can
see what left, where it went, and when.**

## What it does today

Built in milestone M2. It is checked on every change on an Android 15 emulator in CI, and was checked on
Android 11 and 17 emulators and a Galaxy A40.

- **App and permission audit.** Every installed app, with its install source, dates, dangerous
  permissions and special access (accessibility, notification listener, device admin, overlay, usage
  access, installing other apps, all-files access, battery exemption). *Why:* the access that lets an
  app read the screen or act for the user is spread over many Settings screens, and few people look.
- **Risk checks for VPN users.** VPN apps that can also control the phone, user-installed certificate
  authorities, and USB or wireless debugging. *Why:* a VPN app sees all traffic. With remote-control
  access it can also read messages and login codes, and an extra certificate authority lets someone read
  encrypted traffic. Setup guides for some tools tell users to turn debugging on.
- **Preinstalled data collectors.** System apps from data-collecting companies that the phone maker
  ships, for example Meta's services on Samsung phones, with their state and a guide to disable them or
  to remove them reversibly from a computer. *Why:* the user never installed them, they have no icon,
  and an app cannot remove them by itself.
- **Strict sensor review.** A guided pass through every app that holds microphone, camera or location
  access, with a recommendation for each (*Ask every time* or *Don't allow*). An app that regains access
  comes back to the list. Voice assistants that listen for a wake word are named, with the setting that
  turns it off. *Why:* Android does not let one app change another app's permissions, so the user makes
  each change, and Datapavan makes it quick and keeps watch. On our lab phone, the Google app kept the
  microphone open for its wake word until that was turned off.
- **Device integrity.** The bootloader lock and verified-boot state from hardware key attestation,
  checked against Google's attestation root certificates and decoded by a parser in the Rust engine, and
  the age of the security patch. *Why:* on a phone with an unlocked bootloader or a modified system, no
  app can be trusted, Datapavan included.

## What comes next

Each item is designed in [docs/DESIGN.md](docs/DESIGN.md) and [docs/VPN.md](docs/VPN.md), but not built
yet.

- **Tracker scanner** (v0.1, M3). Tracking SDKs inside each app, including proxy and remote-access SDKs,
  and modified copies of known circumvention tools, found by their signing certificates. *Why:* a hidden
  proxy SDK turns the phone into an exit node for other people's traffic, which is traced back to the
  owner. A modified copy of a known tool looks genuine.
- **Network use per app** (v0.1, M4): bytes sent and received, on screen and in the background.
- **Connection log** (v0.2). A local VPN, with no server, records which domain and organisation each app
  talks to. *Why:* this is the question users actually ask, and only the phone itself can answer it.
- **Sensor activity log** (v0.2). When the microphone recorded or the camera was on, with an alert for
  use while the screen is off. *Why:* Android does not tell other apps which app is recording, so without
  a record nobody can check this afterwards.
- **Cross-checks** (v0.2). Datapavan's own records against Android's: sensor use, and Android's per-app
  data accounting against what the VPN saw. *Why:* a contradiction between two records is evidence, for
  example of traffic that went around the VPN.
- **Unusual behaviour** (v0.2). The shape of each app's traffic: a steady, audio-like upload, or large
  uploads while the user only scrolled. Datapavan never decrypts traffic. *Why:* content stays encrypted,
  but its shape does not. A baseline learned on the phone only detects change, so uploads are also split
  by destination and compared with the project's lab measurements.
- **Chaining with circumvention tools** (v0.2). Datapavan stays the phone's VPN and sends traffic
  through the tool's local proxy, so the tool becomes a pipe, not the owner of the network. *Why:* Android
  allows one VPN at a time, and people under censorship should not have to choose between access and
  safety. See [docs/RESTRICTED-REGIONS.md](docs/RESTRICTED-REGIONS.md).
- **Blocking** (v0.3): network access per app, tracker domains, and "notifications yes, hidden uploads
  no", which allows an app the network only while it is on screen. *Why:* notifications arrive through
  the system's push service, so most apps need no connection of their own in the background.
- **Remediation plan** (v0.1, M5). Findings become a short list of actions, ordered by how much risk
  each removes, at a light, medium or strict level; each is previewed, confirmed in one tap, recorded
  and reversible, and a safety floor protects the phone's core functions. *Why:* a phone in daily use
  can have hundreds of apps and dozens of findings, and nobody works through that by hand. See
  [docs/REMEDIATION.md](docs/REMEDIATION.md).
- **Reports** (v0.4): a weekly report, a GDPR Article 15 data-access request for each company whose
  trackers were seen, and each app's declared data practices compared with what was observed. *Why:*
  every observation is a concrete reason to ask a company what it holds.

## What it cannot do

On a stock phone Datapavan has the limits of an app. It cannot read encrypted content, and will never
decrypt it. It cannot remove the maker's system apps without a computer, control firmware or the modem,
or clean a phone that is already compromised; it finds the risk and guides the user. Each limit, and the
stage that addresses it, is listed in [docs/DESIGN.md](docs/DESIGN.md#2-what-we-can-and-cannot-protect).

## Three stages

1. **A layer app** for individuals on stock Android, without root (this repository today).
2. **An enterprise edition** for organisations, in Device Owner mode: system apps disabled, the VPN
   enforced, permissions set by policy.
3. **A hardened Android-based OS** on partner hardware, for users who need control of the whole stack.

## Principles

- **No internet permission in v0.1.** The app cannot open a network connection, and the build fails if
  anything adds the permission.
- **Local-first.** All analysis happens on the device. Datapavan has no servers that receive user data.
- **Zero telemetry.** Datapavan collects nothing about its users and contains no analytics SDKs. It learns
  from its own lab, never from its users' phones ([ADR 0016](docs/decisions/0016-no-user-data.md)).
- **No Google Play Services.** It works on phones without Google's services.
- **Open source.** You can check every claim yourself. Builds will be reproducible and releases signed.
- **Plain language.** Every finding is explained so that anyone can understand it.
- **Hands off other apps.** Datapavan never modifies or injects into other apps. It works only at the system and network level.

## Name

*Datapavan* is built from two Old Persian elements found in Achaemenid inscriptions. *dāta* means "law" and
*pāvan* means "protector", as in *xšaçapāvan*, "protector of the realm". In Old Persian the compound
means "protector of the law". In English it also reads as "data protector".

Datapavan is planned to be maintained by the **Visadahyu Foundation**. *Visadahyu* means "of all nations",
from Xerxes' inscription on the *Gate of All Nations* at Persepolis.

The history and meaning of both names are in [docs/NAMES.md](docs/NAMES.md); logos and colours are in
[brand/](brand/README.md).

## Documentation

| Document | Content |
|---|---|
| [ROADMAP.md](ROADMAP.md) | The three stages, releases and milestones, and their status |
| [docs/DESIGN.md](docs/DESIGN.md) | Stage 1 design: scope, architecture, threat model, internationalisation |
| [docs/VPN.md](docs/VPN.md) | Design of the local VPN (v0.2 and v0.3) |
| [docs/REMEDIATION.md](docs/REMEDIATION.md) | The remediation plan: levels, actions, safety floor, evidence |
| [docs/RESTRICTED-REGIONS.md](docs/RESTRICTED-REGIONS.md) | Working under censorship and surveillance |
| [docs/FOUNDATION.md](docs/FOUNDATION.md) | Charter principles of the Visadahyu Foundation |
| [docs/decisions/](docs/decisions/README.md) | Architecture decision records, including the licences of every dataset (ADR 0015) |
| [docs/spikes/](docs/spikes/) | Feasibility spikes and what they found on real devices |
| [docs/NAMES.md](docs/NAMES.md), [brand/](brand/README.md) | Names, logos and colours |
| [PRIVACY.md](PRIVACY.md), [SECURITY.md](SECURITY.md) | Privacy policy, vulnerability reporting |
| [CONTRIBUTING.md](CONTRIBUTING.md), [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md), [CHANGELOG.md](CHANGELOG.md) | Working on the project |

## How this project is built

Development is **AI-assisted**. Design decisions are made and approved by the maintainer
(mehdashti). Much of the code and documentation is drafted with AI agents (Claude, by Anthropic) and
reviewed by the maintainer before it is committed. Commits made this way carry an `Assisted-by:` trailer.
The rules for contributors are in [CONTRIBUTING.md](CONTRIBUTING.md#ai-assisted-contributions).

## Building

Requirements (versions are pinned in the repository; CI installs exactly these):

- JDK 21. The Gradle daemon is pinned to it and never downloads a JDK by itself.
- Android SDK with `platforms/android-37.0`, `build-tools/37.0.0` and `ndk/30.0.16248370`. Set `ANDROID_HOME`, or `sdk.dir` in `android/local.properties`.
- Rust through `rustup`. The exact toolchain and Android targets come from `rust-toolchain.toml`.
- `cargo install cargo-ndk --version 4.1.2 --locked` and `cargo install cargo-deny --version 0.20.2 --locked`.
  Gradle runs cargo from `$CARGO`, else `$CARGO_HOME/bin/cargo` (default `~/.cargo/bin/cargo`), else
  `cargo` on `PATH`. `cargo deny` needs network access to fetch the advisory database.

```sh
scripts/check.sh                          # every quality gate CI runs
scripts/smoke.sh                          # smoke test on a connected emulator or phone
scripts/verify-audit.sh                   # end-to-end check of the audit's findings (emulator only)
scripts/screenshots.sh                    # screenshots in every language, accessibility check (Android 13+)
scripts/fuzz.sh                           # fuzz every Rust parser (pinned nightly and cargo-fuzz)
cd android && ./gradlew assembleDebug     # debug APK, including the Rust library
```

Every Gradle dependency is checked against `android/gradle/verification-metadata.xml` (SHA-256).
After a deliberate dependency change, regenerate it **from an empty Gradle home** (a warm cache hides
metadata files), check it with a forced refresh, and review the diff:

```sh
cd android
export GRADLE_USER_HOME="$(mktemp -d)"
./gradlew --no-daemon --write-verification-metadata sha256 \
    lintDebug lintRelease testDebugUnitTest assembleDebug assembleRelease bundleRelease
./gradlew --no-daemon --refresh-dependencies \
    lintDebug lintRelease testDebugUnitTest assembleDebug assembleRelease bundleRelease
```

For now the file covers Linux build hosts only.

## Licence

Apache License 2.0. See [LICENSE](LICENSE).
