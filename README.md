# Datapavan

Website: <https://datapavan.org>

**Datapavan shows what the apps on your Android phone can reach and how much they send, and guides you
to the Android settings that limit it.** Who they send to, and blocking, are planned for v0.2 and v0.3. Everything runs on the device. It needs no root and no cloud service, and version
0.1 does not even have permission to use the internet.

> Status: **pre-alpha.** Milestones M1 (the build skeleton), M2 (the app and permission audit), M3
> (the code scanner and its data) and M4 (network use per app) are complete. M5, the first release, is
> in progress: the guided check, the remediation plan, the app's structure and settings, the brand
> theme, the genuine-copy check and the release steps are built, and the signing keys were made offline
> on 2026-11-06. Version 0.1.2, the first release for everyone, is out since 2026-11-07. Nothing has been
> independently audited; the project has one maintainer. It is built for phones with Android 10 or
> newer, 64-bit and, since 0.1.1, 32-bit, and tested from Android 11. See the [roadmap](ROADMAP.md) and <https://datapavan.org>.

## Why

Most people cannot see what their phone does with their data. Tracking SDKs sit inside thousands of apps.
Apps keep talking to third parties in the background, and system components send data to the phone maker
and to the platform owner. Where the internet is filtered, people also install VPN apps from unknown
sources, and such an app sees all of their traffic. Datapavan makes all of this visible and lets the user
control it.

The goal: **no data leaves the device except what the user knowingly gives to a service. The user can
see what left, where it went, and when.**

## What it does today

Built in milestones M2 to M4. It is checked on every change on an Android 15 emulator in CI, and was
checked on Android 11 and 17 emulators and on Galaxy A40 and A56 phones.

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
- **Tracker scan.** The code of every installed app, in its base APK and every split, is read by a DEX
  parser in the Rust engine and matched against the εxodus tracker database. Trackers whose code the app
  contains are shown apart from those it only refers to. *Why:* tracking SDKs collect data inside apps
  that the user chose for other reasons, and only their code shows they are there.
- **Connection sharing, remote support and screen recording.** Datapavan's own list of SDKs that can let
  other people's internet traffic pass through the phone, let a support agent see or control it, or
  record what the user does in an app for its maker. Every identifier is read in the SDK its vendor
  publishes. Findings state what was found, what the code does when it is on, and what Datapavan cannot
  check. *Why:* traffic sent through someone's phone is traced back to that person, and it uses their
  data and battery.
- **Genuine or modified VPN and circumvention apps.** The official signing certificates of 51 apps: VPN,
  proxy and circumvention tools, the messengers often used with them, and Datapavan itself, collected
  from the developers' own channels with a grade for the evidence.
  A copy that someone else signed is called modified only on positive evidence; an unknown key is shown
  with its fingerprint, without a warning. *Why:* a modified VPN app sees all of its user's traffic and
  looks exactly like the real one.
- **Signed data packs.** All of this data comes inside the signed app. Newer data will come in packs signed
  with the project's key, which can be imported as files without any network permission. A *Data sources* screen shows each dataset's
  date, licence and the pack's fingerprint, and the app warns when its data is more than six months old.
  *Why:* data must stay current, and a list without the project's signature is refused.
- **Network use per app.** With usage access, which the user grants and nothing requires: what each app
  received and sent on mobile data and Wi-Fi in the last 30 or 7 days, and how much in the background,
  in the same units as the phone's own Settings. Apps not opened for 90 days that still hold a
  permission, special access or background data are listed. Only totals are read, never which app was
  opened when, and nothing is kept. *Why:* an app the user forgot can still send data, and Android's
  own clean-up skips some apps and all special access.
- **Checking one activity.** On an app's page, the user names what they will do (watch, scroll,
  download, send), Datapavan reads Android's counts, opens the app, and reads again when the user comes
  back, checking that the count is up to date. For activities that only receive, sent bytes appear as
  a share of received ones, next to what acknowledgements alone take. Facts, never alerts (ADR 0025).
  *Why:* a 30-day total cannot be judged, but one activity can.
- **Remediation plan.** Findings become a short session of cards, those that remove the most risk
  first, at a light, medium or strict level. Each card opens the right screen of Android, where the
  user decides; Datapavan changes nothing itself. A journal on the phone records what actually changed,
  notices when a change comes back, and offers undo; a safety floor leaves alone the apps the phone
  needs (ADR 0026). *Why:* a phone in daily use can have hundreds of apps and dozens of findings, and
  nobody works through that by hand. See [docs/REMEDIATION.md](docs/REMEDIATION.md).
- **Easy to find your way.** A summary, the apps with search, filters and orders, the phone, and network
  use, each one tap away; a plain-language card on each app's page; appearance and language settings on
  every Android version (ADR 0027). A long press on the app's icon goes straight to the plan, the apps
  or network use. *Why:* the findings only help if people can reach them.
- **Screen protection.** Every screen of both apps blocks screenshots and screen recordings, and from
  Android 12 other apps' overlays. To ask for help with a screenshot, the settings allow it for one minute.
  *Why:* what Datapavan shows about a phone should not end up in a gallery, a backup or someone else's
  recording ([ADR 0040](docs/decisions/0040-own-safety-in-an-untrusted-environment.md)).
- **Is this copy genuine?** The app shows its own signing key, checks it against its own list, and says
  plainly that the real check is to compare the key with the one published with each release (ADR
  0024). *Why:* a privacy tool is a tempting thing to fake.

## What comes next

Each item is designed in [docs/DESIGN.md](docs/DESIGN.md) and [docs/VPN.md](docs/VPN.md), but not built
yet.

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
- **Chaining with circumvention tools** (v0.2). Datapavan Watch stays the phone's VPN and sends traffic
  through the tool's local proxy, so the tool becomes a pipe, not the owner of the network. *Why:* Android
  allows one VPN at a time, and people under censorship should not have to choose between access and
  safety. See [docs/RESTRICTED-REGIONS.md](docs/RESTRICTED-REGIONS.md).
- **Blocking** (v0.3): network access per app, tracker domains, and "notifications yes, hidden uploads
  no", which allows an app the network only while it is on screen. *Why:* notifications arrive through
  the system's push service, so most apps need no connection of their own in the background.
- **Reports** (v0.4): a weekly report, a GDPR Article 15 data-access request for each company whose
  trackers were seen, and each app's declared data practices compared with what was observed. *Why:*
  every observation is a concrete reason to ask a company what it holds.

## What it cannot do

On a stock phone Datapavan has the limits of an app. It cannot read encrypted content, and will never
decrypt it. It cannot remove the maker's system apps without a computer, control firmware or the modem,
or clean a phone that is already compromised; it finds the risk and guides the user. Each limit, and the
stage that addresses it, is listed in [docs/DESIGN.md](docs/DESIGN.md#2-what-we-can-and-cannot-protect).

The tracker scan looks for known names in an app's code, as εxodus does, so an SDK that is renamed,
obfuscated or loaded later is missed. Finding nothing is not proof that nothing is there.

## Checking a copy

Version 0.1.2 is on [GitHub Releases](https://github.com/visadahyu/datapavan/releases/tag/v0.1.2) and
[the website](https://datapavan.org/download/datapavan-0.1.2.apk). F-Droid is asked in early 2027, after the
three months of development its policy asks for. [Obtainium](https://github.com/ImranR98/Obtainium) can follow this repository's URL. Every genuine copy,
on every channel, is signed with one key. The SHA-256 fingerprint of its certificate is:

```
FA:6A:24:04:2A:BC:AC:8B:
D0:09:01:10:F7:04:FF:EF:
E7:DA:D3:AD:F5:DB:38:FB:
07:38:90:AB:4C:B1:FA:84
```

Compare it at the first install, with a tool other than Datapavan itself, since a fake can show any
text: for example [AppVerifier](https://github.com/soupslurpr/AppVerifier) on the phone, or
`apksigner verify --print-certs` on a computer. After that, Android refuses updates signed with another
key. **Genuine Datapavan has no internet access and never asks for it.**

Data packs are signed with the key `RWSw7mCAus7/cGyV88xK46P7J51/oMhXNl/V6+25UHD888smCReEQdRB`, and release notes with
`RWQ/vFWwVJPevJW9d5d398A2Pp/MTT0TkpvR+7gsVitHUETHkb92YCvk`. The files, and the commands that check with them, are in
[keys/](keys/README.md).

## Three stages

1. **A layer app** for individuals on stock Android, without root (this repository today).
2. **An enterprise edition** for organisations, in Device Owner mode: system apps disabled, the VPN
   enforced, permissions set by policy.
3. **A hardened Android-based OS** on partner hardware, for users who need control of the whole stack.

## Principles

- **No internet permission in v0.1.** The app cannot open a network connection, and the build fails if
  anything adds the permission. Newer data arrives as signed packs that the user imports as files
  ([DATA-PACKS.md](docs/DATA-PACKS.md)), so the app itself contacts no server.
- **Local-first.** All analysis happens on the device. Datapavan has no servers that receive user data.
- **Zero telemetry.** Datapavan collects nothing about its users and contains no analytics SDKs. It learns
  from its own lab, never from its users' phones ([ADR 0016](docs/decisions/0016-no-user-data.md)).
- **No Google Play Services.** It does not depend on Google's services.
- **Open source.** You can read the code behind these claims. `scripts/reproducible.sh` compares two release
  builds, [docs/CHANNELS.md](docs/CHANNELS.md) records F-Droid's build matching ours on one commit, and
  releases will be signed with keys kept offline.
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
| [docs/DATA-PACKS.md](docs/DATA-PACKS.md) | Signed data packs: how data reaches a phone without network access |
| [docs/LAB.md](docs/LAB.md) | The traffic lab: measuring apps on the project's own phones |
| [docs/RELEASE.md](docs/RELEASE.md) | Releasing: the offline keys, the checklist, reproducible builds |
| [docs/CHANNELS.md](docs/CHANNELS.md) | Where releases go: GitHub, the website, F-Droid (from 2027), Obtainium |
| [docs/DEVICES.md](docs/DEVICES.md) | Phones Datapavan has been tried on, and how to add one |
| [keys/](keys/README.md) | The signing certificate and public keys, and how to check with them |
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

**What is public and what is not.** Strategy, funding, legal questions under review and the research
behind them are kept in the maintainer's private repository. Every decision that changes what
the software does, or how it treats its users, is published here with its reasons, as an
[architecture decision record](docs/decisions/README.md), together with the spikes that measure the
software's behaviour.

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
