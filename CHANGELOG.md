# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Project skeleton (milestone M1):
  - Android app: Kotlin and Jetpack Compose, minSdk 29, target SDK 37.
  - Rust engine (`datapavan-engine`, `unsafe` forbidden) and JNI bridge (`datapavan-jni`).
- App audit (milestone M2, first part): every installed app with its install source, dates, dangerous permissions and special access; risk checks for VPN apps that could control the phone, preinstalled data collectors, apps that can install other apps, and sensor access; phone-wide checks for USB and wireless debugging, user-installed certificate authorities, an active VPN, an old security patch, and the bootloader and verified-boot state from hardware key attestation, decoded by a Rust parser.
- Strict sensor review: a guided pass through every app with microphone, camera or location access, which remembers what each app had when reviewed and brings it back if it gains access again; voice assistants that listen for a wake word are named, with a link to their setting; the privacy dashboard is linked on Android 12+. Preinstalled data collectors get a guide to disable them, or to remove them reversibly for the user from a computer.
- Hardware attestation is checked like a verifier on a server would: every certificate in the chain must be signed by the next, the root must hold one of Google's two attestation root keys, and no certificate may be on Google's revocation list. A revoked key or a chain that Google does not vouch for is reported. Google's roots and the revoked serial numbers ship in `data/attestation`, with their licence, source and converter.
- DEX parser in the Rust engine (milestone M3, first part): lists the classes that an app's DEX files define, for DEX versions 035 to 041, including version 041's containers of several logical files. It treats other apps' code as untrusted input, is fuzzed like every parser, and matched the SDK's `dexdump` exactly on 109 DEX files from 22 real apps (651,420 classes; `scripts/compare-dex.sh`).
- Tracker matching (milestone M3, second part): the εxodus tracker signatures in `data/exodus` (432 trackers, ODbL, with their licence, source and converter), the list of classes an app's code refers to, and a matcher in the Rust engine that finds the signatures in one pass with an Aho-Corasick automaton and tells trackers whose code an app contains from those it only refers to. Compared with εxodus reports on 22 real apps, it found every tracker that εxodus reports for the same version ([spike](docs/spikes/2026-10-m3-exodus-comparison.md)).
- Tracker scan in the app (milestone M3, third part): every installed app's code, in its base APK and every split, is matched against the εxodus signatures by the Rust engine. The overview shows the scan's progress and how many apps contain trackers; each app's page lists its trackers with their purpose, apart from those its code only refers to, and names the εxodus database and its licence. Results are cached and reused while an app and the signatures stay unchanged, and saved as the scan goes. On the A40, the first scan of 436 apps takes about two minutes, later ones seconds.
- Permissions (ADR 0014): see all installed apps, and network state to tell whether a VPN is active. The build fails if INTERNET is added through any build path (APK, bundle or install). Cloud backup and device-to-device transfer are disabled.
- UI in English, French, German and Persian, with right-to-left support, pseudo-locales in debug builds, and LTR token isolation.
- Supply-chain protection:
  - pinned toolchains;
  - the Gradle distribution pinned by checksum, and the wrapper jar validated in CI;
  - SHA-256 verification for every Gradle artifact;
  - exclusive repository content (Google's groups only from Google, everything else only from Maven Central);
  - a cargo-deny policy;
  - native libraries built without paths from the build machine.
- Quality gates in `scripts/check.sh`, run by CI on GitHub, including a check that every APK carries the Rust library and its JNI export, a check that every bundled dataset names its licence and source, an emulator smoke test (`scripts/smoke.sh`), an end-to-end check of the audit's findings with a test fixture app (`scripts/verify-audit.sh`), and screenshots in all four languages and both pseudo-locales with an accessibility check (`scripts/screenshots.sh`).
- Fuzzing of the attestation and DEX parsers and, against a plain search, of the tracker matcher, with cargo fuzz (`scripts/fuzz.sh`): locally, for two minutes in CI when the engine changes, and for twenty minutes every week.
- Brand: the Old Persian sign DA as the product mark and app icon, the DAHYĀUŠ logogram for the foundation, a palette with measured contrast ratios, and avatars.
- Documentation: design, roadmap, names, brand, VPN design, restricted regions, foundation charter, security policy, contributing guide (with the AI-assistance rules), privacy policy, code of conduct, and architecture decision records, including the licence check of every planned dataset (ADR 0015) and the decision to collect no data from users (ADR 0016); the design of the remediation plan.

### Security

- EmojiCompat's start-up lookup of a downloadable font through Google Play services is disabled.
- Release builds of the Rust engine keep integer-overflow checks.

[Unreleased]: https://github.com/visadahyu/datapavan/commits/main
