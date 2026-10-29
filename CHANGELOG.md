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
- Fuzzing of the attestation parser with cargo fuzz, locally and for two minutes in every CI run (`scripts/fuzz.sh`).
- Brand: the Old Persian sign DA as the product mark and app icon, the DAHYĀUŠ logogram for the foundation, a palette with measured contrast ratios, and avatars.
- Documentation: design, roadmap, names, brand, VPN design, restricted regions, foundation charter, security policy, contributing guide (with the AI-assistance rules), privacy policy, code of conduct, and architecture decision records, including the licence check of every planned dataset (ADR 0015).

### Security

- EmojiCompat's start-up lookup of a downloadable font through Google Play services is disabled.
- Release builds of the Rust engine keep integer-overflow checks.

[Unreleased]: https://github.com/visadahyu/datapavan/commits/main
