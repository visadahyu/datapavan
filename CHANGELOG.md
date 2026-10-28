# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- Project skeleton (milestone M1):
  - Android app: Kotlin and Jetpack Compose, minSdk 29, target SDK 37.
  - Rust engine (`datapavan-engine`, `unsafe` forbidden) and JNI bridge (`datapavan-jni`).
- No permissions at all; the build fails if INTERNET is added. Backup and device-to-device transfer are disabled.
- UI in English, French, German and Persian, with right-to-left support, pseudo-locales in debug builds, and LTR token isolation.
- Supply-chain protection: pinned toolchains, the Gradle wrapper checked by SHA-256, verification metadata for every Gradle artifact, repository content filters, and a cargo-deny policy.
- Quality gates in `scripts/check.sh`, run by CI on the GitHub mirror.
- Brand: the Old Persian sign DA as the product mark and app icon, the DAHYĀUŠ logogram for the foundation, and a palette with measured contrast ratios.
- Documentation: design, roadmap, names, brand, VPN design, restricted regions, foundation charter, security policy, contributing guide, privacy policy, code of conduct, and architecture decision records.
