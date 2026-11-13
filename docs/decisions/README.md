# Architecture decision records

Each file records one lasting decision: its context, the decision, and its consequences. Decisions are
made and approved by the maintainer; drafting is AI-assisted, which is disclosed (see
[CONTRIBUTING.md](../../CONTRIBUTING.md)). A changed decision gets a new record that supersedes the old
one. Until the first release, records may still be corrected for accuracy; every correction is visible
in the Git history.

| # | Decision | Status |
|---|---|---|
| [0001](0001-apache-2-licence.md) | Apache-2.0 licence | Accepted |
| [0002](0002-codeberg-with-github-mirror.md) | Codeberg as home, GitHub as read-only mirror | Superseded by 0013 |
| [0003](0003-minimum-android-10.md) | Minimum Android version 10 (API 29) | Accepted |
| [0004](0004-ui-languages-and-rtl.md) | Languages at launch, changed by ADR 0030; RTL from the first commit | Accepted |
| [0005](0005-english-documentation.md) | Documentation in English only | Accepted |
| [0006](0006-rust-engine-unsafe-forbidden.md) | Rust engine with `unsafe` forbidden; separate JNI crate | Accepted |
| [0007](0007-direct-jni-over-uniffi.md) | Direct JNI instead of UniFFI | Accepted |
| [0008](0008-gradle-dependency-verification.md) | Gradle dependency verification, generated from an empty Gradle home | Accepted |
| [0009](0009-no-automatic-jdk-download.md) | Gradle daemon pinned to JDK 21, no automatic JDK download | Accepted |
| [0010](0010-cuneiform-brand-marks.md) | Old Persian cuneiform signs as brand marks | Accepted |
| [0011](0011-m1-test-devices.md) | M1 tested on emulators and the Galaxy A40 only | Accepted |
| [0012](0012-packet-engine.md) | Packet engine for the local VPN: Android's own TCP stack through rewritten addresses, in Rust | Accepted |
| [0013](0013-github-as-home.md) | GitHub as the only home; Codeberg dropped | Accepted |
| [0014](0014-v0.1-permissions.md) | Permissions for v0.1 "Audit" | Accepted |
| [0015](0015-dataset-licences.md) | Licences of bundled datasets | Accepted |
| [0016](0016-no-user-data.md) | No data from users; learning happens in the lab | Accepted |
| [0017](0017-data-pack-format.md) | Data packs in signify's format, checked with ed25519-compact | Accepted |
| [0018](0018-app-signing-certificates.md) | Official signing certificates of VPN, proxy and circumvention apps | Accepted |
| [0019](0019-traffic-sharing-remote-support-sdks.md) | Traffic-sharing, remote-support and screen-recording SDKs | Accepted |
| [0020](0020-same-company-trackers.md) | Trackers from the app's own company group | Accepted |
| [0021](0021-service-dependent-capabilities.md) | Tracker capabilities that need a service the phone lacks | Accepted |
| [0022](0022-network-use-and-unused-apps.md) | Network use per app and apps not opened, from Android's own records | Accepted |
| [0023](0023-maker-software-and-system-keys.md) | The phone maker's software and leaked system keys | Accepted |
| [0024](0024-fake-copies-of-datapavan.md) | Fake copies of Datapavan | Accepted |
| [0025](0025-guided-check-and-traffic-facts.md) | The guided check of one activity, and two traffic facts that need no comparison | Accepted |
| [0026](0026-remediation-plan-v0.1.md) | The remediation plan's part for v0.1 | Accepted |
| [0027](0027-app-structure-and-settings.md) | The app's structure and settings | Accepted |
| 0028 | This number was not used | – |
| [0029](0029-network-access-for-v0.2.md) | v0.2's VPN in a separate app, Datapavan Watch, so that Datapavan never holds INTERNET | Superseded by 0045 |
| [0030](0030-more-languages-reviewed-by-independent-models.md) | Spanish, Russian, Chinese and Arabic at launch, reviewed by independent models | Accepted |
| [0031](0031-datapavan-lite-on-google-play.md) | Datapavan Lite on Google Play: its own name, package and key | Accepted, being built |
| [0032](0032-expert-tool-for-preinstalled-apps.md) | An expert tool of Datapavan's own for preinstalled apps | Proposed |
| [0033](0033-organisational-edition-beside-a-suite.md) | The organisational edition beside a device-management suite | Accepted, not built yet |
| [0034](0034-watch-permissions.md) | Permissions for Watch: five, one only on Android 10 and 11 and one only on 17, and the build's allowlist | Accepted |
| [0035](0035-wireguard-upstream.md) | WireGuard upstream: GotaTun's protocol core in the engine, raw packets forwarded | Accepted |
| [0036](0036-ip-to-organisation-dataset.md) | The IP-to-organisation dataset: DB-IP Lite, checked against iptoasn | Accepted |
| [0037](0037-connection-log-storage.md) | The connection log: records sealed one by one, a key for each day, readable only on an unlocked phone | Accepted |
| [0038](0038-dns-of-chained-apps.md) | DNS of chained apps: stand-in addresses, names to the tool | Accepted |
| [0039](0039-release-gates.md) | Release gates, a preview for identified testers, and what 1.0 means | Accepted |
| [0040](0040-own-safety-in-an-untrusted-environment.md) | Datapavan's own safety in an untrusted environment | Accepted |
| [0041](0041-watch-visibility-and-coexistence.md) | What other apps see of Watch, and working beside every app | Accepted |
| [0042](0042-dns-of-apps-that-go-directly.md) | DNS of apps that go directly: Oblivious DoH, several jurisdictions | Accepted, with open questions |
| [0043](0043-release-integrity-and-repository-controls.md) | Release integrity, repository controls and continuous fuzzing | Accepted |
| [0044](0044-udp-mapping-and-budgets.md) | UDP mapping, budgets for each app, and the engine's smaller gaps | Accepted |
| [0045](0045-three-editions-of-one-app.md) | Three editions of one app: Basic, Advanced and Enterprise | Accepted |
| [0046](0046-live-activity.md) | What apps sent while the user was not using them, shown live | Proposed |

## Template

```markdown
# NNNN. Title

- Status: Proposed | Accepted | Superseded by NNNN
- Date: YYYY-MM-DD
- Decided by: name or pseudonym

## Context
Why a decision is needed; the forces and constraints.

## Decision
What we decided.

## Consequences
What becomes easier or harder, and what we accept in return.
```
