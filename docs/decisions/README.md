# Architecture decision records

Each file records one lasting decision: its context, the decision, and its consequences. Records are
never rewritten. A changed decision gets a new record that supersedes the old one.

| # | Decision | Status |
|---|---|---|
| [0001](0001-apache-2-licence.md) | Apache-2.0 licence | Accepted |
| [0002](0002-codeberg-with-github-mirror.md) | Codeberg as home, GitHub as read-only mirror | Accepted |
| [0003](0003-minimum-android-10.md) | Minimum Android version 10 (API 29) | Accepted |
| [0004](0004-ui-languages-and-rtl.md) | UI languages at launch, RTL from the first commit | Accepted |
| [0005](0005-english-documentation.md) | Documentation in English only | Accepted |
| [0006](0006-rust-engine-unsafe-forbidden.md) | Rust engine with `unsafe` forbidden; separate JNI crate | Accepted |
| [0007](0007-direct-jni-over-uniffi.md) | Direct JNI instead of UniFFI | Accepted |
| [0008](0008-gradle-dependency-verification.md) | Gradle dependency verification, generated from an empty Gradle home | Accepted |
| [0009](0009-no-automatic-jdk-download.md) | Gradle daemon pinned to JDK 21, no automatic JDK download | Accepted |
| [0010](0010-cuneiform-brand-marks.md) | Old Persian cuneiform signs as brand marks | Accepted |
| [0011](0011-m1-test-devices.md) | M1 tested on emulators and the Galaxy A40 only | Accepted |
| [0012](0012-packet-engine.md) | Packet engine for the local VPN | Proposed (spike pending) |

## Template

```markdown
# NNNN. Title

- Status: Proposed | Accepted | Superseded by NNNN
- Date: YYYY-MM-DD

## Context
Why a decision is needed; the forces and constraints.

## Decision
What we decided.

## Consequences
What becomes easier or harder, and what we accept in return.
```
