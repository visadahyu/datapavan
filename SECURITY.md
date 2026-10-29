# Security policy

Datapavan is a security product. Reports of vulnerabilities are welcome and taken seriously.

> **Pre-release.** A dedicated security contact (an e-mail address with a published OpenPGP key) will be
> set up before the repository becomes public. Until then, contact the maintainer directly.

## Reporting a vulnerability

- **Do not** open a public issue for a vulnerability.
- Report privately to the security contact. Once the repository is public, GitHub's private
  vulnerability reporting will also be enabled.
- Please include the affected version or commit, the device and Android version, steps to reproduce,
  the impact you expect, and whether you want to be credited.

## What happens next

| Step | Target time |
|---|---|
| Acknowledgement of your report | 3 working days |
| First assessment and severity | 10 working days |
| Fix released for critical issues | as fast as possible, normally within 30 days |
| Public disclosure | coordinated with you, at the latest 90 days after the report |

We credit reporters in the release notes, unless they prefer otherwise.

## Scope

In scope: the Android app, the Rust engine, the build and release pipeline, and signed update payloads.
Especially interesting: anything that lets another app read Datapavan's data or change its rules, any
way to make the app send data off the device, parser crashes on crafted packets or DEX files, and
supply-chain weaknesses.

Out of scope: vulnerabilities in Android itself or in device firmware (report those to the vendor),
and findings that need root access or physical access to an unlocked device.

## Safe harbour

We will not take legal action against research done in good faith that follows this policy, respects
users' privacy and data, and gives us reasonable time to fix the issue before disclosure.

## Supported versions

Before 1.0, only the latest release receives security fixes.
