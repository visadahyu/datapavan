# Security policy

Datapavan is a security product. Reports of vulnerabilities are welcome and taken seriously.

> **Releases.** The audit app's current release is 0.1.2, of 2026-11-07. Datapavan Watch, the second
> app, has not been released yet. Private reports go through GitHub's private vulnerability reporting, or by
> e-mail to security@datapavan.org. An OpenPGP key for that address will be published here; until then, send
> a first contact by e-mail without the details, and we will agree on a private channel.

## Reporting a vulnerability

- **Do not** open a public issue for a vulnerability.
- Report privately through [GitHub's private vulnerability
  reporting](https://github.com/visadahyu/datapavan/security/advisories/new), or by e-mail to
  security@datapavan.org (see the note above about encryption).
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

In scope: both Android apps (the audit app and Datapavan Watch), the Rust engine, the build and release
pipeline, and signed update payloads. Especially interesting: anything that lets another app read
Datapavan's data or change its rules, any way to make either app send data off the device, traffic that
escapes the user's circumvention tool when Watch chains through it, parser crashes on crafted packets or
DEX files, and supply-chain weaknesses. Also in scope: what someone holding an unlocked phone can read of
Watch's log or chain settings beyond what [ADR 0037](docs/decisions/0037-connection-log-storage.md) and
[ADR 0040](docs/decisions/0040-own-safety-in-an-untrusted-environment.md) promise, since a phone check is a
threat the design names.

Out of scope: vulnerabilities in Android itself or in device firmware (report those to the vendor), and
findings that need root access.

## Safe harbour

We will not take legal action against research done in good faith that follows this policy, respects
users' privacy and data, and gives us reasonable time to fix the issue before disclosure.

## Supported versions

Before 1.0, only the latest release receives security fixes.
