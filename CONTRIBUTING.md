# Contributing

Thank you for helping. Datapavan's home is **Codeberg**: issues and pull requests go to
<https://codeberg.org/visadahyu/datapavan>. The GitHub repository is a read-only mirror.

## Before you start

- Read [docs/DESIGN.md](docs/DESIGN.md) and the [roadmap](ROADMAP.md). For larger changes, open an issue first so we can agree on the approach.
- Lasting decisions are recorded as ADRs in [docs/decisions/](docs/decisions/). A change that alters one of them needs a new ADR.
- Security issues: see [SECURITY.md](SECURITY.md). Never in public issues.

## Setup and checks

The build setup is described in the [README](README.md#building). Every change must pass:

```sh
scripts/check.sh
```

This runs rustfmt, Clippy (pedantic, warnings as errors), the Rust tests, cargo-deny, Android Lint
(warnings as errors), the unit tests, debug and release builds, and the forbidden-permission guard.
CI runs the same script.

## Rules for code

- **Untrusted input is parsed in Rust,** in `datapavan-engine`, where `unsafe` is forbidden. `unsafe` is allowed only in `datapavan-jni`, and every block needs a `// SAFETY:` comment.
- **No new permissions** without discussion. INTERNET is forbidden in v0.1, and the build enforces it.
- **No new dependencies** without discussion. Every dependency is a supply-chain risk and adds size. After an agreed dependency change, regenerate `android/gradle/verification-metadata.xml` from an empty Gradle home (see the README) and include the diff.
- **User-visible text** goes in string resources. Never concatenate strings; use plurals. Wrap domains, IPs, package names and versions with `isolateLtr()`.
- **Never copy code from GPL projects** (e.g. NetGuard). This project is Apache-2.0.

## Commits

- Write the subject line in the imperative ("Add …", "Fix …"), and explain *why* in the body.
- Sign off every commit (`git commit -s`). This certifies the [Developer Certificate of Origin](https://developercertificate.org/): you wrote the change, or have the right to submit it under the project's licence.
- Contributions are licensed under Apache-2.0, the same as the project.

## AI-assisted contributions

AI tools may be used, under these conditions:

- **Say so** in the pull request: which tool you used and for what.
- **You are the author.** You have read, understood and tested every line, and you can explain and defend it in review.
- **Keep the design human.** Architecture decisions and ADRs are made and written by people.
- Some funders do not accept AI-generated code in the work they pay for. Work for such grants is marked as such and done without AI code generation.

## Translations

The UI ships in English, French, German and Persian. Translations will move to Weblate. Until then,
open a pull request against `android/app/src/main/res/values-<lang>/strings.xml`. Follow the glossary,
and keep the plain-language tone.

## Conduct

Everyone taking part follows the [code of conduct](CODE_OF_CONDUCT.md).
