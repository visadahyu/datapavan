# Contributing

Thank you for helping. Issues and pull requests go to <https://github.com/visadahyu/datapavan>.

## Before you start

- Read [docs/DESIGN.md](docs/DESIGN.md) and the [roadmap](ROADMAP.md). For larger changes, open an issue first so we can agree on the approach.
- Lasting decisions are recorded as ADRs in [docs/decisions/](docs/decisions/). A change that alters one of them needs a new ADR.
- Security issues: see [SECURITY.md](SECURITY.md). Never in public issues.

## Setup and checks

The build setup is described in the [README](README.md#building). Every change must pass:

```sh
scripts/check.sh
```

This runs rustfmt, Clippy (pedantic, warnings as errors, for the host and both Android targets), the
Rust tests, cargo-deny, Android Lint for debug and release (warnings as errors), the unit tests, APK and
bundle builds, the forbidden-permission guard, and a check that every APK carries the Rust library.
CI runs the same script, and then the emulator checks in parallel shards (`scripts/emulator-shard.sh`), when a
change touches what they test (`scripts/ci-scope.sh`). `scripts/emulator-shards.sh` runs the same shards on
local emulators before a push, and `scripts/batch-merge.sh` brings several approved branches into one branch
for one CI run before main moves to it.

## Rules for code

- **Untrusted input is parsed in Rust,** in `datapavan-engine`, where `unsafe` is forbidden. `unsafe` is allowed only in `datapavan-jni`, and every block needs a `// SAFETY:` comment.
- **No new permissions** without discussion. INTERNET is forbidden in v0.1, and the build enforces it.
- **No new dependencies** without discussion. Every dependency is a supply-chain risk and adds size. After an agreed dependency change, regenerate `android/gradle/verification-metadata.xml` from an empty Gradle home (see the README) and include the diff.
- **User-visible text** goes in string resources. Never concatenate strings; use plurals. Wrap domains, IPs, package names and versions with `isolateLtr()`.
- **Never copy code from GPL projects** (e.g. NetGuard). This project is Apache-2.0.

## Commits

- Write the subject line in the imperative ("Add …", "Fix …"), and explain *why* in the body.
- Sign off every commit (`git commit -s`). This certifies the [Developer Certificate of Origin](https://developercertificate.org/): you wrote the change, or have the right to submit it under the project's licence. A consistent pseudonym is accepted, because contributors in restricted regions may not be able to use their legal name safely.
- Contributions are licensed under Apache-2.0, the same as the project.

## AI-assisted contributions

AI tools may be used, under the same conditions for contributors and maintainers:

- **Say so.** Add an `Assisted-by:` trailer to each commit that was drafted with AI help (for example `Assisted-by: Claude (Anthropic)`), and mention it in the pull request.
- **You are the author.** You have read, understood and tested every line, and you can explain and defend it in review.
- **People decide.** Architecture decisions and ADRs are made and approved by a named maintainer. Drafting them may be AI-assisted, and that is disclosed.
- Work funded by a grant follows that funder's rules on AI use.
- **Outside review of security-critical code.** Code that parses hostile input or guards secrets gets a human
  reviewer from outside the project before a stable release ([ADR 0043](docs/decisions/0043-release-integrity-and-repository-controls.md)).

## What may be public

This repository is public, and so is every branch pushed to it, with its CI logs. Three rules follow, for
contributors and maintainers alike, and for AI agents working here:

- **A branch is a publication.** A draft finding that names a company, a bank or a state stays out of every
  public branch until it meets [ADR 0015](docs/decisions/0015-dataset-licences.md)'s standard of evidence. Only
  the finished version is pushed.
- **No live circumvention endpoints.** No server, bridge, relay or resolver that works in a given country now
  goes into the repository, its issues or its CI logs: a censor would block it at once. Public tools and their
  public defaults are fine.
- **Findings on state-linked tools appear under the project's name.** People who work on them are not named in
  the finding, for their safety.

## Translations

The UI ships in English, French, German, Spanish, Russian, Simplified Chinese, Arabic and Persian. Corrections from native
speakers are especially welcome ([ADR 0030](docs/decisions/0030-more-languages-reviewed-by-independent-models.md)). Translations will move to Weblate. Until then,
open a pull request against `android/app/src/main/res/values-<lang>/strings.xml`. Keep key terms consistent
with the existing translations (a per-language glossary will come with the Weblate setup), and keep the
plain-language tone.

## Conduct

Everyone taking part follows the [code of conduct](CODE_OF_CONDUCT.md).
