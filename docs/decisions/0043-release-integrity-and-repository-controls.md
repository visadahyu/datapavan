# 0043. Release integrity, repository controls and continuous fuzzing

- Status: Accepted (by the maintainer on 2026-11-12)
- Date: 2026-11-12

## Context

Releases are reproducible ([docs/RELEASE.md](../RELEASE.md), `scripts/reproducible.sh`): two builds give the
same bytes, which the offline signing then signs. Two builds on the same computer prove that the build is
deterministic, not that it is clean. A compromised development computer, or a poisoned toolchain on it, gives
the same backdoored bytes twice, and the signature then vouches for them. Nobody outside the project could
tell that a build had been made for one person alone.

The repository's main branch had no rules: anyone holding a push token, agents included, could rewrite it,
and a commit whose CI failed could still become a release candidate. Fuzzing ran for minutes a week. Most of
the code is written with AI coding agents, to the maintainer's design and under the maintainer's review
(CONTRIBUTING.md), and there is one maintainer.

## Decision

1. **Matching hashes before signing.** Before any offline signing, starting with Watch 0.2.0, the APK built
   in CI and the APK built from F-Droid's build image must both match the bytes to be signed. A mismatch stops
   the release.
2. **A public transparency log.** The hash of each release and of each data pack is published to a Sigsum
   log. A build or pack made for a few people would then show up, or fail to verify.
3. **Build provenance.** CI publishes SLSA provenance for each release build: which commit, which workflow,
   which runner.
4. **Rules on main.** A ruleset on `main` requires green CI and signed commits, and forbids force-pushes and
   deletion. Agents sign their commits with an SSH key of their own. That key is kept apart from every release
   and data key, and it can be revoked alone.
5. **Continuous fuzzing.** The project applies to OSS-Fuzz. Until it is admitted, ClusterFuzzLite runs the
   fuzz targets in CI on every change and keeps their corpora.
6. **An outside reviewer for security-critical code.** Before a stable release, the code paths that parse
   hostile input or guard secrets get a human reviewer from outside the project:
   - packet and DNS parsing;
   - TLS and QUIC names;
   - SOCKS5;
   - the DEX scanner;
   - attestation;
   - data-pack signatures;
   - the log's sealing;
   - the JNI boundary.

   With one maintainer this is the independent review of ADR 0039. A second maintainer adds a review of every
   change to these paths.
7. **Reports by e-mail too.** Security reports can also go to `security@datapavan.org`. An OpenPGP key for it
   is published in SECURITY.md, so reports can be encrypted.

## Consequences

- **Releases need CI and F-Droid's image to agree,** which adds a step and a dependency on F-Droid's build
  image to every signing.
- **Pushing changes for agents.** Unsigned commits are refused on `main`, and the push-cadence rule follows: a
  change reaches `main` only through a green run.
- **Sigsum and provenance add public records.** They name no person. They show that a release or pack exists
  and where it came from.
- **The single maintainer remains a limit.** Rule 6 covers it in part until a second person joins.
