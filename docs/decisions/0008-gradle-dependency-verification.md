# 0008. Gradle dependency verification, generated from an empty Gradle home

- Status: Accepted
- Date: 2026-10-28

## Context
A compromised dependency is one of the most likely ways to attack a security app. Gradle can check
every downloaded artifact against recorded SHA-256 hashes. The first CI run failed even though local
builds passed: a warm local cache never re-resolves metadata files (BOMs, parent POMs), so they were
missing from the recorded hashes.

## Decision
- `android/gradle/verification-metadata.xml` records SHA-256 hashes for every artifact and metadata file, and verification is strict.
- The file is always regenerated in an **empty** Gradle user home, and checked with `--refresh-dependencies`, which reproduces what a clean CI machine sees.
- Each repository may serve only its expected artifact groups (content filtering).

## Consequences
- Any change to a dependency, or to an artifact served under an existing name, stops the build.
- Updating dependencies takes a deliberate step, and its diff must be reviewed.
- The file currently covers Linux build hosts; macOS and Windows hosts need their platform-specific artifacts added.
