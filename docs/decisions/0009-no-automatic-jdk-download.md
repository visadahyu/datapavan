# 0009. Gradle daemon pinned to JDK 21, no automatic JDK download

- Status: Accepted
- Date: 2026-10-28

## Context
Builds must be reproducible, and the Android Gradle Plugin is tested against JDK 21, while developer
machines may have newer JDKs (25 on the founder's machine). Gradle's `updateDaemonJvm` task requires a
toolchain download repository, which would let a build fetch a JDK from the internet on its own.

## Decision
`android/gradle/gradle-daemon-jvm.properties` contains `toolchainVersion=21`, written by hand. No
toolchain download repository is configured.

## Consequences
- The daemon always runs on JDK 21, even when Gradle is launched with another JDK.
- A machine without JDK 21 fails with a clear message instead of downloading one silently. Developers install JDK 21 themselves.
