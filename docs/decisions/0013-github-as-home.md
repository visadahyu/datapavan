# 0013. GitHub as the only home; Codeberg dropped

- Status: Accepted
- Date: 2026-10-29
- Decided by: mehdashti

## Context
ADR 0002 made Codeberg the primary repository and GitHub a mirror. Codeberg's Terms of Use, amended by
its 2026 general assembly, now prohibit sharing projects that mostly consist of code written by
generative AI tools (§ 2 (1) 7). Violations lead to removal of the content and, if repeated, to account
suspension. Datapavan is developed with AI assistance and says so openly (README, `Assisted-by`
trailers). Staying on Codeberg would mean either breaking its terms or hiding how the project is
built. Neither is acceptable.

## Decision
- GitHub (`visadahyu/datapavan`) is the only repository. Issues, pull requests and CI live there.
- The Codeberg repositories are removed.
- Supersedes [ADR 0002](0002-codeberg-with-github-mirror.md).

## Consequences
- One remote, nothing to keep in sync, and CI results appear where the code lives.
- Hosting with a US company weakens the European-sovereignty story. What makes a build genuine is the release signing key and the reproducible build, not the host, so moving later is cheap. A self-hosted forge in the EU on the project's own domain should be reconsidered once that domain exists.
- GitHub's terms and its trade-controls policy apply. Users in restricted regions get the app from APK mirrors and F-Droid, verified by signature (see [RESTRICTED-REGIONS.md](../RESTRICTED-REGIONS.md)), not from GitHub alone.
