# 0002. Codeberg as home, GitHub as read-only mirror

- Status: Superseded by [0013](0013-github-as-home.md)
- Date: 2026-10-28

## Context
The project positions itself within European digital sovereignty. GitHub has the largest audience
and the most capable free CI. Codeberg is a non-profit in Berlin.

## Decision
- Codeberg (`visadahyu/datapavan`) is the primary repository. Issues and pull requests live there.
- GitHub (`visadahyu/datapavan`) is a read-only mirror. The local `origin` remote pushes to both.
- CI runs on the GitHub mirror until access to Codeberg's Woodpecker CI is granted. Both call the same `scripts/check.sh`.

## Consequences
- The hosting matches the project's story, and we still reach GitHub's audience.
- Two remotes must stay in sync. A single `git push` to `origin` handles that.
- For now, CI results appear on GitHub, not on Codeberg.
