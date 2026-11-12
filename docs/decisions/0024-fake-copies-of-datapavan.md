# 0024. Fake copies of Datapavan

- Status: Accepted
- Date: 2026-10-31
- Amended by [ADR 0045](0045-three-editions-of-one-app.md) on 2026-11-13: the project ships as three editions of one app.
- Decided by: mehdashti

## Context
Datapavan checks whether other apps are genuine (ADR 0018) and whether the phone's system key can be
trusted (ADR 0023). The more people use it, the more fake copies of Datapavan itself will spread
through channels, app mirrors and messaging groups: the very problem it detects for others. A fake
copy could collect what Datapavan sees, or tell people that their modified apps are genuine.

An app cannot prove its own authenticity from inside. A modified copy can remove any self-check and
show any fingerprint it likes. The check that decides must therefore happen outside the copy being
judged. Projects with the same problem (Signal, Briar, GrapheneOS) publish their signing fingerprints
and point to external verifiers; none of them has partner tools that check each other's copies.

## Decision
The defence is layered, from the first public release:

1. **Android after the first install.** Android refuses an update signed with another key, so a phone
   that has a genuine copy cannot be "updated" to a fake. The first install is the moment of risk, and
   the documentation says so.
2. **Published fingerprints, everywhere.** The SHA-256 of the app's signing certificate is published
   on the website and its mirrors, in the README, in every release note signed with signify, on the
   project's accounts and in partners' documentation, with an entry for AppVerifier (an open-source app
   that compares an installed app's key with a published value).
3. **Trusted channels.** F-Droid (which checks reproducible builds), Google Play, GitHub Releases and
   the website. Release announcements are signed, so that channel operators can check them too.
4. **Mutual checks.** Datapavan lists its own official keys in `data/app-signers`, and partner tools
   (for example VPN and circumvention apps) are invited to list Datapavan's. A genuine Datapavan, or a
   partner's tool, can then judge a copy of Datapavan on the same phone. Datapavan also notes apps
   that use its name or icon (the lookalike notice, ADR 0018 decision 8).
5. **A self-check as a speed bump only.** The app compares its own signing key with the one built
   into it and shows the result, which stops naive repackaging but not a determined forger. The screen
   says plainly that the real check is the published fingerprint, compared from outside.
6. **Reproducible builds,** so that anyone can rebuild a release from source and compare.
7. **Takedowns.** With the registered trademark, the project asks stores and channels to remove fakes,
   and watches for them.
8. **One sentence to teach:** "Genuine Datapavan has no internet access and never asks for it." (Until
   2026-11-05 it said "v0.1"; ADR 0029 keeps the INTERNET permission out of Datapavan for good.)
   Any copy that asks for it is not genuine. When a later version needs network access, the sentence
   changes with it, and the release notes say so.

## Consequences
- The signing key's custody matters more than ever: it is made offline, with a documented ceremony
  and a second custodian, before the first release (the data-signing key follows DATA-PACKS.md).
- The first release cannot ship until the fingerprints are published in at least two independent
  places and the self-check and lookalike notice are built.
- Partners get a short guide for listing Datapavan's keys and for pointing their users to it.
- Datapavan's own entry in `data/app-signers` is added with the first release, from the published
  fingerprint (grade 1).
- Limits accepted: a user who installs a fake first and never compares a fingerprint is not protected
  by anything inside the fake; the defence is that the genuine paths are easy and well known.
