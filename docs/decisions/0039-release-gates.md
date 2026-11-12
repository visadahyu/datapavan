# 0039. Release gates, a preview for identified testers, and what 1.0 means

- Status: Accepted (by the maintainer on 2026-11-12)
- Date: 2026-11-12

## Context

Until now the roadmap listed features and milestones, each with a "done when". It had no gates that a
release as a whole must pass. Watch will carry all of a phone's traffic, often for people who may be at risk.
Several conditions decide whether a release of it is safe:
- whether it shows what it cannot see;
- whether it works with the apps people depend on;
- whether anyone outside the project has reviewed it;
- whether its safety texts were read by native speakers.

None of these was a condition of release. A re-audit of the project against the field's best on 2026-11-12
found that the features stand at or above the field. The assurance around them stands below it: outside
review, staged release, compatibility, testing with people, and native review. It also found public documents
that stated as true what was not, with no step that checked them.

The bar the maintainer set on 2026-11-11 is best in class. A release that cannot show it meets that bar says
so, and does not reach the public as if it did.

## Decision

**Gates for every release of either app:**
1. **A truth check.** Every statement of state in the public documents is read against the code and the
   record before the release: versions, channels, mirrors, what is built, what is planned. A script checks
   what it can (SECURITY.md's version against the latest tag, the ADR table against `docs/decisions/`, the
   roadmap's status date), and RELEASE.md's checklist carries the rest.
2. **Build integrity.** As [ADR 0043](0043-release-integrity-and-repository-controls.md) sets it: the hash
   built in CI and the hash built from F-Droid's build image match before anything is signed.
3. **The CI matrix is green** on every Android version the release promises, from Android 10 up.
4. **Native review of care and safety texts.** Every string that warns about someone who may be watching the
   user, or tells a person at risk what to do, is read by a native speaker of each UI language before release.
   Model review (ADR 0030) stays for the other strings.
5. **Licences and SBOM.** The licence statements match what ships, and each release carries its software bill
   of materials.

**Gates for Watch 0.2.0, on top of those:**
1. Watch says plainly what other apps can see while it runs, and lets the user leave an app out of the tunnel
   ([ADR 0041](0041-watch-visibility-and-coexistence.md)).
2. The forwarding path's known gaps are closed. Calls and peer-to-peer apps keep their direct paths. No one app
   can use up the sockets and ports of every app. Flows on shared CDN addresses are not given another site's
   name. Ping works.
3. Android 17's local-network rule is built (ADR 0034, as amended by ADR 0041).
4. Tools whose proxy takes no password, or whose UDP relay accepts other apps, are handled as ADR 0041 says.
5. Watch's own safety, as [ADR 0040](0040-own-safety-in-an-untrusted-environment.md) sets it.
6. The compatibility matrix is published and kept current (ADR 0041).
7. Four things the user meets directly:
   - a page that says what Watch cannot see;
   - a speed and battery budget, measured per release;
   - wording tested with people who are not experts;
   - a way for the user to flag a finding they think is wrong.
8. A second way to get the apps exists besides GitHub and the website.

**A preview before outside review.** A Watch build that has not had an independent security review goes only
to testers who have identified themselves to the project, each told that it is not yet reviewed. It is not
published as a release for everyone. Public release comes after the review, and its findings are fixed or
stated.

**1.0, of both apps**, means:
- all the gates above;
- an independent review of both apps;
- published compatibility and device matrices;
- native review of every UI language;
- a second holder of the signing keys.

## Consequences

- **The roadmap changes shape.** It lists features with their gates, and 1.0 is reached by the gates, not by a
  feature count. ROADMAP.md and DESIGN.md §13.2 point here.
- **Releases may come later.** Each gate costs time, people or outside help, and the project says so rather
  than shipping around them. A gate that cannot be met yet is named in the release's notes. It is never
  silently skipped.
- **The second key holder ties 1.0 to people as well as code.**
- **Two limits stay named.** A second human reviewer on every security change is not possible with one
  maintainer; the outside review before public release covers part of it. Hiding Watch from other apps is not
  possible on stock Android (ADR 0041).
