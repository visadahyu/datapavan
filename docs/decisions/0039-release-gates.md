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

## The speed budget of direct apps' names (W8, part 1, 2026-11-20)

Gate 7's "speed budget, measured per release" begins with the names of the apps that go directly
([ADR 0042](0042-dns-of-apps-that-go-directly.md)). Measured on 2026-11-20, on one residential network, warm, 30
public names, one connection per way kept open as Watch keeps it (`scripts/dns-latency.py`, clients independent of
the app, endpoints and addresses from the data pack):

| Way | p50 | p95 |
|---|---|---|
| Plain DNS to the network's resolver (the baseline) | 45 ms | 230 ms |
| ODoH, Numa to Cloudflare (first default) | 147 ms | 171 ms |
| ODoH, crypto.sx on Fastly to dnscry.pt fra01 (second) | 135 ms | 282 ms |
| DoH to Cloudflare, the first target's operator | 146 ms | 203 ms |
| DoH to dnscry.pt fra01 | 123 ms | 128 ms |
| DoT presets: Cloudflare, Quad9 without blocking | 42, 57 ms | 145, 227 ms |

**The budget:** on the same network, the default way's warm p50 at most 150 ms above plain DNS's, and its p95 at
most 250 ms above it (measured: +102 ms and −59 ms), checked by `scripts/dns-latency.py` before each release that
carries Watch (docs/RELEASE.md, step 3), which exits non-zero over the budget or when the default pair or plain DNS
does not answer; and Watch's own cost of each way, where every server is a few milliseconds away (the DNS lab), in
the same form, against plain DNS timed in the same step: each way's p50 at most 100 ms above plain DNS's, its p95 at
most 250 ms above plain DNS's, and plain DNS's own p50 through Watch at most 100 ms, held by `scripts/verify-dns.sh`
on CI's dns shard (below). The first query of a way opens its TLS connection: 250 to 300 ms on the internet for an
ODoH pair, which Android's cache and Watch's own then hide for each name's time to live. Battery on a phone is W9's.

**How the lab holds it (2026-11-21).** W8's fix round (review R-M5) first wrote the lab's bound absolute, p50 at most
100 ms and p95 at most 250 ms over every exchange of the check (400 ms was three times what the lab measured and
equal to the hedge's delay; measured then on the Android 15 emulator: ODoH 7 and 124 ms, DoH 2 and 7 ms, DoT 1 and
5 ms). On CI it failed about every other run (runs 44899858955, 44905337897, 44910873200 and 44910928225,
`docs/ci-flakes.md`): the p50 within, 11 to 23 ms, the p95 over, 301 to 542 ms, and the same build passing its rerun
at 57 to 122 ms. The engine keeps the last 256 durations of each carry for the whole check, a carry had 20 to 250 of
them, and so the "p95" was its largest one to three, which one stall of CI's emulator decided; and those stalls hold
every process on the emulator, not Watch alone. So the check now measures as the budget on real networks is written:

- **Only the step's own exchanges.** A debug build's command (`dns-times-clear`) clears the engine's durations before
  each way, after one lookup that opens the way's connection, since the budget on real networks is warm.
- **Enough of them.** The project's workload app looks up 100 fresh names of the way in one process, one after the
  other, so that the p95 of some 200 exchanges (an A and an AAAA question for each) is about its tenth largest.
- **A baseline from the same moments.** Each of those lookups is followed by one of a fresh local name under
  `home.arpa`, which only the network's resolver answers: plain DNS, through Watch's engine and the same Kotlin
  exchanger, without encryption (the lab's resolver answers NXDOMAIN, which the engine times as an answer: held by a
  unit test, and the check fails with fewer than 100 such exchanges). A stall of the emulator then falls on both
  carries alike.
- **The bounds.** Each way against plain DNS, as above, and plain DNS's p50 at most 100 ms, so that a slowness
  common to every carry still fails. The message gives both carries' figures. No retry.

It is not a looser budget: what is bounded is still Watch's own cost of a way, its time above plain DNS's at the
same moments, by margins no wider than on real networks (100 ms on the p50, where they allow 150; 250 ms on the
p95), and an absolute bound stays, on plain DNS's p50. Measured on the Android 15 emulator (emulated x86_64, three
runs in a row, each on a freshly booted emulator; p50 and p95, plain DNS's in the same step in brackets): ODoH 10 to
11 and 49 to 52 ms (0 to 1 and 1 to 10 ms), DoH 1 and 3 to 7 ms (0 and 3 to 4 ms), DoT 0 to 1 and 2 to 9 ms (0 to 2
and 5 to 11 ms). A debug build whose engine waited 150 ms before each encrypted exchange, a local edit for this test
alone, failed the check at its first way: ODoH p50 154 ms and p95 200 ms, against plain DNS's 1 and 1 ms. Watch's
process spent 1 to 5 ms of CPU per lookup in the lab, the local lookups among them (15 to 24 ms as measured before,
when each lookup was a new start of the workload app).
