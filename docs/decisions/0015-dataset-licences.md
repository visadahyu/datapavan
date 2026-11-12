# 0015. Licences of bundled datasets

- Status: Accepted
- Date: 2026-10-29
- Decided by: mehdashti

## Context
v0.1 has no INTERNET permission, so every dataset that Datapavan uses ships inside the APK and is
updated with each release. The enterprise edition (stage 2) will be sold, so a dataset is usable only
if its licence allows commercial use. Both editions use the same datasets, so that no finding depends
on which edition a user runs.

DESIGN §9 listed the candidates with their licences still to be verified. They were read from each
project's own licence file or website on 2026-10-29:

| Dataset | Licence, as the source states it | Commercial use |
|---|---|---|
| εxodus tracker database (432 trackers with code and network signatures) and its reports | ODbL 1.0; individual contents under DbCL 1.0 (READMEs of `Exodus-Privacy/exodus` and `Exodus-Privacy/etip`). The εxodus software itself is AGPL-3.0 | Yes |
| EasyPrivacy | GPL-3.0-or-later or CC BY-SA 3.0-or-later, at the user's choice; attribution to "The EasyList authors" (easylist.to licence page) | Yes |
| HaGeZi DNS blocklists | GPL-3.0; its README says that upstream sources keep their own terms | Yes, but the upstream terms are unchecked |
| Disconnect tracking protection | CC BY-NC-SA 4.0 (repository LICENSE) | No |
| DuckDuckGo Tracker Radar | CC BY-NC-SA 4.0 (repository LICENSE) | No |
| IPtoASN | PDDL 1.0 (iptoasn.com) | Yes, without attribution |
| DB-IP Lite | CC BY 4.0; attribution "IP Geolocation by DB-IP" with a link (db-ip.com) | Yes, with attribution |
| JA3 and JA4 (TLS client fingerprints) | BSD-3-Clause (`salesforce/ja3`, `FoxIO-LLC/ja4`) | Yes |
| JA4+ (JA4S, JA4H, JA4X and the other methods) | FoxIO License 1.1, patent pending; the README says it "is not permissive for monetization" | No, without an OEM licence |
| Google's attestation root certificates | Apache-2.0: the Android Developers site states that its documentation, including code shown in it, is under Apache-2.0 (developer.android.com/license) | Yes |
| Google's attestation revocation list (`android.googleapis.com/attestation/status`) | No licence stated. Google publishes it for anyone who verifies key attestation | Unclear |
| Google Play data-safety labels | The Play terms forbid redistributing content; Play's robots.txt disallows `/store/apps/datasafety*`; Google's terms forbid automated access against robots.txt | Not applicable |

Two needs have no ready dataset. The εxodus database contains no proxy or remote-access SDKs (checked
on 2026-10-29). Official signing certificates of circumvention tools are published only in each
project's own channels.

## Decision
1. **εxodus under ODbL.** The tracker signatures are converted into `data/exodus/`, a derivative
   database under ODbL 1.0. Datapavan writes its own matcher in Rust and copies no εxodus code. The app
   shows the notice that ODbL § 4.3 requires: "Contains information from the εxodus tracker database,
   which is made available here under the Open Database License (ODbL)", with both names linked. The
   converted database is public in this repository, which meets the share-alike and access terms
   (§§ 4.4 and 4.6), for the enterprise edition too. Signing the bundled files restricts no one's
   rights under § 4.7, because the same files are public.
2. **Our own lists under CC0 1.0.** The project compiles these lists itself:
   - proxy and remote-access SDK signatures;
   - official signing certificates of circumvention tools;
   - preinstalled data collectors;
   - wake-word assistants.

   Each entry records its source, such as a security report or a project's release page, and a date.
   Only facts are recorded, such as package names and certificate digests, and never text from the
   sources. These lists live in files apart from the εxodus data, so the two licences never mix
   (a collective database, § 4.5). New tracker signatures are also offered to εxodus ETIP, which CC0
   allows.
3. **Non-commercial datasets are excluded from both editions:** Disconnect, DuckDuckGo Tracker Radar
   and JA4+.
4. **v0.2 uses these, under these terms:**
   - EasyPrivacy, under CC BY-SA 3.0 or later;
   - DB-IP Lite, under CC BY 4.0 with its credit, and IPtoASN, under PDDL, to check it every month and
     as its fallback ([ADR 0036](0036-ip-to-organisation-dataset.md), which reversed the first order on
     2026-11-09: IPtoASN gives AS handles, not organisations);
   - JA3 and JA4, computed by our own code.

   HaGeZi and any fingerprint database get their own check before use.
5. **Data-safety labels are not collected automatically.** The app links to each app's Play listing,
   where the user can read the label. The measurement lab reads by hand the labels of the apps it
   measures, and cites each one with its link and date. For use at scale, the foundation asks either
   for Google's permission or for researcher access to publicly accessible data under DSA Article
   40(12), which applies to Google Play as a very large online platform.
6. **Attestation data is bundled for the integrity check.** Google's root certificates are used
    under Apache-2.0. Only the serial numbers from the revocation list are kept: facts, used for the
    purpose Google publishes them for. The legal review (decision 12) confirms that use before a
    release ships it; if it does not, the check falls back to the chain and the root keys.
7. **Every bundled dataset has this structure.** It sits in `data/<name>/` with its `LICENSE`, a
   `SOURCE` file (URL, download date, SHA-256 of what was downloaded) and the script that converts it.
   The in-app "Data sources" screen lists it with its licence and attribution. A new dataset is added
   to this record, or to one that supersedes it, before it ships.
8. **Licences are machine-readable.** Every file under `data/` carries an SPDX licence identifier, so
   that the repository can follow the REUSE specification and be checked with `reuse lint`. Each
   release's software bill of materials lists every dataset as a component, with its licence, snapshot
   date and hash.
9. **A changed upstream licence stops the update.** `SOURCE` also records the upstream licence as it
   was read: the SHA-256 of a licence file, or the licence statement on a web page. When a converter
   fetches a new snapshot and that file or statement has changed, it fails. The snapshot is updated only
   after a person has read the new licence and updated this record.
10. **Entries that name a company need evidence and a way to dispute them.** Every entry in our own lists
    that names a company or product records its evidence:
    - a primary source, such as the vendor's own documentation, the SDK's code, or an official report;
    - or a reproduction on the project's lab phones.

    Entries state facts, such as "contains the X SDK, which can route other people's traffic through the
    phone", never accusations. `data/CORRECTIONS.md` describes how anyone, the named company included,
    disputes an entry in a public issue, how it is reviewed, and how the outcome is recorded with the
    entry. Disputes about εxodus data go to εxodus.
11. **Datasets travel as signed data packs.** From M3, every dataset is shipped in a pack signed with the
    project's data-signing key (Ed25519), whose public key is pinned in the app. The APK carries the
    current packs. Newer packs can be imported through the system file picker, without any network
    permission: from the release page with any browser, from a mirror, or from another phone over
    Bluetooth, a messenger or USB (see [RESTRICTED-REGIONS.md](../RESTRICTED-REGIONS.md)). The app checks
    the signature before it parses anything, and refuses a pack older than the installed one. The
    packs' contents stay public, so signing them restricts no rights under ODbL § 4.7.
12. **A lawyer reviews this record before the first public release.** It was drafted with AI help and
    is not legal advice. The review is part of the release checklist, next to the other actions
    deferred to the public v0.1 release.
    *Note of 2026-11-12:* the review did not happen before the first public release (0.1.0, of
    2026-11-06), and RELEASE.md's checklist did not carry it. It is still open.

## Consequences
- M3 can start. Everything it needs is either εxodus data under ODbL or our own lists under CC0.
- The app cannot download signatures. They change with each release, or when the user imports a newer
  signed pack. Each pack states the date of every snapshot in it.
- Licence notices need an in-app "Data sources" screen. They also need a gate in `scripts/check.sh`
  that every folder under `data/` has its `LICENSE` and `SOURCE` files and SPDX identifiers.
- M3 grows: the pack format and its verifier in the Rust engine (fuzzed like every parser), the import
  screen, and a data-signing key that is generated and kept offline, with a documented rotation in
  which a new key is announced in a pack signed by the old one.
- Every list that names companies carries a maintenance cost: evidence for each entry, and answers to
  disputes.
- Without Disconnect, tracker domains in v0.2 rest on EasyPrivacy and the εxodus network signatures.
  The v0.2 spike checks that coverage.
- In-app comparison of declared against observed behaviour waits for a lawful source of the labels.
  Until then it belongs to the lab and to the reports.
