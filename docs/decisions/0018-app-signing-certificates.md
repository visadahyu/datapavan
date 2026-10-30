# 0018. Official signing certificates of VPN, proxy and circumvention apps

- Status: Accepted
- Date: 2026-10-30
- Decided by: mehdashti

## Context
Datapavan is a privacy and security tool for people anywhere. Many of them use VPN, proxy or
circumvention apps: for privacy, for work, or because their internet is filtered. Datapavan has to work
alongside those apps (see [VPN.md](../VPN.md)). A modified copy of such an app sees all of its user's
traffic, so a copy that its developer did not sign is one of the most serious things the audit can
find. ADR 0015 decided that Datapavan keeps its own list of official signing certificates under CC0.
This record decides how that list is built and how the app judges a copy.

A review of usage data across countries, the channels and keys of more than forty apps, documented
fake and repackaged copies, and existing verifiers found:
- **Most projects publish nothing to check against.** Only six publish their certificate fingerprint:
  Psiphon, Proton VPN, Signal, Exclave, ByeByeDPI and WG Tunnel. For the others, the certificate has to
  be read from APKs from official channels.
- **One app often has several legitimate keys.** There are separate keys for Google Play (Play App
  Signing, and since 2026 one key per range of Android versions), for F-Droid's own builds, and for
  each flavour. Keys are also rotated, either through a signing lineage (Signal) or without one. On
  IzzyOnDroid, 2.35% of apps changed key, none of them maliciously. For almost every app, the key of the
  Play copy is unknown.
- **A package name proves nothing.** Forks reuse names, stores in some countries carry uploads by third
  parties under the developer's package name, and Lantern's disguised builds use random names.
- **A certificate check catches repackaged copies, not lookalikes.** It catches copies that keep the
  package name and change the key, such as the trojanised Psiphon builds on record and most apps in
  "modded" markets. It does not catch apps under their own names that imitate a known one, which is
  the usual pattern of state-run campaigns, nor installers that bring a genuine app along with
  something else.
- **Existing verifiers** (AppVerifier, Verified Apps) compare only the newest key, which fails after a
  rotation. Their databases are small or of unclear licence, so they serve for cross-checks only.

The research behind this record is kept in the foundation's private repository.

## Decision
1. **An app is identified by its package name and its set of signing certificates**, never by its name
   alone. The list can also be searched by certificate, so that a genuine build under another name is
   still recognised.
2. **The dataset `data/app-signers/`** is CC0. It holds one row per package and certificate, with:
   - the channel (website, GitHub, Google Play, F-Droid, a repository such as IzzyOnDroid or the
     Guardian Project's);
   - the party that controls the key (developer, Google, F-Droid, or a third party since a given date);
   - an evidence grade, the source URL and the date of the check.

   The collector marks Android debug certificates. One row per package records whether its key set is
   **closed**, meaning every official channel is covered.
3. **Evidence grades**, from strongest:
   1. a fingerprint the developer publishes on its own channel;
   2. a developer key pinned in reviewed public metadata (F-Droid's `AllowedAPKSigningKeys`) or recorded
      in a repository index whose signature was checked against the repository's published key;
   3. a redistributor that checks the author's key (IzzyOnDroid), or an APK verified with the
      developer's OpenPGP signature;
   4. a certificate read from APKs of official channels that agree across at least two channels or
      fetches;
   5. a single reading.

   A key that F-Droid holds identifies only F-Droid's build. A value proposed by a third party is grade
   5.
4. **Collection happens off the phone**, with `data/app-signers/update.py`:
   - every APK goes through `apksigner verify` across Datapavan's range of Android versions (10 to 17),
     so that every signer some phone would see is recorded, together with its lineage;
   - an OpenPGP signature is checked first wherever the project offers one;
   - repository indexes are used only after their signature is checked against the published
     repository key.

   Play copies are read from devices on which they were installed from Play.
5. **Matching on the phone.** For an app with one signer, any certificate in its signing history may
   match a recorded key, and the app says when only an older one did. For an app with several signers,
   the set must match exactly. Install source adds detail but never decides a verdict, because adb and
   other installers can set it.
6. **Verdicts:**
   - **Genuine:** the key matches a record. The verdict names the controlling party (developer, Google
     Play, F-Droid).
   - **Genuine key, channel no longer the developer's:** the key matches a record that is marked as
     taken over by someone else. A neutral note names the official channel. No channel is marked yet.
   - **Key not known yet:** the package is listed, nothing matches, and the evidence does not allow
     more. This is shown in grey, never as a warning. It shows the fingerprint so that the user can
     compare it with the developer's page, and says where to get a copy that can be confirmed. This is
     the default.
   - **Modified copy:** shown in red, and only on positive evidence. Either the package's key set is
     closed, its rows are grade 1 to 4, and the data is fresh; or the certificate is the Android debug
     certificate and the package's official builds are never debug-signed.

   When the data is more than six months old, "modified" falls back to "key not known yet", because
   keys change.
7. **Disguised builds stay disguised.** When a certificate identifies a genuine app under another name,
   the app's brand is shown only after a tap, because the disguise protects people whose phones are
   searched.
8. **Lookalikes:** an app that is not listed but uses the name or icon of a listed one gets an
   informational note in a later release. It is never a "modified" verdict.

## Consequences
- The first release covers the apps with the strongest evidence and the widest use across countries:
  Psiphon, Tor Browser, Orbot, Proton VPN, v2rayNG, Lantern, WARP, Outline, Hiddify and Amnezia, then
  the proxy clients. Only a few key sets can be closed today (Proton, Signal, Briar, Exclave), so most
  copies with an unknown key are shown in grey, by design.
- The keys of Play copies need test devices with Google Play in each range of Android versions, on
  which someone signs in to Play by hand.
- Asking each project to publish its fingerprint is the cheapest way to raise many entries to grade 1.
  Such requests are sent only with the maintainer's approval.
- The list decays: keys and channels change. Its date shows on the *Data sources* screen, and stale
  data turns red verdicts grey.
- The list names products, not companies, and judges only whether a copy carries its developer's key,
  not whether the product is trustworthy. Disputes go through `data/CORRECTIONS.md` (ADR 0015).
