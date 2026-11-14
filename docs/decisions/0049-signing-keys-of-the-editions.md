# 0049. A signing key for each edition, ready to rotate, backed up in shares

- Status: Proposed
- Date: 2026-11-14
- Decided by: the maintainer, 2026-11-14 (decisions 1 to 6); drafted with AI help.
- Builds on: ADRs [0018](0018-app-signing-certificates.md), [0024](0024-fake-copies-of-datapavan.md),
  [0031](0031-datapavan-lite-on-google-play.md), [0039](0039-release-gates.md),
  [0043](0043-release-integrity-and-repository-controls.md) and [0045](0045-three-editions-of-one-app.md).
- Amends, once accepted: [docs/RELEASE.md](../RELEASE.md), its first steps and steps 4 to 7, which take the
  procedures below; the README's "Checking a copy", whose "Every genuine copy, on every channel, is signed with one
  key" becomes one key for each edition; ADR 0018's matching of a signing history (decision 3).

## Context

Datapavan Basic 0.1.2 is signed with one key. The maintainer made it on 2026-11-06 on a live Debian system with
networking off: RSA 4096, PKCS12, valid for 50 years, certificate fingerprint `FA:6A:24:04:…:4C:B1:FA:84`
([keys/](../../keys/README.md), [RELEASE.md](../RELEASE.md)). The data-signing key and the release-notes key were
made in the same session and are separate from it. Its backups are whole copies on encrypted offline media.

Datapavan Advanced's first release, 0.2.0, comes from the same commit as Datapavan Basic 0.2.0, since the two
share one version line. Nothing yet says which key signs it. The scripts already prepare and rehearse Advanced
(`scripts/prepare-signing.sh`, `scripts/release-rehearsal.sh`), and RELEASE.md's step 4 shows one keystore,
`datapavan-release.p12`, for either edition.

Four things need deciding before that release:
- **Basic judges Advanced from outside** ([ADR 0045](0045-three-editions-of-one-app.md), decision 2), first by its
  signing key. That holds only if Basic's key is not also Advanced's. With one key, whoever holds it can forge
  updates of both, and the judge falls with the judged.
- **No way to replace a key.** RELEASE.md says that if the key leaks, "the project must say so publicly and ask
  users to reinstall". APK Signature Scheme v3 lets an update move an installed app to a new key. Nobody has
  rehearsed it here, and it has limits on Android 10 to 12 (decision 3).
- **The backups are whole copies.** Each copy is the key, protected by its passphrase alone, and the backup works
  only while the maintainer remembers that passphrase. The second key holder that ADR 0039 requires for 1.0 has no
  way in.
- **One release, two editions.** `prepare-signing.sh` writes a `notes.txt` and a `SHA256SUMS` for one edition in a
  directory of its own. Two such sets in one release would collide.

## Decision

### 1. A separate offline key for Datapavan Advanced

- **Made and kept as Basic's is.** The maintainer makes it on a live USB system with networking off, with
  RELEASE.md's step 1:
  - `keytool -genkeypair -keystore datapavan-advanced-release.p12 -storetype PKCS12 -alias datapavan-advanced
    -keyalg RSA -keysize 4096 -validity 18250 -dname "CN=Datapavan Advanced, O=Visadahyu"`;
  - its own encrypted offline medium and its own passphrase, never Basic's;
  - never on an online computer. CI and AI assistants never touch it. This ADR made no key.
- **Each edition is signed in its own boot of the offline system,** with only that edition's medium attached.
  Both keys still pass through the same live system image. A compromised offline system would reach both, and
  this decision does not cover that. It covers the leak of one medium, one passphrase or one holder.
- **Why.** Basic is the offline app that checks Advanced from outside, so the two must not fall to one secret.
  A shared key would buy nothing:
  - the editions have no signature-level interface, since Advanced reads its own log (ADR 0045, decision 10);
  - `android:sharedUserId` is refused (decision 9);
  - neither defines a signature permission for the other.

  Separate keys also keep the editions clear of a platform bug that apksigner describes for Android 11 and earlier:
  when apps share a signer in their lineages, capabilities set for it in one app's lineage are applied to the
  others. Two editions that share no signer cannot meet it.
- **Unchanged:**
  - **Basic on Google Play** keeps its own package, `org.visadahyu.datapavan.lite`, under Google's key
    ([ADR 0031](0031-datapavan-lite-on-google-play.md)).
  - **The data-signing key and the release-notes key** stay one each, shared by both editions. They sign data and
    notes that name both editions. Neither APK key can forge what they sign, which decision 3 relies on.
  - **Enterprise's key** is decided with stage 2.

### 2. Each edition knows the other's certificate

- **`data/app-signers` gains Advanced's rows,** for `org.visadahyu.datapavan.advanced`:
  - `apps.tsv`: "Datapavan Advanced", closed (one developer key on every channel);
  - `signers.tsv`: grade 1, controller `developer`;
  - `sources.tsv`: the published fingerprint.

  They are added in the commit that publishes the fingerprint, before 0.2.0, so that both editions' 0.2.0 builds
  carry them. Basic's rows are there already.
- **What this gives:**
  - Basic shows a copy of Advanced under any other key as modified (ADR 0018, decision 6: closed, grade 1,
    fresh).
  - Advanced's self-check ([ADR 0024](0024-fake-copies-of-datapavan.md), point 5) reads its own row.
  - Advanced knows Basic's certificate.
  - Either certificate under the other edition's package is a modified copy. Under any other package it is a
    disguised Datapavan, as Basic's is today.
- **Both fingerprints are published wherever Basic's is today:**
  - the README's "Checking a copy";
  - `keys/` (`datapavan-advanced-release.pem` and keys/README.md);
  - the website: `site/hugo.toml` and the pages in `docs/site/`, in every language;
  - Advanced's own F-Droid recipe (`AllowedAPKSigningKeys`);
  - every release's signed notes;
  - an entry for AppVerifier.

  SECURITY.md lists no fingerprint (checked on 2026-11-14), so it gains none. `scripts/check-keys.py` compares every
  place with both certificate files.

### 3. Ready to rotate

**What Android does** (sources at the end):
- **v3 rotation.** Since Android 9, a v3 signature can carry a *proof-of-rotation*: a lineage of certificates in
  which each one signs the next. An update signed with the newest key and carrying the lineage replaces an
  installed copy signed with an older one. `apksigner rotate` makes the lineage.
- **Capabilities of the old key.** These are set at rotation:
  - installed data, without which the app's data does not move to the new key;
  - shared UID;
  - signature permissions;
  - authenticator access;
  - rollback.

  apksigner warns that rollback "effectively removes any benefit of signing certificate rotation since a
  compromised key could retake control of an app".
- **A rotation is signed by the key it replaces.** `--old-signer` must be the lineage's newest certificate, so a
  lost key cannot be rotated away afterwards.
- **v3.1, Android 13.** It changes what "Android 9 and later honour it" means in practice:
  - **Signing.** By default, apksigner puts a rotated key into a v3.1 block, which only Android 13 and later read.
    Android 9 to 12 then keep verifying the original signer in the v3.0 block. With `--rotation-min-sdk-version`
    of 32 or lower, the rotated signer goes into the v3.0 block, which every version from Android 9 reads.
  - **Google's advice.** It states that "APK key rotation is not recommended for Android 12 (API level 31) and
    earlier", and that v3.1 "addresses some of the known issues" of v3 rotation. Neither page lists those issues.
    The one apksigner names, the shared-signer bug above, does not apply here.
  - **v2 needs the oldest key.** If v1 or v2 signing stays on, apksigner needs the lineage's oldest signer to make
    them. The old key would then go on signing every release.

  So for Datapavan, whose minimum is Android 10, with the default targeting a rotation would leave phones on
  Android 10, 11 and 12 trusting the old key for as long as a v3.0 block is signed with it. After a compromise or a
  change of holder, that is the case that matters.

**The decision:**
- **Rotation covers every supported version.** The rotated release is signed with
  `--rotation-min-sdk-version 29`, and v2 is turned off from that release on. After the rotation, the old key signs
  nothing.
  - Android 10 and later check the v3 signature. v2 served Android 7 and 8 and outside tools that read only v2,
    which then can no longer check a release.
  - Because Google advises against rotation on Android 12 and earlier, the rehearsal below must pass on the Android
    10, 12 and 13 emulators and on the newest one.
  - If it finds a fault on 10 to 12 that cannot be worked around, the fallback is the default targeting. The
    release notes and the website then say plainly that phones on Android 10 to 12 keep trusting the old key, and,
    after a compromise, that their users must reinstall from a checked source.
- **The old key's capabilities:** installed data on, everything else off: `--set-installed-data true
  --set-shared-uid false --set-permission false --set-rollback false --set-auth false`. Each flag is named, so that
  apksigner's defaults decide nothing. The rehearsal checks that both editions still update and work with these
  settings.
- **What triggers a rotation:**
  - **A suspected compromise.** Any sign that a private key or its passphrase left the offline media: a medium lost
    or seen, an APK under the key that the project did not release (found in the transparency log, by a user or by
    a channel), or a signing nobody remembers making. The rotation is started at once.
  - **A change of key holder.** Someone who held a key, or two of its shares, leaves that role. A holder who joins
    needs no rotation.
  - **The algorithm's age.** Once a year, at the year's first release, the keys are checked against NIST's
    transition guidance (SP 800-131A) and what Android and the stores accept. A key is rotated when RSA 4096 with
    SHA-256 is deprecated for signatures, or no longer accepted by Android or by a store the edition ships through.
  - **Not a trigger:**
    - the loss of one share: the key is split again (decision 4);
    - the loss of the working medium while two shares remain: the key is recovered.

    A key lost with fewer than two shares left cannot be rotated. Installed copies then get no update, and their
    users must install a new app, as RELEASE.md says today.

**The procedure, for either key.** RELEASE.md takes it when this ADR is accepted. In the offline system:
1. **Make the new key** as in decision 1, named with its number (`datapavan-release-2.p12`,
   `datapavan-advanced-release-2.p12`). Split it into shares (decision 4) before anything is signed with it.
2. **Make the lineage:**

   ```sh
   apksigner rotate --out <edition>-lineage-2.bin \
       --old-signer --ks <old>.p12 --set-installed-data true --set-shared-uid false \
           --set-permission false --set-rollback false --set-auth false \
       --new-signer --ks <new>.p12
   apksigner lineage --in <edition>-lineage-2.bin --print-certs
   ```

   The lineage holds certificates and signatures, no secret. It is published in `keys/` beside the new
   certificate.
3. **Record the new certificate** in `data/app-signers` and everywhere decision 2 lists, in the release commit.
   After a compromise, the old certificate is marked compromised (below).
4. **Sign the rotated release:**

   ```sh
   apksigner sign --ks <new>.p12 --lineage <edition>-lineage-2.bin --rotation-min-sdk-version 29 \
       --v1-signing-enabled false --v2-signing-enabled false --v3-signing-enabled true \
       --v4-signing-enabled false --out datapavan-<edition>-<version>.apk datapavan-<edition>-<version>-unsigned.apk
   apksigner verify --verbose --print-certs datapavan-<edition>-<version>.apk
   apksigner lineage --in datapavan-<edition>-<version>.apk --print-certs
   ```

   `verify` must show the new certificate as the signer, with v3 true. `lineage` must show the old certificate,
   then the new one. The rehearsal settles the exact flags before any real use.
5. **The notes** give the new certificate as "Signing certificate SHA-256" and add "Rotated from:" with the old
   one.
6. **After a compromise, also:**
   - a public notice in the README, on the website and in the notes: which key, since when, and what to do;
   - a data pack that marks the old certificate. It is signed with the data key, which the leaked APK key cannot
     forge, so it reaches Basic without an app update ([DATA-PACKS.md](../DATA-PACKS.md)).

**How `data/app-signers` and the Verifier treat a lineage:**
- **One row per certificate.** A package keeps a row for every certificate in its lineage, as Signal's two rows do
  today. `update.py` already records a lineage's older certificates.
- **After a planned rotation,** the old row stays valid. A copy signed with the old key (an earlier release), or
  one whose history holds it, is genuine (ADR 0018, decision 5).
- **The transition.** A Basic whose data predates the new row shows a rotated Advanced as "genuine, only an older
  key matched" until its data or the app is updated.
- **A compromised certificate gets a mark** in `signers.tsv`. The build decides its format: a column, or a value
  with the date. Then:
  - **A copy whose current signer is that certificate** is no longer shown as genuine: "signed with a key that
    leaked on <date>; this copy cannot be confirmed; update, or reinstall from a checked source". It is not shown
    in red as modified, since genuine earlier releases carry the same key.
  - **A copy whose current signer is unknown** is never made genuine by a compromised certificate in its history.
    Whoever holds the old key can make a lineage to a key of their own. The match on history skips compromised
    certificates; this is the change to ADR 0018 named above.
  - The self-check reads the same rows.
- **The Verifier** ([ADR 0040](0040-own-safety-in-an-untrusted-environment.md); a mode of Basic) applies the same
  rules wherever it compares an edition's signing certificate. It pins a certificate between checks. When that
  certificate changes, the change is accepted only if the new certificate is the recorded successor of the pinned
  one in the lineage, and it is shown as a rotation with its date. Any other change is reported.
- **Outside tools.** AppVerifier compares one value, which fails after a rotation (ADR 0018). Its entry changes with
  the rotated release, and the notes say that copies not yet updated still show the old value. F-Droid's recipe
  lists the new certificate. Whether F-Droid's client, and its copying of the developer's signature onto its own
  reproducible build, handle a lineage is checked before a rotation. Neither edition is on F-Droid before
  2027-01-28.

**The rehearsal, a gate of Datapavan Advanced 0.2.0** (with ADR 0039's gates), and of every release after a
change to these procedures. `scripts/release-rehearsal.sh` gains a rotation mode, run for each edition with
throwaway keys on the Android 10, 12 and 13 emulators and the newest one:
1. **Before:** release N, signed with key A as today, installed, with data of its own (an audit run).
2. **The rotation:** A to B with the flags above. Release N+1 is signed with B, targeted at API 29, without v2.
   `adb install -r` must keep the app and its data, and Android must report B as the signer, with A in the history.
3. **The old key alone:** an N+2 signed with A alone is refused on every emulator.
4. **A forged lineage:** an N+2 signed with a third key C, over a lineage A to C:
   - refused on a phone that already has N+1;
   - accepted on a phone still at N.

   The second result is shown in the output on purpose: after a compromise, phones that have not yet updated are
   in a race, which is why the notice and the data pack matter.
5. **The self-check, on N+1:**
   - with both A and B in the data: genuine;
   - with A alone: genuine, "only an older key matched";
   - with A marked compromised: N shown as not confirmed, and C's copy as modified.
6. **The default targeting,** run once too, to record what Android 10 to 12 do with it.
7. **A recovery from shares** of a throwaway keystore (decision 4).

The result and its date go into RELEASE.md, as the rehearsal of 2026-11-05 did.

### 4. A split backup

- **Each APK signing key is split 2-of-3** with Shamir's secret sharing, on the offline system. There are three
  shares in three separate places, never online. One share alone reveals nothing of the key. Basic's key is split
  in the session in which Advanced's key is made.
- **The tool.** Privy's `shamir-secret-sharing`: TypeScript, Apache-2.0, with no runtime dependencies.
  - **Audits:** Cure53 audited it in February 2023 and found one high-severity flaw (the polynomial's degree could
    fall below *t*−1), which release 0.0.1 fixed. Zellic's audit is linked from its README. Release 0.0.3 adds
    "additional safety checks from second wave of audits".
  - **The version:** pinned exactly, with its npm integrity hash recorded. The diff between that version and the
    audited code is read before use. 0.0.4, of 2025-01-10, is the latest.
  - **On the live system** it runs under Node.js from Debian's own `nodejs` package. Both are copied onto the stick,
    as the JDK and apksigner are today.
  - **A short script of the project** splits and combines files with the library: `scripts/key-shares.mjs`, still
    to write and review. It uses no network and no other dependency. CI tests it with fixed vectors and round trips.

  No audited implementation is packaged by Debian (searched on 2026-11-14):
  - `ssss` takes at most 128 ASCII characters, so its documentation advises encrypting a larger secret and sharing
    the key;
  - `gfsplit` (`libgfshare-bin`) splits whole files, but no audit of it was found.

  Privy's library is the only audited implementation found that splits arbitrary bytes. The price is Node on the
  stick.
- **What is split.** For each key, one bundle (a tar file): the PKCS12 keystore, its passphrase, the certificate,
  and a short text on how to restore. The bundle is made in the live system's memory (tmpfs) and never written
  unencrypted to any medium. Each share is one file. It carries a plain header (the key's name, the share's number,
  the date, the tool and its version, the bundle's SHA-256) and the share's bytes. The library does not verify what
  it reconstructs, so the script compares the SHA-256 after combining.
- **The passphrase:**
  - each keystore has its own: at least six words from the EFF's long Diceware list, rolled with physical dice
    (about 77 bits);
  - it is never typed on an online computer;
  - keytool and apksigner read it from their prompt, never as `pass:` on a command line.

  It goes into the bundle, so that two shares recover the key without anyone's memory, which is the case the
  backup exists for. The threshold protects the shares. The maintainer's working medium keeps the passphrase's
  protection.
- **The places.** Shares of both keys may lie in the same three places. Two places then give both keys: the one
  failure that decision 1's separation does not cover. It is accepted, since it needs the theft of two separate
  places. Which places they are is private and not recorded here.
- **The media.** Each share is proven as RELEASE.md's backup rule says:
  1. close the medium and open it again read-only;
  2. combine each of the three pairs from the media themselves;
  3. sign a test file with the recovered keystore and compare its certificate.

  Once a year each share is read and its hash compared with its header. A share that fails is replaced by splitting
  again: new shares, and the old ones destroyed where they can be reached.
- **Recovery is rehearsed once** with a throwaway key, end to end on the live system, before the real keys are
  split: split, write to three media, combine each pair, sign. The rehearsal script repeats the round trip.
- **The other keys.** The data-signing and release-notes keys keep their present backups. Their loss is repaired by
  a new key and an app update (DATA-PACKS.md, "Rotation").
- **The second key holder** of ADR 0039 can be handed a share without being handed a key. Who holds which share is
  decided at 1.0.

### 5. A hardware token is a separate decision

- **Spending needs the maintainer's word,** so no token is chosen here.
- **If one is ever chosen, its key must have an encrypted, split backup.** The SmartCard-HSM and the Nitrokey HSM
  export a key wrapped under a DKEK, and the password of a DKEK share can itself be split n-of-m (OpenSC's
  `sc-hsm-tool`). Otherwise the rotation path must cover the token's loss.
- **A rotation cannot be made after the loss,** since it is signed by the key it replaces. Covering a loss means a
  rotation made in advance: while the token works, it signs a lineage entry to a spare key, made offline, split
  as decision 4 says and kept unused until needed.
- **Either way, a copy of equal power exists outside the token.** A token protects the key while it signs, not its
  backup.
- **apksigner can sign through PKCS #11** (`--ks NONE` with a provider), so a token would change the signing
  command only.

### 6. One tag, two editions

From 0.2.0 on, each tag `v<version>` holds both editions. They come from one commit, and an edition with no change
is still built and signed from it.
- **The files:**
  - `datapavan-basic-<version>.apk` and `datapavan-advanced-<version>.apk`;
  - one data pack, `datapavan-data-<sequence>.pack`, which both read;
  - `notes.txt` and `notes.txt.sig`;
  - `SHA256SUMS`.

  The 0.1.x tags keep their files, and the copy on Google Play is not in the tag.
- **One notes file, signed once** with the release-notes key. Its first line is "Datapavan Basic and Datapavan
  Advanced <version>". Then come, once each, the commit, the data pack and its fingerprint. Then one block for
  each edition:
  - the edition's name;
  - the APK's name;
  - its SHA-256;
  - its signing certificate's SHA-256, and after a rotation "Rotated from:".

  The store changelog and the sentence to teach (which already names both) close it. `prepare-signing.sh` prepares
  both editions in one directory, and `verify-signed.py` reads both blocks. The edition argument stays for the
  rehearsals.
- **One `SHA256SUMS`** lists every file of the tag except itself. It is written on the offline system after
  signing. It is not signed. The notes are, and they name each APK's and the pack's hash. `verify-signed.py`
  checks that the list agrees with them.
- **One Sigsum entry for each file a user runs or the app reads** ([ADR 0043](0043-release-integrity-and-repository-controls.md),
  decision 2): each APK, the data pack, and the notes. A build of one edition made for a few people then shows up
  even when the other edition's is honest. ADR 0043's build decides which key signs the entries and how they leave
  the offline system. It is never an APK key.

## Against the field

- **At the standard:** a separate key for each trust domain. NIST SP 800-57 Part 1 Rev. 5, section 5.2, holds that
  a key is used for one purpose only. Basic, as the checker, and Advanced, as the checked, are two purposes.
- **Above the usual standard for app developers:** a rotation procedure, rehearsed on each supported Android
  version before it is needed, together with a 2-of-3 split backup with an audited tool and a transparency log for
  each file. Most app developers keep one key with one backup, or leave it to Google. Few say what their rotation
  does on Android 10 to 12.
- **Below some high-assurance projects, on purpose for now:** no hardware token (decision 5).
- **No frontier research is needed.** Each piece is documented practice. The work is the rehearsal.

## Consequences

- **Two APK keys to keep:** two media, two passphrases, six shares, two boots of the offline system per release,
  and two fingerprints to publish, check and teach. AppVerifier, F-Droid and the website get an entry each.
- **More to build before 0.2.0:**
  - Advanced's rows in `data/app-signers`;
  - `check-keys.py` for both certificates;
  - the compromised mark and the history rule;
  - one notes file for both editions;
  - the rotation mode of the rehearsal;
  - `scripts/key-shares.mjs` and its tests.

  The maintainer has two offline sessions: the throwaway rehearsal of the shares, then the real keys.
- **Rehearsals cost emulator time:** four versions, two editions, the forged lineage and the default targeting.
  They are what make a rotation something the project has done, not only read about.
- **A rotation drops v2 for good,** so tools that read only v2 can no longer check a rotated release.
- **Two places hold both keys,** an accepted limit (decision 4).
- **The words change.** "Every genuine copy, on every channel, is signed with one key" becomes one key for each
  edition, published side by side. Each edition's page says which fingerprint is its own.
- **A compromise is still a race** for phones that have not updated. The data pack shortens it for Basic's
  verdicts. Nothing shortens it for Android's own check.

## What this does not decide

- **The hardware token,** its purchase and its model (decision 5).
- **Enterprise's key,** with stage 2.
- **A Play listing for Advanced,** and the key Google would hold for it.
- **The three places and who holds each share,** which stay private. The second key holder, at 1.0 (ADR 0039).
- **The key that signs Sigsum entries,** which ADR 0043's build decides.

## Sources

All read on 2026-11-14.

- apksigner: https://developer.android.com/tools/apksigner (`--rotation-min-sdk-version`, `rotate`, `--ks NONE`
  for PKCS #11), and the help of `apksigner rotate` and `apksigner sign` in apksigner 0.9 (build-tools 37.0.0): the
  capability flags, the rollback warning, the shared-signer bug before Android 12, and the oldest signer needed for
  v1 and v2
- APK Signature Scheme v3: https://source.android.com/docs/security/features/apksigning/v3
- APK Signature Scheme v3.1: https://source.android.com/docs/security/features/apksigning/v3-1
- Android 13 features, "APK Signature Scheme v3.1": https://developer.android.com/about/versions/13/features
- Privy, `shamir-secret-sharing`: https://github.com/privy-io/shamir-secret-sharing, its releases, and the npm
  registry's record (https://registry.npmjs.org/shamir-secret-sharing)
- Cure53, "Audit-Report Privy.io Shamir Secret Sharing 02.2023":
  https://cure53.de/audit-report_privy-sss-library.pdf
- `ssss`: https://sources.debian.org/data/main/s/ssss/0.5-5/doc.html
- `libgfshare-bin`: https://packages.debian.org/sid/libgfshare-bin
- EFF dice-generated passphrases: https://www.eff.org/dice
- OpenSC, SmartCard-HSM (DKEK shares, n-of-m for a share's password): https://github.com/OpenSC/OpenSC/wiki/SmartCardHSM
- NIST SP 800-57 Part 1 Rev. 5, Recommendation for Key Management: Part 1 – General (May 2020):
  https://csrc.nist.gov/pubs/sp/800/57/pt1/r5/final
- NIST SP 800-131A, Transitioning the Use of Cryptographic Algorithms and Key Lengths; Rev. 3 was an initial public
  draft on 2024-10-21: https://csrc.nist.gov/pubs/sp/800/131/a/r3/ipd. The yearly check reads the revision then
  current.
