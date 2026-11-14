# Releasing Datapavan

Status: v0.1.0 and v0.1.1 were signed and published as pre-releases on 2026-11-06 and 2026-11-07, and v0.1.2, Datapavan Basic 0.1.2, as the first full release on 2026-11-07 (its build is dated 2026-11-08, the day it was planned for). This file says what the maintainer does by
hand, once before the first release and then for every release, and what the repository checks by
itself. The keys never touch an online computer ([DATA-PACKS.md](DATA-PACKS.md#keys), ADR 0024).

## Once, before the first release

These steps need the maintainer in person and an offline system. CI, the development computer's own
system and AI assistants never touch the keys.

Steps 1 to 3 were done on 2026-11-06, on a live Debian system with networking off. The public halves are
in [keys/](../keys/README.md), and the certificate's fingerprint is `FA:6A:24:04:2A:BC:AC:8B:D0:09:01:10:F7:04:FF:EF:E7:DA:D3:AD:F5:DB:38:FB:07:38:90:AB:4C:B1:FA:84`.
The steps stay here for the day a key must be replaced. Step 4 was done on the same day, when the repository went public.

1. **The APK signing key**, made offline like the data-signing key: start a live USB system with
   networking off (for example Debian Live), with a JDK and the Android SDK's `apksigner` copied onto
   the stick, and make the key there:

   ```sh
   keytool -genkeypair -keystore datapavan-release.p12 -storetype PKCS12 -alias datapavan \
       -keyalg RSA -keysize 4096 -validity 18250 -dname "CN=Datapavan, O=Visadahyu"
   ```

   RSA 4096 is accepted by every Android version Datapavan supports and by every store. The keystore
   stays on encrypted offline media. A backup copy is proven before it is relied on: close the media, open it again
   read-only, compare every file, and sign something with the copy on it. A check of a copy in memory passes with no media at
   all, which is how the first set of keys was lost on 2026-11-05, before anything was signed with them. The key's certificate is what users and other apps
   compare, so it must outlive the project's releases: 18,250 days is 50 years. If the key is ever lost,
   no update can reach an installed copy (ADR 0024, point 1); if it leaks, the project must say so
   publicly and ask users to reinstall.
2. **The data-signing key**, as [DATA-PACKS.md](DATA-PACKS.md#keys) describes, and **a key for
   release notes**, in the same offline session. They are separate, so that a leak of one cannot
   forge what the other signs:

   ```sh
   signify-openbsd -G -c "Datapavan release notes key 1" -p datapavan-notes-1.pub -s datapavan-notes-1.sec
   ```

   The data key's public key's second line goes into `data/PACK` as a `key` line; both `.pub` files
   are published with the first release and in the README.
3. **The certificate's fingerprint**, read offline:

   ```sh
   keytool -list -v -keystore datapavan-release.p12 -alias datapavan | grep SHA256
   ```

   It goes into `data/app-signers` as Datapavan's own row (developer key, closed), so that the app's
   self-check ("Is this copy genuine?") and partner tools can judge a copy (ADR 0024, point 4), and
   into the README and the website.
4. **Private vulnerability reporting** turned on in the repository's settings when it goes public, as
   [SECURITY.md](../SECURITY.md) says. An e-mail address with an OpenPGP key waits for 1.0: its private
   key needs a device of its own, and until then the server runs no mail service.

## Every release

1. **Version.** Raise `versionCode` by one and set `versionName` and `RELEASE_DATE` in
   `android/app/build.gradle.kts`; move the changelog's "Unreleased" items under the new version, with
   the same date; write
   `fastlane/metadata/android/en-US/changelogs/<versionCode>.txt` (500 characters at most) and its
   translations. If the interface changed, take the store images again with `scripts/store-images.sh`
   on an emulator with CI's image (`dp-api35-ci`) at a phone's size (`wm size 1080x2400; wm density 420`): the icon from the launcher
   icon's layers, and six screenshots per language in SystemUI's demo mode.
2. **Checks.** `scripts/check.sh all`, the emulator scripts (`smoke.sh`, `verify-audit.sh`,
   `verify-plan.sh`, `verify-shortcuts.sh`, `verify-datapack.sh`, `screenshots.sh`) on the CI image
   `dp-api35-ci`, and `scripts/reproducible.sh`, which builds the release twice from clean checkouts in
   different directories and fails unless the two unsigned APKs are identical. Then
   `scripts/release-rehearsal.sh --install` runs steps 4 and 5 for Basic with throwaway keys and puts the signed
   release build, the only one R8 shrinks, through the smoke test and the shortcut check on the
   emulator; `scripts/release-rehearsal.sh advanced` runs steps 4 and 5 for Advanced, whose
   release build `scripts/verify-watch-release.sh` runs on the emulator. CI's emulator cannot run 32-bit ARM code, so the 32-bit build is tried by hand on the
   Android 11 emulator (`dp-api30`), which translates ARM code: `INSTALL_ABI=armeabi-v7a scripts/smoke.sh`,
   then `verify-audit.sh`, `verify-plan.sh` and `verify-shortcuts.sh`. The data pack scripts stay on
   CI's image: Android 11's file picker there would not pick a file that adb had put in Downloads
   (2026-11-07, with the 64-bit build too). CI must be green on the release commit. A CI check that failed
   while nothing it tests had changed goes into [ci-flakes.md](ci-flakes.md), with the run, the check, its
   cause and its fix, before the run is repeated.

   **The documents match the code** ([ADR 0039](decisions/0039-release-gates.md)). `scripts/check-truth.py`,
   part of `check.sh`, checks what a machine can read (below). Everything else that states how things
   stand is read against the code and the record by a reviewer other than its author, an independent
   model at least and a person when one is available. That covers versions, channels, mirrors, backups
   and what is built, in SECURITY.md, RESTRICTED-REGIONS.md, DATA-PACKS.md, REMEDIATION.md, CHANNELS.md,
   the datasets' LICENSE files, the roadmap's status and the website. A statement that is not true yet
   is changed or dated before signing, never left for the next release.
3. **Data pack.** If `data/` changed, raise the sequence in `data/PACK`, set its date, and sign the
   pack offline ([DATA-PACKS.md](DATA-PACKS.md#publishing-a-pack)).
4. **Signing, offline.** `scripts/prepare-signing.sh <directory> [<edition>]` gathers what goes to the offline
   system for one edition, `basic` unless `advanced` is given, from a clean commit on `main`: the unsigned APK,
   once two builds agree, the data pack's payload, the notes and their hashes. Each edition is prepared in a
   directory of its own. Copy them over and sign the APK:

   ```sh
   apksigner sign --ks datapavan-release.p12 --ks-key-alias datapavan \
       --v1-signing-enabled false --v2-signing-enabled true --v3-signing-enabled true \
       --v4-signing-enabled false --out datapavan-<edition>-<version>.apk datapavan-<edition>-<version>-unsigned.apk
   apksigner verify --verbose --print-certs --min-sdk-version 24 datapavan-<edition>-<version>.apk
   ```

   The APK's name carries the edition from the release after 0.1.2 (ADR 0045; the maintainer, 2026-11-14):
   `datapavan-basic-<version>.apk` and `datapavan-advanced-<version>.apk`. Basic and Advanced share one version
   line, so Datapavan Advanced 0.2.0 comes from the same commit as Datapavan Basic 0.2.0, and the script
   refuses Advanced at another version than Basic's. The published 0.1.2 keeps `datapavan-0.1.2.apk`.

   The printed SHA-256 must be the published fingerprint, and both v2 and v3 must say `true`. The
   schemes are named because apksigner's defaults depend on the APK: for minSdk 29 it signs with v3
   alone, which tools that read only v2 cannot check, and it writes a v4 `.idsig` file that no channel
   publishes (found by the rehearsal on 2026-11-05). `--min-sdk-version 24` makes `verify` report v2
   too, which it otherwise skips for this minSdk.
5. **Release notes, signed.** The notes name the version, the commit, the APK's SHA-256, the certificate's
   fingerprint and the sentence to teach (ADR 0045, decision 4: "Genuine Datapavan Basic never has internet
   access. Genuine Datapavan Advanced uses it only for your own apps' traffic and the servers you choose, …").
   Their first line is the edition's name and the version, "Datapavan Basic <version>". They are signed offline with the release notes key
   (`signify-openbsd -S -e -s datapavan-notes-1.sec -m notes.txt`), so that users and channel
   operators can check them with `signify -V -e` (ADR 0024, point 3).
6. **Check what came back** on the main system, from the published keys only:
   `python3 -I scripts/verify-signed.py <directory> [<commit>] [<edition>]` checks the signatures of the notes and the data
   pack, that the notes name the release commit, its version, the APK's hash and certificate and the
   pack's fingerprint, and that the pack holds the data the APK carries. Then
   `scripts/verify-signed-release.sh <directory>` runs Basic's signed APK on CI's emulator image (Advanced's
   check is still to build; `scripts/verify-watch-release.sh` runs its release build): it must
   know itself genuine and refuse a damaged copy of the pack. On `dp-api30`, put the signed APK
   through `INSTALL_ABI=armeabi-v7a scripts/smoke.sh <apk>` and `verify-shortcuts.sh`.
7. **Publish** the signed APK, the notes and their signature on GitHub Releases and under `download/` on the
   website, where `site/hugo.toml` names the current APK, its hash, size, tag and `release_code`, whose
   store changelog the download section shows, and tag the commit
   (`v<version>`). The tag itself is not signed, since none of the offline keys can sign a Git tag. The
   signed notes name the commit, so a tag moved later no longer matches them: compare with
   `git rev-parse v<version>^{commit}`. A key for tags can be added later, if `git verify-tag` should work too.
8. **F-Droid.** F-Droid builds from the tag. With reproducible builds it publishes the APK signed by
   the project only when its own build matches; the recipe lists the certificate's fingerprint.
   [fastlane/](../fastlane/) holds the store texts, which F-Droid reads from the repository.

## What the repository checks by itself

- The build fails if any component adds the INTERNET permission, and `verifyApkRelease` checks the
  native library and its JNI export.
- `scripts/reproducible.sh` compares two builds of the same commit.
- `scripts/check-keys.py` fails if the fingerprint or a key in the README, the website, the F-Droid
  recipe, `data/PACK` or `data/app-signers` differs from the files in `keys/`.
- `scripts/check-truth.py` fails if a public document disagrees with its source:
  - the release tags against the changelog, the status lines of the README, SECURITY.md, CHANNELS.md and
    this file, the app's version and build date, and the website's download button;
  - the ADR files against their index and DESIGN.md's table;
  - the roadmap's and DESIGN.md's dates against the newest decision and release;
  - the minimum Android version and the UI languages against the build;
  - the datasets' counts against their rows;
  - the README's milestones against the roadmap.

  `scripts/check-truth-test.py` plants one false statement for each check and fails if it goes unseen.
  CI runs both on every push, documents only included.
- `scripts/release-rehearsal.sh` signs a release build and its notes with throwaway keys and checks
  the schemes, the certificate, the version, the permissions and the notes' signature.
- `ThemeTest`, `scripts/plain-language.py` and `scripts/screenshots.sh` keep the interface's contrast,
  wording and touch targets.
