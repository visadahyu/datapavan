# Releasing Datapavan

Status: prepared for v0.1. Nothing has been released yet. This file says what the maintainer does by
hand, once before the first release and then for every release, and what the repository checks by
itself. The keys never touch an online computer ([DATA-PACKS.md](DATA-PACKS.md#keys), ADR 0024).

## Once, before the first release

These steps need the maintainer and an offline system. They cannot be done by CI, by a script on the
development computer, or by an assistant.

1. **The APK signing key**, made offline like the data-signing key: start a live USB system with
   networking off (for example Debian Live), with a JDK and the Android SDK's `apksigner` copied onto
   the stick, and make the key there:

   ```sh
   keytool -genkeypair -keystore datapavan-release.p12 -storetype PKCS12 -alias datapavan \
       -keyalg RSA -keysize 4096 -validity 18250 -dname "CN=Datapavan, O=Visadahyu"
   ```

   RSA 4096 is accepted by every Android version Datapavan supports and by every store. The keystore
   and its backup stay on encrypted offline media. The key's certificate is what users and other apps
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
4. **A security contact with an OpenPGP key** in [SECURITY.md](../SECURITY.md), before the repository
   goes public.

## Every release

1. **Version.** Raise `versionCode` by one and set `versionName` in `android/app/build.gradle.kts`;
   move the changelog's "Unreleased" items under the new version; write
   `fastlane/metadata/android/en-US/changelogs/<versionCode>.txt` (500 characters at most) and its
   translations.
2. **Checks.** `scripts/check.sh all`, the emulator scripts (`smoke.sh`, `verify-audit.sh`,
   `verify-plan.sh`, `verify-datapack.sh`, `screenshots.sh`) on the CI image `dp-api35-ci`, and
   `scripts/reproducible.sh`, which builds the release twice from clean checkouts in different
   directories and fails unless the two unsigned APKs are identical. CI must be green on the release
   commit.
3. **Data pack.** If `data/` changed, raise the sequence in `data/PACK`, set its date, and sign the
   pack offline ([DATA-PACKS.md](DATA-PACKS.md#publishing-a-pack)).
4. **Signing, offline.** Copy the unsigned APK to the offline system and sign it:

   ```sh
   apksigner sign --ks datapavan-release.p12 --ks-key-alias datapavan --out datapavan-<version>.apk \
       app-release-unsigned.apk
   apksigner verify --print-certs datapavan-<version>.apk
   ```

   The printed SHA-256 must be the published fingerprint.
5. **Release notes, signed.** The notes name the version, the APK's SHA-256, the certificate's
   fingerprint and the sentence to teach ("Genuine Datapavan v0.1 has no internet access and never
   asks for it"). They are signed offline with the release notes key
   (`signify-openbsd -S -e -s datapavan-notes-1.sec -m notes.txt`), so that users and channel
   operators can check them with `signify -V -e` (ADR 0024, point 3).
6. **Publish** the signed APK, the notes and their signature on GitHub Releases; tag the commit
   (`v<version>`), signed.
7. **F-Droid.** F-Droid builds from the tag. With reproducible builds it publishes the APK signed by
   the project only when its own build matches; the recipe lists the certificate's fingerprint.
   [fastlane/](../fastlane/) holds the store texts, which F-Droid reads from the repository.

## What the repository checks by itself

- The build fails if any component adds the INTERNET permission, and `verifyApkRelease` checks the
  native library and its JNI export.
- `scripts/reproducible.sh` compares two builds of the same commit.
- `ThemeTest`, `scripts/plain-language.py` and `scripts/screenshots.sh` keep the interface's contrast,
  wording and touch targets.
