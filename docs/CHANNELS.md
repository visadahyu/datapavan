# Distribution channels

Status: prepared for v0.1 on 2026-11-05; nothing is published yet. [RELEASE.md](RELEASE.md) says how a
release is made and signed; this file says where it goes and what each channel needs. Every channel
carries the same APK, signed with the same offline key, so a user can move between them and every
copy can be checked against the one published fingerprint (ADR 0024).

## Order for v0.1

1. **GitHub Releases**, the source of every other channel: the signed APK, its SHA-256, the release
   notes and their signify signature (RELEASE.md, steps 4 to 6).
2. **IzzyOnDroid**, which lists an app within days of a request, from the APK on GitHub Releases.
3. **F-Droid**, which builds from source and needs a reviewed merge request; it takes weeks, so the
   request goes in with the first release.
4. **Obtainium**, which needs nothing from the project: users add the repository's URL and get the
   releases from GitHub. The README says how.

Accrescent and Google Play come later: Play in the foundation's name and as an audit-only edition
(see the private strategy notes), Accrescent once it accepts new developers again.

## GitHub Releases

- Tag `v<version>`, signed. The release holds `datapavan-<version>.apk`, `notes.txt` and
  `notes.txt.sig`, and the README and website carry the certificate's fingerprint.
- The APK's file name is fixed, since F-Droid's `Binaries` line and Obtainium find it by name.

## IzzyOnDroid

- **Request:** an issue in IzzyOnDroid's repository on GitLab (`IzzyOnDroid/repo`), naming the
  GitHub repository and the package. Its client scans each APK for trackers and non-free libraries;
  Datapavan has none, and its INTERNET-free manifest is easy to confirm.
- **What it reads:** the APK from the latest release, and the texts and images from
  `fastlane/metadata/android` in the repository: titles, short and full descriptions in four
  languages, changelogs by versionCode, the 512 px icon and six screenshots per language
  (`scripts/store-images.sh`).
- **Reproducible builds:** IzzyOnDroid can check that its own build of the tag matches the APK. The
  same recipe facts as for F-Droid apply (below).

## F-Droid

- **Recipe:** [fdroid/org.visadahyu.datapavan.yml](fdroid/org.visadahyu.datapavan.yml), a draft for
  `fdroiddata`. It installs JDK 21, the Rust toolchain from `rust-toolchain.toml` through F-Droid's
  pinned rustup source library, cargo-ndk 4.1.2 and NDK 30.0.16248370, then builds the release with
  Gradle. With `Binaries` and `AllowedAPKSigningKeys`, F-Droid publishes the project's signed APK when
  its build matches.
- **Before the merge request:**
  - Build the recipe with `fdroid build` on F-Droid's build server image, or in its Docker
    container, which needs `fdroidserver` installed here first.
  - Run `fdroid lint` and `fdroid rewritemeta` on it.
  - Compare the result with `scripts/reproducible.sh`'s APK.

  So far `scripts/reproducible.sh` has shown the build identical across two directories on one
  computer only. F-Droid's server differs in user, paths and installed packages, so a mismatch there
  is the likeliest problem; the build already remaps the cargo paths for this reason.
- **Anti-features:** none expected. The app has no network access, no tracking and no non-free
  dependencies.

## Obtainium

Nothing to submit. The README's install section names the repository's URL and the fingerprint to
compare after the first install, since Obtainium checks updates against the installed key.

## Store texts and images

`fastlane/metadata/android/<locale>/` holds, for en-US, fr-FR, de-DE and fa-IR:

- `title.txt` and `short_description.txt` (80 characters at most);
- `full_description.txt`;
- `changelogs/<versionCode>.txt` (500 characters at most);
- `images/phoneScreenshots/1.png` to `6.png`.

`en-US/images/icon.png` serves every language. `scripts/store-images.sh` makes the images again.
