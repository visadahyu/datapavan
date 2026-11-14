# Distribution channels

Status: Datapavan Basic 0.1.2, the first release for everyone, is out on GitHub Releases and the website since 2026-11-07, after the pre-releases 0.1.0 and 0.1.1. F-Droid is asked in early 2027; IzzyOnDroid is not asked (below). [RELEASE.md](RELEASE.md) says how a
release is made and signed; this file says where it goes and what each channel needs. Every channel
carries the same APK, signed with the same offline key, so a user can move between them and every
copy can be checked against the one published fingerprint (ADR 0024).

## Order for v0.1

1. **GitHub Releases**, the source of every other channel: the signed APK, its SHA-256, the release
   notes and their signify signature (RELEASE.md, steps 4 to 6).
2. **The website**, `datapavan.org/download/`: the same signed files from a server that keeps no access log.
3. **F-Droid**, which builds from source and needs a reviewed merge request. Its inclusion policy
   asks for at least three months of active development (Quality, point 6); Datapavan's began on
   2026-10-28, so the request goes in after about 2027-01-28, with the recipe at the release of that
   time. Decided by the maintainer on 2026-11-08.
4. **Obtainium**, which needs nothing from the project: users add the repository's URL and get the
   releases from GitHub. The README says how.

Accrescent comes later, once it accepts new developers again. Google Play gets Datapavan Basic under a package
of its own, `org.visadahyu.datapavan.lite`, signed by Google ([ADR 0031](decisions/0031-datapavan-lite-on-google-play.md),
[ADR 0045](decisions/0045-three-editions-of-one-app.md)), after the first release here.

## GitHub Releases

- Tag `v<version>`, not signed: the signed `notes.txt` names its commit ([RELEASE.md](RELEASE.md)). The release
  holds the APK, `notes.txt` and `notes.txt.sig`, and the README and website carry the certificate's
  fingerprint.
- The APK's file name carries the edition (ADR 0045; the maintainer, 2026-11-14): `datapavan-basic-<version>.apk`
  and, from 0.2.0, `datapavan-advanced-<version>.apk`, built from the same commit at the same version. The
  published 0.1.2 keeps `datapavan-0.1.2.apk`, which its signed notes and `SHA256SUMS` name.
- The names are fixed, since F-Droid's `Binaries` line and Obtainium find the APK by name: the recipe's
  `Binaries` names Basic's APK, and its 0.1.2 build names `datapavan-0.1.2.apk` in a `binary` line of its own.

## IzzyOnDroid

Not asked for now. Its App Inclusion Policy (read on 2026-11-08) sets rules on how an app's code is
written that Datapavan does not meet, so a request would be refused. IzzyOnDroid has also moved its
requests from GitLab to Codeberg.

## F-Droid

- **Recipe:** [fdroid/org.visadahyu.datapavan.yml](fdroid/org.visadahyu.datapavan.yml), for `fdroiddata`,
  in the form `fdroid rewritemeta` writes, which keeps no comments; the reasons are here. The commit in
  angle brackets exists only after the release.
  - **`sudo`:** `build-essential`, since F-Droid's build server has no C compiler, and installing
    cargo-ndk builds crates whose build scripts need one. It needs no JDK step: the build server runs
    Debian 13, whose default JDK is 21, as Gradle's daemon criteria require (ADR 0009).
  - **`srclibs` and `prebuild`:** rustup comes from F-Droid's pinned source library. rustup 1.28 no
    longer installs a project's toolchain on first use, so `rustup toolchain install` installs the
    one in `rust-toolchain.toml`. cargo-ndk is pinned as in CI.
  - **`scandelete`:** F-Droid's scanner refuses binary files in the source: the fuzzing seeds and a
    test DEX file. Neither is needed to build the app, so they are deleted from the build tree.
  - **`Binaries` and `AllowedAPKSigningKeys`:** F-Droid publishes the project's own signed APK when
    its build matches the one on GitHub Releases, so both channels carry the same key (ADR 0024).
    `Binaries` names `datapavan-basic-%v.apk`; the 0.1.2 build's `binary` line names the file published
    before the editions. Advanced gets a recipe of its own (ADR 0045).
- **Checked on 2026-11-05:** `main` (`121ca38`) was built with this recipe and `fdroid build
  --on-server` in F-Droid's build server image (`registry.gitlab.com/fdroid/fdroidserver:buildserver`,
  Debian 13). Its unsigned APK was identical to `scripts/reproducible.sh`'s two builds on the
  development computer, SHA-256 `88470c1e47359056a180143a76df6bfd7b751cd5561f321ba2a942a125f0a163`.
  The NDK, the same revision, was mounted from the development computer, and everything else was
  fetched fresh. `fdroid lint` raised nothing that applies outside the test setup.
- **How to repeat it:** clone `fdroidserver`, put the recipe (with `Repo:` pointing at a checkout and
  a real `commit:`) and fdroiddata's `srclibs/rustup.yml` in a directory with `config.yml`, and run in
  the image: `fdroid fetch_srclibs <appid>:<code>`, then `fdroid build --on-server --no-tarball
  <appid>:<code>`.
- **Anti-features:** none expected. The app has no network access, no tracking and no non-free
  dependencies.

## Obtainium

Nothing to submit. The README's section on checking a copy names the repository's URL and the
fingerprint to compare after the first install, since Obtainium checks updates against the installed
key.

## The website

datapavan.org is plain files in `docs/site`, built with a pinned Hugo from `site/` ([site/README.md](../site/README.md)):
the main page, news and privacy policy in every language. `scripts/check.sh` fails if the
two differ, if a page has a script or loads anything from another server, or if a first load is over about 200 KB.

## Store texts and images

`fastlane/metadata/android/<locale>/` holds, for en-US, fr-FR, de-DE, es-ES, ru-RU, zh-CN, ar and fa-IR:

- `title.txt` and `short_description.txt` (80 characters at most);
- `full_description.txt`;
- `changelogs/<versionCode>.txt` (500 characters at most);
- `images/phoneScreenshots/1.png` to `6.png`, taken on an emulator with apps of our own (`scripts/store-scene.sh`, then
  `scripts/smoke.sh` and `scripts/store-images.sh`), so that they name no one else's app. The website uses three of them.

`en-US/images/icon.png` serves every language. `scripts/store-images.sh` makes the images again.
