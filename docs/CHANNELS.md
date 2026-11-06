# Distribution channels

Status: prepared for v0.1 on 2026-11-05; no build is published yet. [RELEASE.md](RELEASE.md) says how a
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

Accrescent comes later, once it accepts new developers again. Google Play gets a separate app, Datapavan Lite, with its
own name, package and key ([ADR 0031](decisions/0031-datapavan-lite-on-google-play.md)), after the first release here.

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
