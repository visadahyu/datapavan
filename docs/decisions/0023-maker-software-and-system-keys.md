# 0023. The phone maker's software and leaked system keys

- Status: Accepted
- Date: 2026-10-31
- Decided by: mehdashti

## Context
Every Android phone has a *platform key*: the certificate that signs the package `android`, the
framework itself. Apps signed with the same key receive the framework's signature permissions, and
those that share the user ID `android.uid.system` run as the system. The phone's maker decides which
apps get this key. Datapavan wants to show the maker's software, and to warn where the key itself
cannot be trusted.

A reading of two devices on 2026-10-31, and a review of AOSP, Google's partner disclosures, research
on preinstalled software and the tools that list it, found:
- **The key is easy to read and widely used.** On the A40 (Samsung, Android 11), 254 of 473 system
  packages and 6 apps from Samsung's and Google's stores are signed with the platform key. On the
  Android 17 emulator, 58 of 267 system packages are. Package names and the system flag alone do not
  tell these apart.
- **The key says who shipped an app with system rights, not who wrote it.** Makers sign third-party
  code with it (an update service has been seen under 60 different makers' keys), sign some of their
  own apps with other keys, and on Pixel phones Google's apps use Google's app keys. Certificate
  subjects are self-asserted: "CN=Samsung Cert" names two different keys, and over a hundred
  certificates in one study just say "Android".
- **Some platform keys are public or leaked.** AOSP's test keys, including a platform test key, are
  public; Google's compatibility tests fail a certified device that ships them, but uncertified phones
  and custom systems do, and the build tag `test-keys` is only a hint. In November 2022 Google's
  Android Partner Vulnerability Initiative published ten platform certificates that had signed
  malware, from Samsung, LG, MediaTek and smaller makers. **The A40's platform certificate is one of
  them** (the SHA-256 and the serial number match), and public crowd data shows Samsung still using it
  on phones up to Android 17. The emulator's key is Google's private development key, not a public
  one.
- **What a leaked key allows depends on the Android version.** Up to Android 14, an app installed
  from a file and signed with the phone's leaked key can run as the system and take the framework's
  signature permissions without asking. Android 15 and later block that for apps outside the system
  image, but on every version such an app can pose as an update of a preinstalled app signed with the
  same key and keep that app's rights. Samsung's own store apps still carry the leaked key, so a match
  alone is not malware.
- **No consumer tool checks keys.** Debloaters, App Manager, εxodus and TrackerControl go by package
  name and the system flag; their lists are GPL or AGPL. Google checks partner images and Play Protect
  scans in the cloud. One crowd database groups keys by maker the same way, without a licence.
- **Research on maker software:** system apps of Samsung, Xiaomi, Realme and Huawei send persistent
  identifiers and, for most, the list of installed apps, and declining the options during setup does
  not stop it (Liu, Patras and Leith, 2023). No study tested how people read a label such as "made by
  your phone's maker".

The research behind this record is kept in the maintainer's private repository.

## Decision
1. **The platform key is read on the phone.** Datapavan reads the signing certificate and its history
   of the package `android` and tests every app against it. It ships no list of makers' platform keys
   for this.
2. **Each app gets separate facts, not one verdict:**
   - its signer: this phone's system key, a maker's key recorded in `data/owners` (ADR 0020), another
     recorded company, or not known;
   - its origin: the system image, an updated system app, or installed later, with the installer;
   - whether it runs as the system user;
   - whether it has an icon in the app drawer, or is a part of the system.

   An app signed with the system key says so, and what it means: the phone's maker shipped or
   approved it with system rights, and it may still be another company's code. The words "safe",
   "bloat" and "needed" are not used.
3. **The maker is named from evidence.** A key recorded in `data/owners` names its company, from the
   makers' own Digital Asset Links files at grade 1, as ADR 0020 does for publishers; those apps then
   count for the same-group notes. Otherwise the page says "the phone reports its maker as X"
   (`Build.MANUFACTURER`).
4. **Keys that cannot be trusted are named in `data/system-keys`** (CC0): AOSP's public test keys,
   Google's development keys, and the ten certificates of Google's 2022 disclosure, each with its
   source, the source's SHA-256 and the date. Only fingerprints that a source states or that are read
   from the certificate files are recorded; the files are downloaded with the maintainer's approval.
5. **Phone-wide findings:**
   - the system key is a public test key: high. Anyone can make an app that this phone trusts as part
     of the system;
   - the system key is on the leaked list: medium. The maker kept using a key that has signed malware,
     and the page says what that allows on this Android version and to install apps only from the
     maker's store and Google Play;
   - a Google development key: a note that the system was built for development, as emulators are.
6. **App findings:**
   - an app signed with a leaked or public test key, of this phone or another, that was installed
     later or updated from a source other than the maker's store or Google Play: high;
   - the same from the maker's store or Google Play, or put there by the phone's own setup (no
     installer, and signed with this phone's own system key): a note, because the maker still signs
     its apps with that key. (The setup case was added on 2026-10-31, when the build found three such
     Samsung apps on the A40; an app installed from a file always has an installer.)
   - an app installed later and signed with this phone's system key, which is not leaked: a note.
7. **Nothing of the maker's is to be removed by default.** Where research shows what a maker's
   software sends, the page cites it with the vendor, model and year, and the remediation plan
   prefers the maker's own privacy settings, saying that they reduce collection but may not stop it.

## Consequences
- The Galaxy A56 (Android 16, 2025) carries the same leaked key (same SHA-256 and serial number, read
  on 2026-10-31), so the leak is not limited to old phones.
- On the A40, the overview reports the leaked system key, and Samsung's six store apps signed with it
  get a note, not a warning. The emulator gets the development-key note.
- Before it is built:
  - the nine AOSP certificate files (about 2 KB each) and Google's development-key files from the
    compatibility tests (about 1 KB each) are downloaded, with the maintainer's approval;
  - the ten fingerprints are copied from Google's disclosure and checked against the A40.
- The checks are tested on the A40, on the emulator, and with a test app signed with AOSP's public
  test platform key, whose private half is public (its download also needs approval).
- Accepted limits:
  - an ordinary app cannot read privileged status, the partition an app came from, or the factory
    version of an updated app;
  - the installer is what the installing app reported;
  - a key match is evidence about the signer, never proof of what the app does.
- Makers' own keys and statements about their software grow in `data/owners` and in later research.
