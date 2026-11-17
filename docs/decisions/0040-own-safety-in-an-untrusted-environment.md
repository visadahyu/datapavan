# 0040. Datapavan's own safety in an untrusted environment

- Status: Accepted (by the maintainer on 2026-11-12)
- Date: 2026-11-12
- Amended by [ADR 0045](0045-three-editions-of-one-app.md) on 2026-11-13: the project ships as three editions of one app.

## Context

Datapavan judges other apps and the phone. Its own copy, though, can run where it cannot trust what it sees:
- in an emulator or a virtual machine;
- inside an app cloner, which runs its code under the host's own UID;
- under a debugger or a hooking framework;
- on a screen that is recorded or read by another app's accessibility service;
- on a phone that someone else unlocks or extracts.

What it holds is sensitive. The audit's findings can name stalkerware on the phone. Watch's log says which app
spoke to whom. Watch's chain settings name the user's circumvention tool and the apps sent through it.

[ADR 0024](0024-fake-copies-of-datapavan.md) already states the principle: an app cannot prove its own
authenticity from inside, and the check that decides happens outside the copy being judged. The same holds for
its environment. A hostile host can lie to the app and strip any check, so the checks are signals, not proofs.
The one signal that is hard to forge is hardware key attestation. Even that is weaker when it is verified on the
same phone, as Google's own guidance says.

A virtual machine is not a danger by itself. Chromebooks run Android in one, and systems signed with their own
key, such as GrapheneOS and later Datapavan's own, are legitimate. The question is whether the host can be
trusted, never whether it is a virtual machine. Datapavan never shuts users out the way a bank's integrity check
does.

## Decision

1. **The screen is protected everywhere.** Both apps set FLAG_SECURE on every screen by default, as Molly does
   for people at risk, and hide other apps' overlays from their own windows (Android 12 and later). A person who needs a screenshot to ask for help can lift the protection for a moment. It comes back by
   itself. On Android 14 and 15 the apps also notice screenshots and screen recording, and say so calmly.
2. **The log keeps nothing until the user chooses.** Watch's log has no default retention: the user chooses at
   onboarding (W9) between none, 1, 7 and 30 days, with each explained. Until W9 exists, the default is none.
   This replaces the default of 30 days in DESIGN.md §6.4 and the W4 row, under the principle "no log that
   becomes evidence by default".
3. **A lock of Watch's own, and a panic answer.** Watch offers an optional lock of its own, as Molly does, so
   that a forced unlock of the phone does not open the log and the chain settings. It answers PanicKit triggers:
   it can wipe its log and its chain settings, at the user's choice. The chain settings are kept as protected as
   the log.
4. **Calm signals about the environment, never a lock-out.** The apps say, in plain words, when this copy runs:
   - under a debugger;
   - inside an app cloner;
   - in an emulator or a virtual machine, by attestation together with what the system says the device is
     (`Build.HARDWARE`; see "How it is built");
   - with hooks present;
   - while the screen is recorded.

   Each signal comes with what it means for what the app shows. The app keeps working, and nothing is sent
   anywhere.
5. **The attestation verifier follows Google's rules.** It reads the KeyDescription from the leaf and allows
   no other occurrence (amended on 2026-11-17: first written as "its first occurrence counted from the root",
   but Google's validator requires the extension in the leaf and nowhere else, which also closes a chain
   extended below the attested key). It compares the challenge it sent. It reads the
   root of trust from the hardware-enforced list for TEE and StrongBox. It checks the validity of Remote Key
   Provisioning certificates, while factory-key chains stay exempt as Google says. It reads the full root of
   trust, the OS version and the OS, vendor and boot patch levels. The project's own Rust parser stays, and CI
   tests it on a corpus of real chains against Google's reference library.
6. **The decisive check comes from outside: Datapavan Verifier.** A third small app of the project, signed with
   the same key, holds the camera permission and nothing else of note. It checks a phone's attestation from a
   second phone by scanning QR codes both ways, pinning what it saw between checks, as GrapheneOS's Auditor does.
   The audit app and Watch stay without a camera.
7. **Systems signed with their own key are named.** A dataset of known OS keys lets the audit say "signed with
   its own key; it matches GrapheneOS's published key for this model", as an INFO fact. A self-signed key that
   matches no published one is a MEDIUM fact. Datapavan's own OS key joins the dataset in stage 3.

## Consequences

- **Screenshots in CI need a debug path.** `scripts/screenshots.sh` and the accessibility check take
  screenshots, which FLAG_SECURE blackens. Debug builds get a switch that lifts it for tests; release builds
  have none.
- **Some users lose a convenience.** Screenshots of the apps need a deliberate step. This is the price of not
  leaking the screens of people at risk.
- **A third app.** Datapavan Verifier is small, but it is one more package to sign, release and explain. In
  return the camera stays out of the two apps that see the most.
- **Honest limits.** On Android 10 to 13 no app can hide its views from an accessibility service, and on every
  version a service that declares itself an accessibility tool can still read the screen. The apps say this
  where it matters, above all next to the stalkerware finding.

## How it is built

**The hardware check after six independent reviews (2026-11-17, decisions 5 and 7).** The first review read
the parser, `core/engine/src/attestation.rs`; the second the whole check, the chain included; the third the
result, adversarially, twice; the fourth, the fifth and the sixth the result again, each with probes and fresh
mutants. Each fault was shown
before its fix by a test that failed, by a mutant that a new test kills, or, where neither could be, as stated
below.

- **The attestation must answer the app's own request.** The chain check verified only signatures,
  revocation and the root, and the app read the first certificate, so a hooked keystore could append a
  certificate with a forged "locked and verified" extension, signed by a genuine key of its own; nor were the
  challenge or any date checked, so a captured genuine chain from any locked phone could be replayed.
  `AttestationChain.kt` now follows Google's reference verifier (`android/keyattestation`,
  `KeyAttestationCertPathValidator.kt`) rule by rule: the KeyDescription occurs once, in the leaf; the chain has
  the shape Google tells from the certificate the root signed (four certificates for a factory key, five for
  Remote Key Provisioning, three or four when that certificate names neither); each certificate is issued by the
  next by name and signed by it, the root by itself; and every certificate between the leaf and the root is valid
  at the phone's date, but for an expired one in a factory chain. The app compares the challenge. Like Google's
  verifier, it does not require the certificates above the leaf to be marked as CAs: the attestation
  certificates of the Pixel 2 and the Sony Xperia 10 III in Google's test data are not, and their chains are
  genuine.
- **The leaf's key.** The check also requires the leaf to certify the key the app generated. This costs
  nothing but protects little: on Android 12 and later the keystore takes the generated key's public half from
  the same answer's leaf, and on 10 and 11 from its own export, so a hooked keystore controls both; Google's
  verifier does not check it. It catches a keystore that answers with another key's chain by mistake.
- **The date** is the phone's, set by its system: a wrong date can make a sound chain look out of date, and a
  system that sets it back can make an expired one look valid, but cannot make a forged extension, another
  challenge or a revoked or unknown root pass.
- **The revocation list** is the one in the data pack, fetched on the day its `SOURCE` names; a key revoked since
  then passes. Every value the hardware confirms is shown with that day, after them (the "locked and verified"
  line, the patch levels, an owner's boot key), and past 90 days the line says the list is old and asks for a
  newer data pack, which is how the list is refreshed (DATA-PACKS.md): half the age at which the app calls the
  whole pack stale, since a leaked attestation key, the usual way to fake this check, is caught only once Google
  revokes it. The list and its `SOURCE` are read from the same pack, the first that holds the list: the data
  store falls back to the APK's pack file by file, which could have put a newer pack's date on the APK's older
  list. The roots come from the newest pack that holds them, so that a pack can rotate them. A pack whose
  attestation `SOURCE` does not date the list, or dates it after the pack's own signed date (which would keep the
  list fresh for ever), is refused at import, with a message for each case (ADR 0017, DATA-PACKS.md), and a
  test checks that every dataset in the repository dates itself. The build of a pack to publish refuses one
  dated before any dataset it holds, so that the project's own tooling cannot make a pack every phone refuses;
  `scripts/datapack-test.py` moves its test packs' datasets back to an old date it gives them. (The APK's own
  pack is not bounded so: `data/PACK`'s date is the last published pack's, while the datasets are updated
  between releases.) A list whose date is unknown all the same (an imported pack from before this rule) is shown as
  such, never as fresh. The phone's date is its system's, so a clock set back could make an old list look fresh:
  the list's age is counted at the least from the first day of the month before the patch level that Google's
  key confirms, since a system with that patch cannot run long before its month, and makers ship a month's
  patch up to a few weeks early (Samsung has shipped June's in late May): counting from the patch month itself
  called a fresh list old on such a phone (the fifth review's probe). An offline app has no better time: the
  pack's signed date is close to the list's own, and Remote Key Provisioning's certificates, which Google
  dates, are already checked against the phone's date, so a clock set before them makes the chain out of date.
  What remains: on a phone with an old patch level, a clock set back still silences this warning, as it silences the
  old-patch finding.
- **What a hooked keystore can still do.** Sign a whole chain with an attestation key that leaked and is not yet
  revoked; or pass the challenge to another phone it controls, locked and sound, and show that phone's answer as
  this one's. **What a hook inside the app's own process can do besides:** make the challenge one it knows, so
  that a captured genuine chain from any phone answers it, with no leaked key and no second phone; or hand back
  certificate objects whose signature check lies. Doing the chain's arithmetic in the parsers' process on the
  raw bytes would not help: the hook in the app's process feeds that process too. On the phone, no check can
  tell these from the truth; decision 6's check from a second phone, which pins what it saw, closes them.
- **A software answer.** A hook could also answer in software, with the app's challenge, under a chain it signs
  itself or under AOSP's software attestation root, whose private key AOSP publishes; the check called that
  "No hardware check available" (low), quieter than the unlocked bootloader it could hide. Now the chain is
  judged at every security level. On a phone that declares secure hardware for its keys (`FEATURE_HARDWARE_KEYSTORE`
  from Android 12, `FEATURE_STRONGBOX_KEYSTORE` from 9, both answered by the package manager, apart from the
  keystore), a software answer is "Hardware check answered by software" (high). The feature is a declaration,
  not proof (the emulator, below, declares it too); a system with root can hide it, and a phone upgraded to
  Android 12 or later whose vendor partition stayed as it shipped may not make it (AOSP added the feature's file
  to the Keymaster 4.1 reference HAL only in 2021). Where it is not declared, the chain's own verdict decides
  first: a broken chain, another root or a revoked key is reported as such.
- **Android 12 and later as a second declaration (the fourth and fifth reviews).** The Android version is set by
  the whole system and much harder to fake than one file. The Compatibility Definition Document requires every
  handheld to back its keystore with an isolated execution environment and to support key attestation signed in
  secure hardware ([9.11/H-0-2] and [9.11/H-0-5], unconditional for handhelds but not tablets, which have 9.11
  [C-1-1] and [C-1-4] whenever they have a secure lock screen), and has done so in the Android 11 CDD as in
  Android 12's; the only exemption is a device "already launched on an earlier Android version", and
  attestation has been required of phones launched with Android 8 or later. The CDD has no exemption for
  low-RAM or Android Go devices. So the line is where phones launched before Android 8 stop: Google's Pixel and
  Pixel XL, launched with 7.1, were updated to Android 10, and Google's test data holds the Pixel XL on 10
  attesting in software; we found no phone launched before Android 8 with an official update to 11 or 12, but
  could not rule one out for 11, and custom systems run 11 on such phones; the hardware-keystore feature also
  begins at 12. So 12 is the line we can stand behind; moving it to 11 would bring the Android 11 phones (the
  Galaxy A40 among them) under this rule too, and is the maintainer's call. On Android 12 or later, a software
  answer under a root that vouches for nothing (AOSP's published software root, Google's test root) has no
  sound-phone explanation, and others: Android running on a computer (Waydroid, Redroid, the Windows Subsystem
  for Android, Genymotion and other virtual machines and containers, whose keystores are software), phones that
  do not meet the CDD (uncertified ones), and a modified system. It is "Hardware check answered by software on
  Android 12 or later" (medium), whose text names all three, whether or not the feature is declared: AOSP's own
  software keystores declare it (`keymaster/4.1/default` requires `android.hardware.hardware_keystore.km41.xml`,
  and `security/keymint/aidl/default`'s C++ service, registered at the software level, requires
  `android.hardware.hardware_keystore.xml`), so Redroid 13 to 15 and Waydroid's Android 16 branch declare it and
  answer in software under AOSP's root, and high would call them hooked; and since every other answer a system
  with root can give is already medium (below), high would raise no floor. A software answer under Google's own
  root, in date or not (not seen on a device), is judged the same way by version. On a phone that declares
  secure hardware, a software answer under any other chain, or one on Android 10 or 11, stays "Hardware check
  answered by software" (high): no virtual machine is known to give it. On Android 10 and 11, a software answer
  with nothing declared is "No hardware check available", medium since the fifth review (2026-11-17; it was low
  before): after the emulator got its
  own finding, its only sound causes are phones launched before Android 8 and Android on a computer, while on
  most phones on those versions, which declare nothing since the feature begins at 12 and have no secure chip, a
  hook reaches it with nothing to hide; its text now says that phones launched with Android 8 or later all
  support the check, so that an owner can tell it is not normal for their phone. Whether the app could read the
  version a phone launched with on 10 and 11: `Build.VERSION.DEVICE_INITIAL_SDK_INT` is public only from Android
  12; `ro.product.first_api_level` is a system property, read only through hidden API (`SystemProperties`),
  native code (`__system_property_get`, which this project's native code would need new unsafe code for), or a
  shell; whether an app's SELinux domain may read it on 10 and 11 is not verified; and a modified system can
  set it as it can `ro.hardware`. So it is left. What is known of ChromeOS's Android (ARC): its sources hold
  `libarc-attestation`, so it may answer at a hardware level, under a root we have not seen; whether it does,
  under which root, at which level, and whether it declares the feature, is unknown until a Chromebook is run
  with the lab record below. If it answers in software under a root of nothing on Android 12 or later, it reads
  as medium; if under another root, as that root's verdict.
  A claim of secure hardware under AOSP's software root is "Hardware check signed with a published key" (high),
  and, as with a forged attestation, nothing it says is used: no sound phone makes either, and what they say is
  their maker's choice, or another phone's answer. The warnings of any other attestation, which a sound phone
  could have made, are reported confirmed or not (an unlocked bootloader, an old patch level), since a forger
  gains nothing by them.
- **The emulator, from its real chains.** The hardware-keystore feature does not prove the hardware: Android 15's
  emulator (CI's `dp-api35-ci`) declares `android.hardware.hardware_keystore=300` for a KeyMint that runs in
  software. What tells it is what the system says the device is: `Build.HARDWARE` (`ro.hardware`) is "ranchu" on
  Android's emulator, and was "goldfish" before. Its chain was first assumed to be AOSP's software root; the
  fourth review's round limited the emulator's claim to that root, and Android 15's emulator then showed
  "answered by software" again, so its chains were read from the device with the lab record below (2026-11-17,
  `core/engine/testdata/emulator`, with SOURCE):
  - Android 15 (`system-images;android-35;google_apis;x86_64`, revision 9, userdebug) runs AOSP's in-process
    KeyMint (`android.hardware.security.keymint-service`, KeyMint 300, documented in AOSP as insecure, its TA
    running in the HAL's process), and its attestation key came from Google's key provisioning service: the
    chain is the leaf, an intermediate "O=TEE" valid for 16 days, and the root "Droid Unregistered Device CA" of
    "Google Test LLC", self-signed and valid for 72 days, issued the same day as the intermediate. Two captures
    were made: the first (16:44 UTC+3, intermediate "CN=a6a327…") said OTHER_ROOT, at the software level, before
    the test root was told; the second (17:44, intermediate "CN=977cc1…", the committed `sdk35.pem`, with a build
    that tells it and is signed with a throwaway debug key) said TEST_ROOT. Both are under the same root (serial
    9BA2D252…, SubjectPublicKeyInfo SHA-256 51894c…).
  - Android 11 (`android-30`, revision 16, userdebug) runs Keymaster 4.1 in software and signs under AOSP's
    software intermediate (expired 2026-01-08) and root, as `system/keymaster`'s `soft_attestation_cert.cpp`
    holds them. The check said SOFTWARE_ROOT. So the two images' keystores differ, and the captures say how.

  Both roots vouch for nothing about a phone, so the emulator's claim counts under either, and only under them:
  "No hardware check on an emulator", medium; a revoked, broken or other chain is judged as on any device. The
  finding is free on real emulators, which developers and CI run, and level with the other answers a system with
  root can give; its text says plainly what an emulator is (a program that runs Android on a computer) and that on
  a real phone the report is false, made only by a modified system, which can hide an unlocked bootloader this
  way. What a hook can do with it: set `ro.hardware` on a phone and turn "answered by software" (high) into this
  medium finding. What it cannot do: make that quiet, or change how a hardware attestation is judged.
- **Google's test root for unregistered devices.** Google's key provisioning service gives devices whose maker did
  not register them certificates under a test root (a vendor's guide to it, ArmSoM's on Rockchip boards, says so
  of unregistered devices on userdebug and eng builds, and that the root must not be trusted for production; we
  found no Google page that names it). It is not among Google's attestation roots, and anyone who runs Android's
  public emulator holds a key certified under it, in software, so it vouches for nothing, as AOSP's published
  root does not. The app tells it as its own verdict (TEST_ROOT) by the root's name, not its key: Google reissues
  the root (the captured one lives 72 days), nothing says its key stays, and a key pinned today could miss the
  next. The name gives a forger nothing: anyone can already sign under AOSP's published root key, which is judged
  alike, and a root that holds one of Google's keys is Google's whatever its name. What a device that does not
  call itself an emulator is shown under it:
  - in software, on Android 12 or later, declared or not: "Hardware check answered by software on Android 12 or
    later" (medium), whose text names Android on a computer and phones that do not meet Android's requirements;
  - in software, on Android 10 or 11, where the phone declares a secure chip: "Hardware check answered by
    software" (high);
  - in software, on Android 10 or 11, which had no key provisioning: "Hardware check signed with Google's test
    certificate" (high), whose text there says that those versions cannot get such keys, so that only a modified
    system answers so;
  - claiming secure hardware: the same high finding, and nothing else it says, as under AOSP's published root: on
    Android 12 or later an unregistered device on a test build can answer so, and so can a forgery, and the text
    says both; on 10 and 11, only a forgery, and the text says that; no phone made for sale does.

  The test root's intermediates live about two weeks, so the test vector is judged at fixed dates; and the
  verdict comes before the dates are checked, so that an expired chain under it is still the test root's, as one
  under AOSP's root is. The Galaxy A40's chain, captured the same way (factory-provisioned, four certificates),
  is Google's at its capture date with the bundled revocation list; it is the maintainer's lab phone, so it is
  not a test vector until the maintainer agrees.
- **What a hook can still make of a phone that declares the hardware, or runs Android 12 or later.** The rules
  above keep a hook from turning such a phone's answer quiet; short of that, a hooked keystore can still give,
  in place of the high finding an unlocked bootloader gets, a medium one: a chain at a hardware level under a
  root of its own ("Hardware check not confirmed"), a broken chain ("Hardware check broken"), a failed check
  ("Hardware check failed"), or one of the errors that say the keys are unavailable, need a system update, or
  were refused ("Hardware check waiting for Google", "Hardware check needs a system update", "Google refused
  keys for the hardware check", each of whose texts says that a modified system could give this answer). With
  root, it can also answer in software under a root of nothing, which on Android 12 or later gives "Hardware
  check answered by software on Android 12 or later" (medium) whether or not the declaration is hidden, or set
  `ro.hardware` to the emulator's, which gives "No hardware check on an emulator" (medium); on Android 10 and 11,
  where most phones declare nothing, a software answer gives "No hardware check available" (medium) with nothing
  to hide. Each says that the state cannot be confirmed, none shows a value as the hardware's, and a sound phone
  gives each rarely, so none is made high, and since the fifth review (2026-11-17) none is low.
- **Not remembering earlier checks (trust on first use), with the reason.** The third review asked whether to
  remember, locally, what an earlier sound check saw (Google's root, the provisioning, the boot key) and report a
  weaker later answer as a change, high where it could hide an unlocked bootloader. It is not built on the phone,
  for four reasons. Unlocking the bootloader wipes the phone's data, this app's memory with it, so the memory is
  gone exactly when the change it should catch happens: AOSP's description of the device states says that "all
  state transitions wipe the data partitions" (source.android.com, Verified Boot, Device state), and KeyMint binds
  every key to the root of trust, so that after a change of the lock state or of the boot key "none of the
  KeyMint-protected keys created by the previous system are usable" (source.android.com, Keystore features, Root
  of trust binding), which also covers an unlock by an exploit that skipped the wipe. A hook on a phone whose
  bootloader stays locked, as after an exploit that unlocked nothing, gains nothing by hiding a locked and
  verified state. The fourth review agreed. With root, the memory can be erased or rewritten, and an erased
  memory looks like a first check. A phone whose keys run out, as they do after one to four weeks on a network
  that blocks Google, or whose provisioning changes with a system update, would raise a false high alarm, which
  teaches its owner to ignore the finding. And a stored boot key and state is more than the app keeps today
  (PRIVACY.md). The memory belongs outside the phone, where neither a wipe nor root reaches it: decision 6's
  check from a second phone pins what it saw, as GrapheneOS's Auditor does. What it would change: the medium
  routes above would show as a change on a phone checked before.
- **The lab record (debug builds only).** To judge a device's real chain from facts, as the emulator's, debug
  builds log what each check saw under the logcat tag `DatapavanAttestationLab`: the verdict, the chain check's
  verdict before the challenge is compared, the security level the parser reads (the weaker of the two; both
  are in the leaf), the chain's length, and each certificate as base64 DER, in parts under logcat's limit
  (`src/debug/.../audit/AttestationLab.kt`). It is off unless the lab turns it on, so that a debug build given to
  a tester logs nothing: only while the app's files hold `attestation-lab`, which only `adb shell run-as` can put
  there, and only for a debuggable build (`adb shell run-as <package> touch files/attestation-lab`; `rm` turns
  it off). `scripts/attestation-chain-from-logcat.py` turns a capture into PEM, and fails unless every
  certificate the summary counts is there whole. What a chain holds, beyond the verdict: the leaf states the
  phone's bootloader lock state, verified boot state, verified boot key and hash, OS version and patch levels,
  and the app that asked, by its package and the SHA-256 of the certificate that signed it (in a debug build,
  the developer's own debug key, often the same for all their projects); a chain from Remote Key Provisioning
  carries an intermediate issued for the phone's current attestation key (O=TEE, CN=a serial), which links
  captures while that key lives; a factory-provisioned intermediate may name a serial number of the batch or the
  unit (the Galaxy A40's names one). So a chain becomes a test vector only from a lab device, from a build
  signed with a throwaway key, as the emulators' are. Nothing the record does can change the check's result: a
  record that fails is ignored. Release builds cannot reach it: the code lives in the debug source set, the
  release source set has a no-op in its place, and `verifyApkRelease` fails if a release APK's code holds the
  tag, while `verifyApkDebug` fails if a debug APK's does not, so that the check is shown to see it.
- **One check at a time.** The check used one fixed key alias, and a rotation, a fold or a theme change recreates
  the screen and starts a second check while the first waits on the keystore: the second could read the first's
  key and call a sound phone's check tampered with. `HardwareCheck` now runs one check at a time in the process,
  each under an alias of its own, and sweeps keys left by a check that did not finish. A fake keystore with real
  phones' chains tests what the collector runs, two checks at once included.
- **Each value comes from one list only.** The parser took `rootOfTrust` and `osPatchLevel` from the
  software-enforced list, which the system writes, whenever the hardware-enforced list lacked them. Now a
  trusted environment's or StrongBox attestation is read from its hardware-enforced list alone, and a
  software attestation from its software-enforced list alone. The security level is the weaker of
  `attestationSecurityLevel` and `keyMintSecurityLevel`, as Google's verifier takes it; a precedence test
  shows the hardware list winning where both carry values, which passed before as well.
- **Encoding: never a false "locked and verified", never a false failure.** The first review asked for DER
  everywhere; the second asked to decide each difference from Google's verifier, which reads through
  BouncyCastle, by that rule instead: once the chain check holds, every byte is signed by the phone's attestation
  key for this request, so leniency lets nothing unsigned through, while strictness could only fail a sound phone.
  So the parser reads lengths in any definite form, a BOOLEAN as false only when 0x00 (a genuine chain in
  Google's test data writes `deviceLocked` as 0x01, and BER and BouncyCastle read any non-zero byte as true),
  entries in any order, and treats a malformed or contradicting `rootOfTrust` or patch level as absent rather than
  failing the whole extension. It stays as strict as BouncyCastle on tag numbers and integers, and as Google's
  verifier on the KeyDescription's eight fields. Where it differs from Google's verifier, it says so in its
  documentation: it refuses the indefinite length form; it treats two different copies of an entry as absent,
  where Google keeps the last; it treats every malformed root of trust as absent, where Google fails on some; and
  it skips tags it does not know, where Google fails. All nine chains of the corpus are strict DER but for that
  one BOOLEAN.
- **The corpus of real chains.** The maintainer approved the download of 16 files of Google's test data
  (`android/keyattestation` at c391708, Apache-2.0), recorded in `core/engine/testdata/keyattestation/SOURCE`
  with each file's SHA-256: chains from a Pixel 2, a Pixel XL, a Pixel 3's StrongBox, a Sony Xperia 10 III, a
  Pixel 8a, a Pixel 9 Pro and a Pixel 9, and two samples Google keeps as invalid. The Rust tests compare every
  value the parser reads with the values Google's library decodes, on all seven; the JVM tests run the chain
  check on all nine. One invalid sample is a genuine chain whose `deviceLocked` is 0x01, read as true; the
  other's leaf was edited, and its chain is broken. Synthetic chains show the rules no real chain can.
- **Every field of decision 5, and what the app shows of it.** The parser reads the challenge, the whole root
  of trust (`verifiedBootKey`, `verifiedBootHash`), `osVersion`, and the OS, vendor and boot patch levels (as
  `YYYYMM`, from the six or eight digits keystores write; anything else is absent). A value is shown as the
  hardware's only when Google's root confirms a hardware attestation; otherwise the patch level reads as the
  system's word, and the vendor level and an owner's boot key are not shown, since a forger can show any key.
- **Keys from Google.** On phones that get their attestation keys from Google's provisioning server, keys last
  one to four weeks (the corpus's: 28, 9 and 13 days); one that cannot reach Google, as on a network that blocks
  it, has none, and Android 13 and later say so, with a retry policy (`KeyStoreException.getRetryPolicy`). Once
  online, or keys unavailable and later, is "Hardware check waiting for Google" (medium, calm text, which says
  that a modified system could claim it). Keys unavailable for good is Google's server refusing this phone keys,
  as for a phone its maker did not register, which no connection mends: "Google refused keys for the hardware
  check", which says the maker or seller may be able to help. Keys only after the next reboot (Android 14: the
  server gives keys only once a pending system update is installed) is "Hardware check needs a system update",
  which says to install it and restart. Any other error, and anything before Android 13, which does not say, is
  "Hardware check failed", whose text names the sound-phone causes, an Android 12 phone whose keys ran out while
  it could not reach Google included. Each is medium, not low, since a hook could claim it too. Basic never
  connects; the phone fetches the keys itself.
- **Tests.** The truncation test cut only the outer element; the tests now cut every element at every byte,
  about 2,500 cases. Two extensions encoded by OpenSSL test the tests' own encoder. The fuzz target also puts its
  bytes inside a valid extension and checks that the list the parser does not read never changes its values and
  makes the extension fail exactly when it is not well formed, and that a malformed root of trust never fails the
  rest. The reviews' surviving mutants, in Rust and Kotlin, are each killed by a test, and the record that
  carries the result across JNI is tested from both sides.
- **Smaller.** The depth limit could not be shown by a failing test, since nothing reached it: nested
  SEQUENCEs put at every position the parser reads never produced it. It is gone, and the documentation names
  the real bound. Errors say whether a field was missing or data followed the last one.

What the app shows, in each case:

- a check that failed or could not be read: "Hardware check failed" (medium). Android requires attestation of
  phones launched with Android 8 or later; the keystore of an older one on Android 10 attests in software, as the
  Pixel XL in the corpus, launched with Android 7, does; and no public API says which version a phone launched
  with. So a failure counts everywhere;
- a phone without attestation keys until it reaches Google: "Hardware check waiting for Google" (medium); one
  that Google's server refused keys for good: "Google refused keys for the hardware check" (medium); one that
  gets keys only after a system update: "Hardware check needs a system update" (medium);
- a forged attestation (another challenge or key, or a certificate below the attested key): "Hardware check
  tampered with" (high), and nothing else it says, not even its patch level;
- a software answer on a phone that declares secure hardware for keys: "Hardware check answered by software"
  (high), but for one under a root of nothing on Android 12 or later (next);
- a software answer under AOSP's software root or Google's test root on a device whose system reports it as
  Android's emulator: "No hardware check on an emulator" (medium), which says what an emulator is and that on a
  real phone the report is false;
- a software answer on Android 12 or later under a root of nothing, declared or not, or under Google's root with
  nothing declared: "Hardware check answered by software on Android 12 or later" (medium);
- a claim of secure hardware under AOSP's software root: "Hardware check signed with a published key" (high),
  and nothing else it says; under Google's test root for unregistered devices: "Hardware check signed with
  Google's test certificate" (high), and nothing else it says, as for a software answer under it on Android 10
  or 11;
- a software attestation under AOSP's software root or Google's on Android 10 or 11, on a phone that declares no
  such hardware: "No hardware check available" (medium), which says that phones launched with Android 8 or later
  all support the check, and its patch level as "Security patch, as the system states it";
- a broken chain: "Hardware check broken" (medium); a chain to another root: "Hardware check not confirmed"
  (medium); a revoked key: "Hardware check key revoked" (high); a certificate not valid at the phone's date, for
  a hardware attestation: "Hardware check out of date" (medium); each with its patch level as the system's word.
  For a software answer, the first three apply where the phone declares no secure hardware, whether or not it
  calls itself an emulator (where it declares it, "answered by software", high, comes first), and a software
  answer is never called out of date: under Google's root, in date or not, it is judged by version;
- a hardware attestation without a root of trust in its hardware list: "Hardware check incomplete" (medium);
- a locked phone whose boot state is self-signed: "System signed with its own key" (medium, as decision 7
  rates a key that matches no published one, since the dataset of published keys does not exist yet), and, with
  Google's root, its verified boot key, to compare with the one its project publishes;
- otherwise, with Google's root, a locked bootloader and a verified boot: the "locked and verified" line, the
  patch level, and the vendor's where it lags;
- under any value Google's root confirms: the day of the revocation list it was checked against, its age counted
  at the least from the first day of the month before the confirmed patch month, or that the list's date is
  unknown.

Decoded but not shown, with the reason: `verifiedBootHash`, which nothing on the phone could be compared with
(decision 6's check pins it); `osVersion`, until real phones show how often it differs from what the system
reports; the boot patch level, which equals the system's on every chain of the corpus. Shown but not judged: the
vendor patch level. A Pixel 3 in the corpus, patched in August 2019, still stated its vendor level as September
2018, so an old vendor level is no sign of an unpatched phone, and the finding that judged it is gone.

Still open from decisions 5 and 7: the dataset of the boot keys that systems such as GrapheneOS publish
(decision 7), which would name the system and make the self-signed fact informational; a comparison of
`osVersion` and the patch levels with what the system reports; the check from a second phone (decision 6); and
a run on real phones of each vendor, since the corpus holds only Pixels and one Sony, and the Galaxy A40 is the
only phone this build has run on.
