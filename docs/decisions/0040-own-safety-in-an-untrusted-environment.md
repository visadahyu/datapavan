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
   - in an emulator or a virtual machine, by attestation;
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

**The hardware check after three independent reviews (2026-11-17, decisions 5 and 7).** The first review read
the parser, `core/engine/src/attestation.rs`; the second the whole check, the chain included; the third the
result, adversarially, twice. Each fault was shown before its fix by a test that failed, by a mutant that a new test
kills, or, where neither could be, as stated below.

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
  list. A list without its `SOURCE` is undated, and no date is shown.
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
  not proof (the emulator, below, declares it too), and a phone upgraded to Android 12 or later whose vendor
  partition stayed as it shipped may not declare it; such a phone, and one on Android 10 or 11 without a secure
  chip, where no public API says whether a phone has such hardware, is judged by the chain: under AOSP's
  software root it is "No hardware check available" (low), with a text that names a modified system as well as
  emulators and phones without such hardware; a broken chain, another root or a revoked key is reported as such.
  A claim of secure hardware under AOSP's software root is "Hardware check signed with a published key" (high),
  and, as with a forged attestation, nothing it says is used: no sound phone makes either, and what they say is
  their maker's choice, or another phone's answer. The warnings of any other attestation, which a sound phone
  could have made, are reported confirmed or not (an unlocked bootloader, an old patch level), since a forger
  gains nothing by them.
- **The emulator.** The hardware-keystore feature does not prove the hardware: Android 15's emulator (CI's
  `dp-api35-ci`) declares `android.hardware.hardware_keystore=300` for a KeyMint that runs in software and signs
  under AOSP's software root, so the rule above called it "answered by software" (high). Nothing else tells that
  KeyMint from a hooked keystore's answer: its extension states the software level for both the attestation and
  the key, which is exactly what a hook answering in software writes, and its chain is AOSP's. What tells it is
  what the system says the device is: `Build.HARDWARE` (`ro.hardware`) is "ranchu" on Android's emulator, and was
  "goldfish" before. A software answer on a device that says so is "No hardware check on an emulator" (low), whose
  text says, in words, that the device reports itself as an emulator, and that on a phone this is untrue and a
  serious warning. What a hook can do with it: a modified system can set `ro.hardware` on a phone and turn
  "answered by software" (high) into this low finding. What it cannot do: make that quiet. The phone then tells
  its owner, by name, that it is an emulator, which they can see is false, and the finding says what that means;
  and the claim changes nothing for a hardware attestation, which is judged as before.
- **What a hook can still make of a phone that declares the hardware.** The rules above keep a hook from turning
  such a phone's answer quiet; short of that, a hooked keystore can still give, in place of the high finding an
  unlocked bootloader gets, a medium one: a chain at a hardware level under a root of its own ("Hardware check
  not confirmed"), a broken chain ("Hardware check broken"), a failed check ("Hardware check failed"), or the
  error that says the keys are unavailable ("Hardware check waiting for Google", whose text says that a modified
  system could give this answer). Each says that the state cannot be confirmed, none shows a value as the
  hardware's, and a sound phone gives each rarely, so none is made high. And with root, a modified system can
  hide the declaration itself (the feature's file in the vendor partition, under `/vendor/etc/permissions`):
  then a software answer reads as on a phone without such hardware, "No hardware check available" (low), whose
  text names a modified system among its causes. The declaration is the system's word, as `ro.hardware` is.
- **Not remembering earlier checks (trust on first use), with the reason.** The third review asked whether to
  remember, locally, what an earlier sound check saw (Google's root, the provisioning, the boot key) and report a
  weaker later answer as a change, high where it could hide an unlocked bootloader. It is not built on the phone,
  for four reasons. Unlocking the bootloader wipes the phone's data (Android's verified boot: every change of the
  lock state wipes the data partitions), this app's memory with it, so the memory is gone exactly when the
  change it should catch happens; and a hook on a phone whose bootloader stays locked, as after an exploit, gains
  nothing by hiding a locked and verified state. With root, the memory can be erased or rewritten, and an erased
  memory looks like a first check. A phone whose keys run out, as they do after one to four weeks on a network
  that blocks Google, or whose provisioning changes with a system update, would raise a false high alarm, which
  teaches its owner to ignore the finding. And a stored boot key and state is more than the app keeps today
  (PRIVACY.md). The memory belongs outside the phone, where neither a wipe nor root reaches it: decision 6's
  check from a second phone pins what it saw, as GrapheneOS's Auditor does. What it would change: the four medium
  routes and the hidden declaration above would show as a change on a phone checked before.
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
  that a modified system could claim it). A refusal for good, as when Google's server refused to issue keys to
  this phone, which no connection mends, or a wait for a reboot or a system update, is "Hardware check failed";
  so is anything before Android 13, which does not say. It is not low, since a hook could claim it too. Basic
  never connects; the phone fetches the keys itself.
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
- a phone without attestation keys until it reaches Google: "Hardware check waiting for Google" (medium);
- a forged attestation (another challenge or key, or a certificate below the attested key): "Hardware check
  tampered with" (high), and nothing else it says, not even its patch level;
- a software answer on a phone that declares secure hardware for keys: "Hardware check answered by software"
  (high);
- a software answer on a device whose system reports it as Android's emulator: "No hardware check on an
  emulator" (low), which says that on a phone this would be false;
- a claim of secure hardware under AOSP's software root: "Hardware check signed with a published key" (high),
  and nothing else it says;
- a software attestation under AOSP's software root, on a phone that declares no such hardware: "No hardware
  check available" (low), and its patch level as "Security patch, as the system states it";
- a broken chain: "Hardware check broken" (medium); a chain to another root: "Hardware check not confirmed"
  (medium); a revoked key: "Hardware check key revoked" (high); a certificate not valid at the phone's date:
  "Hardware check out of date" (medium); each with its patch level as the system's word;
- a hardware attestation without a root of trust in its hardware list: "Hardware check incomplete" (medium);
- a locked phone whose boot state is self-signed: "System signed with its own key" (medium, as decision 7
  rates a key that matches no published one, since the dataset of published keys does not exist yet), and, with
  Google's root, its verified boot key, to compare with the one its project publishes;
- otherwise, with Google's root, a locked bootloader and a verified boot: the "locked and verified" line, the
  patch level, and the vendor's where it lags;
- under any value Google's root confirms: the day of the revocation list it was checked against.

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
