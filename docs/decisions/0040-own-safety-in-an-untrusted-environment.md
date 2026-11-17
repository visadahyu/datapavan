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
5. **The attestation verifier follows Google's rules.** It reads the KeyDescription only from its first
   occurrence counted from the root, and allows one occurrence. It compares the challenge it sent. It reads the
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

**The hardware check after two independent reviews (2026-11-17, decisions 5 and 7).** The first review read
the parser, `core/engine/src/attestation.rs`; the second read the whole check, the chain included. Each fault
was shown before its fix by a test that failed, or, where no test could fail, as stated below.

- **The attestation must answer the app's own request.** The chain check verified only signatures,
  revocation and the root, and the app read the first certificate, so a hooked keystore could append a
  certificate with a forged "locked and verified" extension, signed by a genuine key of its own, and the check
  trusted it; nor were the challenge, the leaf's key or any date checked, so any captured genuine chain from
  any locked phone could be replayed. `AttestationChain.kt` now follows Google's reference verifier
  (`android/keyattestation`, `KeyAttestationCertPathValidator.kt`): the KeyDescription occurs once, in the
  leaf; the leaf certifies the key the app generated; the challenge is the app's; the chain has the shape of
  its provisioning (four certificates, five for Remote Key Provisioning, three for a software keystore), each
  issued by the next and signed by it; and every certificate between the leaf and the root is valid at the
  phone's date, but for an expired one in a factory chain, which Google exempts. Like Google's verifier, it
  does not require the certificates above the leaf to be marked as CAs: the attestation certificates of the
  Pixel 2 and the Sony Xperia 10 III in Google's test data are not, and their chains are genuine.
  The date is the phone's, set by its system: a wrong date can make a sound chain look out of date, and a
  system that sets it back can make an expired one look valid, but cannot make a forged extension, another
  key, another challenge or a revoked or unknown root pass.
- **What a hooked keystore can still do.** Sign a whole chain with an attestation key that leaked and is not
  yet revoked; or pass the challenge to another phone it controls, locked and sound, and show that phone's
  answer as this one's. On the phone, no check can tell either from the truth; decision 6's check from a
  second phone, which pins what it saw, is what closes them. The README and the changelog say so.
- **Each value comes from one list only.** The parser took `rootOfTrust` and `osPatchLevel` from the
  software-enforced list, which the system writes, whenever the hardware-enforced list lacked them. Now a
  trusted environment's or StrongBox attestation is read from its hardware-enforced list alone, and a
  software attestation from its software-enforced list alone. The security level is the weaker of
  `attestationSecurityLevel` and `keyMintSecurityLevel`, as Google's verifier takes it; a precedence test
  shows the hardware list winning where both carry values, which passed before as well.
- **Encoding: never a false "locked and verified", never a false failure.** The first review asked for DER
  everywhere, and the parser became strict. The second asked to decide each difference from Google's
  verifier, which reads through BouncyCastle, by that rule instead: once the chain check holds, every byte is
  signed by the phone's attestation key for this request, so leniency lets nothing unsigned through, while
  strictness could only fail a sound phone. So the parser reads lengths in any definite form, a BOOLEAN as
  false only when 0x00 (a genuine chain in Google's test data writes `deviceLocked` as 0x01, and BER and
  BouncyCastle read any other byte as true), entries in any order, and treats a malformed or contradicting
  `rootOfTrust` or patch level as absent rather than failing the whole extension. It stays as strict as
  BouncyCastle on tag numbers and integers, and as Google's verifier on the KeyDescription's eight fields.
  Where it differs from Google's verifier, it says so in its documentation: it refuses the indefinite
  length form (skipping such an element would need descent driven by the input, and no keystore writes it);
  it treats two different copies of an entry as absent, where Google keeps the last; it treats every
  malformed root of trust as absent, where Google fails on some; and it skips tags it does not know, where
  Google fails. All nine chains of the corpus below are strict DER but for that one BOOLEAN.
- **The corpus of real chains.** The maintainer approved the download of 16 files of Google's test data
  (`android/keyattestation` at c391708, Apache-2.0), recorded in `core/engine/testdata/keyattestation/SOURCE`
  with each file's SHA-256: chains from a Pixel 2, a Pixel XL, a Pixel 3's StrongBox, a Sony Xperia 10 III, a
  Pixel 8a, a Pixel 9 Pro and a Pixel 9, and two samples Google keeps as invalid. The Rust tests compare
  every value the parser reads with the values Google's library decodes, on all seven; the JVM tests run the
  whole chain check on all nine. One invalid sample is a genuine chain whose `deviceLocked` is 0x01, read as
  true; the other's leaf was edited, and its chain is broken.
- **Every field of decision 5, and what the app shows of it.** The parser reads the challenge, the whole root
  of trust (`verifiedBootKey`, `verifiedBootHash`), `osVersion`, and the OS, vendor and boot patch levels (as
  `YYYYMM`, from the six or eight digits keystores write; anything else is absent).
- **Tests.** The truncation test cut only the outer element; the tests now cut every element at every byte,
  about 2,500 cases, and a parser that read a missing boot state as verified fails them. Two extensions encoded
  by OpenSSL test the tests' own encoder. The fuzz target also puts its bytes inside a valid extension, as each
  list and as a root of trust, and checks that the list the parser does not read never changes its result and
  that a malformed root of trust never fails the rest. The second review's surviving mutants are pinned
  (lengths `82 00 a1` and of exactly 128 bytes, tag numbers 30 and 31, each boot state, the types of
  `uniqueId` and `verifiedBootKey`), and the record that carries the result across JNI is tested from both
  sides.
- **Smaller.** The depth limit could not be shown by a failing test, since nothing reached it: nested
  SEQUENCEs put at every position the parser reads never produced it. It is gone, and the documentation names
  the real bound. Errors say whether a field was missing or data followed the last one.

What the app shows, in each case:

- a check that failed or could not be read: "Hardware check failed" (medium) and its own line. Android
  requires attestation of phones launched with Android 8 or later; the keystore of an older one on Android 10
  attests in software, as the Pixel XL in the corpus, launched with Android 7, does; and no public API says
  which version a phone launched with. So a failure counts everywhere;
- a forged attestation (another key or challenge, or a certificate below the attested key): "Hardware check
  tampered with" (high), and nothing else it says, not even its patch level;
- a software attestation: "No hardware check available" (low), nothing about the bootloader, and its patch
  level as "Security patch, as the system states it";
- a hardware attestation without a root of trust in its hardware list: "Hardware check incomplete" (medium);
- a chain to another root, or a broken one: "Hardware check not confirmed" (medium); a revoked key: "Hardware
  check key revoked" (high); a certificate not valid at the phone's date: "Hardware check out of date"
  (medium);
- a locked phone whose boot state is self-signed: "System signed with its own key" (medium, as decision 7
  rates a key that matches no published one, since the dataset of published keys does not exist yet), and
  its verified boot key, to compare with the one its project publishes;
- a vendor patch level more than a year old: "Vendor security updates are old" (medium), and the vendor's
  level beside the system's where it lags behind;
- otherwise, with Google's root, a locked bootloader and a verified boot: the "locked and verified" line.

Decoded but not shown, with the reason: `verifiedBootHash`, which nothing on the phone could be compared with
(decision 6's check pins it); `osVersion`, until real phones show how often it differs from what the system
reports; and the boot patch level, which equals the system's on every chain of the corpus.

Still open from decisions 5 and 7: the dataset of the boot keys that systems such as GrapheneOS publish
(decision 7), which would turn the self-signed fact into a named one; a comparison of `osVersion` and the
patch levels with what the system reports; the check from a second phone (decision 6); and a run on real
phones of each vendor, since the corpus holds only Pixels and one Sony.
