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

**The attestation parser after an independent review (2026-11-17, decision 5).** The review of
`core/engine/src/attestation.rs` found six faults; each was shown by a test that failed before its fix.
- **Each value comes from one list only.** The parser took `rootOfTrust` and `osPatchLevel` from the
  software-enforced list, which the system writes, whenever the hardware-enforced list lacked them, and
  nothing downstream could tell. Now a trusted environment's or StrongBox attestation is read from its
  hardware-enforced list alone, and a software attestation from its software-enforced list alone, never
  from the other. The security level is the weaker of `attestationSecurityLevel` and
  `keyMintSecurityLevel`, as Google's verifier takes it. What the app shows:
  - a software attestation: "No hardware check available" (low), and nothing about the bootloader; the
    patch level it states is shown and checked for age, as the system's own word;
  - a hardware attestation with a root of trust in its hardware list: as before, the "locked and
    verified" line only with Google's root, or the bootloader and boot findings;
  - a hardware attestation without one, whatever its software list says: "Hardware check incomplete"
    (medium), since a sound trusted environment always states both, and no "locked and verified" line;
  - a hardware attestation without a patch level in its hardware list: no patch line and no finding about
    its age;
  - an extension the parser rejects: "The hardware check is not available on this phone."
- **DER.** The parser read lengths, tag numbers and integers that were not in their shortest form,
  INTEGER and ENUMERATED in each other's places, any non-zero BOOLEAN as true, and more elements than
  the schema allows. It now requires DER for every element it reads, so that it and a strict verifier
  cannot read the same bytes in two ways. Two tolerances follow Google's reference verifier,
  `android/keyattestation`, for encodings whose meaning is not in doubt: `deviceLocked` as 0x01 reads as
  true, as that verifier accepts it with a sample chain of four certificates (commit 2462d01); and the
  entries of an authorization list may come in any order, with the entries the audit does not use left
  unread, as that verifier checks the order only on request (commit a6e9faf). A `rootOfTrust` or
  `osPatchLevel` that appears twice in the list read is an error. Real devices' extensions have not yet
  been checked against these rules: a device whose keystore writes other non-DER encodings gets "not
  available" until a tolerance with its evidence is added.
- **Tests.** The truncation test cut only the outer element; the tests now build each extension as a
  tree and cut every element at every byte, about 2,500 cases. Two extensions encoded by OpenSSL from
  the published schema test the parser and the tests' own encoder against an encoder that shares no
  code with them. The fuzz target also puts its bytes inside a valid extension, as each list and as a
  root of trust, and checks there that a list the parser does not read never changes what it returns.
- **Smaller.** The depth limit, which no input could reach, is gone, and the documentation names the
  real bound; errors say whether a field was missing or data followed the last one.

Still open from decision 5: the corpus of real chains checked against Google's reference library, which
needs a download that the maintainer has not yet approved (`android/keyattestation`'s `testdata/`,
Apache-2.0); and the comparison of the challenge, the first-occurrence rule, the validity of Remote Key
Provisioning certificates, and the rest of the root of trust and the patch levels.
