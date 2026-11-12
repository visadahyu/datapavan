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
