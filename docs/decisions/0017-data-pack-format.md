# 0017. Data packs in signify's format, checked with ed25519-compact

- Status: Accepted
- Date: 2026-10-30
- Decided by: mehdashti

## Context
ADR 0015 (decision 11) decided that datasets travel as signed packs: the app checks an Ed25519 signature
with a pinned key before it parses anything, refuses older packs, and a new key is announced in a pack
signed by the old one. It left open the file format, the signing tool, the library that checks
signatures, and what happens when a key is replaced or stolen.

The constraints:
- **People must be able to check a pack without the app.** "Check every claim yourself" is a principle,
  and packs travel through messengers and mirrors that nobody controls.
- **The signing key must be easy to keep offline**, encrypted, with a tool that is packaged for common
  systems.
- **The Rust engine has had no dependencies.** CONTRIBUTING.md allows a new one only after discussion,
  and the licence policy in `core/deny.toml` allows Apache-2.0, MIT and Unicode-3.0. Writing our own
  Ed25519 is not an option.
- **There is no network.** Every rule must work offline, including recovery from a stolen key.

## Decision
1. **Packs use the embedded-signature format of OpenBSD's `signify`** (`signify -S -e`): a comment line, a
   base64 signature line, then the signed payload. `signify` is small, OpenBSD signs its own releases with
   it, it is packaged for Debian, Ubuntu, Arch and macOS, and it keeps the secret key encrypted with a
   passphrase. Anyone can check a pack with `signify -V -e` and the published public key. minisign was
   considered: it hashes the file with BLAKE2b before signing, which the app would need as well, and it
   cannot embed the message, so a pack would need a second file or a container of our own.
2. **The payload is plain text followed by the files**: a header with the format version, a sequence
   number, a date, trusted and revoked keys, and each file's path and size; then the files. A reader can
   inspect a pack with `less`. The format is strict, so every pack has one canonical form; it is described
   in [DATA-PACKS.md](../DATA-PACKS.md).
3. **Signatures are checked with the `ed25519-compact` crate** (MIT, version 2.6, without default
   features). It has no dependencies of its own, so the engine gains one crate, not a tree. Its author,
   Frank Denis, wrote libsodium; its documentation states that its field arithmetic is formally
   verified. It refuses non-canonical signatures and public keys of small order. Its one `unsafe` block clears secret keys during signing, which the
   app never does. `ed25519-dalek` was considered: it is the most widely used Rust implementation, but
   it brings about fifteen crates, a procedural macro, and a licence (BSD-3-Clause) that the policy does
   not yet allow.
4. **A pack must be newer than the one in use** (its sequence number), so an old pack with known errors
   cannot be brought back.
5. **Trust follows a chain to a pinned key.** The keys pinned in a build are the `key` lines of
   `data/PACK`, which go into the APK's own pack. An imported pack may name more keys and revoke keys, and
   the app records which keys led to each imported pack. A build drops an imported pack whose chain does
   not start at a key it pins or contains a key it revokes. A stolen key is therefore handled by an app
   update, and a fake pack with a huge sequence number cannot block later packs.
6. **The APK carries the bare payload**, built reproducibly from `data/` by the Gradle build. The APK's
   signature covers it, and the published pack for a release is the same payload, signed.
7. **Debug builds trust a public test key** (`scripts/testdata`), so that imports are tested end to end
   on emulators in CI. Release builds never contain it.
8. **The design is measured against the attacks that The Update Framework (TUF) lists** for update
   systems:
   - **Covered:** forged and changed packs, rollback, hostile mirrors, oversized files, a stolen key used
     to set a huge sequence number, and packs for another product.
   - **Freeze attack:** someone keeps the user on old data. An app without a network cannot detect it,
     so it shows the pack's date and warns on the overview when the data is more than six months old.
   - **A pack signed with a stolen key and given to a few people:** every pack's SHA-256 fingerprint is
     published with it and shown on the *Data sources* screen, so a pack that matches no published
     fingerprint stands out. This is a small form of transparency.
   - **The signature library:** it is tested against Project Wycheproof's 210 Ed25519 vectors.
     Every valid signature must verify and every invalid one must fail, and keys of small order are
     refused.
9. **Two limits are accepted for now and revisited later:**
   - **One signature, one key:** a single stolen key is enough to sign a pack. The strongest systems
     require k of n signatures, for example two of three keys kept in different places. That is
     worth adding once the foundation has more than one key holder. The format's version number lets
     a later app release add it.
   - **The key lives on an offline computer, under a passphrase, not on a hardware token:** `signify`
     does not support tokens. This is revisited together with multiple signatures.

## Consequences
- The engine has its first dependency, which `cargo deny` checks like any other. The `Cargo.lock` change
  is reviewed.
- The maintainer generates the data-signing key on an offline computer before the first release that can
  import packs. Until then, release builds say that they cannot import, and debug builds accept only
  test packs.
- Publishing data becomes a release step: raise the sequence, build the payload, sign it offline, check
  it, and publish it (DATA-PACKS.md).
- The pack reader is fuzzed with the other parsers, and `scripts/verify-datapack.sh` checks on an
  emulator that a damaged pack is refused, a newer one is used, a repeated one is refused, and an imported
  one survives a restart.
- The format has a version number. A later format will be refused by older apps with a clear message, so
  it must be introduced in an app release before any pack uses it.
