# Data packs

Datapavan has no network permission, so its data reaches the phone in two ways only: inside the APK,
and in **data packs** that the user imports as files. A pack holds every dataset under [`data/`](../data):
the εxodus tracker signatures, the attestation roots and revocation list, and later the project's own
lists. Each dataset keeps its `LICENSE` and `SOURCE` files.

Every pack is signed with the project's data-signing key. Anyone can get a pack from the release page with
any browser, from a mirror, or from another phone over Bluetooth, a messenger or a USB stick, and the
phone still knows whether the project made it. The reasons are in [ADR 0015](decisions/0015-dataset-licences.md)
(decision 11), and the format and trust rules are decided in
[ADR 0017](decisions/0017-data-pack-format.md).

## Format

A pack is a file in the **embedded-signature format of OpenBSD's `signify`**, the format that
`signify -S -e` writes:

```
untrusted comment: verify with datapavan-data.pub
RWSaKiYnaFJUiXmnLJxTebUYXxhrpLboOAb9haqCTHF8afIDvkT00q+m2bIesJul5wlDiVT2/BGHYLBvnd39jCotIHt9qL6W0gE=
datapavan-data-pack 1
sequence 2
date 2026-10-30
key RWSaKiYnaFJUifZRfEPxHyXNGoBK8ZRt44B2pqafPP6DCPmmnxA7fyPR
file exodus/LICENSE 1209
file exodus/SOURCE 418
file exodus/trackers.tsv 48463
end
<the bytes of each file, in the order listed, with nothing between them>
```

- **Line 1** is a comment that nothing checks.
- **Line 2** is base64 of `Ed`, the eight-byte number of the signing key, and the 64-byte Ed25519 signature
  over everything after line 2: the **payload**.
- **The payload** starts with a header of text lines, each ending in `\n` and in this order:
  - `datapavan-data-pack 1`, the format and its version;
  - `sequence N`, a number from 1 to 2³¹−1 that is raised by one for every published pack;
  - `date YYYY-MM-DD`, the day the pack was made;
  - `key K` lines, the public keys that may sign later packs (the second line of a `signify` public key
    file), at most 16;
  - `revoked K` lines, keys that must no longer be trusted, at most 16;
  - `file PATH SIZE` lines, at most 256, with paths in strictly ascending byte order;
  - `end`.

  The files follow the header, and their sizes must add up to the rest of the payload exactly.

The reader is strict, so every pack has one canonical form:
- Numbers have no leading zeros.
- Base64 has no spare bits.
- A path is plain names of letters, digits, `.`, `_` and `-`, separated by `/`, at most 128 bytes. No
  name is empty or starts with `.`.
- The header is at most 64 KiB and the whole pack at most 32 MiB.

Anything else is refused. A pack in a later format (`datapavan-data-pack 2`) is refused with a message
that a newer version of the app is needed.

The **APK's own copy** is the bare payload, `assets/data/bundled.payload`, which the APK's signature
already covers. `BundledDataTask` in `android/app/build.gradle.kts` builds it from `data/`. The header
values come from [`data/PACK`](../data/PACK), and files are sorted by path, so the same data always gives
the same bytes.

## How the app checks a pack

The Rust engine (`core/engine/src/datapack.rs`) reads every pack, and it is fuzzed like the other parsers.
The signature library is also tested against Project Wycheproof's Ed25519 vectors
(`core/engine/testdata/wycheproof`).
1. **Signature first.** It finds the trusted keys whose number matches the signature's, and checks the
   Ed25519 signature over the whole payload (the `ed25519-compact` crate). Nothing in the payload is read
   until the signature matches.
2. **Then the header**, by the rules above.
3. **Then the app's rules** (`DataPackRules` in the app):
   - The pack must be newer than the one in use. An old pack with known errors cannot be brought back,
     and replaying a pack changes nothing.
   - **Trusted keys** are those named by the APK's pack (the pinned keys) and by the imported pack in
     use, minus every key either one revokes.
   - For each imported pack the app records its **chain**: the key that signed it and the keys that
     introduced that key, back to a pinned one.

**Fingerprint.** The *Data sources* screen shows the SHA-256 of the payload in use. The same fingerprint
is published with every pack, and anyone can compute it: `tail -n +3 datapavan-data-N.pack | sha256sum`.
A pack that someone signed with a stolen key and gave to a few people matches no published fingerprint.

**Old data.** The app cannot know whether a newer pack exists, or whether someone keeps it from the
user. When the pack in use is more than six months old, the overview says so and links to the *Data
sources* screen.

An imported pack is stored as it arrived, in app-private storage that backups exclude, and its signature
is checked again every time the app loads it. After an app update, an imported pack stays in use only
when all of these hold:
- it is newer than the APK's pack;
- its chain starts at a key that the new build still pins;
- the chain contains no key the new build revokes.

Otherwise the app uses its own pack again.

## Keys

**The data-signing key is created and kept offline by the maintainer.** Until it exists, `data/PACK`
names no key, and release builds refuse every import with a message that says so.

```sh
# On a computer that is never online, with signify (Debian: signify-openbsd):
signify-openbsd -G -c "Datapavan data-signing key 1" -p datapavan-data-1.pub -s datapavan-data-1.sec
```

The secret key is encrypted with a passphrase (bcrypt-pbkdf). It stays on the offline computer and its
backup media, and never enters the repository or CI. The public key's second line goes into `data/PACK`
as a `key` line, and the whole `.pub` file is published with the releases, so that anyone can check a
pack with `signify` itself.

**Rotation.** A new key is announced in a pack signed by the old one, which names both keys. The next
app release pins the new key, and a later pack can revoke the old one. A **compromised** key cannot be
handled by a pack alone, because whoever holds it can sign packs too. An app update revokes the key: the
new build lists it in a `revoked` line, and drops every imported pack whose chain contains it. The
build's own data then replaces those packs, so a fake pack with a very high sequence number cannot block
real updates.

**The test key** in `scripts/testdata/` is public, secret half included. **Debug builds trust it**, so
that imports can be tested on emulators and phones (`scripts/verify-datapack.sh`), and **release builds
never do**. `scripts/datapack-test.py` signs packs with it. It uses OpenSSL, because CI has no
`signify`, and its output is byte for byte what `signify -S -e` writes, since Ed25519 signatures are
deterministic. The engine's test pack, `core/engine/testdata/test.pack`, was signed by `signify`
itself.

## Publishing a pack

1. Update the datasets with their `update.py` converters and review the diff (ADR 0015).
2. In `data/PACK`, raise `sequence` by one and set `date`. Commit.
3. Build the payload: `cd android && ./gradlew :app:dataPayload`. It is written to
   `android/app/build/datapack/data/bundled.payload`; the release APK built from the same commit carries
   the same bytes.
4. Carry the payload to the offline computer and sign it:
   `signify-openbsd -S -e -s datapavan-data-1.sec -m bundled.payload -x datapavan-data-N.pack`.
5. Check it on a second computer with the published public key:
   `signify-openbsd -V -e -p datapavan-data-1.pub -x datapavan-data-N.pack -m /dev/null`.
6. Publish `datapavan-data-N.pack` with the release, together with its fingerprint
   (`tail -n +3 datapavan-data-N.pack | sha256sum`), and import it on a test phone with a release build.
   The fingerprint on the *Data sources* screen must match.

## What a pack does not do

- **It cannot run code or change the app.** It holds data that the app's own parsers read.
- **It does not hide what it contains.** Packs are public, as the ODbL requires for εxodus data, and
  signing restricts no one's rights to the data (ADR 0015).
- **It does not reveal who uses it.** The app never fetches packs, so nobody learns which phones import
  which pack (ADR 0016).
