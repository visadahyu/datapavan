# Public keys

The public halves of Datapavan's three keys. The maintainer made the keys on 2026-11-06 on a live
system with networking off. The secret halves stay on encrypted offline media: they are never in this
repository, on an online computer or in CI ([docs/RELEASE.md](../docs/RELEASE.md), ADR 0024). The keys
are separate, so that a leak of one cannot forge what the others sign.

## The APK signing certificate

[datapavan-release.pem](datapavan-release.pem): RSA 4096, `CN=Datapavan, O=Visadahyu`, valid until 2076.
Every genuine copy of Datapavan is signed with this key. The SHA-256 fingerprint of the certificate is:

```
FA:6A:24:04:2A:BC:AC:8B:
D0:09:01:10:F7:04:FF:EF:
E7:DA:D3:AD:F5:DB:38:FB:
07:38:90:AB:4C:B1:FA:84
```

To read it from this file:

```sh
openssl x509 -in keys/datapavan-release.pem -noout -fingerprint -sha256
```

## The data-signing key

[datapavan-data-1.pub](datapavan-data-1.pub) signs data packs, and `data/PACK` pins it
([docs/DATA-PACKS.md](../docs/DATA-PACKS.md#keys)):

```
RWSw7mCAus7/cGyV88xK46P7J51/oMhXNl/V6+25UHD888smCReEQdRB
```

```sh
signify-openbsd -V -e -p keys/datapavan-data-1.pub -x datapavan-data-N.pack -m /dev/null
```

## The release notes key

[datapavan-notes-1.pub](datapavan-notes-1.pub) signs each release's notes, which name the commit, the
APK's SHA-256 and the certificate's fingerprint:

```
RWQ/vFWwVJPevJW9d5d398A2Pp/MTT0TkpvR+7gsVitHUETHkb92YCvk
```

```sh
signify-openbsd -V -e -p keys/datapavan-notes-1.pub -x notes.txt.sig -m /dev/null
```

A first set, made on 2026-11-05, was lost before anything was signed with it, because its backup was never written. Its public
keys remain in this repository's history. Nobody holds their secret halves, so a copy signed with them is not genuine.

`scripts/check-keys.py`, part of `scripts/check.sh`, fails if the fingerprint or a key in the README, the
website, the F-Droid recipe, `data/PACK` or `data/app-signers` differs from these files.
