# Public keys

The public halves of Datapavan's three keys. The maintainer made the keys on 2026-11-05 on a live
system with networking off. The secret halves stay on encrypted offline media: they are never in this
repository, on an online computer or in CI ([docs/RELEASE.md](../docs/RELEASE.md), ADR 0024). The keys
are separate, so that a leak of one cannot forge what the others sign.

## The APK signing certificate

[datapavan-release.pem](datapavan-release.pem): RSA 4096, `CN=Datapavan, O=Visadahyu`, valid until 2076.
Every genuine copy of Datapavan is signed with this key. The SHA-256 fingerprint of the certificate is:

```
FF:DF:39:72:91:80:12:31:
AB:2D:81:20:8D:F8:AD:7E:
52:03:1D:3D:1E:D8:FD:62:
11:C3:29:FC:5A:14:CE:2D
```

To read it from this file:

```sh
openssl x509 -in keys/datapavan-release.pem -noout -fingerprint -sha256
```

## The data-signing key

[datapavan-data-1.pub](datapavan-data-1.pub) signs data packs, and `data/PACK` pins it
([docs/DATA-PACKS.md](../docs/DATA-PACKS.md#keys)):

```
RWTvKNnePsEUaJrL7VYOD589PmfVSfBApZ8LtNM12T3GtlQemrgp4cf0
```

```sh
signify-openbsd -V -e -p keys/datapavan-data-1.pub -x datapavan-data-N.pack -m /dev/null
```

## The release notes key

[datapavan-notes-1.pub](datapavan-notes-1.pub) signs each release's notes, which name the APK's SHA-256
and the certificate's fingerprint:

```
RWSV0XJ7jyVe9uaZq/mrqIHyhE6cGIaSzN0wg0DA7nlVsNqZ8jZ8pb1q
```

```sh
signify-openbsd -V -e -p keys/datapavan-notes-1.pub -x notes.txt.sig -m /dev/null
```

`scripts/check-keys.py`, part of `scripts/check.sh`, fails if the fingerprint or a key in the README, the
website, the F-Droid recipe, `data/PACK` or `data/app-signers` differs from these files.
