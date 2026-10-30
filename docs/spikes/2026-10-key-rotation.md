# Spike: what Android reports for an app whose developer rotated its signing key (M3)

- Date: 2026-10-30
- Question: when a developer rotates its signing key with APK Signature Scheme v3.1, what do Android's
  `SigningInfo` fields show on old and new versions of Android, and does the list of official
  certificates (`data/app-signers`, ADR 0018) still recognise a genuine copy on both?

## Method

The test fixture app (`scripts/fixture-app`) was signed with two throwaway RSA keys, A and B, linked
by a signing lineage (`apksigner rotate`). The rotation was targeted at Android 13 and later
(`apksigner sign --lineage … --rotation-min-sdk-version 33`), as Google recommends for v3.1.

- `apksigner verify --print-certs --min-sdk-version 29 --max-sdk-version 37` shows a v3.0 signer with
  key A for API levels 24 to 32, and a v3.1 signer with key B from API level 33.
- `apksigner lineage --print-certs` shows A then B.

The APK was installed on the `dp-api30` emulator (Android 11) and the `dp-api37-16k` emulator (Android
17), and `dumpsys package` showed what the package manager recorded. The collector's reader
(`apk_certificates` in `data/app-signers/update.py`) was run on the same APK.

## Results

| | Current signer | Signing history |
|---|---|---|
| Android 11 | A | none |
| Android 17 | B | A, B |

`SigningInfo.getApkContentsSigners()` returns the current signer, and `getSigningCertificateHistory()`
the history. Datapavan's collector reads both A and B from the APK.

## Consequences

- **Every key a phone might see must be on the list.** A copy whose developer rotated its key looks
  different on old and new phones. If the list held only the developer's new key, a genuine copy on
  Android 12 or older would carry only the old key, with no history. It would be "key not known yet",
  or a false "modified" if the key set were closed. The collector therefore records every signer
  that `apksigner` reports across Android 10 to 17, and the lineage. Signal's two published keys are
  both on the list.
- **Matching any entry in the history is right.** On Android 13 and later, an app keeps its old key in
  its history. Datapavan's rule (ADR 0018) accepts a match on any entry, and says when only an older
  key matched.
- **Not seen yet: hybrid signing (APK Signature Scheme v3.2).** Google Play's 2026 "quantum-ready"
  hybrid signing adds an ML-DSA key for Android 17. `apksigner` 37.0.0 cannot produce such a
  signature, but it reports whether one verifies. None of the 23 Play copies read on Android 17 on
  2026-10-30 carries one (below). The collector records the schemes that verify for each Play copy
  in `data/app-signers/play.tsv`, so the first one will show there.

## A real rotation in a Play copy (2026-10-30)

`data/app-signers/from-play.sh` installed the listed apps from Google Play on the `dp-api37-16k`
emulator (Android 17) and copied their APKs. Hiddify's Play copy carries two signers:

| Signer | For API levels | Certificate |
|---|---|---|
| v3.0 | 24 to 32 | `74a3e9f9…`, a key Google generated for Play App Signing (`CN=Android, O=Google Inc.`) |
| v3.1 | 33 and later | `454bf1f6…`, the developer's own key, the one on its GitHub releases |

The lineage runs from Google's key to the developer's. The developer moved its Play copy to its own key,
targeted at Android 13 and later. On the emulator, Android 17 reports the developer's key as current
and both keys in its history, and Datapavan calls the copy genuine and signed by its developer. A phone
with Android 12 or older sees only Google's key, which the list now also holds, so the copy is
genuine there too. This is the case the spike above predicted, in a real app: a list holding only
the developer's key would have called the copy on older phones "key not known yet".

Signal's Play copy carries its two published keys the same way (v3.0 and v3.1). The other 21 copies
have one signer, with APK Signature Scheme v3 (19) or v2 (Briar, Orbot).
