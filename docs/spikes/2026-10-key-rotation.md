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
- **Not tested: hybrid signing (APK Signature Scheme v3.2).** Google Play's 2026 "quantum-ready"
  hybrid signing adds an ML-DSA key for Android 17. `apksigner` 37.0.0 cannot produce such a
  signature, so testing it needs an APK that Play signed this way, installed from Play on a lab
  device. That check belongs with the work on Play copies' keys.
