# Spike: tracker matching compared with εxodus reports (M3)

- Date: 2026-10-29
- Question: does the M3 scanner (`core/engine/src/dex.rs`, `core/engine/src/trackers.rs`, signatures in
  `data/exodus/trackers.tsv`) find the trackers that εxodus reports for the same apps, and where it
  differs, why?

## Method

22 apps were pulled from the A40 lab phone with `adb pull`: browsers, messengers, media, tools and
VPN apps, from Google Play and from Samsung. Each app's DEX files were scanned with
`cargo run --release --example scan_trackers`. For six apps every APK split was pulled as well,
because Android installs many apps as a base APK plus splits. The result was compared with the
app's latest public report on reports.exodus-privacy.eu.org, read on 2026-10-29.

The scanner reports two kinds of finding:

- **Embedded:** a class that the app itself defines matches a signature, so the tracker's code is in
  the app.
- **Referenced only:** the app's code refers to a matching class but does not contain it, for
  example an optional integration that is used only if the SDK is present.

εxodus counts both: it searches the type names in `dexdump`'s listing, which includes the classes an
app defines and the types in their declarations.

## Results

19 of the 22 apps have an εxodus report; 6 of those reports are for the same version as the phone's.

| | Trackers in εxodus reports | Found embedded | Found referenced only | Not found |
|---|---|---|---|---|
| Same version (6 apps) | 8 | 7 | 1 | 0 |
| Other versions (13 apps) | 74 | 66 | 3 | 5 |
| All (19 apps) | 82 | 73 | 4 | 5 |

- **Same version:** every tracker that εxodus reports was found. One (Google Crashlytics in Opera) is
  only referenced in the app's DEX files.
- **Not found:** all five are in apps whose report covers another version (Edge 155 against 150 on
  the phone, MX Player 2.13 against 3.4, Istanbulkart 3.1 against 6.1).
- **Found, not in the report:** the scanner found more trackers in apps that load code from APK
  splits. Opera's splits add IAB Open Measurement and Pangle, and the voice recorder's splits add
  Facebook Ads. εxodus analyses the APK it downloads, which does not hold every split that a phone
  installs.
- **No report:** three apps have no εxodus report. In two of them the scanner found Google
  Firebase Analytics, AdMob and Crashlytics.

## What this changes

1. **Scan every APK of an app:** the base APK and its splits (`ApplicationInfo.splitSourceDirs`).
   Scanning only the base APK missed three embedded trackers in two of the six apps checked.
2. **Show embedded and referenced trackers apart:** "contains" is evidence that the code is on
   the phone; "refers to" is weaker and is shown as such.
3. **M3's definition of done needs a precise wording:** the scanner agrees with εxodus on every
   tracker that εxodus reports for the same version, counting referenced ones. Every other
   difference is explained, by splits or by version. Results that only match on versions are not
   a fair test, so the final check uses 20 apps whose installed version has an εxodus report.

## Open

- Signatures with a literal `-` (one, Backtrace) can never match a Java class name; εxodus has the
  same limitation. To be reported upstream.
- Speed on the A40, where unpacking the DEX files is the slow step: measured when the scanner is
  wired into the app.
