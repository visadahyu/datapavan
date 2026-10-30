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
- Speed on the A40, measured once the scanner was wired into the app (2026-10-29): the first scan of
  all 436 apps, base APKs and splits, takes 116 seconds, two apps at a time; later runs reuse the
  results of unchanged apps and finish within seconds. A first scan that is cut short resumes where
  it stopped (160 apps were saved after 30 seconds). 58 apps contain trackers, 10 more only refer to
  some; no app was unreadable.

## Definition of done (2026-10-30)

`scripts/compare-exodus.sh` repeated the comparison on the `dp-api37-16k` emulator (Android 17),
signed in to Google Play with a test account. It was given 40 popular apps from many categories and
regions. For each app it read the latest εxodus report, installed the app from Play, and scanned
every installed APK only when the version code matched. 16 apps matched. 19 had another version:
Play served a newer build than the latest report, or a build for x86_64 with its own version code.
5 were not offered to the test account.

| App | Version | In the report | Found embedded | Found referenced only | Missed | Found besides (all referenced only, except Opera Mini) |
|---|---|---|---|---|---|---|
| Reddit | 2026.43.1 | 3 | 3 | 0 | 0 | |
| Adobe Acrobat Reader | 26.10.0.51147 | 9 | 9 | 0 | 0 | |
| DuckDuckGo | 5.300.0 | 0 | 0 | 0 | 0 | |
| WhatsApp | 2.26.42.74 | 0 | 0 | 0 | 0 | |
| Duolingo | 6.103.6 | 31 | 13 | 18 | 0 | AppMonet |
| Shazam | 16.65.0 | 2 | 2 | 0 | 0 | Facebook Login |
| MyFitnessPal | 26.43.0 | 14 | 14 | 0 | 0 | |
| Candy Crush Saga | 1.339.0.2 | 13 | 10 | 3 | 0 | 16 ad networks |
| Waze | 5.26.0.0 | 1 | 1 | 0 | 0 | |
| Viber | 29.2.0.0 | 21 | 6 | 15 | 0 | Add Apt Tr, Admost, Appodeal Stack |
| AliExpress | 8.180.1 | 7 | 7 | 0 | 0 | |
| Telegram | 13.1.1 | 0 | 0 | 0 | 0 | |
| Airbnb | 26.43 | 7 | 7 | 0 | 0 | |
| Amazon Shopping | 32.19.0.100 | 3 | 3 | 0 | 0 | |
| Opera Mini | 99.7.2254.2684 | 7 | 7 | 0 | 0 | IAB Open Measurement and Pangle embedded, in a split; 6 more referenced |
| Subway Surfers | 3.70.2 | 23 | 20 | 3 | 0 | 9 ad networks |
| **16 apps** | | **141** | **102** | **39** | **0** | |

- **Every tracker in the 16 reports was found.** With the six same-version apps of 2026-10-29, the
  scan agrees with εxodus on 22 apps, which meets M3's definition of done. Three of the 16 reports
  list no tracker (DuckDuckGo, WhatsApp, Telegram), and the scan found none either.
- **What the scan finds besides is explained.**
  - Almost all of it is referenced only. Ad mediation SDKs (in games, Viber and Duolingo) name the ad
    networks they can work with, and those networks' classes are not in the app. The scan reads
    every type an app's code refers to, which is more than the declarations that εxodus reads, so
    it shows more of them. The app lists these apart, as "referred to, not included".
  - Opera Mini's two embedded extras are in an APK split, as in the first run with Opera.
- **εxodus counts references as trackers too.** 39 of the 141 trackers in these reports are only
  referred to in the app's code. In Duolingo that is 18 of 31, and in Viber 15 of 21. Datapavan
  keeps telling the user which trackers an app contains and which it only names.
