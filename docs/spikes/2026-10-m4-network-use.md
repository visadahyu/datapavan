# Spike: network use per app compared with Settings (M4)

- Date: 2026-10-31
- Question: do the numbers that Datapavan reads with usage access (ADR 0022) match the data-usage
  screen in Settings within 5 %, as M4's definition of done asks, and what does Android's counting
  mean for the pages?

## Method

Settings' per-app list of one network type was opened by hand, and `scripts/compare-usage.sh` read
its largest rows, opened each app's page in a debug build of Datapavan and read the same network type
there. Settings' periods differ from Datapavan's: a billing month for mobile data, and four weeks for
Wi-Fi on both devices. Debug builds therefore take the period's length (and, for a cycle that has
ended, its end) from the command line; release builds always read the last 30 or 7 days.

- **Android 17 emulator** (`dp-api37-16k`, Google Play image): all of its data is from the three
  days since it was created, inside both Settings' cycles and Datapavan's 30 days.
- **A40** (Samsung, Android 11, the lab phone): Wi-Fi over Settings' current four weeks against
  Datapavan's last 28 days. Mobile data is off on that phone. It holds personal use, so the script ran
  with `PRIVATE=1`, which prints only each row's rank and difference; no app name or amount was kept.

## Results

The ten largest rows of each list, compared after the unit fix described below:

| Device and network | App rows compared | Largest difference | Rows not compared |
|---|---|---|---|
| Emulator, mobile data (Oct 28 – Nov 27) | 8 | 0.00 % | 2 system rows |
| Emulator, Wi-Fi (Oct 3 – 31) | 9 | 0.00 % | 1 system row |
| A40, Wi-Fi (Oct 3 – 31) | 9 | 0.07 % | 1 system row |

**M4's definition of done (within 5 % of Settings) is met** on both devices. On the emulator every
size read the same as in Settings, from 3.90 GB down to 7.43 kB. A later Wi-Fi run, after the
emulator had counted new traffic, matched seven apps exactly and differed for Chrome, which the end
of Settings' period explains (below). The A40's small differences come from the edges of the period:
Settings' four weeks start at midnight, Datapavan's 28 days at the time of reading.

- **System rows** were not compared. Settings' "Android OS" and rows such as `android.media:10113` add
  up several system user IDs, while Datapavan shows the system's own ID on the overview, and removed
  apps and tethering separately. On the emulator, Settings' "Android OS" had 882 kB of Wi-Fi and
  Datapavan's "Android system" 563 kB in total.
- **Names can differ.** Settings named one app "Wallpaper & style", where the package's label, which
  Datapavan shows, is "Wallpaper and style"; its numbers agree (274 kB and 556 kB).

## What the build showed

- **Units differ by vendor.** AOSP's Settings, on the emulator, counts in steps of 1,024 under the
  names kB, MB and GB; with Android's public formatter, which steps by 1,000, the emulator's totals
  read 39.19 MB and 4.56 GB against Settings' 37.39 MB and 4.26 GB, exactly 1.024² and 1.024³ more.
  Samsung's Settings, on the A40, steps by 1,000: with steps of 1,024, Datapavan's numbers there were
  4.4 to 4.7 % lower for every row in megabytes and 6.7 % for the one in gigabytes, within a few
  tenths of the ratio of the steps (4.6 and 6.9 %). Datapavan now uses the step of the phone's
  Settings (`ui/DataSize.kt`): 1,000 on Samsung phones, 1,024 elsewhere until other vendors are
  measured.
- **Traffic made for an app counts under that app.** The emulator listed 3.05 MB of Wi-Fi under
  Datapavan, which cannot open a connection. The bytes fall in the two hours in which the first build
  was installed (2026-10-28), and that build still let AndroidX's EmojiCompat ask Google Play services'
  font provider for an emoji font; the provider was removed from the manifest the next morning. The
  download was most likely charged to the app that asked for it. The pages therefore never treat an
  app's count as proof that the app itself opened a connection.
- **No lag.** The system writes its counters about every 30 minutes, when about 2 MB more was used,
  and when an app opens a query. A first reading of `dumpsys netstats` found no write on opening
  (`OPEN_SESSION: 0` for 1,509 queries), but those were the system's own; after Datapavan's and
  Settings' queries the count rose to 387, and a write followed each time Datapavan read alone. The
  pages therefore show no lag note, and ADR 0022 was corrected twice on this point.
- **Settings' period can end before now.** Between two readings that day, 15 MB appeared for Chrome
  in the emulator's two-hour bucket that starts at 03:00 local time, hours before the readings; why
  the system placed the bytes there was not found. Settings showed 7.50 MB for Chrome and Datapavan,
  counting up to the moment of reading, 14.96 MB. With its period ended at 04:00, inside that bucket,
  Datapavan also read 7.50 MB: Settings' current four weeks end there, and Android counts a bucket
  that a period cuts in proportion.
- **Settings' own usage access page** opens for Datapavan directly on Android 17
  (`ACTION_USAGE_ACCESS_SETTINGS` with the package), and the overview reads the numbers as soon as the
  user returns.
- **Installed from a file, the switch is locked.** Datapavan was installed on the emulator through
  the system package installer from a file in Downloads (`packageSource` 3, a local file; Play
  Protect's offer to upload the app for a scan was declined). Android 17 then greys out the usage
  access switch and, when tapped, says that the app was denied access to a restricted permission.
  After "Allow restricted settings" in the app's info menu, the switch works. Releases on GitHub are
  installed this way, so the access card now explains the step and opens the app's info when the app
  was installed from a file (Android 13 and later). Installed over adb, as in CI, nothing is locked.
- **Removed apps and the system are visible with usage access.** The documentation promises these
  lines only to device and profile owners and carrier apps, but on Android 17 the overview shows
  "Android system", and after the first emulator build of Datapavan was uninstalled for the test
  above, its 3.05 MB moved to "Removed apps".
- **Persian.** Lines that join an app's name and a size ("Google: 15.32 MB") were reordered in
  right-to-left text; names and sizes are now wrapped in first-strong isolates (`ui/Bidi.kt`).

## Not checked yet

- Traffic through a VPN service and through a local proxy app, which needs a VPN or proxy app on the
  emulator.
- Whether Android 13 to 16 also lock usage access for apps installed from a file.
- Android 10, mobile data on a Samsung phone, and phones of other vendors.
