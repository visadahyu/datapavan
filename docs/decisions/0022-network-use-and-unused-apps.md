# 0022. Network use per app and apps not opened, from Android's own records

- Status: Accepted
- Date: 2026-10-31
- Decided by: mehdashti

## Context
M4 adds two facts for the remediation plan: how much data each app sends and receives, and which apps
have not been opened for a long time. ADR 0014 already allows usage access (`PACKAGE_USAGE_STATS`) for
this; the manifest does not request it yet.

Both facts come from records that Android keeps anyway. The API documentation of SDK 37 and a reading
of the Android 17 emulator and the A40 (Android 11) show:
- **Network use** (`NetworkStatsManager`) is counted per UID, not per package. It is split by mobile and
  Wi-Fi, received and sent bytes, and two states: *foreground*, which in AOSP covers an app on screen
  and one running a foreground service with its notification, and *default*, which is everything else,
  so background use. A summary query adds up a period; per-app data is kept in two-hour buckets on both
  devices. AOSP keeps it for 90 days; the A40 still had 200 days. Mobile use is read for all SIMs
  together, because an ordinary app cannot read the subscriber ID; Settings shows each SIM separately.
- **When the numbers are written.** The system writes its counters about every 30 minutes, whenever
  about 2 MB more has been used, and when an app opens a query. (A first reading said that queries
  did not trigger a write; those were the system's own queries. Datapavan's and Settings' do, as the
  build showed on 2026-10-31.)
- **Who is counted.** Several packages can share one UID; Android has a single count for all of them.
  Traffic that apps send through a local proxy app counts under the proxy app, because the proxy opens
  the connections. AOSP moves traffic through a VPN service back to the apps that made it, and leaves
  the VPN app its own overhead. Only the current profile is visible. Tethering, removed apps and the
  system have counts of their own. The documentation promises those three only to device owners,
  profile owners and carrier apps.
- **Use of apps** (`UsageStatsManager`) gives, per package, the last time it was visible and the last
  time it ran a foreground service. Android keeps daily records for about 10 days, weekly for 4 weeks,
  monthly for 6 months and yearly for 3 years; the A40's files match. The same permission also opens
  an event stream that says which app was opened when.
- **Android's own protection is hidden.** Since Android 11 the system resets the permissions of apps
  not used for about three months, and since Android 12 it also puts them to sleep. It judges use by a
  hidden timestamp that covers every component of the app. Ordinary apps can read neither that
  timestamp nor whether an app is exempt or asleep. The protection skips system apps, apps without a
  launcher icon and apps that target old Android versions. The reset covers runtime permissions only,
  not special access such as accessibility or a notification listener.
- **Some apps work without ever being opened:** keyboards, accessibility services, notification
  listeners, VPNs, widgets, wallpapers and the default SMS app. Saying they are not opened says little.

## Decision
1. **Usage access is asked for, explained, and never required.** One screen says what the access
   allows: seeing which apps were opened and when, and their data use. It also says what Datapavan
   reads and that nothing is kept. Then it opens the system's usage access page. Without the access, the
   network and "not opened" sections say what is missing, and everything else works. Datapavan lists
   itself among the holders of usage access, like any other app.
2. **Only totals are read, and nothing is kept.** Datapavan reads summaries for a period
   (`querySummary` for mobile and Wi-Fi, `queryAndAggregateUsageStats`). It never reads the event
   stream, keeps no history of its own and writes none of these numbers to storage. They exist in
   memory while the audit is on screen (ADR 0016), and the app has no network access to send them
   anywhere.
3. **Periods are fixed and named.** The default is the last 30 days, and the last 7 days can be
   chosen. Each screen shows the dates. Datapavan cannot read the billing cycle that the user set in
   Settings, so it never claims to match it; mobile use is for all SIMs together.
4. **What an app page shows:**
   - received and sent bytes, for mobile and for Wi-Fi;
   - how much of it Android counted as background;
   - that the numbers come from Android's own count. (This line first said the time of the
     system's last count; the build showed on 2026-10-31 that a query brings the count up to date,
     so there is no lag to show.)

   Notes:
   - where several packages share the UID, the page says so, names them and shows the shared total.
     It never splits the total;
   - the page of a proxy app says that traffic of apps routed through it counts there;
   - the overview lists tethering, removed apps and the system as Settings does, where Android shows
     them.

   Background use is a fact, not a verdict. Push messages, sync and backups happen in the background.
5. **"Not opened for N days" is a fact; "unused" is Android's word.** An app is not opened in a period
   when Android records no visible use and no foreground service in it. The period starts at the later
   of the app's install and the oldest record. Datapavan never calls an app unneeded or safe to remove,
   and never says whether Android has reset or put it to sleep. For apps that work without being
   opened (as listed above), the page says that the fact says little.
6. **The remediation plan gets what Android's protection skips.** M4 lists apps not opened for 90 days
   or more that still hold one of these:
   - a dangerous permission;
   - special access;
   - VPN permission;
   - background data use in the last 30 days.

   Preinstalled system apps are included. Each row hands off with one tap to the app's settings page,
   and on Android 12 and later also to the system's page of unused apps. The order and the cards
   belong to M5.

## Consequences
- The manifest requests `PACKAGE_USAGE_STATS`, as ADR 0014 already says, and the privacy policy
  explains it.
- Before M4 is done, a spike measures it on the Android 17 emulator and the A40:
  - for the ten apps with the most use on each network type, Datapavan's numbers must be within 5 % of
    Settings for the same dates, as DESIGN.md requires;
  - it checks the counts for tethering, removed apps and the system;
  - it checks traffic through a VPN and through a local proxy;
  - it checks the lag after a query;
  - it checks the usage access page when Datapavan was installed from a file, where Android 13 and
    later restrict some settings.

  From the A40 only the differences are recorded, never app names or amounts.
- The v0.2 cross-check of Android's count against the VPN's own count (DESIGN.md) builds on this
  reader.
- Accepted limits:
  - no per-SIM numbers;
  - no profile other than the current one;
  - no fine timeline: buckets are two hours long;
  - no view of Android's own hibernation state.
- Uninstall hand-offs (`REQUEST_DELETE_PACKAGES`, REMEDIATION.md) need their own change to ADR 0014 in
  M5.
