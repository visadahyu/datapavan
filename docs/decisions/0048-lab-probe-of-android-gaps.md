# 0048. A lab probe of where stock Android leaves privacy tools blind or exposed

- Status: Proposed
- Date: 2026-11-14
- Fulfils, once accepted: the probe app of [ADR 0041](0041-watch-visibility-and-coexistence.md), decision 2.
  Amends its words "on every Android version in CI": the runs happen on the maintainer's machine, and CI only
  builds and unit-tests the probe (decision 7).

## Context

ADR 0041 promised a probe app of the project's own to measure what an app left out of Watch's tunnel still sees.
[ADR 0046](0046-live-activity.md), decision 5, lists what Watch's view cannot see: traffic carried for an app by
another, use of data on the device, traffic between apps over loopback. Both rest on documents and on a few
device tests, not on measurements on each Android version.

These limits are not Watch's alone. Stock Android, without root, leaves every privacy tool blind to some things
and exposed in others. They change between versions, and some change within a version, since the resolver and
other parts of Android are updated as modules through Google Play system updates. A sentence that holds on
Android 10 may be false on 17. Users at risk need to know what Watch cannot see, and the project's claims about it
must be checkable by anyone.

**The behaviours to measure.** Each is stated as its public source states it, where one exists. The probe checks it on each version.

| Id | The behaviour | Public source |
|---|---|---|
| `vpn-seen` | Any app that holds `ACCESS_NETWORK_STATE`, a normal permission, sees that its network has `TRANSPORT_VPN`, finds the VPN's network in `getAllNetworks`, and reads the tunnel's interface name and addresses through `NetworkInterface`. An app left out of the tunnel (`addDisallowedApplication`) gets a network that is not a VPN, and may still see the tunnel's interface (ADR 0041) | Android's references for `NetworkCapabilities`, `ConnectivityManager` and `VpnService.Builder` |
| `appops-closed` | Android keeps a history of what each app did under each permission (AppOps), which its privacy dashboard and `dumpsys appops` read. Other apps cannot: `getHistoricalOps` is a system API behind `GET_APP_OPS_STATS`, which a user-installed app is not granted on the phone itself, and `startWatchingActive` (Android 11 and later) watches only the caller's own UID unless it holds `WATCH_APPOPS` | `AppOpsManager` reference; AOSP's `core/res/AndroidManifest.xml` |
| `proc-net` | "On devices that run Android 10 or higher, apps cannot access `/proc/net`." So no app can list the phone's sockets | Android 10's privacy changes |
| `loopback` | Traffic to 127.0.0.1 and `::1` stays on the loopback interface and never enters a VPN's tunnel. With `/proc/net` closed, no app can see who listens on the phone; it can only try ports. Android 17's local-network permission does not gate loopback (ADR 0034). The "Local Mess" disclosure of June 2025 (KU Leuven, IMDEA Networks, Radboud University) showed scripts on web pages handing identifiers to native apps listening on localhost | [localmess.github.io](https://localmess.github.io/); ADR 0034 |
| `indicators` | From Android 12, an icon shows in the status bar when an app uses the microphone or the camera, and the privacy dashboard leads with location, camera and microphone. A toast tells the user when an app reads a clip that another app put on the clipboard (Android 12 and later); from Android 10 only the focused app or the default keyboard can read the clipboard at all. No public document says that the user is told when an app reads contacts, the call log, SMS or a file | Android 12's behaviour changes for all apps and its features; Android 10's privacy changes |
| `carried-by-system` | Traffic that a system service carries for an app has the service's UID: downloads through `DownloadManager` (`com.android.providers.downloads`), push messages through Google Play services, and pages opened in a Custom Tab, which the user's browser loads. Which UID a lookup made by Android's resolver carries, plain and over Private DNS, is measured, not assumed | NetGuard's FAQ, items 8 and 66; Custom Tabs' overview |
| `short-lived` | A VPN asks Android who owns a connection while the socket exists. A socket closed before it asks has no owner left to name | PCAPdroid's FAQ, on its "unknown" app; `getConnectionOwnerUid` reference |
| `webview` | A WebView's requests carry the app's UID, whichever origin in the page asked | No source found yet; the row rests on the measurement until one is |

The table does not yet say what each Android version does; that is what the probe measures. Two of the rows are
blind spots (`appops-closed`, `indicators`), one is an exposure of Watch (`vpn-seen`), and the rest are ways in
which traffic reaches the network without Watch being able to name the app behind it.

**Several are routes by which an app can hide traffic from Watch.** Publishing them needs a rule, and so does a
finding that turns out to be new.

**The lab's apps today** live under `scripts/` (`fixture-app`, `workload-app`, `test-tool`). They are built with
the SDK's build tools only, without Gradle, and signed with a throwaway key. [LAB.md](../LAB.md) measures apps'
traffic; this probe measures the platform.

## Decision

### 1. Where it lives

- **Two apps, outside the product's build:** `lab/gaps-probe/` and `lab/gaps-fixture/`, at the repository's root,
  outside `android/`. They are built as `scripts/fixture-app` is: the SDK's build tools only, no Gradle, platform
  APIs only, no library, and a throwaway key made for each build. No module of a release can depend on them, and
  ADR 0008's dependency verification is not touched.
- **Their own names.** Their packages are `org.visadahyu.lab.gapsprobe` and `org.visadahyu.lab.gapsfixture`,
  outside the product's `org.visadahyu.datapavan`, and their labels, "Gaps probe (lab)" and "Gaps fixture (lab)",
  do not carry the product's name. They cannot be taken for an edition (ADR 0045) or for a copy of one (ADR 0024).
- **Never shipped.** They are never part of a release build, a store listing, the website's downloads or a GitHub
  release, and no signed build of them is published. The source is public; anyone builds it with the same script.
- **A check in CI.** `scripts/check.sh` lists the classes of every release APK and bundle it builds, with the
  SDK's `dexdump`, and fails if one of them is under `org.visadahyu.lab.` or has the name of a class defined under
  `lab/`. It also fails if a release manifest names a lab package.
- **The VPN under test** is Watch's debug build, with its exclusion list (ADR 0041, decision 2) and its debug
  counters. The probe changes nothing in Watch.
- **It is ADR 0041's probe.** Decision 2 of that ADR is fulfilled when `vpn-seen` has a row for every version below.

### 2. What it publishes

- **Where:** `docs/platform-gaps/`, with a README that holds the table and the method, and each run's raw output
  beside it. The versions are Android 10, 12, 14, 15, 16 and 17 on the emulator, one emulator at a time.
- **One row per behaviour and version,** with:
  - **the image's identity:** the system image's SDK package and revision, the SHA-256 of its archive,
    `ro.build.fingerprint`, the Google Play system update month that Settings shows (or "none" on an image
    without Google's modules), the resolver module's version (`pm list packages --apex-only
    --show-versioncode`), and the emulator's version;
  - **the result:** held, did not hold, or held in part, with the values measured. A behaviour that depends on
    timing (`short-lived`, the resolver's part of `carried-by-system`, and any row whose first runs disagree) is
    run many times, at least 100 trials, and its row gives the count and the rate with a 95 % interval (Wilson's),
    never one outcome;
  - **the public source,** with the date it was read;
  - **what Watch does and tells the user** (decision 3);
  - **one command** that reproduces it on a fresh emulator: `lab/run.sh <behaviour> <api> [--trials N]`. It creates an AVD from
    the named image, boots it with `-no-snapshot -wipe-data -tcpdump`, installs the probe, the fixture and Watch's
    debug build, runs the behaviour's steps, writes the raw output, then stops the emulator and deletes the AVD;
  - **the date and the probe's commit;**
  - **who replicated it:** "not yet", or the person or organisation outside the project who ran the same command
    and sent the raw output, the date and that output's SHA-256. A row is marked replicated only on raw output
    that matches.
- **A dataset, not only a page.** The rows live in `docs/platform-gaps/results.csv`, whose columns and values the
  README defines; the table in the README is written from it by a script, never by hand, and CI checks that the two
  agree.
- **Dated snapshots that can be cited.** Before the table is cited outside the repository (a report, a filing, a
  talk), its state is fixed by a signed tag `platform-gaps-YYYY-MM-DD`, and the README records the SHA-256 of
  `results.csv` and of each raw output at that tag. A snapshot holds results and code, never a build of the lab
  apps. A permanent identifier (a DOI) would need an account, and so the maintainer's word.
- **The capture is the ground truth where traffic matters.** The emulator's own capture (`-tcpdump`) sees every
  packet that leaves the virtual phone, whoever sent it. A row that rests on what Watch logged or on what the probe
  saw is checked against it, and its SHA-256 is recorded with the run.
- **What the probe does for each behaviour,** in short:
  - `vpn-seen`: reads the transport, the networks, the interfaces, the addresses, the routes and the DNS servers,
    once inside the tunnel and once left out of it;
  - `appops-closed`: calls `getHistoricalOps` and `startWatchingActive` for another app's operations, and records
    the answer; on the emulator only, it records whether `GET_APP_OPS_STATS`, granted over USB with `pm grant`,
    opens the history, which is the route of DESIGN's advanced mode;
  - `proc-net`: tries to read `/proc/net/tcp`, `tcp6`, `udp`, `udp6`, `unix` and `route`, and records the error;
  - `loopback`: the probe and the fixture, two UIDs, exchange a fixed payload over 127.0.0.1 and `::1` while Watch
    runs; Watch's counters and the capture show whether anything entered the tunnel or left the phone;
  - `indicators`: the fixture runs its reads and then the microphone (decision 5); the run records the status bar,
    the dashboard, the notifications and the toasts, with screenshots and `dumpsys`. What a version's dashboard
    lists beyond location, camera and microphone is recorded, not assumed;
  - `carried-by-system`, `short-lived`, `webview`: each sends to the lab's own server on the host (10.0.2.2) or
    looks up names reserved for testing (RFC 2606), and records which UID Watch was given, against the capture.
- **A result that differs from its source** is a finding, and goes by decision 4.
- **Stock images first, then other makers' builds.** Phone makers change Android, and Datapavan is designed for
  every maker's phones, not one. The table says at its top which builds it covers.
  - **The stock emulator images** come first: anyone can repeat them.
  - **The lab's own phones** come next, under decision 5's consent. Their rows name the maker, the model, the build
    fingerprint, the security patch level and the maker's own version (One UI, HyperOS and the like). Each run on a
    phone is a session the maintainer agrees to.
  - **A wider set of makers** (a device farm, or phones lent by allies) is a later decision, since it means an
    account or spending. Until then the table names the makers it lacks, so no row is read as true for them.

### 3. It measures; it never packages evasion

**Why publishing is right.**
- **Kerckhoffs's principle.** Datapavan is fully open source. Watch's design has to hold with everything about it
  known, its gaps included; a gap kept quiet protects no one who reads the source.
- **The routes are already documented.** NetGuard's FAQ names the download manager and Google Play services as
  carriers of other apps' traffic; PCAPdroid's FAQ explains its "unknown" app for short-lived connections; the
  "Local Mess" disclosure described the localhost route in detail in June 2025.
- **Users at risk must know what Watch cannot see.** A user who trusts Watch to show everything, and does not
  learn what it misses, is worse off than one told plainly.

**Each route is paired with what Watch does and says.** The table carries both. Where Watch's answer is not built
yet, the row says "not built" and links the gate; it never claims more than the build on `main` does.

| Route or gap | What Watch does | What Watch tells the user |
|---|---|---|
| `carried-by-system`: the download service | The flow stays under the download service, marked as carried for another app. Watch never guesses which app asked | "Downloaded for an app by Android's download service. Android does not say which app." |
| `carried-by-system`: a Custom Tab | The flow stays under the browser | "Pages an app opens in a browser tab count under the browser." |
| `carried-by-system`: push | The flow stays under Google Play services, marked as the push service | "Push messages for many apps come through Google Play services." |
| `carried-by-system`: the resolver | A lookup is shown under the app when Android names it, and under "Android's resolver" when it does not | "Some lookups are made by Android for an app; they show under Android's resolver." |
| `short-lived` | A flow whose owner is gone is shown as "app not known" and counted with the flows Android cannot name (ADR 0044); it is never given to a guessed app | The count of flows with no known app, on the view |
| `webview` | The flow stays under the app, with its destination's name | "Web pages shown inside an app count under that app." |
| `loopback` | Not seen | "Traffic between apps on the phone does not pass through Watch." (ADR 0046, decision 5) |
| `appops-closed`, `indicators` | Not seen. The audit app shows which apps hold each permission (ADR 0014) | "Whether an app read contacts, files or messages on the phone is not visible to any app without root." (ADR 0046, decision 5) |
| `vpn-seen` | Common tunnel addresses (ADR 0041, decision 3) | That other apps can see that a VPN runs (ADR 0041, decision 1) |

The strings are made and reviewed in the eight languages as ADR 0030 sets out; the words above give their sense.

**What the code may be.**
- **Only what a measurement needs.** Each behaviour is one file, the smallest code that shows the effect.
- **Only to the lab.** It sends fixed payloads, only to the lab's own server on the host or to names reserved for
  testing. It takes no payload and no destination from outside.
- **No reusable evasion library.** It offers no interface for other code, no wrapper that picks a route by Android
  version, and no combination of routes. The licence (Apache-2.0) does not restrict reuse; the code's shape keeps
  it a measurement.

**The residual risk, honestly.** A precise table, version by version, makes a careless attacker's work slightly
easier. The attacker who matters, one who builds an app to hide its traffic from privacy tools, already knows these
routes from the sources above. The gain for users and for the field outweighs that.

### 4. Three routes for a finding

1. **Documented, or "works as intended":** a behaviour that a public document states, or that Google has called
   intended in a document or in its answer to a report, is published in the table with that source.
2. **New and undocumented:** a weakness of the platform that no public source states stays out of this repository
   and its public channels. The maintainer reports it to Google first, under coordinated disclosure (ISO/IEC
   29147), with a deadline of 90 days from the report. It is published after a fix ships or at the deadline,
   whichever comes first, with Google's answer. Until then no row, commit or issue names it. A finding of
   uncertain status is treated as new until the sources settle it; one that Google answers as intended moves to
   route 1. A weakness found in another maker's app goes to that maker the same way.
3. **In Datapavan's own code:** it follows [SECURITY.md](../../SECURITY.md), and is fixed before the row that
   shows it is published, with the release that fixes it.

Filing with Google, on its issue tracker or its reporting programme, stays the maintainer's, one report at a
time. A draft may be prepared with AI help; the maintainer files it.

### 5. The fixture app's data

- **On an emulator by default.** The fixture checks that it runs on one (the emulator's own properties,
  `ro.boot.qemu` or, on older images, `ro.kernel.qemu`, and its hardware name) and otherwise stops before it reads
  anything.
- **Synthetic data only.** The run puts it there: contacts under a lab account with made-up names, an SMS and a
  call through the emulator's console (`adb emu sms send`, `adb emu gsm call`), a clip on the clipboard and a file
  in shared storage.
- **Only that a read happened.** The fixture records that each read succeeded and how many items it returned,
  never a value. The microphone records one second into memory, which is then discarded.
- **On a lab phone only by explicit choice:** a build flag (`build.sh --lab-phone`), and the maintainer's consent
  for each device and each session. On each start the fixture shows the phone's model and serial and waits for the
  maintainer to confirm, and the run script refuses a phone not named on its command line.
- **It never ships and never uploads.** The fixture holds no `INTERNET` permission; its build script fails if its
  manifest names one, and `scripts/check.sh` checks the same.
- This follows [ADR 0016](0016-no-user-data.md): no data from users; learning happens in the lab.

### 6. Names

- **ADR 0015's evidence rule.** Any app or company named in the table or its runs follows ADR 0015, decision 10:
  a primary source, or a reproduction on the lab's images; facts, never accusations; disputes through
  `data/CORRECTIONS.md`.
- **Platform components only.** The table names what the image itself ships: the download service, Google Play
  services, the resolver, the image's browser.
- **No other makers' apps.** It does not measure whether a given app uses a route. That would be a finding about
  the app, and belongs to the lab's reports ([LAB.md](../LAB.md)), with the maker asked for comment first.
- **Sources** that name companies, such as the "Local Mess" disclosure, are cited by title and link.

### 7. CI and cost

- **CI, small.** CI builds the two lab apps with the SDK's build tools, which takes seconds, and runs their unit
  tests on the JVM: turning the probe's raw output into a row, and checking the table's format. It also runs
  decision 1's class check and decision 5's manifest check. No emulator runs the probe in CI: CI minutes are
  limited.
- **Full runs on the maintainer's machine,** one emulator at a time, each stopped and its AVD deleted after its run.
- **When rows are run again:** when a new image revision or Google Play system update month appears for a version
  in the table, and before a Watch release whose texts cite the table (ADR 0039).

### Against the field

Tools of the field state their limits in prose (NetGuard's FAQ, PCAPdroid's FAQ), without the Android version or a
way to check them. Measurement research at its best publishes its artefacts so that others can repeat them,
gives rates over many trials where behaviour varies, covers the builds people actually run, has results repeated
by someone else, and fixes the version it cites. This ADR takes each of those: a table by version, with each
image's identity, the capture as ground truth and one command per row; rates with intervals for timing; stock
images, then makers' builds, with the makers it lacks named; a replication column; a dataset beside the page; and
dated, signed snapshots. No frontier research is needed; it is lab work.

## Consequences

- **Claims get numbers.** ADR 0041's promise and ADR 0046's "what this view cannot see" rest on measurements by
  version, which anyone can repeat.
- **Users at risk are told precisely** what Watch cannot see, and the view's words follow the table.
- **Changes between versions are caught,** including those that a Google Play system update brings within a
  version.
- **Google learns of new weaknesses first,** through coordinated reports.
- **CI costs little:** a build of seconds and a few unit tests.
- **Maintenance:** six versions and eight behaviours make 48 rows, run again with each new image, and the
  maintainer's machine time for them.
- **A published route can be used.** The residual risk of decision 3 is accepted.
- **Emulators are not phones.** Makers' builds may differ; rows from lab phones need consent each time, so they
  will be few, and the makers the table lacks are named until a wider set is decided.
- **Timing rows take longer:** a hundred trials or more per version. The rate they give is worth it: one run of a
  race says little.
- **Others can check and reuse the results:** the dataset, the replication column and the dated snapshots let a
  report, an ally or Google cite one exact state.
- **Some rows need Google's modules:** push and the Google Play system update month exist only on images with
  them.
- **The lab apps have no Gradle lint,** as `scripts/fixture-app` has none; their unit tests and review stand in.

## What this does not decide

Each of these needs the maintainer's word:
- **outreach:** telling other tools' makers, writing to Google beyond the reports of decision 4, or the press;
- **a report from the table:** whether one is published, where, and under whose names;
- **accounts:** a Firebase project for a push test, an account on Google's issue tracker or reporting programme,
  a device farm, a permanent identifier (a DOI) for a snapshot, or any other.

Also outside this ADR:
- runs on phones of other makers beyond the lab's own;
- what Watch does about a route beyond decision 3's labels, which the ADR that builds it decides.

## Sources

- Android 10 privacy changes: https://developer.android.com/about/versions/10/privacy/changes (read on 2026-11-14)
- Android 12 behaviour changes for all apps (microphone and camera indicators, clipboard access notifications):
  https://developer.android.com/about/versions/12/behavior-changes-all (read on 2026-11-14)
- Android 12 features (the privacy dashboard): https://developer.android.com/about/versions/12/features
- `AppOpsManager` (`startWatchingActive`, added in API level 30, and its note on `WATCH_APPOPS`):
  https://developer.android.com/reference/android/app/AppOpsManager (read on 2026-11-14)
- `NetworkCapabilities`: https://developer.android.com/reference/android/net/NetworkCapabilities
- `ConnectivityManager` (`getAllNetworks`, `getConnectionOwnerUid`):
  https://developer.android.com/reference/android/net/ConnectivityManager
- `VpnService.Builder`: https://developer.android.com/reference/android/net/VpnService.Builder
- Custom Tabs overview: https://developer.chrome.com/docs/android/custom-tabs
- NetGuard FAQ, items 8 and 66: https://github.com/M66B/NetGuard/blob/master/FAQ.md (read on 2026-11-14)
- PCAPdroid FAQ, "I see the 'unknown' app in PCAPdroid": https://emanuele-f.github.io/PCAPdroid/faq (read on
  2026-11-14)
- "Local Mess" disclosure, June 2025: https://localmess.github.io/ (read on 2026-11-14)
- ISO/IEC 29147, Vulnerability disclosure
- RFC 2606, Reserved Top Level DNS Names

The sources without a date are read again, and dated, when the row that cites them is written.
