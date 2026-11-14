# Android's platform gaps, measured

Stock Android, without root, leaves every privacy tool blind to some things and exposed in others, and these
limits change between versions. [ADR 0048](../decisions/0048-lab-probe-of-android-gaps.md) has the lab measure
them, version by version, with a probe app of the project's own, and publish each result beside its public
source and what Watch does about it. This page holds the method, the results and the images they come from. The
results live in [results.csv](results.csv); the tables below are written from it by a program, never by hand,
and CI checks that the two agree.

Rows are added as they are run and checked. A missing row has no published result. A result that differs from
its public source, or a behaviour that no public source states, is a possible new finding: it goes to Google
first, under coordinated disclosure, and stays out of this repository until a fix ships or 90 days pass (ADR 0048,
decision 4).

## What it covers

- **Builds:** the stock emulator images with Google's modules, x86_64: Android 10 (API 29), 11 (API 30), 12
  (API 31), 14 (API 34), 15 (API 35), 16 (API 36) and 17 (API 37, the image with Google Play and 16 KB pages).
  Each row names its image, revision and build fingerprint.
- **Makers not covered:** every maker's own build of Android. Emulators run Google's builds; makers change
  Android, and no row here is true of their phones until a row from their build says so. Not covered so far:
  Samsung (One UI), Xiaomi (HyperOS), Google's own Pixel builds, OPPO, OnePlus and realme (ColorOS and
  OxygenOS), vivo (Funtouch OS and OriginOS), Honor (MagicOS), Huawei (EMUI and HarmonyOS), Motorola, Nokia (HMD),
  Sony, Tecno, Infinix and itel (HiOS, XOS and itel OS), Fairphone, and the custom builds (LineageOS, GrapheneOS,
  /e/OS, CalyxOS). The lab's own phones come next, each session under the maintainer's consent (ADR 0048,
  decision 5).

## Method

**One command per row.** `lab/run.sh <behaviour> <api> [--trials N]` creates an AVD from the named image (under
`build/gaps-avd`, apart from any other), boots it with `-no-snapshot -wipe-data -tcpdump` and in UTC, so that
its clock never shows the computer's local time, installs the probe, the fixture and Watch's Advanced debug build
where the behaviour needs them, runs the behaviour's steps, records the image's identity and the capture's
SHA-256, then stops the emulator and deletes the AVD. Every adb command names the emulator's serial, so a phone
plugged into the machine is never touched. The script downloads nothing: an image that is not installed is
named and the run stops.

**The apps** live in [`lab/`](../../lab), outside the product's build, and are built with the SDK's build tools
alone, signed with a throwaway key made for each build. They are never shipped, and `scripts/check.sh` fails if
a release APK or bundle holds one of their classes.
- `lab/gaps-probe` (`org.visadahyu.lab.gapsprobe`, "Gaps probe (lab)"), one file per behaviour. It targets
  API 37, so that the newest version's limits for apps apply to it. It sends fixed payloads only to the lab's
  server on the host (`lab/server.py`, reached at 10.0.2.2), and looks up only names under `.example` (RFC 2606).
- The same probe built as a second app, `org.visadahyu.lab.gapsprobe.peer`: the loopback behaviour needs two
  apps that may open sockets, and the fixture may not.
- `lab/gaps-fixture` (`org.visadahyu.lab.gapsfixture`, "Gaps fixture (lab)"). It checks first that it runs on an
  emulator (`ro.boot.qemu` or `ro.kernel.qemu`, and the hardware name) and stops otherwise, unless it was built
  with `--lab-phone`; then it shows the device and waits to be confirmed. It reads only synthetic data that the
  run puts there (a contact under a lab account, a call and an SMS through the emulator's console, an image, a
  clip), and records only that each read happened and how many items it returned. The microphone records one
  second into memory, which is then dropped. It holds no INTERNET permission.

**Watch** is the VPN under test, its debug build from the same commit, with its debug list of flows: each flow's
protocol, addresses, the UID Android named for it (`-` when none) and its outcome. The probe changes nothing in
Watch. An app is left out of the tunnel through Watch's own list, as a user leaves one out. A run keeps only the
flows to the lab's own addresses (its server, the emulator's network, loopback and the tunnel) with names under
`.example`; any other flow, such as one of the image's own components to a server near the computer's network,
becomes `other:<port>` with its UID, so that no run tells where it ran (`lab/redact-flows.awk`).
`scripts/check.sh lab` fails on a published run that holds any other address or name.

**The capture is the ground truth** where traffic matters: the emulator's own capture sees every packet that
leaves the virtual phone, whoever sent it, on its cellular network; it does not see the emulator's Wi-Fi, so the
run turns Wi-Fi off after boot. A row that rests on what Watch logged is checked against it. The run
keeps a summary of the capture with its raw output (`capture.txt`: connections and datagrams to the lab's
server, packets holding the probe's payloads, and the names of the probe's lookups); the capture itself stays on the machine that ran it, under
`build/gaps-runs`, since it also holds the emulator's own traffic to Google's services. Its SHA-256 is in the
run's `run.txt`.

**What each behaviour's run does:**
- `vpn-seen`: the probe reads its own network, every network `getAllNetworks` lists, and every interface,
  three times: with no VPN, inside Watch's tunnel, and left out of it.
- `appops-closed`: the probe watches the microphone and the camera with `startWatchingActive` while the fixture
  records, then records with its own microphone (the control); then it asks `getHistoricalOps` for every app's
  history, and for its own (the control), as installed, with the emulator's setting that opens hidden APIs to
  apps, with `GET_APP_OPS_STATS` granted over adb, and with both.
- `proc-net`: the probe tries to read `/proc/net/tcp`, `tcp6`, `udp`, `udp6`, `unix` and `route`.
- `loopback`: the probe and its peer exchange a fixed payload over 127.0.0.1 and `::1` while Watch runs; the
  run reads Watch's flows and the capture for it. The fixture tries to open a socket too.
- `indicators`: the fixture reads contacts, the call log, SMS, an image and the clipboard, then records with the
  microphone. The run records Android's toasts, the status bar's privacy chip as accessibility sees it,
  SystemUI's list of privacy items, the notifications, and the privacy dashboard with its other permissions.
- `carried-by-system`: the download service fetches a file from the lab's server; a Custom Tab opens one of
  its pages; and the probe looks up names under `.example`, with Private DNS off, automatic and strict. The run
  reads which UID Watch was given for each. Push messages need a Firebase project, an account, and wait for the
  maintainer's word. `--parts` runs some of these parts only; the resolver's part is a timing one.
- `short-lived`: UDP and TCP sockets to the lab's server that close at once, against sockets kept open (the
  control); the run finds each trial's flow by its local port and reads its owner.
- `webview`: a WebView in the probe loads a page whose image and fetch come from a second origin.

**Timing.** A behaviour that depends on timing (`short-lived`, the resolver's part of `carried-by-system`) is run
at least 100 times, and its row gives the count of events, the rate and Wilson's 95 % interval. The resolver's
trials are the probe's own lookups, and its events those that left under the probe's UID: each lookup leaves
under the probe's UID or under one of the system, so the count is known when the flows of the window show only
one of the two; other apps' lookups in the window do not count. Where it is not known, the row gives the
counts and no rate. A timing run is alone on the machine: no other emulator runs, and the emulator is pinned
to its own threads with `taskset`. Every run records the load, the free memory, the emulators and the busiest
processes by kind (`beside_before` and `beside_after` in `run.txt`), and whether it ran alone from start to
end (`alone`); a timing run that finds another emulator at any of its checks stops.

**The machine's rule** (ADR 0048, decision 7): at most three emulators at once, on at most 12 of the machine's 24
threads, with at least 14 GB of memory left free. The script refuses to start otherwise.

**The image's identity.** The SDK manager keeps no archive once an image is installed, and its repository lists
each archive's SHA-1 only. A row records that SHA-1 from the SDK manager's cache (`not-in-sdk-cache` when the
cache does not list that revision) and the SHA-256 of the installed image's files, in place of the archive's
SHA-256 that ADR 0048 asks for.

**Sources** are read and dated when the row that cites them is written. `-` in "read" means the source is still
to be read and dated.

## The columns of results.csv

| Column | What it holds | Values |
|---|---|---|
| `behaviour` | The behaviour of ADR 0048's table | `vpn-seen`, `appops-closed`, `proc-net`, `loopback`, `indicators`, `carried-by-system`, `short-lived`, `webview` |
| `part` | The part of a behaviour that has several | `download`, `tab`, `push`, `resolver-off`, `resolver-opportunistic`, `resolver-hostname` (`carried-by-system`); `udp`, `tcp` (`short-lived`); `-` |
| `android` | Android's version | `10` to `17` |
| `api` | The API level of the image | `29` to `37` |
| `image` | The system image's SDK package | for example `system-images;android-35;google_apis;x86_64` |
| `image_revision` | Its revision | a number |
| `archive_sha1` | The SHA-1 of its archive, from the SDK repository's list in the SDK manager's cache | 40 hex digits, or `not-in-sdk-cache` |
| `image_files_sha256` | The SHA-256 of the list of SHA-256 sums of the installed image's files, sorted by path | 64 hex digits |
| `fingerprint` | `ro.build.fingerprint` | text |
| `security_patch` | `ro.build.version.security_patch` | a date |
| `play_update` | The Google Play system update month that Settings shows | `YYYY-MM`, or `none` on an image without Google's modules |
| `resolver` | The resolver module and its version | `package@versionCode`, or `none` where the image lists no resolver module (Android 10's) |
| `emulator` | The emulator's version | a version |
| `result` | What was measured, against the public source | `held`; `not held`; `in part` (some of it held, or a control did not); `not run` (with the reason in `measured`); `measured` (no source makes a claim to hold: the resolver without strict Private DNS, whose UIDs ADR 0048 measures rather than assumes) |
| `measured` | The values measured | text |
| `trials` | Trials of a timing row; `1` otherwise | a number (at least 100 where a rate is given) |
| `events` | The events counted in those trials, which `measured` names | a number, or `-` |
| `rate` | `events` divided by `trials` | 0 to 1, or `-` |
| `ci95` | Wilson's 95 % interval of the rate | `low-high`, or `-` |
| `source` | The public source of the behaviour; "in part" where it states only some of what the row measures, and what it states | text |
| `source_read` | When the source was read | a date, followed by the sources it covers when it does not cover all; or `-` |
| `watch` | What Watch does, and tells the user, about it (ADR 0048, decision 3), on `main`'s build | text; `not built` with its gate where it is not built yet |
| `probe_commit` | The commit of the probe that ran | 12 hex digits (`-dirty` if `lab/` had changes not committed) |
| `date` | The run's date | `YYYY-MM-DD` |
| `run` | The raw output, beside this page | `runs/<run>` |
| `capture_sha256` | The SHA-256 of the run's capture | 64 hex digits |
| `replicated` | Who outside the project ran the same command and sent raw output that matches | `not yet`, or the person or organisation, the date and the SHA-256 of their output |

## Results

<!-- results: written from results.csv by lab/gaps-tools; do not edit -->
| Behaviour | Part | Android | Result | Measured | Trials: events, rate (95 % interval) | Source (read) | What Watch does | Run |
|---|---|---|---|---|---|---|---|---|
<!-- results end -->

## Images

<!-- images: written from results.csv by lab/gaps-tools; do not edit -->
| Android | Image and revision | Archive SHA-1 | Image files' SHA-256 | Fingerprint | Security patch | Google Play system update | Resolver | Emulator |
|---|---|---|---|---|---|---|---|---|
<!-- images end -->

## A run's raw output

Each run writes a directory under [runs/](runs):
- `run.txt`: the behaviour, the version, the date, the probe's commit, the trials, the emulator's serial and
  threads, what ran beside it, and the capture's SHA-256;
- `image.txt`: the image's identity;
- `probe.log`: the probe's and the fixture's lines, as they wrote them;
- `flows-*.txt`: Watch's flows at each point the run read them;
- `observed.txt`, `screens/`: what the run read off the emulator (toasts, the privacy chip, notifications, the
  dashboard; screenshots). In the screenshots published here, a filled box covers the status bar's clock and the
  icons beside it: these runs' emulators showed the computer's local time. The privacy chips on the right stay
  visible;
- `capture.txt`: the capture's summary; `server.log`: what the lab's server received;
- `uids.txt`: the image's packages and their UIDs, by which a flow's UID is named;
- `rows.csv`: the rows the run gives.

## Repeating a row

From a clone of the repository, with the Android SDK, the row's image and Watch's Advanced debug build
(`cd android && ./gradlew -Pdatapavan.edition=advanced --project-cache-dir .gradle-advanced :app:assembleDebug`):

```
lab/run.sh <behaviour> <api>
```

A row is marked replicated only when someone outside the project sends raw output that matches. Before the table
is cited outside the repository, its state is fixed by a signed tag `platform-gaps-YYYY-MM-DD`, and this page
records the SHA-256 of `results.csv` and of each run's raw output at that tag. No snapshot has been tagged yet.

To add a checked run's rows and write the tables again:

```
lab/gaps-tools/build.sh
java -cp build/gaps-tools/classes org.visadahyu.lab.gapstools.GapsRows add docs/platform-gaps/runs/<run> docs/platform-gaps/results.csv
java -cp build/gaps-tools/classes org.visadahyu.lab.gapstools.GapsTable write docs/platform-gaps/results.csv docs/platform-gaps/README.md
```
